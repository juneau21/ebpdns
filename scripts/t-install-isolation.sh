#!/usr/bin/env bash
# ============================================================================
# ebpdns **2.1.38**：安装器**隔离**回归（check_all 第 13 项的第二半）
#
#   sudo bash scripts/t-install-isolation.sh
#   EBP_TII_KEEP=1 sudo bash scripts/t-install-isolation.sh    # 保留临时目录
#
# 为什么需要它（两条生产事故，都必须有机器判据）：
#   事故 #1（22:38:42）：`install.sh` 的端口预检读**包内**默认配置
#     `$(dirname "$0")/etc/ebpdns/config.json`（53/8353），不跟随 `EBP_INSTALL_ROOT`
#     ⇒ 隔离前缀安装把**生产实例**当"自家旧实例" SIGTERM。
#   事故 #2（23:06:19）：包自测的 PATH 里没有隔离 shim ⇒ `install.sh uninstall` 直接
#     `systemctl stop` + `disable` **真 systemd unit**（生产中断 35 分钟）。
#
# 场景（全部在 mktemp 前缀 + **fake systemctl** 下；生产全程只读）：
#   S1 隔离前缀 + 生产占 53/8353 + 无 `EBP_INSTALL_PORTS` ⇒ **生产不受影响**、rc≠0、
#      报出 pid/exe/端口（事故 #1 的复现＋修复判据）
#   S2 同前缀实例在跑（自家）⇒ 只停它、rc=0、旧 pid 退出、端口释放
#   S3 外部进程（python）占前缀端口 ⇒ rc≠0、报 pid/exe/端口、零写入
#   S4 `uninstall` 三条：
#      S4a 前缀里有**旧布局遗留** `ebpdns.service` ⇒ rc≠0，0 次 stop/disable，真 unit 不变
#      S4b unit 名与前缀匹配（派生名）⇒ 只 stop/disable **该前缀**的 unit，rc=0
#      S4c 派生名但 systemd 报的 FragmentPath 在前缀外 ⇒ rc≠0，0 次 stop/disable
#   S5 恶意演练（隔离前缀端口故意配 53/8353）⇒ **必须拒绝**，且日志里**不再**出现
#      "将先停止旧实例（pid=…）"（DEFECT_REPRODUCED 归零）
#   S6 端口来源证明：包内模板 53/8353、前缀配置 1985x、自家实例在跑 ⇒ rc=0
#      （= 模板**没有**参与判定；若读了模板，53 被生产占 ⇒ 必 rc≠0）
#
# 安全纪律：
#   * 所有 install.sh 调用都带 `EBP_INSTALL_ROOT=<临时前缀>`；`systemctl` 由 `$MOCK/systemctl`
#     在 PATH 首位遮蔽 ⇒ 真 systemd 调用 **0 次**（以调用日志 + 真 unit 文件/状态快照为证）；
#   * 生产面（`MainPID` / `NRestarts` / `ActiveState` / 真 unit 文件 md5）**前后断言相等**；
#   * 隔离实例私有 `state_dir`（`$PREFIX/var/lib/ebpdns/state`）+ 高位端口 1985x/1885x。
#
# 退出码：0 = PASS 或 SKIP（非 root / 无可执行二进制）；1 = 至少一项 FAIL。
# ============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL_SRC="$HERE/packaging/install.sh"
UNIT_SRC="$HERE/packaging/systemd/ebpdns.service"
CFG_SRC="$HERE/packaging/etc/ebpdns/config.json"
REAL_BIN="${EBP_BIN:-$HERE/target/release/ebpdns}"
REAL_SYSTEMCTL="/usr/bin/systemctl"
REAL_UNIT="/etc/systemd/system/ebpdns.service"

if [ "$(id -u)" -ne 0 ]; then
  echo "T_INSTALL_ISOLATION=SKIP（需要 root；当前 uid=$(id -u)）"
  exit 0
fi
if [ ! -x "$REAL_BIN" ]; then
  echo "T_INSTALL_ISOLATION=SKIP（未发现可执行二进制：$REAL_BIN；构建后本项严格执行）"
  exit 0
fi
for f in "$INSTALL_SRC" "$UNIT_SRC" "$CFG_SRC"; do
  if [ ! -f "$f" ]; then
    echo "T_INSTALL_ISOLATION=FAIL（缺少测试输入：$f）"
    exit 1
  fi
done

TMP="$(mktemp -d "${TMPDIR:-/tmp}/ebpdns-isolation-XXXXXX")" || exit 1
PASS=0
FAIL=0
SKIP=0
PIDS=""

cleanup() {
  local p
  for p in $PIDS; do kill -9 "$p" 2>/dev/null || true; done
  if [ -d "$TMP/mock/units" ]; then
    for f in "$TMP"/mock/units/*.pid; do
      [ -f "$f" ] || continue
      p="$(cat "$f" 2>/dev/null || true)"
      [ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
    done
  fi
  [ "${EBP_TII_KEEP:-0}" = "1" ] || rm -rf "$TMP"
}
trap cleanup EXIT

say() { printf '\n=== [%s] %s\n' "$1" "$2"; }
ok() { PASS=$((PASS + 1)); printf '  RESULT: PASS  (%s)\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  RESULT: FAIL  (%s)\n' "$1"; }
skip() { SKIP=$((SKIP + 1)); printf '  RESULT: SKIP  (%s)\n' "$1"; }
want() { # got want label
  if [ "$1" = "$2" ]; then ok "$3"; else bad "$3"; printf '    got=%s want=%s\n' "$1" "$2"; fi
}
want_in() { # needle file label
  if grep -qF -- "$1" "$2"; then ok "$3"; else bad "$3"; printf '    missing=%q in %s\n' "$1" "$2"; fi
}
want_not_in() { # needle file label
  if grep -qF -- "$1" "$2"; then bad "$3"; printf '    unexpected=%q in %s\n' "$1" "$2"; else ok "$3"; fi
}

# ---------------------------------------------------------------------------
# 生产面快照（**只读**；用绝对路径 /usr/bin/systemctl，避免被 shim 遮蔽）
# ---------------------------------------------------------------------------
prod_mainpid() { "$REAL_SYSTEMCTL" show ebpdns -p MainPID --value --no-pager 2>/dev/null | head -n1; }
prod_nrestarts() { "$REAL_SYSTEMCTL" show ebpdns -p NRestarts --value --no-pager 2>/dev/null | head -n1; }
prod_active() { "$REAL_SYSTEMCTL" is-active ebpdns 2>/dev/null | head -n1; }
prod_unit_md5() { md5sum "$REAL_UNIT" 2>/dev/null | awk '{print $1}'; }
prod_unit_list() { ls /etc/systemd/system 2>/dev/null | grep -c '^ebpdns' || true; }

P0_PID="$(prod_mainpid)"
P0_NR="$(prod_nrestarts)"
P0_ACT="$(prod_active)"
P0_MD5="$(prod_unit_md5)"
P0_LIST="$(prod_unit_list)"

# ---------------------------------------------------------------------------
# 端口（高位、空闲）—— 隔离实例一律用 1985x/1885x
# ---------------------------------------------------------------------------
free_port_tcp() { # $1 = 首选端口（1985x）；被占则退回临时端口
  python3 - "$1" <<'PY'
import socket, sys
pref = int(sys.argv[1]) if len(sys.argv) > 1 else 0
for p in (pref, 0):
    if p is None:
        continue
    try:
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", p))
        print(s.getsockname()[1]); s.close(); raise SystemExit(0)
    except OSError:
        continue
print(0)
PY
}
free_port_udp() { # $1 = 首选端口（1885x）
  python3 - "$1" <<'PY'
import socket, sys
pref = int(sys.argv[1]) if len(sys.argv) > 1 else 0
for p in (pref, 0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", p))
        print(s.getsockname()[1]); s.close(); raise SystemExit(0)
    except OSError:
        continue
print(0)
PY
}
APIP="$(free_port_tcp 19855)"; DNSP="$(free_port_udp 18855)"
APIP2="$(free_port_tcp 19856)"; DNSP2="$(free_port_udp 18856)"
case "$APIP" in ''|0) APIP="$(free_port_tcp 0)" ;; esac
case "$DNSP" in ''|0) DNSP="$(free_port_udp 0)" ;; esac
case "$APIP2" in ''|0) APIP2="$(free_port_tcp 0)" ;; esac
case "$DNSP2" in ''|0) DNSP2="$(free_port_udp 0)" ;; esac
[ -n "$APIP" ] && [ -n "$DNSP" ] && [ -n "$APIP2" ] && [ -n "$DNSP2" ] || {
  echo "T_INSTALL_ISOLATION=FAIL（无法分配测试端口）"; exit 1;
}

port_holder() { ss -H -ltnup "( sport = :$1 )" 2>/dev/null | grep -o 'pid=[0-9]*' | head -n1 | cut -d= -f2 | head -n1; }
wait_free() { local i; for i in $(seq 1 50); do [ -z "$(port_holder "$1")" ] && return 0; sleep 0.1; done; return 1; }
wait_holder() { local i; for i in $(seq 1 100); do [ -n "$(port_holder "$1")" ] && return 0; sleep 0.1; done; return 1; }

# ---------------------------------------------------------------------------
# 包布局（install.sh 必须从包根运行）
#   包 A：模板端口 = **真默认 53/8353**（事故 #1 的现场）
#   包 B：模板端口 = 高位（"模拟生产"占高位端口的场景用）
# ---------------------------------------------------------------------------
mkpkg() { # $1 = dir
  local d="$1"
  mkdir -p "$d/bin" "$d/etc/ebpdns" "$d/systemd" "$d/web"
  cp -a "$INSTALL_SRC" "$d/install.sh"
  cp -a "$UNIT_SRC" "$d/systemd/ebpdns.service"
  cp -a "$CFG_SRC" "$d/etc/ebpdns/config.json"
  cp -a "$REAL_BIN" "$d/bin/ebpdns"
  printf '<html>ok</html>\n' >"$d/web/index.html"
  chmod +x "$d/install.sh" "$d/bin/ebpdns"
}
PKG_PROD="$TMP/pkg-prod/ebpdns-2.1.38"
PKG_HI="$TMP/pkg-hi/ebpdns-2.1.38"
mkpkg "$PKG_PROD"
mkpkg "$PKG_HI"
python3 - "$PKG_HI/etc/ebpdns/config.json" "$APIP" "$DNSP" <<'PY'
import json, sys
p, apip, dnsp = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
c = json.load(open(p, encoding="utf-8"))
c["api"] = {"host": "127.0.0.1", "port": apip, "token": "t138"}
c["listen"] = {"udp": "127.0.0.1:%d" % dnsp, "tcp": "127.0.0.1:%d" % dnsp, "udp6": "", "tcp6": ""}
c["dns_port"] = dnsp
c["upstreams"] = []
c["rules"] = []
c["rule_subscriptions"] = []
c["cache_persist"] = False
c["prefetch"] = False
c["speed_test"] = False
c["health_check_interval"] = 3600
c["log_level"] = "warn"
json.dump(c, open(p, "w", encoding="utf-8"), indent=2)
PY

# ---------------------------------------------------------------------------
# fake systemctl：**真 systemd 调用 0 次**的证明载体
#   * 每次调用追加到 $EBP_MOCK/log（含 show / 写动作）；
#   * 写动作另记一行 `ACTION <verb> <unit>`（stop/disable/restart/start）；
#   * `ebpdns.service`（真 unit 名）单独记账，任何前缀安装都**不该**碰它。
# ---------------------------------------------------------------------------
MOCK="$TMP/mock"
mkdir -p "$MOCK/units"
export EBP_MOCK="$MOCK"
mkdir -p "$MOCK/frag"
cat >"$MOCK/systemctl" <<'EOS'
#!/usr/bin/env bash
set -u
D="${EBP_MOCK:?}"; L="$D/log"; U="$D/units"
mkdir -p "$U" "$D"
printf 'systemctl %s\n' "$*" >>"$L"
st() { printf '%s/%s.%s' "$U" "$1" "$2"; }
active_of() { [ -f "$(st "$1" active)" ]; }
pid_of() {
  local p=""
  [ -f "$(st "$1" pid)" ] && p="$(cat "$(st "$1" pid)" 2>/dev/null || true)"
  case "$p" in ''|0|*[!0-9]*) printf '' ;; *) printf '%s' "$p" ;; esac
}
case "${1:-}" in
  is-system-running) echo running; exit 0 ;;
  is-active)
    if active_of "${2:-}"; then echo active; exit 0; else echo inactive; exit 3; fi ;;
  show)
    unit="${5:-}"
    case "$*" in
      *MainPID*) p="$(pid_of "$unit")"; echo "${p:-0}"; exit 0 ;;
      *NRestarts*) cat "$U/$unit.nrestarts" 2>/dev/null || echo 0; exit 0 ;;
      *FragmentPath*)
        if [ -n "${EBP_MOCK_FRAG_OVERRIDE:-}" ]; then printf '%s\n' "$EBP_MOCK_FRAG_OVERRIDE"; exit 0; fi
        if [ "$unit" = "ebpdns.service" ]; then printf '/etc/systemd/system/ebpdns.service\n'
        else printf '%s/%s\n' "${EBP_MOCK_UNIT_DIR:-$D/frag}" "$unit"; fi
        exit 0 ;;
      *) exit 0 ;;
    esac ;;
  stop|disable|enable|restart|start)
    unit="${2:-}"
    printf 'ACTION %s %s\n' "$1" "$unit" >>"$D/actions"
    case "$1" in
      stop|restart)
        p="$(pid_of "$unit")"
        if [ -n "$p" ]; then
          kill -TERM "$p" 2>/dev/null || true
          for _ in $(seq 1 40); do kill -0 "$p" 2>/dev/null || break; sleep 0.1; done
          kill -KILL "$p" 2>/dev/null || true
        fi
        rm -f "$(st "$unit" active)" "$(st "$unit" pid)" ;;
    esac
    if [ "$1" = "start" ] || [ "$1" = "restart" ]; then
      n="$(cat "$U/$unit.nrestarts" 2>/dev/null || echo 0)"
      if [ "$1" = "restart" ]; then echo $((n + 1)) >"$U/$unit.nrestarts"; fi
      nohup "$EBP_MOCK_BIN" --config "$EBP_MOCK_CFG" --state-dir "$EBP_MOCK_STATE" \
        --foreground >>"$D/bin.log" 2>&1 &
      echo $! >"$(st "$unit" pid)"
      : >"$(st "$unit" active)"
    fi
    exit 0 ;;
  *) exit 0 ;;
esac
EOS
chmod +x "$MOCK/systemctl"
: >"$MOCK/log"
: >"$MOCK/actions"

echo "########## ebpdns 2.1.38 安装器隔离回归 $(date '+%F %T %z') ##########"
echo "TMP=$TMP"
echo "隔离端口：api=$APIP dns=$DNSP（备用 api=$APIP2 dns=$DNSP2）"
echo "生产基线（只读）：MainPID=${P0_PID:-?} NRestarts=${P0_NR:-?} ActiveState=${P0_ACT:-?} unit_md5=${P0_MD5:0:8}"
if [ -z "$(command -v systemctl)" ]; then
  echo "T_INSTALL_ISOLATION=FAIL（本机没有 systemctl；本用例需要真 systemctl 的只读查询作对照）"
  exit 1
fi
if [ "$(PATH="$MOCK:$PATH" command -v systemctl)" != "$MOCK/systemctl" ]; then
  bad "mock-first-in-PATH"
else
  ok "mock-first-in-PATH（PATH 首位 = $MOCK/systemctl）"
fi

# ---------------------------------------------------------------------------
# 通用：造一个带私有 state_dir + 高位端口的**目标前缀配置**
# ---------------------------------------------------------------------------
mkcfg() { # $1 = prefix, $2 = api port, $3 = dns port, $4 = state dir (可选)
  local pfx="$1" api="$2" dns="$3" st="${4:-$1/var/lib/ebpdns/state}"
  mkdir -p "$pfx/etc/ebpdns" "$st"
  python3 - "$CFG_SRC" "$pfx/etc/ebpdns/config.json" "$api" "$dns" "$st" <<'PY'
import json, sys
src, dst, api, dns, st = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
c = json.load(open(src, encoding="utf-8"))
c["api"] = {"host": "127.0.0.1", "port": api, "token": "t138"}
c["listen"] = {"udp": "127.0.0.1:%d" % dns, "tcp": "127.0.0.1:%d" % dns, "udp6": "", "tcp6": ""}
c["dns_port"] = dns
c["state_dir"] = st
c["upstreams"] = []
c["rules"] = []
c["rule_subscriptions"] = []
c["cache_persist"] = False
c["prefetch"] = False
c["speed_test"] = False
c["health_check_interval"] = 3600
c["log_level"] = "warn"
json.dump(c, open(dst, "w", encoding="utf-8"), indent=2)
PY
}

unit_name_of() { EBP_INSTALL_ROOT="$1" bash "$2/install.sh" --unit-name; }

run_install() { # $1 = pkg dir, $2 = prefix, $3 = systemd mode, 其余 = 参数
  local pkg="$1" pfx="$2" mode="$3"; shift 3
  EBP_INSTALL_ROOT="$pfx" EBP_SYSTEMD="$mode" PATH="$MOCK:$PATH" \
    bash "$pkg/install.sh" "$@" 2>&1
}

start_own_instance() { # $1 = prefix（用前缀里的二进制 + 前缀配置 + 私有 state）
  local pfx="$1" p
  nohup "$pfx/usr/local/bin/ebpdns" --config "$pfx/etc/ebpdns/config.json" \
    --state-dir "$pfx/var/lib/ebpdns/state" --foreground >>"$TMP/own.log" 2>&1 &
  p=$!
  PIDS="$PIDS $p"
  if ! wait_holder "$APIP" >/dev/null 2>&1; then
    printf '\n'
    return 0
  fi
  p="$(port_holder "$APIP")"
  [ -n "$p" ] && PIDS="$PIDS $p"
  printf '%s\n' "${p:-}"
}

# 每个场景开跑前清空日志，但把上一段追加进 all.log（TAIL 用**全量**日志判"真 unit 0 次"）
reset_mock() {
  {
    [ -f "$MOCK/log" ] && sed 's/^/[log] /' "$MOCK/log"
    [ -f "$MOCK/actions" ] && sed 's/^/[act] /' "$MOCK/actions"
  } >>"$MOCK/all.log" 2>/dev/null
  : >"$MOCK/log"
  : >"$MOCK/actions"
}
: >"$MOCK/all.log"

# ===========================================================================
# S1 事故 #1 复现：隔离前缀 + 生产占 53/8353 + 无 EBP_INSTALL_PORTS ⇒ 拒绝、生产不动
# ===========================================================================
say S1 "隔离前缀 + 生产占 53/8353 + 无 EBP_INSTALL_PORTS ⇒ 生产不受影响、rc≠0、报 pid/exe/端口"
ROOT1="$TMP/s1/root"
mkdir -p "$ROOT1"
reset_mock
run_install "$PKG_PROD" "$ROOT1" on start >"$TMP/s1.log" 2>&1; S1RC=$?
printf '  ---- s1.log ----\n'
sed -n '1,40p' "$TMP/s1.log" | sed 's/^/    /'
if [ -z "$P0_PID" ] || [ "$P0_PID" = "0" ]; then
  skip "s1(no-production-on-this-host)"
else
  # 生产是否真的占着 53/8353？
  if ss -H -ltnup '( sport = :53 )' 2>/dev/null | grep -q "pid=$P0_PID"; then
    if [ "$S1RC" -ne 0 ]; then ok "s1-rc-nonzero($S1RC)"; else bad "s1-rc-nonzero"; fi
    want_in "pid=$P0_PID" "$TMP/s1.log" "s1-reports-prod-pid"
    want_in "exe=/usr/local/bin/ebpdns" "$TMP/s1.log" "s1-reports-prod-exe"
    want_in "端口 53" "$TMP/s1.log" "s1-reports-port"
    want_in "拒绝把" "$TMP/s1.log" "s1-refusal-wording"
    want_not_in "将先停止旧实例" "$TMP/s1.log" "s1-no-stop-plan"
    want_not_in "SIGTERM" "$TMP/s1.log" "s1-no-sigterm"
    [ ! -f "$ROOT1/usr/local/bin/ebpdns" ] && ok "s1-zero-write" || bad "s1-zero-write"
    [ -f "$REAL_UNIT" ] && [ "$(prod_unit_md5)" = "$P0_MD5" ] && ok "s1-real-unit-unchanged" || bad "s1-real-unit-unchanged"
  else
    skip "s1(port-53-not-held-by-prod)"
  fi
fi

# ===========================================================================
# S2 同前缀实例在跑 ⇒ 只停它、rc=0
# ===========================================================================
say S2 "同前缀实例在跑 ⇒ 只停它、rc=0、旧 pid 退出、端口释放"
ROOT2="$TMP/s2/root"
mkcfg "$ROOT2" "$APIP" "$DNSP"
reset_mock
run_install "$PKG_HI" "$ROOT2" off start >"$TMP/s2a.log" 2>&1; S2ARC=$?
want "$S2ARC" 0 "s2-first-install-rc0"
OLD2="$(start_own_instance "$ROOT2")"
want "$(port_holder "$APIP")" "$OLD2" "s2-own-holds-port"
run_install "$PKG_HI" "$ROOT2" off start >"$TMP/s2b.log" 2>&1; S2BRC=$?
printf '  ---- s2b.log ----\n'
grep -E '检测到旧实例|target|SIGTERM|已退出|端口来源' "$TMP/s2b.log" | sed 's/^/    /'
want "$S2BRC" 0 "s2-second-install-rc0"
want_in "检测到旧实例在运行" "$TMP/s2b.log" "s2-detected-log"
want_in "[target] pid=" "$TMP/s2b.log" "s2-target-log"
for _ in $(seq 1 50); do kill -0 "$OLD2" 2>/dev/null || break; sleep 0.1; done
if kill -0 "$OLD2" 2>/dev/null; then bad "s2-old-exited"; else ok "s2-old-exited"; fi
wait_free "$APIP" && ok "s2-port-free" || bad "s2-port-free"
[ -x "$ROOT2/usr/local/bin/ebpdns" ] && ok "s2-binary-updated" || bad "s2-binary-updated"

# ===========================================================================
# S3 外部进程占前缀端口 ⇒ rc≠0
# ===========================================================================
say S3 "外部进程（python）占前缀端口 ⇒ rc≠0、报 pid/exe/端口、零写入"
ROOT3="$TMP/s3/root"
mkcfg "$ROOT3" "$APIP2" "$DNSP2"
python3 - "$APIP2" <<'PY' >"$TMP/s3-hold.log" 2>&1 &
import socket, sys, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(5); time.sleep(90)
PY
FPID=$!
PIDS="$PIDS $FPID"
wait_holder "$APIP2" >/dev/null 2>&1 || true
run_install "$PKG_HI" "$ROOT3" off start >"$TMP/s3.log" 2>&1; S3RC=$?
printf '  ---- s3.log ----\n'
grep -E '端口|pid=|exe=' "$TMP/s3.log" | head -6 | sed 's/^/    /'
if [ "$S3RC" -ne 0 ]; then ok "s3-rc-nonzero($S3RC)"; else bad "s3-rc-nonzero"; fi
want_in "端口 $APIP2" "$TMP/s3.log" "s3-reports-port"
want_in "pid=$FPID" "$TMP/s3.log" "s3-reports-pid"
[ ! -f "$ROOT3/usr/local/bin/ebpdns" ] && ok "s3-zero-write" || bad "s3-zero-write"
kill -9 "$FPID" 2>/dev/null || true

# ===========================================================================
# S4 uninstall：三条
# ===========================================================================
say S4a "uninstall：前缀里有旧布局遗留 ebpdns.service ⇒ rc≠0，0 次 stop/disable，真 unit 不变"
ROOT4="$TMP/s4a/root"
mkdir -p "$ROOT4/etc/systemd/system"
printf '# legacy unit file left over from an older prefixed install\n' >"$ROOT4/etc/systemd/system/ebpdns.service"
reset_mock
run_install "$PKG_HI" "$ROOT4" on uninstall >"$TMP/s4a.log" 2>&1; S4ARC=$?
printf '  ---- s4a.log ----\n'
sed -n '1,20p' "$TMP/s4a.log" | sed 's/^/    /'
if [ "$S4ARC" -ne 0 ]; then ok "s4a-rc-nonzero($S4ARC)"; else bad "s4a-rc-nonzero"; fi
want_in "旧布局遗留" "$TMP/s4a.log" "s4a-legacy-wording"
want "$(grep -c '^ACTION \(stop\|disable\)' "$MOCK/actions" 2>/dev/null || true)" "0" "s4a-zero-stop-disable"
[ -f "$ROOT4/etc/systemd/system/ebpdns.service" ] && ok "s4a-legacy-file-kept" || bad "s4a-legacy-file-kept"
want_in "ebpdns.service" "$TMP/s4a.log" "s4a-names-the-file"

say S4b "uninstall：unit 名与前缀匹配（派生名）⇒ 只 stop/disable 该前缀的 unit，rc=0"
ROOT4B="$TMP/s4b/root"
mkcfg "$ROOT4B" "$APIP" "$DNSP" "$ROOT4B/var/lib/ebpdns/state"
export EBP_MOCK_BIN="$ROOT4B/usr/local/bin/ebpdns"
export EBP_MOCK_CFG="$ROOT4B/etc/ebpdns/config.json"
export EBP_MOCK_STATE="$ROOT4B/var/lib/ebpdns/state"
export EBP_MOCK_UNIT_DIR="$ROOT4B/etc/systemd/system"
UNIT4B="$(unit_name_of "$ROOT4B" "$PKG_HI")"
printf '  derived unit = %s\n' "$UNIT4B"
want "$UNIT4B" "ebpdns-$(printf '%s' "$(realpath -m "$ROOT4B")" | md5sum | cut -c1-8).service" "s4b-unit-name-derivation"
reset_mock
run_install "$PKG_HI" "$ROOT4B" on start >"$TMP/s4b-a.log" 2>&1; S4B1=$?
want "$S4B1" 0 "s4b-install-rc0"
[ -f "$ROOT4B/etc/systemd/system/$UNIT4B" ] && ok "s4b-unit-installed" || bad "s4b-unit-installed"
want_in "restart $UNIT4B" "$MOCK/actions" "s4b-restart-derived-unit"
run_install "$PKG_HI" "$ROOT4B" on uninstall >"$TMP/s4b-b.log" 2>&1; S4B2=$?
printf '  ---- s4b uninstall log ----\n'
grep -E 'uninstall 目标前缀|target|停止并禁用' "$TMP/s4b-b.log" | sed 's/^/    /'
printf '  ---- mock actions ----\n'
sed 's/^/    /' "$MOCK/actions"
want "$S4B2" 0 "s4b-uninstall-rc0"
want_in "ACTION stop $UNIT4B" "$MOCK/actions" "s4b-stop-only-this-unit"
want_in "ACTION disable $UNIT4B" "$MOCK/actions" "s4b-disable-only-this-unit"
[ ! -f "$ROOT4B/etc/systemd/system/$UNIT4B" ] && ok "s4b-unit-removed" || bad "s4b-unit-removed"
[ ! -f "$ROOT4B/usr/local/bin/ebpdns" ] && ok "s4b-binary-removed" || bad "s4b-binary-removed"
if grep -qE '^ACTION (stop|disable) ebpdns\.service$' "$MOCK/actions"; then
  bad "s4b-never-touches-real-unit"
else
  ok "s4b-never-touches-real-unit"
fi
want "$(prod_unit_md5)" "$P0_MD5" "s4b-real-unit-md5-unchanged"

say S4c "uninstall：派生名但 systemd 报的 FragmentPath 在前缀外 ⇒ rc≠0，0 次 stop/disable"
ROOT4C="$TMP/s4c/root"
mkcfg "$ROOT4C" "$APIP" "$DNSP" "$ROOT4C/var/lib/ebpdns/state"
UNIT4C="$(unit_name_of "$ROOT4C" "$PKG_HI")"
mkdir -p "$ROOT4C/etc/systemd/system" "$ROOT4C/usr/local/bin"
printf '# fake unit file inside prefix\n' >"$ROOT4C/etc/systemd/system/$UNIT4C"
reset_mock
EBP_MOCK_FRAG_OVERRIDE="/etc/systemd/system/ebpdns.service" \
  EBP_INSTALL_ROOT="$ROOT4C" EBP_SYSTEMD=on PATH="$MOCK:$PATH" \
  bash "$PKG_HI/install.sh" uninstall >"$TMP/s4c.log" 2>&1; S4CRC=$?
printf '  ---- s4c.log ----\n'
sed -n '1,20p' "$TMP/s4c.log" | sed 's/^/    /'
if [ "$S4CRC" -ne 0 ]; then ok "s4c-rc-nonzero($S4CRC)"; else bad "s4c-rc-nonzero"; fi
want_in "FragmentPath=/etc/systemd/system/ebpdns.service" "$TMP/s4c.log" "s4c-names-fragment"
want "$(grep -c '^ACTION \(stop\|disable\)' "$MOCK/actions" 2>/dev/null || true)" "0" "s4c-zero-stop-disable"

# ===========================================================================
# S5 恶意演练：隔离前缀端口故意配 53/8353 ⇒ 必须拒绝（不再是"将停止 pid=…"）
# ===========================================================================
# >>> 242B BEGIN P0-3-test >>> #
# ===========================================================================
# S4d **2.1.42-B（P0-3）**：uninstall --dry-run 必须 0 写、文件树 md5 不变
#     （旧缺陷：分派早于 DRY_RUN 判断 ⇒ 真 stop/disable、删 bin/web、--purge 删配置）
# ===========================================================================
say S4d "uninstall --dry-run / --purge --dry-run ⇒ 0 次 systemctl 写动作、文件树 md5 前后相同"
ROOT4D="$TMP/s4d/root"
mkcfg "$ROOT4D" "$APIP" "$DNSP" "$ROOT4D/var/lib/ebpdns/state"
tree_md5() { ( cd "$1" && find . -type f -print0 | sort -z | xargs -0 md5sum | md5sum | cut -d' ' -f1 ); }
reset_mock
run_install "$PKG_HI" "$ROOT4D" on >"$TMP/s4d-install.log" 2>&1; S4D0=$?
want "$S4D0" 0 "s4d-install-rc0"
UNIT4D="$(unit_name_of "$ROOT4D" "$PKG_HI")"
[ -f "$ROOT4D/etc/systemd/system/$UNIT4D" ] && ok "s4d-unit-installed" || bad "s4d-unit-installed"
BEFORE4D="$(tree_md5 "$ROOT4D")"
reset_mock
run_install "$PKG_HI" "$ROOT4D" on --dry-run uninstall >"$TMP/s4d-a.log" 2>&1; S4DA=$?
printf '  ---- s4d dry-run uninstall log ----\n'
sed -n '1,20p' "$TMP/s4d-a.log" | sed 's/^/    /'
want "$S4DA" 0 "s4d-dryrun-uninstall-rc0"
want "$(grep -c '^ACTION ' "$MOCK/actions" 2>/dev/null || true)" 0 "s4d-dryrun-zero-write-actions"
[ -f "$ROOT4D/usr/local/bin/ebpdns" ] && ok "s4d-dryrun-binary-kept" || bad "s4d-dryrun-binary-kept"
[ -f "$ROOT4D/etc/systemd/system/$UNIT4D" ] && ok "s4d-dryrun-unit-kept" || bad "s4d-dryrun-unit-kept"
want "$(tree_md5 "$ROOT4D")" "$BEFORE4D" "s4d-dryrun-tree-md5-unchanged"
reset_mock
run_install "$PKG_HI" "$ROOT4D" on --dry-run uninstall --purge >"$TMP/s4d-b.log" 2>&1; S4DB=$?
want "$S4DB" 0 "s4d-dryrun-purge-rc0"
want "$(grep -c '^ACTION ' "$MOCK/actions" 2>/dev/null || true)" 0 "s4d-dryrun-purge-zero-write-actions"
[ -d "$ROOT4D/etc/ebpdns" ] && ok "s4d-dryrun-purge-conf-kept" || bad "s4d-dryrun-purge-conf-kept"
[ -d "$ROOT4D/var/lib/ebpdns/state" ] && ok "s4d-dryrun-purge-state-kept" || bad "s4d-dryrun-purge-state-kept"
want "$(tree_md5 "$ROOT4D")" "$BEFORE4D" "s4d-dryrun-purge-tree-md5-unchanged"

# ===========================================================================
# S5 恶意演练：隔离前缀端口故意配 53/8353 ⇒ 必须拒绝（不再是"将停止 pid=…"）
# ===========================================================================
# <<< 242B END P0-3-test <<< #
say S5 "恶意演练：隔离前缀端口故意配 53/8353 ⇒ 必须拒绝（dry-run 也不得写"将先停止旧实例"）"
if [ -z "$P0_PID" ] || [ "$P0_PID" = "0" ]; then
  skip "s5(no-production-on-this-host)"
else
  ROOT5="$TMP/s5/root"
  mkcfg "$ROOT5" 8353 53
  grep -E '"(dns_port|port)"' "$ROOT5/etc/ebpdns/config.json" | head -3 | sed 's/^/    /'
  reset_mock
  run_install "$PKG_PROD" "$ROOT5" off --dry-run start >"$TMP/s5a.log" 2>&1; S5ARC=$?
  printf '  ---- s5 dry-run log ----\n'
  sed -n '1,30p' "$TMP/s5a.log" | sed 's/^/    /'
  if [ "$S5ARC" -ne 0 ]; then ok "s5-dryrun-rc-nonzero($S5ARC)"; else bad "s5-dryrun-rc-nonzero"; fi
  want_in "pid=$P0_PID" "$TMP/s5a.log" "s5-dryrun-reports-pid"
  want_in "exe=/usr/local/bin/ebpdns" "$TMP/s5a.log" "s5-dryrun-reports-exe"
  want_in "端口 53" "$TMP/s5a.log" "s5-dryrun-reports-port"
  want_not_in "将先停止旧实例" "$TMP/s5a.log" "s5-no-stop-plan"
  want_not_in "[dry-run] 将" "$TMP/s5a.log" "s5-no-plan-at-all"
  [ ! -f "$ROOT5/usr/local/bin/ebpdns" ] && ok "s5-dryrun-zero-write" || bad "s5-dryrun-zero-write"

  run_install "$PKG_PROD" "$ROOT5" off start >"$TMP/s5b.log" 2>&1; S5BRC=$?
  printf '  ---- s5 start log ----\n'
  sed -n '1,30p' "$TMP/s5b.log" | sed 's/^/    /'
  if [ "$S5BRC" -ne 0 ]; then ok "s5-start-rc-nonzero($S5BRC)"; else bad "s5-start-rc-nonzero"; fi
  want_in "pid=$P0_PID" "$TMP/s5b.log" "s5-start-reports-pid"
  want_not_in "将先停止旧实例" "$TMP/s5b.log" "s5-start-no-stop-plan"
  [ ! -f "$ROOT5/usr/local/bin/ebpdns" ] && ok "s5-start-zero-write" || bad "s5-start-zero-write"
fi

# S5b 与生产无关的**固定**演练："模拟生产"（exe 在前缀外、名字也叫 ebpdns）占前缀端口
say S5b "恶意演练（可复现版）：模拟生产 ebpdns（前缀外）占前缀端口 ⇒ 必须拒绝"
ROOT5B="$TMP/s5b/root"
mkcfg "$ROOT5B" "$APIP" "$DNSP" "$ROOT5B/var/lib/ebpdns/state"
mkdir -p "$TMP/prod/bin"
cp -aL "$(readlink -f "$(command -v python3)")" "$TMP/prod/bin/ebpdns"
"$TMP/prod/bin/ebpdns" -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', $DNSP))
t = socket.socket(); t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
t.bind(('127.0.0.1', $APIP)); t.listen(5)
time.sleep(90)
" >"$TMP/s5b-prod.log" 2>&1 &
SPID=$!
PIDS="$PIDS $SPID"
wait_holder "$APIP" >/dev/null 2>&1 || true
reset_mock
run_install "$PKG_HI" "$ROOT5B" off start >"$TMP/s5c.log" 2>&1; S5CRC=$?
printf '  ---- s5b log ----\n'
grep -E '拒绝|端口|pid=|exe=' "$TMP/s5c.log" | head -8 | sed 's/^/    /'
if [ "$S5CRC" -ne 0 ]; then ok "s5b-rc-nonzero($S5CRC)"; else bad "s5b-rc-nonzero"; fi
want_in "pid=$SPID" "$TMP/s5c.log" "s5b-reports-sim-prod-pid"
want_in "exe=$TMP/prod/bin/ebpdns" "$TMP/s5c.log" "s5b-reports-sim-prod-exe"
want_in "端口 $APIP" "$TMP/s5c.log" "s5b-reports-port"
want_not_in "将先停止旧实例" "$TMP/s5c.log" "s5b-no-stop-plan"
if kill -0 "$SPID" 2>/dev/null; then ok "s5b-sim-prod-alive"; else bad "s5b-sim-prod-alive"; fi
[ ! -f "$ROOT5B/usr/local/bin/ebpdns" ] && ok "s5b-zero-write" || bad "s5b-zero-write"
kill -9 "$SPID" 2>/dev/null || true

# ===========================================================================
# S6 端口来源证明：包内模板 53/8353、前缀配置 1985x、自家实例在跑 ⇒ rc=0
#    （若脚本还读包内模板，53 被生产占 ⇒ 必然 rc≠0；rc=0 即证明模板未参与判定）
# ===========================================================================
say S6 "端口来源：包内模板 53/8353 + 前缀配置 $APIP/$DNSP ⇒ rc=0（模板未参与判定）"
ROOT6="$TMP/s6/root"
mkcfg "$ROOT6" "$APIP" "$DNSP" "$ROOT6/var/lib/ebpdns/state"
grep -E '"(dns_port)"' "$PKG_PROD/etc/ebpdns/config.json" | head -1 | sed 's/^/    模板 /'
reset_mock
run_install "$PKG_PROD" "$ROOT6" off --dry-run start >"$TMP/s6a.log" 2>&1; S6ARC=$?
printf '  ---- s6 dry-run log ----\n'
sed -n '1,12p' "$TMP/s6a.log" | sed 's/^/    /'
want "$S6ARC" 0 "s6-dryrun-rc0"
want_in "端口来源 = 目标前缀配置" "$TMP/s6a.log" "s6-ports-from-prefix-config"
# `--dry-run` 在 check_ports **之前**就打印计划并退出，所以这里核的是计划行（print_plan）。
want_in "端口 = $DNSP $APIP" "$TMP/s6a.log" "s6-ports-are-prefix-ports"
want_not_in "端口来源 = 将安装的包内模板" "$TMP/s6a.log" "s6-template-not-used"
run_install "$PKG_PROD" "$ROOT6" off start >"$TMP/s6b.log" 2>&1; S6BRC=$?
want "$S6BRC" 0 "s6-install-rc0"
OLD6="$(start_own_instance "$ROOT6")"
want "$(port_holder "$APIP")" "$OLD6" "s6-own-holds-port"
run_install "$PKG_PROD" "$ROOT6" off start >"$TMP/s6c.log" 2>&1; S6CRC=$?
printf '  ---- s6 second-install log ----\n'
grep -E '端口来源|检测到旧实例|target' "$TMP/s6c.log" | sed 's/^/    /'
want "$S6CRC" 0 "s6-second-install-rc0"
want_in "端口来源 = 目标前缀配置" "$TMP/s6c.log" "s6-second-ports-from-prefix"
want_in "预检端口 = $DNSP $APIP" "$TMP/s6c.log" "s6-precheck-ports-line"
for _ in $(seq 1 50); do kill -0 "$OLD6" 2>/dev/null || break; sleep 0.1; done
if kill -0 "$OLD6" 2>/dev/null; then bad "s6-old-exited"; else ok "s6-old-exited"; fi

# ===========================================================================
# 收尾：真 systemd 0 次 + 生产面不变
# ===========================================================================
say TAIL "真 systemd 调用 0 次（fake shim 调用日志为证）+ 生产面不变"
{
  [ -f "$MOCK/log" ] && sed 's/^/[log] /' "$MOCK/log"
  [ -f "$MOCK/actions" ] && sed 's/^/[act] /' "$MOCK/actions"
} >>"$MOCK/all.log" 2>/dev/null
: >"$MOCK/log"; : >"$MOCK/actions"
echo "  ---- fake systemctl 调用日志（全量；[log]=每次调用，[act]=写动作）----"
sed 's/^/    /' "$MOCK/all.log"
printf '    systemctl 调用总数 = %s\n' "$(grep -c '^\[log\] systemctl ' "$MOCK/all.log" 2>/dev/null || echo 0)"
printf '    写动作（stop/disable/enable/restart/start）= %s\n' "$(grep -c '^\[act\] ACTION ' "$MOCK/all.log" 2>/dev/null || echo 0)"
if grep -qE '^\[log\] systemctl .* ebpdns\.service$' "$MOCK/all.log" 2>/dev/null; then
  bad "tail-never-addresses-real-unit"
else
  ok "tail-never-addresses-real-unit"
fi
if grep -qE '^\[act\] ACTION (stop|disable|restart|start) ebpdns\.service$' "$MOCK/all.log" 2>/dev/null; then
  bad "tail-real-unit-never-stopped"
else
  ok "tail-real-unit-never-stopped"
fi
want "$(prod_mainpid)" "$P0_PID" "tail-prod-mainpid-unchanged"
want "$(prod_nrestarts)" "$P0_NR" "tail-prod-nrestarts-unchanged"
want "$(prod_active)" "$P0_ACT" "tail-prod-active-unchanged"
want "$(prod_unit_md5)" "$P0_MD5" "tail-prod-unit-md5-unchanged"
want "$(prod_unit_list)" "$P0_LIST" "tail-real-unit-dir-count-unchanged"
if [ -n "$P0_PID" ] && [ "$P0_PID" != "0" ] && kill -0 "$P0_PID" 2>/dev/null; then
  ok "tail-prod-process-alive(pid=$P0_PID)"
else
  skip "tail-prod-process-alive(no prod pid)"
fi

# ===========================================================================
echo
echo "==================== T_INSTALL_ISOLATION SUMMARY ===================="
echo "SCENARIOS: S1(事故#1) S2(同前缀实例) S3(外部进程) S4a/S4b/S4c(uninstall) S5/S5b(恶意演练) S6(端口来源)"
echo "PASS=$PASS FAIL=$FAIL SKIP=$SKIP  REAL_SYSTEMD_CALLS=0（全部经 $MOCK/systemctl）"
if [ "$FAIL" -eq 0 ]; then
  echo "T_INSTALL_ISOLATION=PASS"
  exit 0
fi
echo "T_INSTALL_ISOLATION=FAIL（$FAIL 项红）"
exit 1
