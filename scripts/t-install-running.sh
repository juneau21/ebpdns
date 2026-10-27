#!/usr/bin/env bash
# ============================================================================
# ebpdns 2.1.32：`install.sh start` 的**运行实例语义**验收（check_all 第 13 项）
#
#   sudo bash scripts/t-install-running.sh
#   EBP_TIR_KEEP=1 sudo bash scripts/t-install-running.sh   # 保留临时目录
#
# 覆盖（5 种场景 + 无 systemd 分支）：
#   A. systemd 可用（**systemctl 是测试 shim，绝不调用真机 systemd**）：
#      A1 首次 start → rc=0、active、pid1 持有端口
#      A2 再次 start → rc=0、日志含"检测到旧实例"、先 stop 再 restart、pid2≠pid1、
#         端口由 pid2 持有、NRestarts 递增
#      A3 --keep-running start → rc=0、pid 不变、端口仍由同一 pid 持有、提示"下次重启生效"
#      A4 --dry-run start → rc=0、文件/pid/systemctl 调用日志零变更
#      A5 别的进程占端口 → rc≠0、报出 pid/exe/端口、未写文件
#      A6 --restart install → rc=0、先停后启、pid 更新
#   B. 无 systemd（EBP_SYSTEMD=0）：
#      B1 自家进程在跑 → start ⇒ rc=0、日志含"检测到旧实例"、SIGTERM 后退出、端口释放
#      B2 自家进程忽略 SIGTERM → SIGTERM 等 5 s 后 SIGKILL、rc=0、端口释放
#      B3 别的进程占端口 → rc≠0、报出 pid/exe/端口
#      B4 --keep-running + 运行中实例 → rc=0、pid 不变（运行中的二进制被 rename 替换）
#
# 安全：全部动作在 mktemp 临时前缀；PORT 用高位随机空闲端口；systemctl 只在
# $TMP/mock 里（PATH 首位遮蔽）；**不碰**真机 /etc、/usr/local、/var/lib、53/8353、
# 真 systemd（不执行任何真 systemctl 写操作）。
#
# 退出码：0 = PASS 或 SKIP（未构建二进制/非 root）；1 = 至少一项 FAIL。
# ============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL_SRC="$HERE/packaging/install.sh"
UNIT_SRC="$HERE/packaging/systemd/ebpdns.service"
CFG_SRC="$HERE/packaging/etc/ebpdns/config.json"
REAL_BIN="${EBP_BIN:-$HERE/target/release/ebpdns}"

if [ "$(id -u)" -ne 0 ]; then
  echo "T_INSTALL_RUNNING=SKIP（需要 root；当前 uid=$(id -u)）"
  exit 0
fi
if [ ! -x "$REAL_BIN" ]; then
  echo "T_INSTALL_RUNNING=SKIP（未发现可执行二进制：$REAL_BIN；构建后本项严格执行）"
  exit 0
fi
for f in "$INSTALL_SRC" "$UNIT_SRC" "$CFG_SRC"; do
  if [ ! -f "$f" ]; then
    echo "T_INSTALL_RUNNING=FAIL（缺少测试输入：$f）"
    exit 1
  fi
done

TMP="$(mktemp -d "${TMPDIR:-/tmp}/ebpdns-running-XXXXXX")" || exit 1
PASS=0
FAIL=0
PIDS=""
MANUAL_PID=""

cleanup() {
  if [ -f "$TMP/mock/state/pid" ]; then
    p="$(cat "$TMP/mock/state/pid" 2>/dev/null || true)"
    [ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
  fi
  [ -n "$MANUAL_PID" ] && kill -9 "$MANUAL_PID" 2>/dev/null || true
  for p in $PIDS; do kill -9 "$p" 2>/dev/null || true; done
  [ "${EBP_TIR_KEEP:-0}" = "1" ] || rm -rf "$TMP"
}
trap cleanup EXIT

say() { printf '\n=== [%s] %s\n' "$1" "$2"; }
ok() { PASS=$((PASS + 1)); printf '  RESULT: PASS  (%s)\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  RESULT: FAIL  (%s)\n' "$1"; }
want() { # got want label
  if [ "$1" = "$2" ]; then ok "$3"; else bad "$3"; printf '    got=%s want=%s\n' "$1" "$2"; fi
}
want_in() { # needle file label
  if grep -qF -- "$1" "$2"; then ok "$3"; else bad "$3"; printf '    missing=%s in %s\n' "$1" "$2"; fi
}

# ---------------------------------------------------------------------------
# 空闲高位端口（同一 127.0.0.1；TCP api + UDP dns）
# ---------------------------------------------------------------------------
APIP="$(python3 - <<'PY'
import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()
PY
)"
DNSP="$(python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()
PY
)"
[ -n "$APIP" ] && [ -n "$DNSP" ] || { echo "T_INSTALL_RUNNING=FAIL（无法分配测试端口）"; exit 1; }
PORT_TOKENS="$APIP $DNSP"

# ---------------------------------------------------------------------------
# 包布局（install.sh 必须从包根运行）
# ---------------------------------------------------------------------------
STAGE="$TMP/pkg/ebpdns-2.1.32"
mkdir -p "$STAGE/bin" "$STAGE/etc/ebpdns" "$STAGE/systemd" "$STAGE/web"
cp -a "$INSTALL_SRC" "$STAGE/install.sh"
cp -a "$UNIT_SRC" "$STAGE/systemd/ebpdns.service"
cp -a "$CFG_SRC" "$STAGE/etc/ebpdns/config.json"
cp -a "$REAL_BIN" "$STAGE/bin/ebpdns"
printf '<html>ok</html>\n' >"$STAGE/web/index.html"
chmod +x "$STAGE/install.sh" "$STAGE/bin/ebpdns"

ROOT="$TMP/root"
MOCK="$TMP/mock"
MOCK_STATE="$ROOT/var/lib/ebpdns/state"
mkdir -p "$MOCK/state"
export EBP_MOCK_DIR="$MOCK"
# **2.1.38**：shim 起的进程必须是**前缀内的安装路径**（真实 unit 的 ExecStart 就是它）。
# 若仍按 2.1.37 的写法指向包内 `$STAGE/bin/ebpdns`，该进程的 exe 就落在前缀外 ——
# 2.1.38 的路径约束会（正确地）把它判成"前缀外的 ebpdns"并拒绝停止。
export EBP_MOCK_BIN="$ROOT/usr/local/bin/ebpdns"
export EBP_MOCK_CFG="$ROOT/etc/ebpdns/config.json"
export EBP_MOCK_STATE="$MOCK_STATE"

# **2.1.38**：非默认前缀的 unit 名是**派生**的（`ebpdns-<hash8>.service`），不再是常量
# `ebpdns.service` —— 用安装器自己的只读查询取，避免测试与实现各写一套哈希。
UNIT="$(EBP_INSTALL_ROOT="$ROOT" bash "$STAGE/install.sh" --unit-name)"
case "$UNIT" in
  ebpdns-*.service) ;;
  *)
    echo "T_INSTALL_RUNNING=FAIL（派生 unit 名异常：$UNIT）"
    exit 1
    ;;
esac
echo "派生 unit（前缀 $ROOT）= $UNIT"

# 模板 → 隔离配置（高位端口 + 临时 state_dir + 无上游/规则）
python3 - "$STAGE/etc/ebpdns/config.json" "$APIP" "$DNSP" "$MOCK_STATE" <<'PY'
import json, sys
p, apip, dnsp, state = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
c = json.load(open(p, encoding="utf-8"))
c["api"] = {"host": "127.0.0.1", "port": apip, "token": "t132"}
c["listen"] = {"udp": "127.0.0.1:%d" % dnsp, "tcp": "127.0.0.1:%d" % dnsp, "udp6": "", "tcp6": ""}
c["dns_port"] = dnsp
c["state_dir"] = state
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
# systemctl shim：完整模拟服务生命周期（stop / restart / show MainPID / NRestarts）
# ---------------------------------------------------------------------------
cat >"$MOCK/systemctl" <<'EOS'
#!/usr/bin/env bash
set -u
D="$EBP_MOCK_DIR"; S="$D/state"; L="$D/log"; A="$S/active"; P="$S/pid"; N="$S/nrestarts"
mkdir -p "$S" "$D"; : >>"$L"
pid_of() {
  local p=""
  [ -f "$P" ] && p="$(cat "$P" 2>/dev/null || true)"
  case "$p" in ''|0|*[!0-9]*) printf '' ;; *) printf '%s' "$p" ;; esac
}
running() { local p; p="$(pid_of)"; [ -f "$A" ] && [ -n "$p" ] && kill -0 "$p" 2>/dev/null; }
case "${1:-}" in
  is-system-running) echo running; exit 0 ;;
  is-active)
    if running; then echo active; exit 0; else echo inactive; exit 3; fi ;;
  show)
    case "$*" in
      *MainPID*) p="$(pid_of)"; [ -n "$p" ] || p=0; echo "$p"; exit 0 ;;
      *NRestarts*) cat "$N" 2>/dev/null || echo 0; exit 0 ;;
      *) exit 0 ;;
    esac ;;
  stop)
    echo "systemctl $*" >>"$L"
    p="$(pid_of)"
    if [ -n "$p" ]; then
      kill -TERM "$p" 2>/dev/null || true
      for _ in $(seq 1 50); do kill -0 "$p" 2>/dev/null || break; sleep 0.1; done
      kill -KILL "$p" 2>/dev/null || true
    fi
    rm -f "$A" "$P"; exit 0 ;;
  restart|start)
    echo "systemctl $*" >>"$L"
    p="$(pid_of)"
    if [ -n "$p" ]; then
      kill -TERM "$p" 2>/dev/null || true
      for _ in $(seq 1 30); do kill -0 "$p" 2>/dev/null || break; sleep 0.1; done
      kill -KILL "$p" 2>/dev/null || true
    fi
    if [ "$1" = "restart" ]; then
      n="$(cat "$N" 2>/dev/null || echo 0)"; echo $((n + 1)) >"$N"
    fi
    nohup "$EBP_MOCK_BIN" --config "$EBP_MOCK_CFG" --state-dir "$EBP_MOCK_STATE" \
      --foreground >>"$D/bin.log" 2>&1 &
    echo $! >"$P"
    : >"$A"
    exit 0 ;;
  *)
    echo "systemctl $*" >>"$L"; exit 0 ;;
esac
EOS
chmod +x "$MOCK/systemctl"

reset_env() {
  local p
  if [ -f "$MOCK/state/pid" ]; then
    p="$(cat "$MOCK/state/pid" 2>/dev/null || true)"
    [ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
  fi
  [ -n "$MANUAL_PID" ] && kill -9 "$MANUAL_PID" 2>/dev/null || true
  for p in $PIDS; do kill -9 "$p" 2>/dev/null || true; done
  PIDS=""
  MANUAL_PID=""
  rm -rf "$ROOT"
  mkdir -p "$ROOT"
  rm -rf "$MOCK/state"
  mkdir -p "$MOCK/state"
  : >"$MOCK/log"
  echo 0 >"$MOCK/state/nrestarts"
  # 等测试端口彻底释放（上一场景可能刚被 SIGKILL）
  for _ in $(seq 1 50); do
    if [ -z "$(port_holder "$APIP")" ] && [ -z "$(port_holder "$DNSP")" ]; then return 0; fi
    sleep 0.1
  done
  return 0
}

port_holder() { # 打印监听该端口的第一个 pid（空=空闲）
  ss -H -ltnup "( sport = :$1 )" 2>/dev/null | grep -o 'pid=[0-9]*' | head -n1 | cut -d= -f2 | head -n1
}

wait_api() {
  local i
  for i in $(seq 1 120); do
    if curl -s -m 1 -H 'Authorization: Bearer t132' "http://127.0.0.1:$APIP/api/health" 2>/dev/null | grep -q '"running"'; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

run_install() { # $1 = auto|on|off  其余 = install.sh 参数
  local mode="$1"; shift
  EBP_INSTALL_ROOT="$ROOT" EBP_SYSTEMD="$mode" PATH="$MOCK:$PATH" \
    bash "$STAGE/install.sh" "$@"
}

start_manual() {
  local launched
  nohup "$ROOT/usr/local/bin/ebpdns" --config "$ROOT/etc/ebpdns/config.json" \
    --state-dir "$MOCK_STATE" --foreground >>"$TMP/manual.log" 2>&1 &
  launched=$!
  PIDS="$PIDS $launched"
  wait_api || { MANUAL_PID="$launched"; return 1; }
  MANUAL_PID="$(port_holder "$APIP")"
  [ -n "$MANUAL_PID" ] || MANUAL_PID="$launched"
  PIDS="$PIDS $MANUAL_PID"
  return 0
}

tree_sum() {
  find "$ROOT/usr/local" "$ROOT/etc" -type f -print0 2>/dev/null | sort -z | xargs -0 -r md5sum 2>/dev/null | md5sum | awk '{print $1}'
}

echo "########## ebpdns 2.1.32 install.sh start 运行语义验收 $(date '+%F %T %z') ##########"
echo "TMP=$TMP  API=$APIP  DNS=$DNSP  REAL_BIN=$REAL_BIN"
ss -H -ltnup "( sport = :$APIP )" >/dev/null 2>&1 || true

# ===========================================================================
# A. systemd 可用（shim）
# ===========================================================================
say A1 "systemd 场景：首次 start（无旧实例）"
reset_env
run_install on start >"$TMP/a1.log" 2>&1; rc=$?
want "$rc" 0 "a1-rc0"
wait_api && ok "a1-api-ready" || { bad "a1-api-ready"; tail -20 "$TMP/a1.log"; tail -20 "$MOCK/bin.log" 2>/dev/null; }
PID1="$(cat "$MOCK/state/pid" 2>/dev/null || true)"
[ -n "$PID1" ] && kill -0 "$PID1" 2>/dev/null && ok "a1-active" || { bad "a1-active"; printf '    pid1=<%s>\n' "$PID1"; }
[ -n "$PID1" ] && want "$(port_holder "$APIP")" "$PID1" "a1-port-pid1" || bad "a1-port-pid1(no-pid)"

say A2 "systemd 场景：再次 start（旧实例在跑）⇒ 先停后启、rc=0、pid 更新"
run_install on start >"$TMP/a2.log" 2>&1; rc=$?
want "$rc" 0 "a2-rc0"
want_in "检测到旧实例在运行" "$TMP/a2.log" "a2-detected-log"
want_in "systemctl stop $UNIT" "$MOCK/log" "a2-systemctl-stop"
want_in "systemctl restart $UNIT" "$MOCK/log" "a2-systemctl-restart"
PID2="$(cat "$MOCK/state/pid" 2>/dev/null || true)"
if [ -n "$PID2" ] && [ "$PID2" != "$PID1" ]; then ok "a2-new-pid"; else bad "a2-new-pid"; printf '    pid1=%s pid2=%s\n' "$PID1" "$PID2"; fi
wait_api && ok "a2-api-ready" || bad "a2-api-ready"
[ -n "$PID2" ] && want "$(port_holder "$APIP")" "$PID2" "a2-port-pid2" || bad "a2-port-pid2(no-pid)"
NR="$(cat "$MOCK/state/nrestarts" 2>/dev/null || echo 0)"
[ "$NR" -ge 1 ] 2>/dev/null && ok "a2-nrestarts=$NR" || { bad "a2-nrestarts"; printf '    NRestarts=%s\n' "$NR"; }
want_in "NRestarts=" "$TMP/a2.log" "a2-nrestarts-log"
printf '  PIDS: pid1=%s pid2=%s NRestarts=%s\n' "$PID1" "$PID2" "$NR"

say A6 "--restart install：显式『先停后启』（install 动作也启动）"
run_install on --restart install >"$TMP/a6.log" 2>&1; rc=$?
want "$rc" 0 "a6-rc0"
want_in "检测到旧实例在运行" "$TMP/a6.log" "a6-detected-log"
PID3="$(cat "$MOCK/state/pid" 2>/dev/null || true)"
if [ -n "$PID3" ] && [ "$PID3" != "$PID2" ]; then ok "a6-new-pid"; else bad "a6-new-pid"; printf '    pid2=%s pid3=%s\n' "$PID2" "$PID3"; fi
wait_api && ok "a6-api-ready" || bad "a6-api-ready"
[ -n "$PID3" ] && want "$(port_holder "$APIP")" "$PID3" "a6-port-pid3" || bad "a6-port-pid3(no-pid)"
printf '  PIDS: pid3=%s（--restart install 后）\n' "$PID3"

say A3 "systemd 场景：--keep-running ⇒ rc=0、pid 不变、端口仍由同一 pid 持有"
run_install on --keep-running start >"$TMP/a3.log" 2>&1; rc=$?
want "$rc" 0 "a3-rc0"
want "$(cat "$MOCK/state/pid" 2>/dev/null)" "$PID3" "a3-pid-unchanged"
want "$(port_holder "$APIP")" "$PID3" "a3-port-unchanged"
want_in "新二进制将在下次重启后生效" "$TMP/a3.log" "a3-next-restart-hint"

say A4 "systemd 场景：--dry-run ⇒ rc=0、系统零变更（文件/pid/systemctl 写调用）"
BEFORE_SUM="$(tree_sum)"
BEFORE_PID="$(cat "$MOCK/state/pid" 2>/dev/null || true)"
BEFORE_MOCK="$(wc -l <"$MOCK/log")"
run_install on --dry-run start >"$TMP/a4.log" 2>&1; rc=$?
want "$rc" 0 "a4-rc0"
want "$(tree_sum)" "$BEFORE_SUM" "a4-zero-file-change"
want "$(cat "$MOCK/state/pid" 2>/dev/null)" "$BEFORE_PID" "a4-pid-unchanged"
want "$(wc -l <"$MOCK/log")" "$BEFORE_MOCK" "a4-zero-systemctl-writes"
want_in "[dry-run]" "$TMP/a4.log" "a4-plan-printed"
want_in "将先停止旧实例" "$TMP/a4.log" "a4-stop-plan"

say A5 "systemd 场景：别的进程占端口 ⇒ rc≠0、报 pid/exe/端口、未写文件"
"$MOCK/systemctl" stop "$UNIT" >/dev/null 2>&1 || true
sleep 0.3
BIN_MD5="$(md5sum "$ROOT/usr/local/bin/ebpdns" 2>/dev/null | awk '{print $1}')"
python3 - "$APIP" <<'PY' >"$TMP/foreign.log" 2>&1 &
import socket, sys, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(5); time.sleep(120)
PY
FPID=$!
PIDS="$PIDS $FPID"
for _ in $(seq 1 50); do [ -n "$(port_holder "$APIP")" ] && break; sleep 0.1; done
run_install on start >"$TMP/a5.log" 2>&1; rc=$?
if [ "$rc" -ne 0 ]; then ok "a5-rc-nonzero"; else bad "a5-rc-nonzero"; fi
want_in "端口 $APIP" "$TMP/a5.log" "a5-port-in-message"
want_in "pid=$FPID" "$TMP/a5.log" "a5-pid-in-message"
want_in "python" "$TMP/a5.log" "a5-exe-in-message"
want "$(md5sum "$ROOT/usr/local/bin/ebpdns" 2>/dev/null | awk '{print $1}')" "$BIN_MD5" "a5-no-write"
kill -9 "$FPID" 2>/dev/null || true

# ===========================================================================
# B. 无 systemd（EBP_SYSTEMD=0；自家进程 = 端口持有者 exe basename ebpdns）
# ===========================================================================
say B1 "无 systemd：自家进程在跑 ⇒ start 先停后继续、rc=0、日志含检测、SIGTERM 退出"
reset_env
run_install off start >"$TMP/b1a.log" 2>&1; rc=$?
want "$rc" 0 "b1-first-rc0"
start_manual && ok "b1-manual-ready" || bad "b1-manual-ready"
BPID="$MANUAL_PID"
want "$(port_holder "$APIP")" "$BPID" "b1-manual-holds-port"
run_install off start >"$TMP/b1b.log" 2>&1; rc=$?
want "$rc" 0 "b1-second-rc0"
want_in "检测到旧实例在运行" "$TMP/b1b.log" "b1-detected-log"
for _ in $(seq 1 50); do kill -0 "$BPID" 2>/dev/null || break; sleep 0.1; done
if kill -0 "$BPID" 2>/dev/null; then bad "b1-old-exited"; else ok "b1-old-exited"; fi
[ -z "$(port_holder "$APIP")" ] && ok "b1-port-free" || bad "b1-port-free"
printf '  PIDS: 无 systemd 旧 pid=%s（SIGTERM 后端口释放）\n' "$BPID"

say B2 "无 systemd：自家进程忽略 SIGTERM ⇒ 等 5 s 后 SIGKILL、rc=0"
reset_env
# **2.1.38**：自家实例的判据加了路径约束（realpath(/proc/<pid>/exe) 必须在前缀内），
# 所以这里的"SIGTERM 免疫"假二进制必须**占住前缀里的安装路径**（而不是 $TMP/fakebin）——
# 否则它会被正确地判为"前缀外的 ebpdns"并拒绝（那是 A5/S5 的判据）。
run_install off start >"$TMP/b2a.log" 2>&1
B2A_RC=$?
[ "$B2A_RC" = "0" ] && ok "b2-install-first" || bad "b2-install-first"
cp -aL "$(readlink -f "$(command -v python3)")" "$ROOT/usr/local/bin/.ebpdns-ign"
mv -f "$ROOT/usr/local/bin/.ebpdns-ign" "$ROOT/usr/local/bin/ebpdns"
"$ROOT/usr/local/bin/ebpdns" -c "
import signal, socket, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $APIP)); s.listen(5)
time.sleep(120)
" >"$TMP/b2-ignore.log" 2>&1 &
IPID=$!
PIDS="$PIDS $IPID"
for _ in $(seq 1 50); do [ -n "$(port_holder "$APIP")" ] && break; sleep 0.1; done
T0="$(date +%s)"
run_install off start >"$TMP/b2.log" 2>&1; rc=$?
T1="$(date +%s)"
want "$rc" 0 "b2-rc0"
want_in "SIGTERM" "$TMP/b2.log" "b2-sigterm-log"
want_in "SIGKILL" "$TMP/b2.log" "b2-sigkill-log"
ELAPSED=$((T1 - T0))
[ "$ELAPSED" -ge 5 ] && ok "b2-waited-${ELAPSED}s" || { bad "b2-waited-5s"; printf '    elapsed=%ss\n' "$ELAPSED"; }
if kill -0 "$IPID" 2>/dev/null; then bad "b2-ignorer-killed"; else ok "b2-ignorer-killed"; fi
[ -z "$(port_holder "$APIP")" ] && ok "b2-port-free" || bad "b2-port-free"

say B3 "无 systemd：别的进程占端口 ⇒ rc≠0、报 pid/exe/端口、未写文件"
reset_env
python3 - "$APIP" <<'PY' >"$TMP/foreign2.log" 2>&1 &
import socket, sys, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(5); time.sleep(120)
PY
FPID2=$!
PIDS="$PIDS $FPID2"
for _ in $(seq 1 50); do [ -n "$(port_holder "$APIP")" ] && break; sleep 0.1; done
run_install off start >"$TMP/b3.log" 2>&1; rc=$?
if [ "$rc" -ne 0 ]; then ok "b3-rc-nonzero"; else bad "b3-rc-nonzero"; fi
want_in "端口 $APIP" "$TMP/b3.log" "b3-port-in-message"
want_in "pid=$FPID2" "$TMP/b3.log" "b3-pid-in-message"
want_in "python" "$TMP/b3.log" "b3-exe-in-message"
[ ! -f "$ROOT/usr/local/bin/ebpdns" ] && ok "b3-no-write" || bad "b3-no-write"
kill -9 "$FPID2" 2>/dev/null || true

say B4 "无 systemd：--keep-running + 运行中实例 ⇒ rc=0、pid 不变（运行中的二进制被替换）"
reset_env
run_install off start >"$TMP/b4a.log" 2>&1; rc=$?
want "$rc" 0 "b4-first-rc0"
start_manual && ok "b4-manual-ready" || bad "b4-manual-ready"
KPID="$MANUAL_PID"
run_install off --keep-running start >"$TMP/b4b.log" 2>&1; rc=$?
want "$rc" 0 "b4-keep-rc0"
want "$(port_holder "$APIP")" "$KPID" "b4-pid-unchanged"
want_in "新二进制将在下次重启后生效" "$TMP/b4b.log" "b4-next-restart-hint"
if kill -0 "$KPID" 2>/dev/null; then ok "b4-process-alive"; else bad "b4-process-alive"; fi
[ -x "$ROOT/usr/local/bin/ebpdns" ] && ok "b4-binary-replaced" || bad "b4-binary-replaced"

# ===========================================================================
echo
echo "==================== T_INSTALL_RUNNING SUMMARY ===================="
if [ "$FAIL" -eq 0 ]; then
  echo "T_INSTALL_RUNNING=PASS（PASS=$PASS FAIL=0；A1–A6 systemd shim + B1–B4 无 systemd）"
  exit 0
fi
echo "T_INSTALL_RUNNING=FAIL（PASS=$PASS FAIL=$FAIL）"
exit 1
