#!/usr/bin/env bash
# ============================================================================
# ebpdns 2.1.32：**干净机安装验收矩阵**（1–9；10 为容器能力探测）
#
#   sudo bash scripts/t-install-matrix.sh              # 全矩阵
#   sudo bash scripts/t-install-matrix.sh --only 2     # 只跑第 2 行
#   EBP_MATRIX_KEEP=1 ...                              # 保留临时目录
#
# 安全：全部动作发生在 mktemp 临时前缀里；EBP_INSTALL_ROOT / EBP_PASSWD_FILE /
# EBP_GROUP_FILE / EBP_PWD_LOCK 把安装器的系统路径整体重定向；PATH 用最小命令集
# （getent/id/systemctl/groupadd 全是测试 shim），**不碰**真机 /etc、/usr/local、
# /var/lib、systemd 与 53/8353 端口。
#
# 退出码：0 = 全部 PASS（或按 --only 的子集全 PASS；容器能力缺失记 SKIP）；
#         1 = 至少一项 FAIL。
# ============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL_SRC="$HERE/packaging/install.sh"
UNIT_SRC="$HERE/packaging/systemd/ebpdns.service"
CFG_SRC="$HERE/packaging/etc/ebpdns/config.json"
REAL_BIN="${EBP_BIN:-$HERE/target/release/ebpdns}"
ONLY=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --only) ONLY="${2:-}"; shift 2 ;;
    --only=*) ONLY="${1#--only=}"; shift ;;
    *) echo "未知参数：$1" >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "INSTALL_MATRIX=SKIP（需要 root 才能跑 install.sh 的 require_root；当前 uid=$(id -u)）"
  exit 0
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/ebpdns-matrix-XXXXXX")" || exit 1
cleanup() { [ "${EBP_MATRIX_KEEP:-0}" = "1" ] || rm -rf "$TMP"; }
trap cleanup EXIT

PASS=0
FAIL=0
SKIP=0
declare -a ROWS=()
row() { ROWS+=("$1"); }

say() { printf '\n=== [%s] %s\n' "$1" "$2"; }
ok() { PASS=$((PASS + 1)); printf '  RESULT: PASS  (%s)\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  RESULT: FAIL  (%s)\n' "$1"; }
skip() { SKIP=$((SKIP + 1)); printf '  RESULT: SKIP  (%s)\n' "$1"; }
want() { [ "$1" = "$2" ] && ok "$3" || { bad "$3"; printf '    got=%r want=%r\n' "$1" "$2"; }; }

# ---------------------------------------------------------------------------
# 测试环境：临时 passwd/group + 最小 PATH + shims
# ---------------------------------------------------------------------------
REALPATH_DIR="$TMP/realbin"
SHIM="$TMP/shim"
NOTOOLS="$TMP/notools"
NOSYSTEMD="$TMP/nosystemd"
mkdir -p "$REALPATH_DIR" "$SHIM" "$NOTOOLS" "$NOSYSTEMD"
PASSWD_DB="$TMP/etc/passwd"
GROUP_DB="$TMP/etc/group"
mkdir -p "$TMP/etc"
printf 'root:x:0:0:root:/root:/bin/sh\n' >"$PASSWD_DB"
printf 'root:x:0:\n' >"$GROUP_DB"
export EBP_PASSWD_FILE="$PASSWD_DB" EBP_GROUP_FILE="$GROUP_DB" EBP_PWD_LOCK="$TMP/etc/.pwd.lock"

# 真命令：只保留安装器实际用到的 POSIX 基础工具（**不含** ss/lsof/ip/systemctl）。
for c in bash sh env sed grep cat cp mv rm mkdir mktemp install chmod chown find sort \
         awk dirname basename tail head tr wc cut date seq flock sleep kill ps stat \
         touch diff curl; do
  p="$(command -v "$c" 2>/dev/null || true)"
  [ -n "$p" ] && ln -sf "$p" "$REALPATH_DIR/$c"
done

cat >"$SHIM/getent" <<'EOS'
#!/bin/sh
db="$1"; key="$2"
case "$db" in
  group) file="$EBP_GROUP_FILE" ;;
  passwd) file="$EBP_PASSWD_FILE" ;;
  *) exit 2 ;;
esac
[ -f "$file" ] || exit 2
if printf '%s' "$key" | grep -qE '^[0-9]+$'; then
  awk -F: -v k="$key" '$3==k{print; found=1} END{exit !found}' "$file"
else
  awk -F: -v k="$key" '$1==k{print; found=1} END{exit !found}' "$file"
fi
EOS

cat >"$SHIM/id" <<'EOS'
#!/bin/sh
if [ "${1:-}" = "-u" ]; then echo 0; exit 0; fi
if [ "${1:-}" = "-g" ]; then echo 0; exit 0; fi
exec getent passwd "${1:-root}"
EOS

cat >"$SHIM/systemctl" <<'EOS'
#!/bin/sh
echo "systemctl $*" >>"$EBP_SYSTEMCTL_LOG"
case "${1:-}" in
  is-system-running) echo running; exit 0 ;;
  restart|start) echo active >"$EBP_SERVICE_STATE"; exit 0 ;;
  stop) echo inactive >"$EBP_SERVICE_STATE"; exit 0 ;;
  *) exit 0 ;;
esac
EOS

cat >"$SHIM/chown" <<'EOS'
#!/bin/sh
echo "chown $*" >>"$EBP_CHOWN_LOG"
exit 0
EOS

cat >"$SHIM/setcap" <<'EOS'
#!/bin/sh
exit 0
EOS

cat >"$SHIM/groupadd" <<'EOS'
#!/bin/sh
echo "groupadd $*" >>"$EBP_USERTOOL_LOG"
printf 'ebpdns:x:999:\n' >>"$EBP_GROUP_FILE"
exit 0
EOS

cat >"$SHIM/useradd" <<'EOS'
#!/bin/sh
echo "useradd $*" >>"$EBP_USERTOOL_LOG"
printf 'ebpdns:x:998:999::/var/lib/ebpdns:/usr/sbin/nologin\n' >>"$EBP_PASSWD_FILE"
exit 0
EOS

cat >"$NOTOOLS/groupadd" <<'EOS'
#!/bin/sh
echo "groupadd: not found" >&2; exit 127
EOS
for t in useradd addgroup adduser; do
  cat >"$NOTOOLS/$t" <<'EOS'
#!/bin/sh
echo "$0: not found" >&2; exit 127
EOS
done
chmod +x "$SHIM"/* "$NOTOOLS"/*

# no-systemd：除 systemctl 之外的同一套 shim + 真命令
for f in "$SHIM"/*; do
  b="$(basename "$f")"
  [ "$b" = "systemctl" ] || ln -sf "$f" "$NOSYSTEMD/$b"
done
for f in "$REALPATH_DIR"/*; do ln -sf "$f" "$NOSYSTEMD/$(basename "$f")"; done

BASE_PATH="$SHIM:$REALPATH_DIR"
NOTOOLS_PATH="$NOTOOLS:$BASE_PATH"
NOSYSTEMD_PATH="$NOSYSTEMD"
export EBP_SYSTEMCTL_LOG="$TMP/systemctl.log"
export EBP_SERVICE_STATE="$TMP/service.state"
export EBP_CHOWN_LOG="$TMP/chown.log"
export EBP_USERTOOL_LOG="$TMP/usertools.log"

# ---------------------------------------------------------------------------
# 包 + 假二进制
# ---------------------------------------------------------------------------
STAGE="$TMP/pkg/ebpdns-2.1.32"
mkdir -p "$STAGE/bin" "$STAGE/etc/ebpdns" "$STAGE/systemd" "$STAGE/web"
cp -a "$INSTALL_SRC" "$STAGE/install.sh"
cp -a "$UNIT_SRC" "$STAGE/systemd/ebpdns.service"
cp -a "$CFG_SRC" "$STAGE/etc/ebpdns/config.json"
printf '<html>ok</html>\n' >"$STAGE/web/index.html"
cat >"$STAGE/bin/ebpdns" <<'EOS'
#!/bin/sh
case "${1:-}" in
  --version)
    if [ "${FAKE_VERSION_RC:-0}" != "0" ]; then
      echo "ebpdns: error while loading shared libraries: libc.so.6: version \`GLIBC_2.99' not found" >&2
      exit "${FAKE_VERSION_RC}"
    fi
    echo "ebpdns 2.1.32"
    ;;
  check-config) echo "CONFIG OK" ;;
  migrate-config) echo "MIGRATE-SUMMARY missing_keys: 0" ;;
esac
exit 0
EOS
chmod +x "$STAGE/install.sh" "$STAGE/bin/ebpdns"

# 把模板端口改成高位（避免真机 53/8353 干扰）
python3 - "$STAGE/etc/ebpdns/config.json" <<'PY' 2>/dev/null || true
import json, sys
p = sys.argv[1]
c = json.load(open(p))
c["api"] = {"host": "127.0.0.1", "port": 19853, "token": ""}
c["listen"] = {"udp": "127.0.0.1:19854", "tcp": "127.0.0.1:19854", "udp6": "", "tcp6": ""}
c["dns_port"] = 19854
c["state_dir"] = "/var/lib/ebpdns/state"
c["upstreams"] = []
c["rule_subscriptions"] = []
c["rules"] = []
json.dump(c, open(p, "w"), indent=2)
PY

ROOT="$TMP/root"
reset_root() {
  rm -rf "$ROOT"
  mkdir -p "$ROOT/etc/systemd/system" "$ROOT/usr/local/bin" "$ROOT/var/lib/ebpdns" "$ROOT/etc/ebpdns"
  printf 'root:x:0:0:root:/root:/bin/sh\n' >"$PASSWD_DB"
  printf 'root:x:0:\n' >"$GROUP_DB"
  : >"$EBP_SYSTEMCTL_LOG"
  : >"$EBP_CHOWN_LOG"
  : >"$EBP_USERTOOL_LOG"
  rm -f "$EBP_SERVICE_STATE"
}

run_install() { # $1 = PATH, 其余 = install.sh 参数
  local path="$1"; shift
  EBP_INSTALL_ROOT="$ROOT" PATH="$path" bash "$STAGE/install.sh" "$@"
}

want_in() { # $1 = needle, $2 = file, $3 = label
  if grep -qF -- "$1" "$2"; then ok "$3"; else bad "$3"; printf '    missing=%s in %s\n' "$1" "$2"; fi
}

# 可选：实二进制 API 200（有构建产物时才跑；与安装脚本解耦，只作最小 API 门）
api_200() {
  [ -x "$REAL_BIN" ] || { skip "api-200(no-real-bin)"; return 0; }
  local d cfg port dport out rc pid
  d="$(mktemp -d "$TMP/api-XXXX")"
  port="$(python3 - <<'PY'
import socket
s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()
PY
)"
  dport="$(python3 - <<'PY'
import socket
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()
PY
)"
  cfg="$d/config.json"
  printf '{"api":{"host":"127.0.0.1","port":%s,"token":"m231t"},"listen":{"udp":"127.0.0.1:%s","tcp":"127.0.0.1:%s","udp6":"","tcp6":""},"dns_port":%s,"web_root":"","cache_size":64,"cache_persist":false,"state_dir":"%s/state","prefetch":false,"speed_test":false,"warmup":{"enabled":false,"queries":0,"timeout_ms":500},"health_check_interval":3600,"rule_subscriptions":[],"rules":[],"upstreams":[],"log_level":"warn"}\n' \
    "$port" "$dport" "$dport" "$dport" "$d" >"$cfg"
  mkdir -p "$d/state"
  "$REAL_BIN" --config "$cfg" --state-dir "$d/state" --foreground >"$d/log" 2>&1 &
  pid=$!
  out=""
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    out="$(curl -s -m 2 -H 'Authorization: Bearer m231t' "http://127.0.0.1:$port/api/health" 2>/dev/null || true)"
    printf '%s' "$out" | grep -q '"running"' && break
    sleep 0.2
  done
  if printf '%s' "$out" | grep -q '"running"'; then ok "api-200"; else bad "api-200"; printf '    out=%s\n' "$out"; tail -10 "$d/log" 2>/dev/null; fi
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  rm -rf "$d"
}

# ---------------------------------------------------------------------------
# 场景实现
# ---------------------------------------------------------------------------
run_1() { # 全新机（有 systemd、有 passwd）
  say 1 "全新机：有 systemd + 有 passwd 工具"
  reset_root
  local log="$TMP/s1.log" rc
  run_install "$BASE_PATH" start >"$log" 2>&1; rc=$?
  want "$rc" 0 "s1-rc0"
  [ -f "$ROOT/usr/local/bin/ebpdns" ] && ok "s1-bin" || bad "s1-bin"
  [ -f "$ROOT/etc/ebpdns/config.json" ] && ok "s1-config" || bad "s1-config"
  want_in "ebpdns:x:" "$GROUP_DB" "s1-group-created"
  want_in "ebpdns:x:" "$PASSWD_DB" "s1-user-created"
  # **2.1.38**：非默认前缀的 unit 名是派生的（`ebpdns-<hash8>.service`），故只匹配前缀。
  grep -q 'restart ebpdns' "$EBP_SYSTEMCTL_LOG" && ok "s1-service-started" || { bad "s1-service-started"; cat "$EBP_SYSTEMCTL_LOG"; }
  api_200
  row "1|fresh(systemd+passwd)|rc=$rc|bin/config/user/group/service OK"
}

run_2() { # 无 groupadd/useradd/addgroup/adduser
  say 2 "无 passwd 工具：PATH 遮蔽 groupadd/useradd/addgroup/adduser"
  reset_root
  local log="$TMP/s2.log" rc
  run_install "$NOTOOLS_PATH" start >"$log" 2>&1; rc=$?
  want "$rc" 0 "s2-rc0"
  want_in "ebpdns:x:" "$GROUP_DB" "s2-group-db"
  want_in "ebpdns:x:" "$PASSWD_DB" "s2-user-db"
  grep -q 'restart ebpdns' "$EBP_SYSTEMCTL_LOG" && ok "s2-service-started" || bad "s2-service-started"
  grep -q '直接追加' "$log" && ok "s2-log-fallback" || { bad "s2-log-fallback"; tail -20 "$log"; }
  # 极端：账号库不可写（路径不存在）⇒ 必须 rc=0 + 明确 WARN，不得中止。
  local nowrite="$TMP/nowrite"
  rm -rf "$nowrite"
  EBP_GROUP_FILE="$nowrite/group" EBP_PASSWD_FILE="$nowrite/passwd" \
    run_install "$NOTOOLS_PATH" >"$TMP/s2b.log" 2>&1
  local rc2=$?
  want "$rc2" 0 "s2b-rc0-unwritable"
  grep -q '无法创建运行账号' "$TMP/s2b.log" && ok "s2b-warn" || { bad "s2b-warn"; tail -20 "$TMP/s2b.log"; }
  [ -f "$ROOT/usr/local/bin/ebpdns" ] && ok "s2b-installed" || bad "s2b-installed"
  row "2|no usertools|rc=$rc/$rc2|db fallback OK; unwritable => WARN + rc0"
}

run_3() { # 无 systemd
  say 3 "无 systemd：遮蔽 systemctl"
  reset_root
  local log="$TMP/s3.log" rc
  run_install "$NOSYSTEMD_PATH" start >"$log" 2>&1; rc=$?
  want "$rc" 0 "s3-rc0"
  [ -f "$ROOT/usr/local/bin/ebpdns" ] && ok "s3-bin" || bad "s3-bin"
  grep -q '未检测到可用的 systemd' "$log" && ok "s3-manual-hint" || { bad "s3-manual-hint"; tail -20 "$log"; }
  grep -q -- '--config' "$log" && grep -q -- '--foreground' "$log" && ok "s3-manual-command" || bad "s3-manual-command"
  [ ! -f "$EBP_SERVICE_STATE" ] && ok "s3-no-systemd-start" || bad "s3-no-systemd-start"
  row "3|no systemd|rc=$rc|files installed + manual start hint"
}

run_4() { # 缺 ip/ss/lsof
  say 4 "缺 ip/ss/lsof：端口检查退化"
  reset_root
  local log="$TMP/s4.log" rc
  run_install "$BASE_PATH" >"$log" 2>&1; rc=$?
  want "$rc" 0 "s4-rc0"
  # BASE_PATH 刻意不含 ss/lsof/ip
  if PATH="$BASE_PATH" command -v ss >/dev/null 2>&1; then bad "s4-no-ss"; else ok "s4-no-ss"; fi
  grep -q '端口' "$log" && ok "s4-port-check" || bad "s4-port-check"
  row "4|no ip/ss/lsof|rc=$rc|/proc fallback + port check OK"
}

run_5() { # 端口占用
  say 5 "端口占用：dns_port 被占用必须 rc≠0 且不写文件"
  reset_root
  local port=19854 log="$TMP/s5.log" rc pid
  # 用最简 Python 占住 TCP 端口
  cat >"$TMP/hold.py" <<'PY'
import socket, time, sys
p = int(sys.argv[1])
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", p))
s.listen(5)
time.sleep(60)
PY
  python3 "$TMP/hold.py" "$port" >"$TMP/hold.log" 2>&1 &
  pid=$!
  sleep 0.3
  run_install "$BASE_PATH" >"$log" 2>&1; rc=$?
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  if [ "$rc" -ne 0 ]; then ok "s5-rc-nonzero"; else bad "s5-rc-nonzero"; fi
  grep -q "端口 $port 已被占用" "$log" && ok "s5-message" || { bad "s5-message"; tail -20 "$log"; }
  [ ! -f "$ROOT/usr/local/bin/ebpdns" ] && ok "s5-no-write" || bad "s5-no-write"
  row "5|port busy|rc=$rc|explicit error, no files written"
}

run_6() { # glibc
  say 6 "glibc 不足：假二进制 --version 失败必须预检中止"
  reset_root
  local log="$TMP/s6.log" rc
  FAKE_VERSION_RC=1 run_install "$BASE_PATH" >"$log" 2>&1; rc=$?
  if [ "$rc" -ne 0 ]; then ok "s6-rc-nonzero"; else bad "s6-rc-nonzero"; fi
  grep -q 'GLIBC_2.99' "$log" && ok "s6-glibc-message" || { bad "s6-glibc-message"; tail -20 "$log"; }
  [ ! -f "$ROOT/usr/local/bin/ebpdns" ] && ok "s6-no-install" || bad "s6-no-install"
  row "6|glibc too old|rc=$rc|preflight aborts with GLIBC reason"
}

run_7() { # 幂等
  say 7 "重复安装 ×2：配置/state 不破坏"
  reset_root
  local log1="$TMP/s7a.log" log2="$TMP/s7b.log" rc1 rc2 md1 md2 st1 st2
  run_install "$BASE_PATH" start >"$log1" 2>&1; rc1=$?
  md1="$(md5sum "$ROOT/etc/ebpdns/config.json" | awk '{print $1}')"
  st1="$(find "$ROOT/var/lib/ebpdns" -type f -printf '%p\n' | sort | md5sum | awk '{print $1}')"
  run_install "$BASE_PATH" start >"$log2" 2>&1; rc2=$?
  md2="$(md5sum "$ROOT/etc/ebpdns/config.json" | awk '{print $1}')"
  st2="$(find "$ROOT/var/lib/ebpdns" -type f -printf '%p\n' | sort | md5sum | awk '{print $1}')"
  want "$rc1" 0 "s7-first-rc0"
  want "$rc2" 0 "s7-second-rc0"
  want "$md1" "$md2" "s7-config-preserved"
  want "$st1" "$st2" "s7-state-preserved"
  [ "$(grep -c 'groupadd' "$EBP_USERTOOL_LOG")" -le 1 ] && ok "s7-user-not-recreated" || bad "s7-user-not-recreated"
  row "7|install x2|rc=$rc1/$rc2|CONFIG_PRESERVED=YES"
}

run_8() { # uninstall -> install
  say 8 "--uninstall 后重装：保留 /etc/ebpdns 与 state"
  reset_root
  local log1="$TMP/s8a.log" log2="$TMP/s8b.log" rc1 rc2 md1 md2
  run_install "$BASE_PATH" start >"$log1" 2>&1; rc1=$?
  md1="$(md5sum "$ROOT/etc/ebpdns/config.json" | awk '{print $1}')"
  run_install "$BASE_PATH" --uninstall >"$log2" 2>&1; rc2=$?
  [ ! -f "$ROOT/usr/local/bin/ebpdns" ] && ok "s8-bin-removed" || bad "s8-bin-removed"
  [ -f "$ROOT/etc/ebpdns/config.json" ] && ok "s8-config-kept" || bad "s8-config-kept"
  run_install "$BASE_PATH" start >>"$log2" 2>&1; rc3=$?
  md2="$(md5sum "$ROOT/etc/ebpdns/config.json" | awk '{print $1}')"
  want "$rc1" 0 "s8-install-rc0"
  want "$rc2" 0 "s8-uninstall-rc0"
  want "$rc3" 0 "s8-reinstall-rc0"
  want "$md1" "$md2" "s8-config-preserved"
  row "8|uninstall->install|rc=$rc1/$rc2/$rc3|config+state preserved"
}

run_9() { # dry-run
  say 9 "--dry-run：系统零变更"
  reset_root
  local before after log="$TMP/s9.log" rc
  before="$(find "$ROOT" -type f -printf '%p\n' | sort)"
  run_install "$BASE_PATH" --dry-run start >"$log" 2>&1; rc=$?
  after="$(find "$ROOT" -type f -printf '%p\n' | sort)"
  want "$rc" 0 "s9-rc0"
  want "$before" "$after" "s9-zero-change"
  grep -q '\[dry-run\]' "$log" && ok "s9-plan" || bad "s9-plan"
  row "9|--dry-run|rc=$rc|zero file changes"
}

run_10() { # 容器能力
  say 10 "真容器干净机（docker/podman 可用时才执行）"
  local eng=""
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then eng=docker; fi
  if [ -z "$eng" ] && command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then eng=podman; fi
  if [ -z "$eng" ]; then
    skip "container(no docker/podman capacity)"
    row "10|container debian:13-slim|SKIP|no container capability on host"
    return 0
  fi
  if ! "$eng" image inspect debian:13-slim >/dev/null 2>&1; then
    # 有引擎但本地无镜像：尝试拉取（容器行要求"有 docker/podman ⇒ 真跑"）；
    # 拉取失败则如实 SKIP，不把"没跑"写成绿。
    if ! "$eng" pull debian:13-slim >"$TMP/s10-pull.log" 2>&1; then
      skip "container(image debian:13-slim unavailable: pull failed)"
      row "10|container debian:13-slim|SKIP|image not present and pull failed"
      return 0
    fi
  fi
  # 容器内：解包 → bin --version → check-config → install.sh start（无 systemd）
  # 三个 rc 分开记录；install.sh 用 EBP_SYSTEMD=0 走"无 systemd"分支。
  local out rc
  out="$("$eng" run --rm -v "$STAGE:/pkg:ro" debian:13-slim sh -c '
    set +e
    cd /tmp && cp -a /pkg ./ebpdns-2.1.32 && cd ebpdns-2.1.32 && chmod +x install.sh bin/ebpdns
    ./bin/ebpdns --version; VRC=$?
    ./bin/ebpdns check-config --config etc/ebpdns/config.json; CRC=$?
    EBP_SYSTEMD=0 ./install.sh start; IRC=$?
    echo "CONTAINER_VERSION_RC=$VRC"
    echo "CONTAINER_CHECK_CONFIG_RC=$CRC"
    echo "CONTAINER_INSTALL_RC=$IRC"
    exit $IRC
  ' 2>&1)"
  rc=$?
  printf '%s\n' "$out" | tail -30
  if [ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -q 'CONTAINER_INSTALL_RC=0'; then
    ok "s10-container"
  else
    bad "s10-container"
  fi
  row "10|container debian:13-slim|rc=$rc|version+check-config+install(no systemd)"
}

# ---------------------------------------------------------------------------
# 执行
# ---------------------------------------------------------------------------
echo "########## ebpdns 2.1.31 干净机安装验收矩阵 $(date '+%F %T %z') ##########"
echo "TMP=$TMP  ROOT=$ROOT  REAL_BIN=$REAL_BIN"
for n in 1 2 3 4 5 6 7 8 9 10; do
  if [ -n "$ONLY" ]; then
    case "$ONLY" in
      1-9) [ "$n" = "10" ] && continue ;;
      *) [ "$n" != "$ONLY" ] && continue ;;
    esac
  fi
  "run_$n"
done

echo
echo "==================== MATRIX SUMMARY ===================="
for r in "${ROWS[@]}"; do printf '%s\n' "$r"; done
if [ "$FAIL" -eq 0 ]; then
  echo "INSTALL_MATRIX=PASS（PASS=$PASS SKIP=$SKIP FAIL=0）"
  exit 0
fi
echo "INSTALL_MATRIX=FAIL（PASS=$PASS SKIP=$SKIP FAIL=$FAIL）"
exit 1
