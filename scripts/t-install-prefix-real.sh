#!/usr/bin/env bash
# ============================================================================
# **2.2.4（P2-G）**：`EBP_INSTALL_ROOT` 前缀安装 × **真 systemd** 回归。
#
# 背景（2.2.3 复审 R-1）：前缀把 unit 写进 `$PFX/etc/systemd/system`，而旧安装器
# 仍对**宿主** systemd 执行 `daemon-reload/enable/start` —— `enable` 找不到前缀内
# unit ⇒ 安装 rc=1；更早版本还会把前缀 unit 拷到宿主 `/etc/systemd/system`（触碰生产）。
# 2.2.4 起前缀模式 = 纯文件模式：只写 unit + 打印离线 enable 命令，**不调用宿主
# systemd**，安装 rc=0。
#
# **2.2.5（P2-A6/A7）**：本脚本用**真 systemd**（不是 mock）验证：
#   1. 前缀安装 rc=0，且前缀 unit 的 ExecStart/WorkingDirectory/ReadWritePaths 全部前缀化；
#   2. 宿主 `ebpdns.service` 文件 md5 / MainPID / NRestarts 安装前后不变；
#   3. 宿主 unit 列表里没有派生 unit（`ebpdns-<hash8>.service` 未被加载）；
#   4. 前缀端口没有被安装器启动（纯文件模式不 start）；
#   5. 安装器创建**相对**启用 symlink（`../<unit>`）→ 前缀内**不悬空**，
#      `systemctl --root=<前缀> is-enabled` 可识别；全前缀 `find -xtype l` 为空；
#   6. `uninstall --purge --force` rc=0、应用目录（含派生空父目录）清空、无悬空链接、
#      宿主仍不变。
#
# 安全：只写 `mktemp -d` 前缀；对宿主 systemd 只有**只读** show/is-active 调用；
# 绝不 stop/disable/restart 宿主 `ebpdns.service`。
#
# 用法：sudo bash scripts/t-install-prefix-real.sh <已解包的 prod 包目录>
# ============================================================================
set -u

PKG="${1:-}"
if [ -z "$PKG" ] || [ ! -x "$PKG/install.sh" ]; then
  echo "用法：sudo bash $0 <已解包的 prod 包目录>" >&2
  exit 2
fi
[ "$(id -u)" = "0" ] || { echo "需要 root（真 systemd + /etc/systemd/system 只读校验）" >&2; exit 2; }
command -v systemctl >/dev/null 2>&1 || { echo "SYSTEMD=SKIP（无 systemctl）"; exit 0; }
if ! systemctl is-system-running >/dev/null 2>&1; then
  ST="$(systemctl is-system-running 2>/dev/null || true)"
  case "$ST" in running|degraded|starting) ;; *) echo "SYSTEMD=SKIP（systemd 不可用：${ST:-unknown}）"; exit 0 ;; esac
fi

PASS=0; FAIL=0; SKIP=0
ok() { PASS=$((PASS + 1)); echo "PASS $*"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL $*"; }
skip() { SKIP=$((SKIP + 1)); echo "SKIP $*"; }
want() { if [ "$1" = "$2" ]; then ok "$3（$1）"; else bad "$3（实际=$1 期望=$2）"; fi; }
want_in() { if grep -qF -- "$1" "$2"; then ok "$3"; else bad "$3（缺 $1）"; fi; }

PFX="$(mktemp -d /tmp/ebpdns224real.XXXXXX)"
trap 'rm -rf "$PFX"' EXIT
HOST_UNIT=/etc/systemd/system/ebpdns.service
HOST_UNIT_MD5="$(md5sum "$HOST_UNIT" 2>/dev/null | awk '{print $1}')"
HOST_PID="$(systemctl show ebpdns -p MainPID --value 2>/dev/null | head -n1)"
HOST_NR="$(systemctl show ebpdns -p NRestarts --value 2>/dev/null | head -n1)"
HOST_ACTIVE="$(systemctl is-active ebpdns 2>/dev/null | head -n1)"

echo "== 前缀 $PFX；宿主 ebpdns: active=$HOST_ACTIVE pid=${HOST_PID:-?} NRestarts=${HOST_NR:-?} unit_md5=${HOST_UNIT_MD5:-none} =="

# 隔离端口：让前缀配置用高位端口（避免与生产 53/8353 冲突）。
APIP=$((18000 + RANDOM % 500))
DNSP=$((19000 + RANDOM % 500))
mkdir -p "$PFX/etc/ebpdns"
python3 - "$PKG/etc/ebpdns/config.json" "$PFX/etc/ebpdns/config.json" "$APIP" "$DNSP" "$PFX" <<'PY'
import json, sys
src, dst, api, dns, pfx = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
c = json.load(open(src, encoding="utf-8"))
c["dns_port"] = dns
c["listen"] = {"udp": "127.0.0.1:%d" % dns, "tcp": "127.0.0.1:%d" % dns,
                "udp6": "", "tcp6": ""}
c["api"] = {"host": "127.0.0.1", "port": api, "token": "t224real"}
c["upstreams"] = [{"id": "u1", "proto": "udp", "host": "223.5.5.5"}]
c["cache_file"] = pfx + "/var/lib/ebpdns/cache.bin"
c["state_dir"] = pfx + "/var/lib/ebpdns/state"
c["rules"] = []
c["rule_subscriptions"] = []
c["cache_persist"] = False
c["prefetch"] = False
c["speed_test"] = False
c["health_check_interval"] = 3600
c["log_level"] = "warn"
json.dump(c, open(dst, "w", encoding="utf-8"), indent=2)
PY

# ---- 1) 真 systemd + 前缀：必须 rc=0、纯文件模式 ----
LOG="$PFX/install.log"
EBP_INSTALL_ROOT="$PFX" EBP_SYSTEMD=on bash "$PKG/install.sh" start >"$LOG" 2>&1
RC=$?
want "$RC" 0 "install-rc0"
want_in "不调用宿主 systemd" "$LOG" "file-mode-log"
UNIT="$(EBP_INSTALL_ROOT="$PFX" bash "$PKG/install.sh" --unit-name)"
UNIT_PATH="$PFX/etc/systemd/system/$UNIT"
if [ -f "$UNIT_PATH" ]; then ok "prefix-unit-installed($UNIT)"; else bad "prefix-unit-installed($UNIT)"; fi
if grep -q "ExecStart=$PFX/usr/local/bin/ebpdns --config $PFX/etc/ebpdns/config.json" "$UNIT_PATH" 2>/dev/null; then
  ok "prefix-unit-execstart-prefixed"
else
  bad "prefix-unit-execstart-prefixed"
  grep -E '^(ExecStart|WorkingDirectory|ReadWritePaths)=' "$UNIT_PATH" 2>/dev/null | sed 's/^/    /'
fi
if grep -E '^(ExecStart|WorkingDirectory|ReadWritePaths)=' "$UNIT_PATH" 2>/dev/null | grep -vF -- "$PFX" | grep -q .; then
  bad "prefix-unit-no-host-paths"
else
  ok "prefix-unit-no-host-paths"
fi
# 安装器不得启动前缀端口（纯文件模式不 start）。
if ss -lntup 2>/dev/null | grep -q ":$DNSP "; then bad "install-did-not-start-dns($DNSP)"; else ok "install-did-not-start-dns($DNSP)"; fi
if ss -lntup 2>/dev/null | grep -q ":$APIP "; then bad "install-did-not-start-api($APIP)"; else ok "install-did-not-start-api($APIP)"; fi
# 宿主派生 unit 不得被加载。
if systemctl list-unit-files --no-legend "$UNIT" 2>/dev/null | grep -q "$UNIT"; then
  bad "host-does-not-see-derived-unit($UNIT)"
else
  ok "host-does-not-see-derived-unit($UNIT)"
fi

# **2.2.5（P2-A7）**：安装器自己创建**相对**启用 symlink（前缀内可解析、不悬空），
# 不再跑 `systemctl --root enable`（那会产生指向宿主绝对路径的悬空链接）。
WANTS="$PFX/etc/systemd/system/multi-user.target.wants/$UNIT"
if [ -L "$WANTS" ]; then ok "install-created-wants-symlink"; else bad "install-created-wants-symlink"; fi
LINK_TGT="$(readlink "$WANTS" 2>/dev/null || true)"
want "$LINK_TGT" "../$UNIT" "wants-symlink-is-relative"
if [ -e "$WANTS" ]; then ok "wants-symlink-not-dangling"; else bad "wants-symlink-not-dangling"; fi
# 真 systemd 只读核对：--root 下必须看到 enabled（相对链接在 root 内可解析）。
EN="$(systemctl --root="$PFX" is-enabled "$UNIT" 2>/dev/null | head -n1 || true)"
want "$EN" "enabled" "offline-is-enabled"
# 全前缀不得存在悬空链接（`find -xtype l` 精确匹配断链）。
DANGLING="$(find "$PFX" -xtype l 2>/dev/null | head -n5)"
want "$DANGLING" "" "prefix-has-no-dangling-symlink"

# ---- 3) 宿主面不变 ----
NOW_MD5="$(md5sum "$HOST_UNIT" 2>/dev/null | awk '{print $1}')"
want "$NOW_MD5" "$HOST_UNIT_MD5" "host-unit-md5-unchanged"
want "$(systemctl show ebpdns -p MainPID --value 2>/dev/null | head -n1)" "$HOST_PID" "host-mainpid-unchanged"
want "$(systemctl show ebpdns -p NRestarts --value 2>/dev/null | head -n1)" "$HOST_NR" "host-nrestarts-unchanged"
want "$(systemctl is-active ebpdns 2>/dev/null | head -n1)" "$HOST_ACTIVE" "host-active-unchanged"

# ---- 4) uninstall --purge --force：rc=0、前缀清空、宿主不变 ----
EBP_INSTALL_ROOT="$PFX" EBP_SYSTEMD=on bash "$PKG/install.sh" uninstall --purge --force >"$PFX/uninstall.log" 2>&1
want "$?" 0 "uninstall-rc0"
# 卸载删除**文件/数据**，并回收**派生空父目录**（只删空目录，不碰用户文件）。
if [ ! -e "$PFX/usr/local/bin/ebpdns" ] \
   && [ ! -e "$PFX/usr/local/share/ebpdns" ] \
   && [ ! -e "$PFX/etc/ebpdns" ] \
   && [ ! -e "$PFX/var/lib/ebpdns" ] \
   && [ ! -e "$UNIT_PATH" ] \
   && [ ! -L "$WANTS" ]; then
  ok "uninstall-purged-prefix"
else
  bad "uninstall-purged-prefix"
  find "$PFX" -maxdepth 6 | sed 's/^/    /' | head -30
fi
want "$(find "$PFX" -xtype l 2>/dev/null | head -n5)" "" "no-dangling-after-uninstall"
want "$(md5sum "$HOST_UNIT" 2>/dev/null | awk '{print $1}')" "$HOST_UNIT_MD5" "host-unit-md5-unchanged-after-uninstall"
want "$(systemctl is-active ebpdns 2>/dev/null | head -n1)" "$HOST_ACTIVE" "host-active-unchanged-after-uninstall"

echo "T_INSTALL_PREFIX_REAL: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
[ "$FAIL" = "0" ]
