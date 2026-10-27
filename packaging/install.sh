#!/usr/bin/env bash
# ebpdns v2.1.49 安装脚本（Rust 版；以 Python v1.9.162 为行为参照）
# 用法：
#   sudo ./install.sh            # 安装并 enable（不自动 start）
#   sudo ./install.sh start      # 安装、enable 并立即 start
#   sudo ./install.sh uninstall  # 卸载（默认保留配置与 state_dir）
#   sudo ./install.sh --help     # 打印全部开关与退出码
#
# **2.1.38（安装器隔离：两条生产事故的根因）**——
#   事故 #1（22:38:42）：端口预检读**包内**默认配置（`$(dirname "$0")/etc/ebpdns/config.json`，
#     53/8353），不跟随 `EBP_INSTALL_ROOT` ⇒ 隔离前缀安装把**生产实例**当"自家旧实例" SIGTERM。
#   事故 #2（23:06:19）：包自测 PATH 无隔离 shim ⇒ `install.sh uninstall` 直接 stop + disable
#     **真 systemd unit**（生产中断 35 min）。
#   五条修法（行为契约见 docs/PACKAGING.md §3.3）：
#     ① 端口**只**从目标前缀配置（`$EBP_INSTALL_ROOT/etc/ebpdns/config.json`）取，
#        显式 `EBP_INSTALL_PORTS` 优先；不再无条件读包内默认配置；
#     ② "自家实例"判定加**路径约束**：`realpath(/proc/<pid>/exe)` 必须落在目标前缀内
#        （或 unit 文件在前缀内）才可停，否则 rc≠0 并报出 pid/exe/端口；
#     ③ unit 名与前缀绑定：非默认前缀派生 `ebpdns-<hash>.service`（`--unit-name` 可查）；
#        `uninstall` 先校验 unit 路径在前缀内，否则拒绝（rc≠0）；
#     ④ 默认安全：`--dry-run` / 前缀模式默认不执行破坏性动作，破坏性动作先打印
#        目标 `pid/exe/unit`，无法证明归属时一律拒绝（`--force` 只放开两处具名例外）；
#     ⑤ 回归：`scripts/t-install-isolation.sh`（fake systemctl + 前缀，五个场景）。
#
# **2.1.32（start 语义）**：`start` 时若检测到**本服务已在运行**（systemd active，或
# 配置端口被 basename 为 `ebpdns` 的进程持有）⇒ 打印 INFO、先停止旧实例、确认端口释放，
# 再继续安装/启动，最终 rc=0。端口被**别的进程**占用仍 rc=1 并报 pid/exe/端口。
# 新增 `--restart`（显式先停后启）、`--keep-running`（只更新文件、不动运行中的进程，
# 端口占用降为 WARN）、`--dry-run`（打印动作）。无 systemd 时同一语义：
# 自家进程 ⇒ SIGTERM → 等 5 s → SIGKILL；其它进程占端口 ⇒ rc≠0。
#
# **2.1.31（干净机安装）**：不再假设目标机有 `passwd` 包或 systemd —— 用户/组缺失时
# 分级回退（groupadd → addgroup → 直接追加 /etc/group；useradd → adduser → /etc/passwd），
# 全失败只 WARN 并继续（chown 退化为 root:root、unit 退化为 User=root）；无 systemctl
# 时只装文件并打印手动启动命令。另加：二进制可运行性预检（GLIBC）、端口占用预检、
# `--dry-run`、`--uninstall` / `--purge`。
set -euo pipefail

# 测试/容器可用：EBP_INSTALL_ROOT 把系统路径整体前缀到临时目录（生产不设 = 空）。
INSTALL_ROOT="${EBP_INSTALL_ROOT:-}"
PFX_REAL=""          # 目标前缀的 realpath（2.1.38：所有归属判定都用它，init_paths 里算）
BIN_DST="$INSTALL_ROOT/usr/local/bin/ebpdns"
WEB_DST="$INSTALL_ROOT/usr/local/share/ebpdns/web"
CONF_DIR="$INSTALL_ROOT/etc/ebpdns"
CONF_FILE="$CONF_DIR/config.json"
STATE_DIR="$INSTALL_ROOT/var/lib/ebpdns"
# **2.1.38（unit 名与前缀绑定）**：SERVICE 不再是常量 —— 默认前缀（INSTALL_ROOT 为空）
# 沿用 `ebpdns.service`；非默认前缀派生 `ebpdns-<hash8>.service`（hash = realpath(前缀) 的
# md5 前 8 位）。理由：`systemctl stop ebpdns.service` 命中的是**系统级** unit，与
# `EBP_INSTALL_ROOT` 无关 —— 事故 #2 正是这样停掉了生产。派生名让前缀安装**不可能**命中它。
# `--unit-name` 打印派生结果（只读），供部署脚本与回归测试使用。
SERVICE=""
SERVICE_DIR="$INSTALL_ROOT/etc/systemd/system"
SERVICE_PATH=""
SERVICE_SRC="$(dirname "$0")/systemd/ebpdns.service"
# 事故 #2 的第二层：uninstall 只认"前缀里确实存在的那个 unit 文件"，并校验其路径在前缀内。
UNIT_SCOPE_ERR=""
RUN_USER=ebpdns
RUN_GROUP=ebpdns
# 测试钩子：把 /etc/passwd、/etc/group、flock 锁文件指到临时文件（默认就是真实路径）。
PASSWD_FILE="${EBP_PASSWD_FILE:-/etc/passwd}"
GROUP_FILE="${EBP_GROUP_FILE:-/etc/group}"
PWD_LOCK="${EBP_PWD_LOCK:-/etc/.pwd.lock}"
# **2.1.38（端口来源）**：端口**只**从目标前缀配置 `$CONF_FILE` 取；显式 `EBP_INSTALL_PORTS`
# 优先。事故 #1 的根因是 2.1.37 的调用点写死 `$(dirname "$0")/etc/ebpdns/config.json`
# （包内 53/8353），与 `EBP_INSTALL_ROOT` 无关。PORTS_SOURCE 记录本次用的来源（日志可核）。
PORTS_OVERRIDE="${EBP_INSTALL_PORTS:-}"
PORTS_SOURCE=""

MIGRATE_STATE_DIR=""
DRY_RUN=0
PURGE=0
FORCE=0          # --force：只放开两处具名例外（见 usage / uninstall），绝不覆盖进程归属判定
SERVICE_ACCOUNT_OK=0
SYSTEMD_MODE="auto" # auto | on | off（测试可用 EBP_SYSTEMD=0 强制关闭）
case "${EBP_SYSTEMD:-auto}" in
  0|off|no) SYSTEMD_MODE="off" ;;
  1|on|yes) SYSTEMD_MODE="on" ;;
  *) SYSTEMD_MODE="auto" ;;
esac
# **2.1.32**：start 的运行实例语义。
RESTART=0       # --restart：显式「先停后启」（等价 start 的默认行为）
KEEP_RUNNING=0  # --keep-running：只更新文件，不停止/不重启运行中的进程
OLD_PIDS=""     # 端口上 exe=ebpdns 且**路径在前缀内**的 pid 列表（空格分隔）
OLD_PID=""      # systemd 报告的 MainPID（优先用于日志）
SERVICE_WAS_ACTIVE=0
SERVICE_FRAG=""    # systemd 报告的 FragmentPath（2.1.38：unit 归属判据）
FOREIGN_HOLDERS="" # 每行「端口|pid|exe」：exe 不是 ebpdns 的占用者
NONPREFIX_HOLDERS="" # 每行「端口|pid|exe」：是 ebpdns 但**不在目标前缀内**（2.1.38 新判据）
PORTS=""           # configured_ports 的结果（空格分隔）
EFFECTIVE_START=0  # action=start 或 --restart

log() { printf '\033[1;32m[install]\033[0m %s\n' "$*"; }
info() { printf '\033[1;36m[info]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
err() { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; }

# ============================================================================
# **2.1.38**：路径/前缀/归属判定的公共件
# ============================================================================
# 绝对路径（不要求存在）：realpath -m → cd/pwd -P → 手工拼接。
_abs_path() {
  local p="${1:-}"
  [ -n "$p" ] || { printf '\n'; return 0; }
  if command -v realpath >/dev/null 2>&1; then
    realpath -m -- "$p" 2>/dev/null && return 0
  fi
  if [ -d "$p" ]; then
    ( cd "$p" 2>/dev/null && pwd -P ) && return 0
  fi
  case "$p" in
    /*) printf '%s\n' "$p" ;;
    *) printf '%s/%s\n' "$PWD" "$p" ;;
  esac
}

# 依据目标前缀派生 SERVICE / SERVICE_PATH / PFX_REAL。**只读**，可在 --unit-name 里单独调用。
#
# 派生名只用"不与系统级 ebpdns.service 同名"这个目的，不需要密码学强度；因此这里对
# **外部命令缺失**是**硬容忍**的（2.1.38 实测：`t-install-matrix.sh` 的受限 PATH 里没有
# md5sum/cksum，而 `set -o pipefail` 会让 `h="$(… | md5sum …)"` 直接以 rc=127 终止整个
# 安装器 —— 那是"工具缺失导致安装失败"，不是隔离语义）。三级退化：md5sum → cksum → bash 内建。
_prefix_digest8() {
  local s="${1:-}" h=""
  if command -v md5sum >/dev/null 2>&1; then
    h="$( { printf '%s' "$s" | md5sum 2>/dev/null || true; } | cut -c1-8 )" || true
  fi
  if [ -z "$h" ] && command -v cksum >/dev/null 2>&1; then
    h="$( { printf '%s' "$s" | cksum 2>/dev/null || true; } | cut -d' ' -f1 )" || true
    h="${h:0:8}"
  fi
  if [ -z "$h" ]; then
    # 纯 bash FNV-1a 32 位：确定性、零外部依赖。
    local i ch a=2166136261
    for (( i = 0; i < ${#s}; i++ )); do
      ch="$(printf '%d' "'${s:$i:1}" 2>/dev/null)" || ch=0
      case "$ch" in ''|*[!0-9]*) ch=0 ;; esac
      a=$(( ((a ^ ch) * 16777619) & 0xFFFFFFFF ))
    done
    h="$(printf '%08x' "$a")"
  fi
  printf '%s\n' "$h"
}

init_paths() {
  PFX_REAL="$(_abs_path "${INSTALL_ROOT:-/}")"
  if [ -z "$INSTALL_ROOT" ]; then
    SERVICE="ebpdns.service"
  else
    SERVICE="ebpdns-$(_prefix_digest8 "$PFX_REAL").service"
  fi
  SERVICE_PATH="$SERVICE_DIR/$SERVICE"
}

# 路径是否落在**目标前缀**内（前缀为空 = 生产，视为根）。
_in_prefix() {
  local p
  p="$(_abs_path "${1:-}")"
  [ -n "$p" ] || return 1
  [ -n "$INSTALL_ROOT" ] || return 0
  case "$p" in
    "$PFX_REAL"/*) return 0 ;;
  esac
  return 1
}

# **2.1.38 修法②**：只有"exe 落在目标前缀内"的 ebpdns 才算**自家实例**。
# 事故 #1 的判据只有 `basename == ebpdns`，于是生产（/usr/local/bin/ebpdns，前缀外）被当成自家。
own_exe_ok() {
  local exe="${1:-}"
  [ -n "$exe" ] || return 1
  [ "$exe" = "unknown" ] && return 1
  is_own_exe "$exe" || return 1
  if [ -z "$INSTALL_ROOT" ]; then
    # 生产：只认目标二进制所在目录（默认 /usr/local/bin），不接受 /opt 之类的手工实例。
    case "$(_abs_path "$exe")" in
      "$(_abs_path "$(dirname "$BIN_DST")")"/*) return 0 ;;
    esac
    return 1
  fi
  _in_prefix "$exe"
}

# **2.1.38 修法③**：systemd 操作的目标 unit 必须可证明在前缀内。
# 判据：① 前缀内确实存在该 unit 文件；② 若 systemd 报得出 FragmentPath，它也必须在前缀内。
unit_scope_ok() {
  UNIT_SCOPE_ERR=""
  [ -n "$INSTALL_ROOT" ] || return 0
  if [ ! -f "$SERVICE_PATH" ]; then
    UNIT_SCOPE_ERR="前缀内没有 unit 文件 $SERVICE_PATH"
    return 1
  fi
  if [ -n "${SERVICE_FRAG:-}" ] && ! _in_prefix "$SERVICE_FRAG"; then
    UNIT_SCOPE_ERR="systemd 报告的 unit 路径 $SERVICE_FRAG 不在前缀 $PFX_REAL 内"
    return 1
  fi
  return 0
}

# 破坏性动作的目标一律先打印（pid/exe/unit 路径），便于事后审计"到底动了谁"。
log_target() {
  log "[target] $*"
}

usage() {
  cat <<'USAGE'
ebpdns install.sh —— 预编译包安装 / 升级 / 卸载（2.1.38 隔离语义）

用法：
  sudo ./install.sh                    安装 + enable（不自动启动）
  sudo ./install.sh start              安装 + enable + 立即启动
                                         （检测到旧实例 ⇒ 先停后启，rc=0）
  sudo ./install.sh uninstall          卸载（默认保留 /etc/ebpdns 与 state_dir）
  sudo ./install.sh --uninstall        同 uninstall（长开关别名）
  sudo ./install.sh --help             打印本页（不执行任何写操作）

开关（可与上面的 action 任意顺序组合）：
  --strict-config              配置预检/装后复核报 ERROR 时中止安装（= STRICT_CONFIG=1，退出码 2）
  --migrate-config             目标配置已存在时**只做加法**补齐缺失键（写前备份 config.json.bak.<ts>）
  --state-dir <DIR>            **只对 --migrate-config 生效**：显式把该目录透传给
                                `ebpdns migrate-config --state-dir <DIR>`。
                                不给时**只**用配置里的 `state_dir`；两者都没有 ⇒
                                二进制退出码 3（只读报告、零写入），**绝不**默认生产路径。
  --adopt-new-defaults         目标配置已存在时：先备份，再用包内模板覆盖（会丢本地改动）
  --restart                    **2.1.32 新增**：显式「先停后启」。start 的默认行为已是
                                「检测到旧实例就先停后启」，本开关用于把该意图写明；
                                也可与 install 同用（停旧 → 更新文件 → 启动）。
  --keep-running               **2.1.32 新增**：只更新文件，**不停止、不重启**运行中的
                                进程（pid 不变）。端口被占用只 WARN，不报错；新二进制
                                在下次重启后生效。
  --dry-run                    只打印将执行的动作（用户/组、文件、停止/启动旧实例），不改系统
  --force                      **2.1.38 新增**：只放开两处**具名例外** ——
                                 (a) uninstall 时删除旧布局遗留的 `etc/systemd/system/ebpdns.service`
                                     （只删文件，**不**对它执行 systemctl）；
                                 (b) uninstall 时 systemd 报的 FragmentPath 落在**前缀外**，仍按
                                     前缀内**派生** unit 名执行 stop/disable（默认拒绝）。
                               进程归属判定（exe 必须在前缀内）**不可**被 --force 覆盖。
  --purge                      仅与 uninstall 同用：连同 /etc/ebpdns 与 state_dir 一起删除
  -h, --help                   打印本页
  --unit-name                  **2.1.38 新增**：只读打印本前缀派生出的 unit 名后退出
                                （默认前缀 ⇒ `ebpdns.service`；前缀 ⇒ `ebpdns-<hash8>.service`）

环境变量（隔离安装/测试用）：
  EBP_INSTALL_ROOT=<前缀>      系统路径整体前缀（默认空 = 生产）
  EBP_INSTALL_PORTS="<dns> <api>"  **最高优先级**的端口来源（显式覆盖）
  EBP_SYSTEMD=0|1|auto        强制"纯文件模式"/"必须用 systemd"/自动

**2.1.38 隔离语义（两个事故的修法）**：
  · 端口**只**从 `$EBP_INSTALL_ROOT/etc/ebpdns/config.json` 取（`EBP_INSTALL_PORTS` 优先）；
  · 只有 `realpath(/proc/<pid>/exe)` 落在目标前缀内（或 unit 文件在前缀内）才可停；
    否则 **rc=1** 并打印 `pid=` / `exe=` / `端口=`，**不发送任何信号**；
  · 非默认前缀的 unit 名派生为 `ebpdns-<hash8>.service`（`--unit-name` 可查），
    `uninstall` 先校验 unit 路径在前缀内，否则 **rc=1** 且不调用 systemctl；
  · `--dry-run` 与前缀模式默认**不执行**破坏性动作；破坏性动作先打印目标 pid/exe/unit。

**参数解析是 fail-closed 的**：未知开关 / 未知动作 / 多余的位置参数 / `--state-dir`
缺值 / `--restart` 与 `--keep-running` 同时给出 一律 **rc=1 并在任何写操作之前退出**。

退出码（2.1.38 起 `1` 覆盖"拒绝停前缀外实例/拒绝卸载前缀外 unit"）：
  0  安装完成（含"配置有 WARN 但非严格模式"、无 systemd 的"只装文件"、账号降级；
     **含 start 检测到自家旧实例并成功先停后启 / --keep-running 跳过重启**）
  1  前置失败：非 root、包内没有 bin/ebpdns、**用法错误**、系统命令失败、
     **端口被别的进程占用（不是 ebpdns）**、**端口被前缀外的 ebpdns 占用（拒绝误停）**、
     **旧实例停止失败**、**uninstall 的 unit 路径不在前缀内 / 旧布局遗留 unit**、
     **包内二进制的 GLIBC/动态库不满足**
  2  布局预检失败；或 --strict-config 下配置预检/装后复核失败
  3  --migrate-config 未落盘（配置里没有 state_dir 且未给 --state-dir；零写入）
  4  --migrate-config 已写回配置但提交点未更新（最常见：服务在运行、持有 state/.lock）

文档：docs/PACKAGING.md §3 / §3.3 / §5.2；README「安装与升级」。
USAGE
}

# 只读地取出目标配置里的 `state_dir`（仅用于**打印**"将用哪个目录"）。
cfg_state_dir() {
  local conf="$1"
  [ -f "$conf" ] || return 0
  sed -n 's/.*"state_dir"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$conf" 2>/dev/null | head -n1
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "请以 root（或 sudo）运行本脚本。" >&2
    exit 1
  fi
}

# ============================================================================
# 用户/组：幂等检测 + 分级回退（**绝不**因为缺 passwd 包中止安装）
# ============================================================================
have_group() { getent group "$RUN_GROUP" >/dev/null 2>&1; }
have_user() { getent passwd "$RUN_USER" >/dev/null 2>&1; }

pick_free_system_id() {
  local id
  for id in $(seq 991 -1 100); do
    if ! getent group "$id" >/dev/null 2>&1 && ! getent passwd "$id" >/dev/null 2>&1; then
      printf '%s\n' "$id"
      return 0
    fi
  done
  return 1
}

append_group_db() {
  have_group && return 0
  if ! command -v flock >/dev/null 2>&1; then
    warn "缺少 flock，无法安全追加 $GROUP_FILE（跳过直接写库回退）。"
    return 1
  fi
  local gid
  gid="$(pick_free_system_id)" || {
    warn "在系统段 100–991 找不到未占用的 GID，无法直接追加 $GROUP_FILE。"
    return 1
  }
  (
    flock -x 9 || exit 1
    have_group && exit 0
    printf '%s:x:%s:\n' "$RUN_GROUP" "$gid" >>"$GROUP_FILE"
  ) 9>"$PWD_LOCK" || return 1
  have_group
}

append_passwd_db() {
  have_user && return 0
  have_group || return 1
  if ! command -v flock >/dev/null 2>&1; then
    warn "缺少 flock，无法安全追加 $PASSWD_FILE（跳过直接写库回退）。"
    return 1
  fi
  local uid gid
  uid="$(pick_free_system_id)" || {
    warn "在系统段 100–991 找不到未占用的 UID，无法直接追加 $PASSWD_FILE。"
    return 1
  }
  gid="$(getent group "$RUN_GROUP" 2>/dev/null | cut -d: -f3 | head -n1)"
  [ -n "$gid" ] || return 1
  (
    flock -x 9 || exit 1
    have_user && exit 0
    printf '%s:x:%s:%s::%s:/usr/sbin/nologin\n' \
      "$RUN_USER" "$uid" "$gid" "$STATE_DIR" >>"$PASSWD_FILE"
  ) 9>"$PWD_LOCK" || return 1
  have_user
}

try_create_group() {
  have_group && return 0
  if command -v groupadd >/dev/null 2>&1; then
    if groupadd --system "$RUN_GROUP" 2>/dev/null; then
      have_group && { log "已用 groupadd 创建系统组 $RUN_GROUP"; return 0; }
    else
      warn "groupadd 失败（继续尝试 addgroup/直接写库）。"
    fi
  else
    info "未找到 groupadd（passwd 包可能未安装），尝试 addgroup/直接写库。"
  fi
  if command -v addgroup >/dev/null 2>&1; then
    if addgroup --system "$RUN_GROUP" 2>/dev/null; then
      have_group && { log "已用 addgroup 创建系统组 $RUN_GROUP"; return 0; }
    else
      warn "addgroup 失败（继续尝试直接写库）。"
    fi
  fi
  if append_group_db; then
    log "已直接追加 $GROUP_FILE 创建系统组 $RUN_GROUP（getent 复验通过）"
    return 0
  fi
  return 1
}

try_create_user() {
  have_user && return 0
  have_group || return 1
  if command -v useradd >/dev/null 2>&1; then
    if useradd --system --gid "$RUN_GROUP" --home-dir "$STATE_DIR" \
      --shell /usr/sbin/nologin --comment "ebpdns DNS service" "$RUN_USER" 2>/dev/null; then
      have_user && { log "已用 useradd 创建系统用户 $RUN_USER"; return 0; }
    else
      warn "useradd 失败（继续尝试 adduser/直接写库）。"
    fi
  else
    info "未找到 useradd（passwd 包可能未安装），尝试 adduser/直接写库。"
  fi
  if command -v adduser >/dev/null 2>&1; then
    if adduser --system --ingroup "$RUN_GROUP" --no-create-home \
      --home "$STATE_DIR" --shell /usr/sbin/nologin "$RUN_USER" 2>/dev/null; then
      have_user && { log "已用 adduser 创建系统用户 $RUN_USER"; return 0; }
    else
      warn "adduser 失败（继续尝试直接写库）。"
    fi
  fi
  if append_passwd_db; then
    log "已直接追加 $PASSWD_FILE 创建系统用户 $RUN_USER（getent 复验通过）"
    return 0
  fi
  return 1
}

ensure_service_account() {
  if have_group && have_user; then
    log "运行账号已存在：$RUN_USER:$RUN_GROUP（跳过创建）"
    SERVICE_ACCOUNT_OK=1
    return 0
  fi
  try_create_group || true
  try_create_user || true
  if have_group && have_user; then
    SERVICE_ACCOUNT_OK=1
    log "运行账号就绪：$RUN_USER:$RUN_GROUP"
    return 0
  fi
  SERVICE_ACCOUNT_OK=0
  warn "无法创建运行账号 $RUN_USER:$RUN_GROUP（缺 passwd 包且 $GROUP_FILE/$PASSWD_FILE 不可写）。"
  warn "  后续 chown 将退化为 root:root；systemd unit 将临时改为 User=root/Group=root（仅本次安装）。"
  warn "  修复后可重跑：sudo groupadd ebpdns && sudo useradd -r -g ebpdns -d $STATE_DIR -s /usr/sbin/nologin ebpdns && sudo ./install.sh"
  return 1
}

chown_service() {
  local path="$1"
  if have_user && have_group; then
    if chown "$RUN_USER:$RUN_GROUP" "$path" 2>/dev/null; then
      return 0
    fi
    warn "chown $RUN_USER:$RUN_GROUP $path 失败，退化为 root:root。"
  fi
  chown root:root "$path" 2>/dev/null || warn "chown root:root $path 失败（继续安装）。"
}

chown_r_service() {
  local path="$1"
  if have_user && have_group; then
    if chown -R "$RUN_USER:$RUN_GROUP" "$path" 2>/dev/null; then
      return 0
    fi
    warn "chown -R $RUN_USER:$RUN_GROUP $path 失败，退化为 root:root。"
  fi
  chown -R root:root "$path" 2>/dev/null || warn "chown -R root:root $path 失败（继续安装）。"
}

# 安装单文件：先落盘，再按实际账号情况设置属主（不用 install -o/-g，避免账号不存在时失败）。
install_file() {
  local src="$1" dst="$2" mode="$3"
  install -m "$mode" "$src" "$dst"
  chown_service "$dst"
}

# **2.1.32**：同名临时文件 + rename 替换。运行中的进程持有旧 inode 时，直接覆盖会
# 得到 ETXTBSY（Text file busy）；rename 则能安全地换上新二进制（--keep-running 必需）。
install_binary() {
  local src="$1" dst="$2" tmp
  tmp="$dst.ebpdns-new.$$"
  if ! install -m 0755 "$src" "$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  if ! mv -f "$tmp" "$dst"; then
    rm -f "$tmp"
    return 1
  fi
  return 0
}

# ============================================================================
# 预检：包布局 / 配置 / 二进制可运行性 / 端口占用
# ============================================================================
preflight_layout() {
  local here bin_src
  here="$(cd "$(dirname "$0")" && pwd)"
  bin_src="$here/bin/ebpdns"
  if [ -f "$bin_src" ]; then
    return 0
  fi
  err "未找到安装产物：$bin_src"
  err "本脚本必须从**预编译包根目录**运行（包布局：bin/ + etc/ + systemd/ + web/ + install.sh）。"
  err ""
  err "正确做法二选一："
  err "  1) 用预编译包（推荐）："
  err "       tar xzf ebpdns-2.1.49-prod.tar.gz && cd ebpdns-2.1.49 && sudo ./install.sh start"
  err "  2) 从源码树构建并打包（源码树里本来就没有 bin/ebpdns）："
  err "       make wasm && cargo build --release --bin ebpdns --features embed-frontend"
  err "       ./scripts/make_packages_221r2.sh   # 交付链：wasm → bin → 清单 → prod+src 包"
  err "       tar xzf <生成的 prod 包> && cd ebpdns-2.1.49 && sudo ./install.sh start"
  err ""
  err "（若确实只想在源码树里装：install -m0755 target/release/ebpdns /usr/local/bin/ebpdns）"
  exit 2
}

preflight_config() {
  local bin_src conf strict=0
  bin_src="$(cd "$(dirname "$0")" && pwd)/bin/ebpdns"
  conf="$(dirname "$0")/etc/ebpdns/config.json"
  [ "${STRICT_CONFIG:-0}" = "1" ] && strict=1
  [ -f "$conf" ] || return 0
  if [ ! -f "$bin_src" ]; then
    warn "跳过 check-config 预检：包内**没有** $bin_src"
    warn "  少做的检查：配置文件的类型 / 范围 / 枚举 / 未知键 / config_version 校验。"
    warn "  补救：确认包完整（prod 包应含 bin/ebpdns）；或安装后手工执行"
    warn "        /usr/local/bin/ebpdns check-config --config $conf"
    return 0
  fi
  local exec_bin="$bin_src" tmpdir="" used_tmp=0
  if [ ! -x "$bin_src" ]; then
    if tmpdir="$(mktemp -d 2>/dev/null)"; then
      if install -m 0755 "$bin_src" "$tmpdir/ebpdns" 2>/dev/null; then
        exec_bin="$tmpdir/ebpdns"
        used_tmp=1
        info "包内二进制缺少执行位（$bin_src）—— 典型的**跨平台解包丢权限**"
        info "  已用临时副本预检（install -m 0755 → $exec_bin），安装行为不变"
        info "  建议：用能保留权限的方式解包（Linux tar -xzf；Windows 解包后 chmod +x）"
      else
        rmdir "$tmpdir" 2>/dev/null || true
        tmpdir=""
      fi
    fi
    if [ "$used_tmp" = "0" ]; then
      err "════════════════════════════════════════════════════════════════"
      err "⚠️  跳过 check-config 预检：$bin_src 不可执行，且无法创建临时副本"
      err "════════════════════════════════════════════════════════════════"
      err "原因：跨平台解包（Windows/zip/SFTP 客户端）会丢失执行位。"
      err "补救（任一即可）："
      err "  1) chmod +x bin/ebpdns install.sh     # 就地修复后重跑本脚本"
      err "  2) tar -xzf ebpdns-*-prod.tar.gz      # 用 Linux tar 重新解包"
      err "本次安装**少做了**配置预检（类型/范围/枚举/未知键/config_version）——"
      err "请安装后手工复核：/usr/local/bin/ebpdns check-config --config $conf"
      return 0
    fi
  fi

  local out rc
  out="$("$exec_bin" check-config --config "$conf" 2>&1)" && rc=0 || rc=$?
  [ "$used_tmp" = "1" ] && rm -rf "$tmpdir"
  if [ "$rc" -eq 0 ]; then
    case "$out" in
      *WARN:*)
        warn "check-config 通过但有告警（不阻断安装）："
        printf '%s\n' "$out" | sed 's/^/    /' >&2
        ;;
      *)
        log "check-config 预检通过：$(printf '%s' "$out" | tail -n1)"
        ;;
    esac
    return 0
  fi
  err "════════════════════════════════════════════════════════════════"
  err "⚠️  配置预检未通过（ebpdns check-config 退出码 $rc）"
  err "════════════════════════════════════════════════════════════════"
  printf '%s\n' "$out" | sed 's/^/    /' >&2
  err "修法：按上面逐条 ERROR 修正 $conf（类型/范围/枚举/未知键）；"
  err "      `config_version 过高` ⇒ 配置来自更新的 ebpdns，请改用对应版本的二进制。"
  err "开关：默认**不阻断安装**；需要硬门时：sudo STRICT_CONFIG=1 ./install.sh start"
  if [ "$strict" = "1" ]; then
    err "STRICT_CONFIG=1：已按严格模式中止安装。"
    exit 2
  fi
  warn "继续安装（**默认非阻断**）；服务可能因该配置异常而启动失败，请留意 journalctl。"
  return 0
}

# **2.1.31**：安装**之前**证明包内二进制能在本机跑起来（避免"装完才发现 GLIBC 不够"）。
preflight_binary_runnable() {
  local bin_src out rc tmpdir="" exec_bin
  bin_src="$(cd "$(dirname "$0")" && pwd)/bin/ebpdns"
  [ -f "$bin_src" ] || { err "包内没有 bin/ebpdns。"; exit 2; }
  exec_bin="$bin_src"
  if [ ! -x "$bin_src" ]; then
    tmpdir="$(mktemp -d 2>/dev/null)" || { err "无法创建临时目录做二进制预检。"; exit 1; }
    install -m 0755 "$bin_src" "$tmpdir/ebpdns" || { err "无法创建二进制临时副本。"; exit 1; }
    exec_bin="$tmpdir/ebpdns"
  fi
  out="$("$exec_bin" --version 2>&1)" && rc=0 || rc=$?
  [ -n "$tmpdir" ] && rm -rf "$tmpdir"
  if [ "$rc" -eq 0 ]; then
    log "二进制可运行性预检通过：$(printf '%s' "$out" | head -n1)"
    return 0
  fi
  err "════════════════════════════════════════════════════════════════"
  err "⚠️  包内二进制无法在本机运行（$bin_src --version 退出码 $rc）"
  err "════════════════════════════════════════════════════════════════"
  printf '%s\n' "$out" | sed 's/^/    /' >&2
  case "$out" in
    *GLIBC_*)
      err "原因：目标机 glibc 低于二进制要求（上面给出了缺失的 GLIBC_* 符号版本）。"
      err "修法：① 升级目标机 glibc；或 ② 使用与目标机匹配的构建；"
      err "      ③ 静态 musl 构建**当前未提供**（已登记为后续项）。"
      ;;
    *)
      err "原因：动态库/CPU 指令集/文件损坏等（见上面的加载器输出）。"
      err "修法：用 'ldd $bin_src' 与 'file $bin_src' 复核目标机兼容性。"
      ;;
  esac
  exit 1
}

# 端口占用预检：ss → lsof → /proc/net/*；都没有则 WARN 并跳过（不硬失败）。
_port_busy_by_proc() {
  local p="$1" hex
  hex="$(printf '%04X' "$p")"
  local f
  for f in /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6; do
    [ -r "$f" ] || continue
    awk -v h="$hex" 'NR>1 { n=split($2,a,":"); if (a[n]==h) { found=1; exit } } END { exit !found }' "$f" && return 0
  done
  return 1
}

_port_busy() {
  local p="$1" out
  if command -v ss >/dev/null 2>&1; then
    out="$(ss -H -ltnup "( sport = :$p )" 2>/dev/null || true)"
    [ -n "$out" ] && { printf '%s\n' "$out"; return 0; }
    return 1
  fi
  if command -v lsof >/dev/null 2>&1; then
    out="$(lsof -nP -iTCP:"$p" -iUDP:"$p" 2>/dev/null || true)"
    [ -n "$out" ] && { printf '%s\n' "$out"; return 0; }
    return 1
  fi
  _port_busy_by_proc "$p"
}

# **2.1.38（端口来源）**：把结果写进全局 `PORTS` / `PORTS_SOURCE`。
# 注意：**不能**用 `PORTS="$(configured_ports)"` 的形式 —— 命令替换在子 shell 里跑，
# `PORTS_SOURCE` 的赋值会丢，日志里就只剩空来源（回归 S6 专门断言这一行）。
resolve_ports() {
  local conf="" dns api src=""
  # ① 显式覆盖永远最高优先级（部署代理/回归测试用）。
  if [ -n "$PORTS_OVERRIDE" ]; then
    PORTS_SOURCE="EBP_INSTALL_PORTS（显式覆盖）"
    PORTS="$PORTS_OVERRIDE"
    return 0
  fi
  # ② **只认目标前缀配置**（事故 #1 的修法：不再无条件读包内默认配置）。
  if [ -f "$CONF_FILE" ]; then
    conf="$CONF_FILE"
    src="目标前缀配置 $CONF_FILE"
  else
    # 目标前缀还没有配置 ⇒ 本次安装会**把包内模板装进去**，因此那份模板就是"将来生效的
    # 目标配置"。这里显式记录来源，并且**只有这条分支**会碰包内模板 —— 目标配置一旦存在，
    # 模板永不参与判定（回归 S6 用"模板端口故意写成 53/8353"证明这一点）。
    conf="$(dirname "$0")/etc/ebpdns/config.json"
    src="将安装的包内模板（$CONF_FILE 尚不存在）"
  fi
  dns="$(sed -n 's/.*"dns_port"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$conf" 2>/dev/null | head -n1)"
  api="$(awk '
    /"api"[[:space:]]*:/ { inapi=1 }
    inapi && /"port"[[:space:]]*:/ { gsub(/[^0-9]/, "", $0); print; exit }
    inapi && /}/ { inapi=0 }
  ' "$conf" 2>/dev/null | head -n1)"
  if [ -z "$dns" ]; then
    dns=53
    warn "配置里没有 dns_port（$conf）⇒ 按内置默认 53 预检。"
  fi
  if [ -z "$api" ]; then
    api=8353
    warn "配置里没有 api.port（$conf）⇒ 按内置默认 8353 预检。"
  fi
  PORTS_SOURCE="$src"
  PORTS="$dns $api"
}

check_ports() {
  local ports p detail seen=" "
  # 2.1.38：端口来源由 resolve_ports 决定（目标前缀配置 / 显式覆盖），**不再传包内路径**。
  resolve_ports
  ports="$PORTS"
  [ -n "$ports" ] || return 0
  info "端口来源 = ${PORTS_SOURCE}；预检端口 = $ports"
  if ! command -v ss >/dev/null 2>&1 && ! command -v lsof >/dev/null 2>&1 && [ ! -r /proc/net/tcp ]; then
    warn "未找到 ss/lsof 且无法读 /proc/net/tcp*，端口占用检查**已跳过**（继续安装）。"
    return 0
  fi
  if ! command -v ss >/dev/null 2>&1 && ! command -v lsof >/dev/null 2>&1; then
    warn "未找到 ss/lsof，端口占用检查退化为 /proc/net/tcp* 解析（进程名不可见）。"
  fi
  for p in $ports; do
    case "$seen" in *" $p "*) continue ;; esac
    seen="$seen$p "
    if detail="$(_port_busy "$p")"; then
      if [ "$KEEP_RUNNING" = "1" ]; then
        warn "--keep-running：端口 $p 仍被占用（按约定不中止、不重启；新二进制下次重启生效）："
        printf '%s\n' "$detail" | sed 's/^/    /' >&2
        continue
      fi
      err "端口 $p 已被占用，安装中止（未写任何文件）："
      printf '%s\n' "$detail" | sed 's/^/    /' >&2
      err "修法：停止占用该端口的进程后重跑；若占用者是旧 ebpdns，直接重跑"
      err "      'sudo ./install.sh start'（默认先停后启）或加 --restart。"
      return 1
    fi
  done
  info "端口占用预检通过（$ports）"
  return 0
}

# ============================================================================
# **2.1.32**：运行实例检测（判定优先级：systemd is-active → 端口持有者的 /proc/<pid>/exe）
# ============================================================================
proc_exe() {
  local pid="${1:-}" exe=""
  [ -n "$pid" ] || return 0
  if exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null)" && [ -n "$exe" ]; then
    :
  else
    exe="$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null | awk '{print $1}')"
  fi
  printf '%s\n' "$exe"
}

# 只认 basename == ebpdns（兼容内核在可执行文件已被替换后追加的 " (deleted)"）。
is_own_exe() {
  local b
  b="$(basename -- "${1:-}")"
  b="${b% (deleted)}"
  [ "$b" = "ebpdns" ]
}

# 打印「pid exe」行；无法拿到 pid 时打印「? unknown」；端口空闲则无输出。
port_holders() {
  local p="$1" out pids pid
  if command -v ss >/dev/null 2>&1; then
    out="$(ss -H -ltnup "( sport = :$p )" 2>/dev/null || true)"
    [ -n "$out" ] || return 0
    pids="$(printf '%s\n' "$out" | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u || true)"
    if [ -z "$pids" ]; then
      printf '? unknown\n'
      return 0
    fi
    for pid in $pids; do printf '%s %s\n' "$pid" "$(proc_exe "$pid")"; done
    return 0
  fi
  if command -v lsof >/dev/null 2>&1; then
    pids="$(lsof -nP -t -iTCP:"$p" -iUDP:"$p" 2>/dev/null | sort -u || true)"
    [ -n "$pids" ] || return 0
    for pid in $pids; do printf '%s %s\n' "$pid" "$(proc_exe "$pid")"; done
    return 0
  fi
  if _port_busy_by_proc "$p"; then printf '? unknown\n'; fi
  return 0
}

ports_busy_detail() {
  local p line pid exe out=""
  for p in $PORTS; do
    while IFS=' ' read -r pid exe; do
      [ -n "${pid:-}" ] || continue
      out="$out $p:pid=$pid,exe=${exe:-unknown}"
    done <<<"$(port_holders "$p")"
  done
  printf '%s' "${out:-unknown}"
}

# 等所有配置端口释放（每 0.1 s 轮询）。
wait_ports_free() {
  local secs="$1" i=0 limit p busy
  limit=$((secs * 10))
  while [ "$i" -lt "$limit" ]; do
    busy=0
    for p in $PORTS; do
      if [ -n "$(port_holders "$p")" ]; then
        busy=1
        break
      fi
    done
    [ "$busy" = "0" ] && return 0
    sleep 0.1
    i=$((i + 1))
  done
  return 1
}

# 只读检测；发现「别的进程」或「**目标前缀外的 ebpdns**」占端口时返回 1（在任何写操作前）。
detect_running() {
  local p pid exe st fp fpid fexe
  OLD_PIDS=""
  OLD_PID=""
  SERVICE_WAS_ACTIVE=0
  SERVICE_FRAG=""
  FOREIGN_HOLDERS=""
  NONPREFIX_HOLDERS=""
  init_paths
  resolve_ports
  info "端口来源 = ${PORTS_SOURCE}；判定端口 = $PORTS"

  # ① systemd 的 active 是最高优先级（容器/命名空间里 ss 可能看不到宿主 pid）。
  if systemd_available; then
    st="$(systemctl is-active "$SERVICE" 2>/dev/null || true)"
    case "$st" in
      active|activating|reloading|deactivating)
        SERVICE_WAS_ACTIVE=1
        OLD_PID="$(systemctl show -p MainPID --value "$SERVICE" 2>/dev/null || true)"
        case "$OLD_PID" in ''|0|*[!0-9]*) OLD_PID="" ;; esac
        SERVICE_FRAG="$(systemctl show -p FragmentPath --value "$SERVICE" 2>/dev/null || true)"
        # **2.1.38 修法③**：unit 必须可证明在目标前缀内，否则一律不停（rc≠0，且不调用 systemctl）。
        if ! unit_scope_ok; then
          err "拒绝停止：$SERVICE 处于 active，但 $UNIT_SCOPE_ERR。"
          err "  unit=$SERVICE unit_path=$SERVICE_PATH pid=${OLD_PID:-unknown} 端口=$PORTS"
          err "  FragmentPath=${SERVICE_FRAG:-<unknown>} 目标前缀=${PFX_REAL:-/}"
          err "  判定规则：前缀模式只允许停「unit 文件在前缀内」的 unit；本次未 stop/disable/写文件。"
          return 1
        fi
        case "${OLD_PID:-}" in
          '') ;;
          *)
            exe="$(proc_exe "$OLD_PID")"
            # **2.1.38 修法②**：systemd 报的 MainPID 也必须过路径约束。
            if ! own_exe_ok "$exe"; then
              err "拒绝停止：systemd 的 MainPID=$OLD_PID 的 exe=${exe:-unknown} 不在目标前缀 ${PFX_REAL:-/} 内。"
              err "  unit=$SERVICE unit_path=$SERVICE_PATH 端口=$PORTS"
              err "  该进程属于**另一个实例**（很可能是生产）：本次未发送任何信号、未写任何文件。"
              return 1
            fi
            ;;
        esac
        ;;
    esac
  fi

  # ② 端口持有者：exe=ebpdns **且路径在前缀内** ⇒ 自家；ebpdns 但前缀外 ⇒ 拒绝；否则 ⇒ 别的进程。
  for p in $PORTS; do
    while IFS=' ' read -r pid exe; do
      [ -n "${pid:-}" ] || continue
      if [ "$pid" = "?" ]; then
        FOREIGN_HOLDERS="${FOREIGN_HOLDERS}${p}|?|unknown"$'\n'
      elif ! is_own_exe "$exe"; then
        FOREIGN_HOLDERS="${FOREIGN_HOLDERS}${p}|${pid}|${exe:-unknown}"$'\n'
      elif own_exe_ok "$exe"; then
        case " $OLD_PIDS " in *" $pid "*) ;; *) OLD_PIDS="$OLD_PIDS $pid" ;; esac
      else
        NONPREFIX_HOLDERS="${NONPREFIX_HOLDERS}${p}|${pid}|${exe:-unknown}"$'\n'
      fi
    done <<<"$(port_holders "$p")"
  done
  OLD_PIDS="${OLD_PIDS# }"

  # **2.1.38 修法②**：前缀外的 ebpdns 一律拒绝 —— 事故 #1 就是把它当成了"自家旧实例"。
  if [ -n "$NONPREFIX_HOLDERS" ] && [ "$KEEP_RUNNING" != "1" ]; then
    err "拒绝把**目标前缀外**的 ebpdns 当成「自家旧实例」（2.1.38 隔离约束）："
    while IFS='|' read -r fp fpid fexe; do
      [ -n "$fp" ] || continue
      err "  端口 $fp 已被占用：pid=$fpid exe=${fexe:-unknown}（不在 ${PFX_REAL:-/} 内）"
    done <<<"$NONPREFIX_HOLDERS"
    err "判定规则：只有 realpath(/proc/<pid>/exe) 落在 ${PFX_REAL:-/} 内（或 unit 文件在前缀内）才可停止。"
    err "本次**未**发送任何信号、**未**调用 systemctl、**未**写任何文件。"
    err "修法：① 隔离实例请给专用配置 $CONF_FILE（端口别与生产重合）；或"
    err "      ② 显式指定端口：EBP_INSTALL_PORTS=\"<dns> <api>\" sudo -E ./install.sh start"
    return 1
  fi

  if [ -n "$FOREIGN_HOLDERS" ] && [ "$KEEP_RUNNING" != "1" ]; then
    err "端口被**其他进程**占用（不是 ebpdns），安装中止（未写任何文件）："
    while IFS='|' read -r fp fpid fexe; do
      [ -n "$fp" ] || continue
      err "  端口 $fp 已被占用：pid=$fpid exe=${fexe:-unknown}"
    done <<<"$FOREIGN_HOLDERS"
    err "修法：停止占用端口的进程后重跑。若它其实是旧版 ebpdns（但 exe 不叫 ebpdns），"
    err "      请手工停止；脚本只自动停止 exe 在前缀内的 ebpdns，或前缀内的 $SERVICE。"
    return 1
  fi

  if [ "$KEEP_RUNNING" = "1" ]; then
    if [ -n "$OLD_PIDS" ] || [ "$SERVICE_WAS_ACTIVE" = "1" ] || [ -n "$FOREIGN_HOLDERS" ] || [ -n "$NONPREFIX_HOLDERS" ]; then
      warn "--keep-running：检测到运行中的实例/端口占用（pid=${OLD_PID:-${OLD_PIDS:-unknown}}），按约定**不停止、不重启**。"
      while IFS='|' read -r fp fpid fexe; do
        [ -n "$fp" ] || continue
        warn "  端口 $fp 被 pid=$fpid exe=${fexe:-unknown} 占用（仅 WARN，不中止）"
      done <<<"$FOREIGN_HOLDERS"
      while IFS='|' read -r fp fpid fexe; do
        [ -n "$fp" ] || continue
        warn "  端口 $fp 被**前缀外的 ebpdns** pid=$fpid exe=${fexe:-unknown} 占用（仅 WARN，不中止、不停它）"
      done <<<"$NONPREFIX_HOLDERS"
      warn "  本次只更新文件；**新二进制将在下次重启后生效**。"
    fi
    return 0
  fi

  if [ "$SERVICE_WAS_ACTIVE" = "1" ] || [ -n "$OLD_PIDS" ]; then
    info "检测到旧实例在运行（pid=${OLD_PID:-${OLD_PIDS:-unknown}}），先停止再继续。"
  fi
  return 0
}

# 停旧实例：systemd 用 stop；无 systemd 用 SIGTERM → 等 5 s → SIGKILL。
# **2.1.38 修法④**：动手之前先把目标 pid/exe/unit 打印出来（可审计"到底动了谁"），
# 且 systemd 路径还要再过一遍 unit 归属校验（双保险：detect_running 已校验过一次）。
stop_own_instance() {
  local p
  if [ "$SERVICE_WAS_ACTIVE" = "1" ] && systemd_available; then
    if ! unit_scope_ok; then
      err "拒绝停止：$UNIT_SCOPE_ERR（unit=$SERVICE unit_path=$SERVICE_PATH）。"
      return 1
    fi
    log_target "unit=$SERVICE unit_path=$SERVICE_PATH pid=${OLD_PID:-unknown} exe=$(proc_exe "${OLD_PID:-0}")"
    log "停止运行中的服务：systemctl stop $SERVICE"
    if ! systemctl stop "$SERVICE" 2>/dev/null; then
      err "systemctl stop $SERVICE 失败。"
      return 1
    fi
    if wait_ports_free 15; then
      log "旧实例已停止（systemd stop，端口已释放）。"
      return 0
    fi
    err "systemctl stop 后 15 s 内端口仍未释放：$(ports_busy_detail)"
    err "请手工检查：systemctl status $SERVICE；ss -lntup"
    return 1
  fi
  [ -n "$OLD_PIDS" ] || return 0
  for p in $OLD_PIDS; do
    log_target "pid=$p exe=$(proc_exe "$p") 端口=$PORTS"
  done
  log "向旧实例发送 SIGTERM：pid=$OLD_PIDS"
  for p in $OLD_PIDS; do kill -TERM "$p" 2>/dev/null || true; done
  if wait_ports_free 5; then
    log "旧实例已退出（SIGTERM，等待 ≤5 s）。"
    return 0
  fi
  warn "SIGTERM 后 5 s 端口未释放，升级为 SIGKILL：pid=$OLD_PIDS"
  for p in $OLD_PIDS; do kill -KILL "$p" 2>/dev/null || true; done
  if wait_ports_free 5; then
    log "旧实例已退出（SIGKILL，等待 ≤5 s）。"
    return 0
  fi
  err "SIGKILL 后端口仍未释放：$(ports_busy_detail)"
  return 1
}

# ============================================================================
# 兼容旧行为的配置补救函数
# ============================================================================
inspect_existing_config() {
  local bin_dst="$1" conf="$2"
  warn "已存在 $conf，保留不覆盖（本地改动不会被冲掉）。"
  warn "  ① 用**已安装的二进制**复核这份配置："
  local out rc
  out="$("$bin_dst" check-config --config "$conf" 2>&1)" && rc=0 || rc=$?
  printf '%s\n' "$out" | sed 's/^/      /' >&2
  if [ "$rc" -ne 0 ]; then
    warn "      ⇒ check-config 退出码 $rc（配置**未通过**校验，见上面逐条 ERROR）"
  else
    warn "      ⇒ check-config 退出码 0（通过；WARN 只提示不阻断）"
  fi
  warn "  ② 与包内默认键集的差集（缺失键会让服务按内置默认值运行）："
  local mig
  mig="$("$bin_dst" migrate-config --config "$conf" --dry-run 2>&1)" && rc=0 || rc=$?
  printf '%s\n' "$mig" | grep -E '^MIGRATE-SUMMARY|^MIGRATE:' | sed 's/^/      /' >&2 || true
  case "$mig" in
    *"missing_keys: 0"*)
      warn "      ⇒ 该配置已含本版本全部顶层键，**无需迁移**。" ;;
    *)
      warn "      ⇒ 存在缺失键：可**只做加法**补齐（写前自动备份）："
      warn "           sudo $0 --migrate-config                      # 配置里已有 state_dir 时"
      warn "           sudo $0 --migrate-config --state-dir <专用目录> # 配置里**没有** state_dir 时必须给"
      warn "         或先用包内模板**整体覆盖**（同样先备份，会丢本地改动）："
      warn "           sudo $0 --adopt-new-defaults"
      warn "         也可只预览不改动：$bin_dst migrate-config --config $conf --dry-run" ;;
  esac
  warn "  ③ 语义与退出码见 README「安装与升级」/ PACKAGING 文档。"
}

apply_migrate_config() {
  local bin_dst="$1" conf="$2"
  local state_dir="${3:-}"
  log "--migrate-config：对 $conf 执行**只做加法**的键补齐（写前备份）……"
  if [ -n "$state_dir" ]; then
    log "  状态目录：显式 --state-dir $state_dir（**透传**给 migrate-config；不读配置里的值）"
  else
    local from_cfg
    from_cfg="$(cfg_state_dir "$conf")"
    if [ -n "$from_cfg" ]; then
      log "  状态目录：取配置里的 state_dir=$from_cfg（未给 --state-dir）"
    else
      warn "  状态目录：配置里**没有** state_dir，且本次**未给** --state-dir"
      warn "           ⇒ 二进制会以**退出码 3** 只做只读报告（**零写入**），"
      warn "             它**绝不会**默认落到生产路径 /var/lib/ebpdns/state。"
      warn "          要真落盘请加：sudo $0 --migrate-config --state-dir <专用目录>"
    fi
  fi
  local out rc
  local margs=(migrate-config --config "$conf")
  if [ -n "$state_dir" ]; then
    margs+=(--state-dir "$state_dir")
  fi
  out="$("$bin_dst" "${margs[@]}" 2>&1)" && rc=0 || rc=$?
  printf '%s\n' "$out" | sed 's/^/    /'
  case "$rc" in
    0) log "--migrate-config 完成（退出码 0）" ;;
    2) err "--migrate-config 失败：配置不可迁移（退出码 2，文件未被改动）" ;;
    3) warn "--migrate-config **未落盘**（退出码 3）：该配置里**没有** \`state_dir\`，本次也没给 \`--state-dir\`\
  ⇒ 二进制只做了只读报告（**未改动任何文件**），因为它拒绝默认落到生产路径 \`/var/lib/ebpdns/state\`。\
  请显式给出状态目录后重跑：\`sudo $0 --migrate-config --state-dir <专用目录>\`\
  （或 \`$bin_dst migrate-config --config $conf --state-dir <专用目录>\`）" ;;
    4) warn "--migrate-config 已**写回**配置，但**提交点未更新**（退出码 4）：重锚 \`state/\` 失败，\
 最常见原因是服务正在运行（持有 \`state/.lock\`）。配置内容已是迁移后的内容；\
 停服后重跑 \`$bin_dst migrate-config --config $conf${state_dir:+ --state-dir $state_dir}\` 即可补齐提交点。" ;;
    *) err "--migrate-config 失败：IO/备份失败（退出码 $rc）" ;;
  esac
  return "$rc"
}

apply_adopt_new_defaults() {
  local conf="$1" tpl="$2"
  if [ ! -f "$tpl" ]; then
    err "--adopt-new-defaults：包内模板不存在（$tpl）—— 包不完整，已跳过。"
    return 1
  fi
  local ts bak
  ts="$(date +%Y%m%d%H%M%S 2>/dev/null || echo 0)"
  bak="$conf.bak.$ts"
  log "--adopt-new-defaults：备份 $conf → $bak，然后用包内模板覆盖。"
  cp -p "$conf" "$bak" || { err "备份失败：未覆盖 $conf"; return 2; }
  install -m 0640 "$tpl" "$conf" || { err "覆盖失败：已保留备份 $bak"; return 2; }
  chown_service "$conf"
  log "--adopt-new-defaults 完成（旧配置在 $bak；本地改动**不会**被保留）"
  return 0
}

postinstall_check_config() {
  local strict=0
  [ "${STRICT_CONFIG:-0}" = "1" ] && strict=1
  [ -x "$BIN_DST" ] && [ -f "$CONF_FILE" ] || return 0
  local out rc
  out="$("$BIN_DST" check-config --config "$CONF_FILE" 2>&1)" && rc=0 || rc=$?
  if [ "$rc" -eq 0 ]; then
    case "$out" in
      *WARN:*)
        warn "安装后复核：$CONF_FILE 通过但有告警（来自**已安装**的二进制）："
        printf '%s\n' "$out" | sed 's/^/    /' >&2
        ;;
      *)
        log "安装后复核通过（已安装二进制 + 目标配置）：$(printf '%s' "$out" | tail -n1)"
        ;;
    esac
    return 0
  fi
  err "════════════════════════════════════════════════════════════════"
  err "⚠️  安装后复核未通过：$BIN_DST check-config --config $CONF_FILE → 退出码 $rc"
  err "     （这是服务**将要面对**的那一份二进制与配置，不是包内副本）"
  err "════════════════════════════════════════════════════════════════"
  printf '%s\n' "$out" | sed 's/^/    /' >&2
  err "修法：① 修正 $CONF_FILE 中的 ERROR；或"
  err "      ② sudo $0 --migrate-config        # 只做加法补齐缺失键（先备份）"
  err "      ③ sudo $0 --adopt-new-defaults    # 用包内模板覆盖（先备份）"
  if [ "$strict" = "1" ]; then
    err "STRICT_CONFIG=1：已在 enable/start **之前**中止（二进制与配置已就位）。"
    exit 2
  fi
  warn "继续（默认非阻断）：服务可能因该配置异常而启动失败，请留意 journalctl -u $SERVICE。"
  return 0
}

# ============================================================================
# systemd 可选：无 systemctl 时只装文件 + 打印手动启动命令
# ============================================================================
systemd_available() {
  case "$SYSTEMD_MODE" in
    off) return 1 ;;
    on) return 0 ;;
  esac
  command -v systemctl >/dev/null 2>&1 || return 1
  # 容器里常有 systemctl 二进制但没有 systemd（PID1 不是 systemd）。
  if command -v systemctl >/dev/null 2>&1; then
    local st
    st="$(systemctl is-system-running 2>/dev/null || true)"
    case "$st" in
      running|degraded|starting) return 0 ;;
      *) return 1 ;;
    esac
  fi
  return 1
}

# 无运行账号时，把 unit 的 User/Group 临时改成 root（并 WARN），避免"装完起不来"。
prepare_unit() {
  local dst="$1" src="$2"
  if have_user && have_group; then
    install -m 0644 "$src" "$dst"
    return 0
  fi
  warn "运行账号 $RUN_USER:$RUN_GROUP 不存在：本次安装的 systemd unit 将临时使用 User=root/Group=root。"
  warn "  修复后重跑安装即可恢复 User=$RUN_USER（不会静默留下起不来的服务）。"
  sed -e 's/^User=.*/User=root/' -e 's/^Group=.*/Group=root/' "$src" >"$dst"
  chmod 0644 "$dst"
}

manual_start_hint() {
  log "未检测到可用的 systemd：已只安装文件，可用下面的命令手动启动："
  log "  $BIN_DST --config $CONF_FILE --foreground"
  log "  后台示例：nohup $BIN_DST --config $CONF_FILE --foreground >/var/log/ebpdns.log 2>&1 &"
  log "  或自行编写 systemd/OpenRC/s6 服务（unit 模板：$SERVICE_SRC）"
}

# >>> 242B BEGIN P0-3-plan >>> #
# **2.1.42-B（P0-3）**：`--dry-run` 的卸载计划（**只打印，不写系统**）。
# 必须在 uninstall / purge / stop / disable / rm 任何分派之前调用。
print_uninstall_plan() {
  log "[dry-run] uninstall 目标前缀：${INSTALL_ROOT:-<系统级>}（realpath=${PFX_REAL:-/}）；unit=$SERVICE（$SERVICE_PATH）"
  if [ -n "$INSTALL_ROOT" ] && [ -f "$SERVICE_DIR/ebpdns.service" ] && [ "$SERVICE" != "ebpdns.service" ]; then
    log "[dry-run] 检测到旧布局遗留 unit：$SERVICE_DIR/ebpdns.service（真实执行时只会删文件，不对它执行 systemctl）"
  fi
  log "[dry-run] 将停止并禁用：$SERVICE（仅当前缀内 unit 可证明归属时）"
  log "[dry-run] 将删除：$SERVICE_PATH $BIN_DST $WEB_DST"
  if [ "$PURGE" = "1" ]; then
    log "[dry-run] --purge：将删除 $CONF_DIR 与 $STATE_DIR（不可恢复）"
  else
    log "[dry-run] 保留：$CONF_DIR 与 $STATE_DIR"
  fi
  log "[dry-run] 未执行任何 systemctl、未删除任何文件（文件树 md5 应保持不变）。"
}

# <<< 242B END P0-3-plan <<< #
uninstall() {
  require_root
  init_paths
  log "卸载目标前缀：${INSTALL_ROOT:-<系统级>}；unit=$SERVICE（$SERVICE_PATH）"

  # **2.1.38 修法③/⑤**：事故 #2 —— 包自测的 PATH 里没有隔离 shim，`install.sh uninstall`
  # 于是直接 `systemctl stop/disable ebpdns.service`，停掉的却是**真 systemd unit**（生产 35 min）。
  # 现在的两道路障：
  #   ① 前缀内有**旧布局遗留**的 `ebpdns.service`（名字与系统级 unit 同名）⇒ 直接拒绝；
  #   ② 前缀模式下，unit 文件路径必须在前缀内，且 stop/disable 只对**前缀内确实存在**的
  #      那个 unit 文件执行 ⇒ `systemctl` 不可能被指向系统级 unit。
  if [ -n "$INSTALL_ROOT" ] && [ -f "$SERVICE_DIR/ebpdns.service" ] && [ "$SERVICE" != "ebpdns.service" ]; then
    if [ "$FORCE" = "1" ]; then
      warn "--force：删除旧布局遗留 unit 文件 $SERVICE_DIR/ebpdns.service（**只删文件**，不对它执行 systemctl）。"
      rm -f "$SERVICE_DIR/ebpdns.service"
    else
      err "拒绝卸载：$SERVICE_DIR/ebpdns.service 是**旧布局遗留**的 unit 文件名，"
      err "  而 \`systemctl stop/disable ebpdns.service\` 命中的是**系统级**（生产）unit。"
      err "  本次**未**调用 systemctl、**未**删除任何文件。"
      err "  修法：① 先删遗留文件：rm -f $SERVICE_DIR/ebpdns.service；或"
      err "        ② 确认它只是遗留文件后再加 --force（只会删文件，不会动系统级 unit）。"
      return 1
    fi
  fi

  if [ -n "$INSTALL_ROOT" ] && ! _in_prefix "$SERVICE_PATH"; then
    err "拒绝卸载：unit 路径 $SERVICE_PATH 不在前缀 ${PFX_REAL:-/} 内。"
    return 1
  fi

  local have_unit=0
  [ -f "$SERVICE_PATH" ] && have_unit=1
  if [ -z "$INSTALL_ROOT" ]; then
    have_unit=1  # 生产：/etc/systemd/system/ebpdns.service 就是本机的 unit
  fi
  if [ "$have_unit" != "1" ]; then
    info "前缀内没有 unit 文件（$SERVICE_PATH）：不执行任何 systemctl stop/disable（避免命中系统级 unit）。"
  elif command -v systemctl >/dev/null 2>&1; then
    local frag=""
    frag="$(systemctl show -p FragmentPath --value "$SERVICE" 2>/dev/null || true)"
    SERVICE_FRAG="$frag"
    if [ -n "$INSTALL_ROOT" ] && [ -n "$frag" ] && ! _in_prefix "$frag"; then
      if [ "$FORCE" = "1" ]; then
        warn "--force：FragmentPath=$frag 在前缀外，仍按**前缀内派生**的 unit 名 $SERVICE 执行"
        warn "          （派生名不可能等于系统级 ebpdns.service，故不会命中生产 unit）。"
      else
        err "拒绝卸载：systemd 报告的 FragmentPath=$frag，无法证明 $SERVICE 属于前缀 $PFX_REAL。"
        err "  本次**未**调用 systemctl、**未**删除任何文件。"
        err "  修法：确认前缀内 unit 文件（$SERVICE_PATH）后重跑；确认无误会可加 --force"
        err "        （仍只对派生名 $SERVICE 执行，绝不指向系统级 ebpdns.service）。"
        return 1
      fi
    elif [ -n "$INSTALL_ROOT" ] && [ -z "$frag" ]; then
      info "systemd 未报出 FragmentPath：按前缀内 unit 文件 $SERVICE_PATH 证明归属。"
    fi
    log_target "unit=$SERVICE unit_path=$SERVICE_PATH FragmentPath=${frag:-<unknown>}"
    log "停止并禁用服务：$SERVICE"
    systemctl stop "$SERVICE" 2>/dev/null || true
    systemctl disable "$SERVICE" 2>/dev/null || true
  else
    info "未找到 systemctl：跳过 stop/disable。"
  fi
  rm -f "$SERVICE_PATH"
  if command -v systemctl >/dev/null 2>&1 && [ "$have_unit" = "1" ]; then systemctl daemon-reload 2>/dev/null || true; fi
  rm -f "$BIN_DST"
  rm -rf "$WEB_DST"
  if [ "$PURGE" = "1" ]; then
    warn "--purge：删除 $CONF_DIR 与 $STATE_DIR（不可恢复）。"
    rm -rf "$CONF_DIR" "$STATE_DIR"
  else
    log "已卸载二进制与服务（保留 $CONF_DIR 与 $STATE_DIR）。"
  fi
  return 0
}

# ============================================================================
# 参数解析（fail-closed；抽成独立函数以便脚本级单测）
# ============================================================================
ARGS_ACTION=""
DO_MIGRATE=0
DO_ADOPT=0

parse_args() {
  local a
  ARGS_ACTION=""
  DO_MIGRATE=0
  DO_ADOPT=0
  DRY_RUN=0
  PURGE=0
  FORCE=0
  RESTART=0
  KEEP_RUNNING=0
  MIGRATE_STATE_DIR=""
  local pos=()
  while [ "$#" -gt 0 ]; do
    a="$1"
    shift
    case "$a" in
      -h|--help) usage; exit 0 ;;
      --unit-name) init_paths; printf '%s\n' "$SERVICE"; exit 0 ;;
      --strict-config) STRICT_CONFIG=1 ;;
      --migrate-config) DO_MIGRATE=1 ;;
      --adopt-new-defaults) DO_ADOPT=1 ;;
      --dry-run) DRY_RUN=1 ;;
      --force) FORCE=1 ;;
      --restart) RESTART=1 ;;
      --keep-running) KEEP_RUNNING=1 ;;
      --purge) PURGE=1 ;;
      --uninstall) pos+=("uninstall") ;;
      --state-dir)
        if [ "$#" -lt 1 ] || [ -z "${1:-}" ]; then
          err "--state-dir 需要一个目录参数（例：--state-dir /var/lib/ebpdns-state-isolated）。"
          err "用法见：./install.sh --help"
          exit 1
        fi
        MIGRATE_STATE_DIR="$1"
        shift
        ;;
      --state-dir=*)
        MIGRATE_STATE_DIR="${a#--state-dir=}"
        if [ -z "$MIGRATE_STATE_DIR" ]; then
          err "--state-dir= 后面的目录不能为空。用法见：./install.sh --help"
          exit 1
        fi
        ;;
      -*)
        err "未知开关：$a"
        err "用法见：./install.sh --help"
        exit 1
        ;;
      *) pos+=("$a") ;;
    esac
  done
  if [ "${#pos[@]}" -gt 1 ]; then
    err "多余的位置参数：${pos[*]:1}（只接受一个动作：install / start / uninstall）"
    err "用法见：./install.sh --help"
    exit 1
  fi
  ARGS_ACTION="${pos[0]:-install}"
  case "$ARGS_ACTION" in
    install|start|uninstall) ;;
    *)
      err "未知动作：$ARGS_ACTION（只支持 install / start / uninstall）"
      err "用法见：./install.sh --help"
      exit 1
      ;;
  esac
  if [ -n "${MIGRATE_STATE_DIR}" ] && [ "$DO_MIGRATE" != "1" ]; then
    warn "--state-dir $MIGRATE_STATE_DIR 只对 --migrate-config 生效；本次没有 --migrate-config，**已忽略（未生效）**。"
    MIGRATE_STATE_DIR=""
  fi
  if [ "$PURGE" = "1" ] && [ "$ARGS_ACTION" != "uninstall" ]; then
    err "--purge 只能与 uninstall 同用。用法见：./install.sh --help"
    exit 1
  fi
  if [ "$RESTART" = "1" ] && [ "$KEEP_RUNNING" = "1" ]; then
    err "--restart（先停后启）与 --keep-running（不动运行中的进程）互斥，不能同时给出。"
    err "用法见：./install.sh --help"
    exit 1
  fi
  if [ "$ARGS_ACTION" = "uninstall" ] && { [ "$RESTART" = "1" ] || [ "$KEEP_RUNNING" = "1" ]; }; then
    err "--restart / --keep-running 只能与 install 或 start 同用（uninstall 不接受）。"
    err "用法见：./install.sh --help"
    exit 1
  fi
  return 0
}

print_plan() {
  log "[dry-run] 目标前缀：${INSTALL_ROOT:-<系统级>}（realpath=${PFX_REAL:-/}）；unit=$SERVICE"
  log "[dry-run] 端口来源 = ${PORTS_SOURCE:-<未解析>}；端口 = ${PORTS:-<无>}"
  log "[dry-run] 将确保运行账号：$RUN_USER:$RUN_GROUP（已存在则跳过；缺 groupadd/useradd 时分级回退/优雅降级）"
  log "[dry-run] 将创建目录：$WEB_DST $CONF_DIR $STATE_DIR"
  log "[dry-run] 将安装：$BIN_DST（0755）、$WEB_DST（静态资源）"
  log "[dry-run] 将安装配置：$CONF_FILE（已存在则保留）"
  log "[dry-run] 将设置属主：$RUN_USER:$RUN_GROUP（不可用时退化为 root:root）"
  if [ "$KEEP_RUNNING" = "1" ]; then
    log "[dry-run] --keep-running：不会停止/重启运行中的进程（pid=${OLD_PID:-${OLD_PIDS:-none}}）；新二进制下次重启生效"
  elif [ -n "$OLD_PIDS" ] || [ "$SERVICE_WAS_ACTIVE" = "1" ]; then
    log "[dry-run] 将先停止旧实例（pid=${OLD_PID:-${OLD_PIDS:-unknown}}，exe=$(proc_exe "${OLD_PID:-${OLD_PIDS%% *}}")，unit=$SERVICE，unit_path=$SERVICE_PATH）并确认端口释放，然后继续安装"
  fi
  if systemd_available; then
    log "[dry-run] 将安装 unit：$SERVICE_PATH 并 enable${ARGS_ACTION:+（action=$ARGS_ACTION）}"
    if [ "$KEEP_RUNNING" = "1" ]; then
      log "[dry-run] --keep-running：不执行 systemctl start/restart"
    elif [ "$EFFECTIVE_START" = "1" ]; then
      log "[dry-run] 将 systemctl restart $SERVICE（先停后启）"
    fi
  else
    log "[dry-run] 未检测到 systemd：将只装文件并打印手动启动命令"
  fi
  log "[dry-run] 未改动任何系统文件。"
  return 0
}

main() {
  # **2.1.38**：`--unit-name` 是**只读查询**（不 require_root、不写任何东西、不改任何状态）。
  local a
  for a in "$@"; do
    case "$a" in
      --unit-name) init_paths; printf '%s\n' "$SERVICE"; exit 0 ;;
    esac
  done
  require_root
  init_paths
  parse_args "$@"
  local action="$ARGS_ACTION"
  local REMEDY_RC=0
  export REMEDY_RC
  EFFECTIVE_START=0
  if [ "$action" = "start" ] || [ "$RESTART" = "1" ]; then
    EFFECTIVE_START=1
  fi
  if [ "$DO_MIGRATE" = "1" ] && [ "$DO_ADOPT" = "1" ]; then
    warn "--migrate-config 与 --adopt-new-defaults 同时给出：以**只做加法**的 --migrate-config 为准。"
    DO_ADOPT=0
  fi
# >>> 242B BEGIN P0-3-dispatch >>> #
  # **2.1.42-B（P0-3）**：DRY_RUN 判定**前置到所有破坏性分派之前**。
  # 旧顺序把 uninstall 放在 :1328 的 DRY_RUN 判断之前 ⇒ `uninstall --dry-run`
  # 仍会 stop/disable、删 bin/web，`--purge` 还会删 /etc/ebpdns 与 state。
  if [ "$DRY_RUN" = "1" ] && [ "$action" = "uninstall" ]; then
    print_uninstall_plan
    exit 0
  fi
  if [ "$action" = "uninstall" ]; then uninstall || exit $?; exit 0; fi
# <<< 242B END P0-3-dispatch <<< #
  preflight_layout
  preflight_config
  preflight_binary_runnable

  # **2.1.32**：先识别「本服务已在运行」还是「别的进程占端口」，再决定是否停旧实例。
  # **2.1.38**：端口来源改为 `configured_ports`（目标前缀配置 / 显式覆盖），**不再**把包内
  # 路径传进来；检测里带路径约束 ⇒ 前缀外的 ebpdns 一律 rc=1 且不发信号。
  # 只读；任何拒绝都发生在**写操作之前**（`--dry-run` 也走同一条拒绝路径）。
  detect_running || exit 1
  if [ "$KEEP_RUNNING" != "1" ] && { [ "$SERVICE_WAS_ACTIVE" = "1" ] || [ -n "$OLD_PIDS" ]; }; then
    if [ "$EFFECTIVE_START" != "1" ]; then
      err "检测到本服务已在运行（pid=${OLD_PID:-${OLD_PIDS:-unknown}}）：install（未带 start / --restart）不会停止运行中的实例。"
      err "  升级请用：sudo $0 start（默认先停后启）或 sudo $0 --restart start"
      err "  只想更新文件、不动进程：sudo $0 --keep-running start"
      exit 1
    fi
  fi
  if [ "$DRY_RUN" = "1" ]; then print_plan; exit 0; fi
  if [ "$KEEP_RUNNING" != "1" ] && [ "$EFFECTIVE_START" = "1" ] &&
    { [ "$SERVICE_WAS_ACTIVE" = "1" ] || [ -n "$OLD_PIDS" ]; }; then
    stop_own_instance || exit 1
  fi
  check_ports || exit 1

  # 1) 专用降权用户/组（幂等 + 分级回退，绝不中止）。
  ensure_service_account || true

  # 2) 目录（含 BIN_DST 的父目录；临时前缀 EBP_INSTALL_ROOT 下也成立）。
  install -d -m 0755 "$(dirname "$BIN_DST")" "$WEB_DST" "$CONF_DIR" "$STATE_DIR"

  # 3) 二进制 + 前端静态资源。
  log "安装二进制 -> $BIN_DST"
  if ! install_binary "$(dirname "$0")/bin/ebpdns" "$BIN_DST"; then
    err "安装二进制失败：$BIN_DST"
    exit 1
  fi
  chown_service "$BIN_DST"
  if [ -d "$(dirname "$0")/web" ]; then
    log "安装前端静态资源 -> $WEB_DST"
    cp -a "$(dirname "$0")/web/." "$WEB_DST/"
  fi

  # 4) 配置（不覆盖已有配置）。
  local tpl_cfg
  tpl_cfg="$(dirname "$0")/etc/ebpdns/config.json"
  if [ ! -f "$CONF_FILE" ]; then
    if [ -f "$tpl_cfg" ]; then
      log "安装默认配置 -> $CONF_FILE"
      install -m 0640 "$tpl_cfg" "$CONF_FILE"
      chown_service "$CONF_FILE"
    fi
    if [ "$DO_MIGRATE" = "1" ] || [ "$DO_ADOPT" = "1" ]; then
      warn "本次是**全新安装**（$CONF_FILE 不存在）：迁移/覆盖旗标无事可做（已装包内默认配置）。"
    fi
  else
    if [ "$DO_MIGRATE" = "1" ]; then
      apply_migrate_config "$BIN_DST" "$CONF_FILE" "$MIGRATE_STATE_DIR" || REMEDY_RC=$?
      inspect_existing_config "$BIN_DST" "$CONF_FILE"
    elif [ "$DO_ADOPT" = "1" ]; then
      apply_adopt_new_defaults "$CONF_FILE" "$tpl_cfg" || REMEDY_RC=$?
      inspect_existing_config "$BIN_DST" "$CONF_FILE"
    else
      inspect_existing_config "$BIN_DST" "$CONF_FILE"
    fi
  fi

  # 5) 状态目录属主。
  chown_r_service "$STATE_DIR"
  chmod 0750 "$STATE_DIR"

  # 5b) 配置目录属主。
  chown_service "$CONF_DIR"
  chmod 0750 "$CONF_DIR"
  [ -f "$CONF_FILE" ] && chown_service "$CONF_FILE"

  # 6) 文件能力。
  if command -v setcap >/dev/null 2>&1; then
    setcap 'cap_net_bind_service=+ep' "$BIN_DST" || \
      warn "setcap 失败（可改用 systemd 的 AmbientCapabilities）。"
  else
    warn "未找到 setcap，跳过文件能力设置（systemd 单元已含 AmbientCapabilities）。"
  fi

  # 6.5) 安装后、enable/start 之前复核配置。
  postinstall_check_config

  # 7) systemd（可选）。
  if systemd_available; then
    log "安装 systemd 单元……"
    install -d -m 0755 "$SERVICE_DIR"
    prepare_unit "$SERVICE_PATH" "$SERVICE_SRC"
    systemctl daemon-reload
    systemctl enable "$SERVICE"
    if [ "$KEEP_RUNNING" = "1" ]; then
      log "--keep-running：不 start/restart $SERVICE（只更新文件；新二进制将在下次重启后生效）"
    elif [ "$EFFECTIVE_START" = "1" ]; then
      log "启动 $SERVICE"
      systemctl restart "$SERVICE" || warn "服务启动失败，请用 'journalctl -u $SERVICE' 排查。"
      local nr active
      nr="$(systemctl show -p NRestarts --value "$SERVICE" 2>/dev/null || true)"
      active="$(systemctl is-active "$SERVICE" 2>/dev/null || true)"
      [ -n "$active" ] && log "启动后状态：active=$active${nr:+，NRestarts=$nr}"
    else
      log "已 enable，未启动。可执行：systemctl start $SERVICE"
    fi
  elif [ "$KEEP_RUNNING" = "1" ]; then
    info "--keep-running：未检测到 systemd；只更新文件，**不启动**新实例（需手工在下次重启时启动）。"
  else
    if [ -d "$SERVICE_DIR" ]; then
      prepare_unit "$SERVICE_PATH" "$SERVICE_SRC" 2>/dev/null || true
    fi
    manual_start_hint
  fi

  log "安装完成。版本：$("$BIN_DST" --version 2>/dev/null || echo unknown)"
  if [ "$SERVICE_ACCOUNT_OK" = "0" ]; then
    warn "本次安装**未能创建专用运行账号**：服务当前以 root 运行（unit/chown 已降级），请尽快补建账号后重跑。"
  fi
  if [ "${REMEDY_RC:-0}" != "0" ]; then
    case "${REMEDY_RC}" in
      3) err "补救操作**未落盘**（--migrate-config 退出码 3）：配置里没有 \`state_dir\` 且本次未给 \`--state-dir\`\
  ⇒ 二进制拒绝默认落到生产路径 \`/var/lib/ebpdns/state\`，因此**未改动任何文件**。\
  安装本身已完成；请显式给出状态目录后重跑：\`$BIN_DST migrate-config --config $CONF_FILE --state-dir <专用目录>\`" ;;
      4) warn "补救操作**已写回配置、但提交点未更新**（--migrate-config 退出码 4）：\
 配置内容已是迁移后的内容，重锚 \`state/\` 失败（最常见原因：服务正在运行、持有 \`state/.lock\`）。\
 安装本身已完成；停服后重跑 \`$BIN_DST migrate-config --config $CONF_FILE\` 即可补齐提交点。" ;;
      *) err "补救操作失败（--migrate-config / --adopt-new-defaults 退出码 $REMEDY_RC）：\
 安装本身已完成，但配置**未被**按旗标处理，请据上方错误处理后重试。" ;;
    esac
    return "$REMEDY_RC"
  fi
  return 0
}

main "$@"
