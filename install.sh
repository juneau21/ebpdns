#!/usr/bin/env bash
# ebpdns v2.1.18 安装脚本（Rust 版；以 Python v1.9.162 为行为参照）
# 用法：
#   sudo ./install.sh            # 安装并 enable（不自动 start）
#   sudo ./install.sh start      # 安装、enable 并立即 start
#   sudo ./install.sh uninstall  # 卸载（保留配置与缓存）
set -euo pipefail

BIN_DST=/usr/local/bin/ebpdns
LIB_DIR=/usr/local/lib/ebpdns
WEB_DST=/usr/local/share/ebpdns/web
CONF_DIR=/etc/ebpdns
CONF_FILE="$CONF_DIR/config.json"
STATE_DIR=/var/lib/ebpdns
SERVICE=ebpdns.service
SERVICE_SRC="$(dirname "$0")/systemd/ebpdns.service"
RUN_USER=ebpdns
RUN_GROUP=ebpdns

log() { printf '\033[1;32m[install]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
err() { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; }

# **2.1.15（P3）**：包布局预检。
#
# 本脚本按**预编译包布局**取产物（`$(dirname $0)/bin/ebpdns`），因此**必须**从解包后的
# 包根目录运行。旧实现在源码树里直接跑只会得到一句
# `install: cannot stat 'packaging/bin/ebpdns'`，看不出"该从哪里跑、怎么生成产物"。
#
# 现在：先给出明确的两种正确做法（用包 / 先构建再打包），再以退出码 2 退出；
# **不**静默回退到 `target/release/ebpdns` —— 那会把"来源不明的二进制"装进系统，
# 运维事后无法从版本号追溯它到底是不是发布包。
preflight_layout() {
  local here bin_src
  here="$(cd "$(dirname "$0")" && pwd)"
  bin_src="$here/bin/ebpdns"
  if [ -f "$bin_src" ]; then
    return 0
  fi
  err "未找到安装产物：$bin_src"
  err "本脚本必须从**预编译包根目录**运行（包布局：bin/ + etc/ + share/ + systemd/ + web/ + install.sh）。"
  err ""
  err "正确做法二选一："
  err "  1) 用预编译包（推荐）："
  err "       tar xzf ebpdns-2.1.18-prod.tar.gz && cd ebpdns-2.1.18 && sudo ./install.sh start"
  err "  2) 从源码树构建并打包（源码树里本来就没有 bin/ebpdns）："
  err "       make wasm && cargo build --release --bin ebpdns --features embed-frontend"
  err "       ./scripts/make_packages.sh      # 生成 dist/ebpdns-*-prod.tar.gz"
  err "       tar xzf <生成的 prod 包> && cd ebpdns-2.1.18 && sudo ./install.sh start"
  err ""
  err "（若确实只想在源码树里装：install -m0755 target/release/ebpdns /usr/local/bin/ebpdns）"
  exit 2
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "请以 root（或 sudo）运行本脚本。" >&2
    exit 1
  fi
}

# **2.1.17（修复项 1③）/ 2.1.18（修复项 1①）**：安装前调用 `ebpdns check-config`
# 预检待安装的配置。
#
# 为什么需要它：2.1.16 的 `check-config` 子命令已经能给出**类型 / 范围 / 枚举 /
# 未知键 / config_version 过高**的诊断，但**没有任何调用点** —— 安装脚本直接把包内
# 的 `etc/ebpdns/config.json` 拷到 `/etc/ebpdns/`、enable+start，配置里一个拼错的键名
# 或非法取值要到服务起来之后（或根本起不来、只在 journal 里留一行）才被发现。
#
# **默认不阻断安装**（`--strict-config` 才阻断），理由：
#   1. `check-config` 的 ERROR 里有一类是**兼容性**问题而非致命问题（例如
#      `config_version` 高于本二进制 —— 那是"该用更新版本的 ebpdns"，而不是
#      "配置坏了"；把安装直接打断会让升级/回滚流程更难做）；
#   2. 安装脚本还要服务"装好但先不启动（`install.sh` 不带 `start`）"的场景，
#      此时用户可能正打算装完再手工调整配置；
#   3. 目标机可能**没有可执行的 ebpdns**（例如纯离线校验另有所依），
#      硬阻断会把"能装但配置有警告"变成"完全装不了"。
#   因此：**显著 WARN + 打印原始诊断 + 给出修法与开关**，把决定权交给运维；
#   需要 CI/生产强一致时用 `--strict-config` 让它变成硬门（退出码 2）。
#
# **2.1.18（修复项 1①）：不得因"包内二进制缺少执行位"而静默跳过。**
#
# 用户实测的缺陷：从 Windows/非 Unix 环境解包（zip、Windows 资源管理器、
# `python -m tarfile`、某些 SFTP 客户端）后 `bin/ebpdns` **没有执行位**，
# 于是 2.1.17 的实现走到 `[ ! -x "$bin_src" ]` 分支、只打一句
# `[warn] 跳过 check-config 预检` —— 预检**静默失效**，而安装本身照样成功，
# 运维会以为"配置已经检查过了"。
# 现在：
#   - `bin/ebpdns` 存在但不可执行 ⇒ **`install -m 0755` 到临时路径后照常预检**
#     （明确打印"已用临时副本预检"），临时副本用完即删；
#   - 只有当**根本没有**可用的二进制时才算"跳过"，并且**必须**打印：
#     ① 跳过原因、② 补救命令（`chmod +x bin/ebpdns install.sh`）、
#     ③ 这次安装少了哪一道检查。
# 另：`--migrate-config` / `--adopt-new-defaults` 两条补救路径也在这里提示。
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
  # 组装"可执行的包内二进制"：直接可用就用它；不可执行（跨平台解包丢执行位）
  # 就复制一份 0755 的临时副本 —— **不修改包内文件**（包可能只读/已签名）。
  local exec_bin="$bin_src" tmpdir="" used_tmp=0
  if [ ! -x "$bin_src" ]; then
    if tmpdir="$(mktemp -d 2>/dev/null)"; then
      if install -m 0755 "$bin_src" "$tmpdir/ebpdns" 2>/dev/null; then
        exec_bin="$tmpdir/ebpdns"
        used_tmp=1
        warn "包内二进制缺少执行位（$bin_src）—— 典型的**跨平台解包丢权限**"
        warn "  已用临时副本预检（install -m 0755 → $exec_bin），安装行为不变"
        warn "  建议修复包内权限（否则手工执行 bin/ebpdns 仍会失败）："
        warn "      chmod +x bin/ebpdns install.sh"
        warn "      # 或重新用 Linux tar 解包：tar -xzf ebpdns-*-prod.tar.gz"
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
  # 用包内二进制校验包内配置（发布前一致性），失败不因 set -e 中断。
  out="$("$exec_bin" check-config --config "$conf" 2>&1)" && rc=0 || rc=$?
  [ "$used_tmp" = "1" ] && rm -rf "$tmpdir"
  if [ "$rc" -eq 0 ]; then
    # 退出码 0 仍可能有 WARN（未知键 / 缺 config_version）→ 原样打印，别吞掉。
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
  err "开关：默认**不阻断安装**（见 install.sh::preflight_config 的三条理由）；"
  err "     需要硬门时：sudo STRICT_CONFIG=1 ./install.sh start"
  err "     （或 ./install.sh --strict-config start）—— 此时以退出码 2 中止。"
  if [ "$strict" = "1" ]; then
    err "STRICT_CONFIG=1：已按严格模式中止安装。"
    exit 2
  fi
  warn "继续安装（**默认非阻断**）；服务可能因该配置异常而启动失败，请留意 journalctl。"
  return 0
}

# **2.1.18（修复项 1②）**：目标配置已存在时的**迁移/校验提示**。
#
# 2.1.17 的缺陷：保留已有配置时只打一句
# `[warn] 已存在 /etc/ebpdns/config.json，保留不覆盖。` —— 既不说这份配置**能不能用**，
# 也不说它**缺了本版本新增的哪些键**（旧配置缺键时，ebpdns 会按内置默认值运行，
# 页面上的开关/字段可能与 config.json 不一致，运维无从发现）。
#
# 现在打印三件事（判据全部来自**已安装的二进制**，不依赖脚本自己维护键表）：
#   ① `check-config` 对该文件的结果（0 / 2 + 逐条诊断）；
#   ② 缺失的顶层键**个数与名字**（= `default_config()` 键集差集，由
#      `ebpdns migrate-config --dry-run` 计算）；
#   ③ 两条可采用的新旗标：
#      - `--migrate-config`：**只做加法**补齐缺失键（写前备份 `config.json.bak.<ts>`）；
#      - `--adopt-new-defaults`：用包内模板**覆盖**（同样先备份，会丢本地改动）。
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
      warn "           sudo $0 --migrate-config"
      warn "         或先用包内模板**整体覆盖**（同样先备份，会丢本地改动）："
      warn "           sudo $0 --adopt-new-defaults"
      warn "         也可只预览不改动：$bin_dst migrate-config --config $conf --dry-run" ;;
  esac
  warn "  ③ 语义与退出码见 README「安装与升级」/ PACKAGING 文档。"
}

# **2.1.18（修复项 1②）**：`--migrate-config` —— 只做加法补齐缺失键（写前备份）。
apply_migrate_config() {
  local bin_dst="$1" conf="$2"
  log "--migrate-config：对 $conf 执行**只做加法**的键补齐（写前备份）……"
  local out rc
  out="$("$bin_dst" migrate-config --config "$conf" 2>&1)" && rc=0 || rc=$?
  printf '%s\n' "$out" | sed 's/^/    /'
  case "$rc" in
    0) log "--migrate-config 完成（退出码 0）" ;;
    2) err "--migrate-config 失败：配置不可迁移（退出码 2，文件未被改动）" ;;
    *) err "--migrate-config 失败：IO/备份失败（退出码 $rc）" ;;
  esac
  return 0
}

# **2.1.18（修复项 1②）**：`--adopt-new-defaults` —— 用包内模板覆盖（写前备份）。
apply_adopt_new_defaults() {
  local conf="$1" tpl="$2"
  if [ ! -f "$tpl" ]; then
    err "--adopt-new-defaults：包内模板不存在（$tpl）—— 包不完整，已跳过。"
    return 0
  fi
  local ts bak
  ts="$(date +%Y%m%d%H%M%S 2>/dev/null || echo 0)"
  bak="$conf.bak.$ts"
  log "--adopt-new-defaults：备份 $conf → $bak，然后用包内模板覆盖。"
  cp -p "$conf" "$bak" || { err "备份失败：未覆盖 $conf"; return 0; }
  install -m 0640 -o "$RUN_USER" -g "$RUN_GROUP" "$tpl" "$conf" || {
    err "覆盖失败：已保留备份 $bak（原文件可能仍完好）"
    return 0
  }
  log "--adopt-new-defaults 完成（旧配置在 $bak；本地改动**不会**被保留）"
}

# **2.1.18（修复项 1①）**：安装完成后、`systemctl enable` **之前**，用**已安装的
# 二进制**对**目标配置**再跑一次 check-config。
#
# 为什么必须有第二道：第一道（`preflight_config`）校验的是**包内**配置、
# 用的是**包内**二进制，而且"包内二进制缺执行位"时还要走临时副本 —— 三种情形都
# 可能让"预检"与"真正要跑的那份配置/那个二进制"不是同一个东西。安装后复核则
# **恒等于服务将要面对的现场**（`$BIN_DST` + `$CONF_FILE`），因此预检**永不**因
# 源权限、包布局或路径差异被绕过。
#
# 语义：与第一道一致 —— 默认**非阻断但显著打印**；`--strict-config` /
# `STRICT_CONFIG=1` 时以退出码 2 中止（此时二进制已装好、配置已就位，
# 中止只是不 enable/start，便于修好后重跑）。
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

uninstall() {
  require_root
  log "停止并禁用服务……"
  systemctl stop "$SERVICE" 2>/dev/null || true
  systemctl disable "$SERVICE" 2>/dev/null || true
  rm -f "/etc/systemd/system/$SERVICE"
  systemctl daemon-reload || true
  rm -f "$BIN_DST"
  rm -rf "$LIB_DIR" "$WEB_DST"
  log "已卸载二进制与服务（保留 $CONF_DIR 与 $STATE_DIR）。"
}

main() {
  require_root
  # `--strict-config` 等价于 `STRICT_CONFIG=1`（**2.1.17 修复项 1③**）。
  # `--migrate-config` / `--adopt-new-defaults`（**2.1.18 修复项 1②**）也会被消费掉，
  # 不参与 action 解析。放在 action 解析**之前**：允许
  # `./install.sh --strict-config start` 与 `./install.sh start --strict-config` 两种写法。
  local args=() a
  local DO_MIGRATE=0 DO_ADOPT=0
  for a in "$@"; do
    case "$a" in
      --strict-config) STRICT_CONFIG=1 ;;
      --migrate-config) DO_MIGRATE=1 ;;
      --adopt-new-defaults) DO_ADOPT=1 ;;
      *) args+=("$a") ;;
    esac
  done
  local action="${args[0]:-install}"
  # **2.1.18（修复项 1②）**：两条旗标都只对"安装/升级已有配置"有意义。
  # 冲突时以 `--migrate-config` 为准（加法优先，避免误覆盖）。
  if [ "$DO_MIGRATE" = "1" ] && [ "$DO_ADOPT" = "1" ]; then
    warn "--migrate-config 与 --adopt-new-defaults 同时给出：以**只做加法**的 --migrate-config 为准。"
    DO_ADOPT=0
  fi
  # 卸载不需要产物（BIN_DST/LIB_DIR 是固定系统路径），故预检只对安装路径生效。
  if [ "$action" = "uninstall" ]; then uninstall; exit 0; fi
  preflight_layout
  # **2.1.17（修复项 1③）**：布局预检通过后、**任何写操作之前**先做配置预检。
  preflight_config

  # 1) 专用降权用户/组。
  if ! getent group "$RUN_GROUP" >/dev/null; then
    log "创建系统组 $RUN_GROUP"
    groupadd --system "$RUN_GROUP"
  fi
  if ! id "$RUN_USER" >/dev/null 2>&1; then
    log "创建系统用户 $RUN_USER"
    useradd --system --gid "$RUN_GROUP" --home-dir "$STATE_DIR" \
      --shell /usr/sbin/nologin --comment "ebpdns DNS service" "$RUN_USER"
  fi

  # 2) 目录。
  install -d -m 0755 "$LIB_DIR" "$WEB_DST" "$CONF_DIR" "$STATE_DIR"

  # 3) 二进制 + eBPF + 前端静态资源（前端已嵌入二进制，此处额外留档）。
  log "安装二进制 -> $BIN_DST"
  install -m 0755 "$(dirname "$0")/bin/ebpdns" "$BIN_DST"
  # eBPF/XDP 程序：**允许缺失**——本版 artifact 在 kernel 6.12 上被 verifier 拒绝、
  # 默认 kernel_cache=false 不会用到它（见 docs/EBPF.md）。缺失时只告警，不得让安装失败。
  if [ -f "$(dirname "$0")/share/ebpdns/ebpdns-xdp" ]; then
    log "安装 eBPF 程序 -> $LIB_DIR/ebpdns-xdp"
    install -m 0644 "$(dirname "$0")/share/ebpdns/ebpdns-xdp" "$LIB_DIR/ebpdns-xdp"
  else
    warn "未随包提供 eBPF/XDP 程序（kernel_cache=false 不需要）；如需内核直答请按 docs/EBPF.md 自行构建"
  fi
  if [ -d "$(dirname "$0")/web" ]; then
    log "安装前端静态资源 -> $WEB_DST"
    cp -a "$(dirname "$0")/web/." "$WEB_DST/"
  fi

  # 4) 配置（不覆盖已有配置）。
  #
  # **2.1.18（修复项 1②）**：保留已有配置时不再"只说一句保留"，而是给出
  # ① `check-config` 结果 ② 缺失键个数/名字 ③ 两条新旗标的用法（见
  # `inspect_existing_config`）。`--migrate-config` / `--adopt-new-defaults` 在
  # **这里**执行（要等 `$BIN_DST` 装好、`$CONF_DIR` 属主设好之后）。
  local tpl_cfg
  tpl_cfg="$(dirname "$0")/etc/ebpdns/config.json"
  if [ ! -f "$CONF_FILE" ]; then
    if [ -f "$tpl_cfg" ]; then
      log "安装默认配置 -> $CONF_FILE"
      install -m 0640 -o "$RUN_USER" -g "$RUN_GROUP" "$tpl_cfg" "$CONF_FILE"
    fi
    if [ "$DO_MIGRATE" = "1" ] || [ "$DO_ADOPT" = "1" ]; then
      warn "本次是**全新安装**（$CONF_FILE 不存在）：迁移/覆盖旗标无事可做（已装包内默认配置）。"
    fi
  else
    if [ "$DO_MIGRATE" = "1" ]; then
      apply_migrate_config "$BIN_DST" "$CONF_FILE"
      inspect_existing_config "$BIN_DST" "$CONF_FILE"
    elif [ "$DO_ADOPT" = "1" ]; then
      apply_adopt_new_defaults "$CONF_FILE" "$tpl_cfg"
      inspect_existing_config "$BIN_DST" "$CONF_FILE"
    else
      inspect_existing_config "$BIN_DST" "$CONF_FILE"
    fi
  fi

  # 5) 状态目录属主。
  chown -R "$RUN_USER:$RUN_GROUP" "$STATE_DIR"
  chmod 0750 "$STATE_DIR"

  # 5b) 配置目录属主 —— **必须**：运行期会原子写回 `config.json`（配置保存 / 规则 CRUD /
  # 订阅元信息），原子写需要在该目录内建 `.tmp` 再 `rename`。此前只把 config.json
  # 本身给了 ebpdns，目录仍是 root:root 0755 → 所有保存操作 `Permission denied (os error 13)`
  # → 控制台「保存配置 / 新增规则」全部 500（真实部署才暴露，高权限测试实例掩盖了它）。
  # 与 v1.9.162 install.sh 同型：`chown -R ebpdns:ebpdns /etc/ebpdns` + `chmod 750`。
  chown "$RUN_USER:$RUN_GROUP" "$CONF_DIR"
  chmod 0750 "$CONF_DIR"
  [ -f "$CONF_FILE" ] && chown "$RUN_USER:$RUN_GROUP" "$CONF_FILE"

  # 6) 文件能力（在非 systemd 场景下也能绑 53 / 加载挂载 XDP）。
  #
  # 能力名必须是 libcap 合法名且**全小写**：cap_bpf / cap_perfmon /
  # cap_net_admin。注意 cap_perfmonitor 之类是**无效名**，真机实测
  # setcap 会直接报 "fatal error: Invalid argument" 并退出码 1；写成无效名
  # 会让整条 setcap 失败，二进制一个能力都拿不到。
  #
  # CAP_NET_ADMIN（const char *cap 12）：XDP 程序的 BPF_PROG_LOAD 与原生
  # 驱动模式的 netlink 挂载都要求它；真机对照见 systemd 单元里的注释。
  #
  # 注意：本单元 NoNewPrivileges=true，**文件能力对 systemd 启动的进程不生效**
  # （NNP 会抑制 file caps）。systemd 部署真正生效的是单元里的
  # AmbientCapabilities；这里设置只为「直接命令行跑 /usr/local/bin/ebpdns」
  # 的场景，两者必须保持一致，否则会出现「手工跑能挂、systemd 跑挂不上」。
  if command -v setcap >/dev/null 2>&1; then
    setcap 'cap_net_bind_service,cap_bpf,cap_perfmon,cap_net_admin=+ep' "$BIN_DST" || \
      warn "setcap 失败（可改用 systemd 的 AmbientCapabilities）。"
  else
    warn "未找到 setcap，跳过文件能力设置（systemd 单元已含 AmbientCapabilities）。"
  fi

  # 6.5) **2.1.18（修复项 1①）**：安装后、enable/start **之前**的配置复核。
  #
  # 用**已安装的二进制**（$BIN_DST）对**目标配置**（$CONF_FILE）再跑一次
  # `check-config`：这才是服务将要面对的现场。即使前面因为"包内二进制缺执行位"
  # 走了临时副本、或包内配置与目标配置不是同一份，这一步也**不会**被绕过。
  postinstall_check_config

  # 7) systemd。
  if [ -d /etc/systemd/system ]; then
    log "安装 systemd 单元……"
    install -m 0644 "$SERVICE_SRC" "/etc/systemd/system/$SERVICE"
    systemctl daemon-reload
    systemctl enable "$SERVICE"
    if [ "$action" = "start" ]; then
      log "启动 $SERVICE"
      systemctl restart "$SERVICE" || warn "服务启动失败，请用 'journalctl -u $SERVICE' 排查。"
    else
      log "已 enable，未启动。可执行：systemctl start $SERVICE"
    fi
  else
    warn "未检测到 systemd，请手动运行：$BIN_DST --config $CONF_FILE --foreground"
  fi

  log "安装完成。版本：$("$BIN_DST" --version 2>/dev/null || echo unknown)"
}

main "${1:-install}"
