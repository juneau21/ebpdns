#!/usr/bin/env bash
# ebpdns v2.1.17 安装脚本（Rust 版；以 Python v1.9.162 为行为参照）
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
  err "       tar xzf ebpdns-2.1.17-prod.tar.gz && cd ebpdns-2.1.17 && sudo ./install.sh start"
  err "  2) 从源码树构建并打包（源码树里本来就没有 bin/ebpdns）："
  err "       make wasm && cargo build --release --bin ebpdns --features embed-frontend"
  err "       ./scripts/make_packages.sh      # 生成 dist/ebpdns-*-prod.tar.gz"
  err "       tar xzf <生成的 prod 包> && cd ebpdns-2.1.17 && sudo ./install.sh start"
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

# **2.1.17（修复项 1③）**：安装前调用 `ebpdns check-config` 预检待安装的配置。
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
preflight_config() {
  local bin_src conf strict=0
  bin_src="$(cd "$(dirname "$0")" && pwd)/bin/ebpdns"
  conf="$(dirname "$0")/etc/ebpdns/config.json"
  [ "${STRICT_CONFIG:-0}" = "1" ] && strict=1
  [ -f "$conf" ] || return 0
  if [ ! -x "$bin_src" ]; then
    warn "跳过 check-config 预检（未找到可执行的 $bin_src）"
    return 0
  fi
  local out rc
  # 用包内二进制校验包内配置（发布前一致性），失败不因 set -e 中断。
  out="$("$bin_src" check-config --config "$conf" 2>&1)" && rc=0 || rc=$?
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
  # 放在 action 解析**之前**：允许 `./install.sh --strict-config start` 与
  # `./install.sh start --strict-config` 两种写法。
  local args=() a
  for a in "$@"; do
    case "$a" in
      --strict-config) STRICT_CONFIG=1 ;;
      *) args+=("$a") ;;
    esac
  done
  local action="${args[0]:-install}"
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
  if [ ! -f "$CONF_FILE" ]; then
    if [ -f "$(dirname "$0")/etc/ebpdns/config.json" ]; then
      log "安装默认配置 -> $CONF_FILE"
      install -m 0640 -o "$RUN_USER" -g "$RUN_GROUP" \
        "$(dirname "$0")/etc/ebpdns/config.json" "$CONF_FILE"
    fi
  else
    warn "已存在 $CONF_FILE，保留不覆盖。"
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
