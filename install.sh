#!/usr/bin/env bash
# ============================================================
# ebpdns 安装脚本 (Debian 13 / 兼容 Debian 系)
#   用法: sudo ./install.sh
#         自动检测并安装依赖 (python3 / aioquic); 可用
#         EBPDNS_SKIP_DEPS=1 跳过自动安装(仅检测并提示)
#   支持两种场景:
#     A) 就地安装: 包已解压到 /opt/ebpdns, 直接在 /opt/ebpdns 下运行本脚本
#     B) 异地安装: 包在任意目录, 运行后拷贝到 /opt/ebpdns
#   安装结果: /opt/ebpdns (代码) + /etc/ebpdns (配置) + systemd 服务
# ============================================================
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/ebpdns"
CONF_DIR="/etc/ebpdns"
UNIT_FILE="/etc/systemd/system/ebpdns.service"
SERVICE_NAME="ebpdns"

# ---------- 检查权限 ----------
if [[ "$(id -u)" -ne 0 ]]; then
  echo "错误: 需要 root 权限, 请使用 sudo ./install.sh" >&2
  exit 1
fi

# ---------- 依赖检测与自动安装 ----------
# 自动安装开关: 默认开启; EBPDNS_SKIP_DEPS=1 仅检测并提示, 不自动安装
if [[ "${EBPDNS_SKIP_DEPS:-0}" == "1" ]]; then
  AUTO_DEPS=0
  echo "==> 0/4 依赖检测 (EBPDNS_SKIP_DEPS=1 已跳过自动安装)"
else
  AUTO_DEPS=1
  echo "==> 0/4 依赖检测与自动安装"
fi

# --- python3 ---
if ! command -v python3 >/dev/null 2>&1; then
  if [[ "$AUTO_DEPS" == "1" ]] && command -v apt-get >/dev/null 2>&1; then
    echo "    (未检测到 python3 → 自动安装 python3)"
    # P2-25(第九轮审查): 原 `|| true` 静默吞掉 apt-get update 失败, 网络/DNS 异常时
    # 用户不知道索引已过期, 后续安装到过期包才报错。改为打印 WARN 但继续安装。
    apt-get update -qq 2>/dev/null || echo "[WARN] apt-get update 失败，继续尝试安装（可能安装到过期包）"
    DEBIAN_FRONTEND=noninteractive apt-get install -y python3 >/dev/null 2>&1 \
      || { echo "错误: 自动安装 python3 失败, 请手动执行:  apt install -y python3" >&2; exit 1; }
  else
    echo "错误: 未检测到 python3, 请先安装:  apt install -y python3" >&2
    exit 1
  fi
fi

# --- Python 版本 ---
if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
  echo "错误: ebpdns 需要 Python 3.10+, 当前为 $(python3 --version 2>&1)" >&2
  echo "   Debian 13 自带 3.13; 其他系统请升级 Python 或改用 Python3.11+/3.12+" >&2
  exit 1
fi

# --- aioquic (DoQ/DoH3 上游需要; UDP/TCP/DoH/DoT 不依赖) ---
if ! python3 -c 'import aioquic' 2>/dev/null; then
  echo "    (未检测到 aioquic, DoQ/DoH3 上游需要它)"
  if [[ "$AUTO_DEPS" == "1" ]]; then
    _aq_ok=0
    # 优先 apt 系统包(与系统 python3 版本一致); 先 apt-get update 防索引过期
    # P2-25(第九轮审查): 同上, update 失败打印 WARN 但继续, 不静默吞掉。
    apt-get update -qq 2>/dev/null || echo "[WARN] apt-get update 失败，继续尝试安装（可能安装到过期包）"
    if command -v apt-get >/dev/null 2>&1 && apt-get install -y python3-aioquic >/dev/null 2>&1; then
      echo "    aioquic 已通过 apt 安装 (python3-aioquic)"
      _aq_ok=1
    elif command -v python3 >/dev/null 2>&1 && python3 -m pip --version >/dev/null 2>&1; then
      # 回退 python3 -m pip(保证装到与 python3 同版本的解释器);
      # PEP 668 系统 Python 需 --break-system-packages, 否则 pip 拒绝安装
      echo "    (apt 无 python3-aioquic, 改用 python3 -m pip 安装)"
      # R31 P3-3: 去掉 `2>/dev/null`, 让 pip 的错误诊断(网络错误/依赖冲突)透传到 stderr。
      # --quiet 仍抑制正常安装进度与"Successfully installed"提示, 不会刷屏; 失败时用户能看到具体原因。
      python3 -m pip install --quiet --break-system-packages aioquic && _aq_ok=1 \
        || echo "    (python3 -m pip 安装失败, 详见上方 pip 错误输出)" >&2
    fi
    if [[ "$_aq_ok" == "0" ]] && command -v pip3 >/dev/null 2>&1; then
      echo "    (最后尝试 pip3 安装)"
      # R31 P3-3: 同上, 不丢弃 pip3 stderr, 失败原因可见; 失败后下方已有友好兜底提示。
      pip3 install --quiet --break-system-packages aioquic && _aq_ok=1
    fi
    if [[ "$_aq_ok" == "1" ]] && python3 -c 'import aioquic' 2>/dev/null; then
      echo "    aioquic 安装成功 → DoQ/DoH3 上游可用"
    else
      echo "    警告: aioquic 自动安装失败, DoQ/DoH3 上游暂不可用" >&2
      echo "          (可稍后手动:  sudo python3 -m pip install aioquic)" >&2
      echo "          UDP/TCP/DoH/DoT 上游不受影响, 可继续安装" >&2
    fi
  else
    echo "    (已跳过自动安装) 未检测到 aioquic, DoQ/DoH3 上游暂不可用"
    echo "    (可稍后手动:  sudo python3 -m pip install aioquic; UDP/TCP/DoH/DoT 不受影响)"
  fi
else
  echo "    aioquic 已就绪 → DoQ/DoH3 上游可用"
fi


# ---------- 创建运行用户 ebpdns ----------
# systemd 以专用系统用户 ebpdns 运行服务(配合 User=ebpdns/Group=ebpdns)。
# 该用户无需登录 shell(nologin), 仅用于降权运行; home 指向代码目录 /opt/ebpdns。
# 不创建会导致 systemd 启动报 "Failed to determine user credentials"。
if ! getent group ebpdns >/dev/null 2>&1; then
  groupadd --system ebpdns
fi
if ! id -u ebpdns >/dev/null 2>&1; then
  useradd --system --gid ebpdns --home-dir /opt/ebpdns --shell /usr/sbin/nologin ebpdns
  echo "==> 已创建系统用户 ebpdns (运行服务, 无登录 shell)"
fi

# ---------- 1/4 代码就位 ----------
IN_PLACE=0
if [[ "$SRC_DIR" == "$INSTALL_DIR" ]]; then
  IN_PLACE=1
  echo "==> 检测到源码已位于 ${INSTALL_DIR} (就地安装), 跳过代码拷贝"
  # 完整性校验: 就地安装时关键文件必须齐全, 否则后续 systemd 启动必然失败
  # (历史问题: 早期版本就地安装缺文件时 cp 报错, 用户 VM 上 systemd 启动失败)
  # v1.9.80: 关键文件清单补全到运行时实际依赖(入口/包核心模块/前端页面与图表/unit)
  for _req in bin/ebpdns ebpdns/__init__.py ebpdns/__main__.py ebpdns/cli.py ebpdns/api.py \
              ebpdns/resolver.py ebpdns/server.py ebpdns/cache.py ebpdns/config.py \
              ebpdns/telemetry.py ebpdns/upstream.py ebpdns/dnsmsg.py ebpdns/probe.py \
              ebpdns/quic_upstream.py web/index.html web/echarts.min.js systemd/ebpdns.service; do
    if [[ ! -e "${INSTALL_DIR}/${_req}" ]]; then
      echo "错误: 就地安装缺少关键文件 ${INSTALL_DIR}/${_req}, 请确认完整解压部署包后再运行" >&2
      exit 1
    fi
  done
  # 就地安装: 包就在 /opt/ebpdns, 仍清理构建缓存(__pycache__/*.pyc),
  # 与异地 rsync/cp 分支行为对齐, 避免陈旧字节码随升级残留。
  find "${INSTALL_DIR}" -type d -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
  find "${INSTALL_DIR}" -name '*.pyc' -delete 2>/dev/null || true
else
  echo "==> 1/4 复制代码到 ${INSTALL_DIR}"
  # P2-26(第九轮审查): 异地安装前, 若发布包附带 SHA256SUMS, 先校验文件完整性。
  # 防止传输中断/磁盘损坏导致半拷贝包直接进 /opt, 后续 systemd 启动才报 ModuleNotFoundError。
  # 就地安装分支上方已做关键文件存在性检查, 此处只对异地拷贝包做 sha256 校验。
  if [ -f "$SRC_DIR/SHA256SUMS" ]; then
    echo "[INFO] 校验文件完整性..."
    # P3-5(R2 审查): sha256sum -c 失败时它本身已把 "FAILED" 行打到 stdout/stderr;
    # 原脚本只笼统打一句"文件完整性校验失败", 用户看不到哪个文件不通过。
    # 这里保留 sha256sum 的输出(不重定向), 失败后再补一句指向 FAILED 行的提示。
    (cd "$SRC_DIR" && sha256sum -c SHA256SUMS) || { echo "[ERROR] 文件完整性校验失败(详见上方 FAILED 行, 重新下载/拷贝发布包后再安装)" >&2; exit 1; }
  fi
  mkdir -p "${INSTALL_DIR}"
  if command -v rsync >/dev/null 2>&1; then
    # v1.9.90: --delete 重新引入, 但仅按纯代码子目录逐项加 --delete(尾斜杠语义),
    # 清理上一版本已删除的陈旧 .py/入口文件, 避免升级后残留死模块被误导入。
    # 不做整目录 --delete: 用户数据目录是独立的 /etc/ebpdns(rules_local.json/cache.json),
    # 不在 ${INSTALL_DIR} 内, 天然不受影响; bpf/ 与 etc/(配置模板)按覆盖拷贝, 不加 --delete。
    # v1.9.80: rsync 失败必须立即中止(磁盘满/权限不足), 不带 || true。
    for _d in bin ebpdns web systemd; do
      rsync -a --delete --ignore-missing-args \
        --exclude='*.pyc' --exclude='__pycache__' \
        "${SRC_DIR}/${_d}/" "${INSTALL_DIR}/${_d}/"
    done
    rsync -a --ignore-missing-args \
      --exclude='*.pyc' --exclude='__pycache__' --exclude='tools' \
      --exclude='deploy-test' --exclude='tests' \
      "${SRC_DIR}/bpf" "${SRC_DIR}/etc" \
      "${SRC_DIR}/README.md" "${SRC_DIR}/LICENSE" \
      "${INSTALL_DIR}/"
  else
    # rsync 不可用 → 退回 cp。纯代码子目录(bin/ebpdns/web/systemd)先删旧再拷,
    # 对齐 rsync --delete: 清除上版本已删除的陈旧 .py/入口文件。bpf/etc(模板)按覆盖拷贝。
    # 用户数据目录 /etc/ebpdns 独立于 ${INSTALL_DIR}, 不受影响。
    for _d in bin ebpdns web systemd; do
      rm -rf -- "${INSTALL_DIR:?}/${_d}"
    done
    mkdir -p "${INSTALL_DIR}"/bin "${INSTALL_DIR}"/ebpdns "${INSTALL_DIR}"/web \
             "${INSTALL_DIR}"/bpf "${INSTALL_DIR}"/etc "${INSTALL_DIR}"/systemd
    cp -r "${SRC_DIR}"/bin "${SRC_DIR}"/ebpdns "${SRC_DIR}"/web \
          "${SRC_DIR}"/bpf "${SRC_DIR}"/etc "${SRC_DIR}"/systemd "${INSTALL_DIR}/"
    cp -f "${SRC_DIR}"/README.md "${SRC_DIR}"/LICENSE "${INSTALL_DIR}/" 2>/dev/null || true
    # R31 P3-4: rsync 路径有 --exclude(*.pyc / __pycache__ / tests), cp 回退路径无 exclude 能力。
    # 拷贝后置清理构建缓存与测试目录, 避免陈旧 .pyc/__pycache__/tests 进入 /opt/ebpdns,
    # 与 rsync 路径排除项行为对齐。失败(目录不存在等)静默忽略, 不影响主安装流程。
    find "${INSTALL_DIR}" -type d -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
    find "${INSTALL_DIR}" -name '*.pyc' -delete 2>/dev/null || true
    find "${INSTALL_DIR}" -type d -name 'tests' -exec rm -rf {} + 2>/dev/null || true
  fi
fi

chmod +x "${INSTALL_DIR}/bin/ebpdns"
# P3-5(R3 修复): 原 `|| true` 静默吞掉 chown 失败。/opt/ebpdns 若在只读挂载/NFS root-squash
# 上, chown 失败会被掩盖, 后续 systemd 以 root 启动可能因属主不对触发权限问题而脚本仍报"完成"。
# 改为显式 WARN(非致命, root 仍可读既有 root 文件), 不再静默。
chown -R root:root "${INSTALL_DIR}" 2>/dev/null \
  || echo "[WARN] chown ${INSTALL_DIR} 失败(只读挂载/NFS root-squash?), 请人工确认文件属主为 root"
# M2 修复: 降权后服务以 ebpdns 用户运行, 需读 /opt/ebpdns/web/ 下的静态控制台资源。
# 源码包中 index.html 等可能是 600(root:root), chown -R root:root 后 ebpdns 无权读,
# 会导致控制台静态资源 404。补一条目录 755 / 静态文件 644, 保证 ebpdns(及其它用户)可读。
chmod 755 "${INSTALL_DIR}/web" 2>/dev/null || true
chmod 644 "${INSTALL_DIR}/web/"*.{html,js,css,svg,png,ico} 2>/dev/null || true

# ---------- 2/4 生成配置 ----------
echo "==> 2/4 生成配置 ${CONF_DIR}/config.json"
# P3-5(R3 修复): 原 `|| true` 静默吞掉 mkdir 失败。无法创建配置目录属致命错误, 立即中止并提示。
mkdir -p "${CONF_DIR}" \
  || { echo "[ERROR] 无法创建配置目录 ${CONF_DIR}(权限不足?)" >&2; exit 1; }
if [[ ! -f "${CONF_DIR}/config.json" ]]; then
  # R5 P3-2: 原两处 `cp -f ... || true` 静默吞掉配置模板拷贝失败(磁盘满/只读挂载)。
  # 模板存在但拷贝失败时不再静默——先定位模板, 拷贝失败打印 [WARN] 并回退到下方 python 兜底。
  _cfg_tmpl=""
  if [[ -f "${INSTALL_DIR}/etc/ebpdns.conf.json" ]]; then _cfg_tmpl="${INSTALL_DIR}/etc/ebpdns.conf.json"
  elif [[ -f "${SRC_DIR}/etc/ebpdns.conf.json" ]]; then _cfg_tmpl="${SRC_DIR}/etc/ebpdns.conf.json"; fi
  if [[ -n "${_cfg_tmpl}" ]]; then
    if ! cp -f "${_cfg_tmpl}" "${CONF_DIR}/config.json"; then
      echo "[WARN] 配置模板拷贝失败(${_cfg_tmpl}), 将写入最小默认配置" >&2
      rm -f "${CONF_DIR}/config.json" 2>/dev/null || true
    fi
  fi
  if [[ ! -f "${CONF_DIR}/config.json" ]]; then
    # v1.9.76: 配置模板缺失(精简包未带 etc/), 用 python3 -c 落一份最小可用默认配置,
    # 避免 config.json 不存在导致后续 chmod/systemd 启动失败。
    # v1.9.80: 兜底 api.host 改 127.0.0.1(与 DEFAULTS 一致), 避免控制台意外暴露到局域网;
    # R5 P2-2: listen 与 api.host 一致用 127.0.0.1:53(旧注释误写 0.0.0.0, 与代码及下方"下一步"提示不符),
    #          DNS 默认仅本机; 需局域网 DNS/控制台访问时用户显式把 api.host/listen 改为 0.0.0.0。
    # R10 P2: Python 布尔字面量必须大写 True/False, 小写 true 会触发 NameError: name 'true' is not defined。
    echo "    (未找到配置模板, 写入最小默认配置)"
    python3 -c 'import json; json.dump({"listen":{"udp":"127.0.0.1:53","tcp":"127.0.0.1:53"},"api":{"host":"127.0.0.1","port":8080},"upstreams":[{"id":"ali","name":"AliDNS","proto":"udp","addr":"223.5.5.5","port":53,"url":"","group":"domestic","latency":5000,"enabled":True}]}, open("'"${CONF_DIR}/config.json"'","w"), ensure_ascii=False, indent=2)' || { echo "错误: 写入兜底配置失败" >&2; exit 1; }
  fi
  echo "    (新配置已创建, 请按需编辑上游/端口/规则)"
else
  echo "    (已存在配置, 保留不动)"
fi
# P3-5(R3 修复): chown 失败显式 WARN 而非静默 `|| true`。
# v1.9.90: 服务现以 ebpdns 用户运行(systemd User=ebpdns), 配置目录需读写(含
# cache.json/rules_sub.json/rules_local.json 落盘), 故属主改 ebpdns:ebpdns,
# 目录权限 750(仅 ebpdns 与 root 可读/进入), config.json 保持 640。
chown -R ebpdns:ebpdns "${CONF_DIR}" 2>/dev/null \
  || echo "[WARN] chown ${CONF_DIR} 失败(只读挂载/NFS root-squash?), 请人工确认配置属主为 ebpdns"
chmod 750 "${CONF_DIR}" \
  || echo "[WARN] chmod 750 ${CONF_DIR} 失败(只读挂载?), 请人工确认配置目录权限为 750"
# v1.9.76: chmod 前判存在, 防模板缺失且 python 落盘失败时 chmod 报错中断安装
# v7 P2-4: 644(全局可读)→640(仅 root 可读/组可读), 配置含上游地址/订阅链接, 不应全局可读
# R31 P3-1: 与上方 chown 显式 WARN 风格对齐。文件不存在时条件已判静默跳过;
# 文件存在但 chmod 失败(只读挂载/NFS root-squash)时打 WARN, 不再静默吞掉。
[[ -f "${CONF_DIR}/config.json" ]] && (chmod 640 "${CONF_DIR}/config.json" \
  || echo "[WARN] chmod 640 config.json 失败(只读挂载?), 请人工确认配置权限为 640") || true

# ---------- 3/4 安装 systemd 服务 ----------
echo "==> 3/4 安装 systemd 服务"
if [[ -f "${SRC_DIR}/systemd/ebpdns.service" ]]; then
  # R5 P3-3: 原 `cp -f ... || true` 静默吞掉 unit 拷贝失败。unit 文件是 systemd 启动的必需件,
  # 拷贝失败属致命错误(否则 daemon-reload 沿用旧 unit, R3/R4 新增硬化项缺失且无任何提示), 显式报错并中止。
  cp -f "${SRC_DIR}/systemd/ebpdns.service" "${UNIT_FILE}" \
    || { echo "[ERROR] systemd unit 拷贝失败: ${UNIT_FILE}" >&2; exit 1; }
elif [[ -f "${INSTALL_DIR}/systemd/ebpdns.service" ]]; then
  cp -f "${INSTALL_DIR}/systemd/ebpdns.service" "${UNIT_FILE}" \
    || { echo "[ERROR] systemd unit 拷贝失败: ${UNIT_FILE}" >&2; exit 1; }
fi
# 两个来源都不存在时, 若本机也无旧 unit 文件则服务无法启动, 属致命错误中止。
[[ -f "${UNIT_FILE}" ]] || { echo "[ERROR] 未找到 systemd unit 模板且 ${UNIT_FILE} 不存在" >&2; exit 1; }
chmod 644 "${UNIT_FILE}"
# v1.9.81: 检测 systemd 是否真正在运行(不只是有 systemctl 命令), 容器/WSL/chroot 中
# systemctl 存在但 PID 1 不是 systemd, daemon-reload 会报错中断安装
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || echo "    (daemon-reload 失败, 跳过)"
  # R31 P3-2: 与下方 timer enable 的显式 WARN 风格对齐, 不再静默 `|| true` 吞掉 enable 失败。
  # enable 失败(unit 损坏/systemd 异常)时用户无感知直到手动 start 才发现, 改为显式 WARN 并给出手动命令。
  systemctl enable "${SERVICE_NAME}" >/dev/null 2>&1 \
    || echo "    [WARN] enable 服务失败, 请手动执行: systemctl enable ${SERVICE_NAME}"
  # v1.9.83: 安装每日低峰重启 timer(内存卫生兜底, 每天 04:30 ± 5min)
  # P3-6(第七轮审查): 原两处 `cp ... || true` 静默吞掉 timer/service 拷贝失败。
  # 拷贝失败时主 ebpdns.service 仍在(上面已强制拷贝), 仅丢失每日内存卫生自动重启,
  # 故为非致命——改为显式 WARN(与 chown 风格对齐), 不再静默。
  if [[ -f "${SRC_DIR}/systemd/ebpdns-restart.timer" ]]; then
    cp -f "${SRC_DIR}/systemd/ebpdns-restart.service" /etc/systemd/system/ \
      || echo "[WARN] 重启 service 拷贝失败, 将无每日内存卫生自动重启(主服务不受影响)"
    cp -f "${SRC_DIR}/systemd/ebpdns-restart.timer" /etc/systemd/system/ \
      || echo "[WARN] 重启 timer 拷贝失败, 将无每日内存卫生自动重启(主服务不受影响)"
    # P3-3(第八轮审查): 原 `|| true` 静默吞掉 enable/start 失败。与上方 timer/service 拷贝
    # 的 WARN 风格对齐——启用/启动失败只丢失每日内存卫生自动重启, 主服务不受影响, 故为非致命,
    # 改为显式 WARN, 不再静默。
    systemctl enable ebpdns-restart.timer >/dev/null 2>&1 \
      || echo "[WARN] timer 启用失败, 将无每日内存卫生自动重启(主服务不受影响)"
    systemctl start ebpdns-restart.timer >/dev/null 2>&1 \
      || echo "[WARN] timer 启动失败, 将无每日内存卫生自动重启(主服务不受影响)"
  fi
else
  echo "    (未检测到运行中的 systemd, 跳过 daemon-reload/enable; 请手动启动 ebpdns)"
fi

# ---------- 4/4 完成 ----------
echo "==> 4/4 完成"
echo ""
echo "  已安装:"
echo "    代码     ${INSTALL_DIR}"
echo "    配置     ${CONF_DIR}/config.json"
echo "    服务     ${SERVICE_NAME} (systemd)"
echo ""
echo "  下一步:"
echo "    1. 编辑配置:  sudo nano ${CONF_DIR}/config.json"
echo "       - 默认监听 127.0.0.1:53 (DNS) + 127.0.0.1:8080 (控制台, 仅本机)"
echo "       - 如 53 端口被占用(systemd-resolved), 先禁用或改用其他端口"
echo "       - 需局域网访问时把 api.host 改为 0.0.0.0 并注意安全"
echo "    2. 启动:      sudo systemctl start ${SERVICE_NAME}"
echo "    3. 状态:      sudo systemctl status ${SERVICE_NAME}"
echo "    4. 控制台:    本机浏览器打开 http://127.0.0.1:8080/  (局域网访问需改 api.host)"
echo "    5. 测试解析:  dig @127.0.0.1 www.baidu.com"
echo ""
echo "  数据面: 用户态 LRU 已启用; eBPF XDP 内核旁路为预留接口(参考实现见 ${INSTALL_DIR}/bpf/README.md)"
echo ""
echo "  可选 DoQ/DoH3 上游(需要 aioquic):"
if python3 -c 'import aioquic' 2>/dev/null; then
  echo "    - aioquic 已安装, DoQ/DoH3 上游可直接使用"
else
  echo "    - 未检测到 aioquic, 使用 DoQ/DoH3 上游需先:  sudo python3 -m pip install aioquic"
  echo "      (UDP/TCP/DoH/DoT 上游不受影响)"
fi
