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
    apt-get update -qq 2>/dev/null || true
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
    # 优先 apt 系统包(与系统 python3 版本一致)
    if command -v apt-get >/dev/null 2>&1 && apt-get install -y python3-aioquic >/dev/null 2>&1; then
      echo "    aioquic 已通过 apt 安装 (python3-aioquic)"
      _aq_ok=1
    elif command -v python3 >/dev/null 2>&1 && python3 -m pip --version >/dev/null 2>&1; then
      # 回退 python3 -m pip(保证装到与 python3 同版本的解释器)
      echo "    (apt 无 python3-aioquic, 改用 python3 -m pip 安装)"
      python3 -m pip install --quiet aioquic 2>/dev/null && _aq_ok=1 \
        || echo "    (python3 -m pip 安装失败)" >&2
    fi
    if [[ "$_aq_ok" == "0" ]] && command -v pip3 >/dev/null 2>&1; then
      echo "    (最后尝试 pip3 安装)"
      pip3 install --quiet aioquic 2>/dev/null && _aq_ok=1
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


# ---------- 1/4 代码就位 ----------
IN_PLACE=0
if [[ "$SRC_DIR" == "$INSTALL_DIR" ]]; then
  IN_PLACE=1
  echo "==> 检测到源码已位于 ${INSTALL_DIR} (就地安装), 跳过代码拷贝"
  # 完整性校验: 就地安装时关键文件必须齐全, 否则后续 systemd 启动必然失败
  # (历史问题: 早期版本就地安装缺文件时 cp 报错, 用户 VM 上 systemd 启动失败)
  for _req in bin/ebpdns ebpdns/cli.py web/index.html systemd/ebpdns.service; do
    if [[ ! -e "${INSTALL_DIR}/${_req}" ]]; then
      echo "错误: 就地安装缺少关键文件 ${INSTALL_DIR}/${_req}, 请确认完整解压部署包后再运行" >&2
      exit 1
    fi
  done
else
  echo "==> 1/4 复制代码到 ${INSTALL_DIR}"
  mkdir -p "${INSTALL_DIR}"
  if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete \
      --exclude='*.pyc' --exclude='__pycache__' --exclude='tools' \
      --exclude='deploy-test' --exclude='tests' \
      "${SRC_DIR}/bin" "${SRC_DIR}/ebpdns" "${SRC_DIR}/web" \
      "${SRC_DIR}/bpf" "${SRC_DIR}/etc" "${SRC_DIR}/systemd" \
      "${SRC_DIR}/README.md" "${SRC_DIR}/LICENSE" \
      "${INSTALL_DIR}/"
  else
    # rsync 不可用 → 退回 cp
    rm -rf "${INSTALL_DIR}"/bin "${INSTALL_DIR}"/ebpdns "${INSTALL_DIR}"/web \
           "${INSTALL_DIR}"/bpf "${INSTALL_DIR}"/etc "${INSTALL_DIR}"/systemd
    cp -r "${SRC_DIR}"/bin "${SRC_DIR}"/ebpdns "${SRC_DIR}"/web \
          "${SRC_DIR}"/bpf "${SRC_DIR}"/etc "${SRC_DIR}"/systemd "${INSTALL_DIR}/"
    cp -f "${SRC_DIR}"/README.md "${SRC_DIR}"/LICENSE "${INSTALL_DIR}/" 2>/dev/null || true
  fi
fi

chmod +x "${INSTALL_DIR}/bin/ebpdns"
chown -R root:root "${INSTALL_DIR}"

# ---------- 2/4 生成配置 ----------
echo "==> 2/4 生成配置 ${CONF_DIR}/config.json"
mkdir -p "${CONF_DIR}"
if [[ ! -f "${CONF_DIR}/config.json" ]]; then
  if [[ -f "${INSTALL_DIR}/etc/ebpdns.conf.json" ]]; then
    cp -f "${INSTALL_DIR}/etc/ebpdns.conf.json" "${CONF_DIR}/config.json"
  elif [[ -f "${SRC_DIR}/etc/ebpdns.conf.json" ]]; then
    cp -f "${SRC_DIR}/etc/ebpdns.conf.json" "${CONF_DIR}/config.json"
  fi
  echo "    (新配置已创建, 请按需编辑上游/端口/规则)"
else
  echo "    (已存在配置, 保留不动)"
fi
chown -R root:root "${CONF_DIR}"
chmod 644 "${CONF_DIR}/config.json"

# ---------- 3/4 安装 systemd 服务 ----------
echo "==> 3/4 安装 systemd 服务"
if [[ -f "${SRC_DIR}/systemd/ebpdns.service" ]]; then
  cp -f "${SRC_DIR}/systemd/ebpdns.service" "${UNIT_FILE}"
else
  cp -f "${INSTALL_DIR}/systemd/ebpdns.service" "${UNIT_FILE}"
fi
chmod 644 "${UNIT_FILE}"
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}" >/dev/null 2>&1 || true

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
echo "       - 默认监听 0.0.0.0:53 (DNS) + 0.0.0.0:8080 (控制台)"
echo "       - 如 53 端口被占用(systemd-resolved), 先禁用或改用其他端口"
echo "    2. 启动:      sudo systemctl start ${SERVICE_NAME}"
echo "    3. 状态:      sudo systemctl status ${SERVICE_NAME}"
echo "    4. 控制台:    浏览器打开 http://<本机IP>:8080/"
echo "    5. 测试解析:  dig @<本机IP> www.baidu.com"
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
