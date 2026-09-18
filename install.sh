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
    # 优先 apt 系统包(与系统 python3 版本一致); 先 apt-get update 防索引过期
    apt-get update -qq 2>/dev/null || true
    if command -v apt-get >/dev/null 2>&1 && apt-get install -y python3-aioquic >/dev/null 2>&1; then
      echo "    aioquic 已通过 apt 安装 (python3-aioquic)"
      _aq_ok=1
    elif command -v python3 >/dev/null 2>&1 && python3 -m pip --version >/dev/null 2>&1; then
      # 回退 python3 -m pip(保证装到与 python3 同版本的解释器);
      # PEP 668 系统 Python 需 --break-system-packages, 否则 pip 拒绝安装
      echo "    (apt 无 python3-aioquic, 改用 python3 -m pip 安装)"
      python3 -m pip install --quiet --break-system-packages aioquic 2>/dev/null && _aq_ok=1 \
        || echo "    (python3 -m pip 安装失败)" >&2
    fi
    if [[ "$_aq_ok" == "0" ]] && command -v pip3 >/dev/null 2>&1; then
      echo "    (最后尝试 pip3 安装)"
      pip3 install --quiet --break-system-packages aioquic 2>/dev/null && _aq_ok=1
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
else
  echo "==> 1/4 复制代码到 ${INSTALL_DIR}"
  mkdir -p "${INSTALL_DIR}"
  if command -v rsync >/dev/null 2>&1; then
    # v1.9.76: 去掉 --delete。旧 --delete 会把 INSTALL_DIR 里用户自有的本地文件
    # (rules_local.json / 缓存持久化 / 备份)随升级一并删除, 危险。改为只覆盖拷贝。
    # v1.9.80: 去掉末尾 || true, rsync 失败必须立即中止(磁盘满/权限不足), 否则
    # 后续 systemd 启动报 ModuleNotFoundError 且日志看不到根因。
    rsync -a --ignore-missing-args \
      --exclude='*.pyc' --exclude='__pycache__' --exclude='tools' \
      --exclude='deploy-test' --exclude='tests' \
      "${SRC_DIR}/bin" "${SRC_DIR}/ebpdns" "${SRC_DIR}/web" \
      "${SRC_DIR}/bpf" "${SRC_DIR}/etc" "${SRC_DIR}/systemd" \
      "${SRC_DIR}/README.md" "${SRC_DIR}/LICENSE" \
      "${INSTALL_DIR}/"
  else
    # rsync 不可用 → 退回 cp(不 rm -rf, 保留用户本地文件)
    mkdir -p "${INSTALL_DIR}"/bin "${INSTALL_DIR}"/ebpdns "${INSTALL_DIR}"/web \
             "${INSTALL_DIR}"/bpf "${INSTALL_DIR}"/etc "${INSTALL_DIR}"/systemd
    cp -r "${SRC_DIR}"/bin "${SRC_DIR}"/ebpdns "${SRC_DIR}"/web \
          "${SRC_DIR}"/bpf "${SRC_DIR}"/etc "${SRC_DIR}"/systemd "${INSTALL_DIR}/"
    cp -f "${SRC_DIR}"/README.md "${SRC_DIR}"/LICENSE "${INSTALL_DIR}/" 2>/dev/null || true
  fi
fi

chmod +x "${INSTALL_DIR}/bin/ebpdns"
chown -R root:root "${INSTALL_DIR}" || true

# ---------- 2/4 生成配置 ----------
echo "==> 2/4 生成配置 ${CONF_DIR}/config.json"
mkdir -p "${CONF_DIR}" || true
if [[ ! -f "${CONF_DIR}/config.json" ]]; then
  if [[ -f "${INSTALL_DIR}/etc/ebpdns.conf.json" ]]; then
    cp -f "${INSTALL_DIR}/etc/ebpdns.conf.json" "${CONF_DIR}/config.json" || true
  elif [[ -f "${SRC_DIR}/etc/ebpdns.conf.json" ]]; then
    cp -f "${SRC_DIR}/etc/ebpdns.conf.json" "${CONF_DIR}/config.json" || true
  else
    # v1.9.76: 配置模板缺失(精简包未带 etc/), 用 python3 -c 落一份最小可用默认配置,
    # 避免 config.json 不存在导致后续 chmod/systemd 启动失败。
    # v1.9.80: 兜底 api.host 改 127.0.0.1(与 DEFAULTS 一致), 避免控制台意外暴露到局域网;
    #          listen 仍 0.0.0.0:53(DNS 服务器常规需求), 需要局域网访问控制台时用户显式改。
    echo "    (未找到配置模板, 写入最小默认配置)"
    python3 -c 'import json; json.dump({"listen":{"udp":"127.0.0.1:53","tcp":"127.0.0.1:53"},"api":{"host":"127.0.0.1","port":8080},"upstreams":[{"id":"ali","name":"AliDNS","proto":"udp","addr":"223.5.5.5","port":53,"url":"","group":"domestic","latency":8,"enabled":true}]}, open("'"${CONF_DIR}/config.json"'","w"), ensure_ascii=False, indent=2)' || { echo "错误: 写入兜底配置失败" >&2; exit 1; }
  fi
  echo "    (新配置已创建, 请按需编辑上游/端口/规则)"
else
  echo "    (已存在配置, 保留不动)"
fi
chown -R root:root "${CONF_DIR}" || true
# v1.9.76: chmod 前判存在, 防模板缺失且 python 落盘失败时 chmod 报错中断安装
[[ -f "${CONF_DIR}/config.json" ]] && chmod 644 "${CONF_DIR}/config.json" || true

# ---------- 3/4 安装 systemd 服务 ----------
echo "==> 3/4 安装 systemd 服务"
if [[ -f "${SRC_DIR}/systemd/ebpdns.service" ]]; then
  cp -f "${SRC_DIR}/systemd/ebpdns.service" "${UNIT_FILE}" || true
elif [[ -f "${INSTALL_DIR}/systemd/ebpdns.service" ]]; then
  cp -f "${INSTALL_DIR}/systemd/ebpdns.service" "${UNIT_FILE}" || true
fi
[[ -f "${UNIT_FILE}" ]] && chmod 644 "${UNIT_FILE}" || true
# v1.9.81: 检测 systemd 是否真正在运行(不只是有 systemctl 命令), 容器/WSL/chroot 中
# systemctl 存在但 PID 1 不是 systemd, daemon-reload 会报错中断安装
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || echo "    (daemon-reload 失败, 跳过)"
  systemctl enable "${SERVICE_NAME}" >/dev/null 2>&1 || true
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
