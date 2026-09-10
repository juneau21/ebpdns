#!/usr/bin/env bash
# ============================================================
# 挂载 ebpdns XDP 数据面到指定网卡 (示例)
#   用法: sudo ./load.sh eth0
#   前提: 已编译 ebpdns_xdp.o (make), 内核支持原生 XDP, root
# ============================================================
set -euo pipefail
IFACE="${1:-eth0}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "需要 root" >&2; exit 1
fi
if [[ ! -f ebpdns_xdp.o ]]; then
  echo "未找到 ebpdns_xdp.o, 请先执行 make" >&2; exit 1
fi

echo "==> 挂载 ebpdns_xdp 到 $IFACE"
ip link set dev "$IFACE" xdp obj ebpdns_xdp.o sec xdp 2>/dev/null \
  || bpftool prog load ebpdns_xdp.o /sys/fs/bpf/ebpdns_xdp type xdp \
     && ip link set dev "$IFACE" xdp pinned /sys/fs/bpf/ebpdns_xdp

echo "==> 已挂载, 查看:"
bpftool prog show | grep -i ebpdns || true
bpftool map show | grep -i dns_cache || true

echo ""
echo "卸载: ip link set dev $IFACE xdp off"
echo "提示: 用户态 daemon 需要把未命中解析结果同步写入 dns_cache map (bpf()/libbpf),"
echo "      本项目默认以纯用户态 LRU 运行; 启用 XDP 直答后建议关闭控制台"内核直答"开关的"
echo "      用户态回填冲突(详见 README 进阶章节)。"
