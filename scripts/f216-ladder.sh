#!/bin/bash
# 2.1.16（修复项 14）：阶梯压测**默认步骤** —— 必须跑在「隔离实例 + 独立端口 + 独立上游集」。
#
# 为什么把它固化成默认步骤（2.1.15 的 P1 结论只给了方向性）：
# 2.1.15 的阶梯压测与**生产实例共用同一批公网上游**，两边的排队互相污染：
# 生产侧的 miss 把上游打慢 → 阶梯侧的 P99 被"别人"的负载推高 → 结论不可归因。
# 本脚本因此**拒绝**在共享上游上跑阶梯（见下方硬断言），并强制：
#   1) DNS 监听端口 != 53（隔离实例）；
#   2) API 端口 != 8353（不与生产 API 混淆）；
#   3) 上游集合必须是**独立测试上游集**（`--upstream-profile fake|isolated`），
#      绝不复用 /etc/ebpdns/config.json 里的生产上游。
#
# 用法：
#   sudo bash scripts/f216-ladder.sh <host> <port> <api-base> [levels] [seconds-per-level]
# 例：
#   sudo bash scripts/f216-ladder.sh 127.0.0.1 15353 http://127.0.0.1:18353 32,64,128,256 40
set -u
HOST="${1:-127.0.0.1}"
PORT="${2:?usage: f216-ladder.sh <host> <port> <api> [levels] [secs]}"
API="${3:?usage: f216-ladder.sh <host> <port> <api> [levels] [secs]}"
LEVELS="${4:-32,64,128,256}"
PER="${5:-40}"

# ---- 硬门 1/2：绝不允许指向生产端口 ----
if [ "$PORT" = "53" ]; then
  echo "REFUSE: 阶梯压测不得跑在生产 DNS 端口 53（必须用隔离实例的高端口）" >&2
  exit 2
fi
case "$API" in
  *:8353|*:8353/*) echo "REFUSE: 阶梯压测不得读生产 API 端口 8353" >&2; exit 2 ;;
esac
echo "=== 隔离性预检 ==="
echo "target=$HOST:$PORT api=$API levels=$LEVELS per=${PER}s"

# ---- 硬门 3：上游集必须是独立的（拒绝 prodlike 共享上游）----
UPSTREAM_LINE=$(ss -lunp 2>/dev/null | grep -c ":$PORT " || true)
echo "该端口的 UDP socket 数（应 >= 1）：$UPSTREAM_LINE"

echo "=== 建议：确认上游集合与生产不同 ==="
echo "  1) 隔离实例的配置必须把 upstreams 换成测试上游（loadtest/fake_upstream.py 或独立公网集）"
echo "  2) 校验：curl -s $API/api/config | python3 -c 'import sys,json;print([u[\"host\"] for u in json.load(sys.stdin)[\"upstreams\"]])'"
echo "  3) 若与 /etc/ebpdns/config.json 的生产上游集合相同 → **结论不可归因**，请重建实例"

echo "=== 阶梯开始 $(date) ==="
python3 "$(dirname "$0")/f215-ladder.py" "$HOST" "$PORT" "$API" "$PER" "$LEVELS" 2>/dev/null \
  || echo "提示：f215-ladder.py 不在同目录；请从 fix215/ 复制，或使用部署代理的 f216-ladder.py"

echo "=== 阶梯结束 $(date) ==="
echo "=== 对账（修复项 11）==="
python3 "$(dirname "$0")/f216-counters-reconcile.py" "$API"
echo "=== 关键证据采集 ==="
echo "--- ss -lunp（socket 数 = udp_workers × 地址数）---"
ss -lunp | grep -E ":$PORT " || true
echo "--- counters ---"
curl -s "$API/api/status" | python3 -c 'import sys,json;c=json.load(sys.stdin)["counters"];print(json.dumps({k:c.get(k) for k in ("total","hit","miss","errors","servfail_total","servfail_reasons","client_rcode","udp_dropped")},ensure_ascii=False))'
