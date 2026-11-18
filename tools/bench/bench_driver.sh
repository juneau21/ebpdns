#!/bin/bash
# 两种现存缓存策略命中率对比（s3fifo / lru；假上游隔离网络：只测缓存策略本身）
set -u
BIN=/root/build/ebpdns-2.1.49/target/release/ebpdns
SIZE=${SIZE:-1024}
POOL=${POOL:-5000}
RATE=${RATE:-800}
WARM=${WARM:-30}
MEAS=${MEAS:-60}
API=18360
DNS=15353
OUT=${OUT:-/root/bench-result.txt}
: > $OUT

# 假上游
pkill -f fake_upstream.py 2>/dev/null
python3 /root/fake_upstream.py 15453 > /tmp/fake-up.log 2>&1 &
FAKE=$!
sleep 1

mkcfg() {
  local pol=$1 dest=$2
  python3 - "$pol" "$dest" "$SIZE" <<'PY'
import json, sys
pol, dest, size = sys.argv[1], sys.argv[2], int(sys.argv[3])
c = json.load(open('/etc/ebpdns/config.json'))
c['api'] = {'host': '127.0.0.1', 'port': 18360, 'token': ''}
c['listen'] = {'udp': '127.0.0.1:15353', 'tcp': '127.0.0.1:15353', 'udp6': '', 'tcp6': ''}
c['cache_size'] = size
c['cache_policy'] = pol
c['cache_persist'] = False
c['cache_file'] = '/tmp/bench-cache.json'
c['state_dir'] = '/tmp/bench-state'
c['state_persist'] = False
c['log_level'] = 'warn'
c['prefetch'] = False
c['warmup'] = {'enabled': False, 'queries': 0, 'timeout_ms': 500}
c['speed_test'] = False
c['ip_speed_check'] = False
c['health_check_interval'] = 0
c['fallback'] = False
c['timeout_ms'] = 500
c['upstreams'] = [{'id': 'fake', 'name': 'Fake', 'proto': 'udp', 'host': '127.0.0.1',
                   'addr': '127.0.0.1', 'port': 15453, 'url': '', 'group': 'domestic',
                   'enabled': True}]
c['rule_subscriptions'] = []
c['rules'] = []
json.dump(c, open(dest, 'w'), indent=1)
PY
}

counters() {
  curl -s --max-time 3 "http://127.0.0.1:$API/api/status" | python3 -c "
import json,sys
d=json.load(sys.stdin); c=d['counters']
print(c['hit'], c['miss'], d['cache']['used'])
"
}

for pol in s3fifo lru; do
  mkcfg "$pol" /tmp/bench-$pol.json
  $BIN --config /tmp/bench-$pol.json --foreground > /tmp/bench-$pol.log 2>&1 &
  pid=$!
  sleep 2
  if ! kill -0 $pid 2>/dev/null; then
    echo "$pol: 启动失败" | tee -a $OUT
    tail -5 /tmp/bench-$pol.log | tee -a $OUT
    continue
  fi
  python3 /root/bench.py --port $DNS --duration $WARM --rate $RATE --pool $POOL > /tmp/bench-warm-$pol.txt 2>&1
  read h0 m0 u0 <<< "$(counters)"
  python3 /root/bench.py --port $DNS --duration $MEAS --rate $RATE --pool $POOL > /tmp/bench-run-$pol.txt 2>&1
  read h1 m1 u1 <<< "$(counters)"
  kill $pid 2>/dev/null; wait $pid 2>/dev/null
  python3 - "$pol" "$h0" "$m0" "$h1" "$m1" "$u1" "$POOL" "$SIZE" <<'PY' | tee -a $OUT
import sys
pol = sys.argv[1]
h0, m0, h1, m1, u1, pool, size = map(int, sys.argv[2:9])
h = h1 - h0; m = m1 - m0
tot = h + m
rate = (100.0 * h / tot) if tot else 0.0
print("%-12s hit=%-7d miss=%-7d hit_rate=%6.2f%%  used=%-6d pool=%d size=%d" % (pol, h, m, rate, u1, pool, size))
PY
  cp /tmp/bench-run-$pol.txt /root/bench-load-$pol.txt
  sleep 1
done
kill $FAKE 2>/dev/null
echo "---- 负载端 ----" | tee -a $OUT
cat /tmp/bench-run-*.txt 2>/dev/null | tee -a $OUT
