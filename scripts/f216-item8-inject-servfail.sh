#!/bin/bash
# 2.1.16（修复项 8）：**注入式可控 SERVFAIL 上游**对照实验。
#
# 目的：把"客户端实际看到的 rcode==2 应答数"与"服务端 servfail_total"做**一一对应**
# 断言，并给出**服务端侧自证**口径（`client_rcode`）。
#
# 隔离性：UDP/TCP 监听 127.0.0.1:${DNS_PORT:-15353}，API 127.0.0.1:${API_PORT:-18353}，
# 假上游 127.0.0.1:${UP_PORT:-15300}。**绝不**触碰 53 / 8353。
#
# 用法：sudo bash scripts/f216-item8-inject-servfail.sh [/usr/local/bin/ebpdns]
set -eu
BIN="${1:-/usr/local/bin/ebpdns}"
DNS_PORT="${DNS_PORT:-15353}"
API_PORT="${API_PORT:-18353}"
UP_PORT="${UP_PORT:-15300}"
D=/tmp/f216-item8
mkdir -p "$D"

cat > "$D/fake.py" <<'PY'
import socket, struct, sys
PORT = int(sys.argv[1])
def dn(data, off):
    labels = []
    while True:
        l = data[off]
        if l == 0:
            return ".".join(labels), off + 1
        labels.append(data[off+1:off+1+l].decode('latin1')); off += 1 + l
def build(req):
    if len(req) < 12:
        return None
    try:
        _, off = dn(req, 12)
    except Exception:
        return None
    q = req[12:off+4]
    # 恒回 SERVFAIL(2)：rcode 位于 header flags 低 4 位。
    return struct.pack(">HHHHHH", int.from_bytes(req[:2], "big"), 0x8182, 1, 0, 0, 0) + q
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", PORT))
print("fake SERVFAIL upstream 127.0.0.1:%d" % PORT, flush=True)
while True:
    try:
        data, addr = s.recvfrom(4096)
        r = build(data)
        if r:
            s.sendto(r, addr)
    except Exception:
        pass
PY

cat > "$D/probe.py" <<'PY'
import json, random, socket, struct, sys, threading, time, urllib.request
API, HOST, PORT, N, MODE = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
def build(name, tid):
    b = struct.pack(">HHHHHH", tid & 0xFFFF, 0x0100, 1, 0, 0, 0)
    for l in name.split("."):
        b += bytes([len(l)]) + l.encode()
    return b + b"\x00" + struct.pack(">HH", 1, 1)
def counters():
    with urllib.request.urlopen(API + "/api/status", timeout=20) as f:
        return json.loads(f.read().decode())["counters"]
def metrics():
    with urllib.request.urlopen(API + "/metrics", timeout=20) as f:
        return f.read().decode()
def udp(name, tid):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5.0)
    try:
        s.sendto(build(name, tid), (HOST, PORT))
        d, _ = s.recvfrom(4096)
        return d[3] & 0xF
    except socket.timeout:
        return -1
    finally:
        s.close()
def tcp(name, tid):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(6.0)
    try:
        s.connect((HOST, PORT)); q = build(name, tid)
        s.sendall(struct.pack(">H", len(q)) + q)
        h = s.recv(2)
        if len(h) < 2: return -1
        ln = struct.unpack(">H", h)[0]; buf = b""
        while len(buf) < ln:
            c = s.recv(ln - len(buf))
            if not c: break
            buf += c
        return (buf[3] & 0xF) if len(buf) >= 4 else -1
    except socket.timeout:
        return -1
    finally:
        s.close()
c0 = counters()
rc = {}
if MODE == "tcp":
    for i in range(N):
        k = tcp("t%d.servfail.test" % i, i); rc[k] = rc.get(k, 0) + 1
elif MODE == "conc":
    lk = threading.Lock()
    def w(ti):
        for j in range(N):
            k = udp("c%d-%d.servfail.test" % (ti, j), ti * 1000 + j)
            with lk: rc[k] = rc.get(k, 0) + 1
    ts = [threading.Thread(target=w, args=(i,), daemon=True) for i in range(16)]
    [t.start() for t in ts]; [t.join() for t in ts]
elif MODE == "repeat":
    # 同名重复：第一条 miss（上游 SERVFAIL），其后仍应逐条发出 rcode=2 并被计数。
    for i in range(N):
        k = udp("same.servfail.test", i); rc[k] = rc.get(k, 0) + 1
else:
    for i in range(N):
        k = udp("u%d.servfail.test" % i, i); rc[k] = rc.get(k, 0) + 1
time.sleep(1.0)
c1 = counters(); mt = metrics()
cli2 = rc.get(2, 0)
dsf = c1["servfail_total"] - c0["servfail_total"]
dcr2 = int(c1["client_rcode"]["2"]) - int(c0["client_rcode"]["2"])
agg = [l for l in mt.splitlines() if l.startswith("ebpdns_servfail_total ")]
per = [l for l in mt.splitlines() if l.startswith("ebpdns_servfail_reasons_total{")]
out = {
    "mode": MODE, "sent": N, "client_rcode": {str(k): v for k, v in sorted(rc.items())},
    "client_rcode2": cli2, "client_timeouts_or_noanswer": rc.get(-1, 0),
    "delta_servfail_total": dsf, "delta_client_rcode2": dcr2,
    "one_to_one": cli2 == dsf == dcr2,
    "metrics_aggregate": agg, "metrics_reasons": per,
    "invariant_client_rcode2_eq_servfail_total":
        c1["client_rcode"]["2"] == c1["servfail_total"],
}
print(json.dumps(out, ensure_ascii=False, indent=1))
PY

python3 "$D/fake.py" "$UP_PORT" > "$D/fake.log" 2>&1 &
FAKE=$!
sleep 1
cat > "$D/cfg.py" <<'PY'
import json, sys
c = json.load(open('/etc/ebpdns/config.json'))
c["listen"] = {"udp": "127.0.0.1:%s" % sys.argv[2], "tcp": "127.0.0.1:%s" % sys.argv[2],
               "udp6": False, "tcp6": False}
c["api"] = {"host": "127.0.0.1", "port": int(sys.argv[3]), "token": ""}
c["dns_port"] = int(sys.argv[2])
c["web_root"] = ""
c["cache_persist"] = False
c["prefetch"] = False
c["speed_test"] = False
c["ip_speed_check"] = False
c["rfc8020_infer"] = False
c["upstreams"] = [{"id": "fake-sf", "name": "fake-sf", "proto": "udp",
                   "host": "127.0.0.1", "port": int(sys.argv[4]), "enabled": True,
                   "latency": 10, "weight": 1}]
json.dump(c, open(sys.argv[1], "w"), ensure_ascii=False, indent=2)
PY
python3 "$D/cfg.py" "$D/cfg.json" "$DNS_PORT" "$API_PORT" "$UP_PORT"
"$BIN" --config "$D/cfg.json" --foreground > "$D/srv.log" 2>&1 &
SRV=$!
for i in $(seq 1 60); do curl -s -m 2 "http://127.0.0.1:$API_PORT/api/status" >/dev/null 2>&1 && break; sleep 0.5; done

FAIL=0
for spec in "udp 25" "tcp 20" "conc 16" "repeat 12"; do
  set -- $spec
  echo "=== phase $1 n=$2 ==="
  python3 "$D/probe.py" "http://127.0.0.1:$API_PORT" 127.0.0.1 "$DNS_PORT" "$2" "$1" | tee "$D/$1.json"
  grep -q '"one_to_one": true' "$D/$1.json" || { echo "PHASE $1 FAILED"; FAIL=1; }
done

echo "=== 服务端日志（不得有 panic）==="
grep -icE 'panic' "$D/srv.log" || true
kill "$SRV" 2>/dev/null; sleep 1; kill -9 "$SRV" 2>/dev/null
kill "$FAKE" 2>/dev/null; kill -9 "$FAKE" 2>/dev/null
if [ "$FAIL" = "0" ]; then echo "ITEM8_VERDICT one_to_one_all_phases=True"; else echo "ITEM8_VERDICT FAILED"; fi
exit "$FAIL"
