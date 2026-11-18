
#!/usr/bin/env python3
"""ebpdns 缓存策略基准：UDP 查询发生器 + 命中率统计。

用法: bench.py --port 15353 --duration 60 --rate 800 --pool 10000 --alpha 1.0
"""
import argparse, random, socket, struct, time, sys

def build_query(name: str, qid: int) -> bytes:
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    q = b""
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack("!HH", 1, 1)  # A, IN
    return header + q

def zipf_weights(n, alpha):
    w = [1.0 / ((i + 1) ** alpha) for i in range(n)]
    tot = sum(w)
    cum, acc = [], 0.0
    for x in w:
        acc += x / tot
        cum.append(acc)
    return cum

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=15353)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--duration", type=float, default=60)
    ap.add_argument("--rate", type=float, default=800)
    ap.add_argument("--pool", type=int, default=10000)
    ap.add_argument("--alpha", type=float, default=1.0)
    ap.add_argument("--timeout", type=float, default=1.0)
    a = ap.parse_args()

    random.seed(20261102)
    names = ["n%d.bench.test" % i for i in range(a.pool)]
    cum = zipf_weights(a.pool, a.alpha)

    def pick():
        r = random.random()
        lo, hi = 0, a.pool - 1
        while lo < hi:
            mid = (lo + hi) // 2
            if cum[mid] < r:
                lo = mid + 1
            else:
                hi = mid
        return names[lo]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(a.timeout)
    sent = recv = timeout = 0
    lat = []
    t0 = time.time()
    interval = 1.0 / a.rate
    qid = 0
    while time.time() - t0 < a.duration:
        name = pick()
        qid = (qid + 1) & 0xFFFF
        pkt = build_query(name, qid)
        ts = time.time()
        try:
            sock.sendto(pkt, (a.host, a.port))
            sent += 1
            sock.recvfrom(4096)
            recv += 1
            lat.append((time.time() - ts) * 1000.0)
        except socket.timeout:
            timeout += 1
        # 简单节流
        nxt = t0 + sent * interval
        d = nxt - time.time()
        if d > 0:
            time.sleep(d)
    el = time.time() - t0
    lat.sort()
    p50 = lat[len(lat)//2] if lat else 0
    p95 = lat[int(len(lat)*0.95)] if lat else 0
    print("sent=%d recv=%d timeout=%d elapsed=%.1fs qps=%.0f p50=%.1fms p95=%.1fms"
          % (sent, recv, timeout, el, sent / el, p50, p95))

if __name__ == "__main__":
    main()
