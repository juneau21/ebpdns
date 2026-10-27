#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ebpdns release 混合压测：精确 180s。
启动 fake upstream + release ebpdns，多并发 UDP 施压 + 周期性 API 调用，
每 5s 采样 RSS/fd/线程，结束输出指标表与泄漏判定。
"""
import json, os, socket, struct, subprocess, sys, threading, time, random, urllib.request, statistics

DNS_IP, DNS_PORT = "127.0.0.1", 5353
API = "http://127.0.0.1:8353"
DUR = 180.0
WORKERS = 24
WARM_NAMES = [f"warm{i}.example.internal" for i in range(100)]

CFG = {
    "api": {"host": "127.0.0.1", "port": 8353, "token": ""},
    "listen": {"udp": "127.0.0.1", "tcp": "127.0.0.1"},
    "upstreams": [{"id": "fake", "name": "fake", "proto": "udp",
                   "host": "127.0.0.1", "port": 15353, "enabled": True}],
    "rules": [], "rule_subscriptions": [],
    "cache_size": 131072, "cache_persist": False, "persist_ttl": 86400.0,
    "ttl": 300, "timeout_ms": 1500, "prefetch": False,
}

def qwire(name, qtype=1):
    hdr = struct.pack(">HHHHHH", random.randint(0,65535), 0x0100, 1,0,0,0)
    qn = b"".join(bytes([len(l)])+l.encode() for l in name.split(".")) + b"\x00"
    return hdr + qn + struct.pack(">HH", qtype, 1)

# ---- metrics ----
lat_hit, lat_miss, lat_aaaa, lat_api = [], [], [], []
err = {"dns":0, "api":0}
stop = threading.Event()

def dns_worker(wid):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    while not stop.is_set():
        r = random.random()
        t0 = time.perf_counter()
        try:
            if r < 0.45:                       # cache hit
                name = random.choice(WARM_NAMES); qt = 1; bucket = lat_hit
            elif r < 0.85:                     # miss (unique)
                name = f"u{random.randint(0,10**9)}-{wid}.m.internal"; qt = 1; bucket = lat_miss
            else:                              # AAAA
                name = f"a{random.randint(0,10**6)}.internal"; qt = 28; bucket = lat_aaaa
            sock.sendto(qwire(name, qt), (DNS_IP, DNS_PORT))
            sock.recvfrom(4096)
            bucket.append((time.perf_counter()-t0)*1000.0)
        except Exception:
            err["dns"] += 1

def api_loop():
    n = 0
    while not stop.is_set():
        try:
            t0=time.perf_counter()
            for ep in ["/api/status","/api/snapshot","/api/config"]:
                urllib.request.urlopen(API+ep, timeout=2).read()
            # PUT toggle a harmless key (prefetch off/on)
                body=json.dumps({"prefetch": (n%2==0)}).encode()
            req=urllib.request.Request(API+"/api/config", data=body,
                headers={"Content-Type":"application/json"}, method="PUT")
            urllib.request.urlopen(req, timeout=2).read()
            # rule subscribe + reset
            try:
                req=urllib.request.Request(API+"/api/rules/subscribe",
                    data=json.dumps({"url":"http://127.0.0.1/x.list"}).encode(),
                    headers={"Content-Type":"application/json"}, method="POST")
                urllib.request.urlopen(req, timeout=2).read()
            except Exception: pass
            if n % 5 == 0:
                req=urllib.request.Request(API+"/api/reset",
                    data=b'{"confirm":true}',
                    headers={"Content-Type":"application/json"}, method="POST")
                urllib.request.urlopen(req, timeout=2).read()
            lat_api.append((time.perf_counter()-t0)*1000.0)
        except Exception:
            err["api"] += 1
        n+=1
        time.sleep(0.5)

def pid_of(name):
    out=subprocess.run(["pgrep","-f",name],capture_output=True,text=True).stdout.split()
    return int(out[0]) if out else None

def sample_rss(pid):
    try:
        s=open(f"/proc/{pid}/status").read()
        rss=[l for l in s.splitlines() if l.startswith("VmRSS")][0]
        return int(rss.split()[1])  # kB
    except Exception: return -1

def sample_fds(pid):
    try: return len(os.listdir(f"/proc/{pid}/fd"))
    except Exception: return -1

def sample_threads(pid):
    try: return len(os.listdir(f"/proc/{pid}/task"))
    except Exception: return -1

def pct(arr,p):
    if not arr: return 0.0
    arr=sorted(arr); k=(len(arr)-1)*p/100
    f=int(k); c=min(f+1,len(arr)-1)
    return arr[f]+(arr[c]-arr[f])*(k-f)

def main():
    cfgpath="/tmp/ebload.json"
    json.dump(CFG, open(cfgpath,"w"))
    # start fake upstream
    up=subprocess.Popen([sys.executable,"fake_upstream.py","15353"])
    time.sleep(0.5)
    # start ebpdns release
    # 二进制路径：优先 EBPDNS_BIN 环境变量 / argv[1]，否则回退到仓库默认 target 路径。
    binp = os.environ.get("EBPDNS_BIN") or (sys.argv[1] if len(sys.argv) > 1 else
        "/home/user/Doubao/chats/38443811575070978/rust200/target/release/ebpdns")
    srv=subprocess.Popen([binp,"--dns-udp-port",str(DNS_PORT),"--dns-tcp-port","5353",
        "--api-port","8353","--api-host","127.0.0.1","--config",cfgpath],
        stdout=open("/tmp/ebload_srv.log","w"), stderr=subprocess.STDOUT)
    time.sleep(2.0)
    # 用完整二进制路径定位进程（同一机器上可能存在其它同二进制实例，按 basename 会抓错 pid）。
    pid=pid_of(binp)
    print(f"ebpdns pid={pid}", flush=True)

    # pre-warm cache: resolve 100 fixed names once
    ws=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); ws.settimeout(2)
    for nm in WARM_NAMES:
        try:
            ws.sendto(qwire(nm,1),(DNS_IP,DNS_PORT)); ws.recvfrom(4096)
        except Exception: pass
    time.sleep(0.3)

    # baseline metrics
    base_rss=sample_rss(pid); base_fd=sample_fds(pid); base_th=sample_threads(pid)
    print(f"BASELINE rss_kb={base_rss} fds={base_fd} threads={base_th}", flush=True)

    # launch workers
    ths=[threading.Thread(target=dns_worker,args=(i,),daemon=True) for i in range(WORKERS)]
    apith=threading.Thread(target=api_loop,daemon=True)
    tstart=time.perf_counter()
    for t in ths: t.start()
    apith.start()

    # sample every 5s
    series=[]
    while time.perf_counter()-tstart < DUR:
        time.sleep(5.0)
        el=time.perf_counter()-tstart
        rss=sample_rss(pid); fd=sample_fds(pid); th=sample_threads(pid)
        series.append((el,rss,fd,th))
        print(f"  t={el:6.1f}s rss_kb={rss} fds={fd} threads={th}", flush=True)

    stop.set()
    for t in ths: t.join(timeout=3)
    apith.join(timeout=3)
    wall=time.perf_counter()-tstart

    # graceful stop
    srv.terminate(); srv.wait(timeout=8)
    up.terminate()

    # ---- report ----
    total=len(lat_hit)+len(lat_miss)+len(lat_aaaa)
    print("\n================ RESULTS ================")
    print(f"wall={wall:.1f}s workers={WORKERS}")
    print(f"QPS total        = {total/wall:.1f}")
    print(f"  cache hit QPS  = {len(lat_hit)/wall:.1f}  (n={len(lat_hit)})")
    print(f"  miss QPS       = {len(lat_miss)/wall:.1f}  (n={len(lat_miss)})")
    print(f"  AAAA QPS       = {len(lat_aaaa)/wall:.1f}  (n={len(lat_aaaa)})")
    alllat=lat_hit+lat_miss+lat_aaaa
    print(f"DNS latency P50={pct(alllat,50):.3f}ms P99={pct(alllat,99):.3f}ms")
    print(f"  hit P50={pct(lat_hit,50):.3f} P99={pct(lat_hit,99):.3f}")
    print(f"  miss P50={pct(lat_miss,50):.3f} P99={pct(lat_miss,99):.3f}")
    print(f"API calls={len(lat_api)} err_dns={err['dns']} err_api={err['api']}")
    end_rss=series[-1][1]; peak=max(s[1] for s in series)
    mid_rss=series[len(series)//2][1]
    print(f"RSS kB: start={base_rss} warm/early={series[0][1]} mid={mid_rss} end={end_rss} peak={peak}")
    print(f"fds: start={base_fd} end={series[-1][2]}")
    print(f"threads: start={base_th} end={series[-1][3]}")
    # leak verdict: compare mid vs end deltas
    drss=end_rss-mid_rss; dfd=series[-1][2]-series[len(series)//2][2]; dth=series[-1][3]-series[len(series)//2][3]
    print(f"LEAK mid->end: drss_kb={drss} dfds={dfd} dthreads={dth}")
    json.dump({"series":series,"base":[base_rss,base_fd,base_th],"wall":wall,
        "total":total,"hit":len(lat_hit),"miss":len(lat_miss),"aaaa":len(lat_aaaa),
        "p50":pct(alllat,50),"p99":pct(alllat,99),"err":err},
        open("/tmp/ebload_result.json","w"))

if __name__=="__main__":
    main()
