"""三缓存策略基准对比 + cProfile 热点分析。

工作负载: 真实感域名混合, Zipf 分布(s=0.99)模拟热点。
阶段:
  1) warmup put: 灌入 keyspace 30% 的唯一域名
  2) run: 按 Zipf 抽样查询(先 put 未命中则填回), 统计命中/未命中
容量: 1024 / 4096 两档。
输出: 命中率、p50/p99 get 延迟、put 延迟、内存占用。
"""
import cProfile
import io
import os
import random
import sys
import time
import pstats

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ebpdns.cache import LRUCache, PartitionedCache, TinyLFUCache  # noqa: E402

NOW = 1_000_000.0
KEYSPACE = 20000
N_QUERIES = 200000


def _val():
    return {"answers": [{"value": "1.2.3.4"}], "rcode": 0, "expires_at": NOW + 3600}


def zipf_keys(n, s=0.99, seed=42):
    rnd = random.Random(seed)
    # 构造 zipf 权重表
    weights = [1.0 / (i ** s) for i in range(1, n + 1)]
    tot = sum(weights)
    cum = []
    acc = 0.0
    for w in weights:
        acc += w / tot
        cum.append(acc)
    return rnd, cum


def sample_key(rnd, cum):
    r = rnd.random()
    # 二分
    lo, hi = 0, len(cum) - 1
    while lo < hi:
        mid = (lo + hi) // 2
        if cum[mid] < r:
            lo = mid + 1
        else:
            hi = mid
    return "d%05d.com" % lo


def make(policy, cap):
    if policy == "lru":
        return LRUCache(cap)
    if policy == "tinylfu":
        return TinyLFUCache(cap)
    return PartitionedCache(cap)


def keyfn(policy, domain):
    return (domain, "A") if policy in ("lru", "tinylfu") else ("default", domain, "A")


def bench(policy, cap):
    cache = make(policy, cap)
    rnd, cum = zipf_keys(KEYSPACE)
    # warmup: 灌入 30% 唯一域名
    warm = set()
    for _ in range(int(KEYSPACE * 0.3)):
        d = sample_key(rnd, cum)
        warm.add(d)
        cache.put(keyfn(policy, d), _val(), now=NOW)
    # run
    lat = []
    hits = miss = 0
    for _ in range(N_QUERIES):
        d = sample_key(rnd, cum)
        k = keyfn(policy, d)
        t0 = time.perf_counter()
        e = cache.get(k, now=NOW)
        dt = (time.perf_counter() - t0) * 1e6  # us
        lat.append(dt)
        if e is None:
            miss += 1
            cache.put(k, _val(), now=NOW)
        else:
            hits += 1
    lat.sort()
    n = len(lat)
    p50 = lat[n // 2]
    p99 = lat[int(n * 0.99)]
    hit_rate = hits / (hits + miss) * 100
    # 内存: 粗略测量
    import pickle
    mem = len(pickle.dumps(cache.serialize(now=NOW)))
    return {
        "policy": policy, "cap": cap, "hit_rate": round(hit_rate, 2),
        "p50_us": round(p50, 2), "p99_us": round(p99, 2),
        "entries": len(cache), "serialized_bytes": mem,
    }


def profile_tinylfu():
    print("\n=== cProfile: TinyLFUCache get/put hot path (cap=4096, 50k ops) ===")
    c = TinyLFUCache(4096)
    rnd, cum = zipf_keys(KEYSPACE)
    pr = cProfile.Profile()
    pr.enable()
    for i in range(50000):
        d = sample_key(rnd, cum)
        k = (d, "A")
        e = c.get(k, now=NOW)
        if e is None:
            c.put(k, _val(), now=NOW)
    pr.disable()
    s = io.StringIO()
    pstats.Stats(pr, stream=s).sort_stats("cumulative").print_stats(18)
    print(s.getvalue())


if __name__ == "__main__":
    results = []
    for cap in (1024, 4096):
        for pol in ("lru", "partitioned", "tinylfu"):
            r = bench(pol, cap)
            results.append(r)
            print("cap=%-5d policy=%-11s hit=%5.2f%%  p50=%6.2fus  p99=%7.2fus  entries=%d  ser_bytes=%d"
                  % (r["cap"], r["policy"], r["hit_rate"], r["p50_us"],
                     r["p99_us"], r["entries"], r["serialized_bytes"]))
    # 保存结果供报告
    import json
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "bench_results.json"), "w") as f:
        json.dump(results, f, indent=2)
    profile_tinylfu()
