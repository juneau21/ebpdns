"""线程安全高并发测试: 16 线程 get/put 50000 次, 无死锁/异常/数据不一致。"""
import os
import sys
import threading
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ebpdns.cache import LRUCache, PartitionedCache, TinyLFUCache  # noqa: E402

NOW = 1_000_000.0
N_THREADS = 16
N_OPS = 50000


def _val():
    return {"answers": [{"value": "1.2.3.4"}], "rcode": 0, "expires_at": NOW + 3600}


def hammer(cache, keyfn, errors, idx):
    try:
        for i in range(N_OPS):
            k = keyfn("d%05d.com" % (i % 4096), "A" if i % 2 else "AAAA")
            if i % 3:
                cache.get(k, now=NOW)
            else:
                cache.put(k, _val(), now=NOW)
            if i % 97 == 0:
                _ = len(cache)
                _ = cache.summary()
                _ = len(cache.snapshot_keys())
        errors.append(None)
    except Exception:
        errors.append(traceback.format_exc())


def run(name, cache, keyfn):
    print("[%s]" % name)
    errors = []
    t0 = time.time()
    threads = [threading.Thread(target=hammer, args=(cache, keyfn, errors, t))
               for t in range(N_THREADS)]
    for t in threads:
        t.start()
    deadline = t0 + 60
    for t in threads:
        t.join(timeout=max(1, deadline - time.time()))
    alive = [t for t in threads if t.is_alive()]
    check_ = lambda c, m: (_ for _ in ()).throw(AssertionError("FAIL: " + m)) if not c else None
    try:
        check_(not alive, "no deadlock (still alive: %d)" % len(alive))
        errs = [e for e in errors if e]
        check_(not errs, "no exceptions:\n" + (errs[0] if errs else ""))
        # 最终一致性: 所有 key 都在各段容量内
        if isinstance(cache, TinyLFUCache):
            s = cache.summary()
            check_(s["window"] <= cache._win_cap + 1, "window within cap")
            check_(s["probation"] <= cache._prob_cap + 1, "probation within cap")
            check_(s["protected"] <= cache._prot_cap + 1, "protected within cap")
        check_(len(cache) <= cache.capacity + 8, "total within capacity")
        dt = time.time() - t0
        print("  ok - %d threads x %d ops in %.2fs, len=%d"
              % (N_THREADS, N_OPS, dt, len(cache)))
    except AssertionError as e:
        print("  FAIL - %s" % e)
        raise


if __name__ == "__main__":
    run("LRUCache", LRUCache(2048), lambda d, q: (d, q))
    run("TinyLFUCache", TinyLFUCache(2048), lambda d, q: (d, q))
    run("PartitionedCache", PartitionedCache(2048), lambda d, q: ("default", d, q))
    print("ALL THREAD-SAFETY TESTS PASSED")
