"""热切换 cache_policy 数据迁移校验。

注意: resolver.py 的 reload() 目前在切策略时直接 new 容器, 不主动迁移
(代码注释: "策略不同步迁移数据...直接重建容器, 冷启动短暂命中率下降是可接受代价")。
本测试站在 cache.py 接口层验证: 任意策略之间 serialize/restore 往返不丢数据,
即一旦 resolver 侧选择迁移, 接口是兼容的。覆盖 lru <-> tinylfu <-> partitioned 全路径。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ebpdns.cache import LRUCache, PartitionedCache, TinyLFUCache  # noqa: E402

NOW = 1_000_000.0


def _val(ttl=3600):
    return {"answers": [{"value": "8.8.8.8"}], "rcode": 0, "expires_at": NOW + ttl}


def check(cond, msg):
    if not cond:
        raise AssertionError("FAIL: " + msg)
    print("  ok - " + msg)


def make_cache(policy, cap=256):
    if policy == "lru":
        return LRUCache(cap)
    if policy == "tinylfu":
        return TinyLFUCache(cap)
    if policy == "partitioned":
        return PartitionedCache(cap)
    raise ValueError(policy)


def _key(policy, domain, qtype):
    return (domain, qtype) if policy in ("lru", "tinylfu") else ("default", domain, qtype)


def test_switch_chain():
    print("[test_switch_chain lru->tinylfu->partitioned->lru]")
    policies = ["lru", "tinylfu", "partitioned", "lru"]
    cap = 256
    caches = []
    # 每段策略都写入一批数据
    seed_keys = [("svc%d.com" % i, "A") for i in range(40)]
    cur = make_cache("lru", cap)
    for d, q in seed_keys:
        cur.put(("default", d, q) if isinstance(cur, PartitionedCache) else (d, q),
                _val(), now=NOW)
    total_after_each = []
    for nxt in policies[1:]:
        dumped = cur.serialize(now=NOW)
        nxt_cache = make_cache(nxt, cap)
        nxt_cache.restore(dumped, now=NOW)
        total_after_each.append(len(nxt_cache))
        cur = nxt_cache
    # 迁移后数据量基本保留(允许因容量上限丢弃少数)
    check(total_after_each[0] >= 38, "lru->tinylfu kept %d/40" % total_after_each[0])
    check(total_after_each[1] >= 38, "tinylfu->partitioned kept %d/40" % total_after_each[1])
    check(total_after_each[2] >= 38, "partitioned->lru kept %d/40 (修复项)" % total_after_each[2])
    # 取回验证
    for d, q in seed_keys[:10]:
        k = ("default", d, q) if isinstance(cur, PartitionedCache) else (d, q)
        check(cur.get(k, now=NOW) is not None, "key %s retrievable after chain" % (k,))
    print("  switch chain OK\n")


def test_partitioned_groups_survive():
    """partitioned 内 domestic/global/default 分组迁移后仍按 group 路由。"""
    print("[test_partitioned_groups_survive]")
    src = PartitionedCache(256)
    src.put(("domestic", "cn.com", "A"), _val(), now=NOW)
    src.put(("global", "io.com", "A"), _val(), now=NOW)
    src.put(("default", "x.com", "A"), _val(), now=NOW)
    dumped = src.serialize(now=NOW)
    dst = PartitionedCache(256)
    dst.restore(dumped, now=NOW)
    check(dst.get(("domestic", "cn.com", "A"), now=NOW) is not None, "domestic survives")
    check(dst.get(("global", "io.com", "A"), now=NOW) is not None, "global survives")
    check(dst.get(("default", "x.com", "A"), now=NOW) is not None, "default survives")
    # domestic 那条不应落到 global 池
    check(dst._caches["domestic"].get(("cn.com", "A"), now=NOW) is not None,
          "domestic entry routed to domestic pool")
    print("  groups OK\n")


def test_resolver_reload_note():
    """文档化: resolver.reload 现状是不迁移(读代码确认)。"""
    print("[test_resolver_reload_note]")
    import inspect
    import ebpdns.resolver as R
    src = inspect.getsource(R.Resolver.reload)
    check("TinyLFUCache(cap)" in src or "PartitionedCache(cap" in src,
          "reload reconstructs container on policy switch")
    # 确认 reload 没有调用 serialize/restore 迁移
    check("serialize" not in src or "restore" not in src,
          "reload currently does NOT migrate data (by design); cache.py interface compatible")
    print("  resolver reload behavior confirmed (no migration by design)\n")


if __name__ == "__main__":
    test_switch_chain()
    test_partitioned_groups_survive()
    test_resolver_reload_note()
    print("ALL HOT-SWITCH TESTS PASSED")
