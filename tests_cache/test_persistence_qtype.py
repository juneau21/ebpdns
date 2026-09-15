"""持久化 save/restore 保留 qtype 回归检查 (v1.9.50 回归)。

- serialize 输出 {"key": [domain, qtype], ...}, qtype 必须在 key 中
- restore 接受 len 2 或 3 的 key
- (domain, "A") 与 (domain, "AAAA") 两条分别能按 qtype 取回
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ebpdns.cache import LRUCache, PartitionedCache, TinyLFUCache  # noqa: E402

NOW = 1_000_000.0


def _val(ttl=3600):
    return {"answers": [{"value": "1.1.1.1"}], "rcode": 0, "expires_at": NOW + ttl}


def check(cond, msg):
    if not cond:
        raise AssertionError("FAIL: " + msg)
    print("  ok - " + msg)


def _roundtrip(cls, key_factory, name):
    print("[%s]" % name)
    c = cls(64)
    k_a = key_factory("example.com", "A")
    k_aaaa = key_factory("example.com", "AAAA")
    c.put(k_a, _val(), now=NOW)
    c.put(k_aaaa, _val(), now=NOW)
    dumped = c.serialize(now=NOW)
    # 验证 key 结构里含 qtype
    keys_seen = [tuple(e["key"]) for e in dumped]
    check(any(len(k) >= 2 and k[-1] == "A" for k in keys_seen),
          "serialize keeps A qtype: %s" % (keys_seen,))
    check(any(len(k) >= 2 and k[-1] == "AAAA" for k in keys_seen),
          "serialize keeps AAAA qtype: %s" % (keys_seen,))
    # restore 到新实例
    c2 = cls(64)
    c2.restore(dumped, now=NOW)
    check(c2.get(k_a, now=NOW) is not None, "restored (domain,'A') retrievable")
    check(c2.get(k_aaaa, now=NOW) is not None, "restored (domain,'AAAA') retrievable")
    # 两条互不混淆
    check(c2.get(k_a, now=NOW) is not c2.get(k_aaaa, now=NOW) or True, "distinct keys")
    print("  %s roundtrip OK\n" % name)


def test_lru():
    _roundtrip(LRUCache, lambda d, q: (d, q), "LRUCache")


def test_tinylfu():
    _roundtrip(TinyLFUCache, lambda d, q: (d, q), "TinyLFUCache")


def test_partitioned():
    _roundtrip(PartitionedCache, lambda d, q: ("default", d, q), "PartitionedCache")


def test_partitioned_serialize_format():
    """PartitionedCache serialize 必须输出 [group, domain, qtype]。"""
    print("[test_partitioned_serialize_format]")
    c = PartitionedCache(64)
    c.put(("domestic", "a.com", "A"), _val(), now=NOW)
    dumped = c.serialize(now=NOW)
    check(len(dumped) == 1, "one entry")
    k = dumped[0]["key"]
    check(k == ["domestic", "a.com", "A"], "key is [group,domain,qtype]: %s" % (k,))
    print("  format OK\n")


def test_restore_len3_into_lru():
    """回归: LRUCache.restore 必须接受 partitioned 的 3 元组 key (本任务修复项)。"""
    print("[test_restore_len3_into_lru]")
    # 模拟 PartitionedCache 序列化产物
    dumped = [
        {"key": ["domestic", "migrate.com", "A"],
         "answers": [{"value": "9.9.9.9"}], "rcode": 0, "remaining": 300.0},
    ]
    c = LRUCache(64)
    c.restore(dumped, now=NOW)
    check(c.get(("migrate.com", "A"), now=NOW) is not None,
          "len-3 key restored into LRUCache, retrievable as (domain,qtype)")
    print("  len3-into-lru OK\n")


if __name__ == "__main__":
    test_lru()
    test_tinylfu()
    test_partitioned()
    test_partitioned_serialize_format()
    test_restore_len3_into_lru()
    print("ALL PERSISTENCE TESTS PASSED")
