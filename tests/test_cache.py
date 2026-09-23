"""缓存(LRU / Partitioned / TinyLFU)单元测试。"""

import time
import unittest

from ebpdns.cache import LRUCache, PartitionedCache, TinyLFUCache


def _entry(ttl=60, answers=None, rcode=0):
    return {
        "domain": "example.com",
        "qtype": "A",
        "answers": answers if answers is not None else [{"value": "1.2.3.4", "ttl": ttl, "type": 1}],
        "chosen": "1.2.3.4",
        "ttl": ttl,
        "rcode": rcode,
        "expires_at": time.time() + ttl,
    }


class TestLRUCache(unittest.TestCase):
    def test_put_get(self):
        c = LRUCache(64)
        c.put(("example.com", "A"), _entry())
        self.assertIsNotNone(c.get(("example.com", "A")))
        self.assertIsNone(c.get(("missing.com", "A")))

    def test_expiry(self):
        c = LRUCache(64)
        e = _entry(ttl=1)
        c.put(("example.com", "A"), e)
        time.sleep(1.1)
        self.assertIsNone(c.get(("example.com", "A")))

    def test_eviction(self):
        c = LRUCache(16)
        for i in range(100):
            c.put(("host%d.test" % i, "A"), _entry())
        self.assertLessEqual(len(c), 16)

    def test_serialize_restore(self):
        c = LRUCache(64)
        c.put(("example.com", "A"), _entry())
        blob = c.serialize()
        self.assertEqual(len(blob), 1)
        c2 = LRUCache(64)
        c2.restore(blob)
        self.assertIsNotNone(c2.get(("example.com", "A")))

    def test_restore_persist_ttl(self):
        c = LRUCache(64)
        c.put(("example.com", "A"), _entry())
        blob = c.serialize()
        c2 = LRUCache(64)
        c2.restore(blob, persist_ttl=5)
        got = c2.get(("example.com", "A"))
        self.assertAlmostEqual(got["expires_at"] - time.time(), 5, delta=1)


class TestPartitionedCache(unittest.TestCase):
    def test_partition_isolation(self):
        c = PartitionedCache(128, {"domestic": 0.5, "global": 0.3, "default": 0.2})
        c.put(("domestic", "a.test", "A"), _entry())
        c.put(("global", "b.test", "A"), _entry())
        self.assertIsNotNone(c.get(("domestic", "a.test", "A")))
        self.assertIsNone(c.get(("global", "a.test", "A")))

    def test_serialize_restore_roundtrip(self):
        c = PartitionedCache(128)
        c.put(("domestic", "a.test", "A"), _entry())
        blob = c.serialize()
        c2 = PartitionedCache(128)
        c2.restore(blob)
        self.assertIsNotNone(c2.get(("domestic", "a.test", "A")))


class TestTinyLFUCache(unittest.TestCase):
    def test_put_get(self):
        c = TinyLFUCache(64)
        c.put(("example.com", "A"), _entry())
        self.assertIsNotNone(c.get(("example.com", "A")))

    def test_hot_key_retention(self):
        c = TinyLFUCache(64)
        c.put(("hot.test", "A"), _entry())
        # 反复访问热点
        for _ in range(50):
            c.get(("hot.test", "A"))
        # 灌入其他条目触发淘汰
        for i in range(100):
            c.put(("cold%d.test" % i, "A"), _entry())
        self.assertIsNotNone(c.get(("hot.test", "A")))

    def test_serialize_restore(self):
        c = TinyLFUCache(64)
        c.put(("example.com", "A"), _entry())
        blob = c.serialize()
        c2 = TinyLFUCache(64)
        c2.restore(blob)
        self.assertIsNotNone(c2.get(("example.com", "A")))


if __name__ == "__main__":
    unittest.main()
