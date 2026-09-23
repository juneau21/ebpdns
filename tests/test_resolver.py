"""Resolver 规则匹配 / NXDOMAIN quorum / forceIp 单元测试(无网络)。"""

import unittest

from ebpdns import resolver as resolver_mod
from ebpdns.resolver import Resolver
from ebpdns.telemetry import Telemetry


def _up(uid, proto="udp"):
    return {"id": uid, "name": uid, "proto": proto, "addr": "127.0.0.1",
            "port": 53, "enabled": True, "latency": 5000}


def make_resolver(rules=None, quorum=2, upstreams=None):
    cfg = {
        "upstreams": upstreams or [_up("u1"), _up("u2")],
        "rules": rules or [],
        "cache_size": 64,
        "cache_policy": "lru",
        "max_parallel_upstreams": 3,
        "timeout_ms": 200,
        "nxdomain_quorum": quorum,
        "fallback": True,
        "rebind_protection": True,
        "edns": False,
        "prefetch": False,
        "speed_test": False,
        "ipv6": True,
    }
    r = Resolver(cfg, Telemetry())
    r._boot_ts = 0.0   # 关闭启动预热重试, 保证测试确定性
    return r


def stop_instance(r):
    """轻量停止单个 Resolver 实例的后台线程与实例级线程池。
    不调用 Resolver.shutdown(): 后者会关闭模块级共享 _REGEX_POOL,
    跨实例测试会让后续实例的正则匹配全部 RuntimeError→None。"""
    r._prefetch_stop.set()
    r._bg_stop.set()
    for pool in (r._up_pool, r._doh_pool, r._prefetch_pool,
                 r._collect_pool, r._probe_pool):
        try:
            pool.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass


_NX = {"rcode": 3, "answers": [], "up_name": "u1", "cnames": []}
_FAIL = {"rcode": None, "answers": [], "up_name": "u2", "cnames": []}
_NODATA = {"rcode": 0, "answers": [], "up_name": "u1", "cnames": []}


class TestRuleMatching(unittest.TestCase):
    def test_exact_block(self):
        r = make_resolver([{"match": "blocked.test", "action": "block"}])
        self.addCleanup(stop_instance, r)
        self.assertEqual(r.match_rule("blocked.test")["action"], "block")
        self.assertIsNone(r.match_rule("other.test"))

    def test_wildcard_block(self):
        r = make_resolver([{"match": "*.ads.com", "action": "block"}])
        self.addCleanup(stop_instance, r)
        self.assertEqual(r.match_rule("x.ads.com")["action"], "block")
        self.assertEqual(r.match_rule("a.b.ads.com")["action"], "block")
        # 设计语义: *.core 同时匹配 core 自身
        self.assertEqual(r.match_rule("ads.com")["action"], "block")
        self.assertIsNone(r.match_rule("other.com"))

    def test_allow_priority(self):
        r = make_resolver([
            {"match": "ok.ads.com", "action": "allow"},
            {"match": "*.ads.com", "action": "block"},
        ])
        self.addCleanup(stop_instance, r)
        self.assertEqual(r.match_rule("ok.ads.com")["action"], "allow")

    def test_regex_match(self):
        r = make_resolver([{"match": r"re:^ads\..*", "action": "block"}])
        self.addCleanup(stop_instance, r)
        self.assertEqual(r.match_rule("ads.x.com")["action"], "block")
        self.assertIsNone(r.match_rule("notads.x.com"))

    def test_regex_inconclusive_fail_closed(self):
        r = make_resolver([{"match": "re:evil.*", "action": "block"}])
        self.addCleanup(stop_instance, r)
        orig = resolver_mod._regex_search_safe
        resolver_mod._regex_search_safe = lambda pat, text, timeout=None: None
        try:
            rule = r.match_rule("evil-x.test")
        finally:
            resolver_mod._regex_search_safe = orig
        self.assertIsNotNone(rule)
        self.assertEqual(rule["action"], "block")

    def test_force_ip(self):
        r = make_resolver([{"match": "forced.test", "action": "forceIp", "ip": "9.9.9.9"}])
        self.addCleanup(stop_instance, r)
        res = r.resolve("forced.test", "A")
        self.assertFalse(res["error"])
        self.assertEqual(res["answers"][0]["value"], "9.9.9.9")


class TestNXDOMAINQuorum(unittest.TestCase):
    def _patch(self, r, results):
        r._query_parallel = lambda ups, qb, d, qt, trace, qmap=None: list(results)

    def test_single_nx_with_failure_is_servfail(self):
        r = make_resolver(quorum=2)
        self.addCleanup(stop_instance, r)
        self._patch(r, [_NX, _FAIL])
        self.assertEqual(r.resolve("nx.test", "A")["rcode"], 2)

    def test_two_nx_is_nxdomain(self):
        r = make_resolver(quorum=2)
        self.addCleanup(stop_instance, r)
        self._patch(r, [dict(_NX, up_name="u1"), dict(_NX, up_name="u2")])
        self.assertEqual(r.resolve("nx.test", "A")["rcode"], 3)

    def test_single_upstream_nx_is_nxdomain(self):
        r = make_resolver(quorum=2, upstreams=[_up("u1")])
        self.addCleanup(stop_instance, r)
        self._patch(r, [_NX])
        self.assertEqual(r.resolve("nx.test", "A")["rcode"], 3)

    def test_nodata(self):
        r = make_resolver(quorum=2)
        self.addCleanup(stop_instance, r)
        self._patch(r, [_NODATA, _FAIL])
        res = r.resolve("empty.test", "A")
        self.assertEqual(res["rcode"], 0)
        self.assertEqual(res["answers"], [])


if __name__ == "__main__":
    unittest.main()
