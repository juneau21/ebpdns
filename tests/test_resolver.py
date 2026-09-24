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
        "health_check_interval": 0,  # 禁用后台主动健康检查, 避免 bg 线程首次 tick 干扰本测试
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
        # match_rule 现在以 pool=/sem= 关键字传入实例池, patch 的替身签名需兼容
        # (返回 None=不确定, 屏蔽规则应 fail-closed 命中)。
        resolver_mod._regex_search_safe = lambda pat, text, timeout=None, pool=None, sem=None: None
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


class TestCircuitBreakerReload(unittest.TestCase):
    """M3: 热重载后 _cb 必须清理已删除上游的死条目。"""

    def test_reload_clears_dead_upstream_cb(self):
        r = make_resolver(upstreams=[_up("u1"), _up("u2")])
        self.addCleanup(stop_instance, r)
        # 注入一个"已删除上游"的熔断死条目 + 一个存活上游 u1 的条目
        with r._cb_lock:
            r._cb["gone"] = {"fails": 99, "until": 999999999.0}
            r._cb["u1"] = {"fails": 1, "until": 0.0}
        # 新配置只保留 u1: gone 与 u2 均不在新上游集合中
        new_cfg = {
            "upstreams": [_up("u1")],
            "rules": [], "cache_size": 64, "cache_policy": "lru",
            "max_parallel_upstreams": 3, "timeout_ms": 200,
            "nxdomain_quorum": 2, "fallback": True, "rebind_protection": True,
            "edns": False, "prefetch": False, "speed_test": False, "ipv6": True,
        }
        r.reload(new_cfg)
        with r._cb_lock:
            self.assertNotIn("gone", r._cb)   # 死条目被清理
            self.assertIn("u1", r._cb)       # 存活上游保留


class TestPrefetchOrdering(unittest.TestCase):
    """S1: _prefetch_pending 为 OrderedDict, 遍历顺序稳定可预测。"""

    def test_pending_is_ordered_dict(self):
        from collections import OrderedDict
        r = make_resolver(upstreams=[_up("u1")])
        self.addCleanup(stop_instance, r)
        self.assertIsInstance(r._prefetch_pending, OrderedDict)

    def test_pending_insertion_order_stable(self):
        r = make_resolver(upstreams=[_up("u1")])
        self.addCleanup(stop_instance, r)
        r.cfg["prefetch"] = True
        for k in ("kA", "kB", "kC"):
            r.schedule_prefetch(k, "example.com", "A")
        # 插入顺序稳定, 轮转指针在固定序窗口上前进才能覆盖全部 key
        self.assertEqual(list(r._prefetch_pending.keys()), ["kA", "kB", "kC"])

    def test_reschedule_moves_to_end(self):
        r = make_resolver(upstreams=[_up("u1")])
        self.addCleanup(stop_instance, r)
        r.cfg["prefetch"] = True
        for k in ("kA", "kB", "kC"):
            r.schedule_prefetch(k, "example.com", "A")
        # 重新调度已有 key B → 移到 MRU 末尾
        r.schedule_prefetch("kB", "example.com", "A")
        self.assertEqual(list(r._prefetch_pending.keys()), ["kA", "kC", "kB"])


class TestCnameChainOwnerName(unittest.TestCase):
    """v1.9.139: CNAME 链展开后 A/AAAA RR 的 owner name 应为 CNAME 目标域名。

    RFC 1034: CNAME 链中后续 RR 的 owner 必须是 CNAME 目标域名,
    而非原始查询域名。修复前 sub_ans 无 name 键, build_response_body_answers
    统一使用查询域名 enc_owner, 导致严格 stub resolver 多一次往返。
    """

    def test_cname_chain_a_record_owner_is_target(self):
        r = make_resolver(quorum=1)
        self.addCleanup(stop_instance, r)

        def _fake_query(ups, qb, d, qt, trace, qmap=None):
            if d == "cname.test":
                # 返回 CNAME 但无 A 答案 → 触发 CNAME 链展开
                return [{"rcode": 0, "answers": [], "up_name": "u1", "lat": 10.0,
                         "cnames": [("cdn.test", 300)]}]
            elif d == "cdn.test":
                # CNAME 目标的递归解析返回 A 答案
                return [{"rcode": 0, "answers": [
                    {"value": "1.2.3.4", "ttl": 300, "type": 1}],
                    "up_name": "u1", "lat": 12.0, "cnames": []}]
            return [{"rcode": 2, "answers": [], "up_name": "u1", "lat": 200.0, "cnames": []}]

        r._query_parallel = _fake_query
        res = r.resolve("cname.test", "A")

        # 应答应有 2 条: CNAME + A
        self.assertEqual(len(res["answers"]), 2)
        # 第一条 CNAME 记录无 name 键(owner 为查询域名, 用 enc_owner)
        self.assertEqual(res["answers"][0]["type"], 5)  # TYPE_CNAME
        self.assertNotIn("name", res["answers"][0])
        # 第二条 A 记录应有 name=cdn.test (CNAME 目标域名)
        self.assertEqual(res["answers"][1]["type"], 1)  # TYPE_A
        self.assertEqual(res["answers"][1].get("name"), "cdn.test")

    def test_cname_chain_aaaa_record_owner_is_target(self):
        r = make_resolver(quorum=1)
        self.addCleanup(stop_instance, r)

        def _fake_query(ups, qb, d, qt, trace, qmap=None):
            if d == "cname.test":
                return [{"rcode": 0, "answers": [], "up_name": "u1", "lat": 10.0,
                         "cnames": [("cdn6.test", 300)]}]
            elif d == "cdn6.test":
                return [{"rcode": 0, "answers": [
                    {"value": "2001:4860:4860::8888", "ttl": 300, "type": 28}],
                    "up_name": "u1", "lat": 12.0, "cnames": []}]
            return [{"rcode": 2, "answers": [], "up_name": "u1", "lat": 200.0, "cnames": []}]

        r._query_parallel = _fake_query
        res = r.resolve("cname.test", "AAAA")
        self.assertEqual(len(res["answers"]), 2)
        self.assertEqual(res["answers"][0]["type"], 5)  # CNAME
        self.assertEqual(res["answers"][1]["type"], 28)  # AAAA
        self.assertEqual(res["answers"][1].get("name"), "cdn6.test")
        self.assertEqual(res["answers"][1]["value"], "2001:4860:4860::8888")


class TestAnswerFastSecondHit(unittest.TestCase):
    """v1.9.140 回归: _enc_owner 必须是 OrderedDict, 否则第二次缓存命中
    调用 move_to_end() 抛 AttributeError, 被 server.py broad except 吞掉
    导致快路径对重复查询静默失效。"""

    def test_second_cache_hit_does_not_crash(self):
        from ebpdns import dnsmsg
        r = make_resolver([])
        self.addCleanup(stop_instance, r)
        # 手动回填缓存: A 记录
        key = r._ckey("fast.test", "A")
        r._fill_cache(key, "fast.test", "A",
                       [{"value": "1.2.3.4", "ttl": 300, "type": 1}])
        raw, _ = dnsmsg.build_query("fast.test", dnsmsg.type_code("A"), qid=0x1234, edns=False)
        # 第一次命中: memo miss → encode → insert (不调 move_to_end)
        resp1 = r.answer_fast(raw)
        self.assertIsNotNone(resp1, "first cache hit should return response")
        self.assertIsInstance(resp1, bytes)
        # 第二次命中: memo hit → move_to_end(domain) — plain dict 会在此崩溃
        resp2 = r.answer_fast(raw)
        self.assertIsNotNone(resp2, "second cache hit should not crash (OrderedDict required)")
        self.assertIsInstance(resp2, bytes)
        # 验证 memo 容器类型
        from collections import OrderedDict
        self.assertIsInstance(r._enc_owner, OrderedDict,
                              "_enc_owner must be OrderedDict for move_to_end/popitem(last=False)")

    def test_second_cache_hit_with_cname_does_not_crash(self):
        """CNAME 链 answers 带 name=tgt, 第二次命中时 _ec.move_to_end(nm) 也需 OrderedDict。"""
        from ebpdns import dnsmsg
        r = make_resolver([])
        self.addCleanup(stop_instance, r)
        key = r._ckey("cname-fast.test", "A")
        # CNAME + A, A 记录带 name=tgt
        r._fill_cache(key, "cname-fast.test", "A", [
            {"value": "cdn.test", "ttl": 300, "type": 5},  # CNAME, 无 name
            {"value": "5.6.7.8", "ttl": 300, "type": 1, "name": "cdn.test"},  # A, 有 name
        ])
        raw, _ = dnsmsg.build_query("cname-fast.test", dnsmsg.type_code("A"), qid=0x5678, edns=False)
        resp1 = r.answer_fast(raw)
        self.assertIsNotNone(resp1)
        resp2 = r.answer_fast(raw)
        self.assertIsNotNone(resp2, "second CNAME cache hit should not crash")


class TestUpstreamWeightedSort(unittest.TestCase):
    """v1.9.140 回归: 上游 weight 加权轮询 — weight 字段在 api.py 全链路校验
    并存储, 但 resolver 排序 key 必须读取 weight 才能生效。"""

    def _sort_key(self, r, u):
        """与 resolver.py:827 完全一致的排序 key 表达式(经 _safe_float 兜底)。"""
        from ebpdns.resolver import _safe_float
        return r._upstream_eff_lat(u) / max(1.0, _safe_float(u.get("weight", 1), 1.0))

    def test_higher_weight_ranks_first_when_latency_equal(self):
        """两个上游 latency 相同, weight 高的排序 key 更小 → 排前面。"""
        r = make_resolver()
        self.addCleanup(stop_instance, r)
        u_low = {"id": "u_low", "name": "u_low", "proto": "udp", "addr": "127.0.0.1",
                 "port": 53, "enabled": True, "latency": 5000, "weight": 1}
        u_high = {"id": "u_high", "name": "u_high", "proto": "udp", "addr": "127.0.0.1",
                  "port": 53, "enabled": True, "latency": 5000, "weight": 10}
        ordered = sorted([u_low, u_high], key=lambda u: self._sort_key(r, u))
        self.assertEqual(ordered[0]["id"], "u_high",
                         "weight=10 should sort before weight=1 when latency equal")
        self.assertEqual(ordered[1]["id"], "u_low")

    def test_default_weight_one_matches_original_behavior(self):
        """weight 缺省为 1 时, 排序 key 等于纯延迟, 与原逻辑一致(向后兼容)。"""
        r = make_resolver()
        self.addCleanup(stop_instance, r)
        # mock _upstream_eff_lat 返回固定值, 排除 telemetry 干扰
        r._upstream_eff_lat = lambda u: 100.0
        u1 = {"id": "u1", "name": "u1", "proto": "udp", "addr": "127.0.0.1",
              "port": 53, "enabled": True, "latency": 5000}  # 无 weight 字段
        u2 = {"id": "u2", "name": "u2", "proto": "udp", "addr": "127.0.0.1",
              "port": 53, "enabled": True, "latency": 5000, "weight": 1}  # 显式 weight=1
        # 两者排序 key 应完全相等 (100/1 == 100/1)
        k1 = self._sort_key(r, u1)
        k2 = self._sort_key(r, u2)
        self.assertEqual(k1, k2,
                         "missing weight and weight=1 should produce identical sort key")
        # 反向也验证: 与原 sorted(ups, key=_upstream_eff_lat) 结果一致
        orig_order = sorted([u1, u2], key=r._upstream_eff_lat)
        new_order = sorted([u1, u2], key=lambda u: self._sort_key(r, u))
        self.assertEqual([u["id"] for u in orig_order],
                         [u["id"] for u in new_order])

    def test_weight_zero_falls_back_to_one_no_crash(self):
        """weight=0 时 `or 1` 兜底为 1, 不崩溃也不除零。"""
        r = make_resolver()
        self.addCleanup(stop_instance, r)
        r._upstream_eff_lat = lambda u: 200.0
        u_zero = {"id": "u_zero", "name": "u_zero", "proto": "udp", "addr": "127.0.0.1",
                  "port": 53, "enabled": True, "latency": 5000, "weight": 0}
        u_normal = {"id": "u_normal", "name": "u_normal", "proto": "udp", "addr": "127.0.0.1",
                    "port": 53, "enabled": True, "latency": 5000, "weight": 2}
        # weight=0 → 兜底为 1 → key=200/1=200; weight=2 → key=200/2=100
        # 不应抛 ZeroDivisionError
        ordered = sorted([u_zero, u_normal], key=lambda u: self._sort_key(r, u))
        self.assertEqual(ordered[0]["id"], "u_normal",
                         "weight=2 should rank before weight=0 (which falls back to 1)")
        self.assertEqual(ordered[1]["id"], "u_zero")

    def test_float_weight_supported(self):
        """api.py 允许 float weight, resolver 排序也应兼容。"""
        r = make_resolver()
        self.addCleanup(stop_instance, r)
        r._upstream_eff_lat = lambda u: 100.0
        u_float = {"id": "u_float", "name": "u_float", "proto": "udp", "addr": "127.0.0.1",
                   "port": 53, "enabled": True, "latency": 5000, "weight": 1.5}
        u_int = {"id": "u_int", "name": "u_int", "proto": "udp", "addr": "127.0.0.1",
                 "port": 53, "enabled": True, "latency": 5000, "weight": 1}
        ordered = sorted([u_int, u_float], key=lambda u: self._sort_key(r, u))
        self.assertEqual(ordered[0]["id"], "u_float",
                         "float weight=1.5 should rank before int weight=1")

    def test_malformed_weight_string_does_not_crash(self):
        """v1.9.141 回归: weight 为非数字字符串(如 "abc"/"N/A")时, 裸 float() 抛
        ValueError 穿透 sorted()→resolve() 致 SERVFAIL。改用 _safe_float 兜底 1.0,
        与 latency 解析口径一致, 排序不崩溃。"""
        r = make_resolver()
        self.addCleanup(stop_instance, r)
        r._upstream_eff_lat = lambda u: 100.0
        u_bad = {"id": "u_bad", "name": "u_bad", "proto": "udp", "addr": "127.0.0.1",
                 "port": 53, "enabled": True, "latency": 5000, "weight": "abc"}
        u_none = {"id": "u_none", "name": "u_none", "proto": "udp", "addr": "127.0.0.1",
                  "port": 53, "enabled": True, "latency": 5000, "weight": None}
        u_normal = {"id": "u_normal", "name": "u_normal", "proto": "udp", "addr": "127.0.0.1",
                    "port": 53, "enabled": True, "latency": 5000, "weight": 2}
        # 不应抛 ValueError / TypeError
        ordered = sorted([u_bad, u_none, u_normal], key=lambda u: self._sort_key(r, u))
        # 畸形 weight 兜底为 1.0 → key=100/1=100; weight=2 → key=100/2=50
        self.assertEqual(ordered[0]["id"], "u_normal",
                         "weight=2 should rank before malformed weight (which falls back to 1.0)")
        # 畸形串与 None 都应兜底到 1.0, key 相等
        k_bad = self._sort_key(r, u_bad)
        k_none = self._sort_key(r, u_none)
        self.assertEqual(k_bad, k_none,
                         "malformed weight string and None should both fall back to 1.0")


class TestHealthCheckConcurrent(unittest.TestCase):
    """v1.9.142: 健康检查多上游并发探测, 结果喂入熔断器。"""
    def test_probes_concurrently_and_updates_breaker(self):
        import time as _time
        from unittest import mock
        ups = [_up("h1"), _up("h2"), _up("h3")]
        r = make_resolver(upstreams=ups)
        self.addCleanup(stop_instance, r)
        calls = []

        def fake_qu(u, qb, to):
            calls.append(u["id"])
            _time.sleep(0.2)
            if u["id"] == "h1":
                return True, b"resp", 1, None
            return False, None, to, "timeout"

        with mock.patch.object(resolver_mod, "query_upstream", side_effect=fake_qu):
            t0 = _time.monotonic()
            r._health_check_once()
            elapsed = _time.monotonic() - t0
        # 3 个上游一轮全部被探测
        self.assertEqual(sorted(calls), ["h1", "h2", "h3"])
        # 并发: 串行需 ~0.6s, 并发约 0.2s
        self.assertLess(elapsed, 0.45, "健康检查应并发, 不应串行累加超时")
        # h1 成功 → fails=0; h2/h3 失败 → fails=1(未达阈值 3, 熔断不打开)
        self.assertFalse(r._cb_is_open("h1"))
        self.assertFalse(r._cb_is_open("h2"))
        self.assertEqual(r._cb["h1"]["fails"], 0)
        self.assertEqual(r._cb["h2"]["fails"], 1)

    def test_rotation_probes_subset_and_advances_offset(self):
        from unittest import mock
        ups = [_up("r1"), _up("r2"), _up("r3"), _up("r4")]
        r = make_resolver(upstreams=ups)
        self.addCleanup(stop_instance, r)
        calls = []

        def fake_qu(u, qb, to):
            calls.append(u["id"])
            return True, b"x", 1, None

        with mock.patch.object(resolver_mod, "query_upstream", side_effect=fake_qu):
            r._health_check_once()
        # 4 个上游一轮只探 3 个, 轮转 offset 推进
        self.assertEqual(len(calls), 3)
        self.assertEqual(r._hc_off, 3)


if __name__ == "__main__":
    unittest.main()
