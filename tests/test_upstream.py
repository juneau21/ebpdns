"""上游配置校验与工具函数单元测试(无网络)。"""

import struct
import unittest
from unittest import mock

from ebpdns import upstream
from ebpdns.api import _validate_upstream_dict, _upstream_optional_fields


def _udp_up(**extra):
    u = {"id": "u1", "name": "u1", "proto": "udp", "addr": "223.5.5.5",
         "port": 53, "enabled": True, "latency": 5000}
    u.update(extra)
    return u


class TestValidateUpstream(unittest.TestCase):
    def test_valid_udp(self):
        self.assertIsNone(_validate_upstream_dict(_udp_up()))

    def test_valid_doh(self):
        u = _udp_up(proto="doh", addr="dns.google", port=443,
                    url="https://dns.google/dns-query")
        self.assertIsNone(_validate_upstream_dict(u))

    def test_bad_proto(self):
        self.assertIsNotNone(_validate_upstream_dict(_udp_up(proto="bogus")))

    def test_bad_port(self):
        self.assertIsNotNone(_validate_upstream_dict(_udp_up(port=99999)))

    def test_port_bool_rejected(self):
        self.assertIsNotNone(_validate_upstream_dict(_udp_up(port=True)))

    def test_bad_latency(self):
        self.assertIsNotNone(_validate_upstream_dict(_udp_up(latency=-1)))

    def test_bad_addr_charset(self):
        self.assertIsNotNone(_validate_upstream_dict(_udp_up(addr="1.2.3.4; rm -rf")))

    def test_bad_url_control_char(self):
        self.assertIsNotNone(_validate_upstream_dict(
            _udp_up(proto="doh", url="https://x.test/dns\n")))


class TestStrictCertSafeDefault(unittest.TestCase):
    """v1.9.141 回归: doh_strict_cert/dot_strict_cert 畸形值兜底方向改为 True
    (安全方向), 与运行时 upstream.py up.get("doh_strict_cert", True) 缺省一致。
    显式传 None(键存在但值为 null) 不应关闭严格证书校验。"""

    def test_none_value_defaults_to_true_bulk_path(self):
        """bulk 校验路径: doh_strict_cert=None → 归一为 True(安全方向)。"""
        u = _udp_up(proto="doh", addr="dns.google", port=443,
                    url="https://dns.google/dns-query", doh_strict_cert=None)
        self.assertIsNone(_validate_upstream_dict(u))
        self.assertTrue(u["doh_strict_cert"],
                        "doh_strict_cert=None should normalize to True (safe default)")

    def test_none_value_defaults_to_true_post_path(self):
        """POST _upstream_optional_fields: doh_strict_cert=None → True。"""
        fields, err = _upstream_optional_fields({"doh_strict_cert": None})
        self.assertIsNone(err)
        self.assertTrue(fields["doh_strict_cert"],
                        "doh_strict_cert=None should normalize to True in POST path")

    def test_explicit_false_still_respected(self):
        """显式传 "false" 仍应归一为 False(向后兼容, 不被默认值覆盖)。"""
        fields, err = _upstream_optional_fields({"doh_strict_cert": "false"})
        self.assertIsNone(err)
        self.assertFalse(fields["doh_strict_cert"],
                         "explicit doh_strict_cert='false' must remain False")

    def test_explicit_true_still_respected(self):
        fields, err = _upstream_optional_fields({"doh_strict_cert": "true"})
        self.assertIsNone(err)
        self.assertTrue(fields["doh_strict_cert"])

    def test_allow_private_ip_default_unchanged(self):
        """allow_private_ip 缺省 False 是安全方向(默认不过滤豁免), 不应被本次修改影响。"""
        fields, err = _upstream_optional_fields({"allow_private_ip": None})
        self.assertIsNone(err)
        self.assertFalse(fields["allow_private_ip"],
                         "allow_private_ip=None should still default to False")


class TestHostnameHelpers(unittest.TestCase):
    def test_is_hostname(self):
        self.assertTrue(upstream._is_hostname("dns.google"))
        self.assertTrue(upstream._is_hostname("localhost"))
        self.assertFalse(upstream._is_hostname("223.5.5.5"))
        self.assertFalse(upstream._is_hostname("::1"))

    def test_host_port(self):
        host, port = upstream._host_port({"addr": "1.2.3.4", "port": 5353})
        self.assertEqual(host, "1.2.3.4")
        self.assertEqual(port, 5353)


class TestDnsResolveBackpressure(unittest.TestCase):
    """UP-MED-02: _DNS_RESOLVE_POOL 队列积压时 _submit_dns_resolve 拒绝提交。"""

    def test_queue_full_returns_none_without_submit(self):
        pool = upstream._DNS_RESOLVE_POOL
        submitted = []

        def fake_submit(fn, *args):
            submitted.append(args)
            return "future"

        class _FullQueue:
            def qsize(self):
                return upstream._DNS_RESOLVE_QUEUE_LIMIT + 1

        orig_q = pool._work_queue
        orig_submit = pool.submit
        pool._work_queue = _FullQueue()
        pool.submit = fake_submit
        try:
            result = upstream._submit_dns_resolve(socket_getaddrinfo_noop, "host", None)
        finally:
            pool._work_queue = orig_q
            pool.submit = orig_submit
        # 队列积压 → 拒绝, 返回 None, 且未真正向线程池提交任务
        self.assertIsNone(result)
        self.assertEqual(submitted, [])

    def test_queue_ok_submits_future(self):
        pool = upstream._DNS_RESOLVE_POOL
        submitted = []

        def fake_submit(fn, *args):
            submitted.append(args)
            return "future-ok"

        class _EmptyQueue:
            def qsize(self):
                return 1

        orig_q = pool._work_queue
        orig_submit = pool.submit
        pool._work_queue = _EmptyQueue()
        pool.submit = fake_submit
        try:
            result = upstream._submit_dns_resolve(socket_getaddrinfo_noop, "host", 443)
        finally:
            pool._work_queue = orig_q
            pool.submit = orig_submit
        self.assertEqual(result, "future-ok")
        self.assertEqual(submitted, [("host", 443)])


def socket_getaddrinfo_noop(*args):
    return []


class TestDoHLeftoverDiscard(unittest.TestCase):
    """UP-MED-01: DoH 响应有残留未读字节(length>0)时连接被 discard 而非归还池。"""

    def _run_doh(self, resp_length):
        up = {"id": "u1", "name": "u1", "proto": "doh",
              "addr": "dns.google", "port": 443,
              "url": "https://dns.google/dns-query", "enabled": True}
        conn = mock.MagicMock()
        conn.sock = mock.MagicMock()
        conn._ebpdns_pending_bootstrap = None  # 避免触发 bootstrap 回写
        entry = object()
        resp = mock.MagicMock()
        resp.status = 200
        resp.read.return_value = b"\x00\x00\x20\x01" + b"\x00" * 16
        resp.getheader.return_value = "application/dns-message"
        resp.will_close = False
        resp.length = resp_length
        conn.getresponse.return_value = resp

        calls = []
        orig_acquire = upstream._pool.acquire
        orig_release = upstream._pool.release
        upstream._pool.acquire = lambda key, timeout: (conn, entry)
        upstream._pool.release = lambda e, c: calls.append((e, c))
        try:
            ok, body = upstream._doh_query(up, b"\x00\x00\x00\x00", 1000)
        finally:
            upstream._pool.acquire = orig_acquire
            upstream._pool.release = orig_release
        return ok, body, calls, conn, entry

    def test_leftover_bytes_discard_not_reuse(self):
        ok, body, calls, conn, entry = self._run_doh(resp_length=100)
        self.assertTrue(ok)
        # 有残留字节 → 连接被关闭, 归还时第二参数为 None(不入池复用)
        conn.close.assert_called()
        self.assertEqual(calls, [(entry, None)])
        self.assertNotIn((entry, conn), calls)

    def test_clean_response_reuse_conn(self):
        ok, body, calls, conn, entry = self._run_doh(resp_length=0)
        self.assertTrue(ok)
        # 无残留字节 → 正常归还连接(第二参数为 conn, 写回池复用)
        self.assertEqual(calls, [(entry, conn)])


class _FakeUdpSock:
    """记录 sendto 目标地址、可脚本化 recvfrom 的假 UDP socket。"""
    def __init__(self, *a, **kw):
        self.sent = []
        self.closed = False
        self.response = None
    def settimeout(self, t):
        pass
    def sendto(self, data, addr):
        self.sent.append((bytes(data), addr))
    def recvfrom(self, n):
        # 第一个 socket 可读时返回合法响应; 多 socket 路径下响应源 IP 只要落在
        # expect_ips 集合内即可通过校验。
        return self.response or (b"\x12\x34resp", ("1.1.1.1", 53))
    def close(self):
        self.closed = True


class _ErrorUdpSock(_FakeUdpSock):
    """recvfrom 抛 OSError 的假 UDP socket(模拟对端端口不可达/连接重置)。"""
    error = None
    def recvfrom(self, n):
        if self.error is not None:
            raise self.error
        return super().recvfrom(n)


class TestUdpMultiIp(unittest.TestCase):
    """P3-LOW: hostname 解析出多个 IP 时, 不再确定性只向首个 IP 发送——
    应并行向前两个 IP 各发一个 socket, 先到的合法响应获胜, 另一个被关闭。"""

    def _up(self):
        return {"id": "u1", "name": "u1", "proto": "udp",
                "addr": "dns.example.com", "port": 53, "enabled": True}

    def test_multi_ip_sends_to_both_ips_and_closes_all(self):
        up = self._up()
        qid = 0x1234
        query = struct.pack(">H", qid) + b"q"

        created = []

        def fake_socket(*a, **kw):
            s = _FakeUdpSock(*a, **kw)
            s.response = (struct.pack(">H", qid) + b"resp", ("1.1.1.1", 53))
            created.append(s)
            return s

        # select 每次都报告全部已建 socket 可读; 第一个 recvfrom 即返回合法响应
        fake_select = lambda r, w, x, t: (list(r), [], [])

        with mock.patch.object(upstream, "_cached_udp_addrs",
                               return_value=frozenset(["1.1.1.1", "2.2.2.2"])), \
             mock.patch.object(upstream.socket, "socket", fake_socket), \
             mock.patch.object(upstream.select, "select", fake_select):
            ok, data = upstream._udp_query(up, query, 1000)

        self.assertTrue(ok)
        self.assertEqual(data, struct.pack(">H", qid) + b"resp")
        # 两个 socket 都被创建并各自 sendto 了一个目标 IP
        self.assertEqual(len(created), 2)
        all_addrs = set()
        for s in created:
            self.assertEqual(len(s.sent), 1, "每个 socket 应只发送一次")
            self.assertEqual(s.sent[0][0], query)
            all_addrs.add(s.sent[0][1])
        self.assertEqual(all_addrs, {("1.1.1.1", 53), ("2.2.2.2", 53)})
        # finally 关闭全部 socket(含未响应的落选者), 无 fd 泄漏
        for s in created:
            self.assertTrue(s.closed)

    def test_single_ip_sends_only_one(self):
        up = self._up()
        qid = 0x1234
        query = struct.pack(">H", qid) + b"q"

        created = []

        def fake_socket(*a, **kw):
            s = _FakeUdpSock(*a, **kw)
            s.response = (struct.pack(">H", qid) + b"resp", ("1.1.1.1", 53))
            created.append(s)
            return s

        with mock.patch.object(upstream, "_cached_udp_addrs",
                               return_value=frozenset(["1.1.1.1"])), \
             mock.patch.object(upstream.socket, "socket", fake_socket):
            ok, data = upstream._udp_query(up, query, 1000)

        self.assertTrue(ok)
        # 单 IP 保持原逻辑: 只建一个 socket, 只发一次
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0].sent, [(query, ("1.1.1.1", 53))])
        self.assertTrue(created[0].closed)

    def test_recvfrom_error_socket_removed_and_closed(self):
        """修复1: recvfrom 抛 OSError 的 socket 必须从等待集合移除并关闭,
        否则下一轮 select 立即再次返回该 fd 形成 tight spin。"""
        up = self._up()
        qid = 0x1234
        query = struct.pack(">H", qid) + b"q"

        created = []

        def direct_socket(*a, **kw):
            s = _ErrorUdpSock(*a, **kw)
            idx = len(created)
            if idx == 0:
                # 第一个 socket: recvfrom 抛 OSError
                s.error = OSError("ECONNREFUSED")
            else:
                # 第二个 socket: 返回合法响应
                s.response = (struct.pack(">H", qid) + b"resp", ("2.2.2.2", 53))
            created.append(s)
            return s

        select_history = []
        def tracking_select(r, w, x, t):
            select_history.append(len(r))
            return (list(r), [], [])

        with mock.patch.object(upstream, "_cached_udp_addrs",
                               return_value=frozenset(["1.1.1.1", "2.2.2.2"])), \
             mock.patch.object(upstream.socket, "socket", direct_socket), \
             mock.patch.object(upstream.select, "select", tracking_select):
            ok, data = upstream._udp_query(up, query, 1000)

        self.assertTrue(ok)
        self.assertEqual(data, struct.pack(">H", qid) + b"resp")
        self.assertEqual(len(created), 2)
        # 错误 socket 必须被主动关闭(在 except OSError 分支中)
        self.assertTrue(created[0].closed, "错误 socket 应被主动关闭")
        # 成功的 socket 也应被 finally 关闭
        self.assertTrue(created[1].closed)
        # 关键: 首次 select 应看到 2 个 socket
        self.assertGreaterEqual(len(select_history), 1)
        self.assertEqual(select_history[0], 2, "首次 select 应看到 2 个 socket")
        # 错误 socket 被移除后, 若还有下一轮 select 则应只看到 1 个
        # (否则会 tight spin: 2个→2个→2个...直到 deadline)
        if len(select_history) >= 2:
            self.assertEqual(select_history[1], 1,
                             "错误 socket 移除后, 下一轮 select 应只看到 1 个 socket")


class TestQueryUpstreamErrorPassthrough(unittest.TestCase):
    """v1.9.142: doq/doh3 失败的具体原因必须透传, 不被笼统 "query failed" 覆盖。"""
    def _up(self):
        return {"proto": "doh3", "addr": "1.2.3.4", "port": 443, "url": "/dns-query"}

    def test_doh3_failure_reason_preserved(self):
        with mock.patch.object(upstream, "_quic_available", return_value=True), \
             mock.patch.object(upstream, "_quic_query_doh3",
                               return_value=(False, None, 120, "timeout")):
            ok, _data, _lat, err = upstream.query_upstream(self._up(), b"\x00", 1500)
        self.assertFalse(ok)
        self.assertEqual(err, "timeout")

    def test_doq_failure_reason_preserved(self):
        up = self._up(); up["proto"] = "doq"
        with mock.patch.object(upstream, "_quic_available", return_value=True), \
             mock.patch.object(upstream, "_quic_query_doq",
                               return_value=(False, None, 80, "connection refused")):
            ok, _data, _lat, err = upstream.query_upstream(up, b"\x00", 1500)
        self.assertFalse(ok)
        self.assertEqual(err, "connection refused")

    def test_empty_reason_falls_back_to_query_failed(self):
        with mock.patch.object(upstream, "_quic_available", return_value=True), \
             mock.patch.object(upstream, "_quic_query_doh3",
                               return_value=(False, None, 5, "")):
            ok, _data, _lat, err = upstream.query_upstream(self._up(), b"\x00", 1500)
        self.assertFalse(ok)
        self.assertEqual(err, "query failed")

    def test_aioquic_missing_message(self):
        with mock.patch.object(upstream, "_quic_available", return_value=False):
            ok, _data, _lat, err = upstream.query_upstream(self._up(), b"\x00", 1500)
        self.assertFalse(ok)
        self.assertIn("aioquic", err)


if __name__ == "__main__":
    unittest.main()
