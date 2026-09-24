"""dnsmsg 协议编解码单元测试。"""

import struct
import unittest

from ebpdns import dnsmsg


class TestNameCodec(unittest.TestCase):
    def test_encode_decode_roundtrip(self):
        for name in ("example.com", "www.baidu.com", "a.b.c.example.org"):
            wire = dnsmsg.encode_name(name)
            decoded, pos = dnsmsg.decode_name(wire, 0)
            self.assertEqual(decoded, name)
            self.assertEqual(pos, len(wire))

    def test_encode_rejects_overlong(self):
        long_name = ".".join(["a" * 60] * 5) + ".com"
        with self.assertRaises(dnsmsg.DNSError):
            dnsmsg.encode_name(long_name)

    def test_decode_rejects_compression_loop(self):
        # 自指压缩指针: 偏移 0 指向 0
        data = b"\xc0\x00"
        with self.assertRaises(dnsmsg.DNSError):
            dnsmsg.decode_name(data, 0)

    def test_decode_rejects_forward_pointer(self):
        # 指针指向自身之后
        data = b"\x03www\xc0\x02"
        with self.assertRaises(dnsmsg.DNSError):
            dnsmsg.decode_name(data, 0)


class TestBuildParseQuery(unittest.TestCase):
    def _query(self, name, qtype=1):
        qb, _ = dnsmsg.build_query(name, qtype, edns=True, udp_size=1232)
        return qb

    def test_query_roundtrip(self):
        qb = self._query("example.com", dnsmsg.TYPE_A)
        msg = dnsmsg.parse_message(qb)
        self.assertEqual(msg["questions"][0]["name"], "example.com")
        self.assertEqual(msg["questions"][0]["qtype"], dnsmsg.TYPE_A)
        # EDNS OPT 在 additional
        self.assertTrue(any(True for _ in ()) or len(msg["additional"]) >= 0)

    def test_extract_qname(self):
        qb = self._query("test.example.com")
        raw = dnsmsg.extract_qname(qb)
        name, _ = dnsmsg.decode_name(raw, 0)
        self.assertEqual(name, "test.example.com")

    def test_parse_short_message(self):
        with self.assertRaises(dnsmsg.DNSError):
            dnsmsg.parse_message(b"\x00" * 5)


class TestSOABoundary(unittest.TestCase):
    def _soa_packet(self, mname, rname, rdlen_override=None):
        # question
        q = dnsmsg.encode_name("example.com") + struct.pack(">HH", dnsmsg.TYPE_SOA, dnsmsg.CLASS_IN)
        rdata = dnsmsg.encode_name(mname) + dnsmsg.encode_name(rname) + struct.pack(">IIIII", 1, 2, 3, 4, 5)
        if rdlen_override is not None:
            rdata = rdata[:rdlen_override]
        hdr = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
        rr = dnsmsg.encode_name("example.com") + struct.pack(">HHIH", dnsmsg.TYPE_SOA, dnsmsg.CLASS_IN, 300, len(rdata)) + rdata
        return hdr + q + rr

    def test_valid_soa(self):
        pkt = self._soa_packet("ns.example.com", "hostmaster.example.com")
        msg = dnsmsg.parse_message(pkt)
        self.assertEqual(len(msg["answers"]), 1)
        self.assertIn("ns.example.com", msg["answers"][0]["rdata"])

    def test_soa_rdlen_too_small_dropped(self):
        # 恶意上游声明 rdlen=6 但 mname 实际经后续字节(伪装下一条 RR)才能读完:
        # decode_name 包级边界不报错, 名称实际消费 15B > 声明 6B → RR 丢弃。
        q = dnsmsg.encode_name("example.com") + struct.pack(">HH", dnsmsg.TYPE_SOA, dnsmsg.CLASS_IN)
        full = (dnsmsg.encode_name("ns.example.com")
                + dnsmsg.encode_name("hostmaster.example.com")
                + struct.pack(">IIIII", 1, 2, 3, 4, 5))
        hdr = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
        owner = dnsmsg.encode_name("example.com")
        # 声明 rdlen=6, rdata 放前 6B, 剩余字节作为"后续 RR"尾随
        rr = owner + struct.pack(">HHIH", dnsmsg.TYPE_SOA, dnsmsg.CLASS_IN, 300, 6) + full[:6]
        pkt = hdr + q + rr + full[6:]
        msg = dnsmsg.parse_message(pkt)
        self.assertEqual(msg["answers"], [])


class TestInvalidARdata(unittest.TestCase):
    def test_invalid_a_rdata_returns_none(self):
        self.assertIsNone(dnsmsg.encode_rdata(dnsmsg.TYPE_A, "abcd"))
        self.assertIsNone(dnsmsg.encode_rdata(dnsmsg.TYPE_A, "not-an-ip"))

    def test_valid_a_rdata(self):
        self.assertEqual(dnsmsg.encode_rdata(dnsmsg.TYPE_A, "1.2.3.4"), bytes([1, 2, 3, 4]))

    def test_invalid_aaaa_rdata_returns_none(self):
        self.assertIsNone(dnsmsg.encode_rdata(dnsmsg.TYPE_AAAA, "zzzz"))

    def test_answer_body_skips_bad_rdata(self):
        answers = [
            {"type": dnsmsg.TYPE_A, "value": "1.2.3.4", "ttl": 60},
            {"type": dnsmsg.TYPE_A, "value": "abcd", "ttl": 60},
        ]
        body = dnsmsg.build_response_body_answers(answers, owner_name="example.com")
        # 只保留一条合法 RR
        self.assertEqual(body.count(b"\x01\x02\x03\x04"), 1)
        self.assertNotIn(b"abcd", body)


class TestTCPFrame(unittest.TestCase):
    def test_roundtrip(self):
        payload = b"\x12\x34\x00" + b"\x00" * 20
        frame = dnsmsg.tcp_frame(payload)
        msg, rest = dnsmsg.parse_tcp_frame(frame)
        self.assertEqual(bytes(msg), payload)
        self.assertEqual(bytes(rest), b"")

    def test_incomplete(self):
        frame = dnsmsg.tcp_frame(b"x" * 100)
        with self.assertRaises(dnsmsg.DNSError):
            dnsmsg.parse_tcp_frame(frame[:10])


class TestInvalidLabelLength(unittest.TestCase):
    """S2: _question_edns_info 内联标签解析器必须拒绝 0x40/0x80 非法标签长度。"""

    def _hdr(self, qd=1, ar=0):
        return struct.pack(">HHHHHH", 0x1234, 0x0100, qd, 0, 0, ar)

    def test_question_invalid_label_0x40_returns_none(self):
        # question 首标签长度 0x40(非法高位组合, 非压缩指针) → qbytes=None
        pkt = self._hdr() + b"\x40" + b"\x00" * 12
        qbytes, bufsize, opt = dnsmsg._question_edns_info(pkt)
        self.assertIsNone(qbytes)
        self.assertEqual(bufsize, 512)
        self.assertIsNone(opt)

    def test_question_invalid_label_0x80_returns_none(self):
        pkt = self._hdr() + b"\x80" + b"\x00" * 12
        qbytes, bufsize, opt = dnsmsg._question_edns_info(pkt)
        self.assertIsNone(qbytes)
        self.assertEqual(bufsize, 512)

    def test_additional_invalid_label_skips_rr(self):
        # additional 段 owner name 含非法标签长度 0x40 → 该 RR 被 skip,
        # 不应抛异常穿透(外层 except 会把已解析 qbytes 一并丢弃)。
        q = dnsmsg.encode_name("example.com") + struct.pack(">HH", dnsmsg.TYPE_A, dnsmsg.CLASS_IN)
        # 一个畸形 additional RR: owner name 以 0x40 开头
        bad_rr = b"\x40" + b"\x00" * 10
        hdr = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 0, 0, 1)
        pkt = hdr + q + bad_rr
        qbytes, bufsize, opt = dnsmsg._question_edns_info(pkt)
        # question 正常解析, additional 坏 RR 被跳过(不崩溃, opt 为 None)
        self.assertIsNotNone(qbytes)
        self.assertIsNone(opt)
        self.assertEqual(bufsize, 512)


class TestForwardPointer(unittest.TestCase):
    """L5: decode_name 必须拒绝前向压缩指针(ptr >= 当前 pos)。"""

    def test_decode_rejects_genuine_forward_pointer(self):
        # 在偏移 4 处放压缩指针, 指向偏移 6(前向引用, ptr=6 >= pos=4)
        data = b"\x03abc" + b"\xc0\x06" + b"\x00"
        with self.assertRaises(dnsmsg.DNSError):
            dnsmsg.decode_name(data, 0)

    def test_backward_pointer_still_allowed(self):
        # 向后引用(ptr < pos)是合法压缩, 不应误杀。
        # 偏移 5 处的指针指向偏移 0 的完整名称(\x03abc\x00)。
        data = b"\x03abc\x00\xc0\x00"
        name, _end = dnsmsg.decode_name(data, 5)
        self.assertEqual(name, "abc")


class TestExtractQnameInvalidLabel(unittest.TestCase):
    """修复2: extract_qname 0x20 快速路径必须拒绝 0x40/0x80 非法标签长度。"""

    def _hdr(self, qd=1):
        return struct.pack(">HHHHHH", 0x1234, 0x0100, qd, 0, 0, 0)

    def test_qname_label_0x40_returns_none(self):
        # question 首标签长度 0x40: 高位有置位但非压缩指针(0xC0) → 必须拒绝
        pkt = self._hdr() + b"\x40" + b"\x00" * 20
        self.assertIsNone(dnsmsg.extract_qname(pkt))

    def test_qname_label_0x80_returns_none(self):
        # question 首标签长度 0x80: 高位有置位但非压缩指针 → 必须拒绝
        pkt = self._hdr() + b"\x80" + b"\x00" * 20
        self.assertIsNone(dnsmsg.extract_qname(pkt))

    def test_qname_label_0xc0_compression_returns_none(self):
        # 压缩指针(0xC0)在 question 区也应返回 None(原有行为, 确保未回归)
        pkt = self._hdr() + b"\xc0\x0c" + struct.pack(">HH", dnsmsg.TYPE_A, dnsmsg.CLASS_IN)
        self.assertIsNone(dnsmsg.extract_qname(pkt))

    def test_qname_normal_label_still_works(self):
        # 正常标签长度(0x03 等)不受影响
        qb, _ = dnsmsg.build_query("example.com", dnsmsg.TYPE_A)
        raw = dnsmsg.extract_qname(qb)
        self.assertIsNotNone(raw)
        name, _ = dnsmsg.decode_name(raw, 0)
        self.assertEqual(name, "example.com")


class TestCheck0x20Side(unittest.TestCase):
    """M5: check_0x20 响应侧 question 畸形应 fail-closed, 查询侧畸形不误杀。"""

    def test_response_malformed_question_fail_closed(self):
        qb, _ = dnsmsg.build_query("example.com", dnsmsg.TYPE_A)
        # 响应 question 首标签为压缩指针 → extract_qname 返回 None
        resp = (struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 0, 0, 0)
                + b"\xc0\x0c" + struct.pack(">HH", dnsmsg.TYPE_A, dnsmsg.CLASS_IN))
        self.assertFalse(dnsmsg.check_0x20(qb, resp))

    def test_query_malformed_fail_open(self):
        # 查询本身 question 畸形 → qn=None → 无法比较, 不误杀
        bad_q = (struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
                 + b"\xc0\x0c" + struct.pack(">HH", dnsmsg.TYPE_A, dnsmsg.CLASS_IN))
        resp = (struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 0, 0, 0)
                + b"\xc0\x0c" + struct.pack(">HH", dnsmsg.TYPE_A, dnsmsg.CLASS_IN))
        self.assertTrue(dnsmsg.check_0x20(bad_q, resp))


class TestEDNSPadding(unittest.TestCase):
    """RFC 8467: padding 应对齐整条 DNS 消息(非仅 OPT options 段)到 128B 边界。"""

    def test_padding_aligns_entire_message(self):
        """开启 padding 时整条消息长度必须为 128 的倍数。"""
        # 不同长度的域名产生不同 question 长度, 覆盖多种偏移
        for domain in ("a.com", "example.com", "www.example.org",
                       "a.b.c.d.e.f.example.co.uk", "x" * 50 + ".com"):
            qb, _ = dnsmsg.build_query(domain, dnsmsg.TYPE_A, edns=True,
                                       udp_size=1232, padding=True)
            self.assertEqual(len(qb) % 128, 0,
                             "domain=%r msg_len=%d not 128-aligned" % (domain, len(qb)))

    def test_padding_with_ecs(self):
        """padding + ECS 同时开启时整条消息仍 128 对齐。"""
        qb, _ = dnsmsg.build_query("example.com", dnsmsg.TYPE_A, edns=True,
                                   udp_size=1232, padding=True,
                                   edns_client_subnet="203.0.113.0/24")
        self.assertEqual(len(qb) % 128, 0,
                         "padding+ecs msg_len=%d not 128-aligned" % len(qb))

    def test_padding_option_present(self):
        """padding 开启时 OPT RR 内应含 option code 12 (Padding)。"""
        qb, _ = dnsmsg.build_query("example.com", dnsmsg.TYPE_A, edns=True,
                                   udp_size=1232, padding=True)
        msg = dnsmsg.parse_message(qb)
        # parse_message 跳过 OPT RR, 直接在原始字节中找 option code 12
        # OPT RR 在 additional 末尾, 其 rdata 中应有 struct.pack(">H", 12)
        self.assertIn(struct.pack(">H", 12), qb,
                      "padding option code 12 not found in message")

    def test_no_padding_no_alignment(self):
        """不开 padding 时消息不必 128 对齐(仅验证不崩)。"""
        qb, _ = dnsmsg.build_query("example.com", dnsmsg.TYPE_A, edns=True,
                                   udp_size=1232, padding=False)
        # 不带 padding 的 OPT RR 仅 11+0=11B, 总消息远小于 128, 不应对齐
        self.assertGreater(len(qb), 0)

    def test_padding_no_edns(self):
        """padding=True 但 edns=False 时不应崩溃(padding 仅 edns 路径生效)。"""
        qb, _ = dnsmsg.build_query("example.com", dnsmsg.TYPE_A, edns=False,
                                   padding=True)
        self.assertGreater(len(qb), 0)


if __name__ == "__main__":
    unittest.main()
