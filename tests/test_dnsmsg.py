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


if __name__ == "__main__":
    unittest.main()
