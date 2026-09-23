"""上游配置校验与工具函数单元测试(无网络)。"""

import unittest

from ebpdns import upstream
from ebpdns.api import _validate_upstream_dict


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


if __name__ == "__main__":
    unittest.main()
