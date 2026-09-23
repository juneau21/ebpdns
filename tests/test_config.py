"""config 默认值与校验单元测试。"""

import unittest

from ebpdns import config


class TestDefaults(unittest.TestCase):
    def setUp(self):
        self.cfg = config.default_config()

    def test_ipv6_listen_default_on(self):
        self.assertEqual(self.cfg["listen"].get("udp6"), "[::]:53")
        self.assertEqual(self.cfg["listen"].get("tcp6"), "[::]:53")

    def test_edns_client_max_size(self):
        self.assertEqual(self.cfg.get("edns_client_max_size"), 1232)

    def test_persist_ttl_range(self):
        lo, hi = config._NUM_RANGES["persist_ttl"]
        self.assertEqual(lo, 0)
        self.assertEqual(hi, 31_536_000)

    def test_all_base_latencies_5000(self):
        lats = {u.get("latency") for u in self.cfg["upstreams"]}
        self.assertEqual(lats, {5000})


class TestValidation(unittest.TestCase):
    def test_defaults_pass_validation(self):
        cfg = config.default_config()
        config._validate_cfg(cfg)
        self.assertEqual(cfg["persist_ttl"], config.DEFAULTS["persist_ttl"])
        self.assertEqual(cfg["edns_client_max_size"], 1232)

    def test_persist_ttl_over_year_falls_back(self):
        cfg = config.default_config()
        default = cfg["persist_ttl"]
        cfg["persist_ttl"] = 40_000_000
        config._validate_cfg(cfg)
        self.assertEqual(cfg["persist_ttl"], default)

    def test_persist_ttl_year_accepted(self):
        cfg = config.default_config()
        cfg["persist_ttl"] = 31_536_000
        config._validate_cfg(cfg)
        self.assertEqual(cfg["persist_ttl"], 31_536_000)

    def test_edns_bufsize_out_of_range_falls_back(self):
        cfg = config.default_config()
        cfg["edns_client_max_size"] = 100
        config._validate_cfg(cfg)
        self.assertEqual(cfg["edns_client_max_size"], 1232)


if __name__ == "__main__":
    unittest.main()
