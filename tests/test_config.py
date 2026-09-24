"""config 默认值与校验单元测试。"""

import unittest

from ebpdns import config


class TestDefaults(unittest.TestCase):
    def setUp(self):
        self.cfg = config.default_config()

    def test_ipv6_listen_default_on(self):
        self.assertEqual(self.cfg["listen"].get("udp6"), "[::1]:53")
        self.assertEqual(self.cfg["listen"].get("tcp6"), "[::1]:53")

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

    def test_upstream_malformed_items_skipped(self):
        """M1: upstreams[] 内 proto 非法/port 越界/addr 或 id 为空的项被跳过, 合法项保留。"""
        cfg = config.default_config()
        cfg["upstreams"] = [
            {"id": "keep", "proto": "udp", "addr": "1.1.1.1", "port": 53},
            {"id": "bad-proto", "proto": "ftp", "addr": "1.1.1.1", "port": 53},
            {"id": "bad-port", "proto": "udp", "addr": "1.1.1.1", "port": 99999},
            {"id": "zero-port", "proto": "udp", "addr": "1.1.1.1", "port": 0},
            {"id": "empty-addr", "proto": "udp", "addr": "   ", "port": 53},
            {"id": "", "proto": "udp", "addr": "1.1.1.1", "port": 53},
            "not-a-dict",
        ]
        config._validate_cfg(cfg)
        self.assertEqual([u.get("id") for u in cfg["upstreams"]], ["keep"])

    def test_listen_bind_port_out_of_range_falls_back(self):
        """M2: listen.udp 端口越界时回退默认绑定串, 不保留非法值。"""
        cfg = config.default_config()
        cfg["listen"]["udp"] = "0.0.0.0:99999"
        config._validate_cfg(cfg)
        self.assertEqual(cfg["listen"]["udp"], config.DEFAULTS["listen"]["udp"])

    def test_listen_bind_malformed_falls_back(self):
        """M2: listen.tcp 畸形 host:port(非数字端口) 回退默认。"""
        cfg = config.default_config()
        cfg["listen"]["tcp"] = "0.0.0.0:abc"
        config._validate_cfg(cfg)
        self.assertEqual(cfg["listen"]["tcp"], config.DEFAULTS["listen"]["tcp"])

    def test_listen_null_preserved(self):
        """M2: 显式 null(关闭某协议监听) 不被回退默认, 保持向后兼容。"""
        cfg = config.default_config()
        cfg["listen"]["udp6"] = None
        config._validate_cfg(cfg)
        self.assertIsNone(cfg["listen"]["udp6"])

    def test_ttl_min_greater_than_max_swapped(self):
        """M4: ttl_min > ttl_max 且两者均启用(非 0) 时自动交换。"""
        cfg = config.default_config()
        cfg["ttl_min"] = 600
        cfg["ttl_max"] = 100
        config._validate_cfg(cfg)
        self.assertEqual(cfg["ttl_min"], 100)
        self.assertEqual(cfg["ttl_max"], 600)

    def test_ttl_zero_limit_not_swapped(self):
        """M4: 任一为 0(不限制) 时不触发交换, 保持用户配置。"""
        cfg = config.default_config()
        cfg["ttl_min"] = 300
        cfg["ttl_max"] = 0
        config._validate_cfg(cfg)
        self.assertEqual(cfg["ttl_min"], 300)
        self.assertEqual(cfg["ttl_max"], 0)


class TestSaveConfig(unittest.TestCase):
    """C1: save_config 不得剥离用户可配的 cache_file。"""

    def test_cache_file_preserved_on_save(self):
        import json, tempfile, os
        cfg = config.default_config()
        cfg["cache_file"] = "/data/my_custom_cache.json"
        cfg["rule_sub_file"] = "/tmp/derived_sub.json"
        cfg["rule_local_file"] = "/tmp/derived_local.json"
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "config.json")
            config.save_config(cfg, path)
            with open(path) as f:
                saved = json.load(f)
        self.assertEqual(saved.get("cache_file"), "/data/my_custom_cache.json",
                         "用户手配的 cache_file 不得被 save_config 剥离")
        self.assertNotIn("rule_sub_file", saved, "纯派生的 rule_sub_file 应被剥离")
        self.assertNotIn("rule_local_file", saved, "纯派生的 rule_local_file 应被剥离")


if __name__ == "__main__":
    unittest.main()
