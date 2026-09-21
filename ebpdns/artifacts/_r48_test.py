#!/usr/bin/env python3
"""R48 P2-1 功能验证: _csrf_ok 对三种绑定地址形态的写操作判定。"""
import sys, types
sys.path.insert(0, "/home/user/.super_doubao/super-doubao-runtime/workspace/ebpdns-v1931")
from ebpdns import api as api_mod
from ebpdns.api import _Handler

def make_handler(cfg_host, headers):
    h = _Handler.__new__(_Handler)
    h.server = types.SimpleNamespace(app=types.SimpleNamespace(
        cfg={"api": {"host": cfg_host, "port": 8080}}))
    h.headers = headers
    h.path = "/api/upstreams"
    h.command = "POST"
    return h

PASS, FAIL = 0, 0
def check(name, got, expect):
    global PASS, FAIL
    ok = (got == expect)
    PASS += ok; FAIL += (not ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}: csrf_ok={got} (expect {expect})")

print("== 场景1: 绑定具体 LAN IP 192.168.1.10 (修复目标) ==")
# 正常浏览器写操作: Origin == Host == 192.168.1.10:8080
check("LAN IP + 同源 Origin (应放行)",
      make_handler("192.168.1.10", {"Host": "192.168.1.10:8080",
                                    "Origin": "http://192.168.1.10:8080"})._csrf_ok(), True)
check("LAN IP + 同源 Referer (应放行)",
      make_handler("192.168.1.10", {"Host": "192.168.1.10:8080",
                                    "Referer": "http://192.168.1.10:8080/"})._csrf_ok(), True)
# 跨源攻击: Origin 指向恶意主机
check("LAN IP + 跨源 Origin evil.ddns.net (应拒绝)",
      make_handler("192.168.1.10", {"Host": "192.168.1.10:8080",
                                    "Origin": "http://evil.ddns.net:8080"})._csrf_ok(), False)

print("== 场景2: 绑定环回 127.0.0.1 (原行为必须保持) ==")
# 正常环回访问
check("Loopback + Origin localhost (应放行)",
      make_handler("127.0.0.1", {"Host": "127.0.0.1:8080",
                                  "Origin": "http://127.0.0.1:8080"})._csrf_ok(), True)
# 纵深: Host 头里出现非环回 hostname 必须被拒
check("Loopback 绑定 + Host 头 evil.ddns.net (应拒绝)",
      make_handler("127.0.0.1", {"Host": "evil.ddns.net:8080",
                                "Origin": "http://evil.ddns.net:8080"})._csrf_ok(), False)
# 跨源 Origin
check("Loopback + 跨源 Origin (应拒绝)",
      make_handler("127.0.0.1", {"Host": "127.0.0.1:8080",
                                  "Origin": "http://evil.ddns.net:8080"})._csrf_ok(), False)

print("== 场景3: 绑定通配 0.0.0.0 (lan_mode, 应保持) ==")
check("Wildcard + 同源 LAN Origin (应放行)",
      make_handler("0.0.0.0", {"Host": "192.168.1.10:8080",
                               "Origin": "http://192.168.1.10:8080"})._csrf_ok(), True)
check("Wildcard + 公网域名 Origin (应拒绝)",
      make_handler("0.0.0.0", {"Host": "evil.ddns.net:8080",
                                "Origin": "http://evil.ddns.net:8080"})._csrf_ok(), False)

print()
print(f"RESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
