#!/usr/bin/env python3
"""R49 P3-1 功能验证: 环回绑定下 Origin/Referer 无显式端口(localhost:80 场景)
端口对称校验不再被跳过。

修复前: Origin=http://localhost (oport=None) 时 `oport is not None and ...` 整体跳过
        端口比较 → 本机 80 端口被攻陷后可 CSRF 127.0.0.1:8080 管理口。
修复后: oport=None 按 scheme 归一为 80(http)/443(https) 再与 configured_port 比较。
"""
import sys, types
sys.path.insert(0, "/home/user/.super_doubao/super-doubao-runtime/workspace/ebpdns-v1931")
from ebpdns.api import _Handler

def make_handler(cfg_host, cfg_port, headers):
    h = _Handler.__new__(_Handler)
    h.server = types.SimpleNamespace(app=types.SimpleNamespace(
        cfg={"api": {"host": cfg_host, "port": cfg_port}}))
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

print("== 目标场景: 绑定 127.0.0.1:8080, Origin=http://localhost (无端口, 默认 80) ==")
# 修复前: oport=None → 端口比较跳过 → 返回 True(放行, 漏洞)
# 修复后: oport 归一为 80, 80 != 8080 → 拒绝
check("Origin=http://localhost (无端口, 应拒绝)",
      make_handler("127.0.0.1", 8080, {"Host": "127.0.0.1:8080",
                                        "Origin": "http://localhost"})._csrf_ok(), False)
check("Referer=http://localhost/ (无端口, 应拒绝)",
      make_handler("127.0.0.1", 8080, {"Host": "127.0.0.1:8080",
                                        "Referer": "http://localhost/"})._csrf_ok(), False)

print("== 合法访问必须仍放行 (回归) ==")
check("Origin=http://localhost:8080 (应放行)",
      make_handler("127.0.0.1", 8080, {"Host": "127.0.0.1:8080",
                                        "Origin": "http://localhost:8080"})._csrf_ok(), True)
check("Referer=http://localhost:8080/ (应放行)",
      make_handler("127.0.0.1", 8080, {"Host": "127.0.0.1:8080",
                                        "Referer": "http://localhost:8080/"})._csrf_ok(), True)
check("Origin=http://127.0.0.1:8080 (应放行, R48 回归)",
      make_handler("127.0.0.1", 8080, {"Host": "127.0.0.1:8080",
                                        "Origin": "http://127.0.0.1:8080"})._csrf_ok(), True)

print("== https 归一: scheme=https 时缺省端口应为 443 ==")
check("Origin=https://localhost (无端口, 归一 443 != 8080, 应拒绝)",
      make_handler("127.0.0.1", 8080, {"Host": "127.0.0.1:8080",
                                        "Origin": "https://localhost"})._csrf_ok(), False)
# 若 API 本身监听 443(https 管理口), localhost 无端口应放行
check("Origin=https://localhost (绑定 443, 归一 443==443, 应放行)",
      make_handler("127.0.0.1", 443, {"Host": "127.0.0.1",
                                       "Origin": "https://localhost"})._csrf_ok(), True)

print("== 其他回归: 跨源/非环回 Host 仍被拒 ==")
check("Origin=evil.ddns.net:8080 (应拒绝)",
      make_handler("127.0.0.1", 8080, {"Host": "127.0.0.1:8080",
                                        "Origin": "http://evil.ddns.net:8080"})._csrf_ok(), False)
check("Host=evil.ddns.net:8080 (纵深, 应拒绝)",
      make_handler("127.0.0.1", 8080, {"Host": "evil.ddns.net:8080",
                                        "Origin": "http://evil.ddns.net:8080"})._csrf_ok(), False)

print()
print(f"RESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
