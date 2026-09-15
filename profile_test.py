#!/usr/bin/env python3
"""cProfile 性能测试脚本: 模拟混合 DNS 查询负载, 分析 resolve() 热路径。

场景:
  1. 缓存命中快路径 (answer_fast): 大量重复域名查询
  2. 规则匹配: 大量不同域名匹配分流规则
  3. 缓存操作: get/put/evict 混合
  4. dnsmsg 解析/构建: 模拟上游响应处理
"""
import sys, os, time, cProfile, pstats, io, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ebpdns import config as config_mod
from ebpdns.resolver import Resolver
from ebpdns.telemetry import Telemetry
from ebpdns import dnsmsg

# ---- 构建测试配置 ----
cfg = config_mod.load_config(None)
cfg["listen"] = {"udp": "127.0.0.1:0", "tcp": "127.0.0.1:0"}
cfg["cache_size"] = 50000
cfg["cache_policy"] = "lru"
cfg["speed_test"] = False
cfg["ipv6"] = True
cfg["prefetch"] = False
cfg["serve_stale"] = False
cfg["edns"] = True
cfg["padding"] = False
cfg["dnssec_0x20"] = False  # 测试时关闭 0x20 以获得确定性
cfg["upstreams"] = [
    {"id": "u1", "name": "Test1", "proto": "udp", "addr": "223.5.5.5", "port": 53,
     "url": "", "group": "domestic", "latency": 10, "enabled": True, "latency_measured": True},
    {"id": "u2", "name": "Test2", "proto": "udp", "addr": "119.29.29.29", "port": 53,
     "url": "", "group": "domestic", "latency": 15, "enabled": True, "latency_measured": True},
]
# 添加分流规则测试
cfg["rule_local_file"] = "/tmp/test_rules_local.json"
cfg["rule_sub_file"] = "/tmp/test_rules_sub.json"
import json as _json
os.makedirs("/tmp", exist_ok=True)
with open("/tmp/test_rules_local.json", "w") as f:
    _json.dump({"rules": [
        {"id": "r1", "match": "*.baidu.com", "action": "group", "group": "domestic"},
        {"id": "r2", "match": "*.google.com", "action": "group", "group": "global"},
        {"id": "r3", "match": "*.cn", "action": "group", "group": "domestic"},
        {"id": "r4", "match": "example.com", "action": "group", "group": "global"},
    ]}, f)
open("/tmp/test_rules_sub.json", "w").write('{"subscriptions": []}')

# ---- 构建 Resolver (不启动网络服务) ----
tel = Telemetry()
resolver = Resolver(cfg, tel, cache=None)

# ---- 准备测试域名池 ----
DOMAINS = [
    "www.baidu.com", "www.qq.com", "www.taobao.com", "www.jd.com",
    "www.google.com", "www.youtube.com", "www.facebook.com", "twitter.com",
    "mail.163.com", "smtp.126.com", "www.zhihu.com", "www.bilibili.com",
    "www.microsoft.com", "www.apple.com", "www.amazon.com", "github.com",
    "api.github.com", "docs.python.org", "pypi.org", "nodejs.org",
    "cloudflare.com", "1.1.1.1", "dns.google", "quad9.net",
    "www.openai.com", "chat.openai.com", "api.openai.com", "www.cloudflare.com",
] * 10  # 280 unique-ish domains

# ---- 预填充缓存: 模拟 5000 条缓存条目 ----
print("预填充缓存...")
for i in range(5000):
    d = "cachetest%d.example.com" % i
    key = resolver._ckey(d, "A")
    resolver.cache.put(key, {
        "domain": d, "qtype": "A",
        "answers": [{"value": "10.0.%d.%d" % (i // 256, i % 256), "from": "test", "ttl": 300, "type": 1}],
        "chosen": "10.0.%d.%d" % (i // 256, i % 256),
        "ttl": 300, "rcode": 0,
        "expires_at": time.time() + 300, "access_at": time.time(),
    })

# ---- 构建测试用 DNS 查询字节 ----
def make_query(domain, qtype="A"):
    qb, _ = dnsmsg.build_query(domain, dnsmsg.type_code(qtype), edns=True, udp_size=1232)
    return qb

print("缓存条目数: %d" % len(resolver.cache))

# ---- 场景1: answer_fast 缓存命中热路径 ----
print("\n=== 场景1: answer_fast 缓存命中 (20万次) ===")
queries = [(make_query(d), d) for d in DOMAINS[:100]]
# 预填充这些域名的缓存
for qb, d in queries:
    key = resolver._ckey(d, "A")
    resolver.cache.put(key, {
        "domain": d, "qtype": "A",
        "answers": [{"value": "1.2.3.4", "from": "test", "ttl": 300, "type": 1}],
        "chosen": "1.2.3.4",
        "ttl": 300, "rcode": 0,
        "expires_at": time.time() + 300, "access_at": time.time(),
    })

prof = cProfile.Profile()
prof.enable()
for i in range(200000):
    qb, d = queries[i % len(queries)]
    try:
        resolver.answer_fast(qb, ("127.0.0.1", 12345))
    except Exception:
        pass
prof.disable()

s = io.StringIO()
ps = pstats.Stats(prof, stream=s).sort_stats("cumulative")
ps.print_stats(25)
print(s.getvalue())

# ---- 场景2: match_rule 规则匹配 ----
print("\n=== 场景2: match_rule 规则匹配 (10万次) ===")
rule_domains = [
    "www.baidu.com", "sub.deep.baidu.com", "cdn.baidu.com",
    "www.google.com", "mail.google.com", "maps.google.com",
    "www.cn", "test.cn", "sub.test.cn",
    "example.com", "www.example.com",
    "random-site.net", "another.org", "test.io",
] * 100

prof2 = cProfile.Profile()
prof2.enable()
for i in range(100000):
    resolver.match_rule(rule_domains[i % len(rule_domains)])
prof2.disable()

s2 = io.StringIO()
ps2 = pstats.Stats(prof2, stream=s2).sort_stats("cumulative")
ps2.print_stats(20)
print(s2.getvalue())

# ---- 场景3: 缓存 get/put 混合 ----
print("\n=== 场景3: 缓存 get/put 混合 (10万次) ===")
prof3 = cProfile.Profile()
prof3.enable()
for i in range(100000):
    d = "mixed%d.example.com" % (i % 5000)
    key = resolver._ckey(d, "A")
    resolver.cache.get(key, time.time())
    if i % 5 == 0:
        resolver.cache.put(key, {
            "domain": d, "qtype": "A", "answers": [], "chosen": "",
            "ttl": 300, "rcode": 0,
            "expires_at": time.time() + 300, "access_at": time.time(),
        })
prof3.disable()

s3 = io.StringIO()
ps3 = pstats.Stats(prof3, stream=s3).sort_stats("cumulative")
ps3.print_stats(20)
print(s3.getvalue())

# ---- 场景4: dnsmsg.parse_message 解析 ----
print("\n=== 场景4: dnsmsg.parse_message 响应解析 (10万次) ===")
# 构造一个模拟的上游响应
query_bytes, qid = dnsmsg.build_query("www.baidu.com", 1, edns=True, udp_size=1232)
# 构造一个 NOERROR 响应
resp_body = dnsmsg.build_response_body("www.baidu.com", 1, [
    {"value": "180.101.50.242", "ttl": 300, "type": 1},
    {"value": "180.101.50.195", "ttl": 300, "type": 1},
])
resp = dnsmsg.build_response_header(query_bytes, 0, 2) + resp_body

prof4 = cProfile.Profile()
prof4.enable()
for i in range(100000):
    dnsmsg.parse_message(resp)
prof4.disable()

s4 = io.StringIO()
ps4 = pstats.Stats(prof4, stream=s4).sort_stats("cumulative")
ps4.print_stats(15)
print(s4.getvalue())

print("\n=== 基线测试完成 ===")
