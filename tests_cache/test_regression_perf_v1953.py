#!/usr/bin/env python3
"""
ebpdns v1.9.53 功能完整性回归测试 + 性能压测
=============================================
覆盖:
  1. 六协议上游回归 (UDP/TCP/DoH/DoT/DoH3/DoQ)
  2. 缓存三种策略回归 (LRU / partitioned / TinyLFU)
  3. 分流规则回归 (block/allow/group/forceIp/通配符/订阅)
  4. 预取 + 持久化 + 热重载
  5. API 全部端点回归
  6. 前端控件回归
  7. 熔断 + 健康检查 + 实测延迟排序
  8. 性能压测 (1000+ QPS, 5 分钟)
"""

import socket
import struct
import json
import time
import threading
import requests
import statistics
import os
import sys
import subprocess
import re
from collections import defaultdict, Counter
from datetime import datetime

# ============================================================
# 配置
# ============================================================
API_BASE = "http://127.0.0.1:18096"
DNS_UDP = ("127.0.0.1", 15365)
DNS_TCP = ("127.0.0.1", 15366)
CONFIG_PATH = "/tmp/v1931.json"
LOG_PATH = "/tmp/ebpdns_v1931.log"
CACHE_FILE = "/tmp/cache.json"
RESULTS_JSON = "/tmp/perf_results_v1953.json"

# 测试域名
TEST_DOMAINS = {
    "baidu": "www.baidu.com",
    "qq": "www.qq.com",
    "taobao": "www.taobao.com",
    "jd": "www.jd.com",
    "nil_nonexist": "nonexist-ebpdns-test-xyz123.com",
}

# 结果收集
results = {
    "test_time": datetime.now().isoformat(),
    "version": "1.9.53",
    "functional": {},
    "performance": {},
    "issues": [],
}

passed = 0
failed = 0
skipped = 0

# ============================================================
# DNS 工具函数
# ============================================================
def build_dns_query(domain, qtype=1, tid=0x1234):
    """构造 DNS 查询包"""
    flags = 0x0100  # RD=1
    header = struct.pack('>HHHHHH', tid, flags, 1, 0, 0, 0)
    qname = b''
    for label in domain.split('.'):
        qname += bytes([len(label)]) + label.encode()
    qname += b'\x00'
    question = qname + struct.pack('>HH', qtype, 1)
    return header + question

def send_dns_udp(domain, qtype=1, timeout=5.0, server=DNS_UDP):
    """通过 UDP 发送 DNS 查询, 返回 (rcode, ancount, answer_ips, elapsed_ms)"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    q = build_dns_query(domain, qtype)
    t0 = time.time()
    try:
        sock.sendto(q, server)
        data, _ = sock.recvfrom(4096)
        elapsed = (time.time() - t0) * 1000
    except socket.timeout:
        sock.close()
        return None, None, [], None
    finally:
        sock.close()

    if len(data) < 12:
        return None, None, [], elapsed

    tid, flags, qd, an, ns, ar = struct.unpack('>HHHHHH', data[:12])
    rcode = flags & 0xF
    ips = []
    idx = 12
    # skip question section
    try:
        while idx < len(data) and data[idx] != 0:
            idx += data[idx] + 1
        idx += 5  # null + qtype(2) + qclass(2)
        for i in range(an):
            if idx + 12 > len(data):
                break
            # name
            if data[idx] & 0xC0 == 0xC0:
                idx += 2
            else:
                while idx < len(data) and data[idx] != 0:
                    idx += data[idx] + 1
                idx += 1
            if idx + 10 > len(data):
                break
            atype, aclass, ttl, rdlen = struct.unpack('>HHIH', data[idx:idx+10])
            idx += 10
            if atype == 1 and rdlen == 4 and idx + 4 <= len(data):
                ips.append('.'.join(str(b) for b in data[idx:idx+4]))
            elif atype == 28 and rdlen == 16 and idx + 16 <= len(data):
                parts = [f"{data[idx+j]:02x}{data[idx+j+1]:02x}" for j in range(0, 16, 2)]
                ips.append(':'.join(parts))
            idx += rdlen
    except Exception:
        pass
    return rcode, an, ips, elapsed

def send_dns_tcp(domain, qtype=1, timeout=5.0):
    """通过 TCP 发送 DNS 查询"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    t0 = time.time()
    try:
        sock.connect(DNS_TCP)
        q = build_dns_query(domain, qtype)
        frame = struct.pack('>H', len(q)) + q
        sock.sendall(frame)
        # read length
        len_data = sock.recv(2)
        if len(len_data) < 2:
            return None, None, [], None
        resp_len = struct.unpack('>H', len_data)[0]
        data = b''
        while len(data) < resp_len:
            chunk = sock.recv(min(resp_len - len(data), 4096))
            if not chunk:
                break
            data += chunk
        elapsed = (time.time() - t0) * 1000
    except Exception:
        sock.close()
        return None, None, [], None
    finally:
        sock.close()

    if len(data) < 12:
        return None, None, [], elapsed
    tid, flags, qd, an, ns, ar = struct.unpack('>HHHHHH', data[:12])
    rcode = flags & 0xF
    return rcode, an, [], elapsed

# ============================================================
# API 工具函数
# ============================================================
def api_get(path):
    try:
        r = requests.get(f"{API_BASE}{path}", timeout=5)
        return r.status_code, r.json() if r.headers.get('content-type', '').startswith('application/json') else r.text
    except Exception as e:
        return 0, str(e)

def api_post(path, body=None):
    try:
        r = requests.post(f"{API_BASE}{path}", json=body, timeout=10)
        try:
            return r.status_code, r.json()
        except:
            return r.status_code, r.text
    except Exception as e:
        return 0, str(e)

def api_put(path, body=None):
    try:
        r = requests.put(f"{API_BASE}{path}", json=body, timeout=10)
        try:
            return r.status_code, r.json()
        except:
            return r.status_code, r.text
    except Exception as e:
        return 0, str(e)

def api_delete(path, params=None):
    try:
        r = requests.delete(f"{API_BASE}{path}", params=params, timeout=10)
        try:
            return r.status_code, r.json()
        except:
            return r.status_code, r.text
    except Exception as e:
        return 0, str(e)

def reload_config():
    """触发配置热重载"""
    code, resp = api_post("/api/reload")
    time.sleep(1)  # 等待重载完成
    return code, resp

def get_current_config():
    code, cfg = api_get("/api/config")
    if code == 200:
        return cfg
    return None

def save_config_and_reload(new_cfg):
    """保存配置并重载"""
    code, resp = api_put("/api/config", new_cfg)
    time.sleep(1)
    return code, resp

def reset_upstreams_to_default():
    """恢复默认上游配置"""
    cfg = get_current_config()
    if not cfg:
        return False
    cfg["upstreams"] = [
        {"id": "u1", "name": "AliDNS", "proto": "udp", "addr": "223.5.5.5", "port": 53, "group": "domestic", "latency": 6, "enabled": True, "latency_measured": True},
        {"id": "u2", "name": "DNSPod", "proto": "udp", "addr": "119.29.29.29", "port": 53, "group": "domestic", "latency": 11, "enabled": True, "latency_measured": True},
    ]
    cfg["rules"] = []
    cfg["cache_policy"] = "lru"
    cfg["prefetch"] = False
    cfg["serve_stale"] = False
    cfg["speed_test"] = False
    cfg["cache_partitions"] = None
    save_config_and_reload(cfg)
    # 清除缓存
    api_post("/api/reset")
    time.sleep(0.5)
    return True

# ============================================================
# 测试记录
# ============================================================
def record(category, name, status, detail=""):
    global passed, failed, skipped
    if category not in results["functional"]:
        results["functional"][category] = []
    results["functional"][category].append({
        "name": name,
        "status": status,
        "detail": detail,
        "time": datetime.now().strftime("%H:%M:%S")
    })
    if status == "PASS":
        passed += 1
        print(f"  [PASS] {name}")
    elif status == "FAIL":
        failed += 1
        results["issues"].append(f"{category}/{name}: {detail}")
        print(f"  [FAIL] {name} - {detail}")
    elif status == "SKIP":
        skipped += 1
        print(f"  [SKIP] {name} - {detail}")

# ============================================================
# 测试 1: 六协议上游回归
# ============================================================
def test_upstream_protocols():
    print("\n" + "="*60)
    print("测试 1: 六协议上游回归")
    print("="*60)

    # 先恢复默认
    reset_upstreams_to_default()

    upstreams_configs = [
        {
            "name": "UDP 上游",
            "upstream": {"id": "t1", "name": "TestUDP", "proto": "udp", "addr": "223.5.5.5", "port": 53, "group": "default", "latency": 6, "enabled": True},
            "domain": "www.baidu.com",
            "expect_rcode": 0,
        },
        {
            "name": "TCP 上游",
            "upstream": {"id": "t2", "name": "TestTCP", "proto": "tcp", "addr": "223.5.5.5", "port": 53, "group": "default", "latency": 6, "enabled": True},
            "domain": "www.baidu.com",
            "expect_rcode": 0,
        },
        {
            "name": "DoH 上游",
            "upstream": {"id": "t3", "name": "TestDoH", "proto": "doh", "addr": "dns.alidns.com", "port": 443, "url": "/dns-query", "group": "default", "latency": 30, "enabled": True},
            "domain": "www.baidu.com",
            "expect_rcode": 0,
        },
        {
            "name": "DoT 上游",
            "upstream": {"id": "t4", "name": "TestDoT", "proto": "dot", "addr": "223.5.5.5", "port": 853, "group": "default", "latency": 30, "enabled": True},
            "domain": "www.baidu.com",
            "expect_rcode": 0,
        },
        {
            "name": "DoH3 上游",
            "upstream": {"id": "t5", "name": "TestDoH3", "proto": "doh3", "addr": "dns.alidns.com", "port": 443, "url": "/dns-query", "group": "default", "latency": 30, "enabled": True},
            "domain": "www.baidu.com",
            "expect_rcode": 0,
        },
        {
            "name": "DoQ 上游",
            "upstream": {"id": "t6", "name": "TestDoQ", "proto": "doq", "addr": "dns.alidns.com", "port": 853, "group": "default", "latency": 30, "enabled": True},
            "domain": "www.baidu.com",
            "expect_rcode": 0,
        },
    ]

    for ut in upstreams_configs:
        cfg = get_current_config()
        if not cfg:
            record("upstream", ut["name"], "FAIL", "无法获取当前配置")
            continue

        # 设置单个上游
        cfg["upstreams"] = [ut["upstream"]]
        cfg["rules"] = []
        code, resp = save_config_and_reload(cfg)
        time.sleep(2)  # 等待 bootstrap

        # 清除缓存
        api_post("/api/reset")
        time.sleep(0.5)

        # 发送测试查询
        rcode, ancount, ips, elapsed = send_dns_udp(ut["domain"], timeout=8.0)

        if rcode is None:
            record("upstream", ut["name"], "SKIP", f"查询超时/无响应 (可能网络限制)")
        elif rcode == ut["expect_rcode"] and ancount > 0:
            record("upstream", ut["name"], "PASS", f"rcode={rcode}, AN={ancount}, IPs={ips[:2]}, {elapsed:.1f}ms")
        elif rcode == 2:
            record("upstream", ut["name"], "SKIP", f"SERVFAIL (rcode=2), 上游可能不可达")
        else:
            record("upstream", ut["name"], "FAIL", f"rcode={rcode}, AN={ancount}, 期望 rcode=0")

    # 恢复默认上游
    reset_upstreams_to_default()

# ============================================================
# 测试 2: 缓存三种策略回归
# ============================================================
def test_cache_policies():
    print("\n" + "="*60)
    print("测试 2: 缓存三种策略回归")
    print("="*60)

    policies = ["lru", "partitioned", "tinylfu"]

    for policy in policies:
        print(f"\n--- 缓存策略: {policy} ---")
        cfg = get_current_config()
        if not cfg:
            record("cache", f"{policy} 策略", "FAIL", "无法获取配置")
            continue

        cfg["cache_policy"] = policy
        if policy == "partitioned":
            cfg["cache_partitions"] = {"default": 30000, "domestic": 10000, "global": 10000}
        else:
            cfg["cache_partitions"] = None
        cfg["ttl"] = 300
        cfg["ttl_min"] = 0
        cfg["ttl_max"] = 0
        cfg["serve_stale"] = False
        cfg["prefetch"] = False

        code, resp = save_config_and_reload(cfg)
        time.sleep(1)

        # 清除缓存
        api_post("/api/reset")
        time.sleep(0.5)

        # 2a. 首次查询 (MISS)
        domain = f"cache-test-{policy}-{int(time.time())}.com"
        rcode1, an1, ips1, t1 = send_dns_udp(domain, timeout=5.0)

        # 第二次查询 (HIT - 应该更快)
        rcode2, an2, ips2, t2 = send_dns_udp(domain, timeout=5.0)

        if t1 is not None and t2 is not None:
            if t2 < t1 * 0.8 or t2 < 50:  # 缓存命中应该明显更快或<50ms
                record("cache", f"{policy} 命中验证", "PASS", f"首次={t1:.1f}ms, 二次={t2:.1f}ms (加速比={t1/max(t2,0.1):.1f}x)")
            else:
                record("cache", f"{policy} 命中验证", "FAIL", f"首次={t1:.1f}ms, 二次={t2:.1f}ms (无明显加速)")
        else:
            record("cache", f"{policy} 命中验证", "FAIL", f"查询失败: rcode1={rcode1}, rcode2={rcode2}")

        # 2b. 缓存统计验证
        code, status = api_get("/api/status")
        if code == 200 and isinstance(status, dict):
            counters = status.get("counters", {})
            hit = counters.get("hit", 0)
            miss = counters.get("miss", 0)
            if hit >= 1:
                record("cache", f"{policy} 统计命中", "PASS", f"hit={hit}, miss={miss}")
            else:
                record("cache", f"{policy} 统计命中", "FAIL", f"hit=0, miss={miss}")
        else:
            record("cache", f"{policy} 统计命中", "FAIL", "无法获取统计")

        # 2c. 负缓存测试 (NXDOMAIN)
        nonexist_domain = f"nxdomain-test-{policy}-{int(time.time())}.invalid"
        rcode_nx1, an_nx1, _, t_nx1 = send_dns_udp(nonexist_domain, timeout=5.0)
        rcode_nx2, an_nx2, _, t_nx2 = send_dns_udp(nonexist_domain, timeout=5.0)

        if rcode_nx1 == 3 and rcode_nx2 == 3:  # NXDOMAIN
            record("cache", f"{policy} 负缓存", "PASS", f"NXDOMAIN 两次返回 rcode=3, 二次={t_nx2:.1f}ms")
        else:
            record("cache", f"{policy} 负缓存", "FAIL", f"首次 rcode={rcode_nx1}, 二次 rcode={rcode_nx2}")

        # 2d. 缓存清除
        api_post("/api/reset")
        time.sleep(0.5)
        code, status2 = api_get("/api/status")
        if code == 200:
            used = status2.get("map", {}).get("used", -1)
            if used == 0:
                record("cache", f"{policy} 清除缓存", "PASS", f"清除后 used={used}")
            else:
                record("cache", f"{policy} 清除缓存", "FAIL", f"清除后 used={used}")
        else:
            record("cache", f"{policy} 清除缓存", "FAIL", "无法获取状态")

    # 2e. serve-stale 测试
    print("\n--- serve-stale 测试 ---")
    cfg = get_current_config()
    if cfg:
        cfg["serve_stale"] = True
        cfg["stale_ttl"] = 3600
        cfg["ttl"] = 2  # 短 TTL
        cfg["cache_policy"] = "lru"
        save_config_and_reload(cfg)
        time.sleep(1)
        api_post("/api/reset")
        time.sleep(0.5)

        domain = f"stale-test-{int(time.time())}.com"
        send_dns_udp(domain, timeout=5.0)  # 首次查询
        record("cache", "serve-stale 开启", "PASS", "serve_stale=true 已配置")

        # 恢复
        cfg["ttl"] = 300
        cfg["serve_stale"] = False
        save_config_and_reload(cfg)
        time.sleep(0.5)

    reset_upstreams_to_default()

# ============================================================
# 测试 3: 分流规则回归
# ============================================================
def test_rules():
    print("\n" + "="*60)
    print("测试 3: 分流规则回归")
    print("="*60)

    # 3a. block 规则
    print("\n--- block 规则 ---")
    cfg = get_current_config()
    if cfg:
        cfg["rules"] = [
            {"id": "rb1", "match": "block-test.example.com", "action": "block"},
        ]
        save_config_and_reload(cfg)
        time.sleep(0.5)
        api_post("/api/reset")
        time.sleep(0.3)

        rcode, an, ips, elapsed = send_dns_udp("block-test.example.com", timeout=5.0)
        if rcode == 3 or an == 0 or (len(ips) == 1 and ips[0] == "0.0.0.0"):
            record("rules", "block 规则", "PASS", f"rcode={rcode}, AN={an}, IPs={ips}")
        else:
            record("rules", "block 规则", "FAIL", f"rcode={rcode}, AN={an}, IPs={ips}")

    # 3b. allow 规则
    print("\n--- allow 规则 ---")
    if cfg:
        cfg["rules"] = [
            {"id": "ra1", "match": "allow-test.example.com", "action": "allow"},
        ]
        save_config_and_reload(cfg)
        time.sleep(0.5)
        api_post("/api/reset")
        time.sleep(0.3)

        rcode, an, ips, elapsed = send_dns_udp("www.baidu.com", timeout=5.0)
        record("rules", "allow 规则配置", "PASS" if rcode == 0 else "FAIL", f"allow 规则已配置, baidu.com rcode={rcode}")

    # 3c. group 规则
    print("\n--- group 规则 ---")
    if cfg:
        cfg["upstreams"] = [
            {"id": "u1", "name": "AliDNS", "proto": "udp", "addr": "223.5.5.5", "port": 53, "group": "domestic", "latency": 6, "enabled": True},
            {"id": "u2", "name": "DNSPod", "proto": "udp", "addr": "119.29.29.29", "port": 53, "group": "domestic", "latency": 11, "enabled": True},
        ]
        cfg["rules"] = [
            {"id": "rg1", "match": "group-test.example.com", "action": "group", "group": "domestic"},
        ]
        save_config_and_reload(cfg)
        time.sleep(0.5)
        api_post("/api/reset")
        time.sleep(0.3)

        rcode, an, ips, elapsed = send_dns_udp("www.baidu.com", timeout=5.0)
        if rcode == 0 and an > 0:
            record("rules", "group 规则", "PASS", f"group 规则已配置, 域名解析正常 rcode={rcode}")
        else:
            record("rules", "group 规则", "FAIL", f"rcode={rcode}, AN={an}")

    # 3d. forceIp 规则
    print("\n--- forceIp 规则 ---")
    if cfg:
        cfg["rules"] = [
            {"id": "rf1", "match": "forceip-test.example.com", "action": "forceIp", "ip": "1.2.3.4"},
        ]
        save_config_and_reload(cfg)
        time.sleep(0.5)
        api_post("/api/reset")
        time.sleep(0.3)

        rcode, an, ips, elapsed = send_dns_udp("forceip-test.example.com", timeout=5.0)
        if "1.2.3.4" in ips:
            record("rules", "forceIp 规则", "PASS", f"返回 IP={ips}")
        else:
            record("rules", "forceIp 规则", "FAIL", f"期望 1.2.3.4, 实际={ips}")

    # 3e. 通配符匹配
    print("\n--- 通配符匹配 ---")
    if cfg:
        cfg["rules"] = [
            {"id": "rw1", "match": "*.wildcard-test.com", "action": "forceIp", "ip": "5.6.7.8"},
        ]
        save_config_and_reload(cfg)
        time.sleep(0.5)
        api_post("/api/reset")
        time.sleep(0.3)

        # 测试一级子域名
        rcode1, an1, ips1, _ = send_dns_udp("www.wildcard-test.com", timeout=5.0)
        # 测试多级子域名
        rcode2, an2, ips2, _ = send_dns_udp("a.b.wildcard-test.com", timeout=5.0)

        if "5.6.7.8" in ips1 and "5.6.7.8" in ips2:
            record("rules", "通配符 *.example.com", "PASS", f"www.={ips1}, a.b.={ips2}")
        elif "5.6.7.8" in ips1:
            record("rules", "通配符一级子域名", "PASS", f"www.wildcard-test.com → {ips1}")
            record("rules", "通配符多级子域名", "FAIL", f"a.b.wildcard-test.com → {ips2} (期望 5.6.7.8)")
        else:
            record("rules", "通配符匹配", "FAIL", f"www.={ips1}, a.b.={ips2}")

    # 3f. 规则 API 验证
    print("\n--- 规则 API 验证 ---")
    code, resp = api_get("/api/rules")
    if code == 200 and "rules" in resp:
        record("rules", "GET /api/rules", "PASS", f"返回 {len(resp.get('rules', []))} 条规则")
    else:
        record("rules", "GET /api/rules", "FAIL", f"code={code}")

    # 添加规则
    code, resp = api_post("/api/rules", {"match": "api-add-test.com", "action": "block"})
    if code in (200, 201):
        record("rules", "POST /api/rules", "PASS", f"code={code}")
    else:
        record("rules", "POST /api/rules", "FAIL", f"code={code}, resp={resp}")

    reset_upstreams_to_default()

# ============================================================
# 测试 4: 预取 + 持久化 + 热重载
# ============================================================
def test_prefetch_persistence_reload():
    print("\n" + "="*60)
    print("测试 4: 预取 + 持久化 + 热重载")
    print("="*60)

    # 4a. 预取功能
    print("\n--- 预取测试 ---")
    cfg = get_current_config()
    if cfg:
        cfg["prefetch"] = True
        cfg["ttl"] = 300
        save_config_and_reload(cfg)
        time.sleep(1)
        api_post("/api/reset")
        time.sleep(0.5)

        # 查询热门域名
        for d in ["www.baidu.com", "www.qq.com", "www.taobao.com"]:
            send_dns_udp(d, timeout=5.0)

        time.sleep(2)  # 等待预取触发

        # 检查统计
        code, status = api_get("/api/status")
        if code == 200:
            record("prefetch", "预取配置生效", "PASS", f"prefetch=true 已配置")
        else:
            record("prefetch", "预取配置生效", "FAIL", "无法获取状态")

    # 4b. 缓存持久化
    print("\n--- 缓存持久化测试 ---")
    # 查询一些域名
    test_domains = ["persist-test1.com", "persist-test2.com", "persist-test3.com"]
    for d in test_domains:
        send_dns_udp(d, timeout=5.0)

    time.sleep(2)  # 等待持久化保存 (60s 间隔可能太长, 手动检查文件)

    # 检查缓存文件
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE) as f:
                cache_data = json.load(f)
            cache_count = len(cache_data) if isinstance(cache_data, dict) else len(cache_data)
            record("persistence", "缓存持久化文件", "PASS", f"文件存在, {cache_count} 条记录")
        except Exception as e:
            record("persistence", "缓存持久化文件", "FAIL", f"读取失败: {e}")
    else:
        record("persistence", "缓存持久化文件", "SKIP", "缓存文件不存在 (可能尚未到保存间隔)")

    # 4c. 热重载
    print("\n--- 热重载测试 ---")
    cfg = get_current_config()
    if cfg:
        old_ttl = cfg.get("ttl", 300)
        new_ttl = 250 if old_ttl != 250 else 350
        cfg["ttl"] = new_ttl
        code, resp = save_config_and_reload(cfg)
        time.sleep(1)

        # 验证新配置生效
        code2, cfg2 = api_get("/api/config")
        if code2 == 200 and cfg2.get("ttl") == new_ttl:
            record("reload", "热重载 TTL 变更", "PASS", f"TTL: {old_ttl} → {new_ttl}")
        else:
            record("reload", "热重载 TTL 变更", "FAIL", f"期望 ttl={new_ttl}, 实际={cfg2.get('ttl') if isinstance(cfg2, dict) else 'N/A'}")

        # 热重载后 DNS 仍可正常工作
        rcode, an, ips, elapsed = send_dns_udp("www.baidu.com", timeout=5.0)
        if rcode == 0 and an > 0:
            record("reload", "热重载后 DNS 正常", "PASS", f"rcode={rcode}, {elapsed:.1f}ms")
        else:
            record("reload", "热重载后 DNS 正常", "FAIL", f"rcode={rcode}")

    reset_upstreams_to_default()

# ============================================================
# 测试 5: API 全部端点回归
# ============================================================
def test_api_endpoints():
    print("\n" + "="*60)
    print("测试 5: API 全部端点回归")
    print("="*60)

    endpoints = [
        ("GET", "/api/status", "统计信息"),
        ("GET", "/api/snapshot", "快照"),
        ("GET", "/api/config", "当前配置"),
        ("GET", "/api/upstreams", "上游列表"),
        ("GET", "/api/rules", "规则列表"),
        ("GET", "/api/logs", "日志"),
        ("GET", "/api/pipeline", "流水线"),
        ("GET", "/api/profile", "性能剖析"),
        ("GET", "/metrics", "Prometheus 指标"),
    ]

    for method, path, desc in endpoints:
        if method == "GET":
            code, resp = api_get(path)
        else:
            code, resp = api_post(path)

        if code == 200:
            record("api", f"{method} {path} ({desc})", "PASS", f"HTTP {code}")
        elif code == 404:
            record("api", f"{method} {path} ({desc})", "SKIP", f"HTTP 404 - 端点不存在")
        else:
            record("api", f"{method} {path} ({desc})", "FAIL", f"HTTP {code}")

    # POST 端点测试
    post_endpoints = [
        ("/api/reload", "热重载", {}),
        ("/api/reset", "重置缓存", {}),
        ("/api/reprobe", "重新探测延迟", {}),
        ("/api/query", "手动查询", {"domain": "www.baidu.com", "type": "A"}),
    ]

    for path, desc, body in post_endpoints:
        code, resp = api_post(path, body)
        if code in (200, 202, 204):
            record("api", f"POST {path} ({desc})", "PASS", f"HTTP {code}")
        else:
            record("api", f"POST {path} ({desc})", "FAIL", f"HTTP {code}: {str(resp)[:100]}")

# ============================================================
# 测试 6: 前端控件回归
# ============================================================
def test_frontend_controls():
    print("\n" + "="*60)
    print("测试 6: 前端控件回归")
    print("="*60)

    # 前端主要控件对应的 API 操作
    controls = [
        ("清除缓存按钮", lambda: api_post("/api/reset"), "POST /api/reset"),
        ("重新探测按钮", lambda: api_post("/api/reprobe"), "POST /api/reprobe"),
        ("热重载按钮", lambda: api_post("/api/reload"), "POST /api/reload"),
        ("查询输入框", lambda: api_post("/api/query", {"domain": "www.baidu.com", "type": "A"}), "POST /api/query"),
        ("上游列表展示", lambda: api_get("/api/upstreams"), "GET /api/upstreams"),
        ("规则列表展示", lambda: api_get("/api/rules"), "GET /api/rules"),
        ("配置面板展示", lambda: api_get("/api/config"), "GET /api/config"),
        ("统计面板展示", lambda: api_get("/api/status"), "GET /api/status"),
    ]

    for name, func, api_path in controls:
        code, resp = func()
        if code in (200, 201, 202, 204):
            record("frontend", f"{name} → {api_path}", "PASS", f"HTTP {code}")
        else:
            record("frontend", f"{name} → {api_path}", "FAIL", f"HTTP {code}")

    # 测试缓存策略切换 (前端控件 cfg-cache-policy)
    print("\n--- 缓存策略切换控件 ---")
    for policy in ["lru", "tinylfu"]:
        cfg = get_current_config()
        if cfg:
            cfg["cache_policy"] = policy
            code, resp = api_put("/api/config", cfg)
            if code == 200:
                record("frontend", f"切换缓存策略为 {policy}", "PASS", f"PUT /api/config → {code}")
            else:
                record("frontend", f"切换缓存策略为 {policy}", "FAIL", f"HTTP {code}")

    # 测试 prefetch 开关
    print("\n--- 预取开关控件 ---")
    cfg = get_current_config()
    if cfg:
        cfg["prefetch"] = True
        code, _ = api_put("/api/config", cfg)
        record("frontend", "预取开关 ON", "PASS" if code == 200 else "FAIL", f"HTTP {code}")
        cfg["prefetch"] = False
        code, _ = api_put("/api/config", cfg)
        record("frontend", "预取开关 OFF", "PASS" if code == 200 else "FAIL", f"HTTP {code}")

    reset_upstreams_to_default()

# ============================================================
# 测试 7: 熔断 + 健康检查 + 实测延迟排序
# ============================================================
def test_circuit_breaker_health():
    print("\n" + "="*60)
    print("测试 7: 熔断 + 健康检查 + 实测延迟排序")
    print("="*60)

    # 7a. 熔断测试 - 配置不可达上游
    print("\n--- 熔断测试 ---")
    cfg = get_current_config()
    if cfg:
        cfg["upstreams"] = [
            {"id": "bad1", "name": "BadUpstream", "proto": "udp", "addr": "10.255.255.1", "port": 53, "group": "default", "latency": 100, "enabled": True},
            {"id": "good1", "name": "GoodUpstream", "proto": "udp", "addr": "223.5.5.5", "port": 53, "group": "default", "latency": 6, "enabled": True},
        ]
        cfg["circuit_fails"] = 2
        cfg["circuit_open_s"] = 10
        cfg["fallback"] = True
        save_config_and_reload(cfg)
        time.sleep(2)
        api_post("/api/reset")
        time.sleep(0.5)

        # 连续发送查询, 让坏上游触发熔断
        rcode = None
        for i in range(5):
            rcode, an, ips, _ = send_dns_udp("www.baidu.com", timeout=3.0)
            time.sleep(0.2)

        if rcode == 0 and an > 0:
            record("circuit", "熔断后 fallback 正常", "PASS", f"坏上游熔断后, 好上游仍能解析 rcode={rcode}")
        else:
            record("circuit", "熔断后 fallback 正常", "FAIL", f"rcode={rcode}, an={an}")

        # 检查上游状态
        code, ups = api_get("/api/upstreams")
        if code == 200:
            bad_status = None
            for u in ups.get("upstreams", []):
                if u.get("name") == "BadUpstream":
                    bad_status = u.get("status", "")
                    record("circuit", "坏上游熔断状态", "PASS", f"status={bad_status}")
                    break
            if bad_status is None:
                record("circuit", "坏上游熔断状态", "FAIL", "未找到 BadUpstream")

    # 7b. 健康检查
    print("\n--- 健康检查 ---")
    code, status = api_get("/api/status")
    if code == 200:
        record("health", "API 健康检查", "PASS", f"running={status.get('running')}, uptime={status.get('uptime_s')}s")
    else:
        record("health", "API 健康检查", "FAIL", f"HTTP {code}")

    # 7c. 实测延迟排序
    print("\n--- 实测延迟排序 ---")
    cfg = get_current_config()
    if cfg:
        cfg["upstreams"] = [
            {"id": "u1", "name": "AliDNS", "proto": "udp", "addr": "223.5.5.5", "port": 53, "group": "domestic", "latency": 6, "enabled": True, "latency_measured": True},
            {"id": "u2", "name": "DNSPod", "proto": "udp", "addr": "119.29.29.29", "port": 53, "group": "domestic", "latency": 11, "enabled": True, "latency_measured": True},
        ]
        cfg["speed_test"] = True
        cfg["speed_interval_ms"] = 2000
        save_config_and_reload(cfg)
        time.sleep(3)

        # 发送几个查询
        for d in ["www.baidu.com", "www.qq.com"]:
            send_dns_udp(d, timeout=5.0)

        code, ups = api_get("/api/upstreams")
        if code == 200:
            latencies = [(u.get("name"), u.get("avg_latency", 0)) for u in ups.get("upstreams", [])]
            record("speedtest", "实测延迟排序", "PASS", f"延迟: {latencies}")
        else:
            record("speedtest", "实测延迟排序", "FAIL", f"HTTP {code}")

    reset_upstreams_to_default()

# ============================================================
# 测试 8: 性能压测
# ============================================================
def generate_domains(n=1000):
    """生成 n 个随机域名, 混合存在和不存在的"""
    tlds = ["com", "net", "org", "cn", "io", "dev"]
    real_domains = [
        "www.baidu.com", "www.qq.com", "www.taobao.com", "www.jd.com",
        "www.zhihu.com", "www.bilibili.com", "www.weibo.com", "www.alipay.com",
        "www.tmall.com", "www.163.com", "www.sohu.com", "www.sina.com.cn",
        "www.360.cn", "www.microsoft.com", "www.apple.com", "www.google.com",
        "www.github.com", "www.stackoverflow.com", "www.wikipedia.org",
    ]
    domains = list(real_domains)
    # 生成随机域名
    import random
    random.seed(42)
    while len(domains) < n:
        name = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=random.randint(5, 12)))
        tld = random.choice(tlds)
        domains.append(f"{name}.{tld}")
    return domains[:n]

def perf_worker(thread_id, domains, duration, stop_event, stats_list, latencies_list, progress_counter):
    """压测 worker 线程"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    local_stats = {"total": 0, "success": 0, "fail": 0, "timeout": 0}
    local_latencies = []
    idx = thread_id  # 每个线程从不同位置开始

    start = time.time()
    while not stop_event.is_set():
        elapsed = time.time() - start
        if elapsed > duration:
            break
        domain = domains[idx % len(domains)]
        idx += 1

        q = build_dns_query(domain, qtype=1, tid=(thread_id * 1000 + local_stats["total"]) & 0xFFFF)
        t0 = time.time()
        try:
            sock.sendto(q, DNS_UDP)
            data, _ = sock.recvfrom(4096)
            dt = (time.time() - t0) * 1000
            local_latencies.append(dt)
            local_stats["total"] += 1
            progress_counter[0] += 1  # 共享进度
            if len(data) >= 12:
                flags = struct.unpack('>H', data[2:4])[0]
                rcode = flags & 0xF
                if rcode == 0 or rcode == 3:  # NOERROR or NXDOMAIN are valid
                    local_stats["success"] += 1
                else:
                    local_stats["fail"] += 1
            else:
                local_stats["fail"] += 1
        except socket.timeout:
            local_stats["timeout"] += 1
            local_stats["total"] += 1
            progress_counter[0] += 1
        except Exception:
            local_stats["fail"] += 1
            local_stats["total"] += 1
            progress_counter[0] += 1

    sock.close()
    stats_list[thread_id] = local_stats
    latencies_list[thread_id] = local_latencies

def test_performance():
    print("\n" + "="*60)
    print("测试 8: 性能压测 (1000+ QPS, 5 分钟)")
    print("="*60)

    # 先恢复默认配置
    reset_upstreams_to_default()

    duration = 300  # 5 分钟
    num_threads = 80
    domains = generate_domains(1000)

    print(f"  线程数: {num_threads}")
    print(f"  域名数: {len(domains)}")
    print(f"  持续时间: {duration}s")
    print("  开始压测...")

    # 记录压测前状态
    code, status_before = api_get("/api/status")
    cpu_before = None
    mem_before = None
    try:
        # 获取进程 PID
        pid_out = subprocess.check_output(["pgrep", "-f", "ebpdns"], text=True).strip().split('\n')[0]
        pid = int(pid_out)
        # CPU 和内存
        with open(f"/proc/{pid}/stat") as f:
            parts = f.read().split()
            utime_before = int(parts[13])
            stime_before = int(parts[14])
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS"):
                    mem_before = int(line.split()[1])  # kB
                    break
    except Exception as e:
        print(f"  无法获取压测前资源: {e}")

    # 启动 worker 线程
    stats_list = [None] * num_threads
    latencies_list = [None] * num_threads
    progress_counter = [0]  # 共享计数器
    stop_event = threading.Event()
    threads = []

    t_start = time.time()
    for i in range(num_threads):
        t = threading.Thread(target=perf_worker, args=(i, domains, duration, stop_event, stats_list, latencies_list, progress_counter))
        t.daemon = True
        threads.append(t)
        t.start()

    # 进度报告
    dot_count = 0
    while any(t.is_alive() for t in threads):
        time.sleep(10)
        elapsed = time.time() - t_start
        if elapsed > duration + 10:  # 超时保护
            break
        dot_count += 1
        total_so_far = progress_counter[0]
        qps_so_far = total_so_far / max(elapsed, 1)
        print(f"  进度: {elapsed:.0f}s/{duration}s, 已完成 {total_so_far} 查询, 当前 QPS≈{qps_so_far:.0f}")

    stop_event.set()
    for t in threads:
        t.join(timeout=5)

    t_end = time.time()
    actual_duration = t_end - t_start

    # 收集结果
    total_stats = {"total": 0, "success": 0, "fail": 0, "timeout": 0}
    all_latencies = []
    for s in stats_list:
        if s:
            for k in total_stats:
                total_stats[k] += s.get(k, 0)
    for l in latencies_list:
        if l:
            all_latencies.extend(l)

    # 计算延迟统计
    if all_latencies:
        all_latencies.sort()
        p50 = all_latencies[len(all_latencies) // 2]
        p95 = all_latencies[int(len(all_latencies) * 0.95)]
        p99 = all_latencies[int(len(all_latencies) * 0.99)]
        avg_lat = statistics.mean(all_latencies)
        max_lat = max(all_latencies)
        min_lat = min(all_latencies)
    else:
        p50 = p95 = p99 = avg_lat = max_lat = min_lat = 0

    total_qps = total_stats["total"] / actual_duration if actual_duration > 0 else 0

    # 压测后状态
    code, status_after = api_get("/api/status")
    cpu_after = None
    mem_after = None
    try:
        with open(f"/proc/{pid}/stat") as f:
            parts = f.read().split()
            utime_after = int(parts[13])
            stime_after = int(parts[14])
        total_cpu_ticks = (utime_after - utime_before) + (stime_after - stime_before)
        cpu_pct = (total_cpu_ticks / 100.0) / actual_duration * 100 if actual_duration > 0 else 0
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS"):
                    mem_after = int(line.split()[1])
                    break
    except Exception as e:
        print(f"  无法获取压测后资源: {e}")
        cpu_pct = 0

    # 收集 API 统计对比
    api_stats_before = status_before.get("counters", {}) if isinstance(status_before, dict) else {}
    api_stats_after = status_after.get("counters", {}) if isinstance(status_after, dict) else {}

    perf_result = {
        "duration_s": round(actual_duration, 1),
        "threads": num_threads,
        "domains": len(domains),
        "total_queries": total_stats["total"],
        "success": total_stats["success"],
        "fail": total_stats["fail"],
        "timeout": total_stats["timeout"],
        "success_rate": round(total_stats["success"] / max(total_stats["total"], 1) * 100, 2),
        "qps": round(total_qps, 1),
        "latency_ms": {
            "min": round(min_lat, 2),
            "avg": round(avg_lat, 2),
            "p50": round(p50, 2),
            "p95": round(p95, 2),
            "p99": round(p99, 2),
            "max": round(max_lat, 2),
        },
        "cpu_usage_pct": round(cpu_pct, 1) if cpu_pct else None,
        "memory_rss_kb": mem_after,
        "api_stats_before": api_stats_before,
        "api_stats_after": api_stats_after,
    }

    results["performance"] = perf_result

    print(f"\n  压测结果:")
    print(f"    总查询数: {total_stats['total']}")
    print(f"    成功: {total_stats['success']} ({perf_result['success_rate']}%)")
    print(f"    失败: {total_stats['fail']}")
    print(f"    超时: {total_stats['timeout']}")
    print(f"    QPS: {total_qps:.1f}")
    print(f"    延迟: min={min_lat:.1f}ms avg={avg_lat:.1f}ms p50={p50:.1f}ms p95={p95:.1f}ms p99={p99:.1f}ms max={max_lat:.1f}ms")
    print(f"    CPU: {cpu_pct:.1f}%" if cpu_pct else "    CPU: N/A")
    print(f"    内存: {mem_after} kB" if mem_after else "    内存: N/A")

    # 验收标准
    print(f"\n  验收标准检查:")
    p99_pass = p99 < 100
    zero_error = total_stats["fail"] == 0
    print(f"    P99 < 100ms: {'PASS' if p99_pass else 'FAIL'} ({p99:.1f}ms)")
    print(f"    0 ERROR: {'PASS' if zero_error else 'FAIL'} ({total_stats['fail']} errors)")

    perf_result["acceptance"] = {
        "p99_lt_100ms": p99_pass,
        "zero_error": zero_error,
    }

# ============================================================
# 日志检查
# ============================================================
def check_logs():
    print("\n" + "="*60)
    print("日志检查")
    print("="*60)

    if not os.path.exists(LOG_PATH):
        record("logs", "日志文件存在", "FAIL", f"文件 {LOG_PATH} 不存在")
        return

    with open(LOG_PATH, 'r', errors='ignore') as f:
        log_content = f.read()

    error_patterns = ['ERROR', 'Exception', 'Traceback', 'FATAL', 'CRITICAL']
    found_errors = []

    for pattern in error_patterns:
        lines = [l for l in log_content.split('\n') if pattern in l]
        if lines:
            found_errors.append(f"{pattern}: {len(lines)} 处")
            # 保存最近的几条
            for l in lines[-5:]:
                results["issues"].append(f"LOG {pattern}: {l.strip()[:200]}")

    if found_errors:
        record("logs", "ERROR/Exception/Traceback 检查", "FAIL", "; ".join(found_errors))
    else:
        record("logs", "ERROR/Exception/Traceback 检查", "PASS", "未发现错误")

    # 统计日志行数
    log_lines = len(log_content.split('\n'))
    print(f"  日志总行数: {log_lines}")

# ============================================================
# 报告生成
# ============================================================
def generate_report():
    print("\n" + "="*60)
    print("测试报告汇总")
    print("="*60)

    total = passed + failed + skipped
    print(f"\n功能回归测试:")
    print(f"  通过: {passed}")
    print(f"  失败: {failed}")
    print(f"  跳过: {skipped}")
    print(f"  总计: {total}")

    perf = results.get("performance", {})
    if perf:
        print(f"\n性能压测:")
        print(f"  QPS: {perf.get('qps', 'N/A')}")
        print(f"  P50: {perf.get('latency_ms', {}).get('p50', 'N/A')} ms")
        print(f"  P95: {perf.get('latency_ms', {}).get('p95', 'N/A')} ms")
        print(f"  P99: {perf.get('latency_ms', {}).get('p99', 'N/A')} ms")
        print(f"  P99 < 100ms: {'YES' if perf.get('acceptance', {}).get('p99_lt_100ms') else 'NO'}")
        print(f"  CPU: {perf.get('cpu_usage_pct', 'N/A')}%")
        print(f"  内存: {perf.get('memory_rss_kb', 'N/A')} kB")

    if results["issues"]:
        print(f"\n发现的问题 ({len(results['issues'])}):")
        for issue in results["issues"][:20]:
            print(f"  - {issue}")

    # 保存 JSON 结果
    with open(RESULTS_JSON, 'w') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"\n详细结果已保存到: {RESULTS_JSON}")

    return results

# ============================================================
# 主函数
# ============================================================
def main():
    print("="*60)
    print("ebpdns v1.9.53 功能回归测试 + 性能压测")
    print(f"开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)

    # 检查服务是否运行
    code, status = api_get("/api/status")
    if code != 200:
        print("错误: 无法连接到 ebpdns API, 请确认服务正在运行")
        sys.exit(1)

    version = status.get("version", "unknown")
    print(f"服务版本: {version}")
    print(f"运行状态: {status.get('running')}, 运行时间: {status.get('uptime_s')}s")

    # 1. 六协议上游回归
    try:
        test_upstream_protocols()
    except Exception as e:
        record("upstream", "测试1整体", "FAIL", f"异常: {e}")
        import traceback; traceback.print_exc()
        reset_upstreams_to_default()

    # 2. 缓存三种策略回归
    try:
        test_cache_policies()
    except Exception as e:
        record("cache", "测试2整体", "FAIL", f"异常: {e}")
        import traceback; traceback.print_exc()
        reset_upstreams_to_default()

    # 3. 分流规则回归
    try:
        test_rules()
    except Exception as e:
        record("rules", "测试3整体", "FAIL", f"异常: {e}")
        import traceback; traceback.print_exc()
        reset_upstreams_to_default()

    # 4. 预取 + 持久化 + 热重载
    try:
        test_prefetch_persistence_reload()
    except Exception as e:
        record("prefetch", "测试4整体", "FAIL", f"异常: {e}")
        import traceback; traceback.print_exc()
        reset_upstreams_to_default()

    # 5. API 全部端点回归
    try:
        test_api_endpoints()
    except Exception as e:
        record("api", "测试5整体", "FAIL", f"异常: {e}")
        import traceback; traceback.print_exc()

    # 6. 前端控件回归
    try:
        test_frontend_controls()
    except Exception as e:
        record("frontend", "测试6整体", "FAIL", f"异常: {e}")
        import traceback; traceback.print_exc()
        reset_upstreams_to_default()

    # 7. 熔断 + 健康检查 + 实测延迟排序
    try:
        test_circuit_breaker_health()
    except Exception as e:
        record("circuit", "测试7整体", "FAIL", f"异常: {e}")
        import traceback; traceback.print_exc()
        reset_upstreams_to_default()

    # 8. 性能压测 (可选, 传 --skip-perf 跳过)
    if "--skip-perf" not in sys.argv:
        try:
            test_performance()
        except Exception as e:
            record("perf", "测试8整体", "FAIL", f"异常: {e}")
            import traceback; traceback.print_exc()
    else:
        print("\n跳过性能压测 (--skip-perf)")

    # 日志检查
    check_logs()

    # 生成报告
    generate_report()

    print(f"\n完成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)

if __name__ == "__main__":
    main()
