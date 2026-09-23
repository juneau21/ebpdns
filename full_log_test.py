#!/usr/bin/env python3
"""ebpdns v1.9.52 全量日志测试：混合查询压测 + 三缓存策略对比 + 0 ERROR 校验。"""
import json
import socket
import struct
import time
import random
import sys
import os
import urllib.request
import threading
from collections import Counter

PROJECT = "/home/user/.super_doubao/super-doubao-runtime/workspace/ebpdns-v1931"
CONFIG = "/tmp/v1931_test.json"
DNS_HOST = "127.0.0.1"
DNS_PORT = 15365
API_PORT = 18096

# 混合查询域名池：热点(高频) + 长尾(低频) + 特殊类型
HOT_DOMAINS = [
    "www.baidu.com", "www.qq.com", "www.taobao.com", "www.jd.com",
    "www.weibo.com", "www.zhihu.com", "www.bilibili.com", "www.douban.com",
    "www.google.com", "www.youtube.com", "www.github.com", "www.cloudflare.com",
    "dns.alidns.com", "doh.pub", "www.163.com", "www.sina.com.cn",
    "www.sohu.com", "www.ifeng.com", "www.tmall.com", "www.alipay.com",
]
TAIL_DOMAINS = [f"tail-{i}.example.com" for i in range(500)]
SPECIAL = [
    ("www.baidu.com", "AAAA"), ("www.qq.com", "AAAA"),
    ("www.baidu.com", "MX"), ("www.qq.com", "TXT"),
    ("www.baidu.com", "NS"), ("nonexistent-xyz-12345.invalid", "A"),
    ("www.googleapis.com", "A"), ("fonts.gstatic.com", "A"),
]

TYPE_CODES = {"A": 1, "AAAA": 28, "MX": 15, "TXT": 16, "NS": 2, "CNAME": 5}


def build_query(domain, qtype="A", qid=None):
    if qid is None:
        qid = random.randint(1, 65535)
    labels = b"".join(bytes([len(p)]) + p.encode() for p in domain.split("."))
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    question = labels + b"\x00" + struct.pack(">HH", TYPE_CODES.get(qtype, 1), 1)
    return header + question


def udp_query(domain, qtype="A", timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(build_query(domain, qtype), (DNS_HOST, DNS_PORT))
        data, _ = sock.recvfrom(4096)
        rcode = struct.unpack(">H", data[2:4])[0] & 0x0F
        return True, rcode, len(data)
    except Exception as e:
        return False, -1, str(e)
    finally:
        sock.close()


def api_get(path):
    try:
        with urllib.request.urlopen(f"http://{DNS_HOST}:{API_PORT}{path}", timeout=5) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except Exception as e:
        return -1, str(e)


def api_post(path, data=None):
    try:
        body = json.dumps(data or {}).encode() if data else b"{}"
        req = urllib.request.Request(f"http://{DNS_HOST}:{API_PORT}{path}", data=body,
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except Exception as e:
        return -1, str(e)


def api_put(path, data=None):
    try:
        body = json.dumps(data or {}).encode() if data else b"{}"
        req = urllib.request.Request(f"http://{DNS_HOST}:{API_PORT}{path}", data=body,
                                     headers={"Content-Type": "application/json"}, method="PUT")
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except Exception as e:
        return -1, str(e)


def set_cache_policy(policy):
    """通过 API 切换缓存策略（PUT 即时生效）。"""
    status, body = api_put("/api/config", {"cache_policy": policy})
    if status != 200:
        return False
    time.sleep(0.5)
    status, body = api_get("/api/status")
    if status == 200:
        st = json.loads(body)
        return st.get("cache_policy") == policy
    return False


def run_mixed_queries(duration_sec, label):
    """运行混合查询指定时长，返回统计。"""
    stats = Counter()
    errors = []
    t0 = time.time()
    n = 0
    while time.time() - t0 < duration_sec:
        # 70% 热点, 20% 长尾, 10% 特殊类型
        r = random.random()
        if r < 0.7:
            d = random.choice(HOT_DOMAINS)
            qt = "A"
        elif r < 0.9:
            d = random.choice(TAIL_DOMAINS)
            qt = "A"
        else:
            d, qt = random.choice(SPECIAL)
        ok, rcode, info = udp_query(d, qt)
        n += 1
        if ok:
            stats[f"rcode_{rcode}"] += 1
            stats["success"] += 1
        else:
            stats["timeout"] += 1
            if len(errors) < 10:
                errors.append(f"{d} {qt}: {info}")
        # 控制速率 ~50 QPS
        if n % 50 == 0:
            elapsed = time.time() - t0
            if elapsed < n / 50:
                time.sleep(n / 50 - elapsed)
    elapsed = time.time() - t0
    return {
        "label": label,
        "total": n,
        "elapsed": round(elapsed, 1),
        "qps": round(n / max(0.1, elapsed), 1),
        "success": stats["success"],
        "timeout": stats["timeout"],
        "rcode_dist": {k: v for k, v in stats.items() if k.startswith("rcode_")},
        "sample_errors": errors,
    }


def check_logs():
    """检查日志中是否有 ERROR。"""
    status, body = api_get("/api/logs?limit=500")
    if status != 200:
        return False, f"API logs failed: {body}"
    try:
        data = json.loads(body)
        events = data.get("events", [])
        err_events = [e for e in events if e.get("level") in ("err", "error")]
        return len(err_events) == 0, f"total_events={len(events)}, error_events={len(err_events)}"
    except Exception as e:
        return False, f"parse failed: {e}"


def test_api_endpoints():
    """测试所有 API 端点可用性。"""
    results = {}
    for path in ["/api/status", "/api/snapshot", "/api/config", "/api/upstreams",
                 "/api/rules", "/api/logs?limit=10", "/api/pipeline", "/metrics"]:
        status, _ = api_get(path)
        results[path] = status
    for path in ["/api/reset", "/api/reprobe"]:
        status, _ = api_post(path)
        results[path] = status
    # 查询测试
    status, _ = api_post("/api/query", {"domain": "www.baidu.com", "qtype": "A"})
    results["/api/query"] = status
    return results


def main():
    print("=" * 70)
    print("ebpdns v1.9.52 全量日志测试")
    print("=" * 70)

    # 等待服务启动
    print("\n[1] 等待服务就绪...")
    ready = False
    for i in range(30):
        status, _ = api_get("/api/status")
        if status == 200:
            ready = True
            print(f"    服务已就绪 (尝试 {i+1} 次)")
            break
        time.sleep(1)
    if not ready:
        print("    错误: 服务未就绪")
        sys.exit(1)

    # API 端点测试
    print("\n[2] API 端点测试...")
    api_results = test_api_endpoints()
    for path, status in api_results.items():
        ok = "✓" if status == 200 else "✗"
        print(f"    {ok} {path} -> {status}")

    all_results = []
    policies = ["lru", "tinylfu", "partitioned"]

    for policy in policies:
        print(f"\n[3] 缓存策略: {policy.upper()}")
        print(f"    切换策略...")
        if not set_cache_policy(policy):
            print(f"    警告: 策略切换验证失败，继续测试")
        time.sleep(1)

        # 重置统计
        api_post("/api/reset")

        # 运行 120 秒混合查询（三策略共 6 分钟）
        print(f"    运行 120s 混合查询 (~50 QPS)...")
        result = run_mixed_queries(120, policy)
        all_results.append(result)
        print(f"    完成: {result['total']} 查询, {result['qps']} QPS, "
              f"成功={result['success']}, 超时={result['timeout']}")
        print(f"    RCODE 分布: {result['rcode_dist']}")

        # 检查日志
        ok, info = check_logs()
        print(f"    日志检查: {'✓ 0 ERROR' if ok else '✗ 有 ERROR'} ({info})")
        if result["sample_errors"]:
            print(f"    样本错误: {result['sample_errors'][:3]}")

        # 获取命中率
        status, body = api_get("/api/status")
        if status == 200:
            st = json.loads(body)
            print(f"    命中率: {st.get('hit_rate', 0)}%, "
                  f"QPS: {st.get('qps', 0)}, "
                  f"缓存: {st.get('map', {}).get('used', 0)}/{st.get('map', {}).get('capacity', 0)}")

    # 汇总
    print("\n" + "=" * 70)
    print("测试汇总")
    print("=" * 70)
    print(f"{'策略':<15} {'查询数':>8} {'QPS':>8} {'成功':>8} {'超时':>8}")
    print("-" * 50)
    for r in all_results:
        print(f"{r['label']:<15} {r['total']:>8} {r['qps']:>8} {r['success']:>8} {r['timeout']:>8}")

    # 最终日志检查
    print("\n[最终] 全量日志 ERROR 检查...")
    ok, info = check_logs()
    print(f"    {'✓ 通过: 0 ERROR' if ok else '✗ 失败: 有 ERROR'} ({info})")

    print("\n测试完成。")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
