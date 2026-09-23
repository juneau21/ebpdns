#!/usr/bin/env python3
"""
ebpdns v1.9.53 资源泄漏检测 & 模糊测试
测试范围:
  1. 随机 DNS 查询报文模糊测试 (UDP)
  2. 随机配置热重载模糊测试 (PUT /api/config)
  3. 随机 API 调用模糊测试
  4. 长时间运行内存监控 (10分钟+)
  5. Socket/FD 泄漏检测
  6. 线程泄漏检测
  7. 连接池连接泄漏检测
"""

import socket
import struct
import json
import time
import random
import string
import os
import sys
import threading
import urllib.request
import urllib.error
import csv
import subprocess
import traceback
from collections import defaultdict
from datetime import datetime

# ============ 配置 ============
DNS_UDP_HOST = "127.0.0.1"
DNS_UDP_PORT = 15365
DNS_TCP_HOST = "127.0.0.1"
DNS_TCP_PORT = 15366
API_BASE = "http://127.0.0.1:18096"
CONFIG_PATH = "/tmp/v1931.json"
LOG_PATH = "/tmp/ebpdns_v1931.log"
MEMORY_CSV = "/tmp/memory_monitor_v1953.csv"
PROJECT_DIR = "/home/user/.super_doubao/super-doubao-runtime/workspace/ebpdns-v1931"

# 测试参数
FUZZ_RANDOM_BYTES = 10000
FUZZ_SEMI_STRUCTURED = 5000
FUZZ_RELOAD_COUNT = 500
FUZZ_API_COUNT = 2000
MEM_MONITOR_DURATION = 660  # 11 分钟
MEM_MONITOR_INTERVAL = 30   # 每30秒记录
MEM_QPS = 100
RELOAD_INTERVAL = 60        # 每60秒热重载一次
TCP_QUERY_COUNT = 1000
API_LEAK_COUNT = 1000
THREAD_RELOAD_COUNT = 10

# ============ 工具函数 ============

def get_pid():
    """获取 ebpdns 服务 PID (python3 进程)"""
    try:
        result = subprocess.run(
            ["pgrep", "-f", "python3 -m ebpdns run"],
            capture_output=True, text=True, timeout=5
        )
        for p in result.stdout.strip().split("\n"):
            p = p.strip()
            if not p.isdigit():
                continue
            pid = int(p)
            # 验证是 python 进程
            try:
                with open(f"/proc/{pid}/comm") as f:
                    comm = f.read().strip()
                if "python" in comm:
                    return pid
            except:
                pass
    except:
        pass
    return None

def is_service_alive():
    """检查服务是否存活"""
    try:
        req = urllib.request.Request(f"{API_BASE}/api/status")
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read())
            return data.get("running", False)
    except:
        return False

def get_rss_kb(pid):
    """获取进程 RSS (KB)"""
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except:
        pass
    return -1

def get_fd_count(pid):
    """获取文件描述符数量"""
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except:
        return -1

def get_thread_count(pid):
    """获取线程数量"""
    try:
        return len(os.listdir(f"/proc/{pid}/task"))
    except:
        return -1

def send_udp_dns(data, timeout=2.0):
    """发送 UDP DNS 报文"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(data, (DNS_UDP_HOST, DNS_UDP_PORT))
        resp, _ = sock.recvfrom(4096)
        return True, resp
    except socket.timeout:
        return False, None
    except Exception as e:
        return False, str(e)
    finally:
        sock.close()

def send_tcp_dns(data, timeout=3.0):
    """发送 TCP DNS 报文"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((DNS_TCP_HOST, DNS_TCP_PORT))
        tcp_data = struct.pack("!H", len(data)) + data
        sock.sendall(tcp_data)
        len_data = sock.recv(2)
        if len(len_data) < 2:
            return False, "short read"
        resp_len = struct.unpack("!H", len_data)[0]
        resp = b""
        while len(resp) < resp_len:
            chunk = sock.recv(resp_len - len(resp))
            if not chunk:
                break
            resp += chunk
        return True, resp
    except Exception as e:
        return False, str(e)
    finally:
        sock.close()

def http_request(method, path, body=None, content_type="application/json", timeout=5.0):
    """发送 HTTP API 请求"""
    url = f"{API_BASE}{path}"
    data = None
    headers = {}
    if body is not None:
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode()
        elif isinstance(body, str):
            data = body.encode()
        else:
            data = body
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")[:500]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")[:500]
    except Exception as e:
        return -1, str(e)

def random_domain():
    """生成随机域名"""
    labels = []
    num_labels = random.randint(1, 5)
    charset = string.ascii_lowercase + string.digits + "-"
    for _ in range(num_labels):
        ll = random.randint(1, 12)
        labels.append("".join(random.choice(charset) for _ in range(ll)))
    labels.append(random.choice(["com", "net", "org", "cn", "io", "test", "local"]))
    return ".".join(labels)

def build_dns_query(domain, qtype=1, qclass=1):
    """构建标准 DNS 查询报文"""
    header = struct.pack("!HHHHHH",
                        random.randint(0, 65535),
                        0x0100, 1, 0, 0, 0)
    qname = b""
    for label in domain.split("."):
        qname += bytes([len(label)]) + label.encode()
    qname += b"\x00"
    question = qname + struct.pack("!HH", qtype, qclass)
    return header + question

def random_dns_header():
    return os.urandom(12)

def random_qname():
    qname = b""
    num_labels = random.randint(0, 10)
    for _ in range(num_labels):
        llen = random.randint(0, 63)
        qname += bytes([llen]) + os.urandom(llen)
    qname += b"\x00"
    qtype = random.choice([1, 2, 5, 6, 15, 28, 255, random.randint(0, 65535)])
    qclass = random.choice([1, 3, 4, 255, random.randint(0, 65535)])
    return qname + struct.pack("!HH", qtype, qclass)

# 禁止模糊测试的关键字段 (防止崩溃/端口变更)
PROTECTED_KEYS = {"listen", "api", "web_root", "cache_file",
                  "rule_sub_file", "rule_local_file", "bootstrap_dns"}

def generate_random_config():
    """生成随机配置 JSON (安全字段，不含 listen/api 等)"""
    config = {}
    int_fields = [
        "cache_size", "ttl", "ttl_min", "ttl_max", "timeout_ms",
        "max_parallel_upstreams", "health_check_interval",
        "circuit_fails", "circuit_open_s", "stale_ttl", "persist_ttl",
        "edns_udp_size", "speed_interval_ms", "speed_timeout_ms",
        "ip_speed_cache_ttl", "rule_sub_interval"
    ]
    bool_fields = [
        "serve_stale", "prefetch", "kernel_direct", "speed_test",
        "ip_speed_check", "fallback", "ipv4_first", "ipv6",
        "prefer_ipv4", "edns", "padding", "rebind_protection",
        "dnssec_0x20"
    ]
    str_fields = ["cache_policy", "log_level", "log_format", "hook", "map_type"]

    for f in int_fields:
        if random.random() < 0.4:
            config[f] = random.choice([
                random.randint(1, 100000),
                0, -1, 99999999,
                random.uniform(1, 1000)
            ])
    for f in bool_fields:
        if random.random() < 0.4:
            config[f] = random.choice([True, False, 0, 1, "true", None])
    for f in str_fields:
        if random.random() < 0.4:
            config[f] = random.choice([
                "lru", "lfu", "tinylfu", "random", "INVALID",
                "", "123", None
            ])
    return config

# ============ 测试 1: 随机 DNS 报文模糊测试 ============

def test_fuzz_dns_udp():
    print("\n" + "="*60)
    print("测试 1: DNS UDP 报文模糊测试")
    print("="*60)

    stats = defaultdict(int)
    start = time.time()

    # 1a. 完全随机字节 - 纯发送 (fire-and-forget, 不读响应)
    print(f"\n[1a] 完全随机字节 ({FUZZ_RANDOM_BYTES} 个, 纯发送)...")
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(FUZZ_RANDOM_BYTES):
        size = random.randint(1, 512)
        data = os.urandom(size)
        try:
            send_sock.sendto(data, (DNS_UDP_HOST, DNS_UDP_PORT))
            stats["sent"] += 1
        except:
            stats["send_failed"] += 1
        if (i + 1) % 2000 == 0:
            print(f"  进度: {i+1}/{FUZZ_RANDOM_BYTES} ({time.time()-start:.1f}s)")
    send_sock.close()

    # 1b. 半结构化随机 - 短超时
    print(f"\n[1b] 半结构化随机 ({FUZZ_SEMI_STRUCTURED} 个, timeout=0.2s)...")
    for i in range(FUZZ_SEMI_STRUCTURED):
        hdr = random_dns_header()
        question = random_qname()
        data = hdr + question
        ok, resp = send_udp_dns(data, timeout=0.2)
        if ok:
            stats["semi_resp_ok"] += 1
        else:
            stats["semi_no_resp"] += 1
        if (i + 1) % 1000 == 0:
            print(f"  进度: {i+1}/{FUZZ_SEMI_STRUCTURED} ({time.time()-start:.1f}s)")

    # 1c. 合法查询随机 qtype/qclass/域名
    print(f"\n[1c] 随机域名+qtype+qclass ({FUZZ_SEMI_STRUCTURED} 个, timeout=2s)...")
    qtypes = [1, 2, 5, 6, 15, 28, 255, random.randint(0, 65535)]
    qclasses = [1, 3, 4, 255, random.randint(0, 65535)]
    for i in range(FUZZ_SEMI_STRUCTURED):
        domain = random_domain()
        data = build_dns_query(domain, random.choice(qtypes), random.choice(qclasses))
        ok, resp = send_udp_dns(data, timeout=2.0)
        if ok:
            stats["valid_resp_ok"] += 1
        else:
            stats["valid_no_resp"] += 1
        if (i + 1) % 1000 == 0:
            print(f"  进度: {i+1}/{FUZZ_SEMI_STRUCTURED} ({time.time()-start:.1f}s)")

    elapsed = time.time() - start
    print(f"\n[结果] 耗时: {elapsed:.1f}s")
    for k, v in sorted(stats.items()):
        print(f"  {k}: {v}")

    time.sleep(1)
    alive = is_service_alive()
    stats["service_alive"] = alive
    print(f"  服务存活: {'YES' if alive else 'NO - CRASHED!'}")
    return dict(stats), elapsed

# ============ 测试 2: 随机配置热重载模糊测试 ============

def test_fuzz_reload():
    print("\n" + "="*60)
    print("测试 2: 随机配置热重载模糊测试")
    print("="*60)

    stats = defaultdict(int)
    start = time.time()

    print(f"\n发送 {FUZZ_RELOAD_COUNT} 次随机配置 (PUT /api/config)...")

    for i in range(FUZZ_RELOAD_COUNT):
        attack = random.choice([
            "random_config", "empty_config", "partial_config",
            "type_error", "value_out_of_range", "huge_json",
            "malformed_json", "null_body", "array_body", "string_body",
        ])

        if attack == "random_config":
            body = generate_random_config()
            status, resp = http_request("PUT", "/api/config", body)
        elif attack == "empty_config":
            status, resp = http_request("PUT", "/api/config", {})
        elif attack == "partial_config":
            body = {"cache_size": random.choice([1000, 50000, -1, 999999])}
            status, resp = http_request("PUT", "/api/config", body)
        elif attack == "type_error":
            body = {"cache_size": "not_a_number", "ttl": [1,2,3],
                    "cache_policy": {"nested": "obj"}, "upstreams": "should_be_array"}
            status, resp = http_request("PUT", "/api/config", body)
        elif attack == "value_out_of_range":
            body = {"cache_size": -99999999, "ttl": 999999999,
                    "ttl_min": 999999, "ttl_max": -1, "timeout_ms": -500}
            status, resp = http_request("PUT", "/api/config", body)
        elif attack == "huge_json":
            body = json.dumps({"padding": "A" * (1024 * 1024)})
            status, resp = http_request("PUT", "/api/config", body)
        elif attack == "malformed_json":
            body = b'{"cache_size": 123, broken'
            status, resp = http_request("PUT", "/api/config", body, content_type="application/json")
        elif attack == "null_body":
            status, resp = http_request("PUT", "/api/config", None)
        elif attack == "array_body":
            status, resp = http_request("PUT", "/api/config", [1,2,3,"test"])
        elif attack == "string_body":
            status, resp = http_request("PUT", "/api/config", "just a string")

        stats[f"http_{status}"] += 1

        # 每 50 次检查一次服务
        if (i + 1) % 50 == 0:
            alive = is_service_alive()
            if not alive:
                stats["service_crashed"] += 1
                print(f"  !!! 服务在第 {i+1} 次后崩溃!")
                break

        # 验证查询
        ok, _ = send_udp_dns(build_dns_query("www.baidu.com"), timeout=2.0)
        if not ok:
            stats["query_failed"] += 1

        if (i + 1) % 100 == 0:
            print(f"  进度: {i+1}/{FUZZ_RELOAD_COUNT} ({time.time()-start:.1f}s)")

    # 恢复安全配置
    print("\n恢复安全配置...")
    safe_cfg = {"cache_size": 50000, "cache_policy": "lru", "ttl": 300}
    http_request("PUT", "/api/config", safe_cfg)
    time.sleep(2)

    alive = is_service_alive()
    stats["service_alive"] = alive
    elapsed = time.time() - start
    print(f"\n[结果] 耗时: {elapsed:.1f}s, 服务存活: {'YES' if alive else 'NO'}")
    for k, v in sorted(stats.items()):
        print(f"  {k}: {v}")
    return dict(stats), elapsed

# ============ 测试 3: 随机 API 调用模糊测试 ============

def test_fuzz_api():
    print("\n" + "="*60)
    print("测试 3: 随机 API 调用模糊测试")
    print("="*60)

    endpoints = [
        ("GET", "/api/status"), ("GET", "/api/snapshot"),
        ("GET", "/api/config"), ("PUT", "/api/config"),
        ("GET", "/api/upstreams"), ("POST", "/api/upstreams"),
        ("GET", "/api/rules"), ("POST", "/api/rules"),
        ("POST", "/api/rules/import"), ("POST", "/api/rules/subscribe"),
        ("POST", "/api/rules/subscribe/update"), ("DELETE", "/api/rules/subscribe"),
        ("POST", "/api/reset"), ("POST", "/api/reprobe"),
        ("POST", "/api/reload"), ("GET", "/api/profile"),
        ("GET", "/api/logs"), ("GET", "/api/pipeline"),
        ("GET", "/metrics"), ("GET", "/"),
        ("GET", "/nonexistent"), ("POST", "/api/nonexistent"),
        ("GET", "/api/query"), ("POST", "/api/query"),
    ]

    stats = defaultdict(int)
    status_codes = defaultdict(int)
    start = time.time()

    print(f"\n发送 {FUZZ_API_COUNT} 次随机 API 调用...")

    for i in range(FUZZ_API_COUNT):
        method, path = random.choice(endpoints)
        body = None

        if method in ("POST", "PUT"):
            body_type = random.choice([
                "none", "valid_json", "invalid_json", "huge_json",
                "special_chars", "array", "number", "boolean", "null", "empty"
            ])
            if body_type == "valid_json":
                body = {"test": "data", "num": 123}
            elif body_type == "invalid_json":
                body = b'{bad json'
            elif body_type == "huge_json":
                body = json.dumps({"data": "X" * 100000})
            elif body_type == "special_chars":
                body = {"name": "测试<script>alert(1)</script>", "emoji": "😀"}
            elif body_type == "array":
                body = [1, "two", None, True, {"nested": [1,2,3]}]
            elif body_type == "number":
                body = 42
            elif body_type == "boolean":
                body = True
            elif body_type == "empty":
                body = {}

        if "?" not in path:
            path += f"?_={random.randint(0, 999999)}"

        status, resp = http_request(method, path, body, timeout=5.0)
        status_codes[status] += 1
        stats["total_calls"] += 1
        if status >= 500:
            stats["server_errors"] += 1

        if (i + 1) % 500 == 0:
            print(f"  进度: {i+1}/{FUZZ_API_COUNT} ({time.time()-start:.1f}s)")

    elapsed = time.time() - start
    alive = is_service_alive()
    stats["service_alive"] = alive

    print(f"\n[结果] 耗时: {elapsed:.1f}s")
    print(f"  总调用: {stats['total_calls']}, 5xx错误: {stats.get('server_errors', 0)}")
    print(f"  服务存活: {'YES' if alive else 'NO'}")
    for sc, cnt in sorted(status_codes.items()):
        print(f"    HTTP {sc}: {cnt}")
    return dict(stats), dict(status_codes), elapsed

# ============ 测试 4: 长时间运行内存监控 ============

def test_memory_monitoring(pid):
    print("\n" + "="*60)
    print(f"测试 4: 长时间运行内存监控 ({MEM_MONITOR_DURATION//60}分钟)")
    print("="*60)

    baseline_rss = get_rss_kb(pid)
    baseline_fd = get_fd_count(pid)
    baseline_threads = get_thread_count(pid)
    print(f"\n基线: RSS={baseline_rss/1024:.2f}MB, FD={baseline_fd}, Threads={baseline_threads}")

    csv_file = open(MEMORY_CSV, "w", newline="")
    writer = csv.writer(csv_file)
    writer.writerow(["timestamp", "elapsed_s", "rss_kb", "rss_mb",
                      "fd_count", "thread_count", "qps_achieved", "reloads"])

    stop_flag = threading.Event()
    query_count = [0]
    reload_count = [0]
    lock = threading.Lock()

    def dns_query_worker():
        domains = ["www.baidu.com", "www.qq.com", "www.taobao.com",
                   "github.com", "stackoverflow.com", "nginx.org"]
        while not stop_flag.is_set():
            domain = random.choice(domains)
            qtype = random.choice([1, 1, 1, 28, 5])
            data = build_dns_query(domain, qtype)
            send_udp_dns(data, timeout=1.0)
            with lock:
                query_count[0] += 1
            time.sleep(1.0 / MEM_QPS)

    def reload_worker():
        while not stop_flag.is_set():
            time.sleep(RELOAD_INTERVAL)
            if stop_flag.is_set():
                break
            cfg = {"cache_policy": random.choice(["lru", "lfu", "tinylfu"])}
            http_request("PUT", "/api/config", cfg, timeout=5.0)
            with lock:
                reload_count[0] += 1

    # 启动工作线程
    threads = []
    for _ in range(5):
        t = threading.Thread(target=dns_query_worker, daemon=True)
        t.start()
        threads.append(t)
    rt = threading.Thread(target=reload_worker, daemon=True)
    rt.start()

    start_time = time.time()
    monitor_data = []
    last_count = 0

    print(f"\n{'时间':>8} {'RSS(MB)':>10} {'FD':>6} {'线程':>6} {'QPS':>8} {'累计查询':>10}")
    print("-" * 60)

    while time.time() - start_time < MEM_MONITOR_DURATION:
        elapsed = time.time() - start_time
        rss = get_rss_kb(pid)
        fd = get_fd_count(pid)
        threads_n = get_thread_count(pid)

        with lock:
            qps = (query_count[0] - last_count) / MEM_MONITOR_INTERVAL
            last_count = query_count[0]
            total_q = query_count[0]
            rl = reload_count[0]

        rss_mb = rss / 1024.0
        writer.writerow([
            datetime.now().strftime("%H:%M:%S"), f"{elapsed:.0f}",
            rss, f"{rss_mb:.2f}", fd, threads_n, f"{qps:.0f}"
        ])
        csv_file.flush()
        monitor_data.append({"elapsed": elapsed, "rss_kb": rss,
                            "fd": fd, "threads": threads_n})

        print(f"{elapsed:7.0f}s {rss_mb:10.2f} {fd:6d} {threads_n:6d} {qps:8.0f} {total_q:10d}")
        time.sleep(MEM_MONITOR_INTERVAL)

    stop_flag.set()
    for t in threads:
        t.join(timeout=5)
    rt.join(timeout=5)
    csv_file.close()

    final_rss = get_rss_kb(pid)
    final_fd = get_fd_count(pid)
    final_threads = get_thread_count(pid)
    growth_mb = (final_rss - baseline_rss) / 1024.0

    print(f"\n{'='*60}")
    print(f"内存监控结果:")
    print(f"  基线 RSS: {baseline_rss/1024:.2f} MB")
    print(f"  最终 RSS: {final_rss/1024:.2f} MB")
    print(f"  增长: {growth_mb:.2f} MB")
    print(f"  FD: {baseline_fd} -> {final_fd} ({final_fd - baseline_fd:+d})")
    print(f"  线程: {baseline_threads} -> {final_threads} ({final_threads - baseline_threads:+d})")
    print(f"  总查询: {total_q}, 热重载: {rl} 次")
    print(f"  验收 (< 5MB): {'PASS' if growth_mb < 5.0 else 'FAIL'}")
    print(f"{'='*60}")

    return {
        "baseline_rss_mb": baseline_rss / 1024.0,
        "final_rss_mb": final_rss / 1024.0,
        "growth_mb": growth_mb,
        "baseline_fd": baseline_fd, "final_fd": final_fd,
        "baseline_threads": baseline_threads, "final_threads": final_threads,
        "total_queries": total_q, "reloads": rl,
        "pass": growth_mb < 5.0,
        "monitor_data": monitor_data
    }

# ============ 测试 5: Socket/FD 泄漏检测 ============

def test_fd_leak(pid):
    print("\n" + "="*60)
    print("测试 5: Socket/FD 泄漏检测")
    print("="*60)

    baseline_fd = get_fd_count(pid)
    baseline_rss = get_rss_kb(pid)
    print(f"\n基线: FD={baseline_fd}, RSS={baseline_rss/1024:.2f}MB")

    # TCP DNS 查询
    print(f"\n[5a] {TCP_QUERY_COUNT} 次 TCP DNS 查询...")
    domains = ["www.baidu.com", "www.qq.com", "github.com"]
    for i in range(TCP_QUERY_COUNT):
        data = build_dns_query(random.choice(domains), random.choice([1, 28]))
        send_tcp_dns(data, timeout=2.0)
        if (i + 1) % 200 == 0:
            print(f"  进度: {i+1}/{TCP_QUERY_COUNT}, FD={get_fd_count(pid)}")

    time.sleep(2)
    after_tcp_fd = get_fd_count(pid)
    print(f"  TCP 后: FD={after_tcp_fd} (差 {after_tcp_fd - baseline_fd:+d})")

    # API HTTP 调用
    print(f"\n[5b] {API_LEAK_COUNT} 次 API 调用...")
    apis = ["/api/status", "/api/snapshot", "/api/config", "/api/upstreams"]
    for i in range(API_LEAK_COUNT):
        http_request("GET", random.choice(apis), timeout=3.0)
        if (i + 1) % 200 == 0:
            print(f"  进度: {i+1}/{API_LEAK_COUNT}, FD={get_fd_count(pid)}")

    time.sleep(3)
    final_fd = get_fd_count(pid)
    final_rss = get_rss_kb(pid)
    fd_diff = final_fd - baseline_fd

    print(f"\n[结果]")
    print(f"  基线 FD: {baseline_fd}")
    print(f"  TCP 后 FD: {after_tcp_fd}")
    print(f"  最终 FD: {final_fd}")
    print(f"  FD 变化: {fd_diff:+d}")
    print(f"  RSS 变化: {(final_rss - baseline_rss)/1024:.2f} MB")
    fd_ok = abs(fd_diff) <= 5
    print(f"  FD 泄漏: {'无 (PASS)' if fd_ok else f'可能泄漏 {fd_diff} (FAIL)'}")

    return {"baseline_fd": baseline_fd, "after_tcp_fd": after_tcp_fd,
            "final_fd": final_fd, "fd_change": fd_diff, "fd_ok": fd_ok,
            "baseline_rss_mb": baseline_rss / 1024.0,
            "final_rss_mb": final_rss / 1024.0}

# ============ 测试 6: 线程泄漏检测 ============

def test_thread_leak(pid):
    print("\n" + "="*60)
    print("测试 6: 线程泄漏检测")
    print("="*60)

    baseline_threads = get_thread_count(pid)
    print(f"\n基线线程数: {baseline_threads}")

    print(f"\n触发 {THREAD_RELOAD_COUNT} 次热重载 (切换 cache_policy)...")
    policies = ["lru", "lfu", "tinylfu", "lru"]
    thread_history = [baseline_threads]

    for i in range(THREAD_RELOAD_COUNT):
        cfg = {"cache_policy": policies[i % len(policies)]}
        status, resp = http_request("PUT", "/api/config", cfg, timeout=5.0)
        time.sleep(1)
        t = get_thread_count(pid)
        thread_history.append(t)
        print(f"  重载 {i+1}/{THREAD_RELOAD_COUNT}: policy={cfg['cache_policy']}, threads={t}, status={status}")

    time.sleep(5)
    final_threads = get_thread_count(pid)
    diff = final_threads - baseline_threads
    thread_ok = abs(diff) <= 3

    print(f"\n[结果] 基线={baseline_threads}, 最终={final_threads}, 变化={diff:+d}")
    print(f"  历史: {thread_history}")
    print(f"  线程泄漏: {'无 (PASS)' if thread_ok else f'可能泄漏 {diff} (FAIL)'}")

    # 恢复
    http_request("PUT", "/api/config", {"cache_policy": "lru"}, timeout=5.0)

    return {"baseline_threads": baseline_threads, "final_threads": final_threads,
            "thread_diff": diff, "thread_history": thread_history, "thread_ok": thread_ok}

# ============ 测试 7: 连接池连接泄漏检测 ============

def test_connection_pool_leak(pid):
    print("\n" + "="*60)
    print("测试 7: 连接池连接泄漏检测")
    print("="*60)

    baseline_fd = get_fd_count(pid)
    print(f"\n基线 FD: {baseline_fd}")

    with open(CONFIG_PATH) as f:
        cfg = json.load(f)
    proto_types = set(u.get("proto", "?") for u in cfg.get("upstreams", []))
    print(f"上游协议: {proto_types}")

    # 大量查询测试
    print(f"\n发送 500 次 UDP 查询...")
    for i in range(500):
        data = build_dns_query(random_domain(), 1)
        send_udp_dns(data, timeout=1.0)
        if (i + 1) % 100 == 0:
            time.sleep(0.5)
            print(f"  进度: {i+1}/500, FD={get_fd_count(pid)}")

    time.sleep(3)
    final_fd = get_fd_count(pid)
    fd_diff = final_fd - baseline_fd

    print(f"\n[结果] FD 变化: {fd_diff:+d}")
    if "udp" in proto_types and len(proto_types) == 1:
        print("  注: 仅 UDP 上游 (无连接池复用)")

    return {"has_tcp_upstream": len(proto_types - {"udp"}) > 0,
            "baseline_fd": baseline_fd, "final_fd": final_fd, "fd_diff": fd_diff}

# ============ 日志检查 ============

def check_log_errors():
    print("\n" + "="*60)
    print("日志错误检查")
    print("="*60)

    errors = []
    tracebacks = []

    try:
        with open(LOG_PATH) as f:
            lines = f.readlines()
    except:
        return {"error": "无法读取日志"}

    for i, line in enumerate(lines):
        if "ERROR" in line or "CRITICAL" in line:
            errors.append((i+1, line.strip()))
        if "Traceback (most recent call last)" in line:
            tb_lines = [line.strip()]
            for j in range(i+1, min(i+25, len(lines))):
                tb_lines.append(lines[j].strip())
            tracebacks.append((i+1, "\n".join(tb_lines)))

    print(f"\n总行数: {len(lines)}")
    print(f"ERROR/CRITICAL: {len(errors)}")
    print(f"Traceback 块: {len(tracebacks)}")

    if errors:
        print("\n--- ERROR 行 (前10条) ---")
        for ln, line in errors[:10]:
            print(f"  L{ln}: {line[:200]}")

    if tracebacks:
        print("\n--- Traceback (前3个) ---")
        for ln, tb in tracebacks[:3]:
            print(f"  L{ln}:")
            for tl in tb.split("\n")[:5]:
                print(f"    {tl[:150]}")

    return {"total_lines": len(lines), "error_count": len(errors),
            "traceback_count": len(tracebacks)}

# ============ 主函数 ============

def main():
    print("="*70)
    print("ebpdns v1.9.53 资源泄漏检测 & 模糊测试")
    print(f"开始: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)

    pid = get_pid()
    if not pid:
        print("错误: 未找到 ebpdns 进程!")
        sys.exit(1)
    print(f"ebpdns PID: {pid}")

    if not is_service_alive():
        print("错误: 服务无响应!")
        sys.exit(1)
    print("服务状态: OK")

    results = {}

    try:
        # 测试 1: DNS UDP 模糊
        results["fuzz_dns"], _ = test_fuzz_dns_udp()

        # 测试 2: 配置热重载模糊
        results["fuzz_reload"], _ = test_fuzz_reload()

        # 测试 3: API 模糊
        results["fuzz_api"], results["api_status"], _ = test_fuzz_api()

        # 测试 5: FD 泄漏
        results["fd_leak"] = test_fd_leak(pid)

        # 测试 6: 线程泄漏
        results["thread_leak"] = test_thread_leak(pid)

        # 测试 7: 连接池
        results["conn_pool"] = test_connection_pool_leak(pid)

        # 测试 4: 内存监控 (最后，耗时最长)
        results["memory"] = test_memory_monitoring(pid)

        # 日志检查
        results["log_check"] = check_log_errors()

    except KeyboardInterrupt:
        print("\n测试被中断!")
    except Exception as e:
        print(f"\n测试异常: {e}")
        traceback.print_exc()
        results["fatal_error"] = str(e)

    # ============ 汇总报告 ============
    print("\n\n" + "="*70)
    print("测试汇总报告")
    print("="*70)

    print("\n--- 模糊测试 ---")
    if "fuzz_dns" in results:
        fd = results["fuzz_dns"]
        alive = fd.get("service_alive", False)
        print(f"  DNS 模糊: {'PASS' if alive else 'FAIL'}")
        print(f"    完全随机: {FUZZ_RANDOM_BYTES}, 半结构化: {FUZZ_SEMI_STRUCTURED}, 合法随机: {FUZZ_SEMI_STRUCTURED}")

    if "fuzz_reload" in results:
        fr = results["fuzz_reload"]
        alive = fr.get("service_alive", False)
        crashed = fr.get("service_crashed", 0)
        failed = fr.get("query_failed", 0)
        print(f"  配置热重载模糊: {'PASS' if alive and crashed == 0 else 'WARN'}")
        print(f"    总次数: {FUZZ_RELOAD_COUNT}, 崩溃: {crashed}, 查询失败: {failed}")

    if "fuzz_api" in results:
        fa = results["fuzz_api"]
        alive = fa.get("service_alive", False)
        se = fa.get("server_errors", 0)
        print(f"  API 模糊: {'PASS' if alive and se == 0 else 'WARN'}")
        print(f"    总调用: {fa.get('total_calls', 0)}, 5xx错误: {se}")

    print("\n--- 资源泄漏 ---")
    if "memory" in results:
        m = results["memory"]
        print(f"  内存增长: {m['growth_mb']:.2f} MB ({'PASS' if m['pass'] else 'FAIL'} < 5MB)")
        print(f"    基线: {m['baseline_rss_mb']:.2f} MB -> 最终: {m['final_rss_mb']:.2f} MB")
        print(f"    监控: {MEM_MONITOR_DURATION}s, {m['total_queries']} 查询, {m['reloads']} 次重载")

    if "fd_leak" in results:
        f = results["fd_leak"]
        print(f"  FD 泄漏: {'PASS' if f['fd_ok'] else 'FAIL'} (变化 {f['fd_change']:+d})")

    if "thread_leak" in results:
        t = results["thread_leak"]
        print(f"  线程泄漏: {'PASS' if t['thread_ok'] else 'FAIL'} (变化 {t['thread_diff']:+d})")

    if "log_check" in results:
        lc = results["log_check"]
        print(f"\n--- 日志 ---")
        print(f"  ERROR: {lc.get('error_count', 0)}, Traceback: {lc.get('traceback_count', 0)}")

    print("\n" + "="*70)
    print(f"完成: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)

    # 保存 JSON 报告
    report = {
        "test_time": datetime.now().isoformat(), "pid": pid,
        "fuzz_dns": results.get("fuzz_dns", {}),
        "fuzz_reload": results.get("fuzz_reload", {}),
        "fuzz_api": results.get("fuzz_api", {}),
        "memory": {k: v for k, v in results.get("memory", {}).items() if k != "monitor_data"},
        "fd_leak": results.get("fd_leak", {}),
        "thread_leak": results.get("thread_leak", {}),
        "log_check": results.get("log_check", {})
    }
    with open("/tmp/test_report_v1953.json", "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)
    print(f"\n报告: /tmp/test_report_v1953.json")
    print(f"内存 CSV: {MEMORY_CSV}")

if __name__ == "__main__":
    main()
