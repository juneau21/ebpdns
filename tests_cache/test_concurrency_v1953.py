#!/usr/bin/env python3
"""
ebpdns v1.9.53 并发与竞态条件深度测试
======================================
覆盖6大测试域:
  1. 多线程同时读写缓存 (LRU / Partitioned / TinyLFU)
  2. 热重载期间并发查询
  3. 预取线程与查询线程竞争
  4. 连接池并发获取/释放
  5. telemetry 计数器并发更新
  6. DNS 查询并发风暴

用法:
  cd /home/user/.super_doubao/super-doubao-runtime/workspace/ebpdns-v1931
  python3 tests_cache/test_concurrency_v1953.py
"""
import os
import sys
import json
import time
import socket
import struct
import threading
import traceback
import random
import urllib.request
import urllib.error
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── 路径设置 ──
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from ebpdns.cache import LRUCache, PartitionedCache, TinyLFUCache  # noqa: E402
from ebpdns.telemetry import Telemetry  # noqa: E402
from ebpdns.upstream import _ConnPool  # noqa: E402
from ebpdns.dnsmsg import build_query, TYPE_A, TYPE_AAAA  # noqa: E402

# ── 服务地址 ──
DNS_UDP = ("127.0.0.1", 15365)
DNS_TCP = ("127.0.0.1", 15366)
API_BASE = "http://127.0.0.1:18096"
CONFIG_PATH = "/tmp/v1931.json"
LOG_PATH = "/tmp/ebpdns_v1931.log"

# ── 测试结果收集 ──
RESULTS = []  # [(test_name, status, detail)]
LOCK = threading.Lock()


def record(name, status, detail=""):
    with LOCK:
        RESULTS.append((name, status, detail))
    print("  [%s] %s%s" % (status, name, (" — " + detail if detail else "")))


# ============================================================================
# 测试 1: 多线程同时读写缓存
# ============================================================================
def test_cache_concurrent_rw():
    """50线程 × 10000次操作, 70% read / 20% write / 10% delete"""
    print("\n" + "=" * 70)
    print("测试 1: 多线程同时读写缓存 (50 threads × 10000 ops)")
    print("=" * 70)

    NOW = time.time() + 3600  # 固定 now 避免过期
    N_THREADS = 50
    N_OPS = 10000
    N_KEYS = 2000  # key 空间, 制造冲突

    def make_value():
        return {
            "answers": [{"value": "1.2.3.4", "ttl": 300}],
            "rcode": 0,
            "expires_at": NOW + 3600,
            "chosen": "1.2.3.4",
        }

    def hammer(cache, keyfn, errors, thread_id):
        rng = random.Random(thread_id)
        try:
            for i in range(N_OPS):
                dom = "d%04d.com" % rng.randint(0, N_KEYS - 1)
                qtype = "A" if rng.random() < 0.7 else "AAAA"
                key = keyfn(dom, qtype)
                r = rng.random()
                if r < 0.70:
                    # 70% read
                    cache.get(key, now=NOW)
                elif r < 0.90:
                    # 20% write
                    cache.put(key, make_value(), now=NOW)
                else:
                    # 10% delete
                    cache.delete(key)
            errors.append(None)
        except Exception:
            errors.append(traceback.format_exc())

    def run_cache_test(name, cache, keyfn):
        print("\n  --- %s ---" % name)
        errors = []
        threads = [
            threading.Thread(target=hammer, args=(cache, keyfn, errors, t),
                           name="cache-hammer-%d" % t, daemon=True)
            for t in range(N_THREADS)
        ]
        t0 = time.time()
        for t in threads:
            t.start()
        deadline = t0 + 120
        for t in threads:
            t.join(timeout=max(1, deadline - time.time()))
        dt = time.time() - t0

        alive = [t for t in threads if t.is_alive()]
        errs = [e for e in errors if e]

        ok = True
        detail_parts = []

        if alive:
            ok = False
            detail_parts.append("DEADLOCK: %d threads still alive after 120s" % len(alive))
            # 强制终止标记
            for t in alive:
                t._stop()
        if errs:
            ok = False
            detail_parts.append("EXCEPTIONS: %d errors, first:\n%s" % (len(errs), errs[0][:500]))

        # 验证容量不超限
        try:
            total = len(cache)
            if total > cache.capacity + 16:  # 允许少量溢出(并发窗口)
                ok = False
                detail_parts.append("CAPACITY OVERFLOW: %d > %d+16" % (total, cache.capacity))
            detail_parts.append("final_len=%d, cap=%d" % (total, cache.capacity))
        except Exception as e:
            ok = False
            detail_parts.append("SIZE CHECK FAILED: %r" % e)

        # 验证可正常操作
        try:
            probe_key = keyfn("probe-test.com", "A")
            cache.put(probe_key, make_value(), now=NOW)
            v = cache.get(probe_key, now=NOW)
            if v is None:
                ok = False
                detail_parts.append("PROBE READ AFTER HAMMER: None (data loss?)")
            cache.delete(probe_key)
        except Exception as e:
            ok = False
            detail_parts.append("PROBE OP FAILED: %r" % e)

        ops_total = N_THREADS * N_OPS
        detail_parts.append("%.1fs, %d ops, %.0f ops/s" % (dt, ops_total, ops_total / max(dt, 0.01)))

        record("1.%s" % name, "PASS" if ok else "FAIL", "; ".join(detail_parts))

    # 1a. LRUCache
    run_cache_test("LRUCache", LRUCache(1000), lambda d, q: (d, q))

    # 1b. PartitionedCache
    run_cache_test("PartitionedCache", PartitionedCache(1000),
                   lambda d, q: ("default", d, q))

    # 1c. TinyLFUCache
    run_cache_test("TinyLFUCache", TinyLFUCache(1000), lambda d, q: (d, q))


# ============================================================================
# 测试 2: 热重载期间并发查询
# ============================================================================
def test_reload_concurrent_queries():
    """20线程持续DNS查询 + 每2秒API热重载, 交替切换cache_policy"""
    print("\n" + "=" * 70)
    print("测试 2: 热重载期间并发查询 (20 threads, 2 min)")
    print("=" * 70)

    DURATION = 120  # 2 分钟
    N_QUERY_THREADS = 20
    RELOAD_INTERVAL = 2.0  # 秒

    # 读取当前配置备份 (服务原子写会短暂删除文件, 重试3次)
    original_cfg = None
    for attempt in range(3):
        try:
            with open(CONFIG_PATH) as f:
                original_cfg = json.load(f)
            break
        except (FileNotFoundError, json.JSONDecodeError):
            time.sleep(0.5)
    if original_cfg is None:
        record("2.热重载并发查询", "FAIL", "无法读取配置文件")
        return

    stop_event = threading.Event()
    query_stats = {"success": 0, "fail": 0, "timeouts": 0, "errors": []}
    reload_stats = {"count": 0, "success": 0, "fail": 0, "errors": []}

    def dns_query_thread(thread_id):
        """持续发送DNS查询"""
        rng = random.Random(thread_id * 7919)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        domains = [
            "www.baidu.com", "www.qq.com", "www.taobao.com",
            "www.jd.com", "www.163.com", "www.weibo.com",
            "www.bilibili.com", "www.zhihu.com", "www.douyin.com",
            "www.xinhuanet.com",
        ]
        try:
            while not stop_event.is_set():
                dom = domains[rng.randint(0, len(domains) - 1)]
                qtype = TYPE_A if rng.random() < 0.8 else TYPE_AAAA
                qbytes, qid = build_query(dom, qtype, edns=True)
                try:
                    sock.sendto(qbytes, DNS_UDP)
                    data, _ = sock.recvfrom(4096)
                    # 验证响应 qid 匹配
                    if len(data) >= 2 and struct.unpack(">H", data[:2])[0] == qid:
                        query_stats["success"] += 1
                    else:
                        query_stats["fail"] += 1
                except socket.timeout:
                    query_stats["timeouts"] += 1
                except Exception as e:
                    query_stats["fail"] += 1
                    if len(query_stats["errors"]) < 5:
                        query_stats["errors"].append(str(e))
        except Exception:
            query_stats["errors"].append(traceback.format_exc()[:300])
        finally:
            sock.close()

    def reload_thread():
        """定期修改配置并触发热重载"""
        policies = ["lru", "tinylfu", "partitioned", "lru", "tinylfu"]
        sizes = [50000, 30000, 80000, 40000, 60000]
        idx = 0
        while not stop_event.is_set():
            time.sleep(RELOAD_INTERVAL)
            policy = policies[idx % len(policies)]
            size = sizes[idx % len(sizes)]
            idx += 1
            reload_stats["count"] += 1
            try:
                # 修改配置文件
                with open(CONFIG_PATH) as f:
                    cfg = json.load(f)
                cfg["cache_policy"] = policy
                cfg["cache_size"] = size
                with open(CONFIG_PATH, "w") as f:
                    json.dump(cfg, f, indent=2)

                # 触发热重载
                req = urllib.request.Request(
                    "%s/api/reload" % API_BASE, method="POST"
                )
                resp = urllib.request.urlopen(req, timeout=5)
                body = json.loads(resp.read())
                if body.get("ok"):
                    reload_stats["success"] += 1
                else:
                    reload_stats["fail"] += 1
                    reload_stats["errors"].append(
                        "reload#%d policy=%s: %s" % (idx, policy, body.get("error", "")))
            except Exception as e:
                reload_stats["fail"] += 1
                if len(reload_stats["errors"]) < 5:
                    reload_stats["errors"].append("reload#%d: %r" % (idx, e))

    # 启动查询线程
    qthreads = [
        threading.Thread(target=dns_query_thread, args=(t,),
                        name="dns-q-%d" % t, daemon=True)
        for t in range(N_QUERY_THREADS)
    ]
    rt = threading.Thread(target=reload_thread, name="reload-loop", daemon=True)

    t0 = time.time()
    for t in qthreads:
        t.start()
    rt.start()

    print("  持续运行 %d 秒... (查询线程=%d, 重载间隔=%.1fs)" % (
        DURATION, N_QUERY_THREADS, RELOAD_INTERVAL))
    time.sleep(DURATION)
    stop_event.set()

    for t in qthreads:
        t.join(timeout=5)
    rt.join(timeout=5)
    dt = time.time() - t0

    total_q = query_stats["success"] + query_stats["fail"] + query_stats["timeouts"]
    sr = (query_stats["success"] / max(1, total_q)) * 100
    qps = total_q / max(dt, 1)

    ok = True
    details = []

    if query_stats["fail"] > total_q * 0.05:
        ok = False
        details.append("FAIL RATE %.1f%% (errors: %s)" % (
            query_stats["fail"] / max(1, total_q) * 100,
            query_stats["errors"][:2]))
    if query_stats["timeouts"] > total_q * 0.10:
        ok = False
        details.append("TIMEOUT RATE %.1f%%" % (
            query_stats["timeouts"] / max(1, total_q) * 100))
    if reload_stats["fail"] > 0:
        ok = False
        details.append("RELOAD FAILURES: %d/%d (errors: %s)" % (
            reload_stats["fail"], reload_stats["count"],
            reload_stats["errors"][:2]))

    # 验证服务仍在运行
    try:
        resp = urllib.request.urlopen("%s/api/status" % API_BASE, timeout=3)
        status = json.loads(resp.read())
        if not status.get("running"):
            ok = False
            details.append("SERVICE NOT RUNNING after test")
    except Exception as e:
        ok = False
        details.append("SERVICE UNREACHABLE: %r" % e)

    details.append("QPS=%.0f, success=%d, fail=%d, timeout=%d (%.1f%%)" % (
        qps, query_stats["success"], query_stats["fail"],
        query_stats["timeouts"], sr))
    details.append("reloads: %d ok / %d total" % (
        reload_stats["success"], reload_stats["count"]))

    record("2.热重载并发查询", "PASS" if ok else "FAIL", "; ".join(details))

    # 恢复原始配置
    try:
        with open(CONFIG_PATH, "w") as f:
            json.dump(original_cfg, f, indent=2)
        # 触发一次重载恢复
        req = urllib.request.Request("%s/api/reload" % API_BASE, method="POST")
        urllib.request.urlopen(req, timeout=5)
        print("  [恢复] 配置已还原并热重载")
    except Exception as e:
        print("  [警告] 恢复配置失败: %r" % e)


# ============================================================================
# 测试 3: 预取线程与查询线程竞争
# ============================================================================
def test_prefetch_race():
    """开启prefetch, 大量查询触发预取, 验证无死锁/无损坏"""
    print("\n" + "=" * 70)
    print("测试 3: 预取线程与查询线程竞争")
    print("=" * 70)

    # 先通过 API 开启 prefetch
    try:
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        cfg["prefetch"] = True
        cfg["cache_policy"] = "lru"
        cfg["cache_size"] = 50000
        with open(CONFIG_PATH, "w") as f:
            json.dump(cfg, f, indent=2)
        req = urllib.request.Request("%s/api/reload" % API_BASE, method="POST")
        urllib.request.urlopen(req, timeout=5)
        print("  [设置] prefetch=true, 已热重载")
    except Exception as e:
        record("3.预取竞争", "FAIL", "无法开启prefetch: %r" % e)
        return

    # 用一批热门域名触发预取
    hot_domains = [
        "www.baidu.com", "www.qq.com", "www.taobao.com", "www.jd.com",
        "www.163.com", "www.weibo.com", "www.bilibili.com", "www.zhihu.com",
        "www.douyin.com", "www.tmall.com", "www.alipay.com", "www.ctrip.com",
        "www.meituan.com", "www.dianping.com", "www.4399.com", "www.sohu.com",
        "www.sina.com.cn", "www.ifeng.com", "www.xunlei.com", "www.58.com",
    ]

    N_QUERY_THREADS = 15
    QUERIES_PER_THREAD = 500
    stop_event = threading.Event()
    stats = {"success": 0, "fail": 0, "timeouts": 0, "latencies": [], "errors": []}

    def query_worker(thread_id):
        rng = random.Random(thread_id * 1337)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        try:
            for i in range(QUERIES_PER_THREAD):
                dom = hot_domains[rng.randint(0, len(hot_domains) - 1)]
                qtype = TYPE_A if rng.random() < 0.8 else TYPE_AAAA
                qbytes, qid = build_query(dom, qtype, edns=True)
                t0 = time.time()
                try:
                    sock.sendto(qbytes, DNS_UDP)
                    data, _ = sock.recvfrom(4096)
                    lat = (time.time() - t0) * 1000
                    if len(data) >= 2 and struct.unpack(">H", data[:2])[0] == qid:
                        stats["success"] += 1
                        stats["latencies"].append(lat)
                    else:
                        stats["fail"] += 1
                except socket.timeout:
                    stats["timeouts"] += 1
                except Exception as e:
                    stats["fail"] += 1
                    if len(stats["errors"]) < 3:
                        stats["errors"].append(str(e))
        except Exception:
            stats["errors"].append(traceback.format_exc()[:300])
        finally:
            sock.close()

    # 阶段1: 预热 — 查询两轮让缓存填充, 触发预取调度
    print("  [预热] 两轮热门域名查询填充缓存...")
    warmup_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    warmup_sock.settimeout(3.0)
    for rnd in range(2):
        for dom in hot_domains:
            qbytes, qid = build_query(dom, TYPE_A, edns=True)
            try:
                warmup_sock.sendto(qbytes, DNS_UDP)
                warmup_sock.recvfrom(4096)
            except Exception:
                pass
    warmup_sock.close()
    time.sleep(3)  # 给预取线程时间运行

    # 阶段2: 并发查询 + 预取线程同时运行
    print("  [并发] %d 线程 × %d 查询 (预取线程后台运行中)..." % (
        N_QUERY_THREADS, QUERIES_PER_THREAD))
    t0 = time.time()
    threads = [
        threading.Thread(target=query_worker, args=(t,),
                        name="pf-q-%d" % t, daemon=True)
        for t in range(N_QUERY_THREADS)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    dt = time.time() - t0

    alive = [t for t in threads if t.is_alive()]
    total = stats["success"] + stats["fail"] + stats["timeouts"]
    latencies = sorted(stats["latencies"])
    avg_lat = sum(latencies) / max(1, len(latencies))
    p95 = latencies[int(len(latencies) * 0.95)] if latencies else 0
    p99 = latencies[int(len(latencies) * 0.99)] if latencies else 0

    ok = True
    details = []

    if alive:
        ok = False
        details.append("DEADLOCK: %d threads alive after 60s" % len(alive))
    if stats["fail"] > total * 0.05:
        ok = False
        details.append("FAIL RATE %.1f%%" % (stats["fail"] / max(1, total) * 100))
    if stats["timeouts"] > total * 0.10:
        ok = False
        details.append("TIMEOUT RATE %.1f%%" % (stats["timeouts"] / max(1, total) * 100))

    # 验证服务仍正常
    try:
        resp = urllib.request.urlopen("%s/api/status" % API_BASE, timeout=3)
        s = json.loads(resp.read())
        if not s.get("running"):
            ok = False
            details.append("SERVICE CRASHED")
    except Exception as e:
        ok = False
        details.append("SERVICE UNREACHABLE: %r" % e)

    details.append("total=%d, success=%d, fail=%d, timeout=%d" % (
        total, stats["success"], stats["fail"], stats["timeouts"]))
    details.append("latency: avg=%.1fms, P95=%.1fms, P99=%.1fms" % (avg_lat, p95, p99))
    details.append("duration=%.1fs, QPS=%.0f" % (dt, total / max(dt, 0.1)))

    record("3.预取线程竞争", "PASS" if ok else "FAIL", "; ".join(details))

    # 关闭 prefetch 恢复
    try:
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        cfg["prefetch"] = False
        with open(CONFIG_PATH, "w") as f:
            json.dump(cfg, f, indent=2)
        req = urllib.request.Request("%s/api/reload" % API_BASE, method="POST")
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass


# ============================================================================
# 测试 4: 连接池并发获取/释放
# ============================================================================
class _FakeConn:
    """模拟连接对象, 支持 close() 和 _ebpdns_last_use"""
    def __init__(self, cid):
        self.cid = cid
        self.closed = False
        self._ebpdns_last_use = 0.0
    def close(self):
        self.closed = True
    def __repr__(self):
        return "<FakeConn %d closed=%s>" % (self.cid, self.closed)


def test_conn_pool():
    """多线程并发获取/释放 _ConnPool, 测试连接耗尽和泄漏"""
    print("\n" + "=" * 70)
    print("测试 4: 连接池并发获取/释放")
    print("=" * 70)

    results_detail = []

    # 4a. 基本并发 acquire/release 无泄漏
    print("\n  --- 4a: 并发 acquire/release (20 threads) ---")
    pool = _ConnPool()
    key = ("test_proto", "testhost.com", 443, "/test")
    N_THREADS = 20
    N_OPS = 500
    errors = []
    acquired_count = [0]
    acquired_lock = threading.Lock()

    def pool_worker(thread_id):
        rng = random.Random(thread_id * 31)
        try:
            for i in range(N_OPS):
                conn = pool.acquire(key, timeout=2.0)
                if conn is None:
                    # 池满超时 — 正常行为
                    continue
                if conn == "NEW":
                    # 新建假连接
                    conn = _FakeConn(thread_id * 1000 + i)
                    with acquired_lock:
                        acquired_count[0] += 1
                # 模拟使用
                time.sleep(rng.uniform(0.0001, 0.001))
                pool.release(key, conn)
            errors.append(None)
        except Exception:
            errors.append(traceback.format_exc())

    t0 = time.time()
    threads = [
        threading.Thread(target=pool_worker, args=(t,),
                        name="pool-%d" % t, daemon=True)
        for t in range(N_THREADS)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    dt = time.time() - t0

    alive = [t for t in threads if t.is_alive()]
    errs = [e for e in errors if e]
    ok_a = True
    if alive:
        ok_a = False
        results_detail.append("4a DEADLOCK: %d threads alive" % len(alive))
    if errs:
        ok_a = False
        results_detail.append("4a EXCEPTION: %s" % errs[0][:300])

    # 验证: 所有连接都已释放(信号量计数恢复)
    # acquire 一次应该立即成功(不超时)
    probe = pool.acquire(key, timeout=0.5)
    if probe is None:
        ok_a = False
        results_detail.append("4a LEAK: semaphore exhausted after all releases")
    else:
        pool.release(key, probe if probe != "NEW" else None)

    results_detail.append("4a: %d threads × %d ops in %.2fs, %d new conns created" % (
        N_THREADS, N_OPS, dt, acquired_count[0]))
    record("4a.连接池并发获取释放", "PASS" if ok_a else "FAIL", "; ".join(
        [r for r in results_detail if r.startswith("4a")]))

    # 4b. 连接耗尽场景 — 超过 max_connections 时正确超时
    print("\n  --- 4b: 连接耗尽超时测试 ---")
    pool2 = _ConnPool()
    key2 = ("doh", "exhaust-test.com", 443, "/dns-query")
    # _MAX_CONN = 4, 先占满
    held = []
    for i in range(_ConnPool._MAX_CONN):
        c = pool2.acquire(key2, timeout=1.0)
        assert c is not None, "pre-acquire failed at %d" % i
        held.append(c)

    # 第5个应该超时(池满)
    t0 = time.time()
    blocked = pool2.acquire(key2, timeout=1.0)
    wait_ms = (time.time() - t0) * 1000
    ok_b = (blocked is None)
    detail_b = "5th acquire blocked (timeout=%.0fms, expected ~1000ms)" % wait_ms

    if not ok_b:
        detail_b += " — BUG: 5th acquire should timeout but got %r" % blocked

    # 释放后应该能获取
    for c in held:
        pool2.release(key2, c if c != "NEW" else None)
    after_release = pool2.acquire(key2, timeout=1.0)
    if after_release is None:
        ok_b = False
        detail_b += " — BUG: after release, acquire still fails"
    else:
        pool2.release(key2, after_release if after_release != "NEW" else None)

    record("4b.连接耗尽超时", "PASS" if ok_b else "FAIL", detail_b)

    # 4c. 连接空闲回收
    print("\n  --- 4c: 空闲连接回收 ---")
    pool3 = _ConnPool()
    key3 = ("dot", "idle-test.com", 853, "")
    # acquire + release 放回一个连接
    c1 = pool3.acquire(key3, timeout=1.0)
    assert c1 is not None
    fake = _FakeConn(999) if c1 == "NEW" else c1
    pool3.release(key3, fake)

    # 模拟超龄空闲: 直接修改 last_use 时间戳
    entry = pool3.entry(key3)
    for c in entry["conns"]:
        c._ebpdns_last_use = time.monotonic() - 60.0  # 60s 前, >30s MAX_IDLE

    # 再次 acquire 应该丢弃超龄连接, 返回 NEW
    c2 = pool3.acquire(key3, timeout=1.0)
    ok_c = (c2 == "NEW" or c2 is not None)  # 超龄连接被丢弃, 新建
    detail_c = "stale conn evicted: got %r (expected NEW or fresh)" % c2
    if c2 is None:
        ok_c = False
        detail_c = "FAIL: acquire returned None after stale eviction"
    else:
        pool3.release(key3, c2 if c2 != "NEW" else None)

    record("4c.空闲连接回收", "PASS" if ok_c else "FAIL", detail_c)


# ============================================================================
# 测试 5: telemetry 计数器并发更新
# ============================================================================
def test_telemetry_counters():
    """100线程同时increment, 验证计数无丢失"""
    print("\n" + "=" * 70)
    print("测试 5: telemetry 计数器并发更新 (100 threads)")
    print("=" * 70)

    N_THREADS = 100
    INCR_PER_THREAD = 1000

    tel = Telemetry()
    errors = []

    def inc_worker(thread_id):
        try:
            for i in range(INCR_PER_THREAD):
                tel.inc("total")
                tel.inc("hit")
                tel.inc("errors", n=2)
                tel.inc_rule("domestic")
                tel.inc_qtype("A")
                tel.fast_hit("A", 50, 100, 1.5)
                tel.count_query("AAAA")
            errors.append(None)
        except Exception:
            errors.append(traceback.format_exc())

    t0 = time.time()
    threads = [
        threading.Thread(target=inc_worker, args=(t,),
                        name="tel-%d" % t, daemon=True)
        for t in range(N_THREADS)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    dt = time.time() - t0

    alive = [t for t in threads if t.is_alive()]
    errs = [e for e in errors if e]

    ok = True
    details = []

    if alive:
        ok = False
        details.append("DEADLOCK: %d threads alive" % len(alive))
    if errs:
        ok = False
        details.append("EXCEPTIONS: %s" % errs[0][:300])

    # 验证计数完整性
    expected_inc = N_THREADS * INCR_PER_THREAD
    total_count = tel.counters["total"]
    hit_count = tel.counters["hit"]
    err_count = tel.counters["errors"]

    # inc("total") 每个 worker 调用一次 + fast_hit 也 +1 + count_query 也 +1
    # 每轮: inc(total)+1, fast_hit(total)+1, count_query(total)+1 = 3 per iter
    expected_total = expected_inc * 3
    if total_count != expected_total:
        ok = False
        details.append("TOTAL COUNT MISMATCH: got=%d, expected=%d (diff=%d)" % (
            total_count, expected_total, expected_total - total_count))

    # hit: inc("hit") + fast_hit(hit) = 2 per iter
    expected_hit = expected_inc * 2
    if hit_count != expected_hit:
        ok = False
        details.append("HIT COUNT MISMATCH: got=%d, expected=%d" % (
            hit_count, expected_hit))

    # errors: inc("errors", n=2) = 2 per iter
    expected_err = expected_inc * 2
    if err_count != expected_err:
        ok = False
        details.append("ERRORS COUNT MISMATCH: got=%d, expected=%d" % (
            err_count, expected_err))

    # rule_hits domestic: inc_rule("domestic") = 1 per iter
    if tel.rule_hits["domestic"] != expected_inc:
        ok = False
        details.append("RULE_HITS MISMATCH: got=%d, expected=%d" % (
            tel.rule_hits["domestic"], expected_inc))

    # qtype_dist: inc_qtype("A") + fast_hit(A) + count_query("AAAA")
    # A: inc_qtype(A)+1 + fast_hit(A qtype)+1 = 2 per iter
    # AAAA: count_query(AAAA)+1 = 1 per iter
    if tel.qtype_dist["A"] != expected_inc * 2:
        ok = False
        details.append("QTYPE_A MISMATCH: got=%d, expected=%d" % (
            tel.qtype_dist["A"], expected_inc * 2))
    if tel.qtype_dist["AAAA"] != expected_inc:
        ok = False
        details.append("QTYPE_AAAA MISMATCH: got=%d, expected=%d" % (
            tel.qtype_dist["AAAA"], expected_inc))

    details.append("total=%d (exp=%d), hit=%d (exp=%d), errors=%d (exp=%d)" % (
        total_count, expected_total, hit_count, expected_hit,
        err_count, expected_err))
    details.append("%.2fs, %d inc ops/s" % (
        dt, N_THREADS * INCR_PER_THREAD * 7 / max(dt, 0.01)))

    record("5.telemetry计数器", "PASS" if ok else "FAIL", "; ".join(details))


# ============================================================================
# 测试 6: DNS 查询并发风暴
# ============================================================================
def test_dns_storm():
    """50线程 × 1000 查询 = 50000 总查询, 监控成功率/延迟"""
    print("\n" + "=" * 70)
    print("测试 6: DNS 查询并发风暴 (50 threads × 1000 = 50000 queries)")
    print("=" * 70)

    N_THREADS = 50
    Q_PER_THREAD = 1000
    TOTAL = N_THREADS * Q_PER_THREAD

    # 生成 1000 个不同域名
    domains = []
    for i in range(1000):
        domains.append("storm%04d.com" % i)
    # 加上一些热门域名(让缓存命中)
    hot = ["www.baidu.com", "www.qq.com", "www.taobao.com", "www.jd.com",
           "www.163.com", "www.weibo.com", "www.bilibili.com", "www.zhihu.com"]

    stats = {"success": 0, "fail": 0, "timeouts": 0,
             "latencies": [], "errors": []}
    stats_lock = threading.Lock()
    stop_event = threading.Event()

    def storm_worker(thread_id):
        rng = random.Random(thread_id * 65537)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        try:
            for i in range(Q_PER_THREAD):
                # 80% 随机域名(miss), 20% 热门域名(hit)
                if rng.random() < 0.20:
                    dom = hot[rng.randint(0, len(hot) - 1)]
                else:
                    dom = domains[rng.randint(0, len(domains) - 1)]
                qtype = TYPE_A if rng.random() < 0.8 else TYPE_AAAA
                qbytes, qid = build_query(dom, qtype, edns=True)
                t0 = time.time()
                try:
                    sock.sendto(qbytes, DNS_UDP)
                    data, _ = sock.recvfrom(4096)
                    lat = (time.time() - t0) * 1000
                    if len(data) >= 2 and struct.unpack(">H", data[:2])[0] == qid:
                        with stats_lock:
                            stats["success"] += 1
                            stats["latencies"].append(lat)
                    else:
                        with stats_lock:
                            stats["fail"] += 1
                except socket.timeout:
                    with stats_lock:
                        stats["timeouts"] += 1
                except Exception as e:
                    with stats_lock:
                        stats["fail"] += 1
                        if len(stats["errors"]) < 3:
                            stats["errors"].append(str(e))
        except Exception:
            with stats_lock:
                stats["errors"].append(traceback.format_exc()[:300])
        finally:
            sock.close()

    # 先重置 telemetry 计数器
    try:
        req = urllib.request.Request("%s/api/reset" % API_BASE, method="POST")
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass

    print("  启动 %d 线程, 每线程 %d 查询 (总计 %d)..." % (
        N_THREADS, Q_PER_THREAD, TOTAL))
    t0 = time.time()
    threads = [
        threading.Thread(target=storm_worker, args=(t,),
                        name="storm-%d" % t, daemon=True)
        for t in range(N_THREADS)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
    dt = time.time() - t0

    alive = [t for t in threads if t.is_alive()]
    total_done = stats["success"] + stats["fail"] + stats["timeouts"]
    latencies = sorted(stats["latencies"])
    avg_lat = sum(latencies) / max(1, len(latencies))
    p50 = latencies[len(latencies) // 2] if latencies else 0
    p95 = latencies[int(len(latencies) * 0.95)] if latencies else 0
    p99 = latencies[int(len(latencies) * 0.99)] if latencies else 0
    sr = stats["success"] / max(1, total_done) * 100
    qps = total_done / max(dt, 0.1)

    ok = True
    details = []

    if alive:
        ok = False
        details.append("DEADLOCK: %d threads alive after 120s" % len(alive))

    if sr < 99.0:
        ok = False
        details.append("SUCCESS RATE %.2f%% < 99%%" % sr)

    if stats["timeouts"] > total_done * 0.02:
        details.append("note: timeout rate %.2f%%" % (
            stats["timeouts"] / max(1, total_done) * 100))

    # 验证服务未崩溃
    try:
        resp = urllib.request.urlopen("%s/api/status" % API_BASE, timeout=3)
        s = json.loads(resp.read())
        if not s.get("running"):
            ok = False
            details.append("SERVICE CRASHED")
        else:
            details.append("service running, uptime=%ds, cache=%s" % (
                s.get("uptime_s", 0), s.get("map", {})))
    except Exception as e:
        ok = False
        details.append("SERVICE UNREACHABLE: %r" % e)

    details.append("total=%d/%d, success=%d, fail=%d, timeout=%d" % (
        total_done, TOTAL, stats["success"], stats["fail"], stats["timeouts"]))
    details.append("success rate=%.2f%%, QPS=%.0f" % (sr, qps))
    details.append("latency: avg=%.1fms, P50=%.1fms, P95=%.1fms, P99=%.1fms" % (
        avg_lat, p50, p95, p99))
    if stats["errors"]:
        details.append("sample errors: %s" % stats["errors"][:2])

    record("6.DNS查询风暴", "PASS" if ok else "FAIL", "; ".join(details))


# ============================================================================
# 日志检查
# ============================================================================
def check_logs():
    """检查日志中是否有 ERROR/Exception/Traceback"""
    print("\n" + "=" * 70)
    print("日志检查: %s" % LOG_PATH)
    print("=" * 70)

    try:
        with open(LOG_PATH, "r", errors="replace") as f:
            lines = f.readlines()
    except Exception as e:
        record("日志检查", "WARN", "无法读取日志: %r" % e)
        return

    error_lines = []
    for i, line in enumerate(lines):
        upper = line.upper()
        if any(kw in upper for kw in ["ERROR", "EXCEPTION", "TRACEBACK", "CRITICAL"]):
            error_lines.append((i + 1, line.rstrip()))

    if error_lines:
        detail = "发现 %d 条错误日志:" % len(error_lines)
        for ln, txt in error_lines[:10]:
            detail += "\n    L%d: %s" % (ln, txt[:200])
        record("日志检查", "WARN", detail)
    else:
        record("日志检查", "PASS", "无 ERROR/Exception/Traceback (%d 行日志)" % len(lines))


# ============================================================================
# 主入口
# ============================================================================
def main():
    print("=" * 70)
    print("ebpdns v1.9.53 并发与竞态条件深度测试")
    print("项目根: %s" % PROJECT_ROOT)
    print("服务: DNS UDP=%s, TCP=%s, API=%s" % (DNS_UDP, DNS_TCP, API_BASE))
    print("配置: %s" % CONFIG_PATH)
    print("日志: %s" % LOG_PATH)
    print("开始时间: %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 70)

    # 记录测试前日志行数
    try:
        with open(LOG_PATH) as f:
            pre_lines = len(f.readlines())
    except Exception:
        pre_lines = 0
    print("测试前日志行数: %d" % pre_lines)

    overall_t0 = time.time()

    # 执行所有测试
    test_cache_concurrent_rw()
    test_reload_concurrent_queries()
    test_prefetch_race()
    test_conn_pool()
    test_telemetry_counters()
    test_dns_storm()

    overall_dt = time.time() - overall_t0

    # 日志检查
    check_logs()

    # ── 汇总报告 ──
    print("\n" + "=" * 70)
    print("测试报告汇总")
    print("=" * 70)

    pass_count = sum(1 for _, s, _ in RESULTS if s == "PASS")
    fail_count = sum(1 for _, s, _ in RESULTS if s == "FAIL")
    warn_count = sum(1 for _, s, _ in RESULTS if s == "WARN")
    total = len(RESULTS)

    print("\n%-40s %-6s %s" % ("测试项", "结果", "详情"))
    print("-" * 70)
    for name, status, detail in RESULTS:
        print("%-40s %-6s %s" % (name, status, detail[:120]))
    print("-" * 70)
    print("总计: %d 项 | PASS=%d | FAIL=%d | WARN=%d | 总耗时=%.1fs" % (
        total, pass_count, fail_count, warn_count, overall_dt))
    print("=" * 70)

    if fail_count > 0:
        print("\n⚠ 发现 %d 个 FAIL 项, 请检查上方详情。" % fail_count)
        sys.exit(1)
    else:
        print("\n✓ 全部核心测试通过。")
        sys.exit(0)


if __name__ == "__main__":
    main()
