#!/usr/bin/env python3
"""High-intensity DNS stress test for ebpdns.
Asyncio UDP-based, gradual concurrency ramp, mixed query types.
"""
import asyncio
import socket
import struct
import random
import time
import json
import statistics
import sys
from collections import defaultdict

DNS_HOST = '127.0.0.1'
DNS_PORT = 15365
DURATION = 320  # seconds (over 300 for safety)

# Query domain pools
CACHE_HIT_DOMAINS = [
    'www.baidu.com', 'www.qq.com', 'www.taobao.com', 'www.jd.com',
    'www.bilibili.com', 'www.weibo.com', 'www.zhihu.com', 'www.163.com',
    'www.sohu.com', 'www.sina.com.cn', 'www.alibaba.com', 'www.tmall.com',
]
RULE_DOMAINS = [
    'forceip-test.example.com',
    'block-test.example.com',
    'empty-group-test.example.com',
    '*.example.com',  # won't work as query, use actual subdomain
    'sub1.example.com',
    'sub2.example.com',
]
RANDOM_SUFFIX = ['.com', '.org', '.net', '.cn', '.io', '.dev']

def build_dns_query(domain, qtype=1):
    """Build a DNS query packet."""
    tid = random.randint(0, 65535)
    flags = 0x0100  # RD=1
    header = struct.pack('!HHHHHH', tid, flags, 1, 0, 0, 0)
    qname = b''.join(bytes([len(p)]) + p.encode() for p in domain.split('.')) + b'\x00'
    question = qname + struct.pack('!HH', qtype, 1)  # A, IN
    return tid, header + question

def pick_domain():
    r = random.random()
    if r < 0.70:
        return random.choice(CACHE_HIT_DOMAINS)
    elif r < 0.90:
        return random.choice(RULE_DOMAINS)
    else:
        return f'random-{random.randint(10000, 99999)}{random.choice(RANDOM_SUFFIX)}'

class DNSStressor:
    def __init__(self):
        self.latencies = []  # all successful query latencies in ms
        self.errors = 0
        self.timeouts = 0
        self.total_queries = 0
        self.start_time = None
        self.transport = None
        self.protocol = None
        self.pending = {}  # tid -> (send_time, future)

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if len(data) < 12:
            return
        tid = struct.unpack('!H', data[0:2])[0]
        if tid in self.pending:
            send_time, fut = self.pending.pop(tid)
            elapsed = (time.monotonic() - send_time) * 1000
            if not fut.done():
                fut.set_result(elapsed)

    def error_received(self, exc):
        self.errors += 1

    async def query_one(self):
        """Send one DNS query and wait for response."""
        domain = pick_domain()
        tid, pkt = build_dns_query(domain)
        loop = asyncio.get_event_loop()
        fut = loop.create_future()
        self.pending[tid] = (time.monotonic(), fut)
        self.transport.sendto(pkt, (DNS_HOST, DNS_PORT))
        self.total_queries += 1
        try:
            elapsed = await asyncio.wait_for(fut, timeout=2.0)
            self.latencies.append(elapsed)
            return True
        except asyncio.TimeoutError:
            self.timeouts += 1
            self.pending.pop(tid, None)
            return False
        except Exception:
            self.errors += 1
            self.pending.pop(tid, None)
            return False

    async def worker(self, worker_id, duration):
        """Worker loop that sends queries until duration expires."""
        end_time = time.monotonic() + duration
        while time.monotonic() < end_time:
            await self.query_one()

async def api_stressor(duration, api_port=18096):
    """Concurrent API stress test."""
    import urllib.request
    endpoints = ['/api/status', '/api/cache/stats', '/api/upstreams', '/api/health']
    api_latencies = []
    api_errors = 0
    api_total = 0
    end_time = time.monotonic() + duration

    async def api_worker(worker_id):
        nonlocal api_errors, api_total
        while time.monotonic() < end_time:
            ep = random.choice(endpoints)
            url = f'http://127.0.0.1:{api_port}{ep}'
            loop = asyncio.get_event_loop()
            t0 = time.monotonic()
            try:
                def fetch():
                    with urllib.request.urlopen(url, timeout=2) as resp:
                        return resp.read()
                await loop.run_in_executor(None, fetch)
                elapsed = (time.monotonic() - t0) * 1000
                api_latencies.append(elapsed)
                api_total += 1
            except Exception:
                api_errors += 1
                api_total += 1
            await asyncio.sleep(0.05)  # small delay between requests

    workers = [asyncio.create_task(api_worker(i)) for i in range(10)]
    await asyncio.gather(*workers)
    return api_latencies, api_errors, api_total

async def main():
    print(f"=== ebpdns Stress Test ===")
    print(f"Target: {DNS_HOST}:{DNS_PORT}, Duration: {DURATION}s")
    print()

    # Phase 1: Warmup (10s at 20 concurrent)
    print("[Phase 1] Warmup: 20 workers, 10s")
    stressor = DNSStressor()
    loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: stressor,
        remote_addr=(DNS_HOST, DNS_PORT)
    )
    stressor.transport = transport
    stressor.protocol = protocol

    warmup_workers = [asyncio.create_task(stressor.worker(i, 10)) for i in range(20)]
    await asyncio.gather(*warmup_workers)
    print(f"  Warmup queries: {stressor.total_queries}, errors: {stressor.errors}, timeouts: {stressor.timeouts}")
    stressor.latencies.clear()
    stressor.total_queries = 0
    stressor.errors = 0
    stressor.timeouts = 0

    # Phase 2: Ramp up to 50 concurrent (30s)
    print("[Phase 2] Ramp: 50 workers, 30s")
    t0 = time.monotonic()
    workers = [asyncio.create_task(stressor.worker(i, 30)) for i in range(50)]
    await asyncio.gather(*workers)
    elapsed = time.monotonic() - t0
    qps = stressor.total_queries / elapsed
    print(f"  Queries: {stressor.total_queries}, QPS: {qps:.0f}, errors: {stressor.errors}, timeouts: {stressor.timeouts}")

    # Phase 3: Sustained at 50 concurrent (140s)
    print("[Phase 3] Sustained: 50 workers, 140s")
    stressor.latencies.clear()
    stressor.total_queries = 0
    stressor.errors = 0
    stressor.timeouts = 0
    t0 = time.monotonic()
    workers = [asyncio.create_task(stressor.worker(i, 140)) for i in range(50)]
    await asyncio.gather(*workers)
    elapsed = time.monotonic() - t0
    qps = stressor.total_queries / elapsed
    print(f"  Queries: {stressor.total_queries}, QPS: {qps:.0f}, errors: {stressor.errors}, timeouts: {stressor.timeouts}")

    # Phase 4: Peak at 100 concurrent (140s)
    print("[Phase 4] Peak: 100 workers, 140s")
    stressor.latencies.clear()
    stressor.total_queries = 0
    stressor.errors = 0
    stressor.timeouts = 0
    t0 = time.monotonic()
    workers = [asyncio.create_task(stressor.worker(i, 120)) for i in range(100)]
    # Also run API stress in parallel
    api_task = asyncio.create_task(api_stressor(140))
    results = await asyncio.gather(*workers, api_task)
    api_latencies, api_errors, api_total = results[-1]
    elapsed = time.monotonic() - t0
    qps = stressor.total_queries / elapsed
    print(f"  Queries: {stressor.total_queries}, QPS: {qps:.0f}, errors: {stressor.errors}, timeouts: {stressor.timeouts}")
    print(f"  API: {api_total} requests, errors: {api_errors}")

    # Calculate percentiles
    transport.close()

    if stressor.latencies:
        lats = sorted(stressor.latencies)
        n = len(lats)
        p50 = lats[n // 2]
        p95 = lats[int(n * 0.95)]
        p99 = lats[int(n * 0.99)]
        avg = statistics.mean(lats)
        mn = lats[0]
        mx = lats[-1]
    else:
        p50 = p95 = p99 = avg = mn = mx = 0

    if api_latencies:
        api_lats = sorted(api_latencies)
        n = len(api_lats)
        api_p50 = api_lats[n // 2]
        api_p95 = api_lats[int(n * 0.95)]
        api_p99 = api_lats[int(n * 0.99)]
        api_avg = statistics.mean(api_lats)
    else:
        api_p50 = api_p95 = api_p99 = api_avg = 0

    total_elapsed = DURATION
    total_qps_all = (50*30 + 50*120 + 100*120) / (30+120+120)  # rough average

    report = {
        'dns': {
            'total_queries': stressor.total_queries,
            'qps_peak_100': round(qps, 0),
            'p50_ms': round(p50, 2),
            'p95_ms': round(p95, 2),
            'p99_ms': round(p99, 2),
            'avg_ms': round(avg, 2),
            'min_ms': round(mn, 3),
            'max_ms': round(mx, 2),
            'errors': stressor.errors,
            'timeouts': stressor.timeouts,
            'error_rate': round((stressor.errors + stressor.timeouts) / max(stressor.total_queries, 1) * 100, 4),
        },
        'api': {
            'total_requests': api_total,
            'p50_ms': round(api_p50, 2),
            'p95_ms': round(api_p95, 2),
            'p99_ms': round(api_p99, 2),
            'avg_ms': round(api_avg, 2),
            'errors': api_errors,
        },
        'config': {
            'duration_s': DURATION,
            'concurrency_peak': 100,
            'concurrency_sustained': 50,
        }
    }

    print()
    print("=== RESULTS ===")
    print(json.dumps(report, indent=2))

    # Save report
    with open('/tmp/stress_result.json', 'w') as f:
        json.dump(report, f, indent=2)

if __name__ == '__main__':
    asyncio.run(main())
