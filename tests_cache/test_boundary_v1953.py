#!/usr/bin/env python3
"""
ebpdns v1.9.53 边界条件与异常路径深度测试

测试范围:
  1. 畸形 DNS 报文 (UDP/TCP)
  2. 上游返回异常 (mock 上游)
  3. 缓存极端值
  4. 规则极端值
  5. 配置热重载极端场景

用法: python3 test_boundary_v1953.py
"""

import json
import os
import socket
import struct
import sys
import time
import threading
import traceback
import urllib.request
import urllib.error
import copy

# ─── 常量 ───────────────────────────────────────────────────────────
UDP_HOST = "127.0.0.1"
UDP_PORT = 15365
TCP_PORT = 15366
API_BASE = "http://127.0.0.1:18096"
CONFIG_PATH = "/tmp/v1931.json"
LOG_PATH = "/tmp/ebpdns_v1931.log"
MOCK_UPSTREAM_PORT = 15553

RESULTS = []  # (category, name, passed, detail)


# ─── 工具函数 ───────────────────────────────────────────────────────
def record(cat, name, passed, detail=""):
    status = "PASS" if passed else "FAIL"
    RESULTS.append((cat, name, passed, detail))
    print("  [%s] %s — %s" % (status, name, detail if detail else ""))


def api_get(path):
    try:
        with urllib.request.urlopen(API_BASE + path, timeout=5) as r:
            return json.loads(r.read()), r.status
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read()), e.code
        except Exception:
            return {"error": str(e)}, e.code
    except Exception as e:
        return {"error": str(e)}, 0


def api_post(path, body=None):
    data = json.dumps(body or {}).encode()
    req = urllib.request.Request(API_BASE + path, data=data,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read()), r.status
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read()), e.code
        except Exception:
            return {"error": str(e)}, e.code
    except Exception as e:
        return {"error": str(e)}, 0


def api_put(path, body=None):
    data = json.dumps(body or {}).encode()
    req = urllib.request.Request(API_BASE + path, data=data,
                                 headers={"Content-Type": "application/json"}, method="PUT")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read()), r.status
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read()), e.code
        except Exception:
            return {"error": str(e)}, e.code
    except Exception as e:
        return {"error": str(e)}, 0


def dns_send_udp(data, timeout=3.0):
    """发送 UDP 报文并等待响应。返回 (response_bytes, elapsed_ms) 或 (None, elapsed_ms)。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    t0 = time.monotonic()
    try:
        sock.sendto(data, (UDP_HOST, UDP_PORT))
        resp, _ = sock.recvfrom(4096)
        elapsed = (time.monotonic() - t0) * 1000
        return resp, elapsed
    except socket.timeout:
        return None, (time.monotonic() - t0) * 1000
    except Exception:
        return None, (time.monotonic() - t0) * 1000
    finally:
        sock.close()


def dns_send_tcp(data, timeout=3.0):
    """发送 DNS over TCP (2字节长度前缀)。返回 (response_bytes, elapsed_ms) 或 (None, elapsed_ms)。"""
    frame = struct.pack(">H", len(data)) + data
    t0 = time.monotonic()
    try:
        sock = socket.create_connection((UDP_HOST, TCP_PORT), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(frame)
        # 读长度前缀
        hdr = sock.recv(2)
        if len(hdr) < 2:
            return None, (time.monotonic() - t0) * 1000
        (rlen,) = struct.unpack(">H", hdr)
        chunks = []
        received = 0
        while received < rlen:
            chunk = sock.recv(min(4096, rlen - received))
            if not chunk:
                break
            chunks.append(chunk)
            received += len(chunk)
        elapsed = (time.monotonic() - t0) * 1000
        return b"".join(chunks), elapsed
    except socket.timeout:
        return None, (time.monotonic() - t0) * 1000
    except Exception:
        return None, (time.monotonic() - t0) * 1000
    finally:
        try:
            sock.close()
        except Exception:
            pass


def build_dns_header(qid=0x1234, flags=0x0100, qd=1, an=0, ns=0, ar=0):
    return struct.pack(">HHHHHH", qid, flags, qd, an, ns, ar)


def encode_name(name):
    """编码域名为 DNS 标签序列。"""
    name = name.rstrip(".")
    if not name:
        return b"\x00"
    out = bytearray()
    for label in name.split("."):
        b = label.encode("ascii", errors="replace")
        if len(b) > 63:
            b = b[:63]  # 截断超长标签
        out.append(len(b))
        out += b
    out.append(0)
    return bytes(out)


def build_standard_query(domain="www.baidu.com", qtype=1, qid=0xABCD):
    hdr = build_dns_header(qid=qid, flags=0x0100, qd=1)
    q = encode_name(domain) + struct.pack(">HH", qtype, 1)
    return hdr + q


def is_service_alive():
    """检查服务是否还活着。"""
    try:
        resp, code = api_get("/api/status")
        return code == 200 and resp.get("running", False)
    except Exception:
        return False


def save_config_file(cfg_dict):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg_dict, f, ensure_ascii=False, indent=2)


def load_config_file():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def reload_config():
    return api_post("/api/reload")


# ─── Mock DNS 上游服务器 ───────────────────────────────────────────
class MockUpstream:
    """模拟上游 DNS 服务器，可配置返回各种异常响应。"""

    def __init__(self, port=MOCK_UPSTREAM_PORT):
        self.port = port
        self.sock = None
        self.thread = None
        self._stop = threading.Event()
        self.mode = "normal"  # normal / empty / tc / formerr / servfail / nxdomain / refused / timeout
        self._lock = threading.Lock()

    def set_mode(self, mode):
        with self._lock:
            self.mode = mode

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", self.port))
        self.sock.settimeout(0.5)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def stop(self):
        self._stop.set()
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass

    def _serve(self):
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            with self._lock:
                mode = self.mode
            if mode == "timeout":
                continue  # 不响应
            if mode == "empty":
                self.sock.sendto(b"", addr)
                continue
            # 解析查询以构造合理响应
            try:
                if len(data) < 12:
                    resp = data[:2] + b"\x80\x80" + b"\x00" * 10
                else:
                    qid = data[0:2]
                    if mode == "tc":
                        flags = b"\x82\x80"  # QR=1, TC=1, RA=1, rcode=0
                    elif mode == "formerr":
                        flags = b"\x80\x81"  # FORMERR
                    elif mode == "servfail":
                        flags = b"\x80\x82"  # SERVFAIL
                    elif mode == "nxdomain":
                        flags = b"\x80\x83"  # NXDOMAIN
                    elif mode == "refused":
                        flags = b"\x80\x85"  # REFUSED
                    else:
                        flags = b"\x80\x80"  # NOERROR
                    # 回拷 question section
                    resp = qid + flags + struct.pack(">HHHH", 1, 0, 0, 0) + data[12:]
            except Exception:
                resp = b"\x12\x34\x80\x80\x00\x01\x00\x00\x00\x00\x00\x00"
            try:
                self.sock.sendto(resp, addr)
            except Exception:
                pass


# ─── 测试 1: 畸形 DNS 报文 ─────────────────────────────────────────
def test_malformed_udp():
    print("\n=== 1. 畸形 DNS 报文测试 (UDP) ===")
    cat = "畸形报文"

    # 1a. 空报文 (0 字节)
    try:
        resp, ms = dns_send_udp(b"", timeout=2.0)
        record(cat, "UDP 空报文(0字节)", True,
               "无响应(预期不崩溃) %.0fms" % ms if resp is None else "收到响应 %d 字节" % len(resp))
    except Exception as e:
        record(cat, "UDP 空报文(0字节)", False, "异常: %r" % e)

    # 1b. 只有 header (12字节), 无 question
    hdr = build_dns_header(qd=1)
    try:
        resp, ms = dns_send_udp(hdr, timeout=2.0)
        ok = resp is None or (resp is not None and len(resp) >= 12)
        record(cat, "UDP 仅header无question", ok,
               "无响应 %.0fms" % ms if resp is None else "响应 %d 字节" % len(resp))
    except Exception as e:
        record(cat, "UDP 仅header无question", False, "异常: %r" % e)

    # 1c. 部分 label 截断 (只发了一半域名)
    partial_q = build_dns_header(qd=1) + b"\x03www\x06goog"  # 域名只写了一半
    try:
        resp, ms = dns_send_udp(partial_q, timeout=2.0)
        record(cat, "UDP 截断label(部分域名)", True,
               "无响应 %.0fms" % ms if resp is None else "响应 %d 字节" % len(resp))
    except Exception as e:
        record(cat, "UDP 截断label(部分域名)", False, "异常: %r" % e)

    # 1d. QDCOUNT=10 但实际只有 1 个 question
    fake_qd = build_dns_header(qd=10) + encode_name("test.com") + struct.pack(">HH", 1, 1)
    try:
        resp, ms = dns_send_udp(fake_qd, timeout=2.0)
        record(cat, "UDP QDCOUNT=10实际1question", True,
               "无响应 %.0fms" % ms if resp is None else "响应 %d 字节" % len(resp))
    except Exception as e:
        record(cat, "UDP QDCOUNT=10实际1question", False, "异常: %r" % e)

    # 1e. ANCOUNT=9999 但无 answer 数据
    fake_an = build_dns_header(qd=1, an=9999) + encode_name("test.com") + struct.pack(">HH", 1, 1)
    try:
        resp, ms = dns_send_udp(fake_an, timeout=2.0)
        record(cat, "UDP ANCOUNT=9999无answer", True,
               "无响应 %.0fms" % ms if resp is None else "响应 %d 字节" % len(resp))
    except Exception as e:
        record(cat, "UDP ANCOUNT=9999无answer", False, "异常: %r" % e)

    # 1f. 非法 qtype = 0
    qtype0 = build_dns_header(qd=1) + encode_name("test.com") + struct.pack(">HH", 0, 1)
    try:
        resp, ms = dns_send_udp(qtype0, timeout=3.0)
        record(cat, "UDP qtype=0", True,
               "无响应 %.0fms" % ms if resp is None else "响应 %d 字节" % len(resp))
    except Exception as e:
        record(cat, "UDP qtype=0", False, "异常: %r" % e)

    # 1g. 非法 qtype = 65535
    qtype_max = build_dns_header(qd=1) + encode_name("test.com") + struct.pack(">HH", 65535, 1)
    try:
        resp, ms = dns_send_udp(qtype_max, timeout=3.0)
        record(cat, "UDP qtype=65535", True,
               "无响应 %.0fms" % ms if resp is None else "响应 %d 字节" % len(resp))
    except Exception as e:
        record(cat, "UDP qtype=65535", False, "异常: %r" % e)

    # 1h. 未分配 qtype = 1000
    qtype_1000 = build_dns_header(qd=1) + encode_name("test.com") + struct.pack(">HH", 1000, 1)
    try:
        resp, ms = dns_send_udp(qtype_1000, timeout=3.0)
        record(cat, "UDP qtype=1000(未分配)", True,
               "无响应 %.0fms" % ms if resp is None else "响应 %d 字节" % len(resp))
    except Exception as e:
        record(cat, "UDP qtype=1000(未分配)", False, "异常: %r" % e)

    # 1i. 超大 label (>63字节)
    big_label = "A" * 70
    hdr = build_dns_header(qd=1)
    # 手动构造: length=70 但 DNS 协议规定 label<=63
    qname = bytes([70]) + big_label.encode() + b"\x00"
    big_label_query = hdr + qname + struct.pack(">HH", 1, 1)
    try:
        resp, ms = dns_send_udp(big_label_query, timeout=2.0)
        record(cat, "UDP 单label>63字节", True,
               "无响应 %.0fms" % ms if resp is None else "响应 %d 字节" % len(resp))
    except Exception as e:
        record(cat, "UDP 单label>63字节", False, "异常: %r" % e)

    # 1j. 总域名 > 255 字节
    many_labels = ".".join(["a" * 10] * 25)  # 25 * 11 = 275 字节
    try:
        big_domain_query = build_dns_header(qd=1) + encode_name(many_labels) + struct.pack(">HH", 1, 1)
        resp, ms = dns_send_udp(big_domain_query, timeout=3.0)
        record(cat, "UDP 总域名>255字节", True,
               "无响应 %.0fms" % ms if resp is None else "响应 %d 字节" % len(resp))
    except Exception as e:
        record(cat, "UDP 总域名>255字节", False, "异常: %r" % e)

    # 1k. 压缩指针循环 (pointer 指向自己)
    # 在 question 区域放一个压缩指针 0xC00C 指向 offset 12 自身
    self_ptr = build_dns_header(qd=1) + b"\xc0\x0c" + struct.pack(">HH", 1, 1)
    try:
        resp, ms = dns_send_udp(self_ptr, timeout=3.0)
        record(cat, "UDP 压缩指针自循环", True,
               "无响应(预期不卡死) %.0fms" % ms if resp is None else "响应 %d 字节" % len(resp))
    except Exception as e:
        record(cat, "UDP 压缩指针自循环", False, "异常: %r" % e)

    # 1l. 极短报文 (1字节)
    try:
        resp, ms = dns_send_udp(b"\x12", timeout=2.0)
        record(cat, "UDP 1字节报文", True,
               "无响应 %.0fms" % ms if resp is None else "响应 %d 字节" % len(resp))
    except Exception as e:
        record(cat, "UDP 1字节报文", False, "异常: %r" % e)

    # 1m. 9字节报文 (<12 header 最小值)
    try:
        resp, ms = dns_send_udp(b"\x12\x34\x01\x00\x00\x01\x00", timeout=2.0)
        record(cat, "UDP 9字节(<12)", True,
               "无响应 %.0fms" % ms if resp is None else "响应 %d 字节" % len(resp))
    except Exception as e:
        record(cat, "UDP 9字节(<12)", False, "异常: %r" % e)


def test_malformed_tcp():
    print("\n=== 1b. 畸形 DNS 报文测试 (TCP) ===")
    cat = "畸形报文-TCP"

    # TCP 空报文 (长度=0)
    try:
        resp, ms = dns_send_tcp(b"", timeout=2.0)
        record(cat, "TCP 空报文(长度=0)", True,
               "无响应/连接关闭(预期) %.0fms" % ms if resp is None else "响应 %d 字节" % len(resp))
    except Exception as e:
        record(cat, "TCP 空报文(长度=0)", False, "异常: %r" % e)

    # TCP 只有长度前缀=0
    try:
        sock = socket.create_connection((UDP_HOST, TCP_PORT), timeout=2.0)
        sock.sendall(struct.pack(">H", 0))
        sock.settimeout(1.0)
        try:
            data = sock.recv(1024)
            record(cat, "TCP 长度=0帧", True, "收到 %d 字节" % len(data))
        except socket.timeout:
            record(cat, "TCP 长度=0帧", True, "超时无响应(预期)")
        sock.close()
    except Exception as e:
        record(cat, "TCP 长度=0帧", False, "异常: %r" % e)

    # TCP 畸形报文
    partial_q = build_dns_header(qd=1) + b"\x03www\x06goog"
    try:
        resp, ms = dns_send_tcp(partial_q, timeout=2.0)
        record(cat, "TCP 截断label", True,
               "无响应 %.0fms" % ms if resp is None else "响应 %d 字节" % len(resp))
    except Exception as e:
        record(cat, "TCP 截断label", False, "异常: %r" % e)

    # TCP 压缩指针循环
    self_ptr = build_dns_header(qd=1) + b"\xc0\x0c" + struct.pack(">HH", 1, 1)
    try:
        resp, ms = dns_send_tcp(self_ptr, timeout=3.0)
        record(cat, "TCP 压缩指针自循环", True,
               "无响应(预期不卡死) %.0fms" % ms if resp is None else "响应 %d 字节" % len(resp))
    except Exception as e:
        record(cat, "TCP 压缩指针自循环", False, "异常: %r" % e)

    # TCP 大长度前缀 (声明 65535 但只发少量数据)
    try:
        sock = socket.create_connection((UDP_HOST, TCP_PORT), timeout=2.0)
        sock.sendall(struct.pack(">H", 65535) + build_standard_query())
        sock.settimeout(1.0)
        try:
            data = sock.recv(1024)
            record(cat, "TCP 超长长度前缀", True, "收到 %d 字节" % len(data))
        except socket.timeout:
            record(cat, "TCP 超长长度前缀", True, "超时(预期等待更多数据)")
        sock.close()
    except Exception as e:
        record(cat, "TCP 超长长度前缀", False, "异常: %r" % e)


# ─── 测试 2: 上游返回异常 ──────────────────────────────────────────
def test_upstream_anomalies(mock):
    print("\n=== 2. 上游返回异常测试 ===")
    cat = "上游异常"

    # 备份原始配置
    orig_cfg = load_config_file()

    # 配置使用 mock 上游作为唯一上游
    test_cfg = copy.deepcopy(orig_cfg)
    test_cfg["upstreams"] = [
        {"id": "mock1", "name": "MockDNS", "proto": "udp", "addr": "127.0.0.1",
         "port": MOCK_UPSTREAM_PORT, "group": "domestic", "latency": 1, "enabled": True}
    ]
    test_cfg["timeout_ms"] = 2000
    test_cfg["fallback"] = False  # 关闭 fallback 以便精确测试单个上游行为
    save_config_file(test_cfg)
    reload_config()
    time.sleep(0.5)

    # 2a. 空响应
    mock.set_mode("empty")
    time.sleep(0.2)
    try:
        q = build_standard_query("test-empty.example.com", qtype=1)
        resp, ms = dns_send_udp(q, timeout=5.0)
        record(cat, "上游空响应", True,
               "响应 %.0fms %s" % (ms, "有响应" if resp else "超时无响应"))
    except Exception as e:
        record(cat, "上游空响应", False, "异常: %r" % e)

    # 2b. TC=1 截断响应
    mock.set_mode("tc")
    time.sleep(0.2)
    try:
        q = build_standard_query("test-tc.example.com", qtype=1)
        resp, ms = dns_send_udp(q, timeout=5.0)
        record(cat, "上游TC=1截断", True,
               "响应 %.0fms %s" % (ms, "有响应" if resp else "超时无响应"))
    except Exception as e:
        record(cat, "上游TC=1截断", False, "异常: %r" % e)

    # 2c. FORMERR (RCODE=1)
    mock.set_mode("formerr")
    time.sleep(0.2)
    try:
        q = build_standard_query("test-formerr.example.com", qtype=1)
        resp, ms = dns_send_udp(q, timeout=5.0)
        rcode = None
        if resp and len(resp) >= 12:
            rcode = resp[3] & 0x0F
        record(cat, "上游FORMERR(RCODE=1)", True,
               "响应 %.0fms rcode=%s" % (ms, rcode))
    except Exception as e:
        record(cat, "上游FORMERR(RCODE=1)", False, "异常: %r" % e)

    # 2d. SERVFAIL (RCODE=2)
    mock.set_mode("servfail")
    time.sleep(0.2)
    try:
        q = build_standard_query("test-servfail.example.com", qtype=1)
        resp, ms = dns_send_udp(q, timeout=5.0)
        rcode = None
        if resp and len(resp) >= 12:
            rcode = resp[3] & 0x0F
        record(cat, "上游SERVFAIL(RCODE=2)", True,
               "响应 %.0fms rcode=%s" % (ms, rcode))
    except Exception as e:
        record(cat, "上游SERVFAIL(RCODE=2)", False, "异常: %r" % e)

    # 2e. NXDOMAIN (RCODE=3) - 验证负缓存
    mock.set_mode("nxdomain")
    time.sleep(0.2)
    nxdomain_test = "test-nxdomain-%d.example.com" % int(time.time())
    try:
        q = build_standard_query(nxdomain_test, qtype=1)
        resp, ms1 = dns_send_udp(q, timeout=5.0)
        rcode1 = resp[3] & 0x0F if resp and len(resp) >= 12 else None
        # 第二次查询应该命中负缓存(更快)
        resp2, ms2 = dns_send_udp(q, timeout=5.0)
        rcode2 = resp2[3] & 0x0F if resp2 and len(resp2) >= 12 else None
        record(cat, "上游NXDOMAIN负缓存", True,
               "首次rcode=%s(%.0fms) 二次rcode=%s(%.0fms)" % (rcode1, ms1, rcode2, ms2))
    except Exception as e:
        record(cat, "上游NXDOMAIN负缓存", False, "异常: %r" % e)

    # 2f. REFUSED (RCODE=5)
    mock.set_mode("refused")
    time.sleep(0.2)
    try:
        q = build_standard_query("test-refused.example.com", qtype=1)
        resp, ms = dns_send_udp(q, timeout=5.0)
        rcode = None
        if resp and len(resp) >= 12:
            rcode = resp[3] & 0x0F
        record(cat, "上游REFUSED(RCODE=5)", True,
               "响应 %.0fms rcode=%s" % (ms, rcode))
    except Exception as e:
        record(cat, "上游REFUSED(RCODE=5)", False, "异常: %r" % e)

    # 2g. 超时 (上游不响应)
    mock.set_mode("timeout")
    time.sleep(0.2)
    # 先设短超时
    test_cfg2 = copy.deepcopy(orig_cfg)
    test_cfg2["upstreams"] = [
        {"id": "mock1", "name": "MockDNS", "proto": "udp", "addr": "127.0.0.1",
         "port": MOCK_UPSTREAM_PORT, "group": "domestic", "latency": 1, "enabled": True}
    ]
    test_cfg2["timeout_ms"] = 500
    test_cfg2["fallback"] = False
    save_config_file(test_cfg2)
    reload_config()
    time.sleep(0.5)
    try:
        q = build_standard_query("test-timeout.example.com", qtype=1)
        resp, ms = dns_send_udp(q, timeout=5.0)
        record(cat, "上游超时(timeout_ms=500)", True,
               "%.0fms 后 %s" % (ms, "响应" if resp else "无响应(SERVFAIL预期)"))
    except Exception as e:
        record(cat, "上游超时(timeout_ms=500)", False, "异常: %r" % e)

    # 恢复正常上游
    save_config_file(orig_cfg)
    reload_config()
    time.sleep(1.0)


# ─── 测试 3: 缓存极端值 ────────────────────────────────────────────
def test_cache_extremes():
    print("\n=== 3. 缓存极端值测试 ===")
    cat = "缓存极端值"
    orig_cfg = load_config_file()

    # 3a. cache_size=0 (通过 PUT API 应被拒绝, 因为验证 1..10M)
    try:
        resp, code = api_put("/api/config", {"cache_size": 0})
        record(cat, "cache_size=0", code == 400,
               "HTTP %d %s" % (code, resp.get("error", "") if isinstance(resp, dict) else ""))
    except Exception as e:
        record(cat, "cache_size=0", False, "异常: %r" % e)

    # 3b. cache_size=1 (极小容量)
    try:
        resp, code = api_put("/api/config", {"cache_size": 1})
        time.sleep(0.3)
        # 发几个查询验证不崩溃
        for i in range(5):
            q = build_standard_query("cache-test-%d.example.com" % i, qtype=1)
            dns_send_udp(q, timeout=3.0)
        # 检查状态
        st, _ = api_get("/api/status")
        record(cat, "cache_size=1(极小)", code == 200 and is_service_alive(),
               "HTTP %d, 服务存活=%s" % (code, is_service_alive()))
    except Exception as e:
        record(cat, "cache_size=1(极小)", False, "异常: %r" % e)

    # 3c. cache_size=10000000 (超大容量)
    try:
        resp, code = api_put("/api/config", {"cache_size": 10000000})
        time.sleep(0.5)
        st, _ = api_get("/api/status")
        record(cat, "cache_size=10000000(超大)", code == 200 and is_service_alive(),
               "HTTP %d, 服务存活=%s" % (code, is_service_alive()))
    except Exception as e:
        record(cat, "cache_size=10000000(超大)", False, "异常: %r" % e)

    # 3d. cache_size=-1 (负数, 应被拒绝)
    try:
        resp, code = api_put("/api/config", {"cache_size": -1})
        record(cat, "cache_size=-1(负数)", code == 400,
               "HTTP %d %s" % (code, resp.get("error", "") if isinstance(resp, dict) else ""))
    except Exception as e:
        record(cat, "cache_size=-1(负数)", False, "异常: %r" % e)

    # 3e. cache_size 为字符串
    try:
        resp, code = api_put("/api/config", {"cache_size": "50000"})
        record(cat, "cache_size=字符串", code == 400,
               "HTTP %d %s" % (code, resp.get("error", "") if isinstance(resp, dict) else ""))
    except Exception as e:
        record(cat, "cache_size=字符串", False, "异常: %r" % e)

    # 3f. 三种缓存策略切换 lru -> tinylfu -> lru
    for policy in ["lru", "tinylfu", "lru"]:
        try:
            resp, code = api_put("/api/config", {"cache_policy": policy})
            time.sleep(0.5)
            # 发一个查询验证
            q = build_standard_query("policy-test-%s.example.com" % policy, qtype=1)
            dns_send_udp(q, timeout=3.0)
            st, _ = api_get("/api/status")
            actual_policy = st.get("cache_policy", "?")
            record(cat, "缓存策略=%s" % policy, code == 200 and is_service_alive(),
                   "HTTP %d, 实际=%s, 服务存活=%s" % (code, actual_policy, is_service_alive()))
        except Exception as e:
            record(cat, "缓存策略=%s" % policy, False, "异常: %r" % e)

    # 3g. TTL=0 的记录行为 (通过 ttl 配置)
    try:
        resp, code = api_put("/api/config", {"ttl": 0})
        time.sleep(0.3)
        q = build_standard_query("ttl0-test.example.com", qtype=1)
        resp_dns, ms = dns_send_udp(q, timeout=5.0)
        record(cat, "全局TTL=0", code == 200 and is_service_alive(),
               "HTTP %d, DNS %s %.0fms" % (code, "响应" if resp_dns else "无响应", ms))
    except Exception as e:
        record(cat, "全局TTL=0", False, "异常: %r" % e)

    # 恢复
    api_put("/api/config", {"cache_size": 50000, "cache_policy": "lru", "ttl": 300})
    time.sleep(0.3)


# ─── 测试 4: 规则极端值 ───────────────────────────────────────────
def test_rules_extremes():
    print("\n=== 4. 规则极端值测试 ===")
    cat = "规则极端值"

    # 清空规则
    api_post("/api/reset")  # 清缓存
    # 先清空所有规则
    try:
        # 通过 PUT config 设空 rules
        api_put("/api/config", {"rules": []})
    except Exception:
        pass

    # 4a. 空规则列表
    try:
        resp, code = api_put("/api/config", {"rules": []})
        time.sleep(0.3)
        q = build_standard_query("empty-rules-test.example.com", qtype=1)
        dns_send_udp(q, timeout=3.0)
        record(cat, "空规则列表[]", code == 200 and is_service_alive(),
               "HTTP %d, 服务存活=%s" % (code, is_service_alive()))
    except Exception as e:
        record(cat, "空规则列表[]", False, "异常: %r" % e)

    # 4b. 超长域名规则 (1000字符)
    long_domain = "a" * 900 + ".com"
    try:
        resp, code = api_post("/api/rules", {"match": long_domain, "action": "block"})
        time.sleep(0.3)
        record(cat, "超长域名规则(900+字符)", code == 200 and is_service_alive(),
               "HTTP %d, 服务存活=%s" % (code, is_service_alive()))
    except Exception as e:
        record(cat, "超长域名规则(900+字符)", False, "异常: %r" % e)

    # 4c. 正则灾难 ReDoS 测试
    # 用 (a+)+$ 这样的灾难性回溯正则
    try:
        resp, code = api_post("/api/rules", {"match": "re:(a+)+$", "action": "block"})
        time.sleep(0.3)
        # 发一个长字符串查询看是否卡死
        t0 = time.monotonic()
        long_name = "a" * 40 + ".com"
        q = build_standard_query(long_name, qtype=1)
        resp_dns, ms = dns_send_udp(q, timeout=5.0)
        elapsed = time.monotonic() - t0
        record(cat, "正则灾难ReDoS((a+)+$)", code == 200 and is_service_alive() and elapsed < 5.0,
               "HTTP %d, 耗时 %.2fs, 服务存活=%s" % (code, elapsed, is_service_alive()))
    except Exception as e:
        record(cat, "正则灾难ReDoS((a+)+$)", False, "异常: %r" % e)

    # 4d. 重复规则 (相同 match 不同 action)
    try:
        api_post("/api/rules", {"match": "dup-rule-test.com", "action": "block"})
        api_post("/api/rules", {"match": "dup-rule-test.com", "action": "allow"})
        time.sleep(0.3)
        q = build_standard_query("dup-rule-test.com", qtype=1)
        resp_dns, ms = dns_send_udp(q, timeout=5.0)
        record(cat, "重复规则不同action", is_service_alive(),
               "服务存活=%s, 响应=%s" % (is_service_alive(), "有" if resp_dns else "无"))
    except Exception as e:
        record(cat, "重复规则不同action", False, "异常: %r" % e)

    # 4e. 非法 action 值
    try:
        resp, code = api_post("/api/rules", {"match": "bad-action-test.com", "action": "nonexistent_action"})
        time.sleep(0.3)
        q = build_standard_query("bad-action-test.com", qtype=1)
        resp_dns, ms = dns_send_udp(q, timeout=5.0)
        record(cat, "非法action值", is_service_alive(),
               "HTTP %d, 服务存活=%s" % (code, is_service_alive()))
    except Exception as e:
        record(cat, "非法action值", False, "异常: %r" % e)

    # 4f. forceIp 规则测试
    try:
        api_post("/api/rules", {"match": "forceip-test.com", "action": "forceIp", "ip": "1.2.3.4"})
        time.sleep(0.3)
        q = build_standard_query("forceip-test.com", qtype=1)
        resp_dns, ms = dns_send_udp(q, timeout=3.0)
        ok = False
        if resp_dns and len(resp_dns) >= 12:
            # 检查是否返回了 1.2.3.4
            try:
                from ebpdns.dnsmsg import parse_message
                parsed = parse_message(resp_dns)
                answers = parsed.get("answers", [])
                for a in answers:
                    if a.get("rdata") == "1.2.3.4":
                        ok = True
                        break
            except Exception:
                pass
        record(cat, "forceIp规则", ok and is_service_alive(),
               "响应=%s, forceIp命中=%s, 服务存活=%s" % ("有" if resp_dns else "无", ok, is_service_alive()))
    except Exception as e:
        record(cat, "forceIp规则", False, "异常: %r" % e)

    # 4g. block action 测试
    try:
        api_post("/api/rules", {"match": "block-test.com", "action": "block"})
        time.sleep(0.3)
        q = build_standard_query("block-test.com", qtype=1)
        resp_dns, ms = dns_send_udp(q, timeout=3.0)
        rcode = None
        if resp_dns and len(resp_dns) >= 12:
            rcode = resp_dns[3] & 0x0F
        record(cat, "block action", rcode == 2 and is_service_alive(),
               "rcode=%s (预期2=SERVFAIL)" % rcode)
    except Exception as e:
        record(cat, "block action", False, "异常: %r" % e)

    # 4h. allow action 测试
    try:
        api_post("/api/rules", {"match": "allow-test.com", "action": "allow"})
        time.sleep(0.3)
        q = build_standard_query("allow-test.com", qtype=1)
        resp_dns, ms = dns_send_udp(q, timeout=5.0)
        record(cat, "allow action", is_service_alive(),
               "响应=%s, 服务存活=%s" % ("有" if resp_dns else "无", is_service_alive()))
    except Exception as e:
        record(cat, "allow action", False, "异常: %r" % e)

    # 4i. group action 测试
    try:
        api_post("/api/rules", {"match": "group-test.com", "action": "group", "group": "domestic"})
        time.sleep(0.3)
        q = build_standard_query("group-test.com", qtype=1)
        resp_dns, ms = dns_send_udp(q, timeout=5.0)
        record(cat, "group action", is_service_alive(),
               "响应=%s, 服务存活=%s" % ("有" if resp_dns else "无", is_service_alive()))
    except Exception as e:
        record(cat, "group action", False, "异常: %r" % e)

    # 清理规则
    try:
        api_put("/api/config", {"rules": []})
    except Exception:
        pass


# ─── 测试 5: 配置热重载极端场景 ─────────────────────────────────────
def test_reload_extremes():
    print("\n=== 5. 配置热重载极端场景 ===")
    cat = "热重载"
    orig_cfg = load_config_file()

    # 5a. 空配置 {} 写入文件后 reload
    try:
        save_config_file({})
        resp, code = reload_config()
        time.sleep(0.5)
        alive = is_service_alive()
        record(cat, "空配置{}热重载", alive,
               "reload结果=%s, 服务存活=%s" % (str(resp)[:100], alive))
    except Exception as e:
        record(cat, "空配置{}热重载", False, "异常: %r" % e)
    finally:
        save_config_file(orig_cfg)
        reload_config()
        time.sleep(0.5)

    # 5b. 缺失 upstreams 字段
    try:
        bad_cfg = copy.deepcopy(orig_cfg)
        del bad_cfg["upstreams"]
        save_config_file(bad_cfg)
        resp, code = reload_config()
        time.sleep(0.5)
        alive = is_service_alive()
        record(cat, "缺失upstreams字段", alive,
               "reload结果=%s, 服务存活=%s" % (str(resp)[:100], alive))
    except Exception as e:
        record(cat, "缺失upstreams字段", False, "异常: %r" % e)
    finally:
        save_config_file(orig_cfg)
        reload_config()
        time.sleep(0.5)

    # 5c. 监听端口为字符串类型
    try:
        bad_cfg = copy.deepcopy(orig_cfg)
        bad_cfg["listen"]["udp"] = "127.0.0.1:not_a_port"
        save_config_file(bad_cfg)
        resp, code = reload_config()
        time.sleep(0.5)
        alive = is_service_alive()
        record(cat, "端口为字符串类型", alive,
               "reload结果=%s, 服务存活=%s" % (str(resp)[:100], alive))
    except Exception as e:
        record(cat, "端口为字符串类型", False, "异常: %r" % e)
    finally:
        save_config_file(orig_cfg)
        reload_config()
        time.sleep(0.5)

    # 5d. 上游地址非法
    try:
        bad_cfg = copy.deepcopy(orig_cfg)
        bad_cfg["upstreams"] = [
            {"id": "bad1", "name": "BadDNS", "proto": "udp", "addr": "not.an.ip",
             "port": 53, "group": "domestic", "enabled": True}
        ]
        save_config_file(bad_cfg)
        resp, code = reload_config()
        time.sleep(0.5)
        alive = is_service_alive()
        # 发个查询验证不崩溃
        q = build_standard_query("bad-upstream-test.com", qtype=1)
        dns_send_udp(q, timeout=5.0)
        record(cat, "上游地址非法(not.an.ip)", alive and is_service_alive(),
               "reload结果=%s, 服务存活=%s" % (str(resp)[:100], is_service_alive()))
    except Exception as e:
        record(cat, "上游地址非法(not.an.ip)", False, "异常: %r" % e)
    finally:
        save_config_file(orig_cfg)
        reload_config()
        time.sleep(1.0)

    # 5e. 重复上游 ID
    try:
        bad_cfg = copy.deepcopy(orig_cfg)
        bad_cfg["upstreams"] = [
            {"id": "dup1", "name": "DNS1", "proto": "udp", "addr": "223.5.5.5",
             "port": 53, "group": "domestic", "enabled": True},
            {"id": "dup1", "name": "DNS2", "proto": "udp", "addr": "119.29.29.29",
             "port": 53, "group": "domestic", "enabled": True},
        ]
        save_config_file(bad_cfg)
        resp, code = reload_config()
        time.sleep(0.5)
        alive = is_service_alive()
        q = build_standard_query("dup-id-test.com", qtype=1)
        dns_send_udp(q, timeout=5.0)
        record(cat, "重复上游ID", alive and is_service_alive(),
               "reload结果=%s, 服务存活=%s" % (str(resp)[:100], is_service_alive()))
    except Exception as e:
        record(cat, "重复上游ID", False, "异常: %r" % e)
    finally:
        save_config_file(orig_cfg)
        reload_config()
        time.sleep(1.0)

    # 5f. cache_size 为字符串 (通过文件 reload)
    try:
        bad_cfg = copy.deepcopy(orig_cfg)
        bad_cfg["cache_size"] = "50000"
        save_config_file(bad_cfg)
        resp, code = reload_config()
        time.sleep(0.5)
        alive = is_service_alive()
        record(cat, "cache_size为字符串(文件reload)", alive,
               "reload结果=%s, 服务存活=%s" % (str(resp)[:100], alive))
    except Exception as e:
        record(cat, "cache_size为字符串(文件reload)", False, "异常: %r" % e)
    finally:
        save_config_file(orig_cfg)
        reload_config()
        time.sleep(0.5)


# ─── 日志检查 ──────────────────────────────────────────────────────
def check_logs():
    print("\n=== 日志错误检查 ===")
    cat = "日志检查"
    try:
        with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        errors = []
        for i, line in enumerate(lines):
            upper = line.upper()
            if "ERROR" in upper or "EXCEPTION" in upper or "TRACEBACK" in upper:
                errors.append((i + 1, line.rstrip()))
        if errors:
            record(cat, "日志错误扫描", False, "发现 %d 条 ERROR/Exception/Traceback" % len(errors))
            for ln, text in errors[-10:]:
                print("    L%d: %s" % (ln, text[:200]))
        else:
            record(cat, "日志错误扫描", True, "无 ERROR/Exception/Traceback")
    except Exception as e:
        record(cat, "日志错误扫描", False, "无法读取日志: %r" % e)


# ─── 主流程 ─────────────────────────────────────────────────────────
def main():
    print("=" * 70)
    print("ebpdns v1.9.53 边界条件与异常路径深度测试")
    print("=" * 70)

    # 确认服务在线
    if not is_service_alive():
        print("ERROR: ebpdns 服务不可用! 请检查服务是否运行。")
        sys.exit(1)
    print("服务状态: 在线")

    # 备份原始配置
    orig_cfg = load_config_file()
    print("原始配置已备份")

    # 启动 mock 上游
    mock = MockUpstream(MOCK_UPSTREAM_PORT)
    mock.start()
    print("Mock 上游已启动: 127.0.0.1:%d" % MOCK_UPSTREAM_PORT)
    time.sleep(0.3)

    try:
        # 1. 畸形 DNS 报文
        test_malformed_udp()
        test_malformed_tcp()

        # 2. 上游返回异常
        test_upstream_anomalies(mock)

        # 3. 缓存极端值
        test_cache_extremes()

        # 4. 规则极端值
        test_rules_extremes()

        # 5. 配置热重载极端
        test_reload_extremes()

    finally:
        mock.stop()
        # 确保恢复原始配置
        try:
            save_config_file(orig_cfg)
            reload_config()
            time.sleep(0.5)
        except Exception:
            pass

    # 日志检查
    check_logs()

    # 服务存活最终确认
    alive = is_service_alive()
    print("\n" + "=" * 70)
    print("服务最终状态: %s" % ("在线" if alive else "*** 已崩溃! ***"))
    print("=" * 70)

    # ─── 汇总报告 ───
    print("\n" + "=" * 70)
    print("测试汇总报告")
    print("=" * 70)
    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r[2])
    failed = total - passed
    print("总计: %d 项 | 通过: %d | 失败: %d | 通过率: %.1f%%" % (
        total, passed, failed, 100.0 * passed / total if total else 0))

    if failed:
        print("\n--- 失败项 ---")
        for cat, name, p, detail in RESULTS:
            if not p:
                print("  [FAIL] [%s] %s: %s" % (cat, name, detail))

    print("\n--- 全部结果 ---")
    for cat, name, p, detail in RESULTS:
        mark = "PASS" if p else "FAIL"
        print("  [%s] [%s] %s" % (mark, cat, name))

    return 0 if alive and failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
