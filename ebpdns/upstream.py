"""上游客户端：UDP / TCP / DoH / DoT。
query_upstream() 返回 (ok, response_bytes, latency_ms, err_str)。

2026-09-01 优化:
  - UDP: 校验响应源地址与 qid (防 DNS 投毒/乱序)
  - DoH / DoT: 连接复用 (keep-alive), 避免高频查询下每次 TLS 握手
"""
import collections
import http.client
import logging
import socket
import ssl
import struct
import threading
import time
from . import dnsmsg
from .dnsmsg import parse_tcp_frame, tcp_frame

log = logging.getLogger("ebpdns.upstream")

# DoH 默认路径（若配置未给 url）
DOH_DEFAULT_PATH = "/dns-query"
UA = "ebpdns/1.0 (Debian; SmartDNS-style resolver)"
# DoH 请求头常量: 避免每次查询新建 dict(http.client.request 会 copy)
_DOH_HEADERS = {
    "Content-Type": "application/dns-message",
    "Accept": "application/dns-message",
    "User-Agent": UA,
}

# ---------------- Bootstrap 解析器（摆脱系统 DNS 依赖） ----------------
# 启动时用 UDP 上游预解析 DoH/DoT hostname，缓存 IP；连接时用 IP + SNI
_bootstrap_cache = {}
_bootstrap_lock = threading.Lock()

# UDP 热路径上游 hostname 解析缓存: host -> (ip_set, expire_monotonic)
# miss 热路径每次 getaddrinfo 是阻塞的系统 DNS 解析, 必须带 TTL 缓存(300s)
_addr_cache = {}
_addr_cache_lock = threading.Lock()
_ADDR_CACHE_TTL = 300.0
_ADDR_CACHE_MAX = 256   # 安全上限: 上游 hostname 数量有限, 超限淘汰最旧项


def _cached_udp_addrs(host):
    """返回上游 hostname 的 IPv4 地址集合, 带 300s TTL 缓存。
    避免 UDP miss 热路径每次查询都阻塞调 getaddrinfo。
    内部存 frozenset 直接返回(只读), 避免每次调用拷贝 set。"""
    now = time.monotonic()
    with _addr_cache_lock:
        hit = _addr_cache.get(host)
        if hit and hit[1] > now:
            return hit[0]
    # 缓存未命中: 释放锁后做阻塞解析
    ips = set()
    try:
        for i in socket.getaddrinfo(host, None, socket.AF_INET):
            ips.add(i[4][0])
    except OSError:
        pass
    if ips:
        fs = frozenset(ips)
        with _addr_cache_lock:
            _addr_cache[host] = (fs, now + _ADDR_CACHE_TTL)
            # 安全上限: 超长运行/大量上游动态添加时防 dict 无限增长
            if len(_addr_cache) > _ADDR_CACHE_MAX:
                # 简单淘汰: 删除已过期或最旧的条目
                expired = [k for k, (_, exp) in _addr_cache.items() if exp <= now]
                for k in expired[:len(expired) // 2 + 1]:
                    _addr_cache.pop(k, None)
                if len(_addr_cache) > _ADDR_CACHE_MAX:
                    # 仍超限: 删除前 1/4 最旧项
                    sorted_items = sorted(_addr_cache.items(), key=lambda kv: kv[1][1])
                    for k, _ in sorted_items[:len(sorted_items) // 4]:
                        _addr_cache.pop(k, None)
        return fs
    return frozenset()


def _is_hostname(s):
    """判断是否为 hostname（非 IP 地址）。"""
    try:
        socket.inet_pton(socket.AF_INET, s)
        return False
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, s)
        return False
    except OSError:
        pass
    return bool(s) and not s.startswith("[")


def bootstrap_resolve(host, bootstrap_dns="223.5.5.5:53", timeout=3):
    """用 UDP bootstrap DNS 解析 hostname，返回 IP 字符串或 None。

    不依赖系统 /etc/resolv.conf，直接向 bootstrap_dns 发 DNS 查询。
    结果缓存到 _bootstrap_cache，后续连接直接用 IP + SNI。
    """
    if not _is_hostname(host):
        return host  # 已经是 IP
    with _bootstrap_lock:
        if host in _bootstrap_cache:
            return _bootstrap_cache[host]
    try:
        bp_host, _, bp_port = bootstrap_dns.partition(":")
        bp_port = int(bp_port) if bp_port else 53
        # 构造 A 查询
        labels = b"".join(bytes([len(p)]) + p.encode() for p in host.split("."))
        q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack(">HH", 1, 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.settimeout(timeout)
            s.sendto(q, (bp_host, bp_port))
            data, _ = s.recvfrom(65535)
        finally:
            s.close()
        # 解析响应中的 A 记录
        pos = 12
        while data[pos]:
            pos += data[pos] + 1
        pos += 5  # 跳过 qname 结尾 + qtype+qclass
        ancount = struct.unpack(">H", data[6:8])[0]
        for _ in range(ancount):
            # 跳过 name（可能是压缩指针）
            if data[pos] & 0xC0:
                pos += 2
            else:
                while data[pos]:
                    pos += data[pos] + 1
                pos += 1
            rtype = struct.unpack(">H", data[pos:pos+2])[0]
            rdlength = struct.unpack(">H", data[pos+8:pos+10])[0]
            if rtype == 1 and rdlength == 4:
                ip = socket.inet_ntoa(data[pos+10:pos+14])
                with _bootstrap_lock:
                    _bootstrap_cache[host] = ip
                return ip
            pos += 10 + rdlength
    except Exception as e:
        log.debug("bootstrap resolve failed for %s: %r", host, e)
    return None


def bootstrap_resolve_all(upstreams, bootstrap_dns="223.5.5.5:53", total_timeout=5.0):
    """并发预解析所有 DoH/DoT 上游的 hostname，缓存 IP。

    使用线程池并发解析(替代串行), 总超时上限 total_timeout 秒,
    避免 bootstrap DNS 不可达时逐个超时导致启动延迟几十秒。
    解析失败的上游回退到系统 getaddrinfo（不影响启动）。
    """
    hosts = []
    for up in upstreams:
        proto = str(up.get("proto", "")).lower()
        if proto not in ("doh", "dot", "doh3", "doq"):
            continue
        host, _ = _host_port(up)
        if _is_hostname(host) and host not in hosts:
            hosts.append(host)
    if not hosts:
        return 0
    # 并发解析: 每个线程独立 socket, 单查询超时 2s, 总等待上限 total_timeout
    from concurrent.futures import ThreadPoolExecutor, as_completed
    resolved = 0
    with ThreadPoolExecutor(max_workers=min(8, len(hosts))) as ex:
        futures = {ex.submit(bootstrap_resolve, h, bootstrap_dns, 2.0): h for h in hosts}
        for fut in as_completed(futures, timeout=total_timeout):
            try:
                if fut.result():
                    resolved += 1
            except Exception:
                pass
    return resolved


def _bootstrap_ip(host):
    """获取 hostname 的 bootstrap 缓存 IP，无缓存返回 None。"""
    if not _is_hostname(host):
        return host
    with _bootstrap_lock:
        return _bootstrap_cache.get(host)


def _host_port(up):
    addr = up.get("addr", "")
    port = int(up.get("port", 53))
    if addr.startswith("["):
        # [v6]:port
        idx = addr.find("]")
        return addr[1:idx], port
    return addr, port


# ---------------- 连接复用池（DoH / DoT） ----------------
class _ConnPool:
    """按 (proto, host, port, path) 维护可复用连接组。

    每 key 最多 _MAX_CONN 个并发连接（BoundedSemaphore 控制), 并发查询可
    并行使用不同连接——旧版单连接单锁会把同上游 DoH/DoT 查询完全串行化
    (每次查询独占连接一个完整 HTTPS/TLS 往返, 高并发 miss 时全部排队)。
    """

    _MAX_CONN = 4
    _MAX_IDLE = 30.0   # 连接空闲超时(秒): 超龄空闲连接惰性回收, 防长期运行连接泄漏

    def __init__(self):
        self._lock = threading.Lock()
        self._entries = {}  # key -> {"conns": deque, "sem": BoundedSemaphore}

    def entry(self, key):
        with self._lock:
            e = self._entries.get(key)
            if e is None:
                e = {"conns": collections.deque(), "sem": threading.BoundedSemaphore(self._MAX_CONN)}
                self._entries[key] = e
            return e

    @staticmethod
    def _idle_ok(conn, now):
        """连接是否在空闲窗口内(未超龄)。连接对象打 _ebpdns_last_use 时间戳。"""
        try:
            last = getattr(conn, "_ebpdns_last_use", 0) or 0
            return (now - last) < _ConnPool._MAX_IDLE
        except Exception:
            return True

    def acquire(self, key, timeout):
        """拿一个连接槽。返回 "NEW" 表示可新建连接; None 表示超时(池满)。
        惰性回收: 空闲超龄连接在取出时关闭丢弃(不归还池), 防连接泄漏。"""
        e = self.entry(key)
        if not e["sem"].acquire(timeout=timeout):
            return None
        try:
            with self._lock:
                now = time.monotonic()
                while e["conns"]:
                    c = e["conns"].popleft()
                    if self._idle_ok(c, now):
                        return c
                    # 超龄: 关闭并继续取下一个
                    try:
                        c.close()
                    except Exception:
                        pass
                return "NEW"
        except Exception:
            e["sem"].release()
            return None

    def release(self, key, conn):
        e = self._entries.get(key)
        if e is None:
            return
        if conn is not None:
            with self._lock:
                try:
                    conn._ebpdns_last_use = time.monotonic()
                except Exception:
                    pass
                e["conns"].append(conn)
        e["sem"].release()

    def discard(self, key):
        """删除上游时回收该 key 的连接组(释放连接对象与信号量)。
        连接对象由 GC 回收(TCP/TLS 连接无显式 close 时由 socket 析构关闭)。"""
        with self._lock:
            e = self._entries.pop(key, None)
        if e is not None:
            try:
                for c in list(e.get("conns") or []):
                    try:
                        c.close()
                    except Exception:
                        pass
            except Exception:
                pass


_pool = _ConnPool()


def discard_upstream_conns(up):
    """删除上游时回收 DoH/DoT 连接池条目(按 proto/host/port/path key),
    防止 _pool 残留已删除上游的连接对象造成内存泄漏。"""
    proto = str(up.get("proto", "")).lower()
    if proto not in ("doh", "dot"):
        return
    host, port = _host_port(up)
    path = "" if proto == "dot" else str(up.get("url") or DOH_DEFAULT_PATH)
    if path and not path.startswith("/"):
        path = "/" + path
    _pool.discard((proto, host, port, path))


def _doh_conn(host, port, timeout):
    """创建 DoH HTTPS 连接。

    若 hostname 已通过 bootstrap 预解析为 IP，用 IP 连接 + SNI=hostname，
    彻底摆脱系统 DNS 依赖；否则回退到 hostname 直连（系统 getaddrinfo）。
    """
    ip = _bootstrap_ip(host)
    if ip and ip != host:
        # 用 IP 连接，SNI 设为原始 hostname（TLS 证书校验需要）
        return http.client.HTTPSConnection(ip, port, timeout=timeout, server_hostname=host)
    return http.client.HTTPSConnection(host, port, timeout=timeout)


def _doh_query(up, query_bytes, timeout_ms):
    host, port = _host_port(up)
    path = up.get("url") or DOH_DEFAULT_PATH
    if not path.startswith("/"):
        path = "/" + path
    # key 含 path: 同一 host:port 不同 DoH 路径(如 NextDNS /4d5525 vs /dns-query)
    # 必须独立连接池, 否则复用连接会把请求发到错误路径
    key = ("doh", host, port, path)
    timeout = timeout_ms / 1000.0
    headers = _DOH_HEADERS
    # 连接槽获取带超时: 池满(4 连接都在忙)时等待, 不无限阻塞
    got = _pool.acquire(key, timeout)
    if got is None:
        return False, None
    try:
        conn = None if got == "NEW" else got
        # 连接有效判据：HTTPConnection.sock 非 None（Python 3.10 无 is_connected()）
        if conn is None or getattr(conn, "sock", None) is None:
            try:
                conn = _doh_conn(host, port, timeout)
            except OSError:
                _pool.release(key, None)
                return False, None
        try:
            conn.request("POST", path, body=query_bytes, headers=headers)
            resp = conn.getresponse()
            body = resp.read()
            if resp.status != 200 or not body:
                try:
                    conn.close()
                except Exception:
                    pass
                _pool.release(key, None)
                return False, None
            _pool.release(key, conn)  # 复用成功，写回池
            return True, body
        except (OSError, http.client.HTTPException):
            # 连接失效 → 关闭并一次性重试（新建连接）
            try:
                conn.close()
            except Exception:
                pass
            try:
                conn = _doh_conn(host, port, timeout)
                conn.request("POST", path, body=query_bytes, headers=headers)
                resp = conn.getresponse()
                body = resp.read()
                if resp.status != 200 or not body:
                    try:
                        conn.close()
                    except Exception:
                        pass
                    _pool.release(key, None)
                    return False, None
                _pool.release(key, conn)
                return True, body
            except (OSError, http.client.HTTPException):
                _pool.release(key, None)
                return False, None
    except Exception:
        # 兜底: 任何异常路径都不泄漏连接槽
        try:
            _pool.release(key, None)
        except Exception:
            pass
        return False, None


def _dot_conn(host, port, timeout):
    """创建 DoT TLS 连接。

    若 hostname 已通过 bootstrap 预解析为 IP，用 IP 连接 + SNI=hostname，
    彻底摆脱系统 DNS 依赖；否则回退到 hostname 直连（系统 getaddrinfo）。
    """
    ip = _bootstrap_ip(host)
    connect_host = ip if ip else host
    sock = socket.create_connection((connect_host, port), timeout=timeout)
    # 使用 ssl.create_default_context() 默认校验(含 CA 校验 + 主机名校验)。
    # IP 直连场景通过 server_hostname=host 传 SNI, 证书校验仍按主机名进行。
    ctx = ssl.create_default_context()
    sock = ctx.wrap_socket(sock, server_hostname=host if _is_hostname(host) else None)
    return sock


def _dot_query(up, query_bytes, timeout_ms):
    """DoT (DNS over TLS)：复用 TLS 连接组（多连接并发）。"""
    host, port = _host_port(up)
    key = ("dot", host, port, "")
    timeout = timeout_ms / 1000.0
    frame = tcp_frame(query_bytes)

    def _exchange(sock):
        sock.settimeout(timeout)
        sock.sendall(frame)
        buf = bytearray()
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                return None
            buf.extend(chunk)
            # 接收缓冲上限: 防止畸形/恶意上游无限累积 chunk 导致内存爆炸
            if len(buf) > 65536:
                return None
            try:
                msg, _ = parse_tcp_frame(bytes(buf))
                return msg
            except Exception:
                continue

    got = _pool.acquire(key, timeout)
    if got is None:
        return False, None
    try:
        sock = None if got == "NEW" else got
        if sock is None:
            try:
                sock = _dot_conn(host, port, timeout)
            except OSError:
                _pool.release(key, None)
                return False, None
        try:
            msg = _exchange(sock)
            if msg is not None:
                _pool.release(key, sock)  # 复用成功，写回池
                return True, msg
            _pool.release(key, None)
            return False, None
        except OSError:
            # 连接失效 → 关闭重试一次
            try:
                sock.close()
            except Exception:
                pass
            try:
                sock = _dot_conn(host, port, timeout)
                msg = _exchange(sock)
                if msg is not None:
                    _pool.release(key, sock)
                    return True, msg
                _pool.release(key, None)
                return False, None
            except OSError:
                _pool.release(key, None)
                return False, None
    except Exception:
        try:
            _pool.release(key, None)
        except Exception:
            pass
        return False, None


# ---------------- UDP / TCP ---------------- #
def _udp_query(up, query_bytes, timeout_ms):
    host, port = _host_port(up)
    addr = (host, port)
    try:
        qid = struct.unpack(">H", query_bytes[:2])[0]
    except Exception:
        qid = None
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # 期望响应源 IP 集合: host 为域名时解析出全部 IP(A 记录可能多个,
    # 单值校验会误丢来自其他 IP 的响应); 解析失败则集合为空 → 不校验源,
    # 靠 qid(16bit 随机)兜底防投毒。
    expect_ips = set()
    if not _is_hostname(host):
        expect_ips.add(host)
    else:
        # 用带 TTL 的解析缓存, 避免 miss 热路径每次阻塞 getaddrinfo
        expect_ips = _cached_udp_addrs(host)
    try:
        sock.settimeout(timeout_ms / 1000.0)
        sock.sendto(query_bytes, addr)
        deadline = time.monotonic() + timeout_ms / 1000.0
        while time.monotonic() < deadline:
            try:
                data, src = sock.recvfrom(4096)
            except socket.timeout:
                return False, None
            # 校验源地址（域名 host 用解析 IP 集合; 解析失败则不校验源, 靠 qid 兜底）
            if expect_ips and src[0] not in expect_ips:
                continue
            if port and src[1] != port:
                continue
            if qid is not None and len(data) >= 2:
                rid = struct.unpack(">H", data[:2])[0]
                if rid != qid:
                    continue  # 响应 ID 不匹配，继续等待（防乱序/投毒）
            # DNS 0x20 投毒防护: 响应 question qname 大小写必须与查询一致
            # (仅对明文 UDP 生效; 查询未做 0x20 时全小写 qname 也通过)
            if not dnsmsg.check_0x20(query_bytes, data):
                continue  # 大小写失配 = 伪造应答嫌疑, 丢弃继续等
            return True, data
        return False, None
    except OSError:
        return False, None
    finally:
        sock.close()


def _tcp_query(up, query_bytes, timeout_ms, use_tls=False):
    host, port = _host_port(up)
    try:
        sock = socket.create_connection((host, port), timeout=timeout_ms / 1000.0)
    except OSError:
        return False, None
    try:
        if use_tls:
            # 默认证书校验: 不关闭 check_hostname/verify_mode
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host if _is_hostname(host) else None)
        sock.settimeout(timeout_ms / 1000.0)
        sock.sendall(tcp_frame(query_bytes))
        buf = bytearray()
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                return False, None
            buf.extend(chunk)
            if len(buf) > 65536:
                return False, None
            try:
                msg, rest = parse_tcp_frame(bytes(buf))
            except Exception:
                continue
            # 明文 TCP 同样做 0x20 校验(加密 DoT 无投毒面, 跳过)
            if not use_tls and not dnsmsg.check_0x20(query_bytes, msg):
                # 被投毒的这一帧丢弃并推进缓冲区到帧尾, 继续读取后续帧。
                # 原实现 buf 不推进: 下次 recv 追加后 parse_tcp_frame 仍反复解析
                # 同一帧, 0x20 持续失败, 直至 len(buf)>64KB 才返回 —— 等于白等。
                buf = bytearray(rest)
                continue
            return True, msg
    except OSError:
        return False, None
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _quic_available():
    try:
        from . import quic_upstream
        return quic_upstream.available()
    except Exception:
        return False


def _quic_query_doq(up, query_bytes, timeout_ms):
    from . import quic_upstream
    return quic_upstream.query_doq(up, query_bytes, timeout_ms)


def _quic_query_doh3(up, query_bytes, timeout_ms):
    from . import quic_upstream
    return quic_upstream.query_doh3(up, query_bytes, timeout_ms)


def query_upstream(up, query_bytes, timeout_ms=1500):
    """按上游协议发起一次查询。返回 (ok, response_bytes, latency_ms, err_str)。"""
    proto = str(up.get("proto", "udp")).lower()
    t0 = time.monotonic()
    try:
        if proto == "udp":
            ok, data = _udp_query(up, query_bytes, timeout_ms)
        elif proto == "tcp":
            ok, data = _tcp_query(up, query_bytes, timeout_ms, use_tls=False)
        elif proto == "dot":
            ok, data = _dot_query(up, query_bytes, timeout_ms)
        elif proto == "doh":
            ok, data = _doh_query(up, query_bytes, timeout_ms)
        elif proto in ("doq", "doh3"):
            if not _quic_available():
                return False, None, timeout_ms, "aioquic 未安装 (pip install aioquic)"
            if proto == "doq":
                ok, data, _lat, _e = _quic_query_doq(up, query_bytes, timeout_ms)
            else:
                ok, data, _lat, _e = _quic_query_doh3(up, query_bytes, timeout_ms)
        else:
            return False, None, timeout_ms, "unknown proto %s" % proto
    except Exception as e:
        return False, None, int((time.monotonic() - t0) * 1000), str(e)
    lat = int((time.monotonic() - t0) * 1000)
    if not ok:
        return False, None, lat, "query failed"
    return True, data, lat, None


def probe_ip(ip, query_bytes, timeout_ms=800):
    """对候选 IP 发起一次快速 UDP DNS 探测（用于测速择优）。返回 RTT ms 或 None。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout_ms / 1000.0)
        t0 = time.monotonic()
        sock.sendto(query_bytes, (ip, 53))
        sock.recvfrom(2048)
        return int((time.monotonic() - t0) * 1000)
    except OSError:
        return None
    finally:
        sock.close()


def probe_tcp(ip, port=443, timeout_ms=800):
    """对候选 IP 发起 TCP connect 探测（SmartDNS speed-check 风格, tcp:443）。

    更贴近真实访问路径；非特权即可（ICMP 才需 root）。返回 RTT ms 或 None。
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout_ms / 1000.0)
        t0 = time.monotonic()
        sock.connect((ip, port))
        return int((time.monotonic() - t0) * 1000)
    except OSError:
        return None
    finally:
        sock.close()
