"""上游客户端：UDP / TCP / DoH / DoT。
query_upstream() 返回 (ok, response_bytes, latency_ms, err_str)。

2026-09-01 优化:
  - UDP: 校验响应源地址与 qid (防 DNS 投毒/乱序)
  - DoH / DoT: 连接复用 (keep-alive), 避免高频查询下每次 TLS 握手
"""
import collections
import http.client
import logging
import os
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
# 缓存条目格式: host -> (ip, monotonic_ts); 超 _BOOTSTRAP_TTL 视为陈旧重解析
_bootstrap_cache = {}
_bootstrap_lock = threading.Lock()
_BOOTSTRAP_TTL = 600.0  # 运行期补写的 bootstrap 缓存 TTL(秒), 防应用层陈旧 IP 无限钉住

# UDP 热路径上游 hostname 解析缓存: host -> (ip_set, expire_monotonic)
# miss 热路径每次 getaddrinfo 是阻塞的系统 DNS 解析, 必须带 TTL 缓存(300s)
_addr_cache = {}
_addr_cache_lock = threading.Lock()
_ADDR_CACHE_TTL = 300.0
_ADDR_CACHE_MAX = 256   # 安全上限: 上游 hostname 数量有限, 超限淘汰最旧项

# v1.9.76 2.3: 0x20 投毒防护按上游自适应降级。部分上游(或其 Anycast 后端)会把
# 查询名规范化为小写后回显, 导致 check_0x20 逐位失配 → 响应被误当投毒丢弃,
# 该上游所有查询超时。按上游统计连续失配次数, 连续 3 次后对该上游关闭 0x20
# 校验(直接接受 qid/源校验通过的响应), 并打日志。
_0x20_misses = {}       # up_id -> 连续失配次数
_0x20_disabled = set()  # up_id 已降级关闭 0x20 校验
_0x20_DISABLED_SINCE = {}  # v1.9.77 R5: up_id -> 降级时间戳(time.monotonic()), 用于 600s 自恢复
_0x20_FAIL_LIMIT = 3
_0x20_RECOVER_S = 600.0  # v1.9.77 R5: 降级后 10 分钟自动重新启用 0x20 校验
# v1.9.77 R4: _0x20_misses / _0x20_disabled 被多线程 _udp_query 并发读写, 裸 dict/set
# 读-改-写存在竞态(连续 +1 可能丢失), 统一用一把模块级锁保护。
_0x20_lock = threading.Lock()


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


def _is_v6(s):
    """v1.9.76 2.8: 判断字符串是否为 IPv6 地址(用于探测 socket 地址族选择)。"""
    try:
        socket.inet_pton(socket.AF_INET6, s)
        return True
    except OSError:
        return False


def bootstrap_resolve(host, bootstrap_dns="223.5.5.5:53", timeout=3):
    """用 UDP bootstrap DNS 解析 hostname，返回 IP 字符串或 None。

    不依赖系统 /etc/resolv.conf，直接向 bootstrap_dns 发 DNS 查询。
    结果缓存到 _bootstrap_cache，后续连接直接用 IP + SNI。
    """
    if not _is_hostname(host):
        return host  # 已经是 IP
    with _bootstrap_lock:
        hit = _bootstrap_cache.get(host)
        if hit is not None:
            ip_cached = hit[0] if isinstance(hit, tuple) else hit
            return ip_cached
    try:
        bp_host, _, bp_port = bootstrap_dns.partition(":")
        bp_port = int(bp_port) if bp_port else 53
        # 构造 A 查询
        labels = b"".join(bytes([len(p)]) + p.encode() for p in host.split("."))
        # v1.9.81: qid 随机化, 防盲打投毒(旧固定 0x1234 只需猜端口)
        qid = int.from_bytes(os.urandom(2), "big")
        q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack(">HH", 1, 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.settimeout(timeout)
            s.sendto(q, (bp_host, bp_port))
            data, _ = s.recvfrom(65535)
        finally:
            s.close()
        # v1.9.80: 校验 qid 与 rcode, 防伪造响应污染 bootstrap 缓存。
        if len(data) < 12:
            return None
        qid_resp = struct.unpack(">H", data[0:2])[0]
        if qid_resp != qid:
            return None
        rcode = data[3] & 0x0F
        if rcode != 0:
            return None
        # 解析响应中的 A 记录
        pos = 12
        # 跳过 question 区 qname: 与 answer 段一致地处理压缩指针(0xC0 首字节),
        # 否则某些转发器回压缩指针时 pos 会跳到包内随机位置, 后续解析错位静默失败。
        # 压缩指针占 2 字节; 字面量走到 null 终止符, else 内 pos+=1 已吃掉该 null。
        # 因此块结束后只需再跳 qtype(2)+qclass(2)=4 字节(原 while+pos+=5 等价)。
        if data[pos] & 0xC0:
            pos += 2
        else:
            while data[pos]:
                pos += data[pos] + 1
            pos += 1
        pos += 4  # 跳过 qtype + qclass
        ancount = struct.unpack(">H", data[6:8])[0]
        for _ in range(ancount):
            # 逐条越界断言: 畸形/截断响应在访问字段前先确认剩余长度,
            # 避免 data[pos] 越界抛 IndexError(虽被外层兜住, 但显式失败更稳)。
            if pos + 10 > len(data):
                break
            # 跳过 name（可能是压缩指针）
            if data[pos] & 0xC0:
                pos += 2
            else:
                while pos < len(data) and data[pos]:
                    pos += data[pos] + 1
                pos += 1
            if pos + 10 > len(data):
                break
            rtype = struct.unpack(">H", data[pos:pos+2])[0]
            rdlength = struct.unpack(">H", data[pos+8:pos+10])[0]
            if pos + 10 + rdlength > len(data):
                break
            if rtype == 1 and rdlength == 4:
                ip = socket.inet_ntoa(data[pos+10:pos+14])
                with _bootstrap_lock:
                    _bootstrap_cache[host] = (ip, time.monotonic())
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
    from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as _FutTimeout
    resolved = 0
    with ThreadPoolExecutor(max_workers=min(8, len(hosts))) as ex:
        futures = {ex.submit(bootstrap_resolve, h, bootstrap_dns, 2.0): h for h in hosts}
        try:
            for fut in as_completed(futures, timeout=total_timeout):
                try:
                    if fut.result():
                        resolved += 1
                except Exception:
                    pass
        except _FutTimeout:
            # v1.9.81: 超时未完成的任务取消, 避免 shutdown(wait=True) 阻塞
            for fut in futures:
                fut.cancel()
    return resolved


def _bootstrap_ip(host):
    """获取 hostname 的 bootstrap 缓存 IP，无缓存或过期返回 None。

    缓存条目为 (ip, monotonic_ts); 超 _BOOTSTRAP_TTL 视为陈旧, 返回 None
    触发重新解析(防应用层陈旧 IP 如 HTTP 421/CDN 迁 vhost 被无限钉住)。"""
    if not _is_hostname(host):
        return host
    now = time.monotonic()
    with _bootstrap_lock:
        hit = _bootstrap_cache.get(host)
        if hit is None:
            return None
        ip_cached = hit[0] if isinstance(hit, tuple) else hit
        if isinstance(hit, tuple) and (now - hit[1]) > _BOOTSTRAP_TTL:
            _bootstrap_cache.pop(host, None)
            return None
        return ip_cached


def _bootstrap_invalidate(host):
    """连接失败时失效 bootstrap 缓存条目。

    DoH/DoT 上游域名 IP 变更(CDN 调度/运营商切换)后, 旧缓存 IP 会持续
    create_connection 失败。清除该条目后, 下次建连 _bootstrap_ip 返回 None,
    回退系统 getaddrinfo 重新解析, 不必等熔断或重启。仅对 hostname 生效。
    v1.9.76: 同时清 _addr_cache(UDP 热路径 hostname 解析缓存), 否则 UDP 上游
    仍钉在旧 A 记录上继续失败。"""
    if not host or not _is_hostname(host):
        return
    with _bootstrap_lock:
        _bootstrap_cache.pop(host, None)
    with _addr_cache_lock:
        _addr_cache.pop(host, None)


def _bootstrap_set(host, ip):
    """连接成功(含 fallback 系统解析)后把 IP 写回 bootstrap 缓存。

    bootstrap 失效只清坏 IP; 正常解析出的新 IP 必须重建缓存, 否则该上游后续
    每次 DoH/DoT 建连都要再走一次阻塞 getaddrinfo(v1.9.66 引入的残余退化)。
    仅对 hostname 生效, 幂等覆盖旧值。缓存条目为 (ip, monotonic_ts),
    供 _bootstrap_ip 做 TTL 过期判断。"""
    if not host or not ip or host == ip or not _is_hostname(host):
        return
    with _bootstrap_lock:
        _bootstrap_cache[host] = (ip, time.monotonic())


def _resolve_host_once(host):
    """系统 getaddrinfo 解析 hostname, 返回首个 IPv4 地址或 None。

    用于 bootstrap 缓存失效后的一次性重建回写(非热路径, 允许短暂阻塞);
    结果由调用方经 _bootstrap_set 写回, 后续建连直接复用缓存 IP。"""
    if not host or not _is_hostname(host):
        return None
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return None
    for _fam, _stype, _proto, _canon, sa in infos:
        if sa and sa[0]:
            return sa[0]
    return None


def _host_port(up):
    addr = up.get("addr", "")
    # #4 port=None 时 int(None) 崩; up.get("port", 53) 仅在 key 缺失时回退,
    # 显式 port=null 会落到 int(None)。用 `or 53` 同时兜住 None 与缺失。
    port = int(up.get("port") or 53)
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
        """拿一个连接槽。返回 (conn_or_"NEW", entry); (None, None) 表示超时(池满)。
        惰性回收: 空闲超龄连接在取出时关闭丢弃(不归还池), 防连接泄漏。"""
        e = self.entry(key)
        if not e["sem"].acquire(timeout=timeout):
            return None, None
        try:
            with self._lock:
                now = time.monotonic()
                while e["conns"]:
                    c = e["conns"].popleft()
                    if self._idle_ok(c, now):
                        return c, e
                    try:
                        c.close()
                    except Exception:
                        pass
                return "NEW", e
        except Exception:
            e["sem"].release()
            return None, None

    def release(self, entry, conn):
        """按 entry 对象身份归还, 避免 discard 后同 key 新建 entry 导致 semaphore 错乱。"""
        if entry is None:
            if conn is not None:
                try: conn.close()
                except Exception: pass
            return
        # entry 已被 discard: 连接关闭, 不归还(旧 semaphore 已随 entry 丢弃)
        if entry.get("_discarded"):
            if conn is not None:
                try: conn.close()
                except Exception: pass
            return
        if conn is not None:
            with self._lock:
                try:
                    conn._ebpdns_last_use = time.monotonic()
                except Exception:
                    pass
                entry["conns"].append(conn)
        entry["sem"].release()

    def discard(self, key):
        """删除上游时回收该 key 的连接组(释放连接对象与信号量)。
        连接对象由 GC 回收(TCP/TLS 连接无显式 close 时由 socket 析构关闭)。"""
        with self._lock:
            e = self._entries.pop(key, None)
            if e is not None:
                e["_discarded"] = True
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
    防止 _pool 残留已删除上游的连接对象造成内存泄漏。

    v1.9.78 S1-1: 同时清理 _0x20 校验状态(_0x20_disabled/_0x20_misses/
    _0x20_DISABLED_SINCE) 与 _addr_cache(hostname 解析缓存)。此清理与 proto
    无关——UDP 上游的 _udp_query 同样按 up_id 写 _0x20_*, _addr_cache 同样按
    host 缓存解析结果; 若只在 doh/dot 分支清理, UDP/TCP 上游删除后这些状态会
    永久残留(内存泄漏 + 已删 up_id 永远不再参与 0x20 自恢复判据)。
    """
    up_id = up.get("id", "")
    if up_id:
        with _0x20_lock:
            _0x20_disabled.discard(up_id)
            _0x20_misses.pop(up_id, None)
            _0x20_DISABLED_SINCE.pop(up_id, None)
    host, port = _host_port(up)
    with _addr_cache_lock:
        _addr_cache.pop(host, None)

    proto = str(up.get("proto", "")).lower()
    if proto not in ("doh", "dot"):
        return
    path = "" if proto == "dot" else str(up.get("url") or DOH_DEFAULT_PATH)
    if path and not path.startswith("/"):
        path = "/" + path
    _pool.discard((proto, host, port, path))


def _doh_conn(host, port, timeout):
    """创建 DoH HTTPS 连接。

    若 hostname 已通过 bootstrap 预解析为 IP，用 IP 连接 + SNI=hostname，
    彻底摆脱系统 DNS 依赖；否则回退到 hostname 直连（系统 getaddrinfo）。

    注意: http.client.HTTPSConnection 不接受 server_hostname= 关键字(它固定用
    self.host 做 SNI), 直接传该 kwarg 会在构造期抛 TypeError。正确做法是
    手工建 TCP socket 连到 bootstrap IP, 再用 ssl.create_default_context()
    .wrap_socket(sock, server_hostname=host) 做 TLS 握手(证书仍按 hostname 校验,
    不能关成 CERT_NONE), 然后把 ssock 挂到 host=hostname 的 HTTPSConnection 上——
    这样 Host 头/SNI/证书校验全部按 hostname, 实际 TCP 走 bootstrap IP。
    """
    ip = _bootstrap_ip(host)
    if ip and ip != host:
        try:
            raw = socket.create_connection((ip, port), timeout=timeout)
        except OSError:
            # bootstrap IP 已失效(CDN 调度/IP 变更) → 失效缓存, 下次回退系统解析
            _bootstrap_invalidate(host)
            raise
        try:
            ctx = ssl.create_default_context()
            ssock = ctx.wrap_socket(raw, server_hostname=host)
        except Exception:
            try:
                raw.close()
            except Exception:
                pass
            _bootstrap_invalidate(host)
            raise
        conn = http.client.HTTPSConnection(host, port, timeout=timeout)
        conn.sock = ssock  # 复用已建 TLS 连接, 不再二次 connect
        return conn
    # fallback: 无可用 bootstrap 缓存 → 系统 getaddrinfo 解析一次。
    # 本次连接仍交还给 http.client(host) 自行建连(保持多 A 记录容错), 但新解析
    # 出的 IP 暂存为 pending, 待首次 exchange 成功后才写回缓存(首个 A 记录不可达
    # 时不缓存坏 IP)。
    resolved = _resolve_host_once(host)
    conn = http.client.HTTPSConnection(host, port, timeout=timeout)
    if resolved:
        conn._ebpdns_pending_bootstrap = resolved
    return conn


def _doh_query(up, query_bytes, timeout_ms):
    host, port = _host_port(up)
    path = up.get("url") or DOH_DEFAULT_PATH
    if not path.startswith("/"):
        path = "/" + path
    # key 含 path: 同一 host:port 不同 DoH 路径(如 NextDNS /4d5525 vs /dns-query)
    # 必须独立连接池, 否则复用连接会把请求发到错误路径
    key = ("doh", host, port, path)
    timeout = timeout_ms / 1000.0
    # H5: 进入函数即设总 deadline, 重试不再重发完整 timeout(原实现首败后
    # 重试用完整 timeout, 总耗时可达 2×timeout)。建连/收发均用剩余时间。
    deadline = time.monotonic() + timeout
    # H3: 经 bootstrap-IP 直连时, HTTPSConnection(ip, ...) 会把 IP 当 Host 头发送,
    # 反向代理/虚拟主机路由会失败; 必须手动把 Host 头设回原始域名。
    bp_ip = _bootstrap_ip(host)
    if bp_ip and bp_ip != host:
        headers = dict(_DOH_HEADERS)
        headers["Host"] = host
    else:
        headers = _DOH_HEADERS

    def _remaining():
        return deadline - time.monotonic()

    # 连接槽获取带超时: 池满(4 连接都在忙)时等待, 不无限阻塞
    got, entry = _pool.acquire(key, timeout)
    if got is None:
        return False, None
    try:
        conn = None if got == "NEW" else got
        # 连接有效判据：HTTPConnection.sock 非 None（Python 3.10 无 is_connected()）
        if conn is None or getattr(conn, "sock", None) is None:
            rt = _remaining()
            if rt <= 0:
                _pool.release(entry, None)
                return False, None
            try:
                conn = _doh_conn(host, port, rt)
            except OSError:
                _pool.release(entry, None)
                return False, None
        try:
            conn.request("POST", path, body=query_bytes, headers=headers)
            resp = conn.getresponse()
            # v1.9.74 P2-2: 读上限 65536 并校验 <=65535, 与 DoT/QUIC 对齐,
            # 防上游异常返回超大 body 撑爆内存。
            body = resp.read(65536)
            if resp.status != 200 or not body or len(body) > 65535:
                try:
                    conn.close()
                except Exception:
                    pass
                _pool.release(entry, None)
                return False, None
            # v1.9.80: 上游要求 close 时不复用, 关闭后放回 None(下次新建)
            if getattr(resp, "will_close", False):
                try:
                    conn.close()
                except Exception:
                    pass
                _pool.release(entry, None)
            else:
                _pool.release(entry, conn)  # 复用成功，写回池
            # 首次 exchange 成功后才写回 fallback 解析出的 IP(防首条坏 A 记录入缓存)
            pb = getattr(conn, '_ebpdns_pending_bootstrap', None)
            if pb:
                _bootstrap_set(host, pb)
                conn._ebpdns_pending_bootstrap = None
            return True, body
        except (OSError, http.client.HTTPException):
            # 连接失效 → 关闭并一次性重试（新建连接），仅用剩余预算
            rt = _remaining()
            if rt <= 0:
                _pool.release(entry, None)
                return False, None
            try:
                conn.close()
            except Exception:
                pass
            try:
                conn = _doh_conn(host, port, rt)
                conn.request("POST", path, body=query_bytes, headers=headers)
                resp = conn.getresponse()
                body = resp.read(65536)  # P2-2: 同上读上限+长度校验
                if resp.status != 200 or not body or len(body) > 65535:
                    try:
                        conn.close()
                    except Exception:
                        pass
                    _pool.release(entry, None)
                    return False, None
                # v1.9.80: 同上, will_close 时不复用
                if getattr(resp, "will_close", False):
                    try:
                        conn.close()
                    except Exception:
                        pass
                    _pool.release(entry, None)
                else:
                    _pool.release(entry, conn)
                pb = getattr(conn, '_ebpdns_pending_bootstrap', None)
                if pb:
                    _bootstrap_set(host, pb)
                    conn._ebpdns_pending_bootstrap = None
                return True, body
            except (OSError, http.client.HTTPException):
                # 重试连接也失败: 该 conn 已损坏, 关闭后再归还槽位, 防 TLS socket 泄漏
                try:
                    conn.close()
                except Exception:
                    pass
                _pool.release(entry, None)
                return False, None
    except Exception as e:
        # 兜底: 任何异常路径都不泄漏连接槽; 若 conn 已建但未成功回池, 关闭防泄漏。
        # 必须记录异常类型与上游身份, 否则连接构造/请求期的非 OSError/HTTPException
        # 异常(如历史上的 server_hostname= TypeError)会被无声吞成 "query failed"。
        log.warning("DoH query unexpected error up=%s(%s proto=doh host=%s:%s): %s: %s",
                    up.get("id"), up.get("name"), host, port, type(e).__name__, e)
        try:
            try:
                if conn is not None:
                    conn.close()
            except Exception:
                pass
            _pool.release(entry, None)
        except Exception:
            pass
        return False, None


def _dot_conn(host, port, timeout):
    """创建 DoT TLS 连接。

    若 hostname 已通过 bootstrap 预解析为 IP，用 IP 连接 + SNI=hostname，
    彻底摆脱系统 DNS 依赖；否则回退到 hostname 直连（系统 getaddrinfo）。
    """
    ip = _bootstrap_ip(host)
    pending_resolved = None
    if not ip or ip == host:
        # bootstrap 缓存已失效/为空: 系统解析一次, 暂存 pending;
        # 待首次 exchange 成功后才写回(同 DoH fallback, 防首条坏 A 记录入缓存)。
        pending_resolved = _resolve_host_once(host)
    connect_host = ip if ip else host
    try:
        sock = socket.create_connection((connect_host, port), timeout=timeout)
    except OSError:
        # 经 bootstrap IP 直连失败 → 失效缓存, 下次回退系统 getaddrinfo 重解析
        if ip and ip != host:
            _bootstrap_invalidate(host)
        raise
    # 使用 ssl.create_default_context() 默认校验(含 CA 校验 + 主机名校验)。
    # hostname 上游: server_hostname=host 做 SNI, 证书按主机名校验。
    # 字面 IP 直连: 不能传 server_hostname=None 又保留默认 check_hostname=True
    # (会抛 ValueError: check_hostname requires server_hostname, 该异常非 OSError
    # 不会被内层 except OSError 接住, 落到外层裸 except 被静默吞)。改为: 仍
    # 校验证书链(CERT_REQUIRED 保持), 仅关闭主机名/SNI 校验(check_hostname=False)。
    # wrap_socket 抛异常时必须关闭原始 TCP socket, 否则 fd 泄漏。
    try:
        ctx = ssl.create_default_context()
        if _is_hostname(host):
            sock = ctx.wrap_socket(sock, server_hostname=host)
        else:
            ctx.check_hostname = False
            sock = ctx.wrap_socket(sock, server_hostname=None)
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        if ip and ip != host:
            _bootstrap_invalidate(host)
        raise
    # TLS 握手成功后暂存 pending bootstrap IP, 待首次 exchange 成功才写回缓存
    if pending_resolved:
        sock._ebpdns_pending_bootstrap = pending_resolved
    return sock


def _dot_query(up, query_bytes, timeout_ms):
    """DoT (DNS over TLS)：复用 TLS 连接组（多连接并发）。"""
    host, port = _host_port(up)
    key = ("dot", host, port, "")
    timeout = timeout_ms / 1000.0
    # H5: 总 deadline 控制重试预算, 首败后重试用剩余时间而非完整 timeout,
    # 避免总耗时达 2×timeout。
    deadline = time.monotonic() + timeout
    frame = tcp_frame(query_bytes)

    def _exchange(sock):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        sock.settimeout(remaining)
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

    got, entry = _pool.acquire(key, timeout)
    if got is None:
        return False, None
    try:
        sock = None if got == "NEW" else got
        if sock is None:
            rt = deadline - time.monotonic()
            if rt <= 0:
                _pool.release(entry, None)
                return False, None
            try:
                sock = _dot_conn(host, port, rt)
            except OSError:
                _pool.release(entry, None)
                return False, None
        try:
            msg = _exchange(sock)
            if msg is not None:
                _pool.release(entry, sock)  # 复用成功，写回池
                pb = getattr(sock, '_ebpdns_pending_bootstrap', None)
                if pb:
                    _bootstrap_set(host, pb)
                    sock._ebpdns_pending_bootstrap = None
                return True, msg
            try:
                sock.close()
            except Exception:
                pass
            _pool.release(entry, None)
            return False, None
        except OSError:
            rt = deadline - time.monotonic()
            if rt <= 0:
                _pool.release(entry, None)
                return False, None
            try:
                sock.close()
            except Exception:
                pass
            try:
                sock = _dot_conn(host, port, rt)
                msg = _exchange(sock)
                if msg is not None:
                    _pool.release(entry, sock)
                    pb = getattr(sock, '_ebpdns_pending_bootstrap', None)
                    if pb:
                        _bootstrap_set(host, pb)
                        sock._ebpdns_pending_bootstrap = None
                    return True, msg
                try:
                    sock.close()
                except Exception:
                    pass
                _pool.release(entry, None)
                return False, None
            except OSError:
                _pool.release(entry, None)
                return False, None
    except Exception as e:
        log.warning("DoT query unexpected error up=%s(%s proto=dot host=%s:%s): %s: %s",
                    up.get("id"), up.get("name"), host, port, type(e).__name__, e)
        try:
            try:
                if sock is not None:
                    sock.close()
            except Exception:
                pass
            _pool.release(entry, None)
        except Exception:
            pass
        return False, None


# ---------------- UDP / TCP ---------------- #
def _udp_query(up, query_bytes, timeout_ms):
    host, port = _host_port(up)
    up_id = up.get("id", "")
    # v1.9.77 R5: 0x20 降级后永不恢复是缺陷——上游被临时规范化大小写的中间设备
    # 误导后, 即使恢复正常也长期跳过 0x20 校验。这里在每次 UDP 查询开头检查:
    # 若已降级且距降级时间 > 600s, 自动从 disabled 移除并清零 misses, 重新启用校验。
    try:
        with _0x20_lock:
            _since = _0x20_DISABLED_SINCE.get(up_id)
            if _since is not None and (time.monotonic() - _since) > _0x20_RECOVER_S:
                _0x20_disabled.discard(up_id)
                _0x20_misses.pop(up_id, None)
                _0x20_DISABLED_SINCE.pop(up_id, None)
                log.info("上游 %s(%s) 0x20 降级已达 %.0fs, 自动重新启用 0x20 校验",
                         up.get("name"), up_id, _0x20_RECOVER_S)
    except Exception:
        pass
    try:
        qid = struct.unpack(">H", query_bytes[:2])[0]
    except Exception:
        qid = None
    # H-5: 根据目标地址族选择 socket family。原硬编码 AF_INET 导致 IPv6 上游
    # (如 2606:4700::1) sendto 抛 OSError 被静默吞掉、IPv6 UDP 上游永不工作。
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(fam, socket.SOCK_DGRAM)
    # 期望响应源 IP 集合: host 为域名时解析出全部 IP(A 记录可能多个,
    # 单值校验会误丢来自其他 IP 的响应); 解析失败则集合为空 → 不校验源,
    # 靠 qid(16bit 随机)兜底防投毒。
    expect_ips = set()
    send_addr = (host, port)
    if not _is_hostname(host):
        expect_ips.add(host)
    else:
        # 用带 TTL 的解析缓存拿到 IP 集合, 避免 miss 热路径阻塞 getaddrinfo。
        ips = _cached_udp_addrs(host)
        expect_ips = set(ips)
        if ips:
            # v1.9.74 P1-3: 直接向已解析出的 IP sendto, 不再把 hostname 交给
            # sendto(其会走系统解析/行为不确定)。多 IP 取集合首个(确定性, 不引入
            # 额外状态); expect_ips 仍用于响应源 IP 校验。
            send_addr = (next(iter(ips)), port)
    try:
        sock.sendto(query_bytes, send_addr)
        deadline = time.monotonic() + timeout_ms / 1000.0
        # H-5: 每轮 recvfrom 前按剩余时间重置超时。原实现 settimeout 只设一次,
        # 收到伪造/无关响应 continue 后, 下一轮 recvfrom 仍等完整 timeout, 总耗时
        # 可超 deadline 50% 甚至翻倍。改为剩余 deadline, 伪造响应不再延长等待。
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False, None
            sock.settimeout(remaining)
            try:
                # v1.9.76 2.6: recvfrom 65535。原 4096 上限在 UDP 大响应(DNSSEC/多 A
                # 记录/EDNS 放大)时截断响应, parse_message 报 truncated 触发无谓 TCP 回退,
                # 或直接解析失败被当投毒丢弃。EDNS UDP 可达上限即 65535。
                data, src = sock.recvfrom(65535)
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
            # v1.9.76 2.3: 已降级上游跳过校验; 失配按上游计数, 连续 3 次降级。
            # v1.9.77 R4: _0x20_misses/_0x20_disabled 全部走 _0x20_lock 串行化, 消除
            # 并发 read-modify-write 竞态。R5: 降级时记录时间戳供 600s 后自恢复。
            with _0x20_lock:
                x20_off = up_id in _0x20_disabled
            if not x20_off and not dnsmsg.check_0x20(query_bytes, data):
                with _0x20_lock:
                    _0x20_misses[up_id] = _0x20_misses.get(up_id, 0) + 1
                    if _0x20_misses[up_id] >= _0x20_FAIL_LIMIT and up_id not in _0x20_disabled:
                        _0x20_disabled.add(up_id)
                        _0x20_DISABLED_SINCE[up_id] = time.monotonic()
                        log.warning("上游 %s(%s) 连续 %d 次 0x20 大小写失配, 自动关闭 0x20 校验"
                                    "(疑似规范化大小写上游, %.0fs 后自动重试)",
                                    up.get("name"), up_id,
                                    _0x20_FAIL_LIMIT, _0x20_RECOVER_S)
                continue  # 大小写失配 = 伪造应答嫌疑, 丢弃继续等
            # 本查询收到 0x20 校验通过的响应 → 清零该上游连续失配计数
            with _0x20_lock:
                _0x20_misses[up_id] = 0
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
            # 与 _dot_conn 同型: hostname 上游 SNI=host 按主机名校验; 字面 IP 直连
            # 不能传 server_hostname=None 又开 check_hostname(必抛 ValueError)。
            # 当前两处调用方均传 use_tls=False(死代码), 此处仅消除潜伏陷阱。
            ctx = ssl.create_default_context()
            if _is_hostname(host):
                sock = ctx.wrap_socket(sock, server_hostname=host)
            else:
                ctx.check_hostname = False
                sock = ctx.wrap_socket(sock, server_hostname=None)
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
    """对候选 IP 发起一次快速 UDP DNS 探测（用于测速择优）。返回 RTT ms 或 None。
    v1.9.76 2.8: 按地址族选择 socket(原硬编码 AF_INET, IPv6 候选探测静默失败)。"""
    fam = socket.AF_INET6 if _is_v6(ip) else socket.AF_INET
    sock = socket.socket(fam, socket.SOCK_DGRAM)
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
    v1.9.76 2.8: 按地址族选择 socket(原硬编码 AF_INET, IPv6 候选探测静默失败)。"""
    fam = socket.AF_INET6 if _is_v6(ip) else socket.AF_INET
    sock = socket.socket(fam, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout_ms / 1000.0)
        t0 = time.monotonic()
        sock.connect((ip, port))
        return int((time.monotonic() - t0) * 1000)
    except OSError:
        return None
    finally:
        sock.close()
