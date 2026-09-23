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
import atexit
from concurrent.futures import ThreadPoolExecutor
from . import dnsmsg, __version__
from .dnsmsg import parse_tcp_frame, tcp_frame

log = logging.getLogger("ebpdns.upstream")

# DoH 默认路径（若配置未给 url）
DOH_DEFAULT_PATH = "/dns-query"
# R28 P3-1: UA 版本号动态取自 __version__(原为硬编码 "ebpdns/1.0", 与实际 1.9.113
# 脱节)。随包版本自动更新, 避免后续版本升级再次过时。
UA = "ebpdns/%s (Debian; SmartDNS-style resolver)" % __version__
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
# R7 P3-1: 与 _ADDR_CACHE_MAX 对称, 防 _bootstrap_cache 无上限增长。上游 hostname
# 数量有限, 超长运行/动态增删时封顶并淘汰最旧条目。
_BOOTSTRAP_CACHE_MAX = 256

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

# R5 P2-1: 模块级 DNS 解析线程池。socket.getaddrinfo() 是无超时参数的阻塞系统
# 调用, 无法被应用层 deadline 中断。通过 ThreadPoolExecutor.submit + future.
# result(timeout) 做硬截断; 超时后 future 仍在后台运行但调用方已放弃。仅在冷
# 缓存/bootstrap IP 失效时触发, 热路径(缓存命中 IP)不走 getaddrinfo。
# R6 P3-3: 超时后被放弃的 future 仍在 worker 内跑完 getaddrinfo 才退出; 其结果
# 无人读取(调用方已 except 放弃), 且因 ips 为空不会写缓存 → 无陈旧缓存污染。
# 池 max_workers=4、队列无界: DNS 不可达时 4 个 worker 各自卡在 ~10s getaddrinfo,
# 期间新提交任务排队形成有界 backlog; worker 释放后队列自动排空(~10s 内),
# 任务均为小闭包内存占用低, 不构成无限增长或泄漏。
_DNS_RESOLVE_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="dns-resolve")
# R6 P2-2: ThreadPoolExecutor 的 worker 为非 daemon 线程, CPython 自身的 atexit
# 收尾会对每个 worker 做无超时 t.join()。若进程退出瞬间 worker 正阻塞在
# getaddrinfo(受 resolv.conf 控制, ~10s), 退出会被挂起最长 ~10s(systemd
# TimeoutStopSec 风险)。显式注册无等待 shutdown: 不等待在途 getaddrinfo、
# 取消未启动的排队 future, 由 OS 在进程退出时回收线程; wait=False 保证正常运行
# 路径完全不受影响(仅在解释器退出时触发一次)。
atexit.register(_DNS_RESOLVE_POOL.shutdown, wait=False, cancel_futures=True)


def _cached_udp_addrs(host, timeout=None):
    """返回上游 hostname 的 IPv4 地址集合, 带 300s TTL 缓存。
    避免 UDP miss 热路径每次查询都阻塞调 getaddrinfo。
    内部存 frozenset 直接返回(只读), 避免每次调用拷贝 set。
    R5 P2-1: 新增 timeout 参数, 冷缓存 miss 时用线程池硬截断 getaddrinfo。"""
    now = time.monotonic()
    with _addr_cache_lock:
        hit = _addr_cache.get(host)
        if hit and hit[1] > now:
            return hit[0]
    # R8 P3-1: timeout<=0 假值守卫。原实现 `fut.result(timeout=_resolve_timeout)
    # if _resolve_timeout else fut.result()` 在 timeout=0.0 时走 else 分支, 变成
    # 无超时 fut.result() 永久阻塞(0.0 在 Python 中为假值)。预算已耗尽时直接返回
    # 空集, 让上层 resolver 切换备用上游, 不提交线程池任务。缓存命中已在上方返回,
    # 此处仅兜住冷 miss 且预算耗尽的边界。
    if timeout is not None and timeout <= 0:
        return frozenset()
    # 缓存未命中: 释放锁后做阻塞解析
    ips = set()
    # R5 P2-1: 用线程池硬截断 getaddrinfo, 避免冷缓存时阻塞 10-20s 无视 deadline
    # R7 P2-3: 不再用 max(0.5, timeout) 超调小超时(用户配 timeout_ms=100 仍阻塞
    # 500ms, 5× 超调)。直接用调用方剩余预算做硬截断上限; 预算极小则尽快超时返回
    # 空集, 让上层走备用上游。timeout=None 表示无 deadline, 透传给 fut.result()。
    _resolve_timeout = timeout
    # R6 P2-1: 记录解析起点单调时钟, 供 A→AAAA 回退时按已消耗时间重算剩余预算。
    _t0 = time.monotonic()
    # P3-17: 先查 A 记录; 无 A 记录时尝试 AAAA 并合并, 记录日志告知管理员。
    # 原实现仅查 AF_INET, 纯 IPv6-only 上游 hostname 永远解析为空 → 静默不工作。
    try:
        fut = _DNS_RESOLVE_POOL.submit(socket.getaddrinfo, host, None, socket.AF_INET)
        infos = fut.result(timeout=_resolve_timeout) if _resolve_timeout else fut.result()
        for i in infos:
            ips.add(i[4][0])
    except Exception:
        pass
    if not ips:
        log.debug("UDP upstream %s has no A record, attempting AAAA", host)
        # R6 P2-1: A 查询已消耗部分(乃至全部)预算, AAAA 不得复用陈旧的
        # _resolve_timeout, 否则冷缓存 + DNS 慢路径总等待 = 2 × _resolve_timeout
        # (floor 0.5s 下最差 ≥1.0s, 违反统一 deadline 模型)。按已消耗时间重算剩余
        # 预算, 与 A 阶段共享同一硬预算; 下限 0.001s 与全文件 deadline 守卫对齐。
        if timeout is not None:
            aaaa_timeout = max(0.001, min(_resolve_timeout, timeout - (time.monotonic() - _t0)))
        else:
            aaaa_timeout = None
        try:
            fut = _DNS_RESOLVE_POOL.submit(socket.getaddrinfo, host, None, socket.AF_INET6)
            infos = fut.result(timeout=aaaa_timeout) if aaaa_timeout else fut.result()
            for i in infos:
                ips.add(i[4][0])
        except Exception:
            pass
        if ips:
            log.warning("UDP upstream %s has no A record, using AAAA (IPv6) only", host)
    if ips:
        fs = frozenset(ips)
        with _addr_cache_lock:
            # v1.9.84: 在锁内重新取 now, 避免从首次取 now 到加锁期间时间已流逝导致淘汰判据略旧
            now = time.monotonic()
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
        # R12 P3-2: strip IPv6 scope ID(如 fe80::1%eth0 的 %eth0 部分),
        # 否则 inet_pton(AF_INET6) 不支持 scope ID 会把 link-local IPv6 误判为 hostname。
        # 无 % 的正常 IPv6 地址 split 后仍为原串, 行为不变。
        socket.inet_pton(socket.AF_INET6, s.split('%')[0])
        return False
    except OSError:
        pass
    return bool(s) and not s.startswith("[")


def _is_v6(s):
    """v1.9.76 2.8: 判断字符串是否为 IPv6 地址(用于探测 socket 地址族选择)。"""
    try:
        # R26 P3-1: 与 _is_hostname() 对齐, 剥离 IPv6 scope ID(如 fe80::1%eth0),
        # 否则 inet_pton(AF_INET6) 不支持 scope ID, link-local 带 scope 的地址会被
        # 误判为非 v6(fam 选成 AF_INET)。无 % 的正常地址 split 后仍为原串, 行为不变。
        socket.inet_pton(socket.AF_INET6, s.split('%')[0])
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
            # P3-4: 命中缓存时对 tuple 条目做 TTL 校验, 过期则 pop 后继续走解析。
            # R31 P3-3: 旧版本直接存字符串 IP 的非 tuple 条目无时间戳, 此前跳过
            # TTL 检查导致永不过期(上游域名 IP 变更后钉死旧 IP)。统一按过期淘汰,
            # 走正常 tuple 解析路径重写缓存。
            if not isinstance(hit, tuple):
                _bootstrap_cache.pop(host, None)
            elif (time.monotonic() - hit[1]) > _BOOTSTRAP_TTL:
                _bootstrap_cache.pop(host, None)
            else:
                return hit[0]
    try:
        # R16 P3-3: 支持 [v6]:port 格式(如 [::1]:53)。原 partition(":") 对
        # IPv6 字面量会把 "[:" 切到 bp_host, 剩余 "::1]:53" 无法 int() 解析,
        # 异常被外层捕获后回退系统 DNS。与 _host_port() 的方括号解析对齐。
        if bootstrap_dns.startswith("["):
            idx = bootstrap_dns.find("]")
            bp_host = bootstrap_dns[1:idx]
            rest = bootstrap_dns[idx+1:]
            bp_port = int(rest[1:]) if rest.startswith(":") and rest[1:] else 53
        else:
            bp_host, _, bp_port = bootstrap_dns.partition(":")
            bp_port = int(bp_port) if bp_port else 53
        # v1.9.84: 按 bootstrap DNS 地址族选择 socket(原硬编码 AF_INET, IPv6 bootstrap 不可用)
        fam = socket.AF_INET6 if _is_v6(bp_host) else socket.AF_INET
        # 构造查询名; rstrip 尾点避免双重根标签。
        # R24 P3-3: bootstrap 路径直接在 UDP 上手工拼 DNS qname(线格式)。原实现用
        # host.encode()(UTF-8) 逐标签拼接: 非 ASCII 上游域名(IDN/中文域名)会在线上
        # 发送原始 UTF-8 字节而非 Punycode(xn--), 递归解析器无法识别; 且未校验单标签
        # ≤63 字节, 超长标签的长度八进制 >63 会与压缩指针标记(0xC0)冲突, 产生畸形
        # qname。这里先整名做 IDNA(Punycode) 转 ASCII, 再逐标签校验字节长度。任一步
        # 失败返回 None, 由调用方回退系统 getaddrinfo(其内部已正确处理 IDNA)。
        try:
            ascii_qname = host.rstrip(".").encode("idna")
        except UnicodeError:
            log.debug("bootstrap: IDNA 转换失败, 放弃 bootstrap 解析: %r", host)
            return None
        labels = b""
        for raw in ascii_qname.split(b"."):
            if len(raw) > 63:
                log.debug("bootstrap: 标签超长(%d>63), 放弃 bootstrap 解析: %r",
                          len(raw), host)
                return None
            labels += bytes([len(raw)]) + raw
        # R25 P3-1: RFC 1035 整名线格式(含各标签长度前缀字节与根零字节)总长 ≤255,
        # 4×63 字节标签会拼出 257 字节畸形 qname, 这里截断回退系统 getaddrinfo。
        if len(labels) + 1 > 255:
            log.debug("bootstrap: qname 线格式总长超长(%d>255), 放弃 bootstrap 解析: %r",
                      len(labels) + 1, host)
            return None

        def _ask(qtype):
            """向 bootstrap DNS 发一次 qtype 查询, 完成源地址/qid/rcode 校验后
            从 answer 段返回首条匹配的 IP 字符串(A: qtype=1 / AAAA: qtype=28),
            无匹配或校验失败返回 None。封装为闭包以支持 A 失败后回退 AAAA。"""
            # v1.9.81: qid 随机化, 防盲打投毒(旧固定 0x1234 只需猜端口)
            qid = int.from_bytes(os.urandom(2), "big")
            q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack(">HH", qtype, 1)
            # R38 P3-1: socket 构造移入 try 内, 与 R37 probe_ip/probe_tcp 范式对齐
            # (s=None 前置守卫 + 构造进 try + finally 守卫 close)。构造失败(EMFILE/
            # ENFILE)时 s 仍为 None, finally 不抛 NameError; 异常由外层 bootstrap_resolve
            # 的 except Exception 兜住返回 None。原实现构造在 try 外虽非泄漏(对象未创建
            # 即无泄漏), 但失去与 R37 防御范式的对称保护。
            s = None
            # R34 P3-1: 与热路径 _udp_query 对齐, 在 timeout 预算内循环 recvfrom。
            # 原实现单次 recvfrom 后 qid 失配即 return None, on-path 注入的一个错误
            # qid junk 包会被单次取走, 真实响应到达时 socket 已 close, 提前终结 bootstrap
            # 预热。改为对源 IP/端口/qid 失配的报文 continue 丢弃后继续等, 直至 deadline
            # 耗尽或超时。qid 随机化 + 源 IP/端口双校验保证 junk 不会被误当成功响应, 此处
            # 循环仅做抗乱序/抗 junk 可用性增强(失败仍有 _resolve_host_once 兜底)。
            deadline = time.monotonic() + timeout
            data = None
            src = None
            try:
                s = socket.socket(fam, socket.SOCK_DGRAM)
                s.settimeout(max(0.001, timeout))
                s.sendto(q, (bp_host, bp_port))
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return None
                    s.settimeout(max(0.001, remaining))
                    try:
                        data, src = s.recvfrom(65535)
                    except socket.timeout:
                        return None
                    # 源 IP/端口不符: 非本 bootstrap 流程的报文, 丢弃继续等。
                    if src[0] != bp_host or src[1] != bp_port:
                        continue
                    # qid 不符: 乱序/上一轮残留/junk 包, 丢弃继续等(与 _udp_query
                    # line 1583 continue 语义一致)。包长 <2 时无法解 qid, 直接交给
                    # 下方 len(data)<12 校验拒绝。
                    if len(data) >= 2 and struct.unpack(">H", data[0:2])[0] != qid:
                        continue
                    break
            finally:
                # R38 P3-1: s 可能因 socket.socket() 构造失败而为 None, 守卫避免 NameError。
                if s is not None:
                    s.close()
            # v1.9.84 UP-01 / R33 P3-1: 源 IP+端口双字段校验。R34 P3-1 重试循环已
            # 在 break 前完成同样校验, 此处保留为防御性 final check(代码自文档化安全不变量)。
            if src[0] != bp_host or src[1] != bp_port:
                return None
            # v1.9.80: 校验包长与 qid。循环内仅对 len>=2 的包比 qid, 故 2~11 字节
            # 畸形包会走到这里, 由 len(data)<12 拒绝; qid 校验保留为防御性 final check。
            if len(data) < 12:
                return None
            qid_resp = struct.unpack(">H", data[0:2])[0]
            if qid_resp != qid:
                return None
            rcode = data[3] & 0x0F
            if rcode != 0:
                return None
            # 解析响应中的答案记录
            pos = 12
            # R19 P3-1: 12 字节畸形响应(仅 DNS 头, 无 question 段)在 data[12] 处
            # 触发 IndexError(虽被外层 except 兜住)。上方 len(data)<12 放行恰好 12
            # 字节的包, 此处显式校验 question 区至少有 1 字节可解析, 长度不足直接
            # 返回 None, 避免越界。
            if pos >= len(data):
                return None
            # 跳过 question 区 qname: 与 answer 段一致地处理压缩指针(0xC0 首字节),
            # 否则某些转发器回压缩指针时 pos 会跳到包内随机位置, 后续解析错位静默失败。
            # 压缩指针占 2 字节; 字面量走到 null 终止符, else 内 pos+=1 已吃掉该 null。
            # 因此块结束后只需再跳 qtype(2)+qclass(2)=4 字节(原 while+pos+=5 等价)。
            if data[pos] & 0xC0:
                pos += 2
            else:
                while pos < len(data) and data[pos]:
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
                    return socket.inet_ntoa(data[pos+10:pos+14])
                # P3-05(R2): 同时解析 AAAA(rtype=28, 16 字节), 兼容 IPv6-only 上游
                # hostname。原实现仅处理 A 记录, 纯 IPv6 上游 bootstrap 返回 None,
                # 每次建连都退化走系统 getaddrinfo。
                if rtype == 28 and rdlength == 16:
                    return socket.inet_ntop(socket.AF_INET6, data[pos+10:pos+26])
                pos += 10 + rdlength
            return None

        # 优先 A 记录; 无 A 记录(IPv6-only 上游)再回退 AAAA。
        ip = _ask(1)
        if ip is None:
            ip = _ask(28)
        if ip is not None:
            with _bootstrap_lock:
                _bootstrap_cache[host] = (ip, time.monotonic())
            return ip
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
    # R16 P3-2: 不用 `with ThreadPoolExecutor(...)` context manager(其退出时
    # shutdown(wait=True) 会阻塞等待在途 socket recv 线程——单查询 2s 超时,
    # _ask(1) 失败后再 _ask(28) 最长 4s, 启动阶段总延迟从 total_timeout=5s
    # 拉长到 ~9s)。改为显式 shutdown(wait=False): 超时后函数立即返回, 在途线程
    # 为 ThreadPoolExecutor 的非 daemon worker, 但各自受 2s socket 超时硬限制
    # 自行退出, 无 fd/线程泄漏。
    ex = ThreadPoolExecutor(max_workers=min(8, len(hosts)))
    try:
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
    finally:
        # R16 P3-2: wait=False 不阻塞, 在途线程自行超时退出
        ex.shutdown(wait=False)
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
        # R31 P3-3: 旧版本直接存字符串 IP 的非 tuple 条目无时间戳, 此前跳过 TTL
        # 检查导致永不过期; 统一按过期淘汰, 回退系统 getaddrinfo 重解析。
        if not isinstance(hit, tuple):
            _bootstrap_cache.pop(host, None)
            return None
        if (now - hit[1]) > _BOOTSTRAP_TTL:
            _bootstrap_cache.pop(host, None)
            return None
        return hit[0]


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
        # R7 P3-1: 与 _addr_cache 对称的容量上限淘汰, 防 dict 无限增长。
        if len(_bootstrap_cache) > _BOOTSTRAP_CACHE_MAX:
            now = time.monotonic()
            # 先清已过期条目(超 TTL 的陈旧 IP)
            expired = [k for k, v in _bootstrap_cache.items()
                       if isinstance(v, tuple) and (now - v[1]) > _BOOTSTRAP_TTL]
            for k in expired:
                _bootstrap_cache.pop(k, None)
            if len(_bootstrap_cache) > _BOOTSTRAP_CACHE_MAX:
                # 仍超限: 按写入时间戳淘汰最旧的 1/4
                sorted_items = sorted(
                    _bootstrap_cache.items(),
                    key=lambda kv: kv[1][1] if isinstance(kv[1], tuple) else 0)
                for k, _ in sorted_items[:len(sorted_items) // 4]:
                    _bootstrap_cache.pop(k, None)


def _resolve_host_once(host, timeout=None):
    """系统 getaddrinfo 解析 hostname, 返回首个地址或 None。

    用于 bootstrap 缓存失效后的一次性重建回写(非热路径, 允许短暂阻塞);
    结果由调用方经 _bootstrap_set 写回, 后续建连直接复用缓存 IP。
    R5 P2-1: 新增 timeout 参数, 用线程池硬截断 getaddrinfo, 避免冷缓存时
    阻塞 10-20s 无视 deadline。超时返回 None, 上层走失败/回退路径。
    R6 P3-1: 先查 AF_INET; 无 A 记录时回退 AF_INET6, 使 IPv6-only 上游
    hostname 也能拿到 IP 直连。否则本函数返回 None → _dot_conn/_doh_conn
    退化为把 host 直接交给 create_connection, 其内部的 getaddrinfo 不受线程池
    硬截断保护(connect timeout 只控 TCP connect 阶段), 冷缓存仍可阻塞 ~10s。"""
    if not host or not _is_hostname(host):
        return None
    # R8 P3-1: 同 _cached_udp_addrs 的假值守卫。timeout=0.0 会被
    # `if _resolve_timeout` 判假导致 fut.result() 无超时阻塞。预算已耗尽直接
    # 返回 None, 不提交线程池任务, 让调用方走 fallback 路径。
    if timeout is not None and timeout <= 0:
        return None
    # R7 P2-3: 同 _cached_udp_addrs, 不再用 max(0.5, timeout) 超调小超时。
    # 直接用调用方剩余预算做硬截断上限; None 表示无 deadline 透传。
    _resolve_timeout = timeout
    _t0 = time.monotonic()
    try:
        fut = _DNS_RESOLVE_POOL.submit(
            socket.getaddrinfo, host, None, socket.AF_INET, socket.SOCK_STREAM)
        infos = fut.result(timeout=_resolve_timeout) if _resolve_timeout else fut.result()
        for _fam, _stype, _proto, _canon, sa in infos:
            if sa and sa[0]:
                return sa[0]
    except Exception:
        pass
    # AF_INET 无可用地址: 按已消耗时间重算剩余预算后回退 AF_INET6(共享同一硬预算)
    try:
        if timeout is not None:
            aaaa_timeout = max(0.001, min(_resolve_timeout, timeout - (time.monotonic() - _t0)))
        else:
            aaaa_timeout = None
        fut = _DNS_RESOLVE_POOL.submit(
            socket.getaddrinfo, host, None, socket.AF_INET6, socket.SOCK_STREAM)
        infos = fut.result(timeout=aaaa_timeout) if aaaa_timeout else fut.result()
        for _fam, _stype, _proto, _canon, sa in infos:
            if sa and sa[0]:
                return sa[0]
    except Exception:
        pass
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
        # P3-01(R2): acquire 触发全池回收的计数器(替代每次 acquire 的 os.urandom syscall)
        self._reclaim_counter = 0

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
        # P3-18: 约 1/10 概率触发一次全池空闲连接扫描回收, 避免每次 acquire 都
        # 扫描全部 entries 的开销; 长期不活跃上游的空闲连接(最多 _MAX_CONN 个 fd)
        # 不会因无人 checkout 而永远残留。
        # P3-01(R2): 用本地计数器替代 os.urandom(1)[0] % 10 —— 原实现每次 acquire
        # 都做一次 getrandom() 系统调用(热路径每查询一次 syscall)。改为纯内存自增,
        # 每 10 次 acquire 触发一次回收, 触发频率与原 1/10 随机一致。
        # R3-N3: 此计数器跨线程无锁 read-modify-write, 确认为无害的 best-effort:
        #   - 丢失自增(两线程同时读到同值) → 回收略稀疏(少触发一周期);
        #   - 重复/竞态(9→10→0 与另一线程的 9→10→0) → 回收略频繁或当周期触发两次;
        #   - Python int 无溢出, 不存在回绕到负或符号翻转;
        #   - reclaim_idle() 自身在 self._lock 内幂等执行, 重复调用只是多扫一遍空闲
        #     连接(连接未超龄即保留), 不会误关正在使用的连接;
        #   - 触发点在取锁之前(line 401 调用, 早于 line 407 取锁), 与 acquire 临界区
        #     不重入。
        # 因此无需加锁或改用 itertools.count(): 加锁反而在热路径引入争用, 与 P3-01
        # 去 syscall 的优化目标相悖。维持现状, 仅显式记录此安全权衡。
        self._reclaim_counter += 1
        if self._reclaim_counter >= 10:
            self._reclaim_counter = 0
            try:
                self.reclaim_idle()
            except Exception:
                pass
        if not e["sem"].acquire(timeout=timeout):
            return None, None
        try:
            with self._lock:
                now = time.monotonic()
                # R16 P3-1: discard 与 acquire 之间的极窄竞态——若本 entry 在
                # sem.acquire 等待期间被 discard() 弹出(_discarded=True)并关闭了
                # deque 中的全部连接, 则不再从中取已关闭连接。直接返回 "NEW" 让
                # 调用方新建; release() 见 _discarded=True 会直接关闭新连接并归还
                # 信号量(已有此路径, 语义安全)。窗口虽窄(微秒级)且调用方有
                # sock is None / OSError 自愈重试, 但加此检查可从源头杜绝取出
                # 已关闭连接, 无需额外锁。
                if e.get("_discarded"):
                    return "NEW", e
                while e["conns"]:
                    c = e["conns"].popleft()
                    # R3-N2/R4 P2-2: 降级弱校验连接(_ebpdns_degraded=True, 即
                    # check_hostname=False 的 DoT IP 字面量降级连接)不复用——直接关闭
                    # 丢弃。此类连接仅校验证书链而不校验主机名/SAN, 若进池复用会在
                    # _MAX_IDLE=30s 窗口内服务后续查询, 扩大残余 MITM 面。
                    # R4 P2-2: release() 已对 _ebpdns_degraded 连接直接 close 不入队,
                    # 此处检查为 defense-in-depth(防止历史版本/旁路将降级连接推入池)。
                    if getattr(c, "_ebpdns_degraded", False):
                        try:
                            c.close()
                        except Exception:
                            pass
                        continue
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
        """按 entry 对象身份归还, 避免 discard 后同 key 新建 entry 导致 semaphore 错乱。
        R4 P3-1: 整个方法体包 try/except, 保证 release 永不向上抛异常——否则调用方
        在 direct-return 路径上 release 后立即 return, 若 release 自身抛异常(如锁
        获取失败)会穿透到外层 except, 此时 released 仍为 False, 导致外层再次 release
        (double-release, BoundedSemaphore 计数溢出)。
        R4 P2-2: 降级弱校验连接(_ebpdns_degraded=True)即用即弃, 不进池复用。
        此类连接 check_hostname=False, 仅校验证书链而不校验主机名/SAN; 入池后即使
        acquire 时会被驱逐, 也会在 idle 窗口内残留 fd。直接关闭, 仅归还信号量槽位。
        """
        try:
            if entry is None:
                if conn is not None:
                    try: conn.close()
                    except Exception: pass
                return
            close_conn = False
            with self._lock:
                if entry.get("_discarded"):
                    close_conn = True
                elif conn is not None:
                    if getattr(conn, "_ebpdns_degraded", False):
                        close_conn = True
                    else:
                        try:
                            conn._ebpdns_last_use = time.monotonic()
                        except Exception:
                            pass
                        entry["conns"].append(conn)
            if close_conn and conn is not None:
                try: conn.close()
                except Exception: pass
            # v1.9.84 UP-02: discard 路径也必须释放信号量, 否则每个在途连接漏一个计数
            try: entry["sem"].release()
            except Exception as e:
                # R5 P3-1: sem.release() 溢出(ValueError)是 double-release 已发生的
                # 唯一运行时信号, 不能无声吞掉。记录 warning 以便诊断。
                log.warning("conn pool semaphore release error (possible double-release): %s", e)
        except Exception as e:
            # R5 P3-1: 原全局 except:pass 会吞掉 semaphore 溢出等真正的 bug 信号。
            # 改为 log.warning, 不改变控制流(仍不向上抛)但保留诊断信号。
            # R7 P3-6: 补异常类型名, 便于区分 OSError/KeyError/ValueError 等。
            log.warning("conn pool release error: %s: %s", type(e).__name__, e)

    def discard(self, key):
        """删除上游时回收该 key 的连接组(释放连接对象与信号量)。
        连接对象由 GC 回收(TCP/TLS 连接无显式 close 时由 socket 析构关闭)。"""
        with self._lock:
            e = self._entries.pop(key, None)
            if e is not None:
                e["_discarded"] = True
                # v1.9.84 UP-03: 在锁内快照待关闭连接, 避免释放锁后另一线程
                # 在 acquire 中 popleft 同一 deque 导致竞争
                to_close = list(e.get("conns") or [])
            else:
                to_close = []
        for c in to_close:
            try:
                c.close()
            except Exception:
                pass

    def reclaim_idle(self):
        """P3-18: 主动扫描全池, 关闭空闲超龄(idle > _MAX_IDLE)的空闲连接。
        原实现仅惰性回收(acquire 取出时判断), 长期不活跃上游的空闲连接会一直
        残留到进程退出(每 key 最多 _MAX_CONN 个 fd)。本方法由 acquire 以约 1/10
        概率触发, 开销可控; 扫描在锁内快照后关闭, 不持锁做 close 避免阻塞其他线程。
        注意: 仅关闭"空闲中"的连接(在 deque 里的), 正在被 checkout 使用的连接
        不在 deque 中, 不会被误关。"""
        now = time.monotonic()
        to_close = []
        with self._lock:
            for e in self._entries.values():
                if e.get("_discarded"):
                    continue
                conns = e.get("conns")
                if not conns:
                    continue
                # 反向遍历以安全地从 deque 中剔除超龄项
                keep = collections.deque()
                while conns:
                    c = conns.popleft()
                    # R3-N2: 降级弱校验连接即使在空闲窗口内也优先关闭, 不让其残留到
                    # 下次 acquire 才被发现关闭(acquire 见到同样会关, 但主动回收更早)。
                    if getattr(c, "_ebpdns_degraded", False) or not self._idle_ok(c, now):
                        to_close.append(c)
                    else:
                        keep.append(c)
                # 把仍在空闲窗口内的连接放回
                conns.extend(keep)
        for c in to_close:
            try:
                c.close()
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
    # P2-4: 删除上游时同步清理 bootstrap IP 缓存, 与 _addr_cache 清理对称。
    # 否则已删上游的旧 IP 会钉在缓存中, 下次重建同名上游时仍走旧 IP。
    with _bootstrap_lock:
        _bootstrap_cache.pop(host, None)

    proto = str(up.get("proto", "")).lower()
    if proto not in ("doh", "dot"):
        return
    path = "" if proto == "dot" else str(up.get("url") or DOH_DEFAULT_PATH)
    if path and not path.startswith("/"):
        path = "/" + path
    _pool.discard((proto, host, port, path))


def _doh_tls_wrap(raw, host, port, deadline, connect_addr, strict_cert=False):
    """DoH TLS 握手: 严格校验; 与 _dot_conn 对称地对 IP 字面量 + 仅 DNS SAN
    证书做 ssl.CertificateError → check_hostname=False 降级重试(仅一次)。

    R7 P2-1: DoT 路径(_dot_conn)对 IP 字面量 + 仅 DNS SAN 证书有 CertificateError
    降级, DoH 两处 wrap_socket 原先缺失, 这里补齐对称逻辑。降级连接标记
    _ebpdns_degraded=True, 防止入连接池复用(R3-N2/R4 P2-2: 池 release 见到该
    标记即直接 close 不入队)。hostname 上游证书必须严格匹配, 不降级。
    R8 P2-1: 新增 strict_cert kill switch(与 dot_strict_cert 对等)。True 时
    IP 字面量证书 SAN 校验失败也不降级, 直接抛出。默认 False 保持兼容。

    成功返回 ssock; 失败抛异常, 调用方负责关闭传入的 raw(降级路径内已自行
    close raw 并新建 raw2, 调用方再 close 为幂等无害)。
    """
    raw.settimeout(max(0.001, deadline - time.monotonic()))
    ctx = ssl.create_default_context()
    try:
        ssock = ctx.wrap_socket(raw, server_hostname=host)
        return ssock
    except ssl.CertificateError:
        # hostname 上游证书必须严格匹配, 不降级(与 _dot_conn 一致)
        if _is_hostname(host):
            # R8 P3-3: hostname 证书不匹配是真正的安全问题(非自托管 IP 字面量情形),
            # 打 warning 提示管理员, 不静默吞掉。
            log.warning(
                "DoH 上游 %s:%s hostname 证书校验失败(CertificateError), 拒绝降级"
                "(hostname 证书不匹配是真正的安全问题)。请检查证书是否过期/"
                "SAN 是否包含该域名。",
                host, port)
            raise
        # R8 P2-1: doh_strict_cert kill switch —— 与 dot_strict_cert 对等。
        # True 时 IP 字面量证书 SAN 校验失败也不降级, 直接抛出。默认 False 保持兼容。
        if strict_cert:
            log.warning(
                "DoH 上游 %s:%s doh_strict_cert=True, 证书主机名/SAN 校验失败"
                "且 kill switch 开启, 不降级直接报错。",
                host, port)
            raise
        log.warning(
            "DoH 上游 %s:%s 为 IP 字面量, 证书无匹配 IP SAN (疑似仅含 DNS SAN 的"
            "自托管证书), 已降级为跳过主机名/SAN 校验重试一次(证书链仍校验)。"
            "建议改用 hostname 上游, 或为该服务器配置含 IP SAN 的证书。",
            host, port)
        # 失败握手后底层 TCP/TLS 状态不可靠: 关闭旧 raw sock, 重建一条再宽松重试
        try:
            raw.close()
        except Exception:
            pass
        degraded_remaining = deadline - time.monotonic()
        if degraded_remaining <= 0:
            raise ssl.CertificateError("no budget left for degraded retry")
        raw2 = socket.create_connection(
            connect_addr, timeout=max(0.001, degraded_remaining))
        raw2.settimeout(max(0.001, deadline - time.monotonic()))
        ctx2 = ssl.create_default_context()
        ctx2.check_hostname = False  # 仅跳过主机名/SAN 匹配, 仍校验证书链
        try:
            # R8 P3-5: 进入本降级分支前已确认 host 为 IP 字面量(_is_hostname(host)
            # 为 False)。此处 server_hostname=host 传的是 IP 字符串作为 SNI —— 对 IP
            # 字面量而言 SNI 本无意义(TLS SNI 面向 hostname), 但 check_hostname=False
            # 已跳过主机名/SAN 校验, 传 IP 作 server_name 仅用于 OpenSSL 填充 SNI
            # 扩展(部分服务器容忍 IP SNI), 不影响安全性。这是有意设计: 保持与严格
            # 握手路径同一 server_hostname 入参, 避免引入分支差异。
            ssock2 = ctx2.wrap_socket(raw2, server_hostname=host)
        except Exception:
            try:
                raw2.close()
            except Exception:
                pass
            raise
        ssock2._ebpdns_degraded = True
        return ssock2


def _doh_conn(host, port, timeout, bp_ip=None, strict_cert=False):
    """创建 DoH HTTPS 连接。

    若 hostname 已通过 bootstrap 预解析为 IP，用 IP 连接 + SNI=hostname，
    彻底摆脱系统 DNS 依赖；否则回退到 hostname 直连（系统 getaddrinfo）。

    v1.9.84 UP-11: 新增 bp_ip 参数, 允许调用方传入已计算的 bootstrap IP,
    避免热路径上重复查询 _bootstrap_cache(减少一次锁竞争)。
    R4 P2-1: 入口统一设 deadline, 后续所有操作(bootstrap_ip 查询/阻塞 getaddrinfo/
    create_connection/wrap_socket/HTTPSConnection timeout)都按剩余预算扣减, 与
    DoT _dot_conn 及调用方 _doh_query 的 deadline 模型对齐。原实现首次建连用完整
    入参 timeout, 阻塞 getaddrinfo + create_connection(全预算) + wrap_socket(全
    预算) 三段叠加最坏超调 2×timeout + DNS解析。
    R8 P2-1: 新增 strict_cert kill switch, 透传给 _doh_tls_wrap。
    """
    # R4 P2-1: deadline 在函数入口即设定, 与调用方 _doh_query 的 deadline 同源
    deadline = time.monotonic() + timeout
    if bp_ip is None:
        bp_ip = _bootstrap_ip(host)
    ip = bp_ip
    if ip and ip != host:
        try:
            raw = socket.create_connection(
                (ip, port), timeout=max(0.001, deadline - time.monotonic()))
        except OSError:
            # bootstrap IP 已失效(CDN 调度/IP 变更) → 失效缓存, 下次回退系统解析
            _bootstrap_invalidate(host)
            raise
        try:
            # R7 P2-1: 经 helper 做严格 TLS 握手 + IP 字面量 CertificateError 降级。
            ssock = _doh_tls_wrap(raw, host, port, deadline, (ip, port),
                                  strict_cert=strict_cert)
        except Exception:
            try:
                raw.close()
            except Exception:
                pass
            _bootstrap_invalidate(host)
            raise
        # R5 P3-5: conn.sock 已预赋值为 ssock, connect() 不会被调用,
        # HTTPSConnection 的 timeout 参数是死存储。实际 socket 超时由调用方
        # conn.sock.settimeout() 控制(见 _doh_query)。不传 timeout。
        # R8 P3-2: HTTPSConnection(host, port) 构造仅做属性赋值, 不发起任何
        # 网络 I/O(连接延迟到 connect()/request() 才发生), 理论上不抛 OSError;
        # 且下方 conn.sock=ssock 已绕过 connect()。故此处不额外包 try/except,
        # 与本文件其他构造点保持一致。
        conn = http.client.HTTPSConnection(host, port)
        conn.sock = ssock  # 复用已建 TLS 连接, 不再二次 connect
        # R8 P1: 降级标记(_ebpdns_degraded)由 _doh_tls_wrap 打在 ssock 上, 但连接池
        # release()/acquire()/reclaim_idle() 检查的是外层 conn 对象的该属性。只打在
        # conn.sock 上池完全看不到, 会把 check_hostname=False 的降级连接归还池在 30s
        # 空闲窗口内反复复用, 架空"降级即弃"防护。这里把标记从 ssock 同步到外层 conn。
        conn._ebpdns_degraded = getattr(ssock, "_ebpdns_degraded", False)
        return conn
    # fallback: 无可用 bootstrap 缓存 → 系统 getaddrinfo 解析一次。
    # R6 P2: 若 _resolve_host_once 返回 IP, 复用上方 IP 直连 + TLS wrap 模式,
    # 避免 HTTPSConnection 内部无界 getaddrinfo(不受线程池硬截断保护)。
    resolved = _resolve_host_once(host, timeout=max(0.001, deadline - time.monotonic()))
    if resolved:
        raw = socket.create_connection(
            (resolved, port), timeout=max(0.001, deadline - time.monotonic()))
        try:
            # R7 P2-1: 同主路径, 经 helper 做严格握手 + CertificateError 降级。
            ssock = _doh_tls_wrap(raw, host, port, deadline, (resolved, port),
                                  strict_cert=strict_cert)
        except Exception:
            try:
                raw.close()
            except Exception:
                pass
            raise
        conn = http.client.HTTPSConnection(host, port)
        conn.sock = ssock
        # R8 P1: 同主路径, 把 ssock 上的降级标记同步到外层 conn, 供连接池识别即弃。
        conn._ebpdns_degraded = getattr(ssock, "_ebpdns_degraded", False)
        conn._ebpdns_pending_bootstrap = resolved
        return conn
    # R9 P1: IP 字面量上游(如自托管 DoH addr: 1.2.3.4)显式走 raw socket +
    # _doh_tls_wrap, 与 hostname 的 bootstrap/resolved 路径及 DoT _dot_conn 在
    # CertificateError 降级 + doh_strict_cert kill switch 上对等。原实现此处直接落
    # HTTPSConnection(host, port) 默认 context, 绕过 _doh_tls_wrap: 无降级、无
    # kill switch、无 CertificateError 日志, 导致仅含 DNS SAN 的自托管证书永远
    # query failed(DoT 同配置可正常降级)。_doh_tls_wrap 内部已对 IP 字面量做
    # check_hostname=False 降级重试(证书链仍校验), 此处只需把建连 raw 交给它;
    # 其内部 `if _is_hostname(host): raise` 对 IP 字面量为 False, 不会误 raise。
    if not _is_hostname(host):
        raw = socket.create_connection(
            (host, port), timeout=max(0.001, deadline - time.monotonic()))
        try:
            ssock = _doh_tls_wrap(raw, host, port, deadline, (host, port),
                                  strict_cert=strict_cert)
        except Exception:
            try:
                raw.close()
            except Exception:
                pass
            raise
        conn = http.client.HTTPSConnection(host, port)
        conn.sock = ssock  # 复用已建 TLS 连接, 不再二次 connect
        # R8 P1: 同主路径, 把 ssock 上的降级标记同步到外层 conn, 供连接池识别即弃。
        conn._ebpdns_degraded = getattr(ssock, "_ebpdns_degraded", False)
        # IP 字面量无 bootstrap 概念, 不挂 pending bootstrap(与 hostname resolved
        # 路径不同, 那个写 resolved 供首次成功后回写缓存)。
        conn._ebpdns_pending_bootstrap = None
        return conn
    # R7 P3-4: 解析失败(如 hostname 不存在/bootstrap+硬截断解析均超时) → 交还给
    # http.client(host) 自行建连。此处为最终 fallback, 其内部 getaddrinfo 不受
    # 线程池硬截断保护, 在 DNS 极不健康场景可能阻塞 ~10s。但触发本路径意味着
    # bootstrap 缓存与硬截断解析均已失败, 服务已处于降级状态, 阻塞风险可接受;
    # timeout 参数仍对 TCP connect 阶段生效。
    # R7 P3-8: IPv6 字面量 host 的 Host 头方括号由 http.client 内部 _wrap_ipv6
    # 自动处理(RFC 273), 与 QUIC 路径(quic line 446 手动补方括号)行为一致,
    # 此处无需手动设置 Host 头。
    conn = http.client.HTTPSConnection(
        host, port, timeout=max(0.001, deadline - time.monotonic()))
    # R12 P3-1: 本最终 fallback 路径绕过 _doh_tls_wrap, 其内部 connect() 遇
    # hostname CertificateError 时无 warning 日志, 与 _doh_tls_wrap 路径不对称。
    # 包装 connect() 以补齐对称 warning(hostname 证书不匹配是真正的安全问题)。
    _orig_connect = conn.connect
    def _fallback_connect():
        try:
            _orig_connect()
        except ssl.CertificateError:
            log.warning(
                "DoH 上游 %s:%s hostname 证书校验失败(CertificateError), 拒绝降级"
                "(hostname 证书不匹配是真正的安全问题)。请检查证书是否过期/"
                "SAN 是否包含该域名。",
                host, port)
            raise
    conn.connect = _fallback_connect
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
    # 上游级证书校验开关 doh_strict_cert: 默认 True(严格, 不降级)。
    # IP 字面量上游证书 SAN 校验失败时直接报错, 不做 check_hostname=False 重试,
    # 防止持有任意受信 CA 证书的 MITM 劫持 IP 直连 DoH。仅当确需兼容仅含 DNS SAN
    # 的自托管证书时, 显式在上游配置 "doh_strict_cert": false 才允许旧的降级行为
    # (降级连接即用即弃不入池, 证书链仍校验)。配置示例:
    #   - proto: doh
    #     addr: 1.2.3.4          # IP 字面量直连
    #     doh_strict_cert: false # 显式允许降级(默认 true, 不匹配即失败)
    strict_cert = bool(up.get("doh_strict_cert", True))
    # R31 P3-1: 经 bootstrap-IP 直连时, 底层 socket 已直连到 bp_ip, 但所有
    # HTTPSConnection 构造点仍传入原始域名 host(非 IP), HTTPConnection 据此自动
    # 生成的 Host 头本来就是域名。此处显式再设一次 Host 头作为 defense-in-depth:
    # 即使未来有人误把构造点改成 HTTPSConnection(ip, ...), 此守卫仍能把 Host 头
    # 校正回原始域名, 避免反向代理/虚拟主机路由失败。值与自动生成相同, 无功能影响。
    bp_ip = _bootstrap_ip(host)
    if bp_ip and bp_ip != host:
        headers = dict(_DOH_HEADERS)
        headers["Host"] = host
    else:
        headers = _DOH_HEADERS

    def _remaining():
        return deadline - time.monotonic()

    # 连接槽获取带超时: 池满(4 连接都在忙)时等待, 不无限阻塞。
    # P3-03(R2): 传剩余预算 _remaining() 而非完整 timeout —— 原实现信号量等待可
    # 耗尽整个预算, 后续 I/O 无剩余时间。用剩余预算让池等待与 I/O 共享同一 deadline。
    got, entry = _pool.acquire(key, _remaining())
    if got is None:
        return False, None
    conn = None
    released = False  # v1.9.84 UP-05: 跟踪连接槽是否已归还, 防外层 except double-release
    try:
        conn = None if got == "NEW" else got
        # 连接有效判据：HTTPConnection.sock 非 None（Python 3.10 无 is_connected()）
        if conn is None or getattr(conn, "sock", None) is None:
            rt = _remaining()
            if rt <= 0:
                _pool.release(entry, None)
                return False, None
            try:
                conn = _doh_conn(host, port, rt, bp_ip=bp_ip, strict_cert=strict_cert)
            except OSError:
                _pool.release(entry, None)
                return False, None
        try:
            # v1.9.84-r2: 连接池复用的 conn 保留其创建时的旧 socket 超时; 若不重置,
            # 挂起上游会阻塞到旧超时而非本次查询的剩余 deadline。创建路径(_doh_conn)
            # 已按 rt 设置, 此处对复用/新建统一再设一次当前剩余预算(幂等, 无副作用)。
            try:
                if getattr(conn, "sock", None) is not None:
                    # P3-16: 下限 0.001s 而非 0.05s, 减少 deadline 超调(剩余时间
                    # 本就很短时不应人为拉长到 50ms)。
                    conn.sock.settimeout(max(0.001, _remaining()))
            except Exception:
                pass
            conn.request("POST", path, body=query_bytes, headers=headers)
            resp = conn.getresponse()
            # v1.9.74 P2-2: 读上限 65536 并校验 <=65535, 与 DoT/QUIC 对齐,
            # 防上游异常返回超大 body 撑爆内存。
            body = resp.read(65536)
            # P3-5: 校验 Content-Type 必须为 application/dns-message(RFC 8484),
            # 非预期类型(如 HTML 错误页/重定向)按失败处理。
            # R7 P3-5: 子串匹配转小写, 兼容大写/混合大小写的 Content-Type(如
            # "Application/DNS-Message")。
            ctype = resp.getheader("Content-Type", "")
            if resp.status != 200 or not body or len(body) > 65535 or "application/dns-message" not in ctype.lower():
                if "application/dns-message" not in ctype.lower():
                    log.debug("DoH unexpected Content-Type: %r", ctype)
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
                released = True
            else:
                # v1.9.84 UP-04/UP-05: 先处理 pending bootstrap 再归还连接池,
                # 避免 release 后另一线程 checkout 此连接时本线程仍在读写其属性
                # (竞态), 以及 release 后抛异常导致外层 except double-release。
                pb = getattr(conn, '_ebpdns_pending_bootstrap', None)
                if pb:
                    _bootstrap_set(host, pb)
                    conn._ebpdns_pending_bootstrap = None
                _pool.release(entry, conn)  # 复用成功，写回池
                released = True
            return True, body
        except (OSError, http.client.HTTPException):
            # 连接失效 → 关闭并一次性重试（新建连接），仅用剩余预算
            rt = _remaining()
            if rt <= 0:
                # R19 P3-2: 与 rt>0 路径(下方 conn.close())对齐, 预算耗尽时也显式
                # 关闭已出错的旧 conn, 防 fd 泄漏。conn 已通过 _pool.acquire checkout
                # 到本线程, 不再在池中, 关闭安全。
                try:
                    conn.close()
                except Exception:
                    pass
                _pool.release(entry, None)
                return False, None
            try:
                conn.close()
            except Exception:
                pass
            try:
                # P3-04(R2): 首路径 _doh_conn 失败时已 _bootstrap_invalidate(host),
                # 但函数开头缓存的 bp_ip 仍可能是已失效的旧 IP。重试前重新取一次
                # bp_ip(失效后为 None → _doh_conn 内部自动回退系统解析), 避免把
                # 这唯一一次重试机会浪费在已知失效的 IP 上。
                bp_ip = _bootstrap_ip(host)
                conn = _doh_conn(host, port, rt, bp_ip=bp_ip, strict_cert=strict_cert)
                # P2-02(R2): 与首路径对齐, 重试新建连接后也按当前剩余 deadline
                # 重置 sock 超时。原实现 _doh_conn 把 sock 超时设为建连时刻的 rt,
                # TLS 握手已消耗时间, 不重置会以旧 rt 等待超出 deadline 一个握手耗时。
                try:
                    if getattr(conn, "sock", None) is not None:
                        conn.sock.settimeout(max(0.001, _remaining()))
                except Exception:
                    pass
                conn.request("POST", path, body=query_bytes, headers=headers)
                resp = conn.getresponse()
                body = resp.read(65536)  # P2-2: 同上读上限+长度校验
                # P3-5: 同首路径, 校验 Content-Type
                # R7 P3-5: 子串匹配转小写, 兼容大写/混合大小写。
                ctype = resp.getheader("Content-Type", "")
                if resp.status != 200 or not body or len(body) > 65535 or "application/dns-message" not in ctype.lower():
                    if "application/dns-message" not in ctype.lower():
                        log.debug("DoH retry unexpected Content-Type: %r", ctype)
                    try:
                        conn.close()
                    except Exception:
                        pass
                    _pool.release(entry, None)
                    return False, None
                # v1.9.80: will_close 时不复用
                if getattr(resp, "will_close", False):
                    try:
                        conn.close()
                    except Exception:
                        pass
                    _pool.release(entry, None)
                    released = True
                else:
                    # v1.9.84 UP-04/UP-05: 同首路径, 先处理 pending bootstrap 再归还
                    pb = getattr(conn, '_ebpdns_pending_bootstrap', None)
                    if pb:
                        _bootstrap_set(host, pb)
                        conn._ebpdns_pending_bootstrap = None
                    _pool.release(entry, conn)
                    released = True
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
        # v1.9.84 UP-05: 仅当连接槽尚未归还时才 close+release, 否则 double-release
        # (BoundedSemaphore 计数溢出) 并误关已被其他线程 checkout 的连接。
        log.warning("DoH query unexpected error up=%s(%s proto=doh host=%s:%s): %s: %s",
                    up.get("id"), up.get("name"), host, port, type(e).__name__, e)
        if not released:
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


def _dot_conn(host, port, timeout, strict_cert=False):
    """创建 DoT TLS 连接。

    若 hostname 已通过 bootstrap 预解析为 IP，用 IP 连接 + SNI=hostname，
    彻底摆脱系统 DNS 依赖；否则回退到 hostname 直连（系统 getaddrinfo）。

    R3-N1: 记录进入函数时刻。入参 timeout 是调用方在调用瞬间算出的剩余预算
    (rt = deadline - now), 但严格握手(下方 wrap_socket)已消耗部分预算;
    IP 字面量降级重建 TCP 时必须扣除已耗时, 否则小超时场景总耗时可超调约
    一个握手时长。
    R4 P2-1: 改为统一 deadline 模型——入口记录 deadline = now + timeout, 所有
    后续操作(_resolve_host_once 阻塞 getaddrinfo、create_connection、wrap_socket、
    降级重试)都用 max(0.001, deadline - time.monotonic()) 作为超时。原实现仅
    降级重试路径按 conn_t0 扣减预算, 首次 create_connection/wrap_socket 仍用
    完整入参 timeout, 阻塞 DNS 解析未计入预算, 最坏超调 2×timeout + DNS解析。
    """
    deadline = time.monotonic() + timeout
    ip = _bootstrap_ip(host)
    pending_resolved = None
    if not ip or ip == host:
        # bootstrap 缓存已失效/为空: 系统解析一次, 暂存 pending;
        # 待首次 exchange 成功后才写回(同 DoH fallback, 防首条坏 A 记录入缓存)。
        # R5 P2-1: 传入剩余预算, 用线程池硬截断 getaddrinfo。
        pending_resolved = _resolve_host_once(host, timeout=max(0.001, deadline - time.monotonic()))
    # R5 P3-4: 若 _resolve_host_once 已解析出 IP, 优先用它做 create_connection,
    # 避免 create_connection 内部对同一 hostname 再次 getaddrinfo(冷启动双倍解析)。
    # 仅当 pending_resolved 不可用(超时/失败)时才回退到 hostname 直连。
    connect_host = ip if ip else (pending_resolved or host)
    try:
        sock = socket.create_connection(
            (connect_host, port),
            timeout=max(0.001, deadline - time.monotonic()))
    except OSError:
        # 经 bootstrap IP 直连失败 → 失效缓存, 下次回退系统 getaddrinfo 重解析
        if ip and ip != host:
            _bootstrap_invalidate(host)
        raise
    # 使用 ssl.create_default_context() 默认校验(含 CA 校验 + 主机名校验)。
    # hostname 上游: server_hostname=host 做 SNI, 证书按主机名校验。
    # P2-20: 字面 IP 直连也做证书校验——传 IP 字符串作为 server_hostname,
    # Python 3.7+ 会校验证书中是否存在匹配的 IP SAN(SubjectAltName iPAddress)。
    # P1-01(R2): 上轮 P2-20 对 IP 字面量强制 IP SAN 验证, 但大量自托管/私有 DoT
    # 用仅含 DNS SAN 的证书 + IP 直连(无域名), 升级后全部因 CertificateError 失败
    # 且无 fallback。这里对 IP 字面量: 先严格验证; 若握手因证书主机名/SAN 校验
    # 失败(ssl.CertificateError), 记录 warning 后关闭旧 TCP 连接重建一次, 以
    # check_hostname=False 重试(仍走默认 verify_mode=CERT_REQUIRED 校验证书链,
    # 仅跳过主机名/SAN 匹配)。既保持默认安全验证, 又兼容自托管场景, 对用户透明。
    # hostname 上游行为完全不变(严格主机名校验, 不走降级)。
    # wrap_socket 抛异常时必须关闭原始 TCP socket, 否则 fd 泄漏。
    try:
        ctx = ssl.create_default_context()
        # R4 P2-1: TLS 握手前按剩余 deadline 重置 socket 超时。create_connection
        # 成功后 socket timeout 仍为建连时刻的剩余值, 握手已消耗时间, 不重置会
        # 以旧超时等待超出 deadline。
        sock.settimeout(max(0.001, deadline - time.monotonic()))
        if _is_hostname(host):
            try:
                sock = ctx.wrap_socket(sock, server_hostname=host)
            except ssl.CertificateError:
                # R8 P3-3: hostname 证书不匹配是真正的安全问题(非自托管 IP 字面量
                # 情形), 打 warning 提示管理员, 不静默吞到外层 except。
                log.warning(
                    "DoT 上游 %s:%s hostname 证书校验失败(CertificateError)。"
                    "请检查证书是否过期/SAN 是否包含该域名。",
                    host, port)
                raise
        else:
            # IP 字面量: 先严格验证 IP SAN (Python 3.7+)
            try:
                sock = ctx.wrap_socket(sock, server_hostname=host)
            except ssl.CertificateError:
                # R7 P2-2: dot_strict_cert=True 时 kill switch —— 证书主机名/SAN 校验
                # 失败直接抛出, 不降级(check_hostname=False)。默认 False 保持兼容。
                if strict_cert:
                    log.warning(
                        "DoT 上游 %s:%s dot_strict_cert=True, 证书主机名/SAN 校验失败"
                        "且 kill switch 开启, 不降级直接报错。",
                        host, port)
                    raise
                log.warning(
                    "DoT 上游 %s:%s 为 IP 字面量, 证书无匹配 IP SAN (疑似仅含 DNS SAN 的"
                    "自托管证书), 已降级为跳过主机名/SAN 校验重试一次(证书链仍校验)。"
                    "建议改用 hostname 上游, 或为该服务器配置含 IP SAN 的证书。",
                    host, port)
                # 失败握手后底层 TCP/TLS 状态不可靠: 关闭旧 raw sock, 重建一条再宽松重试
                try:
                    sock.close()
                except Exception:
                    pass
                # R4 P2-1/P3-3: 降级重试按统一 deadline 模型计算剩余预算。
                # 先检查预算是否已耗尽——若首次建连+握手已耗尽预算, 直接抛异常跳过
                # 降级(原 max(0.05, ...) 下限 50ms 会强制多阻塞 ~100ms 纯开销)。
                degraded_remaining = deadline - time.monotonic()
                if degraded_remaining <= 0:
                    raise ssl.CertificateError("no budget left for degraded retry")
                sock = socket.create_connection(
                    (connect_host, port),
                    timeout=max(0.001, degraded_remaining))
                # R4 P2-1: 降级握手前也按剩余 deadline 重置 socket 超时
                sock.settimeout(max(0.001, deadline - time.monotonic()))
                ctx2 = ssl.create_default_context()
                ctx2.check_hostname = False  # 仅跳过主机名/SAN 匹配, 仍校验证书链
                sock = ctx2.wrap_socket(sock, server_hostname=host)
                # R3-N2/R4 P2-2: 标记降级弱校验连接(check_hostname=False)。此类连接
                # 仅校验证书链而不校验主机名/SAN, 不进入连接池复用——_ConnPool.release
                # 见到 _ebpdns_degraded=True 即直接 close 不入队(R4 P2-2 修复),
                # acquire/reclaim_idle 亦保留检查作为 defense-in-depth。残余风险提示:
                # 若攻击者可向受信 CA 申请到"链受信但无匹配 IP SAN"的证书, 降级会静默
                # 放行 MITM; 强烈建议改用 hostname 上游(走严格主机名校验, 不进降级分支)。
                sock._ebpdns_degraded = True
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
    # 上游级证书校验开关 dot_strict_cert: 默认 True(严格, 不降级), 与
    # doh_strict_cert 对等。IP 字面量上游证书 SAN 校验失败时直接报错, 不做
    # check_hostname=False 重试, 防止持有任意受信 CA 证书的 MITM 劫持 IP 直连 DoT。
    # 仅当确需兼容仅含 DNS SAN 的自托管证书时, 显式配置 "dot_strict_cert": false
    # 才允许旧的降级行为(证书链仍校验, 仅跳过主机名/SAN 匹配)。配置示例:
    #   - proto: dot
    #     addr: 1.2.3.4          # IP 字面量直连
    #     dot_strict_cert: false # 显式允许降级(默认 true, 不匹配即失败)
    strict_cert = bool(up.get("dot_strict_cert", True))

    def _exchange(sock):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        # P3-15: sendall 前按当前 deadline 重置 socket 超时。复用连接池的 sock
        # 保留上次查询时 settimeout 的旧值(可能是更长/更短的超时), 不重置会导致
        # sendall 阻塞到旧超时而非本次剩余 deadline。
        sock.settimeout(max(0.001, remaining))
        sock.sendall(frame)
        # P2-5: 每轮 recv 前按 deadline 重置剩余超时, 与 _udp_query 路径对齐。
        # 原实现只在循环前设一次 settimeout, 跨段停顿时总等待可达 ~2×timeout。
        # R31 P2-1: 撤销 R30 P3-2 的跨查询保存/恢复机制。上一次 _exchange 已从
        # 内核读出但未消费的残余帧(协议违规服务器同段多发)属于上一次查询的数据,
        # 跨查询恢复会把它拼到新响应 buf 开头, 内层 parse_tcp_frame 从 buf 头部
        # 优先解析该残余帧; 而 DoT 路径不做 qid 校验, 会把上一次查询的应答误当作
        # 当前查询的响应返回(可能返回错误域名的 IP)。正确做法是当前 _exchange
        # 内消费完所需响应帧后直接丢弃 rest, 不跨查询保留。合法 DoT 服务器(RFC
        # 7858)绝不流水线多发帧, rest 恒为空, 直接丢弃零开销。
        buf = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            sock.settimeout(max(0.001, remaining))
            chunk = sock.recv(4096)
            if not chunk:
                return None
            buf.extend(chunk)
            # 接收缓冲上限: 防止畸形/恶意上游无限累积 chunk 导致内存爆炸。
            # R24 P3-1: TCP DNS 帧法定最大 = 2 字节长度前缀 + 65535 字节报文 = 65537。
            # 原 >65536 会把恰好 65535 字节的最大 DNS 报文(DNSSEC 走 TCP 回退)误判超长丢弃。
            if len(buf) > 65535 + 2:
                return None
            # R28 P3-2: 仅在遇到 length=0 空帧时才保留并推进 rest——空帧(2字节
            # 0x0000)是上游协议违规。DoH 层显式拒绝空 body(_doh_query 判 not body),
            # TCP 路径经 0x20 校验 + 下游 resolver 真值判断(resolver._classify_one
            # 处 `if ok and data:` 把空 bytes 当失败)兜底; DoT 既无 0x20 校验,
            # 又曾直接 parse 后 return 空报文, 此处对齐其他路径显式丢弃空帧并继续
            # 读后续帧, 避免把空报文当成功响应上交(下游虽会兜底判失败, 但此处拒绝
            # 更早、语义更清晰)。
            # R29 P3-1: 丢弃空帧后先把缓冲里残余数据连续消费掉, 再决定是否回 recv。
            # 原实现丢弃空帧后 `continue` 直接回 sock.recv(), 若同一 TCP 段中空帧后
            # 紧跟完整有效帧(需上游协议违规), 残余帧会滞留在 buf 中, 阻塞到 recv
            # 超时再读新数据重解析, 白浪费一个超时周期。改为内层循环: 空帧丢弃后
            # 只要 rest 非空就立即重解析; 帧不完整(raise)或 rest 已耗尽时才跳出
            # 回外层 recv 读新数据。
            while True:
                try:
                    msg, rest = parse_tcp_frame(buf)
                except Exception:
                    # 帧头/帧体不完整, 缓冲已不足以构成完整帧, 回外层 recv 读新数据。
                    break
                if not msg:
                    # P3-2: rest 已是 bytearray 切片(parse_tcp_frame 对 bytearray
                    # 切片返回新 bytearray), 直接赋值避免再拷一次。
                    buf = rest
                    if not buf:
                        # 空帧后无残余, 回 recv。
                        break
                    continue
                # qid 校验: 复用连接帧错位/协议违规服务器多发帧时, 响应 qid 必须
                # 与本次查询一致; 不一致的帧丢弃并继续读后续帧(与空帧处理同型),
                # 防止把别的查询的应答误当作本次结果返回。合法 DoT 服务器严格一问
                # 一答(RFC 7858), qid 恒匹配, 本检查为纵深防御。
                if len(msg) >= 2 and bytes(msg[0:2]) != query_bytes[0:2]:
                    buf = rest
                    if not buf:
                        break
                    continue
                # R31 P2-1: 有效帧 return 前直接丢弃 rest(协议违规服务器多发的
                # 额外帧), 不挂到 socket 属性跨查询保留。
                return bytes(msg)

    # P3-03(R2): 同 DoH, acquire 传剩余 deadline 而非完整 timeout, 让池等待与
    # 后续建连/I/O 共享同一预算, 避免池信号量等待耗尽全部预算。
    got, entry = _pool.acquire(key, deadline - time.monotonic())
    if got is None:
        return False, None
    sock = None
    released = False  # v1.9.84 UP-05: 跟踪连接槽是否已归还, 防外层 except double-release
    try:
        sock = None if got == "NEW" else got
        if sock is None:
            rt = deadline - time.monotonic()
            if rt <= 0:
                _pool.release(entry, None)
                return False, None
            try:
                sock = _dot_conn(host, port, rt, strict_cert=strict_cert)
            except OSError:
                _pool.release(entry, None)
                return False, None
        try:
            msg = _exchange(sock)
            if msg is not None:
                # v1.9.84 UP-04/UP-05: 先处理 pending bootstrap 再归还连接池
                pb = getattr(sock, '_ebpdns_pending_bootstrap', None)
                if pb:
                    _bootstrap_set(host, pb)
                    sock._ebpdns_pending_bootstrap = None
                _pool.release(entry, sock)  # 复用成功，写回池
                released = True
                return True, msg
            # P2-7: _exchange 返回 None(服务端 EOF)时, 连接池里闲置的连接很可能已被
            # 服务端半关闭。按与 OSError 相同的路径 close 旧连接、新建一条再 exchange 一次。
            try:
                sock.close()
            except Exception:
                pass
            rt = deadline - time.monotonic()
            if rt <= 0:
                _pool.release(entry, None)
                return False, None
            try:
                sock = _dot_conn(host, port, rt, strict_cert=strict_cert)
                msg = _exchange(sock)
            except OSError:
                # P1-7: 新建 TLS 连接后 _exchange 抛 OSError 时, 新建的 sock 必须
                # 关闭, 否则该 fd 泄漏(旧 sock 已在上方 close)。参考 DoH 重试路径。
                # R7 P3-7: sock 可能已被对端关闭/部分握手失败置为关闭态, close()
                # 幂等无害(重复 close 抛 OSError 被 except 兜住), 无需额外守卫。
                try:
                    sock.close()
                except Exception:
                    pass
                _pool.release(entry, None)
                return False, None
            if msg is not None:
                pb = getattr(sock, '_ebpdns_pending_bootstrap', None)
                if pb:
                    _bootstrap_set(host, pb)
                    sock._ebpdns_pending_bootstrap = None
                _pool.release(entry, sock)
                released = True
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
                # R19 P3-3: 与 rt>0 路径(下方 sock.close())对齐, 预算耗尽时也显式
                # 关闭已出错的旧 sock, 防 fd 泄漏。sock 已通过 _pool.acquire checkout
                # 到本线程, 不再在池中, 关闭安全。
                try:
                    sock.close()
                except Exception:
                    pass
                _pool.release(entry, None)
                return False, None
            try:
                sock.close()
            except Exception:
                pass
            try:
                sock = _dot_conn(host, port, rt, strict_cert=strict_cert)
                msg = _exchange(sock)
                if msg is not None:
                    # v1.9.84 UP-04/UP-05: 同首路径, 先处理 pending bootstrap 再归还
                    pb = getattr(sock, '_ebpdns_pending_bootstrap', None)
                    if pb:
                        _bootstrap_set(host, pb)
                        sock._ebpdns_pending_bootstrap = None
                    _pool.release(entry, sock)
                    released = True
                    return True, msg
                try:
                    sock.close()
                except Exception:
                    pass
                _pool.release(entry, None)
                return False, None
            except OSError:
                # P1-8: 与 P1-7 同型: 新建连接后再次 OSError 时关闭新建 sock,
                # 防 TLS socket fd 泄漏。
                # R7 P3-7: 同 P1-7, sock 可能已关闭, close() 幂等无害。
                try:
                    sock.close()
                except Exception:
                    pass
                _pool.release(entry, None)
                return False, None
    except Exception as e:
        # v1.9.84 UP-05: 仅当连接槽尚未归还时才 close+release, 防 double-release
        # 及误关已被其他线程 checkout 的连接。
        log.warning("DoT query unexpected error up=%s(%s proto=dot host=%s:%s): %s: %s",
                    up.get("id"), up.get("name"), host, port, type(e).__name__, e)
        if not released:
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
    # R5 P2-1: deadline 提前到 _cached_udp_addrs 之前设定。原实现在 sendto 后才
    # 设 deadline, 冷缓存时 _cached_udp_addrs 阻塞 getaddrinfo 的时间完全不计入预算。
    # 现在 deadline 在解析前设定, 传给 _cached_udp_addrs 做硬截断, 后续 I/O 共用同一预算。
    deadline = time.monotonic() + timeout_ms / 1000.0
    # H-5: 根据目标地址族选择 socket family。原硬编码 AF_INET 导致 IPv6 上游
    # (如 2606:4700::1) sendto 抛 OSError 被静默吞掉、IPv6 UDP 上游永不工作。
    # 期望响应源 IP 集合: host 为域名时解析出全部 IP(A 记录可能多个,
    # 单值校验会误丢来自其他 IP 的响应); 解析失败则集合为空 → 不校验源,
    # 靠 qid(16bit 随机)兜底防投毒。
    expect_ips = set()
    send_addr = (host, port)
    if not _is_hostname(host):
        expect_ips.add(host)
    else:
        # 用带 TTL 的解析缓存拿到 IP 集合, 避免 miss 热路径阻塞 getaddrinfo。
        # R5 P2-1: 传入剩余预算做硬截断, 超时返回空集(不校验源, 靠 qid 兜底)。
        ips = _cached_udp_addrs(host, timeout=max(0.001, deadline - time.monotonic()))
        expect_ips = set(ips)
        if ips:
            # v1.9.74 P1-3: 直接向已解析出的 IP sendto, 不再把 hostname 交给
            # sendto(其会走系统解析/行为不确定)。多 IP 取集合首个(确定性, 不引入
            # 额外状态); expect_ips 仍用于响应源 IP 校验。
            send_addr = (next(iter(ips)), port)
    # P3-17: fam 必须按实际 sendto 的地址(可能是解析出的 AAAA)判定, 而非按
    # 原始 host 字符串。否则 hostname 仅解析到 IPv6 时, 仍用 AF_INET socket 向
    # IPv6 地址 sendto, 必抛 OSError 被静默吞掉。
    fam = socket.AF_INET6 if ":" in send_addr[0] else socket.AF_INET
    # R7 P1-1: 冷缓存 getaddrinfo 硬截断超时后 ips 为空, send_addr 仍为 hostname。
    # 此时若继续 sendto(hostname) 会触发同步无超时 getaddrinfo(~10s 阻塞),
    # 且 expect_ips 为空导致源 IP 校验被跳过。直接返回 False 让上层 resolver
    # 切换备用上游, 不再阻塞在 hostname 上。
    if _is_hostname(host) and not expect_ips:
        return False, None
    # P2-5: socket 创建移入 try 块, 与 sendto/recvfrom 共用同一 finally close,
    # 确保 expect_ips/send_addr 计算之后到 recvfrom 之间任何异常都不会泄漏 fd。
    # sock 先置 None, 防止 socket.socket() 构造失败时 finally 对未绑定名 close。
    sock = None
    try:
        sock = socket.socket(fam, socket.SOCK_DGRAM)
        # R5 P2-2: settimeout 移到 sendto 之前。原实现先 sendto 再 settimeout,
        # 新建 socket 为默认阻塞模式, UDP sendto 在发送缓冲区满/内核路由异常时
        # 可能无限阻塞。现在先设超时再发送, 与统一 deadline 模型一致。
        sock.settimeout(max(0.001, deadline - time.monotonic()))
        sock.sendto(query_bytes, send_addr)
        # H-5: 每轮 recvfrom 前按剩余时间重置超时。原实现 settimeout 只设一次,
        # 收到伪造/无关响应 continue 后, 下一轮 recvfrom 仍等完整 timeout, 总耗时
        # 可超 deadline 50% 甚至翻倍。改为剩余 deadline, 伪造响应不再延长等待。
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False, None
            sock.settimeout(max(0.001, remaining))
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
            # P2-1: check_0x20 为纯函数(无共享状态), 在锁外计算失配判定;
            # 但"读旧值+1"的失配计数 与 "成功清零" 的写, 合并到同一个 _0x20_lock
            # 块内原子完成, 杜绝跨锁获取丢失增量/过早降级。
            # P3-21: 消除 stale-read 窗口——原实现先在第一个锁块读 x20_off, 锁外
            # 算 _is_mismatch, 再进第二个锁块; 两锁之间另一线程可能刚把该上游
            # 降级加入 _0x20_disabled, 但本线程仍按旧 x20_off 决策(误丢刚降级上游
            # 的响应)。改为: 锁外只算 check_0x20, x20_off 在锁内重读后再决策。
            _is_mismatch = not dnsmsg.check_0x20(query_bytes, data)
            with _0x20_lock:
                x20_off = up_id in _0x20_disabled
                if not x20_off and _is_mismatch:
                    # 锁内先读旧值再 +1 (read-modify-write 整体原子)
                    _0x20_misses[up_id] = _0x20_misses.get(up_id, 0) + 1
                    if _0x20_misses[up_id] >= _0x20_FAIL_LIMIT and up_id not in _0x20_disabled:
                        _0x20_disabled.add(up_id)
                        _0x20_DISABLED_SINCE[up_id] = time.monotonic()
                        log.warning("上游 %s(%s) 连续 %d 次 0x20 大小写失配, 自动关闭 0x20 校验"
                                    "(疑似规范化大小写上游, %.0fs 后自动重试)",
                                    up.get("name"), up_id,
                                    _0x20_FAIL_LIMIT, _0x20_RECOVER_S)
                else:
                    # 本查询收到 0x20 校验通过(或已降级)的响应 → 锁内清零连续失配计数
                    _0x20_misses[up_id] = 0
                # R26 P3-2: 把"丢弃决策"也并入同一把锁内。P3-21 已把 x20_off 的读
                # 收敛进锁, 但原实现在出锁后(line 外)才用本地 x20_off 做丢弃决策,
                # 出锁与决策之间仍存在微秒级窗口——另一线程恰在此刻把该上游降级
                # 加入 _0x20_disabled, 本线程仍按旧 x20_off=False 决策, 误丢刚降级
                # 上游的单条响应。将决策并入锁块后, 读 x20_off 与决策原子完成, 彻底
                # 关闭该窗口。该窗口本就只能造成"多丢一条真实失配响应"(绝不会误收
                # 投毒响应), 影响极小; 此改动为低成本收口, 与 P3-21 的原子化意图一致。
                if _is_mismatch and not x20_off:
                    continue  # 大小写失配 = 伪造应答嫌疑, 丢弃继续等
            return True, data
        return False, None
    except OSError:
        return False, None
    finally:
        # P2-5: sock 可能因 socket.socket() 构造失败而为 None, 守卫避免 NameError。
        if sock is not None:
            sock.close()


def _tcp_query(up, query_bytes, timeout_ms):
    # R17 P3-4: 原 use_tls 参数为死代码——DoT 由独立的 _dot_query 完整实现,
    # 全部调用方(upstream.py: query_upstream、resolver.py: TCP 回退)均只走明文
    # TCP。删除不会被触发的 TLS 分支与 use_tls 形参, 避免保留半吊子 TLS 策略。
    host, port = _host_port(up)
    # P2-19: 总 deadline 在建连前设定, 建连与 I/O 共用同一预算, 避免
    # create_connection(完整 timeout) + I/O deadline(完整 timeout) 叠加导致
    # 总耗时可达配置值 2 倍。
    deadline = time.monotonic() + timeout_ms / 1000.0
    try:
        # R5 P2-1: create_connection 内部 getaddrinfo 不受 deadline 控制。
        # 若 host 是 hostname, 先用线程池硬截断解析到 IP, 再用 IP 直连。
        # 若解析超时/失败, 回退到 create_connection(host, port)(可能阻塞但
        # 保持原行为, 与冷缓存 bootstrap miss 路径一致)。
        connect_host = host
        if _is_hostname(host):
            remaining = deadline - time.monotonic()
            if remaining > 0:
                resolved = _resolve_host_once(host, timeout=remaining)
                if resolved:
                    connect_host = resolved
            else:
                # R19 P3-4: 预算已耗尽且 host 仍为 hostname 时, create_connection
                # 内部 getaddrinfo 是阻塞系统调用, 不受 socket timeout 控制, 会无视
                # deadline 阻塞数秒(系统 DNS 超时)。直接返回 False 让上层切换备用上游。
                return False, None
        # P3-02(R2): 超时下限 0.001s 而非 0.05s, 与 DoH P3-16 对齐。剩余预算已
        # 很短时不应人为拉长建连等待到 50ms, 否则小超时场景总耗时超调 ~50ms。
        sock = socket.create_connection((connect_host, port),
                                        timeout=max(0.001, deadline - time.monotonic()))
    except OSError:
        return False, None
    try:
        # R7 P3-3: 明文 TCP 路径在 sendall 前重设 settimeout。
        # create_connection 的 timeout 在建连时设过, 但后续处理已耗时, 不重设会以
        # 旧超时等待超出 deadline。
        sock.settimeout(max(0.001, deadline - time.monotonic()))
        sock.sendall(tcp_frame(query_bytes))
        # v1.9.84 UP-07: 用 bytearray 累积, 避免每轮 bytes(buf) 全量拷贝
        buf = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False, None
            sock.settimeout(max(0.001, remaining))
            chunk = sock.recv(4096)
            if not chunk:
                return False, None
            buf.extend(chunk)
            # R24 P3-1: 与 _exchange(DoT) 对齐, TCP 帧最大 65535+2=65537,
            # 原 >65536 会误杀恰好 65535 字节的最大 DNS 报文。
            if len(buf) > 65535 + 2:
                return False, None
            # R30 P3-1: 与 R29 DoT 内层解析循环对齐。原实现单层循环: 0x20 失配
            # 丢弃后 `buf = rest` 已保留残余, 但 `continue` 直接回外层
            # recv 阻塞; 若攻击者伪造的失配帧与合法帧在同一 TCP 段 coalesce,
            # 合法帧已在 rest 中却要等 recv 超时/新数据才被重解析, 最坏单条查询
            # 超时失败。改为内层循环: 失配丢弃后只要 rest 非空就立即重解析;
            # 帧不完整(raise)或 rest 耗尽时才跳出回外层 recv。
            while True:
                try:
                    msg, rest = parse_tcp_frame(buf)
                except Exception:
                    # 帧头/帧体不完整, 缓冲已不足以构成完整帧, 回外层 recv 读新数据。
                    break
                # 明文 TCP 做 0x20 校验(加密 DoT 走独立 _dot_query, 不在此函数)。
                # R38 P3-3: 此处有意不复制 _udp_query 的 0x20 自适应降级
                # (_0x20_misses 连续 3 次失配后加入 _0x20_disabled)。理由:
                # (1) 本函数仅为 UDP 失败后的明文 TCP 回退通道, 实际触发面小;
                # (2) 同上游 UDP/TCP 通常走同一网络路径, 若中间设备规范化 qname
                #     大小写, UDP 热路径已会累积失配并降级(共享 _0x20_disabled),
                #     覆盖该上游——此处无条件校验不会长期误丢;
                # (3) 明文 TCP 是已建立的连接流, 无 UDP 那样的源地址伪造向量,
                #     0x20 在此仅作纵深防御, 无条件拒绝失配帧失败方向安全
                #     (丢弃后回退/返回 False, 不上交残缺数据)。
                # 残余缺口(UDP 被防火墙完全阻断、且 TCP 路径单独存在规范化中间设备)
                # 为三重罕见场景, 不值得在回退路径再引入一套锁保护的失配计数状态机。
                if not dnsmsg.check_0x20(query_bytes, bytes(msg)):
                    # 被投毒的这一帧丢弃并推进缓冲区到帧尾, 继续读取后续帧。
                    # 原实现 buf 不推进: 下次 recv 追加后 parse_tcp_frame 仍反复解析
                    # 同一帧, 0x20 持续失败, 直至 len(buf)>64KB 才返回 —— 等于白等。
                    # P3-2: rest 已是 bytearray 切片, 直接赋值避免多余拷贝。
                    buf = rest
                    if not buf:
                        # 失配帧后无残余, 回外层 recv 读新数据。
                        break
                    continue
                return True, bytes(msg)
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
            ok, data = _tcp_query(up, query_bytes, timeout_ms)
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


def probe_ip(ip, query_bytes, port=53, timeout_ms=800):
    """对候选 IP 发起一次快速 UDP DNS 探测（用于测速择优）。返回 RTT ms 或 None。
    v1.9.76 2.8: 按地址族选择 socket(原硬编码 AF_INET, IPv6 候选探测静默失败)。
    v1.9.84 UP-09: 新增 port 参数(原硬编码 53, 非标准端口上游探测必失败)。
    v1.9.84 UP-10: 校验响应源地址/端口与 qid, 防伪造响应误导测速。
    R36 P3-1: 单次 recvfrom 改为 deadline 循环, 源 IP/端口或 qid 失配时 continue
    继续等待真正响应直至超时, 与 _udp_query(L1587) 及 R34 bootstrap _ask(L271)
    语义对齐。原实现收到首个失配报文(陈旧包/同端口噪声/on-path 伪造)即 return
    None, 会把健康上游误判为慢/不可达, 拉低测速择优准确性。数据面不受影响
    (真实查询仍走 _udp_query 四层校验)。"""
    fam = socket.AF_INET6 if _is_v6(ip) else socket.AF_INET
    # R37 P3-1: socket 构造移入 try 并加 sock=None 守卫, 与 _udp_query(L1576) 同型。
    # 原实现在 try 外构造 socket, 构造失败(如 fd 耗尽 EMFILE/ENFILE)时 OSError 穿透
    # 到后台探测线程池而非走 except OSError: return None。happy path 行为不变。
    sock = None
    try:
        sock = socket.socket(fam, socket.SOCK_DGRAM)
        t0 = time.monotonic()
        deadline = t0 + timeout_ms / 1000.0
        # R5 P2-2 同款: sendto 前先设超时, 防新建阻塞 socket 发送路径无限挂起。
        sock.settimeout(max(0.001, deadline - t0))
        sock.sendto(query_bytes, (ip, port))
        # R36 P3-1: deadline 循环等待匹配响应, 失配不立即判失败。
        # 每轮按剩余时间重置超时, 失配报文不延长整体等待(对齐 _udp_query H-5)。
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            sock.settimeout(max(0.001, remaining))
            try:
                data, src = sock.recvfrom(2048)
            except socket.timeout:
                return None
            # v1.9.84 UP-10: 校验源 IP、源端口与响应 qid, 防伪造响应误导测速。
            # R35 P3-1: 补源端口校验, 与 _udp_query(L1602) 对称; 同源不同端口的
            # 伪造回包不再被当成功响应, 避免 on-path 攻击者低估某上游 RTT。
            if src[0] != ip or src[1] != port:
                continue
            # R41 P3-1: 补最小 DNS 报文头长度校验(12 字节), 与 bootstrap_resolve._ask
            # (L305 len(data)<12 拒绝) 同型。原 qid 短路逻辑 `len(data) >= 2 and ...`
            # 在收到 0/1 字节 UDP 数据报时跳过 qid 校验直接 return 成功, 使伪造的
            # 0 字节回包可误判上游 RTT。此处与 _ask 对齐, 短包 continue 丢弃。
            if len(data) < 12:
                continue
            if len(data) >= 2 and query_bytes[:2] != data[:2]:
                continue
            return int((time.monotonic() - t0) * 1000)
    except OSError:
        return None
    finally:
        # R37 P3-1: sock 可能因构造失败而为 None, 守卫避免 NameError(同 _udp_query L1651)。
        if sock is not None:
            sock.close()


def probe_tcp(ip, port=443, timeout_ms=800):
    """对候选 IP 发起 TCP connect 探测（SmartDNS speed-check 风格, tcp:443）。

    更贴近真实访问路径；非特权即可（ICMP 才需 root）。返回 RTT ms 或 None。
    v1.9.76 2.8: 按地址族选择 socket(原硬编码 AF_INET, IPv6 候选探测静默失败)。
    R37 P3-1: socket 构造移入 try 并加 sock=None 守卫, 与 _udp_query 同型。"""
    fam = socket.AF_INET6 if _is_v6(ip) else socket.AF_INET
    sock = None
    try:
        sock = socket.socket(fam, socket.SOCK_STREAM)
        # R42 P3-1: 补 max(0.001, ...) 下限, 与 probe_ip(L1828/L1836) 同型。
        # _safe_int 原样保留 speed_timeout_ms 的负值, settimeout(负值) 会抛 ValueError
        # (非 OSError 子类), L1877 except OSError 捕获不到, 穿透后台测速 worker。
        # 对 0/正值行为不变, 仅消除负值配置触发的未捕获异常。
        sock.settimeout(max(0.001, timeout_ms / 1000.0))
        t0 = time.monotonic()
        sock.connect((ip, port))
        return int((time.monotonic() - t0) * 1000)
    except OSError:
        return None
    finally:
        if sock is not None:
            sock.close()
