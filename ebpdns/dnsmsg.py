"""DNS 报文编解码 —— 纯标准库实现（无第三方依赖）。

支持:
  - 构建查询报文 (A/AAAA/MX/TXT/NS/CNAME/SOA... , 可选 EDNS0)
  - 解析响应报文 (header/question/answer/authority/additional, 支持压缩指针)
  - DNS over TCP / TLS 的长度前缀帧
"""

import os
import struct
import socket
import random as _random

# ---------- 类型与类 ----------
TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_PTR = 12
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_SRV = 33
TYPE_HTTPS = 65
TYPE_OPT = 41

CLASS_IN = 1

# 单条响应允许的最大答案数（超出截断并置 TC 位，避免超大 UDP 响应）
MAX_ANSWERS = 8

TYPE_NAMES = {
    TYPE_A: "A", TYPE_NS: "NS", TYPE_CNAME: "CNAME", TYPE_SOA: "SOA",
    TYPE_PTR: "PTR", TYPE_MX: "MX", TYPE_TXT: "TXT", TYPE_AAAA: "AAAA",
    TYPE_SRV: "SRV", TYPE_HTTPS: "HTTPS", TYPE_OPT: "OPT",
}
TYPE_CODES = {v: k for k, v in TYPE_NAMES.items()}
# 可解析的记录类型（用于查询控制台下拉）
QUERY_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "HTTPS", "PTR"]


def type_code(name):
    """类型名 -> 数字。未知类型返回 0。"""
    return TYPE_CODES.get(str(name).upper(), 0)


def type_name(code):
    return TYPE_NAMES.get(code, str(code))


class DNSError(Exception):
    pass


def _safe_int(v, default=0):
    """R7/P3-10: 与 resolver/cache/probe 的 _safe_int 同模式(本地副本, 避免循环 import)。
    畸形配置值(非数值字符串)不抛 ValueError——build_query 热路径裸 int(udp_size)
    对 "abc" 会穿透 miss 主路径。None/无法解析→default, 可解析值(含 0)保留。"""
    if v is None:
        return default
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


# ---------- 名称编解码 ----------
def encode_name(name):
    """将域名编码为 DNS 标签序列（不含根 0 结尾）。"""
    name = name.rstrip(".")
    if not name:
        return b"\x00"
    # 热路径快速通道: 纯 ASCII 域名(99%+ 真实查询)——跳过逐标签 isascii()/
    # idna() 判定与中间 list 推导。空标签过滤与 >63 长度检查保留。
    if name.isascii():
        out = bytearray()
        for label in name.split("."):
            if not label:
                continue   # 过滤 "a..b" 连续点产生的空标签(原 list 推导语义)
            ll = len(label)
            if ll > 63:
                raise DNSError("label too long: %s" % label)
            out.append(ll)
            out += label.encode()
        out.append(0)
        if len(out) > 255:
            raise DNSError("name too long")
        return bytes(out) if out else b"\x00"
    # 非 ASCII: IDNA 路径(保留原语义)
    # D-03: 过滤连续点产生的空标签(如 "example..com" 拆分出 ""),
    # 否则 len(b)=0 会写入长度字节 0 被误判为根标签终止, 域名被提前截断。
    labels = [l for l in name.split(".") if l]
    if not labels:
        return b"\x00"
    out = bytearray()
    for label in labels:
        # #5 [中] IDNA 死代码简化: 原外层 except UnicodeError 内重试同一
        # encode("idna") 是死代码(结果必然相同), 直接一次编码, 失败抛 DNSError。
        try:
            b = label.encode("idna")
        except UnicodeError:
            raise DNSError("invalid IDNA label: %s" % label)
        if len(b) > 63:
            raise DNSError("label too long: %s" % label)
        out.append(len(b))
        out += b
    out.append(0)
    if len(out) > 255:
        raise DNSError("name too long")
    return bytes(out)


def decode_name(data, offset):
    """从 data 的 offset 处解码域名，支持压缩指针。返回 (name, new_offset)。

    带压缩跳转上限（MAX_PTR_JUMPS=32）防自引用指针环死循环:
    恶意报文可构造 0xc00c 自引用环, 若无上限将永久循环, 使处理线程/主循环卡死 (DoS)。
    """
    labels = []
    jump_done = False
    end = offset
    pos = offset
    jumps = 0
    dlen = len(data)  # 缓存长度避免每次循环调用 len()
    name_len = 0      # 解码出的域名总长度(标签字节 + 分隔点), 上限 255
    while True:
        if pos >= dlen:
            raise DNSError("truncated name")
        length = data[pos]
        if length == 0:
            if not jump_done:
                end = pos + 1
            pos += 1
            break
        # 标签长度最高两位: 0xC0 才是压缩指针; 0x40/0x80(及 0xC0 之外的高位组合)
        # 是非法标签长度, 必须拒绝, 否则会被当成普通长度字节引发越界/误解码。
        if length & 0xC0 and length & 0xC0 != 0xC0:
            raise DNSError("invalid label length")
        if length & 0xC0 == 0xC0:
            if pos + 1 >= dlen:
                raise DNSError("truncated pointer")
            jumps += 1
            if jumps > 32:
                raise DNSError("too many compression jumps")
            ptr = ((length & 0x3F) << 8) | data[pos + 1]
            if not jump_done:
                end = pos + 2
                jump_done = True
            pos = ptr
            continue
        pos += 1
        if pos + length > dlen:
            raise DNSError("truncated label")
        # 热路径优化: DNS 标签几乎总是纯 ASCII, 直接 decode('ascii') 比 errors='replace'
        # 快约 30%(避免 UnicodeDecodeError 分支); 非法字符回退 replace 不丢数据。
        try:
            labels.append(data[pos:pos + length].decode("ascii"))
        except UnicodeDecodeError:
            labels.append(data[pos:pos + length].decode("ascii", errors="replace"))
        # 累计线格式长度: 每标签 1(长度前缀) + label_len; 末尾 +1(根终止符)。
        # RFC 1035: 线格式域名总长 ≤ 255 字节。
        name_len += 1 + length
        if name_len >= 255:
            raise DNSError("name too long")
        pos += length
    return ".".join(labels), end


# ---------- 查询构建 ----------
def build_query(domain, qtype, qid=None, edns=False, edns_client_subnet=None,
                udp_size=1232, padding=False):
    """构建一个 DNS 查询报文。返回 (bytes, qid)。

    udp_size: EDNS0 UDP payload 大小(字节)。1232 = IPv6 最小 MTU 1280 减
              IPv6 头 40 + UDP 头 8 的最大不分片安全值 —— 超过 MTU 的大 UDP
              应答会被分片, 穿越 NAT/防火墙/PPPoE 时 UDP 分片经常被丢弃,
              导致解析超时重试。钳制到该值保证应答不分片(需要更大应答时
              上游会置 TC 位让客户端走 TCP 重试)。
    padding: 是否启用加密查询报文填充(RFC 8467)。把 OPT options 段对齐到
             128 字节块的倍数(上限 512), 抹平加密报文长度指纹, 防止流量
             分析攻击通过报文长度推断查询类型/域名。仅对 DoT/DoH/DoH3/DoQ
             等加密传输有意义; 明文 UDP/TCP 填充只会增大报文无收益。
    """
    qid = qid if qid is not None else _rand_id()
    flags = 0x0100  # RD=1
    # 预编译 struct: 上游查询构造热路径避免重复 Struct 解析
    header = _QHDR.pack(qid, flags, 1, 0, 0, 1 if edns else 0)
    question = encode_name(domain) + _QTAIL.pack(qtype, CLASS_IN)
    additional = b""
    if edns:
        # OPT RR: name=0, type=OPT(41), class=UDP payload, ttl=0, rdlen, rdata(options)
        options = b""
        if edns_client_subnet:
            # ECS: family(2)=1 IPv4, src(1)=0, scope(1)=0, addr
            options = _ecs_option(edns_client_subnet)
        if padding:
            # RFC 8467 Padding 选项(option code 12, 数据全零): 对齐 128B 块
            opts_len = len(options)
            need = (128 - (opts_len % 128)) % 128
            if need < 4:
                need += 128
            if need > 512:
                need = 512
            options += struct.pack(">HH", 12, need - 4) + b"\x00" * (need - 4)
        opt_ttl = 0
        # R7/P3-10: 裸 int(udp_size) 对畸形串(如 "abc")抛 ValueError 穿透 miss 主路径。
        # 用本地 _safe_int 兜底; 保留 falsy(None/0)→1232 的既有语义。
        size = _safe_int(udp_size, 1232) if udp_size else 1232
        # R12/P3: 钳制 udp_size 到 [0, 65535]。API 热重载若绕过 config 校验写入
        # 越限值(如 -1 或 70000), 下方 _OPT_RR.pack(">H") 会抛 struct.error 穿透
        # miss 主路径。负值/超大值均钳到边界, 与 ECS prefix 钳制策略一致。
        size = max(0, min(65535, size))
        additional = b"\x00" + _OPT_RR.pack(TYPE_OPT, size, opt_ttl, len(options)) + options
    return header + question + additional, qid


def _ecs_option(subnet):
    """EDNS0 Client Subnet 选项：subnet 形如 '203.0.113.0/24' 或 '1.2.3.4'。"""
    try:
        addr, prefix = subnet.split("/")
        prefix = int(prefix)
    except ValueError:
        addr, prefix = subnet, 32
    try:
        family = 1  # IPv4
        raw = socket.inet_aton(addr)
    except OSError:
        family = 2  # IPv6
        try:
            raw = socket.inet_pton(socket.AF_INET6, addr)
        except OSError:
            # v1.9.87 P2-2: 畸形 edns_client_subnet(既非合法 IPv4 也非合法 IPv6,
            # 如手误填 "not-an-ip") 优雅降级——不带 ECS 选项返回空 bytes。原实现
            # 此处 inet_pton 抛未捕获 OSError, 穿透 build_query → _build_query_map
            # → resolve, 每次 cache miss 都被 server 兜底为 SERVFAIL(整域名不可用)。
            # _normalize_ecs_key 只保护缓存 key 命名空间, 不保护 wire 编码路径。
            return b""
        # D-02: 无显式前缀时 IPv6 默认 /128(非 /32), 否则只发前 4 字节地址。
        if prefix == 32 and "/" not in subnet:
            prefix = 128
    # R7/P2-1: 钳制 prefix 到合法范围。负值 prefix(如 "/-1")原会在下方
    # struct.pack('B', prefix) 抛 struct.error 穿透整个 miss 主路径; 超大值也会
    # 使 addr_bytes 越界切片。IPv4 ≤32, IPv6 ≤128, 负值/越界均钳到边界。
    prefix = max(0, min(prefix, 32 if family == 1 else 128))
    addr_bytes = raw[: (prefix + 7) // 8]
    # option code ECS = 8, len = 4 + addrlen
    # D-01: Source Prefix Length 必须填实际 prefix(原硬编码 0 导致 ECS 地理分流失效)。
    return struct.pack(">HHHBB", 8, 4 + len(addr_bytes), family, prefix, 0) + addr_bytes


def _rand_id():
    return int.from_bytes(os.urandom(2), "big")


# ---------- DNS 0x20 缓存投毒防护 ----------
def random_case_name(domain):
    """生成域名大小写随机变体（DNS 0x20 编码）。

    每个字母独立 50% 概率大写/小写。查询名增加约 26 位熵（与 qid 16bit +
    源端口 16bit 叠加），使伪造应答投毒需同时猜中 58+ bit，防御成本指数级
    上升。仅对明文 UDP/TCP 有意义（加密通道无投毒面）。
    返回: 大小写随机化的域名（标签分隔点不变）。
    """
    out = []
    for ch in domain:
        if "a" <= ch <= "z":
            out.append(ch.upper() if _random.getrandbits(1) else ch)
        else:
            out.append(ch)
    return "".join(out)


def extract_qname(data):
    """提取 DNS 报文 question section 的原始 qname 字节（含标签长度前缀）。

    返回 bytes（编码后，未解码）。header 后第一个 question 的 name 字段。
    用于 0x20 校验: 与发送报文的 qname 字节逐位比较（大小写敏感）。
    解析失败返回 None。
    """
    try:
        if len(data) < 12:
            return None
        qd = struct.unpack(">H", data[4:6])[0]
        if qd < 1:
            return None
        pos = 12
        start = pos
        while True:
            ln = data[pos]
            if ln == 0:
                return data[start:pos + 1]
            if ln & 0xC0 == 0xC0:  # 压缩指针不应出现在 question 区
                return None
            pos += 1 + ln
            if pos >= len(data):
                return None
    except Exception:
        return None


def check_0x20(query_bytes, response_data):
    """0x20 校验: 响应 question qname 字节必须与查询完全一致（含大小写）。

    攻击者无法预知查询名大小写，伪造应答（即使猜中 qid+端口）在大小写
    位上必然失配。上游若规范化大小写也会失配 → 该响应被丢弃（视为投毒），
    查询会由其他上游/重试兜底。
    返回 True=通过；False=失配（投毒嫌疑）。
    """
    qn = extract_qname(query_bytes)
    rn = extract_qname(response_data)
    if qn is None or rn is None:
        return True  # 无法解析不误杀（qid+源IP校验仍在）
    return qn == rn


# ---------- 响应解析 ----------
def _parse_rdata(data, pos, rtype, rdlen):
    """解析单条 RR 的 rdata 字段。pos 为 rdata 起始偏移, rdlen 为长度。"""
    raw = data[pos:pos + rdlen]
    if rtype == TYPE_A:
        if rdlen == 4:
            return socket.inet_ntoa(raw)
        # R32/P3-1: rdlen≠4 的畸形 A 记录不再降级为 hex 入库(hex 经候选过滤时
        # _is_private_ip 因 ip_address(hex) 抛 ValueError 误判为"非私有"放行,
        # 重编码又产出 rdata 长度不匹配的非法应答)。返回 None 由调用方跳过该 RR。
        return None
    if rtype == TYPE_AAAA:
        if rdlen == 16:
            return socket.inet_ntop(socket.AF_INET6, raw)
        return None
    if rtype == TYPE_CNAME or rtype == TYPE_NS or rtype == TYPE_PTR:
        name, np = decode_name(data, pos)
        # R33/P3-1: 与 A/AAAA/MX/SRV/SOA 对齐, 校验 decode_name 实际消费的
        # 线格式字节不超过声明的 rdlen。恶意上游声明 rdlen 偏小但名称实际更长时,
        # decode_name 会读到声明 rdata 范围之外(包级边界由 decode_name 自检, 但
        # 此处若放行, parse_message 的 pos += rdlen 只前进 rdlen 导致后续 RR 解析
        # 错位为垃圾)。结构不匹配返回 None, 由调用方跳过整条 RR。
        # 压缩指针情形下 np-pos 恒为 2(仅占指针字节) ≤ rdlen, 不影响合法压缩名称。
        if np - pos > rdlen:
            return None
        return name
    if rtype == TYPE_MX:
        if rdlen >= 3:
            pref = struct.unpack(">H", raw[:2])[0]
            mx, np = decode_name(data, pos + 2)
            # R34/P3-1: 与 R33 CNAME/NS/PTR 同型, 校验 decode_name 实际消费的
            # 线格式字节(np-pos)不超过声明的 rdlen。恶意上游声明 rdlen 偏小但名称
            # 经压缩指针指向 rdata 范围外(如下一条 RR 首字节)时, 结构不匹配整条 RR
            # 丢弃, 避免产出内容错误的 MX exchange 字符串。压缩指针情形 np-pos 恒为
            # 4(2B pref + 2B 指针) ≤ rdlen, 合法压缩 MX 不受误杀。
            if np - pos > rdlen:
                return None
            return "%d %s" % (pref, mx)
        return None
    if rtype == TYPE_TXT:
        out = []
        p = 0
        while p < rdlen:
            ln = raw[p]
            p += 1
            # P2-3: 恶意/截断 TXT 的长度字节 ln 超过剩余 rdlen 时,
            # raw[p:p+ln] 静默截断但 p+=ln 越过 rdlen → 越界。
            if p + ln > rdlen:
                break
            out.append(raw[p:p + ln].decode("utf-8", errors="replace"))
            p += ln
        return '"' + "".join(out) + '"'
    if rtype == TYPE_SOA:
        # SOA rdata = mname + rname + 5×uint32(20B)。校验两个名称 decode_name
        # 实际消费的线格式字节不超过声明 rdlen(与 CNAME/NS/MX/SRV 同型), 且
        # 名称后 20 字节定长字段恰好落在 rdlen 内。恶意上游声明 rdlen 偏小但
        # 名称经标签/前向指针读到 rdata 之外时, 整条 RR 丢弃, 避免产出内容
        # 不一致的转发应答。
        mname, p = decode_name(data, pos)
        if p - pos > rdlen:
            return None
        rname, p = decode_name(data, p)
        if p - pos > rdlen:
            return None
        if p + 20 == pos + rdlen:
            serial, refresh, retry, expire, minimum = struct.unpack(">IIIII", data[p:p + 20])
            return "%s %s %d %d %d %d %d" % (mname, rname, serial, refresh, retry, expire, minimum)
        return None
    if rtype == TYPE_SRV:
        if rdlen >= 7:
            pri, weight, port = struct.unpack(">HHH", raw[:6])
            target, np = decode_name(data, pos + 6)
            # R34/P3-1: 与 R33 CNAME/NS/PTR 及本函数 MX 分支同型, 校验
            # decode_name 实际消费字节(np-pos) ≤ 声明 rdlen。压缩指针情形
            # np-pos 恒为 8(6B 前缀 + 2B 指针) ≤ rdlen, 合法压缩 SRV 不受误杀。
            if np - pos > rdlen:
                return None
            return "%d %d %d %s" % (pri, weight, port, target)
        return None
    if rtype == TYPE_HTTPS:
        return raw.hex()
    return raw.hex()


def parse_message(data):
    """解析完整 DNS 报文。返回 dict 结构。"""
    if len(data) < 12:
        raise DNSError("message too short")
    qid, flags, qd, an, ns, ar = _PARSE_HDR.unpack_from(data, 0)
    rcode = flags & 0x000F
    opcode = (flags >> 11) & 0x0F
    truncated = bool(flags & 0x0200)
    rd = bool(flags & 0x0100)
    ra = bool(flags & 0x0080)
    pos = 12
    # 热路径优化: 局部绑定频繁调用的函数/dict, 避免全局查找+属性访问开销。
    # struct.Struct 已模块级预编译(原每次调用新建 Struct 对象)。
    _decode_name = decode_name
    _unpack_HH = _PARSE_HH
    _unpack_HHIH = _PARSE_HHIH
    _type_names = TYPE_NAMES
    _rcode_names = _RCODE_NAMES
    questions = []
    for _ in range(qd):
        name, pos = _decode_name(data, pos)
        # v1.9.82: question 段边界检查, 与 RR 段一致
        if pos + 4 > len(data):
            raise DNSError("truncated question section")
        qtype, qclass = _unpack_HH(data, pos)
        pos += 4
        questions.append({"name": name, "qtype": qtype,
                          "qtype_name": _type_names.get(qtype, str(qtype)),
                          "qclass": qclass})
    # v1.9.74 P1-1: 三 section 必须分列表, 不再混列到单一 answers。
    # 旧实现把 answer/authority/additional 全部 append 进 answers, 导致:
    #   - authority 段的 SOA(负缓存权威)被 _extract_answers_full 当成答案;
    #   - additional 段的 A(如 EDNS/NS glue)被误判为查询类型答案;
    #   - NODATA 判定、CNAME 链、fast_hit 答案数全被污染。
    # 现在 answers=仅 an(answer 段), authority=ns 段, additional=ar 段(OPT 已跳过);
    # 每条 RR 带 section 字段便于消费方判别。
    # D-06: 直接按 (列表, 名称, 计数) 迭代, 避免循环内构造临时 dict 做 section 查找。
    answers = []
    authority = []
    additional = []
    for section_list, rr_section, count in ((answers, "answer", an),
                                             (authority, "authority", ns),
                                             (additional, "additional", ar)):
        for _ in range(count):
            name, pos = _decode_name(data, pos)
            # RR 头固定 10 字节: 校验长度防止越界 unpack
            if pos + 10 > len(data):
                raise DNSError("truncated RR header")
            rtype, rclass, ttl, rdlen = _unpack_HHIH(data, pos)
            pos += 10
            if rtype == TYPE_OPT:
                # OPT RR 无 rdata 解析，直接跳过；但仍需校验 rdlen 不越界，
                # 否则恶意/截断包会让 pos 越过 data 末尾。
                if pos + rdlen > len(data):
                    raise DNSError("truncated OPT rdata")
                pos += rdlen
                continue
            # rdata 长度越界校验
            if pos + rdlen > len(data):
                raise DNSError("truncated RR rdata")
            try:
                value = _parse_rdata(data, pos, rtype, rdlen)
            except Exception:
                value = data[pos:pos + rdlen].hex()
            pos += rdlen
            if value is None:
                # R32/P3-1: 结构化类型(A/AAAA/MX/SRV/SOA) rdlen 与预期结构不符时,
                # _parse_rdata 返回 None → 整条 RR 丢弃, 不降级为 hex 字符串入库,
                # 避免产出 rdata 长度不匹配的非法应答或绕过 rebind 私有地址判定。
                continue
            section_list.append({
                "name": name, "type": rtype,
                "type_name": _type_names.get(rtype, str(rtype)),
                "ttl": ttl, "rdata": value,
                "section": rr_section,
            })
    return {
        "id": qid, "rcode": rcode, "rcode_name": _rcode_names.get(rcode, "RCODE%d" % rcode),
        "truncated": truncated, "ra": ra, "rd": rd, "opcode": opcode,
        "questions": questions, "answers": answers,
        "authority": authority, "additional": additional,
        "answer_count": an,
    }


_RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
                4: "NOTIMP", 5: "REFUSED"}


def _rcode_name(rcode):
    return _RCODE_NAMES.get(rcode, "RCODE%d" % rcode)


# ---------- TCP / TLS 帧 ----------
def tcp_frame(payload):
    """DNS over TCP: 2 字节长度前缀。"""
    return struct.pack(">H", len(payload)) + payload


def parse_tcp_frame(data):
    """从 TCP 流中提取一条 DNS 报文。返回 (dns_bytes, rest)。"""
    if len(data) < 2:
        raise DNSError("incomplete frame header")
    (length,) = struct.unpack(">H", data[:2])
    if len(data) < 2 + length:
        raise DNSError("incomplete frame body")
    return data[2:2 + length], data[2 + length:]


# ---------- 构造响应 ----------
def encode_rdata(rtype, value):
    """将 rdata 字符串编码为字节。"""
    value = value.strip()
    if rtype == TYPE_A:
        try:
            return socket.inet_aton(value)
        except OSError:
            # 非法 IPv4(如 forceIp 规则误配 "abcd"/主机名)不再把任意 4 字节
            # 字符串当 IP 编码(旧兜底会把 "abcd" 编为 97.98.99.100)。返回 None,
            # build_response_body_answers 跳过该记录; 规则配置侧也会在创建时
            # 校验 forceIp 的 IP 合法性。
            return None
    if rtype == TYPE_AAAA:
        try:
            return socket.inet_pton(socket.AF_INET6, value)
        except OSError:
            # 与 TYPE_A 同型: 非法 IPv6 返回 None 跳过, 不做 16 字节字符串兜底。
            return None
    if rtype in (TYPE_CNAME, TYPE_NS, TYPE_PTR):
        # R39/P3-1: 与 SOA/SRV 分支同型兜底。恶意上游在 wire label 发送非 ASCII
        # 字节时 decode_name 经 errors="replace" 产出 U+FFFD, 重建应答阶段
        # encode_name 的 IDNA 路径抛 DNSError; 此处兜底后落入末尾
        # bytes.fromhex(value) → value.encode(), 不穿透 miss 主路径。
        try:
            return encode_name(value)
        except (ValueError, DNSError, struct.error):
            pass
    if rtype == TYPE_MX:
        parts = value.split(" ", 1)
        # R43/P3-1: 收窄为 ASCII 数字(拒绝 Unicode 数字, 避免 int() 抛 ValueError)。
        # parts[0] 为空串时 `not parts[0]` 短路 → 默认 10, 与原 isdigit()(空串 False)一致。
        pref = int(parts[0]) if parts and parts[0] and all('0' <= c <= '9' for c in parts[0]) else 10
        target = parts[1] if len(parts) > 1 else value
        try:
            return struct.pack(">H", pref) + encode_name(target)
        except (ValueError, DNSError, struct.error):
            pass
    if rtype == TYPE_TXT:
        s = value.strip('"')
        b = s.encode("utf-8")
        # R32/P2-1: 原实现 `[:255]` 硬截断为单段, DKIM/DMARC 长记录(256~400B)
        # 后续字节丢失 → 客户端收到截断 TXT, 邮件认证失败。
        # RFC 1035 §3.3.14: TXT rdata 由若干 ≤255 字节的 <character-string> 拼接,
        # 每段前 1 字节长度前缀。解码侧(_parse_rdata)已将多段拼接为一个带引号串,
        # 编码侧按 255 字节重新分块, 保证往返对称、不丢字节。
        if not b:
            return b"\x00"
        # R41/P3-2: 原按 255 字节硬切在 UTF-8 字节流上, 未对齐字符边界。多字节字符
        # (如 CJK 3 字节)在 255 边界断开时, 解析侧对每段独立 decode("utf-8",
        # errors="replace") 各产出 U+FFFD, 往返不一致。改为逐字符累积, 使每段编码后
        # ≤255 字节且不切断任何多字节字符。纯 ASCII 长 TXT(DKIM/DMARC/SPF)每字符
        # 1 字节, 分块结果与原 255 字节硬切完全一致, 无回归。
        segs = []
        cur = bytearray()
        for ch in s:
            cb = ch.encode("utf-8")
            if len(cur) + len(cb) > 255:
                segs.append(bytes(cur))
                cur = bytearray()
            cur.extend(cb)
        if cur:
            segs.append(bytes(cur))
        return b"".join(bytes([len(seg)]) + seg for seg in segs)
    if rtype == TYPE_SOA:
        # R37/P3-1: 与解析侧 _parse_rdata SOA 分支线格式对称。
        # 解析侧把 rdata 解码为 "mname rname serial refresh retry expire minimum"
        # (前 2 字段域名, 后 5 字段 uint32); 此处必须按同格式重新编码, 否则落入
        # 默认 bytes.fromhex() → ValueError → value.encode() 产出 UTF-8 文本字节,
        # 客户端把首字节(如 'n'=0x6e=110)当标签长度 → 越界拒绝 SOA 应答。
        parts = value.split()
        if len(parts) >= 7:
            try:
                return (encode_name(parts[0]) + encode_name(parts[1])
                        + struct.pack(">IIIII", int(parts[2]), int(parts[3]),
                                      int(parts[4]), int(parts[5]), int(parts[6])))
            except (ValueError, DNSError, struct.error):
                pass
    if rtype == TYPE_SRV:
        # R37/P3-1: 与解析侧 _parse_rdata SRV 分支线格式对称。
        # 解析侧把 rdata 解码为 "priority weight port target"
        # (前 3 字段 uint16, 末字段域名); 原落入默认兜底产出 UTF-8 文本字节,
        # 往返线格式不对称(正确 26B 线格式被编为 27B 文本)。
        parts = value.split()
        if len(parts) >= 4:
            try:
                return (struct.pack(">HHH", int(parts[0]), int(parts[1]), int(parts[2]))
                        + encode_name(parts[3]))
            except (ValueError, DNSError, struct.error):
                pass
    try:
        return bytes.fromhex(value)
    except ValueError:
        return value.encode()


# 预编译 struct: 响应头构造热路径避免重复编译
_RESP_HDR = struct.Struct(">HHHHH")


def _response_header_bits(query_data, rcode, truncated=False):
    """从请求报文提取 qid 并构造响应 flags。返回 (qid_bytes, new_flags)。
    qid 直接截取原始字节(大端序), 避免 unpack+repack 的双重开销。
    D-04: 掩码保留 opcode(0x7800) + RD(0x0100) + CD(0x0010), 置 QR+RA, 附 rcode。"""
    qid_bytes = query_data[0:2]
    flags = (query_data[2] << 8) | query_data[3]
    new_flags = (flags & 0x7910) | 0x8080 | (rcode & 0x0F)
    if truncated:
        new_flags |= 0x0200  # TC
    return qid_bytes, new_flags

def build_response_header(query_data, rcode, an_count, truncated=False, ar_count=0):
    """构造响应 12 字节头（qid 回显 + QR/RD/RA/rcode + 计数）。
    ar_count: additional 段计数(回显 EDNS OPT 时传 1)。"""
    qid_bytes, new_flags = _response_header_bits(query_data, rcode, truncated)
    return qid_bytes + _RESP_HDR.pack(new_flags, 1, an_count, 0, ar_count)
# 预编译 struct: 响应 RR 头 (name 之后的 type/class/ttl/rdlen)
_RR_HDR = struct.Struct(">HHIH")

# 预编译 struct: 查询构造热路径 (build_query)
_QHDR = struct.Struct(">HHHHHH")   # 12 字节查询头
_QTAIL = struct.Struct(">HH")      # question 尾部 qtype + qclass
_OPT_RR = struct.Struct(">HHIH")   # OPT RR: type/class(size)/ttl/rdlen

# 预编译 struct: parse_message 热路径(原每次调用都新建 Struct 对象, 浪费)
_PARSE_HDR = struct.Struct(">HHHHHH")
_PARSE_HH = struct.Struct(">HH").unpack_from
_PARSE_HHIH = struct.Struct(">HHIH").unpack_from


def extract_question(data):
    """返回第一个 question section 的原始字节(qname 含长度前缀与 null 终止 +
    qtype(2) + qclass(2))。v1.9.74 P0-2: question 段必须原样回显客户端查询字节
    (含 0x20 大小写), 不能再用小写化 domain 重新编码。解析失败返回 None。

    R7/P3-4: 原实现自带一份宽泛 try/except + 独立的标签遍历, 与
    _question_edns_info 的 question 段切片逻辑重复(且后者已被 build_response 复用,
    边界/压缩指针/截断守卫更完备)。此处直接复用 _question_edns_info(data)[0]——
    二者对 qd<1 / question 截断 / question 区压缩指针的失败语义完全一致(均返回
    None), 消除第二份易漂移的宽 except。注意: 这会顺带遍历 additional 段(开销与
    单独走一遍 question 相当), 换来单一事实来源。"""
    return _question_edns_info(data)[0]


def _question_edns_info(data):
    """单次遍历 question + additional 段, 返回 (qbytes, bufsize, opt_bytes)。

    合并 extract_question + _edns_bufsize + _opt_rr_bytes 三次重复的标签遍历:
    原快路径每次缓存命中要把 question 段走 3 遍、additional 段走 2 遍。
    这里一遍走完, 结果与三者分别调用完全一致(含边界/压缩指针/钳制语义)。
    解析失败返回 (None, 512, None) —— 与各函数独立失败行为一致, 不误杀。

    R5/P3-6 已知设计取舍: question 段任一截断点(见下方 :567/:582/:587/:592)
    均直接 return (qbytes, 512, None), 即使该报文 additional 段本有合法 OPT
    也不解析——question 截断后 pos 已不可靠, 无法安全跳到 additional。仅当
    qd>1 且后续 question 截断(畸形/截断包)时 OPT 丢失、bufsize 钳到 512;
    正常 qd=1 包不受影响。行为合理(畸形 question 本就不应信任其 OPT), 不为此
    增加从 header ar 计数 + 固定偏移回跳的复杂度。"""
    try:
        dlen = len(data)
        if dlen < 12:
            return None, 512, None
        qd = struct.unpack(">H", data[4:6])[0]
        ar = struct.unpack(">H", data[10:12])[0]
        pos = 12
        qbytes = None
        # ---- question 段: 遍历, 同时记录第一个 question 的原始字节 ----
        for qi in range(qd):
            qstart = pos
            # P2-1/R4: 守卫 pos >= dlen。上一条 question 的 pos+=4 可能使 pos==dlen,
            # 下轮迭代 while 顶部 data[pos] 抛 IndexError → 外层 except 丢弃已解析 qbytes。
            # 此处提前返回已解析结果, 不穿透 except。
            if pos >= dlen:
                return (None if qi == 0 else qbytes), 512, None
            while True:
                ln = data[pos]
                if ln == 0:
                    qend = pos + 1   # 含 null 终止符
                    pos += 1
                    break
                if ln & 0xC0 == 0xC0:
                    # question 区不应出现压缩指针
                    if qi == 0:
                        return None, 512, None
                    # P2-2/R4: 压缩指针需 2 字节, 对齐 additional 段(:597)。
                    # 若指针字节位于报文末尾(pos==dlen-1), pos+=2 使 pos>dlen,
                    # 随后 pos+=4 进一步越界, 下轮 qi 读 data[pos] → IndexError。
                    if pos + 1 >= dlen:
                        return (None if qi == 0 else qbytes), 512, None
                    pos += 2
                    break
                pos += 1 + ln
                if pos >= dlen:
                    return (None if qi == 0 else qbytes), 512, None
            # R4: 名字已终止, 校验 qtype+qclass 4 字节(所有 qi, 不只 qi==0)。
            # 原仅 qi==0 检查 qend+4>dlen, qi>=1 直接 pos+=4 可使 pos>dlen,
            # 下轮 qi 读 data[pos] → IndexError → 外层 except 丢弃 qbytes。
            if pos + 4 > dlen:
                return (None if qi == 0 else qbytes), 512, None
            if qi == 0:
                qbytes = data[qstart:pos + 4]   # qname + qtype + qclass
            pos += 4   # qtype + qclass
        # ---- additional 段: 找 OPT RR, 一次拿到 bufsize + opt 原始字节 ----
        bufsize = 512
        opt_bytes = None
        for _ in range(ar):
            rstart = pos
            # P2-1/R4: 守卫 pos >= dlen。上一条 RR 的 pos=rr_end 可能使 pos==dlen,
            # 下轮迭代 while 顶部 data[pos] 抛 IndexError → 外层 except 丢弃已解析结果。
            if pos >= dlen:
                break
            skip_rr = False
            while True:
                ln = data[pos]
                if ln == 0:
                    pos += 1
                    break
                if ln & 0xC0 == 0xC0:
                    # P2-7: 校验压缩指针目标范围。指针只能向前引用(ptr < pos)
                    # 且不能超出报文边界(ptr < dlen)。不合法则跳过该 RR。
                    if pos + 1 >= dlen:
                        skip_rr = True
                        pos += 2
                        break
                    ptr = ((ln & 0x3F) << 8) | data[pos + 1]
                    if not (ptr < pos and ptr < dlen):
                        skip_rr = True
                    pos += 2
                    break
                pos += 1 + ln
                # R3-P2-1: 正常标签遍历后越界校验, 对齐 question 段(:576)。
                # 恶意/截断 RR 的 owner name 大长度字节可使 pos 越过 dlen,
                # 下一轮 while 读 data[pos] 抛 IndexError → 外层 except 把已
                # 解析的 qbytes/opt 一并丢弃。此处 break 只丢这一条坏 RR。
                if pos >= dlen:
                    break
            if skip_rr:
                # 指针目标非法: 读完 RR 头后跳过整个 RR(rr_end), 不崩溃
                if pos + 10 > dlen:
                    break
                rdlen = struct.unpack(">H", data[pos + 8:pos + 10])[0]
                # R2-P2 [P2-2]: 跳帧前校验整 RR 长度不越界。恶意/截断的 additional 段
                # rdlen 可使 pos 越过 dlen, 下一轮 while 读 data[pos] 抛 IndexError →
                # 外层 except 把已解析的 qbytes/opt 一并丢弃(DO 位丢失、bufsize 钳到
                # 512)。此处 break 只丢这一条坏 RR, 不污染已解析结果。
                rr_end = pos + 10 + rdlen
                if rr_end > dlen:
                    break
                pos = rr_end
                continue
            if pos + 10 > dlen:
                break
            rtype = struct.unpack(">H", data[pos:pos + 2])[0]
            rdlen = struct.unpack(">H", data[pos + 8:pos + 10])[0]
            rr_end = pos + 10 + rdlen
            # R3-P2-1: 正常 RR 路径 rr_end 越界校验, 与 skip_rr 分支(:617)对齐。
            # 恶意 rdlen 可使 pos 越过 dlen, 下一轮 for 读 data[pos] 抛 IndexError →
            # 外层 except 把已解析的 qbytes/opt 一并丢弃。此处 break 只丢这一条坏 RR。
            if rr_end > dlen:
                break
            if rtype == TYPE_OPT:
                raw_buf = struct.unpack(">H", data[pos + 2:pos + 4])[0]
                bufsize = max(512, min(65535, raw_buf or 512))
                opt_bytes = data[rstart:rr_end]
            pos = rr_end
        return qbytes, bufsize, opt_bytes
    except Exception:
        return None, 512, None


def _edns_bufsize(query_data):
    """P2-9: 从客户端查询读 EDNS0 UDP payload size(OPT RR class 字段)。
    无 EDNS OPT → 512(经典 UDP 上限); 有 OPT → 钳制到 [512, 65535]。"""
    return _question_edns_info(query_data)[1]


def _opt_rr_bytes(query_data):
    """从查询报文 additional 段提取 OPT RR 原始字节(name=0 + type/class/ttl/rdlen + rdata)。

    v1.9.76 2.5: 有 OPT 的查询必须在响应 additional 段回显 OPT(保留 DO 位),
    否则下游/客户端按"不支持 EDNS"处理, 大响应能力与 DNSSEC 链验证失效。
    逐字节复制查询 OPT(含 DO 位与 options), 无 OPT 返回 None。"""
    return _question_edns_info(query_data)[2]


def build_udp_response(raw_query, qbytes, answers, rcode, abody=None,
                       owner_name=None, fallback_type=0, _edns=None, _ttl_override=None,
                       bufsize_cap=None):
    """UDP 响应公共拼接函数(v1.9.76 P0-1): 快路径与完整路径统一走这里做
    EDNS bufsize 截断 + 逐条丢弃 + 置 TC。

    - raw_query: 客户端原始查询(读 qid/flags/OPT bufsize/回显 OPT)
    - qbytes: 原样回显的 question 段字节(extract_question)
    - answers: answer dict 列表(逐条重编码用于截断判定)
    - abody: 快路径缓存的完整 answer bytes(可选)。未超 bufsize 直接复用,
      零重编码; 超 bufsize 才逐条重编码 chunk 累计长度、丢尾部置 TC。
      resp_body 缓存始终是完整 answers, 截断只在拼接时发生, 不改缓存。
    - _edns: 可选 (bufsize, opt_bytes) 预计算结果。快路径调用方已用
      _question_edns_info 一遍拿到 qbytes+bufsize+opt, 直接传入避免本函数
      再遍历一次 question/additional 段。
    - bufsize_cap: 客户端侧 bufsize 上限(防开放解析器放大攻击); 非空时
      钳制客户端声明的 bufsize, 超限应答置 TC 走 TCP。"""
    if len(raw_query) < 12:
        return None
    # P3-4: qbytes 防御性兜底(调用方 extract_question 失败可能传 None,
    # 下方 bytearray(qbytes) 与 len(qbytes) 会 TypeError)
    if qbytes is None:
        qbytes = b""
    if _edns is not None:
        limit, opt = _edns
    else:
        _qb, limit, opt = _question_edns_info(raw_query)
    # 客户端 bufsize 上限钳制(快路径已在调用方钳 _edns, 此处覆盖完整路径)
    if bufsize_cap is not None:
        limit = min(limit, int(bufsize_cap))
    opt_len = len(opt) if opt else 0
    # 先按 MAX_ANSWERS 截断答案数。abody 缓存的是完整(未按 MAX_ANSWERS 截断)的
    # 编码字节; 仅当传入答案数未超 MAX_ANSWERS 时才能直接复用 abody, 否则 abody
    # 含被丢弃的多余记录, 会绕过 MAX_ANSWERS 上限。
    n_in = len(answers or [])
    answers = (answers or [])[:MAX_ANSWERS]
    can_use_abody = abody is not None and n_in <= MAX_ANSWERS
    # 无截断快速路径: 完整 abody + OPT 直接放下
    if can_use_abody and 12 + len(qbytes) + len(abody) + opt_len <= limit:
        return (build_response_header(raw_query, rcode, len(answers), False, 1 if opt else 0)
                + qbytes + abody + (opt or b""))
    # 逐条累计: 超 bufsize 丢尾部并置 TC(让客户端走 TCP 重试)
    out = bytearray(qbytes)
    kept = 0
    truncated = False
    for a in answers:
        chunk = build_response_body_answers([a], owner_name=owner_name,
                                            fallback_type=fallback_type,
                                            _ttl_override=_ttl_override)
        if 12 + len(out) + len(chunk) + opt_len > limit:
            truncated = True
            break
        out += chunk
        kept += 1
    return (build_response_header(raw_query, rcode, kept, truncated, 1 if opt else 0)
            + bytes(out) + (opt or b""))


def build_simple_response(raw_query, rcode):
    """无 answer 段响应(NXDOMAIN/NOTIMP/空 NOERROR): 回显 question + 可选 OPT。
    v1.9.76 2.5: 与 build_udp_response 一致回显 OPT(保留 DO 位)。
    v1.9.85: 一遍遍历同时拿到 qbytes + opt(原 extract_question + _opt_rr_bytes 两遍)。"""
    if len(raw_query) < 12:
        return None
    qbytes, _limit, opt = _question_edns_info(raw_query)
    if qbytes is None:
        qbytes = b""
    return (build_response_header(raw_query, rcode, 0, False, 1 if opt else 0)
            + qbytes + (opt or b""))


def build_response_body_answers(answers, owner_name=None, fallback_type=0, _ttl_override=None):
    """只构造 answer section bytes(不含 question)。
    v1.9.74 P0-2: 快路径缓存的 resp_body 只缓存 answer 段; question 段每次从
    raw_query 原样切片(extract_question), 既保证 0x20 大小写逐位回显, 又避免把
    小写化 domain 编码进 question 段污染上游 0x20 校验。
    v1.9.85: 缓存回填的 answers 无 "name" 键, owner_name 对所有答案相同——
    域名编码只做一次(原每条答案都 encode_name(name), 多答案时重复 N 次)。
    v1.9.85: _ttl_override 传入时统一覆盖每条 TTL, 避免快路径为 TTL 衰减而
    [dict(a, ttl=...) for a in answers] 整表拷贝 dict(每命中一次的临时对象)。"""
    out = bytearray()
    enc_owner = encode_name(owner_name) if owner_name else b"\x00"
    _rr_hdr = _RR_HDR

    def _append(a, ttl):
        rtype = int(a.get("type", fallback_type) or fallback_type)
        rdata = encode_rdata(rtype, a.get("value", a.get("rdata", "")))
        # rdata 编码失败(如非法 A/AAAA)跳过整条 RR, 不产出畸形应答
        if rdata is None:
            return
        name = a.get("name")
        # 注意: 必须用 out.extend 方法调用, 不能写 out += —— 增广赋值会让
        # Python 把 out 当作本内嵌函数的局部变量, 触发 UnboundLocalError。
        out.extend(encode_name(name) if name else enc_owner)
        out.extend(_rr_hdr.pack(rtype, CLASS_IN, ttl, len(rdata)))
        out.extend(rdata)

    if _ttl_override is None:
        for a in answers:
            _append(a, _safe_int(a.get("ttl", 300), 300))
    else:
        ttl = _safe_int(_ttl_override, 300)
        for a in answers:
            _append(a, ttl)
    return bytes(out)


def build_response_body(domain, qtype, answers):
    """兼容旧接口: question + answer。新快路径应直接用
    extract_question + build_response_body_answers。"""
    question = encode_name(domain) + struct.pack(">HH", qtype, CLASS_IN)
    return question + build_response_body_answers(answers, owner_name=domain,
                                                 fallback_type=qtype)


def build_response(query_data, domain, qtype, answers, rcode=0, bufsize_cap=None):
    """基于请求报文构造响应。answers: [{value, type, ttl, name?}]。
    v1.9.76 P0-1: 统一走 build_udp_response 做 EDNS bufsize 截断 + 逐条丢弃 + 置 TC,
    并回显 OPT(保留 DO 位)。答案数仍限 MAX_ANSWERS。
    bufsize_cap: 客户端侧 bufsize 上限(防放大), 透传 build_udp_response。"""
    if len(query_data) < 12:
        return None
    answers = (answers or [])[:MAX_ANSWERS]
    qbytes = extract_question(query_data)
    if qbytes is None:
        qbytes = encode_name(domain) + struct.pack(">HH", qtype, CLASS_IN)
    return build_udp_response(query_data, qbytes, answers, rcode,
                              abody=None, owner_name=domain, fallback_type=qtype,
                              bufsize_cap=bufsize_cap)


def build_error_response(query_data, rcode=2):
    """基于请求报文构建一个错误响应（SERVFAIL 等），保留 question。

    D-04: 保留 opcode(RFC 1035)。
    D-05: 回显 EDNS OPT RR(保留 DO 位), 与 build_simple_response 一致。
    P2-6: 用 _question_edns_info 切片原始 question 字节(保留 0x20 大小写),
    与 build_simple_response / build_udp_response 做法对齐。原 encode_name(name)
    重新编码丢失原始大小写, 破坏 0x20 投毒防护。"""
    if len(query_data) < 12:
        return None
    # P2-6: 一遍拿到原始 question 字节(含 0x20) + OPT, 不再 decode_name 后
    # encode_name 重新编码(丢失大小写)。
    qbytes, _limit, opt = _question_edns_info(query_data)
    if qbytes is None:
        qbytes = b""
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", query_data[:12])
    # D-04: 掩码保留 opcode(0x7800) + RD(0x0100) + CD(0x0010), 置 QR+RA。
    flags = (flags & 0x7910) | 0x8080 | (rcode & 0x0F)
    opt_count = 1 if opt else 0
    header = struct.pack(">HHHHHH", qid, flags, qd, 0, 0, opt_count)
    resp = header + qbytes
    if opt:
        resp += opt
    return resp
