"""DNS 报文编解码 —— 纯标准库实现（无第三方依赖）。

支持:
  - 构建查询报文 (A/AAAA/MX/TXT/NS/CNAME/SOA... , 可选 EDNS0)
  - 解析响应报文 (header/question/answer/authority/additional, 支持压缩指针)
  - DNS over TCP / TLS 的长度前缀帧
"""

import struct
import socket

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


# ---------- 名称编解码 ----------
def encode_name(name):
    """将域名编码为 DNS 标签序列（不含根 0 结尾）。"""
    name = name.rstrip(".")
    if not name:
        return b"\x00"
    labels = name.split(".")
    out = bytearray()
    for label in labels:
        b = label.encode("idna") if not label.isascii() else label.encode()
        if len(b) > 63:
            raise DNSError("label too long: %s" % label)
        out.append(len(b))
        out += b
    out.append(0)
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
    while True:
        if pos >= len(data):
            raise DNSError("truncated name")
        length = data[pos]
        if length == 0:
            if not jump_done:
                end = pos + 1
            pos += 1
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
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
        if pos + length > len(data):
            raise DNSError("truncated label")
        labels.append(data[pos:pos + length].decode("ascii", errors="replace"))
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
    header = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 1 if edns else 0)
    question = encode_name(domain) + struct.pack(">HH", qtype, CLASS_IN)
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
            need = 128 - (opts_len % 128)
            if need < 4:
                need += 128
            if need > 512:
                need = 512
            options += struct.pack(">HH", 12, need - 4) + b"\x00" * (need - 4)
        opt_ttl = 0
        size = int(udp_size) if udp_size else 1232
        additional = b"\x00" + struct.pack(">HHIH", TYPE_OPT, size, opt_ttl, len(options)) + options
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
        raw = socket.inet_pton(socket.AF_INET6, addr)
    addr_bytes = raw[: (prefix + 7) // 8]
    # option code ECS = 8, len = 4 + addrlen
    return struct.pack(">HHHBB", 8, 4 + len(addr_bytes), family, 0, 0) + addr_bytes


def _rand_id():
    import os
    return int.from_bytes(os.urandom(2), "big")


# ---------- DNS 0x20 缓存投毒防护 ----------
def random_case_name(domain):
    """生成域名大小写随机变体（DNS 0x20 编码）。

    每个字母独立 50% 概率大写/小写。查询名增加约 26 位熵（与 qid 16bit +
    源端口 16bit 叠加），使伪造应答投毒需同时猜中 58+ bit，防御成本指数级
    上升。仅对明文 UDP/TCP 有意义（加密通道无投毒面）。
    返回: 大小写随机化的域名（标签分隔点不变）。
    """
    import random as _r
    out = []
    for ch in domain:
        if "a" <= ch <= "z":
            out.append(ch.upper() if _r.getrandbits(1) else ch)
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
def _parse_rdata(data, pos, rtype, rdlen, end):
    raw = data[pos:pos + rdlen]
    if rtype == TYPE_A:
        if rdlen == 4:
            return socket.inet_ntoa(raw)
        return raw.hex()
    if rtype == TYPE_AAAA:
        if rdlen == 16:
            return socket.inet_ntop(socket.AF_INET6, raw)
        return raw.hex()
    if rtype == TYPE_CNAME or rtype == TYPE_NS or rtype == TYPE_PTR:
        name, _ = decode_name(data, pos)
        return name
    if rtype == TYPE_MX:
        if rdlen >= 3:
            pref = struct.unpack(">H", raw[:2])[0]
            mx, _ = decode_name(data, pos + 2)
            return "%d %s" % (pref, mx)
        return raw.hex()
    if rtype == TYPE_TXT:
        out = []
        p = 0
        while p < rdlen:
            ln = raw[p]
            p += 1
            out.append(raw[p:p + ln].decode("utf-8", errors="replace"))
            p += ln
        return '"' + "".join(out) + '"'
    if rtype == TYPE_SOA:
        mname, p = decode_name(data, pos)
        rname, p = decode_name(data, p)
        if p + 20 <= pos + rdlen:
            serial, refresh, retry, expire, minimum = struct.unpack(">IIIII", data[p:p + 20])
            return "%s %s %d %d %d %d %d" % (mname, rname, serial, refresh, retry, expire, minimum)
        return raw.hex()
    if rtype == TYPE_SRV:
        if rdlen >= 7:
            pri, weight, port = struct.unpack(">HHH", raw[:6])
            target, _ = decode_name(data, pos + 6)
            return "%d %d %d %s" % (pri, weight, port, target)
        return raw.hex()
    if rtype == TYPE_HTTPS:
        return raw.hex()
    return raw.hex()


def parse_message(data):
    """解析完整 DNS 报文。返回 dict 结构。"""
    if len(data) < 12:
        raise DNSError("message too short")
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    rcode = flags & 0x000F
    opcode = (flags >> 11) & 0x0F
    truncated = bool(flags & 0x0200)
    rd = bool(flags & 0x0100)
    ra = bool(flags & 0x0080)
    pos = 12
    questions = []
    for _ in range(qd):
        name, pos = decode_name(data, pos)
        qtype, qclass = struct.unpack(">HH", data[pos:pos + 4])
        pos += 4
        questions.append({"name": name, "qtype": qtype, "qtype_name": type_name(qtype), "qclass": qclass})
    answers = []
    for rr_type, count in (("answer", an), ("authority", ns), ("additional", ar)):
        for _ in range(count):
            name, pos = decode_name(data, pos)
            rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
            pos += 10
            if rtype == TYPE_OPT:
                # OPT RR 无 rdata 解析，直接跳过
                pos += rdlen
                continue
            try:
                value = _parse_rdata(data, pos, rtype, rdlen, len(data))
            except Exception:
                value = data[pos:pos + rdlen].hex()
            pos += rdlen
            answers.append({
                "name": name, "type": rtype, "type_name": type_name(rtype),
                "ttl": ttl, "rdata": value,
            })
    return {
        "id": qid, "rcode": rcode, "rcode_name": _rcode_name(rcode),
        "truncated": truncated, "ra": ra, "rd": rd, "opcode": opcode,
        "questions": questions, "answers": answers,
        "answer_count": an,
    }


def _rcode_name(rcode):
    return {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
            4: "NOTIMP", 5: "REFUSED"}.get(rcode, "RCODE%d" % rcode)


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
            return value.encode()
    if rtype == TYPE_AAAA:
        try:
            return socket.inet_pton(socket.AF_INET6, value)
        except OSError:
            return value.encode()
    if rtype in (TYPE_CNAME, TYPE_NS, TYPE_PTR):
        return encode_name(value)
    if rtype == TYPE_MX:
        parts = value.split(" ", 1)
        pref = int(parts[0]) if parts and parts[0].isdigit() else 10
        target = parts[1] if len(parts) > 1 else value
        return struct.pack(">H", pref) + encode_name(target)
    if rtype == TYPE_TXT:
        s = value.strip('"')
        b = s.encode("utf-8")[:255]
        return bytes([len(b)]) + b
    try:
        return bytes.fromhex(value)
    except ValueError:
        return value.encode()


def _response_header_bits(query_data, rcode, truncated=False):
    """从请求报文提取 qid 并构造响应 flags。返回 (qid, flags)。"""
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", query_data[:12])
    new_flags = (flags & 0x0110) | 0x8080 | (rcode & 0x0F)  # QR RD RA
    if truncated:
        new_flags |= 0x0200  # TC
    return qid, new_flags
def build_response_header(query_data, rcode, an_count, truncated=False):
    """构造响应 12 字节头（qid 回显 + QR/RD/RA/rcode + 计数）。"""
    qid, new_flags = _response_header_bits(query_data, rcode, truncated)
    return struct.pack(">HHHHHH", qid, new_flags, 1, an_count, 0, 0)
def build_response_body(domain, qtype, answers):
    """构造 question + answer section（不含 header）。供快路径按缓存条目预编码复用。"""
    question = encode_name(domain) + struct.pack(">HH", qtype, CLASS_IN)
    answer_section = b""
    for a in answers:
        rtype = int(a.get("type", qtype) or qtype)
        ttl = int(a.get("ttl", 300))
        rdata = encode_rdata(rtype, a["value"])
        name = a.get("name", domain)
        answer_section += encode_name(name) + struct.pack(">HHIH", rtype, CLASS_IN, ttl, len(rdata)) + rdata
    return question + answer_section
def build_response(query_data, domain, qtype, answers, rcode=0):
    """基于请求报文构造响应。answers: [{value, type, ttl, name?}]。
    限制答案数量上限（避免超大 UDP 响应），超限设置 TC 位。"""
    if len(query_data) < 12:
        return None
    truncated = len(answers) > MAX_ANSWERS
    answers = answers[:MAX_ANSWERS]
    return build_response_header(query_data, rcode, len(answers), truncated) + build_response_body(domain, qtype, answers)


def build_error_response(query_data, rcode=2):
    """基于请求报文构建一个错误响应（SERVFAIL 等），保留 question。

    只回拷 question section（按 qdcount 重新编码），不复用原始 additional 段：
    原查询若带 EDNS OPT，直接 query_data[12:] 会把 OPT 原样附回但 arcount
    未同步更新，产生 OPT 在 additional 且计数错位的畸形响应。
    """
    if len(query_data) < 12:
        return None
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", query_data[:12])
    flags = (flags & 0x0110) | 0x8080 | (rcode & 0x0F)  # QR=1, RD, RA, 设置 RCODE
    header = struct.pack(">HHHHHH", qid, flags, qd, 0, 0, 0)
    pos = 12
    try:
        question = b""
        for _ in range(qd):
            name, pos = decode_name(query_data, pos)
            if pos + 4 > len(query_data):
                return None
            question += encode_name(name) + query_data[pos:pos + 4]
            pos += 4
        return header + question
    except Exception:
        # 解析失败退化为空 question 的错误响应（客户端可识别 rcode）
        return header
