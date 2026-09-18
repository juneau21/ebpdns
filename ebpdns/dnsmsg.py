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
        if not label.isascii():
            # #5 [中] IDNA 死代码简化: 原外层 except UnicodeError 内重试同一
            # encode("idna") 是死代码(结果必然相同), 直接一次编码, 失败抛 DNSError。
            try:
                b = label.encode("idna")
            except UnicodeError:
                raise DNSError("invalid IDNA label: %s" % label)
        else:
            b = label.encode()
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
        # 累计 presentation 长度: 标签字节 + 其后分隔点(首个标签前无点)
        name_len += length + (1 if name_len else 0)
        if name_len > 255:
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
            need = (128 - (opts_len % 128)) % 128
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
    # 热路径优化: 局部绑定频繁调用的函数/dict, 避免全局查找+属性访问开销
    _decode_name = decode_name
    _unpack_HH = struct.Struct(">HH").unpack_from
    _unpack_HHIH = struct.Struct(">HHIH").unpack_from
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
    answers = []
    authority = []
    additional = []
    for rr_section, count in (("answer", an), ("authority", ns), ("additional", ar)):
        section_list = {"answer": answers, "authority": authority,
                        "additional": additional}[rr_section]
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
                value = _parse_rdata(data, pos, rtype, rdlen, len(data))
            except Exception:
                value = data[pos:pos + rdlen].hex()
            pos += rdlen
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


# 预编译 struct: 响应头构造热路径避免重复编译
_RESP_HDR = struct.Struct(">HHHHH")


def _response_header_bits(query_data, rcode, truncated=False):
    """从请求报文提取 qid 并构造响应 flags。返回 (qid_bytes, new_flags)。
    qid 直接截取原始字节(大端序), 避免 unpack+repack 的双重开销。
    热路径优化: 用 int.from_bytes 读取 flags 避免切片创建。"""
    qid_bytes = query_data[0:2]
    # 直接从 bytes 切片读 uint16, 比 int.from_bytes + slice 快
    flags = (query_data[2] << 8) | query_data[3]
    new_flags = (flags & 0x0110) | 0x8080 | (rcode & 0x0F)  # QR RD RA
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


def extract_question(data):
    """返回第一个 question section 的原始字节(qname 含长度前缀与 null 终止 +
    qtype(2) + qclass(2))。v1.9.74 P0-2: question 段必须原样回显客户端查询字节
    (含 0x20 大小写), 不能再用小写化 domain 重新编码。解析失败返回 None。"""
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
                end = pos + 1  # 含 null 终止符
                break
            if ln & 0xC0 == 0xC0:  # question 区不应出现压缩指针
                return None
            pos += 1 + ln
            if pos >= len(data):
                return None
        if end + 4 > len(data):
            return None
        return data[start:end + 4]  # qname + qtype + qclass
    except Exception:
        return None


def _edns_bufsize(query_data):
    """P2-9: 从客户端查询读 EDNS0 UDP payload size(OPT RR class 字段)。
    无 EDNS OPT → 512(经典 UDP 上限); 有 OPT → 钳制到 [512, 65535]。"""
    try:
        if len(query_data) < 12:
            return 512
        qd = struct.unpack(">H", query_data[4:6])[0]
        ar = struct.unpack(">H", query_data[10:12])[0]
        pos = 12
        for _ in range(qd):
            while True:
                ln = query_data[pos]
                if ln == 0:
                    pos += 1
                    break
                if ln & 0xC0 == 0xC0:
                    pos += 2
                    break
                pos += 1 + ln
            pos += 4  # qtype + qclass
        for _ in range(ar):
            while True:
                ln = query_data[pos]
                if ln == 0:
                    pos += 1
                    break
                if ln & 0xC0 == 0xC0:
                    pos += 2
                    break
                pos += 1 + ln
            if pos + 10 > len(query_data):
                break
            rtype = struct.unpack(">H", query_data[pos:pos + 2])[0]
            bufsize = struct.unpack(">H", query_data[pos + 2:pos + 4])[0]
            rdlen = struct.unpack(">H", query_data[pos + 8:pos + 10])[0]
            pos += 10 + rdlen
            if rtype == TYPE_OPT:
                return max(512, min(65535, bufsize or 512))
    except Exception:
        pass
    return 512


def _opt_rr_bytes(query_data):
    """从查询报文 additional 段提取 OPT RR 原始字节(name=0 + type/class/ttl/rdlen + rdata)。

    v1.9.76 2.5: 有 OPT 的查询必须在响应 additional 段回显 OPT(保留 DO 位),
    否则下游/客户端按"不支持 EDNS"处理, 大响应能力与 DNSSEC 链验证失效。
    逐字节复制查询 OPT(含 DO 位与 options), 无 OPT 返回 None。"""
    try:
        if len(query_data) < 12:
            return None
        qd = struct.unpack(">H", query_data[4:6])[0]
        ar = struct.unpack(">H", query_data[10:12])[0]
        pos = 12
        for _ in range(qd):
            while True:
                ln = query_data[pos]
                if ln == 0:
                    pos += 1
                    break
                if ln & 0xC0 == 0xC0:
                    pos += 2
                    break
                pos += 1 + ln
            pos += 4  # qtype + qclass
        for _ in range(ar):
            start = pos
            while True:
                ln = query_data[pos]
                if ln == 0:
                    pos += 1
                    break
                if ln & 0xC0 == 0xC0:
                    pos += 2
                    break
                pos += 1 + ln
            if pos + 10 > len(query_data):
                break
            rtype = struct.unpack(">H", query_data[pos:pos + 2])[0]
            rdlen = struct.unpack(">H", query_data[pos + 8:pos + 10])[0]
            rr_end = pos + 10 + rdlen
            pos = rr_end
            if rtype == TYPE_OPT:
                return query_data[start:rr_end]
    except Exception:
        pass
    return None


def build_udp_response(raw_query, qbytes, answers, rcode, abody=None,
                       owner_name=None, fallback_type=0):
    """UDP 响应公共拼接函数(v1.9.76 P0-1): 快路径与完整路径统一走这里做
    EDNS bufsize 截断 + 逐条丢弃 + 置 TC。

    - raw_query: 客户端原始查询(读 qid/flags/OPT bufsize/回显 OPT)
    - qbytes: 原样回显的 question 段字节(extract_question)
    - answers: answer dict 列表(逐条重编码用于截断判定)
    - abody: 快路径缓存的完整 answer bytes(可选)。未超 bufsize 直接复用,
      零重编码; 超 bufsize 才逐条重编码 chunk 累计长度、丢尾部置 TC。
      resp_body 缓存始终是完整 answers, 截断只在拼接时发生, 不改缓存。
    """
    if len(raw_query) < 12:
        return None
    limit = _edns_bufsize(raw_query)
    opt = _opt_rr_bytes(raw_query)
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
                                            fallback_type=fallback_type)
        if 12 + len(out) + len(chunk) + opt_len > limit:
            truncated = True
            break
        out += chunk
        kept += 1
    return (build_response_header(raw_query, rcode, kept, truncated, 1 if opt else 0)
            + bytes(out) + (opt or b""))


def build_simple_response(raw_query, rcode):
    """无 answer 段响应(NXDOMAIN/NOTIMP/空 NOERROR): 回显 question + 可选 OPT。
    v1.9.76 2.5: 与 build_udp_response 一致回显 OPT(保留 DO 位)。"""
    if len(raw_query) < 12:
        return None
    qbytes = extract_question(raw_query) or b""
    opt = _opt_rr_bytes(raw_query)
    return (build_response_header(raw_query, rcode, 0, False, 1 if opt else 0)
            + qbytes + (opt or b""))


def build_response_body_answers(answers, owner_name=None, fallback_type=0):
    """只构造 answer section bytes(不含 question)。
    v1.9.74 P0-2: 快路径缓存的 resp_body 只缓存 answer 段; question 段每次从
    raw_query 原样切片(extract_question), 既保证 0x20 大小写逐位回显, 又避免把
    小写化 domain 编码进 question 段污染上游 0x20 校验。"""
    out = bytearray()
    for a in answers:
        rtype = int(a.get("type", fallback_type) or fallback_type)
        ttl = int(a.get("ttl", 300))
        rdata = encode_rdata(rtype, a["value"])
        name = a.get("name", owner_name)
        if not name:
            name = owner_name
        if not name:
            # 无 owner_name 兜底(不应发生): 用根标签, 避免 encode_name(None) 崩
            out += b"\x00"
        else:
            out += encode_name(name)
        out += _RR_HDR.pack(rtype, CLASS_IN, ttl, len(rdata))
        out += rdata
    return bytes(out)


def build_response_body(domain, qtype, answers):
    """兼容旧接口: question + answer。新快路径应直接用
    extract_question + build_response_body_answers。"""
    question = encode_name(domain) + struct.pack(">HH", qtype, CLASS_IN)
    return question + build_response_body_answers(answers, owner_name=domain,
                                                 fallback_type=qtype)


def build_response(query_data, domain, qtype, answers, rcode=0):
    """基于请求报文构造响应。answers: [{value, type, ttl, name?}]。
    v1.9.76 P0-1: 统一走 build_udp_response 做 EDNS bufsize 截断 + 逐条丢弃 + 置 TC,
    并回显 OPT(保留 DO 位)。答案数仍限 MAX_ANSWERS。"""
    if len(query_data) < 12:
        return None
    answers = (answers or [])[:MAX_ANSWERS]
    qbytes = extract_question(query_data)
    if qbytes is None:
        qbytes = encode_name(domain) + struct.pack(">HH", qtype, CLASS_IN)
    return build_udp_response(query_data, qbytes, answers, rcode,
                              abody=None, owner_name=domain, fallback_type=qtype)


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
        question = bytearray()
        for _ in range(qd):
            name, pos = decode_name(query_data, pos)
            if pos + 4 > len(query_data):
                return None
            question += encode_name(name)
            question += query_data[pos:pos + 4]
            pos += 4
        return header + bytes(question)
    except Exception:
        # 解析失败退化为空 question 的错误响应（客户端可识别 rcode）
        return header
