//! 响应构造：header / UDP 响应 / 简单响应 / 错误响应 / answer body。

use crate::constants::*;
use crate::edns::question_edns_info;
use crate::name::encode_name;
use crate::rdata::encode_rdata;
use crate::record::AnswerInput;

fn be_u16(data: &[u8], pos: usize) -> Option<u16> {
    data.get(pos..pos + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
}

/// 构造响应 12 字节头（qid 回显 + QR/RD/RA/rcode + 计数）。
/// `ar_count`：回显 EDNS OPT 时传 1。query 不足 12 字节返回 `None`。
///
/// **[历史归因]** **qd 口径（P-05）**：本函数恒声明 `qd=1`，与 Python `dnsmsg.build_response_header`
/// （`_RESP_HDR.pack(new_flags, 1, an_count, 0, ar_count)`，dnsmsg.py:734-738）逐字节一致。
/// 调用方必须保证随后的 question 段**恰好**是 1 段（`qbytes` 来自
/// `question_edns_info`，正常 qd>=1 报文的第 0 个 question 恒非空）。
/// qd=0 / 首 question 畸形的报文必须走 [`build_error_response`]——那里的口径是
/// **[历史归因]** **动态 `declared_qd`**（Python `build_error_response` dnsmsg.py:1150
/// `declared_qd = 1 if qbytes else 0`），使"头部声明段数 == body 实际段数"。
///
/// **[历史归因]** 两个函数的口径差异不是不一致，而是与 Python 同名函数一一对应；共用本 helper 的
/// [`build_simple_response`] / [`build_udp_response`] 已由调用方保证 qbytes 非空。
pub fn build_response_header(
    query: &[u8],
    rcode: u8,
    an_count: u16,
    truncated: bool,
    ar_count: u16,
) -> Option<Vec<u8>> {
    build_response_header_qd(query, rcode, 1, an_count, truncated, ar_count)
}

/// **[历史归因]** 带显式 `qd_count` 的响应头构造（P-05：与 Python 的 `qd=1` 硬编码 + error 路径
/// 的动态 `declared_qd` 两种口径共用同一实现，避免两份易漂移的位运算）。
pub(crate) fn build_response_header_qd(
    query: &[u8],
    rcode: u8,
    qd_count: u16,
    an_count: u16,
    truncated: bool,
    ar_count: u16,
) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let qid = [query[0], query[1]];
    let flags = u16::from_be_bytes([query[2], query[3]]);
    // 保留 opcode(0x7800)+RD(0x0100)+CD(0x0010)，置 QR+RA，附 rcode。
    let mut new_flags = (flags & FLAG_KEEP_MASK) | FLAG_QR_RA | ((rcode as u16) & FLAG_RCODE_MASK);
    if truncated {
        new_flags |= FLAG_TC;
    }
    let mut out = Vec::with_capacity(12);
    out.extend(qid);
    out.extend(new_flags.to_be_bytes());
    out.extend(qd_count.to_be_bytes()); // qd
    out.extend(an_count.to_be_bytes());
    out.extend(0u16.to_be_bytes()); // ns
    out.extend(ar_count.to_be_bytes());
    Some(out)
}

/// 只构造 answer section bytes（不含 question）。
///
/// `encode_rdata` 失败的 RR 跳过（不写任何字节、不计数）。
/// 返回 `(body_bytes, n_encoded)`，让调用方按实际编码数填 `an_count`。
pub fn build_response_body_answers(
    answers: &[AnswerInput],
    owner_name: Option<&str>,
    fallback_type: u16,
    ttl_override: Option<u32>,
    enc_owner: Option<&[u8]>,
) -> (Vec<u8>, usize) {
    let enc_owner: Vec<u8> = match enc_owner {
        Some(b) => b.to_vec(),
        None => match owner_name {
            Some(n) => encode_name(n).unwrap_or_else(|_| vec![0]),
            None => vec![0],
        },
    };

    // 预分配：每条 RR 至少 10 字节头 + rdata，owner 共享只计一次。
    let mut out: Vec<u8> = Vec::with_capacity(enc_owner.len() + answers.len() * 32);
    let mut n_encoded = 0usize;

    for a in answers {
        let rtype = if a.rtype != 0 { a.rtype } else { fallback_type };
        let rdata = match encode_rdata(rtype, a.value) {
            Some(r) => r,
            None => continue, // 非法 rdata 跳过整条 RR
        };
        // owner 编码缓冲直接追加，避免每条答案一次 clone。
        match a.name {
            Some(n) => match encode_name(n) {
                Ok(w) => out.extend(w),
                Err(_) => out.extend(&enc_owner),
            },
            None => out.extend(&enc_owner),
        }
        let ttl_raw = match ttl_override {
            Some(t) => t,
            None => a.ttl.unwrap_or(TTL_DEFAULT),
        };
        let ttl = clamp_ttl(ttl_raw as u64);

        out.extend(rtype.to_be_bytes());
        out.extend(CLASS_IN.to_be_bytes());
        out.extend(ttl.to_be_bytes());
        out.extend((rdata.len() as u16).to_be_bytes());
        out.extend(rdata);
        n_encoded += 1;
    }

    (out, n_encoded)
}

/// 无 answer 段响应（NXDOMAIN / NOTIMP / 空 NOERROR）：回显 question + 可选 OPT。
pub fn build_simple_response(raw_query: &[u8], rcode: u8) -> Option<Vec<u8>> {
    if raw_query.len() < 12 {
        return None;
    }
    let info = question_edns_info(raw_query);
    let qbytes = info.qbytes.unwrap_or_default();
    let ar_count = if info.opt_bytes.is_some() { 1u16 } else { 0u16 };
    let opt = info.opt_bytes.unwrap_or_default();
    // **2.1.20（A-09 修复：FORMERR 回包 `qdcount` 与实际内容自相矛盾）**：
    // 此前这里无条件走 `build_response_header(..)`，而该函数**硬编码 `qd_count=1`**
    // ⇒ 当 question **解析失败**（畸形 label / 压缩指针环 / 70 字节 label …）时，
    // 回包只有 12 字节、**没有 question 段**，header 却声明 `qdcount=1`
    // （实测 `malformed 70B label` → `rcode=1 len=12 qd=1`；而 3 字节包走
    // `build_error_response_short` → `qd=0` 自洽 ⇒ 同一份代码两种口径）。
    //
    // 现在 `qdcount` **由实际写入的 question 字节决定**：解析成功 ⇒ 1（回显 question，
    // 与 RFC 一致）；解析失败 ⇒ **0**（"我没有 question 段"）。
    let qd_count: u16 = if qbytes.is_empty() { 0 } else { 1 };
    let header = build_response_header_qd(raw_query, rcode, qd_count, 0, false, ar_count)?;
    let mut out = Vec::with_capacity(header.len() + qbytes.len() + opt.len());
    out.extend(header);
    out.extend(qbytes);
    out.extend(opt);
    Some(out)
}

/// `build_udp_response` 的参数集合。
pub struct UdpResp<'a> {
    pub raw_query: &'a [u8],
    pub qbytes: Option<&'a [u8]>,
    pub answers: &'a [AnswerInput<'a>],
    pub rcode: u8,
    /// 快路径已编码的完整 answer body（可选）。
    pub abody: Option<&'a [u8]>,
    /// `abody` 中实际成功编码的 RR 数。
    pub abody_count: Option<usize>,
    pub owner_name: Option<&'a str>,
    pub fallback_type: u16,
    pub ttl_override: Option<u32>,
    /// 客户端侧 bufsize 上限（防放大）。
    pub bufsize_cap: Option<u16>,
    pub force_truncated: bool,
    /// 调用方预编码的 owner name bytes。
    pub enc_owner: Option<&'a [u8]>,
    /// 调用方预计算的 question/EDNS 解析结果（避免重复遍历查询报文）。
    pub edns_info: Option<&'a crate::edns::EdnsInfo>,
}

/// UDP 响应公共拼接：EDNS bufsize 截断 + 逐条丢弃 + 置 TC，并回显 OPT。
pub fn build_udp_response(c: &UdpResp<'_>) -> Option<Vec<u8>> {
    if c.raw_query.len() < 12 {
        return None;
    }
    let qbytes: &[u8] = c.qbytes.unwrap_or(&[]);
    // 复用调用方预计算结果，避免对查询报文二次遍历。
    let info = match c.edns_info {
        Some(info) => info.clone(),
        None => crate::edns::question_edns_info(c.raw_query),
    };
    let mut limit = info.bufsize;
    if let Some(cap) = c.bufsize_cap {
        limit = limit.min(cap);
    }
    let has_opt = info.opt_bytes.is_some();
    let opt = info.opt_bytes.unwrap_or_default();
    let opt_len = opt.len();
    let ar_count: u16 = if has_opt { 1 } else { 0 };

    let n_in = c.answers.len();
    let trimmed: &[AnswerInput] = &c.answers[..n_in.min(MAX_ANSWERS)];
    let can_use_abody = c.abody.is_some() && n_in <= MAX_ANSWERS;
    let count_truncated = n_in > MAX_ANSWERS;
    let force_tc = c.force_truncated || count_truncated;

    // 无截断快速路径：完整 abody + OPT 直接放下。
    if let (Some(abody), true) = (c.abody, can_use_abody) {
        if 12 + qbytes.len() + abody.len() + opt_len <= limit as usize {
            let an_count = match c.abody_count {
                Some(n) => n as u16,
                None => trimmed.len() as u16,
            };
            let header = build_response_header(c.raw_query, c.rcode, an_count, force_tc, ar_count)?;
            let mut out = Vec::with_capacity(header.len() + qbytes.len() + abody.len() + opt_len);
            out.extend(header);
            out.extend(qbytes);
            out.extend(abody);
            out.extend(opt);
            return Some(out);
        }
    }

    // 逐条累计：超 bufsize 丢尾部并置 TC。
    let enc_owner: Vec<u8> = match c.enc_owner {
        Some(b) => b.to_vec(),
        None => match c.owner_name {
            Some(n) => encode_name(n).unwrap_or_else(|_| vec![0]),
            None => vec![0],
        },
    };

    let mut out: Vec<u8> = qbytes.to_vec();
    let mut kept = 0usize;
    let mut truncated = force_tc;
    for a in trimmed {
        let chunk = build_response_body_answers(
            std::slice::from_ref(a),
            c.owner_name,
            c.fallback_type,
            c.ttl_override,
            Some(&enc_owner),
        )
        .0;
        if chunk.is_empty() {
            continue; // encode_rdata 失败：不占长度不计数
        }
        if 12 + out.len() + chunk.len() + opt_len > limit as usize {
            truncated = true;
            break;
        }
        out.extend(chunk);
        kept += 1;
    }

    let header = build_response_header(c.raw_query, c.rcode, kept as u16, truncated, ar_count)?;
    let mut resp = Vec::with_capacity(header.len() + out.len() + opt_len);
    resp.extend(header);
    resp.extend(out);
    resp.extend(opt);
    Some(resp)
}

/// 基于请求报文构造响应。answers: `{rtype, value, ttl?, name?}`。
#[allow(clippy::too_many_arguments)]
pub fn build_response(
    query: &[u8],
    domain: &str,
    qtype: u16,
    answers: &[AnswerInput<'_>],
    rcode: u8,
    bufsize_cap: Option<u16>,
    ttl_override: Option<u32>,
    truncated: bool,
) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let n_in = answers.len();
    let trimmed = &answers[..n_in.min(MAX_ANSWERS)];
    let count_tc = n_in > MAX_ANSWERS;

    let info = question_edns_info(query);
    // **[历史归因]** 无 question 回显字节时，用 encode_name 重新构造（对齐 Python 兜底）。
    let qbytes_owned: Vec<u8>;
    let qbytes_ref: &[u8] = match info.qbytes.as_deref() {
        Some(q) if !q.is_empty() => q,
        _ => {
            let mut q = encode_name(domain).unwrap_or_default();
            q.extend(qtype.to_be_bytes());
            q.extend(CLASS_IN.to_be_bytes());
            qbytes_owned = q;
            &qbytes_owned
        }
    };

    build_udp_response(&UdpResp {
        raw_query: query,
        qbytes: Some(qbytes_ref),
        answers: trimmed,
        rcode,
        abody: None,
        abody_count: None,
        owner_name: Some(domain),
        fallback_type: qtype,
        ttl_override,
        bufsize_cap,
        force_truncated: truncated || count_tc,
        enc_owner: None,
        edns_info: Some(&info),
    })
}

/// 基于请求报文构建错误响应（SERVFAIL 等），保留 question 与 opcode / OPT。
///
/// **[历史归因]** P-05：qd 口径 = 动态 `declared_qd`，与 Python `dnsmsg.build_error_response`
/// （dnsmsg.py:1150-1151 `declared_qd = 1 if qbytes else 0`）一致：
/// qbytes 非空声明 1，空（qd=0 / 首 question 畸形）声明 0，保证头部声明段数与
/// **[历史归因]** body 实际段数自洽。与 [`build_response_header`] 的恒定 `qd=1` 是 Python
/// 两个同名函数各自的既有口径，逐条对齐而非强行统一成一个值。
pub fn build_error_response(query: &[u8], rcode: u8) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let info = question_edns_info(query);
    let qbytes = info.qbytes.unwrap_or_default();
    let opt_count = if info.opt_bytes.is_some() { 1u16 } else { 0u16 };
    let opt = info.opt_bytes.unwrap_or_default();

    // 声明 qd 与实际 question 段一致：qbytes 非空=1，空=0。
    let declared_qd = if qbytes.is_empty() { 0u16 } else { 1u16 };
    // 共用同一份 flag/位运算实现，避免 error 路径与正常路径漂移。
    let header = build_response_header_qd(query, rcode, declared_qd, 0, false, opt_count)?;

    let mut resp = Vec::with_capacity(header.len() + qbytes.len() + opt.len());
    resp.extend(header);
    resp.extend(&qbytes);
    resp.extend(opt);
    Some(resp)
}

/// 长度不足 12 字节的**截断**报文：合成一个 12 字节最小头，回 FORMERR/NOTIMP。
///
/// 为什么需要（P0-4）：标准 [`build_error_response`] / [`build_simple_response`] 都要求
/// `query.len() >= 12`（要按位回显 flags/opcode），截断包因此**无法**构造任何应答 ——
/// 旧实现只能返回 `None`，数据面兜底成 **SERVFAIL**。实测 11 例畸形包（含截断包）
/// 「该回 FORMERR 却回 SERVFAIL」正是这条路径。
///
/// 口径（尽力而为、绝不臆造）：
/// - qid：有 2 字节就回显，否则 0；
/// - flags：只置 QR + RA + rcode，**不回显** RD/CD/opcode（字节不足，无从得知）；
/// - 四段计数全部 0（无法解析出 question）。
///
/// 应答恒为 12 字节 ≤ 请求长度，**不存在放大**（不构成反射放大面）。
pub fn build_error_response_short(query: &[u8], rcode: u8) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(12);
    match query.get(0..2) {
        Some(qid) => out.extend_from_slice(qid),
        None => out.extend(0u16.to_be_bytes()),
    }
    let flags = FLAG_QR_RA | ((rcode as u16) & FLAG_RCODE_MASK);
    out.extend(flags.to_be_bytes());
    out.extend(0u16.to_be_bytes()); // qd
    out.extend(0u16.to_be_bytes()); // an
    out.extend(0u16.to_be_bytes()); // ns
    out.extend(0u16.to_be_bytes()); // ar
    Some(out)
}

/// 供内部读取 header 计数的小工具（保留以备下游使用）。
pub fn qd_count(query: &[u8]) -> Option<u16> {
    be_u16(query, 4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::AnswerInput;

    /// 构造一条查询：`qd` 为声明的 question 数，`with_question` 决定是否真的写入
    /// 一段 question（用于制造 qd=0 与"qd=1 但 question 缺失"两种畸形）。
    fn make_query(qid: u16, qd: u16, with_question: bool) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend(qid.to_be_bytes());
        q.extend(0x0100u16.to_be_bytes()); // RD
        q.extend(qd.to_be_bytes());
        q.extend(0u16.to_be_bytes());
        q.extend(0u16.to_be_bytes());
        q.extend(0u16.to_be_bytes());
        if with_question {
            q.extend(b"\x07example\x03com\x00");
            q.extend(1u16.to_be_bytes()); // A
            q.extend(1u16.to_be_bytes()); // IN
        }
        q
    }

    fn qd_of(pkt: &[u8]) -> u16 {
        u16::from_be_bytes([pkt[4], pkt[5]])
    }

    fn an_of(pkt: &[u8]) -> u16 {
        u16::from_be_bytes([pkt[6], pkt[7]])
    }
    fn ns_of(pkt: &[u8]) -> u16 {
        u16::from_be_bytes([pkt[8], pkt[9]])
    }
    fn ar_of(pkt: &[u8]) -> u16 {
        u16::from_be_bytes([pkt[10], pkt[11]])
    }
    fn flags_of(pkt: &[u8]) -> u16 {
        u16::from_be_bytes([pkt[2], pkt[3]])
    }

    /// **[历史归因]** P-05：`build_response_header` 恒 qd=1（Python `_RESP_HDR.pack(new_flags, 1, ...)`）。
    #[test]
    fn response_header_declares_qd_1_even_for_qd0_query() {
        let q0 = make_query(0x1234, 0, false);
        let h = build_response_header(&q0, 0, 0, false, 0).unwrap();
        assert_eq!(h.len(), 12);
        assert_eq!(qd_of(&h), 1, "正常路径头恒声明 qd=1（对齐 Python）");
        assert_eq!(an_of(&h), 0);
        assert_eq!(ns_of(&h), 0);
        assert_eq!(ar_of(&h), 0);
        assert_eq!(&h[..2], &[0x12, 0x34], "qid 必须回显");
    }

    /// **2.1.20（A-09）**：`build_simple_response` 的 `qdcount` 必须由**实际写入的
    /// question 字节**决定：解析成功 ⇒ 1；解析失败（无 question 段）⇒ **0**。
    ///
    /// 审计 A-09 实测：`malformed 70B label` / 压缩环 / `QR=1` / `opcode=2` 四种畸形查询
    /// 的回包都是 `rcode=1 len=12 qd=1` —— **12 字节里没有 question，头部却声明 1 段**
    /// （自相矛盾的报文会被严格客户端直接丢弃）。
    #[test]
    fn simple_response_reports_qd_0_when_question_unparseable() {
        // ① 畸形 label：长度字节 0x46=70 但剩余字节远不足 70 ⇒ 解析必然失败。
        let mut q = Vec::new();
        q.extend(0x1234u16.to_be_bytes());
        q.extend(0x0100u16.to_be_bytes()); // RD
        q.extend(1u16.to_be_bytes()); // qd=1
        q.extend([0u8; 6]);
        q.push(0x46); // 声明 70 字节 label
        q.extend(b"abc"); // 只给 3 字节
        let r = build_simple_response(&q, 1).expect("12+ 字节查询必须能构造回包");
        assert_eq!(r.len(), 12, "没有 question 段 ⇒ 回包恰好 12 字节");
        assert_eq!(qd_of(&r), 0, "**解析失败时 qdcount 必须是 0**（A-09）");
        assert_eq!(an_of(&r) + ns_of(&r) + ar_of(&r), 0);
        assert_eq!(flags_of(&r) & 0x000F, 1, "rcode=FORMERR");

        // ② 反向：question 可解析 ⇒ qd=1 且 question 段被回显（不得误伤正常路径）。
        let ok = make_query(0x1234, 1, true);
        let r2 = build_simple_response(&ok, 0).expect("正常查询");
        assert_eq!(qd_of(&r2), 1, "正常解析路径必须仍声明 qd=1");
        assert_eq!(r2.len(), 12 + 17, "question 段必须被回显");
    }

    /// P-05：`build_error_response` 动态 qd —— 有 question 段时声明 1。
    #[test]
    fn error_response_declares_qd_1_when_question_present() {
        let q = make_query(0xBEEF, 1, true);
        let r = build_error_response(&q, 2).unwrap();
        assert_eq!(qd_of(&r), 1, "有 qbytes → declared_qd=1");
        assert_eq!(an_of(&r), 0);
        assert_eq!(ns_of(&r), 0);
        assert_eq!(ar_of(&r), 0, "无 OPT → ar=0");
        // flags：QR+RA+rcode，保留 RD。
        let f = flags_of(&r);
        assert_ne!(f & 0x8000, 0, "QR 必须置位");
        assert_ne!(f & 0x0080, 0, "RA 必须置位");
        assert_ne!(f & 0x0100, 0, "RD 必须保留（FLAG_KEEP_MASK）");
        assert_eq!(f & 0x000F, 2, "rcode=SERVFAIL");
        // body 恰好一段 question（qname+qtype+qclass = 17 字节）。
        assert_eq!(r.len(), 12 + 17, "头部声明段数必须等于 body 实际段数");
    }

    /// P-05：`build_error_response` 动态 qd —— qd=0（无 question 段）时声明 0，
    /// 保证头/段自洽（旧代码在 error 路径也写 1 时头声明 1 段而 body 0 段）。
    #[test]
    fn error_response_declares_qd_0_when_no_question() {
        let q = make_query(0x0001, 0, false);
        let r = build_error_response(&q, 2).unwrap();
        assert_eq!(qd_of(&r), 0, "无 qbytes → declared_qd=0");
        assert_eq!(r.len(), 12, "无 question 段时响应恒 12 字节头");
    }

    /// P-05 / **2.1.20（A-09）**：`build_simple_response` 的 `qdcount` **与实际回显的
    /// question 段数严格一致** —— 有 question ⇒ 1；没有 ⇒ **0**。
    ///
    /// **[历史归因]** 2.1.19 及以前这里断言"畸形请求也恒 qd=1"（对齐 Python
    /// `_RESP_HDR` 的硬编码 1）。审计 A-09 实测该口径会产出**自相矛盾的报文**：
    /// `malformed 70B label` / 压缩环 / `QR=1` / `opcode=2` 的回包都是
    /// `rcode=1 len=12 qd=1` —— **12 字节里没有 question，头部却声明 1 段**。
    /// 现在 qdcount 由实际写入的 question 字节数决定（RFC 一致性优先）。
    #[test]
    fn simple_response_qd_1_matches_echoed_question() {
        let q = make_query(0x2222, 1, true);
        let r = build_simple_response(&q, 3).unwrap();
        assert_eq!(qd_of(&r), 1);
        assert_eq!(r.len(), 12 + 17, "qbytes 恰好一段 question");
        assert_eq!(flags_of(&r) & 0x000F, 3, "NXDOMAIN rcode");

        // qd=0 的畸形请求走 simple_response 时：**没有 question 段 ⇒ qdcount=0**。
        // （2.1.20 / A-09 修正：不再声明"有 1 段"。）
        let r0 = build_simple_response(&make_query(0x33, 0, false), 0).unwrap();
        assert_eq!(
            qd_of(&r0),
            0,
            "没有 question 段时 qdcount 必须是 0（A-09：不得自相矛盾）"
        );
        assert_eq!(r0.len(), 12, "无 question ⇒ 恰好 12 字节头");
    }

    #[test]
    fn udp_response_qd_and_ancount() {
        let q = make_query(0x4444, 1, true);
        let ans = [AnswerInput {
            name: None,
            rtype: 1,
            value: "93.184.216.34",
            ttl: Some(60),
        }];
        let r = build_udp_response(&UdpResp {
            raw_query: &q,
            qbytes: None,
            answers: &ans,
            rcode: 0,
            abody: None,
            abody_count: None,
            owner_name: Some("example.com"),
            fallback_type: 1,
            ttl_override: None,
            bufsize_cap: None,
            force_truncated: false,
            enc_owner: None,
            edns_info: None,
        })
        .unwrap();
        assert_eq!(qd_of(&r), 1);
        assert_eq!(an_of(&r), 1);
        assert_eq!(ns_of(&r), 0);
    }

    #[test]
    fn short_query_returns_none() {
        assert!(build_response_header(&[0u8; 11], 0, 0, false, 0).is_none());
        assert!(build_error_response(&[0u8; 11], 2).is_none());
        assert!(build_simple_response(&[0u8; 11], 0).is_none());
    }

    /// FLAG_TC 仅在 truncated=true 时置位；rcode 只取低 4 位，且 flags 与
    /// dnsmsg.py 的位运算**逐位相同**。
    ///
    /// 依据 dnsmsg.py:723-732 `_response_header_bits`：
    /// `new_flags = (flags & 0x7910) | 0x8080 | (rcode & 0x0F)`。
    /// 注意 `0x8080` 本身含 RA(0x0080)，所以 `& 0x00F0` 里**本来就**有 0x80 置位
    /// **[历史归因]** （RA 是主动置的，不是 rcode 污染）。原断言 `& 0x00F0 == 0` 与 Python 不符，
    /// 属**测试写错**：真正该断言的是"低字节除 RA 外为空"+"保留/置位掩码之外恒 0"。
    #[test]
    fn truncated_flag_and_rcode_mask() {
        let q = make_query(0x5555, 1, true);
        let query_flags = u16::from_be_bytes([q[2], q[3]]); // RD=0x0100
        let allowed = FLAG_KEEP_MASK | FLAG_QR_RA | FLAG_RCODE_MASK;
        let plain = build_response_header(&q, 0, 0, false, 0).unwrap();
        let tc = build_response_header(&q, 0, 0, true, 0).unwrap();
        assert_eq!(flags_of(&plain) & FLAG_TC, 0);
        assert_eq!(flags_of(&tc) & FLAG_TC, FLAG_TC);
        // 无 TC 时整字与 dnsmsg.py:729 完全一致：(flags & 0x7910) | 0x8080 | rcode。
        assert_eq!(
            flags_of(&plain),
            (query_flags & FLAG_KEEP_MASK) | FLAG_QR_RA
        );
        assert_eq!(
            flags_of(&tc),
            ((query_flags & FLAG_KEEP_MASK) | FLAG_QR_RA) | FLAG_TC
        );
        // **[历史归因]** rcode 超 4 位被掩码；其余位与 Python 位运算逐位相同。
        let masked = build_response_header(&q, 0xFF, 0, false, 0).unwrap();
        let expect = (query_flags & FLAG_KEEP_MASK) | FLAG_QR_RA | 0x000F;
        assert_eq!(
            flags_of(&masked),
            expect,
            "rcode=0xFF 时必须与 dnsmsg.py:729 的 (flags & 0x7910)|0x8080|(rcode & 0x0F) 逐位一致"
        );
        assert_eq!(flags_of(&masked) & 0x000F, 0x0F, "rcode 被掩到低 4 位");
        // 低字节 0x00F0 中只允许 RA(0x0080)——它来自 FLAG_QR_RA，与 rcode 无关。
        assert_eq!(
            flags_of(&masked) & 0x00F0,
            FLAG_RA,
            "0x00F0 内只有 RA 允许置位"
        );
        // rcode 不得污染保留掩码/置位掩码之外的任何位（AA/TC/Z/AD 等恒 0）。
        assert_eq!(
            flags_of(&masked) & !allowed,
            0,
            "rcode 不得污染保留位之外的位（Python 只做 &0x0F）"
        );
        assert_eq!(flags_of(&masked) & FLAG_AA, 0, "AA 不得由 rcode 置位");
    }
}
