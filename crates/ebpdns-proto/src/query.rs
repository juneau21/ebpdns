//! 查询构造：`build_query`、0x20 大小写随机化、`extract_qname`、`check_0x20`。

use crate::constants::*;
use crate::edns::{append_padding, build_opt_rr, ecs_option};
use crate::name::encode_name;
use crate::ProtoResult;

/// 构造一个 DNS 查询报文，返回 `(wire_bytes, qid)`。
///
/// - `qid`：None → 随机 16bit。
/// - `edns`：是否附加 OPT RR。
/// - `ecs`：可选 ECS 子串（`"ip/prefix"`）。
/// - `udp_size`：EDNS UDP payload size（钳制到 [512,9000]，默认 1232）。
/// - `padding`：是否启用 RFC 8467 填充（仅 edns 路径生效）。
pub fn build_query(
    domain: &str,
    qtype: u16,
    qid: Option<u16>,
    edns: bool,
    ecs: Option<&str>,
    udp_size: Option<u32>,
    padding: bool,
) -> ProtoResult<(Vec<u8>, u16)> {
    let qid = qid.unwrap_or_else(rand_id);
    let flags: u16 = FLAG_RD; // RD=1
    let ar: u16 = if edns { 1 } else { 0 };

    let question = encode_name(domain)?;
    let mut out = Vec::with_capacity(12 + question.len() + 64);
    out.extend(qid.to_be_bytes());
    out.extend(flags.to_be_bytes());
    out.extend(1u16.to_be_bytes()); // qd
    out.extend(0u16.to_be_bytes()); // an
    out.extend(0u16.to_be_bytes()); // ns
    out.extend(ar.to_be_bytes()); // ar
    out.extend(&question);
    out.extend(qtype.to_be_bytes());
    out.extend(CLASS_IN.to_be_bytes());

    if edns {
        let mut options: Vec<u8> = Vec::new();
        if let Some(subnet) = ecs {
            options.extend(ecs_option(subnet));
        }
        if padding {
            // **[历史归因]** Python `question = encode_name(domain) + qtype + qclass`，
            // 前缀需含 qtype/qclass 4 字节。
            append_padding(&mut options, question.len() + 4)?;
        }
        let size = clamp_edns_udp_size(udp_size);
        out.extend(build_opt_rr(size, &options));
    }

    Ok((out, qid))
}

/// 随机 16bit 查询 ID。
pub fn rand_id() -> u16 {
    use rand::Rng;
    rand::thread_rng().gen::<u16>()
}

/// DNS 0x20 大小写随机化：每个小写字母 50% 概率转大写，其余字符不变。
pub fn random_case_name(domain: &str) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut out = String::with_capacity(domain.len());
    for ch in domain.chars() {
        if ch.is_ascii_lowercase() && rng.gen::<bool>() {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push(ch);
        }
    }
    out
}

/// 提取 question 段的 qname 原始字节（含标签长度前缀与 null 终止，**不含** qtype/qclass）。
///
/// 用于 0x20 校验：与发送报文逐位比较（大小写敏感）。解析失败返回 `None`。
/// **[历史归因]** 对齐 Python `extract_qname`：拒绝 0x40/0x80 非法标签与 question 区压缩指针。
pub fn extract_qname(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 12 {
        return None;
    }
    let qd = be_u16(data, 4)?;
    if qd < 1 {
        return None;
    }
    let mut pos = 12usize;
    let start = pos;
    loop {
        let ln = *data.get(pos)?;
        if ln == 0 {
            return Some(data[start..pos + 1].to_vec());
        }
        // 高位有置位但不是标准压缩指针(0xC0) → 非法标签。
        if ln & 0xC0 != 0 && ln & 0xC0 != 0xC0 {
            return None;
        }
        // question 区不应出现压缩指针。
        if ln & 0xC0 == 0xC0 {
            return None;
        }
        pos += 1 + ln as usize;
        if pos >= data.len() {
            return None;
        }
    }
}

/// 0x20 校验：响应 question qname 字节必须与查询逐位一致（含大小写）。
///
/// - 查询侧 question 畸形（qn=None）→ 无法比较，fail-open（返回 true）。
/// - 响应侧 question 畸形（rn=None）→ fail-closed（返回 false，投毒嫌疑）。
/// - 响应 qd != 1 → false；qtype/qclass 段不一致 → false。
pub fn check_0x20(query: &[u8], response: &[u8]) -> bool {
    let qn = match extract_qname(query) {
        // 查询侧 question 畸形 → 无法比较，fail-open。
        None => return true,
        Some(qn) => qn,
    };
    let rn = match extract_qname(response) {
        // 响应侧 question 畸形 → fail-closed。
        None => return false,
        Some(rn) => rn,
    };
    // 响应必须 ≥12 字节且 qd == 1。
    if response.len() < 12 || !matches!(be_u16(response, 4), Some(1)) {
        return false;
    }
    if qn != rn {
        return false;
    }
    // 一并校验 qtype/qclass 4 字节一致。
    let qs = 12 + qn.len();
    if query.len() >= qs + 4
        && response.len() >= qs + 4
        && query[qs..qs + 4] != response[qs..qs + 4]
    {
        return false;
    }
    true
}

fn be_u16(data: &[u8], pos: usize) -> Option<u16> {
    data.get(pos..pos + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
}
