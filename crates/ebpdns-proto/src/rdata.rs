//! rdata 解析与编码。
//!
//! - [`parse_rdata`]：从报文 `pos` 处解析 rdata；结构化类型长度不符 / 名称越界 /
//!   异常 → 返回 `None`（调用方丢弃整条 RR，fail-closed），绝不产出错误数据。
//! - **[历史归因]** [`encode_rdata`]：把 Python 风格的字符串 rdata（与 `build_response_body_answers`
//!   的 dict 输入一致）编码为线格式字节；非法 A/AAAA 返回 `None` 跳过。
//!
//! # 2.1.29：新增类型的 presentation 与编码是**互逆**的
//!
//! 数据面缓存把答案存成字符串（`RData::as_display`），出缓存时再用
//! [`encode_rdata`] 重新编码 ⟹ 每种新类型的 `parse → as_display → encode` 必须
//! **逐字节可逆**（见 `tests` 里的往返用例）。约定：
//! - 名字字段（`SVCB`/`HTTPS` 的 target、`NAPTR` 的 replacement）用**整包上下文**
//!   解压（`decode_name` 支持压缩指针），编码时一律写未压缩名字；
//! - `SVCB`/`HTTPS` 的 SvcParams 按 `(key, value)` **原样保存**（不排序、不改写、
//!   不解压参数区 —— RFC 9460 本来就禁止压缩 SvcParams）；
//! - 未知 SvcParam key 以 `keyNNN=` 保留；二进制值用 `\DDD` 转义，可无损往返；
//! - 根名（wire 上的单个 `0x00`）显示为 `"."`（`decode_name` 返回空串时的唯一情况）。

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::constants::*;
use crate::name::{decode_name, encode_name};

/// 解析后的 rdata（结构化）。`Other` 为**未知类型**的 hex 透传原始字节。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(String),
    NS(String),
    PTR(String),
    MX {
        preference: u16,
        exchange: String,
    },
    /// **[历史归因]** 已带首尾引号，对齐 Python 解码（`'"' + joined + '"'`）。
    TXT(String),
    SOA {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    /// **2.1.29**：SVCB(64) / HTTPS(65)。`params` 为 `(SvcParamKey, 原样 value)` 序列
    /// —— **保持线上顺序**，不做语义改写；value 含长度前缀/列表的语义只影响展示。
    SVCB {
        priority: u16,
        target: String,
        params: Vec<(u16, Vec<u8>)>,
    },
    /// **2.1.29**：NAPTR(35)。三个 char-string 原样保存（RFC 只允许可打印 ASCII，
    /// 但仍按字节保存以避免非法输入被静默改写）；`replacement` 可能被压缩。
    NAPTR {
        order: u16,
        preference: u16,
        flags: Vec<u8>,
        services: Vec<u8>,
        regexp: Vec<u8>,
        replacement: String,
    },
    /// **2.1.29**：CAA(257)。`value` 为 `tag` 之后的**全部原始字节**。
    CAA {
        flags: u8,
        tag: Vec<u8>,
        value: Vec<u8>,
    },
    /// **2.1.29**：DS(43) / CDS(59)。
    DS {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Vec<u8>,
    },
    /// **2.1.29**：SSHFP(44)。
    SSHFP {
        algorithm: u8,
        fp_type: u8,
        fingerprint: Vec<u8>,
    },
    /// **2.1.29**：DNSKEY(48) / CDNSKEY(60)。
    DNSKEY {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        key: Vec<u8>,
    },
    /// **2.1.29**：TLSA(52)。
    TLSA {
        usage: u8,
        selector: u8,
        matching: u8,
        cert: Vec<u8>,
    },
    /// **2.1.29**：URI(256)。
    URI {
        priority: u16,
        weight: u16,
        target: Vec<u8>,
    },
    /// 未知类型：原始字节透传（`as_display` 为小写 hex）。
    Other(Vec<u8>),
}

impl RData {
    /// **[历史归因]** 与 Python `_parse_rdata` 输出对齐的字符串形式（答案字典 `rdata` 字段）。
    pub fn as_display(&self) -> String {
        match self {
            RData::A(ip) => ip.to_string(),
            RData::AAAA(ip) => ip.to_string(),
            RData::CNAME(s) | RData::NS(s) | RData::PTR(s) => s.clone(),
            RData::MX {
                preference,
                exchange,
            } => format!("{preference} {exchange}"),
            RData::TXT(s) => s.clone(),
            RData::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                format!("{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}")
            }
            RData::SRV {
                priority,
                weight,
                port,
                target,
            } => {
                format!("{priority} {weight} {port} {target}")
            }
            // ---- 2.1.29 新增类型的 dig 风格 presentation ----
            RData::SVCB {
                priority,
                target,
                params,
            } => svcb_display(*priority, target, params),
            RData::NAPTR {
                order,
                preference,
                flags,
                services,
                regexp,
                replacement,
            } => format!(
                "{order} {preference} {} {} {} {}",
                quoted(flags),
                quoted(services),
                quoted(regexp),
                name_display(replacement)
            ),
            RData::CAA { flags, tag, value } => {
                format!("{flags} {} {}", token_display(tag), quoted(value))
            }
            RData::DS {
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => format!("{key_tag} {algorithm} {digest_type} {}", hex_encode(digest)),
            RData::SSHFP {
                algorithm,
                fp_type,
                fingerprint,
            } => format!("{algorithm} {fp_type} {}", hex_encode(fingerprint)),
            RData::DNSKEY {
                flags,
                protocol,
                algorithm,
                key,
            } => format!("{flags} {protocol} {algorithm} {}", base64_encode(key)),
            RData::TLSA {
                usage,
                selector,
                matching,
                cert,
            } => format!("{usage} {selector} {matching} {}", hex_encode(cert)),
            RData::URI {
                priority,
                weight,
                target,
            } => format!("{priority} {weight} {}", quoted(target)),
            RData::Other(b) => hex_encode(b),
        }
    }
}

/// 域名字段的展示：根名（`decode_name` 返回空串）显示为 `"."`，其余按原样。
///
/// 与既有 MX/NS/PTR 的展示口径一致（**不带**结尾点），只有根名例外 —— 否则
/// `SVCB 0 <target>` 的 AliasMode 记录会显示成两个连续空格，无法与"缺字段"区分。
fn name_display(name: &str) -> &str {
    if name.is_empty() {
        "."
    } else {
        name
    }
}

/// 小写十六进制字符查表（P-04：替代逐字节 `format!` 的临时 String 分配）。
///
/// `HEX_DIGITS[n]` = 半字节 `n`(0..=15) 的 ASCII 字符。`as u8` 的越界在本模块内
/// 不可能发生（调用点均传入 `byte >> 4` / `byte & 0x0f`），故用 `get(..).copied()`
/// 兜底为 `b'0'` 以满足"生产路径不得 panic"的约束。
const HEX_DIGITS: [u8; 16] = *b"0123456789abcdef";

/// 字节切片 → 小写十六进制串（`RData::Other` 的 `as_display`）。
///
/// 热路径（未知类型透传的 hex 展示）每个字节原实现一次 `format!` 临时 String，
/// 再 `push_str` 拷贝：N 字节 = N 次分配 + N 次拷贝。改为查表直接 `push` 两个
/// `char`，一次预分配即可，行为（小写、无分隔、非 ASCII 字节按字节展开）完全一致。
fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len().saturating_mul(2));
    for &byte in b {
        let hi = HEX_DIGITS
            .get((byte >> 4) as usize)
            .copied()
            .unwrap_or(b'0');
        let lo = HEX_DIGITS
            .get((byte & 0x0f) as usize)
            .copied()
            .unwrap_or(b'0');
        s.push(hi as char);
        s.push(lo as char);
    }
    s
}

/* ======================= 2.1.29：presentation 词法工具 ======================= */

/// 把任意字节写成**带引号的 char-string**：`"…"`，其中 `"` / `\` / 非可打印字节
/// 用 `\DDD` 转义。与 [`split_tokens`] + [`unescape`] 互逆。
fn quoted(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_add(2));
    s.push('"');
    push_escaped(&mut s, bytes, false);
    s.push('"');
    s
}

/// 把字节写成**裸 token**（能裸写就裸写，否则加引号）；用于 CAA tag 之类
/// 通常为可打印 ASCII、但不保证的字段。
fn token_display(bytes: &[u8]) -> String {
    let bare = !bytes.is_empty()
        && bytes
            .iter()
            .all(|b| b.is_ascii_graphic() && !matches!(*b, b'"' | b'\\'));
    if bare {
        String::from_utf8_lossy(bytes).into_owned()
    } else {
        quoted(bytes)
    }
}

/// 转义写入。`escape_comma=true` 时用于**裸列表项**（`alpn=h3,h2` 的单项）：
/// 逗号/空格也要转义，否则会被二次切分。
fn push_escaped(out: &mut String, bytes: &[u8], escape_comma: bool) {
    for &b in bytes {
        if b.is_ascii_graphic() && b != b'"' && b != b'\\' && !(escape_comma && b == b',') {
            out.push(b as char);
        } else if b == b' ' && !escape_comma {
            out.push(' ');
        } else {
            out.push('\\');
            out.push((b'0' + b / 100) as char);
            out.push((b'0' + (b / 10) % 10) as char);
            out.push((b'0' + b % 10) as char);
        }
    }
}

/// presentation 分词：按空白切分，支持 `"…"` 引号与 `\DDD` / `\c` 转义。
///
/// 返回的 token **保留转义序列原文**（引号已剥离），由 [`unescape`] 统一还原 ——
/// 这样 `alpn=h3,h2` 这类"先按 `,` 切分、再做转义还原"的字段不会被值内部的
/// `\044` 干扰。
fn split_tokens(s: &str) -> Option<Vec<String>> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        let mut tok = String::new();
        let mut in_quote = false;
        while i < b.len() {
            let c = b[i];
            if c == b'\\' {
                tok.push('\\');
                i += 1;
                if i >= b.len() {
                    return None;
                }
                if b[i].is_ascii_digit() {
                    for _ in 0..3 {
                        let d = *b.get(i)?;
                        if !d.is_ascii_digit() {
                            return None;
                        }
                        tok.push(d as char);
                        i += 1;
                    }
                } else {
                    let ch = s[i..].chars().next()?;
                    tok.push(ch);
                    i += ch.len_utf8();
                }
                continue;
            }
            if c == b'"' {
                in_quote = !in_quote;
                i += 1;
                continue;
            }
            if !in_quote && c.is_ascii_whitespace() {
                break;
            }
            let ch = s[i..].chars().next()?;
            tok.push(ch);
            i += ch.len_utf8();
        }
        if in_quote {
            return None;
        }
        out.push(tok);
    }
    Some(out)
}

/// 还原 [`split_tokens`] 保留的转义序列：`\DDD` → 单字节，`\c` → `c` 的 UTF-8 字节。
fn unescape(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while i < b.len() {
        if b[i] != b'\\' {
            let ch = s[i..].chars().next()?;
            let mut buf = [0u8; 4];
            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            i += ch.len_utf8();
            continue;
        }
        i += 1;
        if i >= b.len() {
            return None;
        }
        if b[i].is_ascii_digit() {
            let mut v = 0u32;
            for _ in 0..3 {
                let d = *b.get(i)?;
                if !d.is_ascii_digit() {
                    return None;
                }
                v = v * 10 + u32::from(d - b'0');
                i += 1;
            }
            if v > 255 {
                return None;
            }
            out.push(v as u8);
        } else {
            let ch = s[i..].chars().next()?;
            let mut buf = [0u8; 4];
            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            i += ch.len_utf8();
        }
    }
    Some(out)
}

/// token → 纯 ASCII 数字（拒绝空串/符号/Unicode 数字）。
fn digits_of(tok: &str) -> Option<&str> {
    if tok.is_empty() || !tok.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(tok)
}

fn token_u8(tok: &str) -> Option<u8> {
    digits_of(tok)?.parse::<u8>().ok()
}

fn token_u16(tok: &str) -> Option<u16> {
    digits_of(tok)?.parse::<u16>().ok()
}

/* ======================= 2.1.29：base64（DNSKEY / ech） ======================= */

const B64: [u8; 64] = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// 标准 base64（带 `=` 填充）。DNSKEY 公钥与 SVCB `ech` 参数都用它展示。
fn base64_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len().div_ceil(3).saturating_mul(4));
    for chunk in b.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        s.push(B64[(b0 >> 2) as usize] as char);
        s.push(B64[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            s.push(B64[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            s.push('=');
        }
        if chunk.len() > 2 {
            s.push(B64[(b2 & 0x3f) as usize] as char);
        } else {
            s.push('=');
        }
    }
    s
}

/// base64 解码：容忍 `=` 填充与空白，遇到非法字符返回 `None`（fail-closed）。
///
/// 尾部不足 8 bit 的残余位**丢弃**（与常见解码器一致；`base64_encode` 的输出
/// 不会产生残余位，故往返测试逐字节成立）。
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        if c == b'=' {
            break;
        }
        if c.is_ascii_whitespace() {
            continue;
        }
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/* ======================= 2.1.29：SVCB / HTTPS ======================= */

/// SvcParamKey 的展示名（RFC 9460 §14.3.2 + 已登记的扩展）。
fn svcparam_key_name(key: u16) -> Option<&'static str> {
    match key {
        0 => Some("mandatory"),
        1 => Some("alpn"),
        2 => Some("no-default-alpn"),
        3 => Some("port"),
        4 => Some("ipv4hint"),
        5 => Some("ech"),
        6 => Some("ipv6hint"),
        7 => Some("dohpath"),
        8 => Some("ohttp"),
        _ => None,
    }
}

/// SvcParamKey 名（或 `keyNNN`）→ 数值。
fn svcparam_key_code(name: &str) -> Option<u16> {
    let lower = name.to_ascii_lowercase();
    match lower.as_str() {
        "mandatory" => Some(0),
        "alpn" => Some(1),
        "no-default-alpn" => Some(2),
        "port" => Some(3),
        "ipv4hint" => Some(4),
        "ech" => Some(5),
        "ipv6hint" => Some(6),
        "dohpath" => Some(7),
        "ohttp" => Some(8),
        _ => digits_of(lower.strip_prefix("key")?)?.parse().ok(),
    }
}

/// key 的展示形式：已登记 key 用名字，未知 key 用 `keyNNN`。
fn svcparam_key_text(key: u16) -> String {
    match svcparam_key_name(key) {
        Some(n) => n.to_string(),
        None => format!("key{key}"),
    }
}

/// 单个 SvcParam 的 presentation。**未知 key 一律 `keyNNN="…"` 原样保留**；
/// 已知 key 的值若形状不合法（长度不对），也退回 `keyNNN="…"`，保证无损往返。
fn svcparam_display(key: u16, value: &[u8]) -> String {
    match key {
        0 => match svcparam_mandatory_text(value) {
            Some(v) => format!("mandatory={v}"),
            None => svcparam_raw_display(key, value),
        },
        1 => match svcparam_alpn_text(value) {
            Some(v) => format!("alpn={v}"),
            None => svcparam_raw_display(key, value),
        },
        2 if value.is_empty() => "no-default-alpn".to_string(),
        3 => match value {
            [hi, lo] => format!("port={}", u16::from_be_bytes([*hi, *lo])),
            _ => svcparam_raw_display(key, value),
        },
        4 => match svcparam_hint_text(value, 4) {
            Some(v) => format!("ipv4hint={v}"),
            None => svcparam_raw_display(key, value),
        },
        5 => format!("ech={}", base64_encode(value)),
        6 => match svcparam_hint_text(value, 16) {
            Some(v) => format!("ipv6hint={v}"),
            None => svcparam_raw_display(key, value),
        },
        7 => format!("dohpath={}", quoted(value)),
        8 if value.is_empty() => "ohttp".to_string(),
        _ => svcparam_raw_display(key, value),
    }
}

/// 未知/形状不合法的 SvcParam：`keyNNN="…"`（二进制安全、可无损解析）。
fn svcparam_raw_display(key: u16, value: &[u8]) -> String {
    format!("key{key}={}", quoted(value))
}

/// `mandatory=`：key 列表（空值非法 → 退回原始形式）。
fn svcparam_mandatory_text(value: &[u8]) -> Option<String> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return None;
    }
    let mut out = String::new();
    for pair in value.chunks(2) {
        let key = u16::from_be_bytes([pair[0], pair[1]]);
        if !out.is_empty() {
            out.push(',');
        }
        out.push_str(&svcparam_key_text(key));
    }
    Some(out)
}

/// `alpn=`：逐项 `len(1) + bytes`，逗号连接；每项内部特殊字节转义（裸列表项）。
fn svcparam_alpn_text(value: &[u8]) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    let mut out = String::new();
    let mut p = 0usize;
    let mut first = true;
    while p < value.len() {
        let ln = *value.get(p)? as usize;
        p += 1;
        if ln == 0 || p + ln > value.len() {
            return None;
        }
        if !first {
            out.push(',');
        }
        first = false;
        push_escaped(&mut out, &value[p..p + ln], true);
        p += ln;
    }
    Some(out)
}

/// `ipv4hint=` / `ipv6hint=`：定长地址列表；长度不是 `width` 的整数倍 → 非法。
fn svcparam_hint_text(value: &[u8], width: usize) -> Option<String> {
    if value.is_empty() || !value.len().is_multiple_of(width) {
        return None;
    }
    let mut out = String::new();
    for (i, chunk) in value.chunks(width).enumerate() {
        if i > 0 {
            out.push(',');
        }
        match width {
            4 => {
                let a = [chunk[0], chunk[1], chunk[2], chunk[3]];
                out.push_str(&Ipv4Addr::from(a).to_string());
            }
            16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(chunk);
                out.push_str(&Ipv6Addr::from(a).to_string());
            }
            _ => return None,
        }
    }
    Some(out)
}

/// SVCB / HTTPS 的完整 presentation：`priority target [k=v]…`。
fn svcb_display(priority: u16, target: &str, params: &[(u16, Vec<u8>)]) -> String {
    let mut out = format!("{priority} {}", name_display(target));
    for (key, value) in params {
        out.push(' ');
        out.push_str(&svcparam_display(*key, value));
    }
    out
}

/// 解析 SVCB/HTTPS rdata（target 可被压缩；参数区**不解压** —— RFC 不允许）。
fn parse_svcb(data: &[u8], pos: usize, rdlen: usize) -> Option<RData> {
    if rdlen < 3 {
        // priority(2) + 至少一个根名终止字节(1)
        return None;
    }
    let end = pos.checked_add(rdlen)?;
    let priority = be_u16(data, pos)?;
    let (target, mut p) = decode_name(data, pos + 2).ok()?;
    if p > end {
        return None;
    }
    let mut params = Vec::new();
    while p < end {
        if p + 4 > end {
            return None;
        }
        let key = be_u16(data, p)?;
        let len = be_u16(data, p + 2)? as usize;
        p += 4;
        if p + len > end {
            return None;
        }
        params.push((key, data[p..p + len].to_vec()));
        p += len;
    }
    Some(RData::SVCB {
        priority,
        target,
        params,
    })
}

/// 解析 `key=value` 形式的单个 SvcParam（token 已由 [`split_tokens`] 保留转义原文）。
///
/// **数值形式 `keyNNN=` 一律按原始字节解析**（不解码成该 key 的语义值）——
/// 这正是展示侧对"未知 key / 形状不合法的已知 key"的输出形式，保证无损往返。
fn parse_svcparam(tok: &str) -> Option<(u16, Vec<u8>)> {
    let (key_text, value_text) = match tok.split_once('=') {
        Some((k, v)) => (k, v),
        None => (tok, ""),
    };
    let key = svcparam_key_code(key_text)?;
    let lower = key_text.to_ascii_lowercase();
    let numeric_form = lower
        .strip_prefix("key")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit()));
    if numeric_form {
        return Some((key, unescape(value_text)?));
    }
    let value = match key {
        0 => parse_mandatory(value_text)?,
        1 => parse_alpn(value_text)?,
        2 | 8 => {
            if value_text.is_empty() {
                Vec::new()
            } else {
                return None;
            }
        }
        3 => token_u16(value_text)?.to_be_bytes().to_vec(),
        4 => parse_hints(value_text, 4)?,
        5 => base64_decode(value_text)?,
        6 => parse_hints(value_text, 16)?,
        _ => unescape(value_text)?,
    };
    Some((key, value))
}

fn parse_mandatory(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    for item in value.split(',') {
        out.extend(svcparam_key_code(item)?.to_be_bytes());
    }
    Some(out)
}

fn parse_alpn(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    for item in value.split(',') {
        let bytes = unescape(item)?;
        if bytes.is_empty() || bytes.len() > 255 {
            return None;
        }
        out.push(bytes.len() as u8);
        out.extend(bytes);
    }
    Some(out)
}

fn parse_hints(value: &str, width: usize) -> Option<Vec<u8>> {
    if value.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    for item in value.split(',') {
        let bytes = unescape(item)?;
        let text = std::str::from_utf8(&bytes).ok()?;
        match width {
            4 => out.extend(text.parse::<Ipv4Addr>().ok()?.octets()),
            16 => out.extend(text.parse::<Ipv6Addr>().ok()?.octets()),
            _ => return None,
        }
    }
    Some(out)
}

/// 编码 SVCB/HTTPS presentation → wire。
fn encode_svcb(value: &str) -> Option<Vec<u8>> {
    let toks = split_tokens(value)?;
    if toks.len() < 2 {
        return None;
    }
    let priority = token_u16(&toks[0])?;
    let target = String::from_utf8(unescape(&toks[1])?).ok()?;
    let mut out = Vec::with_capacity(16);
    out.extend(priority.to_be_bytes());
    out.extend(encode_name(&target).ok()?);
    for tok in &toks[2..] {
        let (key, val) = parse_svcparam(tok)?;
        if val.len() > u16::MAX as usize {
            return None;
        }
        out.extend(key.to_be_bytes());
        out.extend((val.len() as u16).to_be_bytes());
        out.extend(val);
    }
    Some(out)
}

/* ======================= 2.1.29：其余新增类型 ======================= */

/// 读一个 char-string（`len(1) + bytes`），返回 `(bytes, next_pos)`。
fn read_char_string(data: &[u8], p: usize, end: usize) -> Option<(Vec<u8>, usize)> {
    if p >= end {
        return None;
    }
    let ln = *data.get(p)? as usize;
    let start = p + 1;
    if start + ln > end {
        return None;
    }
    Some((data[start..start + ln].to_vec(), start + ln))
}

fn parse_naptr(data: &[u8], pos: usize, rdlen: usize) -> Option<RData> {
    // order(2) + preference(2) + 3×空 char-string(1 each) + 根名(1) = 8
    if rdlen < 8 {
        return None;
    }
    let end = pos.checked_add(rdlen)?;
    let order = be_u16(data, pos)?;
    let preference = be_u16(data, pos + 2)?;
    let (flags, p) = read_char_string(data, pos + 4, end)?;
    let (services, p) = read_char_string(data, p, end)?;
    let (regexp, p) = read_char_string(data, p, end)?;
    let (replacement, np) = decode_name(data, p).ok()?;
    // replacement 必须恰好用完 rdata（否则是尾随垃圾，fail-closed）。
    if np != end {
        return None;
    }
    Some(RData::NAPTR {
        order,
        preference,
        flags,
        services,
        regexp,
        replacement,
    })
}

fn parse_caa(raw: &[u8]) -> Option<RData> {
    if raw.len() < 2 {
        return None;
    }
    let flags = raw[0];
    let tag_len = raw[1] as usize;
    // RFC 8659：tag 非空且 1..=15 字节的字母数字。（这里只要求非空，宽松接收。）
    if tag_len == 0 || 2 + tag_len > raw.len() {
        return None;
    }
    Some(RData::CAA {
        flags,
        tag: raw[2..2 + tag_len].to_vec(),
        value: raw[2 + tag_len..].to_vec(),
    })
}

fn parse_ds(raw: &[u8]) -> Option<RData> {
    if raw.len() < 4 {
        return None;
    }
    Some(RData::DS {
        key_tag: u16::from_be_bytes([raw[0], raw[1]]),
        algorithm: raw[2],
        digest_type: raw[3],
        digest: raw[4..].to_vec(),
    })
}

fn parse_sshfp(raw: &[u8]) -> Option<RData> {
    if raw.len() < 2 {
        return None;
    }
    Some(RData::SSHFP {
        algorithm: raw[0],
        fp_type: raw[1],
        fingerprint: raw[2..].to_vec(),
    })
}

fn parse_dnskey(raw: &[u8]) -> Option<RData> {
    if raw.len() < 4 {
        return None;
    }
    Some(RData::DNSKEY {
        flags: u16::from_be_bytes([raw[0], raw[1]]),
        protocol: raw[2],
        algorithm: raw[3],
        key: raw[4..].to_vec(),
    })
}

fn parse_tlsa(raw: &[u8]) -> Option<RData> {
    if raw.len() < 3 {
        return None;
    }
    Some(RData::TLSA {
        usage: raw[0],
        selector: raw[1],
        matching: raw[2],
        cert: raw[3..].to_vec(),
    })
}

fn parse_uri(raw: &[u8]) -> Option<RData> {
    if raw.len() < 4 {
        return None;
    }
    Some(RData::URI {
        priority: u16::from_be_bytes([raw[0], raw[1]]),
        weight: u16::from_be_bytes([raw[2], raw[3]]),
        target: raw[4..].to_vec(),
    })
}

/// 从第 `first_hex` 个 token 起把**剩余全部** token 当十六进制串（允许空格分段）。
fn encode_hex_fields(toks: &[String], first_hex: usize) -> Option<Vec<u8>> {
    if toks.len() <= first_hex {
        return None;
    }
    hex_decode(&toks[first_hex..].join(""))
}

fn encode_naptr(value: &str) -> Option<Vec<u8>> {
    let toks = split_tokens(value)?;
    if toks.len() != 6 {
        return None;
    }
    let order = token_u16(&toks[0])?;
    let preference = token_u16(&toks[1])?;
    let mut out = Vec::with_capacity(32);
    out.extend(order.to_be_bytes());
    out.extend(preference.to_be_bytes());
    for tok in &toks[2..5] {
        let bytes = unescape(tok)?;
        if bytes.len() > 255 {
            return None;
        }
        out.push(bytes.len() as u8);
        out.extend(bytes);
    }
    let replacement = String::from_utf8(unescape(&toks[5])?).ok()?;
    out.extend(encode_name(&replacement).ok()?);
    Some(out)
}

fn encode_caa(value: &str) -> Option<Vec<u8>> {
    let toks = split_tokens(value)?;
    if toks.len() < 3 {
        return None;
    }
    let flags = token_u8(&toks[0])?;
    let tag = unescape(&toks[1])?;
    if tag.is_empty() || tag.len() > 255 {
        return None;
    }
    let val = unescape(&toks[2])?;
    let mut out = Vec::with_capacity(2 + tag.len() + val.len());
    out.push(flags);
    out.push(tag.len() as u8);
    out.extend(tag);
    out.extend(val);
    Some(out)
}

fn encode_ds(value: &str) -> Option<Vec<u8>> {
    let toks = split_tokens(value)?;
    if toks.len() < 4 {
        return None;
    }
    let key_tag = token_u16(&toks[0])?;
    let algorithm = token_u8(&toks[1])?;
    let digest_type = token_u8(&toks[2])?;
    let digest = encode_hex_fields(&toks, 3)?;
    let mut out = Vec::with_capacity(4 + digest.len());
    out.extend(key_tag.to_be_bytes());
    out.push(algorithm);
    out.push(digest_type);
    out.extend(digest);
    Some(out)
}

fn encode_sshfp(value: &str) -> Option<Vec<u8>> {
    let toks = split_tokens(value)?;
    if toks.len() < 3 {
        return None;
    }
    let algorithm = token_u8(&toks[0])?;
    let fp_type = token_u8(&toks[1])?;
    let fingerprint = encode_hex_fields(&toks, 2)?;
    let mut out = Vec::with_capacity(2 + fingerprint.len());
    out.push(algorithm);
    out.push(fp_type);
    out.extend(fingerprint);
    Some(out)
}

fn encode_dnskey(value: &str) -> Option<Vec<u8>> {
    let toks = split_tokens(value)?;
    if toks.len() < 4 {
        return None;
    }
    let flags = token_u16(&toks[0])?;
    let protocol = token_u8(&toks[1])?;
    let algorithm = token_u8(&toks[2])?;
    let key = base64_decode(&toks[3..].join(""))?;
    let mut out = Vec::with_capacity(4 + key.len());
    out.extend(flags.to_be_bytes());
    out.push(protocol);
    out.push(algorithm);
    out.extend(key);
    Some(out)
}

fn encode_tlsa(value: &str) -> Option<Vec<u8>> {
    let toks = split_tokens(value)?;
    if toks.len() < 4 {
        return None;
    }
    let usage = token_u8(&toks[0])?;
    let selector = token_u8(&toks[1])?;
    let matching = token_u8(&toks[2])?;
    let cert = encode_hex_fields(&toks, 3)?;
    let mut out = Vec::with_capacity(3 + cert.len());
    out.push(usage);
    out.push(selector);
    out.push(matching);
    out.extend(cert);
    Some(out)
}

fn encode_uri(value: &str) -> Option<Vec<u8>> {
    let toks = split_tokens(value)?;
    if toks.len() < 3 {
        return None;
    }
    let priority = token_u16(&toks[0])?;
    let weight = token_u16(&toks[1])?;
    let target = unescape(&toks[2..].join(" "))?;
    let mut out = Vec::with_capacity(4 + target.len());
    out.extend(priority.to_be_bytes());
    out.extend(weight.to_be_bytes());
    out.extend(target);
    Some(out)
}

/// 读大端 u16（越界返回 None）。
fn be_u16(data: &[u8], pos: usize) -> Option<u16> {
    data.get(pos..pos + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
}

/// 读大端 u32（越界返回 None）。
fn be_u32(data: &[u8], pos: usize) -> Option<u32> {
    data.get(pos..pos + 4)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// 解析单条 RR 的 rdata。`pos` 为 rdata 起始偏移，`rdlen` 为声明长度。
///
/// 返回 `None` 表示该 RR 结构非法（长度不符 / 名称越界 / 解码异常），调用方丢弃。
pub fn parse_rdata(data: &[u8], pos: usize, rtype: u16, rdlen: u16) -> Option<RData> {
    let rdlen = rdlen as usize;
    // rdata 整体越界已在 parse_message 校验；这里做防御性检查。
    if pos.checked_add(rdlen)? > data.len() {
        return None;
    }
    let raw = &data[pos..pos + rdlen];

    match rtype {
        TYPE_A => {
            if rdlen == 4 {
                Some(RData::A(Ipv4Addr::from_bits(u32::from_be_bytes([
                    raw[0], raw[1], raw[2], raw[3],
                ]))))
            } else {
                None
            }
        }
        TYPE_AAAA => {
            if rdlen == 16 {
                let mut b = [0u8; 16];
                b.copy_from_slice(raw);
                Some(RData::AAAA(Ipv6Addr::from(b)))
            } else {
                None
            }
        }
        TYPE_CNAME | TYPE_NS | TYPE_PTR => {
            let (name, np) = decode_name(data, pos).ok()?;
            if np - pos > rdlen {
                return None;
            }
            match rtype {
                TYPE_CNAME => Some(RData::CNAME(name)),
                TYPE_NS => Some(RData::NS(name)),
                _ => Some(RData::PTR(name)),
            }
        }
        TYPE_MX => {
            if rdlen >= 3 {
                let preference = be_u16(data, pos)?;
                let (exchange, np) = decode_name(data, pos + 2).ok()?;
                if np - pos > rdlen {
                    return None;
                }
                Some(RData::MX {
                    preference,
                    exchange,
                })
            } else {
                None
            }
        }
        TYPE_TXT => {
            let mut out = String::new();
            let mut p = 0usize;
            while p < rdlen {
                let ln = raw[p] as usize;
                p += 1;
                // **[历史归因]** 段长度字节超过剩余 rdlen → 截断（对齐 Python break，越界防护）。
                if p + ln > rdlen {
                    break;
                }
                let seg = &raw[p..p + ln];
                match std::str::from_utf8(seg) {
                    Ok(s) => out.push_str(s),
                    Err(_) => out.push_str(&String::from_utf8_lossy(seg)),
                }
                p += ln;
            }
            Some(RData::TXT(format!("\"{out}\"")))
        }
        TYPE_SOA => {
            let (mname, p) = decode_name(data, pos).ok()?;
            if p - pos > rdlen {
                return None;
            }
            let (rname, p) = decode_name(data, p).ok()?;
            if p - pos > rdlen {
                return None;
            }
            // 名称后 20 字节定长字段必须恰好落在 rdlen 内。
            if p + 20 != pos + rdlen {
                return None;
            }
            let serial = be_u32(data, p)?;
            let refresh = be_u32(data, p + 4)?;
            let retry = be_u32(data, p + 8)?;
            let expire = be_u32(data, p + 12)?;
            let minimum = be_u32(data, p + 16)?;
            Some(RData::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            })
        }
        TYPE_SRV => {
            if rdlen >= 7 {
                let priority = be_u16(data, pos)?;
                let weight = be_u16(data, pos + 2)?;
                let port = be_u16(data, pos + 4)?;
                let (target, np) = decode_name(data, pos + 6).ok()?;
                if np - pos > rdlen {
                    return None;
                }
                Some(RData::SRV {
                    priority,
                    weight,
                    port,
                    target,
                })
            } else {
                None
            }
        }
        // ---- 2.1.29 新增 ----
        TYPE_SVCB | TYPE_HTTPS => parse_svcb(data, pos, rdlen),
        TYPE_NAPTR => parse_naptr(data, pos, rdlen),
        TYPE_CAA => parse_caa(raw),
        TYPE_DS | TYPE_CDS => parse_ds(raw),
        TYPE_SSHFP => parse_sshfp(raw),
        TYPE_DNSKEY | TYPE_CDNSKEY => parse_dnskey(raw),
        TYPE_TLSA => parse_tlsa(raw),
        TYPE_URI => parse_uri(raw),
        _ => Some(RData::Other(raw.to_vec())),
    }
}

/// **[历史归因]** 把 Python 风格字符串 rdata 编码为线格式字节。
///
/// 对齐 `encode_rdata(rtype, value)`：非法 A/AAAA 返回 `None`（调用方跳过整条 RR）；
/// 非法域名/数字在对应分支失败后回退 hex 解码 → UTF-8 编码兜底。
///
/// **2.1.29**：新增类型的非法 presentation 一律返回 `None`（**不**走 hex/text 兜底：
/// 那是"未知类型"的语义，已知类型写出垃圾 rdata 比丢整条更危险）。
pub fn encode_rdata(rtype: u16, value: &str) -> Option<Vec<u8>> {
    let value = value.trim();
    match rtype {
        TYPE_A => value
            .parse::<Ipv4Addr>()
            .map(|ip| ip.octets().to_vec())
            .ok(),
        TYPE_AAAA => value
            .parse::<Ipv6Addr>()
            .map(|ip| ip.octets().to_vec())
            .ok(),
        TYPE_CNAME | TYPE_NS | TYPE_PTR => encode_name(value).ok(),
        TYPE_MX => {
            let mut it = value.splitn(2, ' ');
            let pref_str = it.next().unwrap_or("");
            let exchange = it.next().unwrap_or(value);
            // 仅接受 ASCII 数字（拒绝 Unicode 数字）；空串 → 默认 10。
            let pref = if !pref_str.is_empty() && pref_str.bytes().all(|c| c.is_ascii_digit()) {
                pref_str.parse::<u32>().unwrap_or(0).min(65535) as u16
            } else {
                10u16
            };
            let name = encode_name(exchange).ok()?;
            let mut out = Vec::with_capacity(2 + name.len());
            out.extend_from_slice(&pref.to_be_bytes());
            out.extend(name);
            Some(out)
        }
        TYPE_TXT => {
            let s = value.strip_prefix('"').unwrap_or(value);
            let s = s.strip_suffix('"').unwrap_or(s);
            let b = s.as_bytes();
            if b.is_empty() {
                return Some(vec![0]);
            }
            // 逐字符累积，保证每段 ≤255 字节且不切断多字节字符。
            let mut segs: Vec<Vec<u8>> = Vec::new();
            let mut cur: Vec<u8> = Vec::new();
            for ch in s.chars() {
                let mut buf = [0u8; 4];
                let cb = ch.encode_utf8(&mut buf).as_bytes().to_vec();
                if cur.len() + cb.len() > 255 {
                    segs.push(std::mem::take(&mut cur));
                }
                cur.extend(cb);
            }
            if !cur.is_empty() {
                segs.push(cur);
            }
            let total: usize = segs.iter().map(|s| 1 + s.len()).sum();
            let mut out = Vec::with_capacity(total);
            for seg in segs {
                out.push(seg.len() as u8);
                out.extend(seg);
            }
            Some(out)
        }
        TYPE_SOA => {
            let parts: Vec<&str> = value.split_whitespace().collect();
            if parts.len() >= 7 {
                let m = encode_name(parts[0]).ok()?;
                let r = encode_name(parts[1]).ok()?;
                let mut nums: [u32; 5] = [0; 5];
                for (i, slot) in nums.iter_mut().enumerate() {
                    *slot = parts[2 + i].parse::<u32>().ok()?;
                }
                let mut out = Vec::with_capacity(m.len() + r.len() + 20);
                out.extend(m);
                out.extend(r);
                for n in nums {
                    out.extend(n.to_be_bytes());
                }
                Some(out)
            } else {
                fallback_hex_or_text(value)
            }
        }
        TYPE_SRV => {
            let parts: Vec<&str> = value.split_whitespace().collect();
            if parts.len() >= 4 {
                let mut nums: [u16; 3] = [0; 3];
                for (i, slot) in nums.iter_mut().enumerate() {
                    let v = parts[i].parse::<u32>().ok()?;
                    *slot = v.min(65535) as u16;
                }
                let target = encode_name(parts[3]).ok()?;
                let mut out = Vec::with_capacity(6 + target.len());
                for n in nums {
                    out.extend(n.to_be_bytes());
                }
                out.extend(target);
                Some(out)
            } else {
                fallback_hex_or_text(value)
            }
        }
        // ---- 2.1.29 新增 ----
        TYPE_SVCB | TYPE_HTTPS => encode_svcb(value),
        TYPE_NAPTR => encode_naptr(value),
        TYPE_CAA => encode_caa(value),
        TYPE_DS | TYPE_CDS => encode_ds(value),
        TYPE_SSHFP => encode_sshfp(value),
        TYPE_DNSKEY | TYPE_CDNSKEY => encode_dnskey(value),
        TYPE_TLSA => encode_tlsa(value),
        TYPE_URI => encode_uri(value),
        _ => fallback_hex_or_text(value),
    }
}

/// **[历史归因]** 默认兜底：尝试 hex 解码，失败则 UTF-8 文本字节（对齐 Python 末尾分支）。
fn fallback_hex_or_text(value: &str) -> Option<Vec<u8>> {
    match hex_decode(value) {
        Some(b) => Some(b),
        None => Some(value.as_bytes().to_vec()),
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        let hi = hex_nibble(b[i])?;
        let lo = hex_nibble(b[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_empty() {
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn hex_encode_single_bytes_are_two_chars() {
        assert_eq!(hex_encode(&[0x00]), "00");
        assert_eq!(hex_encode(&[0x0f]), "0f");
        assert_eq!(hex_encode(&[0xf0]), "f0");
        assert_eq!(hex_encode(&[0xff]), "ff");
        assert_eq!(hex_encode(&[0x0a]), "0a");
        assert_eq!(hex_encode(&[0xa0]), "a0");
    }

    #[test]
    fn hex_encode_all_256_bytes_is_lowercase_two_per_byte() {
        let all: Vec<u8> = (0u8..=255).collect();
        let got = hex_encode(&all);
        assert_eq!(got.len(), 512, "输出长度必须恰好是输入的 2 倍");
        assert!(
            got.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "只允许小写十六进制字符：{got}"
        );
        // 首尾抽样对照。
        assert!(got.starts_with("000102030405060708090a0b0c0d0e0f"));
        assert!(got.ends_with("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"));
    }

    #[test]
    fn hex_encode_is_inverse_of_hex_decode() {
        let raw: Vec<u8> = (0u8..=255).collect();
        assert_eq!(hex_decode(&hex_encode(&raw)).unwrap(), raw);
    }

    #[test]
    fn hex_decode_rejects_odd_and_non_hex() {
        assert!(hex_decode("abc").is_none(), "奇数长度拒绝");
        assert!(hex_decode("zz").is_none(), "非十六进制字符拒绝");
        assert!(hex_decode("g0").is_none());
        assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());
    }

    /// 未知类型（type 65280，不在受理名单）仍走 `Other` → hex_encode 路径。
    #[test]
    fn other_rdata_display_is_lowercase_hex() {
        let data = [0x00u8, 0x01, 0x00, 0x00, 0xAB, 0xCD, 0xEF];
        let rd = parse_rdata(&data, 0, 65280, data.len() as u16).expect("未知类型走 Other 透传");
        assert_eq!(rd, RData::Other(data.to_vec()));
        assert_eq!(rd.as_display(), "00010000abcdef");
    }

    #[test]
    fn other_rdata_display_empty_when_rdlen_zero() {
        let data = [0u8; 4];
        let rd = parse_rdata(&data, 0, 65280, 0).expect("rdlen=0 仍可透传");
        assert_eq!(rd.as_display(), "");
    }

    /* -------------------- 2.1.29：presentation 词法 -------------------- */

    #[test]
    fn quoted_unescape_round_trip_bytes() {
        for raw in [
            b"".to_vec(),
            b"letsencrypt.org".to_vec(),
            b"a b\tc".to_vec(),
            vec![0x00, 0xff, b'"', b'\\', b','],
            b"https://example.com/".to_vec(),
        ] {
            let text = quoted(&raw);
            let toks = split_tokens(&text).expect("分词");
            assert_eq!(toks.len(), 1);
            assert_eq!(unescape(&toks[0]).unwrap(), raw, "text={text}");
        }
    }

    #[test]
    fn split_tokens_handles_quotes_and_escapes() {
        let toks = split_tokens(r#"1 svc.example alpn="h3,h2" key99="a b\000c""#).unwrap();
        assert_eq!(toks.len(), 4);
        assert_eq!(toks[0], "1");
        assert_eq!(toks[1], "svc.example");
        assert_eq!(toks[2], "alpn=h3,h2");
        assert_eq!(unescape("a b\\000c").unwrap(), b"a b\x00c");
        assert!(split_tokens("\"unterminated").is_none());
    }

    #[test]
    fn base64_round_trip() {
        for raw in [
            b"".to_vec(),
            b"a".to_vec(),
            b"ab".to_vec(),
            b"abc".to_vec(),
            (0u8..=255).collect::<Vec<_>>(),
        ] {
            let b64 = base64_encode(&raw);
            assert_eq!(base64_decode(&b64).unwrap(), raw, "b64={b64}");
        }
        assert!(base64_decode("!!!!").is_none());
    }

    /* -------------------- 2.1.29：逐类型往返 -------------------- */

    fn round_trip(rtype: u16, presentation: &str) {
        let wire = encode_rdata(rtype, presentation)
            .unwrap_or_else(|| panic!("encode 失败：type={rtype} value={presentation}"));
        let rd = parse_rdata(&wire, 0, rtype, wire.len() as u16)
            .unwrap_or_else(|| panic!("parse 失败：type={rtype} wire={wire:02x?}"));
        assert_eq!(
            rd.as_display(),
            presentation,
            "presentation 必须可逆（type={rtype}）"
        );
        let wire2 = encode_rdata(rtype, &rd.as_display()).expect("re-encode");
        assert_eq!(wire2, wire, "encode→decode→encode 必须逐字节相同");
    }

    #[test]
    fn svcb_https_full_params_round_trip() {
        let ech = base64_encode(&[0xfe, 0x0d, 0x00, 0x01, 0x02]);
        let text = format!(
            "1 svc.example.com alpn=h3,h2 port=443 ipv4hint=192.0.2.1,192.0.2.2 \
             ipv6hint=2001:db8::1 ech={ech} mandatory=alpn,port no-default-alpn \
             key65432=\"x\\000y\""
        );
        round_trip(TYPE_SVCB, &text);
        round_trip(TYPE_HTTPS, &text);
    }

    #[test]
    fn svcb_alias_mode_root_target_round_trip() {
        round_trip(TYPE_SVCB, "0 .");
        round_trip(TYPE_HTTPS, "0 .");
    }

    #[test]
    fn caa_round_trip() {
        round_trip(TYPE_CAA, "0 issue \"letsencrypt.org\"");
        round_trip(TYPE_CAA, "128 iodef \"mailto:security@example.com\"");
    }

    #[test]
    fn tlsa_ds_sshfp_dnskey_round_trip() {
        let hex = "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9";
        round_trip(TYPE_TLSA, &format!("3 1 1 {hex}"));
        round_trip(TYPE_DS, &format!("2371 13 2 {hex}"));
        round_trip(TYPE_CDS, &format!("2371 13 2 {hex}"));
        round_trip(TYPE_SSHFP, &format!("4 2 {hex}"));
        let key = base64_encode(&[1u8, 2, 3, 4, 5, 0xfe, 0xff]);
        round_trip(TYPE_DNSKEY, &format!("257 3 13 {key}"));
        round_trip(TYPE_CDNSKEY, &format!("257 3 13 {key}"));
    }

    #[test]
    fn uri_naptr_round_trip() {
        round_trip(TYPE_URI, "10 1 \"https://example.com/\"");
        round_trip(
            TYPE_NAPTR,
            "100 10 \"U\" \"E2U+sip\" \"!^.*$!sip:info@example.com!\" .",
        );
    }

    /* -------------------- 2.1.29：名字压缩 -------------------- */

    /// 手工构造含**压缩 target** 的 SVCB 报文：target 指针指回包内名字 `svc.example`。
    #[test]
    fn svcb_compressed_target_is_decompressed() {
        let mut data = b"\x03svc\x07example\x00".to_vec(); // offset 0
        let rd_pos = data.len();
        data.extend(1u16.to_be_bytes()); // priority
        data.extend([0xC0, 0x00]); // target: 压缩指针 → offset 0
        data.extend(0x0001u16.to_be_bytes()); // key alpn
        data.extend(3u16.to_be_bytes()); // len
        data.extend(b"\x02h2");
        let rdlen = (data.len() - rd_pos) as u16;
        let rd = parse_rdata(&data, rd_pos, TYPE_SVCB, rdlen).expect("SVCB 压缩 target");
        assert_eq!(rd.as_display(), "1 svc.example alpn=h2");
        // 编码必须写**未压缩**名字（RFC 9460 禁止压缩），且可再次解析。
        let wire = encode_rdata(TYPE_SVCB, &rd.as_display()).expect("re-encode");
        let again = parse_rdata(&wire, 0, TYPE_SVCB, wire.len() as u16).expect("re-parse");
        assert_eq!(again, rd);
    }

    /// 手工构造含**压缩 replacement** 的 NAPTR 报文。
    #[test]
    fn naptr_compressed_replacement_is_decompressed() {
        let mut data = b"\x07example\x00".to_vec(); // offset 0
        let rd_pos = data.len();
        data.extend(100u16.to_be_bytes());
        data.extend(10u16.to_be_bytes());
        data.push(1);
        data.push(b'U');
        data.push(7);
        data.extend(b"E2U+sip");
        data.push(5);
        data.extend(b"!x!y!");
        data.extend([0xC0, 0x00]); // replacement: 压缩指针 → offset 0
        let rdlen = (data.len() - rd_pos) as u16;
        let rd = parse_rdata(&data, rd_pos, TYPE_NAPTR, rdlen).expect("NAPTR 压缩 replacement");
        assert_eq!(
            rd.as_display(),
            "100 10 \"U\" \"E2U+sip\" \"!x!y!\" example"
        );
        let wire = encode_rdata(TYPE_NAPTR, &rd.as_display()).expect("re-encode");
        let again = parse_rdata(&wire, 0, TYPE_NAPTR, wire.len() as u16).expect("re-parse");
        assert_eq!(again, rd);
    }

    /// 结构非法（长度不符 / 参数越界 / 尾随垃圾）必须 fail-closed。
    #[test]
    fn malformed_new_types_are_rejected() {
        assert!(parse_rdata(&[0, 0], 0, TYPE_SVCB, 2).is_none(), "SVCB 过短");
        assert!(
            parse_rdata(&[0, 0], 0, TYPE_CAA, 2).is_none(),
            "CAA tag 缺失"
        );
        assert!(parse_rdata(&[0, 0], 0, TYPE_TLSA, 2).is_none(), "TLSA 过短");
        assert!(parse_rdata(&[0, 1, 2], 0, TYPE_DS, 3).is_none(), "DS 过短");
        assert!(parse_rdata(&[0], 0, TYPE_NAPTR, 1).is_none(), "NAPTR 过短");
        // SVCB：声明 key 长度超过 rdata 末尾。
        let bad = [0u8, 1, 0, 0, 1, 0, 5, 0, 0];
        assert!(parse_rdata(&bad, 0, TYPE_SVCB, bad.len() as u16).is_none());
        // NAPTR：replacement 后还有尾随字节。
        let mut naptr = Vec::new();
        naptr.extend(1u16.to_be_bytes());
        naptr.extend(1u16.to_be_bytes());
        naptr.extend([0u8, 0, 0]); // 三个空 char-string
        naptr.push(0); // root replacement
        naptr.push(0xff); // 尾随垃圾
        assert!(parse_rdata(&naptr, 0, TYPE_NAPTR, naptr.len() as u16).is_none());
    }
}
