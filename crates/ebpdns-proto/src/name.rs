//! 域名（owner name / qname）线格式编解码。
//!
//! - [`encode_name`]：域名字符串 → 标签序列（含末尾 `\x00`），不含压缩。
//! - [`decode_name`]：从报文 offset 解码域名，支持压缩指针；返回 `(name, next_offset)`。
//! - [`Name`]：规范化域名（缓存键/规则匹配口径），与线格式编解码分离。

use crate::constants::{MAX_LABEL_LEN, MAX_NAME_WIRE_LEN, MAX_PTR_JUMPS};
use crate::error::ProtoError;
use crate::ProtoResult;

/// 规范化域名：`trim().trim_end_matches('.')` + 大小写折叠。
///
/// 与线格式编解码分离——线格式必须**保留大小写**（0x20 熵），
/// 而缓存键/规则匹配需要小写归一。
///
/// **[历史归因]** P-02 口径说明：这里做的是**纯大小写折叠**（与 Python
/// `resolver._normalize` = `strip().rstrip(".").lower()` 逐条对齐），**不做** IDNA
/// punycode 转换。缓存键在 DNS 名"语义相等"的意义上必须是纯小写形态：若把
/// `"bücher.example.com"` 归一成 `"xn--bcher-kva.example.com"`，则已经以 punycode
/// 存过一次的键与本次 Unicode 键会分叉，且规则匹配（`engine.rs:162` 也走本函数）
/// 会对同一条规则产生两种键。真正的 IDNA 大小写折叠修复在 [`encode_name`]
/// **[历史归因]** —— 即"发出去的报文体"必须是 `xn--bcher-kva`，与 Python `label.encode("idna")`
/// 一致；其中已含 `to_lowercase()`，故 `"BÜCHER"` 与 `"bücher"` 的**线格式**相同。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Name(String);

impl Name {
    /// 规范化一个域名字符串。
    pub fn normalize(s: &str) -> Self {
        let trimmed = s.trim().trim_end_matches('.');
        Name(trimmed.to_lowercase())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// 非 ASCII 标签 → IDNA（Punycode）ASCII 标签。
///
/// **[历史归因]** P-02：**先做 Unicode 小写折叠**再做 IDNA。Python `encode("idna")` 隐含 nameprep
/// 的大小写折叠（RFC 3490），`"BÜCHER"` 与 `"bücher"` 必须映射到同一个 punycode
/// `"xn--bcher-kva"`；`idna::domain_to_ascii` 的 UTS#46 映射表虽也折叠大小写，
/// 但显式 `to_lowercase()` 让该不变量不依赖具体 crate 版本，并顺带覆盖
/// 映射表缺失的码位。
///
/// 已知取舍：Unicode **多字符**大小写映射（如 `"ß"` 无 1:1 大写）无法折叠——
/// **[历史归因]** 与 Python `str.lower()` 行为一致（`"STRASSE".lower() != "straße"`）。
fn normalize_idna_label(label: &str) -> ProtoResult<String> {
    let lower = label.to_lowercase();
    if lower.is_ascii() {
        // 小写化后已纯 ASCII（如 "BÜCHER" 之外的 "ÖBB"→"öbb" 仍非 ASCII，不受影响）。
        return Ok(lower);
    }
    idna::domain_to_ascii(&lower)
        .map_err(|_| ProtoError::invalid_name(format!("invalid IDNA label: {label}")))
}

/// 将域名编码为 DNS 标签序列（含根 `\x00` 结尾）。
///
/// **[历史归因]** 对齐 Python `encode_name`：
/// - 去掉结尾 `.`；空名 → `\x00`；
/// - 连续点产生的空标签被过滤；
/// - 单标签 >63 字节或展开名 >255 字节 → [`Err`]。
///
/// **保留大小写**（不做 lower-case），因为 query 段需回显 0x20 熵。
///
/// **[历史归因]** 非 ASCII 域名走 IDNA（Punycode）编码，对齐 Python `label.encode("idna")`：
/// 逐标签 Unicode 小写折叠 + punycode，失败 → [`ProtoError::InvalidName`]。
pub fn encode_name(name: &str) -> ProtoResult<Vec<u8>> {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        return Ok(vec![0]);
    }
    // 纯 ASCII 快速通道：直接按 UTF-8(==ASCII) 字节写入，保留大小写。
    if name.is_ascii() {
        let mut out: Vec<u8> = Vec::new();
        for label in name.split('.') {
            if label.is_empty() {
                continue; // 过滤 "a..b" 连续点产生的空标签
            }
            append_label(&mut out, label.as_bytes(), label)?;
        }
        out.push(0);
        if out.len() > MAX_NAME_WIRE_LEN {
            return Err(ProtoError::invalid_name("name too long"));
        }
        return Ok(out);
    }
    // **[历史归因]** 非 ASCII：IDNA 路径（对齐 Python：过滤空标签、逐标签 idna 编码）。
    let mut out: Vec<u8> = Vec::new();
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        let ascii_label = normalize_idna_label(label)?;
        append_label(&mut out, ascii_label.as_bytes(), label)?;
    }
    out.push(0);
    if out.len() > MAX_NAME_WIRE_LEN {
        return Err(ProtoError::invalid_name("name too long"));
    }
    Ok(out)
}

/// 写入一个标签（长度前缀 + 字节），带 >63 字节校验。`orig` 仅用于报错信息。
fn append_label(out: &mut Vec<u8>, lb: &[u8], orig: &str) -> ProtoResult<()> {
    if lb.len() > MAX_LABEL_LEN {
        return Err(ProtoError::invalid_name(format!("label too long: {orig}")));
    }
    out.push(lb.len() as u8);
    out.extend_from_slice(lb);
    Ok(())
}

/// 从 `data` 的 `offset` 处解码域名，支持压缩指针。
/// 返回 `(name, next_offset)`。
///
/// **[历史归因]** 压缩安全（对齐 Python `decode_name`）：
/// - 跳转上限 [`MAX_PTR_JUMPS`]（32）防自引用环；
/// - 前向指针（`ptr >= pos`）拒绝；
/// - `0x40` / `0x80` 非法标签高位拒绝；
/// - 展开名 `name_len >= 255` 拒绝；
/// - 越界读取拒绝。
pub fn decode_name(data: &[u8], offset: usize) -> ProtoResult<(String, usize)> {
    let dlen = data.len();
    // 直接追加进单个 String，省去 Vec<String> 中间分配与 join（解析热路径）。
    let mut name = String::with_capacity(64);
    let mut first = true;
    let mut jump_done = false;
    let mut end = offset;
    let mut pos = offset;
    let mut jumps = 0usize;
    let mut name_len = 0usize;

    loop {
        if pos >= dlen {
            return Err(ProtoError::truncated("truncated name"));
        }
        let length = data[pos];
        if length == 0 {
            if !jump_done {
                end = pos + 1;
            }
            break;
        }
        // 最高两位非 0 但不是标准压缩指针(0xC0xx) → 非法标签长度。
        if length & 0xC0 != 0 && length & 0xC0 != 0xC0 {
            return Err(ProtoError::invalid_name("invalid label length"));
        }
        if length & 0xC0 == 0xC0 {
            if pos + 1 >= dlen {
                return Err(ProtoError::truncated("truncated pointer"));
            }
            jumps += 1;
            if jumps > MAX_PTR_JUMPS {
                return Err(ProtoError::invalid_name("too many compression jumps"));
            }
            let ptr = ((length & 0x3F) as usize) << 8 | data[pos + 1] as usize;
            // 压缩指针只能向后引用（ptr < 当前 pos）。
            if ptr >= pos {
                return Err(ProtoError::invalid_name("forward compression pointer"));
            }
            if !jump_done {
                end = pos + 2;
                jump_done = true;
            }
            pos = ptr;
            continue;
        }
        // 普通标签。
        pos += 1;
        if pos + length as usize > dlen {
            return Err(ProtoError::truncated("truncated label"));
        }
        // **[历史归因]** 标签字节按 UTF-8 解码，非法字节替换为 U+FFFD（对齐 Python errors=replace）。
        let raw = &data[pos..pos + length as usize];
        if !first {
            name.push('.');
        }
        match std::str::from_utf8(raw) {
            Ok(s) => name.push_str(s),
            // 罕见路径：非法字节用 lossy 串替换（分配仅在畸形报文时发生）。
            Err(_) => name.push_str(&String::from_utf8_lossy(raw)),
        }
        first = false;
        name_len += 1 + length as usize;
        if name_len >= MAX_NAME_WIRE_LEN {
            return Err(ProtoError::invalid_name("name too long"));
        }
        pos += length as usize;
    }

    Ok((name, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_lowercases_and_trims_dot() {
        assert_eq!(
            Name::normalize("  Ww.Example.Com.  ").as_str(),
            "ww.example.com"
        );
    }

    /// P-02：ASCII 快速通道逐字节不变（0x20 熵）。
    #[test]
    fn encode_name_ascii_preserves_case() {
        assert_eq!(
            encode_name("WwW.Example.COM").unwrap(),
            b"\x03WwW\x07Example\x03COM\x00"
        );
        assert_eq!(
            encode_name("WwW.Example.COM").unwrap(),
            encode_name("WwW.Example.COM").unwrap()
        );
    }

    /// P-02：Unicode 大写必须与 Unicode 小写产生**逐字节相同**的 punycode 线格式。
    #[test]
    fn encode_name_idna_folds_unicode_case() {
        let upper = encode_name("BÜCHER.example.com").unwrap();
        let lower = encode_name("bücher.example.com").unwrap();
        let mixed = encode_name("Bücher.Example.Com").unwrap();
        assert_eq!(upper, lower, "Unicode 大写/小写必须编码为同一线格式");
        assert_eq!(upper, mixed);
        // 期望字节：punycode "xn--bcher-kva"（13 字节）+ example + com + 根。
        assert_eq!(
            upper,
            b"\x0dxn--bcher-kva\x07example\x03com\x00".to_vec(),
            "IDNA 结果应为 xn--bcher-kva"
        );
        // 首标签长度前缀只出现一次（未被 to_lowercase 改变长度而错位）。
        assert_eq!(upper[0], 13);
    }

    /// **[历史归因]** P-02：缓存键口径 = 纯 Unicode 小写折叠（对齐 Python `resolver._normalize`
    /// = `strip().rstrip(".").lower()`），**不做** IDNA punycode 转换。
    /// `"BÜCHER"` 与 `"bücher"` 必须折叠到同一键（这是 P-02 要求的"Unicode 大写与
    /// ASCII/小写写法映射到同一缓存键"）；punycode 写法是**另一种写法**，其归一
    /// 结果与键空间刻意保持形式一致（不做二次转换），由 `encode_name` 保证"发出去
    /// 的线格式"统一为 punycode。
    #[test]
    fn name_normalize_folds_unicode_case_only() {
        let a = Name::normalize("BÜCHER.example.com");
        let b = Name::normalize("bücher.example.com");
        let c = Name::normalize("Bücher.Example.Com.");
        assert_eq!(a, b, "Unicode 大写/小写必须折叠到同一缓存键");
        assert_eq!(a, c, "尾点与混合大小写同样折叠");
        assert_eq!(a.as_str(), "bücher.example.com");
        // **[历史归因]** punycode 写法是独立键（不经 IDNA 反解）——与 Python `_normalize` 一致；
        // 两者在 DNS 语义上等价，但缓存键形式不同，故此处显式固化而非"悄悄相等"。
        assert_eq!(
            Name::normalize("xn--bcher-kva.example.com").as_str(),
            "xn--bcher-kva.example.com"
        );
        // ASCII 行为不变。
        assert_eq!(
            Name::normalize("WWW.Example.COM.").as_str(),
            "www.example.com"
        );
    }

    /// P-02 端到端：`encode_name` 发出的线格式对 Unicode 大写/小写/punycode
    /// **三种写法完全一致**（缓存键分形式、线格式统一，避免同一域名被上游看到
    /// 两种编码）。
    #[test]
    fn wire_format_agrees_across_unicode_and_punycode_spellings() {
        let upper = encode_name("BÜCHER.example.com").expect("可编码");
        let lower = encode_name("bücher.example.com").expect("可编码");
        let puny = encode_name("xn--bcher-kva.example.com").expect("可编码");
        assert_eq!(upper, lower, "Unicode 大写/小写线格式必须一致");
        assert_eq!(upper, puny, "punycode 与 Unicode 写法线格式必须一致");
        let (decoded, _) = decode_name(&upper, 0).expect("可解码");
        assert_eq!(decoded, "xn--bcher-kva.example.com");
    }

    /// 缓存键与线格式的**正确**关系：线格式保留调用方给定的大小写（0x20 熵），
    /// 缓存键一律小写，故两者只在"输入本身已全小写"时才逐字节相等。
    ///
    /// 依据 dnsmsg.py（逐行）：
    /// - `encode_name` 的 ASCII 快速通道 `out.append(ll); out += label.encode()`
    ///   （dnsmsg.py:115-124）**不做任何小写化**；非 ASCII 路径同理只在 `label.encode("idna")`
    ///   内隐式折叠（dnsmsg.py:139-146）。
    /// - `decode_name` 同样按原样 `data[pos:pos+length].decode("ascii")`（dnsmsg.py:200-203），
    ///   不折叠大小写。
    /// - 0x20 查询名随机化的回显契约明确写在 `extract_question` docstring
    ///   （dnsmsg.py:755-756）："question 段必须原样回显客户端查询字节(含 0x20 大小写)"。
    /// - 缓存键口径在 `resolver._normalize`（resolver.py:4128-4130）
    ///   = `strip().rstrip(".").lower()`，等价 [`Name::normalize`]，恒小写。
    ///
    /// 所以正确的往返不变量是「归一后（大小写不敏感）一致」+「线格式逐字节保留原大小写」；
    /// 原断言（缓存键 == 线格式解码结果）在小写输入上偶然成立，在
    /// `WWW.Example.COM` 上必然失败——那是**测试写错**，不是编码回归。
    #[test]
    fn cache_key_matches_wire_for_ascii_domains() {
        for input in ["WWW.Example.COM", "api.example.com.", "a.b.c"] {
            let wire = encode_name(input).expect("可编码");
            let (decoded, _) = decode_name(&wire, 0).expect("可解码");
            // 真·不变量：归一后一致（大小写不敏感）——这是缓存键的判定口径。
            assert_eq!(
                Name::normalize(input),
                Name::normalize(&decoded),
                "{input}: 归一后缓存键必须与线格式解码结果一致"
            );
            // 线格式保留调用方大小写（仅去尾点），与解码结果逐字节相同。
            assert_eq!(
                decoded,
                input.trim_end_matches('.'),
                "{input}: 线格式必须保留调用方给定的大小写（dnsmsg.py:115-128 / 755-756）"
            );
        }
        // 仅当输入已全小写时，缓存键才与线格式解码结果逐字节相等。
        for input in ["api.example.com.", "a.b.c"] {
            let wire = encode_name(input).expect("可编码");
            let (decoded, _) = decode_name(&wire, 0).expect("可解码");
            assert_eq!(Name::normalize(input).as_str(), decoded, "{input}");
        }
        // 混合大小写反例固化：0x20 熵保留在线上，缓存键仍是小写，两者刻意不等。
        let wire = encode_name("WWW.Example.COM").expect("可编码");
        let (decoded, _) = decode_name(&wire, 0).expect("可解码");
        assert_eq!(decoded, "WWW.Example.COM", "线格式保留 0x20 大小写");
        assert_eq!(
            Name::normalize("WWW.Example.COM").as_str(),
            "www.example.com"
        );
        assert_ne!(
            Name::normalize("WWW.Example.COM").as_str(),
            decoded,
            "缓存键（小写）与线格式（保留大小写）本就不同——见 dnsmsg.py:115-128"
        );
    }

    /// P-02：IDNA 失败（非法标签）必须报错而不是产出错误线格式。
    #[test]
    fn encode_name_rejects_invalid_idna_label() {
        // **[历史归因]** 58 个 'ü' → punycode 标签 64 字节 > MAX_LABEL_LEN(63)：Python
        // `'\u00fc'*58.encode("idna")` 亦抛 "label empty or too long"。
        let long = "ü".repeat(58);
        assert!(
            encode_name(&long).is_err(),
            "IDNA 后 >63 字节的标签必须被拒"
        );
    }

    /// IDNA 后标签长度不得被 `to_lowercase()` 的长度变化破坏。
    #[test]
    fn encode_name_idna_label_length_prefix_is_consistent() {
        let enc = encode_name("ÖBB.at").unwrap();
        let first = enc[0] as usize;
        assert_eq!(enc.len(), 1 + first + 1 + 2 + 1);
        assert_eq!(&enc[1..1 + first], b"xn--bb-eka");
    }
}
