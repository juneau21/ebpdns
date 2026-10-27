//! **[历史归因]** DNS 线格式常量与默认值（对齐 RFC 与 Python `dnsmsg.py` / `config.py`）。

// ---- TYPE（qtype / rrtype）----
pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_NULL: u16 = 10;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_MX: u16 = 15;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_NAPTR: u16 = 35;
pub const TYPE_OPT: u16 = 41;
pub const TYPE_DS: u16 = 43;
pub const TYPE_SSHFP: u16 = 44;
pub const TYPE_RRSIG: u16 = 46;
pub const TYPE_NSEC: u16 = 47;
pub const TYPE_DNSKEY: u16 = 48;
pub const TYPE_NSEC3: u16 = 50;
pub const TYPE_NSEC3PARAM: u16 = 51;
pub const TYPE_TLSA: u16 = 52;
pub const TYPE_CDS: u16 = 59;
pub const TYPE_CDNSKEY: u16 = 60;
pub const TYPE_SVCB: u16 = 64;
pub const TYPE_HTTPS: u16 = 65;
pub const TYPE_TKEY: u16 = 249;
pub const TYPE_TSIG: u16 = 250;
pub const TYPE_IXFR: u16 = 251;
pub const TYPE_AXFR: u16 = 252;
pub const TYPE_MAILB: u16 = 253;
pub const TYPE_MAILA: u16 = 254;
pub const TYPE_ANY: u16 = 255;
pub const TYPE_URI: u16 = 256;
pub const TYPE_CAA: u16 = 257;

// ---- CLASS ----
pub const CLASS_IN: u16 = 1;

// ---- RCODE（低 4 位）----
pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_FORMERR: u8 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_NOTIMP: u8 = 4;
pub const RCODE_REFUSED: u8 = 5;

// ---- Header flag 位掩码 ----
pub const FLAG_QR: u16 = 0x8000;
pub const FLAG_AA: u16 = 0x0400;
pub const FLAG_TC: u16 = 0x0200;
pub const FLAG_RD: u16 = 0x0100;
pub const FLAG_RA: u16 = 0x0080;
pub const FLAG_OPCODE_MASK: u16 = 0x7800;
pub const FLAG_RCODE_MASK: u16 = 0x000F;
/// `_response_header_bits` 保留位掩码：opcode(0x7800) + RD(0x0100) + CD(0x0010)。
pub const FLAG_KEEP_MASK: u16 = 0x7910;
/// 置位：QR(0x8000) + RA(0x0080)。
pub const FLAG_QR_RA: u16 = 0x8080;

// ---- EDNS option codes ----
pub const OPTION_ECS: u16 = 8;
pub const OPTION_PADDING: u16 = 12;

// ---- 容量 / 默认值 ----
/// 单条响应允许的最大答案数（超出截断并置 TC）。
pub const MAX_ANSWERS: usize = 8;
/// 展开后域名线格式长度上限（RFC 1035：255 字节；实现判定 `name_len >= 255` 拒绝）。
pub const MAX_NAME_WIRE_LEN: usize = 255;
/// 单标签字节上限。
pub const MAX_LABEL_LEN: usize = 63;
/// 压缩指针跳转上限（防自引用环 DoS）。
pub const MAX_PTR_JUMPS: usize = 32;
/// **[历史归因]** TTL 打包前钳制上限（Python resolver：`min(2147483647, ...)`）。
pub const TTL_MAX: u32 = 2_147_483_647;
/// TTL 默认值（`_safe_int(..., 300)`）。
pub const TTL_DEFAULT: u32 = 300;

/// 默认 EDNS0 UDP payload 大小（IPv6 最小 MTU 防分片安全值）。
pub const DEFAULT_EDNS_UDP_SIZE: u16 = 1232;
/// 出站 EDNS UDP size 配置下限（config.py：512..9000）。
pub const MIN_EDNS_UDP_SIZE: u16 = 512;
/// 出站 EDNS UDP size 配置上限（config.py：512..9000）。
pub const MAX_EDNS_UDP_SIZE: u16 = 9000;
/// 解析侧无 EDNS 时的经典 UDP 上限；OPT class 钳制下限。
pub const DEFAULT_BUF_SIZE: u16 = 512;
/// OPT class 字段线格式上限（u16）。
pub const MAX_BUF_SIZE_WIRE: u16 = 65535;

/// Padding 对齐块大小（RFC 8467）。
pub const PADDING_BLOCK: usize = 128;
/// Padding 最大填充字节数。
pub const PADDING_MAX: usize = 512;

/// TCP 帧长度前缀上限（u16）。
pub const TCP_FRAME_MAX: usize = 65535;

/// 把出站 EDNS UDP size 钳制到配置范围 [512, 9000]，falsy/越界回退默认 1232。
pub fn clamp_edns_udp_size(size: Option<u32>) -> u16 {
    let raw = match size {
        None => return DEFAULT_EDNS_UDP_SIZE,
        Some(v) => v,
    };
    // **[历史归因]** 0 / falsy → 默认；越界钳到边界。与 Python `_safe_int` + 配置范围一致。
    if raw == 0 {
        return DEFAULT_EDNS_UDP_SIZE;
    }
    let v = raw.min(MAX_EDNS_UDP_SIZE as u32) as u16;
    if v < MIN_EDNS_UDP_SIZE {
        MIN_EDNS_UDP_SIZE
    } else {
        v
    }
}

/// 解析侧 OPT class 字段钳制到 [512, 65535]（`_edns_bufsize`）。
pub fn clamp_bufsize_received(raw: u16) -> u16 {
    let v = if raw == 0 { DEFAULT_BUF_SIZE } else { raw };
    v.clamp(DEFAULT_BUF_SIZE, MAX_BUF_SIZE_WIRE)
}

/// TTL 打包前钳到 [0, 2147483647]。
pub fn clamp_ttl(ttl: u64) -> u32 {
    ttl.min(TTL_MAX as u64) as u32
}

/* ======================= 受支持的 qtype（单一来源） ======================= */

/// 本服务**能真正解析并编码**的 qtype 名单：(线格式码, 大写名)。
///
/// **单一来源**：数据面受理判定（`ebpdns-server::dns`）、缓存键名字映射
/// （`ebpdns-resolver::answer`）、上游查询组包（`ebpdns-resolver::helpers`）都从这里取，
/// 取代此前三处各自 `_ => "A"` / `_ => TYPE_A` 的兜底 —— 那个兜底让
/// `AXFR(252)` / `TYPE65280` / `TYPE0` / `ANY(255)` 被**当成 A 查询**发往上游
/// （P0-4：实测这些畸形 qtype 都返回了 A 记录）。
///
/// 名单与 [`crate::rdata::encode_rdata`] 能编码的 RR 类型一一对应。数据面
/// 对此名单是**三分派**（`ebpdns-server::dns::classify_qtype`）：
/// 1. 名单内 → 解析 + 编码 + **缓存**（正常 TTL 语义）；
/// 2. [`qtype_must_reject`] → `NOTIMP`（区传送/元查询/DNSSEC 语义类型）；
/// 3. 其余未知/其他合法类型 → **透传**（按原始 u16 发上游、原样回传、**不缓存**）。
///
/// 无论哪一支都**绝不静默降级成 `A`**（P0-4 的底线）。
pub const SUPPORTED_QTYPES: &[(u16, &str)] = &[
    (TYPE_A, "A"),
    (TYPE_NS, "NS"),
    (TYPE_CNAME, "CNAME"),
    (TYPE_SOA, "SOA"),
    (TYPE_PTR, "PTR"),
    (TYPE_MX, "MX"),
    (TYPE_TXT, "TXT"),
    (TYPE_AAAA, "AAAA"),
    (TYPE_SRV, "SRV"),
    // ---- 2.1.29 新增：SVCB/HTTPS 与同批"长度前缀/定长"RDATA 类型 ----
    (TYPE_NAPTR, "NAPTR"),
    (TYPE_DS, "DS"),
    (TYPE_SSHFP, "SSHFP"),
    (TYPE_DNSKEY, "DNSKEY"),
    (TYPE_TLSA, "TLSA"),
    (TYPE_CDS, "CDS"),
    (TYPE_CDNSKEY, "CDNSKEY"),
    (TYPE_SVCB, "SVCB"),
    (TYPE_HTTPS, "HTTPS"),
    (TYPE_URI, "URI"),
    (TYPE_CAA, "CAA"),
];

/// **必须拒绝（`NOTIMP`）**的 qtype：区传送 / 元查询 / DNSSEC 语义类型 / 保留类型。
///
/// 这些码**不进**透传路径，理由逐类：
/// - `AXFR(252)` / `IXFR(251)`：区传送是 TCP 多报文流，本服务只做单次解析；
/// - `ANY(255)`：RFC 8482 明确允许以 NOTIMP/HINFO 拒绝（放大面）；
/// - `OPT(41)` / `TSIG(250)` / `TKEY(249)`：只允许出现在 additional 段的伪 RR /
///   事务层类型，作为 question 没有解析语义；
/// - `NULL(10)`：已废弃且无定义语义（RFC 1035 保留）；
/// - `RRSIG(46)` / `NSEC(47)` / `NSEC3(50)` / `NSEC3PARAM(51)`：DNSSEC 语义类型，
///   其 RRSIG 覆盖范围/NSEC 链需要 DNSSEC 验证上下文，且历史上是压缩指针滥用面；
/// - `TYPE0`：保留码（RFC 6895），不是合法 qtype。
///
/// 判据与 [`SUPPORTED_QTYPES`] **互斥**（单测钉死）：受支持的类型不在这里。
/// 未列出的其余码（含 `MAILA(254)` / `MAILB(253)` 这类无实现的元查询）一律走**透传**支
/// —— 它们只是普通单查询，不构成区传送/放大面。
pub fn qtype_must_reject(t: u16) -> bool {
    t == 0
        || matches!(
            t,
            TYPE_NULL
                | TYPE_OPT
                | TYPE_RRSIG
                | TYPE_NSEC
                | TYPE_NSEC3
                | TYPE_NSEC3PARAM
                | TYPE_TKEY
                | TYPE_TSIG
                | TYPE_IXFR
                | TYPE_AXFR
                | TYPE_ANY
        )
}

/// 未知/其他合法 qtype → **透传**判定（数据面据此走 `resolve_passthrough`）。
///
/// 三分派的第三支：既不在受理名单、也不在必须拒绝名单。透传语义见
/// `ebpdns-resolver::passthrough` 模块文档（按原始 u16 发上游、原样回传、不缓存）。
pub fn qtype_passthrough(t: u16) -> bool {
    qtype_name(t).is_none() && !qtype_must_reject(t)
}

/// 线格式 qtype 码 → 大写名；**不支持的类型返回 `None`**（不得兜底成 `"A"`）。
pub fn qtype_name(t: u16) -> Option<&'static str> {
    SUPPORTED_QTYPES
        .iter()
        .find(|(code, _)| *code == t)
        .map(|(_, name)| *name)
}

/// 大写名 → 线格式 qtype 码；**不支持的名字返回 `None`**（不得兜底成 [`TYPE_A`]）。
///
/// 大小写不敏感（与配置/API 的 qtype 输入一致）。
pub fn qtype_code(name: &str) -> Option<u16> {
    let up = name.trim().to_ascii_uppercase();
    SUPPORTED_QTYPES
        .iter()
        .find(|(_, n)| *n == up)
        .map(|(code, _)| *code)
}

/// 该 qtype 是否受支持（解析 + 编码 + 缓存；**不**含透传/拒绝判定）。
pub fn qtype_supported(t: u16) -> bool {
    qtype_name(t).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P0-4 回归（**2.1.29 三分派后仍钉死**）：区传送 / 元查询 / 保留码 / DNSSEC
    /// 语义类型**一律必须拒绝**，且它们**不得**落进透传支（否则会以原始 qtype
    /// 发上游，等于对 AXFR/ANY 放行）。
    #[test]
    fn rejected_qtypes_are_not_supported_not_passthrough_and_never_fall_back_to_a() {
        for t in [0u16, 10, 41, 46, 47, 50, 51, 249, 250, 251, 252, 255] {
            assert!(!qtype_supported(t), "qtype {t} 不得被受理");
            assert_eq!(qtype_name(t), None, "qtype {t} 不得兜底成 A");
            assert!(qtype_must_reject(t), "qtype {t} 必须留在 NOTIMP 支");
            assert!(!qtype_passthrough(t), "qtype {t} 不得进透传支");
        }
    }

    /// **2.1.29**：未知/其他合法 qtype 进**透传**支 —— 不是"受理"（无解析/无缓存），
    /// 也不是"拒绝"（不再 NOTIMP）；仍然**不得**兜底成 A。
    #[test]
    fn unknown_qtypes_are_passthrough_not_supported_and_not_a() {
        for t in [65_280u16, 65_534, 999, 253, 254, 65, 64, 257] {
            // 65/64/257 是 2.1.29 新增的**受支持**类型，单独在下面的测试里钉。
            if matches!(t, 64 | 65 | 257) {
                assert!(qtype_supported(t), "qtype {t} 已转为受支持");
                assert!(!qtype_passthrough(t));
                continue;
            }
            assert!(!qtype_supported(t), "qtype {t} 不是受理名单成员");
            assert!(!qtype_must_reject(t), "qtype {t} 不是必须拒绝");
            assert!(qtype_passthrough(t), "qtype {t} 必须进透传支");
            assert_eq!(qtype_name(t), None, "qtype {t} 不得兜底成 A");
        }
    }

    /// 三分派**互斥且完备**：每个码恰好落一支。
    #[test]
    fn qtype_taxonomy_is_mutually_exclusive_and_complete() {
        for t in 0u16..=u16::MAX {
            let supported = qtype_supported(t);
            let rejected = qtype_must_reject(t);
            let passthrough = qtype_passthrough(t);
            assert!(
                (supported as u8 + rejected as u8 + passthrough as u8) == 1,
                "qtype {t} 必须恰好落一支（supported={supported} rejected={rejected} \
                 passthrough={passthrough}）"
            );
        }
    }

    /// 受理名单内的新增类型：名称/码双向可逆，且 HTTPS/SVCB/CAA 等已转为支持。
    #[test]
    fn newly_supported_qtypes_round_trip() {
        for (code, name) in [
            (TYPE_SVCB, "SVCB"),
            (TYPE_HTTPS, "HTTPS"),
            (TYPE_CAA, "CAA"),
            (TYPE_TLSA, "TLSA"),
            (TYPE_DS, "DS"),
            (TYPE_SSHFP, "SSHFP"),
            (TYPE_DNSKEY, "DNSKEY"),
            (TYPE_CDS, "CDS"),
            (TYPE_CDNSKEY, "CDNSKEY"),
            (TYPE_URI, "URI"),
            (TYPE_NAPTR, "NAPTR"),
        ] {
            assert_eq!(qtype_name(code), Some(name));
            assert_eq!(qtype_code(name), Some(code));
            assert!(qtype_supported(code));
            assert!(!qtype_must_reject(code));
            assert!(!qtype_passthrough(code));
        }
        // 原本被 P0-4 钉成"不受支持"的 HTTPS 现已受理；ANY/AXFR 仍拒。
        assert!(qtype_supported(TYPE_HTTPS));
        assert!(qtype_must_reject(TYPE_ANY));
        assert!(qtype_must_reject(TYPE_AXFR));
        assert_eq!(qtype_code("ANY"), None);
        assert_eq!(qtype_code("AXFR"), None);
    }

    /// 名单内类型双向可逆，且与 rdata 编码能力一致。
    #[test]
    fn supported_qtypes_round_trip() {
        for (code, name) in SUPPORTED_QTYPES {
            assert_eq!(qtype_name(*code), Some(*name));
            assert_eq!(qtype_code(name), Some(*code));
            // 小写/带空白输入同样受理（API/配置里常见）。
            assert_eq!(qtype_code(&name.to_ascii_lowercase()), Some(*code));
            assert_eq!(qtype_code(&format!(" {name} ")), Some(*code));
            assert!(!qtype_must_reject(*code), "受理名单与拒绝名单必须互斥");
            assert!(!qtype_passthrough(*code));
        }
        assert_eq!(qtype_code("a"), Some(TYPE_A));
        assert_eq!(qtype_name(TYPE_A), Some("A"));
        assert_eq!(qtype_code("not-a-type"), None);
        assert_eq!(qtype_name(1), Some("A"));
    }
}
