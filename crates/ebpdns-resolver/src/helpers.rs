//! 纯函数辅助：normalize / guess_type / clamp_ttl / qtype_code / is_private_ip。
//!
//! 死代码收敛（本次复核）：原文件里的 `neg_ttl` 已确认**全仓无调用者**，且其口径与
//! `resolve.rs::neg_ttl_of`（现行实现）**不一致**——前者 `raw.clamp(1.0, min(cfg_ttl,60))`
//! 对畸形/极小 cfg_ttl 会把 TTL 抬到 1 秒上限区间，后者是
//! `clamp_ttl(min(SOA, cfg.ttl.min(60)))`。保留一份实现即删除此重复死代码，避免
//! 后续误用。`rule_label` 薄封装同样无调用者（调用方直接用 `ebpdns_rules::rule_label`），
//! **[历史归因]** 一并删除（含移植期助手 `safe_int` / `safe_float`，本版本无调用者）。

use ebpdns_proto::constants::{TYPE_A, TYPE_AAAA};

/// **[历史归因]** 对齐 Python `_normalize`：strip + 去尾点 + 小写。
pub fn normalize(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// **[历史归因]** 对齐 Python `_guess_type`：含 `:` → AAAA；纯 ASCII 数字(去点) → A；否则按 qtype。
pub fn guess_type(ip: &str, qtype: u16) -> u16 {
    let v = ip.trim();
    if v.contains(':') {
        return TYPE_AAAA;
    }
    let digits: String = v.chars().filter(|c| *c != '.').collect();
    if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
        return TYPE_A;
    }
    qtype
}

/// **[历史归因]** 对齐 Python `_clamp_ttl`：ttl_min/ttl_max 生效；rule 级 TTL 覆盖。
/// **[历史归因]** Python: `max(ttl_min, min(ttl, ttl_max))`，ttl_max=0 表示不限制。
pub fn clamp_ttl(ttl: u32, ttl_min: u32, ttl_max: u32) -> u32 {
    let mut out = ttl;
    if ttl_max > 0 {
        out = out.min(ttl_max);
    }
    out.max(ttl_min)
}

/// 判断 IP 是否私有/保留（rebind 防护）。非 IP（域名）返回 false。
pub fn is_private_ip(s: &str) -> bool {
    ebpdns_upstream::is_private_ip(s)
}

/// **[历史归因]** qtype 字符串 → 线格式类型码（对齐 Python `dnsmsg.type_code`）。
///
/// **P0-4**：单一来源 = [`ebpdns_proto::constants::qtype_code`]；**不支持的名字返回
/// `None`**（旧实现 `_ => TYPE_A` 会把 `AXFR`/`ANY`/任意拼写错误静默变成 A 查询，
/// 实测这些畸形 qtype 全都拿到了 A 记录）。调用方必须显式处理 `None`：数据面回
/// `NOTIMP`，绝不发上游。
pub fn qtype_code(qtype: &str) -> Option<u16> {
    ebpdns_proto::constants::qtype_code(qtype)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P0-4 回归：不支持的 qtype 名字**不得**被兜底成 A。
    #[test]
    fn qtype_code_rejects_unsupported_names() {
        assert_eq!(qtype_code("A"), Some(TYPE_A));
        assert_eq!(qtype_code("aaaa"), Some(TYPE_AAAA));
        assert_eq!(qtype_code("AXFR"), None);
        assert_eq!(qtype_code("ANY"), None);
        assert_eq!(qtype_code(""), None);
        assert_eq!(qtype_code("TYPE65280"), None);
    }
}
