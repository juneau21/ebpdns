//! 上游并发查询：`ParallelQuerier` trait（测试 seam）+ 生产实现 + classify_one。
//!
//! **[历史归因]** 对齐 Python `_query_parallel` / `classify_one`：并发全部可用上游，分类单条应答。
//! 测试通过注入 [`ScriptedQuerier`] 返回 canned `UpstreamAnswer`，不联网、不起服。

use crate::config::UpstreamCfg;
use crate::types::{ResolveAnswer, UpstreamAnswer};
use async_trait::async_trait;
use ebpdns_proto::constants::TYPE_CNAME;
use ebpdns_proto::message::parse_message;

/// 并发上游查询 seam。生产实现包装 `UpstreamRuntime`；测试注入脚本化应答。
#[async_trait]
#[allow(clippy::type_complexity)]
pub trait ParallelQuerier: Send + Sync + 'static {
    async fn query_parallel(
        &self,
        ups: &[UpstreamCfg],
        qname: &str,
        qtype: &str,
        depth: u32,
    ) -> Vec<UpstreamAnswer>;

    /// **2.1.29**：未知 qtype **透传**专用 —— 按**原始 `u16`** 发上游，返回带
    /// `UpstreamAnswer::raw`（上游响应原字节）的结果。
    ///
    /// 默认实现返回空（"该实现不支持透传" ⇒ 数据面按上游失败回 SERVFAIL）；
    /// 生产实现与 [`Self::query_parallel`] 共用**同一条**上游路径（熔断过滤 /
    /// 自适应对冲 / 在途闸门 / 健康统计全部沿用），只是不做 rdata 解析。
    async fn query_parallel_raw(
        &self,
        ups: &[UpstreamCfg],
        qname: &str,
        qtype: u16,
        depth: u32,
    ) -> Vec<UpstreamAnswer> {
        let _ = (ups, qname, qtype, depth);
        Vec::new()
    }
}

/// 脚本化查询器：按 (qname, qtype, depth) 返回 canned 应答（测试注入点）。
pub struct ScriptedQuerier {
    pub handler: Box<ScriptedHandler>,
}

/// 脚本化 handler 类型别名。
pub type ScriptedHandler = dyn Fn(&str, &str, u32) -> Vec<UpstreamAnswer> + Send + Sync;

impl ScriptedQuerier {
    pub fn new<F>(f: F) -> Self
    where
        F: Fn(&str, &str, u32) -> Vec<UpstreamAnswer> + Send + Sync + 'static,
    {
        Self {
            handler: Box::new(f),
        }
    }
}

#[async_trait]
impl ParallelQuerier for ScriptedQuerier {
    async fn query_parallel(
        &self,
        _ups: &[UpstreamCfg],
        qname: &str,
        qtype: &str,
        depth: u32,
    ) -> Vec<UpstreamAnswer> {
        (self.handler)(qname, qtype, depth)
    }

    /// **2.1.29**：脚本化透传 —— 用 `TYPE<n>` 作为 qtype 字符串调用同一 handler，
    /// 测试据此返回带 `raw` 的 canned 上游报文（证明**原始 u16** 被透传到上游层）。
    async fn query_parallel_raw(
        &self,
        _ups: &[UpstreamCfg],
        qname: &str,
        qtype: u16,
        depth: u32,
    ) -> Vec<UpstreamAnswer> {
        (self.handler)(qname, &format!("TYPE{qtype}"), depth)
    }
}

/// classify_one：把上游响应字节解析为 [`UpstreamAnswer`]。
///
/// **S1 bailiwick 锚定**：信任根锚定在真实查询名 `qname`（非响应 question 段）。
/// 维护 `allowed = {qname} ∪ 已见 CNAME 目标`；CNAME owner 与目标答案 owner 必须
/// ∈ allowed，否则丢弃（缓存投毒防护）。空 owner（根 "."）对非根查询恒拒绝。
///
/// **TC 位**：`udp_truncated` 直接从响应报文 header 的 TC 位解析（上游已对 UDP TC
/// 做 TCP 回退；回退失败时字节仍带 TC=1，据此正确置位，不再硬编码 false）。
///
/// **目标 qtype**：`want_qtype` 为本轮查询类型。仅当 `rr.rtype == want_qtype` 的 RR
/// 才作为 target answer；CNAME 仅在“非直查 CNAME”时作为链步（直查 CNAME 时该
/// CNAME RR 本身即答案，PTR/NS 等直查类型同理按其 RR 作为答案）。
pub fn classify_one(
    up_name: &str,
    qname: &str,
    body: &[u8],
    want_qtype: u16,
    lat: f64,
) -> UpstreamAnswer {
    let mut out = UpstreamAnswer {
        up_name: up_name.to_string(),
        lat,
        ..Default::default()
    };
    let msg = match parse_message(body) {
        Ok(m) => m,
        Err(_) => {
            out.rcode = None;
            return out;
        }
    };
    out.rcode = Some(msg.rcode);
    // 从响应字节读 TC 位（上游 TCP 回退失败时仍带 TC=1）。
    out.udp_truncated = msg.truncated;

    // 信任根：真实查询名 d（规范化）。d 为空 → allowed 空 → 退化为不限制。
    let root = crate::helpers::normalize(qname);
    let mut allowed: std::collections::HashSet<String> = std::collections::HashSet::new();
    if !root.is_empty() {
        allowed.insert(root);
    }

    for rr in &msg.answers {
        let owner = crate::helpers::normalize(&rr.name);
        // CNAME 链步：仅当本轮不是“直查 CNAME”时，CNAME RR 才沿链推进。
        if rr.rtype == TYPE_CNAME && want_qtype != TYPE_CNAME {
            let Some(tgt) = cname_target(rr) else {
                continue;
            };
            let tgt = crate::helpers::normalize(&tgt);
            // CNAME owner 必须在 bailiwick 内；空 owner 对非根查询恒拒绝。
            if !allowed.is_empty() && !allowed.contains(&owner) {
                continue;
            }
            if tgt.is_empty() {
                continue;
            }
            // **2.1.46（REV247 B P2-9）**：保留上游 TTL=0 的语义。旧实现
            // `max(1)` 会把"明确不缓存"抬成至少 1 s；下游 `fill_cache_capped`
            // 的 `ttl_min` 才是唯一的下限策略（出厂 5 s，可配 0）。
            out.cnames.push((tgt.clone(), rr.ttl));
            allowed.insert(tgt);
            continue;
        }
        // 目标答案：仅 rtype 命中本轮查询类型（A/AAAA 直查、或 CNAME/PTR/NS 等直查）。
        if rr.rtype != want_qtype {
            continue;
        }
        // 目标答案 owner 必须落在 bailiwick 内。
        if !allowed.is_empty() && !allowed.contains(&owner) {
            continue;
        }
        out.answers.push(ResolveAnswer {
            value: rr.rdata.as_display(),
            ttl: rr.ttl as f64,
            rtype: rr.rtype,
            name: None,
        });
    }
    // **[历史归因]** SOA minimum（仅 authority 段，对齐 Python `_soa_minimum`）→ neg_ttl。
    for rr in &msg.authority {
        if let ebpdns_proto::rdata::RData::SOA { minimum, .. } = &rr.rdata {
            out.neg_ttl = Some(*minimum);
        }
    }
    out
}

fn cname_target(rr: &ebpdns_proto::record::ResourceRecord) -> Option<String> {
    if let ebpdns_proto::rdata::RData::CNAME(t) = &rr.rdata {
        Some(t.clone())
    } else {
        None
    }
}
