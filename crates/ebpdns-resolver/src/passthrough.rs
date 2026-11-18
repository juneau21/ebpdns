//! **2.1.29**：未知 qtype **透传**（原始 `u16` 发上游、原样回传、**不缓存**）。
//!
//! # 为什么需要它
//!
//! 2.1.19 的 P0-4 修复把"不受支持/未知 qtype"一律拒为 `NOTIMP`，底线是**绝不**
//! 把它们当 A 查询发上游。但那也意味着 DNS 生态里大量合法类型（`SVCB` 之外的
//! 新类型、实验类型、私有类型）全部不可用。2.1.29 起改成三分派：
//! 受理名单（解析+缓存）/ 必须拒绝（`NOTIMP`）/ **其余透传**。
//!
//! 透传的语义边界（与"受理类型"刻意不同）：
//! - **不解析 rdata**：不碰未知类型的编码能力边界，上游报文**原样**回传
//!   （数据面只改写 12 字节头：ID/QR/RA/TC/rcode）；
//! - **不缓存**：不读缓存、不写缓存、不做负缓存；`serve-stale` 不适用。
//!   因此同一查询每次都会真的发上游（这是刻意的：未知类型的语义无法保证
//!   可安全复用，也不想让缓存键空间被任意类型撑大）；
//! - **规则仍先判决**：`block` / `allow` / `group` / `forceIp` 命中时与受理类型
//!   走同一套规则语义 —— 类型未知**不得**绕过屏蔽；
//! - **走既有上游路径**：熔断过滤 / 自适应对冲 / 在途闸门 / 健康统计全部沿用
//!   （由 [`crate::query::ParallelQuerier::query_parallel_raw`] 的生产实现保证）；
//! - **失败**：全部上游超时/无应答 → 结构化 `SERVFAIL`（带
//!   [`ServfailReason::UpstreamTimeout`] / [`ServfailReason::UpstreamNoAnswer`]），
//!   由数据面按既有 `servfail_total` 口径记账，不静默空答。
//!
//! 计数器：`/api/status.counters.passthrough_qtype_total`
//! （`/metrics` 同名 `ebpdns_passthrough_qtype_total`）；事件文案
//! 「类型未知→透传」（与 NOTIMP 的「类型/opcode 不支持」**不同**标签）。

use std::sync::Arc;

use ebpdns_rules::{Action, Rule};

use crate::config::UpstreamCfg;
use crate::helpers::normalize;
use crate::types::{RuleHit, ServfailReason};
use crate::Resolver;

/// 一次透传解析的结果（数据面 `dns.rs::finish_passthrough_outcome` 的**唯一**输入）。
#[derive(Debug, Clone, Default)]
pub struct PassthroughResult {
    pub domain: String,
    /// **原始** `u16` qtype（不经过名字白名单）。
    pub qtype: u16,
    /// 上游**原始响应报文**（成功时 `Some`；数据面只改 12 字节头）。
    pub resp: Option<Vec<u8>>,
    /// 应答 rcode（成功 = 上游 rcode；失败 = SERVFAIL/本地判定码）。
    pub rcode: u8,
    /// 是否失败（全部上游无有效响应）。
    pub error: bool,
    /// SERVFAIL 结构化归因（仅失败时非空）。
    pub servfail_reason: Option<ServfailReason>,
    /// 实际应答的上游 id（事件「上游」列）。
    pub up_name: String,
    /// 命中的规则（`level="rule"` 事件的唯一来源）。
    pub rule: Option<RuleHit>,
    pub latency: f64,
    /// 失败原因（事件 `answer` 列展示）。
    pub reason: Option<String>,
}

impl Resolver {
    /// 未知 qtype 透传解析入口（**不写缓存、不读缓存、不做负缓存**）。
    ///
    /// 与 [`Resolver::resolve`] 的关系：复用同一套"规则优先 + 上游选择 + 熔断"
    /// 语义，但**不进入** `finish_resolve`（quorum/CNAME 链/候选去重/回填缓存
    /// 全部不适用 —— 我们对未知类型没有解析语义）。
    pub async fn resolve_passthrough(
        self: Arc<Self>,
        domain: &str,
        qtype: u16,
    ) -> PassthroughResult {
        let t0 = self.clock.monotonic_ms();
        let d = normalize(domain);
        let lat = || self.clock.monotonic_ms() - t0;

        if d.is_empty() {
            return PassthroughResult {
                domain: d,
                qtype,
                rcode: ebpdns_proto::constants::RCODE_FORMERR,
                error: true,
                reason: Some("empty-domain".to_string()),
                latency: lat(),
                ..Default::default()
            };
        }

        // ---- 规则优先（与 `resolve_inner` 的 block/allow/group/forceIp 语义一致）----
        let mut rule_hit: Option<RuleHit> = None;
        let matched = self.match_rule(&d);
        if let Some(r) = &matched {
            if r.action == Action::Allow {
                self.tel.inc_rule_kind(
                    ebpdns_rules::match_kind(&r.match_raw),
                    ebpdns_rules::action_key(r),
                );
                rule_hit = Some(RuleHit {
                    label: ebpdns_rules::rule_label(r),
                    msg: "白名单放行 → 正常解析".to_string(),
                    answer: String::new(),
                    upstream: "白名单".to_string(),
                });
            }
        }
        let rule: Option<Rule> = match matched {
            Some(r) if r.action == Action::Allow => None,
            other => other,
        };
        if let Some(r) = &rule {
            match r.action {
                Action::Block => {
                    self.tel.inc_rule_kind(
                        ebpdns_rules::match_kind(&r.match_raw),
                        ebpdns_rules::action_key(r),
                    );
                    return PassthroughResult {
                        domain: d,
                        qtype,
                        rcode: ebpdns_proto::constants::RCODE_NXDOMAIN,
                        rule: Some(RuleHit {
                            label: ebpdns_rules::rule_label(r),
                            msg: "规则屏蔽 → NXDOMAIN".to_string(),
                            answer: String::new(),
                            upstream: "规则屏蔽".to_string(),
                        }),
                        latency: lat(),
                        ..Default::default()
                    };
                }
                Action::ForceIp => {
                    // 未知 qtype 与 forceIp 的 IP 类型（A/AAAA）必然不匹配 ——
                    // 与 `synthesize_forceip` 的"类型不匹配 → NODATA"同口径，
                    // **不**把 IP 硬塞进未知类型的 rdata。
                    self.tel.inc_rule_kind(
                        ebpdns_rules::match_kind(&r.match_raw),
                        ebpdns_rules::action_key(r),
                    );
                    return PassthroughResult {
                        domain: d,
                        qtype,
                        rcode: ebpdns_proto::constants::RCODE_NOERROR,
                        rule: Some(RuleHit {
                            label: ebpdns_rules::rule_label(r),
                            msg: "forceIp 类型不匹配 → NODATA".to_string(),
                            answer: String::new(),
                            upstream: "分流规则".to_string(),
                        }),
                        latency: lat(),
                        ..Default::default()
                    };
                }
                Action::Allow | Action::Group => {}
            }
        }

        // ---- 上游选择（与 resolve 同源：启用过滤 + 分组 + eff_lat 排序/熔断）----
        let all_up: Vec<UpstreamCfg> = self
            .cfg
            .read()
            .upstreams
            .iter()
            .filter(|u| u.enabled)
            .cloned()
            .collect();
        let mut ups = all_up.clone();
        if let Some(r) = &rule {
            if r.action == Action::Group {
                self.tel.inc_rule_kind(
                    ebpdns_rules::match_kind(&r.match_raw),
                    ebpdns_rules::action_key(r),
                );
                let g_disp = r.group.as_deref().unwrap_or("global");
                rule_hit = Some(RuleHit {
                    label: ebpdns_rules::rule_label(r),
                    msg: format!("分流规则 → 「{g_disp}」组"),
                    answer: String::new(),
                    upstream: "分流规则".to_string(),
                });
                if let Some(g) = &r.group {
                    let filtered: Vec<UpstreamCfg> = all_up
                        .iter()
                        .filter(|u| u.group.as_deref() == Some(g.as_str()))
                        .cloned()
                        .collect();
                    if !filtered.is_empty() {
                        ups = filtered;
                    }
                }
            }
        }
        if ups.is_empty() {
            return self.passthrough_fail(
                d,
                qtype,
                rule_hit,
                lat(),
                ServfailReason::NoUpstream,
                String::new(),
            );
        }
        let (primary, backup) = self.select_upstreams(&ups);
        if primary.is_empty() {
            return self.passthrough_fail(
                d,
                qtype,
                rule_hit,
                lat(),
                ServfailReason::NoUpstream,
                String::new(),
            );
        }

        // ---- 上游扇出（`query_parallel_raw` = 生产实现里与受理类型**同一条**路径）----
        let querier = self.querier.read().clone();
        let mut results = querier.query_parallel_raw(&primary, &d, qtype, 0).await;
        // fallback：首选波全部无有效响应（无 rcode）→ 回退剩余上游重查一轮。
        if !backup.is_empty() && results.iter().all(|r| r.rcode.is_none()) {
            let more = querier.query_parallel_raw(&backup, &d, qtype, 0).await;
            results.extend(more);
        }

        // 熔断账 + DNS 业务账（与 `finish_resolve` / `record_dns_verdicts` 同口径）。
        for r in &results {
            if r.up_name.is_empty() {
                continue;
            }
            let ok = matches!(
                r.rcode,
                Some(ebpdns_proto::constants::RCODE_NOERROR)
                    | Some(ebpdns_proto::constants::RCODE_NXDOMAIN)
            );
            if ok {
                self.cb_ok(&r.up_name);
            } else {
                self.cb_fail(&r.up_name);
            }
        }
        if let Some(rt) = self.upstream_runtime() {
            for r in &results {
                if r.up_name.is_empty() {
                    continue;
                }
                let ok = matches!(
                    r.rcode,
                    Some(ebpdns_proto::constants::RCODE_NOERROR)
                        | Some(ebpdns_proto::constants::RCODE_NXDOMAIN)
                ) && !r.udp_truncated;
                rt.health.stats(&r.up_name).record_dns_verdict(ok);
            }
        }

        // 取**第一条**有效上游响应（不表决、不合并 —— 原样回传）。
        if let Some(r) = results
            .iter()
            .find(|r| r.rcode.is_some() && r.raw.as_ref().is_some_and(|b| b.len() >= 12))
        {
            return PassthroughResult {
                domain: d,
                qtype,
                resp: r.raw.clone(),
                rcode: r.rcode.unwrap_or(ebpdns_proto::constants::RCODE_NOERROR),
                up_name: r.up_name.clone(),
                rule: rule_hit,
                latency: lat(),
                ..Default::default()
            };
        }

        // 全部失败：区分"全部超时/无应答"与"有应答但无可用报文"。
        let all_timeout = results.iter().all(|r| r.rcode.is_none());
        let reason = if all_timeout {
            ServfailReason::UpstreamTimeout
        } else {
            ServfailReason::UpstreamNoAnswer
        };
        let up_name = results
            .iter()
            .find(|r| !r.up_name.is_empty())
            .map(|r| r.up_name.clone())
            .unwrap_or_default();
        self.passthrough_fail(d, qtype, rule_hit, lat(), reason, up_name)
    }

    /// 透传失败结果（SERVFAIL + 结构化原因；`up_name` 保留首个有名字的上游便于排障）。
    fn passthrough_fail(
        &self,
        domain: String,
        qtype: u16,
        rule: Option<RuleHit>,
        latency: f64,
        reason: ServfailReason,
        up_name: String,
    ) -> PassthroughResult {
        PassthroughResult {
            domain,
            qtype,
            rcode: ebpdns_proto::constants::RCODE_SERVFAIL,
            error: true,
            servfail_reason: Some(reason),
            up_name,
            rule,
            latency,
            reason: Some(reason.as_str().to_string()),
            ..Default::default()
        }
    }
}
