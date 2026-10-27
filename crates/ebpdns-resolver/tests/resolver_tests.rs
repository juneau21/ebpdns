//! 移植自 `review161/tests/test_resolver.py` 的行为向量。
//! 全部确定性：脚本化上游、mock 时钟，不联网/不起服。

use ebpdns_cache::DnsCache;
use std::sync::Arc;

use ebpdns_proto::constants::{RCODE_NOERROR, RCODE_NXDOMAIN, RCODE_SERVFAIL, TYPE_A, TYPE_CNAME};
use ebpdns_resolver::clock::MockClock;
use ebpdns_resolver::config::{ResolverConfig, UpstreamCfg};
use ebpdns_resolver::query::ScriptedQuerier;
use ebpdns_resolver::resolve::ResolveOpts;
use ebpdns_resolver::telemetry::NoopTelemetry;
use ebpdns_resolver::types::{ResolveAnswer, UpstreamAnswer};
use ebpdns_resolver::Resolver;
use ebpdns_rules::{rule_from_json, RuleSource};
use serde_json::json;

/// **[历史归因]** 构造一条规则（对齐 Python `{"match": ..., "action": ..., "ip": ...}`）。
fn rule(m: &str, action: &str, ip: Option<&str>) -> ebpdns_rules::Rule {
    let mut obj = serde_json::Map::new();
    obj.insert("match".into(), json!(m));
    obj.insert("action".into(), json!(action));
    if let Some(ip) = ip {
        obj.insert("ip".into(), json!(ip));
    }
    rule_from_json(obj, RuleSource::Local).expect("rule should build")
}

/// 测试基座：两个上游 u1/u2，Lru 缓存，quorum 可配。
fn base(rules: Vec<ebpdns_rules::Rule>, quorum: usize) -> Arc<Resolver> {
    let ups = vec![UpstreamCfg::test_up("u1"), UpstreamCfg::test_up("u2")];
    let cfg = ResolverConfig::test_default(ups, rules, quorum);
    Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(1_700_000_000.0)),
        Arc::new(ScriptedQuerier::new(|_, _, _| Vec::new())),
    )
}

fn a(value: &str, ttl: f64) -> ResolveAnswer {
    ResolveAnswer::new(value, ttl, TYPE_A)
}

#[tokio::test]
async fn test_block_rule_returns_nxdomain() {
    let r = base(vec![rule("blocked.test", "block", None)], 2);
    let res = r
        .clone()
        .resolve("blocked.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_NXDOMAIN);
}

#[tokio::test]
async fn test_force_ip_synthesizes() {
    let r = base(vec![rule("forced.test", "forceIp", Some("9.9.9.9"))], 2);
    let res = r
        .clone()
        .resolve("forced.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_NOERROR);
    assert_eq!(res.answers.len(), 1);
    assert_eq!(res.answers[0].value, "9.9.9.9");
    assert_eq!(res.answers[0].rtype, TYPE_A);
}

#[tokio::test]
async fn test_force_ip_type_mismatch_is_nodata() {
    let r = base(vec![rule("forced.test", "forceIp", Some("9.9.9.9"))], 2);
    // forceIp 9.9.9.9 是 A，但查 AAAA → NODATA。
    let res = r
        .clone()
        .resolve("forced.test", "AAAA", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_NOERROR);
    assert!(res.empty);
}

// ---------- NXDOMAIN quorum ----------

fn nx(up: &str) -> UpstreamAnswer {
    UpstreamAnswer {
        rcode: Some(RCODE_NXDOMAIN),
        up_name: up.into(),
        ..Default::default()
    }
}
fn fail(up: &str) -> UpstreamAnswer {
    UpstreamAnswer::fail(up)
}
fn nodata(up: &str) -> UpstreamAnswer {
    UpstreamAnswer {
        rcode: Some(0),
        up_name: up.into(),
        ..Default::default()
    }
}
fn trunc(up: &str) -> UpstreamAnswer {
    UpstreamAnswer {
        rcode: Some(0),
        up_name: up.into(),
        udp_truncated: true,
        ..Default::default()
    }
}

#[tokio::test]
async fn test_nxdomain_quorum_confirmed() {
    let r = base(vec![], 2);
    r.set_querier(Arc::new(ScriptedQuerier::new(move |_, _, _| {
        vec![nx("u1"), nx("u2")]
    })));
    let res = r
        .clone()
        .resolve("nx.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_NXDOMAIN);
    assert!(!res.error);
    // 缺陷 P0：事件 `upstream` 列必须是**单一**获胜上游，而不是候选列表（旧实现
    // `up_names_display` 会写出 "u1 / u2"）。
    assert_eq!(res.up_name, "u1");
}

/// **2.1.42（P0-1，替换旧断言）**：1×NXDOMAIN + 1×无票（超时/`no-answer`）只有
/// 1 张负票，quorum=2 时**不得**采纳 NXDOMAIN ⇒ SERVFAIL，且不写负缓存。
#[tokio::test]
async fn test_nxdomain_minority_servfail() {
    let r = base(vec![], 2);
    r.set_querier(Arc::new(ScriptedQuerier::new(move |_, _, _| {
        vec![nx("u1"), fail("u2")]
    })));
    let res = r
        .clone()
        .resolve("nx.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(
        res.rcode, RCODE_SERVFAIL,
        "1/2 票不足 quorum，必须 SERVFAIL"
    );
    assert!(res.error);
    assert!(!res.up_name.contains(" / "));
}

/// **2.1.45（P1-1，替换 2.1.42 的"钳制"断言）**：`quorum=2` 且只有 1 个可用上游 ⇒
/// **永不** NXDOMAIN（SERVFAIL），且不写负缓存、不登记 RFC 8020。
///
/// 旧断言把"单候选塌缩到 1 票即确认"当成设计取舍；REV247 P1-3 指出它违反
/// `quorum=N` 的验收原文（一张负票即可写负缓存并经 RFC 8020 放大整棵子树）。
/// 现在语义是 fail-closed：可用上游少于 quorum 时，部署必须显式配 `nxdomain_quorum=1`。
#[tokio::test]
async fn test_single_upstream_quorum_unreachable_servfail() {
    let ups = vec![UpstreamCfg::test_up("u1")];
    let mut cfg = ResolverConfig::test_default(ups, vec![], 2);
    cfg.max_parallel_upstreams = 1;
    cfg.rfc8020_infer = true;
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(1_700_000_000.0)),
        Arc::new(ScriptedQuerier::new(|_, _, _| vec![nx("u1")])),
    );
    let res = r
        .clone()
        .resolve("nx.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(
        res.rcode, RCODE_SERVFAIL,
        "可用上游 1 < quorum 2 ⇒ SERVFAIL（不得少票确认 NXDOMAIN）"
    );
    let ck = r.ckey_normalized("nx.test", "A");
    assert!(
        r.cache().get(&ck, 1_700_000_000.0).is_none(),
        "quorum 不可达 ⇒ 不得写负缓存"
    );
    assert_eq!(
        r.rfc8020_registrations(),
        0,
        "quorum 不可达 ⇒ 不得登记 RFC 8020"
    );
}

// ---------- NODATA quorum ----------

#[tokio::test]
async fn test_nodata_confirmed() {
    let r = base(vec![], 2);
    r.set_querier(Arc::new(ScriptedQuerier::new(move |_, _, _| {
        vec![nodata("u1"), nodata("u2")]
    })));
    let res = r
        .clone()
        .resolve("nd.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_NOERROR);
    assert!(res.empty);
    // NODATA quorum：事件 `upstream` 列写单一获胜上游（旧实现 "u1 / u2"）。
    assert_eq!(res.up_name, "u1");
}

/// **2.1.42（P0-1，替换旧断言）**：1×NODATA + 1×无票 ⇒ 1/2 票不足 quorum ⇒ SERVFAIL。
#[tokio::test]
async fn test_nodata_minority_not_trusted() {
    let r = base(vec![], 2);
    r.set_querier(Arc::new(ScriptedQuerier::new(move |_, _, _| {
        vec![nodata("u1"), fail("u2")]
    })));
    let res = r
        .clone()
        .resolve("nd.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_SERVFAIL, "1/2 票不足 quorum ⇒ SERVFAIL");
    assert!(res.error);
}

#[tokio::test]
async fn test_truncated_not_counted_as_nodata() {
    let r = base(vec![], 2);
    r.set_querier(Arc::new(ScriptedQuerier::new(move |_, _, _| {
        vec![trunc("u1"), trunc("u2")]
    })));
    let res = r
        .clone()
        .resolve("trunc.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_SERVFAIL);
    // 不写负缓存。
    let key = r.ckey("trunc.test", "A");
    assert!(r.cache().get(&key, 1_700_000_000.0).is_none());
}

/// M1 截断沿用（TC 直答）：事件 `upstream` 列同样只写**一个**获胜上游，
/// 不再是候选列表（旧实现 `up_names_display` 会写 "u1 / u2"）。
#[tokio::test]
async fn test_truncated_kept_answers_single_winner_up_name() {
    let r = base(vec![], 2);
    r.set_querier(Arc::new(ScriptedQuerier::new(move |_, _, _| {
        vec![
            UpstreamAnswer {
                rcode: Some(0),
                up_name: "u1".into(),
                udp_truncated: true,
                answers: vec![a("1.2.3.4", 60.0)],
                ..Default::default()
            },
            UpstreamAnswer {
                rcode: Some(0),
                up_name: "u2".into(),
                udp_truncated: true,
                answers: vec![a("5.6.7.8", 60.0)],
                ..Default::default()
            },
        ]
    })));
    let res = r
        .clone()
        .resolve("tc.test", "A", ResolveOpts::default())
        .await;
    assert!(res.truncated, "TC 沿用应答 → truncated=true");
    assert_eq!(res.up_name, "u1", "TC 沿用路径只写单一获胜上游");
}

#[tokio::test]
async fn test_cname_only_not_counted_as_nodata() {
    // 两个上游都只回 CNAME 链头（无答案），目标自身也只回 CNAME → depth 耗尽 → SERVFAIL。
    let r = base(vec![], 2);
    r.set_querier(Arc::new(ScriptedQuerier::new(move |_, _, _| {
        vec![
            UpstreamAnswer {
                rcode: Some(0),
                up_name: "u1".into(),
                cnames: vec![("cdn.test".into(), 300)],
                ..Default::default()
            },
            UpstreamAnswer {
                rcode: Some(0),
                up_name: "u2".into(),
                cnames: vec![("cdn.test".into(), 300)],
                ..Default::default()
            },
        ]
    })));
    let res = r
        .clone()
        .resolve("deep.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_SERVFAIL);
    assert!(res.error);
}

#[tokio::test]
async fn test_real_nodata_writes_negative_cache() {
    let r = base(vec![], 2);
    r.set_querier(Arc::new(ScriptedQuerier::new(move |_, _, _| {
        vec![nodata("u1"), nodata("u2")]
    })));
    let res = r
        .clone()
        .resolve("nd.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_NOERROR);
    let key = r.ckey("nd.test", "A");
    let e = r
        .cache()
        .get(&key, 1_700_000_000.0)
        .expect("negative cached");
    assert_eq!(e.rcode, 0);
    assert!(e.answers.is_empty());
    // 第二次命中缓存。
    let res2 = r
        .clone()
        .resolve("nd.test", "A", ResolveOpts::default())
        .await;
    assert!(res2.hit);
    assert!(res2.empty);
}

// ---------- CNAME 链 ----------

#[tokio::test]
async fn test_cname_chain_a_owner_is_target() {
    let r = base(vec![], 1);
    r.set_querier(Arc::new(ScriptedQuerier::new(move |d, _, _| {
        if d == "cname.test" {
            vec![UpstreamAnswer {
                rcode: Some(0),
                // CNAME 记录来自 u2（慢/备选上游）。
                up_name: "u2".into(),
                cnames: vec![("cdn.test".into(), 300)],
                answers: vec![],
                ..Default::default()
            }]
        } else if d == "cdn.test" {
            vec![UpstreamAnswer::ok(
                "u1",
                0,
                vec![a("1.2.3.4", 300.0)],
                vec![],
            )]
        } else {
            vec![UpstreamAnswer::fail("u1")]
        }
    })));
    let res = r
        .clone()
        .resolve("cname.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_NOERROR);
    assert_eq!(res.answers.len(), 2);
    assert_eq!(res.answers[0].rtype, TYPE_CNAME);
    assert!(res.answers[0].name.is_none());
    assert_eq!(res.answers[1].rtype, TYPE_A);
    assert_eq!(res.answers[1].name.as_deref(), Some("cdn.test"));
    // 事件 `upstream` 列：CNAME 链上报**真正给出链尾 A 记录**的上游（u1），
    // 而不是 CNAME 提供者 u2，也不是候选列表。
    assert_eq!(res.up_name, "u1");
}

#[tokio::test]
async fn test_cname_to_nodata_returns_nodata_not_servfail() {
    let r = base(vec![], 2);
    r.set_querier(Arc::new(ScriptedQuerier::new(move |d, _, _| {
        if d == "parent.test" {
            vec![
                UpstreamAnswer {
                    rcode: Some(0),
                    up_name: "u1".into(),
                    cnames: vec![("nodata-target.test".into(), 300)],
                    ..Default::default()
                },
                UpstreamAnswer {
                    rcode: Some(0),
                    up_name: "u2".into(),
                    cnames: vec![("nodata-target.test".into(), 300)],
                    ..Default::default()
                },
            ]
        } else {
            vec![nodata("u1"), nodata("u2")]
        }
    })));
    let res = r
        .clone()
        .resolve("parent.test", "AAAA", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_NOERROR);
    assert!(res.empty);
    // 第二次命中负缓存。
    let res2 = r
        .clone()
        .resolve("parent.test", "AAAA", ResolveOpts::default())
        .await;
    assert!(res2.hit);
    assert!(res2.empty);
}

// ---------- gen 写回门禁 ----------

// ---------- 熔断 ----------

#[tokio::test]
async fn test_circuit_breaker_opens_after_threshold() {
    let r = base(vec![], 2);
    r.cb_fail("u1");
    r.cb_fail("u1");
    assert!(!r.cb_is_open("u1"), "2 次失败未达阈值 3");
    r.cb_fail("u1");
    assert!(r.cb_is_open("u1"), "3 次失败 → 打开");
    r.cb_ok("u1");
    assert!(!r.cb_is_open("u1"), "成功复位");
}

#[tokio::test]
async fn test_reload_prunes_dead_upstream_cb() {
    let r = base(vec![], 2);
    r.cb_inject("gone", 99, 9_999_999.0);
    r.cb_inject("u1", 1, 0.0);
    // reload：只保留 u1。
    let mut cfg = r.config().clone();
    cfg.upstreams = vec![UpstreamCfg::test_up("u1")];
    r.reload(cfg);
    assert!(r.cb_get("gone").is_none(), "已删除上游的熔断条目清理");
    assert!(r.cb_get("u1").is_some(), "存活上游熔断条目保留");
}

#[tokio::test]
async fn test_reset_clears_cache_and_breaker() {
    let r = base(vec![], 2);
    r.set_querier(Arc::new(ScriptedQuerier::new(move |_, _, _| {
        vec![UpstreamAnswer::ok(
            "u1",
            0,
            vec![a("1.2.3.4", 300.0)],
            vec![],
        )]
    })));
    r.clone()
        .resolve("reset.test", "A", ResolveOpts::default())
        .await;
    assert!(r
        .cache()
        .get(&r.ckey("reset.test", "A"), 1_700_000_000.0)
        .is_some());
    r.cb_inject("u1", 5, 9_999.0);
    r.reset_runtime_state();
    assert!(r
        .cache()
        .get(&r.ckey("reset.test", "A"), 1_700_000_000.0)
        .is_none());
    assert!(r.cb_get("u1").is_none());
}

// ---------- 预取队列 ----------

#[tokio::test]
async fn test_prefetch_ordering_move_to_end() {
    let ups = vec![UpstreamCfg::test_up("u1")];
    let mut cfg = ResolverConfig::test_default(ups, vec![], 2);
    cfg.prefetch = true;
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(1_700_000_000.0)),
        Arc::new(ScriptedQuerier::new(|_, _, _| Vec::new())),
    );
    r.schedule_prefetch("a.test", "A", 0.0);
    r.schedule_prefetch("b.test", "A", 0.0);
    r.schedule_prefetch("c.test", "A", 0.0);
    assert_eq!(r.prefetch_order(), vec!["a.test|A", "b.test|A", "c.test|A"]);
    // reschedule a → 移到末尾。
    r.schedule_prefetch("a.test", "A", 0.0);
    assert_eq!(r.prefetch_order(), vec!["b.test|A", "c.test|A", "a.test|A"]);
}

// ---------- answer_fast ----------

#[tokio::test]
async fn test_answer_fast_second_hit_no_crash() {
    let r = base(vec![], 2);
    let key = r.ckey("second-hit.test", "A");
    r.fill_cache(
        &key,
        "second-hit.test",
        "A",
        vec![a("1.2.3.4", 300.0), a("1.2.3.5", 300.0)],
        None,
    );
    let (raw, _) =
        ebpdns_proto::query::build_query("second-hit.test", TYPE_A, None, false, None, None, false)
            .unwrap();
    let resp = r.answer_fast(&raw).expect("cache hit → response");
    assert!(!resp.is_empty());
    let resp2 = r.answer_fast(&raw).expect("second hit still ok");
    assert_eq!(resp.len(), resp2.len());
}

// ---------- prefer_ipv4 双栈探测 gen 门禁 ----------

#[tokio::test]
async fn test_prefer_ipv4_probe_gen_gate() {
    let mut cfg = ResolverConfig::test_default(
        vec![UpstreamCfg::test_up("u1"), UpstreamCfg::test_up("u2")],
        vec![],
        2,
    );
    cfg.prefer_ipv4 = true;
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(1_700_000_000.0)),
        Arc::new(ScriptedQuerier::new(|_, _, _| Vec::new())),
    );
    let r2 = r.clone();
    r.set_querier(Arc::new(ScriptedQuerier::new(move |_, qt, _| {
        if qt == "A" {
            r2.test_bump_gen(); // 探测 RTT 期间规则重建
            vec![UpstreamAnswer::ok(
                "u1",
                0,
                vec![a("9.9.9.9", 300.0)],
                vec![],
            )]
        } else {
            vec![nodata("u1"), nodata("u2")]
        }
    })));
    let res = r
        .clone()
        .resolve("ds.test", "AAAA", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_NOERROR);
    assert!(res.empty, "有 A → AAAA 屏蔽");
    assert!(
        r.cache()
            .get(&r.ckey("ds.test", "A"), 1_700_000_000.0)
            .is_some(),
        "A 缓存已预热"
    );
}

// ---------- 2.1.40：本地策略短路的显式 reason（指标口径） ----------

/// `ipv6=false`：AAAA 恒本地 NODATA —— 必须带 `reason="policy_filtered"`，
/// 且**绝不发上游**（2.1.39 及以前 reason=None ⇒ 数据面记 miss，拉低 hit_rate）。
#[tokio::test]
async fn test_ipv6_off_aaaa_reason_is_policy_filtered() {
    let mut cfg = ResolverConfig::test_default(
        vec![UpstreamCfg::test_up("u1"), UpstreamCfg::test_up("u2")],
        vec![],
        2,
    );
    cfg.ipv6 = false;
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(1_700_000_000.0)),
        Arc::new(ScriptedQuerier::new(|_, _, _| {
            panic!("ipv6=false 的 AAAA 不得发上游")
        })),
    );
    let res = r
        .clone()
        .resolve("ds.test", "AAAA", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_NOERROR);
    assert!(res.empty, "ipv6=false → AAAA 本地 NODATA");
    assert!(!res.hit, "本地策略应答不是缓存命中");
    assert_eq!(
        res.reason.as_deref(),
        Some(ebpdns_resolver::types::REASON_POLICY_FILTERED),
        "必须显式标记策略原因（否则数据面会记成 miss/Upstream）"
    );
}

/// `prefer_ipv4=true` 且域名有 A：AAAA 被本地屏蔽 —— 同样必须带
/// `reason="policy_filtered"`，且**只发 A 探测、不发 AAAA 上游**。
#[tokio::test]
async fn test_prefer_ipv4_aaaa_reason_is_policy_filtered() {
    let mut cfg = ResolverConfig::test_default(
        vec![UpstreamCfg::test_up("u1"), UpstreamCfg::test_up("u2")],
        vec![],
        2,
    );
    cfg.prefer_ipv4 = true;
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let c2 = calls.clone();
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(1_700_000_000.0)),
        Arc::new(ScriptedQuerier::new(move |_, qt, _| {
            c2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if qt == "A" {
                vec![UpstreamAnswer::ok(
                    "u1",
                    0,
                    vec![a("9.9.9.9", 300.0)],
                    vec![],
                )]
            } else {
                vec![nodata("u1"), nodata("u2")]
            }
        })),
    );
    let res = r
        .clone()
        .resolve("ds.test", "AAAA", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_NOERROR);
    assert!(res.empty, "有 A → AAAA 屏蔽");
    assert!(!res.hit);
    assert_eq!(
        res.reason.as_deref(),
        Some(ebpdns_resolver::types::REASON_POLICY_FILTERED),
        "必须显式标记策略原因"
    );
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "只允许 A 探测那一次上游；AAAA 本身不得出站"
    );
}
