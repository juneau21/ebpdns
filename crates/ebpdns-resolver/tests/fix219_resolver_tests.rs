//! 2.1.9 解析器/缓存侧修复与优化的确定性回归测试。
//!
//! 覆盖：
//! - **P1-B** quorum 分母 = 候选数（单票 NXDOMAIN/NODATA 不得确认）；
//! - **P1-2** 负缓存 TTL 硬上限 `neg_ttl_max`（无 SOA / 超大 SOA 都被夹取）；
//! - **P1-1** 规则集指纹变化 → 旧答案缓存立即失效（规则 CRUD 后无需 `/api/reset`）；
//! - **P2-B** 预取（单上游）不得写负缓存；
//! - 全部确定性：脚本化上游 + mock 时钟，不联网/不起服/不加载内核态缓存。

use std::sync::Arc;

use ebpdns_cache::DnsCache;
use ebpdns_proto::constants::{RCODE_NOERROR, RCODE_NXDOMAIN, RCODE_SERVFAIL, TYPE_A};
use ebpdns_resolver::clock::MockClock;
use ebpdns_resolver::config::{ResolverConfig, UpstreamCfg};
use ebpdns_resolver::query::ScriptedQuerier;
use ebpdns_resolver::resolve::ResolveOpts;
use ebpdns_resolver::telemetry::NoopTelemetry;
use ebpdns_resolver::types::{ResolveAnswer, UpstreamAnswer};
use ebpdns_resolver::Resolver;
use ebpdns_rules::{rule_from_json, RuleSource};
use serde_json::json;

const EPOCH: f64 = 1_700_000_000.0;

fn a(value: &str, ttl: f64) -> ResolveAnswer {
    ResolveAnswer::new(value, ttl, TYPE_A)
}

/// NXDOMAIN 应答（可带 SOA minimum → `neg_ttl`）。
fn nx(up: &str, neg_ttl: Option<u32>) -> UpstreamAnswer {
    UpstreamAnswer {
        rcode: Some(RCODE_NXDOMAIN),
        up_name: up.into(),
        neg_ttl,
        ..Default::default()
    }
}

/// NOERROR 无答案（NODATA）。
fn nodata(up: &str, neg_ttl: Option<u32>) -> UpstreamAnswer {
    UpstreamAnswer {
        rcode: Some(RCODE_NOERROR),
        up_name: up.into(),
        neg_ttl,
        ..Default::default()
    }
}

/// 传输失败（rcode=None，模拟超时/被 abort 掉的那一票）。
fn fail(up: &str) -> UpstreamAnswer {
    UpstreamAnswer {
        rcode: None,
        up_name: up.into(),
        ..Default::default()
    }
}

fn rule(m: &str, action: &str) -> ebpdns_rules::Rule {
    let mut obj = serde_json::Map::new();
    obj.insert("match".into(), json!(m));
    obj.insert("action".into(), json!(action));
    rule_from_json(obj, RuleSource::Local).expect("rule")
}

/// 测试基座：2 个上游 u1/u2，quorum 可配，脚本化应答。
fn base<F>(quorum: usize, handler: F) -> Arc<Resolver>
where
    F: Fn(&str, &str, u32) -> Vec<UpstreamAnswer> + Send + Sync + 'static,
{
    let ups = vec![UpstreamCfg::test_up("u1"), UpstreamCfg::test_up("u2")];
    let cfg = ResolverConfig::test_default(ups, vec![], quorum);
    Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(EPOCH)),
        Arc::new(ScriptedQuerier::new(handler)),
    )
}

/// 负缓存条目（若存在）。
fn neg_entry(r: &Resolver, domain: &str) -> Option<ebpdns_cache::CacheEntry> {
    r.cache().get(&r.ckey(domain, "A"), EPOCH + 0.5)
}

/* ==================== P1-B：quorum 分母 = 候选数 ==================== */

/// **2.1.42（P0-1，替换旧断言）**：quorum=2 时 1×NXDOMAIN + 1×no-answer 只有
/// 1 张负票 ⇒ **不得**采纳 NXDOMAIN；诚实结论是 SERVFAIL，且不写负缓存。
#[tokio::test]
async fn p1b_single_nxdomain_plus_no_answer_is_not_enough_quorum() {
    let r = base(2, |_, _, _| vec![nx("u1", None), fail("u2")]);
    let res = r
        .clone()
        .resolve("p1b-noanswer.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(
        res.rcode, RCODE_SERVFAIL,
        "1×NXDOMAIN + 1×no-answer 只凑到 1/2 票 ⇒ SERVFAIL，实际 {}",
        res.rcode
    );
    assert!(res.error, "未确认的负结论必须记为错误");
    assert!(
        neg_entry(&r, "p1b-noanswer.test").is_none(),
        "未达 quorum 不得写负缓存"
    );
}

/// **2.1.42（P0-1，替换旧断言）**：3 个候选、1×NXDOMAIN + 2×no-answer 同样
/// 只有 1/2 票 ⇒ SERVFAIL，不写负缓存。
#[tokio::test]
async fn p1b_single_nxdomain_plus_two_no_answer_is_not_enough_quorum() {
    let ups = vec![
        UpstreamCfg::test_up("u1"),
        UpstreamCfg::test_up("u2"),
        UpstreamCfg::test_up("u3"),
    ];
    let cfg = ResolverConfig::test_default(ups, vec![], 2);
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(EPOCH)),
        Arc::new(ScriptedQuerier::new(|_, _, _| {
            vec![nx("u1", None), fail("u2"), fail("u3")]
        })),
    );
    let res = r
        .clone()
        .resolve("p1b-noanswer3.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(
        res.rcode, RCODE_SERVFAIL,
        "1×NXDOMAIN + 2×no-answer 只凑到 1/2 票 ⇒ SERVFAIL"
    );
    assert!(neg_entry(&r, "p1b-noanswer3.test").is_none());
}

/// **2.1.42（P0-1，替换旧断言）**：SERVFAIL/REFUSED 应答是**无票**（不是反对票）；
/// 在只有 1 张 NXDOMAIN 票时不能把阈值降回 1 ⇒ SERVFAIL。
#[tokio::test]
async fn p1b_servfail_response_is_not_a_vote() {
    let r = base(2, |_, _, _| {
        vec![
            nx("u1", None),
            UpstreamAnswer {
                up_name: "u2".into(),
                rcode: Some(RCODE_SERVFAIL),
                ..Default::default()
            },
        ]
    });
    let res = r
        .clone()
        .resolve("p1b-servfail.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(
        res.rcode, RCODE_SERVFAIL,
        "SERVFAIL 是无票，不能把 1 张负票当成 quorum 达成"
    );
    assert!(neg_entry(&r, "p1b-servfail.test").is_none());
}

/// P1-B：对抗场景仍然成立 —— 单票 NXDOMAIN 遇到**矛盾的正向答案**时，正向答案获胜
/// （对齐 v1.9.162：只要有任何成功应答给出目标 A 记录，就不采纳负结论）。
#[tokio::test]
async fn p1b_nxdomain_with_contradicting_positive_is_not_confirmed() {
    let r = base(2, |_, _, _| {
        vec![
            nx("u1", None),
            UpstreamAnswer::ok("u2", 0, vec![a("1.2.3.4", 300.0)], vec![]),
        ]
    });
    let res = r
        .clone()
        .resolve("p1b-contradict.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(
        res.rcode, RCODE_NOERROR,
        "正向答案获胜（rcode={}）",
        res.rcode
    );
    assert_eq!(res.answers.len(), 1, "应返回上游给的 A 记录");
    assert_eq!(res.answers[0].value, "1.2.3.4");
    // 正向答案必须写正向缓存（不是负缓存）。
    let e = r
        .cache()
        .get(&r.ckey("p1b-contradict.test", "A"), EPOCH + 0.5)
        .expect("正向答案应写缓存");
    assert_eq!(e.rcode, RCODE_NOERROR);
    assert_eq!(e.answers.len(), 1, "缓存里必须是正向答案，不得是负缓存");
}

/// P1-B：全部 no-answer/超时 → 真失败（SERVFAIL），不写任何缓存。
#[tokio::test]
async fn p1b_all_no_answer_is_servfail() {
    let r = base(2, |_, _, _| vec![fail("u1"), fail("u2")]);
    let res = r
        .clone()
        .resolve("p1b-allfail.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_SERVFAIL);
    assert!(res.error);
    assert!(
        neg_entry(&r, "p1b-allfail.test").is_none(),
        "全失败不得写负缓存"
    );
}

/// **2.1.42（P0-1，替换旧断言）**：NODATA 单票 + 无票（quorum=2）同样不足 ⇒
/// SERVFAIL，不写负缓存（NODATA 与 NXDOMAIN 同口径）。
#[tokio::test]
async fn p1b_single_nodata_plus_no_answer_is_not_enough_quorum() {
    let r = base(2, |_, _, _| vec![nodata("u1", None), fail("u2")]);
    let res = r
        .clone()
        .resolve("p1b-ndnoanswer.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_SERVFAIL);
    assert!(res.error, "未确认的 NODATA 必须记为错误");
    assert!(
        neg_entry(&r, "p1b-ndnoanswer.test").is_none(),
        "未达 quorum 不得写负缓存"
    );
}

/// 回归（既有 quorum 语义）：两票一致 → 确认并写负缓存。
#[tokio::test]
async fn p1b_quorum_met_still_confirms_and_caches() {
    let r = base(2, |_, _, _| vec![nx("u1", None), nx("u2", None)]);
    let res = r
        .clone()
        .resolve("p1b-ok.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_NXDOMAIN);
    assert!(
        neg_entry(&r, "p1b-ok.test").is_some(),
        "两票 NXDOMAIN 应写负缓存"
    );
}

/// **2.1.45（P1-1）**：单上游 + `quorum=2` ⇒ quorum **不可达** ⇒ SERVFAIL，
/// 且不写负缓存（2.1.42/2.1.44 的"钳到 1 票即确认"已在 2.1.45 撤销）。
#[tokio::test]
async fn p1b_single_candidate_quorum_unreachable_servfail() {
    let ups = vec![UpstreamCfg::test_up("u1")];
    let mut cfg = ResolverConfig::test_default(ups, vec![], 2);
    cfg.rfc8020_infer = true;
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(EPOCH)),
        Arc::new(ScriptedQuerier::new(|_, _, _| vec![nx("u1", None)])),
    );
    let res = r
        .clone()
        .resolve("p1b-one.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(
        res.rcode, RCODE_SERVFAIL,
        "可用上游 1 < quorum 2 ⇒ SERVFAIL（不得少票确认）"
    );
    assert!(
        neg_entry(&r, "p1b-one.test").is_none(),
        "quorum 不可达时不得写负缓存"
    );
    assert_eq!(r.rfc8020_registrations(), 0, "不得登记 RFC 8020");
}

/* ==================== P1-2：负缓存 TTL 硬上限 ==================== */

/// P1-2：上游 NXDOMAIN **不带 SOA**（`neg_ttl=None`）→ 负缓存 TTL 必须是
/// `min(ttl, 60)` 并被 `neg_ttl_max` 夹取（默认 60），而不是 86400 之类的量级。
#[tokio::test]
async fn p1_2_no_soa_negative_ttl_is_capped_at_60() {
    let r = base(2, |_, _, _| vec![nx("u1", None), nx("u2", None)]);
    let res = r
        .clone()
        .resolve("p12-nosoa.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_NXDOMAIN);
    assert!(
        (res.ttl_left - 60.0).abs() < 1e-6,
        "无 SOA 的 NXDOMAIN 负缓存 TTL 应为 min(ttl,60)=60，实际 {}",
        res.ttl_left
    );
    let e = neg_entry(&r, "p12-nosoa.test").expect("负缓存已写");
    assert!(
        e.expires_at - EPOCH <= 60.5,
        "缓存条目过期时间不得超过 60s，实际 {}",
        e.expires_at - EPOCH
    );
}

/// P1-2：上游返回**超大 SOA**（86400）→ 必须被 `neg_ttl_max` 夹到 60。
#[tokio::test]
async fn p1_2_huge_soa_negative_ttl_is_capped() {
    let r = base(2, |_, _, _| {
        vec![nx("u1", Some(86_400)), nx("u2", Some(86_400))]
    });
    let res = r
        .clone()
        .resolve("p12-huge.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_NXDOMAIN);
    assert!(
        (res.ttl_left - 60.0).abs() < 1e-6,
        "86400 的 SOA minimum 必须被 neg_ttl_max(60) 夹取，实际 {}",
        res.ttl_left
    );
    let e = neg_entry(&r, "p12-huge.test").expect("负缓存已写");
    assert!(e.ttl <= 60.0, "条目 ttl={} 超过上限", e.ttl);
}

/// P1-2：SOA 给的小值（10s）不被抬到上限，仍按最小值生效。
#[tokio::test]
async fn p1_2_small_soa_is_respected() {
    let r = base(2, |_, _, _| vec![nx("u1", Some(10)), nx("u2", Some(30))]);
    let res = r
        .clone()
        .resolve("p12-small.test", "A", ResolveOpts::default())
        .await;
    assert!(
        (res.ttl_left - 10.0).abs() < 1e-6,
        "应取最小 SOA minimum=10，实际 {}",
        res.ttl_left
    );
}

/// P1-2：`neg_ttl_max=0` 表示关闭该上限（显式配置语义），此时回落到旧口径。
#[tokio::test]
async fn p1_2_neg_ttl_max_zero_disables_cap() {
    let ups = vec![UpstreamCfg::test_up("u1"), UpstreamCfg::test_up("u2")];
    let mut cfg = ResolverConfig::test_default(ups, vec![], 2);
    cfg.neg_ttl_max = 0;
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(EPOCH)),
        Arc::new(ScriptedQuerier::new(|_, _, _| {
            vec![nx("u1", Some(86_400)), nx("u2", Some(86_400))]
        })),
    );
    let res = r
        .clone()
        .resolve("p12-off.test", "A", ResolveOpts::default())
        .await;
    assert!(
        (res.ttl_left - 86_400.0).abs() < 1e-6,
        "neg_ttl_max=0 → 不设上限，实际 {}",
        res.ttl_left
    );
}

/// P1-2 契约：默认值 60（三处默认值必须一致，另见 main.rs 模板一致性测试）。
#[test]
fn p1_2_default_neg_ttl_max_is_60() {
    assert_eq!(ResolverConfig::default().neg_ttl_max, 60);
    assert_eq!(
        ResolverConfig::test_default(vec![], vec![], 2).neg_ttl_max,
        60
    );
}

/* ==================== A3：默认缓存容量 ==================== */

/// A3：默认 `cache_size` 必须是 16384（实测 ≈117kB/条 → 131072 投影 ≈15GB，4GB 机型不可行）。
#[test]
fn a3_default_cache_size_is_16384() {
    assert_eq!(
        ResolverConfig::default().cache_size,
        16_384,
        "默认 cache_size 必须收敛到 16384（A3）"
    );
}

/* ==================== P1-1：规则代际 → 缓存失效 ==================== */

/// P1-1 核心回归：先按「无规则」查一次并缓存，再新增 block 规则重建索引 →
/// 同一域名**立即**返回 NXDOMAIN（不需要 `/api/reset`，也不允许再命中旧答案）。
#[tokio::test]
async fn p1_1_new_block_rule_invalidates_cached_answer_immediately() {
    let r = base(2, |_, _, _| {
        vec![UpstreamAnswer::ok(
            "u1",
            0,
            vec![a("1.2.3.4", 300.0)],
            vec![],
        )]
    });
    // ① 缓存一条正向答案（TTL 300s）。
    let res1 = r
        .clone()
        .resolve("p11.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res1.rcode, RCODE_NOERROR);
    assert_eq!(res1.answers.len(), 1);
    assert!(!res1.hit);
    // ② 新增 block 规则并重建索引（等价于 POST /api/rules + 索引重建）。
    r.rebuild_rules(vec![rule("p11.test", "block")]);
    // ③ 立刻再查：规则命中优先于缓存 → NXDOMAIN，且**不是**缓存命中。
    let res2 = r
        .clone()
        .resolve("p11.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res2.rcode, RCODE_NXDOMAIN, "新增 block 规则必须立即生效");
    assert!(!res2.hit, "不得再命中规则变更前的旧答案");
}

/// P1-1 逆向：**删除** block 规则后，旧答案不得继续命中（必须重新走上游）。
#[tokio::test]
async fn p1_1_deleted_rule_does_not_serve_stale_answer() {
    let r = base(2, |_, _, _| {
        vec![UpstreamAnswer::ok(
            "u1",
            0,
            vec![a("5.6.7.8", 300.0)],
            vec![],
        )]
    });
    // ① 有 block 规则 → NXDOMAIN（不写正向缓存）。
    r.rebuild_rules(vec![rule("p11-del.test", "block")]);
    let res1 = r
        .clone()
        .resolve("p11-del.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res1.rcode, RCODE_NXDOMAIN);
    // ② 删除规则（等价于 DELETE /api/rules）→ 立即按无规则解析，取到上游答案。
    r.rebuild_rules(vec![]);
    let res2 = r
        .clone()
        .resolve("p11-del.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res2.rcode, RCODE_NOERROR);
    assert_eq!(res2.answers.len(), 1, "删除规则后应立即取到真实答案");
    assert!(!res2.hit, "不得命中规则变更前的旧结果");
}

/// P1-1：规则**内容未变**时重建不得改变代际（重复 rebuild / 启动同名恢复不清缓存）。
#[tokio::test]
async fn p1_1_unchanged_rules_keep_rule_gen_and_cache() {
    let r = base(2, |_, _, _| {
        vec![UpstreamAnswer::ok(
            "u1",
            0,
            vec![a("9.9.9.9", 300.0)],
            vec![],
        )]
    });
    let rules = vec![rule("keep.test", "block")];
    r.rebuild_rules(rules.clone());
    let gen1 = r.rule_gen();
    // ① 缓存一条正向答案。
    let _ = r
        .clone()
        .resolve("keep2.test", "A", ResolveOpts::default())
        .await;
    // ② 同内容重建（等价于启动时重复装配）→ 代际不变。
    r.rebuild_rules(rules.clone());
    assert_eq!(r.rule_gen(), gen1, "规则内容未变 → 代际不得改变");
    // ③ 同一查询仍是缓存命中。
    let res = r
        .clone()
        .resolve("keep2.test", "A", ResolveOpts::default())
        .await;
    assert!(res.hit, "规则未变时缓存必须继续可用");
}

/// P1-1：**顺序**变化（同集合重排）也算变化 —— 规则优先级与顺序相关。
#[tokio::test]
async fn p1_1_reordered_rules_change_rule_gen() {
    let r = base(2, |_, _, _| vec![]);
    r.rebuild_rules(vec![rule("a.test", "block"), rule("b.test", "allow")]);
    let g1 = r.rule_gen();
    r.rebuild_rules(vec![rule("b.test", "allow"), rule("a.test", "block")]);
    assert_ne!(r.rule_gen(), g1, "顺序变化必须改变指纹");
}

/* ==================== P2-B：预取不得写负缓存 ==================== */

/// P2-B：`resolve_prefetch`（单上游预取，quorum 被钳到 1）拿到 NXDOMAIN →
/// 允许把结果返回给调用方，但**绝不能**写负缓存。
#[tokio::test]
async fn p2b_prefetch_never_writes_negative_cache() {
    let r = base(2, |_, _, _| vec![nx("u1", None)]);
    let res = r
        .clone()
        .resolve_prefetch("p2b.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_NXDOMAIN, "预取仍返回上游结论");
    assert!(
        neg_entry(&r, "p2b.test").is_none(),
        "预取链路不得写 NXDOMAIN 负缓存（P2-B）"
    );

    // NODATA 同型。
    let r2 = base(2, |_, _, _| vec![nodata("u1", None)]);
    let res2 = r2
        .clone()
        .resolve_prefetch("p2b-nd.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res2.rcode, RCODE_NOERROR);
    assert!(res2.empty);
    assert!(
        neg_entry(&r2, "p2b-nd.test").is_none(),
        "预取链路不得写 NODATA 负缓存（P2-B）"
    );
}

/// P2-B 对照：数据面（多上游）两票 NXDOMAIN 仍照写负缓存。
#[tokio::test]
async fn p2b_data_plane_still_writes_negative_cache() {
    let r = base(2, |_, _, _| vec![nx("u1", None), nx("u2", None)]);
    let _ = r
        .clone()
        .resolve("p2b-data.test", "A", ResolveOpts::default())
        .await;
    assert!(neg_entry(&r, "p2b-data.test").is_some());
}

/// **2.1.19（F-06 修复：`counters.stale_served` 恒 0）**：serve-stale 直答必须**计数**。
///
/// 此前 `stale_served` 只能经 `Telemetry::inc`/`inc_n` 自增而**生产零调用点**
/// ⇒ `/api/status.counters.stale_served` 与 `/metrics` 恒 0，而 `/api/query` 的 trace
/// 明明显示 `serve-stale: 过期窗口内返回旧数据` —— 指标与运行态自相矛盾。
/// 现在唯一打点 = `resolve.rs::serve_stale_from_cache`（真的把过期数据发给客户端）。
#[tokio::test]
async fn f06_serve_stale_increments_stale_served_once() {
    /// 只记录 `inc(key)` 次数的遥测桩（不依赖 tracing，也不依赖 server crate）。
    #[derive(Default)]
    struct Rec {
        incs: std::sync::Mutex<std::collections::HashMap<String, u64>>,
        counts: std::sync::Mutex<std::collections::HashMap<String, u64>>,
    }
    impl ebpdns_resolver::telemetry::Telemetry for Rec {
        fn inc(&self, key: &str) {
            *self
                .incs
                .lock()
                .unwrap()
                .entry(key.to_string())
                .or_insert(0) += 1;
        }
        fn count_query(&self, cat: &str) {
            *self
                .counts
                .lock()
                .unwrap()
                .entry(cat.to_string())
                .or_insert(0) += 1;
        }
    }

    let rec = Arc::new(Rec::default());
    let clock = Arc::new(MockClock::new(EPOCH));
    let ups = vec![UpstreamCfg::test_up("u1")];
    let mut cfg = ResolverConfig::test_default(ups, vec![], 1);
    cfg.serve_stale = true;
    // stale 窗口远大于 TTL，保证过期后仍可服务。
    cfg.stale_ttl = 86_400.0;
    cfg.prefetch = false;
    let r = Resolver::new(
        cfg,
        rec.clone(),
        clock.clone(),
        Arc::new(ScriptedQuerier::new(|_, _, _| {
            vec![UpstreamAnswer::ok(
                "u1",
                0,
                vec![a("1.2.3.4", 20.0)],
                vec![],
            )]
        })),
    );

    // ① 首次解析：写正向缓存（TTL 20s），不是 stale。
    let res1 = r
        .clone()
        .resolve("f06stale.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res1.rcode, RCODE_NOERROR);
    assert_eq!(
        rec.incs
            .lock()
            .unwrap()
            .get("stale_served")
            .copied()
            .unwrap_or(0),
        0,
        "首查不得计 stale"
    );

    // ② 时钟推进到过期之后（仍在 stale 窗口内）。
    // **必须显式开 trace**：`ResolveOpts.trace` 默认 **false**（性能契约）⇒ 此时
    // `TraceSink` 是空操作、`res.trace` 恒为空。本用例的"前置"断言需要 trace，
    // 因此这里显式打开（**不改产品默认值**）。
    clock.advance(30.0);
    let traced = ResolveOpts {
        trace: true,
        ..Default::default()
    };
    let res2 = r.clone().resolve("f06stale.test", "A", traced).await;
    assert!(
        res2.trace.iter().any(|t| t.text.contains("serve-stale")),
        "前置：本用例必须真的走 serve-stale 路径，实际 trace={:?}",
        res2.trace
    );
    assert_eq!(
        rec.incs
            .lock()
            .unwrap()
            .get("stale_served")
            .copied()
            .unwrap_or(0),
        1,
        "serve-stale 直答必须恰好计 1 次（此前恒 0）"
    );

    // ③ 再查一次（仍过期、仍在窗口内）⇒ 计数继续 +1（每次直答各计一次）。
    clock.advance(1.0);
    let _ = r
        .clone()
        .resolve("f06stale.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(
        rec.incs
            .lock()
            .unwrap()
            .get("stale_served")
            .copied()
            .unwrap_or(0),
        2,
        "每次 serve-stale 直答各计 1 次"
    );
}

/* ====== 2.1.20（A-02）：前端范围必须与后端权威表同源（跨语言机器校验） ====== */

/// 仓库根（`crates/ebpdns-resolver` → 上溯两级）。
fn repo_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root")
        .to_path_buf()
}

/// **A-02**：`web/src/fmtnum.rs::CONFIG_RANGE_FALLBACK`（控制台的**兜底**范围表）必须与
/// 后端权威表 `CONFIG_RANGES` **逐键同值**，且覆盖那 **6 个曾经分叉的键**。
///
/// 为什么必须有这条：审计 A-02 的决定性证据是"后端已下发 `config_ranges`、前端
/// **零消费**、6 个键能摆出后端必然 400 的值"，而当时**没有任何测试**能发现它
/// （`config.rs` 注释里声称的 `web::range_consistency` 根本不存在）。
/// 本用例把"两表一致"变成硬约束：改一边不改另一边即红。
#[test]
fn web_config_range_fallback_matches_backend_table() {
    let src =
        std::fs::read_to_string(repo_root().join("web/src/fmtnum.rs")).expect("web/src/fmtnum.rs");
    let start = src
        .find("pub const CONFIG_RANGE_FALLBACK")
        .expect("必须存在 CONFIG_RANGE_FALLBACK");
    let body = &src[start..];
    let end = body.find("\n];").expect("数组必须以 `\\n];` 结束");
    let body = &body[..end];
    let mut parsed: Vec<(String, i64, i64)> = Vec::new();
    for line in body.lines() {
        let l = line.trim();
        if !l.starts_with("(\"") {
            continue;
        }
        let l = l.trim_end_matches(',');
        let inner = l.trim_start_matches('(').trim_end_matches(')');
        let parts: Vec<&str> = inner.split(',').map(str::trim).collect();
        assert_eq!(parts.len(), 3, "表项形状必须是 (\"key\", lo, hi)：{l}");
        let key = parts[0].trim_matches('"').to_string();
        let lo: i64 = parts[1].replace('_', "").parse().expect("lo 必须是整数");
        let hi: i64 = parts[2].replace('_', "").parse().expect("hi 必须是整数");
        parsed.push((key, lo, hi));
    }
    assert!(
        parsed.len() >= 25,
        "兜底表条目过少（{}）—— 疑似被误删",
        parsed.len()
    );
    for (k, lo, hi) in &parsed {
        let want = ebpdns_resolver::config::config_range_of(k)
            .unwrap_or_else(|| panic!("兜底表有后端 `CONFIG_RANGES` 里没有的键：{k}"));
        assert_eq!(
            (*lo, *hi),
            (want.0 as i64, want.1 as i64),
            "`{k}` 的兜底区间 ({lo}, {hi}) 与后端权威区间 {want:?} 不一致"
        );
    }
    for k in [
        "cache_size",
        "ttl",
        "ttl_min",
        "ttl_max",
        "stale_ttl",
        "speed_interval_ms",
        "health_check_interval",
    ] {
        assert!(
            parsed.iter().any(|(pk, _, _)| pk == k),
            "兜底表缺 `{k}`（它正是审计 A-02 的 6 个分叉键之一）"
        );
    }
}

/// **A-02**：控制台的**整数**配置键必须走 `dom_clamped_key`（运行期读后端权威表），
/// 且那 6 个曾经分叉的键**不得**再出现硬编码 `dom_clamped("<id>", lo, hi, d)`。
///
/// 这条是"回归护栏"：任何人把 clamp 改回硬编码常量，本用例立刻红。
#[test]
fn frontend_uses_runtime_range_table_for_integer_keys() {
    let src = std::fs::read_to_string(repo_root().join("web/src/pages/config.rs"))
        .expect("web/src/pages/config.rs");
    // **2.1.29**：判据与**排版无关**。`web/` 由 `cargo fmt` 保持 rustfmt-clean，长嵌套调用会被
    // rustfmt 拆成多行（实测 2.1.29：`dom_clamped_key(app,` / `"speed_interval_ms",` … 分行），
    // 因此先把两侧空白全部去掉再比子串 —— 判据仍然是"该键必须走 `dom_clamped_key(app,
    // "<key>"`"（而不是硬编码 `dom_clamped("<id>", …)`），只是不再依赖"必须在同一行"。
    let squash = |s: &str| s.chars().filter(|c| !c.is_whitespace()).collect::<String>();
    let src_norm = squash(&src);
    for key in [
        "cache_size",
        "ttl",
        "ttl_min",
        "ttl_max",
        "stale_ttl",
        "speed_interval_ms",
        "health_check_interval",
    ] {
        let needle = format!("dom_clamped_key(app,\"{key}\"");
        assert!(
            src_norm.contains(&needle),
            "控制台的 `{key}` 必须走 `dom_clamped_key`（运行期读 /api/status.config_ranges）；\
             缺 `{needle}` ⇒ 该键又会用硬编码范围、可能摆出后端必然 400 的值"
        );
    }
    for id in [
        "cfg-size",
        "cfg-ttl",
        "cfg-ttlmin",
        "cfg-ttlmax",
        "cfg-stalettl",
        "cfg-spint",
        "cfg-healthint",
    ] {
        let needle = format!("dom_clamped(\"{id}\"");
        assert!(
            !src_norm.contains(&needle),
            "`{id}` 仍在用硬编码 `{needle}` —— A-02 回归（该键必须走 dom_clamped_key）"
        );
    }
    assert!(
        ebpdns_resolver::config::config_range_of("circuit_open_s").is_none(),
        "`circuit_open_s` 是浮点键，不应出现在整数权威表里（若加入，请一并改前端）"
    );
}

/* ====== 2.1.19：P1-1 门禁的**真实漏洞** —— 数据面快路径 `answer_fast` 缺门禁 ====== */

/// 最小合法 DNS 查询包（QR=0 / opcode=0 / RD=1 / qclass=IN）——
/// `answer_fast` 的预检全部满足，因此能走到它的缓存命中点。
fn query_packet(domain: &str, qtype: u16) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
    v.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
    v.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    v.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    v.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    v.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    for label in domain.trim_end_matches('.').split('.') {
        v.push(label.len() as u8);
        v.extend_from_slice(label.as_bytes());
    }
    v.push(0);
    v.extend_from_slice(&qtype.to_be_bytes());
    v.extend_from_slice(&1u16.to_be_bytes()); // CLASS_IN
    v
}

/// 三种策略各建一个 resolver（`cache_policy` 决定内层实现）。
fn with_policy<F>(policy: &str, handler: F) -> Arc<Resolver>
where
    F: Fn(&str, &str, u32) -> Vec<UpstreamAnswer> + Send + Sync + 'static,
{
    let ups = vec![UpstreamCfg::test_up("u1"), UpstreamCfg::test_up("u2")];
    let mut cfg = ResolverConfig::test_default(ups, vec![], 2);
    cfg.cache_policy = policy.to_string();
    Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(EPOCH)),
        Arc::new(ScriptedQuerier::new(handler)),
    )
}

/// **2.1.19（P1-1 门禁回归，部署代理隔离实例三组实验互证）**：**数据面快路径
/// `answer_fast` 此前完全没有规则集指纹门禁** —— `resolve.rs` 的 `stale_rule` 检查只在
/// `answer_fast` 返回 `None` 之后才会执行，而**缓存命中时快路径直接返回**，
/// 于是"规则变了 ⇒ 旧答案立即失效"对**绝大多数真实查询**（UDP 热路径）根本不生效：
/// `hit=1 / miss=0`、`cache.used` 不下降。
///
/// 本用例遍历 **lru / tinylfu / partitioned** 三种策略，断言：
/// ①改规则前：快路径**命中**（前置条件，证明用例真的走到了那条路径）；
/// ②只改一条**无关**规则（仅让指纹变）后：快路径**必须不再命中**（返回 None），
///   且该条目**必须被删除**（`used` 下降 1）—— 否则 `resolve()` 也不会重新解析。
#[tokio::test]
async fn p1_1_fast_path_rejects_answers_from_previous_rule_generation() {
    for policy in ["lru", "tinylfu", "partitioned"] {
        let r = with_policy(policy, |_, _, _| {
            vec![UpstreamAnswer::ok(
                "u1",
                0,
                vec![a("1.2.3.4", 300.0)],
                vec![],
            )]
        });
        let dom = "fastgate.test";
        let pkt = query_packet(dom, 1);

        // ① 先走完整路径缓存一条正向答案（TTL 300s）。
        let res1 = r.clone().resolve(dom, "A", ResolveOpts::default()).await;
        assert_eq!(
            res1.rcode, RCODE_NOERROR,
            "[{policy}] 前置：上游应给 NOERROR"
        );
        assert!(!res1.hit, "[{policy}] 前置：首次必须 miss");
        assert_eq!(
            r.cache().summary()["used"].as_u64().unwrap_or(0),
            1,
            "[{policy}] 前置：缓存应有 1 条"
        );

        // ② 同一代 → 快路径必须命中（证明用例走的是快路径，而不是别的分支）。
        assert!(
            r.answer_fast(&pkt).is_some(),
            "[{policy}] 前置：规则未变时快路径必须命中缓存"
        );
        assert_eq!(
            r.cache().summary()["used"].as_u64().unwrap_or(0),
            1,
            "[{policy}] 命中不应改变条目数"
        );

        // ③ 加一条**与查询域名无关**的规则 ⇒ 只有指纹变（内容确实变了）。
        let g1 = r.rule_gen();
        r.rebuild_rules(vec![rule("unrelated-other.test", "block")]);
        let g2 = r.rule_gen();
        assert_ne!(g2, g1, "[{policy}] 规则内容变化必须改变指纹");

        // ④ **核心断言**：快路径不得再用上一代盖章的答案直答。
        assert!(
            r.answer_fast(&pkt).is_none(),
            "[{policy}] 规则集指纹已变，快路径**不得**再直答旧答案（2.1.17 功能回归）"
        );
        assert_eq!(
            r.cache().summary()["used"].as_u64().unwrap_or(0),
            0,
            "[{policy}] 被拒的陈旧条目必须同时被删除（used 20→20 的零驱逐现象必须消失）"
        );

        // ⑤ 随后走完整路径：必须是 miss（重新解析），不是命中旧答案。
        let res2 = r.clone().resolve(dom, "A", ResolveOpts::default()).await;
        assert!(
            !res2.hit,
            "[{policy}] 规则变更后的首次查询必须 miss（重新解析），实际 hit={}",
            res2.hit
        );
        assert_eq!(res2.rcode, RCODE_NOERROR);
    }
}

/// **2.1.19（P1-1 门禁回归）**：批量场景 —— 填 N 条后改规则，快路径必须**逐条**失效，
/// 且每拒绝一条就删除一条（`used` 单调下降），而不是"什么都没发生"。
#[tokio::test]
async fn p1_1_fast_path_evicts_every_stale_entry_after_rule_change() {
    const N: usize = 6;
    let r = with_policy("tinylfu", |_, _, _| {
        vec![UpstreamAnswer::ok(
            "u1",
            0,
            vec![a("9.9.9.9", 300.0)],
            vec![],
        )]
    });
    let doms: Vec<String> = (0..N).map(|i| format!("fastgate{i}.test")).collect();
    for d in &doms {
        let _ = r.clone().resolve(d, "A", ResolveOpts::default()).await;
    }
    assert_eq!(
        r.cache().summary()["used"].as_u64().unwrap_or(0) as usize,
        N,
        "前置：应缓存 {N} 条"
    );

    // 改规则（无关规则，只动指纹）。
    r.rebuild_rules(vec![rule("unrelated2.test", "block")]);

    for (i, d) in doms.iter().enumerate() {
        let pkt = query_packet(d, 1);
        assert!(
            r.answer_fast(&pkt).is_none(),
            "第 {i} 条（{d}）在规则变更后不得被快路径直答"
        );
        assert_eq!(
            r.cache().summary()["used"].as_u64().unwrap_or(0) as usize,
            N - 1 - i,
            "每拒绝一条应立即删除一条（used 应逐条下降）"
        );
    }
    assert_eq!(
        r.cache().summary()["used"].as_u64().unwrap_or(0),
        0,
        "全部陈旧条目都必须被清掉"
    );
}

/// **2.1.19（P1-1 门禁回归）对照**：规则**未变**时快路径必须继续命中
/// （避免"修成一律不命中"这种过度收紧 —— 那会让整个用户态缓存失效）。
#[tokio::test]
async fn p1_1_fast_path_still_hits_when_rule_gen_unchanged() {
    let r = with_policy("lru", |_, _, _| {
        vec![UpstreamAnswer::ok(
            "u1",
            0,
            vec![a("7.7.7.7", 300.0)],
            vec![],
        )]
    });
    let pkt = query_packet("fastkeep.test", 1);
    let _ = r
        .clone()
        .resolve("fastkeep.test", "A", ResolveOpts::default())
        .await;
    // 同内容 rebuild（等价于启动时重复装配 / 订阅轮询内容未变）→ 指纹不变。
    let g1 = r.rule_gen();
    r.rebuild_rules(vec![]);
    assert_eq!(r.rule_gen(), g1, "空规则重复 rebuild 不得改变指纹");
    assert!(
        r.answer_fast(&pkt).is_some(),
        "规则未变时快路径必须继续命中（缓存不得被过度失效）"
    );
}
