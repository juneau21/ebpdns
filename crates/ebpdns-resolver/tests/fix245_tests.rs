//! **2.1.45（fix245）**：REV247 P1-2/P1-3 —— quorum 的候选分母只数
//! **本轮实际派发过的上游**，补查波次不得计入；凑不满配置票数 ⇒ 永不 NXDOMAIN。
//!
//! 判别力：旧实现 `candidates = primary + backup + extra_waves` 在
//! `fallback=false` + `q>=4` 时把 2 个波次算成 2 个候选 ⇒ `nxq` 被钳到 3，
//! 3 张负票就确认 NXDOMAIN（并登记 RFC 8020）。本文件的
//! `extra_waves_never_fill_the_quorum_denominator` 在旧实现下会红。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ebpdns_cache::DnsCache;
use ebpdns_proto::constants::RCODE_NXDOMAIN;
use ebpdns_resolver::clock::MockClock;
use ebpdns_resolver::config::{ResolverConfig, UpstreamCfg};
use ebpdns_resolver::query::ScriptedQuerier;
use ebpdns_resolver::resolve::ResolveOpts;
use ebpdns_resolver::telemetry::NoopTelemetry;
use ebpdns_resolver::types::UpstreamAnswer;
use ebpdns_resolver::Resolver;

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

type Script = Arc<dyn Fn(usize) -> Vec<UpstreamAnswer> + Send + Sync>;

fn build(
    n_up: usize,
    quorum: usize,
    fallback: bool,
    parallel: usize,
    script: Script,
) -> Arc<Resolver> {
    let ups: Vec<UpstreamCfg> = (1..=n_up)
        .map(|i| UpstreamCfg::test_up(&format!("u{i}")))
        .collect();
    let mut cfg = ResolverConfig::test_default(ups, vec![], quorum);
    cfg.fallback = fallback;
    cfg.max_parallel_upstreams = parallel;
    cfg.adaptive_parallel = false;
    // `test_default` 里 `rfc8020_infer=false`（历史用例需要显式打开才能断言登记）。
    cfg.rfc8020_infer = true;
    let call = Arc::new(AtomicUsize::new(0));
    Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(1_700_000_000.0)),
        Arc::new(ScriptedQuerier::new(move |_, _, _| {
            let i = call.fetch_add(1, Ordering::SeqCst);
            script(i)
        })),
    )
}

/// `quorum=3` 但只有 2 个可用上游 ⇒ **永不** NXDOMAIN（SERVFAIL），且不写负缓存、
/// 不登记 RFC 8020（`fallback` 两种取值各一条用例）。
async fn assert_quorum_unreachable_never_nxdomain(fallback: bool) {
    // 第 1 次派发问 u1、后续补查波次问 u2 —— 一共只有 2 个可用上游。
    let r = build(
        2,
        3,
        fallback,
        2,
        Arc::new(|i| {
            if i == 0 {
                vec![nx("u1")]
            } else {
                vec![nx("u2")]
            }
        }),
    );
    let res = r
        .clone()
        .resolve("q3.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(
        res.rcode, 2,
        "可用上游 2 < quorum 3 ⇒ SERVFAIL（fallback={fallback}），实际 rcode={}",
        res.rcode
    );
    assert!(res.error, "未确认的负结论必须显式记为错误");
    let ck = r.ckey_normalized("q3.test", "A");
    assert!(
        r.cache().get(&ck, 1_700_000_000.0).is_none(),
        "quorum 不可达 ⇒ 不得写负缓存（fallback={fallback}）"
    );
    assert_eq!(
        r.rfc8020_registrations(),
        0,
        "quorum 不可达 ⇒ 不得登记 RFC 8020（否则整棵子树被放大判负）"
    );
}

#[tokio::test]
async fn quorum3_two_upstreams_never_nxdomain_fallback_false() {
    assert_quorum_unreachable_never_nxdomain(false).await;
}

#[tokio::test]
async fn quorum3_two_upstreams_never_nxdomain_fallback_true() {
    assert_quorum_unreachable_never_nxdomain(true).await;
}

/// `quorum=3`、可用上游 3、三张负票 ⇒ NXDOMAIN，且负缓存与 RFC 8020 **各 1**。
async fn assert_quorum_met_confirms(fallback: bool) {
    let r = build(
        3,
        3,
        fallback,
        3,
        Arc::new(|i| match i {
            0 => vec![nx("u1")],
            1 => vec![nx("u2")],
            _ => vec![nx("u3")],
        }),
    );
    let res = r
        .clone()
        .resolve("q3ok.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(
        res.rcode, RCODE_NXDOMAIN,
        "3/3 负票必须确认（fallback={fallback}）"
    );
    let ck = r.ckey_normalized("q3ok.test", "A");
    assert!(
        r.cache().get(&ck, 1_700_000_000.0).is_some(),
        "确认后必须写负缓存（恰好 1 条）"
    );
    assert_eq!(
        r.rfc8020_registrations(),
        1,
        "确认后必须登记 RFC 8020（恰好 1 次）"
    );
}

#[tokio::test]
async fn quorum3_three_negatives_confirms_fallback_false() {
    assert_quorum_met_confirms(false).await;
}

#[tokio::test]
async fn quorum3_three_negatives_confirms_fallback_true() {
    assert_quorum_met_confirms(true).await;
}

/// **REV247 P1-2 的静态反例**：`fallback=false`、8 个上游、`q=4`、`max_parallel=3`。
/// 实际派发 1 + 3 + 3 = 7 个上游，其中只有 **3 张负票**；旧实现把"2 个补查波次"
/// 算成 2 个候选（`candidates=1+0+2=3`）⇒ `nxq=3` ⇒ **3 票即确认**（错误 NXDOMAIN
/// + RFC 8020 放大）。新实现分母 = 去重派发数 7 ⇒ `nxq=4` ⇒ 3 票不足 ⇒ SERVFAIL。
#[tokio::test]
async fn extra_waves_never_fill_the_quorum_denominator() {
    let r = build(
        8,
        4,
        false,
        3,
        Arc::new(|i| match i {
            0 => vec![fail("u1")],
            1 => vec![nx("u2"), nx("u3"), nx("u4")],
            _ => vec![fail("u5"), fail("u6"), fail("u7")],
        }),
    );
    let res = r
        .clone()
        .resolve("waves.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(
        res.rcode, 2,
        "3 张负票 < quorum 4 ⇒ SERVFAIL（旧实现此处会 NXDOMAIN）"
    );
    let ck = r.ckey_normalized("waves.test", "A");
    assert!(
        r.cache().get(&ck, 1_700_000_000.0).is_none(),
        "不得写负缓存"
    );
    assert_eq!(r.rfc8020_registrations(), 0, "不得登记 RFC 8020");
}
