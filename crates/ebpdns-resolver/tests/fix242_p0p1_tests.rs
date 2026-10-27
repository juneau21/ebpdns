// >>> PATCH242A P0-1/P1-1 tests BEGIN
//! **2.1.42（2.1.42-A）**：resolver 侧 P0-1 / P1-1 的确定性回归。
//!
//! - P0-1：`nxdomain_quorum=N` 必须等满 N 张负票（或超时）才判 NXDOMAIN；
//!   一负一正 ⇒ 正向获胜、不写负缓存；两负 ⇒ NXDOMAIN + 负缓存恰好 1 条；
//!   quorum=1/单候选 ⇒ 行为不变。
//! - P1-1：数据面快路径同样应用 `ipv6=false` / `prefer_ipv4` 策略（与慢路径同一
//!   判定函数），已缓存 AAAA 不得下发。

use std::sync::Arc;

use ebpdns_cache::DnsCache;
use ebpdns_proto::constants::{RCODE_NOERROR, RCODE_NXDOMAIN, TYPE_A, TYPE_AAAA};
use ebpdns_resolver::answer::FastKind;
use ebpdns_resolver::clock::MockClock;
use ebpdns_resolver::config::{ResolverConfig, UpstreamCfg};
use ebpdns_resolver::query::ScriptedQuerier;
use ebpdns_resolver::resolve::ResolveOpts;
use ebpdns_resolver::telemetry::NoopTelemetry;
use ebpdns_resolver::types::{ResolveAnswer, UpstreamAnswer};
use ebpdns_resolver::Resolver;

const EPOCH: f64 = 1_700_000_000.0;

fn a(value: &str, ttl: f64) -> ResolveAnswer {
    ResolveAnswer::new(value, ttl, TYPE_A)
}

fn nx(up: &str) -> UpstreamAnswer {
    UpstreamAnswer {
        rcode: Some(RCODE_NXDOMAIN),
        up_name: up.into(),
        ..Default::default()
    }
}

fn build_resolver(
    quorum: usize,
    ipv6: bool,
    prefer_ipv4: bool,
    answers: Vec<UpstreamAnswer>,
) -> Arc<Resolver> {
    let ups = vec![UpstreamCfg::test_up("u1"), UpstreamCfg::test_up("u2")];
    let mut cfg = ResolverConfig::test_default(ups, vec![], quorum);
    cfg.ipv6 = ipv6;
    cfg.prefer_ipv4 = prefer_ipv4;
    Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(EPOCH)),
        Arc::new(ScriptedQuerier::new(move |_, _, _| answers.clone())),
    )
}

/// P0-1 ①：quorum=2、一负一正 ⇒ **不得** NXDOMAIN；正向 A 获胜且不写负缓存。
#[tokio::test]
async fn p0_1_one_negative_one_positive_is_not_nxdomain() {
    let r = build_resolver(
        2,
        true,
        false,
        vec![
            nx("u1"),
            UpstreamAnswer::ok("u2", 0, vec![a("1.2.3.4", 300.0)], vec![]),
        ],
    );
    let res = r
        .clone()
        .resolve("p0-one-one.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_NOERROR, "一负一正不得判 NXDOMAIN");
    assert_eq!(res.answers.len(), 1);
    assert_eq!(res.answers[0].value, "1.2.3.4");
    let e = r
        .cache()
        .get(&r.ckey("p0-one-one.test", "A"), EPOCH + 0.5)
        .expect("正向答案应写缓存");
    assert_eq!(e.rcode, RCODE_NOERROR);
    assert!(!e.answers.is_empty(), "缓存里必须是正向答案");
}

/// P0-1 ②：quorum=2、两负 ⇒ NXDOMAIN，且负缓存**恰好 1 条**。
#[tokio::test]
async fn p0_1_two_negatives_confirm_and_cache_once() {
    let r = build_resolver(2, true, false, vec![nx("u1"), nx("u2")]);
    let res = r
        .clone()
        .resolve("p0-two-neg.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_NXDOMAIN);
    assert_eq!(r.cache().len(), 1, "负缓存只应写入 1 条（不得重复/放大）");
    let e = r
        .cache()
        .get(&r.ckey("p0-two-neg.test", "A"), EPOCH + 0.5)
        .expect("确认 NXDOMAIN 后必须写负缓存");
    assert_eq!(e.rcode, RCODE_NXDOMAIN);
}

/// P0-1 ③：quorum=1（单候选）行为不变 ⇒ 单张 NXDOMAIN 即确认并写负缓存。
#[tokio::test]
async fn p0_1_quorum_one_still_confirms() {
    let ups = vec![UpstreamCfg::test_up("u1")];
    let cfg = ResolverConfig::test_default(ups, vec![], 1);
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(EPOCH)),
        Arc::new(ScriptedQuerier::new(|_, _, _| vec![nx("u1")])),
    );
    let res = r
        .clone()
        .resolve("p0-quorum-one.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_NXDOMAIN, "quorum=1 行为必须不变");
    assert_eq!(r.cache().len(), 1);
}

// ---------------- P1-1：数据面快路径策略过滤 ----------------

fn put_entry(r: &Resolver, d: &str, qtype: &str, rtype: u16, value: &str, ttl: f64) {
    let key = r.ckey_normalized(d, qtype);
    r.cache().put(
        key,
        ebpdns_cache::CacheEntry {
            domain: d.to_string(),
            qtype: qtype.to_string(),
            answers: vec![ebpdns_cache::CacheAnswer {
                value: value.to_string(),
                ttl,
                rtype,
                name: None,
            }],
            chosen: value.to_string(),
            ttl,
            rcode: 0,
            rule_gen: r.rule_gen(),
            expires_at: EPOCH + ttl,
            seq: 0,
        },
        EPOCH,
    );
}

fn query(name: &str, qtype: u16) -> Vec<u8> {
    let mut v = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for p in name.split('.') {
        v.push(p.len() as u8);
        v.extend_from_slice(p.as_bytes());
    }
    v.push(0);
    v.extend_from_slice(&qtype.to_be_bytes());
    v.extend_from_slice(&1u16.to_be_bytes()); // CLASS_IN
    v
}

fn rcode_of(resp: &[u8]) -> u8 {
    resp[3] & 0x0F
}

fn ancount_of(resp: &[u8]) -> u16 {
    u16::from_be_bytes([resp[6], resp[7]])
}

/// P1-1 ①：`ipv6=false` 且缓存里已有 AAAA ⇒ 快路径必须本地 NODATA（不下发 AAAA），
/// 且来源标记为 `PolicyFiltered`（不得冒充缓存 hit）。
#[test]
fn p1_1_ipv6_disabled_filters_cached_aaaa() {
    let r = build_resolver(1, false, false, vec![]);
    put_entry(&r, "aaaa.test", "AAAA", TYPE_AAAA, "2001:db8::1", 300.0);
    let raw = query("aaaa.test", TYPE_AAAA);
    let (resp, kind) = r.answer_fast_ex(&raw).expect("策略应答必须由快路径给出");
    assert_eq!(kind, FastKind::PolicyFiltered);
    assert_eq!(
        rcode_of(&resp),
        RCODE_NOERROR,
        "策略应答应是 NOERROR/NODATA"
    );
    assert_eq!(ancount_of(&resp), 0, "ipv6=false 时不得下发缓存的 AAAA");
}

/// P1-1 ②：`prefer_ipv4=true` 且 A 缓存存在 ⇒ AAAA 快路径同样 NODATA。
#[test]
fn p1_1_prefer_ipv4_filters_cached_aaaa() {
    let r = build_resolver(1, true, true, vec![]);
    put_entry(&r, "dual.test", "A", TYPE_A, "1.2.3.4", 300.0);
    put_entry(&r, "dual.test", "AAAA", TYPE_AAAA, "2001:db8::1", 300.0);
    let raw = query("dual.test", TYPE_AAAA);
    let (resp, kind) = r.answer_fast_ex(&raw).expect("策略应答必须由快路径给出");
    assert_eq!(kind, FastKind::PolicyFiltered);
    assert_eq!(ancount_of(&resp), 0, "prefer_ipv4 且 A 存在时不得下发 AAAA");
}

/// P1-1 ③（对照）：`prefer_ipv4=true` 但 A 不在缓存 ⇒ 快路径返回 None 交慢路径
/// （由 `probe_a_record` 探 A），不得擅自下发已缓存的 AAAA。
#[test]
fn p1_1_prefer_ipv4_without_cached_a_defers_to_slow_path() {
    let r = build_resolver(1, true, true, vec![]);
    put_entry(&r, "only6.test", "AAAA", TYPE_AAAA, "2001:db8::1", 300.0);
    let raw = query("only6.test", TYPE_AAAA);
    assert!(
        r.answer_fast(&raw).is_none(),
        "A 未确认时必须交慢路径（先 probe A）"
    );
}
// <<< PATCH242A P0-1/P1-1 tests END
