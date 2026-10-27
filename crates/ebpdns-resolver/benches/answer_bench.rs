//! 拆解 answer_fast 热路径成本：parse / ckey+cache.get / match_rule / 全量编码。

use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use ebpdns_cache::DnsCache;
use ebpdns_proto::constants::TYPE_A;
use ebpdns_proto::message::parse_message;
use ebpdns_proto::query::build_query;
use ebpdns_resolver::clock::MockClock;
use ebpdns_resolver::config::{ResolverConfig, UpstreamCfg};
use ebpdns_resolver::query::ScriptedQuerier;
use ebpdns_resolver::telemetry::NoopTelemetry;
use ebpdns_resolver::types::ResolveAnswer;
use ebpdns_resolver::Resolver;

fn setup() -> (Arc<Resolver>, Vec<u8>) {
    let ups = vec![UpstreamCfg::test_up("u1")];
    let cfg = ResolverConfig::test_default(ups, vec![], 2);
    let clock = Arc::new(MockClock::new(1_700_000_000.0));
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        clock,
        Arc::new(ScriptedQuerier::new(|_, _, _| Vec::new())),
    );
    let key = r.ckey("hit.example.com", "A");
    r.fill_cache(
        &key,
        "hit.example.com",
        "A",
        vec![ResolveAnswer::new("1.2.3.4", 300.0, TYPE_A)],
        None,
    );
    let (raw, _qid) = build_query("hit.example.com", TYPE_A, None, false, None, None, false)
        .expect("build query");
    (r, raw)
}

fn bench_parse_only(c: &mut Criterion) {
    let (_r, raw) = setup();
    c.bench_function("parse_only", |b| {
        b.iter(|| black_box(parse_message(black_box(&raw))).unwrap());
    });
}

fn bench_ckey_cacheget(c: &mut Criterion) {
    let (r, raw) = setup();
    let msg = parse_message(&raw).unwrap();
    let q = msg.questions.first().unwrap();
    c.bench_function("ckey_cacheget", |b| {
        b.iter(|| {
            let d = q.name.trim_end_matches('.').to_ascii_lowercase();
            let now = 1_700_000_000.0;
            let key = r.ckey(&d, "A");
            black_box(r.cache().get(black_box(&key), now));
        })
    });
}

fn bench_match_rule(c: &mut Criterion) {
    let (r, _raw) = setup();
    c.bench_function("match_rule_hit", |b| {
        b.iter(|| black_box(r.match_rule(black_box("hit.example.com"))));
    });
}

criterion_group!(
    benches,
    bench_parse_only,
    bench_ckey_cacheget,
    bench_match_rule
);
criterion_main!(benches);
