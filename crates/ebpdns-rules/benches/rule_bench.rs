//! RuleEngine::match_rule 热路径基准：精确 / 通配 / 正则，以及结论缓存命中。

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use ebpdns_rules::{rule_from_json, RuleEngine, RuleSource};
use serde_json::json;

fn mkrule(match_: &str, action: &str) -> ebpdns_rules::Rule {
    let mut obj = serde_json::Map::new();
    obj.insert("match".into(), json!(match_));
    obj.insert("action".into(), json!(action));
    rule_from_json(obj, RuleSource::Local).expect("rule builds")
}

fn engine() -> RuleEngine {
    let e = RuleEngine::new();
    e.rebuild(vec![
        mkrule("exact.example.com", "block"),
        mkrule("*.wild.example.com", "block"),
        mkrule("re:ads[0-9]+\\.net$", "block"),
    ]);
    e
}

fn bench_exact_hit(c: &mut Criterion) {
    let e = engine();
    // 预热结论缓存。
    let _ = e.match_rule("exact.example.com", false);
    c.bench_function("rule_exact_hit_cached", |b| {
        b.iter(|| black_box(e.match_rule(black_box("exact.example.com"), false)))
    });
}

fn bench_exact_miss(c: &mut Criterion) {
    let e = engine();
    c.bench_function("rule_exact_miss_cached", |b| {
        b.iter(|| black_box(e.match_rule(black_box("nomatch.example.org"), false)))
    });
}

fn bench_wild_hit(c: &mut Criterion) {
    let e = engine();
    let _ = e.match_rule("a.b.wild.example.com", false);
    c.bench_function("rule_wild_hit_cached", |b| {
        b.iter(|| black_box(e.match_rule(black_box("a.b.wild.example.com"), false)))
    });
}

fn bench_regex_eval(c: &mut Criterion) {
    // 正则求值（不命中结论缓存，换不同子域）。
    let e = engine();
    let mut i = 0usize;
    c.bench_function("rule_regex_eval", |b| {
        b.iter(|| {
            let d = format!("page{i}.ads123.net");
            i += 1;
            black_box(e.match_rule(black_box(&d), false));
        })
    });
}

criterion_group!(
    benches,
    bench_exact_hit,
    bench_exact_miss,
    bench_wild_hit,
    bench_regex_eval
);
criterion_main!(benches);
