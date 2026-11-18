//! **2.1.46（REV247 P3-2）**：两个"曾是恒 0"的计数必须有**正向**单测 ——
//! `ipv4_fallback`（`ipv4_first` 的 A 预热成功）与 `probe_upstream_queries`
//! （`prefer_ipv4` 真的发出 A 探测）。旧实现没有任何写点，本文件会红。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ebpdns_cache::DnsCache;
use ebpdns_resolver::clock::MockClock;
use ebpdns_resolver::config::{ResolverConfig, UpstreamCfg};
use ebpdns_resolver::query::ScriptedQuerier;
use ebpdns_resolver::resolve::ResolveOpts;
use ebpdns_resolver::telemetry::Telemetry;
use ebpdns_resolver::types::{ResolveAnswer, UpstreamAnswer};
use ebpdns_resolver::Resolver;

#[derive(Default)]
struct RecordingTelemetry {
    counts: Mutex<HashMap<String, u64>>,
}

impl Telemetry for RecordingTelemetry {
    fn inc(&self, key: &str) {
        *self
            .counts
            .lock()
            .unwrap()
            .entry(key.to_string())
            .or_insert(0) += 1;
    }
}

impl RecordingTelemetry {
    fn get(&self, key: &str) -> u64 {
        *self.counts.lock().unwrap().get(key).unwrap_or(&0)
    }
}

fn resolver<F>(mut cfg: ResolverConfig, handler: F) -> (Arc<Resolver>, Arc<RecordingTelemetry>)
where
    F: Fn(&str, &str) -> Vec<UpstreamAnswer> + Send + Sync + 'static,
{
    cfg.fallback = false;
    cfg.adaptive_parallel = false;
    let tel = Arc::new(RecordingTelemetry::default());
    let r = Resolver::new(
        cfg,
        tel.clone(),
        Arc::new(MockClock::new(1_700_000_000.0)),
        Arc::new(ScriptedQuerier::new(move |_, qtype, _| handler("", qtype))),
    );
    (r, tel)
}

fn nodata(up: &str) -> UpstreamAnswer {
    UpstreamAnswer {
        rcode: Some(0),
        up_name: up.into(),
        ..Default::default()
    }
}

fn a_answer(up: &str, ip: &str) -> UpstreamAnswer {
    UpstreamAnswer::ok(
        up,
        1,
        vec![ResolveAnswer::new(ip.to_string(), 300.0, 1)],
        vec![],
    )
}

/// `ipv4_first=true`：AAAA NODATA ⇒ 回退查 A 并回填；计数恰好 +1。
#[tokio::test]
async fn ipv4_fallback_positive_path_increments_counter() {
    let ups = vec![UpstreamCfg::test_up("u1")];
    let mut cfg = ResolverConfig::test_default(ups, vec![], 1);
    cfg.ipv4_first = true;
    cfg.prefer_ipv4 = false;
    let (r, tel) = resolver(cfg, |_, qtype| match qtype {
        "AAAA" => vec![nodata("u1")],
        "A" => vec![a_answer("u1", "93.184.216.34")],
        _ => vec![],
    });
    let res = r
        .clone()
        .resolve(
            "v4fallback.test",
            "AAAA",
            ResolveOpts {
                trace: true,
                ..Default::default()
            },
        )
        .await;
    assert_eq!(res.rcode, 0);
    assert!(res.empty, "AAAA 仍应返回 NODATA");
    assert_eq!(
        tel.get("ipv4_fallback"),
        1,
        "A 预热成功必须计 ipv4_fallback（旧实现无写点，恒 0）"
    );
    // 预热真的回填了 A 缓存。
    let ck = r.ckey_normalized("v4fallback.test", "A");
    assert!(
        r.cache().get(&ck, 1_700_000_000.0).is_some(),
        "A 记录必须被回填"
    );
}

/// **2.1.46（REV247 P3-4）**：探测查询 panic（派发未成功返回）时不得先加计数。
/// 旧实现 `inc` 在 `query_parallel` 之前 ⇒ 本用例会看到 1。
#[tokio::test]
async fn probe_counter_not_incremented_when_query_panics() {
    let ups = vec![UpstreamCfg::test_up("u1")];
    let mut cfg = ResolverConfig::test_default(ups, vec![], 1);
    cfg.ipv4_first = false;
    cfg.prefer_ipv4 = true;
    let (r, tel) = resolver(cfg, |_, qtype| {
        if qtype == "A" {
            panic!("模拟探测查询在派发阶段立即失败");
        }
        vec![UpstreamAnswer::ok(
            "u1",
            1,
            vec![ResolveAnswer::new("2001:db8::11", 300.0, 28)],
            vec![],
        )]
    });
    let h = tokio::spawn(async move {
        r.resolve("probe-panic.test", "AAAA", ResolveOpts::default())
            .await
    });
    let err = h.await.expect_err("探测 panic 必须传播为 JoinError");
    assert!(err.is_panic(), "期望 panic，实际 {err:?}");
    assert_eq!(
        tel.get("probe_upstream_queries"),
        0,
        "查询未成功返回前不得计 probe_upstream_queries（旧实现先加后发）"
    );
}

/// `prefer_ipv4=true` 且 A 不在缓存：AAAA 查询前真的发出 A 探测 ⇒ 计数 +1。
#[tokio::test]
async fn probe_a_record_positive_path_increments_counter() {
    let ups = vec![UpstreamCfg::test_up("u1")];
    let mut cfg = ResolverConfig::test_default(ups, vec![], 1);
    cfg.ipv4_first = false;
    cfg.prefer_ipv4 = true;
    let (r, tel) = resolver(cfg, |_, qtype| match qtype {
        "A" => vec![a_answer("u1", "93.184.216.34")],
        "AAAA" => vec![UpstreamAnswer::ok(
            "u1",
            1,
            vec![ResolveAnswer::new("2001:db8::10", 300.0, 28)],
            vec![],
        )],
        _ => vec![],
    });
    let res = r
        .clone()
        .resolve("probe.test", "AAAA", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, 0);
    assert_eq!(
        tel.get("probe_upstream_queries"),
        1,
        "双栈探测真的发了上游 A 查询 ⇒ 必须 +1（旧测试只手工 inc，未驱动 probe_a_record）"
    );
}
