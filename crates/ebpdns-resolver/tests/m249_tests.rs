//! **2.1.49（AUDIT-251 收尾）**：AUD-12 / AUD-13 的判别性回归。
//!
//! 这两个用例在 2.1.48 上是红的：
//! - `aud12_*`：重复 upstream id 的两条 NXDOMAIN 结果会被当成两票（q=2 错误确认）；
//! - `aud13_*`：`rule_gen` 的已知 SHA-256 向量与 FNV-1a 值不同。

use std::sync::Arc;

use ebpdns_cache::DnsCache;
use ebpdns_resolver::clock::MockClock;
use ebpdns_resolver::config::{ResolverConfig, UpstreamCfg};
use ebpdns_resolver::query::ScriptedQuerier;
use ebpdns_resolver::resolve::ResolveOpts;
use ebpdns_resolver::telemetry::NoopTelemetry;
use ebpdns_resolver::types::UpstreamAnswer;
use ebpdns_resolver::Resolver;
use serde_json::json;

fn nx(up: &str) -> UpstreamAnswer {
    UpstreamAnswer {
        rcode: Some(3),
        up_name: up.into(),
        ..Default::default()
    }
}

/// **AUD-12**：配置重复 id（两个条目同一个 `up_name`）且 q=2 ⇒ 只有**一个**物理
/// 票源，`candidates=1 < q=2` ⇒ SERVFAIL；绝不 NXDOMAIN / 不写负缓存。
///
/// 2.1.48：`candidates` 去重后为 1，但 `nx.len()` 是 2 ⇒ `nx.len() >= nxq` 成立
/// ⇒ 错误 NXDOMAIN（本用例会红）。
#[tokio::test]
async fn aud12_duplicate_upstream_id_never_confirms_nxdomain() {
    let ups: Vec<UpstreamCfg> = (0..2)
        .map(|i| {
            let mut u = UpstreamCfg::test_up("dup");
            u.host = format!("192.0.2.{}", i + 1);
            u
        })
        .collect();
    let mut cfg = ResolverConfig::test_default(ups, vec![], 2);
    cfg.fallback = false;
    cfg.adaptive_parallel = false;
    cfg.max_parallel_upstreams = 2;
    cfg.rfc8020_infer = true;
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(1_700_000_000.0)),
        Arc::new(ScriptedQuerier::new(|_, _, _| {
            // 两个重复 id 的结果（模拟一次扇出两条同 up_name 的 NXDOMAIN）。
            vec![nx("dup"), nx("dup")]
        })),
    );
    let res = r
        .clone()
        .resolve("dup-id.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(
        res.rcode, 2,
        "candidates=1 < q=2 ⇒ 必须 SERVFAIL，实际 rcode={}",
        res.rcode
    );
    assert!(res.error, "未确认的负结论必须显式记为错误");
    let ck = r.ckey_normalized("dup-id.test", "A");
    assert!(
        r.cache().get(&ck, 1_700_000_000.0).is_none(),
        "重复 id 不得写负缓存"
    );
    assert_eq!(r.rfc8020_registrations(), 0, "重复 id 不得登记 RFC 8020");
}

/// **AUD-13**：`rule_gen` 改为 SHA-256 前 64 位投影。已知向量：
/// `*.sha.test` + block + local → SHA-256 前 8 字节 = `1e45b319f8c0122b`。
/// 2.1.48 的 FNV-1a 值为另一组数字（本用例会红）。
#[test]
fn aud13_rule_gen_is_sha256_vector_not_fnv() {
    let mut map = serde_json::Map::new();
    map.insert("match".into(), json!("*.sha.test"));
    map.insert("action".into(), json!("block"));
    let rule = ebpdns_rules::rule_from_json(map, ebpdns_rules::RuleSource::Local).expect("rule");
    let cfg = ResolverConfig::test_default(vec![UpstreamCfg::test_up("u1")], vec![rule], 1);
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(1_700_000_000.0)),
        Arc::new(ScriptedQuerier::new(|_, _, _| vec![])),
    );
    assert_eq!(
        r.rule_gen(),
        0x1e45_b319_f8c0_122b,
        "rule_gen 必须是 SHA-256 前 64 位投影（2.1.48 的 FNV 值会红）"
    );
}
