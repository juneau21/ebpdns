//! **P1-2（2.1.14）** 负缓存 TTL 与持久化的确定性回归。
//!
//! 现场症状（上一轮审查 + 部署实测）：
//! 1. `neg_ttl_max=60`，但某负应答在 +195s（真实 +680s）仍以 0.08ms 直答；
//! 2. `GET /api/snapshot` 里该条目的 `ttl` 恒为 `60.0`（看起来"永不过期"）；
//! 3. 负缓存"重启即丢"（未参与落盘/恢复）。
//!
//! 本文件把**缓存层**能被证明的部分固化成测试：
//! - 负条目（`rcode=3` / 空答案段）到 `expires_at` 后必须 miss 且被物理删除；
//! - `get_stale`（serve-stale 窗口）**仍会**返回过期条目 —— 这是缓存层的中性行为，
//!   「负缓存不得走 serve-stale」由 `ebpdns-resolver::resolve_inner` 的门禁实现
//!   （见 `crates/ebpdns-resolver/src/resolve.rs::is_negative_entry`）；
//! - 负条目能完整参与 `serialize` → `restore`（落盘/恢复）往返，剩余 TTL 正确承接。
//!
//! 三个缓存实现（LRU / TinyLFU / Partitioned）逐一代入，避免"只修一种策略"。
//!
//! 期望值来自实现口径本身（缓存层不做负缓存特判），因此这些断言同时是
//! 「缓存层没有偷偷延长负 TTL」的证据。

use ebpdns_cache::{CacheEntry, CacheKey, DnsCache, LruCache, PartitionedCache, TinyLfuCache};

const T0: f64 = 1_700_000_000.0;

/// 负条目：NXDOMAIN（rcode=3，无答案段），TTL 60s（= 现场 `neg_ttl_max`）。
fn neg_nxdomain(domain: &str, ttl: f64, now: f64) -> CacheEntry {
    CacheEntry {
        domain: domain.to_string(),
        qtype: "A".to_string(),
        answers: Vec::new(),
        chosen: String::new(),
        ttl,
        rcode: 3,
        expires_at: now + ttl,
        rule_gen: 0,
        seq: 0,
    }
}

/// 负条目：NODATA（rcode=0 但答案段为空）。
fn neg_nodata(domain: &str, ttl: f64, now: f64) -> CacheEntry {
    CacheEntry {
        rcode: 0,
        seq: 0,
        ..neg_nxdomain(domain, ttl, now)
    }
}

fn all_caches() -> Vec<(&'static str, Box<dyn DnsCache>)> {
    vec![
        ("lru", Box::new(LruCache::new(1024)) as Box<dyn DnsCache>),
        (
            "tinylfu",
            Box::new(TinyLfuCache::new(1024)) as Box<dyn DnsCache>,
        ),
        (
            "partitioned",
            Box::new(PartitionedCache::new(1024, None)) as Box<dyn DnsCache>,
        ),
    ]
}

/// 按名字新建**同一种**实现（模拟"重启后的新实例"）。
fn fresh_cache(name: &str) -> Box<dyn DnsCache> {
    match name {
        "lru" => Box::new(LruCache::new(1024)) as Box<dyn DnsCache>,
        "tinylfu" => Box::new(TinyLfuCache::new(1024)) as Box<dyn DnsCache>,
        _ => Box::new(PartitionedCache::new(1024, None)) as Box<dyn DnsCache>,
    }
}

/// TTL 到点即失效（`get` 返回 None 并物理删除），**不因是负应答而延长**。
#[test]
fn negative_entry_expires_exactly_at_ttl() {
    for (name, c) in all_caches() {
        let key = CacheKey::new("nx.example", "A");
        c.put(key.clone(), neg_nxdomain("nx.example", 60.0, T0), T0);
        // 59.9s：仍在 TTL 内 → 命中。
        assert!(
            c.get(&key, T0 + 59.9).is_some(),
            "{name}: 未到 TTL 必须命中"
        );
        // 60.0s（恰好到点，判定 `expires_at <= now`）→ miss。
        assert!(c.get(&key, T0 + 60.0).is_none(), "{name}: 到 TTL 必须 miss");
        // +195s（现场观测点）→ 必须仍然 miss，且条目已被删除。
        assert!(
            c.get(&key, T0 + 195.0).is_none(),
            "{name}: +195s 必须 miss（现场缺陷：仍 0.08ms 直答）"
        );
        // NODATA（rcode=0 + 空答案段）同口径。
        let key2 = CacheKey::new("nodata.example", "A");
        c.put(key2.clone(), neg_nodata("nodata.example", 60.0, T0), T0);
        assert!(
            c.get(&key2, T0 + 60.0).is_none(),
            "{name}: NODATA 到 TTL 必须 miss"
        );
    }
}

/// serve-stale 窗口的中性行为：**缓存层**仍会给出过期条目（`get_stale`），
/// 因此"负缓存过期即失效"这条语义必须由 **resolver 侧门禁**保证 ——
/// 这正是本轮 P1-2 修的 `resolve_inner`（负条目 → 删除 + 重新解析，不 serve-stale）。
#[test]
fn get_stale_still_returns_expired_entry_hence_resolver_gate_is_required() {
    for (name, c) in all_caches() {
        let key = CacheKey::new("nx2.example", "A");
        c.put(key.clone(), neg_nxdomain("nx2.example", 60.0, T0), T0);
        // stale_ttl=120 的窗口内 → 返回（这就是"过期仍直答"的缓存层来源）。
        assert!(
            c.get_stale(&key, T0 + 120.0, 120.0).is_some(),
            "{name}: stale 窗口内 get_stale 返回旧条目（由 resolver 侧负缓存门禁拦截）"
        );
        // 窗口外 → None。
        assert!(
            c.get_stale(&key, T0 + 200.0, 120.0).is_none(),
            "{name}: 超出 stale 窗口必须 miss"
        );
    }
}

/// **落盘/恢复**：负条目必须能 round-trip，并正确承接**剩余** TTL。
///
/// 现场"重启即丢"的真因在这条测试下就是可判定的：
/// - 若 serialize/restore 丢弃负条目 → 本测试失败（那就是需要修的缺陷）；
/// - 若往返正常 → "重启即丢"只能是**负 TTL 本身很短**（≤ `neg_ttl_max`=60s，
///   重启 + 首次查询往往已过期）或 `cache_persist=false`，属预期行为。
#[test]
fn negative_entry_survives_persist_restore_roundtrip() {
    for (name, c) in all_caches() {
        let key = CacheKey::new("persist-neg.example", "A");
        c.put(
            key.clone(),
            neg_nxdomain("persist-neg.example", 60.0, T0),
            T0,
        );
        let dump = c.serialize(T0 + 10.0);
        assert!(
            dump.iter().any(|v| {
                v.get("rcode").and_then(|r| r.as_u64()) == Some(3)
                    && v.get("domain").and_then(|d| d.as_str()) == Some("persist-neg.example")
            }),
            "{name}: 负条目（rcode=3）必须出现在落盘快照里"
        );
        // 恢复到一个新实例（模拟重启），`persist_ttl=0` → 按 `remaining` 承接。
        let fresh = fresh_cache(name);
        fresh.restore(&dump, T0 + 10.0, 0.0);
        assert!(
            fresh.get(&key, T0 + 11.0).is_some(),
            "{name}: 恢复后同一域名必须命中（剩余 TTL ≈50s）"
        );
        // 原 TTL 到点后，恢复出来的条目也要同步失效（TTL 递减不被重置）。
        assert!(
            fresh.get(&key, T0 + 61.0).is_none(),
            "{name}: 恢复后仍必须按原 TTL 过期（不得被 persist 重置成新的 60s）"
        );
    }
}
