//! 2.1.9 缓存侧：A3（默认容量收敛）的确定性回归。
//!
//! **A4（tinylfu 三段 5/35/60 + 晋升水位）本轮未交付**：该改动与
//! `crates/ebpdns-cache/tests/cache_fix_test.rs` / `cache_test.rs` 既有的容量与
//! LRU 契约（`win+prob+prot == cap`、热点挺过冷插入）冲突，需单独一轮设计+回归；
//! 本轮 tinylfu 的三段准入/晋升语义**保持 2.1.8 行为**，缓存侧收益来自
//! `cache_size` 默认值 131072 → 16384（RSS 实测明显下降，hit 率无衰减）。
//!
//! `cache_size` 默认值在三处必须一致（`ResolverConfig::default` /
//! `main.rs::default_config()` / `packaging/etc/ebpdns/config.json`）：
//! resolver 侧断言在 `crates/ebpdns-resolver/tests/fix219_resolver_tests.rs`
//! （避免本 crate 反向依赖 resolver 造成依赖环），另两处由 `ebpdns` bin 的
//! `default_config_matches_packaging_template` 覆盖。

use ebpdns_cache::{CacheEntry, CacheKey, DnsCache, TinyLfuCache};

const T0: f64 = 1_000.0;

fn e(domain: &str, ttl: f64, now: f64) -> CacheEntry {
    CacheEntry::new(domain, "A", ttl, now)
}

/// A3 配套：容量硬上限在小容量下依然成立（灌 3 倍容量后 len 不超 cap）。
#[test]
fn a3_len_never_exceeds_capacity_at_small_caps() {
    for cap in [16usize, 17, 32, 47, 48, 64, 1000, 4096] {
        let c = TinyLfuCache::new(cap);
        for i in 0..(cap * 3 + 64) {
            let d = format!("c{cap}-{i}.test");
            c.put(CacheKey::new(&d, "A"), e(&d, 600.0, T0), T0);
        }
        assert!(
            c.len() <= cap,
            "cap={cap} 灌入 3 倍容量后 len={} 超过上限",
            c.len()
        );
        let s = c.summary();
        assert_eq!(s["capacity"].as_u64().unwrap() as usize, cap.max(16));
    }
}
