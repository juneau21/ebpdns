//! 2.1.9 缓存侧：A3（默认容量收敛）的确定性回归。
//!
//! **2.1.50（阶段 2）**：W-TinyLFU（`tinylfu`）策略已整体移除，原先针对它的
//! 三段比例/晋升用例随实现一并删除；本文件只保留 **A3（默认容量收敛）** 的容量
//! 硬上限回归，改用 `S3FifoCache`（当前出厂默认）覆盖同一不变量。
//!
//! `cache_size` 默认值在三处必须一致（`ResolverConfig::default` /
//! `main.rs::default_config()` / `packaging/etc/ebpdns/config.json`）：
//! resolver 侧断言在 `crates/ebpdns-resolver/tests/fix219_resolver_tests.rs`
//! （避免本 crate 反向依赖 resolver 造成依赖环），另两处由 `ebpdns` bin 的
//! `default_config_matches_packaging_template` 覆盖。

use ebpdns_cache::{CacheEntry, CacheKey, DnsCache, S3FifoCache};

const T0: f64 = 1_000.0;

fn e(domain: &str, ttl: f64, now: f64) -> CacheEntry {
    CacheEntry::new(domain, "A", ttl, now)
}

/// A3 配套：容量硬上限在小容量下依然成立（灌 3 倍容量后 len 不超 cap）。
#[test]
fn a3_len_never_exceeds_capacity_at_small_caps() {
    for cap in [16usize, 17, 32, 47, 48, 64, 1000, 4096] {
        let c = S3FifoCache::new(cap);
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
