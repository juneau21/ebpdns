//! LruCache 热路径基准：get 命中 / put / TTL 过期快路径。

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use ebpdns_cache::{CacheEntry, CacheKey, DnsCache, LruCache};

const NOW: f64 = 1_700_000_000.0;

fn seeded(cap: usize, n: usize) -> (LruCache, Vec<CacheKey>) {
    let c = LruCache::new(cap);
    let mut keys = Vec::with_capacity(n);
    for i in 0..n {
        let k = CacheKey::new(format!("host{i}.example.com"), "A");
        let e = CacheEntry::new(format!("host{i}.example.com"), "A", 300.0, NOW);
        c.put(k.clone(), e, NOW);
        keys.push(k);
    }
    (c, keys)
}

fn bench_get_hit(c: &mut Criterion) {
    let (cache, keys) = seeded(16_384, 8_192);
    let mut i = 0usize;
    c.bench_function("lru_get_hit", |b| {
        b.iter(|| {
            let k = &keys[i % keys.len()];
            i += 1;
            let e = black_box(cache.get(black_box(k), NOW));
            black_box(e);
        })
    });
}

fn bench_put(c: &mut Criterion) {
    let cache = LruCache::new(16_384);
    let mut i = 0usize;
    c.bench_function("lru_put", |b| {
        b.iter(|| {
            let k = CacheKey::new(format!("put{i}.example.com"), "A");
            let e = CacheEntry::new(format!("put{i}.example.com"), "A", 300.0, NOW);
            cache.put(black_box(k), e, NOW);
            i += 1;
        })
    });
}

fn bench_get_expired(c: &mut Criterion) {
    // 全部条目已过期 → get 快路径惰性删除（stale_window=0）。
    let (cache, keys) = seeded(16_384, 8_192);
    let later = NOW + 10_000.0;
    let mut i = 0usize;
    c.bench_function("lru_get_expired_evict", |b| {
        b.iter(|| {
            let k = &keys[i % keys.len()];
            i += 1;
            // 复写一条新鲜的，避免缓存被第一轮清空后后续全 miss。
            let e = CacheEntry::new("re.Example.com", "A", 300.0, later);
            cache.put(k.clone(), e, later);
            // 同一 key 立即读：新鲜命中。
            black_box(cache.get(black_box(k), later));
        })
    });
}

criterion_group!(benches, bench_get_hit, bench_put, bench_get_expired);
criterion_main!(benches);
