//! 性能探针（默认 `#[ignore]`，不进 CI；用于量化 C-06/C-07 的锁/克隆开销）。
//!
//! 运行方式：
//! ```text
//! cargo test -p ebpdns-cache --release --test cache_perf_probe -- --ignored --nocapture
//! ```
//!
//! 只打印 ns/op 并做**极宽松**的合理性断言（5x 量级），避免在噪声机器上偶发失败；
//! 真正的回归防线是 `cache_alloc_test.rs` 里的分配次数（确定性）。

use ebpdns_cache::{CacheEntry, CacheKey, DnsCache, LruCache, SwappableCache, TinyLfuCache};
use std::hint::black_box;
use std::sync::Arc;
use std::time::Instant;

const T0: f64 = 1_000.0;

fn e(domain: &str, ttl: f64, now: f64) -> CacheEntry {
    CacheEntry::new(domain, "A", ttl, now)
}

/// 返回 ns/op。
fn bench<F: FnMut()>(name: &str, iters: u64, mut f: F) -> f64 {
    for _ in 0..iters / 10 + 1 {
        f();
    }
    let t = Instant::now();
    for _ in 0..iters {
        f();
    }
    let ns = t.elapsed().as_nanos() as f64 / iters as f64;
    println!("  {name:<46} {ns:9.2} ns/op");
    ns
}

#[test]
#[ignore = "perf probe: run with --release --ignored --nocapture"]
fn probe_c07_owned_clone_vs_arc() {
    println!("\n== C-07: get() 克隆整条 entry vs get_arc() 零拷贝 ==");
    let c = LruCache::new(4096);
    let k = CacheKey::new("hot.probe", "A");
    c.put(k.clone(), e("hot.probe", 1e9, T0), T0);
    let iters = 2_000_000;

    let get_owned = bench("LruCache::get        (克隆 entry)", iters, || {
        black_box(c.get(black_box(&k), T0));
    });
    let get_arc = bench("LruCache::get_arc    (Arc 自增)", iters, || {
        black_box(c.get_arc(black_box(&k), T0));
    });
    println!(
        "  → 每次命中省下 {:.1} ns（{:.2}x）",
        get_owned - get_arc,
        get_owned / get_arc.max(0.001)
    );

    let t = TinyLfuCache::new(4096);
    t.put(k.clone(), e("hot.probe", 1e9, T0), T0);
    let tlfu_owned = bench("TinyLFU::get        (克隆 entry)", iters, || {
        black_box(t.get(black_box(&k), T0));
    });
    let tlfu_arc = bench("TinyLFU::get_arc    (Arc 自增)", iters, || {
        black_box(t.get_arc(black_box(&k), T0));
    });
    println!(
        "  → TinyLFU 每次命中省下 {:.1} ns（{:.2}x）",
        tlfu_owned - tlfu_arc,
        tlfu_owned / tlfu_arc.max(0.001)
    );
    assert!(
        get_arc < get_owned,
        "get_arc 应比 get 便宜（get_arc={get_arc} get={get_owned}）"
    );
    assert!(
        tlfu_arc < tlfu_owned,
        "TinyLFU get_arc 应比 get 便宜（{tlfu_arc} vs {tlfu_owned}）"
    );
}

#[test]
#[ignore = "perf probe: run with --release --ignored --nocapture"]
fn probe_c06_swappable_forwarding_overhead() {
    println!("\n== C-06: SwappableCache 每次 `current()`（读锁 + Arc 克隆）的开销 ==");
    let iters = 2_000_000;
    let k = CacheKey::new("hot.probe", "A");

    let plain = LruCache::new(4096);
    plain.put(k.clone(), e("hot.probe", 1e9, T0), T0);
    let boxed = LruCache::new(4096);
    boxed.put(k.clone(), e("hot.probe", 1e9, T0), T0);
    let dyn_cache: Arc<dyn DnsCache> = Arc::new(boxed);
    let sw = SwappableCache::new(Arc::clone(&dyn_cache));

    let current_only = bench(
        "SwappableCache::current()      (纯转发成本)",
        iters,
        || {
            black_box(sw.current());
        },
    );
    let plain_arc = bench("LruCache::get_arc      (直接调用)", iters, || {
        black_box(plain.get_arc(black_box(&k), T0));
    });
    let dyn_arc = bench("dyn DnsCache::get_arc  (虚调用)", iters, || {
        black_box(dyn_cache.get_arc(black_box(&k), T0));
    });
    let swap_arc = bench("SwappableCache::get_arc (读锁+虚调用)", iters, || {
        black_box(sw.get_arc(black_box(&k), T0));
    });
    let swap_owned = bench("SwappableCache::get     (含 entry 克隆)", iters, || {
        black_box(sw.get(black_box(&k), T0));
    });
    println!("  → 直接调用 {plain_arc:.1} ns / 虚调用 {dyn_arc:.1} ns / 转发后 {swap_arc:.1} ns");
    println!(
        "  → 转发额外成本 ≈ {:.1} ns/op（get_arc: swappable {:.1} - dyn {:.1}）",
        swap_arc - dyn_arc,
        swap_arc,
        dyn_arc
    );
    println!(
        "  → 占单次缓存操作比例 ≈ {:.1}%",
        (swap_arc - dyn_arc) / swap_arc.max(0.001) * 100.0
    );
    println!(
        "  → 对比：entry 克隆（C-07 已消除）约 {:.1} ns/op",
        swap_owned - swap_arc
    );
    assert!(current_only >= 0.0);
}

#[test]
#[ignore = "perf probe: run with --release --ignored --nocapture"]
fn probe_c01_round1_cost() {
    use ebpdns_cache::round1;
    println!(
        "\n== C-01: Python 口径 round1（十进制正确舍入 + 半值取偶）vs 旧 (v*10).round()/10 =="
    );
    let vals = [6.25f64, 12.345, 99.99, 1.23456];
    let iters = 500_000;
    let fmt = bench("round1（{:.1} 格式化 + parse）", iters, || {
        for v in vals {
            black_box(round1(black_box(v)));
        }
    });
    let naive = bench("(v*10).round()/10（旧口径）", iters, || {
        for v in vals {
            black_box((black_box(v) * 10.0).round() / 10.0);
        }
    });
    println!(
        "  → 每次调用 +{:.1} ns（{:.2}x）。round1 只出现在 summary()（3 次/请求）\n    与 serialize()（每条 1 次），不在 get/put 数据面路径上。",
        (fmt - naive) / vals.len() as f64,
        fmt / naive.max(0.001)
    );
    assert!(fmt > 0.0);
}

#[test]
#[ignore = "perf probe: run with --release --ignored --nocapture"]
fn probe_serialize_cost_per_entry() {
    println!("\n== serialize()（持久化/快照路径）每条成本 ==");
    const N: usize = 20_000;
    let c = LruCache::new(1 << 20);
    for i in 0..N {
        let d = format!("ser{i}.test");
        c.put(CacheKey::new(d.clone(), "A"), e(&d, 600.0, T0), T0);
    }
    assert_eq!(c.len(), N);
    let iters = 20;
    let t = Instant::now();
    let mut total = 0usize;
    for _ in 0..iters {
        total += black_box(c.serialize(T0)).len();
    }
    let ns = t.elapsed().as_nanos() as f64 / (iters as f64 * N as f64);
    println!("  {N} 条 × {iters} 次：{ns:8.1} ns/条（total={total}）");
}
