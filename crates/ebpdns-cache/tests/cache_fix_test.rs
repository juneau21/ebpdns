//! 2.1.2 缓存层修复的回归测试：C-01/C-02/C-03/C-04/C-08/C-09/C-10 + TTL/serve-stale 边界。
//!
//! 时间一律用注入的 mock 时钟（显式 `now`），纯逻辑确定性。
//! 分配次数相关的量化测试在 `tests/cache_alloc_test.rs`（需要自定义全局分配器）。

use ebpdns_cache::{CacheEntry, CacheKey, DnsCache, LruCache, S3FifoCache};
use serde_json::json;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

const T0: f64 = 1_000.0;

fn e(domain: &str, ttl: f64, now: f64) -> CacheEntry {
    CacheEntry::new(domain, "A", ttl, now)
}

// ============================ C-03 restore_cap 溢出 ============================

fn big_blob(n: usize, now: f64) -> Vec<serde_json::Value> {
    (0..n)
        .map(|i| {
            json!({
                "key": [format!("h{i}.test"), "A"],
                "domain": format!("h{i}.test"),
                "qtype": "A",
                "answers": [{"value": "1.2.3.4", "ttl": 60.0, "type": 1}],
                "chosen": "1.2.3.4",
                "ttl": 60.0,
                "rcode": 0,
                "expires_at": now + 60.0,
            })
        })
        .collect()
}

#[test]
fn c03_restore_huge_capacity_does_not_overflow_panic() {
    // 旧实现 `(cap * 4)`：debug 下 "attempt to multiply with overflow" 直接 panic。
    let lru = LruCache::new(usize::MAX);
    lru.restore(&[], T0, 0.0);
    assert_eq!(lru.len(), 0);
}

#[test]
fn c03_huge_capacity_restore_does_not_silently_truncate() {
    // cap = 2^62 → 旧实现 `cap * 4` 回绕成 0，`.max(65536)` 得到 65536：
    // 任何超过 65536 条的持久化缓存都会被**静默丢弃**（只剩截断后的部分）。
    // 这里 65537 条正好越过该下限 1 条。
    const N: usize = 65_537;
    let blob = big_blob(N, T0);

    let lru = LruCache::new(1usize << 62);
    lru.restore(&blob, T0, 0.0);
    assert_eq!(lru.len(), N, "大容量下 restore 不应截断");

    // 数据真的可用（不只是计数）。
    let k = CacheKey::new("h0.test", "A");
    assert!(lru.get(&k, T0 + 1.0).is_some());
}

// ============================ C-02 分配溢出 ============================

// ============================ C-04 容量快照 ============================

/// 把 `n` 条互不相同的条目灌进缓存（mock 时钟固定，永不过期）。
fn fill<C: DnsCache + ?Sized>(c: &C, tag: &str, n: usize) {
    for i in 0..n {
        let d = format!("{tag}-{i}.test");
        c.put(CacheKey::new(d.clone(), "A"), e(&d, 600.0, T0), T0);
    }
}

#[test]
fn c04_s3fifo_capacity_change_is_atomic_wrt_eviction() {
    // 单线程下的原子性：每次 set_capacity 之后**下一次写入/淘汰**立即满足 len <= 新容量；
    // 扩容回来必须能重新装满到新容量（若容量被撕裂/残留小值，这里会永久装不满）。
    //
    // 注：S3FIFO 的存储层是 2× 容量的 LruCache（策略层再按 cap 裁剪），因此
    // `set_capacity` 只保证内层立即收缩到 2×cap；策略层收敛由随后的 put 触发。
    let c = S3FifoCache::new(64);
    for round in 0..4 {
        c.set_capacity(64);
        fill(&c, &format!("small{round}"), 300);
        assert!(c.len() <= 64, "round={round} 缩容后 len={} > 64", c.len());

        c.set_capacity(4096);
        fill(&c, &format!("big{round}"), 6000);
        assert_eq!(
            c.len(),
            4096,
            "round={round} 扩容后必须能装满到新容量（策略层按 cap 裁剪）"
        );

        c.set_capacity(64);
        // 触发一次策略层淘汰（否则只收缩到内层 2×cap）。
        fill(&c, &format!("shrink{round}"), 1);
        assert!(
            c.len() <= 64,
            "round={round} 再次缩容后 len={} > 64",
            c.len()
        );
    }
    // 容量不变时重复 set_capacity 必须幂等（不额外淘汰、不膨胀）。
    c.set_capacity(64);
    let l1 = c.len();
    c.set_capacity(64);
    assert_eq!(c.len(), l1);
}

#[test]
fn c04_concurrent_set_capacity_and_get_do_not_panic_or_exceed_bounds() {
    // 并发：3 个线程反复换容量（互相竞争），4 个线程混合 get/get_arc/put/len。
    //
    // 断言的是**对外安全不变量**：不 panic，且任何时刻 len()/used 不超过
    // **存储层上界**（S3FIFO 的存储层是 2× 策略容量的 LruCache；策略层的 cap 由
    // 下一次 put 的淘汰收敛，并发 set_capacity 的瞬态允许存储层暂时到 2×cap）。
    // C-04 的撕裂只会让外部观察到"不 panic + 有界"。
    const MAX_CAP: usize = 4096;
    const STORAGE_MAX: usize = MAX_CAP * 2;
    const CAPS: [usize; 3] = [64, 1024, MAX_CAP];
    let c = Arc::new(S3FifoCache::new(256));
    let stop = Arc::new(AtomicBool::new(false));
    let iters = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for t in 0..3usize {
        let c = Arc::clone(&c);
        let stop = Arc::clone(&stop);
        let iters = Arc::clone(&iters);
        handles.push(std::thread::spawn(move || {
            let mut i = 0usize;
            while !stop.load(Ordering::Relaxed) {
                c.set_capacity(CAPS[(i + t) % CAPS.len()]);
                i += 1;
                iters.fetch_add(1, Ordering::Relaxed);
                if i >= 20_000 {
                    break;
                }
            }
        }));
    }
    for t in 0..4usize {
        let c = Arc::clone(&c);
        let stop = Arc::clone(&stop);
        let iters = Arc::clone(&iters);
        handles.push(std::thread::spawn(move || {
            let mut i = 0usize;
            while !stop.load(Ordering::Relaxed) {
                let d = format!("w{t}-{i}.test");
                let k = CacheKey::new(d.clone(), "A");
                c.put(k.clone(), e(&d, 600.0, T0), T0);
                let _ = c.get(&k, T0);
                let _ = c.get_arc(&k, T0);
                let _ = c.get_stale_arc(&k, T0, 0.0);
                let len = c.len();
                assert!(
                    len <= STORAGE_MAX,
                    "len={len} 超过存储层上界 {STORAGE_MAX}（2× 最大策略容量）"
                );
                let s = c.summary();
                assert!(s["used"].as_u64().unwrap() <= STORAGE_MAX as u64);
                // S3FIFO 的观测字段是 segment_s/segment_m/segment_g（没有 tinylfu 三段）；
                // 每条队列自身必须保持在存储层上界内（C-04 的容量快照撕裂判据）。
                assert!(
                    s["segment_s"].as_u64().unwrap() <= STORAGE_MAX as u64
                        && s["segment_m"].as_u64().unwrap() <= STORAGE_MAX as u64
                );
                i += 1;
                iters.fetch_add(1, Ordering::Relaxed);
                if i >= 20_000 {
                    break;
                }
            }
        }));
    }
    std::thread::sleep(std::time::Duration::from_millis(400));
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        h.join().expect("并发线程 panic");
    }
    assert!(iters.load(Ordering::Relaxed) > 0, "并发路径未被覆盖");

    // 收尾：静默期观测必须满足 len <= capacity（缩容后下一次写入淘汰到位）。
    c.set_capacity(64);
    fill(c.as_ref(), "final", 1);
    assert!(c.len() <= 64, "静默期 len={} > capacity=64", c.len());
    let s = c.summary();
    assert!(s["used"].as_u64().unwrap() <= s["capacity"].as_u64().unwrap());
}

// ============================ C-07 get_arc 零拷贝 ============================

#[test]
fn c07_get_arc_returns_the_same_allocation() {
    // LRU
    let lru = LruCache::new(64);
    let k = CacheKey::new("arc.test", "A");
    lru.put(k.clone(), e("arc.test", 60.0, T0), T0);
    let a = lru.get_arc(&k, T0).expect("hit");
    let b = lru.get_arc(&k, T0).expect("hit");
    assert!(
        Arc::ptr_eq(&a, &b),
        "get_arc 必须返回缓存内部同一个 Arc（零拷贝），而不是每次命中克隆一份"
    );
    assert_eq!(*a, lru.get(&k, T0).expect("get 同样命中"));

    // serve-stale 路径
    lru.set_stale_window(3600);
    lru.put(k.clone(), e("arc.test", 1.0, T0), T0);
    let now = T0 + 10.0;
    let s1 = lru.get_stale_arc(&k, now, 3600.0).expect("stale hit");
    let s2 = lru.get_stale_arc(&k, now, 3600.0).expect("stale hit");
    assert!(Arc::ptr_eq(&s1, &s2));

    // S3FIFO：内层 LRU 分片命中
    let s3 = S3FifoCache::new(64);
    let k2 = CacheKey::new("s3-arc.test", "A");
    s3.put(k2.clone(), e("s3-arc.test", 60.0, T0), T0);
    let t1 = s3.get_arc(&k2, T0).expect("hit");
    let t2 = s3.get_arc(&k2, T0).expect("hit");
    assert!(Arc::ptr_eq(&t1, &t2), "S3FIFO 命中必须零拷贝");
    assert_eq!(*t1, s3.get(&k2, T0).expect("hit"));
}

#[test]
fn c07_get_arc_keeps_lru_and_s3fifo_semantics() {
    // LRU 序：get_arc 也必须把命中项移到 MRU。
    let lru = LruCache::new(16);
    for i in 0..16 {
        lru.put(
            CacheKey::new(format!("a{i}.t"), "A"),
            e("a.t", 600.0, T0),
            T0,
        );
    }
    // a0 是 head(LRU)，用 get_arc 访问后应变成 MRU，从而不被下一次 put 淘汰。
    assert!(lru.get_arc(&CacheKey::new("a0.t", "A"), T0).is_some());
    lru.put(CacheKey::new("new.t", "A"), e("new.t", 600.0, T0), T0);
    assert!(
        lru.get_arc(&CacheKey::new("a0.t", "A"), T0).is_some(),
        "get_arc 必须与 get 一样触发 move_to_end"
    );
    // a1 未被访问过，应已被淘汰。
    assert!(lru.get_arc(&CacheKey::new("a1.t", "A"), T0).is_none());

    // S3FIFO：get_arc 命中同样累积频率（S 队首晋升 M，与 get 同语义）。
    let s3 = S3FifoCache::new(64);
    let hot = CacheKey::new("hot-arc.test", "A");
    s3.put(hot.clone(), e("hot-arc.test", 600.0, T0), T0);
    for _ in 0..50 {
        assert!(s3.get_arc(&hot, T0).is_some());
    }
    for i in 0..100 {
        let d = format!("cold-arc{i}.test");
        s3.put(CacheKey::new(d.clone(), "A"), e(&d, 600.0, T0), T0);
    }
    assert!(
        s3.get_arc(&hot, T0).is_some(),
        "热点必须挺过 S3FIFO 淘汰（get_arc 频率计数与 get 一致）"
    );
}

// ============================ C-01 pct 舍入口径 ============================

#[test]
fn c01_pct_uses_python_bankers_rounding() {
    // **[历史归因]** used=2 / cap=32 → 6.25%：Python `round(6.25, 1) == 6.2`，
    // 旧实现 `(6.25*10).round()/10 == 6.3`（half-away-from-zero）。
    // 有独立 pct 口径的策略都必须给出 6.2（`s3fifo` 的 summary 恒 0.0，见其实现）。
    let lru = LruCache::new(32);
    let mut used = 0;
    for i in 0..2 {
        let d = format!("pct{i}.test");
        lru.put(CacheKey::new(d.clone(), "A"), e(&d, 600.0, T0), T0);
        used += 1;
    }
    assert_eq!(used, 2);
    assert_eq!(lru.len(), 2);
    assert_eq!(lru.summary()["capacity"], json!(32));
    assert_eq!(
        lru.summary()["pct"],
        json!(6.2),
        "LRU pct 必须用 Python round(x,1)"
    );
}

#[test]
fn c01_pct_covers_more_decimal_tie_cases() {
    // **[历史归因]** 更多 `.x5` 边界：used/cap*100 恰好落在十进制半值上，Python 一律取偶。
    // 注意 LRU 是 8 分片结构（每分片 cap/8），故 used 必须 <= cap/8
    // 才能保证不被容量淘汰，否则 len() 会小于 used（与舍入无关）。
    for (cap, used, want) in [
        (32usize, 2usize, 6.2f64),
        (64, 4, 6.2),
        (128, 8, 6.2),
        (256, 16, 6.2),
    ] {
        let c = LruCache::new(cap);
        for i in 0..used {
            let d = format!("m{i}.test");
            c.put(CacheKey::new(d.clone(), "A"), e(&d, 600.0, T0), T0);
        }
        assert_eq!(c.len(), used, "cap={cap} used={used}");
        assert_eq!(
            c.summary()["pct"],
            json!(want),
            "LRU cap={cap} used={used} → Python round({},1)={want}",
            used as f64 / cap as f64 * 100.0
        );
    }
}

// ============================ C-09 轮转抽样 purge ============================

#[test]
fn c09_rotating_purge_reaches_non_head_expired_entries() {
    // 每个分片头部放"长寿"条目（队首快路径立刻 break），过期条目压在队列中段：
    // 只有轮转游标抽样能清掉它们（旧实现用 range_keys+get+remove 双重查找，
    // 新实现改为节点索引单次遍历/删除，语义与游标推进必须完全一致）。
    let cap = 4096;
    let c = LruCache::new(cap);
    let mut doomed = Vec::new();
    for i in 0..64 {
        let d = format!("fresh{i}.test");
        c.put(CacheKey::new(d.clone(), "A"), e(&d, 1e6, T0), T0);
    }
    for i in 0..64 {
        let d = format!("doomed{i}.test");
        let k = CacheKey::new(d.clone(), "A");
        c.put(k.clone(), e(&d, 1.0, T0), T0);
        doomed.push(k);
    }
    let now = T0 + 1_000.0;
    // 大量新写入：每个分片累计到 32 次 put 就触发一次 purge（步长 <= 64、
    // 且 step >= n 时强制 pos=0 全分片扫描）。
    for i in 0..2048 {
        let d = format!("new{i}.test");
        c.put(CacheKey::new(d.clone(), "A"), e(&d, 1e6, now), now);
    }
    assert_eq!(
        c.len(),
        64 + 2048,
        "轮转抽样应清掉中段的 64 条过期条目（保留 64 条长寿 + 2048 条新写入）"
    );
    assert_eq!(c.keys().len(), c.len(), "remove_index 后链与索引必须一致");
    for k in &doomed {
        assert!(
            c.get_stale_arc(k, now, 0.0).is_none(),
            "过期条目 {:?} 应已被 purge 回收",
            k.domain
        );
    }
    // 链完整性：所有仍可枚举的 key 都能查到且未过期。
    for k in c.keys() {
        assert!(c.get_arc(&k, now).is_some(), "{:?} 应可命中", k.domain);
    }
}

// ============================ 容量/分片不变量 ============================

#[test]
fn lru_shard_caps_sum_to_capacity() {
    // 8 分片 divmod 之后容量之和必须恰好等于 capacity（不因取整丢容量）。
    for &cap in &[16usize, 17, 23, 24, 63, 64, 100, 1024] {
        let c = LruCache::new(cap);
        fill(&c, &format!("sum{cap}"), cap * 3 + 64);
        assert_eq!(c.len(), cap, "cap={cap}: 分片容量之和必须 == capacity");
        assert_eq!(c.keys().len(), cap, "cap={cap}: keys/len 一致");
    }
}

#[test]
fn s3fifo_shrink_converges_and_len_is_bounded() {
    let c = S3FifoCache::new(4096);
    fill(&c, "shrink", 8000);
    assert_eq!(c.len(), 4096);
    for &cap in &[2048usize, 1024, 512, 64, 16, 17, 48, 1] {
        c.set_capacity(cap);
        let want = cap.max(16); // clamp_capacity 下限 16
                                // 策略层在下一次写入时收敛（见 c04 的说明）。
        fill(&c, &format!("shrink-trigger{cap}"), 1);
        assert!(
            c.len() <= want,
            "set_capacity({cap}) 后 len={} > {want}",
            c.len()
        );
        assert_eq!(c.summary()["capacity"], json!(want));
    }
    // 缩到底之后继续 put 不得越过容量。
    fill(&c, "after-shrink", 500);
    assert!(c.len() <= 16, "len={}", c.len());
    // 再扩容回来能重新装满。
    c.set_capacity(256);
    fill(&c, "regrow", 2000);
    assert_eq!(c.len(), 256);
}

// ============================ TTL / serve-stale 边界 ============================

#[test]
fn ttl_boundary_is_expires_at_le_now() {
    // **[历史归因]** Python: `if e["expires_at"] <= now: 过期`。expires_at == now 即为过期。
    for policy in 0..2 {
        let c: Arc<dyn DnsCache> = match policy {
            0 => Arc::new(LruCache::new(64)),
            _ => Arc::new(S3FifoCache::new(64)),
        };
        let k = CacheKey::new("boundary.test", "A");
        c.put(k.clone(), e("boundary.test", 10.0, T0), T0); // expires_at = T0+10
        assert!(
            c.get_arc(&k, T0 + 9.999).is_some(),
            "policy={policy} 未到期应命中"
        );
        assert!(
            c.get_arc(&k, T0 + 10.0).is_none(),
            "policy={policy} expires_at == now 必须视为过期"
        );
        assert!(c.get_arc(&k, T0 + 10.001).is_none());
    }
}

#[test]
fn serve_stale_window_boundary_is_inclusive() {
    // **[历史归因]** Python: `if now - exp > stale_window: 删除`；恰好等于窗口时仍可使用。
    for policy in 0..2 {
        let c: Arc<dyn DnsCache> = match policy {
            0 => Arc::new(LruCache::new(64)),
            _ => Arc::new(S3FifoCache::new(64)),
        };
        c.set_stale_window(3600);
        let k = CacheKey::new("stale-boundary.test", "A");
        c.put(k.clone(), e("stale-boundary.test", 1.0, T0), T0); // exp = T0+1
        let win = 3600.0;
        // now - exp == win → 仍在窗口内
        assert!(
            c.get_stale_arc(&k, T0 + 1.0 + win, win).is_some(),
            "policy={policy} now-exp == stale_window 必须仍在窗口内"
        );
        // now - exp == win + eps → 超出窗口并删除
        assert!(
            c.get_stale_arc(&k, T0 + 1.0 + win + 0.5, win).is_none(),
            "policy={policy} 超窗口必须删除"
        );
        assert!(c.get_arc(&k, T0 + 1.0 + win + 0.5).is_none());
    }
}

#[test]
fn serve_stale_window_zero_deletes_lazily_on_get() {
    // stale_window == 0 时 get() 命中过期条目必须惰性删除（两种策略一致）。
    for policy in 0..2 {
        let c: Arc<dyn DnsCache> = match policy {
            0 => Arc::new(LruCache::new(64)),
            _ => Arc::new(S3FifoCache::new(64)),
        };
        let k = CacheKey::new("lazy-del.test", "A");
        c.put(k.clone(), e("lazy-del.test", 1.0, T0), T0);
        assert_eq!(c.len(), 1);
        assert!(c.get_arc(&k, T0 + 5.0).is_none());
        assert_eq!(c.len(), 0, "policy={policy} 过期命中应被惰性删除");
    }
}
