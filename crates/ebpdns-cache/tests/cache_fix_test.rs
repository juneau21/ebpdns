//! 2.1.2 缓存层修复的回归测试：C-01/C-02/C-03/C-04/C-08/C-09/C-10 + TTL/serve-stale 边界。
//!
//! 时间一律用注入的 mock 时钟（显式 `now`），纯逻辑确定性。
//! 分配次数相关的量化测试在 `tests/cache_alloc_test.rs`（需要自定义全局分配器）。

use ebpdns_cache::{CacheEntry, CacheKey, DnsCache, LruCache, PartitionedCache, TinyLfuCache};
use serde_json::json;
use std::collections::BTreeMap;
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

    // TinyLFU 同型，且顺带覆盖 `Caps::compute` 的 `main * 2`（也改成 saturating）。
    let tlf = TinyLfuCache::new(usize::MAX);
    tlf.restore(&[], T0, 0.0);
    assert_eq!(tlf.len(), 0);
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

    let tlf = TinyLfuCache::new(1usize << 62);
    tlf.restore(&blob, T0, 0.0);
    assert_eq!(tlf.len(), N, "大容量下 TinyLFU.restore 不应截断");

    // 数据真的可用（不只是计数）。
    let k = CacheKey::new("h0.test", "A");
    assert!(lru.get(&k, T0 + 1.0).is_some());
    assert!(tlf.get(&k, T0 + 1.0).is_some());
}

// ============================ C-02 分配溢出 ============================

fn partition(shares: &[(&str, f64)]) -> Option<BTreeMap<String, f64>> {
    Some(
        shares
            .iter()
            .map(|(g, w)| (g.to_string(), *w))
            .collect::<BTreeMap<_, _>>(),
    )
}

/// 读回各分区实际容量（内层 LRUCache 的 `capacity`）。
fn part_caps(c: &PartitionedCache) -> Vec<u64> {
    c.summary()["partitions"]
        .as_object()
        .expect("partitions object")
        .values()
        .map(|v| v["capacity"].as_u64().expect("capacity u64"))
        .collect()
}

#[test]
fn c02_partitioned_huge_capacity_does_not_overflow_panic() {
    // 旧实现 `base + c` / `used` 求和会在超大 cap 下 overflow panic（debug），
    // release 下回绕成一个很小的份额 → 分区容量被静默改小。
    let c = PartitionedCache::new(usize::MAX, partition(&[("only", 1.0)]));
    assert_eq!(c.summary()["capacity"], json!(u64::MAX));
    assert_eq!(part_caps(&c), vec![u64::MAX]);
    // 仍然完全可用。
    let k = CacheKey::with_group("only", "a.test", "A");
    c.put(k.clone(), e("a.test", 60.0, T0), T0);
    assert!(c.get(&k, T0).is_some());

    // 默认三分权重（0.2/0.2/0.6）同样不再 panic。
    let c2 = PartitionedCache::new(usize::MAX, None);
    assert_eq!(c2.summary()["capacity"], json!(u64::MAX));
    let k2 = CacheKey::new("b.test", "A");
    c2.put(k2.clone(), e("b.test", 60.0, T0), T0);
    assert!(c2.get(&k2, T0).is_some());

    // 各种权重组合下的极大 cap 都必须能构造。
    for shares in [
        vec![("a", 0.5), ("b", 0.5)],
        vec![("a", 0.1), ("b", 0.2), ("c", 0.3), ("d", 0.4)],
        vec![("x", 1.0), ("y", 0.0), ("z", 0.0)],
        vec![("a", 0.7), ("b", 0.7)],
    ] {
        let _ = PartitionedCache::new(usize::MAX, partition(&shares));
        let _ = PartitionedCache::new(1usize << 63, partition(&shares));
    }
}

#[test]
fn c02_partitioned_shares_sum_to_capacity_for_practical_caps() {
    // **[历史归因]** 正常量级下分配必须精确（与 Python 大整数运算同值）。
    for &cap in &[48usize, 49, 64, 100, 128, 1000, 1024, 65_537, 1 << 20] {
        let c = PartitionedCache::new(cap, None);
        let sum: u64 = part_caps(&c).iter().sum();
        assert_eq!(sum, cap as u64, "cap={cap} 分区容量之和必须恰为 capacity");
    }
    // 非默认权重 / 更多分区同样精确。
    for &cap in &[64usize, 128, 1024, 9999] {
        let c = PartitionedCache::new(
            cap,
            partition(&[("a", 0.1), ("b", 0.2), ("c", 0.3), ("d", 0.4)]),
        );
        let sum: u64 = part_caps(&c).iter().sum();
        assert_eq!(sum, cap as u64, "cap={cap} 4 分区容量之和必须恰为 capacity");
    }
    // 注：cap < 16*分区数 时每个内层 LRUCache 会被 `clamp_capacity` 抬到 16，
    // **[历史归因]** 总容量因此大于 cap —— 这是 Python 亦有的既定安全下限（cache.py:389-392），
    // 不是缺陷，故不在此断言相等。
}

// ============================ C-04 容量快照 ============================

/// 把 `n` 条互不相同的条目灌进缓存（mock 时钟固定，永不过期）。
fn fill<C: DnsCache + ?Sized>(c: &C, tag: &str, n: usize) {
    for i in 0..n {
        let d = format!("{tag}-{i}.test");
        c.put(CacheKey::new(d.clone(), "A"), e(&d, 600.0, T0), T0);
    }
}

#[test]
fn c04_tinylfu_capacity_change_is_atomic_wrt_eviction() {
    // 单线程下的原子性：每次 set_capacity 之后立即满足 len <= 新容量；
    // 扩容回来必须能重新装满到新容量（若整组容量被撕裂/残留小值，这里会永久装不满）。
    let c = TinyLfuCache::new(64);
    for round in 0..4 {
        c.set_capacity(64);
        fill(&c, &format!("small{round}"), 300);
        assert!(c.len() <= 64, "round={round} 缩容后 len={} > 64", c.len());

        c.set_capacity(4096);
        fill(&c, &format!("big{round}"), 6000);
        assert_eq!(
            c.len(),
            4096,
            "round={round} 扩容后必须能装满到新容量（win+prob+prot == cap）"
        );

        c.set_capacity(64);
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
    // 断言的是**对外安全不变量**：不 panic，且任何时刻 len() 不超过历史上配置过的
    // 最大容量。C-04 的撕裂组合（新 win + 旧 protected）本身只是瞬态内部状态，
    // 且其和不大于 max(cap_old, cap_new)，因此外部只能观察到"不 panic + 有界"。
    // 修复后整组容量与三段 map 同锁发布，读侧不可能看到跨代组合（见
    // `Caps` 与 `TinyLfuCache::set_capacity` 的实现注释）。
    const MAX_CAP: usize = 4096;
    const CAPS: [usize; 3] = [64, 1024, MAX_CAP];
    let c = Arc::new(TinyLfuCache::new(256));
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
                    len <= MAX_CAP,
                    "len={len} 超过历史最大容量 {MAX_CAP}（容量快照撕裂）"
                );
                let s = c.summary();
                assert!(s["used"].as_u64().unwrap() <= MAX_CAP as u64);
                assert!(
                    s["window"].as_u64().unwrap()
                        + s["probation"].as_u64().unwrap()
                        + s["protected"].as_u64().unwrap()
                        <= MAX_CAP as u64
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

    // 收尾：静默期观测必须满足 len <= capacity（缩容后立即淘汰到位）。
    c.set_capacity(64);
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

    // TinyLFU：window 命中
    let tlf = TinyLfuCache::new(64);
    let k2 = CacheKey::new("tlfu-arc.test", "A");
    tlf.put(k2.clone(), e("tlfu-arc.test", 60.0, T0), T0);
    let t1 = tlf.get_arc(&k2, T0).expect("hit");
    let t2 = tlf.get_arc(&k2, T0).expect("hit");
    assert!(Arc::ptr_eq(&t1, &t2), "TinyLFU window 命中必须零拷贝");
    assert_eq!(*t1, tlf.get(&k2, T0).expect("hit"));

    // Partitioned
    let pc = PartitionedCache::new(128, None);
    let k3 = CacheKey::with_group("domestic", "p-arc.test", "A");
    pc.put(k3.clone(), e("p-arc.test", 60.0, T0), T0);
    let p1 = pc.get_arc(&k3, T0).expect("hit");
    let p2 = pc.get_arc(&k3, T0).expect("hit");
    assert!(Arc::ptr_eq(&p1, &p2), "Partitioned 命中必须零拷贝");

    // 二元组 key 路径（运行期 resolver 的实际形态）同样零拷贝
    let k4 = CacheKey::new("plain-arc.test", "A");
    pc.put(k4.clone(), e("plain-arc.test", 60.0, T0), T0);
    let q1 = pc.get_arc(&k4, T0).expect("hit");
    let q2 = pc.get_arc(&k4, T0).expect("hit");
    assert!(Arc::ptr_eq(&q1, &q2));
}

#[test]
fn c07_get_arc_keeps_lru_and_tinylfu_semantics() {
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

    // TinyLFU：probation 命中晋升 protected（与 get 同语义）。
    let tlf = TinyLfuCache::new(64);
    let hot = CacheKey::new("hot-arc.test", "A");
    tlf.put(hot.clone(), e("hot-arc.test", 600.0, T0), T0);
    for _ in 0..50 {
        assert!(tlf.get_arc(&hot, T0).is_some());
    }
    for i in 0..100 {
        let d = format!("cold-arc{i}.test");
        tlf.put(CacheKey::new(d.clone(), "A"), e(&d, 600.0, T0), T0);
    }
    assert!(
        tlf.get_arc(&hot, T0).is_some(),
        "热点必须挺过 TinyLFU 淘汰（get_arc 频率计数与 get 一致）"
    );
}

// ============================ C-08 split 借用 ============================

#[test]
fn c08_partitioned_group_roundtrip_and_fallback() {
    let c = PartitionedCache::new(128, None);
    let kd = CacheKey::with_group("domestic", "a.test", "A");
    c.put(kd.clone(), e("a.test", 60.0, T0), T0);
    assert!(c.get_arc(&kd, T0).is_some());
    assert!(c.get(&kd, T0).is_some());
    assert!(c.keys().contains(&kd), "keys() 必须保留 3 元组 group");

    // **[历史归因]** serialize → [group, domain, qtype]（对齐 Python `e["key"] = [g] + list(k)`）
    let blob = c.serialize(T0);
    assert_eq!(blob.len(), 1);
    assert_eq!(blob[0]["key"], json!(["domestic", "a.test", "A"]));

    // 往返不丢 group
    let c2 = PartitionedCache::new(128, None);
    c2.restore(&blob, T0, 0.0);
    assert!(
        c2.get_arc(&kd, T0).is_some(),
        "restore 后原 group 必须可命中"
    );
    assert!(c2.keys().contains(&kd), "restore 后 keys() 必须保留 group");
    assert_eq!(
        c2.serialize(T0)[0]["key"],
        json!(["domestic", "a.test", "A"])
    );

    // 二元组 key → default 分区
    let k2 = CacheKey::new("b.test", "A");
    c.put(k2.clone(), e("b.test", 60.0, T0), T0);
    assert!(c.get_arc(&k2, T0).is_some());
    assert!(c
        .keys()
        .contains(&CacheKey::with_group("default", "b.test", "A")));

    // 未知 group → 回退 default（对齐 `_split`：g → "default" → 第一个可用分区）
    let ku = CacheKey::with_group("no-such-group", "c.test", "A");
    c.put(ku.clone(), e("c.test", 60.0, T0), T0);
    assert!(
        c.get_arc(&ku, T0).is_some(),
        "未知 group 必须回退，不能丢写"
    );
    assert!(
        c.get_arc(&CacheKey::with_group("default", "c.test", "A"), T0)
            .is_some(),
        "回退后条目在 default 分区可见（对齐 Python 存入 2 元组语义）"
    );
    assert!(c
        .keys()
        .contains(&CacheKey::with_group("default", "c.test", "A")));

    // 自定义分区集且不含 "default"：回退第一个可用分区。
    let c3 = PartitionedCache::new(64, partition(&[("zulu", 0.5), ("alpha", 0.5)]));
    let kz = CacheKey::new("d.test", "A");
    c3.put(kz.clone(), e("d.test", 60.0, T0), T0);
    assert!(c3.get_arc(&kz, T0).is_some());
    assert!(c3
        .keys()
        .contains(&CacheKey::with_group("alpha", "d.test", "A")));

    // 分区隔离：domestic 的键在 global 分区查不到（2 元组内层键形态）。
    let kg = CacheKey::with_group("global", "a.test", "A");
    assert!(
        c.get_arc(&kg, T0).is_none(),
        "内层键必须剥掉 group：a.test 只在 domestic 分区"
    );
}

// ============================ C-01 pct 舍入口径 ============================

#[test]
fn c01_pct_uses_python_bankers_rounding() {
    // **[历史归因]** used=2 / cap=32 → 6.25%：Python `round(6.25, 1) == 6.2`，
    // 旧实现 `(6.25*10).round()/10 == 6.3`（half-away-from-zero）。
    // 三种策略都必须给出 6.2。
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

    let tlf = TinyLfuCache::new(32);
    for i in 0..2 {
        let d = format!("pct{i}.test");
        tlf.put(CacheKey::new(d.clone(), "A"), e(&d, 600.0, T0), T0);
    }
    assert_eq!(tlf.len(), 2);
    assert_eq!(tlf.summary()["pct"], json!(6.2), "TinyLFU pct 同口径");

    let pc = PartitionedCache::new(32, None);
    for i in 0..2 {
        let d = format!("pct{i}.test");
        pc.put(CacheKey::new(d.clone(), "A"), e(&d, 600.0, T0), T0);
    }
    assert_eq!(pc.len(), 2);
    assert_eq!(pc.summary()["capacity"], json!(32));
    assert_eq!(pc.summary()["pct"], json!(6.2), "Partitioned pct 同口径");
}

#[test]
fn c01_pct_covers_more_decimal_tie_cases() {
    // **[历史归因]** 更多 `.x5` 边界：used/cap*100 恰好落在十进制半值上，Python 一律取偶。
    // 注意 LRU/Partitioned 是 8 分片结构（每分片 cap/8），故 used 必须 <= cap/8
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

    // TinyLFU 的三段合计 == cap，只要 used <= cap 就都能留住（可用于更大 used）。
    for (cap, used, want) in [
        (32usize, 2usize, 6.2f64),
        (32, 10, 31.2),
        (32, 26, 81.2),
        (16, 5, 31.2),
        (48, 15, 31.2),
    ] {
        let c = TinyLfuCache::new(cap);
        for i in 0..used {
            let d = format!("t{i}.test");
            c.put(CacheKey::new(d.clone(), "A"), e(&d, 600.0, T0), T0);
        }
        assert_eq!(c.len(), used, "TinyLFU cap={cap} used={used}");
        assert_eq!(
            c.summary()["pct"],
            json!(want),
            "TinyLFU cap={cap} used={used} → {want}"
        );
    }

    // Partitioned：总容量用于 pct，内层 default 分区容量足够即可。
    for (cap, used, want) in [(64usize, 4usize, 6.2f64), (128, 8, 6.2)] {
        let c = PartitionedCache::new(cap, None);
        for i in 0..used {
            let d = format!("p{i}.test");
            c.put(CacheKey::new(d.clone(), "A"), e(&d, 600.0, T0), T0);
        }
        assert_eq!(c.len(), used, "Partitioned cap={cap} used={used}");
        assert_eq!(
            c.summary()["pct"],
            json!(want),
            "Partitioned cap={cap} used={used} → {want}"
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
fn tinylfu_three_segments_sum_to_capacity() {
    // win+prob+prot == cap：灌满后可容纳条数必须恰为 cap。
    for &cap in &[16usize, 17, 47, 48, 49, 64, 1000, 4096] {
        let c = TinyLfuCache::new(cap);
        fill(&c, &format!("seg{cap}"), cap * 3 + 64);
        assert_eq!(c.len(), cap, "cap={cap}: 三段容量之和必须 == capacity");
        let s = c.summary();
        assert!(s["window"].as_u64().unwrap() <= cap as u64);
        assert!(s["probation"].as_u64().unwrap() <= cap as u64);
        assert!(s["protected"].as_u64().unwrap() <= cap as u64);
    }
}

#[test]
fn tinylfu_shrink_converges_and_len_is_bounded() {
    let c = TinyLfuCache::new(4096);
    fill(&c, "shrink", 8000);
    assert_eq!(c.len(), 4096);
    for &cap in &[2048usize, 1024, 512, 64, 16, 17, 48, 1] {
        c.set_capacity(cap);
        let want = cap.max(16); // clamp_capacity 下限 16
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
    for policy in 0..3 {
        let c: Arc<dyn DnsCache> = match policy {
            0 => Arc::new(LruCache::new(64)),
            1 => Arc::new(TinyLfuCache::new(64)),
            _ => Arc::new(PartitionedCache::new(64, None)),
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
    for policy in 0..3 {
        let c: Arc<dyn DnsCache> = match policy {
            0 => Arc::new(LruCache::new(64)),
            1 => Arc::new(TinyLfuCache::new(64)),
            _ => Arc::new(PartitionedCache::new(64, None)),
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
    // stale_window == 0 时 get() 命中过期条目必须惰性删除（三种策略一致）。
    for policy in 0..3 {
        let c: Arc<dyn DnsCache> = match policy {
            0 => Arc::new(LruCache::new(64)),
            1 => Arc::new(TinyLfuCache::new(64)),
            _ => Arc::new(PartitionedCache::new(64, None)),
        };
        let k = CacheKey::new("lazy-del.test", "A");
        c.put(k.clone(), e("lazy-del.test", 1.0, T0), T0);
        assert_eq!(c.len(), 1);
        assert!(c.get_arc(&k, T0 + 5.0).is_none());
        assert_eq!(c.len(), 0, "policy={policy} 过期命中应被惰性删除");
    }
}
