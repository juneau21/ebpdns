//! 堆分配次数量化测试（C-05/C-07/C-08/C-10）。
//!
//! 用自定义 `#[global_allocator]` 统计**当前线程**在指定闭包期间的分配次数与字节数。
//! TLS 计数变量一律用 `const` 初始化（无 lazy 分配、无析构函数），因此在分配器内部
//! 访问是安全的（不会递归分配）。
//!
//! 这是本 crate 里唯一能"把分配次数钉死成数字"的手段，用来证明：
//! - `get_arc` 命中 0 次分配（旧 `get` 每次命中克隆整条 entry）；
//! - TinyLFU `clear()`/`restore()` 复用 4 KiB sketch 缓冲区后 0 次分配 0 字节；
//! - PartitionedCache 二元组 key 的读路径 0 次分配（旧 `split()` 固定 3 次）；
//! - `keys()` 用 `with_capacity` 精确预留，不发生 realloc。

use ebpdns_cache::{CacheEntry, CacheKey, DnsCache, LruCache, PartitionedCache, TinyLfuCache};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

const T0: f64 = 1_000.0;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCS: Cell<u64> = const { Cell::new(0) };
    static BYTES: Cell<u64> = const { Cell::new(0) };
}

struct CountingAlloc;

#[inline]
fn bump(layout: Layout) {
    // try_with：线程销毁/TLS 不可用时静默跳过（不 panic、不分配）。
    let _ = COUNTING.try_with(|c| {
        if c.get() {
            let _ = ALLOCS.try_with(|a| a.set(a.get().wrapping_add(1)));
            let _ = BYTES.try_with(|b| b.set(b.get().wrapping_add(layout.size() as u64)));
        }
    });
}

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        bump(layout);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        bump(layout);
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if let Ok(counted) = Layout::from_size_align(new_size, layout.align()) {
            bump(counted);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

struct Measure;

impl Measure {
    fn start() -> Self {
        COUNTING.with(|c| c.set(true));
        Self
    }
}

impl Drop for Measure {
    fn drop(&mut self) {
        COUNTING.with(|c| c.set(false));
    }
}

/// 统计 `f` 期间的 (分配次数, 分配字节数)。只计当前线程。
fn measure<R>(f: impl FnOnce() -> R) -> (R, u64, u64) {
    let a0 = ALLOCS.with(|a| a.get());
    let b0 = BYTES.with(|b| b.get());
    let out = {
        let _g = Measure::start();
        f()
    };
    let a1 = ALLOCS.with(|a| a.get());
    let b1 = BYTES.with(|b| b.get());
    (out, a1 - a0, b1 - b0)
}

fn e(domain: &str, ttl: f64, now: f64) -> CacheEntry {
    CacheEntry::new(domain, "A", ttl, now)
}

// ============================ C-07 get_arc vs get ============================

#[test]
fn c07_get_arc_hit_allocates_zero_times() {
    // 1 条 answer 的 entry 克隆 = 5 次分配（domain/qtype/answers-Vec/answer.value/chosen）。
    let lru = LruCache::new(64);
    let k = CacheKey::new("alloc-lru.test", "A");
    lru.put(k.clone(), e("alloc-lru.test", 600.0, T0), T0);

    let (hit, a_arc, b_arc) = measure(|| lru.get_arc(&k, T0));
    assert!(hit.is_some());
    assert_eq!(a_arc, 0, "get_arc 命中必须 0 次堆分配");
    assert_eq!(b_arc, 0, "get_arc 命中必须 0 字节分配");

    let (owned, a_get, _) = measure(|| lru.get(&k, T0));
    assert!(owned.is_some());
    assert_eq!(a_get, 5, "旧签名 get() 每次命中克隆整条 entry（5 次分配）");

    // TinyLFU：window 命中同样 0 分配。
    let tlf = TinyLfuCache::new(64);
    let k2 = CacheKey::new("alloc-tlfu.test", "A");
    tlf.put(k2.clone(), e("alloc-tlfu.test", 600.0, T0), T0);
    let (hit2, a2, b2) = measure(|| tlf.get_arc(&k2, T0));
    assert!(hit2.is_some());
    assert_eq!((a2, b2), (0, 0), "TinyLFU get_arc 命中必须 0 分配");
    let (_, a2g, _) = measure(|| tlf.get(&k2, T0));
    assert_eq!(a2g, 5, "TinyLFU get() 克隆 entry（5 次分配）");

    // Partitioned（二元组 key：运行期 resolver 的实际形态）0 分配。
    let pc = PartitionedCache::new(128, None);
    let k3 = CacheKey::new("alloc-part.test", "A");
    pc.put(k3.clone(), e("alloc-part.test", 600.0, T0), T0);
    let (hit3, a3, b3) = measure(|| pc.get_arc(&k3, T0));
    assert!(hit3.is_some());
    assert_eq!((a3, b3), (0, 0), "Partitioned 二元组 key 读路径必须 0 分配");
    let (_, a3g, _) = measure(|| pc.get(&k3, T0));
    assert_eq!(a3g, 5, "Partitioned get() 只克隆 entry");
}

#[test]
fn c07_serve_stale_arc_allocates_zero_times() {
    let lru = LruCache::new(64);
    lru.set_stale_window(3600);
    let k = CacheKey::new("alloc-stale.test", "A");
    lru.put(k.clone(), e("alloc-stale.test", 1.0, T0), T0);
    let now = T0 + 10.0;
    let (hit, a, b) = measure(|| lru.get_stale_arc(&k, now, 3600.0));
    assert!(hit.is_some());
    assert_eq!((a, b), (0, 0), "get_stale_arc 命中必须 0 分配");
    let (_, ag, _) = measure(|| lru.get_stale(&k, now, 3600.0));
    assert_eq!(ag, 5);
}

// ============================ C-05 sketch 缓冲区复用 ============================

#[test]
fn c05_tinylfu_clear_and_restore_allocate_nothing() {
    let tlf = TinyLfuCache::new(1024);
    for i in 0..64 {
        let d = format!("sk{i}.test");
        tlf.put(CacheKey::new(d.clone(), "A"), e(&d, 600.0, T0), T0);
    }
    // 旧实现 `inner.sketch = CmSketch::new()`：每次 clear/restore 分配 4096 字节
    // 并整体搬 4 KiB。现在 Box + `reset()` 原地填充 → 0 分配 0 字节。
    let (_, a_clear, b_clear) = measure(|| tlf.clear());
    assert_eq!(
        (a_clear, b_clear),
        (0, 0),
        "clear() 必须原地复用 sketch 缓冲区"
    );
    assert_eq!(tlf.len(), 0);

    // restore 同样（空输入；含 clear + sketch.reset）。
    let (_, a_rs, b_rs) = measure(|| tlf.restore(&[], T0, 0.0));
    assert_eq!(
        (a_rs, b_rs),
        (0, 0),
        "restore() 必须原地复用 sketch 缓冲区（旧实现每次分配 4096 字节）"
    );

    // 非空 restore 也要 0 分配在 sketch 上；这里只断言"没有 4 KiB 级分配"。
    let blob = {
        let src = TinyLfuCache::new(64);
        src.put(CacheKey::new("rs.test", "A"), e("rs.test", 60.0, T0), T0);
        src.serialize(T0)
    };
    let (_, _a_rs2, b_rs2) = measure(|| tlf.restore(&blob, T0, 0.0));
    assert!(
        b_rs2 < 4096,
        "restore 不应再分配 4 KiB 的 sketch 表（实测 {b_rs2} 字节）"
    );
}

// ============================ C-08 split 借用 ============================

#[test]
fn c08_partitioned_read_path_avoids_split_allocations() {
    let pc = PartitionedCache::new(128, None);
    let k = CacheKey::with_group("domestic", "c08.test", "A");
    pc.put(k.clone(), e("c08.test", 600.0, T0), T0);

    // 控制组：旧 `split()` 每步固定做的三件事 = 3 次分配。
    let g = "domestic".to_string();
    let domain = "c08.test".to_string();
    let qtype = "A".to_string();
    let (_, a_old, _) = measure(|| {
        let _g = g.clone();
        let _inner = CacheKey::new(domain.clone(), qtype.clone());
    });
    assert_eq!(a_old, 3, "旧 split() 的固定成本 = 3 次 String 分配");

    // 二元组 key（resolver 实际形态）：新读路径 0 次分配。
    let k2 = CacheKey::new("c08-plain.test", "A");
    pc.put(k2.clone(), e("c08-plain.test", 600.0, T0), T0);
    let (_, a_plain, _) = measure(|| pc.get_arc(&k2, T0));
    assert_eq!(a_plain, 0, "二元组 key 读路径不再有 split 分配");

    // 三元组 key：仍要剥掉 group（借用无法剥离），2 次分配（domain+qtype），
    // 但仍省掉了旧的 `g.clone()`（第 3 次）。
    let (_, a_group, _) = measure(|| pc.get_arc(&k, T0));
    assert_eq!(a_group, 2, "三元组 key 读路径只剩 domain/qtype 两次克隆");

    // put 路径完全避免 split 分配（key 已拥有所有权，就地剥 group）。
    // 用"更新已有键"来钉死成本：内层 OrderedMap 命中已有键 → 只 `Arc::new` 一次，
    // key 字符串一次都不克隆（旧实现这里还要多花 3 次 split 分配）。
    let kk = CacheKey::with_group("domestic", "c08-put.test", "A");
    pc.put(kk.clone(), e("c08-put.test", 600.0, T0), T0);
    let kk2 = kk.clone();
    let v2 = e("c08-put.test", 600.0, T0);
    // 闭包按需捕获：`kk2`/`v2` 被移动进闭包，`pc` 只被共享借用。
    let (_, a_upd, _) = measure(|| pc.put(kk2, v2, T0));
    assert_eq!(
        a_upd, 1,
        "更新已有键：只分配 Arc<CacheEntry>，key 字符串 0 克隆（实测 {a_upd}）"
    );

    // keys() 不再为每条记录克隆整组 key 字符串。
    let (keys, a_keys, _) = measure(|| pc.keys());
    let bound = 3 + 3 * keys.len() as u64;
    assert_eq!(keys.len(), 3);
    assert!(a_keys <= bound, "keys() 分配上界 {bound}，实测 {a_keys}");
}

// ============================ C-10 keys() 容量预留 ============================

#[test]
fn c10_keys_reserves_capacity_once() {
    const N: usize = 100;
    // 容量取远大于 N：保证 N 条全部留下（分片路由不会把任何一条挤掉），
    // 这样 keys() 的分配次数才是确定值。
    let lru = LruCache::new(1 << 20);
    for i in 0..N {
        let d = format!("cap{i}.test");
        lru.put(CacheKey::new(d.clone(), "A"), e(&d, 600.0, T0), T0);
    }
    assert_eq!(lru.len(), N);
    // keys()：1 次 Vec 分配（with_capacity(100) 恰好一次，无 realloc）
    // + 每个 CacheKey 克隆 2 次 String 分配 = 1 + 2N。
    // 旧实现 `Vec::new()` 会随增长 realloc ~7 次。
    let (keys, a, _) = measure(|| lru.keys());
    assert_eq!(keys.len(), N);
    assert_eq!(
        a,
        1 + 2 * N as u64,
        "keys() 必须一次到位（with_capacity），实测 {a} 次分配"
    );

    // TinyLFU 同型（三段合计 N；容量取大保证都落在 window）。
    let tlf = TinyLfuCache::new(1 << 20);
    for i in 0..N {
        let d = format!("tcap{i}.test");
        tlf.put(CacheKey::new(d.clone(), "A"), e(&d, 600.0, T0), T0);
    }
    assert_eq!(tlf.len(), N);
    let (keys2, a2, _) = measure(|| tlf.keys());
    assert_eq!(keys2.len(), N);
    assert_eq!(a2, 1 + 2 * N as u64, "TinyLFU keys() 必须一次到位");
}

#[test]
fn c10_keys_on_empty_cache_does_not_allocate() {
    let lru = LruCache::new(64);
    let (keys, a, _) = measure(|| lru.keys());
    assert!(keys.is_empty());
    assert_eq!(a, 0, "空缓存 with_capacity(0) 不应分配");
}

// ============================ entry 克隆成本基线 ============================

#[test]
fn baseline_entry_clone_cost_documented() {
    // 作为 C-07 的对照基线：一条 N=1 answer 的 entry 克隆成本 5 次分配；
    // 3 条 answer 时 = 4 + 3*1 = 7 次。这就是旧 `get()` 每次命中的代价。
    let one = e("base.test", 60.0, T0);
    let (_, a1, _) = measure(|| one.clone());
    assert_eq!(a1, 5);

    let mut three = e("base3.test", 60.0, T0);
    three.answers = vec![
        ebpdns_cache::CacheAnswer {
            value: "1.1.1.1".into(),
            ttl: 60.0,
            rtype: 1,
            name: None,
        };
        3
    ];
    let (_, a3, _) = measure(|| three.clone());
    assert_eq!(a3, 7, "3 条 answer 的 entry 克隆 = 7 次分配");
}
