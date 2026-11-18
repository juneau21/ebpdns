//! 堆分配次数量化测试（C-05/C-07/C-08/C-10）。
//!
//! 用自定义 `#[global_allocator]` 统计**当前线程**在指定闭包期间的分配次数与字节数。
//! TLS 计数变量一律用 `const` 初始化（无 lazy 分配、无析构函数），因此在分配器内部
//! 访问是安全的（不会递归分配）。
//!
//! 这是本 crate 里唯一能"把分配次数钉死成数字"的手段，用来证明：
//! - `get_arc` 命中 0 次分配（旧 `get` 每次命中克隆整条 entry）；
//! - S3FIFO 的 `keys()` 与 LRU 同型（`with_capacity` 一次到位，见 c10）；
//! - （历史）分区策略已移除，其 `split()` 分配回归随实现一并删除；
//! - `keys()` 用 `with_capacity` 精确预留，不发生 realloc。
//!
//! **阶段 B-2（RRset 对象级缓存）**：`CacheEntry.rrsets` 是 `Vec<Arc<Rrset>>`，
//! `CacheEntry::clone()` 只克隆这个 **Vec**（1 次分配，长度 = RRset 个数）并做
//! `Arc` 引用计数自增，**不复制任何答案内容**。因此 `get()` 每次命中的分配次数
//! 由 3 升到 **4**（domain/qtype/chosen 三个 `String` + rrsets Vec），且**与答案
//! 条数无关**（旧实现 3 条答案时是 7 次）。断言数字随模型更新，断言的**语义**
//! 不变：`get_arc` 仍然 0 分配，`get` 仍然只克隆条目。

use ebpdns_cache::{CacheEntry, CacheKey, DnsCache, LruCache, S3FifoCache};
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
    // **阶段 B-2**：entry 克隆 = 4 次分配（domain/qtype/chosen 三个 String +
    // `rrsets` 的 Vec 外壳）；Vec 里只有 `Arc<Rrset>` 的引用计数自增。
    let lru = LruCache::new(64);
    let k = CacheKey::new("alloc-lru.test", "A");
    lru.put(k.clone(), e("alloc-lru.test", 600.0, T0), T0);

    let (hit, a_arc, b_arc) = measure(|| lru.get_arc(&k, T0));
    assert!(hit.is_some());
    assert_eq!(a_arc, 0, "get_arc 命中必须 0 次堆分配");
    assert_eq!(b_arc, 0, "get_arc 命中必须 0 字节分配");

    let (owned, a_get, _) = measure(|| lru.get(&k, T0));
    assert!(owned.is_some());
    assert_eq!(
        a_get, 4,
        "get() 每次命中克隆 entry 的 3 个 String + 1 个 rrsets Vec 外壳（RRset 内容共享，0 分配）"
    );
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
    assert_eq!(
        ag, 4,
        "get_stale() 与 get() 同型：3 个 String + 1 个 rrsets Vec 外壳"
    );
}

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

    // S3FIFO 同型（委托内层 LruCache；容量取大保证 N 条全部留下）。
    let s3 = S3FifoCache::new(1 << 20);
    for i in 0..N {
        let d = format!("tcap{i}.test");
        s3.put(CacheKey::new(d.clone(), "A"), e(&d, 600.0, T0), T0);
    }
    assert_eq!(s3.len(), N);
    let (keys2, a2, _) = measure(|| s3.keys());
    assert_eq!(keys2.len(), N);
    assert_eq!(a2, 1 + 2 * N as u64, "S3FIFO keys() 必须一次到位");
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
    // 作为 C-07 的对照基线：`CacheEntry::clone()` = 4 次分配（domain/qtype/chosen
    // 三个 String + 1 个 `rrsets` Vec 外壳）—— **阶段 B-2 之后与答案条数无关**：
    // RRset 是共享 `Arc`，克隆只做引用计数自增，Vec 长度只随 RRset **个数**增长。
    // 这就是 `get()` 每次命中的代价（旧实现：1 条 answer 5 次、3 条 7 次）。
    let one = e("base.test", 60.0, T0);
    let (_, a1, _) = measure(|| one.clone());
    assert_eq!(a1, 4);

    let mut three = e("base3.test", 60.0, T0);
    let flat: Vec<ebpdns_cache::CacheAnswer> = (0..3)
        .map(|_| ebpdns_cache::CacheAnswer {
            value: "1.1.1.1".into(),
            ttl: 60.0,
            rtype: 1,
            name: None,
        })
        .collect();
    three.rrsets = ebpdns_cache::rrset::rrsets_from_flat(&flat);
    let (_, a3, _) = measure(|| three.clone());
    assert_eq!(
        a3, 4,
        "3 条同 owner/rtype 的 answer 合成 1 个 RRset ⇒ entry 克隆仍是 4 次分配"
    );
}
