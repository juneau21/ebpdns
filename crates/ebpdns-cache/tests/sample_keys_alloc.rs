//! **2.1.46（REV247 P2-4）**：`sample_keys(500)` 在默认 `tinylfu` 与 `partitioned`
//! 策略下必须**早停**，不得 `keys()` 全量克隆后再截断。
//!
//! 判别方式：进程级计数分配器。先灌 20 000 条，清零计数，再采样 500 条：
//! * 新实现：约 500×3 个 `String` + Vec（≈ 2 000 次分配）；
//! * 旧实现（trait 默认 `keys().truncate`）：20 000×3 个 `String`（≥ 60 000 次分配）。
//!
//! 阈值 10 000 足以稳定区分两者，又不受哈希表/锁的少量临时分配影响。

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};

use ebpdns_cache::{CacheEntry, CacheKey, DnsCache, PartitionedCache, TinyLfuCache};

struct CountingAlloc;

static ALLOCS: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static A: CountingAlloc = CountingAlloc;

fn fill<C: DnsCache>(c: &C, n: usize) {
    let now = 1_700_000_000.0;
    for i in 0..n {
        let d = format!("alloc{i}.test");
        let mut e = CacheEntry::new(&d, "A", 300.0, now);
        e.expires_at = now + 300.0;
        c.put(CacheKey::new(&d, "A"), e, now);
    }
}

fn assert_early_stop<C: DnsCache>(c: &C) {
    let before = ALLOCS.load(Ordering::Relaxed);
    let keys = c.sample_keys(500);
    let allocs = ALLOCS.load(Ordering::Relaxed) - before;
    assert_eq!(keys.len(), 500, "样本数必须恰为 limit");
    assert!(
        allocs < 10_000,
        "sample_keys(500) 分配了 {allocs} 次（旧实现全量克隆 20k×3 个 String 会 >60k）"
    );
}

#[test]
fn tinylfu_sample_keys_stops_at_limit() {
    let c = TinyLfuCache::new(30_000);
    fill(&c, 20_000);
    assert_eq!(c.len(), 20_000);
    assert_early_stop(&c);
}

#[test]
fn partitioned_sample_keys_stops_at_limit() {
    let c = PartitionedCache::new(30_000, None);
    fill(&c, 20_000);
    // 权重 20/20/60 ⇒ 插入 20k 后总容量 30k 仍有淘汰；只需确保样本池 >> limit。
    assert!(c.len() > 10_000, "样本池太小：len={}", c.len());
    assert_early_stop(&c);
}
