//! **2.1.46（REV247 P2-4）**：`sample_keys(500)` 在 `s3fifo` 策略下必须**早停**，
//! 不得 `keys()` 全量克隆后再截断。
//!
//! **2.1.50（阶段 2）**：`tinylfu` 已移除，原先针对它的专测一并删除；s3fifo 用例
//! （委托内层 LruCache 的采样路径）保留并继续作为早停判据。
//!
//! 判别方式：进程级计数分配器。先灌 20 000 条，清零计数，再采样 500 条：
//! * 新实现：约 500×3 个 `String` + Vec（≈ 2 000 次分配）；
//! * 旧实现（trait 默认 `keys().truncate`）：20 000×3 个 `String`（≥ 60 000 次分配）。
//!
//! 阈值 10 000 足以稳定区分两者，又不受哈希表/锁的少量临时分配影响。

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};

use ebpdns_cache::{CacheEntry, CacheKey, DnsCache, S3FifoCache};

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

/// **2.1.49-p2**：计数分配器是**进程级**的 —— 两个用例并行执行时，彼此的分配会串进
/// 对方的计数窗口（实测 `*_sample_keys_*` 在 `cargo test --workspace` 并行时 flaky）。
/// 用一把测试级锁把两个用例串行化（`--test-threads=1` 亦可，但锁对调用方零要求）。
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
fn s3fifo_sample_keys_stops_at_limit() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let c = S3FifoCache::new(30_000);
    fill(&c, 20_000);
    // 容量 30k > 插入 20k ⇒ 无淘汰；只需确保样本池 >> limit。
    assert!(c.len() > 10_000, "样本池太小：len={}", c.len());
    assert_early_stop(&c);
}
