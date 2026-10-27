//! **数据面 → actor 的 journal**（§6.1）。
//!
//! **数据面从不等待磁盘**：`put/delete/clear` 在缓存锁内完成内存变更并分配 `seq`，
//! 出锁后只有一次 `try_send`。有界 ring（[`super::JOURNAL_RING`]）满了就
//! **丢事件 + 置 `needs_resync` + 计数**，由 actor 下一拍直接做全量快照（快照是权威）。
//!
//! **`seq` 分配与 journal 开关解耦**（M/N7）：即使 `cache_save_interval=0` 关闭了
//! journal，`entry.seq` 仍要正确递增 —— 否则后续开启持久化时 seq 会与历史记录冲突。

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::Arc;

use super::PersistStats;
use crate::{CacheEntry, CacheKey};

/// 显式逐出的原因（`EVICT.reason`，§5.4.2）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvictReason {
    /// 容量逐出（LRU 队首 / TinyLFU probation 队首 / 分区裁剪）—— **必须记录**，
    /// 否则回放后集合与崩溃前不同 ⇒ 命中率漂移。
    Capacity,
    /// 规则代际不匹配的显式删除。
    RuleGen,
    /// 管理面删除。
    Admin,
    /// 其它显式删除。
    Explicit,
    /// `set_capacity` 收缩裁剪。
    Resize,
}

impl EvictReason {
    pub fn code(self) -> u8 {
        match self {
            EvictReason::Capacity => super::wal::R_CAPACITY,
            EvictReason::RuleGen => super::wal::R_RULE_GEN,
            EvictReason::Admin => super::wal::R_ADMIN,
            EvictReason::Explicit => super::wal::R_EXPLICIT,
            EvictReason::Resize => super::wal::R_RESIZE,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            EvictReason::Capacity => "capacity",
            EvictReason::RuleGen => "rule_gen",
            EvictReason::Admin => "admin",
            EvictReason::Explicit => "explicit",
            EvictReason::Resize => "resize",
        }
    }
}

/// 整表清空的原因（`CLEAR.reason`）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClearReason {
    GroupFlip,
    Admin,
    PolicySwap,
    Resync,
}

impl ClearReason {
    pub fn code(self) -> u8 {
        match self {
            ClearReason::GroupFlip => super::wal::C_GROUP_FLIP,
            ClearReason::Admin => super::wal::C_ADMIN,
            ClearReason::PolicySwap => super::wal::C_POLICY_SWAP,
            ClearReason::Resync => super::wal::C_RESYNC,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            ClearReason::GroupFlip => "group_flip",
            ClearReason::Admin => "admin",
            ClearReason::PolicySwap => "policy_swap",
            ClearReason::Resync => "resync",
        }
    }
}

/// 一次缓存变更。**只有“真实存在的状态变更”才产生事件**（TinyLFU 拒绝不记）。
#[derive(Debug)]
pub enum Event {
    Put {
        seq: u64,
        key: CacheKey,
        entry: Arc<CacheEntry>,
    },
    Evict {
        seq: u64,
        key: CacheKey,
        reason: EvictReason,
    },
    Clear {
        seq: u64,
        reason: ClearReason,
    },
}

impl Event {
    pub fn seq(&self) -> u64 {
        match self {
            Event::Put { seq, .. } | Event::Evict { seq, .. } | Event::Clear { seq, .. } => *seq,
        }
    }
}

/// 有界 journal。`SwappableCache` 持一份 `Arc`，三条策略通过 `attach_journal` 共享。
pub struct CacheJournal {
    tx: Option<SyncSender<Event>>,
    /// 下一个要分配的 seq（**始终递增**，与开关无关）。
    next_seq: AtomicU64,
    /// `> 0` 时静默（恢复/迁移期间不是“新变更”）。
    suspended: AtomicUsize,
    enabled: AtomicBool,
    dropped: AtomicU64,
    needs_resync: AtomicBool,
    /// 待处理的快照请求（`request_snapshot`）；`&'static str` = reason。
    snapshot_req: parking_lot::Mutex<Option<&'static str>>,
    /// **2.1.34（D1）**：「`seq` 分配 + 事件入队」的总序临界区。
    ///
    /// 数据面此前在缓存锁内分配 `seq`、**出锁后**才 `try_send` ⇒ 并发线程可以
    /// “先拿小 seq、后入队”，队列顺序 ≠ `seq` 顺序；WAL 读侧把回退判成
    /// “中段损坏”后整段截断 ⇒ 静默丢条目。
    ///
    /// 现在所有会写 WAL 的路径（TinyLFU/LRU `put`、`set_capacity`、`delete`、`clear`）
    /// 都在**同一把锁**内完成“分配 + 入队”。锁序固定为
    /// `缓存锁(/mutation_barrier) → order → journal 队列`，任何路径都不得反向持有。
    order: parking_lot::Mutex<()>,
    stats: Arc<PersistStats>,
}

impl CacheJournal {
    /// 构造 + 返回消费端（由 actor 独占）。
    pub fn new(stats: Arc<PersistStats>) -> (Arc<Self>, Receiver<Event>) {
        let (tx, rx) = sync_channel(super::JOURNAL_RING);
        (
            Arc::new(Self {
                tx: Some(tx),
                next_seq: AtomicU64::new(0),
                suspended: AtomicUsize::new(0),
                enabled: AtomicBool::new(true),
                dropped: AtomicU64::new(0),
                needs_resync: AtomicBool::new(false),
                snapshot_req: parking_lot::Mutex::new(None),
                order: parking_lot::Mutex::new(()),
                stats,
            }),
            rx,
        )
    }

    /// 关闭 journal（`cache_save_interval=0` / v1 模式 / 只读恢复）。
    ///
    /// `seq` 仍然递增 —— 语义是“没有持久化”，不是“没有变更序号”。
    pub fn disabled() -> Arc<Self> {
        Arc::new(Self {
            tx: None,
            next_seq: AtomicU64::new(0),
            suspended: AtomicUsize::new(0),
            enabled: AtomicBool::new(false),
            dropped: AtomicU64::new(0),
            needs_resync: AtomicBool::new(false),
            snapshot_req: parking_lot::Mutex::new(None),
            order: parking_lot::Mutex::new(()),
            stats: Arc::new(PersistStats::default()),
        })
    }

    pub fn enable(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// 分配下一个 `seq`（从 1 开始）。
    ///
    /// **必须在内存变更完成之后调用**（§6.1 的顺序证明）：只有“变更完成 → 分配 seq”
    /// 才能保证 `seq <= snapshot_seq` ⇒ 快照迭代一定看得见它。
    #[inline]
    pub fn next_seq(&self) -> u64 {
        self.next_seq.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// 让下一个 `next_seq()` 至少返回 `v`（恢复后避免与历史记录冲突）。
    pub fn set_next_seq_at_least(&self, v: u64) {
        let mut cur = self.next_seq.load(Ordering::Relaxed);
        while cur < v {
            match self
                .next_seq
                .compare_exchange_weak(cur, v, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
    }

    pub fn current_seq(&self) -> u64 {
        self.next_seq.load(Ordering::Relaxed)
    }

    /// **2.1.34（D1）**：取“总序”守卫 —— 守卫存活期间完成 `next_seq()` + `put/evict/clear`
    /// 的入队，保证**队列顺序 == seq 顺序**（WAL 因此单调，恢复不再误判损坏）。
    ///
    /// 锁序：缓存锁 → 本守卫 → journal 队列。**禁止**在持有本守卫时再去拿缓存锁。
    #[inline]
    pub fn order_guard(&self) -> parking_lot::MutexGuard<'_, ()> {
        self.order.lock()
    }

    /// 恢复/迁移期间静默（不是新变更；回放/快照已代表它）。
    pub fn suspend(&self) {
        self.suspended.fetch_add(1, Ordering::Relaxed);
    }

    pub fn resume(&self) {
        // 不用 `fetch_update`（新版 std 已把它改名为 `try_update`，跨工具链不稳定）。
        let cur = self.suspended.load(Ordering::Relaxed);
        if cur > 0 {
            let _ = self.suspended.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn is_suspended(&self) -> bool {
        self.suspended.load(Ordering::Relaxed) > 0
    }

    fn send(&self, ev: Event) {
        if !self.enabled.load(Ordering::Relaxed) || self.is_suspended() {
            return;
        }
        let Some(tx) = &self.tx else {
            return;
        };
        match tx.try_send(ev) {
            Ok(()) => {}
            // 满 / 断连 ⇒ **绝不阻塞数据面**：丢事件 + 计数 + 标记需要重同步。
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                self.stats.note_journal_dropped(1);
                self.needs_resync.store(true, Ordering::Relaxed);
            }
        }
    }

    /// 记一次成功的 `put`（仅在策略**确认插入成功后**调用）。
    pub fn put(&self, key: CacheKey, entry: Arc<CacheEntry>, seq: u64) {
        self.send(Event::Put { seq, key, entry });
    }

    /// 记一次显式逐出。
    pub fn evict(&self, key: CacheKey, reason: EvictReason, seq: u64) {
        self.send(Event::Evict { seq, key, reason });
    }

    /// 记一次整表清空。
    pub fn clear(&self, reason: ClearReason, seq: u64) {
        self.send(Event::Clear { seq, reason });
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// 取走“需要重同步”标记（actor 每拍检查）。
    pub fn take_needs_resync(&self) -> bool {
        self.needs_resync.swap(false, Ordering::Relaxed)
    }

    pub fn needs_resync(&self) -> bool {
        self.needs_resync.load(Ordering::Relaxed)
    }

    /// 请求一次快照（策略热切换/迁移/管理动作）；actor 下一拍执行。
    pub fn request_snapshot(&self, reason: &'static str) {
        *self.snapshot_req.lock() = Some(reason);
    }

    pub fn take_snapshot_request(&self) -> Option<&'static str> {
        self.snapshot_req.lock().take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CacheEntry;

    fn e() -> CacheEntry {
        CacheEntry::new("a.test", "A", 60.0, 1_700_000_000.0)
    }

    #[test]
    fn seq_is_monotonic_and_starts_at_one() {
        let (j, _rx) = CacheJournal::new(PersistStats::new());
        assert_eq!(j.next_seq(), 1);
        assert_eq!(j.next_seq(), 2);
        assert_eq!(j.current_seq(), 2);
        j.set_next_seq_at_least(100);
        assert_eq!(j.next_seq(), 101);
        // 不能后退
        j.set_next_seq_at_least(5);
        assert_eq!(j.next_seq(), 102);
    }

    #[test]
    fn seq_still_increments_when_disabled() {
        // M/N7：关闭 journal（interval=0）时 `entry.seq` 仍必须递增。
        let j = CacheJournal::disabled();
        assert_eq!(j.next_seq(), 1);
        assert_eq!(j.next_seq(), 2);
        assert!(!j.is_enabled());
        j.put(CacheKey::new("a", "A"), Arc::new(e()), 1); // 不 panic、不入队
    }

    #[test]
    fn suspension_silences_events() {
        let (j, rx) = CacheJournal::new(PersistStats::new());
        j.suspend();
        j.put(CacheKey::new("a", "A"), Arc::new(e()), 1);
        assert!(rx.try_recv().is_err());
        j.resume();
        j.put(CacheKey::new("a", "A"), Arc::new(e()), 2);
        assert_eq!(rx.try_recv().map(|ev| ev.seq()), Ok(2));
    }

    #[test]
    fn overflow_drops_and_flags_resync() {
        let (j, _rx) = CacheJournal::new(PersistStats::new());
        // 填满 ring（+1 触发 Full）。
        for i in 0..(super::super::JOURNAL_RING as u64 + 8) {
            j.put(
                CacheKey::new(format!("d{i}"), "A"),
                Arc::new(e()),
                j.next_seq(),
            );
        }
        assert!(j.dropped() >= 8, "应至少丢弃 8 条，实际 {}", j.dropped());
        assert!(j.take_needs_resync());
        assert!(!j.take_needs_resync());
        assert!(j.stats.journal_dropped() >= 8);
    }

    #[test]
    fn snapshot_request_is_taken_once() {
        let (j, _rx) = CacheJournal::new(PersistStats::new());
        assert_eq!(j.take_snapshot_request(), None);
        j.request_snapshot("policy_swap");
        assert_eq!(j.take_snapshot_request(), Some("policy_swap"));
        assert_eq!(j.take_snapshot_request(), None);
    }

    #[test]
    fn disconnected_does_not_panic() {
        let (j, rx) = CacheJournal::new(PersistStats::new());
        drop(rx);
        for i in 0..10 {
            j.put(
                CacheKey::new(format!("d{i}"), "A"),
                Arc::new(e()),
                j.next_seq(),
            );
        }
        assert!(j.dropped() >= 1);
        assert!(j.needs_resync());
    }
}
