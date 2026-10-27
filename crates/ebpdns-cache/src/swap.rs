//! **[历史归因]** 可热切换的缓存包装：语义等价于 Python `PUT /api/config` 里
//! 「切换 cache_policy / cache_size 后重建缓存对象并整体换引用」。
//!
//! 做法：内部持 `RwLock<Arc<dyn DnsCache>>`，所有 trait 方法转发给当前实现；
//! `swap()` 原子替换（旧实例由 Arc 自然回收），读端要么看到完整旧缓存、
//! 要么看到完整新缓存（对齐 cache.py 的 C-01 原子换引用）。
//!
//! ### 2.1.29（缓存持久化 v2）：本外壳新增的三件事
//!
//! 1. **`mutation_barrier`**（§6.1）：`put`/`delete`/`set_capacity` 取**读**守卫，
//!    `clear`/`swap`/`restore`/`restore_records` 取**写**守卫 ⇒ `seq` 的全序 =
//!    内存变更的全序。没有它会出现“`put` 在 `clear` 之后插入、却拿到更小 `seq`”
//!    ⇒ 回放先 PUT 后 CLEAR ⇒ **把新值清掉**。
//! 2. **`delete`/`clear` 在**外层**记录**（内层不再记，避免双记）。
//! 3. **`generation`**：`swap`/`restore` 递增；快照线程完成时若不匹配 ⇒ 丢弃 tmp
//!    （避免把旧策略的快照发布成新代）。
//!
//! ### C-06 评估：每方法 `current()`（读锁 + Arc 克隆）——保留现状
//!
//! 13 个方法的转发都先 `self.current()`，即 1 次 `parking_lot::RwLock::read`
//! 加 1 次 `Arc::clone`/`drop`（各 1 次 `fetch_add`/`fetch_sub`）。
//! 实测（Debian，8 核，release，`tests/cache_perf_probe.rs`）：
//! `current()` 单独约 28.6 ns/op；`SwappableCache::get_arc` 比直接
//! `dyn DnsCache::get_arc` 多约 10~27 ns/op，占单次缓存操作（约 330~600 ns）
//! 的 **3%~8%**。注意 `ebpdns-resolver` 持有的就是 `Arc<SwappableCache>`，
//! 每次 `get`/`put`/`get_stale` 都走这层转发，所以这确实是数据面开销。
//!
//! 可选"优化"是 `with(|c| ...)`：持读锁跑完整个操作以省掉 Arc 克隆。**不采用**：
//! (1) `serialize`/`restore`/`keys` 在 10 万条量级上要毫秒级，持读锁期间若有
//!     `swap()` 在等写锁，parking_lot 会让后续读锁排队（防写饥饿）——即一次
//!     `/api/snapshot` 的大序列化会**阻塞整个数据面的读**；
//! (2) 调用方不再持有独立句柄，swap 期间的语义保证被削弱（当前设计刻意让调用方
//!     在操作期间不受 swap 影响）。
//! 不新增依赖的前提下没有 `arc_swap` 级别的无锁方案（`AtomicPtr<dyn DnsCache>`
//! 需手写引用计数/退役，属 UB 风险区）。收益 3%~8%、代价是把长管理操作暴露成
//! 数据面停顿，故**保留现状**。
//!
//! `2.1.29` 的 `put` 多了一次 `RwLock::read`（约 20 ns，生产 ~1.2 put/s，可忽略）；
//! `get` **零新增开销**（不取守卫，也不碰 journal）。
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::RwLock;
use serde_json::Value;

use crate::persist::journal::{CacheJournal, ClearReason, EvictReason};
use crate::persist::PersistStats;
use crate::{CacheEntry, CacheKey, DnsCache};

/// 可热切换缓存。
pub struct SwappableCache {
    inner: RwLock<Arc<dyn DnsCache>>,
    /// **2.1.19（修复项 1 补漏：文件级损坏）**：当**整个文件**无法解析时，
    /// per-entry 的 `restore()` **根本不会被调用** ⇒ 内层三个丢弃计数会**保留上一次
    /// 的值**，`/api/status.cache.restore_drops` 于是显示 `failed: 0`（**说谎**）。
    ///
    /// 这里给外壳持一份"本次恢复是文件级失败"的记录：`Some((expired, legacy, failed))`
    /// 时 `last_restore_drops()` 返回它而**不**转发内层；一次真正的 `restore()`（无论
    /// 成功与否）都会把它清掉 ⇒ 读数永远反映**本次**结果，不可能是陈旧值。
    file_level: RwLock<Option<(u64, u64, u64)>>,
    // ---------------- 2.1.29：缓存持久化 v2（M16） ----------------
    /// journal（数据面 → actor 的唯一通道）。默认是 **disabled**，由
    /// `enable_journal()` 在启动序列里换成真正带 ring 的实例。
    journal: RwLock<Arc<CacheJournal>>,
    /// 持久化现场统计（**唯一来源**；`/api/status` 与 `/api/cache/stats` 读同一份）。
    stats: Arc<PersistStats>,
    /// 内容代际：`swap`/`restore` 递增；快照线程完成时用它对账。
    generation: AtomicU64,
    /// 变更屏障（见文件头说明 1）。
    mutation_barrier: RwLock<()>,
}

impl SwappableCache {
    pub fn new(inner: Arc<dyn DnsCache>) -> Self {
        Self {
            inner: RwLock::new(inner),
            file_level: RwLock::new(None),
            journal: RwLock::new(CacheJournal::disabled()),
            stats: PersistStats::new(),
            generation: AtomicU64::new(1),
            mutation_barrier: RwLock::new(()),
        }
    }

    /// 当前实现句柄（调用方持 Arc，期间不受 swap 影响）。
    pub fn current(&self) -> Arc<dyn DnsCache> {
        self.inner.read().clone()
    }

    /// 原子替换实现；返回被替换下来的旧实例（调用方可决定是否迁移数据）。
    ///
    /// **2.1.29**：写守卫覆盖“迁移 put + swap”；新实例装上**同一个** journal
    /// （否则热切换后的变更不进 WAL，崩溃会丢）；generation 递增。
    pub fn swap(&self, fresh: Arc<dyn DnsCache>) -> Arc<dyn DnsCache> {
        let _g = self.mutation_barrier.write();
        let j = self.journal.read().clone();
        fresh.attach_journal(j);
        self.generation.fetch_add(1, Ordering::Relaxed);
        let mut g = self.inner.write();
        // 换实现后旧的"文件级失败"记录不再适用（新实现有自己的计数）。
        *self.file_level.write() = None;
        std::mem::replace(&mut *g, fresh)
    }

    /// **2.1.19（修复项 1 补漏）**：记录一次**文件级**恢复失败（整个文件不可解析）。
    ///
    /// `failed` 语义 = "本次启动因文件不可用而丢失的记录数"，文件级失败时至少为 `1`
    /// （单位是"整个文件"）。调用后 `last_restore_drops()` 立即返回本次结果，
    /// 不再转发内层陈旧计数。
    pub fn record_file_level_failure(&self, failed: u64) {
        *self.file_level.write() = Some((0, 0, failed.max(1)));
    }

    /// **2.1.19（修复项 1 补漏）**：清除文件级记录（一次真正的 `restore()` 之后）。
    pub fn clear_file_level(&self) {
        *self.file_level.write() = None;
    }

    // ---------------- 2.1.29：持久化接缝 ----------------

    /// 当前的 journal（`disabled` 表示未启用持久化 / v1 模式）。
    pub fn journal(&self) -> Arc<CacheJournal> {
        self.journal.read().clone()
    }

    /// **启动序列调用一次**：创建带 ring 的 journal，装进当前实现，返回消费端。
    ///
    /// 返回的 `Receiver` 由 actor 独占（单写者，§6.4）。
    pub fn enable_journal(&self) -> std::sync::mpsc::Receiver<crate::persist::Event> {
        let (j, rx) = CacheJournal::new(Arc::clone(&self.stats));
        *self.journal.write() = Arc::clone(&j);
        self.current().attach_journal(j);
        rx
    }

    /// 现场统计（**总是**有值；与两个 API 端点同源）。
    pub fn persist_stats_arc(&self) -> Arc<PersistStats> {
        Arc::clone(&self.stats)
    }

    /// 内容代际（快照线程对账用）。
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    /// 带原因的整表清空（reason 只影响 WAL 诊断字段；回放语义都是“清空”）。
    pub fn clear_with_reason(&self, reason: ClearReason) {
        let _g = self.mutation_barrier.write();
        self.current().clear();
        let j = self.journal.read().clone();
        // **2.1.34（D1）**：`seq` 分配 + 入队必须原子（否则与并发 put 的 seq 顺序可回退）。
        let _order = j.order_guard();
        let s = j.next_seq();
        j.clear(reason, s);
    }
}

impl DnsCache for SwappableCache {
    fn get(&self, key: &CacheKey, now: f64) -> Option<CacheEntry> {
        self.current().get(key, now)
    }

    fn get_stale(&self, key: &CacheKey, now: f64, stale_window: f64) -> Option<CacheEntry> {
        self.current().get_stale(key, now, stale_window)
    }
    // >>> 242B BEGIN P1-9-swap >>> //
    /// **2.1.42-B（P1-9）**：转发到**当前**策略的 no-touch 读取。
    fn peek(&self, key: &CacheKey, now: f64) -> Option<CacheEntry> {
        self.current().peek(key, now)
    }
    // <<< 242B END P1-9-swap <<< //

    /// C-07：转发后仍是零拷贝（内层 `LruCache`/`TinyLfuCache` 覆写了 `get_arc`），
    /// 即调用方拿到的是缓存内部那个 `Arc<CacheEntry>` 本身。
    fn get_arc(&self, key: &CacheKey, now: f64) -> Option<Arc<CacheEntry>> {
        self.current().get_arc(key, now)
    }

    /// C-07：同 `get_arc`，serve-stale 路径零拷贝。
    fn get_stale_arc(
        &self,
        key: &CacheKey,
        now: f64,
        stale_window: f64,
    ) -> Option<Arc<CacheEntry>> {
        self.current().get_stale_arc(key, now, stale_window)
    }

    /// **2.1.29**：读守卫覆盖“内层 put + seq 分配”（§6.1 的总序）。
    /// journal 事件由**内层**发送（只有它知道 TinyLFU 是否真的接受了这次写入）。
    fn put(&self, key: CacheKey, value: CacheEntry, now: f64) {
        let _g = self.mutation_barrier.read();
        self.current().put(key, value, now);
    }

    /// **2.1.29**：`delete` 在**外层**记 `EVICT`（内层不记，避免双记）。
    ///
    /// **2.1.43-B（P2-2）**：事件键必须与 `PUT` **同源** —— 用当前实现的
    /// [`DnsCache::journal_key`] 归一（`PartitionedCache` 补分区名 ⇒ 3 元组）。
    /// 旧实现 `key.clone()` 直接落 2 元组，回放时删除落不到 PUT 的分区。
    fn delete(&self, key: &CacheKey) {
        let _g = self.mutation_barrier.read();
        // 同一个实现句柄必须同时用于"删内存"与"算落盘键"（热切换期间不能各取一次）。
        let cur = self.current();
        cur.delete(key);
        let j = self.journal.read().clone();
        if j.is_enabled() {
            // **2.1.34（D1）**：分配 + 入队原子化（与并发 put 共享同一总序临界区）。
            let _order = j.order_guard();
            let s = j.next_seq();
            j.evict(cur.journal_key(key), EvictReason::Explicit, s);
        }
    }

    /// **2.1.29**：`clear` 在**外层**记 `CLEAR`（内层不记）。
    ///
    /// 不记录会导致恢复时**复活整表**（group 语义/规则代际已变 ⇒ 复活是错的）。
    fn clear(&self) {
        self.clear_with_reason(ClearReason::Admin);
    }

    fn len(&self) -> usize {
        self.current().len()
    }

    fn keys(&self) -> Vec<CacheKey> {
        self.current().keys()
    }

    fn sample_keys(&self, limit: usize) -> Vec<CacheKey> {
        self.current().sample_keys(limit)
    }

    fn summary(&self) -> Value {
        self.current().summary()
    }

    fn serialize(&self, now: f64) -> Vec<Value> {
        self.current().serialize(now)
    }

    /// **2.1.25（B8）**：流式落盘透传给**当前**策略（热切换期间写出的仍是同一代快照）。
    fn write_snapshot(&self, now: f64, w: &mut dyn std::io::Write) -> std::io::Result<u64> {
        self.current().write_snapshot(now, w)
    }

    /// **2.1.25（B8）**：逐条产出透传给当前策略。
    fn for_each_snapshot_entry(&self, now: f64, f: &mut dyn FnMut(Value)) {
        self.current().for_each_snapshot_entry(now, f);
    }

    /// **2.1.29**：v2 快照的逐条产出（零拷贝 `Arc` 句柄）。
    fn for_each_entry(&self, now: f64, f: &mut dyn FnMut(&CacheKey, &Arc<CacheEntry>)) {
        self.current().for_each_entry(now, f);
    }

    /// **2.1.46（REV247 B P2-6）**：透传给当前策略；锁只覆盖收集、不覆盖写盘。
    fn collect_snapshot_entries(&self, now: f64) -> Vec<(CacheKey, Arc<CacheEntry>)> {
        self.current().collect_snapshot_entries(now)
    }

    fn restore(&self, entries: &[Value], now: f64, persist_ttl: f64) {
        // **2.1.19（修复项 1 补漏）**：一次真正的 per-entry 恢复之后，文件级记录必须清除
        // —— 否则 `last_restore_drops()` 会一直返回上一次的文件级失败（新的说谎方式）。
        self.clear_file_level();
        let _g = self.mutation_barrier.write();
        self.generation.fetch_add(1, Ordering::Relaxed);
        // 恢复不是“新变更”：回放/快照已经代表它（§6.1 hook 矩阵）。
        let j = self.journal.read().clone();
        j.suspend();
        self.current().restore(entries, now, persist_ttl);
        j.resume();
    }

    /// **2.1.29**：v2 一次性装入（TTL 已由 `persist::recover` 统一决策）。
    fn restore_records(&self, entries: Vec<(CacheKey, CacheEntry)>, now: f64) {
        self.clear_file_level();
        let _g = self.mutation_barrier.write();
        self.generation.fetch_add(1, Ordering::Relaxed);
        let j = self.journal.read().clone();
        j.suspend();
        self.current().restore_records(entries, now);
        j.resume();
    }

    fn set_capacity(&self, n: usize) {
        let _g = self.mutation_barrier.read();
        self.current().set_capacity(n);
    }

    fn set_stale_window(&self, v: u64) {
        self.current().set_stale_window(v);
    }

    /// **2.1.19（修复项 1）**：热切换外壳也透传可观测计数（切到哪个实现就看哪个）。
    ///
    /// **2.1.19（修复项 1 补漏）**：若本次恢复是**文件级**失败（整个 JSON 不可解析），
    /// per-entry 路径从未执行 ⇒ 内层计数是**上一次的陈旧值** ⇒ 必须优先返回外壳记录的
    /// 本次结果（`failed >= 1`），否则两端点会显示 `failed: 0`（说谎）。
    fn last_restore_drops(&self) -> (u64, u64, u64) {
        if let Some(v) = *self.file_level.read() {
            return v;
        }
        self.current().last_restore_drops()
    }

    /// **2.1.43-B（P2-4）**：透传"快照写了、恢复只灌 main 段 ⇒ 被挤出"的条数
    /// （切到哪个实现就看哪个；lru / partitioned 恒 0）。
    fn last_restore_window_unpersisted(&self) -> u64 {
        self.current().last_restore_window_unpersisted()
    }

    /// **2.1.19（修复项 1 补漏）**：trait 侧的"文件级恢复失败"入口
    /// （`main.rs::restore_cache` 通过 `Arc<SwappableCache>` 的固有方法调用；
    /// 这里同时实现 trait 版本，`Arc<dyn DnsCache>` 调用方也能用）。
    fn record_file_level_restore_failure(&self, failed: u64) {
        self.record_file_level_failure(failed);
    }

    /// **2.1.29**：两 API 端点读**同一份**现场统计（外壳持有，不转发 ——
    /// 内层实例在热切换后会被替换，转发会让读数在切换瞬间回退）。
    fn persist_stats(&self) -> Option<Arc<PersistStats>> {
        Some(Arc::clone(&self.stats))
    }

    /// **2.1.29**：把 journal 装进当前实现（热切换时 `swap` 已对新实例做过一次）。
    fn attach_journal(&self, j: Arc<CacheJournal>) {
        *self.journal.write() = Arc::clone(&j);
        self.current().attach_journal(j);
    }

    /// **2.1.29**：请求快照（策略热切换/迁移/管理动作）。
    fn request_snapshot(&self, reason: &'static str) {
        self.journal.read().request_snapshot(reason);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CacheEntry, LruCache, TinyLfuCache};

    /// **2.1.34（D1）回归**：4 写者并发 `put` 时，journal 的**入队顺序**必须与 `seq` 严格同序。
    ///
    /// 旧实现的 `seq` 在缓存锁内分配、`try_send` 在锁外 ⇒ 队列里会出现回退；WAL 读侧
    /// 把回退判成“中段损坏”后整段截断（实测 12k 突发丢 0.75–59%）。
    #[test]
    fn concurrent_puts_enqueue_in_seq_order() {
        let inner: Arc<dyn DnsCache> = Arc::new(TinyLfuCache::new(8192));
        let sw = Arc::new(SwappableCache::new(inner));
        let rx = sw.enable_journal();
        let now = 1_700_000_000.0;
        let mut hs = Vec::new();
        for t in 0..4 {
            let sw = Arc::clone(&sw);
            hs.push(std::thread::spawn(move || {
                for i in 0..500 {
                    let d = format!("d1-{t}-{i}.test");
                    sw.put(
                        CacheKey::new(&d, "A"),
                        CacheEntry::new(&d, "A", 60.0, now),
                        now,
                    );
                }
            }));
        }
        for h in hs {
            h.join().unwrap();
        }
        let mut last = 0u64;
        let mut n = 0usize;
        while let Ok(ev) = rx.try_recv() {
            let seq = ev.seq();
            assert!(
                seq > last,
                "入队顺序必须 == seq 顺序（seq={seq}, last={last}, n={n}）"
            );
            last = seq;
            n += 1;
        }
        assert!(n >= 2000, "4×500 次 put 至少应有 2000 条事件，实际 {n}");
    }

    #[test]
    fn swap_replaces_impl_and_keeps_api() {
        let a: Arc<dyn DnsCache> = Arc::new(LruCache::new(16));
        let sw = SwappableCache::new(a);
        assert_eq!(sw.len(), 0);
        let b: Arc<dyn DnsCache> = Arc::new(LruCache::new(64));
        let old = sw.swap(b);
        assert_eq!(old.summary()["capacity"], serde_json::json!(16));
        assert_eq!(sw.summary()["capacity"], serde_json::json!(64));
        sw.set_capacity(8);
        // `LruCache::set_capacity` 走 `clamp_capacity`（最小 16），故 8 会被钳到 16；
        // 断言钳制后的真实值而不是入参，避免把实现的合法下限当成缺陷。
        assert_eq!(sw.summary()["capacity"], serde_json::json!(16));
    }

    /// M16：`delete`/`clear` 在**外层**记录；`put` 由内层记录（不双记）。
    #[test]
    fn journal_records_outer_delete_and_clear_once() {
        let inner: Arc<dyn DnsCache> = Arc::new(LruCache::new(64));
        let sw = SwappableCache::new(inner);
        let rx = sw.enable_journal();
        let now = 1_700_000_000.0;
        sw.put(
            CacheKey::new("a.test", "A"),
            CacheEntry::new("a.test", "A", 60.0, now),
            now,
        );
        // 内层记录：1 条 PUT
        let ev = rx.try_recv().expect("应有一条 PUT");
        assert!(matches!(ev, crate::persist::Event::Put { .. }));
        assert!(rx.try_recv().is_err(), "put 不应双记");

        sw.delete(&CacheKey::new("a.test", "A"));
        let ev = rx.try_recv().expect("应有一条 EVICT");
        match ev {
            crate::persist::Event::Evict { key, .. } => assert_eq!(key.domain, "a.test"),
            other => panic!("期望 EVICT，得到 {other:?}"),
        }

        sw.clear();
        let ev = rx.try_recv().expect("应有一条 CLEAR");
        assert!(matches!(ev, crate::persist::Event::Clear { .. }));
        assert!(rx.try_recv().is_err());
    }

    /// 恢复期 journal 必须静默（回放/快照已代表这些条目）。
    #[test]
    fn restore_is_silent_in_journal() {
        let inner: Arc<dyn DnsCache> = Arc::new(LruCache::new(64));
        let sw = SwappableCache::new(inner);
        let rx = sw.enable_journal();
        let now = 1_700_000_000.0;
        let mut e = CacheEntry::new("a.test", "A", 60.0, now);
        e.expires_at = now + 60.0;
        sw.restore_records(vec![(CacheKey::new("a.test", "A"), e)], now);
        assert!(rx.try_recv().is_err(), "恢复不得产生 journal 事件");
        assert_eq!(sw.len(), 1);
    }

    #[test]
    fn swap_keeps_journal_and_bumps_generation() {
        let inner: Arc<dyn DnsCache> = Arc::new(LruCache::new(64));
        let sw = SwappableCache::new(inner);
        let rx = sw.enable_journal();
        let g0 = sw.generation();
        let fresh: Arc<dyn DnsCache> = Arc::new(LruCache::new(64));
        sw.swap(fresh);
        assert!(sw.generation() > g0);
        let now = 1_700_000_000.0;
        sw.put(
            CacheKey::new("b.test", "A"),
            CacheEntry::new("b.test", "A", 60.0, now),
            now,
        );
        let ev = rx.try_recv().expect("swap 后新实例必须仍写 journal");
        assert!(matches!(ev, crate::persist::Event::Put { .. }));
    }

    /// **2.1.43-B（P2-2）回归**：`PartitionedCache` 的 `PUT` 与 `EVICT` 必须由
    /// **同一函数**生成**同一个键**（3 元组含实际分区名）。
    ///
    /// 旧行为：内层写 `PUT [group,domain,qtype]`，外层 `delete` 记 `EVICT [domain,qtype]`
    /// ⇒ 回放时 EVICT 被 `resolve_group` 回退到 `default` 分区，删除落空 ⇒
    /// **已删除条目在重启后复活**。
    #[test]
    fn partitioned_put_and_evict_use_the_same_journal_key() {
        let inner: Arc<dyn DnsCache> = Arc::new(crate::PartitionedCache::new(256, None));
        let sw = SwappableCache::new(inner);
        let rx = sw.enable_journal();
        let now = 1_700_000_000.0;
        // 2 元组入口键（运行期 resolver 的 `CacheKey::new` 形态）：分区由实现决定。
        let k = CacheKey::new("same-key.test", "A");
        sw.put(
            k.clone(),
            CacheEntry::new("same-key.test", "A", 60.0, now),
            now,
        );
        sw.delete(&k);
        let mut put_key = None;
        let mut evict_key = None;
        while let Ok(ev) = rx.try_recv() {
            match ev {
                crate::persist::Event::Put { key, .. } => put_key = Some(key),
                crate::persist::Event::Evict { key, .. } => evict_key = Some(key),
                _ => {}
            }
        }
        let p = put_key.expect("PUT 事件");
        let e = evict_key.expect("EVICT 事件");
        assert_eq!(
            p, e,
            "PUT/EVICT 必须是同一个键（同函数生成）：PUT={p:?} EVICT={e:?}"
        );
        assert_eq!(
            p.group.as_deref(),
            Some("default"),
            "2 元组入口键必须补上实际分区名（resolve_group 回退 default）"
        );
        assert_eq!(sw.len(), 0, "EVICT 必须真的把 PUT 的条目删掉");
    }

    /// **2.1.46（REV247 覆盖不足 #8）**：非 `default` 分区的 PUT/EVICT 也必须
    /// 使用同一个 3 元组键。旧实现只测 `default` 回退，`domestic/global` 未覆盖。
    #[test]
    fn partitioned_non_default_group_put_and_evict_share_journal_key() {
        let inner: Arc<dyn DnsCache> = Arc::new(crate::PartitionedCache::new(256, None));
        let sw = SwappableCache::new(inner);
        let rx = sw.enable_journal();
        let now = 1_700_000_000.0;
        let k = CacheKey::with_group("domestic", "group-key.test", "A");
        sw.put(
            k.clone(),
            CacheEntry::new("group-key.test", "A", 60.0, now),
            now,
        );
        sw.delete(&k);
        let mut put_key = None;
        let mut evict_key = None;
        while let Ok(ev) = rx.try_recv() {
            match ev {
                crate::persist::Event::Put { key, .. } => put_key = Some(key),
                crate::persist::Event::Evict { key, .. } => evict_key = Some(key),
                _ => {}
            }
        }
        let p = put_key.expect("PUT 事件");
        let e = evict_key.expect("EVICT 事件");
        assert_eq!(
            p, e,
            "非默认分区的 PUT/EVICT 键必须一致：PUT={p:?} EVICT={e:?}"
        );
        assert_eq!(
            p.group.as_deref(),
            Some("domestic"),
            "键必须保留实际分区名（不得回退 default）"
        );
        assert_eq!(sw.len(), 0, "EVICT 必须真的把 domestic 分区的条目删掉");
    }
}
