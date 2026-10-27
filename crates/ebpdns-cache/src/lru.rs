//! **[历史归因]** 分片 LRU 缓存，对齐 Python `LRUCache`（cache.py:49-357）。
//!
//! 内部 8 个独立分片，每分片一把锁 + 一个 [`OrderedMap`]。按 key 哈希路由分片，
//! 不同 key 可并行读写。TTL 过期采用"队首连续快路径 + 轮转游标抽样"的惰性回收。

use crate::entry::{CacheEntry, CacheKey};
use crate::ordered_map::OrderedMap;
use crate::persist::journal::{CacheJournal, EvictReason};
use crate::persist::PersistStats;
use crate::util::{
    clamp_capacity, has_absolute_expiry, is_legacy_format, resolve_restored_expiry, round1,
    safe_float, structural_check,
};
use crate::{hash_key, DnsCache};
use parking_lot::{Mutex, RwLock};
use serde_json::{json, Map, Value};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

/// 分片数（**单一来源**：Web 控制台「缓存策略说明」里的分桶数就是它）。
///
/// 为什么导出为 `pub`：2.1.19 起有一条**机器可校验**的文档一致性回归
/// （`crates/ebpdns-cache/tests/doc_consistency_tests.rs`）会拿这个常量核对
/// `web/src/pages/config.rs` 里的用户可见文案，避免"文案写 8、实现改成 16"这类漂移。
pub const SHARDS: usize = 8;

// **2.1.18（修复项 23）**：`restore` 的**丢弃计数**是**每实例**字段
// （`RESTORE_DROPPED_*` → `LruCache::restore_dropped_*`），不是进程级 static ——
// 后者在并行测试下会被其他用例覆盖（实测：6 passed / 1 failed 的假失败）。
//
// 语义：`expired` = 文件里的绝对到期时间已过而丢弃；`legacy` = 旧格式
// （只有 `remaining`、无绝对 `expires_at`）按安全侧丢弃。两者都有对应的
// INFO/WARN 日志（在同一个代码块里赋值 + 打日志，因此断言计数等价于断言分支被走到）。
const PURGE_SCAN_STEP: usize = 64;

struct Shard {
    cap: usize,
    /// C-07：存 `Arc<CacheEntry>` 而非 `CacheEntry`，命中时 `get_arc` 只做引用计数
    /// 自增；`get` 仍在返回前克隆一次以保持既有签名。
    map: OrderedMap<CacheKey, Arc<CacheEntry>>,
    put_count: u64,
    purge_cursor: usize,
}

impl Shard {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            map: OrderedMap::new(),
            put_count: 0,
            purge_cursor: 0,
        }
    }
}

/// 分片 LRU 缓存。
pub struct LruCache {
    /// 最近一次 `restore` 因**绝对到期已过**而丢弃的条数（诊断/测试用）。
    restore_dropped_expired: AtomicU64,
    /// 最近一次 `restore` 因**旧格式**（无绝对 `expires_at`）而丢弃的条数。
    restore_dropped_legacy: AtomicU64,
    /// **2.1.19（修复项 1）**：最近一次 `restore` 因**记录损坏**
    /// （既无绝对 `expires_at`、也无 `remaining`，或反序列化失败）而丢弃的条数。
    restore_failed: AtomicU64,
    total_cap: AtomicUsize,
    shards: Vec<Mutex<Shard>>,
    stale_window: AtomicU64,
    // ---------------- 2.1.29：缓存持久化 v2 的接缝（M4） ----------------
    /// journal：运行期变更 → actor。`None` = 测试/未启用（`put` 零开销）。
    journal: RwLock<Option<Arc<CacheJournal>>>,
    /// 本内层实例所属的分区名（`PartitionedCache` 用它把 2 元组键补回 3 元组，
    /// 否则 WAL/快照里会丢掉 group 维，回放后键不相等 ⇒ 命中率下降）。
    group: Option<String>,
    /// 持久化现场统计（与外壳 `SwappableCache` **同一份**）。
    stats: Arc<PersistStats>,
}

impl LruCache {
    /// 构造。容量经 `max(16, ...)` 钳制后 divmod 到 8 分片。
    pub fn new(capacity: usize) -> Self {
        Self::with_group(capacity, None)
    }

    /// **2.1.29（v2）**：带分区名的构造（`PartitionedCache` 的内层用）。
    ///
    /// `group` 只影响**日志事件的键形态**（2 元组 → 3 元组）；分片路由仍用二元组键。
    pub fn with_group(capacity: usize, group: Option<String>) -> Self {
        let cap = clamp_capacity(Some(capacity));
        let base = cap / SHARDS;
        let rem = cap % SHARDS;
        let shards = (0..SHARDS)
            .map(|i| {
                let c = base + if i < rem { 1 } else { 0 };
                Mutex::new(Shard::new(c))
            })
            .collect();
        Self {
            total_cap: AtomicUsize::new(cap),
            shards,
            restore_dropped_expired: AtomicU64::new(0),
            restore_dropped_legacy: AtomicU64::new(0),
            restore_failed: AtomicU64::new(0),
            stale_window: AtomicU64::new(0),
            journal: RwLock::new(None),
            group,
            stats: PersistStats::new(),
        }
    }

    /// **2.1.29（v2）**：注入现场统计（由外壳 `SwappableCache` 下发同一份）。
    pub fn with_stats(mut self, stats: Arc<PersistStats>) -> Self {
        self.stats = stats;
        self
    }

    /// 把内层二元组键补成对外的键形态（有 group 时补 group）。
    ///
    /// **2.1.43-B（P2-2）**：本函数是**落盘键形态的唯一构造点**（经
    /// [`DnsCache::journal_key`] 暴露）。`PUT` 与 `EVICT` 必须由**同一个**函数生成键，
    /// 否则 `PartitionedCache` 会出现「PUT 写 3 元组、外层 `delete` 记 2 元组」⇒
    /// 回放时 EVICT 落不到同一条目（先删后复活）。
    fn expand_key(&self, mut k: CacheKey) -> CacheKey {
        if let Some(g) = &self.group {
            k.group = Some(g.clone());
        }
        k
    }

    #[inline]
    fn journal_snapshot(&self) -> Option<Arc<CacheJournal>> {
        self.journal.read().clone()
    }

    #[inline]
    fn shard_index(&self, key: &CacheKey) -> usize {
        (hash_key(key) as usize) & (SHARDS - 1)
    }

    #[inline]
    fn stale_window_f64(&self) -> f64 {
        self.stale_window.load(Ordering::Relaxed) as f64
    }

    /// 分片内淘汰：超过本分片容量则从 head(LRU) 弹出。**逐出的键**收进 `out`
    /// （v2 要为它们写 `EVICT(reason=CAPACITY)`，否则回放后集合与崩溃前不同）。
    fn evict_locked(shard: &mut Shard, out: &mut Vec<CacheKey>) {
        while shard.map.len() > shard.cap {
            match shard.map.pop_front() {
                Some((k, _)) => out.push(k),
                None => break,
            }
        }
    }
}

impl DnsCache for LruCache {
    /// **2.1.43-B（P2-2）**：`PUT` / `EVICT` / 快照共用的**唯一**键构造函数
    /// （`PartitionedCache` 的内层在这里把 2 元组补回 3 元组）。
    fn journal_key(&self, key: &CacheKey) -> CacheKey {
        self.expand_key(key.clone())
    }

    fn get(&self, key: &CacheKey, now: f64) -> Option<CacheEntry> {
        // 保持既有签名：这里必须克隆一份拥有所有权的条目。
        self.get_arc(key, now).map(|e| (*e).clone())
    }

    fn get_stale(&self, key: &CacheKey, now: f64, stale_window: f64) -> Option<CacheEntry> {
        self.get_stale_arc(key, now, stale_window)
            .map(|e| (*e).clone())
    }
    // >>> 242B BEGIN P1-9-lru >>> //
    /// **2.1.42-B（P1-9）**：不触碰的读取（不 `move_to_end`、不删过期项）。
    fn peek(&self, key: &CacheKey, now: f64) -> Option<CacheEntry> {
        let i = self.shard_index(key);
        let mut shard = self.shards[i].lock();
        let entry = shard.map.get(key).cloned()?;
        if entry.expires_at <= now {
            // **2.1.45（P2-8 / REV247 P2-7）**：仍**只读不晋升**（不 `move_to_end`，
            // 观测端点不得改变淘汰顺序），但**允许惰性移除已过期条目** —— 否则
            // `total`/采样会被"过期却永不清理"的键长期占位（低流量下尤其明显）。
            shard.map.remove(key);
            return None;
        }
        Some((*entry).clone())
    }
    // <<< 242B END P1-9-lru <<< //

    /// C-07：命中零堆分配（只 `Arc::clone`），LRU 语义与 `get` 完全一致。
    fn get_arc(&self, key: &CacheKey, now: f64) -> Option<Arc<CacheEntry>> {
        let i = self.shard_index(key);
        let mut shard = self.shards[i].lock();
        let entry = shard.map.get(key).cloned();
        match entry {
            None => None,
            Some(e) => {
                if e.expires_at <= now {
                    if self.stale_window_f64() <= 0.0 {
                        shard.map.remove(key);
                    }
                    None
                } else {
                    shard.map.move_to_end(key);
                    Some(e)
                }
            }
        }
    }

    /// C-07：命中零堆分配（只 `Arc::clone`），serve-stale 语义与 `get_stale` 一致。
    fn get_stale_arc(
        &self,
        key: &CacheKey,
        now: f64,
        stale_window: f64,
    ) -> Option<Arc<CacheEntry>> {
        let i = self.shard_index(key);
        let mut shard = self.shards[i].lock();
        let entry = shard.map.get(key).cloned()?;
        let exp = entry.expires_at;
        if exp > now {
            return None;
        }
        if now - exp > stale_window {
            shard.map.remove(key);
            return None;
        }
        shard.map.move_to_end(key);
        Some(entry)
    }

    fn put(&self, key: CacheKey, value: CacheEntry, now: f64) {
        let i = self.shard_index(&key);
        let j = self.journal_snapshot();
        let mut evicted: Vec<CacheKey> = Vec::new();
        {
            let mut shard = self.shards[i].lock();
            // **2.1.34（D1）**：与 TinyLFU 同修 —— `seq` 分配 + 入队在同一临界区，
            // 队列顺序 == seq 顺序（旧实现出锁后才 `try_send`，并发时会回退）。
            let _order = j.as_ref().map(|jj| jj.order_guard());
            // **顺序（§6.1）**：内存变更（插入/逐出）与 seq 分配都在**同一临界区**内，
            // 因此快照迭代（也要拿这把锁）看到的要么是“旧值 + 旧 seq”，要么是
            // “新值 + 新 seq”，不存在“新值 + 更小 seq”的错配。
            let mut value = value;
            if let Some(jj) = &j {
                value.seq = jj.next_seq();
            }
            let arc = Arc::new(value);
            // key 只在**需要发事件**时才克隆（journal 关闭 = 0 次克隆，
            // `tests/cache_alloc_test.rs` 的分配上界因此不变）。
            let key_for_event = j.as_ref().map(|_| key.clone());
            shard.map.insert(key, Arc::clone(&arc));
            Self::evict_locked(&mut shard, &mut evicted);
            shard.put_count += 1;
            if (shard.put_count & 0x1F) == 0 {
                Self::purge_expired_locked_with_sw(&mut shard, now, self.stale_window_f64());
            }
            if let Some(jj) = &j {
                for k in evicted.drain(..) {
                    let s = jj.next_seq();
                    jj.evict(self.journal_key(&k), EvictReason::Capacity, s);
                }
                if let Some(k) = key_for_event {
                    let seq = arc.seq;
                    jj.put(self.journal_key(&k), arc, seq);
                }
            }
        }
    }

    fn delete(&self, key: &CacheKey) {
        let i = self.shard_index(key);
        let mut shard = self.shards[i].lock();
        shard.map.remove(key);
    }

    fn clear(&self) {
        for s in &self.shards {
            s.lock().map.clear();
        }
    }

    fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().map.len()).sum()
    }

    fn keys(&self) -> Vec<CacheKey> {
        // C-10: 预留容量，避免大容量下多次 realloc（13 万条时旧实现要 17 次翻倍拷贝）。
        let mut out = Vec::with_capacity(self.len());
        for s in &self.shards {
            let shard = s.lock();
            for (k, _) in shard.map.iter() {
                out.push(k.clone());
            }
        }
        out
    }

    /// 只取前 `limit` 个 key（早停）：`/api/snapshot` 只需要少量样本条目，
    /// 全量 `keys()` 会在 13 万容量下每次请求克隆全部 key（高频轮询的热点分配）。
    fn sample_keys(&self, limit: usize) -> Vec<CacheKey> {
        let mut out = Vec::with_capacity(limit.min(1024));
        if limit == 0 {
            return out;
        }
        // 从各分片轮流取，保证样本覆盖不同分片（避免只看到第一个分片）。
        // **2.1.46**：商 + 余数分配（旧实现每片 `floor(limit/n)` ⇒ 500/8 只取 496，
        // 分区缓存再套一层配额时更少）；余数给前 `rem` 片 ⇒ 装得下时恰好 `limit`。
        let n = self.shards.len().max(1);
        let base = limit / n;
        let rem = limit % n;
        for (i, s) in self.shards.iter().enumerate() {
            let per = base + usize::from(i < rem);
            if per == 0 {
                continue;
            }
            let shard = s.lock();
            for (k, _) in shard.map.iter().take(per) {
                out.push(k.clone());
                if out.len() >= limit {
                    return out;
                }
            }
        }
        out
    }

    fn summary(&self) -> Value {
        let used = self.len();
        let cap = self.total_cap.load(Ordering::Relaxed).max(1);
        let pct = (used as f64 / cap as f64) * 100.0;
        json!({
            "used": used,
            "capacity": self.total_cap.load(Ordering::Relaxed),
            // **[历史归因]** C-01: Python `round(x, 1)`（十进制正确舍入 + 半值取偶），非 (x*10).round()/10。
            "pct": round1(pct),
        })
    }

    fn serialize(&self, now: f64) -> Vec<Value> {
        // C-10: 上界即总条目数（过期条目会被跳过，容量是保守上界）。
        let mut out = Vec::with_capacity(self.len());
        // **2.1.25（B8）**：逐条产出的单一实现在 `for_each_snapshot_entry` 里 ——
        // `serialize` 只是把它收集成 `Vec`，两条路径的口径不可能分叉。
        self.for_each_snapshot_entry(now, &mut |v| out.push(v));
        out
    }

    /// **2.1.25（B8 性能项）**：**逐条**产出（不建整表 `Vec<Value>`）。
    ///
    /// 锁粒度与旧实现**完全一致**：仍然一次只持一个分片的锁（`for s in &self.shards`
    /// 每轮 `lock()`）—— 因为本函数是流式写盘，逐条 `push` 只写进 `BufWriter` 的
    /// 内存缓冲，不会在持锁期间做真正的磁盘 write。
    fn for_each_snapshot_entry(&self, now: f64, f: &mut dyn FnMut(Value)) {
        for s in &self.shards {
            let shard = s.lock();
            for (k, e) in shard.map.iter() {
                if e.expires_at <= now {
                    continue;
                }
                let remaining = (e.expires_at - now).max(0.0);
                let mut obj = entry_to_json(k, e);
                if let Some(map) = obj.as_object_mut() {
                    // **[历史归因]** C-01: 与 Python `max(0, round(exp - now, 1))` 同口径。
                    map.insert("remaining".to_string(), json!(round1(remaining)));
                }
                f(obj);
            }
        }
    }

    fn restore(&self, entries: &[Value], now: f64, persist_ttl: f64) {
        // 借用版实现（只按引用遍历），这里多一次指针数组的开销，但避免了
        // PartitionedCache 侧逐条 `Value` 深拷贝。
        let refs: Vec<&Value> = entries.iter().collect();
        self.restore_refs(&refs, now, persist_ttl);
    }

    fn set_capacity(&self, n: usize) {
        let n = clamp_capacity(Some(n));
        self.total_cap.store(n, Ordering::Relaxed);
        let j = self.journal_snapshot();
        let base = n / SHARDS;
        let rem = n % SHARDS;
        let mut evicted_all: Vec<CacheKey> = Vec::new();
        for (i, s) in self.shards.iter().enumerate() {
            let mut shard = s.lock();
            shard.cap = base + if i < rem { 1 } else { 0 };
            let mut evicted = Vec::new();
            Self::evict_locked(&mut shard, &mut evicted);
            for k in evicted {
                evicted_all.push(self.journal_key(&k));
            }
        }
        if let Some(jj) = &j {
            // **2.1.34（D1）**：seq 分配 + 入队在同一总序临界区（不跨分片锁，避免反向锁序）。
            let _order = jj.order_guard();
            for k in evicted_all {
                let s = jj.next_seq();
                jj.evict(k, EvictReason::Resize, s);
            }
        }
    }

    fn set_stale_window(&self, v: u64) {
        self.stale_window.store(v, Ordering::Relaxed);
    }

    /// **2.1.19（修复项 1）**：`(expired, legacy, failed)` —— 与尾部 WARN/INFO
    /// **同一代码块**里赋值，所以断言计数等价于断言"日志分支真的被走到"。
    fn last_restore_drops(&self) -> (u64, u64, u64) {
        (
            self.restore_dropped_expired.load(Ordering::Relaxed),
            self.restore_dropped_legacy.load(Ordering::Relaxed),
            self.restore_failed.load(Ordering::Relaxed),
        )
    }

    // ---------------- 2.1.29：v2 持久化接缝 ----------------

    /// **2.1.29（v2）**：逐条产出（键 + `Arc` 句柄，零克隆）。
    ///
    /// 锁粒度与 [`DnsCache::for_each_snapshot_entry`] 一致：一次只持一个分片的锁。
    /// `entry.seq <= snapshot_seq` 的过滤由**写快照的调用方**做（§6.3.4）。
    fn for_each_entry(&self, _now: f64, f: &mut dyn FnMut(&CacheKey, &Arc<CacheEntry>)) {
        for s in &self.shards {
            let shard = s.lock();
            for (k, e) in shard.map.iter() {
                match &self.group {
                    // 常见路径（LRU / TinyLFU 顶层）：0 次分配。
                    None => f(k, e),
                    // 分区内层：把 group 补回 3 元组（每条约 1 次 String 分配，只在快照时发生）。
                    Some(_) => {
                        let ek = self.journal_key(k);
                        f(&ek, e);
                    }
                }
            }
        }
    }

    /// **2.1.29（v2）**：一次性装入恢复条目（TTL 已由 `recover` 统一决策）。
    fn restore_records(&self, entries: Vec<(CacheKey, CacheEntry)>, now: f64) {
        let cap = self.total_cap.load(Ordering::Relaxed);
        let restore_cap = cap.saturating_mul(4).max(65536);
        let mut entries = entries;
        if entries.len() > restore_cap {
            tracing::warn!(
                "cache.restore_records: {} 条恢复记录超过上限 {}, 截断（按 seq 升序保留前 N 条）",
                entries.len(),
                restore_cap
            );
            entries.sort_by_key(|(_, e)| e.seq);
            entries.truncate(restore_cap);
        }
        let mut new_maps: Vec<OrderedMap<CacheKey, Arc<CacheEntry>>> =
            (0..SHARDS).map(|_| OrderedMap::new()).collect();
        for (mut k, e) in entries {
            // 内层一律用二元组键（分区已由外层决定）。
            k.group = None;
            if e.expires_at <= now {
                // 上游 `apply_restore_policy` 已过滤过；这里只是兜底（不静默计数）。
                continue;
            }
            let i = (hash_key(&k) as usize) & (SHARDS - 1);
            new_maps[i].insert(k, Arc::new(e));
        }
        for (i, s) in self.shards.iter().enumerate() {
            let mut shard = s.lock();
            std::mem::swap(&mut shard.map, &mut new_maps[i]);
            let mut dropped = Vec::new();
            Self::evict_locked(&mut shard, &mut dropped);
        }
    }

    fn persist_stats(&self) -> Option<Arc<PersistStats>> {
        Some(Arc::clone(&self.stats))
    }

    fn attach_journal(&self, j: Arc<CacheJournal>) {
        *self.journal.write() = Some(j);
    }

    fn request_snapshot(&self, reason: &'static str) {
        if let Some(j) = self.journal_snapshot() {
            j.request_snapshot(reason);
        }
    }
}

impl LruCache {
    // **2.1.18（修复项 23）**：本实例最近一次 `restore` 的丢弃计数原本是这里的**固有**
    // 方法 `last_restore_drops() -> (expired, legacy)`。
    //
    // 用途：①测试断言"丢弃分支被走到"（计数与 WARN/INFO 日志在**同一代码块**里赋值，
    // 因此不需要抓日志、也不会因测试环境无全局订阅者而假通过）；
    // ②运维诊断（恢复后 `legacy > 0` 说明文件是旧格式、已按安全侧丢弃）。
    // 计数是**每实例**的（不是进程级 static）—— 进程级会被并行测试互相覆盖。
    //
    // **2.1.19（修复项 1）**：`(expired, legacy, failed)` 的**唯一**读取入口已上移到
    // [`DnsCache::last_restore_drops`]（trait 方法，三条策略都实现）。
    // 2.1.19 只有 `LruCache` 能读这个计数，而生产默认 `cache_policy=tinylfu`
    // ⇒ **实际生效的那条路径永远观测不到**，已删除该固有方法以免"同一语义两处定义"漂移。

    /// [`DnsCache::restore`] 的**借用切片**版本：条目只按 `&Value` 传入。
    ///
    /// `PartitionedCache::restore` 用它来避免为每条记录做一次 `Value` 深拷贝
    /// （旧路径 `e.clone()` + 重写 key 数组，每条 8 次以上分配）。3 元组 key 的
    /// **[历史归因]** group 前缀在此剥掉（对齐 Python cache.py:318-325）。
    pub fn restore_refs(&self, entries: &[&Value], now: f64, persist_ttl: f64) {
        let pt = safe_float(persist_ttl, 0.0).max(0.0);
        let cap = self.total_cap.load(Ordering::Relaxed);
        // C-03: cap 极大时 `cap * 4` 在 debug 下 panic、release 下回绕成小值，
        // 会把整份持久化缓存静默截断/丢弃。saturating_mul 保证单调不减。
        let restore_cap = cap.saturating_mul(4).max(65536);
        let raw: &[&Value] = if entries.len() > restore_cap {
            tracing::warn!(
                "cache.restore: {} 条恢复记录超过上限 {}, 截断",
                entries.len(),
                restore_cap
            );
            &entries[..restore_cap]
        } else {
            entries
        };

        // C-01: 锁外为每个分片构建新 OrderedMap，再逐分片原子换引用。
        let mut new_maps: Vec<OrderedMap<CacheKey, Arc<CacheEntry>>> =
            (0..SHARDS).map(|_| OrderedMap::new()).collect();
        // 2.1.18（修复项 17）：两类丢弃分别计数，恢复结束后**各打一条日志**
        // （`legacy` 只打 WARN 一次，避免刷屏；`expired` 打 INFO 汇总）。
        let mut expired_dropped = 0usize;
        let mut legacy_dropped = 0usize;
        // **2.1.18（修复项 26）**：反序列化失败的条目（真损坏）单独计数，不再静默。
        let mut parse_failed = 0usize;
        // **2.1.19（修复项 1 补漏：2.1.18"静默丢弃"同类残留）**：**结构不完整**的条目
        // （`key` 不是数组 / `key` 长度非 2|3 / domain·qtype 取不出 / 缺 `answers` 或
        // `rcode`）此前是**四个裸 `continue`** —— 实测 WARN=0 且 `failed=0`，属同一类
        // "静默丢弃"残留。现在逐类计数并按类归因（函数尾部 WARN 列出各为几条）。
        //
        // 与 `parse_failed` 分开统计**只为可读归因**；对外暴露时两者都计入
        // `failed`（"这条记录不可用"是同一件事），因此 `last_restore_drops().2`
        // 一定涵盖这两类，不会再说谎。
        let mut structural_failed = [0usize; 4]; // [key非数组, key长度非法, domain/qtype缺失, 缺answers/rcode]

        for &e in raw {
            // **2.1.19（修复项 1 补漏）**：结构判定**唯一来源** = `util::structural_check`
            // （此前 lru / tinylfu 各写一份 ⇒ `[123,456]` 这类在两边结果不同）。
            let parsed = match structural_check(e) {
                Ok(p) => p,
                Err(iss) => {
                    structural_failed[iss.idx()] += 1;
                    continue;
                }
            };
            // `lru` 的分片由 key 哈希决定，**3 元组的 group 前缀在此剥掉**
            // （对齐 Python cache.py:318-325；分区已由 `PartitionedCache` 决定）。
            let _ = parsed.key_len;
            let (domain, qtype) = (parsed.domain, parsed.qtype);
            // **2.1.18（修复项 26，真实根因）**：**旧格式必须在反序列化之前判定**。
            //
            // 为什么：`CacheEntry::expires_at` 是**必填**字段（无 `#[serde(default)]`），
            // 因此"只有 `remaining`、没有绝对 `expires_at`"的旧文件会在下面
            // `serde_json::from_value` **直接失败** → 被当成"损坏条目"**静默丢弃** ——
            // 这正是部署代理实测的现象：**0/40 命中（丢弃正确）但 WARN=0**。
            //
            // **2.1.19（修复项 1：2.1.18 交付登记的唯一残留）**：判定必须
            // **① 在 TTL 策略分派之前**、**② 与 `persist_ttl` 取值无关**。
            //
            // 2.1.18 的写法把这段判定挂在 `if pt <= 0.0` 之内，尾部 `else` 里又留了
            // 第二份相同判定 ⇒ 两个真实缺陷：
            //   ① `persist_ttl > 0` 时旧格式条目**既不计数也不丢弃**，会被
            //      `now + persist_ttl` **复活**（违反"旧格式只能安全侧丢弃"的契约）；
            //   ② 尾部 `else` 的第二份判定**永远不可达**（`pt <= 0.0` 且缺
            //      `expires_at` 的分支已经 `continue`）。
            // 而**生产真正生效的那条路径**是 `cache_policy=tinylfu`
            // （见 `tinylfu.rs::restore`），2.1.18 的 tinylfu 分支**根本没有 legacy 计数**
            // ⇒ 实测"计数恒 0、WARN 不触发、hits 0/40"。
            //
            // 现在：**无条件**先判定"缺（或非正）`expires_at` 且有 `remaining`"
            // ⇒ `legacy_dropped += 1` ⇒ `continue`（绝不进入 TTL 分派，绝不复活），
            // 函数尾部 WARN 含条数。与"真的损坏"（计数 `parse_failed`）区分开，
            // 两者都不再静默。
            if is_legacy_format(e) {
                legacy_dropped += 1;
                continue;
            }
            if !has_absolute_expiry(e) {
                // 既没有绝对到期时间、也没有 `remaining` ⇒ 文件被截断/由不兼容版本写入
                // ⇒ 与"旧格式"分开计数（函数尾部 WARN 会写明是哪一类）。
                parse_failed += 1;
                continue;
            }
            // 反序列化基础条目。
            let mut entry: CacheEntry = match serde_json::from_value(e.clone()) {
                Ok(en) => en,
                // **不再静默**：坏条目单独计数（函数尾部 WARN 汇总）。
                Err(_) => {
                    parse_failed += 1;
                    continue;
                }
            };
            // ---- **时间口径（2.1.19 修复项 17：DNS TTL 契约）** ----
            //
            // **缺陷**（部署代理隔离实测）：旧实现在 `persist_ttl == 0` 且文件里有
            // `remaining` 时执行 `expires_at = now + remaining` —— 把"剩余时长"
            // 当成**新窗口重新计时**。夹具 TTL=20s、停 25s（已过期）后重启，
            // 5200/5200 **全部命中**：等于向下游提供了**超过原 TTL** 的数据。
            //
            // **裁决**：DNS TTL 是与下游客户的契约，缓存不得比原 TTL 活得久。
            // 新口径（`serialize` 同时写绝对 `expires_at` 与 `remaining`）：
            // 1. **优先用绝对 `expires_at`**（停机期间的时间**计入**）；
            //    `expires_at <= now` ⇒ 直接丢弃（已过期）；
            // 2. 文件里**没有**绝对 `expires_at`（旧版本写的文件）⇒ **安全侧**：
            //    丢弃并打一次 WARN（不静默重新锚定）；
            // 3. `persist_ttl > 0` ⇒ **用户显式选择**的"统一恢复 TTL"（opt-in 延长）：
            //    恢复的条目一律用 `now + persist_ttl`，**不再看原到期时间**
            //    （配置页文案与 README 都明确标注风险：会让缓存比原 TTL 活得更久，
            //     可能向下游返回超过原 TTL 的数据）。默认 `0` = 不延长（见 1/2 条）。
            //
            // **2.1.18（修复项 23）**：两条路径**共用下面的 key 构造 + 分片插入尾部**，
            // 这里只决定 `expires_at`。旧实现把 `pt > 0` 写成"提前 insert + continue"，
            // 且把 `group` **硬编码为 `None`** —— 对 `PartitionedCache`（3 元组 key 带
            // group 前缀）会把条目插进错误的 group，表现为"设了 persist_ttl 命中率反而更低"。
            if pt > 0.0 {
                entry.expires_at = now + pt;
                entry.ttl = pt;
            } else {
                // **2.1.29**：判定逻辑已抽成**唯一实现** [`resolve_restored_expiry`]
                // （与 v2 恢复、v1 迁移共用），这里保留 v1 的算术写法以免浮点末位漂移。
                match resolve_restored_expiry(entry.expires_at, now, pt) {
                    Some(abs) => {
                        entry.expires_at = abs;
                        entry.ttl = (abs - now).max(0.0);
                    }
                    None => {
                        expired_dropped += 1;
                        continue;
                    }
                }
            }
            let key = CacheKey {
                group: None,
                domain,
                qtype,
            };
            let i = (hash_key(&key) as usize) & (SHARDS - 1);
            new_maps[i].insert(key, Arc::new(entry));
        }

        for (i, s) in self.shards.iter().enumerate() {
            let mut shard = s.lock();
            // 原子换引用：读端持锁后要么看到完整旧 map，要么看到完整新 map。
            std::mem::swap(&mut shard.map, &mut new_maps[i]);
            // 恢复期的容量裁剪**不记日志**（journal 在恢复期 suspend；回放/快照已代表它）。
            let mut dropped = Vec::new();
            Self::evict_locked(&mut shard, &mut dropped);
        }
        // **2.1.18（修复项 17）**：把两类丢弃**显式打出来**（不再静默）：
        // - `expired`：文件里的绝对到期时间已过（停机期间的时间已计入）⇒ INFO 汇总；
        // - `legacy`：旧格式（只有 `remaining`、无绝对 `expires_at`）⇒ WARN 一次，
        //   写明"已按安全侧丢弃"，避免用户以为"缓存没恢复"是缺陷。
        // **2.1.18（修复项 23）**：把两类丢弃写成**本实例可读计数**（测试/运维都能看），
        // 然后再打日志 —— 两者在同一个代码块里，断言计数等价于断言"WARN/INFO 分支被走到"。
        self.restore_dropped_expired
            .store(expired_dropped as u64, Ordering::Relaxed);
        self.restore_dropped_legacy
            .store(legacy_dropped as u64, Ordering::Relaxed);
        // **2.1.19（修复项 1）**：`failed` = 「反序列化失败」**加上**「结构不完整」
        // （四个此前静默的裸 `continue`）—— 对读者而言两者都是"这条记录不可用"，
        // 因此暴露口径统一为 `failed`，不存在"明明丢了却报 0"的可能。
        let structural_total: usize = structural_failed.iter().sum();
        let failed_total = parse_failed + structural_total;
        self.restore_failed
            .store(failed_total as u64, Ordering::Relaxed);
        if expired_dropped > 0 {
            tracing::info!(
                dropped_expired = expired_dropped,
                "cache.restore: 已丢弃 {} 条（文件里的绝对到期时间已过 —— 停机时长计入 TTL，符合 DNS TTL 契约）",
                expired_dropped
            );
        }
        if parse_failed > 0 {
            tracing::warn!(
                dropped_parse_failed = parse_failed,
                "cache.restore: **已丢弃 {} 条无法反序列化的记录**（字段缺失/类型不符 ⇒ 文件可能被截断或由不兼容版本写入）",
                parse_failed
            );
        }
        // **2.1.19（修复项 1 补漏）**：四个结构不完整分支各打一条 WARN（含逐类条数），
        // 不再静默。逐类分开是为了让运维一眼看出"是 key 坏了还是 answers 缺了"。
        if structural_total > 0 {
            // 类别标签来自 `StructuralIssue::label()`（三条策略同一组词，见 util.rs）。
            let breakdown = crate::util::structural_breakdown(&structural_failed);
            tracing::warn!(
                dropped_structural = structural_total,
                key_not_array = structural_failed[0],
                key_len_invalid = structural_failed[1],
                domain_or_qtype_missing = structural_failed[2],
                answers_or_rcode_missing = structural_failed[3],
                "cache.restore: **已丢弃 {} 条结构不完整的记录**（{}）—— 逐类计数见本行的同名字段",
                structural_total,
                breakdown
            );
        }
        if legacy_dropped > 0 {
            tracing::warn!(
                dropped_legacy = legacy_dropped,
                "cache.restore: **已丢弃 {} 条旧格式记录**（文件里缺少绝对 `expires_at`，只有 `remaining`；\
                 无从判断停机了多久 ⇒ 按安全侧丢弃，不重新锚定 TTL）。下一次落盘会写成新格式。",
                legacy_dropped
            );
        }
    }

    fn purge_expired_locked_with_sw(shard: &mut Shard, now: f64, sw: f64) -> usize {
        let mut cnt = 0usize;
        while let Some((_k, e)) = shard.map.front() {
            let exp = e.expires_at;
            if exp > now {
                break;
            }
            if sw > 0.0 && (now - exp) <= sw {
                break;
            }
            shard.map.pop_front();
            cnt += 1;
        }
        let n = shard.map.len();
        if n > 0 {
            let mut pos = shard.purge_cursor;
            if pos >= n {
                pos = 0;
            }
            let step = PURGE_SCAN_STEP.min(n);
            let pos = if step >= n { 0 } else { pos };
            // C-09: 旧实现 `range_keys()`(克隆 ≤64 个键，每个键 2~3 次 String 分配)
            // + `get()`(一次哈希查找) + `remove()`(再一次哈希查找)。改为只取节点索引，
            // 原地读值 / 原地删除：0 次键克隆、1 次遍历、1 次哈希删除。
            // **[历史归因]** 抽样位置、步长与游标推进与 Python `_purge_expired_locked` 逐项一致。
            let sampled = shard.map.range_indices(pos, step);
            for idx in sampled {
                let drop = shard
                    .map
                    .value_at(idx)
                    .map(|e| {
                        let exp = e.expires_at;
                        exp <= now && !(sw > 0.0 && (now - exp) <= sw)
                    })
                    .unwrap_or(false);
                if drop {
                    shard.map.remove_index(idx);
                    cnt += 1;
                }
            }
            shard.purge_cursor = (pos + step) % n;
        }
        cnt
    }
}

/// 把条目转成 JSON 对象（含 key 数组，不含 remaining）。
pub(crate) fn entry_to_json(key: &CacheKey, e: &CacheEntry) -> Value {
    let mut map = Map::new();
    map.insert("key".to_string(), Value::from(key.to_key_array()));
    // answers/chosen/ttl/rcode/domain/qtype/expires_at。
    if let Ok(v) = serde_json::to_value(e) {
        if let Some(em) = v.as_object() {
            for (k, val) in em {
                map.insert(k.clone(), val.clone());
            }
        }
    }
    // >>> 242B BEGIN T-cache-lru >>> //
    Value::Object(map)
}

#[cfg(test)]
mod p242b_peek_tests {
    use super::*;
    use crate::DnsCache;

    /// **2.1.42-B（P1-9）**：`peek` 不得 `move_to_end`、不得删过期项。
    #[test]
    fn peek_does_not_change_lru_order() {
        let c = LruCache::new(64);
        for i in 0..6 {
            let k = CacheKey::new(format!("k{i}.test"), "A");
            c.put(
                k,
                CacheEntry::new(format!("k{i}.test"), "A", 300.0, 100.0),
                100.0,
            );
        }
        let order = |c: &LruCache| {
            c.keys()
                .iter()
                .map(|k| k.domain.clone())
                .collect::<Vec<_>>()
        };
        let before = order(&c);
        let k = CacheKey::new("k0.test", "A");
        for _ in 0..10 {
            assert!(c.peek(&k, 100.0).is_some(), "peek 必须能读到条目");
        }
        assert_eq!(order(&c), before, "peek 不得改变 LRU 顺序（move_to_end）");
        // **2.1.45（P2-8 / REV247 P2-7）**：过期条目 peek 返回 None 且**惰性移除**
        // （否则观测端 `total`/采样会被"过期却永不清理"的键长期占位）；仍不 move。
        let old = CacheKey::new("k1.test", "A");
        assert!(c.peek(&old, 1000.0).is_none());
        assert_eq!(c.len(), 5, "peek 必须惰性移除已过期条目（2.1.45 起）");
        let mut want = before.clone();
        want.retain(|d| d != "k1.test");
        assert_eq!(order(&c), want, "只移除过期项，其余条目顺序不变");
    }
}
// <<< 242B END T-cache-lru <<< //
