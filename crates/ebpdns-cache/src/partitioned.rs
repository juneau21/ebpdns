//! 分区缓存。
//!
//! **[历史归因]** 行为对齐 Python 旧线 `PartitionedCache`（`cache.py:368-580`）；Rust 侧实现就是本文件的 [`PartitionedCache`]，
//! 语义等价但结构不同：每区一个 8 分片 [`LruCache`]，权重负数钳 0 后归一化到和为 1。
//!
//! 按分流 group（domestic/global/default）隔离缓存池，每区一个独立 [`LruCache`]，
//! 总容量按归一化权重分配。对外接口与 LRU 一致，仅 key 多一个 group 维。

use crate::entry::CacheKey;
use crate::lru::LruCache;
use crate::persist::journal::CacheJournal;
use crate::persist::PersistStats;
use crate::util::{clamp_capacity, round1, safe_float};
use crate::DnsCache;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// 默认分区权重（对齐 `_DEFAULT_PARTITIONS`）。
pub const DEFAULT_PARTITIONS: [(&str, f64); 3] =
    [("domestic", 0.2), ("global", 0.2), ("default", 0.6)];

/// 按 group 分区的缓存。
pub struct PartitionedCache {
    total_cap: AtomicUsize,
    parts: Vec<(String, f64)>,
    caches: BTreeMap<String, LruCache>,
    /// **2.1.19（修复项 1 补漏）**：本次 `restore` 在**分组阶段**就被跳过的条数
    /// （`key` 非数组 / 长度非 2|3 / 无可用分区）。这些条目**根本到不了内层
    /// `LruCache`**，因此内层计数看不到它们 —— 以前是静默丢弃。
    ///
    /// 语义：由 `restore` 开头清零；`last_restore_drops()` 把本值加进 `failed`。
    restore_skipped: AtomicUsize,
    /// **2.1.29（v2）**：持久化现场统计（与外壳同一份）。
    stats: Arc<PersistStats>,
}

impl PartitionedCache {
    /// 构造。`partitions` 为 group→权重；`None` 用默认三分。
    pub fn new(capacity: usize, partitions: Option<BTreeMap<String, f64>>) -> Self {
        let cap = clamp_capacity(Some(capacity));
        let raw: Vec<(String, f64)> = match partitions {
            Some(p) => p.into_iter().collect(),
            None => DEFAULT_PARTITIONS
                .iter()
                .map(|(g, w)| (g.to_string(), *w))
                .collect(),
        };
        // 钳权重 >=0，再归一化到和为 1（全 0 时 sum==0 → 回退 1.0）。
        let clamped: Vec<(String, f64)> = raw
            .into_iter()
            .map(|(g, w)| (g, safe_float(w, 0.0).max(0.0)))
            .collect();
        let total: f64 = clamped.iter().map(|(_, w)| *w).sum::<f64>();
        let denom = if total > 0.0 { total } else { 1.0 };
        let mut parts: Vec<(String, f64)> =
            clamped.into_iter().map(|(g, w)| (g, w / denom)).collect();
        parts.sort_by(|a, b| a.0.cmp(&b.0));

        let caches = BTreeMap::new();
        let mut this = Self {
            total_cap: AtomicUsize::new(cap),
            parts,
            caches,
            restore_skipped: AtomicUsize::new(0),
            stats: PersistStats::new(),
        };
        this.rebuild_caches();
        this
    }

    /// **2.1.29（v2）**：注入现场统计（由外壳下发同一份）。
    ///
    /// 只在**构造之后、开始服务之前**调用一次（会按当前（空）权重表重建内层，
    /// 因此不能拿来热改已有数据）。
    pub fn with_stats(mut self, stats: Arc<PersistStats>) -> Self {
        self.stats = stats;
        self.rebuild_caches();
        self
    }

    /// 按当前权重把总容量分配到各分区，并重建内层 LRU。
    fn rebuild_caches(&mut self) {
        let cap = self.total_cap.load(Ordering::Relaxed);
        let shares = self.allocate(cap);
        let mut caches = BTreeMap::new();
        for (g, share) in shares {
            // **2.1.29（v2）**：内层必须知道自己的分区名 —— 否则 WAL/快照里的事件键
            // 会丢掉 group 维（回放后键不相等 ⇒ 命中率下降）。分片路由仍用二元组键。
            caches.insert(
                g.clone(),
                LruCache::with_group(share, Some(g)).with_stats(Arc::clone(&self.stats)),
            );
        }
        self.caches = caches;
    }

    /// 容量分配（对齐 `_allocate`），返回 group→capacity，总和恰为 cap。
    fn allocate(&self, cap: usize) -> Vec<(String, usize)> {
        let n = self.parts.len();
        if n == 0 {
            return Vec::new();
        }
        // C-02: `16 * n` / `base + c` 在大 cap（或大量分区）下会溢出 panic。
        // **[历史归因]** 全部改饱和运算：正常量级下与 Python 的大整数运算逐位同值（Python 无溢出）。
        let floor_total = 16usize.saturating_mul(n);
        if cap >= floor_total {
            let base = 16usize;
            let rem = cap - floor_total;
            let mut raw: Vec<(String, f64)> = self
                .parts
                .iter()
                .map(|(g, w)| (g.clone(), rem as f64 * w))
                .collect();
            let mut floored: Vec<(String, usize)> = raw
                .iter()
                .map(|(g, r)| (g.clone(), r.floor() as usize))
                .collect();
            let used: usize = floored
                .iter()
                .fold(0usize, |a, (_, c)| a.saturating_add(*c));
            // 归一化后的权重和可能因浮点误差略大于 1.0，使 `used` 比 rem 大 1；
            // **[历史归因]** Python 此处 leftover 变负 → `range(负数)` 不迭代。saturating_sub 同语义。
            let mut leftover = rem.saturating_sub(used);
            // 按小数部分降序补发余数。
            raw.sort_by(|a, b| {
                let fa = a.1 - a.1.floor();
                let fb = b.1 - b.1.floor();
                fb.partial_cmp(&fa).unwrap_or(std::cmp::Ordering::Equal)
            });
            let mut i = 0usize;
            while leftover > 0 {
                let g = &raw[i % n].0;
                if let Some(slot) = floored.iter_mut().find(|(x, _)| x == g) {
                    slot.1 += 1;
                }
                leftover -= 1;
                i += 1;
            }
            floored
                .into_iter()
                .map(|(g, c)| (g, base.saturating_add(c)))
                .collect()
        } else {
            // 总容量太小：按比例分，每分区至少 1。
            let mut raw: Vec<(String, f64)> = self
                .parts
                .iter()
                .map(|(g, w)| (g.clone(), cap as f64 * w))
                .collect();
            let mut floored: Vec<(String, usize)> = raw
                .iter()
                .map(|(g, r)| (g.clone(), (r.floor() as usize).max(1)))
                .collect();
            let mut diff = cap as i64 - floored.iter().map(|(_, c)| *c as i64).sum::<i64>();
            raw.sort_by(|a, b| {
                let fa = a.1 - a.1.floor();
                let fb = b.1 - b.1.floor();
                fb.partial_cmp(&fa).unwrap_or(std::cmp::Ordering::Equal)
            });
            let mut i = 0usize;
            while diff > 0 {
                let g = &raw[i % n].0;
                if let Some(slot) = floored.iter_mut().find(|(x, _)| x == g) {
                    slot.1 += 1;
                }
                diff -= 1;
                i += 1;
            }
            while diff < 0 {
                let mut found = false;
                for _ in 0..n {
                    let g = &raw[i % n].0;
                    if let Some(slot) = floored.iter_mut().find(|(x, _)| x == g) {
                        if slot.1 > 1 {
                            slot.1 -= 1;
                            diff += 1;
                            found = true;
                            break;
                        }
                    }
                    i += 1;
                }
                if !found {
                    break;
                }
            }
            floored
        }
    }

    /// **[历史归因]** 解析 key 归属的分区名（对齐 Python `_split`，逐项同序）。
    ///
    /// C-08：旧实现 `split()` 返回 `(String, CacheKey)`，每次操作做
    /// `g.clone()`（1 次分配）+ `CacheKey::new(domain.clone(), qtype.clone())`
    /// （2 次分配）。现在只借出**分区名字符串的 `&str`**（生命周期只绑 `&self`），
    /// **[历史归因]** 回退顺序与 Python 完全一致：`key.group` → `"default"` → 第一个可用分区。
    fn resolve_group<'s>(&'s self, key: &CacheKey) -> Option<&'s str> {
        let want = key.group.as_deref().unwrap_or("default");
        if let Some((name, _)) = self.caches.get_key_value(want) {
            return Some(name.as_str());
        }
        // 未知/缺失分组 → 回退 "default"，再回退第一个可用分区（极端空配置 → None）。
        if let Some((name, _)) = self.caches.get_key_value("default") {
            return Some(name.as_str());
        }
        self.caches.keys().next().map(|s| s.as_str())
    }

    /// 内层二元组键（对齐 `_split` 的 `key[1:]`）。
    ///
    /// C-08：`group == None` 时调用方的 key **本身就是**内层键
    /// （`CacheKey { None, domain, qtype }`，正是 `CacheKey::new` 的形态），
    /// 直接借用 → 0 次字符串分配（运行期 resolver 走的就是这条路径，见
    /// `ebpdns-resolver` 的 `_ckey`）。只有带 group 的三元组键才需要剥掉 group，
    /// 此时克隆 domain/qtype（无法从 `&self` 侧移动）。
    fn inner_key(key: &CacheKey) -> InnerKey<'_> {
        if key.group.is_none() {
            InnerKey::Borrowed(key)
        } else {
            InnerKey::Owned(CacheKey::new(key.domain.clone(), key.qtype.clone()))
        }
    }
}

/// 内层二元组键：借用调用方 key（零分配）或持有一份剥掉 group 的副本。
enum InnerKey<'a> {
    Borrowed(&'a CacheKey),
    Owned(CacheKey),
}

impl InnerKey<'_> {
    #[inline]
    fn as_key(&self) -> &CacheKey {
        match self {
            InnerKey::Borrowed(k) => k,
            InnerKey::Owned(k) => k,
        }
    }
}

impl DnsCache for PartitionedCache {
    /// **2.1.43-B（P2-2）**：落盘键 = **实际分区名** + domain + qtype（3 元组）。
    ///
    /// 与内层 `LruCache::journal_key`（`expand_key` 补内层 group）**同构**：同一个
    /// `PUT` 与随后的 `EVICT` 因此必然得到同一个键，回放不再"删错分区"。
    /// 未知/缺失分组按 [`PartitionedCache::resolve_group`] 的同一套回退规则解析
    /// （`default` → 第一个可用分区），与运行期写路径逐位一致。
    fn journal_key(&self, key: &CacheKey) -> CacheKey {
        let mut k = key.clone();
        if let Some(g) = self.resolve_group(key) {
            k.group = Some(g.to_string());
        }
        k
    }

    fn get(&self, key: &CacheKey, now: f64) -> Option<crate::CacheEntry> {
        self.get_arc(key, now).map(|e| (*e).clone())
    }

    fn get_stale(&self, key: &CacheKey, now: f64, stale_window: f64) -> Option<crate::CacheEntry> {
        self.get_stale_arc(key, now, stale_window)
            .map(|e| (*e).clone())
    }

    /// C-07：转发到内层 LRU 的真零拷贝实现（命中只 `Arc::clone`）。
    fn get_arc(&self, key: &CacheKey, now: f64) -> Option<std::sync::Arc<crate::CacheEntry>> {
        let g = self.resolve_group(key)?;
        let c = self.caches.get(g)?;
        let ik = Self::inner_key(key);
        c.get_arc(ik.as_key(), now)
    }

    // >>> 242B BEGIN P1-9-part >>> //
    /// **2.1.42-B（P1-9）**：转发到内层 LRU 的 no-touch 读取。
    fn peek(&self, key: &CacheKey, now: f64) -> Option<crate::CacheEntry> {
        let g = self.resolve_group(key)?;
        let c = self.caches.get(g)?;
        let ik = Self::inner_key(key);
        c.peek(ik.as_key(), now)
    }

    // <<< 242B END P1-9-part <<< //
    /// C-07：同 `get_arc`，serve-stale 路径零拷贝。
    fn get_stale_arc(
        &self,
        key: &CacheKey,
        now: f64,
        stale_window: f64,
    ) -> Option<std::sync::Arc<crate::CacheEntry>> {
        let g = self.resolve_group(key)?;
        let c = self.caches.get(g)?;
        let ik = Self::inner_key(key);
        c.get_stale_arc(ik.as_key(), now, stale_window)
    }

    fn put(&self, mut key: CacheKey, value: crate::CacheEntry, now: f64) {
        let Some(g) = self.resolve_group(&key) else {
            return;
        };
        // C-08：内层键是剥掉 group 的二元组；key 已归属本方法，直接置空 group
        // 即可（0 次 String 克隆，旧实现克隆 domain+qtype 两次）。
        key.group = None;
        if let Some(c) = self.caches.get(g) {
            c.put(key, value, now);
        }
    }

    fn delete(&self, key: &CacheKey) {
        let Some(g) = self.resolve_group(key) else {
            return;
        };
        let Some(c) = self.caches.get(g) else {
            return;
        };
        let ik = Self::inner_key(key);
        c.delete(ik.as_key());
    }

    fn clear(&self) {
        for c in self.caches.values() {
            c.clear();
        }
    }

    fn len(&self) -> usize {
        self.caches.values().map(|c| c.len()).sum()
    }

    fn keys(&self) -> Vec<CacheKey> {
        // C-10: 预留容量，避免大容量下反复 realloc。
        let mut out = Vec::with_capacity(self.len());
        for (g, c) in &self.caches {
            for k in c.keys() {
                // domain/qtype 已是拥有所有权的 String，直接搬进三元组（1 次分配，
                // 旧实现 `with_group(g.clone(), k.domain, k.qtype)` 克隆全部 3 个字段）。
                out.push(CacheKey {
                    group: Some(g.clone()),
                    domain: k.domain,
                    qtype: k.qtype,
                });
            }
        }
        out
    }

    /// **2.1.46（REV247 P2-4）**：把 `limit` 摊到各分区，逐分区早停。
    ///
    /// 旧实现用 trait 默认的 `keys().truncate(limit)`：`partitioned` 下
    /// `/api/snapshot` 会把**所有分区**的全量 key 克隆成 3 元组再截断。
    ///
    /// 与 LRU 覆写同口径：每个分区至少取 `limit / n` 个（保证样本覆盖不同分区），
    /// 总量严格 `<= limit`；分区较多/限额较小时也不会空转。
    fn sample_keys(&self, limit: usize) -> Vec<CacheKey> {
        let mut out = Vec::with_capacity(limit.min(1024));
        if limit == 0 || self.caches.is_empty() {
            return out;
        }
        let n = self.caches.len();
        let base = limit / n;
        let rem = limit % n;
        let quota = |idx: usize| base + usize::from(idx < rem);
        for (idx, (g, c)) in self.caches.iter().enumerate() {
            // 把余数分给前 `rem` 个分区 ⇒ 分区都装得下时第一轮覆盖各分区。
            for k in c.sample_keys(quota(idx)) {
                out.push(CacheKey {
                    group: Some(g.clone()),
                    domain: k.domain,
                    qtype: k.qtype,
                });
                if out.len() >= limit {
                    return out;
                }
            }
        }
        // **2.1.46**：某个分区条目不足（或只有 default 分区在用）时，第一轮凑不满
        // `limit`；按余量再取一轮，跳过第一轮已经取过的前缀，避免重复样本。
        for (idx, (g, c)) in self.caches.iter().enumerate() {
            let q = quota(idx);
            let need = limit - out.len();
            if need == 0 {
                return out;
            }
            for (i, k) in c.sample_keys(q + need).into_iter().enumerate() {
                if i < q {
                    continue; // 第一轮已取过
                }
                out.push(CacheKey {
                    group: Some(g.clone()),
                    domain: k.domain,
                    qtype: k.qtype,
                });
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
        let mut parts = serde_json::Map::new();
        for (g, c) in &self.caches {
            parts.insert(g.clone(), c.summary());
        }
        json!({
            "used": used,
            "capacity": self.total_cap.load(Ordering::Relaxed),
            // **[历史归因]** C-01: 与 Python `round(x, 1)` 同口径（半值取偶）。
            "pct": round1(pct),
            "partitions": Value::Object(parts),
        })
    }

    fn serialize(&self, now: f64) -> Vec<Value> {
        // C-10: 预留容量。
        let mut out = Vec::with_capacity(self.len());
        // **2.1.25（B8）**：逐条产出的单一实现在 `for_each_snapshot_entry` 里。
        self.for_each_snapshot_entry(now, &mut |v| out.push(v));
        out
    }

    /// **2.1.25（B8 性能项）**：**逐条**产出（不建整表 `Vec<Value>`）。
    ///
    /// group 前缀的插入与旧实现逐位一致（原地 `insert(0, ..)`，只分配 group 字符串）；
    /// 区别只是"逐条交出去"而不是"攒成一个 `Vec` 再交出去"。
    fn for_each_snapshot_entry(&self, now: f64, f: &mut dyn FnMut(Value)) {
        for (g, c) in &self.caches {
            c.for_each_snapshot_entry(now, &mut |mut e| {
                // key 前插 group → [group, domain, qtype]。
                // 旧实现先 `.clone()` 整个 key 数组（每个元素一次 String 分配）再重建
                // Vec；现在原地 `insert(0, ..)`，只分配那个 group 字符串。
                if let Some(Value::Array(arr)) = e.get_mut("key") {
                    arr.insert(0, Value::String(g.clone()));
                }
                f(e);
            });
        }
    }

    fn restore(&self, entries: &[Value], now: f64, persist_ttl: f64) {
        // 按 group 聚合，每组只调一次内层 restore（避免逐条 restore 清空整 shard）。
        //
        // 内层 `LruCache::restore_refs` 自己会剥掉 3 元组的 group 前缀
        // **[历史归因]** （对齐 Python cache.py:318-325），所以这里**按引用**聚合即可：旧实现为每条
        // 记录做一次 `e.clone()` 深拷贝 + 重写 key 数组（每条 8 次以上分配）。
        let mut groups: BTreeMap<&str, Vec<&Value>> = BTreeMap::new();
        // **2.1.19（修复项 1 补漏）**：分组阶段的跳过必须计数（此前三个 `continue`
        // 完全静默，且这些条目**到不了内层 LruCache** ⇒ 内层 `failed` 也看不到它们）。
        // 判定与 lru / tinylfu **同源** = `util::structural_check`（唯一来源）。
        let mut skipped = 0usize;
        for e in entries {
            let parsed = match crate::util::structural_check(e) {
                Ok(p) => p,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };
            // 3 元组取显式 group（非字符串回退 `default`），2 元组恒 `default`
            // —— 与既有行为逐位一致。
            //
            // **借用注意**：`g` 必须借自 `e`（`entries` 的元素，活得比 `groups` 长），
            // **不能**借自上面那个每轮新建的 `parsed`（否则 E0597）。
            let g: &str = if parsed.key_len == 3 {
                e.get("key")
                    .and_then(|v| v.as_array())
                    .and_then(|a| a.first())
                    .and_then(|v| v.as_str())
                    .unwrap_or("default")
            } else {
                "default"
            };
            // 注意：restore 的回退口径与运行期 `_split` 不同 —— 它直接回退到
            // **[历史归因]** 第一个可用分区，不先试 "default"（对齐 Python cache.py:564-571）。
            let g = if self.caches.contains_key(g) {
                g
            } else {
                match self.caches.keys().next() {
                    Some(f) => f.as_str(),
                    None => {
                        skipped += 1;
                        continue;
                    }
                }
            };
            groups.entry(g).or_default().push(e);
        }
        for (g, es) in groups {
            if let Some(c) = self.caches.get(g) {
                c.restore_refs(&es, now, persist_ttl);
            }
        }
        // 本次值（不是累加）：与内层 `restore_refs` 的"每次覆盖"语义保持一致。
        self.restore_skipped.store(skipped, Ordering::Relaxed);
        if skipped > 0 {
            tracing::warn!(
                dropped_structural = skipped,
                "PartitionedCache.restore: **已在分组阶段丢弃 {} 条结构不完整的记录**\
                 （key 非数组 / key 长度非 2|3 / 无可用分区）—— 这些条目不会进入任何分区，\
                 其条数计入 `/api/status.cache.restore_drops.failed`",
                skipped
            );
        }
    }

    fn set_capacity(&self, n: usize) {
        let n = clamp_capacity(Some(n));
        self.total_cap.store(n, Ordering::Relaxed);
        // 重算份额并逐分区调整内层 LRU 容量（分组集合不变，仅调容量）。
        let shares = self.allocate(n);
        for (g, c) in &self.caches {
            let share = shares
                .iter()
                .find(|(x, _)| x == g)
                .map(|(_, s)| *s)
                .unwrap_or(16);
            c.set_capacity(share);
        }
    }

    fn set_stale_window(&self, v: u64) {
        for c in self.caches.values() {
            c.set_stale_window(v);
        }
    }

    /// **2.1.19（修复项 1）**：委托路径也必须有可观测计数。
    ///
    /// `PartitionedCache::restore` 按 group 分组后调用内层 `LruCache::restore_refs`，
    /// 因此丢弃发生在**各分区内部**：这里把各分区**本次**的计数**求和**
    /// （`restore` 每次都会覆盖内层计数，所以求和 = 本次委托的总丢弃量）。
    fn last_restore_drops(&self) -> (u64, u64, u64) {
        let mut acc = (0u64, 0u64, 0u64);
        for c in self.caches.values() {
            let (e, l, f) = c.last_restore_drops();
            acc = (acc.0 + e, acc.1 + l, acc.2 + f);
        }
        // **2.1.19（修复项 1 补漏）**：把"分组阶段就被跳过"的条数一并计入 `failed`
        // —— 它们从未进入任何分区，内层计数看不到。
        acc.2 += self.restore_skipped.load(Ordering::Relaxed) as u64;
        acc
    }

    // ---------------- 2.1.29：v2 持久化接缝（M17） ----------------

    /// **2.1.29（v2）**：逐条产出**3 元组键**（分组维由内层补回）。
    fn for_each_entry(&self, now: f64, f: &mut dyn FnMut(&CacheKey, &Arc<crate::CacheEntry>)) {
        for c in self.caches.values() {
            c.for_each_entry(now, f);
        }
    }

    /// **2.1.29（v2）**：按 group 分组后委托内层 `restore_records`（内层会剥掉 group）。
    fn restore_records(&self, entries: Vec<(CacheKey, crate::CacheEntry)>, now: f64) {
        let mut groups: BTreeMap<String, Vec<(CacheKey, crate::CacheEntry)>> = BTreeMap::new();
        let mut skipped = 0u64;
        for (k, e) in entries {
            let g = match k.group.as_deref() {
                Some(g) => g.to_string(),
                None => "default".to_string(),
            };
            // 回退口径与 v1 的 `restore` 一致：找不到分区就退到第一个可用分区。
            let g = if self.caches.contains_key(&g) {
                g
            } else {
                match self.caches.keys().next() {
                    Some(f) => f.clone(),
                    None => {
                        skipped += 1;
                        continue;
                    }
                }
            };
            groups.entry(g).or_default().push((k, e));
        }
        for (g, mut es) in groups {
            if let Some(c) = self.caches.get(&g) {
                for (k, _) in es.iter_mut() {
                    k.group = None;
                }
                c.restore_records(es, now);
            }
        }
        if skipped > 0 {
            tracing::warn!(
                dropped = skipped,
                "PartitionedCache.restore_records: 已在分组阶段丢弃 {skipped} 条（无可用分区）"
            );
        }
    }

    fn persist_stats(&self) -> Option<Arc<PersistStats>> {
        Some(Arc::clone(&self.stats))
    }

    fn attach_journal(&self, j: Arc<CacheJournal>) {
        for c in self.caches.values() {
            c.attach_journal(Arc::clone(&j));
        }
    }

    fn request_snapshot(&self, reason: &'static str) {
        if let Some(c) = self.caches.values().next() {
            c.request_snapshot(reason);
        }
    }
}
