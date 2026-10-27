//! ebpdns-cache：带 TTL 的 DNS 应答缓存，三种淘汰策略共接口。
//!
//! **[历史归因]** 忠实对齐 Python `ebpdns/cache.py`：
//! - [`LruCache`]（`LRUCache`）：8 分片有界 LRU + TTL 惰性/轮转 purge + serve-stale。
//! - [`PartitionedCache`]（`PartitionedCache`）：按 group 分区，每区独立 LRU。
//! - [`TinyLfuCache`]（`TinyLFUCache`）：W-TinyLFU，window/probation/protected 三段 + Count-Min Sketch。
//!
//! 统一抽象见 [`DnsCache`] trait。所有方法以显式 `now: f64`（epoch 秒）为时间源，
//! 便于测试注入 mock 时钟；生产侧用 [`util::now_epoch`]。

// **2.1.24（B4：clippy 清零）**：`clippy::doc_lazy_continuation` 在本 crate **整片允许**，
// 理由是可核查的，不是"关掉告警换清静"：
//   * 命中的全是**中文**文档注释（29 处，逐条清单见 `docs/CLIPPY.md`）。该 lint 用
//     Markdown 的"列表项缩进"规则判连续性，而中文条目里的 `*`/`-` 后面常跟全角标点
//     （`：`/`、`/`⇒`），clippy 据此把**同一个句子的续行**判成"新的段落缺少空行"。
//   * 按它的建议逐行加缩进或空行，会把**已经排好版的中文说明**改写成另一种排版，
//     既不改变任何代码行为，也让 `git diff` 里真正要审的改动被 29 处纯排版噪声淹没。
//   * 真正有害的文档缺陷（缺链接目标、缺 `# Safety` 等）**不在**这条 lint 里，
//     因此允许它不会掩盖真问题。
// 复现：`cargo clippy --workspace --all-targets` 不再报告该 lint；逐条位置见 docs/CLIPPY.md。
#![allow(clippy::doc_lazy_continuation)]

pub mod entry;
pub mod error;
pub mod lru;
pub mod ordered_map;
pub mod partitioned;
pub mod persist;
pub mod swap;
pub mod tinylfu;
pub mod util;

use serde_json::Value;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

pub use entry::{CacheAnswer, CacheEntry, CacheKey};
pub use error::{CacheError, CacheResult};
pub use lru::LruCache;
pub use partitioned::PartitionedCache;
pub use persist::journal::{CacheJournal, ClearReason, Event, EvictReason};
pub use persist::{PersistStats, RestoreSource};
pub use swap::SwappableCache;
pub use tinylfu::TinyLfuCache;
pub use util::{now_epoch, round1};

/// **[历史归因]** 三种缓存策略共用的接口。语义逐一对应 Python `cache.py` 同名方法。
///
/// 所有时间参数为 epoch 秒（浮点）。实现必须 `Send + Sync`，读端在 restore 期间
/// 要么看到完整旧数据、要么看到完整新数据（对齐 C-01 原子换引用）。
pub trait DnsCache: Send + Sync {
    /// 取有效（未过期）条目；过期且 `stale_window<=0` 时惰性删除。命中移到 MRU。
    ///
    /// 返回**拥有所有权**的条目（签名保持不变，兼容既有调用方）。缓存内部按
    /// `Arc<CacheEntry>` 存储，本方法因此需要克隆一份条目（含若干 `String`）。
    /// 调用方若只需要读取，请改用 [`DnsCache::get_arc`] 以避免这次克隆。
    fn get(&self, key: &CacheKey, now: f64) -> Option<CacheEntry>;

    /// 取"已过期但在 stale_window 内"的兜底条目；窗口外则删除。
    /// **[历史归因]** 注意：仍新鲜的条目返回 `None`（对齐 Python get_stale）。
    fn get_stale(&self, key: &CacheKey, now: f64, stale_window: f64) -> Option<CacheEntry>;
    // >>> 242B BEGIN P1-9-trait >>> //
    /// **2.1.42-B（P1-9）**：**纯观测**读取 —— 与 [`DnsCache::get`] 返回同样的
    /// 有效条目判定，但**不改变**任何内部状态：
    /// * LRU 不 `move_to_end`（不改变淘汰顺序）；
    /// * TinyLFU 不 `sketch.inc`、不做 probation→protected 晋升；
    /// * 过期条目不删除（观测端点不得产生写副作用）。
    ///
    /// `/api/snapshot` 这类只读端点必须用它，否则每 2 s 一次的轮询会把前 500 个
    /// key 当成热点刷新，长期改变数据面的真实命中率（审计 A-05）。
    fn peek(&self, key: &CacheKey, now: f64) -> Option<CacheEntry> {
        // 默认实现退化为 get（第三方实现可覆写）；内置三种策略都覆写为 no-touch。
        self.get(key, now)
    }
    // <<< 242B END P1-9-trait <<< //

    /// C-07：与 [`DnsCache::get`] 语义完全相同，但返回 `Arc<CacheEntry>`，
    /// 命中时只做一次引用计数自增（**零堆分配、零克隆**）。
    ///
    /// 默认实现用 `get` 包装（`Arc::new`）——语义等价但对提高性能无益；
    /// [`LruCache`] / [`TinyLfuCache`] / [`PartitionedCache`] / [`SwappableCache`]
    /// 均覆写为直接从内部 `Arc` 取句柄。
    ///
    /// 调用方可这样受益（无需改动本 trait 的既有方法）：
    /// ```ignore
    /// // 旧：每次命中克隆整条 entry（Vec<CacheAnswer> + 4 个 String ≈ 4~6 次堆分配）
    /// if let Some(e) = cache.get(&k, now) { use_ref(&e); }
    /// // 新：命中 0 次堆分配，仅 1 次原子自增
    /// if let Some(e) = cache.get_arc(&k, now) { use_ref(&e); }
    /// ```
    fn get_arc(&self, key: &CacheKey, now: f64) -> Option<Arc<CacheEntry>> {
        self.get(key, now).map(Arc::new)
    }

    /// C-07：与 [`DnsCache::get_stale`] 语义完全相同，但返回 `Arc<CacheEntry>`
    /// （命中零堆分配）。默认实现用 `get_stale` 包装，各策略覆写为真零拷贝。
    fn get_stale_arc(
        &self,
        key: &CacheKey,
        now: f64,
        stale_window: f64,
    ) -> Option<Arc<CacheEntry>> {
        self.get_stale(key, now, stale_window).map(Arc::new)
    }

    /// **2.1.43-B（P2-2）**：把任意入口键归一为**落盘键形态**（= WAL/快照里记录的键）。
    ///
    /// # 为什么必须有这个入口
    ///
    /// `PUT` 由内层策略写出（`PartitionedCache` 的内层会把 2 元组补成 3 元组），而
    /// `EVICT` 由**外层** `SwappableCache::delete` 记录 —— 旧实现直接 `key.clone()`，
    /// 于是同一个条目在 WAL 里出现两种键：
    /// `PUT [group,domain,qtype]` vs `EVICT [domain,qtype]`。回放时 EVICT 走
    /// `PartitionedCache::resolve_group` 回退到 `default` 分区 ⇒ 若条目本来在
    /// `domestic/global`，删除落空 ⇒ **已删除的条目在重启后复活**。
    ///
    /// 现在 `PUT` / `EVICT` / 快照一律经本函数生成键（默认实现 = 原样克隆；
    /// `PartitionedCache` 覆写为"补上实际分区名"）。
    fn journal_key(&self, key: &CacheKey) -> CacheKey {
        key.clone()
    }

    /// 写入/更新条目（含 TTL 淘汰与概率式过期 purge）。
    fn put(&self, key: CacheKey, value: CacheEntry, now: f64);

    /// 删除条目（三种存储段都查）。
    fn delete(&self, key: &CacheKey);

    /// 清空全部条目。
    fn clear(&self);

    /// 当前条目数（持锁求和）。
    fn len(&self) -> usize;

    /// 是否为空。
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 键快照。
    fn keys(&self) -> Vec<CacheKey>;

    /// 只取前 `limit` 个键（管理面采样用；实现应尽量早停避免全量克隆）。
    /// 默认实现退化为 `keys()` 截断，具体策略可按需覆盖。
    fn sample_keys(&self, limit: usize) -> Vec<CacheKey> {
        let mut v = self.keys();
        v.truncate(limit);
        v
    }

    /// 统计摘要（used/capacity/pct + 策略专属段）。
    fn summary(&self) -> Value;

    /// 序列化为可持久化 JSON 对象数组（剔除 resp_body，写入 remaining）。
    fn serialize(&self, now: f64) -> Vec<Value>;

    /// 从 JSON 对象数组恢复；`persist_ttl>0` 时把剩余 TTL 抬升为该值。原子换引用。
    fn restore(&self, entries: &[Value], now: f64, persist_ttl: f64);

    /// 调整总容量（重算分段/分片并裁剪）。
    fn set_capacity(&self, n: usize);

    /// 设置 serve-stale 窗口（秒，>=0）。
    fn set_stale_window(&self, v: u64);

    /// **2.1.19（修复项 1）**：本实例**最近一次** `restore` 的丢弃计数
    /// `(expired, legacy, failed)`。
    ///
    /// 三条策略都必须实现（`PartitionedCache` 聚合各分区）。默认实现返回全 0 是
    /// **刻意的安全默认** —— 它意味着"不做承诺"，而不是"没有丢弃"；因此生产侧
    /// （`main.rs::restore_cache`）只把它当**附加日志字段**打印。
    ///
    /// 为什么放在 trait 上而不是只留 `LruCache` 的固有方法：运维需要在**配置了任意
    /// `cache_policy` 时**都能自证"旧格式条目被丢弃且被计数"。2.1.19 只有 `LruCache`
    /// 有这个固有方法，而生产默认策略是 `tinylfu` ⇒ **实际生效的那条路径无法观测**，
    /// 这正是"计数恒 0 / WARN 不触发"得以长期潜伏的结构性原因。
    fn last_restore_drops(&self) -> (u64, u64, u64) {
        (0, 0, 0)
    }

    /// **2.1.43-B（P2-4）**：本实例**最近一次** `restore` 中"**因 window 段不参与恢复**
    /// 而被挤出的条目数"（仅 [`crate::TinyLfuCache`] 有 window 段；lru / partitioned 恒 0）。
    ///
    /// # 为什么需要这个口径
    ///
    /// TinyLFU 的快照**包含** window 段（`for_each_entry` 三段全写），但 `restore` 只把
    /// **main 段容量**（`cap − window`，出厂比例 ≈ 99%）灌满，其余（≈ 1%，正是 window 段
    /// 容量级）**不再放回**。这是 2.1.29 起就有的行为，却**从未计数**：
    /// `restore_drops` 三键全 0，`used_live` 又按"恢复计划里的条数"赋值 ⇒ 恢复丢失率
    /// 公式 `(snap_entries − used_live) / snap_entries` 读出来是 **0**，而实际丢了 ~1%。
    ///
    /// 现在：①本键让这部分丢失**可观测**（`/api/status.cache.restore_drops.window_unpersisted`
    /// 与 `/api/cache/stats.restore_drops.window_unpersisted` 同源）；
    /// ②`used_live` 改为"**恢复后实际插入**的条数"，于是丢失率公式**自动包含**本项。
    ///
    /// 默认实现返回 0 是**刻意的安全默认**（"不做承诺"，而不是"没有丢失"），与
    /// [`DnsCache::last_restore_drops`] 同口径。
    fn last_restore_window_unpersisted(&self) -> u64 {
        0
    }

    /// **2.1.19（修复项 1 补漏：文件级损坏）**：记录一次**整个文件不可解析**的恢复失败。
    ///
    /// 为什么必须单独有这个入口：文件级失败时 per-entry 的 [`DnsCache::restore`]
    /// **根本不会被调用** ⇒ 各实现的丢弃计数会保留**上一次**的值，于是
    /// `/api/status.cache.restore_drops` 与 `/api/cache/stats.restore_drops` 会显示
    /// `failed: 0`（**说谎**；部署代理实测：ERROR=1、WARN=0、两端点 `{"expired":0,"failed":0,"legacy":0}`）。
    ///
    /// 单位约定：`failed` 至少为 `1`（表示"整个文件一份都没恢复"）。
    /// 默认实现是**刻意的 no-op**（真正需要它的是外壳 [`crate::SwappableCache`] ——
    /// 它是唯一同时知道"文件级"与"per-entry"两条路径的对象）。
    fn record_file_level_restore_failure(&self, failed: u64) {
        let _ = failed;
    }

    /// **2.1.25（B8 性能项：分块流式落盘）**：逐条产出快照（每条是**最终**形态的
    /// `Value`：已含 `remaining`；分区策略已含 group 前缀）。
    ///
    /// 默认实现 = "先 [`DnsCache::serialize`] 再逐条吐出"（语义正确，但仍会建整表
    /// `Vec<Value>`）；三条真实策略**覆盖**它，做到逐条产生、逐条丢弃。
    fn for_each_snapshot_entry(&self, now: f64, f: &mut dyn FnMut(Value)) {
        for v in self.serialize(now) {
            f(v);
        }
    }

    /// **2.1.25（B8 性能项：分块流式落盘）**：把当前快照**直接**写成 JSON，
    /// 返回写出的**条目数**。
    ///
    /// 契约（硬）：产出字节与 `serde_json::to_vec_pretty(&self.serialize(now))`
    /// **逐字节相同**（单测 `write_snapshot_is_byte_identical_to_to_vec_pretty` 钉死），
    /// 因此**磁盘格式、恢复语义、崩溃安全窗口全都不变** —— 变的只有"为了写这份文件
    /// 需要多少内存、锁要持多久"。
    ///
    /// 旧路径的三处浪费（2.1.24 登记项「缓存落盘整表重写」）：
    /// ①`serialize(now)` 把**整表**建成 `Vec<Value>`（每条约 6 键的 `Map` + 若干
    ///   `String`）；②`to_vec_pretty` 再把它变成**整块** `Vec<u8>`；③两者同时存活
    ///   ⇒ 峰值内存 ≈ 表大小 × (Value 树 + 文本)，且**整段时间持有缓存锁**。
    fn write_snapshot(&self, now: f64, w: &mut dyn std::io::Write) -> std::io::Result<u64> {
        let mut sink = SnapshotSink::new(w);
        self.for_each_snapshot_entry(now, &mut |v| sink.push(&v));
        sink.finish()
    }

    // ---------------- 2.1.29：缓存持久化 v2 的接缝（M2） ----------------

    /// **2.1.29（v2）**：逐条产出**原始条目**（键 + `Arc<CacheEntry>`），供二进制快照使用。
    ///
    /// 与 [`DnsCache::for_each_snapshot_entry`] 的区别：这里**不做** JSON 化、**不写**
    /// `remaining`、**不克隆**条目（零拷贝），因为二进制快照直接按字段表编码。
    ///
    /// 快照一致性靠 `entry.seq <= snapshot_seq` 过滤（§6.3.4），**不要求全局锁** ——
    /// 一 shard 一锁、逐片迭代即可（迭代期间的新变更 seq 必 > S）。
    ///
    /// 默认实现退化为“`keys()` + `get_arc`”（语义正确，但会改动 LRU 顺序且多一次
    /// `Arc` 克隆）；三条真实策略**都覆盖**它。
    fn for_each_entry(&self, now: f64, f: &mut dyn FnMut(&CacheKey, &Arc<CacheEntry>)) {
        for k in self.keys() {
            if let Some(e) = self.get_arc(&k, now) {
                f(&k, &e);
            }
        }
    }

    /// **2.1.46（REV247 B P2-6）**：把当前**未过期**条目收集成 `(key, Arc<entry>)`，
    /// 让快照写盘在**缓存锁外**序列化/写文件。
    ///
    /// 旧路径直接把 `SnapshotWriter` 的写入闭包传给 [`DnsCache::for_each_entry`]：
    /// TinyLFU 的 `for_each_entry` 持整把 `inner` 锁遍历三段，`EntryBody::from_entry`
    /// 编码 + `BufWriter` 写盘全在锁内 —— 一次 13 万条快照会让数据面 `put/get`
    /// 阻塞到磁盘写完。现在只在本方法内持锁克隆键与 `Arc`（不编码、不做 IO），
    /// 随后在锁外逐条编码/写盘。
    fn collect_snapshot_entries(&self, now: f64) -> Vec<(CacheKey, std::sync::Arc<CacheEntry>)> {
        let mut out = Vec::new();
        self.for_each_entry(now, &mut |k, e| {
            if e.expires_at > now {
                out.push((k.clone(), std::sync::Arc::clone(e)));
            }
        });
        out
    }

    /// **2.1.29（v2）**：一次性装入恢复条目（**TTL 决策已完成**，不再传 `persist_ttl`）。
    ///
    /// 调用方（`persist::recover` / v1 迁移）已用
    /// [`util::resolve_restored_expiry`] 统一处理过三段语义；本方法只负责
    /// “建 map / 分片 / 容量截断 / 按策略插入”，**不得**再套一次 `persist_ttl`
    /// （否则 `now` 会被二次锚定）。
    fn restore_records(&self, entries: Vec<(CacheKey, CacheEntry)>, now: f64);

    /// **2.1.29（v2）**：持久化现场统计（两 API 端点读**同一份**）。
    fn persist_stats(&self) -> Option<Arc<PersistStats>> {
        None
    }

    /// **2.1.29（v2）**：把 journal 装进本策略（热切换后由外壳对新实例重放一次）。
    fn attach_journal(&self, j: Arc<CacheJournal>) {
        let _ = j;
    }

    /// **2.1.29（v2）**：请求下一次快照（策略热切换/迁移/管理动作）。
    fn request_snapshot(&self, reason: &'static str) {
        let _ = reason;
    }
}

/// **2.1.25（B8）**：`serde_json::to_vec_pretty(&Vec<Value>)` 的**流式等价物**。
///
/// 复刻 `PrettyFormatter` 对**顶层数组**的形态：
/// 空表 ⇒ `[]`；否则 `[\n` + 每元素（整体缩进 **2** 空格）+ `,\n` 分隔 + `\n]`。
/// 元素内部沿用 `serde_json::to_string_pretty` 自己的缩进（同源 formatter），
/// 因此整段文本与"一次性序列化整个 `Vec<Value>`"**逐字节相同**（有单测）。
///
/// 错误处理：`push` 把第一个 IO 错误记下来并**停止写入**（闭包签名 `FnMut(Value)`
/// 无法返回 `Result`），`finish` 再把它交出去 —— 调用方看到的仍是 `io::Result`。
pub struct SnapshotSink<'w> {
    w: &'w mut dyn std::io::Write,
    n: u64,
    err: Option<std::io::Error>,
}

impl<'w> SnapshotSink<'w> {
    /// 包装一个 writer（生产侧是 `BufWriter<File>`）。
    pub fn new(w: &'w mut dyn std::io::Write) -> Self {
        Self { w, n: 0, err: None }
    }

    /// 追加一条记录（**已成形**的 `Value`）。首次 push 负责写 `[\n`。
    pub fn push(&mut self, v: &Value) {
        if self.err.is_some() {
            return;
        }
        let r = (|| -> std::io::Result<()> {
            if self.n == 0 {
                self.w.write_all(b"[\n")?;
            } else {
                self.w.write_all(b",\n")?;
            }
            write_indented(self.w, v)
        })();
        match r {
            Ok(()) => self.n += 1,
            Err(e) => self.err = Some(e),
        }
    }

    /// 收尾（空表写 `[]`，否则补 `\n]`），返回条目数。
    pub fn finish(mut self) -> std::io::Result<u64> {
        if let Some(e) = self.err.take() {
            return Err(e);
        }
        if self.n == 0 {
            self.w.write_all(b"[]")?;
        } else {
            self.w.write_all(b"\n]")?;
        }
        Ok(self.n)
    }
}

/// 把一条 `Value` 的 pretty 文本**整体缩进两空格**写出去（数组元素在 depth=1）。
fn write_indented(w: &mut dyn std::io::Write, v: &Value) -> std::io::Result<()> {
    // 注意：**不要**在这里 `use std::io::Write` —— `w` 的类型就是 `dyn std::io::Write`，
    // 其方法（`write_all`）无需 trait 导入即可调用；多写一行 `use` 会触发
    // `unused_imports`，而在 `-D warnings` 下 clippy 直接红（2.1.25 实测过一次）。
    let s = serde_json::to_string_pretty(v).map_err(std::io::Error::other)?;
    let bytes = s.as_bytes();
    let mut start = 0usize;
    loop {
        w.write_all(b"  ")?;
        match s[start..].find('\n') {
            Some(i) => {
                w.write_all(&bytes[start..start + i + 1])?;
                start += i + 1;
            }
            None => {
                w.write_all(&bytes[start..])?;
                break;
            }
        }
    }
    Ok(())
}

/// **[历史归因]** 计算分片路由哈希（对齐 Python `hash(key) & (SHARDS-1)`）。
/// 用稳定的 DefaultHasher；同一进程内 inc/freq/shard 口径一致即可。
pub(crate) fn hash_key(k: &CacheKey) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    k.hash(&mut h);
    h.finish()
}
