//! **2.1.49-p3**：S3-FIFO（Simple, Scalable, S3）缓存策略。
//!
//! 设计（对齐 SOSP'23《FIFO queues are all you need for cache eviction》）：
//! * **S**（small FIFO，约 10% 容量）：新对象先进 S；被复用（freq>0）的移入 M；
//! * **M**（main FIFO，约 90%）：需要空间时检查队首——freq>0 则减一后放回队尾（惰性晋升），
//!   否则淘汰；
//! * **G**（ghost FIFO）：只记被淘汰的键（不含数据），再次请求命中 ghost ⇒ 直接进 M；
//! * 命中只做 2-bit 计数（0..=3），**不移动队列**，热路径无锁竞争。
//!
//! 本实现采用**包装式**结构：数据存储/持久化/过期清理复用 [`LruCache`]（它是经过审计的
//! 分片存储 + journal + 快照实现），S3-FIFO 只负责**淘汰决策**：
//! `put` 后若超容量/超字节预算，由策略选出牺牲者并调用 `inner.delete`（会写 EVICT 事件），
//! 因此持久化与既有一致性保证不变。
//!
//! 额外能力（p3 需求）：
//! * **字节预算**：`cache_bytes > 0` 时按条目估算大小淘汰（防大 TXT/长 CNAME 链打爆内存）；
//! * **单条上限**：`max_entry_bytes > 0` 时拒绝缓存超大条目；
//! * **过期优先**：淘汰前先探测队首是否已过期（`peek` 返回 None），过期条目立即回收；
//! * **频率优先预取**：`hot_keys(limit)` 按 freq 降序返回候选，供 resolver 预取使用。
//!
//! # **2.1.49-p6**：policy 分片（8 片）
//!
//! 旧结构是**单一全局 `Mutex<Policy>` + 单 TTL 堆**：`get_arc` 命中、`put`、`delete`
//! 全都要抢同一把锁 ⇒ 高并发下 policy Mutex 成了内层分片锁之外的**第二个串行点**
//! （命中率越高、并发越大，这把锁越烫）。现在 `policy` 拆成 `POLICY_SHARDS = 8` 个
//! **互相独立**的分片，每片自带 S/M/G 队列、TTL 最小堆、负缓存集合、字节用量与
//! `freq`/`sizes` 簿记：
//!
//! * **路由**：`policy_shard_index(k) = crate::hash_key(k) & (POLICY_SHARDS - 1)`
//!   ——稳定哈希，同一键永远落在同一片（与内层 `LruCache` 用**同一个** hash 函数，
//!   但 policy 分片是独立关注点：不读取、也不依赖 LRU 的分片编号/容量）；
//! * **锁序**：任何路径**同一时刻只持有一把 policy 分片锁**（`clear` / `policy_stats` /
//!   `hot_keys` / `rebuild_policy` / `set_capacity` 都是逐片加锁-释放），持锁期间只
//!   向下调用内层 `LruCache`（其分片锁是叶子锁，不会回调 policy）⇒ 分片锁之间无环；
//! * **容量/预算均分**：`cap_i = cap/8 + (i < cap%8 ? 1 : 0)`（`Σ cap_i == cap`，
//!   逐片严格 ⇒ 全局仍严格 `len() <= cap`）；`bytes_cap` 同法均分；`neg_pct` 是**百分比**，
//!   每片用同一 pct 施加在**本片 cap_i** 上（Σ 配额 ≈ 全局 pct）；
//! * **evicted 只影响本片**：各片只淘汰本片的键；`put` 只 drain 本片 `evicted` 并失效
//!   对应热点副本（`hot` 是全局表，按键失效即可）；
//! * **restore 后重建**：按路由把存活键分桶回各片（堆/负缓存/大小/队列同步重建）。
//!
//! ## 语义放宽（刻意、已知、已在交付说明中列明）
//!
//! 1. 总容量 / 字节预算 / 负配额 从"全局精确"变为"**按片均分后的近似全局上限**"：
//!    逐片严格不超过 `cap_i`/`bytes_cap_i`，所以全局**不会超过**原上限，但分布不均时
//!    某片先用满、别的片还有空位（旧实现可跨片借用空间）。
//! 2. 单键热点计数只在**片内**统计 —— 同一键永远在同一片，故逐键 `freq` 与旧实现
//!    **完全相同**；唯一差异在 `hot_keys`：候选池按片取样后合并排序，与旧实现的
//!    "全表 top-K"可能在同一频率边界上差几个键。
//! 3. `len()` 仍来自内层 `LruCache`（`Σ 片内 <= cap_i` ⇒ `<= cap`），口径不变。

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};

use crate::entry::{CacheEntry, CacheKey};
use crate::lru::{LruCache, RemovalReason};
use crate::persist::journal::CacheJournal;
use crate::persist::PersistStats;
use crate::wire::WireEntry;
use crate::{hash_key, DnsCache};
use serde_json::{json, Value};

/// S 队列占容量比例（%）：10%。
const S_PCT: usize = 10;

/// 负缓存配额默认值（%）：由配置 `negative_pct` 覆盖（0 = 不限制）。
const NEG_PCT_DEFAULT: usize = 20;

/// **2.1.49-p6**：policy 分片数（必须是 2 的幂：路由用 `& (POLICY_SHARDS - 1)`）。
///
/// 取 8 与内层 `LruCache::SHARDS` 相同：容量/预算均分后每片的 `cap_i` 恰好是内层
/// 同号分片容量（`2×cap/8`）的一半 ⇒ 内层的 2× 余量按片继续成立，正常写入路径上
/// **只有 policy 层会淘汰**（与旧实现的"策略层裁剪、存储层留余量"一致）。
const POLICY_SHARDS: usize = 8;

/// 单条条目的大小估算（字节）：只计**堆上主要数据**，用于字节预算。
///
/// 结构体自身/Arc 头等固定开销用一个常数近似（不追求逐位精确，只需单调可比）。
pub fn entry_size_bytes(e: &CacheEntry) -> usize {
    let mut n = 96 + e.domain.len() + e.qtype.len() + e.chosen.len();
    // **阶段 B-2**：`rrsets` 是「RRset 列表 + 每个 RRset 的取值列表」，逐条累计
    // （共享只降低真实 RSS，不改变这里的逻辑计费）。
    for rs in &e.rrsets {
        n += 48 + rs.owner.len();
        for a in &rs.values {
            n += 48 + a.value.len() + a.name.as_ref().map_or(0, |s| s.len());
        }
    }
    // 规则/负缓存等附加字段的粗略开销
    n += 32;
    n
}

fn present(inner: &LruCache, k: &CacheKey) -> bool {
    inner.peek(k, 0.0).is_some()
}

/// **2.1.49-p6**：policy 分片路由（稳定哈希 → 分片号）。
///
/// 复用 crate 的 [`hash_key`]（`DefaultHasher`，与 `LruCache` 的分片路由同一函数），
/// 因此同一键在**任何**入口（`get`/`get_arc`/`put`/`delete`/`restore`/`policy_stats`）
/// 都得到同一个片号 —— 这是"片内簿记不会张冠李戴"的唯一前提。
///
/// 与 LRU 内层分片**无关**：本函数只用于 policy 路由，不读取 LRU 的分片状态；两者
/// 恰好都是 8 片（同余）是刻意选择（见 [`POLICY_SHARDS`] 的说明），改这里的分片数
/// 不影响正确性，只是失去与内层 2× 余量的对齐。
#[inline]
fn policy_shard_index(k: &CacheKey) -> usize {
    (hash_key(k) as usize) & (POLICY_SHARDS - 1)
}

/// **2.1.49-p6**：把总量均分到各片：前 `total % POLICY_SHARDS` 片各多 1（`Σ == total`）。
///
/// * `total == 0` ⇒ 0（0 在容量/预算里的语义是"关闭"，不得被抬成 1）；
/// * `total > 0` 时每片至少 1（总量极小时 `Σ` 会略大于 `total` —— 近似上限的已知代价，
///   典型值 `cache_size >= 16`、`cache_bytes` 都是几百 KB 以上，不会走到这一档）。
#[inline]
fn split_total(total: usize, i: usize) -> usize {
    if total == 0 {
        return 0;
    }
    (total / POLICY_SHARDS + usize::from(i < total % POLICY_SHARDS)).max(1)
}

/// **2.1.49-p6**：一个 policy 分片的全部簿记（S/M/G 队列 + TTL 堆 + 配额与字节用量）。
///
/// 分片之间不共享任何字段；`cap`/`bytes_cap`/`max_entry_bytes`/`neg_pct` 是**每片的
/// 配置值**（由 `S3FifoCache` 在构造 / `set_*` 时下发）。
/// **2.2.1（P2-01）**：S/M 段标识（`sizes` 里记住条目当前在哪个队列，`remove()` 用它
/// 精确扣减 `s_live`/`m_live`）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Segment {
    S,
    M,
    /// 已从队列弹出（淘汰/晋升过程中）：**不再计入** `s_live`/`m_live`，`remove()`
    /// 见到它不得再次扣减（否则同一键被扣两次 ⇒ `segment_*` 漂移）。
    Out,
}

/// **2.2.1（P2-01）**：`sizes` 值 = 字节数 + 队列代际 + 所在段。
#[derive(Clone, Copy)]
struct Sizing {
    bytes: usize,
    gen: u32,
    seg: Segment,
}

struct Policy {
    cap: usize,
    scap: usize,
    mcap: usize,
    gcap: usize,
    bytes_cap: usize,
    max_entry_bytes: usize,
    neg_pct: usize,
    used_bytes: usize,
    /// S/M 队列元素 = `(key, 代际)`；代际与 `sizes[key].gen` 不一致即为删除后残留的
    /// 旧节点（跳过即可，无需从队列中间摘除）。
    s: VecDeque<(CacheKey, u32)>,
    m: VecDeque<(CacheKey, u32)>,
    g: VecDeque<CacheKey>,
    gset: HashSet<CacheKey>,
    freq: HashMap<CacheKey, u8>,
    /// 每个存活条目的字节数与**队列代际**。
    ///
    /// `gen`/`seg` 是 **2.2.1（P2-01）** 修掉"队列簿记漂移"的关键：`remove()` 只删本表
    /// 与 `freq`（O(1)），队列里的旧节点不立刻摘除，而是凭"代际不再匹配"被识别为残影
    /// 并跳过。没有它就只能 O(n) 扫描 `VecDeque` 摘节点（TTL 批量过期时 O(n²)）或放任
    /// `segment_s + segment_m > size`（2.2.0 生产实测 371 > 351）。
    sizes: HashMap<CacheKey, Sizing>,
    /// 队列节点的代际分配器（0 保留 = 未入队）。
    next_gen: u32,
    /// **存活**（代际匹配）的 S/M 队列长度；`VecDeque::len()` 含残影，**不得**用于
    /// 容量判据与 `/api/cache/stats.segment_*`。
    s_live: usize,
    m_live: usize,
    /// **2.1.49-p4**：TTL 最小堆（毫秒, key）——淘汰/写入前先回收最早过期的条目。
    expiry: BinaryHeap<Reverse<(i64, CacheKey)>>,
    /// **2.1.49-p4**：负缓存键集合（用于配额与优先淘汰）。
    negatives: HashSet<CacheKey>,
    /// **2.1.49-p5**：本次操作中被淘汰的键（供外层同步失效 hot 副本）。
    evicted: Vec<CacheKey>,
    /// 因单条超限被拒绝缓存的条数（诊断）。
    rejected_large: u64,
    /// **2.2.0（能力 1）/ 2.2.3（P2-D）**：淘汰原因计数（累计量，`clear()` 不清）。
    ///
    /// 口径（与 `summary()` 的字段逐字对应）：
    /// * `evict_expired` / `evict_capacity` / `evict_negative`：**条目数**；
    /// * `evict_bytes`：上述淘汰事件实际释放的**字节数**（2.2.3 前是"字节超预算次数"，
    ///   名实不符；现在为真实字节，且与三个条目计数同源）；
    /// * `ghost_hits`：被淘汰的键再次写入时**命中幽灵队列**（直接进 M 队列）的次数。
    ///
    /// **2.2.3（P2-D）**：显式 `delete`/`clear` **不是淘汰**，但同样会让 `used_bytes`
    /// 下降；为了让字节账可对账，单独计 `removed_delete*` / `removed_clear*`。
    /// `evict_*` 与 `removed_*` 互不重叠。
    evict_expired: u64,
    /// **2.2.4（P2-G）**：其中由**写路径轮转 TTL purge** 删除的条目数。
    ///
    /// `evict_expired` 包含"轮转 purge + 读路径惰性删除"两类；本字段只计前者，
    /// 用于回答"生产为什么长期是 0"：`serve_stale + stale_ttl=3600` 时，条目必须
    /// 过期满 3600s 才会被 purge 扫到。短 TTL/短 stale 窗口的受控实例可直接观测到它增长。
    purge_expired: u64,
    evict_capacity: u64,
    evict_negative: u64,
    /// 淘汰释放的**真实字节**（不是次数）。
    evict_bytes: u64,
    /// 显式 `delete` 删除的条目数 / 字节。
    removed_delete: u64,
    removed_delete_bytes: u64,
    /// `clear()` 清空的条目数 / 字节。
    removed_clear: u64,
    removed_clear_bytes: u64,
    ghost_hits: u64,
}

/// wire 打包缓存：键 → 原始响应字节；容量 = 4×条目容量（防无界）。
struct WireStore {
    map: HashMap<CacheKey, Arc<WireEntry>>,
    fifo: VecDeque<CacheKey>,
    cap: usize,
}

impl WireStore {
    fn new(cap: usize) -> Self {
        Self {
            map: HashMap::new(),
            fifo: VecDeque::new(),
            cap: cap.max(16).saturating_mul(4),
        }
    }

    fn put(&mut self, k: CacheKey, w: Arc<WireEntry>) {
        if self.map.insert(k.clone(), w).is_none() {
            self.fifo.push_back(k);
        }
        while self.fifo.len() > self.cap {
            if let Some(old) = self.fifo.pop_front() {
                self.map.remove(&old);
            }
        }
    }

    fn get(&self, k: &CacheKey) -> Option<Arc<WireEntry>> {
        self.map.get(k).cloned()
    }

    fn remove(&mut self, k: &CacheKey) {
        self.map.remove(k);
    }

    fn clear(&mut self) {
        self.map.clear();
        self.fifo.clear();
    }
}

/// **2.2.3（P2-D）**：淘汰原因（决定计入哪个条目计数；字节统一计 `evict_bytes`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvictCause {
    Expired,
    Capacity,
    Negative,
}

impl Policy {
    /// 构造一个分片。**不再做 `max(16)`**：全局容量在 `S3FifoCache` 侧已钳到 `>= 16`，
    /// 均分后每片 `>= 2`（16/8）；这里只防 0（否则 `scap`/`mcap` 会退化）。
    fn new(cap: usize) -> Self {
        let cap = cap.max(1);
        let scap = (cap * S_PCT / 100).max(1);
        Self {
            cap,
            scap,
            mcap: cap - scap,
            gcap: cap,
            bytes_cap: 0,
            max_entry_bytes: 0,
            neg_pct: NEG_PCT_DEFAULT,
            used_bytes: 0,
            // **2.2.0（能力 1 / 优化：实测后回退）**：曾尝试按分片容量**预分配**
            // 簿记容器（`with_capacity(cap)`，每片 cap_i≈16384）。10 分钟真实域名额
            // A/B 实测：
            //   * 收益：lost 0.135% → 0.051%、p99 219.9ms → 186.0ms、qps +1.6%
            //   * 代价：**RSS 66MB → 145MB（+120%）** —— 违反"RSS ≤ 基线 +10%"的验收线
            // 结论：收益主要来自上游网络波动（同期 SERVFAIL 未变），RSS 代价是确定的
            // ⇒ **回退**，保留惰性增长（稳态 RSS 与 2.1.49 持平，见 REBUILD 报告 §7）。
            s: VecDeque::new(),
            m: VecDeque::new(),
            g: VecDeque::new(),
            gset: HashSet::new(),
            freq: HashMap::new(),
            sizes: HashMap::new(),
            next_gen: 1,
            s_live: 0,
            m_live: 0,
            expiry: BinaryHeap::new(),
            negatives: HashSet::new(),
            evicted: Vec::new(),
            rejected_large: 0,
            evict_expired: 0,
            purge_expired: 0,
            evict_capacity: 0,
            evict_negative: 0,
            evict_bytes: 0,
            removed_delete: 0,
            removed_delete_bytes: 0,
            removed_clear: 0,
            removed_clear_bytes: 0,
            ghost_hits: 0,
        }
    }

    fn rebuild_caps(&mut self, cap: usize) {
        self.cap = cap.max(1);
        self.scap = (self.cap * S_PCT / 100).max(1);
        self.mcap = self.cap - self.scap;
        self.gcap = self.cap;
    }

    /// **2.1.49-p6**：清空全部簿记（保留 `cap`/`bytes_cap`/`max_entry_bytes`/`neg_pct`
    /// 这些**配置**字段与诊断计数 `rejected_large`）。
    ///
    /// `clear()` 与 `rebuild_policy()` 共用：分片后原来那段 12 行的手写清空要重复 8 次，
    /// 漏一个字段就会留下跨片脏状态，所以收敛到一处。
    fn reset(&mut self) {
        self.s.clear();
        self.m.clear();
        self.g.clear();
        self.next_gen = 1;
        self.s_live = 0;
        self.m_live = 0;
        self.gset.clear();
        self.freq.clear();
        self.sizes.clear();
        self.expiry.clear();
        self.negatives.clear();
        self.used_bytes = 0;
    }

    fn on_hit(&mut self, k: &CacheKey) -> u8 {
        // **2.2.2（P1-01 复审修正）**：只为**已登记**的键累计频率。
        // 并发窗口：`inner.put` 已写入、`on_insert` 还没拿到 policy 锁时，读路径的
        // `on_hit` 若先插入 `freq`，`on_insert` 会因 `freq.contains_key` 为真而**跳过
        // 入队** ⇒ `freq` 有键但 `s_live+m_live` 没加（"0+0 vs 1"的不变量破坏）。
        // 未登记的命中直接返回 0（频率只是启发式，下一次命中照常累计）。
        if !self.sizes.contains_key(k) {
            return 0;
        }
        let f = self.freq.entry(k.clone()).or_insert(0);
        if *f < 3 {
            *f += 1;
        }
        *f
    }

    /// **2.2.3（P2-D）**：淘汰一个键：删存储 + 清策略簿记 + 记录给外层失效 hot 副本，
    /// 并**按真实字节**记账。
    ///
    /// `evict_bytes` 在 2.2.3 前是"淘汰时同时超字节预算"的**次数**（名实不符）；
    /// 现在累计被淘汰条目的 `Sizing.bytes`，与 `evict_expired/capacity/negative` 的
    /// 条目计数同源、同一批事件（可互相校验：`evict_bytes` = Σ 这些条目的大小）。
    fn evict_entry(&mut self, inner: &LruCache, k: &CacheKey, cause: EvictCause) {
        let bytes = self.sizes.get(k).map(|sz| sz.bytes as u64).unwrap_or(0);
        inner.delete(k);
        self.remove(k);
        // **2.2.1（P2-09）**：不再截断到 512。旧实现一次淘汰 >512 条时只把前 512 个键
        // 交给外层失效 hot 副本，其余 hot 副本能继续返回**已淘汰**的旧答案直到 TTL。
        // 现在全量收集；调用方（`put`/setter）在超过 512 条时直接 `hot.clear()+gen++`，
        // 既正确又避免上万次哈希删除。
        self.evicted.push(k.clone());
        self.evict_bytes = self.evict_bytes.saturating_add(bytes);
        match cause {
            EvictCause::Expired => self.evict_expired += 1,
            EvictCause::Capacity => self.evict_capacity += 1,
            EvictCause::Negative => self.evict_negative += 1,
        }
    }

    /// **2.2.1（P2-01）**：删除一个键的**全部簿记**（O(1)）。
    ///
    /// 不再从 `s`/`m` 做 O(n) 摘除：队列节点带代际，`remove` 后旧节点自然失效；
    /// 这里只需按 `sizes.seg` 精确扣减 `s_live`/`m_live`，保证
    /// `segment_s + segment_m == freq.len()`（无 ghost 时）恒成立。
    fn remove(&mut self, k: &CacheKey) {
        self.freq.remove(k);
        self.negatives.remove(k);
        if let Some(sz) = self.sizes.remove(k) {
            self.used_bytes = self.used_bytes.saturating_sub(sz.bytes);
            match sz.seg {
                Segment::S => self.s_live = self.s_live.saturating_sub(1),
                Segment::M => self.m_live = self.m_live.saturating_sub(1),
                Segment::Out => {} // 已被 pop_live 扣减过
            }
        }
        self.gset.remove(k);
    }

    /// 新代际入队（同一键重复入队即产生新的"当前节点"，旧节点自动成为残影）。
    fn enqueue(&mut self, seg: Segment, k: CacheKey) {
        let g = self.next_gen.max(1);
        self.next_gen = self.next_gen.wrapping_add(1).max(1);
        if let Some(sz) = self.sizes.get_mut(&k) {
            sz.gen = g;
            sz.seg = seg;
        }
        match seg {
            Segment::S => {
                self.s.push_back((k, g));
                self.s_live += 1;
            }
            Segment::M => {
                self.m.push_back((k, g));
                self.m_live += 1;
            }
            Segment::Out => unreachable!("enqueue(Segment::Out)"),
        }
    }

    /// 弹出一个**存活**节点；残影（代际不匹配）顺带丢弃，不计入队列长度。
    fn pop_live(&mut self, seg: Segment) -> Option<CacheKey> {
        loop {
            let item = match seg {
                Segment::S => self.s.pop_front(),
                Segment::M => self.m.pop_front(),
                Segment::Out => None,
            };
            let (k, g) = item?;
            let live = self
                .sizes
                .get(&k)
                .is_some_and(|sz| sz.gen == g && sz.seg == seg);
            if !live {
                continue;
            }
            match seg {
                Segment::S => self.s_live = self.s_live.saturating_sub(1),
                Segment::M => self.m_live = self.m_live.saturating_sub(1),
                Segment::Out => {}
            }
            // **关键**：标记"已出队"，让后续 `remove()` 不再重复扣减计数器。
            if let Some(sz) = self.sizes.get_mut(&k) {
                sz.seg = Segment::Out;
            }
            return Some(k);
        }
    }

    fn is_live_node(&self, k: &CacheKey, g: u32) -> bool {
        self.sizes.get(k).is_some_and(|sz| sz.gen == g)
    }

    /// 存活键（按队列顺序去重）：TTL 堆重建 / 诊断用。
    fn live_keys(&self) -> Vec<CacheKey> {
        let mut out = Vec::with_capacity(self.s_live + self.m_live);
        for (k, g) in self.s.iter().chain(self.m.iter()) {
            if self.is_live_node(k, *g) {
                out.push(k.clone());
            }
        }
        out
    }

    fn push_ghost(&mut self, k: &CacheKey) {
        if self.gset.insert(k.clone()) {
            self.g.push_back(k.clone());
            while self.g.len() > self.gcap {
                if let Some(old) = self.g.pop_front() {
                    self.gset.remove(&old);
                }
            }
        }
    }

    /// 插入新条目（数据已写入 inner）。
    ///
    /// `expires_at`：绝对到期时间（epoch 秒）；`is_negative`：NXDOMAIN/NODATA。
    fn on_insert(
        &mut self,
        k: &CacheKey,
        size: usize,
        expires_at: f64,
        is_negative: bool,
        now: f64,
        inner: &LruCache,
    ) {
        if self.max_entry_bytes > 0 && size > self.max_entry_bytes {
            self.rejected_large += 1;
            // 单条超限拒绝：也走统一淘汰记账（按容量原因），保证 byte 账闭合。
            self.evict_entry(inner, k, EvictCause::Capacity);
            return;
        }
        // **审查修复（round 1）**：覆盖写同一键时必须先扣掉旧尺寸，否则 `used_bytes`
        // 每次刷新都只增不减 ⇒ 配了 `cache_bytes` 的实例会误判超预算而过度淘汰
        // （极端情况下"刷新一个热键把其它条目全挤掉"）。`sizes.insert` 返回旧值。
        match self.sizes.get_mut(k) {
            Some(sz) => {
                // **2.2.1（P2-01）**：覆盖写**不得**重置 `gen`/`seg` —— 该键已经在
                // S/M 队列里（计数器也记在对应段），重置会让后续 `remove()` 扣错段，
                // 造成"m_live 有、freq 没有"的幽灵计数。
                let prev = sz.bytes;
                sz.bytes = size;
                self.used_bytes = self.used_bytes.saturating_sub(prev);
            }
            None => {
                self.sizes.insert(
                    k.clone(),
                    Sizing {
                        bytes: size,
                        gen: 0,
                        seg: Segment::Out,
                    },
                );
            }
        }
        self.used_bytes += size;
        self.expiry
            .push(Reverse(((expires_at * 1000.0) as i64, k.clone())));
        if is_negative {
            self.negatives.insert(k.clone());
        } else {
            // **2.2.0 终审（P1）**：同一键可能先从负条目（NXDOMAIN/NODATA）变成正条目
            // （域名后来注册 / 上游恢复）。旧实现只在 `is_negative` 时插入、从不在转正时
            // 移除 ⇒ `negatives.len()` 只增不减，累计超过配额后 `negative_over_quota()`
            // 恒真，`evict_if_needed` 会一直走"优先淘汰负条目"的分支（找不到负条目时
            // 每次插入都白扫 128 个键并兜底淘汰正条目），直到重启/清缓存才恢复。
            // 配额是"当前负条目数"的判据，必须随条目状态双向维护。
            self.negatives.remove(k);
        }
        // **审查修复（p4）**：TTL 堆惰性删除会累积陈旧项（反复写同键/被淘汰的键）——
        // 超过 4×容量时按当前存活键重建，保证堆内存有界。
        //
        // **2.1.49-p6**：重建源从"全局 `inner.keys()`"改为"**本片** S/M 队列"：
        //   * 分片后若仍扫全表，8 片各自都要过滤掉 7/8 的键 ⇒ 同样的重建总量变成 8 倍；
        //   * S/M 已包含本片**全部存活键**（每次 `on_insert` 必入队，出队只有"晋升到 M /
        //     被淘汰 / 清账"三种，都仍保持"存活 ⇒ 在 S 或 M 里"）；
        //   * 必须**去重**：同键重复写入会在队列里留下多份，不去重会让堆长期高于阈值，
        //     变成"每次插入都重建"的抖动。排序 + `dedup` 比 HashSet 少一轮克隆。
        if self.expiry.len() > self.cap.saturating_mul(4) {
            let mut live = self.live_keys();
            live.sort_unstable();
            live.dedup();
            self.expiry.clear();
            for kk in live {
                if let Some(e) = inner.peek(&kk, now) {
                    self.expiry
                        .push(Reverse(((e.expires_at * 1000.0) as i64, kk)));
                }
            }
        }
        // **最终审查（P1）**：同一键**已在策略表里**（覆盖写/刷新）时不再重复入队。
        //
        // 旧实现每次 `put` 都 push 一份：S 队列溢出后那份被挪进 M，而 M 的裁剪只在
        // `over_budget()`（`freq.len() > cap`）时发生 —— 对"少量热键 + 短 TTL/频繁回填"
        // 的负载，`freq.len()` 始终很小 ⇒ M 每个 put 增长 1 条、永不回收（无界内存）。
        // 入队是一次性的：键只要还活着就必然在 S 或 M 里（淘汰/清账都会同步 `remove`），
        // 覆盖写保留原队列位置即可（语义上也更接近"命中后不重排"）。
        if !self.freq.contains_key(k) {
            // ghost 命中 ⇒ 直接进 M（说明它在被淘汰前被复用）。
            if self.gset.remove(k) {
                self.ghost_hits += 1;
                self.freq.insert(k.clone(), 1);
                self.enqueue(Segment::M, k.clone());
            } else {
                self.freq.insert(k.clone(), 0);
                self.enqueue(Segment::S, k.clone());
            }
        }
        self.evict_if_needed(now, inner);
    }

    fn negative_over_quota(&self) -> bool {
        self.neg_pct > 0
            && !self.negatives.is_empty()
            && self.negatives.len() > (self.cap * self.neg_pct / 100).max(1)
    }

    /// **2.1.49-p6**：片内是否超预算。
    ///
    /// 条目数用 `freq.len()`（本片策略已登记的去重键数），**不用** `inner.len()`：
    /// 后者是全局数，逐片比较会让每个分片都误以为"全局超了"而各自淘汰一遍（8 倍过杀）。
    ///
    /// `freq.len()` 只会 **>= 本片真实条目数**（内层自行淘汰/订正的键要等到被队列弹出
    /// 才清账）⇒ 判断偏保守（宁多淘汰一条），**绝不会**让片内越过 `cap_i`。
    fn over_budget(&self) -> bool {
        if self.freq.len() > self.cap {
            return true;
        }
        if self.negative_over_quota() {
            return true;
        }
        self.bytes_cap > 0 && self.used_bytes > self.bytes_cap
    }

    /// 淘汰：优先回收**已过期**条目，然后按 S3-FIFO（S→M，freq 惰性晋升）。
    ///
    /// `now` 仅用于过期探测（`inner.peek` 对过期条目返回 None）。
    fn evict_if_needed(&mut self, now: f64, inner: &LruCache) {
        // 1) TTL 优先：只回收**已过期**条目（O(log n)）。预算/配额部分交给
        //    [`Self::trim_to_limits`]，两条路径共用同一套 S/M 淘汰逻辑。
        let mut guard = 0usize;
        let limit = self
            .freq
            .len()
            .saturating_mul(2)
            .saturating_add(1024)
            .min(1_000_000);
        while self.over_budget() && guard < limit {
            guard += 1;
            let Some(k) = self.pop_expired_from_heap(inner, now) else {
                break;
            };
            self.evict_entry(inner, &k, EvictCause::Expired);
        }
        self.trim_to_limits(inner);
    }

    /// **2.2.1（P2-02）**：按 `cap` / `bytes_cap` / 负配额**立即**收敛（不探测 TTL）。
    ///
    /// 与 [`Self::evict_if_needed`] 的唯一区别：不做过期探测。运行期 setter
    /// （`cache_bytes` / `negative_pct` / `max_entry_bytes`）没有可信的 `now`，若拿真实
    /// 时钟探测会把 mock 时钟下的条目整片误杀（同 `shrink_to_cap` 的历史教训）。
    fn trim_to_limits(&mut self, inner: &LruCache) {
        let mut guard = 0usize;
        let limit = self
            .freq
            .len()
            .saturating_mul(2)
            .saturating_add(1024)
            .min(1_000_000);
        while self.over_budget() && guard < limit {
            guard += 1;
            // 2) S 队列超限：队首晋升 M 或淘汰。
            if self.s_live > self.scap {
                if let Some(k) = self.pop_live(Segment::S) {
                    if !present(inner, &k) {
                        self.remove(&k);
                        continue;
                    }
                    let f = self.freq.get(&k).copied().unwrap_or(0);
                    if f > 0 {
                        self.freq.insert(k.clone(), f - 1);
                        self.enqueue(Segment::M, k);
                    } else {
                        self.evict_entry(inner, &k, EvictCause::Capacity);
                        self.push_ghost(&k);
                    }
                    continue;
                }
            }
            // 3) M 队列超限：队首惰性晋升或淘汰。
            if self.m_live > self.mcap {
                if let Some(k) = self.pop_live(Segment::M) {
                    if !present(inner, &k) {
                        self.remove(&k);
                        continue;
                    }
                    let f = self.freq.get(&k).copied().unwrap_or(0);
                    if f > 0 {
                        self.freq.insert(k.clone(), f - 1);
                        self.enqueue(Segment::M, k);
                    } else {
                        self.evict_entry(inner, &k, EvictCause::Capacity);
                        self.push_ghost(&k);
                    }
                    continue;
                }
            }
            // 3.5) 负缓存超配额：优先淘汰一个负条目（从队首向后最多找 128 个）。
            //
            // **2.2.1 复审修正**：这里必须传 `f64::NEG_INFINITY`（"不把任何条目视为
            // 已过期"），不能传 `INFINITY` —— `inner.peek(k, INFINITY)` 对所有条目都返回
            // `None`，`find_victim` 将永远找不到负条目，配额收缩退化成"从队首乱杀"，
            // 且 `evict_negative` 恒 0（可观测性失真）。
            if self.negative_over_quota() {
                if let Some(k) = self.find_victim(inner, true, f64::NEG_INFINITY) {
                    self.evict_entry(inner, &k, EvictCause::Negative);
                    continue;
                }
            }
            // 4) 兜底：从 S/M 队首淘汰最旧的**存活**键，保证能收敛。
            let k = self
                .pop_live(Segment::S)
                .or_else(|| self.pop_live(Segment::M));
            match k {
                Some(k) => {
                    self.evict_entry(inner, &k, EvictCause::Capacity);
                }
                None => break,
            }
        }
        // 同步 S/M 队列长度到容量比例（防止 restore 后队列过长）。
        while self.s_live > self.scap {
            let Some(k) = self.pop_live(Segment::S) else {
                break;
            };
            if present(inner, &k) {
                self.enqueue(Segment::M, k);
            } else {
                self.remove(&k);
            }
        }
    }

    /// **2.1.49-p6**：把 S/M 队列里**已不在内层**的键从簿记中清掉。
    ///
    /// 为什么必须做：`freq.len()` 是片内预算的判据。内层 `set_capacity` 缩容时会**自行**
    /// 删键（策略不知情），那些键仍留在 `freq`/`sizes`/队列里 ⇒ `freq.len()` 会**永久
    /// 高于**本片真实条目数 ⇒ 该片再也装不满 `cap_i`（实测：缩容后再扩容，`len()` 停在
    /// `cap - 幽灵数`，`c04` 的"扩容后必须装满"就是这么红的）。所以缩容时必须把簿记与
    /// 存储对齐一次（`live` = 缩容后的内层全量键快照）。
    ///
    /// `live` 只作**快速过滤**：不在快照里的键再问一次内层，避免把"快照之后刚被并发
    /// `put` 进来的键"误删（那会造成反向漂移：内层有、簿记没有）。
    fn purge_stale(&mut self, inner: &LruCache, live: &HashSet<CacheKey>) {
        // **2.2.1（P2-01）**：重建队列 —— 只保留"当前代际 + 仍存活"的键，并按 key 去重
        // （删后重插会在队列里留下旧代际节点；CTRL 重建后计数器与真实队列一一对应）。
        let s = std::mem::take(&mut self.s);
        let m = std::mem::take(&mut self.m);
        let mut keep: Vec<(CacheKey, Segment)> = Vec::new();
        let mut dead: Vec<CacheKey> = Vec::new();
        let mut seen: HashSet<CacheKey> = HashSet::new();
        for (k, g) in s.into_iter().chain(m) {
            if !self.is_live_node(&k, g) {
                continue; // 删除/重插留下的旧代际残影
            }
            if !seen.insert(k.clone()) {
                continue;
            }
            if live.contains(&k) || present(inner, &k) {
                let seg = self.sizes.get(&k).map(|sz| sz.seg).unwrap_or(Segment::S);
                keep.push((k, seg));
            } else {
                // 内层缩容已自行删掉的键：策略簿记必须同步清除，否则 `freq.len()` 虚高，
                // 后续 `shrink_to_cap` 会把**仍存活**的条目全部淘汰（2.2.1 回归）。
                dead.push(k);
            }
        }
        self.s.clear();
        self.m.clear();
        self.s_live = 0;
        self.m_live = 0;
        for k in dead {
            self.remove(&k);
        }
        for (k, seg) in keep {
            self.enqueue(seg, k);
        }
    }

    /// **2.1.49-p6**：缩容收敛（`set_capacity` 把片容量调小后调用）。
    ///
    /// 只按 S/M FIFO 顺序淘汰到片内上限，**不做 TTL 探测**：`set_capacity` 没有 `now`
    /// 参数，若在这里用真实时钟探测，会把"mock 时钟"（测试/回放）里的条目整片误杀
    /// （那些条目的 `expires_at` 相对 `now_epoch()` 早已过期）。惰性晋升口径与
    /// [`Policy::evict_if_needed`] 完全一致（freq>0 减一后放回 M 队尾）。
    fn shrink_to_cap(&mut self, inner: &LruCache) {
        let mut guard = 0usize;
        let limit = self.freq.len().saturating_mul(2).saturating_add(1024);
        while self.freq.len() > self.cap && guard < limit {
            guard += 1;
            let k = self
                .pop_live(Segment::S)
                .or_else(|| self.pop_live(Segment::M));
            let Some(k) = k else { break };
            if !present(inner, &k) {
                self.remove(&k);
                continue;
            }
            let f = self.freq.get(&k).copied().unwrap_or(0);
            if f > 0 {
                self.freq.insert(k.clone(), f - 1);
                self.enqueue(Segment::M, k);
            } else {
                self.evict_entry(inner, &k, EvictCause::Capacity);
                self.push_ghost(&k);
            }
        }
    }

    /// **2.2.1（P2-02）**：单条上限收紧后，把已存在的超大条目也回收（否则要等它们
    /// 各自过期/被挤出才恢复"单条 ≤ 上限"的契约）。
    fn trim_oversized(&mut self, inner: &LruCache, limit: usize) {
        if limit == 0 {
            return;
        }
        let keys: Vec<CacheKey> = self
            .sizes
            .iter()
            .filter(|(_, sz)| sz.bytes > limit)
            .map(|(k, _)| k.clone())
            .collect();
        for k in keys {
            self.evict_entry(inner, &k, EvictCause::Capacity);
        }
    }

    /// 从 TTL 最小堆取“已过期且仍存在”的键；陈旧的堆项（键已删/被重写）惰性丢弃。
    fn pop_expired_from_heap(&mut self, inner: &LruCache, now: f64) -> Option<CacheKey> {
        loop {
            let Reverse((ms, k)) = self.expiry.peek()?.clone();
            if (ms as f64) / 1000.0 > now {
                return None; // 堆顶尚未过期 ⇒ 后面更不会
            }
            self.expiry.pop();
            if !present(inner, &k) {
                self.remove(&k);
                continue;
            }
            // 条目仍在：校验堆项不是陈旧记录（被重写后 expires_at 变化）。
            match inner.peek(&k, now) {
                None => return Some(k), // 已过期
                Some(e) => {
                    if ((e.expires_at * 1000.0) as i64) != ms {
                        continue; // 陈旧堆项
                    }
                    return None; // 该键被重写且未过期，等 S3 逻辑处理
                }
            }
        }
    }

    /// 在 S/M 队列中找一个满足条件的牺牲者（`want_negative=true` 只找负条目）。
    /// 扫描上限 128 个键（避免退化 O(n)）。
    fn find_victim(&mut self, inner: &LruCache, want_negative: bool, now: f64) -> Option<CacheKey> {
        for seg in [Segment::S, Segment::M] {
            let q: Vec<CacheKey> = match seg {
                Segment::S => self
                    .s
                    .iter()
                    .filter(|(k, g)| self.is_live_node(k, *g))
                    .take(128)
                    .map(|(k, _)| k.clone())
                    .collect(),
                Segment::M => self
                    .m
                    .iter()
                    .filter(|(k, g)| self.is_live_node(k, *g))
                    .take(128)
                    .map(|(k, _)| k.clone())
                    .collect(),
                Segment::Out => Vec::new(),
            };
            for k in q {
                if !present(inner, &k) {
                    self.remove(&k);
                    continue;
                }
                if let Some(e) = inner.peek(&k, now) {
                    let neg = e.rcode != 0 || e.rrsets.is_empty();
                    if want_negative == neg {
                        return Some(k);
                    }
                }
            }
        }
        None
    }

    /// 按频率返回候选（供预取使用）：频率高者优先；返回 `(freq, key)` 以免外层再查一次。
    fn hot_keys(&self, limit: usize) -> Vec<(u8, CacheKey)> {
        let mut v: Vec<(u8, &CacheKey)> = self
            .freq
            .iter()
            .filter(|(_, &f)| f > 0)
            .map(|(k, &f)| (f, k))
            .collect();
        v.sort_unstable_by_key(|x| std::cmp::Reverse(x.0));
        v.into_iter()
            .take(limit)
            .map(|(f, k)| (f, k.clone()))
            .collect()
    }
}

/// S3-FIFO 缓存（包装 [`LruCache`] 作为存储/持久化层）。
pub struct S3FifoCache {
    inner: Arc<LruCache>,
    /// **2.1.49-p6**：全局容量（= `Σ 片 cap_i` 的权威值；避免 `capacity()` 去汇总 8 把锁）。
    cap: AtomicUsize,
    /// **2.1.49-p6**：`POLICY_SHARDS` 个 policy 分片（路由见 [`policy_shard_index`]）。
    ///
    /// 用 `Vec` 而不是数组：`with_stats` 需要按字段解构再重组，`Vec` 让构造点只有一处
    /// （数组就得把 `[Mutex::new(...); N]` 的初始化再写一遍）。
    policy: Vec<Mutex<Policy>>,
    /// **2.1.49-p3**：wire-format 打包响应（与条目同生命周期，淘汰后惰性清理）。
    wire: Mutex<WireStore>,
    /// **2.1.49-p5（阶段 1.4）**：热点键 top-K 只读副本 —— 命中先查这里（RwLock 读），
    /// 避免极热域名反复争同一分片 `Mutex`。写入/淘汰/删除时同步失效。
    hot: RwLock<HashMap<CacheKey, Arc<CacheEntry>>>,
    /// **审查修复（round 1）**：热点副本的**内容代际**。
    ///
    /// 旧实现只做"写入前删副本"，但读线程可能已经拿到旧 `Arc`、在写入之后才把旧值
    /// 插回 `hot`（check-then-act 窗口）⇒ 旧答案复活，直到旧 TTL 到期才消失。
    /// 现在：写线程在**结构化写入完成之后**（持 `hot` 写锁）递增本代际；晋升副本时
    /// 在写锁内校验"读到的代际 == 当前代际"，不等则不登记。
    hot_gen: AtomicU64,
    /// 副本上限（= 容量/64，钳制到 [64, 4096]）。
    hot_cap: AtomicUsize,
    stale_window: AtomicU64,
    /// 字节预算（0 = 关闭）。
    bytes_cap: AtomicUsize,
    /// 单条上限（0 = 关闭）。
    max_entry_bytes: AtomicUsize,
    /// 负缓存配额（%）。
    negative_pct: AtomicUsize,
}

impl S3FifoCache {
    /// 当前容量上限（条目数）。
    pub fn capacity(&self) -> usize {
        self.cap.load(Ordering::Relaxed)
    }

    pub fn new(capacity: usize) -> Self {
        Self::with_group(capacity, None)
    }

    /// `group` 只影响日志键形态（与 LruCache 一致）；存储层容量放大 2 倍，
    /// 避免 S3 策略与底层 LRU 同时淘汰造成抖动。
    pub fn with_group(capacity: usize, group: Option<String>) -> Self {
        let cap = capacity.max(16);
        let inner = Arc::new(LruCache::with_group(cap.saturating_mul(2).max(64), group));
        // **2.1.49-p6**：容量按片 divmod 均分（Σ cap_i == cap，不因取整丢容量）。
        let policy: Vec<Mutex<Policy>> = (0..POLICY_SHARDS)
            .map(|i| Mutex::new(Policy::new(split_total(cap, i))))
            .collect();
        Self {
            inner,
            cap: AtomicUsize::new(cap),
            policy,
            wire: Mutex::new(WireStore::new(cap)),
            hot: RwLock::new(HashMap::new()),
            hot_gen: AtomicU64::new(0),
            hot_cap: AtomicUsize::new((cap / 64).clamp(64, 4096)),
            stale_window: AtomicU64::new(0),
            bytes_cap: AtomicUsize::new(0),
            max_entry_bytes: AtomicUsize::new(0),
            negative_pct: AtomicUsize::new(NEG_PCT_DEFAULT),
        }
    }

    pub fn with_stats(self, stats: Arc<PersistStats>) -> Self {
        let S3FifoCache {
            inner,
            cap,
            policy,
            wire,
            hot,
            hot_gen,
            hot_cap,
            stale_window,
            bytes_cap,
            max_entry_bytes,
            negative_pct,
        } = self;
        let inner = match Arc::try_unwrap(inner) {
            Ok(c) => Arc::new(c.with_stats(stats)),
            Err(_) => Arc::new(LruCache::new(16).with_stats(stats)),
        };
        Self {
            inner,
            cap,
            policy,
            wire,
            hot,
            hot_gen,
            hot_cap,
            stale_window,
            bytes_cap,
            max_entry_bytes,
            negative_pct,
        }
    }

    /// 设置字节预算（0 = 关闭）。按片均分下发（`bytes_cap_i`，Σ ≈ 总预算）。
    pub fn set_byte_budget(&self, bytes: usize) {
        self.bytes_cap.store(bytes, Ordering::Relaxed);
        // **2.1.49-p6**：逐片 `lock()`（旧实现用 `try_lock()`，竞争时会**静默丢弃**本次
        // 配置 —— 分片后 `try_lock` 失败概率更高，所以这里改成阻塞锁；这些 setter 只在
        // 配置装载/重载路径调用，不在数据面热路径上）。
        //
        // **2.2.1（P2-02）**：改完预算**立即逐片收敛**（2.2.0 只改字段，要等下一次
        // `put` 落到某片才回收该片 ⇒ 低流量时可能长期超预算）。
        let mut evicted: Vec<CacheKey> = Vec::new();
        for (i, m) in self.policy.iter().enumerate() {
            let mut p = m.lock();
            p.bytes_cap = split_total(bytes, i);
            p.trim_to_limits(&self.inner);
            evicted.append(&mut p.evicted);
        }
        self.invalidate_hot_keys(evicted);
    }

    /// **2.1.49-p5**：设置负缓存配额（%，0 = 不限制）。
    ///
    /// 百分比按**每片 cap_i** 施加（`neg_pct` 不切分：切分百分比没有意义），因此
    /// 全局负条目上限 ≈ `Σ (cap_i * pct / 100)` ≈ `cap * pct / 100`。
    pub fn set_negative_pct(&self, pct: usize) {
        let pct = pct.min(100);
        self.negative_pct.store(pct, Ordering::Relaxed);
        // **2.2.1（P2-02）**：配额收紧立即生效（逐片回收超配额负条目）。
        let mut evicted: Vec<CacheKey> = Vec::new();
        for m in &self.policy {
            let mut p = m.lock();
            p.neg_pct = pct;
            p.trim_to_limits(&self.inner);
            evicted.append(&mut p.evicted);
        }
        self.invalidate_hot_keys(evicted);
    }

    /// 设置单条大小上限（0 = 关闭）。单条上限是**逐条**语义，不切分：每片同一个值。
    pub fn set_max_entry_bytes(&self, bytes: usize) {
        self.max_entry_bytes.store(bytes, Ordering::Relaxed);
        // **2.2.1（P2-02）**：单条上限收紧后，已存在的超大条目也立即回收。
        let mut evicted: Vec<CacheKey> = Vec::new();
        for m in &self.policy {
            let mut p = m.lock();
            p.max_entry_bytes = bytes;
            p.trim_oversized(&self.inner, bytes);
            p.trim_to_limits(&self.inner);
            evicted.append(&mut p.evicted);
        }
        self.invalidate_hot_keys(evicted);
    }

    /// **2.1.49-p5（阶段 1.2）**：预取候选 = **热度 + 到期紧迫度** 双排序。
    ///
    /// **2.1.49-p6**：分片后必须**逐片**取候选再合并——只从"某一片"取会让别的片的热键
    /// 永远进不了预取（分片把全局 top-K 拆成了 8 个局部 top-K）。每片取
    /// `ceil(limit*4/8)` 个（候选总量与旧的 `limit*4` 同阶），合并后按
    /// `(freq 降序, ttl_left 升序)` 排序并截断：既优先热键，又优先“快过期”的键
    /// （尽早续期，减少过期后的冷启动）。
    pub fn hot_keys(&self, limit: usize) -> Vec<CacheKey> {
        if limit == 0 {
            return Vec::new();
        }
        let per_shard = limit.saturating_mul(4).div_ceil(POLICY_SHARDS).max(1);
        let mut pool: Vec<(u8, CacheKey)> = Vec::with_capacity(per_shard * POLICY_SHARDS);
        for m in &self.policy {
            // 逐片加锁-释放：绝不同时持两把 policy 锁。
            pool.extend(m.lock().hot_keys(per_shard));
        }
        let now = crate::util::now_epoch();
        let mut scored: Vec<(u8, f64, CacheKey)> = Vec::with_capacity(pool.len());
        for (f, k) in pool {
            let ttl_left = self
                .inner
                .peek(&k, now)
                .map(|e| (e.expires_at - now).max(0.0))
                .unwrap_or(f64::MAX);
            scored.push((f, ttl_left, k));
        }
        scored.sort_unstable_by(|a, b| {
            b.0.cmp(&a.0)
                .then(a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
        });
        scored.truncate(limit);
        scored.into_iter().map(|(_, _, k)| k).collect()
    }

    /// 运行时统计（诊断用）：各队列长度、字节用量、超大条目拒绝数。
    ///
    /// **2.1.49-p6**：汇总 8 片（旧口径的全局值）。注意这是**逐片采样**而非原子快照：
    /// 汇总过程中其它线程可能正在改某一两片（误差上界 = 采样期间的单次操作），
    /// 这些字段只用于诊断，不参与任何一致性判定。
    pub fn policy_stats(&self) -> Value {
        // **2.2.2（P1-01）**：读诊断值前先对账（内层 purge 可能在两次数据面操作之间
        // 留下待处理的删除）；否则 `/api/cache/stats` 会短暂把已删条目算进 segment。
        self.drain_inner_removals();
        let mut segment_s = 0usize;
        let mut segment_m = 0usize;
        let mut segment_g = 0usize;
        let mut used_bytes = 0usize;
        let mut bytes_cap = 0usize;
        let mut max_entry_bytes = 0usize;
        let mut rejected_large = 0u64;
        let mut evict_expired = 0u64;
        let mut purge_expired = 0u64;
        let mut evict_capacity = 0u64;
        let mut evict_negative = 0u64;
        let mut evict_bytes = 0u64;
        let mut removed_delete = 0u64;
        let mut removed_delete_bytes = 0u64;
        let mut removed_clear = 0u64;
        let mut removed_clear_bytes = 0u64;
        let mut ghost_hits = 0u64;
        let mut policy_keys = 0usize;
        let mut shard_used: Vec<usize> = Vec::with_capacity(POLICY_SHARDS);
        for m in &self.policy {
            let p = m.lock();
            shard_used.push(p.freq.len());
            policy_keys += p.freq.len();
            evict_expired += p.evict_expired;
            purge_expired += p.purge_expired;
            evict_capacity += p.evict_capacity;
            evict_negative += p.evict_negative;
            evict_bytes += p.evict_bytes;
            removed_delete += p.removed_delete;
            removed_delete_bytes += p.removed_delete_bytes;
            removed_clear += p.removed_clear;
            removed_clear_bytes += p.removed_clear_bytes;
            ghost_hits += p.ghost_hits;
            segment_s += p.s_live;
            segment_m += p.m_live;
            // ghost 队列里可能有"已被重新写入"的残影（`gset` 已移除）⇒ 报 `gset.len()`
            // 才是当前幽灵条数。
            segment_g += p.gset.len();
            used_bytes += p.used_bytes;
            bytes_cap += p.bytes_cap;
            max_entry_bytes = max_entry_bytes.max(p.max_entry_bytes);
            rejected_large += p.rejected_large;
        }
        // `json!` 不接受带 `let` 的块表达式 ⇒ 均衡度先算好再放进去。
        // 口径：`(max-min)/avg`（0 = 完全均衡；avg=0 ⇒ 0）。
        let shard_imbalance = {
            let total: usize = shard_used.iter().sum();
            let n = shard_used.len().max(1);
            let avg = total as f64 / n as f64;
            if avg <= 0.0 {
                0.0
            } else {
                let max = *shard_used.iter().max().unwrap_or(&0) as f64;
                let min = *shard_used.iter().min().unwrap_or(&0) as f64;
                ((max - min) / avg * 1000.0).round() / 1000.0
            }
        };
        json!({
            "segment_s": segment_s,
            "segment_m": segment_m,
            "segment_g": segment_g,
            "used_bytes": used_bytes,
            "bytes_cap": bytes_cap,
            "max_entry_bytes": max_entry_bytes,
            "rejected_large": rejected_large,
            // **2.2.0（能力 1）**：淘汰原因 + 幽灵命中 + 分片均衡度。
            // `shard_imbalance = (max-min)/avg`（0 = 完全均衡；avg=0 时为 0）。
            "evict_expired": evict_expired,
            "purge_expired": purge_expired,
            "evict_capacity": evict_capacity,
            "evict_negative": evict_negative,
            "evict_bytes": evict_bytes,
            "removed_delete": removed_delete,
            "removed_delete_bytes": removed_delete_bytes,
            "removed_clear": removed_clear,
            "removed_clear_bytes": removed_clear_bytes,
            "ghost_hits": ghost_hits,
            // **2.2.2（P1-01）**：策略跟踪的键数（正常应恒等于 `size`；不等即为漂移）。
            "policy_keys": policy_keys,
            "shard_max": shard_used.iter().copied().max().unwrap_or(0),
            "shard_min": shard_used.iter().copied().min().unwrap_or(0),
            "shard_imbalance": shard_imbalance,
        })
    }
}

impl DnsCache for S3FifoCache {
    fn journal_key(&self, key: &CacheKey) -> CacheKey {
        self.inner.journal_key(key)
    }

    fn get(&self, key: &CacheKey, now: f64) -> Option<CacheEntry> {
        let e = self.inner.get(key, now);
        // **2.2.2（P1-01）**：读路径可能惰性删除过期条目 ⇒ 立即对账（miss 快路径为
        // `pending_removals == 0` 的原子读，无额外锁）。
        self.drain_inner_removals();
        let e = e?;
        self.policy[policy_shard_index(key)].lock().on_hit(key);
        Some(e)
    }

    fn get_stale(&self, key: &CacheKey, now: f64, stale_window: f64) -> Option<CacheEntry> {
        let e = self.inner.get_stale(key, now, stale_window);
        self.drain_inner_removals();
        e
    }

    fn peek(&self, key: &CacheKey, now: f64) -> Option<CacheEntry> {
        self.inner.peek(key, now)
    }

    fn get_arc(&self, key: &CacheKey, now: f64) -> Option<Arc<CacheEntry>> {
        // **1.4** 热点副本：命中直接返回（只拿读锁，不碰分片 Mutex）；TTL 过期即失效。
        //
        // **审查修复（round 1）**：
        // * 冷未命中（`hot` 里根本没有这个键）不再为了"删除不存在的副本"去抢全局
        //   `hot` 写锁 —— 旧实现每个 cache miss 都拿一次写锁，等于把 miss 路径串行化；
        // * 只有"确有**过期**副本"时才升级到写锁删除；
        // * 晋升副本时校验 `hot_gen`（见字段文档），杜绝旧 `Arc` 在覆盖写之后被插回。
        let gen = self.hot_gen.load(Ordering::Acquire);
        let has_expired = {
            let hot = self.hot.read();
            match hot.get(key) {
                Some(e) if e.expires_at > now => return Some(Arc::clone(e)),
                Some(_) => true,
                None => false,
            }
        };
        if has_expired {
            let mut hot = self.hot.write();
            if hot.get(key).is_some_and(|e| e.expires_at <= now) {
                hot.remove(key);
            }
        }
        let e = self.inner.get_arc(key, now);
        // **2.2.2（P1-01）**：`get_arc` 在关闭 stale 时会删除过期条目 ⇒ 立即对账。
        self.drain_inner_removals();
        let e = e?;
        self.promote_hot(key, &e, gen);
        Some(e)
    }

    fn get_stale_arc(
        &self,
        key: &CacheKey,
        now: f64,
        stale_window: f64,
    ) -> Option<Arc<CacheEntry>> {
        let e = self.inner.get_stale_arc(key, now, stale_window);
        self.drain_inner_removals();
        e
    }

    fn put(&self, key: CacheKey, value: CacheEntry, now: f64) {
        // **2.2.2（P1-01）**：先对账其它线程在内层留下的自行删除（TTL purge / 容量淘汰）。
        self.drain_inner_removals();
        // **阶段 B-2**：RRset 列表与其中 value/name/owner 的 intern 都由**唯一存储层**
        // [`LruCache::put`]（下面 `self.inner.put(...)`）统一完成 —— 本入口不再重复
        // 调用，否则每次写入会多拿一次全局 RRset 表锁（收益为零：第二次必然命中）。
        // 字节预算 `entry_size_bytes` 仍按"每条答案各自计费"估算：共享只降低**真实**
        // RSS，不降低这里的**逻辑**计费（淘汰判据因此不随共享率漂移）。
        let shard = policy_shard_index(&key);
        let size = entry_size_bytes(&value);
        let expires_at = value.expires_at;
        // **阶段 B-2**：负缓存判据 = rcode≠0 或 **没有任何 RRset**（空 = NODATA）。
        let is_negative = value.rcode != 0 || value.rrsets.is_empty();
        // 单条上限：超限直接不缓存（不写 journal，避免回放后仍存在）。
        let max_e = self.max_entry_bytes.load(Ordering::Relaxed);
        if max_e > 0 && size > max_e {
            // 计数必须落在**该键所属分片**上（`policy_stats` 汇总 8 片）。
            self.policy[shard].lock().rejected_large += 1;
            return;
        }
        // **审查修复（round 1）**：覆盖写之前先失效旧 wire —— 旧报文字节属于**旧条目**，
        // 绝不能在新条目上被命中（旧实现只失效 hot，wire 一直留到 delete/淘汰）。
        self.wire.lock().remove(&key);
        {
            let mut hot = self.hot.write();
            hot.remove(&key);
        }
        self.inner.put(key.clone(), value, now);
        // **2.2.2（P1-01）**：本次写入可能触发内层 TTL purge / 容量淘汰 ⇒ 先把这些
        // 删除同步到策略，再登记新键。
        self.drain_inner_removals();
        // 退化输入（ttl<=0）可能让刚写入的条目被同一次 purge 立刻删掉：此时绝不能再把
        // 它登记进策略（否则 `freq.len()` 永久多一条幽灵）。
        if !self.inner.contains(&key) {
            return;
        }
        let evicted = {
            let mut p = self.policy[shard].lock();
            p.on_insert(&key, size, expires_at, is_negative, now, &self.inner);
            std::mem::take(&mut p.evicted)
        };
        {
            let mut hot = self.hot.write();
            // 数据面写入已完成 ⇒ 递增代际：任何"先读到旧 Arc、之后才晋升"的读线程
            // 都会在 `promote_hot` 的校验里失败。二次删除覆盖"写入期间的晋升"。
            self.hot_gen.fetch_add(1, Ordering::Release);
            hot.remove(&key);
            // **2.2.1（P2-09）**：一次淘汰超过 512 条时整表清空（旧实现只失效前 512 个，
            // 其余 hot 副本会继续返回已淘汰的旧答案直到 TTL）。
            if evicted.len() > 512 {
                hot.clear();
            } else {
                for k in evicted {
                    hot.remove(&k);
                }
            }
        }
    }

    fn delete(&self, key: &CacheKey) {
        self.inner.delete(key);
        let mut p = self.policy[policy_shard_index(key)].lock();
        // **2.2.3（P2-D）**：显式删除不是淘汰（不计 `evict_*`），但释放的字节必须
        // 可对账 ⇒ 单独计 `removed_delete*`。只有策略已登记的条目才计数。
        let removed_bytes = p.sizes.get(key).map(|sz| sz.bytes as u64);
        if let Some(bytes) = removed_bytes {
            p.removed_delete += 1;
            p.removed_delete_bytes = p.removed_delete_bytes.saturating_add(bytes);
        }
        p.remove(key);
        drop(p);
        self.wire.lock().remove(key);
        let mut hot = self.hot.write();
        self.hot_gen.fetch_add(1, Ordering::Release);
        hot.remove(key);
    }

    fn len(&self) -> usize {
        self.inner.len()
    }

    fn set_capacity(&self, n: usize) {
        let cap = n.max(16);
        let old = self.cap.swap(cap, Ordering::Relaxed);
        self.inner.set_capacity(cap.saturating_mul(2).max(64));
        // **2.2.2（P1-01）**：缩容时内层会自行删键 ⇒ 先对账（并计 `evict_capacity`），
        // 再做 `purge_stale` 兜底。
        self.drain_inner_removals();
        self.wire.lock().cap = cap.saturating_mul(4);
        // **2.1.49-p6**：分片后"下一次 put 自然收敛"不再成立（一次 put 只碰一片），
        // 所以这里**立即逐片收敛**：先重算 `cap_i`，再按 FIFO 淘汰到片内上限。
        //
        // 缩容时内层已经自行删过键（策略不知情），必须先按内层实际键集把各片簿记
        // 对齐（`purge_stale`），否则残留项会让该片永久装不满 `cap_i`。
        // 逐片加锁-释放；收集到的 evicted 键统一失效热点副本。
        let live: Option<HashSet<CacheKey>> = if cap < old {
            Some(self.inner.keys().into_iter().collect())
        } else {
            None
        };
        let mut evicted: Vec<CacheKey> = Vec::new();
        for (i, m) in self.policy.iter().enumerate() {
            let mut p = m.lock();
            p.rebuild_caps(split_total(cap, i));
            if let Some(live) = &live {
                p.purge_stale(&self.inner, live);
            }
            p.shrink_to_cap(&self.inner);
            // 缩容同时收紧负配额（`cap*pct/100`）；字节预算由 setter 负责，这里不重复。
            p.trim_to_limits(&self.inner);
            evicted.append(&mut p.evicted);
        }
        {
            let mut hot = self.hot.write();
            if cap < old {
                // 收缩时内层会自行删键（策略不知情），这些键的 hot 副本无法逐一枚举；
                // 直接整体清空（`hot` 有界，≤ `hot_cap`）并递增代际，杜绝已删条目
                // 继续从副本被服务。
                self.hot_gen.fetch_add(1, Ordering::Release);
                hot.clear();
            } else {
                for k in evicted {
                    hot.remove(&k);
                }
            }
        }
    }

    fn keys(&self) -> Vec<CacheKey> {
        self.inner.keys()
    }

    fn hot_keys(&self, limit: usize) -> Vec<CacheKey> {
        S3FifoCache::hot_keys(self, limit)
    }

    fn get_wire(&self, key: &CacheKey) -> Option<Arc<WireEntry>> {
        // 条目已被淘汰/过期 ⇒ 丢掉打包件（惰性清理），避免返回无主响应。
        if !present(&self.inner, key) {
            self.wire.lock().remove(key);
            return None;
        }
        self.wire.lock().get(key)
    }

    fn put_wire(&self, key: &CacheKey, wire: Arc<WireEntry>) {
        self.wire.lock().put(key.clone(), wire);
    }

    fn sample_keys(&self, limit: usize) -> Vec<CacheKey> {
        self.inner.sample_keys(limit)
    }

    fn summary(&self) -> Value {
        let mut v = self.inner.summary();
        let st = self.policy_stats();
        if let Some(o) = v.as_object_mut() {
            o.insert("pct".into(), json!(0.0));
            o.insert("capacity".into(), json!(self.capacity()));
            o.insert("used".into(), json!(self.inner.len()));
            // **2.1.49-p3**：S3-FIFO 专属观测（段长度 / 字节用量 / 超大条目拒绝数）。
            o.insert("segment_s".into(), st["segment_s"].clone());
            o.insert("segment_m".into(), st["segment_m"].clone());
            o.insert("segment_g".into(), st["segment_g"].clone());
            // **2.2.2（P1-01）**：策略跟踪键数（正常 == size；暴露到 `/api/cache/stats`，
            // 运维可直接判定 inner→policy 是否漂移）。
            o.insert("policy_keys".into(), st["policy_keys"].clone());
            o.insert("used_bytes".into(), st["used_bytes"].clone());
            o.insert("bytes_cap".into(), st["bytes_cap"].clone());
            o.insert("max_entry_bytes".into(), st["max_entry_bytes"].clone());
            o.insert("rejected_large".into(), st["rejected_large"].clone());
            // **2.2.0（能力 1）**：hit/miss 由内层统计（`summary()` 已带），这里补
            // ghost 命中、四类淘汰原因与分片均衡度。
            for k in [
                "evict_expired",
                "purge_expired",
                "evict_capacity",
                "evict_negative",
                "evict_bytes",
                "removed_delete",
                "removed_delete_bytes",
                "removed_clear",
                "removed_clear_bytes",
                "ghost_hits",
                "shard_max",
                "shard_min",
                "shard_imbalance",
            ] {
                o.insert(k.to_string(), st[k].clone());
            }
            o.insert("hot_replicas".into(), json!(self.hot.read().len()));
        }
        v
    }

    fn serialize(&self, now: f64) -> Vec<Value> {
        self.inner.serialize(now)
    }

    fn for_each_snapshot_entry(&self, now: f64, f: &mut dyn FnMut(Value)) {
        self.inner.for_each_snapshot_entry(now, f)
    }

    fn restore(&self, entries: &[Value], now: f64, persist_ttl: f64) {
        // **阶段 A / B-1**：intern 由内层 `LruCache::restore`（唯一存储层）完成。
        self.inner.restore(entries, now, persist_ttl);
        // **审查修复（round 1）**：恢复会整体替换条目集合，旧 hot/wire 视图必须一起清空
        // （否则恢复后仍可能从副本/打包字节返回恢复前的内容）。
        self.invalidate_replicas();
        // **2.2.1（P1-01）**：恢复后立即按当前 cap/字节/负配额收敛（见 rebuild_policy）。
        self.rebuild_policy(now);
    }

    fn restore_records(&self, entries: Vec<(CacheKey, CacheEntry)>, now: f64) {
        // **阶段 A / B-1**：intern 由内层 `LruCache::restore_records`（唯一存储层）完成。
        self.inner.restore_records(entries, now);
        self.invalidate_replicas();
        self.rebuild_policy(now);
    }

    fn last_restore_drops(&self) -> (u64, u64, u64) {
        self.inner.last_restore_drops()
    }

    fn for_each_entry(&self, now: f64, f: &mut dyn FnMut(&CacheKey, &Arc<CacheEntry>)) {
        self.inner.for_each_entry(now, f);
    }

    fn persist_stats(&self) -> Option<Arc<PersistStats>> {
        self.inner.persist_stats()
    }

    fn attach_journal(&self, j: Arc<CacheJournal>) {
        self.inner.attach_journal(j);
    }

    fn request_snapshot(&self, reason: &'static str) {
        self.inner.request_snapshot(reason);
    }

    fn clear(&self) {
        self.inner.clear();
        self.invalidate_replicas();
        // **2.2.1（P2-01）**：逐片加锁-释放（绝不同时持多把 policy 锁 ⇒ 不会与并发路径成环）。
        // **2.2.3（P2-D）**：`clear` 不是淘汰（不计 `evict_*`），但清空的条目数/字节
        // 单独记入 `removed_clear*`，让 `used_bytes` 的下降有对应账目。
        for m in &self.policy {
            let mut p = m.lock();
            let n = p.freq.len() as u64;
            let bytes = p.used_bytes as u64;
            p.removed_clear = p.removed_clear.saturating_add(n);
            p.removed_clear_bytes = p.removed_clear_bytes.saturating_add(bytes);
            p.reset();
        }
    }

    fn set_stale_window(&self, v: u64) {
        self.stale_window.store(v, Ordering::Relaxed);
        self.inner.set_stale_window(v);
    }

    fn set_byte_budget(&self, bytes: usize) {
        S3FifoCache::set_byte_budget(self, bytes);
    }

    fn set_max_entry_bytes(&self, bytes: usize) {
        S3FifoCache::set_max_entry_bytes(self, bytes);
    }

    fn set_negative_pct(&self, pct: usize) {
        S3FifoCache::set_negative_pct(self, pct);
    }
}

impl S3FifoCache {
    /// **审查修复（round 1）**：把命中条目晋升为热点副本（`freq >= 2` 才晋升）。
    ///
    /// `gen` 是调用方在**读取内层之前**读到的 `hot_gen`。只有它仍等于当前代际时，
    /// 才允许登记 —— 否则说明期间发生过 `put`/`delete`/`clear`/`restore`，手里的
    /// `e` 可能是已经被替换掉的旧 `Arc`（登记它会让旧答案"复活"到旧 TTL 到期）。
    ///
    /// **2.1.49-p6（hot 写锁优化）**：旧实现对 `freq >= 2` 的**每次** `get_arc` 都直接
    /// 拿全局 `hot` **写锁**再判断要不要插。热点键在刚晋升前、`put` 覆盖写之后、或
    /// `hot` 已满时，每个命中都会排队抢一次写锁 —— 高 QPS 下这把锁会成为新的串行点
    /// （写锁还会阻塞所有 hot 读）。现在分三段：
    /// 1. 频率累计仍逐片小锁（不碰全局）；
    /// 2. **先拿读锁**判断副本是否已存在/已满：已存在（或满）⇒ 直接返回，不升级写锁；
    /// 3. 只有"确实不存在且未满"才拿写锁，并在写锁内**二次检查**（读锁释放到写锁
    ///    之间可能有并发晋升）与代际校验。
    ///
    /// 副本容量上界仍为 `hot_cap`：满时**不插入**（best-effort 只读加速层，不是
    /// 正确性组件；后续有淘汰腾出空间时新的命中会再尝试晋升），不会无界增长。
    ///
    /// 独立成函数是为了让回归测试可以**确定性地**复现"读旧 Arc → 写入 → 尝试晋升"
    /// 这个交错（见本文件测试 `stale_hot_replica_is_not_resurrected_after_put`）。
    fn promote_hot(&self, key: &CacheKey, e: &Arc<CacheEntry>, gen: u64) {
        // **2.1.49-p6**：只锁**该键所属分片**做频率累计（旧实现锁全局 policy）。
        let freq = self.policy[policy_shard_index(key)].lock().on_hit(key);
        if freq < 2 {
            return;
        }
        let cap = self.hot_cap.load(Ordering::Relaxed);
        {
            // 读锁快判：已登记 / 已满都不需要写锁。
            // 注意：这里看到的 `hot_gen` 可能已过期 —— 代际校验统一放在写锁内做
            //（与插入同一临界区），读锁只用于"要不要尝试写"的预判。
            let hot = self.hot.read();
            if hot.contains_key(key) || hot.len() >= cap {
                return;
            }
        }
        let mut hot = self.hot.write();
        if self.hot_gen.load(Ordering::Acquire) != gen {
            return; // 期间有写入：本次晋升作废（不登记旧值）
        }
        // 写锁内二次检查：读锁释放到拿到写锁之间，别的线程可能已登记同键副本
        //（同代同键 ⇒ 内容等价），此时直接返回，不重复插入/替换。
        if hot.contains_key(key) || hot.len() >= cap {
            return;
        }
        hot.insert(key.clone(), Arc::clone(e));
    }

    /// **审查修复（round 1）**：整表替换（restore / clear）后清空所有"缓存视图"。
    ///
    /// 旧实现 `restore` 只换内层 map + 重建 policy，**不碰 hot/wire**：
    /// * hot 副本可能在恢复后继续返回**已不存在/内容已变**的旧条目；
    /// * wire 字节同理（恢复后的条目 TTL/答案都可能不同）。
    /// 现在两者一起清空并递增 `hot_gen`（使在途晋升作废）。
    fn invalidate_replicas(&self) {
        self.wire.lock().clear();
        let mut hot = self.hot.write();
        self.hot_gen.fetch_add(1, Ordering::Release);
        hot.clear();
    }

    /// **2.2.2（P1-01/P2-07）**：把内层**自行删除**的条目同步到 policy 簿记。
    ///
    /// 背景（2.2.1 生产实测）：内层 `LruCache` 的 TTL purge（`stale_ttl` 到期后每 32
    /// 次 put 扫一次）与容量淘汰**只删存储**，策略侧的 `freq`/`sizes`/S/M 队列节点/
    /// TTL 堆项全部残留 ⇒ ① `segment_s + segment_m` = 190 而 `size` = 54（3.5× 漂移）；
    /// ② `evict_expired` 恒 0（观测者以为从未淘汰）；③ `freq.len()` 虚高，逼着
    /// `trim_to_limits` 先弹死键、延长淘汰扫描。
    ///
    /// 锁序：`policy → inner`（与 `on_insert`/`trim_to_limits` 一致）；`take_removals`
    /// 只逐片拿内层片锁，**不**在持内层锁时取 policy ⇒ 不会成环。
    /// 对账时二次确认"内层确已不存在"：删除后同键又被并发 `put` 回来时必须**跳过**
    /// （否则会把刚登记的新条目误删，造成反向漂移）。
    fn drain_inner_removals(&self) {
        let removed = self.inner.take_removals();
        if removed.is_empty() {
            return;
        }
        let mut hot_keys: Vec<CacheKey> = Vec::new();
        for (k, reason) in removed {
            let mut p = self.policy[policy_shard_index(&k)].lock();
            if !p.sizes.contains_key(&k) || self.inner.contains(&k) {
                continue;
            }
            let bytes = p.sizes.get(&k).map(|sz| sz.bytes as u64).unwrap_or(0);
            p.remove(&k);
            // **2.2.3（P2-D）**：内层自行删除的条目同样释放真实字节，按原因计入。
            p.evict_bytes = p.evict_bytes.saturating_add(bytes);
            match reason {
                // **2.2.4（P2-G）**：轮转 purge 与惰性删除都算 `evict_expired`；
                // `purge_expired` 只计轮转 purge（生产 `stale_ttl=3600` 时长期为 0）。
                RemovalReason::Expired => p.evict_expired += 1,
                RemovalReason::Purged => {
                    p.evict_expired += 1;
                    p.purge_expired += 1;
                }
                RemovalReason::Capacity => p.evict_capacity += 1,
            }
            hot_keys.push(k);
        }
        // 内层已删的键不得再从热点副本返回（过期条目本会被 TTL 拦下，但容量/缩容
        // 删除的**未过期**条目必须立刻失效）。
        self.invalidate_hot_keys(hot_keys);
    }

    /// **2.2.1（P2-02/P2-09）**：失效一批被淘汰键的 hot 副本。
    ///
    /// * 空列表 ⇒ 无操作（不白白递增代际）；
    /// * `> 512` 条 ⇒ 整表清空 + 代际递增（比上万次哈希删除便宜，且语义更强）；
    /// * 否则逐键删除（与 `put` 的既有语义一致：递增代际防在途晋升）。
    fn invalidate_hot_keys(&self, evicted: Vec<CacheKey>) {
        if evicted.is_empty() {
            return;
        }
        let mut hot = self.hot.write();
        self.hot_gen.fetch_add(1, Ordering::Release);
        if evicted.len() > 512 {
            hot.clear();
        } else {
            for k in evicted {
                hot.remove(&k);
            }
        }
    }

    /// restore 之后重建各分片的 S/M/G 队列：一律视为 M 队列（freq=1），避免快照顺序丢失。
    ///
    /// **2.1.49-p6**：先把存活键按 [`policy_shard_index`] 分桶（键→片只算一次），再
    /// **逐片**加锁重建；堆/负缓存/大小/字节用量与旧实现逐键同口径。
    fn rebuild_policy(&self, now: f64) {
        let mut buckets: Vec<Vec<(CacheKey, usize, f64, bool)>> =
            (0..POLICY_SHARDS).map(|_| Vec::new()).collect();
        for k in self.inner.keys() {
            let Some(e) = self.inner.peek(&k, 0.0) else {
                continue;
            };
            let i = policy_shard_index(&k);
            let neg = e.rcode != 0 || e.rrsets.is_empty();
            buckets[i].push((k, entry_size_bytes(&e), e.expires_at, neg));
        }
        let mut evicted: Vec<CacheKey> = Vec::new();
        for (i, m) in self.policy.iter().enumerate() {
            let mut p = m.lock();
            p.reset();
            for (k, sz, exp, neg) in std::mem::take(&mut buckets[i]) {
                p.sizes.insert(
                    k.clone(),
                    Sizing {
                        bytes: sz,
                        gen: 0,
                        seg: Segment::M,
                    },
                );
                p.used_bytes += sz;
                p.expiry.push(Reverse(((exp * 1000.0) as i64, k.clone())));
                if neg {
                    p.negatives.insert(k.clone());
                }
                p.freq.insert(k.clone(), 1);
                p.enqueue(Segment::M, k);
            }
            // **2.2.1（P1-01）**：恢复的条目数/字节数可能超过**当前**配置（典型：
            // 用 cache_size=32 落盘的 26 条快照，重启时配置已缩到 16；或 cache_bytes
            // 调小）。2.2.0 只重建簿记、不淘汰 ⇒ `used=26 > capacity=16`（162.5%），
            // 且要等每个分片各来一次 put 才逐片收敛。这里当场按 cap/bytes/负配额
            // 收敛到契约内。
            p.evict_if_needed(now, &self.inner);
            evicted.append(&mut p.evicted);
        }
        if !evicted.is_empty() {
            // 淘汰发生在 `invalidate_replicas()` 之后：再失效一次 hot（restore 期间可能
            // 有读线程已经拿到 Arc 并尝试晋升），杜绝"已淘汰条目从副本复活到 TTL"。
            self.invalidate_hot_keys(evicted);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::now_epoch;

    fn entry(d: &str, ttl: f64, now: f64) -> CacheEntry {
        let mut e = CacheEntry::new(d, "A", ttl, now);
        e.expires_at = now + ttl;
        e
    }

    /// 各片的容量/预算分配（与实现同一条公式，测试用来独立复算）。
    fn shard_caps(cap: usize) -> Vec<usize> {
        (0..POLICY_SHARDS).map(|i| split_total(cap, i)).collect()
    }

    #[test]
    fn capacity_is_enforced_and_s_flows_to_m() {
        let c = S3FifoCache::new(100);
        let now = now_epoch();
        for i in 0..1000 {
            c.put(
                CacheKey::new(format!("d{i}.test"), "A"),
                entry(&format!("d{i}.test"), 600.0, now),
                now,
            );
        }
        assert!(c.len() <= 100, "len={} 超过容量", c.len());
        assert!(c.policy_stats()["rejected_large"] == json!(0));
    }

    #[test]
    fn hot_keys_prefers_repeated_hits() {
        let c = S3FifoCache::new(100);
        let now = now_epoch();
        let k = CacheKey::new("hot.test", "A");
        c.put(k.clone(), entry("hot.test", 600.0, now), now);
        for _ in 0..5 {
            let _ = c.get_arc(&k, now);
        }
        let hot = c.hot_keys(10);
        assert!(hot.contains(&k), "hot_keys 必须包含被反复命中的键");
    }

    /// **2.1.49-p6（hot replica 接线）**：`get_arc` 连续命中只登记**一份**副本。
    ///
    /// 语义：第 2 次命中（freq=2）晋升；第 3 次起命中 hot 读锁直接返回 —— 不得因为
    /// "再次达到阈值"而重复插入/替换副本（写锁优化后尤其要钉死这一点）。
    /// 同时验证副本容量仍受 `hot_cap` 限制（不会无界增长）。
    #[test]
    fn get_arc_promotes_hot_replica_once_and_hot_cap_bounds_it() {
        let c = S3FifoCache::new(100); // hot_cap = (100/64).clamp(64,4096) = 64
        let now = now_epoch();
        let k = CacheKey::new("hot-once.test", "A");
        c.put(k.clone(), entry("hot-once.test", 600.0, now), now);
        // 第 1 次：freq=1，不晋升；第 2 次：freq=2，晋升 1 份副本。
        assert!(c.get_arc(&k, now).is_some());
        assert_eq!(c.summary()["hot_replicas"], json!(0), "首次命中不晋升");
        assert!(c.get_arc(&k, now).is_some());
        assert_eq!(c.summary()["hot_replicas"], json!(1), "第二次命中必须晋升");
        // 第 3~10 次：走 hot 读锁早退，副本数不得变化。
        for _ in 0..8 {
            assert!(c.get_arc(&k, now).is_some());
            assert_eq!(
                c.summary()["hot_replicas"],
                json!(1),
                "重复命中不得重复插入副本"
            );
        }
        // 容量上界：再灌 hot_cap 个热点键，副本数必须恰为 hot_cap（有界）。
        let cap = c.hot_cap.load(Ordering::Relaxed);
        for i in 0..(cap + 32) {
            let d = format!("hotcap{i}.test");
            let kk = CacheKey::new(d.clone(), "A");
            c.put(kk.clone(), entry(&d, 600.0, now), now);
            for _ in 0..2 {
                assert!(c.get_arc(&kk, now).is_some());
            }
        }
        assert_eq!(
            c.summary()["hot_replicas"].as_u64().unwrap() as usize,
            cap,
            "hot 副本数必须被 hot_cap={cap} 限制"
        );
    }

    #[test]
    fn hot_replica_is_invalidated_on_put_and_delete() {
        let c = S3FifoCache::new(100);
        let now = now_epoch();
        let k = CacheKey::new("hot-replica.test", "A");
        c.put(k.clone(), entry("hot-replica.test", 600.0, now), now);
        // 两次命中 → freq=2 → 进入热点副本
        for _ in 0..2 {
            assert!(c.get_arc(&k, now).is_some());
        }
        assert_eq!(c.summary()["hot_replicas"], json!(1));
        // 覆盖写：副本必须失效，读到新值（TTL 变成 1s）
        c.put(k.clone(), entry("hot-replica.test", 1.0, now), now);
        let e = c.get_arc(&k, now).expect("new value");
        assert!((e.expires_at - now - 1.0).abs() < 0.01);
        // 删除：副本与条目都没了
        c.delete(&k);
        assert!(c.get_arc(&k, now).is_none());
        // TTL 过期：副本不服务过期条目
        let k2 = CacheKey::new("hot-expire.test", "A");
        c.put(k2.clone(), entry("hot-expire.test", 5.0, now), now);
        for _ in 0..2 {
            assert!(c.get_arc(&k2, now).is_some());
        }
        assert!(c.get_arc(&k2, now + 6.0).is_none());
    }

    #[test]
    fn ttl_heap_prefers_expired_victims() {
        let c = S3FifoCache::new(50);
        let now = now_epoch();
        // 40 条立即过期（ttl=0 → expires_at=now），再灌 60 条新条目。
        for i in 0..40 {
            let d = format!("old{i}.test");
            c.put(CacheKey::new(d.clone(), "A"), entry(&d, 0.0, now), now);
        }
        for i in 0..60 {
            let d = format!("new{i}.test");
            c.put(CacheKey::new(d.clone(), "A"), entry(&d, 600.0, now), now);
        }
        assert!(c.len() <= 50, "len={} 超过容量", c.len());
        // 过期条目应被优先回收：剩余 key 以 new* 为主。
        let keys = c.keys();
        let new_cnt = keys.iter().filter(|k| k.domain.starts_with("new")).count();
        assert!(
            new_cnt >= 30,
            "new 条目只剩 {} / {}（TTL 堆未优先回收过期）",
            new_cnt,
            keys.len()
        );
    }

    #[test]
    fn negative_quota_bounds_negative_entries() {
        let c = S3FifoCache::new(200);
        let now = now_epoch();
        // 负条目（rcode=3）与正条目交替写入 400 条。
        for i in 0..400 {
            let d = format!("n{i}.test");
            let mut e = entry(&d, 600.0, now);
            if i % 2 == 0 {
                e.rcode = 3;
                // **阶段 B-2**：`rrsets` 是普通 `Vec<Arc<Rrset>>`，负条目直接清空即可
                // （空列表 = 无 RRset = NODATA）。
                e.rrsets.clear();
            }
            c.put(CacheKey::new(d.clone(), "A"), e, now);
        }
        let keys = c.keys();
        let neg = keys
            .iter()
            .filter(|k| {
                c.peek(k, now)
                    .map(|e| e.rcode != 0 || e.rrsets.is_empty())
                    .unwrap_or(false)
            })
            .count();
        // 配额 20% + 扫描上限的松弛：不应接近一半。
        assert!(
            neg <= 60,
            "负条目 {} / {} 超过配额（20%+松弛）",
            neg,
            keys.len()
        );
    }

    /// **2.2.0 终审（P1）**：负条目转正后必须从负配额集合里移除。
    ///
    /// 旧实现只增不减：同一键先 NXDOMAIN、后 NOERROR（域名注册/上游恢复）时
    /// `negatives` 永远保留该键，累计超过 `negative_pct` 后配额判据恒真。
    #[test]
    fn negative_flag_is_cleared_when_key_becomes_positive() {
        let c = S3FifoCache::new(200);
        let now = now_epoch();
        let d = "flip.example";
        let k = CacheKey::new(d, "A");
        // 先写负条目。
        let mut neg = entry(d, 600.0, now);
        neg.rcode = 3;
        neg.rrsets.clear();
        c.put(k.clone(), neg, now);
        assert!(
            c.policy[policy_shard_index(&k)]
                .lock()
                .negatives
                .contains(&k),
            "负条目必须登记进 negatives"
        );
        // 再写同键正条目（覆盖写）。
        let mut pos = entry(d, 600.0, now);
        pos.rcode = 0;
        c.put(k.clone(), pos, now);
        assert!(
            !c.policy[policy_shard_index(&k)]
                .lock()
                .negatives
                .contains(&k),
            "转正后必须从 negatives 移除（旧实现只增不减）"
        );
    }

    #[test]
    fn byte_budget_evicts() {
        let c = S3FifoCache::new(1000);
        let now = now_epoch();
        c.set_byte_budget(4 * 1024);
        for i in 0..200 {
            c.put(
                CacheKey::new(format!("b{i}.test"), "A"),
                entry(&format!("b{i}.test"), 600.0, now),
                now,
            );
        }
        let st = c.policy_stats();
        assert!(
            st["used_bytes"].as_u64().unwrap() <= 6 * 1024,
            "used_bytes={} 超预算",
            st["used_bytes"]
        );
    }

    #[test]
    fn oversized_entry_is_rejected() {
        let c = S3FifoCache::new(100);
        let now = now_epoch();
        c.set_max_entry_bytes(64);
        let mut e = entry("big.test", 600.0, now);
        e.rrsets = crate::rrset::rrsets_from_flat(&[crate::entry::CacheAnswer {
            value: "x".repeat(200).into(),
            ttl: 600.0,
            rtype: 16,
            name: None,
        }]);
        c.put(CacheKey::new("big.test", "TXT"), e, now);
        assert_eq!(c.len(), 0, "超大条目不得入缓存");
        assert_eq!(c.policy_stats()["rejected_large"], json!(1));
    }

    /* ==================== **2.1.49-p6**：policy 分片专项 ==================== */

    /// ① 8 片路由分布：写入 10k 键后 `Σ 片内 len == cache.len()`，且每片 <= cap_i，
    /// 片内每个键的路由都必须指向该片（路由稳定性 = 分片簿记不张冠李戴的前提）。
    #[test]
    fn policy_shards_route_and_bound_keys() {
        const N: usize = 10_000;
        let cap = 1024usize;
        let c = S3FifoCache::new(cap);
        let now = now_epoch();
        for i in 0..N {
            let d = format!("shard{i}.routing.test");
            c.put(CacheKey::new(d.clone(), "A"), entry(&d, 600.0, now), now);
        }
        let caps = shard_caps(cap);
        assert_eq!(caps.iter().sum::<usize>(), cap, "Σ cap_i 必须等于全局容量");
        let mut per_shard = Vec::with_capacity(POLICY_SHARDS);
        for (i, m) in c.policy.iter().enumerate() {
            let p = m.lock();
            per_shard.push(p.freq.len());
            assert_eq!(p.cap, caps[i], "第 {i} 片容量未按 divmod 分配");
            assert!(
                p.freq.len() <= caps[i],
                "第 {i} 片 {} 条 > cap_i {}",
                p.freq.len(),
                caps[i]
            );
            // 片内每个键都必须路由到本片（否则别的入口会锁错片 ⇒ 簿记分叉）。
            for k in p.freq.keys() {
                assert_eq!(policy_shard_index(k), i, "键 {k:?} 落在第 {i} 片");
            }
        }
        assert_eq!(
            per_shard.iter().sum::<usize>(),
            c.len(),
            "Σ 片内 len 必须 == cache.len()（逐片：{per_shard:?}）"
        );
        assert!(
            per_shard.iter().all(|&n| n > 0),
            "分片分布退化：{per_shard:?}"
        );
        assert_eq!(c.summary()["capacity"], json!(cap));
    }

    /// ② hot_keys 跨片合并：候选必须来自多个分片，合并后仍按 freq 降序。
    #[test]
    fn hot_keys_merges_candidates_across_shards() {
        let c = S3FifoCache::new(1024);
        let now = now_epoch();
        let mut keys = Vec::new();
        for i in 0..40usize {
            let d = format!("hk{i}.merge.test");
            let k = CacheKey::new(d.clone(), "A");
            c.put(k.clone(), entry(&d, 600.0, now), now);
            keys.push(k);
        }
        // 命中次数 3/2/1/0 循环：`get`（不走 hot 副本，freq 不会被副本短路）。
        for (i, k) in keys.iter().enumerate() {
            for _ in 0..(3 - i % 4) {
                assert!(c.get(k, now).is_some());
            }
        }
        // 全量候选：10 个键命中 0 次 ⇒ 恰好 30 个 freq>0 的候选，且必须跨多片。
        let all = c.hot_keys(64);
        assert_eq!(all.len(), 30, "hot_keys 应返回全部 30 个 freq>0 的键");
        let shards: HashSet<usize> = all.iter().map(policy_shard_index).collect();
        assert!(
            shards.len() >= 2,
            "hot_keys 必须跨片合并（实测只来自 {} 片）",
            shards.len()
        );
        // 截断后仍是"freq 降序、ttl 升序"，且只取 freq 最高的那批。
        let hot = c.hot_keys(8);
        assert_eq!(hot.len(), 8, "hot_keys(8) 必须给满 8 个候选");
        let freqs: Vec<u8> = hot
            .iter()
            .map(|k| {
                c.policy[policy_shard_index(k)]
                    .lock()
                    .freq
                    .get(k)
                    .copied()
                    .unwrap_or(0)
            })
            .collect();
        assert!(freqs.iter().all(|&f| f > 0), "hot_keys 只返回 freq>0 的键");
        assert!(
            freqs.windows(2).all(|w| w[0] >= w[1]),
            "hot_keys 必须按 freq 降序：{freqs:?}"
        );
        assert_eq!(freqs[0], 3, "最高频（freq=3）必须排在最前：{freqs:?}");
    }

    /// ③ restore 后分片重建：serialize → restore 后 len/命中不变，且每个键都回到
    /// hash 对应的那片（堆、负缓存、大小同步重建，堆里不得混入别的片的键）。
    #[test]
    fn restore_rebuilds_policy_shards() {
        let now = now_epoch();
        // 容量取 512（cap_i=64）：200 个键按 8 片分布时不会撞到某片的 64 上限，
        // 保证"200 条全部存活"是确定性的（用 256 时片容量 32 会偶发溢出而淘汰）。
        let c = S3FifoCache::new(512);
        let mut keys = Vec::new();
        for i in 0..200usize {
            let d = format!("rs{i}.restore.test");
            let k = CacheKey::new(d.clone(), "A");
            c.put(k.clone(), entry(&d, 600.0, now), now);
            keys.push(k);
        }
        let blob = c.serialize(now);
        assert_eq!(blob.len(), 200, "快照条目数必须为 200");
        let c2 = S3FifoCache::new(512);
        c2.restore(&blob, now, 0.0);
        assert_eq!(c2.len(), c.len(), "restore 后 len 必须不变");
        assert_eq!(c2.len(), 200);
        let mut per_shard = [0usize; POLICY_SHARDS];
        for k in &keys {
            let i = policy_shard_index(k);
            {
                let p = c2.policy[i].lock();
                assert_eq!(p.freq.get(k), Some(&1), "restore 后 freq 必须为 1（{k:?}）");
                assert!(p.sizes.contains_key(k), "restore 后 sizes 缺失（{k:?}）");
                assert!(
                    p.expiry.iter().any(|Reverse((_, kk))| kk == k),
                    "restore 后 TTL 堆缺失（{k:?}）"
                );
            }
            per_shard[i] += 1;
        }
        assert_eq!(per_shard.iter().sum::<usize>(), 200);
        // 各片 TTL 堆里只能有本片的键（跨片污染会让本片淘汰掉别的片的条目）。
        for (i, m) in c2.policy.iter().enumerate() {
            let p = m.lock();
            for Reverse((_, k)) in p.expiry.iter() {
                assert_eq!(policy_shard_index(k), i, "第 {i} 片 TTL 堆混入了别的片的键");
            }
        }
        // 命中与 hot_keys 仍工作（freq=1 ⇒ 全部是预取候选）。
        assert!(c2.get(&keys[0], now).is_some(), "restore 后必须命中");
        assert!(!c2.hot_keys(4).is_empty(), "restore 后 hot_keys 不得为空");
    }

    /// ④ 并发正确性：多线程 put/get 后仍满足"逐片 <= cap_i"与"内层条目都被策略跟踪"。
    #[test]
    fn concurrent_put_get_keeps_shard_invariants() {
        let cap = 512usize;
        let c = Arc::new(S3FifoCache::new(cap));
        let now = now_epoch();
        let mut handles = Vec::new();
        for t in 0..4usize {
            let c = Arc::clone(&c);
            handles.push(std::thread::spawn(move || {
                for i in 0..5_000usize {
                    let d = format!("mt{t}-{i}.conc.test");
                    let k = CacheKey::new(d.clone(), "A");
                    c.put(k.clone(), entry(&d, 600.0, now), now);
                    if i % 3 == 0 {
                        // 同时读：命中路径要能取到**该键所属片**的锁（不能锁错片）。
                        let _ = c.get_arc(&k, now);
                    }
                    if i % 97 == 0 {
                        let _ = c.len();
                        let _ = c.policy_stats();
                    }
                }
            }));
        }
        for h in handles {
            h.join().expect("并发线程 panic");
        }
        assert!(c.len() <= cap, "并发写入后 len={} > cap={}", c.len(), cap);
        let caps = shard_caps(cap);
        let mut total = 0usize;
        for (i, m) in c.policy.iter().enumerate() {
            let p = m.lock();
            assert!(
                p.freq.len() <= caps[i],
                "第 {i} 片 {} > cap_i {}",
                p.freq.len(),
                caps[i]
            );
            total += p.freq.len();
        }
        assert!(total <= cap, "Σ 片内计数 {total} > cap {cap}");
        assert!(
            c.len() <= total,
            "内层条目必须都被策略跟踪：len={} > Σfreq={total}",
            c.len()
        );
    }

    /// ⑤ 缩容：重分配各片 cap（Σ == 新容量）、立即收敛且**不是清空**；`set_*` 按片分发。
    #[test]
    fn set_capacity_redistributes_shards_and_shrinks() {
        let now = now_epoch();
        let c = S3FifoCache::new(1024);
        for i in 0..4000usize {
            let d = format!("sc{i}.resize.test");
            c.put(CacheKey::new(d.clone(), "A"), entry(&d, 600.0, now), now);
        }
        assert_eq!(c.len(), 1024, "原容量必须装满");
        c.set_capacity(256);
        assert_eq!(c.capacity(), 256, "capacity() 必须立即反映新容量");
        assert_eq!(c.summary()["capacity"], json!(256));
        let sum: usize = c.policy.iter().map(|m| m.lock().cap).sum();
        assert_eq!(sum, 256, "重分配后 Σ cap_i 必须等于新容量");
        assert!(c.len() <= 256, "缩容后 len={} > 256", c.len());
        assert!(c.len() >= 16, "缩容不得变成清空（len={}）", c.len());
        // 继续写入仍受新容量约束。
        for i in 0..2000usize {
            let d = format!("sc2-{i}.resize.test");
            c.put(CacheKey::new(d.clone(), "A"), entry(&d, 600.0, now), now);
        }
        assert!(c.len() <= 256, "扩容未发生但 len={} 越过 256", c.len());
        // 预算/单条上限/负配额：按片下发后汇总值 == 配置值。
        c.set_byte_budget(8192);
        assert_eq!(c.policy_stats()["bytes_cap"], json!(8192));
        c.set_max_entry_bytes(4096);
        assert_eq!(c.policy_stats()["max_entry_bytes"], json!(4096));
        c.set_negative_pct(30);
        assert!(
            c.policy.iter().all(|m| m.lock().neg_pct == 30),
            "负配额必须下发到每一片"
        );
    }

    /* ============== **审查修复（round 1）**：wire/hot/字节簿记 ============== */

    /// 一条最小合法响应：qd=1 an=1，question `w.test A IN`，answer `1.2.3.4 TTL 300`。
    fn wire_response() -> Vec<u8> {
        let mut m = vec![0u8; 12];
        m[4..6].copy_from_slice(&1u16.to_be_bytes());
        m[6..8].copy_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&[1, b'w', 4, b't', b'e', b's', b't', 0]);
        m.extend_from_slice(&[0, 1, 0, 1]);
        m.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 1, 2, 3, 4]);
        m
    }

    /// **P0 回归**：覆盖写同一键必须让旧 wire 立即失效。
    ///
    /// 旧实现只在 `delete` 里删 wire：结构化条目被上游刷新后，命中仍可能返回**旧报文**
    /// （实测：q4 返回旧 IP + TTL=1，且永远不恢复）。
    #[test]
    fn put_invalidates_wire_for_same_key() {
        let c = S3FifoCache::new(64);
        let now = now_epoch();
        let k = CacheKey::new("wire-inval.test", "A");
        c.put(k.clone(), entry("wire-inval.test", 600.0, now), now);
        let w = crate::wire::WireEntry::from_response(&wire_response(), now).expect("wire");
        c.put_wire(&k, Arc::new(w));
        assert!(c.get_wire(&k).is_some(), "写入后应能取到 wire");

        let mut fresh = entry("wire-inval.test", 600.0, now);
        fresh.chosen = "new-value".into();
        c.put(k.clone(), fresh, now);
        assert!(
            c.get_wire(&k).is_none(),
            "覆盖写后旧 wire 必须失效（否则会用旧报文字节应答）"
        );
    }

    /// **P1 回归**：`put` 之后，读线程若把"put 之前读到的旧 Arc"再晋升为热点副本，
    /// 必须被代际校验拒绝 —— 旧实现没有这个校验，旧答案会复活到旧 TTL 到期。
    #[test]
    fn stale_hot_replica_is_not_resurrected_after_put() {
        let c = S3FifoCache::new(64);
        let now = now_epoch();
        let k = CacheKey::new("hot-race.test", "A");
        c.put(k.clone(), entry("hot-race.test", 600.0, now), now);
        // 两次命中 ⇒ freq=2 ⇒ 副本晋升
        assert!(c.get_arc(&k, now).is_some());
        assert!(c.get_arc(&k, now).is_some());
        assert_eq!(c.summary()["hot_replicas"], json!(1));

        // 模拟：读线程在 put 之前读到旧 Arc 与旧代际，put 之后才尝试晋升。
        let old_arc = c.hot.read().get(&k).cloned().expect("旧副本存在");
        let gen_before = c.hot_gen.load(Ordering::Acquire);
        let mut fresh = entry("hot-race.test", 600.0, now);
        fresh.chosen = "new".into();
        c.put(k.clone(), fresh, now);
        c.promote_hot(&k, &old_arc, gen_before);

        assert!(
            !c.hot.read().contains_key(&k),
            "旧代际的副本不得被登记回 hot"
        );
        assert_eq!(
            c.get_arc(&k, now).expect("新条目命中").chosen,
            "new",
            "命中必须是覆盖写之后的新值"
        );
    }

    /// **P2 回归**：restore 整体替换条目集合后，hot/wire 这些"视图"必须一起清空。
    #[test]
    fn restore_clears_hot_and_wire_views() {
        let c = S3FifoCache::new(64);
        let now = now_epoch();
        let k = CacheKey::new("restore-view.test", "A");
        c.put(k.clone(), entry("restore-view.test", 600.0, now), now);
        assert!(c.get_arc(&k, now).is_some());
        assert!(c.get_arc(&k, now).is_some());
        assert_eq!(c.summary()["hot_replicas"], json!(1));
        let w = crate::wire::WireEntry::from_response(&wire_response(), now).expect("wire");
        c.put_wire(&k, Arc::new(w));
        assert!(c.get_wire(&k).is_some());

        c.restore(&[], now, 0.0);
        assert_eq!(c.len(), 0);
        assert_eq!(
            c.summary()["hot_replicas"],
            json!(0),
            "restore 后 hot 必须清空"
        );
        assert!(c.get_wire(&k).is_none(), "restore 后 wire 必须清空");
        assert!(c.get_arc(&k, now).is_none(), "restore 后不得命中旧副本");
    }

    /// **P1 回归**：同一键反复覆盖写不得让 `used_bytes` 只增不减（会触发过度淘汰）。
    #[test]
    fn overwrite_same_key_does_not_leak_byte_usage() {
        let c = S3FifoCache::new(64);
        let now = now_epoch();
        let k = CacheKey::new("bytes-account.test", "A");
        let e = entry("bytes-account.test", 600.0, now);
        let one = entry_size_bytes(&e);
        for _ in 0..50 {
            c.put(k.clone(), e.clone(), now);
        }
        assert_eq!(c.len(), 1);
        assert_eq!(
            c.policy_stats()["used_bytes"],
            json!(one),
            "同一键覆盖 50 次后 used_bytes 必须仍等于单条大小（旧实现会累计到 50 倍）"
        );
    }

    /// **P1 回归（最终审查）**：同一键反复覆盖写不得让 S/M 队列无界增长。
    ///
    /// 旧实现每次 `put` 都向 S 队尾 push 一份（S 溢出的那份再进 M），而 `m` 只在
    /// `over_budget()`（`freq.len() > cap`）时才会被弹 —— 对"少量热键 + 短 TTL /
    /// 频繁回填"的负载，`freq.len()` 始终很小 ⇒ `m` 每个 put 增长 1 条、永不回收。
    #[test]
    fn overwrite_same_key_does_not_grow_policy_queues() {
        let c = S3FifoCache::new(64);
        let now = now_epoch();
        let k = CacheKey::new("queue-growth.test", "A");
        for _ in 0..1000 {
            c.put(k.clone(), entry("queue-growth.test", 600.0, now), now);
        }
        let st = c.policy_stats();
        let queued = st["segment_s"].as_u64().unwrap() + st["segment_m"].as_u64().unwrap();
        assert_eq!(
            queued, 1,
            "同一键 1000 次覆盖写后 S+M 队列只能有 1 条（旧实现会堆到 ~1000 条）"
        );
        assert_eq!(c.len(), 1);
    }

    /* ============== **2.2.1（P1-01/P2-01/P2-02）**：恢复收敛 / 队列簿记 / setter 回收 ============== */

    /// 对全部分片做簿记一致性断言（无并发时必须是**等式**，不是不等式）。
    fn assert_policy_invariants(c: &S3FifoCache) {
        let st = c.policy_stats();
        let mut freq_total = 0usize;
        let mut live_total = 0usize;
        let mut bytes_total = 0usize;
        for (i, m) in c.policy.iter().enumerate() {
            let p = m.lock();
            assert_eq!(
                p.s_live + p.m_live,
                p.freq.len(),
                "第 {i} 片 segment_s+segment_m != freq.len()（{} + {} vs {}）",
                p.s_live,
                p.m_live,
                p.freq.len()
            );
            assert_eq!(p.sizes.len(), p.freq.len(), "第 {i} 片 sizes/freq 键集分叉");
            let bytes: usize = p.sizes.values().map(|s| s.bytes).sum();
            assert_eq!(bytes, p.used_bytes, "第 {i} 片 sizes 汇总 != used_bytes");
            freq_total += p.freq.len();
            live_total += p.s_live + p.m_live;
            bytes_total += p.used_bytes;
        }
        assert_eq!(
            freq_total, live_total,
            "Σ(S+M) 必须 == Σfreq（segment_s={} segment_m={}）",
            st["segment_s"], st["segment_m"]
        );
        assert_eq!(
            st["used_bytes"].as_u64().unwrap() as usize,
            bytes_total,
            "policy_stats.used_bytes 汇总口径错误"
        );
        assert_eq!(
            c.summary()["used"].as_u64().unwrap() as usize,
            c.len(),
            "summary.used 必须等于内层 len"
        );
        // **P2-01 的直接回归**：`segment_s + segment_m` 必须等于**策略跟踪的**键数
        // （2.2.0 的问题正是两者漂移：队列里有已删键的残影 ⇒ 371 > 351）。
        let seg_sum = st["segment_s"].as_u64().unwrap() + st["segment_m"].as_u64().unwrap();
        assert_eq!(
            seg_sum, freq_total as u64,
            "segment_s+segment_m ({seg_sum}) != Σfreq ({freq_total})（队列簿记漂移）"
        );
        // **2.2.2（P1-01）**：内层自行删除（TTL purge / 容量淘汰 / 读路径惰性过期）现在
        // 全部经 `take_removals()` 同步到策略 ⇒ 不变量从 "freq >= len" 收紧为**等式**。
        // 旧实现只允许 `freq >= len`（"策略侧短暂多出幽灵"正是生产 190 vs 54 的漂移）。
        assert_eq!(
            freq_total,
            c.len(),
            "策略跟踪 {freq_total} != 内层 len {}（inner→policy 对账失效）",
            c.len()
        );
    }

    /// **P1-01**：26 条快照 + 重启后 cap=16 ⇒ 必须立即淘汰到 `used <= capacity`。
    #[test]
    fn restore_after_capacity_shrink_evicts_to_cap() {
        let now = now_epoch();
        let c = S3FifoCache::new(32);
        for i in 0..26usize {
            let d = format!("cap26-{i}.test");
            c.put(CacheKey::new(d.clone(), "A"), entry(&d, 600.0, now), now);
        }
        assert!(
            c.len() > 16,
            "先决条件：快照条数 {} 必须大于新容量 16",
            c.len()
        );
        let blob = c.serialize(now);
        let before = blob.len();

        let c2 = S3FifoCache::new(16);
        c2.restore(&blob, now, 0.0);
        let st = c2.policy_stats();
        assert!(
            c2.len() <= 16,
            "恢复后 used={} > capacity=16（2.2.0 实测 26/162.5%）",
            c2.len()
        );
        let evicted = st["evict_expired"].as_u64().unwrap()
            + st["evict_capacity"].as_u64().unwrap()
            + st["evict_negative"].as_u64().unwrap();
        assert_eq!(
            evicted,
            (before - c2.len()) as u64,
            "快照 {before} 条 → 实际保留 {} 条，淘汰记账 {evicted} 不一致（不能静默超容量）",
            c2.len()
        );
        assert_policy_invariants(&c2);
    }

    /// **P1-01（字节维度）**：大快照 + 小 `bytes_cap` ⇒ 恢复后 `used_bytes <= bytes_cap`。
    #[test]
    fn restore_with_small_bytes_cap_evicts_bytes() {
        let now = now_epoch();
        let c = S3FifoCache::new(2048);
        for i in 0..300usize {
            let d = format!("bigsnap-{i}.test");
            c.put(CacheKey::new(d.clone(), "A"), entry(&d, 600.0, now), now);
        }
        assert!(
            c.len() >= 250,
            "先决条件：快照至少 250 条（实际 {}）",
            c.len()
        );
        let blob = c.serialize(now);

        let c2 = S3FifoCache::new(2048);
        c2.set_byte_budget(8192);
        c2.restore(&blob, now, 0.0);
        let st = c2.policy_stats();
        assert!(
            st["used_bytes"].as_u64().unwrap() <= 8192,
            "恢复后 used_bytes={} > bytes_cap=8192",
            st["used_bytes"]
        );
        assert!(
            st["evict_bytes"].as_u64().unwrap() > 0,
            "字节超预算淘汰必须计入 evict_bytes"
        );
        assert_policy_invariants(&c2);
    }

    /// **2.2.3（P2-D）**：`evict_bytes` 是**真实字节**（不是次数），且显式
    /// `delete`/`clear` 单独记账（`removed_*`），不与 `evict_*` 重叠。
    #[test]
    fn evict_bytes_are_real_bytes_and_delete_clear_accounted() {
        let now = now_epoch();
        let c = S3FifoCache::new(64);
        // 同长度域名 ⇒ 每条 entry_size 相同，可精确断言字节数。
        let probe = entry("s000.test", 600.0, now);
        let sz = entry_size_bytes(&probe) as u64;
        assert!(sz > 0);
        // 小字节预算：写入 20 条必然触发字节/容量淘汰。
        c.set_byte_budget((sz * 4) as usize);
        for i in 0..20usize {
            let d = format!("s{i:03}.test");
            c.put(CacheKey::new(d.clone(), "A"), entry(&d, 600.0, now), now);
        }
        let st = c.policy_stats();
        let n_evict = st["evict_expired"].as_u64().unwrap()
            + st["evict_capacity"].as_u64().unwrap()
            + st["evict_negative"].as_u64().unwrap();
        assert!(n_evict > 0, "先决条件：必须发生淘汰：{st}");
        assert_eq!(
            st["evict_bytes"].as_u64().unwrap(),
            n_evict * sz,
            "evict_bytes 必须是真实字节（Σ 被淘汰条目大小），不是淘汰次数：{st}"
        );
        assert!(
            st["used_bytes"].as_u64().unwrap() <= (sz * 4),
            "字节预算必须收敛：{st}"
        );

        // delete：只计 removed_delete*，不得计入 evict_*。
        c.set_byte_budget(0); // 先取消字节预算，确保该条不会被立即淘汰
        let del = CacheKey::new("s999.test", "A");
        c.put(del.clone(), entry("s999.test", 600.0, now), now);
        let before = c.policy_stats();
        c.delete(&del);
        let after = c.policy_stats();
        assert_eq!(
            after["removed_delete"].as_u64().unwrap() - before["removed_delete"].as_u64().unwrap(),
            1
        );
        assert_eq!(
            after["removed_delete_bytes"].as_u64().unwrap()
                - before["removed_delete_bytes"].as_u64().unwrap(),
            sz,
            "delete 释放字节必须精确记账"
        );
        let ev_before: u64 = ["evict_expired", "evict_capacity", "evict_negative"]
            .iter()
            .map(|k| before[k].as_u64().unwrap())
            .sum();
        let ev_after: u64 = ["evict_expired", "evict_capacity", "evict_negative"]
            .iter()
            .map(|k| after[k].as_u64().unwrap())
            .sum();
        assert_eq!(
            ev_before, ev_after,
            "显式 delete 不是淘汰，不得计入 evict_*"
        );

        // clear：清空 5 条 ⇒ removed_clear += 5、字节 += 5*sz。
        c.set_byte_budget(0); // 取消字节预算，保证 5 条同时存活
        let before = c.policy_stats();
        for i in 0..5usize {
            let d = format!("c{i:03}.test");
            c.put(CacheKey::new(d.clone(), "A"), entry(&d, 600.0, now), now);
        }
        assert_eq!(c.len(), 5, "先决条件：5 条同时存活");
        c.clear();
        let after = c.policy_stats();
        assert_eq!(
            after["removed_clear"].as_u64().unwrap() - before["removed_clear"].as_u64().unwrap(),
            5,
            "clear 必须计清空条目数：{after}"
        );
        assert_eq!(
            after["removed_clear_bytes"].as_u64().unwrap()
                - before["removed_clear_bytes"].as_u64().unwrap(),
            5 * sz,
            "clear 必须计释放字节：{after}"
        );
        assert_eq!(c.len(), 0);
    }

    /// **P2-01**：TTL 过期淘汰 / delete / 覆盖写之后，队列长度与 `size` 严格同步。
    #[test]
    fn ttl_and_delete_keep_queue_bookkeeping_in_sync() {
        let now = now_epoch();
        let c = S3FifoCache::new(16);
        // 8 条已过期 + 9 条存活：第 17 条写入时触发 TTL 优先淘汰。
        for i in 0..8usize {
            let d = format!("exp-{i}.test");
            c.put(CacheKey::new(d.clone(), "A"), entry(&d, 0.0, now), now);
        }
        for i in 0..8usize {
            let d = format!("live-{i}.test");
            c.put(CacheKey::new(d.clone(), "A"), entry(&d, 600.0, now), now);
        }
        c.put(
            CacheKey::new("trigger.test", "A"),
            entry("trigger.test", 600.0, now),
            now,
        );
        assert_policy_invariants(&c);

        // 直接删除 3 条：队列残影不得再计入 segment。
        for i in 0..3usize {
            let k = CacheKey::new(format!("live-{i}.test"), "A");
            c.delete(&k);
        }
        assert_policy_invariants(&c);

        // 删后同键重写：不得出现"同一键在队列里两份都算存活"。
        for i in 0..3usize {
            let d = format!("live-{i}.test");
            c.put(CacheKey::new(d.clone(), "A"), entry(&d, 600.0, now), now);
        }
        assert_policy_invariants(&c);

        // 过期后再写同键（TTL 淘汰 + 重插）：仍必须严格相等。
        let k = CacheKey::new("reinsert-exp.test", "A");
        c.put(k.clone(), entry("reinsert-exp.test", 0.0, now), now);
        c.put(
            CacheKey::new("trigger2.test", "A"),
            entry("trigger2.test", 600.0, now),
            now,
        );
        c.put(k.clone(), entry("reinsert-exp.test", 600.0, now), now);
        assert_policy_invariants(&c);
        // 本用例不通过 `get` 惰性删除过期条目 ⇒ 策略与内层必须**严格**相等。
        let st = c.policy_stats();
        let seg_sum = st["segment_s"].as_u64().unwrap() + st["segment_m"].as_u64().unwrap();
        assert_eq!(
            seg_sum,
            c.len() as u64,
            "segment_s+segment_m ({seg_sum}) != size ({})",
            c.len()
        );
    }

    /// **2.2.2（P1-01）直接回归**：生产 `size 60→59` 时 `segment_s+segment_m` 必须同步。
    ///
    /// 2.2.1 的 inner→policy 断链：`purge_expired_locked_with_sw` 只删内层 map，策略侧
    /// 的 `freq/sizes/队列` 全部残留 ⇒ 生产实测 60→54 而 segment 恒 190、`evict_expired=0`。
    #[test]
    fn inner_ttl_purge_reconciles_segments_at_60_to_59() {
        let now = now_epoch();
        let c = S3FifoCache::new(256);
        c.set_stale_window(0); // serve_stale=false：过期即物理删除
        for i in 0..59usize {
            let d = format!("sync-{i}.test");
            c.put(CacheKey::new(d.clone(), "A"), entry(&d, 600.0, now), now);
        }
        let d = "sync-expired.test";
        c.put(CacheKey::new(d.to_string(), "A"), entry(d, 1.0, now), now);
        assert_eq!(c.len(), 60, "先决条件：60 条");
        // t=now+5：唯一一条 TTL=1s 的条目已过期。
        let purged = c.purge_for_test(now + 5.0);
        assert_eq!(purged, 1, "只应删除 1 条过期条目");
        assert_eq!(c.len(), 59, "size 必须 60→59");
        let st = c.policy_stats();
        let seg = st["segment_s"].as_u64().unwrap() + st["segment_m"].as_u64().unwrap();
        assert_eq!(
            seg, 59,
            "segment_s+segment_m 必须同步到 59（2.2.1 会停在 60+）"
        );
        assert_eq!(
            st["policy_keys"].as_u64().unwrap(),
            59,
            "policy_keys 必须等于真实 size"
        );
        assert_eq!(
            st["evict_expired"].as_u64().unwrap(),
            1,
            "TTL purge 必须记 evict_expired（2.2.1 恒 0）"
        );
        assert_eq!(
            st["purge_expired"].as_u64().unwrap(),
            1,
            "轮转 purge 必须单独记 purge_expired（2.2.4/P2-G）"
        );
        assert_policy_invariants(&c);
    }

    /// **2.2.4（P2-G）**：`purge_expired` 只计**轮转 TTL purge**；读路径惰性删除
    /// 计入 `evict_expired` 但不计入 `purge_expired`（两者口径分开，生产长期 0 可解释）。
    #[test]
    fn purge_expired_excludes_lazy_read_removal() {
        let now = now_epoch();
        let c = S3FifoCache::new(64);
        c.set_stale_window(0);
        let d1 = "lazy-expired.test";
        c.put(CacheKey::new(d1.to_string(), "A"), entry(d1, 1.0, now), now);
        // 读路径惰性删除（stale_window=0 ⇒ 过期即删）。
        let _ = c.get(&CacheKey::new(d1.to_string(), "A"), now + 5.0);
        let st = c.policy_stats();
        assert_eq!(st["evict_expired"].as_u64().unwrap(), 1, "{st}");
        assert_eq!(
            st["purge_expired"].as_u64().unwrap(),
            0,
            "惰性删除不是 purge：{st}"
        );
        // 再放一条过期条目，由轮转 purge 清理 ⇒ 只有 purge_expired 增长。
        let d2 = "rotating-purged.test";
        c.put(CacheKey::new(d2.to_string(), "A"), entry(d2, 1.0, now), now);
        assert_eq!(c.purge_for_test(now + 10.0), 1);
        let st = c.policy_stats();
        assert_eq!(st["evict_expired"].as_u64().unwrap(), 2, "{st}");
        assert_eq!(st["purge_expired"].as_u64().unwrap(), 1, "{st}");
        assert_policy_invariants(&c);
    }

    /// **2.2.2（P1-01）**：随机 put/get/delete/过期混合 4000 步，内层与策略簿记每 97 步
    /// 严格相等（覆盖容量淘汰、TTL purge、读路径惰性删除）；最后清空后也必须相等。
    #[test]
    fn randomized_ops_keep_inner_and_policy_in_sync() {
        let mut now = now_epoch();
        let c = S3FifoCache::new(64);
        c.set_stale_window(0);
        let mut seed: u64 = 0x1234_5678_9abc_def0;
        let mut rnd = move || {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (seed >> 33) as usize
        };
        for step in 0..4000usize {
            let r = rnd();
            let d = format!("rand-{}.test", r % 200);
            let k = CacheKey::new(d.clone(), "A");
            match r % 5 {
                0..=2 => {
                    let ttl = if r % 7 == 0 { 1.0 } else { 120.0 };
                    c.put(k, entry(&d, ttl, now), now);
                }
                3 => {
                    let _ = c.get(&k, now);
                }
                4 => {
                    c.delete(&k);
                }
                _ => {}
            }
            if step % 3 == 0 {
                now += 2.0; // 时钟前进 ⇒ 制造真实 TTL 过期
            }
            if step % 97 == 0 {
                assert_policy_invariants(&c);
            }
        }
        // 把剩余条目全部过期清掉后再断言（覆盖批量 purge 路径）。
        let purged = c.purge_for_test(now + 1_000_000.0);
        assert!(purged > 0, "前置条件：最终必须有过期条目被清理");
        assert_eq!(c.len(), 0, "全部过期后 size 必须归零");
        assert_policy_invariants(&c);
    }

    /// **2.2.2（P1-01）**：4 线程并发 put/get（含短 TTL 过期）后，内层与策略仍严格一致。
    #[test]
    fn concurrent_put_get_keep_inner_and_policy_in_sync() {
        use std::sync::Arc as StdArc;
        let c = StdArc::new(S3FifoCache::new(128));
        c.set_stale_window(0);
        let now = now_epoch();
        let mut hs = Vec::new();
        for t in 0..4usize {
            let c = StdArc::clone(&c);
            hs.push(std::thread::spawn(move || {
                for i in 0..600usize {
                    let d = format!("thr-{t}-{}.test", i % 50);
                    let k = CacheKey::new(d.clone(), "A");
                    let ttl = if i % 9 == 0 { 1.0 } else { 300.0 };
                    let tn = now + i as f64;
                    c.put(k.clone(), entry(&d, ttl, tn), tn);
                    let _ = c.get_arc(&k, tn + 3.0);
                }
            }));
        }
        for h in hs {
            h.join().expect("并发线程不得 panic");
        }
        // 并发结束后：先丢弃所有残留 TTL 条目，再断言严格等式。
        c.purge_for_test(now + 1_000_000.0);
        assert_policy_invariants(&c);
        assert_eq!(c.len(), 0);
    }

    /// **2.2.2（P1-01）测试夹具**：立即触发内层 TTL purge + 策略对账。
    impl S3FifoCache {
        fn purge_for_test(&self, now: f64) -> usize {
            let n = self.inner.purge_for_test(now);
            self.drain_inner_removals();
            n
        }
    }

    /// **P2-02**：运行期缩 `cache_bytes` 必须**立即**回收（不等下一次 put）。
    #[test]
    fn shrinking_byte_budget_reclaims_immediately() {
        let now = now_epoch();
        let c = S3FifoCache::new(4096);
        for i in 0..300usize {
            let d = format!("shrink-b-{i}.test");
            c.put(CacheKey::new(d.clone(), "A"), entry(&d, 600.0, now), now);
        }
        let before = c.policy_stats()["used_bytes"].as_u64().unwrap();
        assert!(
            before > 8192,
            "先决条件：已用字节 {before} 必须大于目标预算"
        );
        c.set_byte_budget(8192);
        let after = c.policy_stats()["used_bytes"].as_u64().unwrap();
        assert!(
            after <= 8192,
            "set_byte_budget 后立即断言失败：used_bytes={after} > 8192"
        );
        assert!(c.len() < 300, "必须真的淘汰了条目（len={}）", c.len());
        assert_policy_invariants(&c);
    }

    /// **P2-02**：运行期收紧 `max_entry_bytes` 必须回收已存在的超大条目。
    #[test]
    fn shrinking_max_entry_bytes_reclaims_existing() {
        let now = now_epoch();
        let c = S3FifoCache::new(64);
        let mut big = entry("oversize-existing.test", 600.0, now);
        big.rrsets = crate::rrset::rrsets_from_flat(&[crate::entry::CacheAnswer {
            value: "y".repeat(400).into(),
            ttl: 600.0,
            rtype: 16,
            name: None,
        }]);
        c.put(CacheKey::new("oversize-existing.test", "TXT"), big, now);
        assert_eq!(c.len(), 1, "先决条件：大条目已入缓存");
        c.set_max_entry_bytes(64);
        assert_eq!(c.len(), 0, "收紧单条上限后已有超大条目必须立即回收");
        assert_eq!(c.policy_stats()["used_bytes"], json!(0));
        assert_policy_invariants(&c);
    }

    /// **P2-02（负配额维度）**：运行期收紧 `negative_pct` 必须**优先淘汰负条目**
    /// 并计入 `evict_negative`（复审修正：此前 `find_victim` 传 `INFINITY` 会让
    /// `peek` 认为所有条目已过期 ⇒ 永远找不到负条目，退化成从队首乱杀）。
    #[test]
    fn shrinking_negative_pct_evicts_negative_victims() {
        let now = now_epoch();
        let c = S3FifoCache::new(512);
        // 先写 100 条正条目，再写 100 条负条目（负配额默认 20%，写入时就会被压住，
        // 所以先把配额放到 100 让它们全部进缓存）。
        c.set_negative_pct(100);
        for i in 0..100usize {
            let d = format!("negtrim-pos-{i}.test");
            c.put(CacheKey::new(d.clone(), "A"), entry(&d, 600.0, now), now);
        }
        for i in 0..100usize {
            let d = format!("negtrim-neg-{i}.test");
            let mut e = entry(&d, 600.0, now);
            e.rcode = 3;
            e.rrsets.clear();
            c.put(CacheKey::new(d.clone(), "A"), e, now);
        }
        let before_neg = c
            .keys()
            .iter()
            .filter(|k| {
                c.peek(k, now)
                    .map(|e| e.rcode != 0 || e.rrsets.is_empty())
                    .unwrap_or(false)
            })
            .count();
        assert!(
            before_neg >= 80,
            "先决条件：负条目应全部存活（实际 {before_neg}）"
        );
        c.set_negative_pct(10);
        let st = c.policy_stats();
        let after_neg = c
            .keys()
            .iter()
            .filter(|k| {
                c.peek(k, now)
                    .map(|e| e.rcode != 0 || e.rrsets.is_empty())
                    .unwrap_or(false)
            })
            .count();
        assert!(
            after_neg <= 52,
            "negative_pct=10 ⇒ 负条目 {after_neg} 必须收敛到配额附近"
        );
        assert!(
            st["evict_negative"].as_u64().unwrap() > 0,
            "负配额淘汰必须计入 evict_negative（否则可观测性失真）：{st}"
        );
        assert_policy_invariants(&c);
    }

    /// **P2-01/P2-02 属性/随机测试**：随机 put/get/delete/过期 + 随机 setter，
    /// 每步后校验全分片等式不变量（任何簿记漂移都会在这里炸出来）。
    #[test]
    fn randomized_ops_keep_policy_bookkeeping_exact() {
        let now = now_epoch();
        let c = S3FifoCache::new(128);
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state >> 33
        };
        for step in 0..6000usize {
            let d = format!("rand-{}.test", next() % 400);
            let k = CacheKey::new(d.clone(), "A");
            match next() % 10 {
                0..=5 => {
                    // TTL 偶尔为 0（立即过期，覆盖 TTL 堆淘汰路径）。
                    let ttl = if next() % 5 == 0 { 0.0 } else { 600.0 };
                    c.put(k, entry(&d, ttl, now), now);
                }
                6..=7 => {
                    let _ = c.get_arc(&k, now);
                }
                8 => c.delete(&k),
                _ => {
                    // 随机运行期收敛：每次都给一个较小预算/配额。
                    match next() % 3 {
                        0 => c.set_byte_budget((next() % 20000) as usize),
                        1 => c.set_negative_pct((next() % 100) as usize),
                        _ => c.set_max_entry_bytes((next() % 4096) as usize),
                    }
                }
            }
            if step % 97 == 0 {
                assert_policy_invariants(&c);
                assert!(c.len() <= 128, "len={} 越过容量", c.len());
            }
        }
        assert_policy_invariants(&c);
        assert!(c.len() <= 128);
    }
}
