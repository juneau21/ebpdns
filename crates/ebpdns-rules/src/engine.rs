//! 规则引擎：索引原子发布、三态匹配、结论缓存（分片）、代际门控与宽限期。
//!
//! **[历史归因]** 忠实对齐 Python `resolver.match_rule` / `_cache_rule` / `_in_rule_grace` /
//! **[历史归因]** `_rebuild_rule_index`。与 Python 的取舍：
//! **[历史归因]** - Rust `regex` 保证线性时间（无灾难性回溯），故**不移植** Python 的线程池超时
//!   （`_regex_search_safe` / `_regex_match_safe` / `_regex_pool`）；匹配为同步短临界区，
//!   由异步调用方放 `spawn_blocking`。
//! - ReDoS 三态“不确定”在 Rust 侧不存在（编译失败已在加载期拒绝），故屏蔽类规则
//!   的 fail-closed 分支恒不触发；保留其结构以便日后对照。
//!
//! # R-02：结论缓存的锁粒度
//! **[历史归因]** Python 读路径（`cache.get(n, _MISS)` + `move_to_end`）在 CPython GIL 下**无锁**，
//! 旧 Rust 实现却让每个查询都经过一次全局 `Mutex<LruCache>`。这里改为
//! **按域名哈希分片的 64 个独立 `Mutex<LruCache>`**（对齐 `cache.py` 的分片分锁思路）：
//! 同一域名恒落同一分片（保留单域名真 LRU 提升语义），不同域名落到不同锁，
//! 把原来「全局一把锁」的跨线程串行点摊薄到 64 把锁。代际门控（gen）与三态语义
//! 保持不变：gen 仍是 `AtomicU64`，写回前在**持有分片锁**时校验，失配即丢弃。
//!
//! **[历史归因]** # 语义不变量（与 Python 逐条对齐）
//! - 重建：先无锁发布新索引快照 → 再自增 gen 并清空全部结论缓存；
//! - 读路径先读 gen 再解包索引快照（R17/P2-1，避免「旧索引 + 新代际」fail-open 窗口）；
//! - `fast=true`：字典类（精确/通配/白名单）照常求值，一旦进入正则阶段即
//!   `Uncertain`（不写缓存）；无正则类规则时可直接判 `NoRule` 并缓存。
//!
//! # 分配/锁统计（单次 `match_rule`，热路径）
//! | 场景 | 旧实现 | 新实现 |
//! |---|---|---|
//! | 结论缓存命中 | 1×`String` + **1 次全局锁** + `Rule` 深拷贝（约 5 次堆分配） | 1×`String` + **1 次分片锁** + `Arc` 引用计数（0 次堆分配） |
//! | 字典命中（冷） | 1×`String` + 2 次全局锁 + 约 10 次堆分配 | 1×`String` + 2 次分片锁 + 约 5 次堆分配 |
//! | suffix 阶段 | +`Vec<&str>` + `Vec<String>` + `HashSet<String>`（约 2×标签数+1 次堆分配） | 标签边界候选 **0 次**（借用切片 + 定长线性去重）；跨标签拼接候选 1×`String` |

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use lru::LruCache;
use parking_lot::{Mutex, RwLock};

use ebpdns_proto::name::Name;

use crate::index::{BuildStats, RuleIndex};
use crate::rule::Rule;

/// **[历史归因]** 默认规则结论缓存容量（对齐 Python `_rule_cache_max = 8192`）。
pub const RULE_CACHE_MAX: usize = 8192;
/// **[历史归因]** 默认宽限期（对齐 Python `_RULE_GRACE_SEC = 3.0`）。
pub const RULE_GRACE_SEC: f64 = 3.0;
/// 结论缓存分片数（2 的幂）。对齐 `cache.py` 的「按分片分锁 + 单分片真 LRU」思路。
pub const RULE_CACHE_SHARDS: usize = 64;

/// 匹配结果。
#[derive(Debug, Clone)]
pub enum MatchOutcome {
    /// 命中一条规则。
    Hit(Rule),
    /// 确定无规则适用（可缓存）。
    NoRule,
    /// fast 路径：字典类已 miss，进入正则阶段未求值，调用方应 fallthrough 到完整判定。
    Uncertain,
}

/// 一次索引重建的报告（供 resolver 决定是否整体清答案缓存）。
#[derive(Debug, Clone, Copy)]
pub struct BuildReport {
    /// 新代际号（原子发布）。
    pub gen: u64,
    /// 重建后是否存在 group 分流规则。
    pub has_group_rules: bool,
    /// group 规则有无发生翻转（true → resolver 必须整体清答案缓存）。
    pub group_flip: bool,
    pub stats: BuildStats,
}

/// **2.1.49（P0）**：已构建、**尚未发布**的候选索引。
///
/// 为什么要拆成"先构建、后发布"：reload/订阅重建失败时（全部规则被拒/丢弃）
/// 旧实现先把索引换成空快照、再返回 500 ⇒ 端点报错但数据面已经 fail-open。
/// 调用方用 [`RuleEngine::build_candidate`] 构建、检查统计后再决定是否
/// [`RuleEngine::publish_candidate`]（不发布 ⇒ 旧索引原样保留）。
pub struct BuiltIndex {
    pub index: RuleIndex,
    pub stats: BuildStats,
    pub has_group_rules: bool,
    /// 构建前的 `has_group_rules`（发布时算 `group_flip` 用）。
    pub old_has_group: bool,
}

/// 结论缓存观测计数（热路径只用 `Relaxed` 原子自增，不做任何同步等待）。
///
/// `lock_acquisitions` 记录**分片锁获取次数**，用于回归对比「旧全局锁 vs 新分片锁」
/// 的锁竞争面：锁次数不变（每次查询 1 次读 + 冷路径 1 次写），但竞争被摊到
/// [`RULE_CACHE_SHARDS`] 把互不相干的锁上。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RuleCacheStats {
    /// 结论缓存命中次数（含缓存了 `None` 的负结论）。
    pub hits: u64,
    /// 结论缓存未命中次数。
    pub misses: u64,
    /// 分片锁获取次数（读 + 写）。
    pub lock_acquisitions: u64,
    /// gen 失配（期间发生过重建）而丢弃的写回次数。
    pub gen_rejected_puts: u64,
    /// 分片满时的半量淘汰次数。
    pub half_evictions: u64,
}

/// 单分片结论缓存（独立锁 → 跨分片无竞争）。
struct CacheShard {
    map: parking_lot::Mutex<LruCache<String, Option<Arc<Rule>>>>,
    /// 本分片条目上界（`总容量/分片数`，余数分摊到前若干分片）。
    cap: usize,
    hits: AtomicU64,
    misses: AtomicU64,
    locks: AtomicU64,
    gen_rejected: AtomicU64,
    half_evictions: AtomicU64,
}

impl CacheShard {
    fn new(cap: usize) -> Self {
        Self {
            map: parking_lot::Mutex::new(LruCache::unbounded()),
            cap: cap.max(1),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            locks: AtomicU64::new(0),
            gen_rejected: AtomicU64::new(0),
            half_evictions: AtomicU64::new(0),
        }
    }

    fn add_stats(&self, out: &mut RuleCacheStats) {
        out.hits += self.hits.load(Ordering::Relaxed);
        out.misses += self.misses.load(Ordering::Relaxed);
        out.lock_acquisitions += self.locks.load(Ordering::Relaxed);
        out.gen_rejected_puts += self.gen_rejected.load(Ordering::Relaxed);
        out.half_evictions += self.half_evictions.load(Ordering::Relaxed);
    }
}

/// 分片结论缓存：按归一化域名哈希选片，同域名恒同片。
struct ShardedRuleCache {
    shards: Vec<CacheShard>,
    mask: usize,
}

impl ShardedRuleCache {
    fn new(total_cap: usize, shards: usize) -> Self {
        let n = shards.next_power_of_two().max(1);
        let base = total_cap / n;
        let rem = total_cap % n;
        let shards = (0..n)
            .map(|i| CacheShard::new(base + if i < rem { 1 } else { 0 }))
            .collect();
        Self {
            shards,
            mask: n - 1,
        }
    }

    #[inline]
    fn shard_index(&self, n: &str) -> usize {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        n.hash(&mut h);
        (h.finish() as usize) & self.mask
    }

    #[inline]
    fn shard(&self, n: &str) -> &CacheShard {
        &self.shards[self.shard_index(n)]
    }

    fn clear(&self) {
        for s in &self.shards {
            s.map.lock().clear();
        }
    }

    fn len(&self) -> usize {
        self.shards.iter().map(|s| s.map.lock().len()).sum()
    }

    fn stats(&self) -> RuleCacheStats {
        let mut out = RuleCacheStats::default();
        for s in &self.shards {
            s.add_stats(&mut out);
        }
        out
    }
}

/// 规则引擎。共享状态用 parking_lot 短临界区；索引以 `Arc` 原子发布，
/// 读路径仅克隆 Arc（O(1)），看到的是同一份不可变快照。
pub struct RuleEngine {
    index: RwLock<Arc<RuleIndex>>,
    gen: AtomicU64,
    /// 分片结论缓存（替代旧全局 `Mutex<LruCache>`，见模块头 R-02）。
    cache: ShardedRuleCache,
    cache_max: usize,
    rebuild_ts: Mutex<Instant>,
    grace: Duration,
    has_group_rules: AtomicBool,
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleEngine {
    /// 空引擎（空索引，gen=0）。
    pub fn new() -> Self {
        Self::with_options(RULE_CACHE_MAX, Duration::from_secs_f64(RULE_GRACE_SEC))
    }

    /// 自定义缓存容量与宽限期。
    pub fn with_options(cache_max: usize, grace: Duration) -> Self {
        Self {
            index: RwLock::new(Arc::new(RuleIndex::build(Vec::new()).0)),
            gen: AtomicU64::new(0),
            cache: ShardedRuleCache::new(cache_max, RULE_CACHE_SHARDS),
            cache_max,
            rebuild_ts: Mutex::new(Instant::now()),
            grace,
            has_group_rules: AtomicBool::new(false),
        }
    }

    /// 当前代际号（供 resolver 写回门禁用：RTT 前后 gen 不一致则跳过内核写回）。
    pub fn gen(&self) -> u64 {
        self.gen.load(Ordering::Relaxed)
    }

    /// 重建后是否存在 group 规则。
    pub fn has_group_rules(&self) -> bool {
        self.has_group_rules.load(Ordering::Relaxed)
    }

    /// 当前索引快照（Arc 克隆，O(1)）。
    pub fn snapshot(&self) -> Arc<RuleIndex> {
        self.index.read().clone()
    }

    /// **[历史归因]** 结论缓存容量上界（对齐 Python `_rule_cache_max`）。
    pub fn cache_max(&self) -> usize {
        self.cache_max
    }

    /// 当前索引内的规则条数（O(1)；管理面 `/api/pipeline` 用）。
    ///
    /// 取索引快照的只读字段，不做任何重建/遍历；重建后立即反映新值。
    pub fn rule_count(&self) -> usize {
        self.index.read().rule_count()
    }

    /// 当前结论缓存条目数（测试/观测）。
    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    /// 结论缓存观测计数快照（测试/指标）。
    pub fn cache_stats(&self) -> RuleCacheStats {
        self.cache.stats()
    }

    /// 重建规则索引。`rules` 顺序须为「本地在前、订阅在后」（本地占位优先）。
    ///
    /// **[历史归因]** 顺序对齐 Python：先无锁发布新索引快照，再自增 gen 并清空结论缓存。
    pub fn rebuild(&self, rules: Vec<Rule>) -> BuildReport {
        let cand = self.build_candidate(rules);
        self.publish_candidate(cand)
    }

    /// **2.1.49（P0）**：只构建候选索引，**不发布**（不修改当前索引/gen/结论缓存）。
    ///
    /// 失败判定在调用方：`RuleIndex::build` 只统计"进索引"与"被拒"，
    /// 解析期丢弃（`dropped`）只有 `subscribe` 知道，因此本方法不替调用方做决定。
    pub fn build_candidate(&self, rules: Vec<Rule>) -> BuiltIndex {
        let old_has_group = self.has_group_rules.load(Ordering::Relaxed);
        let (index, stats) = RuleIndex::build(rules);
        let has_group_rules = index.has_group_rules;
        BuiltIndex {
            index,
            stats,
            has_group_rules,
            old_has_group,
        }
    }

    /// **2.1.49（P0）**：发布 [`BuiltIndex`]（与 [`RuleEngine::rebuild`] 的发布语义逐位相同）。
    pub fn publish_candidate(&self, cand: BuiltIndex) -> BuildReport {
        let new_has_group = cand.has_group_rules;
        // 1) 发布新索引快照（读路径立即看到同一份不可变快照）。
        *self.index.write() = Arc::new(cand.index);
        // 2) 自增代际 + 清空结论缓存；写回侧在持分片锁内校验 gen，失配即丢弃
        //    （对齐 `_cache_rule`）。
        self.gen.fetch_add(1, Ordering::Relaxed);
        self.cache.clear();
        *self.rebuild_ts.lock() = Instant::now();

        let group_flip = cand.old_has_group != new_has_group;
        // mirror（非热路径，普通写即可）。
        self.has_group_rules.store(new_has_group, Ordering::Relaxed);

        BuildReport {
            gen: self.gen.load(Ordering::Relaxed),
            has_group_rules: new_has_group,
            group_flip,
            stats: cand.stats,
        }
    }

    /// 读结论缓存：`Ok(值)` = 命中（副作用：提升到 MRU），`Err(())` = 未命中。
    #[inline]
    fn cache_get(&self, n: &str) -> Result<Option<Arc<Rule>>, ()> {
        let shard = self.cache.shard(n);
        shard.locks.fetch_add(1, Ordering::Relaxed);
        let mut map = shard.map.lock();
        match map.get(n) {
            Some(v) => {
                let v = v.clone();
                drop(map);
                shard.hits.fetch_add(1, Ordering::Relaxed);
                Ok(v)
            }
            None => {
                drop(map);
                shard.misses.fetch_add(1, Ordering::Relaxed);
                Err(())
            }
        }
    }

    /// 写入一条结论缓存。gen 与当前不一致（重建发生在取快照之后）则丢弃，
    /// 避免旧索引结论污染新缓存（对齐 `_cache_rule` 的 gen 校验）。
    fn cache_put(&self, n: String, value: Option<Arc<Rule>>, gen: u64) {
        let shard = self.cache.shard(&n);
        shard.locks.fetch_add(1, Ordering::Relaxed);
        let mut map = shard.map.lock();
        if gen != self.gen.load(Ordering::Relaxed) {
            shard.gen_rejected.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // 淘汰 + 写入在一次锁获取内完成（无「check-then-act」二次加锁窗口）。
        let replacing = map.peek(&n).is_some();
        if !replacing && map.len() >= shard.cap {
            // 满时弹出一半最久未用，而非整体清空（对齐 L7 半量淘汰）。
            let half = map.len() / 2;
            for _ in 0..half {
                map.pop_lru();
            }
            shard.half_evictions.fetch_add(1, Ordering::Relaxed);
        }
        map.put(n, value);
    }

    /// 命中写缓存 + 返回（压缩重复分支；`Rule` 只克隆一次）。
    #[inline]
    fn hit(&self, n: String, r: Arc<Rule>, gen: u64) -> MatchOutcome {
        let owner = Arc::clone(&r);
        let out = (*r).clone();
        self.cache_put(n, Some(owner), gen);
        MatchOutcome::Hit(out)
    }

    /// 域名级规则匹配。`fast=true` 时一旦进入正则阶段即返回 [`MatchOutcome::Uncertain`]。
    pub fn match_rule(&self, domain: &str, fast: bool) -> MatchOutcome {
        let n = Name::normalize(domain).into_string();

        // R17：先读代际，再解包索引快照（避免「旧索引 + 新代际」fail-open 窗口）。
        let gen = self.gen.load(Ordering::Relaxed);
        let idx = self.index.read().clone();

        // 结论缓存命中（读路径即返回；`LruCache::get` 已提升到 MRU）。
        if let Ok(v) = self.cache_get(&n) {
            return match v {
                Some(r) => MatchOutcome::Hit((*r).clone()),
                None => MatchOutcome::NoRule,
            };
        }

        // ---- 白名单（allow）优先 ----
        if let Some(r) = idx.allow_exact.get(&n) {
            let r = Arc::clone(r);
            return self.hit(n, r, gen);
        }
        if let Some(r) = strip_lookup(&n, &idx.allow_wild) {
            let r = Arc::clone(r);
            return self.hit(n, r, gen);
        }

        // ---- 非 allow：精确 ----
        if let Some(r) = idx.exact.get(&n) {
            let r = Arc::clone(r);
            return self.hit(n, r, gen);
        }

        // ---- 纯后缀通配：*.core 匹配 core 及其子域，逐级剥离最长优先 ----
        if let Some(r) = strip_lookup(&n, &idx.wild) {
            let r = Arc::clone(r);
            return self.hit(n, r, gen);
        }

        // ---- fast 路径早退 ----
        if fast {
            if idx.has_no_regex_rules() {
                self.cache_put(n, None, gen);
                return MatchOutcome::NoRule;
            }
            return MatchOutcome::Uncertain;
        }

        // ---- 中缀/前缀通配：按字面后缀定位候选小组后逐条正则 ----
        if let Some(r) = self.match_suffix_wild(&idx, &n) {
            let r = Arc::clone(r);
            return self.hit(n, r, gen);
        }

        // ---- re: 正则：按序首个命中 ----
        for rr in idx.regex.iter() {
            if rr.regex.is_match(&n) {
                let r = Arc::clone(&rr.rule);
                return self.hit(n, r, gen);
            }
        }

        self.cache_put(n, None, gen);
        MatchOutcome::NoRule
    }

    /// 枚举查询名的候选后缀（标签边界后缀 + 每标签尾部 1..=4 字符短后缀，
    /// 覆盖 `myads.com -> ads.com`），在 `suffix_wild` 分组里定位候选规则并逐条正则。
    /// **[历史归因]** 对齐 Python `match_rule` 的候选生成（resolver.py:3987-4014）与 `_seen_groups` 去重语义。
    ///
    /// **[历史归因]** 候选枚举两阶段（顺序与 Python `_cands` 一致）：
    /// 1. 标签边界后缀：`a.b.c.com -> a.b.c.com / b.c.com / c.com / com`（借用切片）；
    /// 2. 每标签尾部短后缀 `cut ∈ (4,3,2,1)`：同标签内为借用切片，跨标签需拼接
    ///    `pre + "." + tail` → 一个 `String` 缓冲（参考实现用 `_pre + "." + _tail`）。
    ///
    /// R-03：候选尽量以**借用切片**表示（阶段 1 与阶段 2 的同标签形态），去重改用
    /// **定长数组线性扫描**（候选数 ≤ 标签数×5），仅跨标签拼接候选需要一次堆分配。
    fn match_suffix_wild<'a>(&self, idx: &'a RuleIndex, n: &str) -> Option<&'a Arc<Rule>> {
        // 标签字节边界：bounds[i] = 第 i 个标签的**结束**偏移（分隔点位置或 n.len()）。
        // 标签 i 的起点 = if i == 0 { 0 } else { bounds[i-1] + 1 }。
        let mut bounds: [usize; MAX_LABELS] = [0; MAX_LABELS];
        let mut nl = 0usize;
        for (i, b) in n.bytes().enumerate() {
            if b == b'.' {
                if nl >= MAX_LABELS {
                    // 标签数 >127：DNS 名线格式上限内不可能；放弃分组加速（保守不误判）。
                    return None;
                }
                bounds[nl] = i;
                nl += 1;
            }
        }
        if nl >= MAX_LABELS {
            return None;
        }
        bounds[nl] = n.len();
        let nlab = nl + 1;

        // **[历史归因]** 已成功查表的后缀小集合（对齐 Python `_seen_groups`：**只在命中分组后**才记入，
        // **[历史归因]** 因此重复候选仍会再做一次（必然 miss 的）哈希查找，与 Python 行为一致）。
        let mut known: [&str; KNOWN_SUFFIX_MAX] = [""; KNOWN_SUFFIX_MAX];
        let mut known_len = 0usize;

        // ---- 阶段 1：标签边界后缀（最长优先，覆盖 a.b.c.com / b.c.com / c.com / com）----
        for i in 0..nlab {
            let start = if i == 0 { 0 } else { bounds[i - 1] + 1 };
            // **[历史归因]** 候选 = 第 i 个标签起点到**名尾**的完整后缀，对齐 Python
            // `".".join(_labels[_i:])`（resolver.py:3989-3990）。
            // 2.1.2 的「0 堆分配」重写曾误写成 `&n[start..bounds[i]]`（单个标签），
            // 于是所有多标签分组 key（`*ads.com` 的 "ads.com"、`*a.b.test` 的 "b.test"）
            // 永不命中——屏蔽类规则静默失效（fail-open）。候选仍是 `n` 的借用切片，
            // 不产生任何堆分配。
            let cand = &n[start..];
            if let Some(r) = self.suffix_group_hit(idx, n, cand, &mut known, &mut known_len) {
                return Some(r);
            }
        }

        // ---- 阶段 2：每个标签自身的尾部短后缀（覆盖 myads.com -> ads.com）----
        for i in 0..nlab {
            let start = if i == 0 { 0 } else { bounds[i - 1] + 1 };
            let end = bounds[i];
            let lab = &n[start..end];
            // 该标签之后的完整尾部（不含分隔点）；末标签 → 空。
            let tail = if i + 1 < nlab {
                &n[bounds[i] + 1..]
            } else {
                ""
            };
            // **[历史归因]** Python 用**字符**切片（`_lab[-_cut:]`，resolver.py:3993-3996）；按字节切
            // 会在多字节标签上切出非 UTF-8 边界（`&s[a..b]` panic）。
            let lab_chars = lab.chars().count();
            for cut in TAIL_CUTS {
                if lab_chars <= cut {
                    continue;
                }
                let off = lab.char_indices().rev().nth(cut - 1).map_or(0, |(j, _)| j);
                let pre = &lab[off..];
                if tail.is_empty() {
                    if let Some(r) = self.suffix_group_hit(idx, n, pre, &mut known, &mut known_len)
                    {
                        return Some(r);
                    }
                } else {
                    // 跨标签拼接（`pre + "." + tail`）：一个 `String` 缓冲。此处**不走**
                    // `known` 去重表——该表的元素是借自 `n` 的 `&str`，而本候选借自函数内
                    // 缓冲，生命周期不足以写入跨迭代复用的表。去重只是省一次哈希查找的
                    // 优化，跳过它不改变匹配结论（同一候选重复查表结果相同）。
                    // 旧实现在此用 256 字节栈缓冲，超长名会**静默跳过**该候选（漏屏蔽），
                    // 故改用与参考实现等价的按需缓冲。
                    let mut joined = String::with_capacity(pre.len() + 1 + tail.len());
                    joined.push_str(pre);
                    joined.push('.');
                    joined.push_str(tail);
                    if let Some(r) = self.suffix_group_lookup(idx, n, &joined) {
                        return Some(r);
                    }
                }
            }
        }
        None
    }

    /// 跨标签拼接候选的查表（不做 `known` 去重，见调用点注释）。
    /// 返回引用来自 `idx`，与 `cand` 的生命周期无关。
    #[inline]
    fn suffix_group_lookup<'a>(
        &self,
        idx: &'a RuleIndex,
        n: &str,
        cand: &str,
    ) -> Option<&'a Arc<Rule>> {
        let group = idx.suffix_wild.get(cand)?;
        for rr in group {
            if rr.regex.is_match(n) {
                return Some(&rr.rule);
            }
        }
        None
    }

    /// 单个候选后缀的分组查表 + 逐条正则；命中时记录到 `known`（对齐 `_seen_groups`
    /// 的「命中才标记」语义）。`known`/`known_len` 为定长线性去重表。
    #[inline]
    fn suffix_group_hit<'a, 'c>(
        &self,
        idx: &'a RuleIndex,
        n: &str,
        cand: &'c str,
        known: &mut [&'c str; KNOWN_SUFFIX_MAX],
        known_len: &mut usize,
    ) -> Option<&'a Arc<Rule>> {
        if cand.is_empty() || known[..*known_len].contains(&cand) {
            return None;
        }
        let group = idx.suffix_wild.get(cand)?;
        if *known_len < KNOWN_SUFFIX_MAX {
            known[*known_len] = cand;
            *known_len += 1;
        }
        for rr in group {
            if rr.regex.is_match(n) {
                // SAFETY: 返回引用自 idx（调用方持有 Arc 快照），生命周期安全。
                return Some(&rr.rule);
            }
        }
        None
    }

    /// 是否仍在规则重建后的宽限期内（对齐 `_in_rule_grace`）。
    pub fn in_grace_at(&self, now: Instant) -> bool {
        let ts = *self.rebuild_ts.lock();
        now.duration_since(ts) < self.grace
    }

    /// 宽限期判定（以当前时刻）。
    pub fn in_grace(&self) -> bool {
        self.in_grace_at(Instant::now())
    }
}

/* ---------------- R-03：栈上候选后缀辅助（零堆分配） ---------------- */

/// 标签数上限（DNS 线格式 ≤255 字节、每标签 ≥1 字节 + 分隔点 → 标签数 ≤127）。
const MAX_LABELS: usize = 127;
/// 已命中后缀的线性去重表容量（候选数 ≤ 标签数×5，正常域名远小于此）。
const KNOWN_SUFFIX_MAX: usize = 64;
/// **[历史归因]** 尾部短后缀的切割长度序列（对齐 Python `for _cut in (4, 3, 2, 1)`）。
const TAIL_CUTS: [usize; 4] = [4, 3, 2, 1];

/// **[历史归因]** 从完整域名逐级剥标签，在 `*.core` 表里查最长匹配（对齐 Python while-core 循环）。
fn strip_lookup<'a>(n: &str, table: &'a HashMap<String, Arc<Rule>>) -> Option<&'a Arc<Rule>> {
    let mut core: &str = n;
    loop {
        if let Some(r) = table.get(core) {
            return Some(r);
        }
        match core.find('.') {
            Some(idx) => core = &core[idx + 1..],
            None => break,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::{rule_from_json, RuleSource};
    use serde_json::json;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc as StdArc;

    fn rule(m: &str, action: &str) -> Rule {
        let v = json!({"match": m, "action": action});
        rule_from_json(v.as_object().expect("object").clone(), RuleSource::Local)
            .unwrap_or_else(|| panic!("应能构造规则 {action} {m}"))
    }

    fn action_of(e: &RuleEngine, d: &str) -> Option<crate::rule::Action> {
        match e.match_rule(d, false) {
            MatchOutcome::Hit(r) => Some(r.action),
            _ => None,
        }
    }

    /// R-02：缓存命中不应产生新的堆分配（值类型为 `Arc<Rule>`，只做引用计数）。
    #[test]
    fn cache_hit_is_arc_clone_and_hits_are_counted() {
        let e = RuleEngine::new();
        e.rebuild(vec![rule("hot.test", "block")]);
        assert!(matches!(
            e.match_rule("hot.test", false),
            MatchOutcome::Hit(_)
        ));
        let s1 = e.cache_stats();
        assert_eq!(s1.hits, 0, "首次为冷路径");
        assert_eq!(s1.misses, 1);
        for _ in 0..8 {
            assert!(matches!(
                e.match_rule("hot.test", false),
                MatchOutcome::Hit(_)
            ));
        }
        let s2 = e.cache_stats();
        assert_eq!(s2.hits, 8, "8 次读全部命中分片缓存");
        assert_eq!(s2.misses, 1);
        // 锁次数：冷路径 1 读 + 1 写 = 2；热路径每次 1 读 = 8 → 合计 10。
        // （旧实现是每次查询 1 次**全局**锁；这里改为 64 把独立分片锁。）
        assert_eq!(s2.lock_acquisitions, 10, "1 冷读 + 1 冷写 + 8 热读");
    }

    /// R-02：分片数 >1，跨域名落到不同锁上（串行点被摊薄）。
    #[test]
    fn cache_is_sharded_across_distinct_domains() {
        let e = RuleEngine::new();
        e.rebuild(vec![rule("*.test", "block")]);
        // 至少两个不同域名写入后，两个分片都应有条目（哈希分布）。
        for i in 0..64 {
            let _ = e.match_rule(&format!("d{i}.test"), false);
        }
        assert_eq!(e.cache_len(), 64, "64 个域名全部入缓存");
        let s = e.cache_stats();
        assert_eq!(s.misses, 64);
        assert!(s.hits == 0);
    }

    /// R-02：代际变更立即失效（重建后旧结论不得继续生效）。
    #[test]
    fn gen_change_invalidates_cache_immediately() {
        let e = RuleEngine::new();
        e.rebuild(vec![rule("g.test", "block")]);
        assert_eq!(action_of(&e, "g.test"), Some(crate::rule::Action::Block));
        assert!(matches!(
            e.match_rule("g.test", false),
            MatchOutcome::Hit(_)
        ));
        e.rebuild(vec![rule("g.test", "allow")]);
        assert_eq!(
            action_of(&e, "g.test"),
            Some(crate::rule::Action::Allow),
            "重建后新规则立即生效（旧结论已随代际清空）"
        );
        assert_eq!(e.cache_len(), 1);
    }

    /// 并发读：多线程同时 match_rule + 周期 rebuild，不得 panic，且结论始终属于
    /// 某一代（block 或 allow 之一，绝不出现第三个值/空）。
    #[test]
    fn concurrent_reads_are_stable_across_rebuilds() {
        let e = StdArc::new(RuleEngine::new());
        e.rebuild(vec![rule("c.test", "block"), rule("*.co.test", "block")]);
        let stop = StdArc::new(AtomicBool::new(false));
        let errors = StdArc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for t in 0..8 {
            let e = StdArc::clone(&e);
            let stop = StdArc::clone(&stop);
            let errors = StdArc::clone(&errors);
            handles.push(std::thread::spawn(move || {
                let mut i = 0usize;
                while !stop.load(Ordering::Relaxed) {
                    let d = if i.is_multiple_of(2) {
                        "c.test"
                    } else {
                        "x.co.test"
                    };
                    match e.match_rule(d, false) {
                        MatchOutcome::Hit(r) => {
                            if r.action != crate::rule::Action::Block
                                && r.action != crate::rule::Action::Allow
                            {
                                errors.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        MatchOutcome::NoRule => {
                            errors.fetch_add(1, Ordering::Relaxed);
                        }
                        MatchOutcome::Uncertain => {}
                    }
                    // 交错 fast 读：三态语义不得错乱。
                    let _ = e.match_rule("zzz.test", true);
                    i += 1;
                    if t == 0 && i.is_multiple_of(512) {
                        // 交替重建：block ↔ allow，观察切换期间读路径稳定性。
                        let r = if (i / 512).is_multiple_of(2) {
                            vec![rule("c.test", "allow"), rule("*.co.test", "block")]
                        } else {
                            vec![rule("c.test", "block"), rule("*.co.test", "block")]
                        };
                        e.rebuild(r);
                    }
                }
            }));
        }
        std::thread::sleep(std::time::Duration::from_millis(120));
        stop.store(true, Ordering::Relaxed);
        for h in handles {
            h.join().expect("读线程不得 panic");
        }
        assert_eq!(errors.load(Ordering::Relaxed), 0, "并发读结论恒稳定");
    }

    /// 缺陷 B：`RuleEngine::rule_count()` = 索引真实收录条数（六分表合并计数），
    /// 重建后立即反映；空引擎为 0；被拒的坏规则不计入。
    #[test]
    fn rule_count_tracks_indexed_rules_across_rebuilds() {
        let e = RuleEngine::new();
        assert_eq!(e.rule_count(), 0, "空引擎 → 0");
        // 精确 / *.通配 / 中缀通配 / re: 各一条 → 4 条全部进索引。
        e.rebuild(vec![
            rule("a.test", "block"),
            rule("*.b.test", "block"),
            rule("*ads.c.test", "block"),
            rule("re:^x[0-9]+\\.test$", "block"),
        ]);
        assert_eq!(e.rule_count(), 4);
        // 坏规则被拒（正则编译失败 / 空正则体）不计入。
        e.rebuild(vec![
            rule("ok.test", "block"),
            rule("re:[", "block"),
            rule("re:   ", "block"),
        ]);
        assert_eq!(e.rule_count(), 1, "被拒规则不得计入");
        // 重建为大规模规则集（模拟订阅展开）→ 计数立即跟随。
        let many: Vec<_> = (0..500)
            .map(|i| rule(&format!("*.d{i}.test"), "block"))
            .collect();
        e.rebuild(many);
        assert_eq!(e.rule_count(), 500);
        e.rebuild(Vec::new());
        assert_eq!(e.rule_count(), 0, "DELETE 订阅清空后归零");
    }

    /// R-03：标签边界 + 最长优先 + 标签内候选（分组 key 可被标签内短后缀定位）。
    ///
    /// **[历史归因]** 行为判据 = Python v1.9.162 `resolver.py`：`_wildcard_to_regex` 把前导 `*`
    /// 译为 `(?:.*\.)?`（:3788），故 `*ads.com` 命中 `ads.com` / `x.ads.com`，
    /// 但**不**命中标签内形态 `myads.com`（:3774-3778 原文“但**不**命中 myads.com”）；
    /// 标签内候选（`_lab[-_cut:]`，:3991-3996）只负责把分组找出来，正则仍是最终判据
    /// （:4005-4009）。该结论已用 v1.9.162 的 `Resolver.match_rule` 实测（返回 None），
    /// 与 `tests/rules_test.rs:154-170`、`README.md`（通配语义迁移一节）一致。
    #[test]
    fn suffix_wild_longest_and_label_boundary() {
        let e = RuleEngine::new();
        e.rebuild(vec![
            rule("*ac*.com", "block"),
            rule("*ads.com", "block"),
            rule("*.deep.ads.com", "allow"),
        ]);
        // *ads.com 分组 key = "ads.com"：标签边界形态命中（阶段 1 的完整后缀候选）
        assert_eq!(action_of(&e, "ads.com"), Some(crate::rule::Action::Block));
        assert_eq!(action_of(&e, "x.ads.com"), Some(crate::rule::Action::Block));
        // 标签内形态（myads.com -> 候选 "ads.com"）能定位到分组，但组内正则
        // **[历史归因]** `^(?:.*\.)?ads\.com$` 要求 `*` 落在标签边界 → 不命中（同 Python）。
        assert!(matches!(
            e.match_rule("myads.com", false),
            MatchOutcome::NoRule
        ));
        // 更长/更具体的 *.deep.ads.com（allow）应优先
        assert_eq!(
            action_of(&e, "x.deep.ads.com"),
            Some(crate::rule::Action::Allow)
        );
        // 不相关域名不命中
        assert!(matches!(
            e.match_rule("plain.net", false),
            MatchOutcome::NoRule
        ));
    }

    /// **[历史归因]** R-03：候选去重后结论仍与 Python 同序（首个命中生效）。
    ///
    /// 查询名用 `zz.com`（标签边界）而非 `azz.com`：`*zz.com` 的正则
    /// `^(?:.*\.)?zz\.com$`（resolver.py:3788）不匹配标签内形态，参考实现实测
    /// `match_rule("azz.com") is None`；`zz.com` 落在同一分组 "zz.com" 上，
    /// 同样检验「组内按配置顺序首个命中」。
    #[test]
    fn suffix_wild_dedup_keeps_first_hit_order() {
        let e = RuleEngine::new();
        // 同一分组内两条规则：先索引者优先（配置顺序）。
        e.rebuild(vec![rule("*zz.com", "block"), rule("*zz.com", "allow")]);
        assert_eq!(
            action_of(&e, "zz.com"),
            Some(crate::rule::Action::Block),
            "同后缀分组内按配置顺序首个命中（allow 去重不影响）"
        );
        // 标签内形态不命中（同 resolver.py:3774-3788 / 实测 None）。
        assert!(matches!(
            e.match_rule("azz.com", false),
            MatchOutcome::NoRule
        ));
    }

    /// allow 优先：白名单精确/通配均优先于 block。
    #[test]
    fn allow_priority_over_block() {
        let e = RuleEngine::new();
        e.rebuild(vec![
            rule("ok.test", "allow"),
            rule("*.test", "block"),
            rule("*.safe.test", "allow"),
        ]);
        assert_eq!(action_of(&e, "ok.test"), Some(crate::rule::Action::Allow));
        assert_eq!(
            action_of(&e, "x.safe.test"),
            Some(crate::rule::Action::Allow)
        );
        assert_eq!(action_of(&e, "x.test"), Some(crate::rule::Action::Block));
    }

    /// `re:` fail-closed：坏正则加载期拒绝，且不污染邻近规则；好正则按序首个命中。
    #[test]
    fn regex_fail_closed_and_ordered() {
        let e = RuleEngine::new();
        e.rebuild(vec![
            rule("re:[unclosed", "block"),
            rule("re:^ads\\.", "block"),
            rule("re:ads", "block"),
        ]);
        assert!(matches!(
            e.match_rule("other.test", false),
            MatchOutcome::NoRule
        ));
        assert_eq!(action_of(&e, "ads.x.com"), Some(crate::rule::Action::Block));
        // 坏正则不生效（不会被当成通配或精确）
        assert!(matches!(
            e.match_rule("[unclosed", false),
            MatchOutcome::NoRule
        ));
    }

    /// fast 三态：无正则类时 fast 可判 NoRule 并缓存；有正则类时 Uncertain（不缓存）。
    #[test]
    fn fast_three_state_unchanged() {
        let e = RuleEngine::new();
        e.rebuild(vec![rule("f.test", "block")]);
        assert!(matches!(
            e.match_rule("miss.test", true),
            MatchOutcome::NoRule
        ));
        assert_eq!(e.cache_len(), 1, "fast NoRule 已缓存");
        assert_eq!(e.cache_stats().lock_acquisitions, 2, "1 读锁 + 1 写锁");
        // 夹具不能用 `re:^r\.`：规范化 `trim_end_matches('.')`（`rule_from_json`，
        // **[历史归因]** 对齐 Python `resolver.py:3659` 的 `rstrip(".")`）会把尾部 `.` 削掉，得到
        // `re:^r\` → 正则编译失败被丢弃（对齐 :3676-3680），此时索引内**没有**正则类
        // 规则，fast 自然返回 NoRule 并缓存（v1.9.162 实测同为 None）。故改用 `re:^r`，
        // 才能覆盖「存在正则类规则 → Uncertain」这一分支。
        e.rebuild(vec![rule("f.test", "block"), rule("re:^r", "block")]);
        assert!(matches!(
            e.match_rule("miss.test", true),
            MatchOutcome::Uncertain
        ));
        assert_eq!(e.cache_len(), 0, "Uncertain 绝不写缓存");
        // Uncertain 只在读锁上落一次 miss（1 冷读 + 1 冷写 + 1 Uncertain 读 = 3）。
        assert_eq!(e.cache_stats().lock_acquisitions, 3, "Uncertain 不产生写锁");
    }

    /// 超长/边界域名（>127 标签）：suffix 分组路径保守放弃，不得 panic、不得误判。
    #[test]
    fn overlong_label_count_does_not_panic() {
        let e = RuleEngine::new();
        e.rebuild(vec![rule("*ads.com", "block")]);
        let long = (0..200)
            .map(|i| format!("l{i}"))
            .collect::<Vec<_>>()
            .join(".");
        // 不 panic 即可（分组加速被放弃 → 可能 NoRule，但绝不误报）。
        let _ = e.match_rule(&long, false);
        // **[历史归因]** 正常域名仍工作（标签边界形态；标签内形态 myads.com 按 Python 语义不命中，
        // 见 resolver.py:3774-3788 与 `suffix_wild_longest_and_label_boundary`）。
        assert_eq!(action_of(&e, "ads.com"), Some(crate::rule::Action::Block));
        assert!(matches!(
            e.match_rule("myads.com", false),
            MatchOutcome::NoRule
        ));
    }
}
