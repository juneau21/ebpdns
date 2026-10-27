//! **[历史归因]** W-TinyLFU 缓存，对齐 Python `TinyLFUCache` + `_CMSketch`（cache.py:591-1032）。
//!
//! 三段结构：window → probation → protected（默认 **1% / 40% / 60%**，= 2.1.8 行为）。
//! 新条目先进 window，溢出时与 probation 队首按 Count-Min Sketch 频率准入；
//! 命中 probation 即晋升 protected。
//!
//! ## A4：三段比例与晋升闸门
//!
//! 2.1.9 曾把比例改成 5/35/60 并与既有测试契约冲突而整体回退。本轮把"比例 + 晋升
//! 闸门"收敛成[`Policy`]（生产默认 [`Policy::BASELINE`]，逐位等价 2.1.8），并配
//! 独立固定 trace 回放基准（`benches/tinylfu_trace.rs`）**先用数据决定是否合并**：
//!
//! - `win_pct` / `prob_pct`：window 占总量、probation 占 main 的百分比（protected = 余下）；
//! - `promote_min_freq`：probation→protected 晋升的**最低 sketch 频率水位**（0 = 不设水位）；
//! - `restrict_promotion`：protected 满时，仅当晋升者频率严格高于 protected LRU 队首才晋升。
//!
//! 比例参数化不改变 `Caps` 的和不变量（`win + prob + prot == cap`，`cap >= 16` 时成立）。

use crate::entry::{CacheEntry, CacheKey};
use crate::lru::entry_to_json;
use crate::ordered_map::OrderedMap;
use crate::persist::journal::{CacheJournal, EvictReason};
use crate::persist::PersistStats;
use crate::util::{
    clamp_capacity, has_absolute_expiry, is_legacy_format, resolve_restored_expiry, round1,
    safe_float,
};
use crate::{hash_key, DnsCache};
use parking_lot::{Mutex, RwLock};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

/// Count-Min Sketch 行数（导出给文档一致性回归用，见 [`SKETCH_BYTES`]）。
pub const SKETCH_D: usize = 4;
/// Count-Min Sketch 列数（`u8` 饱和计数：每行每列 1 字节）。
pub const SKETCH_W: usize = 1024;
/// **Count-Min Sketch 的实际内存占用（字节）** = `D × W × size_of::<u8>()` = **4 KiB**。
///
/// 单一来源：Web 控制台文案里的"额外内存约 N"必须由本常量推导
/// （`crates/ebpdns-cache/tests/doc_consistency_tests.rs` 会核对）。
/// 历史文案曾写"约 512KB"（比实际大 128 倍），属文档漂移。
pub const SKETCH_BYTES: usize = SKETCH_D * SKETCH_W;
/// 老化触发间隔 = 65536 / D（每 16384 次 inc 只老化一行）。
const AGE_INTERVAL: u64 = 65536 / (SKETCH_D as u64);

const ROW_MULTS: [u64; SKETCH_D] = [
    0x9E37_79B9_7F4A_7C15,
    0xBF58_476D_1CE4_E5B9,
    0x94D0_49BB_1331_11EB,
    0xC2B2_AE3D_27D4_EB4F,
];

/// Count-Min Sketch：D 行 × W 列，u8 饱和计数，分片老化。
///
/// C-05：`table` 原来是 4 KiB **内联**数组，`clear()`/`restore()` 里
/// `sketch = CmSketch::new()` 每次都要整体搬 4 KiB。现在改为 `Box<[...]>`
/// （结构体只剩 8 字节指针 + 两个计数）并新增 [`CmSketch::reset`] 原地复用缓冲区，
/// clear/restore 的 4 KiB 拷贝与分配都降为 0。
struct CmSketch {
    table: Box<[[u8; SKETCH_W]; SKETCH_D]>,
    ops: u64,
    age_row: usize,
}

impl Default for CmSketch {
    fn default() -> Self {
        Self::new()
    }
}

impl CmSketch {
    fn new() -> Self {
        Self {
            table: Box::new([[0u8; SKETCH_W]; SKETCH_D]),
            ops: 0,
            age_row: 0,
        }
    }

    /// 原地清空（复用已分配的 4 KiB 缓冲区，不重新分配）。
    fn reset(&mut self) {
        self.table.fill([0u8; SKETCH_W]);
        self.ops = 0;
        self.age_row = 0;
    }

    #[inline]
    fn col_for(row: usize, h1: u64) -> usize {
        let h = h1.wrapping_mul(ROW_MULTS[row]);
        ((h >> 32) as usize) % SKETCH_W
    }

    fn inc(&mut self, h1: u64, n: u64) {
        self.ops += n;
        if self.ops >= AGE_INTERVAL {
            self.ops = 0;
            self.age_one_row();
        }
        let add = n.min(255) as u8;
        for i in 0..SKETCH_D {
            let col = Self::col_for(i, h1);
            let cell = &mut self.table[i][col];
            *cell = (*cell).saturating_add(add);
        }
    }

    fn freq(&self, h1: u64) -> u8 {
        let mut mn = 255u8;
        for i in 0..SKETCH_D {
            let col = Self::col_for(i, h1);
            let v = self.table[i][col];
            if v < mn {
                mn = v;
            }
        }
        mn
    }

    fn age_one_row(&mut self) {
        let row = &mut self.table[self.age_row];
        for c in row.iter_mut() {
            *c >>= 1;
        }
        self.age_row = (self.age_row + 1) % SKETCH_D;
    }
}

/// 三段容量快照（对齐 `_repartition_locked`）。
///
/// C-04：整组容量是 [`TinyInner`] 内的普通字段，与三段 map 同锁发布，读侧不可能
/// 看到撕裂组合。
///
/// **比例默认 1 / 40 / 60（= 2.1.8 行为）**：A4 的 5/35/60 改动必须先由独立基准
/// （`benches/tinylfu_trace.rs`）证明 hit 率提升且无回归才合并；比例经
/// [`Caps::compute_ratio`] 参数化，`compute_ratio(cap, 1, 40)` 与 2.1.8 的整数运算
/// 逐位一致（回归锁在 `a4_policy_tests::caps_ratio_1_40_60_is_bitwise_legacy`）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Caps {
    win: usize,
    prob: usize,
    prot: usize,
    main: usize,
}

/// A4 三段比例 + 晋升闸门策略。生产默认 [`Policy::BASELINE`]（= 2.1.8 行为）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Policy {
    /// window 占总容量的百分比（默认 1）。
    win_pct: usize,
    /// probation 占 main（= cap - window）的百分比（默认 40，protected 取余下 60）。
    prob_pct: usize,
    /// probation→protected 晋升的最低 sketch 频率水位（0 = 不设水位，恒放行）。
    promote_min_freq: u8,
    /// protected 满时，仅当晋升者频率**严格高于** protected LRU 队首频率才晋升。
    restrict_promotion: bool,
}

/// **三段比例的默认值**（百分比；单一来源 = [`Policy::BASELINE`]）。
///
/// 导出给文档一致性回归：控制台文案里的 "window(1%) → probation(40%) → protected(60%)"
/// 必须与这两个常量一致。
pub const WINDOW_PCT_DEFAULT: usize = 1;
/// probation 占 **main**（= cap − window）的百分比；protected 取余下的 60%。
pub const PROBATION_PCT_DEFAULT: usize = 40;

impl Policy {
    /// 2.1.8 行为：1/40/60，无晋升闸门。
    const BASELINE: Self = Self {
        win_pct: 1,
        prob_pct: 40,
        promote_min_freq: 0,
        restrict_promotion: false,
    };
}

impl Caps {
    /// 按 `win_pct` / `prob_pct` 计算三段容量。
    ///
    /// 不变量（`cap >= 16`）：`win + prob + prot == cap`。`cap < 48` 走小容量分支，
    /// 与 2.1.8 同样按 `max(1, ...)` 保底。1/40/60 时两分支的整数运算与旧实现逐位相同
    /// （`main * 40 / 100` 与旧 `main * 2 / 5` 在有理性上等值，故 floor 亦等值）。
    fn compute_ratio(cap: usize, win_pct: usize, prob_pct: usize) -> Self {
        if cap < 48 {
            let win = (cap.saturating_mul(win_pct) / 100).max(1);
            let main = cap - win;
            let prob = (main.saturating_mul(prob_pct) / 100).max(1);
            let prot = main.saturating_sub(prob).max(1);
            Self {
                win,
                prob,
                prot,
                main,
            }
        } else {
            let win = (cap.saturating_mul(win_pct) / 100).max(16);
            let main = cap - win;
            let prob = (main.saturating_mul(prob_pct) / 100).max(16);
            let prot = main.saturating_sub(prob);
            Self {
                win,
                prob,
                prot,
                main,
            }
        }
    }
}

/// W-TinyLFU 工程版缓存。
pub struct TinyLfuCache {
    /// 仅用于对外汇报容量（`summary`/`capacity`）；驱动的三段容量在 [`TinyInner::caps`]。
    total_cap: AtomicUsize,
    inner: Mutex<TinyInner>,
    stale_window: AtomicU64,
    // ---- **2.1.19（修复项 1）**：`restore` 的丢弃计数（每实例，非进程级 static）----
    /// 绝对到期已过而丢弃的条数（INFO 汇总，与计数在同一代码块赋值）。
    restore_dropped_expired: AtomicU64,
    /// **旧格式**（只有 `remaining`、无绝对 `expires_at`）按安全侧丢弃的条数（WARN）。
    ///
    /// 2.1.19 的 tinylfu 分支**没有这个计数、也没有那条 WARN** —— 而
    /// `cache_policy` 的出厂默认就是 `tinylfu` ⇒ 生产上"旧格式被丢弃"完全不可观测，
    /// 这正是"计数恒 0 / WARN 不触发"的真实根因（`lru.rs` 的计数本身是好的）。
    restore_dropped_legacy: AtomicU64,
    /// 记录损坏（既无绝对 `expires_at`、也无 `remaining`，或反序列化失败）的条数（WARN）。
    restore_failed: AtomicU64,
    /// **2.1.43-B（P2-4）**：最近一次 `restore` 里"**快照写了、但恢复只灌 main 段**"
    /// ⇒ 被挤出（≈ window 段容量）的条数。口径与用途见
    /// [`DnsCache::last_restore_window_unpersisted`]。
    restore_window_unpersisted: AtomicU64,
    // ---------------- 2.1.29：缓存持久化 v2 的接缝（M10） ----------------
    journal: RwLock<Option<Arc<CacheJournal>>>,
    stats: Arc<PersistStats>,
}

struct TinyInner {
    window: OrderedMap<CacheKey, Arc<CacheEntry>>,
    probation: OrderedMap<CacheKey, Arc<CacheEntry>>,
    protected: OrderedMap<CacheKey, Arc<CacheEntry>>,
    /// C-04：三段容量与 map 同锁，读侧永远看到一致快照。
    caps: Caps,
    /// A4：比例与晋升闸门（生产默认 = [`Policy::BASELINE`]，同锁发布）。
    policy: Policy,
    sketch: CmSketch,
    puts: u64,
    misses: u64,
}

impl TinyLfuCache {
    /// 构造。容量经 `max(16, ...)` 钳制后重算三段。
    pub fn new(capacity: usize) -> Self {
        Self::with_policy(capacity, Policy::BASELINE)
    }

    fn with_policy(capacity: usize, policy: Policy) -> Self {
        let cap = clamp_capacity(Some(capacity));
        Self {
            total_cap: AtomicUsize::new(cap),
            inner: Mutex::new(TinyInner {
                window: OrderedMap::new(),
                probation: OrderedMap::new(),
                protected: OrderedMap::new(),
                caps: Caps::compute_ratio(cap, policy.win_pct, policy.prob_pct),
                policy,
                sketch: CmSketch::new(),
                puts: 0,
                misses: 0,
            }),
            stale_window: AtomicU64::new(0),
            restore_dropped_expired: AtomicU64::new(0),
            restore_dropped_legacy: AtomicU64::new(0),
            restore_failed: AtomicU64::new(0),
            restore_window_unpersisted: AtomicU64::new(0),
            journal: RwLock::new(None),
            stats: PersistStats::new(),
        }
    }

    /// **2.1.29（v2）**：注入现场统计（由外壳 `SwappableCache` 下发同一份）。
    pub fn with_stats(mut self, stats: Arc<PersistStats>) -> Self {
        self.stats = stats;
        self
    }

    #[inline]
    fn journal_snapshot(&self) -> Option<Arc<CacheJournal>> {
        self.journal.read().clone()
    }

    fn stale_f64(&self) -> f64 {
        self.stale_window.load(Ordering::Relaxed) as f64
    }

    /// 淘汰（调用方必须已持 [`TinyLfuCache::inner`] 锁）。
    ///
    /// **2.1.29（v2）**：真正被丢弃的键收进 `out` —— 它们必须写 `EVICT(reason=CAPACITY)`，
    /// 否则回放后集合与崩溃前不同（容量逐出恰恰是稳态下最频繁的变更）。
    ///
    /// 全程零分配搬移：
    /// - 原来的 `probation.front()` + `k.clone()` 只为算 victim 哈希（3 次 String
    ///   分配）→ 改为借用算哈希后 `pop_front()` 直接丢 victim；
    /// - `probation.insert(pk.clone(), pv); probation.move_to_front(&pk)`
    ///   （3 次 String 分配 + 一次多余哈希查找）→ 改为 `push_front(pk, pv)`。
    fn evict_locked(inner: &mut TinyInner, out: &mut Vec<CacheKey>) {
        let Caps {
            win: win_cap,
            prob: prob_cap,
            prot: prot_cap,
            main: main_cap,
        } = inner.caps;

        // 1) window 溢出 → 准入 main。
        while inner.window.len() > win_cap {
            let Some((wk, wv)) = inner.window.pop_front() else {
                break;
            };
            if inner.probation.len() < prob_cap {
                inner.probation.insert(wk, wv);
                continue;
            }
            if inner.probation.len() + inner.protected.len() < main_cap {
                inner.protected.insert(wk, wv);
                continue;
            }
            // 与 probation 队首 victim 比频率；严格 > 才准入。
            let h_wk = hash_key(&wk);
            let h_mk = match inner.probation.front() {
                Some((k, _)) => hash_key(k),
                None => {
                    // 没有 victim 可比 ⇒ `wk` 被丢弃（与既有行为一致）。
                    out.push(wk);
                    continue;
                }
            };
            if inner.sketch.freq(h_wk) > inner.sketch.freq(h_mk) {
                if let Some((victim, _)) = inner.probation.pop_front() {
                    out.push(victim);
                }
                inner.probation.insert(wk, wv);
            } else {
                out.push(wk);
            }
        }
        // 2) protected 溢出 → 队首挤回 probation 队首（**不是**逐出）。
        while inner.protected.len() > prot_cap {
            let Some((pk, pv)) = inner.protected.pop_front() else {
                break;
            };
            inner.probation.push_front(pk, pv);
        }
        // 3) probation 溢出 → 丢队首（真正淘汰点）。
        while inner.probation.len() > prob_cap {
            match inner.probation.pop_front() {
                Some((k, _)) => out.push(k),
                None => break,
            }
        }
    }

    fn purge_expired_locked(inner: &mut TinyInner, now: f64, sw: f64) {
        purge_one(&mut inner.window, now, sw);
        purge_one(&mut inner.probation, now, sw);
        purge_one(&mut inner.protected, now, sw);
    }

    /// A4 晋升闸门（调用方必须已持 [`TinyLfuCache::inner`] 锁）。
    ///
    /// [`Policy::BASELINE`] 下**恒返回 true**：`promote_min_freq == 0` 且
    /// `restrict_promotion == false`，因此生产默认路径与 2.1.8 逐位一致。
    #[inline]
    fn promotion_allowed(inner: &TinyInner, f_new: u8) -> bool {
        let p = inner.policy;
        if p.promote_min_freq > 0 && f_new < p.promote_min_freq {
            return false;
        }
        if p.restrict_promotion && inner.protected.len() >= inner.caps.prot {
            if let Some((pk, _)) = inner.protected.front() {
                // 只读频率估算（不 inc，不改 sketch）。
                if inner.sketch.freq(hash_key(pk)) >= f_new {
                    return false;
                }
            }
        }
        true
    }
}

/// A4 基准专用构造（`cargo bench --features bench-policy`）。
///
/// 生产默认路径不经过这里；此 API 的存在只为让独立基准能在**同一份实现**上
/// 对比"三段比例 + 晋升闸门"组合，避免在基准里复制算法造成实现漂移。
#[cfg(feature = "bench-policy")]
impl TinyLfuCache {
    /// 显式指定三段比例与晋升闸门。
    ///
    /// - `win_pct`：window 占总容量百分比（基线 1）；
    /// - `prob_pct`：probation 占 main 百分比（基线 40，protected = 余下）；
    /// - `promote_min_freq`：晋升最低 sketch 频率水位（0 = 不设水位）；
    /// - `restrict_promotion`：protected 满时要求晋升者频率严格高于 LRU 队首。
    pub fn new_with_policy(
        capacity: usize,
        win_pct: usize,
        prob_pct: usize,
        promote_min_freq: u8,
        restrict_promotion: bool,
    ) -> Self {
        // 比例同样做有界钳制，避免 bench 传入越界值把 `Caps` 推到退化态（不 panic）。
        let win_pct = win_pct.min(50);
        let prob_pct = prob_pct.min(100);
        Self::with_policy(
            capacity,
            Policy {
                win_pct,
                prob_pct,
                promote_min_freq,
                restrict_promotion,
            },
        )
    }
}

impl DnsCache for TinyLfuCache {
    fn get(&self, key: &CacheKey, now: f64) -> Option<CacheEntry> {
        self.get_arc(key, now).map(|e| (*e).clone())
    }

    /// C-07：三段命中路径全部零堆分配（只 `Arc::clone`）。probation→protected
    /// 晋升用 `remove_entry` 把已拥有的键搬过去，不再 `key.clone()`。
    fn get_arc(&self, key: &CacheKey, now: f64) -> Option<Arc<CacheEntry>> {
        let mut inner = self.inner.lock();
        let sw = self.stale_f64();
        let h1 = hash_key(key);

        if let Some(e) = inner.window.get(key).cloned() {
            if e.expires_at <= now {
                if sw <= 0.0 {
                    inner.window.remove(key);
                }
                return None;
            }
            inner.window.move_to_end(key);
            inner.sketch.inc(h1, 1);
            return Some(e);
        }
        // probation 命中：先借一次判断"存在/是否过期"（1 次哈希查找），
        // 命中再 `remove_entry` 连键一起搬走（第 2 次查找，0 次键克隆）。
        match inner.probation.get(key).map(|e| e.expires_at <= now) {
            Some(true) => {
                if sw <= 0.0 {
                    inner.probation.remove(key);
                }
                return None;
            }
            Some(false) => {
                // A4 晋升闸门（默认 [`Policy::BASELINE`] 恒放行 → 与 2.1.8 逐位一致）：
                // 未达最低频率水位 / 受限晋升不通过时，**留在 probation**（置 MRU），
                // 不把一次性长尾条目塞进 protected 挤掉真热点。
                if !Self::promotion_allowed(&inner, inner.sketch.freq(h1)) {
                    inner.probation.move_to_end(key);
                    inner.sketch.inc(h1, 1);
                    return inner.probation.get(key).cloned();
                }
                // 搬移：连键一起取出（不克隆），再原地插到 protected 尾（MRU）。
                let (owned_key, e) = inner.probation.remove_entry(key)?;
                // protected 满 → 队首（LRU）挤回 probation 队首（搬移，不克隆）。
                if inner.protected.len() >= inner.caps.prot && !inner.protected.is_empty() {
                    if let Some((pk, pv)) = inner.protected.pop_front() {
                        inner.probation.push_front(pk, pv);
                    }
                }
                inner.protected.insert(owned_key, e.clone());
                inner.sketch.inc(h1, 1);
                return Some(e);
            }
            None => {}
        }
        if let Some(e) = inner.protected.get(key).cloned() {
            if e.expires_at <= now {
                if sw <= 0.0 {
                    inner.protected.remove(key);
                }
                return None;
            }
            inner.protected.move_to_end(key);
            inner.sketch.inc(h1, 1);
            return Some(e);
        }
        // miss：每 32 次扫一次队首过期。
        inner.misses += 1;
        if sw <= 0.0 && (inner.misses & 0x1F) == 0 {
            sweep_front(&mut inner.window, now);
            sweep_front(&mut inner.probation, now);
            sweep_front(&mut inner.protected, now);
        }
        None
    }

    // >>> 242B BEGIN P1-9-tinylfu >>> //
    /// **2.1.42-B（P1-9）**：纯观测 —— 不 move、不 `sketch.inc`、不晋升、不删过期项。
    fn peek(&self, key: &CacheKey, now: f64) -> Option<CacheEntry> {
        let mut inner = self.inner.lock();
        let store = if inner.window.contains_key(key) {
            0u8
        } else if inner.probation.contains_key(key) {
            1
        } else if inner.protected.contains_key(key) {
            2
        } else {
            return None;
        };
        let e = match store {
            0 => inner.window.get(key).cloned(),
            1 => inner.probation.get(key).cloned(),
            _ => inner.protected.get(key).cloned(),
        }?;
        if e.expires_at <= now {
            // **2.1.45（P2-8 / REV247 P2-7）**：只读不晋升（不 `sketch.inc`、不 move），
            // 但惰性移除过期项（与 `delete` 同口径：移除三层存储，不动 sketch 计数）。
            match store {
                0 => inner.window.remove(key),
                1 => inner.probation.remove(key),
                _ => inner.protected.remove(key),
            };
            return None;
        }
        Some((*e).clone())
    }

    // <<< 242B END P1-9-tinylfu <<< //
    fn get_stale(&self, key: &CacheKey, now: f64, stale_window: f64) -> Option<CacheEntry> {
        self.get_stale_arc(key, now, stale_window)
            .map(|e| (*e).clone())
    }

    /// C-07：零堆分配（只 `Arc::clone`）。
    fn get_stale_arc(
        &self,
        key: &CacheKey,
        now: f64,
        stale_window: f64,
    ) -> Option<Arc<CacheEntry>> {
        let mut inner = self.inner.lock();
        for store in [0, 1, 2] {
            let found = match store {
                0 => inner.window.get(key).cloned(),
                1 => inner.probation.get(key).cloned(),
                _ => inner.protected.get(key).cloned(),
            };
            let Some(e) = found else { continue };
            let exp = e.expires_at;
            if exp > now {
                return None;
            }
            if now - exp > stale_window {
                match store {
                    0 => inner.window.remove(key),
                    1 => inner.probation.remove(key),
                    _ => inner.protected.remove(key),
                };
                return None;
            }
            match store {
                0 => inner.window.move_to_end(key),
                1 => inner.probation.move_to_end(key),
                _ => inner.protected.move_to_end(key),
            };
            return Some(e);
        }
        None
    }

    fn put(&self, key: CacheKey, value: CacheEntry, now: f64) {
        let j = self.journal_snapshot();
        {
            let mut inner = self.inner.lock();
            // **2.1.34（D1）**：`seq` 分配与入队放进**同一临界区**（缓存锁 + journal 总序锁）。
            // 旧实现出锁后才 `try_send`：并发线程可能“先分配小 seq、后入队” ⇒ WAL 回退。
            let _order = j.as_ref().map(|jj| jj.order_guard());
            let h1 = hash_key(&key);
            // **2.1.29（§6.1）**：内存变更 + seq 分配在**同一临界区**内完成；
            // 准入被拒（TinyLFU 拒绝）时**既不分配也不发送**，否则回放会凭空插入。
            let mut value = value;
            if let Some(jj) = &j {
                value.seq = jj.next_seq();
            }
            let arc = Arc::new(value);
            // key 只在**需要发事件**时才克隆（journal 关闭 = 0 次克隆）。
            let key_for_event = j.as_ref().map(|_| key.clone());
            // 三段的“命中哪段就更新哪段”与既有行为逐位一致；走到这里**必定插入成功**
            // （本策略没有“拒绝 put”的分支 —— 准入比较发生在 evict 里，且被淘汰的是别的键）。
            if inner.protected.contains_key(&key) {
                inner.protected.insert(key, Arc::clone(&arc));
            } else if inner.probation.contains_key(&key) {
                inner.probation.insert(key, Arc::clone(&arc));
            } else {
                inner.window.insert(key, Arc::clone(&arc));
            }
            inner.sketch.inc(h1, 1);
            let mut evicted = Vec::new();
            Self::evict_locked(&mut inner, &mut evicted);
            inner.puts += 1;
            if (inner.puts & 0x1F) == 0 {
                let sw = self.stale_f64();
                Self::purge_expired_locked(&mut inner, now, sw);
            }
            if let Some(jj) = &j {
                // **2.1.34（D1）**：入队也在同一临界区（`try_send` 非阻塞，代价可忽略）。
                for k in evicted {
                    let s = jj.next_seq();
                    jj.evict(k, EvictReason::Capacity, s);
                }
                if let Some(k) = key_for_event {
                    let seq = arc.seq;
                    jj.put(k, arc, seq);
                }
            }
        }
    }

    fn delete(&self, key: &CacheKey) {
        let mut inner = self.inner.lock();
        inner.window.remove(key);
        inner.probation.remove(key);
        inner.protected.remove(key);
    }

    fn clear(&self) {
        let mut inner = self.inner.lock();
        inner.window.clear();
        inner.probation.clear();
        inner.protected.clear();
        // C-05: 原地复用 4 KiB 缓冲区，不再整体重建 CmSketch。
        inner.sketch.reset();
    }

    fn len(&self) -> usize {
        let inner = self.inner.lock();
        inner.window.len() + inner.probation.len() + inner.protected.len()
    }

    fn keys(&self) -> Vec<CacheKey> {
        let inner = self.inner.lock();
        // C-10: 精确预留（三段的 len 已知，无需 realloc）。
        let mut out =
            Vec::with_capacity(inner.window.len() + inner.probation.len() + inner.protected.len());
        for store in [&inner.window, &inner.probation, &inner.protected] {
            for (k, _) in store.iter() {
                out.push(k.clone());
            }
        }
        out
    }

    /// **2.1.46（REV247 P2-4）**：早停采样 —— 只克隆至多 `limit` 个 key。
    ///
    /// 旧实现用 trait 默认的 `keys().truncate(limit)`：在默认 `tinylfu` 策略下，
    /// `/api/snapshot` 每 2 s 会把**全表**（生产 13 万条 ≈ 39 万个 String）克隆一遍，
    /// 然后才截到 500；本覆写把克隆量降到 O(limit)，且仍只持一次缓存锁。
    ///
    /// 采样顺序与 [`TinyLfuCache::keys`] 一致（window → probation → protected），
    /// 因此 `/api/snapshot.entries` 的"前 500 个"语义不变。
    fn sample_keys(&self, limit: usize) -> Vec<CacheKey> {
        let mut out = Vec::with_capacity(limit.min(1024));
        if limit == 0 {
            return out;
        }
        let inner = self.inner.lock();
        for store in [&inner.window, &inner.probation, &inner.protected] {
            for (k, _) in store.iter() {
                out.push(k.clone());
                if out.len() >= limit {
                    return out;
                }
            }
        }
        out
    }

    fn summary(&self) -> Value {
        let inner = self.inner.lock();
        let used = inner.window.len() + inner.probation.len() + inner.protected.len();
        let cap = self.total_cap.load(Ordering::Relaxed).max(1);
        let pct = (used as f64 / cap as f64) * 100.0;
        json!({
            "used": used,
            "capacity": self.total_cap.load(Ordering::Relaxed),
            // **[历史归因]** C-01: 与 Python `round(x, 1)` 同口径（半值取偶）。
            "pct": round1(pct),
            "window": inner.window.len(),
            "probation": inner.probation.len(),
            "protected": inner.protected.len(),
        })
    }

    fn serialize(&self, now: f64) -> Vec<Value> {
        // C-10: 精确预留。
        let cap = {
            let inner = self.inner.lock();
            inner.window.len() + inner.probation.len() + inner.protected.len()
        };
        let mut out = Vec::with_capacity(cap);
        // **2.1.25（B8）**：逐条产出的单一实现在 `for_each_snapshot_entry` 里。
        self.for_each_snapshot_entry(now, &mut |v| out.push(v));
        out
    }

    /// **2.1.25（B8 性能项）**：**逐条**产出（不建整表 `Vec<Value>`）。
    ///
    /// 锁粒度与旧实现**完全一致**：整段仍持 `self.inner` 一把锁（三段同属一个
    /// `Inner`，拆不开）—— 但不再把整表建成 `Value` 树，因此**持锁期间的分配量
    /// 从 O(表大小) 降到 O(1)**（每个条目一条记录的 `Value` + 一段文本）。
    fn for_each_snapshot_entry(&self, now: f64, f: &mut dyn FnMut(Value)) {
        let inner = self.inner.lock();
        for store in [&inner.window, &inner.probation, &inner.protected] {
            for (k, e) in store.iter() {
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
        let pt = safe_float(persist_ttl, 0.0).max(0.0);
        let cap = self.total_cap.load(Ordering::Relaxed);
        // C-03: 同 LRUCache::restore，大 cap 下 `cap * 4` 会 panic/回绕。
        let restore_cap = cap.saturating_mul(4).max(65536);
        // **2.1.45（P2-9 / REV247 P2-8）**：`restore_cap` 截断条数也计入
        // `window_unpersisted`（v1 路径与 v2 路径同口径，不低报）。
        let mut cap_dropped = 0u64;
        let raw: &[Value] = if entries.len() > restore_cap {
            tracing::warn!(
                "TinyLFU.restore: {} 条恢复记录超过上限 {}, 截断",
                entries.len(),
                restore_cap
            );
            cap_dropped = (entries.len() - restore_cap) as u64;
            &entries[..restore_cap]
        } else {
            entries
        };

        let mut inner = self.inner.lock();
        inner.window.clear();
        inner.probation.clear();
        inner.protected.clear();
        // C-05: 原地复用缓冲区。
        inner.sketch.reset();
        let main_cap = inner.caps.main;

        // 收集有效条目及其剩余 TTL。
        let mut valid: Vec<(CacheKey, CacheEntry, f64)> = Vec::new();
        // **2.1.19（修复项 1）**：三类丢弃分别计数，恢复结束后各打一条日志
        // （`legacy` WARN 一次含条数；`expired` INFO 汇总；`failed` WARN 汇总）。
        // 与 `lru.rs::restore_refs` **同源同口径** —— 判据统一走
        // `util::is_legacy_format` / `util::has_absolute_expiry`，不可能再漂移。
        let mut expired_dropped = 0usize;
        let mut legacy_dropped = 0usize;
        let mut parse_failed = 0usize;
        // **2.1.19（修复项 1 补漏）**：结构判定与 `lru.rs::restore_refs` **同源** ——
        // 唯一来源 = `util::structural_check`（此前 tinylfu **自己实现了第二份解析**，
        // 且用 `unwrap_or_default()` 把"取不出的 domain/qtype"当成空字符串**真的插进缓存**：
        // 既漏计数又写垃圾条目。部署代理的"同口径"单测正是抓到了这一类）。
        let mut structural_failed = [0usize; crate::util::StructuralIssue::COUNT];
        for e in raw {
            let parsed = match crate::util::structural_check(e) {
                Ok(p) => p,
                Err(iss) => {
                    structural_failed[iss.idx()] += 1;
                    continue;
                }
            };
            let key = CacheKey {
                group: parsed.group,
                domain: parsed.domain,
                qtype: parsed.qtype,
            };
            // **2.1.19（修复项 1，2.1.18 唯一残留的真实根因）**：旧格式判定
            // **必须**在 TTL 策略分派之前、且**与 `persist_ttl` 取值无关**。
            //
            // 2.1.19 这里把判定挂在 `if pt <= 0.0` 之内，命中后**只是裸 `continue`**：
            //   * 既不计数、也不打日志 ⇒ 生产（`cache_policy=tinylfu`）上"旧格式被
            //     丢弃"**完全不可观测**，"丢弃正确但 WARN 缺"就是这么来的；
            //   * `persist_ttl > 0` 时旧格式条目会被 `now + persist_ttl` **复活**，
            //     违反"旧格式只能安全侧丢弃"的契约。
            // 现在：先 `is_legacy_format` ⇒ `legacy_dropped += 1` ⇒ `continue`；
            // 既无绝对到期也无 `remaining` ⇒ 记为损坏（`parse_failed`）。
            if is_legacy_format(e) {
                legacy_dropped += 1;
                continue;
            }
            if !has_absolute_expiry(e) {
                parse_failed += 1;
                continue;
            }
            let mut entry: CacheEntry = match serde_json::from_value(e.clone()) {
                Ok(en) => en,
                // **不再静默**：坏条目单独计数（函数尾部 WARN 汇总）。
                Err(_) => {
                    parse_failed += 1;
                    continue;
                }
            };
            // ---- **时间口径（2.1.19 修复项 17：DNS TTL 契约）** ----
            // 与 `lru.rs::restore_refs` **逐字同源**（三策略必须一致，否则换策略就换语义）：
            // ①绝对 `expires_at` 优先（停机时长计入 TTL；已过期直接丢弃）；
            // ②只有 `remaining` 的旧格式 ⇒ 安全侧丢弃（不重新锚定）；
            // ③`persist_ttl > 0` 是**剩余 TTL 上限（cap）**，只可能缩短寿命。
            // **2.1.18（修复项 23）**：`persist_ttl > 0` = 用户显式选择的"统一恢复 TTL"
            // （opt-in 延长，配置页与 README 已标注风险）；`= 0` = 严格遵守绝对到期时间。
            // **2.1.19（修复项 1）**：走到这里时 `expires_at` 必定是有限正数（上面两关已挡），
            // 因此 2.1.19 在此处的第二份"旧格式 ⇒ continue"已删除（它永不执行）。
            let remaining = if pt > 0.0 {
                entry.expires_at = now + pt;
                entry.ttl = pt;
                pt
            } else {
                // **2.1.29**：判定逻辑的唯一实现 = [`resolve_restored_expiry`]
                // （与 v2 恢复、v1 迁移共用）；这里保留 v1 的算术写法以免浮点末位漂移。
                match resolve_restored_expiry(entry.expires_at, now, pt) {
                    Some(abs) => {
                        entry.expires_at = abs;
                        entry.ttl = (abs - now).max(0.0);
                        abs - now
                    }
                    None => {
                        expired_dropped += 1;
                        continue;
                    }
                }
            };
            valid.push((key, entry, remaining));
        }
        // 按剩余 TTL 升序（尾部=最耐用），只保留最长 main_cap 条灌入 protected。
        valid.sort_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal));
        let start = valid.len().saturating_sub(main_cap);
        // **2.1.43-B（P2-4）**：`start` = 快照里写了、恢复却**没放回**的条数 ——
        // 恢复只灌 main 段（`cap − window`），其余恰好是 window 段容量级（出厂 ≈1%）。
        // 此前完全静默 ⇒ `used_live` 按恢复计划条数赋值 ⇒ 丢失率读成 0。
        // **2.1.45（P2-9）**：再并入 `restore_cap` 截断量 = window 段实际未持久化条数。
        let window_unpersisted = start as u64 + cap_dropped;
        for (k, en, _rem) in valid.into_iter().skip(start) {
            inner.protected.insert(k, Arc::new(en));
        }
        // 恢复期容量裁剪不记日志（journal 在恢复期 suspend）。
        let mut evicted = Vec::new();
        Self::evict_locked(&mut inner, &mut evicted);
        drop(inner);
        // **2.1.19（修复项 1）**：计数先写实例字段，再在同一代码块里打日志 ——
        // 断言计数等价于断言"WARN/INFO 分支被走到"，**不依赖 `tracing` 全局订阅者**。
        self.restore_dropped_expired
            .store(expired_dropped as u64, Ordering::Relaxed);
        self.restore_dropped_legacy
            .store(legacy_dropped as u64, Ordering::Relaxed);
        // **2.1.19（修复项 1 补漏）**：`failed` = 反序列化失败 + 结构不完整（与 lru 同口径）。
        let structural_total: usize = structural_failed.iter().sum();
        let failed_total = parse_failed + structural_total;
        self.restore_failed
            .store(failed_total as u64, Ordering::Relaxed);
        // **2.1.43-B（P2-4）**：window 段不参与恢复的条数（v1 路径，与 v2 同口径）。
        self.restore_window_unpersisted
            .store(window_unpersisted, Ordering::Relaxed);
        if window_unpersisted > 0 {
            tracing::info!(
                window_unpersisted,
                "TinyLFU.restore: 快照里写了、但恢复只灌 main 段 ⇒ 挤出 {window_unpersisted} 条\
                 （≈ window 段容量）—— 计入 `restore_drops.window_unpersisted`"
            );
        }
        if expired_dropped > 0 {
            tracing::info!(
                dropped_expired = expired_dropped,
                "TinyLFU.restore: 已丢弃 {} 条（文件里的绝对到期时间已过 —— 停机时长计入 TTL，符合 DNS TTL 契约）",
                expired_dropped
            );
        }
        if parse_failed > 0 {
            tracing::warn!(
                dropped_parse_failed = parse_failed,
                "TinyLFU.restore: **已丢弃 {} 条无法反序列化的记录**（字段缺失/类型不符 ⇒ 文件可能被截断或由不兼容版本写入）",
                parse_failed
            );
        }
        if structural_total > 0 {
            // 与 `lru.rs` **逐字同源**的逐类归因（标签来自 util.rs，四条路径同一组词）。
            let breakdown = crate::util::structural_breakdown(&structural_failed);
            tracing::warn!(
                dropped_structural = structural_total,
                key_not_array = structural_failed[0],
                key_len_invalid = structural_failed[1],
                domain_or_qtype_missing = structural_failed[2],
                answers_or_rcode_missing = structural_failed[3],
                "TinyLFU.restore: **已丢弃 {} 条结构不完整的记录**（{}）—— 逐类计数见本行的同名字段",
                structural_total,
                breakdown
            );
        }
        if legacy_dropped > 0 {
            tracing::warn!(
                dropped_legacy = legacy_dropped,
                "TinyLFU.restore: **已丢弃 {} 条旧格式记录**（文件里缺少绝对 `expires_at`，只有 `remaining`；\
                 无从判断停机了多久 ⇒ 按安全侧丢弃，不重新锚定 TTL）。下一次落盘会写成新格式。",
                legacy_dropped
            );
        }
    }

    fn set_capacity(&self, n: usize) {
        let n = clamp_capacity(Some(n));
        self.total_cap.store(n, Ordering::Relaxed);
        let j = self.journal_snapshot();
        let evicted_all: Vec<CacheKey>;
        // C-04: 容量整组更新 + 立即淘汰在同一把锁内完成，读侧不可能看到撕裂组合。
        {
            let mut inner = self.inner.lock();
            let p = inner.policy;
            inner.caps = Caps::compute_ratio(n, p.win_pct, p.prob_pct);
            let mut evicted = Vec::new();
            Self::evict_locked(&mut inner, &mut evicted);
            evicted_all = evicted;
        }
        if let Some(jj) = &j {
            // **2.1.34（D1）**：seq 分配 + 入队在同一总序临界区（不跨缓存锁，避免反向锁序）。
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
    /// **同一代码块**里赋值（本文件的 `restore` 尾部）。这是生产默认策略
    /// （`cache_policy=tinylfu`）的**唯一**可观测面。
    fn last_restore_drops(&self) -> (u64, u64, u64) {
        (
            self.restore_dropped_expired.load(Ordering::Relaxed),
            self.restore_dropped_legacy.load(Ordering::Relaxed),
            self.restore_failed.load(Ordering::Relaxed),
        )
    }

    /// **2.1.43-B（P2-4）**：恢复时"window 段不参与"被挤出的条数（见 trait 文档）。
    fn last_restore_window_unpersisted(&self) -> u64 {
        self.restore_window_unpersisted.load(Ordering::Relaxed)
    }

    // ---------------- 2.1.29：v2 持久化接缝 ----------------

    /// **2.1.29（v2）**：逐条产出。三段顺序 `window → probation → protected` 与
    /// v1 快照文件顺序**一致**（别改成 hash 序：快照顺序影响回放后的逐出顺序）。
    fn for_each_entry(&self, _now: f64, f: &mut dyn FnMut(&CacheKey, &Arc<CacheEntry>)) {
        let inner = self.inner.lock();
        for store in [&inner.window, &inner.probation, &inner.protected] {
            for (k, e) in store.iter() {
                f(k, e);
            }
        }
    }

    /// **2.1.29（v2）**：一次性装入恢复条目（TTL 已由 `recover` 统一决策）。
    ///
    /// 保留 v1 的 `valid.sort_by(remaining)` + 只灌 `main_cap` 条进 `protected` 的行为
    /// —— 换策略就换恢复语义是历史缺陷，v2 不重演。
    fn restore_records(&self, entries: Vec<(CacheKey, CacheEntry)>, now: f64) {
        let cap = self.total_cap.load(Ordering::Relaxed);
        let restore_cap = cap.saturating_mul(4).max(65536);
        let mut entries = entries;
        // **2.1.45（P2-9 / REV247 P2-8）**：`restore_cap` 截断的条数也必须计入
        // `window_unpersisted`（旧口径只数 main 段挤出 ⇒ 低报"快照里写了、恢复没灌"）。
        let mut cap_dropped = 0u64;
        if entries.len() > restore_cap {
            tracing::warn!(
                "TinyLFU.restore_records: {} 条恢复记录超过上限 {}, 截断（按 seq 升序保留前 N 条）",
                entries.len(),
                restore_cap
            );
            cap_dropped = (entries.len() - restore_cap) as u64;
            entries.sort_by_key(|(_, e)| e.seq);
            entries.truncate(restore_cap);
        }
        let mut inner = self.inner.lock();
        inner.window.clear();
        inner.probation.clear();
        inner.protected.clear();
        inner.sketch.reset();
        let main_cap = inner.caps.main;
        let mut valid: Vec<(CacheKey, CacheEntry, f64)> = Vec::with_capacity(entries.len());
        for (k, e) in entries {
            let remaining = e.expires_at - now;
            if remaining <= 0.0 {
                continue;
            }
            valid.push((k, e, remaining));
        }
        // 按剩余 TTL 升序（尾部 = 最耐用），只保留最长 `main_cap` 条灌入 protected。
        valid.sort_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal));
        let start = valid.len().saturating_sub(main_cap);
        // **2.1.43-B（P2-4）**：与 v1 `restore` 同口径 —— 被 main 段容量挤出的条数
        // （≈ window 段容量）。v2 是生产路径 ⇒ 这个计数必须在这里写。
        // **2.1.45（P2-9 / REV247 P2-8）**：口径 = `restore_cap` 截断量 + main 段挤出量
        // （"window 段实际未持久化条数"，含增量；旧口径低报截断部分）。
        let window_unpersisted = start as u64 + cap_dropped;
        for (k, en, _rem) in valid.into_iter().skip(start) {
            inner.protected.insert(k, Arc::new(en));
        }
        let mut evicted = Vec::new();
        Self::evict_locked(&mut inner, &mut evicted);
        drop(inner);
        // 恢复期的容量裁剪不记日志（journal 恢复期 suspend）。
        self.restore_window_unpersisted
            .store(window_unpersisted, Ordering::Relaxed);
        if window_unpersisted > 0 {
            tracing::info!(
                window_unpersisted,
                "TinyLFU.restore_records: 快照里写了、恢复没灌（restore_cap 截断 + main 段挤出）{window_unpersisted} 条\
                 （≈ window 段容量，出厂比例 1%）—— 计入 `restore_drops.window_unpersisted`，\
                 并被恢复丢失率公式覆盖（used_live = 恢复后实际插入条数）"
            );
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

/// 从单段 head 连续清理过期条目（serve-stale 窗口内保留）。
fn purge_one(store: &mut OrderedMap<CacheKey, Arc<CacheEntry>>, now: f64, sw: f64) {
    while let Some((_k, e)) = store.front() {
        let exp = e.expires_at;
        if exp > now {
            break;
        }
        if sw > 0.0 && (now - exp) <= sw {
            break;
        }
        store.pop_front();
    }
}

/// miss 时每段最多弹 4 条队首过期条目。
fn sweep_front(store: &mut OrderedMap<CacheKey, Arc<CacheEntry>>, now: f64) {
    for _ in 0..4 {
        let expired = store
            .front()
            .map(|(_, e)| e.expires_at <= now)
            .unwrap_or(false);
        if !expired {
            break;
        }
        store.pop_front();
    }
}

#[cfg(test)]
mod a4_policy_tests {
    use super::*;

    /// **2.1.8 的原始三段运算**（参考实现，只用于回归锁，不是生产代码）。
    fn legacy_1_40_60(cap: usize) -> (usize, usize, usize) {
        if cap < 48 {
            let win = (cap / 100).max(1);
            let main = cap - win;
            let prob = (main.saturating_mul(2) / 5).max(1);
            let prot = (main - prob).max(1);
            (win, prob, prot)
        } else {
            let win = (cap / 100).max(16);
            let main = cap - win;
            let prob = (main.saturating_mul(2) / 5).max(16);
            let prot = main - prob;
            (win, prob, prot)
        }
    }

    /// 参数化不得改变基线：`compute_ratio(cap, 1, 40)` 必须与 2.1.8 的原始整数运算
    /// **逐位相同**（`legacy_1_40_60` 是 2.1.8 公式的参考实现，只存在于测试里），
    /// 且三段之和恒等于容量（既有 `tinylfu_three_segments_sum_to_capacity` 契约）。
    #[test]
    fn caps_ratio_1_40_60_is_bitwise_legacy() {
        for cap in [
            16usize,
            17,
            32,
            47,
            48,
            49,
            64,
            100,
            1000,
            4096,
            16_384,
            131_072,
            1 << 20,
        ] {
            let c = Caps::compute_ratio(cap, 1, 40);
            let (win, prob, prot) = legacy_1_40_60(cap);
            assert_eq!(
                (c.win, c.prob, c.prot, c.main),
                (win, prob, prot, cap - win),
                "cap={cap}: 参数化 1/40/60 必须与 2.1.8 逐位一致"
            );
            assert_eq!(
                c.win + c.prob + c.prot,
                cap,
                "cap={cap}: 三段之和必须 == cap"
            );
        }
    }

    /// A4 候选比例在 `cap >= 16` 下同样满足"和不变量"（合并的前提条件之一）。
    ///
    /// 例外（非本轮引入，与 2.1.8 一致）：小容量分支里 `prot = max(1, main - prob)`
    /// 会在 `prob == main`（如 `prob_pct = 100`）时把总和抬高 1 —— 该保底是既有语义，
    /// 故 `(50, 100)` 这种退化输入只断言"≥ cap + 不 panic"，不进和不变量名单。
    #[test]
    fn caps_ratio_variants_keep_sum_invariant() {
        for (wp, pp) in [(5usize, 35usize), (1, 40), (5, 40), (10, 30), (2, 50)] {
            for cap in [16usize, 17, 47, 48, 64, 1000, 4096, 16_384, 131_072] {
                let c = Caps::compute_ratio(cap, wp, pp);
                assert_eq!(
                    c.win + c.prob + c.prot,
                    cap,
                    "cap={cap} {wp}/{pp}: 三段之和必须 == cap"
                );
            }
        }
        // 退化输入（prob 吃满 main）不得 panic：`cap>=48` 分支沿用 2.1.8 语义
        // （不强制 `prot>=1`），因此只断言"不 panic + 三段都不越界 + 总和 ≥ cap"。
        for cap in [16usize, 47, 48, 4096, 16_384] {
            let c = Caps::compute_ratio(cap, 50, 100);
            assert!(
                c.win <= cap && c.prob <= cap && c.prot <= cap,
                "cap={cap}: 不越界"
            );
            assert!(
                c.win >= 1 && c.prob >= 1,
                "cap={cap}: window/probation 保底"
            );
            assert!(
                c.win + c.prob + c.prot >= cap,
                "cap={cap}: 保底只允许 ≥ cap"
            );
        }
    }

    /// 生产默认（`new`）与显式 [`Policy::BASELINE`] 行为逐项一致：
    /// 同样的访问序列必须得到同样的命中判定与同样的三段占用。
    #[test]
    fn default_policy_equals_explicit_baseline() {
        let keys: Vec<CacheKey> = (0..1200)
            .map(|i| CacheKey::new(format!("d{}.x.test", i % 700), "A"))
            .collect();
        let now = 1000.0;
        let a = TinyLfuCache::new(256);
        let b = TinyLfuCache::with_policy(256, Policy::BASELINE);
        for k in &keys {
            let ha = a.get_arc(k, now).is_some();
            let hb = b.get_arc(k, now).is_some();
            assert_eq!(ha, hb, "命中判定必须一致（key={}）", k.domain);
            if !ha {
                let mk = || CacheEntry::new(&k.domain, &k.qtype, 600.0, now);
                a.put(k.clone(), mk(), now);
                b.put(k.clone(), mk(), now);
            }
        }
        assert_eq!(a.summary(), b.summary(), "三段占用必须逐项一致");
    }

    /// 晋升闸门确有生效路径：水位必须真的挡住"刚进 probation 就被命中一次"的晋升。
    ///
    /// 设计（使 protected **不会**被填满，从而能观察到差异）：
    /// cap=256 → window=16 / probation=96 / protected=144。
    /// - 阶段 1：60 个互不相同的键各 put 一次 → window 溢出把最旧的 44 个推进 probation
    ///   （每个键当时 sketch 频率 = 1）。
    /// - 阶段 2：把这 60 个键各 get 一次（频率 → 2）。
    ///   - 不设水位：probation 命中的 44 个立刻晋升 → protected ≈ 44；
    ///   - 水位 3：频率 2 < 3 → 全部拒绝晋升 → protected = 0，且**总占用不变**（60）。
    /// 这样断言的是"闸门只改变了晋升路径"，而不是"把某个不变量放宽"。
    #[test]
    fn promotion_watermark_actually_blocks_promotions() {
        let now = 1000.0;
        let keys: Vec<CacheKey> = (0..60)
            .map(|i| CacheKey::new(format!("w{i}.y.test"), "A"))
            .collect();
        let mk = |k: &CacheKey| CacheEntry::new(&k.domain, &k.qtype, 600.0, now);
        let run = |wm: u8| {
            let c = TinyLfuCache::with_policy(
                256,
                Policy {
                    win_pct: 1,
                    prob_pct: 40,
                    promote_min_freq: wm,
                    restrict_promotion: false,
                },
            );
            for k in &keys {
                c.put(k.clone(), mk(k), now);
            }
            for k in &keys {
                assert!(c.get_arc(k, now).is_some(), "阶段 2 必须全部命中");
            }
            c.summary()
        };
        let ungated = run(0);
        let gated = run(3);
        let prot = |s: &Value| s["protected"].as_u64().unwrap();
        let used = |s: &Value| s["used"].as_u64().unwrap();
        assert!(
            prot(&ungated) > 0,
            "无水位时必须发生 probation→protected 晋升：{ungated}"
        );
        assert!(
            prot(&gated) < prot(&ungated),
            "水位=3 必须挡住'频率 2'的晋升（gated={} vs ungated={}）",
            prot(&gated),
            prot(&ungated)
        );
        assert_eq!(
            used(&gated),
            used(&ungated),
            "闸门只应改变归属，不应改变总占用：gated={gated} ungated={ungated}"
        );
    }

    // >>> 242B BEGIN T-cache-tlfu >>> //
    /// **2.1.42-B（P1-9）**：`peek` 不得 `sketch.inc`、不得晋升、不得 move。
    #[test]
    fn p242b_peek_does_not_touch_sketch_or_segments() {
        use crate::DnsCache;
        let c = TinyLfuCache::new(64);
        for i in 0..8 {
            let k = CacheKey::new(format!("k{i}.test"), "A");
            c.put(
                k,
                CacheEntry::new(format!("k{i}.test"), "A", 300.0, 100.0),
                100.0,
            );
        }
        let snapshot = |c: &TinyLfuCache| {
            let g = c.inner.lock();
            (
                g.sketch.ops,
                g.window.len(),
                g.probation.len(),
                g.protected.len(),
            )
        };
        let before = snapshot(&c);
        let k = CacheKey::new("k0.test", "A");
        for _ in 0..10 {
            assert!(c.peek(&k, 100.0).is_some());
        }
        assert_eq!(snapshot(&c), before, "peek 不得 inc sketch / 晋升 / move");
    }
    // <<< 242B END T-cache-tlfu <<< //
}

#[cfg(test)]
mod fix245_tests {
    use super::*;
    use crate::DnsCache;

    /// **2.1.45（P2-8 / REV247 P2-7）**：`peek` 只读不晋升，但**惰性移除已过期**条目；
    /// 其余条目的顺序不受影响。
    #[test]
    fn peek_lazily_removes_expired_and_keeps_order() {
        let c = TinyLfuCache::new(64);
        for i in 0..4 {
            let dom = format!("peek{i}.test");
            c.put(
                CacheKey::new(dom.clone(), "A"),
                CacheEntry::new(dom, "A", 1.0, 100.0),
                100.0,
            );
        }
        let expired = CacheKey::new("peek0.test", "A");
        let before: Vec<String> = c
            .keys()
            .iter()
            .map(|k| k.domain.clone())
            .filter(|d| d != "peek0.test")
            .collect();
        assert!(c.peek(&expired, 200.0).is_none(), "过期项不得被观测端读到");
        assert_eq!(c.len(), 3, "peek 必须惰性移除过期项");
        let after: Vec<String> = c.keys().iter().map(|k| k.domain.clone()).collect();
        assert_eq!(after, before, "剩余条目顺序不得变化（不 move / 不晋升）");
    }

    /// **2.1.45（P2-9 / REV247 P2-8）**：`window_unpersisted` 必须包含 `restore_cap`
    /// 截断量（旧口径只数 main 段挤出 ⇒ 低报）。
    ///
    /// 判别力：70 000 条 > `restore_cap`(65 536) ⇒ 旧实现的值 ≤ 65 536；新实现
    /// 至少为 `4 464 + (65 536 − main_cap)` > 65 536。
    #[test]
    fn window_unpersisted_includes_restore_cap_truncation() {
        let c = TinyLfuCache::new(1000);
        let now = 1_700_000_000.0;
        let total = 70_000u64;
        let mut entries = Vec::with_capacity(total as usize);
        for i in 0..total {
            let dom = format!("cap{i}.test");
            let mut e = CacheEntry::new(dom.clone(), "A", 300.0, 100.0);
            e.expires_at = now + 300.0;
            entries.push((CacheKey::new(dom, "A"), e));
        }
        c.restore_records(entries, now);
        let stored = c.len() as u64;
        let dropped = c.last_restore_window_unpersisted();
        assert!(
            dropped > 65_536,
            "必须包含 restore_cap 截断量（旧口径 ≤ 65 536），实际 {dropped}"
        );
        assert!(
            dropped <= total - stored,
            "window_unpersisted 不得高于总丢失量（{dropped} <= {}）",
            total - stored
        );
        assert_eq!(
            c.summary()["used"].as_u64().unwrap(),
            stored,
            "used 必须等于恢复后实际条数"
        );
    }
}
