//! **阶段 B-2（RRset 对象级缓存）**：RRset 的进程内 intern（弱引用）表 +
//! 扁平答案的分组/展平。
//!
//! ## 为什么需要（A → B-1 → B-2 的演进）
//!
//! * **阶段 A** 把 `CacheEntry.answers` 改成 `Arc<Vec<CacheAnswer>>`：只共享
//!   **整条答案集完全相同**的消息。CNAME 链前置名一换，整份答案集就不同，
//!   链尾的 A/AAAA RRset 仍会被重复存很多份。
//! * **阶段 B-1** 再把 `CacheAnswer.value` / `name` 换成全进程内容唯一的
//!   `Arc<str>`：RDATA 字符串不再重复，但每条消息仍需各自分配一份答案数组。
//! * **阶段 B-2（本模块）** 把缓存模型升级为 **RRset 对象**：
//!
//!   ```text
//!   CacheEntry { rrsets: Vec<Arc<Rrset>>, ... }
//!   Rrset { owner: Arc<str>, rtype: u16, values: Vec<Arc<CacheAnswer>> }
//!   ```
//!
//!   相同 owner + 相同类型 + 相同取值集合的 RRset 全进程只保留**一个**
//!   `Arc<Rrset>`（弱引用表，不延长寿命）。于是「同一段 CNAME 前缀 + 同一个
//!   链尾 A RRset」的两条消息，链尾那段 `Arc<Rrset>` 是同一个分配
//!   （`Arc::ptr_eq` 为真）—— 这正是 B-2 相对 A/B-1 的净收益。
//!
//! ## 设计
//!
//! * **键**：`(owner, rtype, 按 value/ttl/name 排序后的 multiset 签名)`。
//!   顺序**不敏感**（RRset 的取值在 DNS 语义里无序；同一 RRset 即使上游返回的
//!   顺序不同也共享），哈希用逐值哈希的**可交换组合**（wrapping_add），相等性用
//!   多重集比对（≤64 条时用 `u64` 位掩码 + O(n²)，不分配；更多时退化为排序比对）。
//! * **owner 的表示**：`name = None`（owner 名 = 查询名）在 RRset 里存**空串**；
//!   展平时由每条 `CacheAnswer.name` 原样恢复（`None`/`Some("")` 的字节差异因此
//!   不会被本模块改写）。
//! * **字符串归一**：新建 RRset 时，`value` / `name` 先经阶段 B-1 的字符串表
//!   （[`intern_str`]）换成规范句柄；表满（[`MAX_INTERNED_STR`] 全活）时保留原句柄
//!   （有界优先）。**已经规范的 RRset 走快路径**：只查 RRset 表、不碰字符串表、
//!   不分配。
//! * **并发**：一把全局 `parking_lot::Mutex`；堆分配在锁外，慢路径拿锁后再查一次
//!   （check-insert）⇒ 8 线程并发 intern 同一 RRset 只有 1 个存活实例。
//! * **有界**：表项上限 [`MAX_INTERNED`]；到顶先 [`sweep`] 回收死弱引用，仍满则
//!   **拒绝登记**（只返回新 `Arc`）—— 有界优先，绝不无限增长。
//!
//! ## 与持久化的关系（v2 契约不变）
//!
//! RRset 只存在于**内存**表示。`CacheEntry` 的自定义 serde 仍把条目序列化成
//! **扁平的 `answers` 数组**（`{value,ttl,type,name}`，name 为 Option；顺序保持），
//! 反序列化时按「相邻 `(name, rtype)`」重新分组并 intern。因此快照/WAL 的 JSON
//! 字节契约、二进制 `entry_codec` 的记录格式、旧 v2 文件的恢复能力**全部不变**。

use crate::entry::CacheAnswer;
use parking_lot::Mutex;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, OnceLock, Weak};

/// RRset 弱引用表项数上限（**有界**：到顶先 sweep，仍满则拒绝登记新 RRset）。
pub const MAX_INTERNED: usize = 65_536;

/// **阶段 B-1**：字符串（`value` / `name` / `owner`）intern 表项数上限。
///
/// 与 RRset 表 [`MAX_INTERNED`] **分开计数**：`value` 的基数通常远大于 RRset
/// （每条答案是独立字符串），但共享收益也最大（同一条 A 记录会出现在成千上万个
/// 不同域名/消息里）。65,536 条活字符串 ≈ 2~4 MiB 级上限，仍属"有界优先"。
pub const MAX_INTERNED_STR: usize = 65_536;

/// **阶段 B-2**：一个 RRset 对象（owner + 类型 + 取值集合）。
///
/// * `owner`：owner name（CNAME 链逐跳 owner；空串 = **查询名**，对应
///   `CacheAnswer.name = None`）。
/// * `rtype`：记录类型。同一 RRset 内所有 `CacheAnswer.rtype` 必然相同。
/// * `values`：取值集合（`ttl` 在 [`CacheAnswer`] 内）。取值顺序来自**首次**
///   intern 的那条消息；DNS 语义里 RRset 内顺序无序。
///
/// 本类型**只由** [`intern_rrset`] 构造（字段 public 是为了让组装端直接读，
/// 但调用方不应手工 `Arc::new(Rrset{..})`，否则会绕过共享表）。
#[derive(Debug)]
pub struct Rrset {
    pub owner: Arc<str>,
    pub rtype: u16,
    pub values: Vec<Arc<CacheAnswer>>,
}

impl Rrset {
    /// owner name；空串（= 查询名）返回 `None`（与 `CacheAnswer.name` 的 `Option` 对齐）。
    pub fn owner_name(&self) -> Option<&str> {
        if self.owner.is_empty() {
            None
        } else {
            Some(&self.owner)
        }
    }

    /// 取值条数。
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// 是否没有取值（正常分组不会产生空 RRset；仅供完备性判断）。
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// RRset intern 表本体：哈希 → 弱引用（+ 命中计数）。
struct Table {
    map: HashMap<u64, Weak<Rrset>>,
    /// 复用命中次数（`weak.upgrade()` 成功**且** owner/rtype/取值多重集相等）。
    hits: u64,
}

impl Table {
    /// 查表：哈希命中 + 弱引用仍活 + owner/rtype/取值多重集相等 ⇒ 复用并计数。
    fn lookup(
        &mut self,
        h: u64,
        owner: &str,
        rtype: u16,
        values: &[Arc<CacheAnswer>],
    ) -> Option<Arc<Rrset>> {
        let arc = self.map.get(&h)?.upgrade()?;
        if &*arc.owner == owner && arc.rtype == rtype && multiset_eq(&arc.values, values) {
            self.hits += 1;
            Some(arc)
        } else {
            None
        }
    }

    /// 回收死弱引用，返回移除的表项数。
    fn sweep_dead(&mut self) -> usize {
        let before = self.map.len();
        self.map.retain(|_, w| w.strong_count() > 0);
        before - self.map.len()
    }
}

/// 全局 RRset 表（`OnceLock` 惰性初始化：不引入构造顺序问题，测试/生产同一路径）。
fn table() -> &'static Mutex<Table> {
    static TABLE: OnceLock<Mutex<Table>> = OnceLock::new();
    TABLE.get_or_init(|| {
        Mutex::new(Table {
            map: HashMap::new(),
            hits: 0,
        })
    })
}

/// 单条取值的哈希（`value` / `name` / `ttl` 位模式 / `rtype`）。
fn hash_answer(a: &CacheAnswer) -> u64 {
    let mut h = DefaultHasher::new();
    a.value.hash(&mut h);
    a.name.hash(&mut h);
    // f64 没有 Hash：用位模式（`-0.0`/`0.0` 因此哈希不同，但相等性判定仍按
    // `PartialEq`，所以只影响"能否命中"，不影响正确性）。
    a.ttl.to_bits().hash(&mut h);
    a.rtype.hash(&mut h);
    h.finish()
}

/// RRset 的**顺序不敏感**哈希：owner/rtype/条数 + 逐值哈希的可交换组合
/// （`wrapping_add` 对顺序不敏感；旋转只为打散相近取值）。
fn hash_rrset(owner: &str, rtype: u16, values: &[Arc<CacheAnswer>]) -> u64 {
    let mut h = DefaultHasher::new();
    owner.hash(&mut h);
    rtype.hash(&mut h);
    values.len().hash(&mut h);
    let mut acc = h.finish();
    for a in values {
        acc = acc.wrapping_add(hash_answer(a).rotate_left(23));
    }
    acc
}

/// 两条取值是否**逐字段**相等（`ttl` 用 `PartialEq`，与阶段 A/B-1 同口径）。
fn answers_equal(a: &CacheAnswer, b: &CacheAnswer) -> bool {
    a.rtype == b.rtype && a.value == b.value && a.name == b.name && a.ttl == b.ttl
}

/// 多重集比对（顺序不敏感）：≤64 条时用位掩码 + O(n²) 匹配（**0 分配**，
/// 典型 RRset 只有 1~8 条）；更多时退化为排序比对（分配两个索引/引用 Vec，
/// 只在超大 RRset 上发生）。
fn multiset_eq(a: &[Arc<CacheAnswer>], b: &[Arc<CacheAnswer>]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    if a.len() > 64 {
        let mut ia: Vec<&CacheAnswer> = a.iter().map(|x| &**x).collect();
        let mut ib: Vec<&CacheAnswer> = b.iter().map(|x| &**x).collect();
        ia.sort_unstable_by(|x, y| answer_cmp(x, y));
        ib.sort_unstable_by(|x, y| answer_cmp(x, y));
        return ia == ib;
    }
    let mut used = 0u64;
    for x in a {
        let mut found = None;
        for (j, y) in b.iter().enumerate() {
            if used & (1u64 << j) == 0 && answers_equal(x, y) {
                found = Some(j);
                break;
            }
        }
        match found {
            Some(j) => used |= 1u64 << j,
            None => return false,
        }
    }
    true
}

/// 排序比对键（只在 >64 条的大 RRset 上使用）：value → ttl → name → rtype。
fn answer_cmp(a: &CacheAnswer, b: &CacheAnswer) -> std::cmp::Ordering {
    a.value
        .as_ref()
        .cmp(b.value.as_ref())
        .then_with(|| a.ttl.to_bits().cmp(&b.ttl.to_bits()))
        .then_with(|| a.name.as_deref().cmp(&b.name.as_deref()))
        .then_with(|| a.rtype.cmp(&b.rtype))
}

/// 空 owner（= 查询名）的共享句柄：避免每个 RRset 各自为 `""` 分配一份 `Arc<str>`。
fn empty_owner() -> Arc<str> {
    static EMPTY: OnceLock<Arc<str>> = OnceLock::new();
    Arc::clone(EMPTY.get_or_init(|| Arc::from("")))
}

/// 把 RRset 的取值逐个换成字符串表里的规范句柄；**任何一个没变就不重建 Vec**。
///
/// 与阶段 B-1 的字符串归一逻辑同口径：表满时 [`intern_value`] 返回 `None`
/// ⇒ 保留原句柄（有界优先，不制造"每次写入都重建"的抖动）。
fn canonical_values(values: &[Arc<CacheAnswer>]) -> Vec<Arc<CacheAnswer>> {
    let mut rebuilt: Option<Vec<Arc<CacheAnswer>>> = None;
    for (i, a) in values.iter().enumerate() {
        let new_value = intern_value(&a.value).filter(|v| !Arc::ptr_eq(v, &a.value));
        let new_name = a
            .name
            .as_ref()
            .and_then(|cur| intern_value(cur).filter(|v| !Arc::ptr_eq(v, cur)));
        if new_value.is_none() && new_name.is_none() {
            continue;
        }
        let out = rebuilt.get_or_insert_with(|| values.to_vec());
        let cur = Arc::clone(&out[i]);
        let value = match new_value {
            Some(v) => v,
            None => Arc::clone(&cur.value),
        };
        let name = match new_name {
            Some(n) => Some(n),
            None => cur.name.clone(),
        };
        out[i] = Arc::new(CacheAnswer {
            value,
            ttl: cur.ttl,
            rtype: cur.rtype,
            name,
        });
    }
    rebuilt.unwrap_or_else(|| values.to_vec())
}

/// **阶段 B-2 写入路径唯一入口**：取（必要时新建）RRset 的共享句柄。
///
/// * **快路径**：RRset 表命中（owner/rtype/取值多重集都相等）⇒ 直接返回同一
///   `Arc`，**不碰字符串表、不分配**；
/// * **慢路径**：先把 `value`/`name` 归一成字符串表的规范句柄（锁外分配），
///   再拿 RRset 表锁插入（check-insert，保证并发下只有 1 个存活实例）；
/// * **表满且全活** ⇒ 返回未登记的独立实例（有界优先；内容正确，只是本次不共享）。
pub fn intern_rrset(owner: &str, rtype: u16, values: &[Arc<CacheAnswer>]) -> Arc<Rrset> {
    let h = hash_rrset(owner, rtype, values);
    // 快路径：命中 ⇒ 直接返回（锁内不分配、不碰字符串表）。
    {
        let mut t = table().lock();
        if let Some(arc) = t.lookup(h, owner, rtype, values) {
            return arc;
        }
    }
    // 慢路径：**锁外**做字符串归一与 RRset 分配（临界区只做 map 操作）。
    let owner_arc = if owner.is_empty() {
        empty_owner()
    } else {
        intern_value(owner).unwrap_or_else(|| Arc::from(owner))
    };
    let vals = canonical_values(values);
    let fresh = Arc::new(Rrset {
        owner: owner_arc,
        rtype,
        values: vals,
    });
    let mut t = table().lock();
    // 再查一次：并发下别的线程可能刚登记了同一内容 ⇒ 复用它（保证唯一存活实例）。
    if let Some(arc) = t.lookup(h, owner, rtype, values) {
        return arc;
    }
    if t.map.len() >= MAX_INTERNED {
        t.sweep_dead();
        if t.map.len() >= MAX_INTERNED {
            // 表项全活（真有 MAX_INTERNED 个不同 RRset 在线）：**有界优先**，不登记。
            return fresh;
        }
    }
    t.map.insert(h, Arc::downgrade(&fresh));
    fresh
}

/// **阶段 B-2**：把一个条目的 RRset 列表就地归一到共享表。
///
/// * 已规范的 RRset 命中快路径 ⇒ **同一个 `Arc` 原样保留**，整条消息 0 次分配；
/// * 未登记的 RRset 被换成表里的规范实例（未命中则登记新实例）。
///
/// 这是 `LruCache::{put, restore, restore_records}` 的唯一调用点。
pub fn intern_rrsets(rrsets: &mut [Arc<Rrset>]) {
    for rs in rrsets.iter_mut() {
        let canonical = intern_rrset(rs.owner.as_ref(), rs.rtype, &rs.values);
        if !Arc::ptr_eq(rs, &canonical) {
            *rs = canonical;
        }
    }
}

/// **阶段 B-2**：把扁平答案列表按「相邻 `(name, rtype)`」分组并 intern 成 RRset 列表。
///
/// 这是**冷路径**（JSON/二进制恢复、测试构造）：会为每组分配一个 `Vec`，并走
/// [`intern_rrset`] 的登记逻辑。生产热路径只消费已经分好组的 `CacheEntry.rrsets`。
///
/// 相邻分组的语义与持久化的扁平 `answers` 顺序**一一对应**：展平
/// （[`crate::CacheEntry::flat_answers`]）后顺序、owner、TTL 逐字段不变。
pub fn rrsets_from_flat(answers: &[CacheAnswer]) -> Vec<Arc<Rrset>> {
    let mut out: Vec<Arc<Rrset>> = Vec::new();
    let mut i = 0usize;
    while i < answers.len() {
        let name = answers[i].name.clone();
        let rtype = answers[i].rtype;
        let start = i;
        i += 1;
        while i < answers.len() && answers[i].rtype == rtype && answers[i].name == name {
            i += 1;
        }
        let values: Vec<Arc<CacheAnswer>> =
            answers[start..i].iter().cloned().map(Arc::new).collect();
        out.push(intern_rrset(name.as_deref().unwrap_or(""), rtype, &values));
    }
    out
}

/// `(RRset interned 表项数, 复用命中次数)`。
///
/// `interned` = 弱引用表**当前表项数**（含尚未被 [`sweep`] 回收的死引用；正常写入
/// 路径下死引用只增不减到下一次 sweep，数量上界即 [`MAX_INTERNED`]）；
/// `hits` = 自进程启动（或 [`reset_stats`]）以来"命中并复用"的次数。
pub fn stats() -> (usize, usize) {
    let t = table().lock();
    (t.map.len(), t.hits as usize)
}

/// 回收死弱引用（条目已全部释放的表项），返回移除条数。
///
/// 写入路径在**表满时**自动调用；本函数额外导出给诊断/测试用（`/api/cache/stats`
/// 的 `rrset_interned` 因此可以自证"drop 之后表项真的会被清掉"）。
pub fn sweep() -> usize {
    let mut t = table().lock();
    t.sweep_dead()
}

/// 清零 RRset 命中计数（**测试用**）。
///
/// **不清空表**：清表会让"同一 RRset 全进程只有一份存活实例"的既有保证在并发测试
/// 里瞬间失效（A 用例刚 intern 的内容被 B 用例清掉 ⇒ A 再 intern 得到新实例 ⇒
/// 假失败）。需要回收死引用请用 [`sweep`]。
pub fn reset_stats() {
    let mut t = table().lock();
    t.hits = 0;
}

// ============================ 阶段 B-1：字符串 intern ============================

/// 字符串表本体：`str` 的 64-bit 哈希 → 弱引用（+ 命中计数）。
///
/// 与 RRset 表 [`Table`]**完全独立**（各一把锁、各自的上限/计数）：字符串的生命周期
/// 比 RRset 更细粒度（一条答案一个），且写路径对字符串的调用次数更多（每条答案
/// 1~2 次），分开可以把两把锁的争用与容量语义解耦。
struct StrTable {
    map: HashMap<u64, Weak<str>>,
    /// 复用命中次数（`weak.upgrade()` 成功**且**内容相等）。
    hits: u64,
}

impl StrTable {
    /// 查表：哈希命中 + 弱引用仍活 + 内容相等 ⇒ 复用并计数；否则 `None`。
    fn lookup(&mut self, h: u64, s: &str) -> Option<Arc<str>> {
        let arc = self.map.get(&h)?.upgrade()?;
        if &*arc == s {
            self.hits += 1;
            Some(arc)
        } else {
            None
        }
    }

    /// 回收死弱引用，返回移除的表项数。
    fn sweep_dead(&mut self) -> usize {
        let before = self.map.len();
        self.map.retain(|_, w| w.strong_count() > 0);
        before - self.map.len()
    }
}

/// 全局字符串表（`OnceLock` 惰性初始化，测试/生产同一路径）。
fn str_table() -> &'static Mutex<StrTable> {
    static TABLE: OnceLock<Mutex<StrTable>> = OnceLock::new();
    TABLE.get_or_init(|| {
        Mutex::new(StrTable {
            map: HashMap::new(),
            hits: 0,
        })
    })
}

/// 字符串的稳定哈希（与 RRset 哈希共用 `DefaultHasher`，进程内确定性）。
fn hash_str_value(s: &str) -> u64 {
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

/// 命中或**新登记**时返回表里的规范句柄；表满且全活时返回 `None`。
///
/// `None` 的语义刻意区分于"返回一个新 `Arc`"：调用方据此**保留原句柄**（不重建
/// 数据），避免表满时每次写入都重新分配；面向外部的 [`intern_str`] 则回退到
/// 独立 `Arc`（语义仍正确，只是不共享）。
fn intern_value(s: &str) -> Option<Arc<str>> {
    let h = hash_str_value(s);
    // 快路径：命中 ⇒ 直接返回（锁内不分配）。
    {
        let mut t = str_table().lock();
        if let Some(arc) = t.lookup(h, s) {
            return Some(arc);
        }
    }
    // 慢路径：**锁外**分配，拿锁后再查一次（并发下别的线程可能刚登记同一内容）。
    let fresh: Arc<str> = Arc::from(s);
    let mut t = str_table().lock();
    if let Some(arc) = t.lookup(h, s) {
        return Some(arc);
    }
    if t.map.len() >= MAX_INTERNED_STR {
        t.sweep_dead();
        if t.map.len() >= MAX_INTERNED_STR {
            // 表项全活：**有界优先**，不登记（调用方回退到独立实例/保留原句柄）。
            return None;
        }
    }
    t.map.insert(h, Arc::downgrade(&fresh));
    Some(fresh)
}

/// **阶段 B-1**：把 RDATA / owner 展示串 intern 成全进程内容唯一的 `Arc<str>`。
///
/// * 命中（表里已有内容相等的活字符串）⇒ 返回同一份分配（`Arc::ptr_eq` 为真）；
/// * 未命中 ⇒ 登记后返回新句柄；
/// * 表满且全活 ⇒ 返回一个**未登记**的独立 `Arc<str>`（有界优先；内容正确，只是
///   本次不参与共享，下一次 sweep 后可再登记）。
pub fn intern_str(s: &str) -> Arc<str> {
    intern_value(s).unwrap_or_else(|| Arc::from(s))
}

/// **阶段 B-1**：[`intern_str`] 的 `Option` 版本（`None` 原样保留）。
///
/// `name` 在旧持久化 JSON 里缺省为 `None`；这个包装让调用点保持"空就是空"的语义，
/// 不会为了 intern 把 `None` 变成 `Some("")`。
pub fn intern_opt_str(name: Option<&str>) -> Option<Arc<str>> {
    name.map(intern_str)
}

/// **阶段 B-1**：`(字符串 interned 表项数, 复用命中次数)`。
///
/// 口径与 [`stats`] 相同：`interned` 是**当前表项数**（含等待 sweep 的死引用，上界
/// [`MAX_INTERNED_STR`]）；`hits` 是自进程启动（或 [`reset_str_stats`]）以来"命中
/// 并复用"的次数。`/api/cache/stats` 的 `rrset_str_interned` / `rrset_str_hits` 即此。
pub fn stats_str() -> (usize, usize) {
    let t = str_table().lock();
    (t.map.len(), t.hits as usize)
}

/// **阶段 B-1**：回收字符串表的死弱引用，返回移除条数（诊断/测试用）。
pub fn sweep_str() -> usize {
    let mut t = str_table().lock();
    t.sweep_dead()
}

/// **阶段 B-1**：清零字符串表的命中计数（**测试用**；不清表，理由同 [`reset_stats`]）。
pub fn reset_str_stats() {
    let mut t = str_table().lock();
    t.hits = 0;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Barrier;

    fn ans(value: &str, ttl: f64, rtype: u16, name: Option<&str>) -> CacheAnswer {
        CacheAnswer::new(value, ttl, rtype, name.map(Arc::from))
    }

    fn arc_ans(value: &str, ttl: f64, rtype: u16, name: Option<&str>) -> Arc<CacheAnswer> {
        Arc::new(ans(value, ttl, rtype, name))
    }

    /// 进程内唯一内容：避免与**并行执行的其他用例**（lru/s3fifo/persist 的写入路径
    /// 也会 intern）共享到同一表项，从而让"只有一份实例""可被 sweep 回收"这类断言
    /// 在不同用例之间互不干扰。
    fn uniq(tag: &str) -> String {
        static N: AtomicU64 = AtomicU64::new(0);
        format!(
            "{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        )
    }

    /// 相同 RRset（owner/rtype/取值都相同）两次 intern 必须返回**同一个** `Arc`。
    #[test]
    fn same_rrset_shares_one_arc() {
        let u = uniq("same");
        let owner = format!("{u}.cdn.example");
        let vals = vec![
            arc_ans(&format!("{u}-a"), 60.0, 1, Some(&owner)),
            arc_ans(&format!("{u}-b"), 60.0, 1, Some(&owner)),
        ];
        let x = intern_rrset(&owner, 1, &vals);
        let y = intern_rrset(&owner, 1, &vals);
        assert!(
            Arc::ptr_eq(&x, &y),
            "相同 RRset 必须复用同一个 Arc（实测两份不同实例）"
        );
        assert_eq!(x.owner.as_ref(), owner.as_str());
        assert_eq!(x.values.len(), 2);
    }

    /// **B-2 关键语义**：取值**顺序不同**也共享（RRset 内顺序无序，键用排序签名）。
    #[test]
    fn rrset_sharing_is_order_insensitive() {
        let u = uniq("order");
        let owner = format!("{u}.cdn.example");
        let a = arc_ans(&format!("{u}-a"), 60.0, 1, Some(&owner));
        let b = arc_ans(&format!("{u}-b"), 60.0, 1, Some(&owner));
        let x = intern_rrset(&owner, 1, &[a.clone(), b.clone()]);
        let y = intern_rrset(&owner, 1, &[b, a]);
        assert!(Arc::ptr_eq(&x, &y), "同一 RRset 的不同取值顺序必须共享");
    }

    /// owner / rtype / TTL / 条数任一不同 ⇒ **不得**共享（否则会串记录）。
    #[test]
    fn different_owner_rtype_ttl_or_len_is_not_shared() {
        let u = uniq("diff");
        let owner = format!("{u}.cdn.example");
        let other = format!("{u}.other.example");
        let base = vec![
            arc_ans(&format!("{u}-a"), 60.0, 1, Some(&owner)),
            arc_ans(&format!("{u}-b"), 60.0, 1, Some(&owner)),
        ];
        let x = intern_rrset(&owner, 1, &base);

        assert!(
            !Arc::ptr_eq(&x, &intern_rrset(&other, 1, &base)),
            "owner 不同不得共享"
        );
        assert!(
            !Arc::ptr_eq(&x, &intern_rrset(&owner, 28, &base)),
            "rtype 不同不得共享"
        );
        let mut diff_ttl = base.clone();
        diff_ttl[0] = arc_ans(&format!("{u}-a"), 61.0, 1, Some(&owner));
        assert!(
            !Arc::ptr_eq(&x, &intern_rrset(&owner, 1, &diff_ttl)),
            "TTL 不同不得共享"
        );
        let shorter = vec![base[0].clone()];
        assert!(
            !Arc::ptr_eq(&x, &intern_rrset(&owner, 1, &shorter)),
            "条数不同不得共享"
        );
    }

    /// **B-2 分组**：相邻 `(name, rtype)` 分组、扁平化后逐字段/顺序不变。
    #[test]
    fn flat_group_roundtrip_preserves_order_and_fields() {
        let u = uniq("group");
        let cname_owner = format!("{u}.example");
        let flat = vec![
            ans(&format!("{u}-cdn.example"), 300.0, 5, None),
            ans(&format!("{u}-edge.example"), 300.0, 5, Some(&cname_owner)),
            ans(
                &format!("{u}-a1"),
                300.0,
                1,
                Some(&format!("{u}-edge.example")),
            ),
            ans(
                &format!("{u}-a2"),
                301.0,
                1,
                Some(&format!("{u}-edge.example")),
            ),
        ];
        let rrsets = rrsets_from_flat(&flat);
        assert_eq!(rrsets.len(), 3, "相邻 (name,rtype) 分组必须得到 3 个 RRset");
        assert!(rrsets[0].owner.is_empty(), "name=None 的 owner 必须存空串");
        assert_eq!(rrsets[0].rtype, 5);
        assert_eq!(rrsets[2].values.len(), 2);
        let back: Vec<CacheAnswer> = rrsets
            .iter()
            .flat_map(|rs| rs.values.iter().map(|a| a.as_ref().clone()))
            .collect();
        assert_eq!(back, flat, "分组→展平必须逐字段、逐顺序不变");
    }

    /// 弱引用语义：条目释放后表里只剩死引用（`upgrade()` 失败），可被 sweep 回收。
    #[test]
    fn dead_weak_entry_is_sweepable() {
        let u = uniq("weak");
        let vals = vec![arc_ans(&u, 60.0, 1, None)];
        let weak = {
            let arc = intern_rrset("", 1, &vals);
            let weak = Arc::downgrade(&arc);
            assert_eq!(weak.strong_count(), 1, "仅本用例持有强引用");
            drop(arc);
            weak
        };
        // 强引用已全部释放 ⇒ 表项是死引用（`upgrade()` 必须失败）。
        assert!(weak.upgrade().is_none(), "drop 之后不得再能从表中取到实例");
        let removed = sweep();
        assert!(
            removed >= 1,
            "sweep 必须能回收死弱引用（removed={removed}）"
        );
        // 回收后再 intern 同一内容 ⇒ 得到**新**实例（旧实例已不存在）。
        let fresh = intern_rrset("", 1, &vals);
        assert_eq!(fresh.values.len(), 1);
    }

    /// 并发：8 线程同时 intern 相同 RRset ⇒ 只有 **1 个**存活实例。
    #[test]
    fn concurrent_intern_yields_single_live_instance() {
        let u = uniq("conc");
        let vals: Vec<Arc<CacheAnswer>> = (0..4)
            .map(|i| arc_ans(&format!("{u}-{i}"), 60.0, 1, None))
            .collect();
        let vals = Arc::new(vals);
        let n = 8usize;
        let barrier = Arc::new(Barrier::new(n));
        let mut handles = Vec::with_capacity(n);
        for _ in 0..n {
            let vals = Arc::clone(&vals);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait(); // 尽量让 8 个线程同时进入 intern（放大竞争窗口）
                intern_rrset("", 1, &vals)
            }));
        }
        let arcs: Vec<Arc<Rrset>> = handles
            .into_iter()
            .map(|h| h.join().expect("intern 线程不得 panic"))
            .collect();
        let first = &arcs[0];
        let distinct = arcs.iter().filter(|a| !Arc::ptr_eq(a, first)).count();
        assert_eq!(
            distinct, 0,
            "8 线程 intern 相同 RRset 必须只有 1 个存活实例（实测 {distinct} 个不同实例）"
        );
        // 8 个返回值都指向同一分配：强引用数恰为 8（表里只有弱引用，不计数）。
        assert_eq!(Arc::strong_count(first), n, "所有返回值必须指向同一分配");
    }

    /// 写路径幂等：对已经规范的 RRset 再走一次 [`intern_rrsets`] ⇒ 同一个 `Arc`，
    /// 且 `Vec` 不被重建（0 次分配是 `put` 热路径的前提）。
    #[test]
    fn intern_rrsets_is_idempotent_for_canonical_set() {
        let u = uniq("idem");
        let mut rrsets = rrsets_from_flat(&[
            ans(&u, 60.0, 1, None),
            ans(&u, 61.0, 1, None), // 同 (name,rtype) 相邻 ⇒ 同一 RRset
        ]);
        assert_eq!(
            rrsets.len(),
            1,
            "同 owner/rtype 的相邻答案必须合成 1 个 RRset"
        );
        let first = Arc::clone(&rrsets[0]);
        intern_rrsets(&mut rrsets);
        assert!(
            Arc::ptr_eq(&first, &rrsets[0]),
            "已规范的 RRset 再次写入必须命中同一份（0 次堆分配/不重建）"
        );
    }

    // ---------------- 阶段 B-1：字符串 intern 单测 ----------------

    /// 相同 `&str` 两次 intern ⇒ 同一个 `Arc<str>`（内容级去重）。
    #[test]
    fn same_string_is_interned_once() {
        let u = uniq("str-same");
        let a = intern_str(&u);
        let b = intern_str(&u);
        assert!(Arc::ptr_eq(&a, &b), "相同字符串必须复用同一 Arc<str>");
        assert_eq!(&*a, u.as_str());
        assert_eq!(
            Arc::strong_count(&a),
            2,
            "a/b 两个强引用；表里只有弱引用，不计数"
        );
    }

    /// 不同内容不得共享；`None` 必须保持 `None`（不得变成 `Some("")`）。
    #[test]
    fn different_strings_and_none_are_not_shared() {
        let x = uniq("str-x");
        let y = uniq("str-y");
        let a = intern_str(&x);
        let b = intern_str(&y);
        assert!(!Arc::ptr_eq(&a, &b), "不同字符串不得共享");
        assert!(intern_opt_str(None).is_none(), "None 必须原样保留");
        let c = intern_opt_str(Some(&x)).expect("Some 输入必须返回 Some");
        assert!(
            Arc::ptr_eq(&a, &c),
            "intern_opt_str(Some) 必须与 intern_str 命中同一份"
        );
    }

    /// 字符串弱引用：强引用全部释放后可被 [`sweep_str`] 回收（表不延长寿命）。
    #[test]
    fn dropped_string_is_sweepable() {
        let u = uniq("str-sweep");
        let weak = {
            let arc = intern_str(&u);
            let weak = Arc::downgrade(&arc);
            assert_eq!(weak.strong_count(), 1, "仅本用例持有强引用");
            drop(arc);
            weak
        };
        assert!(weak.upgrade().is_none(), "drop 之后不得再能从表中取到实例");
        let removed = sweep_str();
        assert!(
            removed >= 1,
            "sweep_str 必须能回收死弱引用（removed={removed}）"
        );
        // 回收后再 intern 同一内容 ⇒ 新实例（旧实例已不存在）。
        let fresh = intern_str(&u);
        assert_eq!(&*fresh, u.as_str());
    }

    /// [`intern_rrset`]：RRset 不同（TTL 不同）但 value/name 相同 ⇒ 字符串共享、
    /// RRset **不**共享（隔离出"字符串级"去重，证明它不是被 RRset 共享顺带做到的）。
    #[test]
    fn intern_rrset_shares_strings_across_distinct_rrsets() {
        let u = uniq("str-set");
        let name = format!("{u}.owner");
        let a = intern_rrset(&name, 1, &[arc_ans(&u, 60.0, 1, Some(&name))]);
        let b = intern_rrset(&name, 1, &[arc_ans(&u, 61.0, 1, Some(&name))]);
        assert!(
            !Arc::ptr_eq(&a, &b),
            "TTL 不同 ⇒ RRset 不得共享（RRset 的判据是 owner/rtype/取值集合）"
        );
        assert!(
            Arc::ptr_eq(&a.values[0].value, &b.values[0].value),
            "相同 RDATA 字符串必须跨 RRset 共享同一份 Arc<str>"
        );
        assert!(
            Arc::ptr_eq(
                a.values[0].name.as_ref().unwrap(),
                b.values[0].name.as_ref().unwrap()
            ),
            "相同 owner 名必须跨 RRset 共享同一份 Arc<str>"
        );
        assert!(
            Arc::ptr_eq(&a.owner, &intern_str(&name)),
            "RRset.owner 也必须指向字符串表的规范句柄"
        );
    }
}
