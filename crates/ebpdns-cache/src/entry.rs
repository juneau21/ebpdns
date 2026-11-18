//! **[历史归因]** 缓存键与条目类型，忠实对齐 Python `cache.py` 的 dict 结构。
//!
//! **[历史归因]** Python 缓存键为元组：运行期是 `(domain_lower, qtype)` 或
//! `(group, domain, qtype)`（后者来自已移除的 `partitioned` 策略）。这里用一个带可选
//! `group` 的结构统一表示，`group=None` 表示 LRU 二元组。

use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};
use std::sync::Arc;

/// **[历史归因]** 统一缓存键。`group` 为 `None` 时对应 Python 二元组 `(domain, qtype)`；
/// 为 `Some(g)` 时对应三元组 `(group, domain, qtype)`。
///
/// # **阶段 3-14：缓存键变体**
///
/// `dnssec` 是**向后兼容**追加的变体位（`DO` 位）：
/// * `false`（默认，也是**旧键**的语义）⇒ 键数组仍是 **2/3 元素**，落盘字节与旧版
///   **逐字节相同**（`to_key_array()` 不追加任何元素，二进制 key 编码的 `qtype_len`
///   高位为 0）⇒ 旧快照/WAL/JSON 缓存文件照旧可恢复，且恢复为 `dnssec=false`；
/// * `true` ⇒ 键数组追加一个字面量 `"DO"`（2/3+1 元素），二进制 key 编码把
///   `qtype_len` 的 **bit15** 置 1。
///
/// 为什么需要它：带 EDNS DO 位的查询与不带 DO 的查询在上游可能拿到**不同的
/// answer section**（RRSIG 的有无/内容不同），共用一个缓存条目会把 DNSSEC 记录
/// 串给非 DNSSEC 客户端（反之亦然）。因此两者必须是**不同的键**。
///
/// `Hash` / `Eq` / `Ord` 都包含本字段（`Eq`/`Ord` 由 derive 覆盖，`Hash` 手写补上），
/// 否则 `HashMap`/`OrderedMap` 会把两条变体键当成同一键（"不串条目"就失效了）。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CacheKey {
    pub group: Option<String>,
    pub domain: String,
    pub qtype: String,
    /// **阶段 3-14**：DNSSEC（EDNS `DO` 位）变体。`false` = 非 DNSSEC 键（旧键形态）。
    pub dnssec: bool,
}

impl CacheKey {
    /// 二元组键 `(domain, qtype)`（LRU 默认形态；`dnssec=false`）。
    pub fn new(domain: impl Into<String>, qtype: impl Into<String>) -> Self {
        Self {
            group: None,
            domain: domain.into(),
            qtype: qtype.into(),
            dnssec: false,
        }
    }

    /// 三元组键 `(group, domain, qtype)`（带 group 维度的历史/落盘形态）。
    pub fn with_group(
        group: impl Into<String>,
        domain: impl Into<String>,
        qtype: impl Into<String>,
    ) -> Self {
        Self {
            group: Some(group.into()),
            domain: domain.into(),
            qtype: qtype.into(),
            dnssec: false,
        }
    }

    /// **阶段 3-14**：就地设置 DNSSEC 变体位（链式，便于 `ckey` → 变体一处构造）。
    pub fn with_dnssec(mut self, dnssec: bool) -> Self {
        self.dnssec = dnssec;
        self
    }

    /// **[历史归因]** 序列化为 Python 同款 key 数组（2 或 3 元素）。
    ///
    /// **阶段 3-14**：`dnssec=true` 时**追加**一个 `"DO"` 元素（2/3 + 1）；`false` 时
    /// 输出与旧版逐字节相同（旧文件可恢复、新文件可被旧版读取）。
    pub fn to_key_array(&self) -> Vec<String> {
        let mut out = match &self.group {
            Some(g) => vec![g.clone(), self.domain.clone(), self.qtype.clone()],
            None => vec![self.domain.clone(), self.qtype.clone()],
        };
        if self.dnssec {
            out.push(KEY_ARRAY_DNSSEC_TAG.to_string());
        }
        out
    }
}

/// **阶段 3-14**：键数组里的 DNSSEC 变体标记（仅在 `dnssec=true` 时追加）。
pub const KEY_ARRAY_DNSSEC_TAG: &str = "DO";

impl Hash for CacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // group 可能是 None（LRU/S3FIFO）或 Some（带分区的落盘键）。统一参与哈希，
        // **[历史归因]** 与 Python 对元组整体取 hash 的语义一致。
        self.group.hash(state);
        self.domain.hash(state);
        self.qtype.hash(state);
        // **阶段 3-14**：变体位**只在 `true` 时**参与哈希。
        //
        // 为什么是条件式而不是无条件 `self.dnssec.hash(state)`：判据是
        // 「**相等 ⇒ 同哈希**」（`Eq` 负责区分），而非「不等 ⇒ 必不同哈希」。
        // 条件式让**非 DO 键（= 旧键形态）的 `hash_key` 与旧版逐位相同** ——
        // 分片路由（`hash_key & (SHARDS-1)`）与 `freq`/`hot` 表的落位对既有部署
        // 零变化（真正意义上的"向后兼容"：不只字节兼容，连分片分布也兼容）。
        // 无条件多写一个字节会让所有既有键重新分片，属不必要的扰动
        // （既有用例 `c07_get_arc_keeps_lru_and_s3fifo_semantics` 就是被这种
        //   重新分片撞红的：16 条键在 8 分片里多出一条碰撞即触发淘汰）。
        if self.dnssec {
            true.hash(state);
        }
    }
}

/// **[历史归因]** 单条答案，对齐 Python answer dict `{value, ttl, type, name?}`。
///
/// **阶段 B-1（RRset 数据去重）**：`value` / `name` 由 `String` 改为 `Arc<str>`。
///
/// * **为什么**：同一段 RDATA（典型：`A 1.2.3.4`）会出现在大量不同 `(domain, qtype)`
///   条目、以及同一 CNAME 链的不同答案集里；`String` 形态下每条都是一份独立的堆分配。
///   改成 `Arc<str>` 并在**写入路径**经 [`crate::rrset::intern_str`] 归一后，相同内容
///   全进程只保留一份分配，其余只是引用计数自增。
/// * **JSON 契约不变**：serde 的 `rc` feature 让 `Arc<str>` 与 `String` 都序列化成
///   JSON **字符串**（`"value": "1.2.3.4"`），反序列化也接受字符串 ⇒ 快照/WAL/
///   二进制 `entry_codec` 的字节契约、旧文件兼容性都**完全不变**（v2 格式不变）。
/// * **相等/哈希语义不变**：`Arc<str>` 的 `PartialEq`/`Hash` 委托给 `str` 内容比较，
///   `CacheAnswer` 的逐字段相等（答案集 intern 的命中判定）与旧实现同口径。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CacheAnswer {
    /// RDATA 展示串（A/AAAA 的点分/冒号形式、TXT 的引号形式等），写入路径会
    /// intern 成**内容唯一的共享句柄**。读取处按 `&str` 用即可（`&*a.value` /
    /// `a.value.as_ref()`）；需要 `String` 时显式 `.to_string()`。
    pub value: Arc<str>,
    pub ttl: f64,
    #[serde(rename = "type")]
    pub rtype: u16,
    /// 答案 owner 名（CNAME 链上逐跳 owner）；旧持久化 JSON 无此字段时反序列化为 None。
    /// **阶段 B-1** 起与 `value` 同口径 intern（相同 owner 名只保留一份分配）。
    #[serde(default)]
    pub name: Option<Arc<str>>,
}

impl CacheAnswer {
    /// **阶段 B-1**：构造一条答案；`value`/`name` 接受 `&str` / `String` / `Arc<str>`
    /// （`impl Into<Arc<str>>`），调用方不必关心底层是独立字符串还是共享句柄。
    ///
    /// **本构造器不查 intern 表** —— 去重统一发生在写入缓存时
    /// （[`crate::rrset::intern_rrset`]），因此测试可以刻意构造"内容相同但
    /// 指针不同"的输入，用来验证共享确实由写路径建立，而不是构造期偷跑。
    pub fn new(value: impl Into<Arc<str>>, ttl: f64, rtype: u16, name: Option<Arc<str>>) -> Self {
        Self {
            value: value.into(),
            ttl,
            rtype,
            name,
        }
    }
}

/// **[历史归因]** 缓存条目，对齐 Python entry dict：
/// `{domain, qtype, answers, chosen, ttl, rcode, expires_at}`。
///
/// **[历史归因]** `expires_at` 为 epoch 秒（浮点），与 Python `time.time()` 同口径。
///
/// **阶段 B-2（RRset 对象级缓存）**：`answers: Arc<Vec<CacheAnswer>>` 被替换为
/// `rrsets: Vec<Arc<Rrset>>` —— 同一 RRset（owner + 类型 + 取值集合）跨消息共享
/// 同一份 `Arc<Rrset>`，CNAME 链前置名不同的消息不再重复存链尾 RRset。
///
/// **持久化契约（v2）一字未改**：见字段 `rrsets` 上的自定义 serde —— 序列化仍是
/// **扁平 `answers` 数组**（`[{value,ttl,type,name}]`，`name` 为 Option，顺序保持），
/// 反序列化把 `answers` 按相邻 `(name, rtype)` 分组后重建 `rrsets`。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CacheEntry {
    pub domain: String,
    pub qtype: String,
    /// **阶段 B-2**：按 CNAME 链序（CNAME → 目标 RRset）排列的 RRset 列表。
    ///
    /// * 每个 `Arc<Rrset>` 由 [`crate::rrset::intern_rrset`] 归一：相同 RRset 全进程
    ///   只有一份活分配；写入路径（`put`/`restore*`）会经
    ///   [`crate::rrset::intern_rrsets`] 再归一一次（已规范时 0 分配）；
    /// * **JSON 形态不变**：`#[serde(rename = "answers", serialize_with = ...,
    ///   deserialize_with = ...)]` 让本字段在 JSON 里仍是旧版的 `"answers"` **数组**
    ///   （逐条 `{value,ttl,type,name?}`，顺序 = 组内顺序 + 组间顺序）⇒ 快照/WAL
    ///   字节契约、旧 v2 文件恢复能力都不变；
    /// * `#[serde(default)]`：旧持久化文件（或手写 JSON）缺该字段时按**空列表**处理，
    ///   与旧行为一致（负缓存的答案是空列表）；
    /// * 只读遍历请用嵌套循环 `for rs in &entry.rrsets { for a in &rs.values { .. } }`
    ///   或 [`CacheEntry::iter_answers`]；需要拥有扁平 `Vec<CacheAnswer>` 的冷路径
    ///   （持久化/测试）用 [`CacheEntry::flat_answers`]。
    #[serde(
        rename = "answers",
        default,
        serialize_with = "serialize_flat_answers",
        deserialize_with = "deserialize_rrsets"
    )]
    pub rrsets: Vec<Arc<crate::rrset::Rrset>>,
    pub chosen: String,
    pub ttl: f64,
    pub rcode: u8,
    pub expires_at: f64,
    /// 写入本条时的**规则集指纹**（`ebpdns_resolver` 侧的规则代际）。
    ///
    /// 缓存命中路径（`Resolver::serve_from_cache`）用它做「规则变更后旧答案立即失效」
    /// 门禁：指纹 ≠ 当前指纹 → 视为 miss（并顺带删除）。`0` = 未盖章
    /// （旧持久化文件 / 缓存 crate 测试构造的条目）→ 与当前指纹（恒 ≥1）不匹配即失效。
    #[serde(default)]
    pub rule_gen: u64,
    /// **2.1.29（缓存持久化 v2）**：该条目最后一次变更的**逻辑 seq**。
    ///
    /// 用途只有一个：快照一致性过滤 —— 快照只收录 `seq <= snapshot_seq` 的条目
    /// （`PROPOSAL-cache-snapshot-wal.md §6.3.4`）。省略这个过滤会复活“迭代前已逐出”
    /// 的条目（`W_old` 已删、`W_new` 又按 `seq > S` 过滤掉）。
    ///
    /// **必须 `#[serde(skip)]`**：否则 v1 JSON 会多一个 `"seq"` 字段，破坏
    /// `write_snapshot_is_byte_identical_to_to_vec_pretty` 钉死的字节契约。
    /// 0 = 未分配（启动构造 / v1 迁移来源的条目）。
    #[serde(skip)]
    pub seq: u64,
}

/// **阶段 B-2**：`CacheEntry.rrsets` → 扁平 `answers` 数组的 serde 序列化侧。
///
/// 逐条写出 `CacheAnswer`（`{value,ttl,type,name?}`），**顺序不变**：RRset 顺序 ×
/// 组内取值顺序。字段名由 `#[serde(rename = "answers")]` 决定，与旧版逐字节一致。
fn serialize_flat_answers<S>(rrsets: &[Arc<crate::rrset::Rrset>], ser: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq;
    let len: usize = rrsets.iter().map(|rs| rs.values.len()).sum();
    let mut seq = ser.serialize_seq(Some(len))?;
    for rs in rrsets {
        for a in &rs.values {
            seq.serialize_element(a.as_ref())?;
        }
    }
    seq.end()
}

/// **阶段 B-2**：扁平 `answers` 数组 → `CacheEntry.rrsets` 的 serde 反序列化侧。
///
/// 旧 v2 快照/WAL（只有 `answers` 数组）因此可以原样恢复：按相邻 `(name, rtype)`
/// 分组，再走 [`crate::rrset::rrsets_from_flat`] 的 intern（相同 RRset 与进程内
/// 现有条目共享同一份）。
fn deserialize_rrsets<'de, D>(de: D) -> Result<Vec<Arc<crate::rrset::Rrset>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let flat = Vec::<CacheAnswer>::deserialize(de)?;
    Ok(crate::rrset::rrsets_from_flat(&flat))
}

/// **2.1.29**：手写 `PartialEq`，**忽略 `seq`**。
///
/// 为什么：`seq` 是持久化簿记，不是条目内容；恢复后 `seq` 必然不同。
/// **阶段 B-2**：比较的是 `flat_answers()`（逐字段、逐顺序），因此"RRset 相同但
/// 内部取值顺序被共享表归一成另一条消息的顺序"这种边缘情况也不会伪造相等。
impl PartialEq for CacheEntry {
    fn eq(&self, other: &Self) -> bool {
        self.domain == other.domain
            && self.qtype == other.qtype
            && self.flat_answers() == other.flat_answers()
            && self.chosen == other.chosen
            && self.ttl == other.ttl
            && self.rcode == other.rcode
            && self.expires_at == other.expires_at
            && self.rule_gen == other.rule_gen
    }
}

impl CacheEntry {
    /// 构造一条测试/普通条目，`ttl` 为相对秒数，`now` 为当前 epoch。
    pub fn new(domain: impl Into<String>, qtype: impl Into<String>, ttl: f64, now: f64) -> Self {
        let domain = domain.into();
        let qtype = qtype.into();
        Self {
            rrsets: crate::rrset::rrsets_from_flat(&[CacheAnswer::new("1.2.3.4", ttl, 1, None)]),
            chosen: "1.2.3.4".to_string(),
            ttl,
            rcode: 0,
            expires_at: now + ttl,
            // 测试基座不涉及规则门禁：0 = 未盖章。
            rule_gen: 0,
            // v2：未分配 seq（快照/回放时再填）。
            seq: 0,
            domain,
            qtype,
        }
    }

    /// **阶段 B-2（冷路径）**：把 `rrsets` 展平成旧模型的 `Vec<CacheAnswer>`。
    ///
    /// 用于持久化（`entry_codec` 仍按扁平数组编码）、JSON 测试、以及需要拥有
    /// `Vec` 的兼容调用点。**热路径不要调用**（会分配一份 `Arc` 克隆的 Vec）。
    pub fn flat_answers(&self) -> Vec<CacheAnswer> {
        let mut out: Vec<CacheAnswer> = Vec::with_capacity(self.answers_len());
        for rs in &self.rrsets {
            for a in &rs.values {
                out.push(a.as_ref().clone());
            }
        }
        out
    }

    /// **阶段 B-2（热路径友好）**：按报文顺序只读遍历全部答案（**0 分配**）。
    ///
    /// 嵌套循环的迭代器版本，供 `map`/`filter` 等只读场景使用；需要 `&[CacheAnswer]`
    /// 连续切片时用 [`CacheEntry::flat_answers`]（冷路径）。
    pub fn iter_answers(&self) -> impl Iterator<Item = &CacheAnswer> + '_ {
        self.rrsets
            .iter()
            .flat_map(|rs| rs.values.iter().map(|a| a.as_ref()))
    }

    /// 全部答案条数（`Σ 每个 RRset 的取值数`）。
    pub fn answers_len(&self) -> usize {
        self.rrsets.iter().map(|rs| rs.values.len()).sum()
    }

    /// 用扁平答案替换 `rrsets`（重新分组 + intern）。**测试/恢复辅助**。
    pub fn set_flat_answers(&mut self, answers: &[CacheAnswer]) {
        self.rrsets = crate::rrset::rrsets_from_flat(answers);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// **阶段 3-14**：`dnssec=false` 的键数组与旧版**逐字节相同**（2/3 元素）。
    #[test]
    fn key_array_without_dnssec_is_legacy_shape() {
        let k2 = CacheKey::new("example.com", "A");
        assert_eq!(k2.to_key_array(), vec!["example.com", "A"]);
        assert!(!k2.dnssec, "默认必须是 false（旧键语义）");

        let k3 = CacheKey::with_group("g1", "example.com", "A");
        assert_eq!(k3.to_key_array(), vec!["g1", "example.com", "A"]);
        assert!(!k3.dnssec);
    }

    /// **阶段 3-14**：`dnssec=true` 时**仅在末尾追加** `"DO"`。
    #[test]
    fn key_array_with_dnssec_appends_tag() {
        let k2 = CacheKey::new("example.com", "A").with_dnssec(true);
        assert_eq!(k2.to_key_array(), vec!["example.com", "A", "DO"]);

        let k3 = CacheKey::with_group("g1", "example.com", "A").with_dnssec(true);
        assert_eq!(k3.to_key_array(), vec!["g1", "example.com", "A", "DO"]);
    }

    /// **阶段 3-14**：`Hash` / `Eq` 必须包含变体位 —— 否则 `HashSet` 会把 DO 与非 DO
    /// 键当成同一个键（"不串条目"失效）。
    ///
    /// 注：`Hash` 对 `dnssec=false` **不写任何字节**（= 旧键的哈希值不变，见 `Hash`
    /// 实现的注释），因此这里只断言"两条键在哈希表里各占一位"，不断言"哈希值必不同"。
    #[test]
    fn dnssec_bit_participates_in_eq_and_hash() {
        let plain = CacheKey::new("example.com", "A");
        let sec = CacheKey::new("example.com", "A").with_dnssec(true);
        assert_ne!(plain, sec, "DO 与非 DO 键必须不相等");
        let mut set: HashSet<CacheKey> = HashSet::new();
        set.insert(plain.clone());
        set.insert(sec.clone());
        assert_eq!(set.len(), 2, "两条变体键必须在 HashSet 里各占一个位置");
        // 同变体再插一次 → 去重（哈希与相等口径一致）。
        set.insert(plain.clone());
        set.insert(sec.clone());
        assert_eq!(set.len(), 2);
        // 非 DO 键的哈希与"旧三字段形态"一致（用同一组字段重算一遍作对照）。
        let mut a = std::collections::hash_map::DefaultHasher::new();
        plain.hash(&mut a);
        let mut b = std::collections::hash_map::DefaultHasher::new();
        plain.group.hash(&mut b);
        plain.domain.hash(&mut b);
        plain.qtype.hash(&mut b);
        assert_eq!(a.finish(), b.finish(), "非 DO 键的哈希必须与旧键逐位相同");
        // DO 键的哈希必须与同内容的非 DO 键不同（条件式哈希的实际效果）。
        let mut c = std::collections::hash_map::DefaultHasher::new();
        sec.hash(&mut c);
        assert_ne!(a.finish(), c.finish(), "DO 键必须哈希到不同的值");
    }
}
