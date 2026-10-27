//! **[历史归因]** 缓存键与条目类型，忠实对齐 Python `cache.py` 的 dict 结构。
//!
//! **[历史归因]** Python 缓存键为元组：LRU/TinyLFU 运行期是 `(domain_lower, qtype)` 或
//! `(group, domain, qtype)`；PartitionedCache 统一 3 元组。这里用一个带可选
//! `group` 的结构统一表示，`group=None` 表示 LRU 二元组。

use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

/// **[历史归因]** 统一缓存键。`group` 为 `None` 时对应 Python 二元组 `(domain, qtype)`；
/// 为 `Some(g)` 时对应三元组 `(group, domain, qtype)`。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheKey {
    pub group: Option<String>,
    pub domain: String,
    pub qtype: String,
}

impl CacheKey {
    /// 二元组键 `(domain, qtype)`（LRU 默认形态）。
    pub fn new(domain: impl Into<String>, qtype: impl Into<String>) -> Self {
        Self {
            group: None,
            domain: domain.into(),
            qtype: qtype.into(),
        }
    }

    /// 三元组键 `(group, domain, qtype)`（Partitioned / TinyLFU 运行期形态）。
    pub fn with_group(
        group: impl Into<String>,
        domain: impl Into<String>,
        qtype: impl Into<String>,
    ) -> Self {
        Self {
            group: Some(group.into()),
            domain: domain.into(),
            qtype: qtype.into(),
        }
    }

    /// **[历史归因]** 序列化为 Python 同款 key 数组（2 或 3 元素）。
    pub fn to_key_array(&self) -> Vec<String> {
        match &self.group {
            Some(g) => vec![g.clone(), self.domain.clone(), self.qtype.clone()],
            None => vec![self.domain.clone(), self.qtype.clone()],
        }
    }
}

impl Hash for CacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // group 可能是 None（LRU）或 Some（partitioned）。统一参与哈希，
        // **[历史归因]** 与 Python 对元组整体取 hash 的语义一致。
        self.group.hash(state);
        self.domain.hash(state);
        self.qtype.hash(state);
    }
}

/// **[历史归因]** 单条答案，对齐 Python answer dict `{value, ttl, type, name?}`。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CacheAnswer {
    pub value: String,
    pub ttl: f64,
    #[serde(rename = "type")]
    pub rtype: u16,
    /// 答案 owner 名（CNAME 链上逐跳 owner）；旧持久化 JSON 无此字段时反序列化为 None。
    #[serde(default)]
    pub name: Option<String>,
}

/// **[历史归因]** 缓存条目，对齐 Python entry dict：
/// `{domain, qtype, answers, chosen, ttl, rcode, expires_at}`。
///
/// **[历史归因]** `expires_at` 为 epoch 秒（浮点），与 Python `time.time()` 同口径。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CacheEntry {
    pub domain: String,
    pub qtype: String,
    pub answers: Vec<CacheAnswer>,
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

/// **2.1.29**：手写 `PartialEq`，**忽略 `seq`**。
///
/// 为什么：`seq` 是持久化簿记，不是条目内容。若参与相等判定，所有“恢复后条目应等于
/// 原条目”的既有断言（`cache_fix_test.rs` 等）都会因为 seq 不同而假红。
impl PartialEq for CacheEntry {
    fn eq(&self, other: &Self) -> bool {
        self.domain == other.domain
            && self.qtype == other.qtype
            && self.answers == other.answers
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
            answers: vec![CacheAnswer {
                value: "1.2.3.4".to_string(),
                ttl,
                rtype: 1,
                name: None,
            }],
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
}
