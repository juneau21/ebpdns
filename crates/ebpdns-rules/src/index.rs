//! **[历史归因]** 规则索引构建：分类建表 + 原子快照。对齐 Python `resolver._rebuild_rule_index`。
//!
//! **[历史归因]** 六个分表（对应 Python 元组 `(exact, wild, allow_exact, allow_wild, suffix_wild, regex)`）：
//! - `exact` / `allow_exact`：精确域名 O(1) 哈希；
//! - `wild` / `allow_wild`：纯后缀通配 `*.core`，按 `core` 建表，查询时逐级剥标签最长匹配；
//! - `suffix_wild`：中缀/前缀通配（`*ads.com` / `*ac*.com` 中可分组者）按字面后缀分组；
//! - `regex`：`re:` 正则 + 无法分组的通配，按配置顺序首个命中生效。
//!
//! 本地规则先加载、占位，订阅后加载不覆盖同域名本地规则（`setdefault` 语义）。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use regex::Regex;

use crate::rule::{Action, Rule};

/// 单条编译后的（正则类）规则。
#[derive(Debug)]
pub struct RegexRule {
    pub regex: Regex,
    pub rule: Arc<Rule>,
}

/// 不可变规则索引快照。构建后只读，整表以 `Arc` 原子发布。
///
/// 值类型为 `Arc<Rule>`：热路径命中时只做一次引用计数自增即可把规则交给调用方与
/// 结论缓存，避免 `Rule`（4 个 `String` + 1 个 `Option<IpAddr>`）的深拷贝分配。
#[derive(Debug)]
pub struct RuleIndex {
    pub exact: HashMap<String, Arc<Rule>>,
    pub wild: HashMap<String, Arc<Rule>>,
    pub allow_exact: HashMap<String, Arc<Rule>>,
    pub allow_wild: HashMap<String, Arc<Rule>>,
    pub suffix_wild: HashMap<String, Vec<RegexRule>>,
    pub regex: Vec<RegexRule>,
    /// 是否存在 group 分流规则（供 resolver 决定是否走 match_rule）。
    pub has_group_rules: bool,
    /// 本次建索引成功收录的规则条数（= [`BuildStats::indexed`]）。
    ///
    /// 只读计数访问器 [`RuleIndex::rule_count`] 供管理面（`GET /api/pipeline.rules`）
    /// 展示「真实索引规则数」：此前该端点读的是 `config.rules`（逐条本地规则）长度，
    /// 订阅来的 10 万条规则完全不计入，控制台「数据面流水线」页恒显示 0 规则。
    pub rule_count: usize,
}

/// 建索引统计。
#[derive(Debug, Clone, Copy, Default)]
pub struct BuildStats {
    /// 成功入索引的规则数。
    pub indexed: usize,
    /// 被跳过的坏规则数（空 match / 正则编译失败 / 超长 / 控制符等）。
    pub rejected: usize,
}

/// match 字段字节上限（对齐 api `_validate_rule_dict` 的 4096）。
pub const MATCH_MAX_BYTES: usize = 4096;

/// 判断字符串是否含控制字符（0x00-0x1f / 0x7f）。
fn has_control_char(s: &str) -> bool {
    s.bytes().any(|b| b < 0x20 || b == 0x7f)
}

impl RuleIndex {
    /// 从规则列表构建索引。`rules` 顺序即本地在前、订阅在后（本地占位优先）。
    pub fn build(rules: Vec<Rule>) -> (RuleIndex, BuildStats) {
        let mut exact: HashMap<String, Arc<Rule>> = HashMap::new();
        let mut wild: HashMap<String, Arc<Rule>> = HashMap::new();
        let mut allow_exact: HashMap<String, Arc<Rule>> = HashMap::new();
        let mut allow_wild: HashMap<String, Arc<Rule>> = HashMap::new();
        let mut suffix_wild: HashMap<String, Vec<RegexRule>> = HashMap::new();
        let mut regex: Vec<RegexRule> = Vec::new();

        let mut stats = BuildStats::default();
        let mut has_group_rules = false;

        for r in rules {
            if r.action == Action::Group {
                has_group_rules = true;
            }
            // 规则包装为 Arc：索引/结论缓存共享同一份不可变规则，克隆恒为 O(1)。
            // `match_raw` 先取出（重建路径，非热路径），避免与 `Arc::new(r)` 的所有权冲突。
            let m_raw = r.match_raw.clone();
            let is_allow = r.action.is_allow();
            let r = Arc::new(r);
            let m = m_raw.as_str();

            if let Some(pat) = m.strip_prefix("re:") {
                // ---- 正则规则 ----
                // 加载期拒绝（fail-closed 方向 = 不索引坏规则，避免死规则/膨胀）。
                if pat.trim().is_empty() || has_control_char(m) || m.len() > MATCH_MAX_BYTES {
                    tracing::warn!("正则规则非法（空体/控制符/超长），已忽略: {}", m);
                    stats.rejected += 1;
                    continue;
                }
                match Regex::new(pat) {
                    Ok(c) => regex.push(RegexRule { regex: c, rule: r }),
                    Err(e) => {
                        tracing::warn!("正则规则编译失败 {:?}: {}", m, e);
                        stats.rejected += 1;
                        continue;
                    }
                }
                stats.indexed += 1;
            } else if let Some(core) = m.strip_prefix("*.").filter(|rest| !rest.contains('*')) {
                // ---- 纯后缀通配 *.core ----
                let core = core.trim_matches('.');
                if core.is_empty() {
                    stats.rejected += 1;
                    continue;
                }
                if is_allow {
                    allow_wild.entry(core.to_string()).or_insert(r);
                } else {
                    wild.entry(core.to_string()).or_insert(r);
                }
                stats.indexed += 1;
            } else if m.contains('*') {
                // ---- 中缀/前缀通配 ----
                // 取尾部连续不含 '*' 的完整标签作分组 key；末段含 '*' 则退化为全局正则。
                let body = m.trim_start_matches(&['*', '.'] as &[_]);
                let parts: Vec<&str> = body.split('.').collect();
                // 建索引侧 key 必须落在标签边界：取末两段；若末段本身含 '*' 则无法
                // 确定标签边界，退化为全局正则兜底（对齐 R-fix）。
                let suffix = if parts.len() >= 2 {
                    let s = parts[parts.len() - 2..].join(".");
                    if s.contains('*') {
                        String::new()
                    } else {
                        s
                    }
                } else {
                    String::new()
                };
                let pat = crate::wildcard::wildcard_to_regex(m);
                match Regex::new(&pat) {
                    Ok(c) => {
                        if !suffix.is_empty() {
                            suffix_wild
                                .entry(suffix)
                                .or_default()
                                .push(RegexRule { regex: c, rule: r });
                        } else {
                            regex.push(RegexRule { regex: c, rule: r });
                        }
                    }
                    Err(e) => {
                        tracing::warn!("通配规则编译失败 {:?}: {}", m, e);
                        stats.rejected += 1;
                        continue;
                    }
                }
                stats.indexed += 1;
            } else {
                // ---- 精确规则 ----
                if is_allow {
                    allow_exact
                        .entry(m.to_string())
                        .or_insert_with(|| r.clone());
                } else {
                    exact.entry(m.to_string()).or_insert_with(|| r.clone());
                }
                stats.indexed += 1;
            }
        }

        (
            RuleIndex {
                exact,
                wild,
                allow_exact,
                allow_wild,
                suffix_wild,
                regex,
                has_group_rules,
                rule_count: stats.indexed,
            },
            stats,
        )
    }

    /// 当前索引里成功收录的规则条数（O(1) 只读访问器）。
    ///
    /// 口径 = 建索引时计入 `BuildStats::indexed` 的规则数（含被同表去重折叠的重复
    /// **[历史归因]** match——与 Python `_rebuild_rule_index` 的 `len(rule_list)` 语义一致）。
    #[inline]
    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    /// 是否完全没有任何正则类规则（suffix_wild 与 regex 皆空）。
    /// fast 路径据此决定是否可直接缓存 None。
    pub fn has_no_regex_rules(&self) -> bool {
        self.regex.is_empty() && self.suffix_wild.is_empty()
    }

    /// forceIp 规则里引用的 IP（供类型/序列化测试）。
    pub fn force_ips(&self) -> Vec<IpAddr> {
        let mut out = Vec::new();
        for bag in [&self.exact, &self.wild, &self.allow_exact, &self.allow_wild] {
            for r in bag.values() {
                if let Some(ip) = r.ip {
                    out.push(ip);
                }
            }
        }
        for rr in self.regex.iter().chain(self.suffix_wild.values().flatten()) {
            if let Some(ip) = rr.rule.ip {
                out.push(ip);
            }
        }
        out
    }
}
