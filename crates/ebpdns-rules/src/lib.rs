//! **[历史归因]** ebpdns-rules：分流规则引擎，忠实对齐 Python `ebpdns v1.9.161` resolver 规则段。
//!
//! 模块：
//! - [`rule`]：[`rule::Action`] / [`rule::Rule`] / [`rule::normalize_rule`]；
//! - [`wildcard`]：通配 → 锚定正则；
//! - [`index`]：六分表规则索引（exact / wild / allow_* / suffix_wild / regex）；
//! - [`engine`]：[`engine::RuleEngine`]（三态匹配 + 结论 LRU + 代际门控 + 宽限期）；
//! - [`parse`]：hosts / AdGuard / dnsmasq / Surge / Clash 列表解析；
//! - [`load`]：本地 / 订阅规则文件路径与加载。
//!
//! **[历史归因]** 与 Python 的关键取舍：Rust `regex` 保证线性时间（无灾难性回溯），故不移植
//! `_regex_search_safe` / `_regex_match_safe` 的线程池超时；匹配为同步短临界区，
//! 由异步调用方放 `spawn_blocking`。坏正则在加载期拒绝（编译失败即跳过）。

pub mod engine;
pub mod error;
pub mod index;
pub mod load;
pub mod parse;
pub mod rule;
pub mod wildcard;

pub use engine::{BuildReport, MatchOutcome, RuleEngine, RULE_CACHE_MAX, RULE_GRACE_SEC};
pub use error::RulesError;
pub use index::{BuildStats, RuleIndex};
pub use rule::{
    action_key, match_kind, normalize_rule, rule_from_json, rule_label, Action, Rule, RuleSource,
};
