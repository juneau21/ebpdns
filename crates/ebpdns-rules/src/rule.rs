//! 规则模型：[`Action`] 枚举、[`Rule`] 与 [`normalize_rule`]。
//!
//! **[历史归因]** 忠实对齐 Python `resolver._normalize_rule`（旧字段名 pattern/value 迁移）与
//! `config._validate_rule_subscription_item`（forceIp 的 ip 合法性）。

use serde_json::Value;
use std::net::IpAddr;

/// **[历史归因]** 规则动作枚举。对应 Python `_RULE_ACTIONS = ("allow","block","group","forceIp")`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// 白名单例外：命中即放行，优先于 block/group/forceIp。
    Allow,
    /// 屏蔽（fail-closed）。
    Block,
    /// 分流到上游组 [`Rule::group`]。
    Group,
    /// 强制使用 [`Rule::ip`] 应答。
    ForceIp,
}

impl Action {
    /// 从字符串解析；未知/缺失返回 [`Action::Block`]（sub 加载默认 block，屏蔽类 fail-closed）。
    pub fn parse(s: &str) -> Self {
        match s {
            "allow" => Action::Allow,
            "block" => Action::Block,
            "group" => Action::Group,
            "forceIp" => Action::ForceIp,
            _ => Action::Block,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Block => "block",
            Action::Group => "group",
            Action::ForceIp => "forceIp",
        }
    }

    /// 是否为白名单（allow）。建索引时 allow 单独建表，匹配时优先。
    pub fn is_allow(self) -> bool {
        matches!(self, Action::Allow)
    }
}

/// 规则来源：本地逐条规则 / 订阅规则。本地先加载、占位，订阅不覆盖同域名本地规则。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSource {
    Local,
    Sub,
}

/// 一条分流规则。
///
/// `match_raw` 已经过规范化（`trim().trim_end_matches('.').to_ascii_lowercase()`），
/// 与 proto `Name` 口径一致；`re:` / `*.` / 中缀通配的分类由建索引侧完成。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub id: Option<String>,
    /// 规范化后的匹配表达式（域名 / `*.core` / `*x*` / `re:pat`）。
    pub match_raw: String,
    pub action: Action,
    /// action=group 时的上游组名。
    pub group: Option<String>,
    /// action=forceIp 时的强制 IP。
    pub ip: Option<IpAddr>,
    /// 是否启用（resolver 建索引当前不过滤 disabled；字段供 API/序列化往返）。
    pub enabled: bool,
    /// 注释 / 备注。
    pub comment: Option<String>,
    pub source: RuleSource,
}

/// **[历史归因]** 对齐 Python `resolver._normalize_rule`：把旧字段名迁移到新字段。
///
/// - `match_raw` / `pattern` → `match`（仅当尚无 `match`；`match_raw` 是 2.0
///   落盘口径，`config.json` 的 `rules[]` 用的就是它）；
/// - `value`  → action=group 落 `group`（尚无 group），否则落 `ip`（尚无 ip）。
///
/// 原地修改 JSON 对象；非对象条目调用方应已过滤。
pub fn normalize_rule(map: &mut serde_json::Map<String, Value>) {
    // match_raw / pattern -> match
    //
    // `match_raw` 是 2.0 内部与**落盘**口径（`config.json` 的 `rules[]` 由
    // `rules_admin`/`subscribe` 写回时用的就是它，见 `/etc/ebpdns/config.json`），
    // `pattern` 是 v1.9.162 之前的旧字段名。此前这里只认 `pattern` → `match`，
    // 于是 `config.json` 里的 `rules[]`（只有 `match_raw`）经 `main.rs::apply_cfg`
    // 全部解析失败 → `Resolver::reload()` 把规则索引重建为**空**（10 万条订阅规则
    // 一并被摘掉）：实测 `POST /api/reload` 后 `pipeline.rules` 101147 → 0、
    // `rule_hits` 停止增长。
    let has_match = map
        .get("match")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty());
    if !has_match {
        let migrated = ["match_raw", "pattern"].iter().find_map(|k| {
            map.get(*k)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        });
        if let Some(m) = migrated {
            map.insert("match".to_string(), Value::String(m));
        }
        map.remove("pattern");
    }
    // value -> ip / group
    if map.contains_key("value") {
        let act = map.get("action").and_then(Value::as_str).unwrap_or("");
        if act == "group" {
            let has_group = map
                .get("group")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty());
            if !has_group {
                if let Some(v) = map.remove("value") {
                    if v.is_string() {
                        map.insert("group".to_string(), v);
                    }
                }
            }
        } else {
            let has_ip = map.get("ip").is_some();
            if !has_ip {
                if let Some(v) = map.remove("value") {
                    map.insert("ip".to_string(), v);
                }
            }
        }
    }
}

fn as_str(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str)
}

/// 从（已 `normalize_rule` 的）JSON 对象构造 [`Rule`]；`match` 为空或非法时返回 `None`。
///
/// forceIp 且 ip 无法解析为 IPv4/IPv6 时跳过该规则（避免永不命中的死规则，对齐
/// `config`/`api` 写侧 ip 合法性校验）。
pub fn rule_from_json(mut map: serde_json::Map<String, Value>, source: RuleSource) -> Option<Rule> {
    normalize_rule(&mut map);

    let m_raw = as_str(map.get("match")).unwrap_or("");
    // 规范化口径与 proto::Name 一致：strip().rstrip('.').lower()
    let m = m_raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if m.is_empty() {
        return None;
    }

    let action = Action::parse(as_str(map.get("action")).unwrap_or("block"));

    let group = match map.get("group") {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    };

    // ip：仅接受字符串且能解析为 IpAddr。
    let ip = match map.get("ip") {
        Some(Value::String(s)) => s.trim().parse::<IpAddr>().ok(),
        _ => None,
    };
    // forceIp 必须带合法 ip，否则死规则 → 跳过（fail-closed 方向）。
    if action == Action::ForceIp && ip.is_none() {
        tracing::warn!("forceIp 规则缺合法 ip，已跳过: {}", m);
        return None;
    }

    let id = match map.get("id") {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    };
    let enabled = map.get("enabled").and_then(Value::as_bool).unwrap_or(true);
    let comment = match map.get("comment") {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    };

    Some(Rule {
        id,
        match_raw: m,
        action,
        group,
        ip,
        enabled,
        comment,
        source,
    })
}

/// **[历史归因]** 对齐 Python `resolver._rule_label`：规则命中显示标签。
pub fn rule_label(rule: &Rule) -> String {
    match rule.action {
        Action::Allow => format!("放行 {}", rule.match_raw),
        Action::Block => format!("屏蔽 {}", rule.match_raw),
        Action::ForceIp => format!("强制IP {}", rule.match_raw),
        Action::Group => match rule.group.as_deref() {
            Some("domestic") => format!("国内 {}", rule.match_raw),
            _ => format!("国外 {}", rule.match_raw),
        },
    }
}

/// **2.1.16（功能 3）**：规则 match 的**语法分类**（供 `ebpdns_rule_hits_total{match_type,action}`）。
///
/// 取值与 [`crate::index::RuleIndex`] 的**六分表判定逐条同构**（同一个 `match_raw`
/// 在别处被放进哪张表，这里就返回哪个名字）—— 单测
/// `match_kind_mirrors_index_tables` 用同一批样本同时跑两条路径做交叉验证，
/// 因此这不是"另写一套分类"，而是把建索引时的分类口径暴露给观测面：
/// - `"regex"`：`re:` 前缀的显式正则；或含 `*` 但**末段标签仍含 `*`**（无法分组）→ 退化为全局正则；
/// - `"wild_suffix"`：`*.core`（`core` 内无 `*`）—— 纯后缀通配，建 `wild`/`allow_wild` 表；
/// - `"wild_infix"`：含 `*` 且能取到不含 `*` 的末两段后缀 —— 建 `suffix_wild` 分组表；
/// - `"exact"`：其余（不含 `*`、无 `re:` 前缀）—— 建 `exact`/`allow_exact` 表。
///
/// 为什么放在观测面而不是索引里逐条存：`Rule` 结构不变（避免 10 万条订阅规则
/// 每条多一个 `&'static str` 字段的布局/兼容成本），分类是**纯语法函数**（O(长度)，
/// 只在规则命中时调用一次，命中率远低于数据面 QPS）。
pub fn match_kind(match_raw: &str) -> &'static str {
    let m = match_raw;
    if m.starts_with("re:") {
        return "regex";
    }
    if let Some(core) = m.strip_prefix("*.") {
        if !core.contains('*') {
            return "wild_suffix";
        }
    }
    if m.contains('*') {
        // 与 `index.rs` 的分组 key 判定同构：取末两段，若仍含 '*' 则退化为全局正则。
        let body = m.trim_start_matches(&['*', '.'][..]);
        let parts: Vec<&str> = body.split('.').collect();
        let suffix_ok = if parts.len() >= 2 {
            let s = parts[parts.len() - 2..].join(".");
            !s.contains('*')
        } else {
            false
        };
        return if suffix_ok { "wild_infix" } else { "regex" };
    }
    "exact"
}

/// **2.1.16（功能 3）**：规则的**动作**维度键（与 `telemetry.rule_hits` 的既有键逐字一致）。
///
/// 取值 = `resolve.rs` 里 `tel.inc_rule(...)` 的历史参数（`allow` / `block` /
/// `domestic` / `global` / `forceIp`），因此新指标的分组与既有 `status.rule_hits`
/// **同源可对账**（`sum(action 各档) == sum(rule_hits 各键)`）。
pub fn action_key(rule: &Rule) -> &'static str {
    match rule.action {
        Action::Allow => "allow",
        Action::Block => "block",
        Action::ForceIp => "forceIp",
        Action::Group => match rule.group.as_deref() {
            Some("domestic") => "domestic",
            _ => "global",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: Value) -> serde_json::Map<String, Value> {
        v.as_object().cloned().unwrap_or_default()
    }

    /// 缺陷（P0）：`config.json` 的 `rules[]` 落盘键是 **`match_raw`**
    /// （`rules_admin`/`subscribe` 写回口径）。此前 `normalize_rule` 只认
    /// `pattern`，于是这些条目全部解析失败被丢弃 → 热重载把规则索引重建为空。
    #[test]
    fn match_raw_is_migrated_to_match() {
        let r = rule_from_json(
            obj(json!({
                "action": "block",
                "comment": null,
                "enabled": true,
                "group": "domestic",
                "id": "r1791700473564_ay4hgc",
                "ip": null,
                "match_raw": "*.probe.test"
            })),
            RuleSource::Local,
        )
        .expect("match_raw 条目必须能构造规则");
        assert_eq!(r.match_raw, "*.probe.test");
        assert_eq!(r.action, Action::Block);
        assert_eq!(r.group.as_deref(), Some("domestic"));
        assert_eq!(r.id.as_deref(), Some("r1791700473564_ay4hgc"));
    }

    /// `match` 优先于 `match_raw`（两者同时给出时以 `match` 为准）；
    /// `pattern` 旧字段仍兼容；空白/空串一律视为缺失。
    #[test]
    fn match_key_precedence_and_legacy_pattern() {
        let r = rule_from_json(
            obj(json!({"match": "a.test", "match_raw": "b.test", "action": "block"})),
            RuleSource::Local,
        )
        .expect("rule");
        assert_eq!(r.match_raw, "a.test");

        let legacy = rule_from_json(
            obj(json!({"pattern": "old.test", "action": "block"})),
            RuleSource::Local,
        )
        .expect("pattern 兼容");
        assert_eq!(legacy.match_raw, "old.test");

        assert!(
            rule_from_json(
                obj(json!({"match_raw": "   ", "action": "block"})),
                RuleSource::Local
            )
            .is_none(),
            "空白 match_raw 不得构造出规则"
        );
        assert!(
            rule_from_json(obj(json!({"action": "block"})), RuleSource::Local).is_none(),
            "缺 match 不得构造出规则"
        );
    }

    /// 规范化口径保持一致：大小写/尾点/空白。
    #[test]
    fn match_raw_is_normalized() {
        let r = rule_from_json(
            obj(json!({"match_raw": "  Ad.Example.COM.  ", "action": "block"})),
            RuleSource::Local,
        )
        .expect("rule");
        assert_eq!(r.match_raw, "ad.example.com");
    }
}
