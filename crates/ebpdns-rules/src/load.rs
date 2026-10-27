//! 本地逐条规则 / 订阅规则文件的路径解析与加载。
//!
//! **[历史归因]** 忠实对齐 Python `config.local_rules_path` / `sub_rules_path` 与
//! `resolver._load_local_rules` / `_load_sub_rules`：
//! - 文件不存在视为空规则（不报错）；
//! - JSON 损坏告警并返回空，不静默 panic；
//! - 订阅规则按订阅项的默认 action=block / group=global / ip=1.2.3.4 注入。

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::error::RulesError;
use crate::rule::{rule_from_json, Action, Rule, RuleSource};

/// 逐条规则独立文件名（与 config.json 同目录）。
pub const LOCAL_RULES_FILE: &str = "rules_local.json";
/// 订阅规则独立文件名。
pub const SUB_RULES_FILE: &str = "rules_sub.json";

/// 由 config.json 路径推导逐条规则文件路径（对齐 `local_rules_path`）。
pub fn local_rules_path(config_path: &Path) -> PathBuf {
    let dir = config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    dir.join(LOCAL_RULES_FILE)
}

/// 由 config.json 路径推导订阅规则文件路径（对齐 `sub_rules_path`）。
pub fn sub_rules_path(config_path: &Path) -> PathBuf {
    let dir = config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    dir.join(SUB_RULES_FILE)
}

fn load_json(path: &Path) -> Result<Option<Value>, RulesError> {
    let s = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            tracing::warn!("规则文件读取失败 {}: {}", path.display(), e);
            return Ok(None);
        }
    };
    // **[历史归因]** JSON 损坏：告警并按空规则处理（对齐 Python，不静默 panic、不上抛崩溃启动）。
    match serde_json::from_str(&s) {
        Ok(v) => Ok(Some(v)),
        Err(e) => {
            tracing::warn!("规则文件 JSON 解析失败 {}: {}", path.display(), e);
            Ok(None)
        }
    }
}

/// 加载本地逐条规则文件。**两种格式都接受**（**2.1.20 / A-22**）：
/// * 信封 `{ "version":1, …, "rules": [ {…}, … ] }`（本程序写出的规范格式）；
/// * **裸 JSON 数组** `[ {…}, … ]`（整个文件就是规则列表）。
///
/// 文件不存在/损坏 → 空列表（调用方另有回落逻辑）。
///
/// **2.1.20（A-22 修复：裸数组被静默吞掉）**：此前只认信封 ⇒ 裸数组时
/// `data.get("rules")` 为 `None` ⇒ 直接返回**空列表**，**没有任何 WARN**
/// （审计实测：规则索引 `indexed=0`、`rules_gen` 停在 FNV 初值、域名不再被屏蔽，
/// 而同一内容改成信封格式一切正常）。现在：
/// * 顶层数组 ⇒ 按规则列表解析（INFO 说明走了兼容路径）；
/// * 既不是数组、也没有 `rules` 数组 ⇒ **WARN**（不得静默空集）。
pub fn load_local_rules_file(path: &Path) -> Result<Vec<Rule>, RulesError> {
    let Some(data) = load_json(path)? else {
        tracing::info!("逐条规则文件 {} 不存在，按空规则启动", path.display());
        return Ok(Vec::new());
    };
    // ① 裸数组兼容：整个文件就是规则列表。
    let arr = if let Some(a) = data.as_array() {
        tracing::info!(
            path = %path.display(),
            rules = a.len(),
            "逐条规则文件是**裸 JSON 数组**（非信封格式）：已按规则列表解析（兼容模式）"
        );
        Some(a)
    } else {
        // ② 信封：取 `rules`；形状不认识时**必须**告警（不得静默空集）。
        match data.get("rules").and_then(Value::as_array) {
            Some(a) => Some(a),
            None => {
                tracing::warn!(
                    path = %path.display(),
                    "**逐条规则文件解析不到规则列表**（既不是裸数组、也没有 `rules` 数组）\
                     ⇒ 本次按空规则处理；请检查文件格式（**这会导致屏蔽规则静默失效**）"
                );
                None
            }
        }
    };
    let mut out = Vec::new();
    if let Some(arr) = arr {
        for item in arr {
            if let Value::Object(map) = item {
                if let Some(r) = rule_from_json(map.clone(), RuleSource::Local) {
                    out.push(r);
                }
            } else {
                tracing::warn!("规则索引跳过非 dict 条目: {:?}", item);
            }
        }
    }
    Ok(out)
}

/// 加载订阅规则文件 `{ "subscriptions": [ {action,group,ip,rules:[{match}]} ] }`。
///
/// 文件不存在/JSON 损坏 → 空列表（与本地规则同口径）。
///
/// **2.1.46（REV247 C P2-13）**：顶层形状不认识（不是对象、没有
/// `subscriptions` 数组、或 `subscriptions` 不是数组）⇒ 返回
/// [`RulesError::InvalidStructure`]，**不再静默返回空列表**。库调用方此前无法区分
/// "确实没有订阅"和"文件格式写错/键名拼错"，会把整份订阅规则静默丢成 0 条。
/// 服务端的订阅文件走独立的 `subscribe` 实现，不受本函数影响。
pub fn load_sub_rules_file(path: &Path) -> Result<Vec<Rule>, RulesError> {
    let Some(data) = load_json(path)? else {
        return Ok(Vec::new());
    };
    let Some(subs) = data.get("subscriptions").and_then(Value::as_array) else {
        return Err(RulesError::InvalidStructure(format!(
            "{}：顶层必须是含 `subscriptions` 数组的对象（实际 keys={:?}）",
            path.display(),
            data.as_object()
                .map(|o| o.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default()
        )));
    };
    let mut out = Vec::new();
    {
        for sub in subs {
            let sub = match sub.as_object() {
                Some(o) => o,
                None => {
                    tracing::warn!(
                        path = %path.display(),
                        "订阅项不是 JSON 对象，已跳过（不影响其它订阅项）"
                    );
                    continue;
                }
            };
            let action_s = sub.get("action").and_then(Value::as_str).unwrap_or("block");
            let action = Action::parse(action_s);
            // **[历史归因]** Python 用 `sub.get("group") or "global"`（falsy 语义）：显式 `""` 与 `null`
            // 都取默认。Rust 若只做 `unwrap_or`，空串会让 forceIp 解析出空 IP →
            // `rule_from_json` 整条丢弃 → 该订阅的全部域名失去分流。
            let group = sub
                .get("group")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .unwrap_or("global");
            let ip = sub
                .get("ip")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .unwrap_or("1.2.3.4");
            let Some(items) = sub.get("rules").and_then(Value::as_array) else {
                tracing::warn!(
                    path = %path.display(),
                    "订阅项缺少 `rules` 数组，已跳过（该订阅的域名会静默失效）"
                );
                continue;
            };
            {
                for item in items {
                    let m = item
                        .get("match")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .trim();
                    if m.is_empty() {
                        continue;
                    }
                    let mut map = serde_json::Map::new();
                    map.insert("match".to_string(), Value::String(m.to_string()));
                    map.insert("action".to_string(), Value::String(action_s.to_string()));
                    if action == Action::Group {
                        map.insert("group".to_string(), Value::String(group.to_string()));
                    } else if action == Action::ForceIp {
                        map.insert("ip".to_string(), Value::String(ip.to_string()));
                    }
                    if let Some(r) = rule_from_json(map, RuleSource::Sub) {
                        out.push(r);
                    }
                }
            }
        }
    }
    Ok(out)
}
