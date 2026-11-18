//! 本地 / 订阅规则文件加载测试（用 tempfile，不联网）。

use std::io::Write;
use std::path::PathBuf;

use ebpdns_rules::*;

fn tmp_path(name: &str) -> PathBuf {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join(name);
    // 防止 tempdir 被 drop 删除
    let keep = p.clone();
    std::mem::forget(dir);
    keep
}

#[test]
fn local_rules_path_next_to_config() {
    let cfg = PathBuf::from("/etc/ebpdns/config.json");
    assert_eq!(
        load::local_rules_path(&cfg),
        PathBuf::from("/etc/ebpdns/rules_local.json")
    );
    assert_eq!(
        load::sub_rules_path(&cfg),
        PathBuf::from("/etc/ebpdns/rules_sub.json")
    );
}

#[test]
fn load_local_rules_file() {
    let p = tmp_path("rules_local.json");
    let body = r#"{"version":1,"rules":[
        {"id":"r1","match":"*.ads.com","action":"block"},
        {"match":"ok.test","action":"allow"}
    ]}"#;
    let mut f = std::fs::File::create(&p).unwrap();
    f.write_all(body.as_bytes()).unwrap();

    let rules = load::load_local_rules_file(&p).unwrap();
    assert_eq!(rules.len(), 2);
    let e = RuleEngine::new();
    e.rebuild(rules);
    assert_eq!(
        action_of(&e.match_rule("x.ads.com", false)),
        Some(Action::Block)
    );
    assert_eq!(
        action_of(&e.match_rule("ok.test", false)),
        Some(Action::Allow)
    );
}

#[test]
fn load_missing_local_file_is_empty() {
    let p = PathBuf::from("/nonexistent/ebpdns_rules_no_such_file.json");
    let rules = load::load_local_rules_file(&p).unwrap();
    assert!(rules.is_empty());
}

#[test]
fn load_corrupt_local_file_is_empty() {
    let p = tmp_path("rules_local_bad.json");
    std::fs::write(&p, "{ not valid json").unwrap();
    let rules = load::load_local_rules_file(&p).unwrap();
    assert!(rules.is_empty());
}

/// **2.1.20（A-22，安全相关）**：**裸 JSON 数组**格式的规则文件必须被解析 ——
/// 且规则要**真的能屏蔽域名**（不只是"读到了"）。
///
/// 缺陷（审计实测）：此前 `load_local_rules_file` 只认信封 `{"rules":[…]}` ⇒ 裸数组时
/// 直接返回**空列表**且**没有任何 WARN** ⇒ 规则索引 `indexed=0`、域名不再被屏蔽
/// （对屏蔽规则集而言是 **fail-open**），而同一内容改成信封格式一切正常。
#[test]
fn a22_bare_array_local_file_is_parsed_and_enforced() {
    let p = tmp_path("rules_local_bare_array.json");
    let body = r#"[
        {"id":"b1","match":"*.bare-ads.com","action":"block"},
        {"id":"b2","match":"bare-ok.test","action":"allow"}
    ]"#;
    std::fs::write(&p, body).unwrap();

    let rules = load::load_local_rules_file(&p).unwrap();
    assert_eq!(
        rules.len(),
        2,
        "裸数组必须被解析成 2 条规则（此前是 0 条、且无任何告警）"
    );
    // 必须**真的生效**：引擎按规则屏蔽 / 放行。
    let e = RuleEngine::new();
    e.rebuild(rules);
    assert_eq!(
        action_of(&e.match_rule("x.bare-ads.com", false)),
        Some(Action::Block),
        "裸数组里的 block 规则必须真的屏蔽域名（fail-open 已修）"
    );
    assert_eq!(
        action_of(&e.match_rule("bare-ok.test", false)),
        Some(Action::Allow)
    );
}

/// **2.1.20（A-22）**：既不是数组、也没有 `rules` 数组的文件 ⇒ 空列表（**但有 WARN**，
/// 由 `load_local_rules_file` 内部打点；调用方另有 `cfg.rules` 回落）。
#[test]
fn a22_unknown_shape_local_file_is_empty_not_panicking() {
    let p = tmp_path("rules_local_unknown_shape.json");
    std::fs::write(&p, r#"{"version":1}"#).unwrap();
    let rules = load::load_local_rules_file(&p).unwrap();
    assert!(rules.is_empty(), "形状不认识 ⇒ 空列表（不得 panic）");
}

#[test]
fn load_sub_rules_with_defaults() {
    let p = tmp_path("rules_sub.json");
    // 订阅项：缺省 action=block / group=global / ip=1.2.3.4
    let body = r#"{"subscriptions":[
        {"action":"block","rules":[{"match":"sub.ads.com"},{"match":"*.sub.net"}]},
        {"action":"forceIp","ip":"9.9.9.9","rules":[{"match":"f.sub.test"}]},
        {"action":"group","group":"domestic","rules":[{"match":"*.cn"}]}
    ]}"#;
    std::fs::write(&p, body).unwrap();

    let rules = load::load_sub_rules_file(&p).unwrap();
    let e = RuleEngine::new();
    e.rebuild(rules);
    assert_eq!(
        action_of(&e.match_rule("sub.ads.com", false)),
        Some(Action::Block)
    );
    assert_eq!(
        action_of(&e.match_rule("x.sub.net", false)),
        Some(Action::Block)
    );
    // forceIp 注入了订阅的 ip
    let out = e.match_rule("f.sub.test", false);
    if let MatchOutcome::Hit(r) = out {
        assert_eq!(r.ip.unwrap().to_string(), "9.9.9.9");
        assert_eq!(r.action, Action::ForceIp);
    } else {
        panic!("应命中 forceIp 规则");
    }
    assert_eq!(action_of(&e.match_rule("x.cn", false)), Some(Action::Group));
}

#[test]
fn load_sub_missing_file_empty() {
    let p = PathBuf::from("/nonexistent/ebpdns_rules_no_sub.json");
    assert!(load::load_sub_rules_file(&p).unwrap().is_empty());
}

/// **2.1.46（REV247 C P2-13）**：库 loader 对"形状不认识"的订阅文件必须报错，
/// 不得静默返回空列表（旧实现 `data.get("subscriptions")` 为 None 时直接 `Ok([])`）。
#[test]
fn load_sub_unknown_shape_is_an_error_not_silent_empty() {
    for (name, body) in [
        ("no_sub_key", r#"{"rules":[]}"#),
        ("sub_not_array", r#"{"subscriptions":{}}"#),
        ("top_array", r#"[]"#),
    ] {
        let p = tmp_path(&format!("rules_sub_bad_{name}.json"));
        std::fs::write(&p, body).unwrap();
        let got = load::load_sub_rules_file(&p);
        assert!(
            matches!(got, Err(RulesError::InvalidStructure(_))),
            "{name}：必须返回 InvalidStructure，实际 {got:?}"
        );
    }
    // 合法的空数组仍然 Ok([])（不误伤"确实没有订阅"）。
    let p = tmp_path("rules_sub_empty_ok.json");
    std::fs::write(&p, r#"{"subscriptions":[]}"#).unwrap();
    assert!(load::load_sub_rules_file(&p).unwrap().is_empty());
}

fn action_of(out: &MatchOutcome) -> Option<Action> {
    match out {
        MatchOutcome::Hit(r) => Some(r.action),
        _ => None,
    }
}
