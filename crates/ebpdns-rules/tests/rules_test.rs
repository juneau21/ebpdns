//! **[历史归因]** 规则引擎集成测试：移植 Python tests/test_resolver.py::TestRuleMatching 及
//! 规则/匹配/订阅相关用例。确定性、不联网。

use ebpdns_rules::*;
use serde_json::json;

fn rule(match_expr: &str, action: &str) -> Rule {
    let v = json!({"match": match_expr, "action": action});
    rule_from_json(v.as_object().unwrap().clone(), RuleSource::Local)
        .unwrap_or_else(|| panic!("应能构造规则 {} {}", action, match_expr))
}

fn engine(rules: Vec<Rule>) -> RuleEngine {
    let e = RuleEngine::new();
    e.rebuild(rules);
    e
}

fn action_of(out: &MatchOutcome) -> Option<Action> {
    match out {
        MatchOutcome::Hit(r) => Some(r.action),
        _ => None,
    }
}

#[test]
fn exact_block() {
    let e = engine(vec![rule("blocked.test", "block")]);
    assert_eq!(
        action_of(&e.match_rule("blocked.test", false)),
        Some(Action::Block)
    );
    assert!(matches!(
        e.match_rule("other.test", false),
        MatchOutcome::NoRule
    ));
}

#[test]
fn exact_normalizes_case_and_dot() {
    // 建索引前 match 规范化：strip().rstrip('.').lower()；查询名同理。
    let e = engine(vec![rule("Blocked.Test.", "block")]);
    assert_eq!(
        action_of(&e.match_rule("blocked.test", false)),
        Some(Action::Block)
    );
    assert_eq!(
        action_of(&e.match_rule("  BLOCKED.TEST. ", false)),
        Some(Action::Block)
    );
}

#[test]
fn wildcard_suffix_block() {
    let e = engine(vec![rule("*.ads.com", "block")]);
    assert_eq!(
        action_of(&e.match_rule("x.ads.com", false)),
        Some(Action::Block)
    );
    assert_eq!(
        action_of(&e.match_rule("a.b.ads.com", false)),
        Some(Action::Block)
    );
    // 设计语义：*.core 同时匹配 core 自身
    assert_eq!(
        action_of(&e.match_rule("ads.com", false)),
        Some(Action::Block)
    );
    assert!(matches!(
        e.match_rule("other.com", false),
        MatchOutcome::NoRule
    ));
}

#[test]
fn wildcard_suffix_longest_match() {
    // 更具体的 *.deep.ads.com 应胜出（最长剥标签）。
    let e = engine(vec![
        rule("*.ads.com", "block"),
        rule("*.deep.ads.com", "allow"),
    ]);
    assert_eq!(
        action_of(&e.match_rule("x.deep.ads.com", false)),
        Some(Action::Allow)
    );
    assert_eq!(
        action_of(&e.match_rule("x.ads.com", false)),
        Some(Action::Block)
    );
}

#[test]
fn allow_priority() {
    let e = engine(vec![
        rule("ok.ads.com", "allow"),
        rule("*.ads.com", "block"),
    ]);
    assert_eq!(
        action_of(&e.match_rule("ok.ads.com", false)),
        Some(Action::Allow)
    );
    // 白名单只对精确命中放行，其他 *.ads.com 仍 block
    assert_eq!(
        action_of(&e.match_rule("x.ads.com", false)),
        Some(Action::Block)
    );
}

#[test]
fn allow_wildcard_priority() {
    let e = engine(vec![rule("*.safe.com", "allow"), rule("*.com", "block")]);
    // 先查 allow：x.safe.com 命中 allow_wild
    assert_eq!(
        action_of(&e.match_rule("x.safe.com", false)),
        Some(Action::Allow)
    );
    assert_eq!(
        action_of(&e.match_rule("other.com", false)),
        Some(Action::Block)
    );
}

#[test]
fn regex_match() {
    let e = engine(vec![rule(r"re:^ads\..*", "block")]);
    assert_eq!(
        action_of(&e.match_rule("ads.x.com", false)),
        Some(Action::Block)
    );
    assert!(matches!(
        e.match_rule("notads.x.com", false),
        MatchOutcome::NoRule
    ));
}

#[test]
fn regex_search_unanchored() {
    // re: 用 search（非锚定）：子串命中即 block。
    let e = engine(vec![rule(r"re:ads\.x\.com", "block")]);
    assert_eq!(
        action_of(&e.match_rule("ads.x.com", false)),
        Some(Action::Block)
    );
    assert_eq!(
        action_of(&e.match_rule("prefix.ads.x.com", false)),
        Some(Action::Block)
    );
    assert!(matches!(
        e.match_rule("other.net", false),
        MatchOutcome::NoRule
    ));
}

#[test]
fn infix_wildcard_grouped() {
    // *ads.com：标签边界通配，命中 ads.com / x.ads.com，不命中 myads.com。
    let e = engine(vec![rule("*ads.com", "block")]);
    assert_eq!(
        action_of(&e.match_rule("ads.com", false)),
        Some(Action::Block)
    );
    assert_eq!(
        action_of(&e.match_rule("x.ads.com", false)),
        Some(Action::Block)
    );
    assert!(matches!(
        e.match_rule("myads.com", false),
        MatchOutcome::NoRule
    ));
}

#[test]
fn internal_wildcard_label_boundary() {
    // ads* → ^ads[^.]*$ ：命中 ads / ads1，不命中跨标签。
    let e = engine(vec![rule("ads*", "block")]);
    assert_eq!(action_of(&e.match_rule("ads", false)), Some(Action::Block));
    assert_eq!(action_of(&e.match_rule("ads1", false)), Some(Action::Block));
    assert!(matches!(e.match_rule("xads", false), MatchOutcome::NoRule));
}

#[test]
fn bare_star_blocks_all() {
    let e = engine(vec![rule("*", "block")]);
    assert_eq!(
        action_of(&e.match_rule("anything.foo", false)),
        Some(Action::Block)
    );
}

#[test]
fn force_ip_type() {
    let v = json!({"match":"forced.test","action":"forceIp","ip":"9.9.9.9"});
    let r = rule_from_json(v.as_object().unwrap().clone(), RuleSource::Local).unwrap();
    assert_eq!(r.ip.unwrap().to_string(), "9.9.9.9");
    assert_eq!(r.action, Action::ForceIp);
}

#[test]
fn force_ip_bad_ip_rejected() {
    let v = json!({"match":"f.test","action":"forceIp","ip":"not-an-ip"});
    assert!(rule_from_json(v.as_object().unwrap().clone(), RuleSource::Local).is_none());
}

#[test]
fn group_action_and_flag() {
    let e = engine(vec![rule("*.cn", "group")]);
    assert!(e.has_group_rules());
    assert_eq!(action_of(&e.match_rule("x.cn", false)), Some(Action::Group));
}

#[test]
fn group_flip_signal() {
    let e = RuleEngine::new();
    assert!(!e.has_group_rules());
    let r1 = e.rebuild(vec![]);
    assert!(!r1.group_flip);
    let r2 = e.rebuild(vec![rule("*.cn", "group")]);
    assert!(r2.group_flip); // 无 group → 有 group，必须清答案缓存
    let r3 = e.rebuild(vec![rule("*.cn", "group")]);
    assert!(!r3.group_flip); // 仍有 group，不翻转
}

#[test]
fn gen_increments_on_rebuild() {
    let e = engine(vec![rule("a.test", "block")]);
    let g0 = e.gen();
    e.rebuild(vec![rule("b.test", "block")]);
    assert_eq!(e.gen(), g0 + 1);
    // 新规则生效，旧规则消失
    assert!(matches!(
        e.match_rule("a.test", false),
        MatchOutcome::NoRule
    ));
    assert_eq!(
        action_of(&e.match_rule("b.test", false)),
        Some(Action::Block)
    );
}

#[test]
fn cache_invalidated_on_rebuild() {
    let e = engine(vec![rule("a.test", "block")]);
    // 先命中并写缓存
    assert_eq!(
        action_of(&e.match_rule("a.test", false)),
        Some(Action::Block)
    );
    // 重建（清空规则）
    e.rebuild(vec![]);
    assert!(matches!(
        e.match_rule("a.test", false),
        MatchOutcome::NoRule
    ));
}

#[test]
fn fast_path_uncertain_when_regex_present() {
    let e = engine(vec![rule(r"re:ads\.x", "block")]);
    // fast：字典类 miss 后进入正则阶段 → Uncertain，不毒化缓存
    assert!(matches!(
        e.match_rule("ads.x", true),
        MatchOutcome::Uncertain
    ));
    // 非 fast：完整求值
    assert_eq!(
        action_of(&e.match_rule("ads.x", false)),
        Some(Action::Block)
    );
}

#[test]
fn fast_path_caches_none_when_no_regex() {
    let e = engine(vec![rule("a.test", "block")]);
    // 无正则类规则：fast 可直接判定并缓存 None
    assert!(matches!(
        e.match_rule("other.test", true),
        MatchOutcome::NoRule
    ));
}

#[test]
fn malformed_regex_rejected() {
    // 畸形正则加载期拒绝（fail-closed 方向 = 不索引），rebuild 仍成功。
    let e = engine(vec![
        rule("re:[unclosed", "block"),
        rule("good.test", "block"),
    ]);
    // 坏正则被跳过；好规则仍在
    assert_eq!(
        action_of(&e.match_rule("good.test", false)),
        Some(Action::Block)
    );
    // 坏正则不生效
    assert!(matches!(
        e.match_rule("[unclosed", false),
        MatchOutcome::NoRule
    ));
}

#[test]
fn empty_re_body_rejected() {
    let v = json!({"match":"re:","action":"block"});
    // rule_from_json 本身不拒空 re:，建索引侧拒绝。
    let r = rule_from_json(v.as_object().unwrap().clone(), RuleSource::Local).unwrap();
    let e = engine(vec![r]);
    assert!(matches!(
        e.match_rule("anything", false),
        MatchOutcome::NoRule
    ));
}

#[test]
fn normalize_old_field_names() {
    // pattern -> match, value -> ip (forceIp)
    let v = json!({"pattern":"old.test","action":"forceIp","value":"8.8.8.8"});
    let r = rule_from_json(v.as_object().unwrap().clone(), RuleSource::Local).unwrap();
    assert_eq!(r.match_raw, "old.test");
    assert_eq!(r.ip.unwrap().to_string(), "8.8.8.8");
}

#[test]
fn normalize_value_to_group() {
    let v = json!({"pattern":"*.cn","action":"group","value":"domestic"});
    let r = rule_from_json(v.as_object().unwrap().clone(), RuleSource::Local).unwrap();
    assert_eq!(r.group.as_deref(), Some("domestic"));
}

#[test]
fn local_and_sub_merged_local_first() {
    // 本地先加载占位；同桶同域名 setdefault 本地胜出。本地 block 与订阅 block 同域 → block。
    let local = vec![rule("x.com", "block")];
    let sub = vec![rule("x.com", "block"), rule("sub-only.com", "block")];
    let e = RuleEngine::new();
    e.rebuild(local.into_iter().chain(sub).collect());
    assert_eq!(
        action_of(&e.match_rule("x.com", false)),
        Some(Action::Block)
    );
    // 订阅独有域名也生效
    assert_eq!(
        action_of(&e.match_rule("sub-only.com", false)),
        Some(Action::Block)
    );
}

#[test]
fn grace_period() {
    use std::time::{Duration, Instant};
    let e = RuleEngine::with_options(1024, Duration::from_secs(3));
    e.rebuild(vec![rule("a.test", "block")]);
    // 刚重建：在宽限期内
    assert!(e.in_grace_at(Instant::now()));
    // 4 秒后：超出宽限期
    let later = Instant::now() + Duration::from_secs(4);
    assert!(!e.in_grace_at(later));
}

#[test]
fn rule_label_format() {
    let r = rule("*.ads.com", "block");
    assert_eq!(rule_label(&r), "屏蔽 *.ads.com");
    let r = rule("x.test", "allow");
    assert_eq!(rule_label(&r), "放行 x.test");
    let v = json!({"match":"*.cn","action":"group","group":"domestic"});
    let r = rule_from_json(v.as_object().unwrap().clone(), RuleSource::Local).unwrap();
    assert_eq!(rule_label(&r), "国内 *.cn");
}
