//! 对抗审查新增行为的确定性测试：bailiwick 锚定、FORMERR、neg_ttl 钳制、
//! chosen 反向、prefetch 上界、默认值契约。

use std::sync::Arc;

use ebpdns_proto::constants::{RCODE_FORMERR, TYPE_A, TYPE_CNAME};
use ebpdns_proto::query::build_query;
use ebpdns_proto::record::AnswerInput;
use ebpdns_proto::response::{build_response_body_answers, build_response_header};
use ebpdns_resolver::clock::MockClock;
use ebpdns_resolver::config::{ResolverConfig, UpstreamCfg};
use ebpdns_resolver::query::{classify_one, ScriptedQuerier};
use ebpdns_resolver::resolve::ResolveOpts;
use ebpdns_resolver::telemetry::NoopTelemetry;
use ebpdns_resolver::Resolver;

/// **2.1.46（REV247 B P2-9）**：上游 TTL=0 必须保留为 0（旧实现 `max(1)` 抬到 1s）。
///
/// 判别力：旧实现下 A 记录 `ttl=1.0`、CNAME 链步 `ttl=1`，本用例必红。
#[test]
fn upstream_ttl_zero_is_not_rounded_up_to_one() {
    let ans = [AnswerInput {
        rtype: 1,
        value: "192.0.2.7",
        ttl: Some(0),
        name: Some("ttl0.example"),
    }];
    let got = classify_one(
        "u1",
        "ttl0.example",
        &make_resp("ttl0.example", &ans),
        1,
        0.0,
    );
    assert_eq!(got.answers.len(), 1);
    assert_eq!(got.answers[0].ttl, 0.0, "TTL=0 不得被抬成 1s");
    // CNAME 链步同样保留 0。
    let c = [AnswerInput {
        rtype: 5,
        value: "target.example",
        ttl: Some(0),
        name: Some("alias.example"),
    }];
    let got = classify_one(
        "u1",
        "alias.example",
        &make_resp("alias.example", &c),
        1,
        0.0,
    );
    assert_eq!(got.cnames, vec![("target.example".to_string(), 0)]);
}

fn base() -> Arc<Resolver> {
    let ups = vec![UpstreamCfg::test_up("u1")];
    Resolver::new(
        ResolverConfig::test_default(ups, vec![], 1),
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(1_700_000_000.0)),
        Arc::new(ScriptedQuerier::new(|_, _, _| Vec::new())),
    )
}

/// 构造一个响应字节：question=qname，answers 为给定 AnswerInput（可带任意 owner name）。
fn make_resp(qname: &str, answers: &[AnswerInput]) -> Vec<u8> {
    let (qbytes, _qid) = build_query(qname, 1, None, false, None, None, false).unwrap();
    let (abody, n) = build_response_body_answers(answers, Some(qname), 1, None, None);
    let header = build_response_header(&qbytes, 0, n as u16, false, 0).unwrap();
    // question 段 = qbytes 去掉前 12 字节头。
    let qsec = &qbytes[12..];
    let mut out = Vec::new();
    out.extend(header);
    out.extend(qsec);
    out.extend(abody);
    out
}

#[test]
fn test_bailiwick_rejects_forged_owner() {
    // 两条 A：owner=bank.example(合法) 与 owner=attacker.example(伪造)。
    let ans = [
        AnswerInput {
            rtype: 1,
            value: "1.1.1.1",
            ttl: Some(300),
            name: Some("bank.example"),
        },
        AnswerInput {
            rtype: 1,
            value: "2.2.2.2",
            ttl: Some(300),
            name: Some("attacker.example"),
        },
    ];
    let resp = make_resp("bank.example", &ans);
    let got = classify_one("up", "bank.example", &resp, TYPE_A, 1.0);
    assert_eq!(
        got.answers.len(),
        1,
        "伪造 owner 应被丢弃: {:?}",
        got.answers
    );
    assert_eq!(got.answers[0].value, "1.1.1.1");
}

#[test]
fn test_bailiwick_empty_owner_rejected() {
    // owner 为空（根 "."）→ 对非根查询恒拒绝。
    let ans = [AnswerInput {
        rtype: 1,
        value: "5.5.5.5",
        ttl: Some(300),
        name: Some(""),
    }];
    let resp = make_resp("bank.example", &ans);
    let got = classify_one("up", "bank.example", &resp, TYPE_A, 1.0);
    assert!(got.answers.is_empty(), "空 owner 应被拒绝");
}

#[tokio::test]
async fn test_formerr_long_label() {
    let r = base();
    let long = "a".repeat(64);
    let res = r
        .clone()
        .resolve(&format!("{long}.test"), "A", ResolveOpts::default())
        .await;
    assert_eq!(
        res.rcode, RCODE_FORMERR,
        "超长标签应 FORMERR: {}",
        res.rcode
    );
}

#[test]
fn test_default_values_contract() {
    let c = ResolverConfig::default();
    assert_eq!(c.circuit_fails, 3);
    assert_eq!(c.circuit_open_s, 30.0);
    assert_eq!(c.health_probe_domain, "www.baidu.com");
    assert_eq!(c.rule_sub_interval, 3600);
    assert!(c.cache_persist);
}

/// 构造响应字节，可指定 header 的 TC 位。
fn make_resp_tc(qname: &str, answers: &[AnswerInput], tc: bool) -> Vec<u8> {
    let (qbytes, _qid) = build_query(qname, 1, None, false, None, None, false).unwrap();
    let (abody, n) = build_response_body_answers(answers, Some(qname), 1, None, None);
    let header = build_response_header(&qbytes, 0, n as u16, tc, 0).unwrap();
    let qsec = &qbytes[12..];
    let mut out = Vec::new();
    out.extend(header);
    out.extend(qsec);
    out.extend(abody);
    out
}

#[test]
fn test_classify_reads_tc_bit() {
    let ans = [AnswerInput {
        rtype: 1,
        value: "1.1.1.1",
        ttl: Some(300),
        name: Some("bank.example"),
    }];
    // TC=1 字节 → udp_truncated=true。
    let tc_resp = make_resp_tc("bank.example", &ans, true);
    let got_tc = classify_one("up", "bank.example", &tc_resp, TYPE_A, 1.0);
    assert!(got_tc.udp_truncated, "TC=1 字节应解析为 udp_truncated");
    // 同一份 answers 仍被收集（截断沿用分支消费）。
    assert_eq!(got_tc.answers.len(), 1);

    // TC=0 字节 → udp_truncated=false。
    let ok_resp = make_resp_tc("bank.example", &ans, false);
    let got_ok = classify_one("up", "bank.example", &ok_resp, TYPE_A, 1.0);
    assert!(!got_ok.udp_truncated, "TC=0 字节不应置 udp_truncated");
}

#[test]
fn test_direct_cname_query_returns_cname_answer() {
    // 直查 CNAME：owner=alias.example 的 CNAME RR 指向 real.example。
    let ans = [AnswerInput {
        rtype: TYPE_CNAME,
        value: "real.example",
        ttl: Some(300),
        name: Some("alias.example"),
    }];
    let resp = make_resp_tc("alias.example", &ans, false);
    // want_qtype = CNAME → 该 CNAME RR 本身即答案，而非链步。
    let got = classify_one("up", "alias.example", &resp, TYPE_CNAME, 1.0);
    assert_eq!(got.answers.len(), 1, "直查 CNAME 应返回该 CNAME 记录");
    assert_eq!(got.answers[0].rtype, TYPE_CNAME);
    assert!(
        got.answers[0].value.trim_end_matches('.') == "real.example",
        "CNAME target 应为 real.example, 实际: {}",
        got.answers[0].value
    );
    assert!(got.cnames.is_empty(), "直查 CNAME 不应把它当链步");
}
