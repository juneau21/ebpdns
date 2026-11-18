//! **阶段 B-2（RRset 对象级缓存）**：命中组装的**逐字节**回归。
//!
//! 旧实现（阶段 B-1）在 `answer_fast_into` 里先把 `entry.answers` 收集成
//! `Vec<AnswerInput>` 再交给 `build_udp_response_into`；B-2 直接遍历
//! `entry.rrsets`（嵌套循环、栈上 `[AnswerInput; MAX_ANSWERS]`、不分配中间 Vec）。
//!
//! 本文件把**旧实现的输出**（用 `flat_answers()` 逐条构造 `AnswerInput` 后调
//! `build_udp_response`）当作基线，与**新实现**（`answer_fast_into`）的输出逐字节
//! 比较 —— 覆盖 CNAME + A 链的 owner 名、TTL、EDNS/非 EDNS、以及 >MAX_ANSWERS
//! 时的截断/TC 行为。

use std::sync::Arc;

use ebpdns_cache::{rrset, CacheAnswer, CacheEntry, DnsCache};
use ebpdns_proto::constants::{MAX_ANSWERS, TYPE_A, TYPE_CNAME};
use ebpdns_proto::edns::question_edns_info;
use ebpdns_proto::query::build_query;
use ebpdns_proto::record::AnswerInput;
use ebpdns_proto::response::{build_udp_response, UdpResp};
use ebpdns_resolver::answer::FastKind;
use ebpdns_resolver::clock::MockClock;
use ebpdns_resolver::config::{ResolverConfig, UpstreamCfg};
use ebpdns_resolver::query::ScriptedQuerier;
use ebpdns_resolver::telemetry::NoopTelemetry;
use ebpdns_resolver::Resolver;

const NOW: f64 = 1_700_000_000.0;

/// `ResolverConfig::test_default` 的 EDNS UDP 上限（与 `answer_fast_into` 的
/// `client_cap.min(u16::MAX)` 同口径）。显式写下来，基线侧才能构造同一个 `UdpResp`。
const EDNS_UDP_SIZE: u16 = 1232;

fn resolver() -> Arc<Resolver> {
    let cfg = ResolverConfig::test_default(vec![UpstreamCfg::test_up("u1")], vec![], 1);
    assert_eq!(cfg.edns_udp_size, u32::from(EDNS_UDP_SIZE));
    Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(NOW)),
        Arc::new(ScriptedQuerier::new(|_, _, _| Vec::new())),
    )
}

fn ca(value: &str, ttl: f64, rtype: u16, name: Option<&str>) -> CacheAnswer {
    CacheAnswer::new(value, ttl, rtype, name.map(Arc::from))
}

/// 把一条 CNAME + A 链播种进缓存；`extra_a` 控制 A 记录条数（测截断用）。
fn seed(r: &Resolver, domain: &str, extra_a: usize) -> Vec<CacheAnswer> {
    let alias = "cdn.rrset-b2.test";
    let owner = "edge.rrset-b2.test";
    let mut flat = vec![
        // 查询名 → CNAME（owner = 查询名 ⇒ name=None）
        ca(alias, 300.0, TYPE_CNAME, None),
        // 链中一跳（owner = 别名）
        ca(owner, 300.0, TYPE_CNAME, Some(alias)),
    ];
    for i in 0..extra_a {
        flat.push(ca(
            &format!("192.0.2.{}", i + 1),
            300.0,
            TYPE_A,
            Some(owner),
        ));
    }
    let key = r.ckey(domain, "A");
    let entry = CacheEntry {
        domain: domain.to_string(),
        qtype: "A".to_string(),
        rrsets: rrset::rrsets_from_flat(&flat),
        chosen: "192.0.2.1".to_string(),
        ttl: 300.0,
        rcode: 0,
        expires_at: NOW + 300.0,
        // 命中路径的规则门禁：必须与当前代际一致，否则会降级为 miss。
        rule_gen: r.rule_gen(),
        seq: 0,
    };
    r.cache().put(key, entry, NOW);
    flat
}

/// **旧实现基线**：用扁平 answers 逐条构造 `AnswerInput`，再走 `build_udp_response`。
///
/// 参数与 `answer_fast_into` 内完全一致（同一个 `UdpResp` 字段集）。
fn baseline_response(r: &Resolver, raw: &[u8], domain: &str) -> Vec<u8> {
    let key = r.ckey(domain, "A");
    let entry = r.cache().get_arc(&key, NOW).expect("基线：缓存必须命中");
    // 与 answer_fast_into 同口径：ttl_max=0（test_default）⇒ 不封顶。
    let ttl_left = (entry.expires_at - NOW).clamp(0.0, 2_147_483_647.0);
    let flat = entry.flat_answers();
    let inputs: Vec<AnswerInput> = flat
        .iter()
        .map(|a| AnswerInput {
            rtype: a.rtype,
            value: a.value.as_ref(),
            ttl: Some(ttl_left as u32),
            name: a.name.as_deref(),
        })
        .collect();
    let info = question_edns_info(raw);
    build_udp_response(&UdpResp {
        raw_query: raw,
        qbytes: info.qbytes.as_deref(),
        answers: &inputs,
        rcode: 0,
        abody: None,
        abody_count: None,
        owner_name: Some(domain),
        fallback_type: TYPE_A,
        ttl_override: None,
        bufsize_cap: Some(EDNS_UDP_SIZE),
        force_truncated: false,
        enc_owner: None,
        edns_info: Some(&info),
    })
    .expect("基线响应必须可构造")
}

/// 用新实现（`answer_fast_into`）产出响应，并断言与旧实现基线**逐字节相同**。
fn assert_fast_matches_baseline(domain: &str, edns: Option<u16>) -> Vec<u8> {
    let r = resolver();
    let flat = seed(&r, domain, 2);
    let (raw, _) = build_query(
        domain,
        TYPE_A,
        None,
        edns.is_some(),
        None,
        edns.map(u32::from),
        false,
    )
    .expect("构造查询失败");
    let mut out = Vec::new();
    let kind = r
        .answer_fast_into(&raw, &mut out)
        .expect("命中缓存必须返回响应");
    assert_eq!(kind, FastKind::Cache, "缓存直答必须标记为 Cache");
    let expected = baseline_response(&r, &raw, domain);
    assert_eq!(
        out, expected,
        "B-2 命中组装必须与旧实现逐字节一致（domain={domain}, edns={edns:?}）"
    );
    // 顺带钉死：消息里的 owner 名确实来自 RRset（CNAME 链逐跳）。
    let msg = ebpdns_proto::message::parse_message(&out).expect("解析响应");
    assert_eq!(msg.answers.len(), flat.len());
    assert_eq!(msg.answers[0].rtype, TYPE_CNAME);
    assert_eq!(
        msg.answers[0].rdata_str().trim_end_matches('.'),
        "cdn.rrset-b2.test"
    );
    assert_eq!(
        msg.answers[1].rdata_str().trim_end_matches('.'),
        "edge.rrset-b2.test"
    );
    assert_eq!(
        msg.answers[1].name.trim_end_matches('.'),
        "cdn.rrset-b2.test"
    );
    assert_eq!(
        msg.answers[2].name.trim_end_matches('.'),
        "edge.rrset-b2.test"
    );
    out
}

/// 普通（非 EDNS）查询：CNAME + A 命中组装逐字节一致。
#[test]
fn fast_path_assembly_matches_flat_baseline_without_edns() {
    let out = assert_fast_matches_baseline("rrset-b2.test", None);
    assert!(!out.is_empty());
}

/// EDNS（DO=0、bufsize=1232）查询：OPT 回显路径也逐字节一致。
#[test]
fn fast_path_assembly_matches_flat_baseline_with_edns() {
    assert_fast_matches_baseline("rrset-b2-edns.test", Some(1232));
}

/// >`MAX_ANSWERS` 条答案：新实现必须与旧实现一样**只编码前 8 条并置 TC**。
#[test]
fn fast_path_truncation_matches_flat_baseline() {
    let domain = "rrset-b2-trunc.test";
    let r = resolver();
    let flat = seed(&r, domain, MAX_ANSWERS + 4);
    assert!(flat.len() > MAX_ANSWERS);
    let (raw, _) = build_query(domain, TYPE_A, None, false, None, None, false).unwrap();
    let mut out = Vec::new();
    r.answer_fast_into(&raw, &mut out).expect("命中");
    let expected = baseline_response(&r, &raw, domain);
    assert_eq!(out, expected, "截断/TC 行为必须与旧实现逐字节一致");
    let msg = ebpdns_proto::message::parse_message(&out).expect("解析响应");
    assert_eq!(
        msg.answers.len(),
        MAX_ANSWERS,
        "超过 MAX_ANSWERS 的部分必须被截断"
    );
    assert!(msg.truncated, "超过 MAX_ANSWERS 必须置 TC（与旧实现一致）");
}
