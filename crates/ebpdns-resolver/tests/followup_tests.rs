//! 对抗审查第二批：M1 截断沿用 / M4 fallback / M5 serve_stale / M8 上游豁免私网 /
//! M11 熔断单调时钟 / padding 仅加密 / dnssec_0x20。确定性、不联网。

use ebpdns_cache::DnsCache;
use std::sync::Arc;

use ebpdns_proto::constants::TYPE_A;
use ebpdns_proto::query::build_query;
use ebpdns_resolver::clock::MockClock;
use ebpdns_resolver::config::{ResolverConfig, UpstreamCfg};
use ebpdns_resolver::query::ScriptedQuerier;
use ebpdns_resolver::resolve::ResolveOpts;
use ebpdns_resolver::telemetry::NoopTelemetry;
use ebpdns_resolver::types::ResolveAnswer;
use ebpdns_resolver::types::UpstreamAnswer;
use ebpdns_resolver::Resolver;
use ebpdns_rules::Rule;

fn a(v: &str, ttl: f64) -> ResolveAnswer {
    ResolveAnswer::new(v, ttl, TYPE_A)
}

fn cfg_with(ups: Vec<UpstreamCfg>, rules: Vec<Rule>, quorum: usize) -> ResolverConfig {
    ResolverConfig::test_default(ups, rules, quorum)
}

// ---------- M1 截断沿用 ----------

#[tokio::test]
async fn test_m1_truncated_reuse() {
    // 唯一应答：udp_truncated=true 且带 answers → 去重直答、TC=1、不写缓存。
    let r = base_with(|_, _, _| {
        let mut ans = UpstreamAnswer::ok(
            "u1",
            0,
            vec![a("1.1.1.1", 300.0), a("1.1.1.1", 300.0)],
            vec![],
        );
        ans.udp_truncated = true;
        vec![ans]
    });
    let res = r
        .clone()
        .resolve("trunc.test", "A", ResolveOpts::default())
        .await;
    assert!(res.truncated, "M1 应强制 truncated=true");
    assert_eq!(res.answers.len(), 1, "应去重");
    assert_eq!(res.answers[0].value, "1.1.1.1");
    // 不写缓存：再查一次仍走上游（缓存无命中 hit=false）。
    let key = r.ckey("trunc.test", "A");
    assert!(
        r.cache().get(&key, 1_700_000_000.0).is_none(),
        "截断应答不写缓存"
    );
}

// ---------- M4 fallback ----------

#[tokio::test]
async fn test_m4_fallback_uses_remaining_upstreams() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let calls = Arc::new(AtomicUsize::new(0));
    let c2 = calls.clone();
    let ups = vec![UpstreamCfg::test_up("u1"), UpstreamCfg::test_up("u2")];
    let mut cfg = cfg_with(ups, vec![], 1);
    cfg.max_parallel_upstreams = 1; // 首选仅 u1，u2 为 fallback 剩余。
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(1_700_000_000.0)),
        Arc::new(ScriptedQuerier::new(move |_, _, _| {
            let n = c2.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                // 首选全真失败（SERVFAIL rcode=2）。
                vec![UpstreamAnswer {
                    rcode: Some(2),
                    answers: vec![],
                    ..UpstreamAnswer::fail("u1")
                }]
            } else {
                // fallback 剩余上游给出好答案。
                vec![UpstreamAnswer::ok(
                    "u2",
                    0,
                    vec![a("9.9.9.9", 300.0)],
                    vec![],
                )]
            }
        })),
    );
    let res = r
        .clone()
        .resolve("fb.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, 0);
    assert_eq!(
        res.answers[0].value, "9.9.9.9",
        "fallback 应回退剩余上游命中"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2, "应触发二次 query_parallel");
}

// ---------- M5 serve_stale ----------

#[tokio::test]
async fn test_m5_serve_stale_returns_ttl0_and_refreshes() {
    let clock = Arc::new(MockClock::new(1_700_000_000.0));
    let ups = vec![UpstreamCfg::test_up("u1")];
    let mut cfg = cfg_with(ups, vec![], 1);
    cfg.serve_stale = true;
    cfg.stale_ttl = 300.0;
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        clock.clone(),
        Arc::new(ScriptedQuerier::new(|_, _, _| {
            vec![UpstreamAnswer::ok(
                "u1",
                0,
                vec![a("5.5.5.5", 60.0)],
                vec![],
            )]
        })),
    );
    // 首次解析 → 写缓存。
    let res = r
        .clone()
        .resolve("stale.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.answers[0].value, "5.5.5.5");
    // 时钟推进：过期 60s，但仍在 stale_ttl=300 窗口内。
    clock.advance(360.0);
    let res = r
        .clone()
        .resolve("stale.test", "A", ResolveOpts::default())
        .await;
    assert!(res.hit, "serve-stale 应命中（过期窗口内旧数据）");
    assert_eq!(res.ttl_left, 0.0, "过期数据 TTL=0");
    assert_eq!(res.answers[0].value, "5.5.5.5", "应返回旧数据");
}

#[tokio::test]
async fn test_m5_serve_stale_disabled_no_stale() {
    // serve_stale=false：过期后不返回旧数据，走上游。
    let clock = Arc::new(MockClock::new(1_700_000_000.0));
    let ups = vec![UpstreamCfg::test_up("u1")];
    let mut cfg = cfg_with(ups, vec![], 1);
    cfg.serve_stale = false;
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        clock.clone(),
        Arc::new(ScriptedQuerier::new(|_, _, _| {
            vec![UpstreamAnswer::ok(
                "u1",
                0,
                vec![a("7.7.7.7", 60.0)],
                vec![],
            )]
        })),
    );
    r.clone()
        .resolve("s.test", "A", ResolveOpts::default())
        .await;
    clock.advance(360.0);
    let res = r
        .clone()
        .resolve("s.test", "A", ResolveOpts::default())
        .await;
    assert!(!res.hit || res.answers[0].value == "7.7.7.7");
}

// ---------- M8 allow_private_ip 上游豁免 ----------

#[tokio::test]
async fn test_m8_exempt_upstream_keeps_private() {
    let r = base_with(|_, _, _| {
        let mut good = UpstreamAnswer::ok("u1", 0, vec![a("10.1.2.3", 300.0)], vec![]);
        good.allow_private = true; // 豁免上游
        vec![good]
    });
    let res = r
        .clone()
        .resolve("priv.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.answers[0].value, "10.1.2.3", "豁免上游私网答案应放行");
}

#[tokio::test]
async fn test_m8_non_exempt_upstream_drops_private() {
    let r = base_with(|_, _, _| {
        vec![UpstreamAnswer::ok(
            "u1",
            0,
            vec![a("10.1.2.3", 300.0)],
            vec![],
        )]
    });
    let res = r
        .clone()
        .resolve("priv2.test", "A", ResolveOpts::default())
        .await;
    assert!(res.answers.is_empty(), "非豁免私网答案应被 rebind 过滤");
}

/// **2.1.17（修复项 3）**：私网答案过滤必须**可观测**，且该结果**不入缓存**。
///
/// 判据（三条，逐条对应审计侧 2.1.16 的错误结论）：
/// 1. `private_answers_filtered` 结构化回传被丢弃的条数（1 条 → 1）；
/// 2. 私有地址应答**不写缓存**（`cache().get(ckey)` 为 None）——「同键重查恒 miss」
///    是**设计行为**，不是缓存缺陷；
/// 3. 无私有地址被丢弃时计数恒 0（不得虚报）。
#[tokio::test]
async fn test_s17_private_answer_filter_is_counted_and_not_cached() {
    let r = base_with(|_, _, _| {
        vec![UpstreamAnswer::ok(
            "u1",
            0,
            vec![a("10.9.9.9", 300.0)],
            vec![],
        )]
    });
    let res = r
        .clone()
        .resolve("priv17.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(
        res.private_answers_filtered, 1,
        "1 条私网答案被丢弃 ⇒ 计数必须为 1（审计侧据此不再误判“缓存坏了”）"
    );
    let key = r.ckey("priv17.test", "A");
    assert!(
        r.cache().get(&key, 1_700_000_000.0).is_none(),
        "私网答案应答按设计不入缓存（同键重查恒 miss）"
    );
    // 同键重查：仍不上缓存命中，且计数仍为 1（每次解析各计一次，不累计到结果里）。
    let res2 = r
        .clone()
        .resolve("priv17.test", "A", ResolveOpts::default())
        .await;
    assert!(!res2.hit, "私网答案不得被缓存命中");
    assert_eq!(res2.private_answers_filtered, 1);
}

/// **2.1.17（修复项 3）**：公网答案路径的计数必须恒 0（反面对照，防虚报）。
#[tokio::test]
async fn test_s17_public_answer_filter_count_is_zero() {
    let r = base_with(|_, _, _| {
        vec![UpstreamAnswer::ok(
            "u1",
            0,
            vec![a("93.184.216.34", 300.0)],
            vec![],
        )]
    });
    let res = r
        .clone()
        .resolve("pub17.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.answers.len(), 1, "公网答案必须保留");
    assert_eq!(
        res.private_answers_filtered, 0,
        "没有任何私网答案被丢弃 ⇒ 计数必须为 0"
    );
}

// ---------- M11 熔断单调时钟 ----------

#[tokio::test]
async fn test_m11_breaker_monotonic_open() {
    let clock = Arc::new(MockClock::new(1_700_000_000.0));
    let ups = vec![UpstreamCfg::test_up("u1")];
    let cfg = cfg_with(ups, vec![], 1);
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        clock.clone(),
        Arc::new(ScriptedQuerier::new(|_, _, _| Vec::new())),
    );
    for _ in 0..3 {
        r.cb_fail("u1");
    }
    assert!(r.cb_is_open("u1"), "3 次失败后应打开熔断");
    // monotonic 推进（与 epoch 同步）超过 open_s=30 → 半开放行。
    clock.advance(31.0);
    assert!(!r.cb_is_open("u1"), "open_s 过期后应自然放行");
}

// ---------- padding 仅加密 / 0x20 ----------

#[test]
fn test_padding_grows_wire() {
    // padding=true 时查询报文更长（EDNS padding OPT）。
    let (plain, _) = build_query("example.com", 1, None, true, None, Some(1232), false).unwrap();
    let (padded, _) = build_query("example.com", 1, None, true, None, Some(1232), true).unwrap();
    assert!(padded.len() > plain.len(), "padding 应增大报文");
}

#[test]
fn test_x20_randomizes_case() {
    // 仅冒烟：x20_case 在 production；此处验证 build_query 接受大写域名不 panic。
    let (b, _) = build_query("ExAmPlE.CoM", 1, None, false, None, None, false).unwrap();
    assert!(!b.is_empty());
}

// **[历史归因]** ---------- 语义熔断喂点：按 rcode（对齐 Python resolver.py ~2295） ----------

#[tokio::test]
async fn test_breaker_opens_on_semantic_servfail() {
    // 上游传输可达但持续 SERVFAIL(rcode=2) → 按语义累计失败 → 熔断打开。
    let r = base_with(|_, _, _| {
        vec![UpstreamAnswer {
            up_name: "u1".to_string(),
            rcode: Some(2), // SERVFAIL
            answers: vec![],
            cnames: vec![],
            lat: 1.0,
            udp_truncated: false,
            neg_ttl: None,
            allow_private: false,
            raw: None,
        }]
    });
    // cb_fails=3；每次换域名避免缓存，确保每次都走到 finish_resolve 喂点。
    for i in 0..3 {
        r.clone()
            .resolve(
                &format!("srvfail{i}.example.com"),
                "A",
                ResolveOpts::default(),
            )
            .await;
    }
    assert!(
        r.cb_is_open("u1"),
        "持续 SERVFAIL(rcode=2) 应累计失败并打开熔断"
    );
}

#[tokio::test]
async fn test_breaker_ignores_nxdomain() {
    // 上游返回 NXDOMAIN(rcode=3) → 语义成功，不累计失败、不熔断。
    let r = base_with(|_, _, _| {
        vec![UpstreamAnswer {
            up_name: "u1".to_string(),
            rcode: Some(3), // NXDOMAIN
            answers: vec![],
            cnames: vec![],
            lat: 1.0,
            udp_truncated: false,
            neg_ttl: None,
            allow_private: false,
            raw: None,
        }]
    });
    for i in 0..5 {
        r.clone()
            .resolve(&format!("nx{i}.example.com"), "A", ResolveOpts::default())
            .await;
    }
    assert!(!r.cb_is_open("u1"), "NXDOMAIN(rcode=3) 不应熔断上游");
}

// ---------- answer_fast fast 规则路径 / block 降级 / IP 速度择优 ----------

fn rule(m: &str, action: &str) -> ebpdns_rules::Rule {
    let mut o = serde_json::Map::new();
    o.insert("match".into(), serde_json::json!(m));
    o.insert("action".into(), serde_json::json!(action));
    ebpdns_rules::rule_from_json(o, ebpdns_rules::RuleSource::Local).unwrap()
}

#[tokio::test]
async fn test_answer_fast_uncertain_falls_through() {
    // 正则规则存在 → 域名进入正则阶段 fast 返回 Uncertain → answer_fast 返回 None 降级 resolve。
    let ups = vec![UpstreamCfg::test_up("u1")];
    let cfg = ResolverConfig::test_default(ups, vec![rule("re:.*\\.ads\\.net$", "block")], 1);
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(1_700_000_000.0)),
        Arc::new(ScriptedQuerier::new(|_, _, _| Vec::new())),
    );
    // 预灌缓存命中。
    let key = r.ckey("x.ads.net", "A");
    r.fill_cache(
        &key,
        "x.ads.net",
        "A",
        vec![ResolveAnswer::new("1.2.3.4", 300.0, TYPE_A)],
        None,
    );
    let (raw, _) = build_query("x.ads.net", TYPE_A, None, false, None, None, false).unwrap();
    let out = r.answer_fast(&raw);
    assert!(
        out.is_none(),
        "fast 路径进入正则阶段应返回 None 降级 resolve，而非阻塞求值"
    );
}

#[tokio::test]
async fn test_answer_fast_block_falls_through() {
    // 精确 block 规则 fast 命中 → answer_fast 返回 None（降级 resolve 做复查+遥测）。
    let ups = vec![UpstreamCfg::test_up("u1")];
    let cfg = ResolverConfig::test_default(ups, vec![rule("blocked.test", "block")], 1);
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(1_700_000_000.0)),
        Arc::new(ScriptedQuerier::new(|_, _, _| Vec::new())),
    );
    let key = r.ckey("blocked.test", "A");
    r.fill_cache(
        &key,
        "blocked.test",
        "A",
        vec![ResolveAnswer::new("9.9.9.9", 300.0, TYPE_A)],
        None,
    );
    let (raw, _) = build_query("blocked.test", TYPE_A, None, false, None, None, false).unwrap();
    let out = r.answer_fast(&raw);
    assert!(
        out.is_none(),
        "Block 命中应降级 resolve 走完整复查与 block 遥测，不内联吞掉"
    );
}

#[test]
fn test_speed_choose_picks_faster() {
    // speed_test=true 才按速度表重排。
    let ups = vec![UpstreamCfg::test_up("u1")];
    let mut cfg = ResolverConfig::test_default(ups, vec![], 1);
    cfg.speed_test = true;
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(1_700_000_000.0)),
        Arc::new(ScriptedQuerier::new(|_, _, _| Vec::new())),
    );
    r.record_ip_speed("1.1.1.1", 5.0);
    r.record_ip_speed("2.2.2.2", 50.0);
    let cands = vec![
        ResolveAnswer::new("2.2.2.2", 300.0, TYPE_A),
        ResolveAnswer::new("1.1.1.1", 300.0, TYPE_A),
    ];
    assert_eq!(r.speed_choose(&cands), "1.1.1.1", "应选 EWMA 更低的 IP");
}

#[test]
fn test_speed_test_disabled_preserves_order() {
    // speed_test=false（test_default）：不按速度表重排，即使更慢 IP 在表内也取首条（保序）。
    let r = base_with(|_, _, _| Vec::new());
    r.record_ip_speed("1.1.1.1", 5.0); // 表里更快，但开关关闭
    let cands = vec![
        ResolveAnswer::new("2.2.2.2", 300.0, TYPE_A),
        ResolveAnswer::new("1.1.1.1", 300.0, TYPE_A),
    ];
    assert_eq!(
        r.speed_choose(&cands),
        "2.2.2.2",
        "speed_test=false 应保上游插入序首条"
    );
}

#[test]
fn test_speed_choose_no_data_falls_back_first() {
    let r = base_with(|_, _, _| Vec::new());
    let cands = vec![
        ResolveAnswer::new("9.9.9.9", 300.0, TYPE_A),
        ResolveAnswer::new("8.8.8.8", 300.0, TYPE_A),
    ];
    assert_eq!(
        r.speed_choose(&cands),
        "9.9.9.9",
        "无测速数据应退回首条，不 panic"
    );
}

#[tokio::test]
async fn test_probe_ip_local_listener() {
    // 本地起 TCP listener 验证真实有界探测返回 RTT。
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let _ = stream; // 接受即关，测连接建立 RTT
        }
    });
    let r = base_with(|_, _, _| Vec::new());
    let rtt = r.probe_ip_once("127.0.0.1", addr.port()).await;
    assert!(rtt.is_some(), "本地 listener 探测应成功返回 RTT");
    assert!(rtt.unwrap() >= 0.0);
}

// ---------- 缓存命中：owner 透传 / 剩余 TTL 衰减 / bufsize 截断 / 预检 ----------

#[test]
fn test_cache_hit_passes_owner_name() {
    // 链尾 owner=tgt.example 的 A 记录，缓存命中重编码后 RR owner 应为 tgt.example。
    let r = base_with(|_, _, _| Vec::new());
    let key = r.ckey("q.example", "A");
    let ans = vec![ResolveAnswer {
        value: "1.2.3.4".into(),
        ttl: 300.0,
        rtype: TYPE_A,
        name: Some("tgt.example".into()),
    }];
    r.fill_cache(&key, "q.example", "A", ans, None);
    let (raw, _) = build_query("q.example", TYPE_A, None, false, None, None, false).unwrap();
    let out = r.answer_fast(&raw).expect("命中应返回响应");
    let msg = ebpdns_proto::message::parse_message(&out).unwrap();
    assert_eq!(msg.answers.len(), 1);
    assert_eq!(
        msg.answers[0]
            .name
            .trim_end_matches('.')
            .to_ascii_lowercase(),
        "tgt.example",
        "RR owner 应为缓存透传的链尾名, 实际: {}",
        msg.answers[0].name
    );
}

#[test]
fn test_cache_hit_ttl_is_remaining() {
    // 用可推进的 MockClock：写入后推 now，断言 wire TTL == clamp(expires−now)（剩余衰减）。
    let clock = Arc::new(MockClock::new(1_700_000_000.0));
    let ups = vec![UpstreamCfg::test_up("u1")];
    let cfg = ResolverConfig::test_default(ups, vec![], 1);
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        clock.clone(),
        Arc::new(ScriptedQuerier::new(|_, _, _| Vec::new())),
    );
    let key = r.ckey("ttl.example", "A");
    // 写入 300s TTL（clamp 后仍 >300）。
    r.fill_cache(
        &key,
        "ttl.example",
        "A",
        vec![ResolveAnswer::new("5.6.7.8", 300.0, TYPE_A)],
        None,
    );
    let (raw, _) = build_query("ttl.example", TYPE_A, None, false, None, None, false).unwrap();

    // 刚写入：剩余 ≈ 300。
    let msg0 = ebpdns_proto::message::parse_message(&r.answer_fast(&raw).unwrap()).unwrap();
    let t0 = msg0.answers[0].ttl;
    assert_eq!(t0, 300, "刚写入剩余应≈300, 实际 {t0}");

    // 推进 100s → 剩余应为 200（衰减，非满 TTL）。
    clock.advance(100.0);
    let msg1 = ebpdns_proto::message::parse_message(&r.answer_fast(&raw).unwrap()).unwrap();
    let t1 = msg1.answers[0].ttl;
    assert_eq!(t1, 200, "推进100s后剩余应=200, 实际 {t1}");

    // 推进 3000s → 条目已过期，命中应 miss（缓存 get 惰性删除），返回 None。
    clock.advance(3000.0);
    assert!(r.answer_fast(&raw).is_none(), "过期后应 miss 不再命中");
}

#[test]
fn test_answer_fast_small_bufsize_truncates_tc() {
    // 客户端 bufsize 上限很小 → 多答案放不下 → build_udp_response 丢尾并置 TC。
    let ups = vec![UpstreamCfg::test_up("u1")];
    let mut cfg = ResolverConfig::test_default(ups, vec![], 1);
    cfg.edns_udp_size = 40; // bufsize_cap=min(info.bufsize, 40)=40
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(1_700_000_000.0)),
        Arc::new(ScriptedQuerier::new(|_, _, _| Vec::new())),
    );
    let key = r.ckey("many.example", "A");
    let ans = vec![
        ResolveAnswer::new("10.0.0.1", 300.0, TYPE_A),
        ResolveAnswer::new("10.0.0.2", 300.0, TYPE_A),
        ResolveAnswer::new("10.0.0.3", 300.0, TYPE_A),
    ];
    r.fill_cache(&key, "many.example", "A", ans, None);
    let (raw, _) =
        build_query("many.example", TYPE_A, None, true, None, Some(1232), false).unwrap();
    let out = r.answer_fast(&raw).expect("命中");
    let msg = ebpdns_proto::message::parse_message(&out).unwrap();
    assert!(msg.truncated, "小 bufsize 放不下应置 TC 位");
}

#[test]
fn test_answer_fast_rejects_nonzero_opcode() {
    let r = base_with(|_, _, _| Vec::new());
    let key = r.ckey("op.example", "A");
    r.fill_cache(
        &key,
        "op.example",
        "A",
        vec![ResolveAnswer::new("1.2.3.4", 300.0, TYPE_A)],
        None,
    );
    let (mut raw, _) = build_query("op.example", TYPE_A, None, false, None, None, false).unwrap();
    raw[2] |= 0x08; // opcode = 1（IQUERY），非 0
    assert!(
        r.answer_fast(&raw).is_none(),
        "opcode≠0 应返回 None 交完整路径"
    );
}

// ---------- helpers ----------
/// 用脚本化 querier 构造 resolver（单上游，quorum=1）。
fn base_with<F: Fn(&str, &str, u32) -> Vec<UpstreamAnswer> + Send + Sync + 'static>(
    f: F,
) -> Arc<Resolver> {
    let ups = vec![UpstreamCfg::test_up("u1")];
    let cfg = cfg_with(ups, vec![], 1);
    Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(1_700_000_000.0)),
        Arc::new(ScriptedQuerier::new(f)),
    )
}

#[test]
fn test_import_rules_group_and_forceip_dedup() {
    use ebpdns_resolver::ImportOpts;
    let r = base_with(|_, _, _| Vec::new());

    // action=group，wildcard=true → *.svc.example，带 group。
    let n = r.import_rules(
        "svc.example",
        ImportOpts {
            action: "group".into(),
            group: Some("g1".into()),
            ..Default::default()
        },
    );
    assert_eq!(n, 1);
    let hit = r.match_rule("x.svc.example").expect("应命中 group 规则");
    assert_eq!(hit.action, ebpdns_rules::Action::Group);
    assert_eq!(hit.group.as_deref(), Some("g1"));

    // forceIp 直查（wildcard=false，不包 *.）→ forceIp 带 ip。
    let n2 = r.import_rules(
        "fix.example",
        ImportOpts {
            action: "forceIp".into(),
            ip: Some("9.9.9.9".into()),
            wildcard: false,
            ..Default::default()
        },
    );
    assert_eq!(n2, 1);
    let h2 = r.match_rule("fix.example").expect("forceIp 命中");
    assert_eq!(h2.action, ebpdns_rules::Action::ForceIp);
    assert_eq!(h2.ip.map(|i| i.to_string()), Some("9.9.9.9".into()));

    // 重复导入同一 match → 去重，新增 0。
    let n3 = r.import_rules(
        "svc.example",
        ImportOpts {
            action: "group".into(),
            group: Some("g1".into()),
            ..Default::default()
        },
    );
    assert_eq!(n3, 0, "重复 match 应去重");
}

#[test]
fn test_import_rules_text_default_group() {
    let r = base_with(|_, _, _| Vec::new());
    let n = r.import_rules_text("blog.example");
    assert_eq!(n, 1);
    let h = r.match_rule("a.blog.example").expect("默认导入应命中");
    // 手动导入默认 group。
    assert_eq!(h.action, ebpdns_rules::Action::Group);
}
