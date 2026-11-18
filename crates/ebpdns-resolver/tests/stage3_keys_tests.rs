//! **阶段 3-14：缓存键变体（DNSSEC / ECS）** —— 行为门禁。
//!
//! 判据（与 `docs/INTERFACE.md` / README 的键表口径一致）：
//! 1. `dnssec_cache_variants=true`（默认）时，**带 EDNS DO 位**的查询与**不带**的查询
//!    是**两条独立条目**：各自首次 miss、之后各自命中，互不串条目；
//! 2. `dnssec_cache_variants=false` 时**退回旧行为**：两者共用同一条条目
//!    （DO 查询直接命中非 DO 条目）；
//! 3. 预取按**原条目变体**重建键：DO 条目续期后仍是 DO 条目（不得被刷新成非 DO 键）；
//! 4. `ecs_cache_variants=true` **不分裂**缓存（ECS 未外发 ⇒ 键形态与 `false` 完全一致）。
//!
//! 说明：本文件的期望值来自"键变体"的**语义**（不是实现对实现的镜像）：两种查询必须
//! 不共用条目；配置关掉后必须共用 —— 任一侧反了都是串条目或回归。

use std::sync::Arc;

use ebpdns_cache::DnsCache;
use ebpdns_proto::constants::{TYPE_A, TYPE_OPT};
use ebpdns_resolver::clock::MockClock;
use ebpdns_resolver::config::{ResolverConfig, UpstreamCfg};
use ebpdns_resolver::query::ScriptedQuerier;
use ebpdns_resolver::resolve::ResolveOpts;
use ebpdns_resolver::telemetry::NoopTelemetry;
use ebpdns_resolver::types::{ResolveAnswer, UpstreamAnswer};
use ebpdns_resolver::Resolver;

const EPOCH: f64 = 1_700_000_000.0;

fn a(value: &str, ttl: f64) -> ResolveAnswer {
    ResolveAnswer::new(value, ttl, TYPE_A)
}

/// 测试基座：上游固定返回 `1.2.3.4 / TTL 300`；可配两个键变体开关与预取参数。
fn base(
    dnssec_cache_variants: bool,
    ecs_cache_variants: bool,
    prefetch: bool,
) -> (Arc<Resolver>, Arc<MockClock>) {
    let ups = vec![UpstreamCfg::test_up("u1"), UpstreamCfg::test_up("u2")];
    let mut cfg = ResolverConfig::test_default(ups, Vec::new(), 2);
    cfg.dnssec_cache_variants = dnssec_cache_variants;
    cfg.ecs_cache_variants = ecs_cache_variants;
    cfg.prefetch = prefetch;
    // 预取：让"剩余 TTL <= trigger"成立（短 TTL 播种条目才能被真的续期）。
    cfg.prefetch_trigger = 60_000.0;
    cfg.prefetch_target = 300.0;
    // 与本测试无关的后台行为一律关掉（确定性）。
    cfg.speed_test = false;
    cfg.ip_speed_check = false;
    cfg.serve_stale = false;
    let clock = Arc::new(MockClock::new(EPOCH));
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        clock.clone(),
        Arc::new(ScriptedQuerier::new(|_, _, _| {
            vec![UpstreamAnswer::ok(
                "u1",
                0,
                vec![a("1.2.3.4", 300.0)],
                vec![],
            )]
        })),
    );
    (r, clock)
}

/// 构造查询报文：`edns=true` 时可置 DO 位；`edns=false` 时**没有** OPT RR。
fn query(name: &str, edns: bool, do_bit: bool) -> Vec<u8> {
    let (mut q, _) =
        ebpdns_proto::query::build_query(name, TYPE_A, Some(0x4242), edns, None, Some(1232), false)
            .expect("build_query");
    if do_bit {
        assert!(edns, "DO 位只能出现在 EDNS 查询里");
        // additional 段最后一个 RR 是 OPT：末 11 字节 = name(1)+type(2)+class(2)+ttl(4)+rdlen(2)
        // ⇒ flags_hi 是倒数第 4 字节（与 `edns::query_do_bit` 的读法一致）。
        let n = q.len();
        assert_eq!(u16::from_be_bytes([q[n - 10], q[n - 9]]), TYPE_OPT);
        q[n - 4] |= 0x80;
        assert!(ebpdns_proto::edns::query_do_bit(&q), "DO 位必须置上");
    }
    q
}

/// 数据面快路径：命中返回 `Some(响应)`，miss 返回 `None`。
fn fast(r: &Resolver, raw: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    r.answer_fast_into(raw, &mut out).map(|_| out)
}

/// 响应里是否含 A 记录 rdata `1.2.3.4`（只判"有答案"，不判编码细节）。
fn has_a_rdata(resp: &[u8]) -> bool {
    resp.windows(4).any(|w| w == [1u8, 2, 3, 4])
}

/* ================== 1) 默认：DO 与非 DO 不共用条目 ================== */

#[tokio::test]
async fn do_and_non_do_queries_do_not_share_cache_entries() {
    let (r, _clock) = base(true, false, false);
    let d = "variant.test";
    let plain = query(d, false, false); // 无 EDNS ⇒ DO=false
    let with_do = query(d, true, true); // EDNS + DO=1

    // ① 两条都是 miss（DO 查询不得命中非 DO 条目，反之亦然）。
    assert!(fast(&r, &plain).is_none(), "非 DO 首次查询必须 miss");
    assert!(
        fast(&r, &with_do).is_none(),
        "DO 首次查询必须 miss（不得命中非 DO 条目）"
    );

    // ② 完整路径各回填一次（模拟两个客户端先后穿透）。
    let res_plain = r.clone().resolve(d, "A", ResolveOpts::default()).await;
    assert_eq!(res_plain.rcode, 0);
    assert!(!res_plain.answers.is_empty());
    let res_do = r
        .clone()
        .resolve(
            d,
            "A",
            ResolveOpts {
                dnssec: true,
                ..Default::default()
            },
        )
        .await;
    assert_eq!(res_do.rcode, 0);
    assert!(!res_do.answers.is_empty());

    // ③ 现在各自命中（且**只**命中自己的那一条）。
    let hit_plain = fast(&r, &plain).expect("非 DO 条目必须命中");
    let hit_do = fast(&r, &with_do).expect("DO 条目必须命中");
    assert!(has_a_rdata(&hit_plain), "非 DO 命中的响应必须有 A 记录");
    assert!(has_a_rdata(&hit_do), "DO 命中的响应必须有 A 记录");

    // ④ 缓存里确实是**两条**条目（键的 dnssec 位不同）。
    let k_plain = r.ckey_normalized(d, "A");
    let k_do = r.ckey_variant(d, "A", true);
    assert!(!k_plain.dnssec, "`ckey_normalized` 恒为非 DO 键");
    assert!(k_do.dnssec, "`ckey_variant(.., true)` 必须带 DO 变体");
    assert_ne!(k_plain, k_do);
    let now = EPOCH + 0.5;
    assert!(r.cache().get(&k_plain, now).is_some(), "非 DO 条目必须存在");
    assert!(r.cache().get(&k_do, now).is_some(), "DO 条目必须存在");
    // 两条条目的 domain/qtype 相同 —— 差异**只**在变体位（这是"同域名两条"的定义）。
    let e_plain = r.cache().get(&k_plain, now).unwrap();
    let e_do = r.cache().get(&k_do, now).unwrap();
    assert_eq!((e_plain.domain.as_str(), e_plain.qtype.as_str()), (d, "A"));
    assert_eq!((e_do.domain.as_str(), e_do.qtype.as_str()), (d, "A"));
}

/* ================== 2) dnssec_cache_variants=false：共用一条 ================== */

#[tokio::test]
async fn dnssec_variants_off_shares_one_entry_legacy_behavior() {
    let (r, _clock) = base(false, false, false);
    let d = "legacy-share.test";
    let plain = query(d, false, false);
    let with_do = query(d, true, true);

    // 非 DO 查询先穿透并回填。
    assert!(fast(&r, &plain).is_none());
    let _ = r.clone().resolve(d, "A", ResolveOpts::default()).await;
    assert!(fast(&r, &plain).is_some(), "非 DO 查询回填后必须命中");

    // **旧行为**：配置关闭变体 ⇒ DO 查询**直接命中**同一条目（不分裂）。
    assert!(
        fast(&r, &with_do).is_some(),
        "dnssec_cache_variants=false 时 DO 查询必须与非 DO 共用条目"
    );
    // 键里确实没有 DO 维（两条键相等）。
    let k_plain = r.ckey_normalized(d, "A");
    let k_do = r.ckey_variant(d, "A", true);
    assert_eq!(k_plain, k_do, "配置关闭时两键必须相等（键里不带 DO）");
    assert!(!k_do.dnssec);
}

/* ================== 3) 预取按原条目变体重建键 ================== */

#[tokio::test]
async fn prefetch_keeps_do_variant_and_never_downgrades_entry() {
    let (r, _clock) = base(true, false, true);
    let d = "pf-variant.test";
    let k_do = r.ckey_variant(d, "A", true);
    let k_plain = r.ckey_normalized(d, "A");
    assert!(k_do.dnssec && !k_plain.dnssec);
    // 手工播种一条 **DO** 条目（TTL 很短 ⇒ 剩余 TTL <= trigger，会被续期）。
    r.fill_cache(&k_do, d, "A", vec![a("9.9.9.9", 5.0)], None);
    assert!(r.cache().get(&k_do, EPOCH + 0.5).is_some());

    // 按 DO 变体入队 → 预取续期。
    r.schedule_prefetch(d, "A", 0.0, true);
    assert_eq!(r.prefetch_order(), vec![format!("{d}|A|DO")]);
    r.prefetch_tick().await;

    // 续期后：DO 条目仍在（且 TTL 被续到 prefetch_target=300 ⇒ 到期时间更远），
    // 非 DO 条目**不得**出现（把 DO 条目刷新成非 DO 键 = 跨变体串条目）。
    let now = EPOCH + 0.5;
    let refreshed = r
        .cache()
        .get(&k_do, now)
        .expect("DO 条目续期后必须仍在 DO 键上");
    assert!(
        refreshed.expires_at > EPOCH + 100.0,
        "续期后 TTL 必须被拉长到 prefetch_target（实际 expires_at={}）",
        refreshed.expires_at
    );
    assert!(
        r.cache().get(&k_plain, now).is_none(),
        "预取**不得**把 DO 条目刷新成非 DO 键（跨变体串条目）"
    );
}

/* ================== 4) ECS 变体：不分裂（ECS 未外发） ================== */

/// `ecs_cache_variants=true` 只作配置接收：键形态与 `false` **完全一致**，
/// 因此同域名不同客户端子网查询共用一条（本仓当前没有"按客户端子网分裂"的实现，
/// 因为 `edns_client_subnet` 从不外发给上游，见 README / `config.rs` 字段注释）。
#[tokio::test]
async fn ecs_variants_do_not_split_cache_keys() {
    let (off, _c1) = base(true, false, false);
    let (on, _c2) = base(true, true, false);
    let d = "ecs-variant.test";
    for dnssec in [false, true] {
        let k_off = off.ckey_variant(d, "A", dnssec);
        let k_on = on.ckey_variant(d, "A", dnssec);
        assert_eq!(
            k_off, k_on,
            "ecs_cache_variants 不得改变键形态（ECS 未外发 ⇒ 按子网分裂只会产生碎片）"
        );
        assert_eq!(k_off.to_key_array(), k_on.to_key_array());
    }
    // 行为侧：`ecs_cache_variants=true` 的实例仍然只有一条条目（同域名同 qtype）。
    let _ = on.clone().resolve(d, "A", ResolveOpts::default()).await;
    let _ = on.clone().resolve(d, "A", ResolveOpts::default()).await;
    let seen = on.cache().keys();
    let n = seen
        .iter()
        .filter(|k| k.domain == d && k.qtype == "A")
        .count();
    assert_eq!(n, 1, "同域名同 qtype 只能有一条条目（ECS 不分裂缓存）");
}

/* ================== 5) wire 缓存同样按 DO 变体隔离 ================== */

/// 与 [`base`] 相同，但把缓存策略切成 `s3fifo`（wire 缓存只在该策略上启用）。
fn base_s3fifo() -> (Arc<Resolver>, Arc<MockClock>) {
    let ups = vec![UpstreamCfg::test_up("u1"), UpstreamCfg::test_up("u2")];
    let mut cfg = ResolverConfig::test_default(ups, Vec::new(), 2);
    cfg.cache_policy = "s3fifo".to_string();
    cfg.dnssec_cache_variants = true;
    cfg.prefetch = false;
    cfg.speed_test = false;
    cfg.ip_speed_check = false;
    cfg.serve_stale = false;
    let clock = Arc::new(MockClock::new(EPOCH));
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        clock.clone(),
        Arc::new(ScriptedQuerier::new(|_, _, _| {
            vec![UpstreamAnswer::ok(
                "u1",
                0,
                vec![a("1.2.3.4", 300.0)],
                vec![],
            )]
        })),
    );
    (r, clock)
}

/// 用查询报文里的 question 段构造一条最小响应（qd=1/an=1，答案 `ip`）。
fn wire_resp_for(query: &[u8], ip: [u8; 4], ttl: u32) -> Vec<u8> {
    let mut pos = 12usize;
    while query[pos] != 0 {
        pos += 1 + query[pos] as usize;
    }
    pos += 1 + 4; // 终止 0 + qtype + qclass
    let question = &query[12..pos];
    let mut m = vec![0u8; 12];
    m[0..2].copy_from_slice(&query[0..2]);
    m[2] = 0x81;
    m[3] = 0x80;
    m[4..6].copy_from_slice(&1u16.to_be_bytes()); // qd=1
    m[6..8].copy_from_slice(&1u16.to_be_bytes()); // an=1
    m.extend_from_slice(question);
    m.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1]);
    m.extend_from_slice(&ttl.to_be_bytes());
    m.extend_from_slice(&[0, 4]);
    m.extend_from_slice(&ip);
    m
}

/// **审查修复（round 1）**：wire 缓存键必须与结构化条目**同一个 DO 变体**。
///
/// 若 wire 按 `ckey_normalized`（非 DO）存，DO 查询会直接拿到非 DO 的报文字节；
/// 本用例把 wire 只放在 DO 键上，断言非 DO 命中不受影响、DO 命中确实用到 wire。
#[tokio::test]
async fn wire_cache_is_isolated_by_dnssec_variant() {
    let (r, _clock) = base_s3fifo();
    let d = "wire-variant.test";
    let plain = query(d, false, false);
    let with_do = query(d, true, true);

    // 先让两条结构化条目都存在（wire 命中要求 `cache.get` 先成功）。
    let _ = r.clone().resolve(d, "A", ResolveOpts::default()).await;
    let _ = r
        .clone()
        .resolve(
            d,
            "A",
            ResolveOpts {
                dnssec: true,
                ..Default::default()
            },
        )
        .await;

    let k_do = r.ckey_variant(d, "A", true);
    let k_plain = r.ckey_variant(d, "A", false);
    assert!(k_do.dnssec && !k_plain.dnssec);

    // 只在 **DO** 键上登记一条"9.9.9.9"的打包响应。
    let wire_bytes = wire_resp_for(&with_do, [9, 9, 9, 9], 300);
    let w = ebpdns_cache::wire::WireEntry::from_response(&wire_bytes, EPOCH)
        .expect("最小响应应可建 wire");
    r.cache().put_wire(&k_do, Arc::new(w));

    // DO 查询走 wire，拿到 9.9.9.9；非 DO 查询必须仍走结构化条目（1.2.3.4）。
    let hit_do = fast(&r, &with_do).expect("DO 命中");
    assert!(
        hit_do.windows(4).any(|x| x == [9, 9, 9, 9]),
        "DO 查询应命中 DO 键上的 wire 字节"
    );
    let hit_plain = fast(&r, &plain).expect("非 DO 命中");
    assert!(
        !hit_plain.windows(4).any(|x| x == [9, 9, 9, 9]),
        "非 DO 查询不得拿到 DO 变体的 wire 字节（跨变体串条目）"
    );
    assert!(
        has_a_rdata(&hit_plain),
        "非 DO 命中必须是结构化编码的正常答案"
    );
}
