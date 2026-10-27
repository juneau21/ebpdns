//! **2.1.21（DEF-220-01 / DEF-220-09 / DEF-220-11）**：预取语义与"两本账"。
//!
//! * `prefetch_trigger` 是**唯一**的续期阈值（入队与真的发上游同一条判据）；
//! * `prefetch_target` 是续期回填的 TTL **上限**（此前全树零读取点）；
//! * `dns_success_rate` = DNS **业务**成功率（SERVFAIL 计失败），与传输层
//!   `success_rate` 分开统计（A-17 的实现）。

use std::sync::Arc;

use ebpdns_cache::DnsCache;
use ebpdns_proto::constants::{RCODE_SERVFAIL, TYPE_A};
use ebpdns_resolver::clock::MockClock;
use ebpdns_resolver::config::{ResolverConfig, UpstreamCfg};
use ebpdns_resolver::query::ScriptedQuerier;
use ebpdns_resolver::resolve::ResolveOpts;
use ebpdns_resolver::telemetry::NoopTelemetry;
use ebpdns_resolver::types::{ResolveAnswer, UpstreamAnswer};
use ebpdns_resolver::Resolver;

fn a(value: &str, ttl: f64) -> ResolveAnswer {
    ResolveAnswer::new(value, ttl, TYPE_A)
}

fn base(
    handler: impl Fn(&str, &str, u32) -> Vec<UpstreamAnswer> + Send + Sync + 'static,
) -> Arc<Resolver> {
    let cfg = ResolverConfig::test_default(
        vec![UpstreamCfg::test_up("u1"), UpstreamCfg::test_up("u2")],
        Vec::new(),
        1,
    );
    Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(1_700_000_000.0)),
        Arc::new(ScriptedQuerier::new(handler)),
    )
}

/// **A-17 / DEF-220-09**：`dns_success_rate` 的分子分母必须来自**真实 rcode**：
/// 业务成功 = `rcode ∈ {NOERROR, NXDOMAIN}` 且**未被截断**（**不要求答案段非空** ——
/// NXDOMAIN / NODATA 都是上游真实结论）；`SERVFAIL` → **失败**（而传输层 `success_rate`
/// 会把它算成"成功"，因为 UDP 往返本身是通的）。口径与 README / `web/INTERFACE.md` /
/// `/metrics` 的 HELP 逐字一致。

#[tokio::test]
async fn dns_business_verdicts_are_recorded_per_upstream() {
    let rt = Arc::new(ebpdns_upstream::UpstreamRuntime::new());
    let r = base(|_d, _q, _depth| {
        vec![
            // u1：业务成功（NOERROR + 一条 A）。
            UpstreamAnswer::ok("u1", 0, vec![a("1.1.1.1", 300.0)], vec![]),
            // u2：业务失败（SERVFAIL）。
            UpstreamAnswer {
                rcode: Some(RCODE_SERVFAIL),
                up_name: "u2".into(),
                ..Default::default()
            },
        ]
    });
    r.set_runtime(rt.clone());

    let res = r
        .clone()
        .resolve("a17-biz.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, 0, "有 u1 的成功应答 ⇒ NOERROR");

    let s1 = rt.health.stats("u1");
    let s2 = rt.health.stats("u2");
    assert_eq!(
        s1.dns_ok_count(),
        1,
        "NOERROR 且未截断 ⇒ 业务成功 1 次（**不要求答案段非空**）"
    );

    assert_eq!(s1.dns_fail_count(), 0);
    assert_eq!(s1.dns_total(), 1);
    assert_eq!(s2.dns_ok_count(), 0, "SERVFAIL 不得计业务成功");
    assert_eq!(s2.dns_fail_count(), 1, "SERVFAIL ⇒ 业务失败 1 次");
    assert_eq!(s2.dns_total(), 1);

    // 两本账**确实不同**：`u2` 的传输层样本在本用例里是 0（没有走真实 runtime.query），
    // 而业务层已经有 1 条失败 —— 这正是"传输层成功率 ≠ DNS 业务成功率"的最小证据。
    assert_eq!(
        s2.ok_count() + s2.fail_count(),
        0,
        "本用例不经真实传输层 ⇒ 传输账为 0（两本账互不覆盖）"
    );

    // 再来一轮：u1 业务成功 ×2、u2 业务失败 ×2（计数单调）。
    let _ = r
        .clone()
        .resolve("a17-biz2.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(rt.health.stats("u1").dns_ok_count(), 2);
    assert_eq!(rt.health.stats("u2").dns_fail_count(), 2);
    assert_eq!(rt.health.stats("u2").dns_total(), 2);
}

/// **DEF-220-09 口径**：NXDOMAIN 是**有效业务结论**（上游真的答了"不存在"），
/// 因此计**业务成功**；`rcode=None`（超时/解析失败）计失败。
#[tokio::test]
async fn dns_business_verdict_counts_nxdomain_as_success_and_timeout_as_failure() {
    let rt = Arc::new(ebpdns_upstream::UpstreamRuntime::new());
    let r = base(|_d, _q, _depth| {
        vec![
            UpstreamAnswer {
                rcode: Some(3), // NXDOMAIN
                up_name: "u1".into(),
                ..Default::default()
            },
            UpstreamAnswer {
                rcode: None, // 超时 / 解析失败
                up_name: "u2".into(),
                ..Default::default()
            },
        ]
    });
    r.set_runtime(rt.clone());
    let res = r
        .clone()
        .resolve("a17-nx.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, 3, "NXDOMAIN（quorum=1）");
    assert_eq!(
        rt.health.stats("u1").dns_ok_count(),
        1,
        "NXDOMAIN 是有效业务结论 ⇒ 计成功"
    );
    assert_eq!(
        rt.health.stats("u2").dns_fail_count(),
        1,
        "rcode=None（超时/解析失败）⇒ 计失败"
    );
}

/// **DEF-221-04（2.1.23 修完）**：`single_flight=true` 时 N 路并发同名查询
/// ⇒ **记账次数 == 物理上游扇出次数**（每个物理应答恰好记一次，**不是**按调用方记）。
///
/// 为什么必须有这条**确定性**判据：2.1.21 第 2 轮把记账点从 `finish_resolve`
/// （逐调用方）挪到 single-flight 之后，交付报告据此声称已修 —— 但那一行**仍然逐调用方
/// 执行**，所以"N 路并发 ⇒ `dns_ok` +N"依旧成立（审计 AUDIT-222 复现：5 并发同名
/// = 1 次 wire 查询 + `dns_ok +5`）。
///
/// **判据为什么是"相等"而不是"扇出恰好 1 次"**：8 个 `tokio::spawn` 任务虽然用
/// `Barrier` 对齐了起跑线，但 single-flight 只合并**真正重叠**在途的那一段 ——
/// 状态机是「leader 完成后表被摘除，之后到达者成为新 leader」。所以扇出次数
/// 可以是 1..N 之间的任何值（实测 3），**它由调度决定、不是产品契约**。
///
/// 产品契约只有一条：**每个物理上游应答恰好记一次账**（`health.rs` 的口径）。
/// 改前（逐调用方记账）这个等式必然不成立（recorded = N > physical）；改后恒成立。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn d221_04_concurrent_same_name_records_dns_ok_exactly_once() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    const N: usize = 8;
    let waves = Arc::new(AtomicUsize::new(0));
    let waves_c = waves.clone();
    let rt = Arc::new(ebpdns_upstream::UpstreamRuntime::new());
    let mut cfg = ResolverConfig::test_default(vec![UpstreamCfg::test_up("u1")], Vec::new(), 1);
    cfg.single_flight = true;
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(1_700_000_000.0)),
        Arc::new(ScriptedQuerier::new(move |_d, _q, _dep| {
            waves_c.fetch_add(1, Ordering::SeqCst);
            // 让扇出真的耗时：并发调用者才有机会落进同一张在途表。
            std::thread::sleep(Duration::from_millis(50));
            vec![UpstreamAnswer::ok(
                "u1",
                0,
                vec![a("9.9.9.9", 300.0)],
                vec![],
            )]
        })),
    );
    r.set_runtime(rt.clone());
    let before = rt.health.stats("u1").dns_total();

    let barrier = Arc::new(tokio::sync::Barrier::new(N));
    let mut handles = Vec::with_capacity(N);
    for _ in 0..N {
        let r = r.clone();
        let b = barrier.clone();
        handles.push(tokio::spawn(async move {
            b.wait().await;
            r.resolve("d221-04-sf.test", "A", ResolveOpts::default())
                .await
                .rcode
        }));
    }
    for h in handles {
        assert_eq!(
            h.await.expect("join"),
            0,
            "上游有 NOERROR 应答 ⇒ 都拿到 NOERROR"
        );
    }

    let physical = waves.load(Ordering::SeqCst) as u64;
    let recorded = rt.health.stats("u1").dns_total() - before;
    assert!(physical >= 1, "至少发生 1 次物理上游扇出");
    assert_eq!(
        recorded, physical,
        "**DEF-221-04**：业务账必须按**物理上游应答**逐条记 —— 实测 recorded={recorded} \
         但 physical={physical}（改前是 recorded={N} > physical，因为每个调用方各记一次）"
    );
    assert_eq!(
        rt.health.stats("u1").dns_ok_count(),
        physical,
        "NOERROR 应答数 == 物理扇出数（每个物理应答恰好记一次）"
    );
    assert_eq!(r.single_flight_inflight(), 0, "全部完成后在途表必须清空");
}

/// **DEF-220-01**：预取链路（单上游、后台流量）**不写**业务账 —— 否则后台续期会把
/// 运维看到的业务成功率拉高（口径污染）。
#[tokio::test]
async fn prefetch_path_does_not_touch_dns_business_counters() {
    let rt = Arc::new(ebpdns_upstream::UpstreamRuntime::new());
    let r = base(|_d, _q, _depth| {
        vec![UpstreamAnswer::ok(
            "u1",
            0,
            vec![a("1.1.1.1", 300.0)],
            vec![],
        )]
    });
    r.set_runtime(rt.clone());
    let _ = r
        .clone()
        .resolve_prefetch("a17-pf.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(
        rt.health.stats("u1").dns_total(),
        0,
        "预取链路不得写 DNS 业务账（它不是客户端业务）"
    );
}

/// **2.1.21 第 2 轮（DEF-221-03）：数据面快路径命中必须**真的入队**。**
///
/// 为什么必须有这条：第 1 轮的 3 条 DEF-220-01/11 单测都是
/// `r.schedule_prefetch(...)` + `r.do_prefetch()` **手工**驱动队列，**从不经过
/// `answer_fast`**（审计 AUDIT-221 D.4 点名），因此"入队闸门"被证明一致、而
/// "用户查一次就能触发续期"从未被证明 —— 快路径不入队的缺陷就是这样潜伏的。
///
/// 本条通过**真实快路径**（`answer_fast` 处理一个真实 DNS 查询报文）驱动入队：
/// * 剩余 TTL 低于 `prefetch_trigger` ⇒ `prefetch_len()` 必须变 1；
/// * 剩余 TTL 高于 `prefetch_trigger` ⇒ 必须仍是 0；
/// * 且入队的那条**真的会被 `do_prefetch` 发上游并回填**（端到端，不只查队列）。
#[tokio::test]
async fn d221_03_answer_fast_enqueues_prefetch_and_refreshes() {
    use ebpdns_cache::DnsCache;
    use ebpdns_resolver::clock::Clock;
    use std::sync::atomic::{AtomicU64, Ordering};

    // 真实 DNS 查询报文（QR=0 / opcode=0 / qd=1 / qtype=A / qclass=IN）。
    fn query_packet(domain: &str) -> Vec<u8> {
        let mut q = vec![0u8; 12];
        q[0..2].copy_from_slice(&0x2112u16.to_be_bytes());
        q[2] = 0x01; // RD
        q[5] = 1; // qdcount
        for label in domain.trim_end_matches('.').split('.') {
            q.push(label.len() as u8);
            q.extend(label.as_bytes());
        }
        q.push(0);
        q.extend(1u16.to_be_bytes()); // TYPE_A
        q.extend(1u16.to_be_bytes()); // CLASS_IN
        q
    }

    fn seed(r: &Resolver, d: &str, ttl: f64, now: f64) {
        let key = r.ckey_normalized(d, "A");
        r.cache().put(
            key,
            ebpdns_cache::CacheEntry {
                domain: d.to_string(),
                qtype: "A".into(),
                answers: vec![ebpdns_cache::CacheAnswer {
                    value: "1.1.1.1".into(),
                    ttl,
                    rtype: 1,
                    name: None,
                }],
                chosen: "1.1.1.1".into(),
                ttl,
                rcode: 0,
                rule_gen: r.rule_gen(),
                expires_at: now + ttl,

                seq: 0,
            },
            now,
        );
    }

    let calls = Arc::new(AtomicU64::new(0));
    let c = calls.clone();
    let clock: Arc<dyn Clock> = Arc::new(MockClock::new(1_700_000_000.0));
    let mut cfg = ResolverConfig::test_default(vec![UpstreamCfg::test_up("u1")], Vec::new(), 1);
    cfg.prefetch = true;
    cfg.prefetch_interval = 1.0;
    cfg.prefetch_trigger = 600.0; // ≫ ttl*0.15（300*0.15=45）—— 15% 暗闸门已不存在
    cfg.prefetch_target = 0.0;
    cfg.ttl = 300;
    cfg.ttl_min = 0;
    cfg.ttl_max = 604_800;
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::clone(&clock),
        Arc::new(ScriptedQuerier::new(move |_d, _q, _dep| {
            c.fetch_add(1, Ordering::Relaxed);
            vec![UpstreamAnswer::ok(
                "u1",
                0,
                vec![a("9.9.9.9", 300.0)],
                vec![],
            )]
        })),
    );

    // ① 低于 trigger（剩 100s）⇒ 快路径命中必须入队。
    seed(&r, "d221-fast-low.test", 100.0, clock.epoch());
    let raw = query_packet("d221-fast-low.test.");
    let resp = r
        .answer_fast(&raw)
        .expect("预置条目必须由快路径命中（否则本用例没有覆盖到快路径）");
    assert!(resp.len() > 12, "快路径必须产出带答案的应答");
    assert_eq!(
        r.prefetch_len(),
        1,
        "**DEF-221-03**：数据面快路径命中且剩余 TTL(100) ≤ trigger(600) ⇒ 必须入队"
    );

    // ② 入队的条目真的会被续期（端到端：消费队列 → 发上游 → 回填）。
    let before = calls.load(Ordering::Relaxed);
    r.prefetch_tick().await;
    assert!(
        calls.load(Ordering::Relaxed) > before,
        "入队的条目必须真的发上游续期（快路径 ⇒ do_prefetch 的闭环）"
    );
    let left = r
        .cache()
        .get(&r.ckey_normalized("d221-fast-low.test", "A"), clock.epoch())
        .map(|e| e.expires_at - clock.epoch())
        .unwrap_or(0.0);
    assert!(left > 250.0, "续期必须把 TTL 顶回上游值，实际剩余 {left}s");

    // ③ 高于 trigger（剩 200s > 60s）⇒ 快路径不得入队。
    let mut cfg2 = ResolverConfig::test_default(vec![UpstreamCfg::test_up("u1")], Vec::new(), 1);
    cfg2.prefetch = true;
    cfg2.prefetch_trigger = 60.0;
    cfg2.ttl = 300;
    let r2 = Resolver::new(
        cfg2,
        Arc::new(NoopTelemetry),
        Arc::clone(&clock),
        Arc::new(ScriptedQuerier::new(|_d, _q, _dep| Vec::new())),
    );
    seed(&r2, "d221-fast-high.test", 200.0, clock.epoch());
    let raw2 = query_packet("d221-fast-high.test.");
    assert!(r2.answer_fast(&raw2).is_some(), "快路径必须命中");
    assert_eq!(
        r2.prefetch_len(),
        0,
        "剩余 TTL(200) > trigger(60) ⇒ 快路径不得入队（同一条判据）"
    );
}

/// **2.1.21 第 2 轮（DEF-221-04）：single-flight 合并不得放大"业务账"。**
///
/// 缺陷（AUDIT-221 DEF-221-04）：记账点在 `finish_resolve` 的**逐调用方**循环里，
/// 而 single-flight 只合并上游扇出段 ⇒ 5 个并发同名 miss 合并成 **1 次物理查询**，
/// 却把 `dns_ok` 记了 **5** 次（与 `health.rs` 的"每个上游应答恰好记一次"矛盾）。
///
/// 本用例同时钉死两件事：**物理查询确实只有 1 次**（否则用例没有覆盖到合并路径）、
/// 以及 **`dns_ok` 也只 +1**。
#[tokio::test]
async fn d221_04_singleflight_records_business_verdict_once() {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::time::Duration;

    let rt = Arc::new(ebpdns_upstream::UpstreamRuntime::new());
    let calls = Arc::new(AtomicU64::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let max_active = Arc::new(AtomicUsize::new(0));
    let (c, act, mx) = (calls.clone(), active.clone(), max_active.clone());

    let mut cfg = ResolverConfig::test_default(vec![UpstreamCfg::test_up("u1")], Vec::new(), 1);
    cfg.single_flight = true;
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(1_700_000_000.0)),
        Arc::new(ScriptedQuerier::new(move |_d, _q, _dep| {
            c.fetch_add(1, Ordering::SeqCst);
            let n = act.fetch_add(1, Ordering::SeqCst) + 1;
            mx.fetch_max(n, Ordering::SeqCst);
            // 让扇出**真的**耗时，5 个调用方才有机会同时落在同一张在途表上。
            std::thread::sleep(Duration::from_millis(50));
            act.fetch_sub(1, Ordering::SeqCst);
            vec![UpstreamAnswer::ok(
                "u1",
                0,
                vec![a("5.5.5.5", 300.0)],
                vec![],
            )]
        })),
    );
    r.set_runtime(rt.clone());
    let before = rt.health.stats("u1").dns_total();

    let mut tasks = Vec::new();
    for _ in 0..5 {
        let r = r.clone();
        tasks.push(tokio::spawn(async move {
            r.resolve("d221-04-sf.test", "A", ResolveOpts::default())
                .await
                .rcode
        }));
    }
    for t in tasks {
        assert_eq!(t.await.expect("join"), 0, "并发解析都应是 NOERROR");
    }

    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "single-flight 必须把 5 个同名并发 miss 合并成 **1 次**物理上游查询"
    );
    // **为什么不断言"观测到的并发度"**：`max_active` 取决于测试运行时的调度策略（同一个
    // runtime 上 5 个 `tokio::spawn` 任务可能被逐个 poll 到完成），它描述的是**夹具**而不是
    // 产品；2.1.21 第 2 轮实测在单线程调度下它恒为 1，导致用例假失败。
    //
    // 真正要钉的是**记账不变式**：业务账的增量 ÷ 物理上游查询数 ≤ 1。
    // 改前（每个调用方各记一次）这个比值 = 并发调用方数 = 5；改后恒 ≤ 1，与调度无关。
    // **2.1.22（P3 D-221-04）**：把判据从"观测到的并发度"换成**确定性**的
    // "1 次物理上游查询 ⇒ `dns_ok` 恰好 +1"。理由：`tokio::spawn` 的 5 个任务是否真的
    // 重叠取决于测试运行时的调度策略（单线程下可能逐个跑完），据此断言会让用例假失败；
    // 而缺陷的本质是"**每个调用方各记一次**"，因此"每次物理查询恰好记一次"才是判据。
    let recorded = rt.health.stats("u1").dns_total() - before;
    let physical = calls.load(Ordering::SeqCst);
    assert!(physical >= 1, "至少发生 1 次物理上游查询");
    assert!(
        recorded <= physical,
        "**DEF-221-04**：业务账被放大 —— 记录 {recorded} 次业务判决，但只有 {physical} 次物理上游         查询（改前每个调用方各记一次 ⇒ 5/1）。最大观测并发度={}（仅作参考，不作为判据）。",
        max_active.load(Ordering::SeqCst)
    );
    assert!(
        rt.health.stats("u1").dns_ok_count() <= physical,
        "业务成功数不得超过物理上游查询数"
    );

    // ---- **确定性**判据（不依赖调度）：单飞一次 ⇒ 记账恰好一次 ----
    //
    // 重置探针后，用**同键连续两次**解析（第二次必然命中缓存或与第一次合并）证明
    // "记账跟着**物理查询**走、不跟调用方数量走"。
    let before2 = rt.health.stats("u1").dns_total();
    let calls_before = calls.load(Ordering::SeqCst);
    let _ = r
        .resolve("d221-04-sf.test", "A", ResolveOpts::default())
        .await;
    let physical2 = calls.load(Ordering::SeqCst) - calls_before;
    let recorded2 = rt.health.stats("u1").dns_total() - before2;
    assert_eq!(
        recorded2, physical2,
        "**D-221-04（记账不变式，确定性版本）**：业务账增量必须**恰好等于**物理上游查询数\
         （每个物理应答记一次，调用方数量不影响；实测 recorded={recorded2} physical={physical2}）"
    );
}

/// **DEF-220-11**：`resolve_prefetch` 必须把 `prefetch_target` 作为回填 TTL 上限
/// （`ResolveOpts::ttl_cap`）传下去 —— 该键从此**不再是死字段**。
#[tokio::test]
async fn prefetch_target_caps_the_refilled_ttl() {
    use ebpdns_resolver::clock::Clock;
    // Arc<dyn Clock> 从一开始就是 trait object：既能 float 给 Resolver::new，
    // 又能在测试里调 Clock::epoch()。
    let clock: Arc<dyn Clock> = Arc::new(MockClock::new(1_700_000_000.0));
    let mut cfg = ResolverConfig::test_default(vec![UpstreamCfg::test_up("u1")], Vec::new(), 1);
    cfg.ttl = 3600;
    cfg.ttl_min = 0;
    cfg.ttl_max = 604_800;
    cfg.prefetch_target = 120.0;
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::clone(&clock),
        Arc::new(ScriptedQuerier::new(|_d, _q, _depth| {
            vec![UpstreamAnswer::ok(
                "u1",
                0,
                vec![a("2.2.2.2", 3600.0)],
                vec![],
            )]
        })),
    );
    let _ = r
        .clone()
        .resolve_prefetch("a11-target.test", "A", ResolveOpts::default())
        .await;
    let now = clock.epoch();
    let e = r
        .cache()
        .get(&r.ckey_normalized("a11-target.test", "A"), now)
        .expect("预取必须回填缓存");
    let left = e.expires_at - now;
    assert!(
        left <= 121.0 && left > 110.0,
        "`prefetch_target=120` 必须是续期回填的 TTL 上限（上游给 3600s），实际 {left}s"
    );
    assert_eq!(
        e.answers.first().map(|x| x.value.as_str()),
        Some("2.2.2.2"),
        "回填的答案必须来自预取查询"
    );
}
