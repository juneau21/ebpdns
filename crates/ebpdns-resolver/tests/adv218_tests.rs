// **2.1.24（B4：clippy 清零）**：本文件是**对抗性测试夹具**，7 处 let mut cfg =
// ResolverConfig::default(); cfg.<field> = …; 是逐字段覆盖默认值的写法 ——
// 改成结构体更新语法会把 7 个夹具的可读性换成 lint 的偏好（每个夹具要重排 30+ 行
// 与断言交织的字段设置），且这些代码**不在产品路径上**。逐条位置见 docs/CLIPPY.md。
#![allow(clippy::field_reassign_with_default)]

//! 2.1.8 对抗性审查单测（只读审查附带的证明用例，不修改生产逻辑）。
//!
//! 覆盖优化的四条主线：
//! 1. 「首答即返」（`ProductionQuerier::query_parallel` 的 `is_positive`/`abort_all`）
//!    —— 与 NXDOMAIN/NODATA quorum 的交互、迟到正向答案被丢弃、abort 后任务清理；
//! 2. 自适应并发/对冲（`adaptive_parallel` + `hedge_after_ms`）—— 不重复派发、不超上限；
//! 3. 按上游自适应超时（`timeout_for`）—— 单点快样本永久收紧超时；
//! 4. `UpstreamMode::Single`（预取）—— 单上游即可写负缓存（quorum 塌缩到 1）、
//!    失败不进数据面 `circuit_fails`。
//!
//! 全部用例本地起 UDP 假上游（127.0.0.1），不联网、不起服务、不加载内核态缓存。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use ebpdns_cache::DnsCache;
use ebpdns_proto::constants::TYPE_A;
use ebpdns_proto::record::AnswerInput;
use ebpdns_resolver::breaker::SharedCircuit;
use ebpdns_resolver::clock::MockClock;
use ebpdns_resolver::config::{ResolverConfig, UpstreamCfg};
use ebpdns_resolver::production::{ProductionQuerier, QuerierTuning};
use ebpdns_resolver::query::ParallelQuerier;
use ebpdns_resolver::resolve::ResolveOpts;
use ebpdns_resolver::telemetry::NoopTelemetry;
use ebpdns_resolver::Resolver;
use ebpdns_upstream::{UpstreamConfig, UpstreamRuntime};

/* ------------------------------------------------------------------ 假上游 */

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Positive,
    Nxdomain,
    /// 收到查询但不应答（让上层超时）。
    NoReply,
}

#[derive(Clone, Copy)]
struct Behaviour {
    delay_ms: u64,
    kind: Kind,
}

struct MockUp {
    port: u16,
    queries: Arc<AtomicUsize>,
}

/// 起一个本地 UDP 假上游；返回绑定端口与内部计数。
async fn spawn_mock(delay_ms: u64, kind: Kind) -> MockUp {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    let queries = Arc::new(AtomicUsize::new(0));
    let q = queries.clone();
    let b = Behaviour { delay_ms, kind };
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                break;
            };
            q.fetch_add(1, Ordering::SeqCst);
            let query = buf[..n].to_vec();
            // 串行处理（每个 mock 的延迟很小；测试用 --test-threads 4 并发跑不同用例）。
            if b.delay_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(b.delay_ms)).await;
            }
            let reply: Option<Vec<u8>> = match b.kind {
                Kind::Positive => ebpdns_proto::response::build_response(
                    &query,
                    "mock.test",
                    TYPE_A,
                    &[AnswerInput::new(TYPE_A, "1.2.3.4").with_ttl(60)],
                    0,
                    None,
                    None,
                    false,
                ),
                Kind::Nxdomain => ebpdns_proto::response::build_simple_response(&query, 3),
                Kind::NoReply => None,
            };
            if let Some(r) = reply {
                let _ = sock.send_to(&r, peer).await;
            }
        }
    });
    MockUp { port, queries }
}

fn up(id: &str, port: u16) -> UpstreamCfg {
    UpstreamCfg {
        id: id.to_string(),
        name: id.to_string(),
        proto: "udp".to_string(),
        host: "127.0.0.1".to_string(),
        port,
        url: String::new(),
        enabled: true,
        latency: 5000,
        weight: 1.0,
        group: None,
        allow_private_ip: true,
    }
}

/// 生产形态上游（`latency_measured=true`）。
///
/// **P2（2.1.14）**：本文件零引用 → 明确标注为「测试场景保留的构造器」并 allow，
/// 消除 `cargo test` 的 dead_code 告警（不删除：它是与上面 `test_up` 成对的场景构造器，
/// 删除会让后续补用例时重复实现）。
#[allow(dead_code)]
fn prod(id: &str, port: u16) -> UpstreamConfig {
    UpstreamConfig {
        id: id.to_string(),
        name: id.to_string(),
        proto: ebpdns_upstream::Proto::Udp,
        host: "127.0.0.1".to_string(),
        port,
        url: String::new(),
        weight: 1,
        strict_cert: true,
        allow_private_ip: true,
        bootstrap: None,
        latency: 5000,
        latency_measured: false,
        enabled: true,
    }
}

fn querier(
    timeout_ms: u64,
    cfg: &ResolverConfig,
) -> (Arc<ProductionQuerier>, Arc<UpstreamRuntime>) {
    let rt = Arc::new(UpstreamRuntime::new());
    let tuning = QuerierTuning::from_config(cfg);
    let q = ProductionQuerier::new(
        rt.clone(),
        SharedCircuit::new(),
        Arc::new(MockClock::new(100_000.0)),
        timeout_ms,
        false,
        1232,
        false,
        false,
    )
    .with_tuning(tuning);
    (Arc::new(q), rt)
}

/* ------------------------------------------------- 1. 首答即返 / quorum 交互 */

/// 有正向答案时立刻返回：全部并发发出（非自适应）→ 首个 30ms 的正向答案即终结本轮，
/// 迟到的 NXDOMAIN 与更迟的正向答案都被 abort，`results` 只有 1 条。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn early_return_on_first_positive_answer() {
    let s1 = spawn_mock(20, Kind::Positive).await;
    let s2 = spawn_mock(400, Kind::Nxdomain).await;
    let s3 = spawn_mock(700, Kind::Positive).await;

    let cfg = ResolverConfig::default();
    let (q, _rt) = querier(1500, &cfg);
    let ups = vec![up("m1", s1.port), up("m2", s2.port), up("m3", s3.port)];

    let t0 = Instant::now();
    let out = q.query_parallel(&ups, "mock.test", "A", 0).await;
    let el = t0.elapsed().as_millis();
    eprintln!(
        "early_return: elapsed={el}ms n1={} n2={} n3={} dispatched={} early={} out={:?}",
        s1.queries.load(Ordering::SeqCst),
        s2.queries.load(Ordering::SeqCst),
        s3.queries.load(Ordering::SeqCst),
        q.tuning().dispatched(),
        q.tuning().early_returns(),
        out.iter()
            .map(|a| (a.up_name.clone(), a.rcode, a.answers.len(), a.udp_truncated))
            .collect::<Vec<_>>()
    );

    assert_eq!(
        out.len(),
        1,
        "首答即返后 results 只应有 1 条（实测 {}）",
        out.len()
    );
    assert!(out[0].up_name == "m1");
    assert_eq!(out[0].rcode, Some(0));
    assert!(el < 200, "必须在 200ms 内返回（实测 {el}ms）");
    assert_eq!(s1.queries.load(Ordering::SeqCst), 1);
    // 2.1.9 A1：**自适应并发**（`ResolverConfig::default()` 的 `adaptive_parallel=true`）
    // 下健康时只发 1 个上游，`hedge_after_ms`（默认 200ms）到点才追加其余候选。
    // 本用例 m1 在 20ms 就给出正向答案 → 首答即返在 200ms 的 hedge 定时器之前结束，
    // m2/m3 **从未被派发**（这正是负向 amp 2.0→1.0 的来源；旧实现无条件先发齐全部）。
    assert_eq!(
        s2.queries.load(Ordering::SeqCst),
        0,
        "自适应并发下 m2 不应被派发"
    );
    assert_eq!(
        s3.queries.load(Ordering::SeqCst),
        0,
        "自适应并发下 m3 不应被派发"
    );
    assert_eq!(q.tuning().dispatched(), 1, "物理只派发 1 次");
    assert_eq!(q.tuning().early_returns(), 1);
}

/// **2.1.42（P0-1，替换旧断言）**：`adaptive_parallel=true` 时首个负票**不再**
/// abort 其余候选；`nxdomain_quorum=2` 必须继续等第二张负票或迟到的正向答案。
///
/// 旧断言（"首个负票即收口、迟到正向答案被丢弃"）把 P0 缺陷固化成了期望，
/// 本用例改为 1 负 + 1 正（2 候选）：正向答案必须被保留，不得被 abort 丢掉。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn late_positive_answer_survives_single_negative_vote() {
    let s1 = spawn_mock(20, Kind::Nxdomain).await;
    let s2 = spawn_mock(200, Kind::Positive).await;

    let cfg = ResolverConfig::default(); // nxdomain_quorum = 2, adaptive_parallel = true
    let (q, _rt) = querier(1500, &cfg);
    let ups = vec![up("m1", s1.port), up("m2", s2.port)];

    let out = q.query_parallel(&ups, "mock.test", "A", 0).await;
    let positives = out
        .iter()
        .filter(|a| a.rcode == Some(0) && !a.answers.is_empty())
        .count();
    let nx = out.iter().filter(|a| a.rcode == Some(3)).count();
    eprintln!(
        "late_positive: total={} nx={} positive={} up_names={:?}",
        out.len(),
        nx,
        positives,
        out.iter().map(|a| a.up_name.clone()).collect::<Vec<_>>()
    );
    assert_eq!(nx, 1, "单张负票不足 quorum=2");
    assert_eq!(positives, 1, "迟到的正向答案不得被 abort 丢弃");
    assert!(
        out.iter().any(|a| a.up_name == "m2"),
        "m2 必须被派发且其正向答案参与判决"
    );
    assert_eq!(q.tuning().dispatched(), 2, "两张票都必须物理派发");
}

/// **2.1.42（P0-1，替换旧断言）**：quorum 分母 = 候选数 —— 3 个候选里 1 个 NXDOMAIN、
/// 另两个 no-answer/超时（无票）时只有 1 张负票 ⇒ **不得**采纳 NXDOMAIN。
///
/// 旧口径 `clamp(nxdomain_quorum,1,有效票数)` 会塌缩到 1 并写负缓存，正是 P0 的
/// "配置 quorum 实际不可达"。新口径下唯一诚实结论是 SERVFAIL（未确认），且
/// **绝不**写负缓存 / 登记 RFC 8020。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_nxdomain_among_three_candidates_is_not_enough_quorum() {
    let s1 = spawn_mock(0, Kind::Nxdomain).await;
    let s2 = spawn_mock(0, Kind::NoReply).await;
    let s3 = spawn_mock(0, Kind::NoReply).await;

    let ups = vec![up("q1", s1.port), up("q2", s2.port), up("q3", s3.port)];
    let mut cfg = ResolverConfig::default();
    cfg.upstreams = ups.clone();
    cfg.timeout_ms = 300;
    cfg.nxdomain_quorum = 2;
    cfg.max_parallel_upstreams = 3;
    cfg.adaptive_parallel = false;
    cfg.prefetch = false;

    let rt = Arc::new(UpstreamRuntime::new());
    let r = Resolver::new(
        cfg.clone(),
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(100_000.0)),
        Arc::new(ebpdns_resolver::query::ScriptedQuerier::new(|_, _, _| {
            Vec::new()
        })),
    );
    r.set_runtime(rt.clone());
    let tuning = r.querier_tuning();
    r.set_querier(Arc::new(
        ProductionQuerier::new(
            rt.clone(),
            SharedCircuit::new(),
            Arc::new(MockClock::new(100_000.0)),
            cfg.timeout_ms,
            false,
            1232,
            false,
            false,
        )
        .with_tuning(tuning),
    ));

    let res = r
        .clone()
        .resolve("nx-mock.test", "A", ResolveOpts::default())
        .await;
    eprintln!(
        "single_nxdomain_among_three: rcode={} empty={} err={}",
        res.rcode, res.empty, res.error
    );
    assert_eq!(
        res.rcode, 2,
        "1×NXDOMAIN + 2×无票（no-answer/超时）只凑到 1/2 票 → SERVFAIL(2)"
    );
    assert!(res.error, "未确认的负结论必须显式记为错误");
    let ck = r.ckey_normalized("nx-mock.test", "A");
    assert!(
        r.cache().get(&ck, 100_000.0).is_none(),
        "未达 quorum 时**不得**写负缓存"
    );
}

/// **2.1.45（P1-1）**：单候选 + `quorum=2` ⇒ quorum **不可达** ⇒ SERVFAIL，
/// 且**不写负缓存**（2.1.42/2.1.44 的"钳制到 1 票"已在 2.1.45 撤销）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_candidate_quorum_unreachable_servfail() {
    let s1 = spawn_mock(0, Kind::Nxdomain).await;
    let ups = vec![up("solo", s1.port)];
    let mut cfg = ResolverConfig::default();
    cfg.upstreams = ups.clone();
    cfg.timeout_ms = 300;
    cfg.nxdomain_quorum = 2;
    cfg.max_parallel_upstreams = 1;
    cfg.adaptive_parallel = false;
    cfg.prefetch = false;

    let rt = Arc::new(UpstreamRuntime::new());
    let r = Resolver::new(
        cfg.clone(),
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(100_000.0)),
        Arc::new(ebpdns_resolver::query::ScriptedQuerier::new(|_, _, _| {
            Vec::new()
        })),
    );
    r.set_runtime(rt.clone());
    let tuning = r.querier_tuning();
    r.set_querier(Arc::new(
        ProductionQuerier::new(
            rt.clone(),
            SharedCircuit::new(),
            Arc::new(MockClock::new(100_000.0)),
            cfg.timeout_ms,
            false,
            1232,
            false,
            false,
        )
        .with_tuning(tuning),
    ));
    let res = r
        .clone()
        .resolve("solo-nx.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, 2, "可用上游 1 < quorum 2 ⇒ SERVFAIL");
    assert!(res.error);
    let ck = r.ckey_normalized("solo-nx.test", "A");
    assert!(
        r.cache().get(&ck, 100_000.0).is_none(),
        "quorum 不可达时**不得**写负缓存（旧实现的 1 票确认已撤销）"
    );
    assert_eq!(
        r.rfc8020_registrations(),
        0,
        "quorum 不可达 ⇒ 不得登记 RFC 8020"
    );
}

/* ----------------------------------------------------------- 2. 对冲/调参 */

/// 自适应并发：首选的 NoReply 触发 200ms 对冲，其余候选被追加；**每个上游恰好被
/// 派发 1 次**（无重复派发），且并发数不超过候选数。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adaptive_hedge_dispatches_each_upstream_exactly_once() {
    let s1 = spawn_mock(0, Kind::NoReply).await;
    let s2 = spawn_mock(0, Kind::NoReply).await;
    let s3 = spawn_mock(0, Kind::NoReply).await;

    let mut cfg = ResolverConfig::default();
    cfg.adaptive_parallel = true;
    cfg.hedge_after_ms = 60;
    let (q, _rt) = querier(400, &cfg);
    let ups = vec![up("h1", s1.port), up("h2", s2.port), up("h3", s3.port)];

    let out = q.query_parallel(&ups, "hedge.test", "A", 0).await;
    // 全部超时 → 无 early return；对冲计数 >= 1（首次对冲把剩余候选一次发齐）。
    assert!(q.tuning().hedges() >= 1, "必须触发对冲");
    assert_eq!(
        q.tuning().dispatched(),
        3,
        "3 个候选各派发 1 次（物理口径）"
    );
    assert_eq!(s1.queries.load(Ordering::SeqCst), 1, "h1 不得重复派发");
    assert_eq!(s2.queries.load(Ordering::SeqCst), 1, "h2 不得重复派发");
    assert_eq!(s3.queries.load(Ordering::SeqCst), 1, "h3 不得重复派发");
    assert!(out.is_empty() || out.iter().all(|a| a.rcode.is_none()));
}

/// 并发压力下自适应路径的派发上限：N 次并发查询 × M 个候选，
/// 物理派发总量 = N×M（一次不多），每个上游服务端样本数 = N。
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_adaptive_queries_do_not_exceed_parallel_cap() {
    let s = [
        spawn_mock(0, Kind::NoReply).await,
        spawn_mock(0, Kind::NoReply).await,
        spawn_mock(40, Kind::Positive).await,
    ];
    let mut cfg = ResolverConfig::default();
    cfg.adaptive_parallel = true;
    cfg.hedge_after_ms = 10;
    let (q, _rt) = querier(300, &cfg);
    let ups = vec![
        up("c0", s[0].port),
        up("c1", s[1].port),
        up("c2", s[2].port),
    ];

    let n = 40usize;
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..n {
        let q = q.clone();
        let ups = ups.clone();
        set.spawn(async move { q.query_parallel(&ups, "cap.test", "A", 0).await.len() });
    }
    let mut total = 0usize;
    while let Some(Ok(l)) = set.join_next().await {
        total += l;
    }
    let dispatched = q.tuning().dispatched();
    eprintln!(
        "concurrent_cap: dispatched={} expected<={} results_len_sum={} s0={} s1={} s2={}",
        dispatched,
        (n * 3) as u64,
        total,
        s[0].queries.load(Ordering::SeqCst),
        s[1].queries.load(Ordering::SeqCst),
        s[2].queries.load(Ordering::SeqCst)
    );
    assert!(
        dispatched <= (n * 3) as u64,
        "物理派发 {dispatched} 不得超过 N×候选数 {}",
        n * 3
    );
    let c2 = s[2].queries.load(Ordering::SeqCst);
    eprintln!("concurrent_cap detail: s2_queries={c2} (n={n})");
    assert!(
        c2 <= n && c2 >= n - 6,
        "正向上游 c2 的物理样本数必须 ≤ 查询数（无重复发送），实测 {c2}/{n}"
    );
}

/* -------------------------------------------------- 3. 按上游自适应超时 */

/// **P2-A（2.1.9 修复）**：基准从"成功延迟**算术均值**"改为"最近 32 个成功样本的
/// **p90**"，加**抖动安全余量** `max(k×p90, p90×1.2)`，并加"连续 3 次超时 → 丢弃
/// 滑窗样本回退 `timeout_ms`"的解锁器。
///
/// 本用例就是缺陷现场：单次 1500ms 慢样本下旧公式给出 `0.5 × 1500 = 750ms`
/// （= 上游真实 RTT 的一半）→ 下一轮必然超时（慢上游被自己的 RTT 误杀）。
/// 修复后 `max(0.5×1500, 1.2×1500) = 1800ms`（受 `timeout_ms=2000` 封顶）：
/// **生效超时必须 ≥ 观测 p90**，两次查询都必须成功。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adaptive_timeout_shrinks_permanently_after_one_fast_sample() {
    let _s1 = spawn_mock(0, Kind::Positive).await;
    let s2 = spawn_mock(1500, Kind::Positive).await;

    let mut cfg = ResolverConfig::default();
    cfg.timeout_ms = 2000;
    cfg.adaptive_timeout = true;
    cfg.adaptive_timeout_k = 0.5;
    cfg.adaptive_timeout_min_ms = 200;
    let (q, rt) = querier(2000, &cfg);
    let up2 = up("t2", s2.port);

    let t0 = Instant::now();
    let out = q
        .query_parallel(std::slice::from_ref(&up2), "t.test", "A", 0)
        .await;
    let first = t0.elapsed().as_millis();
    assert!(
        out[0].rcode == Some(0),
        "首次 1500ms 慢应答必须在 2000ms 内成功"
    );
    let avg = rt.health.stats("t2").avg_latency().unwrap();
    // 修复后的基准：滑窗 p90（单样本即该样本本身）。
    let p90 = q.tuning().p90_latency("t2").unwrap_or(avg);
    // 与 `ProductionQuerier::timeout_for` 同公式复算：max(k×p90, p90×1.2)，再两端夹取。
    let margin = ebpdns_resolver::production::TIMEOUT_P90_MARGIN;
    let next = ((p90 * cfg.adaptive_timeout_k).max(p90 * margin).round() as u64)
        .clamp(cfg.adaptive_timeout_min_ms, cfg.timeout_ms);
    eprintln!("adaptive_timeout: first={first}ms avg={avg:.0} p90={p90:.0} next_timeout={next}ms",);
    assert!(
        (p90 - 1500.0).abs() < 200.0,
        "单样本下 p90 必须等于该样本（≈1500ms），实际 {p90:.0}ms"
    );
    assert!(
        next as f64 >= p90,
        "**核心不变量**：生效超时 {next}ms 必须 ≥ 观测 p90={p90:.0}ms（k<1 时由 1.2 余量兜住）"
    );
    assert!(
        next >= cfg.adaptive_timeout_min_ms && next <= cfg.timeout_ms,
        "生效超时必须落在 [下限, timeout_ms] 内，实际 {next}ms"
    );
    // 第二次查询：超时预算必须**仍能覆盖**上游 1500ms 的 RTT（不得被自己误杀）。
    let t1 = Instant::now();
    let out2 = q
        .query_parallel(std::slice::from_ref(&up2), "t.test", "A", 0)
        .await;
    let second = t1.elapsed().as_millis();
    eprintln!(
        "adaptive_timeout: second={second}ms rcode={:?}",
        out2.first().map(|a| a.rcode)
    );
    assert!(
        out2.first().and_then(|a| a.rcode) == Some(0),
        "P2-A：修复后同一慢上游不得因超时被误杀（实测 second={second}ms，预算 {next}ms）"
    );
}

/* ---------------------------------------------- 4. 预取（Single）语义 */

/// 预取（`UpstreamMode::Single`）下 single NXDOMAIN 即写负缓存（quorum 塌缩到 1），
/// 且失败不进数据面 `circuit_fails`（只进独立 `probe_fail`）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prefetch_single_upstream_quorum_is_one_and_decoupled_from_circuit() {
    let s1 = spawn_mock(0, Kind::Nxdomain).await;
    let s2 = spawn_mock(0, Kind::Nxdomain).await;
    let ups = vec![up("p1", s1.port), up("p2", s2.port)];

    let mut cfg = ResolverConfig::default();
    cfg.upstreams = ups.clone();
    cfg.timeout_ms = 300;
    cfg.nxdomain_quorum = 2;
    cfg.max_parallel_upstreams = 3;
    cfg.adaptive_parallel = false;
    cfg.prefetch = true;

    let rt = Arc::new(UpstreamRuntime::new());
    let r = Resolver::new(
        cfg.clone(),
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(100_000.0)),
        Arc::new(ebpdns_resolver::query::ScriptedQuerier::new(|_, _, _| {
            Vec::new()
        })),
    );
    r.set_runtime(rt.clone());
    let tuning = r.querier_tuning();
    r.set_querier(Arc::new(
        ProductionQuerier::new(
            rt.clone(),
            SharedCircuit::new(),
            Arc::new(MockClock::new(100_000.0)),
            cfg.timeout_ms,
            false,
            1232,
            false,
            false,
        )
        .with_tuning(tuning),
    ));
    // 预取：只发 1 个上游。
    assert_eq!(r.query_targets(&ups, true).len(), 1, "预取目标恒为 1 个");
    let res = r
        .clone()
        .resolve_prefetch(
            "prefetch-nx.test",
            "A",
            ResolveOpts {
                force_refresh: true,
                silent: true,
                counted: false,
                ..Default::default()
            },
        )
        .await;
    eprintln!(
        "prefetch: rcode={} empty={} err={}",
        res.rcode, res.empty, res.error
    );
    eprintln!(
        "prefetch: s1_q={} s2_q={} cb1={:?} cb2={:?}",
        s1.queries.load(Ordering::SeqCst),
        s2.queries.load(Ordering::SeqCst),
        r.cb_view("p1"),
        r.cb_view("p2")
    );
    assert_eq!(s1.queries.load(Ordering::SeqCst), 1, "只应发 1 个上游");
    assert_eq!(
        s2.queries.load(Ordering::SeqCst),
        0,
        "第二个上游不得被预取触达"
    );
    let ck = r.ckey_normalized("prefetch-nx.test", "A");
    assert!(
        r.cache().get(&ck, 100_000.0).is_none(),
        "P2-B：预取（单上游）的 NXDOMAIN **不得**写负缓存（单票无第二票校验，写进去会污染 60s 窗口）"
    );
    assert_eq!(
        r.cb_view("p1").probe_fail + r.cb_view("p1").probe_ok,
        1,
        "整轮预取只应产生 1 个探针口径计数（诊断用；实际值见上方 eprintln）"
    );
}

/// 预取失败：`rcode=None` 只记 `probe_fail`，`fails` 保持 0（不打开熔断）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prefetch_failure_does_not_increment_circuit_fails() {
    let s1 = spawn_mock(0, Kind::NoReply).await;
    let ups = vec![up("pf1", s1.port)];
    let mut cfg = ResolverConfig::default();
    cfg.upstreams = ups.clone();
    cfg.timeout_ms = 120;
    cfg.circuit_fails = 3;

    let rt = Arc::new(UpstreamRuntime::new());
    let r = Resolver::new(
        cfg.clone(),
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(100_000.0)),
        Arc::new(ebpdns_resolver::query::ScriptedQuerier::new(|_, _, _| {
            Vec::new()
        })),
    );
    r.set_runtime(rt.clone());
    let tuning = r.querier_tuning();
    r.set_querier(Arc::new(
        ProductionQuerier::new(
            rt.clone(),
            SharedCircuit::new(),
            Arc::new(MockClock::new(100_000.0)),
            cfg.timeout_ms,
            false,
            1232,
            false,
            false,
        )
        .with_tuning(tuning),
    ));
    for _ in 0..5 {
        let _ = r
            .clone()
            .resolve_prefetch(
                "pf-fail.test",
                "A",
                ResolveOpts {
                    force_refresh: true,
                    silent: true,
                    counted: false,
                    ..Default::default()
                },
            )
            .await;
    }
    let v = r.cb_view("pf1");
    eprintln!(
        "prefetch_fail: fails={} probe_fail={}",
        v.fails, v.probe_fail
    );
    assert_eq!(v.fails, 0, "预取失败不得计入数据面 fails");
    assert!(!r.cb_is_open("pf1"), "预取失败不得打开熔断");
    assert!(v.probe_fail >= 5, "应累加独立 probe_fail");
}

/// 数据面失败**仍能**正常打开熔断（确认没"修过头变成永不熔断"）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dataplane_failures_still_open_circuit() {
    let s1 = spawn_mock(0, Kind::NoReply).await;
    let ups = vec![up("dp1", s1.port)];
    let mut cfg = ResolverConfig::default();
    cfg.upstreams = ups.clone();
    cfg.timeout_ms = 100;
    cfg.circuit_fails = 3;
    cfg.circuit_open_s = 30.0;

    let rt = Arc::new(UpstreamRuntime::new());
    let r = Resolver::new(
        cfg.clone(),
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(100_000.0)),
        Arc::new(ebpdns_resolver::query::ScriptedQuerier::new(|_, _, _| {
            Vec::new()
        })),
    );
    r.set_runtime(rt.clone());
    let tuning = r.querier_tuning();
    r.set_querier(Arc::new(
        ProductionQuerier::new(
            rt.clone(),
            SharedCircuit::new(),
            Arc::new(MockClock::new(100_000.0)),
            cfg.timeout_ms,
            false,
            1232,
            false,
            false,
        )
        .with_tuning(tuning),
    ));
    for _ in 0..3 {
        let _ = r
            .clone()
            .resolve("dp-fail.test", "A", ResolveOpts::default())
            .await;
    }
    let v = r.cb_view("dp1");
    eprintln!(
        "dataplane: fails={} open={} until_in_s={}",
        v.fails,
        r.cb_is_open("dp1"),
        v.until_in_s
    );
    assert!(v.fails >= 3, "数据面失败必须累计 fails");
    assert!(r.cb_is_open("dp1"), "3 次数据面失败必须打开熔断");
}

/* --------------------------- 5. 健康检查覆盖率的轮转步长（优化项 7） --------------------------- */

/// 起一个已接好 runtime 的 Resolver（供健康检查覆盖用例使用）。
fn resolver_with_ups(cfg: ResolverConfig, rt: Arc<UpstreamRuntime>) -> Arc<Resolver> {
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(100_000.0)),
        Arc::new(ebpdns_resolver::query::ScriptedQuerier::new(|_, _, _| {
            Vec::new()
        })),
    );
    r.set_runtime(rt);
    r
}

/// 后台健康循环的真实触发方式（`health_check_once` 是 `pub(crate)`，
/// 集成测试通过 `spawn_background_tasks` + `health_check_interval` 驱动）。
/// 健康循环**先 sleep 一个周期**再探，故多等 500ms 以避免与驱动 sleep 同时到期。
async fn drive_health_for(r: &Arc<Resolver>, secs: u64) -> Vec<tokio::task::JoinHandle<()>> {
    let handles = r.spawn_background_tasks();
    tokio::time::sleep(std::time::Duration::from_millis(secs * 1000 + 500)).await;
    r.shutdown();
    handles
}

/// **覆盖缺陷（核心）**：`enabled > 8` 时轮转用 `fetch_add(per=3)`，
/// 偏移只能取 `{3k mod n}` 这个子群 —— `gcd(n,3) > 1` 时**大部分上游永远探不到**。
///
/// 12 个上游、健康探针全部成功（真实 UDP 假上游），跑 3~4 轮：
/// 期望（`ceil(12/3)=4` 轮全覆盖）12 个上游都被探到；
/// 实际偏移只在 {0,3,6,9} 之间循环，其余 8 个上游 0 次。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotation_step_three_skips_upstreams_when_n_divisible_by_three() {
    // 12 个真实应答的假上游 → 探针必然成功，计数不受超时/丢包影响。
    let mut mocks = Vec::new();
    for _ in 0..12 {
        mocks.push(spawn_mock(0, Kind::Positive).await);
    }
    let ups: Vec<UpstreamCfg> = mocks
        .iter()
        .enumerate()
        .map(|(i, m)| up(&format!("r{i:02}"), m.port))
        .collect();

    let mut cfg = ResolverConfig::default();
    cfg.upstreams = ups;
    cfg.health_check_interval = 1; // 每秒一轮
    cfg.prefetch = false;
    cfg.rule_sub_interval = 0;
    cfg.subscriptions = Vec::new();
    cfg.probe_timeout_ms = 300;
    cfg.dnssec_0x20 = false; // 假上游恒回显 question；关掉 0x20 减少变量

    let rt = Arc::new(UpstreamRuntime::new());
    let r = resolver_with_ups(cfg, rt.clone());
    let handles = drive_health_for(&r, 5).await;
    for h in handles {
        h.abort();
    }

    let counts: Vec<usize> = mocks
        .iter()
        .map(|m| m.queries.load(Ordering::SeqCst))
        .collect();
    let touched = counts.iter().filter(|c| **c > 0).count();
    let total: usize = counts.iter().sum();
    let never: Vec<usize> = counts
        .iter()
        .enumerate()
        .filter(|(_, c)| **c == 0)
        .map(|(i, _)| i)
        .collect();
    eprintln!(
        "rotation(step=3,n=12): per-upstream={counts:?} touched={touched}/12 never={never:?} total={total}"
    );
    assert!(
        total >= 9,
        "4 轮 × 每轮 3 个 ≥ 9 次派发（实测 {total}，探针池容量 8 足够）"
    );
    assert_eq!(
        touched, 12,
        "优化项 7 要求「>8 时单个上游最迟 ceil(N/3)=4 轮必被探到」，\
         实测 {touched}/12（never={never:?}，计数={counts:?}）"
    );
    // 轮次总数取决于真实时钟（`drive_health_for` 跑 5.5s / interval=1s → 5 轮 × 3 = 15），
    // 故只断言"每轮 3 个、无大量重复"的区间，**不**把轮数写死成 4
    // （旧断言 `total == touched` 依赖恰好 4 轮，属时间抖动，非逻辑回归）。
    assert!(
        total >= 12 && total <= touched * 3,
        "4~5 轮 × 每轮 3 个应落在 [12, 36]，实测 total={total} touched={touched} 计数={counts:?}"
    );
}

/// 边界：恰好 8 个 enabled → 走「全探」分支（1 轮 8 个）；
/// 9 个 → 走轮转（每轮 3 个，且 `gcd(9,3)=3` → 只有 3 个下游能被轮转到）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn health_probe_all_boundary_at_eight_and_nine() {
    let mut observed = Vec::new();
    for n in [8usize, 9usize] {
        let mut mocks = Vec::new();
        for _ in 0..n {
            mocks.push(spawn_mock(0, Kind::Positive).await);
        }
        let ups: Vec<UpstreamCfg> = mocks
            .iter()
            .enumerate()
            .map(|(i, m)| up(&format!("b{i}"), m.port))
            .collect();
        let mut cfg = ResolverConfig::default();
        cfg.upstreams = ups;
        cfg.health_check_interval = 1;
        cfg.prefetch = false;
        cfg.rule_sub_interval = 0;
        cfg.subscriptions = Vec::new();
        cfg.probe_timeout_ms = 300;
        cfg.dnssec_0x20 = false;
        let rt = Arc::new(UpstreamRuntime::new());
        let r = resolver_with_ups(cfg, rt.clone());
        // n=8：1 轮即全覆盖；n=9：多跑几轮看轮转能覆盖多少。
        let secs = if n == 8 { 1 } else { 4 };
        let handles = drive_health_for(&r, secs).await;
        for h in handles {
            h.abort();
        }
        let counts: Vec<usize> = mocks
            .iter()
            .map(|m| m.queries.load(Ordering::SeqCst))
            .collect();
        let touched = counts.iter().filter(|c| **c > 0).count();
        let total: usize = counts.iter().sum();
        eprintln!("boundary n={n} secs={secs}: touched={touched} total={total} counts={counts:?}");
        observed.push((n, touched, total, counts));
        if n == 8 {
            assert_eq!(touched, 8, "n=8 必须一轮全覆盖（≤8 走全探分支）");
        }
    }
    let (n9, touched9, _total9, counts9) = &observed[1];
    assert_eq!(*n9, 9);
    assert_eq!(
        *touched9, 9,
        "n=9（>8 走轮转）在 N 轮内必须覆盖全部上游，实测 {touched9}/9（counts={counts9:?}）"
    );
}
