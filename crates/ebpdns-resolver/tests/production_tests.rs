//! 生产接线装配测试：`new_production` 构造、后台任务 spawn/shutdown 联动。
//! 全部确定性、不联网/不起服（死上游优雅失败）。

use std::sync::Arc;
use std::time::Duration;

use ebpdns_resolver::clock::RealClock;
use ebpdns_resolver::config::{ResolverConfig, UpstreamCfg};
use ebpdns_resolver::resolve::ResolveOpts;
use ebpdns_resolver::telemetry::NoopTelemetry;
use ebpdns_resolver::Resolver;
use ebpdns_upstream::UpstreamRuntime;

fn prod_cfg() -> ResolverConfig {
    let ups = vec![UpstreamCfg {
        id: "up1".into(),
        name: "up1".into(),
        proto: "udp".into(),
        host: "127.0.0.1".into(),
        // 端口 1 保证无人监听（**不要用 5353**：隔离测试实例常监听 127.0.0.1:5353，
        // 会让 fail-closed 断言拿到"活上游"而随机失败）。
        port: 1,
        url: String::new(),
        enabled: true,
        latency: 10,
        weight: 1.0,
        group: None,
        allow_private_ip: false,
    }];
    ResolverConfig {
        upstreams: ups,
        rules: Vec::new(),
        cache_size: 64,
        cache_policy: "lru".into(),
        max_parallel_upstreams: 1,
        timeout_ms: 100,
        nxdomain_quorum: 1,
        prefetch: true,
        health_check_interval: 1,
        subscriptions: vec!["http://127.0.0.1:1/rules".into()], // 不可达 → 优雅失败
        rule_sub_interval: 1,
        ..Default::default()
    }
}

#[test]
fn test_new_production_constructs() {
    let runtime = Arc::new(UpstreamRuntime::new());
    let _r = Resolver::new_production(prod_cfg(), runtime, Arc::new(NoopTelemetry));
    // 真实时钟接入不 panic。
    let _c = RealClock::default();
}

#[tokio::test]
async fn test_production_resolve_dead_upstream_fail_closed() {
    let runtime = Arc::new(UpstreamRuntime::new());
    let r = Resolver::new_production(prod_cfg(), runtime, Arc::new(NoopTelemetry));
    // 死上游 → fail-closed SERVFAIL，不 panic。
    let res = r
        .clone()
        .resolve("example.com", "A", ResolveOpts::default())
        .await;
    assert!(res.error, "死上游应 fail-closed: {res:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_production_background_tasks_shutdown_clean() {
    let runtime = Arc::new(UpstreamRuntime::new());
    let r = Resolver::new_production(prod_cfg(), runtime, Arc::new(NoopTelemetry));
    let handles = r.spawn_background_tasks();
    // 三个后台循环都应被 spawn（health / prefetch / bg）。
    assert!(
        handles.len() >= 2,
        "应 spawn 后台任务, got {}",
        handles.len()
    );
    // 给它们跑一小会（健康检查/订阅拉取会优雅失败）。
    tokio::time::sleep(Duration::from_millis(150)).await;
    r.shutdown();
    // shutdown 应让所有任务及时退出。
    for h in handles {
        tokio::time::timeout(Duration::from_secs(2), h)
            .await
            .expect("后台任务应在 shutdown 后及时退出")
            .expect("任务不应 panic");
    }
}

/* ============ 2.1.19（F-01）：warmup / 在途 governor 的**生产接线**回归 ============ */

/// 计数 querier：用 `ScriptedQuerier` + 计数闭包（**不需要** `async-trait` 进 dev-deps）。
///
/// warmup 对**每个启用上游**各调一次 `query_parallel`，因此调用次数 == 发出的探测查询数。
/// 返回一条成功应答（否则预热会把它算作 `conn_fail`，但调用次数照记）。
fn counting_querier(
    calls: Arc<std::sync::atomic::AtomicUsize>,
) -> ebpdns_resolver::query::ScriptedQuerier {
    ebpdns_resolver::query::ScriptedQuerier::new(move |_d, _q, _depth| {
        calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        vec![ebpdns_resolver::types::UpstreamAnswer::ok(
            "up",
            0,
            vec![ebpdns_resolver::types::ResolveAnswer::new(
                "1.2.3.4", 300.0, 1,
            )],
            vec![],
        )]
    })
}

/// **F-01（P1）**：生产装配路径（`Resolver::new` + `set_querier_tuning` +
/// `set_runtime`）**必须**显式启动 `spawn_upstream_warmup` —— 此前该任务**只在**
/// 测试专用 `new_production` 里被调用，生产上 `warmup.enabled=true, queries=3`
/// 启动 8s 内上游收到 **0** 条探测查询（功能契约存在但不可达）。
///
/// 判据：`warmup_queries × 启用上游数` 条查询必须**真的发出**。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn f01_warmup_actually_queries_enabled_upstreams() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let ups = vec![UpstreamCfg::test_up("w1"), UpstreamCfg::test_up("w2")];
    let mut cfg = ResolverConfig::test_default(ups, vec![], 2);
    cfg.warmup_enabled = true;
    cfg.warmup_queries = 3;
    cfg.warmup_timeout_ms = 5_000;
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(RealClock::default()),
        Arc::new(counting_querier(calls.clone())),
    );
    // 生产装配：runtime 必须先注入，否则 `spawn_inflight_governor` 按设计直接返回。
    r.set_runtime(Arc::new(UpstreamRuntime::new()));
    // 与 `main.rs` 生产装配**同一调用序列**。
    r.spawn_upstream_warmup();

    // 预热是 fire-and-forget：轮询等待（最多 2s）。
    let want = 2 * 3;
    let mut got = 0usize;
    for _ in 0..200 {
        got = calls.load(std::sync::atomic::Ordering::Relaxed);
        if got >= want {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        got, want,
        "warmup 必须向每个启用上游发 warmup_queries 条查询（实测 {got}，期望 {want}）"
    );
}

/// **F-01（P1）**：`spawn_inflight_governor` 必须真的启动（可断言，不靠日志）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn f01_inflight_governor_task_actually_runs() {
    let ups = vec![UpstreamCfg::test_up("g1")];
    let cfg = ResolverConfig::test_default(ups, vec![], 1);
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(RealClock::default()),
        Arc::new(counting_querier(Arc::new(
            std::sync::atomic::AtomicUsize::new(0),
        ))),
    );
    r.set_runtime(Arc::new(UpstreamRuntime::new()));
    assert_eq!(r.inflight_governor_ticks(), 0, "启动前应为 0");
    r.spawn_inflight_governor();
    // `interval` 首 tick 立即返回 ⇒ 很快应 ≥1。
    let mut ticks = 0;
    for _ in 0..200 {
        ticks = r.inflight_governor_ticks();
        if ticks >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        ticks >= 1,
        "在途 governor 任务必须真的跑起来（实测 ticks={ticks}）"
    );
}

/// **F-01 反向**：`warmup_enabled=false` 时**不得**发任何探测查询
/// （防止"接线"变成"无条件打上游"）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn f01_warmup_disabled_sends_nothing() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let ups = vec![UpstreamCfg::test_up("w3")];
    let mut cfg = ResolverConfig::test_default(ups, vec![], 1);
    cfg.warmup_enabled = false;
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(RealClock::default()),
        Arc::new(counting_querier(calls.clone())),
    );
    r.set_runtime(Arc::new(UpstreamRuntime::new()));
    r.spawn_upstream_warmup();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "warmup 关闭时不得发探测查询"
    );
}
