//! 2.1.8 对抗性审查·诊断用例（只读）：验证假上游应答能否被 `classify_one` 认成正向答案。
//! 若这里的正/负控制组都通过，而 `early_return_on_first_positive_answer` 仍失败，
//! 说明问题出在 `ProductionQuerier::query_parallel` 而非测试夹具。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ebpdns_proto::constants::TYPE_A;
use ebpdns_proto::record::AnswerInput;
use ebpdns_resolver::breaker::SharedCircuit;
use ebpdns_resolver::clock::MockClock;
use ebpdns_resolver::config::{ResolverConfig, UpstreamCfg};
use ebpdns_resolver::production::{ProductionQuerier, QuerierTuning};
use ebpdns_resolver::query::{classify_one, ParallelQuerier};
use ebpdns_upstream::UpstreamRuntime;

async fn spawn_mock(reply: bool, kind: u8) -> (u16, Arc<AtomicUsize>) {
    spawn_mock_delay(reply, kind, 0).await
}

async fn spawn_mock_delay(reply: bool, kind: u8, delay_ms: u64) -> (u16, Arc<AtomicUsize>) {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    let n = Arc::new(AtomicUsize::new(0));
    let c = n.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, peer)) = sock.recv_from(&mut buf).await else {
                break;
            };
            c.fetch_add(1, Ordering::SeqCst);
            if !reply {
                continue;
            }
            let q = buf[..len].to_vec();
            if delay_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }
            let r = match kind {
                0 => ebpdns_proto::response::build_response(
                    &q,
                    "mock.test",
                    TYPE_A,
                    &[AnswerInput::new(TYPE_A, "1.2.3.4").with_ttl(60)],
                    0,
                    None,
                    None,
                    false,
                ),
                _ => ebpdns_proto::response::build_simple_response(&q, 3),
            };
            if let Some(r) = r {
                let _ = sock.send_to(&r, peer).await;
            }
        }
    });
    (port, n)
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

/// 控制组：`classify_one` 必须把假上游的 A 应答认成 NOERROR + 1 条答案。
#[test]
fn classify_one_accepts_synthetic_a_answer() {
    // 手工构造一个最小查询（与 ProductionQuerier 内部一致：无 EDNS、无 padding）。
    let (q, _) =
        ebpdns_proto::query::build_query("mock.test", TYPE_A, None, false, None, None, false)
            .unwrap();
    let resp = ebpdns_proto::response::build_response(
        &q,
        "mock.test",
        TYPE_A,
        &[AnswerInput::new(TYPE_A, "1.2.3.4").with_ttl(60)],
        0,
        None,
        None,
        false,
    )
    .unwrap();
    let a = classify_one("m1", "mock.test", &resp, TYPE_A, 12.0);
    eprintln!(
        "classify_one(no-edns): rcode={:?} answers={:?} trunc={}",
        a.rcode,
        a.answers
            .iter()
            .map(|x| x.value.clone())
            .collect::<Vec<_>>(),
        a.udp_truncated
    );
    assert_eq!(a.rcode, Some(0));
    assert_eq!(a.answers.len(), 1);
    assert!(!a.udp_truncated);

    // 带 EDNS（生产配置 edns=true, udp_size=1232）时同样要成立。
    let (q2, _) =
        ebpdns_proto::query::build_query("mock.test", TYPE_A, None, true, None, Some(1232), false)
            .unwrap();
    let resp2 = ebpdns_proto::response::build_response(
        &q2,
        "mock.test",
        TYPE_A,
        &[AnswerInput::new(TYPE_A, "1.2.3.4").with_ttl(60)],
        0,
        None,
        None,
        false,
    )
    .unwrap();
    let a2 = classify_one("m1", "mock.test", &resp2, TYPE_A, 12.0);
    eprintln!(
        "classify_one(edns): rcode={:?} answers={:?} trunc={} resp_len={}",
        a2.rcode,
        a2.answers
            .iter()
            .map(|x| x.value.clone())
            .collect::<Vec<_>>(),
        a2.udp_truncated,
        resp2.len()
    );
    assert_eq!(a2.rcode, Some(0));
    assert_eq!(a2.answers.len(), 1, "EDNS 应答也必须解析出 1 条答案");
}

/// 单个假上游（正向应答）：`query_parallel` 必须返回 1 条正向答案并触发首答即返。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_positive_mock_upstream_is_detected() {
    let (port, n) = spawn_mock(true, 0).await;
    let cfg = ResolverConfig::default();
    let rt = Arc::new(UpstreamRuntime::new());
    let q = ProductionQuerier::new(
        rt.clone(),
        SharedCircuit::new(),
        Arc::new(MockClock::new(100_000.0)),
        800,
        cfg.edns,
        1232,
        false,
        false,
    )
    .with_tuning(QuerierTuning::from_config(&cfg));
    let out = q
        .query_parallel(&[up("m1", port)], "mock.test", "A", 0)
        .await;
    eprintln!(
        "single mock: queries={} dispatched={} early={} out={:?}",
        n.load(Ordering::SeqCst),
        q.tuning().dispatched(),
        q.tuning().early_returns(),
        out.iter()
            .map(|a| (a.up_name.clone(), a.rcode, a.answers.len(), a.udp_truncated))
            .collect::<Vec<_>>()
    );
    assert_eq!(n.load(Ordering::SeqCst), 1, "假上游必须收到 1 次查询");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].rcode, Some(0), "必须是 NOERROR");
    assert_eq!(out[0].answers.len(), 1, "必须有 1 条答案");
    assert_eq!(q.tuning().early_returns(), 1, "必须触发首答即返");
}

/// 单个假上游（NXDOMAIN）：早退不得触发，且结果必须是 rcode=3。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_nxdomain_mock_upstream_is_detected() {
    let (port, n) = spawn_mock(true, 3).await;
    let cfg = ResolverConfig::default();
    let rt = Arc::new(UpstreamRuntime::new());
    let q = ProductionQuerier::new(
        rt.clone(),
        SharedCircuit::new(),
        Arc::new(MockClock::new(100_000.0)),
        800,
        cfg.edns,
        1232,
        false,
        false,
    )
    .with_tuning(QuerierTuning::from_config(&cfg));
    let out = q
        .query_parallel(&[up("m1", port)], "mock.test", "A", 0)
        .await;
    eprintln!(
        "single nx: queries={} early={} out={:?}",
        n.load(Ordering::SeqCst),
        q.tuning().early_returns(),
        out.iter()
            .map(|a| (a.up_name.clone(), a.rcode))
            .collect::<Vec<_>>()
    );
    assert_eq!(n.load(Ordering::SeqCst), 1);
    assert_eq!(out[0].rcode, Some(3), "必须是 NXDOMAIN");
    assert_eq!(q.tuning().early_returns(), 0, "NXDOMAIN 不得触发首答即返");
}

/// 三上游场景（复现 `adv218_tests::early_return_on_first_positive_answer`）：
/// 打印每个上游的实测计数与每条结果的细节，定位早退为何未触发。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_upstream_early_return_diagnostic() {
    let (p1, n1) = spawn_mock_delay(true, 0, 20).await;
    let (p2, n2) = spawn_mock_delay(true, 3, 400).await;
    let (p3, n3) = spawn_mock_delay(true, 0, 700).await;
    let cfg = ResolverConfig::default();
    let rt = Arc::new(UpstreamRuntime::new());
    let q = ProductionQuerier::new(
        rt.clone(),
        SharedCircuit::new(),
        Arc::new(MockClock::new(100_000.0)),
        1500,
        cfg.edns,
        1232,
        false,
        false,
    )
    .with_tuning(QuerierTuning::from_config(&cfg));
    let ups = vec![up("m1", p1), up("m2", p2), up("m3", p3)];
    let t0 = std::time::Instant::now();
    let out = q.query_parallel(&ups, "mock.test", "A", 0).await;
    let el = t0.elapsed().as_millis();
    eprintln!(
        "three: elapsed={el}ms n1={} n2={} n3={} dispatched={} early={} out={:?}",
        n1.load(Ordering::SeqCst),
        n2.load(Ordering::SeqCst),
        n3.load(Ordering::SeqCst),
        q.tuning().dispatched(),
        q.tuning().early_returns(),
        out.iter()
            .map(|a| (a.up_name.clone(), a.rcode, a.answers.len(), a.udp_truncated))
            .collect::<Vec<_>>()
    );
}
