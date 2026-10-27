//! 2.1.8 对抗性审查单测·第二部分（只读审查附带证明用例，不修改生产逻辑）。
//!
//! 回答两个资源类问题：
//! 1. `abort_all` / 超时取消之后，被取消任务的 **fd 与连接**是否被释放
//!    （UDP 查询 socket + DoH 的 TCP 连接池槽位/连接本身）；
//! 2. 早退路径下「谁真正被发出去、谁没被记入 HealthKeeper」。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ebpdns_proto::constants::TYPE_A;
use ebpdns_proto::record::AnswerInput;
use ebpdns_resolver::breaker::SharedCircuit;
use ebpdns_resolver::clock::MockClock;
use ebpdns_resolver::config::ResolverConfig;
use ebpdns_resolver::production::{ProductionQuerier, QuerierTuning};
use ebpdns_resolver::query::ParallelQuerier;
use ebpdns_upstream::UpstreamRuntime;

/* ------------------------------- UDP 假上游 ------------------------------- */

async fn spawn_udp_mock(reply: bool) -> (u16, Arc<AtomicUsize>) {
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
            if let Some(r) = ebpdns_proto::response::build_response(
                &q,
                "mock.test",
                TYPE_A,
                &[AnswerInput::new(TYPE_A, "1.2.3.4")],
                0,
                None,
                None,
                false,
            ) {
                let _ = sock.send_to(&r, peer).await;
            }
        }
    });
    (port, n)
}

fn up(id: &str, port: u16) -> ebpdns_resolver::config::UpstreamCfg {
    ebpdns_resolver::config::UpstreamCfg {
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

/// 统计本进程打开的文件描述符数（Linux `/proc/self/fd`）。
fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .map(|it| it.count())
        .unwrap_or(0)
}

/* --------------------------- 1. 取消后 UDP socket 释放 --------------------------- */

/// 早退/超时取消后，被取消任务持有的 UDP socket 必须随 future drop 关闭：
/// 200 次并发早退查询后 fd 数不得净增长。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_sockets_are_released_after_early_return() {
    let (p_fast, n_fast) = spawn_udp_mock(true).await;
    let (p_slow, n_slow) = spawn_udp_mock(false).await;
    let (p_slow2, n_slow2) = spawn_udp_mock(false).await;

    let cfg = ResolverConfig::default();
    let rt = Arc::new(UpstreamRuntime::new());
    let q = Arc::new(
        ProductionQuerier::new(
            rt.clone(),
            SharedCircuit::new(),
            Arc::new(MockClock::new(100_000.0)),
            800,
            false,
            1232,
            false,
            false,
        )
        .with_tuning(QuerierTuning::from_config(&cfg)),
    );
    let ups = vec![up("fast", p_fast), up("slow", p_slow), up("slow2", p_slow2)];

    // 预热一轮（避免首次分配污染 fd 基线）。
    let _ = q.query_parallel(&ups, "fd.test", "A", 0).await;
    // 分 4 批，逐批差分求和：fd 只在批次间净增长才说明泄漏（单批内的残留不影响求和）。
    let mut fd_delta_sum: i64 = 0;
    let mut lens = 0usize;
    for batch in 0..4 {
        let before = open_fds();
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..50 {
            let q = q.clone();
            let ups = ups.clone();
            set.spawn(async move { q.query_parallel(&ups, "fd.test", "A", 0).await.len() });
        }
        while let Some(Ok(l)) = set.join_next().await {
            lens += l;
        }
        let after = open_fds();
        fd_delta_sum += after as i64 - before as i64;
        eprintln!("udp abort batch {batch}: fds {before} -> {after}");
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let after_all = open_fds();
    eprintln!(
        "udp abort: fds_after_all={after_all} sum(delta)={fd_delta_sum}, dispatched={} fast={} slow={} slow2={} results_len_sum={}",
        q.tuning().dispatched(),
        n_fast.load(Ordering::SeqCst),
        n_slow.load(Ordering::SeqCst),
        n_slow2.load(Ordering::SeqCst),
        lens
    );
    assert!(
        fd_delta_sum <= 8,
        "取消后 fd 不得逐批净增长（4 批差分和 = {fd_delta_sum}）"
    );
    // 每个上游每次查询至多派发 1 次（无重复派发）；预热 +1。
    assert!(
        n_fast.load(Ordering::SeqCst) >= 200 && n_fast.load(Ordering::SeqCst) <= 202,
        "fast 上游应恰被查 ~201 次（含预热，实测 {}）",
        n_fast.load(Ordering::SeqCst)
    );
    assert!(
        n_slow.load(Ordering::SeqCst) <= 201 && n_slow2.load(Ordering::SeqCst) <= 201,
        "慢上游派发次数不得超过查询数（实测 slow={} slow2={}）",
        n_slow.load(Ordering::SeqCst),
        n_slow2.load(Ordering::SeqCst)
    );
    assert!(
        lens >= 200,
        "200 次查询每次至少返回 1 条正向答案（实测 {lens}）"
    );
}

/* --------------------------- 2. DoH 取消后连接释放 --------------------------- */

/// 取消一次在途 DoH 查询后，服务端 TCP 连接必须被关闭（连接池槽位/连接不泄漏）。
/// 客户端指向本地 TLS 服务端（握手不会完成），查询超时→失败→**连接即弃**
/// （`doh.rs` 的 `Checkout` 随 future drop，`OwnedSemaphorePermit` 归还、
/// TCP 连接 drop 即 close）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn doh_cancellation_closes_server_side_connection() {
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let alive = Arc::new(AtomicUsize::new(0));
    let accepted = Arc::new(AtomicUsize::new(0));
    {
        let alive = alive.clone();
        let accepted = accepted.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut tcp, _)) = listener.accept().await else {
                    break;
                };
                accepted.fetch_add(1, Ordering::SeqCst);
                alive.fetch_add(1, Ordering::SeqCst);
                let alive = alive.clone();
                tokio::spawn(async move {
                    // 只观察对端是否关闭：EOF 即代表客户端已释放连接。
                    let mut buf = [0u8; 4096];
                    loop {
                        match tcp.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => continue, // 收下 ClientHello 但不回应 → 握手悬停
                        }
                    }
                    alive.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
    }

    let rt = Arc::new(UpstreamRuntime::new());
    let cfg = ResolverConfig::default();
    let q = ProductionQuerier::new(
        rt.clone(),
        SharedCircuit::new(),
        Arc::new(MockClock::new(100_000.0)),
        400, // DoH 单次超时 400ms
        false,
        1232,
        false,
        false,
    )
    .with_tuning(QuerierTuning::from_config(&cfg));
    let doh = ebpdns_resolver::config::UpstreamCfg {
        proto: "doh".to_string(),
        host: "127.0.0.1".to_string(),
        url: "/dns-query".to_string(),
        ..up("doh-local", port)
    };

    let out = match tokio::time::timeout(
        std::time::Duration::from_secs(3),
        q.query_parallel(&[doh], "doh.test", "A", 0),
    )
    .await
    {
        Ok(v) => v,
        Err(_) => panic!(
            "doh_query 的 400ms 超时没有约束 TLS 握手：connect+TLS 阶段无 deadline，\
             整轮查询挂死超过 3s（生产由 ProductionQuerier 外层超时兜住，但挂起期间\
             连接/fd/池槽位一直占用）"
        ),
    };
    assert!(out[0].rcode.is_none(), "本地假 TLS 服务端不应答 → 失败");
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    let alive_now = alive.load(Ordering::SeqCst);
    eprintln!(
        "doh cancel: accepted={} alive_after={}",
        accepted.load(Ordering::SeqCst),
        alive_now
    );
    assert!(accepted.load(Ordering::SeqCst) >= 1, "应真正发起过连接");
    assert_eq!(
        alive_now, 0,
        "取消/超时后服务端连接必须被关闭（alive={alive_now}）—— 否则 fd 与池槽位泄漏"
    );
}
