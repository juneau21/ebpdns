//! 移植自 review161/tests/test_upstream.py：全部用本地 socket / 本地状态机，不依赖外网。

use ebpdns_upstream::*;

/// 构造一个合法 DNS 查询字节（A 记录 example.com，固定 qid 0x1234）。
fn make_query() -> Vec<u8> {
    let mut q = Vec::new();
    q.extend(0x1234u16.to_be_bytes()); // id
    q.extend(0x0100u16.to_be_bytes()); // flags RD
    q.extend(1u16.to_be_bytes()); // qd
    q.extend(0u16.to_be_bytes());
    q.extend(0u16.to_be_bytes());
    q.extend(0u16.to_be_bytes());
    q.extend(b"\x07example\x03com\x00");
    q.extend(1u16.to_be_bytes()); // A
    q.extend(1u16.to_be_bytes()); // IN
    q
}

/// 构造一个合法 DNS 响应字节（qd=1, an=1，回显 qid）。
fn make_response(qid: u16, qdcount: u16, ancount: u16) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend(qid.to_be_bytes());
    r.extend(0x8180u16.to_be_bytes()); // flags QR+RD+RA
    r.extend(qdcount.to_be_bytes());
    r.extend(ancount.to_be_bytes());
    r.extend(0u16.to_be_bytes());
    r.extend(0u16.to_be_bytes());
    // question
    r.extend(b"\x07example\x03com\x00");
    r.extend(1u16.to_be_bytes());
    r.extend(1u16.to_be_bytes());
    // answer（压缩指针 + A 记录）
    if ancount > 0 {
        r.extend(0xC00Cu16.to_be_bytes());
        r.extend(1u16.to_be_bytes()); // A
        r.extend(1u16.to_be_bytes()); // IN
        r.extend(60u32.to_be_bytes()); // TTL
        r.extend(4u16.to_be_bytes()); // rdlength
        r.extend(&[93, 184, 216, 34]); // 93.184.216.34
    }
    r
}

#[test]
fn parse_addr_basic() {
    // udp 默认端口 53。
    let p = parse_upstream_addr("8.8.8.8", Some("udp")).unwrap();
    assert_eq!(p.host, "8.8.8.8");
    assert_eq!(p.port, 53);
    assert_eq!(p.proto, Proto::Udp);

    // DoH https 默认 443 + 路径。
    let p = parse_upstream_addr("https://dns.google/dns-query", None).unwrap();
    assert_eq!(p.proto, Proto::Doh);
    assert_eq!(p.host, "dns.google");
    assert_eq!(p.port, 443);
    assert_eq!(p.url, "/dns-query");

    // DoQ scheme。
    let p = parse_upstream_addr("quic://dns.adguard-dns.com:8853", None).unwrap();
    assert_eq!(p.proto, Proto::Doq);
    assert_eq!(p.port, 8853);

    // IPv6 [::1]:5300 —— D4/D5 分叉显式固化：
    // **[历史归因]**   权威 Python `config.parse_upstream_addr("[::1]:5300")` 返回
    //   `addr="[::1]"`（**保留**方括号，config.py:314 `host = host[:_rb + 1]`）。
    //   Rust 交付 **裸** `"::1"`（此处断言），因为 `UpstreamConfig.host` 的既有契约
    //   就是"已剥离 `[`"（crates/ebpdns-upstream/src/config.rs:12），
    //   `tcp::resolve_target` / `udp::resolve_udp_addrs` / `doh::connect_doh` / quic
    //   都对 host 直接 `IpAddr::parse` / `getaddrinfo`——保留方括号会让这四处双失败。
    // **[历史归因]**   Python 侧每次使用时经 `upstream._host_port()` 再剥一次括号（upstream.py:599），
    //   端到端连接目标一致；Rust 把这次剥离提前到解析期。
    //   即：**连接语义等价，存储形态分叉**（分叉已在此处被测试固定，不会被静默回归）。
    let p = parse_upstream_addr("[::1]:5300", Some("tcp")).unwrap();
    assert_eq!(p.host, "::1");
    assert_eq!(p.port, 5300);
    assert_eq!(p.proto, Proto::Tcp);

    // **[历史归因]** 同一分支的其它形态（与 Python 实测逐条对齐，详见 addr.rs 的三分支测试矩阵）。
    assert_eq!(
        parse_upstream_addr("[::1]", Some("udp")).unwrap().host,
        "::1"
    );
    assert!(parse_upstream_addr("[]:80", None).is_err());
    assert!(parse_upstream_addr("[::1", None).is_err());
    assert!(parse_upstream_addr("[::1]:", None).is_err());
    assert!(parse_upstream_addr("[::1]:53a", None).is_err());
    assert!(parse_upstream_addr("[::1]abc", None).is_err());
    assert!(parse_upstream_addr("[::1]:0", None).is_err());
    assert!(parse_upstream_addr("[::1]:65536", None).is_err());

    // 裸 IPv6（冒号 > 1）不切端口。
    let p = parse_upstream_addr("2001:db8::1", None).unwrap();
    assert_eq!((p.host.as_str(), p.port), ("2001:db8::1", 53));

    // 非法：host:port 未命中切分后的残留单冒号（`example.com:` / `example.com:abc`）。
    // **[历史归因]** 权威 Python `config.parse_upstream_addr("example.com:")` 同样返回 None
    // （`tail.isdigit()` 为假 → 不切端口 → config.py:348 的 `count(":") == 1` 拒绝），
    // **[历史归因]** 故此处与 Python 一致，无需放宽。
    assert!(parse_upstream_addr("example.com:", None).is_err());
    assert!(parse_upstream_addr("example.com:abc", None).is_err());
    assert!(parse_upstream_addr("example.com:0", None).is_err());
    assert!(parse_upstream_addr("example.com:65536", None).is_err());
    assert_eq!(
        parse_upstream_addr("example.com:5353", None).unwrap().port,
        5353
    );
}

#[test]
fn private_ip_classification() {
    assert!(is_private_ip("10.0.0.1"));
    assert!(is_private_ip("192.168.1.1"));
    assert!(is_private_ip("127.0.0.1"));
    assert!(is_private_ip("169.254.1.1"));
    assert!(!is_private_ip("8.8.8.8"));
    assert!(!is_private_ip("93.184.216.34"));
    // 域名不拦截。
    assert!(!is_private_ip("example.com"));
}

#[test]
fn hostname_helper() {
    assert!(is_hostname("example.com"));
    assert!(!is_hostname("8.8.8.8"));
    assert!(!is_hostname("::1"));
}

#[tokio::test]
async fn udp_roundtrip_and_header_only_rejected() {
    // 本地 UDP 服务器：回显一个合法响应。
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = sock.local_addr().unwrap().port();
    sock.set_nonblocking(true).unwrap();
    let sock = std::sync::Arc::new(sock);
    let srv = sock.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            match srv.recv_from(&mut buf) {
                Ok((n, src)) => {
                    let resp = make_response(0x1234, 1, 1);
                    let _ = srv.send_to(&resp, src);
                    let _ = &buf[..n];
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                Err(_) => break,
            }
        }
    });

    let rt = std::sync::Arc::new(UpstreamRuntime::new());
    let cfg = UpstreamConfig {
        id: "u1".into(),
        host: "127.0.0.1".into(),
        port,
        proto: Proto::Udp,
        ..Default::default()
    };
    let out = rt.query(&cfg, &make_query(), 1000).await;
    assert!(out.ok, "udp query should succeed, err={:?}", out.err);
    assert!(out.data.unwrap().len() >= 12);
}

#[tokio::test]
async fn tcp_roundtrip() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut lenb = [0u8; 2];
                let _ = stream.read_exact(&mut lenb).await;
                let len = u16::from_be_bytes(lenb) as usize;
                let mut q = vec![0u8; len];
                let _ = stream.read_exact(&mut q).await;
                let resp = make_response(0x1234, 1, 1);
                let mut framed = Vec::new();
                framed.extend((resp.len() as u16).to_be_bytes());
                framed.extend(&resp);
                let _ = stream.write_all(&framed).await;
            });
        }
    });

    let rt = std::sync::Arc::new(UpstreamRuntime::new());
    let cfg = UpstreamConfig {
        id: "t1".into(),
        host: "127.0.0.1".into(),
        port,
        proto: Proto::Tcp,
        ..Default::default()
    };
    let out = rt.query(&cfg, &make_query(), 1000).await;
    assert!(out.ok, "tcp query should succeed, err={:?}", out.err);
}

#[test]
fn quic_error_classification() {
    let (k, _r) = classify_conn_error("tls: certificate verify failed");
    assert_eq!(k, "certificate");
    let (k, _r) = classify_conn_error("Connection refused");
    assert_eq!(k, "refused");
    let (k, _r) = classify_conn_error("dns: no upstream ip");
    assert_eq!(k, "dns");
    let (k, _r) = classify_conn_error("timeout");
    assert_eq!(k, "timeout");
}

/* ================== P1-A：DoH / DoT 握手 deadline ================== */

/// 假的"半死 TLS 终结器"：accept 之后**只读不应答**（客户端 ClientHello 被吞掉，
/// 握手永不完成）。返回 (port, accepted 计数, 关闭信号)。
///
/// 旧实现的 `connect_doh` / `connect_dot` 把 TLS 握手裸 await → 调用方永久挂起；
/// 本模块两个回归测试因此在修复前会**超时失败**（而不是返回错误）。
async fn spawn_silent_tls_peer() -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let acc = accepted.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            acc.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // 持续读取（排空 ClientHello）但从不回写 —— 握手永久停滞。
            tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
            });
        }
    });
    (port, accepted)
}

/// P1-A 核心断言（DoH）：上游只 accept 不做 TLS 时，`query` 必须在
/// **自身 timeout 附近**返回失败，而不是永久挂起。
///
/// 修复前：`connector.connect()` 无 timeout → 本 await 永不返回 → 测试被
/// tokio 的 test-harness 挂死（实测 >8s 仍无返回，见 2.1.9 报告 before 段）。
/// 修复后：≤ timeout + 宽限（此处 1200ms 预算，断言 < 4s，实测 ≈1.2s）。
#[tokio::test]
async fn doh_silent_tls_peer_times_out_instead_of_hanging() {
    let (port, accepted) = spawn_silent_tls_peer().await;
    let rt = std::sync::Arc::new(UpstreamRuntime::new());
    let cfg = UpstreamConfig {
        id: "p1a-doh".into(),
        host: "127.0.0.1".into(),
        port,
        url: "/dns-query".into(),
        proto: Proto::Doh,
        ..Default::default()
    };
    let t0 = std::time::Instant::now();
    // 外层 4s 硬护栏：修复前该 await 不会返回，测试会以此失败（而不是挂死整个套件）。
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(4),
        rt.query(&cfg, &make_query(), 1200),
    )
    .await
    .expect("P1-A 回归：DoH 握手无 deadline，query 在 4s 内未返回（永久挂起）");
    let el = t0.elapsed();
    assert!(!out.ok, "静默 TLS 对端不可能成功: {out:?}");
    assert!(
        el < std::time::Duration::from_millis(2500),
        "DoH 建连超时未生效：耗时 {el:?} 远超 timeout(1200ms)"
    );
    assert!(
        accepted.load(std::sync::atomic::Ordering::Relaxed) >= 1,
        "假对端应至少 accept 一次（证明确实卡在 TLS 握手而非未连上）"
    );
}

/// P1-A 核心断言（DoT）：与 DoH 同一缺陷、同一修法。
#[tokio::test]
async fn dot_silent_tls_peer_times_out_instead_of_hanging() {
    let (port, accepted) = spawn_silent_tls_peer().await;
    let rt = std::sync::Arc::new(UpstreamRuntime::new());
    let cfg = UpstreamConfig {
        id: "p1a-dot".into(),
        host: "127.0.0.1".into(),
        port,
        proto: Proto::Dot,
        ..Default::default()
    };
    let t0 = std::time::Instant::now();
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(4),
        rt.query(&cfg, &make_query(), 1200),
    )
    .await
    .expect("P1-A 回归：DoT 握手无 deadline，query 在 4s 内未返回（永久挂起）");
    let el = t0.elapsed();
    assert!(!out.ok, "静默 TLS 对端不可能成功: {out:?}");
    assert!(
        el < std::time::Duration::from_millis(2500),
        "DoT 建连超时未生效：耗时 {el:?} 远超 timeout(1200ms)"
    );
    assert!(accepted.load(std::sync::atomic::Ordering::Relaxed) >= 1);
}

/// P1-A 的**池自愈**断言：静默对端下连续 `2 * MAX_CONN + 2` 次查询必须全部
/// 在预算内返回（每次都 ≤ timeout + 宽限），**不出现"前 4 次挂死后剩余全部
/// 等信号量超时"的永久劣化**。
///
/// 修复前：前 4 次调用各永久占住一个池许可 → 第 5 次起 `acquire` 只能等
/// 上层 timeout（或永久），上游彻底不可用。
#[tokio::test]
async fn doh_pool_recovers_after_silent_tls_peers() {
    // `slot_cap` 必须与连接池真实上限同源；用 `idle_count`/`key_count` 观测池状态，
    // 避免依赖 crate 私有模块（`pool` 是 `mod pool;`，外部测试不可见）。
    let (port, _accepted) = spawn_silent_tls_peer().await;
    let rt = std::sync::Arc::new(UpstreamRuntime::new());
    let cfg = UpstreamConfig {
        id: "p1a-pool".into(),
        host: "127.0.0.1".into(),
        port,
        url: "/dns-query".into(),
        proto: Proto::Doh,
        ..Default::default()
    };
    let n = 10; // = 2 * MAX_CONN(4) + 2：足够盖过"池槽被永久占住"的阈值
    let t0 = std::time::Instant::now();
    for i in 0..n {
        let out = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            rt.query(&cfg, &make_query(), 800),
        )
        .await
        .unwrap_or_else(|_| panic!("第 {} 次查询挂死（池许可泄漏/握手无 deadline）", i + 1));
        assert!(!out.ok);
    }
    let per = t0.elapsed() / n as u32;
    assert!(
        per < std::time::Duration::from_millis(2000),
        "{n} 次静默对端查询平均耗时 {per:?} —— 存在许可泄漏或死等"
    );
    // 池自愈的直接证据：所有连接都已被回收，池里**没有**残留空闲连接被算作存活。
    assert_eq!(rt.pool.idle_count(), 0, "静默对端下不应有连接被放回空闲池");
}

#[tokio::test]
async fn quic_unreachable_fails_fast_with_reason() {
    // 连一个没人监听的端口：建连失败应分类并进入退避。
    let rt = std::sync::Arc::new(UpstreamRuntime::new());
    let cfg = UpstreamConfig {
        id: "q1".into(),
        host: "127.0.0.1".into(),
        port: 1, // 关闭的端口 → refused/不可达
        proto: Proto::Doq,
        strict_cert: true,
        ..Default::default()
    };
    let mgr = rt.quic_manager(&cfg);
    let out = mgr
        .query(&rt, &make_query(), std::time::Duration::from_millis(2000))
        .await;
    assert!(!out.0);
    assert!(!out.2.is_empty());
    // 第二次：退避窗口内应快速失败（不重复握手），仍返回分类原因。
    let out2 = mgr
        .query(&rt, &make_query(), std::time::Duration::from_millis(2000))
        .await;
    assert!(!out2.0);
    assert!(!out2.2.is_empty());
    mgr.close();
}

/// 构造带自定义 flags 的响应。
fn make_response_flags(qid: u16, flags: u16, qdcount: u16, ancount: u16) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend(qid.to_be_bytes());
    r.extend(flags.to_be_bytes());
    r.extend(qdcount.to_be_bytes());
    r.extend(ancount.to_be_bytes());
    r.extend(0u16.to_be_bytes());
    r.extend(0u16.to_be_bytes());
    r.extend(b"\x07example\x03com\x00");
    r.extend(1u16.to_be_bytes());
    r.extend(1u16.to_be_bytes());
    if ancount > 0 {
        r.extend(0xC00Cu16.to_be_bytes());
        r.extend(1u16.to_be_bytes());
        r.extend(1u16.to_be_bytes());
        r.extend(60u32.to_be_bytes());
        r.extend(4u16.to_be_bytes());
        r.extend(&[1, 2, 3, 4]);
    }
    r
}

fn flags_of(pkt: &[u8]) -> u16 {
    u16::from_be_bytes([pkt[2], pkt[3]])
}

/// **2.1.38（flaky 加固）**：TCP 回退三个用例的等待预算（2.1.37 及以前是 1000 ms）。
///
/// 1000 ms 是"空闲机器上的往返时间"，不是"负载下的上界"：整目标并行跑（JOBS>1、同机还有
/// 8 线程压测）时，tokio 工作线程被抢占 1 s 以上是可能的，于是 `out.ok=false` ⇒ 断言偶发红。
/// 这里提到 5000 ms：它**只是等待预算**，成功路径不会因此变慢（数据报一到就返回），
/// 也不是用 sleep 掩盖竞态 —— 竞态由下面的**确定性端口分配**消除。
const UPSTREAM_TEST_TIMEOUT_MS: u64 = 5_000;

/// 确定性分配"同一端口号上 UDP 与 TCP **都**空闲"的一对 socket（TCP 回退成功路径用）。
///
/// 2.1.37 的做法：先 `UdpSocket::bind("127.0.0.1:0")` 拿一个临时端口，再
/// `TcpListener::bind(("127.0.0.1", port)).unwrap()`。UDP 与 TCP 是**两套独立的端口空间**，
/// "临时端口"只保证 **UDP** 侧空闲 ⇒ 高负载并行跑时该号可能已被**别的测试的 TCP 监听**占用，
/// `unwrap()` 直接 panic（现场：隔离单跑 3/3 全过、整目标并行 18/18 才复现）。
/// 现在改成"先 TCP（拿号）→ 再 UDP（同号）"，两边都成功才采用，最多重试 64 次。
async fn bind_udp_tcp_pair() -> (
    std::sync::Arc<tokio::net::UdpSocket>,
    tokio::net::TcpListener,
    u16,
) {
    for _ in 0..64 {
        let listener = match tokio::net::TcpListener::bind(("127.0.0.1", 0)).await {
            Ok(l) => l,
            Err(_) => continue,
        };
        let port = listener.local_addr().unwrap().port();
        match tokio::net::UdpSocket::bind(("127.0.0.1", port)).await {
            Ok(u) => return (std::sync::Arc::new(u), listener, port),
            Err(_) => {
                drop(listener);
                continue;
            }
        }
    }
    panic!("bind_udp_tcp_pair: 64 次尝试都没拿到 UDP+TCP 同时空闲的端口");
}

/// 分配一个"UDP 可绑、且 **TCP 连接被拒**"的端口（`udp_tc_tcp_failure_keeps_truncated` 用）。
///
/// 那个用例要求"TCP 不可达"；若该号恰好被别的测试的 TCP 监听占用，回退会**意外成功**并
/// 返回完整应答（反向 flake）。这里先连一次确认被拒，再交给用例。
async fn bind_udp_tcp_refused() -> (std::sync::Arc<tokio::net::UdpSocket>, u16) {
    for _ in 0..64 {
        let u = match tokio::net::UdpSocket::bind("127.0.0.1:0").await {
            Ok(u) => u,
            Err(_) => continue,
        };
        let port = u.local_addr().unwrap().port();
        // loopback 上"没人听"会立即 RST ⇒ connect 返回 Err；成功则说明有监听者，换一个号。
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err()
        {
            return (std::sync::Arc::new(u), port);
        }
    }
    panic!("bind_udp_tcp_refused: 64 次尝试都没拿到 TCP 侧拒绝的端口");
}

/// UDP 回 TC=1 → 有界 TCP 回退成功，返回 TCP 的完整应答（非截断子集）。
#[tokio::test]
async fn udp_tc_falls_back_to_tcp_and_returns_full() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // **2.1.38**：确定性"同号 UDP+TCP"分配（双栈都空闲才采用，见 bind_udp_tcp_pair）。
    let (udp, listener, port) = bind_udp_tcp_pair().await;
    let usrv = udp.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((_, src)) = usrv.recv_from(&mut buf).await {
            let truncated = make_response_flags(0x1234, 0x8380, 1, 0);
            let _ = usrv.send_to(&truncated, src).await;
        }
    });

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut lenb = [0u8; 2];
                let _ = stream.read_exact(&mut lenb).await;
                let len = u16::from_be_bytes(lenb) as usize;
                let mut q = vec![0u8; len];
                let _ = stream.read_exact(&mut q).await;
                let full = make_response_flags(0x1234, 0x8180, 1, 1);
                let mut framed = Vec::new();
                framed.extend((full.len() as u16).to_be_bytes());
                framed.extend(&full);
                let _ = stream.write_all(&framed).await;
            });
        }
    });

    let rt = std::sync::Arc::new(UpstreamRuntime::new());
    let cfg = UpstreamConfig {
        id: "u2".into(),
        host: "127.0.0.1".into(),
        port,
        proto: Proto::Udp,
        ..Default::default()
    };
    let out = rt
        .query(&cfg, &make_query(), UPSTREAM_TEST_TIMEOUT_MS)
        .await;
    assert!(out.ok, "query should succeed, err={:?}", out.err);
    let data = out.data.unwrap();
    assert_eq!(
        flags_of(&data) & 0x0200,
        0,
        "should return non-truncated TCP answer"
    );
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    assert_eq!(ancount, 1, "should return the full answer from TCP");
}

/// UDP 回 TC=1 但 TCP 不可达 → 回退失败，保留原截断应答（上层据 TC 处理）。
#[tokio::test]
async fn udp_tc_tcp_failure_keeps_truncated() {
    // **2.1.38**：端口先验证"UDP 可绑 + TCP 明确拒绝"，避免该号被别的 TCP 监听占用时
    // 回退意外成功（反向 flake）。
    let (udp, port) = bind_udp_tcp_refused().await;
    let usrv = udp.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((_, src)) = usrv.recv_from(&mut buf).await {
            let truncated = make_response_flags(0x1234, 0x8380, 1, 0);
            let _ = usrv.send_to(&truncated, src).await;
        }
    });

    let rt = std::sync::Arc::new(UpstreamRuntime::new());
    let cfg = UpstreamConfig {
        id: "u3".into(),
        host: "127.0.0.1".into(),
        port,
        proto: Proto::Udp,
        ..Default::default()
    };
    let out = rt
        .query(&cfg, &make_query(), UPSTREAM_TEST_TIMEOUT_MS)
        .await;
    assert!(
        out.ok,
        "should still return truncated udp data, err={:?}",
        out.err
    );
    let data = out.data.unwrap();
    assert_ne!(
        flags_of(&data) & 0x0200,
        0,
        "should keep TC=1 truncated answer"
    );
}

/// UDP 截断(TC=1,rcode=0)，但 TCP 回退返回 SERVFAIL(rcode=2) →
/// 必须沿用原 UDP 截断帧（带 TC），不能把 SERVFAIL 上交。
#[tokio::test]
async fn udp_tc_tcp_servfail_keeps_truncated() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // **2.1.38（flaky 加固）**：原实现用 `UdpSocket::bind(":0")` 取临时端口，再
    // `TcpListener::bind(同号).unwrap()`；UDP/TCP 端口空间独立 ⇒ 高负载并行跑时该号可能已被
    // 别的 TCP 监听占用，`unwrap()` 直接 panic（现场：隔离 3/3 过、整目标 18/18 才复现）。
    // 现在用 bind_udp_tcp_pair 做**确定性分配**（先 TCP 后 UDP，两边都空闲才采用），
    // UDP 服务端改成真正的 async socket（去掉 5 ms 轮询 sleep），并把等待预算提到 5000 ms。
    let (udp, listener, port) = bind_udp_tcp_pair().await;
    let usrv = udp.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((_, src)) = usrv.recv_from(&mut buf).await {
            // 截断：TC=1（byte2=0x83），rcode=0。
            let truncated = make_response_flags(0x1234, 0x8380, 1, 0);
            let _ = usrv.send_to(&truncated, src).await;
        }
    });

    // TCP 假服务器：回 SERVFAIL（rcode=2，byte3=0x82 → flags 0x8182）。
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut lenb = [0u8; 2];
                let _ = stream.read_exact(&mut lenb).await;
                let len = u16::from_be_bytes(lenb) as usize;
                let mut q = vec![0u8; len];
                let _ = stream.read_exact(&mut q).await;
                let servfail = make_response_flags(0x1234, 0x8182, 1, 0);
                let mut framed = Vec::new();
                framed.extend((servfail.len() as u16).to_be_bytes());
                framed.extend(&servfail);
                let _ = stream.write_all(&framed).await;
            });
        }
    });

    let rt = std::sync::Arc::new(UpstreamRuntime::new());
    let cfg = UpstreamConfig {
        id: "u4".into(),
        host: "127.0.0.1".into(),
        port,
        proto: Proto::Udp,
        ..Default::default()
    };
    let out = rt
        .query(&cfg, &make_query(), UPSTREAM_TEST_TIMEOUT_MS)
        .await;
    assert!(out.ok, "should keep truncated udp frame, err={:?}", out.err);
    let data = out.data.unwrap();
    // 沿用 UDP 截断帧：仍带 TC 位。
    assert_ne!(
        flags_of(&data) & 0x0200,
        0,
        "should keep TC=1 truncated frame"
    );
    // 且 rcode 必须为 0（原截断帧），不是 SERVFAIL(2)。
    assert_eq!(flags_of(&data) & 0x000F, 0, "must not adopt SERVFAIL frame");
}

#[test]
fn v4_mapped_and_compatible_and_nat64_blocked() {
    // IPv4-mapped loopback/private/link-local。
    assert!(is_private_ip("::ffff:127.0.0.1"));
    assert!(is_private_ip("::ffff:10.0.0.1"));
    assert!(is_private_ip("::ffff:169.254.1.1"));
    // mapped 公网 v4 不拦。
    assert!(!is_private_ip("::ffff:8.8.8.8"));
    // IPv4-compatible ::a.b.c.d（::/96 整段 reserved，含公网 v4）。
    assert!(is_private_ip("::10.0.0.1"));
    assert!(is_private_ip("::127.0.0.1"));
    assert!(is_private_ip("::8.8.8.8"));
    // **[历史归因]** NAT64 64:ff9b::/32 整段 reserved（即使内嵌公网 v4 也拒，对齐 Python）。
    assert!(is_private_ip("64:ff9b::a00:1")); // 10.0.0.1 内嵌
    assert!(is_private_ip("64:ff9b::808:808")); // 8.8.8.8 内嵌 → 仍 reserved
    assert!(is_private_ip("64:ff9b:1::1")); // NAT64 local 前缀
}

#[test]
fn v4_special_segments_aligned_with_python() {
    // 每段代表地址判私网。
    assert!(is_private_ip("0.0.0.0"));
    assert!(is_private_ip("0.0.0.1")); // 0.0.0.0/8
    assert!(is_private_ip("192.0.0.1")); // 192.0.0.0/24
    assert!(is_private_ip("192.0.2.1")); // TEST-NET-1
    assert!(is_private_ip("198.18.0.1")); // benchmarking /15
    assert!(is_private_ip("198.19.255.255"));
    assert!(is_private_ip("198.51.100.1")); // TEST-NET-2
    assert!(is_private_ip("203.0.113.1")); // TEST-NET-3
                                           // 段外相邻地址放行。
    assert!(!is_private_ip("192.0.1.1"));
    assert!(!is_private_ip("192.0.3.1"));
    assert!(!is_private_ip("198.20.0.1"));
    assert!(!is_private_ip("198.51.101.1"));
    assert!(!is_private_ip("203.0.114.1"));
    assert!(!is_private_ip("11.0.0.1")); // 非 RFC1918
                                         // mapped 经补齐后 v4 判定。
    assert!(is_private_ip("::ffff:198.18.0.1"));
}

#[test]
fn v6_reserved_prefixes_aligned_with_python() {
    assert!(is_private_ip("2001::1")); // Teredo 2001::/32
    assert!(!is_private_ip("2001:1::1")); // /32 外
    assert!(is_private_ip("100::1")); // discard 100::/64
    assert!(is_private_ip("2001:db8::1")); // documentation
    assert!(!is_private_ip("2606:4700::1")); // 公网放行
}

#[test]
fn cgnat_rejected_only_for_subscription() {
    // CGNAT 100.64.0.0/10：答案路径放行。
    assert!(!is_private_ip("100.64.0.1"));
    assert!(!is_private_ip("100.127.255.255"));
    // 订阅 guard 拒。
    assert!(is_non_global_for_subscription("100.64.0.1"));
    assert!(is_non_global_for_subscription("100.127.255.255"));
    // 范围外不拒（100.63.x 与 100.128.x 不在 /10）。
    assert!(!is_non_global_for_subscription("100.63.0.1"));
    assert!(!is_non_global_for_subscription("100.128.0.1"));
    // mapped CGNAT。
    assert!(is_non_global_for_subscription("::ffff:100.64.0.1"));
    // 私网在两谓词下都拒。
    assert!(is_non_global_for_subscription("10.0.0.1"));
}

#[test]
fn v6_more_reserved_prefixes() {
    // 6to4 2002::/16 整段拒。
    assert!(is_private_ip("2002::1"));
    assert!(is_private_ip("2002:1::1"));
    assert!(!is_private_ip("2003::1")); // 段外放行
                                        // benchmarking 2001:2::/48（与 Teredo 2001:0::/32 区分）。
    assert!(is_private_ip("2001:2::1"));
    assert!(is_private_ip("2001:2:0:1::1"));
    assert!(!is_private_ip("2001:3::1"));
    assert!(!is_private_ip("2001:1::1"));
}
