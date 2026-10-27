//! **[历史归因]** DoT（DNS over TLS）上游收发（对齐 Python `upstream._dot_query`）。
//!
//! tokio-rustls over TCP，连接池复用；服务端 EOF / 传输错误时关闭旧连接新建一条再试一次。
//! `strict_cert=false` 且 IP 字面量时降级为仅链校验（degraded），连接即用即弃不入池。

use std::time::Duration;

use ebpdns_proto::tcp::{parse_tcp_frame, tcp_frame};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::config::UpstreamConfig;
use crate::header_check::{is_header_only, qid_of};
use crate::pool::{PooledConn, TlsConn};
use crate::runtime::UpstreamRuntime;
use crate::{tcp, tls};

const MAX_BUF: usize = 65535 + 2;

/// DoT 查询。返回 `(ok, data)`。
pub(crate) async fn dot_query(
    rt: &UpstreamRuntime,
    cfg: &UpstreamConfig,
    query: &[u8],
    timeout: Duration,
) -> (bool, Option<Vec<u8>>) {
    let deadline = std::time::Instant::now() + timeout;
    let remain = || deadline.saturating_duration_since(std::time::Instant::now());
    let frame = match tcp_frame(query) {
        Ok(f) => f,
        Err(_) => return (false, None),
    };
    let key = cfg.pool_key();

    let got = match rt.pool.acquire(&key, remain()).await {
        Some(g) => g,
        None => return (false, None),
    };
    let (checkout, reused) = got;

    // 首次尝试：复用池内连接，或新建连接。
    let first: (Option<Vec<u8>>, Option<(TlsConn, bool)>) = match reused {
        Some(pc) => exchange_once(rt, cfg, Some(pc.conn), &frame, query, deadline).await,
        None => {
            if remain().is_zero() {
                rt.pool.clone().release(checkout, None);
                return (false, None);
            }
            exchange_once(rt, cfg, None, &frame, query, deadline).await
        }
    };

    match first {
        (Some(msg), conn) => {
            release_reuse(rt, checkout, conn);
            return (true, Some(msg));
        }
        (None, conn) => {
            // 旧连接已在 exchange_once 内 drop（不可用）。预算耗尽直接返回。
            if remain().is_zero() {
                rt.pool.clone().release(checkout, None);
                return (false, None);
            }
            drop(conn);
        }
    }

    // 重试：新建一条连接再 exchange。
    match exchange_once(rt, cfg, None, &frame, query, deadline).await {
        (Some(msg), conn) => {
            release_reuse(rt, checkout, conn);
            (true, Some(msg))
        }
        (None, conn) => {
            drop(conn);
            rt.pool.clone().release(checkout, None);
            (false, None)
        }
    }
}

/// 成功后把连接（非降级）归还池；降级连接即弃。
fn release_reuse(
    rt: &UpstreamRuntime,
    checkout: crate::pool::Checkout,
    conn: Option<(TlsConn, bool)>,
) {
    match conn {
        Some((c, degraded)) => rt
            .pool
            .clone()
            .release(checkout, Some(PooledConn { conn: c, degraded })),
        None => rt.pool.clone().release(checkout, None),
    }
}

/// 用给定连接（None 则新建）完成一次 DoT 收发。返回 `(结果, (连接, 降级))`。
///
/// 成功时连接可用可入池；失败时连接不可用（drop 关闭）。
async fn exchange_once(
    rt: &UpstreamRuntime,
    cfg: &UpstreamConfig,
    existing: Option<TlsConn>,
    frame: &[u8],
    query: &[u8],
    deadline: std::time::Instant,
) -> (Option<Vec<u8>>, Option<(TlsConn, bool)>) {
    let mut conn = match existing {
        Some(c) => (c, false),
        None => match connect_dot(
            rt,
            cfg,
            deadline.saturating_duration_since(std::time::Instant::now()),
        )
        .await
        {
            Ok(c) => c,
            Err(_) => return (None, None),
        },
    };
    match do_exchange(&mut conn.0, frame, query, deadline).await {
        Some(msg) => {
            // A7：一次 DoT 收发 = 一次真实线速请求（复用池内连接同样计入）。
            rt.record_wire_request();
            (Some(msg), Some(conn))
        }
        None => (None, None), // drop conn：不可用。
    }
}

/// 建立 DoT TCP+TLS 连接。返回 `(tls_conn, degraded)`。
///
/// **P1-A（2.1.9）**：与 `doh::connect_doh` 同一缺陷、同一修法 —— `timeout` 是
/// **整个建连预算**（TCP connect + TLS 握手）。旧实现把 TLS 握手裸 await，
/// "接受 TCP 不应答 TLS"的 DoT 上游会让查询永久挂起并**永久占住池信号量槽**
/// （`connect_dot` 由 `exchange_once` 在**已取到 Checkout 许可之后**调用）。
/// 这里改用局部 deadline：先按剩余预算建 TCP，再按重新计算的剩余预算做握手。
pub(crate) async fn connect_dot(
    rt: &UpstreamRuntime,
    cfg: &UpstreamConfig,
    timeout: Duration,
) -> crate::error::UpstreamResult<(TlsConn, bool)> {
    let deadline = std::time::Instant::now() + timeout;
    let remain = || deadline.saturating_duration_since(std::time::Instant::now());
    let ip = tcp::resolve_target(rt, cfg)
        .await
        .ok_or_else(|| crate::error::UpstreamError::InvalidConfig("no target ip".into()))?;
    let addr = std::net::SocketAddr::new(ip, cfg.port);
    let tcp_budget = remain();
    if tcp_budget.is_zero() {
        return Err(crate::error::UpstreamError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "connect timeout",
        )));
    }
    let tcp = tokio::time::timeout(tcp_budget, TcpStream::connect(addr))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))?
        .map_err(crate::error::UpstreamError::Io)?;
    if remain().is_zero() {
        return Err(crate::error::UpstreamError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "tls handshake timeout",
        )));
    }

    // strict：hostname 恒严格；IP 字面量才允许 strict=false 降级。
    let hostname = crate::addr::is_hostname(&cfg.host);
    let strict = cfg.strict_cert || hostname;
    // 两层 `Result`：外层是 timeout 的 `Elapsed`（超时 → TimedOut），
    // 内层是握手/配置构建本身的 `UpstreamError`。`??` 逐层展开，语义明确。
    let handshake = tokio::time::timeout(remain(), async {
        let config = tls::build_client_config(strict)?;
        let sni = tls::server_name(&cfg.host)?;
        let connector = TlsConnector::from(config);
        connector
            .connect(sni, tcp)
            .await
            .map_err(|e| crate::error::UpstreamError::Tls(e.to_string()))
    })
    .await
    .map_err(|_| {
        // 超时：`tcp` 随被丢弃的 future 一起 drop → close(fd)，不泄漏。
        std::io::Error::new(std::io::ErrorKind::TimedOut, "tls handshake timeout")
    })?;
    let tls = handshake?;
    Ok((tls, !strict))
}

/// 在一条已建立的 TLS 连接上完成一次 DNS 帧收发。
///
/// 校验：长度 <12 丢弃、header-only 丢弃、qid 不符丢弃、空帧丢弃；返回首个合法帧。
async fn do_exchange(
    conn: &mut TlsConn,
    frame: &[u8],
    query: &[u8],
    deadline: std::time::Instant,
) -> Option<Vec<u8>> {
    let (mut rd, mut wr) = tokio::io::split(conn);
    let remain = || deadline.saturating_duration_since(std::time::Instant::now());
    if remain().is_zero() {
        return None;
    }
    if tokio::time::timeout(remain(), wr.write_all(frame))
        .await
        .is_err()
    {
        return None;
    }
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if remain().is_zero() {
            return None;
        }
        match tokio::time::timeout(remain(), rd.read(&mut chunk)).await {
            Ok(Ok(0)) => return None, // EOF
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            _ => return None,
        }
        if buf.len() > MAX_BUF {
            return None;
        }
        #[allow(clippy::while_let_loop)]
        loop {
            match parse_tcp_frame(&buf) {
                Ok((msg, rest)) => {
                    let accept =
                        msg.len() >= 12 && !is_header_only(&msg) && qid_of(&msg) == qid_of(query);
                    if accept {
                        return Some(msg);
                    }
                    buf = rest;
                    if buf.is_empty() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    }
}
