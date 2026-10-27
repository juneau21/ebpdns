//! **[历史归因]** 明文 TCP 上游收发（对齐 Python `upstream._tcp_query`）。
//!
//! 2 字节大端长度前缀帧；recv 循环解析帧，丢弃短帧/header-only/qid 失配/0x20 失配帧，
//! **[历史归因]** 返回首个合法帧。连接单次使用（Python 路径无池）。

use std::time::Duration;

use ebpdns_proto::tcp::{parse_tcp_frame, tcp_frame};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::UpstreamConfig;
use crate::header_check::{evaluate_x20, is_header_only, qid_of};
use crate::runtime::UpstreamRuntime;

const MAX_BUF: usize = 65535 + 2;

/// 明文 TCP 查询。返回 `(ok, data)`。
pub(crate) async fn tcp_query(
    rt: &UpstreamRuntime,
    cfg: &UpstreamConfig,
    query: &[u8],
    timeout: Duration,
) -> (bool, Option<Vec<u8>>) {
    let deadline = std::time::Instant::now() + timeout;
    // 解析到 IP 直连（hostname 走 bootstrap 缓存）。
    let ip = resolve_target(rt, cfg).await;
    let ip = match ip {
        Some(ip) => ip,
        None => return (false, None),
    };
    let addr = std::net::SocketAddr::new(ip, cfg.port);

    let remain = || deadline.saturating_duration_since(std::time::Instant::now());
    let stream = match tokio::time::timeout(remain(), TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return (false, None),
    };
    // A7：明文 TCP 上游每次查询都是**新建连接 + 一次查询往返**，记 1 次线速请求
    // （UDP→TCP 的 TC 回退路径也经这里，因此回退会被正确计入）。
    rt.record_wire_request();
    let (mut rd, mut wr) = stream.into_split();

    let frame = match tcp_frame(query) {
        Ok(f) => f,
        Err(_) => return (false, None),
    };
    if remain().is_zero() {
        return (false, None);
    }
    if tokio::time::timeout(remain(), wr.write_all(&frame))
        .await
        .is_err()
    {
        return (false, None);
    }

    let now = std::time::Instant::now();
    let mut counted = false;
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if remain().is_zero() {
            return (false, None);
        }
        let read = tokio::time::timeout(remain(), rd.read(&mut chunk)).await;
        match read {
            Ok(Ok(0)) => return (false, None), // EOF
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            _ => return (false, None), // 超时/错误
        }
        if buf.len() > MAX_BUF {
            return (false, None);
        }
        // 内层循环：连续解析已缓冲的完整帧。
        #[allow(clippy::while_let_loop)]
        loop {
            match parse_tcp_frame(&buf) {
                Ok((msg, rest)) => {
                    let accept = msg.len() >= 12
                        && !is_header_only(&msg)
                        && qid_of(&msg) == qid_of(query)
                        && evaluate_x20(&rt.x20, &cfg.id, query, &msg, now, &mut counted);
                    if accept {
                        return (true, Some(msg));
                    }
                    buf = rest;
                    if buf.is_empty() {
                        break;
                    }
                }
                Err(_) => {
                    // 帧不完整：回外层 recv。
                    break;
                }
            }
        }
    }
}

/// 解析上游目标 IP（IP 字面量直取；hostname 走 bootstrap/addr 缓存）。
pub(crate) async fn resolve_target(
    rt: &UpstreamRuntime,
    cfg: &UpstreamConfig,
) -> Option<std::net::IpAddr> {
    if !crate::addr::is_hostname(&cfg.host) {
        return cfg.host.parse::<std::net::IpAddr>().ok();
    }
    if let Some(ip) = rt.bootstrap.bootstrap_ip(&cfg.host) {
        return Some(ip);
    }
    let ips = rt.bootstrap.resolve_udp_addrs(&cfg.host, cfg.port).await;
    ips.into_iter().next()
}
