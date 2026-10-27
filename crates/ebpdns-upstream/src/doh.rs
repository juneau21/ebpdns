//! **[历史归因]** DoH（DNS over HTTPS）上游收发（对齐 Python `upstream._doh_query`）。
//!
//! 在 tokio-rustls TLS 连接上跑最小 HTTP/1.1：POST `application/dns-message`。
//! 响应校验：status==200、Content-Type 含 application/dns-message、body 12..=65535、
//! 无截断残留、qid 一致、非 header-only。按 Content-Length 精确读取（不超读），
//! 合法完整响应后连接无缓冲残留、可安全回池复用；其余关闭即弃。
//!
//! **D2 连接复用判据**：除"无残留 / 非 chunked"外，还必须判定服务端是否要关闭
//! **[历史归因]** 连接（`Connection: close` 或 HTTP/1.0 缺 `keep-alive`）。对齐 Python
//! `upstream.py:1252` / `:1339`：
//! `if getattr(resp, "will_close", False) or _leftover > 0 or getattr(resp, "chunked", False): conn.close()`
//! —— `http.client.HTTPResponse.will_close` 的判据见
//! `HTTPResponse._check_close()`：HTTP/1.0 服务端响应只有在客户端发了
//! `Connection: keep-alive` **且**响应也带 `Connection: keep-alive` 时才保持长连接，
//! 否则关闭；HTTP/1.1 仅在响应含 `Connection: close` 时关闭。
//! 未判定时会把"即将被对端关闭"的连接放回池里，下次 acquire 首次 write 不报错而
//! 读立即 EOF → 重试一次新建连接 → 每次查询固定 2 倍 HTTP 往返。
//!
//! 本模块**不发** `Connection: close`（请求恒带 `Connection: keep-alive`），故
//! **[历史归因]** "客户端要求关闭"分支不会触发；HTTP/1.0 且响应 `keep-alive` 时按 Python
//! 语义仍可复用。

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::config::UpstreamConfig;
use crate::header_check::{is_header_only, qid_of};
use crate::pool::{PooledConn, TlsConn};
use crate::runtime::UpstreamRuntime;
use crate::{tcp, tls};

const MAX_BODY: usize = 65535;

/// DoH 查询。返回 `(ok, data)`。
pub(crate) async fn doh_query(
    rt: &UpstreamRuntime,
    cfg: &UpstreamConfig,
    query: &[u8],
    timeout: Duration,
) -> (bool, Option<Vec<u8>>) {
    // P1-A：deadline 必须在 `acquire` **之前**算好，`acquire` 自身也吃这份预算；
    // 建连（TCP+TLS）与 HTTP 收发都从同一条 deadline 扣减，保证总耗时 ≤ `timeout`。
    let deadline = std::time::Instant::now() + timeout;
    let remain = || deadline.saturating_duration_since(std::time::Instant::now());
    let path = normalize_path(&cfg.url);
    let key = cfg.pool_key();

    let got = match rt.pool.acquire(&key, remain()).await {
        Some(g) => g,
        None => return (false, None),
    };
    let (checkout, reused) = got;

    let first = attempt(rt, cfg, reused.map(|p| p.conn), &path, query, deadline).await;
    match first {
        Attempt::Success {
            body,
            conn,
            will_close,
        } => {
            release_conn(rt, checkout, conn, will_close);
            return (true, Some(body));
        }
        Attempt::Reject(conn) => {
            drop(conn);
            if remain().is_zero() {
                rt.pool.clone().release(checkout, None);
                return (false, None);
            }
        }
    }

    // 重试一次（新建连接）。
    match attempt(rt, cfg, None, &path, query, deadline).await {
        Attempt::Success {
            body,
            conn,
            will_close,
        } => {
            release_conn(rt, checkout, conn, will_close);
            (true, Some(body))
        }
        Attempt::Reject(conn) => {
            drop(conn);
            rt.pool.clone().release(checkout, None);
            (false, None)
        }
    }
}

/// 归还连接槽（D2）。`will_close` 为真时把连接标记 `degraded` —— `pool.release`
/// **[历史归因]** 对 `degraded` 连接**直接 drop（即 close）不入队**，与 Python
/// `_doh_query` 在 `will_close` 时显式 `conn.close()` 且不 `release` 连接语义一致。
/// 这样"服务端要求关闭"的连接不会再被 acquire 取到，消除必然 EOF 的空转往返。
fn release_conn(
    rt: &UpstreamRuntime,
    checkout: crate::pool::Checkout,
    conn: TlsConn,
    will_close: bool,
) {
    let pooled = PooledConn {
        conn,
        degraded: will_close,
    };
    rt.pool.clone().release(checkout, Some(pooled));
}

fn normalize_path(url: &str) -> String {
    // 统一走 [`crate::addr::request_path`]：容忍空串（默认 `/dns-query`）、路径形态，
    // 并把完整 URL（`https://host:port/dns-query`）剥成路径——否则请求行会变成
    // `POST /https://host:port/dns-query HTTP/1.1`，真实 DoH 服务器一律 404。
    crate::addr::request_path(url, true)
}

/// 单次尝试的结果。
enum Attempt {
    /// 合法响应；`will_close` 为真时连接不可复用（D2）。
    Success {
        body: Vec<u8>,
        conn: TlsConn,
        will_close: bool,
    },
    /// 协议级拒绝；连接关闭即弃。
    Reject(Option<TlsConn>),
}

async fn attempt(
    rt: &UpstreamRuntime,
    cfg: &UpstreamConfig,
    existing: Option<TlsConn>,
    path: &str,
    query: &[u8],
    deadline: std::time::Instant,
) -> Attempt {
    let remain = || deadline.saturating_duration_since(std::time::Instant::now());
    let mut conn = match existing {
        Some(c) => c,
        None => match connect_doh(rt, cfg, remain()).await {
            Ok(c) => c,
            Err(_) => return Attempt::Reject(None),
        },
    };
    // A7：一次 DoH 尝试 = 一次真实 HTTP POST 往返（含复用池内连接的情形）。
    rt.record_wire_request();
    match http_post(&mut conn, cfg, path, query, remain).await {
        Some(out) => Attempt::Success {
            body: out.body,
            conn,
            will_close: out.will_close,
        },
        None => Attempt::Reject(Some(conn)),
    }
}

/// 建立 DoH TLS 连接。
///
/// **P1-A（2.1.9）**：`timeout` 是**整个建连预算**（TCP connect + TLS 握手），不是只给
/// TCP connect。旧实现只把 `TcpStream::connect` 包进 `tokio::time::timeout`，
/// TLS 握手 `connector.connect(...)` **裸 await** —— 一个"接受 TCP 但不应答 TLS"
/// 的 DoH 上游（黑洞/中间盒/半死 TLS 终结器）会让 `doh_query` **永久挂起**：
/// - 该 future 永不返回 → 调用方（resolver 的并行上游/对冲）永不收到结果，
///   客户端查询被拖到自身超时；
/// - 更重要的是**池的信号量许可永不归还**（`Checkout.permit` 绑在那些 future 上），
///   对外**全 id 共享**的 `(proto,host,port,path)` 键用满 [`crate::pool::MAX_CONN`]
///   个槽后，后续所有 `acquire` 全部超时 → 该上游**永久不可用**（自愈失败）。
///
/// 修法：先按**剩余预算**建 TCP，再按**重新计算的剩余预算**做 TLS 握手；
/// 第二步同时用外层 `timeout` 包住「建 rustls 配置 + 握手」，预算归零时立即返回
/// `TimedOut` 而不是继续 await。两段都用 `remain()` 语义 → 总耗时 ≤ `timeout`
/// （除 `resolve_target` 的 bootstrap 解析，其自有超时且不持池许可）。
async fn connect_doh(
    rt: &UpstreamRuntime,
    cfg: &UpstreamConfig,
    timeout: Duration,
) -> crate::error::UpstreamResult<TlsConn> {
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
    let hostname = crate::addr::is_hostname(&cfg.host);
    let strict = cfg.strict_cert || hostname;
    // TLS 握手（含 rustls 配置构建）纳入**同一个** deadline；返回即刻保证 TCP
    // 连接被 drop（上层 `Attempt::Reject(None)` / 错误分支不再持有 fd）。
    tokio::time::timeout(remain(), async {
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
    })?
}

/// `http_post` 的成功结果：body + 连接是否可复用。
struct PostOutcome {
    body: Vec<u8>,
    /// 服务端要求关闭连接（`Connection: close` 或 HTTP/1.0 未协商 keep-alive）。
    will_close: bool,
}

/// 在一条 TLS 连接上发 POST 并精确读取校验响应。失败返回 None（连接不可复用）。
async fn http_post(
    conn: &mut TlsConn,
    cfg: &UpstreamConfig,
    path: &str,
    query: &[u8],
    mut remain: impl FnMut() -> Duration,
) -> Option<PostOutcome> {
    let host_header = if cfg.port == 443 || cfg.port == 80 {
        cfg.host.clone()
    } else {
        format!("{}:{}", cfg.host, cfg.port)
    };
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/dns-message\r\n\
         Accept: application/dns-message\r\nUser-Agent: ebpdns/2.0\r\nContent-Length: {cl}\r\n\
         Connection: keep-alive\r\n\r\n",
        host = host_header,
        cl = query.len(),
    );
    if remain().is_zero() {
        return None;
    }
    if tokio::time::timeout(remain(), async {
        conn.write_all(req.as_bytes()).await?;
        conn.write_all(query).await?;
        conn.flush().await?;
        Ok::<_, std::io::Error>(())
    })
    .await
    .is_err()
    {
        return None;
    }

    // 精确读取：先读到 header 结束（\r\n\r\n），再按 Content-Length 读满 body。不超读。
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end: usize;
    loop {
        if remain().is_zero() {
            return None;
        }
        let n = match tokio::time::timeout(remain(), conn.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return None,
        };
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_header_end(&buf) {
            header_end = pos;
            break;
        }
        if buf.len() > 64 * 1024 {
            return None;
        }
    }

    let headers = &buf[..header_end];
    let head = parse_response_headers(headers)?;
    if head.status != 200 {
        return None;
    }
    if !head
        .content_type
        .to_ascii_lowercase()
        .contains("application/dns-message")
    {
        return None;
    }
    let len = head.content_length?;
    if !(12..=MAX_BODY).contains(&len) {
        return None;
    }
    // 读满 body（可能需继续读）。
    let body_start = header_end + 4;
    while buf.len() < body_start + len {
        if remain().is_zero() {
            return None;
        }
        let n = match tokio::time::timeout(remain(), conn.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return None, // 截断。
        };
        buf.extend_from_slice(&chunk[..n]);
    }
    let body = buf[body_start..body_start + len].to_vec();
    if is_header_only(&body) {
        return None;
    }
    if qid_of(&body) != qid_of(query) {
        return None;
    }
    // chunked 响应保守不回池。
    if head.chunked {
        return None;
    }
    // buf 未读超过 body（无残留）→ 连接干净可回池。
    if buf.len() > body_start + len {
        return None; // 多余字节（协议违规）→ 不回池。
    }
    Some(PostOutcome {
        body,
        will_close: head.will_close,
    })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// 解析后的响应头（含 D2 的连接复用判据）。
struct ResponseHead {
    status: u16,
    content_type: String,
    content_length: Option<usize>,
    chunked: bool,
    /// 服务端是否会在本次响应后关闭连接。
    will_close: bool,
}

/// 解析响应头。
fn parse_response_headers(hdr: &[u8]) -> Option<ResponseHead> {
    let text = std::str::from_utf8(hdr).ok()?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next()?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next()?;
    let status: u16 = parts.next()?.parse().ok()?;

    let mut content_type = String::new();
    let mut content_length = None;
    let mut chunked = false;
    let mut conn_close = false;
    let mut conn_keep_alive = false;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let v = v.trim();
            match k.to_ascii_lowercase().as_str() {
                "content-type" => content_type = v.to_string(),
                "content-length" => content_length = v.parse().ok(),
                "transfer-encoding" if v.to_ascii_lowercase().contains("chunked") => chunked = true,
                "connection" => {
                    // 逐 token 精确匹配，避免 "close" 命中 "enclose" 之类的子串。
                    for token in v.split(',') {
                        match token.trim().to_ascii_lowercase().as_str() {
                            "close" => conn_close = true,
                            "keep-alive" => conn_keep_alive = true,
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Some(ResponseHead {
        status,
        content_type,
        content_length,
        chunked,
        will_close: will_close(version, conn_close, conn_keep_alive),
    })
}

/// D2：服务端是否会在本次响应后关闭连接。
///
/// **[历史归因]** 判据与 Python `http.client.HTTPResponse._check_close()` 等价（`http.client` 里
/// `will_close` 即由它赋值）。注意请求侧恒带 `Connection: keep-alive`，即
/// `_check_close` 中 "if we sent keep-alive and the server says keep-alive, keep alive"
/// 的前提成立，因此：
/// - 响应显式 `Connection: close` → 关闭（HTTP/1.0 与 1.1 都关闭）；
/// - HTTP/1.1+ → 只要没要求 close 就保持长连接（HTTP/1.1 默认持久）；
/// - HTTP/1.0 → 仅当响应显式 `Connection: keep-alive` 时保持，否则默认关闭；
/// - 版本串不可识别（HTTP/0.9 等）→ 保守关闭：绝不把语义未知的连接入池。
///
/// 未判定此项时，服务端要求关闭的连接会被放回池里，下次 acquire 的首次
/// `read` 直接 EOF（write 因 TCP 缓冲常不报错）→ 每次查询固定 2 倍 HTTP 往返。
fn will_close(version: &str, conn_close: bool, conn_keep_alive: bool) -> bool {
    if conn_close {
        return true;
    }
    match http_version(version) {
        // HTTP/1.1+ 默认持久连接。
        Some((major, minor)) if (major, minor) >= (1, 1) => false,
        // **[历史归因]** HTTP/1.0 默认关闭；请求/响应都 keep-alive 时才复用（Python 语义）。
        Some(_) => !conn_keep_alive,
        // 版本不可识别（HTTP/0.9 等）：保守视为关闭。
        None => true,
    }
}

/// 解析 `HTTP/1.0` / `HTTP/1.1` 状的版本串为 `(major, minor)`。
fn http_version(version: &str) -> Option<(u32, u32)> {
    let rest = version
        .strip_prefix("HTTP/")
        .or_else(|| version.strip_prefix("http/"))?;
    let (major, minor) = rest.split_once('.')?;
    Some((major.trim().parse().ok()?, minor.trim().parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /* ---------------- D2: will_close 判定 ---------------- */

    #[test]
    fn http11_without_connection_header_stays_open() {
        assert!(!will_close("HTTP/1.1", false, false));
        assert!(!will_close("HTTP/1.1", false, true));
    }

    #[test]
    fn http11_explicit_close_closes() {
        assert!(will_close("HTTP/1.1", true, false));
        // **[历史归因]** 同时出现 keep-alive 与 close 时以 close 优先（Python 亦然）。
        assert!(will_close("HTTP/1.1", true, true));
    }

    #[test]
    fn http10_defaults_to_close() {
        assert!(will_close("HTTP/1.0", false, false), "HTTP/1.0 默认关闭");
    }

    #[test]
    fn http10_with_keep_alive_is_reusable() {
        assert!(!will_close("HTTP/1.0", false, true));
        assert!(
            will_close("HTTP/1.0", true, true),
            "close 优先于 keep-alive"
        );
    }

    #[test]
    fn unknown_version_is_conservatively_closed() {
        assert!(will_close("HTTP/0.9", false, false));
        assert!(will_close("garbage", false, false));
        assert!(will_close("", false, false));
        // 版本不可识别但显式 close 时同样关闭。
        assert!(will_close("garbage", true, false));
    }

    #[test]
    fn http_version_parsing() {
        assert_eq!(http_version("HTTP/1.1"), Some((1, 1)));
        assert_eq!(http_version("HTTP/1.0"), Some((1, 0)));
        assert_eq!(http_version("HTTP/2.0"), Some((2, 0)));
        assert_eq!(http_version("HTTP/10.0"), Some((10, 0)));
        assert_eq!(http_version("ICY/1.0"), None);
        assert_eq!(http_version("HTTP/1"), None);
        assert_eq!(http_version("HTTP/1."), None);
        assert_eq!(http_version("HTTP/.1"), None);
    }

    /* ---------------- D2: 响应头解析 ---------------- */

    #[test]
    fn parse_headers_http11_keep_alive() {
        let hdr = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 45\r\nConnection: keep-alive\r\n";
        let h = parse_response_headers(hdr).unwrap();
        assert_eq!(h.status, 200);
        assert_eq!(h.content_length, Some(45));
        assert!(!h.chunked);
        assert!(!h.will_close, "HTTP/1.1 + keep-alive 可复用");
    }

    #[test]
    fn parse_headers_connection_close_marks_will_close() {
        let hdr = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 45\r\nConnection: close\r\n";
        let h = parse_response_headers(hdr).unwrap();
        assert!(h.will_close, "Connection: close 必须判定为将关闭");
    }

    #[test]
    fn parse_headers_http10_marks_will_close() {
        let hdr =
            b"HTTP/1.0 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 45\r\n";
        let h = parse_response_headers(hdr).unwrap();
        assert!(h.will_close, "HTTP/1.0 无 keep-alive 必须判定为将关闭");
    }

    #[test]
    fn parse_headers_is_case_insensitive_and_trims() {
        let hdr = b"HTTP/1.1 200 OK\r\ncontent-type:  Application/DNS-Message \r\nCONTENT-LENGTH: 12\r\nCoNnEcTiOn:  Close \r\n";
        let h = parse_response_headers(hdr).unwrap();
        assert_eq!(h.content_type.trim(), "Application/DNS-Message");
        assert_eq!(h.content_length, Some(12));
        assert!(h.will_close);
    }

    #[test]
    fn parse_headers_close_token_not_matched_inside_other_word() {
        // "enclose" 不得被误判为 close；"keep-alive" 与 "close" 逗号列表按 token 判定。
        let hdr = b"HTTP/1.1 200 OK\r\nX-Other: enclose\r\nContent-Length: 12\r\nConnection: Upgrade, close\r\n";
        let h = parse_response_headers(hdr).unwrap();
        assert!(h.will_close, "逗号列表中的 close token 必须命中");
        let hdr2 = b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: enclose\r\n";
        assert!(
            !parse_response_headers(hdr2).unwrap().will_close,
            "enclose 不是 close"
        );
    }

    #[test]
    fn parse_headers_chunked_detected() {
        let hdr = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n";
        let h = parse_response_headers(hdr).unwrap();
        assert!(h.chunked);
        assert_eq!(h.content_length, None);
    }

    #[test]
    fn parse_headers_rejects_garbage() {
        assert!(parse_response_headers(b"not-a-status-line").is_none());
        assert!(parse_response_headers(b"HTTP/1.1 abc OK").is_none());
        // 非 UTF-8 字节 → None（不 panic）。0xFF/0xFD 均为非法 UTF-8 起始字节。
        assert!(parse_response_headers(&[0xff, 0xfe, 0xfd]).is_none());
        // 空头 → 无 status line。
        assert!(parse_response_headers(b"").is_none());
    }

    #[test]
    fn find_header_end_positions() {
        assert_eq!(find_header_end(b"A\r\n\r\nB"), Some(1));
        assert_eq!(find_header_end(b"\r\n\r\n"), Some(0));
        assert_eq!(find_header_end(b"no terminator"), None);
    }

    /// 旧实现把响应连接无条件回池（`degraded: false`），D2 后 `Connection: close`
    /// 必须映射为 `degraded=true` 从而"即用即弃"。
    #[test]
    fn will_close_maps_to_pool_degraded_semantics() {
        for (hdr, expect_degraded) in [
            (
                &b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n"[..],
                true,
            ),
            (
                &b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: keep-alive\r\n"[..],
                false,
            ),
            (&b"HTTP/1.0 200 OK\r\nContent-Length: 12\r\n"[..], true),
            (
                &b"HTTP/1.0 200 OK\r\nContent-Length: 12\r\nConnection: keep-alive\r\n"[..],
                false,
            ),
        ] {
            let h = parse_response_headers(hdr).unwrap();
            assert_eq!(
                h.will_close,
                expect_degraded,
                "will_close 即 pool.degraded（true ⇒ 不入池）：{}",
                String::from_utf8_lossy(hdr)
            );
        }
    }
}
