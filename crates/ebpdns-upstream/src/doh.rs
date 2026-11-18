//! DoH（DNS over HTTPS）上游收发：**HTTP/2 流级多路复用**（P0-3）+ HTTP/1.1 自动回退。
//!
//! # 传输选择（ALPN）
//!
//! DoH 的 TLS `ClientConfig` 恒传 `alpn = ["h2", "http/1.1"]`（[`alpn_doh`]），握手后按
//! **[`rustls::ClientConnection::alpn_protocol`] 的真实协商结果**决定 codec：
//! - `h2` ⇒ [`crate::doh_h2`]：一条 TLS 连接上并发 N 个 stream（连接池在那边）；
//! - 其它（`http/1.1`，或服务端未协商 ALPN）⇒ 本文件下方的 HTTP/1.1 实现（既有连接池
//!   语义不变：**每连接单请求**）。服务端只支持 h1 时**自动回退，不失败**；
//! - DoH3（QUIC）走 `h3`，不经本模块。
//!
//! # RFC 8484 正确性
//!
//! - **qid = 0**（RFC 8484 §4.1：DoH 客户端 SHOULD 在请求里用 DNS ID 0）。请求上线前把
//!   前两字节改写为 0（[`crate::doh_h2`] 与 h1 共用同一条 wire 报文），响应侧按 `0`
//!   校验后**还原调用方的原始 qid**——这样上游看不到调用方 qid（缓存友好），下游拿到的
//!   仍是与自己查询匹配的应答；
//! - **framing**：h2 用 DATA 帧 + END_STREAM 界定正文，**不依赖 Content-Length**；
//!   HTTP/1.1 回退路径同时支持 `Content-Length`、`Transfer-Encoding: chunked`、
//!   以及"两者都没有 ⇒ 读到 EOF"（后者必然不可复用连接）。2.1.50 之前"必须有
//!   Content-Length / 拒绝 chunked"的限制已删除；
//! - 拒绝路径：状态码非 200、`content-type` 不含 `application/dns-message`、正文
//!   12..=[`MAX_BODY`] 之外、QDCOUNT!=1、qid 不为 0 ⇒ 失败（连接按 framing 语义决定
//!   是否可复用）。
//!
//! # HTTP/1.1 连接复用判据（D2，2.1.9 起）
//!
//! 除"无残留 / 非 chunked"外，还必须判定服务端是否要关闭连接（`Connection: close`
//! 或 HTTP/1.0 缺 `keep-alive`），对齐 Python `upstream.py:1252` / `:1339`：
//! `if getattr(resp, "will_close", False) or _leftover > 0 or getattr(resp, "chunked", False): conn.close()`
//! —— Python 的 `chunked` 分支是"python http.client 解码后不可复用"，本实现**自己解码
//! chunked**（能精确知道帧边界与残留），因此 chunked 响应在**无残留**时仍可复用；
//! 无 `Content-Length` 且非 chunked 的响应读到 EOF ⇒ 连接已关，`degraded=true` 不入池。
//!
//! 本模块**不发** `Connection: close`（请求恒带 `Connection: keep-alive`），故
//! "客户端要求关闭"分支不会触发；HTTP/1.0 且响应 `keep-alive` 时按 Python 语义仍可复用。

use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::config::UpstreamConfig;
use crate::doh_h2::{self, MAX_BODY};
use crate::header_check::{is_header_only, qid_of};
use crate::pool::{PoolKey, PooledConn, TlsConn};
use crate::runtime::UpstreamRuntime;
use crate::{tcp, tls};

/// RFC 8484 §4.1：DoH 客户端 SHOULD 用 0 作为 DNS ID。
const DOH_QID: u16 = 0;
/// DoH 的 ALPN 偏好：h2 优先，http/1.1 回退（服务端只支持 h1 时必须成功回退）。
fn alpn_doh() -> Vec<Vec<u8>> {
    vec![b"h2".to_vec(), b"http/1.1".to_vec()]
}

/// 一次 DoH 查询的 HTTP 目标。
///
/// - `path`：HTTP/1.1 请求行用的 origin-form（`POST /dns-query HTTP/1.1`）；
/// - `h2_uri`：HTTP/2 用的**绝对 URI** —— h2 强制 `:scheme`/`:authority` 伪头，
///   只给相对路径会被 h2 客户端以 `MissingUriSchemeAndAuthority` 拒绝。
struct Targets {
    path: String,
    h2_uri: String,
}

impl Targets {
    fn new(cfg: &UpstreamConfig, path: String) -> Self {
        // IPv6 字面量在 URI authority 里必须加方括号（配置里的 host 是裸地址）。
        let host = if cfg.host.contains(':') && !cfg.host.starts_with('[') {
            format!("[{}]", cfg.host)
        } else {
            cfg.host.clone()
        };
        let authority = if cfg.port == 443 {
            host
        } else {
            format!("{host}:{}", cfg.port)
        };
        Targets {
            h2_uri: format!("https://{authority}{path}"),
            path,
        }
    }
}

/// DoH 查询。返回 `(ok, data)`。
pub(crate) async fn doh_query(
    rt: &UpstreamRuntime,
    cfg: &UpstreamConfig,
    query: &[u8],
    timeout: Duration,
) -> (bool, Option<Vec<u8>>) {
    // P1-A：deadline 必须在 `acquire` **之前**算好，`acquire` 自身也吃这份预算；
    // 建连（TCP+TLS）与 HTTP 收发都从同一条 deadline 扣减，保证总耗时 ≤ `timeout`。
    let deadline = Instant::now() + timeout;
    let remain = || deadline.saturating_duration_since(Instant::now());
    let path = normalize_path(&cfg.url);
    let targets = Targets::new(cfg, path);
    let key = cfg.pool_key();

    // **P0-3（RFC 8484 §4.1）**：qid=0 上线。取不到前两字节的畸形查询直接失败
    // （DNS 报文头恒 12 字节，正常路径不会到这里）。
    let Some(orig_qid) = qid_of(query) else {
        return (false, None);
    };
    let wire = rewrite_qid(query, DOH_QID);

    // ---------- 1) h2：已建立连接上的**流级复用**（快路径，不占 h1 连接池许可） ----------
    //
    // 失败语义：连接级失败（GOAWAY / 连接关闭 / REFUSED_STREAM）**重连一次**；
    // 摘掉坏连接后若池里再无可用连接，则落下去走"新建连接"（下面的 h1 路径会按 ALPN
    // 重新协商，若仍是 h2 就建立新连接）。stream 级失败（RST/超时/超大/错
    // content-type）只失败本次查询，连接保留给后续查询。
    let mut h2_retried = false;
    while let Some(lease) = rt.h2.acquire_lease(&key) {
        rt.record_wire_request();
        match lease.exchange(&targets.h2_uri, &wire, deadline).await {
            Ok(body) => return finish(body, orig_qid),
            Err(e) => {
                if e.evict_conn() {
                    rt.h2.evict(&key, lease.conn());
                }
                tracing::debug!(
                    up = %cfg.id,
                    host = %cfg.host,
                    kind = e.kind(),
                    err = %e,
                    "DoH h2 交换失败"
                );
                if e.retryable() && !h2_retried && !remain().is_zero() {
                    h2_retried = true;
                    continue;
                }
                return (false, None);
            }
        }
    }

    // ---------- 2) HTTP/1.1（或"尚未建连时的 h2 建连"）：既有连接池/重试语义 ----------
    let got = match rt.pool.acquire(&key, remain()).await {
        Some(g) => g,
        None => return (false, None),
    };
    let (checkout, reused) = got;

    let first = attempt(
        rt,
        cfg,
        &key,
        reused.map(|p| p.conn),
        &targets,
        &wire,
        deadline,
    )
    .await;
    match first {
        Attempt::H1 {
            body,
            conn,
            will_close,
        } => {
            release_conn(rt, checkout, conn, will_close);
            return finish(body, orig_qid);
        }
        Attempt::H2 { body } => {
            rt.pool.clone().release(checkout, None);
            return finish(body, orig_qid);
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
    match attempt(rt, cfg, &key, None, &targets, &wire, deadline).await {
        Attempt::H1 {
            body,
            conn,
            will_close,
        } => {
            release_conn(rt, checkout, conn, will_close);
            finish(body, orig_qid)
        }
        Attempt::H2 { body } => {
            rt.pool.clone().release(checkout, None);
            finish(body, orig_qid)
        }
        Attempt::Reject(conn) => {
            drop(conn);
            rt.pool.clone().release(checkout, None);
            (false, None)
        }
    }
}

/// 把查询前两字节改写为 `qid`（返回新的 wire 报文）。
fn rewrite_qid(query: &[u8], qid: u16) -> Vec<u8> {
    let mut wire = query.to_vec();
    let b = qid.to_be_bytes();
    wire[0] = b[0];
    wire[1] = b[1];
    wire
}

/// 响应收尾：DNS 层校验 + **qid 还原**。
///
/// 校验口径（h2 与 h1 共用，避免两条传输路径分叉）：
/// - 长度 `12..=MAX_BODY`；
/// - QDCOUNT == 1（[`is_header_only`]）；
/// - 响应 qid **必须为 0**（请求侧用 0，RFC 8484 §4.1；服务端回显查询 ID）。
///
/// 通过后把前两字节替换回调用方的 `orig_qid`：上游看不到真实 qid（缓存友好），
/// 下游拿到的应答仍与自己的查询匹配。
fn finish(mut body: Vec<u8>, orig_qid: u16) -> (bool, Option<Vec<u8>>) {
    if !(12..=MAX_BODY).contains(&body.len()) {
        return (false, None);
    }
    if is_header_only(&body) {
        return (false, None);
    }
    if qid_of(&body) != Some(DOH_QID) {
        return (false, None);
    }
    let b = orig_qid.to_be_bytes();
    body[0] = b[0];
    body[1] = b[1];
    (true, Some(body))
}

/// 归还连接槽（D2）。`will_close` 为真时把连接标记 `degraded` —— `pool.release`
/// 对 `degraded` 连接**直接 drop（即 close）不入队**，与 Python `_doh_query` 在
/// `will_close` 时显式 `conn.close()` 且不 `release` 连接语义一致。
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
    /// HTTP/1.1 合法响应；`will_close` 为真时连接不可复用（D2）。
    H1 {
        body: Vec<u8>,
        conn: TlsConn,
        will_close: bool,
    },
    /// h2 合法响应（连接归池所有，不随本次尝试归还）。
    H2 { body: Vec<u8> },
    /// 协议级拒绝；HTTP/1.1 连接关闭即弃。
    Reject(Option<TlsConn>),
}

async fn attempt(
    rt: &UpstreamRuntime,
    cfg: &UpstreamConfig,
    key: &PoolKey,
    existing: Option<TlsConn>,
    targets: &Targets,
    query: &[u8],
    deadline: Instant,
) -> Attempt {
    let remain = || deadline.saturating_duration_since(Instant::now());
    let mut conn = match existing {
        // 池里的连接恒为 HTTP/1.1（ALPN 协商到 h2 的连接不会进 h1 池）。
        Some(c) => c,
        None => {
            // **P0-3（single-flight）**：冷启动/重连突发时串行化"建连 + 传输判定"。
            //
            // 没有这道门，N 个并发查询会各自 TLS 握手各建一条 h2 连接 —— 而 h2 的
            // 全部意义就是**一条**连接的多 stream。持门期间：先双检（等门的人可能
            // 已经建好 h2 连接），再建连；ALPN 一落定就放门（交换在门外跑，不串行化）。
            //
            // 门只在"该键从未回退过 http/1.1"时使用：h1-only 服务端首条查询落定后
            // 所有查询直接走既有 h1 路径，并发度不受任何影响。
            let gate = if rt.h2.needs_gate(key) {
                if remain().is_zero() {
                    return Attempt::Reject(None);
                }
                match tokio::time::timeout(remain(), rt.h2.lock_gate(key)).await {
                    Err(_) => return Attempt::Reject(None),
                    Ok(g) => g,
                }
            } else {
                None
            };
            if gate.is_some() {
                if let Some(lease) = rt.h2.acquire_lease(key) {
                    drop(gate);
                    return h2_exchange(rt, key, lease, targets, query, deadline).await;
                }
            }
            match connect_doh(rt, cfg, remain()).await {
                Ok(Connected::Http1(c)) => {
                    // P0-3：ALPN 只协商到 http/1.1（或对端不支持 ALPN）⇒ 既有 h1 实现。
                    // 计数按"新建连接"记，用于 /api/upstreams 与 /metrics 的回退可见性。
                    rt.h2.note_fallback_h1(key);
                    drop(gate);
                    c
                }
                Ok(Connected::H2(tls)) => {
                    let conn = match doh_h2::establish(rt.h2.as_ref(), key, tls, deadline).await {
                        Ok(c) => c,
                        Err(e) => {
                            drop(gate);
                            tracing::debug!(kind = e.kind(), err = %e, "DoH h2 握手失败");
                            return Attempt::Reject(None);
                        }
                    };
                    // 先注册再放门：等门者双检时能直接复用这条连接（连接数=1）。
                    let registered = rt.h2.register(key, conn.clone());
                    drop(gate);
                    let Some(lease) = conn.lease() else {
                        return Attempt::Reject(None);
                    };
                    if !registered {
                        // 未注册（每键连接数到顶）：本次用完即关，不泄漏。
                        tracing::debug!("DoH h2 连接未入池（每键上限）");
                    }
                    return h2_exchange(rt, key, lease, targets, query, deadline).await;
                }
                Err(e) => {
                    // P0-4：连接失败按 TLS 阶段归因（链/主机名/过期/pin/版本/握手）。
                    drop(gate);
                    tracing::debug!(up = %cfg.id, host = %cfg.host, err = %e, "DoH 建连失败");
                    return Attempt::Reject(None);
                }
            }
        }
    };
    // A7：一次 DoH 尝试 = 一次真实 HTTP POST 往返（含复用池内连接的情形）。
    rt.record_wire_request();
    match http_post(&mut conn, cfg, &targets.path, query, remain).await {
        Some(out) => Attempt::H1 {
            body: out.body,
            conn,
            will_close: out.will_close,
        },
        None => Attempt::Reject(Some(conn)),
    }
}

/// 在一条 h2 连接上跑一次交换（计数 + 失败回收）。
async fn h2_exchange(
    rt: &UpstreamRuntime,
    key: &PoolKey,
    lease: doh_h2::H2Lease,
    targets: &Targets,
    query: &[u8],
    deadline: Instant,
) -> Attempt {
    rt.record_wire_request();
    match lease.exchange(&targets.h2_uri, query, deadline).await {
        Ok(body) => Attempt::H2 { body },
        Err(e) => {
            if e.evict_conn() {
                rt.h2.evict(key, lease.conn());
            }
            tracing::debug!(kind = e.kind(), err = %e, "DoH h2 交换失败（新建连接）");
            Attempt::Reject(None)
        }
    }
}

/// 建好 TLS 连接后的传输形态（由 ALPN 协商结果决定，P0-3）。
enum Connected {
    /// ALPN 协商到 `h2`：交 h2 codec（[`crate::doh_h2`]）。
    H2(TlsConn),
    /// ALPN 协商到 `http/1.1` 或对端未协商 ALPN：走既有 HTTP/1.1 实现。
    Http1(TlsConn),
}

/// 建立 DoH TLS 连接（ALPN 恒为 h2 + http/1.1）。
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
) -> crate::error::UpstreamResult<Connected> {
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
    // TLS 握手（含 rustls 配置构建）纳入**同一个** deadline；返回即刻保证 TCP
    // 连接被 drop（上层 `Attempt::Reject(None)` / 错误分支不再持有 fd）。
    tokio::time::timeout(remain(), async {
        // **P0-4**：TLS 策略（版本下限 / 系统+自定义 CA / SPKI pin）统一由 runtime
        // 构建并缓存；**P0-3**：ALPN 由传输层给出 `["h2","http/1.1"]`。
        let config = rt.tls_config(false, alpn_doh())?;
        let sni = tls::server_name(&cfg.host)?;
        let connector = TlsConnector::from(config);
        let stream = connector.connect(sni, tcp).await.map_err(|e| {
            let described = e
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<rustls::Error>())
                .map(tls::describe_tls_error)
                .unwrap_or_else(|| e.to_string());
            crate::error::UpstreamError::Tls(described)
        })?;
        // ALPN 协商结果决定 codec（h2 / http/1.1 回退）。
        Ok(match stream.get_ref().1.alpn_protocol() {
            Some(b"h2") => Connected::H2(stream),
            _ => Connected::Http1(stream),
        })
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
    /// 服务端要求关闭连接（`Connection: close` / HTTP/1.0 未协商 keep-alive /
    /// 无 Content-Length 且非 chunked 的"读到 EOF"响应）。
    will_close: bool,
}

/// 在一条 HTTP/1.1 TLS 连接上发 POST 并读取校验响应。失败返回 None（连接不可复用）。
///
/// **P0-3**：去掉"必须有 Content-Length / 拒绝 chunked"的限制：
/// - `Transfer-Encoding: chunked` ⇒ 就地解码（[`decode_chunked`]），帧边界精确；
/// - 无 `Content-Length` 且非 chunked ⇒ 读到 EOF（HTTP/1.1 语义），连接**必然**不可复用；
/// - 有 `Content-Length` ⇒ 精确读满，不超读（连接可复用）。
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

    // 读取：先到 header 结束（\r\n\r\n），再按 framing 语义读正文。不超读。
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let header_end: usize;
    loop {
        if let Some(pos) = find_header_end(&buf) {
            header_end = pos;
            break;
        }
        if remain().is_zero() {
            return None;
        }
        let n = match tokio::time::timeout(remain(), conn.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return None,
        };
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 64 * 1024 {
            return None;
        }
    }

    let head = parse_response_headers(&buf[..header_end])?;
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

    let body_start = header_end + 4;
    let body: Vec<u8>;
    let leftover: usize;
    if head.chunked {
        // chunked：可能跨多次 read，边读边解。
        loop {
            match decode_chunked(&buf[body_start..]) {
                Chunked::Done(b, consumed) => {
                    body = b;
                    leftover = buf.len() - body_start - consumed;
                    break;
                }
                Chunked::NeedMore => {
                    if remain().is_zero() {
                        return None;
                    }
                    let n = match tokio::time::timeout(remain(), conn.read(&mut chunk)).await {
                        Ok(Ok(n)) if n > 0 => n,
                        _ => return None,
                    };
                    buf.extend_from_slice(&chunk[..n]);
                    // 防御 chunked 无限膨胀（正文上限 + 每 chunk 元数据余量）。
                    if buf.len() - body_start > MAX_BODY + 64 * 1024 {
                        return None;
                    }
                }
                Chunked::TooLarge | Chunked::Malformed => return None,
            }
        }
    } else if let Some(len) = head.content_length {
        if !(12..=MAX_BODY).contains(&len) {
            return None;
        }
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
        body = buf[body_start..body_start + len].to_vec();
        leftover = buf.len() - body_start - len;
    } else {
        // 无 Content-Length、非 chunked：HTTP/1.1 只能是"读到 EOF"（服务端会关连接）。
        loop {
            if remain().is_zero() {
                return None;
            }
            let n = match tokio::time::timeout(remain(), conn.read(&mut chunk)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => n,
                _ => return None,
            };
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() - body_start > MAX_BODY {
                return None;
            }
        }
        body = buf[body_start..].to_vec();
        leftover = 0;
    }
    if body.len() > MAX_BODY {
        return None;
    }
    // 有残留字节（在上一个响应之后多读了）⇒ 协议违规/不可复用。
    if leftover > 0 {
        return None;
    }
    // 无 Content-Length 且非 chunked 的响应以 EOF 结束 ⇒ 连接已被对端关闭。
    let eof_framed = head.content_length.is_none() && !head.chunked;
    Some(PostOutcome {
        body,
        will_close: head.will_close || eof_framed,
    })
}

/// chunked 解码结果。
#[derive(Debug, PartialEq, Eq)]
enum Chunked {
    /// 完整正文 + 消耗的字节数（从正文起点算起，含结尾 CRLF 与 trailer）。
    Done(Vec<u8>, usize),
    /// 数据不够，需要继续读。
    NeedMore,
    /// 正文超过 [`MAX_BODY`]。
    TooLarge,
    /// 编码非法（size 行/CRLF/trailer）。
    Malformed,
}

/// 就地解码 `Transfer-Encoding: chunked`（RFC 9112 §7.1）。
///
/// 只做**一个响应**的解码：`Done(body, consumed)` 的 `consumed` 精确到结尾空行，
/// 供调用方判断"是否有残留字节"（决定连接能否复用）。
fn decode_chunked(buf: &[u8]) -> Chunked {
    let mut pos = 0usize;
    let mut body: Vec<u8> = Vec::new();
    loop {
        let line_end = match find_crlf(buf, pos) {
            Some(i) => i,
            None => return Chunked::NeedMore,
        };
        // size 行可带 chunk extension（`1a;foo=bar`），只取分号前的十六进制。
        let size_part = trim_ascii(
            buf[pos..line_end]
                .split(|&b| b == b';')
                .next()
                .unwrap_or(&[]),
        );
        if size_part.is_empty() || size_part.len() > 8 {
            return Chunked::Malformed;
        }
        let mut size = 0usize;
        for &b in size_part {
            let digit = match (b as char).to_digit(16) {
                Some(d) => d as usize,
                None => return Chunked::Malformed,
            };
            size = match size.checked_mul(16).and_then(|v| v.checked_add(digit)) {
                Some(v) => v,
                None => return Chunked::Malformed,
            };
        }
        pos = line_end + 2;
        if size == 0 {
            // 结尾：0 长度块后跟可选 trailer，最后是空行。
            loop {
                let e = match find_crlf(buf, pos) {
                    Some(i) => i,
                    None => return Chunked::NeedMore,
                };
                if e == pos {
                    return Chunked::Done(body, e + 2);
                }
                pos = e + 2;
            }
        }
        if buf.len() < pos + size + 2 {
            return Chunked::NeedMore;
        }
        if body.len() + size > MAX_BODY {
            return Chunked::TooLarge;
        }
        body.extend_from_slice(&buf[pos..pos + size]);
        if &buf[pos + size..pos + size + 2] != b"\r\n" {
            return Chunked::Malformed;
        }
        pos += size + 2;
    }
}

/// 从 `from` 起找 CRLF 的偏移。
fn find_crlf(buf: &[u8], from: usize) -> Option<usize> {
    if from >= buf.len() {
        return None;
    }
    buf[from..]
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|i| from + i)
}

/// 去掉首尾 ASCII 空白（不分配）。
fn trim_ascii(mut s: &[u8]) -> &[u8] {
    while let Some((&b, rest)) = s.split_first() {
        if b.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    while let Some((&b, rest)) = s.split_last() {
        if b.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    s
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
                // `Transfer-Encoding` 只认 chunked（h2 不产生该头；h1 回退路径需要）。
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
/// 判据与 Python `http.client.HTTPResponse._check_close()` 等价（`http.client` 里
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
        // HTTP/1.0 默认关闭；请求/响应都 keep-alive 时才复用（Python 语义）。
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

    /* ---------------- P0-3：qid=0 与响应收尾 ---------------- */

    fn dns_response(qid: u16, qd: u16, an: u16) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(qid.to_be_bytes());
        v.extend(0x8180u16.to_be_bytes());
        v.extend(qd.to_be_bytes());
        v.extend(an.to_be_bytes());
        v.extend(0u16.to_be_bytes());
        v.extend(0u16.to_be_bytes());
        v.extend(b"\x07example\x03com\x00");
        v.extend(1u16.to_be_bytes());
        v.extend(1u16.to_be_bytes());
        v
    }

    #[test]
    fn wire_qid_is_zeroed_and_original_preserved() {
        let q = dns_response(0x1234, 1, 0); // 复用构造器造"查询字节"
        let wire = rewrite_qid(&q, DOH_QID);
        assert_eq!(
            &wire[0..2],
            &[0, 0],
            "上线报文 qid 必须为 0（RFC 8484 §4.1）"
        );
        assert_eq!(&wire[2..], &q[2..], "除 qid 外不得改动查询字节");
        assert_eq!(qid_of(&q), Some(0x1234), "原查询不被就地修改");
    }

    #[test]
    fn finish_requires_qid_zero_then_restores_original() {
        // 响应回显 qid=0（正确）⇒ 接受，并还原调用方 qid。
        let (ok, body) = finish(dns_response(0, 1, 1), 0xBEEF);
        assert!(ok);
        assert_eq!(
            qid_of(&body.unwrap()),
            Some(0xBEEF),
            "qid 必须还原为调用方原值"
        );
        // 响应回显非 0（服务端没按请求的 0 回显）⇒ 拒绝。
        let (ok, body) = finish(dns_response(0x1234, 1, 1), 0xBEEF);
        assert!(!ok, "响应 qid 必须按 0 校验");
        assert!(body.is_none());
        // 长度下限 / header-only / 上限。
        assert!(!finish(vec![0u8; 11], 1).0, "len<12 必须拒绝");
        assert!(!finish(dns_response(0, 0, 0), 1).0, "QDCOUNT!=1 必须拒绝");
        let mut big = dns_response(0, 1, 0);
        big.resize(MAX_BODY + 1, 0);
        assert!(!finish(big, 1).0, "len>MAX_BODY 必须拒绝");
    }

    /* ---------------- P0-3：chunked 解码 ---------------- */

    #[test]
    fn decode_chunked_single_and_multi_chunk() {
        // 单块：`c\r\n` + 12 字节 + `\r\n` + `0\r\n\r\n`
        let payload = dns_response(0, 1, 1);
        let n = payload.len();
        let mut buf = format!("{n:x}\r\n").into_bytes();
        buf.extend_from_slice(&payload);
        buf.extend_from_slice(b"\r\n0\r\n\r\n");
        match decode_chunked(&buf) {
            Chunked::Done(body, consumed) => {
                assert_eq!(body, payload);
                assert_eq!(consumed, buf.len(), "consumed 必须精确到结尾空行");
            }
            other => panic!("单块 chunked 解码失败: {other:?}"),
        }
        // 多块 + chunk extension + trailer。
        let mut buf = Vec::new();
        let (a, b) = payload.split_at(5);
        buf.extend_from_slice(format!("{:x};ext=1\r\n", a.len()).as_bytes());
        buf.extend_from_slice(a);
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(format!("{:x}\r\n", b.len()).as_bytes());
        buf.extend_from_slice(b);
        buf.extend_from_slice(b"\r\n0\r\nX-Trailer: v\r\n\r\n");
        match decode_chunked(&buf) {
            Chunked::Done(body, consumed) => {
                assert_eq!(body, payload);
                assert_eq!(consumed, buf.len());
            }
            other => panic!("多块 chunked 解码失败: {other:?}"),
        }
    }

    #[test]
    fn decode_chunked_incremental_and_malformed() {
        let payload = dns_response(0, 1, 1);
        let full = {
            let mut v = format!("{:x}\r\n", payload.len()).into_bytes();
            v.extend_from_slice(&payload);
            v.extend_from_slice(b"\r\n0\r\n\r\n");
            v
        };
        // 每截断一个字节都必须 NeedMore（增量读的核心性质）。
        for cut in 0..full.len() {
            assert_eq!(
                decode_chunked(&full[..cut]),
                Chunked::NeedMore,
                "截断 {cut} 字节时必须是 NeedMore"
            );
        }
        // 非法 size 行。
        assert_eq!(decode_chunked(b"zz\r\n"), Chunked::Malformed);
        // 缺 CRLF 结尾的块。
        let mut bad = format!("{:x}\r\n", payload.len()).into_bytes();
        bad.extend_from_slice(&payload);
        bad.extend_from_slice(b"XX");
        assert_eq!(decode_chunked(&bad), Chunked::Malformed);
        // 超过正文上限。
        let mut big = format!("{:x}\r\n", MAX_BODY + 1).into_bytes();
        big.extend(std::iter::repeat_n(b'A', MAX_BODY + 1));
        big.extend_from_slice(b"\r\n");
        assert_eq!(decode_chunked(&big), Chunked::TooLarge);
    }

    #[test]
    fn trim_and_find_crlf_basics() {
        assert_eq!(trim_ascii(b"  ab \r\n"), &b"ab"[..]);
        assert_eq!(trim_ascii(b""), &b""[..]);
        assert_eq!(find_crlf(b"ab\r\ncd", 0), Some(2));
        assert_eq!(find_crlf(b"ab\r\ncd", 3), None);
        assert_eq!(find_crlf(b"", 0), None);
    }

    /* ---------------- D2: will_close 判定 ---------------- */

    #[test]
    fn http11_without_connection_header_stays_open() {
        assert!(!will_close("HTTP/1.1", false, false));
        assert!(!will_close("HTTP/1.1", false, true));
    }

    #[test]
    fn http11_explicit_close_closes() {
        assert!(will_close("HTTP/1.1", true, false));
        // 同时出现 keep-alive 与 close 时以 close 优先（Python 亦然）。
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

    /// **P0-3**：ALPN 偏好必须是 h2 优先、http/1.1 回退（顺序即优先级）。
    #[test]
    fn alpn_prefers_h2_then_http11() {
        assert_eq!(
            alpn_doh(),
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            "DoH 必须同时提供 h2 与 http/1.1，且 h2 在前"
        );
    }
}
