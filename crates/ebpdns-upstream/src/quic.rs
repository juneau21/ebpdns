//! **[历史归因]** QUIC 上游（DoQ / DoH3）状态机 + 收发，对齐 Python `quic_upstream.py`。
//!
//! 状态机：单连接 + 单飞重连。建连失败记分类原因（证书/拒绝/DNS/TLS）并进入退避快失败窗口；
//! 窗口内新查询立即返回缓存原因，不重复握手；重连开始即清退避；成功连接清原因。
//! 超时归因：等待/收发超时统一返回 `"timeout"`。`close()` 用在途 future 列表快照逐一 cancel，
//! 且每个在途任务由 `InflightGuard` 在 Drop 时中止（含超时/调用方取消两条路径），不留悬挂任务。
//!
//! # DoH3（RFC 9114 + RFC 9204）最小客户端合规要点
//! - ALPN：DoH3 = `h3`（RFC 9114 §3.1）；DoQ = `doq`（RFC 9250 §4.1，`doq-i03` 仅作草案回退）。
//! - 连接建立后**每连接一次**打开三个单向流：control(0x00, 首帧 SETTINGS)、
//!   QPACK encoder(0x02)、QPACK decoder(0x03)（RFC 9114 §6.2.1、RFC 9204 §4.2）。
//!   三者都是关键流：**不得关闭/重置**，故只写不 `finish()`，句柄由 `QuicManager` 持有到连接终结。
//! - 请求字段段必须带 QPACK 字段段前缀（Required Insert Count=0 + Delta Base=0，RFC 9204 §4.5.1），
//!   `:authority` 用静态表名字引用 + 完整 host:port 值（IPv6 加方括号），绝不为空。
//! - 响应按帧解析 HEADERS/DATA，校验 `:status==200` 与 `content-type` 含 `application/dns-message`，
//!   按 `content-length` 精确读取，缺省以 FIN 为准，并设 64KB 上限。

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::{ClientConfig, Connection, Endpoint, SendStream};

use crate::config::UpstreamConfig;
use crate::header_check::{is_header_only, qid_of};
use crate::runtime::UpstreamRuntime;
use crate::Proto;

/// **[历史归因]** 建连失败退避窗口（秒）：窗口内查询快失败（Python `QUIC_FAIL_BACKOFF_S`）。
const FAIL_BACKOFF: Duration = Duration::from_secs(10);

/// DoH3 请求 `user-agent`（静态表索引 95 的名字引用 + 字面值；RFC 9110 §10.1.5 SHOULD 发送）。
const H3_USER_AGENT: &[u8] = b"ebpdns/2.1";

/// **[历史归因]** DoH3 响应体上限（对齐 Python `_MAX_MSG`，也是 DoH/DoT 路径的 DNS 报文上限）。
const H3_MAX_BODY: usize = 65535;

/// 单个 HTTP/3 帧载荷上限：DoH3 合法帧（HEADERS/DATA）远小于此值，超限即判协议异常，
/// 避免对端声明超长帧导致缓冲无界增长。
const H3_MAX_FRAME: u64 = 64 * 1024;

/// **[历史归因]** 分类 QUIC/建连错误为 `(kind, reason)`，对齐 Python `classify_conn_error`。
pub fn classify_conn_error(err: &str) -> (String, String) {
    let e = err.to_ascii_lowercase();
    if e.contains("certificate")
        || e.contains("unknown issuer")
        || e.contains("unknownca")
        || e.contains("self signed")
        || e.contains("cert invalid")
        || e.contains("certificate verify")
    {
        return ("certificate".into(), "TLS certificate verify failed".into());
    }
    if e.contains("refused") {
        return ("refused".into(), "connection refused".into());
    }
    if e.contains("dns")
        || e.contains("name resolution")
        || e.contains("getaddrinfo")
        || e.contains("no such host")
        || e.contains("failed to lookup")
    {
        return ("dns".into(), "DNS resolution failed".into());
    }
    if e.contains("timed out") || e.contains("timeout") {
        return ("timeout".into(), "timeout".into());
    }
    // 对端关闭 / 流被重置：DoQ 服务器以应用错误码拒绝查询时落到这里
    // （例如 AliDNS DoQ 对合法查询回 DOQ_PROTOCOL_ERROR=0x2）。
    // 必须排在下面 tls 分支之前：这些串里不含 "tls" 但含 "connection"。
    if e.contains("connection lost")
        || e.contains("closed by peer")
        || e.contains("applicationclosed")
        || e.contains("connection closed")
        || e.contains("reset by peer")
        || e.contains("stream reset")
    {
        return (
            "connection".into(),
            "connection lost or closed by peer".into(),
        );
    }
    if e.contains("tls")
        || e.contains("handshake")
        || e.contains("no application protocol")
        || e.contains("application protocol")
        || e.contains("protocol violation")
    {
        return ("tls".into(), "TLS handshake failed".into());
    }
    ("".into(), err.to_string())
}

/// **[历史归因]** 单上游的 QUIC 连接管理器（对齐 Python `_QuicConnManager`）。
pub struct QuicManager {
    pub host: String,
    pub port: u16,
    pub path: String,
    pub proto: Proto,
    strict_cert: bool,
    /// 缓存的就绪连接。
    conn: parking_lot::Mutex<Option<Arc<Connection>>>,
    /// endpoint 必须随连接存活（丢弃 endpoint 会杀连接）；close 时一并 drop 回收 fd。
    endpoint: parking_lot::Mutex<Option<quinn::Endpoint>>,
    /// 建连失败退避：失败时刻与分类原因。
    failed_since: parking_lot::Mutex<Option<Instant>>,
    last_err: parking_lot::Mutex<Option<(String, String)>>,
    /// 单飞重连锁。
    connect_lock: tokio::sync::Mutex<()>,
    closing: AtomicBool,
    /// 在途 exchange 的 (token, AbortHandle)（close 快照 cancel）。RAII guard 保证取消即清理。
    inflight: Arc<parking_lot::Mutex<Vec<(u64, tokio::task::AbortHandle)>>>,
    next_token: std::sync::atomic::AtomicU64,
    /// DoH3 关键单向流（control + QPACK encoder/decoder）的发送端句柄。
    /// 必须持有到连接终结：关键流被关闭/重置会被对端判为 H3_CLOSED_CRITICAL_STREAM
    /// （RFC 9114 §6.2.1、RFC 9204 §4.2），因此永不 `finish()`，只在换连接/关闭时随连接一起丢弃。
    h3_uni: parking_lot::Mutex<Vec<SendStream>>,
    /// A7 线速请求计数：每次尝试的 exchange 都是一次真实 QUIC 往返。
    wire: std::sync::atomic::AtomicU64,
}

/// 在途 exchange 登记的 RAII guard：Drop 时先中止自己登记的任务（防"drop JoinHandle 不取消任务"
/// 与"调用方取消 query() 后任务仍挂后台"的双重泄漏），再按 token 自 inflight 列表移除。
struct InflightGuard {
    inflight: Arc<parking_lot::Mutex<Vec<(u64, tokio::task::AbortHandle)>>>,
    token: u64,
    abort: tokio::task::AbortHandle,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        // 幂等：任务已结束时 abort 为 no-op；未结束（超时/被外部取消）则立即中止，
        // 同时让 QUIC 层发 STOP_SENDING/RESET_STREAM 通知对端取消本流。
        self.abort.abort();
        self.inflight.lock().retain(|(t, _)| *t != self.token);
    }
}

impl QuicManager {
    pub fn new(cfg: &UpstreamConfig) -> Self {
        QuicManager {
            host: cfg.host.clone(),
            port: cfg.port,
            // H3 `:path`：与 DoH 的 request-target 同口径（完整 URL 必须剥成路径，
            // 见 [`crate::addr::request_path`] 的缺陷说明）。
            path: crate::addr::request_path(&cfg.url, true),
            proto: cfg.proto,
            strict_cert: cfg.strict_cert,
            conn: parking_lot::Mutex::new(None),
            endpoint: parking_lot::Mutex::new(None),
            failed_since: parking_lot::Mutex::new(None),
            last_err: parking_lot::Mutex::new(None),
            connect_lock: tokio::sync::Mutex::new(()),
            closing: AtomicBool::new(false),
            inflight: Arc::new(parking_lot::Mutex::new(Vec::new())),
            next_token: std::sync::atomic::AtomicU64::new(1),
            h3_uni: parking_lot::Mutex::new(Vec::new()),
            wire: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// **[历史归因]** 当前连接是否就绪（存在且未被对端关闭）。对齐 Python `_conn_ready`。
    fn ready_conn(&self) -> Option<Arc<Connection>> {
        let g = self.conn.lock();
        match g.as_ref() {
            Some(c) if c.close_reason().is_none() => Some(c.clone()),
            _ => None,
        }
    }

    /// **[历史归因]** 标记连接失败并存分类原因（对齐 Python `_conn_failed`）。
    fn mark_failed(&self, kind: String, reason: String) {
        *self.conn.lock() = None;
        // 连接已被判定作废：连带丢弃 DoH3 关键单向流句柄（若底层连接尚存，对端会因关键流
        // 被 reset 而关闭它，避免"僵尸连接"占着 fd 直到 idle 超时）。
        self.h3_uni.lock().clear();
        *self.failed_since.lock() = Some(Instant::now());
        *self.last_err.lock() = Some((kind, reason));
    }

    /// 退避窗口内？
    fn in_backoff(&self) -> bool {
        self.failed_since
            .lock()
            .is_some_and(|t| t.elapsed() < FAIL_BACKOFF)
    }

    /// A7：本管理器累计的**真实** QUIC 往返次数
    /// （每次尝试的 exchange 各计 1；重连后的重试也计）。
    pub fn wire_count(&self) -> u64 {
        self.wire.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn take_last_err(&self) -> (String, String) {
        self.last_err
            .lock()
            .clone()
            .unwrap_or_else(|| ("".into(), "connection failed".into()))
    }

    /// 统一查询入口。返回 `(ok, data, err)`。
    pub async fn query(
        &self,
        rt: &UpstreamRuntime,
        query: &[u8],
        timeout: Duration,
    ) -> (bool, Option<Vec<u8>>, String) {
        if self.closing.load(Ordering::Relaxed) {
            return (false, None, "closed".into());
        }
        // 已有就绪连接：直接 exchange。
        if let Some(conn) = self.ready_conn() {
            self.wire.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            match self.exchange_with_timeout(&conn, query, timeout).await {
                Ok(body) => return (true, Some(body), String::new()),
                Err(e) => {
                    let (kind, reason) = classify_conn_error(&e);
                    self.mark_failed(kind, reason.clone());
                    // 连接坏了：下面走重连。
                }
            }
        }

        // 退避窗口内：快失败，不重复握手。
        if self.in_backoff() {
            let (_, reason) = self.take_last_err();
            return (false, None, reason);
        }

        // 单飞重连：拿锁，拿到后若已有就绪连接直接复用。
        let _guard = self.connect_lock.lock().await;
        if self.closing.load(Ordering::Relaxed) {
            return (false, None, "closed".into());
        }
        if let Some(conn) = self.ready_conn() {
            self.wire.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return self
                .exchange_with_timeout(&conn, query, timeout)
                .await
                .map_or_else(
                    |e| {
                        let (kind, reason) = classify_conn_error(&e);
                        self.mark_failed(kind, reason.clone());
                        (false, None, reason)
                    },
                    |body| (true, Some(body), String::new()),
                );
        }

        // **[历史归因]** 开始重连：清除退避（对齐 Python：reconnect 开始即清）。
        *self.failed_since.lock() = None;
        let connect_timeout = timeout.min(Duration::from_secs(5));
        let conn = match self.do_connect(rt, connect_timeout).await {
            Ok(c) => c,
            Err(e) => {
                let (kind, reason) = classify_conn_error(&e);
                self.mark_failed(kind, reason.clone());
                return (false, None, reason);
            }
        };
        // **[历史归因]** 成功建连：清失败原因（对齐 Python）。
        *self.last_err.lock() = None;
        *self.failed_since.lock() = None;
        *self.conn.lock() = Some(conn.clone());
        rt.bootstrap.set_bootstrap(&self.host, remote_ip(&conn));

        self.wire.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        match self.exchange_with_timeout(&conn, query, timeout).await {
            Ok(body) => (true, Some(body), String::new()),
            Err(e) => {
                let (kind, reason) = classify_conn_error(&e);
                self.mark_failed(kind, reason.clone());
                (false, None, reason)
            }
        }
    }

    /// 带超时的 exchange（DoQ / DoH3 分派）。超时 → "timeout"。
    async fn exchange_with_timeout(
        &self,
        conn: &Connection,
        query: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        let mut h = tokio::spawn({
            let conn = conn.clone();
            let q = query.to_vec();
            let path = self.path.clone();
            let host = self.host.clone();
            let port = self.port;
            let proto = self.proto;
            async move {
                match proto {
                    Proto::Doq => doq_exchange(&conn, &q).await,
                    // DoH3 需要 host:port 组装 :authority，且关键单向流已在 do_connect 建好。
                    Proto::Doh3 => doh3_exchange(&conn, &host, port, &path, &q).await,
                    _ => Err("not a quic proto".to_string()),
                }
            }
        });
        // 登记 in-flight（close 可快照 cancel）。RAII guard 保证取消/错误路径均清理。
        let token = self.next_token.fetch_add(1, Ordering::Relaxed);
        let ah = h.abort_handle();
        self.inflight.lock().push((token, ah.clone()));
        let _guard = InflightGuard {
            inflight: self.inflight.clone(),
            token,
            abort: ah,
        };
        // 用 `&mut h` 轮询：超时后仍持有 JoinHandle，可显式 abort（只 drop JoinHandle 不会
        // 取消任务，旧实现会让超时的 exchange 在后台继续跑到连接 idle 超时，属泄漏）。
        let res = tokio::time::timeout(timeout, &mut h).await;
        // guard Drop 时按 token 自 inflight 移除并 abort 自身任务（含本 await 被外部取消的情况）。
        match res {
            Ok(Ok(Ok(body))) => Ok(body),
            Ok(Ok(Err(e))) => Err(e),
            Ok(Err(join_err)) => Err(join_err.to_string()),
            Err(_) => {
                h.abort();
                Err("timeout".to_string())
            }
        }
    }

    /// 建立一条新 QUIC 连接。
    async fn do_connect(
        &self,
        rt: &UpstreamRuntime,
        timeout: Duration,
    ) -> Result<Arc<Connection>, String> {
        let ip = match resolve_quic_ip(rt, self.host(), self.port).await {
            Some(ip) => ip,
            None => return Err("dns: no upstream ip".to_string()),
        };
        let addr = SocketAddr::new(ip, self.port);

        // rustls client config + ALPN。
        let hostname = crate::addr::is_hostname(&self.host);
        let strict = self.strict_cert || hostname;
        let rustls_cfg =
            crate::tls::build_client_config(strict).map_err(|e| format!("tls: {e}"))?;
        let mut rustls_cfg = (*rustls_cfg).clone();
        // ALPN 两条分支各自独立，不得混用：
        // - DoQ：RFC 9250 §4.1 最终 ALPN 为 "doq"（放在首位）；"doq-i03" 是已废弃草案标识，
        //   仅作与老服务端的兼容回退保留在后。
        // - DoH3：RFC 9114 §3.1 为 "h3"。
        let alpn = match self.proto {
            Proto::Doq => vec![b"doq".to_vec(), b"doq-i03".to_vec()],
            Proto::Doh3 => vec![b"h3".to_vec()],
            _ => vec![],
        };
        rustls_cfg.alpn_protocols = alpn;
        let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(rustls_cfg))
            .map_err(|e| format!("tls: {e}"))?;
        let mut qcfg = ClientConfig::new(Arc::new(qcc));
        qcfg.transport_config(quic_transport_config());

        let bind: SocketAddr = "0.0.0.0:0".parse().map_err(|e| format!("{e}"))?;
        let mut endpoint = Endpoint::client(bind).map_err(|e| format!("{e}"))?;
        endpoint.set_default_client_config(qcfg);
        let connecting = endpoint
            .connect(addr, &self.host)
            .map_err(|e| format!("connect: {e}"))?;
        let conn = tokio::time::timeout(timeout, connecting)
            .await
            .map_err(|_| "timeout".to_string())?
            .map_err(|e| format!("{e}"))?;
        let conn = Arc::new(conn);
        // DoH3：连接级 HTTP/3 初始化（每连接一次，绝不能每请求重开 control 流：
        // 第二个 control 流会被对端判为 H3_STREAM_CREATION_ERROR，RFC 9114 §6.2.1）。
        // 失败按建连失败处理：endpoint 尚未存入管理器，drop 即回收 socket（不泄漏 fd）。
        if self.proto == Proto::Doh3 {
            let streams = tokio::time::timeout(timeout, h3_client_setup(&conn))
                .await
                .map_err(|_| "timeout".to_string())?
                .map_err(|e| format!("h3 setup: {e}"))?;
            let held = streams.len();
            *self.h3_uni.lock() = streams;
            tracing::debug!(held, "doh3 critical uni streams retained");
        }
        // endpoint 必须存活连接才活着；存入管理器，close 时 drop 回收 fd（替代 mem::forget 泄漏）。
        *self.endpoint.lock() = Some(endpoint);
        Ok(conn)
    }

    fn host(&self) -> &str {
        &self.host
    }

    /// 关闭：标记 closing，快照 cancel 在途 future，关闭连接并 drop endpoint 回收 fd。
    pub fn close(&self) {
        self.closing.store(true, Ordering::Relaxed);
        // list 快照 cancel 在途。
        let handles: Vec<tokio::task::AbortHandle> =
            self.inflight.lock().drain(..).map(|(_, h)| h).collect();
        for h in handles {
            h.abort();
        }
        if let Some(conn) = self.conn.lock().take() {
            conn.close(0u32.into(), b"");
        }
        // DoH3 关键单向流句柄随连接一起释放。
        self.h3_uni.lock().clear();
        // drop endpoint：关闭底层 socket/回收 fd。
        *self.endpoint.lock() = None;
    }
}

fn remote_ip(conn: &Connection) -> std::net::IpAddr {
    conn.remote_address().ip()
}

fn quic_transport_config() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    // 15s 空闲超时（Varint 合法范围，失败回退默认）。
    if let Ok(v) = Duration::from_secs(15).try_into() {
        t.max_idle_timeout(Some(v));
    }
    Arc::new(t)
}

/// 解析 QUIC 上游目标 IP（IP 字面量直取；hostname 走 bootstrap）。
async fn resolve_quic_ip(rt: &UpstreamRuntime, host: &str, port: u16) -> Option<std::net::IpAddr> {
    if !crate::addr::is_hostname(host) {
        return host.parse::<std::net::IpAddr>().ok();
    }
    if let Some(ip) = rt.bootstrap.bootstrap_ip(host) {
        return Some(ip);
    }
    let ips = rt.bootstrap.resolve_udp_addrs(host, port).await;
    ips.into_iter().next()
}

/// DoQ 请求帧（RFC 9250 §4.2）：2 字节大端长度前缀 + DNS 报文。
///
/// 长度字段是 u16，超出即视为不可发（DNS 报文上限 65535，且上游查询构造已保证 < 65536）。
fn doq_frame(query: &[u8]) -> Result<Vec<u8>, String> {
    let qlen = u16::try_from(query.len()).map_err(|_| "query too long for DoQ".to_string())?;
    let mut frame = Vec::with_capacity(2 + query.len());
    frame.extend(qlen.to_be_bytes());
    frame.extend_from_slice(query);
    Ok(frame)
}

/// DoQ 响应读取状态机（纯函数，可单测）：累积流字节 → 产出恰好一条定长报文。
///
/// RFC 9250 §4.2：应答同样是「2 字节长度前缀 + 报文」，且**一条流只有一问一答**
/// （§4.2.1 客户端发完查询即 FIN 发送方向）。这里显式拒绝：
/// - 长度前缀 < 12（放不下 DNS 头）；
/// - 声明长度之外的尾随字节（对端多发一律视为协议错误，不静默截断）。
#[derive(Default)]
struct DoqReader {
    buf: Vec<u8>,
    /// 已解析出的报文长度（含前缀解析完成后置位）。
    want: Option<usize>,
}

impl DoqReader {
    fn new() -> Self {
        DoqReader {
            buf: Vec::new(),
            want: None,
        }
    }

    /// 追加字节；返回已就绪的完整响应报文（仅一次）。
    fn feed(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>, String> {
        self.buf.extend_from_slice(data);
        if self.want.is_none() && self.buf.len() >= 2 {
            let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
            if len < 12 {
                return Err("invalid response".to_string());
            }
            self.want = Some(len);
        }
        let Some(len) = self.want else {
            return Ok(None);
        };
        let need = 2 + len;
        if self.buf.len() < need {
            return Ok(None);
        }
        if self.buf.len() > need {
            return Err("trailing bytes after DoQ response".to_string());
        }
        Ok(Some(self.buf[2..need].to_vec()))
    }
}

/// DoQ exchange：bi-stream 上 2 字节大端长度前缀收发。
async fn doq_exchange(conn: &Connection, query: &[u8]) -> Result<Vec<u8>, String> {
    let frame = doq_frame(query)?;
    let (mut tx, mut rx) = conn.open_bi().await.map_err(|e| e.to_string())?;
    tx.write_all(&frame)
        .await
        .map_err(|e| stream_error(conn, &e))?;
    // RFC 9250 §4.2.1：客户端必须用 FIN 表明不再发送数据。
    tx.finish().map_err(|e| e.to_string())?;

    let mut reader = DoqReader::new();
    let mut chunk = [0u8; 4096];
    let body = loop {
        match rx.read(&mut chunk).await {
            Ok(Some(n)) if n > 0 => {
                if let Some(body) = reader.feed(&chunk[..n])? {
                    break body;
                }
            }
            // FIN（None）或 0 长读：流已结束但响应不完整。
            Ok(_) => return Err("connection closed before response".to_string()),
            Err(e) => return Err(stream_error(conn, &e)),
        }
    };

    // 校验：长度下限、非 header-only、qid 一致。
    if body.len() < 12 || is_header_only(&body) {
        return Err("invalid response".to_string());
    }
    if qid_of(&body) != qid_of(query) {
        return Err("qid mismatch".to_string());
    }
    Ok(body)
}

/// 流层错误 + 连接关闭原因：只透出 `Display` 会丢掉端点给的应用错误码
/// （如 DoQ 的 DOQ_PROTOCOL_ERROR=0x2），运维无法区分"服务端拒绝"与"网络抖动"。
fn stream_error(conn: &Connection, e: &(impl std::fmt::Display + ?Sized)) -> String {
    match conn.close_reason() {
        Some(reason) => format!("{e} ({reason:?})"),
        None => e.to_string(),
    }
}

/// DoH3 exchange：最小 HTTP/3 客户端（请求流 HEADERS/DATA + 逐帧解析响应）。
///
/// 关键单向流（control / QPACK encoder / QPACK decoder）在 [`h3_client_setup`] 中
/// **每连接只建一次**，本函数不再碰它们；此处只做一次请求-响应交换。
async fn doh3_exchange(
    conn: &Connection,
    host: &str,
    port: u16,
    path: &str,
    query: &[u8],
) -> Result<Vec<u8>, String> {
    // 请求流：HEADERS(请求字段段) + DATA(DNS wire)，随后半关闭发送方向
    // （RFC 9114 §4.1：客户端发完请求 MUST 关闭发送方向）。
    let (mut tx, mut rx) = conn.open_bi().await.map_err(|e| e.to_string())?;
    let hblock = qpack_encode_request(host, port, path, query.len());
    tracing::debug!(
        host = %host,
        stream_id = tx.id().index(),
        block = %hblock.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        "doh3 request field section"
    );
    let mut headers_frame = Vec::with_capacity(hblock.len() + 8);
    h3_write_frame(&mut headers_frame, H3_FRAME_HEADERS, &hblock);
    tx.write_all(&headers_frame)
        .await
        .map_err(|e| stream_error(conn, &e))?;

    let mut data_frame = Vec::with_capacity(query.len() + 8);
    h3_write_frame(&mut data_frame, H3_FRAME_DATA, query);
    tx.write_all(&data_frame)
        .await
        .map_err(|e| stream_error(conn, &e))?;
    tx.finish().map_err(|e| e.to_string())?;

    // 读响应：HEADERS + DATA。有 content-length 则收齐即停（HTTP 语义下正文长度以此为准），
    // 否则以 FIN/EOF 为结束标志；解析过程中任何协议错误立即返回。
    let mut resp = H3Response::new();
    let mut chunk = [0u8; 4096];
    while !resp.is_complete() {
        match rx
            .read(&mut chunk)
            .await
            .map_err(|e| stream_error(conn, &e))?
        {
            Some(n) => {
                resp.feed(&chunk[..n]);
                if let Some(e) = resp.error() {
                    return Err(e);
                }
            }
            None => break, // FIN：流已结束
        }
    }
    let body = resp.finish()?;

    // DNS 层校验（与 DoQ/DoT/DoH 路径同口径）：长度下限、非 header-only、qid 一致。
    if body.len() < 12 || is_header_only(&body) {
        return Err("invalid response".to_string());
    }
    if qid_of(&body) != qid_of(query) {
        return Err("qid mismatch".to_string());
    }
    Ok(body)
}

/// 写一帧：varint 类型 + varint 长度 + 载荷（RFC 9114 §7.1）。
fn h3_write_frame(out: &mut Vec<u8>, ftype: u64, payload: &[u8]) {
    out.extend(&encode_varint(ftype));
    out.extend(&encode_varint(payload.len() as u64));
    out.extend_from_slice(payload);
}

// ==================== HTTP/3 连接级单向流（RFC 9114 §6.2 / RFC 9204 §4.2） ====================

/// 帧类型（RFC 9114 §11.2.1）。
const H3_FRAME_DATA: u64 = 0x00;
const H3_FRAME_HEADERS: u64 = 0x01;
const H3_FRAME_SETTINGS: u64 = 0x04;
const H3_FRAME_PUSH_PROMISE: u64 = 0x05;
const H3_FRAME_GOAWAY: u64 = 0x07;

/// 单向流类型（RFC 9114 §6.2、RFC 9204 §4.2）。
const H3_STREAM_CONTROL: u8 = 0x00;
const H3_STREAM_QPACK_ENCODER: u8 = 0x02;
const H3_STREAM_QPACK_DECODER: u8 = 0x03;

/// 控制流起始字节：流类型 0x00 + SETTINGS 帧（空设置）。
///
/// 空 SETTINGS 意味着 QPACK_MAX_TABLE_CAPACITY=0 / QPACK_BLOCKED_STREAMS=0（RFC 9204 §5
/// 未出现的设置取默认值 0），于是服务端**不得**使用动态表，我们也就无需跟踪动态表状态。
fn h3_control_stream_bytes() -> Vec<u8> {
    let mut out = vec![H3_STREAM_CONTROL];
    h3_write_frame(&mut out, H3_FRAME_SETTINGS, &[]);
    out
}

/// QPACK encoder 流起始字节（只有流类型前缀，不发任何指令：我们不使用动态表）。
fn h3_qpack_encoder_stream_bytes() -> Vec<u8> {
    vec![H3_STREAM_QPACK_ENCODER]
}

/// QPACK decoder 流起始字节（只有流类型前缀；空 SETTINGS 下无需回送任何指令）。
fn h3_qpack_decoder_stream_bytes() -> Vec<u8> {
    vec![H3_STREAM_QPACK_DECODER]
}

/// 建立连接级 HTTP/3 单向流：control(0x00 + SETTINGS) + QPACK encoder(0x02) + decoder(0x03)。
///
/// 三者都必须在连接建立后立即打开（RFC 9114 §6.2.1：SETTINGS 必须是控制流首帧；
/// RFC 9204 §4.2：每端至多一条 encoder/decoder 流，且收到第二条即为连接错误）。
/// 返回的 `SendStream` **由调用方长期持有**：这些是关键流，关闭或 reset 会被对端判为
/// H3_CLOSED_CRITICAL_STREAM（RFC 9114 §6.2.1、RFC 9204 §4.2），因此只写不 `finish()`。
async fn h3_client_setup(conn: &Connection) -> Result<Vec<SendStream>, String> {
    let mut streams = Vec::with_capacity(3);
    let mut ctl = conn.open_uni().await.map_err(|e| e.to_string())?;
    let ctl_id = ctl.id().index();
    ctl.write_all(&h3_control_stream_bytes())
        .await
        .map_err(|e| stream_error(conn, &e))?;
    streams.push(ctl);
    let mut enc = conn.open_uni().await.map_err(|e| e.to_string())?;
    let enc_id = enc.id().index();
    enc.write_all(&h3_qpack_encoder_stream_bytes())
        .await
        .map_err(|e| stream_error(conn, &e))?;
    streams.push(enc);
    let mut dec = conn.open_uni().await.map_err(|e| e.to_string())?;
    let dec_id = dec.id().index();
    dec.write_all(&h3_qpack_decoder_stream_bytes())
        .await
        .map_err(|e| stream_error(conn, &e))?;
    streams.push(dec);
    tracing::debug!(
        ctl_uni = ctl_id,
        qpack_encoder = enc_id,
        qpack_decoder = dec_id,
        "doh3 connection-level unidirectional streams opened"
    );
    Ok(streams)
}

// ==================== HTTP/3 响应解析状态机（纯函数，可单测） ====================

/// `buf[pos..]` 处的帧解析结果。
enum H3FrameAt {
    /// 完整帧：`(帧类型, 载荷起, 载荷止)`。
    Frame(u64, usize, usize),
    /// 数据不足，需继续读。
    Incomplete,
    /// 声明长度超过 [`H3_MAX_FRAME`]，判协议异常（防无界缓冲）。
    TooLarge,
}

/// 解析帧头：varint 类型 + varint 长度 + 载荷（RFC 9114 §7.1）。
fn h3_frame_at(buf: &[u8], pos: usize) -> H3FrameAt {
    let Some(rest) = buf.get(pos..) else {
        return H3FrameAt::Incomplete;
    };
    let Some((ftype, r1)) = decode_varint(rest) else {
        return H3FrameAt::Incomplete;
    };
    let Some((len, r2)) = decode_varint(r1) else {
        return H3FrameAt::Incomplete;
    };
    if len > H3_MAX_FRAME {
        return H3FrameAt::TooLarge;
    }
    // r2 是长度字段之后的剩余切片，故载荷起点 = buf.len() - r2.len()。
    let start = buf.len() - r2.len();
    let end = start + len as usize;
    if end > buf.len() {
        return H3FrameAt::Incomplete;
    }
    H3FrameAt::Frame(ftype, start, end)
}

/// DoH3 响应读取状态机：逐帧解析 HEADERS/DATA，提取并校验 `:status` / `content-type` /
/// `content-length`，按需累积正文。
struct H3Response {
    /// 已收到的字节；**只保留尚未完整到达的帧**（完整帧在处理后立即从头部回收，
    /// 见 [`H3Response::feed`]）。因此解析游标恒为 0，不存在"半个帧被丢弃"的可能。
    buf: Vec<u8>,
    status: Option<u16>,
    content_type: Option<String>,
    content_length: Option<usize>,
    body: Vec<u8>,
    /// 已收到首个 HEADERS（最终或中间响应）。
    headers_seen: bool,
    /// 已收到最终响应之后的尾字段段（其后不应再有 DATA，RFC 9114 §4.1）。
    trailers_seen: bool,
    /// 首个协议/语义错误：一旦置位，后续解析停止并由调用方提前失败。
    failed: Option<String>,
}

impl H3Response {
    fn new() -> Self {
        H3Response {
            buf: Vec::new(),
            status: None,
            content_type: None,
            content_length: None,
            body: Vec::new(),
            headers_seen: false,
            trailers_seen: false,
            failed: None,
        }
    }

    /// 追加收到的字节并解析所有完整帧。幂等可重入（可逐字节喂）。
    ///
    /// **缓冲只保留"未完整到达的帧"**：完整帧逐帧处理并立即从缓冲区头部回收。
    /// 旧实现把「已消费位置」`pos` 一同保留，并在 `pos >= 16KiB` 时 `drain(..pos)`——
    /// 当 `pos` 停在一个**跨读未收齐**的帧头之后（`h3_frame_at` 返回 Incomplete，帧头
    /// 已被算进 `pos`）时，该帧的字节会被整段丢弃，后续解析从半截帧开始，永久 desync。
    /// 实测：服务端把 HEADERS 与 DATA 拆到不同 QUIC 包（Quad9/Google 等非阿里 DoH3）
    /// 时 100% 触发；阿里 DoH3 把两帧塞进同一个包，故只有它"看起来正常"。
    fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
        loop {
            if self.failed.is_some() {
                return;
            }
            // 帧头可能跨读到达：此时保留整个未成帧前缀，等下一次 feed 补齐。
            let (ftype, start, end) = match h3_frame_at(&self.buf, 0) {
                H3FrameAt::Frame(t, s, e) => (t, s, e),
                H3FrameAt::Incomplete => break,
                H3FrameAt::TooLarge => {
                    self.failed = Some("doh3 oversized frame".to_string());
                    return;
                }
            };
            // 先取出载荷副本再回收：解析函数需要 &mut self，避免同时借用 buf。
            let payload = self.buf[start..end].to_vec();
            // 帧已完整（`end <= buf.len()` 由 h3_frame_at 保证）→ 整帧（含帧头）可安全回收。
            self.buf.drain(..end);
            self.handle_frame(ftype, &payload);
        }
    }

    /// 处理一个完整帧。未知/保留帧按 RFC 9114 §7.2.8、§9 忽略。
    fn handle_frame(&mut self, ftype: u64, payload: &[u8]) {
        match ftype {
            H3_FRAME_HEADERS => self.handle_headers(payload),
            H3_FRAME_DATA => {
                if !self.headers_seen || self.trailers_seen {
                    // RFC 9114 §4.1：HEADERS 之前的 DATA、尾字段段之后的 DATA 均非法。
                    self.failed = Some("doh3 unexpected DATA frame".to_string());
                    return;
                }
                if self.body.len() + payload.len() > H3_MAX_BODY {
                    self.failed = Some("doh3 response body too large".to_string());
                    return;
                }
                self.body.extend_from_slice(payload);
            }
            // GOAWAY 只允许出现在控制流上（RFC 9114 §7.2.6），请求流收到即为协议错误。
            H3_FRAME_GOAWAY => self.failed = Some("doh3 server goaway".to_string()),
            // 我们从不发 MAX_PUSH_ID，服务端不得推送（RFC 9114 §4.6），收到即协议错误。
            H3_FRAME_PUSH_PROMISE => self.failed = Some("doh3 unexpected push_promise".to_string()),
            _ => {}
        }
    }

    /// 解码 HEADERS 载荷（QPACK 字段段）并提取关心的字段。
    fn handle_headers(&mut self, payload: &[u8]) {
        if self.headers_seen {
            // 先取副本再匹配：避免在匹配臂内改写 self 字段时的借用冲突。
            let prev_status = self.status;
            match prev_status {
                // 1xx 中间响应（RFC 9114 §4.1）之后是最终响应：重置本条消息的状态。
                Some(code) if code < 200 => {
                    self.status = None;
                    self.content_type = None;
                    self.content_length = None;
                    self.body.clear();
                    self.trailers_seen = false;
                }
                // 已有最终响应：本段只能是尾字段段，其后不允许再出现 DATA，也不允许伪头。
                Some(_) => self.trailers_seen = true,
                None => {}
            }
        }
        self.headers_seen = true;

        let fields = match qpack_decode_field_section(payload) {
            Ok(f) => f,
            Err(e) => {
                self.failed = Some(e);
                return;
            }
        };
        for (name, value) in fields {
            let name = name.as_slice();
            if name == b":status" {
                if self.status.is_some() {
                    // 同一字段段内重复伪头（RFC 9114 §4.3.2）→ 拒绝，避免 last-wins 被利用。
                    self.failed = Some("doh3 duplicate :status".to_string());
                    return;
                }
                let parsed = std::str::from_utf8(&value)
                    .ok()
                    .and_then(|s| s.trim().parse::<u16>().ok());
                match parsed {
                    Some(code) => self.status = Some(code),
                    None => {
                        self.failed = Some("doh3 bad :status".to_string());
                        return;
                    }
                }
            } else if name == b"content-type" {
                self.content_type = Some(String::from_utf8_lossy(&value).to_ascii_lowercase());
            } else if name == b"content-length" {
                let parsed = std::str::from_utf8(&value)
                    .ok()
                    .and_then(|s| s.trim().parse::<usize>().ok());
                match parsed {
                    Some(n) => self.content_length = Some(n),
                    None => {
                        self.failed = Some("doh3 bad content-length".to_string());
                        return;
                    }
                }
            }
        }
    }

    /// 已按 `content-length` 收齐？无 `content-length` 时恒 false（以 FIN/EOF 为准）。
    fn is_complete(&self) -> bool {
        self.content_length.is_some_and(|n| self.body.len() >= n)
    }

    /// 在读循环中检查的即时错误（读到即提前失败）。
    fn error(&self) -> Option<String> {
        self.failed.clone()
    }

    /// 收尾校验并取出 DNS 报文。校验顺序：协议错误 → `:status==200` →
    /// `content-type` 含 `application/dns-message` → 正文完整（有 `content-length` 时按其长度截取）。
    fn finish(&mut self) -> Result<Vec<u8>, String> {
        if let Some(e) = self.failed.take() {
            return Err(e);
        }
        match self.status {
            Some(200) => {}
            Some(code) => return Err(format!("doh3 http status {code}")),
            None => return Err("doh3 missing :status".to_string()),
        }
        let ctype = self.content_type.clone().unwrap_or_default();
        if !ctype.contains("application/dns-message") {
            return Err("doh3 bad content-type".to_string());
        }
        match self.content_length {
            Some(n) => {
                if self.body.len() < n {
                    return Err("doh3 truncated body".to_string());
                }
                Ok(self.body[..n].to_vec())
            }
            None => {
                if self.body.is_empty() {
                    return Err("doh3 empty body".to_string());
                }
                Ok(std::mem::take(&mut self.body))
            }
        }
    }
}

// ==================== QPACK（RFC 9204）静态表子集实现 ====================

/// RFC 9204 附录 A 静态表（99 项，索引自 0 起）。**顺序即索引，改动即破坏协议**。
/// 注意与任务描述里的索引提示不同：`:method POST`=20、`:scheme https`=23、`:status 200`=25、
/// `:path /`=1（静态表没有 `/dns-query`）、`accept`=29/30、`content-type`=44（31 是
/// `accept-encoding`）、`user-agent`=95。索引取自 pylsqpack（aioquic 所用 lsqpack）实测导出。
#[rustfmt::skip]
const QPACK_STATIC_TABLE: [(&[u8], &[u8]); 99] = [
    (b":authority".as_slice(), b"".as_slice()),                                    // 0
    (b":path".as_slice(), b"/".as_slice()),                                        // 1
    (b"age".as_slice(), b"0".as_slice()),                                          // 2
    (b"content-disposition".as_slice(), b"".as_slice()),                           // 3
    (b"content-length".as_slice(), b"0".as_slice()),                               // 4
    (b"cookie".as_slice(), b"".as_slice()),                                        // 5
    (b"date".as_slice(), b"".as_slice()),                                          // 6
    (b"etag".as_slice(), b"".as_slice()),                                          // 7
    (b"if-modified-since".as_slice(), b"".as_slice()),                             // 8
    (b"if-none-match".as_slice(), b"".as_slice()),                                 // 9
    (b"last-modified".as_slice(), b"".as_slice()),                                 // 10
    (b"link".as_slice(), b"".as_slice()),                                          // 11
    (b"location".as_slice(), b"".as_slice()),                                      // 12
    (b"referer".as_slice(), b"".as_slice()),                                       // 13
    (b"set-cookie".as_slice(), b"".as_slice()),                                    // 14
    (b":method".as_slice(), b"CONNECT".as_slice()),                                // 15
    (b":method".as_slice(), b"DELETE".as_slice()),                                 // 16
    (b":method".as_slice(), b"GET".as_slice()),                                    // 17
    (b":method".as_slice(), b"HEAD".as_slice()),                                   // 18
    (b":method".as_slice(), b"OPTIONS".as_slice()),                                // 19
    (b":method".as_slice(), b"POST".as_slice()),                                   // 20
    (b":method".as_slice(), b"PUT".as_slice()),                                    // 21
    (b":scheme".as_slice(), b"http".as_slice()),                                   // 22
    (b":scheme".as_slice(), b"https".as_slice()),                                  // 23
    (b":status".as_slice(), b"103".as_slice()),                                    // 24
    (b":status".as_slice(), b"200".as_slice()),                                    // 25
    (b":status".as_slice(), b"304".as_slice()),                                    // 26
    (b":status".as_slice(), b"404".as_slice()),                                    // 27
    (b":status".as_slice(), b"503".as_slice()),                                    // 28
    (b"accept".as_slice(), b"*/*".as_slice()),                                     // 29
    (b"accept".as_slice(), b"application/dns-message".as_slice()),                 // 30
    (b"accept-encoding".as_slice(), b"gzip, deflate, br".as_slice()),              // 31
    (b"accept-ranges".as_slice(), b"bytes".as_slice()),                            // 32
    (b"access-control-allow-headers".as_slice(), b"cache-control".as_slice()),     // 33
    (b"access-control-allow-headers".as_slice(), b"content-type".as_slice()),      // 34
    (b"access-control-allow-origin".as_slice(), b"*".as_slice()),                  // 35
    (b"cache-control".as_slice(), b"max-age=0".as_slice()),                        // 36
    (b"cache-control".as_slice(), b"max-age=2592000".as_slice()),                  // 37
    (b"cache-control".as_slice(), b"max-age=604800".as_slice()),                   // 38
    (b"cache-control".as_slice(), b"no-cache".as_slice()),                         // 39
    (b"cache-control".as_slice(), b"no-store".as_slice()),                         // 40
    (b"cache-control".as_slice(), b"public, max-age=31536000".as_slice()),         // 41
    (b"content-encoding".as_slice(), b"br".as_slice()),                            // 42
    (b"content-encoding".as_slice(), b"gzip".as_slice()),                          // 43
    (b"content-type".as_slice(), b"application/dns-message".as_slice()),           // 44
    (b"content-type".as_slice(), b"application/javascript".as_slice()),            // 45
    (b"content-type".as_slice(), b"application/json".as_slice()),                  // 46
    (b"content-type".as_slice(), b"application/x-www-form-urlencoded".as_slice()), // 47
    (b"content-type".as_slice(), b"image/gif".as_slice()),                         // 48
    (b"content-type".as_slice(), b"image/jpeg".as_slice()),                        // 49
    (b"content-type".as_slice(), b"image/png".as_slice()),                         // 50
    (b"content-type".as_slice(), b"text/css".as_slice()),                          // 51
    (b"content-type".as_slice(), b"text/html; charset=utf-8".as_slice()),          // 52
    (b"content-type".as_slice(), b"text/plain".as_slice()),                        // 53
    (b"content-type".as_slice(), b"text/plain;charset=utf-8".as_slice()),          // 54
    (b"range".as_slice(), b"bytes=0-".as_slice()),                                 // 55
    (b"strict-transport-security".as_slice(), b"max-age=31536000".as_slice()),     // 56
    (b"strict-transport-security".as_slice(), b"max-age=31536000; includesubdomains".as_slice()), // 57
    (b"strict-transport-security".as_slice(), b"max-age=31536000; includesubdomains; preload".as_slice()), // 58
    (b"vary".as_slice(), b"accept-encoding".as_slice()),                           // 59
    (b"vary".as_slice(), b"origin".as_slice()),                                    // 60
    (b"x-content-type-options".as_slice(), b"nosniff".as_slice()),                 // 61
    (b"x-xss-protection".as_slice(), b"1; mode=block".as_slice()),                 // 62
    (b":status".as_slice(), b"100".as_slice()),                                    // 63
    (b":status".as_slice(), b"204".as_slice()),                                    // 64
    (b":status".as_slice(), b"206".as_slice()),                                    // 65
    (b":status".as_slice(), b"302".as_slice()),                                    // 66
    (b":status".as_slice(), b"400".as_slice()),                                    // 67
    (b":status".as_slice(), b"403".as_slice()),                                    // 68
    (b":status".as_slice(), b"421".as_slice()),                                    // 69
    (b":status".as_slice(), b"425".as_slice()),                                    // 70
    (b":status".as_slice(), b"500".as_slice()),                                    // 71
    (b"accept-language".as_slice(), b"".as_slice()),                               // 72
    (b"access-control-allow-credentials".as_slice(), b"FALSE".as_slice()),         // 73
    (b"access-control-allow-credentials".as_slice(), b"TRUE".as_slice()),          // 74
    (b"access-control-allow-headers".as_slice(), b"*".as_slice()),                 // 75
    (b"access-control-allow-methods".as_slice(), b"get".as_slice()),               // 76
    (b"access-control-allow-methods".as_slice(), b"get, post, options".as_slice()), // 77
    (b"access-control-allow-methods".as_slice(), b"options".as_slice()),           // 78
    (b"access-control-expose-headers".as_slice(), b"content-length".as_slice()),   // 79
    (b"access-control-request-headers".as_slice(), b"content-type".as_slice()),    // 80
    (b"access-control-request-method".as_slice(), b"get".as_slice()),              // 81
    (b"access-control-request-method".as_slice(), b"post".as_slice()),             // 82
    (b"alt-svc".as_slice(), b"clear".as_slice()),                                  // 83
    (b"authorization".as_slice(), b"".as_slice()),                                 // 84
    (b"content-security-policy".as_slice(), b"script-src 'none'; object-src 'none'; base-uri 'none'".as_slice()), // 85
    (b"early-data".as_slice(), b"1".as_slice()),                                   // 86
    (b"expect-ct".as_slice(), b"".as_slice()),                                     // 87
    (b"forwarded".as_slice(), b"".as_slice()),                                     // 88
    (b"if-range".as_slice(), b"".as_slice()),                                      // 89
    (b"origin".as_slice(), b"".as_slice()),                                        // 90
    (b"purpose".as_slice(), b"prefetch".as_slice()),                               // 91
    (b"server".as_slice(), b"".as_slice()),                                        // 92
    (b"timing-allow-origin".as_slice(), b"*".as_slice()),                          // 93
    (b"upgrade-insecure-requests".as_slice(), b"1".as_slice()),                    // 94
    (b"user-agent".as_slice(), b"".as_slice()),                                    // 95
    (b"x-forwarded-for".as_slice(), b"".as_slice()),                               // 96
    (b"x-frame-options".as_slice(), b"deny".as_slice()),                           // 97
    (b"x-frame-options".as_slice(), b"sameorigin".as_slice()),                     // 98
];

/// 静态表查表（0 起）。越界返回 None，调用方按 QPACK_DECOMPRESSION_FAILED 处理。
fn qpack_static(idx: u64) -> Option<(&'static [u8], &'static [u8])> {
    QPACK_STATIC_TABLE.get(idx as usize).copied()
}

/// 前缀整数编码（RFC 9204 §4.1.1 = RFC 7541 §5.1）：`prefix_bits` 位前缀，高位固定为 `pattern`。
fn qpack_int(out: &mut Vec<u8>, prefix_bits: u8, pattern: u8, value: u64) {
    let max = (1u64 << prefix_bits) - 1;
    if value < max {
        out.push(pattern | value as u8);
        return;
    }
    out.push(pattern | max as u8);
    let mut rest = value - max;
    while rest >= 128 {
        out.push((rest % 128) as u8 | 0x80);
        rest /= 128;
    }
    out.push(rest as u8);
}

/// 字符串字面量（8 位前缀，H=0 不做 Huffman；RFC 9204 §4.1.2）。
/// 请求侧不做 Huffman：体积略大但无需内嵌 Huffman 编码器，且完全合规。
fn qpack_str(out: &mut Vec<u8>, s: &[u8]) {
    qpack_int(out, 7, 0x00, s.len() as u64);
    out.extend_from_slice(s);
}

/// 精确 (name, value) 命中静态表 → 索引（RFC 9204 附录 C 参考算法的第一步）。
fn qpack_exact_index(name: &[u8], value: &[u8]) -> Option<u64> {
    QPACK_STATIC_TABLE
        .iter()
        .position(|(n, v)| *n == name && *v == value)
        .map(|i| i as u64)
}

/// 仅 name 命中静态表（取最小索引）→ 名字引用索引。
fn qpack_name_index(name: &[u8]) -> Option<u64> {
    QPACK_STATIC_TABLE
        .iter()
        .position(|(n, _)| *n == name)
        .map(|i| i as u64)
}

/// 编码一个字段行（RFC 9204 §4.5）：
/// 1. 精确命中静态表 → Indexed Field Line `1 T=1 Index(6+)`（§4.5.2）；
/// 2. 仅名字命中 → Literal Field Line with Name Reference `01 N=0 T=1 Index(4+)` + 值字符串（§4.5.4）；
/// 3. 都未命中 → Literal Field Line with Literal Name `001 N=0 H=0 NameLen(3+)` + 名 + 值（§4.5.6）。
///
/// 三种形态都写出完整值；第 2/3 种是任务要求的"字面量带名字引用/不带名字引用"编码，
/// 因此 `:authority` 之类不可能出现空值（旧实现固定写 `host = ""`）。
fn qpack_encode_field(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    if let Some(idx) = qpack_exact_index(name, value) {
        qpack_int(out, 6, 0xC0, idx);
        return;
    }
    if let Some(idx) = qpack_name_index(name) {
        // 0x40 是 '01' 前缀；bit5=N=0（允许中间设备再压缩）；bit4=T=1（静态表）。
        qpack_int(out, 4, 0x50, idx);
        qpack_str(out, value);
        return;
    }
    // '001' 前缀 + N=0 + H=0，随后是 3 位前缀的名字长度。
    qpack_int(out, 3, 0x20, name.len() as u64);
    out.extend_from_slice(name);
    qpack_str(out, value);
}

/// **[历史归因]** `:authority` 值：`host:port`；IPv6 字面量补方括号（对齐 Python `_doh3_exchange`）。
fn h3_authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// DoH3 请求字段段（含 RFC 9204 §4.5.1 字段段前缀）：
/// `:method POST` / `:scheme https` / `:authority` / `:path` / `content-type` /
/// `content-length` / `accept` / `user-agent`，伪头在前（RFC 9114 §4.3）。
///
/// 前缀：Required Insert Count=0（不使用动态表）+ Delta Base=0 → 两字节 `00 00`。
/// 缺这个前缀会让合规解码器直接 QPACK_DECOMPRESSION_FAILED（旧实现即缺此前缀）。
fn qpack_encode_request(host: &str, port: u16, path: &str, body_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(160);
    qpack_int(&mut out, 8, 0x00, 0); // Required Insert Count = 0（8 位前缀）
    qpack_int(&mut out, 7, 0x00, 0); // Delta Base = 0（7 位前缀，符号位 0）
    qpack_encode_field(&mut out, b":method", b"POST");
    qpack_encode_field(&mut out, b":scheme", b"https");
    let authority = h3_authority(host, port);
    qpack_encode_field(&mut out, b":authority", authority.as_bytes());
    qpack_encode_field(&mut out, b":path", path.as_bytes());
    qpack_encode_field(&mut out, b"content-type", b"application/dns-message");
    let len = body_len.to_string();
    qpack_encode_field(&mut out, b"content-length", len.as_bytes());
    qpack_encode_field(&mut out, b"accept", b"application/dns-message");
    qpack_encode_field(&mut out, b"user-agent", H3_USER_AGENT);
    out
}

/// 读前缀整数（RFC 9204 §4.1.1）。返回 `(值, 下一个字节位置)`；截断/溢出 → Err。
fn qpack_read_int(buf: &[u8], pos: usize, prefix_bits: u8) -> Result<(u64, usize), String> {
    let prefix_bits = prefix_bits.clamp(1, 8);
    let max = (1u64 << prefix_bits) - 1;
    let first = *buf.get(pos).ok_or("qpack: truncated integer")?;
    let mut value = (first as u64) & max;
    let mut i = pos + 1;
    if value < max {
        return Ok((value, i));
    }
    let mut shift = 0u32;
    loop {
        let b = *buf.get(i).ok_or("qpack: truncated integer")?;
        i += 1;
        if shift > 56 {
            return Err("qpack: integer overflow".to_string());
        }
        value += ((b & 0x7F) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok((value, i));
        }
    }
}

/// 读 "N 位前缀字符串字面量"（RFC 9204 §4.1.2）：H 标志 + (N-1) 位长度前缀 + 字节。
/// `n_bits = 8` 用于字段值与 §4.5.4 的值；`n_bits = 4` 用于 §4.5.6 的字段名。
fn qpack_read_str(buf: &[u8], pos: usize, n_bits: u8) -> Result<(Vec<u8>, usize), String> {
    let first = *buf.get(pos).ok_or("qpack: truncated string")?;
    let huffman = first & (1u8 << (n_bits - 1)) != 0;
    let (len, mut i) = qpack_read_int(buf, pos, n_bits - 1)?;
    let len = len as usize;
    if len > buf.len().saturating_sub(i) {
        return Err("qpack: truncated string".to_string());
    }
    let raw = &buf[i..i + len];
    i += len;
    if huffman {
        Ok((huffman_decode(raw)?, i))
    } else {
        Ok((raw.to_vec(), i))
    }
}

/// 解码字段段（RFC 9204 §4.5）。
///
/// 支持：字段段前缀、Indexed Field Line（T=1）、Literal with Name Reference（T=1）、
/// Literal with Literal Name（含 Huffman 名/值）。
/// 拒绝：任何动态表引用（RIC≠0、T=0、`0001`/`0000` 后基形态）——我们 SETTINGS 声明
/// `QPACK_MAX_TABLE_CAPACITY=0`，合规服务端不可能引用动态表（RFC 9204 §3.2.3），
/// 遇到即按解码失败处理（fail-safe，不猜测表内容）。
/// **2.1.21 第 2 轮（clippy `type_complexity`）**：QPACK 字段段解出的 (name, value) 列表。
type QpackFields = Vec<(Vec<u8>, Vec<u8>)>;

fn qpack_decode_field_section(block: &[u8]) -> Result<QpackFields, String> {
    let (ric, mut i) = qpack_read_int(block, 0, 8)?;
    let (_delta_base, next) = qpack_read_int(block, i, 7)?;
    i = next;
    if ric != 0 {
        return Err("qpack: dynamic table reference".to_string());
    }
    let mut fields: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    while i < block.len() {
        let b = block[i];
        if b & 0x80 != 0 {
            // Indexed Field Line：1 T Index(6+)
            let static_ref = b & 0x40 != 0;
            let (idx, next) = qpack_read_int(block, i, 6)?;
            i = next;
            if !static_ref {
                return Err("qpack: dynamic index reference".to_string());
            }
            let (name, value) = qpack_static(idx).ok_or("qpack: invalid static index")?;
            fields.push((name.to_vec(), value.to_vec()));
        } else if b & 0x40 != 0 {
            // Literal Field Line with Name Reference：01 N T NameIndex(4+)
            let static_ref = b & 0x10 != 0;
            let (idx, next) = qpack_read_int(block, i, 4)?;
            i = next;
            if !static_ref {
                return Err("qpack: dynamic name reference".to_string());
            }
            let (name, _) = qpack_static(idx).ok_or("qpack: invalid static index")?;
            let name = name.to_vec();
            let (value, next) = qpack_read_str(block, i, 8)?;
            i = next;
            fields.push((name, value));
        } else if b & 0x20 != 0 {
            // Literal Field Line with Literal Name：001 N H NameLen(3+) + 名 + 值
            let (name, next) = qpack_read_str(block, i, 4)?;
            i = next;
            let (value, next) = qpack_read_str(block, i, 8)?;
            i = next;
            fields.push((name, value));
        } else {
            // `0001` 后基索引 / `0000` 后基名字引用：都是动态表引用。
            return Err("qpack: post-base dynamic reference".to_string());
        }
    }
    Ok(fields)
}

// ==================== 规范 Huffman 解码（RFC 7541 附录 B，RFC 9204 §4.1.2 复用） ====================

/// 规范 Huffman 码表：`(码字, 位长, 符号)`，按 `(位长, 码字)` 升序，供二分查找。
/// 符号 0..=255 对应字节值，256 = EOS。表内容由 pylsqpack（lsqpack）逐符号交叉验证。
#[rustfmt::skip]
const HUFFMAN_TABLE: [(u32, u8, u16); 257] = [
    (0x00000000,  5,  48), (0x00000001,  5,  49), (0x00000002,  5,  50), (0x00000003,  5,  97),
    (0x00000004,  5,  99), (0x00000005,  5, 101), (0x00000006,  5, 105), (0x00000007,  5, 111),
    (0x00000008,  5, 115), (0x00000009,  5, 116), (0x00000014,  6,  32), (0x00000015,  6,  37),
    (0x00000016,  6,  45), (0x00000017,  6,  46), (0x00000018,  6,  47), (0x00000019,  6,  51),
    (0x0000001a,  6,  52), (0x0000001b,  6,  53), (0x0000001c,  6,  54), (0x0000001d,  6,  55),
    (0x0000001e,  6,  56), (0x0000001f,  6,  57), (0x00000020,  6,  61), (0x00000021,  6,  65),
    (0x00000022,  6,  95), (0x00000023,  6,  98), (0x00000024,  6, 100), (0x00000025,  6, 102),
    (0x00000026,  6, 103), (0x00000027,  6, 104), (0x00000028,  6, 108), (0x00000029,  6, 109),
    (0x0000002a,  6, 110), (0x0000002b,  6, 112), (0x0000002c,  6, 114), (0x0000002d,  6, 117),
    (0x0000005c,  7,  58), (0x0000005d,  7,  66), (0x0000005e,  7,  67), (0x0000005f,  7,  68),
    (0x00000060,  7,  69), (0x00000061,  7,  70), (0x00000062,  7,  71), (0x00000063,  7,  72),
    (0x00000064,  7,  73), (0x00000065,  7,  74), (0x00000066,  7,  75), (0x00000067,  7,  76),
    (0x00000068,  7,  77), (0x00000069,  7,  78), (0x0000006a,  7,  79), (0x0000006b,  7,  80),
    (0x0000006c,  7,  81), (0x0000006d,  7,  82), (0x0000006e,  7,  83), (0x0000006f,  7,  84),
    (0x00000070,  7,  85), (0x00000071,  7,  86), (0x00000072,  7,  87), (0x00000073,  7,  89),
    (0x00000074,  7, 106), (0x00000075,  7, 107), (0x00000076,  7, 113), (0x00000077,  7, 118),
    (0x00000078,  7, 119), (0x00000079,  7, 120), (0x0000007a,  7, 121), (0x0000007b,  7, 122),
    (0x000000f8,  8,  38), (0x000000f9,  8,  42), (0x000000fa,  8,  44), (0x000000fb,  8,  59),
    (0x000000fc,  8,  88), (0x000000fd,  8,  90), (0x000003f8, 10,  33), (0x000003f9, 10,  34),
    (0x000003fa, 10,  40), (0x000003fb, 10,  41), (0x000003fc, 10,  63), (0x000007fa, 11,  39),
    (0x000007fb, 11,  43), (0x000007fc, 11, 124), (0x00000ffa, 12,  35), (0x00000ffb, 12,  62),
    (0x00001ff8, 13,   0), (0x00001ff9, 13,  36), (0x00001ffa, 13,  64), (0x00001ffb, 13,  91),
    (0x00001ffc, 13,  93), (0x00001ffd, 13, 126), (0x00003ffc, 14,  94), (0x00003ffd, 14, 125),
    (0x00007ffc, 15,  60), (0x00007ffd, 15,  96), (0x00007ffe, 15, 123), (0x0007fff0, 19,  92),
    (0x0007fff1, 19, 195), (0x0007fff2, 19, 208), (0x000fffe6, 20, 128), (0x000fffe7, 20, 130),
    (0x000fffe8, 20, 131), (0x000fffe9, 20, 162), (0x000fffea, 20, 184), (0x000fffeb, 20, 194),
    (0x000fffec, 20, 224), (0x000fffed, 20, 226), (0x001fffdc, 21, 153), (0x001fffdd, 21, 161),
    (0x001fffde, 21, 167), (0x001fffdf, 21, 172), (0x001fffe0, 21, 176), (0x001fffe1, 21, 177),
    (0x001fffe2, 21, 179), (0x001fffe3, 21, 209), (0x001fffe4, 21, 216), (0x001fffe5, 21, 217),
    (0x001fffe6, 21, 227), (0x001fffe7, 21, 229), (0x001fffe8, 21, 230), (0x003fffd2, 22, 129),
    (0x003fffd3, 22, 132), (0x003fffd4, 22, 133), (0x003fffd5, 22, 134), (0x003fffd6, 22, 136),
    (0x003fffd7, 22, 146), (0x003fffd8, 22, 154), (0x003fffd9, 22, 156), (0x003fffda, 22, 160),
    (0x003fffdb, 22, 163), (0x003fffdc, 22, 164), (0x003fffdd, 22, 169), (0x003fffde, 22, 170),
    (0x003fffdf, 22, 173), (0x003fffe0, 22, 178), (0x003fffe1, 22, 181), (0x003fffe2, 22, 185),
    (0x003fffe3, 22, 186), (0x003fffe4, 22, 187), (0x003fffe5, 22, 189), (0x003fffe6, 22, 190),
    (0x003fffe7, 22, 196), (0x003fffe8, 22, 198), (0x003fffe9, 22, 228), (0x003fffea, 22, 232),
    (0x003fffeb, 22, 233), (0x007fffd8, 23,   1), (0x007fffd9, 23, 135), (0x007fffda, 23, 137),
    (0x007fffdb, 23, 138), (0x007fffdc, 23, 139), (0x007fffdd, 23, 140), (0x007fffde, 23, 141),
    (0x007fffdf, 23, 143), (0x007fffe0, 23, 147), (0x007fffe1, 23, 149), (0x007fffe2, 23, 150),
    (0x007fffe3, 23, 151), (0x007fffe4, 23, 152), (0x007fffe5, 23, 155), (0x007fffe6, 23, 157),
    (0x007fffe7, 23, 158), (0x007fffe8, 23, 165), (0x007fffe9, 23, 166), (0x007fffea, 23, 168),
    (0x007fffeb, 23, 174), (0x007fffec, 23, 175), (0x007fffed, 23, 180), (0x007fffee, 23, 182),
    (0x007fffef, 23, 183), (0x007ffff0, 23, 188), (0x007ffff1, 23, 191), (0x007ffff2, 23, 197),
    (0x007ffff3, 23, 231), (0x007ffff4, 23, 239), (0x00ffffea, 24,   9), (0x00ffffeb, 24, 142),
    (0x00ffffec, 24, 144), (0x00ffffed, 24, 145), (0x00ffffee, 24, 148), (0x00ffffef, 24, 159),
    (0x00fffff0, 24, 171), (0x00fffff1, 24, 206), (0x00fffff2, 24, 215), (0x00fffff3, 24, 225),
    (0x00fffff4, 24, 236), (0x00fffff5, 24, 237), (0x01ffffec, 25, 199), (0x01ffffed, 25, 207),
    (0x01ffffee, 25, 234), (0x01ffffef, 25, 235), (0x03ffffe0, 26, 192), (0x03ffffe1, 26, 193),
    (0x03ffffe2, 26, 200), (0x03ffffe3, 26, 201), (0x03ffffe4, 26, 202), (0x03ffffe5, 26, 205),
    (0x03ffffe6, 26, 210), (0x03ffffe7, 26, 213), (0x03ffffe8, 26, 218), (0x03ffffe9, 26, 219),
    (0x03ffffea, 26, 238), (0x03ffffeb, 26, 240), (0x03ffffec, 26, 242), (0x03ffffed, 26, 243),
    (0x03ffffee, 26, 255), (0x07ffffde, 27, 203), (0x07ffffdf, 27, 204), (0x07ffffe0, 27, 211),
    (0x07ffffe1, 27, 212), (0x07ffffe2, 27, 214), (0x07ffffe3, 27, 221), (0x07ffffe4, 27, 222),
    (0x07ffffe5, 27, 223), (0x07ffffe6, 27, 241), (0x07ffffe7, 27, 244), (0x07ffffe8, 27, 245),
    (0x07ffffe9, 27, 246), (0x07ffffea, 27, 247), (0x07ffffeb, 27, 248), (0x07ffffec, 27, 250),
    (0x07ffffed, 27, 251), (0x07ffffee, 27, 252), (0x07ffffef, 27, 253), (0x07fffff0, 27, 254),
    (0x0fffffe2, 28,   2), (0x0fffffe3, 28,   3), (0x0fffffe4, 28,   4), (0x0fffffe5, 28,   5),
    (0x0fffffe6, 28,   6), (0x0fffffe7, 28,   7), (0x0fffffe8, 28,   8), (0x0fffffe9, 28,  11),
    (0x0fffffea, 28,  12), (0x0fffffeb, 28,  14), (0x0fffffec, 28,  15), (0x0fffffed, 28,  16),
    (0x0fffffee, 28,  17), (0x0fffffef, 28,  18), (0x0ffffff0, 28,  19), (0x0ffffff1, 28,  20),
    (0x0ffffff2, 28,  21), (0x0ffffff3, 28,  23), (0x0ffffff4, 28,  24), (0x0ffffff5, 28,  25),
    (0x0ffffff6, 28,  26), (0x0ffffff7, 28,  27), (0x0ffffff8, 28,  28), (0x0ffffff9, 28,  29),
    (0x0ffffffa, 28,  30), (0x0ffffffb, 28,  31), (0x0ffffffc, 28, 127), (0x0ffffffd, 28, 220),
    (0x0ffffffe, 28, 249), (0x3ffffffc, 30,  10), (0x3ffffffd, 30,  13), (0x3ffffffe, 30,  22),
    (0x3fffffff, 30, 256),
];

/// 按 `(位长, 码字)` 二分查找符号。
fn huffman_lookup(bits: u8, code: u32) -> Option<u16> {
    HUFFMAN_TABLE
        .binary_search_by(|probe| probe.1.cmp(&bits).then(probe.0.cmp(&code)))
        .ok()
        .map(|i| HUFFMAN_TABLE[i].2)
}

/// 规范 Huffman 解码。
///
/// 码表是前缀无关的，故"从最短位数开始找第一个匹配"即唯一解；末尾必须是
/// **不超过 7 位的全 1 填充**（RFC 7541 §5.2），任何 EOS(256) 或超长/含 0 的填充都判错。
fn huffman_decode(src: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(src.len());
    let mut acc: u64 = 0;
    let mut nbits: u32 = 0;
    for &byte in src {
        acc = (acc << 8) | byte as u64;
        nbits += 8;
        loop {
            let mut hit: Option<(u32, u16)> = None;
            let max_len = nbits.min(30);
            let mut len = 5u32; // 最短码长 5 位，最长 30 位
            while len <= max_len {
                let code = ((acc >> (nbits - len)) & ((1u64 << len) - 1)) as u32;
                if let Some(sym) = huffman_lookup(len as u8, code) {
                    hit = Some((len, sym));
                    break;
                }
                len += 1;
            }
            match hit {
                Some((len, sym)) => {
                    if sym > u8::MAX as u16 {
                        return Err("qpack: huffman EOS".to_string());
                    }
                    out.push(sym as u8);
                    nbits -= len;
                    acc &= if nbits == 0 { 0 } else { (1u64 << nbits) - 1 };
                }
                None => break, // 位不够或已到填充区
            }
        }
    }
    if nbits >= 8 || (nbits > 0 && acc != (1u64 << nbits) - 1) {
        return Err("qpack: huffman invalid padding".to_string());
    }
    Ok(out)
}

fn encode_varint(v: u64) -> Vec<u8> {
    if v < 1 << 6 {
        vec![v as u8]
    } else if v < 1 << 14 {
        let mut b = v.to_be_bytes();
        let _ = &mut b;
        let out = vec![0x40 | (v >> 8) as u8, v as u8];
        out
    } else if v < 1 << 30 {
        vec![
            0x80 | (v >> 24) as u8,
            (v >> 16) as u8,
            (v >> 8) as u8,
            v as u8,
        ]
    } else {
        // 8 字节形式（RFC 9000 §16）：首字节 = 0xC0 | 值的高 6 位，其后跟低 7 字节。
        // 旧实现写 `[0xC0] + v.to_be_bytes()`（共 9 字节）→ 解码端只读 8 字节，
        // 结果等价于把 v 左移 8 位（v≥2^30 时全错）。
        let b = v.to_be_bytes();
        let mut out = Vec::with_capacity(8);
        out.push(0xC0 | (b[0] & 0x3F));
        out.extend_from_slice(&b[1..]);
        out
    }
}

fn decode_varint(buf: &[u8]) -> Option<(u64, &[u8])> {
    if buf.is_empty() {
        return None;
    }
    let first = buf[0];
    let prefix = first >> 6;
    let len = 1usize << prefix;
    if buf.len() < len {
        return None;
    }
    let val = match len {
        1 => (first & 0x3F) as u64,
        2 => u16::from_be_bytes([first & 0x3F, buf[1]]) as u64,
        4 => u32::from_be_bytes([first & 0x3F, buf[1], buf[2], buf[3]]) as u64,
        _ => u64::from_be_bytes([
            first & 0x3F,
            buf[1],
            buf[2],
            buf[3],
            buf[4],
            buf[5],
            buf[6],
            buf[7],
        ]),
    };
    Some((val, &buf[len..]))
}

// 旧的"最小 QPACK 编码/解码"（:authority 空值、缺字段段前缀、静态表索引错位）
// 已由上面的 qpack_encode_request / qpack_decode_field_section 取代。

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------ 测试工具

    /// 十六进制串 → 字节（测试自足，不引第三方依赖）。
    fn unhex(s: &str) -> Vec<u8> {
        let b = s.as_bytes();
        assert_eq!(b.len() % 2, 0, "hex length");
        (0..b.len() / 2)
            .map(|i| {
                let hi = (b[2 * i] as char).to_digit(16).expect("hex") as u8;
                let lo = (b[2 * i + 1] as char).to_digit(16).expect("hex") as u8;
                (hi << 4) | lo
            })
            .collect()
    }

    /// 组装一个 HTTP/3 帧（与 h3_write_frame 同构）。
    fn frame(ftype: u64, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        h3_write_frame(&mut out, ftype, payload);
        out
    }

    /// 用静态表编码一个最小字段段（含 RFC 9204 §4.5.1 前缀），供解析测试构造输入。
    fn field_section(fields: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        qpack_int(&mut out, 8, 0x00, 0);
        qpack_int(&mut out, 7, 0x00, 0);
        for (name, value) in fields {
            qpack_encode_field(&mut out, name, value);
        }
        out
    }

    /// 单个字节的规范 Huffman 编码（左对齐 + 1 填充），用于解码器回环测试。
    fn huffman_encode_byte(sym: u8) -> Vec<u8> {
        let (code, bits) = HUFFMAN_TABLE
            .iter()
            .find(|e| e.2 == sym as u16)
            .map(|e| (e.0, e.1))
            .expect("symbol in table");
        let mut out = Vec::new();
        let mut nbits = bits;
        while nbits >= 8 {
            nbits -= 8;
            out.push(((code >> nbits) & 0xFF) as u8);
        }
        if nbits > 0 {
            let pad = 8 - nbits;
            out.push((((code << pad) | ((1u32 << pad) - 1)) & 0xFF) as u8);
        }
        out
    }

    fn dns_body(len: usize) -> Vec<u8> {
        (0..len).map(|i| i as u8).collect()
    }

    fn ok_field_section(body_len: usize) -> Vec<u8> {
        let len = body_len.to_string();
        field_section(&[
            (b":status", b"200"),
            (b"content-type", b"application/dns-message"),
            (b"content-length", len.as_bytes()),
        ])
    }

    // ------------------------------------------------------------------ InflightGuard

    // ------------------------------------------------------------------ DoQ 帧语义（RFC 9250）

    /// 请求帧 = 2 字节大端长度 + 查询；长度字段是 u16，超限必须报错而非截断。
    #[test]
    fn doq_frame_length_prefix_is_big_endian_u16() {
        let q = dns_body(29);
        let f = doq_frame(&q).expect("frame");
        assert_eq!(f.len(), 31);
        assert_eq!(&f[..2], &[0x00, 0x1d], "长度前缀必须是大端 u16");
        assert_eq!(&f[2..], &q[..]);
        // 边界：65535 可发。
        assert!(doq_frame(&dns_body(65535)).is_ok());
        // 65536 不可发（u16 溢出），必须显式失败。
        assert!(doq_frame(&dns_body(65536)).is_err(), "超长查询必须报错");
    }

    #[test]
    fn doq_reader_accepts_single_and_fragmented_reads() {
        let body = dns_body(29);
        let mut wire = vec![0x00, 29];
        wire.extend_from_slice(&body);
        // 一次读全。
        let mut r = DoqReader::new();
        assert_eq!(r.feed(&wire).unwrap().unwrap(), body);
        // 逐字节喂（真实流可能任意切分）。
        let mut r = DoqReader::new();
        let mut out = None;
        for b in &wire {
            if let Some(v) = r.feed(&[*b]).unwrap() {
                out = Some(v);
            }
        }
        assert_eq!(out.expect("fragmented read must complete"), body);
        // 前缀与正文分开到达。
        let mut r = DoqReader::new();
        assert!(r.feed(&wire[..2]).unwrap().is_none());
        assert_eq!(r.feed(&wire[2..]).unwrap().unwrap(), body);
    }

    #[test]
    fn doq_reader_rejects_short_and_trailing_and_truncated() {
        // 长度前缀 < 12：放不下 DNS 头 → 协议错误（不是"等更多字节"）。
        let mut r = DoqReader::new();
        assert!(r
            .feed(&[0x00, 0x0b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            .is_err());
        // 尾随字节：一问一答的流上多发数据必须拒绝（不静默截断）。
        let body = dns_body(12);
        let mut wire = vec![0x00, 12];
        wire.extend_from_slice(&body);
        wire.push(0xff);
        let mut r = DoqReader::new();
        assert!(r.feed(&wire).is_err(), "尾随字节必须报错");
        // 截断：正文不足时返回 None（继续等），由调用方按 FIN/超时收尾。
        let mut r = DoqReader::new();
        assert!(r.feed(&wire[..8]).unwrap().is_none());
    }

    /// 错误分类：对端关闭（含 DoQ 服务器以应用错误码拒绝）必须归类，不能返回空 kind。
    #[test]
    fn classify_conn_error_covers_peer_close_and_timeout() {
        let (kind, _) = classify_conn_error("timeout");
        assert_eq!(kind, "timeout");
        let (kind, reason) = classify_conn_error(
            "connection lost (ApplicationClosed(ApplicationClose { error_code: 2, reason: b\"\" }))",
        );
        assert_eq!(kind, "connection", "对端应用错误码必须归类");
        assert!(!reason.is_empty());
        let (kind, _) = classify_conn_error("closed by peer: 2");
        assert_eq!(kind, "connection");
        let (kind, _) = classify_conn_error("InvalidCertificate(UnknownIssuer)");
        assert_eq!(kind, "certificate");
        let (kind, _) = classify_conn_error("dns: no upstream ip");
        assert_eq!(kind, "dns");
    }

    #[tokio::test]
    async fn inflight_guard_removes_on_drop() {
        let list = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let h = tokio::spawn(async {});
        list.lock().push((1u64, h.abort_handle()));
        assert_eq!(list.lock().len(), 1);
        {
            let _g = InflightGuard {
                inflight: list.clone(),
                token: 1,
                abort: h.abort_handle(),
            };
            assert_eq!(list.lock().len(), 1);
        }
        assert_eq!(list.lock().len(), 0, "guard drop should remove its token");
    }

    /// 超时/取消路径必须真正中止后台任务：只 drop JoinHandle 不会取消任务（旧实现的泄漏）。
    #[tokio::test]
    async fn inflight_guard_aborts_task_on_drop() {
        let list = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let h = tokio::spawn(std::future::pending::<()>());
        let ah = h.abort_handle();
        list.lock().push((5u64, ah.clone()));
        {
            let _g = InflightGuard {
                inflight: list.clone(),
                token: 5,
                abort: ah,
            };
        }
        for _ in 0..200 {
            if h.is_finished() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(h.is_finished(), "guard drop must abort the spawned task");
        assert_eq!(list.lock().len(), 0);
    }

    #[tokio::test]
    async fn inflight_guard_cleans_on_cancellation() {
        let list = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let list2 = list.clone();
        // 模拟 exchange_with_timeout：登记 inflight + 持 guard 后挂起，直到被外部取消。
        let outer = tokio::spawn(async move {
            let inner = tokio::spawn(std::future::pending::<()>());
            let ah = inner.abort_handle();
            list2.lock().push((7u64, ah.clone()));
            let _g = InflightGuard {
                inflight: list2,
                token: 7,
                abort: ah,
            };
            std::future::pending::<()>().await
        });
        // 等登记出现。
        for _ in 0..50 {
            if list.lock().len() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(list.lock().len(), 1, "inflight should be registered");
        // 调用方取消该 future（drop query）。
        outer.abort();
        let _ = outer.await;
        // guard 在取消路径 drop → inflight 清理，无泄漏。
        assert_eq!(list.lock().len(), 0, "inflight leaked after cancellation");
    }

    // ------------------------------------------------------------------ QPACK 静态表

    #[test]
    fn qpack_static_table_key_entries() {
        // 索引与 RFC 9204 附录 A 一致（并由 pylsqpack/lsqpack 实测导出交叉核对）。
        assert_eq!(
            qpack_static(0),
            Some((b":authority".as_slice(), b"".as_slice()))
        );
        assert_eq!(
            qpack_static(1),
            Some((b":path".as_slice(), b"/".as_slice()))
        );
        assert_eq!(
            qpack_static(4),
            Some((b"content-length".as_slice(), b"0".as_slice()))
        );
        assert_eq!(
            qpack_static(20),
            Some((b":method".as_slice(), b"POST".as_slice()))
        );
        assert_eq!(
            qpack_static(23),
            Some((b":scheme".as_slice(), b"https".as_slice()))
        );
        assert_eq!(
            qpack_static(25),
            Some((b":status".as_slice(), b"200".as_slice()))
        );
        assert_eq!(
            qpack_static(27),
            Some((b":status".as_slice(), b"404".as_slice()))
        );
        assert_eq!(
            qpack_static(30),
            Some((b"accept".as_slice(), b"application/dns-message".as_slice()))
        );
        // 31 是 accept-encoding（旧实现误当 content-type 名字引用用）
        assert_eq!(
            qpack_static(31),
            Some((
                b"accept-encoding".as_slice(),
                b"gzip, deflate, br".as_slice()
            ))
        );
        assert_eq!(
            qpack_static(44),
            Some((
                b"content-type".as_slice(),
                b"application/dns-message".as_slice()
            ))
        );
        assert_eq!(
            qpack_static(95),
            Some((b"user-agent".as_slice(), b"".as_slice()))
        );
        assert_eq!(qpack_static(99), None);
    }

    #[test]
    fn qpack_int_prefix_encoding() {
        // RFC 7541 §5.1 官方向量：5 位前缀编 10 / 1337。
        let mut out = Vec::new();
        qpack_int(&mut out, 5, 0x00, 10);
        assert_eq!(out, vec![0x0A]);
        out.clear();
        qpack_int(&mut out, 5, 0x00, 1337);
        assert_eq!(out, vec![0x1F, 0x9A, 0x0A]);
    }

    // ------------------------------------------------------------------ QPACK 编码

    /// RFC 9204 §4.5.1：字段段前缀必须在最前（缺它会被合规解码器判 QPACK_DECOMPRESSION_FAILED）。
    #[test]
    fn qpack_request_starts_with_field_section_prefix() {
        let block = qpack_encode_request("dns.alidns.com", 443, "/dns-query", 55);
        assert_eq!(&block[..2], &[0x00, 0x00], "RIC=0 + Delta Base=0");
    }

    /// 逐字节期望值；该字节串已由 pylsqpack（aioquic 所用 lsqpack）解码验证为预期 8 个字段。
    #[test]
    fn qpack_request_exact_bytes_alidns() {
        let block = qpack_encode_request("dns.alidns.com", 443, "/dns-query", 55);
        let expect = unhex(concat!(
            "0000", // 字段段前缀
            "d4",   // :method POST（静态 20）
            "d7",   // :scheme https（静态 23）
            "50",
            "12",
            "646e732e616c69646e732e636f6d3a343433", // :authority 名字引用 0 + "dns.alidns.com:443"
            "51",
            "0a",
            "2f646e732d7175657279", // :path 名字引用 1 + "/dns-query"
            "ec",                   // content-type: application/dns-message（静态 44）
            "54",
            "02",
            "3535", // content-length 名字引用 4 + "55"
            "de",   // accept: application/dns-message（静态 30）
            "5f50",
            "0a",
            "656270646e732f322e31", // user-agent 名字引用 95 + "ebpdns/2.1"
        ));
        let got: String = block.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(block, expect, "got {got}");
    }

    /// 任务硬要求：`:authority` 必须有非空值且等于 host:port（旧实现恒为空）。
    #[test]
    fn qpack_request_authority_nonempty() {
        for (host, port) in [
            ("dns.alidns.com", 443u16),
            ("dns.google", 443),
            ("8.8.8.8", 443),
            ("127.0.0.1", 8443),
        ] {
            let block = qpack_encode_request(host, port, "/dns-query", 29);
            let fields = qpack_decode_field_section(&block).expect("decode");
            let authority = fields
                .iter()
                .find(|(n, _)| n.as_slice() == b":authority")
                .map(|(_, v)| v.clone())
                .expect(":authority present");
            assert!(!authority.is_empty(), "authority must not be empty: {host}");
            assert_eq!(authority, format!("{host}:{port}").into_bytes());
        }
    }

    /// **[历史归因]** IPv6 字面量的 authority 必须带方括号（RFC 3986；与 Python 参考实现同口径）。
    #[test]
    fn qpack_request_ipv6_authority() {
        let block = qpack_encode_request("2001:4860:4860::8888", 853, "/dns-query", 29);
        let fields = qpack_decode_field_section(&block).expect("decode");
        let authority = fields
            .iter()
            .find(|(n, _)| n.as_slice() == b":authority")
            .map(|(_, v)| v.clone())
            .expect(":authority present");
        assert_eq!(authority, b"[2001:4860:4860::8888]:853".to_vec());
    }

    /// **[历史归因]** 全字段回环：编码 → 自解码，字段顺序/内容与 Python 参考实现的请求头一致。
    #[test]
    fn qpack_request_roundtrip_all_fields() {
        let block = qpack_encode_request("dns.google", 443, "/dns-query", 29);
        let fields = qpack_decode_field_section(&block).expect("decode");
        let expect: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (b":method".to_vec(), b"POST".to_vec()),
            (b":scheme".to_vec(), b"https".to_vec()),
            (b":authority".to_vec(), b"dns.google:443".to_vec()),
            (b":path".to_vec(), b"/dns-query".to_vec()),
            (
                b"content-type".to_vec(),
                b"application/dns-message".to_vec(),
            ),
            (b"content-length".to_vec(), b"29".to_vec()),
            (b"accept".to_vec(), b"application/dns-message".to_vec()),
            (b"user-agent".to_vec(), H3_USER_AGENT.to_vec()),
        ];
        assert_eq!(fields, expect);
    }

    /// 非默认路径（如 NextDNS `/<profile>`）走名字引用字面量分支；未知名字走字面名分支。
    #[test]
    fn qpack_request_custom_path_and_unknown_name() {
        let block = qpack_encode_request("dns.alidns.com", 443, "/dns-query/abc", 29);
        let fields = qpack_decode_field_section(&block).expect("decode");
        assert!(fields
            .iter()
            .any(|(n, v)| n.as_slice() == b":path" && v.as_slice() == b"/dns-query/abc"));

        let mut out = Vec::new();
        qpack_encode_field(&mut out, b"x-ebpdns", b"v1");
        assert_eq!(out[0] & 0xE0, 0x20, "001 前缀（literal name）");
        let fields = qpack_decode_field_section(&field_section(&[(b"x-ebpdns", b"v1")])).unwrap();
        assert_eq!(fields[0].0, b"x-ebpdns".to_vec());
        assert_eq!(fields[0].1, b"v1".to_vec());
    }

    // ------------------------------------------------------------------ QPACK 解码

    #[test]
    fn qpack_decode_indexed_and_literal_forms() {
        // 索引形态：:status 200（静态 25）+ content-type（静态 44）
        let fields = qpack_decode_field_section(&unhex("0000d9ec")).expect("decode");
        assert_eq!(
            fields,
            vec![
                (b":status".to_vec(), b"200".to_vec()),
                (
                    b"content-type".to_vec(),
                    b"application/dns-message".to_vec()
                ),
            ]
        );
        // 名字引用：:status 静态 25（0x5f 0x0a）+ 字面值 "200"
        let fields = qpack_decode_field_section(&unhex("00005f0a03323030")).expect("decode");
        assert_eq!(fields, vec![(b":status".to_vec(), b"200".to_vec())]);
        // 名字引用：content-type 静态 44（0x5f 0x1d）+ 值
        let mut block = unhex("00005f1d");
        block.push(0x17);
        block.extend_from_slice(b"application/dns-message");
        let fields = qpack_decode_field_section(&block).expect("decode");
        assert_eq!(
            fields,
            vec![(
                b"content-type".to_vec(),
                b"application/dns-message".to_vec()
            )]
        );
        // 字面名 + 字面值（001 前缀，3 位名字长度）
        let fields = qpack_decode_field_section(&unhex("000021780176")).expect("decode");
        assert_eq!(fields, vec![(b"x".to_vec(), b"v".to_vec())]);
        // Huffman 值：:status 名字引用 25 + Huffman("200") = 1001
        let fields = qpack_decode_field_section(&unhex("00005f0a821001")).expect("decode");
        assert_eq!(fields, vec![(b":status".to_vec(), b"200".to_vec())]);
    }

    #[test]
    fn qpack_decode_rejects_dynamic_and_truncated() {
        // RIC != 0（引用动态表）
        assert!(qpack_decode_field_section(&unhex("010000d9")).is_err());
        // 动态索引（1 T=0）
        assert!(qpack_decode_field_section(&unhex("000080")).is_err());
        // 动态名字引用（01 N=0 T=0 索引 5）
        assert!(qpack_decode_field_section(&unhex("000040050176")).is_err());
        // 后基索引（0001）/ 后基名字引用（0000）
        assert!(qpack_decode_field_section(&unhex("000010")).is_err());
        assert!(qpack_decode_field_section(&unhex("000000000176")).is_err());
        // 截断：只有前缀 + 半个名字引用
        assert!(qpack_decode_field_section(&unhex("00005f")).is_err());
        // 越界静态索引（0xff 0x24 = 63 + 36 = 99，超出 99 项静态表）
        assert!(qpack_decode_field_section(&unhex("0000ff24")).is_err());
        // 空块（连字段段前缀都没有）
        assert!(qpack_decode_field_section(&[]).is_err());
    }

    /// 真实形态回归：字段段由 pylsqpack（lsqpack）编码、含 Huffman 值与自定义头，
    /// 解码器必须提取出 :status: 200 / content-type / content-length。
    #[test]
    fn qpack_decode_lsqpack_response_vector() {
        let block = unhex(concat!(
            "0000d9ec540232395f4d84aa6355e75696d07abe941054d444a8200595040b8166e082a62d1bff",
            "5f44909d983f9b8d34cff3f6a52381e71a003f2f04f2b12d424f4ad3947216cfa441e92ac3b2332",
            "6c1d9e96ee3a2d2ade0c99d62d47b669d6a0b54c99d649d69ed965a4757",
        ));
        let fields = qpack_decode_field_section(&block).expect("decode");
        let get = |name: &[u8]| {
            fields
                .iter()
                .find(|(n, _)| n.as_slice() == name)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        assert_eq!(get(b":status"), b"200".to_vec());
        assert_eq!(get(b"content-type"), b"application/dns-message".to_vec());
        assert_eq!(get(b"content-length"), b"29".to_vec());
        assert_eq!(get(b"server"), b"nginx".to_vec());
    }

    // ------------------------------------------------------------------ Huffman

    /// RFC 7541 附录 C.4/C.6 官方测试向量（ASCII 短码与长串两类）。
    #[test]
    fn huffman_decode_rfc7541_vectors() {
        for (hex, plain) in [
            ("f1e3c2e5f23a6ba0ab90f4ff", "www.example.com"),
            ("a8eb10649cbf", "no-cache"),
            ("25a849e95ba97d7f", "custom-key"),
            ("25a849e95bb8e8b4bf", "custom-value"),
            ("6402", "302"),
            ("aec3771a4b", "private"),
            (
                "d07abe941054d444a8200595040b8166e082a62d1bff",
                "Mon, 21 Oct 2013 20:13:21 GMT",
            ),
            (
                "9d29ad171863c78f0b97c8e9ae82ae43d3",
                "https://www.example.com",
            ),
        ] {
            assert_eq!(
                huffman_decode(&unhex(hex)).expect(hex),
                plain.as_bytes().to_vec(),
                "vector {hex}"
            );
        }
    }

    #[test]
    fn huffman_decode_rejects_bad_padding_and_eos() {
        // www.example.com 的末尾填充位改成 0 → 非法填充
        let mut bad = unhex("f1e3c2e5f23a6ba0ab90f4ff");
        *bad.last_mut().unwrap() = 0xFE;
        assert!(huffman_decode(&bad).is_err());
        // 8 位以上全 1 填充 → 非法
        assert!(huffman_decode(&[0xFF]).is_err());
        // EOS（30 位全 1）不得作为符号出现
        assert!(huffman_decode(&unhex("ffffffff")).is_err());
        // 空串合法（长度 0 的字符串值）
        assert_eq!(huffman_decode(&[]).unwrap(), Vec::<u8>::new());
    }

    /// 256 个字节逐一 Huffman 编码→解码回环（同时校验码表前缀无关性与填充规则）。
    #[test]
    fn huffman_roundtrip_all_bytes() {
        for sym in 0u16..256 {
            let encoded = huffman_encode_byte(sym as u8);
            assert_eq!(
                huffman_decode(&encoded).expect("decode"),
                vec![sym as u8],
                "symbol {sym}"
            );
        }
    }

    // ------------------------------------------------------------------ HTTP/3 帧与流

    #[test]
    fn h3_control_and_qpack_stream_bytes() {
        // 控制流：stream type 0x00 + SETTINGS(0x04) 帧、载荷 0 字节
        assert_eq!(h3_control_stream_bytes(), vec![0x00, 0x04, 0x00]);
        // QPACK encoder / decoder：只有流类型前缀，无指令
        assert_eq!(h3_qpack_encoder_stream_bytes(), vec![0x02]);
        assert_eq!(h3_qpack_decoder_stream_bytes(), vec![0x03]);
    }

    #[test]
    fn h3_frame_write_and_varint_roundtrip() {
        let mut out = Vec::new();
        h3_write_frame(&mut out, 0x01, &[0xAA, 0xBB]);
        assert_eq!(out, vec![0x01, 0x02, 0xAA, 0xBB]);
        let mut big = Vec::new();
        h3_write_frame(&mut big, 0x00, &[0u8; 200]);
        assert_eq!(&big[..3], &[0x00, 0x40, 0xC8]);
        assert_eq!(big.len(), 203);
        for v in [
            0u64,
            1,
            63,
            64,
            16383,
            16384,
            1 << 29,
            1 << 30,
            (1 << 62) - 1,
        ] {
            let enc = encode_varint(v);
            let (got, rest) = decode_varint(&enc).expect("decode varint");
            assert_eq!(got, v);
            assert!(rest.is_empty());
        }
    }

    /// 逐字节喂入也要正确解析 HEADERS + DATA（QUIC 上任意分段）。
    #[test]
    fn h3_response_parses_headers_and_data_bytewise() {
        let body = dns_body(29);
        let mut stream = frame(0x01, &ok_field_section(body.len()));
        stream.extend(frame(0x00, &body));
        for chunk in [1usize, 2, 3, 7, 4096] {
            let mut resp = H3Response::new();
            for part in stream.chunks(chunk) {
                resp.feed(part);
                assert!(resp.error().is_none(), "chunk {chunk}: {:?}", resp.error());
                if resp.is_complete() {
                    break;
                }
            }
            assert!(resp.is_complete(), "chunk {chunk} should complete");
            assert_eq!(resp.finish().expect("finish"), body, "chunk {chunk}");
        }
    }

    /// 回归（真机缺陷）：服务端把 HEADERS 与 DATA **拆到不同的 QUIC 包**时，
    /// 未收齐的帧不得被缓冲回收逻辑丢掉。
    ///
    /// 旧实现保留"已消费位置" `pos`，并在 `pos >= 16KiB` 时 `drain(..pos)`；而
    /// `h3_frame_at` 对"帧头已到、载荷未到"的帧会返回 `Incomplete` 却已经把帧头
    /// 计入 `pos`，于是 `drain` 把该帧已到的字节整段丢弃 → 之后每帧都从半截开始解析，
    /// 大响应永久 desync（Quad9/Google 等非阿里 DoH3 100% 复现；阿里把两帧塞进
    /// 同一个包才"看起来正常"）。
    #[test]
    fn h3_response_survives_frame_split_across_reads() {
        let body = dns_body(29);
        let headers = frame(0x01, &ok_field_section(body.len()));
        let data = frame(0x00, &body);
        // 1) HEADERS 帧头先到（帧头 2 字节 + 载荷未到齐）→ 再补剩余字节。
        for split in 1..headers.len() {
            let mut resp = H3Response::new();
            resp.feed(&headers[..split]);
            resp.feed(&headers[split..]);
            resp.feed(&data);
            assert!(
                resp.error().is_none(),
                "split={split} err={:?}",
                resp.error()
            );
            assert_eq!(resp.finish().expect("finish"), body, "split={split}");
        }
        // 2) DATA 帧头单独到达（HEADERS 已完整）→ 也必须保留。
        let mut resp = H3Response::new();
        resp.feed(&headers);
        resp.feed(&data[..2]);
        resp.feed(&data[2..]);
        assert_eq!(resp.finish().expect("finish"), body);
        // 3) 大响应：已解析前缀被回收后，未收齐的帧仍必须正确解析。
        let big = dns_body(20000);
        let big_headers = frame(0x01, &ok_field_section(big.len()));
        let big_data = frame(0x00, &big);
        let mut resp = H3Response::new();
        resp.feed(&big_headers);
        for part in big_data.chunks(4096) {
            resp.feed(part);
        }
        assert_eq!(resp.finish().expect("finish"), big);
        assert!(resp.buf.is_empty(), "完整帧必须立即回收，缓冲不残留");
    }

    /// 跨读的**未完整**帧在多次 feed 之后不得被回收（缓冲只留未成帧数据）。
    #[test]
    fn h3_response_buffer_keeps_incomplete_tail() {
        let body = dns_body(3000);
        let mut stream = frame(0x01, &ok_field_section(body.len()));
        stream.extend(frame(0x00, &body));
        let mut resp = H3Response::new();
        for part in stream.chunks(700) {
            resp.feed(part);
            // 任何时刻缓冲里都不应出现"已完整但未处理"的大块数据。
            assert!(
                resp.buf.len() < stream.len(),
                "buffer must not hoard whole frames: {}",
                resp.buf.len()
            );
        }
        assert_eq!(resp.finish().expect("finish"), body);
    }

    /// content-length 精确读取；正文不足（收到 FIN）必须失败。
    #[test]
    fn h3_response_content_length_handling() {
        let body = dns_body(29);
        let mut resp = H3Response::new();
        resp.feed(&frame(0x01, &ok_field_section(body.len())));
        resp.feed(&frame(0x00, &body));
        assert!(resp.is_complete());
        assert_eq!(resp.finish().unwrap(), body);

        // 服务端多发字节 → 按 content-length 截取
        let mut longer = body.clone();
        longer.extend_from_slice(b"EXTRA");
        let mut resp = H3Response::new();
        resp.feed(&frame(0x01, &ok_field_section(body.len())));
        resp.feed(&frame(0x00, &longer));
        assert_eq!(resp.finish().unwrap(), body);

        // 声明 29 只给 10 + EOF → 正文不完整
        let mut resp = H3Response::new();
        resp.feed(&frame(0x01, &ok_field_section(body.len())));
        resp.feed(&frame(0x00, &body[..10]));
        assert!(!resp.is_complete());
        assert!(resp.finish().is_err(), "truncated body must fail");
    }

    /// 缺 content-length：以 FIN 为准（收齐前 is_complete 恒 false）。
    #[test]
    fn h3_response_without_content_length_uses_eof() {
        let body = dns_body(29);
        let block = field_section(&[
            (b":status", b"200"),
            (b"content-type", b"application/dns-message"),
        ]);
        let mut resp = H3Response::new();
        resp.feed(&frame(0x01, &block));
        resp.feed(&frame(0x00, &body));
        assert!(!resp.is_complete(), "无 content-length 时必须等 FIN");
        assert_eq!(resp.finish().unwrap(), body);
    }

    #[test]
    fn h3_response_requires_status_and_content_type() {
        let body = dns_body(29);
        let wrap = |block: &[u8]| {
            let mut r = H3Response::new();
            r.feed(&frame(0x01, block));
            r.feed(&frame(0x00, &body));
            r
        };
        // 非 200
        let err = wrap(&field_section(&[
            (b":status", b"404"),
            (b"content-type", b"application/dns-message"),
        ]))
        .finish()
        .unwrap_err();
        assert!(err.contains("404"), "{err}");
        // content-type 不符 / 缺失
        assert!(wrap(&field_section(&[
            (b":status", b"200"),
            (b"content-type", b"application/json")
        ]))
        .finish()
        .is_err());
        assert!(wrap(&field_section(&[(b":status", b"200")]))
            .finish()
            .is_err());
        // 缺 :status
        assert!(wrap(&field_section(&[(
            b"content-type",
            b"application/dns-message"
        )]))
        .finish()
        .is_err());
        // 同段重复 :status
        let mut dup = H3Response::new();
        dup.feed(&frame(
            0x01,
            &field_section(&[
                (b":status", b"200"),
                (b":status", b"200"),
                (b"content-type", b"application/dns-message"),
            ]),
        ));
        assert!(dup.error().is_some(), "duplicate :status must fail");
        // 1xx 中间响应之后仍可接受最终响应
        let mut hint = H3Response::new();
        hint.feed(&frame(0x01, &field_section(&[(b":status", b"103")])));
        hint.feed(&frame(0x01, &ok_field_section(body.len())));
        hint.feed(&frame(0x00, &body));
        assert_eq!(hint.finish().unwrap(), body);
    }

    #[test]
    fn h3_response_ignores_unknown_frames_rejects_goaway() {
        let body = dns_body(29);
        // 未知/保留帧（0x21 grease、0x03 CANCEL_PUSH）一律忽略
        let mut stream = frame(0x21, b"grease");
        stream.extend(frame(0x03, b"x"));
        stream.extend(frame(0x01, &ok_field_section(body.len())));
        stream.extend(frame(0x00, &body));
        let mut resp = H3Response::new();
        resp.feed(&stream);
        assert_eq!(resp.finish().unwrap(), body);
        // GOAWAY 出现在请求流 → 协议错误
        let mut resp = H3Response::new();
        resp.feed(&frame(0x07, &[0x00]));
        assert!(resp.error().is_some());
        // PUSH_PROMISE（我们从未发 MAX_PUSH_ID）→ 协议错误
        let mut resp = H3Response::new();
        resp.feed(&frame(0x05, &[0x00, 0x00]));
        assert!(resp.error().is_some());
        // HEADERS 之前的 DATA → 协议错误（RFC 9114 §4.1）
        let mut resp = H3Response::new();
        resp.feed(&frame(0x00, &body));
        assert!(resp.error().is_some());
    }

    /// 超长帧声明立即判错，不无界缓冲（防内存耗尽）。
    #[test]
    fn h3_response_rejects_oversized_frame() {
        let mut oversized = Vec::new();
        oversized.extend(encode_varint(H3_FRAME_DATA));
        oversized.extend(encode_varint(H3_MAX_FRAME + 1));
        let mut resp = H3Response::new();
        resp.feed(&oversized);
        assert!(resp.error().is_some(), "oversized frame must fail");
    }
}
