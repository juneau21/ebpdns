//! **2.1.50（P0-3）**：DoH HTTP/2 多路复用的端到端用例。
//!
//! 全部使用**真实本地 TLS 服务端**（`tests/fixtures/` 的自签 CA1 + localhost/IP SAN
//! 服务器证书），不依赖外网、不 mock TLS/HTTP 栈：
//!
//! - h2 服务端：`h2::server`，可以**分多个 DATA 帧**回正文、**不带 Content-Length**、
//!   在 N 个并发 stream 上设置屏障（证明这些查询真的同时在**一条连接**的多个 stream 上）；
//! - h1-only 服务端：`ALPN=[http/1.1]`（或完全不协商 ALPN）验证 ALPN 自动回退；
//!   还覆盖 `Transfer-Encoding: chunked`（无 Content-Length）与"读到 EOF"两种 framing；
//! - 失败面：GOAWAY（重连一次）、RST_STREAM、超时、超大响应、错误 content-type；
//! - 指标：`rt.h2_stats()` / `rt.h2_key_stats()` 的 gauge/counter 与指标口径一致。
//!
//! 客户端一律走 [`UpstreamRuntime::query`]（= 生产入口），因此覆盖 TLS 策略（自定义
//! CA）、ALPN 协商、qid=0 改写/还原、连接池与重试的完整链路。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ebpdns_upstream::tls::TlsPolicy;
use ebpdns_upstream::{
    is_header_only, qid_of, DohTransport, Proto, UpstreamConfig, UpstreamRuntime,
};
use h2::server::SendResponse;
use http::{Request, Response, StatusCode};
use parking_lot::Mutex;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Barrier;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

const CA1: &[u8] = include_bytes!("fixtures/ca1.pem");
const SERVER1_CERT: &[u8] = include_bytes!("fixtures/server1.pem");
const SERVER1_KEY: &[u8] = include_bytes!("fixtures/server1.key");

/* ============================ 通用工具 ============================ */

fn load_certs(pem: &[u8]) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut &pem[..])
        .collect::<Result<Vec<_>, _>>()
        .expect("fixture certs 必须可解析")
}

fn load_key(pem: &[u8]) -> PrivateKeyDer<'static> {
    rustls_pemfile::private_key(&mut &pem[..])
        .expect("fixture key 必须可解析")
        .expect("fixture key 必须存在")
}

/// 本地 TLS 服务端配置：指定 ALPN 列表（空 = 不协商 ALPN）。
fn server_config(alpn: &[&[u8]]) -> Arc<ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
        .expect("测试服务端协议版本可用")
        .with_no_client_auth()
        .with_single_cert(load_certs(SERVER1_CERT), load_key(SERVER1_KEY))
        .expect("测试证书/私钥必须匹配");
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(cfg)
}

/// 写 CA 到临时文件（客户端 `tls_ca_file` 需要真实路径）。
fn ca_file() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("ca.pem");
    std::fs::write(&path, CA1).expect("写 CA 文件");
    (dir, path.display().to_string())
}

/// **2.2.0**：TLS 策略是**运行时全局**（顶层配置键），不是每上游字段。
/// 测试里每条 runtime 用 CA1 建策略后换入（与生产 `set_tls_policy` 同一入口）。
fn rt_with_ca(ca: &str) -> Arc<UpstreamRuntime> {
    let rt = Arc::new(UpstreamRuntime::new());
    rt.set_tls_policy(Arc::new(
        TlsPolicy::from_config("1.2", false, ca).expect("测试 TLS 策略合法"),
    ));
    rt
}

/// 构造 DoH 上游配置（127.0.0.1；TLS 策略由 `rt_with_ca` 提供）。
fn doh_cfg(port: u16, _ca: &str) -> UpstreamConfig {
    UpstreamConfig {
        id: format!("doh-p03-{port}"),
        name: "local-doh".into(),
        proto: Proto::Doh,
        host: "127.0.0.1".into(),
        port,
        url: "/dns-query".into(),
        ..Default::default()
    }
}

/// 合法 DNS 查询（`example.com A`，qid 由调用方给）。
fn make_query(qid: u16) -> Vec<u8> {
    let mut q = Vec::new();
    q.extend(qid.to_be_bytes());
    q.extend(0x0100u16.to_be_bytes()); // RD
    q.extend(1u16.to_be_bytes()); // qd
    q.extend(0u16.to_be_bytes());
    q.extend(0u16.to_be_bytes());
    q.extend(0u16.to_be_bytes());
    q.extend(b"\x07example\x03com\x00");
    q.extend(1u16.to_be_bytes()); // A
    q.extend(1u16.to_be_bytes()); // IN
    q
}

/// 合法 DNS 应答（回显 qid；QDCOUNT=1、ANCOUNT=1），尾部补 `pad` 字节用于造大正文。
fn make_answer(qid: u16, pad: usize) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend(qid.to_be_bytes());
    r.extend(0x8180u16.to_be_bytes()); // QR + RD + RA
    r.extend(1u16.to_be_bytes());
    r.extend(1u16.to_be_bytes());
    r.extend(0u16.to_be_bytes());
    r.extend(0u16.to_be_bytes());
    r.extend(b"\x07example\x03com\x00");
    r.extend(1u16.to_be_bytes());
    r.extend(1u16.to_be_bytes());
    r.extend(0xC00Cu16.to_be_bytes());
    r.extend(1u16.to_be_bytes());
    r.extend(1u16.to_be_bytes());
    r.extend(60u32.to_be_bytes());
    r.extend(4u16.to_be_bytes());
    r.extend([93, 184, 216, 34]);
    r.resize(r.len() + pad, 0);
    r
}

fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/* ============================ h2 DoH 服务端 ============================ */

/// 单个请求的特殊行为（其余请求一律 `Normal`）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Action {
    Normal,
    /// 直接 RST_STREAM(CANCEL)，不回响应。
    Reset,
    /// 挂起 5s（客户端必然先超时）。
    Hang,
    /// 回一个超过 65535 的正文（客户端必须拒绝）。
    Oversize,
    /// 200 + `text/plain`（客户端必须拒绝）。
    BadContentType,
}

struct H2Ctl {
    conns: AtomicUsize,
    requests: AtomicUsize,
    active: AtomicUsize,
    max_active: AtomicUsize,
    /// 每个请求 body 的前两字节（必须是 0：RFC 8484 §4.1）。
    qids: Mutex<Vec<u16>>,
    body_lens: Mutex<Vec<usize>>,
    /// 请求头违规（method/content-type/accept/version/不该出现的头）。
    violations: Mutex<Vec<String>>,
    /// 响应正文尾部填充（字节）。
    pad: usize,
    /// 响应切成多少个 DATA 帧（1 = 单帧；大响应用例用多帧）。
    frames: usize,
    /// 前 N 条连接直接 GOAWAY（模拟服务端踢连接）。
    goaway_conns: usize,
    /// 第 N 个请求（1-based）的行为。
    special: (usize, Action),
    /// 为 `true` 时所有请求在响应前等待屏障（并发 stream 证据）。
    barrier: Option<Arc<Barrier>>,
}

impl H2Ctl {
    fn new() -> Self {
        Self {
            conns: AtomicUsize::new(0),
            requests: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            max_active: AtomicUsize::new(0),
            qids: Mutex::new(Vec::new()),
            body_lens: Mutex::new(Vec::new()),
            violations: Mutex::new(Vec::new()),
            pad: 0,
            frames: 1,
            goaway_conns: 0,
            special: (0, Action::Normal),
            barrier: None,
        }
    }

    fn action_for(&self, n: usize) -> Action {
        if self.special.0 == n {
            self.special.1
        } else {
            Action::Normal
        }
    }

    fn record_violation(&self, msg: impl Into<String>) {
        self.violations.lock().push(msg.into());
    }

    /// 校验 RFC 8484/h2 请求形态（任何偏差都记进 `violations`，由用例断言为空）。
    fn check_request(&self, req: &Request<h2::RecvStream>) {
        if req.method() != http::Method::POST {
            self.record_violation(format!("method = {}", req.method()));
        }
        if req.version() != http::Version::HTTP_2 {
            self.record_violation(format!("version = {:?}", req.version()));
        }
        let ctype = req
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if ctype != "application/dns-message" {
            self.record_violation(format!("content-type = {ctype:?}"));
        }
        let accept = req
            .headers()
            .get(http::header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if accept != "application/dns-message" {
            self.record_violation(format!("accept = {accept:?}"));
        }
        // HTTP/2 下不允许出现 connection-specific 头（RFC 9113 §8.2.2）。
        for (name, _) in req.headers() {
            let n = name.as_str();
            if n == "connection"
                || n == "transfer-encoding"
                || n == "keep-alive"
                || n == "upgrade"
                || n == "proxy-connection"
            {
                self.record_violation(format!("forbidden h2 header: {name}"));
            }
        }
    }

    /// 把 `body` 切成 `frames` 个 DATA 帧发出（**故意不带 Content-Length**）。
    fn send_frames(&self, respond: &mut SendResponse<Bytes>, body: &[u8]) {
        let resp = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/dns-message")
            .body(())
            .expect("构造响应头");
        let Ok(mut send) = respond.send_response(resp, false) else {
            return;
        };
        let per = body.len().div_ceil(self.frames.max(1)).max(1);
        let mut it = body.chunks(per).peekable();
        while let Some(c) = it.next() {
            let last = it.peek().is_none();
            if send.send_data(Bytes::copy_from_slice(c), last).is_err() {
                return;
            }
        }
    }

    async fn serve(
        self: Arc<Self>,
        req: Request<h2::RecvStream>,
        mut respond: SendResponse<Bytes>,
        n: usize,
    ) {
        let cur = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_active.fetch_max(cur, Ordering::SeqCst);
        self.check_request(&req);

        // 读完请求 body（DATA 帧）。
        let mut body = Vec::new();
        let mut recv = req.into_body();
        while let Some(chunk) = recv.data().await {
            match chunk {
                Ok(c) => {
                    let len = c.len();
                    body.extend_from_slice(&c);
                    drop(c);
                    let _ = recv.flow_control().release_capacity(len);
                }
                Err(_) => break,
            }
        }
        if body.len() >= 2 {
            self.qids
                .lock()
                .push(u16::from_be_bytes([body[0], body[1]]));
        }
        self.body_lens.lock().push(body.len());

        // 并发屏障：N 个 stream 必须**同时**在途才能全员通过。
        if let Some(b) = &self.barrier {
            b.wait().await;
        }

        match self.action_for(n) {
            Action::Normal => {
                let answer = make_answer(0, self.pad);
                self.send_frames(&mut respond, &answer);
            }
            Action::Reset => respond.send_reset(h2::Reason::CANCEL),
            Action::Hang => {
                tokio::time::sleep(Duration::from_secs(5)).await;
                respond.send_reset(h2::Reason::CANCEL);
            }
            Action::Oversize => {
                let answer = make_answer(0, 200_000);
                self.send_frames(&mut respond, &answer);
            }
            Action::BadContentType => {
                let resp = Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "text/plain")
                    .body(())
                    .expect("构造响应头");
                if let Ok(mut send) = respond.send_response(resp, false) {
                    let _ = send.send_data(Bytes::from_static(b"not-dns"), true);
                }
            }
        }
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn h2_conn(tls: TlsStream<TcpStream>, ctl: Arc<H2Ctl>, conn_idx: usize) {
    let Ok(mut h2) = h2::server::handshake(tls).await else {
        return;
    };
    if conn_idx <= ctl.goaway_conns {
        // 收到第一个 stream 后立刻 GOAWAY（不回响应）——客户端必须重连一次再成功。
        // 注意：`respond` 故意**不 drop**（drop 会先发 RST_STREAM(CANCEL)，客户端可能
        // 先看到 stream 级错误而不是 GOAWAY/连接关闭）。
        if let Some(Ok((_req, _respond))) = h2.accept().await {
            h2.abrupt_shutdown(h2::Reason::NO_ERROR);
            while h2.accept().await.is_some() {}
        }
        return;
    }
    while let Some(res) = h2.accept().await {
        let Ok((req, respond)) = res else {
            break;
        };
        let n = ctl.requests.fetch_add(1, Ordering::SeqCst) + 1;
        let ctl2 = ctl.clone();
        tokio::spawn(async move { ctl2.serve(req, respond, n).await });
    }
}

/// 起本地 h2 DoH 服务端（ALPN 只有 `h2`），返回端口。
async fn spawn_h2_server(ctl: Arc<H2Ctl>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let acceptor = TlsAcceptor::from(server_config(&[b"h2"]));
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let idx = ctl.conns.fetch_add(1, Ordering::SeqCst) + 1;
            let acceptor = acceptor.clone();
            let ctl2 = ctl.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(tcp).await {
                    h2_conn(tls, ctl2, idx).await;
                }
            });
        }
    });
    port
}

/* ============================ h1-only DoH 服务端 ============================ */

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum H1Framing {
    /// `Transfer-Encoding: chunked`（无 Content-Length）；连接可复用。
    Chunked,
    /// 无 Content-Length、非 chunked，`Connection: close` + 读到 EOF；连接不可复用。
    CloseDelimited,
}

struct H1Ctl {
    conns: AtomicUsize,
    requests: AtomicUsize,
    qids: Mutex<Vec<u16>>,
    violations: Mutex<Vec<String>>,
    framing: H1Framing,
}

impl H1Ctl {
    fn new(framing: H1Framing) -> Self {
        Self {
            conns: AtomicUsize::new(0),
            requests: AtomicUsize::new(0),
            qids: Mutex::new(Vec::new()),
            violations: Mutex::new(Vec::new()),
            framing,
        }
    }
}

async fn h1_conn(mut stream: TlsStream<TcpStream>, ctl: Arc<H1Ctl>) {
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        // 读请求头。
        let header_end = loop {
            if let Some(p) = find_bytes(&buf, b"\r\n\r\n") {
                break p;
            }
            match stream.read(&mut tmp).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
            }
        };
        let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
        if !head.starts_with("POST /dns-query HTTP/1.1") {
            ctl.violations
                .lock()
                .push(format!("request line: {head:?}"));
        }
        if !head
            .to_ascii_lowercase()
            .contains("content-type: application/dns-message")
        {
            ctl.violations
                .lock()
                .push(format!("content-type 缺失: {head:?}"));
        }
        let cl = head
            .lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                if k.trim().eq_ignore_ascii_case("content-length") {
                    v.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0);
        let need = header_end + 4 + cl;
        while buf.len() < need {
            match stream.read(&mut tmp).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
            }
        }
        let body = buf[header_end + 4..need].to_vec();
        buf.drain(..need);
        ctl.requests.fetch_add(1, Ordering::SeqCst);
        if body.len() >= 2 {
            ctl.qids.lock().push(u16::from_be_bytes([body[0], body[1]]));
        }

        let answer = make_answer(0, 0);
        let mut out: Vec<u8> = Vec::new();
        match ctl.framing {
            H1Framing::Chunked => {
                out.extend_from_slice(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n\
                      Transfer-Encoding: chunked\r\n\r\n",
                );
                // 故意切成多个 chunk（含 1 字节 chunk），验证增量解码。
                for chunk in answer.chunks(17) {
                    out.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                    out.extend_from_slice(chunk);
                    out.extend_from_slice(b"\r\n");
                }
                out.extend_from_slice(b"0\r\n\r\n");
                if stream.write_all(&out).await.is_err() {
                    return;
                }
                let _ = stream.flush().await;
            }
            H1Framing::CloseDelimited => {
                out.extend_from_slice(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n\
                      Connection: close\r\n\r\n",
                );
                out.extend_from_slice(&answer);
                let _ = stream.write_all(&out).await;
                let _ = stream.flush().await;
                let _ = stream.shutdown().await;
                return;
            }
        }
    }
}

/// 起本地 h1-only DoH 服务端（`alpn` 为空 ⇒ 完全不协商 ALPN）。
async fn spawn_h1_server(ctl: Arc<H1Ctl>, alpn: &[&[u8]]) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let acceptor = TlsAcceptor::from(server_config(alpn));
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            ctl.conns.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            let ctl2 = ctl.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(tcp).await {
                    h1_conn(tls, ctl2).await;
                }
            });
        }
    });
    port
}

/* ============================ 断言助手 ============================ */

/// 断言响应是"合法 DNS 应答 + qid 已还原为调用方原值"。
fn assert_answer(out: &ebpdns_upstream::QueryOutcome, want_qid: u16) {
    assert!(out.ok, "查询必须成功: {out:?}");
    let data = out.data.as_ref().expect("成功必须有 data");
    assert!(!is_header_only(data), "响应不得是 header-only");
    assert_eq!(qid_of(data), Some(want_qid), "qid 必须还原为调用方原值");
    assert!(data.len() >= 12);
}

/* ============================ 用例 ============================ */

/// **核心用例：一条 h2 连接上并发 N 个 stream（连接数必须 = 1）。**
///
/// 服务端用**全局屏障**让 N 个请求必须同时在途才能通过：若客户端为每个查询各开一条
/// 连接，每条连接只有 1 个 stream，屏障永远等不到 N 个 → 查询全部超时。因此"全部成功"
/// 本身就是"流级复用"的证明；再叠加 conns==1 / max_active==N 的硬断言。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_multiplexes_concurrent_queries_on_one_connection() {
    const N: usize = 8;
    let (_dir, ca) = ca_file();
    let ctl = Arc::new(H2Ctl {
        // 大正文（>2KB）切成多个 DATA 帧、且不带 Content-Length。
        pad: 3000,
        frames: 16,
        barrier: Some(Arc::new(Barrier::new(N))),
        ..H2Ctl::new()
    });
    let port = spawn_h2_server(ctl.clone()).await;
    let rt = rt_with_ca(&ca);
    let cfg = doh_cfg(port, &ca);

    let futs = (0..N).map(|i| {
        let rt = rt.clone();
        let cfg = cfg.clone();
        let q = make_query(0x1000 + i as u16);
        async move { (0x1000 + i as u16, rt.query(&cfg, &q, 5_000).await) }
    });
    let outs = futures::future::join_all(futs).await;

    for (want_qid, out) in &outs {
        assert_answer(out, *want_qid);
        // 大正文完整（分帧不影响字节数）。答案正文 = 45 + pad 字节。
        let data = out.data.as_ref().unwrap();
        assert_eq!(data.len(), 45 + 3000, "分帧后正文长度必须一致");
    }

    // ---- 连接/stream 证据 ----
    assert_eq!(
        ctl.conns.load(Ordering::SeqCst),
        1,
        "N 个并发查询必须复用在**一条** h2 连接上（conns 必须 = 1）"
    );
    assert_eq!(ctl.requests.load(Ordering::SeqCst), N);
    assert_eq!(
        ctl.max_active.load(Ordering::SeqCst),
        N,
        "服务端必须同时看到 {N} 个在途 stream（屏障通过即证明）"
    );
    // ---- RFC 8484：qid=0 + 请求头 ----
    let qids = ctl.qids.lock().clone();
    assert_eq!(qids.len(), N);
    assert!(
        qids.iter().all(|q| *q == 0),
        "DoH 上线报文 qid 必须全为 0（RFC 8484 §4.1），实际 {qids:?}"
    );
    assert!(
        ctl.violations.lock().is_empty(),
        "h2 请求头违规: {:?}",
        ctl.violations.lock()
    );
    // ---- 指标 ----
    let st = rt.h2_stats();
    assert_eq!(st.conns_open, 1, "gauge: 当前打开 1 条 h2 连接");
    assert_eq!(st.streams_total, N as u64, "累计 stream 数");
    assert_eq!(st.streams_active, 0, "查询结束后不得有活跃 stream 泄漏");
    assert_eq!(st.goaway_total, 0);
    assert_eq!(st.fallback_h1_total, 0);
    let ks = rt.h2_key_stats(&cfg.pool_key());
    assert_eq!(ks.transport, Some(DohTransport::H2), "传输形态必须是 h2");
    assert_eq!(ks.conns_open, 1);
    assert_eq!(ks.streams_total, N as u64);
}

/// **h1-only 服务端（ALPN 只给 http/1.1）⇒ 自动回退且连接池复用。**
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h1_only_alpn_falls_back_and_reuses_pooled_connection() {
    let (_dir, ca) = ca_file();
    let ctl = Arc::new(H1Ctl::new(H1Framing::Chunked));
    let port = spawn_h1_server(ctl.clone(), &[b"http/1.1"]).await;
    let rt = rt_with_ca(&ca);
    let cfg = doh_cfg(port, &ca);

    // 串行两次：第一条建连（ALPN 回退），第二条复用池内 h1 连接。
    assert_answer(&rt.query(&cfg, &make_query(0x2001), 5_000).await, 0x2001);
    assert_answer(
        &rt.query(&cfg, make_query(0x2002).as_slice(), 5_000).await,
        0x2002,
    );

    assert_eq!(
        ctl.conns.load(Ordering::SeqCst),
        1,
        "HTTP/1.1 回退路径必须保留既有连接池语义（第二次复用同一连接）"
    );
    assert_eq!(ctl.requests.load(Ordering::SeqCst), 2);
    let qids = ctl.qids.lock().clone();
    assert_eq!(qids, vec![0, 0], "h1 回退同样必须用 qid=0 上线");
    assert!(
        ctl.violations.lock().is_empty(),
        "h1 请求形态违规: {:?}",
        ctl.violations.lock()
    );
    let st = rt.h2_stats();
    assert_eq!(st.conns_open, 0, "h1 回退不产生 h2 连接");
    assert_eq!(st.streams_total, 0);
    assert_eq!(st.fallback_h1_total, 1, "每次新建 h1 连接计一次回退");
    let ks = rt.h2_key_stats(&cfg.pool_key());
    assert_eq!(ks.transport, Some(DohTransport::Http11));
}

/// **服务端完全不协商 ALPN（旧/极简 h1 服务端）⇒ 仍回退 http/1.1 成功。**
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_alpn_also_falls_back_to_http11() {
    let (_dir, ca) = ca_file();
    let ctl = Arc::new(H1Ctl::new(H1Framing::Chunked));
    let port = spawn_h1_server(ctl.clone(), &[]).await;
    let rt = rt_with_ca(&ca);
    let cfg = doh_cfg(port, &ca);
    assert_answer(&rt.query(&cfg, &make_query(0x2101), 5_000).await, 0x2101);
    assert_eq!(ctl.conns.load(Ordering::SeqCst), 1);
    assert_eq!(rt.h2_stats().fallback_h1_total, 1);
}

/// **h1 无 Content-Length（chunked）必须被接受**（2.1.50 之前的"必须 CL/拒绝 chunked"已删）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h1_chunked_without_content_length_is_accepted() {
    let (_dir, ca) = ca_file();
    let ctl = Arc::new(H1Ctl::new(H1Framing::Chunked));
    let port = spawn_h1_server(ctl.clone(), &[b"http/1.1"]).await;
    let rt = rt_with_ca(&ca);
    let cfg = doh_cfg(port, &ca);
    assert_answer(&rt.query(&cfg, &make_query(0x2201), 5_000).await, 0x2201);
    // chunked 有明确帧边界 ⇒ 无残留 ⇒ 连接可复用（第二次仍是同一连接）。
    assert_answer(&rt.query(&cfg, &make_query(0x2202), 5_000).await, 0x2202);
    assert_eq!(
        ctl.conns.load(Ordering::SeqCst),
        1,
        "chunked 响应必须可复用连接"
    );
}

/// **h1 无 Content-Length 且非 chunked（EOF 定界）⇒ 接受正文但连接不复用。**
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h1_eof_delimited_body_is_accepted_but_connection_not_reused() {
    let (_dir, ca) = ca_file();
    let ctl = Arc::new(H1Ctl::new(H1Framing::CloseDelimited));
    let port = spawn_h1_server(ctl.clone(), &[b"http/1.1"]).await;
    let rt = rt_with_ca(&ca);
    let cfg = doh_cfg(port, &ca);
    assert_answer(&rt.query(&cfg, &make_query(0x2301), 5_000).await, 0x2301);
    assert_answer(&rt.query(&cfg, &make_query(0x2302), 5_000).await, 0x2302);
    assert_eq!(
        ctl.conns.load(Ordering::SeqCst),
        2,
        "EOF 定界的响应意味着连接已关（degraded），第二次必须新建连接"
    );
    assert_eq!(
        rt.h2_stats().fallback_h1_total,
        2,
        "两次新建 h1 连接 ⇒ 回退计数 2"
    );
}

/// **GOAWAY ⇒ 自动重连一次并成功**（服务端第 1 条连接直接踢）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn goaway_triggers_exactly_one_reconnect() {
    let (_dir, ca) = ca_file();
    let ctl = Arc::new(H2Ctl {
        goaway_conns: 1,
        ..H2Ctl::new()
    });
    let port = spawn_h2_server(ctl.clone()).await;
    let rt = rt_with_ca(&ca);
    let cfg = doh_cfg(port, &ca);

    let out = rt.query(&cfg, &make_query(0x3001), 5_000).await;
    assert_answer(&out, 0x3001);

    assert_eq!(
        ctl.conns.load(Ordering::SeqCst),
        2,
        "GOAWAY 后必须重连一次（第 1 条连接被踢，第 2 条成功）"
    );
    // `goaway_total` 是"连接被对端终止"的观测：对端 GOAWAY/关闭与客户端收尾之间可能
    // 差一拍，这里给 ≤2s 的收敛窗口（不在热路径里假设计数器瞬时可见）。
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut st = rt.h2_stats();
    while st.goaway_total == 0 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
        st = rt.h2_stats();
    }
    assert_eq!(st.goaway_total, 1, "对端 GOAWAY 必须计数");
    assert_eq!(st.conns_open, 1, "重连后的连接在池中");
    assert_eq!(st.streams_total, 2, "失败的那次 + 重连后成功的那次");
}

/// **RST_STREAM 只失败该 stream，连接保留**（不重连、后续查询继续用同一连接）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rst_stream_fails_only_that_query_and_keeps_connection() {
    let (_dir, ca) = ca_file();
    let ctl = Arc::new(H2Ctl {
        special: (2, Action::Reset),
        ..H2Ctl::new()
    });
    let port = spawn_h2_server(ctl.clone()).await;
    let rt = rt_with_ca(&ca);
    let cfg = doh_cfg(port, &ca);

    // #1 正常（建立并池化 h2 连接）。
    assert_answer(&rt.query(&cfg, &make_query(0x4001), 5_000).await, 0x4001);
    // #2 被 RST_STREAM(CANCEL) ⇒ 本次失败（h2 快路径不重试）。
    let bad = rt.query(&cfg, &make_query(0x4002), 5_000).await;
    assert!(!bad.ok, "被 RST_STREAM 的查询必须失败: {bad:?}");
    // #3 同一连接上继续成功。
    assert_answer(&rt.query(&cfg, &make_query(0x4003), 5_000).await, 0x4003);

    assert_eq!(
        ctl.conns.load(Ordering::SeqCst),
        1,
        "stream 级 RST 不得导致重连"
    );
    assert_eq!(ctl.requests.load(Ordering::SeqCst), 3);
    let st = rt.h2_stats();
    assert_eq!(st.conns_open, 1);
    assert_eq!(st.streams_total, 3);
    assert_eq!(st.streams_active, 0, "被重置的 stream 不得算作活跃");
    assert_eq!(st.goaway_total, 0, "RST_STREAM 不是 GOAWAY");
}

/// **超时（服务端不回）只失败该查询，连接不被污染**；且不泄漏 stream。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timeout_fails_query_without_poisoning_connection() {
    let (_dir, ca) = ca_file();
    let ctl = Arc::new(H2Ctl {
        special: (2, Action::Hang),
        ..H2Ctl::new()
    });
    let port = spawn_h2_server(ctl.clone()).await;
    let rt = rt_with_ca(&ca);
    let cfg = doh_cfg(port, &ca);

    assert_answer(&rt.query(&cfg, &make_query(0x5001), 5_000).await, 0x5001);
    let t0 = std::time::Instant::now();
    let bad = rt.query(&cfg, &make_query(0x5002), 400).await;
    assert!(!bad.ok, "超时必须失败: {bad:?}");
    assert!(
        t0.elapsed() < Duration::from_millis(2_500),
        "超时预算未生效：{:?}",
        t0.elapsed()
    );
    // 同一条连接继续可用（客户端 drop RecvStream ⇒ RST_STREAM(CANCEL)，连接不受影响）。
    assert_answer(&rt.query(&cfg, &make_query(0x5003), 5_000).await, 0x5003);
    assert_eq!(
        ctl.conns.load(Ordering::SeqCst),
        1,
        "超时不得触发重连（连接仍可用）"
    );
    let st = rt.h2_stats();
    assert_eq!(st.streams_active, 0, "超时后不得有活跃 stream 泄漏");
    assert_eq!(st.conns_open, 1);
}

/// **超大响应（>65535）与错误 content-type 都必须被拒绝，且连接保留。**
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_and_wrong_content_type_are_rejected() {
    let (_dir, ca) = ca_file();
    let ctl = Arc::new(H2Ctl {
        special: (2, Action::Oversize),
        ..H2Ctl::new()
    });
    // #2 = 超大、#3 = 错误 content-type 需要两个不同行为 → 用两个服务端分别验证。
    let port = spawn_h2_server(ctl.clone()).await;
    let rt = rt_with_ca(&ca);
    let cfg = doh_cfg(port, &ca);
    assert_answer(&rt.query(&cfg, &make_query(0x6001), 5_000).await, 0x6001);
    let big = rt.query(&cfg, &make_query(0x6002), 5_000).await;
    assert!(!big.ok, ">65535 的正文必须拒绝: {big:?}");
    assert_eq!(ctl.conns.load(Ordering::SeqCst), 1, "超大响应不得导致重连");
    assert_eq!(rt.h2_stats().streams_active, 0);

    // 错误 content-type：另一个服务端（第 2 个请求返回 text/plain）。
    let ctl2 = Arc::new(H2Ctl {
        special: (2, Action::BadContentType),
        ..H2Ctl::new()
    });
    let port2 = spawn_h2_server(ctl2.clone()).await;
    let rt2 = rt_with_ca(&ca);
    let cfg2 = doh_cfg(port2, &ca);
    assert_answer(&rt2.query(&cfg2, &make_query(0x6101), 5_000).await, 0x6101);
    let bad_ct = rt2.query(&cfg2, &make_query(0x6102), 5_000).await;
    assert!(
        !bad_ct.ok,
        "content-type 不含 application/dns-message 必须拒绝"
    );
    assert_eq!(
        ctl2.conns.load(Ordering::SeqCst),
        1,
        "错误 content-type 不得重连"
    );
    assert_answer(&rt2.query(&cfg2, &make_query(0x6103), 5_000).await, 0x6103);
}

/// **真实并发压测形状**：一条连接上 32 个并发查询（`upstream_max_inflight` 默认值），
/// 必须全部成功且只开 1 条连接（h2 复用带来的核心收益）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_handles_32_concurrent_queries_on_one_connection() {
    const N: usize = 32;
    let (_dir, ca) = ca_file();
    let ctl = Arc::new(H2Ctl {
        pad: 200,
        frames: 3,
        ..H2Ctl::new()
    });
    let port = spawn_h2_server(ctl.clone()).await;
    let rt = rt_with_ca(&ca);
    let cfg = doh_cfg(port, &ca);
    let futs = (0..N).map(|i| {
        let rt = rt.clone();
        let cfg = cfg.clone();
        let q = make_query(0x7000 + i as u16);
        async move { (0x7000 + i as u16, rt.query(&cfg, &q, 10_000).await) }
    });
    let outs = futures::future::join_all(futs).await;
    for (qid, out) in &outs {
        assert_answer(out, *qid);
    }
    assert_eq!(
        ctl.conns.load(Ordering::SeqCst),
        1,
        "32 并发仍应只开 1 条连接"
    );
    assert_eq!(ctl.requests.load(Ordering::SeqCst), N);
    let st = rt.h2_stats();
    assert_eq!(st.conns_open, 1);
    assert_eq!(st.streams_total, N as u64);
    assert_eq!(st.streams_active, 0);
}

/// **池状态与时序**：`discard`（上游删除）必须关闭该键的 h2 连接。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discard_closes_h2_connections() {
    let (_dir, ca) = ca_file();
    let ctl = Arc::new(H2Ctl::new());
    let port = spawn_h2_server(ctl.clone()).await;
    let rt = rt_with_ca(&ca);
    let cfg = doh_cfg(port, &ca);
    assert_answer(&rt.query(&cfg, &make_query(0x8001), 5_000).await, 0x8001);
    assert_eq!(rt.h2_stats().conns_open, 1);
    rt.discard(&cfg);
    // 连接被标记关闭并摘除（gauge 归零；驱动任务收到 close 信号后退出）。
    assert_eq!(rt.h2_stats().conns_open, 0, "discard 后不得残留 h2 连接");
    assert_eq!(rt.h2_key_stats(&cfg.pool_key()).transport, None);
    // 删除后同键再次查询仍可用（新连接、重新注册）—— delete + 重建不丢 h2 能力。
    let cfg2 = doh_cfg(port, &ca);
    assert_answer(&rt.query(&cfg2, &make_query(0x8002), 5_000).await, 0x8002);
    assert_eq!(rt.h2_stats().conns_open, 1);
}

/// **两台上游（不同端口）互不串流**：各自的连接/stream 计数独立。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_upstreams_have_independent_pools() {
    let (_dir, ca) = ca_file();
    let ctl_a = Arc::new(H2Ctl::new());
    let ctl_b = Arc::new(H2Ctl::new());
    let port_a = spawn_h2_server(ctl_a.clone()).await;
    let port_b = spawn_h2_server(ctl_b.clone()).await;
    let rt = rt_with_ca(&ca);
    let cfg_a = doh_cfg(port_a, &ca);
    let cfg_b = doh_cfg(port_b, &ca);
    let qa = make_query(0x9001);
    let qb = make_query(0x9002);
    let (a, b) = futures::join!(rt.query(&cfg_a, &qa, 5_000), rt.query(&cfg_b, &qb, 5_000));
    assert_answer(&a, 0x9001);
    assert_answer(&b, 0x9002);
    assert_eq!(ctl_a.conns.load(Ordering::SeqCst), 1);
    assert_eq!(ctl_b.conns.load(Ordering::SeqCst), 1);
    let st = rt.h2_stats();
    assert_eq!(st.conns_open, 2, "两台上游各 1 条 h2 连接");
    assert_eq!(st.streams_total, 2);
    assert_eq!(rt.h2_key_stats(&cfg_a.pool_key()).conns_open, 1);
    assert_eq!(rt.h2_key_stats(&cfg_b.pool_key()).conns_open, 1);
}
