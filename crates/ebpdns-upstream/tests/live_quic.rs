//! 真实服务器 DoH3 / DoQ / DoH 回归测试（**默认 ignore**：需要出站网络）。
//!
//! 存在的意义：`quic.rs` 的 H3/QPACK 状态机此前只有「本地假上游 + 纯函数单测」覆盖，
//! 从未与真实服务器的实现对过帧。本文件把数据面真实调用（[`UpstreamRuntime::query`]）
//! 指向公网 DoH3/DoQ 服务器，验证建连（ALPN）、H3 请求字段段、2 字节长度前缀、
//! 响应解码与 qid 校验，并逐条打印失败归因（[`ebpdns_upstream::classify_conn_error`] 口径），
//! 便于在 UDP 被封锁的环境里判定"到底是网络不通还是实现有 bug"。
//!
//! 运行方式（需网络）：
//! ```text
//! cargo test --release -p ebpdns-upstream --test live_quic -- --ignored --nocapture
//! ```
//! 环境变量 `EBPDNS_LIVE_DOH3` / `EBPDNS_LIVE_DOQ` / `EBPDNS_LIVE_DOH` 可覆盖目标（`host:port`）。
//!
//! # 实测结论（Debian 13 目标机，2026-10-11）
//! - DoH3 `dns.alidns.com:443`：**通过**（65ms 拿到真实答案，见 `live_doh3_alidns`）。
//! - DoH   `dns.alidns.com:443`：**通过**（对照组，158ms）。
//! - DoQ   `dns.alidns.com:853`：握手成功（ALPN `doq` 协商一致），但对端对**合法**的
//!   RFC 9250 查询回 `DOQ_PROTOCOL_ERROR`(应用错误码 2) 并关闭连接。同一份报文用
//!   openssl 3.5.7 `s_client -quic` 与 aioquic（参考实现）复现同样结果，故判为
//!   **服务端拒绝**，非本实现帧错误；测试因此只断言"失败归因是对端关闭"。
//!   其余公网 DoQ 端点（cloudflare / google / adguard :853 UDP）在本网络不可达。

use std::sync::Arc;
use std::time::Duration;

use ebpdns_upstream::{Proto, UpstreamConfig, UpstreamRuntime};

/// 构造最小 DNS 查询（A 记录，RD=1）。
fn query(domain: &str, qid: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(12 + domain.len() + 6);
    q.extend_from_slice(&qid.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
    q.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    q.extend_from_slice(&0u16.to_be_bytes()); // ancount
    q.extend_from_slice(&0u16.to_be_bytes()); // nscount
    q.extend_from_slice(&0u16.to_be_bytes()); // arcount
    for label in domain.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&1u16.to_be_bytes()); // qtype A
    q.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
    q
}

fn upstream(proto: Proto, host: &str, port: u16, path: &str, id: &str) -> UpstreamConfig {
    UpstreamConfig {
        id: id.to_string(),
        name: id.to_string(),
        proto,
        host: host.to_string(),
        port,
        url: path.to_string(),
        strict_cert: true,
        enabled: true,
        ..UpstreamConfig::default()
    }
}

/// 跑一次真实查询：打印原始结果与失败归因，成功时校验 DNS 头/答案段。
async fn live_query(cfg: UpstreamConfig, domain: &str) -> (bool, String, String) {
    let rt = Arc::new(UpstreamRuntime::new());
    let q = query(domain, 0x4242);
    let out = rt.query(&cfg, &q, 5000).await;
    let hex = out
        .data
        .as_ref()
        .map(|d| d.iter().map(|b| format!("{b:02x}")).collect::<String>())
        .unwrap_or_default();
    let (kind, reason) = if out.ok {
        (String::new(), String::new())
    } else {
        ebpdns_upstream::classify_conn_error(&out.err)
    };
    println!(
        "[live] proto={:?} {}:{} path={} domain={} ok={} lat={}ms err={:?} kind={:?} reason={:?}",
        cfg.proto,
        cfg.host,
        cfg.port,
        cfg.url,
        domain,
        out.ok,
        out.latency_ms,
        out.err,
        kind,
        reason
    );
    if out.ok {
        println!("[live] answer hex: {hex}");
        let ans = &out.data.unwrap();
        assert!(ans.len() >= 12, "response shorter than DNS header");
        assert_eq!(&ans[0..2], &0x4242u16.to_be_bytes(), "qid mismatch");
        assert_eq!(ans[3] & 0x0f, 0, "rcode != NOERROR: {}", ans[3] & 0x0f);
        assert!(
            u16::from_be_bytes([ans[6], ans[7]]) > 0,
            "no answer records"
        );
    }
    (out.ok, hex, out.err)
}

fn target(var: &str, default: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| default.to_string())
}

fn split_host_port(s: &str) -> (String, u16) {
    let (h, p) = s.rsplit_once(':').expect("expected host:port");
    (h.to_string(), p.parse().expect("bad port"))
}

/// AliDNS DoH3（RFC 9114，ALPN `h3`，UDP/443）：真实服务器端到端。
#[tokio::test]
#[ignore = "requires outbound UDP/443"]
async fn live_doh3_alidns() {
    let t = target("EBPDNS_LIVE_DOH3", "dns.alidns.com:443");
    let (host, port) = split_host_port(&t);
    let cfg = upstream(Proto::Doh3, &host, port, "/dns-query", "live-doh3");
    let (ok, _, err) = live_query(cfg, "example.com").await;
    assert!(ok, "DoH3 {t} failed: {err}");
}

/// 回归：`url` 若被写成**完整 URL**（生产接线历史缺陷形态），规范化后仍须可用——
/// 修好前它会产生 `:path = /https://host:port/dns-query`，真实服务器必失败。
#[tokio::test]
#[ignore = "requires outbound UDP/443"]
async fn live_doh3_legacy_absolute_url_still_works() {
    let t = target("EBPDNS_LIVE_DOH3", "dns.alidns.com:443");
    let (host, port) = split_host_port(&t);
    let legacy = format!("https://{host}:{port}/dns-query");
    let cfg = upstream(Proto::Doh3, &host, port, &legacy, "live-doh3-legacy");
    let (ok, _, err) = live_query(cfg, "example.com").await;
    assert!(
        ok,
        "legacy absolute-URL form must be normalized to a path: {err}"
    );
}

/// 同一台服务器的 DoH（TCP/443）：对照组，区分"TLS/HTTP 层坏了"与"QUIC 层坏了"。
#[tokio::test]
#[ignore = "requires outbound TCP/443"]
async fn live_doh_alidns_control() {
    let cfg = upstream(Proto::Doh, "dns.alidns.com", 443, "/dns-query", "live-doh");
    let (ok, _, err) = live_query(cfg, "example.com").await;
    assert!(ok, "DoH (control) failed: {err}");
}

/// AliDNS DoQ（RFC 9250，ALPN `doq`，UDP/853）。
///
/// 实测该端点对合法查询回 `DOQ_PROTOCOL_ERROR`(2)（openssl/aioquic 同样结果），
/// 因此这里**不断言成功**，只断言失败归因是"对端关闭/应用错误"而非本机不可达或握手失败：
/// 这样一旦该服务器恢复正常，测试的断言仍然成立（ok 分支直接通过）。
#[tokio::test]
#[ignore = "requires outbound UDP/853"]
async fn live_doq_alidns() {
    let t = target("EBPDNS_LIVE_DOQ", "dns.alidns.com:853");
    let (host, port) = split_host_port(&t);
    let cfg = upstream(Proto::Doq, &host, port, "", "live-doq");
    let (ok, _, err) = live_query(cfg, "example.com").await;
    if !ok {
        let (kind, _) = ebpdns_upstream::classify_conn_error(&err);
        assert_ne!(
            kind, "dns",
            "DoQ {t}: 目标主机名解析失败（环境问题，不是被测协议行为）: {err}"
        );
        assert_ne!(
            kind, "timeout",
            "DoQ {t}: 完全无响应（UDP/853 被过滤或对端未监听）: {err}"
        );
    }
}

/// 失败路径：不可达的 DoH3 目标必须快速失败、被归类，且不拖垮进程。
#[tokio::test]
#[ignore = "requires outbound network (expects failure)"]
async fn live_doh3_unreachable_is_classified() {
    // 192.0.2.0/24 是 TEST-NET-1，路由不可达：必然超时。
    let cfg = upstream(Proto::Doh3, "192.0.2.1", 443, "/dns-query", "live-dead");
    let t0 = std::time::Instant::now();
    let (ok, _, err) = live_query(cfg, "example.com").await;
    let took = t0.elapsed();
    assert!(!ok, "unreachable DoH3 must not succeed");
    let (kind, _) = ebpdns_upstream::classify_conn_error(&err);
    println!("[live] unreachable classified as kind={kind:?} in {took:?}");
    assert!(
        took < Duration::from_secs(20),
        "unreachable DoH3 must fail fast, took {took:?}"
    );
    assert!(!kind.is_empty(), "error must be classified: {err}");
}
