//! **2.1.50（P0-4）**：TLS 策略端到端用例（真实本地 TLS 服务端，无外网）。
//!
//! **2.2.0**：覆盖 min 1.2/1.3、自定义 CA 生效、错误 CA 拒绝、主机名不匹配、
//! CA 文件非法、IP SAN。证书夹具由 `tests/fixtures/` 提供（自签 CA1/CA2 +
//! localhost/127.0.0.1 SAN 的服务器证书）。
//!
//! **不做 SPKI pin**（2.2.0 范围外）：没有 pin 参数，也就没有"pin 覆盖链校验"路径。

use std::sync::Arc;
use std::time::Duration;

use ebpdns_upstream::tls::{self, TlsMinVersion, TlsPolicy};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const CA1: &[u8] = include_bytes!("fixtures/ca1.pem");
const CA2: &[u8] = include_bytes!("fixtures/ca2.pem");
const SERVER1_CERT: &[u8] = include_bytes!("fixtures/server1.pem");
const SERVER1_KEY: &[u8] = include_bytes!("fixtures/server1.key");

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

fn server_config(
    versions: &[&'static rustls::SupportedProtocolVersion],
    cert: &[u8],
    key: &[u8],
) -> Arc<ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .expect("测试服务端协议版本可用")
        .with_no_client_auth()
        .with_single_cert(load_certs(cert), load_key(key))
        .expect("测试证书/私钥必须匹配");
    Arc::new(cfg)
}

/// 起一个只接受一条连接的本地 TLS 服务端，返回端口。
async fn spawn_tls_server(
    versions: &[&'static rustls::SupportedProtocolVersion],
    cert: &'static [u8],
    key: &'static [u8],
) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acceptor = TlsAcceptor::from(server_config(versions, cert, key));
    tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            let _ = acceptor.accept(tcp).await; // 握手失败也算用例结果
        }
    });
    port
}

fn write_ca(pem: &[u8]) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("ca.pem");
    std::fs::write(&path, pem).expect("写 CA 文件");
    (dir, path.display().to_string())
}

fn policy(min: TlsMinVersion, ca_file: String) -> TlsPolicy {
    TlsPolicy::from_config(min.as_str(), false, &ca_file).expect("测试策略必须合法")
}

/// 尝试用给定策略连接 `server_name`，返回错误字符串（成功时为空）。
async fn try_connect(policy: &TlsPolicy, port: u16, server_name: &str) -> Result<(), String> {
    let cfg = tls::build_client_config(policy, false, vec![]).map_err(|e| e.to_string())?;
    let connector = TlsConnector::from(cfg);
    let tcp = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect(("127.0.0.1", port)),
    )
    .await
    .map_err(|_| "tcp connect timeout".to_string())?
    .map_err(|e| format!("tcp connect: {e}"))?;
    let sni = tls::server_name(server_name).map_err(|e| e.to_string())?;
    match tokio::time::timeout(Duration::from_secs(3), connector.connect(sni, tcp)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => {
            let described = e
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<rustls::Error>())
                .map(tls::describe_tls_error)
                .unwrap_or_else(|| e.to_string());
            Err(described)
        }
        Err(_) => Err("tls handshake timeout".to_string()),
    }
}

#[tokio::test]
async fn custom_ca_accepts_and_wrong_ca_is_rejected() {
    let (_d1, ca1) = write_ca(CA1);
    let (_d2, ca2) = write_ca(CA2);

    // 自定义 CA1 + server1（CA1 签发）⇒ 成功。
    let port = spawn_tls_server(
        &[&rustls::version::TLS12, &rustls::version::TLS13],
        SERVER1_CERT,
        SERVER1_KEY,
    )
    .await;
    let p1 = policy(TlsMinVersion::Tls12, ca1.clone());
    try_connect(&p1, port, "localhost")
        .await
        .expect("CA1 必须能验证 CA1 签发的 server1");
    // 同一个证书：换错误 CA2 ⇒ 必须拒绝且归因为链校验（另起一条服务端连接）。
    let port2 = spawn_tls_server(
        &[&rustls::version::TLS12, &rustls::version::TLS13],
        SERVER1_CERT,
        SERVER1_KEY,
    )
    .await;
    let p2 = policy(TlsMinVersion::Tls12, ca2);
    let err = try_connect(&p2, port2, "localhost")
        .await
        .expect_err("错误 CA 必须拒绝连接");
    assert!(
        err.starts_with("tls-chain"),
        "错误 CA 的失败原因必须归因到链校验，实际：{err}"
    );
}

#[tokio::test]
async fn tls13_min_rejects_tls12_only_server() {
    let (_d, ca) = write_ca(CA1);
    // 服务端只支持 TLS 1.2。
    let port12 = spawn_tls_server(&[&rustls::version::TLS12], SERVER1_CERT, SERVER1_KEY).await;
    let p12 = policy(TlsMinVersion::Tls12, ca.clone());
    try_connect(&p12, port12, "localhost")
        .await
        .expect("min=1.2 必须能连 TLS1.2 服务端");

    // 同端口已被上面用掉（one-shot listener）；重起一个 TLS1.2-only 服务端测 min=1.3。
    let port12b = spawn_tls_server(&[&rustls::version::TLS12], SERVER1_CERT, SERVER1_KEY).await;
    let p13 = policy(TlsMinVersion::Tls13, ca);
    let err = try_connect(&p13, port12b, "localhost")
        .await
        .expect_err("min=1.3 必须拒绝 TLS1.2-only 服务端");
    assert!(
        err.starts_with("tls-version") || err.contains("protocol version"),
        "版本不匹配必须归因到 tls-version，实际：{err}"
    );
}

#[tokio::test]
async fn hostname_mismatch_is_rejected_and_classified() {
    let (_d, ca) = write_ca(CA1);
    let port = spawn_tls_server(
        &[&rustls::version::TLS12, &rustls::version::TLS13],
        SERVER1_CERT,
        SERVER1_KEY,
    )
    .await;
    let p = policy(TlsMinVersion::Tls12, ca);
    let err = try_connect(&p, port, "wrong.example")
        .await
        .expect_err("主机名不匹配必须拒绝");
    assert!(
        err.starts_with("tls-hostname"),
        "主机名不匹配必须归因到 tls-hostname，实际：{err}"
    );
}

#[tokio::test]
async fn invalid_ca_file_is_rejected_at_build_time() {
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("bad.pem");
    std::fs::write(&bad, b"not a pem").unwrap();
    let p = TlsPolicy::from_config("1.2", false, &bad.display().to_string()).unwrap();
    let err = tls::build_client_config(&p, false, vec![]).unwrap_err();
    assert!(err.to_string().contains("CA 文件"), "{err}");

    // 合法 CA + 合法策略 ⇒ 可构建（没有 pin，也就没有"pin 非法"分支）。
    let (_d, ca) = write_ca(CA1);
    let p = policy(TlsMinVersion::Tls12, ca);
    assert!(tls::build_client_config(&p, false, vec![]).is_ok());
}

/// **IP 钉死语义**：连接目标是解析出来的 IP，TLS 的 SNI/证书校验仍用**主机名**。
///
/// 这里用 `127.0.0.1` 直接验证 IP SAN 分支（等价于"解析结果 = 127.0.0.1，SNI = localhost"
/// 时的证书校验目标）；`bootstrap` 单测另验证解析结果本身。
#[tokio::test]
async fn ip_target_uses_ip_san_and_custom_ca() {
    let (_d, ca) = write_ca(CA1);
    let port = spawn_tls_server(
        &[&rustls::version::TLS12, &rustls::version::TLS13],
        SERVER1_CERT,
        SERVER1_KEY,
    )
    .await;
    let p = policy(TlsMinVersion::Tls12, ca);
    try_connect(&p, port, "127.0.0.1")
        .await
        .expect("证书含 IP SAN 127.0.0.1 ⇒ 以 IP 为目标必须通过");
}
