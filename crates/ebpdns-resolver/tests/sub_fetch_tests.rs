//! 订阅拉取 HTTP(S) 确定性测试：本地 rustls(ring) 端点，openssl 自签证书。
//! 不联网：成功路径注入自签根；证书/主机校验失败路径 fail-closed。

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ebpdns_resolver::background::{
    fetch_sub_text, fetch_sub_text_allow_private_for_test, fetch_sub_text_with_trust,
};
use rustls::pki_types::PrivateKeyDer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const BODY: &str = r#"{"subscriptions":[{"action":"block","rules":[{"match":"ads.test"}]}]}"#;

fn http_200() -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        BODY.len(),
        BODY
    )
}

/// openssl 生成自签证书（CN/SAN=cn）。返回 (cert_pem, key_pem)。
fn gen_self_signed(dir: &Path, cn: &str) -> (Vec<u8>, Vec<u8>) {
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    let out = std::process::Command::new("openssl")
        .args(["req", "-x509", "-newkey", "rsa:2048", "-noenc", "-keyout"])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .arg("-days")
        .arg("1")
        .arg("-subj")
        .arg(format!("/CN={cn}"))
        .arg("-addext")
        .arg(format!("subjectAltName=DNS:{cn},IP:127.0.0.1"))
        .arg("-addext")
        .arg("basicConstraints=CA:FALSE")
        .arg("-addext")
        .arg("keyUsage=digitalSignature,keyEncipherment")
        .arg("-addext")
        .arg("extendedKeyUsage=serverAuth")
        .output()
        .expect("openssl 应可用");
    assert!(
        out.status.success(),
        "openssl 生成证书失败: {:?}",
        out.stderr
    );
    (std::fs::read(&cert).unwrap(), std::fs::read(&key).unwrap())
}

/// 读请求直到 header 结束（\r\n\r\n），避免 read_to_end 死锁。
async fn read_request<IO: AsyncReadExt + AsyncWriteExt + Unpin>(
    io: &mut IO,
) -> std::io::Result<()> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 256];
    while !buf.ends_with(b"\r\n\r\n") {
        let n = io.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(())
}

/// 起一个本地 HTTPS 服务，固定返回 `resp`。返回端口。
async fn serve_https(cert: Vec<u8>, key: Vec<u8>, resp: String) -> u16 {
    let certs: Vec<_> = rustls_pemfile::certs(&mut &cert[..])
        .collect::<Result<_, _>>()
        .unwrap();
    let key_der: PrivateKeyDer<'_> = rustls_pemfile::private_key(&mut &key[..]).unwrap().unwrap();
    let provider = rustls::crypto::ring::default_provider();
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key_der)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acc = acceptor.clone();
            let resp = resp.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acc.accept(tcp).await else {
                    return;
                };
                let _ = read_request(&mut tls).await;
                let _ = tls.write_all(resp.as_bytes()).await;
            });
        }
    });
    port
}

#[tokio::test]
async fn test_https_fetch_success_with_self_signed_trust() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = gen_self_signed(dir.path(), "localhost");
    let port = serve_https(cert.clone(), key, http_200()).await;
    let url = format!("https://localhost:{port}/rules");
    let body = tokio::time::timeout(
        Duration::from_secs(5),
        fetch_sub_text_allow_private_for_test(&url, Some(&cert)),
    )
    .await
    .expect("应超时内返回")
    .expect("https 自签端点+信任根应拉取成功");
    assert!(body.contains("ads.test"), "body={body}");
}

#[tokio::test]
async fn test_https_untrusted_cert_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = gen_self_signed(dir.path(), "localhost");
    let port = serve_https(cert, key, http_200()).await;
    let url = format!("https://localhost:{port}/rules");
    // webpki 根不信任自签 → TLS 握手失败，绝不降级。
    let res = tokio::time::timeout(
        Duration::from_secs(5),
        fetch_sub_text_with_trust(&url, None),
    )
    .await
    .expect("应超时内返回");
    assert!(res.is_err(), "自签未受信任应 fail-closed: {res:?}");
}

#[tokio::test]
async fn test_https_hostname_mismatch_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    // 证书只签 example.com，客户端连 localhost → 名校验失败。
    let (cert, key) = gen_self_signed(dir.path(), "example.com");
    let port = serve_https(cert.clone(), key, http_200()).await;
    let url = format!("https://localhost:{port}/rules");
    let res = tokio::time::timeout(
        Duration::from_secs(5),
        fetch_sub_text_with_trust(&url, Some(&cert)),
    )
    .await
    .expect("应超时内返回");
    assert!(res.is_err(), "主机名校验应失败: {res:?}");
}

#[tokio::test]
async fn test_http_local_server_success() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tcp = tcp;
        let _ = read_request(&mut tcp).await;
        let _ = tcp.write_all(http_200().as_bytes()).await;
    });
    let url = format!("http://127.0.0.1:{port}/rules");
    let body = fetch_sub_text_allow_private_for_test(&url, None)
        .await
        .expect("本地 http(跳过ssrf测试 seam) 应成功");
    assert!(body.contains("ads.test"), "body={body}");
}

#[tokio::test]
async fn test_ssrf_refuses_loopback() {
    // 生产 fetch_sub_text 开启 SSRF：loopback 私网地址必须 fail-closed 拒绝。
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (_tcp, _) = listener.accept().await.unwrap();
    });
    let url = format!("http://127.0.0.1:{port}/rules");
    let res = fetch_sub_text(&url).await;
    assert!(res.is_err(), "loopback 应被 SSRF 校验拒绝: {res:?}");
}

#[tokio::test]
async fn test_http_redirect_fail_closed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tcp = tcp;
        let _ = read_request(&mut tcp).await;
        let resp = "HTTP/1.1 302 Found\r\nLocation: http://evil.example/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = tcp.write_all(resp.as_bytes()).await;
    });
    let url = format!("http://127.0.0.1:{port}/rules");
    let res = fetch_sub_text(&url).await;
    assert!(res.is_err(), "重定向应 fail-closed: {res:?}");
}

#[tokio::test]
async fn test_ssrf_refuses_cgnat() {
    // 订阅生产 SSRF：CGNAT 100.64/10 也必须 fail-closed（在私网基础上额外拒绝）。
    let res = fetch_sub_text("http://100.64.0.1:8080/rules").await;
    assert!(res.is_err(), "CGNAT 地址应被订阅 SSRF 拒绝: {res:?}");
}
