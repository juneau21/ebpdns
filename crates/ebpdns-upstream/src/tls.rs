//! TLS 客户端配置构建（tokio-rustls，ring 提供者）。
//!
//! **[历史归因]** 口径对齐 Python，且始终 fail-closed：
//! - 严格模式：`RootCertStore` + 标准主机名/SAN 校验。
//! - 链校验模式（`strict_cert=false`）：**仍校验证书链与主机名/SAN**——本 crate 不把证书校验
//!   降级到"只验链不验名"，更绝不降到完全不校验；取不到对端证书即握手失败。
//!   （即：关闭 strict 不会削弱安全性，只允许换用自定义根证书。）

use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore};

use crate::error::{UpstreamError, UpstreamResult};

/// webpki 根证书库。
pub fn webpki_root_store() -> RootCertStore {
    let mut store = RootCertStore::empty();
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    store
}

fn ring_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::ring::default_provider()
}

/// 构建 DoT/DoH 用的 rustls 客户端配置。
///
/// `strict` 保留以对齐配置语义；无论真假，均用给定根做链 + 名校验（fail-closed）。
/// `roots` 为空时使用 webpki 系统根。
pub fn build_client_config_with_roots(
    strict: bool,
    roots: RootCertStore,
) -> UpstreamResult<Arc<ClientConfig>> {
    let _ = strict;
    let provider = ring_provider();
    let cfg = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| UpstreamError::Tls(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// 用 webpki 系统根构建客户端配置。
pub fn build_client_config(strict: bool) -> UpstreamResult<Arc<ClientConfig>> {
    build_client_config_with_roots(strict, webpki_root_store())
}

/// 把主机名转成 rustls `ServerName`（SNI）。失败返回 Err（fail-closed）。
pub fn server_name(host: &str) -> UpstreamResult<rustls::pki_types::ServerName<'static>> {
    use rustls::pki_types::IpAddr;
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        return Ok(rustls::pki_types::ServerName::IpAddress(IpAddr::from(v4)));
    }
    if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        return Ok(rustls::pki_types::ServerName::IpAddress(IpAddr::from(v6)));
    }
    let h = host.strip_prefix('[').unwrap_or(host);
    let h = h.strip_suffix(']').unwrap_or(h);
    let dn = rustls::pki_types::DnsName::try_from(h.to_string())
        .map_err(|_| UpstreamError::Tls(format!("invalid server name: {host}")))?;
    Ok(rustls::pki_types::ServerName::DnsName(dn))
}
