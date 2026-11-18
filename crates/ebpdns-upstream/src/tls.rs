//! TLS 客户端策略（rustls，ring 提供者）。
//!
//! 本模块是出站加密上游（DoH / DoH3）**唯一**的 TLS 配置构造点：
//! - 协议版本下限：`tls_min_version`（`"1.2"` / `"1.3"`）；QUIC 恒 TLS 1.3；
//! - 根证书：系统 CA bundle（`tls_use_system_roots=true`，读不到时回退 webpki-roots）
//!   + 可选自定义 CA（`tls_ca_file`，PEM）；
//! - 证书校验：**始终**走 WebPKI 链校验 + 主机名/SAN 校验（没有关闭开关）；
//! - ALPN：本模块不写死协议，由传输层传入（DoH = `["h2","http/1.1"]`；DoH3 = `h3`）。
//!
//! **2.2.0 范围**：不做 SPKI pin（后续可选，且必须在链校验之后）。
//!
//! 错误文案按 TLS 失败阶段区分：`tls-chain` / `tls-hostname` / `tls-expired` /
//! `tls-version` / `tls-handshake`，便于日志与探针归因。

use std::sync::{Arc, OnceLock};

use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, Error as RustlsError, RootCertStore};

use crate::error::{UpstreamError, UpstreamResult};

/// `tls_min_version` 的合法值。
pub const TLS_MIN_12: &str = "1.2";
pub const TLS_MIN_13: &str = "1.3";

/// TLS 协议版本下限。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TlsMinVersion {
    #[default]
    Tls12,
    Tls13,
}

impl TlsMinVersion {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            TLS_MIN_12 => Some(Self::Tls12),
            TLS_MIN_13 => Some(Self::Tls13),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tls12 => TLS_MIN_12,
            Self::Tls13 => TLS_MIN_13,
        }
    }
}

/// 可在测试/嵌入场景注入的时钟？不需要：rustls 自带系统时间。
///
/// 每次构建 `ClientConfig` 时读取一次策略（`ResolverConfig` 每代持有独立 `Arc`）。
#[derive(Debug)]
pub struct TlsPolicy {
    /// 协议版本下限。
    pub min_version: TlsMinVersion,
    /// 是否使用系统 CA bundle；false 时只信 `ca_file`。
    pub use_system_roots: bool,
    /// 自定义 CA（PEM 路径；空 = 不额外加载）。
    pub ca_file: String,
    /// 根证书只加载一次（同一策略对象被所有上游共享）。
    roots: OnceLock<Result<Arc<RootCertStore>, String>>,
}

impl Default for TlsPolicy {
    fn default() -> Self {
        Self {
            min_version: TlsMinVersion::default(),
            use_system_roots: true,
            ca_file: String::new(),
            roots: OnceLock::new(),
        }
    }
}

impl TlsPolicy {
    /// 从配置字段构造（不做文件 I/O；根证书在首次建连时惰性加载）。
    pub fn from_config(
        min_version: &str,
        use_system_roots: bool,
        ca_file: &str,
    ) -> Result<Self, String> {
        let min_version = TlsMinVersion::parse(min_version)
            .ok_or_else(|| format!("tls_min_version 非法（允许 1.2 | 1.3）：{min_version:?}"))?;
        let ca_file = ca_file.trim().to_string();
        if !use_system_roots && ca_file.is_empty() {
            return Err(
                "tls_use_system_roots=false 时必须配置 tls_ca_file（否则没有任何信任根）".into(),
            );
        }
        Ok(Self {
            min_version,
            use_system_roots,
            ca_file,
            roots: OnceLock::new(),
        })
    }

    /// 校验配置（含自定义 CA 文件可读且至少含一张证书）。供 `check-config` 使用。
    pub fn validate(&self) -> Result<(), String> {
        if !self.ca_file.is_empty() {
            load_ca_file(&self.ca_file).map(|_| ())?;
        }
        Ok(())
    }

    /// 根证书集合（系统 + 自定义 CA；只加载一次）。
    pub fn roots(&self) -> UpstreamResult<Arc<RootCertStore>> {
        self.roots
            .get_or_init(|| self.load_roots().map(Arc::new))
            .clone()
            .map_err(UpstreamError::Tls)
    }

    fn load_roots(&self) -> Result<RootCertStore, String> {
        let mut store = RootCertStore::empty();
        let mut loaded = 0usize;
        if self.use_system_roots {
            let mut system = RootCertStore::empty();
            if let Some(path) = system_ca_bundle_path() {
                match load_ca_file(&path) {
                    Ok(certs) => {
                        loaded += certs.len();
                        for c in certs {
                            system
                                .add(c)
                                .map_err(|e| format!("加载系统根证书失败（{path}）：{e}"))?;
                        }
                    }
                    Err(e) => {
                        tracing::debug!(path = %path, error = %e, "系统 CA bundle 不可用，回退 webpki-roots");
                    }
                }
            }
            if system.is_empty() {
                // Linux 容器/精简镜像可能没有 CA bundle：回退到编译内置的 Mozilla 根，
                // 保证 DoH 仍可用。这里只打 debug（默认部署有 bundle，不制造噪声）。
                system.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            }
            store = system;
        }
        if !self.ca_file.is_empty() {
            for c in load_ca_file(&self.ca_file)? {
                store
                    .add(c)
                    .map_err(|e| format!("加载自定义 CA 失败（{}）：{e}", self.ca_file))?;
                loaded += 1;
            }
        }
        if store.is_empty() {
            return Err("信任根为空（检查 tls_use_system_roots / tls_ca_file）".into());
        }
        tracing::debug!(
            use_system_roots = self.use_system_roots,
            ca_file = %self.ca_file,
            roots = store.len(),
            loaded,
            "TLS 根证书已加载"
        );
        Ok(store)
    }
}

/// 系统 CA bundle 的候选路径（Linux 发行版；可用 `SSL_CERT_FILE` 覆盖）。
fn system_ca_bundle_path() -> Option<String> {
    if let Ok(p) = std::env::var("SSL_CERT_FILE") {
        if !p.trim().is_empty() {
            return Some(p);
        }
    }
    const CANDIDATES: &[&str] = &[
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/ssl/cert.pem",
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    ];
    CANDIDATES
        .iter()
        .find(|p| std::path::Path::new(p).is_file())
        .map(|p| (*p).to_string())
}

fn load_ca_file(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let pem = std::fs::read(path).map_err(|e| format!("读取 CA 文件失败（{path}）：{e}"))?;
    let mut out = Vec::new();
    for item in rustls_pemfile::certs(&mut &pem[..]) {
        let cert = item.map_err(|e| format!("解析 CA 文件失败（{path}）：{e}"))?;
        out.push(cert);
    }
    if out.is_empty() {
        return Err(format!("CA 文件不含任何 CERTIFICATE（{path}）"));
    }
    Ok(out)
}

fn ring_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// 构建 rustls 客户端配置。
///
/// `for_quic=true` 时强制 TLS 1.3（QUIC 的硬要求），并忽略 `tls_min_version` 的
/// “1.2” 取值（1.3 已满足“不低于 1.2”）。`alpn` 由传输层给出，本函数不覆写。
pub fn build_client_config(
    policy: &TlsPolicy,
    for_quic: bool,
    alpn: Vec<Vec<u8>>,
) -> UpstreamResult<Arc<ClientConfig>> {
    let roots = policy.roots()?;
    let provider = ring_provider();
    let versions: &[&'static rustls::SupportedProtocolVersion] = if for_quic {
        &[&rustls::version::TLS13]
    } else {
        match policy.min_version {
            TlsMinVersion::Tls12 => &[&rustls::version::TLS12, &rustls::version::TLS13],
            TlsMinVersion::Tls13 => &[&rustls::version::TLS13],
        }
    };
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|e| {
            UpstreamError::Tls(format!(
                "tls-version: 无法启用 TLS {:?}：{e}",
                versions.iter().map(|v| v.version).collect::<Vec<_>>()
            ))
        })?;
    let mut cfg = builder
        .with_root_certificates((*roots).clone())
        .with_no_client_auth();
    cfg.alpn_protocols = alpn;
    Ok(Arc::new(cfg))
}

/// 把主机名转成 rustls `ServerName`（SNI）。失败返回 Err（fail-closed）。
pub fn server_name(host: &str) -> UpstreamResult<ServerName<'static>> {
    use rustls::pki_types::IpAddr;
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        return Ok(ServerName::IpAddress(IpAddr::from(v4)));
    }
    if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        return Ok(ServerName::IpAddress(IpAddr::from(v6)));
    }
    let h = host.strip_prefix('[').unwrap_or(host);
    let h = h.strip_suffix(']').unwrap_or(h);
    let dn = rustls::pki_types::DnsName::try_from(h.to_string())
        .map_err(|_| UpstreamError::Tls(format!("invalid server name: {host}")))?;
    Ok(ServerName::DnsName(dn))
}

/// 把 rustls 握手错误翻译成**可归因**的稳定前缀。
pub fn describe_tls_error(e: &RustlsError) -> String {
    use rustls::CertificateError as CE;
    match e {
        RustlsError::InvalidCertificate(ce) => match ce {
            CE::Expired | CE::ExpiredContext { .. } => "tls-expired: 服务器证书已过期".to_string(),
            CE::NotValidYet | CE::NotValidYetContext { .. } => {
                "tls-expired: 服务器证书尚未生效".to_string()
            }
            CE::NotValidForName | CE::NotValidForNameContext { .. } => {
                "tls-hostname: 证书与上游主机名不匹配".to_string()
            }
            CE::UnknownIssuer => "tls-chain: 证书链无法追溯到受信 CA（未知签发者）".to_string(),
            CE::BadSignature => "tls-chain: 证书签名校验失败".to_string(),
            CE::BadEncoding => "tls-chain: 证书编码非法".to_string(),
            CE::Revoked => "tls-chain: 证书已被吊销".to_string(),
            other => format!("tls-cert: {other:?}"),
        },
        RustlsError::General(s) if s.contains("tls-pin") => s.clone(),
        RustlsError::PeerIncompatible(p) => format!("tls-version: 协议/能力不兼容：{p:?}"),
        RustlsError::AlertReceived(rustls::AlertDescription::ProtocolVersion) => {
            "tls-version: 对端拒绝协商的 TLS 版本（例如 min 1.3 连接仅支持 1.2 的服务端）"
                .to_string()
        }
        RustlsError::PeerMisbehaved(p) => format!("tls-protocol: 对端协议违规：{p:?}"),
        other => format!("tls-handshake: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_version_parsing_is_strict() {
        assert_eq!(TlsMinVersion::parse("1.2"), Some(TlsMinVersion::Tls12));
        assert_eq!(TlsMinVersion::parse(" 1.3 "), Some(TlsMinVersion::Tls13));
        assert_eq!(TlsMinVersion::parse("1.1"), None);
        assert_eq!(TlsMinVersion::parse("TLS1.3"), None);
    }

    #[test]
    fn policy_requires_roots() {
        assert!(TlsPolicy::from_config("1.2", false, "").is_err());
        assert!(TlsPolicy::from_config("1.1", true, "").is_err());
        assert!(TlsPolicy::from_config("1.2", true, "").is_ok());
    }

    #[test]
    fn tls_error_messages_are_classified() {
        use rustls::CertificateError as CE;
        for (ce, want) in [
            (CE::Expired, "tls-expired"),
            (CE::NotValidYet, "tls-expired"),
            (CE::NotValidForName, "tls-hostname"),
            (CE::UnknownIssuer, "tls-chain"),
            (CE::BadSignature, "tls-chain"),
        ] {
            let got = describe_tls_error(&RustlsError::InvalidCertificate(ce));
            assert!(got.starts_with(want), "{got} 必须以 {want} 开头");
        }
    }
}
