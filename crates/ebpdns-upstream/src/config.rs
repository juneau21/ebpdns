//! **[历史归因]** 上游配置：对齐 Python 上游 dict 的字段与默认值。

use crate::addr::Proto;

/// **[历史归因]** 单个上游的运行时配置（忠实对齐 Python `up.get(...)` 的字段读取口径）。
#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    /// 上游 id（0x20 降级态 / 统计的键）。
    pub id: String,
    pub name: String,
    pub proto: Proto,
    /// 上游主机（hostname 或 IP 字面量，已剥离 `[`）。
    pub host: String,
    pub port: u16,
    /// DoH/DoH3/DoQ 路径（其余协议为空串）。
    pub url: String,
    /// 权重（0-1000，排序时 eff_lat / max(1,weight)）。默认 1。
    pub weight: u32,
    /// 是否启用证书主机名/SAN 强校验。缺省 true（安全方向）。
    /// 关闭后仅校验证书链（IP 字面量场景），即弃不入池。
    pub strict_cert: bool,
    /// 是否允许私有/环回 IP 应答（rebinding 防护豁免）。缺省 false（fail-closed）。
    pub allow_private_ip: bool,
    /// bootstrap DNS（形如 `1.2.3.4:53` 或 `[v6]:53`），用于域名上游解析。
    pub bootstrap: Option<String>,
    /// 静态基础延迟（ms），无实测时使用。默认 5000。
    pub latency: u32,
    /// 是否已实测。
    pub latency_measured: bool,
    pub enabled: bool,
}

impl UpstreamConfig {
    /// **[历史归因]** 连接池 / QUIC 管理器键：`(proto, host, port, path)`，对齐 Python `_pool` key。
    pub fn pool_key(&self) -> (String, String, u16, String) {
        (
            self.proto.as_str().to_string(),
            self.host.clone(),
            self.port,
            self.url.clone(),
        )
    }
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        UpstreamConfig {
            id: String::new(),
            name: String::new(),
            proto: Proto::Udp,
            host: String::new(),
            port: 53,
            url: String::new(),
            weight: 1,
            strict_cert: true,
            allow_private_ip: false,
            bootstrap: None,
            latency: 5000,
            latency_measured: false,
            enabled: true,
        }
    }
}
