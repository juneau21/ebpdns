//! `UpstreamError`：上游数据面错误。
//!
//! 数据面/解析遇到畸形输入 → 返回 [`Err`] 或显式失败（fail-closed），绝不 panic、
//! 绝不产出错误数据。生产路径禁止 `unwrap`/`expect`/`panic!`。

/// 上游配置/解析/收发错误。
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    /// **[历史归因]** 上游地址无法识别（对齐 Python `parse_upstream_addr` 返回 None）。
    #[error("invalid upstream address: {0}")]
    InvalidAddr(String),

    /// 配置非法（未知协议 / 端口越界 / host 字符集非法等）。
    #[error("invalid upstream config: {0}")]
    InvalidConfig(String),

    /// DNS 协议编解码错误（透传 ebpdns-proto）。
    #[error(transparent)]
    Proto(#[from] ebpdns_proto::ProtoError),

    /// TLS / 证书错误（fail-closed）。
    #[error("tls error: {0}")]
    Tls(String),

    /// I/O 错误。
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// QUIC 传输错误。
    #[error("quic error: {0}")]
    Quic(String),
}

/// 上游结果别名。
pub type UpstreamResult<T> = Result<T, UpstreamError>;
