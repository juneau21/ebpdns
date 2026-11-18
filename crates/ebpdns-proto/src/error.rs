//! `ProtoError`：DNS 协议编解码错误。
//!
//! 数据面/解析遇到畸形输入 → 返回 [`Err`] 或显式跳过（fail-closed），
//! 绝不 panic、绝不产出错误数据。

/// DNS 协议编解码错误。
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ProtoError {
    /// 报文长度不足 / 结构非法。
    #[error("malformed message: {0}")]
    Malformed(String),

    /// 截断：定长字段、rdata 或名称越过报文末尾。
    #[error("truncated: {0}")]
    Truncated(String),

    /// 非法域名：标签过长、展开名过长、压缩指针环/前向指针/非法标签位。
    #[error("invalid name: {0}")]
    InvalidName(String),

    /// 非法 rdata（A/AAAA 长度不符、SOA rdlen 过小等）。
    #[error("invalid rdata: {0}")]
    InvalidRdata(String),

    /// 不支持的记录类型（仅用于需要显式区分的路径）。
    #[error("unsupported type: {0}")]
    Unsupported(u16),
}

impl ProtoError {
    pub fn malformed(msg: impl Into<String>) -> Self {
        Self::Malformed(msg.into())
    }
    pub fn truncated(msg: impl Into<String>) -> Self {
        Self::Truncated(msg.into())
    }
    pub fn invalid_name(msg: impl Into<String>) -> Self {
        Self::InvalidName(msg.into())
    }
    pub fn invalid_rdata(msg: impl Into<String>) -> Self {
        Self::InvalidRdata(msg.into())
    }
}
