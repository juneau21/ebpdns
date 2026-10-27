//! **[历史归因]** ebpdns-proto：DNS 报文编解码，忠实对齐 Python `dnsmsg.py`。
//!
//! 模块布局：
//! - [`error`]：`ProtoError`
//! - [`constants`]：TYPE / CLASS / RCODE / OPCODE / EDNS option 常量与默认值
//! - [`name`]：域名编解码（含压缩指针）
//! - [`rdata`]：`RData` 枚举与 rdata 编解码
//! - [`record`]：`ResourceRecord`
//! - [`message`]：`Message` 与 `parse_message`
//! - [`query`]：`build_query` / `random_case_name` / `extract_qname` / `check_0x20`
//! - [`edns`]：OPT/EDNS0 解析构造、ECS、Padding 对齐、bufsize 钳制
//! - [`response`]：响应构造族
//! - [`tcp`]：DNS over TCP 长度前缀帧

pub mod constants;
pub mod edns;
pub mod error;
pub mod message;
pub mod name;
pub mod query;
pub mod rdata;
pub mod record;
pub mod response;
pub mod tcp;

pub use error::ProtoError;

/// 结果别名：数据面错误一律用 [`ProtoError`]。
pub type ProtoResult<T> = Result<T, ProtoError>;
