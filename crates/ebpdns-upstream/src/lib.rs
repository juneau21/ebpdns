//! ebpdns-upstream：六协议上游 + 连接池 + 健康检查/测速 + bootstrap。
//!
//! **[历史归因]** 忠实对齐 Python `upstream.py`（UDP/TCP/DoH/DoT）、`quic_upstream.py`（DoQ/DoH3 状态机）、
//! `probe.py`（首测/测速）。统一入口 [`UpstreamRuntime::query`] 返回 [`QueryOutcome`] 四元组，
//! **[历史归因]** 对齐 Python `(ok, response_bytes, latency_ms, err_str)`。
//!
//! # 模块布局
//! - [`error`]：`UpstreamError`
//! - [`addr`]：`Proto` 枚举、`parse_upstream_addr`、`is_hostname`、`is_private_ip`
//! - [`config`]：`UpstreamConfig`
//! - [`header_check`]：`is_header_only`、0x20 自适应降级状态机
//! - [`tls`]：rustls（ring）客户端配置（严格 / 仅链校验）
//! - [`udp`] / [`tcp`] / [`dot`] / [`doh`] / [`quic`]：六协议收发
//! - [`pool`]：DoH/DoT 有界连接复用池
//! - [`health`]：per-upstream 测速统计（eff_lat 滚动均值）+ 首测 + submit_drop 探针池
//! - [`bootstrap`]：域名上游解析缓存 + bootstrap DNS
//! - [`runtime`]：共享运行时与查询派发

mod addr;
mod bootstrap;
mod config;
mod doh;
mod dot;
mod error;
mod header_check;
mod health;
mod pool;
mod quic;
mod runtime;
mod tcp;
mod tls;
mod udp;

pub use addr::{
    host_port, is_hostname, is_non_global_for_subscription, is_private_ip, is_v6,
    parse_upstream_addr, request_path, ParsedAddr, Proto,
};
pub use bootstrap::BootstrapResolver;
pub use config::UpstreamConfig;
pub use error::{UpstreamError, UpstreamResult};
pub use header_check::{is_header_only, qid_of, X20Controller};
pub use health::{HealthKeeper, UpstreamStats};
#[allow(unused_imports)]
pub use pool::{MAX_CONN, MAX_IDLE, MAX_IDLE_PER_KEY, MAX_TOTAL_IDLE};
pub use quic::{classify_conn_error, QuicManager};
pub use runtime::{InflightLimiter, UpstreamRuntime, DEFAULT_MAX_INFLIGHT_PER_UPSTREAM};

use std::time::Instant;

/// **[历史归因]** 统一查询结果四元组，对齐 Python `(ok, response_bytes, latency_ms, err_str)`。
#[derive(Debug, Clone)]
pub struct QueryOutcome {
    /// 是否成功收到合法响应。
    pub ok: bool,
    /// 响应报文字节（失败为 None）。
    pub data: Option<Vec<u8>>,
    /// 实际耗时（ms）。
    pub latency_ms: u64,
    /// 失败原因（成功为空串）。QUIC 路径透出证书/拒绝/DNS/TLS 具体归因。
    pub err: String,
}

impl QueryOutcome {
    pub(crate) fn fail(latency_ms: u64, err: impl Into<String>) -> Self {
        QueryOutcome {
            ok: false,
            data: None,
            latency_ms,
            err: err.into(),
        }
    }
    pub(crate) fn ok(data: Vec<u8>, latency_ms: u64) -> Self {
        QueryOutcome {
            ok: true,
            data: Some(data),
            latency_ms,
            err: String::new(),
        }
    }
}

/// 计算耗时（ms）。
pub(crate) fn elapsed_ms(t0: Instant) -> u64 {
    t0.elapsed().as_millis() as u64
}
