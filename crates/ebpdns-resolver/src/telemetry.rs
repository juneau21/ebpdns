//! **[历史归因]** 遥测抽象：对齐 Python `Telemetry` 的增量计数/延迟推送/结构化日志。
//! resolver 编排层只消费这些钩子；默认全空实现（测试与无观测场景）。
//! 热路径绝不因遥测失败而阻断 DNS（fail-closed 方向相反）。

/// 遥测 trait。所有方法提供默认空实现，调用方无需关心。
pub trait Telemetry: Send + Sync + 'static {
    fn count_query(&self, _cat: &str) {}
    /// **2.1.41**：一次客户端查询（数据面唯一出口 `dns.rs::log_and_count`
    /// **恰好调用一次**）→ 推进 QPS 滑动窗口。
    ///
    /// 与 [`Telemetry::count_query`]`("resolve")` / `total` **彻底解耦**：
    /// `counters.total` 是 `Σ client_rcode` 的派生量（唯一写点
    /// `note_data_plane_outcome`），若再用 `resolve` 类别计 total 就会破坏
    /// `total == Σ client_rcode` 这条硬等式。
    ///
    /// 2.1.40 的回归：QPS 的唯一推进点被 `neg_telemetry.is_none()` 门禁掉，
    /// 而生产三条数据面出口**全部**传 `Some(&telemetry)` ⇒ `qps_win` 永不增长、
    /// `/api/status.qps` 恒 0。本方法由出口**无条件**调用，因此 QPS 与
    /// `neg_telemetry` 无关，且每个客户端查询只推进一次。
    ///
    /// 计入的查询类型 = 所有到达数据面出口的客户端查询：缓存命中 / 真 miss /
    /// 本地策略应答（policy_filtered）/ 规则应答（含 block）/ 畸形包（FORMERR）。
    /// 控制面 `POST /api/query` 不经过该出口，故不计入（与 `total` 同口径）。
    fn note_client_query(&self) {}
    fn count_top(&self, _domain: &str, _client: Option<&str>) {}
    fn inc(&self, _key: &str) {}
    fn inc_rule(&self, _key: &str) {}
    /// **2.1.16（功能 3）**：规则命中按 **(`match_type`, `action`)** 二维聚合。
    ///
    /// `match_type` ∈ `exact` / `wild_suffix` / `wild_infix` / `regex`
    /// （= [`ebpdns_rules::match_kind`]，与 `RuleIndex` 六分表同构）；
    /// `action` ∈ `allow` / `block` / `domestic` / `global` / `forceIp`
    /// （= [`ebpdns_rules::action_key`]，与既有 `inc_rule` 参数逐字一致）。
    ///
    /// **默认实现 = 退回一维 `inc_rule(action)`**：这样既有的测试遥测桩
    /// （[`NoopTelemetry`] / `RecordingTelemetry`）与其它 `Telemetry` 实现
    /// **不需要任何改动**就继续编译，且计数总量不变（不丢样本）。
    fn inc_rule_kind(&self, _match_type: &str, action: &str) {
        self.inc_rule(action);
    }
    fn push_latency(&self, _ms: f64) {}
    /// 结构化日志（默认丢弃；测试不断言日志内容）。
    #[allow(clippy::too_many_arguments)]
    fn log(
        &self,
        _domain: &str,
        _qtype: &str,
        _hit: &str,
        _msg: &str,
        _latency_ms: f64,
        _client_ip: Option<&str>,
        _upstream: &str,
        _answer: &str,
        _rule: Option<&str>,
    ) {
    }
}

/// 全空遥测。
#[derive(Default)]
pub struct NoopTelemetry;

impl Telemetry for NoopTelemetry {}

#[cfg(test)]
pub use recording::RecordingTelemetry;

#[cfg(test)]
mod recording {
    use super::*;

    /// 记录 inc 键次数的测试遥测。
    #[derive(Default)]
    pub struct RecordingTelemetry {
        pub hits: parking_lot::Mutex<std::collections::HashMap<String, u64>>,
    }

    impl Telemetry for RecordingTelemetry {
        fn inc(&self, key: &str) {
            *self.hits.lock().entry(key.to_string()).or_insert(0) += 1;
        }
        fn inc_rule(&self, key: &str) {
            self.inc(&format!("rule:{key}"));
        }
    }
}
