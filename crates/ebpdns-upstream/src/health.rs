//! **[历史归因]** per-upstream 测速统计（对齐 Python `telemetry.upstream_eff_lat` + `probe.py`）。
//!
//! - `UpstreamStats`：滚动记录 ok/fail/lat_sum；`eff_lat()` = 平均成功延迟（ms），
//!   失败率 >50% 且样本 >10 时 +500ms 惩罚。
//! - `HealthKeeper`：按 up_id 隔离的统计表。
//! - **[历史归因]** `ProbePool`：独立有界后台探针池，submit 满即丢（对齐 Python `submit_drop`），
//!   保证健康检查不饿死数据面查询。

use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
/// 单个上游的测速/健康统计。
#[derive(Debug, Default)]
pub struct UpstreamStats {
    ok: AtomicU64,
    fail: AtomicU64,
    lat_sum: AtomicU64,
    measured: AtomicBool,
    last_ok: Mutex<Option<Instant>>,
    /// **2.1.21（A-17 / DEF-220-09）**：**DNS 业务层**结果计数（第二本账）。
    ///
    /// 为什么必须与 `ok`/`fail` **分开**：`ok`/`fail` 是**传输层**账
    /// （`runtime.rs` 的 `health.record(cfg.id, ok, lat)`：只要 UDP/TCP/TLS/QUIC
    /// 往返成功就记 ok）—— 一个持续回 `SERVFAIL(2)` 的上游在那里是"100% 成功"。
    /// 本对计数在 `resolve.rs::finish_resolve` 里按**真实 rcode** 记：
    /// `NOERROR(0)`/`NXDOMAIN(3)` 且未截断 → 业务成功（**不要求答案段非空**：
    /// NXDOMAIN / NODATA 都是上游真实算出的结论）；
    /// `SERVFAIL(2)`/`REFUSED(5)`/`NOTIMP(4)`/`FORMERR(1)`/截断 → 业务失败。
    /// 于是 `/api/upstreams[].dns_success_rate` 与 `success_rate` 各说各的口径。
    dns_ok: AtomicU64,
    dns_fail: AtomicU64,
}

impl UpstreamStats {
    pub fn new() -> Self {
        Self::default()
    }

    /// 记录一次成功查询（对齐 telemetry `upstream_result`）。
    pub fn record_ok(&self, latency_ms: u64) {
        self.ok.fetch_add(1, Ordering::Relaxed);
        self.lat_sum.fetch_add(latency_ms, Ordering::Relaxed);
        self.measured.store(true, Ordering::Relaxed);
        *self.last_ok.lock() = Some(Instant::now());
    }

    /// 记录一次失败查询。
    pub fn record_fail(&self) {
        self.fail.fetch_add(1, Ordering::Relaxed);
    }

    /// **2.1.21（A-17 / DEF-220-09）**：记录一次 **DNS 业务层**结果（与传输层解耦）。
    ///
    /// 判据见 `dns_ok`/`dns_fail` 字段文档；调用点唯一 =
    /// `Resolver::record_dns_verdicts`，由 `resolve_inner` 在**上游扇出（single-flight
    /// 合并段）返回之后**调用一次 ⇒ 每个**物理**上游应答恰好记一次，
    /// 5 个并发同名 miss 合并成 1 次物理查询时只 +1（DEF-221-04）。
    pub fn record_dns_verdict(&self, ok: bool) {
        if ok {
            self.dns_ok.fetch_add(1, Ordering::Relaxed);
        } else {
            self.dns_fail.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// DNS 业务成功数（`dns_success_rate` 的分子）。
    pub fn dns_ok_count(&self) -> u64 {
        self.dns_ok.load(Ordering::Relaxed)
    }

    /// DNS 业务失败数（SERVFAIL/REFUSED/NOTIMP/FORMERR/截断）。
    pub fn dns_fail_count(&self) -> u64 {
        self.dns_fail.load(Ordering::Relaxed)
    }

    /// DNS 业务样本总数（0 = 还没有业务样本 ⇒ 上层必须给 `null`，不得编造 100%）。
    pub fn dns_total(&self) -> u64 {
        self.dns_ok_count() + self.dns_fail_count()
    }

    pub fn measured(&self) -> bool {
        self.measured.load(Ordering::Relaxed)
    }
    // >>> 242B BEGIN P1-8-stats >>> //
    /// **2.1.42-B（P1-8）**：清空该上游的全部统计（`/api/reset`；避免 reset 后
    /// `/api/upstreams[].queries/ok/fail/success_rate` 仍显示历史值）。
    pub fn reset(&self) {
        self.ok.store(0, Ordering::Relaxed);
        self.fail.store(0, Ordering::Relaxed);
        self.lat_sum.store(0, Ordering::Relaxed);
        self.measured.store(false, Ordering::Relaxed);
        *self.last_ok.lock() = None;
        self.dns_ok.store(0, Ordering::Relaxed);
        self.dns_fail.store(0, Ordering::Relaxed);
    }
    // <<< 242B END P1-8-stats <<< //

    pub fn ok_count(&self) -> u64 {
        self.ok.load(Ordering::Relaxed)
    }

    pub fn fail_count(&self) -> u64 {
        self.fail.load(Ordering::Relaxed)
    }

    /// 成功延迟累计（ms）。
    pub fn lat_sum(&self) -> u64 {
        self.lat_sum.load(Ordering::Relaxed)
    }

    /// 平均成功延迟（ms）；无成功样本 → None（调用方回退静态延迟）。
    pub fn avg_latency(&self) -> Option<f64> {
        let ok = self.ok_count();
        if ok == 0 {
            None
        } else {
            Some(self.lat_sum() as f64 / ok as f64)
        }
    }

    /// **[历史归因]** 最近一次成功距今秒数（Python `last` 语义；无记录 → None）。
    pub fn last_ok_age_s(&self) -> Option<f64> {
        self.last_ok.lock().map(|t| t.elapsed().as_secs_f64())
    }

    /// **[历史归因]** 有效延迟（ms）：成功均值 + 高失败率惩罚。对齐 Python eff_lat 计算。
    pub fn eff_lat(&self, weight: u32) -> f64 {
        let ok = self.ok.load(Ordering::Relaxed);
        if ok == 0 {
            return f64::MAX;
        }
        let fail = self.fail.load(Ordering::Relaxed);
        let total = ok + fail;
        let mut avg = self.lat_sum.load(Ordering::Relaxed) as f64 / ok as f64;
        // 失败率 >50% 且样本 >10 → +500ms 惩罚。
        if total > 10 && (fail as f64 / total as f64) > 0.5 {
            avg += 500.0;
        }
        let w = f64::from(weight.max(1));
        avg / w
    }
}

/// per-upstream 统计表。
#[derive(Default)]
pub struct HealthKeeper {
    map: Mutex<HashMap<String, Arc<UpstreamStats>>>,
}

impl HealthKeeper {
    pub fn new() -> Self {
        Self::default()
    }

    /// 取（或建）某上游的统计句柄。
    pub fn stats(&self, up_id: &str) -> Arc<UpstreamStats> {
        let mut g = self.map.lock();
        g.entry(up_id.to_string())
            .or_insert_with(|| Arc::new(UpstreamStats::new()))
            .clone()
    }

    /// 记录一次查询结果。
    pub fn record(&self, up_id: &str, ok: bool, latency_ms: u64) {
        let s = self.stats(up_id);
        if ok {
            s.record_ok(latency_ms);
        } else {
            s.record_fail();
        }
    }

    /// 删除上游时清理统计。
    pub fn discard(&self, up_id: &str) {
        self.map.lock().remove(up_id);
    }
    // >>> 242B BEGIN P1-8-keeper >>> //
    /// **2.1.42-B（P1-8）**：清空**全部**上游统计（保留条目，只把计数归零）。
    pub fn reset(&self) {
        for s in self.map.lock().values() {
            s.reset();
        }
    }
    // <<< 242B END P1-8-keeper <<< //
}

/// **[历史归因]** 独立有界后台探针池：submit 满即丢（对齐 Python `submit_drop`）。
///
/// 用一个容量固定的信号量限制并发后台探针数；获取不到许可即丢弃该次探针，
/// 不阻塞数据面查询、不无限堆积。
pub struct ProbePool {
    sem: Arc<tokio::sync::Semaphore>,
}

impl ProbePool {
    /// `max_concurrent`：后台探针并发上限。
    pub fn new(max_concurrent: usize) -> Self {
        ProbePool {
            sem: Arc::new(tokio::sync::Semaphore::new(max_concurrent)),
        }
    }

    /// 尝试获取一个探针许可。`Some(permit)` = 可执行；`None` = 池满，丢弃本次探针。
    pub fn try_submit(&self) -> Option<ProbePermit> {
        match self.sem.clone().try_acquire_owned() {
            Ok(p) => Some(ProbePermit { _p: p }),
            Err(_) => None,
        }
    }
}

/// 探针许可：Drop 归还并发槽。
pub struct ProbePermit {
    _p: tokio::sync::OwnedSemaphorePermit,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eff_lat_rolling_mean_and_penalty() {
        let s = UpstreamStats::new();
        s.record_ok(100);
        s.record_ok(300);
        // ok=2, avg=200.
        assert_eq!(s.eff_lat(1), 200.0);
        assert_eq!(s.eff_lat(2), 100.0);
        // 加大量失败：total>10 且 fail>50%。
        for _ in 0..20 {
            s.record_fail();
        }
        // ok=2, avg=200, fail=20, total=22, fail rate ~91%>50% → 700.
        assert!((s.eff_lat(1) - 700.0).abs() < 1.0);
    }

    #[test]
    fn probe_pool_submit_drop() {
        let pool = ProbePool::new(2);
        let a = pool.try_submit().unwrap();
        let _b = pool.try_submit().unwrap();
        // 第三个：池满即丢。
        assert!(pool.try_submit().is_none());
        drop(a);
        assert!(pool.try_submit().is_some());
    }
}
