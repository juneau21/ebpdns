//! 生产接线适配器：把已封板依赖 crate 的真实类型接到 resolver 的 seam trait 上。
//!
//! **[历史归因]** - [`ProductionQuerier`]：包装 [`ebpdns_upstream::UpstreamRuntime`]，按 Python `_query_parallel`
//!   语义并发查询选中上游，再用 [`crate::query::classify_one`] 汇总为 [`UpstreamAnswer`]；
//!   与 Resolver 共享 [`SharedCircuit`]，跳过打开态上游、按结果记录成功/失败。
//!
//! 2.1.8 优化（本文件承载优化项 1/3/4/6）：
//!
//! 1. **首个正向答案即返回**：`JoinSet` + `try_join_next/select` 驱动，拿到
//!    `NOERROR 且非空且未截断` 的答案立刻 `abort_all()` 返回，不再逐个 `await` 全部任务；
//!    只有需要表决（NXDOMAIN/NODATA/截断）或首批全部失败时才等满。
//! 3. **自适应并发/动态对冲**：`adaptive_parallel=true` 时先发 1 个，`hedge_after_ms`
//!    内无正向答案（或先收到非正向答案）才追加下一个，上限仍是调用方给出的上游数
//!    （即 `max_parallel_upstreams` 经 `select_upstreams` 截断后的结果）。
//! 4. **按上游自适应超时**：`adaptive_timeout=true` 时
//!    `timeout = clamp(k * 实测均值, adaptive_timeout_min_ms, timeout_ms)`。
//! 6. **「全部熔断」可观测**：兜底放行时 `tracing::warn!` 打出被放行的上游 id 列表与原因，
//!    并把次数计入 [`SharedCircuit::all_open_count`]（`/api/status.counters.breaker_all_open`）。
//!
//! 本环境无外网/特权：查询会失败，但代码真实可编译可运行。

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::task::JoinSet;

use ebpdns_proto::query::build_query;
use ebpdns_upstream::{Proto, UpstreamConfig, UpstreamRuntime};

use crate::breaker::SharedCircuit;
use crate::clock::Clock;
use crate::config::{ResolverConfig, UpstreamCfg};
use crate::helpers::qtype_code;
use crate::query::{classify_one, ParallelQuerier};
use crate::types::UpstreamAnswer;

/// P2-A：自适应超时的成功延迟滑窗容量（超过即丢最旧样本）。
pub const TIMEOUT_WINDOW: usize = 32;
/// P2-A：连续超时多少次即"解锁"（回退到配置 `timeout_ms`）。
pub const TIMEOUT_UNLOCK_STREAK: u32 = 3;
/// P2-A：同一上游的解锁日志最小间隔（ms）——解锁是自愈行为，不刷屏。
pub const UNLOCK_LOG_WINDOW_MS: f64 = 60_000.0;
/// P2-A：生效超时相对 **观测 p90** 的抖动安全余量（倍率）。
///
/// `k × p90` 在 `k < 1` 时会取到"小于上游实际 RTT"的值（例如 p90=1500ms、k=0.5 →
/// 750ms），下一轮必然超时 —— 这违背该特性自己的目标（慢上游不得被自身 RTT 误杀）。
/// 因此生效超时额外取 `max(k × p90, p90 × 本余量)`：1.2 覆盖正常抖动；
/// `adaptive_timeout_min_ms` 与 `timeout_ms` 的夹取语义**不变**
/// （默认 `min_ms == timeout_ms == 1500` 时仍恒等于 1500 = 等效关闭）。
pub const TIMEOUT_P90_MARGIN: f64 = 1.2;

/// resolver 自有上游配置 → upstream crate 运行时配置。
pub(crate) fn upcfg_to_runtime(up: &UpstreamCfg) -> UpstreamConfig {
    let proto = Proto::from_lower(&up.proto).unwrap_or(Proto::Udp);
    let port = if up.port == 0 {
        proto.default_port()
    } else {
        up.port
    };
    // 加密协议的请求路径。**必须是路径**，不能是完整 URL：
    // 见 `ebpdns_upstream::request_path` 的缺陷说明（旧实现写死 `https://host:port/dns-query`
    // 整串 → DoH 请求行 / DoH3 `:path` 变成 `/https://host:port/dns-query` → 真实服务器 100% 失败）。
    let url = ebpdns_upstream::request_path(&up.url, proto.is_encrypted());
    UpstreamConfig {
        id: up.id.clone(),
        name: up.name.clone(),
        proto,
        host: up.host.clone(),
        port,
        url,
        weight: up.weight.clamp(1.0, f64::from(u32::MAX)) as u32,
        strict_cert: true,
        allow_private_ip: up.allow_private_ip,
        bootstrap: None,
        latency: up.latency,
        latency_measured: false,
        enabled: up.enabled,
    }
}

/// 数据面并发/超时调参（优化项 3/4）。原子量存储 → 热路径无锁读、可热重载。
///
/// 由 [`Resolver`](crate::Resolver) 持有并与 [`ProductionQuerier`] 共享：
/// `Resolver::reload` 调用 [`QuerierTuning::apply`]，因此 `timeout_ms` /
/// `adaptive_*` / `hedge_after_ms` 在控制台改完即时生效（旧实现里 `timeout_ms`
/// 在 querier 构造后即被冻结，热重载只改 resolver cfg、不改数据面，属静默失效）。
#[derive(Debug)]
pub struct QuerierTuning {
    /// 单上游超时上限（ms，保留 v1.9.162 `timeout_ms` 语义作为上限）。
    timeout_ms: AtomicU64,
    adaptive_parallel: AtomicBool,
    hedge_after_ms: AtomicU64,
    /// 2.1.11 优化项 3：逐上游 p90 对冲因子 ×1000（定点存整数，避免 f64 原子化）。
    hedge_slowest_factor_milli: AtomicU64,
    adaptive_timeout: AtomicBool,
    /// k × 1000（定点存整数，避免 f64 原子化）。
    adaptive_timeout_k_milli: AtomicU64,
    adaptive_timeout_min_ms: AtomicU64,
    /// nxdomain_quorum（A1：负向通道路由的「收齐几票即可 abort 其余」阈值）。
    nxdomain_quorum: AtomicU64,
    /// 物理上游请求数（优化项 1/3 的 QPS 对比口径；`upstream_queries` 是逻辑口径）。
    dispatched: AtomicU64,
    /// 「首个正向答案即返回」触发次数（优化项 1）。
    early_returns: AtomicU64,
    /// 对冲追加（定时器/负应答触发）次数（优化项 3）。
    hedges: AtomicU64,
    /// 2.1.11 优化项 3：对冲触发时刻来自**逐上游实测 p90**（而非 `hedge_after_ms`
    /// 静态兜底）的次数。用于真机量化"p90 决策真的生效了"。
    hedge_p90_decisions: AtomicU64,
    /// A1：**收到负向答案后**因"已收齐 quorum 票"而提前 abort 其余候选的次数。
    quorum_aborts: AtomicU64,
    /// P2-A：按上游滑窗 p90 采样（最近 [`TIMEOUT_WINDOW`] 个**成功**延迟 ms）。
    lat_window: Mutex<HashMap<String, VecDeque<u64>>>,
    /// P2-A：按上游连续超时次数（成功即清零；达 [`TIMEOUT_UNLOCK_STREAK`] 解锁回 `timeout_ms`）。
    timeout_streak: Mutex<HashMap<String, u32>>,
    /// P2-A：连续超时解锁发生的次数（可观测）。
    timeout_unlocks: AtomicU64,
    /// P2-A：解锁日志限流（up_id → 上次记录时刻，单调 ms）。
    unlock_log_at: Mutex<HashMap<String, f64>>,
}

/// 一次查询用到的调参快照（几条 Relaxed 原子读，热路径无锁无分配）。
#[derive(Clone, Copy, Debug)]
pub struct TuningSnapshot {
    pub timeout_ms: u64,
    pub adaptive_parallel: bool,
    pub hedge_after_ms: u64,
    /// 2.1.11 优化项 3：逐上游 p90 对冲因子（默认 1.0 = 生效时刻就是实测 p90）。
    pub hedge_slowest_factor: f64,
    pub adaptive_timeout: bool,
    pub adaptive_timeout_k: f64,
    pub adaptive_timeout_min_ms: u64,
    /// A1：负向通道的 quorum 票数（收齐即 abort 其余候选，不再"首答非正向就一次发齐"）。
    pub nxdomain_quorum: usize,
}

impl QuerierTuning {
    fn defaults(timeout_ms: u64) -> Self {
        Self {
            timeout_ms: AtomicU64::new(timeout_ms.max(1)),
            adaptive_parallel: AtomicBool::new(false),
            hedge_after_ms: AtomicU64::new(200),
            hedge_slowest_factor_milli: AtomicU64::new(1000),
            adaptive_timeout: AtomicBool::new(false),
            adaptive_timeout_k_milli: AtomicU64::new(5000),
            adaptive_timeout_min_ms: AtomicU64::new(500),
            nxdomain_quorum: AtomicU64::new(2),
            dispatched: AtomicU64::new(0),
            early_returns: AtomicU64::new(0),
            hedges: AtomicU64::new(0),
            hedge_p90_decisions: AtomicU64::new(0),
            quorum_aborts: AtomicU64::new(0),
            lat_window: Mutex::new(HashMap::new()),
            timeout_streak: Mutex::new(HashMap::new()),
            timeout_unlocks: AtomicU64::new(0),
            unlock_log_at: Mutex::new(HashMap::new()),
        }
    }

    /// 从 resolver 配置构造（生产路径）。
    pub fn from_config(cfg: &ResolverConfig) -> Arc<Self> {
        let s = Self::defaults(cfg.timeout_ms);
        s.apply(cfg);
        Arc::new(s)
    }

    /// 兼容构造：仅固定 `timeout_ms`，自适应全关 —— 与 2.1.7 行为逐位一致。
    /// `/api/reprobe` 的单上游探测路径用它（探测必须用固定超时口径，不能被
    /// 自适应缩短而改变实测延迟的可解释性）。
    pub fn fixed(timeout_ms: u64) -> Arc<Self> {
        Arc::new(Self::defaults(timeout_ms))
    }

    /// 用新配置刷新全部调参（`Resolver::reload` / `Resolver::new` 调用）。
    pub fn apply(&self, cfg: &ResolverConfig) {
        self.timeout_ms
            .store(cfg.timeout_ms.max(1), Ordering::Relaxed);
        self.adaptive_parallel
            .store(cfg.adaptive_parallel, Ordering::Relaxed);
        self.hedge_after_ms
            .store(cfg.hedge_after_ms.max(1), Ordering::Relaxed);
        // 2.1.11 优化项 3：p90 对冲因子（非有限/<=0 → 1.0，保证 `hedge_delay_for` 有界）。
        let hf = if cfg.hedge_slowest_factor.is_finite() && cfg.hedge_slowest_factor > 0.0 {
            cfg.hedge_slowest_factor.clamp(0.05, 100.0)
        } else {
            1.0
        };
        self.hedge_slowest_factor_milli
            .store((hf * 1000.0).round() as u64, Ordering::Relaxed);
        self.adaptive_timeout
            .store(cfg.adaptive_timeout, Ordering::Relaxed);
        let k = if cfg.adaptive_timeout_k.is_finite() && cfg.adaptive_timeout_k > 0.0 {
            cfg.adaptive_timeout_k
        } else {
            5.0
        };
        self.adaptive_timeout_k_milli
            .store((k * 1000.0).round() as u64, Ordering::Relaxed);
        self.adaptive_timeout_min_ms.store(
            cfg.adaptive_timeout_min_ms.clamp(1, 600_000),
            Ordering::Relaxed,
        );
        // A1：quorum 票数随配置热刷新（控制台改 nxdomain_quorum 即时生效）。
        self.nxdomain_quorum
            .store(cfg.nxdomain_quorum.max(1) as u64, Ordering::Relaxed);
    }

    /// 读一次快照。
    pub fn snapshot(&self) -> TuningSnapshot {
        TuningSnapshot {
            timeout_ms: self.timeout_ms.load(Ordering::Relaxed).max(1),
            adaptive_parallel: self.adaptive_parallel.load(Ordering::Relaxed),
            hedge_after_ms: self.hedge_after_ms.load(Ordering::Relaxed).max(1),
            hedge_slowest_factor: {
                let m = self.hedge_slowest_factor_milli.load(Ordering::Relaxed);
                if m == 0 {
                    1.0
                } else {
                    m as f64 / 1000.0
                }
            },
            adaptive_timeout: self.adaptive_timeout.load(Ordering::Relaxed),
            adaptive_timeout_k: self.adaptive_timeout_k_milli.load(Ordering::Relaxed) as f64
                / 1000.0,
            adaptive_timeout_min_ms: self.adaptive_timeout_min_ms.load(Ordering::Relaxed).max(1),
            nxdomain_quorum: self.nxdomain_quorum.load(Ordering::Relaxed).max(1) as usize,
        }
    }

    /// 当前超时上限（ms）。
    pub fn timeout_ms(&self) -> u64 {
        self.timeout_ms.load(Ordering::Relaxed).max(1)
    }

    /// 物理上游请求计数 +1。
    pub fn note_dispatch(&self) {
        self.dispatched.fetch_add(1, Ordering::Relaxed);
    }

    /// 物理上游请求总数。
    pub fn dispatched(&self) -> u64 {
        self.dispatched.load(Ordering::Relaxed)
    }

    /// 「首答即返」触发次数。
    pub fn early_returns(&self) -> u64 {
        self.early_returns.load(Ordering::Relaxed)
    }

    /// 对冲追加次数。
    pub fn hedges(&self) -> u64 {
        self.hedges.load(Ordering::Relaxed)
    }
    // >>> 242B BEGIN P1-8-querier >>> //
    /// **2.1.42-B（P1-8）**：清空 querier 的累计量 / 采样窗口（`/api/reset`）。
    pub fn reset_counters(&self) {
        for a in [
            &self.dispatched,
            &self.early_returns,
            &self.hedges,
            &self.hedge_p90_decisions,
            &self.quorum_aborts,
            &self.timeout_unlocks,
        ] {
            a.store(0, Ordering::Relaxed);
        }
        self.lat_window.lock().clear();
        self.timeout_streak.lock().clear();
        self.unlock_log_at.lock().clear();
    }
    // <<< 242B END P1-8-querier <<< //

    fn note_early_return(&self) {
        self.early_returns.fetch_add(1, Ordering::Relaxed);
    }

    fn note_hedge(&self) {
        self.hedges.fetch_add(1, Ordering::Relaxed);
    }

    /// 2.1.11 优化项 3：对冲时刻**由逐上游实测 p90 决定**的次数（可观测）。
    pub fn hedge_p90_decisions(&self) -> u64 {
        self.hedge_p90_decisions.load(Ordering::Relaxed)
    }

    /// A1：收齐 quorum 票后 abort 其余候选的次数。
    pub fn quorum_aborts(&self) -> u64 {
        self.quorum_aborts.load(Ordering::Relaxed)
    }

    fn note_quorum_abort(&self) {
        self.quorum_aborts.fetch_add(1, Ordering::Relaxed);
    }

    /// P2-A：连续超时解锁次数（连续 [`TIMEOUT_UNLOCK_STREAK`] 次超时 → 回退 `timeout_ms`）。
    pub fn timeout_unlocks(&self) -> u64 {
        self.timeout_unlocks.load(Ordering::Relaxed)
    }

    /// P2-A：记录一次上游查询结果，维护滑窗与连续超时计数。
    ///
    /// - 成功（有有效应答）→ 记入滑窗（容量 [`TIMEOUT_WINDOW`]，FIFO）+ 连续超时清零；
    /// - 超时（`rcode=None` 且实测延迟 ≥ 本次生效超时的 90%）→ 连续超时 +1；
    ///   达标即清零滑窗（解锁 → `timeout_for` 回退 `timeout_ms`）；
    /// - 其它失败（解析错/构建错等）→ 不动两个状态（避免把非超时归因算成超时）。
    fn record_result(&self, up_id: &str, ok: bool, timed_out: bool, lat_ms: u64) {
        if ok {
            let mut w = self.lat_window.lock();
            let e = w.entry(up_id.to_string()).or_default();
            e.push_back(lat_ms);
            while e.len() > TIMEOUT_WINDOW {
                e.pop_front();
            }
            drop(w);
            self.timeout_streak.lock().remove(up_id);
            return;
        }
        if !timed_out {
            return;
        }
        let mut s = self.timeout_streak.lock();
        let n = s.entry(up_id.to_string()).or_insert(0);
        *n += 1;
        if *n >= TIMEOUT_UNLOCK_STREAK {
            *n = 0;
            drop(s);
            // 解锁：丢弃滑窗样本 → `timeout_for` 回退到 `timeout_ms`（不再被一次快样本钉死）。
            self.lat_window.lock().remove(up_id);
            let total = self.timeout_unlocks.fetch_add(1, Ordering::Relaxed) + 1;
            // P2-A 可观测性：**状态转移**才记日志，且按上游限流（每上游每
            // [`UNLOCK_LOG_WINDOW_MS`] 最多一条）。旧实现每次解锁都 WARN 一条：
            // 生产实测 15 分钟内 3895 条 WARN/ERROR（syscheck 唯一 FAIL），
            // 而解锁是**自愈行为**，不该以 WARN 级别刷屏。
            // 单调毫秒（`Instant` 起点，仅用于日志限流比较）。
            let now_ms = {
                use std::sync::OnceLock;
                static START: OnceLock<std::time::Instant> = OnceLock::new();
                let s = START.get_or_init(std::time::Instant::now);
                s.elapsed().as_secs_f64() * 1000.0
            };
            let log_it = Self::unlock_log_allowed(&self.unlock_log_at, up_id, now_ms);
            if log_it {
                tracing::info!(
                    upstream = %up_id,
                    streak = TIMEOUT_UNLOCK_STREAK,
                    unlock_total = total,
                    "自适应超时解锁：连续超时达阈值 → 回退到配置 timeout_ms（同一上游 60s 内只记一条）"
                );
            }
        }
    }

    /// P2-A：解锁日志限流判定（`up_id` 在 [`UNLOCK_LOG_WINDOW_MS`] 内只放行一次）。
    ///
    /// 提取成独立函数便于确定性单测；生产用单调时钟（`record_result` 传
    /// `Instant::now()` 换算出的 ms）。
    fn unlock_log_allowed(last: &Mutex<HashMap<String, f64>>, up_id: &str, now_ms: f64) -> bool {
        let mut g = last.lock();
        let prev = g.get(up_id).copied().unwrap_or(f64::NEG_INFINITY);
        if now_ms - prev >= UNLOCK_LOG_WINDOW_MS {
            g.insert(up_id.to_string(), now_ms);
            true
        } else {
            false
        }
    }

    /// P2-A：`timeout_for` 的采样基准 —— 滑窗 **p90**（无样本返回 `None`）。
    ///
    /// 公开给集成测试断言"基准不再被单个快样本钉死"（`production.rs` 的单测覆盖
    /// 不涉及真实时钟下的慢上游场景）。
    ///
    /// 旧实现用 `HealthKeeper::avg_latency`（算术均值）：公网 DoH/DoH3 的 RTT 是重尾
    /// 分布，一次 1502ms 的快样本（k=0.5）就能把均值拉到 1502，把超时钉到 751ms →
    /// 下一次必然 TIMEOUT → 之后每次都被误杀，且**只降不升**（无滞回/复位）。
    /// p90 天然带滞回：需要 10% 的样本变快才会下移。
    pub fn p90_latency(&self, up_id: &str) -> Option<f64> {
        let mut v: Vec<u64> = {
            let w = self.lat_window.lock();
            match w.get(up_id) {
                Some(e) if !e.is_empty() => e.iter().copied().collect(),
                _ => return None,
            }
        };
        v.sort_unstable();
        // nearest-rank 法：ceil(0.9 * n) 取第 k 小。
        let n = v.len();
        // clippy::manual_div_ceil（2.1.21 第 2 轮）：语义完全等价，只是标准库写法。
        let k = (n * 9).div_ceil(10); // ceil(0.9n)

        let idx = k.saturating_sub(1).min(n - 1);
        Some(v[idx] as f64)
    }
}

/// 生产上游查询器：并发查询选中上游，分类为 quorum 表决单位。
pub struct ProductionQuerier {
    runtime: Arc<UpstreamRuntime>,
    cb: Arc<SharedCircuit>,
    clock: Arc<dyn Clock>,
    timeout_ms: u64,
    edns: bool,
    udp_size: u32,
    /// padding 开关（仅加密协议生效）。
    padding: bool,
    /// DNS 0x20 大小写随机化开关。
    x20: bool,
    /// 自适应调参（优化项 3/4）；`new` 默认取固定超时（兼容），生产装配用
    /// [`ProductionQuerier::with_tuning`] 注入来自配置的共享句柄。
    tuning: Arc<QuerierTuning>,
}

impl ProductionQuerier {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        runtime: Arc<UpstreamRuntime>,
        cb: Arc<SharedCircuit>,
        clock: Arc<dyn Clock>,
        timeout_ms: u64,
        edns: bool,
        udp_size: u32,
        padding: bool,
        x20: bool,
    ) -> Self {
        Self {
            runtime,
            cb,
            clock,
            timeout_ms,
            edns,
            udp_size,
            padding,
            x20,
            tuning: QuerierTuning::fixed(timeout_ms),
        }
    }

    /// 注入共享调参句柄（生产装配：与 `Resolver` 同一份，支持热重载）。
    #[must_use]
    pub fn with_tuning(mut self, tuning: Arc<QuerierTuning>) -> Self {
        // 句柄与构造参数同源，时间上限以句柄为准（`Resolver::reload` 会刷新它）。
        self.timeout_ms = tuning.timeout_ms();
        self.tuning = tuning;
        self
    }

    /// 当前调参句柄（供 resolver 侧装配/断言）。
    pub fn tuning(&self) -> Arc<QuerierTuning> {
        self.tuning.clone()
    }

    /// 单上游生效超时（优化项 4 + P2-A 修复）。
    ///
    /// `adaptive_timeout=false` → 固定 `timeout_ms`（v1.9.162 语义）。
    /// 否则 `clamp( max(k × p90, p90 × [`TIMEOUT_P90_MARGIN`]), 下限, timeout_ms )`。
    ///
    /// **P2-A 修复（2.1.9）**：
    /// 1. 基准从「成功延迟的**算术均值**」改为「最近 [`TIMEOUT_WINDOW`] 个成功样本的
    ///    **p90**」——均值被一次 1502ms 快样本拉高就把超时钉到 `k×1502`，公网重尾
    ///    分布下"只降不升"，实测出现过 751ms 钉死 → 必超时 → 熔断级联；
    /// 2. **抖动安全余量**：`k < 1` 时 `k × p90` 会小于上游自身 RTT（p90=1500ms、
    ///    k=0.5 → 750ms）→ 下一轮必然超时。故再取 `p90 × TIMEOUT_P90_MARGIN`(1.2)
    ///    作为下限，保证生效超时**不低于观测 p90**；
    /// 3. 加**解锁器**：同一上游连续 [`TIMEOUT_UNLOCK_STREAK`] 次超时 → 丢弃滑窗样本
    ///    并回退到 `timeout_ms`（滞回 + 复位）。
    ///
    /// 默认 `adaptive_timeout_min_ms == timeout_ms == 1500` 时该项仍然"等效关闭"
    /// （`clamp(x,1500,1500)=1500`，与 v1.9.162 固定超时逐位一致）。
    fn timeout_for(&self, up: &UpstreamCfg, snap: &TuningSnapshot) -> u64 {
        if !snap.adaptive_timeout {
            return snap.timeout_ms;
        }
        // P2-A：优先滑窗 p90；无成功样本时回退健康统计均值，再回退静态 latency。
        let base = self
            .tuning
            .p90_latency(&up.id)
            .or_else(|| self.runtime.health.stats(&up.id).avg_latency())
            .unwrap_or(f64::from(up.latency));
        if !base.is_finite() || base <= 0.0 {
            return snap.timeout_ms;
        }
        // `max(k × p90, p90 × 余量)`：k>1 时 k 项通常更大；k<1 时余量项兜底。
        let want = (base * snap.adaptive_timeout_k).max(base * TIMEOUT_P90_MARGIN);
        let lo = snap.adaptive_timeout_min_ms.min(snap.timeout_ms);
        (want.round().max(0.0) as u64).clamp(lo, snap.timeout_ms)
    }

    /// 起一个上游查询任务（按该上游自适应超时）。
    ///
    /// 返回值 = 该任务实际使用的超时（ms），供循环里做「是否超时」归因（P2-A 解锁器）。
    fn launch(
        &self,
        set: &mut JoinSet<UpstreamAnswer>,
        up: &UpstreamCfg,
        snap: &TuningSnapshot,
        qcode: u16,
        qname: &str,
        keep_raw: bool,
    ) -> u64 {
        self.note_dispatch();
        let t = self.timeout_for(up, snap);
        spawn_one(
            set,
            &self.runtime,
            up,
            qcode,
            qname,
            self.edns,
            self.udp_size,
            self.padding,
            self.x20,
            t,
            keep_raw,
        );
        t
    }

    /// 把 `next..` 的剩余候选**一次发齐**（幂等：`next` 到头后为空操作）。
    ///
    /// 返回每个新派发任务的 `(up_id, 生效超时 ms)`（供 P2-A 的超时解锁器归因）。
    #[allow(clippy::too_many_arguments)]
    fn launch_rest(
        &self,
        set: &mut JoinSet<UpstreamAnswer>,
        selected: &[UpstreamCfg],
        next: &mut usize,
        snap: &TuningSnapshot,
        qcode: u16,
        qname: &str,
        keep_raw: bool,
    ) -> Vec<(String, u64)> {
        let mut dispatched = Vec::new();
        while *next < selected.len() {
            let up = &selected[*next];
            let t = self.launch(set, up, snap, qcode, qname, keep_raw);
            dispatched.push((up.id.clone(), t));
            *next += 1;
        }
        dispatched
    }

    /// P2-A：结果归因 —— 记录成功样本 / 超时计数（滑窗 p90 与解锁器的数据源）。
    ///
    /// `would` = 该上游本次的**生效超时**（0 = 未知，不做超时判定）：无有效应答且实测
    /// 延迟已达生效超时的 90% → 判为超时（构建/解析错不会这么慢）。
    fn note_result(&self, ans: &UpstreamAnswer, would: u64) {
        let ok = ans.rcode.is_some();
        let timed_out = !ok && would > 0 && ans.lat >= (would as f64) * 0.9;
        self.tuning
            .record_result(&ans.up_name, ok, timed_out, ans.lat.max(0.0) as u64);
    }

    /// 数据面物理请求计数 +1（`/api/status.counters.upstream_requests`）。
    ///
    /// `counters.upstream_queries` 是**逻辑**口径（每个真正发过上游的客户端查询 +1，
    /// 见 `dns.rs`），无法反映并发/对冲带来的物理放大；本计数器补上物理口径，
    /// 供优化项 1/3 的上游 QPS 对比。
    fn note_dispatch(&self) {
        self.tuning.note_dispatch();
    }

    /// 2.1.11 优化项 3：逐上游 p90 对冲时刻（ms）。
    ///
    /// `cands` = 本轮**已选中且有派发计划**的候选（按排序，`[0]` 为首发）。
    ///
    /// 语义：**取候选里最大的实测滑窗 p90**（"最慢的那台按自己的历史本该回了"），
    /// 再乘 `hedge_slowest_factor`（默认 1.0），夹取到 `[1, timeout_ms]`。
    ///
    /// - 只要有**任一**候选有样本，就用 p90 决策（并计 [`Self::hedge_p90_decisions`]）；
    /// - **一个样本都没有**（冷启动）→ 退回 `hedge_after_ms`（默认 200ms，与 2.1.9 一致）；
    /// - 上限是 `timeout_ms`：对冲时刻晚于单上游超时就没有意义（那时已经在超时收口）。
    ///
    /// **为什么取 max（而不是首发/最快的 p90）**——2.1.11 真机实测（本机 192.168.0.236，
    /// `/metrics` 的 `ebpdns_upstream_latency_ms_quantile`，60s 压测窗口）：
    ///
    /// | 上游 | p50 | **p90** | avg |
    /// |---|---|---|---|
    /// | `lan235`（UDP，首发） | 115.0 | **155.4** | 33.3 |
    /// | `lan235tcp` | 112.9 | **163.9** | 14.2 |
    /// | `ali-doh3` | 262.1 | **275.6** | 61.7 |
    ///
    /// 固定 `hedge_after_ms=200` 的问题：它对**每一个**上游都是同一把尺子。实测
    /// `lan235` 的 p90 已达 155ms、`ali-doh3` 的 p90 达 275ms，而 200ms 落在两者
    /// 之间 —— 对 DoH3 是"必然早触发"（每次查询都白追加候选，`upstream_hedge`
    /// 实测 1983 次 / 约 2000 次 cache miss ≈ 每查询 1 次），对 LAN 则完全看运气。
    /// 按每个候选自己的 p90 决定后，对冲只在"这台按自己的历史本该回了却没回"时发生：
    /// 用 **max** 是**抗放大**的选择（给最慢候选足够的自证时间，不提前撒请求），
    /// 用 min 则会在 LAN 抖动时把多余候选一起放出去（`min(p90)=155ms` 仍会在 ~40%
    /// 的查询上早触发）。要更激进可下调本因子（0.5 → 提前一半）。
    ///
    /// 收敛逻辑不变：负向路径仍由 `resolve.rs` 的"收齐有效票 / 单票 + F-NX 升级波"
    /// 控制，本函数只改**何时追加**，不改**追加谁**、不改 quorum 语义。
    pub(crate) fn hedge_delay_for(
        &self,
        cands: &[UpstreamCfg],
        snap: &TuningSnapshot,
    ) -> (u64, bool) {
        let mut best: Option<f64> = None;
        for up in cands {
            if let Some(p) = self.tuning.p90_latency(&up.id) {
                if p.is_finite() && p > 0.0 {
                    best = Some(match best {
                        Some(b) => b.max(p),
                        None => p,
                    });
                }
            }
        }
        let Some(base) = best else {
            return (snap.hedge_after_ms.max(1), false);
        };
        let want = base * snap.hedge_slowest_factor;
        let want = if want.is_finite() && want > 0.0 {
            want.round()
        } else {
            snap.hedge_after_ms as f64
        };
        let ms = (want as u64).clamp(1, snap.timeout_ms.max(1));
        (ms, true)
    }
}

/// 起一个上游查询任务并挂到 `set`（优化项 1：单个任务 panic/取消不影响其余）。
///
/// **2.1.29**：`keep_raw=true` 时**不解析 rdata**，只从响应头取 rcode 并把上游
/// 原始字节放进 `UpstreamAnswer::raw`（未知 qtype 透传用；不缓存、原样回传）。
#[allow(clippy::too_many_arguments)]
fn spawn_one(
    set: &mut JoinSet<UpstreamAnswer>,
    runtime: &Arc<UpstreamRuntime>,
    up: &UpstreamCfg,
    qcode: u16,
    qname: &str,
    edns: bool,
    udp_size: u32,
    padding: bool,
    x20: bool,
    timeout_ms: u64,
    keep_raw: bool,
) {
    let rt_cfg = upcfg_to_runtime(up);
    let runtime = runtime.clone();
    // answer 标签用 up.id（熔断器键），与 finish_resolve 内按 rcode 喂点一致。
    let up_key = up.id.clone();
    let qn = qname.to_string();
    // padding：仅加密协议（DoH/DoT/DoQ/DoH3）报文填充 128B 对齐。
    let do_padding = padding && rt_cfg.proto.is_encrypted();
    // 0x20：查询名大小写随机化（bailiwick 用规范化原名锚定，不受影响）。
    let wire_qname = if x20 { x20_case(&qn) } else { qn.clone() };
    let allow_priv = up.allow_private_ip;
    set.spawn(async move {
        let query = match build_query(
            &wire_qname,
            qcode,
            None,
            edns,
            None,
            Some(udp_size),
            do_padding,
        ) {
            Ok((b, _)) => b,
            Err(_) => {
                return UpstreamAnswer {
                    up_name: up_key,
                    rcode: None,
                    ..Default::default()
                }
            }
        };
        let outcome = runtime.query(&rt_cfg, &query, timeout_ms).await;
        let lat = outcome.latency_ms as f64;
        if outcome.ok {
            let data = outcome.data.unwrap_or_default();
            if keep_raw {
                // 透传：**不解析**，只读 header 的 rcode（<12 字节视为无效应答）。
                let rcode = if data.len() >= 12 {
                    Some(data.get(3).copied().unwrap_or(0) & 0x0F)
                } else {
                    None
                };
                return UpstreamAnswer {
                    up_name: up_key,
                    rcode,
                    lat,
                    raw: Some(data),
                    ..Default::default()
                };
            }
            let mut ans = classify_one(&up_key, &qn, &data, qcode, lat);
            // M8：按上游豁免标记，该上游贡献的答案整体放行私网。
            ans.allow_private = allow_priv;
            // 熔断喂点统一在 finish_resolve 按 rcode 进行（含本处 classify 的 rcode
            // 与下方传输失败的 rcode=None）；此处不再单独喂，避免双计。
            ans
        } else {
            // 失败归因进日志：QueryOutcome::err 对 QUIC 路径带证书/超时/对端应用
            // 错误码（如 DoQ 的 `... ApplicationClose { error_code: 2 }`），
            // 此前这条信息在数据面被整体丢弃，运维只能看到 /api/upstreams 的
            // 成功率而无法区分"服务端拒绝"与"网络抖动"。debug 级：不污染 info 日志。
            tracing::debug!(
                upstream = %up_key,
                proto = ?rt_cfg.proto,
                error = %outcome.err,
                "上游查询失败"
            );
            UpstreamAnswer {
                up_name: up_key,
                rcode: None,
                lat,
                ..Default::default()
            }
        }
    });
}

/// 正向答案判定（优化项 1）：`NOERROR` + 有目标答案 + 未被截断。
fn is_positive(ans: &UpstreamAnswer) -> bool {
    ans.rcode == Some(0) && !ans.answers.is_empty() && !ans.udp_truncated
}

#[async_trait]
impl ParallelQuerier for ProductionQuerier {
    async fn query_parallel(
        &self,
        ups: &[UpstreamCfg],
        qname: &str,
        qtype: &str,
        _depth: u32,
    ) -> Vec<UpstreamAnswer> {
        // P0-4：不支持的 qtype 不发上游（resolve_inner 已拒为 NOTIMP，这里返回空结果
        // 是类型完备的防御分支）。
        let Some(qcode) = qtype_code(qtype) else {
            return Vec::new();
        };
        self.query_parallel_code(ups, qname, qcode, false).await
    }

    /// **2.1.29**：未知 qtype 透传 —— 按**原始 u16** 组包，返回上游原字节。
    async fn query_parallel_raw(
        &self,
        ups: &[UpstreamCfg],
        qname: &str,
        qtype: u16,
        _depth: u32,
    ) -> Vec<UpstreamAnswer> {
        self.query_parallel_code(ups, qname, qtype, true).await
    }
}

impl ProductionQuerier {
    /// 上游扇出的**唯一**实现：受理类型（`keep_raw=false`，解析 rdata）与未知 qtype
    /// 透传（`keep_raw=true`，只取 header rcode + 原字节）共用熔断过滤 / 自适应对冲 /
    /// 健康统计 / 在途闸门，避免两条路径在超时与熔断口径上漂移。
    async fn query_parallel_code(
        &self,
        ups: &[UpstreamCfg],
        qname: &str,
        qcode: u16,
        keep_raw: bool,
    ) -> Vec<UpstreamAnswer> {
        // M11：熔断判定用单调秒（monotonic，防 NTP/改时钟回拨）。
        let now_mono = self.clock.monotonic_ms() / 1000.0;

        // 熔断打开的上游本轮跳过（不参与 quorum）。
        //
        // **2.1.49（AUD-12）**：同一 `id` 只允许一个物理票源。`PUT /api/config`
        // 不校验 upstream id 唯一；若两个条目共用一个 id，旧实现会把同一票源
        // 派发两次，`finish_resolve` 侧再以 `nx.len()` 计数就能用「一个物理上游的
        // 两条结果」凑满 quorum。这里按 id 去重（保留首个），保证 candidates /
        // 票源 / 实际派发三者同口径。
        let mut selected: Vec<UpstreamCfg> = Vec::new();
        let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        for up in ups {
            if !up.enabled {
                continue;
            }
            if !seen_ids.insert(up.id.clone()) {
                tracing::warn!(
                    upstream_id = %up.id,
                    reason = "配置中存在重复 upstream id；本轮只派发首个，避免重复 id 伪造 quorum 票源",
                    "跳过重复 id 的上游"
                );
                continue;
            }
            if self.cb.is_open(&up.id, now_mono) {
                continue;
            }
            selected.push(up.clone());
        }
        // M10：所有上游都被熔断打开 / selected 为空 → 放行全部 enabled 上游重试一轮兜底，
        // 不直接空结果 SERVFAIL。优化项 6：兜底放行必须可见（日志 + 计数器 + id 列表）。
        if selected.is_empty() {
            let mut seen_released: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            let released: Vec<UpstreamCfg> = ups
                .iter()
                .filter(|u| u.enabled && seen_released.insert(u.id.clone()))
                .cloned()
                .collect();
            if !released.is_empty() {
                let ids: Vec<String> = released.iter().map(|u| u.id.clone()).collect();
                let n = self.cb.note_all_open(&ids);
                tracing::warn!(
                    upstreams = ?ids,
                    released = ids.len(),
                    all_open_total = n,
                    timeout_ms = self.tuning.timeout_ms(),
                    reason = "全部候选上游处于熔断打开态（或均不可用）→ 兜底放行重试一轮，本轮不跳过任何上游",
                    "熔断兜底放行"
                );
            }
            selected = released;
        }
        if selected.is_empty() {
            return Vec::new();
        }

        let snap = self.tuning.snapshot();
        // >>> PATCH242A P0-1 quorum-target BEGIN
        // **2.1.42（P0-1）**：负票 quorum 的**分母 = 本波实际派发的候选数**。
        //
        // 旧实现把分母建在 "收到首张负票后 abort 其余、只剩 1 条结果" 上，于是
        // `nxdomain_quorum=2` 永远只能算出 1；这里改用派发前的候选数（单上游
        // 配置仍会合法地塌缩到 1，保持可用性）。
        // **2.1.45（P1-1/P1-3）**：**不再**按本轮候选数钳制 —— 阈值恒为配置值。
        // 钳制会把"可用上游少"退化成"少票即确认"（REV247 P1-3）；本处
        // `negative_votes >= quorum_target` 只用于**提前 abort**，阈值必须与
        // `resolve.rs` 的确认口径一致：少于 quorum 票就继续等迟到票，绝不提前收口。
        let quorum_target = snap.nxdomain_quorum.max(1);
        // <<< PATCH242A P0-1 quorum-target END
        // 优化项 3：自适应并发仅在"有多个候选"时才有意义。
        let adaptive = snap.adaptive_parallel && selected.len() > 1;
        // 2.1.11 优化项 3：对冲时刻由**逐上游实测 p90** 决定（无样本才退回 hedge_after_ms）。
        let (hedge_ms, hedge_from_p90) = self.hedge_delay_for(&selected, &snap);
        if hedge_from_p90 {
            self.tuning
                .hedge_p90_decisions
                .fetch_add(1, Ordering::Relaxed);
        }
        let hedge = Duration::from_millis(hedge_ms.max(1));
        let mut set: JoinSet<UpstreamAnswer> = JoinSet::new();
        let mut out: Vec<UpstreamAnswer> = Vec::with_capacity(selected.len());
        // P2-A：已派发上游的生效超时（up_id → ms），用于「本次是否超时」归因。
        let mut timeouts: HashMap<String, u64> = HashMap::new();
        // >>> PATCH242A P0-1 vote-counter BEGIN
        // **2.1.42（P0-1）**：负票（NXDOMAIN / NODATA）计数；只有达到
        // `quorum_target` 才收口。传输失败/弃权不计票。
        let mut negative_votes = 0usize;
        // <<< PATCH242A P0-1 vote-counter END

        // 先发最快的一个（优化项 3：健康时只发 1 个）。
        let t0 = self.launch(&mut set, &selected[0], &snap, qcode, qname, keep_raw);
        timeouts.insert(selected[0].id.clone(), t0);
        let mut next = 1usize;
        if !adaptive {
            // 兼容（非自适应）路径：首批一次全部发出，行为与 2.1.7 相同，
            // 只多"首个正向答案即返回"（优化项 1）。
            for (id, t) in self.launch_rest(
                &mut set, &selected, &mut next, &snap, qcode, qname, keep_raw,
            ) {
                timeouts.insert(id, t);
            }
        }
        // A1：对冲倒计时以**首次派发**为起点（固定 deadline，不因收到负向答案而重置）。
        let deadline = tokio::time::Instant::now() + hedge;

        loop {
            if set.is_empty() {
                break;
            }
            let can_hedge = next < selected.len();
            tokio::select! {
                biased;
                joined = set.join_next() => {
                    match joined {
                        Some(Ok(ans)) => {
                            let would = timeouts.get(&ans.up_name).copied().unwrap_or(0);
                            self.note_result(&ans, would);
                            // **2.1.29（透传）**：任何**有效的 DNS 响应**（任意 rcode，
                            // 含 NXDOMAIN/NODATA/SERVFAIL）都算本轮结论 —— 原样回传，
                            // 不做 quorum 表决、也没有"目标答案"概念。
                            if keep_raw && ans.rcode.is_some() {
                                self.tuning.note_early_return();
                                out.push(ans);
                                break;
                            }
                            // 优化项 1：首个正向答案即返回（其余任务 abort，立刻释放
                            // 上游连接与超时预算）。JoinSet Drop 会取消剩余任务。
                            if is_positive(&ans) {
                                self.tuning.note_early_return();
                                out.push(ans);
                                break;
                            }
                            // >>> PATCH242A P0-1 negative-wait BEGIN
                            // **P0-1（2.1.42）：负票不再"首票即 abort"。**
                            //
                            // 旧行为：任意一条 NXDOMAIN/NODATA → `have_vote=true` →
                            // `abort_all()`。于是已派发的迟到正向 A/AAAA 被丢弃，且
                            // `resolve.rs::quorum_threshold` 的分母塌缩到 1 ⇒ 配置的
                            // `nxdomain_quorum=2` 实际不可达 ⇒ 错误 NXDOMAIN 写负缓存并
                            // 被 RFC 8020 放大到整棵子树。
                            //
                            // 新行为：
                            // - 负票计数 < `quorum_target`：立即把**剩余候选全部派发**
                            //   （不再等 hedge），继续等第二张负票或迟到的正向答案；
                            // - 正向答案一到就赢（上面的 `is_positive` 分支）；
                            // - 负票达到 `quorum_target` 才 abort 其余候选并收口；
                            // - 全部候选都答完仍不足 quorum ⇒ 原样返回；resolve 侧用
                            //   **候选数**做阈值 ⇒ SERVFAIL，绝不写负缓存/登记 RFC 8020。
                            let negative = is_negative(&ans);
                            out.push(ans);
                            if negative {
                                negative_votes += 1;
                                if negative_votes < quorum_target {
                                    for (id, t) in self.launch_rest(
                                        &mut set,
                                        &selected,
                                        &mut next,
                                        &snap,
                                        qcode,
                                        qname,
                                        keep_raw,
                                    ) {
                                        timeouts.insert(id, t);
                                    }
                                    // 继续等剩余票 / 迟到的正向答案（JoinSet 仍持有
                                    // 已派发任务；下一轮 select 会先收正向）。
                                    continue;
                                }
                                self.tuning.note_quorum_abort();
                                set.abort_all();
                                break;
                            }
                            // <<< PATCH242A P0-1 negative-wait END
                        }
                        // 任务被取消/panic：该上游本轮视为失败（rcode=None），不阻断其余。
                        Some(Err(_)) => {}
                        None => break,
                    }
                }
                // 优化项 3：首选在 hedge_after_ms 内没有回任何东西 → 追加剩余候选对冲。
                _ = tokio::time::sleep_until(deadline), if can_hedge => {
                    self.tuning.note_hedge();
                    for (id, t) in
                        self.launch_rest(&mut set, &selected, &mut next, &snap, qcode, qname, keep_raw)
                    {
                        timeouts.insert(id, t);
                    }
                }
            }
        }
        out
    }
}

/// 非正向答案判定（A1）：NXDOMAIN 或 NODATA（NOERROR 但无目标答案）——这两类都需要
/// quorum 表决才可信；传输失败（`rcode=None`）不计票（它是"没投票"，不是"投反对票"）。
fn is_negative(ans: &UpstreamAnswer) -> bool {
    ans.rcode == Some(3) || (ans.rcode == Some(0) && ans.answers.is_empty())
}

/// DNS 0x20：随机大写查询名中的 ASCII 字母（大小写不敏感投毒防护）。
fn x20_case(name: &str) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    name.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() && rng.gen_bool(0.5) {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn up(proto: &str, url: &str) -> UpstreamCfg {
        UpstreamCfg {
            url: url.to_string(),
            proto: proto.to_string(),
            ..UpstreamCfg::test_up("u")
        }
    }

    /// 带显式 `id`（= 健康统计/p90 滑窗的键）的上游。2.1.11 优化项 2/3 的单测需要
    /// 「候选 id」与「喂点 id」一致：`up()` 固定 id="u"，用它断言会永远查不到 p90。
    fn up_id(id: &str, proto: &str, url: &str) -> UpstreamCfg {
        UpstreamCfg {
            url: url.to_string(),
            proto: proto.to_string(),
            ..UpstreamCfg::test_up(id)
        }
    }

    /// 回归（真实服务器发现）：DoH/DoH3 的 `url` 必须是**请求路径**。
    /// 旧实现写死 `https://host:port/dns-query` 整串 → DoH 请求行 / H3 `:path` 变成
    /// `/https://host:port/dns-query`，真实服务器 100% 失败（实测 alidoh 0/16、alidoh3 0/4）。
    #[test]
    fn upcfg_to_runtime_url_is_a_path_not_an_absolute_url() {
        for (proto, url, want) in [
            ("doh", "/dns-query", "/dns-query"),
            ("doh3", "/dns-query", "/dns-query"),
            ("doh", "", "/dns-query"),       // 空串 → 协议默认路径
            ("doh3", "resolve", "/resolve"), // 无前导斜杠 → 补上
            (
                "doh3",
                "https://dns.alidns.com:443/dns-query", // 完整 URL → 剥成路径
                "/dns-query",
            ),
        ] {
            let rt = upcfg_to_runtime(&up(proto, url));
            assert_eq!(rt.url, want, "proto={proto} url={url:?}");
            assert!(
                !rt.url.contains("://"),
                "proto={proto} url={url:?} → {:?} 泄漏了 scheme（缺陷回归）",
                rt.url
            );
        }
        // 明文协议不带路径。
        assert_eq!(upcfg_to_runtime(&up("udp", "/dns-query")).url, "");
        assert_eq!(upcfg_to_runtime(&up("tcp", "")).url, "");
    }

    #[test]
    fn upcfg_to_runtime_port_defaults_and_proto() {
        let mut u = up("doh3", "/dns-query");
        u.port = 0;
        let rt = upcfg_to_runtime(&u);
        assert_eq!(rt.port, 443, "DoH3 缺省端口 443");
        assert_eq!(rt.proto, Proto::Doh3);
        let mut u = up("doq", "");
        u.port = 0;
        assert_eq!(upcfg_to_runtime(&u).port, 853, "DoQ 缺省端口 853");
    }

    /// 优化项 3/4：调参句柄默认值 = 配置默认值；`fixed()` 保持 2.1.7 的固定超时语义。
    #[test]
    fn tuning_snapshot_defaults_and_fixed_mode() {
        let cfg = ResolverConfig::default();
        let t = QuerierTuning::from_config(&cfg);
        let s = t.snapshot();
        assert_eq!(s.timeout_ms, 1500);
        assert!(s.adaptive_parallel, "默认开启自适应并发");
        assert_eq!(s.hedge_after_ms, 200);
        assert!(
            (s.hedge_slowest_factor - 1.0).abs() < 1e-9,
            "2.1.11 优化项 3：默认因子 1.0 = 生效时刻就是实测 p90（零行为风险）"
        );
        assert!(
            s.adaptive_timeout,
            "默认开启自适应超时（但默认下限=timeout_ms→不收紧）"
        );
        assert!((s.adaptive_timeout_k - 8.0).abs() < 1e-9);
        assert_eq!(s.adaptive_timeout_min_ms, 1500);
        assert_eq!(
            s.adaptive_timeout_min_ms, s.timeout_ms,
            "默认下限 = timeout_ms → timeout_for 恒等于 timeout_ms（与 2.1.7 一致）"
        );

        // 兼容构造（reprobe 探测路径）：自适应全关。
        let f = QuerierTuning::fixed(900);
        let fs = f.snapshot();
        assert_eq!(fs.timeout_ms, 900);
        assert!(!fs.adaptive_parallel);
        assert!(!fs.adaptive_timeout);
    }

    /// **2.1.11 优化项 3**：对冲时刻由**逐上游实测 p90** 决定（不是固定 `hedge_after_ms`）。
    ///
    /// 真机依据（本机 `/metrics` 的 `ebpdns_upstream_latency_ms_quantile`）：
    /// `lan235` p90=155.4ms、`lan235tcp` p90=163.9ms、`ali-doh3` p90=275.6ms，
    /// 而固定 `hedge_after_ms=200` 对三者是同一把尺子 → 对 DoH3 必然早触发
    /// （实测 `upstream_hedge` ≈ 1.0 次/查询）。断言：
    /// 1. 有样本 → 用 p90（取 **max**，抗放大），并报告 `from_p90=true`；
    /// 2. 无样本（冷启动）→ 退回 `hedge_after_ms`（与 2.1.9 逐位一致）；
    /// 3. 因子可调（0.5 → 提前一半）；
    /// 4. 上限 `timeout_ms`（对冲不得晚于超时）。
    #[test]
    fn hedge_delay_follows_per_upstream_p90_with_static_fallback() {
        let rt = Arc::new(UpstreamRuntime::new());
        let q = ProductionQuerier::new(
            rt,
            SharedCircuit::new(),
            Arc::new(crate::clock::MockClock::new(0.0)),
            1500,
            false,
            1232,
            false,
            false,
        );
        let cfg = ResolverConfig::default();
        let t = QuerierTuning::from_config(&cfg);
        let q = q.with_tuning(t.clone());
        let u1 = up_id("lan235", "udp", "");
        let u2 = up_id("ali-doh3", "doh3", "/dns-query");

        // 冷启动：无样本 → 静态 hedge_after_ms=200，且 from_p90=false。
        let snap = t.snapshot();
        let (ms, from_p90) = q.hedge_delay_for(&[u1.clone(), u2.clone()], &snap);
        assert_eq!(ms, 200, "无 p90 样本必须退回 hedge_after_ms");
        assert!(!from_p90);

        // lan235 p90=155、ali-doh3 p90=276 → 取 max=276（抗放大）。
        for _ in 0..10 {
            t.record_result("lan235", true, false, 155);
            t.record_result("ali-doh3", true, false, 276);
        }
        let snap = t.snapshot();
        let (ms, from_p90) = q.hedge_delay_for(&[u1.clone(), u2.clone()], &snap);
        assert_eq!(ms, 276, "对冲时刻 = max(候选 p90)，不再固定 200ms");
        assert!(from_p90, "必须标记为 p90 决策（可观测）");

        // 因子 0.5 → 提前一半。
        // **2.1.24**：用结构体更新语法（`clippy::field_reassign_with_default`）。
        let c2 = ResolverConfig {
            hedge_slowest_factor: 0.5,
            ..Default::default()
        };
        let t2 = QuerierTuning::from_config(&c2);
        let q2 = ProductionQuerier::new(
            Arc::new(UpstreamRuntime::new()),
            SharedCircuit::new(),
            Arc::new(crate::clock::MockClock::new(0.0)),
            1500,
            false,
            1232,
            false,
            false,
        )
        .with_tuning(t2.clone());
        for _ in 0..10 {
            t2.record_result("lan235", true, false, 155);
        }
        let snap2 = t2.snapshot();
        assert!((snap2.hedge_slowest_factor - 0.5).abs() < 1e-9);
        assert_eq!(
            q2.hedge_delay_for(std::slice::from_ref(&u1), &snap2).0,
            78,
            "155*0.5=77.5→78"
        );

        // 上限 timeout_ms：p90 大于超时时不得晚于超时。
        let t3 = QuerierTuning::from_config(&cfg);
        for _ in 0..10 {
            t3.record_result("slow", true, false, 9_000);
        }
        let q3 = ProductionQuerier::new(
            Arc::new(UpstreamRuntime::new()),
            SharedCircuit::new(),
            Arc::new(crate::clock::MockClock::new(0.0)),
            1500,
            false,
            1232,
            false,
            false,
        )
        .with_tuning(t3.clone());
        let snap3 = t3.snapshot();
        assert_eq!(
            q3.hedge_delay_for(&[up_id("slow", "doh", "/dns-query")], &snap3)
                .0,
            1500,
            "对冲时刻夹取到 timeout_ms"
        );
    }

    /// 优化项 4：`timeout = clamp(k*eff_lat, 下限, timeout_ms)`，静态兜底值不放大超时；
    /// 且**默认参数下恒等于 `timeout_ms`**（默认不收紧）。
    #[test]
    fn adaptive_timeout_clamps_to_floor_and_cap() {
        let rt = Arc::new(UpstreamRuntime::new());
        // 默认调参：下限 = timeout_ms → 任何均值都得到 timeout_ms（零行为变更）。
        let q = ProductionQuerier::new(
            rt.clone(),
            SharedCircuit::new(),
            Arc::new(crate::clock::MockClock::new(0.0)),
            1500,
            false,
            1232,
            false,
            false,
        )
        .with_tuning(QuerierTuning::from_config(&ResolverConfig::default()));
        let snap = q.tuning().snapshot();
        let mut u = UpstreamCfg::test_up("neutral");
        u.latency = 5000;
        rt.health.record("neutral", true, 60);
        assert_eq!(
            q.timeout_for(&u, &snap),
            1500,
            "默认（下限=timeout_ms）必须与 2.1.7 的固定超时逐位一致"
        );
        rt.health.record("neutral", true, 1200);
        assert_eq!(q.timeout_for(&u, &snap), 1500);

        // 显式收紧（下限 500 / k=5）：验证 clamp 逻辑本身。
        let tight = ResolverConfig {
            adaptive_timeout_min_ms: 500,
            adaptive_timeout_k: 5.0,
            ..ResolverConfig::default()
        };
        let q2 = ProductionQuerier::new(
            rt.clone(),
            SharedCircuit::new(),
            Arc::new(crate::clock::MockClock::new(0.0)),
            1500,
            false,
            1232,
            false,
            false,
        )
        .with_tuning(QuerierTuning::from_config(&tight));
        let snap2 = q2.tuning().snapshot();
        // 无实测样本 → 静态延迟 5000 → 被 timeout_ms 封顶。
        let mut nu = UpstreamCfg::test_up("no-sample");
        nu.latency = 5000;
        assert_eq!(q2.timeout_for(&nu, &snap2), 1500);
        // 实测均值 60ms → 5*60 = 300 < 下限 500 → 取下限。
        rt.health.record("fast", true, 60);
        let fast = UpstreamCfg::test_up("fast");
        assert_eq!(q2.timeout_for(&fast, &snap2), 500);
        // 实测均值 200ms → 5*200 = 1000（下限与上限之间）。
        let mid = UpstreamCfg::test_up("mid");
        rt.health.record("mid", true, 200);
        assert_eq!(q2.timeout_for(&mid, &snap2), 1000);
        // 实测均值 800ms → 5*800 = 4000 → 被 timeout_ms=1500 封顶。
        let slow = UpstreamCfg::test_up("slow");
        rt.health.record("slow", true, 800);
        assert_eq!(q2.timeout_for(&slow, &snap2), 1500);
    }

    /// 优化项 1：正向答案判定（NOERROR + 非空 + 未截断）。
    #[test]
    fn positive_answer_predicate() {
        let mut a = UpstreamAnswer {
            up_name: "u".into(),
            rcode: Some(0),
            ..Default::default()
        };
        assert!(!is_positive(&a), "空答案不算正向");
        a.answers.push(crate::types::ResolveAnswer {
            value: "1.2.3.4".into(),
            ttl: 60.0,
            rtype: 1,
            name: None,
        });
        assert!(is_positive(&a));
        a.udp_truncated = true;
        assert!(!is_positive(&a), "截断应答不算正向（需 TCP 回退/表决）");
        a.udp_truncated = false;
        a.rcode = Some(3);
        assert!(!is_positive(&a), "NXDOMAIN 需等满一批做 quorum");
    }

    /* ==================== P2-A：自适应超时（p90 + 解锁器） ==================== */

    /// A1：负向答案判定（NXDOMAIN / NODATA 计票；传输失败不计票）。
    #[test]
    fn a1_negative_predicate_counts_only_real_negative_answers() {
        let nx = UpstreamAnswer {
            up_name: "u".into(),
            rcode: Some(3),
            ..Default::default()
        };
        assert!(is_negative(&nx), "NXDOMAIN 计负向票");
        let nd = UpstreamAnswer {
            up_name: "u".into(),
            rcode: Some(0),
            ..Default::default()
        };
        assert!(is_negative(&nd), "NODATA 计负向票");
        let mut pos = nd.clone();
        pos.answers.push(crate::types::ResolveAnswer {
            value: "1.2.3.4".into(),
            ttl: 60.0,
            rtype: 1,
            name: None,
        });
        assert!(!is_negative(&pos), "正向答案不是负向票");
        assert!(
            !is_negative(&UpstreamAnswer::fail("u")),
            "传输失败（rcode=None）是「没投票」，不是反对票"
        );
    }

    /// A1：`nxdomain_quorum` 随配置进入快照（负向通道收敛阈值的数据源）。
    #[test]
    fn a1_quorum_is_exposed_in_tuning_snapshot() {
        let cfg = ResolverConfig {
            nxdomain_quorum: 3,
            ..ResolverConfig::default()
        };
        let t = QuerierTuning::from_config(&cfg);
        assert_eq!(t.snapshot().nxdomain_quorum, 3);
        // 0 非法 → 至少 1（与 resolver 侧 `max(1)` 同口径）。
        let t0 = QuerierTuning::from_config(&ResolverConfig {
            nxdomain_quorum: 0,
            ..ResolverConfig::default()
        });
        assert_eq!(t0.snapshot().nxdomain_quorum, 1);
    }

    /// P2-A：基准是滑窗 **p90**，不是算术均值 —— 一次 100ms 快样本不得把
    /// 32 个 1500ms 样本的基准拉低（旧实现会被均值钉死并"只降不升"）。
    #[test]
    fn p2a_baseline_is_window_p90_not_mean() {
        // k=1.0、下限 100 → base*1.0 决定超时；样本窗里全是 1500ms + 单个 100ms。
        let t2 = QuerierTuning::from_config(&ResolverConfig {
            adaptive_timeout_min_ms: 100,
            adaptive_timeout_k: 1.0,
            ..ResolverConfig::default()
        });
        for _ in 0..32 {
            t2.record_result("u1", true, false, 1500);
        }
        t2.record_result("u1", true, false, 100);
        // 算术均值 ≈ 1454（旧基准）；p90 = 1500（nearest-rank ceil(0.9*33)=30 → 第 30 小）。
        assert_eq!(t2.p90_latency("u1"), Some(1500.0), "p90 必须抵抗单个快样本");
        let q = ProductionQuerier::new(
            Arc::new(UpstreamRuntime::new()),
            SharedCircuit::new(),
            Arc::new(crate::clock::MockClock::new(0.0)),
            1500,
            false,
            1232,
            false,
            false,
        )
        .with_tuning(t2);
        let snap = q.tuning().snapshot();
        assert_eq!(
            q.timeout_for(&UpstreamCfg::test_up("u1"), &snap),
            1500,
            "p90=1500 → 不得被单次快样本收紧"
        );
    }

    /// P2-A：基准确实随滑窗整体变快而下移（滞回但不冻结）。
    #[test]
    fn p2a_baseline_follows_sustained_slowdown() {
        let t = QuerierTuning::fixed(1500);
        for _ in 0..40 {
            t.record_result("u1", true, false, 200);
        }
        // p90 = 200（全部同上限）。
        assert_eq!(t.p90_latency("u1"), Some(200.0));
    }

    /// P2-A 解锁器：连续 3 次超时 → 丢弃滑窗样本（回退 `timeout_ms`）。
    #[test]
    fn p2a_consecutive_timeouts_unlock_to_configured_timeout() {
        let t = QuerierTuning::fixed(1500);
        for _ in 0..32 {
            t.record_result("u1", true, false, 1500);
        }
        assert_eq!(t.p90_latency("u1"), Some(1500.0));
        // 两次超时：仍被钉住（滞回）。
        t.record_result("u1", false, true, 1400);
        t.record_result("u1", false, true, 1400);
        assert_eq!(t.timeout_unlocks(), 0, "未达阈值不得解锁");
        assert_eq!(t.p90_latency("u1"), Some(1500.0));
        // 第三次超时：解锁 → 滑窗清空 → 回退到 timeout_ms 语义（None → 均值/静态兜底）。
        t.record_result("u1", false, true, 1400);
        assert_eq!(t.timeout_unlocks(), 1, "连续 3 次超时必须解锁");
        assert_eq!(t.p90_latency("u1"), None, "解锁后滑窗样本被丢弃");
        // 成功一次即清零连续超时计数。
        t.record_result("u1", false, true, 1400);
        t.record_result("u1", true, false, 120);
        t.record_result("u1", false, true, 1400);
        t.record_result("u1", false, true, 1400);
        assert_eq!(t.timeout_unlocks(), 1, "成功后连续超时计数必须清零");
    }

    /// P2-A：解锁日志限流（同一上游 60s 一条）——防止 syscheck「15 分钟 WARN/ERROR = 0」
    /// 被自愈行为刷屏（真实部署实测 3895 条）。
    #[test]
    fn p2a_unlock_log_is_rate_limited_per_upstream() {
        let m: Mutex<HashMap<String, f64>> = Mutex::new(HashMap::new());
        assert!(QuerierTuning::unlock_log_allowed(&m, "u1", 1_000.0));
        // 窗口内（<60s）全部抑制，且不影响其它上游。
        assert!(!QuerierTuning::unlock_log_allowed(&m, "u1", 1_001.0));
        assert!(!QuerierTuning::unlock_log_allowed(&m, "u1", 60_999.0));
        assert!(QuerierTuning::unlock_log_allowed(&m, "u2", 1_001.0));
        // 窗口过后放行。
        assert!(QuerierTuning::unlock_log_allowed(&m, "u1", 61_000.0));
    }

    /// P2-A：**抖动安全余量** —— `k < 1` 时生效超时不得低于观测 p90。
    ///
    /// 缺陷现场：p90=1500ms、k=0.5 → 旧公式给出 750ms < 上游自身 RTT → 下一轮必然
    /// 超时（慢上游被自己的 RTT 误杀）。修复后取 `max(k×p90, p90×1.2)` = 1800ms。
    #[test]
    fn p2a_effective_timeout_never_below_observed_p90() {
        let cfg = ResolverConfig {
            // `timeout_ms` 必须一并给出：`with_tuning` 以**句柄**为准
            // （`self.timeout_ms = tuning.timeout_ms()`），不给出会用默认 1500 把
            // 1800ms 的上限夹回 1500ms。
            timeout_ms: 2000,
            adaptive_timeout_min_ms: 200,
            adaptive_timeout_k: 0.5,
            ..ResolverConfig::default()
        };
        let t = QuerierTuning::from_config(&cfg);
        for _ in 0..8 {
            t.record_result("slow", true, false, 1500);
        }
        let p90 = t.p90_latency("slow").expect("有样本");
        assert!((p90 - 1500.0).abs() < 1e-6, "p90={p90}");
        let q = ProductionQuerier::new(
            Arc::new(UpstreamRuntime::new()),
            SharedCircuit::new(),
            Arc::new(crate::clock::MockClock::new(0.0)),
            2000,
            false,
            1232,
            false,
            false,
        )
        .with_tuning(t);
        let snap = q.tuning().snapshot();
        let eff = q.timeout_for(&UpstreamCfg::test_up("slow"), &snap);
        assert!(
            eff as f64 >= p90,
            "生效超时 {eff}ms 不得低于观测 p90={p90}ms（k<1 时必须被余量兜住）"
        );
        assert_eq!(eff, 1800, "max(0.5×1500, 1.2×1500)=1800ms");
        // 默认（下限 = timeout_ms）仍然等效关闭：恒等于 timeout_ms。
        let d = QuerierTuning::from_config(&ResolverConfig::default());
        for _ in 0..8 {
            d.record_result("slow", true, false, 1500);
        }
        let q2 = ProductionQuerier::new(
            Arc::new(UpstreamRuntime::new()),
            SharedCircuit::new(),
            Arc::new(crate::clock::MockClock::new(0.0)),
            1500,
            false,
            1232,
            false,
            false,
        )
        .with_tuning(d);
        let snap2 = q2.tuning().snapshot();
        assert_eq!(
            q2.timeout_for(&UpstreamCfg::test_up("slow"), &snap2),
            1500,
            "默认下限=timeout_ms → 余量不得改变'等效关闭'"
        );
    }

    /// P2-A：默认参数（下限 = timeout_ms = 1500）仍然"等效关闭"——不因 p90 而改变行为。
    #[test]
    fn p2a_defaults_still_equivalent_to_fixed_timeout() {
        let cfg = ResolverConfig::default();
        let t = QuerierTuning::from_config(&cfg);
        let q = ProductionQuerier::new(
            Arc::new(UpstreamRuntime::new()),
            SharedCircuit::new(),
            Arc::new(crate::clock::MockClock::new(0.0)),
            1500,
            false,
            1232,
            false,
            false,
        )
        .with_tuning(t.clone());
        let snap = q.tuning().snapshot();
        for _ in 0..32 {
            t.record_result("u1", true, false, 40);
        }
        assert_eq!(
            q.timeout_for(&UpstreamCfg::test_up("u1"), &snap),
            1500,
            "默认下限=timeout_ms → 恒等于 1500（与 2.1.7 逐位一致）"
        );
    }
}
