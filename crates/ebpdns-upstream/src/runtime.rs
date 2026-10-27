//! 共享运行时：持有 0x20 控制器、bootstrap 解析器、健康统计、DoH/DoT 连接池与 QUIC 管理器表，
//! 并按协议派发统一查询。

use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::bootstrap::BootstrapResolver;
use crate::config::UpstreamConfig;
use crate::doh;
use crate::dot;
use crate::header_check::X20Controller;
use crate::health::HealthKeeper;
use crate::pool::ConnPool;
use crate::quic::QuicManager;
use crate::tcp;
use crate::udp;
use crate::{elapsed_ms, Proto, QueryOutcome};

/// **2.1.15（P1 高并发 P50/P99 线性恶化）**：单上游**在途请求上限**的默认值。
///
/// 为什么需要它：2.1.14 实测阶梯 32/64/128/256 的 P50 为 226/457/903/1149 ms，
/// 与服务端**并发度近似线性**（约 +7ms/并发），而 `udp_dropped` 全程为 0 ——
/// 说明瓶颈已不是本进程的 UDP 闸门，而是**上游侧排队**：自适应并发 + 对冲（p90
/// 触发）在 256 并发下把 ~7.4 条线速请求/客户端查询压向 8 条上游，
/// 上游来不及应答 → 实测延迟被拉长 → 对冲更频繁 → 正反馈放大。
///
/// 修法：**每上游**按信号量约束在途请求；超出上限的请求在**本进程**排队等待
/// （有界等待 = 该上游剩余的 `timeout_ms` 预算），而不是继续向上游加压。
/// 上限取 32 的理由：
/// - 远大于单次客户端查询的对上游 fan-out（`max_parallel_upstreams` 默认 3 × 多 IP
///   并行 1~2 = 最多 3~6），因此**不改变**低并发/单查询行为；
/// - 与 DoH/DoT 连接池的每键上限 [`crate::pool::MAX_CONN`]（16）同量级：当一整批
///   请求都打到同一条加密上游（同一 `pool_key`）时，池内真并发最多 16，再往上只会
///   堆在 `pool.acquire` 的等待队列里空耗预算 —— 32 让**排队发生在本层**（可观测、
///   可按上游区分）而不是在池信号量上；
/// - 8 条启用上游 × 32 = 256 个在途上游请求，正好抵住 256 并发客户端的原始 fan-out，
///   再高就把压力交回上游。
pub const DEFAULT_MAX_INFLIGHT_PER_UPSTREAM: usize = 32;

/// **2.1.17（修复项 7）**：排队等待许可后，仍要为上游协议往返保留的最小预算。
///
/// 为什么需要它（2.1.16 lvl256 实测的解释）：`acquire()` 的等待时间与协议往返
/// 共享同一份 `timeout_ms` 预算。当闸门长期满载（256 并发、cap 被 governor 收到
/// `base/4`）时，一条请求可能在**排队上耗掉 2.9s**，只剩 100ms 做协议往返 ——
/// UDP 勉强能回，DoH/DoT/DoQ（1 个 RTT 起）必然失败，于是"排队"变成了
/// **确定性失败**而不是"晚一点成功"，反而把客户端超时数推高。
///
/// 现在的语义（**不改变超时上界，只改变"是否值得再试一次"**）：
/// 排队后剩余预算 `< MIN_POST_QUEUE_BUDGET` 时直接判该上游本次失败
/// （`inflight-queued-out-of-budget`），立即释放许可并把机会让给
/// fallback / 对冲候选 —— 而不是花 100ms 去做一次注定失败的握手。
///
/// 取值 250ms 的依据：本环境实测**最快**的上游往返（LAN UDP `192.168.0.235:53`）
/// p50 ≈ 115ms、p90 ≈ 155ms，两次 RTT + 处理留出的下界约 250ms；
/// 比它更小的预算连局域网 UDP 都不够，继续尝试只会在日志里制造"网络抖动"的假象。
/// 该值**不是**超时上限：正常路径（有许可、队列浅）完全不受影响（零行为变更）。
pub const MIN_POST_QUEUE_BUDGET_MS: u64 = 250;

/// 单上游在途请求闸门（惰性建信号量；键 = 上游 id）。
///
/// 语义与 [`ConnPool`] 的信号量一致但**层次更高**：池管的是"到某个 `pool_key`
/// 的并发连接"，本闸门管的是"到某条上游配置的并发**请求**"（UDP/TCP 也受约束，
/// 而池只覆盖 DoH/DoT/QUIC）。
///
/// **2.1.17（修复项 7）口径更正**：`entries` 是 `id -> Semaphore` 的**映射**，
/// 因此闸门**本来就是逐上游**的（每条上游独立容量、互不挤占）。2.1.16 的文档
/// （`lib.rs::converge_cap`）与 README 曾写成"一个闸门服务所有上游"，那是**错的**
/// 描述（会让人以为慢上游会把快上游的许可吃光）—— 实际不会。governor 的
/// 「整体下调」仍然是对所有上游下发**同一个数值**，但每台上游各自持有独立信号量。
///
/// 观测：`acquired` / `queued_wait` / `rejected` 三个累计量，供
/// `/api/status.counters` 与 `/metrics` 暴露"闸门是否真的在起作用"。
#[derive(Debug, Default)]
pub struct InflightLimiter {
    /// 上限（0 = 关闭闸门，行为与 2.1.14 完全一致）。
    cap: AtomicU64,
    entries: Mutex<HashMap<String, Arc<Semaphore>>>,
    /// 累计成功取到许可的次数。
    acquired: AtomicU64,
    /// 累计**等待过**（首次 `try_acquire` 失败）的次数。
    queued: AtomicU64,
    /// 累计因等待超预算而被拒的次数（= 该上游这次请求直接失败）。
    rejected: AtomicU64,
    /// **2.1.17（修复项 7）**：拿到许可但**剩余预算已不足以做一次协议往返**
    /// （`< MIN_POST_QUEUE_BUDGET_MS`）而主动放弃的次数。
    ///
    /// 为什么与 `rejected` 分开：`rejected` = "没等到许可"（闸门容量/超时问题），
    /// 本计数 = "等到了但已经来不及"（排队把预算吃光）。两者的治理手段不同
    /// （前者调 `upstream_max_inflight`/governor，后者说明排队已经深到不健康），
    /// 混在一个计数里无法归因。
    queued_gave_up: AtomicU64,
}

impl InflightLimiter {
    /// 上限（0 = 关闭）。
    pub fn cap(&self) -> usize {
        self.cap.load(Ordering::Relaxed) as usize
    }

    /// 设置上限（热刷新）。`cap == 0` 关闭闸门；缩小上限时不影响已持有的许可。
    ///
    /// 信号量容量只增不减（`Semaphore::add_permits`）：缩小上限靠**不再补发**许可实现，
    /// 因此不会造成 `OwnedSemaphorePermit` 归还时超出容量的未定义行为。
    pub fn set_cap(&self, cap: usize) {
        let old = self.cap.swap(cap as u64, Ordering::Relaxed) as usize;
        if cap > old {
            let extra = cap - old;
            let g = self.entries.lock();
            for sem in g.values() {
                sem.add_permits(extra);
            }
        }
    }

    // >>> 242B BEGIN P1-8-inflight >>> //
    /// **2.1.42-B（P1-8）**：清空闸门累计量（`/api/reset`）。
    pub fn reset_counters(&self) {
        for a in [
            &self.acquired,
            &self.queued,
            &self.rejected,
            &self.queued_gave_up,
        ] {
            a.store(0, Ordering::Relaxed);
        }
    }

    // <<< 242B END P1-8-inflight <<< //
    /// 累计量快照：`(acquired, queued, rejected)`。
    pub fn stats(&self) -> (u64, u64, u64) {
        (
            self.acquired.load(Ordering::Relaxed),
            self.queued.load(Ordering::Relaxed),
            self.rejected.load(Ordering::Relaxed),
        )
    }

    /// **2.1.17（修复项 7）**：拿到许可但预算已不够做一次协议往返的累计次数。
    ///
    /// 暴露面：`/api/status.counters.upstream_inflight_queued_gave_up` 与
    /// `/metrics` 的 `ebpdns_upstream_inflight_queued_gave_up_total`
    /// （与 `rejected_total` **分开**，两者的治理手段不同，见字段文档）。
    pub fn queued_gave_up(&self) -> u64 {
        self.queued_gave_up.load(Ordering::Relaxed)
    }

    /// 记一次"排队把预算吃光 ⇒ 主动放弃"（供 [`Self::acquire`] 与单测调用）。
    pub(crate) fn note_queued_gave_up(&self) {
        self.queued_gave_up.fetch_add(1, Ordering::Relaxed);
    }

    fn semaphore(&self, id: &str, cap: usize) -> Arc<Semaphore> {
        let mut g = self.entries.lock();
        g.entry(id.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(cap)))
            .clone()
    }

    /// 取一条在途许可；`budget` 为本次请求剩余的 `timeout` 预算。
    ///
    /// 返回 `None` = 本次该上游**不应再尝试**（上限已满且等待超预算，或等到许可后
    /// 剩余预算不足以做一次协议往返 —— 见 [`MIN_POST_QUEUE_BUDGET_MS`]）。
    /// **上限为 0（关闭）时零开销**：不建信号量、不计数。
    pub async fn acquire(&self, id: &str, budget: Duration) -> Option<OwnedSemaphorePermit> {
        let cap = self.cap();
        if cap == 0 {
            return None;
        }
        let sem = self.semaphore(id, cap);
        match sem.clone().try_acquire_owned() {
            Ok(p) => {
                self.acquired.fetch_add(1, Ordering::Relaxed);
                Some(p)
            }
            Err(_) => {
                // 满：记一次"排队"，并只在剩余预算内等待（等待时间计入该次请求延迟）。
                self.queued.fetch_add(1, Ordering::Relaxed);
                let t0 = std::time::Instant::now();
                match tokio::time::timeout(budget, sem.acquire_owned()).await {
                    Ok(Ok(p)) => {
                        self.acquired.fetch_add(1, Ordering::Relaxed);
                        // **2.1.17（修复项 7）**：等到许可 ≠ 还来得及。
                        // 剩余预算不足以做一次协议往返时主动放弃（立即归还许可），
                        // 让 fallback / 对冲候选接手 —— 而不是去做一次注定失败的握手。
                        let left = budget.saturating_sub(t0.elapsed());
                        if left < Duration::from_millis(MIN_POST_QUEUE_BUDGET_MS) {
                            self.note_queued_gave_up();
                            drop(p);
                            return None;
                        }
                        Some(p)
                    }
                    _ => {
                        self.rejected.fetch_add(1, Ordering::Relaxed);
                        None
                    }
                }
            }
        }
    }
}

/// 上游运行时（数据面共享态）。
#[allow(clippy::type_complexity)]
pub struct UpstreamRuntime {
    pub x20: Arc<X20Controller>,
    pub bootstrap: Arc<BootstrapResolver>,
    pub health: Arc<HealthKeeper>,
    pub pool: Arc<ConnPool>,
    /// 独立有界后台探针池（健康检查 submit_drop，不饿死查询）。
    pub probes: Arc<crate::health::ProbePool>,
    /// **2.1.15**：单上游在途请求闸门（默认 [`DEFAULT_MAX_INFLIGHT_PER_UPSTREAM`]）。
    pub inflight: Arc<InflightLimiter>,
    quic_reg: Mutex<HashMap<(String, String, u16, String), Arc<QuicManager>>>,
    /// **A7 线速请求计数**：真正落到 socket/HTTP 往返上的上游请求数。
    /// 语义 = 每次 `send_to` / 每条上游 TCP(TLS) 连接上的一次查询往返 / 每次 HTTP POST。
    /// 与"派发次数"（[`Self::dispatch_count`]）配对，二者的差值就是
    /// **多 IP 并行 + TC 回退 TCP + 连接复用重试**带来的放大倍数。
    wire_requests: AtomicU64,
    /// **A7 派发计数**：`query()` 被调用的次数（= 上游配置被派发了几次），
    /// 对应旧口径的 `upstream_requests`。
    dispatch_count: AtomicU64,
}

impl Default for UpstreamRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl UpstreamRuntime {
    pub fn new() -> Self {
        UpstreamRuntime {
            x20: Arc::new(X20Controller::new()),
            bootstrap: Arc::new(BootstrapResolver::new()),
            health: Arc::new(HealthKeeper::new()),
            pool: Arc::new(ConnPool::new()),
            probes: Arc::new(crate::health::ProbePool::new(8)),
            inflight: Arc::new(InflightLimiter::default()),
            quic_reg: Mutex::new(HashMap::new()),
            wire_requests: AtomicU64::new(0),
            dispatch_count: AtomicU64::new(0),
        }
    }

    /// **2.1.15**：设置单上游在途请求上限（`0` = 关闭闸门，退回 2.1.14 行为）。
    pub fn set_max_inflight(&self, cap: usize) {
        self.inflight.set_cap(cap);
    }

    /// A7：记一次**真实上线**的上游请求（UDP send / TCP(TLS) 连接往返 / HTTP POST）。
    pub fn record_wire_request(&self) {
        self.wire_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// A7：真实线速上游请求累计数（`/metrics` 与 `/api/status` 用）。
    pub fn wire_requests(&self) -> u64 {
        self.wire_requests.load(Ordering::Relaxed)
    }

    /// A7：上游派发次数累计（`query()` 调用次数）。
    pub fn dispatch_count(&self) -> u64 {
        self.dispatch_count.load(Ordering::Relaxed)
    }
    // >>> 242B BEGIN P1-8-runtime >>> //
    /// **2.1.42-B（P1-8）**：清空上游运行时的全部累计量（`/api/reset`）：
    /// 物理线速/派发计数 + 逐上游健康统计 + 在途闸门计数。
    pub fn reset_counters(&self) {
        self.wire_requests.store(0, Ordering::Relaxed);
        self.dispatch_count.store(0, Ordering::Relaxed);
        self.health.reset();
        self.inflight.reset_counters();
    }
    // <<< 242B END P1-8-runtime <<< //

    /// 取（或建）某上游的 QUIC 管理器。
    pub fn quic_manager(self: &Arc<Self>, cfg: &UpstreamConfig) -> Arc<QuicManager> {
        let key = cfg.pool_key();
        let mut g = self.quic_reg.lock();
        g.entry(key)
            .or_insert_with(|| Arc::new(QuicManager::new(cfg)))
            .clone()
    }

    /// **[历史归因]** 统一查询：对齐 Python `query_upstream(up, query_bytes, timeout_ms)`。
    ///
    /// **2.1.15（P1）**：入口先过**单上游在途上限**（[`InflightLimiter`]，默认
    /// [`DEFAULT_MAX_INFLIGHT_PER_UPSTREAM`]）。排队等待计入本次请求耗时，
    /// 但**不额外延长**超时预算：信号量等待 + 协议往返共同受 `timeout_ms` 约束
    /// （等待耗尽的剩余预算不足时直接判该上游本次失败 → 上层 fallback/对冲接手），
    /// 因此单查询总延迟仍有上界，不会因为排队把客户端拖到自身超时。
    ///
    /// **2.1.17（修复项 7）**：闸门**本来就是逐上游**的（`InflightLimiter.entries`
    /// 是 `id -> Semaphore`），慢上游不会吃光快上游的许可；且"等到许可但预算已被
    /// 排队吃光"时主动放弃（`inflight-queued-out-of-budget`），不再去做注定失败的
    /// 握手 —— 两者共同降低 lvl256 档的客户端超时数。
    pub async fn query(
        self: &Arc<Self>,
        cfg: &UpstreamConfig,
        query: &[u8],
        timeout_ms: u64,
    ) -> QueryOutcome {
        let timeout = Duration::from_millis(timeout_ms);
        let t0 = std::time::Instant::now();
        // A7：派发计数（每条上游配置被真正调用一次 = 1）。
        self.dispatch_count.fetch_add(1, Ordering::Relaxed);
        // 在途闸门：`cap == 0` 时**完全不进闸门**（零开销，行为与 2.1.14 逐位一致）；
        // 启用时排队等待计入本次请求耗时，且与协议往返共享同一份 `timeout` 预算。
        let gated = self.inflight.cap() > 0;
        let _permit = if gated {
            match self.inflight.acquire(&cfg.id, timeout).await {
                Some(p) => Some(p),
                // 闸门满且等待超预算：本次该上游失败（固定文案便于归因）。
                None => return QueryOutcome::fail(elapsed_ms(t0), "inflight-capped"),
            }
        } else {
            None
        };
        // 排队之后重新计算剩余预算（等待时间是本次查询延迟的一部分）。
        let timeout = timeout
            .saturating_sub(t0.elapsed())
            .max(Duration::from_millis(1));
        match cfg.proto {
            Proto::Udp => {
                let (ok, data) = udp::udp_query(self, cfg, query, timeout).await;
                let lat = elapsed_ms(t0);
                self.health.record(&cfg.id, ok, lat);
                finalize(ok, data, lat, "udp query failed")
            }
            Proto::Tcp => {
                let (ok, data) = tcp::tcp_query(self, cfg, query, timeout).await;
                let lat = elapsed_ms(t0);
                self.health.record(&cfg.id, ok, lat);
                finalize(ok, data, lat, "tcp query failed")
            }
            Proto::Dot => {
                let (ok, data) = dot::dot_query(self, cfg, query, timeout).await;
                let lat = elapsed_ms(t0);
                self.health.record(&cfg.id, ok, lat);
                finalize(ok, data, lat, "dot query failed")
            }
            Proto::Doh => {
                let (ok, data) = doh::doh_query(self, cfg, query, timeout).await;
                let lat = elapsed_ms(t0);
                self.health.record(&cfg.id, ok, lat);
                finalize(ok, data, lat, "doh query failed")
            }
            Proto::Doq | Proto::Doh3 => {
                let mgr = self.quic_manager(cfg);
                let before = mgr.wire_count();
                let (ok, data, err) = mgr.query(self, query, timeout).await;
                // A7：把本管理器这次 query **真实**发生的 exchange 次数并入线速计数
                // （含重连后的重试；退避早退时为 0）。
                let delta = mgr.wire_count().saturating_sub(before);
                if delta > 0 {
                    self.wire_requests.fetch_add(delta, Ordering::Relaxed);
                }
                let lat = elapsed_ms(t0);
                self.health.record(&cfg.id, ok, lat);
                if !ok {
                    // QUIC（DoQ/DoH3）失败原因在此落 debug 日志：`QueryOutcome::err` 在
                    // 调用方只保留为字符串，probe/API 不回显（不回显上游细节），
                    // 故 "服务端拒绝/协议不互操作" 与 "网络抖动" 只能靠这条日志区分。
                    tracing::debug!(
                        up = %cfg.id,
                        proto = ?cfg.proto,
                        host = %cfg.host,
                        err = %err,
                        lat_ms = lat,
                        "quic upstream failed"
                    );
                }
                finalize(ok, data, lat, &err)
            }
        }
    }
}

/// 统一收尾：成功契约 ok=true 但缺数据 → 显式错误（不再 unwrap）。
fn finalize(ok: bool, data: Option<Vec<u8>>, lat: u64, err: &str) -> QueryOutcome {
    match (ok, data) {
        (true, Some(d)) => QueryOutcome::ok(d, lat),
        (true, None) => QueryOutcome::fail(lat, format!("{}: missing response data", err)),
        (false, _) => QueryOutcome::fail(lat, err),
    }
}

impl UpstreamRuntime {
    /// 删除上游：清理 0x20 / 健康统计 / 连接池 / QUIC 连接 / bootstrap 缓存。
    pub fn discard(&self, cfg: &UpstreamConfig) {
        self.x20.discard(&cfg.id);
        self.health.discard(&cfg.id);
        self.pool.discard(&cfg.pool_key());
        self.bootstrap.discard_host(&cfg.host);
        let key = cfg.pool_key();
        if let Some(mgr) = self.quic_reg.lock().remove(&key) {
            mgr.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **2.1.17（修复项 7）**：闸门是**逐上游**的 —— 满上游不得吃光快上游的许可。
    ///
    /// 这是对 2.1.16 文档错误（"一个闸门服务所有上游"）的**行为级**反证：
    /// 把 `slow` 的容量占满后，`fast` 仍必须能立刻拿到许可。
    #[tokio::test]
    async fn inflight_permits_are_per_upstream_not_global() {
        let lim = InflightLimiter::default();
        lim.set_cap(1);
        let budget = Duration::from_millis(5_000);
        let held = lim.acquire("slow", budget).await.expect("首条必须拿到");
        // slow 已满：再取必须等（这里给极短预算 → 走 rejected 分支）。
        let denied = lim.acquire("slow", Duration::from_millis(20)).await;
        assert!(denied.is_none(), "slow 满时必须拿不到");
        // fast 是**另一条上游** ⇒ 必须立刻拿到（证明信号量是按 id 分的）。
        let fast = lim.acquire("fast", budget).await;
        assert!(
            fast.is_some(),
            "闸门必须逐上游：slow 占满不得影响 fast（2.1.16 文档写成“一个闸门”是错的描述）"
        );
        let (acq, queued, rej) = lim.stats();
        assert_eq!(acq, 2, "slow 首次 + fast 一次 = 2");
        assert_eq!(queued, 1, "只有 slow 的第二次进过排队");
        assert_eq!(rej, 1, "slow 第二次等待超预算 ⇒ rejected");
        assert_eq!(lim.queued_gave_up(), 0, "本例不是“等到许可但预算不够”");
        drop(held);
        drop(fast);
    }

    /// **2.1.17（修复项 7）**：**等到许可但预算已被排队吃光** ⇒ 主动放弃并计数。
    ///
    /// 判据（对应 2.1.16 lvl256 的解释）：`acquired` 增加、许可被立刻归还
    /// （后续请求仍能拿到）、`queued_gave_up` +1，且**不算** `rejected`
    /// （它是"从未拿到许可"，与本情形是两个不同的治理信号）。
    #[tokio::test]
    async fn inflight_gives_up_when_queue_ate_the_budget() {
        let lim = Arc::new(InflightLimiter::default());
        lim.set_cap(1);
        let held = lim
            .acquire("u1", Duration::from_millis(5_000))
            .await
            .unwrap();
        assert_eq!(lim.stats().0, 1, "许可已被取走");

        // 后台：250ms 后释放许可（模拟"排队 250ms"）。
        let l2 = lim.clone();
        let h = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(250)).await;
            drop(held);
            l2
        });
        // 总预算 400ms；排队 250ms 后剩 ~150ms < MIN_POST_QUEUE_BUDGET_MS(250) ⇒ 放弃。
        let r = lim.acquire("u1", Duration::from_millis(400)).await;
        let l = h.await.unwrap();
        assert!(
            r.is_none(),
            "等到许可但剩余预算不足一次协议往返时必须主动放弃（而不是去做注定失败的握手）"
        );
        assert_eq!(l.queued_gave_up(), 1, "必须记一次“排队吃光预算”");
        let (_a, _q, rej) = l.stats();
        assert_eq!(
            rej, 0,
            "本情形**不是** rejected（它拿到了许可），两者不得混计"
        );

        // 许可已被归还 ⇒ 后续请求仍能立刻拿到（绝不泄漏许可）。
        let again = l.acquire("u1", Duration::from_millis(5_000)).await;
        assert!(
            again.is_some(),
            "放弃时必须立刻归还许可，否则闸门会被永久占满"
        );
    }

    /// **2.1.17（修复项 7）**：预算充足时行为**逐位不变**（零行为变更回归）。
    #[tokio::test]
    async fn inflight_budget_sufficient_is_unchanged() {
        let lim = InflightLimiter::default();
        lim.set_cap(2);
        let a = lim.acquire("u1", Duration::from_millis(3_000)).await;
        assert!(a.is_some());
        let (acq, queued, rej) = lim.stats();
        assert_eq!((acq, queued, rej), (1, 0, 0), "有许可时零排队零拒绝");
        assert_eq!(lim.queued_gave_up(), 0);
        // cap == 0（闸门关闭）时零开销、返回 None，且不建信号量、不计数。
        lim.set_cap(0);
        assert!(lim
            .acquire("u1", Duration::from_millis(3_000))
            .await
            .is_none());
        let (acq2, q2, r2) = lim.stats();
        assert_eq!((acq2, q2, r2), (1, 0, 0), "闸门关闭不得产生任何计数");
        assert_eq!(lim.queued_gave_up(), 0);
    }
}
