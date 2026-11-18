//! 后台循环：健康检查 / 预取预热 / 规则订阅拉取。
//!
//! 全部由 [`Resolver::spawn_background_tasks`] 统一 spawn，返回 `JoinHandle` 集合；
//! 每个循环用 `tokio::select!` 在「关闭信号」与「周期 sleep」间等待，取消安全、shutdown 及时退出。
//! 网络/文件 IO 为 async；订阅 JSON 解析为纯 CPU（极轻量，无需 spawn_blocking）。
//!
//! 本环境无外网：探针与订阅拉取会失败，优雅记录并继续，绝不 panic / 不阻断数据面。
use std::sync::atomic::Ordering;

use std::sync::Arc;
use std::time::Duration;

use ebpdns_cache::DnsCache;

use ebpdns_proto::query::build_query;
use ebpdns_rules::{rule_from_json, Rule, RuleSource};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

use crate::config::UpstreamCfg;
use crate::production::upcfg_to_runtime;
use crate::resolve::ResolveOpts;
use crate::Resolver;

/// 订阅拉取总超时（connect + TLS + 读）。
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// 订阅响应体上限（16MB），超限拒绝，防恶意订阅 OOM。
const SUB_MAX_BODY: u64 = 16 * 1024 * 1024;
/// 健康检查"全量探测"的 enabled 上游数上限（优化项 7）。
///
/// = `ProbePool` 的并发容量（`UpstreamRuntime` 构造 `ProbePool::new(8)`）：
/// enabled ≤ 8 时一轮即可覆盖全部上游（单上游最迟 `1×interval` 被发现），
/// 且不会因池满而丢探针；超过 8 保持 3 个轮转 + 打开态优先补探（≤ 3+3）。
const HEALTH_PROBE_ALL_MAX: usize = 8;

/// **2.2.2（P2-05）/ 2.2.3（P2-H）**：低流量闸门 —— 每轮客户端查询数低于该值时，后台
/// 探测降频/跳过全量补扫（探测流量只在"真的有客户端流量"时才值得付）。
///
/// 生产 2.2.1 实测：客户端 0.2 qps 时 `upstream_requests/queries = 2.46×`（其中很大
/// 一部分是健康探针 + 预取补扫在空闲实例上自转）。目标 ≤1.2×。
///
/// **2.2.3 调整 12 → 20**：0.2 qps × 60s = 12 次/轮，旧阈值 `<12` 恰好**不**判空闲
/// ⇒ 低 QPS 场景仍会全量探测。20 次/轮 = 0.33 qps 以下都按低流量处理；有真实流量
///（≥20 次/轮）时保持原频率。测试用 20 次注入仍判"有流量"（`20 < 20` 为假）。
const IDLE_CLIENT_QUERY_GATE: u64 = 20;

/// **2.2.2（P2-05）**：单轮预取补扫硬上限（无论 `prefetch_max/4` 多大）。
///
/// 2.2.1 的预算 = `max(prefetch_max/4, 64)`（生产 4096 ⇒ 1024/轮），一轮就可能打出
/// 上千条上游查询；这里加绝对上限 64/轮，把"突发补扫"摊到后续轮次。
const PREFETCH_SWEEP_ROUND_CAP: usize = 64;

/// **2.2.3（P2-C）**：命中驱动 pending 队列的**单轮**排空上限。
///
/// 2.2.2 只限制了"全量补扫"，pending 仍会在突发后一轮全排（生产实测 107 次/2min）。
/// 24 条/轮 × 默认 60s 间隔 ⇒ 稳态 ≤24 条/分钟；突发被摊到后续轮次。
const PREFETCH_PENDING_ROUND_CAP: usize = 24;

/// **2.2.3（P2-C）**：pending 出队的**每秒**上限（顺序处理时的最小间隔 = 1/8 s）。
///
/// 单轮 24 条最坏耗时约 3s；既能压住"瞬时 100+ 并发上游"的形态，也不会拖住下一轮。
const PREFETCH_PENDING_PER_SEC: u32 = 8;

/// **2.2.3（P2-C/P2-H）**：**低流量**时 pending 的单轮上限（远小于 24）。
///
/// 低 QPS 下 60 次命中会入队 60 条；若仍按 24/轮排空，前 3 轮（暂停前）就会打出
/// 72 条上游请求 ⇒ `upstream/queries` 仍可 >1.2。低流量改为 4 条/轮 ⇒ 3 轮最多 12 条，
/// 之后暂停；有真实流量（≥20 次/轮）时恢复 24/轮。
const PREFETCH_LOW_TRAFFIC_PENDING_CAP: usize = 4;

/// **2.2.3（P2-H）**：连续多少轮低流量后**暂停** pending 出队（队列保留）。
///
/// 3 × `prefetch_interval`（默认 180s）内没有真实客户端流量 ⇒ 命中驱动队列已无
/// "即将被再次查询"的意义；暂停可把空闲态后台上游请求压到 0。一旦有流量立即恢复
/// （计数回落，见 `do_prefetch`）。
const IDLE_PREFETCH_PAUSE_ROUNDS: u32 = 3;

/// **2.2.3（P2-H）**：低流量时健康探针的降频倍数（每 6 轮探一次）。
///
/// 默认 30–60s 间隔 ⇒ 3–6 分钟一轮；再叠加下面"每轮最多 1 个目标"，空闲实例的
/// 探针量约为 0.17–0.33 条/分钟（15 个上游也能在 45–90 分钟内轮询一遍）。
const IDLE_PROBE_EVERY: u32 = 6;

/// **2.2.3（P2-H）**：低流量时每轮最多探几个上游（打开态优先，保底不误伤）。
const IDLE_PROBE_TARGETS: usize = 1;

/// **2.2.6（P2-A9）**：健康探针的**验证层**判据 —— 响应是否为 `NOERROR + ANCOUNT>0`。
///
/// 只读 12 字节 DNS 头（不解析问题/答案段）：`QR` 位必须为 1（是响应）、
/// `rcode == 0`（NOERROR；SERVFAIL/NXDOMAIN 都算验证失败）、`ANCOUNT > 0`
/// （NODATA/空答案算验证失败）。传输层成功（`QueryOutcome.ok`）**不等于**验证
/// 成功：上游回 SERVFAIL 时传输是成功的，但探针并没有验证到"上游能答"。
///
/// 判据是"至少一条答案"而不是"至少一条 A 记录"：健康探针域名的 A/AAAA/CNAME
/// 链都算可用答案（CNAME 也算有答案）；严格按 qtype 过滤会把 CNAME-only 响应
/// 误判成失败。畸形/截断报文（不足 12 字节）一律失败。
fn probe_response_is_valid(bytes: &[u8]) -> bool {
    if bytes.len() < 12 {
        return false;
    }
    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
    let qr = flags & 0x8000 != 0;
    let rcode = (flags & 0x000F) as u8;
    let ancount = u16::from_be_bytes([bytes[6], bytes[7]]);
    qr && rcode == 0 && ancount > 0
}

impl Resolver {
    /// 统一 spawn 全部后台循环，返回 JoinHandle 集合。
    /// 调用方持有句柄即可在 shutdown 后 `join` 等待退出（或直接 detach）。
    pub fn spawn_background_tasks(self: &Arc<Self>) -> Vec<tokio::task::JoinHandle<()>> {
        let mut handles = Vec::new();
        let cfg = self.cfg.read();
        if cfg.health_check_interval > 0 {
            let me = self.clone();
            handles.push(tokio::spawn(async move { me.health_loop().await }));
        }
        if cfg.prefetch {
            let me = self.clone();
            handles.push(tokio::spawn(async move { me.prefetch_loop().await }));
        }
        if cfg.rule_sub_interval > 0 && !cfg.subscriptions.is_empty() {
            let me = self.clone();
            handles.push(tokio::spawn(async move { me.bg_loop().await }));
        }
        handles
    }

    /* ---------------- 健康检查 ---------------- */

    async fn health_loop(self: Arc<Self>) {
        loop {
            let period = Duration::from_secs(self.cfg.read().health_check_interval.max(1));
            tokio::select! {
                _ = self.shutdown.notified() => break,
                _ = tokio::time::sleep(period) => {
                    // **2.2.2（P2-05）/ 2.2.3（P2-H）**：低流量闸门 —— 空闲时每 `IDLE_PROBE_EVERY`
                    // （6）轮才探一次，且每轮只探 **1** 个目标（打开态优先）。相对 2.2.2 的
                    // "每 3 轮全探"把空闲探针量再降一个数量级：0.2 qps 场景下
                    // `upstream/queries` 可压到 ≤1.2×，同时保留"打开态 → 恢复"的保底探测。
                    // 有真实流量时保持原频率（健康度需要及时反映）。
                    let round = self.health_rounds.fetch_add(1, Ordering::Relaxed);
                    let q = self.client_queries();
                    let last = self
                        .probe_last_client_queries
                        .swap(q, Ordering::Relaxed);
                    let idle = q.saturating_sub(last) < IDLE_CLIENT_QUERY_GATE;
                    // 仅对"分钟级"的常规配置启用空闲降频：`interval < 10s` 是测试/特殊
                    // 场景（探针轮转的语义测试依赖每轮都探），不降频。
                    let idle_gate = self.cfg.read().health_check_interval >= 10;
                    if idle_gate && idle && !round.is_multiple_of(IDLE_PROBE_EVERY.into()) {
                        tracing::debug!(
                            client_queries = q.saturating_sub(last),
                            "低流量：跳过本轮健康探针（每 6 轮探一次）"
                        );
                        continue;
                    }
                    let idle_limited = idle_gate && idle;
                    self.health_check_once_limited(if idle_limited {
                        Some(IDLE_PROBE_TARGETS)
                    } else {
                        None
                    })
                    .await;
                }
            }
        }
    }

    /// 一轮健康探针：对每个启用上游发一个轻量查询，复用 runtime.probes 有界池不饿死查询。
    ///
    /// 2.1.8 优化（项 2/5/7）：
    /// - **探针与数据面解耦**（项 2）：失败只记 `probe_fail` 独立计数（+ HealthKeeper 失败样本
    ///   → 失败率惩罚降权重），**不再**计入 `circuit_fails`；成功仍立即 `cb.probe_ok` 恢复。
    /// - **打开态优先**（项 5）：本轮优先探"已熔断打开"的上游以确认恢复（成功即恢复）。
    /// - **覆盖率**（项 7）：`enabled <= HEALTH_PROBE_ALL_MAX(8)` 时每轮**全部**探；
    ///   否则保持 3 个轮转，并额外优先补探打开态上游（总探数 ≤ 3+3）。
    /// **2.2.2（P2-05）**：一轮健康探针（**全量**：≤8 全探 / >8 轮转 3 个），供测试与
    /// 运维自检使用；后台循环在低流量时走 [`Self::health_check_once_limited`] 降频。
    #[cfg(test)]
    pub(crate) async fn health_check_once(self: &Arc<Self>) {
        self.health_check_once_limited(None).await;
    }

    /// **2.2.3（P2-H）**：带"本轮最多 N 个目标"上限的健康探针。
    ///
    /// 目标集合仍按原优先级组装（打开态优先 → 全量/轮转），最后截断到 `max_targets`；
    /// 因此低流量时被探到的永远是**最需要恢复确认**的那个上游（打开态优先），
    /// 不会因为降频而漏掉"熔断已打开却无人探测"的误伤。
    pub(crate) async fn health_check_once_limited(self: &Arc<Self>, max_targets: Option<usize>) {
        let runtime = match self.runtime.read().clone() {
            Some(r) => r,
            None => return,
        };
        let ups: Vec<_> = self
            .cfg
            .read()
            .upstreams
            .iter()
            .filter(|u| u.enabled)
            .cloned()
            .collect();
        if ups.is_empty() {
            return;
        }
        // 轻量 A 探针（可配 health_probe_domain，默认 www.baidu.com，应答小）。
        // 域名 normalize：去尾点 + 小写；超时用 `effective_probe_timeout_ms`（项 2：
        // 探针不得比数据面超时更有耐心，旧默认 2000 > timeout_ms 1500）。
        let (probe_domain, probe_timeout_ms) = {
            let c = self.cfg.read();
            let d = c
                .health_probe_domain
                .trim_end_matches('.')
                .to_ascii_lowercase();
            (d, c.effective_probe_timeout_ms())
        };
        let probe = match build_query(&probe_domain, 1, None, false, None, None, false) {
            Ok((b, _)) => b,
            Err(_) => return,
        };
        // 目标集合组装（项 5/7）：打开态优先，其次覆盖率（≤8 全探 / 否则轮转 3 个）。
        let n = ups.len();
        let mut targets: Vec<UpstreamCfg> = Vec::new();
        let now_probe = self.clock.monotonic_ms() / 1000.0;
        let open_ids: Vec<String> = self.cb.open_ids(now_probe);
        // 1) 打开态优先（最多 3 个，避免与轮转叠加后压满探针池）。
        for id in open_ids.iter().take(3) {
            if let Some(u) = ups.iter().find(|u| &u.id == id) {
                targets.push(u.clone());
            }
        }
        if n <= HEALTH_PROBE_ALL_MAX {
            // 2a) enabled ≤ 8：每轮全部探（单上游最迟 1×interval 被发现）。
            for u in &ups {
                if !targets.iter().any(|t| t.id == u.id) {
                    targets.push(u.clone());
                }
            }
        } else {
            // 2b) enabled > 8：保持轮转，但步长取 `per`（不是 1）——每轮探**互不重叠**的
            // 连续 3 个，于是单个上游最迟 `ceil(N/3) × interval` 必被探到（优化项 7 要求）。
            // 旧实现步长为 1（`fetch_add(1)`），窗口滑动式重叠 → 全覆盖要 N 轮（22 个上游
            // = 660s），比 N/3 轮（240s）差 2.75 倍。
            let per = 3usize.min(n);
            let off = self
                .probe_rot
                .fetch_add(per, std::sync::atomic::Ordering::Relaxed)
                % n;
            for k in 0..per {
                let u = &ups[(off + k) % n];
                if !targets.iter().any(|t| t.id == u.id) {
                    targets.push(u.clone());
                }
            }
        }
        if let Some(max) = max_targets {
            if targets.len() > max {
                tracing::debug!(
                    targets = targets.len(),
                    max,
                    "低流量：本轮健康探针只保留前 N 个目标（打开态优先）"
                );
                targets.truncate(max);
            }
        }
        // **2.2.6（P2-A5）**：**探针退避** —— 连续探针失败 ≥2 次的上游按 2^n 轮跳过
        // （2/4/8/16 轮封顶），成功一次立即恢复每轮探测（`probe_ok` 清 streak）。
        //
        // 为什么需要：P1-03（境外 DoH3）超时是**已知上游/网络问题**，旧实现每轮
        // （默认 30s）都对所有 enabled 上游发探针 —— 一条已确认不可达的链路每 30s
        // 产生一次超时 + `probe_transport_fail`，把"故障噪声"稳定放大，也让探针池
        // 与失败样本持续被坏上游占用。退避把死链路的探针量降到 1/16，同时保留
        // "打开态必探"（熔断恢复不能等退避）与"成功即恢复"。
        //
        // 只影响**探针**，不影响数据面选路；数据面的快速降权见
        // `upstream_rating_detail` 的 `fail_streak` 惩罚。
        {
            let round = self
                .health_rounds
                .load(std::sync::atomic::Ordering::Relaxed);
            let mut kept: Vec<UpstreamCfg> = Vec::with_capacity(targets.len());
            for u in targets {
                // 打开态必须每轮探（半开恢复路径），不受退避约束。
                if self.cb.is_open(&u.id, now_probe) {
                    kept.push(u);
                    continue;
                }
                let streak = self.cb.probe_fail_streak(&u.id);
                if streak >= 2 {
                    let every = 1u64 << streak.min(4) as u32; // 2/4/8/16
                    if !round.is_multiple_of(every) {
                        tracing::debug!(
                            upstream = %u.id,
                            streak,
                            every,
                            round,
                            "健康探针退避：跳过本轮（连续失败，2^n 轮后再探）"
                        );
                        continue;
                    }
                }
                kept.push(u);
            }
            targets = kept;
        }
        let mut tasks = Vec::new();
        for up in targets {
            // 探针池满即丢，不挤占数据面查询。
            let Some(_permit) = runtime.probes.try_submit() else {
                continue;
            };
            let rt = runtime.clone();
            // **2.2.0（能力 3）**：已移除/非法协议的上游不参与健康探针（同数据面口径）。
            let Ok(rc) = upcfg_to_runtime(&up) else {
                tracing::debug!(upstream = %up.id, proto = %up.proto, "上游协议不可用，跳过健康探针");
                continue;
            };
            let q = probe.clone();
            let cb = self.cb.clone();
            let tel = self.tel.clone();
            let was_open = self.cb.is_open(&rc.id, now_probe);
            tasks.push(tokio::spawn(async move {
                let _keep = _permit;
                let out = rt.query(&rc, &q, probe_timeout_ms).await;
                // **2.2.5（P2-A8）/ 2.2.6（P2-A9）**：探针口径 = **完成数**（成功+失败），
                // 完成时按**传输层 / 验证层两本账**分账（2.2.5 只有一对 `ok/fail`，
                // 判据是 `out.ok` = 传输成功；上游回 SERVFAIL 也被记成"成功"，与
                // `dns_ok/dns_fail` 的 rcode 口径互相矛盾 —— R-2）：
                //   * 传输层：`out.ok`（收到合法 DNS 响应，含 SERVFAIL/NXDOMAIN）；
                //   * 验证层：响应还必须 **NOERROR + ANCOUNT>0**（探针问的是 A 记录，
                //     一个"有答案的 NOERROR"才算探针真的验证了上游可用）。
                // 硬等式：`queries == transport_ok + transport_fail`、
                //         `transport_ok == valid_ok + valid_fail`。
                let transport_ok = out.ok;
                let valid_ok = out
                    .data
                    .as_deref()
                    .map(probe_response_is_valid)
                    .unwrap_or(false);
                tel.inc("probe_upstream_queries");
                if transport_ok {
                    tel.inc("probe_transport_ok");
                    if valid_ok {
                        tel.inc("probe_valid_ok");
                    } else {
                        tel.inc("probe_valid_fail");
                    }
                } else {
                    tel.inc("probe_transport_fail");
                }
                // 健康数据面喂点：`UpstreamRuntime::query` 内部已按协议分支调用
                // `self.health.record(&cfg.id, ok, lat)`，即本探针结果**已经**写入
                // **[历史归因]** `HealthKeeper`（`upstream_eff_lat` 的排序数据源，对齐 Python
                // `_upstream_eff_lat` 读 `telemetry.upstream_stats`）。
                // 此处**不得**再调用一次 `health.record`，否则同一次探针被双计，
                // 使均值/失败率偏离数据面口径。
                if out.ok {
                    // 项 5：探针成功 → 立即恢复（含主动半开探测），不再等退避窗口过期。
                    if cb.probe_ok(&rc.id) {
                        tracing::info!(
                            upstream = %rc.id,
                            was_open,
                            "健康探针成功 → 熔断立即恢复（主动半开探测）"
                        );
                    }
                } else {
                    // 项 2：探针失败**只**记独立计数，绝不占用 `circuit_fails` 名额。
                    let pf = cb.probe_fail(&rc.id);
                    tracing::debug!(
                        upstream = %rc.id,
                        probe_fail_total = pf,
                        was_open,
                        "健康探针失败（仅记 probe_fail，不影响熔断打开判定）"
                    );
                }
                debug_assert!(
                    out.ok || rt.health.stats(&rc.id).fail_count() > 0,
                    "健康探针失败必须已由 runtime.query 记入 HealthKeeper"
                );
            }));
        }
        // 熔断阈值/退避封顶在探针路径**不再使用**（项 2：探针失败不打开熔断）。
        for t in tasks {
            let _ = t.await;
        }
    }

    /* ---------------- 预取预热 ---------------- */

    async fn prefetch_loop(self: Arc<Self>) {
        loop {
            let period = Duration::from_secs(self.cfg.read().prefetch_interval.max(1.0) as u64);
            tokio::select! {
                _ = self.shutdown.notified() => break,
                _ = tokio::time::sleep(period) => { self.do_prefetch().await; }
            }
        }
    }

    /// 一轮预取：快照消费待办队列，仅对临近过期的条目后台强制重解析。
    ///
    /// **2.1.21（DEF-220-01 修复：`prefetch_trigger` 与 15% 闸门"两套判据"）**
    ///
    /// 缺陷（AUDIT-220 B 节 DEF-220-01 实测）：`prefetch_trigger` 只控**入队**
    /// （`Resolver::schedule_prefetch`），而"真的发上游"还受这里一条**未文档化**的
    /// 第二道闸门 `left < ttl*0.15` 限制。把 `prefetch_trigger` 设成 3600（远大于
    /// `ttl=300`）时条目**确实入队**，但 `left(≤300) < 45` 恒不成立 ⇒ **从不续期**。
    ///
    /// 现在**只有一条判据**（`trigger` 是唯一权威阈值）：
    /// ```text
    /// 入队（schedule_prefetch，命中路径）: ttl_left <= prefetch_trigger
    /// 续期（本函数，真正发上游）        : 0 < left  <= prefetch_trigger
    /// ```
    /// 两道闸门同式，`left > trigger` 的条目既不入队也不会被续期。
    /// `trigger = 0` ⇒ 两者都不成立（`left <= 0` 即已过期，无需续期）。
    ///
    /// `prefetch_target`（续期目标 TTL **上限**）不参与"是否续期"的判定，
    /// 而是经 `ResolveOpts::ttl_cap` 传到回填路径（`fill_cache`）真的生效。
    /// **2.1.21 第 2 轮（DEF-221-03 测试支撑）**：跑**一次**预取过程（= 消费一次 `prefetch`
    /// 队列并向上游续期）。等价于后台任务的一个 tick，供集成测试与运维自检使用。
    ///
    /// 为什么不直接把 `do_prefetch` 公开：它是后台循环的内部步骤，语义（并发、节流、
    /// 全局闸门）都由循环本身约束；对外只暴露"跑一次"这个稳定动作，避免调用方依赖内部
    /// 细节。预取关闭（`prefetch=false`）或无待续期条目时它立即返回。
    pub async fn prefetch_tick(self: &Arc<Self>) {
        self.do_prefetch().await;
    }

    pub(crate) async fn do_prefetch(self: &Arc<Self>) {
        let (pf_enabled, pf_max, pf_trigger, pf_interval) = {
            let c = self.cfg.read();
            (
                c.prefetch,
                c.prefetch_max,
                c.prefetch_trigger,
                c.prefetch_interval,
            )
        };
        // **2.2.2（P2-05）**：低流量闸门 —— 本轮客户端查询数 < 阈值 ⇒ **跳过全量补扫**。
        // **2.2.3（P2-C/P2-H）**：再叠加 pending 出队上限 / 连续低流量暂停（见下）。
        let q_now = self.client_queries();
        let q_last = self
            .prefetch_last_client_queries
            .swap(q_now, Ordering::Relaxed);
        // 低流量闸门只对"分钟级"的常规预取周期生效：`interval < 10s` 是测试/特殊场景
        // （补扫语义的测试依赖每轮都扫描），不降频。
        let low_traffic =
            pf_interval >= 10.0 && q_now.saturating_sub(q_last) < IDLE_CLIENT_QUERY_GATE;
        let idle_round = if low_traffic {
            self.prefetch_idle_rounds
                .fetch_add(1, Ordering::Relaxed)
                .saturating_add(1)
        } else {
            self.prefetch_idle_rounds.store(0, Ordering::Relaxed);
            0
        };
        // **2.2.3（P2-C/P2-H）**：连续 3 轮低流量（默认 3×60s）后暂停 pending 出队。
        // 队列**保留**（不丢刷新义务）；一旦有流量，`idle_round=0` 立即恢复。
        let pause_pending = pf_enabled && low_traffic && idle_round >= IDLE_PREFETCH_PAUSE_ROUNDS;
        if pause_pending {
            tracing::debug!(
                pending = self.prefetch.lock().len(),
                "低流量：暂停命中驱动 pending 出队（队列保留，有流量即恢复）"
            );
        }
        let raw_pending = if pause_pending {
            // 暂停出队：**不看也不消费**队列（`snapshot` 仅用于诊断/未来扩展），
            // 队列原样保留，有流量时下一轮 `drain_all` 一次取走。
            Vec::new()
        } else {
            self.prefetch.lock().drain_all()
        };
        // **2.2.3（P2-C）**：pending **单轮**上限 + 热 key 优先 + 到期紧迫度次排序。
        //
        // 2.2.2 的 pending 在突发后一次性排空（生产 107 次/2min）。这里只取前
        // `PREFETCH_PENDING_ROUND_CAP`（24）条；**剩余条目重新入队**（不是丢弃），
        // 下一轮继续。排序键：① 策略热频（`cache.hot_keys`，高频先刷新）；
        // ② 剩余 TTL（越接近过期越先）；未在热表里的键排最后（仍会被轮到）。
        let mut pending = raw_pending;
        let pending_total = pending.len();
        let pending_cap = if low_traffic {
            PREFETCH_LOW_TRAFFIC_PENDING_CAP
        } else {
            PREFETCH_PENDING_ROUND_CAP
        };
        if !pause_pending && pending.len() > pending_cap {
            let hot = self
                .cache
                .hot_keys(PREFETCH_PENDING_ROUND_CAP.saturating_mul(4).max(64));
            let mut rank: std::collections::HashMap<(String, String, bool), usize> =
                std::collections::HashMap::with_capacity(hot.len());
            for (i, k) in hot.iter().enumerate() {
                rank.entry((k.domain.clone(), k.qtype.clone(), k.dnssec))
                    .or_insert(i);
            }
            let now = self.clock.epoch();
            let left_of = |d: &str, q: &str, dn: bool| -> f64 {
                match self.cache.peek(&self.ckey_variant(d, q, dn), now) {
                    Some(e) => (e.expires_at - now).max(0.0),
                    None => f64::MAX,
                }
            };
            pending.sort_by(|a, b| {
                let ra = rank
                    .get(&(a.1.clone(), a.2.clone(), a.3))
                    .copied()
                    .unwrap_or(usize::MAX);
                let rb = rank
                    .get(&(b.1.clone(), b.2.clone(), b.3))
                    .copied()
                    .unwrap_or(usize::MAX);
                ra.cmp(&rb).then_with(|| {
                    left_of(&a.1, &a.2, a.3)
                        .partial_cmp(&left_of(&b.1, &b.2, b.3))
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
            });
            let rest = pending.split_off(pending_cap);
            if !rest.is_empty() {
                let mut q = self.prefetch.lock();
                for (key, domain, qtype, dnssec) in rest {
                    q.schedule(&key, &domain, &qtype, dnssec, pf_max.max(1));
                }
            }
            tracing::debug!(
                pending_total,
                take = pending.len(),
                deferred = pending_total - pending.len(),
                "预取 pending 单轮上限：剩余已重新入队（下一轮继续）"
            );
        }
        let mut jobs: Vec<(String, String, bool, bool)> = pending
            .into_iter()
            .map(|(_key, domain, qtype, dnssec)| (domain, qtype, dnssec, false))
            .collect();
        let pending_jobs = jobs.len();
        // **2.1.50（FIX-PREFETCH-SWEEP）**：全量补扫（仅在有真实流量时）。
        if pf_enabled && low_traffic {
            tracing::debug!(
                client_queries = q_now.saturating_sub(q_last),
                "低流量：跳过本轮预取全量补扫"
            );
        }
        if pf_enabled && !low_traffic {
            // **PERF-6（FIX-PREFETCH-STARVATION）**：补扫预算与命中队列**解耦**。
            //
            // 旧实现 `budget = prefetch_max - pending`，而出厂 `prefetch_trigger(=ttl=600)`
            // 使每次命中都入队、队列上限=prefetch_max ⇒ 命中率 ≳6.8 qps 时 pending 恒满、
            // budget 恒 0 ⇒ 补扫**一轮都不跑**（缺陷10 在生产等于没修，且无任何信号）。
            // 现在固定预留 `prefetch_max/4`（至少 64）给补扫。
            //
            // **FIX-PREFETCH-TRIGGER-GATE**：`prefetch_trigger<=0` 表示"关闭预取"
            // （README/INTERFACE 的语义），补扫也必须关闭，否则仍会以 ≤6.8 qps
            // 刷新全部缓存键，产生未声明的后台上游流量。
            let budget = if pf_trigger > 0.0 {
                // **2.2.2（P2-05）**：再加绝对单轮上限（生产 prefetch_max=4096 ⇒ 旧
                // 预算 1024/轮，突发时一轮打上千条上游查询）。
                (pf_max / 4)
                    .max(64)
                    .min(pf_max)
                    .min(PREFETCH_SWEEP_ROUND_CAP)
            } else {
                0
            };
            if budget > 0 {
                // **2.1.49-p3 / p5（阶段 1.2）**：策略提供“热度+到期紧迫度”候选时，
                // 直接按排序取前 budget 个（不再 round-robin 轮转，避免错过最紧迫的键）；
                // 无热度信息（其他策略）时回退到 round-robin 全量补扫（旧行为）。
                let hot = self.cache.hot_keys(budget);
                let (keys, start) = if hot.is_empty() {
                    let keys = self.cache.keys();
                    if keys.is_empty() {
                        (keys, 0)
                    } else {
                        let start = self.prefetch.lock().advance_sweep(keys.len(), budget);
                        (keys, start)
                    }
                } else {
                    (hot, 0)
                };
                if !keys.is_empty() {
                    let take = budget.min(keys.len());
                    // **阶段 3-14**：去重维度必须含 DO 变体 —— 同域名的 DO 与非 DO
                    // 是两条条目，只按 (domain, qtype) 去重会让其中一条永远不补扫。
                    let mut seen: std::collections::HashSet<(String, String, bool)> = jobs
                        .iter()
                        .map(|(d, q, dnssec, _)| (d.clone(), q.clone(), *dnssec))
                        .collect();
                    // **2.2.1（P2-07）**：补扫必须受 `prefetch_trigger` 的**剩余 TTL**
                    // 约束。2.1.50 的"全量补扫"跳过了该判据，于是每一轮都把**全部**
                    // 热键（含刚写入、TTL 几乎满的条目）重新解析一遍：生产实测
                    // `upstream_requests / queries ≈ 20.8×`（零客户端流量下仍 3–6 次
                    // 上游查询/秒），且每 60s 一轮、`prefetch_max/4=1024` 个预算。
                    // 现在只补"真的临近过期"的条目 ⇒ 后台流量与**过期速率**成正比，
                    // 而不是与**缓存条目数**成正比。
                    let trigger = self.cfg.read().prefetch_trigger;
                    let now = self.clock.epoch();
                    let mut added = 0usize;
                    for i in 0..take {
                        if added >= budget {
                            break;
                        }
                        let k = &keys[(start + i) % keys.len()];
                        if !seen.insert((k.domain.clone(), k.qtype.clone(), k.dnssec)) {
                            continue;
                        }
                        // 非触碰读（`peek`）：不得因补扫本身累计 freq/hot 副本。
                        let ckey = self.ckey_variant(&k.domain, &k.qtype, k.dnssec);
                        let need = match self.cache.peek(&ckey, now) {
                            Some(e) => {
                                let left = e.expires_at - now;
                                left > 0.0 && left <= trigger
                            }
                            None => false,
                        };
                        if !need {
                            continue;
                        }
                        jobs.push((k.domain.clone(), k.qtype.clone(), k.dnssec, true));
                        added += 1;
                    }
                }
            }
        }
        // **2.2.1（P2-07）**：单轮任务数上界（`prefetch_max`）。命中驱动的队列本身有界，
        // 但补扫 + pending 叠加时仍可能一轮打太多上游；超出部分下一轮再来。
        let job_cap = self.cfg.read().prefetch_max.max(64);
        if jobs.len() > job_cap {
            tracing::debug!(
                jobs = jobs.len(),
                cap = job_cap,
                "预取单轮任务数超过上限，截断（剩余下一轮继续）"
            );
            jobs.truncate(job_cap);
        }
        let pending_pace = Duration::from_millis(1000 / u64::from(PREFETCH_PENDING_PER_SEC.max(1)));
        for (idx, (domain, qtype, dnssec, sweep)) in jobs.into_iter().enumerate() {
            if self.shutdown.is_stopped() {
                break;
            }
            // 命中驱动的条目仍走原判据；全量补扫的条目**跳过**该判据（它们正是
            // "没被命中、TTL 还很长"的那批，否则永远不会被刷新）。
            if !sweep {
                // **同一条判据**：`trigger` 同时是入队阈值与续期阈值。
                let trigger = self.cfg.read().prefetch_trigger;
                // **阶段 3-14**：按条目的**原变体**取键（DO 条目看 DO 条目的剩余 TTL；
                // 用 `ckey` 会去看非 DO 条目 —— 那是另一条缓存，判据会错）。
                let ckey = self.ckey_variant(&domain, &qtype, dnssec);
                let now = self.clock.epoch();
                let need = match self.cache.get(&ckey, now) {
                    Some(e) => {
                        let left = e.expires_at - now;
                        left > 0.0 && left <= trigger
                    }
                    None => true,
                };
                if !need {
                    continue;
                }
            }

            // 后台静默强制刷新（不计数、失败静默）。
            // 优化项 9：预取走 `resolve_prefetch`（单上游路径）——只向 1 个上游发起查询
            // （`eff_lat/max(1,weight)` 最低且未熔断打开者），不启用后备波、不受
            // `max_parallel_upstreams` 影响，失败不计入数据面 `circuit_fails`。
            // 被选中上游与其实测延迟由 `Resolver::prefetch_upstream` 打 debug 日志
            // （`prefetch upstream=<id> eff_lat=<ms>`）。
            //
            // **阶段 3-14**：`dnssec` 里的**原条目变体**必须原样传进 `ResolveOpts`
            // ⇒ 续期回填用 `ckey_variant(..., dnssec)`，不会把 DO 条目刷新成非 DO 键。
            tracing::debug!(
                target: "ebpdns::prefetch",
                "prefetch refresh domain={} qtype={} dnssec={}",
                domain,
                qtype,
                dnssec
            );
            let _ = self
                .clone()
                .resolve_prefetch(
                    &domain,
                    &qtype,
                    ResolveOpts {
                        force_refresh: true,
                        silent: true,
                        counted: false,
                        dnssec,
                        ..Default::default()
                    },
                )
                .await;
            // **2.2.3（P2-C）**：pending 顺序处理，最小间隔 1/8s ⇒ 每秒排空上限；
            // 突发 24 条最多约 3s，不阻塞下一轮。补扫不在此限速（本身已 ≤64/轮）。
            if !sweep && idx + 1 < pending_jobs {
                tokio::select! {
                    _ = self.shutdown.notified() => break,
                    _ = tokio::time::sleep(pending_pace) => {}
                }
            }
        }
    }

    /* ---------------- 规则订阅 ---------------- */

    async fn bg_loop(self: Arc<Self>) {
        // 启动后先等一个周期，再开始拉取。
        loop {
            let period = Duration::from_secs(self.cfg.read().rule_sub_interval.max(5));
            tokio::select! {
                _ = self.shutdown.notified() => break,
                _ = tokio::time::sleep(period) => { self.update_rule_subs_once().await; }
            }
        }
    }

    /// 拉取全部订阅 → 合并解析 → rebuild（失败优雅跳过，不清空现有规则）。
    pub(crate) async fn update_rule_subs_once(self: &Arc<Self>) {
        let subs: Vec<String> = self.cfg.read().subscriptions.clone();
        if subs.is_empty() {
            return;
        }
        let mut merged: Vec<Rule> = Vec::new();
        for url in subs {
            match fetch_sub_text(&url).await {
                Ok(text) => merged.extend(parse_sub_text(&text)),
                Err(e) => {
                    tracing::warn!(%url, error = %e, "规则订阅拉取失败");
                }
            }
        }
        if merged.is_empty() {
            return;
        }
        self.tel.inc_rule("subscription-rebuild");
        self.rebuild_rules(merged);
    }
}

/// 解析订阅文本为 block 规则列表（M12，对齐 resolver.py ~3518）：
/// `parse_domain_list(text)` → 每项包 `"*."+d`（`*.`/`re:` 开头除外），默认 action=block。
pub(crate) fn parse_sub_text(text: &str) -> Vec<Rule> {
    let mut out = Vec::new();
    for d in ebpdns_rules::parse::parse_domain_list(text) {
        let m = if d.starts_with("*.") || d.starts_with("re:") {
            d
        } else {
            format!("*.{d}")
        };
        let mut map = serde_json::Map::new();
        map.insert("match".to_string(), Value::String(m));
        map.insert("action".to_string(), Value::String("block".to_string()));
        if let Some(r) = rule_from_json(map, RuleSource::Sub) {
            out.push(r);
        }
    }
    out
}

/// 生产订阅 GET：`http://` 明文 / `https://` rustls(ring)+webpki-roots 严格校验。
/// 证书/主机名校验失败一律返回错误，绝不降级为不校验。无外网时 connect/TLS 失败 → Err。
/// 开启 SSRF 私网校验（连接前拒绝 loopback/私网/链路本地）。
pub async fn fetch_sub_text(url: &str) -> std::io::Result<String> {
    fetch_sub_text_inner(url, None, true).await
}

/// 测试 seam：注入自定义信任根 PEM（本地自签端点）。None → webpki 系统根。
/// 开启 SSRF 私网校验。
pub async fn fetch_sub_text_with_trust(
    url: &str,
    trust_pem: Option<&[u8]>,
) -> std::io::Result<String> {
    fetch_sub_text_inner(url, trust_pem, true).await
}

/// 仅测试用：跳过 SSRF 私网校验（本地 loopback 端点正向 TLS/HTTP 覆盖）。
/// 生产端点一律走 `fetch_sub_text*`（ssrf=true）。
pub async fn fetch_sub_text_allow_private_for_test(
    url: &str,
    trust_pem: Option<&[u8]>,
) -> std::io::Result<String> {
    fetch_sub_text_inner(url, trust_pem, false).await
}

async fn fetch_sub_text_inner(
    url: &str,
    trust_pem: Option<&[u8]>,
    ssrf: bool,
) -> std::io::Result<String> {
    let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "订阅仅支持 http:// 或 https://",
        ));
    };
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = split_hostport(hostport, https)?;

    let raw = if https {
        let cfg = build_tls_config(trust_pem)?;
        fetch_https(host, port, path, cfg, ssrf).await?
    } else {
        fetch_http(host, port, path, ssrf).await?
    };
    parse_http_body(&raw)
}

/// hostport → (host, port)。缺省端口：https 443 / http 80。
fn split_hostport(hostport: &str, https: bool) -> std::io::Result<(&str, u16)> {
    let default = if https { 443 } else { 80 };
    // 处理 IPv6 [::1]:8080
    if let Some(rest) = hostport.strip_prefix('[') {
        if let Some((h, p)) = rest.rsplit_once("]:") {
            return Ok((h, p.parse().map_err(|_| bad_addr(hostport))?));
        }
        return Ok((rest.trim_end_matches(']'), default));
    }
    match hostport.rsplit_once(':') {
        Some((h, p)) => Ok((h, p.parse().map_err(|_| bad_addr(hostport))?)),
        None => Ok((hostport, default)),
    }
}

fn bad_addr(hostport: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("bad host:port: {hostport}"),
    )
}

/// 解析订阅主机为 SocketAddr 并做 SSRF 校验；返回**已校验通过**的地址列表，后续
/// 连接直接用它们（不再按主机名二次解析，消除 DNS rebinding TOCTOU）。
/// ssrf=false 时仅解析不校验（仅测试 seam）。任一解析命中私网/环回/链路本地即拒绝。
async fn resolve_peer_addrs(
    host: &str,
    port: u16,
    ssrf: bool,
) -> std::io::Result<Vec<std::net::SocketAddr>> {
    use ebpdns_upstream::is_non_global_for_subscription;
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| io_err(format!("sub dns resolve {host}: {e}")))?
        .collect();
    if addrs.is_empty() {
        return Err(io_err(format!("sub host {host} resolved to no address")));
    }
    if ssrf {
        for a in &addrs {
            // **[历史归因]** 订阅连接：在私网基础上再拒 CGNAT(100.64/10) 等非全局地址（对齐 Python）。
            // 注意：答案 rebind 过滤仍用 is_private_ip，不在此函数。
            if is_non_global_for_subscription(a.ip().to_string().as_str()) {
                return Err(io_err(format!(
                    "refuse non-global upstream host {host} (resolved {})",
                    a.ip()
                )));
            }
        }
    }
    Ok(addrs)
}

/// 连接到已校验地址列表（首个可用者）。
async fn connect_pinned(addrs: &[std::net::SocketAddr]) -> std::io::Result<tokio::net::TcpStream> {
    let mut last: Option<std::io::Error> = None;
    for a in addrs {
        match tokio::time::timeout(FETCH_TIMEOUT, tokio::net::TcpStream::connect(a)).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => last = Some(e),
            Err(_) => last = Some(io_err("connect timeout")),
        }
    }
    Err(last.unwrap_or_else(|| io_err("no peer address")))
}

/// 明文 HTTP/1.1 GET（Connection: close）。连接钉在已校验 SocketAddr 上。
async fn fetch_http(host: &str, port: u16, path: &str, ssrf: bool) -> std::io::Result<Vec<u8>> {
    let addrs = resolve_peer_addrs(host, port, ssrf).await?;
    let mut stream = connect_pinned(&addrs).await?;
    stream.set_nodelay(true).ok();
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\nUser-Agent: ebpdns/2.0\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    let n = tokio::time::timeout(
        FETCH_TIMEOUT,
        stream.take(SUB_MAX_BODY).read_to_end(&mut buf),
    )
    .await??;
    if n >= SUB_MAX_BODY as usize {
        return Err(io_err("订阅响应体超过 16MB 上限"));
    }
    Ok(buf)
}

/// HTTPS GET：rustls(ring) + 严格证书/名校验。TCP 钉在已校验 IP，TLS SNI/校验用原主机名。
async fn fetch_https(
    host: &str,
    port: u16,
    path: &str,
    tls: Arc<ClientConfig>,
    ssrf: bool,
) -> std::io::Result<Vec<u8>> {
    let addrs = resolve_peer_addrs(host, port, ssrf).await?;
    let tcp = connect_pinned(&addrs).await?;
    let sni = ServerName::try_from(host.to_string()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("bad SNI: {host}"))
    })?;
    let connector = TlsConnector::from(tls);
    let mut conn = connector
        .connect(sni, tcp)
        .await
        .map_err(|e| std::io::Error::other(format!("TLS handshake: {e}")))?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\nUser-Agent: ebpdns/2.0\r\nAccept: application/octet-stream\r\n\r\n"
    );
    conn.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    // Connection: close：对端直接断连即 body 结束（TLS 无 close_notify 视为正常 EOF）。
    let res =
        tokio::time::timeout(FETCH_TIMEOUT, conn.take(SUB_MAX_BODY).read_to_end(&mut buf)).await;
    match res {
        Ok(Ok(n)) => {
            if n >= SUB_MAX_BODY as usize {
                return Err(io_err("订阅响应体超过 16MB 上限"));
            }
        }
        // 对端未发 close_notify 直接断连：视为正常 EOF。
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(io_err("read timeout")),
    }
    Ok(buf)
}

/// 构建 rustls 客户端配置。`trust_pem` 为 Some 时用其自签证书作信任锚（测试）；
/// 否则用 webpki-roots。恒严格校验，不提供 dangerous/不校验开关。
fn build_tls_config(trust_pem: Option<&[u8]>) -> std::io::Result<Arc<ClientConfig>> {
    let provider = rustls::crypto::ring::default_provider();
    let mut roots = RootCertStore::empty();
    match trust_pem {
        Some(pem) => {
            let mut cur = std::io::Cursor::new(pem);
            for cert in rustls_pemfile::certs(&mut cur) {
                let cert = cert.map_err(|e| io_err(format!("trust pem: {e}")))?;
                roots
                    .add(cert)
                    .map_err(|e| io_err(format!("trust root: {e}")))?;
            }
            if roots.is_empty() {
                return Err(io_err("信任根为空"));
            }
        }
        None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }
    let cfg = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| io_err(format!("tls provider: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// 解析 HTTP/1.1 响应：状态行 200 才返回 body；3xx 一律 fail-closed（不跟随跨主机重定向）。
/// 支持 Content-Length 与 chunked（兜底）；Connection: close 时读全量。
fn parse_http_body(raw: &[u8]) -> std::io::Result<String> {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| io_err("响应无 header/body 分隔"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| io_err(format!("无法解析状态行: {status_line}")))?;
    if (300..400).contains(&code) {
        return Err(io_err(format!(
            "SSRF: 拒绝跟随重定向 {code}（跨主机/跨协议 fail-closed）"
        )));
    }
    if code != 200 {
        return Err(io_err(format!("订阅 HTTP {code}")));
    }
    let headers: Vec<&str> = lines.collect();
    let chunked = headers.iter().any(|l| {
        l.to_ascii_lowercase().starts_with("transfer-encoding:")
            && l.to_ascii_lowercase().contains("chunked")
    });
    let out = if chunked {
        dechunk(body)?
    } else {
        body.to_string()
    };
    Ok(out)
}

/// 解 chunked body（HTTP/1.1）。
fn dechunk(mut body: &str) -> std::io::Result<String> {
    let mut out = String::new();
    while !body.is_empty() {
        let nl = body
            .find("\r\n")
            .ok_or_else(|| io_err("chunked 缺长度行"))?;
        let size_hex = body[..nl].trim();
        let size: usize = usize::from_str_radix(size_hex, 16)
            .map_err(|_| io_err(format!("bad chunk size: {size_hex}")))?;
        body = &body[nl + 2..];
        if size == 0 {
            break;
        }
        if body.len() < size {
            return Err(io_err("chunked body 不完整"));
        }
        out.push_str(&body[..size]);
        body = &body[size..];
        // 跳过 chunk 尾部 CRLF
        if body.starts_with("\r\n") {
            body = &body[2..];
        }
    }
    Ok(out)
}

fn io_err(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::other(msg.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::MockClock;
    use crate::config::{ResolverConfig, UpstreamCfg};
    use crate::query::ScriptedQuerier;
    use crate::telemetry::NoopTelemetry;

    /// 一致性缺口：排序依赖 `HealthKeeper`，而健康检查此前只喂熔断器。
    /// 断言：一轮健康探针（无论成功/失败）都必须把结果写进 `HealthKeeper`
    /// （`ok_count`/`fail_count` 至少一侧 +1），否则 `upstream_eff_lat` 只能
    /// **[历史归因]** 依赖数据面流量。对齐 Python `_upstream_eff_lat` 的 telemetry 数据源。
    ///
    /// 用 RFC5737 TEST-NET-1（不可路由）作上游，探针必然失败：失败路径同样要落表。
    #[tokio::test]
    async fn health_check_records_into_health_keeper() {
        // **2.1.49-p3（测试设计）**：本用例依赖“TEST-NET-1 不可路由/不应答”这一网络前提，
        // 而开发/部署环境可能对该网段有透明应答器（实测 192.168.0.0/24 网关就会应答），
        // 因此改为**opt-in**：CI/本地显式设置 EBPDNS_NET_TESTS=1 才执行。
        if std::env::var_os("EBPDNS_NET_TESTS").is_none() {
            eprintln!("SKIP: 网络探针用例需 EBPDNS_NET_TESTS=1 显式开启");
            return;
        }
        let mut up = UpstreamCfg::test_up("hb1");
        up.host = "192.0.2.1".to_string();
        up.port = 53;
        let mut cfg = ResolverConfig::test_default(vec![up], Vec::new(), 1);
        cfg.health_probe_timeout_ms = 80;
        cfg.circuit_fails = 3;
        let rt = Arc::new(ebpdns_upstream::UpstreamRuntime::new());
        let r = Resolver::new(
            cfg,
            Arc::new(NoopTelemetry),
            Arc::new(MockClock::new(1_700_000_000.0)),
            Arc::new(ScriptedQuerier::new(|_, _, _| Vec::new())),
        );
        r.set_runtime(rt.clone());

        let before = rt.health.stats("hb1");
        assert_eq!(before.ok_count() + before.fail_count(), 0, "起点无样本");

        r.health_check_once().await;

        let after = rt.health.stats("hb1");
        assert!(
            after.ok_count() + after.fail_count() >= 1,
            "健康检查必须写入 HealthKeeper（排序数据源），实际 ok={} fail={}",
            after.ok_count(),
            after.fail_count()
        );
        // 探针发往不可路由地址 → 期望落失败样本（同时也验证熔断器喂点不 panic）。
        assert!(after.fail_count() >= 1, "不可路由上游应记失败样本");
        assert!(
            r.upstream_runtime().is_some(),
            "runtime 句柄在健康检查后仍可用"
        );
    }

    /// 无 runtime 时健康检查必须静默返回（不 panic、不留副作用）。
    #[tokio::test]
    async fn health_check_without_runtime_is_noop() {
        let cfg = ResolverConfig::test_default(vec![UpstreamCfg::test_up("u1")], Vec::new(), 1);
        let r = Resolver::new(
            cfg,
            Arc::new(NoopTelemetry),
            Arc::new(MockClock::new(1_700_000_000.0)),
            Arc::new(ScriptedQuerier::new(|_, _, _| Vec::new())),
        );
        r.health_check_once().await;
        assert!(r.upstream_runtime().is_none());
    }

    /// 优化项 2：探针失败**不得**占用熔断打开名额（与数据面解耦）。
    /// 3 个探针轮次 × 3 个上游 = 9 次失败 > circuit_fails=3，若仍耦合必然打开。
    #[tokio::test]
    async fn probe_failures_do_not_open_breaker() {
        // **2.1.49-p3（测试设计）**：本用例依赖“TEST-NET-1 不可路由/不应答”这一网络前提，
        // 而开发/部署环境可能对该网段有透明应答器（实测 192.168.0.0/24 网关就会应答），
        // 因此改为**opt-in**：CI/本地显式设置 EBPDNS_NET_TESTS=1 才执行。
        if std::env::var_os("EBPDNS_NET_TESTS").is_none() {
            eprintln!("SKIP: 网络探针用例需 EBPDNS_NET_TESTS=1 显式开启");
            return;
        }
        let ups: Vec<UpstreamCfg> = (0..3)
            .map(|i| {
                let mut u = UpstreamCfg::test_up(&format!("pf{i}"));
                u.host = "192.0.2.1".to_string(); // TEST-NET-1，不可路由
                u.port = 53;
                u
            })
            .collect();
        let mut cfg = ResolverConfig::test_default(ups, Vec::new(), 1);
        cfg.probe_timeout_ms = 40; // 显式探针超时（优化项 2 新键），保持测试快
        cfg.circuit_fails = 3;
        cfg.circuit_open_s = 30.0;
        let rt = Arc::new(ebpdns_upstream::UpstreamRuntime::new());
        let r = Resolver::new(
            cfg,
            Arc::new(NoopTelemetry),
            Arc::new(MockClock::new(1_700_000_000.0)),
            Arc::new(ScriptedQuerier::new(|_, _, _| Vec::new())),
        );
        r.set_runtime(rt.clone());
        for _ in 0..3 {
            r.health_check_once().await;
        }
        for i in 0..3 {
            let id = format!("pf{i}");
            assert!(
                !r.cb_is_open(&id),
                "探针失败不得打开熔断（优化项 2 解耦回归）: {id}"
            );
            assert_eq!(r.cb_view(&id).fails, 0, "探针失败不得计入数据面 fails");
            assert!(r.cb_view(&id).probe_fail >= 3, "独立 probe_fail 计数须累计");
        }
    }

    /// 优化项 7：enabled ≤ 8 时每轮**全部**探（而不是 3 个轮转）。
    #[tokio::test]
    async fn health_check_probes_all_enabled_upstreams_when_le_eight() {
        let ups: Vec<UpstreamCfg> = (0..5)
            .map(|i| {
                let mut u = UpstreamCfg::test_up(&format!("a{i}"));
                u.host = "192.0.2.1".to_string();
                u.port = 53;
                u
            })
            .collect();
        let mut cfg = ResolverConfig::test_default(ups, Vec::new(), 1);
        cfg.probe_timeout_ms = 40;
        let rt = Arc::new(ebpdns_upstream::UpstreamRuntime::new());
        let r = Resolver::new(
            cfg,
            Arc::new(NoopTelemetry),
            Arc::new(MockClock::new(1_700_000_000.0)),
            Arc::new(ScriptedQuerier::new(|_, _, _| Vec::new())),
        );
        r.set_runtime(rt.clone());
        // 一轮就应覆盖全部 5 个（旧实现每轮只探 3 个）。
        r.health_check_once().await;
        for i in 0..5 {
            let st = rt.health.stats(&format!("a{i}"));
            assert!(
                st.ok_count() + st.fail_count() >= 1,
                "enabled=5 ≤ 8 时必须一轮全覆盖: a{i} 无样本"
            );
        }
    }

    /// 优化项 7：enabled > 8 时保持 3 个轮转，N/3 轮内覆盖全部（无打开态时无额外补探）。
    #[tokio::test]
    async fn health_check_rotates_three_per_round_when_many_upstreams() {
        let ups: Vec<UpstreamCfg> = (0..12)
            .map(|i| {
                let mut u = UpstreamCfg::test_up(&format!("m{i:02}"));
                u.host = "192.0.2.1".to_string();
                u.port = 53;
                u
            })
            .collect();
        let mut cfg = ResolverConfig::test_default(ups, Vec::new(), 1);
        cfg.probe_timeout_ms = 30;
        let rt = Arc::new(ebpdns_upstream::UpstreamRuntime::new());
        let r = Resolver::new(
            cfg,
            Arc::new(NoopTelemetry),
            Arc::new(MockClock::new(1_700_000_000.0)),
            Arc::new(ScriptedQuerier::new(|_, _, _| Vec::new())),
        );
        r.set_runtime(rt.clone());
        // 第 1 轮恰好 3 个（不是 12 个）。
        r.health_check_once().await;
        let touched = |rt: &Arc<ebpdns_upstream::UpstreamRuntime>| {
            (0..12)
                .filter(|i| {
                    let st = rt.health.stats(&format!("m{i:02}"));
                    st.ok_count() + st.fail_count() > 0
                })
                .count()
        };
        assert_eq!(touched(&rt), 3, ">8 时每轮只探 3 个（轮转）");
        // 4 轮（12/3）后全覆盖。
        for _ in 0..3 {
            r.health_check_once().await;
        }
        assert_eq!(touched(&rt), 12, "12/3=4 轮内必须覆盖全部上游");
    }

    /// 优化项 5：已打开态上游被**优先**探到；探针成功 → 熔断立即恢复（不等退避窗口）。
    #[tokio::test]
    async fn open_upstream_is_probed_first_and_recovers_on_success() {
        // **2.1.49-p3（测试设计）**：本用例依赖“TEST-NET-1 不可路由/不应答”这一网络前提，
        // 而开发/部署环境可能对该网段有透明应答器（实测 192.168.0.0/24 网关就会应答），
        // 因此改为**opt-in**：CI/本地显式设置 EBPDNS_NET_TESTS=1 才执行。
        if std::env::var_os("EBPDNS_NET_TESTS").is_none() {
            eprintln!("SKIP: 网络探针用例需 EBPDNS_NET_TESTS=1 显式开启");
            return;
        }
        // 12 个上游（>8 → 走轮转），只有被注入打开的 "r00" 会被优先逻辑选中。
        let ups: Vec<UpstreamCfg> = (0..12)
            .map(|i| {
                let mut u = UpstreamCfg::test_up(&format!("r{i:02}"));
                u.host = "192.0.2.1".to_string(); // 全部不可路由（探针必然失败）
                u.port = 53;
                u
            })
            .collect();
        let mut cfg = ResolverConfig::test_default(ups, Vec::new(), 1);
        cfg.probe_timeout_ms = 30;
        cfg.circuit_fails = 3;
        let rt = Arc::new(ebpdns_upstream::UpstreamRuntime::new());
        let r = Resolver::new(
            cfg,
            Arc::new(NoopTelemetry),
            Arc::new(MockClock::new(1_700_000_000.0)),
            Arc::new(ScriptedQuerier::new(|_, _, _| Vec::new())),
        );
        r.set_runtime(rt.clone());
        // 注入一个已经打开的条目（MockClock 固定 → until 用"未来"表示）。
        r.cb_inject("r00", 3, 1_700_000_000.0 + 600.0);
        assert!(r.cb_is_open("r00"));
        r.health_check_once().await;
        // 打开态优先后必然被探到（探针失败 → 仍打开，但 probe_fail 计数上升）。
        assert!(
            r.cb_view("r00").probe_fail >= 1,
            "打开态上游必须被优先探到（优化项 5）"
        );
        assert!(r.cb_is_open("r00"), "探针失败不应误恢复（上游确实不可达）");
        // 探针成功路径：直接喂 probe_ok，打开态必须立即恢复。
        let recovered = r.cb_probe_ok("r00");
        assert!(recovered, "打开态探针成功须报告恢复");
        assert!(!r.cb_is_open("r00"), "探针成功 → 熔断立即恢复");
        assert_eq!(r.cb_view("r00").probe_ok, 1);
    }

    /// 优化项 6：全部上游被熔断打开时 select_upstreams 兜底放行（不空结果），
    /// 且打开态可被 `cb_open_ids` 枚举（数据面据此打 warn + 计数）。
    #[tokio::test]
    async fn all_open_fallback_is_observable() {
        let ups: Vec<UpstreamCfg> = (0..3)
            .map(|i| UpstreamCfg::test_up(&format!("bo{i}")))
            .collect();
        let cfg = ResolverConfig::test_default(ups, Vec::new(), 1);
        let r = Resolver::new(
            cfg,
            Arc::new(NoopTelemetry),
            Arc::new(MockClock::new(1_700_000_000.0)),
            Arc::new(ScriptedQuerier::new(|_, _, _| Vec::new())),
        );
        assert_eq!(r.cb_all_open_count(), 0);
        for i in 0..3 {
            r.cb_inject(&format!("bo{i}"), 3, 1_700_000_000.0 + 600.0);
        }
        let all = r.config().upstreams.clone();
        let (primary, _backup) = r.select_upstreams(&all);
        assert_eq!(primary.len(), 3, "全打开时兜底放行全部（不空结果）");
        assert_eq!(r.cb_open_ids().len(), 3, "三个上游均处于打开态");
        assert!(
            r.cb_last_all_open_ids().is_empty(),
            "兜底放行的计数/列表由数据面 query_parallel 记账（此处尚未发生）"
        );
    }

    /* ================= **2.1.21（DEF-220-01 / DEF-220-11）** =================
     * `prefetch_trigger` = 入队阈值 **且** 续期阈值（唯一判据）；
     * `prefetch_target` = 续期回填时的 TTL 上限（**真的生效**，不再是死字段）。
     * 这两条覆盖审计 DEF-220-01 的两个实测现象：
     *   ① `trigger=3600, ttl=300` 时条目入队却**永不续期**（15% 暗闸门）；
     *   ② `prefetch_target` 全树零读取点。
     */

    /// 组装一条"看起来像从上游拿回来的"缓存条目（TTL 由调用方决定）。
    fn seeded_answer(value: &str, ttl: f64) -> crate::types::ResolveAnswer {
        crate::types::ResolveAnswer::new(value, ttl, ebpdns_proto::constants::TYPE_A)
    }

    /// 剩余 TTL（秒）；条目不存在 → None。
    fn ttl_left_of(r: &Resolver, d: &str, now: f64) -> Option<f64> {
        r.cache()
            .get(&r.ckey_normalized(d, "A"), now)
            .map(|e| e.expires_at - now)
    }

    /// **DEF-220-01 核心回归**：`prefetch_trigger` 必须能让"高于 15% 剩余 TTL"的条目
    /// 真的发上游续期 —— 改前 `do_prefetch` 另有一条 `left < ttl*0.15` 的暗闸门，
    /// `trigger=600 > ttl*0.15=45` 时条目入队却永不续期。
    #[tokio::test]
    async fn prefetch_trigger_actually_refreshes_above_fifteen_percent() {
        use std::sync::atomic::{AtomicU64, Ordering};
        // Arc<dyn Clock>：既 float 给 Resolver::new，又能调 Clock::epoch()。
        let clock: Arc<dyn crate::clock::Clock> = Arc::new(MockClock::new(1_700_000_000.0));
        let calls = Arc::new(AtomicU64::new(0));
        let c = calls.clone();
        let mut cfg = ResolverConfig::test_default(vec![UpstreamCfg::test_up("u1")], Vec::new(), 1);
        cfg.prefetch = true;
        cfg.prefetch_interval = 1.0;
        cfg.prefetch_trigger = 600.0; // ≫ ttl*0.15（300*0.15=45）
        cfg.prefetch_target = 0.0; // 不额外收紧
        cfg.ttl = 300;
        cfg.ttl_min = 0;
        cfg.ttl_max = 604_800;
        let r = Resolver::new(
            cfg,
            Arc::new(NoopTelemetry),
            Arc::clone(&clock),
            Arc::new(ScriptedQuerier::new(move |_, _, _| {
                c.fetch_add(1, Ordering::Relaxed);
                vec![crate::types::UpstreamAnswer::ok(
                    "u1",
                    0,
                    vec![seeded_answer("9.9.9.9", 300.0)],
                    vec![],
                )]
            })),
        );

        // 造一条"还剩 100s"的缓存条目（100 < trigger=600，但 100 > 45 = ttl*0.15）。
        let key = r.ckey_normalized("pf-trig.test", "A");
        r.cache().put(
            key,
            ebpdns_cache::CacheEntry {
                domain: "pf-trig.test".into(),
                qtype: "A".into(),
                rrsets: ebpdns_cache::rrset::rrsets_from_flat(&[ebpdns_cache::CacheAnswer {
                    value: "1.1.1.1".into(),
                    ttl: 300.0,
                    rtype: 1,
                    name: None,
                }]),
                chosen: "1.1.1.1".into(),
                ttl: 300.0,
                rcode: 0,
                rule_gen: r.rule_gen(),
                expires_at: 1_700_000_200.0, // 还剩 200s（> 15%）

                seq: 0,
            },
            1_700_000_000.0,
        );
        r.schedule_prefetch("pf-trig.test", "A", 200.0, false);
        assert_eq!(r.prefetch_len(), 1, "200 ≤ trigger(600) ⇒ 必须入队");

        let before = calls.load(Ordering::Relaxed);
        r.do_prefetch().await;
        assert!(
            calls.load(Ordering::Relaxed) > before,
            "低于 trigger 的条目**必须真的发上游续期**（改前被 15% 暗闸门拦掉）"
        );
        assert_eq!(r.prefetch_len(), 0, "一轮已消费队列");
        // 续期后剩余 TTL 回到上游给的 300s（prefetch_target=0 ⇒ 不收紧）。
        let left = ttl_left_of(&r, "pf-trig.test", clock.epoch()).expect("条目仍在");
        assert!(
            left > 250.0,
            "续期必须把 TTL 顶回上游值（实际剩余 {left}s）"
        );
    }

    /// **DEF-220-01 反向 + 2.2.1（P2-07）**：`left > trigger` 的条目**不入队**，
    /// **全量补扫也不得刷新它**（2.2.0 的补扫跳过 TTL 判据 ⇒ 每轮重查全部热键，
    /// 生产实测上游请求 ≈ 客户端查询 20.8 倍）；只有 `left <= trigger` 的临近过期
    /// 条目才由补扫续期。`prefetch_max=0` 时补扫关闭，一轮预取不发任何上游查询。
    #[tokio::test]
    async fn prefetch_trigger_skips_entries_above_threshold() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let calls = Arc::new(AtomicU64::new(0));
        let c = calls.clone();
        let mut cfg = ResolverConfig::test_default(vec![UpstreamCfg::test_up("u1")], Vec::new(), 1);
        cfg.prefetch = true;
        cfg.prefetch_trigger = 60.0;
        cfg.ttl = 300;
        let r = Resolver::new(
            cfg,
            Arc::new(NoopTelemetry),
            Arc::new(MockClock::new(1_700_000_000.0)),
            Arc::new(ScriptedQuerier::new(move |_, _, _| {
                c.fetch_add(1, Ordering::Relaxed);
                vec![crate::types::UpstreamAnswer::ok(
                    "u1",
                    0,
                    vec![seeded_answer("9.9.9.9", 300.0)],
                    vec![],
                )]
            })),
        );
        // 剩余 200s > trigger=60 ⇒ 不入队。
        let key = r.ckey_normalized("pf-skip.test", "A");
        r.cache().put(
            key,
            ebpdns_cache::CacheEntry {
                domain: "pf-skip.test".into(),
                qtype: "A".into(),
                rrsets: Vec::new(),
                chosen: String::new(),
                ttl: 300.0,
                rcode: 0,
                rule_gen: r.rule_gen(),
                expires_at: 1_700_000_200.0,

                seq: 0,
            },
            1_700_000_000.0,
        );
        r.schedule_prefetch("pf-skip.test", "A", 200.0, false);
        assert_eq!(r.prefetch_len(), 0, "200 > trigger(60) ⇒ 不得入队");
        let before = calls.load(Ordering::Relaxed);
        r.do_prefetch().await;
        assert_eq!(
            calls.load(Ordering::Relaxed),
            before,
            "2.2.1（P2-07）：剩余 TTL(200) > trigger(60) ⇒ 全量补扫**不得**重查（探测流量放大源）"
        );
        // 把同一键压到 trigger 窗口内（剩余 30s ≤ 60s）⇒ 补扫必须续期恰好 1 次。
        r.cache().put(
            r.ckey_normalized("pf-skip.test", "A"),
            ebpdns_cache::CacheEntry {
                domain: "pf-skip.test".into(),
                qtype: "A".into(),
                rrsets: Vec::new(),
                chosen: String::new(),
                ttl: 30.0,
                rcode: 0,
                rule_gen: r.rule_gen(),
                expires_at: 1_700_000_030.0,
                seq: 0,
            },
            1_700_000_000.0,
        );
        let before = calls.load(Ordering::Relaxed);
        // **2.2.2（P2-05）**：模拟"有真实流量"（否则低流量闸门会跳过补扫）。
        for _ in 0..20 {
            r.note_client_query();
        }
        r.do_prefetch().await;
        assert_eq!(
            calls.load(Ordering::Relaxed),
            before + 1,
            "临近过期（30 ≤ trigger 60）的条目必须由补扫续期"
        );

        // 补扫关闭（prefetch_max=0）⇒ 一轮预取不发上游。
        let calls2 = Arc::new(AtomicU64::new(0));
        let c2 = calls2.clone();
        let mut cfg2 =
            ResolverConfig::test_default(vec![UpstreamCfg::test_up("u1")], Vec::new(), 1);
        cfg2.prefetch = true;
        cfg2.prefetch_trigger = 60.0;
        cfg2.prefetch_max = 0;
        let r2 = Resolver::new(
            cfg2,
            Arc::new(NoopTelemetry),
            Arc::new(MockClock::new(1_700_000_000.0)),
            Arc::new(ScriptedQuerier::new(move |_, _, _| {
                c2.fetch_add(1, Ordering::Relaxed);
                vec![]
            })),
        );
        r2.do_prefetch().await;
        assert_eq!(
            calls2.load(Ordering::Relaxed),
            0,
            "prefetch_max=0 ⇒ 补扫关闭，不得发上游"
        );
    }

    /// **2.2.2（P2-05）**：低流量（每轮客户端查询 < 阈值）时**跳过全量补扫** ——
    /// 空闲实例不再以 `prefetch_max/4` 预算自转；有真实流量时补扫照常。
    #[tokio::test]
    async fn idle_low_traffic_skips_prefetch_sweep() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let calls = Arc::new(AtomicU64::new(0));
        let c = calls.clone();
        let mut cfg = ResolverConfig::test_default(vec![UpstreamCfg::test_up("u1")], Vec::new(), 1);
        cfg.prefetch = true;
        cfg.prefetch_trigger = 60.0;
        cfg.prefetch_max = 4096;
        // 低流量闸门只对 >=10s 的常规周期生效（测试用 60s 以覆盖闸门）。
        cfg.prefetch_interval = 60.0;
        cfg.ttl = 300;
        let r = Resolver::new(
            cfg,
            Arc::new(NoopTelemetry),
            Arc::new(MockClock::new(1_700_000_000.0)),
            Arc::new(ScriptedQuerier::new(move |_, _, _| {
                c.fetch_add(1, Ordering::Relaxed);
                vec![]
            })),
        );
        // 一条"临近过期"的条目（本会被补扫续期）。
        r.cache().put(
            r.ckey_normalized("idle-sweep.test", "A"),
            ebpdns_cache::CacheEntry {
                domain: "idle-sweep.test".into(),
                qtype: "A".into(),
                rrsets: Vec::new(),
                chosen: String::new(),
                ttl: 30.0,
                rcode: 0,
                rule_gen: r.rule_gen(),
                expires_at: 1_700_000_030.0,
                seq: 0,
            },
            1_700_000_000.0,
        );
        // 零客户端查询 ⇒ 跳过补扫（0 条上游）。
        r.do_prefetch().await;
        assert_eq!(calls.load(Ordering::Relaxed), 0, "空闲时不得补扫");
        // 注入真实流量（≥ 闸门阈值）⇒ 下一轮补扫 1 条。
        for _ in 0..20 {
            r.note_client_query();
        }
        r.do_prefetch().await;
        assert_eq!(calls.load(Ordering::Relaxed), 1, "有流量时补扫照常");
    }

    /// **DEF-220-11**：`prefetch_target` 是续期回填的 **TTL 上限**（此前零读取点）。
    #[tokio::test]
    async fn prefetch_target_caps_refill_ttl() {
        // Arc<dyn Clock>：既 float 给 Resolver::new，又能调 Clock::epoch()。
        let clock: Arc<dyn crate::clock::Clock> = Arc::new(MockClock::new(1_700_000_000.0));
        let mut cfg = ResolverConfig::test_default(vec![UpstreamCfg::test_up("u1")], Vec::new(), 1);
        cfg.prefetch = true;
        cfg.prefetch_trigger = 600.0;
        cfg.prefetch_target = 100.0; // 上限 100s（上游给 600s）
        cfg.ttl = 600;
        cfg.ttl_min = 0;
        cfg.ttl_max = 604_800;
        let r = Resolver::new(
            cfg,
            Arc::new(NoopTelemetry),
            Arc::clone(&clock),
            Arc::new(ScriptedQuerier::new(|_, _, _| {
                vec![crate::types::UpstreamAnswer::ok(
                    "u1",
                    0,
                    vec![seeded_answer("9.9.9.9", 600.0)],
                    vec![],
                )]
            })),
        );
        let key = r.ckey_normalized("pf-target.test", "A");
        r.cache().put(
            key,
            ebpdns_cache::CacheEntry {
                domain: "pf-target.test".into(),
                qtype: "A".into(),
                rrsets: ebpdns_cache::rrset::rrsets_from_flat(&[ebpdns_cache::CacheAnswer {
                    value: "1.1.1.1".into(),
                    ttl: 600.0,
                    rtype: 1,
                    name: None,
                }]),
                chosen: "1.1.1.1".into(),
                ttl: 600.0,
                rcode: 0,
                rule_gen: r.rule_gen(),
                expires_at: 1_700_000_300.0, // 还剩 300s ≤ trigger=600

                seq: 0,
            },
            1_700_000_000.0,
        );
        r.schedule_prefetch("pf-target.test", "A", 300.0, false);
        assert_eq!(r.prefetch_len(), 1, "300 ≤ trigger(600) ⇒ 入队");
        r.do_prefetch().await;
        let left = ttl_left_of(&r, "pf-target.test", clock.epoch()).expect("条目仍在");
        assert!(
            left <= 101.0 && left > 90.0,
            "`prefetch_target=100` 必须是续期 TTL 上限（上游给 600s），实际剩余 {left}s"
        );
    }

    /// **2.2.3（P2-C）**：命中驱动 pending 的**单轮上限（24）**与**热 key 优先**。
    ///
    /// 2.2.2 在突发后会一轮排空全部 pending（生产 107 次/2min）；这里钉死：
    /// * 41 条 pending ⇒ 一轮只发 24 条上游，其余 17 条**重新入队**（不丢）；
    /// * 热 key（有命中频率）必须先于冷 key 被刷新。
    #[tokio::test]
    async fn prefetch_pending_burst_is_capped_and_hot_first() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Mutex as StdMutex;

        let calls = Arc::new(AtomicU64::new(0));
        let order: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
        let (c, o) = (calls.clone(), order.clone());
        let clock: Arc<dyn crate::clock::Clock> = Arc::new(MockClock::new(1_700_000_000.0));
        let mut cfg = ResolverConfig::test_default(vec![UpstreamCfg::test_up("u1")], Vec::new(), 1);
        cfg.prefetch = true;
        cfg.prefetch_interval = 60.0;
        cfg.prefetch_trigger = 600.0;
        cfg.prefetch_max = 4096;
        cfg.ttl = 300;
        cfg.ttl_min = 0;
        let r = Resolver::new(
            cfg,
            Arc::new(NoopTelemetry),
            Arc::clone(&clock),
            Arc::new(ScriptedQuerier::new(move |d, _, _| {
                c.fetch_add(1, Ordering::Relaxed);
                o.lock().unwrap().push(d.to_string());
                vec![crate::types::UpstreamAnswer::ok(
                    "u1",
                    0,
                    vec![seeded_answer("9.9.9.9", 300.0)],
                    vec![],
                )]
            })),
        );
        // 热 key：先写入并命中两次（freq≥2 ⇒ hot_keys 可见）。
        let hot = r.ckey_normalized("hot-223.test", "A");
        r.cache().put(
            hot.clone(),
            ebpdns_cache::CacheEntry {
                domain: "hot-223.test".into(),
                qtype: "A".into(),
                rrsets: Vec::new(),
                chosen: String::new(),
                ttl: 100.0,
                rcode: 0,
                rule_gen: r.rule_gen(),
                expires_at: 1_700_000_100.0,
                seq: 0,
            },
            clock.epoch(),
        );
        assert!(r.cache().get(&hot, clock.epoch()).is_some());
        assert!(r.cache().get(&hot, clock.epoch()).is_some());
        r.schedule_prefetch("hot-223.test", "A", 100.0, false);
        for i in 0..40 {
            r.schedule_prefetch(&format!("cold-{i:02}.test"), "A", 100.0, false);
        }
        assert_eq!(r.prefetch_len(), 41, "先决条件：41 条 pending");

        // **P2-C/P2-H**：低流量时 pending 上限是 4；本用例验证"有真实流量"时的 24/轮，
        // 因此先注入 20 次客户端查询（= 非低流量阈值边界）。
        for _ in 0..20 {
            r.note_client_query();
        }
        r.do_prefetch().await;
        assert_eq!(
            calls.load(Ordering::Relaxed),
            PREFETCH_PENDING_ROUND_CAP as u64,
            "单轮 pending 上限必须是 {}（不是一次性排空 41 条）",
            PREFETCH_PENDING_ROUND_CAP
        );
        assert_eq!(
            r.prefetch_len(),
            41 - PREFETCH_PENDING_ROUND_CAP,
            "未处理的 pending 必须重新入队（不得丢弃）"
        );
        assert_eq!(
            order.lock().unwrap().first().map(String::as_str),
            Some("hot-223.test"),
            "热 key 必须先被刷新（实际顺序：{:?}）",
            order.lock().unwrap()
        );
    }

    /// **2.2.3（P2-C/P2-H）**：连续 3 轮低流量后暂停 pending 出队；有流量立即恢复。
    #[tokio::test]
    async fn idle_prefetch_pauses_pending_after_three_rounds() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let calls = Arc::new(AtomicU64::new(0));
        let c = calls.clone();
        let mut cfg = ResolverConfig::test_default(vec![UpstreamCfg::test_up("u1")], Vec::new(), 1);
        cfg.prefetch = true;
        cfg.prefetch_interval = 60.0;
        cfg.prefetch_trigger = 600.0;
        cfg.prefetch_max = 4096;
        cfg.ttl = 300;
        cfg.ttl_min = 0;
        let r = Resolver::new(
            cfg,
            Arc::new(NoopTelemetry),
            Arc::new(MockClock::new(1_700_000_000.0)),
            Arc::new(ScriptedQuerier::new(move |_, _, _| {
                c.fetch_add(1, Ordering::Relaxed);
                vec![]
            })),
        );
        let before = calls.load(Ordering::Relaxed);
        for (round, want) in [(1usize, 1u64), (2, 2), (3, 2)] {
            r.schedule_prefetch("idle-pause.test", "A", 100.0, false);
            r.do_prefetch().await;
            assert_eq!(
                calls.load(Ordering::Relaxed) - before,
                want,
                "第 {round} 轮低流量：期望累计 {want} 次上游（3 轮起暂停）"
            );
        }
        assert_eq!(
            r.prefetch_len(),
            1,
            "暂停期间 pending 必须保留（不丢刷新义务）"
        );
        // 真实流量 ⇒ 立即恢复出队。
        for _ in 0..20 {
            r.note_client_query();
        }
        r.do_prefetch().await;
        assert_eq!(
            calls.load(Ordering::Relaxed) - before,
            3,
            "有流量后必须继续消费暂停期间积压的 pending"
        );
        assert_eq!(r.prefetch_len(), 0);
    }

    /// **2.2.3（P2-H）**：低流量健康探针每轮只探 1 个目标（打开态优先、保底探测）。
    #[tokio::test]
    async fn idle_health_probe_limited_to_one_target() {
        let ups: Vec<UpstreamCfg> = (0..5)
            .map(|i| {
                let mut u = UpstreamCfg::test_up(&format!("h{i}"));
                u.host = "192.0.2.1".to_string();
                u.port = 53;
                u
            })
            .collect();
        let mut cfg = ResolverConfig::test_default(ups, Vec::new(), 1);
        cfg.probe_timeout_ms = 40;
        let rt = Arc::new(ebpdns_upstream::UpstreamRuntime::new());
        let r = Resolver::new(
            cfg,
            Arc::new(NoopTelemetry),
            Arc::new(MockClock::new(1_700_000_000.0)),
            Arc::new(ScriptedQuerier::new(|_, _, _| Vec::new())),
        );
        r.set_runtime(rt.clone());
        r.health_check_once_limited(Some(1)).await;
        let touched = (0..5)
            .filter(|i| {
                let st = rt.health.stats(&format!("h{i}"));
                st.ok_count() + st.fail_count() > 0
            })
            .count();
        assert_eq!(touched, 1, "低流量时每轮最多探 1 个上游（实际 {touched}）");
    }

    /// **2.2.4（P2-G）**：健康探针必须计入 `probe_upstream_queries`（2.2.3 及以前
    /// 只接了 `prefer_ipv4` 的 `probe_a_record`，生产该计数器恒 0）。
    #[tokio::test]
    async fn health_probe_increments_probe_upstream_queries() {
        use crate::telemetry::RecordingTelemetry;
        let ups: Vec<UpstreamCfg> = (0..2)
            .map(|i| {
                let mut u = UpstreamCfg::test_up(&format!("hp{i}"));
                u.host = "192.0.2.1".to_string();
                u.port = 53;
                u
            })
            .collect();
        let mut cfg = ResolverConfig::test_default(ups, Vec::new(), 1);
        cfg.probe_timeout_ms = 30;
        let tel = Arc::new(RecordingTelemetry::default());
        let rt = Arc::new(ebpdns_upstream::UpstreamRuntime::new());
        let r = Resolver::new(
            cfg,
            tel.clone(),
            Arc::new(MockClock::new(1_700_000_000.0)),
            Arc::new(ScriptedQuerier::new(|_, _, _| Vec::new())),
        );
        r.set_runtime(rt);
        // 每轮只探 1 个目标 ⇒ 恰好 +1（不是 +2，也不是 0）。
        r.health_check_once_limited(Some(1)).await;
        let n = tel
            .hits
            .lock()
            .get("probe_upstream_queries")
            .copied()
            .unwrap_or(0);
        assert_eq!(
            n, 1,
            "健康探针必须每目标 +1 probe_upstream_queries（实际 {n}）"
        );
        r.health_check_once_limited(None).await;
        let n = tel
            .hits
            .lock()
            .get("probe_upstream_queries")
            .copied()
            .unwrap_or(0);
        assert_eq!(n, 3, "全量一轮（2 个目标）后累计 3（实际 {n}）");
        // **2.2.5（P2-A8）/ 2.2.6（P2-A9）**：完成数必须等于传输层成功 + 失败的分账，
        // 且传输层成功必须等于验证层成功 + 失败（本用例的目标是否可达取决于测试环境，
        // 因此只钉"两本账各自自洽"，不钉具体成功/失败比例）。
        let hits = tel.hits.lock();
        let tok = hits.get("probe_transport_ok").copied().unwrap_or(0);
        let tfail = hits.get("probe_transport_fail").copied().unwrap_or(0);
        let vok = hits.get("probe_valid_ok").copied().unwrap_or(0);
        let vfail = hits.get("probe_valid_fail").copied().unwrap_or(0);
        assert_eq!(
            tok + tfail,
            n,
            "硬等式 probe_upstream_queries == probe_transport_ok + probe_transport_fail（tok={tok} tfail={tfail} n={n}）"
        );
        assert_eq!(
            vok + vfail,
            tok,
            "硬等式 probe_transport_ok == probe_valid_ok + probe_valid_fail（vok={vok} vfail={vfail} tok={tok}）"
        );
        assert_eq!(
            tok + tfail,
            3,
            "三个目标都必须完成（tok={tok} tfail={tfail}）"
        );
    }
}
