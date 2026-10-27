//! `resolve()` 核心：归一化 → 缓存快路径 → 规则 → 并发上游 → quorum 表决 → CNAME 链 →
//! **[历史归因]** 候选去重 → rebind 防护 → 回填缓存。忠实对齐 Python `resolver.py::resolve`。
//!
//! # trace 构造门禁（性能上限项）
//! `trace` 事件只在 `/api/query`（人工查询）需要——`ebpdns-server` 的**数据面**
//! `dns.rs` 从不读 `ResolveResult::trace`，只有 `api.rs::query` 把它序列化进响应。
//! 旧实现无条件为每条链路构造 `Vec<TraceEvent>`（含 `format!` 分配），数据面每 QPS
//! 白付一次堆分配。现在由 [`ResolveOpts::trace`] 门控：关闭时 [`TraceSink`] 为
//! `Option::None`，`push_with` 是 **no-op（闭包不执行 ⇒ 连 `format!` 都不发生）**，
//! 返回的 `ResolveResult::trace` 恒为空 `Vec`（字段仍存在，不报错、不错位）。
//!
//! # 每查询分配（热路径）
//! | 位置 | 旧实现 | 新实现 |
//! |---|---|---|
//! | trace 入口 | 1×`Vec` + 1×`String`(`format!`) + 1×`TraceEvent`（2×`String`） | 0（关闭时） |
//! | `ckey` | `normalize()` 再分配 1×`String` + `qtype.to_ascii_uppercase()` 1×`String` | 0（复用已归一化的 `d` / `qtype`，仅 `CacheKey` 自身的 2×`String`） |
//! | `probe_override`/`proto_of` | 无条件建 `HashMap<String,String>`（每个上游 2×`String`） | 仅 `speed_test && ip_speed_check && 候选>1` 时建 |

use std::fmt::Write as _;
use std::sync::Arc;

use ebpdns_cache::{CacheEntry, CacheKey, DnsCache};
use ebpdns_proto::constants::{RCODE_NOERROR, RCODE_NOTIMP, RCODE_NXDOMAIN, TYPE_CNAME};
use ebpdns_rules::{Action, Rule};

use crate::config::UpstreamCfg;
use crate::helpers::{clamp_ttl, guess_type, is_private_ip, normalize, qtype_code};
use crate::query::ParallelQuerier;
use crate::types::{
    ResolveAnswer, ResolveResult, RuleHit, ServfailReason, TraceEvent, UpstreamAnswer,
    REASON_POLICY_FILTERED,
};
use crate::{CandidateSpeedHint, Resolver};

// >>> PATCH242A P1-1 aaaa-policy BEGIN
/// **2.1.42（P1-1）**：AAAA 本地策略的**唯一**判定结果。
///
/// 数据面快路径（`answer.rs::answer_fast_ex`）与完整解析路径
/// （`resolve_inner`）必须用同一个判定函数 [`Resolver::aaaa_policy_cached`]，
/// 否则"已缓存 AAAA + `ipv6=false`/`prefer_ipv4`"会从快路径漏出去。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AaaaPolicy {
    /// `ipv6=false`：AAAA 一律本地 NODATA。
    Ipv6Disabled,
    /// `prefer_ipv4=true` 且 A 缓存已确认存在：AAAA 本地 NODATA。
    PreferIpv4,
    /// `prefer_ipv4=true` 但 A 不在缓存：慢路径需 `probe_a_record`，**快路径必须交回慢路径**
    /// （不得直接下发已缓存的 AAAA）。
    PreferIpv4Probe,
}
// <<< PATCH242A P1-1 aaaa-policy END

/// resolve 选项。
#[derive(Clone, Debug, Default)]
pub struct ResolveOpts {
    pub silent: bool,
    pub counted: bool,
    pub force_refresh: bool,
    pub client_ip: Option<String>,
    pub depth: u32,
    /// 是否构造 `ResolveResult::trace`。**默认 false**：数据面（`dns.rs`）不读 trace，
    /// 只有 `/api/query` 人工查询需要（`api.rs` 显式置 true）。
    pub trace: bool,
    /// **2.1.21（DEF-220-01/11 修复）**：回填缓存时的 **TTL 上限**（秒），
    /// 语义 = `prefetch_target`（"续期后的目标 TTL 上限"）。
    ///
    /// `None` ⇒ 不额外收紧（仍受 `ttl`/`ttl_min`/`ttl_max` 与上游 TTL 约束）。
    /// 预取链路（`resolve_prefetch`）把它设成 `cfg.prefetch_target`，于是
    /// "续期到 target"是**可观测**的 —— 此前 `prefetch_target` 是全树**零读取点**
    /// 的死字段（只有 `main.rs` 的赋值点）。
    pub ttl_cap: Option<f64>,
}

impl ResolveOpts {
    /// 打开 trace 构造（`/api/query` 人工查询路径用）。
    pub fn with_trace(mut self) -> Self {
        self.trace = true;
        self
    }
}

/// 上游选择模式（优化项 9）。
///
/// 数据面走 [`UpstreamMode::Multi`]（`select_upstreams` 的 primary/backup 两波）；
/// 后台预取走 [`UpstreamMode::Single`]：整条解析链路（含双栈探测 / ipv4 回退 / CNAME 子链）
/// **只向 1 个上游**发起查询（`eff_lat/max(1,weight)` 最低且未熔断打开者），
/// 不启用后备波，失败不计入数据面 `circuit_fails`。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UpstreamMode {
    Multi,
    Single,
}

impl UpstreamMode {
    /// 是否单上游模式（预取）。
    #[inline]
    pub(crate) fn is_single(self) -> bool {
        matches!(self, UpstreamMode::Single)
    }
}

/// trace 收集器：关闭时为 `None`，所有写入退化为 no-op。
///
/// `push_with` 接收闭包而非已构造的 [`TraceEvent`]：关闭时闭包**不执行**，
/// 因此 `format!` 的开销与分配一并省掉（这是「非人工查询不构造 trace」的实质收益）。
#[derive(Debug, Default)]
pub(crate) struct TraceSink {
    events: Option<Vec<TraceEvent>>,
}

impl TraceSink {
    /// 按开关构造（`on=false` → 不分配 `Vec`）。
    #[inline]
    pub(crate) fn new(on: bool) -> Self {
        Self {
            events: if on { Some(Vec::new()) } else { None },
        }
    }

    /// 是否在收集（调用方可据此跳过仅为 trace 服务的昂贵构造）。
    #[inline]
    pub(crate) fn is_on(&self) -> bool {
        self.events.is_some()
    }

    /// 条件写入：仅开启时执行闭包。
    #[inline]
    pub(crate) fn push_with<F: FnOnce() -> TraceEvent>(&mut self, f: F) {
        if let Some(v) = self.events.as_mut() {
            v.push(f());
        }
    }

    /// 定长文本写入（无 `format!`，仅开启时按需分配一次 `String`）。
    #[inline]
    pub(crate) fn push_str(&mut self, tag: &str, text: &str) {
        if let Some(v) = self.events.as_mut() {
            v.push(TraceEvent::new(tag, text));
        }
    }

    /// 取出事件（关闭时恒为空 `Vec`，字段语义/形状不变）。
    #[inline]
    pub(crate) fn into_vec(self) -> Vec<TraceEvent> {
        self.events.unwrap_or_default()
    }
}

/// **2.1.16（功能 2）**：`CacheKey` → 在途合并表的稳定字符串键。
///
/// 为什么不用 `CacheKey` 本身做键：`CacheKey` 已实现 `Hash + Eq`，但 `SingleFlight`
/// 用的是 `HashMap<String, _>`；转成字符串后同键在**跨 qtype / 跨 group** 上不会误合并
/// （三段全带上），且便于日志/观测。开销：每个 miss 一次 `String` 拼接（≤ ~300B），
/// 相对一次上游查询可忽略。
pub(crate) fn cache_key_id(k: &ebpdns_cache::CacheKey) -> String {
    let mut s = String::with_capacity(k.domain.len() + k.qtype.len() + 8);
    s.push_str(k.group.as_deref().unwrap_or(""));
    s.push('|');
    s.push_str(&k.domain);
    s.push('|');
    s.push_str(&k.qtype);
    s
}

/// **2.1.43-B（P2-3）**：single-flight 的**完整**键 = [`cache_key_id`] + **`UpstreamMode`** 维度。
///
/// # 缺陷（2.1.42）
///
/// 在途合并表只用 `cache_key_id`（group|domain|qtype）作键 ⇒ **预取链路
/// （[`UpstreamMode::Single`]：只问 1 个上游、不产生后备波）与数据面
/// （[`UpstreamMode::Multi`]：primary + 后备波 + 补查波）会共享同一次上游扇出**：
/// * 数据面 leader 先到：预取 follower 直接拿"多上游扇出"的结果（比预取应有的
///   1 次上游贵，预取语义被放大）；
/// * 预取 leader 先到：**数据面 follower 只拿到 1 个上游的答案**（后备/补查波与
///   quorum 都按 `max_par`/`quorum_target` 的 Multi 预算算好了，却被 Single 的结果顶替）
///   ⇒ 上游失败时少一层冗余，SERVFAIL 归因也跟着漂。
///
/// # 修法
///
/// 键里显式带模式标签（`#multi` / `#single`）⇒ 两种模式**永不共享**扇出；
/// 同模式内的合并语义（N 路并发同键只发 1 次上游）逐位不变。
pub(crate) fn single_flight_key(k: &ebpdns_cache::CacheKey, mode: UpstreamMode) -> String {
    let mut s = cache_key_id(k);
    s.push('#');
    s.push_str(if mode.is_single() { "single" } else { "multi" });
    s
}

/// **2.1.16（功能 2）**：完整的**上游扇出**段 —— primary 波 + M4 fallback 波 + F-NX 补查波。
///
/// 从 `resolve_inner` 抽出成一个**自由函数**，目的就是让它能被 single-flight 包起来：
/// 该段是"最贵且幂等"的部分（所有 wire 请求都在这里发生），且不触碰任何按调用方
/// 变化的可变状态（trace 文本与波次数以返回值形式带回，由调用方按原顺序写入）。
///
/// 返回 `(results, trace_msgs, extra_waves)`。`trace_msgs` 的顺序与合并前
/// `trace.push_str("eng", …)` 的调用顺序**逐条一致**，因此 trace 内容与顺序不变。
#[allow(clippy::too_many_arguments)]
async fn fetch_upstreams(
    querier: Arc<dyn ParallelQuerier>,
    primary: Vec<UpstreamCfg>,
    backup: Vec<UpstreamCfg>,
    ups: Vec<UpstreamCfg>,
    d: String,
    qtype: String,
    depth: u32,
    single_mode: bool,
    max_parallel: usize,
    // >>> PATCH242A P0-1 fetch-quorum BEGIN
    // **2.1.42（P0-1）**：负票 quorum 阈值（= `clamp(nxdomain_quorum,1,启用候选数)`）。
    // 首波负票不足时继续查后备波 / F-NX 补查波，直到凑齐或问遍。
    quorum_target: usize,
    // <<< PATCH242A P0-1 fetch-quorum END
) -> crate::types::UpstreamFetch {
    let mut trace_msgs: Vec<String> = Vec::new();
    let mut results = querier.query_parallel(&primary, &d, &qtype, depth).await;
    // >>> PATCH242A P0-1 fetch-need-more BEGIN
    let q_eff = quorum_target.max(1);
    let need_more_votes = |rs: &[UpstreamAnswer]| -> bool {
        !rs.iter().any(|r| !r.answers.is_empty() && !r.udp_truncated)
            && rs.iter().filter(|r| is_negative_answer(r)).count() < q_eff
    };
    // <<< PATCH242A P0-1 fetch-need-more END

    // M4 fallback：首选上游全部真失败（无答案且 rcode∉{0,3}）→ 回退剩余上游重查一轮。
    // fallback=false 时 backup 为空 → 不回退（失败即 SERVFAIL）。
    if !results.is_empty() && !backup.is_empty() {
        let all_truly_failed = results
            .iter()
            .all(|r| r.answers.is_empty() && !matches!(r.rcode, Some(0 | 3)));
        // >>> PATCH242A P0-1 fallback-for-quorum BEGIN
        // **2.1.42（P0-1）**：即使首选波"有负票"，只要负票不足 quorum 且没有正向
        // 答案，也要查后备波 —— 否则"只有一台能判负"会永远凑不齐票。
        if all_truly_failed || need_more_votes(&results) {
            trace_msgs.push("首选上游未凑齐负票/全失败 → fallback 剩余上游".to_string());
            let more = querier.query_parallel(&backup, &d, &qtype, depth).await;
            results.extend(more);
        }
        // <<< PATCH242A P0-1 fallback-for-quorum END
    }

    // ---- F-NX 升级：首选波"全部无票"时把**尚未查询过**的启用上游补进来 ----
    //
    // 生产实测（24 条上游 / 8 条启用）：`select_upstreams` 只取 eff_lat 最优的 3 条，
    // 若这 3 条恰好都是 DoH（对不存在域名回 `no-answer`），而唯一能给出权威 NXDOMAIN
    // 的 LAN 上游排在第 4 位及以后，则本轮**一条有效票都没有** → SERVFAIL。
    // 正确修法是**把票源补全**，而不是把 quorum 阈值调回 1。
    //
    // - `no-answer`/超时（无票）**不算**"全部真失败"（那只看 rcode∉{0,3}），
    //   所以在升级之后仍然可能是 SERVFAIL —— 但此时我们已问遍所有启用上游，
    //   SERVFAIL 是诚实的结论；
    // - 上限 `extra_waves`：每个波次最多 `max_parallel_upstreams` 条，
    //   最坏额外延迟 ≈ 波次数 × timeout_ms（默认 2×1500ms），且只在"全部 no-answer"
    //   这种本就无解的输入上才会走满。
    let mut extra_waves = 0usize;
    let extra_limit = if single_mode { 0 } else { 2 };
    // >>> PATCH242A P0-1 extra-waves BEGIN
    // **2.1.42（P0-1）**：触发条件从"**一张有效票都没有**"改为"**负票还没凑齐
    // quorum** 且没有完整正向答案"—— 否则首波只回 1 张 NXDOMAIN 时永远不会补查。
    while extra_waves < extra_limit
        && !results.is_empty()
        && results
            .iter()
            .all(|r| r.answers.is_empty() && r.cnames.is_empty())
        && need_more_votes(&results)
    {
        // <<< PATCH242A P0-1 extra-waves END
        let queried: std::collections::HashSet<&str> =
            results.iter().map(|r| r.up_name.as_str()).collect();
        let wave: Vec<UpstreamCfg> = ups
            .iter()
            .filter(|u| !queried.contains(u.id.as_str()))
            .take(max_parallel)
            .cloned()
            .collect();
        if wave.is_empty() {
            break;
        }
        extra_waves += 1;
        trace_msgs.push(format!(
            "首选波全部无票 → 补查第 {extra_waves} 波上游（防误报 SERVFAIL）"
        ));
        let more = querier.query_parallel(&wave, &d, &qtype, depth).await;
        results.extend(more);
    }
    (results, trace_msgs, extra_waves)
}

impl Resolver {
    /// 公开解析入口。
    pub async fn resolve(
        self: Arc<Self>,
        domain: &str,
        qtype: &str,
        opts: ResolveOpts,
    ) -> ResolveResult {
        self.resolve_inner(domain, qtype, opts, UpstreamMode::Multi)
            .await
    }

    /// 预取单上游刷新入口（优化项 9）：与 [`Resolver::resolve`] 同一条流水线，
    /// 但上游选择被限制为 **1 个**（`eff_lat/max(1,weight)` 最低且未熔断打开），
    /// 不启用后备波、失败不计入数据面 `circuit_fails`（与探针解耦同口径）。
    pub async fn resolve_prefetch(
        self: Arc<Self>,
        domain: &str,
        qtype: &str,
        mut opts: ResolveOpts,
    ) -> ResolveResult {
        // **2.1.21（DEF-220-01/11）**：预取续期的目标 TTL 上限 = `prefetch_target`。
        // 这是该配置键**唯一**的语义读取点（`/api/config` 只做回显），因此它
        // 不再是死字段；语义在 README 与 `main.rs::apply_cfg` 里逐字文档化。
        if opts.ttl_cap.is_none() {
            opts.ttl_cap = Some(self.cfg.read().prefetch_target);
        }
        self.resolve_inner(domain, qtype, opts, UpstreamMode::Single)
            .await
    }

    async fn resolve_inner(
        self: Arc<Self>,
        domain: &str,
        qtype: &str,
        opts: ResolveOpts,
        mode: UpstreamMode,
    ) -> ResolveResult {
        let d = normalize(domain);
        let qtype = qtype.to_ascii_uppercase();
        // trace 门禁：非人工查询（数据面）完全不构造 trace。
        let trace_on = opts.trace;
        // 数据面（silent/counted 语义）与手工查询共用；`expect` 禁止 → 直接构造。
        let mut trace = TraceSink::new(trace_on);
        if d.is_empty() {
            // **[历史归因]** 根(".")/空域名查询：不回 NXDOMAIN，按 FORMERR(rcode=1) 处理（对齐 Python）。
            // 同样受 trace 门控（关闭时字段为空 Vec，语义/形状不变）。
            if trace.is_on() {
                trace.push_str("warn", "根/空域名 → FORMERR");
            }
            return ResolveResult {
                domain: d,
                qtype,
                rcode: 1,
                empty: true,
                latency: 0.0,
                trace: trace.into_vec(),
                // **2.1.18（修复项 11）**：本地判定也要有可读来源 —— 日志「上游解析」列
                // 此前对这些早退路径显示 `?`（用户实测：AAAA / other 类型满屏 `?`）。
                up_name: "本地判定（空/根域名）".to_string(),
                ..Default::default()
            };
        }
        // **[历史归因]** M2 FORMERR 预检：逐标签 >63 或线格式总长 >255 → rcode=1（对齐 Python）。
        if label_invalid(&d) {
            trace.push_with(|| TraceEvent::new("warn", "域名标签非法(>63/>255) → FORMERR"));
            trace.push_with(|| {
                TraceEvent::new("eng", crate::resolve::fmt_text("FORMERR ", &d, " ", &qtype))
            });
            return ResolveResult {
                domain: d,
                qtype,
                rcode: 1,
                empty: true,
                latency: 0.0,
                trace: trace.into_vec(),
                up_name: "本地判定（域名非法）".to_string(),
                ..Default::default()
            };
        }
        // P0-4 预检：**不受支持的 qtype → NOTIMP(4)**，绝不发上游。
        //
        // 单一来源 = `ebpdns_proto::constants::SUPPORTED_QTYPES`（数据面 `dns.rs` 同一判据）。
        // 旧实现 `helpers::qtype_code` 的 `_ => TYPE_A` 兜底把 `AXFR(252)` / `ANY(255)` /
        // `TYPE0` / `TYPE65280` 全部变成一条 **A 查询**发往上游，客户端因此拿到 A 记录
        // （P0-4 实测）。这里与数据面双保险：即使有别的调用方（如 `/api/query`）绕过
        // 报文字段校验，也不会产生「未知类型 → A」的查询。
        if crate::helpers::qtype_code(&qtype).is_none() {
            trace.push_with(|| TraceEvent::new("warn", "不支持的 qtype → NOTIMP"));
            return ResolveResult {
                domain: d,
                qtype,
                rcode: RCODE_NOTIMP,
                empty: true,
                latency: 0.0,
                trace: trace.into_vec(),
                // 不受支持的 qtype（AXFR/ANY/TYPE0/…）：**没发上游**，来源必须可读。
                up_name: "本地判定（不支持的 qtype）".to_string(),
                ..Default::default()
            };
        }
        // ---- **2.1.18（修复项 9）：本处不再自增 `total`** ----
        //
        // 旧实现（2.1.17 及以前）在解析**入口**`if opts.counted { count_query("resolve") }`
        // —— 于是 `total` 的含义是"进入解析入口的查询数"。这与 `counters.client_rcode`
        // （"真的为客户端构造出应答的数"，由数据面唯一出口 `dns.rs::log_and_count` 打点）
        // 之间存在**不可观测的差额**：
        //   - 控制面 `POST /api/query`（`counted=false`，靠本分支门禁才不计入）；
        //   - 启动预热（`crates/ebpdns/src/main.rs` 的 `counted: true`）；
        //   - 任何"进了 resolve() 但没有客户端应答"的内部调用。
        // 部署实例实测 `counters.total = Σ counters.client_rcode + 256`，正是这个差额。
        //
        // 现在 `total` **只有一个**自增点：数据面唯一出口
        // [`ebpdns_server`] 的 `note_data_plane_outcome`（与 `client_rcode` 同分支），
        // 因此：
        //   - `counters.total == Σ counters.client_rcode` **恒成立**（硬等式）；
        //   - 出口登记但无可发送报文的查询落到 `counters.no_response_total`（可对账）；
        //   - 控制面/预热/内部子解析**天然**不污染 `total`（它们不经过那个出口）。
        //
        // `ResolveOpts::counted` 字段**保留**（调用方语义标记 + 兼容既有字面量），
        // 但它不再驱动任何计数 —— 计数归属由"是否经过数据面出口"决定。
        let _ = opts.counted;
        trace.push_with(|| {
            TraceEvent::new("client", crate::resolve::fmt_text("入口 ", &d, " ", &qtype))
        });
        let t0 = self.clock.monotonic_ms();
        // 入口记规则代际（gen 写回门禁）。
        let gen_at_entry = self.rule_gen();
        let now = self.clock.epoch();

        // ---- IPv6 关闭 / prefer_ipv4：AAAA 本地策略 ----
        // 单次读锁同时取开关（policy 判定统一走 aaaa_policy_cached）。
        let (prefer_ipv4, serve_stale, stale_ttl) = {
            let c = self.cfg.read();
            (c.prefer_ipv4, c.serve_stale, c.stale_ttl)
        };
        // >>> PATCH242A P1-1 slow-path-policy BEGIN
        // **2.1.42（P1-1）**：与数据面快路径 `answer.rs::answer_fast_ex` 调用**同一个**
        // 判定函数。此前这里的内联判定只在慢路径生效，快路径命中缓存时完全绕过。
        match self.aaaa_policy_cached(&d, &qtype, now) {
            Some(AaaaPolicy::Ipv6Disabled) => {
                return ResolveResult {
                    domain: d,
                    qtype,
                    rcode: RCODE_NOERROR,
                    empty: true,
                    latency: self.clock.monotonic_ms() - t0,
                    trace: trace.into_vec(),
                    up_name: "本地判定（IPv6 已关闭）".to_string(),
                    reason: Some(REASON_POLICY_FILTERED.to_string()),
                    ..Default::default()
                };
            }
            Some(AaaaPolicy::PreferIpv4) => {
                trace.push_str("warn", "双栈域名(有 A) → AAAA 屏蔽");
                return ResolveResult {
                    domain: d,
                    qtype,
                    rcode: RCODE_NOERROR,
                    empty: true,
                    latency: self.clock.monotonic_ms() - t0,
                    trace: trace.into_vec(),
                    up_name: "本地判定（prefer_ipv4 屏蔽 AAAA）".to_string(),
                    reason: Some(REASON_POLICY_FILTERED.to_string()),
                    ..Default::default()
                };
            }
            // A 未确认：下面 probe_a_record 会先探 A。
            Some(AaaaPolicy::PreferIpv4Probe) => {}
            None => {}
        }
        // <<< PATCH242A P1-1 slow-path-policy END

        // ---- prefer_ipv4：A 不在缓存时先探测 A 记录（快路径会交回慢路径）----
        if qtype == "AAAA"
            && prefer_ipv4
            && self
                .probe_a_record(&d, gen_at_entry, &mut trace, mode)
                .await
        {
            trace.push_str("warn", "双栈域名(有 A) → AAAA 屏蔽");
            return ResolveResult {
                domain: d,
                qtype,
                rcode: RCODE_NOERROR,
                empty: true,
                latency: self.clock.monotonic_ms() - t0,
                trace: trace.into_vec(),
                up_name: "本地判定（prefer_ipv4 屏蔽 AAAA）".to_string(),
                // **2.1.40**：同上（2.1.39 及以前该路径被数据面记成一次 miss）。
                reason: Some(REASON_POLICY_FILTERED.to_string()),
                ..Default::default()
            };
        }

        // ---- 缓存快路径 ----
        // `ckey` 推迟到真正需要访问缓存时才构造：AAAA+ipv6 关闭、prefer_ipv4 早退
        // 等路径上不再白付两次 `String` 分配。`d`/`qtype` 已归一化，故用
        // `ckey_normalized` 直接构造（语义与 `ckey` 完全一致）。
        let ckey = self.ckey_normalized(&d, &qtype);
        // P1-1：命中条目必须与**当前规则集指纹**一致——规则 CRUD / 导入 / 订阅增删改 /
        // `PUT /api/config` 的 rules 变动都会让指纹变化，此时旧答案（含 TTL 300s 的
        // 正向答案与负缓存）在**读取时**立即失效并顺带删除，无需人工 `/api/reset`。
        let gen_now = self.rule_gen();
        let stale_rule = |e: &ebpdns_cache::CacheEntry| e.rule_gen != gen_now;
        if !opts.force_refresh {
            // M5 serve_stale：必须先于 cache.get 查询——cache.get 会物理移除过期条目，
            // get_stale 才能在 stale_ttl 窗口内拿到旧数据（fresh 时 get_stale 返回 None 不影响）。
            //
            // **P1-2（2.1.14）**：**负缓存不走 serve-stale**。RFC 8767 的 stale 窗口
            // 是「上游故障时仍能给出**旧的正向**答案」的兜底；若把已过期的 NXDOMAIN /
            // NODATA 也继续直答，等于负缓存 TTL 永不生效 —— 实测配置
            // `neg_ttl_max=60` 却在 +195s（真实 +680s）仍以 0.08ms 直答，且
            // `/api/snapshot` 的该条目 `ttl` 恒为 60.0（原样回显写入时的 TTL）。
            // 负缓存过期即失效（删除并重新解析，成本 = 一次普通上游查询；`neg_ttl_max`
            // 已经把负 TTL 压到 ≤60s，不会造成上游压力）。
            if serve_stale {
                if let Some(entry) = self.cache.get_stale(&ckey, now, stale_ttl) {
                    if stale_rule(&entry) {
                        self.cache.delete(&ckey);
                        trace.push_str("rule", "规则集已变更 → 丢弃过期旧答案");
                    } else if Self::is_negative_entry(&entry) {
                        self.cache.delete(&ckey);
                        trace
                            .push_str("cache", "负缓存已过期 → 删除并重新解析（不走 serve-stale）");
                    } else {
                        trace.push_str("cache", "serve-stale: 过期窗口内返回旧数据");
                        self.trigger_stale_refresh(&d, &qtype);
                        return self.serve_stale_from_cache(&d, &qtype, entry, trace, t0);
                    }
                }
            }
            if let Some(entry) = self.cache.get(&ckey, now) {
                if stale_rule(&entry) {
                    self.cache.delete(&ckey);
                    trace.push_str("rule", "规则集已变更 → 旧答案缓存失效（P1-1）");
                } else {
                    return self.serve_from_cache(&d, &qtype, entry, trace, t0).await;
                }
            }
            // ---- RFC 8020 父域 NXDOMAIN 推断（2.1.12 优化项 ①）----
            //
            // 位置刻意在**答案缓存之后**（且只在 miss 时）：
            // - 缓存条目（含负缓存）**永远优先** → 2.1.11 已覆盖的"同名重复查询"路径
            //   逐位不变（`cache_direct` / `neg_hits` / `ttl_left` 口径不动，N4 门禁不受影响）；
            // - 本推导体只补"**每个名字只查一次**"的随机子域长尾（结构上不可能命中答案
            //   缓存），命中即零上游请求直答 NXDOMAIN；
            // - `force_refresh`（serve-stale 后台刷新 / 手工强制刷新）**不**走推断，
            //   与缓存旁路同口径。
            if let Some(hit) = self.rfc8020_lookup(&d) {
                // 规则优先于推断（block / forceIp 命中时交回下方正常链路，见函数注释）。
                if !self.rfc8020_rule_bypass(&d) {
                    return self.rfc8020_serve(&d, &qtype, hit, trace, t0);
                }
            }
        }

        trace.push_str("cache", "缓存未命中 → 解析引擎");
        // ---- 分流规则 ----
        // 规则命中信息（供数据面落 `level="rule"` 事件）：命中即填，随结果冒泡。
        let mut rule_hit: Option<RuleHit> = None;
        let matched = self.match_rule(&d);
        // allow 优先：命中即放行（跳过 block/group/forceIp），但仍要按 `allow` 计数 +
        // 落 `level="rule"` 事件（对齐 v1.9.162 resolver.py:855-861）。
        if let Some(r) = &matched {
            if r.action == Action::Allow {
                self.tel.inc_rule_kind(
                    ebpdns_rules::match_kind(&r.match_raw),
                    ebpdns_rules::action_key(r),
                );
                rule_hit = Some(RuleHit {
                    label: ebpdns_rules::rule_label(r),
                    msg: "白名单放行 → 正常解析".to_string(),
                    answer: String::new(),
                    upstream: "白名单".to_string(),
                });
            }
        }
        let rule = match matched {
            Some(r) if r.action == Action::Allow => None,
            other => other,
        };

        if let Some(r) = &rule {
            if r.action == Action::Block {
                // 计数全量（不受事件采样/`counted` 影响，对齐 v1.9.162 `tel.inc_rule("block")`）。
                self.tel.inc_rule_kind(
                    ebpdns_rules::match_kind(&r.match_raw),
                    ebpdns_rules::action_key(r),
                );
                rule_hit = Some(RuleHit {
                    label: ebpdns_rules::rule_label(r),
                    msg: "规则屏蔽 → NXDOMAIN".to_string(),
                    answer: String::new(),
                    upstream: "规则屏蔽".to_string(),
                });
                trace.push_with(|| {
                    TraceEvent::new(
                        "rule",
                        crate::resolve::fmt_text("规则屏蔽 ", &r.match_raw, " → NXDOMAIN", ""),
                    )
                });
                return ResolveResult {
                    domain: d,
                    qtype,
                    rcode: RCODE_NXDOMAIN,
                    latency: self.clock.monotonic_ms() - t0,
                    trace: trace.into_vec(),
                    rule: rule_hit,
                    ..Default::default()
                };
            }
        }

        let all_up: Vec<UpstreamCfg> = self
            .cfg
            .read()
            .upstreams
            .iter()
            .filter(|u| u.enabled)
            .cloned()
            .collect();
        let mut ups = all_up.clone();
        if let Some(r) = &rule {
            if r.action == Action::Group {
                // 分流计数：domestic 组 vs 其它（含 global）——对齐 v1.9.162
                // `tel.inc_rule("domestic" if g == "domestic" else "global")`。
                let g_disp = r.group.as_deref().unwrap_or("global");
                self.tel.inc_rule_kind(
                    ebpdns_rules::match_kind(&r.match_raw),
                    ebpdns_rules::action_key(r),
                );
                rule_hit = Some(RuleHit {
                    label: ebpdns_rules::rule_label(r),
                    msg: format!("分流规则 → 「{g_disp}」组"),
                    answer: String::new(),
                    upstream: "分流规则".to_string(),
                });
                if let Some(g) = &r.group {
                    let filtered: Vec<UpstreamCfg> = all_up
                        .iter()
                        .filter(|u| u.group.as_deref() == Some(g.as_str()))
                        .cloned()
                        .collect();
                    if !filtered.is_empty() {
                        ups = filtered;
                    }
                }
            }
        }
        if let Some(r) = &rule {
            if r.action == Action::ForceIp {
                self.tel.inc_rule_kind(
                    ebpdns_rules::match_kind(&r.match_raw),
                    ebpdns_rules::action_key(r),
                );
                return self.synthesize_forceip(
                    &d,
                    &qtype,
                    r,
                    &ckey,
                    trace,
                    t0,
                    gen_at_entry,
                    false,
                    // **2.1.21（DEF-220-01/11）**：预取续期的目标 TTL 上限。
                    opts.ttl_cap,
                );
            }
        }
        if ups.is_empty() {
            let mut res = ResolveResult::error(&d, &qtype, "no-upstream", trace.into_vec())
                .with_latency(self.clock.monotonic_ms() - t0)
                // **2.1.15（P1）**：结构化 SERVFAIL 归因（配置/规则下无任何可发上游）。
                .mark_servfail(ServfailReason::NoUpstream);
            res.rule = rule_hit;
            // 事件 `upstream` 列：本地判定未发上游（对齐 v1.9.162 resolver.py:928）。
            res.up_name = "无上游".to_string();
            return res;
        }

        // ---- 上游选择：eff_lat/weight 排序（5s 缓存）+ 熔断排除 + fallback 语义 ----
        // **[历史归因]** 对齐 Python resolve:931-967：fallback=true 时先并发最快 max_parallel_upstreams 个，
        // 其余为失败回退备份；fallback=false 时只取排序后最快的 1 个（失败即 SERVFAIL）。
        // 注：`fallback=false` 时 `select_upstreams` 直接 `take(1)`，`max_parallel_upstreams`
        // **[历史归因]** 完全不参与 —— 与 Python `ups = ups[:1]` 一致（见 lib.rs 单测）。
        // 优化项 9：预取（`UpstreamMode::Single`）固定只取 1 个上游且**不产生后备波**。
        let (primary, backup) = if mode.is_single() {
            (self.query_targets(&ups, true), Vec::new())
        } else {
            self.select_upstreams(&ups)
        };
        if primary.is_empty() {
            let mut res = ResolveResult::error(&d, &qtype, "no-upstream", trace.into_vec())
                .with_latency(self.clock.monotonic_ms() - t0)
                // **2.1.15（P1）**：同上（候选集为空：全部禁用/被组过滤）。
                .mark_servfail(ServfailReason::NoUpstream);
            res.rule = rule_hit;
            res.up_name = "无上游".to_string();
            return res;
        }
        trace.push_with(|| {
            TraceEvent::new(
                "eng",
                crate::resolve::fmt_upstream_choice(&primary, &backup),
            )
        });
        // >>> PATCH242A P0-1 resolve-quorum-target BEGIN
        // **2.1.42（P0-1）**：负票 quorum 的**候选分母**在派发前一次算定：
        // - 预取（Single）只问 1 个上游 ⇒ 合法地取 1（保持 P2-B 语义）；
        // - 数据面：`clamp(nxdomain_quorum, 1, 启用上游数)`。用"启用上游总数"
        //   而不是某一波的结果数，避免"首票 abort 后分母塌缩"。
        // >>> 245 P1-1 quorum-target BEGIN
        // **2.1.45（P1-1）**：票数阈值**只取配置值**，不再按"启用上游数"钳制。
        //
        // REV247 P1-3 的反例：单上游（或熔断/组过滤后只剩 1 个可用）时
        // `min(q, 可用数)` 把 q=2/3/4 塌缩成 1 ⇒ 一张 NXDOMAIN 就写负缓存并登记
        // RFC 8020，整棵子树随后本地判负。quorum=N 的语义必须是"凑满 N 张负票，
        // 否则 SERVFAIL"（fail-closed）；只有 1 个上游的部署应显式配 q=1。
        // 预取（Single）仍固定 1：它本来就只问 1 个上游，且禁止写负缓存。
        let quorum_target = if mode.is_single() {
            1
        } else {
            self.cfg.read().nxdomain_quorum.max(1)
        };
        // <<< 245 P1-1 quorum-target END
        // <<< PATCH242A P0-1 resolve-quorum-target END
        // 先把 querier Arc 克隆出来再 await，持同步锁不 await。
        let querier: Arc<dyn ParallelQuerier> = self.querier.read().clone();
        // ---- **2.1.16（功能 2）：在途查询合并（single-flight）** ----
        //
        // 只合并"最贵且幂等"的**上游扇出段**（primary 波 + fallback 波 + 补查波）。
        // 合并后 `finish_resolve` 仍然**逐调用方**执行，因此：
        // - 负缓存写入 / serve-stale / 规则复查 / 计数语义**逐位不变**（P2-B 的
        //   `mode.is_single()` 预取禁写负缓存等门禁照旧按调用方判定）；
        // - follower 拿到的是**同一份上游结果**，其 `latency` 由各自的 `t0` 计算
        //  （即包含"排队等 leader"的时间），因此延迟口径诚实、不会把别人的等待
        //   算成上游 RTT。
        //
        // `cfg.single_flight == false` 时**完全不进**这张表（逐位退回 2.1.15 行为）。
        let sf_on = self.cfg.read().single_flight;
        let depth = opts.depth;
        let single_mode = mode.is_single();
        let max_par = self.cfg.read().max_parallel_upstreams.max(1);
        let fetch = || {
            let querier = querier.clone();
            let primary = primary.clone();
            let backup = backup.clone();
            let ups_all = ups.clone();
            let d = d.clone();
            let qtype = qtype.clone();
            async move {
                fetch_upstreams(
                    querier,
                    primary,
                    backup,
                    ups_all,
                    d,
                    qtype,
                    depth,
                    single_mode,
                    max_par,
                    // >>> PATCH242A P0-1 fetch-arg BEGIN
                    quorum_target,
                    // <<< PATCH242A P0-1 fetch-arg END
                )
                .await
            }
        };
        let (results, wave_trace, extra_waves, was_leader) = if sf_on {
            // **2.1.43-B（P2-3）**：键必须带 `UpstreamMode` —— 预取与数据面不得共享扇出。
            let k = single_flight_key(&ckey, mode);
            let done = self.single_flight.clone();
            let (v, leader) = done.run_tagged(k, fetch).await;
            (v.0, v.1, v.2, leader)
        } else {
            let v = fetch().await;
            // 未启用合并 ⇒ 本调用**必然**自己发了上游 ⇒ 它负责记账。
            (v.0, v.1, v.2, true)
        };
        // **2.1.21 第 2 轮 + 2.1.23（DEF-221-04 修复：业务账按"物理上游应答"记一次）**
        //
        // 为什么必须在**这里**：上面那段（`fetch` 闭包 + single-flight）**包含所有
        // `query_parallel` 调用**，因此它之后的这一行是"这次物理上游扇出刚刚完成"的
        // **唯一**位置。`finish_resolve` 是逐调用方的，把记账放那里会被在途合并放大
        // （审计实测：5 并发同名 ⇒ 1 次 wire 查询、`dns_ok +5`）。
        //
        // **2.1.23 补完**：把记账点挪到 single-flight 之后还不够 —— 那一行仍然
        // **逐调用方**执行，follower 也会记一遍。现在用 `run_tagged` 拿到的
        // `was_leader` 精确判定："只有**真的执行了上游扇出**的调用者记账"
        // ⇒ N 路并发同名 = 1 次 wire 查询 = **`dns_ok` 恰好 +1**。
        //
        // 预取链路（`UpstreamMode::Single`）不记：它是后台维护流量，不是客户端业务；
        // 与"探针失败不计入熔断"（2.1.15 优化项 9）同口径。
        if !mode.is_single() && was_leader {
            self.record_dns_verdicts(&results);
        }

        for m in wave_trace {
            trace.push_str("eng", &m);
        }
        if extra_waves > 0 {
            // **2.1.45（P1-1）**：补查波次只进 trace 与诊断，**不计入** quorum 候选分母。
            trace.push_str(
                "eng",
                &format!("补查波次 {extra_waves}（不计入 quorum 候选分母）"),
            );
        }

        // fallback 波（M4）与 F-NX 补查波都已在 [`fetch_upstreams`] 内完成
        // （2.1.16 功能 2：整段上游扇出被 single-flight 合并，见上方 `fetch` 闭包）。
        // >>> 245 P1-1 candidates BEGIN
        // **2.1.45（P1-1）**：候选分母 = **本轮实际派发过的上游数（按 `up_name` 去重）**。
        //
        // 旧实现 `primary.len() + backup.len() + extra_waves` 把**补查波次**（每波最多
        // `max_parallel_upstreams` 条）当成上游条数 ⇒ q>=4 时 2 个波次就贡献 2 个候选，
        // 3 张负票即可通过 `nxq = clamp(q, 1, candidates)` 确认 NXDOMAIN 并登记 RFC 8020
        // （REV247 P1-2 的静态反例）。现在只数**真的被派发过的物理上游**：结果集每条都带
        // `up_name`，去重后即"投过票/被问过的上游"，补查波次因此**不可能**抬高分母。
        let candidates = {
            let mut seen = std::collections::HashSet::with_capacity(results.len());
            for r in &results {
                seen.insert(r.up_name.as_str());
            }
            seen.len().max(1)
        };
        // <<< 245 P1-1 candidates END
        let mut res = self
            .finish_resolve(
                &d,
                &qtype,
                &ckey,
                results,
                rule,
                opts.depth,
                t0,
                gen_at_entry,
                trace,
                mode,
                candidates,
                // >>> PATCH242A P0-1 finish-arg BEGIN
                quorum_target,
                // <<< PATCH242A P0-1 finish-arg END
                // P2-B：预取链路（Single）**禁止写负缓存**，见 finish_resolve 内注释。
                mode.is_single(),
                // 2.1.21（DEF-220-01/11）：预取续期目标 TTL 上限贯穿整条解析链。
                opts.ttl_cap,
            )
            .await;

        // allow / group 规则命中信息随结果冒泡（level="rule" 事件；计数已在上方全量完成）。
        res.rule = rule_hit;
        res
    }

    /// 缓存命中服务（含 match_rule 复查：block/forceIp 即时生效）。
    async fn serve_from_cache(
        &self,
        d: &str,
        qtype: &str,
        entry: CacheEntry,
        mut trace: TraceSink,
        t0: f64,
    ) -> ResolveResult {
        if let Some(r) = self.match_rule(d) {
            if r.action == Action::Block {
                self.tel.inc_rule_kind(
                    ebpdns_rules::match_kind(&r.match_raw),
                    ebpdns_rules::action_key(&r),
                );
                trace.push_str("rule", "缓存命中复查: 屏蔽 → NXDOMAIN");
                return ResolveResult {
                    domain: d.into(),
                    qtype: qtype.into(),
                    rcode: RCODE_NXDOMAIN,
                    latency: self.clock.monotonic_ms() - t0,
                    trace: trace.into_vec(),
                    rule: Some(RuleHit {
                        label: ebpdns_rules::rule_label(&r),
                        msg: "规则屏蔽(缓存命中复查) → NXDOMAIN".to_string(),
                        answer: String::new(),
                        upstream: "规则屏蔽".to_string(),
                    }),
                    ..Default::default()
                };
            }
            if r.action == Action::ForceIp {
                self.tel.inc_rule_kind(
                    ebpdns_rules::match_kind(&r.match_raw),
                    ebpdns_rules::action_key(&r),
                );
                // 缓存复查路径没有 `opts`（`serve_from_cache` 的签名）⇒ 不额外收紧；
                // 真正需要 target 上限的是**预取回填**（`resolve_prefetch`）。
                return self.synthesize_forceip(
                    d,
                    qtype,
                    &r,
                    &self.ckey_normalized(d, qtype),
                    trace,
                    t0,
                    self.rule_gen(),
                    true,
                    None,
                );
            }
        }
        let now = self.clock.epoch();
        let ttl_left = (entry.expires_at - now).clamp(0.0, 2_147_483_647.0);
        let lat = self.clock.monotonic_ms() - t0;
        if entry.rcode == RCODE_NXDOMAIN {
            trace.push_with(|| {
                TraceEvent::new("cache", format!("缓存命中 NXDOMAIN, 剩余 {ttl_left:.0}s"))
            });
            return ResolveResult {
                domain: d.into(),
                qtype: qtype.into(),
                rcode: RCODE_NXDOMAIN,
                hit: true,
                latency: lat,
                ttl_left,
                trace: trace.into_vec(),
                // 事件 `upstream` 列：缓存直答（对齐 v1.9.162「缓存直答 NXDOMAIN」）。
                up_name: "缓存直答".to_string(),
                ..Default::default()
            };
        }
        if entry.answers.is_empty() {
            trace.push_with(|| {
                TraceEvent::new("cache", format!("缓存命中 NODATA, 剩余 {ttl_left:.0}s"))
            });
            return ResolveResult {
                domain: d.into(),
                qtype: qtype.into(),
                rcode: RCODE_NOERROR,
                hit: true,
                empty: true,
                latency: lat,
                ttl_left,
                trace: trace.into_vec(),
                up_name: "缓存直答".to_string(),
                ..Default::default()
            };
        }
        let answers: Vec<ResolveAnswer> = entry
            .answers
            .iter()
            .map(|a| ResolveAnswer {
                value: a.value.clone(),
                // **[历史归因]** 命中服务按剩余 TTL 衰减下推（对齐 Python answer_fast:1494）。
                ttl: ttl_left,
                rtype: a.rtype,
                // 透传缓存中的 owner 名（CNAME 链逐跳 owner）。
                name: a.name.clone(),
            })
            .collect();
        self.schedule_prefetch(d, qtype, ttl_left);
        trace.push_with(|| TraceEvent::new("cache", format!("缓存命中 → {}", entry.chosen)));
        ResolveResult {
            domain: d.into(),
            qtype: qtype.into(),
            chosen: entry.chosen,
            answers,
            rcode: RCODE_NOERROR,
            hit: true,
            latency: lat,
            ttl_left,
            trace: trace.into_vec(),
            // 事件 `upstream` 列：缓存直答（对齐 v1.9.162 resolver.py:791 的
            // 「用户态缓存直答」/「缓存直答」）。
            up_name: "缓存直答".to_string(),
            ..Default::default()
        }
    }

    /// 触发 stale 后台刷新（去重、非阻塞）：在途集合无该 key 才 spawn。
    ///
    /// 分配优化：先在读锁内以 `&str` 比对（`HashSet<String>` 可用 `&str` 查询），
    /// 仅当确实需要插入时才 `format!` + 克隆（去重命中路径 **0 次 String 分配**）。
    pub(crate) fn trigger_stale_refresh(self: &Arc<Self>, d: &str, qtype: &str) {
        {
            let g = self.stale_inflight.lock();
            if g.contains(&format!("{d}|{qtype}")) {
                return; // 已有在途刷新，去重（此分支仅有 1 次临时分配）。
            }
        }
        let key = format!("{d}|{qtype}");
        {
            let mut g = self.stale_inflight.lock();
            // 二次确认（持写锁）：并发下另一个线程可能刚落座同一 key。
            if !g.insert(key.clone()) {
                return;
            }
        }
        let slf = self.clone();
        let d = d.to_string();
        let qtype = qtype.to_string();
        tokio::spawn(async move {
            // 任务结束（无论成功失败）清理在途标记。
            let _guard = crate::StaleGuard {
                slf: slf.clone(),
                key: key.clone(),
            };
            if slf.shutdown.is_stopped() {
                return;
            }
            let _ = slf
                .resolve(
                    &d,
                    &qtype,
                    ResolveOpts {
                        force_refresh: true,
                        silent: true,
                        counted: false,
                        trace: false,
                        ..Default::default()
                    },
                )
                .await;
        });
    }

    /// serve-stale 应答：与命中服务一致，但 TTL=0（数据已过期）。
    ///
    /// 入口先做 block 规则复查（对齐 v1.9.162 `resolver.py:802-814`「过期缓存复查」）：
    /// 过期兜底不得绕过屏蔽规则，同时按 `block` 类别计数 + 留下 `level="rule"` 事件。
    fn serve_stale_from_cache(
        &self,
        d: &str,
        qtype: &str,
        entry: CacheEntry,
        mut trace: TraceSink,
        t0: f64,
    ) -> ResolveResult {
        if let Some(r) = self.match_rule(d) {
            if r.action == Action::Block {
                self.tel.inc_rule_kind(
                    ebpdns_rules::match_kind(&r.match_raw),
                    ebpdns_rules::action_key(&r),
                );
                trace.push_str("rule", "过期缓存复查: 屏蔽 → NXDOMAIN");
                return ResolveResult {
                    domain: d.into(),
                    qtype: qtype.into(),
                    rcode: RCODE_NXDOMAIN,
                    latency: self.clock.monotonic_ms() - t0,
                    trace: trace.into_vec(),
                    rule: Some(RuleHit {
                        label: ebpdns_rules::rule_label(&r),
                        msg: "规则屏蔽(过期缓存复查) → NXDOMAIN".to_string(),
                        answer: String::new(),
                        upstream: "规则屏蔽".to_string(),
                    }),
                    ..Default::default()
                };
            }
        }
        let lat = self.clock.monotonic_ms() - t0;
        // **2.1.19（F-06 修复：`counters.stale_served` 恒 0）**：这里是**唯一**的
        // "过期缓存仍然直答"出口 ⇒ 计数必须打在这里。
        //
        // 此前 `stale_served` 只能经 `Telemetry::inc`/`inc_n` 自增，而**生产零调用点**
        // （只有 `telemetry.rs` 内部的 `inc_n` 分支），于是 `/api/status.counters
        // .stale_served` 与 `/metrics` 恒为 0；而 `/api/query` 的 trace 明明显示
        // `serve-stale: 过期窗口内返回旧数据` —— **指标与运行态说谎**。
        //
        // 位置在"屏蔽复查"之后：屏蔽命中会提前 return（那条路径不是 stale 直答），
        // 因此本行恰好覆盖"真的把过期数据发给了客户端"的次数。
        self.tel.inc("stale_served");
        if entry.rcode == RCODE_NXDOMAIN {
            return ResolveResult {
                domain: d.into(),
                qtype: qtype.into(),
                rcode: RCODE_NXDOMAIN,
                hit: true,
                latency: lat,
                ttl_left: 0.0,
                trace: trace.into_vec(),
                // 事件 `upstream` 列：serve-stale（对齐 v1.9.162「serve-stale NXDOMAIN」）。
                up_name: "serve-stale".to_string(),
                ..Default::default()
            };
        }
        if entry.answers.is_empty() {
            return ResolveResult {
                domain: d.into(),
                qtype: qtype.into(),
                rcode: RCODE_NOERROR,
                hit: true,
                empty: true,
                latency: lat,
                ttl_left: 0.0,
                trace: trace.into_vec(),
                up_name: "serve-stale".to_string(),
                ..Default::default()
            };
        }
        let answers: Vec<ResolveAnswer> = entry
            .answers
            .iter()
            .map(|a| ResolveAnswer {
                value: a.value.clone(),
                ttl: 0.0,
                rtype: a.rtype,
                // **[历史归因]** 对齐 Python dict(a, ttl=0)：保留 owner 名。
                name: a.name.clone(),
            })
            .collect();
        trace.push_with(|| TraceEvent::new("cache", format!("serve-stale → {}", entry.chosen)));
        ResolveResult {
            domain: d.into(),
            qtype: qtype.into(),
            chosen: entry.chosen,
            answers,
            rcode: RCODE_NOERROR,
            hit: true,
            latency: lat,
            ttl_left: 0.0,
            trace: trace.into_vec(),
            up_name: "serve-stale".to_string(),
            ..Default::default()
        }
    }

    /// forceIp 本地合成应答。
    ///
    /// `from_cache_recheck=true` 表示来自「缓存命中复查」分支（对齐 v1.9.162
    /// `resolver.py:721-753` 的文案差异）；两者的 `rule_hits.forceIp` 计数相同
    /// （调用方已自增，避免重复计数）。
    #[allow(clippy::too_many_arguments)]
    fn synthesize_forceip(
        &self,
        d: &str,
        qtype: &str,
        rule: &Rule,
        ckey: &CacheKey,
        mut trace: TraceSink,
        t0: f64,
        gen: u64,
        from_cache_recheck: bool,
        // **2.1.21（DEF-220-01/11）**：续期回填的 TTL 上限（`prefetch_target`）。
        ttl_cap: Option<f64>,
    ) -> ResolveResult {
        let ip = rule.ip.map(|i| i.to_string()).unwrap_or_default();

        let lat = self.clock.monotonic_ms() - t0;
        // P0-4：不支持的 qtype 不得合成 forceIp 应答（resolve_inner 已拒为 NOTIMP，
        // 这里是类型完备的防御分支，不构成「未知类型 → A」路径）。
        let Some(qcode) = qtype_code(qtype) else {
            return ResolveResult {
                domain: d.into(),
                qtype: qtype.into(),
                rcode: RCODE_NOTIMP,
                empty: true,
                latency: lat,
                trace: trace.into_vec(),
                ..Default::default()
            };
        };
        let rtype = guess_type(&ip, qcode);
        let label = ebpdns_rules::rule_label(rule);
        if rtype != qcode {
            let cfg = self.cfg.read();
            let base = clamp_ttl(cfg.ttl.clamp(1, 60), cfg.ttl_min, cfg.ttl_max);
            drop(cfg);
            // P1-2：本路径也是负缓存写入（NODATA）→ 同样过 `neg_ttl_max` 硬上限。
            let neg = self.neg_ttl_cap(base);
            trace.push_with(|| {
                TraceEvent::new("rule", crate::resolve::fmt_forceip_mismatch(&ip, qtype))
            });
            self.put_negative(ckey, d, qtype, RCODE_NOERROR, neg, Some(gen));
            return ResolveResult {
                domain: d.into(),
                qtype: qtype.into(),
                rcode: RCODE_NOERROR,
                empty: true,
                latency: lat,
                trace: trace.into_vec(),
                ttl_left: neg as f64,
                rule: Some(RuleHit {
                    label,
                    msg: if from_cache_recheck {
                        "forceIp 类型不匹配(缓存命中复查) → NODATA".to_string()
                    } else {
                        "forceIp 类型不匹配 → NODATA".to_string()
                    },
                    answer: String::new(),
                    upstream: "分流规则".to_string(),
                }),
                ..Default::default()
            };
        }
        let cfg = self.cfg.read();
        let rttl = clamp_ttl(cfg.ttl, cfg.ttl_min, cfg.ttl_max);
        drop(cfg);
        let ans = vec![ResolveAnswer {
            value: ip.clone(),
            ttl: rttl as f64,
            rtype,
            name: None,
        }];
        // 克隆一份给缓存（原序答案需要随结果返回）。
        self.fill_cache_capped(ckey, d, qtype, ans.clone(), Some(gen), ttl_cap);

        trace.push_with(|| TraceEvent::new("rule", format!("强制 IP {ip} (TTL {rttl}s)")));
        ResolveResult {
            domain: d.into(),
            qtype: qtype.into(),
            chosen: ip.clone(),
            answers: ans,
            rcode: RCODE_NOERROR,
            latency: lat,
            ttl_left: rttl as f64,
            trace: trace.into_vec(),
            rule: Some(RuleHit {
                label,
                msg: if from_cache_recheck {
                    format!("强制 IP(缓存命中复查) → {ip}")
                } else {
                    format!("分流规则 → {ip}")
                },
                answer: ip,
                upstream: "分流规则".to_string(),
            }),
            ..Default::default()
        }
    }

    /// 写负缓存（NXDOMAIN / NODATA）。
    ///
    /// **2.1.45（P1-3）**：写入前校验 `gen`（resolve 入口的规则代）与当前
    /// `rule_gen()` 一致；不一致 ⇒ **丢弃**并计 `stale_gen_dropped`。
    ///
    /// 缺陷（REV247 P1-4 / 登记册 B P2-1）：旧实现用 `self.rule_gen()` 盖章，于是
    /// "上游 RTT 期间规则重建"的在途查询会把**旧答案盖成新代际**，快路径看起来是
    /// 新代 ⇒ 2.1.42 P1-1 的 rule_gen 门禁被绕过。现在：章 = 入口代，
    /// 入口代 ≠ 当前代 ⇒ 一个字都不写。
    pub(crate) fn put_negative(
        &self,
        ckey: &CacheKey,
        d: &str,
        qtype: &str,
        rcode: u8,
        ttl: u32,
        gen: Option<u64>,
    ) {
        let cur = self.rule_gen();
        let stamp = gen.unwrap_or(cur);
        if stamp != cur {
            self.note_stale_gen_dropped(1);
            tracing::debug!(
                domain = d,
                qtype = qtype,
                entry_gen = stamp,
                rule_gen = cur,
                "负缓存写入被拒：规则代已变化（在途旧答案不得盖新代际）"
            );
            return;
        }
        let now = self.clock.epoch();
        let entry = CacheEntry {
            domain: d.into(),
            qtype: qtype.into(),
            answers: Vec::new(),
            chosen: String::new(),
            ttl: ttl as f64,
            rcode,
            expires_at: now + ttl as f64,
            // P1-1：条目盖章（规则集指纹）→ 规则变更后命中路径立即失效。
            rule_gen: stamp,

            seq: 0,
        };
        self.cache.put(ckey.clone(), entry, now);
    }

    /// 该缓存条目是否为**负应答**（NXDOMAIN / NODATA）。
    ///
    /// P1-2（2.1.14）：判据与数据面 `ebpdns-server::dns::is_negative_answer` **同口径**
    /// （rcode==3 或答案段为空）。用于「负缓存不得走 serve-stale」的门禁（见 `resolve_inner`）。
    fn is_negative_entry(e: &ebpdns_cache::CacheEntry) -> bool {
        e.rcode == 3 || e.answers.is_empty()
    }

    // >>> PATCH242A P0-1 quorum-threshold BEGIN
    /// 负结论表决阈值 = **配置的 `nxdomain_quorum`**（不按候选数钳制）。
    ///
    /// **2.1.45（P1-1/P1-3）**：旧实现 `q.clamp(1, candidates)` 会在"可用上游少于
    /// quorum"时把阈值降到候选数 ⇒ 少票确认 NXDOMAIN（REV247 P1-3）。现在阈值恒为
    /// 配置值，候选数只用于诊断（"本轮派发数 < q ⇒ 必然 SERVFAIL"）。
    ///
    /// 语义：
    /// - 有效票 = NXDOMAIN / NODATA（`is_valid_vote`）；"无票/弃权"（超时 / SERVFAIL /
    ///   REFUSED）**既不抬高也不降低**阈值；
    /// - 只有**凑满配置票数**才写负缓存 / 登记 RFC 8020；凑不满 ⇒ SERVFAIL。
    fn quorum_threshold(&self, quorum_target: usize) -> usize {
        // **2.1.45（P1-1）**：`quorum_target` 已在派发前按模式算定
        // （数据面 = 配置值；预取 Single = 1）——这里**不再**重读 cfg（否则预取
        // 会被抬回配置值，永远凑不满票），也**不**按候选数钳制（否则少票即确认）。
        quorum_target.max(1)
    }
    // <<< PATCH242A P0-1 quorum-threshold END

    // >>> PATCH242A P1-1 policy-cached BEGIN
    /// **2.1.42（P1-1）**：AAAA 本地策略的**缓存态**判定（快路径与慢路径共用）。
    ///
    /// 返回：
    /// - `Some(Ipv6Disabled)`：`ipv6=false`（不查缓存，直接 NODATA）；
    /// - `Some(PreferIpv4)`：`prefer_ipv4=true` **且 A 缓存已确认有正向答案**
    ///   （AAAA 直接 NODATA）；
    /// - `None`：AAAA 可继续正常解析；`prefer_ipv4` 下 A 不在缓存时，慢路径仍会
    ///   `probe_a_record` 发上游探测（快路径则返回 None 交慢路径，避免同步阻塞）。
    ///
    /// **单一判定源**：`answer_fast_ex` 与 `resolve_inner` 都调用本函数，禁止复制逻辑。
    pub(crate) fn aaaa_policy_cached(&self, d: &str, qtype: &str, now: f64) -> Option<AaaaPolicy> {
        if qtype != "AAAA" {
            return None;
        }
        let (ipv6_on, prefer_ipv4) = {
            let c = self.cfg.read();
            (c.ipv6, c.prefer_ipv4)
        };
        if !ipv6_on {
            return Some(AaaaPolicy::Ipv6Disabled);
        }
        if prefer_ipv4 {
            let akey = self.ckey_normalized(d, "A");
            if let Some(e) = self.cache.get(&akey, now) {
                if e.rcode == RCODE_NOERROR && !e.answers.is_empty() {
                    return Some(AaaaPolicy::PreferIpv4);
                }
                // A 缓存确认"无" ⇒ 纯 v6，AAAA 可正常解析。
                return None;
            }
            // A 既不在缓存也没被确认无 ⇒ 慢路径需 probe；快路径必须让路。
            return Some(AaaaPolicy::PreferIpv4Probe);
        }
        None
    }
    // <<< PATCH242A P1-1 policy-cached END

    /// **2.1.15（P1）**：`no-answer` SERVFAIL 的归因（超时 vs 上游有应答但无有效票）。
    ///
    /// 判据：任一条上游的实测延迟 `lat` 达到本次生效超时 `timeout_ms` 的 95% 即认为
    /// 它是**按 timeout 耗尽**的（传输失败的上游在 `query_parallel` 里写入的 `lat`
    /// 就是实际等待时长，正常应答的延迟远低于该阈值）。
    ///
    /// 用 95% 而不是 100%：`tokio::time::timeout` 到期与 `Instant::now()` 采样之间有
    /// 亚毫秒级偏差，且 `elapsed_ms` 取整会向下取整（例如超时 1500ms 实测记 1499ms）。
    fn servfail_reason_of(&self, results: &[&UpstreamAnswer]) -> ServfailReason {
        let timeout_ms = self.cfg.read().timeout_ms.max(1) as f64;
        let threshold = timeout_ms * 0.95;
        if results
            .iter()
            .any(|r| r.lat.is_finite() && r.lat >= threshold)
        {
            ServfailReason::UpstreamTimeout
        } else {
            ServfailReason::UpstreamNoAnswer
        }
    }

    /// 负缓存 TTL：base=min(各结果 neg_ttl，过滤 0)，无则 min(cfg.ttl,60)；
    /// 再过 `clamp_ttl`（受 ttl_min/ttl_max 管控）与 `neg_ttl_max` 硬上限，最后 max(1)。
    ///
    /// **P1-2 修复（2.1.9）**：上游 NXDOMAIN 常不带 SOA（`neg_ttl=None`）或带畸大
    /// SOA minimum（实测 86400）——旧实现只在 `ttl_max>0` 时才夹取，默认配置下
    /// `clamp_ttl` 是恒等函数，于是 86400 原样进缓存。现在**任何**路径都被
    /// `neg_ttl_max`（默认 60s，0=关闭上限）封顶。
    fn neg_ttl_of(&self, results: &[&UpstreamAnswer]) -> f64 {
        let cfg = self.cfg.read();
        // 只关心最小值：避免为收集 + 排序分配 `Vec`（结果数 ≤ 上游数，极小但可省）。
        let mut best: Option<u32> = None;
        for r in results {
            if let Some(v) = r.neg_ttl.filter(|v| *v > 0) {
                best = Some(match best {
                    Some(b) => b.min(v),
                    None => v,
                });
            }
        }
        let base = best.unwrap_or(cfg.ttl.min(60));
        let clamped = clamp_ttl(base, cfg.ttl_min, cfg.ttl_max);
        let capped = if cfg.neg_ttl_max > 0 {
            clamped.min(cfg.neg_ttl_max)
        } else {
            clamped
        };
        capped.max(1) as f64
    }

    /// 负缓存 TTL 硬上限（`neg_ttl_max`，秒；0=不设上限）。
    ///
    /// 所有不在 [`Resolver::neg_ttl_of`] / [`Resolver::neg_ttl_of_sub`] 覆盖范围内的
    /// 负缓存写入（forceIp 类型不匹配的 NODATA）都必须过这一层，保证"任何路径都夹取"。
    pub(crate) fn neg_ttl_cap(&self, ttl: u32) -> u32 {
        let cap = self.cfg.read().neg_ttl_max;
        if cap > 0 {
            ttl.min(cap)
        } else {
            ttl
        }
    }

    /// **2.1.21 第 2 轮（DEF-221-04）**：把一轮**物理**上游扇出的结果记进
    /// "DNS 业务层"第二本账（`UpstreamStats::dns_ok`/`dns_fail`）。
    ///
    /// * 判据（与 README / INTERFACE / `/metrics` HELP 逐字一致）：
    ///   `rcode ∈ {NOERROR, NXDOMAIN}` 且**未截断** ⇒ 业务成功；其余
    ///   （SERVFAIL/REFUSED/NOTIMP/FORMERR/`rcode=None`/截断）⇒ 业务失败。
    ///   **不要求答案段非空** —— NXDOMAIN / NODATA 都是上游真实算出的结论。
    /// * 调用点**唯一** = `resolve_inner`（扇出返回后一次），因此计数口径 = **物理**
    ///   上游应答数，与 `upstream_requests`（物理）同阶，而 `finish_resolve` 的逐调用方
    ///   语义不再影响它。
    /// * `up_name` 为空（本地判定/组包失败等非上游来源）时**跳过**，不制造幽灵上游条目。
    /// * 无 runtime（`ScriptedQuerier` 测试基座）时静默跳过。
    fn record_dns_verdicts(self: &Arc<Self>, results: &[UpstreamAnswer]) {
        let Some(rt) = self.upstream_runtime() else {
            return;
        };
        for r in results {
            if r.up_name.is_empty() {
                continue;
            }
            let dns_ok =
                matches!(r.rcode, Some(RCODE_NOERROR) | Some(RCODE_NXDOMAIN)) && !r.udp_truncated;
            rt.health.stats(&r.up_name).record_dns_verdict(dns_ok);
        }
    }

    /// miss 后处理：quorum 表决 / CNAME 链 / 候选去重 / 回填。
    ///
    /// `candidates` = 本轮参与表决的**候选上游数**（P1-B：quorum 分母，绝不是
    /// `results.len()`）；`prefetch` = 预取链路（P2-B：禁止写负缓存）。
    #[allow(clippy::too_many_arguments)]
    async fn finish_resolve(
        self: Arc<Self>,
        d: &str,
        qtype: &str,
        ckey: &CacheKey,
        results: Vec<UpstreamAnswer>,
        rule: Option<Rule>,
        depth: u32,
        t0: f64,
        gen_at_entry: u64,
        mut trace: TraceSink,
        mode: UpstreamMode,
        candidates: usize,
        // >>> PATCH242A P0-1 finish-quorum BEGIN
        // **2.1.42（P0-1）**：负票 quorum 阈值（候选分母，已 clamp）。
        quorum_target: usize,
        // <<< PATCH242A P0-1 finish-quorum END
        prefetch: bool,
        // **2.1.21（DEF-220-01/11）**：续期回填的 TTL 上限（整条解析链一致）。
        ttl_cap: Option<f64>,
    ) -> ResolveResult {
        let lat = || self.clock.monotonic_ms() - t0;

        // **[历史归因]** 语义熔断喂点（对齐 Python resolver.py ~2295，在 classify 之后按 rcode）：
        // rcode ∈ {0,3}(NOERROR/NXDOMAIN) 记成功；其余 rcode(SERVFAIL/REFUSED/FORMERR…)
        // 或传输失败/解析失败(rcode=None) 记失败。仅传输层可达但持续 SERVFAIL 的上游
        // 也会累计失败而熔断。喂点用 answer 的 up_name（= 熔断器键 up.id）。
        //
        // 优化项 9（要求 4）：**预取**（Single）失败不得占用数据面 `circuit_fails` 名额
        // —— 与"健康探针失败不计入熔断"同口径：成功仍可确认恢复（`probe_ok`），
        // 失败只累加独立 `probe_fail`。
        for r in &results {
            let ok = matches!(r.rcode, Some(RCODE_NOERROR) | Some(RCODE_NXDOMAIN));
            // **DNS 业务层的第二本账不在这里记**（**2.1.21 第 2 轮 / DEF-221-04**）：
            // 本循环是**逐调用方**执行的（single-flight 只合并上游扇出段，`finish_resolve`
            // 每个调用方各跑一次）⇒ 在这里记会把 5 个并发同名 miss 的 1 次物理查询记成
            // `dns_ok +5`（审计实测）。现在记账点移到 `resolve_inner` 里
            // **扇出返回之后**调用一次的 [`Resolver::record_dns_verdicts`]。
            // 熔断账/探针账仍在下面按 `mode` 分别处理（语义与 2.1.15 优化项 9 逐位一致）。
            if mode.is_single() {
                if ok {
                    let _ = self.cb_probe_ok(&r.up_name);
                } else {
                    let _ = self.cb_probe_fail(&r.up_name);
                }
            } else if ok {
                self.cb_ok(&r.up_name);
            } else {
                self.cb_fail(&r.up_name);
            }
        }

        // ok_results: 完整答案且未截断。
        let ok: Vec<&UpstreamAnswer> = results
            .iter()
            .filter(|r| !r.answers.is_empty() && !r.udp_truncated)
            .collect();

        if ok.is_empty() {
            // ---- M1 截断沿用：无完整答案但存在 answers 非空且 udp_truncated 的应答 ----
            // 去重直答、强制 truncated=true(TC)、不写缓存。
            let truncated: Vec<&UpstreamAnswer> = results
                .iter()
                .filter(|r| r.udp_truncated && !r.answers.is_empty())
                .collect();
            if !truncated.is_empty() {
                let mut cand: Vec<ResolveAnswer> = Vec::new();
                for r in &truncated {
                    for a in &r.answers {
                        // 线性去重：只对候选数（≤ 上游数×答案数，通常个位数）扫描，
                        // 避免为 `BTreeSet` 复制每个 value 一次。
                        if cand.iter().any(|c| c.value == a.value) {
                            continue;
                        }
                        cand.push(a.clone());
                    }
                }
                trace.push_with(|| {
                    TraceEvent::new(
                        "warn",
                        format!("截断沿用: {} 条 TC 应答直答", truncated.len()),
                    )
                });
                return ResolveResult {
                    domain: d.into(),
                    qtype: qtype.into(),
                    rcode: RCODE_NOERROR,
                    answers: cand,
                    truncated: true,
                    latency: lat(),
                    trace: trace.into_vec(),
                    // 事件 `upstream` 列：TC 沿用应答的**获胜**上游（单一名字）。
                    // 与 v1.9.162 resolver.py:1021 的候选列表（`" / "` 连接）有意收窄：
                    // 事件只写「谁真正应答」，候选列表只留在 trace。
                    up_name: winner_of(&truncated),
                    ..Default::default()
                };
            }

            // ---- NXDOMAIN quorum（P1-B：分母 = 候选数；P2-B：预取不写负缓存）----
            let nx: Vec<&UpstreamAnswer> = results
                .iter()
                .filter(|r| r.rcode == Some(RCODE_NXDOMAIN))
                .collect();
            // >>> PATCH242A P0-1 nx-quorum BEGIN
            // **2.1.42（P0-1）**：分母 = 候选数（派发前算定），不是"被 abort 后的
            // 应答数"；未满 quorum 时**不**写负缓存、**不**登记 RFC 8020。
            let nxq = self.quorum_threshold(quorum_target);
            // **2.1.49（AUD-12）**：quorum 的**票源**也必须按上游 id 去重。
            // 旧实现只把 `candidates` 按 `up_name` 去重，却用 `nx.len()` 数票；配置里
            // 两个相同 id 的条目（PUT /api/config 不校验唯一性）指向同一服务器时，
            // 一次扇出的两条 NXDOMAIN 就能在 q=2 时“确认”负结论。`nx_sources` 让
            // 票数与候选数使用同一身份口径（一个 id = 一票）。
            let nx_sources = {
                let mut set: std::collections::HashSet<&str> =
                    std::collections::HashSet::with_capacity(nx.len());
                for r in &nx {
                    set.insert(r.up_name.as_str());
                }
                set.len()
            };
            let quorum_reachable = candidates >= nxq;
            // **2.1.45（P1-1）**：本轮实际派发上游 < quorum ⇒ **数学上不可能**确认负结论。
            // **2.1.49（AUD-12）**：这里不再只写 trace 后继续走确认分支 —— 显式
            // fail-closed 到 SERVFAIL，绝不给 `nx.len()>=nxq` 任何机会。
            if !quorum_reachable {
                trace.push_with(|| {
                    TraceEvent::new(
                        "warn",
                        format!(
                            "quorum 不可达: 本轮实际派发上游 {candidates} < nxdomain_quorum {nxq} \
                             ⇒ 直接 SERVFAIL（不进入 NXDOMAIN/NODATA 确认分支），不写负缓存/不登记 RFC8020"
                        ),
                    )
                });
            }
            // <<< PATCH242A P0-1 nx-quorum END
            if quorum_reachable && nx_sources >= nxq {
                // 补偿控制：仅 1 张有效负票即采纳（弃权票不抬高阈值）时计数。
                if nxq == 1
                    && nx_sources == 1
                    && results.iter().filter(|r| is_valid_vote(r)).count() == 1
                {
                    self.note_negative_single_vote();
                }
                let neg = self.neg_ttl_of(&nx);
                if prefetch {
                    trace.push_with(|| {
                        TraceEvent::new(
                            "warn",
                            format!("预取链路达到 NXDOMAIN quorum({nxq}) → 不写负缓存"),
                        )
                    });
                } else {
                    self.put_negative(
                        ckey,
                        d,
                        qtype,
                        RCODE_NXDOMAIN,
                        neg as u32,
                        Some(gen_at_entry),
                    );
                    // 2.1.12 优化项 ①：登记「NXDOMAIN 域」（RFC 8020）。
                    //
                    // **登记点唯一**：只有这里（"确实 NXDOMAIN 且已达 quorum"）登记 ——
                    // SERVFAIL/REFUSED/超时（rcode=None）/NODATA/截断/规则屏蔽全部不经过
                    // 本分支；本条 `else` 分支本身就是 P2-B 的"预取不写负缓存"门禁，
                    // 故**预取链路同样不登记**（`if prefetch` 分支不登记）。
                    //
                    // 注意**不**登记 CNAME→NXDOMAIN 那一支的外层名字：外层名字存在
                    // （有 CNAME RR），只有链尾不存在，`*.外层` 并无 NXDOMAIN 证据。
                    // 链尾目标由子链自己的 `finish_resolve` 在本分支登记。
                    self.rfc8020_register(d, neg as u32);
                    trace
                        .push_with(|| TraceEvent::new("eng", format!("NXDOMAIN 负缓存 {neg:.0}s")));
                }
                return ResolveResult {
                    domain: d.into(),
                    qtype: qtype.into(),
                    rcode: RCODE_NXDOMAIN,
                    latency: lat(),
                    ttl_left: neg,
                    trace: trace.into_vec(),
                    // 事件 `upstream` 列：给出 NXDOMAIN 的**获胜**上游（单一名字；v1.9.162
                    // resolver.py:1054 写候选列表 `"a / b"`，本版按缺陷 P0 收窄为一个）。
                    up_name: winner_of(&nx),
                    ..Default::default()
                };
            }

            // ---- CNAME 链 ----
            let cname_res: Vec<&UpstreamAnswer> =
                results.iter().filter(|r| !r.cnames.is_empty()).collect();
            if !cname_res.is_empty()
                && (qtype == "A" || qtype == "AAAA")
                && depth < crate::MAX_DEPTH
            {
                let (tgt, tgt_ttl) = cname_res[0].cnames[0].clone();
                let chain = vec![ResolveAnswer {
                    value: tgt.clone(),
                    ttl: tgt_ttl as f64,
                    rtype: TYPE_CNAME,
                    name: None,
                }];
                let sub = Box::pin(self.clone().resolve_inner(
                    &tgt,
                    qtype,
                    ResolveOpts {
                        depth: depth + 1,
                        silent: true,
                        counted: false,
                        // 子链不单独出 trace：外层 trace 已记录 CNAME→NXDOMAIN/NODATA。
                        trace: false,
                        // 子链继承外层 TTL 上限（预取续期目标一致）。
                        ttl_cap,
                        ..Default::default()
                    },
                    // 优化项 9：预取的 CNAME 子链同样只发 1 个上游。
                    mode,
                ))
                .await;
                if !sub.error && !sub.answers.is_empty() && !sub.truncated {
                    let mut answers = chain;
                    for a in sub.answers {
                        if a.name.is_none() {
                            answers.push(a.with_name(tgt.clone()));
                        } else {
                            answers.push(a);
                        }
                    }
                    let chosen = answers.last().map(|a| a.value.clone()).unwrap_or_default();
                    // 子链继承外层的 `ttl_cap`（预取续期上限对整条链一致）。
                    self.fill_cache_capped(
                        ckey,
                        d,
                        qtype,
                        answers.clone(),
                        Some(gen_at_entry),
                        ttl_cap,
                    );

                    return ResolveResult {
                        domain: d.into(),
                        qtype: qtype.into(),
                        answers,
                        chosen,
                        rcode: RCODE_NOERROR,
                        latency: lat(),
                        trace: trace.into_vec(),
                        // 事件 `upstream` 列：优先链尾答案的真正来源（子链获胜上游），
                        // 子链无名时回退给出 CNAME 记录的上游；永远单一名字。
                        up_name: cname_winner(&sub.up_name, &cname_res),
                        ..Default::default()
                    };
                }
                if sub.rcode == RCODE_NXDOMAIN {
                    let neg = self.neg_ttl_of_sub(&sub);
                    self.put_negative(
                        ckey,
                        d,
                        qtype,
                        RCODE_NXDOMAIN,
                        neg as u32,
                        Some(gen_at_entry),
                    );
                    trace.push_with(|| TraceEvent::new("eng", format!("CNAME→NXDOMAIN {neg:.0}s")));
                    return ResolveResult {
                        domain: d.into(),
                        qtype: qtype.into(),
                        rcode: RCODE_NXDOMAIN,
                        latency: lat(),
                        trace: trace.into_vec(),
                        ttl_left: neg,
                        // 事件 `upstream` 列：CNAME→NXDOMAIN 的决定性上游（子链获胜
                        // 上游优先，回退 CNAME 提供者；v1.9.162 resolver.py:1123 写列表）。
                        up_name: cname_winner(&sub.up_name, &cname_res),
                        ..Default::default()
                    };
                }
                if sub.truncated || sub.error {
                    return ResolveResult {
                        domain: d.into(),
                        qtype: qtype.into(),
                        rcode: sub.rcode,
                        error: sub.error,
                        truncated: sub.truncated,
                        latency: lat(),
                        trace: trace.into_vec(),
                        up_name: cname_winner(&sub.up_name, &cname_res),
                        ..Default::default()
                    };
                }
                // sub.rcode == 0 → CNAME 终点 NODATA 传播。
                if sub.rcode == RCODE_NOERROR {
                    let mut neg = sub.ttl_left;
                    if neg <= 0.0 {
                        let cfg = self.cfg.read();
                        neg = cfg.ttl.clamp(1, 60) as f64;
                        drop(cfg);
                    }
                    self.put_negative(
                        ckey,
                        d,
                        qtype,
                        RCODE_NOERROR,
                        neg as u32,
                        Some(gen_at_entry),
                    );
                    trace.push_with(|| TraceEvent::new("eng", format!("CNAME→NODATA {neg:.0}s")));
                    return ResolveResult {
                        domain: d.into(),
                        qtype: qtype.into(),
                        rcode: RCODE_NOERROR,
                        empty: true,
                        latency: lat(),
                        ttl_left: neg,
                        trace: trace.into_vec(),
                        up_name: cname_winner(&sub.up_name, &cname_res),
                        ..Default::default()
                    };
                }
            }

            // ---- NODATA quorum（排除 udp_truncated / 带 cnames）----
            let nodata: Vec<&UpstreamAnswer> = results
                .iter()
                .filter(|r| {
                    r.rcode == Some(RCODE_NOERROR) && !r.udp_truncated && r.cnames.is_empty()
                })
                .collect();
            // >>> PATCH242A P0-1 nodata-quorum BEGIN
            // **2.1.42（P0-1）**：NODATA 与 NXDOMAIN 同口径 —— 分母 = 候选数。
            let ndq = self.quorum_threshold(quorum_target);
            // <<< PATCH242A P0-1 nodata-quorum END
            // **2.1.49（AUD-12）**：NODATA 与 NXDOMAIN 同口径 —— 候选不足或
            // 去重后的票源不足 ⇒ 不进入确认分支（直接走下面的 SERVFAIL）。
            let nodata_sources = {
                let mut set: std::collections::HashSet<&str> =
                    std::collections::HashSet::with_capacity(nodata.len());
                for r in &nodata {
                    set.insert(r.up_name.as_str());
                }
                set.len()
            };
            let nodata = if candidates >= ndq && nodata_sources >= ndq {
                nodata
            } else {
                Vec::new()
            };
            if !nodata.is_empty() {
                // 补偿控制：仅 1 张有效负票即采纳（NODATA 侧同口径）。
                if ndq == 1
                    && nodata.len() == 1
                    && results.iter().filter(|r| is_valid_vote(r)).count() == 1
                {
                    self.note_negative_single_vote();
                }
                if qtype == "AAAA" && self.cfg.read().ipv4_first {
                    self.ipv4_fallback(d, gen_at_entry, &mut trace, mode, ttl_cap)
                        .await;
                }
                let neg = self.neg_ttl_of(&nodata);
                if prefetch {
                    trace.push_with(|| {
                        TraceEvent::new(
                            "warn",
                            format!("预取链路达到 NODATA quorum({ndq}) → 不写负缓存"),
                        )
                    });
                } else {
                    self.put_negative(
                        ckey,
                        d,
                        qtype,
                        RCODE_NOERROR,
                        neg as u32,
                        Some(gen_at_entry),
                    );
                    trace.push_with(|| TraceEvent::new("eng", format!("NODATA 负缓存 {neg:.0}s")));
                }
                return ResolveResult {
                    domain: d.into(),
                    qtype: qtype.into(),
                    rcode: RCODE_NOERROR,
                    empty: true,
                    latency: lat(),
                    ttl_left: neg,
                    trace: trace.into_vec(),
                    // 事件 `upstream` 列：给出 NODATA 的**获胜**上游（单一名字；
                    // v1.9.162 resolver.py:1234 写候选列表，本版按缺陷 P0 收窄为一个）。
                    up_name: winner_of(&nodata),
                    ..Default::default()
                };
            }
            // 全部失败 → SERVFAIL（带上游名供排障：对齐 resolver.py:1333 的 err 口径）。
            let all: Vec<&UpstreamAnswer> = results.iter().collect();
            let responded = all.iter().filter(|r| is_valid_vote(r)).count();
            trace.push_with(|| {
                TraceEvent::new(
                    "warn",
                    format!(
                        "无有效负结论: 候选 {candidates} / 返回 {} / 有效应答 {responded}",
                        all.len()
                    ),
                )
            });
            let mut e =
                ResolveResult::error(d, qtype, "no-answer", trace.into_vec()).with_latency(lat());
            // **2.1.15（P1）**：结构化 SERVFAIL 归因（这里是**唯一**的"上游侧"出口）。
            //
            // 判据（互斥二选一，见 `ServfailReason` 文档）：
            // - 至少一条上游的实测延迟触及本次生效超时的 95%（说明它是**按 timeout 耗尽**
            //   的，而不是收到了非 0/3 的应答）→ `upstream_timeout`；
            // - 否则 → `upstream_no_answer`（收到了应答但都不是有效票）。
            e.servfail_reason = Some(self.servfail_reason_of(&all));
            // err 事件 `upstream` 列：单一获胜上游名（首选 / 最先应答的那个）；
            // v1.9.162 resolver.py:1333 写候选列表 `"a / b / c"`，本版按缺陷 P0 收窄。
            e.up_name = winner_of(&all);
            return e;
        }

        // ---- 有完整答案：候选保序去重 ----
        // 不用 BTreeMap（会按字典序重排）；按上游插入序保序，首见保留，后续合并 min ttl / 豁免。
        // **[历史归因]** 同时记录每个候选的静态兜底延迟与探测模式（对齐 Python cand 的 `lat` / `probe`
        // 字段），供 IP 测速择优（`Resolver::speed_sort`）使用。
        //
        // 性能上限：测速输入（probe_override / proto_of / hints）只在
        // **[历史归因]** `speed_test && ip_speed_check && 候选 > 1` 时才需要构造（与 Python
        // `_speed_sort` 的 `if not ip_speed_check: return cand_list` 早退同型），
        // 故先只做候选归并，再按开关决定是否补建测速输入。
        let mut cand: Vec<CandEntry> = Vec::new();
        for r in &ok {
            for a in &r.answers {
                if let Some(slot) = cand.iter_mut().find(|c| c.value == a.value) {
                    slot.ttl = slot.ttl.min(a.ttl);
                } else {
                    cand.push(CandEntry {
                        value: a.value.clone(),
                        ttl: a.ttl,
                        rtype: a.rtype,
                        // **[历史归因]** 静态兜底延迟：首个贡献该答案的上游应答延迟（Python `cand[v]["lat"]`）。
                        static_lat: if r.lat.is_finite() { r.lat } else { 999.0 },
                        probe: None,
                    });
                }
            }
        }
        // 测速门禁（提前判定，后续复用一个 bool，避免重复读 cfg）。
        let speed_gate = {
            let c = self.cfg.read();
            c.speed_test && c.ip_speed_check && cand.len() > 1
        };
        if speed_gate {
            // 探测模式：显式 udp53/tcp443 全局覆盖；否则加密协议（DoH/DoT/DoQ/DoH3）→ tcp443，
            // **[历史归因]** 其余 → udp53（对齐 Python `_speed_sort` 调用点的 probe 选择）。
            let (probe_override, proto_of) = {
                let cfg = self.cfg.read();
                let over = match cfg.ip_speed_probe.to_ascii_lowercase().as_str() {
                    "udp53" => Some("udp53"),
                    "tcp443" => Some("tcp443"),
                    _ => None,
                };
                let map: std::collections::HashMap<String, &'static str> = cfg
                    .upstreams
                    .iter()
                    .map(|u| {
                        let p = if u.proto.eq_ignore_ascii_case("doh")
                            || u.proto.eq_ignore_ascii_case("dot")
                            || u.proto.eq_ignore_ascii_case("doq")
                            || u.proto.eq_ignore_ascii_case("doh3")
                        {
                            "tcp443"
                        } else {
                            "udp53"
                        };
                        (u.id.clone(), p)
                    })
                    .collect();
                (over, map)
            };
            // 每个候选补探测模式：按贡献该答案的（首个）上游协议判定。
            // **[历史归因]** 只补前 `SPEED_SORT_WINDOW` 个（= Python `cand_list[:8]`）：`speed_sort` 只消费
            // 窗口内的 probe，窗口外补了也不会被读，白付哈希查找。
            for r in &ok {
                for a in &r.answers {
                    if let Some(slot) = cand
                        .iter_mut()
                        .take(crate::SPEED_SORT_WINDOW)
                        .find(|c| c.value == a.value)
                    {
                        if slot.probe.is_none() {
                            slot.probe = Some(match probe_override {
                                Some(o) => o,
                                None => {
                                    proto_of.get(r.up_name.as_str()).copied().unwrap_or("udp53")
                                }
                            });
                        }
                    }
                }
            }
        }

        let mut cand_list: Vec<ResolveAnswer> = cand
            .iter()
            .map(|c| ResolveAnswer {
                value: c.value.clone(),
                ttl: c.ttl,
                rtype: c.rtype,
                name: None,
            })
            .collect();
        // M8：豁免标记（与 cand_list 同序）。用与 cand 同序的 `(value, allow_private)`
        // 归并表，避免 O(候选 × 答案) 的重复字符串比较。
        let exempt: Vec<bool> = cand
            .iter()
            .map(|c| {
                ok.iter()
                    .any(|r| r.allow_private && r.answers.iter().any(|a| a.value == c.value))
            })
            .collect();

        // rebind 防护：过滤私有/保留地址（豁免上游贡献的答案整体放行）。
        //
        // **2.1.17（修复项 3）：被丢弃的条数结构化回传**（`private_answers_filtered`）。
        // 该计数是「RFC1918 应答按设计不入缓存」的**唯一可观测证据** —— 2.1.16 只有
        // trace 中文文案，审计侧因此误判 `rebind_blocked=0` 为「缓存坏了」。
        // 语义：只数**被丢弃的候选条数**（全部为私网而回 NODATA 时不额外 +1）。
        let mut private_filtered: u32 = 0;
        if self.cfg.read().rebind_protection
            && (qtype == "A" || qtype == "AAAA")
            && !matches!(rule, Some(r) if r.action == Action::ForceIp)
        {
            let before = cand_list.len();
            for i in (0..cand_list.len()).rev() {
                if !exempt[i] && is_private_ip(&cand_list[i].value) {
                    cand_list.remove(i);
                    private_filtered = private_filtered.saturating_add(1);
                    // cand 与 cand_list 同序：同步删除，保持索引对齐（测速输入稍后按需构造）。
                    if i < cand.len() {
                        cand.remove(i);
                    }
                }
            }
            if cand_list.len() < before {
                trace.push_with(|| {
                    TraceEvent::new(
                        "warn",
                        format!("rebind: 丢弃私有地址答案 {} 条", before - cand_list.len()),
                    )
                });
            }
            if cand_list.is_empty() {
                trace.push_str("warn", "全部答案为私有地址 → NODATA");
                return ResolveResult {
                    domain: d.into(),
                    qtype: qtype.into(),
                    rcode: RCODE_NOERROR,
                    empty: true,
                    latency: lat(),
                    trace: trace.into_vec(),
                    // 事件 `upstream` 列：贡献（被丢弃的）答案的**获胜**上游（单一名字）。
                    up_name: winner_of(&ok),
                    private_answers_filtered: private_filtered,
                    ..Default::default()
                };
            }
        }

        // **[历史归因]** 候选 IP 测速择优（对齐 Python `_speed_sort`）：`speed_test && ip_speed_check`
        // 且候选 >1 时按 EWMA/静态延迟加权随机重排（仅前 8 个），否则保持上游插入序。
        // 早退：不满足开关/候选数条件时**不构造** hints（省一次 Vec + 每候选 String）。
        let cand_list = if speed_gate && cand_list.len() > 1 {
            let hints: Vec<CandidateSpeedHint> = cand
                .iter()
                .map(|c| CandidateSpeedHint {
                    static_lat: c.static_lat,
                    probe: c.probe.unwrap_or("udp53").to_string(),
                })
                .collect();
            let sorted = self.speed_sort(&cand_list, &hints, d);
            trace.push_with(|| {
                TraceEvent::new(
                    "eng",
                    format!(
                        "测速择优(EWMA+加权随机): 首选 {}",
                        sorted.first().map(|a| a.value.as_str()).unwrap_or("")
                    ),
                )
            });
            sorted
        } else {
            cand_list
        };
        let chosen = cand_list
            .first()
            .map(|a| a.value.clone())
            .unwrap_or_default();
        self.fill_cache_capped(
            ckey,
            d,
            qtype,
            cand_list.clone(),
            Some(gen_at_entry),
            // **2.1.21（DEF-220-01/11）**：主成功路径的续期回填上限。
            ttl_cap,
        );

        trace.push_with(|| TraceEvent::new("cache", format!("回填缓存 → {chosen}")));
        // **2.1.20（F-02）/ 2.1.21（DEF-220-01）**：本条刚刚从上游拿到**全新**条目
        // ⇒ 剩余 TTL = 满值，用 `f64::INFINITY` 表达"远高于 `prefetch_trigger`"，
        // 因此**不会**被续期入队（入队判据 `ttl_left <= trigger` 不成立）。
        // 这同时保证与 `do_prefetch` 是**同一条判据**：不存在"入队却永不续期"。
        self.schedule_prefetch(d, qtype, f64::INFINITY);

        ResolveResult {
            domain: d.into(),
            qtype: qtype.into(),
            answers: cand_list,
            chosen: chosen.clone(),
            rcode: RCODE_NOERROR,
            latency: lat(),
            trace: trace.into_vec(),
            // 事件 `upstream` 列：**获胜上游**（真正提供 chosen 这条答案的上游 id）。
            up_name: winner_up_name(&ok, &chosen),
            // **2.1.17（修复项 3）**：本次被 rebind 防护丢弃的私有地址条数（0 = 无）。
            private_answers_filtered: private_filtered,
            ..Default::default()
        }
    }

    /// CNAME 子链 NXDOMAIN 时的负 TTL（取子链 ttl_left 或默认），同样受 `neg_ttl_max` 封顶。
    fn neg_ttl_of_sub(&self, sub: &ResolveResult) -> f64 {
        let mut neg = sub.ttl_left;
        if neg <= 0.0 {
            let cfg = self.cfg.read();
            neg = cfg.ttl.clamp(1, 60) as f64;
            drop(cfg);
        }
        // P1-2：子链 ttl_left 可能来自上游超大 SOA → 仍要过硬上限。
        let cap = self.cfg.read().neg_ttl_max;
        if cap > 0 {
            neg = neg.min(f64::from(cap));
        }
        neg.max(1.0)
    }

    /// prefer_ipv4 双栈探测：查 A 缓存，miss 则上游查 A 并回填（带外层 gen 门禁）。
    async fn probe_a_record(
        &self,
        d: &str,
        _gen: u64,
        trace: &mut TraceSink,
        mode: UpstreamMode,
    ) -> bool {
        let key = self.ckey_normalized(d, "A");
        let now = self.clock.epoch();
        if let Some(e) = self.cache.get(&key, now) {
            if e.rcode == RCODE_NOERROR && !e.answers.is_empty() {
                trace.push_str("eng", "双栈探测: A 缓存命中 → 双栈");
                return true;
            }
            trace.push_str("eng", "双栈探测: A 缓存确认无 → 纯 v6");
            return false;
        }
        let ups: Vec<UpstreamCfg> = self
            .cfg
            .read()
            .upstreams
            .iter()
            .filter(|u| u.enabled)
            .cloned()
            .collect();
        if ups.is_empty() {
            return false;
        }
        // 优化项 9：预取链路（Single）的双栈探测同样只发 1 个上游。
        let ups = self.query_targets(&ups, mode.is_single());
        if ups.is_empty() {
            return false;
        }
        let querier: Arc<dyn ParallelQuerier> = self.querier.read().clone();
        // **2.1.43-A（P2：probe 真发上游但 `upstream_queries` 记 0）**：双栈探测
        // **真的**打了一个上游 A 查询（`prefer_ipv4=true` + AAAA + A 不在缓存），
        // 但 2.1.42 及以前它对**任何**计数器都不可见 —— `upstream_queries` 只统计
        // "数据面客户端查询"（判据在 `dns.rs::log_and_count` 的显式枚举），探针不是
        // 客户端查询，于是"上游确实收到了报文、`counters.upstream_queries` 仍是 0"
        // 看起来像丢计（运维据此会误判上游未被使用）。
        //
        // 现在**只追加**独立键 `probe_upstream_queries`（**不**并入 `upstream_queries`：
        // 两者语义不同，合并会破坏 `upstream_queries` 的"客户端查询"口径与既有单测）。
        // 写点唯一 = 本函数、且只在真的发出上游查询之后。
        //
        // **2.1.46（REV247 P3-4）**：自增移到 `query_parallel` **返回之后** ——
        // 旧实现"先加计数再发查询"，若 querier 立即失败/panic，计数仍然 +1，
        // 把"派发尝试"误报成"上游查询"。现在只有调用正常返回才计入。
        let results = querier.query_parallel(&ups, d, "A", 0).await;
        self.tel.inc("probe_upstream_queries");
        let ok: Vec<&UpstreamAnswer> = results
            .iter()
            .filter(|r| !r.answers.is_empty() && !r.udp_truncated)
            .collect();
        if ok.is_empty() {
            trace.push_str("eng", "双栈探测: 上游无 A → 纯 v6");
            return false;
        }
        let ans = dedup_answers(&ok);
        if self.cfg.read().rebind_protection {
            let ans: Vec<ResolveAnswer> = ans
                .into_iter()
                .filter(|a| !is_private_ip(&a.value))
                .collect();
            if ans.is_empty() {
                return false;
            }
            // 双栈探测（`rebind_protection` 过滤后仍有答案）；内部探测无 `opts`。
            // **2.1.45（P1-4）**：同 `probe_a_record` 主写回点 —— 探针按写回时刻的规则代盖章。
            self.fill_cache_capped(&key, d, "A", ans, Some(self.rule_gen()), None);

            trace.push_str("eng", "双栈探测: 上游确认有 A → 双栈");
            return true;
        }
        if ans.is_empty() {
            return false;
        }
        // 双栈探测（`rebind_protection` 关闭，不过滤私有地址）；内部探测无 `opts`。
        // **2.1.45（P1-4）**：同 `probe_a_record` 主写回点 —— 探针按写回时刻的规则代盖章。
        self.fill_cache_capped(&key, d, "A", ans, Some(self.rule_gen()), None);

        trace.push_str("eng", "双栈探测: 上游确认有 A → 双栈");
        true
    }

    /// ipv4_first 回退：AAAA NODATA 时预热 A 缓存（带外层 gen 门禁）。
    async fn ipv4_fallback(
        &self,
        d: &str,
        gen: u64,
        trace: &mut TraceSink,
        mode: UpstreamMode,
        // **2.1.21（DEF-220-01/11）**：IPv4 回退预热的 TTL 上限。
        ttl_cap: Option<f64>,
    ) -> Option<Vec<ResolveAnswer>> {
        let key = self.ckey_normalized(d, "A");
        let now = self.clock.epoch();
        if let Some(e) = self.cache.get(&key, now) {
            if !e.answers.is_empty() {
                trace.push_str("eng", "IPv4 回退: 命中 A 缓存");
                return Some(
                    e.answers
                        .iter()
                        .map(|a| ResolveAnswer {
                            value: a.value.clone(),
                            ttl: a.ttl,
                            rtype: a.rtype,
                            name: None,
                        })
                        .collect(),
                );
            }
        }
        let ups: Vec<UpstreamCfg> = self
            .cfg
            .read()
            .upstreams
            .iter()
            .filter(|u| u.enabled)
            .cloned()
            .collect();
        if ups.is_empty() {
            return None;
        }
        // 优化项 9：预取链路的 A 预热同样只发 1 个上游。
        let ups = self.query_targets(&ups, mode.is_single());
        if ups.is_empty() {
            return None;
        }
        let querier: Arc<dyn ParallelQuerier> = self.querier.read().clone();
        let results = querier.query_parallel(&ups, d, "A", 0).await;
        let ok: Vec<&UpstreamAnswer> = results
            .iter()
            .filter(|r| !r.answers.is_empty() && !r.udp_truncated)
            .collect();
        if ok.is_empty() {
            return None;
        }
        let mut ans = dedup_answers(&ok);
        if self.cfg.read().rebind_protection {
            ans.retain(|a| !is_private_ip(&a.value));
        }
        if ans.is_empty() {
            return None;
        }
        // **2.1.45（P1-3/P1-4）**：`ipv4_first` 回退取的 A 记录属于**本次客户端查询**
        // 的在途答案 ⇒ 用外层 `gen_at_entry` 盖章（规则代已变则拒绝写回，与
        // `put_negative` / `fill_cache_capped` 两条路径同口径）。
        // 注意与 `probe_a_record` 的区别：那是"当前时刻的新探测"，按写回时刻盖章。
        self.fill_cache_capped(&key, d, "A", ans.clone(), Some(gen), ttl_cap);
        // **2.1.43-A（P2：`ipv4_fallback` 恒 0 = 没有写点）**：2.1.42 及以前
        // `COUNTER_KEYS` 里有 `ipv4_fallback`、`/api/status.counters` 与
        // `/metrics` 都下发它，但**全树没有任何自增点**（`grep -rn 'inc.*ipv4_fallback'
        // crates` 为空）⇒ 恒 0，属"字段存在但不可观测"，不是"业务上罕见"。
        //
        // 现在写点唯一 = 本函数**预热成功**的那一刻（真的发了上游 A 查询、拿到答案、
        // 回填了缓存）。命中 A 缓存 / 上游无 A / 私网答案被过滤掉都**不计**
        // —— 那三种情况并没有发生"回退到 IPv4 的上游取数"。
        self.tel.inc("ipv4_fallback");
        trace.push_str("eng", "IPv4 回退: 预热 A 缓存");

        Some(ans)
    }
}

// >>> PATCH242A P0-1 is-negative BEGIN
/// **2.1.42（P0-1）**：负票判定（NXDOMAIN 或 NODATA），与
/// `production.rs::is_negative` 同口径；传输失败 / SERVFAIL 不算负票。
/// 只用于"是否还需凑票"的判断，不改变 `is_valid_vote` 的计票语义。
fn is_negative_answer(r: &UpstreamAnswer) -> bool {
    r.rcode == Some(RCODE_NXDOMAIN)
        || (r.rcode == Some(RCODE_NOERROR) && !r.udp_truncated && r.answers.is_empty())
}
// <<< PATCH242A P0-1 is-negative END

/// 有效票判定（P1-B 语义修正版）：该应答是否算"成功给出了一个负结论"。///
/// - `rcode=None`（超时/构造失败/报文解析失败）→ **无票**；
/// - `rcode ∈ {SERVFAIL(2), REFUSED(5), NOTIMP(4), FORMERR(1)}` → **无票**
///   （上游自己没算出答案，既不能支持也不能否定负结论）；
/// - `rcode=NXDOMAIN(3)` → 有效票（负）；
/// - `rcode=NOERROR(0)`：截断（TC=1，答案不完整）→ 无票；否则 NODATA→有效票、
///   有答案→有效票（**正**）。
///
/// 表决阈值只在有效票之间取 `min(nxdomain_quorum, 有效票数)`；"无票"不得抬高阈值，
/// 否则生产上 8 个上游里只有 1 个能应答时会大面积误报 SERVFAIL（实测 12/12）。
fn is_valid_vote(r: &UpstreamAnswer) -> bool {
    matches!(r.rcode, Some(0) | Some(3)) && !r.udp_truncated
}

/// 保序去重（首见保留）：把上游应答里的答案摊平去重，供双栈探测/回退复用。
///
/// 用线性扫描而非 `HashSet<String>`：答案数通常个位数，省掉每次 `a.value.clone()`
/// 进集合的一次分配。
fn dedup_answers(ok: &[&UpstreamAnswer]) -> Vec<ResolveAnswer> {
    let mut ans: Vec<ResolveAnswer> = Vec::new();
    for r in ok {
        for a in &r.answers {
            if ans.iter().any(|x| x.value == a.value) {
                continue;
            }
            ans.push(a.clone());
        }
    }
    ans
}

/// 事件 `upstream` 列的**单一获胜上游**名：取「决定本次结论」那组应答里排在最前的
/// 上游 `id`。该组已按上游选择顺序（`eff_lat / max(1, weight)` 升序，fallback 第二轮
/// 追加在后）排列，故首个即本轮首选 / 最先应答的赢家。组为空 → 空串，由
/// `ebpdns-server` 侧 `event_upstream()` 回退到兜底文案。
///
/// **[历史归因]** **与 v1.9.162 的有意差异（缺陷 P0）**：Python 在 NXDOMAIN / NODATA / CNAME /
/// 截断 / 全失败分支写 `" / ".join(r["up_name"] for r in results[:3])`
/// （resolver.py:1054 / 1097 / 1123 / 1234 / 1333），事件 `upstream` 列因此是**候选
/// 列表**（`"lan235 / lan235tcp / alidoh"`），控制台「上游」列看不出谁真正应答。
/// 本版统一收窄为**一个**名字（真正提供该结论的上游）。
fn winner_of(results: &[&UpstreamAnswer]) -> String {
    results
        .first()
        .map(|r| r.up_name.clone())
        .unwrap_or_default()
}

/// CNAME 链路径的获胜上游：优先子链（真正给出链尾 A/AAAA、NXDOMAIN、NODATA 的上游，
/// 含子链本身是「缓存直答 / serve-stale」的情形），子链无名时回退给出 CNAME 记录的
/// 上游。无论走哪条分支都只返回**一个**名字。
fn cname_winner(sub_up: &str, cname_res: &[&UpstreamAnswer]) -> String {
    if sub_up.is_empty() {
        winner_of(cname_res)
    } else {
        sub_up.to_string()
    }
}

/// 「获胜上游」= 真正提供 `chosen` 这个答案的上游 id；找不到则回退首个有答案的上游。
fn winner_up_name(ok: &[&UpstreamAnswer], chosen: &str) -> String {
    if !chosen.is_empty() {
        if let Some(r) = ok
            .iter()
            .find(|r| r.answers.iter().any(|a| a.value == chosen))
        {
            return r.up_name.clone();
        }
    }
    ok.first().map(|r| r.up_name.clone()).unwrap_or_default()
}

/// trace 文本拼装（仅人工查询路径调用；避免为单条 trace 触发多次 `format!`）。
pub(crate) fn fmt_text(a: &str, b: &str, c: &str, e: &str) -> String {
    let mut s = String::with_capacity(a.len() + b.len() + c.len() + e.len());
    let _ = write!(s, "{a}{b}{c}{e}");
    s
}

/// 强制 IP 与查询类型不匹配的 trace 文本（无嵌套 `format!`）。
pub(crate) fn fmt_forceip_mismatch(ip: &str, qtype: &str) -> String {
    let mut s = String::with_capacity(16 + ip.len() + qtype.len());
    let _ = write!(s, "forceIp {ip} 与 {qtype} 不匹配 → NODATA");
    s
}

/// 上游选择 trace 文本：`上游选择(实测延迟排序): 首选 a / b / 备份 c / d`。
///
/// 直接拼装并预分配容量（旧实现 `upstream_names(...).join(" / ")` 会为每个上游
/// 先克隆 `String`、再收集成 `Vec`、再 join，共 3 次分配）。
pub(crate) fn fmt_upstream_choice(primary: &[UpstreamCfg], backup: &[UpstreamCfg]) -> String {
    let mut s = String::with_capacity(64 + (primary.len() + backup.len()) * 12);
    s.push_str("上游选择(实测延迟排序): 首选 ");
    push_names(&mut s, primary);
    s.push_str(" / 备份 ");
    push_names(&mut s, backup);
    s
}

fn push_names(s: &mut String, ups: &[UpstreamCfg]) {
    for (i, u) in ups.iter().enumerate() {
        if i > 0 {
            s.push_str(" / ");
        }
        let n: &str = if u.name.is_empty() { &u.id } else { &u.name };
        s.push_str(n);
    }
}

trait ResolveResultExt {
    fn with_latency(self, ms: f64) -> Self;
}
impl ResolveResultExt for ResolveResult {
    fn with_latency(mut self, ms: f64) -> Self {
        self.latency = ms;
        self
    }
}

/// **[历史归因]** 候选汇总中间态（对齐 Python `cand[v]` dict：value/ttl/type + `lat` / `probe`）。
struct CandEntry {
    value: String,
    ttl: f64,
    rtype: u16,
    /// 静态兜底延迟（ms）：首个贡献该答案的上游应答延迟。
    static_lat: f64,
    /// 探测模式：`udp53` / `tcp443`。仅在测速开关开启时才回填（否则 `None`）。
    probe: Option<&'static str>,
}

/// M2 FORMERR 预检：逐标签 >63 或线格式总长 >255 字节。
fn label_invalid(d: &str) -> bool {
    let mut wire_len: usize = 1; // 根终止符
    for lab in d.split('.') {
        let ll = lab.len();
        wire_len += 1 + ll;
        if ll > 63 || wire_len > 255 {
            return true;
        }
    }
    false
}

// >>> 245 gen-gate tests BEGIN
#[cfg(test)]
mod fix245_gen_gate_tests {
    use super::*;
    use crate::clock::MockClock;
    use crate::config::{ResolverConfig, UpstreamCfg};
    use crate::query::ScriptedQuerier;
    use crate::telemetry::NoopTelemetry;
    use ebpdns_cache::DnsCache;
    use ebpdns_proto::constants::RCODE_NXDOMAIN;

    fn one_up() -> Arc<Resolver> {
        let cfg = ResolverConfig::test_default(vec![UpstreamCfg::test_up("u1")], vec![], 1);
        Resolver::new(
            cfg,
            Arc::new(NoopTelemetry),
            Arc::new(MockClock::new(1_700_000_000.0)),
            Arc::new(ScriptedQuerier::new(|_, _, _| Vec::new())),
        )
    }

    /// **2.1.45（P1-3/P1-4）**：`gen` 变化后旧答案写入被拒、新答案可写 ——
    /// 且 `put_negative` 与 `fill_cache_capped` **两条路径口径一致**。
    #[test]
    fn stale_gen_is_dropped_and_current_gen_is_accepted_on_both_paths() {
        let r = one_up();
        let now = 1_700_000_000.0;
        let ck_neg = r.ckey_normalized("neg-gen.test", "A");
        let ck_pos = r.ckey_normalized("pos-gen.test", "A");
        let g0 = r.rule_gen();

        // ① 模拟"上游 RTT 期间规则重建"：入口代 g0 ≠ 当前代 g1。
        r.test_bump_gen();
        let g1 = r.rule_gen();
        assert_ne!(g0, g1, "test_bump_gen 必须真的推进规则代");
        r.put_negative(&ck_neg, "neg-gen.test", "A", RCODE_NXDOMAIN, 30, Some(g0));
        r.fill_cache(
            &ck_pos,
            "pos-gen.test",
            "A",
            vec![crate::types::ResolveAnswer::new("1.2.3.4", 60.0, 1)],
            Some(g0),
        );
        assert!(
            r.cache().get(&ck_neg, now).is_none(),
            "旧代**负**缓存写入必须被拒（不得盖成新代际）"
        );
        assert!(
            r.cache().get(&ck_pos, now).is_none(),
            "旧代**正**缓存写入必须被拒（两条路径同口径）"
        );
        assert_eq!(
            r.stale_gen_dropped(),
            2,
            "两条路径各计一次 stale_gen_dropped"
        );

        // ② 当代：两条路径都可写。
        r.put_negative(&ck_neg, "neg-gen.test", "A", RCODE_NXDOMAIN, 30, Some(g1));
        r.fill_cache(
            &ck_pos,
            "pos-gen.test",
            "A",
            vec![crate::types::ResolveAnswer::new("1.2.3.4", 60.0, 1)],
            Some(g1),
        );
        assert!(r.cache().get(&ck_neg, now).is_some(), "当代负缓存可写");
        assert!(r.cache().get(&ck_pos, now).is_some(), "当代正缓存可写");
        assert_eq!(r.stale_gen_dropped(), 2, "当代写入不得再增加丢弃计数");
    }
}
// <<< 245 gen-gate tests END
