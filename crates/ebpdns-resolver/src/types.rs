//! resolver 编排层的结构化类型：上游应答（quorum 表决单位）、解析结果、候选、trace。

/// **2.1.40**：`ResolveResult::reason` 的显式取值 —— 本地策略短路。
///
/// 语义：这条应答**既没查缓存、也没发上游**，只是在构造缓存键之前按
/// `prefer_ipv4` / `ipv6` 配置直接给出 NOERROR/NODATA。2.1.39 及以前这类
/// 结果的 `reason` 为 `None`，数据面据此把它归为 `AnswerSource::Upstream`
/// 并记一次 `miss`，污染 `hit_rate`。2.1.40 起改用本常量显式标记，数据面
/// 单独计 `policy_filtered_total`（不计 hit/miss/upstream/error）。
pub const REASON_POLICY_FILTERED: &str = "policy_filtered";

/// 一条答案记录（结构化结果 / CNAME 链展开用）。`name` 为可选 owner name：
/// CNAME 链中后续 RR 的 owner 应为 CNAME 目标域名（RFC 1034），无 `name` 时用查询域名。
#[derive(Clone, Debug, PartialEq)]
pub struct ResolveAnswer {
    pub value: String,
    pub ttl: f64,
    pub rtype: u16,
    /// owner name（CNAME 链目标）；None 表示用查询域名 enc_owner。
    pub name: Option<String>,
}

impl ResolveAnswer {
    pub fn new(value: impl Into<String>, ttl: f64, rtype: u16) -> Self {
        Self {
            value: value.into(),
            ttl,
            rtype,
            name: None,
        }
    }
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
}

/// 单上游应答（`query_parallel` 返回的 quorum 表决单位）。
/// **[历史归因]** 对齐 Python classify_one 产出的 dict：`{rcode, answers, up_name, lat, cnames, ...}`。
#[derive(Clone, Debug, Default)]
pub struct UpstreamAnswer {
    pub up_name: String,
    /// None = 上游失败（超时/网络错误）；Some(rcode) 为真实应答码。
    pub rcode: Option<u8>,
    pub answers: Vec<ResolveAnswer>,
    /// CNAME 链：(目标域名, ttl)。
    pub cnames: Vec<(String, u32)>,
    pub lat: f64,
    /// UDP TC=1 截断且 TCP 回退失败 → 答案不完整，不得冒充 NODATA 证据。
    pub udp_truncated: bool,
    /// authority 段 SOA minimum（负缓存权威 TTL）。
    pub neg_ttl: Option<u32>,
    /// M8：贡献此应答的上游是否豁免私有地址过滤（allow_private_ip）。
    pub allow_private: bool,
    /// **2.1.29**：未知 qtype 透传用的**上游原始响应字节**。
    ///
    /// 只在 [`crate::query::ParallelQuerier::query_parallel_raw`] 路径填充；
    /// 受理类型的解析路径恒为 `None`（不保留原始报文，省一次堆分配）。
    pub raw: Option<Vec<u8>>,
}

impl UpstreamAnswer {
    /// 测试便捷：成功带答案。
    pub fn ok(
        up: &str,
        rcode: u8,
        answers: Vec<ResolveAnswer>,
        cnames: Vec<(String, u32)>,
    ) -> Self {
        Self {
            up_name: up.to_string(),
            rcode: Some(rcode),
            answers,
            cnames,
            lat: 10.0,
            udp_truncated: false,
            neg_ttl: None,
            allow_private: false,
            raw: None,
        }
    }
    /// 测试便捷：上游失败。
    pub fn fail(up: &str) -> Self {
        Self {
            up_name: up.to_string(),
            rcode: None,
            answers: Vec::new(),
            cnames: Vec::new(),
            lat: 200.0,
            udp_truncated: false,
            neg_ttl: None,
            allow_private: false,
            raw: None,
        }
    }
}

/// 一条 trace 事件（处理链路可视化）。
#[derive(Clone, Debug, PartialEq)]
pub struct TraceEvent {
    pub tag: String,
    pub text: String,
}

impl TraceEvent {
    pub fn new(tag: &str, text: impl Into<String>) -> Self {
        Self {
            tag: tag.to_string(),
            text: text.into(),
        }
    }
}

/// **2.1.16（功能 2）**：一次**上游扇出**的完整产物（single-flight 共享值）。
///
/// 三件套整体共享，follower 才能拿到与 leader **逐位一致**的补查波次数与 trace 文案：
/// - `.0` = 各上游应答（primary 波 + fallback 波 + F-NX 补查波）；
/// - `.1` = 该次扇出产生的 `eng` trace 文案（按原顺序，由调用方按序写入自己的 trace）；
/// - `.2` = **F-NX 补查波次数**（`candidates` 口径需要，不能由结果反推）。
pub type UpstreamFetch = (Vec<UpstreamAnswer>, Vec<String>, usize);

/// 规则命中信息（数据面事件用）。
///
/// 对齐 v1.9.162 `resolver.py` 在 block / allow / group / forceIp 各分支里的
/// `tel.inc_rule(cat)` + `tel.log(d, qtype, "rule", msg, ..., upstream=..., rule=...)`：
/// - 计数（`rule_hits`）在 [`crate::resolve`] 里**全量**完成（不受事件采样影响）；
/// - 文案/answer/upstream 随 [`ResolveResult`] 冒泡到数据面 `dns.rs`，由
///   [`crate::resolve`] 之外**唯一的**日志口径统一落 `level="rule"` 事件
///   （避免规则路径同时落一条 miss 事件造成重复）。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuleHit {
    /// 规则标签（`ebpdns_rules::rule_label`：屏蔽/放行/强制IP/国内/国外 + match）。
    pub label: String,
    /// 事件文案（对齐 v1.9.162 各规则分支的 msg 文案）。
    pub msg: String,
    /// 展示用 answer（v1.9.162 规则分支为空串；forceIp 为强制 IP）。
    pub answer: String,
    /// 「上游解析」列展示值：`规则屏蔽` / `白名单` / `分流规则`。
    pub upstream: String,
}

/// **2.1.15（P1 低频 SERVFAIL）**：`ResolveResult` 被判为 SERVFAIL 的**结构化归因**。
///
/// 为什么要有它：上一轮两轮压测各出现 0~4 个客户端 SERVFAIL，而服务端 journal
/// **没有任何 ERROR** —— "客户端看到的 SERVFAIL" 与 "内部错误" 此前没有任何能把
/// 二者对上的计数。数据面 `dns.rs` 现在在**唯一出口**按本枚举自增
/// `servfail_total` 的原因维度（`/api/status.counters.servfail_reasons` +
/// `/metrics` 的 `ebpdns_servfail_total`）。
///
/// **5 个分档互斥且完备**（`total == 各档之和`，由单测钉死）：
/// - [`Self::UpstreamTimeout`]：所有上游都没有给出任何有效票，且**至少一条**上游
///   是按 `timeout_ms` 耗尽的（本轮压测里低频 SERVFAIL 的主导形态）；
/// - [`Self::UpstreamNoAnswer`]：上游有应答但**没有任何有效票**（rcode 非 0/3 或
///   应答畸形/被截断且非 NXDOMAIN/NODATA）；
/// - [`Self::NoUpstream`]：配置/规则导致**没有任何可发的上游**（`no-upstream`）；
/// - [`Self::EncodeFailed`]：解析完成但**组包失败**（内部错误，与上游无关）；
/// - [`Self::Panic`]：解析任务 panic 被 `catch_unwind` 隔离（fail-closed）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServfailReason {
    UpstreamTimeout,
    UpstreamNoAnswer,
    NoUpstream,
    EncodeFailed,
    Panic,
}

impl ServfailReason {
    /// 稳定的机器可读键（与 `ebpdns-server::telemetry::SERVFAIL_REASONS` 一一对应）。
    pub fn as_str(self) -> &'static str {
        match self {
            ServfailReason::UpstreamTimeout => "upstream_timeout",
            ServfailReason::UpstreamNoAnswer => "upstream_no_answer",
            ServfailReason::NoUpstream => "no_upstream",
            ServfailReason::EncodeFailed => "encode_failed",
            ServfailReason::Panic => "panic",
        }
    }
}

/// **[历史归因]** `resolve()` 的结构化结果（对齐 Python `_result` dict）。
#[derive(Clone, Debug, Default)]
pub struct ResolveResult {
    pub domain: String,
    pub qtype: String,
    pub answers: Vec<ResolveAnswer>,
    pub chosen: String,
    pub hit: bool,
    pub error: bool,
    pub reason: Option<String>,
    pub rcode: u8,
    pub truncated: bool,
    pub latency: f64,
    pub ttl_left: f64,
    pub empty: bool,
    pub trace: Vec<TraceEvent>,
    /// 命中的规则（含文案）；`None` = 本次解析未命中任何规则。
    /// 规则命中计数已在此前全量自增，本字段只服务「`level="rule"` 事件」。
    pub rule: Option<RuleHit>,
    /// **实际应答本次查询的获胜上游名**（`UpstreamAnswer::up_name`，即上游 `id`）。
    ///
    /// 数据面 `level="hit"/"miss"/"err"` 事件的 `upstream` 列用它，补齐此前恒为空串
    /// 的「上游」列（对齐 v1.9.162 `resolver.py` 的 `tel.log(..., upstream=...)`）：
    /// - 上游解析成功/负应答/截断沿用/全失败：**单一**获胜上游 id（取决定本次结论的
    ///   那组应答中首个，见 `resolve::winner_of`；CNAME 链优先子链获胜上游）；
    /// - 缓存直答：`"缓存直答"`；serve-stale 窗口直答：`"serve-stale"`；
    /// - 本地判定未发上游（`no-upstream`）：`"无上游"`；
    /// - 规则路径（block/allow/group/forceIp）：由 [`RuleHit::upstream`] 给文案
    ///   （`规则屏蔽` / `白名单` / `分流规则`），本字段留空。
    ///
    /// **[历史归因]** **与 v1.9.162 的有意差异（缺陷 P0）**：Python 在上述多上游分支写的是候选列表
    /// （`"a / b / c"`），本字段一律只承载**一个**上游名；空串仅出现在「未进解析引擎」
    /// 的路径（畸形包 / 空 question），由 `ebpdns-server` 侧回退到兜底文案。
    pub up_name: String,
    /// **2.1.15（P1）**：本次被判定为 SERVFAIL 时的结构化归因；`None` = 不是 SERVFAIL。
    ///
    /// 只在**真正产出 SERVFAIL** 的三处设置：`finish_resolve` 的"无有效负结论"出口、
    /// `resolve_inner` 的两处 `no-upstream` 出口，以及数据面组包失败/panic 兜底
    /// （后两者由 `ebpdns-server` 的 `dns.rs` 直接覆盖字段）。数据面 `dns.rs` 据此
    /// 在唯一出口自增 `servfail_total` 的原因维度。
    pub servfail_reason: Option<ServfailReason>,
    /// **2.1.17（修复项 3）：本次因 rebind 防护被丢弃的私有/保留地址答案条数。**
    ///
    /// 为什么必须结构化回传（而不是让运行侧去解析 trace 文案）：
    /// 「RFC1918 应答按设计不入缓存」这件事在 2.1.16 只能靠 `trace` 里的
    /// `rebind: 丢弃私有地址答案 N 条` 中文文案间接推断，而 `counters.rebind_blocked`
    /// 恒为 0（它统计的是**控制面**的 DNS-rebinding 拦截，不是数据面的私网答案过滤），
    /// 因此审计侧只能得出「缓存坏了」的错误结论。现在把条数**结构化**冒泡到数据面出口，
    /// 由 [`crate::ResolveResult`] 的消费者（`ebpdns-server::dns::log_and_count`）
    /// 累加 `counters.cache_skipped_private_total`（见 `telemetry.rs` 同名键），
    /// 于是「私网答案被过滤 ⇒ 该结果不入缓存」变成**可直接观测的计数**。
    ///
    /// 语义：**仅统计被丢弃的 A/AAAA 候选条数**（不含「全部答案都是私网 ⇒ NODATA」
    /// 时额外计 1 的语义，见 `resolve.rs` 的单测 `s17_private_answer_filter_is_counted`）。
    /// 0 = 本次没有任何私有地址被丢弃（绝大多数查询）。
    pub private_answers_filtered: u32,
}

impl ResolveResult {
    /// 构造一个错误结果（fail-closed：rcode=2 SERVFAIL）。
    pub fn error(
        d: impl Into<String>,
        qtype: impl Into<String>,
        reason: impl Into<String>,
        trace: Vec<TraceEvent>,
    ) -> Self {
        Self {
            domain: d.into(),
            qtype: qtype.into(),
            answers: Vec::new(),
            chosen: String::new(),
            hit: false,
            error: true,
            reason: Some(reason.into()),
            rcode: 2,
            truncated: false,
            latency: 0.0,
            ttl_left: 0.0,
            empty: false,
            trace,
            rule: None,
            up_name: String::new(),
            // `error()` 的 rcode 恒为 2（SERVFAIL），但**原因未定**：调用方
            // （`resolve_inner` / `finish_resolve`）必须用
            // [`ResolveResult::mark_servfail`] 给出结构化归因。
            servfail_reason: None,
            // 错误结果不经过答案过滤（没有候选答案可过滤）。
            private_answers_filtered: 0,
        }
    }
}

impl ResolveResult {
    /// 标记本次为 SERVFAIL 并给出结构化归因（链式，便于在构造点直接写）。
    pub fn mark_servfail(mut self, reason: ServfailReason) -> Self {
        self.servfail_reason = Some(reason);
        self
    }
}
