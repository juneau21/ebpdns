//! **[历史归因]** Resolver 配置：忠实对齐 Python `config.py` 的 `default_config`  relevant 键，
//! 以及 `tests/test_resolver.py::make_resolver` 的 cfg dict 形状。
//!
//! **[历史归因]** 仅保留 resolver 编排层实际消费的字段；默认值与 Python `_fallback` 兜底一致。

use ebpdns_rules::Rule;

/// **2.1.15（P1 高并发 P50/P99 线性恶化）**：`upstream_max_inflight` 的默认值。
///
/// 与 `ebpdns_upstream::DEFAULT_MAX_INFLIGHT_PER_UPSTREAM` **同值同义**（此处复写常量
/// 是为了让 resolver 不依赖 `ebpdns-upstream` 的实现细节；两处的一致性由
/// `ebpdns-resolver` 的单测 [`tests::default_upstream_max_inflight_matches_upstream_crate`]
/// 钉死）。取值依据（32）见 `ebpdns-upstream/src/runtime.rs` 的常量文档。
pub const DEFAULT_UPSTREAM_MAX_INFLIGHT: usize = 32;

/// **[历史归因]** 单个上游运行时配置（对齐 Python 上游 dict 的 `up.get(...)` 读取口径）。
#[derive(Clone, Debug)]
pub struct UpstreamCfg {
    pub id: String,
    pub name: String,
    /// 小写协议名：udp/tcp/doh/dot/doh3/doq。
    pub proto: String,
    pub host: String,
    pub port: u16,
    /// DoH/DoH3 的请求路径（config.json 的 `url`，如 `/dns-query`）。
    /// 空串表示"用协议默认路径"（见 `ebpdns_upstream::request_path`）。
    /// 纯 udp/tcp/dot/doq 无路径，留空。
    pub url: String,
    pub enabled: bool,
    /// 静态基础延迟（ms）。
    pub latency: u32,
    /// 权重（排序 eff_lat / max(1, weight)）。
    pub weight: f64,
    /// group 分流规则归属。
    pub group: Option<String>,
    /// 豁免 rebind 私有地址过滤。
    pub allow_private_ip: bool,
}

impl UpstreamCfg {
    /// 测试便捷构造（对齐 `tests._up`）。
    pub fn test_up(id: &str) -> Self {
        Self {
            id: id.to_string(),
            name: id.to_string(),
            proto: "udp".to_string(),
            host: "127.0.0.1".to_string(),
            port: 53,
            url: String::new(),
            enabled: true,
            latency: 5000,
            weight: 1.0,
            group: None,
            allow_private_ip: false,
        }
    }
}

/// **[历史归因]** Resolver 编排配置。所有阈值与 Python `default_config` / 测试 cfg 一致。
#[derive(Clone, Debug)]
pub struct ResolverConfig {
    pub upstreams: Vec<UpstreamCfg>,
    pub rules: Vec<Rule>,
    pub cache_size: usize,
    /// "lru" / "partitioned" / "tinylfu"。
    pub cache_policy: String,
    pub max_parallel_upstreams: usize,
    /// **2.1.15（P1 高并发 P50/P99 线性恶化）**：**单条上游**的最大在途请求数
    /// （`upstream_max_inflight`）。`0` = 关闭闸门（退回 2.1.14 行为，零开销）。
    ///
    /// 默认 [`crate::config::DEFAULT_UPSTREAM_MAX_INFLIGHT`]（32）：见
    /// `ebpdns-upstream::DEFAULT_MAX_INFLIGHT_PER_UPSTREAM` 的依据说明
    /// （低并发零行为变更；高并发下把排队从"上游侧"搬回"本进程侧"，
    /// 消除"上游越慢 → 对冲越多 → 上游更慢"的正反馈）。
    pub upstream_max_inflight: usize,
    pub timeout_ms: u64,
    pub nxdomain_quorum: usize,
    pub fallback: bool,
    pub rebind_protection: bool,
    pub edns: bool,
    pub prefetch: bool,
    pub speed_test: bool,
    pub ipv6: bool,
    pub prefer_ipv4: bool,
    pub ipv4_first: bool,
    /// 下发 TTL（默认 300）。
    pub ttl: u32,
    pub ttl_min: u32,
    pub ttl_max: u32,
    /// 负缓存（NXDOMAIN / NODATA）TTL 硬上限（秒，默认 60，`0` = 关闭该上限）。
    ///
    /// P1-2 修复：上游 NXDOMAIN 不带 SOA（`neg_ttl=None`）或 SOA minimum 畸大
    /// （如 86400）时，负缓存条目曾按「无上限」落盘 —— 实测 `/api/query` trace 报
    /// 86400s，与 `ttl=300` / `stale_ttl=120` 自相矛盾，且一次单票误判会污染缓存
    /// 一整天。现在**任何**负缓存写入路径都夹取到 `[0, neg_ttl_max]`。
    pub neg_ttl_max: u32,
    pub serve_stale: bool,
    pub stale_ttl: f64,
    /// **[历史归因]** 熔断：连续失败多少次打开（Python `circuit_fails`）。
    pub circuit_fails: u32,
    /// **[历史归因]** 熔断：打开持续秒数（Python `circuit_open_s`；半开为 until 过期自然放行）。
    pub circuit_open_s: f64,
    /// 熔断：指数退避封顶秒数（优化项 5）。第 k 次连续打开 = `min(open_s*2^(k-1), 本值)`。
    pub circuit_open_max_s: f64,
    /// 健康探针独立超时（ms，优化项 2）。`0` = 自动：`min(health_probe_timeout_ms, timeout_ms)`
    /// 下限 250ms —— 探针不得比数据面更"有耐心"（旧默认 2000 > timeout_ms 1500）。
    pub probe_timeout_ms: u64,
    /// 自适应并发/动态对冲（优化项 3）：健康时先发 1 个，`hedge_after_ms` 未回再追加。
    pub adaptive_parallel: bool,
    /// 对冲触发毫秒数（优化项 3）：首选上游超过该时长未回正向答案 → 追加下一个。
    ///
    /// **2.1.11（优化项 3）语义扩展**：本键同时是「**冷启动兜底**」与「p90 不可用时的
    /// 回退值」。一旦本轮候选里任一上游有实测滑窗样本（`production::QuerierTuning::
    /// p90_latency`），触发时刻改为 `max(各候选 p90) × hedge_slowest_factor`（见下键），
    /// 只有**一个样本都没有**时才用本键（默认 200ms，与 2.1.9 逐位一致）。
    pub hedge_after_ms: u64,
    /// **逐上游 p90 对冲因子**（2.1.11 优化项 3；默认 1.0 = 零行为风险）。
    ///
    /// 生效对冲时刻 = `clamp(max(各候选 p90) × 本因子, 1, timeout_ms)`：
    /// - 有 p90 样本时：**用实测 p90 决定何时追加**，而不是固定的 `hedge_after_ms`。
    ///   固定 200ms 的问题（2.1.9 + 2.1.11 真机实测）：公网 DoH/DoH3 的 p90 常在
    ///   250–300ms，而 LAN 上游 p90 约 155ms —— 固定阈值对前者**必然早触发**
    ///   （每个 miss 都白追加候选：实测 `upstream_hedge` 1983 次 / ~2000 miss ≈ 1.0/查询），
    ///   对后者又完全看运气。改成逐上游 p90 后，对冲只在"这台按自己的历史本该回了
    ///   却没回"时才发生，正向路径因此尽早收敛（`early_return` 上升、线速请求下降）。
    /// - 取 **max** 而不是 min：这是**抗放大**的一侧（给最慢候选足够的自证时间）。
    ///   取 min 会在最快上游正常抖动时把多余候选一起放出去，反而抬高 `amp`。
    /// - 默认 `1.0`：生效时刻**就是**最慢候选的实测 p90，不引入任何额外保守/激进余量；
    ///   运维可按自己的抖动幅度调（1.2–2.0 更保守，0.5 更激进）。
    /// - 夹取到 `[1, timeout_ms]`：对冲时刻**不得晚于超时**（否则对冲毫无意义）。
    pub hedge_slowest_factor: f64,
    /// 按上游自适应超时（优化项 4）：`timeout = clamp(k*eff_lat, 下限, timeout_ms)`。
    pub adaptive_timeout: bool,
    /// 自适应超时倍数 k（优化项 4 + P2-A）。
    ///
    /// 生效超时 = `clamp( max(k × p90, p90 × TIMEOUT_P90_MARGIN), 下限, timeout_ms )`：
    /// - 基准是**滑窗 p90**（`production::QuerierTuning::p90_latency`，最近 32 个成功
    ///   样本），不再是算术均值（均值会被单个快样本拉偏且"只降不升"）；
    /// - `production::TIMEOUT_P90_MARGIN = 1.2` 是**抖动安全余量**：`k < 1` 时
    ///   `k × p90` 会小于上游自身 RTT（p90=1500ms、k=0.5 → 750ms）→ 下一轮必然超时；
    ///   余量保证生效超时**不低于观测 p90**；
    /// - 连续 3 次超时（`production::TIMEOUT_UNLOCK_STREAK`）丢弃滑窗样本并回退
    ///   `timeout_ms`（解锁器）。
    ///
    /// 默认 8.0（**实测驱动**）：公网 DoH/DoH3 的 RTT 是重尾分布——实测最快上游均值
    /// 62ms，但单次查询尾部可达数百 ms。用偏小的预算当超时会系统性误杀健康上游
    /// （误杀一次 = 多一轮对冲 + 熔断失败计数 +1，代价远大于"多等 200ms"）。
    pub adaptive_timeout_k: f64,
    /// 自适应超时下限（ms，优化项 4）。
    ///
    /// **默认 1500 = 默认 `timeout_ms`，即默认完全不收紧**（`clamp(k*eff_lat, 1500, 1500)`
    /// 恒等于 `timeout_ms`）→ 默认行为与 v1.9.162 的固定超时**逐位一致**，零上线风险。
    ///
    /// 为什么不默认收紧（实测证据，2026-10-12 真机 192.168.0.236，同一批 20 个真实域名）：
    /// 把下限设为 1000ms 跑 120s 后，实测均值仅 61ms 的 `ali-doh3` 失败率从 **0% 涨到 9.5%**
    /// （7920 ok / 835 fail）——公网 DoH/DoH3 的 RTT 重尾，均值 ×8 仍不足以覆盖尾部；每累计
    /// 3 次失败即熔断 30–120s，最快上游被反复摘掉 → 剩余候选变差 → 回退波全量放出 19 个
    /// 不可达上游 → 22 个上游中 19 个长期 `breaker_open`，`neg_p99` 548ms、出现客户端超时。
    /// 因此**默认不收紧**；需要启用的部署建议 `adaptive_timeout_min_ms >= 1000` 且
    /// `adaptive_timeout_k >= 8`，并在自己的网络上先做与 `timeout_ms` 同口径的 A/B。
    pub adaptive_timeout_min_ms: u64,
    pub edns_udp_size: u32,
    pub edns_client_max_size: u16,
    /// **2.1.43-B（P2-7）：保留键，当前无效果（勿删）**。
    ///
    /// 全树没有**任何行为**读取本键（审计：`grep -rn cache_direct_enabled` 的命中全是
    /// 定义 / 默认值 / 键白名单 / `/api/config`·`/api/pipeline` 回显 / 前端展示），
    /// 计数口径是结构性恒等：`counters.cache_direct ≡ counters.hit`
    /// （`api.rs::cache_direct_projection`，与 `/api/status`、`/api/snapshot`、`/metrics`
    /// 三处同源）。2.1.29 起 eBPF/XDP 内核态缓存已整体移除，本键只描述"用户态口径"。
    ///
    /// 为什么不直接删键：`config.json` 是**对外契约**（随包模板 + 用户存量配置都带它），
    /// 删键会让 `_config_keys` 门禁与用户配置同时漂移。因此按"保留键 + 显式标注无效果"
    /// 处理：结构上仍是可读写字段（`/api/config` 照旧收发），语义上标记
    /// `#[deprecated]`，文档见 `web/INTERFACE.md` 的配置键表。
    #[deprecated(
        note = "2.1.43-B：保留键，当前无效果（不门禁任何行为/计数）。不要删除——config.json 契约键；也不要按它写新逻辑。"
    )]
    pub cache_direct_enabled: bool,
    pub health_check_interval: u64,
    /// 预取触发阈值（TTL 剩余低于此则续入队列）。
    pub prefetch_trigger: f64,
    pub prefetch_interval: f64,
    pub prefetch_target: f64,
    /// 预取队列上界（防随机子域放大堆积）。
    pub prefetch_max: usize,
    /// 规则订阅 URL 列表（HTTP 拉取 → rebuild）。
    pub subscriptions: Vec<String>,
    /// **[历史归因]** 订阅刷新周期（秒，Python `rule_sub_interval`，0=关闭）。
    pub rule_sub_interval: u64,

    /* ---- 持久化缓存（Python DEFAULTS）---- */
    /// 缓存持久化总开关（关闭不写盘也不载入）。
    pub cache_persist: bool,
    /// 持久化恢复后的独立 TTL（秒，0=按保存剩余 TTL 原样恢复）。
    pub persist_ttl: u32,
    /// 分区容量比例（None=默认 0.2/0.2/0.6）。
    pub cache_partitions: Option<serde_json::Value>,

    /* ---- 候选 IP 测速 ---- */
    pub speed_interval_ms: u64,
    pub speed_timeout_ms: u64,
    pub ip_speed_check: bool,
    /// udp53 / tcp443 / both。
    pub ip_speed_probe: String,
    pub ip_speed_cache_ttl: u32,

    /* ---- 查询构造 / 投毒防护 ---- */
    /// 仅加密协议（DoH/DoT/DoQ/DoH3）报文填充至 128B 对齐。
    pub padding: bool,
    /// EDNS 客户端子网（如 "203.0.113.0/24"）。
    pub edns_client_subnet: Option<String>,
    /// DNS 0x20 投毒防护：查询名大小写随机化。
    pub dnssec_0x20: bool,

    /* ---- 引导 / 健康探针 ---- */
    /// DoH/DoT hostname 预解析用的 UDP bootstrap DNS。
    pub bootstrap_dns: String,
    /// 健康检查探测域名。
    pub health_probe_domain: String,
    pub health_probe_timeout_ms: u64,

    /* ---- 2.1.12 优化项 ①：RFC 8020 父域 NXDOMAIN 推断 ---- */
    /// 是否启用 RFC 8020 父域 NXDOMAIN 推导体（登记 + 匹配）。
    ///
    /// **默认 `true`**（建议值，理由见下）。语义与安全边界见 `crate::rfc8020` 模块文档：
    /// 采纳一次**权威 NXDOMAIN** 后登记该名字，其后**该名字自身或其子域**的查询直接回
    /// NXDOMAIN 且**不发上游**（RFC 8020 §Abstract：NXDOMAIN 是"该名字及其以下都不存在"
    /// 的绝对陈述）。压测实测 85% 应答为 NXDOMAIN 而负缓存命中仅 45 次/10954 ——
    /// "每个名字只查一次"的长尾在**结构上**不可能命中答案缓存，本键正是针对该形态。
    ///
    /// 为什么默认 **true**（而不是保守 false）：
    /// 1. 语义正确性由 **RFC 8020** 背书，且登记点**唯一**（只有 `rcode=3` 且达 quorum
    ///    的采纳路径）—— SERVFAIL/超时/NODATA/截断/规则屏蔽/预取链路**全部不登记**；
    /// 2. TTL 与负缓存**同源同夹取**（`neg_ttl_of` → `neg_ttl_max=60s`），最坏影响面
    ///    = 一个已经存在的负缓存条目的影响面，且多出 `serve_stale`/规则指纹双重门禁；
    /// 3. 生效位置在**答案缓存之后**：只对"本来就要发上游"的查询生效，冷/热路径语义
    ///    与 2.1.11 完全一致（首次查询照旧 miss + 上游 + 写负缓存）；
    /// 4. 需要零行为差异时显式置 `false` 即**逐位等价 2.1.11**（有单测门禁）。
    pub rfc8020_infer: bool,
    /// RFC 8020 的**登记/匹配深度上限**（标签数，默认 8）—— 防过度泛化。
    ///
    /// 语义：标签数 **> 本值** 的名字**不登记**（超深域名不登记）；标签数 **> 本值** 的
    /// 查询也**不匹配**（不推断）。默认 8 的依据：与 CNAME 跟随深度上限 `MAX_DEPTH=8`
    /// 同量级 —— 真实域名（含 `_dmarc`/`_domainkey` 之类服务前缀）极少超过 8 个标签，
    /// 而 >8 标签的输入基本都是压测/扫描噪声，登记它们只会白占表空间。
    /// 夹取到 `[1, 127]`（DNS 线格式总长 255B 下标签数不可能超过 127）。
    pub rfc8020_max_labels: usize,

    /* ---- 2.1.12 优化项 ②：上游评分复合键 ---- */
    /// 上游评分的**成功率惩罚下限**（默认 0.5，即惩罚最大 ×2.0）。
    ///
    /// `score = p90 × (1 / max(sr, rating_sr_floor)) × 绝对延迟惩罚`。
    /// 取 0.5 而不是 2.1.11 的 `1/3`：成功率**不是**慢上游的根因，延迟才是。旧口径让
    /// "极低成功率"承担全部区分度（×3），却对"高延迟 + 中等成功率"（实测
    /// `ali-doh 692ms/61.9%`、`lan235 248ms/58.5%`）几乎无作用；2.1.12 把成功率惩罚
    /// **封顶收紧**到 ×2、把区分度交给绝对延迟惩罚（`p90 > 800ms` 额外 ×1.5，见
    /// `lib.rs::RATING_SLOW_P90_MS` / `RATING_SLOW_PENALTY`）。
    /// 下限仍存在（不得为 0）：排序只影响顺序，`max_parallel_upstreams=3` 时必须仍能
    /// 取满候选，绝不允许 `1/sr → ∞` 把刚恢复的上游永久饿死。
    pub rating_sr_floor: f64,

    /* ---- 2.1.16 ①：收包并行化（SO_REUSEPORT N socket） ---- */
    /// UDP 收包 worker（socket）数（`udp_workers`）。
    ///
    /// - `0`（默认）= 自动：`min(可用 CPU 核数, UDP_WORKERS_MAX)`；
    /// - `1` = **退回 2.1.15 旧行为**（单 socket、单 `udp_loop`，逐位等价）；
    /// - `N > 1` = N 个 `SO_REUSEPORT` socket，每个绑定同一地址，内核按 flow 哈希分流，
    ///   每 socket 一个 `udp_loop`，从而让多核并行处理收包 + 回包。
    ///
    /// 兼容性：`SO_REUSEPORT` 会让"端口已被占用"**静默通过**（旧 socket 与新 socket
    /// 同绑成功），因此 `dns.rs::bind_udp` 的**端口占用探测语义**在本值 > 1 时改为
    /// *显式互斥探测*（临时隐式 bind 一次同地址，失败即报 `EADDRINUSE`），见
    /// `crates/ebpdns-server/src/dns.rs::probe_port_free`。
    pub udp_workers: usize,

    /* ---- 2.1.16 ②：在途查询合并（single-flight） ---- */
    /// 同 `CacheKey` 的并发 miss 只发一次上游，其余等待共享结果（`single_flight`）。
    ///
    /// 默认 `true`。语义与取消/超时传播见 `crates/ebpdns-resolver/src/singleflight.rs`。
    /// 置 `false` 逐位退回 2.1.15 的"每个 miss 各自上游"行为（有单测门禁）。
    pub single_flight: bool,

    /* ---- 2.1.16 ⑥：配置 schema 版本 ---- */
    /// 配置 schema 版本（`config_version`）。**当前值 = [`CURRENT_CONFIG_VERSION`]**。
    ///
    /// 缺失该键的旧配置按 [`LEGACY_CONFIG_VERSION`]（1）处理，由 `migrate_cfg`
    /// 分版本迁移到当前版本（见 `crates/ebpdns/src/config_version.rs`）。
    pub config_version: u32,

    /* ---- 2.1.16 ⑨：上游排队治理 / 连接池预热 ---- */
    /// 上游连接池预热总开关（`warmup.enabled`，等价扁平键 `warmup_enabled`）。
    ///
    /// **这次是真的预热**：resolver 构造（以及 `reload` 后上游集合变化时）为每个
    /// 已启用上游**异步**发一条健康探测名查询，把 DoH/DoT/DoQ 的 TLS/QUIC 连接、
    /// UDP socket、`UpstreamRuntime` 滑窗样本一次性建立起来，避免首批真实查询
    /// 承担握手 RTT（实测首批 P99 明显高于稳态）。
    pub warmup_enabled: bool,
    /// 每个上游预热查询条数（`warmup.queries`，夹取到 `[1, 8]`，默认 3）。
    pub warmup_queries: usize,
    /// 预热整体超时（ms，`warmup.timeout_ms`，默认 3000，`0` = 用 `timeout_ms`）。
    pub warmup_timeout_ms: u64,
}

/// 当前配置 schema 版本（**2.1.22 发布值 = 3**）。
///
/// 版本语义（见 `README.md` 的「配置 schema 版本与迁移」）：
/// - **1** = 2.1.0 … 2.1.15（无 `config_version` 键）；
/// - **2** = 2.1.16 … 2.1.21（新增 `udp_workers` / `single_flight` / `warmup.*`）；
/// - **3** = 2.1.22（新增 `state_dir` / `state_persist`；规则唯一真源改为
///   `state/rules.json`，**删除** `config.json` 的 `rules` 镜像键）。
///
/// 迁移**只做加法**：旧版本缺失的键一律补默认值，绝不删除/改写用户已给出的键。
/// **唯一例外**是 2→3 删除 `config.json.rules` 镜像键 —— 它在删之前先做
/// **加法导入**（内容先落 `state/rules.json`），因此信息不丢；见
/// `crates/ebpdns/src/main.rs::migrate_v2_to_v3`。
pub const CURRENT_CONFIG_VERSION: u32 = 3;

/// 缺失 `config_version` 键的旧配置的隐含版本。
pub const LEGACY_CONFIG_VERSION: u32 = 1;

#[allow(deprecated)] // P2-7：出厂默认值仍要初始化该保留键（键必须在 config.json 里）。
impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            upstreams: Vec::new(),
            rules: Vec::new(),
            // A3：默认 16384 而非 131072。实测每条目常驻 ≈117kB（+777 条 → RSS +91MB），
            // 131072 投影 ≈15GB，4GB 机型不可行；16384 投影 ≈1.9GB 且实测 hit 率不变
            // （99.6% 量级，见 P1-1/A3 报告）。
            cache_size: 16_384,
            cache_policy: "lru".to_string(),
            max_parallel_upstreams: 3,
            upstream_max_inflight: DEFAULT_UPSTREAM_MAX_INFLIGHT,
            timeout_ms: 1500,
            nxdomain_quorum: 2,
            fallback: true,
            rebind_protection: true,
            edns: true,
            prefetch: true,
            speed_test: true,
            ipv6: true,
            prefer_ipv4: false,
            ipv4_first: true,
            ttl: 300,
            ttl_min: 0,
            ttl_max: 0,
            neg_ttl_max: 60,
            serve_stale: false,
            stale_ttl: 3600.0,
            circuit_fails: 3,
            circuit_open_s: 30.0,
            circuit_open_max_s: 120.0,
            probe_timeout_ms: 0,
            adaptive_parallel: true,
            hedge_after_ms: 200,
            hedge_slowest_factor: 1.0,
            adaptive_timeout: true,
            // 见 `adaptive_timeout_k` / `adaptive_timeout_min_ms` 的字段注释。
            adaptive_timeout_k: 8.0,
            adaptive_timeout_min_ms: 1500,
            edns_udp_size: 1232,
            edns_client_max_size: 1232,
            cache_direct_enabled: true,
            health_check_interval: 30,
            prefetch_trigger: 60.0,
            prefetch_interval: 300.0,
            prefetch_target: 300.0,
            prefetch_max: 1024,
            subscriptions: Vec::new(),
            rule_sub_interval: 3600,
            cache_persist: true,
            persist_ttl: 0,
            cache_partitions: None,
            speed_interval_ms: 2000,
            speed_timeout_ms: 300,
            ip_speed_check: true,
            ip_speed_probe: "both".to_string(),
            ip_speed_cache_ttl: 60,
            padding: false,
            edns_client_subnet: None,
            dnssec_0x20: true,
            bootstrap_dns: "223.5.5.5:53".to_string(),
            health_probe_domain: "www.baidu.com".to_string(),
            health_probe_timeout_ms: 2000,
            // 2.1.12 优化项 ①：默认开启（理由见字段注释）。与
            // `main.rs::default_config()` / `packaging/etc/ebpdns/config.json` 三处一致。
            rfc8020_infer: true,
            rfc8020_max_labels: 8,
            // 2.1.12 优化项 ②：成功率惩罚下限（默认 0.5 → 最大 ×2.0）。
            rating_sr_floor: 0.5,
            // 2.1.16 ①：0 = 自动（= CPU 核数）；1 = 退回 2.1.15 单 socket 旧行为。
            udp_workers: 0,
            // 2.1.16 ②：默认开启（同键并发 miss 合并为一次上游）。
            single_flight: true,
            // 2.1.16 ⑥：当前 schema 版本。
            config_version: CURRENT_CONFIG_VERSION,
            // 2.1.16 ⑨：上游连接池预热（默认开启，3 条查询，3s 上限）。
            warmup_enabled: true,
            warmup_queries: 3,
            warmup_timeout_ms: 3000,
        }
    }
}

impl ResolverConfig {
    /// 生效的健康探针超时（ms，优化项 2）。
    ///
    /// 规则：显式 `probe_timeout_ms > 0` 时优先（1..60s 夹取）；否则
    /// `min(health_probe_timeout_ms, timeout_ms)`。
    ///
    /// 理由：探针的意义是"提前发现上游不可用"，它不得比任何真实查询更有耐心。
    /// 旧默认 `health_probe_timeout_ms = 2000` **大于** `timeout_ms = 1500`：一次探针会
    /// 比数据面多等 500ms，既拉长一轮健康检查、又让被探上游的判定比用户视角更宽松。
    /// 默认口径因此收敛到 `min(2000, timeout_ms) = timeout_ms`（用户建议的
    /// `min(timeout_ms, 2000)`）；显式配置的小值（测试/内网快上游）原样尊重，不再被人为
    /// 下限抬高。
    pub fn effective_probe_timeout_ms(&self) -> u64 {
        if self.probe_timeout_ms > 0 {
            return self.probe_timeout_ms.clamp(1, 60_000);
        }
        self.health_probe_timeout_ms
            .max(1)
            .min(self.timeout_ms.max(1))
    }

    /// 对齐 `tests/test_resolver.py::make_resolver` 的最小 cfg（测试基座）。
    #[allow(deprecated)] // P2-7：测试基座同样要初始化该保留键（保持与生产默认一致的键集）。
    pub fn test_default(upstreams: Vec<UpstreamCfg>, rules: Vec<Rule>, quorum: usize) -> Self {
        Self {
            upstreams,
            rules,
            cache_size: 64,
            cache_policy: "lru".to_string(),
            max_parallel_upstreams: 3,
            // 测试基座：闸门**关闭**（0）—— 既有脚本化并发断言逐位不变。
            upstream_max_inflight: 0,
            timeout_ms: 200,
            nxdomain_quorum: quorum,
            fallback: true,
            rebind_protection: true,
            edns: false,
            prefetch: false,
            speed_test: false,
            ipv6: true,
            prefer_ipv4: false,
            ipv4_first: true,
            ttl: 300,
            ttl_min: 0,
            ttl_max: 0,
            neg_ttl_max: 60,
            serve_stale: false,
            stale_ttl: 3600.0,
            circuit_fails: 3,
            circuit_open_s: 30.0,
            circuit_open_max_s: 120.0,
            probe_timeout_ms: 0,
            // 测试基座：关闭自适应，确保既有脚本化断言（并发数/超时）逐位不变。
            adaptive_parallel: false,
            hedge_after_ms: 200,
            hedge_slowest_factor: 1.0,
            adaptive_timeout: false,
            adaptive_timeout_k: 8.0,
            adaptive_timeout_min_ms: 1500,
            edns_udp_size: 1232,
            edns_client_max_size: 1232,
            cache_direct_enabled: true,
            health_check_interval: 0,
            prefetch_trigger: 60.0,
            prefetch_interval: 1.0,
            prefetch_target: 300.0,
            prefetch_max: 65536,
            subscriptions: Vec::new(),
            rule_sub_interval: 0,
            cache_persist: false,
            persist_ttl: 0,
            cache_partitions: None,
            speed_interval_ms: 2000,
            speed_timeout_ms: 300,
            ip_speed_check: false,
            ip_speed_probe: "both".to_string(),
            ip_speed_cache_ttl: 60,
            padding: false,
            edns_client_subnet: None,
            dnssec_0x20: false,
            bootstrap_dns: "223.5.5.5:53".to_string(),
            health_probe_domain: "www.baidu.com".to_string(),
            health_probe_timeout_ms: 2000,
            // 2.1.12：**测试基座保持 2.1.11 逐位等价** —— 既有 300+ 用例的断言
            // （含"每个名字只查一次"之外的各种重复解析形态）不因新特性改变结论。
            // 需要覆盖 RFC 8020 的用例显式置 `true`（见 `tests/rfc8020_tests.rs`）。
            rfc8020_infer: false,
            rfc8020_max_labels: 8,
            rating_sr_floor: 0.5,
            // 2.1.16：测试基座**退回 2.1.15 逐位行为** —— 单 socket、无 single-flight、
            // 无预热。需要覆盖新特性的用例显式置值（既有 300+ 脚本化断言不受扰动）。
            udp_workers: 1,
            single_flight: false,
            config_version: CURRENT_CONFIG_VERSION,
            warmup_enabled: false,
            warmup_queries: 3,
            warmup_timeout_ms: 3000,
        }
    }
}

/// **2.1.18（修复项 7）**：`default_config()` 应当出现的**全部顶层配置键**
/// （规范键集，用于"可写 / 只读"划分的完备性门禁）。
///
/// **为什么需要这份清单**（2.1.16 的真实缺陷）：`api.rs::CFG_WRITABLE` 是**逐键枚举**
/// 的冻结白名单，而新增配置键与新增白名单项是两处**独立**改动、没有任何门禁把它们
/// 绑在一起。2.1.16 加了 `single_flight` / `udp_workers` / `warmup` 等键却漏了白名单，
/// 于是这些**用户可配置功能在控制台上不可达**（保存时被归入"忽略的键"，用户以为
/// 保存丢数据 / 改了不生效）。本清单让"新增键必须同时决定它的读写归属"成为**编译期
/// 可见的契约**：
/// - `ebpdns-server` 的单测 `cfg_writable_covers_all_default_top_level_keys` 断言
///   `CONFIG_TOP_LEVEL_KEYS ⊆ (CFG_WRITABLE ∪ CFG_READONLY)` 且两表不相交；
/// - `ebpdns`（binary）的单测 `config_top_level_keys_match_default_config` 断言本清单
///   与 `default_config()` 的键集**逐键相等**（防本清单自身过期）。
///
/// **这是"规范键集"（superset）**：除 `default_config()` 的键外，还包含由
/// `migrate_cfg`/运行期注入的键（`rule_local_file` / `rule_sub_file` / `cache_file`）。
/// 原因：`ebpdns-server` 侧的"可写 ∪ 只读 == 全部"完备性门禁需要它作为**超集**
/// 参照物 —— 那两个路径键**不在** `default_config()` 里，却必须被归类（只读桶）。
///
/// `default_config()` 与它的关系由 `ebpdns` 的单测双向钉死：
/// - `config_top_level_keys_are_a_superset_of_default_config`（不含多余键）；
/// - `config_top_level_keys_covers_all_default_config_keys`（不漏键）。
///
/// `rpz` 尚未在默认配置里，故**不在**本清单（将来加进默认配置时必须同步本清单）。
pub const CONFIG_TOP_LEVEL_KEYS: &[&str] = &[
    "adaptive_parallel",
    "adaptive_timeout",
    "adaptive_timeout_k",
    "adaptive_timeout_min_ms",
    "api",
    "bootstrap_dns",
    "cache_direct_enabled",
    "cache_file",
    "cache_partitions",
    "cache_save_interval",
    "cache_persist",
    "cache_policy",
    "cache_size",
    "circuit_fails",
    "circuit_open_max_s",
    "circuit_open_s",
    "config_version",
    "dns_port",
    "dnssec_0x20",
    "edns",
    "edns_client_max_size",
    "edns_client_subnet",
    "edns_udp_size",
    "fallback",
    "health_check_interval",
    "health_probe_domain",
    "health_probe_timeout_ms",
    "hedge_after_ms",
    "hedge_slowest_factor",
    "ip_speed_cache_ttl",
    "ip_speed_check",
    "ip_speed_probe",
    "ipv4_first",
    "ipv6",
    "listen",
    "log_format",
    "log_level",
    "max_parallel_upstreams",
    "neg_ttl_max",
    "nxdomain_quorum",
    "padding",
    "persist_ttl",
    "prefer_ipv4",
    "prefetch",
    "prefetch_interval",
    "prefetch_max",
    "prefetch_target",
    "prefetch_trigger",
    "probe_timeout_ms",
    "rating_sr_floor",
    "rebind_protection",
    "rfc8020_infer",
    "rfc8020_max_labels",
    "rule_local_file",
    "rule_sub_file",
    "rule_sub_interval",
    "rule_subscriptions",
    "rules",
    "serve_stale",
    "single_flight",
    "speed_interval_ms",
    "speed_test",
    "speed_timeout_ms",
    "stale_ttl",
    // ---- **2.1.22 阶段一（schema version 3）新增的顶层键** ----
    // 统一持久化事务的开关与目录。两者都必须在规范键集里，否则
    // `config_top_level_keys_*` 那组双门禁会立刻红（"default_config 有键、
    // 规范键集没有" = 新键漏登记）。它们在 `api.rs` 里归**只读**桶
    // （路径/进程级启动参数，改了要重启 —— 与 `cache_file` 同口径）。
    "state_dir",
    "state_persist",
    "timeout_ms",
    "ttl",
    "ttl_max",
    "ttl_min",
    "udp_workers",
    "upstream_max_inflight",
    "upstreams",
    "warmup",
    "web_root",
    // ---- **2.1.20（A-12 修复：真被消费的别名键被判"未知键"）** ----
    // 审计 A-12 实测：`PUT {"cb_fails":9}` → `ignored_keys:["cb_fails"]`（同 `cb_open_s`、
    // `prefetch_max`），而这三个键在 `main.rs::apply_cfg` 里**确实被消费**：
    //   * `cb_fails`   → `:2211` `num("circuit_fails").or_else(|| num("cb_fails"))`
    //   * `cb_open_s`  → `:2214` `fnum("circuit_open_s").or_else(|| fnum("cb_open_s"))`
    //   * `prefetch_max` → `:2130` `num("prefetch_max")`
    // 于是"用户写了、程序也读了，接口却说'未知键已忽略'" —— 与 v1.9.162 控制台契约
    // （熔断字段用 `cb_*` 旧名）直接冲突。
    //
    // 归属：三者都是**受支持的别名**，因此进**规范键集 + 可写白名单**
    // （`api.rs::CFG_WRITABLE`），而不是只读桶。它们的**权威名**仍是 `circuit_*`
    // （`validate_write` 同时校验两套名字，见本文件 `rng("cb_fails", …)`）。
    // `prefetch_max` 无对应新名（`prefetch` 是布尔开关），保留原样。
    "cb_fails",
    "cb_open_s",
    // 扁平 warmup.* 别名（pply_cfg 真的读：nested 优先，缺失才用扁平）。
    "warmup_enabled",
    "warmup_queries",
    "warmup_timeout_ms",
];

/// **2.1.19（F-04/F-07）**：整数配置键的**权威范围表**（**单一来源**）。
///
/// 为什么需要它（P1 缺陷）：范围此前散在**三处**且互相不一致 ——
/// ① 本文件 `validate_write`（后端拒绝判据）；② `main.rs::validate_schema`（启动校验）；
/// ③ 控制台 `web/src/pages/config.rs` 的 `dom_clamped(...)`（前端 clamp）。
/// 实测：前端把 `cache_size` 钳到 `[1, 1e7]` 而后端只接受 `[16, 4194304]` ⇒ 用户输入
/// `10000000` 被前端"视为合法"，`PUT /api/config` 回 **400**；而 PUT 是**整份提交**
/// ⇒ **一个坏值让所有编辑一起失败**（用户只能看到"未写入任何键"）。
///
/// 约定：本表是**唯一**来源；`validate_write` 对它逐条校验，
/// 控制台通过 `/api/status.config_ranges` **在运行期读取同一份表**做 clamp，
/// 另有机器校验单测（`config_ranges_match_validate_write_boundaries` 与
/// `web::range_consistency`）防止两侧再次漂移。
///
/// 语义：`(键, 最小, 最大)`；**`0` 是否合法由表本身表达**（"0 = 关闭"的键下限就是 0）。
pub const CONFIG_RANGES: &[(&str, u64, u64)] = &[
    // 缓存 / TTL
    ("cache_size", 16, 4_194_304),
    ("cache_save_interval", 0, 86_400),
    ("ttl", 0, 604_800),
    ("ttl_min", 0, 604_800),
    ("ttl_max", 0, 604_800),
    ("neg_ttl_max", 0, 86_400),
    ("stale_ttl", 0, 604_800),
    ("persist_ttl", 0, 31_536_000),
    // **2.1.20（F-02）**：预取周期/队列上界（此前 prefetch_interval **没有 JSON 键**）。
    ("prefetch_interval", 1, 86_400),
    ("prefetch_max", 1, 1_000_000),
    // 测速 / 并发
    ("speed_interval_ms", 100, 600_000),
    ("speed_timeout_ms", 1, 60_000),
    ("ip_speed_cache_ttl", 0, 86_400),
    ("max_parallel_upstreams", 1, 64),
    ("upstream_max_inflight", 0, 4096),
    ("timeout_ms", 1, 60_000),
    ("nxdomain_quorum", 1, 64),
    ("udp_workers", 0, 64),
    ("rfc8020_max_labels", 1, 127),
    ("warmup_queries", 1, 8),
    ("warmup_timeout_ms", 1, 60_000),
    // EDNS
    ("edns_udp_size", 512, 65_535),
    ("edns_client_max_size", 512, 65_535),
    // 健康 / 订阅（**0 = 关闭**）
    ("health_check_interval", 0, 86_400),
    ("health_probe_timeout_ms", 1, 60_000),
    ("rule_sub_interval", 0, 604_800),
    // 熔断 / 自适应（**整数**键；`circuit_open_s` 等是浮点键，见 `frng` 调用）
    ("circuit_fails", 1, 1000),
    ("cb_fails", 1, 1000),
    ("probe_timeout_ms", 0, 60_000),
    ("hedge_after_ms", 1, 60_000),
    ("adaptive_timeout_min_ms", 1, 60_000),
    // ---- **2.1.21（DEF-220-02 / A-15 修复：补齐"可写但无控件"的整数键）** ----
    // 这 3 个键此前**可写但既无控件、也不在 `CONFIG_RANGES`** ⇒ 控制台只能靠
    // 硬编码默认值兜底（`fmtnum::CONFIG_RANGE_FALLBACK` 里也没有），
    // 现在它们与控制台新控件**成对出现**（见 `CONFIG_RANGE_FALLBACK` 的同步测试）。
    //
    // 另外 9 个新控件键（`cache_save_interval` / `neg_ttl_max` / `prefetch_interval` /
    // `prefetch_max` / `nxdomain_quorum` / `edns_client_max_size` / `probe_timeout_ms` /
    // `hedge_after_ms` / `adaptive_timeout_min_ms`）**本来就在**本表里
    // （2.1.19 起），因此**不重复添加** —— `config_ranges_have_no_duplicate_or_inverted_entries`
    // 会拦住重复键（第一版就踩过 `nxdomain_quorum` 与 `edns_client_max_size` 各一次）。
    ("prefetch_trigger", 0, 604_800),
    ("prefetch_target", 0, 604_800),
    ("circuit_open_max_s", 1, 604_800),
];

/// **2.1.19（F-04）**：查一个整数键的权威范围。
pub fn config_range_of(key: &str) -> Option<(u64, u64)> {
    CONFIG_RANGES
        .iter()
        .find(|(k, _, _)| *k == key)
        .map(|(_, lo, hi)| (*lo, *hi))
}

/// **2.1.19（F-04/F-07）**：把权威范围表下发给控制台（`/api/status.config_ranges`）。
///
/// 控制台据此 clamp ⇒ **前端不可能再摆出后端会拒绝的值**；本地兜底表只用于
/// 旧后端（不返回该字段）。
pub fn config_ranges_json() -> serde_json::Value {
    serde_json::Value::Array(
        CONFIG_RANGES
            .iter()
            .map(|(k, lo, hi)| serde_json::json!({"key": k, "min": lo, "max": hi}))
            .collect(),
    )
}

/// **2.1.18（修复项 7：控制台可写键可达性）**：配置**写入侧**的取值校验
/// （键 → 类型 / 范围）。返回人类可读的错误列表（空 = 通过）。
///
/// **为什么放在 resolver crate**：`PUT /api/config` 的**拒绝判据**与
/// `ebpdns check-config` 的**诊断判据**必须是**同一份实现** —— 否则会出现
/// 「控制台能存进去、但 check-config 报错」或反过来（同一份配置两套结论）。
/// 因此：范围/类型规则在这里，`main.rs::validate_schema` 与
/// `api.rs::put_config` 都调用本函数（`main.rs` 额外叠加 listen/api/未知键等检查）。
///
/// 覆盖范围（与 `main.rs::apply_cfg` 的读取口径**逐条对齐**，含 `cb_*` 别名）：
/// - 整数范围：`... `；
/// - 浮点必须有限且落在区间（`NaN`/`inf`/负数一律拒绝 —— 它们在 `apply_cfg` 里
///   会被静默忽略或夹取，用户会以为"保存生效了"）；
/// - 布尔键必须是布尔（`"true"` 字符串在 JSON 里是类型错，不做隐式转换）。
///
/// **只校验"出现过的键"**：缺失键不报错（由 `default_config()` 兜底），
/// 因此本函数既能校验"整份配置"（check-config），也能校验"用户提交的那几个键"
/// （PUT 拒绝坏值）。嵌套键用点号路径表达（`warmup.queries`）。
pub fn validate_write(cfg: &serde_json::Value) -> Vec<String> {
    let mut err: Vec<String> = Vec::new();
    let Some(o) = cfg.as_object() else {
        return vec!["配置根节点必须是 JSON 对象".to_string()];
    };
    let num = |k: &str| o.get(k).and_then(|v| v.as_u64());
    let fnum = |k: &str| o.get(k).and_then(|v| v.as_f64());
    let func = |k: &str| o.get(k).and_then(|v| v.as_bool());
    let rng = |k: &str, lo: u64, hi: u64, err: &mut Vec<String>| {
        if let Some(v) = o.get(k) {
            match num(k) {
                Some(n) if n >= lo && n <= hi => {}
                Some(n) => err.push(format!("`{k}` = {n} 超出允许范围 [{lo}, {hi}]")),
                None => err.push(format!("`{k}` 必须是整数，实际为 {v}")),
            }
        }
    };
    let frng = |k: &str, lo: f64, hi: f64, err: &mut Vec<String>| {
        if let Some(v) = o.get(k) {
            match fnum(k) {
                Some(f) if f.is_finite() && f >= lo && f <= hi => {}
                Some(f) => err.push(format!("`{k}` = {f} 超出允许范围 [{lo}, {hi}]")),
                None => err.push(format!("`{k}` 必须是数值，实际为 {v}")),
            }
        }
    };
    let boolean = |k: &str, err: &mut Vec<String>| {
        if let Some(v) = o.get(k) {
            if func(k).is_none() {
                err.push(format!("`{k}` 必须是布尔（true/false），实际为 {v}"));
            }
        }
    };

    // **2.1.19（F-04/F-07）**：整数范围**只按权威表**校验（单一来源 `CONFIG_RANGES`）。
    // 表里的键此前散落在本函数各段里各写一遍，与控制台 clamp / 启动期校验三处分叉；
    // 现在：范围的含义只由表表达，`web/src/pages/config.rs` 通过
    // `/api/status.config_ranges` 读取同一份表。
    for (k, lo, hi) in CONFIG_RANGES {
        rng(k, *lo, *hi, &mut err);
    }

    // ---- 缓存 / TTL ----
    // **2.1.18（修复项 12）**：`cache_partitions` 的正确形状是
    // **对象** `{group: weight}`（负数钳 0、再归一化到和为 1），`null` = 默认
    // 0.2/0.2/0.6。旧文档写的"整数 4"从来**没有被实现消费过**：这里保持
    // **接受但忽略**（不判 ERROR，避免既有配置被 `check-config` 判非法），
    // 由 `main.rs::validate_schema` 给显式告警。
    match o.get("cache_partitions") {
        None | Some(serde_json::Value::Null) => {}
        Some(serde_json::Value::Object(m)) => {
            for (k, v) in m {
                match v.as_f64() {
                    Some(f) if f >= 0.0 && f.is_finite() => {}
                    _ => err.push(format!(
                        "`cache_partitions.{k}` 必须是非负数字（group→权重），实际为 {v}"
                    )),
                }
            }
        }
        // 整数/字符串等旧形状：接受但忽略（告警在 `validate_schema`）。
        Some(_) => {}
    }
    // **2.1.18（修复项 10）**：缓存定期落盘间隔（秒）。`0` = 只在优雅退出时落盘。
    // 语义与实现见 `crates/ebpdns/src/main.rs`（周期任务）与 README「缓存持久化」。
    for k in ["prefetch", "serve_stale", "cache_persist"] {
        boolean(k, &mut err);
    }
    if let Some(p) = o.get("cache_policy") {
        match p.as_str() {
            Some(s)
                if matches!(
                    s.trim().to_ascii_lowercase().as_str(),
                    "lru" | "tinylfu" | "w-tinylfu" | "partitioned" | "partition"
                ) => {}
            _ => err.push(format!(
                "`cache_policy` = {p} 不是合法值（允许: lru | tinylfu | partitioned）"
            )),
        }
    }

    // ---- 用户态缓存直答开关 ----
    boolean("cache_direct_enabled", &mut err);

    // ---- 测速 / 并发 ----
    for k in ["speed_test", "ip_speed_check", "fallback"] {
        boolean(k, &mut err);
    }
    if let Some(p) = o.get("ip_speed_probe") {
        match p.as_str().map(|s| s.trim().to_ascii_lowercase()) {
            Some(ref s)
                if matches!(
                    s.as_str(),
                    "udp53" | "tcp443" | "both" | "udp" | "tcp" | "none"
                ) => {}
            _ => err.push(format!(
                "`ip_speed_probe` = {p} 不是合法值（允许: udp53 | tcp443 | both | none）"
            )),
        }
    }

    // ---- 2.1.18（修复项 7）：新纳入白名单的调参键 ----
    // `udp_workers`：0 = 自动（CPU 核数，封顶 8）；1 = 旧单 socket 行为；N>1 = 每地址 N 个 SO_REUSEPORT。
    boolean("single_flight", &mut err);
    boolean("rfc8020_infer", &mut err);
    frng("rating_sr_floor", 1e-3, 1.0, &mut err);
    frng("hedge_slowest_factor", 1e-3, 100.0, &mut err);

    // ---- warmup（**对象键**：整体替换，子键逐个校验）----
    //
    // 语义（与 `main.rs::apply_cfg` 对齐）：`warmup` 可以是对象，也可以完全缺失；
    // 缺失时另有扁平别名 `warmup_enabled` / `warmup_queries` / `warmup_timeout_ms`。
    // 校验必须同时覆盖两种写法，否则"扁平别名能写坏"。
    if let Some(w) = o.get("warmup") {
        match w.as_object() {
            Some(wo) => {
                if let Some(v) = wo.get("enabled") {
                    if v.as_bool().is_none() {
                        err.push(format!("`warmup.enabled` 必须是布尔，实际为 {v}"));
                    }
                }
                if let Some(v) = wo.get("queries") {
                    match v.as_u64() {
                        Some(n) if (1..=8).contains(&n) => {}
                        Some(n) => err.push(format!("`warmup.queries` = {n} 超出允许范围 [1, 8]")),
                        None => err.push(format!("`warmup.queries` 必须是整数，实际为 {v}")),
                    }
                }
                if let Some(v) = wo.get("timeout_ms") {
                    match v.as_u64() {
                        Some(n) if (1..=60_000).contains(&n) => {}
                        Some(n) => {
                            err.push(format!("`warmup.timeout_ms` = {n} 超出允许范围 [1, 60000]"))
                        }
                        None => err.push(format!("`warmup.timeout_ms` 必须是整数，实际为 {v}")),
                    }
                }
            }
            None => err.push(format!(
                "`warmup` 必须是对象（含 enabled/queries/timeout_ms），实际为 {w}"
            )),
        }
    }
    boolean("warmup_enabled", &mut err);

    // ---- 双栈 / EDNS ----
    for k in [
        "ipv6",
        "prefer_ipv4",
        "ipv4_first",
        "edns",
        "padding",
        "dnssec_0x20",
    ] {
        boolean(k, &mut err);
    }
    if let Some(v) = o.get("edns_client_subnet") {
        if v.as_str().is_none() {
            err.push(format!("`edns_client_subnet` 必须是字符串，实际为 {v}"));
        }
    }
    boolean("rebind_protection", &mut err);

    // ---- 健康检查 ----
    // **2.1.19（F-04 修复）**：下限必须是 **0**（= 关闭周期健康检查）。
    // 实现侧 `background.rs:44` 就是 `if cfg.health_check_interval > 0 { spawn }`，
    // 且 `default_config()`/启动期都接受 0 —— 此前这里写 `1..=86400` ⇒ **配置里已有 0
    // 的部署，控制台每次"应用配置"都会被 400 拒绝**（"未写入任何键"），用户无法保存
    // 任何其它改动。范围必须与"0 = 关闭"的语义一致。
    if let Some(v) = o.get("health_probe_domain") {
        match v.as_str() {
            Some(s) if !s.trim().is_empty() => {}
            _ => err.push(format!(
                "`health_probe_domain` 必须是非空字符串，实际为 {v}"
            )),
        }
    }

    // ---- 日志 ----
    if let Some(v) = o.get("log_level") {
        match v.as_str().map(|s| s.trim().to_ascii_lowercase()) {
            Some(ref s)
                if matches!(
                    s.as_str(),
                    "trace" | "debug" | "info" | "warn" | "error" | "off"
                ) => {}
            _ => err.push(format!(
                "`log_level` = {v} 不是合法值（trace|debug|info|warn|error）"
            )),
        }
    }
    if let Some(v) = o.get("log_format") {
        match v.as_str().map(|s| s.trim().to_ascii_lowercase()) {
            Some(ref s) if matches!(s.as_str(), "text" | "plain" | "json") => {}
            _ => err.push(format!("`log_format` = {v} 不是合法值（text|json）")),
        }
    }
    // **2.1.19（F-04 修复）**：下限必须是 **0**（= 关闭订阅自动刷新）。
    // `ResolverConfig::rule_sub_interval` 的文档（本文件 `:174`）与实现
    // （`subscribe.rs` 的"0 = 关闭"）都把 0 当作合法值，此前这里写 `60..` ⇒
    // 配置里为 0 的部署**无法通过控制台保存任何改动**。范围必须与语义一致。

    // ---- 熔断 / 自适应（含 `cb_*` 兼容别名，与 `apply_cfg` 同口径）----
    frng("circuit_open_s", 1.0, 86_400.0, &mut err);
    frng("cb_open_s", 1.0, 86_400.0, &mut err);
    frng("circuit_open_max_s", 1.0, 604_800.0, &mut err);
    frng("adaptive_timeout_k", 0.1, 1000.0, &mut err);
    for k in ["adaptive_parallel", "adaptive_timeout"] {
        boolean(k, &mut err);
    }
    if let Some(v) = o.get("bootstrap_dns") {
        // **2.1.18（修复项 21）**：接受**两种形状**（出厂默认用的是数组形状）：
        // ① 字符串 `"223.5.5.5:53"`（历史形状）；② 数组 `["223.5.5.5:53", ...]`
        // （用户配置与出厂默认的形状）。两者在 `main.rs` 里被归一为同一个
        // `bootstrap_dns: String`（数组用空格连接后取第一个），因此语义等价。
        let ok = match v {
            serde_json::Value::String(s) => !s.trim().is_empty(),
            serde_json::Value::Array(a) => {
                !a.is_empty()
                    && a.iter()
                        .all(|x| x.as_str().map(|s| !s.trim().is_empty()).unwrap_or(false))
            }
            _ => false,
        };
        if !ok {
            err.push(format!(
                "`bootstrap_dns` 必须是字符串 \"host:port\" 或非空字符串数组（如 [\"223.5.5.5:53\"]），实际为 {v}"
            ));
        }
    }

    // ---- 上游列表（写路径结构校验；逐条与 `upstreams_create/update` 同口径）----
    if let Some(ups) = o.get("upstreams") {
        match ups.as_array() {
            Some(list) => {
                for (i, u) in list.iter().enumerate() {
                    let Some(uo) = u.as_object() else {
                        err.push(format!("`upstreams[{i}]` 必须是对象"));
                        continue;
                    };
                    for k in ["id", "proto", "host"] {
                        if uo
                            .get(k)
                            .and_then(|v| v.as_str())
                            .map(|s| !s.trim().is_empty())
                            != Some(true)
                        {
                            err.push(format!("`upstreams[{i}].{k}` 缺失或为空"));
                        }
                    }
                    if let Some(p) = uo.get("port") {
                        match p.as_u64() {
                            Some(n) if (1..=65_535).contains(&n) => {}
                            Some(n) => {
                                err.push(format!("`upstreams[{i}].port` = {n} 超出范围 [1, 65535]"))
                            }
                            None => {
                                err.push(format!("`upstreams[{i}].port` 必须是整数，实际为 {p}"))
                            }
                        }
                    }
                    if let Some(p) = uo.get("proto").and_then(|v| v.as_str()) {
                        let n = p.trim().to_ascii_lowercase();
                        if !matches!(n.as_str(), "udp" | "tcp" | "doh" | "doh3" | "dot" | "doq") {
                            err.push(format!(
                                "`upstreams[{i}].proto` = {p:?} 不是受支持协议（udp|tcp|doh|doh3|dot|doq）"
                            ));
                        }
                    }
                    // 明文私网豁免与权重（数值性）
                    if let Some(w) = uo.get("weight") {
                        match w.as_f64() {
                            Some(f) if f.is_finite() && f >= 0.0 => {}
                            _ => err.push(format!(
                                "`upstreams[{i}].weight` 必须是非负数值，实际为 {w}"
                            )),
                        }
                    }
                }
            }
            None => err.push(format!("`upstreams` 必须是数组，实际为 {ups}")),
        }
    }
    err
}

#[cfg(test)]
mod tests {
    use super::*;

    /* ============ 2.1.19（F-04/F-07）：权威范围表 = 拒收判据 + 边界值 ============ */

    /// **F-04**：`CONFIG_RANGES` 的边界必须与 `validate_write` 的拒收判据**逐键一致**：
    /// 下界与上界**必须通过**，越界一档**必须被拒**（且错误信息里**点名该键**）。
    ///
    /// 这条同时挡住两类回归：①表里有键但 `validate_write` 不校验（等于没有约束）；
    /// ②表与判据分叉（正是"前端 clamp 与后端拒绝不一致 ⇒ 一个坏值让整份提交失败"的根因）。
    #[test]
    fn config_ranges_match_validate_write_boundaries() {
        assert!(
            CONFIG_RANGES.len() >= 25,
            "权威范围表条目过少（{}）—— 疑似被误删",
            CONFIG_RANGES.len()
        );
        for (k, lo, hi) in CONFIG_RANGES {
            let ok_lo = validate_write(&serde_json::json!({ *k: lo }));
            assert!(
                ok_lo.is_empty(),
                "`{k}` = {lo}（下界）必须被接受，实际被拒：{ok_lo:?}"
            );
            let ok_hi = validate_write(&serde_json::json!({ *k: hi }));
            assert!(
                ok_hi.is_empty(),
                "`{k}` = {hi}（上界）必须被接受，实际被拒：{ok_hi:?}"
            );
            if *lo > 0 {
                let bad = validate_write(&serde_json::json!({ *k: lo - 1 }));
                assert!(!bad.is_empty(), "`{k}` = {}（低于下界）必须被拒", lo - 1);
                assert!(
                    bad.iter().any(|e| e.contains(k)),
                    "`{k}` 的拒收原因必须点名该键，实际：{bad:?}"
                );
            }
            let bad_hi = validate_write(&serde_json::json!({ *k: hi + 1 }));
            assert!(!bad_hi.is_empty(), "`{k}` = {}（高于上界）必须被拒", hi + 1);
            assert!(
                bad_hi.iter().any(|e| e.contains(k)),
                "`{k}` 的拒收原因必须点名该键，实际：{bad_hi:?}"
            );
        }
    }

    /// **F-04（"0 = 关闭"）**：`health_check_interval` / `rule_sub_interval` /
    /// `cache_save_interval` 的 **0 必须合法** —— 实现侧（`background.rs`、
    /// `subscribe.rs`、周期落盘任务）都以 `> 0` 判断是否启用。此前下限写 1 / 60
    /// ⇒ 配置里已有 0 的部署**无法通过控制台保存任何改动**（整份 PUT 被 400）。
    #[test]
    fn zero_means_disabled_keys_accept_zero() {
        for k in [
            "health_check_interval",
            "rule_sub_interval",
            "cache_save_interval",
        ] {
            assert_eq!(
                config_range_of(k).map(|(lo, _)| lo),
                Some(0),
                "`{k}` 的下界必须是 0（0 = 关闭）"
            );
            let errs = validate_write(&serde_json::json!({ k: 0 }));
            assert!(
                errs.is_empty(),
                "`{k}` = 0 必须被接受（0 = 关闭），实际：{errs:?}"
            );
        }
    }

    /// **F-07**：`config_ranges_json()`（下发给控制台的**同一份表**）必须与
    /// `CONFIG_RANGES` 逐条一致 —— 否则"前端 clamp 用一份、后端拒绝用另一份"会复发。
    #[test]
    fn config_ranges_json_matches_table() {
        let v = config_ranges_json();
        let arr = v.as_array().expect("必须是数组");
        assert_eq!(arr.len(), CONFIG_RANGES.len());
        for (item, (k, lo, hi)) in arr.iter().zip(CONFIG_RANGES.iter()) {
            assert_eq!(item["key"], serde_json::json!(k));
            assert_eq!(item["min"], serde_json::json!(lo));
            assert_eq!(item["max"], serde_json::json!(hi));
        }
    }

    /// **2.1.20（A-12）**：`CONFIG_RANGES` 的键必须是**规范键集**的子集 ——
    /// 否则会出现"表里有边界、键集里没有 ⇒ 被当未知键忽略"的矛盾
    /// （审计 A-12 正是用 `cb_fails` 抓到这一点）。
    #[test]
    fn config_ranges_keys_are_all_known_top_level_keys() {
        for (k, _, _) in CONFIG_RANGES {
            assert!(
                CONFIG_TOP_LEVEL_KEYS.contains(k),
                "`{k}` 在 `CONFIG_RANGES` 里有边界，却不在 `CONFIG_TOP_LEVEL_KEYS` 里 \
                 ⇒ 它会被当成未知键忽略（A-12 同类缺陷）"
            );
        }
    }

    /// **2.1.21（DEF-220-02 / A-15）**：范围表**不得有重复键**，且区间方向正确。
    #[test]
    fn config_ranges_have_no_duplicate_or_inverted_entries() {
        use std::collections::HashSet;
        let mut seen: HashSet<&str> = HashSet::new();
        for (k, lo, hi) in CONFIG_RANGES {
            assert!(
                seen.insert(k),
                "`{k}` 在 CONFIG_RANGES 里重复（合并两张表时最易发生）"
            );
            assert!(lo <= hi, "`{k}` 的区间 ({lo}, {hi}) 方向反了");
        }
    }

    /// **2.1.21（DEF-220-02 / A-15）**：12 个"2.1.21 新补控件"的整数键**必须**在权威表里
    /// —— 否则控制台控件拿不到运行期区间，只能退回硬编码默认（正是 A-02 的病根）。
    #[test]
    fn config_ranges_cover_the_newly_controlled_keys() {
        for k in [
            "cache_save_interval",
            "neg_ttl_max",
            "prefetch_interval",
            "prefetch_target",
            "prefetch_trigger",
            "prefetch_max",
            "nxdomain_quorum",
            "edns_client_max_size",
            "probe_timeout_ms",
            "circuit_open_max_s",
            "hedge_after_ms",
            "adaptive_timeout_min_ms",
        ] {
            assert!(
                config_range_of(k).is_some(),
                "`{k}` 已有控制台控件，却不在 CONFIG_RANGES（clamp 会退回硬编码默认值）"
            );
        }
    }

    /// **2.1.20（A-12）**：三个**受支持的历史别名**必须被 `validate_write` 接受且
    /// 在规范键集里（`main.rs::apply_cfg` 真的读它们）。
    #[test]
    fn supported_alias_keys_are_known_and_validated() {
        for k in ["cb_fails", "cb_open_s", "prefetch_max"] {
            assert!(
                CONFIG_TOP_LEVEL_KEYS.contains(&k),
                "`{k}` 是受支持的别名（`apply_cfg` 会读），必须在规范键集里"
            );
        }
        // 别名也必须过校验（越界要被拒），否则"接受但静默夹取"。
        assert!(
            validate_write(&serde_json::json!({"cb_fails": 9})).is_empty(),
            "`cb_fails` 合法值必须通过"
        );
        assert!(
            !validate_write(&serde_json::json!({"cb_fails": 0})).is_empty(),
            "`cb_fails` 越界必须被拒（与 `circuit_fails` 同区间 [1, 1000]）"
        );
        assert!(
            validate_write(&serde_json::json!({"cb_open_s": 30.0})).is_empty(),
            "`cb_open_s` 合法值必须通过"
        );
        // `prefetch_max` 目前**没有**范围约束（只被 apply_cfg 读入），
        // 因此这里只要求"不在未知桶、不被拒绝"，不臆造区间。
        assert!(
            validate_write(&serde_json::json!({"prefetch_max": 8})).is_empty(),
            "`prefetch_max` 不得被拒绝（尚无区间约束，见 A-12 的登记）"
        );
    }

    /// 优化项 2：探针超时不得比数据面更有耐心（旧默认 2000 > timeout_ms 1500）。
    #[test]
    fn effective_probe_timeout_follows_data_plane_cap() {
        let c = ResolverConfig::default();
        assert_eq!(
            c.effective_probe_timeout_ms(),
            1500,
            "默认 health_probe_timeout_ms=2000 必须被 timeout_ms=1500 收敛"
        );
        // 显式 probe_timeout_ms 优先（原样尊重，不被人为下限抬高）。
        // **2.1.24**：结构体更新语法（`clippy::field_reassign_with_default`）。
        let mut c2 = ResolverConfig {
            probe_timeout_ms: 40,
            ..Default::default()
        };
        assert_eq!(c2.effective_probe_timeout_ms(), 40);
        // 显式值夹取到 1..60s。
        c2.probe_timeout_ms = 10_000_000;
        assert_eq!(c2.effective_probe_timeout_ms(), 60_000);
        // 快内网配置：health_probe_timeout_ms 小于 timeout_ms 时取下者。
        let c3 = ResolverConfig {
            health_probe_timeout_ms: 300,
            ..Default::default()
        };
        assert_eq!(c3.effective_probe_timeout_ms(), 300);
    }

    /// 2.1.8 默认值（与 `main.rs::default_config()` / `packaging/etc/ebpdns/config.json` 三处一致）。
    #[test]
    fn tuning_defaults_are_2_1_8_contract_values() {
        let c = ResolverConfig::default();
        assert_eq!(c.circuit_open_max_s, 120.0);
        assert_eq!(c.probe_timeout_ms, 0);
        assert!(c.adaptive_parallel);
        assert_eq!(c.hedge_after_ms, 200);
        assert!(c.adaptive_timeout);
        assert!((c.adaptive_timeout_k - 8.0).abs() < 1e-9);
        assert_eq!(
            c.adaptive_timeout_min_ms, c.timeout_ms,
            "默认下限 = timeout_ms → 默认不收紧（与 v1.9.162 固定超时等价）"
        );
        assert_eq!(c.adaptive_timeout_min_ms, 1500);
        // 测试基座保持 2.1.7 的固定并发/固定超时口径（既有断言逐位不变）。
        let t = ResolverConfig::test_default(Vec::new(), Vec::new(), 1);
        assert!(!t.adaptive_parallel);
        assert!(!t.adaptive_timeout);
    }
}
