//! **[历史归因]** ebpdns-resolver：DNS 解析编排核心，忠实复刻 Python `ebpdns/resolver.py`。
//!

// **2.1.24（B4：clippy 清零）**：`clippy::doc_lazy_continuation` 在本 crate **整片允许**，
// 理由是可核查的，不是"关掉告警换清静"：
//   * 命中的全是**中文**文档注释（29 处，逐条清单见 `docs/CLIPPY.md`）。该 lint 用
//     Markdown 的"列表项缩进"规则判连续性，而中文条目里的 `*`/`-` 后面常跟全角标点
//     （`：`/`、`/`⇒`），clippy 据此把**同一个句子的续行**判成"新的段落缺少空行"。
//   * 按它的建议逐行加缩进或空行，会把**已经排好版的中文说明**改写成另一种排版，
//     既不改变任何代码行为，也让 `git diff` 里真正要审的改动被 29 处纯排版噪声淹没。
//   * 真正有害的文档缺陷（缺链接目标、缺 `# Safety` 等）**不在**这条 lint 里，
//     因此允许它不会掩盖真问题。
// 复现：`cargo clippy --workspace --all-targets` 不再报告该 lint；逐条位置见 docs/CLIPPY.md。

#![allow(clippy::doc_lazy_continuation)]
//! 编排四个已封板依赖 crate：
//! - [`ebpdns_proto`]：报文编解码（parse_message / build_query / response）；
//! - [`ebpdns_cache`]：带 TTL 的 LRU/Partitioned/TinyLFU 缓存；
//! - [`ebpdns_rules`]：分流规则引擎（match_rule / rebuild / gen 代际）；
//! - [`ebpdns_upstream`]：六协议上游 + 健康统计；
//!
//! # 关键机制
//! - **quorum 表决**：NXDOMAIN / NODATA 均需 `>= max(1, min(nxdomain_quorum, n))` 个上游一致才确认；
//!   NODATA 证据排除 `udp_truncated` 与带 cnames 的应答（v1.9.161 修复）。
//! - **CNAME 链**：子链独立 resolve，depth 上限 8；owner name 为 CNAME 目标域名；
//!   CNAME→NXDOMAIN/NODATA 正确传播（不误判 SERVFAIL）。
//! - **gen 写回门禁**：resolve 入口记 `gen_at_entry = rule_engine.gen()`；RTT 期间规则重建
//!   （gen 自增 + 清内核 map）后，旧答案跳过内核写回，仅用户态缓存照写。
//! - **双栈**：ipv4_first / prefer_ipv4（有 A 才屏蔽 AAAA）、probe_a_record、ipv4_fallback。
//! - **熔断**：per-upstream 失败计数，达阈值打开；连续打开按 `min(open_s*2^(k-1),
//!   circuit_open_max_s)` 指数退避（默认 30→60→120）；半开为 until 过期自然放行**或**
//!   健康探针成功立即恢复。健康探针成功/失败走独立计数（`probe_ok`/`probe_fail`），
//!   **不**计入数据面 `fails`（探针失败不得打开熔断，优化项 2/5）。
//! - **上游选择**：按 `eff_lat / max(1, weight)` 排序（5s 排序缓存，数据源 `health.stats`），
//!   熔断 open 的上游本轮排除（全 open 兜底放行全部）；`fallback=false` 只取最快 1 个。
//! - **候选 IP 测速择优**：`ip_speed` EWMA 缓存（`ip_speed_cache_ttl` 过期）+ 后台探测
//!   （`ProbePool::try_submit` 池满即丢）+ 前 8 个候选加权随机不放回重排（权重 `1/(rtt+10)`）。
//! - **fail-closed**：depth 超限落 SERVFAIL、NODATA 多数、block 规则屏蔽、私有 IP 过滤。

pub mod answer;
pub mod background;
pub mod breaker;
pub mod clock;
pub mod config;
pub mod helpers;
pub mod passthrough;
pub mod prefetch;
pub mod production;
pub mod query;
pub mod resolve;
mod rfc8020;
pub mod singleflight;
pub mod telemetry;
pub mod types;

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
use sha2::{Digest, Sha256};

use ebpdns_cache::{CacheEntry, CacheKey, DnsCache, LruCache, PartitionedCache, TinyLfuCache};
use ebpdns_rules::{Rule, RuleEngine};

use crate::breaker::{CbView, CircuitState, SharedCircuit};
use crate::clock::Clock;
use crate::config::{ResolverConfig, UpstreamCfg};
use crate::helpers::{clamp_ttl, normalize};
use crate::prefetch::PendingMap;
use crate::production::QuerierTuning;
use crate::query::ParallelQuerier;
use crate::telemetry::Telemetry;
use crate::types::ResolveAnswer;

/// **2.1.18（修复项 12）**：`cache_partitions` 的**规范化指纹**（用于"是否变化"判定）。
///
/// 为什么需要：直接比 `serde_json::Value` 会把"键顺序不同"当成变化，也会把
/// "整数旧形状"与"null"混为一谈。指纹规则：
/// - 非对象（含 `null` / 整数旧形状）→ **空串**（= 用默认权重，等价于"没提供"）；
/// - 对象 → `key=value;` 按 **key 升序**拼接（只取数字值，非数字忽略）。
///
/// 于是"提交无效形状"与"没提交"指纹相同 ⇒ 不会误报"变了但没生效"。
fn partitions_fingerprint(v: Option<&serde_json::Value>) -> String {
    let Some(obj) = v.and_then(|x| x.as_object()) else {
        return String::new();
    };
    let mut items: Vec<(String, f64)> = obj
        .iter()
        .filter_map(|(k, val)| val.as_f64().map(|f| (k.clone(), f)))
        .collect();
    items.sort_by(|a, b| a.0.cmp(&b.0));
    items
        .into_iter()
        .map(|(k, f)| format!("{k}={f};"))
        .collect::<String>()
}

/// **2.1.18（修复项 12）**：把配置里的 `cache_partitions` 转成
/// [`PartitionedCache::new`] 需要的 `{group: weight}` 权重表。
///
/// 形状与语义（**以本函数为准**，文档/控制台文案必须与之一致）：
/// - `null` / 缺失 → `None`（用内置默认 `domestic 0.2 / global 0.2 / default 0.6`）；
/// - **对象** `{"domestic":0.2,"global":0.2,"default":0.6}` → 交给 `PartitionedCache`：
///   负数**钳到 0**、再**归一化到权重和为 1**（全 0 时退化为单分区全量）；
/// - **整数**（2.1.17 及以前文档写的"4"）→ 视为旧配置：**忽略**（用默认权重），
///   并由 `check-config` / 保存接口给出显式告警，不会静默生效。
///
/// 只挑出**数字**值（字符串/布尔被忽略），因此坏数据不会让进程 panic。
fn partitions_from_value(
    v: Option<&serde_json::Value>,
) -> Option<std::collections::BTreeMap<String, f64>> {
    let obj = v?.as_object()?;
    let mut m = std::collections::BTreeMap::new();
    for (k, val) in obj {
        if let Some(f) = val.as_f64() {
            m.insert(k.clone(), f);
        }
    }
    if m.is_empty() {
        None
    } else {
        Some(m)
    }
}

/// **[历史归因]** CNAME 跟随深度上限（对齐 Python `_depth < 8`）。
pub const MAX_DEPTH: u32 = 8;

/// **2.1.11 优化项 2 / 2.1.12 优化项 ②**：成功率惩罚的下限（`1/成功率` 的封顶倒数）
/// 的**默认值**；实际生效值取自配置键 `rating_sr_floor`（见 [`ResolverConfig`]）。
///
/// 2.1.12 起本常量语义收敛为"**默认值常量**"（不再是硬编码上限），默认从 `1/3`
/// 抬到 **0.5** → 惩罚最大 ×2.0（旧 ×3.0）。取"有下限"而不是"直接乘 1/成功率"
/// 或"硬排除"的理由不变：排序只决定**顺序**，`select_upstreams` 仍要在
/// `max_parallel_upstreams=3` 时凑够候选；若允许 `1/sr → ∞`（成功率 1% → ×100），
/// 一个刚恢复的上游会被永久压在静态延迟池后面，变成实质上的"饿死"。×2 已足以把
/// 实测的低成功率慢上游抬到健康 LAN 上游之后，同时保留它们作为后备候选。
///
/// **为什么把惩罚封顶收紧（0.5）而不是继续放大**：成功率**不是**慢上游的根因，
/// 延迟才是。旧口径 `1/3` 让"极低成功率"承担全部区分度（×3），却对"高延迟 +
/// 中等成功率"（实测 ali-doh 692ms/61.9%、lan235 248ms/58.5%）几乎无作用 ——
/// 它们离 1/3 很远，惩罚只有 ×1.6。2.1.12 因此把成功率惩罚**封顶收紧**并把
/// 区分度交给**绝对延迟惩罚**（[`RATING_SLOW_P90_MS`]）。
pub const RATING_SR_FLOOR: f64 = 0.5;

/// **2.1.12 优化项 ②**：绝对延迟惩罚阈值（ms，p90/实测均值口径）。
///
/// 依据（2.1.11 真机实测）：`ali-doh 692ms/61.9%`、`ali-ip-doh 1256ms/35.9%`、
/// `dnspod-doh 690ms/59.5%` —— 它们成功率**没低到触发下限**，仅靠 `1/sr` 无法把它们
/// 排到健康 LAN 上游（`lan235 248ms/98.5%`）之后。800ms 是"用户可感知卡顿"的经验阈值
/// （≈ 一次公网 DoH 往返的 p90 上界）；超过它的上游即使成功率不差，也应让位给快上游。
/// 常量而非新配置键：与 `neg_ttl_max` 之类"行为开关"不同，本阈值是**评分曲线形状**，
/// 多一个键就多一处默认值漂移面（三处默认值一致性由测试门禁）。
pub const RATING_SLOW_P90_MS: f64 = 800.0;

/// **2.1.12 优化项 ②**：超过 [`RATING_SLOW_P90_MS`] 时的额外惩罚倍数（×1.5）。
///
/// 取值依据：×1.5 足以把 `ali-ip-doh`（1256ms）从
/// `1256 × 1/0.5 = 2512` 抬到 `3768`，**严格大于** 2.1.11 旧口径的
/// `1256 × 1/0.359 = 3499`（即本项是净收紧），而 `692ms` 的 `ali-doh` 不受影响
/// （它本来就不算慢）。再大（×2）会让任何一次抖动把上游打到静态延迟池之后。
pub const RATING_SLOW_PENALTY: f64 = 1.5;

/// Resolver 编排器。共享态用 parking_lot 短临界区；持同步锁不 await。
pub struct Resolver {
    cfg: RwLock<ResolverConfig>,
    cache: Arc<ebpdns_cache::SwappableCache>,
    rule_engine: Arc<RuleEngine>,
    querier: RwLock<Arc<dyn ParallelQuerier>>,
    /// **2.1.16（功能 2）**：在途查询合并 —— 同 `CacheKey` 的并发 miss 只向上游发一次。
    ///
    /// 键 = `CacheKey` 的稳定字符串形式；值 = 该次上游扇出的**完整结果**
    /// `(results, trace_msgs, extra_waves)`（三件套整体共享，保证 follower 拿到的
    /// 补查波次数与 trace 文案与 leader 逐位一致）。
    /// 只合并"最贵且幂等"的上游扇出段，`finish_resolve` 之后的一切（负缓存写入 /
    /// serve-stale / 规则复查 / 计数）仍**逐调用方**执行，因此 P2-B 等既有语义不变。
    /// `cfg.single_flight == false` 时**完全不走**本结构（逐位退回 2.1.15 行为）。
    single_flight: Arc<crate::singleflight::SingleFlight<crate::types::UpstreamFetch>>,
    clock: Arc<dyn Clock>,
    tel: Arc<dyn Telemetry>,
    cb: Arc<SharedCircuit>,
    prefetch: Mutex<PendingMap>,
    /// serve-stale 在途刷新集合（去重，有界清理）。
    stale_inflight: Mutex<HashSet<String>>,
    /// 生产上游运行时（健康检查/探针复用；测试为 None）。
    runtime: RwLock<Option<Arc<ebpdns_upstream::UpstreamRuntime>>>,
    /// 测速节流：同域名最近一次测速时间（单调秒），上界 4096 条。
    last_speed_test: Mutex<HashMap<String, f64>>,
    /// IP 速度表：ip -> (ewma_rtt_ms, probed_at_epoch_s)。按 ip_speed_cache_ttl 过期。
    ip_speed: Mutex<std::collections::HashMap<String, (f64, f64)>>,
    /// **[历史归因]** 上游排序缓存（对齐 Python `_sorted_ups`：排序结果 / 时间戳 / 签名）。
    sorted_ups: Mutex<Option<SortedUps>>,
    /// 健康探针轮转偏移（每轮只探 min(3, enabled) 个）。
    probe_rot: std::sync::atomic::AtomicUsize,
    /// 数据面并发/超时调参（优化项 3/4）：与生产 querier 共享同一份，
    /// `reload` 时刷新 → 控制台改 `timeout_ms`/`adaptive_*`/`hedge_after_ms` 即时生效。
    /// `RwLock` 仅服务装配期替换（[`Resolver::set_querier_tuning`]），热路径读的是
    /// querier 自己持有的 `Arc`，不经过此锁。
    querier_tuning: RwLock<Arc<QuerierTuning>>,
    /// P1-1：当前**规则集指纹**（`rule_fingerprint(rules)` 的滚动值）。
    ///
    /// 与 `RuleEngine::gen()` 的区别：`gen` 每次 `rebuild` 都自增（含内容未变的重复
    /// 重建、以及每次进程启动从 0 开始），用它做缓存门禁会在「重建但规则没变」
    /// 与「重启后恢复持久化缓存」两种场景下误清全部缓存。指纹只由**规则内容**
    /// 决定（与顺序相关），因此：规则真变了 → 指纹变 → 旧条目立即失效；规则没变
    /// （含跨进程重启）→ 指纹不变 → 持久化缓存仍然可用。
    rule_gen: std::sync::atomic::AtomicU64,
    /// **2.1.47 / M-247**：规则**来源字节**指纹（本地真源 + 镜像 + cfg.rules + 订阅明细）。
    ///
    /// 与 [`Resolver::rule_gen`] 的区别：`rule_gen` 是**解析后**规则内容的指纹（要先把
    /// 10 万条 JSON 解析成 `Rule` 才能算）；本字段在解析**之前**只看来源字节，用于
    /// "来源没变 ⇒ 索引不可能变 ⇒ 直接复用，不解析、不重建" 的零成本判断。
    /// `0` = 未盖章（启动/任何一次直接 rebuild 后都会清 0）。
    ///
    /// **2.1.49（AUD-13）**：128 位 SHA-256 指纹（非热路径，`Mutex` 读写均可）。
    rule_src_fp: Mutex<u128>,
    /// 与 `rule_src_fp` 配套的上一次成功构建统计 `(fp, indexed, rejected, dropped)`。
    rule_src_build: Mutex<Option<(u128, usize, usize, usize)>>,
    /// P0 取舍的补偿控制（2.1.9）：**仅有 1 张有效负票即被采纳**的次数。
    ///
    /// 语义变更后"静默/超时上游 = 弃权"，因此单票 NXDOMAIN/NODATA 就能成立
    /// （可用性优先）。该计数让运维能量化暴露面：持续 > 0 说明生产上确实存在
    /// "只有一台上游能判负"的形态；若该值很高而信任集里有可投毒的开放解析器，
    /// 应把 `nxdomain_quorum` 调回 2（牺牲可用性换防投毒）。
    negative_single_vote_accepted: std::sync::atomic::AtomicU64,
    /// **2.1.45（P1-3/P1-4）**：因"规则代已变化"被丢弃的缓存写回次数
    /// （`put_negative` / `fill_cache_capped` 两条路径共用，正负缓存合计）。
    stale_gen_dropped: std::sync::atomic::AtomicU64,
    /// **2.1.12 优化项 ①**：RFC 8020 父域 NXDOMAIN 推导体（登记表 + 匹配）。
    /// 见 [`crate::rfc8020`] 的模块文档（语义 / 安全边界 / 为什么不登记祖先）。
    rfc8020: rfc8020::Rfc8020Domains,
    /// RFC 8020 推断命中次数（独立观测口径，与通用 `hit` 分开暴露）。
    rfc8020_hits: std::sync::atomic::AtomicU64,
    /// RFC 8020 有效登记次数（独立观测口径）。
    rfc8020_registrations: std::sync::atomic::AtomicU64,
    /// **2.1.19（修复项 5-⑨）**：当前"全部启用上游的熔断器都打开"这一**状态位**
    /// （`true` = 处于该状态）。见 [`Resolver::prefetch_upstream`]。
    ///
    /// 为什么用状态位而不是每次打 WARN：2.1.18 实测在两轮压测中出现 2 条
    /// `预取：全部上游熔断打开 → 退化为 eff_lat 最低者` **周期性** WARN —— 上游集体
    /// 抖动时它每次预取都打一条，淹没真正的错误；而"是否处于该状态"其实是**状态**，
    /// 不是事件。现在：①WARN **只在进入该状态时打一次**（状态恢复后再进入会再打一次）；
    /// ②状态本身通过 `prefetch_all_open`（当前）与 `prefetch_degraded_total`
    /// （累计进入次数）两个**可查询字段**暴露给 `/api/status.counters` 与 `/metrics`。
    prefetch_all_open: std::sync::atomic::AtomicBool,
    /// 累计**进入**"全部熔断"状态的次数（只增；配合上面的状态位表达完整语义）。
    prefetch_degraded_total: std::sync::atomic::AtomicU64,
    /// **2.1.19（F-01）**：在途上限 governor 的**已执行轮数**（只增）。
    ///
    /// 为什么需要它：`spawn_inflight_governor` 此前**只在测试专用**的 `new_production`
    /// 里被调用 ⇒ 生产上从未启动。为了让"任务真的跑起来了"**可断言**（而不是靠读日志），
    /// 每轮循环开始时自增本计数；`tokio::time::interval` 的**首 tick 立即返回**，
    /// 因此 spawn 之后短时间内该值就应 ≥1。
    gov_ticks: std::sync::atomic::AtomicU64,
    shutdown: Arc<Shutdown>,
}

/// P1-1 / **2.1.49（AUD-13）**：规则集指纹（**SHA-256**，确定性跨进程）。
///
/// 参与指纹的字段 = 影响匹配结果的字段：`match_raw` / `action` / `group` / `ip` /
/// `enabled` / `source`（顺序敏感：本地在前、订阅在后，重排会改变优先级）。
/// 不参与：`id` / `comment`（纯展示，改备注不得清空缓存）。
///
/// **为什么从 FNV-1a 64 改为 SHA-256**：订阅内容来自外部，非密码学 64 位哈希
/// 可被构造碰撞，使“内容已变”被当成“未变”。这里对每个字段先写长度再写字节
/// （消除拼接歧义），最后取 SHA-256 **前 128 位**做内部 128 位指纹；
/// [`Resolver::rule_gen`] 是公共 API / 缓存持久化字段（`u64`），取同一摘要的
/// 前 64 位作为**兼容投影**——因此升级后 `rule_gen` 的值会**整体变一次**。
///
/// **为什么指纹必须对顺序敏感（2.1.16 记录，勿改）**：规则**顺序即优先级**
///（`RuleIndex::regex` 是"按配置顺序首个命中生效"，见 `ebpdns-rules/src/index.rs`）。
/// 顺序变化 ⇒ 同一域名可能命中不同规则 ⇒ 旧缓存答案可能不再正确。
/// 因此"纯重排也必须使指纹失效"是本项目的**故意契约**
///（`tests/fix219_resolver_tests.rs::p1_1_reordered_rules_change_rule_gen` 钉死）。
fn rule_fingerprint128(rules: &[Rule]) -> u128 {
    let mut h = Sha256::new();
    let mut eat = |bytes: &[u8]| {
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(bytes);
        h.update([0xFF]);
    };
    for r in rules {
        eat(r.match_raw.as_bytes());
        eat(r.action.as_str().as_bytes());
        eat(r.group.as_deref().unwrap_or("").as_bytes());
        eat(r.ip.map(|i| i.to_string()).unwrap_or_default().as_bytes());
        eat(if r.enabled { b"1" } else { b"0" });
        eat(if matches!(r.source, ebpdns_rules::RuleSource::Sub) {
            b"sub"
        } else {
            b"local"
        });
    }
    let digest = h.finalize();
    u128::from_be_bytes(digest[..16].try_into().expect("sha256 32 bytes"))
}

/// 公共 `u64` 投影 = SHA-256 前 64 位；`0` 保留给「未盖章」条目。
fn rule_fingerprint(rules: &[Rule]) -> u64 {
    let h = rule_fingerprint128(rules);
    let v = (h >> 64) as u64;
    if v == 0 {
        1
    } else {
        v
    }
}

/// `Resolver::import_rules` 选项。手动导入默认 action=group。
#[derive(Debug, Clone)]
pub struct ImportOpts {
    /// 动作：block / allow / group / forceIp。手动导入默认 "group"。
    pub action: String,
    /// action=group 时的上游组名。
    pub group: Option<String>,
    /// action=forceIp 时的强制 IP。
    pub ip: Option<String>,
    /// 是否给普通域名包 `*.` 前缀（re:/已带通配不重复包）。
    pub wildcard: bool,
}

impl Default for ImportOpts {
    fn default() -> Self {
        Self {
            action: "group".to_string(),
            group: None,
            ip: None,
            wildcard: true,
        }
    }
}

/// **[历史归因]** 上游排序缓存（对齐 Python `_sorted_ups` 三元组：排序结果 / 时间戳 / 签名）。
#[derive(Clone)]
struct SortedUps {
    /// 排序后的上游 id 顺序（`eff_lat / max(1, weight)` 升序；稳定排序保配置序）。
    ids: Vec<String>,
    /// 缓存发布时间（单调毫秒）。
    ts_ms: f64,
    /// 签名：上游集合 + 权重 / 静态延迟 / 地址（任一变化立即失效，兼防热重载旧配置）。
    key: Vec<String>,
}

/// **[历史归因]** 上游排序缓存 TTL（毫秒，对齐 Python `_sorted_ups` 的 5s 刷新）。
const SORTED_UPS_TTL_MS: f64 = 5_000.0;
/// **[历史归因]** 测速节流表上界（域名条数，对齐 Python `_speed_hist_max = 4096`）。
const SPEED_HIST_MAX: usize = 4096;
/// 测速节流记录过期秒数：超过该时长的记录不再影响节流判定，可整体回收。
const SPEED_HIST_TTL_S: f64 = 3600.0;
/// **[历史归因]** IP 速度表上界（对齐 Python `_ip_speed_cache` 的 65536）。
const IP_SPEED_MAX: usize = 65536;
/// **[历史归因]** IP 测速 EWMA 旧值权重（Python `_probe_candidate_ip`：`0.7*旧 + 0.3*新`）。
const IP_SPEED_EWMA_OLD: f64 = 0.7;
/// **[历史归因]** 旧测速样本超过该秒数直接取新值（Python `_probe_candidate_ip` 的 3600s）。
const IP_SPEED_SAMPLE_MAX_AGE_S: f64 = 3600.0;
/// **[历史归因]** 测速重排窗口：只重排前 N 个候选（对齐 Python `cand_list[:8]`）。
const SPEED_SORT_WINDOW: usize = 8;
/// **[历史归因]** 候选无实测延迟时的兜底值（ms，对齐 Python `a.get("lat", 999)`）。
const SPEED_SORT_FALLBACK_MS: f64 = 999.0;

/// **[历史归因]** 一条候选 IP 的测速输入（对齐 Python 候选 dict 的 `lat` / `probe` 字段）。
#[derive(Clone, Debug, Default)]
pub struct CandidateSpeedHint {
    /// **[历史归因]** 静态兜底延迟（ms）：贡献该答案的上游应答延迟（Python `cand[v]["lat"]`）。
    pub static_lat: f64,
    /// **[历史归因]** 探测模式：`udp53` / `tcp443`（Python `cand[v]["probe"]`）。
    pub probe: String,
}

#[derive(Default)]
struct Shutdown {
    stopped: std::sync::atomic::AtomicBool,
    notify: tokio::sync::Notify,
}

impl Shutdown {
    fn is_stopped(&self) -> bool {
        self.stopped.load(std::sync::atomic::Ordering::Relaxed)
    }
    fn stop(&self) {
        self.stopped
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.notify.notify_waiters();
    }
    /// 等待关闭信号（select 分支可安全取消：Notify 仅广播一次）。
    async fn notified(&self) {
        // 已停止则立即返回。
        if self.is_stopped() {
            return;
        }
        std::pin::pin!(self.notify.notified()).await
    }
}

/// serve-stale 后台刷新在途标记的 RAII 守卫：drop 时清理在途集合（取消安全）。
pub(crate) struct StaleGuard {
    slf: Arc<Resolver>,
    key: String,
}

impl Drop for StaleGuard {
    fn drop(&mut self) {
        self.slf.stale_inflight.lock().remove(&self.key);
    }
}

/* ---------------- 排序 / 测速辅助（纯函数，fail-safe） ---------------- */

/// 按缓存的 id 序重排当前上游快照；id 集合不一致（增删/重复）→ None（调用方重算）。
fn reorder_by_ids(ups: &[UpstreamCfg], ids: &[String]) -> Option<Vec<UpstreamCfg>> {
    if ids.len() != ups.len() {
        return None;
    }
    let mut used = vec![false; ups.len()];
    let mut out: Vec<UpstreamCfg> = Vec::with_capacity(ups.len());
    for id in ids {
        let i = ups
            .iter()
            .enumerate()
            .position(|(i, u)| !used[i] && &u.id == id)?;
        used[i] = true;
        out.push(ups[i].clone());
    }
    Some(out)
}

/// **[历史归因]** 候选延迟清洗：非有限值 → 兜底 999ms（Python `a.get("lat", 999)` 语义）。
fn speed_ms(v: f64) -> f64 {
    if v.is_finite() {
        v
    } else {
        SPEED_SORT_FALLBACK_MS
    }
}

/// 权重清洗：非有限 / <=0 → 0（该候选本轮不参与抽取）。
fn safe_weight(w: Option<f64>) -> f64 {
    match w {
        Some(v) if v.is_finite() && v > 0.0 => v,
        _ => 0.0,
    }
}

/// **[历史归因]** 加权随机不放回抽样（对齐 Python `random.choices` + `del remaining[rel]`）：
/// **[历史归因]** `weights[i]` 为第 i 项权重（Python `1/(measured+10)`，恒 >0）；`draw(hi)` 返回
/// `[0, hi)` 内的均匀随机数（生产用 `rand::thread_rng`，测试注入固定序列）。
/// 返回按抽取先后排列的下标；权重非有限/<=0 按 0 处理，绝不 panic、不除零。
fn weighted_sample_order(weights: &[f64], draw: &mut dyn FnMut(f64) -> f64) -> Vec<usize> {
    let mut remaining: Vec<usize> = (0..weights.len()).collect();
    let mut out: Vec<usize> = Vec::with_capacity(weights.len());
    while !remaining.is_empty() {
        let total: f64 = remaining
            .iter()
            .map(|i| safe_weight(weights.get(*i).copied()))
            .sum();
        let pick = if total > 0.0 {
            let mut r = draw(total);
            if !r.is_finite() || r < 0.0 {
                r = 0.0;
            }
            let mut acc = 0.0;
            let mut idx = remaining.len().saturating_sub(1);
            for (k, i) in remaining.iter().enumerate() {
                acc += safe_weight(weights.get(*i).copied());
                if r < acc {
                    idx = k;
                    break;
                }
            }
            idx
        } else {
            0 // 全部权重为 0 → 保序（fail-safe）。
        };
        let Some(&chosen) = remaining.get(pick) else {
            break; // 逻辑上不可达（pick < len）；fail-safe 防越界。
        };
        remaining.remove(pick);
        out.push(chosen);
    }
    out
}

/// **[历史归因]** 有界时间戳表驱逐（近似 Python `OrderedDict.popitem(last=False)` 的 LRU 序）：
/// 超上界时按时间戳升序删除最旧条目，直到剩 `target` 条。
fn evict_oldest_by_ts<V, F: Fn(&V) -> f64>(map: &mut HashMap<String, V>, target: usize, ts_of: F) {
    if map.len() <= target {
        return;
    }
    let mut ages: Vec<(f64, String)> = map.iter().map(|(k, v)| (ts_of(v), k.clone())).collect();
    ages.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    let drop_n = map.len().saturating_sub(target);
    for (_, k) in ages.into_iter().take(drop_n) {
        map.remove(&k);
    }
}

/// 把已释放的堆页归还内核（P0 内存）。
///
/// glibc 的 `free()` 默认只把内存还给**分配器**（保留在 arena 里），不还给内核：
/// 10 万条订阅规则被删除/重建后，`VmRSS` 会长期停在峰值附近（实测 DELETE 订阅后
/// 仍 ~241MB）。`malloc_trim(0)` 是 glibc 的线程安全 API，用于显式归还空闲页。
///
/// 只在**规则重建**（非热路径）调用；非 glibc 平台（musl 等）为空实现。
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn trim_heap() {
    // 直接声明 libc 符号，避免为一个调用新增依赖（glibc 目标必然已链接 libc）。
    unsafe extern "C" {
        fn malloc_trim(pad: usize) -> i32;
    }
    // SAFETY: `malloc_trim` 是 glibc 提供的线程安全 API；pad=0 表示尽量归还。
    unsafe {
        malloc_trim(0);
    }
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn trim_heap() {}

impl Resolver {
    /// 构造 Resolver。`querier` 为上游查询 seam（生产包装 UpstreamRuntime，测试注入脚本化应答）。
    pub fn new(
        cfg: ResolverConfig,
        tel: Arc<dyn Telemetry>,
        clock: Arc<dyn Clock>,
        querier: Arc<dyn ParallelQuerier>,
    ) -> Arc<Self> {
        let inner: Arc<dyn DnsCache> = match cfg.cache_policy.as_str() {
            // **2.1.18（修复项 12）**：`cache_partitions` 以前被**完全忽略**
            // （这里恒传 `None`，即永远用默认 0.2/0.2/0.6），而控制台文案却写
            // "按 cache_partitions 自定义权重（自动归一化）" ⇒ 文档与实现不一致。
            // 现在真正接进来（形状见 `partitions_from_value`）。
            "partitioned" => Arc::new(PartitionedCache::new(
                cfg.cache_size,
                partitions_from_value(cfg.cache_partitions.as_ref()),
            )),
            "tinylfu" => Arc::new(TinyLfuCache::new(cfg.cache_size)),
            _ => Arc::new(LruCache::new(cfg.cache_size)),
        };
        // 包装为可热切换缓存：策略/容量变化时 `reload` 原子换实现（对齐 1.9.162 热切换）。
        let cache: Arc<ebpdns_cache::SwappableCache> =
            Arc::new(ebpdns_cache::SwappableCache::new(inner));
        // serve-stale 窗口按初始配置设定。
        cache.set_stale_window(if cfg.serve_stale {
            cfg.stale_ttl.max(0.0) as u64
        } else {
            0
        });
        let rule_engine = Arc::new(RuleEngine::new());
        // **2.1.16（功能 2）**：在途合并表（每个 Resolver 一个；键空间随并发在途量有界）。
        let single_flight: Arc<crate::singleflight::SingleFlight<crate::types::UpstreamFetch>> =
            Arc::new(crate::singleflight::SingleFlight::new());
        // 应用初始规则。
        let rules: Vec<Rule> = cfg.rules.clone();
        rule_engine.rebuild(rules);
        // P1-1：初始规则集指纹（构造期即盖章，缓存条目从此带上有效指纹）。
        let rule_gen = {
            let v = rule_fingerprint(&cfg.rules);
            std::sync::atomic::AtomicU64::new(if v == 0 { 1 } else { v })
        };
        // 优化项 3/4：数据面调参句柄（与生产 querier 共享；`reload` 时刷新）。
        let querier_tuning = QuerierTuning::from_config(&cfg);

        Arc::new(Self {
            cfg: RwLock::new(cfg),
            cache,
            rule_engine,
            querier: RwLock::new(querier),
            single_flight,
            clock,
            tel,
            cb: SharedCircuit::new(),
            prefetch: Mutex::new(PendingMap::new()),
            stale_inflight: Mutex::new(HashSet::new()),
            runtime: RwLock::new(None),
            last_speed_test: Mutex::new(HashMap::new()),
            ip_speed: Mutex::new(HashMap::new()),
            sorted_ups: Mutex::new(None),
            probe_rot: std::sync::atomic::AtomicUsize::new(0),
            querier_tuning: RwLock::new(querier_tuning),
            rule_gen,
            rule_src_fp: Mutex::new(0),
            rule_src_build: Mutex::new(None),
            negative_single_vote_accepted: std::sync::atomic::AtomicU64::new(0),
            stale_gen_dropped: std::sync::atomic::AtomicU64::new(0),
            rfc8020: rfc8020::Rfc8020Domains::default(),
            rfc8020_hits: std::sync::atomic::AtomicU64::new(0),
            rfc8020_registrations: std::sync::atomic::AtomicU64::new(0),
            prefetch_all_open: std::sync::atomic::AtomicBool::new(false),
            prefetch_degraded_total: std::sync::atomic::AtomicU64::new(0),
            gov_ticks: std::sync::atomic::AtomicU64::new(0),
            shutdown: Arc::new(Shutdown::default()),
        })
    }

    /// **2.1.19（修复项 5-⑨）**：当前是否处于"全部启用上游熔断打开"状态。
    ///
    /// `/api/status.counters.prefetch_all_open` 与 `/metrics` 的
    /// `ebpdns_prefetch_all_open` 都读它（**状态**字段，不是日志噪声）。
    pub fn prefetch_all_open(&self) -> bool {
        self.prefetch_all_open
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// **2.1.19（修复项 5-⑨）**：累计**进入**"全部熔断"状态的次数（只增）。
    pub fn prefetch_degraded_total(&self) -> u64 {
        self.prefetch_degraded_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// **2.1.19（F-01）**：在途上限 governor 的**已执行轮数**（只增）。
    ///
    /// 用途：让"`spawn_inflight_governor` 真的跑起来了"**可被断言**（生产接线回归），
    /// 而不是只能读日志判断。`interval` 首 tick 立即返回 ⇒ spawn 后很快 ≥1。
    pub fn inflight_governor_ticks(&self) -> u64 {
        self.gov_ticks.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// **2.1.16（功能 2）**：当前在途合并键数（`/metrics` / 脚本观测"合并真的在发生"）。
    pub fn single_flight_inflight(&self) -> usize {
        self.single_flight.inflight()
    }

    /// **2.1.16（功能 9）**：按上游 p90 **收敛在途上限**（纯函数，便于单测/复现）。
    ///
    /// 输入：`base` = `upstream_max_inflight`（`0` = 闸门关闭），`p90s` = 各**启用**
    /// 上游的实测 p90（ms，缺失样本的不参与）。
    ///
    /// 规则（`ratio = clamp(min(p90)/max(p90), 0.25, 1.0)`）：
    /// - `base == 0` → **返回 0**（尊重"关闭闸门"，governor 绝不擅自打开闸门）；
    /// - 无样本 → `base`（零行为变更）；
    /// - 全部同样快 → `ratio = 1` → `base`；
    /// - 存在明显慢的上游 → 按"最快/最慢"的比例**整体下调**上限（下界 `max(1, base/4)`）。
    ///
    /// 为什么是"整体下调"而不是逐上游独立上限（**明确的工程取舍，不是遗漏**）：
    /// 现有闸门是**一个** `InflightLimiter`（`UpstreamRuntime::inflight`，一个信号量
    /// 服务所有上游，见 `crates/ebpdns-upstream/src/runtime.rs:146`）。改成逐上游
    /// 需要为每个上游维护独立信号量 + 上游增删时的生命周期管理，并改动 `ProductionQuerier`
    /// 的获取路径 —— 在高并发修复窗口内改数据面同步原语的风险大于收益。
    /// 而"整体下调"恰好对准 I9 要治的**正反馈**：慢上游把在途堆满 → 对冲更频繁 →
    /// 上游更慢。降cap 直接砍掉这条回路；快上游的**延迟不受影响**（它们立刻应答，
    /// cap 只是限制同时在途的条数，不排队快路径）。
    ///
    /// 实测调参依据（`base` 取值，隔离实例 A/B 由部署代理执行）：
    /// - `16`：最保守。排队最浅，但在"上游 p90 波动大"时容易触及上限而拒绝；
    /// - `32`：**默认值**（2.1.15 起）。与 DoH 连接池每键并发 `MAX_CONN=16` 同量级，
    ///   8 条启用上游 × 32 = 256 个在途，正好抵住 256 并发客户端的原始 fan-out；
    /// - `64`：更宽松。lvl256 下 `queued_total` 会显著上升（排队搬回本层），
    ///   适合"上游本身很快（LAN/内网 p90 < 50ms）"的部署。
    /// 目标：lvl256 `P50 < 1.0s`、`P99 < 1.5s`、超时 → 0（量化由部署代理在隔离实例出）。
    pub fn converge_cap(base: usize, p90s: &[f64]) -> usize {
        if base == 0 {
            return 0;
        }
        let valid: Vec<f64> = p90s
            .iter()
            .copied()
            .filter(|v| v.is_finite() && *v > 0.0)
            .collect();
        if valid.len() < 2 {
            return base;
        }
        let fastest = valid.iter().copied().fold(f64::INFINITY, f64::min);
        let slowest = valid.iter().copied().fold(0.0_f64, f64::max);
        if !fastest.is_finite() || slowest <= 0.0 {
            return base;
        }
        let ratio = (fastest / slowest).clamp(0.25, 1.0);
        let scaled = ((base as f64) * ratio).round() as usize;
        scaled.clamp((base / 4).max(1), base)
    }

    /// **2.1.16（功能 9）**：把 [`Self::converge_cap`] 应用到上游运行时（返回生效值）。
    ///
    /// `base` 取自当前配置的 `upstream_max_inflight`；`p90s` 取自生产 querier 的
    /// 逐上游实测滑窗（`QuerierTuning::p90_latency`）。`base == 0` 时不做任何事
    /// （闸门保持关闭）。
    pub fn apply_inflight_governor(&self) -> Option<usize> {
        let base = self.cfg.read().upstream_max_inflight;
        let rt = self.runtime.read().clone()?;
        let ids: Vec<String> = self
            .cfg
            .read()
            .upstreams
            .iter()
            .filter(|u| u.enabled)
            .map(|u| u.id.clone())
            .collect();
        let tuning = self.querier_tuning();
        let p90s: Vec<f64> = ids.iter().filter_map(|id| tuning.p90_latency(id)).collect();
        let want = Self::converge_cap(base, &p90s);
        if base > 0 && want != base {
            tracing::info!(
                base,
                effective = want,
                samples = p90s.len(),
                p90_min = p90s.iter().copied().fold(f64::INFINITY, f64::min),
                p90_max = p90s.iter().copied().fold(0.0_f64, f64::max),
                "在途上限按上游 p90 收敛（慢上游 → 整体降 cap，切断\"越慢越好冲\"正反馈）"
            );
        }
        rt.set_max_inflight(want);
        Some(want)
    }

    /// **2.1.16（功能 9）**：周期性运行在途上限 governor（10s 一次，与健康检查同量级）。
    ///
    /// 异步、不可失败、不阻塞：拿不到 tokio runtime 时静默跳过（同步构造路径）。
    pub fn spawn_inflight_governor(self: &Arc<Self>) {
        if self.runtime.read().is_none() {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let me = self.clone();
        handle.spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(10));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                // **2.1.19（F-01）**：每轮先记账 ⇒ "任务真的在跑"可被单测断言
                // （不依赖日志/时间猜测；首 tick 立即返回，因此很快 ≥1）。
                me.gov_ticks
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                me.apply_inflight_governor();
            }
        });
    }

    /// **2.1.16（功能 9）：上游连接池预热（`warmup.*`）——真的发查询。**
    ///
    /// 为什么需要（实测依据）：DoH/DoT/DoQ 的**首次**查询要额外承担 TLS/QUIC 握手
    /// （实测公网 DoH 建连 + 握手 ≈ 2~3 个 RTT），而 `UpstreamRuntime` 的滑窗样本在
    /// 冷启动时为空 ⇒ 排序只能用配置里的静态 `latency`、对冲阈值退化为固定
    /// `hedge_after_ms`。两者叠加使**首批**查询的 P99 显著高于稳态（2.1.15 阶梯压测
    /// 的第一档就吃到了这部分）。
    ///
    /// 语义：
    /// - 只对 `cfg.warmup_enabled == true` 生效；`warmup_queries` 条/上游（夹取 `[1,8]`）；
    /// - 整体截止 `warmup_timeout_ms`（`0` → `cfg.timeout_ms`）；
    /// - **异步、fire-and-forget**：绝不阻塞 `Resolver::new` / `reload`（拿不到 tokio
    ///   runtime 时直接跳过并 debug 日志 —— 测试常用同步构造，不能因此 panic）；
    /// - 只探**启用**的上游，且**不**计入数据面熔断失败（与健康探针同口径）；
    /// - 每轮打一行 info：`conn_ok / conn_fail / elapsed_ms`（这就是"预热真的执行了"
    ///   的可观测证据）。
    pub fn spawn_upstream_warmup(&self) {
        let (enabled, n, deadline_ms, domain) = {
            let c = self.cfg.read();
            (
                c.warmup_enabled,
                c.warmup_queries.clamp(1, 8),
                if c.warmup_timeout_ms == 0 {
                    c.timeout_ms
                } else {
                    c.warmup_timeout_ms
                },
                c.health_probe_domain.clone(),
            )
        };
        if !enabled {
            return;
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
            return;
        }
        // 同步构造期（无 runtime）静默跳过：预热是"锦上添花"，绝不能成为构造前提。
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            tracing::debug!("上游预热跳过：当前无 tokio runtime（同步构造路径）");
            return;
        };
        // 只捕获预热真正需要的东西（querier 句柄 + 上游快照 + 域名）——
        // 不捕获 `Arc<Self>`，因此本方法可以是 `&self`（`reload(&self)` 内可调用）。
        let querier: Arc<dyn ParallelQuerier> = self.querier.read().clone();
        handle.spawn(async move {
            let t0 = std::time::Instant::now();
            let budget = std::time::Duration::from_millis(deadline_ms.max(1));
            let mut ok = 0usize;
            let mut fail = 0usize;
            // 每个上游顺序发 n 条（顺序而非并发：预热本身不该给上游制造尖峰）。
            'outer: for u in &ups {
                for _ in 0..n {
                    if t0.elapsed() >= budget {
                        tracing::info!(
                            elapsed_ms = t0.elapsed().as_millis() as u64,
                            "上游预热达截止时间，提前结束"
                        );
                        break 'outer;
                    }
                    let res = tokio::time::timeout(
                        budget.saturating_sub(t0.elapsed()),
                        querier.query_parallel(std::slice::from_ref(u), &domain, "A", 0),
                    )
                    .await;
                    match res {
                        Ok(v) if !v.is_empty() => ok += 1,
                        // 超时 / 空结果都算 fail（预热只关心"连接是否建立"，
                        // 不把失败计入数据面熔断器 —— 与健康探针同口径）。
                        _ => fail += 1,
                    }
                }
            }
            tracing::info!(
                upstreams = ups.len(),
                per_upstream = n,
                conn_ok = ok,
                conn_fail = fail,
                elapsed_ms = t0.elapsed().as_millis() as u64,
                "上游连接池预热完成（warmup.*）"
            );
        });
    }

    /// 生产构造器：装配缓存（按 cache_policy）、RuleEngine、生产 querier（包 UpstreamRuntime）、
    /// 共享熔断器与真实时钟。
    ///
    /// - `runtime`：真实六协议上游运行时；
    /// - `tel`：生产遥测。
    pub fn new_production(
        cfg: ResolverConfig,
        runtime: Arc<ebpdns_upstream::UpstreamRuntime>,
        tel: Arc<dyn Telemetry>,
    ) -> Arc<Self> {
        let clock: Arc<dyn clock::Clock> = Arc::new(clock::RealClock::default());
        // 构造前先记录超时/EDNS/熔断阈值（之后 cfg 被移入 new）。
        let (timeout_ms, edns, udp_size, padding, x20) = {
            let c = &cfg;
            (
                c.timeout_ms,
                c.edns,
                c.edns_udp_size,
                c.padding,
                c.dnssec_0x20,
            )
        };
        // 先用空脚本 querier 占位构造（new 必须要一个）；随后替换为生产 querier，
        // 并与 resolver 共享同一 Arc<SharedCircuit>。
        let placeholder = Arc::new(query::ScriptedQuerier::new(|_q, _t, _d| Vec::new()));
        let slf = Self::new(cfg, tel, clock, placeholder);

        let prod_querier = Arc::new(
            production::ProductionQuerier::new(
                runtime.clone(),
                slf.cb.clone(),
                slf.clock.clone(),
                timeout_ms,
                edns,
                udp_size,
                padding,
                x20,
            )
            // 优化项 3/4：与 resolver 共享同一份调参句柄 → `reload` 可热刷新。
            .with_tuning(slf.querier_tuning()),
        );
        slf.set_querier(prod_querier);

        // 记录 runtime 句柄（健康检查复用）。
        *slf.runtime.write() = Some(runtime);
        // **2.1.16（功能 9）**：生产装配完成后异步预热上游连接池（失败不阻塞启动）。
        // 放在最后：此时 querier / runtime / tuning 都已就位，预热发的就是真实数据面路径。
        slf.spawn_upstream_warmup();
        // **2.1.16（功能 9）**：启动在途上限 governor（按上游 p90 收敛并发）。
        slf.spawn_inflight_governor();
        slf
    }

    /// 替换上游查询 seam（测试：构造完 resolver 后注入脚本化 querier）。
    pub fn set_querier(&self, q: Arc<dyn ParallelQuerier>) {
        *self.querier.write() = q;
    }

    /// 数据面调参句柄（优化项 3/4）：生产装配需把生产 querier 的 tuning 指向它，
    /// 否则 `reload` 改了配置而数据面仍用旧超时（静默失效）。
    pub fn querier_tuning(&self) -> Arc<QuerierTuning> {
        self.querier_tuning.read().clone()
    }

    /// 注入数据面调参句柄（生产装配：querier 先于 Resolver 构造时必须调用）。
    /// 注入时会立刻把当前配置刷进该句柄，保证装配后即刻一致。
    pub fn set_querier_tuning(&self, tuning: Arc<QuerierTuning>) {
        tuning.apply(&self.cfg.read());
        *self.querier_tuning.write() = tuning;
    }

    /// 物理上游请求总数（优化项 1/3 的 QPS 口径；`counters.upstream_queries` 为逻辑口径）。
    pub fn upstream_requests(&self) -> u64 {
        self.querier_tuning().dispatched()
    }

    /// **仅有 1 张有效负票即被采纳**的累计次数（2.1.9 P0 取舍的补偿控制）。
    ///
    /// 语义：`quorum_threshold = clamp(nxdomain_quorum, 1, 有效票数)`；当有效票数 = 1
    /// 时单票即成立。该值与 `upstream_queries` 同口径（逻辑查询数），可供
    /// `/api/status.counters.negative_single_vote_accepted` 与 Prometheus 指标暴露。
    pub fn negative_single_vote_accepted(&self) -> u64 {
        self.negative_single_vote_accepted
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// 记一次"单票采纳"（由 `resolve.rs` 的负结论路径调用）。
    pub(crate) fn note_negative_single_vote(&self) {
        self.negative_single_vote_accepted
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// 「首个正向答案即返回」触发次数（优化项 1）。
    pub fn upstream_early_returns(&self) -> u64 {
        self.querier_tuning().early_returns()
    }

    /// 动态对冲追加次数（优化项 3）。
    pub fn upstream_hedges(&self) -> u64 {
        self.querier_tuning().hedges()
    }

    /// 测试 seam：在途推进规则代际（模拟 RTT 期间规则集真变化）→ 旧写回被门禁拦下。
    ///
    /// P1-1 起 [`Resolver::rule_gen`] 是**内容指纹**（内容没变不算变化），故这里显式
    /// `bump_rule_gen()`（测试语义就是"规则变了"）。
    pub fn test_bump_gen(&self) {
        let rules = self.cfg.read().rules.clone();
        self.rule_engine.rebuild(rules);
        self.bump_rule_gen();
    }

    /// 当前**规则代际**（写回门禁 + P1-1 缓存门禁共用）。
    ///
    /// P1-1 起语义收窄为「规则集指纹」：`rebuild_rules` 只在规则内容（顺序敏感）真的
    /// 变化时才更新它。于是：
    /// - 规则 CRUD / 导入 / 订阅增删改 / `PUT /api/config` 的 rules 变动 → 值变 →
    ///   `serve_from_cache` 里的门禁让**旧答案立即失效**（无需 `/api/reset`）；
    /// - 内容未变的重复 rebuild、进程重启（`cache_persist` 恢复）→ 值不变 →
    ///   缓存继续可用（旧的「每次 rebuild 都自增」口径会把持久化缓存整体废掉）。
    pub fn rule_gen(&self) -> u64 {
        self.rule_gen.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// **2.1.47 / M-247**：当前规则来源字节指纹（`0` = 未盖章/已失效）。
    pub fn rule_source_fp(&self) -> u128 {
        *self.rule_src_fp.lock()
    }

    /// **2.1.47 / M-247**：该来源指纹对应的上一次成功构建 `(indexed, rejected, dropped)`。
    ///
    /// 返回 `Some` 表示"来源字节与上次成功重建完全一致 ⇒ 现有索引就是这份来源的产物"。
    pub fn rule_source_last_build(&self, fp: u128) -> Option<(usize, usize, usize)> {
        if fp == 0 {
            return None;
        }
        let g = self.rule_src_build.lock();
        match g.as_ref() {
            Some((f, i, r, d)) if *f == fp => Some((*i, *r, *d)),
            _ => None,
        }
    }

    /// **2.1.47 / M-247**：记住一次成功构建（来源指纹 + 统计），供重复重建时零成本复用。
    pub fn note_rule_source_build(
        &self,
        fp: u128,
        indexed: usize,
        rejected: usize,
        dropped: usize,
    ) {
        if fp == 0 {
            return;
        }
        *self.rule_src_fp.lock() = fp;
        *self.rule_src_build.lock() = Some((fp, indexed, rejected, dropped));
    }

    /// **2.1.47 / M-247**：显式归还 glibc 空闲页（非 glibc / 非 Linux 平台为 no-op）。
    ///
    /// 规则重建/订阅提交会在瞬时分配十几 MB；`malloc_trim(0)` 让内核立刻回收
    /// 已 free 的页，避免"每次重载 VmRSS 上一个小台阶"。
    pub fn trim_allocator(&self) {
        trim_heap();
    }

    /// P1-1：显式推进规则代际（规则集变化时由 [`Resolver::rebuild_rules`] 调用；
    /// 也可被管理面在「改了规则但索引重建走别的入口」时直接调用）。
    pub fn bump_rule_gen(&self) {
        self.rule_gen
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// P1-1：把当前规则指纹设为 `rules` 的指纹；返回是否发生变化。
    ///
    fn refresh_rule_gen(&self, rules: &[Rule]) -> bool {
        let want = rule_fingerprint(rules);
        let want = if want == 0 { 1 } else { want };
        let old = self
            .rule_gen
            .swap(want, std::sync::atomic::Ordering::Relaxed);
        old != want
    }

    /// 当前**规则索引**内的规则条数（本地逐条 + 全部订阅展开后的真实条数）。
    ///
    /// 管理面 `GET /api/pipeline` 的 `rules` 用它：不能用 `config().rules.len()`
    /// （那只含逐条本地规则，订阅来的 10 万条不计入 → 控制台恒显示 0 规则）。
    pub fn rule_count(&self) -> usize {
        self.rule_engine.rule_count()
    }

    pub fn cache(&self) -> &Arc<ebpdns_cache::SwappableCache> {
        &self.cache
    }

    /// 当前缓存实现句柄（需要 `Arc<dyn DnsCache>` 的调用方用）。
    pub fn cache_arc(&self) -> Arc<dyn DnsCache> {
        self.cache.current()
    }

    /// 注入上游运行时句柄（生产装配用：`Resolver::new` + 手工 querier 的路径必须调用，
    /// 否则 per-upstream 健康统计与健康检查循环拿不到 runtime）。
    pub fn set_runtime(&self, rt: Arc<ebpdns_upstream::UpstreamRuntime>) {
        *self.runtime.write() = Some(rt);
    }

    /// 上游运行时句柄（供管理面读取 per-upstream 健康度/连接统计）。
    pub fn upstream_runtime(&self) -> Option<Arc<ebpdns_upstream::UpstreamRuntime>> {
        self.runtime.read().clone()
    }

    pub fn config(&self) -> parking_lot::RwLockReadGuard<'_, ResolverConfig> {
        self.cfg.read()
    }

    /// 重建规则索引（测试：新增 forceIp 规则后调用）。
    ///
    /// P1-1：同时刷新**规则集指纹**（[`Resolver::rule_gen`]）。规则内容/顺序变了
    /// → 指纹变 → 旧答案缓存条目在命中路径被拒绝并删除（无需 `/api/reset`）；
    /// 内容未变（重复重建 / 启动时同名恢复）→ 指纹不变 → 缓存继续可用。
    pub fn rebuild_rules(&self, rules: Vec<Rule>) -> ebpdns_rules::BuildReport {
        // **2.1.47 / M-247**：这是一次真正的重建 ⇒ 之前的"来源字节未变"复用立即失效
        // （调用方可能是直接 rebuild，例如测试/管理面绕过磁盘来源）。
        *self.rule_src_fp.lock() = 0;
        *self.rule_src_build.lock() = None;
        // 先算指纹（`rules` 随后被 move 进索引）。
        let changed = self.refresh_rule_gen(&rules);
        let report = self.rule_engine.rebuild(rules);
        // group 翻转时整体清答案缓存（对齐 _rebuild_rule_index）。
        if report.group_flip {
            self.cache.clear();
        }
        // 规则内容变更 → 旧答案缓存立即失效（指纹门禁）。
        if changed {
            // **2.1.16（日志信噪比）**：本行原为 `info!`。订阅轮询期间
            //（`subscribe::rebuild_all_disk` 每 ~0.3s 一次，而**规则顺序**因
            // `HashMap` 迭代顺序抖动而变化 ⇒ 指纹每轮都"真变"）journal 被它淹没。
            //
            // 为什么降级而不是让指纹对顺序不敏感：顺序即**优先级**（regex 首个命中生效），
            // 纯重排也会改变匹配结果 ⇒ "重排必须使指纹失效"是故意契约（有单测钉死），
            // 不能为了日志安静去削弱它。因此这里只改**日志级别**：
            // 默认 `RUST_LOG=info` 下不再刷屏；需要审计规则失效事件时开 `debug`。
            // `rule_gen` 的**语义与计数完全不变**（该失效照旧发生、`/api/status` 可见）。
            tracing::debug!(
                rule_gen = self.rule_gen(),
                indexed = report.stats.indexed,
                "规则集指纹变更 → 旧答案缓存立即失效（需要审计时开 debug 级）"
            );
        }
        // P0（内存）：规则集变化会一次性释放数十 MB 堆（10 万条订阅规则的旧索引、
        // 明细树等）。glibc 默认**不**把已 free 的页归还内核 → `VmRSS` 长期停在峰值
        // 附近（实测 DELETE 订阅后仍 ~241MB）。重建是非热路径，这里显式归还空闲页。
        trim_heap();
        report
    }

    /// **2.1.49（P0）**：构建并**仅在可用时发布**规则索引；失败 ⇒ `Err(BuildStats)`，
    /// **旧索引/旧 `rule_gen`/旧来源指纹全部原样保留**。
    ///
    /// 判据与 [`ebpdns_server::subscribe::RebuildStats::failed`] 同口径：`indexed == 0`
    /// 且 `rejected + dropped_before_index > 0` ⇒ 失败。空规则集（无拒绝/丢弃）不是失败
    /// （清空规则是合法操作），仍会发布空索引。
    ///
    /// `dropped_before_index` 是**解析期**丢弃数（订阅条目为空 match / 非法 ip 等），
    /// 它们没有机会进入 `RuleIndex::build`，必须由调用方传入才能判"全部死在进索引之前"。
    pub fn try_rebuild_rules(
        &self,
        rules: Vec<Rule>,
        dropped_before_index: usize,
    ) -> Result<ebpdns_rules::BuildReport, ebpdns_rules::BuildStats> {
        // 先算指纹（`rules` 随后被 move 进候选索引）。
        let want = {
            let fp = rule_fingerprint(&rules);
            if fp == 0 {
                1
            } else {
                fp
            }
        };
        let cand = self.rule_engine.build_candidate(rules);
        let build_stats = cand.stats;
        if build_stats.indexed == 0 && build_stats.rejected + dropped_before_index > 0 {
            tracing::error!(
                indexed = build_stats.indexed,
                rejected = build_stats.rejected,
                dropped = dropped_before_index,
                "规则索引重建失败（全部规则被拒/丢弃）⇒ **本次不替换索引**（保留旧快照），端点 5xx"
            );
            return Err(build_stats);
        }
        // 成功路径：清来源指纹盖章（与 rebuild_rules 一致；失败路径刻意不清，
        // 因为旧索引仍对应上一份成功来源）。
        *self.rule_src_fp.lock() = 0;
        *self.rule_src_build.lock() = None;
        let report = self.rule_engine.publish_candidate(cand);
        let old = self
            .rule_gen
            .swap(want, std::sync::atomic::Ordering::Relaxed);
        let changed = old != want;
        // group 翻转时整体清答案缓存（对齐 _rebuild_rule_index）。
        if report.group_flip {
            self.cache.clear();
        }
        // 规则内容变更 → 旧答案缓存立即失效（指纹门禁）。
        if changed {
            tracing::debug!(
                rule_gen = self.rule_gen(),
                indexed = report.stats.indexed,
                "规则集指纹变更 → 旧答案缓存立即失效（需要审计时开 debug 级）"
            );
        }
        trim_heap();
        Ok(report)
    }

    /// 规则匹配（完整判定，fast=false）。返回命中规则。
    pub fn match_rule(&self, domain: &str) -> Option<Rule> {
        match self.rule_engine.match_rule(domain, false) {
            ebpdns_rules::MatchOutcome::Hit(r) => Some(r),
            _ => None,
        }
    }

    /// 导入粘贴的规则文本（/api/rules/import 端点用，默认 opts=group）。薄封装。
    pub fn import_rules_text(&self, text: &str) -> usize {
        self.import_rules(text, ImportOpts::default())
    }

    /// 规则导入批次号（单调递增，进程内唯一）。
    ///
    /// `/api/rules/import` 的包装层用它给**没有 id** 的导入规则生成确定性 id
    /// （`rmig<批次>_<序号>`）：`rule_from_json` 只认 `match`/`action`/`group`/`ip`，
    /// 导入进来的规则 `id` 恒为 `None`，而页面「逐条规则」的删除/编辑按 id 定位，
    /// 且落盘/重启后 id 必须稳定。批次号保证同一次导入内不重、跨次导入也不重
    /// （`rules_admin::ensure_ids` 的 `rmig%d` 用在**已有列表**的补号上，与批次前缀不同）。
    pub fn import_nonce(&self) -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        // 以 epoch 秒为高位基数，避免与手工指定的 `rmig<n>` 撞车。
        let base = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        base.wrapping_mul(1000)
            .wrapping_add(SEQ.fetch_add(1, Ordering::Relaxed))
    }

    /// 通用规则导入：逐行解析，按 opts 构造规则（group 带 group、forceIp 带 ip、
    /// wildcard 控制是否包 `*.` 前缀，`re:`/已带通配不重复包），按 match 模式去重后
    /// 合并进当前规则集并 rebuild，返回实际新增条数。
    pub fn import_rules(&self, content: &str, opts: ImportOpts) -> usize {
        let mut new: Vec<Rule> = Vec::new();
        for d in ebpdns_rules::parse::parse_domain_list(content) {
            let m = if d.starts_with("*.") || d.starts_with("re:") {
                d
            } else if opts.wildcard {
                format!("*.{d}")
            } else {
                d
            };
            let mut map = serde_json::Map::new();
            map.insert("match".to_string(), serde_json::Value::String(m));
            map.insert(
                "action".to_string(),
                serde_json::Value::String(opts.action.clone()),
            );
            if let Some(g) = &opts.group {
                map.insert("group".to_string(), serde_json::Value::String(g.clone()));
            }
            if let Some(ip) = &opts.ip {
                map.insert("ip".to_string(), serde_json::Value::String(ip.clone()));
            }
            if let Some(r) = ebpdns_rules::rule_from_json(map, ebpdns_rules::RuleSource::Local) {
                new.push(r);
            }
        }
        let mut cfg = self.cfg.write();
        // 按 match_raw 去重（已存在则跳过）。
        let mut seen: std::collections::HashSet<String> =
            cfg.rules.iter().map(|r| r.match_raw.clone()).collect();
        let mut added = 0;
        for r in new {
            if seen.insert(r.match_raw.clone()) {
                cfg.rules.push(r);
                added += 1;
            }
        }
        let all = cfg.rules.clone();
        drop(cfg);
        self.rebuild_rules(all);
        added
    }

    /// **[历史归因]** 规则匹配 fast 路径（对齐 Python resolver.py:1425）：字典类 miss 后一旦进入正则阶段
    /// 即返回 [`MatchOutcome::Uncertain`]，**不**在 UDP recv 线程同步遍历正则。调用方
    /// （answer_fast）见 Uncertain 应返回 None，降级到 worker/resolve 做完整求值，
    /// 避免 head-of-line 阻塞。
    pub fn match_rule_fast(&self, domain: &str) -> ebpdns_rules::MatchOutcome {
        self.rule_engine.match_rule(domain, true)
    }

    /* ---------------- 上游排序 / 选择（对齐 Python resolve:931-967） ---------------- */

    /// **[历史归因]** 单个上游有效延迟（ms），对齐 Python `_upstream_eff_lat`：
    /// 优先实测平均成功延迟（失败率 >50% 且样本 >10 → +500ms 惩罚）；无成功样本时回退
    /// **[历史归因]** 配置静态 `latency`（Python 回退的是静态延迟，**不是** f64::MAX）。
    /// 数据源：`upstream_runtime().map(|r| r.health.stats(id))`。
    ///
    /// 管理面 `/api/upstreams.eff_lat_ms` 直接读它（优化项 8 只读字段）。
    pub fn upstream_eff_lat(&self, up: &UpstreamCfg) -> f64 {
        if let Some(rt) = self.upstream_runtime() {
            let st = rt.health.stats(&up.id);
            let ok = st.ok_count();
            if ok > 0 {
                let avg = st.avg_latency().unwrap_or(f64::from(up.latency));
                let fail = st.fail_count();
                let total = ok + fail;
                if total > 10 && (fail as f64 / total as f64) > 0.5 {
                    return avg + 500.0; // 高失败率惩罚性排后。
                }
                return avg;
            }
        }
        // 无实测样本（或测试注入的 resolver 无 runtime）→ 配置静态延迟。
        f64::from(up.latency)
    }

    /// **2.1.11 优化项 2 / 2.1.12 优化项 ②**：上游综合排序权重（**复合键**）
    ///
    /// ```text
    /// score = base × (1 / max(sr, rating_sr_floor)) × slow_penalty) / max(1, weight)
    /// slow_penalty = if 有实测样本 && base > RATING_SLOW_P90_MS { RATING_SLOW_PENALTY } else { 1.0 }
    /// ```
    ///
    /// `base` 选择顺序：
    /// 1. **逐上游实测滑窗 p90**（`QuerierTuning::p90_latency`，最近 32 个**成功**样本）
    ///    —— 与优化项 3 的对冲决策、优化项 4 的自适应超时同源同基准；
    /// 2. 健康统计均值（`avg_latency`，p90 不可用时兜底）；
    /// 3. 配置静态 `latency`（**冷启动**）。
    ///
    /// 成功率惩罚 = `1 / max(success_rate, rating_sr_floor)`（下限默认
    /// [`RATING_SR_FLOOR`] = 0.5，可配置）：
    /// - 成功率 100% → ×1.0；90% → ×1.11；75% → ×1.33；≤50% → ×2.0（封顶）。
    ///
    /// 绝对延迟惩罚（[`RATING_SLOW_P90_MS`] = 800ms → ×[`RATING_SLOW_PENALTY`] = 1.5）：
    /// 2.1.11 的实测分布里 `ali-doh 692ms/61.9%`、`lan235 248ms/58.5%`、
    /// `ali-ip-doh 1256ms/35.9%` —— "中等成功率"离旧下限 `1/3` 很远，`1/sr` 只有
    /// ×1.6–1.7，无法把它们排到健康快上游之后；只有 `35.9%` 那一档才吃到 ×2.8。
    /// 2.1.12 因此把成功率惩罚**封顶收紧到 ×2**、把区分度交给**绝对延迟**：
    /// `>800ms` 再 ×1.5。对实测三例的效果：`lan235 424`（不变）、`ali-doh 1118`（不变）、
    /// `ali-ip-doh 2512×1.5 = 3768`（旧口径 3499，**净收紧**）。
    ///
    /// **冷启动零行为风险**：**没有任何实测样本**时（`sr = None` 且 `base` 来自配置静态
    /// `latency`）两个惩罚都取 1.0 → 打分**逐位等于** 2.1.11 的
    /// `latency / max(1, weight)`（[`RATING_SLOW_P90_MS`] 也**不**作用于静态延迟：
    /// 静态 `latency` 是运维声明值、可能故意写成 5000，用它触发延迟惩罚会凭空改变
    /// 冷启动排序）。
    ///
    /// 惩罚**有下限封顶**（可配置 `rating_sr_floor`）：排序只影响顺序，**不得把候选饿死**
    /// —— `max_parallel_upstreams=3` 时 `select_upstreams` 仍按本顺序取前 3 个，最坏
    /// 情况下被惩罚的上游仍会入选（见该函数注释的"可用上游不足时不饿死"论据）。
    pub fn upstream_rating(&self, up: &UpstreamCfg) -> f64 {
        self.upstream_rating_detail(up).0
    }

    /// **2.1.12 优化项 ②**：评分明细（可观测）。
    ///
    /// 返回 `(score, base, success_rate, measured, slow_penalty)`：
    /// - `score`   = `base × (1/max(sr, floor)) × slow_penalty / max(1, weight)`；
    /// - `base`    = 实际用于打分的延迟基准（p90 → 均值 → 静态 `latency`）；
    /// - `sr`      = 成功率（`None` = 无样本）；
    /// - `measured`= `base` 是否来自真实观测（false = 冷启动，两个惩罚都恒为 1.0）；
    /// - `slow_penalty` = 绝对延迟惩罚因子（1.0 或 [`RATING_SLOW_PENALTY`]）。
    ///
    /// 拆成公开函数是为了**真机可解释性**：`sorted_upstreams` 在重算排序时按 debug
    /// 级别打印这张明细表（`target="ebpdns::rating"`），运维可以据此回答"为什么这台
    /// 上游被首发/被降权"，而不必靠反推选中份额。行为与 [`Resolver::upstream_rating`]
    /// 完全同源（后者只是取 `.0`）。
    pub fn upstream_rating_detail(&self, up: &UpstreamCfg) -> (f64, f64, Option<f64>, bool, f64) {
        let mut base: Option<f64> = None;
        let mut sr: Option<f64> = None;
        // `measured` = base 来自**真实观测**（p90 滑窗或健康统计均值）。
        // 冷启动（配置静态 latency）时为 false → 绝对延迟惩罚不生效（位等价保证）。
        let mut measured = false;
        // 1) 滑窗 p90（有样本即用；`Resolver` 侧拿不到 tuning 时跳过）。
        // parking_lot 的 `read()` 直接返回 guard（不是 Result），且本函数不 await。
        {
            let t = self.querier_tuning.read();
            if let Some(p) = t.p90_latency(&up.id) {
                if p.is_finite() && p > 0.0 {
                    base = Some(p);
                    measured = true;
                }
            }
        }
        // 2) 健康统计：均值 + 成功率（p90 不可用时用均值兜底）。
        if let Some(rt) = self.upstream_runtime() {
            let st = rt.health.stats(&up.id);
            let ok = st.ok_count();
            let fail = st.fail_count();
            let total = ok + fail;
            if total > 0 {
                sr = Some(ok as f64 / total as f64);
            }
            if base.is_none() && ok > 0 {
                base = Some(st.avg_latency().unwrap_or(f64::from(up.latency)));
                measured = true;
            }
        }
        let base = base.unwrap_or(f64::from(up.latency));
        let base = if base.is_finite() && base > 0.0 {
            base
        } else {
            f64::from(up.latency).max(1.0)
        };
        // `rating_sr_floor` 每次读取都做合法性收敛（非有限/<=0 → 默认值），
        // 保证热重载写入畸形值也不会让打分变成 inf/NaN（`partial_cmp` → Equal 乱序）。
        let floor = {
            let f = self.cfg.read().rating_sr_floor;
            if f.is_finite() && f > 0.0 {
                f.clamp(1e-3, 1.0)
            } else {
                RATING_SR_FLOOR
            }
        };
        let pen = match sr {
            Some(s) if s.is_finite() => 1.0 / s.clamp(floor, 1.0),
            _ => 1.0,
        };
        // 绝对延迟惩罚：**仅**对实测值生效（冷启动静态延迟不参与，见文档）。
        let slow = if measured && base > RATING_SLOW_P90_MS {
            RATING_SLOW_PENALTY
        } else {
            1.0
        };
        (
            (base * pen * slow) / up.weight.max(1.0),
            base,
            sr,
            measured,
            slow,
        )
    }

    /// 排序缓存签名（上游集合 + 权重 / 静态延迟 / 地址）：任一变化立即失效。
    fn sort_key(ups: &[UpstreamCfg]) -> Vec<String> {
        ups.iter()
            .map(|u| {
                let parts = [
                    u.id.clone(),
                    u.weight.to_string(),
                    u.latency.to_string(),
                    u.proto.clone(),
                    u.host.clone(),
                    u.port.to_string(),
                    u.enabled.to_string(),
                ];
                parts.join("|")
            })
            .collect()
    }

    /// **[历史归因]** 上游排序（对齐 Python `_sorted_ups`）：按 [`Resolver::upstream_rating`]
    /// （= 实测 p90 / 均值 × 成功率惩罚 / max(1, weight)）升序，
    /// 稳定排序保证等键时保持配置顺序；结果缓存 5s（签名一致才复用）。
    fn sorted_upstreams(&self, ups: &[UpstreamCfg]) -> Vec<UpstreamCfg> {
        if ups.len() <= 1 {
            return ups.to_vec();
        }
        let key = Self::sort_key(ups);
        let now_ms = self.clock.monotonic_ms();
        // 临界区只做缓存判定/发布（不 await、不回调外部锁）。
        let mut cache = self.sorted_ups.lock();
        let cached = cache.as_ref().and_then(|c| {
            if c.key == key && now_ms - c.ts_ms <= SORTED_UPS_TTL_MS {
                reorder_by_ids(ups, &c.ids)
            } else {
                None
            }
        });
        if let Some(ordered) = cached {
            return ordered;
        }
        let mut list: Vec<UpstreamCfg> = ups.to_vec();
        list.sort_by(|a, b| {
            // 先算出两侧键值再比较：避免在闭包参数（`&UpstreamCfg`）上触发移动/借用歧义。
            // 2.1.11 优化项 2：键 = 综合权重（p90 × 成功率惩罚 / weight），见 upstream_rating。
            let ka = self.upstream_rating(a);
            let kb = self.upstream_rating(b);
            ka.partial_cmp(&kb).unwrap_or(std::cmp::Ordering::Equal)
        });
        let ids: Vec<String> = list.iter().map(|u| u.id.clone()).collect();
        *cache = Some(SortedUps {
            ids,
            ts_ms: now_ms,
            key,
        });
        // 2.1.12 可观测性：重算排序时按 debug 级打印**评分明细**（每 ≥5s 一条，见
        // `SORTED_UPS_TTL_MS`），回答"为什么这台上游被首发/被降权"。级别为 debug →
        // 默认 `log_level=info` 下零开销（宏先判级别，参数不构造）。
        if tracing::enabled!(tracing::Level::DEBUG) {
            let mut s = String::with_capacity(64 + list.len() * 48);
            for u in &list {
                let (score, base, sr, measured, slow) = self.upstream_rating_detail(u);
                let _ = write!(
                    s,
                    " {}={:.1}(base={:.1},sr={},m={},slow={:.1})",
                    u.id,
                    score,
                    base,
                    sr.map(|v| format!("{v:.3}")).unwrap_or_else(|| "-".into()),
                    u8::from(measured),
                    slow
                );
            }
            tracing::debug!(target: "ebpdns::rating", "上游评分排序(2.1.12 复合键):{}", s);
        }
        list
    }

    /// **[历史归因]** 上游选择（对齐 Python resolve:931-967 + `_query_parallel` 熔断跳过）：
    /// 1) 按 `eff_lat / max(1, weight)` 升序（5s 排序缓存）；
    /// 2) 熔断 open 的上游本轮排除；全部 open 时兜底放行全部（不直接空结果）；
    /// 3) `fallback=true` → 前 `max_parallel_upstreams` 个为首选、其余为备份；
    ///    `fallback=false` → 只取最快 1 个、无备份（失败即 SERVFAIL）。
    ///
    /// 返回 `(primary, backup)`；`ups` 为空时返回两个空列表（调用方按 no-upstream 处理）。
    ///
    /// **前置条件**：`ups` 必须已过滤掉 `enabled=false` 的上游（`resolve_inner` 与
    /// `prefetch_upstream` 都满足）。禁用项若混进来会被当成候选参与排序与截断 —— 管理面
    /// 视图 [`Resolver::upstream_roles`] 因此显式先过滤。
    pub fn select_upstreams(&self, ups: &[UpstreamCfg]) -> (Vec<UpstreamCfg>, Vec<UpstreamCfg>) {
        if ups.is_empty() {
            return (Vec::new(), Vec::new());
        }
        let sorted = self.sorted_upstreams(ups);
        // 熔断状态每请求实时判定（不进排序缓存，避免缓存期内熔断态被冻结）。
        let mut live: Vec<UpstreamCfg> = sorted
            .iter()
            .filter(|u| !self.cb_is_open(&u.id))
            .cloned()
            .collect();
        if live.is_empty() {
            // M10：全部熔断打开 → 兜底放行全部（保留旧版容错性）。
            // 优化项 6 的可观测（warn 日志 + counters.breaker_all_open + id 列表）落在
            // 数据面真正发起查询的 `ProductionQuerier::query_parallel`（那里的 selected
            // 才是"实际被放行发出"的集合，在此处计数会与它双计）。
            live = sorted;
        }
        let (fallback_on, max_par) = {
            let c = self.cfg.read();
            (c.fallback, c.max_parallel_upstreams.max(1))
        };
        if !fallback_on {
            // **[历史归因]** Python `ups = ups[:1]`：只取排序后最快的 1 个，失败即 SERVFAIL。
            return (live.iter().take(1).cloned().collect(), Vec::new());
        }
        let n = max_par.min(live.len());
        let primary: Vec<UpstreamCfg> = live.iter().take(n).cloned().collect();
        let backup: Vec<UpstreamCfg> = live.iter().skip(n).cloned().collect();
        (primary, backup)
    }

    /// 预取目标上游（优化项 9）：**恰好 1 个**，取 `eff_lat / max(1, weight)` 最小者。
    ///
    /// 与 [`Resolver::select_upstreams`] **复用同一个排序函数**（[`Resolver::sorted_upstreams`]，
    /// 同一份 `HealthKeeper` 数据源 + 同一个 5s 排序缓存），因此不会出现"两套最快上游定义"。
    /// `weight` 的取舍：仍然参与（`eff_lat / max(1, weight)`）；本部署实测所有上游
    /// `weight == 1.0`，此时该键**就是**"健康度实测平均延迟最低"。若运维显式把某上游
    /// weight 调大，则视为"更偏好的上游"而优先预取 —— 这是有意为之：weight 是运维的显式
    /// 表达，若预取忽略它，就会出现"数据面用 weight 选 A、预取固定选 B"的双口径。
    ///
    /// 熔断打开的上游一律跳过；**全部打开**时退化为其中 `eff_lat/max(1,weight)` 最小者，
    /// 并打一条 warn（不因此跳过本轮预取）。
    pub fn prefetch_upstream(&self, ups: &[UpstreamCfg]) -> Option<UpstreamCfg> {
        let cands: Vec<UpstreamCfg> = ups.iter().filter(|u| u.enabled).cloned().collect();
        if cands.is_empty() {
            return None;
        }
        let sorted = self.sorted_upstreams(&cands);
        let (pick, degraded) = match sorted.iter().find(|u| !self.cb_is_open(&u.id)) {
            Some(u) => (u.clone(), false),
            None => (sorted.first()?.clone(), true),
        };
        let eff = self.upstream_eff_lat(&pick);
        // 真机验证用的固定格式行（debug 级，不刷 info 日志）：
        //   prefetch upstream=<id> eff_lat=<ms> weight=<w> all_open=<bool> candidates=<n>
        tracing::debug!(
            target: "ebpdns::prefetch",
            "prefetch upstream={} eff_lat={:.1} weight={} all_open={} candidates={}",
            pick.id,
            eff,
            pick.weight,
            degraded,
            cands.len()
        );
        if degraded {
            // **2.1.19（修复项 5-⑨）**：**只在进入该状态时**打一次 WARN（状态转移边沿），
            // 不再每轮预取各打一条（2.1.18 实测两轮压测各出现 2 条周期性 WARN，
            // 属"把状态当事件"的噪声）；状态本身由 `prefetch_all_open` /
            // `prefetch_degraded_total` 两个可查询字段承载。
            if !self
                .prefetch_all_open
                .swap(true, std::sync::atomic::Ordering::Relaxed)
            {
                self.prefetch_degraded_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::warn!(
                    upstream = %pick.id,
                    candidates = cands.len(),
                    "预取：**进入**『全部上游熔断打开』状态 → 退化为 eff_lat 最低者（不跳过本轮预取）。\
                     该状态可通过 `/api/status.counters.prefetch_all_open` 与 \
                     `/metrics` 的 `ebpdns_prefetch_all_open` 查询；退出该状态时会再打一条。"
                );
            }
        } else if self
            .prefetch_all_open
            .swap(false, std::sync::atomic::Ordering::Relaxed)
        {
            // 退出该状态：明确告知"已恢复按健康度选上游"，避免运维按进入时的 WARN 误判。
            tracing::info!(
                upstream = %pick.id,
                "预取：**退出**『全部上游熔断打开』状态（已有上游熔断器闭合，恢复按健康度选上游）"
            );
        }
        Some(pick)
    }

    /// 数据面/预取共用的查询目标集（优化项 9 的单一入口）。
    ///
    /// `Multi` = 全部启用上游（数据面默认，由 querier 按 `max_parallel_upstreams` 截断）；
    /// `Single` = 仅 [`Resolver::prefetch_upstream`] 选出的 1 个（预取/双栈探测/回退同为单上游，
    /// 保证预取整条链路**不产生任何多上游并发**）。
    pub fn query_targets(&self, ups: &[UpstreamCfg], single: bool) -> Vec<UpstreamCfg> {
        if !single {
            return ups.iter().filter(|u| u.enabled).cloned().collect();
        }
        self.prefetch_upstream(ups).into_iter().collect()
    }

    /// 逐上游「本轮角色」只读视图（优化项 8）：`primary` / `backup` / `idle`。
    /// 语义 = `select_upstreams(&cfg.upstreams)` 的结果（**全局口径**，不做 group/规则
    /// 分流；数据面命中 group 规则时会先用该组子集再选择，故这里的角色是"默认路径"下的
    /// 角色，供控制台展示"谁在首发/谁在做后备/谁完全没进候选"）。
    /// - `primary`：本轮首发（自适应并发下按序次第发出）；
    /// - `backup`：首选全失败时的回退候选；
    /// - `idle`：被禁用、被熔断打开排除、或 `fallback=false` 下被截断掉的上游。
    pub fn upstream_roles(&self) -> HashMap<String, &'static str> {
        let ups: Vec<UpstreamCfg> = self.cfg.read().upstreams.clone();
        let mut out: HashMap<String, &'static str> = HashMap::with_capacity(ups.len());
        for u in &ups {
            out.insert(u.id.clone(), "idle");
        }
        // `select_upstreams` 要求入参已过滤 enabled（禁用上游不得进入候选/role）。
        let enabled: Vec<UpstreamCfg> = ups.iter().filter(|u| u.enabled).cloned().collect();
        let (primary, backup) = self.select_upstreams(&enabled);
        for u in &backup {
            out.insert(u.id.clone(), "backup");
        }
        for u in &primary {
            out.insert(u.id.clone(), "primary");
        }
        out
    }

    /* ---------------- 候选 IP 测速择优（对齐 Python `_speed_sort`） ---------------- */

    /// 记录一次 IP 探测 RTT：EWMA `0.7*旧 + 0.3*新`；旧样本超 3600s 直接取新值。
    /// 生产/测试探测共用；表上界 65536，超限按探测时间驱逐最旧到 3/4 水位线。
    pub fn record_ip_speed(&self, ip: &str, rtt_ms: f64) {
        if !rtt_ms.is_finite() {
            return; // fail-safe：非有限值不污染速度表。
        }
        let now = self.clock.epoch();
        let mut t = self.ip_speed.lock();
        let ewma = match t.get(ip).copied() {
            Some((old, ts)) if old.is_finite() && now - ts < IP_SPEED_SAMPLE_MAX_AGE_S => {
                IP_SPEED_EWMA_OLD * old + (1.0 - IP_SPEED_EWMA_OLD) * rtt_ms
            }
            _ => rtt_ms,
        };
        t.insert(ip.to_string(), (ewma, now));
        if t.len() > IP_SPEED_MAX {
            evict_oldest_by_ts(&mut t, IP_SPEED_MAX * 3 / 4, |v: &(f64, f64)| v.1);
        }
    }

    /// **[历史归因]** 多答案确定性择优：`speed_test=false` 时不按速度表重排（对齐 Python:1338），直接返回
    /// 首条（上游插入序）。启用时在速度表内、未过 `ip_speed_cache_ttl` 的候选里选 EWMA
    /// 最低者；无有效测速数据时退回首条（保序去重，不改序），绝不 panic。
    ///
    /// 生产重排路径见 [`Resolver::speed_sort`]（EWMA + 加权随机）；本方法保留为确定性
    /// EWMA 选择器，供管理面/既有测试使用。
    pub fn speed_choose(&self, cands: &[crate::types::ResolveAnswer]) -> String {
        let Some(first) = cands.first() else {
            return String::new();
        };
        let cfg = self.cfg.read();
        if !cfg.speed_test || cands.len() <= 1 {
            return first.value.clone();
        }
        let now = self.clock.epoch();
        let t = self.ip_speed.lock();
        let mut best: Option<&str> = None;
        let mut best_rtt = f64::MAX;
        for a in cands {
            if let Some((ewma, probed)) = t.get(&a.value) {
                if now - probed <= cfg.ip_speed_cache_ttl as f64 && *ewma < best_rtt {
                    best = Some(&a.value);
                    best_rtt = *ewma;
                }
            }
        }
        best.map(|s| s.to_string())
            .unwrap_or_else(|| first.value.clone())
    }

    /// 对单个 IP 做一次有界 TCP 连接探测，返回 RTT(ms)；超时/失败返回 None。
    /// 仅在 `speed_test && ip_speed_check` 时由生产路径调用；测试用本地 listener 验证。
    pub async fn probe_ip_once(&self, ip: &str, port: u16) -> Option<f64> {
        let timeout = {
            let cfg = self.cfg.read();
            std::time::Duration::from_millis(cfg.speed_timeout_ms)
        };
        let t0 = std::time::Instant::now();
        let _ = tokio::time::timeout(timeout, tokio::net::TcpStream::connect((ip, port)))
            .await
            .ok()?;
        Some(t0.elapsed().as_secs_f64() * 1000.0)
    }

    /// **[历史归因]** 候选 IP 测速重排（对齐 Python `_speed_sort`，查询路径零阻塞）。
    ///
    /// - 仅在 `speed_test && ip_speed_check` 且候选 >1 时生效，否则原序返回；
    /// - **[历史归因]** 同域名 `speed_interval_ms` 节流：窗口内复用上次排序（原序返回，与 Python 一致）；
    /// - 命中 `ip_speed` 新鲜样本（`ip_speed_cache_ttl` 内）→ 直接用 EWMA；未命中 → 用静态
    ///   **[历史归因]** 延迟兜底并把兜底值写入速度表（Python `setdefault`），同时提交后台探测；
    /// - 只重排前 8 个候选：权重 `1/(measured+10)` 加权随机不放回抽样；其余保持原序。
    ///
    /// fail-safe：无 runtime / 池满 / 无 tokio 运行时 / NaN 一律退化为原序，绝不 panic，
    /// 也绝不阻塞请求路径（探测只在后台任务里跑）。
    pub fn speed_sort(
        self: &Arc<Self>,
        cands: &[ResolveAnswer],
        hints: &[CandidateSpeedHint],
        domain: &str,
    ) -> Vec<ResolveAnswer> {
        let (enabled, interval_s, cache_ttl_s, probe_cfg) = {
            let c = self.cfg.read();
            (
                c.speed_test && c.ip_speed_check,
                c.speed_interval_ms as f64 / 1000.0,
                c.ip_speed_cache_ttl as f64,
                c.ip_speed_probe.to_ascii_lowercase(),
            )
        };
        if !enabled || cands.len() <= 1 {
            return cands.to_vec();
        }
        // **[历史归因]** 节流表用单调秒（Python `time.monotonic()`）；`ip_speed` 表时间戳沿用本 crate
        // 既有口径 epoch 秒（与 `record_ip_speed` / `speed_choose` 一致，避免时钟口径混用）。
        let now_mono = self.clock.monotonic_ms() / 1000.0;
        let now_epoch = self.clock.epoch();
        // **[历史归因]** 节流（Python `_last_speed_test`）：同域名间隔内复用上次排序 → 原序返回。
        {
            let mut hist = self.last_speed_test.lock();
            let last = hist.get(domain).copied().unwrap_or(0.0);
            if now_mono - last < interval_s {
                return cands.to_vec();
            }
            hist.insert(domain.to_string(), now_mono);
            if hist.len() > SPEED_HIST_MAX {
                // 过期清理：超 1h 的节流记录已不影响判定，先整体回收。
                hist.retain(|_, ts: &mut f64| now_mono - *ts <= SPEED_HIST_TTL_S);
                if hist.len() > SPEED_HIST_MAX {
                    // 仍超上界 → 按时间戳升序驱逐最旧到 3/4 水位线。
                    evict_oldest_by_ts(&mut hist, SPEED_HIST_MAX * 3 / 4, |v: &f64| *v);
                }
            }
        }
        let window = SPEED_SORT_WINDOW.min(cands.len());
        let mut measured: Vec<f64> = Vec::with_capacity(window);
        let mut to_probe: Vec<(String, String)> = Vec::new();
        {
            let mut table = self.ip_speed.lock();
            for (i, a) in cands.iter().take(window).enumerate() {
                let hit = table.get(&a.value).copied();
                let fresh = hit.filter(|(_, ts)| now_epoch - *ts < cache_ttl_s);
                if let Some((ewma, _)) = fresh {
                    measured.push(speed_ms(ewma));
                    continue;
                }
                // **[历史归因]** 未命中 → 静态延迟兜底（Python `a.get("lat", 999)`）。
                let hint_lat = hints
                    .get(i)
                    .map_or(SPEED_SORT_FALLBACK_MS, |h| h.static_lat);
                let static_ms = speed_ms(hint_lat);
                measured.push(static_ms);
                if hit.is_none() {
                    // **[历史归因]** 仅在槽位真空时写入兜底值（对齐 Python `setdefault`）。
                    table.insert(a.value.clone(), (static_ms, now_epoch));
                }
                // 探测模式：`ip_speed_probe` 显式 udp53/tcp443 时全局覆盖，否则按贡献该答案
                // 的上游协议分流（加密协议 → tcp443，其余 → udp53）。
                let hint_probe = hints.get(i).map_or("udp53", |h| h.probe.as_str());
                let mode = match probe_cfg.as_str() {
                    "udp53" | "tcp443" => probe_cfg.clone(),
                    _ => hint_probe.to_string(),
                };
                to_probe.push((a.value.clone(), mode));
            }
            if table.len() > IP_SPEED_MAX {
                evict_oldest_by_ts(&mut table, IP_SPEED_MAX * 3 / 4, |v: &(f64, f64)| v.1);
            }
        }
        // 后台探测（池满即丢，不阻塞本次请求）。
        for (ip, mode) in to_probe {
            self.submit_ip_probe(ip, mode);
        }
        // **[历史归因]** 加权随机不放回抽样（Python `random.choices` 循环）：权重 `1/(measured+10)`。
        let weights: Vec<f64> = measured.iter().map(|m| 1.0 / (m.max(0.0) + 10.0)).collect();
        let order = {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let mut draw = |hi: f64| -> f64 {
                if hi.is_finite() && hi > 0.0 {
                    rng.gen_range(0.0..hi)
                } else {
                    0.0
                }
            };
            weighted_sample_order(&weights, &mut draw)
        };
        let mut out: Vec<ResolveAnswer> = Vec::with_capacity(cands.len());
        for i in order {
            if let Some(a) = cands.get(i) {
                out.push(a.clone());
            }
        }
        // **[历史归因]** 第 8 个之后的候选保持原序（Python `cand_list[8:]`）。
        out.extend(cands.iter().skip(window).cloned());
        if out.len() != cands.len() {
            // 抽样异常（逻辑上不可达）→ 退回原序，绝不丢答案。
            return cands.to_vec();
        }
        out
    }

    /// **[历史归因]** 提交一次候选 IP 后台探测（对齐 Python `_probe_pool.submit_drop`）：池满即丢；
    /// 无 runtime / 无 tokio 运行时 → 静默跳过。绝不阻塞请求路径。
    fn submit_ip_probe(self: &Arc<Self>, ip: String, mode: String) {
        let Some(rt) = self.upstream_runtime() else {
            return; // 测试/无生产 runtime：无探针池可用，直接跳过。
        };
        let Some(permit) = rt.probes.try_submit() else {
            return; // 池满即丢，不挤占数据面查询。
        };
        if tokio::runtime::Handle::try_current().is_err() {
            return; // 同步上下文（测试/管理面）：放弃本次后台探测。
        }
        let me = self.clone();
        tokio::spawn(async move {
            let _keep = permit;
            if let Some(rtt) = me.probe_candidate_ip_once(&ip, &mode).await {
                me.record_ip_speed(&ip, rtt);
            }
        });
    }

    /// **[历史归因]** 按 `ip_speed_probe` 模式探测候选 IP 的单次 RTT（ms，对齐 Python
    /// `_probe_candidate_ip`）：`udp53` → UDP DNS 探测；`tcp443` → TCP connect 探测
    /// （复用 [`Resolver::probe_ip_once`]）；`both` → 两者取 min。全部失败/超时 → None。
    pub async fn probe_candidate_ip_once(&self, ip: &str, mode: &str) -> Option<f64> {
        let (timeout_ms, domain) = {
            let c = self.cfg.read();
            (
                c.speed_timeout_ms.max(1),
                c.health_probe_domain
                    .trim_end_matches('.')
                    .to_ascii_lowercase(),
            )
        };
        let mut rtts: Vec<f64> = Vec::new();
        match mode.to_ascii_lowercase().as_str() {
            "tcp443" => {
                if let Some(r) = self.probe_ip_once(ip, 443).await {
                    rtts.push(r);
                }
            }
            "both" => {
                if let Some(r) = self.probe_ip_udp53_once(ip, &domain, timeout_ms).await {
                    rtts.push(r);
                }
                if let Some(r) = self.probe_ip_once(ip, 443).await {
                    rtts.push(r);
                }
            }
            // **[历史归因]** "udp53" 及未知值：Python 每上游默认 "udp53"。
            _ => {
                if let Some(r) = self.probe_ip_udp53_once(ip, &domain, timeout_ms).await {
                    rtts.push(r);
                }
            }
        }
        rtts.into_iter().reduce(f64::min)
    }

    /// **[历史归因]** UDP53 候选 IP 探测（对齐 Python `upstream.probe_ip`）：固定域名 A 查询
    /// （`edns=false`），校验响应源地址/端口与 qid（失配继续等待直至超时），成功返回
    /// `max(1, RTT ms)`；socket 构造失败 / 超时 → None，绝不 panic。
    async fn probe_ip_udp53_once(&self, ip: &str, domain: &str, timeout_ms: u64) -> Option<f64> {
        let (query, qid) = ebpdns_proto::query::build_query(
            domain,
            ebpdns_proto::constants::TYPE_A,
            None,
            false,
            None,
            None,
            false,
        )
        .ok()?;
        let bind = if ip.contains(':') {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let sock = tokio::net::UdpSocket::bind(bind).await.ok()?;
        sock.send_to(&query, (ip, 53u16)).await.ok()?;
        let budget = std::time::Duration::from_millis(timeout_ms.max(1));
        let t0 = std::time::Instant::now();
        let mut buf = [0u8; 4096];
        loop {
            let left = budget.checked_sub(t0.elapsed())?; // 超时 → None。
            let (n, from) = tokio::time::timeout(left, sock.recv_from(&mut buf))
                .await
                .ok()?
                .ok()?;
            // 源地址/源端口校验（对齐 probe_ip，防伪造响应误导测速）。
            let same_ip = match (from.ip(), ip.parse::<std::net::IpAddr>()) {
                (a, Ok(b)) => a == b,
                _ => from.ip().to_string() == ip,
            };
            if !same_ip || from.port() != 53 || n < 12 {
                continue;
            }
            // qid 校验：失配报文继续等待，不提前判失败（对齐 probe_ip）。
            if u16::from_be_bytes([buf[0], buf[1]]) != qid {
                continue;
            }
            return Some((t0.elapsed().as_secs_f64() * 1000.0).max(1.0));
        }
    }

    /// **[历史归因]** 缓存键（对齐 Python `_ckey`）。无 group 规则时为二元组 (domain, qtype)。
    ///
    /// 注意：每次调用都会 `normalize` 域名并大写 qtype（各 1 次 `String` 分配）。
    /// 调用方**已经**持有归一化结果时请用 [`Resolver::ckey_normalized`] 省掉这两次分配。
    pub fn ckey(&self, domain: &str, qtype: &str) -> CacheKey {
        // 当前测试均无 group 规则；group 分区由 PartitionedCache 处理。
        let _ = self.rule_engine.has_group_rules();
        CacheKey::new(normalize(domain), qtype.to_ascii_uppercase())
    }

    /// 归一化域名的缓存键构造（`domain` 必须已 `normalize`、`qtype` 必须已大写）。
    ///
    /// `resolve_inner` 的 `d` / `qtype` 正好满足该前置条件，因此热路径上不再重复
    /// 分配两次 `String`（旧实现每查询多付 2 次分配）。语义与 [`Resolver::ckey`] 一致。
    #[inline]
    pub fn ckey_normalized(&self, domain: &str, qtype: &str) -> CacheKey {
        CacheKey::new(domain, qtype)
    }

    /* ---------------- 熔断器（单调秒口径，防 NTP 回拨） ---------------- */
    pub fn cb_fail(&self, uid: &str) {
        let cfg = self.cfg.read();
        let now = self.clock.monotonic_ms() / 1000.0;
        self.cb.fail(
            uid,
            now,
            cfg.circuit_fails,
            cfg.circuit_open_s,
            cfg.circuit_open_max_s,
        );
    }
    pub fn cb_ok(&self, uid: &str) {
        self.cb.ok(uid);
    }
    /// 健康探针成功喂点（优化项 2/5）：累加独立 `probe_ok` 并**立即恢复**打开态。
    /// 返回是否确实从「打开/失败态」恢复（供日志）。
    pub fn cb_probe_ok(&self, uid: &str) -> bool {
        self.cb.probe_ok(uid)
    }
    /// 健康探针失败喂点（优化项 2）：**只**累加独立 `probe_fail`，绝不打开熔断。
    pub fn cb_probe_fail(&self, uid: &str) -> u64 {
        self.cb.probe_fail(uid)
    }
    pub fn cb_is_open(&self, uid: &str) -> bool {
        let now = self.clock.monotonic_ms() / 1000.0;
        self.cb.is_open(uid, now)
    }
    /// 只读熔断视图（`/api/upstreams` 的 fails / until_in_s / probe_* / open_count）。
    pub fn cb_view(&self, uid: &str) -> CbView {
        let now = self.clock.monotonic_ms() / 1000.0;
        self.cb.view(uid, now)
    }
    /// 「全部熔断兜底放行」累计次数（`/api/status.counters.breaker_all_open`，优化项 6）。
    pub fn cb_all_open_count(&self) -> u64 {
        self.cb.all_open_count()
    }
    /// 最近一次兜底放行的上游 id 列表（优化项 6）。
    pub fn cb_last_all_open_ids(&self) -> Vec<String> {
        self.cb.last_all_open_ids()
    }
    /// 当前处于打开态的上游 id（优化项 5：健康探针据此优先探测）。
    pub fn cb_open_ids(&self) -> Vec<String> {
        let now = self.clock.monotonic_ms() / 1000.0;
        self.cb.open_ids(now)
    }
    /// 测试：读熔断器条目。
    pub fn cb_get(&self, uid: &str) -> Option<CircuitState> {
        self.cb.get(uid)
    }
    /// 测试：注入熔断器死条目。
    pub fn cb_inject(&self, uid: &str, fails: u32, until: f64) {
        self.cb.inject(uid, fails, until);
    }

    /* ---------------- 预取队列（OrderedDict 语义） ---------------- */
    /// schedule：`prefetch` 开关关闭则不入队；超上界驱逐最旧。
    ///
    /// `domain` 必须已 `normalize`、`qtype` 必须已大写（`resolve` 内部的 `d`/`qtype`
    /// 满足），内部据此直接拼 key，省掉旧实现为拼 key 额外做的 2 次 `String` 分配。
    ///
    /// **2.1.20（F-02）**：`ttl_left` 是本条缓存命中的**剩余 TTL（秒）**，配置项
    /// `prefetch_trigger`（默认 60s）是"剩余 TTL 低于它才值得提前续期"的阈值 ——
    /// 此前它只被声明、从未被读，于是**每次**缓存命中都入队。
    ///
    /// **2.1.21（DEF-220-01 修复：入队与"真的发上游"必须是同一条判据）**：
    /// 本函数（入队闸门）与 `background.rs::do_prefetch`（续期闸门）现在**同式**：
    ///
    /// ```text
    /// 入队: ttl_left <= prefetch_trigger
    /// 续期: 0 < left  <= prefetch_trigger      （left = 出队时的剩余 TTL）
    /// ```
    ///
    /// 2.1.20 及以前 `do_prefetch` 另有一条**未文档化**的 `left < ttl*0.15` 闸门，
    /// 使得 `prefetch_trigger > ttl`（例如 `trigger=3600, ttl=300`）时条目入队却
    /// **永不续期**（审计实测）。现在 `trigger` 是**唯一权威阈值**。
    ///
    /// 语义（README「预取」与 `main.rs::apply_cfg` 的逐键说明**逐字一致**）：
    /// * `prefetch_trigger`：剩余 TTL **低于或等于**该值才入队/续期（秒；0 = 关闭）；
    /// * `prefetch_target`：续期回填时的 **TTL 上限**（秒；0 = 不额外收紧）。
    pub fn schedule_prefetch(&self, domain: &str, qtype: &str, ttl_left: f64) {
        {
            let cfg = self.cfg.read();
            if !cfg.prefetch {
                return;
            }
            if ttl_left > cfg.prefetch_trigger {
                // 还早（剩余 TTL 高于触发阈值）⇒ 不续期。
                // `f64::INFINITY` = "刚刚才从上游拿到的全新条目"（见 miss 路径的调用点）。
                return;
            }
        }
        let max = self.cfg.read().prefetch_max;
        let mut key = String::with_capacity(domain.len() + 1 + qtype.len());
        key.push_str(domain);
        key.push('|');
        key.push_str(qtype);
        self.prefetch.lock().schedule(&key, domain, qtype, max);
    }
    pub fn prefetch_len(&self) -> usize {
        self.prefetch.lock().len()
    }
    pub fn prefetch_order(&self) -> Vec<String> {
        self.prefetch.lock().order()
    }

    /// **2.1.45（P1-3/P1-4）**：`stale_gen_dropped` 累计值
    /// （`/api/status.counters.stale_gen_dropped` 与 POST /api/query 同源）。
    pub fn stale_gen_dropped(&self) -> u64 {
        self.stale_gen_dropped
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// 记录一次"规则代已变化 ⇒ 丢弃写回"（`put_negative` / `fill_cache_capped` 共用）。
    pub(crate) fn note_stale_gen_dropped(&self, n: u64) {
        if n > 0 {
            self.stale_gen_dropped
                .fetch_add(n, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /* ---------------- fill_cache ---------------- */
    /// 回填用户态缓存。
    /// **公共入口（5 参数，向后兼容）**：不施加额外 TTL 上限
    /// （`ttl_cap = None`），行为与 2.1.20 **逐位一致**。
    ///
    /// 为什么保留这个签名：crate 内约 100 处集成测试（`resolver_tests.rs` /
    /// `followup_tests.rs` / `adv218_tests.rs` / `security_tests.rs` …）用它；
    /// 为一个 2.1.21 的缺陷修复而机械改动全部调用点是不必要的扰动。
    /// 需要 `prefetch_target` 上限的解析路径走 [`Self::fill_cache_capped`]。
    pub fn fill_cache(
        &self,
        key: &CacheKey,
        domain: &str,
        qtype: &str,
        answers: Vec<ResolveAnswer>,
        gen: Option<u64>,
    ) {
        self.fill_cache_capped(key, domain, qtype, answers, gen, None);
    }

    /// 带 **TTL 上限**的回填（**2.1.21 / DEF-220-11**）。
    ///
    /// `ttl_cap`：回填 TTL 的**上限**（秒），来源 = `prefetch_target`。预取续期时传
    /// `Some(cfg.prefetch_target)` ⇒ "续期到 target"真的生效（此前 `prefetch_target`
    /// 是**全树零读取点**的死字段：只有 `main.rs` 的赋值点）。`None`、非有限值或
    /// `<= 0` ⇒ 不额外收紧（"0 = 不用"不得被误解释成"TTL 恒为 0"，那会让每次命中
    /// 都立刻过期）。
    pub fn fill_cache_capped(
        &self,
        key: &CacheKey,
        domain: &str,
        qtype: &str,
        answers: Vec<ResolveAnswer>,
        gen: Option<u64>,
        ttl_cap: Option<f64>,
    ) {
        // **2.1.45（P1-4）**：与 `put_negative` **同一口径** —— 在途答案只能带
        // "入口代"章；入口代 ≠ 当前 `rule_gen()` ⇒ 丢弃（计 `stale_gen_dropped`）。
        // 两条写回路径共用同一个门禁，避免"修了一条、漏了另一条"。
        let cur = self.rule_gen();
        let stamp = gen.unwrap_or(cur);
        if stamp != cur {
            self.note_stale_gen_dropped(1);
            tracing::debug!(
                domain = domain,
                qtype = qtype,
                entry_gen = stamp,
                rule_gen = cur,
                "正缓存写入被拒：规则代已变化（在途旧答案不得盖新代际）"
            );
            return;
        }
        let cfg = self.cfg.read();
        let now = self.clock.epoch();
        let ttl_default = cfg.ttl;
        let raw_ttl = if answers.is_empty() {
            ttl_default
        } else {
            let min_ans = answers
                .iter()
                .map(|a| a.ttl as u32)
                .min()
                .unwrap_or(ttl_default);
            ttl_default.min(min_ans)
        };
        // 预取续期上限（`prefetch_target`）：只在正有限值时收紧。
        let raw_ttl = match ttl_cap {
            Some(c) if c.is_finite() && c > 0.0 => raw_ttl.min(c.min(f64::from(u32::MAX)) as u32),
            _ => raw_ttl,
        };
        let ttl = clamp_ttl(raw_ttl, cfg.ttl_min, cfg.ttl_max);

        // chosen：反向扫描首个 A/AAAA（链尾真实目标 IP），兜底末条（对齐 _fill_cache）。
        let chosen = answers
            .iter()
            .rev()
            .find(|a| a.rtype == 1 || a.rtype == 28)
            .map(|a| a.value.clone())
            .unwrap_or_else(|| answers.last().map(|a| a.value.clone()).unwrap_or_default());
        let cache_answers: Vec<ebpdns_cache::CacheAnswer> = answers
            .iter()
            .map(|a| ebpdns_cache::CacheAnswer {
                value: a.value.clone(),
                ttl: a.ttl,
                rtype: a.rtype,
                // 透传 owner 名（CNAME 链逐跳 owner / 链尾 tgt），缓存命中重编码时用它作 RR owner。
                name: a.name.clone(),
            })
            .collect();
        let entry = CacheEntry {
            domain: domain.to_string(),
            qtype: qtype.to_string(),
            answers: cache_answers,
            chosen,
            ttl: ttl as f64,
            rcode: 0,
            expires_at: now + ttl as f64,
            // P1-1：条目盖章（规则集指纹）——规则变更后命中路径据此立即失效。
            rule_gen: stamp,

            seq: 0,
        };
        self.cache.put(key.clone(), entry, now);
    }

    /* ---------------- reset / reload / shutdown ---------------- */
    /// 对称清理：用户态缓存 + **RFC 8020 推断表** + 熔断器。
    ///
    /// 2.1.12：RFC 8020 表是"负缓存的扩展"，必须与 `cache.clear()` 同批清理 ——
    /// 否则 `/api/reset`（运维排障的标准动作）之后，被登记的名字仍会被本地判负，
    /// 表现为"重置了但 NXDOMAIN 还在"，是最容易被误判为回归的形态。
    // >>> 242B BEGIN P1-8-resolver >>> //
    pub fn reset_runtime_state(&self) {
        self.cache.clear();
        self.rfc8020.clear();
        self.cb.clear();
        // **2.1.42-B（P1-8）**：运行时累计量也必须清（否则 `/api/reset` 后
        // `upstream_requests` / `rfc8020_hits` / `breaker_all_open` 等 13 个键
        // 仍显示历史值，`/api/status` 自相矛盾）。
        self.reset_counters();
    }

    /// **2.1.42-B（P1-8）**：清空 resolver / querier / 上游运行时 / 熔断器的
    /// **全部**累计计数器（单一入口，`reset_runtime_state` 调用）。
    ///
    /// 不含缓存条目与规则索引（那由 `reset_runtime_state` 的 cache/rfc8020 负责）。
    pub fn reset_counters(&self) {
        use std::sync::atomic::Ordering;
        self.negative_single_vote_accepted
            .store(0, Ordering::Relaxed);
        // **2.1.45（P1-3/P1-4）**：读写回门禁的丢弃计数一并归零。
        self.stale_gen_dropped.store(0, Ordering::Relaxed);
        self.rfc8020_hits.store(0, Ordering::Relaxed);
        self.rfc8020_registrations.store(0, Ordering::Relaxed);
        self.prefetch_all_open.store(false, Ordering::Relaxed);
        self.prefetch_degraded_total.store(0, Ordering::Relaxed);
        self.querier_tuning().reset_counters();
        if let Some(rt) = self.upstream_runtime() {
            rt.reset_counters();
        }
        self.cb.clear();
    }
    // <<< 242B END P1-8-resolver <<< //

    /// 热重载：对称回收旧上游派生状态，刷新配置。
    ///
    /// 关键：`cache_policy` / `cache_size` 变化时**重建缓存容器**（对齐 v1.9.162 的
    /// 策略热切换语义），否则页面显示已切换而淘汰引擎/容量仍是旧值。
    ///
    /// **不重建规则索引**（P0 修复）：`new_cfg.rules` 只含 `config.json` 的**逐条本地
    /// 规则**，不含 10 万条订阅展开规则；用它 `rebuild` 会把订阅规则整体摘掉——
    /// 真实部署实测 `POST /api/reload` 后 `pipeline.rules` 101147 → 0、
    /// `status.rule_hits` 停止增长（屏蔽仍在只因进程尚未重建，随下次重建即失效）。
    /// 规则索引的唯一权威重建入口是 `ebpdns_server::subscribe::rebuild_all_disk_stats`
    /// （本地规则文件 + 订阅磁盘明细**合并**重建，本地在前），由 `main.rs` 的
    /// `on_reload` 钩子在 `reload()` 之后调用。
    pub fn reload(&self, new_cfg: ResolverConfig) {
        // 清理已删除上游的熔断器死条目。
        let keep: HashSet<String> = new_cfg.upstreams.iter().map(|u| u.id.clone()).collect();
        self.cb.retain(&keep);
        // 缓存策略/容量变化 → **增量迁移 / resize**（2.1.16 功能 5：不再整表丢弃）。
        // **2.1.18（修复项 12）**：`cache_partitions` 也必须进"重建触发器" ——
        // 以前只比 `cache_policy` / `cache_size`，于是"只改权重"时 `PUT /api/config`
        // 会报 `changed: ["cache_partitions"]` 而**容量分配完全没变**（部署实测
        // E2 FAIL：`{0.5,0.3,0.2}` 提交后仍是默认 9818/3283/3283）。
        let (old_policy, old_size, old_parts) = {
            let c = self.cfg.read();
            (
                c.cache_policy.clone(),
                c.cache_size,
                partitions_fingerprint(c.cache_partitions.as_ref()),
            )
        };
        let new_parts = partitions_fingerprint(new_cfg.cache_partitions.as_ref());
        if new_parts != old_parts {
            if new_cfg.cache_policy != "partitioned" {
                // 明确告警：权重只对 `partitioned` 生效 —— 不能"报 changed 但没变"。
                tracing::warn!(
                    policy = %new_cfg.cache_policy,
                    "cache_partitions 已变更，但当前 cache_policy 不是 partitioned ⇒ 权重**不会生效**\
                     （请把 cache_policy 设为 partitioned）"
                );
            } else if new_parts.is_empty() {
                tracing::warn!(
                    "cache_partitions 已变更但为**空/无效对象** ⇒ 回退内置默认 domestic 0.2 / global 0.2 / default 0.6"
                );
            }
        }
        if old_policy != new_cfg.cache_policy || old_parts != new_parts {
            // ---- 策略切换：**迁移可复用条目**（同键仍可命中）----
            //
            // 旧实现（2.1.15 及以前）在这里直接 `swap(新建空缓存)` ⇒ 全部热条目被丢弃，
            // 切换瞬间命中率**归零**（压测表现为一条垂直断崖），并把全部流量立刻放给上游。
            //
            // 现在：先把旧缓存里**仍然有效**的条目读出来（`get_arc` 会惰性清理过期条目、
            // 并把命中项提升为 MRU），逐条写入新策略的容器 —— 对新容器而言这就是一次正常的
            // `put`，因此：
            // - LRU：写入顺序 ≈ 旧容器的 LRU 顺序（最后写入的最不易被淘汰）；
            // - TinyLFU：每次 `put` 都会喂 count-min sketch 的频次 ⇒ **准入结构被预热**
            //   （这是"策略切换后不是又冷启动一次"的关键）；
            // - partitioned：`put` 按同一套 `hash_key` 路由，分区比例沿用既有语义。
            //
            // 明确文档化的淘汰语义（不承诺"命中率不变"，只承诺"同键仍可命中"）：
            // 迁移**不做**跨策略的热度换算（LRU 的最近性无法无损映射到 TinyLFU 的频次），
            // 因此切换后新策略从"旧键全在、热度从零开始累积"出发；由于键都在，
            // 命中率**不会归零**，最坏情况是随后几秒的淘汰顺序与新策略的稳态略有差异。
            let fresh: Arc<dyn DnsCache> = match new_cfg.cache_policy.as_str() {
                // 与构造路径同源（同一 helper）：热切换时 `cache_partitions` 同样生效。
                "partitioned" => Arc::new(PartitionedCache::new(
                    new_cfg.cache_size,
                    partitions_from_value(new_cfg.cache_partitions.as_ref()),
                )),
                "tinylfu" => Arc::new(TinyLfuCache::new(new_cfg.cache_size)),
                _ => Arc::new(LruCache::new(new_cfg.cache_size)),
            };
            let now = self.clock.epoch();
            let keys = self.cache.keys();
            let total = keys.len();
            let mut migrated = 0usize;
            for k in keys {
                // `get_arc` = 仅**有效**（未过期）条目：过期项不会被迁移"复活"。
                if let Some(e) = self.cache.get_arc(&k, now) {
                    fresh.put(k, (*e).clone(), now);
                    migrated += 1;
                }
            }
            // 目标容量可能小于迁移进来的条目数（新容量更小）→ 由目标策略自行逐出。
            fresh.set_capacity(new_cfg.cache_size);
            self.cache.swap(fresh);
            // 关键：`swap` 换入的是**新建缓存实例**，其 `stale_window` 为 0（关闭）。
            // 若不在此重新下发，热切换后 `get_stale` 会退化为「窗口外立即删除」，
            // **[历史归因]** 与 Python `reload`（`new_cache.stale_window = ...`）不一致。
            self.cache.set_stale_window(if new_cfg.serve_stale {
                new_cfg.stale_ttl.max(0.0) as u64
            } else {
                0
            });
            tracing::info!(
                old_policy = %old_policy,
                new_policy = %new_cfg.cache_policy,
                old_size = old_size,
                new_size = new_cfg.cache_size,
                candidates = total,
                migrated = migrated,
                skipped_expired = total.saturating_sub(migrated),
                "缓存策略已热切换（**增量迁移**：同键仍可命中，过期项不复活）"
            );
        } else if old_size != new_cfg.cache_size {
            // ---- 容量变更（策略不变）：**增量 resize**，条目一个不丢 ----
            //
            // 旧实现同样走 `swap(新建空缓存)` —— 仅仅为了改 `cache_size` 就把整表丢掉，
            // 是"改配置 = 命中率归零"最典型的形态（`/api/reload` 改 `cache_size` 后
            // `counters.hit` 停止增长、`cache_direct` 归零）。
            //
            // 现在直接下发 `set_capacity`：**增长不丢任何条目**；收缩由**当前策略**按自己的
            // 淘汰语义逐出（LRU 淘汰最久未用 / TinyLFU 淘汰最少使用 / partitioned 按分区裁剪），
            // 与"一开始就是这个容量"语义一致。
            self.cache.set_capacity(new_cfg.cache_size);
            self.cache.set_stale_window(if new_cfg.serve_stale {
                new_cfg.stale_ttl.max(0.0) as u64
            } else {
                0
            });
            tracing::info!(
                policy = %new_cfg.cache_policy,
                old_size = old_size,
                new_size = new_cfg.cache_size,
                entries = self.cache.len(),
                "缓存容量已增量 resize（未清空；收缩按当前策略逐出）"
            );
        }
        // serve-stale 窗口与配置实时对齐（0 = 关闭兜底）。
        self.cache.set_stale_window(if new_cfg.serve_stale {
            new_cfg.stale_ttl.max(0.0) as u64
        } else {
            0
        });
        // 刷新派生状态。
        *self.sorted_ups.lock() = None;
        // 优化项 3/4：数据面调参随配置热刷新（含 timeout_ms —— 旧实现只在构造时读一次，
        // 热重载后数据面仍用旧超时）。
        self.querier_tuning.read().apply(&new_cfg);
        // **2.1.15（P1）**：单上游在途闸门上限随配置热刷新（`upstream_max_inflight`）。
        // 与 `tuning` 同一条路径：控制台改完即时生效，无需重启。
        if let Some(rt) = self.runtime.read().as_ref() {
            rt.set_max_inflight(new_cfg.upstream_max_inflight);
        }
        // **2.1.16（功能 9）**：启用上游集合变化时重跑一次连接池预热
        // （新增/启用的上游其 TLS/QUIC 会话还是冷的）。异步，不阻塞 reload。
        let ups_changed = {
            let old: std::collections::HashSet<String> = self
                .cfg
                .read()
                .upstreams
                .iter()
                .map(|u| u.id.clone())
                .collect();
            let new: std::collections::HashSet<String> =
                new_cfg.upstreams.iter().map(|u| u.id.clone()).collect();
            old != new
        };
        *self.cfg.write() = new_cfg;
        if ups_changed {
            self.spawn_upstream_warmup();
        }
    }

    /// 关闭：顺序停预取→后台→池→…。
    pub fn shutdown(&self) {
        self.shutdown.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::MockClock;
    use crate::config::{ResolverConfig, UpstreamCfg};
    use crate::query::{ParallelQuerier, ScriptedQuerier};
    use crate::resolve::ResolveOpts;
    use crate::telemetry::NoopTelemetry;
    use crate::types::{ResolveAnswer, UpstreamAnswer};
    use ebpdns_proto::constants::TYPE_A;
    use parking_lot::Mutex;
    use std::sync::Arc;

    /// 指定静态延迟/权重的上游（`test_up` 默认 5000ms / 1.0）。
    fn up(id: &str, latency: u32, weight: f64) -> UpstreamCfg {
        UpstreamCfg {
            latency,
            weight,
            ..UpstreamCfg::test_up(id)
        }
    }

    /// 测速全开的最小 cfg（`test_default` 默认 speed_test / ip_speed_check = false）。
    fn speed_cfg(ups: Vec<UpstreamCfg>, fallback: bool) -> ResolverConfig {
        let mut cfg = ResolverConfig::test_default(ups, Vec::new(), 1);
        cfg.speed_test = true;
        cfg.ip_speed_check = true;
        cfg.speed_interval_ms = 2000;
        cfg.ip_speed_cache_ttl = 60;
        cfg.fallback = fallback;
        cfg
    }

    fn resolver(cfg: ResolverConfig, clock: Arc<MockClock>) -> Arc<Resolver> {
        Resolver::new(
            cfg,
            Arc::new(NoopTelemetry),
            clock,
            Arc::new(ScriptedQuerier::new(|_, _, _| Vec::new())),
        )
    }

    fn cand(ip: &str) -> ResolveAnswer {
        ResolveAnswer::new(ip, 60.0, TYPE_A)
    }

    fn hint(lat: f64, probe: &str) -> CandidateSpeedHint {
        CandidateSpeedHint {
            static_lat: lat,
            probe: probe.to_string(),
        }
    }

    fn ids(ups: &[UpstreamCfg]) -> Vec<String> {
        ups.iter().map(|u| u.id.clone()).collect()
    }

    fn vals(cands: &[ResolveAnswer]) -> Vec<String> {
        cands.iter().map(|a| a.value.clone()).collect()
    }

    /* ---------------- ① 排序：eff_lat / max(1, weight) ---------------- */

    #[test]
    fn sorted_upstreams_uses_static_latency_then_weight() {
        let clock = Arc::new(MockClock::new(1_700_000_000.0));
        // 配置序 u1(500ms) / u2(100ms) → 排序后 u2 在前。
        let ups = vec![up("u1", 500, 1.0), up("u2", 100, 1.0)];
        let r = resolver(speed_cfg(ups.clone(), true), clock.clone());
        let (primary, backup) = r.select_upstreams(&ups);
        assert_eq!(ids(&primary), vec!["u2", "u1"], "按静态延迟升序");
        assert!(backup.is_empty(), "max_parallel=3 > 2 → 无备份");

        // 权重参与排序键：u1(150ms/w3)=50 < u2(100ms/w1)=100 → u1 在前。
        let ups = vec![up("u1", 150, 3.0), up("u2", 100, 1.0)];
        let r2 = resolver(speed_cfg(ups.clone(), true), clock);
        let (primary, backup) = r2.select_upstreams(&ups);
        assert_eq!(
            ids(&primary),
            vec!["u1", "u2"],
            "键 = eff_lat / max(1, weight)"
        );
        assert!(backup.is_empty());
    }

    #[test]
    fn sorted_upstreams_prefers_measured_health_and_caches_5s() {
        let clock = Arc::new(MockClock::new(1_700_000_000.0));
        let ups = vec![up("u1", 500, 1.0), up("u2", 100, 1.0)];
        let r = resolver(speed_cfg(ups.clone(), true), clock.clone());
        let rt = Arc::new(ebpdns_upstream::UpstreamRuntime::new());
        r.set_runtime(rt.clone());
        // u1 实测 10ms → 有效延迟 10 < u2 静态 100 → u1 在前（实测优先于静态）。
        rt.health.record("u1", true, 10);
        let (primary, _) = r.select_upstreams(&ups);
        assert_eq!(ids(&primary), vec!["u1", "u2"], "实测延迟优先于静态延迟");

        // 5s 内复用排序缓存：u1 实测变慢也不重排。
        rt.health.record("u1", true, 2000);
        rt.health.record("u1", true, 2000);
        let (primary, _) = r.select_upstreams(&ups);
        assert_eq!(ids(&primary), vec!["u1", "u2"], "5s 内复用排序缓存");

        // 推进 6s → 缓存过期，按新实测均值（≈1337ms）重排 → u2 在前。
        clock.advance(6.0);
        let (primary, _) = r.select_upstreams(&ups);
        assert_eq!(ids(&primary), vec!["u2", "u1"], "排序缓存 5s 过期后重算");

        // 全熔断打开 → 兜底放行全部（不空结果）。
        for _ in 0..3 {
            r.cb_fail("u1");
            r.cb_fail("u2");
        }
        let (primary, _) = r.select_upstreams(&ups);
        assert_eq!(primary.len(), 2, "全部 open → 兜底放行全部");
        // 仅 u2 open → 只排除 u2（u1 复位后应放行）。
        r.cb_ok("u1");
        let (primary, _) = r.select_upstreams(&ups);
        assert_eq!(ids(&primary), vec!["u1"], "open 的上游本轮排除");
    }

    /* ---------------- ② failover 综合权重（2.1.11 优化项 2） ---------------- */

    /// **2.1.11 优化项 2**：排序键必须**同时**纳入成功率与实测 p90。
    ///
    /// 真机依据（2.1.9 终版实测）：li-doh eff 1250ms / 成功率 44%、
    /// `dnspod-doh` 1127ms / 48.9%、`ali-ip2-doh` 1031ms / 39.2%，而 `lan235`
    /// 164ms / 94.9%。旧排序键只看 `eff_lat / max(1, weight)`，低成功率慢上游照样
    /// 被首发。本用例构造同型输入并断言：
    /// 1. 低成功率慢上游被排到最后（`nq`）；
    /// 2. **但仍留在候选里**（`max_parallel_upstreams=3` 不饿死）；
    /// 3. 成功率 100% 时**打分与旧口径逐位一致**（`p90 × 1.0 / weight`）——零行为风险。
    #[test]
    fn upstream_rating_combines_success_rate_and_p90() {
        let clock = Arc::new(MockClock::new(1_700_000_000.0));
        let ups = vec![
            up("good", 164, 1.0),
            up("nq", 1031, 1.0),
            up("mid", 300, 1.0),
        ];
        let mut cfg = speed_cfg(ups.clone(), true);
        cfg.max_parallel_upstreams = 3;
        let r = resolver(cfg, clock);
        let rt = Arc::new(ebpdns_upstream::UpstreamRuntime::new());
        r.set_runtime(rt.clone());

        // good：均值 164ms、成功率 100%（无滑窗 p90 样本 → 走均值基准）。
        for _ in 0..12 {
            rt.health.record("good", true, 164);
        }
        // nq：均值 1031ms、成功率 39.2%（61 失败 / 100 总）。
        for _ in 0..39 {
            rt.health.record("nq", true, 1031);
        }
        for _ in 0..61 {
            rt.health.record("nq", false, 1500);
        }
        // mid：均值 300ms、成功率 100%。
        for _ in 0..12 {
            rt.health.record("mid", true, 300);
        }

        let f_good = r.upstream_rating(&ups[0]);
        let f_nq = r.upstream_rating(&ups[1]);
        let f_mid = r.upstream_rating(&ups[2]);
        assert!(
            (f_good - 164.0).abs() < 1e-6,
            "成功率 100% 时打分必须等于旧口径 base/weight：{f_good}"
        );
        assert!(
            (f_mid - 300.0).abs() < 1e-6,
            "成功率 100% 且未过延迟阈值 → 无任何惩罚：{f_mid}"
        );
        assert!(
            f_nq > f_good * 2.0,
            "低成功率慢上游必须被显著降权：nq={f_nq} good={f_good}"
        );

        let (primary, backup) = r.select_upstreams(&ups);
        let order: Vec<String> = primary
            .iter()
            .chain(backup.iter())
            .map(|u| u.id.clone())
            .collect();
        assert_eq!(
            order,
            vec!["good".to_string(), "mid".to_string(), "nq".to_string()],
            "降权后顺序：健康快上游在前，低成功率慢上游在后"
        );
        // 关键：max_parallel_upstreams=3 时**仍取满 3 个候选**（可用上游不足不饿死）。
        assert_eq!(primary.len(), 3, "不得因降权把候选数饿死");
    }

    /// **2.1.11 优化项 2**：没有任何实测样本（冷启动）时，打分必须退回静态延迟口径，
    /// 即与 2.1.9 的 `latency / max(1, weight)` **逐位一致**（零行为风险）。
    #[test]
    fn upstream_rating_cold_start_equals_static_latency_over_weight() {
        let clock = Arc::new(MockClock::new(1_700_000_000.0));
        let ups = vec![up("a", 500, 1.0), up("b", 100, 4.0)];
        let r = resolver(speed_cfg(ups.clone(), true), clock);
        let rt = Arc::new(ebpdns_upstream::UpstreamRuntime::new());
        r.set_runtime(rt);
        assert!((r.upstream_rating(&ups[0]) - 500.0).abs() < 1e-9);
        assert!((r.upstream_rating(&ups[1]) - 25.0).abs() < 1e-9, "100/4");
        let (primary, _) = r.select_upstreams(&ups);
        assert_eq!(ids(&primary), vec!["b", "a"], "冷启动 = 静态延迟/权重口径");
    }

    /* ---------------- ②2 复合键再校准（2.1.12 优化项 ②） ---------------- */

    /// 2.1.12：`rating_sr_floor` 的**边界**语义。
    ///
    /// `pen = 1 / max(sr, floor)`：
    /// - `sr == floor` 与 `sr < floor` 打**完全相同**的分（下限夹住，不再无限放大）；
    /// - `sr > floor` 时严格按 `1/sr` 递减（sr 越高分越低）。
    ///
    /// 用同一实测均值（500ms）造三个只差成功率的假上游，排除 `base` 的干扰。
    #[test]
    fn upstream_rating_sr_floor_boundary() {
        let clock = Arc::new(MockClock::new(1_700_000_000.0));
        // 三台上游同静态延迟，实测均值都用 500ms 的成功样本喂出来。
        let ups = vec![
            up("sr60", 500, 1.0),
            up("sr50", 500, 1.0),
            up("sr40", 500, 1.0),
        ];
        let r = resolver(speed_cfg(ups.clone(), true), clock);
        let rt = Arc::new(ebpdns_upstream::UpstreamRuntime::new());
        r.set_runtime(rt.clone());
        // sr = 0.6（60 ok / 40 fail）
        for _ in 0..60 {
            rt.health.record("sr60", true, 500);
        }
        for _ in 0..40 {
            rt.health.record("sr60", false, 1500);
        }
        // sr = 0.5（恰好等于下限）
        for _ in 0..50 {
            rt.health.record("sr50", true, 500);
        }
        for _ in 0..50 {
            rt.health.record("sr50", false, 1500);
        }
        // sr = 0.4（低于下限）
        for _ in 0..40 {
            rt.health.record("sr40", true, 500);
        }
        for _ in 0..60 {
            rt.health.record("sr40", false, 1500);
        }

        let f60 = r.upstream_rating(&ups[0]);
        let f50 = r.upstream_rating(&ups[1]);
        let f40 = r.upstream_rating(&ups[2]);
        // 期望：500/0.6 = 833.33 ; 500/0.5 = 1000 ; 500/max(0.4,0.5) = 1000
        assert!(
            (f60 - 500.0 / 0.6).abs() < 1e-6,
            "sr=0.6 必须按 1/sr 计：{f60}"
        );
        assert!((f50 - 1000.0).abs() < 1e-6, "sr=0.5 → ×2.0：{f50}");
        assert!(
            (f40 - 1000.0).abs() < 1e-6,
            "sr=0.4 被下限 0.5 夹住，必须与 sr=0.5 同分（不得 ×2.5）：{f40}"
        );
        assert!(
            f60 < f50 && (f50 - f40).abs() < 1e-9,
            "边界两侧必须严格（sr>floor 更低分、sr<=floor 相等）"
        );
    }

    /// 2.1.12：`rating_sr_floor` **可配置**（配置收紧下限 → 低成功率上游被进一步放大惩罚）。
    #[test]
    fn upstream_rating_sr_floor_is_configurable() {
        let clock = Arc::new(MockClock::new(1_700_000_000.0));
        let ups = vec![up("lo", 500, 1.0)];
        let mut cfg = speed_cfg(ups.clone(), true);
        cfg.rating_sr_floor = 0.25;
        let r = resolver(cfg, clock.clone());
        let rt = Arc::new(ebpdns_upstream::UpstreamRuntime::new());
        r.set_runtime(rt.clone());
        // sr = 0.25 恰好等于收紧后的下限 → 500/0.25 = 2000。
        for _ in 0..25 {
            rt.health.record("lo", true, 500);
        }
        for _ in 0..75 {
            rt.health.record("lo", false, 1500);
        }
        assert!(
            (r.upstream_rating(&ups[0]) - 2000.0).abs() < 1e-6,
            "floor=0.25 时 sr=0.25 → ×4.0，实际 {}",
            r.upstream_rating(&ups[0])
        );

        // 非法值（0 / 负 / NaN）必须回退默认下限 0.5，绝不产生 inf/NaN。
        let mut cfg2 = speed_cfg(ups.clone(), true);
        cfg2.rating_sr_floor = 0.0;
        let r2 = resolver(cfg2, clock);
        r2.set_runtime(rt.clone());
        let f = r2.upstream_rating(&ups[0]);
        assert!(f.is_finite(), "非法 floor 不得产生非有限分值：{f}");
        assert!((f - 1000.0).abs() < 1e-6, "0 → 回退默认 0.5（×2.0）：{f}");
    }

    /// 2.1.12：**绝对延迟惩罚** `base > 800ms → ×1.5`，且**只对实测值生效**。
    ///
    /// - 实测慢（1000ms）+ 成功率 100% → `1000 × 1.0 × 1.5 = 1500`；
    /// - 实测快（600ms，**低于** 800ms 阈值）+ 成功率 100% → `600`（不受惩罚）；
    /// - 冷启动：静态 `latency = 5000`（> 800ms）**无任何样本** → 仍是 `5000`
    ///   （静态延迟是运维声明值，不得被延迟惩罚改变 —— 这是 2.1.11 位等价的保证）。
    #[test]
    fn upstream_rating_absolute_latency_penalty_only_for_measured() {
        let clock = Arc::new(MockClock::new(1_700_000_000.0));
        let ups = vec![
            up("slow1000", 1000, 1.0),
            up("fast600", 600, 1.0),
            up("cold5000", 5000, 1.0),
        ];
        let r = resolver(speed_cfg(ups.clone(), true), clock);
        let rt = Arc::new(ebpdns_upstream::UpstreamRuntime::new());
        r.set_runtime(rt.clone());
        for _ in 0..12 {
            rt.health.record("slow1000", true, 1000);
        }
        for _ in 0..12 {
            rt.health.record("fast600", true, 600);
        }

        let f_slow = r.upstream_rating(&ups[0]);
        let f_fast = r.upstream_rating(&ups[1]);
        let f_cold = r.upstream_rating(&ups[2]);
        assert!(
            (f_slow - 1500.0).abs() < 1e-6,
            "实测 1000ms > 800ms 阈值 → ×1.5，实际 {f_slow}"
        );
        assert!(
            (f_fast - 600.0).abs() < 1e-6,
            "实测 600ms 未过阈值 → 不惩罚，实际 {f_fast}"
        );
        assert!(
            (f_cold - 5000.0).abs() < 1e-9,
            "冷启动静态延迟（即使 >800ms）绝不触发延迟惩罚，实际 {f_cold}"
        );
        assert_eq!(
            RATING_SLOW_P90_MS, 800.0,
            "阈值是契约常量（改动必须同步注释与报告）"
        );
        assert_eq!(RATING_SLOW_PENALTY, 1.5);
    }

    /// 2.1.12：给定一组 `(p90/均值, sr)`，**排序必须符合复合键预期**，
    /// 且 `max_parallel_upstreams=3` 时仍能**选满 3 个候选**（不得把上游压到"不可用"）。
    #[test]
    fn upstream_rating_composite_key_orders_as_expected_and_keeps_candidates() {
        let clock = Arc::new(MockClock::new(1_700_000_000.0));
        // 复刻 2.1.11 真机实测的 (延迟, 成功率) 三例 + 两台快上游。
        let ups = vec![
            up("lan235", 248, 1.0),      // 快 + 高成功率 → 第 1
            up("ali-doh", 692, 1.0),     // 中延迟 + 61.9% → 第 2
            up("ali-ip-doh", 1256, 1.0), // 高延迟 + 35.9% → 最后
            up("lan235tcp", 382, 1.0),   // 快 + 57.8%
            up("dnspod-doh", 690, 1.0),  // 中延迟 + 59.5%
        ];
        let mut cfg = speed_cfg(ups.clone(), true);
        cfg.max_parallel_upstreams = 3;
        let r = resolver(cfg, clock);
        let rt = Arc::new(ebpdns_upstream::UpstreamRuntime::new());
        r.set_runtime(rt.clone());
        // (id, ok 次数@均值延迟, fail 次数@1500) —— 成功率与均值都按实测比例构造。
        let script: [(&str, f64, u32, u32); 5] = [
            ("lan235", 248.0, 95, 5),       // 95.0%
            ("ali-doh", 692.0, 62, 38),     // 62.0%
            ("ali-ip-doh", 1256.0, 36, 64), // 36.0%
            ("lan235tcp", 382.0, 58, 42),   // 58.0%
            ("dnspod-doh", 690.0, 60, 40),  // 60.0%
        ];
        for (id, lat, ok, fail) in script {
            for _ in 0..ok {
                rt.health.record(id, true, lat as u64);
            }
            for _ in 0..fail {
                rt.health.record(id, false, 1500);
            }
        }
        let score: Vec<(&str, f64)> = ups
            .iter()
            .map(|u| (u.id.as_str(), r.upstream_rating(u)))
            .collect();
        // 复算契约：score = avg × (1/max(sr, 0.5)) × (avg > 800 ? 1.5 : 1.0)
        // lan235     = 248/0.95            = 261.05
        // lan235tcp  = 382/0.58            = 658.62
        // dnspod-doh = 690/0.60            = 1150.00
        // ali-doh    = 692/0.62            = 1116.13
        // ali-ip-doh = 1256/0.5 × 1.5      = 3768.00
        let got: Vec<(&str, f64)> = {
            let mut v = score.clone();
            v.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
            v
        };
        assert_eq!(
            got.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
            vec!["lan235", "lan235tcp", "ali-doh", "dnspod-doh", "ali-ip-doh"],
            "复合键排序：快+高成功率在前，高延迟+低成功率在最后（实测分值 {got:?}）"
        );
        assert!(
            (got[0].1 - 261.052_631_578_947_4).abs() < 1e-3,
            "lan235 = 248/0.95，实际 {}",
            got[0].1
        );
        assert!(
            (got[4].1 - 3768.0).abs() < 1e-3,
            "ali-ip-doh = 1256/max(0.36,0.5)×1.5 = 3768，实际 {}",
            got[4].1
        );
        // **不得饿死候选**：最坏（被 ×1.5 惩罚）的上游仍进入首批候选。
        let (primary, backup) = r.select_upstreams(&ups);
        assert_eq!(primary.len(), 3, "max_parallel_upstreams=3 必须仍选满 3 个");
        assert_eq!(backup.len(), 2, "其余留作后备（不排除、不判不可用）");
        assert_eq!(
            ids(&primary),
            vec!["lan235", "lan235tcp", "ali-doh"],
            "首批 = 复合键最优的 3 个"
        );
    }

    /// 2.1.12：成功率**全为 0** 且从未成功（无 `ok` 样本 → `base` 走静态延迟、
    /// `measured=false`）时，打分仍是有限值且不触发延迟惩罚（fail-safe，不 NaN/不 inf）。
    #[test]
    fn upstream_rating_all_failures_stays_finite() {
        let clock = Arc::new(MockClock::new(1_700_000_000.0));
        let ups = vec![up("dead", 5000, 1.0)];
        let r = resolver(speed_cfg(ups.clone(), true), clock);
        let rt = Arc::new(ebpdns_upstream::UpstreamRuntime::new());
        r.set_runtime(rt.clone());
        for _ in 0..10 {
            rt.health.record("dead", false, 1500);
        }
        let f = r.upstream_rating(&ups[0]);
        assert!(f.is_finite() && f > 0.0, "全失败也必须给出有限分值：{f}");
        assert!(
            (f - 5000.0 * 2.0).abs() < 1e-6,
            "sr=0 → 1/max(0,0.5)=2.0、无实测基准 → 不做延迟惩罚：{f}"
        );
    }

    /* ---------------- ② fallback=false 只发 1 个上游 ---------------- */

    /// 计数 querier：记录每次 `query_parallel` 收到的上游 id，并给每个上游回一条 A 答案。
    struct CountingQuerier {
        seen: Mutex<Vec<Vec<String>>>,
    }

    impl CountingQuerier {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                seen: Mutex::new(Vec::new()),
            })
        }
        fn calls(&self) -> Vec<Vec<String>> {
            self.seen.lock().clone()
        }
    }

    #[async_trait::async_trait]
    impl ParallelQuerier for CountingQuerier {
        async fn query_parallel(
            &self,
            ups: &[UpstreamCfg],
            _qname: &str,
            _qtype: &str,
            _depth: u32,
        ) -> Vec<UpstreamAnswer> {
            self.seen
                .lock()
                .push(ups.iter().map(|u| u.id.clone()).collect());
            ups.iter()
                .map(|u| {
                    UpstreamAnswer::ok(
                        &u.id,
                        0,
                        vec![ResolveAnswer::new("1.1.1.1", 60.0, TYPE_A)],
                        Vec::new(),
                    )
                })
                .collect()
        }
    }

    #[tokio::test]
    async fn fallback_disabled_queries_only_fastest_upstream() {
        // 配置序 u1(500ms) / u2(100ms)：排序后最快是 u2。
        let mut cfg = speed_cfg(vec![up("u1", 500, 1.0), up("u2", 100, 1.0)], false);
        cfg.max_parallel_upstreams = 3; // 即便并发上限 3，fallback=false 也只发 1 个。
        let q = CountingQuerier::new();
        let r = Resolver::new(
            cfg,
            Arc::new(NoopTelemetry),
            Arc::new(MockClock::new(1_700_000_000.0)),
            q.clone(),
        );
        let res = r
            .clone()
            .resolve("fboff.test", "A", ResolveOpts::default())
            .await;
        assert_eq!(res.rcode, 0);
        let calls = q.calls();
        assert_eq!(calls.len(), 1, "fallback=false 只查一轮，无回退");
        assert_eq!(
            calls[0],
            vec!["u2".to_string()],
            "只取排序后最快的 1 个上游"
        );
    }

    #[tokio::test]
    async fn fallback_enabled_queries_all_sorted_upstreams_once() {
        let mut cfg = speed_cfg(vec![up("u1", 500, 1.0), up("u2", 100, 1.0)], true);
        cfg.max_parallel_upstreams = 3;
        let q = CountingQuerier::new();
        let r = Resolver::new(
            cfg,
            Arc::new(NoopTelemetry),
            Arc::new(MockClock::new(1_700_000_000.0)),
            q.clone(),
        );
        let res = r
            .clone()
            .resolve("fbon.test", "A", ResolveOpts::default())
            .await;
        assert_eq!(res.rcode, 0);
        let calls = q.calls();
        assert_eq!(calls.len(), 1, "首选已含全部上游 → 无需回退");
        assert_eq!(
            calls[0],
            vec!["u2".to_string(), "u1".to_string()],
            "首选按 eff_lat 排序"
        );
    }

    /* ---------------- ②b 预取：固定单上游（优化项 9） ---------------- */

    /// ①候选选择：给一组不同 eff_lat + 部分熔断打开的上游，
    /// `prefetch_upstream` 必须返回**恰好 1 个**且是 `eff_lat/max(1,weight)` 最低者。
    #[test]
    fn prefetch_upstream_picks_exactly_one_lowest_eff_lat_skipping_open() {
        let clock = Arc::new(MockClock::new(1_700_000_000.0));
        let ups = vec![
            up("slow", 500, 1.0),
            up("mid", 100, 1.0),
            up("fast", 20, 1.0),
        ];
        let r = resolver(speed_cfg(ups.clone(), true), clock.clone());
        let rt = Arc::new(ebpdns_upstream::UpstreamRuntime::new());
        r.set_runtime(rt.clone());
        // 实测均值：mid=30 最低（静态 20 的 fast 无样本 → eff=静态 20，仍最低）。
        rt.health.record("mid", true, 30);
        assert_eq!(
            r.prefetch_upstream(&ups).map(|u| u.id),
            Some("fast".to_string()),
            "无样本上游回退静态延迟 20 → 最低"
        );
        // fast 打开 → 跳到下一个（mid）。
        for _ in 0..3 {
            r.cb_fail("fast");
        }
        assert!(r.cb_is_open("fast"));
        let picked = r.prefetch_upstream(&ups).expect("必须选出 1 个");
        assert_eq!(picked.id, "mid", "跳过熔断打开的上游");
        // 返回值只能是 1 个（函数签名即 Option<UpstreamCfg>，这里再断言"不是切片/多值"语义）。
        let one = r.query_targets(&ups, true);
        assert_eq!(one.len(), 1, "预取目标集必须是 1 个");
        assert_eq!(one[0].id, "mid");
        // 权重参与同一排序键：mid(30/1)=30 vs slow(500/1)=500 → mid 仍在前。
        assert_eq!(ids(&[picked]), vec!["mid".to_string()]);
    }

    /// ②全打开退化分支：仍返回 1 个（`eff_lat/max(1,weight)` 最低者），不跳过预取。
    #[test]
    fn prefetch_upstream_degrades_when_all_open() {
        let clock = Arc::new(MockClock::new(1_700_000_000.0));
        let ups = vec![up("a", 400, 1.0), up("b", 50, 1.0), up("c", 900, 1.0)];
        let r = resolver(speed_cfg(ups.clone(), true), clock);
        for id in ["a", "b", "c"] {
            for _ in 0..3 {
                r.cb_fail(id);
            }
        }
        assert_eq!(r.cb_open_ids().len(), 3, "三个上游全部打开");
        let picked = r.prefetch_upstream(&ups).expect("全打开也必须选出 1 个");
        assert_eq!(picked.id, "b", "退化为 eff_lat 最低者");
        assert_eq!(r.query_targets(&ups, true).len(), 1);
        // 无启用上游 → None（不 panic）。
        let mut off = ups.clone();
        for u in off.iter_mut() {
            u.enabled = false;
        }
        assert!(r.prefetch_upstream(&off).is_none());
    }

    /// ③预取路径不产生多上游并发：用记录型 querier 断言被调用的 up id 集合大小恒为 1。
    #[tokio::test]
    async fn prefetch_queries_exactly_one_upstream_while_data_plane_queries_many() {
        let mut cfg = speed_cfg(
            vec![up("u1", 500, 1.0), up("u2", 100, 1.0), up("u3", 300, 1.0)],
            true,
        );
        cfg.max_parallel_upstreams = 3;
        let q = CountingQuerier::new();
        let r = Resolver::new(
            cfg,
            Arc::new(NoopTelemetry),
            Arc::new(MockClock::new(1_700_000_000.0)),
            q.clone(),
        );
        // 数据面：max_parallel_upstreams=3 → 一次调用带 3 个上游（对照基线）。
        let _ = r
            .clone()
            .resolve("prefetch-ctrl.test", "A", ResolveOpts::default())
            .await;
        let dp = q.calls();
        assert_eq!(dp.len(), 1);
        assert_eq!(dp[0].len(), 3, "数据面并发 3 个上游（对照）");

        // 预取：只应产生 1 个上游的调用，且是 eff_lat 最低的 u2。
        let before = q.calls().len();
        let res = r
            .clone()
            .resolve_prefetch(
                "prefetch-one.test",
                "A",
                ResolveOpts {
                    force_refresh: true,
                    silent: true,
                    counted: false,
                    ..Default::default()
                },
            )
            .await;
        assert_eq!(res.rcode, 0);
        let calls = q.calls();
        let pf = &calls[before..];
        assert!(!pf.is_empty(), "预取必须发起查询");
        for c in pf {
            assert_eq!(c.len(), 1, "预取每次调用只能有 1 个上游，实际 {c:?}");
        }
        assert_eq!(pf[0], vec!["u2".to_string()], "选中 eff_lat 最低的 u2");
        assert_eq!(pf.len(), 1, "预取不启用后备波（不产生第二轮）");
    }

    /// 要求 4：预取失败**不得**计入数据面 `circuit_fails`（与探针解耦同口径）。
    #[tokio::test]
    async fn prefetch_failure_does_not_open_breaker() {
        let mut cfg = speed_cfg(vec![up("u1", 100, 1.0), up("u2", 200, 1.0)], true);
        cfg.circuit_fails = 2;
        // 让上游"传输失败"：querier 返回 rcode=None 的失败应答。
        let q = Arc::new(ScriptedQuerier::new(|_n, _t, _d| {
            vec![UpstreamAnswer::fail("u1")]
        }));
        let r = Resolver::new(
            cfg,
            Arc::new(NoopTelemetry),
            Arc::new(MockClock::new(1_700_000_000.0)),
            q,
        );
        for _ in 0..5 {
            let _ = r
                .clone()
                .resolve_prefetch(
                    "pf-fail.test",
                    "A",
                    ResolveOpts {
                        force_refresh: true,
                        silent: true,
                        counted: false,
                        ..Default::default()
                    },
                )
                .await;
        }
        assert!(
            !r.cb_is_open("u1"),
            "预取失败不得打开熔断（优化项 9 要求 4）"
        );
        assert_eq!(r.cb_view("u1").fails, 0, "预取失败不计入数据面 fails");
        assert!(r.cb_view("u1").probe_fail >= 5, "预取失败记独立 probe_fail");

        // 对照：同样 5 次**数据面**失败会打开熔断（阈值 2）→ 证明解耦确实生效。
        for _ in 0..5 {
            let _ = r
                .clone()
                .resolve("pf-fail-dp.test", "A", ResolveOpts::default())
                .await;
        }
        assert!(r.cb_is_open("u1"), "数据面失败仍正常打开熔断（对照）");
    }

    /* ---------------- ③ 测速节流与缓存命中 ---------------- */

    #[test]
    fn speed_sort_throttles_and_uses_cached_ewma() {
        let clock = Arc::new(MockClock::new(1_700_000_000.0));
        let r = resolver(speed_cfg(vec![up("u1", 10, 1.0)], true), clock.clone());
        let cands = vec![cand("1.1.1.1"), cand("2.2.2.2")];
        let hints = vec![hint(30.0, "udp53"), hint(200.0, "udp53")];

        // 首次：非节流窗口 → 允许测速（重排不增删候选）。
        let out = r.speed_sort(&cands, &hints, "speed.test");
        let mut got = vals(&out);
        got.sort();
        assert_eq!(got, vec!["1.1.1.1".to_string(), "2.2.2.2".to_string()]);
        // **[历史归因]** 未命中 → 静态延迟兜底写入速度表（Python setdefault）。
        {
            let t = r.ip_speed.lock();
            assert_eq!(t.get("1.1.1.1").map(|v| v.0), Some(30.0));
            assert_eq!(t.get("2.2.2.2").map(|v| v.0), Some(200.0));
        }
        // 同域名节流窗口内 → 原序返回，不再测速。
        let out2 = r.speed_sort(&cands, &hints, "speed.test");
        assert_eq!(
            vals(&out2),
            vec!["1.1.1.1", "2.2.2.2"],
            "节流窗口内保持原序"
        );

        // 换域名（节流按域名独立）→ 命中新鲜缓存，不覆盖表中已探明 EWMA。
        r.record_ip_speed("2.2.2.2", 5.0); // 0.7*200 + 0.3*5 = 141.5
        let got = r.ip_speed.lock().get("2.2.2.2").map(|v| v.0).unwrap_or(0.0);
        assert!(
            (got - 141.5).abs() < 1e-6,
            "EWMA 应为 0.7*旧+0.3*新, 实际 {got}"
        );
        let _ = r.speed_sort(&cands, &hints, "speed2.test");
        {
            let t = r.ip_speed.lock();
            assert_eq!(
                t.get("2.2.2.2").map(|v| v.0),
                Some(141.5),
                "命中新鲜缓存不覆盖"
            );
            assert_eq!(
                t.get("1.1.1.1").map(|v| v.0),
                Some(30.0),
                "命中新鲜缓存不覆盖"
            );
        }

        // 旧样本超 3600s → 直接取新值（不走 EWMA）。
        clock.advance(3601.0);
        r.record_ip_speed("2.2.2.2", 7.0);
        assert_eq!(
            r.ip_speed.lock().get("2.2.2.2").map(|v| v.0),
            Some(7.0),
            "旧样本过期 → 直接取新值"
        );

        // 节流：窗口内不测速（新 IP 不写表）；超过 interval 后重新测速写表。
        let fresh = vec![cand("5.5.5.5"), cand("6.6.6.6")];
        let fresh_hints = vec![hint(11.0, "udp53"), hint(22.0, "udp53")];
        let _ = r.speed_sort(&fresh, &fresh_hints, "thr.test");
        r.ip_speed.lock().remove("5.5.5.5");
        let _ = r.speed_sort(&fresh, &fresh_hints, "thr.test");
        assert!(
            r.ip_speed.lock().get("5.5.5.5").is_none(),
            "节流窗口内不测速（不写表）"
        );
        clock.advance(3.0); // > speed_interval_ms = 2000ms
        let _ = r.speed_sort(&fresh, &fresh_hints, "thr.test");
        assert_eq!(
            r.ip_speed.lock().get("5.5.5.5").map(|v| v.0),
            Some(11.0),
            "超过 interval 重新测速"
        );

        // 过期命中：表内值不刷新（等后台探测回写），TTL 判定用静态兜底。
        clock.advance(61.0); // > ip_speed_cache_ttl = 60s
        let _ = r.speed_sort(&cands, &hints, "speed3.test");
        assert_eq!(
            r.ip_speed.lock().get("2.2.2.2").map(|v| v.0),
            Some(7.0),
            "过期命中不覆盖表"
        );
    }

    #[test]
    fn speed_sort_disabled_or_single_candidate_keeps_order() {
        let clock = Arc::new(MockClock::new(1_700_000_000.0));
        // ip_speed_check=false（test_default）→ 原序返回。
        let mut cfg = ResolverConfig::test_default(vec![up("u1", 10, 1.0)], Vec::new(), 1);
        cfg.speed_test = true;
        let r = resolver(cfg, clock.clone());
        let cands = vec![cand("9.9.9.9"), cand("8.8.8.8")];
        let hints = vec![hint(1.0, "udp53"), hint(2.0, "udp53")];
        assert_eq!(
            vals(&r.speed_sort(&cands, &hints, "off.test")),
            vec!["9.9.9.9", "8.8.8.8"],
            "ip_speed_check=false → 保持原序"
        );
        // 单候选 → 原序返回。
        let r2 = resolver(speed_cfg(vec![up("u1", 10, 1.0)], true), clock);
        assert_eq!(
            vals(&r2.speed_sort(&cands[..1], &hints[..1], "one.test")),
            vec!["9.9.9.9"]
        );
        // 空候选 → 空输出，不 panic。
        assert!(r2.speed_sort(&[], &[], "empty.test").is_empty());
    }

    /// fail-safe：不可路由地址（RFC5737 TEST-NET-1）探测超时返回 None，绝不 panic。
    #[tokio::test]
    async fn probe_candidate_ip_is_fail_safe() {
        let mut cfg = speed_cfg(vec![up("u1", 10, 1.0)], true);
        cfg.speed_timeout_ms = 50;
        let r = resolver(cfg, Arc::new(MockClock::new(1_700_000_000.0)));
        assert!(r
            .probe_candidate_ip_once("192.0.2.1", "udp53")
            .await
            .is_none());
        assert!(r
            .probe_candidate_ip_once("192.0.2.1", "tcp443")
            .await
            .is_none());
        // **[历史归因]** 未知模式按 udp53 处理（Python 每上游默认），同样 fail-safe。
        assert!(r.probe_candidate_ip_once("192.0.2.1", "").await.is_none());
    }

    /* ---------------- ④ 加权随机抽样：权重 1/(measured+10) ---------------- */

    #[test]
    fn weighted_sample_order_follows_cumulative_weights() {
        // measured = [0, 10, 90] → 权重 [0.1, 0.05, 0.01]（总 0.16）。
        let weights = vec![1.0 / 10.0, 1.0 / 20.0, 1.0 / 100.0];
        // 固定抽样序列（按 total 比例）：0.0 → 第一项；0.7*0.06 = 0.042 → 第二项。
        let mut seq = vec![0.0_f64, 0.7].into_iter();
        let mut draw = |hi: f64| -> f64 { seq.next().unwrap_or(0.0) * hi };
        assert_eq!(
            weighted_sample_order(&weights, &mut draw),
            vec![0, 1, 2],
            "按累积权重抽取"
        );
        // 0.99*0.16 = 0.1584 → 落在第三项区间。
        let mut seq2 = vec![0.99_f64, 0.0].into_iter();
        let mut draw2 = |hi: f64| -> f64 { seq2.next().unwrap_or(0.0) * hi };
        let order2 = weighted_sample_order(&weights, &mut draw2);
        assert_eq!(order2.first(), Some(&2), "高比例命中权重最小区间之外的末项");
        assert_eq!(order2.len(), 3, "不放回 → 每项恰好出现一次");

        // 全 0 权重 / 非法权重 → 保序（fail-safe，不 panic、不除零）。
        let zero = vec![0.0_f64, 0.0, 0.0];
        let mut draw3 = |_hi: f64| -> f64 { 0.0 };
        assert_eq!(weighted_sample_order(&zero, &mut draw3), vec![0, 1, 2]);
        let bad = vec![f64::NAN, -1.0, f64::INFINITY];
        let mut draw4 = |_hi: f64| -> f64 { 0.0 };
        assert_eq!(weighted_sample_order(&bad, &mut draw4), vec![0, 1, 2]);
        // 空输入 → 空输出。
        let mut draw5 = |_hi: f64| -> f64 { 0.0 };
        assert!(weighted_sample_order(&[], &mut draw5).is_empty());
    }

    #[test]
    fn weighted_sample_order_prefers_fast_candidate_seeded() {
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};
        // measured = [1ms, 10000ms] → 权重 [1/11, 1/10010]。
        let weights = vec![1.0 / 11.0, 1.0 / 10010.0];
        let mut rng = StdRng::seed_from_u64(42);
        let mut fast_first = 0;
        for _ in 0..500 {
            let mut draw = |hi: f64| -> f64 { rng.gen_range(0.0..hi) };
            if weighted_sample_order(&weights, &mut draw).first() == Some(&0) {
                fast_first += 1;
            }
        }
        // P(慢者先) ≈ 1.1e-3 → 500 次里「快者先」几乎必然 ≥ 450（固定种子，可复现）。
        assert!(fast_first >= 450, "快候选应显著优先, 实际 {fast_first}");
    }

    /* ---------------- ⑤ trace 开关（性能上限：非人工查询不构造 trace） ---------------- */

    /// `ResolveOpts` 默认 **不** 构造 trace；只有显式 `with_trace()` 才打开。
    #[test]
    fn resolve_opts_trace_defaults_off() {
        assert!(
            !ResolveOpts::default().trace,
            "默认关闭（数据面不读 trace）"
        );
        assert!(ResolveOpts::default().with_trace().trace, "显式开启");
        // 其余字段保持默认，不因开关引入行为差异。
        let o = ResolveOpts::default().with_trace();
        assert!(!o.counted && !o.silent && !o.force_refresh && o.depth == 0);
    }

    /// miss 路径：关闭 trace 时 `ResolveResult::trace` 为空且不报错；
    /// 打开时同一条链路有事件（形状/语义不变）。
    #[tokio::test]
    async fn resolve_trace_gate_miss_path() {
        let q = ScriptedQuerier::new(|_, _, _| {
            vec![UpstreamAnswer::ok(
                "u1",
                0,
                vec![ResolveAnswer::new("1.2.3.4", 60.0, TYPE_A)],
                Vec::new(),
            )]
        });
        let r = Resolver::new(
            speed_cfg(vec![up("u1", 10, 1.0)], true),
            Arc::new(NoopTelemetry),
            Arc::new(MockClock::new(1_700_000_000.0)),
            Arc::new(q),
        );
        let off = r
            .clone()
            .resolve("trace-off.test", "A", ResolveOpts::default())
            .await;
        assert!(off.trace.is_empty(), "关闭时 trace 恒为空（不构造）");
        assert_eq!(off.answers[0].value, "1.2.3.4", "答案不受 trace 开关影响");

        let on = r
            .clone()
            .resolve("trace-on.test", "A", ResolveOpts::default().with_trace())
            .await;
        assert!(!on.trace.is_empty(), "打开时 trace 有事件");
        assert!(
            on.trace
                .iter()
                .any(|t| t.tag == "client" && t.text.contains("入口")),
            "入口事件仍在: {:?}",
            on.trace
        );
        assert_eq!(on.answers[0].value, "1.2.3.4");
    }

    /// 缓存命中路径同样受门控（命中是数据面最高频路径）。
    #[tokio::test]
    async fn resolve_trace_gate_hit_path() {
        let q = ScriptedQuerier::new(|_, _, _| {
            vec![UpstreamAnswer::ok(
                "u1",
                0,
                vec![ResolveAnswer::new("5.6.7.8", 60.0, TYPE_A)],
                Vec::new(),
            )]
        });
        let r = Resolver::new(
            speed_cfg(vec![up("u1", 10, 1.0)], true),
            Arc::new(NoopTelemetry),
            Arc::new(MockClock::new(1_700_000_000.0)),
            Arc::new(q),
        );
        // 先写缓存（无 trace）。
        let _ = r
            .clone()
            .resolve("hit.test", "A", ResolveOpts::default())
            .await;
        let hit_off = r
            .clone()
            .resolve("hit.test", "A", ResolveOpts::default())
            .await;
        assert!(hit_off.hit, "第二次为缓存命中");
        assert!(hit_off.trace.is_empty(), "命中路径关闭时 trace 为空");
        let hit_on = r
            .clone()
            .resolve("hit.test", "A", ResolveOpts::default().with_trace())
            .await;
        assert!(hit_on.hit);
        assert!(!hit_on.trace.is_empty(), "命中路径打开时有事件");
        assert!(
            hit_on.trace.iter().any(|t| t.text.contains("缓存命中")),
            "命中 trace 文本保留: {:?}",
            hit_on.trace
        );
    }

    /* ---------------- ⑥ serve_stale × 缓存热切换（一致性缺口） ---------------- */

    /// 一致性：`reload` 换缓存策略时会**重建缓存实例**，必须同时把
    /// `stale_window` 重新下发；否则热切换后 serve-stale 退化为
    /// **[历史归因]** 「过期即删」，与配置/ Python `reload` 语义不符。
    #[tokio::test]
    async fn serve_stale_survives_cache_policy_swap() {
        let clock = Arc::new(MockClock::new(1_700_000_000.0));
        let mut cfg = speed_cfg(vec![up("u1", 10, 1.0)], true);
        cfg.serve_stale = true;
        cfg.stale_ttl = 300.0;
        cfg.cache_policy = "lru".to_string();
        let r = Resolver::new(
            cfg.clone(),
            Arc::new(NoopTelemetry),
            clock.clone(),
            Arc::new(ScriptedQuerier::new(|_, _, _| {
                vec![UpstreamAnswer::ok(
                    "u1",
                    0,
                    vec![ResolveAnswer::new("3.3.3.3", 60.0, TYPE_A)],
                    Vec::new(),
                )]
            })),
        );
        // 写缓存，然后热切换缓存策略（触发 `cache.swap` 重建实例）。
        let first = r
            .clone()
            .resolve("swap-stale.test", "A", ResolveOpts::default())
            .await;
        assert_eq!(first.answers[0].value, "3.3.3.3");

        let mut next = cfg.clone();
        next.cache_policy = "tinylfu".to_string();
        r.reload(next);

        // 换实例后重新写一条，再让时钟走过 TTL 但留在 stale 窗口内。
        let _ = r
            .clone()
            .resolve("swap-stale.test", "A", ResolveOpts::default())
            .await;
        clock.advance(120.0); // > ttl(60s)，< stale_ttl(300s)
        let stale = r
            .clone()
            .resolve("swap-stale.test", "A", ResolveOpts::default())
            .await;
        assert!(
            stale.hit,
            "热切换后 stale_window 必须已重新下发（否则过期条目被立即删除）"
        );
        assert_eq!(stale.ttl_left, 0.0, "serve-stale 应答 TTL=0");
        assert_eq!(stale.answers[0].value, "3.3.3.3");
    }

    /// `schedule_prefetch` 内部自行拼 key，语义与旧 `"{d}|{qtype}"` 一致。
    #[test]
    fn schedule_prefetch_derives_key_from_domain_qtype() {
        let mut cfg = ResolverConfig::test_default(vec![up("u1", 10, 1.0)], Vec::new(), 1);
        cfg.prefetch = true;
        let r = resolver(cfg, Arc::new(MockClock::new(1_700_000_000.0)));
        r.schedule_prefetch("aa.test", "AAAA", 0.0);
        assert_eq!(r.prefetch_order(), vec!["aa.test|AAAA".to_string()]);
        // prefetch 关闭 → 不入队。
        let mut off = ResolverConfig::test_default(vec![up("u1", 10, 1.0)], Vec::new(), 1);
        off.prefetch = false;
        let r2 = resolver(off, Arc::new(MockClock::new(1_700_000_000.0)));
        r2.schedule_prefetch("bb.test", "A", 0.0);
        assert!(r2.prefetch_order().is_empty());
    }

    /* ---------------- 缺陷 A：规则命中分类计数（全量） ---------------- */

    /// 构造一条规则（`match` / `action` / 可选 `group` / `ip`）。
    fn mk_rule(m: &str, action: &str, group: Option<&str>, ip: Option<&str>) -> Rule {
        let mut map = serde_json::Map::new();
        map.insert(
            "match".to_string(),
            serde_json::Value::String(m.to_string()),
        );
        map.insert(
            "action".to_string(),
            serde_json::Value::String(action.to_string()),
        );
        if let Some(g) = group {
            map.insert(
                "group".to_string(),
                serde_json::Value::String(g.to_string()),
            );
        }
        if let Some(i) = ip {
            map.insert("ip".to_string(), serde_json::Value::String(i.to_string()));
        }
        ebpdns_rules::rule_from_json(map, ebpdns_rules::RuleSource::Local).expect("规则构造")
    }

    /// 带 RecordingTelemetry 的 resolver（上游恒回 A 1.1.1.1）。
    fn resolver_with_tel(cfg: ResolverConfig, tel: Arc<dyn Telemetry>) -> Arc<Resolver> {
        Resolver::new(
            cfg,
            tel,
            Arc::new(MockClock::new(1_700_000_000.0)),
            Arc::new(ScriptedQuerier::new(|_, _, _| {
                vec![UpstreamAnswer::ok(
                    "u1",
                    0,
                    vec![ResolveAnswer::new("1.1.1.1", 60.0, TYPE_A)],
                    Vec::new(),
                )]
            })),
        )
    }

    fn rule_inc(hits: &parking_lot::Mutex<std::collections::HashMap<String, u64>>, k: &str) -> u64 {
        hits.lock().get(k).copied().unwrap_or(0)
    }

    /// block / allow / group(domestic) / forceIp 四类命中 → `inc_rule` 分类计数
    /// （全量，不受事件采样影响），且规则结果带上 `level="rule"` 事件所需的文案。
    #[tokio::test]
    async fn rule_hits_are_counted_per_category() {
        let tel = Arc::new(crate::telemetry::RecordingTelemetry::default());
        let rules = vec![
            mk_rule("*.blk.test", "block", None, None),
            mk_rule("*.ok.test", "allow", None, None),
            mk_rule("*.grp.test", "group", Some("domestic"), None),
            mk_rule("*.fip.test", "forceIp", None, Some("9.9.9.9")),
        ];
        let cfg = ResolverConfig::test_default(vec![up("u1", 10, 1.0)], rules, 1);
        let r = resolver_with_tel(cfg, tel.clone());

        // block：NXDOMAIN + level=rule 文案
        let res = r
            .clone()
            .resolve("a.blk.test", "A", ResolveOpts::default())
            .await;
        assert_eq!(res.rcode, 3);
        let hit = res.rule.as_ref().expect("block 规则命中信息");
        assert_eq!(hit.msg, "规则屏蔽 → NXDOMAIN");
        assert_eq!(hit.upstream, "规则屏蔽");
        assert_eq!(hit.label, "屏蔽 *.blk.test");

        // allow：放行 + 正常解析
        let res = r
            .clone()
            .resolve("a.ok.test", "A", ResolveOpts::default())
            .await;
        assert_eq!(res.rcode, 0);
        assert_eq!(res.answers[0].value, "1.1.1.1");
        let hit = res.rule.as_ref().expect("allow 规则命中信息");
        assert_eq!(hit.msg, "白名单放行 → 正常解析");
        assert_eq!(hit.label, "放行 *.ok.test");

        // group → domestic 组（「分流」也必须有 rule 事件）
        let res = r
            .clone()
            .resolve("a.grp.test", "A", ResolveOpts::default())
            .await;
        let hit = res.rule.as_ref().expect("group 规则命中信息");
        assert_eq!(hit.msg, "分流规则 → 「domestic」组");
        assert_eq!(hit.upstream, "分流规则");

        // forceIp：合成应答
        let res = r
            .clone()
            .resolve("a.fip.test", "A", ResolveOpts::default())
            .await;
        assert_eq!(res.chosen, "9.9.9.9");
        let hit = res.rule.as_ref().expect("forceIp 规则命中信息");
        assert_eq!(hit.msg, "分流规则 → 9.9.9.9");
        assert_eq!(hit.answer, "9.9.9.9");

        // 分类计数：block / allow / domestic / forceIp 各 1（`rule:{cat}` 键）。
        assert_eq!(rule_inc(&tel.hits, "rule:block"), 1);
        assert_eq!(rule_inc(&tel.hits, "rule:allow"), 1);
        assert_eq!(rule_inc(&tel.hits, "rule:domestic"), 1);
        assert_eq!(rule_inc(&tel.hits, "rule:forceIp"), 1);
        assert_eq!(rule_inc(&tel.hits, "rule:global"), 0);

        // 重复查询同一 block 域名（屏蔽结果不入缓存）→ 计数继续全量累加。
        let _ = r
            .clone()
            .resolve("a.blk.test", "A", ResolveOpts::default())
            .await;
        assert_eq!(rule_inc(&tel.hits, "rule:block"), 2);
    }

    /// group 规则的 `global` 分类（非 domestic 组一律计 global，对齐 v1.9.162）。
    #[tokio::test]
    async fn group_rule_non_domestic_counts_as_global() {
        let tel = Arc::new(crate::telemetry::RecordingTelemetry::default());
        let rules = vec![mk_rule("*.gg.test", "group", Some("global"), None)];
        let cfg = ResolverConfig::test_default(vec![up("u1", 10, 1.0)], rules, 1);
        let r = resolver_with_tel(cfg, tel.clone());
        let _ = r
            .clone()
            .resolve("a.gg.test", "A", ResolveOpts::default())
            .await;
        assert_eq!(rule_inc(&tel.hits, "rule:global"), 1);
        assert_eq!(rule_inc(&tel.hits, "rule:domestic"), 0);
    }

    /* ---------------- 缺陷 B：规则索引真实条数 ---------------- */

    /// `Resolver::rule_count()` 反映**索引**真实条数，而不是 `config.rules.len()`。
    #[test]
    fn rule_count_reflects_live_index() {
        // config 里只放 1 条本地规则 → 索引 1 条。
        let cfg = ResolverConfig::test_default(
            vec![up("u1", 10, 1.0)],
            vec![mk_rule("*.local.test", "block", None, None)],
            1,
        );
        let r = resolver(cfg, Arc::new(MockClock::new(1_700_000_000.0)));
        assert_eq!(r.rule_count(), 1);
        // 重建为「本地 + 订阅展开」的 4 条 → 计数立即跟随索引，而不是 config(1)。
        r.rebuild_rules(vec![
            mk_rule("*.local.test", "block", None, None),
            mk_rule("*.sub1.test", "block", None, None),
            mk_rule("sub2.test", "allow", None, None),
            mk_rule("re:^ads\\d+\\.test$", "block", None, None),
        ]);
        assert_eq!(r.rule_count(), 4);
        assert_eq!(r.config().rules.len(), 1, "config.rules 仍是逐条本地规则");
        // 清空 → 0（DELETE 订阅后控制台不再显示残留规则数）。
        r.rebuild_rules(Vec::new());
        assert_eq!(r.rule_count(), 0);
    }

    /// 缺陷（P0）：`Resolver::reload()` **不得**用「仅 `cfg.rules`」重建规则索引。
    ///
    /// `cfg.rules` 只含 config.json 的逐条本地规则；订阅展开的 10 万条只存在于索引
    /// （由 `subscribe::rebuild_all_disk_stats` 装填）。旧实现在 `reload()` 里
    /// `rule_engine.rebuild(cfg.rules)`，于是 `POST /api/reload`、
    /// `POST /api/reprobe`、`PUT /api/config`（三者都经 on_reload → reload）
    /// 会把订阅规则整体摘掉：真实部署实测 `pipeline.rules` 101147 → 0、
    /// `rule_hits` 停止增长（屏蔽静默失效）。
    #[test]
    fn reload_preserves_merged_rule_index() {
        let cfg = ResolverConfig::test_default(
            vec![up("u1", 10, 1.0)],
            vec![mk_rule("*.local.test", "block", None, None)],
            1,
        );
        let r = resolver(cfg, Arc::new(MockClock::new(1_700_000_000.0)));
        // 模拟启动装配：索引 = 本地 1 条 + 订阅展开 3 条（cfg.rules 仍是 1 条）。
        r.rebuild_rules(vec![
            mk_rule("*.local.test", "block", None, None),
            mk_rule("*.sub1.test", "block", None, None),
            mk_rule("*.sub2.test", "block", None, None),
            mk_rule("*.sub3.test", "block", None, None),
        ]);
        assert_eq!(r.rule_count(), 4);
        let gen_before = r.rule_gen();
        // 热重载（改上游延迟，语义上不该动规则索引）。
        let mut next = r.config().clone();
        next.upstreams = vec![up("u1", 20, 1.0)];
        r.reload(next);
        assert_eq!(r.rule_count(), 4, "reload 后订阅规则必须仍在索引里");
        assert_eq!(
            r.rule_gen(),
            gen_before,
            "reload 不得重建规则索引（代际不变）"
        );
        assert!(r.match_rule("x.sub1.test").is_some(), "订阅规则仍可命中");
        assert_eq!(r.config().rules.len(), 1);
    }

    /* ============ 2.1.16（功能 2）：在途查询合并 ============ */

    /// **功能 2 端到端门禁**：N 路并发**同域名**（同 `CacheKey`）只发一次上游。
    ///
    /// 判据用 `CountingQuerier.seen` 的长度（= 物理上游波次数），这是"wire 请求真的
    /// 减少了"的直接证据（`upstream_wire_requests/total` 放大倍数的分子）。
    ///
    /// **测试基座要害**：querier 必须返回**失败**应答（`UpstreamAnswer::fail`），
    /// 否则第一个查询就把答案写进缓存，其余并发查询变成**缓存命中** ——
    /// 那样"只发 1 次上游"是缓存造成的，**测不出 single-flight**（第一版即栽在这里：
    /// `single_flight=false` 也测到 1 次）。
    #[tokio::test]
    async fn s2_concurrent_same_domain_sends_upstream_once_when_enabled() {
        /// 恒回失败的 querier（不写缓存 ⇒ 并发 miss 真的都会打到上游）。
        struct FailingQuerier {
            waves: Mutex<usize>,
        }
        #[async_trait::async_trait]
        impl ParallelQuerier for FailingQuerier {
            async fn query_parallel(
                &self,
                ups: &[UpstreamCfg],
                _qname: &str,
                _qtype: &str,
                _depth: u32,
            ) -> Vec<UpstreamAnswer> {
                *self.waves.lock() += 1;
                // 让并发任务真正重叠，否则"先完成的那个把缓存填上"会掩盖结论。
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                ups.iter().map(|u| UpstreamAnswer::fail(&u.id)).collect()
            }
        }
        let mk = |sf: bool| {
            let mut cfg =
                ResolverConfig::test_default(vec![UpstreamCfg::test_up("u1")], Vec::new(), 1);
            cfg.single_flight = sf;
            cfg.fallback = false;
            cfg.max_parallel_upstreams = 1;
            cfg.prefetch = false;
            let q = Arc::new(FailingQuerier {
                waves: Mutex::new(0),
            });
            (
                Resolver::new(
                    cfg,
                    Arc::new(NoopTelemetry),
                    Arc::new(MockClock::new(1_700_000_000.0)),
                    q.clone(),
                ),
                q,
            )
        };

        // ---- 开：16 路并发同域名 → 1 次上游波次 ----
        let (r, q) = mk(true);
        let mut ts = Vec::new();
        for _ in 0..16 {
            let r = r.clone();
            ts.push(tokio::spawn(async move {
                r.resolve("same.example", "A", ResolveOpts::default()).await
            }));
        }
        for t in ts {
            let _ = t.await.expect("join");
        }
        let waves_on = *q.waves.lock();
        assert_eq!(
            waves_on, 1,
            "single_flight=true：16 路并发同域名必须只发 1 次上游（实测 {waves_on} 次）"
        );
        assert_eq!(r.single_flight_inflight(), 0, "全部完成后在途表必须清空");

        // ---- 关：同一场景退回 2.1.15 行为（每个 miss 各自上游）----
        let (r2, q2) = mk(false);
        let mut ts = Vec::new();
        for _ in 0..16 {
            let r = r2.clone();
            ts.push(tokio::spawn(async move {
                r.resolve("same.example", "A", ResolveOpts::default()).await
            }));
        }
        for t in ts {
            let _ = t.await.expect("join");
        }
        let waves_off = *q2.waves.lock();
        assert!(
            waves_off > 1,
            "single_flight=false：必须逐位退回 2.1.15（每 miss 各自上游），实测 {waves_off} 次"
        );
        assert!(
            waves_on < waves_off,
            "合并必须真的减少上游波次：on={waves_on} off={waves_off}"
        );
    }

    /// 功能 2：**不同域名不得被合并**（否则就是错误答案扩散）。
    #[tokio::test]
    async fn s2_different_domains_are_not_coalesced() {
        let mut cfg = ResolverConfig::test_default(vec![UpstreamCfg::test_up("u1")], Vec::new(), 1);
        cfg.single_flight = true;
        cfg.fallback = false;
        cfg.max_parallel_upstreams = 1;
        let q = CountingQuerier::new();
        let r = Resolver::new(
            cfg,
            Arc::new(NoopTelemetry),
            Arc::new(MockClock::new(1_700_000_000.0)),
            q.clone(),
        );
        let mut ts = Vec::new();
        for i in 0..8 {
            let r = r.clone();
            ts.push(tokio::spawn(async move {
                r.resolve(&format!("d{i}.example"), "A", ResolveOpts::default())
                    .await
            }));
        }
        for t in ts {
            let _ = t.await.expect("join");
        }
        assert_eq!(q.calls().len(), 8, "8 个不同域名必须各自发上游");
    }

    /// **2.1.43-B（P2-3）回归**：**预取（`UpstreamMode::Single`）与数据面
    /// （`UpstreamMode::Multi`）对同一域名并发时，不得共享上游扇出**。
    ///
    /// 旧实现在途合并键 = `group|domain|qtype`（不含模式）⇒ 两种模式互相顶替：
    /// 数据面 follower 可能只拿到"1 个上游"的预取结果（失去后备波/quorum 冗余）。
    /// 现在键里带 `#single` / `#multi` 标签 ⇒ 各发各的一次扇出（同模式内仍合并）。
    ///
    /// 判据用 `FailingQuerier.waves`（= 物理上游波次数）：8 路数据面 + 8 路预取
    /// 并发同域名 ⇒ **恰好 2 次**（每模式 1 次）；旧实现只会有 1 次。
    #[tokio::test]
    async fn s2b_prefetch_and_data_plane_do_not_share_single_flight_fanout() {
        struct FailingQuerier {
            waves: Mutex<usize>,
        }
        #[async_trait::async_trait]
        impl ParallelQuerier for FailingQuerier {
            async fn query_parallel(
                &self,
                ups: &[UpstreamCfg],
                _qname: &str,
                _qtype: &str,
                _depth: u32,
            ) -> Vec<UpstreamAnswer> {
                *self.waves.lock() += 1;
                // 让两种模式的请求真正重叠（否则先完成的那个已离开在途表）。
                tokio::time::sleep(std::time::Duration::from_millis(40)).await;
                ups.iter().map(|u| UpstreamAnswer::fail(&u.id)).collect()
            }
        }
        let mut cfg = ResolverConfig::test_default(vec![UpstreamCfg::test_up("u1")], Vec::new(), 1);
        cfg.single_flight = true;
        cfg.fallback = false;
        cfg.max_parallel_upstreams = 1;
        cfg.prefetch = false;
        let q = Arc::new(FailingQuerier {
            waves: Mutex::new(0),
        });
        let r = Resolver::new(
            cfg,
            Arc::new(NoopTelemetry),
            Arc::new(MockClock::new(1_700_000_000.0)),
            q.clone(),
        );
        let mut ts = Vec::new();
        for i in 0..8 {
            let r = r.clone();
            ts.push(tokio::spawn(async move {
                if i % 2 == 0 {
                    r.resolve("mixed.example", "A", ResolveOpts::default())
                        .await
                } else {
                    r.resolve_prefetch("mixed.example", "A", ResolveOpts::default())
                        .await
                }
            }));
        }
        for t in ts {
            let _ = t.await.expect("join");
        }
        let waves = *q.waves.lock();
        assert_eq!(
            waves, 2,
            "8 路数据面 + 8 路预取并发同域名 ⇒ 每模式各 1 次扇出 = 2 次（旧实现 1 次）；实测 {waves}"
        );
        assert_eq!(r.single_flight_inflight(), 0, "全部完成后在途表必须清空");
    }

    /* ============ 2.1.16（功能 5）：缓存增量迁移 / resize ============ */

    /// **功能 5 门禁 ①**：容量变更（策略不变）走 `set_capacity` —— **旧键仍命中**。
    ///
    /// 旧实现在这里整表 `swap` 丢弃：改 `cache_size` 后 `counters.hit` 归零、
    /// `cache_direct` 归零。本用例直接钉死"resize 后键还在"。
    #[tokio::test]
    async fn s5_resize_keeps_old_keys_hittable_and_does_not_reset_cache() {
        let cfg = {
            let mut c =
                ResolverConfig::test_default(vec![UpstreamCfg::test_up("u1")], Vec::new(), 1);
            // 基座容量必须 ≥ 要填的条目数，否则 `put` 阶段就被逐出（测不出 resize）。
            c.cache_size = 200;
            c
        };
        let r = Resolver::new(
            cfg.clone(),
            Arc::new(NoopTelemetry),
            Arc::new(MockClock::new(1_700_000_000.0)),
            Arc::new(ScriptedQuerier::new(|_, _, _| Vec::new())),
        );
        let now = 1_700_000_000.0;
        let mut keys = Vec::new();
        for i in 0..200 {
            let k = r.ckey(&format!("k{i}.example"), "A");
            r.cache().put(
                k.clone(),
                ebpdns_cache::CacheEntry::new(format!("k{i}.example"), "A", 300.0, now),
                now,
            );
            keys.push(k);
        }
        assert!(
            r.cache().len() >= 150,
            "基座容量 200（LRU 8 分片取整），应至少装下 150 条，实测 {}",
            r.cache().len()
        );
        // 快照"reload 前确实在缓存里"的键 —— 分片取整可能已逐出少数条目，
        // 后续断言只覆盖这批键（这才是"resize 不丢条目"的正确判据）。
        let n0 = r.cache().len();
        let present: Vec<ebpdns_cache::CacheKey> = keys
            .iter()
            .filter(|k| r.cache().get(k, now).is_some())
            .cloned()
            .collect();
        assert_eq!(present.len(), n0, "present 必须等于当前条目数");
        // 增长：一个都不能丢。
        let mut next = cfg.clone();
        next.cache_size = cfg.cache_size * 4;
        r.reload(next);
        for k in &present {
            assert!(
                r.cache().get(k, now).is_some(),
                "扩容量后旧键必须仍命中（旧实现整表丢弃 → 这里会失败）"
            );
        }
        assert_eq!(
            r.cache().len(),
            n0,
            "扩容量不得丢条目（旧实现为 0 = 整表丢弃）"
        );
        // 收缩：按当前策略逐出，但**不是清空**。
        let mut shrunk = cfg.clone();
        shrunk.cache_size = 64;
        r.reload(shrunk);
        let left = r.cache().len();
        assert!(
            left > 0 && left <= 64,
            "收缩到 64 后条目数应在 (0, 64]，实测 {left}（旧实现为 0 = 整表丢弃）"
        );
    }

    /// **功能 5 门禁 ②**：策略切换（lru → tinylfu）后**同键仍可命中**（不再是断崖归零）。
    #[tokio::test]
    async fn s5_policy_switch_keeps_same_key_hittable() {
        let mut cfg = ResolverConfig::test_default(vec![UpstreamCfg::test_up("u1")], Vec::new(), 1);
        cfg.cache_policy = "lru".to_string();
        cfg.cache_size = 128;
        let r = Resolver::new(
            cfg.clone(),
            Arc::new(NoopTelemetry),
            Arc::new(MockClock::new(1_700_000_000.0)),
            Arc::new(ScriptedQuerier::new(|_, _, _| Vec::new())),
        );
        let now = 1_700_000_000.0;
        let k = r.ckey("hot.example", "A");
        r.cache().put(
            k.clone(),
            ebpdns_cache::CacheEntry::new("hot.example", "A", 300.0, now),
            now,
        );
        assert!(r.cache().get(&k, now).is_some());

        let mut next = cfg.clone();
        next.cache_policy = "tinylfu".to_string();
        r.reload(next);
        assert!(
            r.cache().get(&k, now).is_some(),
            "策略 lru→tinylfu 后同键必须仍可命中（2.1.15 会整表丢弃 → None）"
        );
        // 再切到 partitioned 同样必须命中（三种策略两两迁移都走同一条迁移路径）。
        let mut next2 = cfg.clone();
        next2.cache_policy = "partitioned".to_string();
        r.reload(next2);
        assert!(
            r.cache().get(&k, now).is_some(),
            "策略 tinylfu→partitioned 后同键必须仍可命中"
        );
    }

    /* ============ 2.1.16（功能 9）：上游连接池预热 ============ */

    /// **功能 9 门禁**：预热按配置真的发查询（`warmup_queries` 条/启用上游），
    /// 且 `warmup_enabled=false` 或上游被禁用时**一条都不发**；调用不阻塞、不 panic。
    #[tokio::test]
    async fn s9_warmup_issues_configured_queries_and_respects_flags() {
        // 开：2 条启用上游 × 2 条/上游 = 4 次；另 1 条 disabled 不得被探。
        let mut ups = vec![UpstreamCfg::test_up("u1"), UpstreamCfg::test_up("u2")];
        let mut off = UpstreamCfg::test_up("u-off");
        off.enabled = false;
        ups.push(off);
        let mut cfg = ResolverConfig::test_default(ups.clone(), Vec::new(), 1);
        cfg.warmup_enabled = true;
        cfg.warmup_queries = 2;
        cfg.warmup_timeout_ms = 2000;
        let q = CountingQuerier::new();
        let r = Resolver::new(
            cfg,
            Arc::new(NoopTelemetry),
            Arc::new(MockClock::new(1_700_000_000.0)),
            q.clone(),
        );
        r.spawn_upstream_warmup();
        // 异步任务：给它一点时间跑完（预算 2s，实际是即时的）。
        for _ in 0..100 {
            if q.calls().len() >= 4 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let calls = q.calls();
        assert_eq!(calls.len(), 4, "2 启用上游 × 2 条 = 4 次预热：{calls:?}");
        assert!(
            calls.iter().all(|c| c.len() == 1 && c[0] != "u-off"),
            "预热必须逐上游单发，且**绝不探禁用上游**：{calls:?}"
        );

        // 关：一条都不发。
        let mut cfg2 =
            ResolverConfig::test_default(vec![UpstreamCfg::test_up("u1")], Vec::new(), 1);
        cfg2.warmup_enabled = false;
        cfg2.warmup_queries = 2;
        let q2 = CountingQuerier::new();
        let r2 = Resolver::new(
            cfg2,
            Arc::new(NoopTelemetry),
            Arc::new(MockClock::new(1_700_000_000.0)),
            q2.clone(),
        );
        r2.spawn_upstream_warmup();
        tokio::time::sleep(std::time::Duration::from_millis(60)).await;
        assert_eq!(q2.calls().len(), 0, "warmup_enabled=false 必须零查询");
    }

    /// 功能 9：预热**绝不阻塞构造**（无 runtime / 上游慢都不影响 `Resolver::new` 返回）。
    ///
    /// **2.1.16（测试面缺陷 E1 修复）**：本行原来把 `#[tokio::test]` 写在了上面这条
    /// `///` 注释的**同一行末尾** ⇒ 属性被吞进 doc 注释，函数**没有测试属性**、
    /// 触发 `dead_code` 告警，且**该用例从未被执行**（rustc：`function ... is never used`）。
    /// 这与 2.1.11 记录过的同类回归一致（见 `crates/ebpdns-server/src/api.rs:4513-4514`
    /// 的"`#[test]` 被写在 doc 注释同一行导致用例从未执行"）。属性必须独占一行。
    #[tokio::test]
    async fn s9_warmup_never_blocks_construction() {
        let mut cfg =
            ResolverConfig::test_default(vec![UpstreamCfg::test_up("slow")], Vec::new(), 1);
        cfg.warmup_enabled = true;
        cfg.warmup_queries = 8;
        cfg.warmup_timeout_ms = 50; // 极短截止：任务必须自己收手
        let t0 = std::time::Instant::now();
        let r = Resolver::new(
            cfg,
            Arc::new(NoopTelemetry),
            Arc::new(MockClock::new(1_700_000_000.0)),
            Arc::new(ScriptedQuerier::new(|_, _, _| {
                // 模拟慢上游：每个查询 40ms。
                std::thread::sleep(std::time::Duration::from_millis(40));
                vec![UpstreamAnswer::fail("slow")]
            })),
        );
        assert!(
            t0.elapsed() < std::time::Duration::from_millis(500),
            "构造必须立即返回（预热是异步的），实测 {:?}",
            t0.elapsed()
        );
        r.spawn_upstream_warmup();
        // 截止后任务必须结束（不泄漏）：给足余量后表里没有残留。
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        assert_eq!(r.single_flight_inflight(), 0);
    }

    /// **功能 9 门禁**：`converge_cap` 的三条不变式（关闭闸门 / 无样本 / 按比例收敛）。
    #[test]
    fn s9_converge_cap_follows_p90_spread() {
        // base=0（闸门关闭）绝不擅自打开。
        assert_eq!(Resolver::converge_cap(0, &[10.0, 900.0]), 0);
        // 无样本 / 单样本 → 原样（零行为变更）。
        assert_eq!(Resolver::converge_cap(32, &[]), 32);
        assert_eq!(Resolver::converge_cap(32, &[50.0]), 32);
        // 全部同样快 → ratio=1 → base。
        assert_eq!(Resolver::converge_cap(32, &[50.0, 50.0, 50.0]), 32);
        // 快慢差 4× → ratio=0.25 → 32*0.25=8，但下界 base/4=8 → 8。
        assert_eq!(Resolver::converge_cap(32, &[50.0, 200.0]), 8);
        // 差 2× → 16。
        assert_eq!(Resolver::converge_cap(32, &[100.0, 200.0]), 16);
        // 慢到 40×（ratio 被夹到 0.25）→ 仍是下界 8，不会更小。
        assert_eq!(Resolver::converge_cap(32, &[10.0, 400.0]), 8);
        // 大 base 的下界按比例：64/4=16。
        assert_eq!(Resolver::converge_cap(64, &[10.0, 400.0]), 16);
        // 非法样本被忽略；全非法 → base。
        assert_eq!(Resolver::converge_cap(32, &[f64::NAN, 0.0, -1.0]), 32);
        // 结果永远落在 [max(1,base/4), base]。
        for base in [4usize, 16, 32, 64, 128] {
            for p in [[10.0, 11.0], [10.0, 1000.0], [100.0, 101.0]] {
                let c = Resolver::converge_cap(base, &p);
                assert!(
                    c >= (base / 4).max(1) && c <= base,
                    "base={base} p={p:?} → {c} 越界"
                );
            }
        }
    }
}
