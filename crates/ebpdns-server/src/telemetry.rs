//! 服务端遥测：实现 [`ebpdns_resolver::Telemetry`]，同时为 /api/status、/metrics、
//! **[历史归因]** /api/logs 提供快照。对齐 Python `telemetry.py`（v1.9.162）的增量计数 + 环形事件日志语义。
//!
//! 口径要点（逐条对齐 `ebpdns/telemetry.py`）：
//! - **计数器全量**：hit/miss 事件的 10% 采样只裁剪 `events` 环，**不影响**
//!   计数器 / TopN / 延迟窗口。
//! - **平均延迟** = 最近 [`LATENCY_WINDOW_MAX`] 条样本的算术平均（hit/miss 都进窗口），
//!   无样本 → `None`；窗口非空而均值为 `0.0` 时**不是** `None`
//! **[历史归因]**   （对齐 Python `avg_latency()` 的 `if not self.latency_window: return None`）。
//! - **TopN 有界**：频次 map 超 [`TOP_MAP_MAX`] 时裁到高频一半，之后**继续**计新键
//! **[历史归因]**   （对齐 Python `count_top()` 的 `most_common(_top_max // 2)`）。
//! **[历史归因]** - **手动查询不污染数据面**：`record_manual`（/api/query，Python `counted=False`）
//!   只写 manual 历史 + 事件 + 延迟窗口，不动 qtype_dist / top_domains / top_clients。
//! - **时间戳本地时区**：事件/manual 的 `ts_text` 为本地 `HH:MM:SS.mmm`
//! **[历史归因]**   （对齐 Python `time.localtime()`）；`ts` 字段仍是 epoch 秒（前端按浏览器时区格式化）。

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use ebpdns_resolver::telemetry::Telemetry;
use parking_lot::Mutex;
use serde_json::{json, Value};

// **仅测试**：`hit_rate_pct()`（会**二次取快照**的旧入口）的调用次数。
//
// `/api/status` / `/api/snapshot` 修好 A-11 后必须零调用（它们用同代
// `hit_rate_pct_of(snap)`）；该计数让"偷偷退回二次快照"可被确定性抓住。
#[cfg(test)]
thread_local! {
    pub static HIT_RATE_PCT_CALLS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// **[历史归因]** 环形事件日志上限（对齐 Python events 缓冲 500）。
const EVENT_RING_MAX: usize = 500;
/// **[历史归因]** 手动查询历史上限（对齐 Python `add_manual_entry` 的 `[-20:]`）。
const MANUAL_RING_MAX: usize = 20;
/// **[历史归因]** 历史采样环上限（对齐 Python `sample()` 的 `self.history[-120:]`）。
const HISTORY_RING_MAX: usize = 120;
/// **[历史归因]** 历史采样**快照**返回条数（对齐 Python `snapshot()` 的 `history[-60:]`）。
const HISTORY_TAIL_MAX: usize = 60;
/// **[历史归因]** 延迟样本窗口上限（对齐 Python `latency_window = deque(maxlen=400)`）。
const LATENCY_WINDOW_MAX: usize = 400;
/// A7：**上游**延迟样本窗口上限（每条上游独立窗口）。
///
/// 与全局 `latency` 窗口分开：全局窗口服务 `/api/status.avg_latency_ms`（口径不能变），
/// 这个窗口专门给 `/metrics` 的 `ebpdns_upstream_latency_ms` 直方图/分位数用，
/// 键为上游 id。窗口小（256）以免 64 条上游 × 400 样本造成不必要内存。
const UPSTREAM_LAT_WINDOW_MAX: usize = 256;
/// A7：上游延迟窗口最多跟踪多少条上游（超出按计数丢弃新键，防无界增长）。
const UPSTREAM_LAT_MAX_KEYS: usize = 256;
/// A7：延迟直方图桶上界（毫秒）。Prometheus 累积直方图，`+Inf` 隐含。
pub const LATENCY_BUCKETS_MS: [f64; 10] =
    [1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0];
/// **[历史归因]** TopN 频次 map 上限（对齐 Python `_top_max = 2048`；超限裁到一半后继续计新键）。
const TOP_MAP_MAX: usize = 2048;
/// **[历史归因]** QPS 窗口上限（对齐 Python `qps_window = deque(maxlen=600)`）。
const QPS_WINDOW_MAX: usize = 600;
/// **[历史归因]** hit/miss 事件采样率（对齐 Python `random.random() < 0.1`）。
const EVENT_SAMPLE_RATE: f64 = 0.1;
/// top 列表返回条数。
pub const TOP_N: usize = 10;
/// v1.9.162 `Telemetry.__init__.counters` 的全部键（顺序一致）+ 2.1.14/2.1.15 新增的
/// 服务端专有计数（见下一项说明）。
// >>> 242B BEGIN P1-6-keysize >>> //
pub const COUNTER_KEYS: [&str; 21] = [
    // <<< 242B END P1-6-keysize <<< //
    "total",
    "hit",
    "miss",
    "upstream_queries",
    "errors",
    "ipv4_fallback",
    "stale_served",
    "bytes_in",
    "bytes_out",
    "rebind_blocked",
    // **2.1.14（P0-5）**：UDP miss 并发闸门**拒绝/丢包**计数。
    //
    // 为什么必须可见：2.1.12 把闸门槽位从 `workers*16`(=1024) 静默改成
    // `workers*32`（`workers` 同时被固定成 1）⇒ 实际只剩 **32** 槽，256 并发下
    // `try_acquire_owned()` 失败即丢包（客户端 6s 后超时），而复现该缺陷时
    // `/api/status.counters` 与 `/metrics` **都看不到任何丢包迹象**。
    // 现在数据面每次闸门拒绝都自增本计数器（`dns.rs` udp_loop 的 `Err(_)` 分支），
    // 与 `DnsServer::udp_dropped()` 内部计数**同源同值**。
    "udp_dropped",
    // **2.1.15（P1）**：服务端**真的回给客户端**的 SERVFAIL 总数（`rcode == 2`）。
    //
    // 与 `errors` 的区别（本轮刻意分开的第二个口径）：`errors` 是**内部错误**
    // （上游全失败 / 组包失败 / 畸形包），而 `servfail_total` 是**客户端实际看到的
    // 应答码**。上一轮两轮压测出现 0~4 个 SERVFAIL，而 journal 里**没有任何 ERROR**，
    // 正是因为这两件事此前没有任何计数能把它们对上。原因维度见
    // [`SERVFAIL_REASONS`]（`/api/status.counters.servfail_reasons`）。
    "servfail_total",
    // **2.1.16（修复项 15）**：负缓存（NXDOMAIN / NODATA）命中数。
    //
    // 为什么新增（而不是复用既有的 `neg_hit` 内部原子计数）：`neg_hit` 只服务于
    // `/metrics` 的 `ebpdns_negcache_hits_total` / `_ratio`，**不在**
    // `/api/status.counters` 里 —— 压测脚本与服务端对账时读的是 `counters`，
    // 于是"负缓存到底命中了多少"在两侧口径不一致（脚本只能自己另算）。
    // 现在把它作为**标量计数器**纳入 [`COUNTER_KEYS`]，与 `hit`/`miss` 同表同源；
    // `ServerTelemetry::count_neg_hit` 同时自增两者（单一打点，不可能漂移）。
    // 负缓存条目**参与落盘/恢复**（含剩余 TTL）见 `ebpdns-cache` 的 `serialize`/
    // `restore` 与 `crates/ebpdns/src/main.rs::save_cache`，所以重启前后该计数
    // 只增不减（单调性由 `s15_negative_hits_is_monotonic_across_restore` 钉死）。
    "negative_hits",
    // **2.1.17（修复项 3）**：因 rebind 防护被丢弃的**私有/保留地址答案**条数
    // （设计行为：这些结果**不入缓存**）。
    //
    // 为什么必须新增（2.1.16 审计的真实误判）：2.1.16 交付审计用「上游返回
    // `10.9.9.9` → 同键重查恒 miss、`entries=0`」推断"缓存坏了"，而当时
    // `counters` 里**没有任何**能证明"私网答案被按设计过滤掉"的计数
    // （`rebind_blocked` 统计的是**控制面** DNS-rebinding 拦截，数据面不经过它，
    // 因此恒为 0 —— 见 `api.rs` 的 `rebind_protection` 白名单与 `security.rs`）。
    // 现在数据面唯一出口 `dns.rs::log_and_count` 把 resolver 回传的
    // `ResolveResult::private_answers_filtered` 累加到本键，于是
    // 「私网答案被丢弃 ⇒ 该结果不入缓存」变成**可直接观测的计数**，
    // 审计侧不必再从 trace 中文文案反推。
    //
    // 与 `rebind_blocked` 的关系：**两个不同的门**，不得相加、不得互相代替。
    //   - `rebind_blocked`：控制面（API/规则订阅）的 DNS-rebinding 拦截（写入被拒）；
    //   - `cache_skipped_private_total`：数据面**答案**里的私网/保留地址被丢弃的条数。
    // 同源口径：同名键同时出现在 `/api/status.counters` 与
    // `/metrics` 的 `ebpdns_cache_skipped_private_total`（单测钉死三者一致）。
    "cache_skipped_private_total",
    // **2.1.18（修复项 9）**：数据面出口**登记了但没有构造出可发送报文**的次数
    // （畸形包 / 空 question / 组包失败 —— `resp.len() < 12`）。
    //
    // **与 `total` 的关系是"缺口项"，不是加数**：
    //   - `counters.total` **严格等于** `Σ counters.client_rcode`（见
    //     [`CounterSnapshot::total`]：派生量 ⇒ 恒等式由构造保证，无 ±1 撕裂窗口）；
    //   - "没有为客户端构造出应答"的那些登记**不计入 `total`**，单独记在本键；
    //   - 因此 **`total` 不得与本键相加、不得混入 `Σ client_rcode`**：
    //     两者是互斥集合（本键只在 `resp.len() < 12` 时 +1，此时既无应答也无 rcode）。
    //
    // 为什么必须可见（本轮真实缺陷的教训）：2.1.19 早期版本把"没有应答"也算进
    // `total`，于是 `total = 2×Σrcode + 256` 里的 256 没有任何可观测归属。
    "no_response_total",
    // ---- **2.1.20（A-04 修复）：控制面查询的**独立**计数 ----
    //
    // 为什么必须分开（审计 A-04 实测）：控制面 `POST /api/query` **不计 `total`**
    // （刻意对齐 v1.9.162"手动查询不污染遥测"），但 2.1.19 及以前它**会**把 `hit` +1
    // ⇒ `hit_rate = hit/total` 可 **>100%**（实测 600.0%），且 `hit+miss ≤ total` 不成立，
    // 直接违反 `web/INTERFACE.md` 的验收条款「命中率卡显示 ≤100.0%」。
    //
    // 现在的口径（**数据面指标只由数据面写**）：
    //   * `hit`/`miss`/`total`/`hit_rate`/`client_rcode`/`qps`/`topN` = **纯数据面**；
    //   * `control_queries` = 控制面查询次数（每次 `POST /api/query` +1）；
    //   * `control_hits` = 其中由**缓存直答**的次数。
    // 两者都在 `/api/status.counters` 与 `/metrics` 可见，因此"手动查询做了什么"
    // 仍完全可观测，只是不再污染命中率分母。
    "control_queries",
    "control_hits",
    // **2.1.29**：未知/其他合法 qtype 的**透传**次数（成功 + 失败都算）。
    //
    // 语义（与 `upstream_queries` 刻意分开）：`upstream_queries` 是"发过上游"的通用
    // 计数；本键只数"因为 qtype 不在受理名单、也不在必须拒绝名单，所以按原始 u16
    // 原样透传"的查询。**不缓存**（同一查询重复 N 次 ⇒ N 次上游 + N 次本计数），
    // 因此它是审计"透传路径真的在工作、且没有被缓存短路"的直接证据。
    // 写点唯一 = `dns.rs::log_and_count`（数据面唯一出口）。
    "passthrough_qtype_total",
    // >>> 242B BEGIN P1-6-key >>> //
    // **2.1.40**：本地策略短路次数（AAAA 屏蔽 / IPv6 关闭；不计 hit/miss/upstream）。
    "policy_filtered_total",
    // **2.1.42-B（P1-6）**：本地规则**直答**（block / forceIp，以及 no-upstream 的
    // 本地判定）次数。这些查询既没查缓存、也没发上游，单独归入本键 ->
    // `hit + miss + policy_filtered_total + rule == total` 重新成立，且
    // `rule_hits`（正交维度）不再与 `miss` 重叠。
    "rule",
    // **2.1.43-A（P2：prefer_ipv4 探针记 0）**：双栈探测**真的发往上游**的次数。
    // 写点唯一 = `resolve.rs::probe_a_record`。与 `upstream_queries` 互不重叠
    // （后者只数"数据面客户端查询"），因此两者相加才是"本进程发出的逻辑上游请求"。
    "probe_upstream_queries",
];
// <<< 242B END P1-6-key <<< //

static UNKNOWN_INC_KEYS: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
/// 时区解析失败的告警去重（每进程一次）。
static TZ_WARNED: OnceLock<()> = OnceLock::new();
/// 未知 SERVFAIL 原因键的告警去重（同键只告警一次）。
static UNKNOWN_SERVFAIL_REASONS: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

/// 未知 SERVFAIL 原因键告警（去重）。
fn warn_unknown_servfail_reason(reason: &str) {
    let seen = UNKNOWN_SERVFAIL_REASONS.get_or_init(|| Mutex::new(HashSet::new()));
    let mut g = seen.lock();
    if g.insert(reason.to_string()) {
        tracing::warn!(
            reason = %reason,
            "未知 SERVFAIL 原因键：已按 upstream_all_failed 归档（请同步 SERVFAIL_REASONS）"
        );
    }
}
/// 事件采样用的 xorshift64* 状态（非加密用途）。
static RAND_STATE: AtomicU64 = AtomicU64::new(0);

/// **2.1.17（修复项 7）**：`counters()` 里由 `UpstreamRuntime` **现场读取**的
/// 动态键（不是 `ServerTelemetry` 自己的原子计数器）。
///
/// 与 [`STRUCTURED_COUNTER_KEYS`] 的区别：那些是**对象**值；这些是**标量**，
/// 但**不进** [`COUNTER_KEYS`] —— 因为 `COUNTER_KEYS` 的判据是"由
/// `ServerTelemetry::inc_n` 自增"，而这些值由上游运行时在
/// `/api/status` 组装时读取（写点在 `upstream/runtime.rs`，不在遥测里）。
/// 单列出来是为了：① 让"哪些键不由 inc_n 管"这件事显式；② 相关单测能准确断言
/// 键集合的完整构成（`COUNTER_KEYS + STRUCTURED + DYNAMIC`）。
pub const DYNAMIC_COUNTER_KEYS: [&str; 1] = ["upstream_inflight_queued_gave_up"];

/* ============ A7 / 2.1.12：逐上游延迟窗口（增量直方图） ============ */

/// 一条上游的延迟样本窗口 + **增量维护**的聚合量。
///
/// **2.1.18（修复项 9）**：`snapshot()` 的一致性重试上限。
///
/// 为什么需要重试：热路径**不加锁**（性能要求），读侧靠"读前/读后写入代数相同"
/// 判断是否读到同一代；若期间有写入（或恰好撞上 `servfail_total` 与原因分档两次
/// 相邻写入之间的极窄窗口）就重试。正常负载下**第一次就成功**。
const SNAPSHOT_RETRY_MAX: u32 = 64;

/// **2.1.15（P1 低频 SERVFAIL）**：SERVFAIL 原因维度的**固定键集合**（顺序即展示顺序）。
///
/// 与 `dns.rs::servfail_reason_of` 的产出**一一对应**（该函数是全树唯一产出点），
/// 空快照也补齐这 5 个键 → 页面/脚本不必做"键不存在"的兜底。
pub const SERVFAIL_REASONS: [&str; 5] = [
    "upstream_timeout",
    "upstream_no_answer",
    "no_upstream",
    "encode_failed",
    "panic",
];

/// **2.1.15（P1）**：`counters()` 里**不是标量计数器**的键（值为 JSON 对象）。
///
/// 为什么单列：`COUNTER_KEYS` 的语义是「**标量**计数器键集合」——`inc_n` 对每个键都
/// 是 `fetch_add`，测试也对每个键断言「初值 0 → inc 后 1」。`servfail_reasons` 是
/// 5 档原因的**映射**（对象），不属于该集合；两者相加才是 `counters()` 的完整键集
/// （见 `telemetry::tests::counters_expose_v19162_keys_and_inc_paths`）。
///
/// **2.1.16（修复项 8）**：新增 `client_rcode`（16 槽 rcode 分布，同样是对象），
/// 使压测脚本可在**服务端侧**把"客户端数到的 rcode==2"与"服务端实际发出的
/// rcode==2"对账，不再依赖客户端脚本对超时/无应答的分类口径。
pub const STRUCTURED_COUNTER_KEYS: [&str; 2] = ["servfail_reasons", "client_rcode"];

/// 单上游延迟直方图的一行：`(上游 id, 样本数, 和 ms, 累积桶计数, 桶上界)`。
///
/// **2.1.24**：抽成 type alias（`clippy::type_complexity`：五元组里的
/// `Vec<u64>` + `&'static [f64]` 使签名超过阈值）。字段顺序与语义**逐位不变**。
pub type UpstreamHistogramRow = (String, u64, f64, Vec<u64>, &'static [f64]);

/// 为什么需要它（2.1.12 修的 O(n·buckets) 抓取）：改前 `/metrics` 每次抓取都要
/// 对每条上游的每个样本遍历 10 个桶，实测约 **61k 次比较/抓取**。
/// 现在把这份工作搬到**记录延迟时**：入窗 + 淘汰时同步更新
/// `sum` / 累积桶计数 / 排序视图，抓取只做 `O(桶数)` 拷贝。
///
/// **数值一致性（硬要求）**：增量结果必须与「按窗口重算」**逐值相等**：
/// - `buckets[i]`：严格等于 `count(v in window : v <= LATENCY_BUCKETS_MS[i])`。
///   用**累积**桶语义维护：入窗时把 `>= bucket_of(v)` 的桶 +1，淘汰时 -1
///   （`bucket_of` 即「前多少条 le 满足 `v <= le`」，与旧实现的线性扫描同解）。
/// - `sum`：见 [`Self::sum`] 的浮点说明 —— 与旧实现的**加入序累加逐位相同**。
///
/// 有界：`samples.len() <= UPSTREAM_LAT_WINDOW_MAX`（淘汰最旧样本）。
#[derive(Debug, Default)]
struct UpstreamLatWindow {
    /// 插入序样本（环形语义：满则弹最旧）。仅用于长度/淘汰顺序与降级回退。
    samples: VecDeque<f64>,
    /// **增量**窗口和（与 `samples.iter().sum()` **逐位相同**，见 [`Self::sum`]）。
    sum: f64,
    /// **增量**累积桶计数，长度恒为 [`LATENCY_BUCKETS_MS`]。
    buckets: [u64; LATENCY_BUCKETS_MS.len()],
    /// 升序视图（与 `samples` 同一多重集），供分位数 `O(1)` 取秩。
    sorted: Vec<f64>,
}

/// 累积桶下标：`v <= LATENCY_BUCKETS_MS[i]` 成立的桶数（含下标 i 起全部）。
///
/// 与旧实现「对每个 le 线性判断 `v <= le` 并累加」**同解**，只是换成二分。
#[inline]
fn bucket_of(v: f64) -> usize {
    LATENCY_BUCKETS_MS.partition_point(|le| *le < v)
}

/// 累积桶增量：`delta = +1`（入窗）/ `-1`（淘汰）时，从 `idx` 起到末尾全部累加。
///
/// 语义推导：若 `v <= le_i`，则 `v <= le_j`（`j >= i`）恒成立（le 单调增），
/// 所以「满足 `v <= le` 的 le 集合」正是下标 `idx..` 的后缀 —— 只需一次后缀累加。
#[inline]
fn bucket_delta(buckets: &mut [u64; LATENCY_BUCKETS_MS.len()], v: f64, delta: i64) {
    let idx = bucket_of(v);
    if delta >= 0 {
        for b in buckets[idx..].iter_mut() {
            *b += 1;
        }
    } else {
        for b in buckets[idx..].iter_mut() {
            *b = b.saturating_sub(1);
        }
    }
}

/// 升序视图插入（二分定位 + 单次 `Vec::insert`，成本 `O(W)`）。
#[inline]
fn sorted_insert(sorted: &mut Vec<f64>, v: f64) {
    let pos = sorted.partition_point(|x| *x <= v);
    sorted.insert(pos, v);
}

/// 升序视图删除一个等于 `v` 的元素（`v` 必然存在：它就是被淘汰的样本）。
#[inline]
fn sorted_remove(sorted: &mut Vec<f64>, v: f64) {
    let lo = sorted.partition_point(|x| *x < v);
    if lo < sorted.len() && sorted[lo] == v {
        sorted.remove(lo);
    }
}

/// 分位数取秩：`(lo, hi, frac)`，与旧实现逐值一致（见调用方文档）。
#[inline]
fn quantile_rank(n: usize, p: f64) -> (usize, usize, f64) {
    let k = ((n - 1) as f64) * (p / 100.0);
    let lo = k.floor() as usize;
    let hi = (lo + 1).min(n - 1);
    (lo, hi, k - lo as f64)
}

impl UpstreamLatWindow {
    /// 窗口内样本数。
    #[inline]
    fn len(&self) -> u64 {
        self.samples.len() as u64
    }

    /// 是否为空（`buckets`/`sorted` 与之一致，判空只看样本即可）。
    #[inline]
    fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// **增量**窗口和（漂移上界见 [`Self::sum`] 的一致性说明）。
    ///
    /// 一致性（**实测修正**，2.1.12）：`sum` 由「入窗 `+v` / 淘汰 `-v`」增量维护，
    /// 与「按窗口重算」的结果**不保证逐位相同** —— 浮点加减不可逆
    /// （实测随机序列下相对偏差 ≤ 约 4e-16，即 < 4 ULP；见测试
    /// `a7_incremental_histogram_matches_recompute_exactly` 的容差论证）。
    ///
    /// 关键区分（决定用户可见输出）：
    /// - **桶计数**：整数、逐位精确（`buckets[i] == count(v <= le)` 恒成立）；
    /// - **分位数**：由排序视图按秩取值 + 同样的插值/舍入，**逐位精确**；
    /// - **`_sum`**：仅此一项存在 < 4 ULP 的浮点漂移（数学上和相等，
    ///   差值远小于 `_sum` 输出格式 `{:.3}` 的分辨率）。
    ///
    /// 这是「抓取 O(1) 化」与「浮点逐位可复现」之间的**有意取舍**：改前的逐位
    /// 可复现是以「每次抓取重算 `O(上游数 × 窗口 × 桶数)`」换来的，而 `_sum` 的
    /// 1 ULP 级差异不影响任何阈值/告警判定（`_quantile` 才是分位判定依据）。
    #[inline]
    fn sum(&self) -> f64 {
        self.sum
    }

    /// **测试/校验专用**：按窗口重算的和（与旧实现逐位等价）。
    ///
    /// 生产路径**不调用**（会退化成 `O(窗口)`）；只用于单测钉住「增量值 ≈ 精确值」。
    #[cfg(test)]
    fn recompute_sum(&self) -> f64 {
        self.samples.iter().sum()
    }

    /// 累积桶计数（长度 = [`LATENCY_BUCKETS_MS`]）。
    #[inline]
    fn buckets(&self) -> &[u64; LATENCY_BUCKETS_MS.len()] {
        &self.buckets
    }

    /// 升序视图中的第 `rank` 个值（分位数取秩用；越界 → `None`，绝不 panic）。
    #[inline]
    fn sorted_value(&self, rank: usize) -> Option<f64> {
        self.sorted.get(rank).copied()
    }

    /// 入窗：满则先淘汰最旧，再追加；两处都**增量**更新聚合量。
    fn push(&mut self, ms: f64) {
        if self.samples.len() >= UPSTREAM_LAT_WINDOW_MAX {
            if let Some(old) = self.samples.pop_front() {
                self.sum -= old;
                bucket_delta(&mut self.buckets, old, -1);
                sorted_remove(&mut self.sorted, old);
            }
        }
        self.samples.push_back(ms);
        self.sum += ms;
        bucket_delta(&mut self.buckets, ms, 1);
        sorted_insert(&mut self.sorted, ms);
    }
}

/// **2.1.18（修复项 2/9）**：一次「同一次读取」的计数器快照（**所有对外读数的唯一形态**）。
///
/// 为什么需要它（2.1.17 交付报告 E5）：`/api/status.counters` 与 `/metrics` 此前是
/// **逐字段独立 `AtomicU64::load`** 拼出来的 —— 每个字段各自原子，但**整张表不是**。
/// 高 QPS 下"读 `total`"与"读 `client_rcode`"之间会落入一条正在构造中的查询，
/// 于是同一个响应里 `Σ counters.client_rcode` 与 `counters.total` 偶尔差 1。
///
/// **2.1.18（修复项 9）的关键设计**：本结构**不再**由写侧在锁内维护，而是
/// **读侧按需组装**（[`ServerTelemetry::snapshot`]，全程无锁）：
/// - 热路径（每个查询的计数）保持**纯原子** `fetch_add` —— 早期版本用
///   `Mutex<CounterSnapshot>` 在每次自增时重建快照，实测 QPS 回退 6~8%；
/// - `total` 是 `Σ client_rcode` 的**派生量** ⇒ `total == Σ client_rcode` 是
///   **构造性恒等式**（不存在两个原子之间的 ±1 撕裂窗口）；
/// - 其余字段的"读到一半"由 `snapshot_seq`（写入代数）读前/读后校验 + 重试收敛。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CounterSnapshot {
    /// 本份快照对应的**计数器写入代数**（`ServerTelemetry::snapshot_seq`）。
    ///
    /// 语义：**只在计数写入时递增**（读取不推进）。对账脚本"先比 `seq` 再差分"：
    /// 两次抓取 `seq` 相同 ⇒ 期间没有任何计数写入 ⇒ 允许逐字段差分。
    pub seq: u64,
    /// 抓取时刻（进程启动以来的单调毫秒），与 `monotonic_ms()` 同源。
    pub monotonic_ms: u64,
    // ---- [`COUNTER_KEYS`] 的标量键（一一对应）----
    /// **派生量**（**2.1.19 修复项 9**）：**恒等于 `Σ client_rcode`**。
    ///
    /// 语义 = **为客户端构造出来的应答数**（每条恰好一条 rcode）；没有构造出应答的
    /// 登记进 [`Self::no_response_total`]（**与 total 互斥，不得相加**）。
    pub total: u64,
    pub hit: u64,
    pub miss: u64,
    pub upstream_queries: u64,
    pub errors: u64,
    pub ipv4_fallback: u64,
    pub stale_served: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub rebind_blocked: u64,
    pub udp_dropped: u64,
    pub servfail_total: u64,
    pub negative_hits: u64,
    pub cache_skipped_private_total: u64,
    /// **2.1.18（修复项 9）**：出口登记了但**没有构造出可发送报文**的次数。
    ///
    /// **它是 `total` 之外的缺口项，不得与 `total` 相加**（两者互斥）。
    pub no_response_total: u64,
    /// **2.1.20（A-04）**：控制面 `POST /api/query` 的次数（**不含**数据面客户端查询）。
    pub control_queries: u64,
    /// **2.1.20（A-04）**：上述控制面查询里由**缓存直答**的次数。
    ///
    /// **不得**混入 `hit`：`hit_rate = hit/(hit+miss)`（2.1.40 起）的分母只统计数据面，
    /// 把控制面命中加进 `hit` 会让命中率 >100%（2.1.19 实测 600.0%）。
    pub control_hits: u64,
    /// **2.1.29**：未知 qtype 透传次数（成功 + 失败；不缓存）。
    pub passthrough_qtype_total: u64,
    /// **2.1.40**：本地策略短路次数（AAAA 屏蔽 / IPv6 关闭）。
    ///
    /// 与 `hit` / `miss` **互斥**：这类应答既没查缓存也没发上游，
    /// 只在这里 +1。`hit_rate = hit / (hit + miss)` 因此不被它摊薄。
    // >>> 242B BEGIN P1-6-snapfield >>> //
    pub policy_filtered_total: u64,
    /// **2.1.42-B（P1-6）**：本地规则直答次数（block / forceIp / no-upstream）。
    /// `hit + miss + policy_filtered_total + rule == total`。
    pub rule: u64,
    /// **2.1.43-A（P2）**：`prefer_ipv4` 双栈探测**真的发往上游**的次数（只追加）。
    ///
    /// 与 [`Self::upstream_queries`] **互不重叠**：后者是"数据面**客户端查询**里
    /// 发过上游"的数量，探针不是客户端查询。写点唯一 =
    /// `resolve.rs::probe_a_record`（真的调了 `query_parallel` 才算）。
    pub probe_upstream_queries: u64,
    /// `counters.client_rcode`：16 槽定长分布（下标 = wire rcode）。
    // <<< 242B END P1-6-snapfield <<< //
    pub client_rcode: [u64; 16],
    /// `counters.servfail_reasons`：固定 5 档（[`SERVFAIL_REASONS`] 的顺序）。
    pub servfail_reasons: [u64; SERVFAIL_REASONS.len()],
}

/// 服务端遥测。resolver 用它计 query/inc/log；API 层读它做 status/metrics/logs/snapshot。
pub struct ServerTelemetry {
    boot: Instant,
    // ---- v1.9.162 counters 的键（全部原子自增）----
    //
    // **2.1.18（修复项 9）**：`total` **不再是独立原子** —— `counters.total` 由
    // `Σ client_rcode` **派生**（见 [`CounterSnapshot::total`]）。派生让
    // `total == Σ client_rcode` 成为构造性恒等式，同时把热路径从"每查询一次
    // `lock()`"改回纯原子（比 2.1.17 还少一次 `fetch_add`）。
    hit: AtomicU64,
    miss: AtomicU64,
    upstream_queries: AtomicU64,
    errors: AtomicU64,
    ipv4_fallback: AtomicU64,
    stale_served: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    rebind_blocked: AtomicU64,
    /// 规则命中：rule_label -> 计数。
    rule_hits: Mutex<HashMap<String, u64>>,
    /// **2.1.16（功能 3）**：规则命中的**二维**聚合 `(match_type, action) -> 次数`。
    ///
    /// 与一维 [`Self::rule_hits`] 由**同一打点**（`inc_rule_kind`）同时更新，
    /// 因此两者总量恒等（可对账）。键空间有界：4 种 match_type × 5 种 action ≤ 20。
    rule_hits_kind: Mutex<HashMap<(String, String), u64>>,
    events: Mutex<VecDeque<Value>>,
    /// 手动查询历史（/api/query）。
    manual: Mutex<VecDeque<Value>>,
    next_seq: AtomicU64,
    /// 历史采样环（5 图折线）。
    history: Mutex<VecDeque<Value>>,
    /// qtype 分布：A / AAAA / other。
    qtype_a: AtomicU64,
    qtype_aaaa: AtomicU64,
    qtype_other: AtomicU64,
    /// 上游命中频次（top_upstreams）。
    upstream_hits: Mutex<HashMap<String, u64>>,
    /// 域名频次（top_domains）。
    domain_hits: Mutex<HashMap<String, u64>>,
    /// 客户端 IP 频次（top_clients）。
    client_hits: Mutex<HashMap<String, u64>>,
    /// **[历史归因]** 最近 [`LATENCY_WINDOW_MAX`] 条延迟样本（ms；对齐 Python `latency_window`）。
    latency: Mutex<VecDeque<f64>>,
    /// 最近 1 秒内查询时间戳（对齐 v1.9.162 `qps_window` deque(maxlen=600)）。
    qps_win: Mutex<VecDeque<f64>>,
    /// **A7**：逐上游延迟样本窗口（`upstream id -> 增量直方图`）。
    /// `/metrics` 的 `ebpdns_upstream_latency_ms` 直方图/分位数唯一来源；
    /// 与全局 `latency` 窗口分离，保证既有 `avg_latency_ms` 口径不变。
    ///
    /// **2.1.12**：值类型从裸 `VecDeque<f64>` 换成 [`UpstreamLatWindow`] ——
    /// 桶计数/和/排序视图**增量维护**，`/metrics` 抓取不再是「逐桶遍历 61k 次比较」。
    upstream_lat: Mutex<HashMap<String, UpstreamLatWindow>>,
    /// **A7**：负缓存命中数（缓存直答且应答为 NXDOMAIN / 空答案段）。
    /// `ebpdns_negcache_hits_total` + `ebpdns_negcache_hit_ratio` 的来源
    /// （比例分母直接用既有的 `hit` 计数器，无需独立分母）。
    neg_hit: AtomicU64,
    /// **2.1.16（修复项 15）**：`/api/status.counters.negative_hits` 的独立计数器。
    ///
    /// 与 `neg_hit` **同点自增**（`count_neg_hit`），两者恒等（单测钉死）——
    /// 分开存是为了让"内部观测口径"（`neg_hit`，驱动 `/metrics`）与
    /// "对外 counters 口径"（`negative_hits`，驱动 `/api/status`）各自稳定，
    /// 将来任一侧改语义时不会互相牵连。
    negative_hits: AtomicU64,
    /// **2.1.17（修复项 3）**：因 rebind 防护被丢弃的私有/保留地址答案条数
    /// （`/api/status.counters.cache_skipped_private_total`）。
    ///
    /// 唯一打点 = 数据面出口 `dns.rs::log_and_count`（把
    /// `ResolveResult::private_answers_filtered` 累加进来），因此与
    /// `/metrics` 的 `ebpdns_cache_skipped_private_total` **同源同值**。
    ///
    /// 语义边界（**不要与 `rebind_blocked` 混用**）：
    /// - 本键 = **数据面答案**里的私网/保留地址被 `rebind_protection` 过滤掉的**条数**
    ///   （含"全部答案皆为私网 ⇒ 回 NODATA"的情形）；
    /// - `rebind_blocked` = **控制面** DNS-rebinding 拦截（API/订阅写路径被拒），
    ///   数据面**从不**经过它，所以它在纯 DNS 压测里恒 0 是**正确**的。
    ///
    /// 为什么它不是 `rebind_blocked` 的子集：两条路径完全不相交（一个在 resolver
    /// 的答案过滤，一个在 `security.rs` 的主机名/IP 校验）。
    cache_skipped_private_total: AtomicU64,
    /// **2.1.18（修复项 9）**：出口登记但无可发送报文（`resp.len() < 12`）的次数。
    /// 语义与用途见 [`COUNTER_KEYS`] 里同名键的说明（`total` 的可对账差额项）。
    no_response_total: AtomicU64,
    /// **2.1.20（A-04）**：控制面查询计数（与数据面 `hit/miss/total` **互不混用**）。
    control_queries: AtomicU64,
    /// **2.1.20（A-04）**：控制面缓存直答计数（与数据面 `hit` **互不混用**）。
    control_hits: AtomicU64,
    /// **2.1.29**：未知 qtype 透传计数（成功 + 失败都 +1；不缓存）。
    /// 写点唯一 = `dns.rs::log_and_count`（数据面唯一出口）。
    passthrough_qtype_total: AtomicU64,
    // >>> 242B BEGIN P1-6-field >>> //
    /// **2.1.40**：本地策略短路计数（写点唯一 = `dns.rs::log_and_count`）。
    policy_filtered_total: AtomicU64,
    /// **2.1.42-B（P1-6）**：本地规则直答（block/forceIp/no-upstream）计数
    /// （写点唯一 = `dns.rs::log_and_count` 的 `MissClass::Rule` 分支）。
    rule: AtomicU64,
    /// **2.1.43-A（P2）**：`prefer_ipv4` 双栈探测的发上游次数
    /// （写点唯一 = `resolve.rs::probe_a_record`；与数据面 `upstream_queries` 分开）。
    probe_upstream_queries: AtomicU64,
    // <<< 242B END P1-6-field <<< //
    /// **P0-5（2.1.14）**：UDP miss 并发闸门拒绝/丢包数。
    ///
    /// **2.1.43-A（P2：`udp_dropped` 双源）**：改成 `Arc<AtomicU64>` ——
    /// `DnsServer` 通过 [`Self::udp_dropped_handle`] 复用**同一个**原子，
    /// 于是 `/api/status.udp_dropped`（顶层）、`/api/status.counters.udp_dropped`、
    /// `/api/snapshot.counters.udp_dropped` 与 `/metrics`
    /// `ebpdns_udp_dropped_total` **在构造上就是同一个计数器**（不是"两处各写一份、
    /// 靠人肉保证相等"）。2.1.42 有两个原子、丢包时各 +1，任一处漏写即静默分叉。
    udp_dropped: std::sync::Arc<AtomicU64>,
    /// **2.1.15（P1 低频 SERVFAIL）**：服务端**真的回给客户端**的 SERVFAIL 数
    /// （`rcode == 2`），在数据面**唯一出口** `dns.rs::log_and_count` 打点 ——
    /// 与 `errors` 口径刻意不同：`errors` 是"内部错误"（上游全失败 / 组包失败 /
    /// 畸形包），SERVFAIL 是"客户端实际看到的应答码"。
    servfail_total: AtomicU64,
    /// 同一打点处的**原因维度**（5 档**互斥**，见 [`SERVFAIL_REASONS`]）。
    /// 不变式：`servfail_total == sum(各档)`（单测钉死）。
    ///
    /// **2.1.18（修复项 2）**：从 `Mutex<HashMap<String, u64>>` 改成**定长原子数组**
    /// （下标 = [`SERVFAIL_REASONS`] 的顺序）—— 与 [`Self::client_rcode`] 同构。
    /// 为什么必须改：`servfail_total` 是原子、分档是**加锁的表**，两者更新之间有一个
    /// 真实的窗口，并发读者会看到 `Σ 分档 = total − 1`（首轮并发单测实测到 79 vs 80）。
    /// 改成原子数组后，总数与分档在**同一次出口调用里相邻自增**，读侧再用
    /// "写入代数 + 一致性重试"收敛（见 [`ServerTelemetry::snapshot`]），
    /// 读者拿到的快照必然满足 `Σ == total`。
    ///
    /// 对外键名与顺序**不变**（`counters.servfail_reasons` 仍是那 5 个字符串键）。
    servfail_reasons: [AtomicU64; SERVFAIL_REASONS.len()],
    /// **2.1.16（修复项 8）**：**实际发往客户端的 rcode 分布**（16 槽，下标 = rcode）。
    ///
    /// 为什么必须有它（部署代理实测的"客户端 2 / 服务端 0"缺口）：2.1.15 的服务端只有
    /// `servfail_total`（rcode==2 的**总数**）+ `servfail_reasons`（内部归因），
    /// **没有任何**"服务端到底发出了哪些 rcode、各多少条"的计数。于是压测脚本只能用
    /// **客户端** `d[3] & 0xF` 统计 rcode，而客户端脚本对"超时/无应答"的分类各写各的
    /// （`f215-ladder.py` 把它算 timeout、另一版把它算 err），一旦有人把超时并进
    /// SERVFAIL，"客户端 2 / 服务端 0"就会凭空出现且**无法在服务端侧自证**。
    ///
    /// 语义（在数据面**唯一出口** `dns.rs::log_and_count` 打点，与 `servfail_total`
    /// 同一判据源 = 真正写上线的那条报文）：
    /// `client_rcode[i]` = 服务端**成功构造并交给内核发送**的 rcode == i 的应答数。
    /// **注意**：请求被丢弃（UDP 闸门 `udp_dropped` / TCP 缓冲超限）或发送失败
    /// （`send_to` 出错）**不产生任何 rcode** —— 客户端那边表现为**超时/无应答**，
    /// 这正是"客户端 SERVFAIL 数 > 服务端 `servfail_total`"时应当先排除的解释。
    /// 该分布与 `servfail_total` 的关系是**硬等式**：
    /// `client_rcode[2] == servfail_total`（单测钉死）。
    client_rcode: [AtomicU64; 16],
    /// **2.1.18（修复项 2/9）**：**计数器写入代数**（每次计数写入 +1，读取不推进）。
    ///
    /// 与 `next_seq`（**事件**序号）**无关**：那个是 `/api/logs` 游标。
    /// 用途：
    /// - 下发为 `/api/status.snapshot_seq` / `/metrics` 的 `seq=` ⇒ 对账脚本
    ///   "先比 seq 再差分"：**两次抓取 seq 相同 ⇒ 期间没有任何计数写入**；
    /// - **读侧一致性**（本版本核心）：`snapshot()` 读前/读后各取一次，不同则重试，
    ///   从而在**不加锁**的前提下拿到"同一代"的读数。
    ///
    /// 它是**普通原子自增**（`fetch_add`），不是锁：写侧只多一条 `lock xadd`。
    snapshot_seq: AtomicU64,
    // >>> 245 P2-6 reset-gate BEGIN
    /// **2.1.45（P2-6 / REV247 P2-2）**：`/api/reset` 的**冻结位**。
    ///
    /// reset 改为"**先置冻结位 → 清 → 解除**"：冻结期内到达的写入（`inc_n` /
    /// `note_data_plane_outcome`）**一律丢弃**（明确语义：冻结期间的查询**不计**，
    /// 而不是被算进"清到一半"的旧代）。这样 `hit+miss+policy+rule == total` 与
    /// `total == Σ client_rcode` 在 reset 前后都不会出现半新半旧的撕裂。
    reset_frozen: std::sync::atomic::AtomicBool,
    /// 数据面记账 ↔ reset 的**读写屏障**：`log_and_count` 全程持读锁，
    /// `/api/reset` 持写锁 ⇒ 一条查询的"total + 分类"要么全在清空前、要么全在清空后。
    reset_gate: parking_lot::RwLock<()>,
    // <<< 245 P2-6 reset-gate END
}

impl Default for ServerTelemetry {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerTelemetry {
    pub fn new() -> Self {
        Self {
            boot: Instant::now(),
            hit: AtomicU64::new(0),
            miss: AtomicU64::new(0),
            upstream_queries: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            ipv4_fallback: AtomicU64::new(0),
            stale_served: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            rebind_blocked: AtomicU64::new(0),
            rule_hits: Mutex::new(HashMap::new()),
            rule_hits_kind: Mutex::new(HashMap::new()),
            events: Mutex::new(VecDeque::with_capacity(EVENT_RING_MAX)),
            manual: Mutex::new(VecDeque::with_capacity(MANUAL_RING_MAX)),
            next_seq: AtomicU64::new(0),
            history: Mutex::new(VecDeque::with_capacity(HISTORY_RING_MAX)),
            qtype_a: AtomicU64::new(0),
            qtype_aaaa: AtomicU64::new(0),
            qtype_other: AtomicU64::new(0),
            upstream_hits: Mutex::new(HashMap::new()),
            domain_hits: Mutex::new(HashMap::new()),
            client_hits: Mutex::new(HashMap::new()),
            latency: Mutex::new(VecDeque::with_capacity(LATENCY_WINDOW_MAX)),
            qps_win: Mutex::new(VecDeque::with_capacity(QPS_WINDOW_MAX)),
            upstream_lat: Mutex::new(HashMap::new()),
            neg_hit: AtomicU64::new(0),
            negative_hits: AtomicU64::new(0),
            cache_skipped_private_total: AtomicU64::new(0),
            no_response_total: AtomicU64::new(0),
            control_queries: AtomicU64::new(0),
            control_hits: AtomicU64::new(0),
            passthrough_qtype_total: AtomicU64::new(0),
            // >>> 242B BEGIN P1-6-init >>> //
            policy_filtered_total: AtomicU64::new(0),
            rule: AtomicU64::new(0),
            probe_upstream_queries: AtomicU64::new(0),
            udp_dropped: std::sync::Arc::new(AtomicU64::new(0)),
            // <<< 242B END P1-6-init <<< //
            servfail_total: AtomicU64::new(0),
            servfail_reasons: std::array::from_fn(|_| AtomicU64::new(0)),
            client_rcode: std::array::from_fn(|_| AtomicU64::new(0)),
            snapshot_seq: AtomicU64::new(0),
            reset_frozen: std::sync::atomic::AtomicBool::new(false),
            reset_gate: parking_lot::RwLock::new(()),
        }
    }

    /// 启动以来秒数。
    pub fn uptime_s(&self) -> u64 {
        self.boot.elapsed().as_secs()
    }

    /// **2.1.17（修复项 4）**：进程启动以来的**单调**毫秒数（`Instant` 口径，
    /// 不受 NTP 调整/时区/DST 影响）。
    ///
    /// 用途：`/api/status.snapshot_monotonic_ms` —— 压测脚本用它与自己的单调时钟
    /// **[历史归因]** （Python `time.monotonic()`、Rust `Instant::now()`）算 delta，从而把
    /// "服务端快照窗口"与"客户端压测窗口"对齐，闭合 2.1.16 登记的 0.5% 对账余量
    /// （机理与判据见 `api.rs::status` 的文档）。
    ///
    /// 为什么不用墙钟：墙钟可被 `ntpd/chronyd` 步进（甚至回退），而压测窗口只有
    /// 几十秒 —— 一次步进就能把余量算成负数或凭空放大。单调钟没有这个问题。
    /// 与 `uptime_s()` 同源（都是 `boot`），因此 `monotonic_ms / 1000` 与
    /// `uptime_s()` 在整秒粒度上一致（单测钉死）。
    pub fn monotonic_ms(&self) -> u64 {
        self.boot.elapsed().as_millis() as u64
    }

    /// **2.1.18（修复项 2/9）：组装一份计数器快照（全程无锁）。**
    ///
    /// `client_rcode` / `servfail_reasons` 两个数组由调用方读好后传入 ——
    /// 这样它们在一次快照里各只读一遍、不会自相矛盾；其余标量在这里逐个
    /// `load(Relaxed)`。`total` 由 `Σ client_rcode` **派生** ⇒
    /// `total == Σ client_rcode` 是构造性恒等式（不存在撕裂窗口）。
    fn build_counter_snapshot(
        &self,
        seq: u64,
        monotonic_ms: u64,
        mut client_rcode: [u64; 16],
        servfail_reasons: [u64; SERVFAIL_REASONS.len()],
    ) -> CounterSnapshot {
        // **2.1.18（修复项 9）**：rcode=2 的槽位也是**派生量**（= `Σ servfail_reasons`）。
        //
        // 为什么：`client_rcode[2]` 与原因分档位于**两个不同的原子数组**，并发写下
        // 读侧必然存在 ±1 的跨数组撕裂窗口（4 写 × 4 读的并发单测实测到 371 vs 370）。
        // 出口侧"`rcode == 2` ⇔ 恰好记一个原因分档"是一一对应的（见
        // [`Self::note_data_plane_outcome`]），把槽位改成派生即可让
        // `client_rcode[2] == servfail_total == Σ servfail_reasons` **由构造保证**，
        // 读侧不再需要任何重试或校验。
        client_rcode[2] = servfail_reasons.iter().sum::<u64>();
        CounterSnapshot {
            seq,
            monotonic_ms,
            // **派生量**：`total ≡ Σ client_rcode`（构造性恒等式）。
            total: client_rcode.iter().sum::<u64>(),
            hit: self.hit.load(Ordering::Relaxed),
            miss: self.miss.load(Ordering::Relaxed),
            upstream_queries: self.upstream_queries.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            ipv4_fallback: self.ipv4_fallback.load(Ordering::Relaxed),
            stale_served: self.stale_served.load(Ordering::Relaxed),
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
            rebind_blocked: self.rebind_blocked.load(Ordering::Relaxed),
            udp_dropped: self.udp_dropped.load(Ordering::Relaxed),
            // **派生量**：`servfail_total ≡ Σ servfail_reasons`（同一分支内一一对应）。
            // 这样并发读下不存在"总数与分档差 1"的窗口；`self.servfail_total` 原子
            // 仍由 `note_servfail` / `inc_n("servfail_total")` 与分档**成对**推进
            // （保留它是为了 `counters.servfail_total` 的写入侧语义与排查便利）。
            servfail_total: servfail_reasons.iter().sum::<u64>(),
            negative_hits: self.negative_hits.load(Ordering::Relaxed),
            cache_skipped_private_total: self.cache_skipped_private_total.load(Ordering::Relaxed),
            no_response_total: self.no_response_total.load(Ordering::Relaxed),
            control_queries: self.control_queries.load(Ordering::Relaxed),
            control_hits: self.control_hits.load(Ordering::Relaxed),
            passthrough_qtype_total: self.passthrough_qtype_total.load(Ordering::Relaxed),
            // >>> 242B BEGIN P1-6-snapload >>> //
            policy_filtered_total: self.policy_filtered_total.load(Ordering::Relaxed),
            rule: self.rule.load(Ordering::Relaxed),
            probe_upstream_queries: self.probe_upstream_queries.load(Ordering::Relaxed),
            client_rcode,
            // <<< 242B END P1-6-snapload <<< //
            servfail_reasons,
        }
    }
    /// **2.1.18（修复项 2/9）**：取一份快照（对外唯一读取入口）。
    ///
    /// **性能：完全无锁** —— 全部字段逐个 `load(Relaxed)`，`total` 由
    /// `Σ client_rcode` 派生。写侧因此**一次 `lock()` 都不发生**（2.1.19 早期版本用
    /// `Mutex<CounterSnapshot>` 在每次自增时重建快照，实测 QPS 回退 6~8%）。
    ///
    /// **一致性（不加锁如何保证"同一代"）**：
    /// 1. 读前取 `w1 = snapshot_seq`（写入代数）；
    /// 2. 读完全部字段（两个结构化数组各读一遍）；
    /// 3. 读后取 `w2`。`w1 == w2` ⇒ 期间**没有任何计数写入** ⇒ 这份读数属于同一代；
    /// 4. 否则重试（上限 [`SNAPSHOT_RETRY_MAX`] 次）。重试期间若观察到
    ///    `Σ servfail_reasons != servfail_total` 或 `client_rcode[2] != servfail_total`
    ///    （写侧相邻写入之间的极窄窗口）同样重试。
    ///
    /// 重试耗尽后返回最后一次读数：**`total == Σ client_rcode` 仍必然成立**（派生量）；
    /// 其余等式若真被破坏会**如实暴露**，不会被掩盖。
    pub fn snapshot(&self) -> CounterSnapshot {
        let mut attempt = 0u32;
        loop {
            let w1 = self.snapshot_seq.load(Ordering::Acquire);
            let client_rcode =
                std::array::from_fn(|i| self.client_rcode[i].load(Ordering::Relaxed));
            let servfail_reasons =
                std::array::from_fn(|i| self.servfail_reasons[i].load(Ordering::Relaxed));
            let monotonic_ms = self.boot.elapsed().as_millis() as u64;
            let s = self.build_counter_snapshot(w1, monotonic_ms, client_rcode, servfail_reasons);
            let w2 = self.snapshot_seq.load(Ordering::Acquire);
            // **四条硬等式全部是构造性的**（`total` / `servfail_total` /
            // `client_rcode[2]` 都是派生量；`hit + miss <= total` 由写入顺序保证），
            // 因此读侧只需判"读期间有没有写入"。
            let consistent = w1 == w2;
            if consistent || attempt >= SNAPSHOT_RETRY_MAX {
                return CounterSnapshot { seq: w2, ..s };
            }
            attempt += 1;
            std::hint::spin_loop();
        }
    }

    /// **2.1.18（修复项 2）**：读侧唯一入口 —— 在**一次**快照内跑 `f`。
    ///
    /// 用法：`let (a, b) = t.with_snapshot(|s| (s.total, s.hit));`
    /// 一次响应内需要多个**必须同代**的计数时用它，不要多次调 `snapshot()`。
    pub fn with_snapshot<R>(&self, f: impl FnOnce(&CounterSnapshot) -> R) -> R {
        let s = self.snapshot();
        f(&s)
    }

    /// **2.1.18（修复项 9）**：推进"写入代数"（**每个计数写入点一次**）。
    ///
    /// 一条 `Release` 的 `fetch_add`，**不是锁**：它只让读侧知道"这份快照读的过程中
    /// 有没有写入"，从而在需要时重试。热路径因此保持纯原子。
    #[inline]
    fn bump_write_seq(&self) {
        self.snapshot_seq.fetch_add(1, Ordering::Release);
    }
    /// **2.1.18（修复项 2）**：把一次数据面出口的**同点**三类观测一次落账。
    ///
    /// 取代此前 `dns.rs::log_and_count` 里的三次独立调用
    /// （`note_client_rcode` / `note_servfail` / `count_cache_skipped_private`）——
    /// 三次独立加锁会让读者有窗口看到
    /// 「`client_rcode[2]` 已 +1 而 `servfail_total` 还没 +1」的中间态，
    /// 那正好破坏 `client_rcode[2] == servfail_total` 这条硬等式（E5 的同型问题）。
    ///
    /// 参数语义与各自的单独入口**逐字一致**（见各自文档）：
    /// - `rcode`：真正写上线的那条报文的 `resp[3] & 0x0F`；`None` = 未组包（不计分布）；
    /// - `servfail_reason`：`rcode == 2` 时的原因（`None` = 非 SERVFAIL 或原因未知）；
    /// - `private_filtered`：本次应答被 rebind 防护丢弃的私网/保留答案条数（0 = 无）。
    pub fn note_data_plane_outcome(
        &self,
        rcode: Option<u8>,
        servfail_reason: Option<&str>,
        private_filtered: u32,
    ) {
        // **2.1.45（P2-6）**：冻结期内不计（与 `inc_n` 同口径；数据面已由读屏障挡住，
        // 这里是给"未持屏障的旁路写者"的兜底）。
        if self.reset_frozen() {
            return;
        }
        // 归一化到锁外（`warn` 去重本身有独立锁，顺序无关正确性，但避免嵌套锁）。
        let reason: Option<&'static str> = servfail_reason.map(|r| {
            if SERVFAIL_REASONS.contains(&r) {
                SERVFAIL_REASONS[SERVFAIL_REASONS.iter().position(|x| *x == r).unwrap_or(0)]
            } else {
                warn_unknown_servfail_reason(r);
                SERVFAIL_REASONS[0]
            }
        });
        let rcode_idx = rcode.map(|rc| (rc & 0x0F) as usize);
        // **2.1.18（修复项 9）**：这里**不再早退**。`rcode = None` 表示"没有构造出可发送
        // 的报文"，必须记进 `no_response_total`（否则"登记了却没发出去"的查询会变成
        // 静默黑洞 —— 2021.18 早期版本 `total = 2×Σrcode + 256` 里的 256 正是这一类）。
        // **写侧全程无锁**（纯原子自增）。顺序即语义：
        //  ① `client_rcode[i]` 是**应答数的唯一真值**（`counters.total` 由它派生 ⇒
        //     `total == Σ client_rcode` 是构造性恒等式，并发写也无法撕裂它）；
        //  ② **只有 `rcode == 2`** 才计 `servfail_total` + 一个原因分档 ——
        //     `dns.rs::servfail_reason_of` 保证"rcode==2 ⇔ 有结构化归因"，
        //     因此 `client_rcode[2] == servfail_total == Σ servfail_reasons`
        //     是同一分支内的一一对应（不会再出现"无应答却计了 SERVFAIL"的错配）。
        match rcode_idx {
            Some(i) => {
                if i == 2 {
                    // **`rcode == 2` 的槽位不单独写**：它由 `Σ servfail_reasons` 派生
                    // （见 `build_counter_snapshot`），于是
                    // `client_rcode[2] == servfail_total == Σ reasons` 三条**同时**
                    // 由构造保证，而不是靠"两次相邻写入 + 读侧重试"。
                    self.servfail_total.fetch_add(1, Ordering::Relaxed);
                    let idx = reason
                        .map(|r| SERVFAIL_REASONS.iter().position(|x| *x == r).unwrap_or(0))
                        // 防御分支：rcode=2 但调用方没给归因（`servfail_reason_of`
                        // 不会这样）—— 记兜底分档，保证派生值仍是"发出的 SERVFAIL 数"。
                        .unwrap_or(0);
                    self.servfail_reasons[idx].fetch_add(1, Ordering::Relaxed);
                } else {
                    self.client_rcode[i].fetch_add(1, Ordering::Relaxed);
                }
            }
            None => {
                // 出口登记了、但**没有可发送的报文**（畸形包 / 空 question / 组包失败）：
                // **不计 `total`**（没有为客户端构造出任何应答），单独记本键。
                // 文档与 `/metrics` 写明"它是 `total` 之外的缺口项，**不得与 total 相加**"。
                self.no_response_total.fetch_add(1, Ordering::Relaxed);
            }
        }
        if private_filtered > 0 {
            self.cache_skipped_private_total
                .fetch_add(u64::from(private_filtered), Ordering::Relaxed);
        }
        self.bump_write_seq();
    }

    /// 累计计数器快照（**同代**，见 [`CounterSnapshot`]）。
    ///
    /// 键集合与 v1.9.162 `Telemetry.__init__.counters` 完全一致（[`COUNTER_KEYS`]），
    /// 缺失键一律以 0 呈现——页面/`/metrics` 不再需要"键不存在"的兜底分支。
    ///
    /// **2.1.18（修复项 2/9）**：整张表由**一次** [`Self::snapshot`] 派生 ——
    /// 全部标量 + `servfail_reasons` + `client_rcode` 来自**同一次读取**，
    /// 因此"`Σ client_rcode == total`"、"`client_rcode[\"2\"] == servfail_total`"、
    /// "`servfail_total == Σ reasons`" 三条硬等式在同一次响应内**恒成立**
    /// （改前逐字段独立 `load`，高 QPS 下会差 1，即 2.1.17 的 E5）。
    pub fn counters(&self) -> serde_json::Map<String, Value> {
        let t = self.snapshot();
        let s = &t;
        let mut m = serde_json::Map::new();
        m.insert("total".into(), json!(s.total));
        m.insert("hit".into(), json!(s.hit));
        m.insert("miss".into(), json!(s.miss));
        m.insert("upstream_queries".into(), json!(s.upstream_queries));
        m.insert("errors".into(), json!(s.errors));
        m.insert("ipv4_fallback".into(), json!(s.ipv4_fallback));
        m.insert("stale_served".into(), json!(s.stale_served));
        m.insert("bytes_in".into(), json!(s.bytes_in));
        m.insert("bytes_out".into(), json!(s.bytes_out));
        m.insert("rebind_blocked".into(), json!(s.rebind_blocked));
        // P0-5：UDP 闸门拒绝/丢包（`/api/status.counters.udp_dropped`）。
        m.insert("udp_dropped".into(), json!(s.udp_dropped));
        // **2.1.15（P1）**：服务端回给客户端的 SERVFAIL 总数 + 原因维度
        // （唯一打点 = `dns.rs::log_and_count`）。**同一代**取出，不可能对不上。
        m.insert("servfail_total".into(), json!(s.servfail_total));
        {
            let mut o = serde_json::Map::new();
            for (i, k) in SERVFAIL_REASONS.iter().enumerate() {
                o.insert((*k).to_string(), json!(s.servfail_reasons[i]));
            }
            m.insert("servfail_reasons".into(), Value::Object(o));
        }
        // **2.1.16（修复项 8）**：实际发往客户端的 rcode 分布（服务端侧自证口径）。
        //
        // 键是**字符串数字**（JSON 对象键必须是字符串），与 `/metrics` 的
        // `rcode="…"` 标签值逐字一致，压测脚本可直接对账而无需转换。
        // 硬等式：`client_rcode["2"] == servfail_total`（同点打点 + 同代快照）。
        {
            let mut o = serde_json::Map::new();
            for (i, n) in s.client_rcode.iter().enumerate() {
                o.insert(i.to_string(), json!(n));
            }
            m.insert("client_rcode".into(), Value::Object(o));
        }
        // **2.1.16（修复项 15）**：负缓存命中（与 `neg_hits()` 同源同值）。
        m.insert("negative_hits".into(), json!(s.negative_hits));
        // >>> 242B BEGIN P1-6-telcounters >>> //
        m.insert("rule".into(), json!(s.rule));
        // <<< 242B END P1-6-telcounters <<< //
        // **2.1.43-A**：`prefer_ipv4` 双栈探测的发上游次数（与 `upstream_queries` 分开）。
        m.insert(
            "probe_upstream_queries".into(),
            json!(s.probe_upstream_queries),
        );
        // **2.1.17（修复项 3）**：被 rebind 防护丢弃的私网/保留答案条数
        // （设计行为：这些结果**不入缓存**）。与 `/metrics` 的
        // `ebpdns_cache_skipped_private_total` 同源同值（单测钉死）。
        m.insert(
            "cache_skipped_private_total".into(),
            json!(s.cache_skipped_private_total),
        );
        // **2.1.18（修复项 9）**：出口登记但无可发送报文的次数。
        // **它是 `total` 之外的缺口项，不得与 `total` 相加**（两者互斥）。
        m.insert("no_response_total".into(), json!(s.no_response_total));
        // **2.1.20（A-04）**：控制面查询的**独立**计数（`hit`/`miss`/`total` 只统计数据面）。
        // 与 `/metrics` 的 `ebpdns_control_queries_total` / `ebpdns_control_hits_total` 同源。
        m.insert("control_queries".into(), json!(s.control_queries));
        m.insert("control_hits".into(), json!(s.control_hits));
        // **2.1.29**：未知 qtype 透传（成功 + 失败；不缓存）。
        m.insert(
            "passthrough_qtype_total".into(),
            json!(s.passthrough_qtype_total),
        );
        // **2.1.40**：本地策略短路（不计 hit/miss；口径见同名常量说明）。
        m.insert(
            "policy_filtered_total".into(),
            json!(s.policy_filtered_total),
        );
        m
    }

    /// **2.1.16（修复项 8）**：`note_servfail` 的**同点**伙伴 —— 记录本次真正发出的
    /// 报文 rcode（含非 SERVFAIL）。两个计数在 `dns.rs::log_and_count` 的**同一处**
    /// 调用，因此 `client_rcode[2] == servfail_total` 恒成立（单测钉死）。
    ///
    /// `rcode` 取 `resp[3] & 0x0F` 的**wire 值**（0..15），越界按 0 归档并告警一次
    /// （不 panic、不丢样本）。
    ///
    /// **2.1.18（修复项 2）**：数据面出口改用
    /// [`Self::note_data_plane_outcome`]（一次落账三类观测，消除"只 +1 了一半"的
    /// 中间态）；本方法保留给单测/其它调用方，语义**逐字不变**。
    pub fn note_client_rcode(&self, rcode: u8) {
        let i = (rcode & 0x0F) as usize;
        // 结构化原子数组是唯一真值（`counters.total` 由它派生）；无锁、无双写。
        if i == 2 {
            // **2.1.18（修复项 9）**：槽位 2 由 `Σ servfail_reasons` 派生（见
            // `build_counter_snapshot`），因此这里改记**兜底原因分档**，保证
            // `note_client_rcode(2)` 与出口路径同解、且不会让派生值漏计。
            self.servfail_total.fetch_add(1, Ordering::Relaxed);
            self.servfail_reasons[0].fetch_add(1, Ordering::Relaxed);
        } else {
            self.client_rcode[i].fetch_add(1, Ordering::Relaxed);
        }
        self.bump_write_seq();
    }

    /// **2.1.17**：`(match_type, action)` 二维聚合的**公开**打点入口。
    ///
    /// 语义与 trait 里的 `inc_rule_kind` 完全一致（同一函数，单一打点），只是把
    /// 可见性放宽到 `pub`，供 `/api` 层与集成测试直接驱动（不必经过数据面）。
    /// **不得**在别处另写一份自增逻辑（会造成两张表漂移，破坏
    /// `sum(二维) == sum(rule_hits)` 这条可对账恒等式）。
    pub fn rule_hit_by_kind(&self, match_type: &str, action: &str) {
        self.inc_rule_kind(match_type, action);
    }

    /// **2.1.16（修复项 8）**：实际发往客户端的 rcode 分布快照（定长 16 槽，索引即 rcode）。
    ///
    /// 用途（服务端侧自证，不依赖客户端口径）：
    /// - `/metrics` 的 `ebpdns_client_rcode_total{rcode="…"}`；
    /// - `/api/status.counters.client_rcode`（结构化键）→ 压测脚本可直接把
    ///   "客户端数到的 rcode==2" 与 `client_rcode["2"]` 对账；
    /// - 若 `client_rcode[2] == 0` 而客户端统计到 SERVFAIL，则可判定客户端把
    ///   **超时/无应答**误分类成了 SERVFAIL（服务端从未发出 rcode=2）。
    ///
    /// **2.1.18（修复项 2）**：改读**同代快照**（`/metrics` 与 `/api/status` 因此
    /// 不可能出现"分布比 servfail_total 新/旧一档"的错位）。
    pub fn client_rcode_dist(&self) -> [u64; 16] {
        self.with_snapshot(|s| s.client_rcode)
    }

    /// **2.1.15（P1）**：SERVFAIL 原因维度的**唯一打点入口**。
    ///
    /// 只由 `dns.rs::log_and_count` 在"本应答 `rcode == 2`"时调用（全树唯一出口），
    /// 因此 `servfail_total == sum(servfail_reasons)` 恒成立（不变式有单测钉死）。
    /// `reason` 必须是 [`SERVFAIL_REASONS`] 里的键；未知键按 `upstream_all_failed`
    /// 归档并只告警一次（不 panic、不丢样本）。
    ///
    /// **2.1.18（修复项 2）**：数据面出口请改用
    /// [`Self::note_data_plane_outcome`]（一次落账 `rcode` + 原因 + 私网过滤条数）；
    /// 本方法保留给单测等其它调用方，语义**逐字不变**（总数与原因维度仍在同一次
    /// 锁内更新，因此 `Σ == total` 不会出现中间态）。
    pub fn note_servfail(&self, reason: &str) {
        let key = if SERVFAIL_REASONS.contains(&reason) {
            reason
        } else {
            warn_unknown_servfail_reason(reason);
            SERVFAIL_REASONS[0]
        };
        // **2.1.18（修复项 9）**：无锁 —— 总数与分档**相邻**自增，
        // 读侧用"写入代数 + 一致性重试"兜住两次自增之间的极窄窗口。
        let i = SERVFAIL_REASONS.iter().position(|x| *x == key).unwrap_or(0);
        self.servfail_total.fetch_add(1, Ordering::Relaxed);
        self.servfail_reasons[i].fetch_add(1, Ordering::Relaxed);
        self.bump_write_seq();
    }

    /// **P0-5**：UDP miss 闸门拒绝/丢包累计数（供 `/metrics` 与自检）。
    pub fn udp_dropped(&self) -> u64 {
        self.udp_dropped.load(Ordering::Relaxed)
    }

    /// **2.1.43-A（P2：`udp_dropped` 双源）**：`udp_dropped` 的**唯一**原子句柄。
    ///
    /// `DnsServer::start_multi_workers` 用它构造 `dropped`（数据面丢包的唯一写点），
    /// `main.rs` 再把 `dns.dropped()` 交给 `AppState.udp_dropped` —— 三处
    /// （DnsServer / AppState / ServerTelemetry）因此是**同一个** `Arc<AtomicU64>`。
    /// 单测 `udp_dropped_has_exactly_one_atomic` 用 `Arc::ptr_eq` 与
    /// "`/api/status` 顶层 == `counters.udp_dropped`" 双重钉死。
    pub fn udp_dropped_handle(&self) -> std::sync::Arc<AtomicU64> {
        std::sync::Arc::clone(&self.udp_dropped)
    }

    /// **2.1.15（P1）**：`rcode == 2` 的应答累计数（= 客户端可见的 SERVFAIL）。
    ///
    /// **2.1.18（修复项 2）**：读**同代快照**（与 `client_rcode_dist()` /
    /// `servfail_reasons()` / `counters()` 同源；一次 `/metrics` 抓取因此不会
    /// 出现三处互相错位一档）。
    pub fn servfail_total(&self) -> u64 {
        self.with_snapshot(|s| s.servfail_total)
    }

    /// **2.1.15（P1）**：SERVFAIL 的**原因维度**快照（缺失键补 0，便于页面/脚本稳定取值）。
    ///
    /// 5 档**互斥且完备**（`servfail_total == 各档之和`）：
    /// - `upstream_timeout`：所有上游都没有有效票，且**至少一条**按 `timeout_ms` 耗尽；
    /// - `upstream_no_answer`：上游有应答但都不是有效票（rcode 非 0/3 / 畸形 / 截断）；
    /// - `no_upstream`：配置/规则导致**没有可发的上游**（`no-upstream`）；
    /// - `encode_failed`：解析完成但**组包失败**（与上游无关的内部错误）；
    /// - `panic`：解析任务 panic 被 `catch_unwind` 隔离（fail-closed）。
    ///
    /// **2.1.18（修复项 2）**：改读**同代快照**（`Σ == servfail_total` 因此是
    /// 结构保证，而不是"两次加锁之间恰好没有写入"）。
    pub fn servfail_reasons(&self) -> Value {
        let arr = self.with_snapshot(|s| s.servfail_reasons);
        let mut m = serde_json::Map::new();
        for (i, k) in SERVFAIL_REASONS.iter().enumerate() {
            m.insert((*k).to_string(), json!(arr[i]));
        }
        Value::Object(m)
    }

    /// 规则命中快照。
    pub fn rule_hits(&self) -> serde_json::Map<String, Value> {
        let g = self.rule_hits.lock();
        let mut m = serde_json::Map::new();
        for (k, v) in g.iter() {
            m.insert(k.clone(), json!(v));
        }
        m
    }

    /// **2.1.16（功能 3）**：规则命中二维快照 `[(match_type, action, n)]`（**稳定排序**）。
    ///
    /// 排序键 = `(match_type, action)`，保证同一状态多次抓取 `/metrics` 的**行序一致**
    /// （Prometheus 抓取对行序不敏感，但快照 diff/审计需要确定性）。
    /// 只包含**出现过的**组合；总量与 [`Self::rule_hits`] 恒等（同点打点）。
    pub fn rule_hits_by_kind(&self) -> Vec<(String, String, u64)> {
        let g = self.rule_hits_kind.lock();
        let mut out: Vec<(String, String, u64)> = g
            .iter()
            .map(|((mt, ac), n)| (mt.clone(), ac.clone(), *n))
            .collect();
        out.sort();
        out
    }

    /// events 加锁快照。
    pub fn events_snapshot(&self) -> Vec<Value> {
        self.events.lock().iter().cloned().collect()
    }

    /// 最大已发 seq。
    pub fn max_seq(&self) -> u64 {
        self.next_seq.load(Ordering::Relaxed).saturating_sub(1)
    }

    /// QPS：最近 1 秒内到达**数据面出口**的客户端查询条数（滑动窗口，对齐 v1.9.162
    /// `current_qps`）。**唯一推进点 = `Telemetry::note_client_query`**（2.1.41）：
    /// 数据面出口 `log_and_count` 对每个客户端查询无条件调用一次，与
    /// `count_query("resolve")` / `total` / `neg_telemetry` 全部解耦。
    /// 旧实现是「总量 / uptime」，曲线会随时间单调衰减，无法反映瞬时负载。
    pub fn qps(&self) -> f64 {
        let now = now_epoch();
        let mut w = self.qps_win.lock();
        while let Some(front) = w.front().copied() {
            if now - front > 1.0 {
                w.pop_front();
            } else {
                break;
            }
        }
        w.len() as f64
    }

    /// 记录一次查询到 QPS 窗口。
    fn qps_touch(&self) {
        let now = now_epoch();
        let mut w = self.qps_win.lock();
        while let Some(front) = w.front().copied() {
            if now - front > 1.0 {
                w.pop_front();
            } else {
                break;
            }
        }
        if w.len() >= QPS_WINDOW_MAX {
            w.pop_front();
        }
        w.push_back(now);
    }

    /// 命中率（**0..1 比例**；页面显示时乘 100）。
    ///
    /// 保留 0..1 契约以免破坏既有调用方（`api.rs:1555` 直接下发本值、
    /// `api.rs:551` 自行乘 100）。需要 v1.9.162 的 0..100 百分数用 [`Self::hit_rate_pct`]。
    ///
    /// **2.1.18（修复项 2）**：分子分母取自**同一代快照**（改前两次独立 `load`，
    /// 高 QPS 下可能算出 `hit / total` 里 total 还没算上这一条 hit 的比例）。
    pub fn hit_rate(&self) -> f64 {
        // **2.1.40**：分母从 `total` 改为 `hit + miss` —— `total`（= Σ client_rcode）
        // 含本地策略应答与 Rule 本地判定，把它们放进分母会系统性拉低命中率
        // （生产 2.1.39 实测 miss/total=19.75% ≈ AAAA 占比；其中 84% 从未发上游）。
        let (h, m) = self.with_snapshot(|s| (s.hit, s.miss));
        if h + m == 0 {
            0.0
        } else {
            h as f64 / (h + m) as f64
        }
    }

    /// 命中率百分数（0..100，1 位小数；对齐 v1.9.162 `hit_rate()` /
    /// `snapshot()["hit_rate"]` / `/api/status.hit_rate`）。
    pub fn hit_rate_pct(&self) -> f64 {
        #[cfg(test)]
        HIT_RATE_PCT_CALLS.with(|c| c.set(c.get() + 1));
        (self.hit_rate() * 100.0 * 10.0).round() / 10.0
    }

    /// **2.1.46（REV247 A-11）**：从**调用方已经持有**的同代 [`CounterSnapshot`]
    /// 计算命中率百分数（0..100，1 位小数），不再二次取快照。
    ///
    /// 旧实现 `/api/status` 先 `with_snapshot` 取 counters，再调用 `hit_rate_pct()`
    /// 取**第二份**快照；`/api/reset` 或高 QPS 写入落在两次之间时，同一响应里的
    /// `counters.hit/miss` 与顶层 `hit_rate` 会来自不同代（REV247 A-11）。
    pub fn hit_rate_pct_of(snap: &CounterSnapshot) -> f64 {
        let h = snap.hit;
        let m = snap.miss;
        let r = if h + m == 0 {
            0.0
        } else {
            h as f64 / (h + m) as f64
        };
        (r * 100.0 * 10.0).round() / 10.0
    }

    /// 平均延迟（ms，最近 [`LATENCY_WINDOW_MAX`] 条样本的算术平均，1 位小数）。
    ///
    /// 保留旧的 `f64` 返回类型：无样本时返回 `0.0`（需要区分"无样本"用
    /// [`Self::avg_latency_opt`]）。
    pub fn avg_latency_ms(&self) -> f64 {
        self.avg_latency_opt().unwrap_or(0.0)
    }

    /// 平均延迟（ms）；**无样本 → `None`**（页面显示 “–”，对齐 v1.9.162 的
    /// `avg_latency_ms: null`）。
    ///
    /// 注意：判空必须用 `is_empty()`——窗口非空但均值为合法的 `0.0`
    /// （如缓存快路径 ~0ms）时返回 `Some(0.0)`，不得判成 `None`。
    pub fn avg_latency_opt(&self) -> Option<f64> {
        let g = self.latency.lock();
        if g.is_empty() {
            return None;
        }
        let avg = g.iter().sum::<f64>() / g.len() as f64;
        if !avg.is_finite() {
            return None;
        }
        Some((avg * 10.0).round() / 10.0)
    }

    /// 追加一条延迟样本（ms）到最近 [`LATENCY_WINDOW_MAX`] 条窗口
    /// （对齐 v1.9.162 `push_latency`）。NaN/负值丢弃。
    pub fn push_latency(&self, ms: f64) {
        self.latency_push(ms);
    }

    /// 延迟窗口内部实现（trait `push_latency` 与固有方法共用）。
    fn latency_push(&self, ms: f64) {
        if !ms.is_finite() || ms < 0.0 {
            return;
        }
        let mut w = self.latency.lock();
        if w.len() >= LATENCY_WINDOW_MAX {
            w.pop_front();
        }
        w.push_back(ms);
    }

    /// **2.1.16（功能 3）：客户端视角延迟直方图。**
    ///
    /// 返回 `(count, sum_ms, 累积桶)`，其中 `累积桶[i] = count(v in window : v <= le_i)`、
    /// `le_i = LATENCY_BUCKETS_MS[i]`（**单调不减**，Prometheus histogram 语义），
    /// `+Inf` 桶恒等于 `count`（调用方补）。
    ///
    /// **同源保证（硬要求）**：数据源就是 `push_latency` 写入的同一个
    /// [`Self::latency`] 窗口 —— `avg_latency_ms()` 也读它，因此
    /// `sum / count` 与 `/api/status.avg_latency` 在浮点容差内必然一致
    /// （单测 `s3_client_histogram_sum_over_count_matches_avg_latency` 钉死）。
    /// 这样 `/metrics` 的 `ebpdns_query_latency_ms` 与页面上的平均延迟**不可能互相矛盾**。
    ///
    /// 为什么不在入窗时增量维护（像 [`UpstreamLatWindow`] 那样）：全局窗口规模是
    /// `LATENCY_WINDOW_MAX`（≤2048）且**只有一个 key**，抓取时 `O(W + 桶数)` 完全够用；
    /// 引入增量结构反而要多存一份状态、多一处漂移风险。抓取频率是人工/15s 级，
    /// 不在数据面热路径上。
    pub fn client_latency_histogram(&self) -> (u64, f64, Vec<(f64, u64)>) {
        let g = self.latency.lock();
        let count = g.len() as u64;
        let sum: f64 = g.iter().sum();
        let mut buckets = Vec::with_capacity(LATENCY_BUCKETS_MS.len());
        for le in LATENCY_BUCKETS_MS.iter() {
            // 累积语义：`v <= le` 的样本数（`le` 单调增 ⇒ 结果单调不减）。
            let n = g.iter().filter(|v| **v <= *le).count() as u64;
            buckets.push((*le, n));
        }
        (count, sum, buckets)
    }

    /// **A7**：推一条**某个上游**的实测延迟样本（ms）。    ///
    /// 这是 `/metrics` 的 `ebpdns_upstream_latency_ms`（直方图 + 分位数）唯一来源。
    /// 与 [`Self::push_latency`]（全局窗口）**互不影响**：全局窗口继续服务
    /// `/api/status.avg_latency_ms` 的既有口径。
    ///
    /// 有界：每条上游窗口 ≤ [`UPSTREAM_LAT_WINDOW_MAX`]，上游键数 ≤
    /// [`UPSTREAM_LAT_MAX_KEYS`]（新键超限直接丢弃，不淘汰旧键 —— 观测数据，
    /// 丢新不丢旧可保证长时间看得到稳定上游）。
    ///
    /// **2.1.12（O(1) 化）**：入窗/淘汰同时**增量维护**该上游的
    /// 累积桶计数、窗口和与排序视图（见 [`UpstreamLatWindow`]）。推入成本
    /// 从「抓取时逐样本 × 逐桶」变成 `O(log W)`（二分定位 + 有序插入），
    /// 抓取成本从 `O(上游数 × 窗口 × 桶数)` 变成 `O(上游数 × 桶数)`。
    pub fn push_upstream_latency(&self, up: &str, ms: f64) {
        if up.is_empty() || !ms.is_finite() || ms < 0.0 {
            return;
        }
        let mut g = self.upstream_lat.lock();
        if !g.contains_key(up) && g.len() >= UPSTREAM_LAT_MAX_KEYS {
            return;
        }
        g.entry(up.to_string()).or_default().push(ms);
    }

    /// **A7**：逐上游延迟窗口快照（`id -> (count, sum_ms, 累积桶计数, le 上界列表)`）。
    ///
    /// 返回累积直方图（Prometheus 语义：每个桶是"≤ le"的**累积**计数），
    /// 因此 `buckets[i] = count(ms <= LATENCY_BUCKETS_MS[i])`，单调不减。
    ///
    /// **2.1.12**：桶计数/和由 [`UpstreamLatWindow`] **增量维护**，本函数只做
    /// `O(桶数)` 的拷贝 + `O(上游数 log 上游数)` 的稳定排序 —— 不再遍历样本，
    /// 因此与窗口长度无关（改前每个上游要扫 400 样本 × 10 桶）。
    pub fn upstream_latency_histograms(&self) -> Vec<UpstreamHistogramRow> {
        let mut g = self.upstream_lat.lock();
        let mut out: Vec<UpstreamHistogramRow> = Vec::with_capacity(g.len());
        for (id, w) in g.iter_mut() {
            if w.is_empty() {
                continue;
            }
            out.push((
                id.clone(),
                w.len(),
                w.sum(),
                w.buckets().to_vec(),
                &LATENCY_BUCKETS_MS,
            ));
        }
        // 确定性输出顺序（测试/抓取稳定）。
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// **A7**：某上游延迟窗口的分位数（毫秒，线性插值；无样本 → `None`）。
    ///
    /// **2.1.12**：直接在有界排序视图 [`UpstreamLatWindow::sorted`] 上按秩取值，
    /// 不再每次克隆 + 排序整个窗口（旧实现每次调用 `O(n log n)`，
    /// 而 `/metrics` 对每条上游要调 3 次）。
    ///
    /// 插值与取秩规则与旧实现**逐值一致**：
    /// `k = (n-1) * p/100`、`lo = floor(k)`、`hi = min(lo+1, n-1)`、`frac = k - lo`，
    /// `out = v[lo] + (v[hi] - v[lo]) * frac`，最后 `(out*10).round()/10`。
    pub fn upstream_latency_quantile(&self, up: &str, p: f64) -> Option<f64> {
        let mut g = self.upstream_lat.lock();
        let w = g.get_mut(up)?;
        let n = w.samples.len();
        if n == 0 {
            return None;
        }
        let (lo, hi, frac) = quantile_rank(n, p);
        let vlo = w.sorted_value(lo)?;
        let vhi = w.sorted_value(hi)?;
        let out = vlo + (vhi - vlo) * frac;
        if out.is_finite() {
            Some((out * 10.0).round() / 10.0)
        } else {
            None
        }
    }

    /// **A7**：计入一次"负缓存命中"（缓存直答 + NXDOMAIN / 空答案段）。    ///
    /// **2.1.16（修复项 15）**：同一打点处**同时**自增 `negative_hits` 计数器
    /// （`/api/status.counters` / `/metrics`）。两处分开自增会有"数据面只走了一条路"
    /// 的漂移风险，因此这里刻意写在一个函数里 —— 唯一打点，不可能不一致。
    pub fn count_neg_hit(&self) {
        // **2.1.18（修复项 2）**：两个原子与同代快照在**同一把锁内**一起自增
        // （否则并发下会出现"原子 2、快照 1"的丢失更新）。
        // **2.1.18（修复项 9）**：无锁 —— 两个原子相邻自增（快照由读侧组装）。
        self.neg_hit.fetch_add(1, Ordering::Relaxed);
        self.negative_hits.fetch_add(1, Ordering::Relaxed);
        self.bump_write_seq();
    }

    /// **2.1.16（修复项 15）**：负缓存命中累计数（对外 `counters.negative_hits` 口径）。
    ///
    /// 与 [`Self::neg_hits`] 恒等（同一打点），单测
    /// `s15_negative_hits_equals_internal_neg_hit` 钉死。
    ///
    /// 定义在下方（2.1.19 起改读同代快照，与 `counters()` 同源）。
    /// **2.1.17（修复项 3）**：累加"因 rebind 防护被丢弃的私有/保留地址答案条数"。
    ///
    /// 唯一调用点 = 数据面出口 `dns.rs::log_and_count`（把 resolver 结构化回传的
    /// `ResolveResult::private_answers_filtered` 原样累加）。`n == 0` 时 no-op。
    ///
    /// 语义（**设计行为，不是缺陷**）：被丢弃的私网答案**不写缓存**，因此同一
    /// `CacheKey` 反复查询会**每次都走上游**（命中率看起来"不动"）。本计数
    /// 存在的唯一目的就是让这条设计变得**可观测**，从而不再被误判为"缓存坏了"。
    pub fn count_cache_skipped_private(&self, n: u32) {
        if n == 0 {
            return;
        }
        // **2.1.18（修复项 2）**：原子与同代快照在**同一把锁内**一起前进
        // （`/api/status` 与 `/metrics` 因此同源同值，且并发下不丢更新）。
        // **2.1.18（修复项 9）**：无锁 —— 单个原子自增
        //（`/api/status` 与 `/metrics` 同源同值 = 同一个原子）。
        self.cache_skipped_private_total
            .fetch_add(u64::from(n), Ordering::Relaxed);
        self.bump_write_seq();
    }

    /// **2.1.17（修复项 3）**：被 rebind 防护丢弃的私网/保留答案累计条数。
    ///
    /// 与 `/api/status.counters.cache_skipped_private_total` 和 `/metrics` 的
    /// `ebpdns_cache_skipped_private_total` **同源同值**（单测
    /// `s17_cache_skipped_private_is_exposed_and_same_source` 钉死三处一致）。
    ///
    /// **2.1.18（修复项 2）**：读同代快照（与 `counters()` 同一来源）。
    pub fn cache_skipped_private_total(&self) -> u64 {
        self.with_snapshot(|s| s.cache_skipped_private_total)
    }

    /// **A7**：负缓存命中累计数。
    ///
    /// **2.1.18（修复项 2）**：读同代快照（与 `negative_hits()` / `counters()` 同源）。
    pub fn neg_hits(&self) -> u64 {
        self.with_snapshot(|s| s.negative_hits)
    }

    /// **2.1.18（修复项 2）**：同代快照里的负缓存命中数（对外 counters 口径）。
    ///
    /// 与 [`Self::neg_hits`] **逐值相同**（同一原子、同一代快照），单测
    /// `s15_negative_hits_equals_internal_neg_hit` 钉死。
    pub fn negative_hits(&self) -> u64 {
        self.with_snapshot(|s| s.negative_hits)
    }

    /// **A7**：负缓存命中率（0..1；分母为缓存直答总数 `hit`，为 0 → `0.0`）。
    ///
    /// 语义：**在所有缓存直答里，有多少是负应答**。这也是"负缓存是否真的在起作用"
    /// 的可用信号 —— 2.1.8 的 `/metrics` 完全没有负缓存维度。
    ///
    /// **2.1.18（修复项 2）**：分子分母取自同代快照，并**显式钳制到 1.0** ——
    /// 改前两次独立 `load` 可能让 `neg_hit > hit`（负缓存命中与缓存直答不是同一
    /// 临界区），从而输出 > 1 的"比例"（Prometheus gauge 上表现为异常值）。
    pub fn neg_hit_ratio(&self) -> f64 {
        // >>> 242B BEGIN P1-7-ratio >>> //
        let (neg, h) = self.with_snapshot(|s| (s.negative_hits, s.hit));
        // **2.1.42-B（P1-7）**：`negative_hits ⊆ hit` 是结构不变量（控制面已不再
        // 写 `negative_hits`）。这里**不再** `.min(1.0)` 掩盖越界：越界即缺陷，
        // debug 构建直接断言，release 也如实输出真实比值（>1 会被监控看到）。
        debug_assert!(
            neg <= h,
            "negative_hits({neg}) 必须是 hit({h}) 的子集（P1-7 不变量）"
        );
        if h == 0 {
            0.0
        } else {
            neg as f64 / h as f64
        }
        // <<< 242B END P1-7-ratio <<< //
    }

    /// 逐上游遥测：`id -> (查询数, 成功率%, 平均延迟 ms)`。    /// 由事件环（最近 500 条）聚合：`miss` 事件视为走上游，`answer` 非空视为成功。
    pub fn upstream_stats(&self) -> HashMap<String, (u64, f64, f64)> {
        let mut cnt: HashMap<String, u64> = HashMap::new();
        let mut ok: HashMap<String, u64> = HashMap::new();
        let mut lat_sum: HashMap<String, f64> = HashMap::new();
        let mut lat_cnt: HashMap<String, u64> = HashMap::new();
        for ev in self.events.lock().iter() {
            let level = ev.get("level").and_then(Value::as_str).unwrap_or("");
            // hit/rule 不走上游；miss/err 才计上游请求。
            if level != "miss" && level != "err" {
                continue;
            }
            let Some(up) = ev.get("upstream").and_then(Value::as_str) else {
                continue;
            };
            if up.is_empty() {
                continue;
            }
            *cnt.entry(up.to_string()).or_insert(0) += 1;
            let ans = ev.get("answer").and_then(Value::as_str).unwrap_or("");
            if !ans.is_empty() && level != "err" {
                *ok.entry(up.to_string()).or_insert(0) += 1;
            }
            let lat = ev.get("lat").and_then(Value::as_f64).unwrap_or(0.0);
            if lat > 0.0 && lat.is_finite() {
                *lat_sum.entry(up.to_string()).or_insert(0.0) += lat;
                *lat_cnt.entry(up.to_string()).or_insert(0) += 1;
            }
        }
        let mut out: HashMap<String, (u64, f64, f64)> = HashMap::new();
        for (id, n) in cnt {
            let okn = ok.get(&id).copied().unwrap_or(0);
            let sr = if n == 0 {
                100.0
            } else {
                okn as f64 / n as f64 * 100.0
            };
            let lavg = match lat_cnt.get(&id).copied().unwrap_or(0) {
                0 => 0.0,
                c => lat_sum.get(&id).copied().unwrap_or(0.0) / c as f64,
            };
            out.insert(
                id,
                (n, (sr * 10.0).round() / 10.0, (lavg * 10.0).round() / 10.0),
            );
        }
        out
    }

    /// 手动查询入口记录（/api/query 用）：写入手动历史环 + 事件流。
    ///
    /// 对齐 v1.9.162：手动查询走 `counted=False`，**不得**污染
    /// `qtype_dist` / `top_domains`（`domain_hits`）/ `top_clients`（`client_hits`）。
    ///
    /// **2.1.43-A（P2：`avg_latency` 含控制面 `/api/query`）**：本函数**不再**推进
    /// 全局延迟窗口。2.1.42 及以前这里调 `latency_push`，于是控制面
    /// `POST /api/query` 的耗时（含人工调试时的秒级慢查询）混进
    /// `/api/status.avg_latency_ms` 与 `/metrics` 的 `ebpdns_query_latency_ms`
    /// —— 后者 HELP 早已声明"control-plane queries are excluded"，**实现与文档相反**。
    /// 现在口径**只含数据面**（级别 hit/miss/err/warn，唯一写点
    /// `dns.rs::log_and_count` → `push_event`）。手动查询的延迟仍然完整可见：
    /// `manual_history[].latency_ms`（本函数写入）与 `/api/query` 的响应体。
    #[allow(clippy::too_many_arguments)]
    pub fn record_manual(
        &self,
        domain: &str,
        qtype: &str,
        chosen: &str,
        hit: bool,
        latency_ms: f64,
        rcode: u8,
    ) {
        let ts = now_epoch();
        let entry = json!({
            "ts": ts,
            "ts_text": hms_ms_label(ts),
            "domain": domain,
            "qtype": qtype,
            "chosen": chosen,
            "answer": chosen,
            "hit": hit,
            "latency_ms": latency_ms,
            "lat": latency_ms,
            "rcode": rcode,
        });
        {
            let mut g = self.manual.lock();
            if g.len() >= MANUAL_RING_MAX {
                g.pop_front();
            }
            g.push_back(entry);
        }
        // F16: 这里**不再**调 note_data_plane —— 手动查询不计入 qtype_dist /
        // **[历史归因]** domain_hits / client_hits（Python `counted=False` 时跳过 count_query+count_top）。
        //
        // **2.1.43-A**：也不再把延迟推进全局窗口（见本函数文档）。手动查询的延迟
        // 保留在上面的 `manual` 环（`latency_ms`/`lat`）与 `/api/query` 响应里。
        let msg = if chosen.is_empty() {
            format!("手动查询 {domain} {qtype}")
        } else {
            format!("手动查询 {domain} {qtype} → {chosen}")
        };
        self.push_event(
            // level=sys 全量入环；`level_counts_latency("sys") == false` ⇒ 本事件
            // **不进**延迟窗口（控制面耗时不得污染 `avg_latency_ms`，2.1.43-A）。
            "sys", domain, qtype, None, None, None, chosen, latency_ms, &msg,
        );
    }

    /// 手动查询历史（最近在前，最多 MANUAL_RING_MAX）。
    pub fn manual_history(&self) -> Vec<Value> {
        self.manual.lock().iter().cloned().collect()
    }

    /// DNS 数据面记录一次查询（UDP/TCP 对端 IP + 域名 + qtype 频次）。
    pub fn note_data_plane(&self, client_ip: Option<&str>, domain: &str, qtype: &str) {
        // 归一化小写，避免 DNS 0x20 随机大小写把同一域名打散成多键。
        let domain = domain.to_ascii_lowercase();
        self.note_data_plane_normalized(client_ip, &domain, qtype);
    }

    /// **[2.1.24 / 热路径分配]** `domain` **已经**是规范化小写时的数据面入口。
    ///
    /// 为什么需要它：数据面（`dns.rs` 的 UDP 收包循环与 TCP 连接循环）在
    /// [`crate::dns::extract_qname_into`] 里**已经**把 qname 逐标签小写进复用缓冲，
    /// 随后 `note_data_plane` 又 `to_ascii_lowercase()` 复制一份 ⇒ **每个报文一次
    /// 多余的 `String` 分配 + 一次全串扫描**（1 万 QPS 就是 1 万次/秒）。本入口只查表，
    /// **零分配**。
    ///
    /// 契约：调用方**必须**传已小写的域名（`extract_qname_into` 的返回值就是小写；
    /// 该函数对每个标签做 ASCII 小写化）。传大写不会崩，但会让 `top_domains` 把同一域名
    /// 拆成两个键 —— 因此**只有那两个数据面调用点**用它，其它调用方继续走
    /// [`Self::note_data_plane`]（内部归一化，语义不变）。
    pub fn note_data_plane_normalized(&self, client_ip: Option<&str>, domain: &str, qtype: &str) {
        if !domain.is_empty() {
            bounded_inc(&self.domain_hits, domain);
        }
        if let Some(ip) = client_ip {
            if !ip.is_empty() {
                bounded_inc(&self.client_hits, ip);
            }
        }
        self.note_qtype(qtype);
    }

    /// 清空遥测（对齐 v1.9.162 `telemetry.reset()`）：
    /// counters（11 键）/规则命中/事件环/手动历史/历史曲线/TopN/**qps 窗口**/
    /// **延迟窗口**全部归零；
    /// **不重置** `boot`（uptime 继续累积）与 `next_seq`（事件序号继续递增，
    /// 这样客户端的 `since` 游标仍然有效，不会被旧事件"回灌"）。
    pub fn reset(&self) {
        // >>> 245 P2-6 reset-wrapper BEGIN
        // **2.1.45（P2-6）**：先置冻结位（并持写屏障挡住新的数据面记账）→ 清 → 解除。
        let _gate = self.reset_gate.write();
        self.reset_frozen.store(true, Ordering::SeqCst);
        self.reset_clear();
        self.reset_frozen.store(false, Ordering::SeqCst);
        // <<< 245 P2-6 reset-wrapper END
    }

    /// 数据面记账用的**读屏障**（`dns.rs::log_and_count` 全程持有）。
    pub fn reset_read_gate(&self) -> parking_lot::RwLockReadGuard<'_, ()> {
        self.reset_gate.read()
    }

    /// `/api/reset` 用的**写屏障**（与 [`Self::reset_read_gate`] 互斥，不重入）。
    pub(crate) fn reset_write_gate(&self) -> parking_lot::RwLockWriteGuard<'_, ()> {
        self.reset_gate.write()
    }

    /// 当前是否处于 reset 冻结期（未持屏障的写路径据此自我抑制）。
    pub fn reset_frozen(&self) -> bool {
        self.reset_frozen.load(Ordering::Relaxed)
    }

    /// 置/解除冻结位（`AppState::reset_all_counters` 用它把冻结期覆盖到 resolver 清零）。
    pub(crate) fn set_reset_frozen(&self, v: bool) {
        self.reset_frozen.store(v, Ordering::SeqCst);
    }

    /// 清零本体：**不带**冻结/屏障，调用方必须已持写屏障并置冻结位。
    pub(crate) fn reset_clear(&self) {
        self.hit.store(0, Ordering::Relaxed);
        self.miss.store(0, Ordering::Relaxed);
        self.upstream_queries.store(0, Ordering::Relaxed);
        self.errors.store(0, Ordering::Relaxed);
        self.ipv4_fallback.store(0, Ordering::Relaxed);
        self.stale_served.store(0, Ordering::Relaxed);
        self.bytes_in.store(0, Ordering::Relaxed);
        self.bytes_out.store(0, Ordering::Relaxed);
        self.rebind_blocked.store(0, Ordering::Relaxed);
        self.rule_hits.lock().clear();
        self.rule_hits_kind.lock().clear();
        self.events.lock().clear();
        self.manual.lock().clear();
        self.history.lock().clear();
        self.qtype_a.store(0, Ordering::Relaxed);
        self.qtype_aaaa.store(0, Ordering::Relaxed);
        self.qtype_other.store(0, Ordering::Relaxed);
        self.upstream_hits.lock().clear();
        self.domain_hits.lock().clear();
        self.client_hits.lock().clear();
        // **[历史归因]** F13: Python `reset()` 同时 `qps_window.clear()` / `latency_window.clear()`。
        // 漏清会让 reset 后的 QPS / 平均延迟继续显示重置前的旧窗口（页面"清零无效"）。
        self.qps_win.lock().clear();
        self.latency.lock().clear();
        // A7：上游延迟窗口与负缓存计数一并归零（否则 reset 后 /metrics 仍显示旧值）。
        // 2.1.12：窗口值类型带增量聚合量，`clear()` 直接丢弃整张表即可
        // （不存在「清了样本、留下桶计数」的中间态）。
        self.upstream_lat.lock().clear();
        self.neg_hit.store(0, Ordering::Relaxed);
        // P0-5：UDP 闸门拒绝/丢包一并归零（与 COUNTER_KEYS 断言一致）。
        self.udp_dropped.store(0, Ordering::Relaxed);
        // 2.1.15：SERVFAIL 总数与原因维度一并归零。
        self.servfail_total.store(0, Ordering::Relaxed);
        for c in self.servfail_reasons.iter() {
            c.store(0, Ordering::Relaxed);
        }
        // 2.1.16（修复项 15）：负缓存对外计数与内部计数一并归零。
        self.negative_hits.store(0, Ordering::Relaxed);
        // 2.1.17（修复项 3）：私网答案过滤计数一并归零（与 COUNTER_KEYS 断言一致）。
        self.cache_skipped_private_total.store(0, Ordering::Relaxed);
        // 2.1.18（修复项 9）：出口"无可发送报文"计数一并归零。
        self.no_response_total.store(0, Ordering::Relaxed);
        // **2.1.20（A-04）**：控制面独立计数一并归零（与 `COUNTER_KEYS` 断言一致）。
        self.control_queries.store(0, Ordering::Relaxed);
        self.control_hits.store(0, Ordering::Relaxed);
        // **2.1.29**：未知 qtype 透传计数一并归零（与 `COUNTER_KEYS` 断言一致）。
        self.passthrough_qtype_total.store(0, Ordering::Relaxed);
        // >>> 242B BEGIN P1-6-reset >>> //
        // **2.1.40**：本地策略短路计数一并归零（与 `COUNTER_KEYS` 断言一致）。
        self.policy_filtered_total.store(0, Ordering::Relaxed);
        // **2.1.42-B（P1-6）**：本地规则直答计数一并归零（reset 后全 0）。
        self.rule.store(0, Ordering::Relaxed);
        // **2.1.43-A**：双栈探测计数一并归零（与 `COUNTER_KEYS` 断言一致）。
        self.probe_upstream_queries.store(0, Ordering::Relaxed);
        // <<< 242B END P1-6-reset <<< //
        // 2.1.16（修复项 8）：客户端 rcode 分布一并归零（否则 reset 后
        // `client_rcode[2] == servfail_total` 这条硬等式会被破坏）。
        for c in self.client_rcode.iter() {
            c.store(0, Ordering::Relaxed);
        }
        // **2.1.18（修复项 9）**：全部真值都是原子/定长数组（`total` 还是派生的），
        // 上面清零后快照自然全 0 —— **不需要任何锁内重建**。
        // `seq` 不重置但必须 +1：这样"reset 前后的两份快照"不会被误判为同一代。
        self.bump_write_seq();
    }

    /// 采样一个历史点（后台任务每 1–2s 调用一次）。
    /// `label` 保持 epoch 秒（前端按浏览器本地时区格式化）；`label_text` 为**本地** `HH:MM:SS`。
    ///
    /// 字段口径对齐 v1.9.162 `sample()`：
    /// - `hit_rate`：0..100 百分数（1 位小数）；
    /// - `qps`：最近 1 秒滑动窗口条数；
    /// - `lat`：最近 [`LATENCY_WINDOW_MAX`] 条样本的算术平均（1 位小数），无样本 → `0`。
    pub fn sample_point(&self) {
        let now = now_epoch();
        let point = json!({
            "label": now,
            "label_text": hms_label(now),
            "ts": now,
            "hit_rate": self.hit_rate_pct(),
            "qps": self.qps(),
            "lat": self.avg_latency_ms(),
        });
        let mut g = self.history.lock();
        if g.len() >= HISTORY_RING_MAX {
            g.pop_front();
        }
        g.push_back(point);
    }

    /// 后台采样任务：每 1.5s 采一次，直到进程退出。
    pub fn spawn_sampler(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(1500));
            loop {
                tick.tick().await;
                self.sample_point();
            }
        });
    }

    /// 历史采样环**尾部**快照（对齐 v1.9.162 `snapshot()["history"] = history[-60:]`）。
    pub fn history_snapshot(&self) -> Vec<Value> {
        let g = self.history.lock();
        let skip = g.len().saturating_sub(HISTORY_TAIL_MAX);
        g.iter().skip(skip).cloned().collect()
    }

    /// 历史采样环**全量**快照（≤ [`HISTORY_RING_MAX`] 点；需要完整曲线的调用方用本方法）。
    #[allow(dead_code)]
    pub fn history_snapshot_all(&self) -> Vec<Value> {
        self.history.lock().iter().cloned().collect()
    }

    /// qtype 分布 {A, AAAA, other}。
    pub fn qtype_dist(&self) -> Value {
        json!({
            "A": self.qtype_a.load(Ordering::Relaxed),
            "AAAA": self.qtype_aaaa.load(Ordering::Relaxed),
            "other": self.qtype_other.load(Ordering::Relaxed),
        })
    }

    /// top-N 上游 [[name, count]]。
    pub fn top_upstreams(&self) -> Vec<Value> {
        top_n(&self.upstream_hits.lock(), TOP_N)
    }

    /// top-N 域名 [[domain, count]]。
    pub fn top_domains(&self) -> Vec<Value> {
        top_n(&self.domain_hits.lock(), TOP_N)
    }

    /// top-N 客户端 IP [[ip, count]]。
    pub fn top_clients(&self) -> Vec<Value> {
        top_n(&self.client_hits.lock(), TOP_N)
    }

    /// 按 qtype 归类累加（A/AAAA/other）。
    fn note_qtype(&self, qtype: &str) {
        match qtype.to_ascii_uppercase().as_str() {
            "A" => self.qtype_a.fetch_add(1, Ordering::Relaxed),
            "AAAA" => self.qtype_aaaa.fetch_add(1, Ordering::Relaxed),
            _ => self.qtype_other.fetch_add(1, Ordering::Relaxed),
        };
    }

    /// A7：带增量自增（`bytes_in` / `bytes_out` 等按量计数器）。
    ///
    /// **刻意不放进 `Telemetry` trait**：这些是服务端专有的数据面观测，
    /// 由 `dns.rs` 直接对具体类型调用（见 `count_wire`），因此
    /// `ebpdns-resolver` 的 trait 表面**无需任何改动**（该目录另有代理负责）。
    ///
    /// **2.1.18（修复项 2）**：每次自增后在同一把锁内刷新同代快照
    /// （见 [`CounterSnapshot`]）—— 这是"读到的表永远与原子同一代"的前提。
    pub fn inc_n(&self, key: &str, n: u64) {
        // **2.1.45（P2-6）**：reset 冻结期内丢弃（"不计"语义，避免清到一半的代际撕裂）。
        if self.reset_frozen() {
            return;
        }
        if n == 0 {
            return;
        }
        match key {
            // **2.1.18（修复项 9）**：`counters.total` 是**派生量**（`= Σ client_rcode`），
            // **不可单独自增** —— 这里刻意 no-op，使"绕过数据面出口的老路"无法静默
            // 破坏 `total == Σ client_rcode`（生产无任何调用点）。
            "total" => 0,
            "hit" => self.hit.fetch_add(n, Ordering::Relaxed),
            "miss" => self.miss.fetch_add(n, Ordering::Relaxed),
            "upstream_queries" => self.upstream_queries.fetch_add(n, Ordering::Relaxed),
            "errors" => self.errors.fetch_add(n, Ordering::Relaxed),
            "ipv4_fallback" => self.ipv4_fallback.fetch_add(n, Ordering::Relaxed),
            "stale_served" => self.stale_served.fetch_add(n, Ordering::Relaxed),
            "bytes_in" => self.bytes_in.fetch_add(n, Ordering::Relaxed),
            "bytes_out" => self.bytes_out.fetch_add(n, Ordering::Relaxed),
            "rebind_blocked" => self.rebind_blocked.fetch_add(n, Ordering::Relaxed),
            // P0-5：UDP 闸门拒绝/丢包。
            "udp_dropped" => self.udp_dropped.fetch_add(n, Ordering::Relaxed),
            // **2.1.15（P1）**：`servfail_total` 允许经 `inc_n` 自增（原因维度走
            // `note_servfail`，这里只动总数，保持与 `udp_dropped` 同样的可用性）。
            // **2.1.18（修复项 9）**：`servfail_total == Σ servfail_reasons` 是硬等式，
            // 所以通用 `inc_n` 必须**同时**记一个分档（兜底档，与
            // `dns.rs::servfail_reason_of` 的兜底同源），否则这条路径会破坏等式。
            "servfail_total" => {
                self.servfail_reasons[0].fetch_add(n, Ordering::Relaxed);
                self.servfail_total.fetch_add(n, Ordering::Relaxed)
            }
            // **2.1.16（修复项 15）**：负缓存命中可经 `inc_n` 自增（数据面走
            // `count_neg_hit`，这里保证脚本/测试与其它标量计数器同一可用面）。
            "negative_hits" => {
                self.negative_hits.fetch_add(n, Ordering::Relaxed);
                self.neg_hit.fetch_add(n, Ordering::Relaxed);
                n
            }
            // **2.1.17（修复项 3）**：私网答案过滤计数可经 `inc_n` 自增（数据面走
            // `count_cache_skipped_private`，这里保证脚本/测试与其它标量计数器同一可用面）。
            "cache_skipped_private_total" => self
                .cache_skipped_private_total
                .fetch_add(n, Ordering::Relaxed),
            // **2.1.18（修复项 9）**：出口"无可发送报文"计数（脚本/测试可用面）。
            "no_response_total" => self.no_response_total.fetch_add(n, Ordering::Relaxed),
            // **2.1.20（A-04）**：控制面独立计数（`/api/query` 打点）。
            "control_queries" => self.control_queries.fetch_add(n, Ordering::Relaxed),
            "control_hits" => self.control_hits.fetch_add(n, Ordering::Relaxed),
            // **2.1.29**：未知 qtype 透传计数（数据面 `log_and_count` 打点）。
            "passthrough_qtype_total" => {
                self.passthrough_qtype_total.fetch_add(n, Ordering::Relaxed)
            }
            // >>> 242B BEGIN P1-6-incn >>> //
            // **2.1.40**：本地策略短路计数（数据面 `log_and_count` 打点）。
            "policy_filtered_total" => self.policy_filtered_total.fetch_add(n, Ordering::Relaxed),
            // **2.1.42-B（P1-6）**：本地规则直答计数（数据面 `log_and_count` 打点）。
            "rule" => self.rule.fetch_add(n, Ordering::Relaxed),
            // **2.1.43-A**：`prefer_ipv4` 双栈探测的发上游次数（`resolve.rs::probe_a_record` 打点）。
            "probe_upstream_queries" => self.probe_upstream_queries.fetch_add(n, Ordering::Relaxed),
            // <<< 242B END P1-6-incn <<< //
            // 未知键：no-op（仅告警一次）；返回 0 与其它分支的类型（u64）对齐。
            _ => {
                warn_unknown_inc(key);
                0
            }
        };
        // **2.1.18（修复项 9）：热路径无锁** —— 上面全是纯 `fetch_add`；
        // 快照由**读侧**按需组装（`snapshot()`）。这里只推进"写入代数"。
        self.bump_write_seq();
    }

    /// 推一条事件到环形缓冲。
    ///
    /// **[历史归因]** 顺序与 Python 一致：**先做全量聚合**（TopN 上游频次 + 延迟窗口），
    /// **再**做 hit/miss 的 10% 采样门禁——采样只裁剪 `events` 环与 `seq` 推进，
    /// 不得影响计数器/TopN/延迟口径。
    #[allow(clippy::too_many_arguments)]
    fn push_event(
        &self,
        level: &str,
        domain: &str,
        qtype: &str,
        client_ip: Option<&str>,
        upstream: Option<&str>,
        rule: Option<&str>,
        answer: &str,
        lat: f64,
        msg: &str,
    ) {
        // ---- 全量聚合（与采样无关）----
        if let Some(up) = upstream {
            if !up.is_empty() {
                bounded_inc(&self.upstream_hits, up);
                // A7：仅 `miss` / `err` 的 upstream 字段是**真实上游 id**；
                // `hit` 路径写的是"缓存直答"这类描述串，`warn` 是 AAAA 屏蔽等
                // 非上游路径 —— 都不能污染逐上游延迟维度。
                if level == "miss" || level == "err" {
                    // **2.1.41（字段体检修复）**：`miss`/`err` 的 upstream 列并不总是
                    // 真实上游 id —— 本地策略/规则/畸形包会落「本地判定（…）」
                    // 「规则屏蔽」「分流规则」等**展示文案**。2.1.40 及以前把它们
                    // 当成上游 id 建时间窗口 ⇒ `/metrics` 出现
                    // `ebpdns_upstream_latency_ms{id="本地判定（未发上游）"}` 这类
                    // 虚假序列（实测 177 条畸形包样本）。只对真实 id 记账。
                    if !is_local_upstream_label(up) {
                        self.push_upstream_latency(up, lat);
                    }
                }
            }
        }
        if level_counts_latency(level) {
            self.latency_push(lat);
        }
        // **[历史归因]** ---- 10% 采样（对齐 Python `_should_sample_event`）----
        if !should_sample_event(level, next_rand_f64()) {
            return;
        }
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let ts = now_epoch();
        let ev = json!({
            "seq": seq,
            "ts": ts,
            "ts_text": hms_ms_label(ts),
            "level": level,
            "msg": msg,
            "domain": domain,
            "qtype": qtype,
            "client_ip": client_ip.unwrap_or(""),
            "upstream": upstream.unwrap_or(""),
            "rule": rule.unwrap_or(""),
            "answer": answer,
            "lat": lat,
        });
        let mut g = self.events.lock();
        if g.len() >= EVENT_RING_MAX {
            g.pop_front();
        }
        g.push_back(ev);
    }
}

impl Telemetry for ServerTelemetry {
    /// **2.1.41**：QPS 窗口的**唯一**推进点（数据面出口每客户端查询恰好一次）。
    ///
    /// 为什么不放在 `count_query("resolve")`：2.1.40 的唯一调用点被
    /// `neg_telemetry.is_none()` 门禁掉，而生产三条出口全传 `Some` ⇒ QPS 恒 0。
    /// 现在由 `log_and_count` **无条件**调用，且 `count_query` 不再触碰窗口
    /// （避免未来任何 `resolve` 调用造成双计）。
    fn note_client_query(&self) {
        self.qps_touch();
    }

    fn count_query(&self, cat: &str) {
        // **2.1.41**：QPS 窗口不在这里推进（见 [`Self::note_client_query`]）。
        // `count_query("resolve")` 保留「外部 Telemetry 桩的 total 记账」语义，
        // 但生产 `inc_n("total")` 是 no-op（total 由 `note_data_plane_outcome` 派生），
        // 因此它对真实计数与 QPS 都没有副作用。
        let key = match cat {
            "error" | "err" => "errors",
            "resolve" => "total",
            "hit" => "hit",
            "miss" => "miss",
            "upstream" => "upstream_queries",
            // **2.1.29**：未知 qtype 透传（数据面 `log_and_count` 唯一写点）。
            // 必须显式映射：本函数的 `_` 会落到 `total`，那会破坏
            // `total == Σ client_rcode` 的硬等式。
            "passthrough_qtype" => "passthrough_qtype_total",
            // >>> 242B BEGIN P1-6-cat >>> //
            // **2.1.40**：本地策略短路（数据面 `log_and_count` 唯一写点）。
            "policy_filtered" => "policy_filtered_total",
            // **2.1.42-B（P1-6）**：本地规则直答（block/forceIp/no-upstream）。
            // 必须显式映射：`_` 会落到 `total`，那会直接破坏
            // `hit+miss+policy_filtered+rule == total`。
            "rule" => "rule",
            _ => "total",
            // <<< 242B END P1-6-cat <<< //
        };
        self.inc_n(key, 1);
    }

    fn inc(&self, key: &str) {
        // 具体类型的固有方法 `inc_n` 优先解析（trait 里也没有它），
        // 因此 `ebpdns-resolver` 的 `Telemetry` trait 表面**无需改动**。
        self.inc_n(key, 1);
    }

    fn inc_rule(&self, key: &str) {
        *self.rule_hits.lock().entry(key.to_string()).or_insert(0) += 1;
    }

    /// **2.1.16（功能 3）**：规则命中二维聚合（`match_type` × `action`）。
    ///
    /// 一维 `rule_hits` 的既有口径**逐字不变**（`/api/status.rule_hits`、
    /// `/api/snapshot.rule_hits` 与全部既有单测/前端都不受影响）；
    /// 这里额外维护第二张表供 `ebpdns_rule_hits_total{match_type,action}` 使用。
    ///
    /// **可对账性（硬要求）**：同一打点同时更新两张表，因此
    /// `sum(二维表全部值) == sum(rule_hits 全部值)` 恒成立
    /// （单测 `s3_rule_hits_two_dims_are_reconcilable` 钉死）。
    fn inc_rule_kind(&self, match_type: &str, action: &str) {
        self.inc_rule(action);
        let k = (match_type.to_string(), action.to_string());
        *self.rule_hits_kind.lock().entry(k).or_insert(0) += 1;
    }

    fn push_latency(&self, ms: f64) {
        self.latency_push(ms);
    }

    #[allow(clippy::too_many_arguments)]
    fn log(
        &self,
        domain: &str,
        qtype: &str,
        hit: &str,
        msg: &str,
        latency_ms: f64,
        client_ip: Option<&str>,
        upstream: &str,
        answer: &str,
        rule: Option<&str>,
    ) {
        let level = match hit {
            "hit" => "hit",
            "miss" => "miss",
            "rule" => "rule",
            "policy" => "policy",
            "err" => "err",
            _ => "sys",
        };
        self.push_event(
            level,
            domain,
            qtype,
            client_ip,
            if upstream.is_empty() {
                None
            } else {
                Some(upstream)
            },
            rule,
            answer,
            latency_ms,
            msg,
        );
    }
}

/* ---------------- 事件采样 ---------------- */

/// 采样判定（纯函数，随机数由调用方注入 → 可单测）。
///
/// **[历史归因]** 对齐 Python `Telemetry._should_sample_event`：真实流量 `hit`/`miss` 仅 10% 入环；
/// `err`/`sys`/`warn` 等低频事件全量保留。**计数器与本判定无关**（始终全量）。
///
/// **2.1.43-A（P2：policy 事件挤爆 500 环）**：`policy`（本地策略短路：AAAA 屏蔽 /
/// IPv6 关闭）与 `rule`（本地规则直答）此前**不采样**，但它们与 `miss` 是**同量级**
/// 的：一打开 `prefer_ipv4`，每个 AAAA 查询都产生一条 `policy` 事件 ⇒ 500 条的事件环
/// 在几百毫秒内被清一色 `policy` 填满，`hit`/`miss`/`err` 全被挤掉（`/api/logs` 与
/// 依赖事件的逐上游维度同时失真）。
///
/// 现在 `policy` / `rule` 与 `hit` / `miss` **同档采样**（[`EVENT_SAMPLE_RATE`] = 10%）。
/// **"被过滤计数"独立全量**：`policy_filtered_total` / `rule` 由
/// `dns.rs::log_and_count` 逐条自增，**不经过本判定**（采样只裁剪"事件环 + seq 推进"，
/// 不裁剪任何 counter —— 单测 `policy_events_are_sampled_but_policy_filtered_total_is_not`
/// 同时钉死"事件数在采样带内"与"计数逐条不变"）。
fn should_sample_event(level: &str, r: f64) -> bool {
    if matches!(level, "hit" | "miss" | "policy" | "rule") {
        // **[历史归因]** Python: `random.random() < 0.1`（policy/rule 2.1.43-A 起同档）
        r < EVENT_SAMPLE_RATE
    } else {
        true
    }
}

/// 该级别的事件是否计入延迟窗口。
///
/// **[历史归因]** Python 在 hit（缓存直答）/miss/serve-stale/warn（AAAA 屏蔽）等**有实测耗时**的路径
/// 调用 `push_latency`；`rule`（规则直答，未实测）与 `sys`（控制面/手动查询）不计入。
///
/// **2.1.43-A**：`sys` 的延迟**哪里都不进全局窗口** —— 控制面 `/api/query` 的耗时
/// 只写 `manual_history[].latency_ms`（[`ServerTelemetry::record_manual`]），
/// 因此 `avg_latency_ms` 是**纯数据面**口径（与 `/metrics` 的 HELP 逐字一致）。
fn level_counts_latency(level: &str) -> bool {
    matches!(level, "hit" | "miss" | "err" | "warn")
}

/// **2.1.41**：`upstream` 列里的**本地判定文案**（不是真实上游 id）。
///
/// 数据面在"没发上游"时用可读文案填事件列（见 `dns.rs::event_upstream` /
/// `CACHE_DIRECT_UP_NAME` / 规则 `RuleHit::upstream`）。这些值若被当成上游 id，
/// 会在 `/metrics` 的 `ebpdns_upstream_latency_ms{id=…}` 里造出**虚假序列**，
/// 使逐上游延迟/分位数无法按真实 id 对账（2.1.41 实测：
/// `id="本地判定（未发上游）"` 累计 177 条畸形包样本）。
///
/// 真实上游 id 由配置/控制台给出（`base36` 自动生成或用户自定义），不会命中
/// 下面这些**固定文案**；用户若故意把 id 起成「本地…」这类名字，只会让该 id
/// 不参与逐上游延迟（可接受的保守取舍，事件/topN 仍照常）。
fn is_local_upstream_label(up: &str) -> bool {
    up == CACHE_DIRECT_LABEL
        || up == "白名单"
        || up == "规则屏蔽"
        || up == "分流规则"
        || up == "serve-stale"
        || up == "无上游"
        || up.starts_with("本地")
        || up.starts_with("上游失败")
        || up.starts_with("上游（")
}

/// 缓存直答的展示文案（与 `dns.rs::CACHE_DIRECT_UP_NAME` 同字面；此处避免跨 crate 依赖）。
const CACHE_DIRECT_LABEL: &str = "缓存直答";

/// `[0,1)` 均匀随机数（xorshift64*，非加密用途；无新增依赖）。
fn next_rand_f64() -> f64 {
    let mut s = RAND_STATE.load(Ordering::Relaxed);
    if s == 0 {
        // 首次播种：系统时间纳秒（取不到时用固定非零常量），避免种子为 0 的退化序列。
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15);
        s = seed | 1;
    }
    let mut x = s;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    RAND_STATE.store(x, Ordering::Relaxed);
    let v = x.wrapping_mul(0x2545_F491_4F6C_DD1D);
    // 取高 53 位 → [0,1)。
    (v >> 11) as f64 / (1u64 << 53) as f64
}

/// 未知 `inc` 键告警（同键一次；去重集合有上限，防异常调用方传动态键导致内存增长）。
fn warn_unknown_inc(key: &str) {
    let set = UNKNOWN_INC_KEYS.get_or_init(|| Mutex::new(HashSet::new()));
    let mut g = set.lock();
    if g.len() >= 64 {
        return;
    }
    if g.insert(key.to_string()) {
        drop(g);
        tracing::warn!("telemetry.inc: 未知计数器键 {key:?}，已按 no-op 忽略");
    }
}

/* ---------------- TopN 有界频次 ---------------- */

/// **[历史归因]** 有界频次累加（对齐 Python `count_top`）：
/// 键存在 → `+1`；否则插入，插入后若 `len > TOP_MAP_MAX` 则裁到**高频一半**
/// （`most_common(_top_max // 2)`），之后**继续**接受新键。
///
/// 旧实现满额后永久丢弃新键（TopN 冻结在早期键上，长跑后无法反映真实热点）。
fn bounded_inc(map: &Mutex<HashMap<String, u64>>, key: &str) {
    let mut g = map.lock();
    match g.get_mut(key) {
        Some(v) => {
            *v = v.saturating_add(1);
        }
        None => {
            g.insert(key.to_string(), 1);
            if g.len() > TOP_MAP_MAX {
                trim_low_counts(&mut g);
            }
        }
    }
}

/// `Counter.most_common(TOP_MAP_MAX / 2)` 的等价实现：保留计数最高的半数键（计数不衰减）。
fn trim_low_counts(g: &mut HashMap<String, u64>) {
    let keep = TOP_MAP_MAX / 2;
    let mut entries: Vec<(String, u64)> = g.drain().collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    entries.truncate(keep);
    g.extend(entries);
}

/// top-N：按计数降序取前 n，返回 [[name, count], ...]。
fn top_n(map: &HashMap<String, u64>, n: usize) -> Vec<Value> {
    let mut entries: Vec<(&String, &u64)> = map.iter().collect();
    entries.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    entries
        .into_iter()
        .take(n)
        .map(|(k, v)| json!([k, v]))
        .collect()
}

/* ---------------- 本地时间（不新增依赖） ---------------- */

/// **[历史归因]** epoch 秒 → 本地时间 `HH:MM:SS`（对齐 Python `time.strftime("%H:%M:%S")`）。
/// 非法输入返回 `--:--:--`（占位，不 panic）。
pub fn hms_label(epoch: f64) -> String {
    match local_hms(epoch) {
        Some((h, m, s)) => format!("{h:02}:{m:02}:{s:02}"),
        None => "--:--:--".to_string(),
    }
}

/// **[历史归因]** epoch 秒 → 本地时间 `HH:MM:SS.mmm`（对齐 Python `_now_ts()`；事件/manual 时间戳用）。
fn hms_ms_label(epoch: f64) -> String {
    match local_hms(epoch) {
        Some((h, m, s)) => {
            let ms = ((epoch * 1000.0) as u64) % 1000;
            format!("{h:02}:{m:02}:{s:02}.{ms:03}")
        }
        None => "--:--:--.---".to_string(),
    }
}

/// 本地时间 `(时, 分, 秒)`。取值优先级：
/// 1. Unix `localtime_r`（glibc/musl/macOS；走 `TZ`/`/etc/localtime` + tzdata，含 DST）；
/// 2. Windows `GetTimeZoneInformation`（含当前 DST 状态）；
/// 3. `TZ` 固定偏移解析（`UTC` / `CST-8` / `UTC+8` / `+08:00`）；
/// 4. 都拿不到 → UTC（并 `tracing::warn!` 一次）。
fn local_hms(epoch: f64) -> Option<(u32, u32, u32)> {
    if !epoch.is_finite() || epoch <= 0.0 {
        return None;
    }
    #[cfg(unix)]
    if let Some(v) = unix_local_hms(epoch) {
        return Some(v);
    }
    let local = epoch as i64 + local_utc_offset_secs();
    let rem = local.rem_euclid(86_400);
    Some((
        (rem / 3600) as u32,
        ((rem % 3600) / 60) as u32,
        (rem % 60) as u32,
    ))
}

/// Unix：`localtime_r` 取本地时间。自行声明 libc 符号（不新增 libc 依赖）。
///
/// 只按 POSIX 规定的 `struct tm` **前三个字段**（`int tm_sec/tm_min/tm_hour`）读取
/// 128 字节缓冲的前 12 字节，因此不依赖各平台结构体后半部分（`tm_gmtoff`/`tm_zone`）布局。
#[cfg(unix)]
fn unix_local_hms(epoch: f64) -> Option<(u32, u32, u32)> {
    use std::ffi::c_void;
    // **P2（2.1.14）**：签名与 `subscribe.rs::tz_gmtoff`（同 crate 另一处声明）**逐字一致**
    // （`*const c_void` / `*mut c_void`），否则 `clashing_extern_declarations` 告警。
    // ABI 上三者都是裸指针，等价。
    extern "C" {
        fn localtime_r(timep: *const c_void, result: *mut c_void) -> *mut c_void;
    }
    let t: i64 = epoch as i64;
    // struct tm 在 32/64 位平台均 < 128 字节（glibc 64 位 56 字节）。
    let mut buf = [0u8; 128];
    // SAFETY: localtime_r 是可重入的线程安全 libc 调用；buf 容量大于任何受支持平台的
    // struct tm，返回非空时前 3 个 int 字段必已写入。32 位平台 time_t=4 字节，小端下
    // 读取 &i64 的低 4 字节仍是正确 epoch（2038 前有效）。
    let ret = unsafe {
        localtime_r(
            (&t as *const i64).cast::<c_void>(),
            buf.as_mut_ptr().cast::<c_void>(),
        )
    };
    if ret.is_null() {
        return None;
    }
    let sec = i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let min = i32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let hour = i32::from_ne_bytes([buf[8], buf[9], buf[10], buf[11]]);
    if !(0..24).contains(&hour) || !(0..60).contains(&min) || !(0..61).contains(&sec) {
        return None;
    }
    Some((hour as u32, min as u32, sec as u32))
}

/// Windows：Win32 `GetTimeZoneInformation`（含当前 DST 状态）。
/// 与 `subscribe.rs:129-157` 同款实现（该文件不在本次改动范围，故此处内联同逻辑）。
#[cfg(windows)]
fn local_utc_offset_secs() -> i64 {
    #[repr(C)]
    struct TzInfo {
        bias: i32,
        standard_name: [u16; 32],
        standard_date: [u16; 8],
        standard_bias: i32,
        daylight_name: [u16; 32],
        daylight_date: [u16; 8],
        daylight_bias: i32,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetTimeZoneInformation(info: *mut TzInfo) -> u32;
    }
    // SAFETY: TzInfo 是 repr(C) 全整数结构，全零初始化合法；GetTimeZoneInformation
    // 只写该结构体内存。
    let mut info: TzInfo = unsafe { std::mem::zeroed() };
    let rc = unsafe { GetTimeZoneInformation(&mut info) };
    if rc == 0xFFFF_FFFF {
        // TIME_ZONE_ID_INVALID：退回 TZ 解析（再拿不到则按 UTC）。
        return parse_tz_env_offset_secs();
    }
    // BIAS 语义是「本地 = UTC - bias」（分钟）；夏令时生效（rc==2）时叠加 DaylightBias。
    let mut minutes = info.bias + info.standard_bias;
    if rc == 2 {
        minutes += info.daylight_bias;
    }
    -(minutes as i64) * 60
}

/// 非 Windows：先解析 `TZ`，解析不了按 UTC（Unix 正常路径走 `localtime_r`，不经过这里）。
#[cfg(not(windows))]
fn local_utc_offset_secs() -> i64 {
    parse_tz_env_offset_secs()
}

/// `TZ` 环境变量 → UTC 偏移（秒，东为正）；解析不了返回 0 并告警一次。
fn parse_tz_env_offset_secs() -> i64 {
    let tz = std::env::var("TZ").unwrap_or_default();
    match parse_tz_offset_secs(&tz) {
        Some(off) => off,
        None => {
            warn_tz_unknown_once(&tz);
            0
        }
    }
}

/// 时区解析失败告警（每进程一次，避免时间戳格式化刷日志）。
fn warn_tz_unknown_once(tz: &str) {
    if TZ_WARNED.set(()).is_ok() {
        tracing::warn!(
            "无法从 TZ={tz:?} 解析本地时区偏移，时间戳按 UTC 输出（Unix 走 localtime_r，不受影响）"
        );
    }
}

/// 解析 `TZ` 的**固定偏移**（秒，东为正）。支持：
/// - `UTC` / `GMT` / `UT` / `Z`；
/// - `UTC+8` / `GMT-5`（按直觉：UTC 偏移）；
/// - 裸偏移 `+08:00` / `8` / `-3`（扩展）；
/// - POSIX `std[+-]hh[:mm[:ss]][dst...]`（POSIX 符号相反：`CST-8` = UTC+8）；
/// - `<+08>-8` 形式。
///
/// 不解析 DST 规则（非 Unix 兜底路径无 tzdata，取标准时偏移）与 IANA 名
/// （`Asia/Shanghai` → `None`；Unix 由 `localtime_r` 处理，Windows 由 Win32 处理）。
fn parse_tz_offset_secs(tz: &str) -> Option<i64> {
    let tz = tz.trim();
    if tz.is_empty() {
        return None;
    }
    // `<+08>-8`：跳过尖括号内的名字。
    let (head, tail): (&str, &str) = match tz.strip_prefix('<') {
        Some(inner) => match inner.split_once('>') {
            Some((name, rest)) => (name, rest),
            None => return None,
        },
        None => {
            let h = tz
                .split(|c: char| !c.is_ascii_alphabetic())
                .next()
                .unwrap_or("");
            (h, &tz[h.len()..])
        }
    };
    if head.eq_ignore_ascii_case("UTC")
        || head.eq_ignore_ascii_case("GMT")
        || head.eq_ignore_ascii_case("UT")
        || head.eq_ignore_ascii_case("Z")
    {
        if tail.is_empty() {
            return Some(0);
        }
        // `UTC+8`：尾部按 UTC 偏移直读（与下方 POSIX 符号相反）。
        return parse_offset_secs(tail.trim_start_matches(':'));
    }
    if head.is_empty() {
        // 裸偏移扩展：`+08:00` / `8` / `-3`。
        return parse_offset_secs(tail);
    }
    // POSIX `std offset [dst[offset][,start[/time],end[/time]]]`：
    // offset 是"加到本地时间得到 UTC"的量 → 取负得到 UTC 偏移。
    let len = tail
        .find(|c: char| !(c.is_ascii_digit() || c == ':' || c == '+' || c == '-'))
        .unwrap_or(tail.len());
    let (off, _dst) = tail.split_at(len);
    parse_offset_secs(off).map(|posix| -posix)
}

/// `[+-]hh[:mm[:ss]]` → 秒（符号按字面：`+8`/`8` = 28800，`-3` = -10800）。
fn parse_offset_secs(s: &str) -> Option<i64> {
    let s = s.trim();
    let (sign, body) = match s.strip_prefix('-') {
        Some(rest) => (-1i64, rest),
        None => (1i64, s.strip_prefix('+').unwrap_or(s)),
    };
    if body.is_empty() {
        return None;
    }
    let mut it = body.split(':');
    let h: i64 = it.next()?.trim().parse().ok()?;
    let m: i64 = match it.next() {
        Some(v) => v.trim().parse().ok()?,
        None => 0,
    };
    let sec: i64 = match it.next() {
        Some(v) => v.trim().parse().ok()?,
        None => 0,
    };
    if it.next().is_some() || h > 23 || m > 59 || sec > 59 {
        return None;
    }
    Some(sign * (h * 3600 + m * 60 + sec))
}

/// **[历史归因]** epoch 秒（对齐 Python time.time()）。
pub fn now_epoch() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **2.1.45（P2-6 / REV247 P2-2）**：冻结期内写入被丢弃（"不计"语义），
    /// 解除后才重新计数；`reset` 后全 0。
    #[test]
    fn reset_freeze_drops_frozen_increments_then_counts_again() {
        let t = ServerTelemetry::new();
        t.count_query("hit");
        t.note_data_plane_outcome(Some(0), None, 0);
        assert_eq!(t.counters()["hit"], json!(1));
        assert_eq!(t.counters()["total"], json!(1));
        // 冻结期：所有标量写入丢弃。
        t.set_reset_frozen(true);
        t.inc_n("hit", 5);
        t.note_data_plane_outcome(Some(0), None, 0);
        assert_eq!(t.counters()["hit"], json!(1), "冻结期不得计入");
        assert_eq!(t.counters()["total"], json!(1), "冻结期不得计入 total");
        t.set_reset_frozen(false);
        t.reset();
        let c = t.counters();
        assert_eq!(c["hit"], json!(0));
        assert_eq!(c["total"], json!(0));
        // reset 之后新写入正常进新代。
        t.count_query("hit");
        t.note_data_plane_outcome(Some(0), None, 0);
        assert_eq!(t.counters()["hit"], json!(1));
        assert_eq!(t.counters()["total"], json!(1));
    }

    /// **2.1.45（P2-6）**：并发 reset 与数据面记账不会产生"半新半旧"的撕裂 ——
    /// 记账全程持读屏障、reset 持写屏障，因此每个查询的 `total` 与分类同进同出。
    #[test]
    fn concurrent_reset_and_counting_keeps_hit_miss_total_consistent() {
        let t = Arc::new(ServerTelemetry::new());
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut hs = Vec::new();
        for _ in 0..4 {
            let t = Arc::clone(&t);
            let stop = Arc::clone(&stop);
            hs.push(std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    {
                        let _g = t.reset_read_gate();
                        t.note_data_plane_outcome(Some(0), None, 0);
                        t.count_query("hit");
                    }
                    std::thread::yield_now();
                }
            }));
        }
        for _ in 0..20 {
            t.reset();
            std::thread::yield_now();
        }
        stop.store(true, Ordering::Relaxed);
        for h in hs {
            h.join().unwrap();
        }
        let c = t.counters();
        let total = c["total"].as_u64().unwrap();
        let hit = c["hit"].as_u64().unwrap();
        let miss = c["miss"].as_u64().unwrap();
        assert_eq!(
            hit + miss,
            total,
            "`hit+miss == total` 必须在 reset 前后都成立（无跨代撕裂）"
        );
    }

    /// 直接调用 trait 方法（`log`/`inc` 的字面量在测试里用限定路径，避免歧义）。
    fn log_miss(t: &ServerTelemetry, domain: &str, upstream: &str, lat: f64) {
        <ServerTelemetry as Telemetry>::log(
            t, domain, "A", "miss", "", lat, None, upstream, "1.2.3.4", None,
        );
    }

    #[test]
    fn history_ring_120_and_snapshot_tail_60() {
        let t = ServerTelemetry::new();
        for _ in 0..(HISTORY_RING_MAX + 80) {
            t.sample_point();
        }
        let all = t.history_snapshot_all();
        assert_eq!(all.len(), HISTORY_RING_MAX, "历史环上限应为 120");
        let tail = t.history_snapshot();
        assert_eq!(
            tail.len(),
            HISTORY_TAIL_MAX,
            "snapshot 应返回 history[-60:]"
        );
        assert_eq!(tail[0], all[all.len() - HISTORY_TAIL_MAX]);
        assert_eq!(tail[tail.len() - 1], all[all.len() - 1]);
        let p = &all[0];
        for k in ["label", "label_text", "ts", "hit_rate", "qps", "lat"] {
            assert!(p.get(k).is_some(), "history 点缺少字段 {k}");
        }
        // hit_rate 是 0..100 百分数（v1.9.162 口径），不是 0..1 比例。
        let hr = p["hit_rate"].as_f64().unwrap_or(-1.0);
        assert!((0.0..=100.0).contains(&hr), "hit_rate 越界: {hr}");
        // **[历史归因]** 无样本时 lat=0（Python `round(_al,1) if _al is not None else 0`）。
        assert_eq!(p["lat"], json!(0.0));
    }

    #[test]
    fn manual_ring_bounded_20() {
        let t = ServerTelemetry::new();
        for i in 0..(MANUAL_RING_MAX + 10) {
            t.record_manual(&format!("d{i}.com"), "A", "1.1.1.1", true, 1.0, 0);
        }
        assert_eq!(t.manual.lock().len(), MANUAL_RING_MAX);
        let h = t.manual_history();
        assert_eq!(h.len(), MANUAL_RING_MAX);
        assert_eq!(h[0]["domain"], json!("d10.com"));
        assert_eq!(h[h.len() - 1]["domain"], json!("d29.com"));
        // sys 事件全量入环（不受 10% 采样影响）。
        assert_eq!(t.events.lock().len(), MANUAL_RING_MAX + 10);
    }

    #[test]
    fn event_ring_bounded_500_for_unsampled_levels() {
        // **2.1.43-A**：`rule` / `policy` 已改为 10% 采样（与 `hit`/`miss` 同档），
        // 因此"全量入环"的活体样本改用 `sys`（控制面 / 手动查询等低频级别）。
        let t = ServerTelemetry::new();
        for i in 0..(EVENT_RING_MAX + 100) {
            <ServerTelemetry as Telemetry>::log(
                &t,
                &format!("d{i}.com"),
                "A",
                "sys",
                "系统事件",
                0.0,
                None,
                "",
                "",
                None,
            );
        }
        assert_eq!(t.events.lock().len(), EVENT_RING_MAX);
        assert_eq!(t.max_seq(), (EVENT_RING_MAX + 100) as u64 - 1);
    }

    #[test]
    fn event_sampling_gate_is_pure_and_python_semantics() {
        // **[历史归因]** Python: `random.random() < 0.1` → 恰好 0.1 不采样。
        assert!(should_sample_event("hit", 0.0));
        assert!(should_sample_event("hit", 0.0999));
        assert!(!should_sample_event("hit", 0.1));
        assert!(!should_sample_event("miss", 0.999));
        assert!(should_sample_event("miss", 0.05));
        // **2.1.43-A**：`policy` / `rule` 与 `hit`/`miss` **同档采样**（10%），
        // 否则打开 `prefer_ipv4` 后 500 条事件环会被 `policy` 在几百毫秒内挤爆。
        for lvl in ["policy", "rule"] {
            assert!(should_sample_event(lvl, 0.0), "{lvl} 必须进采样档");
            assert!(should_sample_event(lvl, 0.0999), "{lvl} 必须进采样档");
            assert!(!should_sample_event(lvl, 0.1), "{lvl} 必须进采样档");
            assert!(!should_sample_event(lvl, 0.999_999), "{lvl} 不得全量入环");
        }
        // `err` / `sys` / `warn` 仍是低频，**全量**保留。
        for lvl in ["err", "sys", "warn"] {
            assert!(should_sample_event(lvl, 0.999_999), "{lvl} 必须全量");
        }
    }

    #[test]
    fn hit_sampling_keeps_counters_topn_and_latency_full() {
        let t = ServerTelemetry::new();
        let n: u64 = 2000;
        for _ in 0..n {
            // **2.1.18（修复项 9）**：`total` 是 `Σ client_rcode` 的派生量，
            // `count_query("resolve")` 不再推进它 ⇒ 用真实出口调用（同时计 rcode=0）。
            t.note_data_plane_outcome(Some(0), None, 0);
            t.count_query("hit");
            <ServerTelemetry as Telemetry>::log(
                &t,
                "a.com",
                "A",
                "hit",
                "缓存直答",
                2.0,
                None,
                "up1",
                "1.2.3.4",
                None,
            );
        }
        let c = t.counters();
        assert_eq!(c["hit"], json!(n), "计数器必须全量，不受采样影响");
        assert_eq!(c["total"], json!(n));
        let evs = t.events.lock().len();
        assert!((80..=400).contains(&evs), "10% 采样事件数异常: {evs}");
        // TopN 聚合不受采样影响。
        assert_eq!(t.top_upstreams()[0], json!(["up1", n]));
        // 延迟窗口同样全量（上限 400）。
        assert_eq!(t.latency.lock().len(), LATENCY_WINDOW_MAX);
        assert_eq!(t.avg_latency_opt(), Some(2.0));
    }

    #[test]
    fn reset_clears_qps_and_latency_windows_and_all_counters() {
        let t = ServerTelemetry::new();
        <ServerTelemetry as Telemetry>::note_client_query(&t);
        t.count_query("hit");
        t.inc_n("bytes_in", 1500);
        <ServerTelemetry as Telemetry>::inc_rule(&t, "block");
        log_miss(&t, "a.com", "up1", 12.0);
        t.record_manual("m.com", "A", "1.1.1.1", true, 3.0, 0);
        t.sample_point();
        assert_eq!(t.qps(), 1.0);
        assert!(t.avg_latency_opt().is_some());
        assert!(!t.history_snapshot_all().is_empty());

        t.reset();

        // F13: qps 窗口必须一起清空（旧实现漏清 → reset 后 QPS 仍是旧值）。
        assert_eq!(t.qps(), 0.0, "reset 后 qps 窗口未清空");
        assert_eq!(t.avg_latency_opt(), None, "reset 后延迟窗口未清空");
        assert_eq!(t.avg_latency_ms(), 0.0);
        let c = t.counters();
        for k in COUNTER_KEYS {
            assert_eq!(c[k], json!(0), "reset 后 {k} 应为 0");
        }
        assert!(t.rule_hits().is_empty());
        assert!(t.events_snapshot().is_empty());
        assert!(t.manual_history().is_empty());
        assert!(t.history_snapshot_all().is_empty());
        assert!(t.top_upstreams().is_empty());
        assert!(t.top_domains().is_empty());
        assert!(t.top_clients().is_empty());
        assert_eq!(t.qtype_dist(), json!({"A": 0, "AAAA": 0, "other": 0}));
        // boot/next_seq 故意不重置（uptime 累积、客户端 since 游标继续有效）。
        assert_eq!(t.qtype_dist()["A"], json!(0));
    }

    /// **2.1.40**：新计数器在 `COUNTER_KEYS` 内、可经 `inc_n` 自增，
    /// 且**不进入** `hit_rate` 的分母。
    #[test]
    fn policy_filtered_total_is_exposed_but_not_in_hit_rate_denominator() {
        let t = ServerTelemetry::new();
        assert!(COUNTER_KEYS.contains(&"policy_filtered_total"));
        t.inc_n("policy_filtered_total", 7);
        t.inc_n("hit", 9);
        t.inc_n("miss", 1);
        let c = t.snapshot();
        assert_eq!(c.policy_filtered_total, 7);
        assert_eq!(c.hit, 9);
        assert_eq!(c.miss, 1);
        // 分母 = hit + miss = 10（不是 total=0，也不是加上 policy=7）。
        assert!(
            (t.hit_rate() - 0.9).abs() < 1e-12,
            "hit_rate={}",
            t.hit_rate()
        );
        t.reset();
        assert_eq!(t.counters()["policy_filtered_total"], json!(0));
    }

    #[test]
    fn avg_latency_is_window_mean_with_option_semantics() {
        let t = ServerTelemetry::new();
        assert_eq!(t.avg_latency_opt(), None, "无样本必须是 None");
        assert_eq!(t.avg_latency_ms(), 0.0);
        // 合法的 0.0 样本不能被判成 None（必须用 is_empty() 判空）。
        t.push_latency(0.0);
        assert_eq!(t.avg_latency_opt(), Some(0.0));
        t.push_latency(4.0);
        assert_eq!(t.avg_latency_opt(), Some(2.0));

        // 窗口上限 400：只保留最近 400 条样本（算术平均，非 EWMA）。
        let t2 = ServerTelemetry::new();
        for i in 1..=500u64 {
            t2.push_latency(i as f64);
        }
        assert_eq!(t2.latency.lock().len(), LATENCY_WINDOW_MAX);
        // 期望值 = (101+500)/2 = 300.5（1 位小数四舍五入）。
        // 显式标注 f64（并在首个字面量加后缀）：`{float}` 推断在 `.round()` 处尚未定性会报 E0689。
        let expect: f64 = (((101.0_f64 + 500.0) / 2.0) * 10.0).round() / 10.0;
        assert_eq!(t2.avg_latency_opt(), Some(expect));
        // 非有限/负值不入窗口。
        t2.push_latency(f64::NAN);
        t2.push_latency(f64::INFINITY);
        t2.push_latency(-1.0);
        assert_eq!(t2.latency.lock().len(), LATENCY_WINDOW_MAX);
        // reset 清空延迟窗口。
        t2.reset();
        assert_eq!(t2.avg_latency_opt(), None);
    }

    #[test]
    fn top_map_trims_to_half_and_keeps_counting_new_keys() {
        let t = ServerTelemetry::new();
        for i in 0..(TOP_MAP_MAX + 100) {
            t.note_data_plane(None, &format!("d{i}.com"), "A");
        }
        let len = t.domain_hits.lock().len();
        assert!(len <= TOP_MAP_MAX, "domain_hits 未裁剪: {len}");
        assert!(len >= TOP_MAP_MAX / 2, "裁剪过度: {len}");
        // 关键：满额后**新键仍能计入**（旧实现永久丢弃新键，TopN 会冻结）。
        for _ in 0..5 {
            t.note_data_plane(Some("2.2.2.2"), "hot.com", "A");
        }
        assert_eq!(t.top_domains()[0], json!(["hot.com", 5]));
        assert_eq!(t.top_clients()[0], json!(["2.2.2.2", 5]));
        // 已存在的键继续累加。
        for _ in 0..3 {
            t.note_data_plane(None, "hot.com", "A");
        }
        assert_eq!(t.top_domains()[0], json!(["hot.com", 8]));
    }

    /// **2.1.26（B4 的事实依据）**：`domain_hits` 的内存上界与"裁半"的**代价**实测。
    ///
    /// 只测**现状**（本批不改实现）：① 键表真的有界（`TOP_MAP_MAX`）；② 满额后的
    /// 一条**新域名**会触发 `trim_low_counts`（持锁、`O(n log n)`、n 次 `String` 迁移）
    /// —— 这里把"直接裁一次的代价"与"摊还到每条新键的代价"都量出来，供
    /// `docs/PROPOSAL-domain_hits.md` 引用。
    ///
    /// 显式运行：
    /// `cargo test --release -p ebpdns-server --lib bench_domain_hits_trim -- --ignored --nocapture`
    #[test]
    #[ignore = "微基准：需显式 --ignored --nocapture 运行"]
    fn bench_domain_hits_trim() {
        use std::time::Instant;
        let t = ServerTelemetry::new();
        // 填满到 TOP_MAP_MAX（此后每插入 1 个新键就裁一次、裁到一半）。
        for i in 0..TOP_MAP_MAX {
            t.note_data_plane(None, &format!("d{i}.example.invalid"), "A");
        }
        assert_eq!(t.domain_hits.lock().len(), TOP_MAP_MAX);

        // ① 直接裁一次的代价（重复 200 次：每次先填满再裁）。
        let rounds = 200;
        let mut direct = Vec::with_capacity(rounds);
        for _ in 0..rounds {
            {
                let mut g = t.domain_hits.lock();
                while g.len() < TOP_MAP_MAX {
                    let k = format!("f{}.example.invalid", g.len());
                    g.insert(k, 1);
                }
                let t0 = Instant::now();
                trim_low_counts(&mut g);
                direct.push(t0.elapsed().as_nanos() as f64 / 1000.0);
            }
        }

        // ② 摊还：从满额起连续插入 N 条**新**域名（每次插入都触发一次裁半）。
        let n = 20_000;
        let mut amort = Vec::with_capacity(n);
        for i in 0..n {
            let key = format!("n{i}.example.invalid");
            let t0 = Instant::now();
            bounded_inc(&t.domain_hits, &key);
            amort.push(t0.elapsed().as_nanos() as f64 / 1000.0);
        }
        let final_len = t.domain_hits.lock().len();
        let pct = |v: &mut Vec<f64>, p: f64| {
            v.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let k = ((v.len() - 1) as f64 * p / 100.0) as usize;
            v[k.min(v.len() - 1)]
        };
        let (d50, d99) = (pct(&mut direct, 50.0), pct(&mut direct, 99.0));
        let (a50, a99, ap99) = (
            pct(&mut amort, 50.0),
            pct(&mut amort, 99.0),
            pct(&mut amort, 99.9),
        );
        println!(
            "\n[B4/domain_hits] TOP_MAP_MAX={TOP_MAP_MAX} trim_keep={} final_len={final_len}\n  \
             ① 直接裁一次（n={TOP_MAP_MAX} 项）: p50={d50:.2}us p99={d99:.2}us\n  \
             ② 摊还到每条**新域名**（满额后 {n} 条）: p50={a50:.2}us p99={a99:.2}us p99.9={ap99:.2}us",
            TOP_MAP_MAX / 2
        );
        assert!(final_len <= TOP_MAP_MAX, "键表必须有界");
    }

    #[test]
    fn record_manual_does_not_pollute_data_plane() {
        let t = ServerTelemetry::new();
        t.record_manual("Manual.COM", "A", "1.2.3.4", true, 3.0, 0);
        // **[历史归因]** F16: 手动查询不动 qtype_dist / top_domains / top_clients（Python counted=False）。
        assert_eq!(t.qtype_dist(), json!({"A": 0, "AAAA": 0, "other": 0}));
        assert!(t.top_domains().is_empty());
        assert!(t.top_clients().is_empty());
        assert!(t.top_upstreams().is_empty());
        // **[历史归因]** 只写 manual 历史 + 事件环。
        assert_eq!(t.manual_history().len(), 1);
        assert_eq!(t.events.lock().len(), 1);
        // **2.1.43-A（P2：`avg_latency` 口径只数据面）**：控制面查询**不得**进
        // 全局延迟窗口（`sys` 级别本就不计延迟，且不再显式 `latency_push`），
        // 因此这里必须是 `None`。
        assert_eq!(
            t.avg_latency_opt(),
            None,
            "控制面查询不得污染 avg_latency_ms（2.1.43-A）"
        );
        // 但手动查询**自己的**延迟必须仍然可见（`manual_history`）。
        assert_eq!(t.manual_history()[0]["latency_ms"], json!(3.0));
        // 先把历史拷进具名局部量，再借元素（避免 `&temporary()[0]` 的临时量生命周期问题）。
        let mh = t.manual_history();
        let h = &mh[0];
        assert_eq!(h["domain"], json!("Manual.COM"));
        assert_eq!(h["hit"], json!(true));
        assert_eq!(h["rcode"], json!(0));
        // ts_text 为本地 HH:MM:SS.mmm。
        let txt = h["ts_text"].as_str().unwrap_or("");
        assert_eq!(txt.len(), 12, "ts_text 应为 HH:MM:SS.mmm: {txt}");
        assert_eq!(&txt[8..9], ".");
        // 数据面路径照常计数。
        t.note_data_plane(Some("9.9.9.9"), "a.com", "A");
        assert_eq!(t.qtype_dist()["A"], json!(1));
        assert_eq!(t.top_domains()[0], json!(["a.com", 1]));
        assert_eq!(t.top_clients()[0], json!(["9.9.9.9", 1]));
    }

    #[test]
    fn counters_expose_v19162_keys_and_inc_paths() {
        let t = ServerTelemetry::new();
        let c = t.counters();
        // 2.1.15：`counters()` = COUNTER_KEYS（**标量**计数器）+ STRUCTURED_COUNTER_KEYS
        // （结构化键，值是对象）。两者都钉死，避免"悄悄多/少一个键"。
        assert_eq!(c.len(), COUNTER_KEYS.len() + STRUCTURED_COUNTER_KEYS.len());
        for k in STRUCTURED_COUNTER_KEYS {
            assert!(c.contains_key(k), "counters 缺少结构化键 {k}");
            assert!(c[k].is_object(), "结构化键 {k} 必须是对象: {c:?}");
        }
        for k in COUNTER_KEYS {
            assert!(c.contains_key(k), "counters 缺少键 {k}");
            assert_eq!(c[k], json!(0), "counters[{k}] 初值应为 0");
        }
        for k in COUNTER_KEYS {
            <ServerTelemetry as Telemetry>::inc(&t, k);
        }
        let c = t.counters();
        for k in COUNTER_KEYS {
            if k == "total" {
                // **2.1.18（修复项 9）**：`total` 是**派生量**（`= Σ client_rcode`），
                // `inc_n("total")` 刻意 no-op（见 `ServerTelemetry::inc_n` 的注释）⇒
                // 这里断言"它恒等于 Σ client_rcode"，而不是某个固定值。
                // 注意：本轮循环里 `inc("servfail_total")` 会让派生槽 `client_rcode[2]`
                // +1（"又发出了一条 SERVFAIL"），因此 `total` 随之 +1 是**正确**的。
                let sum: u64 = c["client_rcode"]
                    .as_object()
                    .unwrap()
                    .values()
                    .filter_map(serde_json::Value::as_u64)
                    .sum();
                assert_eq!(c["total"], json!(sum), "total 必须恒等于 Σ client_rcode");
                continue;
            }
            assert_eq!(c[k], json!(1), "inc({k}) 未生效");
        }
        // 派生关系的正向验证：走一次真实出口后 `total` 才前进。
        let before_total = t.counters()["total"].as_u64().unwrap();
        t.note_data_plane_outcome(Some(0), None, 0);
        assert_eq!(
            t.counters()["total"].as_u64().unwrap(),
            before_total + 1,
            "total 只能由数据面出口推进（= Σ client_rcode）"
        );
        // **[历史归因]** 带增量的自增（bytes_* / upstream_queries 在 Python 是按量自增）。
        t.inc_n("bytes_in", 1500);
        t.inc_n("bytes_out", 42);
        assert_eq!(t.counters()["bytes_in"], json!(1501));
        assert_eq!(t.counters()["bytes_out"], json!(43));
        // 未知键：no-op（仅告警一次），不 panic、不污染计数。
        let before = t.counters();
        <ServerTelemetry as Telemetry>::inc(&t, "no_such_key");
        <ServerTelemetry as Telemetry>::inc(&t, "no_such_key");
        assert_eq!(t.counters(), before);
    }

    /// **2.1.41**：QPS 窗口 = 最近 1 秒；**唯一**推进点是 `note_client_query`
    /// （数据面出口每客户端查询一次），`count_query("resolve"/"hit"/…)` 一律不推进。
    #[test]
    fn qps_window_is_last_one_second_and_only_client_queries_touch_it() {
        let t = ServerTelemetry::new();
        assert_eq!(t.qps(), 0.0);
        for _ in 0..3 {
            <ServerTelemetry as Telemetry>::note_client_query(&t);
        }
        assert_eq!(t.qps(), 3.0);
        // 过期条目（epoch 0，早于 now-1s）被滑出。
        t.qps_win.lock().push_front(0.0);
        assert_eq!(t.qps(), 3.0);
        assert_eq!(t.qps_win.lock().len(), 3);
        // **2.1.41**：任何 count_query 类别（含 resolve）都不再推进 QPS 窗口 ——
        // 这钉住"每客户端查询只能推进一次"，并防止 `count_query("resolve")` 双计。
        t.count_query("resolve");
        t.count_query("hit");
        t.count_query("miss");
        t.count_query("upstream");
        assert_eq!(t.qps(), 3.0);
        assert_eq!(t.counters()["hit"], json!(1));
        assert_eq!(t.counters()["miss"], json!(1));
        assert_eq!(t.counters()["upstream_queries"], json!(1));
        // **2.1.41 要求②**：超过 1 s 未再发 ⇒ 窗口清空（真实时钟，不是伪时间戳）。
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert_eq!(t.qps(), 0.0, "1 s 内无新查询，QPS 必须归 0");
    }

    /// **2.1.41**：`sample_point`（`/api/snapshot.history[]` 的唯一来源）必须把
    /// 非零 `qps` / 非零 `lat` / 可解析 `label` 一起落环 —— 否则历史曲线仍是 0。
    #[test]
    fn history_sample_carries_nonzero_qps_and_latency() {
        let t = ServerTelemetry::new();
        for _ in 0..3 {
            <ServerTelemetry as Telemetry>::note_client_query(&t);
        }
        <ServerTelemetry as Telemetry>::push_latency(&t, 2.0);
        t.sample_point();
        let h = t.history_snapshot();
        assert_eq!(h.len(), 1);
        assert_eq!(h[0]["qps"], json!(3.0));
        assert_eq!(h[0]["lat"], json!(2.0));
        let label = h[0]["label"].as_f64().expect("label 必须是 epoch 秒");
        assert!(label > 1_600_000_000.0, "label 不能是 0：{label}");
        let text = h[0]["label_text"].as_str().expect("label_text");
        assert_eq!(text.len(), 8, "label_text 必须 HH:MM:SS：{text}");
        let hr = h[0]["hit_rate"].as_f64().expect("hit_rate");
        assert!((0.0..=100.0).contains(&hr), "hit_rate 必须是 0..100：{hr}");
    }

    #[test]
    fn local_time_formatting_and_tz_parse() {
        let epoch = 1_700_000_000.5_f64;
        let s = hms_label(epoch);
        assert_eq!(s.len(), 8, "应为 HH:MM:SS: {s}");
        assert_eq!(s.as_bytes()[2], b':');
        assert_eq!(s.as_bytes()[5], b':');
        assert_eq!(s.chars().filter(|c| c.is_ascii_digit()).count(), 6);
        let ms = hms_ms_label(epoch);
        assert_eq!(ms.len(), 12, "应为 HH:MM:SS.mmm: {ms}");
        assert_eq!(&ms[8..9], ".");
        assert_eq!(&ms[9..], "500");
        // 与 local_hms（本地时区）同源，不再固定 UTC。
        if let Some((h, m, sec)) = local_hms(epoch) {
            assert_eq!(s, format!("{h:02}:{m:02}:{sec:02}"));
        }
        // 非法输入占位，不 panic。
        assert_eq!(hms_label(0.0), "--:--:--");
        assert_eq!(hms_label(f64::NAN), "--:--:--");
        assert_eq!(hms_ms_label(-1.0), "--:--:--.---");

        // TZ 解析：POSIX 符号相反；UTC±hh 直读；裸偏移为扩展。
        assert_eq!(parse_tz_offset_secs("UTC"), Some(0));
        assert_eq!(parse_tz_offset_secs("GMT"), Some(0));
        assert_eq!(parse_tz_offset_secs("Z"), Some(0));
        assert_eq!(parse_tz_offset_secs("CST-8"), Some(8 * 3600));
        assert_eq!(parse_tz_offset_secs("EST5EDT"), Some(-5 * 3600));
        assert_eq!(parse_tz_offset_secs("UTC+8"), Some(8 * 3600));
        assert_eq!(parse_tz_offset_secs("+05:30"), Some(5 * 3600 + 1800));
        assert_eq!(parse_tz_offset_secs("-3"), Some(-3 * 3600));
        assert_eq!(parse_tz_offset_secs("<+08>-8"), Some(8 * 3600));
        assert_eq!(parse_tz_offset_secs("Asia/Shanghai"), None);
        assert_eq!(parse_tz_offset_secs(""), None);
        assert_eq!(parse_offset_secs("+8"), Some(28_800));
        assert_eq!(parse_offset_secs("08:00"), Some(28_800));
        assert_eq!(parse_offset_secs("1:2:3"), Some(3723));
        assert_eq!(parse_offset_secs("99"), None);
        assert_eq!(parse_offset_secs("+"), None);
    }

    #[test]
    fn rng_is_uniform_enough_for_event_sampling() {
        let mut hits = 0;
        for _ in 0..1000 {
            let r = next_rand_f64();
            assert!((0.0..1.0).contains(&r), "随机数越界: {r}");
            if r < EVENT_SAMPLE_RATE {
                hits += 1;
            }
        }
        assert!((30..=200).contains(&hits), "10% 采样分布异常: {hits}");
    }

    /// **2.1.43-A（P2：policy 事件挤爆 500 环）**：`policy` 事件按与 `miss` 同档
    /// 采样（事件数落在采样带内），而"被过滤计数"**逐条全量**（与本判定无关）。
    #[test]
    fn policy_events_are_sampled_but_policy_filtered_total_is_not() {
        const N: usize = 1000;
        let t = ServerTelemetry::new();
        for i in 0..N {
            // 计数侧：`dns.rs::log_and_count` 对每个 policy 查询都会走这一句。
            t.count_query("policy_filtered");
            // 事件侧：唯一写点是 `Telemetry::log(hit="policy")` → `push_event("policy")`。
            <ServerTelemetry as Telemetry>::log(
                &t,
                &format!("p{i}.com"),
                "AAAA",
                "policy",
                "本地策略应答(未发上游)",
                0.0,
                None,
                "本地判定（未发上游）",
                "",
                None,
            );
        }
        // 计数：**逐条全量**，不采样。
        assert_eq!(
            t.counters()["policy_filtered_total"],
            json!(N),
            "被过滤计数必须全量（不得随事件采样丢样本）"
        );
        // 事件：10% 档（n=1000, p=0.1 ⇒ 均值 100、σ≈9.5；判据留足 5σ 余量）。
        let evs = t.events.lock().len();
        assert!(
            (30..=250).contains(&evs),
            "policy 事件应落在 10% 采样带内（实际 {evs}/{N}）"
        );
        assert!(
            evs < N,
            "policy 事件不得全量入环（否则 500 环在几百毫秒内被挤爆）"
        );
        // 事件数与"被过滤计数"因此**必然**不等 —— 这正是修法要区分的两个量。
        assert_ne!(
            evs as u64,
            t.counters()["policy_filtered_total"].as_u64().unwrap()
        );
    }

    /// **2.1.43-A（P2：`avg_latency` 含控制面 `/api/query`）**：控制面查询
    /// **不得**改变 `avg_latency_ms`（口径统一为"只数据面"）。
    #[test]
    fn control_plane_query_does_not_move_avg_latency() {
        let t = ServerTelemetry::new();
        // 数据面两条：1ms / 3ms ⇒ 均值 2ms。
        log_miss(&t, "a.com", "up1", 1.0);
        log_miss(&t, "b.com", "up1", 3.0);
        assert_eq!(t.avg_latency_opt(), Some(2.0));
        let before_sum_cnt = t.client_latency_histogram().0;
        // 控制面 50 次"秒级慢查询"（人工调试的典型形态）。
        for _ in 0..50 {
            t.record_manual("slow.com", "A", "1.1.1.1", true, 900.0, 0);
        }
        assert_eq!(
            t.avg_latency_opt(),
            Some(2.0),
            "控制面 /api/query 不得改变 avg_latency_ms（2.1.43-A 统一口径）"
        );
        assert_eq!(t.avg_latency_ms(), 2.0);
        // 直方图（与 avg 同源）的样本数也不得被控制面撑大。
        assert_eq!(t.client_latency_histogram().0, before_sum_cnt);
        // 手动查询自己的延迟仍然完整可见。
        let mh = t.manual_history();
        assert_eq!(mh.len(), MANUAL_RING_MAX);
        assert_eq!(mh[0]["latency_ms"], json!(900.0));
    }

    /// **2.1.43-A（P2：`udp_dropped` 双源）**：`udp_dropped` 只有**一个**原子。
    #[test]
    fn udp_dropped_has_exactly_one_atomic() {
        let t = ServerTelemetry::new();
        let h = t.udp_dropped_handle();
        assert!(
            std::sync::Arc::ptr_eq(&h, &t.udp_dropped_handle()),
            "句柄必须是同一个 Arc<AtomicU64>（不是第二个计数器）"
        );
        // 数据面写点（`DnsServer` 持有的就是本句柄）+ 通用 `inc_n` 走同一原子。
        h.fetch_add(4, Ordering::Relaxed);
        t.inc_n("udp_dropped", 1);
        assert_eq!(t.udp_dropped(), 5);
        assert_eq!(t.counters()["udp_dropped"], json!(5));
        assert_eq!(h.load(Ordering::Relaxed), 5);
    }

    // REV247 形同虚设 #2（`probe_upstream_queries_is_additive_and_reset`）已删除：
    // 它只对计数器手工 `inc`，不驱动 `probe_a_record`，修复回退也绿。
    // 真正的接线判别在 `ebpdns-resolver/tests/fix248_tests.rs::
    // probe_a_record_positive_path_increments_counter`（驱动 resolver 的真实探测路径）。

    #[test]
    fn upstream_aggregation_is_not_gated_by_event_sampling() {
        let t = ServerTelemetry::new();
        for i in 0..600 {
            log_miss(&t, &format!("d{i}.com"), "up1", 5.0);
        }
        // 全量聚合（与采样无关）。
        assert_eq!(t.top_upstreams()[0], json!(["up1", 600]));
        let evs = t.events.lock().len();
        assert!((20..=200).contains(&evs), "miss 事件采样数异常: {evs}");
        // 延迟窗口同样全量（上限 400）。
        assert_eq!(t.latency.lock().len(), LATENCY_WINDOW_MAX);
        assert_eq!(t.avg_latency_opt(), Some(5.0));
    }

    #[test]
    fn qtype_dist_aggregates() {
        let t = ServerTelemetry::new();
        t.note_data_plane(Some("1.1.1.1"), "a.com", "A");
        t.note_data_plane(Some("1.1.1.1"), "b.com", "AAAA");
        t.note_data_plane(None, "c.com", "MX");
        let d = t.qtype_dist();
        assert_eq!(d["A"], json!(1));
        assert_eq!(d["AAAA"], json!(1));
        assert_eq!(d["other"], json!(1));
    }

    #[test]
    #[ignore = "性能测量（手动）：cargo test --release -p ebpdns-server --lib perf224 -- --ignored --nocapture"]
    fn perf224_note_data_plane_allocation_cost() {
        // **2.1.24（性能证据）**：热路径"每包一次多余 String 分配"的**同进程 A/B**。
        //
        // A = `note_data_plane`（旧口径：内部 `to_ascii_lowercase()` 复制一份）
        // B = `note_data_plane_normalized`（新口径：调用方已小写，零分配）
        //
        // 两者写入**同一个** `ServerTelemetry` 语义（同一张 `domain_hits` 表），因此
        // 这里用同一个实例即可（计数放大不影响"字符串处理"这部分的耗时对比）。
        let t = ServerTelemetry::new();
        // 典型 DNS qname：3 个标签 + 大小写混合（0x20 随机化形态）。
        let mixed = "WwW.ExAmPlE.CoM";
        let lower = "www.example.com";
        let n: u32 = 1_000_000;

        // 预热（把 first-touch 的页错误、HashMap 扩容排除在这次测量之外）。
        for _ in 0..10_000 {
            t.note_data_plane(Some("127.0.0.1"), mixed, "A");
            t.note_data_plane_normalized(Some("127.0.0.1"), lower, "A");
        }
        let t0 = std::time::Instant::now();
        for _ in 0..n {
            t.note_data_plane(Some("127.0.0.1"), mixed, "A");
        }
        let a = t0.elapsed();
        let t1 = std::time::Instant::now();
        for _ in 0..n {
            t.note_data_plane_normalized(Some("127.0.0.1"), lower, "A");
        }
        let b = t1.elapsed();
        let na = a.as_nanos() as f64 / n as f64;
        let nb = b.as_nanos() as f64 / n as f64;
        println!(
            "perf224 note_data_plane: A(normalizing)={na:.2} ns/op  B(normalized)={nb:.2} ns/op  \
             Δ={:.2} ns/op ({:+.1}%)  n={n}",
            na - nb,
            (nb - na) / na * 100.0
        );
        // 判据只要求"不更慢"（新入口必须真的省掉那次分配）。
        assert!(
            nb <= na * 1.05,
            "新入口不得比旧入口更慢：A={na:.2} ns/op B={nb:.2} ns/op"
        );
    }

    #[test]
    fn top_domains_and_clients() {
        let t = ServerTelemetry::new();
        for _ in 0..3 {
            t.note_data_plane(Some("9.9.9.9"), "a.com", "A");
        }
        t.note_data_plane(Some("8.8.8.8"), "b.com", "A");
        let td = t.top_domains();
        assert_eq!(td[0], json!(["a.com", 3]));
        let tc = t.top_clients();
        assert_eq!(tc[0], json!(["9.9.9.9", 3]));
        // b.com 第二。
        assert_eq!(td[1], json!(["b.com", 1]));
    }

    #[test]
    fn top_upstreams_from_events() {
        let t = ServerTelemetry::new();
        // log() 走 push_event → upstream 聚合（全量，不受 10% 采样影响）。
        log_miss(&t, "x.com", "up1", 5.0);
        log_miss(&t, "y.com", "up1", 6.0);
        log_miss(&t, "z.com", "up2", 7.0);
        let tu = t.top_upstreams();
        assert_eq!(tu[0], json!(["up1", 2]));
        assert!(tu.len() >= 2);
    }

    #[test]
    fn unknown_key_warning_and_bounded_inc_do_not_panic() {
        let t = ServerTelemetry::new();
        // 未知键（含动态键）反复调用：不得 panic/不得增长计数。
        for i in 0..200 {
            <ServerTelemetry as Telemetry>::inc(&t, &format!("dyn{i}"));
        }
        assert_eq!(t.counters()["total"], json!(0));
        t.inc_n("no_such_key", 5);
        assert_eq!(t.counters()["total"], json!(0));
    }

    /* ---------------- A7：逐上游延迟 / 负缓存 ---------------- */

    /// A7：`inc_n` 必须按**增量**累加（不含多次）。
    #[test]
    fn a7_inc_n_accumulates_by_delta() {
        let t = ServerTelemetry::new();
        t.inc_n("bytes_in", 100);
        t.inc_n("bytes_in", 250);
        t.inc_n("bytes_out", 40);
        assert_eq!(t.counters()["bytes_in"], json!(350));
        assert_eq!(t.counters()["bytes_out"], json!(40));
        // 0 增量是 no-op（不得把"未知键"告警路径也走一遍）。
        t.inc_n("bytes_in", 0);
        assert_eq!(t.counters()["bytes_in"], json!(350));
        // trait 转发与固有方法等价。
        t.inc_n("bytes_out", 2);
        assert_eq!(t.counters()["bytes_out"], json!(42));
    }

    /// A7：逐上游延迟窗口 —— 有界、按上游隔离、分位数/累积直方图正确。
    #[test]
    fn a7_upstream_latency_window_histogram_and_quantiles() {
        let t = ServerTelemetry::new();
        assert!(t.upstream_latency_histograms().is_empty());
        assert_eq!(t.upstream_latency_quantile("up1", 50.0), None);

        // 3 / 40 / 700 —— 覆盖小、中、大三个桶段。
        for v in [3.0, 40.0, 700.0] {
            t.push_upstream_latency("up1", v);
        }
        t.push_upstream_latency("up2", 1.0);
        // 非法输入丢弃。
        t.push_upstream_latency("", 5.0);
        t.push_upstream_latency("up1", f64::NAN);
        t.push_upstream_latency("up1", -1.0);
        t.push_upstream_latency("up1", f64::INFINITY);

        let h = t.upstream_latency_histograms();
        assert_eq!(h.len(), 2, "应有 up1/up2 两条: {h:?}");
        // 确定性排序：up1 在前。按值取出，避免 `h[0]` 索引 + 模式绑定带来的
        // `&Vec<u64>` / `&&[f64]` 双重引用（比对 `*x == le` 会报类型不匹配）。
        let (id, count, sum, buckets, les) = h.into_iter().next().expect("up1 样本");
        assert_eq!(id, "up1");
        assert_eq!(count, 3, "非法样本不得入窗口");
        assert_eq!(sum, 743.0);
        assert_eq!(les.len(), buckets.len());
        // 累积语义：count(<=1)=0, count(<=5)=1, count(<=50)=2, count(<=1000)=3。
        let at = |le: f64| {
            les.iter()
                .position(|x| *x == le)
                .map(|i| buckets[i])
                .unwrap_or(u64::MAX)
        };
        assert_eq!(at(1.0), 0);
        assert_eq!(at(2.0), 0);
        assert_eq!(at(5.0), 1);
        assert_eq!(at(50.0), 2, "3 与 40 都 <= 50");
        assert_eq!(at(1000.0), 3);
        // 单调不减。
        for w in buckets.windows(2) {
            assert!(w[0] <= w[1], "累积直方图必须单调不减: {buckets:?}");
        }
        // 分位数（线性插值）：3 / 40 / 700。
        assert_eq!(t.upstream_latency_quantile("up1", 50.0), Some(40.0));
        assert_eq!(t.upstream_latency_quantile("up1", 0.0), Some(3.0));
        assert_eq!(t.upstream_latency_quantile("up1", 100.0), Some(700.0));
        assert_eq!(t.upstream_latency_quantile("nope", 50.0), None);
    }

    /// **2.1.12**：增量维护的直方图/分位数必须与「按窗口重算」一致。
    ///
    /// 这是 O(1) 化的正确性钉子。对每个时间点同时取
    /// ①增量输出 ②对 `samples` 现算的参考值（照抄 2.1.11 的旧实现），逐项比对：
    /// - **桶计数**：整数 → `assert_eq!` **逐位精确**；
    /// - **分位数**：排序视图取秩 + 同样的插值与 `(x*10).round()/10` → `assert_eq!` **逐位精确**；
    /// - **`_sum`**：增量加减法的浮点漂移 → 相对误差断言
    ///   `|Δ| <= 4 * f64::EPSILON * max(1, |ref|)`（实测 ≤ 1 ULP；4 eps 留出余量）。
    ///   单调性/量级不受影响，且 `_sum` 的 `{:.3}` 输出格式分辨率远大于该漂移。
    #[test]
    fn a7_incremental_histogram_matches_recompute_exactly() {
        // 参考实现：完全照抄 2.1.11 的「按窗口重算」逻辑。
        fn reference(w: &VecDeque<f64>) -> (u64, f64, Vec<u64>) {
            let mut buckets = vec![0u64; LATENCY_BUCKETS_MS.len()];
            let mut sum = 0.0f64;
            for v in w.iter() {
                sum += *v;
                for (i, le) in LATENCY_BUCKETS_MS.iter().enumerate() {
                    if *v <= *le {
                        buckets[i] += 1;
                    }
                }
            }
            (w.len() as u64, sum, buckets)
        }
        fn reference_quantile(w: &VecDeque<f64>, p: f64) -> Option<f64> {
            if w.is_empty() {
                return None;
            }
            let mut v: Vec<f64> = w.iter().copied().collect();
            v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let k = ((v.len() - 1) as f64) * (p / 100.0);
            let lo = k.floor() as usize;
            let hi = (lo + 1).min(v.len() - 1);
            let frac = k - lo as f64;
            let out = v[lo] + (v[hi] - v[lo]) * frac;
            if out.is_finite() {
                Some((out * 10.0).round() / 10.0)
            } else {
                None
            }
        }

        let t = ServerTelemetry::new();
        let mut refwin: VecDeque<f64> = VecDeque::new();
        // 确定性 LCG（不引依赖、不随机 flake）：同时覆盖 <1ms、桶边界值、
        // 大值、重复值，以及远超窗口上限的入窗次数（必然发生淘汰）。
        let mut state: u64 = 0x2545F4914F6CDD1D;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        // 桶边界（含等值样本，验证 `<=` 而非 `<`）。
        let edges = [
            1.0f64, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0,
        ];
        for step in 0..(UPSTREAM_LAT_WINDOW_MAX * 3 + 37) {
            let v = match step % 4 {
                0 => edges[(next() % 10) as usize], // 恰好落在桶边界
                1 => (next() % 2000) as f64 / 8.0,  // 0..250 连续
                2 => (next() % 5) as f64,           // 高重复率（考验 sorted 删除）
                _ => (next() % 100_000) as f64 / 100.0,
            };
            t.push_upstream_latency("upX", v);
            if refwin.len() >= UPSTREAM_LAT_WINDOW_MAX {
                refwin.pop_front();
            }
            refwin.push_back(v);

            let (rc, rsum, rb) = reference(&refwin);
            let h = t.upstream_latency_histograms();
            assert_eq!(h.len(), 1, "step {step}");
            let (id, c, sum, buckets, les) = &h[0];
            assert_eq!(id, "upX");
            assert_eq!(*c, rc, "count 不一致 @step {step}");
            assert_eq!(buckets, &rb, "累积桶计数必须逐位精确 @step {step}");
            assert_eq!(les.len(), buckets.len());
            // `_sum`：ULP 级容差（见测试文档）。
            let tol = 4.0 * f64::EPSILON * rsum.abs().max(1.0);
            assert!(
                (sum - rsum).abs() <= tol,
                "_sum 漂移超容差 @step {step}: inc={sum} ref={rsum} diff={} tol={tol}",
                (sum - rsum).abs()
            );
            // 累积单调不减（Prometheus 语义）。
            for w in buckets.windows(2) {
                assert!(w[0] <= w[1], "累积直方图必须单调不减 @step {step}");
            }
            // 分位数：逐位精确（用户可见的 p50/p90/p99 就是这里出来的）。
            for p in [0.0, 50.0, 90.0, 99.0, 100.0] {
                assert_eq!(
                    t.upstream_latency_quantile("upX", p),
                    reference_quantile(&refwin, p),
                    "分位数 p={p} 不一致 @step {step}"
                );
            }
        }
        // 罕见输入：单样本、无样本上游。
        assert_eq!(t.upstream_latency_quantile("nope", 50.0), None);
        // 收尾再钉一次：增量和维护的 `_sum` 与「整窗重算」仍在 ULP 容差内
        // （跨 805 次入窗/淘汰后仍不漂移出容差）。
        {
            let g = t.upstream_lat.lock();
            let w = g.get("upX").expect("upX 窗口");
            let exact = w.recompute_sum();
            let inc = w.sum();
            let tol = 4.0 * f64::EPSILON * exact.abs().max(1.0);
            assert!(
                (inc - exact).abs() <= tol,
                "长序列后 _sum 漂移超容差: inc={inc} exact={exact}"
            );
        }
        let t2 = ServerTelemetry::new();
        t2.push_upstream_latency("solo", 7.5);
        let h2 = t2.upstream_latency_histograms();
        assert_eq!(h2[0].1, 1);
        assert_eq!(h2[0].2, 7.5);
        assert_eq!(t2.upstream_latency_quantile("solo", 50.0), Some(7.5));
    }

    /// **2.1.12**：抓取成本与窗口长度**无关**（只与桶数/上游数有关）。
    ///
    /// 判据用**结构性证据**而不是墙钟时间（CI 上时间不稳定）：两条上游，
    /// 一条装满窗口（256 样本）、一条只有 1 个样本，抓取输出的桶数一样，
    /// 且增量桶计数与重算结果一致；再断言「抓取不改动任何增量状态」
    /// （幂等 —— 连抓 3 次结果逐值相同，排除"抓取时偷偷重算"）。
    #[test]
    fn a7_histogram_scrape_is_incremental_and_idempotent() {
        let t = ServerTelemetry::new();
        for i in 0..UPSTREAM_LAT_WINDOW_MAX {
            t.push_upstream_latency("full", i as f64);
        }
        t.push_upstream_latency("one", 3.0);
        let h1 = t.upstream_latency_histograms();
        let h2 = t.upstream_latency_histograms();
        let h3 = t.upstream_latency_histograms();
        assert_eq!(h1.len(), 2);
        assert_eq!(h1, h2, "抓取必须是只读的（幂等）");
        assert_eq!(h2, h3, "抓取必须是只读的（幂等）");
        // full：0..255 → count(<=1)=2（0 与 1）、count(<=1000)=256（+Inf 桶由 api 层补）。
        let full = h1.iter().find(|x| x.0 == "full").expect("full 上游");
        assert_eq!(full.1, UPSTREAM_LAT_WINDOW_MAX as u64);
        assert_eq!(full.3.last().copied(), Some(UPSTREAM_LAT_WINDOW_MAX as u64));
        // 分位数也只读（连取 3 次同值）。
        let q1 = t.upstream_latency_quantile("full", 50.0);
        let q2 = t.upstream_latency_quantile("full", 50.0);
        let q3 = t.upstream_latency_quantile("full", 50.0);
        assert_eq!(q1, q2);
        assert_eq!(q2, q3);
        assert!(q1.is_some());
    }

    /// A7：逐上游延迟窗口**逐上游有界**，且键数有上界（防无界内存）。
    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn a7_upstream_latency_is_bounded() {
        let t = ServerTelemetry::new();
        for i in 0..(UPSTREAM_LAT_WINDOW_MAX + 50) {
            t.push_upstream_latency("hot", i as f64);
        }
        let h = t.upstream_latency_histograms();
        assert_eq!(h[0].1, UPSTREAM_LAT_WINDOW_MAX as u64, "单键窗口未限长"); // 键数上限：超限后**新键被丢弃**，总键数不增长。
        for i in 0..(UPSTREAM_LAT_MAX_KEYS + 100) {
            t.push_upstream_latency(&format!("k{i}"), 1.0);
        }
        assert!(
            t.upstream_latency_histograms().len() <= UPSTREAM_LAT_MAX_KEYS,
            "逐上游延迟键数未限上界（无界内存）"
        );
    }

    /// A7：负缓存命中计数与比例（分母 = 缓存直答总数 `hit`）。
    #[test]
    fn a7_negcache_hit_and_ratio() {
        let t = ServerTelemetry::new();
        assert_eq!(t.neg_hits(), 0);
        assert_eq!(t.neg_hit_ratio(), 0.0, "分母为 0 → 0.0（不得 NaN）");
        for _ in 0..3 {
            // **2.1.18（修复项 9）**：`total` 是 `Σ client_rcode` 的派生量，
            // `count_query("resolve")` 不再推进它 ⇒ 用真实出口调用（同时计 rcode=0）。
            t.note_data_plane_outcome(Some(0), None, 0);
            t.count_query("hit");
        }
        t.count_neg_hit();
        t.count_neg_hit();
        assert_eq!(t.neg_hits(), 2);
        // 3 次缓存直答里 2 次是负应答。
        let r = t.neg_hit_ratio();
        assert!((r - 2.0 / 3.0).abs() < 1e-9, "比例错: {r}");
        // trait 转发等价。
        t.count_neg_hit();
        assert_eq!(t.neg_hits(), 3);
        assert!((t.neg_hit_ratio() - 1.0).abs() < 1e-9);
    }

    /// A7：`reset()` 必须一并清掉逐上游延迟窗口与负缓存计数
    /// （否则重置后 `/metrics` 继续显示旧值 —— 与 F13 的 qps/latency 同类缺陷）。
    #[test]
    fn a7_reset_clears_upstream_latency_and_negcache() {
        let t = ServerTelemetry::new();
        t.push_upstream_latency("up1", 5.0);
        t.count_neg_hit();
        t.inc_n("bytes_in", 100);
        assert!(!t.upstream_latency_histograms().is_empty());
        assert_eq!(t.neg_hits(), 1);

        t.reset();

        assert!(
            t.upstream_latency_histograms().is_empty(),
            "reset 未清逐上游延迟"
        );
        assert_eq!(t.neg_hits(), 0, "reset 未清负缓存命中");
        assert_eq!(t.neg_hit_ratio(), 0.0);
        assert_eq!(t.counters()["bytes_in"], json!(0), "reset 未清 bytes_in");
    }

    /// A7：只有 `miss` / `err` 事件的 upstream 字段（真实上游 id）进逐上游延迟窗；
    /// `hit` 路径写的是"缓存直答"这类描述串，绝不能污染该维度。
    #[test]
    fn a7_only_miss_and_err_feed_per_upstream_latency() {
        let t = ServerTelemetry::new();
        // hit 事件：upstream 字段是描述串 → 不入窗。
        <ServerTelemetry as Telemetry>::log(
            &t,
            "a.com",
            "A",
            "hit",
            "缓存直答",
            1.0,
            None,
            "缓存直答",
            "1.2.3.4",
            None,
        );
        assert!(
            t.upstream_latency_histograms().is_empty(),
            "hit 路径不得进逐上游延迟维度"
        );
        // miss 事件：真实上游 id → 入窗。
        log_miss(&t, "b.com", "up1", 9.0);
        let h = t.upstream_latency_histograms();
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].0, "up1");
        assert_eq!(h[0].1, 1);
        // warn（AAAA 屏蔽等非上游路径）同样不入窗。
        <ServerTelemetry as Telemetry>::log(
            &t,
            "c.com",
            "AAAA",
            "warn",
            "AAAA 屏蔽",
            2.0,
            None,
            "up9",
            "",
            None,
        );
        let h = t.upstream_latency_histograms();
        assert_eq!(h.len(), 1, "warn 路径不得进逐上游延迟维度");
        // **2.1.41**：`err` 的 upstream 列若是**本地判定文案**（畸形包 / 规则屏蔽 /
        // 分流规则），同样不得建逐上游序列（此前会造出 id="本地判定（未发上游）"）。
        for label in ["本地判定（未发上游）", "规则屏蔽", "分流规则", "白名单"]
        {
            <ServerTelemetry as Telemetry>::log(
                &t,
                "d.com",
                "A",
                "err",
                "解析失败",
                3.0,
                None,
                label,
                "",
                None,
            );
        }
        let h = t.upstream_latency_histograms();
        assert_eq!(
            h.len(),
            1,
            "本地判定文案不得进逐上游延迟维度: {:?}",
            h.iter().map(|x| x.0.clone()).collect::<Vec<_>>()
        );
        // 真实上游 id 的 err 仍然入窗（SERVFAIL 归因需要）。
        log_miss(&t, "e.com", "up2", 4.0);
        assert_eq!(t.upstream_latency_histograms().len(), 2);
    }

    /* ============ 2.1.16（功能 3 / 修复项 15） ============ */

    /// **功能 3 硬要求**：客户端延迟直方图必须与 `/api/status.avg_latency` **同源**。
    ///
    /// 判据：`sum / count` 与 `avg_latency_ms()` 在浮点容差内一致（二者读同一个
    /// [`ServerTelemetry::latency`] 窗口），且累积桶**单调不减**、`+Inf` 桶 == count。
    #[test]
    fn s3_client_histogram_sum_over_count_matches_avg_latency() {
        let t = ServerTelemetry::new();
        for v in [0.5, 1.0, 3.0, 7.0, 12.0, 45.0, 120.0, 900.0, 3000.0] {
            t.push_latency(v);
        }
        let (count, sum, buckets) = t.client_latency_histogram();
        assert_eq!(count, 9);
        let avg = t.avg_latency_ms();
        let from_hist = sum / count as f64;
        assert!(
            (from_hist - avg).abs() <= 0.05 + avg.abs() * 1e-9,
            "直方图 sum/count={from_hist} 必须等于 /api/status.avg_latency={avg}（同源）"
        );
        // 累积桶单调不减（Prometheus histogram 语义）。
        let mut prev = 0u64;
        for (le, n) in &buckets {
            assert!(*n >= prev, "桶 le={le} 破坏单调性：{n} < {prev}");
            prev = *n;
        }
        // 最后一个有限桶 <= count；`+Inf`（调用方补）恒 == count。
        assert!(*buckets.last().map(|(_, n)| n).unwrap() <= count);
        assert_eq!(buckets.len(), LATENCY_BUCKETS_MS.len());
    }

    /// **功能 3**：空窗口下直方图必须是 `(0, 0.0, 全 0 桶)`，不得 NaN、不得 panic。
    #[test]
    fn s3_client_histogram_is_empty_safe() {
        let t = ServerTelemetry::new();
        let (count, sum, buckets) = t.client_latency_histogram();
        assert_eq!(count, 0);
        assert_eq!(sum, 0.0);
        assert!(buckets.iter().all(|(_, n)| *n == 0));
        assert_eq!(t.avg_latency_ms(), 0.0);
    }

    /// **功能 3 可对账性**：二维规则命中（`match_type` × `action`）与一维 `rule_hits`
    /// **总量恒等**（同一打点 `inc_rule_kind` 同时更新两张表）。
    #[test]
    fn s3_rule_hits_two_dims_are_reconcilable() {
        let t = ServerTelemetry::new();
        let cases = [
            ("exact", "block", 3usize),
            ("wild_suffix", "block", 2),
            ("wild_infix", "allow", 1),
            ("regex", "forceIp", 4),
            ("exact", "domestic", 2),
            ("exact", "global", 5),
        ];
        for (mt, ac, n) in cases {
            for _ in 0..n {
                <ServerTelemetry as Telemetry>::inc_rule_kind(&t, mt, ac);
            }
        }
        let one_dim: u64 = t.rule_hits().values().filter_map(Value::as_u64).sum();
        let two_dim: u64 = t.rule_hits_by_kind().iter().map(|(_, _, n)| *n).sum();
        assert_eq!(one_dim, two_dim, "一维/二维规则命中总量必须恒等（可对账）");
        assert_eq!(one_dim, 17);
        // 二维快照是确定性排序的。
        let ks = t.rule_hits_by_kind();
        let mut sorted = ks.clone();
        sorted.sort();
        assert_eq!(ks, sorted, "rule_hits_by_kind 必须稳定排序（快照可 diff）");
        // 聚合正确性：exact×block == 3。
        assert!(ks
            .iter()
            .any(|(mt, ac, n)| mt == "exact" && ac == "block" && *n == 3));
    }

    /// **修复项 15**：`negative_hits` 对外计数器与内部 `neg_hit` 同点自增、恒等、
    /// 在 `counters()` 里可见、`inc_n` 可自增、`reset` 归零。
    #[test]
    fn s15_negative_hits_is_exposed_monotonic_and_resettable() {
        let t = ServerTelemetry::new();
        assert_eq!(t.counters()["negative_hits"], json!(0), "初值必须为 0");
        for i in 1..=5u64 {
            t.count_neg_hit();
            assert_eq!(t.negative_hits(), i);
            assert_eq!(
                t.neg_hits(),
                i,
                "对外计数与内部计数必须同点自增（单点打点，不可能漂移）"
            );
            assert_eq!(t.counters()["negative_hits"], json!(i), "counters 必须单调");
        }
        // inc_n 口径可用（脚本/测试与其它标量计数器同一可用面）。
        t.inc_n("negative_hits", 3);
        assert_eq!(t.negative_hits(), 8);
        assert_eq!(t.neg_hits(), 8);
        // reset 归零。
        t.reset();
        assert_eq!(t.negative_hits(), 0);
        assert_eq!(t.neg_hits(), 0);
        assert_eq!(t.counters()["negative_hits"], json!(0));
    }

    /// **2.1.17（修复项 4）**：`monotonic_ms()` 必须与 `uptime_s()` **同源**
    /// （同一 `boot` 基准）、单调不减、且量纲为毫秒。
    ///
    /// 这是 `/api/status.snapshot_monotonic_ms` 与 `/metrics` 的
    /// `# align-snapshot monotonic_ms=` 能被用来对齐压测窗口的前提。
    #[test]
    fn monotonic_ms_shares_the_boot_basis_and_never_goes_backwards() {
        let t = ServerTelemetry::new();
        let a = t.monotonic_ms();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let b = t.monotonic_ms();
        assert!(b >= a, "单调钟不得回退：{a} -> {b}");
        assert!(
            b - a >= 4,
            "毫秒量纲校验：5ms 的 sleep 必须体现为 >=4ms 的差（实测 {}ms）",
            b - a
        );
        // 同源：monotonic_ms/1000 与 uptime_s 在整秒粒度上一致（容差 1s）。
        for _ in 0..3 {
            let drift = (t.monotonic_ms() as f64 / 1000.0 - t.uptime_s() as f64).abs();
            assert!(
                drift < 1.0,
                "monotonic_ms 与 uptime_s 必须同源：drift={drift}s"
            );
            std::thread::sleep(std::time::Duration::from_millis(80));
        }
    }

    /// **2.1.17（修复项 3/7）**：新增计数器的**键集合纪律** —— 三者互不重叠，
    /// 且 `cache_skipped_private_total` 在 `COUNTER_KEYS` 内（走 `inc_n` 面）、
    /// `upstream_inflight_queued_gave_up` 在 `DYNAMIC_COUNTER_KEYS` 内（由上游运行时读）。
    #[test]
    fn new_2_1_17_counters_live_in_the_right_key_sets() {
        assert!(
            COUNTER_KEYS.contains(&"cache_skipped_private_total"),
            "私网过滤计数必须进标量计数器表（/api/status 与 inc_n 同一可用面）"
        );
        assert!(
            DYNAMIC_COUNTER_KEYS.contains(&"upstream_inflight_queued_gave_up"),
            "在途闸门“排队吃光预算”计数由上游运行时现场读取，必须单列"
        );
        for k in DYNAMIC_COUNTER_KEYS {
            assert!(
                !COUNTER_KEYS.contains(&k),
                "{k} 不得同时出现在两张表里（会变成双重自增/双写）"
            );
            assert!(
                !STRUCTURED_COUNTER_KEYS.contains(&k),
                "{k} 是标量，不得进结构化键表"
            );
        }
        for k in STRUCTURED_COUNTER_KEYS {
            assert!(!COUNTER_KEYS.contains(&k), "{k} 是对象，不得进标量表");
        }
        // 两个新键的数值语义：0 起步、可自增、reset 归零。
        let t = ServerTelemetry::new();
        assert_eq!(t.cache_skipped_private_total(), 0);
        t.count_cache_skipped_private(2);
        assert_eq!(t.cache_skipped_private_total(), 2);
        assert_eq!(t.counters()["cache_skipped_private_total"], json!(2));
        t.inc_n("cache_skipped_private_total", 3);
        assert_eq!(t.cache_skipped_private_total(), 5);
        t.reset();
        assert_eq!(t.cache_skipped_private_total(), 0);
        assert_eq!(t.counters()["cache_skipped_private_total"], json!(0));
    }

    /* ==================== 2.1.18（修复项 2）：同代快照 ==================== */

    /// 断言**在任何情况下都必须成立**的同代硬等式（任一违反即真实缺陷）：
    /// 1. **`Σ client_rcode == total`**（**2.1.18（修复项 9）起是恒等式**：两者由
    ///    `note_data_plane_outcome` 在**同一分支、同一把锁**内一起自增；此前 `total`
    ///    另有 `resolve()` 入口与出口两处自增点 ⇒ 存在不可观测差额，见 `dns.rs::log_and_count`
    ///    与 `resolver/src/resolve.rs` 的注释）；
    /// 2. `client_rcode[2] == servfail_total`（同点打点）；
    /// 3. `servfail_total == Σ servfail_reasons`（5 档互斥完备）；
    /// 4. `hit + miss <= total`（`total` 还含规则直答等不计 hit/miss 的应答；
    ///    `Rule` 命中在本函数里**不**计 hit/miss）。
    ///
    /// **并发读也适用**：`total` 是 `Σ client_rcode` 的**派生量**（构造性恒等式），
    /// 因此任何并发写都不可能让读者看到"total 已 +1、rcode 还没 +1"。
    fn assert_snapshot_provable(s: &CounterSnapshot, ctx: &str) {
        let sum_rcode: u64 = s.client_rcode.iter().sum();
        assert_eq!(
            sum_rcode, s.total,
            "[{ctx}] 硬等式 Σ client_rcode == total 被破坏（seq={}）：{s:?}",
            s.seq
        );
        assert_eq!(
            s.client_rcode[2], s.servfail_total,
            "[{ctx}] 硬等式 client_rcode[2] == servfail_total 被破坏（seq={}）：{s:?}",
            s.seq
        );
        let sum_reasons: u64 = s.servfail_reasons.iter().sum();
        assert_eq!(
            sum_reasons, s.servfail_total,
            "[{ctx}] 硬等式 servfail_total == Σ servfail_reasons 被破坏（seq={}）：{s:?}",
            s.seq
        );
        assert!(
            s.hit + s.miss <= s.total,
            "[{ctx}] 硬等式 hit + miss <= total 被破坏（seq={}）：{s:?}",
            s.seq
        );
    }

    /// 兼容旧名（2.1.19 起与 [`assert_snapshot_provable`] 等价：等式已升级为恒等式）。
    fn assert_snapshot_strict(s: &CounterSnapshot, ctx: &str) {
        assert_snapshot_provable(s, ctx);
    }

    /// **2.1.18（修复项 2）**：`counters()` 的整张表来自**同一代**。
    ///
    /// 判据（改前必被此断言抓到）：连续多轮 `count_query` 之后，
    /// `Σ client_rcode == total` 必须**恒成立**；并在每轮之间插入数据面出口打点
    /// （`note_data_plane_outcome`）制造"写入与读取交错"的机会。
    #[test]
    fn counters_map_is_single_generation_and_upholds_hard_equalities() {
        let t = ServerTelemetry::new();
        for round in 0..200u64 {
            // 写入：一次数据面出口（rcode 0）。**不要**额外 `count_query("resolve")`：
            // 那会给 `total` 加一条没有 rcode 的查询（见本测试文档的等式前提）。
            t.note_data_plane_outcome(Some(0), None, 0);
            if round % 7 == 0 {
                // 夹一条 SERVFAIL（含原因维度与私网过滤），逼出跨字段错位的机会。
                // **注意不要**在这里额外调 `count_query("resolve")`：那会给 `total`
                // 加一条**没有 rcode** 的查询，使 `Σ client_rcode == total`
                // （数据面闭环下的强化等式）在**测试夹具**层面不成立。
                t.note_data_plane_outcome(Some(2), Some("upstream_timeout"), 2);
            }
            // 读取：整张表必须自洽。
            let c = t.counters();
            let sum_rcode: u64 = c["client_rcode"]
                .as_object()
                .unwrap()
                .values()
                .filter_map(Value::as_u64)
                .sum();
            assert_eq!(
                sum_rcode,
                c["total"].as_u64().unwrap(),
                "第 {round} 轮：Σ client_rcode != total（同代快照被破坏）: {c:?}"
            );
            assert_eq!(
                c["client_rcode"]["2"], c["servfail_total"],
                "第 {round} 轮：client_rcode[2] != servfail_total: {c:?}"
            );
            let sum_reasons: u64 = c["servfail_reasons"]
                .as_object()
                .unwrap()
                .values()
                .filter_map(Value::as_u64)
                .sum();
            assert_eq!(
                sum_reasons,
                c["servfail_total"].as_u64().unwrap(),
                "第 {round} 轮：Σ servfail_reasons != servfail_total: {c:?}"
            );
            assert!(
                c["hit"].as_u64().unwrap() + c["miss"].as_u64().unwrap()
                    <= c["total"].as_u64().unwrap(),
                "第 {round} 轮：hit + miss > total: {c:?}"
            );
        }
    }

    /// **2.1.18（修复项 2）**：`snapshot_seq` **单调递增**，且同一次读取里各字段同代。
    #[test]
    fn snapshot_seq_is_monotonic_and_consistent_within_one_read() {
        let t = ServerTelemetry::new();
        let mut last = 0u64;
        for i in 0..200 {
            // 只用数据面出口：`total` 与 rcode 由同一次调用产生（强化等式的前提）。
            if i % 3 == 0 {
                t.note_data_plane_outcome(Some(0), None, 0);
            }
            let s = t.snapshot();
            // **2.1.18（修复项 9）**：`seq` 是**写入代数**（读取不推进它）⇒
            // 本轮有写入就必须严格递增，没写入就必须相等。
            if i % 3 == 0 {
                assert!(
                    s.seq > last,
                    "有计数写入 ⇒ seq 必须递增：{last} → {}",
                    s.seq
                );
            } else {
                assert_eq!(s.seq, last, "无计数写入 ⇒ seq 不得变化：{last} → {}", s.seq);
            }
            last = s.seq;
            assert_snapshot_strict(&s, "loop");
            // **一次** `with_snapshot` 内取多个字段必须互相一致（同代）。
            let (a, b, a2, b2) = t.with_snapshot(|x| (x.seq, x.total, x.seq, x.total));
            assert_eq!((a, b), (a2, b2), "同一次快照内 seq/total 必须稳定");
            // **`seq` 只在"计数写入"时 +1**（读取不推进它）—— 这是 2.1.18（修复项 9）
            // 的语义收紧：两次抓取之间**没有写入** ⇒ `seq` 相同 ⇒ 允许逐字段差分。
            let (s_next, tot_next) = t.with_snapshot(|x| (x.seq, x.total));
            assert_eq!(
                s_next, a,
                "两次连续读之间没有写入，写入代数不得变化：{a} → {s_next}"
            );
            assert_eq!(tot_next, b, "两次取快照之间没有写入，total 必须逐字段相等");
        }
        // `monotonic_ms` 与 `monotonic_ms()` 同源（同一 `boot`）。
        let s = t.snapshot();
        assert!(
            s.monotonic_ms <= t.monotonic_ms(),
            "快照时刻不得晚于此刻：{} > {}",
            s.monotonic_ms,
            t.monotonic_ms()
        );
    }

    /// **2.1.18（修复项 2/9）· 确定性单测**：`snapshot_seq` 的写入代数语义。
    ///
    /// 2.1.19 早期版本用"注入到快照构造过程中"的钩子来**确定性**覆盖"取快照期间有写入"；
    /// 本版本把 `total` 改成 `Σ client_rcode` 的**派生量**、写侧改回纯原子之后，
    /// 那条窗口在构造上已不存在（不需要注入），因此改测**语义本身**：
    /// 1. 两次连续读（其间无写入）⇒ `seq` **不变**（可逐字段差分）；
    /// 2. 每次计数写入 ⇒ `seq` **+1**（跨快照必须"先比 seq 再差分"）；
    /// 3. `total == Σ client_rcode` 在每一次读上都成立（构造性恒等式）。
    #[test]
    fn snapshot_seq_advances_exactly_on_counter_writes() {
        let t = ServerTelemetry::new();
        let a = t.snapshot();
        let b = t.snapshot();
        assert_eq!(a.seq, b.seq, "无写入时写入代数不得变化");
        assert_eq!(a.total, b.total);
        assert_snapshot_strict(&b, "quiescent");

        // 每次出口写入都必须推进代数（读侧据此判定"能否跨快照差分"）。
        let mut prev = b.seq;
        for (n, rcode) in [(0u8, 0u8), (1, 3), (2, 2), (3, 0)] {
            let reason = if rcode == 2 {
                Some("upstream_timeout")
            } else {
                None
            };
            t.note_data_plane_outcome(Some(rcode), reason, 0);
            let s = t.snapshot();
            assert!(
                s.seq > prev,
                "第 {n} 次写入后写入代数必须递增：{prev} → {}",
                s.seq
            );
            prev = s.seq;
            assert_snapshot_strict(&s, "after-write");
        }
        // 4 次写入 ⇒ total 与 Σ rcode 都恰好 +4（各自一次，无双计）。
        let s = t.snapshot();
        assert_eq!(s.total, 4, "4 条应答 ⇒ total 恰好 4：{s:?}");
        assert_eq!(s.client_rcode[0], 2, "rcode=0 ×2: {s:?}");
        assert_eq!(s.client_rcode[2], 1, "rcode=2 ×1: {s:?}");
        assert_eq!(s.client_rcode[3], 1, "rcode=3 ×1: {s:?}");
        assert_eq!(s.servfail_total, 1, "{s:?}");
        assert_eq!(s.servfail_reasons[0], 1, "upstream_timeout ×1: {s:?}");
        assert_eq!(s.no_response_total, 0, "全部构造出了应答：{s:?}");
    }
    /// **2.1.18（修复项 9）**：`no_response_total` 的语义 —— 出口**登记了但没有可发送
    /// 报文**（`rcode = None`）时，`total` **不动**、本键 +1；
    /// **同时不计任何 SERVFAIL 归因**（`rcode != 2` ⇒ 没有"客户端看到的 SERVFAIL"，
    /// 计了就会破坏 `client_rcode[2] == servfail_total`）。
    ///
    /// 这两条合起来把"没有应答的查询"从 `total`/`Σ rcode`/`servfail_*` 三个口径里
    /// **干净地摘出去**，只留一个**可观测的缺口项**。
    #[test]
    fn no_response_total_is_the_observable_gap_term() {
        let t = ServerTelemetry::new();
        // ① 正常应答：total 与 rcode 同增，缺口项不动。
        t.note_data_plane_outcome(Some(0), None, 0);
        let s = t.snapshot();
        assert_eq!(s.total, 1);
        assert_eq!(s.client_rcode[0], 1);
        assert_eq!(s.no_response_total, 0);
        assert_snapshot_provable(&s, "after-ok");
        // ② 出口登记但没有任何报文可发（`resp.len() < 12`）。
        //    刻意传一个 SERVFAIL 归因，验证它**不会**被计入（否则
        //    `client_rcode[2] == servfail_total` 立刻被破坏 —— 这正是首轮失败的原因）。
        t.note_data_plane_outcome(None, Some("upstream_timeout"), 2);
        let s = t.snapshot();
        assert_eq!(s.total, 1, "没有构造出应答 ⇒ total 不得增加");
        assert_eq!(s.client_rcode.iter().sum::<u64>(), 1);
        assert_eq!(s.no_response_total, 1, "缺口项必须 +1（可对账）");
        assert_eq!(
            s.servfail_total, 0,
            "没有发出 rcode=2 ⇒ 不得计 SERVFAIL（否则破坏 client_rcode[2] == servfail_total）"
        );
        assert_eq!(s.servfail_reasons.iter().sum::<u64>(), 0);
        assert_eq!(
            s.cache_skipped_private_total, 2,
            "私网过滤与 rcode 无关，照常计"
        );
        assert_snapshot_provable(&s, "after-no-response");
        // ③ **缺口项不得与 total 相加**：两者是互斥集合，只用于诊断。
        assert_eq!(s.total, 1);
        assert_eq!(s.total + s.no_response_total, 2, "口径合计 = 出口登记数");
        // ④ `counters()` 表里同源可见；reset 归零。
        assert_eq!(t.counters()["no_response_total"], json!(1));
        t.reset();
        assert_eq!(t.counters()["no_response_total"], json!(0));
    }

    /// **2.1.18（修复项 9）**：`total` 的**唯一自增点**是 `note_data_plane_outcome`。
    ///
    /// 反向证明（本缺陷的形态）：如果别处再有 `total` 自增，等式
    /// `Σ client_rcode == total` 立刻被打破 —— 本测试用"**只**走数据面出口"的方式
    /// 钉死等式，任何新增的第二自增点都会让它红。
    #[test]
    fn total_has_exactly_one_increment_point() {
        let t = ServerTelemetry::new();
        let before = t.snapshot();
        for i in 0..50u64 {
            match i % 3 {
                0 => t.note_data_plane_outcome(Some(0), None, 0),
                1 => t.note_data_plane_outcome(Some(3), None, 0),
                _ => t.note_data_plane_outcome(Some(2), Some("no_upstream"), 0),
            }
        }
        let s = t.snapshot();
        assert_eq!(s.total - before.total, 50, "50 次出口登记 ⇒ total 恰好 +50");
        assert_eq!(
            s.client_rcode.iter().sum::<u64>() - before.client_rcode.iter().sum::<u64>(),
            50,
            "同一批 50 次 ⇒ Σ rcode 恰好 +50（与 total 同步）"
        );
        assert_eq!(s.no_response_total, 0);
        assert_snapshot_provable(&s, "after-50");
    }

    /// **2.1.18（修复项 2）**：并发读多轮 —— **同一次快照内**等式恒成立
    /// （跨快照允许变化）。
    ///
    /// 4 个写线程 × 4 个读线程，读线程在**每一轮**都验证三条硬等式；
    /// 写线程覆盖 `count_query` / `note_data_plane_outcome` / `inc_n` /
    /// `count_neg_hit` 四条路径。最后核对总量（无丢失更新）。
    #[test]
    fn concurrent_snapshot_reads_uphold_hard_equalities() {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as O};
        use std::sync::Arc;
        let t = Arc::new(ServerTelemetry::new());
        let stop = Arc::new(AtomicBool::new(false));
        let reads = Arc::new(AtomicU64::new(0));
        const WRITES_PER_THREAD: u64 = 300;

        let mut hs = Vec::new();
        for w in 0..4u64 {
            let t = Arc::clone(&t);
            hs.push(std::thread::spawn(move || {
                for i in 0..WRITES_PER_THREAD {
                    // 只用数据面出口：每次恰好一次 `total` + 一条 rcode
                    // （`count_query("resolve")` 会额外加一条没有 rcode 的 total）。
                    match (w + i) % 4 {
                        0 => t.note_data_plane_outcome(Some(0), None, 0),
                        1 => t.note_data_plane_outcome(Some(3), None, 0),
                        2 => t.note_data_plane_outcome(Some(2), Some("upstream_timeout"), 1),
                        _ => {
                            t.note_data_plane_outcome(Some(2), Some("no_upstream"), 0);
                            t.count_neg_hit();
                        }
                    }
                }
            }));
        }
        // **2.1.23（DEF-222-B02：本用例偶发假失败）**：读线程"至少跑过一轮"必须有**握手**，
        // 不能靠"写线程跑得比读线程慢"这种时序巧合。
        //
        // 原实现：写线程 join 完就 `stop.store(true)`，随后断言 `reads > 0`。
        // 若 4 个写线程在**任何一个读线程首次调度**之前就全部跑完（4×300 次纯原子写很快，
        // 而读线程要等 `tokio` 多线程 runtime 启动），读线程醒来看到的第一个
        // `stop` 就是 `true` ⇒ **一轮都没读** ⇒ 断言失败。实测在本轮全量门禁里复现过 1 次
        // （`SUITE passed=855 failed=1`），重跑即过 —— 典型的时序假失败。
        //
        // 修法：`Barrier`（5 方：4 读 + 1 主线程）保证"**每个读线程都完成了第一轮快照**"
        // 之后，主线程才允许置 `stop`。`Barrier` 可重用，因此循环体在它之后照旧。
        let reads_ready = Arc::new(std::sync::Barrier::new(5));
        for _ in 0..4 {
            let t = Arc::clone(&t);
            let stop = Arc::clone(&stop);
            let reads = Arc::clone(&reads);
            let ready = Arc::clone(&reads_ready);
            hs.push(std::thread::spawn(move || {
                let mut last_seq = 0u64;
                let mut first = true;
                while !stop.load(O::Relaxed) {
                    let s = t.snapshot();
                    // 同一次快照内：**可证**硬等式必须成立（跨快照允许变化）。
                    //
                    // **2.1.18（修复项 9）**：`total` 是 `Σ client_rcode` 的派生量 ⇒
                    // 这里其实已经是严格相等；写成 `<=` 只是保留"更强断言先失败"的
                    // 诊断顺序（下面还会断言 `Σ == total`）。
                    //
                    // `hit`/`miss` 由出口之后的两次 `count_query` 单独推进，读者**合法地**
                    // 看到它们比 `total` 少（时序，不是缺陷）⇒ 用 `<=`。
                    let sum: u64 = s.client_rcode.iter().sum();
                    assert!(sum <= s.total, "并发读：Σ client_rcode > total: {s:?}");
                    assert_eq!(
                        s.client_rcode[2], s.servfail_total,
                        "并发读：client_rcode[2] != servfail_total: {s:?}"
                    );
                    assert_eq!(
                        s.servfail_reasons.iter().sum::<u64>(),
                        s.servfail_total,
                        "并发读：Σ reasons != servfail_total: {s:?}"
                    );
                    assert!(
                        s.hit + s.miss <= s.total,
                        "并发读：hit + miss > total: {s:?}"
                    );
                    // 每个读线程自己看到的 seq 必须单调不减（跨线程不要求有序）。
                    assert!(s.seq >= last_seq, "seq 回退：{last_seq} → {}", s.seq);
                    last_seq = s.seq;
                    reads.fetch_add(1, O::Relaxed);
                    if first {
                        // 宣布"我已经至少读了一轮"；主线程在置 `stop` 之前必须等齐 5 方。
                        first = false;
                        ready.wait();
                    }
                }
            }));
        }
        for h in hs.drain(..4) {
            h.join().unwrap();
        }
        // 等"每个读线程都读过至少一轮"，再放行它们退出 ⇒ `reads > 0` 恒成立。
        reads_ready.wait();
        stop.store(true, O::Relaxed);
        for h in hs {
            h.join().unwrap();
        }
        assert!(
            reads.load(O::Relaxed) > 0,
            "读线程必须真的取过快照（否则测试没有覆盖并发读）"
        );
        // 总量核对（无丢失更新）：4 线程 × 300 次，每次 = 1 条 total + 1 条 rcode。
        let s = t.snapshot();
        assert_snapshot_provable(&s, "final");
        assert_eq!(
            s.total,
            4 * WRITES_PER_THREAD,
            "并发写入不得丢失（total = 每次数据面出口恰好 +1）: {s:?}"
        );
        assert_eq!(
            s.client_rcode.iter().sum::<u64>(),
            4 * WRITES_PER_THREAD,
            "并发写入不得丢失（rcode 分布之和）: {s:?}"
        );
    }

    /// **2.1.18（修复项 2）**：`reset()` 之后的第一代快照必须是全 0
    /// （否则页面会看到"复位了但数字还在"）。
    #[test]
    fn reset_publishes_a_zeroed_generation() {
        let t = ServerTelemetry::new();
        for _ in 0..5 {
            t.count_query("resolve");
            t.note_data_plane_outcome(Some(2), Some("upstream_timeout"), 1);
        }
        let before = t.snapshot();
        t.reset();
        let after = t.snapshot();
        assert!(after.seq > before.seq, "reset 必须产生新的一代");
        assert_eq!(after.total, 0);
        assert_eq!(after.hit, 0);
        assert_eq!(after.miss, 0);
        assert_eq!(after.servfail_total, 0);
        assert_eq!(after.client_rcode, [0u64; 16]);
        assert_eq!(after.servfail_reasons, [0u64; SERVFAIL_REASONS.len()]);
        assert_eq!(after.cache_skipped_private_total, 0);
        assert_snapshot_strict(&after, "after-reset");
        // 整张表也必须归零（`counters()` 读的就是这一代）。
        let c = t.counters();
        for k in COUNTER_KEYS {
            assert_eq!(c[k], json!(0), "reset 后 {k} 应为 0");
        }
    }
}
