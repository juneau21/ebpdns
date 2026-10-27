//! 前端数据模型：字段与 v1.9.162 `/api/*` 契约一一对应。
//!
//! 后端（`crates/ebpdns-server`）在同一响应中同时保留 2.0 原有键并补齐本模块所需
//! 的 v1.9.162 兼容键，因此控制台页面可直接按原契约渲染。
use serde::de::{self, Visitor};
use serde::Deserialize;
use serde::Deserializer;

/// `ts` / `manual_history[].ts` 兼容两种后端形状：
/// - 数字（epoch 秒，2.0 原始形状）→ 由 wasm 侧格式化为本地 `HH:MM:SS.mmm`；
/// - 字符串（v1.9.162 形状）→ 原样使用。
fn de_ts<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    struct TsVisitor;
    impl<'de> Visitor<'de> for TsVisitor {
        type Value = String;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("epoch 秒数字或时间字符串")
        }
        fn visit_f64<E: de::Error>(self, v: f64) -> Result<String, E> {
            Ok(crate::fmt::hms_ms(v))
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> Result<String, E> {
            Ok(crate::fmt::hms_ms(v as f64))
        }
        fn visit_i64<E: de::Error>(self, v: i64) -> Result<String, E> {
            Ok(crate::fmt::hms_ms(v as f64))
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<String, E> {
            Ok(v.to_string())
        }
        fn visit_string<E: de::Error>(self, v: String) -> Result<String, E> {
            Ok(v)
        }
    }
    d.deserialize_any(TsVisitor)
}

/// `/api/status` → `.map`
/// **2.1.36（C 批）**：删除前端从未读取的 `pct` 镜像字段（后端 `/api/status.map.pct`
/// 契约不变、照旧下发；`serde` 忽略未知键）。页面用量由 `used/capacity` 现算。
#[derive(Clone, Debug, Default, Deserialize)]
pub struct MapInfo {
    #[serde(default)]
    pub used: f64,
    #[serde(default)]
    pub capacity: f64,
}

/* ===================== v2.1.8 宽松可选字段解析 ===================== */

/// 后端联调期字段可能**缺失**、或类型在数字/字符串/bool 之间变动；
/// 这些 helper 一律吞掉异常形态并回退 `None`（页面显示 `–`），
/// **绝不**让整份 `/api/snapshot` 反序列化因为一个新增字段而失败。
/// 任意标量 → `Option<f64>`（数字 / 可解析字符串 / bool→0|1；其余 → None）。
fn de_opt_f64<'de, D: Deserializer<'de>>(d: D) -> Result<Option<f64>, D::Error> {
    Ok(match Option::<serde_json::Value>::deserialize(d)? {
        Some(serde_json::Value::Number(n)) => n.as_f64(),
        Some(serde_json::Value::String(s)) => s.trim().parse::<f64>().ok(),
        Some(serde_json::Value::Bool(b)) => Some(if b { 1.0 } else { 0.0 }),
        _ => None,
    })
}

/// 任意标量 → `Option<bool>`（bool / 0|1 / "true|open|yes|on" 等；其余 → None）。
fn de_opt_bool<'de, D: Deserializer<'de>>(d: D) -> Result<Option<bool>, D::Error> {
    Ok(match Option::<serde_json::Value>::deserialize(d)? {
        Some(serde_json::Value::Bool(b)) => Some(b),
        Some(serde_json::Value::Number(n)) => n.as_f64().map(|x| x != 0.0),
        Some(serde_json::Value::String(s)) => match s.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" | "open" => Some(true),
            "0" | "false" | "no" | "off" | "closed" => Some(false),
            _ => None,
        },
        _ => None,
    })
}

/// 任意标量 → `Option<String>`（字符串原样；数字/bool 转文本；其余 → None）。
fn de_opt_str<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Ok(match Option::<serde_json::Value>::deserialize(d)? {
        Some(serde_json::Value::String(s)) => Some(s),
        Some(serde_json::Value::Number(n)) => Some(n.to_string()),
        Some(serde_json::Value::Bool(b)) => Some(b.to_string()),
        _ => None,
    })
}

/// `/api/status` → `.counters`
///
/// `servfail_total` 是 2.1.15 新增的服务端 SERVFAIL 计数（与 `errors` 口径不同）。
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Counters {
    #[serde(default)]
    pub total: f64,
    #[serde(default)]
    pub hit: f64,
    #[serde(default)]
    pub miss: f64,
    #[serde(default)]
    pub upstream_queries: f64,
    #[serde(default)]
    pub errors: f64,
    /// **2.1.15（P1）**：真的回给客户端的 SERVFAIL（`rcode == 2`）总数。
    #[serde(default)]
    pub servfail_total: f64,
    /// **2.1.16（修复项 15）**：负缓存（NXDOMAIN / NODATA）命中数。
    ///
    /// 与 `/metrics` 的 `ebpdns_negative_cache_hits_total` **同源**（同一打点
    /// `ServerTelemetry::count_neg_hit`）。负缓存条目参与落盘/恢复（含剩余 TTL），
    /// 因此重启前后该计数**只增不减**。
    #[serde(default)]
    pub negative_hits: f64,
    /// **2.1.15（P1）**：SERVFAIL 的 5 档**互斥归因**（键 = 原因，值 = 次数）。
    ///
    /// **2.1.18（修复项 8）**：此前未反序列化（前端只读总数）。现在要区分
    /// "后端没有分档归因（旧版本）"与"有归因但当前为 0"，因此必须把键收进来
    /// （判空见 [`Counters::has_servfail_reasons`]）。
    #[serde(default)]
    pub servfail_reasons: std::collections::HashMap<String, f64>,
    /// **2.1.16（修复项 8）**：服务端实际发出的 rcode 分布（16 槽，键 `"0"`..`"15"`）。
    ///
    /// 前端只消费 `"2"` 这一槽（"客户端 rcode=2" KPI），但**完整反序列化**整张表，
    /// 便于以后加"rcode 分布"图而不需要再改契约。
    /// 硬等式：`client_rcode["2"] == servfail_total`（同一打点；
    /// 两者不等即为服务端缺陷，见 `scripts/f216-counters-reconcile.py` 的 R3）。
    #[serde(default)]
    pub client_rcode: std::collections::HashMap<String, f64>,
}

impl Counters {
    /// **2.1.16（修复项 8）**：客户端 rcode=2 计数（服务端侧自证口径）。
    ///
    /// 缺失该键（旧后端）时返回 0 —— 此时 KPI 显示 0，页面**不会**报错；
    /// 与 `servfail_total` 的差异本身就是"该后端不支持自证口径"的信号。
    pub fn client_rcode2(&self) -> f64 {
        self.client_rcode.get("2").copied().unwrap_or(0.0)
    }

    /// **2.1.18（修复项 8）**：后端是否**支持服务端自证口径**（`counters.client_rcode`）。
    ///
    /// 判据 = **键是否存在**（不是值是否非 0）。空表（`{}`）也算"不支持"：
    /// `client_rcode` 是 16 槽**定长**分布，合法后端只要存在该键就必然有 16 个槽
    /// （见后端单测 `client_rcode 必须是 16 槽定长分布`）。因此"键在、槽空"只可能来自
    /// 手工构造的响应，按不支持处理更安全（避免把"没有这个口径"显示成"这个口径为 0"）。
    pub fn has_client_rcode(&self) -> bool {
        !self.client_rcode.is_empty()
    }

    /// **2.1.18（修复项 8）**：后端是否返回了 SERVFAIL 的**分档归因**
    /// （`counters.servfail_reasons`）。
    ///
    /// 判据同上：键存在且非空。旧后端（2.1.15 之前）没有该键 ⇒ KPI 副标题必须说明
    /// "该后端无分档归因"，而不是静默显示"0 档"。
    pub fn has_servfail_reasons(&self) -> bool {
        !self.servfail_reasons.is_empty()
    }
}

/// `/api/status` → `.rule_hits`（键名保持 Python 侧的 camelCase `forceIp`）
#[derive(Clone, Debug, Default, Deserialize)]
pub struct RuleHits {
    #[serde(default)]
    pub block: f64,
    #[serde(default)]
    pub domestic: f64,
    #[serde(default)]
    pub global: f64,
    #[serde(default, rename = "forceIp")]
    pub force_ip: f64,
    #[serde(default)]
    pub allow: f64,
}

/// `/api/status`
///
/// **2.1.14 清理（审计 ⑥）**：删除两个**从无消费点**的字段
/// （`config_path` / `running`，全仓 grep 只有定义处）—— 后端仍在返回它们
/// （`/api/status` 的公开契约不变），前端只是不再反序列化（serde 默认忽略未知键）。
/// **2.1.18（修复项 18）**：`/api/status.cache`（= `/api/cache/stats` 摘要）。
///
/// 用途：**「用户态缓存占用」卡片**的数据源（`used`/`capacity`）——
/// 旧实现把这份数字渲染在内核态占用卡里（标签-来源不符）。
/// `window`/`probation`/`protected` 是 **TinyLFU 的条目数**（不是容量），
/// `capacity` = 配置 `cache_size`。
#[derive(Clone, Debug, Default, Deserialize)]
pub struct CacheInfo {
    #[serde(default)]
    pub used: f64,
    #[serde(default)]
    pub capacity: f64,
    /// 百分比（0–100，一位小数）：`used / capacity * 100`。
    #[serde(default)]
    pub pct: f64,
    /// TinyLFU：window 段**条目数**（其余策略缺省 0）。
    #[serde(default)]
    pub window: f64,
    /// TinyLFU：probation 段**条目数**。
    #[serde(default)]
    pub probation: f64,
    /// TinyLFU：protected 段**条目数**。
    #[serde(default)]
    pub protected: f64,
    /// **2.1.19（修复项 3 / R9）**：落盘现场（`/api/status.cache.persist`）。
    ///
    /// 2.1.18 只有 `/api/cache/stats` 有这份数据，而配置页读的是 `/api/status`
    /// ⇒ R9「配置页显示最近落盘时间」在 2.1.18 无法实现。现在两个端点同源。
    #[serde(default)]
    pub persist: PersistInfo,
    /// **2.1.19（修复项 1）**：启动恢复的丢弃计数（legacy/expired/failed）。
    #[serde(default)]
    pub restore_drops: RestoreDrops,
}

/// **2.1.19（修复项 3 / R9）**：缓存**落盘现场**（`/api/status.cache.persist`
/// = `/api/cache/stats.persist`，后端唯一实现 = `api.rs::cache_persist_info`）。
///
/// 用途：配置页「缓存持久化」行显示**最近一次落盘时间 / 内存条目数 / 文件路径**，
/// 并区分两种空态（未开启持久化 / 已开启但文件不存在）。
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PersistInfo {
    /// 配置 `cache_persist`（总开关）。
    #[serde(default)]
    pub enabled: bool,
    /// 配置 `cache_save_interval`（0 = 只在优雅退出时落盘）。
    #[serde(default)]
    pub interval_s: u64,
    /// 实际路径（来自配置 `cache_file`，**不是**硬编码）。
    #[serde(default)]
    pub file: String,
    #[serde(default)]
    pub exists: bool,
    #[serde(default)]
    pub bytes: u64,
    /// 文件 mtime（epoch 秒）。
    #[serde(default)]
    pub mtime_s: u64,
    /// 距最近一次落盘的秒数（**只增不减 ⇒ 可直接判定"未周期落盘"**）。
    #[serde(default)]
    pub age_s: u64,
    /// **内存**条目数（文件里的条数只有落盘那一刻才知道，两个口径不可混用）。
    #[serde(default)]
    pub entries: u64,
    /// 后端给出的可读原因（空态 / 超期提示），前端直接显示，不自行拼文案。
    #[serde(default)]
    pub note: String,
}

/// **2.1.19（修复项 1）**：最近一次启动恢复（`restore`）的**丢弃计数**
/// （`/api/status.cache.restore_drops` = `/api/cache/stats.restore_drops`）。
///
/// 为什么要在页面上可见：2.1.18 的 legacy 计数只存在于日志行与进程内部，
/// 部署侧无法用脚本断言"旧格式确实被丢弃且被计数"。现在它是**状态字段**。
#[derive(Clone, Debug, Default, Deserialize)]
pub struct RestoreDrops {
    /// 文件里的绝对到期时间已过而丢弃的条数。
    #[serde(default)]
    pub expired: u64,
    /// **旧格式**（缺绝对 `expires_at`、只有 `remaining`）按安全侧丢弃的条数。
    #[serde(default)]
    pub legacy: u64,
    /// 记录损坏（缺字段/类型不符）而丢弃的条数。
    #[serde(default)]
    pub failed: u64,
    /// **2.1.43-B（P2-4）**：快照里写了、但恢复只灌 TinyLFU 的 main 段 ⇒ 被挤出的条数
    /// （≈ window 段容量，出厂 1%）。lru/partitioned 恒 0。
    #[serde(default)]
    pub window_unpersisted: u64,
}

/// **2.1.49（AUD-09）**：`/api/status.process` —— 进程自观测（RSS/VM/threads/fds）。
///
/// 每个字段都用 `Option`：**字段缺失 = 旧后端/未采集**，页面显示“不可用”；
/// 字段存在且为 0 是**真实 0**（不得把“没有这个字段”降级成 0）。
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ProcessInfo {
    #[serde(default)]
    pub resident_memory_bytes: Option<u64>,
    #[serde(default)]
    pub virtual_memory_bytes: Option<u64>,
    #[serde(default)]
    pub threads: Option<u64>,
    #[serde(default)]
    pub open_fds: Option<u64>,
    #[serde(default)]
    pub state_missing_parts: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Status {
    #[serde(default)]
    pub app: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub uptime_s: f64,
    #[serde(default)]
    pub qps: f64,
    #[serde(default)]
    pub hit_rate: f64,
    #[serde(default)]
    pub avg_latency_ms: Option<f64>,
    #[serde(default)]
    pub map: MapInfo,
    #[serde(default)]
    pub counters: Counters,
    #[serde(default)]
    pub rule_hits: RuleHits,
    /// **2.1.43-B（P2-1）**：`Option<String>`（不是 `String`）—— 用来区分
    /// 「后端明确下发了 `cache_policy`」与「**字段缺失/解析不出**」。
    ///
    /// 为什么必须区分：遥测页的 TinyLFU 三段（window/probation/protected）只有
    /// `cache_policy=tinylfu` 时才有意义；旧实现是 `String` + `#[serde(default)]`，
    /// 字段缺失时得到空串，与 `lru/partitioned` 无法区分 ⇒ 页面只能把
    /// "**未采集**"和"**真 0**"一起显示成 `–`/0。现在按 `None` 显示"未采集（原因）"。
    #[serde(default)]
    pub cache_policy: Option<String>,
    #[serde(default)]
    pub cache_file: Option<String>,
    #[serde(default)]
    pub udp_dropped: f64,
    /// **2.1.18（修复项 18）**：`/api/status.cache`（用户态缓存摘要）。
    #[serde(default)]
    pub cache: CacheInfo,
    /// **2.1.49（AUD-09）**：进程自观测（RSS / threads / open_fds）。
    #[serde(default)]
    pub process: ProcessInfo,
    #[serde(default)]
    pub top_domains: Vec<(String, f64)>,
    #[serde(default)]
    pub top_clients: Vec<(String, f64)>,
    #[serde(default)]
    pub top_upstreams: Vec<(String, f64)>,
    /// **2.1.20（A-02）**：整数配置键的**权威区间**（`/api/status.config_ranges`）。
    ///
    /// 单一来源 = 后端 `ebpdns_resolver::config::CONFIG_RANGES`（= `validate_write` 的
    /// 同一张表）。配置页据此 clamp ⇒ 前端不可能再摆出后端会 400 的值。
    /// 空数组 = 旧后端（<2.1.19）不返回该字段，此时用 `fmtnum::CONFIG_RANGE_FALLBACK` 兜底。
    #[serde(default)]
    pub config_ranges: Vec<ConfigRange>,
}

/// **2.1.20（A-02）**：`/api/status.config_ranges[]` 的一条（整数键的权威区间）。
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ConfigRange {
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub min: f64,
    #[serde(default)]
    pub max: f64,
}

/// `/api/snapshot` → `.history[]`
#[derive(Clone, Debug, Default, Deserialize)]
pub struct HistoryPoint {
    /// epoch 秒（2.0 形状）或 `HH:MM:SS`（v1.9.162 形状）→ 统一格式化为本地时间。
    #[serde(default, deserialize_with = "de_ts")]
    pub label: String,
    #[serde(default)]
    pub hit_rate: f64,
    #[serde(default)]
    pub qps: f64,
    #[serde(default)]
    pub lat: f64,
}

/// `/api/snapshot` → `.qtype_dist`
#[derive(Clone, Debug, Default, Deserialize)]
pub struct QtypeDist {
    #[serde(default, rename = "A")]
    pub a: f64,
    #[serde(default, rename = "AAAA")]
    pub aaaa: f64,
    #[serde(default)]
    pub other: f64,
}

/// `/api/snapshot` → `.upstreams[]`
/// **2.1.36（C 批）**：删除前端从未读取的 `group` 镜像字段（后端照旧下发）。
#[derive(Clone, Debug, Default, Deserialize)]
pub struct UpstreamStat {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub proto: String,
    #[serde(default)]
    pub addr: String,
    #[serde(default)]
    pub port: f64,
    #[serde(default)]
    pub url: String,
    /// **2.1.18（修复项 3）**：后端下发的完整地址 `scheme://host[:port][/path]`
    /// （单一来源 = `/api/upstreams[].full_addr`，与 `/api/snapshot.upstreams[].full_addr`
    /// 同源，规则见后端 `api.rs::full_addr_parts`）。
    ///
    /// 前端**优先消费本字段**；只有旧后端（不返回该键）或键为空时才回退本地
    /// `telemetry.rs::full_addr()`（该实现保留作兜底，规则与后端逐条一致）。
    /// `#[serde(default)]`（`None`）而不是 `String` 默认空串：让"字段缺失"与
    /// "后端明确给了空串"都能被识别为兜底条件，同时保持向后兼容。
    #[serde(default)]
    pub full_addr: Option<String>,
    #[serde(default)]
    pub latency: Option<f64>,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub queries: f64,
    #[serde(default)]
    pub success_rate: Option<f64>,
    #[serde(default)]
    pub avg_latency: Option<f64>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub conn_avg_lat: Option<f64>,
    #[serde(default)]
    pub conn_ok: f64,
    #[serde(default)]
    pub conn_fail: f64,
    #[serde(default)]
    pub conn_key: String,
    /* ---- v2.1.8：健康度自解释列消费的后端新字段（缺失/类型变动 → None → 显示 `–`） ---- */
    /// 熔断器是否打开
    #[serde(default, deserialize_with = "de_opt_bool")]
    pub breaker_open: Option<bool>,
    /// 熔断剩余秒数
    #[serde(default, deserialize_with = "de_opt_f64")]
    pub until_in_s: Option<f64>,
    /// 连续失败数
    #[serde(default, deserialize_with = "de_opt_f64")]
    pub fails: Option<f64>,
    /// 本进程最近一次选择中的角色：`primary` / `backup` / `idle`
    #[serde(default, deserialize_with = "de_opt_str")]
    pub role: Option<String>,
    /// 排序用的等效延迟（ms）
    #[serde(default, deserialize_with = "de_opt_f64")]
    pub eff_lat_ms: Option<f64>,
    /// 本轮是否可被选中
    #[serde(default, deserialize_with = "de_opt_bool")]
    pub selectable: Option<bool>,
    /// 探针成功 / 失败计数
    #[serde(default, deserialize_with = "de_opt_f64")]
    pub probe_ok: Option<f64>,
    #[serde(default, deserialize_with = "de_opt_f64")]
    pub probe_fail: Option<f64>,
    /// 兼容当前后端已有的 `ok` / `fail` 探针计数
    #[serde(default, deserialize_with = "de_opt_f64")]
    pub ok: Option<f64>,
    #[serde(default, deserialize_with = "de_opt_f64")]
    pub fail: Option<f64>,
    /* ---- **2.1.20（A-16）：后端已产出但前端零消费的"两本账"字段** ---- */
    //
    // 审计 A-16：`breaker_fails` / `transport_ok` / `transport_fail` 后端一直在返回，
    // 而 `grep breaker_fails web/src` = **0 命中** ⇒ F-05 修法注释宣称的
    // "运维一眼能看出两本账差异"在 UI 上**不成立**。现在健康度表消费它们。
    /// **熔断账**（连续数据面失败数，与 `fails` 同值；语义上区分于传输账）。
    #[serde(default, deserialize_with = "de_opt_f64")]
    pub breaker_fails: Option<f64>,
    /// **传输账**：HealthKeeper 的成功/失败计数（DNS 层 SERVFAIL 也算传输成功）。
    #[serde(default, deserialize_with = "de_opt_f64")]
    pub transport_ok: Option<f64>,
    #[serde(default, deserialize_with = "de_opt_f64")]
    pub transport_fail: Option<f64>,
    /* ---- **2.1.21（A-17）**：DNS **业务**成功率（第三本账） ---- */
    /// DNS 业务成功率（%）：分子 = `rcode ∈ {NOERROR,NXDOMAIN}` 且有应答未截断的次数；
    /// SERVFAIL/REFUSED/NOTIMP/FORMERR/截断计入失败。**与 `success_rate` 不同源**
    /// （后者是传输层），`None` = 该上游还没有业务样本（旧后端同样 `None`）。
    #[serde(default, deserialize_with = "de_opt_f64")]
    pub dns_success_rate: Option<f64>,
    /// 业务成功 / 失败样本数（`dns_success_rate` 的分子与分母）。
    #[serde(default, deserialize_with = "de_opt_f64")]
    pub dns_ok: Option<f64>,
    #[serde(default, deserialize_with = "de_opt_f64")]
    pub dns_fail: Option<f64>,

    /* ---- 2.1.15（决策 2）：后端早已返回、此前页面未消费的健康字段 ---- */
    /// 上游权重（排序键 = `eff_lat / max(1, weight)`）。
    #[serde(default, deserialize_with = "de_opt_f64")]
    pub weight: Option<f64>,
    /// `avg_latency` / `eff_lat_ms` 是否来自**实测**样本（false = 回退配置静态值）。
    #[serde(default, deserialize_with = "de_opt_bool")]
    pub latency_measured: Option<bool>,
    /// `eff_lat_ms` 是否来自实测样本（false = 回退配置静态 `latency`）。
    #[serde(default, deserialize_with = "de_opt_bool")]
    pub eff_lat_measured: Option<bool>,
    /// 熔断器**连续打开次数**（指数退避级别 1→open_s、2→2×、3→4×… 封顶）。
    #[serde(default, deserialize_with = "de_opt_f64")]
    pub circuit_open_count: Option<f64>,
}

/// `/api/snapshot` → `.manual_history[]`
/// **2.1.36（C 批）**：删除前端从未读取的 `hit` 镜像字段（后端照旧下发）。
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ManualEntry {
    #[serde(default, deserialize_with = "de_ts")]
    pub ts: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub qtype: String,
    #[serde(default)]
    pub answer: String,
    #[serde(default)]
    pub lat: Option<f64>,
}

/// `/api/snapshot` 与 `/api/logs` → `.events[]`
#[derive(Clone, Debug, Default, Deserialize)]
pub struct LogEvent {
    #[serde(default)]
    pub seq: f64,
    #[serde(default, deserialize_with = "de_ts")]
    pub ts: String,
    #[serde(default)]
    pub level: String,
    #[serde(default)]
    pub msg: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub qtype: String,
    #[serde(default)]
    pub client_ip: String,
    #[serde(default)]
    pub upstream: String,
    #[serde(default)]
    pub answer: String,
    #[serde(default)]
    pub rule: String,
    #[serde(default)]
    pub lat: Option<f64>,
}

/// `/api/snapshot`
///
/// **2.1.14 契约清理（审计 ⑥ / `cargo build` dead_code 告警）**：删掉 5 个
/// **与 `/api/status` 完全重复且前端从无消费点**的字段
/// （`rule_hits` / `top_domains` / `top_clients` / `top_upstreams` / `events`）：
/// 这些数据页面一律从 `Status`（全局 2s 轮询）读取，Snapshot 里的副本无人引用。
/// 后端 `/api/snapshot` 仍照旧下发（公开契约不变），前端只是不再反序列化
/// （serde 默认忽略未知键，`counters`/`map` 等仍按需保留）。
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Snapshot {
    #[serde(default)]
    pub history: Vec<HistoryPoint>,
    #[serde(default)]
    pub qtype_dist: QtypeDist,
    #[serde(default)]
    pub counters: Counters,
    #[serde(default)]
    pub upstreams: Vec<UpstreamStat>,
    #[serde(default)]
    pub manual_history: Vec<ManualEntry>,
    /// **2.1.36（C 批）**：`poll.rs` 的轮询指纹消费 `map.used/capacity`（不是纯展示字段），
    /// 保留；`MapInfo` 内已删除未读的 `pct`。
    #[serde(default)]
    pub map: MapInfo,
}

/// `/api/logs`
///
/// **2.1.36（C 批）**：删除前端从未读取的 `total` 镜像字段（页面计数用本地缓冲长度
/// `#log-count`；后端照旧下发）。
#[derive(Clone, Debug, Default, Deserialize)]
pub struct LogsResp {
    #[serde(default)]
    pub events: Vec<LogEvent>,
    #[serde(default)]
    pub next_seq: f64,
}

/// `/api/pipeline` → `.upstreams[]`（后端对上游脱敏，仅 id/name/proto）
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PipeUpstream {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub proto: String,
}

/// `/api/pipeline`
///
/// **2.1.15（决策 2：把已有数据上页展示）**：新增两个后端**早已返回**但页面从未
/// 消费的字段 —— `rules`（规则索引真实条数）与 `upstream_count`（配置里的上游条数）。
/// 两者在流水线页头部以统计条展示，口径标注见 `pages/pipeline.rs`：
/// - `rules` = `Resolver::rule_count()`（本地逐条 + 订阅展开后**进索引**的条数），
///   **不是** `config.rules[]` 的长度（后者只是本地逐条规则）；
/// - `upstream_count` = `ResolverConfig.upstreams` 的条数（含 `enabled=false` 的条目）。
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Pipeline {
    #[serde(default)]
    pub cache_size: f64,
    /// **用户态**缓存直答开关（配置键 `cache_direct_enabled`）。
    #[serde(default)]
    pub cache_direct_enabled: bool,
    #[serde(default)]
    pub upstreams: Vec<PipeUpstream>,
    /// 规则索引真实条数（见结构体文档）。
    ///
    /// **2.1.43-B（P2-1）**：`Option<f64>` —— 字段缺失/旧后端不返回该键 ⇒ `None`
    /// ⇒ 流水线页显示 **「未知」**（旧实现 `f64` + `#[serde(default)]` 会显示 **0**，
    /// 把"没采集到"伪装成"真的 0 条规则"）。
    #[serde(default)]
    pub rules: Option<f64>,
    /// 配置里的上游条数（含已禁用）。
    ///
    /// **2.1.43-B（P2-1）**：同上 —— 缺失 ⇒ `None` ⇒ 「未知」，不再显示 0。
    #[serde(default)]
    pub upstream_count: Option<f64>,
}

/// `POST /api/query` → `.trace[]`
#[derive(Clone, Debug, Default, Deserialize)]
pub struct TraceStep {
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub text: String,
}

/// `POST /api/query` → `.answers[]`
///
/// **2.1.36（C 批）**：删除前端从未读取的 `rtype`（JSON `type`）镜像字段；
/// `from` 仍被解析结果表消费（保留）。
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Answer {
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub from: String,
    #[serde(default)]
    pub ttl: f64,
}

/// `POST /api/query`
///
/// **2.1.14 清理（审计 ⑥）**：删除从无消费点的 `chosen` 字段（后端仍返回，忽略）。
#[derive(Clone, Debug, Default, Deserialize)]
pub struct QueryResp {
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub qtype: String,
    #[serde(default)]
    pub hit: bool,
    #[serde(default)]
    pub error: bool,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub latency: f64,
    #[serde(default)]
    pub ttl_left: Option<f64>,
    #[serde(default)]
    pub ttl: Option<f64>,
    #[serde(default)]
    pub trace: Vec<TraceStep>,
    #[serde(default)]
    pub answers: Vec<Answer>,
}

/// 流水线动画里「在途数据包」的种类（= 日志 level 的归一）。
///
/// **2.1.14 清理（审计 ⑥ 复核修正）**：只删了 `struct Packet { id, kind }`
/// （真正零引用 —— 动画节点由 DOM 直接生成），**保留 `PacketKind`**：审计把它一并
/// 判为死代码是错的，`pages/pipeline.rs:21/217/230-251/278-280` 一直在用。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketKind {
    Hit,
    Miss,
    Fail,
}
