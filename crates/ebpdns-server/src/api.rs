//! HTTP/REST/WebSocket API：忠实对齐 api.py 路由表与安全模型。
//!
//! 路由↔api.py 对应表见本 crate 顶层文档。安全由 [`security`] 提供的守卫中间件统一收口。

use std::time::Duration;

use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{header, Method, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde_json::{json, Map, Value};

use ebpdns_cache::DnsCache;
use ebpdns_resolver::breaker::SharedCircuit;
use ebpdns_resolver::clock::RealClock;
use ebpdns_resolver::config::UpstreamCfg;
use ebpdns_resolver::production::ProductionQuerier;
use ebpdns_resolver::query::ParallelQuerier;
use ebpdns_resolver::resolve::ResolveOpts;
use futures::StreamExt;

use crate::api_state::put_config_commit;
use crate::error::{ServerError, ServerResult};
use crate::security::*;
use crate::state::AppState;
use crate::telemetry::now_epoch;

/// 版本：**单一来源** = 本 crate 的 `Cargo.toml`（`version.workspace = true` →
/// 根 `[workspace.package] version`，**2.1.19**）。
///
/// 旧实现手写字符串 `"2.1.13"`，与包名（2.1.14）/ 内部目录名（2.1.12）/
/// systemd Description（v2.1.12）四处互相矛盾（审计 ⑤）。改用
/// `env!("CARGO_PKG_VERSION")` 后，`/api/status.version`、`/api/about` 等
/// 所有下发版本号都自动跟随 workspace 版本，**不可能再漂移**。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// 可写顶层配置键（对齐 api.py `_CFG_WRITABLE_KEYS`）。
/// **[历史归因]** 可写顶层配置键（冻结全集 = Python config.py DEFAULTS 顶层键 减 listen/api/web_root）。
/// 只读段 listen/api/web_root 改了不生效（并入 ignored_keys）。
const CFG_WRITABLE: &[&str] = &[
    // 缓存
    "cache_size",
    "cache_policy",
    "cache_partitions",
    "cache_save_interval",
    "ttl",
    "ttl_min",
    "ttl_max",
    // P1-2（2.1.9）：负缓存 TTL 硬上限（秒；0 = 关闭上限）。
    "neg_ttl_max",
    "serve_stale",
    "stale_ttl",
    "cache_persist",
    "persist_ttl",
    "prefetch",
    "prefetch_interval",
    "prefetch_target",
    "prefetch_trigger",
    // 用户态缓存直答开关（历史键 kernel_direct 已移除）
    "cache_direct_enabled",
    // 测速/IP
    "speed_test",
    "speed_interval_ms",
    "speed_timeout_ms",
    "ip_speed_check",
    "ip_speed_probe",
    "ip_speed_cache_ttl",
    "fallback",
    "max_parallel_upstreams",
    // **2.1.15（P1）**：单条上游的最大在途请求数（0 = 关闭闸门）。
    "upstream_max_inflight",
    "timeout_ms",
    "nxdomain_quorum",
    // 双栈
    "ipv6",
    "prefer_ipv4",
    "ipv4_first",
    // EDNS
    "edns",
    "edns_udp_size",
    "edns_client_max_size",
    "edns_client_subnet",
    "padding",
    "dnssec_0x20",
    "rebind_protection",
    // 健康
    "health_check_interval",
    "health_probe_domain",
    "health_probe_timeout_ms",
    // 其他
    "bootstrap_dns",
    // v1.9.162 控制台的熔断字段（`cb_*` 为其别名）。
    "circuit_fails",
    "circuit_open_s",
    // **2.1.20（A-12 修复）**：三个**受支持的历史别名**此前不在白名单 ⇒
    // `PUT {"cb_fails":9}` 回 `ignored_keys:["cb_fails"]`（"未知键已忽略"），
    // 而 `main.rs::apply_cfg` **真的读它们**（`:2211` / `:2214` / `:2130`）——
    // 即"用户写了、程序也读了，接口却说未知"。现在它们是**受支持的别名**（可写）。
    "cb_fails",
    "cb_open_s",
    "prefetch_max",
    // **2.1.20（A-12 同类）**：warmup.* 的扁平别名同样被 pply_cfg 消费。
    "warmup_enabled",
    "warmup_queries",
    "warmup_timeout_ms",
    // 2.1.8 优化项 2/3/4/5 新增键（控制台可读写；缺省值见 default_config()）。
    "circuit_open_max_s",
    "probe_timeout_ms",
    "adaptive_parallel",
    "hedge_after_ms",
    "adaptive_timeout",
    "adaptive_timeout_k",
    "adaptive_timeout_min_ms",
    "log_level",
    "log_format",
    "rule_sub_interval",
    "upstreams",
    "rules",
    "rule_subscriptions",
    // ================= **2.1.18（修复项 7）：此前漏在白名单外的可调键** =================
    //
    // 缺陷（用户实测）：控制台点保存后弹出
    // `配置已保存; 忽略未保存的键: config_version, hedge_slowest_factor, rating_sr_floor,
    //  rfc8020_infer, rfc8020_max_labels, rule_local_file, rule_sub_file, single_flight,
    //  udp_workers, warmup`
    // —— 其中 `single_flight` / `udp_workers` / `warmup` 是 2.1.16 新增的**用户可配置
    // 功能**，`rfc8020_*` / `rating_sr_floor` / `hedge_slowest_factor` 是解析与选路调参，
    // 却都不在白名单里 ⇒ **功能不可达**（不是"数据会丢"，而是"改了不生效"）。
    //
    // 为什么 2.1.16 加键时没同步白名单：白名单是**逐键枚举**的冻结列表，新增配置键
    // 与新增白名单项是两处独立改动，没有门禁把它们绑在一起。本轮除补齐外，
    // 还加了单测 `cfg_writable_covers_all_default_top_level_keys`（以
    // `default_config()` 为参照物）防止再次漂移。
    //
    // `single_flight`：同 CacheKey 并发 miss 合并为一次上游扇出（重启级热重载生效）。
    "single_flight",
    // `udp_workers`：每地址 UDP socket / 收包循环数（0 = 自动，封顶 8）。**重启级**键
    // （改 `listen` 之外的取值不会重建已有 socket，见 README）。
    "udp_workers",
    // `warmup`（**对象键**）：上游连接池预热 `{enabled, queries, timeout_ms}`。
    // 写路径按**整体替换**处理，子键范围校验见 `resolver::config::validate_write`。
    "warmup",
    // 2.1.12 优化项 ①：RFC 8020 父域 NXDOMAIN 推断开关与登记/匹配深度上限。
    "rfc8020_infer",
    "rfc8020_max_labels",
    // 2.1.12 优化项 ②：上游评分成功率惩罚下限（(0,1]；0 会把上游饿死，故校验下限）。
    "rating_sr_floor",
    // 2.1.11 优化项 3：逐上游 p90 对冲因子（>0）。
    "hedge_slowest_factor",
];

/// **2.1.18（修复项 7）**：**只读 / 服务端管理**的配置键集合。
///
/// 语义（必须与 `ignored_keys` 分开，否则前端提示语会误导用户）：
/// - **只读**：这些键**存在于配置里**、`GET /api/config` 会返回、但 `PUT /api/config`
///   不接受它们 —— 保存时它们的**原值保持不变**（既不改磁盘也不改内存）。
///   它们要么由服务端管理（`config_version` 由 `migrate_cfg` 迁移写入），
///   要么必须在配置文件里编辑（路径类键），要么改了不会生效（只读段）。
/// - `ignored_keys`（另一桶）：**不在** [`CFG_WRITABLE`] 也**不在**本集合里的键
///   —— 这才是"未知/拼错的键"，提示语应当不同。
///
/// 为什么 `rule_local_file` / `rule_sub_file` 归**只读**而不是白名单：
/// 它们是**规则/订阅数据的存储路径**，运行期由 `migrate_cfg` 按 `config.json`
/// 同目录推导并注入。允许控制台写它们等于允许把规则文件指向
/// `/etc/shadow` 之类的任意路径（值会被 `rules_admin` 当文件读写 ⇒ 越权 + 数据破坏）。
/// 因此**刻意不开放**：要改请编辑 `/etc/ebpdns/config.json` 后重启（README 已写明）。
const CFG_READONLY: &[&str] = &[
    // schema 版本：由 `migrate_cfg` / `migrate-config` 管理，手工改会让
    // "旧二进制跑新配置"的保护失效。
    "config_version",
    // 只读段（改了不生效；`api.token` 等见 README「安全说明」）。
    "listen",
    "api",
    "web_root",
    // 路径类：由服务端按 config.json 同目录推导（见本常量文档的越权说明）。
    "rule_local_file",
    "rule_sub_file",
    "cache_file",
    // `dns_port` 是 DNS 端口的**旧键**（等价 `listen.*`，需要重建 socket）⇒ 只读。
    "dns_port",
    // **2.1.22 阶段一**：`state/` 统一持久化事务的目录与开关。
    //
    // 归只读桶的理由（与 `cache_file` 同口径）：
    // * `state_dir` 是**路径类**键 —— 开放写入 = 允许经 API 把持久化世代写到任意
    //   目录（与 `rule_local_file` 同一类越权面）；
    // * `state_persist` 是**进程级**启动参数 —— 它决定 `AppState.state` 里有没有
    //   store 句柄，进程内改它不会生效（改了只会造成"配置说开了、实际没开"的假象）。
    // 两者都在 `/api/status.state_persist` 里如实回显，改完重启即可。
    "state_dir",
    "state_persist",
];

/// **2.1.18（修复项 7）**：每个只读键的**原因**（前端只读展示区逐条显示）。
///
/// 存在意义：只说"只读"用户会以为是权限问题；说清"由谁管理 / 为什么不开放 /
/// 要改怎么办"才能避免二次误判（2.1.16 交付审计就踩过"提示语让人以为保存丢数据"）。
pub fn cfg_readonly_reason(key: &str) -> &'static str {
    match key {
        "config_version" => "配置 schema 版本，由 migrate-cfg/迁移自动维护（手工改会让版本保护失效）",
        "listen" => "监听地址段：改动需重建 socket，请在配置文件编辑后重启",
        "api" => "控制台监听与 token 段：只读，请在配置文件编辑后重启",
        "web_root" => "静态资源根目录：只读段",
        "rule_local_file" | "rule_sub_file" => {
            "规则/订阅数据文件路径，由服务端按 config.json 同目录推导（开放写入等于允许任意路径读写）；\
             要改请编辑配置文件后重启"
        }
        "cache_file" => "缓存落盘路径，只读段（请在配置文件编辑后重启）",
        // **2.1.22**：统一持久化事务的两把"启动参数"。
        "state_dir" => {
            "统一持久化事务的 `state/` 目录（`commit.json` + `history/` + 规则真源）：\
             路径类只读键（开放写入等于允许任意路径读写）。改它需重启；\
             自定义路径还要同步改 systemd unit 的 `ReadWritePaths=`"
        }
        "state_persist" => {
            "统一持久化事务开关：进程级启动参数（`AppState` 的 store 句柄在启动时装配），\
             进程内改它不生效。改它需重启；关闭后逐位退回 2.1.21 的各写者原子写"
        }
        _ => "服务端管理的只读键",
    }
}

/// 构建 axum 路由（含静态兜底）。
pub fn build_router(state: AppState) -> Router {
    let api = axum::Router::new()
        .route("/api/health", get(health))
        .route("/api/config", get(get_config).put(put_config))
        .route("/api/query", post(query))
        .route("/api/snapshot", get(snapshot))
        .route("/api/upstreams", get(upstreams).post(upstreams_create))
        .route(
            "/api/upstreams/{id}",
            put(upstream_update).delete(upstream_delete),
        )
        .route("/api/status", get(status))
        .route("/api/logs", get(logs))
        .route("/api/pipeline", get(pipeline))
        .route("/metrics", get(metrics))
        // >>> 242B BEGIN P0-2-route >>> //
        // **2.1.42-B（P0-2）**：`?mode=replace` 才允许覆盖；默认合并。
        .route("/api/rules/import", post(rules_import_http))
        // <<< 242B END P0-2-route <<< //
        .route(
            "/api/rules/subscribe",
            post(rules_subscribe).delete(rules_subscribe_delete),
        )
        .route("/api/rules/subscribe/update", post(rules_subscribe_update))
        .route("/api/reprobe", post(reprobe))
        .route("/api/reload", post(reload))
        .route("/api/restart", post(restart))
        .route("/api/reset", post(reset))
        .route("/api/rules", get(rules_list).post(rules_create))
        .route("/api/rules/{id}", put(rule_update).delete(rule_delete))
        .route("/api/cache/stats", get(cache_stats))
        .route("/api/profile", post(profile));

    Router::new()
        .merge(api)
        .fallback(static_handler)
        .layer(axum::middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

/* ---------------- 安全守卫中间件 ---------------- */

async fn guard(
    State(state): State<AppState>,
    req: axum::http::Request<Body>,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let query = req.uri().query().unwrap_or("").to_string();
    let headers = req.headers().clone();

    // 静态资源：免认证。
    let is_api = path.starts_with("/api/") || path == "/metrics";
    if !is_api {
        return next.run(req).await;
    }

    let presented = presented_token(&headers, &query);

    // 写操作 CSRF。
    if matches!(method, Method::POST | Method::PUT | Method::DELETE)
        && path.starts_with("/api/")
        && !csrf_ok(&state, &headers, &query, &presented)
    {
        // **2.1.43-A（P2：`rebind_blocked` 恒 0 = 没有写点）**：控制面写请求被拒
        // 时区分两种原因 —— ①token/Origin 不符（CSRF）；②**Host 头指向不可信名字**
        // （DNS-rebinding 形态）。2.1.42 及以前只有一个 `rebind_blocked` 字段、却
        // **没有任何自增点**（`grep -rn 'inc.*rebind_blocked' crates` 为空），于是
        // 它恒 0 而文档声称"控制面 rebinding 拦截数"。现在写点唯一 = 本分支的
        // rebinding 形态（`security::host_untrusted`，与 `csrf_ok`/`origin_ok`
        // 的 host 判据同源）；403 的状态码与文案**逐字不变**。
        if crate::security::host_untrusted(&state, &headers) {
            state.telemetry.inc_n("rebind_blocked", 1);
        }
        return ServerError::Forbidden("CSRF check failed".into()).into_response();
    }
    // token 校验（/metrics 一并要求；仅 /api/health 豁免）。
    if path != "/api/health" && !token_ok(&state, &presented) {
        return ServerError::Unauthorized.into_response();
    }
    // 读端点同源/rebinding 防护（health 同样走：无 Origin/Referer 的探针直连放行）。
    if !origin_ok(&state, &headers) {
        return ServerError::Forbidden("origin check failed".into()).into_response();
    }
    next.run(req).await
}

/* ---------------- handlers ---------------- */

/// GET /api/health（免认证）。对齐 v1.9.162：`{status, running, uptime_s}`（不含 version）。
async fn health(State(s): State<AppState>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "running": true,
        "uptime_s": s.telemetry.uptime_s(),
    }))
}

/// `200 OK` + JSON 响应体。
///
/// **2.1.26（B2）**：参数从 `Value` 改成 `impl Serialize` —— 这样"脱敏 + 派生 `rules`"
/// 可以**并进序列化**（见 [`ConfigGetView`]），不必先造一棵新的 `Value` 树。
/// 既有调用点传的仍都是 `Value`，行为与字节输出逐位不变。
fn json_ok(v: impl serde::Serialize) -> Response {
    (StatusCode::OK, Json(v)).into_response()
}

/// qtype 名 → 数值；**不受支持的名字返回 `None`**（`query` 据此回 400）。
///
/// **2.1.21（DEF-220-03 修复：控制面与数据面的受理集合必须同源）**
///
/// 缺陷（AUDIT-220 B 节 DEF-220-03 实测）：本函数此前手写 **24 个名字**
/// （含 `CAA/HTTPS/SVCB/ANY/NAPTR/DS/RRSIG/…`），而数据面受理名单
/// （[`ebpdns_proto::constants::SUPPORTED_QTYPES`]，`dns.rs` 的 `qtype_name`）
/// 当时**只有 9 型**。后果是**同一个 qtype 两条路径结论相反**：
///
/// | 路径 | 当时的 `CAA` / `HTTPS` / `ANY` / `NAPTR` |
/// |---|---|
/// | UDP/TCP 数据面（`dig -t CAA`） | rcode **NOTIMP(4)**（`qtype_name` 返回 `None`） |
/// | 控制面 `POST /api/query {"qtype":"CAA"}` | **HTTP 200** + 上游答案 |
///
/// **2.1.21 起两边同一张表**：本函数直接委托给
/// [`ebpdns_proto::constants::qtype_code`]（与 `dns.rs` 的 `qtype_name` 同源），
/// 于是"数据面不受理的类型"在控制面被**拒收**（400 `bad qtype: X`）。
///
/// **2.1.29**：`SUPPORTED_QTYPES` 扩到 20 型（新增 SVCB/HTTPS/CAA/TLSA/DS/SSHFP/
/// DNSKEY/CDS/CDNSKEY/URI/NAPTR），控制面因此**同时**放开这 11 个名字；
/// `AXFR/ANY/…` 仍不在 `qtype_code` 名单里 ⇒ 控制面仍 400。
///
/// 注意**控制面刻意不提供"未知 qtype 透传"**：`/api/query` 的 qtype 是配置/人工
/// 输入的名字，透传只服务数据面收到的**原始 `u16` 查询**（无法用名字表达）。
fn parse_qtype(t: &str) -> Option<u16> {
    ebpdns_proto::constants::qtype_code(t)
}

/// 深拷贝并脱敏：所有名为 token/secret/password/passwd 的字符串字段替换为 `***`。
///
/// **2.1.26（B2）**：本函数**只保留作参考实现**（`cfg(test)` 里的等价性判据用它当
/// "2.1.25 的参考答案"）。生产路径已改为借用式 [`Redacted`] —— 语义逐字不变
/// （`value_is_redacted_in_streaming_serializer` 与
/// `config_get_body_is_byte_identical_to_2_1_25_snapshot` 两条单测钉死）。
#[cfg(test)]
fn desensitize(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, val) in map {
                if val.is_string() && is_secret_key(k) {
                    out.insert(k.clone(), json!("***"));
                } else {
                    out.insert(k.clone(), desensitize(val));
                }
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(desensitize).collect()),
        other => other.clone(),
    }
}

/// 键名里出现 `token`/`secret`/`password`/`passwd`（大小写不敏感）⇒ 该**字符串值**打码。
///
/// 判据与 2.1.25 的 `desensitize` **逐字相同**（只有字符串值会被替换；对象/数字/数组
/// 原样递归），唯一区别是这里不分配小写副本给调用方复用 —— 每个键仍会 `to_ascii_lowercase`
/// 一次（与旧实现同代价，不引入新行为）。
fn is_secret_key(k: &str) -> bool {
    let lk = k.to_ascii_lowercase();
    lk.contains("token")
        || lk.contains("secret")
        || lk.contains("password")
        || lk.contains("passwd")
}

/// 借用式脱敏序列化器（**2.1.26 / B2 性能项**）。
///
/// # 为什么需要它
///
/// 2.1.25 的 `GET /api/config` 把整份配置**深拷贝**成一棵新的 `Value` 树
/// （每个对象新建 `Map`、每个键与字符串克隆一次），**再**让 `serde_json` 序列化一遍 ——
/// 同一份字节被搬了两遍。生产配置（79 键 / 22 条上游）约 10 KB，即每次请求多出
/// 数百次分配。本类型把脱敏并进序列化：直接读 `&Value`，边遍历边写响应体，
/// **不建中间树**。
struct Redacted<'a>(&'a Value);

impl serde::Serialize for Redacted<'_> {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{SerializeMap, SerializeSeq};
        match self.0 {
            Value::Object(map) => {
                let mut m = ser.serialize_map(Some(map.len()))?;
                for (k, v) in map {
                    if v.is_string() && is_secret_key(k) {
                        m.serialize_entry(k, "***")?;
                    } else {
                        m.serialize_entry(k, &Redacted(v))?;
                    }
                }
                m.end()
            }
            Value::Array(arr) => {
                let mut s = ser.serialize_seq(Some(arr.len()))?;
                for v in arr {
                    s.serialize_element(&Redacted(v))?;
                }
                s.end()
            }
            other => other.serialize(ser),
        }
    }
}

/// `GET /api/config` 的**借用式**响应体（2.1.26 / B2）。
///
/// # 为什么这样拼
///
/// 旧实现是 `desensitize(&cfg)` 建树 → `insert("rules", 派生视图)` → 序列化。三条性质
/// 必须逐位保住：
/// 1. **键序**：本工作区的 `serde_json` 没开 `preserve_order`（`Map` = `BTreeMap`）⇒
///    旧实现输出的键序是**字母序**，`insert("rules", …)` 也是插到字母序的位置。这里
///    遍历 `BTreeMap` 时把 `rules` 插到它该在的位置（`"rules"` 之后没有、`"rules…"` 之前）；
/// 2. **`rules` 不脱敏**：旧实现先脱敏整份 cfg、**随后又被派生视图覆盖** ⇒ 响应里的
///    `rules` 是**原值**。这里同样原样写（不套 [`Redacted`]）；
/// 3. **非对象 cfg**：旧实现对数组/标量直接脱敏返回且**没有** `rules` 键 —— 这里走同一条分支。
struct ConfigGetView<'a> {
    cfg: &'a Value,
    /// `None` ⇒ 内存镜像存在，序列化时直接借用 `cfg["rules"]`（**零克隆**）；
    /// `Some(v)` ⇒ 镜像键已被迁移删除，用真源派生视图。
    rules: Option<Value>,
}

impl serde::Serialize for ConfigGetView<'_> {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let Value::Object(map) = self.cfg else {
            return Redacted(self.cfg).serialize(ser);
        };
        let has_mirror = map.contains_key("rules");
        let extra = usize::from(self.rules.is_some() && !has_mirror);
        let mut m = ser.serialize_map(Some(map.len() + extra))?;
        let mut rules_done = false;
        for (k, v) in map {
            if k == "rules" {
                match &self.rules {
                    Some(rules) => m.serialize_entry("rules", rules)?,
                    None => m.serialize_entry("rules", v)?,
                }
                rules_done = true;
                continue;
            }
            if !rules_done && !has_mirror && k.as_str() > "rules" {
                if let Some(rules) = &self.rules {
                    m.serialize_entry("rules", rules)?;
                }
                rules_done = true;
            }
            m.serialize_entry(k, &Redacted(v))?;
        }
        if !rules_done {
            if let Some(rules) = &self.rules {
                m.serialize_entry("rules", rules)?;
            }
        }
        m.end()
    }
}

/// GET /api/config：脱敏返回。
///
/// **2.1.24（DEF-222-14 收口）**：`rules` 字段**恒为数组**，由真源派生（空则 `[]`）。
///
/// 2.1.23 的实测缺陷（交付报告 ⑫(2)）：2.1.22-era 配置经 `migrate-config` 迁移后，
/// `config.json` 的 `rules` **镜像键被删除**（单一真源 = `state/rules.json`），
/// 旧实现只回显内存 cfg ⇒ `GET /api/config.rules` 变成 `null`（字段消失），
/// 而同一时刻 `/api/rules.total=1`、wire 上规则**确实生效** ⇒ 两个端点自相矛盾。
/// 现在：内存里有数组就原样回显（形状逐位不变），没有就按
/// [`crate::rules_admin::config_rules_view`] 从真源派生；派生只读、无副作用。
///
/// **2.1.26（B2：去掉两遍整份深拷贝）**：2.1.25 这里做了**两次**全量深拷贝 ——
/// `desensitize(&cfg)` 一次，`config_rules_view` 内部的 `state.cfg.read().clone()` 又一次
/// —— 然后把新树再序列化一次。现在：
/// * 镜像键**在**（出厂模板就是 `"rules": []`）⇒ `rules = None`，序列化时直接借用，
///   **零克隆**；
/// * 镜像键**不在**（迁移后的配置）⇒ 才算一次派生视图（它内部仍要一份快照：派生会读盘，
///   不能持锁）；
/// * 脱敏并进序列化（[`Redacted`]）⇒ 不建中间 `Value` 树。
///
/// **锁序不变**：`parking_lot` 的读锁**不可重入**（有排队写者时嵌套会死锁）⇒ 派生
/// （可能读盘、可能再次取读锁）必须在**不持锁**时算完，之后只取**一次**读锁做序列化。
async fn get_config(State(s): State<AppState>) -> Response {
    let has_mirror = s
        .cfg
        .read()
        .get("rules")
        .and_then(Value::as_array)
        .is_some();
    let rules = if has_mirror {
        None
    } else {
        Some(crate::rules_admin::config_rules_view(&s))
    };
    let cfg = s.cfg.read();
    json_ok(ConfigGetView { cfg: &cfg, rules })
}

/// PUT /api/config：白名单合并 + 取值校验 + 原子写 + 三桶回报。
///
/// **2.1.18（修复项 7）**：回报从"一个 `ignored_keys`"拆成**三个语义不同的桶** ——
/// 此前所有非白名单键都进 `ignored_keys`，前端只能原样拼成
/// `配置已保存; 忽略未保存的键: config_version, single_flight, warmup, …`
/// —— 用户会以为**保存丢数据**，而真相是：
/// | 桶 | 含义 | 前端提示 |
/// |---|---|---|
/// | （无桶） | 在 [`CFG_WRITABLE`] 里 | 已保存并生效 |
/// | `readonly_keys` | 在 [`CFG_READONLY`] 里（只读 / 服务端管理 / 路径类） | "由配置文件或服务端管理，原值保持不变" |
/// | `ignored_keys` | **既不可写也不在只读表**里 ⇒ 未知/拼错的键 | "未知键，已忽略" |
///
/// 取值校验（**新增**）：写路径此前**不校验任何范围** —— `{"cache_size": 1}` 会被
/// 原样写盘并在热重载时静默夹取/忽略。现在用
/// [`ebpdns_resolver::config::validate_write`]（与 `check-config` **同一份实现**）
/// 校验**本次提交的键**，任一非法即 `400` + `errors[]`，**不写盘、不改内存**。
/// 为什么只校验"提交的键"而不是"合并后的整份配置"：旧配置里可能带着历史坏值，
/// 拿它阻断本次合法保存属于回归（拒绝原因必须可归因到用户这次的动作）。
async fn put_config(
    State(s): State<AppState>,
    parts: axum::http::request::Parts,
    Json(body): Json<Value>,
) -> ServerResult<Json<Value>> {
    // >>> 242B BEGIN P1-12-server >>> //
    let Some(obj) = body.as_object() else {
        return Err(ServerError::BadRequest("config must be an object".into()));
    };
    // **2.1.42-B（P1-12）**：服务端拒绝"未加载"的空保存。
    // 前端在 `/api/config` 未就绪时提交的是"默认标量 + 空 upstreams/rules"；
    // 一旦把非空 upstreams 清成 `[]`，DNS 直接不可解析。这里：
    //   ① 显式 `config_loaded:false` ⇒ 400；
    //   ② `upstreams: []` 且 live 配置里 upstreams 非空 ⇒ 400（拒绝清空）。
    // 合法清空仍可先删到只剩一条/显式走运维脚本，不会因"未加载"误触。
    if obj.get("config_loaded").and_then(Value::as_bool) == Some(false) {
        return Err(ServerError::BadRequest(
            "配置尚未加载（config_loaded=false），已拒绝保存".into(),
        ));
    }
    if obj
        .get("upstreams")
        .and_then(Value::as_array)
        .is_some_and(|a| a.is_empty())
    {
        let live_has = s
            .cfg
            .read()
            .get("upstreams")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty());
        if live_has {
            return Err(ServerError::BadRequest(
                "拒绝保存空的 upstreams（配置可能尚未加载）；如需清空请先确认再显式删除".into(),
            ));
        }
    }
    // <<< 242B END P1-12-server <<< //
    // **2.1.22**：`if-revision`（乐观并发控制）。请求体字段 `if_revision` 优先，
    // 其次请求头 `if-revision`；两者都缺 ⇒ 不做校验（逐位保留旧行为）。
    //
    // 用 `Parts` 而不是 `HeaderMap` 抽取器：axum 0.8 的 `HeaderMap` 不能被
    // `Option<_>` 包裹（`OptionalFromRequestParts` 要 `FromRequestParts` 而非
    // `FromRequestParts<S>`），而 `Parts` 本身是 `Infallible` 抽取器 ⇒ 签名稳。
    let if_revision = crate::api_state::if_revision_from(
        &body,
        parts
            .headers
            .get("if-revision")
            .and_then(|v| v.to_str().ok()),
    );
    // **2.1.23（DEF-222-17）**：`if_revision` 是**元字段**（乐观并发控制），不是配置键。
    // 2.1.22 把它当未知键，于是成功保存的响应里会多一句
    // `ignored_keys:["if_revision"]` ⇒ 前端提示"未知键已忽略（请核对拼写）"，
    // 用户以为**保存漏了东西**。这里在建 `merged`/`ignored` **之前**就把它摘出去
    //（与 `rules` 的"元字段"处理同口径）。
    let mut meta_keys: Vec<String> = Vec::new();
    if obj.contains_key("if_revision") {
        meta_keys.push("if_revision".to_string());
    }
    let writable: std::collections::HashSet<&str> = CFG_WRITABLE.iter().copied().collect();
    let readonly: std::collections::HashSet<&str> = CFG_READONLY.iter().copied().collect();
    // ---- ① 取值校验（只针对本次提交的键；非法即 400，且**不产生任何副作用**）----
    let submitted = Value::Object(
        obj.iter()
            .filter(|(k, _)| writable.contains(k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    );
    let errors = ebpdns_resolver::config::validate_write(&submitted);
    if !errors.is_empty() {
        return Err(ServerError::BadRequest(format!(
            "配置取值非法（未写入任何键）：{}",
            errors.join("；")
        )));
    }
    // **2.1.19（F-03）**：`rules` 逐条校验 ⇒ 非法即 **400 + 逐条原因**，且**零副作用**。
    //
    // 此前：`rules` 里的非法条目在 `rules_admin::rebuild_index_from_config` 里被
    // `filter_map(normalize_rule_json)` **静默丢弃**（丢弃发生在统计之前 ⇒ 不计
    // `rejected`、不判失败），`PUT /api/config` 照回 200 `ok:true`，并且会把 `rules`
    // **覆盖成丢弃后的数组** —— 用户以为"保存成功"，实际规则被删。
    // 同一形状走 `POST /api/rules` 却正确回 400 ⇒ 两条路径口径必须收敛到同一处。
    //
    // 位置：在**任何写入之前**（原子写、内存替换、规则文件落盘都在下面）。
    if let Some(rules_v) = obj.get("rules") {
        let errs = crate::rules_admin::validate_rules_array(rules_v);
        if !errs.is_empty() {
            return Err(ServerError::BadRequest(format!(
                "rules 非法（未写入任何键、磁盘与内存均未改动）：{}",
                errs.join("；")
            )));
        }
    }
    let mut ignored: Vec<String> = Vec::new();
    let mut readonly_hit: Vec<String> = Vec::new();
    // `rules` 是否与当前值**实际**不同（前端「应用配置」每次都会回传整份 rules，
    // 值没变时不必重写独立规则文件 + 重建十万条级别的规则索引）。
    let rules_changed = obj.get("rules").is_some_and(|v| {
        s.cfg
            .read()
            .get("rules")
            .map(|cur| cur != v)
            .unwrap_or(true)
    });
    let mut merged = Map::new();
    {
        let cur = s.cfg.read();
        if let Some(cur_obj) = cur.as_object() {
            for (k, v) in cur_obj {
                merged.insert(k.clone(), v.clone());
            }
        }
    }
    for (k, v) in obj {
        if writable.contains(k.as_str()) {
            merged.insert(k.clone(), v.clone());
        } else if readonly.contains(k.as_str()) {
            // 只读桶：**不改动**（内存与磁盘都保持原值），单独归类，不算"未知键"。
            readonly_hit.push(k.clone());
        } else if meta_keys.iter().any(|m| m == k) {
            // **2.1.23（DEF-222-17）**：`if_revision` 是元字段 ⇒ 既不写入也不报"未知键"。
            // 但要在响应里单独回显（见下面 `meta_keys`），让客户端能确认自己发的是什么。
        } else {
            ignored.push(k.clone());
        }
    }
    ignored.sort();
    readonly_hit.sort();
    let new_cfg = Value::Object(merged);
    // **2.1.20（A-06 修复：`5xx ⇒ 无副作用` 不变量）**：先留一份完整快照。
    //
    // 缺陷（审计 A-06 实测）：本端点的"零副作用"只对**前置校验**成立。把
    // `rule_local_file` 指到一个目录后 `PUT rules` ⇒ `persist_current` 失败回 **500**，
    // 但此前 `config.json` 与内存配置**已经被改**、规则索引没变 ⇒
    // "配置显示有该规则、引擎不执行、`/api/rules` 还看不见"（日志
    // `规则写盘失败 (put_config): Is a directory`）。对照 CRUD 路径 `commit_rules`
    // 是有 rollback 的。
    let old_cfg = s.cfg.read().clone();
    // **2.1.20（A-06 二次修复：回滚必须**逐字节**还原磁盘）**
    //
    // 首版回滚写回的是 `old_cfg`（**内存**里的旧配置），而内存配置带着 `migrate_cfg`
    // 注入的路径键（`rule_sub_file` 等）—— 磁盘上的原文件**没有**这些键。
    // 于是"回滚"之后磁盘仍然多了 `rule_sub_file`（审计实测 `only in b: ['rule_sub_file']`、
    // 78→79 键），**与日志里"config.json 也回到原状"的说法不符**。
    //
    // 现在：写盘**之前**先把原文件**字节**快照下来，失败时把它**原样写回**
    // （`orig_bytes` 为 `None` = 原文件不存在 ⇒ 删除本次新建的文件，回到"不存在"）。
    let orig_bytes: Option<Vec<u8>> = match &s.cfg_path {
        Some(p) => match tokio::fs::read(p).await {
            Ok(b) => Some(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                tracing::warn!(path = %p.display(), error = %e,
                    "配置原文件读取失败 ⇒ 本次提交失败时无法逐字节回滚（将退回按内存配置重写）");
                None
            }
        },
        None => None,
    };
    // 持久化（**2.1.22：经统一事务**；未启用时逐位保留 2.1.21 的原子写 + 逐字节回滚）。
    //
    // # 为什么不再需要"事后逐字节回滚"
    //
    // 2.1.20 的 `orig_bytes` 回滚是**崩溃安全缺口的补丁**：`config.json` 与规则文件
    // 是两次独立原子写，第二次失败只能靠重新序列化（或原样写回）来补救，而
    // **进程被 `kill -9` 时根本没有回滚的机会**（磁盘上留下"新一代 config +
    // 旧一代规则"的撕裂世代）。2.1.22 把两者放进**一个世代**提交：
    // 提交点是 `commit.json` 的原子替换 ⇒ 失败/崩溃时 `commit.json` 还是旧的
    // ⇒ 读方看到**上一代**（一致），于是"回滚"这件事**不再需要发生**。
    //
    // 旧路径（`state/` 未启用）**逐位保留**，包括 `orig_bytes` 的逐字节还原语义。
    if s.state.store().is_some() {
        let saved_to: Option<String> = s.cfg_path.as_ref().map(|p| p.display().to_string());
        // `if-revision`（可选）：携带时要求磁盘世代**精确等于**它，否则 409 + 当前世代。
        match put_config_commit(&s, &new_cfg, rules_changed, if_revision).await {
            Ok(_) => {
                // 提交成功 ⇒ 内存与磁盘同源。
                *s.cfg.write() = new_cfg.clone();
                let mut index_ok = true;
                if rules_changed {
                    if let Err(e) = crate::rules_admin::rebuild_index_from_cfg(&s) {
                        tracing::warn!("规则索引重建失败（提交已落盘，索引与磁盘不一致）: {e}");
                        index_ok = false;
                    }
                }
                // **2.1.48 / serving_revision**：config 已生效且（规则变更时）索引已就绪。
                if index_ok {
                    s.state.mark_serving();
                }
                if let Some(hook) = s.on_reload.as_ref() {
                    // **2.1.49**：hook 现在返回 `Result`。配置已提交落盘，这里不反转
                    // 提交结果（5xx 会让客户端误以为配置没写），只把原因写日志。
                    if let Err(e) = hook(&new_cfg) {
                        tracing::warn!(
                            code = e.code,
                            detail = %e.detail,
                            "配置已提交，但热重载失败（规则索引保留上一份快照）"
                        );
                    }
                }
                let readonly_detail: Vec<Value> = readonly_hit
                    .iter()
                    .map(|k| json!({"key": k, "reason": cfg_readonly_reason(k)}))
                    .collect();
                return Ok(Json(json!({
                    "ok": true,
                    "ignored_keys": ignored,
                    "readonly_keys": readonly_hit,
                    "readonly_detail": readonly_detail,
                    "written_keys": obj
                        .keys()
                        .filter(|k| writable.contains(k.as_str()))
                        .cloned()
                        .collect::<Vec<_>>(),
                    "writable_keys": CFG_WRITABLE,
                    "saved_to": saved_to,
                    "revision": s
                        .state
                        .store()
                        .and_then(|st| st.current_revision()),
                    // **2.1.23（DEF-222-17）**：元字段单独回显（不再混进 `ignored_keys`）。
                    "meta_keys": meta_keys,
                })));
            }
            Err(e) => {
                // 提交点没动 ⇒ 磁盘还是上一代；内存也**从未**被改 ⇒ 零副作用。
                //
                // **[2.1.23（DEF-222-15，P1）修法]** 2.1.22 在这里对所有 `CommitError`
                // 先打一条 `tracing::error!`，**紧接着**才按变体分流 —— 于是
                // "冲突 ⇒ WARN" 在**逻辑上不可达**（`CONVENTIONS.md` §16.2 明文规定
                // "冲突 WARN、中止 ERROR"），生产 journal 里因此积了 104 条把 409
                // 记成 ERROR 的噪音，**让 409 与真故障不可分**。
                //
                // 现在：**交给唯一的** [`crate::api_state::commit_err_to_server`]，
                // 由它按变体分流（Conflict ⇒ WARN + 409、Io ⇒ ERROR + 500），
                // 本处不再自己打任何日志。这样"日志级别"只有一处定义。
                return Err(crate::api_state::commit_err_to_server(e));
            }
        }
    }
    let saved_to: Option<String> = if let Some(path) = &s.cfg_path {
        atomic_write_json(path, &new_cfg).await.map_err(|e| {
            tracing::error!("config save failed: {e}");
            ServerError::Internal
        })?;
        Some(path.display().to_string())
    } else {
        None
    };
    // 生效：替换内存配置。
    *s.cfg.write() = new_cfg.clone();
    // `rules` 变更 → 同步独立规则文件 + 重建规则索引（否则本次编辑对解析引擎不生效）。
    if rules_changed {
        if let Err(e) = crate::rules_admin::persist_current(&s, "put_config").await {
            // ---- **A-06 回滚**：内存 / 磁盘（**逐字节**）/ 规则索引一起回到原状 ----
            *s.cfg.write() = old_cfg.clone();
            let mut disk_restored = true;
            if let Some(path) = &s.cfg_path {
                match &orig_bytes {
                    // 原文件存在 ⇒ 原样写回**原始字节**（不重新序列化，避免键顺序/注入键差异）。
                    Some(b) => {
                        if let Err(e2) = atomic_write_bytes(path, b).await {
                            disk_restored = false;
                            tracing::warn!("配置回滚写盘失败（磁盘可能与内存不一致）: {e2}");
                        }
                    }
                    // 原文件不存在 ⇒ 本次是新建，删掉它即回到"不存在"。
                    None => {
                        if let Err(e2) = tokio::fs::remove_file(path).await {
                            if e2.kind() != std::io::ErrorKind::NotFound {
                                disk_restored = false;
                                tracing::warn!(
                                    "配置回滚删除失败（磁盘可能残留本次新建的文件）: {e2}"
                                );
                            }
                        }
                    }
                }
            }
            if let Err(e2) = crate::rules_admin::rebuild_index_from_cfg(&s) {
                tracing::warn!("规则索引回滚失败（内存配置已还原）: {e2}");
            }
            tracing::error!(
                disk_restored,
                "**PUT /api/config 规则落盘失败 ⇒ 已回滚**（内存配置与规则索引已还原；\
                 config.json 已按**原始字节**还原 = {}；本次提交**未生效**）：{e:?}",
                if disk_restored {
                    "逐字节未变"
                } else {
                    "**未能**逐字节还原（见上面 WARN）"
                }
            );
            return Err(e);
        }
    }
    // 运行时热重载（由 binary 注册的 hook；未注册则仅持久化）。
    if let Some(hook) = s.on_reload.as_ref() {
        let _ = hook(&new_cfg);
    }
    // ---- ② 三桶回报（含每个只读键的原因，前端只读区直接展示）----
    let readonly_detail: Vec<Value> = readonly_hit
        .iter()
        .map(|k| json!({"key": k, "reason": cfg_readonly_reason(k)}))
        .collect();
    Ok(Json(json!({
        "ok": true,
        // 兼容既有前端/脚本：**只含真正的未知键**（不再混入只读项）。
        "ignored_keys": ignored,
        // 只读 / 服务端管理项（原值保持不变）。
        "readonly_keys": readonly_hit,
        "readonly_detail": readonly_detail,
        // 本次实际写入的键（前端可据此提示"哪些生效了"）。
        "written_keys": obj
            .keys()
            .filter(|k| writable.contains(k.as_str()))
            .cloned()
            .collect::<Vec<_>>(),
        // 白名单快照（前端可自检"我摆的控件是否都在白名单里"）。
        "writable_keys": CFG_WRITABLE,
        "saved_to": saved_to,
        // **2.1.23（DEF-222-17）**：元字段（`if_revision`）单独回显，不进 `ignored_keys`。
        "meta_keys": meta_keys,
    })))
}

/// **2.1.23（DEF-222-19）：把 handler 暴露给集成测试的入口**。
///
/// 为什么需要它：`tests/fix222_state_txn.rs` 自称"走真实 handler 路径"，但 2.1.22 的
/// 7 个用例全部调用 `api_state::put_config_commit` + 本地助手，**复制**了 handler 的
/// 内存刷新与错误映射 —— 于是 409 的**HTTP 状态码 / 响应体 / 日志级别**结构性地测不到
/// （这正是 DEF-222-15 那个缺陷能活下来的原因）。
///
/// 本函数**就是** `put_config`（薄转发，不改任何语义），供集成测试直调 ⇒
/// "HTTP 级判据"（409 + 结构化响应体 + `failed_commits` 不增）才真的跑在**被测代码**上。
#[doc(hidden)]
pub async fn put_config_for_test(
    s: AppState,
    parts: axum::http::request::Parts,
    body: Value,
) -> ServerResult<Json<Value>> {
    put_config(State(s), parts, Json(body)).await
}

/// POST /api/query：`{domain, qtype}`。
/// 对齐 v1.9.162：多余键**忽略**（不报错）；`domain` 缺失或为空 → 400 `domain required`。
async fn query(State(s): State<AppState>, Json(body): Json<Value>) -> ServerResult<Json<Value>> {
    let obj = body
        .as_object()
        .ok_or_else(|| ServerError::BadRequest("body must be object".into()))?;
    let domain = obj
        .get("domain")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .ok_or_else(|| ServerError::BadRequest("domain required".into()))?;
    let qtype = obj
        .get("qtype")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|q| !q.is_empty())
        .unwrap_or("A")
        .to_ascii_uppercase();
    // 域名/类型校验（对齐 v1.9.162 _api_query 的 400 分支）。
    if domain.len() > 253 {
        return Err(ServerError::BadRequest("domain too long (max 253)".into()));
    }
    if !domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(ServerError::BadRequest("invalid domain characters".into()));
    }
    if domain.split('.').any(|label| label.chars().count() > 63) {
        return Err(ServerError::BadRequest(
            "domain label too long (max 63 chars)".into(),
        ));
    }
    // **2.1.21（DEF-220-03）**：受理集合 = 数据面 `SUPPORTED_QTYPES`（同一张表）。
    // 不受理的类型在此 **400 拒收**（给出与数据面 NOTIMP 一致的、"本服务不支持该类型"
    // 的语义），绝不"控制面 200 / 数据面 NOTIMP"两套结论。
    if parse_qtype(&qtype).is_none() {
        return Err(ServerError::BadRequest(format!("bad qtype: {qtype}")));
    }

    let res = s
        .resolver
        .clone()
        .resolve(
            domain,
            &qtype,
            ResolveOpts {
                silent: false,
                // 对齐 v1.9.162：手动查询**不计入** total/qtype_dist/qps/topN
                // （只推进延迟窗口），避免污染遥测口径。
                counted: false,
                force_refresh: false,
                client_ip: None,
                depth: 0,
                // 唯一需要 trace 的调用点（下方把 `res.trace` 序列化进响应）。
                // 数据面 `dns.rs` 保持 false：非人工查询不构造 trace。
                trace: true,
                ttl_cap: None,
            },
        )
        .await;
    // ---- **2.1.20（A-04 / A-05 / A-19 修复）：控制面计数与数据面口径完全分离** ----
    //
    // 2.1.19 及以前这里做两件**都会污染数据面指标**的事（审计 A-04/A-05 实测）：
    //   ① `if res.hit { inc_n("hit", 1) }` —— 但控制面**不计 `total`**（`counted:false`）
    //      ⇒ `hit_rate = hit/(hit+miss)`（2.1.40 起）仍可能被抬高，且 `hit+miss ≤ total`
    //      不成立，直接违反 `web/INTERFACE.md`「命中率卡显示 ≤100.0%」的验收条款；
    //   ② 用**查询报文**合成应答（`build_simple_response(query_wire, rcode)`，`ancount=0`）
    //      再走 `is_negative_answer`（`rcode==3 || ancount==0`）⇒ **恒判负**，
    //      于是"控制面查一条已缓存的正向 A 记录"也会让 `negative_hits` +1，
    //      与 `dns.rs` 注释宣称的"与数据面逐字节同源"不符。
    //
    // 现在的口径（**数据面指标只由数据面写**）：
    //   * `total`/`hit`/`miss`/`hit_rate`/`client_rcode`/`qps`/`topN` **只统计数据面**
    //     （UDP/TCP 的客户端查询）⇒ `hit+miss ≤ total` 与 `hit_rate ≤ 100%` 结构性成立；
    //   * 控制面单独计数：`control_queries`（每次 `POST /api/query` +1）与
    //     `control_hits`（其中由缓存直答的次数）——口径与数据面**分开**，各自可对账；
    //   * `negative_hits`：**只**用解析器给出的**真实结果**判定
    //     （`rcode == NXDOMAIN || answers 为空`），不再合成应答 ⇒ 正向 A 命中不再计负。
    //     控制面控制面的负命中**计入** `negative_hits`（它是"缓存里的负应答被直答"的
    //     真实事件，与谁发起查询无关），但判据必须与数据面同源。
    //
    // 与 `upstream_requests`（物理线速计数）的关系（A-19）：控制面**仍会**推高它 ——
    // 那是**物理**口径（真的向上游发了包），已在 README/INTERFACE 明示，不属污染。
    // >>> 242B BEGIN P1-7-query >>> //
    s.telemetry.inc_n("control_queries", 1);
    if res.hit {
        s.telemetry.inc_n("control_hits", 1);
        // **2.1.42-B（P1-7）**：控制面**不得**写 `negative_hits` —— 该键的口径是
        // "数据面缓存直答中的负应答"，是 `hit` 的子集。控制面命中只进
        // `control_hits`（与 `hit` 分离）；`negative_hits ⊆ hit` 因此结构性成立。
    }
    // <<< 242B END P1-7-query <<< //
    let answers: Vec<Value> = res
        .answers
        .iter()
        .map(|a| {
            json!({
                "type": a.rtype,
                "value": a.value,
                // 2.0 的 ResolveAnswer 不携带逐条答案的上游来源；页面「来源上游」列留空
                // （不伪造成 choosed——那是择优后的 IP，语义不同）。
                "from": "",
                "ttl": a.ttl,
            })
        })
        .collect();
    let trace: Vec<Value> = res
        .trace
        .iter()
        .map(|t| json!({"tag": t.tag, "text": t.text}))
        .collect();
    // 延迟单位：`ResolveResult::latency` 已是毫秒（旧实现误乘 1000 使页面显示 37 万 ms）。
    let latency_ms = res.latency;
    s.telemetry
        .record_manual(domain, &qtype, &res.chosen, res.hit, latency_ms, res.rcode);
    Ok(Json(json!({
        "domain": domain,
        "qtype": qtype,
        "rcode": res.rcode,
        "error": res.error,
        "hit": res.hit,
        "miss": !res.hit,
        "chosen": res.chosen,
        "latency": latency_ms,
        "latency_ms": latency_ms,
        "reason": res.reason,
        "trace": trace,
        "answers": answers,
        // v1.9.162 兼容键
        "empty": res.empty,
        "truncated": res.truncated,
        "ttl_left": res.ttl_left,
    })))
}

/// `proto` → URL scheme（`udp→udp`、`tcp→tcp`、`doh→https`、`doh3→http3`、
/// `dot→tls`、`doq→quic`，其余原样；大小写不敏感，前后空白忽略）。
///
/// **2.1.18（修复项 3）**：与前端 `telemetry.rs::proto_scheme` **同规则**；
/// 后端已成为唯一来源（见 [`full_addr_parts`] 的"单一来源"说明）。
///
/// 返回 `String`（不是 `&str`）："其余原样"分支要保留调用方传入的**原串**
/// （可能带空白），返回借用会让生命周期跟着入参走，调用方反而要额外绑定。
/// 本函数只在 `/api/upstreams` 视图组装时调用（每上游 1 次），不做热路径优化。
fn proto_scheme(proto: &str) -> String {
    match proto.trim().to_ascii_lowercase().as_str() {
        "udp" => "udp".to_string(),
        "tcp" => "tcp".to_string(),
        "doh" => "https".to_string(),
        "doh3" => "http3".to_string(),
        "dot" => "tls".to_string(),
        "doq" => "quic".to_string(),
        _ => proto.trim().to_string(),
    }
}

/// `url` 字段里只取路径：若是完整 URL（含 `://`）先剥掉 `scheme://host`，
/// 再归一化为「单个前导 `/` + 合并重复斜杠」；没有路径则返回空串。
///
/// **2.1.18（修复项 3）**：与前端 `telemetry.rs::addr_path` **同规则**逐行对齐
/// （前端保留该实现**仅作字段缺失时的兜底**）。
fn addr_path(url: &str) -> String {
    let mut p = url.trim();
    if p.is_empty() {
        return String::new();
    }
    if let Some(i) = p.find("://") {
        let rest = &p[i + 3..];
        p = match rest.find('/') {
            Some(j) => &rest[j..],
            None => "",
        };
    }
    let mut out = String::new();
    let mut prev_slash = false;
    for ch in p.chars() {
        if ch == '/' {
            if !prev_slash {
                out.push('/');
            }
            prev_slash = true;
        } else {
            out.push(ch);
            prev_slash = false;
        }
    }
    let out = out.trim_end_matches('/').to_string();
    if out.is_empty() {
        String::new()
    } else if out.starts_with('/') {
        out
    } else {
        format!("/{out}")
    }
}

/// **2.1.18（修复项 3）**：`scheme://host[:port][/path]` 的**唯一**计算实现。
///
/// 六协议 + 默认端口 + IPv6 + 路径的规则**逐条**与 2.1.17 前端
/// `web/src/pages/telemetry.rs::full_addr` 一致（该实现即本规则的参照物）：
/// - `proto`（大小写不敏感）：`udp→udp` / `tcp→tcp` / `doh→https` / `doh3→http3` /
///   `dot→tls` / `doq→quic`，其余原样；
/// - host 取 `host`（空则退回 `name`），**IPv6 加方括号**（已带 `[` 则不重复加）；
/// - 端口：`udp/tcp` **恒带**（端口是端点身份的一部分）；`doh/doh3` 的 **443**、
///   `dot/doq` 的 **853** 为默认端口时**省略**，非默认端口一律附 `:port`；
/// - 路径**只对 HTTP 系**（`https`/`http3`）追加（经 [`addr_path`] 归一化）；
///   `udp/tcp/dot/doq` 是裸 DNS 端点，配置里即便带 `url` 也不拼（否则会得到
///   `udp://223.5.5.5:53/dns-query` 这种不存在的端点）。
///
/// 退化情形：`host` 与 `name` 都为空 ⇒ 返回 `"://"`（调用方按需回退 `–`）。
fn full_addr_parts(proto: &str, host: &str, name: &str, port: u16, url: &str) -> String {
    let scheme = proto_scheme(proto);
    let host_raw = if !host.trim().is_empty() {
        host.trim()
    } else {
        name.trim()
    };
    let host_out = if host_raw.contains(':') && !host_raw.starts_with('[') {
        format!("[{host_raw}]")
    } else {
        host_raw.to_string()
    };
    let p = f64::from(port);
    let show_port = match scheme.as_str() {
        "udp" | "tcp" => p > 0.0,
        "https" | "http3" => p > 0.0 && (p - 443.0).abs() > f64::EPSILON,
        "tls" | "quic" => p > 0.0 && (p - 853.0).abs() > f64::EPSILON,
        _ => p > 0.0,
    };
    let mut s = format!("{scheme}://{host_out}");
    if show_port {
        s.push_str(&format!(":{port}"));
    }
    if matches!(scheme.as_str(), "https" | "http3") {
        s.push_str(&addr_path(url));
    }
    s
}

/// **2.1.18（修复项 3）**：逐上游视图（对齐 api.py:2538-2605 的字段与口径）。
///
/// 数据源 = upstream runtime 的 `HealthKeeper`（ok/fail/lat_sum），
/// **[历史归因]** 与 Python 的 `per_upstream` + `conn_stats` 同口径：
/// - `queries = ok + fail`
/// - `success_rate = 传输层 ok/total*100`（无样本 → `null`）
/// - `dns_success_rate = DNS 业务层 dns_ok/dns_total*100`（**2.1.21 / A-17**；
///   无业务样本 → `null`；分子 = `rcode ∈ {NOERROR, NXDOMAIN}` 且**未被截断**的
///   **物理**上游应答（不要求答案段非空）；SERVFAIL/REFUSED/NOTIMP/FORMERR/截断计入
///   `dns_fail`；每个物理应答只记一次，single-flight 不放大）
/// - `avg_latency = lat_sum/ok`（无成功样本回退配置静态 latency）
/// - `status`：待命 / 健康(≥85) / 抖动(≥60) / 异常
fn upstream_views(s: &AppState) -> Vec<Value> {
    // 2.1.8 优化项 8：逐上游只读视图新增字段的公共数据源。
    // - `role`：本轮默认路径下的角色（primary/backup/idle），一次算全表；
    // - `cb_view`：熔断只读视图（fails / until_in_s / probe_ok / probe_fail / open_count）。
    //
    // 关键顺序：`upstream_roles()` 内部会 `resolver.cfg.read()`，必须在**持有**
    // `resolver.config()` 读守卫**之前**算完 —— 否则同一把 parking_lot RwLock 上嵌套
    // 两次 read，一旦此刻有等待中的 writer（热重载/PUT 配置）就会自锁死。
    let roles = s.resolver.upstream_roles();
    let cfg = s.resolver.config();
    let rt = s.resolver.upstream_runtime();
    cfg.upstreams
        .iter()
        .map(|u| {
            let stats = rt.as_ref().map(|r| r.health.stats(&u.id));
            let ok = stats.as_ref().map(|x| x.ok_count()).unwrap_or(0);
            let fail = stats.as_ref().map(|x| x.fail_count()).unwrap_or(0);
            let total = ok + fail;
            // **2.1.20（A-11 修复：udp/tcp 上游的 `url`/`conn_key` 硬编码 `/dns-query`）**：
            // udp/tcp/dot 上游**没有 HTTP 路径概念**，此前却统一拼成 `udp|host|port|/dns-query`
            // 与 `"url": "/dns-query"`（审计 A-11 实测：`proto=udp` 的上游也带该路径）
            // ⇒ 前端"连接/路径"一列对非 HTTP 协议显示**不存在的东西**。
            // 现在取配置里的 `u.url`（udp/tcp 恒为空串），HTTP 家族才有路径。
            let url_suffix: String = u.url.trim().to_string();
            let conn_key = if url_suffix.is_empty() {
                format!("{}|{}|{}", u.proto, u.host, u.port)
            } else {
                format!("{}|{}|{}|{}", u.proto, u.host, u.port, url_suffix)
            };
            // 既有缺陷（2.1.8 引入，本轮修复）：熔断态**一次加锁读**。
            //
            // 旧实现在这里分两次独立加锁：`cb_is_open(uid)` 判是否打开、`cb_view(uid)`
            // 取 until/fails/open_count，`selectable` 又由第一次读的结果派生。两次读之间
            // 若发生「探针成功恢复」（`background.rs` 的半开探测落点 `cb_probe_ok`）或
            // 反向的「数据面失败打开熔断」，同一响应里就会出现自相矛盾组合：
            //   - `breaker_open=true, until_in_s=0, fails=0, circuit_open_count=0`
            //   - 或 `breaker_open=false, selectable=true, until_in_s=30`
            //
            // 修复：`breaker_open` / `until_in_s` / `fails` / `circuit_open_count` /
            // `probe_*` 全部由**同一次** `cb_view` 快照派生。`until_in_s` 是该快照内的
            // `max(until - now, 0)`，因此 `until_in_s > 0.0` 与旧 `is_open(uid, now)`
            // **逐位等价**（同一把锁、同一个 now），JSON 字段名与语义均不变。
            let cbv = s.resolver.cb_view(&u.id);
            let breaker_open = cbv.until_in_s > 0.0;
            // **2.1.19（F-05 修复：状态/成功率与熔断态自相矛盾）**
            //
            // 缺陷（部署代理实测）：`breaker_open:true, selectable:false, fails:8` 的上游
            // **同时**报 `status:"健康", success_rate:100.0`。两个原因：
            //   ① `status` 只看 `ok/(ok+fail)`，**完全不看** `breaker_open`；
            //   ② 成功率喂点是**传输层**成功（`runtime.rs:306` 的 `health.record(ok)`），
            //      DNS 层的 SERVFAIL **也算 ok** ⇒ 业务失败不体现在这里；
            //      而熔断的 `fails` 是**另一本账**，于是"ok 有样本、fail=0、fails=8"
            //      这种组合会出现，成功率自然 100%。
            //
            // 本轮修法（不改既有字段语义，只让它们**不再互相矛盾**）：
            //   * `success_rate` 明确为**传输层**成功率；**熔断打开时不再用"无样本 ⇒ 100%"
            //     的便利值**（那是把"没数据"显示成"完美"），改为实测率（无样本即 0）；
            //   * `status` 纳入 `breaker_open`（熔断中 ⇒ "熔断中"）与 `enabled`（⇒ "已禁用"），
            //     优先级高于成功率档位；
            //   * 两本账**分别下发**：`ok`/`fail` = 传输层（HealthKeeper），
            //     `breaker_fails` = 熔断账（`cbv.fails`）。运维一眼能看出差异来源。
            //
            // **未纳入本轮**（A-17，已登记 2.1.21）：把 DNS 层结果（SERVFAIL/NOERROR）做成
            // **逐上游**业务成功率 —— 需要在上游运行时按 rcode 记录第二维计数，属新功能。
            // 在那之前，本字段的名字与 HELP 文案都必须明示它是**传输层**口径（见下）。
            //
            // **2.1.20（A-20 修复："无样本 ⇒ 100%"是假数据）**：`success_rate` 改为
            // **可空**（`null`）：
            //   * `total == 0`（**没有**传输样本）⇒ `null`（此前给 100.0 —— 冷启动时
            //     每个上游都显示"成功率 100%"，与 `queries=0` 并列，是**编造的成功率**；
            //     审计 A-20 实测冷启动 `status/success_rate/queries` 三元组自相矛盾）；
            //   * `breaker_open` ⇒ `null`（熔断中，"最近 N 次全失败"与"成功率 100%"
            //     不能并存；当前失败率由 `fails`/`until_in_s` 表达）；
            //   * 有样本且未熔断 ⇒ 实测值。
            // 前端模型早已是 `Option<f64>` 且用 `–` 占位（`model.rs`），因此**无需**前端改动；
            // `status` 仍给出人类可读档位（待命/健康/抖动/异常/熔断中/已禁用）。
            let sr_opt: Option<f64> = if total == 0 || breaker_open {
                None
            } else {
                Some(ok as f64 / total as f64 * 100.0)
            };
            // **2.1.21（A-17 / DEF-220-09 实现：第二本账 —— DNS 业务成功率）**
            //
            // `success_rate` 是**传输层**成功率（UDP/TCP/TLS/QUIC 往返成功即 ok），
            // 因此"SERVFAIL 的上游"在它眼里是 100%。本字段是**业务层**口径：
            // 分子/分母来自 `UpstreamStats::dns_ok_count`/`dns_fail_count`
            // （唯一写入点 = `resolver::resolve::finish_resolve`，按真实 rcode 记）。
            //
            // 口径（**与 README / INTERFACE / `/metrics` HELP 逐字一致**）：
            // * 分母 = 该上游在**数据面**解析里返回的**物理应答数**（预取/健康探针
            //   **不计**，它们不承载客户端业务；single-flight 合并后的 N 个同键 miss
            //   只算 1 次 —— 见 `Resolver::record_dns_verdicts`）；
            // * 分子 = 其中 `rcode ∈ {NOERROR, NXDOMAIN}` 且**未被截断**的次数
            //   （**不要求答案段非空**：NXDOMAIN/NODATA 也是真实结论；
            //   SERVFAIL/REFUSED/NOTIMP/FORMERR/截断 = 业务失败）；

            // * **无业务样本 ⇒ `null`**（不是 0、不是 100 —— 冷启动不得编造）；
            // * 熔断打开时**仍然给出实测值**（它描述"最近这些应答怎么样"，与熔断态
            //   是两个独立事实；熔断态由 `status`/`breaker_open`/`fails` 表达）。
            let dns_ok_n = stats.as_ref().map(|x| x.dns_ok_count()).unwrap_or(0);
            let dns_fail_n = stats.as_ref().map(|x| x.dns_fail_count()).unwrap_or(0);
            let dns_total = dns_ok_n + dns_fail_n;
            let dns_sr_opt: Option<f64> = if dns_total == 0 {
                None
            } else {
                Some(dns_ok_n as f64 / dns_total as f64 * 100.0)
            };

            let avg = stats
                .as_ref()
                .and_then(|x| x.avg_latency())
                .unwrap_or(u.latency as f64);
            // `status` 的优先级：禁用 > 熔断中 > 成功率档位（"待命"= 无样本且未熔断）。
            let status = if !u.enabled {
                "已禁用"
            } else if breaker_open {
                "熔断中"
            } else if total == 0 {
                "待命"
            } else if sr_opt.unwrap_or(0.0) >= 85.0 {
                "健康"
            } else if sr_opt.unwrap_or(0.0) >= 60.0 {
                "抖动"
            } else {
                "异常"
            };
            // eff_lat_ms：`upstream_eff_lat`（有实测 → 成功均值，失败率 >50% 且样本 >10 时
            // +500ms 惩罚；**无实测样本 → 回退配置静态 `latency`**，与排序键同源）。
            // 恒为数值（不再返回 null）：前端那一列需要稳定可用；"是否实测"由
            // `latency_measured` / `eff_lat_measured` 区分，不做静默伪造。
            let eff_lat_ms = s.resolver.upstream_eff_lat(u);
            let eff_lat_ms = if eff_lat_ms.is_finite() {
                (eff_lat_ms * 10.0).round() / 10.0
            } else {
                u.latency as f64
            };
            let eff_lat_measured = stats.as_ref().map(|x| x.ok_count()).unwrap_or(0) > 0;
            json!({
                "id": u.id,
                "name": u.name,
                "proto": u.proto,
                // addr = v1.9.162 契约字段名（host 为 2.0 原字段，两者同值）
                "addr": u.host,
                "host": u.host,
                // **2.1.18（修复项 3）**：`scheme://host[:port][/path]` 的**唯一来源**。
                //
                // 为什么上提到后端（2.1.17 交付报告优化方向 2）：2.1.17 只把「图」与
                // 「健康度表」统一到前端的 `full_addr()`，后端**不提供**该字段 ——
                // 于是任何第三方脚本/断言/新页面都要**各自复刻**一遍规则，
                // 「图 vs 表 vs 文档 vs 脚本」四处漂移只是时间问题。
                // 现在：
                // - `/api/upstreams[].full_addr`（本函数）与
                //   `/api/snapshot.upstreams[].full_addr`（同一函数）**同源**；
                // - 前端改为消费本字段，本地实现**只作缺失兜底**（旧后端仍可用）；
                // - 规则实现见 [`full_addr_parts`]（与 2.1.17 前端逐条一致，单测钉死）。
                "full_addr": full_addr_parts(&u.proto, &u.host, &u.name, u.port, &u.url),
                "port": u.port,
                "url": url_suffix,
                "group": u.group,
                "latency": u.latency,
                "latency_measured": stats.as_ref().map(|x| x.measured()).unwrap_or(false),
                "weight": u.weight,
                "enabled": u.enabled,
                "queries": total,
                "ok": ok,
                "fail": fail,
                // **2.1.19（F-05）/ 2.1.20（A-20）**：本字段是**传输层**成功率
                // （HealthKeeper 的 ok/fail；DNS 层的 SERVFAIL **也算传输成功**，
                // 因此它 **≠** DNS 业务成功率 —— 逐上游业务成功率见 A-17/2.1.21）。
                // **无传输样本或熔断打开时返回 `null`**（不再用"无样本 ⇒ 100%"的假数据）。
                "success_rate": sr_opt.map(|v| (v * 10.0).round() / 10.0),
                // **2.1.21（A-17）**：DNS **业务**成功率（SERVFAIL 计的失败在这里）。
                // `null` = 还没有业务样本。见上面 `dns_sr_opt` 的口径说明。
                "dns_success_rate": dns_sr_opt.map(|v| (v * 10.0).round() / 10.0),
                "dns_ok": dns_ok_n,
                "dns_fail": dns_fail_n,
                "transport_ok": ok,
                "transport_fail": fail,

                "breaker_fails": cbv.fails,
                "avg_latency": (avg * 10.0).round() / 10.0,
                "last_latency": (avg * 10.0).round() / 10.0,
                "status": status,
                "breaker_open": breaker_open,
                // 连接级健康度（2.0 的连接统计与上游统计同源，键按 pool_key 形态给出）
                "conn_key": conn_key,
                "conn_ok": ok,
                "conn_fail": fail,
                "conn_avg_lat": (avg * 10.0).round() / 10.0,
                "allow_private_ip": u.allow_private_ip,
                /* ---- 2.1.8 优化项 8：只读派生字段（前端可直接消费） ---- */
                // 连续（数据面）失败数：熔断打开的分子，成功即归零。
                "fails": cbv.fails,
                // 熔断剩余秒数（未打开 = 0；已过期 = 0）。
                "until_in_s": (cbv.until_in_s * 10.0).round() / 10.0,
                // 连续打开次数（指数退避级别：1→open_s，2→2×，3→4×… 封顶 circuit_open_max_s）。
                "circuit_open_count": cbv.open_count,
                // 生效延迟（ms）：有实测用实测（含高失败率惩罚），无实测回退配置静态
                // `latency`；恒为数值，是否实测见 `eff_lat_measured`。
                "eff_lat_ms": eff_lat_ms,
                // `eff_lat_ms` 是否来自实测样本（false = 回退静态配置值）。
                "eff_lat_measured": eff_lat_measured,
                // 本轮是否可被选为候选（enabled 且未处于熔断打开态）。
                "selectable": u.enabled && !breaker_open,
                // 本轮默认路径下的角色：primary（首发）/ backup（回退候选）/ idle（未进候选）。
                "role": roles.get(&u.id).copied().unwrap_or("idle"),
                // 健康探针独立计数（优化项 2：探针失败不再计入 fails / 不打开熔断）。
                "probe_ok": cbv.probe_ok,
                "probe_fail": cbv.probe_fail,
            })
        })
        .collect()
}

/// **[历史归因]** top-N 上游（按查询数 = ok+fail 降序，取前 10；对齐 Python `top_upstreams`）。
///
/// **2.1.25（性能）**：本函数现在只是 [`top_upstreams_ranked`] 的一个"取数来源"而已 ——
/// 排序/截断/成形的**唯一实现**在 `top_upstreams_ranked` 里，`/api/snapshot`（本函数）与
/// `/api/status`（[`top_upstreams_direct`]）共用它，因此两条路径的输出**结构上不可能分叉**。
fn top_upstream_views(views: &[Value]) -> Vec<Value> {
    top_upstreams_ranked(top_upstream_rows(views))
}

/// 从**已建好的**逐上游视图里抽出排序键 `(id, queries)`（**不过滤**：过滤在 [`top_upstreams_ranked`]）。
fn top_upstream_rows(views: &[Value]) -> Vec<(String, u64)> {
    views
        .iter()
        .filter_map(|v| {
            let id = v.get("id").and_then(Value::as_str)?.to_string();
            let q = v.get("queries").and_then(Value::as_u64).unwrap_or(0);
            Some((id, q))
        })
        .collect()
}

/// **2.1.25（`/api/status` 性能项）**：直接从「解析器配置 + 健康计数」抽 `(id, queries)`，
/// **不建**那 N 个 ~40 键的逐上游 JSON 对象。
///
/// 缺陷（2.1.24 登记）：`/api/status` 只需要 top-10 的 `[id, queries]` 两元组，旧实现却调
/// [`upstream_views`] 把**每个**上游的完整视图（`full_addr` / `conn_key` 各一次 `format!`、
/// `dns_success_rate` / `status` / `eff_lat_ms` 等约 40 个键、每键一次 `json!` 分配与
/// `String` 克隆）全部造出来，再从里面读两个字段就丢掉。上游越多，这笔浪费越大，
/// 而 `/api/status` 是控制台 1 s 轮询的端点。
///
/// 口径与 [`upstream_views`] 的 `queries` **逐位相同**：`(ok_count + fail_count)`，
/// 取自同一个 `UpstreamRuntime::health.stats(&u.id)`，遍历同一个 `resolver.config().upstreams`。
fn upstream_query_rows(s: &AppState) -> Vec<(String, u64)> {
    let cfg = s.resolver.config();
    let rt = s.resolver.upstream_runtime();
    cfg.upstreams
        .iter()
        .map(|u| {
            let stats = rt.as_ref().map(|r| r.health.stats(&u.id));
            let ok = stats.as_ref().map(|x| x.ok_count()).unwrap_or(0);
            let fail = stats.as_ref().map(|x| x.fail_count()).unwrap_or(0);
            (u.id.clone(), ok + fail)
        })
        .collect()
}

/// 排序 / 截断 / 成形的**唯一实现**（两条取数路径共用）。
///
/// 判据（与 2.1.8 起的口径逐位一致）：过滤 `queries == 0` → 按 `queries` **降序**、
/// 同值按 `id` **升序** → 取前 **10** → 每行 `[id, queries]`。
fn top_upstreams_ranked(mut rows: Vec<(String, u64)>) -> Vec<Value> {
    rows.retain(|(_, q)| *q > 0);
    rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    rows.truncate(10);
    rows.into_iter().map(|(id, q)| json!([id, q])).collect()
}

/// `/api/status.top_upstreams` 的取数入口（**不建整表视图**）。
fn top_upstreams_direct(s: &AppState) -> Vec<Value> {
    top_upstreams_ranked(upstream_query_rows(s))
}

async fn snapshot(State(s): State<AppState>) -> Response {
    let now = now_epoch();
    // >>> 242B BEGIN P1-9-snapshot >>> //
    // **2.1.42-B（P1-9）**：观测端点**不得**改变淘汰顺序。
    // 旧实现 `keys()` 克隆全部 key，再对前 500 个调 `cache.get()`：LRU 上每次
    // `move_to_end`、TinyLFU 上 `sketch.inc` + 可能晋升 ⇒ 前端每 2 s 的轮询把
    // 前 500 条当成热点刷新，长期改变真实命中率（审计 A-05）。
    // 现在：`sample_keys(500)` 早停取键 + `peek()` 纯读（不 move / 不 inc / 不删）。
    let keys = s.resolver.cache().sample_keys(500);
    let mut entries = Vec::with_capacity(keys.len());
    for k in keys.iter() {
        if let Some(e) = s.resolver.cache().peek(k, now) {
            // <<< 242B END P1-9-snapshot <<< //
            // **P1-2（2.1.14）口径修正**：`ttl` 此前原样回显**写入时**的 TTL
            // （负缓存恒为 `neg_ttl_max`=60 → 实测"ttl 恒 60.0"，看起来像永不过期）。
            // 现在 `ttl` = **剩余** TTL（`expires_at - now`，0 表示即将过期），
            // 并把写入时的原值放在新增的 `ttl_stored` 里；两者都能观测，语义不再含混。
            let remaining = (e.expires_at - now).max(0.0);
            entries.push(json!({
                "domain": e.domain,
                "qtype": e.qtype,
                "ttl": (remaining * 10.0).round() / 10.0,
                "ttl_stored": e.ttl,
                "rcode": e.rcode,
                "chosen": e.chosen,
            }));
        }
    }
    // v1.9.162 契约：上游条目带协议/地址/分组/健康度与逐上游遥测（真实数据源 =
    // **[历史归因]** UpstreamRuntime 的 HealthKeeper，与 Python `per_upstream` 同口径）。
    let upstreams: Vec<Value> = upstream_views(&s);
    let cache_summary = s.resolver.cache().summary();
    let top_ups = top_upstream_views(&upstreams);
    let cfg_raw = s.cfg.read();
    // v1.9.162 的 `/api/snapshot` 同时带一份「状态摘要」（页面/脚本会读）。
    let snippet = json!({
        "cache_direct_enabled": cfg_raw
            .get("cache_direct_enabled")
            .cloned()
            .unwrap_or(json!(false)),
        "cache_size": cfg_raw.get("cache_size").cloned().unwrap_or(json!(16384)),
        "ttl": cfg_raw.get("ttl").cloned().unwrap_or(json!(300)),
        "prefetch": cfg_raw.get("prefetch").cloned().unwrap_or(json!(true)),
        "speed_test": cfg_raw.get("speed_test").cloned().unwrap_or(json!(true)),
        "ipv6": cfg_raw.get("ipv6").cloned().unwrap_or(json!(true)),
        "edns": cfg_raw.get("edns").cloned().unwrap_or(json!(true)),
        "fallback": cfg_raw.get("fallback").cloned().unwrap_or(json!(true)),
        "ipv4_first": cfg_raw.get("ipv4_first").cloned().unwrap_or(json!(true)),
    });
    // **2.1.18（修复项 2）**：counters 与 `/api/status.counters` **完全同源同代**
    // （同一个组装函数 + 一次 `with_snapshot`），并把代数序号一并下发。
    // 改前这里是独立的 `s.telemetry.counters()`，与 status 那次取数之间会有真实写入
    // ⇒ 两处都自称"同一时刻"其实差了几十条查询（E5 的另一种表现）。
    // **2.1.46（REV247 A-11）**：命中率与 counters 取自**同一代**快照。
    let (mut counters_map, snap_seq, counters_mono_ms, hit_rate) =
        s.telemetry.with_snapshot(|snap| {
            (
                counters_map_from(snap, &s),
                snap.seq,
                snap.monotonic_ms,
                crate::telemetry::ServerTelemetry::hit_rate_pct_of(snap),
            )
        });
    counters_map.insert("snapshot_seq".into(), json!(snap_seq));
    json_ok(json!({
    // >>> 242B BEGIN P1-9-total >>> //
            "entries": entries,
            // 采样只取前 500 个键，`total` 必须是**真实**条目数（不是样本长度）。
            "total": s.resolver.cache().len(),
    // <<< 242B END P1-9-total <<< //
            "manual_history": s.telemetry.manual_history(),
            "upstreams": upstreams,
            "events": s.telemetry.events_snapshot(),
            "cache": cache_summary,
            "map": cache_summary,
            "counters": Value::Object(counters_map),
            // 顶层同名键 = `counters.snapshot_seq`（同一个值，便于只读顶层的脚本）。
            "snapshot_seq": snap_seq,
            "counters_monotonic_ms": counters_mono_ms,
            "rule_hits": s.telemetry.rule_hits(),
            "top_domains": s.telemetry.top_domains(),
            "top_clients": s.telemetry.top_clients(),
            "history": s.telemetry.history_snapshot(),
            "qtype_dist": s.telemetry.qtype_dist(),
            "top_upstreams": top_ups,
            // ---- v1.9.162 兼容摘要块 ----
            "uptime_s": s.telemetry.uptime_s(),
            "running": true,
            // v1.9.162 `/api/snapshot` 契约：history 返回最近 60 点（内部环 120）。
            "hit_rate": hit_rate,
            "qps": s.telemetry.qps(),
            "avg_latency_ms": s.telemetry.avg_latency_opt(),
            "config_snippet": snippet,
        }))
}

/// GET /api/upstreams：注入健康/遥测。
async fn upstreams(State(s): State<AppState>) -> Response {
    // 对齐 v1.9.162 `_upstreams_with_health()`：必须带**真实健康度与逐上游遥测**
    // （queries / success_rate / avg_latency / status / latency / latency_measured /
    // addr / url / weight / allow_private_ip …），否则控制台「上游」页与任何按
    // 该端点取值的外部脚本都会拿到空字段（真实部署实测：只有 id/proto/host/port）。
    // `upstream_views()` 的数据源是 `UpstreamRuntime.health`（ok/fail/lat_sum）。
    json_ok(json!({ "upstreams": upstream_views(&s) }))
}

/* ---------------- 上游管理：白名单 / 校验 / CRUD / 重新测速 ---------------- */

/// 上游可写字段白名单（对齐 api.py `_UPSTREAM_WHITELIST`，api.py:674-682）。
const UPSTREAM_WHITELIST: &[&str] = &[
    "id",
    "name",
    "proto",
    "addr",
    "url",
    "port",
    "enabled",
    "latency",
    "latency_measured",
    "group",
    "weight",
    "allow_private_ip",
    "doh_strict_cert",
    "dot_strict_cert",
    "doq_strict_cert",
    "doh3_strict_cert",
];

/// 合法协议枚举（对齐 api.py `_ALLOWED_UPSTREAM_PROTO`，api.py:72）。
const ALLOWED_UPSTREAM_PROTO: &[&str] = &["udp", "tcp", "doh", "dot", "doq", "doh3"];

/// 协议枚举的字典序视图（对齐 api.py:2926 `"/".join(sorted(_ALLOWED_UPSTREAM_PROTO))`）。
const ALLOWED_UPSTREAM_PROTO_SORTED: &[&str] = &["doh", "doh3", "doq", "dot", "tcp", "udp"];

/// 重新测速固定探测域名（对齐 probe.py `PROBE_DOMAIN`，probe.py:18）。
const PROBE_DOMAIN: &str = "www.baidu.com";

/// 重新测速并发上限（对齐 probe.py:138 `min(8, max(1, len(ups)))`）。
const PROBE_MAX_CONCURRENCY: usize = 8;

/// base36 字母表（id 生成用）。
const BASE36: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";

/// 上游 CRUD 的错误响应（对齐 api.py 的 400 / 404 / 500 三种响应体，api.py:2719/2801/2822）。
///
/// 本文件不直接复用 [`ServerError`]：`ServerError::Internal` 是 unit 变体（见 error.rs:36），
/// **[历史归因]** 无法携带 Python 的 `配置写盘失败（已回滚内存变更）` 文案与 `"ok":false` 伴生键
/// （rules_admin.rs:14 对此有同样记录）。
#[derive(Debug, PartialEq)]
enum UpstreamApiError {
    /// 400：字段/取值非法。
    BadRequest(String),
    /// 404：id 不存在。
    NotFound,
    /// 500：写盘失败（内存必已回滚，与磁盘一致）。
    WriteFailed,
}

impl UpstreamApiError {
    fn bad(msg: impl Into<String>) -> Self {
        UpstreamApiError::BadRequest(msg.into())
    }
}

impl IntoResponse for UpstreamApiError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            UpstreamApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, json!({"error": m})),
            UpstreamApiError::NotFound => (
                StatusCode::NOT_FOUND,
                json!({"error": "upstream not found"}),
            ),
            UpstreamApiError::WriteFailed => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": "配置写盘失败（已回滚内存变更）", "ok": false}),
            ),
        };
        (status, Json(body)).into_response()
    }
}

/// **[历史归因]** Python 真值语义（`body.get("addr")` / `or "domestic"` 的 `or`）。
fn json_truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

/// **[历史归因]** 宽松整数解析（对齐 Python `int(v)`）：拒绝布尔/容器；数字与数字字符串可解析。
fn coerce_int(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f.trunc() as i64)),
        Value::String(s) => {
            let t = s.trim();
            t.parse::<i64>()
                .ok()
                .or_else(|| t.parse::<f64>().ok().map(|f| f.trunc() as i64))
        }
        // **[历史归因]** Bool / Null / Array / Object 一律不可解析（Python 亦拒绝 bool）。
        _ => None,
    }
}

/// 宽松浮点解析（weight 允许 int/float，对齐 api.py:2895-2903）。
fn coerce_f64(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        _ => None,
    }
}

/// **[历史归因]** 宽松布尔归一（对齐 Python `_as_bool`，api.py:403-434）：
/// 可识别真/假值表；畸形值回落 `default`（安全方向——`*_strict_cert` 缺省 true）。
fn as_bool_loose(v: &Value, default: bool) -> bool {
    match v {
        Value::Bool(b) => *b,
        Value::Null => default,
        Value::Number(n) => n
            .as_f64()
            .map(|f| f.is_finite() && f != 0.0)
            .unwrap_or(default),
        Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => default,
        },
        // 容器对布尔字段属畸形输入 → default（不借空/非空真值翻安全键）。
        _ => default,
    }
}

/// 上游 addr 字符集白名单（对齐 api.py:180 `^[a-zA-Z0-9._:\[\]-]{1,253}$`）。
fn valid_host(host: &str) -> bool {
    let n = host.chars().count();
    (1..=253).contains(&n)
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '[' | ']' | '-'))
}

/// 上游 id 字符集（对齐 config.py:466 `_UPSTREAM_ID_RE = ^[A-Za-z0-9_.:-]{1,64}$`）。
fn valid_upstream_id(id: &str) -> bool {
    let n = id.chars().count();
    (1..=64).contains(&n)
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
}

/// DoH 路径控制字符白名单（对齐 api.py:202-209 `_valid_url_path`）：
/// 允许空串；拒绝 ord < 0x20 与 0x7f(DEL)。
fn valid_url_path(url: &str) -> bool {
    url.chars().all(|c| c >= ' ' && c != '\u{7f}')
}

/// 协议默认端口（对齐 api.py:2722 `_default_port`）。
fn proto_default_port(proto: &str) -> u16 {
    match proto {
        "doh" | "doh3" => 443,
        "dot" | "doq" => 853,
        _ => 53,
    }
}

/// 该协议是否携带 URL 路径（DoH/DoH3/DoQ）。
fn is_dohish(proto: &str) -> bool {
    matches!(proto, "doh" | "doh3" | "doq")
}

/// 自动解析分支的 host 字符集（对齐 crates/ebpdns-upstream/src/addr.rs:74-83）。
fn host_char_ok(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '[' | ']')
}

/// 自动解析结果（字段同 `ebpdns_upstream::ParsedAddr`）。
struct LocalParsedAddr {
    proto: String,
    host: String,
    port: u16,
    url: String,
}

/// `addr` 是否内嵌 host:port（对齐 api.py:212-230 `_addr_has_explicit_port`）：
/// 内嵌端口时以解析结果为准，body 显式 port 不覆盖。
fn addr_has_explicit_port(raw: &str) -> bool {
    let mut s = raw.trim();
    if let Some((_, after)) = s.split_once("://") {
        s = after;
    }
    if let Some(i) = s.find('/') {
        s = &s[..i];
    }
    if s.is_empty() {
        return false;
    }
    // 裸 IPv6（多冒号且未方括号）不切端口。
    if s.matches(':').count() > 1 && !s.starts_with('[') {
        return false;
    }
    match s.rfind(':') {
        Some(c) if c > 0 => {
            let tail = &s[c + 1..];
            !tail.is_empty() && tail.chars().all(|ch| ch.is_ascii_digit())
        }
        _ => false,
    }
}

/// 从完整地址串自动识别协议/主机/端口/路径。
///
/// 说明：**不调用** `ebpdns_upstream::parse_upstream_addr` —— `crates/ebpdns-server/Cargo.toml:9-33`
/// 未依赖 `ebpdns-upstream`（本 crate 无法命名该 crate 的任何符号），且本任务只允许改动本文件、
/// **[历史归因]** 不允许新增依赖。故此处按 `ebpdns-upstream/src/addr.rs:150-309` 与 Python
/// `config.parse_upstream_addr`（config.py:224-334）逐分支等价移植，包括：
/// scheme 识别（https/http/quic/doq/tls/dot/udp/tcp/doh/doh3/http3/h3）、`http://` 默认 80、
/// 路径切分、`[v6]`/`[v6]:port`/裸 host:port 三类端口切分、host 字符集与长度、
/// **[历史归因]** 残留单冒号拒绝、端口范围 1-65535。返回 `None` 时调用方回退「手动分支」（与 Python 一致）。
fn parse_upstream_addr_local(raw: &str, proto_sel: Option<&str>) -> Option<LocalParsedAddr> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let mut proto: Option<String> = None;
    let mut rest: &str = s;
    let mut url = String::new();
    let mut http_plain = false;
    if let Some(colon) = s.find(':') {
        let after = &s[colon + 1..];
        if let Some(rest_) = after.strip_prefix("//") {
            let scheme = s[..colon].to_ascii_lowercase();
            rest = rest_;
            match scheme.as_str() {
                "https" => {
                    proto = Some("doh".into());
                    url = "/dns-query".into();
                }
                "http" => {
                    proto = Some("doh".into());
                    url = "/dns-query".into();
                    http_plain = true;
                }
                "quic" | "doq" => {
                    proto = Some("doq".into());
                    url = "/dns-query".into();
                }
                "tls" | "dot" => proto = Some("dot".into()),
                "udp" => proto = Some("udp".into()),
                "tcp" => proto = Some("tcp".into()),
                "doh" => {
                    proto = Some("doh".into());
                    url = "/dns-query".into();
                }
                "doh3" => {
                    proto = Some("doh3".into());
                    url = "/dns-query".into();
                }
                "http3" | "h3" => {
                    proto = Some("doh3".into());
                    url = "/dns-query".into();
                }
                _ => return None,
            }
        }
    }
    let proto = match proto {
        Some(p) => p,
        None => {
            let sel = proto_sel.unwrap_or("").trim().to_string();
            if !sel.is_empty() && sel != "auto" {
                // **[历史归因]** 注意：proto_sel 分支与 Python 一致「原样采用」，枚举校验由调用方兜底 400。
                if is_dohish(&sel) {
                    url = "/dns-query".into();
                }
                sel
            } else {
                "udp".to_string()
            }
        }
    };
    let mut host = rest.to_string();
    let mut port = if http_plain {
        80
    } else {
        proto_default_port(&proto)
    };
    if let Some(slash) = host.find('/') {
        let p = &host[slash..];
        if is_dohish(&proto) {
            url = if p.starts_with('/') {
                p.to_string()
            } else {
                format!("/{p}")
            };
        }
        host.truncate(slash);
    }
    if let Some(inner) = host.strip_prefix('[') {
        // [v6] / [v6]:port
        let rb = inner.find(']')?;
        if rb == 0 {
            return None;
        }
        let after = &inner[rb + 1..];
        if !after.is_empty() {
            let num = after.strip_prefix(':')?;
            if num.is_empty() || !num.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            port = num.parse().ok()?;
        }
        host = inner[..rb].to_string();
    } else if host.matches(':').count() <= 1 {
        if let Some(colon) = host.rfind(':') {
            if colon > 0 {
                let tail = &host[colon + 1..];
                if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) {
                    port = tail.parse().ok()?;
                    host.truncate(colon);
                }
            }
        }
    }
    if host.is_empty() || host.chars().count() > 253 {
        return None;
    }
    if !host.chars().all(host_char_ok) {
        return None;
    }
    // 切分后仍残留单冒号（"example.com:" / "host:abc"）→ 畸形。
    if host.matches(':').count() == 1 {
        return None;
    }
    if !(1..=65535).contains(&port) {
        return None;
    }
    if is_dohish(&proto) {
        if url.is_empty() {
            url = "/dns-query".into();
        } else if !url.starts_with('/') {
            url = format!("/{url}");
        }
    } else {
        url.clear();
    }
    Some(LocalParsedAddr {
        proto,
        host,
        port,
        url,
    })
}

/// **[历史归因]** 生成上游 id：`u<epoch_ms>_<6 位 base36>`（任务契约；Python `_new_id` 为 `u<ms><4 位 hex>`）。
fn new_upstream_id() -> String {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let ms = (now_epoch() * 1000.0) as u64;
    // ms 低位 + 进程内序号混合后取 base36 低 6 位：同一毫秒内连续创建也不同 id。
    let mut x = ms
        .wrapping_mul(1_000_003)
        .wrapping_add(seq.wrapping_mul(21_791))
        % 36u64.pow(6);
    let mut buf = [b'0'; 6];
    for i in (0..6).rev() {
        buf[i] = BASE36[(x % 36) as usize];
        x /= 36;
    }
    format!("u{ms}_{}", String::from_utf8_lossy(&buf))
}

/// 生成不与现有上游冲突的 id。
fn new_unique_id(list: &[Value]) -> String {
    for _ in 0..8 {
        let cand = new_upstream_id();
        if !list
            .iter()
            .any(|u| u.get("id").and_then(Value::as_str) == Some(cand.as_str()))
        {
            return cand;
        }
    }
    new_upstream_id()
}

/// 默认上游名 `上游 N`（跳过已占用名，对齐 api.py:359-369 `_default_upstream_name`）。
fn default_upstream_name(list: &[Value]) -> String {
    let used: Vec<&str> = list
        .iter()
        .filter_map(|u| u.get("name").and_then(Value::as_str))
        .collect();
    let mut n = list.len() + 1;
    loop {
        let cand = format!("上游 {n}");
        if !used.contains(&cand.as_str()) {
            return cand;
        }
        n += 1;
    }
}

/// 读 `cfg["upstreams"]`（缺失/非数组 → 空列表）。
fn cfg_upstreams(cfg: &Value) -> Vec<Value> {
    cfg.get("upstreams")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// 写回 `cfg["upstreams"]`（cfg 非对象时先归一为对象）。
fn set_cfg_upstreams(cfg: &mut Value, list: Vec<Value>) {
    if !cfg.is_object() {
        *cfg = Value::Object(Map::new());
    }
    if let Some(o) = cfg.as_object_mut() {
        o.insert("upstreams".to_string(), Value::Array(list));
    }
}

/// POST 可选字段提取（对齐 api.py:437-464 `_upstream_optional_fields`）：
/// 仅收集 body 显式提供的键，weight 范围 0-1000，布尔字段就地归一。
fn upstream_optional_fields(
    obj: &Map<String, Value>,
) -> Result<Map<String, Value>, UpstreamApiError> {
    let mut fields = Map::new();
    if let Some(w) = obj.get("weight") {
        if !w.is_null() {
            let n = coerce_f64(w)
                .ok_or_else(|| UpstreamApiError::bad("weight 必须是数字 (不能是布尔值)"))?;
            if !(0.0..=1000.0).contains(&n) {
                return Err(UpstreamApiError::bad(format!(
                    "weight 必须在 0-1000 之间 (got {n})"
                )));
            }
            fields.insert("weight".into(), json!(n));
        }
    }
    for (k, d) in [
        ("allow_private_ip", false),
        ("doh_strict_cert", true),
        ("dot_strict_cert", true),
        ("doq_strict_cert", true),
        ("doh3_strict_cert", true),
    ] {
        if let Some(v) = obj.get(k) {
            fields.insert(k.to_string(), json!(as_bool_loose(v, d)));
        }
    }
    Ok(fields)
}

/// 校验 body 的可选 port（对齐 api.py:2728-2741）：显式 0/越界 → 400，缺失 → None。
fn check_body_port(v: Option<&Value>) -> Result<Option<u16>, UpstreamApiError> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(_)) => Err(UpstreamApiError::bad("port 不允许是布尔值")),
        Some(x) => {
            let n = coerce_int(x).ok_or_else(|| UpstreamApiError::bad("port 必须是整数"))?;
            if !(1..=65535).contains(&n) {
                return Err(UpstreamApiError::bad(format!(
                    "port 必须在 1-65535 之间 (got {n})"
                )));
            }
            Ok(Some(n as u16))
        }
    }
}

/// 校验 body 的可选 latency（POST 仅校验合法性；落库统一 0 = 待实测）。
fn check_body_latency(v: Option<&Value>) -> Result<(), UpstreamApiError> {
    match v {
        None | Some(Value::Null) => Ok(()),
        Some(Value::Bool(_)) => Err(UpstreamApiError::bad("latency 不允许是布尔值")),
        Some(x) => coerce_int(x)
            .map(|_| ())
            .ok_or_else(|| UpstreamApiError::bad("latency 必须是整数")),
    }
}

/// 决定新上游 id：显式提供 → 字符集校验 + 查重（重复 400）；缺失/空串 → 自动生成。
fn pick_new_upstream_id(
    list: &[Value],
    obj: &Map<String, Value>,
) -> Result<String, UpstreamApiError> {
    match obj.get("id") {
        None | Some(Value::Null) => Ok(new_unique_id(list)),
        Some(Value::String(x)) if !x.trim().is_empty() => {
            let x = x.trim().to_string();
            if !valid_upstream_id(&x) {
                return Err(UpstreamApiError::bad(format!(
                    "非法 id: {x} (仅允许 [A-Za-z0-9_.:-], 长度 1-64)"
                )));
            }
            if list
                .iter()
                .any(|u| u.get("id").and_then(Value::as_str) == Some(x.as_str()))
            {
                return Err(UpstreamApiError::bad(format!("上游 id 重复: {x}")));
            }
            Ok(x)
        }
        Some(Value::String(_)) => Ok(new_unique_id(list)),
        Some(_) => Err(UpstreamApiError::bad("id 必须是字符串")),
    }
}

/// 上游写事务：内存替换 → 原子落盘 → `on_reload`；**写盘失败回滚内存**（对齐 api.py:2698-2719）。
///
/// 与 [`put_config`] 同型：`cfg_path` 为 None（测试/无文件场景）时只改内存。
async fn commit_upstreams(
    s: &AppState,
    prev: &Value,
    next: &Value,
) -> Result<(), UpstreamApiError> {
    // **2.1.22**：`state/` 已启用 ⇒ 经统一事务提交（提交点 = `commit.json` 原子替换）。
    // 失败时**磁盘仍是上一代**，只需把内存也还原成 `prev`（与旧路径同语义，但
    // 不再有"config.json 已改、规则文件没改"的撕裂窗口）。
    if s.state.is_on() {
        match crate::api_state::commit_cfg_only(s, "api:upstreams", next).await {
            Ok(_) => {
                *s.cfg.write() = next.clone();
                if let Some(hook) = s.on_reload.as_ref() {
                    if let Err(e) = hook(next) {
                        tracing::warn!(
                            code = e.code,
                            detail = %e.detail,
                            "上游配置已提交，但热重载失败（规则索引保留上一份快照）"
                        );
                    }
                }
                return Ok(());
            }
            Err(e) => {
                tracing::error!("上游配置提交中止（磁盘仍是上一代，内存已回滚）: {e}");
                *s.cfg.write() = prev.clone();
                return Err(UpstreamApiError::WriteFailed);
            }
        }
    }
    *s.cfg.write() = next.clone();
    if let Some(path) = s.cfg_path.as_ref() {
        if let Err(e) = atomic_write_json(path, next).await {
            tracing::error!("上游配置写盘失败（已回滚内存变更）: {e}");
            *s.cfg.write() = prev.clone();
            return Err(UpstreamApiError::WriteFailed);
        }
    }
    // 运行时热重载（由 binary 注册；未注册则仅持久化）。
    if let Some(hook) = s.on_reload.as_ref() {
        if let Err(e) = hook(next) {
            tracing::warn!(
                code = e.code,
                detail = %e.detail,
                "上游配置已落盘，但热重载失败（规则索引保留上一份快照）"
            );
        }
    }
    Ok(())
}

/// POST /api/upstreams 的实现体（对齐 api.py:2607-2802 `_api_add_upstream`）。
///
/// **[历史归因]** 两个分支与 Python 一致：
/// - **自动识别分支**：`addr` 非空且可解析出 scheme/host:port → 解析结果为准，响应加 `"auto_parsed":true`；
/// - **手动分支**：`addr` 缺失/为空（兜底 `223.5.5.5`）或地址串无法识别。
///
/// **[历史归因]** 白名单口径：POST 与 Python 一致**只落库白名单内字段**（未知键静默丢弃，不 400；
/// 400 的未知键检查只出现在单条 PUT 路径，见 [`normalize_upstream_field`]）。
async fn upstream_add(s: &AppState, body: Value) -> Result<Value, UpstreamApiError> {
    let obj = body
        .as_object()
        .ok_or_else(|| UpstreamApiError::bad("upstream must be an object"))?;
    // P2-4：必须提供 addr 或 name（消除「空请求静默创建默认上游」）。
    if !json_truthy(obj.get("addr")) && !json_truthy(obj.get("name")) {
        return Err(UpstreamApiError::bad("addr or name is required"));
    }
    // name/group 类型与长度（与 PUT/bulk 同型）。
    if let Some(n) = obj.get("name") {
        let n = n
            .as_str()
            .ok_or_else(|| UpstreamApiError::bad("name 必须是字符串"))?;
        if n.chars().count() > 256 {
            return Err(UpstreamApiError::bad("name 过长 (上限 256 字符)"));
        }
    }
    if let Some(g) = obj.get("group") {
        if !g.is_null() && !g.is_string() {
            return Err(UpstreamApiError::bad("group 必须是字符串"));
        }
    }
    let addr_raw = match obj.get("addr") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(_) => return Err(UpstreamApiError::bad("addr must be a string")),
    };
    let enabled = obj
        .get("enabled")
        .map(|v| as_bool_loose(v, true))
        .unwrap_or(true);
    let group = obj
        .get("group")
        .and_then(Value::as_str)
        .map(|g| g.to_string())
        .unwrap_or_else(|| "domestic".to_string());
    // 可选字段（weight/allow_private_ip/4 个 strict_cert）两个分支共用；
    // **[历史归因]** 校验顺序对齐 Python：分支内的 proto/port/url 先校验，可选字段最后（api.py:2684-2688）。
    check_body_latency(obj.get("latency"))?;
    let raw_trim = addr_raw.trim();
    // **[历史归因]** 对齐 Python `_api_add_upstream`：addr 非空时**总是**尝试 `parse_upstream_addr`
    // （它只对畸形输入返回 None：空串、`[]`/未闭合 `[`、未知 scheme）。proto_sel
    // 只是"无 scheme 时强制协议"，不是"走手动分支"的开关。
    let parsed = if raw_trim.is_empty() {
        None
    } else {
        parse_upstream_addr_local(raw_trim, obj.get("proto").and_then(Value::as_str))
    };
    let auto_parsed = parsed.is_some();
    // 上游对象骨架（id 在事务段插入，name 同理）。
    let mut u: Map<String, Value> = Map::new();
    match parsed {
        Some(p) => {
            // proto 枚举兜底（parse 的 proto_sel 分支原样采用任意串，需在此拒绝）。
            if !ALLOWED_UPSTREAM_PROTO.contains(&p.proto.as_str()) {
                return Err(UpstreamApiError::bad(format!(
                    "非法 proto: {} (允许: {})",
                    p.proto,
                    ALLOWED_UPSTREAM_PROTO.join("/")
                )));
            }
            let mut port = p.port;
            // 显式 port：仅在 addr 未内嵌 host:port 时覆盖解析默认端口（对齐 api.py:2650-2669）。
            if let Some(bp) = check_body_port(obj.get("port"))? {
                if !addr_has_explicit_port(raw_trim) {
                    port = bp;
                }
            }
            if !valid_url_path(&p.url) {
                return Err(UpstreamApiError::bad(format!(
                    "非法 url: {} (不允许包含控制字符)",
                    p.url
                )));
            }
            u.insert("proto".into(), json!(p.proto));
            u.insert("addr".into(), json!(p.host));
            u.insert("port".into(), json!(port));
            u.insert("url".into(), json!(p.url));
        }
        None => {
            let proto = obj
                .get("proto")
                .and_then(Value::as_str)
                .unwrap_or("udp")
                .trim()
                .to_ascii_lowercase();
            if !ALLOWED_UPSTREAM_PROTO.contains(&proto.as_str()) {
                return Err(UpstreamApiError::bad(format!(
                    "非法 proto: {proto} (允许: {})",
                    ALLOWED_UPSTREAM_PROTO.join("/")
                )));
            }
            let addr = if raw_trim.is_empty() {
                "223.5.5.5".to_string()
            } else {
                raw_trim.to_string()
            };
            if !valid_host(&addr) {
                return Err(UpstreamApiError::bad(format!(
                    "非法 addr: {addr} (仅允许 IPv4/IPv6/主机名字符集)"
                )));
            }
            let port =
                check_body_port(obj.get("port"))?.unwrap_or_else(|| proto_default_port(&proto));
            // 手动分支：DoH/DoH3/DoQ 取 body.url（缺省 /dns-query），其余协议恒空串。
            let url = if is_dohish(&proto) {
                obj.get("url")
                    .and_then(Value::as_str)
                    .map(|u| u.to_string())
                    .unwrap_or_else(|| "/dns-query".to_string())
            } else {
                String::new()
            };
            if !valid_url_path(&url) {
                return Err(UpstreamApiError::bad(format!(
                    "非法 url: {url} (不允许包含控制字符)"
                )));
            }
            u.insert("proto".into(), json!(proto));
            u.insert("addr".into(), json!(addr));
            u.insert("port".into(), json!(port));
            u.insert("url".into(), json!(url));
        }
    }
    // **[历史归因]** 可选字段校验（Python 在分支校验通过后才做）。
    let optional = upstream_optional_fields(obj)?;
    u.insert("group".into(), json!(group));
    // 新上游 latency 统一 0（= 未测速，待实测写回），对齐 api.py:2680/2765。
    u.insert("latency".into(), json!(0));
    u.insert("latency_measured".into(), json!(false));
    u.insert("enabled".into(), json!(enabled));
    for (k, v) in optional {
        u.insert(k, v);
    }
    // ---- 事务段：重新取最新 cfg（防持旧 cfg 覆盖并发更新），id/name 在此落定 ----
    let prev = s.cfg.read().clone();
    let list = cfg_upstreams(&prev);
    let id = pick_new_upstream_id(&list, obj)?;
    let name = obj
        .get("name")
        .and_then(Value::as_str)
        .filter(|n| !n.is_empty())
        .map(|n| n.to_string())
        .unwrap_or_else(|| default_upstream_name(&list));
    u.insert("id".into(), json!(id));
    u.insert("name".into(), json!(name));
    let mut next_list = list;
    next_list.push(Value::Object(u.clone()));
    let mut next = prev.clone();
    set_cfg_upstreams(&mut next, next_list);
    commit_upstreams(s, &prev, &next).await?;
    let stored = Value::Object(u);
    if auto_parsed {
        Ok(json!({"ok": true, "upstream": stored, "auto_parsed": true}))
    } else {
        Ok(json!({"ok": true, "upstream": stored}))
    }
}

/// 单条 PUT 的字段校验 + 归一（对齐 api.py:2879-2949 `_api_upstream_op` 的更新分支）。
fn normalize_upstream_field(k: &str, v: &Value) -> Result<Value, UpstreamApiError> {
    match k {
        "id" => Err(UpstreamApiError::bad("不允许修改上游 id")),
        "port" => {
            if v.is_boolean() {
                return Err(UpstreamApiError::bad("port 不允许是布尔值"));
            }
            let n = coerce_int(v).ok_or_else(|| UpstreamApiError::bad("port 必须是整数"))?;
            if !(1..=65535).contains(&n) {
                return Err(UpstreamApiError::bad(format!(
                    "port 必须在 1-65535 之间 (got {n})"
                )));
            }
            Ok(json!(n))
        }
        "latency" => {
            if v.is_boolean() {
                return Err(UpstreamApiError::bad("latency 不允许是布尔值"));
            }
            let n = coerce_int(v).ok_or_else(|| UpstreamApiError::bad("latency 必须是整数"))?;
            if !(0..=3_600_000).contains(&n) {
                return Err(UpstreamApiError::bad(format!(
                    "latency 必须在 0-3600000 ms 之间 (got {n})"
                )));
            }
            Ok(json!(n))
        }
        "weight" => {
            if v.is_boolean() {
                return Err(UpstreamApiError::bad("weight 必须是数字 (不能是布尔值)"));
            }
            let n = coerce_f64(v)
                .ok_or_else(|| UpstreamApiError::bad("weight 必须是数字 (不能是布尔值)"))?;
            if !(0.0..=1000.0).contains(&n) {
                return Err(UpstreamApiError::bad(format!(
                    "weight 必须在 0-1000 之间 (got {n})"
                )));
            }
            Ok(json!(n))
        }
        "enabled" => Ok(json!(as_bool_loose(v, true))),
        "allow_private_ip" => Ok(json!(as_bool_loose(v, false))),
        "doh_strict_cert" | "dot_strict_cert" | "doq_strict_cert" | "doh3_strict_cert" => {
            Ok(json!(as_bool_loose(v, true)))
        }
        "latency_measured" => Ok(json!(as_bool_loose(v, false))),
        "proto" => {
            let p = v.as_str().unwrap_or("").trim().to_ascii_lowercase();
            if !ALLOWED_UPSTREAM_PROTO.contains(&p.as_str()) {
                return Err(UpstreamApiError::bad(format!(
                    "proto 必须是 {} 之一",
                    ALLOWED_UPSTREAM_PROTO_SORTED.join("/")
                )));
            }
            Ok(json!(p))
        }
        "addr" => {
            let a = v.as_str().unwrap_or("");
            if !valid_host(a) {
                return Err(UpstreamApiError::bad(format!(
                    "非法 addr: {a} (仅允许 IPv4/IPv6/主机名字符集)"
                )));
            }
            Ok(json!(a))
        }
        "url" => {
            // 对齐 `_valid_url_path(None) == True`：允许显式 null。
            if v.is_null() {
                return Ok(Value::Null);
            }
            let u = v
                .as_str()
                .ok_or_else(|| UpstreamApiError::bad("非法 url: 不允许包含控制字符"))?;
            if !valid_url_path(u) {
                return Err(UpstreamApiError::bad("非法 url: 不允许包含控制字符"));
            }
            Ok(json!(u))
        }
        "name" => {
            let n = v
                .as_str()
                .ok_or_else(|| UpstreamApiError::bad("name 必须是字符串"))?;
            if n.chars().count() > 256 {
                return Err(UpstreamApiError::bad("name 过长 (上限 256 字符)"));
            }
            Ok(json!(n))
        }
        "group" => {
            if v.is_null() {
                return Ok(Value::Null);
            }
            let g = v
                .as_str()
                .ok_or_else(|| UpstreamApiError::bad("group 必须是字符串"))?;
            Ok(json!(g))
        }
        other => Err(UpstreamApiError::bad(format!(
            "非法字段: {other} (允许: {})",
            whitelist_sorted()
        ))),
    }
}

/// 白名单字典序拼串（对齐 api.py:2884 `",".join(sorted(_UPSTREAM_WHITELIST))`）。
fn whitelist_sorted() -> String {
    let mut w: Vec<&str> = UPSTREAM_WHITELIST.to_vec();
    w.sort_unstable();
    w.join(",")
}

/// PUT /api/upstreams/{id} 的实现体（对齐 api.py:2804-2997 的更新分支）。
///
/// 先**全量校验**（未知键/`id` 字段/取值范围）再统一写回，避免「边写边校」在第 N 个
/// 字段非法时把前 N-1 个字段留在内存却未落盘（api.py:2876-2878）。
async fn upstream_update_apply(
    s: &AppState,
    up_id: &str,
    body: Value,
) -> Result<Value, UpstreamApiError> {
    let obj = body
        .as_object()
        .ok_or_else(|| UpstreamApiError::bad("upstream update must be an object"))?;
    let prev = s.cfg.read().clone();
    let mut list = cfg_upstreams(&prev);
    let idx = list
        .iter()
        .position(|u| u.get("id").and_then(Value::as_str) == Some(up_id))
        .ok_or(UpstreamApiError::NotFound)?;
    let mut updates: Map<String, Value> = Map::new();
    for (k, v) in obj {
        if k == "id" {
            return Err(UpstreamApiError::bad("不允许修改上游 id"));
        }
        if !UPSTREAM_WHITELIST.contains(&k.as_str()) {
            return Err(UpstreamApiError::bad(format!(
                "非法字段: {k} (允许: {})",
                whitelist_sorted()
            )));
        }
        updates.insert(k.clone(), normalize_upstream_field(k, v)?);
    }
    let mut new_up = list[idx].clone();
    {
        let o = new_up
            .as_object_mut()
            .ok_or_else(|| UpstreamApiError::bad("upstream must be an object"))?;
        for (k, v) in updates {
            o.insert(k, v);
        }
    }
    list[idx] = new_up.clone();
    let mut next = prev.clone();
    set_cfg_upstreams(&mut next, list);
    commit_upstreams(s, &prev, &next).await?;
    Ok(json!({"ok": true, "upstream": new_up}))
}

/// DELETE /api/upstreams/{id} 的实现体（对齐 api.py:2823-2869 的删除分支）。
///
/// **[历史归因]** 运行态回收（`HealthKeeper`）**推迟到落盘成功之后**，与 Python 的
/// 「先判 saved is False 返回 500，确认删除落盘后再回收」一致。
async fn upstream_delete_apply(s: &AppState, up_id: &str) -> Result<Value, UpstreamApiError> {
    let prev = s.cfg.read().clone();
    let mut list = cfg_upstreams(&prev);
    let idx = list
        .iter()
        .position(|u| u.get("id").and_then(Value::as_str) == Some(up_id))
        .ok_or(UpstreamApiError::NotFound)?;
    list.remove(idx);
    let mut next = prev.clone();
    set_cfg_upstreams(&mut next, list);
    commit_upstreams(s, &prev, &next).await?;
    if let Some(rt) = s.resolver.upstream_runtime() {
        rt.health.discard(up_id);
    }
    Ok(json!({"ok": true}))
}

/// POST /api/upstreams。
async fn upstreams_create(State(s): State<AppState>, Json(body): Json<Value>) -> Response {
    match upstream_add(&s, body).await {
        Ok(v) => {
            // 新增测速（对齐 api.py:2706-2716）：写盘成功后后台实测该上游并写回 latency；
            // 无 tokio 运行时不 spawn（不 panic）。
            let enabled = v
                .get("upstream")
                .and_then(|u| u.get("enabled"))
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let new_id = v
                .get("upstream")
                .and_then(|u| u.get("id"))
                .and_then(Value::as_str)
                .map(|s| s.to_string());
            if enabled {
                if let (Some(id), Ok(handle)) = (new_id, tokio::runtime::Handle::try_current()) {
                    let st = s.clone();
                    handle.spawn(async move {
                        if let Err(e) = reprobe_impl(&st, Some(&id)).await {
                            tracing::warn!("新增上游后台实测失败: {e}");
                        }
                    });
                }
            }
            json_ok(v)
        }
        Err(e) => e.into_response(),
    }
}

/// PUT /api/upstreams/{id}。
async fn upstream_update(State(s): State<AppState>, uri: Uri, Json(body): Json<Value>) -> Response {
    let id = uri.path().trim_start_matches("/api/upstreams/").to_string();
    match upstream_update_apply(&s, &id, body).await {
        Ok(v) => json_ok(v),
        Err(e) => e.into_response(),
    }
}

/// DELETE /api/upstreams/{id}。
async fn upstream_delete(State(s): State<AppState>, uri: Uri) -> Response {
    let id = uri.path().trim_start_matches("/api/upstreams/").to_string();
    match upstream_delete_apply(&s, &id).await {
        Ok(v) => json_ok(v),
        Err(e) => e.into_response(),
    }
}

/// **用户态缓存直答计数**（`counters.cache_direct`）的唯一来源。
///
/// 2.1.29 起 eBPF/XDP 内核态缓存整体移除后，本投影就是 `cache_direct ≡ hit`
/// 的**同一行代码**：`/api/status`、`/api/snapshot` 与 `/metrics` 三处都只允许
/// 调用本函数，避免同一次抓取出现互相矛盾的数字。
fn cache_direct_projection(hit: u64) -> u64 {
    hit
}

/// GET /api/status。
///
/// **2.1.17（修复项 4）：快照时序可对齐（`snapshot_*` 三键）。**
///
/// 为什么必须新增：2.1.16 首轮压测出现
/// `服务端构造 − 客户端接收 = 3951`、`客户端超时 2896`、**余 1055（0.5%）** 未闭环。
/// 根因是**两侧窗口没有共同的时间基准** —— 压测脚本只能比较"客户端从 T0 到 T1
/// 收到了多少条"与"服务端此刻的累计值"，而 T1 之后（快照之前）服务端仍在把
/// 已经超时的应答构造并发出，这部分既不在客户端的成功计数里，也不在客户端的
/// 超时计数里（客户端已经收摊）。现在服务端把**取数时刻**显式回传：
///
/// | 键 | 含义 | 用途 |
/// |---|---|---|
/// **[历史归因]** | `snapshot_monotonic_ms` | 进程启动以来的**单调**毫秒（不受 NTP/时区影响） | 与脚本自己的单调时钟（如 Python `time.monotonic()`）算 delta —— **推荐口径** |
/// | `snapshot_epoch_ms` | 同一时刻的 **Unix 墙钟毫秒** | 与日志时间戳/抓包时间对齐 |
/// | `snapshot_uptime_s` | 同一时刻的 `uptime_s`（与上面两者同点取值） | 交叉校验（`epoch - boot` 的整秒视图） |
///
/// **2.1.18（修复项 2）：`snapshot_seq`（同代计数器快照的代数）。**
///
/// 2.1.17 交付报告 **E5**：高 QPS 下同一个响应里 `Σ counters.client_rcode` 与
/// `counters.total` 偶尔差 1 —— 因为那时 `counters` 是**逐字段独立原子读**，
/// 整张表不构成快照。现在：
/// - `counters` 由**一次** `ServerTelemetry::snapshot()` 派生（同代）；
/// - 本次取数的代数以 `snapshot_seq` 回传（**单调递增**）；
/// - 于是"`Σ client_rcode == total`"、"`client_rcode[\"2\"] == servfail_total`"、
///   "`servfail_total == Σ servfail_reasons`"三条硬等式**在同一次响应内恒成立**；
/// - **跨快照允许变化**：脚本先比 `snapshot_seq`，不同即说明两次之间发生过写入
///   （或 `/api/reset`），此时**不得**做跨快照的逐字段差分 —— 这是可判定的证据，
///   不再靠"客户端超时"之类的外部因素解释。
///
/// **如何与客户端压测窗口对齐（务必照此做）**：
/// 1. 脚本在压测前记 `c0 = time.monotonic()`，压测结束立刻记 `c1 = time.monotonic()`；
/// 2. 立刻读一次 `/api/status` 拿 `s = snapshot_monotonic_ms`；
/// 3. 对齐窗口 = `[c0, c1]` **∪** 服务端快照时刻 `s`：
///    `服务端窗口内构造数 = counters.client_rcode 在 s 处的累计 − 在 c0 处读到的累计`
///    （两端各读一次 `/api/status`，两端都带 `snapshot_monotonic_ms`）；
/// 4. 判定：`Δ服务端构造 − Δ客户端接收 ≤ Δ客户端超时` **必须恒成立**。
///    2.1.16 的余量 1055 就是"客户端在 c1 已经停手、服务端在 (c1, s] 之间把
///    3 秒超时的应答构造完并发出"的那一段 —— 用 `[c0, c1]` 与 `s` 三点对齐后，
///    这一段会被**显式计入**，余量随之闭合到 0（对账脚本
///    `scripts/f216-counters-reconcile.py` 的 R8 已实现该判据）。
// **2.1.18（修复项 2）**：把一份**同代**计数器快照渲染成 `/api/status.counters`
// / `/api/snapshot.counters` 的完整 JSON 表（含全部动态/投影键）。
//
// 为什么把组装从 `status()` 里抽出来：`snapshot_seq` 必须与**这张表**严格同一代。
// 组装是一个纯函数（只读快照 + 现场读上游/解析器计数），因此
// `tel.with_snapshot(|s| counters_map_from(s, &s2))` 一次调用就能同时拿到
// "表"与"代数"，两者**不可能**错位（改前是两次独立取数，代数会比表新 1）。
fn counters_map_from(
    snap: &crate::telemetry::CounterSnapshot,
    s: &AppState,
) -> serde_json::Map<String, Value> {
    let mut counters = serde_json::Map::new();
    // ---- 同代标量（15 键，顺序与 COUNTER_KEYS 一致）----
    counters.insert("total".into(), json!(snap.total));
    counters.insert("hit".into(), json!(snap.hit));
    counters.insert("miss".into(), json!(snap.miss));
    counters.insert("upstream_queries".into(), json!(snap.upstream_queries));
    counters.insert("errors".into(), json!(snap.errors));
    counters.insert("ipv4_fallback".into(), json!(snap.ipv4_fallback));
    counters.insert("stale_served".into(), json!(snap.stale_served));
    counters.insert("bytes_in".into(), json!(snap.bytes_in));
    counters.insert("bytes_out".into(), json!(snap.bytes_out));
    counters.insert("rebind_blocked".into(), json!(snap.rebind_blocked));
    counters.insert("udp_dropped".into(), json!(snap.udp_dropped));
    counters.insert("servfail_total".into(), json!(snap.servfail_total));
    counters.insert("negative_hits".into(), json!(snap.negative_hits));
    counters.insert(
        "cache_skipped_private_total".into(),
        json!(snap.cache_skipped_private_total),
    );
    // **2.1.18（修复项 9）**：出口登记但**没有可发送报文**的次数（`total` 的差额项）。
    // 恒等式：`total == Σ client_rcode`（同分支自增）；
    // `#(出口登记) == total + no_response_total`。
    counters.insert("no_response_total".into(), json!(snap.no_response_total));
    // **2.1.20（A-04）**：控制面独立计数（`hit`/`miss`/`total` 只统计数据面）。
    counters.insert("control_queries".into(), json!(snap.control_queries));
    counters.insert("control_hits".into(), json!(snap.control_hits));
    // **2.1.29**：未知 qtype 透传（成功 + 失败；不缓存；与 `/metrics` 同源同值）。
    counters.insert(
        "passthrough_qtype_total".into(),
        json!(snap.passthrough_qtype_total),
    );
    // **2.1.40**：本地策略短路（AAAA 屏蔽 / IPv6 关闭）—— 这类应答没查缓存、没发上游，
    // **不计 hit/miss**，单独可观测。`hit_rate` 的分母（hit+miss）因此只含真正的
    // 缓存/上游决策；`total`（= Σ client_rcode）仍包含它们。
    counters.insert(
        "policy_filtered_total".into(),
        json!(snap.policy_filtered_total),
    );
    // >>> 242B BEGIN P1-6-counters >>> //
    counters.insert("rule".into(), json!(snap.rule));
    // <<< 242B END P1-6-counters <<< //
    // **2.1.43-A（P2：prefer_ipv4 探针真的发了上游却记 0）**：`prefer_ipv4=true`
    // 且 AAAA 但 A 不在缓存时，`resolve.rs::probe_a_record` 会**真的**打一个上游
    // A 查询；2.1.42 及以前它对任何计数器都不可见（`upstream_queries` 只统计
    // "数据面客户端查询"，探针不是客户端查询）。现在**只追加**本键，与
    // `upstream_queries` 并列且互不重叠（探针量单独可观测，既有口径不变）。
    // 写点唯一 = `resolve.rs::probe_a_record`。
    counters.insert(
        "probe_upstream_queries".into(),
        json!(snap.probe_upstream_queries),
    );
    // ---- 同代结构化分布（与上面 16 个标量来自**同一次**读取）----
    {
        let mut o = serde_json::Map::new();
        for (i, k) in crate::telemetry::SERVFAIL_REASONS.iter().enumerate() {
            o.insert((*k).to_string(), json!(snap.servfail_reasons[i]));
        }
        counters.insert("servfail_reasons".into(), Value::Object(o));
    }
    {
        let mut o = serde_json::Map::new();
        for (i, n) in snap.client_rcode.iter().enumerate() {
            o.insert(i.to_string(), json!(n));
        }
        counters.insert("client_rcode".into(), Value::Object(o));
    }
    // ---- 用户态缓存直答投影（`cache_direct ≡ hit`，三端点同源）----
    counters.insert(
        "cache_direct".into(),
        json!(cache_direct_projection(snap.hit)),
    );
    // ---- 2.1.8 只读计数（不改既有键语义，纯新增）----
    // - breaker_all_open：优化项 6 —— 「全部上游熔断打开 → 兜底放行」累计次数；
    // - upstream_requests：优化项 1/3 —— **物理**上游请求数（`upstream_queries` 是
    //   逻辑口径：每个真正发过上游的客户端查询 +1），自适应并发/首答即返后它会明显下降；
    // - upstream_early_return / upstream_hedge：首答即返次数 / 对冲追加次数。
    counters.insert(
        "breaker_all_open".into(),
        json!(s.resolver.cb_all_open_count()),
    );
    // **2.1.19（修复项 5-⑨）**：把"预取时全部上游熔断打开"从**周期性 WARN**收敛为
    // **状态字段**（报告 ⑫(9)）：`prefetch_all_open` = 当前是否处于该状态（布尔，瞬时值），
    // `prefetch_degraded_total` = 累计**进入**该状态的次数（只增）。
    // 语义与 `/metrics` 的 `ebpdns_prefetch_all_open` 同源（同一对原子）。
    counters.insert(
        "prefetch_all_open".into(),
        json!(s.resolver.prefetch_all_open()),
    );
    counters.insert(
        "prefetch_degraded_total".into(),
        json!(s.resolver.prefetch_degraded_total()),
    );
    counters.insert(
        "upstream_requests".into(),
        json!(s.resolver.upstream_requests()),
    );
    counters.insert(
        "upstream_early_return".into(),
        json!(s.resolver.upstream_early_returns()),
    );
    counters.insert("upstream_hedge".into(), json!(s.resolver.upstream_hedges()));
    // P0 取舍的补偿控制（2.1.9 解析器侧）：**仅有 1 张有效负票即被采纳**的累计次数。
    // 语义背景：负结论只在"成功应答"之间表决，`rcode=None`（超时/no-answer）与
    // SERVFAIL/REFUSED 一律弃权；因此生产上"只有一台上游能判负"时单票即成立
    // （可用性优先，牺牲对单台上游 NXDOMAIN 投毒的防护）。该计数用于量化暴露面：
    // 持续增长且信任集含开放解析器 → 把 `nxdomain_quorum` 调回 2。
    counters.insert(
        "negative_single_vote_accepted".into(),
        json!(s.resolver.negative_single_vote_accepted()),
    );
    // **2.1.45（P1-3/P1-4）**：规则代已变化而被丢弃的缓存写回次数。负缓存
    // （`put_negative`）与正缓存（`fill_cache_capped`）**共用同一个门禁与同一个
    // 计数**，因此两条路径口径一致、可直接对账。
    counters.insert(
        "stale_gen_dropped".into(),
        json!(s.resolver.stale_gen_dropped()),
    );
    // A7（2.1.9）可观测性：
    // - upstream_dispatch：**派发**的上游配置数（`UpstreamRuntime::query` 调用次数）；
    // - upstream_wire_requests：**真实线速**请求数（多 IP 并行 / TC→TCP 回退 /
    //   连接复用与重试各计 1）。二者之差就是 fan-out + 回退 + 重试的放大倍数；
    //   分母不再是 `upstream_queries`（那是**逻辑**口径："有几次客户端查询发过上游"，
    //   首答即返/自适应并发下必然 != 真实线速，会把物理 amp 算歪）。
    // 旧键 `upstream_requests` 仍保留（前端契约不变）。
    let (wire_requests, upstream_dispatch) = match s.resolver.upstream_runtime() {
        Some(rt) => (rt.wire_requests(), rt.dispatch_count()),
        None => (0, 0),
    };
    counters.insert("upstream_wire_requests".into(), json!(wire_requests));
    counters.insert("upstream_dispatch".into(), json!(upstream_dispatch));
    // **2.1.12（A 的优化项 ①）RFC 8020 父域 NXDOMAIN 推断的独立可观测口径**。
    // 三个键**只增不改**（既有键语义/类型一律不动）：
    // - `rfc8020_hits`：由「被查询名自身或某个祖先已在 NXDOMAIN 登记集合里」直接判负、
    //   **完全未发上游**的应答次数（与通用 `hit`/`cache_direct` 分开，便于把 ① 的
    //   收益从普通缓存命中里分离出来）；
    // - `rfc8020_registrations`：有效登记（新增或更新）次数，同一名字重复登记不重复计；
    // - `rfc8020_len`：当前登记表条数（瞬时值，非累计）。
    counters.insert("rfc8020_hits".into(), json!(s.resolver.rfc8020_hits()));
    counters.insert(
        "rfc8020_registrations".into(),
        json!(s.resolver.rfc8020_registrations()),
    );
    counters.insert("rfc8020_len".into(), json!(s.resolver.rfc8020_len()));
    // **2.1.17（修复项 7）**：单上游在途闸门的"排队把预算吃光 ⇒ 主动放弃"计数。
    //
    // 为什么不放进 `ServerTelemetry::COUNTER_KEYS`：它的写点在 `upstream/runtime.rs`
    // 的 `InflightLimiter`（不在遥测里），且**与 `rejected` 是两个不同的失败原因**：
    //   - `rejected`：等待许可超时（**从未拿到**许可）→ 调 `upstream_max_inflight` / governor；
    //   - 本键：**拿到了**许可，但剩余预算已不足一次协议往返 → 说明排队已深到不健康。
    // 两者混在一起就无法归因，因此单列。见 `ebpdns-upstream::runtime::MIN_POST_QUEUE_BUDGET_MS`。
    let inflight_gave_up = match s.resolver.upstream_runtime() {
        Some(rt) => rt.inflight.queued_gave_up(),
        None => 0,
    };
    counters.insert(
        "upstream_inflight_queued_gave_up".into(),
        json!(inflight_gave_up),
    );
    counters
}

/// **2.1.19（修复项 3 / R9）**：缓存**落盘现场**的**唯一**构造实现。
///
/// 字段（=`/api/cache/stats.persist` 与 `/api/status.cache.persist` 的**同一份**）：
/// ```json
/// {"enabled":true,"interval_s":60,"file":"/var/lib/ebpdns/ebpdns-cache.json",
///  "exists":true,"bytes":24134,"mtime_s":1760500000,"age_s":37,
///  "entries":61,"note":""}
/// ```
/// * `enabled`    = 配置 `cache_persist`（总开关；false ⇒ 不写盘也不恢复）
/// * `interval_s` = 配置 `cache_save_interval`（0 = 只在优雅退出时落盘）
/// * `file` = 配置 `cache_file`（**不是**硬编码路径 —— 2.1.17 的"三种字符串"缺陷
///   就是文档/代码/运行态各自写死路径导致的）
/// * `exists`/`bytes`/`mtime_s`/`age_s` = 文件现场（`exists=false` 时全为 0）
/// * `entries` = 内存中的条目数（= `summary().used`，供"条目数"展示；**不是**
///   文件里的条目数 —— 文件里的条数只有落盘那一刻才知道，这两个值在
///   "刚写入/刚清空"时会不同，UI 必须区分口径）
/// * `age_s` 只增不减 ⇒ **未周期落盘**（用户可据此自证"每 60 秒保存"到底有没有生效）
///
/// 为什么抽成函数：`/api/cache/stats` 与 `/api/status` 都要下发同一份现场，
/// 两处各写一遍必然漂移（2.1.19 只有 `/api/cache/stats` 有，配置页读的是
/// `/api/status`，于是 R9「配置页显示最近落盘时间」无法实现）。
fn cache_persist_info(cfg: &Value, mem_entries: u64, stats: &ebpdns_cache::PersistStats) -> Value {
    #[cfg(test)]
    status_fs_io_hook();
    let persist_enabled = cfg
        .get("cache_persist")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let interval_s = cfg
        .get("cache_save_interval")
        .and_then(Value::as_u64)
        .unwrap_or(60);
    let file_path = cfg
        .get("cache_file")
        .and_then(Value::as_str)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("./ebpdns-cache.json"));
    let mut out = json!({
        "enabled": persist_enabled,
        "interval_s": interval_s,
        "file": file_path.display().to_string(),
        "exists": false,
        "bytes": 0,
        "mtime_s": 0,
        "age_s": 0,
        "entries": mem_entries,
        // 空态/异常态的**可读原因**（前端直接显示，不必自己拼文案）。
        "note": if !persist_enabled {
            "未开启持久化（cache_persist=false）：不写盘也不从磁盘恢复，重启即清零"
        } else {
            "尚未落盘（cache_persist=true 但缓存文件不存在）"
        },
    });
    if let Ok(md) = std::fs::metadata(&file_path) {
        let mtime = md
            .modified()
            .ok()
            .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let now = crate::telemetry::now_epoch() as u64;
        let age_s = now.saturating_sub(mtime);
        out = json!({
            "enabled": persist_enabled,
            "interval_s": interval_s,
            "file": file_path.display().to_string(),
            "exists": true,
            "bytes": md.len(),
            "mtime_s": mtime,
            "age_s": age_s,
            "entries": mem_entries,
            // 周期落盘是否"看起来停了"：`age_s` 超出 2×interval（且 interval>0）
            // 说明**至少漏了一个周期** —— 但优雅退出/无流量时不算异常，故只是提示。
            "note": if !persist_enabled {
                "未开启持久化（cache_persist=false）：该文件是上一次开启时留下的，重启不会恢复它"
            } else if interval_s == 0 {
                "周期落盘已关闭（cache_save_interval=0）：只在优雅退出时写盘"
            } else if age_s > interval_s.saturating_mul(2) {
                "**超过 2 个落盘周期未见更新**：可能当前无流量、或落盘失败（查 ERROR 日志）"
            } else {
                ""
            },
        });
    }
    // ---- **2.1.29（缓存持久化 v2）**：只**覆盖**取值来源，不新增/不改旧键含义 ----
    //
    // 取数规则（§10.1）：
    // * v2 且 manifest 有效 ⇒ `bytes` = `snap_bytes`（**当前快照的字节数**，不含 WAL）；
    //   `mtime_s` = 最近一次成功落盘（manifest 刷新）时刻；
    // * v1 / 未迁移 / manifest 损坏 ⇒ **逐字沿用**上面的 stat 逻辑（2.1.28 行为不变）。
    let fmt = stats.format();
    if fmt == ebpdns_cache::persist::Format::V2 && stats.manifest_valid() {
        let exists = std::fs::metadata(&file_path).is_ok();
        // **2.1.34（D3）**：`mtime_s` 取 manifest 的 `committed_ms`（恢复时已从 manifest
        // 装载，见 `recover.rs`）；极端情况（旧现场 committed_ms=0）再退回**文件 mtime**，
        // 绝不返回 0 —— 旧实现的 `mtime_s=0 / age_s=epoch` 会把正常恢复显示成“落盘失败”。
        let mtime = if stats.last_commit_ms() > 0 {
            (stats.last_commit_ms() / 1000) as u64
        } else {
            std::fs::metadata(&file_path)
                .ok()
                .and_then(|md| md.modified().ok())
                .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0)
        };
        let now = crate::telemetry::now_epoch() as u64;
        let age_s = now.saturating_sub(mtime);
        let note = match stats.restore_source() {
            ebpdns_cache::RestoreSource::Corrupt => {
                "缓存现场损坏：已保留现场并**禁用 v2 写**（查 ERROR 日志；确认后删除 `*.corrupt.*` 再重启）"
            }
            ebpdns_cache::RestoreSource::Unsupported => {
                "不支持的缓存格式版本：已**禁用 v2 写**；请回退二进制，或删除 v2 文件后重启"
            }
            _ if !persist_enabled => {
                "未开启持久化（cache_persist=false）：不写盘也不从磁盘恢复，重启即清零"
            }
            _ if interval_s == 0 => {
                "周期落盘已关闭（cache_save_interval=0）：只在优雅退出时写快照"
            }
            _ if age_s > interval_s.saturating_mul(2) => {
                "**超过 2 个落盘周期未见更新**：可能当前无流量、或落盘失败（查 ERROR 日志）"
            }
            _ => "",
        };
        if let Value::Object(ref mut m) = out {
            m.insert("exists".into(), json!(exists));
            m.insert("bytes".into(), json!(stats.snap_bytes()));
            m.insert("mtime_s".into(), json!(mtime));
            m.insert("age_s".into(), json!(age_s));
            m.insert("note".into(), json!(note));
        }
    }
    // ---- 追加键（只增不改；两个端点必须都出现且相等）----
    if let Value::Object(ref mut m) = out {
        m.insert("format".into(), json!(fmt.as_str()));
        m.insert("snap_seq".into(), json!(stats.snap_seq()));
        m.insert("wal_bytes".into(), json!(stats.wal_bytes()));
        // **2.1.29 / 长稳审计 P3**：未过期条目数。`entries`（= `used`）含"过期但尚未
        // 惰性清理"的条目，不能用来算恢复丢失率。两个键都保留，语义各自独立。
        m.insert("used_live".into(), json!(stats.used_live()));
        m.insert(
            "restore_source".into(),
            json!(stats.restore_source().as_str()),
        );
        // **2.1.34（D4，只追加）**：当前快照的年龄（秒）。
        //
        // “重启后命中率快速恢复”依赖**快照年龄与 TTL 的关系**：快照越老，恢复时
        // 被丢弃的过期条目越多（`cache_save_interval` 只管 WAL/manifest，不等于快照
        // 重写）；运维可用 `snapshot_age_s > TTL/2` 预判。无法取到时间 ⇒ 0。
        let snap_ms = stats.snap_ms();
        let now_secs = crate::telemetry::now_epoch() as u64;
        let snapshot_age_s = if snap_ms > 0 {
            now_secs.saturating_sub((snap_ms / 1000) as u64)
        } else {
            0
        };
        m.insert("snapshot_age_s".into(), json!(snapshot_age_s));
    }
    out
}

/// **2.1.43-B（P2-4）**：`restore_drops.note` 的**唯一**文案。
///
/// 两个端点（`/api/status.cache.restore_drops` 与 `/api/cache/stats.restore_drops`）
/// 必须**逐字节相同**（单测 `status_and_cache_stats_expose_identical_persist_block` 钉死）。
/// 2.1.42 是两段各自手写的字符串；2.1.43-B 增加 `window_unpersisted` 时只改了其中一段
/// ⇒ 端点不一致（单测**实测红**，api.rs 里可见）。现在只允许从这里取，结构上不可能再漂。
const RESTORE_DROPS_NOTE: &str = "最近一次启动恢复（restore）的计数：legacy=旧格式（缺绝对 expires_at，只有 remaining）按安全侧丢弃；expired=文件里的绝对到期时间已过；failed=不可用记录数（反序列化失败 / 结构不完整 / 分组阶段跳过；整个文件不可解析时至少为 1）；window_unpersisted=快照里写了、但恢复只灌 main 段 ⇒ 被挤出的条数（仅 tinylfu 非 0，≈ window 段容量，出厂 1%；lru/partitioned 恒 0）。该值**只反映本次启动**，不是上一次的残留。";

#[cfg(test)]
static STATUS_FS_DELAY_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(test)]
static STATUS_FS_ENTERED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// **仅测试**：在 `/api/status` 的 fs IO 段放慢并置位，用于证明 cfg 读锁已释放。
#[cfg(test)]
fn status_fs_io_hook() {
    use std::sync::atomic::Ordering;
    STATUS_FS_ENTERED.store(true, Ordering::SeqCst);
    let ms = STATUS_FS_DELAY_MS.load(Ordering::SeqCst);
    if ms > 0 {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
    STATUS_FS_ENTERED.store(false, Ordering::SeqCst);
}

/// `GET /api/status`：进程/计数器/缓存/上游的**单一快照**（同一代 `snapshot_seq`）。
async fn status(State(s): State<AppState>) -> Response {
    let tel = &s.telemetry;
    // **2.1.17（修复项 4）**：取数时刻三元组必须在**任何计数读取之前**取，
    // 且只取一次 —— 下面所有 `counters` 都从这一次快照派生。
    let snapshot_monotonic_ms = tel.monotonic_ms();
    let snapshot_epoch_ms = (now_epoch() * 1000.0).round() as u64;
    let snapshot_uptime_s = tel.uptime_s();
    // **2.1.43-A（P2：`/api/status` 持 cfg 读锁做 fs IO）**：这里只把**标量**配置项
    // 拷进一份小快照，读锁在块结束时**立即释放** —— 下面的 `cache_persist_info`
    // （`std::fs::metadata`，见本文件 `cache_persist_info`）与
    // `api_state::state_persist_json`（`StateStore::read_commit` +
    // `read_dir("history")`，`state_store.rs` 的 `history_generations`）因此
    // **全部在锁外**执行。
    //
    // 缺陷（2.1.42）：`let cfg = s.cfg.read();` 的生命周期一直延伸到函数末尾，
    // 于是 1 s 轮询的 `/api/status` 在**每一次**请求里都持着 cfg 读锁去 stat 缓存
    // 文件、扫 `state/history`。并发 200 时写者排队，`PUT /api/config` 的 P99
    // 被拖到 fs IO 的尾部（配置页"保存转圈"）。
    //
    // **返回值语义逐字不变**：6 个键的取值与缺省和改前完全相同
    // （`cache_persist_info` 仍按同名键 + 同缺省解析；`cfg.get(..)` 只是从
    // `&Value` 读变成从快照读）。单测 `status_cfg_echo_matches_live_config`
    // 钉死回显一致。
    let cfg = {
        let cfg = s.cfg.read();
        json!({
            "cache_persist": cfg.get("cache_persist").cloned().unwrap_or(json!(true)),
            "cache_save_interval": cfg
                .get("cache_save_interval")
                .cloned()
                .unwrap_or(json!(60)),
            "cache_file": cfg.get("cache_file").cloned().unwrap_or(Value::Null),
            "cache_policy": cfg.get("cache_policy").cloned().unwrap_or(json!("lru")),
            "health_check_interval": cfg
                .get("health_check_interval")
                .cloned()
                .unwrap_or(json!(30)),
            "rule_sub_interval": cfg
                .get("rule_sub_interval")
                .cloned()
                .unwrap_or(json!(3600)),
        })
    };
    let mut cache_summary = s.resolver.cache().summary();
    // **2.1.19（修复项 3 / R9 + 修复项 1）**：`/api/status.cache` 追加两个子树 ——
    //   ① `persist`：落盘现场（与 `/api/cache/stats.persist` **同一份实现**）。
    //      配置页读的是 `/api/status`（**2.1.18** 只有 `/api/cache/stats` 有落盘现场），
    //      因此 R9「配置页显示最近一次落盘时间/条目数/路径」在 2.1.18 无法实现。
    //   ② `restore_drops`：最近一次 `restore` 的丢弃计数（`DnsCache::last_restore_drops`）
    //      —— 把 2.1.18 只存在于日志/内部的 legacy 计数**变成可断言的状态字段**，
    //      三条策略（lru / partitioned / tinylfu）与热切换外壳都实现该 trait 方法。
    {
        let mem_entries = cache_summary
            .get("used")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let persist = cache_persist_info(
            &cfg,
            mem_entries,
            &s.resolver
                .cache()
                .persist_stats()
                .unwrap_or_else(|| std::sync::Arc::new(ebpdns_cache::PersistStats::default())),
        );
        let (d_expired, d_legacy, d_failed) = s.resolver.cache().last_restore_drops();
        // **2.1.43-B（P2-4）**：window 段不参与恢复的条数（TinyLFU 特有；另两条策略恒 0）。
        let d_window = s.resolver.cache().last_restore_window_unpersisted();
        if let Value::Object(ref mut m) = cache_summary {
            m.insert("persist".into(), persist);
            m.insert(
                "restore_drops".into(),
                json!({
                    "expired": d_expired,
                    "legacy": d_legacy,
                    "failed": d_failed,
                    "window_unpersisted": d_window,
                    // 语义说明随字段一起下发，避免"到底是丢弃还是解析失败"再次被误读。
                    // **2.1.19（修复项 1 补漏）**：`failed` 的口径已明确为
                    // 「不可用记录数」= 反序列化失败 + 结构不完整（key 非数组 / 长度非 2|3 /
                    // domain·qtype 取不出 / 缺 answers·rcode）+ 分组阶段跳过；
                    // **整个文件不可解析**时至少为 1（单位 = 整个文件）。
                    "note": RESTORE_DROPS_NOTE,
                }),
            );
        }
    }
    let config_path: Option<String> = s.cfg_path.as_ref().map(|p| p.display().to_string());
    // **2.1.49（AUD-09）**：把 `/metrics` 已有的进程自观测同时下发到 `/api/status`，
    // 控制台无需再抓 Prometheus 文本即可显示 RSS / threads / open_fds。
    // 口径与 metrics 完全同源（同一个 `process_health()`），不另起第二套 /proc 解析。
    let (proc_rss, proc_vm, proc_threads, proc_fds) = process_health();
    let proc_missing_parts = s
        .state
        .store()
        .map(|st| st.missing_parts().len() as u64)
        .unwrap_or(0);
    // top-N 上游（**2.1.25 性能项**）：只直算 `[id, queries]`，不再为它造 N 个完整逐上游视图。
    // 口径与 `/api/snapshot.top_upstreams` 共用 `top_upstreams_ranked` ⇒ 输出不可能分叉。
    let top_up = top_upstreams_direct(&s);
    // **2.1.18（修复项 2）**：整张 counters 表 + 代数序号从**同一次**取快照派生 ——
    // `with_snapshot` 借出**一代**，闭包里既渲染表又取 `seq`，两者不可能错位。
    // 因此"`Σ client_rcode == total`"等三条硬等式在同一次响应内恒成立；
    // 跨快照的差异由 `snapshot_seq` 显式暴露（脚本先比 seq 再对账）。
    // **2.1.46（REV247 A-11）**：顶层 `hit_rate` 与 `counters` 必须同代。
    let (counters, snapshot_seq, counters_monotonic_ms, hit_rate) = tel.with_snapshot(|snap| {
        (
            counters_map_from(snap, &s),
            snap.seq,
            snap.monotonic_ms,
            crate::telemetry::ServerTelemetry::hit_rate_pct_of(snap),
        )
    });
    // `cache_direct` 投影与 2.1.8/A7/RFC8020/在途闸门等动态键
    // 已由 `counters_map_from` 在**同一代快照**里一并渲染（见该函数文档）；
    // 此处**不得**再插入/覆盖任何计数键 —— 否则它们会脱离同代保证。
    // v1.9.162 兼容段：控制台顶栏/遥测页按原契约读取（map/counters/rule_hits/...）。
    let map = json!({
        "used": cache_summary.get("used").cloned().unwrap_or(json!(0)),
        "capacity": cache_summary.get("capacity").cloned().unwrap_or(json!(0)),
        "pct": cache_summary.get("pct").cloned().unwrap_or(json!(0.0)),
    });
    json_ok(json!({
        "app": "ebpdns",
        "status": "running", "running": true,
        "version": VERSION, "uptime_s": tel.uptime_s(),
        "config_path": config_path,
        "total": counters.get("total").cloned().unwrap_or(json!(0)),
        "hit": counters.get("hit").cloned().unwrap_or(json!(0)),
        "miss": counters.get("miss").cloned().unwrap_or(json!(0)),
        "errors": counters.get("errors").cloned().unwrap_or(json!(0)),
        "hit_rate": hit_rate, "qps": tel.qps(),
        "cache": cache_summary,
        "process": {
            "resident_memory_bytes": proc_rss,
            "virtual_memory_bytes": proc_vm,
            "threads": proc_threads,
            "open_fds": proc_fds,
            "state_missing_parts": proc_missing_parts,
        },
        "endpoints": s.endpoints.read().clone(),
        "rules_gen": s.resolver.rule_gen(),
        "uptime": tel.uptime_s(),
        "top_domains": tel.top_domains(),
        "top_clients": tel.top_clients(),
        // ---- v1.9.162 兼容键 ----
        // 无延迟样本时下发 null（页面对 None 显示 “–”，对齐 api.py 的 `if _avg_lat is not None`）。
        "avg_latency_ms": tel.avg_latency_opt(),
        "map": map,
        "counters": counters,
        "rule_hits": tel.rule_hits(),
        "cache_policy": cfg.get("cache_policy").cloned().unwrap_or(json!("lru")),
        "cache_file": cfg.get("cache_file").cloned().unwrap_or(Value::Null),
        "udp_dropped": s.udp_dropped.load(std::sync::atomic::Ordering::Relaxed),
        "top_upstreams": top_up,
        // 页面/前端契约里直接读取的配置透传（v1.9.162 亦如此）。
        "health_check_interval": cfg.get("health_check_interval").cloned().unwrap_or(json!(30)),
        "rule_sub_interval": cfg.get("rule_sub_interval").cloned().unwrap_or(json!(3600)),
        // ---- **2.1.17（修复项 4）：快照时序（与上面 counters 同一取数点）** ----
        // 三个键同点取值，供压测脚本把"服务端窗口"与"客户端窗口"对齐；
        // 对齐方法与判据见本函数文档（含 1055/0.5% 余量的解释）。
        "snapshot_monotonic_ms": snapshot_monotonic_ms,
        "snapshot_epoch_ms": snapshot_epoch_ms,
        "snapshot_uptime_s": snapshot_uptime_s,
        // ---- **2.1.18（修复项 2）：同代计数器快照的代数序号（E5 的闭环判据）** ----
        // 与上面 `counters` **严格同一代**（同一个 `with_snapshot` 闭包内取出）。
        // 脚本用法：跨两次抓取做逐字段差分前，**先比 `snapshot_seq`**；
        // 不同即说明两次之间发生过写入（或 `/api/reset`），此时不得做逐字段差分。
        "snapshot_seq": snapshot_seq,
        // 计数器表本身的取数时刻（`counters` 与 `snapshot_seq` 都属于这一代）；
        // 与上面的 `snapshot_monotonic_ms` 相差仅"进入函数到取快照"的微秒级间隔。
        "counters_monotonic_ms": counters_monotonic_ms,
        // ---- **2.1.19（F-04/F-07）：整数配置键的权威范围表（单一来源）** ----
        // 控制台据此 clamp 输入 ⇒ **前端不可能再摆出后端会拒绝的值**。
        // 单一来源 = `ebpdns_resolver::config::CONFIG_RANGES`（`validate_write` 用它
        // 做拒绝判据、`check-config` 用它做诊断），因此三处不可能再分叉。
        // 旧前端（不认识本字段）仍可用其本地兜底表，行为不变。
        "config_ranges": ebpdns_resolver::config::config_ranges_json(),
        // ---- **2.1.22 阶段一（新增语义）**：统一持久化事务的现场 ----
        //
        // **键名是 `state_persist` 而不是 `persist`**：`cache.persist`
        // （`api.rs::cache_persist_info`，见上面 `cache_summary`）已被 2.1.19 占用，
        // 复用同名键会**改掉既有 API 形状** —— 而本轮裁决 1 要求
        // "可观测行为除新增语义外不得变化"。两个 `persist` 的语义完全不同：
        // 前者是**缓存文件**的落盘现场，后者是**统一事务世代**的提交点现场。
        "state_persist": crate::api_state::state_persist_json(&s),
    }))
}

/// GET /api/logs：增量事件。游标 `next_seq` / `since` 都是**事件序号**（同义），
/// 并支持 q/domain/qtype/upstream/rule/min_lat 过滤——只回增量，前端不再重复累积。
///
/// **游标语义（2.1.43-A 统一）：游标 = "下一条要取的起始 seq"**，
/// 判据一律 `seq >= cursor`（边界**含**游标本身）；响应里的 `next_seq` =
/// `max(本批最后一条 seq + 1, 入参游标)`。
///
/// 2.1.42 的两个差一缺陷：
/// ① `since` 的实现是 `seq >= since`，而文档写 "只回 `seq > since`" ⇒ 用 `since`
///    的客户端会**重复**收到最后一条；
/// ② 过滤后**空批**时 `max_seq` 回退到 `p.next_seq.unwrap_or(0)`（**忽略 `since`**），
///    于是 `since=5` 的客户端在无新事件时收到的 `next_seq` 是 **1** —— 游标从 5
///    倒退回 1，下一轮把事件环**整段重放**。现在空批时游标**原地不动**（不前进、
///    绝不回退）。
async fn logs(State(s): State<AppState>, Query(p): Query<LogsQuery>) -> Response {
    let all = s.telemetry.events_snapshot();
    let total = all.len();
    let cursor = p.next_seq.or(p.since);
    let out = filter_events(all, &p);
    let next_seq = next_cursor(&out, cursor);
    json_ok(json!({
        "events": out,
        "next_seq": next_seq,
        "seq": next_seq,
        // v1.9.162 兼容：事件环内的事件总数（与本次过滤结果无关）。
        "total": total,
    }))
}

/// **2.1.43-A**：`/api/logs` 的下一个游标（纯函数，便于用单测钉死差一语义）。
///
/// * 非空批 ⇒ `最后一条 seq + 1`（下一批从它开始，`seq >=` 判据下不重不漏）；
/// * 空批   ⇒ 入参游标原样返回（**不前进**，绝不回退到 0/1）；
/// * 两者都取不到 ⇒ 0（真正的"从头开始"）。
fn next_cursor(out: &[Value], cursor: Option<u64>) -> u64 {
    match out
        .last()
        .and_then(|e| e.get("seq"))
        .and_then(Value::as_u64)
    {
        Some(last) => last.saturating_add(1),
        None => cursor.unwrap_or(0),
    }
}

/// 纯函数：按游标 + 过滤参数筛选事件（抽离以便契约测试）。
fn filter_events(events: Vec<Value>, p: &LogsQuery) -> Vec<Value> {
    let mut out = Vec::new();
    for ev in events {
        // 游标（2.1.43-A 统一）：`next_seq`（2.0）与 `since`（v1.9.162）都是
        // **事件序号**且**完全同义** —— "下一条要取的起始 seq"，判据 `seq >= ns`
        // （边界含游标）。两参数同时给出时取 `next_seq`。
        // `since_ts` 是独立的时间戳游标（扩展），只在没有序号游标时生效。
        if let Some(ns) = p.next_seq.or(p.since) {
            let seq = ev.get("seq").and_then(Value::as_u64).unwrap_or(0);
            if seq < ns {
                continue;
            }
        } else if let Some(since) = p.since_ts {
            let ts = ev.get("ts").and_then(Value::as_f64).unwrap_or(0.0);
            if ts < since {
                continue;
            }
        }
        if let Some(lv) = &p.level {
            let evl = ev.get("level").and_then(Value::as_str).unwrap_or("");
            if !evl.eq_ignore_ascii_case(lv.trim()) {
                continue;
            }
        }
        if let Some(d) = &p.domain {
            let evd = ev.get("domain").and_then(Value::as_str).unwrap_or("");
            if !evd.contains(d.as_str()) {
                continue;
            }
        }
        if let Some(qt) = &p.qtype {
            let evq = ev.get("qtype").and_then(Value::as_str).unwrap_or("");
            if !evq.eq_ignore_ascii_case(qt) {
                continue;
            }
        }
        if let Some(ip) = &p.ip {
            let evi = ev.get("client_ip").and_then(Value::as_str).unwrap_or("");
            if !evi.contains(ip.as_str()) {
                continue;
            }
        }
        if let Some(ans) = &p.answer {
            let eva = ev.get("answer").and_then(Value::as_str).unwrap_or("");
            if !eva.contains(ans.as_str()) {
                continue;
            }
        }
        if let Some(up) = &p.upstream {
            let evu = ev.get("upstream").and_then(Value::as_str).unwrap_or("");
            if !evu.contains(up.as_str()) {
                continue;
            }
        }
        if let Some(rl) = &p.rule {
            let evr = ev.get("rule").and_then(Value::as_str).unwrap_or("");
            if !evr.contains(rl.as_str()) {
                continue;
            }
        }
        if let Some(ml) = p.min_lat {
            let lat = ev.get("lat").and_then(Value::as_f64).unwrap_or(0.0);
            if lat < ml {
                continue;
            }
        }
        if let Some(q) = &p.q {
            // 全局搜索覆盖前端八列 + msg + 时间（对齐 v1.9.162 的拼接口径）。
            let blob = format!(
                "{} {} {} {} {} {} {} {}",
                ev.get("domain").and_then(Value::as_str).unwrap_or(""),
                ev.get("answer").and_then(Value::as_str).unwrap_or(""),
                ev.get("rule").and_then(Value::as_str).unwrap_or(""),
                ev.get("upstream").and_then(Value::as_str).unwrap_or(""),
                ev.get("client_ip").and_then(Value::as_str).unwrap_or(""),
                ev.get("msg").and_then(Value::as_str).unwrap_or(""),
                ev.get("ts_text").and_then(Value::as_str).unwrap_or(""),
                ev.get("qtype").and_then(Value::as_str).unwrap_or(""),
            );
            if !blob.to_ascii_lowercase().contains(&q.to_ascii_lowercase()) {
                continue;
            }
        }
        out.push(ev);
    }
    // limit：取最后 N 条（v1.9.162 语义）。
    let limit = match p.limit {
        Some(0) | None => 500,
        Some(n) => n.clamp(1, 2000),
    };
    if out.len() > limit {
        out.drain(0..out.len() - limit);
    }
    out
}

#[derive(serde::Deserialize)]
struct LogsQuery {
    /// 序号游标 = **下一条要取的起始 seq**：只回 `seq >= next_seq` 的事件
    /// （2.0 原生参数名）。响应里的 `next_seq` 可直接回填。
    next_seq: Option<u64>,
    /// 序号游标（v1.9.162 参数名）。**2.1.43-A 起与 `next_seq` 完全同义**
    /// （判据 `seq >= since`）。2.1.42 及以前这里的注释写 "只回 `seq > since`"，
    /// 与实现差 1 ⇒ 用 `since` 的客户端会重复收到最后一条。
    since: Option<u64>,
    /// 时间戳游标（epoch 秒，扩展参数；v1.9.162 无此项，供脚本按时间增量拉取）。
    since_ts: Option<f64>,
    /// 通用文本过滤（domain/answer/rule/upstream/client_ip/msg/ts 子串）。
    q: Option<String>,
    /// 级别精确匹配：hit / miss / rule / err / sys / warn。
    level: Option<String>,
    domain: Option<String>,
    qtype: Option<String>,
    /// 客户端 IP 子串（v1.9.162 参数名）。
    ip: Option<String>,
    /// 解析值子串（2.0 扩展，前端「解析值IP」列）。
    answer: Option<String>,
    upstream: Option<String>,
    rule: Option<String>,
    /// 最小延迟过滤（ms）。
    min_lat: Option<f64>,
    /// 最多返回条数（v1.9.162：默认 500，<1 → 500，>2000 → 2000）。
    limit: Option<usize>,
}

/// GET /api/pipeline：规则/缓存/上游阶段概览（2.1.29 起不含任何 XDP/eBPF 阶段）。
///
/// `upstreams` 为脱敏数组（仅 id/name/proto）；`cache_direct_enabled` 是用户态
/// 缓存直答开关。`rules` 取**规则索引真实条数**（`Resolver::rule_count()`，
/// = 本地逐条 + 所有订阅展开后进索引的条数），不是 `cfg.rules.len()`。
///
/// **2.1.43-B（P2-7）**：`cache_direct_enabled` 是**保留键，当前无效果**
/// （不门禁任何行为/计数）—— 这里只做契约回显，读取点显式 `allow(deprecated)`。
#[allow(deprecated)] // P2-7：保留键回显（config.json 契约），不是行为开关。
async fn pipeline(State(s): State<AppState>) -> Response {
    let cfg = s.resolver.config();
    let upstreams: Vec<Value> = cfg
        .upstreams
        .iter()
        .map(|u| json!({"id": u.id, "name": u.name, "proto": u.proto}))
        .collect();
    let upstream_count = cfg.upstreams.len();
    let rules = s.resolver.rule_count();
    json_ok(json!({
        "cache_direct_enabled": cfg.cache_direct_enabled,
        "cache_size": cfg.cache_size,
        "cache_policy": cfg.cache_policy,
        "upstreams": upstreams,
        "upstream_count": upstream_count,
        "rules": rules,
        "prefetch_len": s.resolver.prefetch_len(),
        "rule_gen": s.resolver.rule_gen(),
    }))
}

/// GET /metrics（Prometheus 文本格式）。
///
/// **A7（2.1.9）补齐可观测性**。2.1.8 只暴露 5 项（queries/hits/misses/errors/uptime），
/// `bytes_in`/`bytes_out` 恒为 0，且**完全没有上游维度**与负缓存维度。
/// 本次新增（均为**追加**，前 5 项的名字/类型/口径不变，旧抓取器不受影响）：
///
/// - `ebpdns_upstream_dispatch_total`：**派发**的上游配置数（`UpstreamRuntime::query` 调用次数）；
/// - `ebpdns_upstream_wire_requests_total`：**真实线速**上游请求数
///   （多 IP 并行 / TC→TCP 回退 / 连接复用与重试各计 1）；
/// - `ebpdns_upstream_requests_total`：与 `/api/status.counters.upstream_requests` **同源**
///   （resolver 的物理口径），保留以兼容既有仪表盘；
/// - `ebpdns_upstream_requests_total_by_id{id=...}`：**逐上游**请求数（来自逐上游事件聚合）；
///
/// **2.1.41**：上面这条以前 HELP 写的是 `_by_id`、样本却写成
/// `ebpdns_upstream_requests_total{id=...}`（挂到聚合 family 上 ⇒ `sum()` 双计、
/// `_by_id` 永远空）；现在 HELP/TYPE/样本统一为 `_by_id`。
/// - `ebpdns_upstream_latency_ms{id=...}`：逐上游延迟**累积直方图**
///   （`_bucket{le=}` + `_sum` + `_count`）+ `_p50/_p90/_p99` 分位数量规；
/// - `ebpdns_cache_entries`：当前缓存条目数；
/// - `ebpdns_cache_negative_hits_total` + `ebpdns_negcache_hit_ratio`：负缓存命中与命中率；
///   **2.1.12 口径修正** —— 计数下移到唯一判定点（`dns.rs::count_negative_cache_hit`），
///   与查询入口（UDP / TCP / 控制面 `/api/query`）**无关**，且恒为
///   `ebpdns_cache_direct_total` 的子集（比值 ≤ 1）；
/// - `ebpdns_bytes_in_total` / `ebpdns_bytes_out_total`：客户端 UDP/TCP 收发**真实字节数**
///   （2.1.8 恒为 0 的 `counters.bytes_*` 现在被数据面真正填充）。
///
/// **2.1.17（修复项 2/3/4）追加**：
/// - `ebpdns_query_latency_ms`：客户端视角延迟**直方图**（单位 ms，桶
///   `1/2/5/10/25/50/100/250/500/1000/+Inf`，累积语义）。窗口 = 最近 **400** 条带实测
///   耗时的数据面应答（hit/miss/err/warn；rule 与手动查询不计入），**与
///   `/api/status.avg_latency_ms` 同一个环形缓冲** ⇒ 同一抓取时刻
///   `_sum/_count == avg_latency_ms`。**必须与 `_count` 一起读**：低流量下几条慢
///   miss 就能把均值抬起来（2.1.16 审计看到的 21.5 ms 是**6 条样本**的均值，
///   与压测满窗均值不是同一抽样时刻）；
/// - `ebpdns_rule_hits_total{match_type,action}`：规则命中的二维聚合（与
///   `/api/status.rule_hits` 同源同点打点，二者总量恒等）；
/// - `ebpdns_cache_skipped_private_total`：因 rebind 防护被丢弃的私有/保留地址答案
///   **条数**（这些结果**按设计不入缓存**）。与
///   `/api/status.counters.cache_skipped_private_total` 同源同值；与
///   `counters.rebind_blocked`（**控制面**拦截口径，数据面恒 0）是两个不同的门。
///
/// 注意 `id` 一律经 `prom_label_escape`，**绝不**让上游 id 里的 `"` / 换行 / 反斜杠
/// 破坏 Prometheus 文本协议（配置由控制台写入，属于可控但不可信输入）。
/// **2.1.48 / AUD-09**：进程自观测（Linux `/proc`，非 Linux 全 0）。
///
/// 2.1.47 的核心验收就是 RSS，但此前 235 只能靠 OS 侧脚本采集。现在 `/metrics` 直接
/// 暴露 RSS/虚拟内存/线程/fd，升级后可用纯 HTTP 自证“内存已平台化”。
fn process_health() -> (u64, u64, u64, u64) {
    let mut rss_kb = 0u64;
    let mut vm_kb = 0u64;
    let mut threads = 0u64;
    if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
        for line in s.lines() {
            if let Some(v) = line.strip_prefix("VmRSS:") {
                rss_kb = v
                    .split_whitespace()
                    .next()
                    .and_then(|x| x.parse::<u64>().ok())
                    .unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("VmSize:") {
                vm_kb = v
                    .split_whitespace()
                    .next()
                    .and_then(|x| x.parse::<u64>().ok())
                    .unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("Threads:") {
                threads = v
                    .split_whitespace()
                    .next()
                    .and_then(|x| x.parse::<u64>().ok())
                    .unwrap_or(0);
            }
        }
    }
    let fds = std::fs::read_dir("/proc/self/fd")
        .map(|d| d.count() as u64)
        .unwrap_or(0);
    (
        rss_kb.saturating_mul(1024),
        vm_kb.saturating_mul(1024),
        threads,
        fds,
    )
}

async fn metrics(State(s): State<AppState>) -> impl IntoResponse {
    // **2.1.17（修复项 4）**：先取时序锚点，**再**取 counters —— 保证
    // `# align-snapshot` 行的时刻 <= counters 的取数时刻（锚点是本次抓取的**下界**，
    // 与 `/api/status.snapshot_monotonic_ms` 同为 `ServerTelemetry::monotonic_ms()`，
    // 两个端点因此可用同一个单调时钟对齐）。
    let align_monotonic_ms = s.telemetry.monotonic_ms();
    let align_epoch_ms = (now_epoch() * 1000.0).round() as u64;
    let align_uptime_s = s.telemetry.uptime_s();
    // **2.1.18（修复项 2）**：本次抓取的**全部**计数器取自**同一代**快照
    // （`total/hit/miss/errors/bytes_*/udp_dropped/servfail*/client_rcode/negative_hits/
    // cache_skipped_private_total` 全在这一份里），并把代数写进首行
    // `# align-snapshot seq=…`，使"这一份抓取属于第几代"可被脚本判定。
    let csnap = s.telemetry.snapshot();
    let snapshot_seq = csnap.seq;
    // 兼容既有 `c.get(k)` 取值风格：把快照投影成 15 键的标量表。
    let c = {
        let mut m = serde_json::Map::new();
        m.insert("total".into(), json!(csnap.total));
        m.insert("hit".into(), json!(csnap.hit));
        m.insert("miss".into(), json!(csnap.miss));
        m.insert("upstream_queries".into(), json!(csnap.upstream_queries));
        m.insert("errors".into(), json!(csnap.errors));
        m.insert("ipv4_fallback".into(), json!(csnap.ipv4_fallback));
        m.insert("stale_served".into(), json!(csnap.stale_served));
        m.insert("bytes_in".into(), json!(csnap.bytes_in));
        m.insert("bytes_out".into(), json!(csnap.bytes_out));
        m.insert("rebind_blocked".into(), json!(csnap.rebind_blocked));
        m.insert("udp_dropped".into(), json!(csnap.udp_dropped));
        m.insert("servfail_total".into(), json!(csnap.servfail_total));
        m.insert("negative_hits".into(), json!(csnap.negative_hits));
        m.insert(
            "cache_skipped_private_total".into(),
            json!(csnap.cache_skipped_private_total),
        );
        // **2.1.18（修复项 9）**：出口登记但无可发送报文的次数（`total` 的差额项）。
        m.insert("no_response_total".into(), json!(csnap.no_response_total));
        // **2.1.29**：未知 qtype 透传（与 `/api/status.counters` 同源同值）。
        m.insert(
            "passthrough_qtype_total".into(),
            json!(csnap.passthrough_qtype_total),
        );
        // **2.1.40**：本地策略短路（AAAA 屏蔽 / IPv6 关闭；不计 hit/miss）。
        m.insert(
            "policy_filtered_total".into(),
            json!(csnap.policy_filtered_total),
        );
        Value::Object(m)
    };
    let u64_of = |k: &str| c.get(k).and_then(Value::as_u64).unwrap_or(0);
    let mut body = String::with_capacity(4096);
    // ---- **2.1.17（修复项 4）：抓取时刻标记（对齐压测窗口用）** ----
    //
    // 为什么放在**最前面**：Prometheus 文本协议允许 `#` 注释，把取数时刻写在
    // 第一行可以让脚本"读到文件头就知道这一份抓取属于哪个瞬间"，从而与
    // `/api/status.snapshot_monotonic_ms` 用**同一个单调时钟**对齐
    // （两个端点的值都来自 `ServerTelemetry::monotonic_ms()`，量纲一致）。
    // 这不是指标（不参与 `sum/rate`），只是时序锚点，因此用注释而不是 gauge。
    //
    // **2.1.18（修复项 2）**：追加 `seq=`（同代快照的代数）。
    // `monotonic_ms` 是"什么时候抓的"（毫秒级），`seq` 是"抓到的是第几代"
    // （**精确到每一次计数写入**）—— 两者都在同一个快照里取出。
    // 对账脚本用 `seq` 判断"两次抓取之间是否有写入"：相同 ⇒ 可以做逐字段差分；
    // 不同 ⇒ 只允许做"单调不减"检查（E5 的 ±1 正是跨代差分造成的假象）。
    body.push_str(&format!(
        "# align-snapshot seq={} monotonic_ms={} epoch_ms={} uptime_s={}\n",
        snapshot_seq, align_monotonic_ms, align_epoch_ms, align_uptime_s
    ));
    // ---- 前 5 项：**逐字保留** 2.1.8 的输出（HELP/TYPE/值三重兼容）----
    body.push_str(&format!(
        "# HELP ebpdns_queries_total Total DNS queries.\n# TYPE ebpdns_queries_total counter\nebpdns_queries_total {total}\n\
         # HELP ebpdns_cache_hits_total Cache hits.\n# TYPE ebpdns_cache_hits_total counter\nebpdns_cache_hits_total {hit}\n\
         # HELP ebpdns_cache_misses_total Cache misses.\n# TYPE ebpdns_cache_misses_total counter\nebpdns_cache_misses_total {miss}\n\
         # HELP ebpdns_errors_total Errors.\n# TYPE ebpdns_errors_total counter\nebpdns_errors_total {errors}\n\
         # HELP ebpdns_uptime_seconds Uptime.\n# TYPE ebpdns_uptime_seconds gauge\nebpdns_uptime_seconds {up}\n",
        total = u64_of("total"),
        hit = u64_of("hit"),
        miss = u64_of("miss"),
        errors = u64_of("errors"),
        up = s.telemetry.uptime_s(),
    ));

    // ---- A7：客户端字节数（2.1.8 恒 0，现在由 dns.rs 数据面真实累加）----
    body.push_str(&format!(
        "# HELP ebpdns_bytes_in_total DNS wire bytes received from clients (UDP datagrams / TCP payloads).\n\
         # TYPE ebpdns_bytes_in_total counter\nebpdns_bytes_in_total {bin}\n\
         # HELP ebpdns_bytes_out_total DNS wire bytes sent to clients.\n\
         # TYPE ebpdns_bytes_out_total counter\nebpdns_bytes_out_total {bout}\n\
         # HELP ebpdns_udp_dropped_total UDP queries dropped because the user-space miss-concurrency gate was exhausted \
         (same source as /api/status.counters.udp_dropped; non-zero means clients will time out and retry).\n\
         # TYPE ebpdns_udp_dropped_total counter\nebpdns_udp_dropped_total {udrop}\n",
        bin = u64_of("bytes_in"),
        bout = u64_of("bytes_out"),
        udrop = u64_of("udp_dropped"),
    ));

    // ---- A7：上游派发 / 线速 / 物理口径 ----
    let (wire, dispatch) = match s.resolver.upstream_runtime() {
        Some(rt) => (rt.wire_requests(), rt.dispatch_count()),
        None => (0, 0),
    };
    body.push_str(&format!(
        "# HELP ebpdns_upstream_dispatch_total Upstream configs dispatched (one per UpstreamRuntime::query call).\n\
         # TYPE ebpdns_upstream_dispatch_total counter\nebpdns_upstream_dispatch_total {dispatch}\n\
         # HELP ebpdns_upstream_wire_requests_total Real wire upstream requests (multi-IP fan-out / TC->TCP fallback / retries each count 1).\n\
         # TYPE ebpdns_upstream_wire_requests_total counter\nebpdns_upstream_wire_requests_total {wire}\n\
         # HELP ebpdns_upstream_requests_total Physical upstream requests (same source as /api/status.counters.upstream_requests).\n\
         # TYPE ebpdns_upstream_requests_total counter\nebpdns_upstream_requests_total {phys}\n\
         # HELP ebpdns_upstream_early_return_total Winner-answered-first early returns.\n\
         # TYPE ebpdns_upstream_early_return_total counter\nebpdns_upstream_early_return_total {er}\n\
         # HELP ebpdns_upstream_hedge_total Hedged (extra) upstream queries.\n\
         # TYPE ebpdns_upstream_hedge_total counter\nebpdns_upstream_hedge_total {hg}\n",
        dispatch = dispatch,
        wire = wire,
        phys = s.resolver.upstream_requests(),
        er = s.resolver.upstream_early_returns(),
        hg = s.resolver.upstream_hedges(),
    ));

    // ---- A7：缓存条目数 + 负缓存 ----
    let cache_summary = s.resolver.cache().summary();
    let cache_used = cache_summary
        .get("used")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let cache_cap = cache_summary
        .get("capacity")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let cache_direct = cache_direct_projection(csnap.hit);
    // **2.1.24**：命中率的格式化**先算好**再传给外层 `format!` —— 原来把
    // `format!("{:.6}", …)` 直接塞进外层 `format!` 的具名参数（`clippy::format_in_format_args`：
    // 多一次分配，且把"格式化"藏进了参数表达式里）。输出的六位小数逐位不变。
    // >>> 242B BEGIN P1-7-metrics >>> //
    // **2.1.42-B（P1-7）**：真实分母（缓存直答 = `hit`）+ 不变量断言。
    // 旧实现的 `.min(1.0)` 把 `negative_hits > hit` 这种口径缺陷静默钳成 1.0。
    debug_assert!(
        csnap.negative_hits <= csnap.hit,
        "negative_hits({}) 必须是 hit({}) 的子集（P1-7）",
        csnap.negative_hits,
        csnap.hit
    );
    let neg_ratio = format!(
        "{:.6}",
        if csnap.hit == 0 {
            0.0
        } else {
            csnap.negative_hits as f64 / csnap.hit as f64
        }
    );
    // <<< 242B END P1-7-metrics <<< //
    body.push_str(&format!(
        "# HELP ebpdns_cache_entries Current cache entry count.\n# TYPE ebpdns_cache_entries gauge\nebpdns_cache_entries {used}\n\
         # HELP ebpdns_cache_capacity Configured cache capacity (entries).\n# TYPE ebpdns_cache_capacity gauge\nebpdns_cache_capacity {cap}\n\
         # HELP ebpdns_cache_direct_total User-space direct cache answers (distinct from kernel hits).\n\
         # TYPE ebpdns_cache_direct_total counter\nebpdns_cache_direct_total {cd}\n\
         # HELP ebpdns_cache_negative_hits_total Negative answers served FROM CACHE (NXDOMAIN / NODATA), counted once per cache-direct answer on the UDP/TCP data plane only (control-plane /api/query never increments it). Subset of ebpdns_cache_direct_total.\n\
         # TYPE ebpdns_cache_negative_hits_total counter\nebpdns_cache_negative_hits_total {neg}\n\
         # HELP ebpdns_negcache_hit_ratio Share of cache-direct answers that were negative (0..1; denominator = ebpdns_cache_direct_total).\n\
         # TYPE ebpdns_negcache_hit_ratio gauge\nebpdns_negcache_hit_ratio {ratio}\n\
         # HELP ebpdns_negative_single_vote_accepted_total Negative conclusions accepted with only ONE valid vote\n\
         #  (silent/timed-out upstreams abstain). Same source as /api/status.counters.negative_single_vote_accepted.\n\
         # TYPE ebpdns_negative_single_vote_accepted_total counter\nebpdns_negative_single_vote_accepted_total {nsv}\n",
        used = cache_used,
        cap = cache_cap,
        cd = cache_direct,
        // **2.1.18（修复项 2）**：直接取本代快照（不再各自 `with_snapshot()`），
        // 于是这几个指标与上面的 `total/hit/miss` 严格同代。
        neg = csnap.negative_hits,
        ratio = neg_ratio,
        nsv = s.resolver.negative_single_vote_accepted(),
    ));

    // ---- 2.1.15（P1）：SERVFAIL 总数 + 原因维度 + 单上游在途闸门 ----
    //
    // 与 `/api/status.counters.servfail_total` / `.servfail_reasons` **同源**
    // （同一组原子计数，唯一打点 = `dns.rs::log_and_count`），因此同一次抓取不会
    // 出现"页面 4 个、metrics 0 个"的互相矛盾。`reason` 标签值取自固定的 5 档
    // （`telemetry::SERVFAIL_REASONS`），不来自用户输入，但仍经 `prom_label_escape`
    // 以免未来新增键破坏 Prometheus 文本协议。
    {
        // **2.1.18（修复项 2）**：聚合值与 5 档明细取自**同一代**快照
        // （`csnap.servfail_total` 与 `csnap.servfail_reasons`）——
        // 改前分别读原子 + 加锁读表，两次读之间可能落入一条 SERVFAIL，
        // 于是同一次抓取里 `Σ 分档 != 聚合`（E5 的同型问题，只是发生在 /metrics 侧）。
        let reasons = &csnap.servfail_reasons;
        let mut per_reason = String::new();
        for (i, k) in crate::telemetry::SERVFAIL_REASONS.iter().enumerate() {
            per_reason.push_str(&format!(
                "ebpdns_servfail_reasons_total{{reason=\"{}\"}} {}\n",
                prom_label_escape(k),
                reasons[i]
            ));
        }
        // **2.1.16（修复项 8 / 口径误读）**：把"聚合值"与"分档值"拆成**两个不同的
        // 指标名**。
        //
        // 为什么必须拆（部署代理实测踩到的真坑）：2.1.15 把两者写成**同一个**
        // `ebpdns_servfail_total`，只靠 `reason="all"` 区分 —— Prometheus 抓取后
        // 对同名 series 求和（`sum(ebpdns_servfail_total)`）会**正好翻倍**
        // （`all` 与 5 档都在同一指标名下，而 `all == Σ各档`）。
        // 现在：
        // - `ebpdns_servfail_total`（**无标签**）= 聚合值，唯一一条 series；
        // - `ebpdns_servfail_reasons_total{reason=…}` = 5 档明细，`Σ == 聚合值`；
        // - 两者**不得相加**（HELP 里写明，单测
        //   `s8_servfail_metric_families_must_not_be_summed` 钉死语义）。
        body.push_str(
            "# HELP ebpdns_servfail_total SERVFAIL (rcode=2) responses actually sent to clients, \
             counted once at the data-plane exit. AGGREGATE ONLY: it equals the sum of \
             ebpdns_servfail_reasons_total, therefore the two metric families MUST NOT be added \
             together (doing so double-counts).\n\
             # TYPE ebpdns_servfail_total counter\n",
        );
        body.push_str(&format!("ebpdns_servfail_total {}\n", csnap.servfail_total));
        body.push_str(
            "# HELP ebpdns_servfail_reasons_total Mutually exclusive reason buckets for \
             ebpdns_servfail_total. Their sum equals ebpdns_servfail_total; do not add them to it.\n\
             # TYPE ebpdns_servfail_reasons_total counter\n",
        );
        body.push_str(&per_reason);
        // 单上游在途闸门（2.1.15 P1）：上限为 gauge，等待/拒绝为 counter。
        let (acq, queued, rej) = match s.resolver.upstream_runtime() {
            Some(rt) => rt.inflight.stats(),
            None => (0, 0, 0),
        };
        let cap = match s.resolver.upstream_runtime() {
            Some(rt) => rt.inflight.cap(),
            None => 0,
        };
        // **2.1.17（修复项 7）**：等到许可但预算已被排队吃光的次数（与 `rejected` 分开）。
        let gave_up = match s.resolver.upstream_runtime() {
            Some(rt) => rt.inflight.queued_gave_up(),
            None => 0,
        };
        body.push_str(&format!(
            "# HELP ebpdns_upstream_inflight_limit Configured per-upstream in-flight request limit \
             (0 = gate disabled).\n\
             # TYPE ebpdns_upstream_inflight_limit gauge\nebpdns_upstream_inflight_limit {cap}\n\
             # HELP ebpdns_upstream_inflight_acquired_total Upstream requests that obtained an \
             in-flight permit.\n\
             # TYPE ebpdns_upstream_inflight_acquired_total counter\n\
             ebpdns_upstream_inflight_acquired_total {acq}\n\
             # HELP ebpdns_upstream_inflight_queued_total Upstream requests that had to wait for a \
             permit (per-upstream limit was full).\n\
             # TYPE ebpdns_upstream_inflight_queued_total counter\n\
             ebpdns_upstream_inflight_queued_total {queued}\n\
             # HELP ebpdns_upstream_inflight_rejected_total Upstream requests that gave up waiting \
             for a permit within their timeout budget (never obtained one).\n\
             # TYPE ebpdns_upstream_inflight_rejected_total counter\n\
             ebpdns_upstream_inflight_rejected_total {rej}\n\
             # HELP ebpdns_upstream_inflight_queued_gave_up_total Upstream requests that DID obtain a \
             permit but whose remaining timeout budget was already below the minimum useful budget \
             for one protocol round trip, so they were abandoned deliberately (queueing had eaten \
             the budget). Distinct from rejected_total: that one never got a permit. Non-zero here \
             means the queue is deeper than it is healthy.\n\
             # TYPE ebpdns_upstream_inflight_queued_gave_up_total counter\n\
             ebpdns_upstream_inflight_queued_gave_up_total {gave_up}\n",
        ));
    }

    // ---- 2.1.16（修复项 3）：客户端视角延迟直方图 ----
    //
    // 口径：**客户端视角**（= 数据面从收包到回包的端到端耗时），数据源与
    // `/api/status.avg_latency_ms` **是同一个 `push_latency` 窗口**，
    // 因此 `_sum / _count` 与 `/api/status.avg_latency_ms` 在同一时刻必然一致
    // （浮点容差内；单测 `s3_client_histogram_sum_over_count_matches_avg_latency`）。
    // **不是**逐上游 RTT（那是 `ebpdns_upstream_latency_ms`，两者刻意分开：
    // 一个包含排队/本地规则/缓存直答，一个只含上游交换）。
    //
    // **2.1.17（修复项 2）：HELP 文案必须精确描述"窗口"到底是什么 ——
    // 不得再用含糊的 "same window" 让人以为它与「上游视角的实测均值」同量级。**
    //
    // 2.1.16 交付审计登记的疑问（"21.5 ms vs 直方图口径差 3 个数量级"）的**真实根因**
    // 不是两者不同源，而是**样本数不同**：
    //   - `21.5 ms` 来自 `/api/status.avg_latency_ms`，当时窗口里只有 **6 条**样本
    //     （`total=6`，5 hit + 1 miss，其中唯一那条 miss 是真实上游往返 ⇒ 均值被它主导）；
    //   - 直方图口径取自**隔离阶梯压测**（400 条满窗、miss 为主）⇒ 均值 ≈ 206 ms。
    // 两者是**同一口径的不同抽样时刻**，不是两个口径。README「延迟口径」一节给出
    // 同一压测窗口下的实测对照表（含 `_count` 与 `sum/_count`）。
    {
        let (count, sum, buckets) = s.telemetry.client_latency_histogram();
        body.push_str(
            "# HELP ebpdns_query_latency_ms Client-observed query latency in milliseconds \
             (data-plane receive-to-reply). Unit = milliseconds. Window = the last \
             LATENCY_WINDOW_MAX (=400) data-plane replies that carry a measured latency \
             (levels hit/miss/err/warn; rule-only and control-plane queries are excluded), \
             i.e. the SAME ring buffer as /api/status.avg_latency_ms, so \
             _sum/_count == avg_latency_ms at the same scrape instant. It is NOT the \
             upstream RTT (use ebpdns_upstream_latency_ms) and NOT a process-lifetime \
             average: at low traffic a handful of slow misses can dominate the mean, which \
             is why it must always be read together with _count. Buckets are cumulative; \
             le values are 1,2,5,10,25,50,100,250,500,1000 ms plus +Inf (= _count).\n\
             # TYPE ebpdns_query_latency_ms histogram\n",
        );
        for (le, n) in &buckets {
            body.push_str(&format!(
                "ebpdns_query_latency_ms_bucket{{le=\"{}\"}} {}\n",
                prom_le(*le),
                n
            ));
        }
        body.push_str(&format!(
            "ebpdns_query_latency_ms_bucket{{le=\"+Inf\"}} {count}\n\
             ebpdns_query_latency_ms_sum {:.3}\n\
             ebpdns_query_latency_ms_count {count}\n",
            sum
        ));
    }

    // ---- 2.1.16（功能 3）：per-rule 命中（match_type × action 二维聚合）----
    //
    // 与 `/api/status.rule_hits`（一维 action 键）**同源同点打点**，
    // 因此 `sum(本指标各行) == sum(status.rule_hits 各键)`（自动对账断言见
    // `scripts/f216-counters-reconcile.py` 与 `telemetry::tests`）。
    // `match_type` 取自 `ebpdns_rules::match_kind`（与 RuleIndex 六分表同构）。
    {
        let kinds = s.telemetry.rule_hits_by_kind();
        body.push_str(
            "# HELP ebpdns_rule_hits_total Rule hits aggregated by rule match type and action \
             (same data source as /api/status.rule_hits).\n\
             # TYPE ebpdns_rule_hits_total counter\n",
        );
        for (mt, ac, n) in &kinds {
            body.push_str(&format!(
                "ebpdns_rule_hits_total{{match_type=\"{}\",action=\"{}\"}} {}\n",
                prom_label_escape(mt),
                prom_label_escape(ac),
                n
            ));
        }
    }

    // ---- 2.1.16（修复项 15）：负缓存命中（对外 counters 口径）----
    body.push_str(&format!(
        "# HELP ebpdns_negative_cache_hits_total Negative-cache (NXDOMAIN/NODATA) hits counted in \
         the cache-direct path. Same source as /api/status.counters.negative_hits.\n\
         # TYPE ebpdns_negative_cache_hits_total counter\n\
         ebpdns_negative_cache_hits_total {nh}\n",
        nh = csnap.negative_hits,
    ));

    // ---- 2.1.17（修复项 3）：私有/保留地址答案被过滤（⇒ 该结果不入缓存）----
    //
    // 设计行为可观测：`rebind_protection=true`（默认）时，上游给出的 RFC1918/保留段
    // A/AAAA 答案会被丢弃，**该结果不写入缓存** —— 于是同一域名反复查询会每次都
    // 走上游。2.1.16 交付审计把这种"同键恒 miss / entries=0"误判为"缓存坏了"，
    // 因为当时 `counters.rebind_blocked` 恒 0（它统计的是**控制面** DNS-rebinding
    // 拦截，数据面不经过它）。本计数 = 数据面答案过滤的**条数**，与
    // `/api/status.counters.cache_skipped_private_total` **同源同值**（同一原子计数，
    // 唯一打点 = `dns.rs::log_and_count`）。
    body.push_str(&format!(
        "# HELP ebpdns_cache_skipped_private_total A/AAAA answers dropped by the rebind \
         protection because they are private/reserved addresses. Such results are NOT written \
         to the cache (by design), so the same name keeps missing and re-querying upstream. \
         Non-zero here explains an \"entries=0 / always-miss\" observation without any cache \
         defect. A different gate from counters.rebind_blocked, which counts CONTROL-PLANE \
         DNS-rebinding rejections and is therefore 0 on the pure DNS data plane. \
         Same source as /api/status.counters.cache_skipped_private_total.\n\
         # TYPE ebpdns_cache_skipped_private_total counter\n\
         ebpdns_cache_skipped_private_total {csp}\n",
        csp = csnap.cache_skipped_private_total,
    ));

    // ---- **2.1.18（修复项 9）**：出口登记但无可发送报文的次数 ----
    //
    // 用途：让 `total` 与 `Σ client_rcode` 的**恒等式**可被完整对账 ——
    // `#(数据面出口登记数) == ebpdns_queries_total + ebpdns_no_response_total`。
    // 非 0 表示存在"进了出口但连 12 字节应答都没构造出来"的查询
    // （畸形包 / 空 question / 组包失败），这类查询**不计** `total`（也就没有 rcode），
    // 因此不会破坏 `total == Σ rcodes`。
    body.push_str(&format!(
        "# HELP ebpdns_no_response_total Data-plane exit registrations for which NO client \
         response could be constructed (malformed packet / empty question / encoding failure), \
         i.e. `resp.len() < 12`. Invariant: ebpdns_queries_total == sum(ebpdns_client_rcode_total) \
         and (#exit registrations) == ebpdns_queries_total + ebpdns_no_response_total. \
         Same source as /api/status.counters.no_response_total.\n\
         # TYPE ebpdns_no_response_total counter\n\
         ebpdns_no_response_total {nrt}\n\
         # HELP ebpdns_control_queries_total Control-plane POST /api/query calls \
         (NOT counted in ebpdns_queries_total / hit / miss / hit_rate).\n\
         # TYPE ebpdns_control_queries_total counter\nebpdns_control_queries_total {cq}\n\
         # HELP ebpdns_control_hits_total Control-plane queries answered from cache. \
         Keep this SEPARATE from ebpdns_hits_total so hit_rate = hit/(hit+miss) stays <= 100%.\n\
         # TYPE ebpdns_control_hits_total counter\nebpdns_control_hits_total {ch}\n\
         # HELP ebpdns_passthrough_qtype_total Queries whose qtype is NEITHER supported \
         (parsed+cached) NOR must-reject: they are forwarded with their ORIGINAL u16 qtype \
         and the upstream response is relayed verbatim, WITHOUT caching. Success and \
         failure both count once. Same source as /api/status.counters.passthrough_qtype_total.\n\
         # TYPE ebpdns_passthrough_qtype_total counter\n\
         ebpdns_passthrough_qtype_total {ptq}\n",
        nrt = csnap.no_response_total,
        cq = csnap.control_queries,
        ch = csnap.control_hits,
        ptq = csnap.passthrough_qtype_total,
    ));

    // ---- **2.1.40**：本地策略短路（AAAA 屏蔽 / IPv6 关闭）----
    //
    // 口径与 `/api/status.counters.policy_filtered_total` **同源同值**（同一份快照）。
    // 这类应答没查缓存、没发上游，**不计** hit/miss：`ebpdns_queries_total` 仍是
    // Σ client_rcode（含策略应答），而 `ebpdns_cache_hits_total / _misses_total` 只数
    // 真正的缓存/上游决策，因此 `hit_rate = hits/(hits+misses)`（2.1.40 起）不被
    // AAAA 策略应答拉低。
    body.push_str(&format!(
        "# HELP ebpdns_policy_filtered_total Queries answered locally by policy (AAAA suppressed by prefer_ipv4, \
         or IPv6 disabled). Not counted in hit/miss/upstream; hit_rate = hits/(hits+misses). \
         Same source as /api/status.counters.policy_filtered_total.\n\
         # TYPE ebpdns_policy_filtered_total counter\n\
         ebpdns_policy_filtered_total {pf}\n",
        pf = u64_of("policy_filtered_total"),
    ));

    // ---- 2.1.16（修复项 8）：实际发往客户端的 rcode 分布（服务端侧自证）----
    //
    // 用途：把"客户端数到的 rcode==2"与"服务端实际发出的 rcode==2"对账。
    // 与 `ebpdns_servfail_total` **同点打点**（`dns.rs::log_and_count`），因此
    // `ebpdns_client_rcode_total{rcode="2"} == ebpdns_servfail_total` 是硬等式。
    // 若客户端统计到 SERVFAIL 而这里 `rcode="2"` 为 0 ⇒ 客户端把**超时/无应答**
    // 误分类成了 SERVFAIL（服务端对应的可观测是 `udp_dropped` / 无回包）。
    {
        // **2.1.18（修复项 2）**：rcode 分布取自**同一代**快照（与上面的
        // `ebpdns_servfail_total` 严格同代 ⇒ `rcode="2" == servfail_total` 恒成立）。
        let d = &csnap.client_rcode;
        body.push_str(
            "# HELP ebpdns_client_rcode_total RCODEs of responses actually constructed for \
             clients, counted at the single data-plane exit. DROPPED/UNANSWERED requests \
             (udp_dropped, TCP buffer limit, send failure) produce NO rcode and are NOT counted \
             here — so clients must not report timeouts as SERVFAIL. Invariant: \
             ebpdns_client_rcode_total{rcode=\"2\"} == ebpdns_servfail_total.\n\
             # TYPE ebpdns_client_rcode_total counter\n",
        );
        for (i, n) in d.iter().enumerate() {
            // 只输出非零档 + rcode=2 档（0 恒输出便于脚本稳定取值）。
            if *n == 0 && i != 0 && i != 2 {
                continue;
            }
            body.push_str(&format!("ebpdns_client_rcode_total{{rcode=\"{i}\"}} {n}\n"));
        }
    }

    // ---- 2.1.12（A 的 ①）：RFC 8020 推断计数 ----
    // 与 `/api/status.counters.rfc8020_*` **同源**（同一组原子计数，见
    // `ebpdns-resolver/src/rfc8020.rs` 的 `rfc8020_hits()/rfc8020_registrations()`），
    // 因此两处抓取不会互相矛盾；两者都是 counter（只增不减，可安全 `rate()`）。
    body.push_str(&format!(
        "# HELP ebpdns_rfc8020_hits_total Answers served by RFC 8020 parent-domain NXDOMAIN \
         inference (no upstream request was sent). Same source as /api/status.counters.rfc8020_hits.\n\
         # TYPE ebpdns_rfc8020_hits_total counter\nebpdns_rfc8020_hits_total {rh}\n\
         # HELP ebpdns_rfc8020_registrations_total NXDOMAIN names registered into the RFC 8020 \
         inference set (new or updated entries; re-registering the same name does not count again).\n\
         # TYPE ebpdns_rfc8020_registrations_total counter\nebpdns_rfc8020_registrations_total {rr}\n",
        rh = s.resolver.rfc8020_hits(),
        rr = s.resolver.rfc8020_registrations(),
    ));

    // ---- **2.1.43-A（P2：`breaker_all_open` 类型）**：**累计 counter** ----
    // 2.1.42 只在 `/api/status.counters` 里下发本键，且 `web/INTERFACE.md` 把它与
    // `prefetch_all_open` 并列写成 `bool`（瞬时 gauge）—— 与实现（`u64` 只增累计）
    // 矛盾：抓取器/页面按 bool 解析会把 37 读成 `true`，且无法算速率。
    // 现在口径**统一为 counter（累计次数）**，`/metrics` 同步给出
    // `ebpdns_breaker_all_open_total`（HELP 里明确"不是 0/1 状态"）；瞬时状态继续由
    // `ebpdns_prefetch_all_open`（gauge）承担，两者语义不重叠。
    body.push_str(&format!(
        "# HELP ebpdns_breaker_all_open_total How many times resolution had to fall back \
         because EVERY enabled upstream circuit breaker was open (cumulative counter, NOT a \
         0/1 gauge; use ebpdns_prefetch_all_open for the instantaneous state). Same source as \
         /api/status.counters.breaker_all_open.\n\
         # TYPE ebpdns_breaker_all_open_total counter\n\
         ebpdns_breaker_all_open_total {bao}\n",
        bao = s.resolver.cb_all_open_count(),
    ));

    // ---- **2.1.19（修复项 5-⑨）**：预取"全部上游熔断"状态（状态而非日志噪声）----
    // 与 `/api/status.counters.prefetch_all_open` / `prefetch_degraded_total` **同源**。
    // `ebpdns_prefetch_all_open` 是 **gauge**（0/1，瞬时状态）；`_total` 是 counter。
    body.push_str(&format!(
        "# HELP ebpdns_prefetch_all_open 1 = every enabled upstream circuit breaker is open, so \
         prefetch degrades to the lowest eff_lat candidate. Same source as \
         /api/status.counters.prefetch_all_open.\n\
         # TYPE ebpdns_prefetch_all_open gauge\nebpdns_prefetch_all_open {ao}\n\
         # HELP ebpdns_prefetch_degraded_total How many times prefetch ENTERED the \
         all-breakers-open state (only state transitions count).\n\
         # TYPE ebpdns_prefetch_degraded_total counter\nebpdns_prefetch_degraded_total {dt}\n",
        ao = u8::from(s.resolver.prefetch_all_open()),
        dt = s.resolver.prefetch_degraded_total(),
    ));

    // ---- **2.1.19（F-06）**：serve-stale 直答计数（此前恒 0，与 trace 自相矛盾）----
    // 与 `/api/status.counters.stale_served` **同源**（`ServerTelemetry::stale_served`），
    // 唯一打点在 `resolve.rs::serve_stale_from_cache`（真的把过期数据发给客户端时）。
    body.push_str(&format!(
        "# HELP ebpdns_stale_served_total Answers served from the serve-stale window \
         (expired data returned to the client). Same source as /api/status.counters.stale_served.\n\
         # TYPE ebpdns_stale_served_total counter\nebpdns_stale_served_total {ss}\n",
        ss = csnap.stale_served,
    ));

    // ---- A7：逐上游请求数 + 延迟直方图/分位数 ----
    //
    // **2.1.41（字段体检修复）**：样本名必须与 HELP/TYPE 的 family 名一致。
    // 2.1.40 及以前 HELP/TYPE 声明的是 `ebpdns_upstream_requests_total_by_id`，
    // 但样本行写成了 `ebpdns_upstream_requests_total{id=...}` —— 于是：
    // ① 文档/门禁里的 `_by_id` family 永远没有样本；
    // ② 该样本挂到**聚合** family `ebpdns_upstream_requests_total` 上，
    //    `sum(ebpdns_upstream_requests_total)` 会把聚合值与逐条值相加（双计）。
    let ups = upstream_views(&s);
    if !ups.is_empty() {
        body.push_str(
            "# HELP ebpdns_upstream_requests_total_by_id Per-upstream request count.\n\
             # TYPE ebpdns_upstream_requests_total_by_id counter\n",
        );
        for u in &ups {
            let id = u.get("id").and_then(Value::as_str).unwrap_or("");
            if id.is_empty() {
                continue;
            }
            let q = u.get("queries").and_then(Value::as_u64).unwrap_or(0);
            body.push_str(&format!(
                "ebpdns_upstream_requests_total_by_id{{id=\"{}\"}} {}\n",
                prom_label_escape(id),
                q
            ));
        }
        body.push_str(
            // **2.1.20（A-20）**：`success_rate` 现在可能是 `null`（无传输样本 / 熔断中）。
            // Prometheus 没有"未知"的数值写法 ⇒ 该样本**整条不发**（`absent()` 可判定），
            // 而不是伪造 0 或 100。
            "# HELP ebpdns_upstream_success_rate Per-upstream TRANSPORT success rate percent \
             (0..100). Samples are OMITTED (absent) when there is no transport sample yet or the \
             circuit breaker is open -- it is NOT a DNS-level business success rate \
             (SERVFAIL counts as a transport success). See /api/upstreams[].success_rate.\n\
             # TYPE ebpdns_upstream_success_rate gauge\n\
             # HELP ebpdns_upstream_dns_success_rate Per-upstream DNS-BUSINESS success rate \
             percent (2.1.21 / A-17): numerator = PHYSICAL upstream answers whose rcode is \
             NOERROR or NXDOMAIN and that were not truncated (an empty answer section still \
             counts -- NXDOMAIN/NODATA are real verdicts); SERVFAIL/REFUSED/NOTIMP/FORMERR/ \
             truncated count as FAILURES here. Counted once per physical upstream answer, so \
             single-flight coalescing does NOT inflate it. Samples are OMITTED (absent) while \
             the upstream has no data-plane DNS sample. See /api/upstreams[].dns_success_rate.\n\
             # TYPE ebpdns_upstream_dns_success_rate gauge\n",
        );
        for u in &ups {
            // **2.1.21（A-17）**：DNS 业务层第二本账（与 `success_rate` 并列、**不相等**：
            // 持续 SERVFAIL 的上游在前者是 100%、在后者是 0%）。`null` → 不发该样本。
            if let Some(dsr) = u.get("dns_success_rate").and_then(Value::as_f64) {
                let id = u.get("id").and_then(Value::as_str).unwrap_or("");
                if !id.is_empty() {
                    body.push_str(&format!(
                        "ebpdns_upstream_dns_success_rate{{id=\"{}\"}} {}\n",
                        prom_label_escape(id),
                        dsr
                    ));
                }
            }
        }
        for u in &ups {
            let id = u.get("id").and_then(Value::as_str).unwrap_or("");
            if id.is_empty() {
                continue;
            }
            // `null` → 不发该样本（见上）。
            let Some(sr) = u.get("success_rate").and_then(Value::as_f64) else {
                continue;
            };
            body.push_str(&format!(
                "ebpdns_upstream_success_rate{{id=\"{}\"}} {}\n",
                prom_label_escape(id),
                sr
            ));
        }
    }

    // 逐上游延迟：累积直方图 + 分位数（数据源 = 逐上游延迟窗口，见 telemetry.rs）。
    let hists = s.telemetry.upstream_latency_histograms();
    if !hists.is_empty() {
        body.push_str(
            "# HELP ebpdns_upstream_latency_ms Upstream exchange latency in milliseconds (per upstream).\n\
             # TYPE ebpdns_upstream_latency_ms histogram\n",
        );
        for (id, count, sum, buckets, les) in &hists {
            let eid = prom_label_escape(id);
            for (i, le) in les.iter().enumerate() {
                body.push_str(&format!(
                    "ebpdns_upstream_latency_ms_bucket{{id=\"{}\",le=\"{}\"}} {}\n",
                    eid,
                    prom_le(*le),
                    buckets.get(i).copied().unwrap_or(0)
                ));
            }
            body.push_str(&format!(
                "ebpdns_upstream_latency_ms_bucket{{id=\"{}\",le=\"+Inf\"}} {}\n",
                eid, count
            ));
            body.push_str(&format!(
                "ebpdns_upstream_latency_ms_sum{{id=\"{}\"}} {:.3}\n",
                eid, sum
            ));
            body.push_str(&format!(
                "ebpdns_upstream_latency_ms_count{{id=\"{}\"}} {}\n",
                eid, count
            ));
        }
        body.push_str(
            "# HELP ebpdns_upstream_latency_ms_quantile Upstream latency quantiles from the in-process window.\n\
             # TYPE ebpdns_upstream_latency_ms_quantile gauge\n",
        );
        for (id, _c, _s, _b, _l) in &hists {
            let eid = prom_label_escape(id);
            for (q, p) in [("0.5", 50.0), ("0.9", 90.0), ("0.99", 99.0)] {
                if let Some(v) = s.telemetry.upstream_latency_quantile(id, p) {
                    body.push_str(&format!(
                        "ebpdns_upstream_latency_ms_quantile{{id=\"{}\",quantile=\"{}\"}} {:.1}\n",
                        eid, q, v
                    ));
                }
            }
        }
    }

    // ---- **2.1.48 / AUD-09**：进程内存/线程/fd + 状态缺失 part（纯 HTTP 可观测）----
    {
        let (rss, vm, threads, fds) = process_health();
        let missing_parts = s
            .state
            .store()
            .map(|st| st.missing_parts().len() as u64)
            .unwrap_or(0);
        body.push_str(&format!(
            "# HELP ebpdns_process_resident_memory_bytes Resident set size of this process \
             (Linux /proc/self/status VmRSS; 0 on unsupported platforms).\n\
             # TYPE ebpdns_process_resident_memory_bytes gauge\n\
             ebpdns_process_resident_memory_bytes {rss}\n\
             # HELP ebpdns_process_virtual_memory_bytes Virtual address space size of this process \
             (Linux /proc/self/status VmSize; 0 on unsupported platforms).\n\
             # TYPE ebpdns_process_virtual_memory_bytes gauge\n\
             ebpdns_process_virtual_memory_bytes {vm}\n\
             # HELP ebpdns_process_threads Number of OS threads in this process.\n\
             # TYPE ebpdns_process_threads gauge\n\
             ebpdns_process_threads {threads}\n\
             # HELP ebpdns_process_open_fds Number of open file descriptors of this process.\n\
             # TYPE ebpdns_process_open_fds gauge\n\
             ebpdns_process_open_fds {fds}\n\
             # HELP ebpdns_state_missing_parts Optional state parts recorded in commit.json but \
             absent on disk (0 = none). Same source as /api/status.state_persist.missing_parts.\n\
             # TYPE ebpdns_state_missing_parts gauge\n\
             ebpdns_state_missing_parts {missing_parts}\n"
        ));
    }

    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body)
}

/// Prometheus 文本格式的 label value 转义：`\` → `\\`、`"` → `\"`、换行 → `\n`
/// （RFC/Prometheus 文本格式规定的三个转义）。
///
/// 上游 id 由控制台写入（`upstreams[].id`），虽非远程不可信，但仍是**可变字符串**：
/// 未转义时一个 `"` 就能让整个 /metrics 响应变成非法文本、抓取器直接丢弃全量指标。
///
/// 注意：**不要**用 `s.contains(['\\','"','\n'])` 做快路径判断 ——
/// `str::contains` 对 `[char; N]` 实现的是 `Pattern` 的**子串**语义
/// （要求这三个字符**连续相邻**出现），而不是"含任一字符"，
/// 会让绝大多数需要转义的输入直接原样返回（本函数的 2 个单测把这个错误钉住了）。
fn prom_label_escape(s: &str) -> String {
    let needs = s.chars().any(|c| matches!(c, '\\' | '"' | '\n'));
    if !needs {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '\\' => {
                out.push('\\');
                out.push('\\');
            }
            '"' => {
                out.push('\\');
                out.push('"');
            }
            '\n' => {
                out.push('\\');
                out.push('n');
            }
            _ => out.push(ch),
        }
    }
    out
}

/// 直方图 `le` 值的 Prometheus 写法：整数不带小数点（`10` 而不是 `10.0`）；
/// 小数值保留原样。Rust 的 `{}` 对 `f64` 会输出 `10`（`Display` 省略 `.0`），
/// 这里显式保证同一形状，避免同一指标在不同上报里出现 `le="10"` / `le="10.0"` 两种桶。
fn prom_le(v: f64) -> String {
    if v.fract() == 0.0 && v.is_finite() {
        format!("{}", v as i64)
    } else {
        format!("{}", v)
    }
}

/// **[历史归因]** POST /api/rules/import：前端粘贴域名（web/src/api.rs / pages/config.rs:583；Python api.py:3017）。
/// 前端实际发 JSON `{"action","content","group","ip","wildcard"}`（键名 content，非 text）。
/// 纯文本 body 走 import_rules_text（默认 block）；JSON 按 ImportOpts 调 import_rules。
/// 回写 s.cfg["rules"] 使 GET /api/config 可见。
// >>> 242B BEGIN P0-2-sig >>> //
async fn rules_import_http(
    State(s): State<AppState>,
    Query(q): Query<std::collections::HashMap<String, String>>,
    body: String,
) -> ServerResult<Json<Value>> {
    rules_import_mode(s, q.get("mode").cloned(), body).await
}

/// 兼容入口（无 query；单测与内部调用用它 ⇒ 语义 = 默认合并）。
#[allow(dead_code)] // 生产走 rules_import_http；本入口供单测/内部调用
async fn rules_import(State(s): State<AppState>, body: String) -> ServerResult<Json<Value>> {
    rules_import_mode(s, None, body).await
}

async fn rules_import_mode(
    s: AppState,
    mode: Option<String>,
    body: String,
) -> ServerResult<Json<Value>> {
    use ebpdns_resolver::ImportOpts;
    // <<< 242B END P0-2-sig <<< //
    use std::net::IpAddr;
    // 解析 body：JSON 则读 content + 选项；纯文本走默认 block 导入。
    // >>> 242B BEGIN P0-2-body >>> //
    let mut mode = mode;
    let (content, opts) = match serde_json::from_str::<Value>(&body) {
        Ok(v) => {
            if mode.is_none() {
                mode = v.get("mode").and_then(Value::as_str).map(String::from);
            }
            // <<< 242B END P0-2-body <<< //
            let content = v
                .get("content")
                .and_then(Value::as_str)
                .or_else(|| v.get("text").and_then(Value::as_str))
                .or_else(|| v.get("rules").and_then(Value::as_str))
                .unwrap_or("")
                .to_string();
            let action = v
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or("group")
                .to_string();
            // 显式提供的 group/ip（区分"未带"与"显式空/非法"）。
            let raw_group = v.get("group");
            let raw_ip = v.get("ip");
            // **[历史归因]** 对齐 Python _validate_rule_dict：仅校验显式提供的值。
            // forceIp 显式带了 ip 但不是合法 IP → 400。
            if action == "forceIp" {
                if let Some(ij) = raw_ip {
                    let s = ij.as_str().unwrap_or("");
                    if s.parse::<IpAddr>().is_err() {
                        return Err(ServerError::BadRequest("invalid forceIp ip address".into()));
                    }
                }
            }
            // group 显式带了但为空串/非字符串 → 400。
            if action == "group" {
                if let Some(gj) = raw_group {
                    match gj.as_str() {
                        Some(g) if !g.is_empty() => {}
                        _ => return Err(ServerError::BadRequest("invalid group".into())),
                    }
                }
            }
            let mut group = raw_group.and_then(Value::as_str).map(String::from);
            let mut ip = raw_ip.and_then(Value::as_str).map(String::from);
            // **[历史归因]** 对齐 Python api.py:3033/3055：group/ip 缺省兜底。
            if action == "group" {
                group = group.or_else(|| Some("global".to_string()));
            }
            if action == "forceIp" {
                ip = ip.or_else(|| Some("1.2.3.4".to_string()));
            }
            // **[历史归因]** 对齐 Python api.py:3036：wildcard 默认 true（落 *.domain，拦裸域+子域）。
            let wildcard = v.get("wildcard").and_then(Value::as_bool).unwrap_or(true);
            (
                content,
                ImportOpts {
                    action,
                    group,
                    ip,
                    wildcard,
                },
            )
        }
        Err(_) => (
            body,
            ImportOpts {
                action: "block".to_string(),
                group: None,
                ip: None,
                wildcard: false,
            },
        ),
    };
    if content.is_empty() {
        return Err(ServerError::BadRequest("未解析到有效域名".into()));
    }
    // >>> 242B BEGIN P0-2-merge >>> //
    // ---- **2.1.42-B（P0-2）：默认合并；覆盖必须显式 ?mode=replace** ----
    //
    // 旧实现从 `resolver.config().rules`（= 启动时 `config.json.rules` 的内存副本）
    // 取"当前规则集"再回写：v3 常态下 `config.json` **没有** `rules` 镜像键
    // （2.1.22 起唯一真源是 `state/rules.json`）⇒ 内存列表为空 ⇒ 一次导入把
    // 真源覆盖成"仅本次导入"，本地规则永久丢失（P0-2）。
    //
    // 现在：
    // ① 当前本地规则一律从**真源**读（`local_rules_authoritative`，与 GET 同入口）；
    // ② 默认合并（按 match 去重，本地在前）；
    // ③ `?mode=replace`（或 body.mode）才允许整份覆盖；
    // ④ 写盘前把真源**原始字节**备份到 `<source>.pre-import.bak`；
    // ⑤ 写盘后重新从真源读条数：合并模式下少于原条数 ⇒ 拒绝并回滚原字节；
    // ⑥ 任何写盘失败也回滚原字节 + 内存 cfg + 索引（不是"导入看似成功"）。
    let replace = mode.as_deref() == Some("replace");
    let unreadable_before = crate::rules_admin::rule_source_unreadable_count();
    let existing = crate::rules_admin::local_rules_authoritative(&s);
    if crate::rules_admin::rule_source_unreadable_count() > unreadable_before {
        // 真源坏了：**不得**拿"空集"当基准去写盘（那正是 P0-2 的放大器）。
        tracing::error!("规则导入被拒绝：本地规则真源无法解析（保留原真源）");
        return Err(ServerError::Internal);
    }
    let original_count = existing.len();
    // 解析导入内容：与 resolver.import_rules 同规则（parse_domain_list + wildcard +
    // group/ip 兜底），但**不**修改 resolver 的 cfg.rules —— 只构造待合并数组。
    let nonce = s.resolver.import_nonce();
    let mut imported: Vec<Value> = Vec::new();
    for d in ebpdns_rules::parse::parse_domain_list(&content) {
        let m = if d.starts_with("*.") || d.starts_with("re:") {
            d
        } else if opts.wildcard {
            format!("*.{d}")
        } else {
            d
        };
        let mut map = Map::new();
        map.insert("match".into(), Value::String(m));
        map.insert("action".into(), Value::String(opts.action.clone()));
        map.insert(
            "id".into(),
            Value::String(format!("rmig{}_{}", nonce, imported.len() + 1)),
        );
        if let Some(g) = &opts.group {
            map.insert("group".into(), Value::String(g.clone()));
        }
        if let Some(ip) = &opts.ip {
            map.insert("ip".into(), Value::String(ip.clone()));
        }
        if let Some(map) = crate::rules_admin::normalize_rule_json(&Value::Object(map)) {
            imported.push(Value::Object(map));
        }
    }
    let n = imported.len();
    if n == 0 {
        // **[历史归因]** 对齐 Python api.py:3020-3022：未解析到有效域名 → 400。
        return Err(ServerError::BadRequest("未解析到有效域名".into()));
    }
    let merged: Vec<Value> = if replace {
        imported
    } else {
        let mut seen: std::collections::HashSet<String> = existing
            .iter()
            .filter_map(|r| r.get("match").and_then(Value::as_str))
            .map(|s| s.trim().to_string())
            .collect();
        let mut out = existing.clone();
        for r in imported {
            let key = r
                .get("match")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string();
            if seen.insert(key) {
                out.push(r);
            }
        }
        out
    };
    // 条数校验（写盘前）：合并语义下**不得**少于原有条数。
    if !replace && merged.len() < original_count {
        tracing::error!(
            before = original_count,
            after = merged.len(),
            "规则导入被拒绝：合并后条数少于原真源（未写盘）"
        );
        return Err(ServerError::Internal);
    }
    // 写盘前备份真源原始字节。
    let source = crate::rules_admin::rules_source_bytes(&s);
    if let Some((path, Some(bytes))) = &source {
        let mut bak = path.clone().into_os_string();
        bak.push(".pre-import.bak");
        if let Err(e) = crate::io_atomic::atomic_write_bytes(std::path::Path::new(&bak), bytes) {
            tracing::warn!(path = %bak.to_string_lossy(), error = %e,
                "规则导入备份写入失败（继续导入，但失败时无法逐字节回滚）");
        }
    }
    s.cfg.write()["rules"] = Value::Array(merged.clone());
    if let Err(e) = crate::rules_admin::persist_current(&s, "import").await {
        // 失败回滚：内存 cfg + 原文件字节 + 索引。
        s.cfg.write()["rules"] = Value::Array(existing.clone());
        if let Some((path, bytes)) = &source {
            match bytes {
                Some(b) => {
                    let _ = crate::io_atomic::atomic_write_bytes(path, b);
                }
                None => {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
        let _ = crate::rules_admin::rebuild_index_from_cfg(&s);
        tracing::error!("规则导入失败 ⇒ 已回滚原真源字节（本次导入未生效）: {e:?}");
        return Err(e);
    }
    // 写盘后条数校验：从**真源**重读（合并模式少于原数 ⇒ 回滚并拒绝）。
    let after = crate::rules_admin::local_rules_authoritative(&s).len();
    if !replace && after < original_count {
        s.cfg.write()["rules"] = Value::Array(existing.clone());
        if let Some((path, bytes)) = &source {
            match bytes {
                Some(b) => {
                    let _ = crate::io_atomic::atomic_write_bytes(path, b);
                }
                None => {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
        let _ = crate::rules_admin::rebuild_index_from_cfg(&s);
        tracing::error!(
            before = original_count,
            after,
            "规则导入被拒绝：落盘后条数少于原真源 ⇒ 已回滚原文件字节"
        );
        return Err(ServerError::Internal);
    }
    Ok(Json(json!({
        "ok": true,
        "added": n,
        "imported": n,
        "total": after,
        "mode": if replace { "replace" } else { "merge" },
    })))
}
// <<< 242B END P0-2-merge <<< //
async fn rules_subscribe(
    State(s): State<AppState>,
    Json(body): Json<Value>,
) -> ServerResult<Json<Value>> {
    Ok(Json(crate::subscribe::subscribe(s, body).await?))
}
async fn rules_subscribe_update(
    State(s): State<AppState>,
    Json(body): Json<Value>,
) -> ServerResult<Json<Value>> {
    Ok(Json(crate::subscribe::update(s, body).await?))
}
/// DELETE /api/rules/subscribe?url=...（body 可选；不再强制要求 JSON body，避免 415）。
async fn rules_subscribe_delete(
    State(s): State<AppState>,
    Query(q): Query<std::collections::HashMap<String, String>>,
    _body: Option<Json<Value>>,
) -> ServerResult<Json<Value>> {
    let url = q.get("url").cloned().unwrap_or_default();
    Ok(Json(crate::subscribe::delete(s, &url).await?))
}
/// 探测超时（ms）：`health_probe_timeout_ms`，缺省 2000（probe.py 用 cfg 的 timeout_ms，
/// 本任务契约固定用健康探针超时）；下限 500 防畸形小值，上限 60s 防异常配置挂死请求。
fn probe_timeout_ms(cfg: &Value) -> u64 {
    cfg.get("health_probe_timeout_ms")
        .and_then(coerce_int)
        .unwrap_or(2000)
        .clamp(500, 60_000) as u64
}

/// 重新测速的单个探测目标（探测入参与回显字段）。
struct ProbeTarget {
    id: String,
    name: String,
    proto: String,
    addr: String,
    /// 探测前配置里的静态 latency（响应里的 `old`；失败时原样保留）。
    old: u64,
    /// 探测用运行时配置（`ProductionQuerier::query_parallel` 的单元素入参）。
    cfg: UpstreamCfg,
}

/// POST /api/reprobe 的实现体（对齐 api.py:1826-1840 `_api_reprobe` + probe.py:145-217）。
///
/// **[历史归因]** - 只探测**已启用**上游（本任务契约；Python `_api_reprobe` 传 force=True 会连禁用一起测，
/// **[历史归因]**   这里按任务要求收敛为 `enabled=true`，缺省 true 与 Python `u.get("enabled", True)` 一致）；
/// - 域名固定 `www.baidu.com`、`edns=false`（probe.py:119），不做 0x20 随机化；
/// - 并发上限 8（probe.py:138 `min(8, max(1, len(ups)))`），单次探测超时取
///   `health_probe_timeout_ms`（缺省 2000，下限 500，上限 60s 防异常配置挂死请求），
///   并在每个并发槽位外再套一层 `tokio::time::timeout` 硬兜底；
/// - 成功（**有答案且未被截断**）→ `latency = max(1, int(lat_ms))`、`latency_measured = true`；
///   失败 → 保留原 `latency`、`latency_measured = false`（对齐 probe.py:144 `bool(ok)`）；
/// - 结果按 id 合并进**最新** cfg（并发删除的上游跳过，对齐 probe.py:170-198），
///   原子落盘 + `on_reload`；**写盘失败回滚内存**并返回 Err（调用方转 502），
///   避免「内存已实测、磁盘没有」的漂移；
/// - `only=Some(id)` 时只探测该上游（POST /api/upstreams 的新增后台实测复用）。
///
/// 探测路径说明：`ebpdns-server` 未依赖 `ebpdns-upstream`（Cargo.toml:9-33），无法命名
/// `UpstreamConfig`，故经 resolver 的公开生产接线 [`ProductionQuerier`] 走同一条数据面：
/// 其 `query_parallel` 内部即 `UpstreamRuntime::query`（六协议真实收发 + `HealthKeeper` 记账），
/// 单上游调用后按 id 取回「是否有答案 + 延迟毫秒」，等价于 probe.py 的 `query_upstream` 单测。
async fn reprobe_impl(s: &AppState, only: Option<&str>) -> Result<Value, String> {
    // 快照（不持锁跨 await）。
    let snapshot = s.cfg.read().clone();
    let arr = match snapshot.get("upstreams") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(a)) => a.clone(),
        Some(_) => return Err("cfg.upstreams 不是数组".into()),
    };
    let mut targets: Vec<ProbeTarget> = Vec::new();
    for u in &arr {
        let Some(obj) = u.as_object() else { continue };
        let id = obj
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if id.is_empty() {
            continue;
        }
        if let Some(only) = only {
            if id != only {
                continue;
            }
        }
        // 已启用（缺省 true）。
        let enabled = obj
            .get("enabled")
            .map(|v| as_bool_loose(v, true))
            .unwrap_or(true);
        if !enabled {
            continue;
        }
        let proto = obj
            .get("proto")
            .and_then(Value::as_str)
            .unwrap_or("udp")
            .trim()
            .to_ascii_lowercase();
        let addr = obj
            .get("addr")
            .and_then(Value::as_str)
            .or_else(|| obj.get("host").and_then(Value::as_str))
            .unwrap_or("")
            .trim()
            .to_string();
        if addr.is_empty() {
            continue;
        }
        let port = obj
            .get("port")
            .and_then(coerce_int)
            .map(|p| p.clamp(1, 65535) as u16)
            .unwrap_or_else(|| proto_default_port(&proto));
        let old = obj.get("latency").and_then(coerce_int).unwrap_or(0).max(0) as u64;
        let name = obj
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(&id)
            .to_string();
        // UpstreamCfg 以 test_up 起底 + 逐字段赋值：只依赖字段名（不要求结构字面量完整），
        // 避免与并行改动 ebpdns-resolver 的任务（如 config.rs 增字段）互相破坏编译。
        let mut rc = UpstreamCfg::test_up(&id);
        rc.name = name.clone();
        rc.proto = proto.clone();
        rc.host = addr.clone();
        rc.port = port;
        // 请求路径必须带过来：漏掉它会让 DoH/DoH3 探针打到一个不是用户配置的路径上
        // （历史上更糟：production 侧重建为完整 URL，导致 100% 误判失败）。
        rc.url = obj
            .get("url")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        rc.enabled = true;
        rc.latency = old.min(u32::MAX as u64) as u32;
        rc.weight = obj.get("weight").and_then(coerce_f64).unwrap_or(1.0);
        rc.group = obj
            .get("group")
            .and_then(Value::as_str)
            .map(|g| g.to_string());
        rc.allow_private_ip = obj
            .get("allow_private_ip")
            .map(|v| as_bool_loose(v, false))
            .unwrap_or(false);
        targets.push(ProbeTarget {
            id,
            name,
            proto,
            addr,
            old,
            cfg: rc,
        });
    }
    if targets.is_empty() {
        // **[历史归因]** Python：无待测上游直接返回空 results，且不落盘（probe.py:115-116）。
        return Ok(json!({"ok": true, "results": []}));
    }
    // 探测超时：health_probe_timeout_ms（缺省 2000，下限 500，上限 60s）。
    let timeout_ms = probe_timeout_ms(&snapshot);
    // 生产探测路径：edns=false / padding=false / 0x20=false，与 probe.py 的探测查询同型。
    let querier = s.resolver.upstream_runtime().map(|rt| {
        ProductionQuerier::new(
            rt,
            SharedCircuit::new(),
            std::sync::Arc::new(RealClock::default()),
            timeout_ms,
            false,
            1232,
            false,
            false,
        )
    });
    // 并发有界（≤8）探测；每槽位再套硬超时兜底，任何失败都不 panic。
    let mut probed: Vec<(bool, u64)> = vec![(false, 0); targets.len()];
    if let Some(q) = querier.as_ref() {
        let timeout = Duration::from_millis(timeout_ms);
        let tref: &[ProbeTarget] = &targets;
        let results: Vec<(usize, bool, u64)> = futures::stream::iter(0..targets.len())
            .map(|i| {
                // 显式复制捕获（均为 Copy）：非 move 闭包内套 `async move` 时避免
                // 「cannot move out of a captured variable」类推断歧义。
                //
                // **2.1.24**：**换名**而不是 `let q = q;`（同名的重新绑定会被
                // `clippy::redundant_redefinition_of_a_binding` 判为冗余；判据与语义不变）。
                let q_copy = q;
                let timeout_copy = timeout;
                let tref_copy = tref;
                async move {
                    let fut = q_copy.query_parallel(
                        std::slice::from_ref(&tref_copy[i].cfg),
                        PROBE_DOMAIN,
                        "A",
                        0,
                    );
                    match tokio::time::timeout(timeout_copy, fut).await {
                        Ok(rows) => match rows.first() {
                            // 成功判据：有答案且未被截断（截断响应不得冒充有效实测）。
                            Some(a) => (
                                i,
                                !a.answers.is_empty() && !a.udp_truncated,
                                a.lat.max(0.0) as u64,
                            ),
                            None => (i, false, 0),
                        },
                        Err(_) => (i, false, 0),
                    }
                }
            })
            .buffer_unordered(PROBE_MAX_CONCURRENCY)
            .collect()
            .await;
        for (i, ok, lat) in results {
            probed[i] = (ok, lat);
        }
    } else {
        tracing::warn!("重新测速：上游运行时未就绪，全部按探测失败处理（保留原 latency）");
    }
    // 响应行（按目标顺序；`new` 失败时 = 原 latency，对齐 probe.py:146/152）。
    let mut rows: Vec<Value> = Vec::with_capacity(targets.len());
    for (i, t) in targets.iter().enumerate() {
        let (ok, lat) = probed[i];
        let new_lat = if ok { lat.max(1) } else { t.old };
        rows.push(json!({
            "id": t.id,
            "name": t.name,
            "proto": t.proto,
            "addr": t.addr,
            "old": t.old,
            "new": new_lat,
            "ok": ok,
        }));
    }
    // 写回内存：按 id 合并进最新 cfg（不持锁跨 await）。
    let (before, next, applied) = {
        let mut g = s.cfg.write();
        let before = g.clone();
        let mut next = before.clone();
        let mut applied = 0usize;
        if let Some(list) = next.get_mut("upstreams").and_then(Value::as_array_mut) {
            for (i, t) in targets.iter().enumerate() {
                let (ok, lat) = probed[i];
                // 按 id 定位（并发删除的上游不在列表里 → 跳过，对齐 probe.py:180-182）。
                let pos = list
                    .iter()
                    .position(|u| u.get("id").and_then(Value::as_str) == Some(t.id.as_str()));
                if let Some(pos) = pos {
                    if let Some(o) = list[pos].as_object_mut() {
                        o.insert("latency_measured".into(), json!(ok));
                        if ok {
                            o.insert("latency".into(), json!(lat.max(1)));
                        }
                        applied += 1;
                    }
                }
            }
        }
        if applied > 0 {
            *g = next.clone();
        }
        (before, next, applied)
    };
    if applied > 0 {
        // **2.1.22**：经统一事务（或旧路径原子写）。
        if s.state.is_on() {
            if let Err(e) = crate::api_state::commit_cfg_only(s, "api:reprobe", &next).await {
                tracing::error!("重新测速提交中止（磁盘仍是上一代，内存已回滚）: {e}");
                *s.cfg.write() = before;
                return Err("reprobe persist failed".into());
            }
        } else if let Some(path) = s.cfg_path.as_ref() {
            if let Err(e) = atomic_write_json(path, &next).await {
                tracing::error!("重新测速写盘失败（已回滚内存变更）: {e}");
                *s.cfg.write() = before;
                return Err("reprobe persist failed".into());
            }
        }
        // 运行时热重载（由 binary 注册；未注册则仅持久化）。
        if let Some(hook) = s.on_reload.as_ref() {
            if let Err(e) = hook(&next) {
                tracing::warn!(
                    code = e.code,
                    detail = %e.detail,
                    "重新测速已落盘，但热重载失败（规则索引保留上一份快照）"
                );
            }
        }
    }
    Ok(json!({"ok": true, "results": rows}))
}

/// POST /api/reprobe：一键重新测速（对齐 api.py:1826-1840）。
///
/// 异常一律 502 `{"error":"reprobe failed"}`，不回显内部细节（上游 IP/端口/网络错误）。
async fn reprobe(State(s): State<AppState>) -> ServerResult<Json<Value>> {
    match reprobe_impl(&s, None).await {
        Ok(v) => Ok(Json(v)),
        Err(e) => {
            tracing::error!("reprobe failed: {e}");
            Err(ServerError::BadGateway("reprobe failed".into()))
        }
    }
}
/// POST /api/reload：把当前内存配置重新应用到 resolver，并回传本次相对
/// 「上次生效配置」发生变化的顶层键（对齐 v1.9.162 的 `changed[]`）。
async fn reload(State(s): State<AppState>) -> ServerResult<Json<Value>> {
    // **不读请求体**（对齐 v1.9.162 `_api_reload`）：此前用 `Option<Json<Value>>` 提取器，
    // 客户端带 `Content-Type: application/json` 而 body 为空/非法时 axum 会回一个
    // **裸 400（无 JSON 体）**，被误判为服务端故障（真实部署实测）。
    // 彻底不声明 body 参数 → 不触发任何 body 解析 → 任意/空 body 均返回 200。
    //
    // 另外：v1.9.162 的 `_api_reload` 是**从磁盘重读配置**再应用。我们此前只重放内存里的
    // `s.cfg`，于是「手工编辑 `/etc/ebpdns/config.json` → POST /api/reload」**不生效**
    // （真实部署实测，只能靠 restart）。这里改为优先读盘、失败才回退内存，并回报来源。
    let mut cur = s.cfg.read().clone();
    let mut source = "memory";
    if let Some(p) = s.cfg_path.as_ref() {
        match std::fs::read_to_string(p) {
            Ok(text) => match serde_json::from_str::<Value>(&text) {
                Ok(v) if v.is_object() => {
                    cur = v;
                    source = "file";
                }
                Ok(_) => tracing::warn!(
                    path = %p.display(),
                    "配置文件不是 JSON 对象 → 忽略磁盘内容，按内存配置重载"
                ),
                Err(e) => tracing::warn!(
                    path = %p.display(),
                    error = %e,
                    "配置文件解析失败 → 忽略磁盘内容，按内存配置重载"
                ),
            },
            Err(e) => tracing::warn!(
                path = %p.display(),
                error = %e,
                "配置文件读取失败 → 按内存配置重载"
            ),
        }
    }
    let mut changed = diff_top_level(&s.applied.read(), &cur);
    // **2.1.20（A-18 修复：`changed[]` 不反映规则文件变更）**：
    // 规则**确实**通过 `hook` 重新生效（审计实测 `rules_gen` 变了、`rule_hits` 有命中），
    // 但 `changed` 只比 `config.json` 的顶层键 ⇒ 返回 `[]`，前端"已重载，变更：…"会
    // **误报"无变化"**（用户以为规则没生效，其实生效了）。
    //
    // 修法：把**规则指纹**（`rule_gen`，内容+顺序敏感）纳入比较 —— 它变了就加一个
    // 合成项 `rules_file`（名字明示"独立规则文件/订阅导致的变更"）。
    //
    // 注意顺序：指纹必须在 `hook` **之后**取（hook 才重建规则索引）。
    let gen_before = s.resolver.rule_gen();
    // 内存基准同步为"刚从磁盘读到的那份"，否则后续 PUT 会把旧内存配置写回磁盘。
    *s.cfg.write() = cur.clone();
    // **2.1.49（P0）**：`on_reload` 现在返回 `Result` —— 规则真源/订阅明细非法、
    // 全部规则被拒等失败**不得**再以 200 静默成功；映射为 500 + 机读原因
    // `{"ok":false,"error":"<code>","detail":"..."}`，且**不替换旧规则索引**、
    // 不推进 `applied`（下一次 reload 仍按旧基准算 changed）。
    let mut indexed = s.resolver.rule_count();
    if let Some(hook) = s.on_reload.as_ref() {
        match hook(&cur) {
            Ok(outcome) => indexed = outcome.indexed,
            Err(e) => {
                tracing::error!(
                    code = e.code,
                    detail = %e.detail,
                    "POST /api/reload 失败 ⇒ 500（旧规则索引保留，applied 不推进）"
                );
                return Err(ServerError::InternalWith(e.body()));
            }
        }
    }
    let gen_after = s.resolver.rule_gen();
    if gen_after != gen_before && !changed.iter().any(|k| k == "rules") {
        changed.push("rules_file".to_string());
        changed.sort();
    }
    *s.applied.write() = cur;
    let unchanged = changed.is_empty();
    Ok(Json(json!({
        "ok": true,
        "changed": changed,
        "source": source,
        // **2.1.49**：成功路径保留既有字段，并补两个可机读结果字段：
        // `rules` = 重建后索引真实条数（hook 未注册时取当前值）；
        // `unchanged` = 本次没有任何变化（含规则指纹）。
        "rules": indexed,
        "unchanged": unchanged,
    })))
}

/// 顶层键差异（仅比较双方都是对象的情况；数组/标量整体比较）。
fn diff_top_level(old: &Value, new: &Value) -> Vec<String> {
    let (Some(a), Some(b)) = (old.as_object(), new.as_object()) else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for (k, v) in b {
        match a.get(k) {
            Some(prev) if prev == v => {}
            _ => out.push(k.clone()),
        }
    }
    for k in a.keys() {
        if !b.contains_key(k) {
            out.push(k.clone());
        }
    }
    out.sort();
    out.dedup();
    out
}
/// POST /api/restart：对齐 v1.9.162，必须 body `{"confirm":true}`（防误触）。
async fn restart(State(s): State<AppState>, body: Option<Json<Value>>) -> Response {
    let confirmed = body
        .and_then(|Json(v)| v.get("confirm").and_then(Value::as_bool))
        .unwrap_or(false);
    if !confirmed {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "需要请求体 {\"confirm\": true} 确认重启服务"})),
        )
            .into_response();
    }
    // 防重入：已请求则 409。
    if s.restart
        .requested
        .swap(true, std::sync::atomic::Ordering::SeqCst)
    {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "重启已在进行中"})),
        )
            .into_response();
    }
    // 给 500ms 让响应发回客户端，再由 main 触发退出码 3。
    let notif = s.restart_notify.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        notif.notify_waiters();
    });
    json_ok(json!({"ok": true, "restarting": true}))
}
/// POST /api/reset：必须 body `{"confirm":true}`（防误触）。
async fn reset(State(s): State<AppState>, body: Option<Json<Value>>) -> ServerResult<Json<Value>> {
    let confirmed = body
        .and_then(|Json(v)| v.get("confirm").and_then(Value::as_bool))
        .unwrap_or(false);
    if !confirmed {
        return Err(ServerError::BadRequest(
            "reset requires body {\"confirm\":true}".into(),
        ));
    }
    // >>> 242B BEGIN P1-8-api >>> //
    // **2.1.42-B（P1-8）**：单一入口清空**全部**运行时计数 —— telemetry、resolver
    // 的 13 个 counters（upstream_* / rfc8020_* / breaker_all_open /
    // prefetch_* / negative_single_vote_accepted …）、逐上游健康统计与顶层
    // `udp_dropped`。旧实现只调 `reset_runtime_state`（cache/rfc8020/cb）+
    // `telemetry.reset()`，上述计数器与顶层 udp_dropped 全部残留（审计 A-04）。
    s.reset_all_counters();
    // <<< 242B END P1-8-api <<< //
    Ok(Json(json!({"ok": true})))
}
async fn rules_list(State(s): State<AppState>) -> Response {
    json_ok(crate::rules_admin::rules_payload(&s))
}
async fn rules_create(
    State(s): State<AppState>,
    Json(body): Json<Value>,
) -> ServerResult<Json<Value>> {
    Ok(Json(crate::rules_admin::add_rule(s, body).await?))
}
async fn rule_update(
    State(s): State<AppState>,
    uri: Uri,
    Json(body): Json<Value>,
) -> ServerResult<Json<Value>> {
    let id = uri.path().trim_start_matches("/api/rules/").to_string();
    Ok(Json(crate::rules_admin::update_rule(s, &id, body).await?))
}
async fn rule_delete(State(s): State<AppState>, uri: Uri) -> ServerResult<Json<Value>> {
    let id = uri.path().trim_start_matches("/api/rules/").to_string();
    Ok(Json(crate::rules_admin::delete_rule(s, &id).await?))
}
async fn cache_stats(State(s): State<AppState>) -> Response {
    let summary = s.resolver.cache().summary();
    let used = summary.get("used").and_then(Value::as_u64).unwrap_or(0);
    let cap = summary.get("capacity").and_then(Value::as_u64).unwrap_or(0);
    // **2.1.18（修复项 14）**：`pct` 口径此前**没有定义**（lru 时报 0.5 而
    // used/capacity 只有 0.5%；partitioned 的 `default` 报 0.8 而权重是 0.6 ——
    // 因为那一档其实是"used / 该分区 capacity"）。现在每个分区**同时给出两个明确口径**：
    //   - `pct`：该分区已用 / **该分区容量** × 100（"这个分区有多满"）；
    //   - `pct_of_total`：该分区已用 / **总容量** × 100（"占全局多少"）。
    // 顶层 `pct` = 全局已用 / 总容量 × 100（与 `size`/`capacity` 同源）。
    let mut partitions = summary
        .get("partitions")
        .cloned()
        .unwrap_or_else(|| json!({"default": {"used": used, "capacity": cap}}));
    if let Value::Object(m) = &mut partitions {
        for v in m.values_mut() {
            if let Value::Object(pv) = v {
                let pu = pv.get("used").and_then(Value::as_u64).unwrap_or(0);
                let pc = pv.get("capacity").and_then(Value::as_u64).unwrap_or(0);
                pv.insert("pct".into(), json!(pct1(pu, pc)));
                pv.insert("pct_of_total".into(), json!(pct1(pu, cap)));
            }
        }
    }
    // **策略名**（修复项 14）：此前缺失，前端/脚本只能靠配置猜。
    let policy = s.resolver.config().cache_policy.clone();
    // ---- 落盘/恢复的**现场可见性**（2.1.19 修复项 10/15）----
    //
    // 为什么放在这里：用户反馈"重启后缓存清零"，而老实现无论"文件不存在 /
    // 权限拒绝 / 内容损坏"都是**同一个静默 return**，用户无从自证。
    // 现在把**文件现场**下发：实际路径（来自配置，不是硬编码）、是否存在、字节数、
    // mtime、距今秒数、内存条目数、以及周期落盘开关与间隔。
    // **`mtime` 不前进 = 没落盘**（可自证）。
    //
    // **2.1.19（修复项 3 / R9）**：本段抽成 `cache_persist_info(&cfg, used)`，
    // 与 `/api/status.cache.persist` **共用同一实现** —— 两处各写一遍必然漂移，
    // 而且配置页读的是 `/api/status`（2.1.19 那里没有这个字段，R9 因此做不到）。
    let persist = {
        let c = s.cfg.read();
        cache_persist_info(
            &c,
            used,
            &s.resolver
                .cache()
                .persist_stats()
                .unwrap_or_else(|| std::sync::Arc::new(ebpdns_cache::PersistStats::default())),
        )
    };
    let mut out = summary;
    if let Value::Object(ref mut m) = out {
        m.insert("size".into(), json!(used));
        m.insert("partitions".into(), partitions);
        m.insert("policy".into(), json!(policy));
        m.insert("pct".into(), json!(pct1(used, cap)));
        m.insert("persist".into(), persist);
        // **2.1.19（修复项 1）**：与 `/api/status.cache.restore_drops` **同一来源**
        // （`DnsCache::last_restore_drops`），脚本只需抓一个端点就能对账。
        let (d_expired, d_legacy, d_failed) = s.resolver.cache().last_restore_drops();
        // **2.1.43-B（P2-4）**：与 `/api/status.cache.restore_drops.window_unpersisted`
        // **同源同值**（有单测钉死）。
        let d_window = s.resolver.cache().last_restore_window_unpersisted();
        m.insert(
            "restore_drops".into(),
            json!({
                "expired": d_expired,
                "legacy": d_legacy,
                "failed": d_failed,
                "window_unpersisted": d_window,
                // 语义说明随字段一起下发，避免"到底是丢弃还是解析失败"再次被误读。
                // **必须与 `/api/status.cache.restore_drops` 逐字段相同**（有单测钉死）。
                // **2.1.43-B（P2-4）**：文案改由 `RESTORE_DROPS_NOTE` 单点提供 —— 两段手写
                // 字符串在加 `window_unpersisted` 时漏改其一，端点不一致（有单测，实测红）。
                "note": RESTORE_DROPS_NOTE,
            }),
        );
        // **单一来源**：控制台「缓存策略说明」里的数字全部由这里下发
        // （分桶数 / 默认权重 / TinyLFU 三段比例 / sketch 内存都取自 crate 常量，
        //   因此"文案与实现不一致"在结构上不可能发生；另有机器校验回归兜底）。
        m.insert(
            "policy_doc".into(),
            json!({
                "lru_shards": ebpdns_cache::lru::SHARDS,
                "default_partitions": ebpdns_cache::partitioned::DEFAULT_PARTITIONS
                    .iter()
                    .map(|(g, w)| json!({"group": g, "weight": w}))
                    .collect::<Vec<_>>(),
                "tinylfu_window_pct": ebpdns_cache::tinylfu::WINDOW_PCT_DEFAULT,
                "tinylfu_probation_pct": ebpdns_cache::tinylfu::PROBATION_PCT_DEFAULT,
                "tinylfu_protected_pct": 100
                    - ebpdns_cache::tinylfu::WINDOW_PCT_DEFAULT
                    - ebpdns_cache::tinylfu::PROBATION_PCT_DEFAULT,
                "tinylfu_sketch_bytes": ebpdns_cache::tinylfu::SKETCH_BYTES,
                "tinylfu_sketch_rows": ebpdns_cache::tinylfu::SKETCH_D,
                "tinylfu_sketch_cols": ebpdns_cache::tinylfu::SKETCH_W,
            }),
        );
    }
    json_ok(out)
}

/// **2.1.18（修复项 14）**：`used / capacity` 的百分比（`capacity == 0` ⇒ `0.0`）。
/// 保留一位小数，避免 `0.5000000001` 这类浮点噪声进 JSON。
fn pct1(used: u64, capacity: u64) -> f64 {
    if capacity == 0 {
        return 0.0;
    }
    ((used as f64) * 1000.0 / (capacity as f64)).round() / 10.0
}
/// `POST /api/profile`：**保留的公开占位端点**（本构建不提供 profiling）。
///
/// 请求/应答契约（**刻意保持，勿改**）：
/// - 只接受 JSON POST：`Content-Type: application/json` + 合法 JSON body；
/// - `GET /api/profile` → **405**（路由只注册了 `post`）；
/// - 缺 `Content-Type` 或 body 非 JSON → **415 / 400**（由 axum 的 `Json` 提取器
///   直接产出，不进本函数）。这不是缺陷，而是**方法矩阵验收门**锁定的行为；
/// - 合法请求 → `200 {"ok":true,"note":"profiling not available in this build"}`。
///
/// 换句话说：它不是一个"坏掉的端点"，而是一个**明确标注能力边界**的占位端点
/// （README「已知限制」与 `web/INTERFACE.md` 的端点表都有此说明）。
async fn profile(State(_s): State<AppState>, Json(_b): Json<Value>) -> ServerResult<Json<Value>> {
    Ok(Json(
        json!({"ok": true, "note": "profiling not available in this build"}),
    ))
}

/// 静态资源兜底（非 API 路径全部进 _serve_static 语义）。
/// **API 命名空间必须 fail-closed**：未知 `/api/*` 返回 404 JSON，绝不落到 SPA 回退，
/// 否则拼错的接口会静默返回 index.html（前端把 HTML 当 JSON 解析失败）。
async fn static_handler(State(s): State<AppState>, uri: Uri) -> Response {
    let path = uri.path();
    if path.starts_with("/api/") || path == "/api" {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response();
    }
    crate::static_assets::serve(&uri, &s.web_root).await
}

/* ---------------- 工具 ---------------- */

/// 原子写 JSON：序列化 + spawn_blocking 写临时文件 + rename（不阻塞 async runtime）。
///
/// **2.1.16（修复项 4）**：升级为崩溃安全的四步写 `write → fsync(file) → rename → fsync(dir)`。
/// 实现见 [`atomic_write_bytes`]（本函数只负责序列化后委派）。
///
/// 旧实现只有 `write + rename`：`kill -9` 后 rename 可能已生效而数据仍在 page cache，
/// 目标文件随即变成 0 字节 / 半截 JSON（`rules.json` / `config.json` 同样受影响）。
/// **2.1.36（D 批）**：不再与 `crates/ebpdns/src/main.rs::write_json_atomic` 各留一份，
/// 两者都委派到 `ebpdns-fs` 的唯一实现（本文件保留 async/`spawn_blocking` 适配层）。
async fn atomic_write_json(path: &std::path::Path, v: &Value) -> std::io::Result<()> {
    let body = serde_json::to_vec_pretty(v)?;
    atomic_write_bytes(path, &body).await
}

/// **2.1.20（A-06 二次修复）**：把**任意字节**按同一套四步写
/// `write → fsync(file) → rename → fsync(dir)` 协议原子写回。
///
/// 用途：`PUT /api/config` 回滚时**逐字节还原**原文件 —— 不重新序列化 ⇒ 既不会引入
/// 键顺序差异，也不会把 `migrate_cfg` 注入的键（`rule_sub_file` 等）写进磁盘，
/// 于是"5xx ⇒ `config.json` 逐字节未变"这条不变量才真正成立。
///
/// [`atomic_write_json`] 序列化后**委派到本函数**，因此两者共用同一份 fsync 实现
/// （`s4_atomic_write_json_uses_fsync_and_leaves_no_tmp` 覆盖）。
///
/// **2.1.36（D 批）**：四步协议收敛到 [`crate::io_atomic::atomic_write_bytes_opts`]；
/// tmp 名逐字保留 `config.json.tmp`，失败不清理（既有语义）。
async fn atomic_write_bytes(path: &std::path::Path, body: &[u8]) -> std::io::Result<()> {
    let body = body.to_vec();
    let path_owned = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        let opts = crate::io_atomic::WriteOptions::json_tmp();
        crate::io_atomic::atomic_write_bytes_opts(&path_owned, &body, &opts)
    })
    .await
    .map_err(|e| std::io::Error::other(e.to_string()))?
}

/// 在已绑定的 TcpListener 上提供 HTTP 服务（收束 axum::serve 到本 crate，避免 binary 直接依赖 axum）。
pub async fn serve_http(app: Router, listener: tokio::net::TcpListener) -> std::io::Result<()> {
    axum::serve(listener, app).await
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    /// **2.1.29**：`web/INTERFACE.md` 的 `/api/status` 顶层键清单必须与**实际响应**
    /// 逐键一致（文档字段 == 实际响应键集合）。清单维护在
    /// `<!-- STATUS_KEYS_BEGIN --> … <!-- STATUS_KEYS_END -->` 之间。
    #[tokio::test]
    async fn status_doc_keys_match_actual_response() {
        use axum::extract::State;
        use axum::response::IntoResponse;
        use std::collections::BTreeSet;

        let resp = status(State(test_state())).await.into_response();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        let actual: BTreeSet<String> = v
            .as_object()
            .expect("status 必须是 JSON 对象")
            .keys()
            .cloned()
            .collect();

        let doc = include_str!("../../../web/INTERFACE.md");
        let block = doc
            .split("<!-- STATUS_KEYS_BEGIN -->")
            .nth(1)
            .expect("INTERFACE.md 缺 STATUS_KEYS_BEGIN")
            .split("<!-- STATUS_KEYS_END -->")
            .next()
            .expect("INTERFACE.md 缺 STATUS_KEYS_END");
        let expected: BTreeSet<String> = block
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();
        assert_eq!(
            actual, expected,
            "INTERFACE.md 的 /api/status 键清单与实际响应不一致（文档/实现必须逐键同步）"
        );
        for gone in ["bpf", "ebpf", "kernel_cache"] {
            assert!(!actual.contains(gone), "2.1.29 已删除顶层键 `{gone}`");
        }
    }

    /// **2.1.29**：删掉 `counters.kernel_direct` 后，计数器块的硬等式仍逐条成立。
    #[tokio::test]
    async fn status_counters_invariants_after_kernel_direct_removal() {
        use crate::telemetry::ServerTelemetry;
        use axum::extract::State;
        use axum::response::IntoResponse;
        use ebpdns_resolver::telemetry::Telemetry;

        let st = test_state();
        for (rcode, cat) in [(0u8, "hit"), (0, "hit"), (3, "miss"), (2, "miss")] {
            <ServerTelemetry as Telemetry>::count_query(&st.telemetry, cat);
            st.telemetry.note_data_plane_outcome(Some(rcode), None, 0);
        }
        let resp = status(State(st)).await.into_response();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        let c = v["counters"].as_object().expect("counters 对象");
        assert!(
            !c.contains_key("kernel_direct"),
            "counters.kernel_direct 必须已删除"
        );
        let total = c["total"].as_u64().unwrap();
        let sum_rcode: u64 = c["client_rcode"]
            .as_object()
            .unwrap()
            .values()
            .filter_map(Value::as_u64)
            .sum();
        assert_eq!(total, sum_rcode, "total ≡ Σ client_rcode");
        assert!(
            c["hit"].as_u64().unwrap() + c["miss"].as_u64().unwrap() <= total,
            "hit + miss ≤ total"
        );
        assert!(v["hit_rate"].as_f64().unwrap() <= 100.0, "hit_rate ≤ 100");
        assert_eq!(
            c["cache_direct"], c["hit"],
            "cache_direct ≡ hit（三端点同源）"
        );
        assert!(
            c["servfail_total"].as_u64().unwrap() >= 1,
            "SERVFAIL 已计入"
        );
    }
    fn ev(seq: u64, ts: f64, domain: &str, qtype: &str, lat: f64) -> Value {
        json!({"seq": seq, "ts": ts, "domain": domain, "qtype": qtype,
               "answer": "1.2.3.4", "upstream": "u1", "rule": "", "lat": lat})
    }

    #[test]
    fn logs_next_seq_incremental() {
        let events = vec![
            ev(1, 100.0, "a.com", "A", 1.0),
            ev(2, 101.0, "b.com", "A", 2.0),
        ];
        let p = LogsQuery {
            next_seq: Some(2),
            since: None,
            since_ts: None,
            q: None,
            level: None,
            domain: None,
            qtype: None,
            ip: None,
            answer: None,
            upstream: None,
            rule: None,
            min_lat: None,
            limit: None,
        };
        let out = filter_events(events, &p);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["seq"], json!(2));
    }

    #[test]
    fn logs_since_timestamp_cursor() {
        let events = vec![
            ev(1, 100.0, "a.com", "A", 1.0),
            ev(2, 200.0, "b.com", "A", 2.0),
        ];
        // since 是**序号**游标（u64）；时间戳游标是 since_ts（f64）。原字面量把
        // 150.0 传给 u64 的 since，既类型不匹配也测不出「时间戳游标」语义。
        let p = LogsQuery {
            next_seq: None,
            since: None,
            since_ts: Some(150.0),
            q: None,
            level: None,
            domain: None,
            qtype: None,
            ip: None,
            answer: None,
            upstream: None,
            rule: None,
            min_lat: None,
            limit: None,
        };
        let out = filter_events(events, &p);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["seq"], json!(2));
    }

    #[test]
    fn logs_filters_qtype_and_min_lat() {
        let events = vec![
            ev(1, 100.0, "a.com", "A", 1.0),
            ev(2, 101.0, "b.com", "AAAA", 50.0),
        ];
        let p = LogsQuery {
            next_seq: None,
            since: None,
            since_ts: None,
            q: None,
            level: None,
            domain: None,
            qtype: Some("aaaa".into()),
            ip: None,
            answer: None,
            upstream: None,
            rule: None,
            min_lat: Some(10.0),
            limit: None,
        };
        let out = filter_events(events, &p);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["seq"], json!(2));
    }

    #[test]
    fn writable_keys_exclude_readonly_segments() {
        for k in ["listen", "api", "web_root"] {
            assert!(!CFG_WRITABLE.contains(&k), "{k} must be read-only");
        }
        // 冻结全集抽样。
        for k in [
            "cache_partitions",
            "cache_direct_enabled",
            "speed_interval_ms",
            "edns_client_subnet",
            "health_probe_domain",
            "bootstrap_dns",
            "rule_sub_interval",
        ] {
            assert!(CFG_WRITABLE.contains(&k), "missing frozen key {k}");
        }
    }

    #[test]
    fn desensitize_masks_token() {
        let v = json!({"api": {"token": "secret123"}, "upstreams": []});
        let out = desensitize(&v);
        assert_eq!(out["api"]["token"], json!("***"));
    }

    /* ================= **2.1.26（B2：`/api/config` 去深拷贝）** ================= */

    /// 2.1.25 的参考实现（**逐字照抄**，不要"顺手优化"这里）：深拷贝脱敏 → 覆盖 `rules`
    /// → 序列化。B2 的断言全部拿它当参照物。
    fn legacy_get_config_body(cfg: &Value, rules: Value) -> Vec<u8> {
        let mut out = desensitize(cfg);
        if let Value::Object(ref mut m) = out {
            m.insert("rules".into(), rules);
        }
        serde_json::to_vec(&out).expect("legacy body")
    }

    /// **2.1.26（B2）**：借用式 [`Redacted`] 与 2.1.25 的 `desensitize` **逐字节等价**。
    ///
    /// 覆盖：嵌套对象、数组、`token/secret/password/passwd` 四类键名（大小写不敏感）、
    /// **非字符串值不打码**（数字/布尔/对象/数组）、空对象、非对象顶层。
    #[test]
    fn redacted_streaming_equals_desensitize_bytes() {
        // `[Value; 7]`（而不是 `vec![]`）：长度固定，且 `clippy::useless_vec` 在
        // `--all-targets -D warnings` 下会把 `vec!` 判成错误（2.1.26 实测）。
        let cases = [
            json!({}),
            json!({"api": {"token": "s3cr3t"}, "upstreams": []}),
            json!({
                "auth": {"Password": "p", "client_secret": "s", "passwd_file": "/x", "Token": "t"},
                "nums": {"token": 5, "secret": true, "password": null, "passwd": ["a", {"token": "b"}]},
                "nested": [{"deep": {"api_token": "z"}}, "plain", 7, null],
                "RULE_SUBSCRIPTIONS": [{"url": "https://x.invalid/a", "auth_token": "aaa"}],
            }),
            json!([1, {"api_token": "x"}, "s", {"n": {"secret": "y"}}]),
            json!("scalar"),
            json!(42),
            json!(null),
        ];
        for (i, cfg) in cases.iter().enumerate() {
            let now = serde_json::to_vec(&Redacted(cfg)).expect("streaming body");
            let old = serde_json::to_vec(&desensitize(cfg)).expect("legacy body");
            assert_eq!(
                now, old,
                "case {i}: 借用式脱敏必须与 2.1.25 的 desensitize 逐字节相同"
            );
            let parsed: Value = serde_json::from_slice(&now).expect("json");
            assert_eq!(&parsed, &desensitize(cfg), "case {i}: 解析后语义相同");
        }
    }

    /// **2.1.26（B2）**：`GET /api/config` 的响应体必须与 2.1.25 的"深拷贝 + 覆盖"**逐字节**相同。
    ///
    /// 判据覆盖三条最容易漂移的性质：
    /// ① 键序（`serde_json::Map` = `BTreeMap` ⇒ 字母序；`rules` 必须插到字母序的位置）；
    /// ② `rules` 的值**不脱敏**（旧实现先脱敏、随后被派生视图覆盖）；
    /// ③ 镜像键在 / 不在（后者走派生视图）这两种形态。
    #[test]
    fn config_get_view_is_byte_identical_to_2_1_25_snapshot() {
        // ---- ① 镜像键在（出厂模板形态）+ 密钥 + 围绕 "rules" 字母序的邻居键 ----
        let cfg = json!({
            "api": {"token": "tok-abc", "port": 8353, "host": "127.0.0.1"},
            "cache_size": 131072,
            "rule_sub_interval": 3600,
            "rule_subscriptions": [{"id": "s1", "url": "https://example.invalid/l", "interval_s": 3600}],
            "rules": [{"id": "r1", "match": "a.example", "action": "block"}],
            "rules_shadow_ext": {"note": "sorts after rules"},
            "upstreams": [{"id": "u1", "proto": "doh3", "url": "https://1.1.1.1/dns-query"}],
        });
        let mirror = cfg["rules"].clone();
        let now = serde_json::to_vec(&ConfigGetView {
            cfg: &cfg,
            rules: None,
        })
        .expect("streaming body");
        let old = legacy_get_config_body(&cfg, mirror.clone());
        assert_eq!(now, old, "镜像键在：响应字节必须与 2.1.25 逐位相同");
        let text = String::from_utf8(now).expect("utf8");
        let at = |needle: &str| text.find(needle).unwrap_or_else(|| panic!("{needle}"));
        assert!(
            at("\"rule_sub_interval\"") < at("\"rules\"")
                && at("\"rules\"") < at("\"rules_shadow_ext\""),
            "rules 必须落在字母序位置（rule_sub_interval < rules < rules_shadow_ext）"
        );
        assert!(
            text.contains("\"rules\":[{\"action\":\"block\""),
            "rules 不得脱敏"
        );

        // ---- ② 镜像键不在 ⇒ 派生视图（`rules` 必须仍出现在字母序位置）----
        let cfg2 = json!({
            "aaa": 1,
            "cache_size": 262144,
            "rule_subscriptions": [],
            "zzz": {"token": "t2"},
        });
        let derived = json!([{"id": "r9", "match": "b.example", "action": "allow"}]);
        let now2 = serde_json::to_vec(&ConfigGetView {
            cfg: &cfg2,
            rules: Some(derived.clone()),
        })
        .expect("streaming body 2");
        let old2 = legacy_get_config_body(&cfg2, derived);
        assert_eq!(now2, old2, "镜像键不在：响应字节必须与 2.1.25 逐位相同");

        // ---- ③ 非对象 cfg ⇒ 没有 rules 键（与旧实现的 `Value::Array` 分支同型）----
        let cfg3 = json!([{"token": "t3"}, 1]);
        let now3 = serde_json::to_vec(&ConfigGetView {
            cfg: &cfg3,
            rules: Some(json!([])),
        })
        .expect("streaming body 3");
        let old3 = serde_json::to_vec(&desensitize(&cfg3)).expect("legacy body 3");
        assert_eq!(now3, old3, "非对象 cfg：与旧实现同型（无 rules 键）");
    }

    /// **2.1.26（B2）**：走**真实 handler** 的两条形态（镜像键在 / 不在）都不得改变
    /// 可观测结果 —— 状态码 200、`rules` 恒为数组、脱敏生效、其余键逐位保留。
    #[tokio::test]
    async fn get_config_handler_two_shapes_are_unchanged() {
        // ① 镜像键在（出厂模板就是 `"rules": []` ⇒ 走**零克隆**那条分支）
        let st = test_state_with_answer("u1");
        let cfg = json!({
            "api": {"token": "tok-abc", "port": 8353},
            "cache_size": 131072,
            "rule_subscriptions": [{"id": "s1", "url": "https://example.invalid/l", "interval_s": 3600}],
            "rules": [{"id": "r1", "match": "a.example", "action": "block"}],
            "upstreams": [{"id": "u1", "proto": "doh3", "url": "https://1.1.1.1/dns-query"}],
        });
        *st.cfg.write() = cfg.clone();
        let resp = get_config(State(st.clone())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body");
        assert_eq!(
            body.as_ref(),
            legacy_get_config_body(&cfg, cfg["rules"].clone()).as_slice(),
            "镜像键在：handler 响应必须与 2.1.25 逐位相同"
        );
        let got: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(got["api"]["token"], json!("***"), "脱敏必须仍然生效");
        assert_eq!(got["rules"], cfg["rules"], "rules 不脱敏（与 2.1.25 相同）");
        assert_eq!(got["cache_size"], json!(131072));
        assert_eq!(
            got["rule_subscriptions"][0]["url"],
            json!("https://example.invalid/l")
        );

        // ② 镜像键被迁移删除 ⇒ 派生视图（`cfg_path=None` ⇒ 无真源文件 ⇒ `[]`）
        let mut st2 = test_state_with_answer("u1");
        *st2.cfg.write() = json!({"cache_size": 262144, "upstreams": []});
        st2.cfg_path = None;
        let resp2 = get_config(State(st2.clone())).await;
        assert_eq!(resp2.status(), StatusCode::OK);
        let body2 = axum::body::to_bytes(resp2.into_body(), usize::MAX)
            .await
            .expect("body2");
        let got2: Value = serde_json::from_slice(&body2).expect("json2");
        assert!(
            got2["rules"].is_array(),
            "/api/config.rules 必须恒为数组（空则 []），实际 {}",
            got2["rules"]
        );
        assert_eq!(got2["cache_size"], json!(262144));
        // 键序：`rules` 落在字母序位置（cache_size < rules < upstreams）
        let text2 = String::from_utf8(body2.to_vec()).expect("utf8");
        let at2 = |needle: &str| text2.find(needle).unwrap_or_else(|| panic!("{needle}"));
        assert!(
            at2("\"cache_size\"") < at2("\"rules\"") && at2("\"rules\"") < at2("\"upstreams\"")
        );
    }

    /// 生产规模的配置（79 键 / 22 条上游 / 1 条规则订阅 / 若干规则），供微基准使用。
    ///
    /// 不读盘、不依赖 fixture 文件：形状与出厂模板同型，`serde_json` 序列化后约 8–10 KB
    /// （= 真实生产 `config.json` 的量级）。
    fn bench_config(n_up: usize, n_rules: usize) -> Value {
        let mut m = Map::new();
        m.insert("config_version".into(), json!(3));
        m.insert("api_port".into(), json!(8353));
        m.insert("api_host".into(), json!("127.0.0.1"));
        m.insert("cache_size".into(), json!(131072));
        m.insert("cache_policy".into(), json!("tinylfu"));
        m.insert("cache_partitions".into(), json!(8));
        m.insert("upstreams".into(), json!([]));
        m.insert("rules".into(), json!([]));
        let mut ups = Vec::with_capacity(n_up);
        for i in 0..n_up {
            ups.push(json!({
                "id": format!("up-{i:02}"),
                "name": format!("上游 {i}"),
                "proto": if i % 3 == 0 { "doh3" } else if i % 3 == 1 { "doh" } else { "udp" },
                "host": format!("10.0.0.{}", i + 1),
                "port": 53,
                "url": format!("https://upstream-{i}.example.invalid/dns-query"),
                "enabled": i % 2 == 0,
                "latency": 10 + i,
                "weight": 1.0,
                "group": Value::Null,
                "allow_private_ip": false,
            }));
        }
        m.insert("upstreams".into(), Value::Array(ups));
        let mut rules = Vec::with_capacity(n_rules);
        for i in 0..n_rules {
            rules.push(json!({
                "id": format!("r{i:02}"),
                "match": format!("host-{i}.example.invalid"),
                "action": "block",
                "note": "微基准用规则（形状与 /api/rules 一致）",
            }));
        }
        m.insert("rules".into(), Value::Array(rules));
        m.insert(
            "rule_subscriptions".into(),
            json!([{
                "id": "sub-1",
                "url": "https://example.invalid/rules.txt",
                "interval_s": 3600,
                "enabled": true,
                "auth_token": "tok-should-be-redacted",
            }]),
        );
        // 其余标量键（凑到 79 键的量级；形状不重要，只影响配置体积）
        let scalars = [
            ("udp_workers", json!(8)),
            ("tcp_workers", json!(4)),
            ("single_flight", json!(true)),
            ("warmup", json!(true)),
            ("speed_interval_ms", json!(60000)),
            ("health_probe_domain", json!("health.example.invalid")),
            ("bootstrap_dns", json!(["1.1.1.1:53", "8.8.8.8:53"])),
            ("edns_client_subnet", json!("")),
            ("rebind_protection", json!(true)),
            ("dnssec", json!(false)),
            ("log_level", json!("info")),
            ("state_persist", json!(true)),
            ("state_dir", json!("/var/lib/ebpdns/state")),
            ("listen", json!(["0.0.0.0:53", "[::]:53"])),
        ];
        for (k, v) in scalars {
            m.insert(k.to_string(), v);
        }
        // 用可预测的填充键凑到 79 个顶层键（配置体积的主要来源仍是 upstreams/rules）。
        let mut filler = 0;
        while m.len() < 79 {
            m.insert(format!("x_filler_{filler:03}"), json!(filler));
            filler += 1;
        }
        Value::Object(m)
    }

    /// **2.1.26（B2）同进程微基准**：`GET /api/config` 的两种构造方式。
    ///
    /// A = 2.1.25：`desensitize` 建整棵新树 + `insert("rules")` + 序列化；
    /// B = 2.1.26：借用式 `ConfigGetView` 直接序列化（**不建树、不克隆**）。
    ///
    /// 显式运行：
    /// `cargo test --release -p ebpdns-server --lib bench_get_config -- --ignored --nocapture`
    #[test]
    #[ignore = "微基准：需显式 --ignored --nocapture 运行"]
    fn bench_get_config_legacy_vs_borrowed() {
        use std::time::Instant;
        for (label, n_up, n_rules) in [
            ("template(22 up/0 rules)", 22, 0),
            ("prod(22 up/20 rules)", 22, 20),
        ] {
            let cfg = bench_config(n_up, n_rules);
            let bytes = serde_json::to_vec(&cfg).expect("cfg").len();
            let mirror = cfg["rules"].clone();
            let n = 5000;
            let mut ta = Vec::with_capacity(n);
            let mut tb = Vec::with_capacity(n);
            for _ in 0..n {
                let t0 = Instant::now();
                std::hint::black_box(legacy_get_config_body(&cfg, mirror.clone()));
                ta.push(t0.elapsed().as_nanos() as f64 / 1000.0);

                let t1 = Instant::now();
                std::hint::black_box(
                    serde_json::to_vec(&ConfigGetView {
                        cfg: &cfg,
                        rules: None,
                    })
                    .expect("body"),
                );
                tb.push(t1.elapsed().as_nanos() as f64 / 1000.0);
            }
            let pct = |v: &mut Vec<f64>, p: f64| {
                v.sort_by(|a, b| a.partial_cmp(b).unwrap());
                let k = ((v.len() - 1) as f64 * p / 100.0) as usize;
                v[k.min(v.len() - 1)]
            };
            let (a50, a99, b50, b99) = (
                pct(&mut ta, 50.0),
                pct(&mut ta, 99.0),
                pct(&mut tb, 50.0),
                pct(&mut tb, 99.0),
            );
            println!(
                "\n[B2/get_config {label}] cfg={bytes}B keys=79 iters={n}\n  \
                 A 深拷贝+建树 : p50={a50:8.2}us p99={a99:8.2}us\n  \
                 B 借用式序列化 : p50={b50:8.2}us p99={b99:8.2}us\n  \
                 ratio(p50) = {:.2}x  (B 相对 A 省 {:.1}%)",
                if b50 > 0.0 { a50 / b50 } else { 0.0 },
                if a50 > 0.0 {
                    (a50 - b50) / a50 * 100.0
                } else {
                    0.0
                }
            );
        }
    }

    /// **2.1.18（修复项 7）**：可写键 + 只读键必须构成 `default_config()` 顶层键的
    /// **完备划分**（不相交、无遗漏）。
    ///
    /// 这是防"再次漂移"的门禁：2.1.16 新增了 `single_flight`/`udp_workers`/`warmup`
    /// 等键却**没有**加进 `CFG_WRITABLE`，结果这些功能在控制台上**不可达**
    /// （保存时被归入 `ignored_keys`，用户以为"改了但没生效/丢了"）。
    /// 本测试以**根 Cargo.toml 同源的 `default_config()`** 为参照物：
    /// 任何新增配置键若既不可写也不在只读表里，就会红。
    #[test]
    fn cfg_writable_covers_all_default_top_level_keys() {
        let dft: Vec<&str> = ebpdns_resolver::config::CONFIG_TOP_LEVEL_KEYS.to_vec();
        let w: std::collections::HashSet<&str> = CFG_WRITABLE.iter().copied().collect();
        let ro: std::collections::HashSet<&str> = CFG_READONLY.iter().copied().collect();
        // ① 两表不相交（同一个键不能既"可写"又"只读"）。
        // **2.1.24**：`for k in w.intersection(&ro) { panic!(…) }` 触 `clippy::never_loop`
        // （deny-by-default ⇒ 整个 `--all-targets` clippy 直接编译失败）。改成
        // `if let Some(k) = …next()`：判据完全相同（"交集非空 ⇒ 红"），且不再有"永不循环"。
        if let Some(k) = w.intersection(&ro).next() {
            panic!("键 `{k}` 同时出现在 CFG_WRITABLE 与 CFG_READONLY");
        }
        // ② `default_config()` 的每个顶层键都必须被归类。
        let mut uncategorized: Vec<&str> = dft
            .iter()
            .copied()
            .filter(|k| !w.contains(k) && !ro.contains(k))
            .collect();
        uncategorized.sort_unstable();
        assert!(
            uncategorized.is_empty(),
            "以下顶层配置键既不可写也不在只读表 ⇒ 控制台不可达且会被误报为『忽略』：{uncategorized:?}"
        );
        // ③ 只读表里不得出现不存在的键（拼错/过期）。
        let dset: std::collections::HashSet<&str> = dft.iter().copied().collect();
        let mut bogus: Vec<&str> = CFG_READONLY
            .iter()
            .copied()
            .filter(|k| !dset.contains(k))
            .collect();
        bogus.sort_unstable();
        assert!(bogus.is_empty(), "CFG_READONLY 含非配置键：{bogus:?}");
    }

    /// **2.1.18（修复项 7）**：`ignored_keys` 与 `readonly_keys` **分桶正确**，
    /// 且白名单内的键确实写入磁盘与内存。
    ///
    /// 用户实测的提示语是
    /// `配置已保存; 忽略未保存的键: config_version, hedge_slowest_factor, rating_sr_floor,
    ///  rfc8020_infer, rfc8020_max_labels, rule_local_file, rule_sub_file, single_flight,
    ///  udp_workers, warmup`
    /// —— 其中前 8 项是**只读/服务端管理**项（混进"忽略"里让人以为保存有损），
    /// 后 2 项（`single_flight` / `udp_workers` / `warmup`）当时**根本不可写**。
    #[tokio::test]
    async fn put_config_buckets_readonly_and_ignored_and_writes_whitelisted() {
        use axum::extract::State;
        let dir = std::env::temp_dir().join(format!(
            "ebpdns_api_cfgbuckets_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let mut state = test_state();
        state.cfg_path = Some(dir.join("config.json"));

        // 前端 act_save 的真实形状：整份配置回传（含只读项与服务端管理项）。
        let body = json!({
            "single_flight": false,
            "udp_workers": 4,
            "warmup": {"enabled": false, "queries": 5, "timeout_ms": 1200},
            "rfc8020_infer": false,
            "rfc8020_max_labels": 4,
            "rating_sr_floor": 0.25,
            "hedge_slowest_factor": 1.5,
            "config_version": 2,
            "rule_local_file": "/etc/passwd",
            "rule_sub_file": "/etc/shadow",
            "listen": {"udp": "0.0.0.0:53"},
            "totally_unknown_key_218": 1,
        });
        let out = put_config(State(state.clone()), test_parts(), Json(body))
            .await
            .expect("合法提交必须成功");
        let v = out.0.clone();

        // ① 可写键一个都不得出现在 ignored/readonly 里。
        for k in [
            "single_flight",
            "udp_workers",
            "warmup",
            "rfc8020_infer",
            "rfc8020_max_labels",
            "rating_sr_floor",
            "hedge_slowest_factor",
        ] {
            let ig = v["ignored_keys"].as_array().unwrap();
            let ro = v["readonly_keys"].as_array().unwrap();
            assert!(
                !ig.iter().any(|x| x.as_str() == Some(k)),
                "可写键 {k} 不得进 ignored_keys: {v}"
            );
            assert!(
                !ro.iter().any(|x| x.as_str() == Some(k)),
                "可写键 {k} 不得进 readonly_keys: {v}"
            );
            assert!(
                v["written_keys"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|x| x.as_str() == Some(k)),
                "可写键 {k} 必须出现在 written_keys: {v}"
            );
        }
        // ② 只读桶：只读/服务端管理项（含 config_version 与两个路径键）。
        let ro: Vec<&str> = v["readonly_keys"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        for k in [
            "config_version",
            "rule_local_file",
            "rule_sub_file",
            "listen",
        ] {
            assert!(
                ro.contains(&k),
                "`{k}` 必须进 readonly_keys（只读桶）：{ro:?}"
            );
        }
        // 每个只读项都必须带原因（前端只读区逐条展示）。
        for d in v["readonly_detail"].as_array().unwrap() {
            assert!(
                d.get("reason")
                    .and_then(Value::as_str)
                    .map(|s| !s.is_empty())
                    == Some(true),
                "只读项必须给出原因：{d}"
            );
        }
        // ③ 真正的未知键才进 ignored_keys。
        let ig: Vec<&str> = v["ignored_keys"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(ig, vec!["totally_unknown_key_218"], "ignored 只应含未知键");
        // ④ 内存已生效（可写键写入）。
        {
            let cfg = state.cfg.read();
            assert_eq!(cfg["single_flight"], json!(false));
            assert_eq!(cfg["udp_workers"], json!(4));
            assert_eq!(cfg["warmup"]["queries"], json!(5));
            assert_eq!(cfg["hedge_slowest_factor"], json!(1.5));
        }
        // ⑤ 磁盘已生效 + 只读键**原值不变**（恶意路径不得被写进去）。
        let on_disk: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap())
                .unwrap();
        assert_eq!(on_disk["single_flight"], json!(false));
        assert_eq!(on_disk["udp_workers"], json!(4));
        assert_ne!(
            on_disk["rule_local_file"],
            json!("/etc/passwd"),
            "只读路径键绝不能被控制台改写（越权读写风险）"
        );
        assert_ne!(on_disk["rule_sub_file"], json!("/etc/shadow"));
        // ⑥ 白名单快照随响应下发（前端可自检控件覆盖）。
        assert!(
            v["writable_keys"]
                .as_array()
                .unwrap()
                .iter()
                .any(|x| x.as_str() == Some("single_flight")),
            "writable_keys 快照必须包含新键"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **2.1.18（修复项 7）**：写路径的取值校验 —— 非法值必须 `400`，
    /// 且**不产生任何副作用**（不写盘、不改内存）。
    #[tokio::test]
    async fn put_config_rejects_out_of_range_values_without_side_effects() {
        use crate::error::ServerError;
        use axum::extract::State;
        let dir = std::env::temp_dir().join(format!(
            "ebpdns_api_cfgval_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let mut state = test_state();
        state.cfg_path = Some(dir.join("config.json"));
        let before = state.cfg.read().clone();

        // 逐个非法值：都必须 400，且内存不变。
        for bad in [
            json!({"udp_workers": 999}),
            json!({"rfc8020_max_labels": 0}),
            json!({"rating_sr_floor": 0}),
            json!({"rating_sr_floor": 2.0}),
            json!({"hedge_slowest_factor": -1.0}),
            json!({"warmup": {"enabled": true, "queries": 99, "timeout_ms": 100}}),
            json!({"warmup": "on"}),
            json!({"single_flight": "yes"}),
            json!({"rfc8020_infer": 1}),
            json!({"cache_size": 1}),
        ] {
            let err = put_config(State(state.clone()), test_parts(), Json(bad.clone()))
                .await
                .expect_err(&format!("非法值必须被拒：{bad}"));
            assert!(
                matches!(err, ServerError::BadRequest(_)),
                "必须是 400（BadRequest）：{bad} → {err:?}"
            );
            assert_eq!(
                *state.cfg.read(),
                before,
                "被拒的提交**不得**修改内存配置：{bad}"
            );
            assert!(
                !dir.join("config.json").exists(),
                "被拒的提交**不得**写盘：{bad}"
            );
        }
        // 合法边界值必须被接受（防止校验过严把功能又堵上）。
        let ok = put_config(
            State(state.clone()),
            test_parts(),
            Json(
                json!({"udp_workers": 0, "rfc8020_max_labels": 127, "rating_sr_floor": 1.0,
                        "hedge_slowest_factor": 0.001,
                        "warmup": {"enabled": true, "queries": 8, "timeout_ms": 60000}}),
            ),
        )
        .await
        .expect("边界合法值必须被接受");
        assert_eq!(ok.0["ok"], json!(true));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 回归（R18）：`PUT /api/config` 带 `rules` 时必须同步**独立规则文件**
    /// 并重建索引。
    ///
    /// 修复前：PUT 只写 `config.json`，`rules_local.json`（索引与 `GET /api/rules`
    /// 的权威来源）保持旧内容 —— 实测「配置页删掉一条规则 → 列表仍显示、dig 仍命中
    /// NXDOMAIN」（config.json 2 条 / rules_local.json 3 条 / pipeline.rules=3）。
    #[tokio::test]
    async fn put_config_rules_syncs_local_rules_file_and_index() {
        use axum::extract::State;
        let dir = std::env::temp_dir().join(format!(
            "ebpdns_api_putcfg_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let mut state = test_state();
        state.cfg_path = Some(dir.join("config.json"));

        // ① 新增一条 block 规则（前端 act_save 形状：rules[] 全量回传，带 id）。
        let body = json!({"cache_size": 131072, "rules": [
            {"id": "rmig1", "match": "del217.example", "match_raw": "del217.example",
             "action": "block", "group": "domestic", "ip": ""}
        ]});
        let out = put_config(State(state.clone()), test_parts(), Json(body))
            .await
            .expect("put 1");
        assert_eq!(out.0["ok"], json!(true));
        assert_eq!(crate::rules_admin::rules_payload(&state)["total"], json!(1));
        assert!(
            state.resolver.match_rule("del217.example").is_some(),
            "索引已生效"
        );
        let file = dir.join("rules_local.json");
        assert!(
            std::fs::read_to_string(&file)
                .expect("rules_local.json 必须存在")
                .contains("del217.example"),
            "独立规则文件必须同步"
        );

        // ② 删除该规则（rules[] 里不再包含它）。
        let body = json!({"rules": [
            {"id": "rmig1", "match": "other.example", "match_raw": "other.example",
             "action": "block", "group": "domestic", "ip": ""}
        ]});
        let _ = put_config(State(state.clone()), test_parts(), Json(body))
            .await
            .expect("put 2");
        let on_disk = std::fs::read_to_string(&file).expect("read file");
        assert!(
            !on_disk.contains("del217.example"),
            "删除必须落到独立规则文件: {on_disk}"
        );
        // 索引同步移除（否则解析引擎仍按旧规则拦截 —— 用户看到的「删了还生效」）。
        assert!(
            state.resolver.match_rule("del217.example").is_none(),
            "删除后索引必须不再命中"
        );
        assert!(state.resolver.match_rule("other.example").is_some());
        assert_eq!(crate::rules_admin::rules_payload(&state)["total"], json!(1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 回归：`/api/rules/import` 必须给新规则补稳定 id 并**落盘**。
    ///
    /// 修复前：导入只改内存 + `cfg["rules"]`，不写 `rules_local.json`，且新条目
    /// `id: null` → ① 页面逐条规则行按 `data-id` 定位，删除/编辑静默 no-op；
    /// ② `systemctl restart ebpdns` 后规则消失（实测 dig 由 NXDOMAIN 回 NOERROR）。
    #[tokio::test]
    async fn rules_import_assigns_id_and_persists() {
        use axum::extract::State;
        let dir = std::env::temp_dir().join(format!(
            "ebpdns_api_import_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let mut state = test_state();
        state.cfg_path = Some(dir.join("config.json"));

        let body =
            json!({"action":"block","content":"imp217.example","wildcard":false}).to_string();
        let _ = rules_import(State(state.clone()), body)
            .await
            .expect("import ok");

        // ① cfg["rules"] 里新条目必须有非空 id。
        //    注：`rules_import` 回写的形状是 `match_raw`（对齐 config.json 的落盘口径）。
        let rules = state
            .cfg
            .read()
            .get("rules")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let got = rules
            .iter()
            .find(|r| {
                r.get("match_raw").and_then(Value::as_str) == Some("imp217.example")
                    || r.get("match").and_then(Value::as_str) == Some("imp217.example")
            })
            .unwrap_or_else(|| panic!("imported rule in cfg: {}", json!(rules)));
        let rid = got["id"].as_str().expect("id 必须是非空字符串").to_string();
        assert!(!rid.is_empty());

        // ② 独立规则文件必须已落盘（重启后索引从此文件重建）。
        let file = dir.join("rules_local.json");
        let on_disk: Value = serde_json::from_str(
            &std::fs::read_to_string(&file).expect("rules_local.json 必须存在"),
        )
        .expect("json");
        let disk_rules = on_disk["rules"].as_array().expect("rules[]");
        assert!(
            disk_rules.iter().any(|r| {
                ["match", "match_raw"]
                    .iter()
                    .any(|k| r.get(*k).and_then(Value::as_str) == Some("imp217.example"))
            }),
            "落盘规则必须含导入项: {disk_rules:?}"
        );

        // ③ 该 id 必须可被 DELETE /api/rules/{id} 定位（id 稳定、非 null）。
        let deleted = crate::rules_admin::delete_rule(state.clone(), &rid)
            .await
            .expect("delete by import id");
        assert_eq!(deleted["rule"]["match"], json!("imp217.example"));
        assert!(state.resolver.match_rule("imp217.example").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **2.1.19（修复项 3 / R9）**：`cache_persist_info` 的两个空态与"文件存在"态。
    ///
    /// 不依赖 HTTP、不依赖 `tracing` 订阅者：直接对纯函数 + 真文件系统断言，
    /// 因此"页面显示的值 == API 的值"里**API 那一半**被逐字段钉死
    /// （前端那一半由 `web/src/pages/config.rs::persist_rows` 的单测 + 真机
    /// `/api/status` 与 `/api/cache/stats` 逐字段对比覆盖）。
    #[test]
    fn cache_persist_info_covers_all_three_states() {
        let dir = std::env::temp_dir().join(format!("ebpdns-persist-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("cache.json");
        let _ = std::fs::remove_file(&file);

        // ① 未开启持久化 ⇒ enabled=false + note 写明"不写盘也不恢复"。
        let off = cache_persist_info(
            &json!({"cache_persist": false, "cache_save_interval": 60,
                    "cache_file": file.display().to_string()}),
            7,
            &ebpdns_cache::PersistStats::default(),
        );
        assert_eq!(off["enabled"], json!(false));
        assert_eq!(off["exists"], json!(false));
        assert_eq!(off["entries"], json!(7), "内存条目数必须照原样下发");
        assert!(
            off["note"].as_str().unwrap_or("").contains("未开启持久化"),
            "空态①必须给出可读原因：{off}"
        );
        assert_eq!(
            off["age_s"],
            json!(0),
            "文件不存在时 age_s 必须是 0（不是缺字段）"
        );
        assert_eq!(off["bytes"], json!(0));

        // ② 开启但文件不存在 ⇒ 明确"尚未落盘"（用户实测的"重启丢缓存"自证入口）。
        let missing = cache_persist_info(
            &json!({"cache_persist": true, "cache_save_interval": 60,
                    "cache_file": file.display().to_string()}),
            0,
            &ebpdns_cache::PersistStats::default(),
        );
        assert_eq!(missing["enabled"], json!(true));
        assert_eq!(missing["exists"], json!(false));
        assert!(
            missing["note"].as_str().unwrap_or("").contains("尚未落盘"),
            "空态②必须与'未开启持久化'区分：{missing}"
        );

        // ③ 文件存在 ⇒ bytes/mtime_s/age_s 来自真实现场。
        std::fs::write(&file, b"[]").expect("write fixture");
        let md = std::fs::metadata(&file).expect("metadata");
        let mtime = md
            .modified()
            .ok()
            .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let on = cache_persist_info(
            &json!({"cache_persist": true, "cache_save_interval": 60,
                    "cache_file": file.display().to_string()}),
            61,
            &ebpdns_cache::PersistStats::default(),
        );
        assert_eq!(on["exists"], json!(true));
        assert_eq!(on["bytes"], json!(2), "`[]` 是 2 字节");
        assert_eq!(
            on["mtime_s"],
            json!(mtime),
            "mtime_s 必须是文件真实 mtime（epoch 秒）"
        );
        assert_eq!(on["entries"], json!(61));
        let age = on["age_s"].as_u64().expect("age_s 必须是数字");
        let now = crate::telemetry::now_epoch() as u64;
        assert!(
            age <= now.saturating_sub(mtime).saturating_add(2),
            "age_s 必须是 now - mtime（实测 {age}）"
        );
        assert_eq!(on["interval_s"], json!(60), "周期落盘间隔必须照原样下发");

        // ④ `cache_save_interval=0`（只在优雅退出落盘）⇒ note 必须说清。
        let zero = cache_persist_info(
            &json!({"cache_persist": true, "cache_save_interval": 0,
                    "cache_file": file.display().to_string()}),
            1,
            &ebpdns_cache::PersistStats::default(),
        );
        assert!(
            zero["note"]
                .as_str()
                .unwrap_or("")
                .contains("周期落盘已关闭"),
            "interval=0 的语义必须显式：{zero}"
        );

        // ⑤ 缺 `cache_file` 时兜底路径必须**存在**（不能是空串/缺字段）。
        let fb = cache_persist_info(&json!({}), 0, &ebpdns_cache::PersistStats::default());
        assert_eq!(fb["file"], json!("./ebpdns-cache.json"));
        assert_eq!(
            fb["enabled"],
            json!(true),
            "缺键时 cache_persist 默认 true（与 default_config 一致）"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **2.1.34（D3/D4）**：v2 恢复后 `mtime_s` 取 manifest 的 `committed_ms`
    /// （不再是 0），并**只追加** `snapshot_age_s`（快照年龄，秒）。
    ///
    /// 旧缺陷：`recover` 从不读 `manifest.committed_ms` ⇒ `mtime_s=0`、`age_s=epoch`、
    /// `note` 假“超过 2 个落盘周期未见更新”（正常恢复被显示成落盘失败）。
    #[test]
    fn cache_persist_info_v2_uses_manifest_commit_and_snapshot_age() {
        let dir = std::env::temp_dir().join(format!("ebpdns-persist-v2-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("cache.manifest");
        std::fs::write(&file, b"x").expect("write manifest fixture");
        let stats = ebpdns_cache::PersistStats::new();
        let now_ms = (crate::telemetry::now_epoch() * 1000.0) as i64;
        stats.set_format(ebpdns_cache::persist::Format::V2);
        stats.set_manifest_valid(true);
        stats.set_last_commit_ms(now_ms - 5_000); // 5 s 前落盘
        stats.set_snap_ms(now_ms - 200_000); // 快照 200 s 前
        stats.set_snap_bytes(4096);
        let v = cache_persist_info(
            &json!({"cache_persist": true, "cache_save_interval": 60,
                    "cache_file": file.display().to_string()}),
            10,
            &stats,
        );
        let mtime = v["mtime_s"].as_u64().expect("mtime_s 必须是数字");
        let age = v["age_s"].as_u64().expect("age_s 必须是数字");
        assert!(mtime > 0, "恢复后 mtime_s 必须 > 0（实际 {mtime}）：{v}");
        assert!(age <= 120, "age_s 必须接近真实落盘年龄（实际 {age}）：{v}");
        assert!(
            v["note"].as_str().unwrap_or("x").is_empty(),
            "落盘正常时 note 必须为空（不得假报失败）：{v}"
        );
        let snap_age = v["snapshot_age_s"]
            .as_u64()
            .expect("snapshot_age_s 必须存在（2.1.34 只追加键）");
        assert!(
            (195..=205).contains(&snap_age),
            "snapshot_age_s 必须 ≈ now - 快照 mtime（实际 {snap_age}）：{v}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **2.1.19（修复项 3 / R9）**：`/api/status.cache.persist` 与
    /// `/api/cache/stats.persist` 必须**逐字段相同**（配置页读前者、脚本读后者 ——
    /// 两处漂移就是 2.1.17"三种字符串"那类缺陷的翻版）。
    ///
    /// 同时钉死字段集合：`enabled/interval_s/file/exists/bytes/mtime_s/age_s/entries/note`。
    #[tokio::test]
    async fn status_and_cache_stats_expose_identical_persist_block() {
        use axum::extract::State;
        let state = test_state();
        // 指向一个真实存在的小文件，让 `exists=true` 分支也被覆盖。
        let dir = std::env::temp_dir().join(format!("ebpdns-r9-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("cache.json");
        std::fs::write(&file, b"[]").expect("write fixture");
        *state.cfg.write() = json!({
            "cache_persist": true,
            "cache_save_interval": 60,
            "cache_file": file.display().to_string(),
            "rules": [],
        });

        let st = status(State(state.clone())).await;
        let stb = axum::body::to_bytes(st.into_body(), usize::MAX)
            .await
            .unwrap();
        let stv: Value = serde_json::from_slice(&stb).expect("status json");
        let cst = cache_stats(State(state.clone())).await;
        let cstb = axum::body::to_bytes(cst.into_body(), usize::MAX)
            .await
            .unwrap();
        let csv: Value = serde_json::from_slice(&cstb).expect("cache/stats json");

        let a = stv
            .get("cache")
            .and_then(|c| c.get("persist"))
            .expect("/api/status.cache.persist 必须存在（R9 的数据源）");
        let b = csv
            .get("persist")
            .expect("/api/cache/stats.persist 必须存在（2.1.19 已有）");
        // **2.1.19**：`age_s` 由**两次独立的文件 stat** 算出（两个端点各自调用
        // `cache_persist_info`），跨 1 秒**边界**时可能相差 1 秒 —— 这是时间源边界，
        // 不是契约漂移。故：`age_s` 容忍 ±1s（并显式断言"这个容差只对 age_s 生效"），
        // **其余字段逐字段严格相等**（含 `mtime_s`：同一个文件在同一秒内 mtime 不变）。
        let (a_age, b_age) = (
            a.get("age_s").and_then(Value::as_u64).unwrap_or(u64::MAX),
            b.get("age_s").and_then(Value::as_u64).unwrap_or(0),
        );
        assert!(
            a_age.abs_diff(b_age) <= 1,
            "age_s 跨端点差异必须 ≤1s（实测 {a_age} vs {b_age}；更大差异说明两个端点算了不同的现场）"
        );
        let mut a_norm = a.clone();
        let mut b_norm = b.clone();
        if let Value::Object(ref mut m) = a_norm {
            m.remove("age_s");
            // **2.1.34（D4）**：`snapshot_age_s` 与 `age_s` 同源（`now_epoch()`），
            // 两次独立 stat 跨秒边界可差 1 s —— 与 `age_s` 同用时间源容差。
            m.remove("snapshot_age_s");
        }
        if let Value::Object(ref mut m) = b_norm {
            m.remove("age_s");
            m.remove("snapshot_age_s");
        }
        assert_eq!(
            a_norm, b_norm,
            "除 age_s（±1s 时间源边界）外，两个端点的落盘现场必须逐字段相同"
        );

        for k in [
            "enabled",
            "interval_s",
            "file",
            "exists",
            "bytes",
            "mtime_s",
            "age_s",
            "entries",
            "note",
            "snapshot_age_s",
        ] {
            assert!(a.get(k).is_some(), "persist 缺字段 {k}：{a}");
        }
        assert_eq!(a["file"], json!(file.display().to_string()));
        assert_eq!(a["exists"], json!(true));
        assert_eq!(a["bytes"], json!(2));
        assert_eq!(a["interval_s"], json!(60));

        // **2.1.19（修复项 1）**：`restore_drops` 也必须两个端点同源同值，且三个键齐备
        // （部署代理 ⑫ 建议："legacy 计数只在日志/内部 ⇒ 不便断言"）。
        let rd_a = stv
            .get("cache")
            .and_then(|c| c.get("restore_drops"))
            .expect("/api/status.cache.restore_drops 必须存在（2.1.19）");
        let rd_b = csv
            .get("restore_drops")
            .expect("/api/cache/stats.restore_drops 必须存在（2.1.19）");
        assert_eq!(rd_a, rd_b, "restore_drops 两个端点必须一致");
        // **2.1.43-B（P2-4）**：`window_unpersisted` 键存在（空/非 tinylfu 态为 0）。
        // **2.1.46 替换 REV247 形同虚设 #3**：非 0 的判别力移到
        // `restore_drops_window_unpersisted_endpoint_is_real` —— 该用例真的用
        // TinyLFU 灌入 > main_cap 条并断言端点值 >0；旧口径/未接线时必红。
        for k in ["expired", "legacy", "failed", "window_unpersisted"] {
            assert!(rd_a.get(k).is_some(), "restore_drops 缺字段 {k}：{rd_a}");
        }
        assert_eq!(rd_a["legacy"], json!(0));
        assert_eq!(rd_a["expired"], json!(0));
        assert_eq!(rd_a["failed"], json!(0));

        // **2.1.19（修复项 1 补漏）**：文件级失败必须**覆盖**为本次值（`failed >= 1`），
        // 不能保留上一次（此前的"说谎"）。这里直接驱动外壳的 trait 入口 —— 与
        // `main.rs::restore_cache` 在 JSON 解析失败/顶层非数组分支里调用的是同一个。
        {
            use ebpdns_cache::DnsCache as _;
            let cache = state.resolver.cache();
            cache.record_file_level_restore_failure(1);
            let st2 = status(State(state.clone())).await;
            let b2 = axum::body::to_bytes(st2.into_body(), usize::MAX)
                .await
                .unwrap();
            let v2: Value = serde_json::from_slice(&b2).expect("json");
            let rd2 = &v2["cache"]["restore_drops"];
            assert_eq!(
                rd2["failed"],
                json!(1),
                "文件级失败后 `failed` 必须 >= 1（此前显示 0 —— 上一次的陈旧值）：{rd2}"
            );
            let cs2 = cache_stats(State(state.clone())).await;
            let cb2 = axum::body::to_bytes(cs2.into_body(), usize::MAX)
                .await
                .unwrap();
            let cv2: Value = serde_json::from_slice(&cb2).expect("json");
            assert_eq!(
                cv2["restore_drops"]["failed"],
                json!(1),
                "两端口径一致：/api/cache/stats 也必须报 1"
            );
            // 一次真正的 restore 必须清掉文件级记录（否则又是新的说谎方式）。
            // 注：这里在 `ebpdns-server` crate 内部，用 `crate::telemetry::now_epoch()`
            // （不能写 `ebpdns_server::…` —— crate 自身不由名字自引用）。
            cache.restore(&[], crate::telemetry::now_epoch(), 0.0);
            assert_eq!(
                cache.last_restore_drops(),
                (0, 0, 0),
                "真正的 per-entry restore 之后不得残留文件级失败"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **2.1.46（REV247 P3-1）**：`ebpdns_cache_negative_hits_total` 的 HELP 必须
    /// 与 P1-7 的写点口径一致 —— **只有数据面**，不得再声称包含 control-plane。
    #[tokio::test]
    async fn negative_hits_help_is_data_plane_only() {
        use axum::extract::State;
        let st = test_state();
        let resp = metrics(State(st)).await.into_response();
        let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&b);
        let line = text
            .lines()
            .find(|l| l.starts_with("# HELP ebpdns_cache_negative_hits_total"))
            .expect("negative_hits HELP 必须存在");
        assert!(
            line.contains("UDP/TCP data plane only"),
            "HELP 必须声明 data plane only：{line}"
        );
        assert!(
            !line.contains("control-plane /api/query)"),
            "HELP 不得再把 control-plane 算进 negative_hits：{line}"
        );
    }

    /// **2.1.46（REV247 P3-2）**：`rebind_blocked` 的**正向**测试 —— 写请求的
    /// `Host` 指向不可信名字 ⇒ 403 且计数 +1（旧实现只有负向断言 `==0`）。
    #[tokio::test]
    async fn rebind_blocked_positive_on_untrusted_host_write() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;
        let st = test_state();
        let before = st.telemetry.snapshot().rebind_blocked;
        let app = build_router(st.clone());
        let req = Request::builder()
            .method("POST")
            .uri("/api/config")
            .header("host", "evil.example.com:8353")
            // 无 Origin 时环回绑定会直接放行；给出不可信 Origin 才能进入 CSRF 拒绝分支。
            .header("origin", "http://evil.example.com:8353")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let after = st.telemetry.snapshot().rebind_blocked;
        assert_eq!(
            after - before,
            1,
            "Host 不可信的写请求必须计 rebind_blocked（旧实现无正向测试/无写点）"
        );
    }

    /// **2.1.46 替换 REV247 形同虚设 #3**：`restore_drops.window_unpersisted` 必须在
    /// 默认 `tinylfu` 策略、恢复条目 > main 段容量时**真的非 0**，并同时出现在
    /// `/api/status` 与 `/api/cache/stats`。
    ///
    /// 旧用例只断言"键存在且默认 0"：即使 TinyLFU 恢复从不置非 0 也绿。这里用
    /// `cache_size=100` + 200 条恢复记录，main 段只灌 ≈99 条，窗口段丢失 ≈101 条。
    #[tokio::test]
    async fn restore_drops_window_unpersisted_endpoint_is_real() {
        use axum::extract::State;
        use ebpdns_cache::{CacheEntry, CacheKey, DnsCache};
        let mut cfg =
            ebpdns_resolver::config::ResolverConfig::test_default(Vec::new(), Vec::new(), 1);
        cfg.cache_policy = "tinylfu".to_string();
        cfg.cache_size = 100;
        let state = test_state_with_resolver_cfg(cfg);
        let cache = state.resolver.cache();
        let now = crate::telemetry::now_epoch();
        let entries: Vec<(CacheKey, CacheEntry)> = (0..200)
            .map(|i| {
                let d = format!("restore{i}.test");
                let mut e = CacheEntry::new(&d, "A", 300.0, now);
                e.expires_at = now + 300.0;
                (CacheKey::new(&d, "A"), e)
            })
            .collect();
        cache.restore_records(entries, now);
        assert!(!cache.is_empty(), "恢复后必须有条目");
        let resp = status(State(state.clone())).await;
        let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&b).expect("json");
        let w = v["cache"]["restore_drops"]["window_unpersisted"]
            .as_u64()
            .expect("window_unpersisted 必须是整数");
        assert!(
            w > 0,
            "TinyLFU 恢复 200 条 / main_cap≈99 ⇒ window_unpersisted 必须 >0（旧弱测试恒 0）：{v}"
        );
        let cs = cache_stats(State(state)).await;
        let cb = axum::body::to_bytes(cs.into_body(), usize::MAX)
            .await
            .unwrap();
        let cv: Value = serde_json::from_slice(&cb).expect("json");
        assert_eq!(
            cv["restore_drops"]["window_unpersisted"],
            json!(w),
            "两个端点必须同源同值"
        );
    }

    /// **2.1.19（F-03）**：`PUT /api/config` 必须在**写入之前**逐条校验 `rules`，
    /// 非法即 **400 + 逐条原因**，且**零副作用**（磁盘与内存都不变）。
    ///
    /// 缺陷：此前非法规则在 `rules_admin::rebuild_index_from_config` 里被
    /// `filter_map(normalize_rule_json)` 静默丢弃，接口照回 `200 ok:true`，
    /// 并把 `rules` **覆盖成丢弃后的数组**（用户以为保存成功、实际规则被删）；
    /// 同一形状走 `POST /api/rules` 却正确回 400 ⇒ 两条路径口径分叉。
    #[tokio::test]
    async fn f03_put_config_rejects_invalid_rules_without_partial_write() {
        use axum::extract::State;
        let state = test_state();
        // 磁盘配置：先放一条**合法**规则（用于断言"未被部分写入/未被覆盖"）。
        let dir = std::env::temp_dir().join(format!("ebpdns-f03-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("config.json");
        let good = json!({"match": "keep.example", "action": "block"});
        std::fs::write(
            &path,
            serde_json::to_vec(&json!({"rules": [good.clone()], "cache_size": 131072})).unwrap(),
        )
        .expect("write fixture");
        let mut st = state.clone();
        st.cfg_path = Some(path.clone());
        *st.cfg.write() = json!({"rules": [good.clone()], "cache_size": 131072});

        // 提交：1 条合法 + 1 条**非法**（缺 match）+ 一个合法标量改动。
        let body = json!({
            "cache_size": 262144,
            "rules": [good.clone(), {"action": "block"}],
        });
        let err = put_config(State(st.clone()), test_parts(), Json(body)).await;
        let msg = match err {
            Ok(_) => panic!("非法 rules 必须回 400，实际 200"),
            Err(e) => format!("{e:?}"),
        };
        assert!(
            msg.contains("match is required") || msg.contains("rules["),
            "必须给出**逐条**原因（含下标与原因），实际：{msg}"
        );
        assert!(msg.contains("rules[1]"), "必须点名第 2 条（下标 1）：{msg}");
        // 零副作用：内存里的 rules 与 cache_size 都不变。
        let cfg_now = st.cfg.read().clone();
        assert_eq!(
            cfg_now["rules"],
            json!([good]),
            "非法提交不得覆盖内存 rules（此前会被覆盖成丢弃后的数组）"
        );
        assert_eq!(
            cfg_now["cache_size"],
            json!(131072),
            "整份提交都不许部分写入（一个坏值 ⇒ 全部不写）"
        );
        // 磁盘也未改。
        let on_disk: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(on_disk["rules"], json!([good]), "磁盘 rules 不得被覆盖");
        assert_eq!(on_disk["cache_size"], json!(131072), "磁盘不得部分写入");

        // 对照：**全合法**的提交应当成功（防止"一律拒绝"的过度收紧）。
        let ok_body = json!({"cache_size": 262144, "rules": [good.clone()]});
        assert!(
            put_config(State(st.clone()), test_parts(), Json(ok_body))
                .await
                .is_ok(),
            "全合法提交必须成功"
        );
        assert_eq!(st.cfg.read()["cache_size"], json!(262144));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **2.1.19（F-05）**：熔断打开的上游**不得**同时显示 `status:"健康"` 与
    /// `success_rate:100.0`（部署代理实测的真实矛盾组合）。
    #[tokio::test]
    async fn f05_breaker_open_upstream_is_not_reported_healthy() {
        use axum::extract::State;
        // 用**自带启用上游**的夹具（`ResolverConfig::default()` 的上游全为 disabled）。
        const UID: &str = "f05-brk-up";
        let state = test_state_with_enabled_upstream(UID);
        let uid = UID.to_string();
        state
            .resolver
            // 注：本 crate 内部**不能**用 `ebpdns_server::…` 自引用 crate 名（E0433）。
            .cb_inject(&uid, 8, crate::telemetry::now_epoch() + 600.0);

        let resp = upstreams(State(state.clone())).await;
        let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&b).expect("json");
        let u = v["upstreams"]
            .as_array()
            .expect("upstreams[]")
            .iter()
            .find(|x| x["id"] == json!(uid))
            .unwrap_or_else(|| panic!("找不到上游 {uid}"));
        assert_eq!(u["breaker_open"], json!(true), "前置：熔断必须处于打开态");
        assert_eq!(u["selectable"], json!(false), "前置：熔断中应不可选");
        assert_ne!(
            u["status"],
            json!("健康"),
            "熔断中的上游不得报『健康』（实际 {}）",
            u["status"]
        );
        assert_eq!(u["status"], json!("熔断中"), "状态必须是『熔断中』");
        assert!(
            u["success_rate"].is_null(),
            "**2.1.20（A-20）**：熔断中且无传输样本 ⇒ `success_rate` 必须是 `null`\
             （不得是 100.0 / 0.0 这类**编造**值），实际 {}",
            u["success_rate"]
        );
        assert_eq!(u["breaker_fails"], json!(8), "熔断账必须单独下发");
    }

    /// **2.1.20（A-06 二次修复）**：`PUT /api/config` 的 5xx 必须让 **`config.json` 逐字节未变**
    /// —— 磁盘 md5 在失败前后完全相同（不得因为把**内存**里的注入键写回而使文件"长胖"）。
    ///
    /// 缺陷（审计复测）：首版回滚写回的是**内存**旧配置，而内存带着 `migrate_cfg` 注入的
    /// `rule_sub_file` ⇒ 回滚后磁盘仍多一个键（`only in b: ['rule_sub_file']`、78→79 键、
    /// 110→111 行），与日志"config.json 也回到原状"的说法不符。
    #[tokio::test]
    async fn a06b_rollback_leaves_config_file_byte_identical() {
        use axum::extract::State;
        let dir = std::env::temp_dir().join(format!("ebpdns-a06b-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let cfg_path = dir.join("config.json");
        let rule_dir = dir.join("rules-as-dir");
        std::fs::create_dir_all(&rule_dir).expect("mkdir rules dir");
        // 磁盘原文件：**故意不含**注入键（真实场景：手工写的 config.json）。
        let on_disk_before = serde_json::to_vec_pretty(&json!({
            "rules": [{"match": "keep-a06b.example", "action": "block"}],
            "rule_local_file": rule_dir.display().to_string(),
            "cache_size": 131072,
        }))
        .unwrap();
        std::fs::write(&cfg_path, &on_disk_before).expect("write fixture");
        let bytes_before = std::fs::read(&cfg_path).unwrap();

        // 内存配置**带**一个注入键（模拟 `migrate_cfg` 的效果：内存比磁盘多键）。
        let mut in_mem = serde_json::from_slice::<Value>(&on_disk_before).unwrap();
        in_mem["rule_sub_file"] = json!(dir.join("rules_sub.json").display().to_string());
        let mut st = test_state();
        st.cfg_path = Some(cfg_path.clone());
        *st.cfg.write() = in_mem;
        crate::rules_admin::rebuild_index_from_cfg(&st).expect("初始索引");

        let body = json!({"cache_size": 262144, "rules": [
            {"match": "keep-a06b.example", "action": "block"},
            {"match": "new-a06b.example", "action": "block"}
        ]});
        assert!(
            put_config(State(st.clone()), test_parts(), Json(body))
                .await
                .is_err(),
            "规则写盘必然失败（rule_local_file 指向目录）"
        );

        // ① **磁盘逐字节未变**（注入键不得被写入）。
        let bytes_after = std::fs::read(&cfg_path).unwrap();
        assert_eq!(
            bytes_after, bytes_before,
            "5xx ⇒ config.json 必须**逐字节**未变（此前会多出 `rule_sub_file` —— A-06 二次修复）"
        );
        let disk: Value = serde_json::from_slice(&bytes_after).unwrap();
        assert!(
            disk.get("rule_sub_file").is_none(),
            "回滚不得把内存里的注入键写进磁盘：{disk:?}"
        );
        assert_eq!(disk["cache_size"], json!(131072), "磁盘不得部分写入");
        // ② 内存也回到原状（内存里**本来就有**注入键 ⇒ 保留）。
        let mem_now = st.cfg.read().clone();
        assert_eq!(mem_now["cache_size"], json!(131072));
        assert_eq!(mem_now["rules"].as_array().map(|a| a.len()), Some(1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **2.1.20（A-04）**：控制面 `POST /api/query` **不得**破坏数据面不变量
    /// `hit + miss <= total` 与 `hit_rate <= 100%`（2.1.19 实测可到 600%）。
    ///
    /// 口径：控制面命中只进 `control_queries` / `control_hits`，**不进** `hit`。
    #[tokio::test]
    async fn a04_control_plane_does_not_break_hit_rate_invariant() {
        use axum::extract::State;
        let state = test_state_with_answer("a04-up");
        let hit_before = state.telemetry.snapshot().hit;
        // 第一次：miss（写缓存）；第二次：命中。
        for _ in 0..2 {
            let r = query(
                State(state.clone()),
                Json(json!({"domain": "a04.test", "qtype": "A"})),
            )
            .await
            .expect("控制面查询必须成功");
            assert!(r.0.get("answers").is_some());
        }
        let snap = state.telemetry.snapshot();
        assert_eq!(snap.hit, hit_before, "**控制面命中的不得进 `hit`**（A-04）");
        assert_eq!(snap.control_queries, 2, "控制面查询计数必须为 2");
        assert_eq!(snap.control_hits, 1, "其中 1 次应为缓存直答");
        // 数据面不变量（`total` 只统计数据面 ⇒ 控制面完全不参与）。
        assert!(
            snap.hit + snap.miss <= snap.total,
            "hit+miss <= total 必须成立：hit={} miss={} total={}",
            snap.hit,
            snap.miss,
            snap.total
        );
        // 命中率必须 <= 100（`/api/status.counters` 与 `/metrics` 同源）。
        let st = status(State(state.clone())).await;
        let b = axum::body::to_bytes(st.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&b).expect("json");
        let rate = v["counters"]["hit_rate"].as_f64().unwrap_or(0.0);
        assert!(
            rate <= 100.0,
            "**命中率不得超过 100%**（web/INTERFACE.md 验收条款）；实际 {rate}"
        );
        assert_eq!(v["counters"]["control_queries"], json!(2));
        assert_eq!(v["counters"]["control_hits"], json!(1));
    }

    /// **2.1.20（A-05）**：控制面判定"负缓存命中"必须用**真实结果**，
    /// 正向 A 记录命中**不得**增加 `negative_hits`（此前合成应答 `ancount=0` ⇒ 恒判负）。
    #[tokio::test]
    async fn a05_positive_cache_hit_does_not_count_negative_hits() {
        use axum::extract::State;
        let state = test_state_with_answer("a05-up");
        let neg_before = state.telemetry.snapshot().negative_hits;
        for _ in 0..3 {
            let _ = query(
                State(state.clone()),
                Json(json!({"domain": "a05.test", "qtype": "A"})),
            )
            .await
            .expect("控制面查询必须成功");
        }
        let snap = state.telemetry.snapshot();
        assert!(snap.control_hits >= 1, "前置：至少一次缓存命中");
        assert_eq!(
            snap.negative_hits, neg_before,
            "**正向 A 记录的缓存命中不得计 `negative_hits`**（A-05：此前恒判负）"
        );
    }

    /// **2.1.20（A-11）**：udp/tcp 上游的 `url`/`conn_key` 不得带 HTTP 路径 `/dns-query`。
    #[tokio::test]
    async fn a11_udp_upstream_has_no_http_path() {
        use axum::extract::State;
        let state = test_state_with_enabled_upstream("a11-up");
        let resp = upstreams(State(state.clone())).await;
        let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&b).expect("json");
        let u = &v["upstreams"][0];
        assert_eq!(u["proto"], json!("udp"));
        assert_eq!(u["url"], json!(""), "udp 上游的 `url` 必须是空串（A-11）");
        assert_eq!(
            u["conn_key"],
            json!("udp|127.0.0.1|53"),
            "udp 上游的 `conn_key` 不得带 `/dns-query`（A-11）"
        );
    }

    /// **2.1.20（A-20）**：无传输样本时 `success_rate` 必须是 `null`（不得编造 100%）。
    #[tokio::test]
    async fn a20_success_rate_is_null_without_samples() {
        use axum::extract::State;
        let state = test_state_with_enabled_upstream("a20-up");
        let resp = upstreams(State(state.clone())).await;
        let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&b).expect("json");
        let u = &v["upstreams"][0];
        assert_eq!(u["queries"], json!(0), "前置：无样本");
        assert_eq!(
            u["success_rate"],
            Value::Null,
            "无样本时必须为 null（A-20：此前报 100.0 是编造）"
        );
        assert_eq!(u["status"], json!("待命"), "无样本的状态是『待命』");
        // `/metrics` 必须**不发**该样本（Prometheus 无"未知"）而不是伪造 0。
        use axum::response::IntoResponse as _;
        let m = metrics(State(state.clone())).await.into_response();
        let mb = axum::body::to_bytes(m.into_body(), usize::MAX)
            .await
            .unwrap();
        let mt = String::from_utf8_lossy(&mb);
        assert!(
            !mt.contains("ebpdns_upstream_success_rate{id=\"a20-up\"}"),
            "null 成功率必须整条不发（absent），不得伪造成 0/100"
        );
    }

    /// **2.1.20（A-06）**：`PUT /api/config` 的规则**落盘失败**必须**可回滚** ——
    /// 内存配置、`config.json`、规则索引三者一起回到原状（此前只有 500，前三者已被改）。
    #[tokio::test]
    async fn a06_put_config_rolls_back_when_rules_persist_fails() {
        use axum::extract::State;
        let dir = std::env::temp_dir().join(format!("ebpdns-a06-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let cfg_path = dir.join("config.json");
        // `rule_local_file` 指向一个**目录** ⇒ 规则写盘必然失败（Is a directory）。
        let rule_dir = dir.join("rules-as-dir");
        std::fs::create_dir_all(&rule_dir).expect("mkdir rules dir");
        let old_rule = json!({"match": "keep-a06.example", "action": "block"});
        let base = json!({
            "rules": [old_rule.clone()],
            "rule_local_file": rule_dir.display().to_string(),
            "cache_size": 131072,
        });
        std::fs::write(&cfg_path, serde_json::to_vec(&base).unwrap()).expect("write fixture");
        let mut st = test_state();
        st.cfg_path = Some(cfg_path.clone());
        *st.cfg.write() = base.clone();
        // 让规则索引先建立（= 现状：旧规则生效）。
        crate::rules_admin::rebuild_index_from_cfg(&st).expect("初始索引");
        let gen_before = st.resolver.rule_gen();
        let count_before = st.resolver.rule_count();

        // 提交：一条**新**规则（走 persist_current ⇒ 必然失败）+ 一个合法标量改动。
        let body = json!({
            "cache_size": 262144,
            "rules": [old_rule.clone(), {"match": "new-a06.example", "action": "block"}],
        });
        let err = put_config(State(st.clone()), test_parts(), Json(body)).await;
        assert!(err.is_err(), "规则写盘失败必须回 5xx，实际成功");

        // ① 内存配置回到原状（含 `cache_size`，即"整份提交都不生效"）。
        let now = st.cfg.read().clone();
        assert_eq!(
            now["rules"],
            json!([old_rule.clone()]),
            "内存 rules 必须回滚"
        );
        assert_eq!(now["cache_size"], json!(131072), "内存其它键也必须回滚");
        // ② 磁盘回到原状。
        let disk: Value =
            serde_json::from_str(&std::fs::read_to_string(&cfg_path).unwrap()).unwrap();
        assert_eq!(disk["rules"], json!([old_rule]), "磁盘 rules 必须回滚");
        assert_eq!(disk["cache_size"], json!(131072), "磁盘不得部分写入");
        // ③ 规则索引回到原状（`rule_gen` 与条数都不变）。
        assert_eq!(
            st.resolver.rule_gen(),
            gen_before,
            "规则指纹必须回滚（否则引擎按新规则跑、控制台显示旧规则）"
        );
        assert_eq!(st.resolver.rule_count(), count_before, "规则条数必须回滚");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **2.1.20（A-14 的 API 侧）**：`cb_fails` / `cb_open_s` / `prefetch_max`
    /// 是**受支持的别名** ⇒ 不得再进 `ignored_keys`（审计 A-12 实测它们被判"未知键"）。
    #[tokio::test]
    async fn a12_supported_aliases_are_not_reported_as_unknown() {
        use axum::extract::State;
        let state = test_state();
        let r = put_config(
            State(state.clone()),
            test_parts(),
            Json(json!({"cb_fails": 9, "cb_open_s": 20.0, "prefetch_max": 8})),
        )
        .await
        .expect("合法别名必须被接受");
        let ignored = r.0["ignored_keys"].as_array().cloned().unwrap_or_default();
        for k in ["cb_fails", "cb_open_s", "prefetch_max"] {
            assert!(
                !ignored.iter().any(|x| x == k),
                "`{k}` 是真被消费的别名，不得报未知键：{ignored:?}"
            );
            assert!(
                r.0["written_keys"]
                    .as_array()
                    .map(|a| a.iter().any(|x| x == k))
                    .unwrap_or(false),
                "`{k}` 必须出现在 written_keys 里"
            );
        }
        assert_eq!(state.cfg.read()["cb_fails"], json!(9));
    }

    /// **2.1.19（F-06）**：`counters.stale_served` 必须与 `/metrics` 的
    /// `ebpdns_stale_served_total` **同源**（同一 `ServerTelemetry` 原子）。
    #[tokio::test]
    async fn f06_stale_served_is_exposed_in_status_and_metrics() {
        use axum::extract::State;
        let state = test_state();
        // 直接经唯一打点（`inc_n` 面的 `inc`）制造一次 stale 直答。
        {
            use ebpdns_resolver::telemetry::Telemetry as _;
            state.telemetry.inc("stale_served");
        }
        let st = status(State(state.clone())).await;
        let b = axum::body::to_bytes(st.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&b).expect("json");
        assert_eq!(v["counters"]["stale_served"], json!(1));
        use axum::response::IntoResponse as _;
        let m = metrics(State(state.clone())).await.into_response();
        let mb = axum::body::to_bytes(m.into_body(), usize::MAX)
            .await
            .unwrap();
        let mt = String::from_utf8_lossy(&mb);
        assert!(
            mt.contains("ebpdns_stale_served_total 1"),
            "/metrics 必须与 counters 同源（缺 `ebpdns_stale_served_total 1`）"
        );
    }

    /// **2.1.20（A-04/A-05 测试夹具）**：与 [`test_state_with_enabled_upstream`] 相同，
    /// 但脚本化上游**真的返回一条 A 记录** ⇒ 第一次控制面查询写缓存、第二次起命中。
    ///
    /// 为什么必须有它：A-04/A-05 只对"**控制面命中缓存**"这一条路径成立，
    /// 而 `test_state()` 的脚本化上游恒返回空向量（永不进缓存）⇒ 断言跑不到目标路径。
    /// **2.1.22**：无请求头的 `Parts`（`put_config` 新增的 `if-revision` 抽取参数）。
    ///
    /// 测试不经过 HTTP 栈，故直接构造一个空的 `Parts` —— 语义等于"客户端没有声明
    /// `if-revision`"，因此既有用例的并发语义逐位不变（不做乐观并发校验）。
    fn test_parts() -> axum::http::request::Parts {
        axum::http::Request::builder()
            .body(())
            .expect("request")
            .into_parts()
            .0
    }

    fn test_state_with_answer(id: &str) -> AppState {
        use crate::state::{AppState, RestartSignal};
        use ebpdns_resolver::clock::RealClock;
        use ebpdns_resolver::config::{ResolverConfig, UpstreamCfg};
        use ebpdns_resolver::query::ScriptedQuerier;
        use ebpdns_resolver::types::{ResolveAnswer, UpstreamAnswer};
        use ebpdns_resolver::Resolver;
        use parking_lot::RwLock;
        use std::sync::Arc;

        let tel = Arc::new(crate::telemetry::ServerTelemetry::new());
        // **2.1.24**：结构体更新语法（`clippy::field_reassign_with_default`）；夹具语义不变。
        let cfg = ResolverConfig {
            upstreams: vec![UpstreamCfg {
                id: id.to_string(),
                name: id.to_string(),
                proto: "udp".into(),
                host: "127.0.0.1".into(),
                port: 53,
                url: String::new(),
                enabled: true,
                latency: 10,
                weight: 1.0,
                group: None,
                allow_private_ip: false,
            }],
            ..Default::default()
        };
        let up_id = id.to_string();
        let resolver = Resolver::new(
            cfg,
            tel.clone(),
            Arc::new(RealClock::default()),
            Arc::new(ScriptedQuerier::new(move |_n, _t, _d| {
                vec![UpstreamAnswer::ok(
                    up_id.as_str(),
                    0,
                    vec![ResolveAnswer::new("1.2.3.4", 300.0, 1)],
                    vec![],
                )]
            })),
        );
        AppState {
            resolver,
            cfg: Arc::new(RwLock::new(json!({"rules": []}))),
            cfg_path: None,
            telemetry: tel,
            api_host: Arc::new(RwLock::new("127.0.0.1".to_string())),
            api_port: 8353,
            web_root: None,
            restart: Arc::new(RestartSignal::default()),
            endpoints: Arc::new(RwLock::new(Vec::new())),
            on_reload: None,
            restart_notify: Arc::new(tokio::sync::Notify::new()),
            udp_dropped: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            applied: Arc::new(RwLock::new(json!({}))),
            // 2.1.22：本夹具不涉及持久化 ⇒ 旧行为（无统一事务）。
            state: Default::default(),
        }
    }

    /// **2.1.19（F-05 测试夹具）**：与 [`test_state`] 相同，但 **resolver 配置里有一条
    /// 启用上游**。
    ///
    /// 为什么需要独立夹具：`ResolverConfig::default()` 的上游**全部 `enabled=false`**，
    /// 而 F-05 的断言（"熔断中的上游不得报健康 / `success_rate` 不得 100%"）
    /// **必须先存在一条启用上游**才能构造熔断态。
    /// **不改产品默认配置**（那是出厂默认集，属另一条门禁）。
    fn test_state_with_enabled_upstream(id: &str) -> AppState {
        use crate::state::{AppState, RestartSignal};
        use ebpdns_resolver::clock::RealClock;
        use ebpdns_resolver::config::{ResolverConfig, UpstreamCfg};
        use ebpdns_resolver::query::ScriptedQuerier;
        use ebpdns_resolver::Resolver;
        use parking_lot::RwLock;
        use std::sync::Arc;

        let tel = Arc::new(crate::telemetry::ServerTelemetry::new());
        // **2.1.24**：结构体更新语法（`clippy::field_reassign_with_default`）；夹具语义不变。
        let cfg = ResolverConfig {
            upstreams: vec![UpstreamCfg {
                id: id.to_string(),
                name: id.to_string(),
                proto: "udp".into(),
                host: "127.0.0.1".into(),
                port: 53,
                url: String::new(),
                enabled: true,
                latency: 10,
                weight: 1.0,
                group: None,
                allow_private_ip: false,
            }],
            ..Default::default()
        };
        let resolver = Resolver::new(
            cfg,
            tel.clone(),
            Arc::new(RealClock::default()),
            Arc::new(ScriptedQuerier::new(|_n, _t, _d| vec![])),
        );
        AppState {
            resolver,
            cfg: Arc::new(RwLock::new(json!({"rules": []}))),
            cfg_path: None,
            telemetry: tel,
            api_host: Arc::new(RwLock::new("127.0.0.1".to_string())),
            api_port: 8353,
            web_root: None,
            restart: Arc::new(RestartSignal::default()),
            endpoints: Arc::new(RwLock::new(Vec::new())),
            on_reload: None,
            restart_notify: Arc::new(tokio::sync::Notify::new()),
            udp_dropped: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            applied: Arc::new(RwLock::new(json!({}))),
            // 2.1.22：本夹具不涉及持久化 ⇒ 旧行为（无统一事务）。
            state: Default::default(),
        }
    }

    /// 构造最小 AppState（注入 ScriptedQuerier，不联网）。
    fn test_state() -> AppState {
        test_state_with_resolver_cfg(ebpdns_resolver::config::ResolverConfig::default())
    }

    /// **2.1.25**：与 [`test_state`] 同构，但允许指定**解析器配置**（只有在"上游非空"的
    /// 配置下才能造出 `top_upstreams`，见下方两条 2.1.25 用例）。
    fn test_state_with_resolver_cfg(cfg: ebpdns_resolver::config::ResolverConfig) -> AppState {
        use crate::state::{AppState, RestartSignal};
        use ebpdns_resolver::clock::RealClock;
        use ebpdns_resolver::query::ScriptedQuerier;
        use ebpdns_resolver::Resolver;
        use parking_lot::RwLock;
        use std::sync::Arc;

        let tel = Arc::new(crate::telemetry::ServerTelemetry::new());
        let q = ScriptedQuerier::new(|_n, _t, _d| vec![]);
        let resolver = Resolver::new(
            cfg,
            tel.clone(),
            Arc::new(RealClock::default()),
            Arc::new(q),
        );
        AppState {
            resolver,
            cfg: Arc::new(RwLock::new(json!({"rules": []}))),
            cfg_path: None,
            telemetry: tel,
            api_host: Arc::new(RwLock::new("127.0.0.1".to_string())),
            api_port: 8353,
            web_root: None,
            restart: Arc::new(RestartSignal::default()),
            endpoints: Arc::new(RwLock::new(Vec::new())),
            on_reload: None,
            restart_notify: Arc::new(tokio::sync::Notify::new()),
            udp_dropped: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            applied: Arc::new(RwLock::new(json!({}))),
            // 2.1.22：本夹具不涉及持久化 ⇒ 旧行为（无统一事务）。
            state: Default::default(),
        }
    }

    /// 缺陷 B：`GET /api/pipeline.rules` 必须报**规则索引真实条数**（含订阅展开的规则），
    /// 而不是 `cfg.rules.len()`（逐条本地规则）——否则订阅 10 万条后控制台仍显示 0 规则。
    #[tokio::test]
    async fn pipeline_reports_live_index_rule_count() {
        use axum::extract::State;
        let state = test_state();
        // 造 3 条规则（block / group / *.通配）直接进索引（模拟订阅展开后的规则集）。
        let mks = |m: &str, a: &str| {
            ebpdns_rules::rule_from_json(
                json!({"match": m, "action": a})
                    .as_object()
                    .cloned()
                    .unwrap(),
                ebpdns_rules::RuleSource::Sub,
            )
            .expect("rule")
        };
        let rules = vec![
            mks("*.sub-a.test", "block"),
            mks("sub-b.test", "block"),
            mks("*.sub-c.test", "group"),
        ];
        state.resolver.rebuild_rules(rules);
        // cfg.rules 仍为空（订阅明细不写 config.json）——旧实现会返回 0。
        assert_eq!(
            state
                .cfg
                .read()
                .get("rules")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );
        let resp = pipeline(State(state.clone())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["rules"], json!(3), "pipeline.rules 必须是索引真实条数");
        assert_eq!(v["rules"], json!(state.resolver.rule_count()));
        // 其余字段与 2.1.29 契约一致：cache_direct_enabled/cache_size 存在，
        // upstreams 为脱敏数组（仅 id/name/proto，不含 host/addr/port/url）。
        for k in ["cache_direct_enabled", "cache_size", "upstreams"] {
            assert!(v.get(k).is_some(), "缺字段 {k}");
        }
        for u in v["upstreams"].as_array().into_iter().flatten() {
            let keys: Vec<&str> = u.as_object().unwrap().keys().map(String::as_str).collect();
            assert!(
                keys.iter().all(|k| matches!(*k, "id" | "name" | "proto")),
                "上游未脱敏: {keys:?}"
            );
        }
        // 规则集变化后立即反映（索引重建 → 计数更新）。
        state.resolver.rebuild_rules(vec![]);
        assert_eq!(state.resolver.rule_count(), 0);
    }

    /// 前端真实负载：POST {"action":"group","content":"a.com\nb.com"}。
    #[tokio::test]
    async fn rules_import_group_content_contract() {
        use axum::extract::State;
        let state = test_state();
        // >>> 242B BEGIN T-import-group >>> //
        let body = json!({"action":"group","group":"g1","content":"a.com\nb.com"}).to_string();
        let resp = rules_import(State(state.clone()), body).await.unwrap();
        assert_eq!(resp.0["added"], json!(2));
        // **2.1.42-B（P0-2）**：导入以真源为基准并写 cfg/真源 + 重建索引；
        // 不再依赖 `resolver.config().rules`（v3 下它恒为空）。
        assert_eq!(state.resolver.rule_count(), 2);
        // <<< 242B END T-import-group <<< //
        // GET /api/config 视角：s.cfg["rules"] 已回写。
        let cfg = state.cfg.read();
        let rules = cfg.get("rules").and_then(Value::as_array).unwrap();
        assert!(rules.len() >= 2);
        // **[历史归因]** F1 锁死：默认不传 wildcard → 对齐 Python api.py:3036 默认 true → 落 *.domain。
        let ra = rules
            .iter()
            // >>> 242B BEGIN T-import-match1 >>> //
            .find(|r| r.get("match").and_then(Value::as_str) == Some("*.a.com"));
        // <<< 242B END T-import-match1 <<< //
        assert!(
            ra.is_some(),
            "default wildcard=true should produce *.a.com, got {:?}",
            rules
        );
    }

    /// 显式 wildcard=false → 落裸域 a.com（非 *.a.com）。
    #[tokio::test]
    async fn rules_import_wildcard_false_bare_domain() {
        use axum::extract::State;
        let state = test_state();
        let body = json!({"action":"block","content":"a.com","wildcard":false}).to_string();
        let resp = rules_import(State(state.clone()), body).await.unwrap();
        assert!(resp.0["added"].as_u64().unwrap() > 0);
        let cfg = state.cfg.read();
        let rules = cfg.get("rules").and_then(Value::as_array).unwrap();
        // >>> 242B BEGIN T-import-match2 >>> //
        let bare = rules
            .iter()
            .any(|r| r.get("match").and_then(Value::as_str) == Some("a.com"));
        let wild = rules
            .iter()
            .any(|r| r.get("match").and_then(Value::as_str) == Some("*.a.com"));
        // <<< 242B END T-import-match2 <<< //
        assert!(
            bare,
            "wildcard=false should produce bare a.com, got {:?}",
            rules
        );
        assert!(!wild, "wildcard=false must NOT produce *.a.com");
    }

    /// forceIp + ip 用例：{"action":"forceIp","ip":"9.9.9.9","content":"f.com"}。
    #[tokio::test]
    async fn rules_import_forceip_with_ip() {
        use axum::extract::State;
        let state = test_state();
        let body = json!({"action":"forceIp","ip":"9.9.9.9","content":"force.example"}).to_string();
        let resp = rules_import(State(state.clone()), body).await.unwrap();
        assert!(resp.0["added"].as_u64().unwrap() > 0);
        let cfg = state.cfg.read();
        let rules = cfg.get("rules").and_then(Value::as_array).unwrap();
        let force = rules
            .iter()
            .find(|r| r.get("ip").and_then(Value::as_str) == Some("9.9.9.9"));
        assert!(
            force.is_some(),
            "forceIp rule with ip should be visible in config"
        );
    }

    /// F2：action=group 不带 group → 兜底 "global"。
    #[tokio::test]
    async fn rules_import_group_defaults_to_global() {
        use axum::extract::State;
        let state = test_state();
        let body = json!({"action":"group","content":"grp.example"}).to_string();
        let resp = rules_import(State(state.clone()), body).await.unwrap();
        assert!(resp.0["added"].as_u64().unwrap() > 0);
        let cfg = state.cfg.read();
        let rules = cfg.get("rules").and_then(Value::as_array).unwrap();
        let g = rules
            .iter()
            .find(|r| r.get("group").and_then(Value::as_str) == Some("global"));
        assert!(
            g.is_some(),
            "group without group field should default to 'global', got {:?}",
            rules
        );
    }

    /// F2：action=forceIp 不带 ip → 兜底 "1.2.3.4"。
    #[tokio::test]
    async fn rules_import_forceip_defaults_ip() {
        use axum::extract::State;
        let state = test_state();
        let body = json!({"action":"forceIp","content":"fi.example"}).to_string();
        let resp = rules_import(State(state.clone()), body).await.unwrap();
        assert!(resp.0["added"].as_u64().unwrap() > 0);
        let cfg = state.cfg.read();
        let rules = cfg.get("rules").and_then(Value::as_array).unwrap();
        let ip = rules
            .iter()
            .any(|r| r.get("ip").and_then(Value::as_str) == Some("1.2.3.4"));
        assert!(
            ip,
            "forceIp without ip should default to 1.2.3.4, got {:?}",
            rules
        );
    }

    /// 空 content（JSON）→ 400。
    #[tokio::test]
    async fn rules_import_empty_content_400() {
        use crate::error::ServerError;
        use axum::extract::State;
        let state = test_state();
        let body = json!({"action":"block","content":""}).to_string();
        let err = rules_import(State(state.clone()), body).await.unwrap_err();
        assert!(matches!(err, ServerError::BadRequest(_)));
    }

    /// 纯文本 body 无可解析域名 → 400。
    #[tokio::test]
    async fn rules_import_plaintext_no_domain_400() {
        use crate::error::ServerError;
        use axum::extract::State;
        let state = test_state();
        let err = rules_import(State(state.clone()), "   \n  ".to_string())
            .await
            .unwrap_err();
        assert!(matches!(err, ServerError::BadRequest(_)));
    }

    /// forceIp 显式非法 ip → 400。
    #[tokio::test]
    async fn rules_import_bad_forceip_400() {
        use crate::error::ServerError;
        use axum::extract::State;
        let state = test_state();
        let body = json!({"action":"forceIp","ip":"not-an-ip","content":"x.example"}).to_string();
        let err = rules_import(State(state.clone()), body).await.unwrap_err();
        assert!(matches!(err, ServerError::BadRequest(_)));
    }

    /// group 显式空串 → 400。
    #[tokio::test]
    async fn rules_import_empty_group_400() {
        use crate::error::ServerError;
        use axum::extract::State;
        let state = test_state();
        let body = json!({"action":"group","group":"","content":"x.example"}).to_string();
        let err = rules_import(State(state.clone()), body).await.unwrap_err();
        assert!(matches!(err, ServerError::BadRequest(_)));
    }

    /* ---------------- 上游 CRUD / 重新测速（本次补齐的两个端点） ---------------- */

    /// 带 upstreams 的状态（`cfg_path=None` → 只改内存，不落盘）。
    fn state_with_upstreams(list: Value) -> AppState {
        let st = test_state();
        *st.cfg.write() = json!({"upstreams": list, "health_probe_timeout_ms": 500});
        st
    }

    /// 一个启用（u1）+ 一个禁用（u2）的上游样例。
    fn sample_ups() -> Value {
        json!([
            {"id": "u1", "name": "a", "proto": "udp", "addr": "127.0.0.1", "port": 1,
             "url": "", "group": "domestic", "latency": 123, "latency_measured": false,
             "enabled": true},
            {"id": "u2", "name": "b", "proto": "udp", "addr": "127.0.0.1", "port": 1,
             "url": "", "group": "domestic", "latency": 456, "latency_measured": false,
             "enabled": false}
        ])
    }

    fn cfg_upstream_list(st: &AppState) -> Vec<Value> {
        st.cfg
            .read()
            .get("upstreams")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    }

    /// **2.1.25（性能项）**：同进程微基准的计时器 —— 返回 `(p50, p90, p99)`（微秒）。
    ///
    /// 只用于 `#[ignore]` 的基准用例（显式 `--ignored --nocapture` 才跑），
    /// 因此**不进**常规测试的确定性判据：这里只打印数字，不做任何"必须更快"的断言
    /// （时间断言在共享机器上必然 flaky；真正的前后对照在隔离阶梯上做）。
    fn bench_pcts<F: FnMut()>(iters: usize, mut f: F) -> (f64, f64, f64) {
        use std::time::Instant;
        let mut v: Vec<f64> = Vec::with_capacity(iters);
        for _ in 0..iters {
            let t0 = Instant::now();
            f();
            v.push(t0.elapsed().as_nanos() as f64 / 1000.0);
        }
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let pick = |p: f64| {
            let k = ((v.len() - 1) as f64 * p / 100.0) as usize;
            v[k.min(v.len() - 1)]
        };
        (pick(50.0), pick(90.0), pick(99.0))
    }

    fn uri_of(p: &str) -> Uri {
        p.parse().unwrap()
    }

    /* ============ **2.1.25（B7 性能项）**：`/api/status.top_upstreams` 的等价性 ============ */

    /// **判据 1**：排序/过滤/截断的**唯一实现**逐条钉死 ——
    /// 过滤 `queries==0` → `queries` 降序 → 同值 `id` 升序 → 前 **10** → `[id, queries]`。
    ///
    /// 这条判据是"两条取数路径不可能分叉"的地基：`/api/status`（直算）与
    /// `/api/snapshot`（先建整表视图再抽取）都只经本函数成形。
    #[test]
    fn top_upstreams_ranked_filters_sorts_tiebreaks_and_truncates() {
        // 12 条非零（100..111）+ 2 条零 ⇒ 必须恰好 10 行、零全部被过滤。
        let mut rows: Vec<(String, u64)> =
            (0..12u64).map(|i| (format!("u{i:02}"), 100 + i)).collect();
        rows.push(("zero-a".to_string(), 0));
        rows.push(("zero-b".to_string(), 0));
        let got = top_upstreams_ranked(rows);
        assert_eq!(got.len(), 10, "必须截断到前 10 行");
        for (k, row) in got.iter().enumerate() {
            let arr = row.as_array().expect("每行必须是 [id, queries] 两元组");
            assert_eq!(arr.len(), 2, "每行必须恰好两个元素");
            // 降序：u11(111) … u02(102)
            assert_eq!(arr[0], json!(format!("u{:02}", 11 - k)), "第 {k} 行 id 错");
            assert_eq!(arr[1], json!(111 - k as u64), "第 {k} 行 queries 错");
        }
        // 同值 ⇒ 按 id 升序（确定性排序：不依赖 HashMap 迭代顺序）。
        assert_eq!(
            top_upstreams_ranked(vec![
                ("b".to_string(), 7),
                ("a".to_string(), 7),
                ("c".to_string(), 7),
            ]),
            vec![json!(["a", 7]), json!(["b", 7]), json!(["c", 7])],
            "同 queries 必须按 id 升序"
        );
        // 全零 ⇒ **空数组**（不是 null、不是把零行留下）。
        assert_eq!(
            top_upstreams_ranked(vec![("a".to_string(), 0)]),
            Vec::<Value>::new(),
            "queries==0 的上游必须被过滤"
        );
        assert_eq!(top_upstreams_ranked(vec![]), Vec::<Value>::new());
    }

    /// **2.1.25（B7）同进程微基准**：`/api/status.top_upstreams` 的**直算** vs
    /// "先造整表逐上游视图再抽两列"。
    ///
    /// 显式运行（8 个上游/22 个上游都行；这里用 22 = 出厂默认条数）：
    /// `cargo test --release -p ebpdns-server --lib bench_top_upstreams -- --ignored --nocapture`
    ///
    /// 只打印数字、不做断言 —— 前后对照的权威数据取自**隔离阶梯 + HTTP A/B**（报告里给）。
    #[test]
    #[ignore = "微基准：需显式 --ignored --nocapture 运行"]
    fn bench_top_upstreams_direct_vs_full_view() {
        use ebpdns_resolver::config::{ResolverConfig, UpstreamCfg};
        use std::sync::Arc;
        let ups: Vec<UpstreamCfg> = (0..22)
            .map(|i| UpstreamCfg::test_up(&format!("bench{i:02}")))
            .collect();
        let st = test_state_with_resolver_cfg(ResolverConfig::test_default(ups, vec![], 1));
        let rt = Arc::new(ebpdns_upstream::UpstreamRuntime::new());
        for i in 0..22u64 {
            let id = format!("bench{i:02}");
            for _ in 0..(i + 1) {
                rt.health.record(&id, true, 1);
            }
        }
        st.resolver.set_runtime(rt);

        let n = 3000;
        // ---- A（2.1.24 路径）：整表视图 + 抽取 ----
        let (a50, a90, a99) = bench_pcts(n, || {
            let views = upstream_views(&st);
            std::hint::black_box(top_upstream_views(&views));
        });
        // ---- B（2.1.25 路径）：直算 ----
        let (b50, b90, b99) = bench_pcts(n, || {
            std::hint::black_box(top_upstreams_direct(&st));
        });
        // 等价性（与耗时无关的硬判据，顺带每次校验）。
        assert_eq!(
            top_upstreams_direct(&st),
            top_upstream_views(&upstream_views(&st))
        );
        println!(
            "\n[B7] upstreams=22 iters={n}\n  A 整表视图 : p50={a50:.2}us p90={a90:.2}us p99={a99:.2}us\n  B 直算     : p50={b50:.2}us p90={b90:.2}us p99={b99:.2}us\n  ratio(p50) = {:.2}x",
            if b50 > 0.0 { a50 / b50 } else { 0.0 }
        );
    }

    /// **判据 2**：`/api/status` 的**直算**路径与 `/api/snapshot` 的"整表视图 + 抽取"路径
    /// **逐位相同**（含排序、截断、零查询过滤），且与真实 `status()` 响应里的
    /// `top_upstreams` 字段逐位相同。
    ///
    /// 这是本性能项的**正确性护栏**：优化只允许"更少的分配"，不允许改口径。
    /// 12 个上游（>10 ⇒ 覆盖截断）、其中 u00 零查询（覆盖过滤）、
    /// 查询数 = `4*i`（覆盖降序）。
    #[tokio::test]
    async fn status_top_upstreams_equals_full_view_path_and_response_field() {
        use axum::extract::State;
        use ebpdns_resolver::config::{ResolverConfig, UpstreamCfg};
        use std::sync::Arc;

        let ups: Vec<UpstreamCfg> = (0..12)
            .map(|i| UpstreamCfg::test_up(&format!("u{i:02}")))
            .collect();
        let st = test_state_with_resolver_cfg(ResolverConfig::test_default(ups, vec![], 1));
        // 真实健康计数：ok = 3*i、fail = i ⇒ queries = 4*i（u00 ⇒ 0）。
        let rt = Arc::new(ebpdns_upstream::UpstreamRuntime::new());
        for i in 0..12u64 {
            let id = format!("u{i:02}");
            for _ in 0..(3 * i) {
                rt.health.record(&id, true, 1);
            }
            for _ in 0..i {
                rt.health.record(&id, false, 1);
            }
        }
        st.resolver.set_runtime(rt);

        // ① 两条**取数**路径的原始行必须一致（同源、同顺序、同计数）。
        let rows_direct = upstream_query_rows(&st);
        let rows_view = top_upstream_rows(&upstream_views(&st));
        assert_eq!(
            rows_direct, rows_view,
            "直算行与整表视图抽取行必须逐位相同（id 顺序与 queries 都要一致）"
        );
        assert_eq!(rows_direct.len(), 12, "12 个上游都要出现在原始行里");

        // ② 成形结果必须一致（覆盖过滤 + 排序 + 截断）。
        let direct = top_upstreams_direct(&st);
        let legacy = top_upstream_views(&upstream_views(&st));
        assert_eq!(direct, legacy, "直算 top-N 与整表视图 top-N 必须逐位相同");
        assert_eq!(direct.len(), 10, "12 个非零上游必须截断到 10 行");
        assert_eq!(direct[0], json!(["u11", 44]), "最大查询数在上，值 = 4*11");
        assert_eq!(direct[9], json!(["u02", 8]), "第 10 行 = u02（u01 被截断）");

        // ③ 真实响应字段必须与直算结果逐位相同（防止 status() 里再走别的路径）。
        let resp = status(State(st.clone())).await;
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(
            v["top_upstreams"],
            Value::Array(direct),
            "`/api/status.top_upstreams` 必须等于直算结果"
        );
    }

    /// 「父路径是普通文件」的非法配置路径：原子写的 tmp 必然写失败（用于回滚路径）。
    fn broken_cfg_path(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("ebpdns-api-test-{}-{tag}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let blocker = dir.join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        let cfg_path = blocker.join("config.json");
        (dir, cfg_path)
    }

    /// **2.1.18（修复项 3）**：`full_addr` 的六协议 + 默认端口 + IPv6 + 路径规则。
    ///
    /// 参照物 = 2.1.17 前端 `web/src/pages/telemetry.rs::full_addr`（同一组用例，
    /// 前端那份现在只作"字段缺失兜底"）。本测试逐条钉死**规则本身**：
    /// - 六协议映射：`udp→udp` / `tcp→tcp` / `doh→https` / `doh3→http3` /
    ///   `dot→tls` / `doq→quic`；
    /// - 端口：`udp/tcp` **恒带**；`doh/doh3` 默认 443、`dot/doq` 默认 853 时**省略**，
    ///   非默认端口一律附 `:port`；
    /// - 路径：**只对 https/http3** 追加（`/dns-query`；完整 URL 只取 path；
    ///   重复斜杠合并、尾部斜杠去掉）；
    /// - IPv6 加方括号（已带方括号不重复加）；`host` 为空退回 `name`。
    #[test]
    fn full_addr_covers_six_protocols_default_ports_ipv6_and_path() {
        let f = |proto: &str, host: &str, port: u16, url: &str| {
            full_addr_parts(proto, host, "", port, url)
        };
        // ---- 六协议 ----
        assert_eq!(f("udp", "223.5.5.5", 53, ""), "udp://223.5.5.5:53");
        assert_eq!(f("tcp", "223.5.5.5", 53, ""), "tcp://223.5.5.5:53");
        assert_eq!(
            f("doh", "dns.alidns.com", 443, "/dns-query"),
            "https://dns.alidns.com/dns-query"
        );
        assert_eq!(
            f("doh3", "dns.alidns.com", 443, "/dns-query"),
            "http3://dns.alidns.com/dns-query"
        );
        assert_eq!(f("dot", "dns.google", 853, ""), "tls://dns.google");
        assert_eq!(f("doq", "dns.alidns.com", 853, ""), "quic://dns.alidns.com");
        // 大小写/空白不敏感（配置里可能写成 "DoH"）。
        assert_eq!(
            f("DoH", "dns.pub", 443, "/dns-query"),
            "https://dns.pub/dns-query"
        );
        // ---- 非默认端口一律显示 ----
        assert_eq!(f("udp", "1.1.1.1", 5353, ""), "udp://1.1.1.1:5353");
        assert_eq!(
            f("doh", "dns.alidns.com", 8443, "/dns-query"),
            "https://dns.alidns.com:8443/dns-query"
        );
        assert_eq!(f("dot", "dns.google", 8853, ""), "tls://dns.google:8853");
        assert_eq!(
            f("doq", "dns.alidns.com", 8853, ""),
            "quic://dns.alidns.com:8853"
        );
        // ---- 路径规则 ----
        // 完整 URL 只取 path；重复斜杠合并、尾部斜杠去掉。
        assert_eq!(
            f("doh", "223.5.5.5", 443, "https://223.5.5.5/dns-query"),
            "https://223.5.5.5/dns-query"
        );
        assert_eq!(
            f("doh", "dns.pub", 443, "//dns//query//"),
            "https://dns.pub/dns/query"
        );
        // 无路径 → 不加多余的 `/`。
        assert_eq!(f("doh", "dns.pub", 443, ""), "https://dns.pub");
        // 裸 DNS 协议即便配置里带了 url 也**不得**拼进来（否则端点根本不存在）。
        assert_eq!(
            f("udp", "223.5.5.5", 53, "/dns-query"),
            "udp://223.5.5.5:53"
        );
        assert_eq!(
            f("dot", "dns.google", 853, "/dns-query"),
            "tls://dns.google"
        );
        // ---- IPv6 ----
        assert_eq!(
            f("doh", "2001:db8::1", 443, "/dns-query"),
            "https://[2001:db8::1]/dns-query"
        );
        assert_eq!(f("udp", "2001:db8::1", 53, ""), "udp://[2001:db8::1]:53");
        // 已带方括号不重复加。
        assert_eq!(f("udp", "[2001:db8::1]", 53, ""), "udp://[2001:db8::1]:53");
        // ---- host 为空 → 退回 name；都为空 → 退化 "://" ----
        assert_eq!(
            full_addr_parts("udp", "", "lan-dns", 53, ""),
            "udp://lan-dns:53"
        );
        assert_eq!(full_addr_parts("udp", "", "", 53, ""), "udp://:53");
        assert_eq!(full_addr_parts("udp", "", "", 0, ""), "udp://");
    }

    /// **2.1.18（修复项 3）**：`/api/upstreams[].full_addr` 必须存在，且与
    /// `/api/snapshot.upstreams[].full_addr` **逐条相等**（单一来源 = `upstream_views`）。
    #[tokio::test]
    async fn upstreams_and_snapshot_expose_identical_full_addr() {
        use axum::extract::State;
        use axum::response::IntoResponse;
        use ebpdns_resolver::config::UpstreamCfg;
        let st = test_state();
        let mut u1 = UpstreamCfg::test_up("fa1");
        u1.proto = "doh".into();
        u1.host = "dns.alidns.com".into();
        u1.port = 443;
        u1.url = "/dns-query".into();
        let mut u2 = UpstreamCfg::test_up("fa2");
        u2.proto = "udp".into();
        u2.host = "192.168.0.235".into();
        u2.port = 53;
        let mut u3 = UpstreamCfg::test_up("fa3");
        u3.proto = "doh3".into();
        u3.host = "2001:db8::1".into();
        u3.port = 8443;
        u3.url = "https://2001:db8::1/dns-query".into();
        st.resolver.reload(ebpdns_resolver::config::ResolverConfig {
            upstreams: vec![u1, u2, u3],
            ..Default::default()
        });

        let listed = upstreams(State(st.clone())).await.into_response();
        let lb = axum::body::to_bytes(listed.into_body(), usize::MAX)
            .await
            .unwrap();
        let lv: Value = serde_json::from_slice(&lb).unwrap();
        let snap = snapshot(State(st.clone())).await.into_response();
        let sb = axum::body::to_bytes(snap.into_body(), usize::MAX)
            .await
            .unwrap();
        let sv: Value = serde_json::from_slice(&sb).unwrap();

        let la = lv["upstreams"].as_array().expect("upstreams[]");
        let sa = sv["upstreams"].as_array().expect("snapshot.upstreams[]");
        assert_eq!(la.len(), 3);
        assert_eq!(sa.len(), 3);
        for (l, s) in la.iter().zip(sa.iter()) {
            assert_eq!(
                l.get("full_addr").and_then(Value::as_str),
                s.get("full_addr").and_then(Value::as_str),
                "两处 full_addr 必须同源同值（单一来源 = upstream_views）: {l} vs {s}"
            );
        }
        let by_id = |v: &Value, id: &str| {
            v["upstreams"]
                .as_array()
                .unwrap()
                .iter()
                .find(|x| x.get("id").and_then(Value::as_str) == Some(id))
                .cloned()
                .unwrap_or(Value::Null)
        };
        assert_eq!(
            by_id(&lv, "fa1")["full_addr"],
            json!("https://dns.alidns.com/dns-query")
        );
        assert_eq!(
            by_id(&lv, "fa2")["full_addr"],
            json!("udp://192.168.0.235:53")
        );
        assert_eq!(
            by_id(&lv, "fa3")["full_addr"],
            json!("http3://[2001:db8::1]:8443/dns-query"),
            "IPv6 方括号 + 非默认端口 + 完整 URL 只取路径"
        );
    }

    /// 优化项 8：`/api/upstreams`（与 `/api/snapshot` 复用同一视图）必须带
    /// `fails` / `until_in_s` / `role` / `eff_lat_ms` / `selectable` / `probe_ok` /
    /// `probe_fail` / `circuit_open_count` 这些只读派生字段，且口径正确：
    /// - 禁用上游 → `selectable=false`、`role=idle`；
    /// - 启用且未熔断 → `selectable=true`；
    /// - 无实测样本 → `eff_lat_ms` 回退配置静态 `latency`（恒为数值，`eff_lat_measured=false`）；
    /// - 起始无熔断 → `fails=0` / `until_in_s=0` / `breaker_open=false`。
    #[tokio::test]
    async fn upstream_views_expose_optimization_readonly_fields() {
        use ebpdns_resolver::config::UpstreamCfg;
        let st = test_state();
        let mut u1 = UpstreamCfg::test_up("ou1");
        u1.latency = 41;
        let mut u2 = UpstreamCfg::test_up("ou2");
        u2.enabled = false;
        st.resolver.reload(ebpdns_resolver::config::ResolverConfig {
            upstreams: vec![u1, u2],
            ..Default::default()
        });
        let views = upstream_views(&st);
        assert_eq!(views.len(), 2);
        let by_id = |id: &str| {
            views
                .iter()
                .find(|v| v.get("id").and_then(Value::as_str) == Some(id))
                .cloned()
                .unwrap_or(Value::Null)
        };
        for k in [
            "fails",
            "until_in_s",
            "role",
            "eff_lat_ms",
            "selectable",
            "probe_ok",
            "probe_fail",
            "circuit_open_count",
            "breaker_open",
        ] {
            assert!(by_id("ou1").get(k).is_some(), "缺优化项 8 字段 {k}");
        }
        let a = by_id("ou1");
        assert_eq!(a["fails"], json!(0));
        assert_eq!(a["until_in_s"], json!(0.0));
        assert_eq!(a["breaker_open"], json!(false));
        assert_eq!(a["selectable"], json!(true));
        assert_eq!(a["role"], json!("primary"));
        assert_eq!(a["probe_ok"], json!(0));
        assert_eq!(a["probe_fail"], json!(0));
        assert_eq!(a["circuit_open_count"], json!(0));
        assert_eq!(
            a["eff_lat_ms"],
            json!(41.0),
            "无实测样本 → 回退配置静态 latency（恒为数值，前端列稳定可用）"
        );
        assert_eq!(a["eff_lat_measured"], json!(false));
        let b = by_id("ou2");
        assert_eq!(b["selectable"], json!(false), "禁用上游不可选");
        assert_eq!(b["role"], json!("idle"), "禁用上游角色为 idle");
    }

    /// 既有缺陷修复回归（2.1.11）：`upstream_views` 的熔断字段必须来自**同一次加锁读**。
    ///
    /// 断言的是**跨字段不变量**（与实现是否两次加锁无关地成立，且旧实现必被此断言抓到）：
    /// 对启用上游恒有 `breaker_open == (until_in_s > 0.0) == !selectable`。
    /// 旧实现先 `cb_is_open` 后 `cb_view`，两次读之间发生探针恢复/数据面失败即违反该式。
    #[test]
    fn upstream_views_breaker_fields_come_from_one_snapshot() {
        use ebpdns_resolver::config::UpstreamCfg;
        let st = test_state();
        let mut u = UpstreamCfg::test_up("snap1");
        u.latency = 10;
        let mut cfg = ebpdns_resolver::config::ResolverConfig {
            upstreams: vec![u],
            ..Default::default()
        };
        cfg.circuit_fails = 3;
        cfg.circuit_open_s = 30.0;
        cfg.circuit_open_max_s = 30.0;
        st.resolver.reload(cfg);

        let snap = || {
            let v = upstream_views(&st);
            let a = v
                .iter()
                .find(|v| v.get("id").and_then(Value::as_str) == Some("snap1"))
                .cloned()
                .expect("snap1 必须在视图里");
            (a, v)
        };
        let check = |a: &Value| {
            let open = a["breaker_open"].as_bool().unwrap();
            let until = a["until_in_s"].as_f64().unwrap();
            let selectable = a["selectable"].as_bool().unwrap();
            assert_eq!(
                open,
                until > 0.0,
                "breaker_open 与 until_in_s 必须同源（实测 {open}/{until}）：{a}"
            );
            assert_eq!(
                selectable, !open,
                "selectable 必须与同一快照的 breaker_open 互补：{a}"
            );
            if open {
                assert!(
                    a["fails"].as_u64().unwrap() >= 3,
                    "打开态 fails 必须已过阈值：{a}"
                );
                assert!(
                    a["circuit_open_count"].as_u64().unwrap() >= 1,
                    "打开态计数不可为 0：{a}"
                );
            }
        };

        // 1) 打开态：3 次数据面失败 → 自洽
        for _ in 0..3 {
            st.resolver.cb_fail("snap1");
        }
        let (a, _) = snap();
        assert_eq!(a["breaker_open"], json!(true));
        check(&a);
        // 2) 探针成功恢复 → 全零，仍自洽（旧实现会在这里留下 breaker_open=true + until_in_s=0）
        assert!(st.resolver.cb_probe_ok("snap1"));
        let (a, _) = snap();
        assert_eq!(a["breaker_open"], json!(false));
        assert_eq!(a["until_in_s"], json!(0.0));
        assert_eq!(a["fails"], json!(0));
        assert_eq!(a["circuit_open_count"], json!(0));
        check(&a);
        // 3) 并发：一边反复「失败打开 / 探针恢复」，一边取视图。
        //    只要投影来自单次快照，跨字段不变量恒成立；两次独立读则必然被抓到矛盾组合。
        let r = st.resolver.clone();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop2 = stop.clone();
        let mutator = std::thread::spawn(move || {
            let mut i = 0u64;
            while !stop2.load(std::sync::atomic::Ordering::Relaxed) {
                if i.is_multiple_of(2) {
                    r.cb_fail("snap1");
                    r.cb_fail("snap1");
                    r.cb_fail("snap1");
                } else {
                    r.cb_probe_ok("snap1");
                }
                i += 1;
            }
            i
        });
        let t0 = std::time::Instant::now();
        let mut n = 0u64;
        let mut seen_open = false;
        let mut seen_closed = false;
        while t0.elapsed() < std::time::Duration::from_millis(300) {
            let (a, all) = snap();
            check(&a);
            // `/api/snapshot` 复用同一视图：同源即同值。
            assert_eq!(all.len(), 1);
            let open = a["breaker_open"].as_bool().unwrap();
            seen_open |= open;
            seen_closed |= !open;
            n += 1;
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let iters = mutator.join().expect("并发喂点线程 panic");
        assert!(
            n > 0 && iters > 0,
            "并发路径未被覆盖（n={n}, iters={iters}）"
        );
        assert!(
            seen_open && seen_closed,
            "两种熔断态都必须被观察到（open={seen_open} closed={seen_closed}）"
        );
    }

    /// **2.1.16（修复项 8）：两个 SERVFAIL 指标族不得相加**（2.1.15 的口径误读）。
    ///
    /// 缺陷本体：2.1.15 把聚合值与 5 档明细写在**同一个**指标名下，只靠
    /// `reason="all"` 区分 ⇒ 抓取器上 `sum(ebpdns_servfail_total)` **正好翻倍**
    /// （部署代理实测踩到）。本测试锁死三件事：
    /// 1. 聚合 series **无标签**（`ebpdns_servfail_total N` 一行）；
    /// 2. 分档 series 在**另一个指标名**下（`ebpdns_servfail_reasons_total{reason=…}`）；
    /// 3. 语义关系是 `Σ(分档) == 聚合`（"相等"而非"需相加"），且旧标签写法不存在。
    #[tokio::test]
    async fn s8_servfail_metric_families_must_not_be_summed() {
        use axum::extract::State;
        use axum::response::IntoResponse;
        let st = test_state();
        // 喂 5 档各 1 次（走数据面唯一打点入口 `note_servfail`）：
        // 聚合必须是 5，分档之和也必须是 5。
        for r in crate::telemetry::SERVFAIL_REASONS {
            st.telemetry.note_servfail(r);
        }
        let resp = metrics(State(st.clone())).await.into_response();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let t = String::from_utf8(body.to_vec()).unwrap();

        // 1) 聚合 series：唯一一行，且**无标签**。
        let agg_lines: Vec<&str> = t
            .lines()
            .filter(|l| l.starts_with("ebpdns_servfail_total"))
            .collect();
        assert_eq!(
            agg_lines.len(),
            1,
            "聚合 series 必须唯一且无标签（否则求和会翻倍）: {agg_lines:?}"
        );
        assert_eq!(
            agg_lines[0], "ebpdns_servfail_total 5",
            "5 档各一次 ⇒ 聚合必须为 5: {agg_lines:?}"
        );
        assert!(
            !t.contains("ebpdns_servfail_total{"),
            "聚合 series 绝不允许带任何标签（旧 reason=\"all\" 写法即翻倍根因）"
        );

        // 2) 分档 series：在**另一个**指标名下，Σ == 聚合。
        let mut sum = 0u64;
        let mut n = 0;
        for l in t.lines() {
            if let Some(rest) = l.strip_prefix("ebpdns_servfail_reasons_total{reason=\"") {
                let v: u64 = rest
                    .split_whitespace()
                    .last()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                sum += v;
                n += 1;
            }
        }
        assert_eq!(n, 5, "必须输出固定 5 档分档 series");
        assert_eq!(
            sum, 5,
            "Σ(各 reason) 必须等于聚合值（相等关系，不得再相加）"
        );
        // 3) HELP 文本必须显式警告"不得相加"。
        assert!(
            t.contains("MUST NOT be added"),
            "HELP 必须写明两族不得相加: \n{t}"
        );
    }

    /// 优化项 6：`/api/status.counters` 必须暴露 `breaker_all_open` 与物理上游请求计数。
    #[tokio::test]
    async fn status_counters_expose_breaker_and_physical_upstream_counts() {
        use axum::extract::State;
        use axum::response::IntoResponse;
        let st = test_state();
        let resp = status(State(st.clone())).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        let c = &v["counters"];
        for k in [
            "breaker_all_open",
            // **2.1.19（修复项 5-⑨）**：预取"全部熔断"状态（布尔瞬时值 + 只增计数）。
            "prefetch_all_open",
            "prefetch_degraded_total",
            "upstream_requests",
            "upstream_early_return",
            "upstream_hedge",
            "upstream_queries",
            // A7：派发口径 vs 真实线速口径（旧键必须继续存在，见下一行断言）。
            "upstream_dispatch",
            "upstream_wire_requests",
            // A7：数据面真实字节数（2.1.8 恒 0）。
            "bytes_in",
            "bytes_out",
            // **2.1.15（P1）**：客户端可见 SERVFAIL 总数 + 5 档互斥原因（同一出口打点）。
            "servfail_total",
            "servfail_reasons",
        ] {
            assert!(c.get(k).is_some(), "counters 缺字段 {k}: {c:?}");
        }
        // 2.1.15：不变式 —— 总数等于各档之和（空快照下两者都为 0）。
        assert_eq!(
            c["servfail_reasons"]
                .as_object()
                .map(|m| m.values().filter_map(Value::as_u64).sum::<u64>())
                .unwrap_or(0),
            c["servfail_total"].as_u64().unwrap_or(0),
            "servfail_total 必须等于各档之和: {c:?}"
        );
        assert_eq!(
            c["servfail_reasons"].as_object().map(|m| m.len()),
            Some(crate::telemetry::SERVFAIL_REASONS.len()),
            "原因维度必须补齐固定 5 档（便于页面/脚本稳定取值）: {c:?}"
        );
        // **2.1.16（修复项 8）**：`client_rcode` 是 16 槽定长分布（键 "0".."15"），
        // 且与 `servfail_total` 存在硬等式（同点打点）：`client_rcode["2"] == servfail_total`。
        assert_eq!(
            c["client_rcode"].as_object().map(|m| m.len()),
            Some(16),
            "client_rcode 必须是 16 槽定长分布（键 \"0\"..\"15\"）: {c:?}"
        );
        assert_eq!(
            c["client_rcode"]["2"], c["servfail_total"],
            "硬等式：client_rcode[\"2\"] 必须等于 servfail_total（同一打点）: {c:?}"
        );
        assert_eq!(
            c["breaker_all_open"],
            json!(st.resolver.cb_all_open_count())
        );
        assert_eq!(
            c["upstream_requests"],
            json!(st.resolver.upstream_requests())
        );
        // 2.1.12（A 的 ①）：RFC 8020 独立口径同样出现在 counters 里，且与 resolver 同源。
        assert_eq!(c["rfc8020_hits"], json!(st.resolver.rfc8020_hits()));
        assert_eq!(
            c["rfc8020_registrations"],
            json!(st.resolver.rfc8020_registrations())
        );
        assert_eq!(c["rfc8020_len"], json!(st.resolver.rfc8020_len()));
    }

    /// A7：`/metrics` 必须补齐上游维度 / 缓存条目 / 负缓存 / 真实字节数，
    /// 且**前 5 项旧指标逐字保留**（旧抓取器与既有仪表盘契约不破）。
    #[tokio::test]
    async fn metrics_exposes_a7_dimensions_and_keeps_legacy_five() {
        use axum::extract::State;
        use axum::response::IntoResponse;
        let st = test_state();
        // 造一点逐上游延迟与负缓存命中，验证新指标真的会输出。
        st.telemetry.push_upstream_latency("up-1", 3.0);
        st.telemetry.push_upstream_latency("up-1", 40.0);
        st.telemetry.push_upstream_latency("up\"2\\x\n", 700.0); // 标签转义用例
                                                                 // >>> 242B BEGIN T-metrics-hit >>> //
                                                                 // 负缓存命中是 hit 的子集：先记一次 hit（P1-7 不变量）。
        st.telemetry.inc_n("hit", 1);
        st.telemetry.count_neg_hit();
        // <<< 242B END T-metrics-hit <<< //
        st.telemetry.inc_n("bytes_in", 1234);
        st.telemetry.inc_n("bytes_out", 5678);

        let resp = metrics(State(st.clone())).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let t = String::from_utf8(body.to_vec()).unwrap();

        // ---- 旧 5 项：名字 + TYPE 逐字保留 ----
        for legacy in [
            "# TYPE ebpdns_queries_total counter",
            "# TYPE ebpdns_cache_hits_total counter",
            "# TYPE ebpdns_cache_misses_total counter",
            "# TYPE ebpdns_errors_total counter",
            "# TYPE ebpdns_uptime_seconds gauge",
        ] {
            assert!(t.contains(legacy), "旧指标缺失/被改名: {legacy}\n{t}");
        }
        // ---- A7 新指标 ----
        for new in [
            "ebpdns_bytes_in_total 1234",
            "ebpdns_bytes_out_total 5678",
            "ebpdns_upstream_dispatch_total ",
            "ebpdns_upstream_wire_requests_total ",
            "ebpdns_upstream_requests_total ",
            "ebpdns_upstream_early_return_total ",
            "ebpdns_upstream_hedge_total ",
            "ebpdns_cache_entries ",
            "ebpdns_cache_capacity ",
            "ebpdns_cache_negative_hits_total 1",
            "ebpdns_negcache_hit_ratio ",
            // 2.1.12：A 的 ① 的独立口径（counter + HELP/TYPE 齐备）。
            "# HELP ebpdns_rfc8020_hits_total ",
            "# TYPE ebpdns_rfc8020_hits_total counter",
            "ebpdns_rfc8020_hits_total ",
            "# TYPE ebpdns_rfc8020_registrations_total counter",
            "ebpdns_rfc8020_registrations_total ",
            // **2.1.19（修复项 5-⑨）**：预取"全部熔断"状态从周期性 WARN 收敛为状态字段。
            "# HELP ebpdns_prefetch_all_open ",
            "# TYPE ebpdns_prefetch_all_open gauge",
            "ebpdns_prefetch_all_open ",
            "# TYPE ebpdns_prefetch_degraded_total counter",
            "ebpdns_prefetch_degraded_total ",
            "# TYPE ebpdns_upstream_latency_ms histogram",
            "ebpdns_upstream_latency_ms_bucket{id=\"up-1\",le=\"1\"} 0",
            "ebpdns_upstream_latency_ms_bucket{id=\"up-1\",le=\"5\"} 1",
            "ebpdns_upstream_latency_ms_bucket{id=\"up-1\",le=\"50\"} 2",
            "ebpdns_upstream_latency_ms_bucket{id=\"up-1\",le=\"+Inf\"} 2",
            "ebpdns_upstream_latency_ms_sum{id=\"up-1\"} 43.000",
            "ebpdns_upstream_latency_ms_count{id=\"up-1\"} 2",
            "ebpdns_upstream_latency_ms_quantile{id=\"up-1\",quantile=\"0.5\"}",
            "ebpdns_upstream_latency_ms_quantile{id=\"up-1\",quantile=\"0.9\"}",
            "ebpdns_upstream_latency_ms_quantile{id=\"up-1\",quantile=\"0.99\"}",
            // **2.1.15（P1）/ 2.1.16（修复项 8）**：SERVFAIL 聚合 + 5 档原因
            // （**两个不同的指标名**，避免"求和翻倍"误读）+ 单上游在途闸门。
            "# HELP ebpdns_servfail_total ",
            "# TYPE ebpdns_servfail_total counter",
            "ebpdns_servfail_total 0",
            "# HELP ebpdns_servfail_reasons_total ",
            "# TYPE ebpdns_servfail_reasons_total counter",
            "ebpdns_servfail_reasons_total{reason=\"upstream_timeout\"} 0",
            "ebpdns_servfail_reasons_total{reason=\"upstream_no_answer\"} 0",
            "ebpdns_servfail_reasons_total{reason=\"no_upstream\"} 0",
            "ebpdns_servfail_reasons_total{reason=\"encode_failed\"} 0",
            "ebpdns_servfail_reasons_total{reason=\"panic\"} 0",
            // 2.1.16（修复项 8）：客户端 rcode 分布（服务端侧自证）。
            "# TYPE ebpdns_client_rcode_total counter",
            "ebpdns_client_rcode_total{rcode=\"2\"} 0",
            "# TYPE ebpdns_upstream_inflight_limit gauge",
            "ebpdns_upstream_inflight_limit ",
            "# TYPE ebpdns_upstream_inflight_acquired_total counter",
            "ebpdns_upstream_inflight_acquired_total ",
            "# TYPE ebpdns_upstream_inflight_queued_total counter",
            "ebpdns_upstream_inflight_queued_total ",
            "# TYPE ebpdns_upstream_inflight_rejected_total counter",
            "ebpdns_upstream_inflight_rejected_total ",
            // **2.1.17（修复项 7）**：排队吃光预算（拿到了许可但已来不及）的独立计数。
            "# HELP ebpdns_upstream_inflight_queued_gave_up_total ",
            "# TYPE ebpdns_upstream_inflight_queued_gave_up_total counter",
            "ebpdns_upstream_inflight_queued_gave_up_total ",
            // **2.1.17（修复项 3）**：私网答案过滤（设计行为可观测）。
            "# HELP ebpdns_cache_skipped_private_total ",
            "# TYPE ebpdns_cache_skipped_private_total counter",
            "ebpdns_cache_skipped_private_total ",
            // **2.1.17（修复项 4）/ 2.1.18（修复项 2）**：抓取时刻锚点（非指标，注释形式）。
            // 2.1.19 起首行追加 `seq=`（同代快照代数）⇒ 断言改为"含 seq= 与 monotonic_ms="。
            "# align-snapshot seq=",
            " monotonic_ms=",
        ] {
            assert!(t.contains(new), "A7 指标缺失: {new}\n{t}");
        }
        // **2.1.16（修复项 8）**：旧写法（同一指标名下的 `reason="all"` 聚合 series）
        // 必须**彻底消失** —— 它正是"求和翻倍"误读的来源。
        assert!(
            !t.contains("ebpdns_servfail_total{reason="),
            "旧聚合 series `ebpdns_servfail_total{{reason=...}}` 必须已删除（否则 sum 会翻倍）\n{t}"
        );
        // ---- label 转义：不得出现裸引号/裸换行破坏文本协议 ----
        assert!(
            t.contains(r#"id="up\"2\\x\n""#),
            "上游 id 的 Prometheus label 未正确转义\n{t}"
        ); // 除转义序列外，任何指标行都不得含裸 `\n`（协议要求一行一指标）。
        for line in t.lines() {
            if line.starts_with("ebpdns_") {
                assert!(!line.contains('\r'), "指标行含 CR: {line}");
            }
        }
        // 无上游样本时不应出现空的逐上游段（`upstream_views` 为空 → 不输出表头）。
        let st2 = test_state();
        let resp2 = metrics(State(st2)).await.into_response();
        let b2 = axum::body::to_bytes(resp2.into_body(), usize::MAX)
            .await
            .unwrap();
        let t2 = String::from_utf8(b2.to_vec()).unwrap();
        assert!(
            !t2.contains("# TYPE ebpdns_upstream_latency_ms histogram"),
            "无逐上游延迟样本时不应输出直方图表头"
        );
    }

    /// A7：**全链**（真实 `upstream_views` → `/metrics`）验证含 `"` / `\` 的上游 id
    /// 被正确转义，且抓取器侧能按 label 解析回来。
    ///
    /// 必须走 `resolver.reload(...)`（而不是只改 `AppState.cfg`）：`upstream_views`
    /// 的数据源是 **resolver 自己的 config**（`s.resolver.config()`），
    /// 只改 `st.cfg` 的话 `upstream_views` 仍为空 → 逐上游段根本不输出（空转测试）。
    #[tokio::test]
    async fn metrics_escapes_hostile_upstream_ids_end_to_end() {
        use axum::extract::State;
        use axum::response::IntoResponse;
        use ebpdns_resolver::config::UpstreamCfg;
        // 上游 id 是控制台可写字段：构造一个含引号 + 反斜杠 + 空格的"敌意" id。
        let hostile = "up\"2\\x y";
        let mut u = UpstreamCfg::test_up("placeholder");
        u.id = hostile.to_string();
        let st = test_state();
        st.resolver.reload(ebpdns_resolver::config::ResolverConfig {
            upstreams: vec![u],
            ..Default::default()
        });
        // 前置断言：视图里确实有这条上游（否则下面的"转义正确"没有意义）。
        let views = upstream_views(&st);
        assert_eq!(views.len(), 1, "reload 后应有 1 条上游视图: {views:?}");
        assert_eq!(views[0]["id"], json!(hostile));

        let resp = metrics(State(st)).await.into_response();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let t = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            t.contains("# TYPE ebpdns_upstream_requests_total_by_id counter"),
            "逐上游段缺失\n{t}"
        );
        // **2.1.41**：family 名与样本名必须一致（此前样本写成聚合名 ⇒ `_by_id` 空、
        // 聚合 `sum()` 双计）。至少一条 `_by_id{id=...}` 样本行，且聚合 family
        // **不得**出现带 `id=` 标签的样本。
        assert!(
            t.lines()
                .any(|l| l.starts_with("ebpdns_upstream_requests_total_by_id{id=")),
            "缺少 `ebpdns_upstream_requests_total_by_id{{id=…}}` 样本\n{t}"
        );
        assert!(
            !t.lines()
                .any(|l| l.starts_with("ebpdns_upstream_requests_total{id=")),
            "逐上游样本不得挂在聚合 family 上（会双计）\n{t}"
        );
        // 转义后的 id 必须原样出现在 label 里。
        let want = format!("id=\"{}\"", prom_label_escape(hostile));
        assert!(t.contains(&want), "转义后的 id 未出现: {want}\n{t}");
        // 关键协议约束：id 的原文（裸引号）**绝不**出现在任何指标行里，
        // 且每行引号必须成对（转义引入的 `\"` 不算分隔符）——否则抓取器截断该行。
        let bare = format!("id=\"{hostile}\"");
        for line in t.lines().filter(|l| l.starts_with("ebpdns_")) {
            assert!(!line.contains(&bare), "裸敌意 id 泄漏进指标行: {line}");
            let mut in_quote = false;
            let mut prev = '\0';
            for ch in line.chars() {
                if ch == '"' && prev != '\\' {
                    in_quote = !in_quote;
                }
                prev = ch;
            }
            assert!(!in_quote, "指标行引号未闭合（协议损坏）: {line}");
        }
    }

    /// A7：Prometheus 文本转义/桶边界纯函数契约。
    ///
    /// 既有缺陷修复（2.1.11）：`#[test]` 原来被写在上一行 doc 注释的**同一行**
    /// （`/// …契约。    #[test]`），整行被当成文档注释 → 本用例**从未被执行**，
    /// 只留下 `function is never used` 警告。修好后它作为真正的门槛参与全量测试。
    #[test]
    fn prom_escape_and_bucket_labels_are_protocol_safe() {
        assert_eq!(prom_label_escape("plain"), "plain");
        assert_eq!(prom_label_escape(r#"a"b"#), r#"a\"b"#);
        assert_eq!(prom_label_escape(r"a\b"), r"a\\b");
        assert_eq!(prom_label_escape("a\nb"), r"a\nb");
        assert_eq!(prom_label_escape(""), "");
        assert_eq!(
            prom_label_escape("a\rb"),
            "a\rb",
            "CR 不是 Prometheus 转义字符"
        );
        // 回归：**不能**用 `contains(['\\','"','\n'])` 当快路径 ——
        // 那是"三字符连续子串"语义，会让单个引号/反斜杠漏转义。
        assert_eq!(prom_label_escape("\""), "\\\"");
        assert_eq!(prom_label_escape("\\"), "\\\\");
        assert_eq!(prom_label_escape("\n"), "\\n");
        assert_eq!(prom_label_escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
        // `le` 整数不带小数点，小数保留原样（同一桶形状稳定）。
        assert_eq!(prom_le(1.0), "1");
        assert_eq!(prom_le(10.0), "10");
        assert_eq!(prom_le(1000.0), "1000");
        assert_eq!(prom_le(2.5), "2.5");
    }

    /// 重新测速：只探测**已启用**上游；无 runtime（test_state）时全部按失败处理，
    /// 且失败必须保留原 latency。
    #[tokio::test]
    async fn reprobe_probes_enabled_only_and_preserves_latency() {
        let st = state_with_upstreams(sample_ups());
        let out = reprobe_impl(&st, None).await.unwrap();
        assert_eq!(out["ok"], json!(true));
        let results = out["results"].as_array().unwrap();
        assert_eq!(results.len(), 1, "只探测已启用上游: {results:?}");
        let row = results[0].as_object().unwrap();
        let mut keys: Vec<&str> = row.keys().map(|k| k.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["addr", "id", "name", "new", "ok", "old", "proto"],
            "响应行字段契约 {{id,name,proto,addr,old,new,ok}}"
        );
        assert_eq!(row["id"], json!("u1"));
        assert_eq!(row["name"], json!("a"));
        assert_eq!(row["proto"], json!("udp"));
        assert_eq!(row["addr"], json!("127.0.0.1"));
        assert_eq!(row["old"], json!(123));
        assert_eq!(row["ok"], json!(false), "无 runtime → 探测失败");
        assert_eq!(row["new"], json!(123), "失败保留原 latency");
        let list = cfg_upstream_list(&st);
        assert_eq!(list[0]["latency"], json!(123));
        assert_eq!(list[0]["latency_measured"], json!(false));
        assert_eq!(list[1]["latency"], json!(456), "禁用上游不被探测、不被改写");
        assert_eq!(list[1]["latency_measured"], json!(false));
    }

    /// 重新测速：`upstreams` 畸形 → 502 `{"error":"reprobe failed"}`。
    #[tokio::test]
    async fn reprobe_malformed_config_502() {
        let st = test_state();
        *st.cfg.write() = json!({"upstreams": "nope"});
        match reprobe(State(st)).await {
            Err(ServerError::BadGateway(m)) => assert_eq!(m, "reprobe failed"),
            Err(e) => panic!("期望 502 BadGateway, 得到 {e}"),
            Ok(_) => panic!("期望 502 BadGateway, 得到 200"),
        }
    }

    /// **[历史归因]** 重新测速：无待测上游 → `{"ok":true,"results":[]}`（Python probe.py:115-116）。
    #[tokio::test]
    async fn reprobe_no_enabled_upstream_empty_results() {
        let st = state_with_upstreams(json!([
            {"id": "u2", "name": "b", "proto": "udp", "addr": "127.0.0.1", "port": 1, "enabled": false}
        ]));
        let out = reprobe_impl(&st, None).await.unwrap();
        assert_eq!(out["ok"], json!(true));
        assert_eq!(out["results"], json!([]));
    }

    /// POST 手动分支：缺 id → `u<epoch_ms>_<6 位 base36>`；latency=0/未实测；响应/落库一致。
    #[tokio::test]
    async fn upstream_add_manual_branch_generates_contract_id() {
        let st = test_state();
        let v = upstream_add(
            &st,
            json!({"addr": "1.1.1.1", "proto": "udp", "name": "cf"}),
        )
        .await
        .unwrap();
        assert_eq!(v["ok"], json!(true));
        // 对齐 v1.9.162：`addr` 非空即走自动识别分支（`parse_upstream_addr("1.1.1.1")`
        // 返回 proto=udp/port=53，故 `auto_parsed` 必须为 true）。手动分支只对畸形
        // addr（空串、`[]`、未知 scheme）才可达。
        assert_eq!(v["auto_parsed"], json!(true));
        let up = &v["upstream"];
        assert_eq!(up["name"], json!("cf"));
        assert_eq!(up["proto"], json!("udp"));
        assert_eq!(up["addr"], json!("1.1.1.1"));
        assert_eq!(up["port"], json!(53));
        assert_eq!(up["url"], json!(""));
        assert_eq!(up["group"], json!("domestic"));
        assert_eq!(up["latency"], json!(0), "新上游 latency=0（待实测）");
        assert_eq!(up["latency_measured"], json!(false));
        assert_eq!(up["enabled"], json!(true));
        let id = up["id"].as_str().unwrap();
        assert!(id.starts_with('u'), "id 前缀 u: {id}");
        let (ms, suffix) = id[1..]
            .split_once('_')
            .expect("id 形态 u<epoch_ms>_<base36>");
        assert!(
            ms.len() >= 12 && ms.chars().all(|c| c.is_ascii_digit()),
            "epoch_ms: {ms}"
        );
        assert_eq!(suffix.chars().count(), 6, "6 位 base36: {suffix}");
        assert!(suffix
            .chars()
            .all(|c| c.is_ascii_digit() || c.is_ascii_lowercase()));
        assert!(
            id.chars().count() <= 64,
            "id 必须过 _UPSTREAM_ID_RE 字符集/长度"
        );
        let list = cfg_upstream_list(&st);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0], *up);
    }

    /// POST 自动识别分支：scheme://host/path、裸主机 + proto_sel、显式 port 覆盖、`[v6]:port`。
    #[tokio::test]
    async fn upstream_add_auto_parse_branches() {
        let st = test_state();
        let v = upstream_add(&st, json!({"addr": "https://dns.google/dns-query"}))
            .await
            .unwrap();
        assert_eq!(v["auto_parsed"], json!(true));
        assert_eq!(v["upstream"]["proto"], json!("doh"));
        assert_eq!(v["upstream"]["addr"], json!("dns.google"));
        assert_eq!(v["upstream"]["port"], json!(443));
        assert_eq!(v["upstream"]["url"], json!("/dns-query"));

        // 裸主机 + proto_sel=doh → 协议默认端口 443 + /dns-query
        let v = upstream_add(&st, json!({"addr": "dns.google", "proto": "doh"}))
            .await
            .unwrap();
        assert_eq!(v["auto_parsed"], json!(true));
        assert_eq!(v["upstream"]["port"], json!(443));
        assert_eq!(v["upstream"]["url"], json!("/dns-query"));

        // 显式 port 覆盖解析默认端口（addr 未内嵌端口）
        let v = upstream_add(
            &st,
            json!({"addr": "dns.google", "proto": "doh", "port": 8443}),
        )
        .await
        .unwrap();
        assert_eq!(v["upstream"]["port"], json!(8443));

        // addr 内嵌 host:port → body port 不覆盖
        let v = upstream_add(&st, json!({"addr": "1.1.1.1:5353", "port": 9999}))
            .await
            .unwrap();
        assert_eq!(v["upstream"]["port"], json!(5353));

        // [v6]:port
        let v = upstream_add(&st, json!({"addr": "[::1]:5300"}))
            .await
            .unwrap();
        assert_eq!(v["upstream"]["addr"], json!("::1"));
        assert_eq!(v["upstream"]["port"], json!(5300));

        // udp:// scheme → url 恒空
        let v = upstream_add(&st, json!({"addr": "udp://8.8.8.8:53"}))
            .await
            .unwrap();
        assert_eq!(v["upstream"]["proto"], json!("udp"));
        assert_eq!(v["upstream"]["url"], json!(""));
    }

    /// POST 校验：缺 addr/name、类型/范围/字符集/长度非法 → 400，且一律不落库。
    #[tokio::test]
    async fn upstream_add_validation_400s() {
        let st = test_state();
        let cases: Vec<Value> = vec![
            json!({}),
            json!({"name": 0}),
            json!({"addr": 123}),
            json!({"addr": "1.1.1.1", "proto": "bogus"}),
            json!({"addr": "1.1.1.1", "port": 0}),
            json!({"addr": "1.1.1.1", "port": 70000}),
            json!({"addr": "1.1.1.1", "port": "abc"}),
            json!({"addr": "1.1.1.1", "port": true}),
            json!({"addr": "bad host"}),
            json!({"addr": "1.1.1.1", "name": "x".repeat(257)}),
            json!({"addr": "1.1.1.1", "group": 5}),
            json!({"addr": "1.1.1.1", "weight": 1001}),
            json!({"addr": "example.com:", "proto": "doh", "url": "/a\nb"}),
        ];
        for c in cases {
            let err = upstream_add(&st, c.clone()).await.unwrap_err();
            assert!(
                matches!(&err, UpstreamApiError::BadRequest(_)),
                "应 400（BadRequest）: {c:?} → {err:?}"
            );
        }
        assert!(cfg_upstream_list(&st).is_empty(), "非法请求不得落库");
    }

    /// POST：显式 id（合法 → 原样落库；重复/字符集非法 → 400）；白名单外的键不落库。
    #[tokio::test]
    async fn upstream_add_explicit_id_and_whitelist_filter() {
        let st = state_with_upstreams(sample_ups());
        let err = upstream_add(&st, json!({"id": "u1", "addr": "1.1.1.1"}))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, UpstreamApiError::BadRequest(m) if m.contains("重复")),
            "重复 id 必须 400: {err:?}"
        );
        let err = upstream_add(&st, json!({"id": "bad id!", "addr": "1.1.1.1"}))
            .await
            .unwrap_err();
        assert!(matches!(err, UpstreamApiError::BadRequest(_)));
        // 合法显式 id + 未知键：id 原样保留，未知键（GET /api/upstreams 回传的派生字段）丢弃。
        let v = upstream_add(
            &st,
            json!({"id": "my.up-1", "addr": "1.1.1.1", "queries": 9, "success_rate": 100.0}),
        )
        .await
        .unwrap();
        assert_eq!(v["upstream"]["id"], json!("my.up-1"));
        assert!(v["upstream"].get("queries").is_none(), "白名单外字段不落库");
        assert!(v["upstream"].get("success_rate").is_none());
    }

    /// PUT：合并 + 归一（数字字符串/宽松布尔），未提供字段保持不变。
    #[tokio::test]
    async fn upstream_update_merges_and_normalizes() {
        let st = state_with_upstreams(sample_ups());
        let v = upstream_update_apply(
            &st,
            "u1",
            json!({"name": "renamed", "latency": "250", "enabled": "false", "doh_strict_cert": "maybe"}),
        )
        .await
        .unwrap();
        assert_eq!(v["upstream"]["name"], json!("renamed"));
        assert_eq!(v["upstream"]["latency"], json!(250));
        assert_eq!(v["upstream"]["enabled"], json!(false));
        // 畸形 strict_cert → 兜底 true（安全方向）
        assert_eq!(v["upstream"]["doh_strict_cert"], json!(true));
        assert_eq!(
            v["upstream"]["addr"],
            json!("127.0.0.1"),
            "未提供字段保持原值"
        );
        assert_eq!(v["upstream"]["id"], json!("u1"));
        let list = cfg_upstream_list(&st);
        assert_eq!(list[0]["name"], json!("renamed"));
        assert_eq!(list[0]["latency"], json!(250));
        assert_eq!(list[1]["name"], json!("b"), "其余上游不受影响");
    }

    /// PUT：改 id / 未知字段 / 越界值 → 400（且不留下半更新状态）。
    #[tokio::test]
    async fn upstream_update_rejects_id_unknown_field_and_bad_values() {
        let st = state_with_upstreams(sample_ups());
        let cases: Vec<Value> = vec![
            json!({"id": "u9"}),
            json!({"bogus": 1}),
            json!({"port": 0}),
            json!({"port": 70000}),
            json!({"latency": 3_600_001}),
            json!({"latency": true}),
            json!({"proto": "bogus"}),
            json!({"addr": "bad host"}),
            json!({"name": 5}),
            json!({"group": 5}),
            json!({"weight": "heavy"}),
            json!({"weight": 1001}),
            json!({"url": "/a\nb"}),
        ];
        for c in cases {
            let err = upstream_update_apply(&st, "u1", c.clone())
                .await
                .unwrap_err();
            assert!(
                matches!(&err, UpstreamApiError::BadRequest(_)),
                "应 400（BadRequest）: {c:?} → {err:?}"
            );
        }
        assert_eq!(
            cfg_upstream_list(&st)[0],
            sample_ups()[0],
            "校验失败不得留下半更新状态"
        );
    }

    /// PUT/DELETE：id 不存在 → 404（`upstream not found`）。
    #[tokio::test]
    async fn upstream_update_delete_missing_404() {
        let st = state_with_upstreams(sample_ups());
        let err = upstream_update_apply(&st, "nope", json!({"name": "x"}))
            .await
            .unwrap_err();
        assert_eq!(err, UpstreamApiError::NotFound);
        let err = upstream_delete_apply(&st, "nope").await.unwrap_err();
        assert_eq!(err, UpstreamApiError::NotFound);
        assert_eq!(cfg_upstream_list(&st).len(), 2);
    }

    /// DELETE：成功返回 `{"ok":true}` 并落库移除。
    #[tokio::test]
    async fn upstream_delete_removes_upstream() {
        let st = state_with_upstreams(sample_ups());
        let v = upstream_delete_apply(&st, "u2").await.unwrap();
        assert_eq!(v, json!({"ok": true}));
        let list = cfg_upstream_list(&st);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["id"], json!("u1"));
    }

    /// 写盘失败：create/update/delete 一律 500 语义 + **内存回滚**（与磁盘一致）。
    #[tokio::test]
    async fn upstream_write_failure_rolls_back_memory() {
        let (dir, bad) = broken_cfg_path("rollback");
        let mut st = state_with_upstreams(sample_ups());
        st.cfg_path = Some(bad);
        // 新增：回滚 → 仍是 2 条
        let err = upstream_add(&st, json!({"addr": "1.1.1.1"}))
            .await
            .unwrap_err();
        assert_eq!(err, UpstreamApiError::WriteFailed);
        assert_eq!(cfg_upstream_list(&st).len(), 2, "新增必须回滚内存");
        // 更新：回滚 → 名称仍是原值
        let err = upstream_update_apply(&st, "u1", json!({"name": "nope"}))
            .await
            .unwrap_err();
        assert_eq!(err, UpstreamApiError::WriteFailed);
        assert_eq!(cfg_upstream_list(&st)[0]["name"], json!("a"));
        // 删除：回滚 → 上游仍在
        let err = upstream_delete_apply(&st, "u1").await.unwrap_err();
        assert_eq!(err, UpstreamApiError::WriteFailed);
        assert_eq!(cfg_upstream_list(&st).len(), 2, "删除必须回滚内存");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **[历史归因]** HTTP 层：404/400/500 的响应体逐字对齐 Python（含 `{"ok":false}` 伴生键）。
    #[tokio::test]
    async fn upstream_handlers_status_and_bodies() {
        let (dir, bad) = broken_cfg_path("http");
        let mut st = state_with_upstreams(sample_ups());
        st.cfg_path = Some(bad);
        // 500：配置写盘失败（已回滚内存变更）
        let resp = upstreams_create(State(st.clone()), Json(json!({"addr": "1.1.1.1"}))).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["ok"], json!(false));
        assert_eq!(v["error"], json!("配置写盘失败（已回滚内存变更）"));
        // 404：upstream not found
        let resp = upstream_update(
            State(st.clone()),
            uri_of("/api/upstreams/nope"),
            Json(json!({"name": "x"})),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"], json!("upstream not found"));
        // 400：缺 addr/name
        let resp = upstreams_create(State(st.clone()), Json(json!({}))).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        // 200：删除成功（cfg_path=None 的状态 → 只改内存）
        let ok_st = state_with_upstreams(sample_ups());
        let resp = upstream_delete(State(ok_st.clone()), uri_of("/api/upstreams/u2")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v, json!({"ok": true}));
        assert_eq!(cfg_upstream_list(&ok_st).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 重新测速：写盘失败 → 内存回滚（latency/latency_measured 都不落内存）。
    #[tokio::test]
    async fn reprobe_persist_failure_rolls_back_memory() {
        let (dir, bad) = broken_cfg_path("reprobe-rollback");
        let mut st = state_with_upstreams(sample_ups());
        st.cfg_path = Some(bad);
        // 无 runtime → 探测全失败；写回 latency_measured=false + 落盘失败 → 回滚
        let err = reprobe_impl(&st, None).await.unwrap_err();
        assert!(err.contains("persist"), "写盘失败必须报错: {err}");
        let list = cfg_upstream_list(&st);
        assert_eq!(list[0]["latency"], json!(123));
        assert_eq!(list[0]["latency_measured"], json!(false));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 重新测速：`only=Some(id)` 只探测该上游（POST 新增测速复用）。
    #[tokio::test]
    async fn reprobe_only_selected_id() {
        let st = state_with_upstreams(json!([
            {"id": "u1", "name": "a", "proto": "udp", "addr": "127.0.0.1", "port": 1,
             "latency": 11, "enabled": true},
            {"id": "u2", "name": "b", "proto": "udp", "addr": "127.0.0.1", "port": 1,
             "latency": 22, "enabled": true}
        ]));
        let out = reprobe_impl(&st, Some("u2")).await.unwrap();
        let results = out["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["id"], json!("u2"));
        assert_eq!(results[0]["old"], json!(22));
    }

    /// 探测超时取值：缺省 2000、下限 500、上限 60s（配置完整性回归）。
    #[test]
    fn probe_timeout_default_floor_and_cap() {
        assert_eq!(probe_timeout_ms(&json!({})), 2000, "缺省 2000");
        assert_eq!(
            probe_timeout_ms(&json!({"health_probe_timeout_ms": 1})),
            500,
            "下限 500"
        );
        assert_eq!(
            probe_timeout_ms(&json!({"health_probe_timeout_ms": "3000"})),
            3000
        );
        assert_eq!(
            probe_timeout_ms(&json!({"health_probe_timeout_ms": null})),
            2000
        );
        assert_eq!(
            probe_timeout_ms(&json!({"health_probe_timeout_ms": 10_000_000})),
            60_000
        );
    }

    /// 畸形超时配置 + 无 runtime 时：端点仍即时返回 200，探测全失败且保留 latency（不 panic/不挂死）。
    #[tokio::test]
    async fn reprobe_absurd_timeout_config_is_bounded() {
        let st = test_state();
        *st.cfg.write() = json!({
            "health_probe_timeout_ms": 1,
            "upstreams": [{"id": "u1", "proto": "udp", "addr": "127.0.0.1", "port": 1,
                           "latency": 77, "enabled": true}]
        });
        let out = reprobe_impl(&st, None).await.unwrap();
        assert_eq!(out["results"].as_array().unwrap().len(), 1);
        assert_eq!(out["results"][0]["ok"], json!(false));
        assert_eq!(out["results"][0]["new"], json!(77));
        assert_eq!(cfg_upstream_list(&st)[0]["latency"], json!(77));
    }

    /// **2.1.17（修复项 4）**：`/api/status` 必须给出**同点取值**的快照时序三元组，
    /// 且三者自洽；`/metrics` 首部必须给出同量纲的 `# align-snapshot` 锚点。
    ///
    /// 判据（对应 2.1.16 首轮 1055 条 / 0.5% 余量无法归因的根因）：
    /// 1. `snapshot_monotonic_ms` / `snapshot_epoch_ms` / `snapshot_uptime_s` 三个键
    ///    必须**同时**存在（缺任一个，压测脚本就无法把两侧窗口对齐）；
    /// 2. `monotonic_ms / 1000 ≈ uptime_s`（同一 `boot` 基准，容差 1s）；
    /// 3. `epoch_ms - monotonic_ms` = 进程启动的墙钟时刻，必须是**过去**的合理值；
    /// 4. `/metrics` 第一行必须是 `# align-snapshot monotonic_ms=… epoch_ms=… uptime_s=…`
    ///    且 `monotonic_ms` 与 `/api/status` **同量纲**（同源函数，差值应远小于 5s）。
    #[tokio::test]
    async fn snapshot_time_anchor_is_present_consistent_and_matches_metrics() {
        let st = test_state();
        let resp = status(State(st.clone())).await.into_response();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();

        let mono = v["snapshot_monotonic_ms"].as_u64();
        let epms = v["snapshot_epoch_ms"].as_u64();
        let up_s = v["snapshot_uptime_s"].as_u64();
        assert!(
            mono.is_some() && epms.is_some() && up_s.is_some(),
            "三个快照时序键必须同时存在：{v:?}"
        );
        let (mono, epms, up_s) = (mono.unwrap(), epms.unwrap(), up_s.unwrap());

        // 2) 同源（同一 boot 基准）。
        let drift = (mono as f64 / 1000.0 - up_s as f64).abs();
        assert!(
            drift < 1.0,
            "monotonic_ms 与 uptime_s 必须同源：mono/1000={} uptime_s={}",
            mono as f64 / 1000.0,
            up_s
        );
        // 3) boot 墙钟在"过去"且合理（2020-09 之后）。
        let boot_epoch = epms - mono;
        assert!(
            boot_epoch > 1_600_000_000_000 && boot_epoch <= epms,
            "boot_epoch 必须是过去的合理时刻：{boot_epoch}"
        );

        // 4) /metrics 锚点。
        let mresp = metrics(State(st.clone())).await.into_response();
        let mbody = axum::body::to_bytes(mresp.into_body(), usize::MAX)
            .await
            .unwrap();
        let mt = String::from_utf8(mbody.to_vec()).unwrap();
        let first = mt.lines().next().unwrap_or("");
        // **2.1.18（修复项 2）**：首行追加 `seq=`（同代快照的代数）。
        // 因此判据从"以 `monotonic_ms=` 开头"改成"含 `seq=` 且含 `monotonic_ms=`"。
        assert!(
            first.starts_with("# align-snapshot seq="),
            "/metrics 首行必须是带 seq 的 align-snapshot 锚点，实测：{first}"
        );
        assert!(
            first.contains(" monotonic_ms="),
            "/metrics 锚点必须同时带取数时刻，实测：{first}"
        );
        let mmono: u64 = first
            .split("monotonic_ms=")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse().ok())
            .expect("锚点必须可解析出 monotonic_ms");
        let mseq: u64 = first
            .split("seq=")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse().ok())
            .expect("锚点必须可解析出 seq（2.1.19）");
        // **2.1.18（修复项 9）**：`seq` 是**计数器写入代数**（只在写入时 +1，
        // 读取不推进）⇒ 刚启动、尚无计数写入时它是 0，这是**正确**的。
        // 真正要钉死的是它与 `/api/status.snapshot_seq` **同源同值**。
        assert_eq!(
            mseq,
            v["snapshot_seq"].as_u64().unwrap_or(u64::MAX),
            "metrics 锚点的 seq 必须与 /api/status.snapshot_seq 完全一致：{first}"
        );
        // 同源同量纲：两次抓取之间的间隔不可能达到 5s。
        let d = (mmono as i64 - mono as i64).unsigned_abs();
        assert!(
            d < 5_000,
            "metrics 锚点与 /api/status 锚点必须同量纲（同源单调钟）：Δ={d}ms"
        );
        // **2.1.23（DEF-222-B01，修既有失败用例）**：**端点内的**顺序不变量是
        // "`/metrics` 自己的锚点 <= `/metrics` 自己的 counters 取数时刻"
        //（`metrics()` 的第一句就是取锚点，见本文件 `:3099-3110`）。
        //
        // 本用例**先调 `/api/status`、后调 `/metrics`**，因此 `mmono` 必然**晚于**
        // `mono`（两次调用之间至少隔着一次完整的 `/api/status` 处理）。
        // 2.1.22 在这里断言的 `mmono <= mono` 只在"两次抓取落在同一毫秒"时才偶然成立
        // ⇒ 在 2.1.22 的**交付树上稳定失败**（实测 `anchor=2 status=0`、
        // `anchor=3 status=0`，重跑 3/3 失败；与本次改动无关）。
        //
        // 现在按**可证的真不变量**断言，并把"端点内顺序"单独钉住：
        // ① 同一单调钟 + 同一量纲（上面 `d < 5_000` 已覆盖，且 `mmono >= mono`
        //    是"metrics 在 status 之后被调用"的直接推论）；
        // ② **端点内**锚点下界：`/metrics` 的锚点不得晚于它自己的 counters 快照时刻
        //    —— 判据是"首行的锚点 <= 该次响应里任一计数器的取数时刻"，而后者正是
        //    同一响应体内的 `snapshot_seq` 对应代；这里用"锚点 >= 调用前"与
        //    "锚点 <= 调用后"两侧夹住（两次 `monotonic_ms()` 夹逼），从而证明
        //    锚点确实取自**本次** `/metrics` 调用内部、且不晚于它的 counters。
        let after = st.telemetry.monotonic_ms();
        assert!(
            mmono >= mono && mmono <= after,
            "`/metrics` 锚点必须落在**两次抓取之间**（同一单调钟、本次调用内取值）：\
             anchor={mmono} status={mono} after={after}"
        );
    }

    /// **2.1.18（修复项 2）**：`/api/status` 的 `snapshot_seq` + 三条**同代硬等式**。
    ///
    /// 对应 2.1.17 交付报告错误清单 **E5**（同一 `/api/status` 里
    /// `Σ counters.client_rcode` 与 `counters.total` 偶尔差 1）。判据：
    /// 1. `snapshot_seq` 存在且**单调递增**（跨两次抓取必须严格变大）；
    /// 2. 同一次响应内 `Σ client_rcode == total`；
    /// 3. 同一次响应内 `client_rcode["2"] == servfail_total == Σ servfail_reasons`；
    /// 4. 同一次响应内 `hit + miss <= total`；
    /// 5. `/metrics` 首行 `seq=` 与 `/api/status.snapshot_seq` **同量纲**（都来自
    ///    `ServerTelemetry::snapshot_seq`，后者更大或相等）。
    #[tokio::test]
    async fn status_snapshot_seq_and_counters_hard_equalities_hold() {
        use axum::extract::State;
        use axum::response::IntoResponse;
        let st = test_state();
        // 制造非零计数：**只走数据面唯一出口**（`note_data_plane_outcome` 同时计
        // `total` 与一条 rcode）。不要在这里额外调 `count_query("resolve")` ——
        // 那会给 `total` 加一条**没有 rcode** 的查询，使 `Σ client_rcode == total`
        // 这条硬等式在测试夹具层面不成立（首轮实测就撞上了）。
        for i in 0..20u64 {
            if i % 2 == 0 {
                st.telemetry.note_data_plane_outcome(Some(0), None, 0);
            } else {
                st.telemetry
                    .note_data_plane_outcome(Some(2), Some("upstream_timeout"), 1);
            }
        }
        let read_status = |st: crate::state::AppState| async move {
            let r = status(State(st)).await.into_response();
            let b = axum::body::to_bytes(r.into_body(), usize::MAX)
                .await
                .unwrap();
            serde_json::from_slice::<Value>(&b).unwrap()
        };
        let v1 = read_status(st.clone()).await;
        let v2 = read_status(st.clone()).await;

        let s1 = v1["snapshot_seq"].as_u64().expect("snapshot_seq 必须存在");
        let s2 = v2["snapshot_seq"].as_u64().expect("snapshot_seq 必须存在");
        // **2.1.18（修复项 9）**：`seq` = **写入代数**（读取不推进）⇒
        // 两次连续抓取（其间无写入）必须**相等**，这正是"允许逐字段差分"的判据。
        assert_eq!(s2, s1, "两次抓取之间无计数写入 ⇒ seq 不得变化：{s1} → {s2}");
        // 有写入则必须前进（用一次真实出口调用验证）。
        st.telemetry.note_data_plane_outcome(Some(0), None, 0);
        let v3 = read_status(st.clone()).await;
        let s3 = v3["snapshot_seq"].as_u64().expect("snapshot_seq 必须存在");
        assert!(s3 > s2, "发生计数写入后 seq 必须递增：{s2} → {s3}");

        for (name, v) in [("v1", &v1), ("v2", &v2)] {
            let c = &v["counters"];
            let sum_rcode: u64 = c["client_rcode"]
                .as_object()
                .unwrap()
                .values()
                .filter_map(Value::as_u64)
                .sum();
            // **2.1.18（修复项 9）**：这是**恒等式**（`total` 与 rcode 同分支自增），
            // 因此断言用严格相等；若 `no_response_total > 0` 则说明本用例里存在
            // "登记但无可发送报文"的出口调用（见专门的用例）。
            assert_eq!(
                sum_rcode,
                c["total"].as_u64().unwrap(),
                "[{name}] 硬等式 Σ client_rcode == total 被破坏: {c:?}"
            );
            assert_eq!(
                c["no_response_total"].as_u64().unwrap(),
                0,
                "[{name}] 本用例所有出口调用都构造出了应答 ⇒ 差额项必须为 0: {c:?}"
            );
            assert_eq!(
                c["client_rcode"]["2"], c["servfail_total"],
                "[{name}] 硬等式 client_rcode[\"2\"] == servfail_total 被破坏: {c:?}"
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
                "[{name}] 硬等式 servfail_total == Σ servfail_reasons 被破坏: {c:?}"
            );
            assert!(
                c["hit"].as_u64().unwrap() + c["miss"].as_u64().unwrap()
                    <= c["total"].as_u64().unwrap(),
                "[{name}] 硬等式 hit + miss <= total 被破坏: {c:?}"
            );
            // `client_rcode` 仍是 16 槽定长分布（键 "0".."15"）。
            assert_eq!(c["client_rcode"].as_object().map(|m| m.len()), Some(16));
        }
        // 计数语义：20 次数据面出口（10×rcode0 + 10×rcode2）、20 次 total。
        assert_eq!(v2["counters"]["total"], json!(20));
        assert_eq!(v2["counters"]["client_rcode"]["0"], json!(10));
        assert_eq!(v2["counters"]["client_rcode"]["2"], json!(10));
        assert_eq!(v2["counters"]["servfail_total"], json!(10));
        assert_eq!(
            v2["counters"]["cache_skipped_private_total"],
            json!(10),
            "每次 SERVFAIL 都带 1 条私网过滤"
        );

        // 5) /metrics 的 `seq` 与 status 同源（同一计数器，metrics 抓取更晚 ⇒ 更大或相等）。
        let mresp = metrics(State(st.clone())).await.into_response();
        let mbody = axum::body::to_bytes(mresp.into_body(), usize::MAX)
            .await
            .unwrap();
        let mt = String::from_utf8(mbody.to_vec()).unwrap();
        let first = mt.lines().next().unwrap_or("");
        let mseq: u64 = first
            .split("seq=")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse().ok())
            .expect("metrics 首行必须带可解析的 seq");
        assert!(
            mseq >= s2,
            "metrics.seq 必须 >= 之前读到的 status.seq（同一计数器）：{mseq} vs {s2}"
        );
        // `/metrics` 的聚合值与分档值必须来自同一代（Σ 分档 == 聚合）。
        let agg: u64 = mt
            .lines()
            .find(|l| l.starts_with("ebpdns_servfail_total "))
            .and_then(|l| l.split_whitespace().last())
            .and_then(|s| s.parse().ok())
            .expect("聚合 series 必须存在");
        let mut per = 0u64;
        for l in mt.lines() {
            if let Some(rest) = l.strip_prefix("ebpdns_servfail_reasons_total{reason=\"") {
                per += rest
                    .split_whitespace()
                    .last()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
            }
        }
        assert_eq!(agg, 10, "聚合值必须等于实际 SERVFAIL 数：{mt}");
        assert_eq!(per, agg, "Σ(分档) 必须等于聚合（同代快照）：\n{mt}");
        // `client_rcode{rcode="2"}` 与聚合同代。
        assert!(
            mt.contains("ebpdns_client_rcode_total{rcode=\"2\"} 10"),
            "rcode=2 必须与 servfail_total 同代同值：\n{mt}"
        );
    }

    /// **2.1.18（修复项 9）**：`total == Σ client_rcode` 是**恒等式**；
    /// 唯一的"登记但无可发送报文"情形由 `no_response_total` 显式承接。
    ///
    /// 背景（本轮修掉的真缺陷）：`total` 此前有**两个**自增点（`resolve()` 入口 +
    /// 出口的 `!outcome.resolved` 分支），而 `client_rcode` 只在出口按
    /// `resp.len() >= 12` 自增 ⇒ 部署实例实测 `total = 2×Σrcode + 256`
    /// （×2 是 2.1.19 引入的第二自增点；256 是控制面/预热等**不产生客户端应答**的
    /// `resolve()` 调用）。现在 `total` 只有一个自增点，等式恒成立。
    #[tokio::test]
    async fn status_total_equals_sum_client_rcode_exactly() {
        use axum::extract::State;
        use axum::response::IntoResponse;
        let st = test_state();
        // ① 三条出口各 3 条真应答（`resp.len() >= 12`）：total 与 rcode 同步 +1。
        for i in 0..9u64 {
            match i % 3 {
                0 => st.telemetry.note_data_plane_outcome(Some(0), None, 0),
                1 => st.telemetry.note_data_plane_outcome(Some(3), None, 0),
                _ => st
                    .telemetry
                    .note_data_plane_outcome(Some(2), Some("upstream_timeout"), 1),
            }
        }
        // ② "登记但无可发送报文"（`rcode = None`）：total 不动，差额项 +1。
        st.telemetry
            .note_data_plane_outcome(None, Some("encode_failed"), 0);
        // ③ 控制面 `/api/query`：不经过数据面出口 ⇒ 对 total/rcode 均无影响
        //    （这里用 `inc_n("hit")` 表示"控制面只动自己的键"）。
        st.telemetry.inc_n("hit", 1);

        let read = |st: crate::state::AppState| async move {
            let r = status(State(st)).await.into_response();
            let b = axum::body::to_bytes(r.into_body(), usize::MAX)
                .await
                .unwrap();
            serde_json::from_slice::<Value>(&b).unwrap()
        };
        let v = read(st.clone()).await;
        let c = &v["counters"];
        let sum: u64 = c["client_rcode"]
            .as_object()
            .unwrap()
            .values()
            .filter_map(Value::as_u64)
            .sum();
        assert_eq!(sum, 9, "9 条真应答 ⇒ Σ rcode = 9：{c:?}");
        assert_eq!(
            c["total"],
            json!(9),
            "**恒等式**：total 必须等于 Σ client_rcode（无应答的那条只进差额项）：{c:?}"
        );
        assert_eq!(
            c["no_response_total"],
            json!(1),
            "『登记但无可发送报文』必须落在差额项里（可对账）：{c:?}"
        );
        assert_eq!(
            c["total"].as_u64().unwrap() + c["no_response_total"].as_u64().unwrap(),
            10,
            "出口登记数 == total + no_response_total：{c:?}"
        );
        // 可证的三条仍然必须成立。
        assert_eq!(c["client_rcode"]["2"], c["servfail_total"], "{c:?}");
        assert_eq!(
            c["servfail_reasons"]
                .as_object()
                .unwrap()
                .values()
                .filter_map(Value::as_u64)
                .sum::<u64>(),
            c["servfail_total"].as_u64().unwrap(),
            "{c:?}"
        );
    }

    /// **2.1.17（修复项 3）**：`cache_skipped_private_total` 必须在
    /// `/api/status.counters` 与 `/metrics` 两处**同源同值**。
    #[tokio::test]
    async fn cache_skipped_private_is_same_source_in_status_and_metrics() {
        let st = test_state();
        st.telemetry.count_cache_skipped_private(3);
        let resp = status(State(st.clone())).await.into_response();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["counters"]["cache_skipped_private_total"],
            json!(3),
            "/api/status.counters.cache_skipped_private_total 必须反映数据面打点"
        );
        let mresp = metrics(State(st.clone())).await.into_response();
        let mbody = axum::body::to_bytes(mresp.into_body(), usize::MAX)
            .await
            .unwrap();
        let mt = String::from_utf8(mbody.to_vec()).unwrap();
        assert!(
            mt.contains("ebpdns_cache_skipped_private_total 3"),
            "/metrics 必须与 /api/status 同源：\n{mt}"
        );
        assert!(
            mt.contains("# HELP ebpdns_cache_skipped_private_total"),
            "该指标必须有 HELP（写清它是设计行为、不是缓存缺陷）"
        );
        // 与 rebind_blocked 是两个不同的门：这里不得被写。
        assert_eq!(
            v["counters"]["rebind_blocked"],
            json!(0),
            "数据面私网过滤不得写控制面的 rebind_blocked"
        );
    }

    /// **2.1.17（修复项 2）**：`ebpdns_query_latency_ms` 的 HELP 必须**精确**写明
    /// 窗口定义（400 条、单位 ms、与 `avg_latency_ms` 同源、不是上游 RTT），
    /// 且桶边界固定为 1/2/5/10/25/50/100/250/500/1000 + `+Inf`。
    ///
    /// 判据来源：2.1.16 登记"HELP 自称 same window 却看似差 3 个数量级" ——
    /// 含糊的 HELP 是误读的直接诱因，因此把口径写进 HELP 并用单测钉死。
    #[tokio::test]
    async fn query_latency_help_states_window_and_buckets_exactly() {
        let st = test_state();
        // 清空窗口后推 6 条样本（只能用公开 API：`push_latency`）。
        st.telemetry.reset();
        for v in [0.5_f64, 3.0, 7.0, 30.0, 300.0, 3000.0] {
            st.telemetry.push_latency(v);
        }
        let mresp = metrics(State(st.clone())).await.into_response();
        let mbody = axum::body::to_bytes(mresp.into_body(), usize::MAX)
            .await
            .unwrap();
        let mt = String::from_utf8(mbody.to_vec()).unwrap();
        let help = mt
            .lines()
            .find(|l| l.starts_with("# HELP ebpdns_query_latency_ms"))
            .expect("必须有 HELP");
        for kw in [
            "milliseconds",
            "LATENCY_WINDOW_MAX",
            "400",
            "SAME ring buffer",
            "/api/status.avg_latency_ms",
            "_sum/_count",
            "NOT the upstream RTT",
            "ebpdns_upstream_latency_ms",
            "cumulative",
        ] {
            assert!(
                help.contains(kw),
                "HELP 必须精确描述窗口/单位/同源关系，缺少 {kw:?}：\n{help}"
            );
        }
        // 桶边界（累积语义）+ +Inf == _count。
        for le in ["1", "2", "5", "10", "25", "50", "100", "250", "500", "1000"] {
            assert!(
                mt.contains(&format!("ebpdns_query_latency_ms_bucket{{le=\"{le}\"}}")),
                "缺少 le={le} 桶"
            );
        }
        assert!(
            mt.contains("ebpdns_query_latency_ms_bucket{le=\"+Inf\"} 6"),
            "+Inf 桶必须等于样本数 6：\n{mt}"
        );
        assert!(
            mt.contains("ebpdns_query_latency_ms_count 6"),
            "_count 必须等于样本数 6"
        );
        // 累积单调 + sum/count == avg_latency（同源硬等式）。
        let sum: f64 = mt
            .lines()
            .find(|l| l.starts_with("ebpdns_query_latency_ms_sum "))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .expect("必须有 _sum");
        let avg = st.telemetry.avg_latency_ms();
        assert!(
            (sum / 6.0 - avg).abs() < 0.06,
            "_sum/_count 必须等于 avg_latency_ms：{} vs {}",
            sum / 6.0,
            avg
        );
        // 桶计数必须累积单调不减。
        let mut prev = 0u64;
        for le in ["1", "2", "5", "10", "25", "50", "100", "250", "500", "1000"] {
            let n: u64 = mt
                .lines()
                .find(|l| l.starts_with(&format!("ebpdns_query_latency_ms_bucket{{le=\"{le}\"}}")))
                .and_then(|l| l.split_whitespace().last())
                .and_then(|s| s.parse().ok())
                .unwrap();
            assert!(n >= prev, "桶必须累积单调：le={le} n={n} prev={prev}");
            prev = n;
        }
    }

    /// **2.1.17**：`ebpdns_rule_hits_total{match_type,action}` 必须与
    /// `/api/status.rule_hits`（一维 action 表）**总量恒等**（可对账）。
    #[tokio::test]
    async fn rule_hits_two_dims_reconcile_with_status_rule_hits() {
        let st = test_state();
        st.telemetry.rule_hit_by_kind("exact", "block");
        st.telemetry.rule_hit_by_kind("wild_suffix", "block");
        st.telemetry.rule_hit_by_kind("regex", "allow");
        let resp = status(State(st.clone())).await.into_response();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        let one_dim: u64 = v["rule_hits"]
            .as_object()
            .unwrap()
            .values()
            .filter_map(Value::as_u64)
            .sum();
        let mresp = metrics(State(st.clone())).await.into_response();
        let mbody = axum::body::to_bytes(mresp.into_body(), usize::MAX)
            .await
            .unwrap();
        let mt = String::from_utf8(mbody.to_vec()).unwrap();
        let two_dim: u64 = mt
            .lines()
            .filter(|l| l.starts_with("ebpdns_rule_hits_total{"))
            .filter_map(|l| l.split_whitespace().last())
            .filter_map(|s| s.parse::<u64>().ok())
            .sum();
        assert_eq!(two_dim, 3, "三条命中必须落在二维指标里：\n{mt}");
        assert_eq!(
            two_dim, one_dim,
            "二维聚合总量必须等于 /api/status.rule_hits 的各键之和（可对账）"
        );
        for want in [
            "ebpdns_rule_hits_total{match_type=\"exact\",action=\"block\"} 1",
            "ebpdns_rule_hits_total{match_type=\"wild_suffix\",action=\"block\"} 1",
            "ebpdns_rule_hits_total{match_type=\"regex\",action=\"allow\"} 1",
        ] {
            assert!(mt.contains(want), "缺少 {want}\n{mt}");
        }
    }

    /// **2.1.41（/api/history 核查）**：`/api/history` 与 `/api/telemetry/history`
    /// **不是**契约端点（前端 `web/src` 只调 `/api/snapshot`，历史曲线读
    /// `snapshot.history[]`）。未知 `/api/*` 必须 **404 + JSON**（不得落到 SPA
    /// 回退，否则拼错的接口会返回 index.html 被当 JSON 解析）；真实历史端点必须
    /// 非空且 `qps` 非 0（2.1.40 的 QPS 恒 0 回归会让曲线全 0）。
    #[tokio::test]
    async fn history_aliases_are_404_and_snapshot_history_is_the_real_endpoint() {
        use axum::extract::State;
        use axum::response::IntoResponse;
        use ebpdns_resolver::telemetry::Telemetry as _;

        let st = test_state();
        for path in ["/api/history", "/api/telemetry/history"] {
            let resp = static_handler(State(st.clone()), Uri::from_static(path))
                .await
                .into_response();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path} 必须 404");
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let v: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(v["error"], json!("not found"), "{path} 必须是 404 JSON");
        }
        // 真实端点：/api/snapshot.history[]。
        st.telemetry.note_client_query();
        st.telemetry.sample_point();
        let resp = snapshot(State(st.clone())).await.into_response();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        let history = v["history"].as_array().expect("history 必须是数组");
        assert!(!history.is_empty(), "历史曲线不得为空：{v}");
        let last = history.last().unwrap();
        assert!(
            last["qps"].as_f64().unwrap_or(0.0) >= 1.0,
            "history[].qps 不得为 0（2.1.40 回归）：{last}"
        );
        assert!(last["label"].as_f64().unwrap_or(0.0) > 1_600_000_000.0);
        // >>> 242B BEGIN T-api >>> //
        assert_eq!(
            last["label_text"].as_str().map(str::len),
            Some(8),
            "label_text 必须 HH:MM:SS：{last}"
        );
    }
    /// **2.1.42-B（P0-2）测试夹具**：v3 形态（config.json **无** `rules` 镜像）+
    /// 真源 `rules_local.json` 里已有 `n` 条本地规则。
    fn p0_2_state(dir: &std::path::Path, n: usize) -> AppState {
        let mut state = test_state();
        state.cfg_path = Some(dir.join("config.json"));
        *state.cfg.write() = json!({});
        let rules: Vec<Value> = (0..n)
            .map(|i| json!({"id": format!("r{i}"), "match": format!("local{i}.test"), "action": "block"}))
            .collect();
        std::fs::write(
            dir.join("rules_local.json"),
            serde_json::to_vec(&json!({"version": 1, "rules": rules})).unwrap(),
        )
        .expect("write rules_local.json");
        state
    }

    fn p0_2_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "ebpdns_api_242b_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|x| x.as_millis())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&d).expect("mkdir");
        d
    }

    /// **P0-2**：v3 形态（`config.json` 无 rules 镜像）下，导入 1 条必须**合并**到
    /// 真源里的 100 条 ⇒ 101；旧的"仅本次导入"覆盖会让本地规则永久丢失。
    #[tokio::test]
    async fn p0_2_import_merges_100_local_plus_1() {
        let dir = p0_2_dir("merge");
        let state = p0_2_state(&dir, 100);
        let body =
            json!({"action": "block", "content": "new.example", "wildcard": false}).to_string();
        let out = rules_import_mode(state.clone(), None, body)
            .await
            .expect("import merge ok");
        assert_eq!(out.0["total"], json!(101), "100 本地 + 1 导入 = 101");
        let cfg_rules = state.cfg.read()["rules"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert_eq!(cfg_rules.len(), 101, "内存 cfg rules 必须 101 条");
        let disk: Value =
            serde_json::from_slice(&std::fs::read(dir.join("rules_local.json")).unwrap()).unwrap();
        assert_eq!(
            disk["rules"].as_array().map(|a| a.len()),
            Some(101),
            "真源必须 101 条"
        );
        assert!(
            state.resolver.match_rule("local0.test").is_some(),
            "旧规则必须仍在索引里"
        );
        assert!(state.resolver.match_rule("new.example").is_some());
        // 备份必须写出（原始字节）。
        assert!(
            dir.join("rules_local.json.pre-import.bak").is_file(),
            "导入前必须有备份"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **P0-2**：只有显式 `?mode=replace` 才允许把真源覆盖成"仅本次导入"。
    #[tokio::test]
    async fn p0_2_import_mode_replace_overwrites() {
        let dir = p0_2_dir("replace");
        let state = p0_2_state(&dir, 100);
        let body =
            json!({"action": "block", "content": "only.example", "wildcard": false}).to_string();
        let out = rules_import_mode(state.clone(), Some("replace".to_string()), body)
            .await
            .expect("import replace ok");
        assert_eq!(out.0["total"], json!(1), "mode=replace ⇒ 1");
        let disk: Value =
            serde_json::from_slice(&std::fs::read(dir.join("rules_local.json")).unwrap()).unwrap();
        assert_eq!(disk["rules"].as_array().map(|a| a.len()), Some(1));
        assert!(
            state.resolver.match_rule("local0.test").is_none(),
            "旧规则应按 replace 移除"
        );
        assert!(state.resolver.match_rule("only.example").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **P0-2**：写盘失败必须回滚**原文件字节**（不是重新序列化），内存 cfg 也还原。
    #[tokio::test]
    async fn p0_2_import_failure_restores_original_bytes() {
        let dir = p0_2_dir("rollback");
        let state = p0_2_state(&dir, 100);
        let src = dir.join("rules_local.json");
        let original = std::fs::read(&src).unwrap();
        // 让第二次写（config.json）必然失败：把目标路径做成目录。
        std::fs::create_dir_all(dir.join("config.json")).unwrap();
        let body =
            json!({"action": "block", "content": "new.example", "wildcard": false}).to_string();
        let res = rules_import_mode(state.clone(), None, body).await;
        assert!(res.is_err(), "写盘失败必须返回错误（不得 200 假成功）");
        assert_eq!(
            std::fs::read(&src).unwrap(),
            original,
            "失败必须回滚**原文件字节**"
        );
        let cfg_rules = state.cfg.read()["rules"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert_eq!(cfg_rules.len(), 100, "内存 cfg 也必须回滚到 100 条");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **P1-8**：`/api/reset` 单一入口清空全部计数器（含 resolver 侧与顶层
    /// `udp_dropped`），reset 后 `counters` 全 0 且 `hit+miss+... == total == 0`。
    #[tokio::test]
    async fn p1_8_reset_clears_every_counter_and_udp_dropped() {
        use axum::extract::State;
        let state = test_state();
        state.resolver.querier_tuning().note_dispatch();
        state.resolver.querier_tuning().note_dispatch();
        state
            .udp_dropped
            .store(7, std::sync::atomic::Ordering::Relaxed);
        state.telemetry.inc_n("miss", 3);
        state.telemetry.inc_n("udp_dropped", 2);
        assert!(state.resolver.upstream_requests() >= 2);
        let _ = reset(State(state.clone()), Some(Json(json!({"confirm": true}))))
            .await
            .expect("reset");
        let c = state.telemetry.counters();
        for k in crate::telemetry::COUNTER_KEYS {
            if matches!(k, "servfail_reasons" | "client_rcode") {
                continue;
            }
            assert_eq!(c[k], json!(0), "reset 后 counters.{k} 必须为 0: {c:?}");
        }
        assert_eq!(
            c["total"].as_u64(),
            Some(0),
            "hit+miss+policy+rule == total == 0"
        );
        assert_eq!(
            state.udp_dropped.load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(c["udp_dropped"], json!(0));
        assert_eq!(
            state.resolver.upstream_requests(),
            0,
            "resolver 13 counters 必须清空"
        );
        let st = status(State(state.clone())).await;
        let b = axum::body::to_bytes(st.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(
            v["udp_dropped"], v["counters"]["udp_dropped"],
            "顶层 udp_dropped 必须等于 counters.udp_dropped"
        );
    }

    /// **2.1.43-A（P2：`/api/logs` 游标差一）**：游标 = "下一条起始 seq"。
    ///
    /// 写入 10 条（生产 `seq` 从 0 开始 ⇒ `0..=9`）：`cursor=5` ⇒ 返回**第 6..10 条**
    /// （`seq` 5..=9）；再取一次（`cursor=10`）⇒ **空批**且游标**不回退**（2.1.42
    /// 在空批时把游标回退到 1，前端会整段重放）。
    #[test]
    fn logs_cursor_is_next_start_seq_and_never_regresses() {
        let events: Vec<Value> = (0..10)
            .map(|i| ev(i, 100.0 + i as f64, "a.com", "A", 1.0))
            .collect();
        let q = |next_seq: Option<u64>, since: Option<u64>| LogsQuery {
            next_seq,
            since,
            since_ts: None,
            q: None,
            level: None,
            domain: None,
            qtype: None,
            ip: None,
            answer: None,
            upstream: None,
            rule: None,
            min_lat: None,
            limit: None,
        };
        // cursor=5 ⇒ 第 6..10 条（seq 5,6,7,8,9）；不重（不含 4）不漏。
        let out = filter_events(events.clone(), &q(Some(5), None));
        let seqs: Vec<u64> = out.iter().map(|e| e["seq"].as_u64().unwrap()).collect();
        assert_eq!(seqs, vec![5, 6, 7, 8, 9], "cursor=5 必须回第 6..10 条");
        assert_eq!(next_cursor(&out, Some(5)), 10);
        // 再取（cursor=10）⇒ 空批；游标原地不动。
        let empty = filter_events(events.clone(), &q(Some(10), None));
        assert!(empty.is_empty(), "cursor=10 之后必须为空");
        assert_eq!(next_cursor(&empty, Some(10)), 10, "空批游标不得回退到 1");
        // `since` 与 `next_seq` 完全同义（改前 `since` 会重复最后一条）。
        let by_since = filter_events(events.clone(), &q(None, Some(5)));
        let seqs_since: Vec<u64> = by_since
            .iter()
            .map(|e| e["seq"].as_u64().unwrap())
            .collect();
        assert_eq!(
            seqs_since, seqs,
            "since=cursor 与 next_seq=cursor 必须逐条一致"
        );
        assert_eq!(next_cursor(&by_since, Some(5)), 10);
        // 游标超过最大 seq ⇒ 空批且游标保持（无回退、无重放）。
        let past = filter_events(events, &q(Some(99), None));
        assert!(past.is_empty());
        assert_eq!(next_cursor(&past, Some(99)), 99);
    }

    /// **2.1.43-A（P2：`udp_dropped` 双源）**：顶层与 `counters` 读**同一个原子**，
    /// `/metrics` 同值；顺带钉死 `/metrics` 暴露 `breaker_all_open_total`（counter）。
    #[tokio::test]
    async fn status_udp_dropped_top_level_equals_counters_same_atomic() {
        use axum::extract::State;
        use axum::response::IntoResponse;
        use std::sync::atomic::Ordering;
        let mut st = test_state();
        // 生产装配：`AppState.udp_dropped` = `DnsServer::dropped()` =
        // `telemetry.udp_dropped_handle()`（同一个 `Arc<AtomicU64>`）。
        let h = st.telemetry.udp_dropped_handle();
        st.udp_dropped = std::sync::Arc::clone(&h);
        assert!(
            std::sync::Arc::ptr_eq(&st.udp_dropped, &h),
            "AppState 与 telemetry 必须共用同一个 udp_dropped 原子"
        );
        h.fetch_add(5, Ordering::Relaxed);
        let resp = status(State(st.clone())).await;
        let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["udp_dropped"], json!(5));
        assert_eq!(v["counters"]["udp_dropped"], json!(5));
        assert_eq!(
            v["udp_dropped"], v["counters"]["udp_dropped"],
            "顶层与 counters.udp_dropped 必须恒等（同一原子）"
        );
        let m = metrics(State(st)).await.into_response();
        let mb = axum::body::to_bytes(m.into_body(), usize::MAX)
            .await
            .unwrap();
        let mt = String::from_utf8_lossy(&mb);
        assert!(
            mt.contains("ebpdns_udp_dropped_total 5"),
            "metrics 必须与同一原子同值:\n{mt}"
        );
        assert!(
            mt.contains("ebpdns_breaker_all_open_total"),
            "2.1.43-A：/metrics 必须暴露 breaker_all_open_total（cumulative counter）"
        );
    }

    /// **2.1.43-A（P2：`/api/status` 持 cfg 读锁做 fs IO）**：收窄锁范围后
    /// **返回值语义不变** —— 配置回显仍取实时 cfg 的 6 个标量键。
    #[tokio::test]
    async fn status_cfg_echo_matches_live_config() {
        use axum::extract::State;
        let st = test_state();
        {
            let mut g = st.cfg.write();
            if let Some(o) = g.as_object_mut() {
                o.insert("cache_policy".into(), json!("partitioned"));
                o.insert("health_check_interval".into(), json!(77));
                o.insert("rule_sub_interval".into(), json!(99));
            }
        }
        let resp = status(State(st)).await;
        let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["cache_policy"], json!("partitioned"));
        assert_eq!(v["health_check_interval"], json!(77));
        assert_eq!(v["rule_sub_interval"], json!(99));
        // `cache.persist` 与 `/api/cache/stats.persist` 同源（唯一构造实现）。
        assert!(v["cache"]["persist"].is_object());
    }

    /// **2.1.46（REV247 A-11）**：`/api/status` 的 `hit_rate` 与 `counters` 必须同代；
    /// 旧实现先取 counters、再调 `hit_rate_pct()` 取**第二份**快照。
    ///
    /// 判别：旧入口 `hit_rate_pct()` 在测试下计数；修复后 status 只调用
    /// `hit_rate_pct_of(snap)`，该计数必须保持 0（旧实现会变 1）。
    #[tokio::test]
    async fn status_hit_rate_uses_same_snapshot_as_counters() {
        use axum::extract::State;
        let st = test_state();
        crate::telemetry::HIT_RATE_PCT_CALLS.with(|c| c.set(0));
        let resp = status(State(st)).await;
        let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&b).expect("json");
        let hit = v["counters"]["hit"].as_u64().unwrap_or(0) as f64;
        let miss = v["counters"]["miss"].as_u64().unwrap_or(0) as f64;
        let want = if hit + miss == 0.0 {
            0.0
        } else {
            (hit / (hit + miss) * 1000.0).round() / 10.0
        };
        assert_eq!(
            v["hit_rate"],
            json!(want),
            "hit_rate 必须由同代 counters 计算"
        );
        let calls = crate::telemetry::HIT_RATE_PCT_CALLS.with(|c| c.get());
        assert_eq!(
            calls, 0,
            "/api/status 不得调用二次取快照的 hit_rate_pct()（A-11）"
        );
    }

    /// **2.1.43-A / 2.1.46 替换 REV247 形同虚设 #1**：`/api/status` 必须在做 fs IO
    /// **之前**释放 cfg 读锁。
    ///
    /// 旧用例 `status_200_concurrent_..._does_not_deadlock` 在旧实现（读锁活到函数末尾）
    /// 下同样绿 —— parking_lot 读锁不会死锁。这里用测试钩子把 `cache_persist_info` 的
    /// fs 段放慢 250 ms，然后 `try_write()`：新实现（先拷贝 6 个标量再释放）拿得到写锁；
    /// 旧实现仍持读锁 ⇒ `try_write()` 返回 None，用例必红。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn status_releases_cfg_lock_before_fs_io() {
        use axum::extract::State;
        use std::sync::atomic::Ordering;
        let st = test_state();
        STATUS_FS_DELAY_MS.store(250, Ordering::SeqCst);
        STATUS_FS_ENTERED.store(false, Ordering::SeqCst);
        let task = {
            let st = st.clone();
            tokio::spawn(async move { status(State(st)).await.status() })
        };
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
        while !STATUS_FS_ENTERED.load(Ordering::SeqCst) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "/api/status 未在 2s 内进入 fs IO 段"
            );
            tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
        }
        let guard = st.cfg.try_write();
        assert!(
            guard.is_some(),
            "**fs IO 期间 cfg 读锁仍被持有**：配置写者会被磁盘 IO 阻塞（REV247 形同虚设 #1）"
        );
        drop(guard);
        assert_eq!(task.await.unwrap(), StatusCode::OK);
        STATUS_FS_DELAY_MS.store(0, Ordering::SeqCst);
        STATUS_FS_ENTERED.store(false, Ordering::SeqCst);
    }

    /// **2.1.46（REV247 覆盖不足 #6）**：`/api/snapshot` 在**默认 TinyLFU** 与
    /// `partitioned` 策略下也必须只采样 500 条、且不改变缓存顺序。
    ///
    /// 旧 P1-9 用例只用 LRU 基座，抓不到 `sample_keys` 默认实现在 TinyLFU 上的
    /// 全量 `keys()`/`get()` 副作用；这里两种真实策略各跑一遍。
    #[tokio::test]
    async fn snapshot_default_policies_sample_500_without_reordering() {
        use axum::extract::State;
        use ebpdns_cache::{CacheEntry, CacheKey, DnsCache};
        for policy in ["tinylfu", "partitioned"] {
            let mut cfg =
                ebpdns_resolver::config::ResolverConfig::test_default(Vec::new(), Vec::new(), 1);
            cfg.cache_policy = policy.to_string();
            cfg.cache_size = 2048;
            let state = test_state_with_resolver_cfg(cfg);
            let cache = state.resolver.cache();
            let now = crate::telemetry::now_epoch();
            for i in 0..700 {
                let d = format!("{policy}{i}.test");
                let mut e = CacheEntry::new(&d, "A", 300.0, now);
                e.expires_at = now + 300.0;
                cache.put(CacheKey::new(&d, "A"), e, now);
            }
            assert_eq!(cache.len(), 700);
            let order = |c: &ebpdns_cache::SwappableCache| {
                c.keys()
                    .iter()
                    .map(|k| (k.domain.clone(), k.qtype.clone()))
                    .collect::<Vec<_>>()
            };
            let before = order(cache);
            let resp = snapshot(State(state.clone())).await;
            let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let v: Value = serde_json::from_slice(&b).expect("json");
            assert_eq!(
                v["entries"].as_array().map(|a| a.len()),
                Some(500),
                "{policy}: sample 必须是 500 条"
            );
            assert_eq!(v["total"], json!(700), "{policy}: total 必须是真实条目数");
            assert_eq!(
                order(cache),
                before,
                "{policy}: /api/snapshot 不得改变缓存顺序"
            );
        }
    }

    /// **P1-9**：连续 10 次 `/api/snapshot` 不得改变 LRU 顺序 / TinyLFU sketch。
    #[tokio::test]
    async fn p1_9_snapshot_does_not_change_cache_order() {
        use axum::extract::State;
        let state = test_state_with_answer("p19-up");
        for d in ["s1.test", "s2.test", "s3.test", "s4.test"] {
            let _ = query(
                State(state.clone()),
                Json(json!({"domain": d, "qtype": "A"})),
            )
            .await
            .expect("控制面查询");
        }
        let order = |st: &AppState| -> Vec<String> {
            st.resolver
                .cache()
                .keys()
                .iter()
                .map(|k| format!("{}|{}", k.domain, k.qtype))
                .collect()
        };
        let before = order(&state);
        assert!(!before.is_empty(), "前置：缓存里必须有条目");
        for _ in 0..10 {
            let resp = snapshot(State(state.clone())).await;
            let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let v: Value = serde_json::from_slice(&b).unwrap();
            assert_eq!(v["entries"].as_array().map(|a| a.len()), Some(before.len()));
            assert_eq!(v["total"], json!(before.len()), "total 必须是真实条目数");
        }
        assert_eq!(order(&state), before, "10 次 snapshot 后 LRU 顺序不得改变");
    }

    /// **P1-12（服务端）**：live 配置有 upstreams 时，拒绝空 upstreams 的整份 PUT
    /// （前端 config_loaded 守卫之外的第二道），且 `config_loaded:false` 直接 400。
    #[tokio::test]
    async fn p1_12_put_config_rejects_empty_upstreams_before_loaded() {
        use axum::extract::State;
        let state = test_state();
        *state.cfg.write() = json!({
            "upstreams": [{"id": "u1", "host": "127.0.0.1", "port": 53, "enabled": true}],
            "rules": []
        });
        let r = put_config(
            State(state.clone()),
            test_parts(),
            Json(json!({"upstreams": [], "rules": []})),
        )
        .await;
        assert!(
            matches!(r, Err(ServerError::BadRequest(_))),
            "空 upstreams 必须 400 拒绝"
        );
        assert!(
            !state.cfg.read()["upstreams"].as_array().unwrap().is_empty(),
            "拒绝后 live 配置不得被改动"
        );
        let r2 = put_config(
            State(state.clone()),
            test_parts(),
            Json(json!({"config_loaded": false, "cache_size": 16384})),
        )
        .await;
        assert!(matches!(r2, Err(ServerError::BadRequest(_))));
    }

    /* ---- **2.1.49（P0）**：`POST /api/reload` 失败必须 5xx，且旧索引不被替换 ---- */

    /// 与 `crates/ebpdns/src/main.rs` 的 `on_reload` **同构**的最小钩子：
    /// 规则索引统一走 `rebuild_all_disk_checked`，失败映射成 `ReloadError`。
    fn m249_state(dir: &std::path::Path, cfg: Value) -> AppState {
        use crate::state::{ReloadError, ReloadOutcome};
        use std::sync::Arc;

        let mut st =
            test_state_with_resolver_cfg(ebpdns_resolver::config::ResolverConfig::default());
        st.cfg_path = Some(dir.join("config.json"));
        *st.cfg.write() = cfg;
        let hook_state = st.clone();
        st.on_reload = Some(Arc::new(
            move |_new_cfg: &Value| -> Result<ReloadOutcome, ReloadError> {
                let outcome = crate::subscribe::rebuild_all_disk_checked(&hook_state);
                if let Some(failure) = outcome.failure {
                    return Err(ReloadError::new(failure.code(), failure.detail()));
                }
                if outcome.failed() {
                    return Err(ReloadError::new(
                        "rules_rebuild_failed",
                        "规则索引重建失败（保留旧索引）",
                    ));
                }
                Ok(ReloadOutcome {
                    indexed: outcome.stats.indexed,
                    rejected: outcome.stats.rejected,
                    dropped: outcome.stats.dropped,
                })
            },
        ));
        st
    }

    /// 调 `reload` handler 并拆出 `(status, body)`（`Err` 也走 `IntoResponse`）。
    async fn m249_call_reload(st: &AppState) -> (axum::http::StatusCode, Value) {
        use axum::extract::State;
        use axum::response::IntoResponse;

        match reload(State(st.clone())).await {
            Ok(axum::Json(v)) => (axum::http::StatusCode::OK, v),
            Err(e) => {
                let resp = e.into_response();
                let status = resp.status();
                let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                    .await
                    .expect("body");
                let v = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                (status, v)
            }
        }
    }

    fn m249_tmp_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ebpdns_m249_{}_{}_{}",
            tag,
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mk tmp dir");
        dir
    }

    /// 写 `config.json` + `rules_sub.json`（`rule_sub_file` 用绝对路径，避免读默认位置）。
    fn m249_write_case(dir: &std::path::Path, cfg: &Value, sub: &[u8]) -> Value {
        let mut cfg = cfg.clone();
        cfg["rule_sub_file"] = json!(dir.join("rules_sub.json").display().to_string());
        std::fs::write(
            dir.join("config.json"),
            serde_json::to_vec(&cfg).expect("serialize cfg"),
        )
        .expect("write config");
        std::fs::write(dir.join("rules_sub.json"), sub).expect("write rules_sub");
        cfg
    }

    fn m249_cfg() -> Value {
        json!({
            "rules": [],
            "rule_subscriptions": [{"url": "https://m249.invalid/list", "action": "block"}],
        })
    }

    fn m249_seed_old_index(st: &AppState) -> u64 {
        let mut map = serde_json::Map::new();
        map.insert("match".into(), json!("*.m249-old.example"));
        map.insert("action".into(), json!("block"));
        let rule =
            ebpdns_rules::rule_from_json(map, ebpdns_rules::RuleSource::Local).expect("seed rule");
        st.resolver.rebuild_rules(vec![rule]);
        assert_eq!(st.resolver.rule_count(), 1);
        st.resolver.rule_gen()
    }

    /// ① `rules_sub.json = {}`（缺 `subscriptions`）⇒ **500** + 旧索引不变。
    #[tokio::test]
    async fn m249_reload_rules_sub_empty_object_is_5xx_and_keeps_old_index() {
        let dir = m249_tmp_dir("empty");
        let cfg = m249_write_case(&dir, &m249_cfg(), b"{}");
        let st = m249_state(&dir, cfg);
        let gen0 = m249_seed_old_index(&st);

        let (status, body) = m249_call_reload(&st).await;
        assert_eq!(
            status,
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "body={body}"
        );
        assert_eq!(body["ok"], json!(false), "body={body}");
        assert_eq!(
            body["error"],
            json!("rules_sub_missing_subscriptions"),
            "body={body}"
        );
        assert!(
            body["detail"]
                .as_str()
                .unwrap_or("")
                .contains("subscriptions"),
            "detail 必须可机读定位到 subscriptions: {body}"
        );
        assert_eq!(st.resolver.rule_count(), 1, "旧规则索引必须保留");
        assert_eq!(st.resolver.rule_gen(), gen0, "失败不得推进 rule_gen");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ② 缺 `subscriptions`（非空对象）⇒ 500；同一通道下的语法错误 ⇒ 500（code 不同）。
    #[tokio::test]
    async fn m249_reload_missing_subscriptions_and_bad_json_are_5xx() {
        let dir = m249_tmp_dir("missing");
        let cfg = m249_write_case(
            &dir,
            &m249_cfg(),
            br#"{"updated_at":"2026-10-25 00:00:00","rules":[]}"#,
        );
        let st = m249_state(&dir, cfg);
        let gen0 = m249_seed_old_index(&st);

        let (status, body) = m249_call_reload(&st).await;
        assert_eq!(
            status,
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "body={body}"
        );
        assert_eq!(
            body["error"],
            json!("rules_sub_missing_subscriptions"),
            "body={body}"
        );
        assert_eq!(st.resolver.rule_count(), 1);

        // 语法错误 ⇒ rules_sub_invalid（同一 5xx 通道；旧索引仍不变）。
        std::fs::write(dir.join("rules_sub.json"), br#"{"subscriptions":[}"#)
            .expect("write bad json");
        let (status2, body2) = m249_call_reload(&st).await;
        assert_eq!(
            status2,
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "body={body2}"
        );
        assert_eq!(body2["error"], json!("rules_sub_invalid"), "body={body2}");
        assert_eq!(st.resolver.rule_count(), 1, "旧规则索引必须保留");
        assert_eq!(st.resolver.rule_gen(), gen0, "失败不得推进 rule_gen");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ③ 正常 reload ⇒ 200 + `unchanged`/`rules` 计数正确；第二次 unchanged:true。
    #[tokio::test]
    async fn m249_reload_success_is_200_with_unchanged_and_counts() {
        let dir = m249_tmp_dir("ok");
        let cfg = m249_write_case(
            &dir,
            &m249_cfg(),
            br#"{"subscriptions":[{"url":"https://m249.invalid/list","action":"block","rules":[{"match":"*.m249-a.example"},{"match":"*.m249-b.example"}]}]}"#,
        );
        let st = m249_state(&dir, cfg);
        let _gen0 = m249_seed_old_index(&st);

        let (status, body) = m249_call_reload(&st).await;
        assert_eq!(status, axum::http::StatusCode::OK, "body={body}");
        assert_eq!(body["ok"], json!(true));
        assert_eq!(body["unchanged"], json!(false), "规则集变化必须报 changed");
        // **2.1.49**：规则索引来源只有 `config.rules`（空）+ 订阅明细（2 条）；
        // 之前手工 seed 的旧索引不是磁盘来源，重载后应被完整替换为 2。
        assert_eq!(
            body["rules"],
            json!(2),
            "订阅 2 条（旧 seed 索引不属于来源）"
        );
        assert!(
            body["changed"]
                .as_array()
                .map(|a| a.iter().any(|v| v == "rules" || v == "rules_file"))
                .unwrap_or(false),
            "changed 必须含 rules / rules_file: {body}"
        );
        assert_eq!(st.resolver.rule_count(), 2);
        let gen1 = st.resolver.rule_gen();

        // 第二次：来源字节未变 ⇒ 200 unchanged:true，计数与 rule_gen 不变。
        let (status2, body2) = m249_call_reload(&st).await;
        assert_eq!(status2, axum::http::StatusCode::OK, "body={body2}");
        assert_eq!(body2["unchanged"], json!(true), "body={body2}");
        assert_eq!(body2["rules"], json!(2), "body={body2}");
        assert_eq!(body2["changed"], json!([]), "body={body2}");
        assert_eq!(body2["source"], json!("file"));
        assert_eq!(st.resolver.rule_count(), 2);
        assert_eq!(st.resolver.rule_gen(), gen1, "unchanged 不得推进 rule_gen");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ④ 重建失败（坏规则：全部被丢弃）⇒ 500 + 旧索引不变（旧实现会先替换成空索引）。
    #[tokio::test]
    async fn m249_reload_bad_rules_is_5xx_and_keeps_old_index() {
        let dir = m249_tmp_dir("badrule");
        let cfg = m249_write_case(
            &dir,
            &m249_cfg(),
            br#"{"subscriptions":[{"url":"https://m249.invalid/list","action":"block","rules":[{"match":"   "}]}]}"#,
        );
        let st = m249_state(&dir, cfg);
        let gen0 = m249_seed_old_index(&st);

        let (status, body) = m249_call_reload(&st).await;
        assert_eq!(
            status,
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "body={body}"
        );
        assert_eq!(body["error"], json!("rules_rebuild_failed"), "body={body}");
        assert_eq!(st.resolver.rule_count(), 1, "重建失败必须保留旧索引");
        assert_eq!(st.resolver.rule_gen(), gen0, "重建失败不得推进 rule_gen");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
// <<< 242B END T-api <<< //
