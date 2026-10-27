//! 共享应用状态：axum handlers 通过它访问 resolver / 配置 / 遥测 / 静态资源 / 重启信号。

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ebpdns_resolver::Resolver;
use parking_lot::RwLock;
use serde_json::Value;

use crate::state_store::{LoadState, StateStore};
use crate::telemetry::ServerTelemetry;

/// **2.1.22 阶段一**：持久化上下文（`state/` 统一事务的进程内入口）。
///
/// 为什么要有这一层而不是直接在 `AppState` 上加两个字段：`AppState` 在
/// `crates/` 里有 9 处字面量构造（含测试夹具），本类型把「store 句柄 + 生效的
/// `state/` 路径」收成一个 `Arc`，构造点只需补 `state: Default::default()` 一行
/// ⇒ 改动面从 18 处降到 9 处，且不影响 `AppState` 的 `Clone`。
///
/// * `store = None` ⇒ **旧行为**（无统一事务：仍是各写者自己的原子写）。
///   纯内存态（测试/嵌入式、`cfg_path=None`）与「目录不可写但服务仍要起来」
///   两种情况都走这里 —— 2.1.21 的可观测行为因此逐位保留。
/// * `store = Some(_)` ⇒ **所有持久化写者必须走它**（见 `CONVENTIONS.md`
///   「统一持久化事务」四条规范）。
#[derive(Clone, Default)]
pub struct StateCtx {
    /// 统一两阶段提交 store（`commit.json` + `history/` 所在目录）。
    pub store: Option<Arc<StateStore>>,
    /// **生效的** `state/` 目录（默认 `/var/lib/ebpdns/state`，可配置）。
    ///
    /// 与 `store.dir()` 同值；`store` 为 `None` 时它仍承载「配置里写的路径」，
    /// 供 `/api/status.state_persist` 如实回显（不静默藏起来）。
    pub state_dir: PathBuf,
    /// **启动时的四态判定结果**（**2.1.23 / DEF-222-04，P1**）。
    ///
    /// 2.1.22 把 `load()` 的结论**只写进日志**，而 `state_persist` 一律用原始
    /// `commit.json` ⇒ 端点**无法区分**"健康 / 已回退 / Torn"：Torn 时它照报
    /// `revision = 被拒绝的世代`、`parts[]` = 已失效的记录值、`note = "统一事务已启用"`，
    /// 而 `parts[].sha256` 与 `bytes` 正是文档承诺的判据。⇒ 现在把结论**存下来**，
    /// 由 [`crate::state_store::persist_info`] 如实下发。
    pub load_state: Option<LoadStateInfo>,
    /// **2.1.23 / DEF-222-03**：`state/` 独占锁是否由本进程持有。
    pub lock_held: bool,
    /// **2.1.23 / DEF-222-03**：本实例未持有锁（被别的实例占用 / 平台不支持）时的原因。
    pub lock_note: Option<String>,
}

/// 启动四态的**可观测快照**（`/api/status.state_persist.load_state` 的数据源）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadStateInfo {
    /// `"Legacy"` / `"Committed"` / `"RolledBack"` / `"Torn"`。
    pub kind: &'static str,
    /// 读方**实际服务**的世代（`Legacy` ⇒ `None`；`Torn` ⇒ `None`）。
    pub serving_revision: Option<u64>,
    /// 被判定为损坏、因而被拒绝的世代（仅 `RolledBack`）。
    pub broken_revision: Option<u64>,
    /// `Torn` 的原因（端点可判）。
    pub torn_reason: Option<String>,
    /// `state/` 是否已启用统一事务（`Legacy` 且 store 为 None ⇒ 未启用）。
    pub enabled: bool,
}

impl LoadStateInfo {
    /// 由 [`LoadState`] 构造。
    pub fn from_load_state(ls: &LoadState, enabled: bool) -> Self {
        match ls {
            LoadState::Legacy => Self {
                kind: "Legacy",
                serving_revision: None,
                broken_revision: None,
                torn_reason: None,
                enabled,
            },
            LoadState::Committed(c) => Self {
                kind: "Committed",
                serving_revision: Some(c.revision),
                broken_revision: None,
                torn_reason: None,
                enabled,
            },
            LoadState::RolledBack { broken, restored } => Self {
                kind: "RolledBack",
                serving_revision: Some(restored.revision),
                broken_revision: Some(*broken),
                torn_reason: None,
                enabled,
            },
            LoadState::Torn { reason } => Self {
                kind: "Torn",
                serving_revision: None,
                broken_revision: None,
                torn_reason: Some(reason.clone()),
                enabled,
            },
        }
    }

    /// `Torn` ⇒ 端点必须能判（`/api/status` 里 `torn=true`）。
    pub fn is_torn(&self) -> bool {
        self.kind == "Torn"
    }
}

impl StateCtx {
    /// 未启用统一事务（旧行为）。
    pub fn disabled() -> Self {
        Self {
            store: None,
            state_dir: PathBuf::new(),
            load_state: None,
            lock_held: false,
            lock_note: None,
        }
    }

    /// 启用统一事务。
    pub fn with_store(store: Arc<StateStore>, state_dir: impl Into<PathBuf>) -> Self {
        Self {
            store: Some(store),
            state_dir: state_dir.into(),
            load_state: None,
            lock_held: false,
            lock_note: None,
        }
    }

    /// 记录启动四态（**2.1.23 / DEF-222-04**）。
    pub fn with_load_state(mut self, info: LoadStateInfo) -> Self {
        self.load_state = Some(info);
        self
    }

    /// 记录独占锁状态（**2.1.23 / DEF-222-03**）。
    pub fn with_lock(mut self, held: bool, note: Option<String>) -> Self {
        self.lock_held = held;
        self.lock_note = note;
        self
    }

    /// 统一事务 store（`None` = 未启用）。
    pub fn store(&self) -> Option<&Arc<StateStore>> {
        self.store.as_ref()
    }

    /// 生效的 `state/` 目录（可能为空串 = 未启用且未配置）。
    pub fn dir(&self) -> &Path {
        &self.state_dir
    }

    /// `state/` 是否已启用统一事务。
    pub fn is_on(&self) -> bool {
        self.store.is_some()
    }

    /// **2.1.48 / serving_revision**：把当前提交点标记为“正在服务”。
    ///
    /// 调用点必须是「提交成功 + 内存配置/索引已就绪」（subscription 刷新在 rebuild 之后，
    /// config-only 提交在 `state.cfg` 同步之后）。见 `state_store::mark_serving_current`。
    pub fn mark_serving(&self) -> Option<u64> {
        self.store.as_ref()?.mark_serving_current()
    }

    /// 启动期判定结果（`Legacy` = 2.1.21 布局，需迁移；**不是错误**）。
    ///
    /// 未启用统一事务时恒为 `LoadState::Legacy`（调用方据此跳过迁移）。
    pub fn load(&self) -> LoadState {
        match &self.store {
            Some(s) => s.load(),
            None => LoadState::Legacy,
        }
    }
}

/// 触发 /api/restart：置位后 main 优雅退出并以退出码 3 退出（systemd on-failure 拉起）。
#[derive(Default)]
pub struct RestartSignal {
    pub requested: std::sync::atomic::AtomicBool,
}

/// **2.1.49（P0）**：一次 reload 的成功结果。
///
/// `indexed/rejected/dropped` 是本次规则索引重建的统计（成功路径回传，供 reload
/// 响应体的 `rules` 字段与测试断言使用）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReloadOutcome {
    pub indexed: usize,
    pub rejected: usize,
    pub dropped: usize,
}

/// **2.1.49（P0）**：一次 reload 的失败（可机读 code + 人类可读 detail）。
///
/// 2.1.48 的 [`ReloadHook`] 是 `Fn(&Value)`，失败只能写日志 ⇒ reload 端点
/// 对"订阅非法/规则真源坏/重建失败"返回 200（静默成功）。现在 hook 返回
/// `Result<ReloadOutcome, ReloadError>`，端点映射 **500** +
/// `{"ok":false,"error":"<code>","detail":"..."}`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadError {
    /// 机器可读 code（如 `rules_sub_invalid`）。
    pub code: &'static str,
    /// 人类可读说明（只描述类别，不回显文件内容/内网拓扑）。
    pub detail: String,
}

impl ReloadError {
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// HTTP 500 的响应体（机读原因）。
    pub fn body(&self) -> serde_json::Value {
        serde_json::json!({
            "ok": false,
            "error": self.code,
            "detail": self.detail,
        })
    }
}

/// 配置热重载 hook 类型别名（收束复杂函数指针类型）。
///
/// **2.1.49（P0）**：返回值是错误通道 —— `Err` 必须让 reload 端点返回 5xx，
/// 且调用方必须保证**旧规则索引不被替换**（见 `subscribe::rebuild_all_disk_checked`）。
pub type ReloadHook =
    dyn Fn(&serde_json::Value) -> Result<ReloadOutcome, ReloadError> + Send + Sync + 'static;

/// axum 共享状态（Clone，内部全 Arc）。
#[derive(Clone)]
pub struct AppState {
    pub resolver: Arc<Resolver>,
    /// 当前生效配置 JSON 对象（API GET/PUT 读写；启动时由 binary 注入）。
    pub cfg: Arc<RwLock<Value>>,
    /// 配置文件路径（PUT 原子写目标）。
    pub cfg_path: Option<PathBuf>,
    pub telemetry: Arc<ServerTelemetry>,
    /// 配置的 api.host（Origin/CSRF/loopback 判定基准）。
    pub api_host: Arc<RwLock<String>>,
    pub api_port: u16,
    /// 磁盘静态根（embed-frontend feature 未开时从磁盘读；None=无静态资源）。
    /// **启动期固定值**：来源见 `static_root_of`（env / 配置 / None），进程内不可热改
    /// （改它需要改 `static_assets::serve` / `api::static_handler` 的签名，且会波及
    /// 本次任务不允许修改的 api.rs）。
    pub web_root: Option<PathBuf>,
    pub restart: Arc<RestartSignal>,
    /// 端点展示（DNS 监听地址）。
    pub endpoints: Arc<RwLock<Vec<(String, String)>>>,
    /// 配置热重载 hook：PUT/reload 时由 binary 注入（cfg JSON → resolver.reload）。
    /// server crate 不直接知道如何把 JSON 映射成 ResolverConfig，故由调用方注入。
    pub on_reload: Option<Arc<ReloadHook>>,
    /// /api/restart 触发：main 监听它，收到后退出码 3。
    pub restart_notify: Arc<tokio::sync::Notify>,
    /// UDP miss 队列满时丢弃的包数（数据面写入，`/api/status.udp_dropped` 读取）。
    pub udp_dropped: Arc<std::sync::atomic::AtomicU64>,
    /// 「上次已生效」配置快照：`POST /api/reload` 用它算出 `changed[]`。
    pub applied: Arc<RwLock<Value>>,
    /// **2.1.22 阶段一**：`state/` 统一持久化事务（两阶段提交 store + 生效路径）。
    ///
    /// `store = None` ⇒ 未启用（旧行为，逐位等于 2.1.21）。启用后**所有**持久化
    /// 写者（`config.json` / `rules.json` / `subscriptions.json`）都必须经它提交，
    /// 见 `state_store::{state_txn, commit_droppable}` 与 `CONVENTIONS.md`。
    pub state: Arc<StateCtx>,
}

impl AppState {
    // >>> 242B BEGIN P1-8-appstate >>> //
    /// **2.1.42-B（P1-8）**：`POST /api/reset` 的**单一入口** —— 清空数据面
    /// 遥测 + resolver 运行时（13 个 counters / 健康统计 / 熔断器）+ 顶层
    /// `udp_dropped`。任何新增的运行时计数器都必须加进这里，否则 reset 后
    /// `counters` 与顶层字段会自相矛盾（审计 A-04）。
    pub fn reset_all_counters(&self) {
        // >>> 245 P2-6 reset-all BEGIN
        // **2.1.45（P2-6 / REV247 P2-2）**：冻结位 + 写屏障横跨"resolver 运行时 +
        // telemetry + 顶层 udp_dropped"三段清零：期间到达的数据面查询**不计**，
        // 因此不存在"policy/rule 已 +1 而 total 已被清 0"的跨代读数。
        let _gate = self.telemetry.reset_write_gate();
        self.telemetry.set_reset_frozen(true);
        self.resolver.reset_runtime_state();
        self.telemetry.reset_clear();
        self.udp_dropped
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.telemetry.set_reset_frozen(false);
        // <<< 245 P2-6 reset-all END
    }

    // <<< 242B END P1-8-appstate <<< //
    /// 热重载时刷新**可热改**的运行时基准（F31），返回本次实际替换的字段名。
    ///
    /// - `api_host`（`RwLock<String>`）实时刷新：`_origin_ok` / `_csrf_ok` /
    ///   `bound_to_loopback` 都以它为基准，此前只刷新 resolver，手工改
    ///   `api.host` 后 `/api/reload` 仍按启动快照判定 → 合法请求 fail-closed 403。
    /// - `web_root`（`Option<PathBuf>`，**启动期固定值**）/ `api_port` / `listen.*`
    ///   **不可热改**：`web_root` 已被 `static_assets::serve` 按值持有、`api_port` 与
    ///   `listen` 的 socket 在启动时已 bind，进程内都没有重绑定/替换路径。三者只在
    ///   与新配置不一致时记录「**需重启生效**」告警，**绝不**写回字段（不假报已生效）。
    ///   故意**不**刷新 `api_port` —— 按新端口校验 Origin 只会把可用请求判成跨源
    ///   （fail-closed 403），保持"按实际生效端口判定"更安全也更可诊断。
    ///
    /// `listen_cfg` 为**当前已生效**的 `listen` 段原样 JSON（与 bind 地址同源），
    /// 由调用方（binary）传入，避免把只读段复制进 AppState。
    pub fn apply_runtime_cfg(&self, new_cfg: &Value, listen_cfg: &Value) -> Vec<&'static str> {
        let mut updated: Vec<&'static str> = Vec::new();

        let new_host = api_host_of(new_cfg);
        {
            let mut host = self.api_host.write();
            if *host != new_host {
                tracing::info!(old = %*host, new = %new_host, "api.host 已热刷新（Origin/CSRF 判定基准）");
                *host = new_host.clone();
                updated.push("api.host");
            }
        }

        // web_root：只比较、只告警（字段是 `Option<PathBuf>`，启动期固定）。
        let desired_root =
            static_root_of(new_cfg, std::env::var("EBPDNS_WEB_ROOT").ok().as_deref());
        // 两侧统一成 `Option<&Path>` 比较（`PathBuf`/`&Path` 跨类型 `!=` 不成立）。
        if self.web_root.as_deref() != desired_root.as_deref() {
            tracing::warn!(
                current = ?self.web_root,
                desired = ?desired_root,
                "配置 web_root / EBPDNS_WEB_ROOT 与当前生效值不同：**需重启生效**（静态资源根为启动期确定）"
            );
        }

        let cfg_port = api_port_of(new_cfg);
        if cfg_port != self.api_port {
            tracing::warn!(
                configured = cfg_port,
                bound = self.api_port,
                "配置 api.port 与已 bind 端口不同：**需重启生效**（socket 不可热改）"
            );
        }
        let new_listen = new_cfg.get("listen");
        let listen_changed = match (new_listen, listen_cfg.is_null()) {
            (None, _) => false,
            (Some(_), true) => false,
            (Some(n), false) => n != listen_cfg,
        };
        if listen_changed {
            tracing::warn!(
                requested = %new_listen.cloned().unwrap_or(serde_json::Value::Null),
                bound = %listen_cfg,
                "配置 listen.* 与已 bind 地址不同：**需重启生效**（socket 不可热改）"
            );
        }
        updated
    }
}

/// 从配置取 `api.host`：缺失/null 时回退启动默认 `127.0.0.1`（与 main.rs 启动路径同口径）。
/// 纯函数，便于单测。
pub fn api_host_of(cfg: &Value) -> String {
    cfg.get("api")
        .and_then(|a| a.get("host"))
        .and_then(Value::as_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "127.0.0.1".to_string())
}

/// 从配置取 `api.port`（数字或数字字符串），缺失时回退 8353。纯函数。
pub fn api_port_of(cfg: &Value) -> u16 {
    let raw = cfg.get("api").and_then(|a| a.get("port"));
    let n = match raw {
        Some(Value::Number(n)) => n.as_u64().or_else(|| n.as_f64().map(|f| f.max(0.0) as u64)),
        Some(Value::String(s)) => s.trim().parse::<u64>().ok(),
        _ => None,
    };
    n.map(|v| v.clamp(1, 65535) as u16).unwrap_or(8353)
}

/// 静态资源根解析（F28）：`EBPDNS_WEB_ROOT`（非空）优先 → `cfg["web_root"]`（非空
/// 字符串）→ `None`（仅嵌入资源）。
///
/// 与 binary 启动路径（main.rs 步骤 8 直接调用本函数注入 `AppState::web_root`）同口径，
/// 供 [`AppState::apply_runtime_cfg`] 对比「配置想要的值」与「当前生效值」，
/// 从而在 hot reload 时给出「需重启生效」告警。纯函数（env 由调用方读取后传入）。
pub fn static_root_of(cfg: &Value, env_web_root: Option<&str>) -> Option<PathBuf> {
    if let Some(p) = env_web_root.map(str::trim).filter(|s| !s.is_empty()) {
        return Some(PathBuf::from(p));
    }
    cfg.get("web_root")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn api_host_priority_and_defaults() {
        assert_eq!(api_host_of(&json!({"api": {"host": "0.0.0.0"}})), "0.0.0.0");
        assert_eq!(api_host_of(&json!({"api": {"host": "  ::1  "}})), "::1");
        assert_eq!(api_host_of(&json!({"api": {"host": ""}})), "127.0.0.1");
        assert_eq!(api_host_of(&json!({"api": {"host": null}})), "127.0.0.1");
        assert_eq!(api_host_of(&json!({})), "127.0.0.1");
    }

    #[test]
    fn api_port_accepts_number_and_string() {
        assert_eq!(api_port_of(&json!({"api": {"port": 9000}})), 9000);
        assert_eq!(api_port_of(&json!({"api": {"port": "9000"}})), 9000);
        assert_eq!(api_port_of(&json!({"api": {"port": 0}})), 1);
        assert_eq!(api_port_of(&json!({"api": {"port": 99999}})), 65535);
        assert_eq!(api_port_of(&json!({"api": {}})), 8353);
        assert_eq!(api_port_of(&json!({})), 8353);
    }

    #[test]
    fn static_root_priority_env_then_cfg_then_none() {
        let cfg = json!({"web_root": "/srv/dist"});
        assert_eq!(
            static_root_of(&cfg, Some("/env/dist")),
            Some(PathBuf::from("/env/dist"))
        );
        assert_eq!(
            static_root_of(&cfg, Some("   ")),
            Some(PathBuf::from("/srv/dist"))
        );
        assert_eq!(static_root_of(&cfg, None), Some(PathBuf::from("/srv/dist")));
        assert_eq!(static_root_of(&json!({"web_root": "  "}), None), None);
        assert_eq!(static_root_of(&json!({"web_root": ""}), None), None);
        assert_eq!(static_root_of(&json!({}), None), None);
        assert_eq!(static_root_of(&json!({"web_root": 5}), None), None);
        // 临时真实目录（端到端取值 + 规范化，与启动注入路径同口径）。
        let dir = std::env::temp_dir().join(format!("ebpdns-webroot-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let cfg = json!({ "web_root": dir.display().to_string() });
        let got = static_root_of(&cfg, None).expect("cfg web_root used");
        assert_eq!(got, dir);
        assert!(got.is_dir());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// F31：`apply_runtime_cfg` **只**热刷新 `api.host`（Origin/CSRF 判定基准）；
    /// `web_root` / `api.port` / `listen` 均为启动期固定值，只告警「需重启生效」，
    /// 既不出现在返回值里，字段本身也不可被改写。
    #[test]
    fn apply_runtime_cfg_refreshes_api_host_only() {
        use crate::telemetry::ServerTelemetry;
        use ebpdns_resolver::clock::RealClock;
        use ebpdns_resolver::config::ResolverConfig;
        use ebpdns_resolver::query::ScriptedQuerier;
        use ebpdns_resolver::Resolver;

        let tel = Arc::new(ServerTelemetry::new());
        let q = ScriptedQuerier::new(|_n, _t, _d| Vec::new());
        let resolver = Resolver::new(
            ResolverConfig::default(),
            tel.clone(),
            Arc::new(RealClock::default()),
            Arc::new(q),
        );
        let st = AppState {
            resolver,
            cfg: Arc::new(RwLock::new(json!({}))),
            cfg_path: None,
            telemetry: tel,
            api_host: Arc::new(RwLock::new("127.0.0.1".to_string())),
            api_port: 8353,
            // 启动期固定的磁盘静态根（`Option<PathBuf>`，不是 RwLock）。
            web_root: Some(PathBuf::from("/boot/dist")),
            restart: Arc::new(RestartSignal::default()),
            endpoints: Arc::new(RwLock::new(Vec::new())),
            on_reload: None,
            restart_notify: Arc::new(tokio::sync::Notify::new()),
            udp_dropped: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            applied: Arc::new(RwLock::new(json!({}))),
            // 本用例只验 `apply_runtime_cfg`，不涉及持久化 ⇒ 旧行为（无统一事务）。
            state: Default::default(),
        };
        let listen = json!({"udp": "127.0.0.1", "tcp": "127.0.0.1"});

        // 无变化：不报告任何字段。
        assert!(st
            .apply_runtime_cfg(
                &json!({"api": {"host": "127.0.0.1", "port": 8353}}),
                &listen
            )
            .is_empty());
        assert_eq!(st.api_host.read().clone(), "127.0.0.1");

        // api.host 变更 → 立即生效（不再等到重启）；web_root 不在热刷新范围内。
        let changed = st.apply_runtime_cfg(
            &json!({"api": {"host": "0.0.0.0", "port": 8353}, "web_root": "/srv/dist", "listen": listen}),
            &listen,
        );
        assert_eq!(changed, vec!["api.host"], "changed={changed:?}");
        assert!(!changed.contains(&"web_root"), "changed={changed:?}");
        assert_eq!(st.api_host.read().clone(), "0.0.0.0");
        // web_root 是启动期固定值：字段不可热改（保持启动时的值，只记 warning）。
        assert_eq!(st.web_root, Some(PathBuf::from("/boot/dist")));

        // api.port 变更不可热改：api_port 保持已 bind 值（只记 warning）。
        let changed2 =
            st.apply_runtime_cfg(&json!({"api": {"host": "0.0.0.0", "port": 9999}}), &listen);
        assert!(changed2.is_empty(), "changed={changed2:?}");
        assert_eq!(st.api_port, 8353);
        assert_eq!(st.web_root, Some(PathBuf::from("/boot/dist")));
    }
}
