//! 全局状态：路由、模式、REAL 数据快照、日志筛选与提示。
//! 结构对齐 v1.9.162 前端的 `real` / `config` / `logFilters` 全局对象。
use leptos::prelude::*;
use serde_json::Value;

use crate::model::{LogEvent, Pipeline, QueryResp, Snapshot, Status};

/// 前端**显示**的版本号：**单一来源** = 根 `Cargo.toml` 的
/// `[workspace.package] version`，由 `web/build.rs` 在编译期注入
/// （页脚、关于页共用同一常量，不再各自手写 → 不会再出现 2.1.1/2.1.7/2.1.12 漂移）。
pub const VERSION: &str = env!("EBPDNS_VERSION");

/// 五个控制台页面（与 v1.9.162 `data-route` 一致）。
///
/// **2.1.14**：独立的「规则管理」页（`Route::Rules`）已被**删除** —— 它在
/// `main.rs` 的渲染 match 里被重复写了 3 次，`RulesPage` 从未挂载（实测
/// `?route=rules` 的 `.routes` 只有占位 `<span>R</span>`、0 卡片/0 按钮），
/// 且 `pages/rules.rs:174` 引用了不存在的 `action2/group2/ip2`（无法编译）。
/// 分流规则能力保留在**配置页的「分流规则」卡片**里（那是可用且已在用的路径：
/// `PUT /api/config` 全量下发 `rules[]`）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Pipeline,
    Query,
    Config,
    Telemetry,
    About,
}

impl Route {
    /// URL 片段（`from_str` 的反函数）。
    ///
    /// 生产渲染不读它（每个页面组件自带 `data-route="…"` 字面量，与原件 DOM 一致），
    /// 但它是路由往返单测（`route_roundtrip` / `removed_rules_route_is_gone_…`）与
    /// 未来 URL 同步的唯一来源，故保留；`cargo build`（非 test）下显式 allow。
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            Route::Pipeline => "pipeline",
            Route::Query => "query",
            Route::Config => "config",
            Route::Telemetry => "telemetry",
            Route::About => "about",
        }
    }

    /// (顶栏标题, 顶栏副标题)
    pub fn meta(self) -> (&'static str, &'static str) {
        match self {
            Route::Pipeline => ("数据面流水线", "用户态缓存 · 用户态解析引擎"),
            Route::Query => ("查询控制台", "手动发起 DNS 解析，查看完整处理链路"),
            Route::Config => ("配置", "上游服务器 · 缓存 · 测速 · 分流"),
            Route::Telemetry => ("遥测", "命中率 · 吞吐 · 延迟 · 上游健康度 · 缓存占用"),
            Route::About => ("架构说明", "Rust 用户态数据面 + SmartDNS 式引擎的设计拆解"),
        }
    }

    /// URL → 路由。**已删除的路由**（历史 `rules`）返回 `None`，调用方回退到
    /// 默认页（[`initial_route`] → `Route::Pipeline`），即 `?route=rules` /
    /// `#rules` **安全回退**而不是渲染空白页。
    pub fn from_str(s: &str) -> Option<Route> {
        match s {
            "pipeline" => Some(Route::Pipeline),
            "query" => Some(Route::Query),
            "config" => Some(Route::Config),
            "telemetry" => Some(Route::Telemetry),
            "about" => Some(Route::About),
            _ => None,
        }
    }
}

/// 运行模式：REAL（后端可达）/ AuthFailed（401）/ Down（不可达，页面以空数据渲染）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Real,
    AuthFailed,
    Down,
}

/// 日志八列筛选（`ts/ip/dm/qt/up/an/la/rl`），对齐 `logFilters`。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LogFilters {
    pub ts: String,
    pub ip: String,
    pub dm: String,
    pub qt: String,
    pub up: String,
    pub an: String,
    pub la: String,
    pub rl: String,
}

impl LogFilters {
    pub fn get(&self, f: &str) -> &str {
        match f {
            "ts" => &self.ts,
            "ip" => &self.ip,
            "dm" => &self.dm,
            "qt" => &self.qt,
            "up" => &self.up,
            "an" => &self.an,
            "la" => &self.la,
            "rl" => &self.rl,
            _ => "",
        }
    }

    pub fn set(&mut self, f: &str, v: String) {
        match f {
            "ts" => self.ts = v,
            "ip" => self.ip = v,
            "dm" => self.dm = v,
            "qt" => self.qt = v,
            "up" => self.up = v,
            "an" => self.an = v,
            "la" => self.la = v,
            "rl" => self.rl = v,
            _ => {}
        }
    }

    pub fn any(&self) -> bool {
        [
            &self.ts, &self.ip, &self.dm, &self.qt, &self.up, &self.an, &self.la, &self.rl,
        ]
        .iter()
        .any(|s| !s.trim().is_empty())
    }

    pub fn clear(&mut self) {
        *self = LogFilters::default();
    }
}

/// 提示类型（决定 `.note` 颜色）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoteKind {
    Info,
    Ok,
    Err,
    Warn,
}

/// **2.1.43-B（P2-1）**：每个轮询端点的**数据不可用**原因（`None` = 本次成功）。
///
/// 为什么需要它：`api::*` 旧实现在解析失败时 `unwrap_or_default()` → 页面拿到的
/// 是"全 0 模型"，看起来一切正常。现在 `api` 返回 `Err`，本结构把"哪个端点、为什么"
/// 留在状态里供**顶栏**（`main.rs` 的 `#data-unavailable`）与页面渲染，
/// 而不是只闪一条 2 s 就消失的提示。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DataErrs {
    pub status: Option<String>,
    pub snapshot: Option<String>,
    pub pipeline: Option<String>,
    pub logs: Option<String>,
}

impl DataErrs {
    /// 写某个端点的失败原因（空串也当作失败原因，避免"有错但不显示"）。
    pub fn set(&mut self, ep: &str, msg: impl Into<String>) {
        let m = Some(msg.into());
        match ep {
            "status" => self.status = m,
            "snapshot" => self.snapshot = m,
            "pipeline" => self.pipeline = m,
            "logs" => self.logs = m,
            _ => {}
        }
    }

    /// 该端点本次成功 ⇒ 清掉它的旧原因。
    pub fn clear(&mut self, ep: &str) {
        match ep {
            "status" => self.status = None,
            "snapshot" => self.snapshot = None,
            "pipeline" => self.pipeline = None,
            "logs" => self.logs = None,
            _ => {}
        }
    }

    /// 顶栏横幅文案：`None` = 全部正常；`Some` = 「数据不可用：<端点> <原因>」。
    ///
    /// 只报**第一条**（status > snapshot > pipeline > logs）：顶栏是单行，逐条挤在一起
    /// 反而看不清；完整原因在各自页面/配置页的提示里。
    pub fn banner(&self) -> Option<String> {
        let (name, msg) = if let Some(m) = &self.status {
            ("/api/status", m)
        } else if let Some(m) = &self.snapshot {
            ("/api/snapshot", m)
        } else if let Some(m) = &self.pipeline {
            ("/api/pipeline", m)
        } else if let Some(m) = &self.logs {
            ("/api/logs", m)
        } else {
            return None;
        };
        Some(format!("数据不可用：{name} {msg}"))
    }
}

/// 配置页底部提示，对齐 `#cfg-saved-note`。
#[derive(Clone, Debug)]
pub struct Note {
    pub text: String,
    pub kind: NoteKind,
}
impl Default for Note {
    fn default() -> Self {
        Note {
            text: "修改暂存于浏览器，点击「应用配置」下发到后端".into(),
            kind: NoteKind::Info,
        }
    }
}

/// 前端全局状态（Copy：内部全是信号句柄）。
#[derive(Clone, Copy)]
pub struct App {
    pub route: RwSignal<Route>,
    pub mode: RwSignal<Mode>,
    pub status: RwSignal<Option<Status>>,
    pub snapshot: RwSignal<Option<Snapshot>>,
    pub config: RwSignal<Option<Value>>,
    /// 服务器配置每次刷新 +1，用于强制重建配置表单（避免输入焦点被覆盖）。
    pub cfg_epoch: RwSignal<u32>,
    pub pipeline: RwSignal<Option<Pipeline>>,
    pub logs: RwSignal<Vec<LogEvent>>,
    pub log_seq: RwSignal<u64>,
    pub filters: RwSignal<LogFilters>,
    pub global_q: RwSignal<String>,
    /// 点击「清空」(#btn-qclear) 的时间点，格式与 `manual_history[].ts` 同为定宽
    /// `HH:MM:SS.mmm`：早于该串的会话记录不再显示（对齐原件 `real.hiddenHistoryBefore`）。
    /// 空串 = 未清空过（不过滤）。用字符串而非 epoch，是因为后端下发的 `ts` 已被
    /// `model::de_ts` 归一成同格式的本地时间串，字典序即时序（原件同口径）。
    pub hidden_before: RwSignal<String>,
    pub query_out: RwSignal<Option<QueryResp>>,
    pub query_busy: RwSignal<bool>,
    pub note: RwSignal<Note>,
    pub uptime_text: RwSignal<String>,
    /// 连接设置卡片里的认证状态文案。
    pub token_status: RwSignal<String>,
    /// **2.1.18（修复项 7）**：后端 `PUT /api/config` 回报的
    /// `readonly_detail[].reason`（`键 → 为什么只读 / 要改怎么办`）。
    ///
    /// 存在意义：配置页「高级选项 → 只读/服务端管理项」区逐条展示这些键的**当前值**
    /// 与**原因**，避免用户再次把"由配置文件管理"误读成"保存丢数据"。
    /// 只在一次保存成功后填充（首次进入页面时为空 → 组件用本地兜底文案）。
    pub readonly_reasons: RwSignal<std::collections::HashMap<String, String>>,
    /// **2.1.43-B（P2-1）**：各轮询端点"数据不可用"的**原因**（见 [`DataErrs`]）。
    ///
    /// 与 `note` 的区别：`note` 是一次性提示（会被下一条覆盖），本信号是**持续状态**
    /// —— 只要后端响应还解析不出来，顶栏横幅就一直显示，不会"闪一下又回到 0"。
    pub errs: RwSignal<DataErrs>,
}

impl App {
    pub fn new() -> Self {
        App {
            route: RwSignal::new(initial_route()),
            mode: RwSignal::new(Mode::Down),
            status: RwSignal::new(None),
            snapshot: RwSignal::new(None),
            config: RwSignal::new(None),
            cfg_epoch: RwSignal::new(0),
            pipeline: RwSignal::new(None),
            logs: RwSignal::new(Vec::new()),
            log_seq: RwSignal::new(0),
            filters: RwSignal::new(LogFilters::default()),
            global_q: RwSignal::new(String::new()),
            hidden_before: RwSignal::new(String::new()),
            query_out: RwSignal::new(None),
            query_busy: RwSignal::new(false),
            note: RwSignal::new(Note::default()),
            uptime_text: RwSignal::new(format!("up 0m · v{VERSION}")),
            token_status: RwSignal::new("未配置".into()),
            readonly_reasons: RwSignal::new(std::collections::HashMap::new()),
            errs: RwSignal::new(DataErrs::default()),
        }
    }

    /// 是否已拿到服务器配置（`#cfg-loading-banner` 显隐）。
    pub fn config_loaded(&self) -> bool {
        self.config.get().is_some()
    }

    /// 当前状态（缺省零值），供顶栏/KPI 直接读取。
    pub fn status_or_default(&self) -> Status {
        self.status.get().unwrap_or_default()
    }

    /// 快照（缺省零值）。
    pub fn snapshot_or_default(&self) -> Snapshot {
        self.snapshot.get().unwrap_or_default()
    }

    /// 写一条提示。
    pub fn note_set(&self, text: impl Into<String>, kind: NoteKind) {
        self.note.set(Note {
            text: text.into(),
            kind,
        });
    }

    /// **2.1.43-B（P2-1）**：记下某端点的"数据不可用"原因（幂等：同原因不重复写信号）。
    pub fn err_set(&self, ep: &str, msg: impl Into<String>) {
        let msg = msg.into();
        let mut cur = self.errs.get_untracked();
        let before = cur.clone();
        cur.set(ep, msg);
        // 只在**内容真的变化**时写信号：否则 2 s 一轮的失败会每拍都通知一次全树重渲染。
        if cur != before {
            self.errs.set(cur);
        }
    }

    /// **2.1.43-B（P2-1）**：该端点本次成功 ⇒ 清掉旧原因。
    pub fn err_clear(&self, ep: &str) {
        let mut cur = self.errs.get_untracked();
        let before = cur.clone();
        cur.clear(ep);
        if cur != before {
            self.errs.set(cur);
        }
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

/// 初始路由：`?route=` > `#hash` > pipeline（对齐 boot 的优先级）。
pub fn initial_route() -> Route {
    let Some(win) = web_sys::window() else {
        return Route::Pipeline;
    };
    let loc = win.location();
    if let Ok(search) = loc.search() {
        let s = search.trim_start_matches('?');
        for pair in s.split('&') {
            let mut it = pair.splitn(2, '=');
            if let (Some(k), Some(v)) = (it.next(), it.next()) {
                if k == "route" {
                    if let Some(r) = Route::from_str(v) {
                        return r;
                    }
                }
            }
        }
    }
    if let Ok(hash) = loc.hash() {
        let h = hash.trim_start_matches('#').trim_start_matches('/');
        if let Some(r) = Route::from_str(h) {
            return r;
        }
    }
    Route::Pipeline
}

/// 「清空」(#btn-qclear) 后的可见区间过滤（D16）。
///
/// 原件语义：`real.hiddenHistoryBefore = nowTs()` 之后，`manual_history` 里
/// `ts < hiddenHistoryBefore` 的记录不再渲染（`!(hidden && e && e.ts && String(e.ts) < hidden)`）。
/// `ts` 与 `hiddenHistoryBefore` 同为定宽 `HH:MM:SS.mmm` 本地时间串，字典序即时序；
/// 任一为空串时不过滤（与原件对缺 `ts` 记录的处理一致）。
pub fn history_visible(ts: &str, hidden_before: &str) -> bool {
    if hidden_before.is_empty() || ts.is_empty() {
        return true;
    }
    ts >= hidden_before
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_visible_empty_cursor_keeps_all() {
        assert!(history_visible("12:00:00.000", ""));
        assert!(history_visible("", ""));
    }

    #[test]
    fn history_visible_hides_older_records_only() {
        let cut = "12:00:00.000";
        assert!(!history_visible("11:59:59.999", cut));
        assert!(
            history_visible("12:00:00.000", cut),
            "同一毫秒保留（原件只有 < 才隐藏）"
        );
        assert!(history_visible("12:00:00.001", cut));
        assert!(history_visible("23:59:59.999", cut));
    }

    /// 缺 `ts` 的记录（后端异常/旧契约）不被隐藏，否则「清空」会把之后的新记录也吞掉。
    #[test]
    fn history_visible_keeps_records_without_ts() {
        assert!(history_visible("", "12:00:00.000"));
    }

    #[test]
    fn route_roundtrip() {
        for r in [
            Route::Pipeline,
            Route::Query,
            Route::Config,
            Route::Telemetry,
            Route::About,
        ] {
            assert_eq!(Route::from_str(r.as_str()), Some(r));
        }
        assert_eq!(Route::from_str("nope"), None);
    }

    /// **2.1.14 回归**：已删除的「规则管理」路由必须**不再存在**，
    /// 且 `?route=rules` / `#rules` 这类历史 URL 要**安全回退**到默认页
    /// （旧实现在 `main.rs` 里给 `Route::Rules` 写了三条分支，其中占位分支胜出 →
    /// 渲染空白页 `R`；现在解析层直接拒绝该串）。
    #[test]
    fn removed_rules_route_is_gone_and_falls_back_safely() {
        assert_eq!(Route::from_str("rules"), None, "rules 路由必须已删除");
        assert_eq!(initial_route(), Route::Pipeline);
        // 五个页面各自可往返，且没有任何 route 的 as_str 等于 "rules"。
        for r in [
            Route::Pipeline,
            Route::Query,
            Route::Config,
            Route::Telemetry,
            Route::About,
        ] {
            assert_ne!(r.as_str(), "rules");
        }
        assert_ne!(Route::Config.meta().0, "规则管理");
    }

    #[test]
    fn log_filters_set_get_clear() {
        let mut f = LogFilters::default();
        assert!(!f.any());
        f.set("dm", " example.com ".into());
        assert_eq!(f.get("dm"), " example.com ");
        assert!(f.any());
        f.clear();
        assert!(!f.any());
        assert_eq!(f.get("nope"), "");
    }

    /// **2.1.43-B（P2-1）**：`DataErrs` 的横幅必须带**端点名 + 原因**，清空后消失；
    /// 顶栏单行只报第一条（status > snapshot > pipeline > logs）。
    #[test]
    fn data_errs_banner_shows_endpoint_and_reason() {
        let mut e = DataErrs::default();
        assert_eq!(e.banner(), None, "全绿时不得有横幅");
        e.set(
            "snapshot",
            "/api/snapshot 响应解析失败（数据不可用）: missing field `cache`",
        );
        let b = e.banner().expect("有失败必须有横幅");
        assert!(b.starts_with("数据不可用："), "{b}");
        assert!(b.contains("/api/snapshot"), "必须带端点名：{b}");
        assert!(b.contains("missing field"), "必须带原因：{b}");
        // 优先级：status 压过 snapshot。
        e.set("status", "请求失败: timeout");
        assert!(e.banner().unwrap().contains("/api/status"));
        e.clear("status");
        assert!(
            e.banner().unwrap().contains("/api/snapshot"),
            "清掉 status 后必须回落到 snapshot"
        );
        e.clear("snapshot");
        assert_eq!(e.banner(), None, "全部恢复后横幅必须消失");
    }
}
