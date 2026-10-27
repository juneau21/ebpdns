//! 启动与轮询（v2.1.32 / poll2s：单一 2s 节拍 + 按需 + 去重合并）。
//!
//! 与 2.1.7 的差别：
//! - **全端点统一 2000ms**：`/api/status`、`/api/snapshot`、`/api/pipeline`、
//!   `/api/logs` 都按 `poll_policy::TICK_MS` 调度；不再有 5s 端点，也不再有
//!   「无变化逐档降频到 8s/20s」——避免同一页面里多套节奏互相错位。
//! - **单调度循环**：整个前端只有一个 `TimeoutFuture`；每 2s 一个 tick，把「本 tick
//!   到期的全部端点」并发拉取（`zip` 折叠，Promise.all 语义）后**一次性**写状态。
//!   同一 tick 不可能重复请求同一端点，多次状态写入合并为一次渲染。
//! - **按需**：`/api/snapshot` 只在遥测页轮询（查询页按需单发）、`/api/pipeline`
//!   与 `/api/logs` 只在流水线页轮询（策略见 `poll_policy::Ep::needed_on`）。
//! - **失败退避**：非 401 失败按 2s→4s→8s→16s→30s 倍增封顶；任一成功立即回 2s。
//!   退避只影响该端点，全局 tick 仍是 2s。
//! - **可见性**：`document.hidden` 时不取数、不推进节拍；回到前台立即补一轮。
//! - **手动刷新**：顶栏「刷新」按钮调用 [`kick`]，立即补一轮（不影响自动 2s 节拍）。
//! - **页脚时钟本地外推**：`uptime` 由 1s 本地时钟基于最后一次 `/api/status` 的外推锚点
//!   计算，不为刷新时钟额外发请求。
//! - 401 → `on_auth_lost`：停机、切配置页、页脚红字（行为与 2.1.6 一致）。
//!
//! 文案与 DOM 契约（`#foot-mode`/`#foot-uptime` 等）保持不变；新增的
//! `#api-req`/`#boot-ms` 只是附加展示，不影响既有选择器。

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use crate::api;
use crate::poll_policy::{Delta, Ep, RouteId, Scheduler, TICK_MS};
use crate::state::{App, Mode, NoteKind, Route};
use futures_lite::future::{race, zip};
use gloo_timers::future::TimeoutFuture;
use leptos::prelude::*;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::spawn_local;

/// 日志控制台保留条数（对齐 1.9.162 的 300 行上限）。
const LOG_MAX: usize = 300;
/// 隐藏（后台标签）时暂停取数，最长睡 1s 再查一次可见性；回前台由通知提前唤醒。
const HIDDEN_SLEEP_MS: u32 = 1_000;
/// `/api/config` 兜底重试间隔（首屏失败时）。
const CONFIG_RETRY_MS: u64 = 10_000;

fn hidden() -> bool {
    web_sys::window()
        .and_then(|w| w.document())
        .map(|d| d.hidden())
        .unwrap_or(false)
}

fn ms_now() -> u64 {
    js_sys::Date::now().max(0.0) as u64
}

fn rid(r: Route) -> RouteId {
    match r {
        Route::Pipeline => RouteId::Pipeline,
        Route::Query => RouteId::Query,
        Route::Config => RouteId::Config,
        Route::Telemetry => RouteId::Telemetry,
        Route::About => RouteId::About,
    }
}

/* ======================= 前端埋点计数器（页脚 / 架构页可见） ======================= */

/// 请求计数与节奏快照（信号句柄；在 `boot` 的 Owner 上下文内创建）。
#[derive(Clone, Copy)]
pub struct Stats {
    /// `/api/*` 累计请求数（含 config 首屏与查询页手动补充的请求）。
    pub calls: RwSignal<u64>,
    /// 按端点累计（顺序同 `Ep::ALL`：status/snapshot/pipeline/logs）。
    pub per_ep: RwSignal<[u64; 4]>,
    /// 页脚节奏文案（正常 `2s`，失败退避时 `退避 30s`）。
    pub cadence: RwSignal<String>,
    /// 首屏耗时文案（`boot 42ms · 首帧 18ms`）。
    pub boot_text: RwSignal<String>,
}

impl Stats {
    fn new() -> Self {
        Stats {
            calls: RwSignal::new(0),
            per_ep: RwSignal::new([0u64; 4]),
            cadence: RwSignal::new("2s".into()),
            boot_text: RwSignal::new("–".into()),
        }
    }
}

thread_local! {
    /// 全局唯一实例；`boot` 内创建（保证在响应式 Owner 上下文里）。
    static STATS: RefCell<Option<Stats>> = const { RefCell::new(None) };
    /// 各端点上一次的「变化指纹」：仅用于统计/兼容旧的 Delta 语义，不再影响节奏。
    static LAST_SIG: RefCell<[Option<String>; 4]> = const { RefCell::new([None, None, None, None]) };
    /// status 连续失败计数（≥3 → Mode::Down）。
    static STATUS_FAILS: Cell<u32> = const { Cell::new(0) };
    /// 页脚节奏文案去重（避免每 tick 写信号 → 每 tick 重渲染页脚）。
    static LAST_CADENCE: RefCell<String> = const { RefCell::new(String::new()) };
    /// `/api/config` 兜底重试的上次尝试时刻。
    static LAST_CFG_TRY: Cell<u64> = const { Cell::new(0) };
    /// 查询页按需快照的「在途」标记（合并重复请求：在途时丢弃后来的同端点请求）。
    static SNAPSHOT_ONESHOT: Cell<bool> = const { Cell::new(false) };
    /// 页脚时钟锚点：(后端 uptime_s, 本地锚定时刻 ms, 版本号)。
    static UP: RefCell<(f64, f64, String)> = const { RefCell::new((0.0, 0.0, String::new())) };
}

/// 取计数句柄（`boot` 之前调用时给出一个临时信号，避免 panic）。
pub fn stats() -> Stats {
    STATS.with(|s| {
        s.borrow().unwrap_or_else(|| {
            // 只可能在极早的渲染路径上触发；创建后不缓存，保持语义简单。
            Stats::new()
        })
    })
}

fn count(ep: Ep) {
    STATS.with(|s| {
        if let Some(st) = *s.borrow() {
            st.calls.update(|c| *c += 1);
            st.per_ep.update(|v| v[ep.idx()] += 1);
        }
    });
}

/// 端点外的一次性请求（首屏 `/api/config` 等）也计入总请求数。
fn count_extra() {
    STATS.with(|s| {
        if let Some(st) = *s.borrow() {
            st.calls.update(|c| *c += 1);
        }
    });
}

fn publish_cadence(sched: &Scheduler, route: RouteId) {
    let text = sched.cadence_text(route);
    let changed = LAST_CADENCE.with(|c| {
        let mut g = c.borrow_mut();
        if *g == text {
            false
        } else {
            *g = text.clone();
            true
        }
    });
    if changed {
        STATS.with(|s| {
            if let Some(st) = *s.borrow() {
                st.cadence.set(text);
            }
        });
    }
}

/// 变化指纹比对：返回 `true` 表示与上轮不同（有变化）。
fn remember(ep: Ep, sig: String) -> bool {
    LAST_SIG.with(|l| {
        let mut g = l.borrow_mut();
        let i = ep.idx();
        let changed = g[i].as_deref() != Some(sig.as_str());
        g[i] = Some(sig);
        changed
    })
}

/* ======================= 可见性 / 交互通知 ======================= */

/// 通用「一次性通知」：回前台通知与交互升频通知共用。
struct Notifier {
    signaled: Cell<bool>,
    wakers: RefCell<Vec<Waker>>,
}

impl Notifier {
    fn new() -> Self {
        Notifier {
            signaled: Cell::new(false),
            wakers: RefCell::new(Vec::new()),
        }
    }

    /// 置位 + 唤醒全部等待者。
    fn signal(&self) {
        self.signaled.set(true);
        let ws: Vec<Waker> = self.wakers.borrow_mut().drain(..).collect();
        for w in ws {
            w.wake();
        }
    }

    /// 清掉待处理标记（不唤醒，让循环自然到期）。
    fn clear(&self) {
        self.signaled.set(false);
    }

    fn take(&self) -> bool {
        self.signaled.replace(false)
    }
}

/// `wait_on()` 返回的 Future：等待一次通知。
struct WaitOn {
    n: Rc<Notifier>,
    /// 本轮注册的 waker（Drop 时按 `will_wake` 摘除，避免长时间运行无界增长）。
    registered: RefCell<Option<Waker>>,
}

impl Future for WaitOn {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.n.take() {
            return Poll::Ready(());
        }
        let this = self.get_mut();
        {
            let mut ws = this.n.wakers.borrow_mut();
            if !ws.iter().any(|w| w.will_wake(cx.waker())) {
                ws.push(cx.waker().clone());
            }
        }
        *this.registered.borrow_mut() = Some(cx.waker().clone());
        // 注册后再确认一次，避免「注册前 signal」丢唤醒。
        if this.n.take() {
            return Poll::Ready(());
        }
        Poll::Pending
    }
}

impl Drop for WaitOn {
    fn drop(&mut self) {
        if let Some(mine) = self.registered.borrow_mut().take() {
            self.n.wakers.borrow_mut().retain(|w| !w.will_wake(&mine));
        }
    }
}

thread_local! {
    /// 单页生命周期内常驻。
    static VIS: Rc<Notifier> = Rc::new(Notifier::new());
    /// 交互升频通知（筛选/搜索/手动查询/配置保存）。
    static KICK: Rc<Notifier> = Rc::new(Notifier::new());
    /// 监听回调句柄：必须常驻，drop 会导致 JS 侧回调失效。
    static VIS_CB: RefCell<Option<Closure<dyn FnMut()>>> = const { RefCell::new(None) };
}

fn wait_on(n: &Rc<Notifier>) -> WaitOn {
    WaitOn {
        n: n.clone(),
        registered: RefCell::new(None),
    }
}

/// 睡眠被提前唤醒的原因。
#[derive(Clone, Copy, PartialEq, Eq)]
enum Wake {
    Timeout,
    Visible,
    Kick,
}

/// 睡 `ms`，或被「回前台」/「交互升频」通知提前唤醒。
async fn sleep_or_wake(ms: u32) -> Wake {
    let vis = VIS.with(|n| n.clone());
    let kick = KICK.with(|n| n.clone());
    race(
        async {
            TimeoutFuture::new(ms).await;
            Wake::Timeout
        },
        race(
            async {
                wait_on(&vis).await;
                Wake::Visible
            },
            async {
                wait_on(&kick).await;
                Wake::Kick
            },
        ),
    )
    .await
}

/// 安装 `visibilitychange` 监听（幂等，仅在 boot 调一次）。
fn install_visibility_listener() {
    let Some(doc) = web_sys::window().and_then(|w| w.document()) else {
        return;
    };
    VIS_CB.with(|slot| {
        if slot.borrow().is_some() {
            return;
        }
        let cb = Closure::<dyn FnMut()>::new(move || {
            if hidden() {
                // 隐藏：暂停取数（循环只睡不拉），清标记避免恢复时误触发。
                VIS.with(|w| w.clear());
            } else {
                // 回前台：立即唤醒并补一轮。
                VIS.with(|w| w.signal());
            }
        });
        let _ =
            doc.add_event_listener_with_callback("visibilitychange", cb.as_ref().unchecked_ref());
        *slot.borrow_mut() = Some(cb);
    });
}

/// 交互 / 手动刷新：下一次 tick 立即拉取（不再有空闲降频）。
pub fn kick() {
    KICK.with(|k| k.signal());
}

/* ======================= 展示助手 ======================= */

/// 把秒数格式化成 1.9.162 页脚的 `1m 8s` 形式。
fn human_uptime(s: f64) -> String {
    let t = if s.is_finite() && s > 0.0 {
        s as u64
    } else {
        0
    };
    let (h, m, sec) = (t / 3600, (t % 3600) / 60, t % 60);
    if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m {sec}s")
    }
}

/// 页脚时钟：以「最后一次 /api/status 的 uptime_s + 本地经过时间」外推，
/// 与轮询频率解耦（固定 2s 刷新也不会让时钟跳变）。
fn anchor_uptime(s: &crate::model::Status) {
    UP.with(|u| {
        let mut g = u.borrow_mut();
        g.0 = s.uptime_s;
        g.1 = js_sys::Date::now();
        g.2 = s.version.clone();
    });
}

/// 由锚点外推得到当前 uptime 文案（锚点未就绪 → None）。
fn uptime_now() -> Option<String> {
    UP.with(|u| {
        let g = u.borrow();
        if g.2.is_empty() {
            return None;
        }
        let t = g.0 + ((js_sys::Date::now() - g.1) / 1000.0).max(0.0);
        Some(format!("up {} · v{}", human_uptime(t), g.2))
    })
}

/// 把外推文案写进页脚（值未变则不写信号，避免无谓重渲染）。
fn sync_uptime_text(app: App) {
    if let Some(t) = uptime_now() {
        if app.uptime_text.get_untracked() != t {
            app.uptime_text.set(t);
        }
    }
}

async fn uptime_ticker(app: App) {
    loop {
        TimeoutFuture::new(1_000).await;
        if hidden() {
            continue;
        }
        sync_uptime_text(app);
    }
}

/// 读取 `index.html` 引导脚本写入的 `window.__ebpdns_boot` 指标。
fn boot_metric(key: &str) -> f64 {
    web_sys::window()
        .and_then(|w| js_sys::Reflect::get(&w, &JsValue::from_str("__ebpdns_boot")).ok())
        .and_then(|b| js_sys::Reflect::get(&b, &JsValue::from_str(key)).ok())
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0)
}

/// 首屏耗时：`init()` 完成后的首帧（interactive）与引导屏首帧（first_paint）。
async fn boot_metrics_ticker(app: App) {
    for ms in [1_200u32, 2_000, 3_000] {
        TimeoutFuture::new(ms).await;
        let t0 = boot_metric("t0");
        if t0 <= 0.0 {
            continue;
        }
        let fp = boot_metric("first_paint");
        let it = boot_metric("interactive");
        let txt = if it > 0.0 && fp > 0.0 {
            format!(
                "boot {:.0}ms · 首帧 {:.0}ms",
                (it - t0).max(0.0),
                (fp - t0).max(0.0)
            )
        } else {
            format!("boot {:.0}ms", (fp - t0).max(0.0))
        };
        STATS.with(|s| {
            if let Some(st) = *s.borrow() {
                st.boot_text.set(txt);
            }
        });
        let _ = app;
    }
}

/* ======================= 变化指纹 ======================= */

fn sig_status(s: &crate::model::Status) -> String {
    let c = &s.counters;
    format!(
        "{:.0}/{:.0}/{:.0}/{:.0}|q{:.2}|h{:.4}|l{}|m{:.0}/{:.0}",
        c.total,
        c.hit,
        c.miss,
        c.upstream_queries + c.errors,
        s.qps,
        s.hit_rate,
        s.avg_latency_ms.map(|v| v.round()).unwrap_or(-1.0),
        s.map.used,
        s.map.capacity,
    )
}

fn sig_snapshot(s: &crate::model::Snapshot) -> String {
    let tail: Vec<String> = s
        .history
        .iter()
        .rev()
        .take(2)
        .map(|h| format!("{}/{:.0}/{:.1}", h.label, h.qps, h.lat))
        .collect();
    let ups = s.upstreams.iter().fold(0.0, |a, u| {
        a + u.queries + u.success_rate.unwrap_or(0.0).round()
    });
    format!(
        "h{}|{}|A{:.0}/AAAA{:.0}/O{:.0}|c{:.0}|m{:.0}|u{}|{:.0}",
        s.history.len(),
        tail.join(","),
        s.qtype_dist.a,
        s.qtype_dist.aaaa,
        s.qtype_dist.other,
        s.counters.total,
        s.map.used,
        s.upstreams.len(),
        ups
    )
}

fn sig_pipeline(p: &crate::model::Pipeline) -> String {
    let ups: Vec<String> = p
        .upstreams
        .iter()
        .map(|u| format!("{}:{}:{}", u.id, u.name, u.proto))
        .collect();
    format!(
        "{}|{}|{}",
        p.cache_size,
        p.cache_direct_enabled,
        ups.join(",")
    )
}

/* ======================= 端点取数 ======================= */

async fn fetch_status(app: App) -> Delta {
    count(Ep::Status);
    match api::status().await {
        Ok(s) => {
            // 只在取值变化时写信号（渲染代理：把一个 tick 的状态写次数压到 1 次）。
            if s.app == "ebpdns" && app.mode.get_untracked() != Mode::Real {
                app.mode.set(Mode::Real);
            }
            anchor_uptime(&s);
            sync_uptime_text(app);
            STATUS_FAILS.with(|c| c.set(0));
            // **2.1.43-B（P2-1）**：本次成功 ⇒ 清掉"数据不可用"的旧原因（含解析失败）。
            app.err_clear("status");
            let changed = remember(Ep::Status, sig_status(&s));
            app.status.set(Some(s));
            let token = if api::get_token().is_empty() {
                "未配置(不携带认证头)"
            } else {
                "已配置 · 连通正常"
            };
            if app.token_status.get_untracked() != token {
                app.token_status.set(token.into());
            }
            if changed {
                Delta::Changed
            } else {
                Delta::Same
            }
        }
        Err(e) => {
            if e.is_auth_error {
                return Delta::AuthFail;
            }
            // **2.1.43-B（P2-1）**：解析失败（"数据不可用"）与网络失败一样必须**持续可见**
            // —— 顶栏横幅读 `App.errs`，配置页「连接」卡片读 `token_status`。
            app.err_set("status", &e.message);
            let msg = format!("请求失败: {}", e.message);
            if app.token_status.get_untracked() != msg {
                app.token_status.set(msg);
            }
            let n = STATUS_FAILS.with(|c| {
                let v = c.get().saturating_add(1);
                c.set(v);
                v
            });
            if n >= 3 && app.mode.get_untracked() != Mode::Down {
                app.mode.set(Mode::Down);
            }
            Delta::Failed
        }
    }
}

async fn fetch_snapshot(app: App) -> Delta {
    count(Ep::Snapshot);
    match api::snapshot().await {
        Ok(s) => {
            app.err_clear("snapshot");
            let changed = remember(Ep::Snapshot, sig_snapshot(&s));
            app.snapshot.set(Some(s));
            if changed {
                Delta::Changed
            } else {
                Delta::Same
            }
        }
        Err(e) => {
            if e.is_auth_error {
                return Delta::AuthFail;
            }
            // **2.1.43-B（P2-1）**：快照解析失败 ⇒ 顶栏横幅 + 一次性提示（不再静默归零）。
            app.err_set("snapshot", &e.message);
            if !SNAP_NOTE.with(|c| c.replace(true)) {
                app.note_set(
                    format!("快照接口请求失败(将持续重试): {}", e.message),
                    NoteKind::Warn,
                );
            }
            Delta::Failed
        }
    }
}

async fn fetch_pipeline(app: App) -> Delta {
    count(Ep::Pipeline);
    match api::pipeline().await {
        Ok(p) => {
            app.err_clear("pipeline");
            let changed = remember(Ep::Pipeline, sig_pipeline(&p));
            app.pipeline.set(Some(p));
            if changed {
                Delta::Changed
            } else {
                Delta::Same
            }
        }
        Err(e) => {
            if e.is_auth_error {
                return Delta::AuthFail;
            }
            // **2.1.43-B（P2-1）**：流水线解析失败 ⇒ 统计条显示「未知」+ 顶栏原因。
            app.err_set("pipeline", &e.message);
            if !PIPE_NOTE.with(|c| c.replace(true)) {
                app.note_set(
                    format!("流水线接口请求失败(将持续重试): {}", e.message),
                    NoteKind::Warn,
                );
            }
            Delta::Failed
        }
    }
}

thread_local! {
    /// 失败提示只给一条（避免 2s 轮询刷屏）。
    static SNAP_NOTE: Cell<bool> = const { Cell::new(false) };
    static PIPE_NOTE: Cell<bool> = const { Cell::new(false) };
    /// **2.1.43-B（P2-1）**：`/api/logs` 失败也只提示一次；**持续状态**在 `App.errs`。
    static LOGS_NOTE: Cell<bool> = const { Cell::new(false) };
}

/// `/api/logs`：**增量**（`next_seq` 游标）+ 本地缓冲上限。
async fn fetch_logs(app: App) -> Delta {
    count(Ep::Logs);
    let since = app.log_seq.get_untracked();
    let filters = app.filters.get_untracked();
    let q = app.global_q.get_untracked();
    match api::logs(since, &filters, &q).await {
        Ok(r) => {
            // **2.1.43-B（P2-1）**：日志恢复 ⇒ 清掉横幅原因 + 允许下一次失败再提示一次。
            app.err_clear("logs");
            LOGS_NOTE.with(|c| c.set(false));
            // next_seq 回退说明后端重启过，清空本地缓冲。
            if (r.next_seq as u64) < since {
                app.logs.set(Vec::new());
            }
            app.log_seq.set(r.next_seq as u64);
            if r.events.is_empty() {
                return Delta::Same;
            }
            let evs = r.events;
            app.logs.update(|v| {
                v.extend(evs);
                let n = v.len();
                if n > LOG_MAX {
                    v.drain(0..n - LOG_MAX);
                }
            });
            Delta::Changed
        }
        Err(e) => {
            if e.is_auth_error {
                return Delta::AuthFail;
            }
            // **2.1.43-B（P2-1）**：旧实现此处只 `Delta::Failed`（**完全静默**）：日志
            // 接口 500 / 响应解析失败时页面既不报错也不长新行，运维会以为"没有查询"。
            // 现在：①`App.errs` 记原因 ⇒ 顶栏横幅持续显示；②首次失败给一条 Warn 提示
            // （`#log-count` 旁边不刷屏）；③恢复后自动清除（见上面的 Ok 分支）。
            app.err_set("logs", &e.message);
            if !LOGS_NOTE.with(|c| c.replace(true)) {
                app.note_set(
                    format!("日志接口请求失败(将持续重试): {}", e.message),
                    NoteKind::Warn,
                );
            }
            Delta::Failed
        }
    }
}

async fn fetch_ep(app: App, ep: Ep) -> Vec<(Ep, Delta)> {
    let d = match ep {
        Ep::Status => fetch_status(app).await,
        Ep::Snapshot => fetch_snapshot(app).await,
        Ep::Pipeline => fetch_pipeline(app).await,
        Ep::Logs => fetch_logs(app).await,
    };
    vec![(ep, d)]
}

/// 本 tick 的全部到期端点**并发**拉取（`zip` 折叠 = Promise.all 语义），
/// 结果一次性返回给调用方统一写状态（合并渲染）。
async fn run_tick(app: App, due: &[Ep]) -> Vec<(Ep, Delta)> {
    type Fut = Pin<Box<dyn Future<Output = Vec<(Ep, Delta)>>>>;
    fn bx<F: Future<Output = Vec<(Ep, Delta)>> + 'static>(f: F) -> Fut {
        Box::pin(f)
    }
    let mut futs: Vec<Fut> = due.iter().map(|ep| bx(fetch_ep(app, *ep))).collect();
    while futs.len() > 1 {
        let b = futs.pop().expect("len>1");
        let a = futs.pop().expect("len>1");
        futs.push(bx(async move {
            let (mut x, y) = zip(a, b).await;
            x.extend(y);
            x
        }));
    }
    match futs.pop() {
        Some(f) => f.await,
        None => Vec::new(),
    }
}

/// 首屏 `/api/config`（失败时由调度循环兜底重试）。
async fn fetch_config(app: App) -> bool {
    count_extra();
    if let Ok(c) = api::config().await {
        app.config.set(Some(c));
        app.cfg_epoch.update(|e| *e += 1);
        true
    } else {
        false
    }
}

/// 查询页按需补一次快照（合并：在途时丢弃重复请求）。
pub fn refresh_snapshot(app: App) {
    if SNAPSHOT_ONESHOT.with(|c| c.replace(true)) {
        return;
    }
    spawn_local(async move {
        let _ = fetch_snapshot(app).await;
        SNAPSHOT_ONESHOT.with(|c| c.set(false));
    });
}

/* ======================= 启动 ======================= */

/// boot：探测后端并启动唯一调度循环。
pub fn boot(app: App) {
    // 计数/节奏信号必须在这里创建（组件体 = 有 Owner 的响应式上下文）。
    STATS.with(|s| *s.borrow_mut() = Some(Stats::new()));
    install_visibility_listener();
    // 首屏占位：真实 uptime 由首个 /api/status 的锚点 + 本地时钟外推补齐。
    app.uptime_text.set("正在连接…".into());
    // 首屏 `/api/config` 由 boot 并发发出，这里先把「上次尝试时刻」记为现在，
    // 否则调度循环第一轮会在 config 尚未返回时**重复**再发一次配置请求。
    LAST_CFG_TRY.with(|c| c.set(ms_now()));

    spawn_local(uptime_ticker(app));
    spawn_local(boot_metrics_ticker(app));

    // 交互升频：筛选/全局搜索变化 → 立即补一轮日志（首次运行不触发）。
    Effect::new(move |prev: Option<()>| {
        if prev.is_none() {
            return;
        }
        let _ = app.filters.get();
        let _ = app.global_q.get();
        kick();
    });

    spawn_local(async move {
        // 配置与首轮状态请求并发，省一跳串行等待（`refresh_loop` 永不返回）。
        let cfg = fetch_config(app);
        let lp = refresh_loop(app);
        let _ = zip(cfg, lp).await;
    });
}

/// 唯一调度循环：固定 2s 节拍 + 按需 + 单 tick 去重合并。
///
/// 整个前端只有这一个周期性 timer：每 2s 醒来一次，只拉当前路由按需的端点。
/// 失败退避只改端点的 `next_due`，不会新增 timer，也不改变全局 2s 节拍。
async fn refresh_loop(app: App) {
    let mut sched = Scheduler::new(ms_now());
    // 下一 tick 的计划时刻（不是请求完成时刻）：保证 60s 内稳定 ~30 个 tick，
    // 不会因为请求耗时把 2s 拖成 4s。
    let mut next_tick = ms_now();
    loop {
        // 不可见：暂停取数，也不推进节拍（回前台立刻补一轮）。
        if hidden() {
            if sleep_or_wake(HIDDEN_SLEEP_MS).await != Wake::Timeout {
                sched.kick(ms_now());
                next_tick = ms_now();
            }
            continue;
        }

        // 等到本 tick 的计划时刻；被「回前台 / 交互 / 手动刷新」提前唤醒则立即补一轮。
        let now = ms_now();
        if now < next_tick {
            let wait = (next_tick - now).min(TICK_MS as u64) as u32;
            if sleep_or_wake(wait).await != Wake::Timeout {
                sched.kick(ms_now());
                next_tick = ms_now();
            }
            continue;
        }

        // `/api/config` 兜底重试（首屏失败才发生，10s 一次）。
        if app.config.get_untracked().is_none() {
            let now = ms_now();
            let due = LAST_CFG_TRY.with(|c| {
                let last = c.get();
                if now.saturating_sub(last) >= CONFIG_RETRY_MS {
                    c.set(now);
                    true
                } else {
                    false
                }
            });
            if due && fetch_config(app).await {
                app.note_set("配置已加载", NoteKind::Ok);
            }
        }

        let route = rid(app.route.get_untracked());
        let tick_at = next_tick;
        let due = sched.due(route, tick_at);

        if !due.is_empty() {
            let results = run_tick(app, &due).await;
            let mut auth = false;
            for (ep, delta) in results {
                if delta == Delta::AuthFail {
                    auth = true;
                }
                // 用 tick 计划时刻回填：请求耗时不会把下一次 2s 推后。
                sched.note(ep, delta, tick_at);
            }
            publish_cadence(&sched, route);
            if auth {
                on_auth_lost(app, "API Token 无效或缺失");
                return;
            }
        } else {
            publish_cadence(&sched, route);
        }

        // 固定节拍：下一 tick = 本 tick + 2s；若请求本身耗时超过 2s，
        // 跳过错过的 tick（不补发、不形成请求风暴），从当前时刻重新对齐。
        next_tick = next_tick.saturating_add(TICK_MS as u64);
        let after = ms_now();
        if next_tick <= after {
            next_tick = after.saturating_add(TICK_MS as u64);
        }
    }
}

/// 认证失效处理：切配置页 + 页脚红字 + 停止日志/流水线数据（循环各自检查 mode）。
pub fn on_auth_lost(app: App, msg: &str) {
    app.mode.set(Mode::AuthFailed);
    app.route.set(Route::Config);
    app.token_status.set(format!("认证失败(401): {msg}"));
    app.note_set(
        "认证失败 · 请在「连接设置」填入正确 API Token 后保存",
        NoteKind::Err,
    );
    app.logs.set(Vec::new());
    app.log_seq.set(0);
    // 认证失效后不再需要「回前台补一轮」：清掉待处理标记。
    VIS.with(|w| w.clear());
}
