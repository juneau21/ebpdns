//! ebpdns Web 控制台 — Leptos CSR → WASM 入口。
//!
//! 结构与样式完全对齐 v1.9.162 `web/index.html`（侧栏 / 顶栏 / 五个路由页），
//! 数据来自 2.0 后端的 v1.9.162 兼容 API；图表沿用同源 ECharts。

// **2.1.29**：`web/` 是独立 workspace，此前 `scripts/check_all.sh` 只跑根 workspace 的
// fmt/clippy ⇒ 前端**从未**被 clippy 门禁覆盖。本轮把 web clippy 接入门禁时，
// 首次扫描暴露 22 条**与本次 eBPF/XDP 删除无关**的历史 lint（逐条见交付报告）。
// 为避免把纯风格改动混进"删除内核态缓存"补丁，这里按 lint 逐条 allow；后续单独清理。
#![allow(clippy::empty_line_after_doc_comments)]
#![allow(clippy::format_in_format_args)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::manual_clamp)]
#![allow(clippy::missing_const_for_thread_local)]
#![allow(clippy::type_complexity)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::neg_cmp_op_on_partial_ord)]
#![allow(clippy::manual_is_multiple_of)]

mod api;
mod echarts;
mod fmt;
mod fmtnum;
mod model;
mod pages;
mod poll;
mod poll_policy;
mod state;
mod ui;

use leptos::mount::mount_to_body;
use leptos::prelude::*;

use crate::state::{App, Mode, NoteKind, Route};

fn main() {
    console_error_panic_hook::set_once();
    let _ = console_log::init_with_level(log::Level::Warn);
    mount_to_body(Shell);
}

#[component]
fn Shell() -> impl IntoView {
    let app = App::new();
    provide_context(app);
    // 轮询只需启动一次（组件体只在挂载时执行一次）。
    poll::boot(app);

    view! {
        <div class="app">
            <Sidebar />
            <main class="main">
                <Topbar />
                <div class="routes">
                    {move || match app.route.get() {
                        Route::Pipeline => view! { <pages::PipelinePage /> }.into_any(),
                        Route::Query => view! { <pages::QueryPage /> }.into_any(),
                        Route::Config => view! { <pages::ConfigPage /> }.into_any(),
                        Route::Telemetry => view! { <pages::TelemetryPage /> }.into_any(),
                        Route::About => view! { <pages::AboutPage /> }.into_any(),
                    }}
                </div>
            </main>
        </div>
    }
}

/// 侧栏（品牌 / 导航 / 页脚状态）。
#[component]
fn Sidebar() -> impl IntoView {
    let app = expect_context::<App>();
    let st = poll::stats();

    // 键盘可达（a11y）：`role=button` + `tabindex=0` + Enter/Space 激活 + 可见焦点环。
    let nav_item = move |r: Route, label: &'static str| {
        let active = move || app.route.get() == r;
        view! {
            <div
                class="nav-item"
                class:active=active
                role="button"
                tabindex="0"
                aria-label=label
                on:click=move |_| app.route.set(r)
                on:keydown=move |ev: web_sys::KeyboardEvent| {
                    let k = ev.key();
                    if k == "Enter" || k == " " {
                        ev.prevent_default();
                        app.route.set(r);
                    }
                }
            >
                {nav_icon(r)}
                {label}
            </div>
        }
    };

    view! {
        <aside class="sidebar">
            <div class="brand">
                <svg class="brand-mark" viewBox="0 0 40 40" fill="none" stroke="currentColor" stroke-width="2.2">
                    <path d="M8 6h24v28H8z"></path>
                    <path d="M14 14h12M14 20h12M14 26h8"></path>
                    <circle cx="30" cy="30" r="6" fill="var(--bg)" stroke="currentColor"></circle>
                </svg>
                <div class="brand-name">
                    "ebpdns"<small>"RUST DNS RESOLVER"</small>
                </div>
            </div>
            <nav class="nav" aria-label="主导航">
                {nav_item(Route::Pipeline, "数据面流水线")}
                {nav_item(Route::Query, "查询控制台")}
                {nav_item(Route::Config, "配置")}
                {nav_item(Route::Telemetry, "遥测")}
                {nav_item(Route::About, "架构说明")}
            </nav>
            <div class="side-foot">
                <span class="dot"></span>
                <span id="foot-mode">{move || foot_mode(app)}</span>
                <span class="uptime" id="foot-uptime">
                    {move || app.uptime_text.get()}
                </span>
                // v2.1.7 前端埋点：/api/* 累计请求数 + 当前轮询节奏（用于量化刷新效率）。
                <span
                    class="uptime"
                    id="api-req"
                    title="前端埋点：/api/* 累计请求数（st=status sn=snapshot pl=pipeline lg=logs）· 当前轮询节奏"
                >
                    {move || {
                        let e = st.per_ep.get();
                        format!(
                            "req {} · st{}/sn{}/pl{}/lg{} · {}",
                            st.calls.get(),
                            e[0],
                            e[1],
                            e[2],
                            e[3],
                            st.cadence.get(),
                        )
                    }}
                </span>
                <span class="uptime" id="boot-ms" title="引导屏首帧 → WASM 就绪首帧（可交互）耗时">
                    {move || st.boot_text.get()}
                </span>
            </div>
        </aside>
    }
}

fn foot_mode(app: App) -> String {
    // 1.9.162 未检测到后端时会进入 SIM 演示；本版本在后端不可达时以空数据渲染，
    // 因此这里给出对应的降级文案（不伪造仿真数据）。
    match app.mode.get() {
        Mode::Real => "守护进程运行中 · REAL".to_string(),
        Mode::AuthFailed => "认证失败 · 请在「配置 → 连接设置」填入 API Token".to_string(),
        Mode::Down => "未连接后端守护进程".to_string(),
    }
}

fn nav_icon(r: Route) -> impl IntoView {
    match r {
        Route::Pipeline => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M3 7h6l2 5h8l2-3h0"></path>
                <circle cx="3" cy="7" r="1"></circle>
                <circle cx="21" cy="9" r="1.4"></circle>
                <path d="M3 17h10l1-3h7"></path>
                <circle cx="3" cy="17" r="1"></circle>
                <circle cx="21" cy="14" r="1.4"></circle>
            </svg>
        }
        .into_any(),
        Route::Query => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="3" y="4" width="18" height="16" rx="2"></rect>
                <path d="M7 9l3 3-3 3M13 15h4"></path>
            </svg>
        }
        .into_any(),
        Route::Config => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
                <path d="M4 8h10M18 8h2M4 16h2M10 16h10"></path>
                <circle cx="16" cy="8" r="2.2"></circle>
                <circle cx="8" cy="16" r="2.2"></circle>
            </svg>
        }
        .into_any(),
        Route::Telemetry => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M3 12h4l2.5-7 4 14 2.5-7H21"></path>
            </svg>
        }
        .into_any(),
        Route::About => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="9"></circle>
                <path d="M12 8v5"></path>
                <path d="M12 16v.01"></path>
            </svg>
        }
        .into_any(),
    }
}

/// 顶栏：标题 + 五个指标芯片 + 手动刷新/清空按钮。
#[component]
fn Topbar() -> impl IntoView {
    let app = expect_context::<App>();
    let meta = move || app.route.get().meta();

    let on_clear = move |_| {
        let app = app;
        if let Some(win) = web_sys::window() {
            let ok = win
                .confirm_with_message("清空全部统计与日志缓冲？该操作会调用后端 /api/reset。")
                .unwrap_or(false);
            if !ok {
                return;
            }
        }
        wasm_bindgen_futures::spawn_local(async move {
            match api::reset().await {
                Ok(_) => {
                    // 只清本地缓冲，**不动游标**：后端已清空事件环（seq 继续递增），
                    // 游标置 0 会把旧事件重新拉回来。
                    app.logs.set(Vec::new());
                    app.note_set("统计与日志已清空", NoteKind::Ok);
                }
                Err(e) => app.note_set(format!("清空失败：{e}"), NoteKind::Err),
            }
        });
    };

    view! {
        <header class="topbar">
            <div class="tb-title" id="tb-title">
                <span id="tb-title-main">{move || meta().0}</span>
                <small id="tb-sub">{move || meta().1}</small>
            </div>
            <div class="tb-metrics">
                <div class="mchip" title="最近窗口吞吐（QPS）">
                    <span class="k">"QPS"</span>
                    {live_span(
                        "m-qps",
                        "v",
                        move || fmt::group0(app.status_or_default().qps),
                    )}
                </div>
                <div class="mchip" title="缓存命中率（0–100%，后端按百分数下发）">
                    <span class="k">"命中率"</span>
                    {live_span(
                        "m-hit",
                        "v ok",
                        // v2.1.7 修正：后端 `/api/status.hit_rate` = `hit_rate_pct()`
                        // 已是 **0..100 百分数**（`ebpdns-server/src/api.rs:561`，
                        // 与 `/api/snapshot.history[].hit_rate` 同口径），此前这里再 ×100
                        // 会把 70.0% 显示成 6950.0%（实测截图可见）。
                        move || fmt::pct1(app.status_or_default().hit_rate),
                    )}
                </div>
                <div class="mchip" title="平均响应延迟（ms）">
                    <span class="k">"平均延迟"</span>
                    {live_span("m-lat", "v", move || {
                        match app.status_or_default().avg_latency_ms {
                            Some(v) if v.is_finite() => format!("{}ms", fmt::num1(v)),
                            _ => "–".to_string(),
                        }
                    })}
                </div>
                <div
                    class="mchip"
                    data-src="cache.used/cache.capacity"
                    title="用户态缓存条目 已用/容量（来源 = `/api/cache/stats.used` ÷ 配置 `cache_size`）。"
                >
                    <span class="k">"用户态缓存占用"</span>
                    {live_span("m-map", "v", move || {
                        // **2.1.18（修复项 24）**：读用户态缓存摘要（`/api/status.cache`），
                        // 不再读 `status.map`（历史兼容别名，内容相同但名字容易被误读成内核 map）。
                        let c = app.status_or_default().cache;
                        if c.capacity > 0.0 {
                            format!("{}/{}", fmt::group0(c.used), fmt::group0(c.capacity))
                        } else {
                            "–/–".to_string()
                        }
                    })}
                </div>
                <button
                    class="tb-btn"
                    id="btn-refresh"
                    aria-label="立即刷新"
                    title="立即刷新当前页数据（自动刷新固定 2s；请求失败时按 2s→4s→8s→16s→30s 退避）"
                    on:click=move |_| poll::kick()
                >
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M20 12a8 8 0 1 1-2.34-5.66"></path>
                        <path d="M20 4v5h-5"></path>
                    </svg>
                    "刷新"
                </button>
                <button class="tb-btn" id="btn-clear" aria-label="清空统计与日志" on:click=on_clear>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M4 7h16M9 7V5h6v2M6 7l1 13h10l1-13"></path>
                    </svg>
                    "清空"
                </button>
            </div>
        </header>
        // **2.1.43-B（P2-1）**：**数据不可用横幅**（顶栏常驻）。
        //
        // 审计：`api.rs` 的 5 处 `from_value(...).unwrap_or_default()` 把"响应解析失败 /
        // 字段缺失"静默降级成全 0 模型 ⇒ QPS/命中率/缓存占用/分段/规则数一律显示 0，
        // 与"真的 0"不可区分。现在 `decode()` 返回 Err，`poll` 把原因写进 `App.errs`，
        // 本横幅持续显示「数据不可用：<端点> <原因>」；恢复后自动消失（`err_clear`）。
        <div
            id="data-unavailable"
            class="data-unavailable"
            role="status"
            aria-live="polite"
            style:display=move || {
                if app.errs.get().banner().is_some() { "block" } else { "none" }
            }
        >
            {move || app.errs.get().banner().unwrap_or_default()}
        </div>
    }
}

/// 数值变化高亮：转调 `ui::live_span`（实现在 `ui.rs`，遥测页共用）。
fn live_span(id: &'static str, cls: &'static str, f: impl Fn() -> String + 'static) -> AnyView {
    ui::live_span(id, cls, f)
}
