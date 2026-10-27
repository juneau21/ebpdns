//! Telemetry 路由：KPI 数字 + 5 张 ECharts 图（命中率 / 吞吐 / 延迟 / qtype 环形 / 上游延迟）
//! + 用户态缓存占用条 + 上游健康度表 + Top N 统计。
//!
//! DOM 逐字复刻 v1.9.162 `web/index.html` 第 967–1019 行；行为对齐
//! refreshMapUI(1805–1822)、initCharts(1831–1865)、refreshCharts(1878–1898)、
//! chartUpOpt(1899–1918)、refreshKpiNums(1954–2014)、refreshTelemetryUI(2015–2060)
//! 与 pollSnapshot 的 telemetry 分支(3250–3253)。

use std::cell::{Cell, RefCell};

use crate::echarts::{self, UpBar};
use crate::fmt;
use crate::model::UpstreamStat;
use crate::state::{App, Mode, Route};
use crate::ui;
use gloo_timers::future::TimeoutFuture;
use leptos::prelude::*;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::spawn_local;

/// 5 个图表容器 id（顺序与 initCharts 一致：hit/qps/lat/qtypes/up）。
const CHART_IDS: [&str; 5] = ["ch-hit", "ch-qps", "ch-lat", "ch-qtypes", "ch-up"];
/// 图表库重试上限（对齐 `_ECHARTS_MAX_RETRY = 20`），间隔 300ms ≈ 6s。
const ECHARTS_MAX_RETRY: u32 = 20;
const ECHARTS_RETRY_MS: u32 = 300;

thread_local! {
    /// 图表实例句柄（hit/qps/lat/qtypes/up）。
    /// `JsValue` 非 `Send + Sync`，放不进同步存储的 `RwSignal`；本页同一时刻只挂载一个
    /// 实例，故用线程局部变量持有句柄，组件卸载时统一 dispose（对齐 initCharts）。
    static CHARTS: RefCell<[Option<JsValue>; 5]> =
        const { RefCell::new([None, None, None, None, None]) };
    /// window `resize` 回调句柄：不持有会被 GC 回收（对齐原件 ResizeObserver 的兜底）。
    static RESIZE_CB: RefCell<Option<Closure<dyn FnMut()>>> = RefCell::new(None);
    /// 初始化代次：组件卸载后让仍在重试的异步任务提前退出，避免写入已 dispose 的句柄。
    static CHART_GEN: Cell<u32> = const { Cell::new(0) };
    /// 每张图是否已首绘（首绘 `notMerge=true` 重建，之后走 diff + 过渡动画）。
    static DRAWN: Cell<[bool; 5]> = const { Cell::new([false; 5]) };
    /// 容器最近一次的 (宽,高)：尺寸没变就不 resize（减少无谓重绘）。
    static CHART_SIZE: RefCell<[(i32, i32); 5]> = const { RefCell::new([(0, 0); 5]) };
}

/// 首绘判定：返回 `true` 表示这是本实例的第一次绘制。
fn take_first(i: usize) -> bool {
    DRAWN.with(|d| {
        let mut v = d.get();
        let first = !v[i];
        v[i] = true;
        d.set(v);
        first
    })
}

fn reset_drawn() {
    DRAWN.with(|d| d.set([false; 5]));
    CHART_SIZE.with(|s| s.borrow_mut().copy_from_slice(&[(0, 0); 5]));
}

fn chart_gen() -> u32 {
    CHART_GEN.with(|g| g.get())
}

fn bump_chart_gen() -> u32 {
    CHART_GEN.with(|g| {
        let v = g.get().wrapping_add(1);
        g.set(v);
        v
    })
}

fn has_chart(i: usize) -> bool {
    CHARTS.with(|c| c.borrow()[i].is_some())
}

fn put_chart(i: usize, chart: JsValue) {
    CHARTS.with(|c| c.borrow_mut()[i] = Some(chart));
}

/// 对第 `i` 个图表实例执行操作（未初始化则跳过，对齐 `if (!charts.hit) return;`）。
fn with_chart(i: usize, f: impl FnOnce(&JsValue)) {
    CHARTS.with(|c| {
        if let Some(chart) = c.borrow()[i].as_ref() {
            f(chart);
        }
    });
}

/// 按容器尺寸自适应：容器尺寸变化才 `resize()`（减少无谓重绘）。
///
/// 不用 ResizeObserver（需给 web-sys 加 feature）：窗口 resize、切页、响应式断点
/// 都会改变容器尺寸，这里在每次快照重绘与窗口 resize 时比对缓存的 (宽,高)。
fn fit_charts() {
    let Some(doc) = web_sys::window().and_then(|w| w.document()) else {
        return;
    };
    for (i, id) in CHART_IDS.iter().enumerate() {
        let Some(el) = doc.get_element_by_id(id) else {
            continue;
        };
        let (w, h) = (el.client_width(), el.client_height());
        if w <= 0 || h <= 0 {
            continue;
        }
        let changed = CHART_SIZE.with(|s| {
            let mut v = s.borrow_mut();
            if v[i] != (w, h) {
                v[i] = (w, h);
                true
            } else {
                false
            }
        });
        if changed {
            with_chart(i, |c| echarts::resize_if_visible(id, c));
        }
    }
}

/// 窗口尺寸变化 → 逐个容器比对并 resize。
fn resize_charts() {
    fit_charts();
}

/// 逐个 `chart.dispose()` 并清空句柄。
fn dispose_charts() {
    CHARTS.with(|c| {
        let mut slots = c.borrow_mut();
        for slot in slots.iter_mut() {
            if let Some(chart) = slot.take() {
                echarts::dispose(&chart);
            }
        }
    });
    bump_chart_gen();
    reset_drawn();
}

fn install_resize_listener() {
    let Some(win) = web_sys::window() else {
        return;
    };
    if RESIZE_CB.with(|c| c.borrow().is_some()) {
        return;
    }
    let cb = Closure::<dyn FnMut()>::new(resize_charts);
    if win
        .add_event_listener_with_callback("resize", cb.as_ref().unchecked_ref())
        .is_ok()
    {
        RESIZE_CB.with(|c| *c.borrow_mut() = Some(cb));
    }
}

fn remove_resize_listener() {
    let cb = RESIZE_CB.with(|c| c.borrow_mut().take());
    if let Some(cb) = cb {
        if let Some(win) = web_sys::window() {
            let _ = win.remove_event_listener_with_callback("resize", cb.as_ref().unchecked_ref());
        }
        // cb 在此 drop：监听已移除，不会留下悬垂回调。
    }
}

/// 初始化 5 个图表；图表库未就绪时每 300ms 重试，超过上限给出可见提示。
fn spawn_init_charts(app: App) {
    let gen = chart_gen();
    spawn_local(async move {
        let mut retry: u32 = 0;
        loop {
            if chart_gen() != gen {
                return;
            }
            if echarts::available() {
                for (i, id) in CHART_IDS.iter().enumerate() {
                    if !has_chart(i) {
                        if let Some(chart) = echarts::init(id) {
                            put_chart(i, chart);
                        }
                    }
                }
                reset_drawn();
                break;
            }
            retry += 1;
            if retry > ECHARTS_MAX_RETRY {
                // 同源 echarts.min.js 部署遗漏：兜底提示，不再空转。
                echarts::set_text(CHART_IDS[0], "图表库未加载");
                return;
            }
            TimeoutFuture::new(ECHARTS_RETRY_MS).await;
        }
        if chart_gen() == gen {
            draw_charts(app);
        }
    });
}

/// 重绘 5 张图（对齐 refreshCharts / chartUpOpt）。
///
/// v2.1.7：首次 `notMerge=true` 整图重建一次，之后 `notMerge=false` 走 ECharts
/// diff + 260ms 过渡动画；`lazyUpdate=true` 让 5 次 `setOption` 合并到同一帧渲染。
/// 重绘前先按容器尺寸自适应（`fit_charts`），容器尺寸未变则不 resize。
fn draw_charts(app: App) {
    if !has_chart(0) {
        return;
    }
    fit_charts();
    let snap = app.snapshot.get_untracked().unwrap_or_default();
    let labels: Vec<String> = snap.history.iter().map(|h| h.label.clone()).collect();
    // 后端 `history[].hit_rate` 与 v1.9.162 一致已是 0..100 百分数，这里**不再**乘 100
    // （否则曲线 100 倍超量程、恒顶格）。
    let hit: Vec<f64> = snap.history.iter().map(|h| fmt::n(h.hit_rate)).collect();
    let qps: Vec<f64> = snap.history.iter().map(|h| fmt::n(h.qps)).collect();
    let lat: Vec<f64> = snap.history.iter().map(|h| fmt::n(h.lat)).collect();
    let o0 = echarts::hit_opt(&labels, &hit);
    let o1 = echarts::qps_opt(&labels, &qps);
    let o2 = echarts::lat_opt(&labels, &lat);
    let qd = &snap.qtype_dist;
    let o3 = echarts::qtypes_opt(qd.a, qd.aaaa, qd.other);
    let bars = up_bars(&snap.upstreams);
    // **2.1.18（修复项 8）**：空态文案必须**区分**"没配上游"与"有上游但还没有延迟样本"
    // —— 后者不是空态而是"刚起来还没测到"，说"暂无上游"会让用户以为上游丢了。
    let o4 = echarts::up_opt_msg(&bars, &up_empty_msg(&bars, &snap.upstreams));
    with_chart(0, |c| echarts::set_option(c, &o0, take_first(0)));
    with_chart(1, |c| echarts::set_option(c, &o1, take_first(1)));
    with_chart(2, |c| echarts::set_option(c, &o2, take_first(2)));
    with_chart(3, |c| echarts::set_option(c, &o3, take_first(3)));
    with_chart(4, |c| echarts::set_option(c, &o4, take_first(4)));
}

/// **2.1.18（修复项 8）**：上游延迟图的空态**文案**（空 bars 时才有意义）。
///
/// 为什么要区分（用户实测的误读）：`up_bars` 只画"启用且有可用延迟"的上游，
/// 因此**没有可画的横条**有两种完全不同的成因：
/// - `upstreams` 列表**本身为空**（没配上游 / 快照未到）⇒ "暂无上游"；
/// - 有上游，但**还没有任何延迟样本**（刚启动、全部上游被禁用、或延迟样本尚未产生）
///   ⇒ "暂无延迟样本（等待上游流量）"。
///   两者都显示"暂无上游"会让"刚起来还没测到"被读成"上游配置丢了"。
pub fn up_empty_msg(bars: &[UpBar], all: &[UpstreamStat]) -> String {
    if !bars.is_empty() {
        return String::new();
    }
    if all.is_empty() {
        "暂无数据 · 尚未配置上游".to_string()
    } else {
        "暂无数据 · 还没有延迟样本（等待上游流量）".to_string()
    }
}

/// 上游延迟横条数据（对齐 chartUpOpt 的过滤与配色）。
///
/// v2.1.8 修复（用户反馈“卡片不显示数据”）：原过滤条件要求 `queries > 0`，
/// 于是**进程刚重启 / 还没有上游流量的那段时间**里横条为空，整张卡只剩空坐标轴
/// （CDP 实测：非透明像素 278、`series[0].data.length = 0`）。
/// 现在改为「启用中 + 有可用延迟（真实均值 `avg_latency` 或探针值 `latency`）」即绘制，
/// 地址与延迟不再因为查询计数为 0 而消失；未启用且从未查询的上游仍然跳过。
///
/// **2.1.17（UI 能力核对 · 修复 R2）**：轴标签改用与健康度表**同一个**
/// [`full_addr`] 渲染器（`scheme://host[:port][/path]`）。
///
/// 为什么必须统一（早期交付已修、本轮核对发现 `up_bars` 仍用旧式 `host:port`）：
/// 用户在「上游平均延迟」图上要看到的是**完整上游地址**（如
/// `http3://dns.alidns.com/dns-query`），而旧实现只画 `dns.alidns.com:443` ——
/// 同一页面上「图」与「健康度表」对同一条上游给出**两种写法**，无法互相印证，
/// 且 `https://…/dns-query` 与 `udp://…:53` 这类**同主机不同协议/路径**的上游在图上
/// 会退化成完全相同的标签。现在两处共用 `full_addr`（单一口径，不可能漂移）。
fn up_bars(ups: &[UpstreamStat]) -> Vec<UpBar> {
    let mut bars = Vec::new();
    for u in ups {
        // `!(x > 0.0)` 对 NaN 也为真；用 partial_cmp 显式表达"不是有限正数"，
        // 避免 clippy::neg_cmp_op_on_partial_ord，同时保持 NaN 语义不变。
        if !u.enabled
            && !matches!(
                u.queries.partial_cmp(&0.0),
                Some(std::cmp::Ordering::Greater)
            )
        {
            continue;
        }
        let avg = u.avg_latency.or(u.latency).unwrap_or(0.0);
        if !(avg.is_finite() && avg > 0.0) {
            continue;
        }
        let sr = u.success_rate.unwrap_or(100.0);
        let color = if sr < 60.0 {
            "#ff6b5e"
        } else if sr < 85.0 {
            "#ffb454"
        } else {
            "#2ee6c8"
        };
        // 轴标签 = 完整地址（与「完整地址」列逐字一致）；上游名/地址/协议全空时
        // `full_addr` 会退化成人眼不可读的 `://`，此时回退上游名，再回退 `–` ——
        // 空标签在 ECharts 里会渲染成空白行，看起来像"少了几个上游"。
        let label = {
            let a = full_addr(u);
            if a.trim().is_empty() || a == "://" {
                if u.name.trim().is_empty() {
                    "–".to_string()
                } else {
                    u.name.trim().to_string()
                }
            } else {
                a
            }
        };
        bars.push(UpBar { label, avg, color });
    }
    bars
}

/// **2.1.18（修复项 3）**：上游完整地址 —— **单一来源 = 后端**
/// `/api/upstreams[].full_addr`（与 `/api/snapshot.upstreams[].full_addr` 同源）。
///
/// 消费顺序：
/// 1. `u.full_addr` 非空 ⇒ **直接用**（后端 `api.rs::full_addr_parts` 的产物，
///    规则与下面的本地实现逐条一致；单测 `full_addr_prefers_backend_field` 与
///    `full_addr_matches_backend_rules_when_field_present` 钉死）；
/// 2. 字段缺失（`None`）或为空串（旧后端 / 手工构造的测试数据）⇒ 回退本地
///    [`local_full_addr`]。
///
/// **为什么保留本地实现**（而不是删掉只读后端字段）：`/api/status` 与
/// `/api/snapshot` 的轮询是**两个请求**，旧后端或未来某个端点的 `upstreams[]`
/// 都可能暂时没有该键；没有兜底就会在页面上显示空地址。因此本地实现是
/// **兜底**而不是"第二个来源"——有后端字段时它**不参与**输出。
fn full_addr(u: &UpstreamStat) -> String {
    if let Some(a) = u.full_addr.as_deref() {
        if !a.trim().is_empty() {
            return a.trim().to_string();
        }
    }
    local_full_addr(u)
}

/// `proto` → URL scheme（`udp→udp`、`tcp→tcp`、`doh→https`、`doh3→http3`、
/// `dot→tls`、`doq→quic`，其余原样；大小写不敏感，前后空白忽略）。
///
/// **2.1.18（修复项 3）**：与后端 `api.rs::proto_scheme` **同规则**；
/// 本地这份只在后端字段缺失时使用（见 [`full_addr`]）。
fn proto_scheme(proto: &str) -> &str {
    match proto.trim().to_ascii_lowercase().as_str() {
        "udp" => "udp",
        "tcp" => "tcp",
        "doh" => "https",
        "doh3" => "http3",
        "dot" => "tls",
        "doq" => "quic",
        _ => proto.trim(),
    }
}

/// `url` 字段里只取路径：若是完整 URL（含 `://`）先剥掉 `scheme://host`，
/// 再归一化为「单个前导 `/` + 合并重复斜杠」；没有路径则返回空串。
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

/// 健康度表「完整地址」列的文本：`scheme://host[:port][/path]`。
///
/// **2.1.18（修复项 3）**：本函数改名为 `local_full_addr` 并**降级为兜底** ——
/// 有后端字段（`UpstreamStat::full_addr`）时**不参与**输出，见 [`full_addr`]。
/// 规则与后端 `api.rs::full_addr_parts` **逐条一致**（2.1.17 起这两处就是同一套规则）：
///
/// - host 取 `addr`（空则退回 `name`），IPv6 加方括号；
/// - 端口：`udp/tcp` **恒显**（端口是 UDP/TCP 端点身份的一部分，与 v1.9.162 的
///   `udp://ip:53` 写法一致）；`doh/doh3` 的 443、`dot/doq` 的 853 为默认端口时省略，
///   非默认端口一律附 `:port`；
/// - `url` 里的路径（如 `/dns-query`）**只对 HTTP 系（`doh→https`、`doh3→http3`）**追加，
///   并去掉重复斜杠：`udp/tcp/dot/doq` 是裸 DNS 端点、没有 URL 路径（配置里即便带了
///   `url: "/dns-query"` 也不该拼进来，否则会得到 `udp://223.5.5.5:53/dns-query`）。
fn local_full_addr(u: &UpstreamStat) -> String {
    let scheme = proto_scheme(&u.proto);
    let host_raw = if !u.addr.trim().is_empty() {
        u.addr.trim()
    } else {
        u.name.trim()
    };
    let host = if host_raw.contains(':') && !host_raw.starts_with('[') {
        format!("[{host_raw}]")
    } else {
        host_raw.to_string()
    };
    let show_port = match scheme {
        "udp" | "tcp" => u.port > 0.0,
        "https" | "http3" => u.port > 0.0 && (u.port - 443.0).abs() > f64::EPSILON,
        "tls" | "quic" => u.port > 0.0 && (u.port - 853.0).abs() > f64::EPSILON,
        _ => u.port > 0.0,
    };
    let mut s = format!("{scheme}://{host}");
    if show_port {
        s.push_str(&format!(":{}", u.port as i64));
    }
    if matches!(scheme, "https" | "http3") {
        s.push_str(&addr_path(&u.url));
    }
    s
}

/// 上游健康度表的一行（对齐 refreshTelemetryUI 的 `<tr>` 结构；
/// v2.1.8 追加「熔断 / 连续失败 / 等效延迟 / 角色」自解释列，后端字段缺失一律 `–`）。
#[derive(Clone, Debug, PartialEq)]
struct HealthRow {
    key: String,
    name: String,
    addr: String,
    proto: String,
    /// 熔断列文本（`正常` / `熔断 12s`）+ 状态点样式类（`ok` / `open`）
    breaker: String,
    breaker_dot: &'static str,
    /// 熔断列 title：breaker_open / until_in_s / selectable 原值
    breaker_title: String,
    /// 连续失败数（`fails`，回退后端已有的 `fail`）
    fails: String,
    /// 等效延迟（`eff_lat_ms`，回退 conn_avg_lat / avg_latency / latency，`lat_auto` 单位）
    eff_lat: String,
    /// **2.1.15（决策 2）**：等效延迟的数据来源徽标（`实测` / `静态` / `–`）+ 其 title。
    eff_lat_src: String,
    eff_lat_src_title: &'static str,
    /// **2.1.21 第 2 轮（DEF-221-05）**：DNS **业务**成功率（`dns_success_rate`）+ title。
    /// 与「成功率」（传输层）**并列但不同源**：SERVFAIL 的上游在传输层可能是 100%、
    /// 在这里是 0%。`null`（无业务样本）显示 `–`。
    dsr: String,
    dsr_title: String,

    queries: String,
    sr: String,
    lat: String,
    status: String,
    color: &'static str,
    /// 角色徽标：`首选` / `后备` / `闲置` / `–` + 样式类
    role: String,
    role_class: &'static str,
    /// 状态/角色单元格 title：探针计数 + 角色原值 + selectable
    meta_title: String,
}

/// `Option<f64>` → 展示文本（缺失/非有限 → `–`）；`f` 决定格式化方式。
fn opt_text(v: Option<f64>, f: impl Fn(f64) -> String) -> String {
    match v {
        Some(x) if x.is_finite() => f(x),
        _ => "–".to_string(),
    }
}

/// `Option<bool>` → `true` / `false` / `–`。
fn opt_bool_text(v: Option<bool>) -> String {
    match v {
        Some(b) => b.to_string(),
        None => "–".to_string(),
    }
}

/* ===== **2.1.18（修复项 8）**：三张"低频/易误读"KPI 的副标题口径 ===== */

/// 卡片在**首帧未到**时显示加载态（现有 `···` 保持不变）；拿到 `/api/status` **之后**
/// 一律显示明确数值（`0` 就是 `0`），"无数据"只用于**字段缺失**（旧后端）。
///
/// 这三张卡（SERVFAIL / 负缓存命中 / 客户端 rcode=2）在无流量或刚重启时都是 0，
/// 用户实测把它们读成"无数据/坏了"。因此副标题必须**分三态**：
/// 1. 加载中（`loading == true`，由调用方渲染 `···`，本函数不管）；
/// 2. 字段缺失（旧后端不支持该口径）⇒ 明说"该后端不支持/无此口径"；
/// 3. 字段存在 ⇒ 给出**口语化的"何时会非 0"**解释。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KpiSub {
    /// 后端返回了该口径：给出"何时会非 0"。
    Explain,
    /// `counters.client_rcode` 整块缺失 ⇒ 旧后端不支持服务端自证口径。
    NoSelfProof,
    /// `counters.servfail_reasons` 缺失 ⇒ 旧后端没有分档归因。
    NoReasonBuckets,
}

/// SERVFAIL 卡副标题。
pub fn kpi_sub_servfail(has_reasons: bool) -> KpiSub {
    if has_reasons {
        KpiSub::Explain
    } else {
        KpiSub::NoReasonBuckets
    }
}

/// 客户端 rcode=2 卡副标题（判据 = `counters.client_rcode` 是否存在）。
pub fn kpi_sub_client_rcode(has_client_rcode: bool) -> KpiSub {
    if has_client_rcode {
        KpiSub::Explain
    } else {
        KpiSub::NoSelfProof
    }
}

/// 负缓存命中卡副标题（该口径自 2.1.16 起一直在 `counters.negative_hits` 里，
/// 仅当整个 `counters` 缺失即"首帧未到"时才无值 —— 因此只有两态；
/// 保留函数是为了与上面两张卡**同一套**文案机制，便于将来加"字段缺失"分支）。
pub fn kpi_sub_negcache(has_counters: bool) -> KpiSub {
    if has_counters {
        KpiSub::Explain
    } else {
        KpiSub::NoSelfProof
    }
}

/// 副标题文本（`KpiSub` → 人话）。
///
/// 文案要求（**2.1.18（修复项 8）**）：简短、口语化、说清"什么时候才会非 0"，
/// 让"当前是 0"变成**可判定**的事实而不是"疑似没数据"。
pub fn kpi_sub_text(kind: KpiSub, which: &str) -> &'static str {
    match (kind, which) {
        // 三张卡的"何时非 0"（用户点名要求的口径）。
        (KpiSub::Explain, "servfail") => {
            "服务端实际发出 rcode=2 的应答数（客户端超时/无应答不计入）"
        }
        (KpiSub::Explain, "negcache") => {
            "NXDOMAIN/NODATA 直接由缓存回答、未回源 的次数（重启不清零）"
        }
        (KpiSub::Explain, "clirccode2") => "服务端侧自证；恒等于 SERVFAIL",
        // 字段缺失（旧后端）。
        (KpiSub::NoSelfProof, _) => "该后端不支持自证口径",
        (KpiSub::NoReasonBuckets, _) => "该后端无分档归因",
        // 兜底（不应到达）。
        (KpiSub::Explain, _) => "",
    }
}

/// 三张卡副标题的 `title`（悬停精确口径；**中文在前、英文原文附后**）。
///
/// **2.1.18（修复项 8）**：把 2.1.16 的长英文原文缩句 + 前置中文说明 ——
/// 精确信息（含"MUST NOT be added"）**全部保留**，只是可读性更好。
const TIP_SERVFAIL: &str = "中文口径：服务端真的发给客户端的 SERVFAIL（rcode=2）条数 = counters.servfail_total。\
与「解析失败」（counters.errors，内部错误：上游全失败/组包失败/畸形包）不是同一个口径。\
分档归因见 counters.servfail_reasons（5 档互斥，Σ == 总数）。\
Prometheus：聚合 series 是 ebpdns_servfail_total（无标签），分档是 ebpdns_servfail_reasons_total{reason=…}；\
两族不得相加（相加即双计）。\
EN: SERVFAIL (rcode=2) responses actually sent to clients = counters.servfail_total; \
distinct from the errors counter (internal failures). /metrics splits the aggregate \
(ebpdns_servfail_total, no labels) from the buckets (ebpdns_servfail_reasons_total) — \
do NOT add the two metric families together.";
const TIP_NEGCACHE: &str =
    "中文口径：负缓存（NXDOMAIN / NODATA）由缓存直接回答的次数 = counters.negative_hits，\
与 /metrics 的 ebpdns_negative_cache_hits_total 同源（唯一打点 ServerTelemetry::count_neg_hit）。\
负缓存条目参与落盘/恢复（含剩余 TTL），因此重启前后只增不减；无流量时为 0 属正常。\
EN: negative-cache (NXDOMAIN/NODATA) hits served from cache = counters.negative_hits; \
same source as ebpdns_negative_cache_hits_total; 条目按剩余 TTL 落盘/恢复，\
故计数器重启前后单调不减。";
const TIP_CLI_RCODE2: &str = "中文口径：服务端实际构造并发出的 rcode=2 条数 = counters.client_rcode[\"2\"]（服务端侧自证）。\
硬等式：client_rcode[\"2\"] == servfail_total。客户端脚本报的 SERVFAIL 若大于本值，\
说明客户端把「超时/无应答」误分类成了 SERVFAIL（被丢弃的请求不产生任何 rcode）。\
EN: server-side self-proof = counters.client_rcode[\"2\"]; invariant client_rcode[\"2\"] == servfail_total; \
a client-side SERVFAIL count larger than this means the client mis-classified timeouts as SERVFAIL \
(dropped/unanswered requests produce no rcode at all).";

fn health_rows(ups: &[UpstreamStat]) -> Vec<HealthRow> {
    let mut rows = Vec::new();
    for (i, u) in ups.iter().enumerate() {
        let is_enabled = u.enabled;
        let has_real_data = u.queries > 0.0 && u.success_rate.unwrap_or(0.0) > 0.0;
        // 只显示「启用」或「有真实查询数据且成功率 > 0」的上游。
        if !is_enabled && !has_real_data {
            continue;
        }
        // **2.1.20（A-20/A-16）**：后端 `success_rate` 现在是**可空**的
        // （无传输样本 / 熔断中 ⇒ `null`）。此前这里对 `None` 回退成 100.0
        // （`is_enabled → 100.0`）⇒ **前端又把"无数据"显示成"完美"**，等于把 A-20 在 UI 上撤销。
        // 现在 `None` 一律显示 `–`（中性色），并且**不再**据此推断"健康"。
        let sr_opt: Option<f64> = u.success_rate.filter(|v| v.is_finite());
        let sr = sr_opt.unwrap_or(0.0);
        let status = if !u.status.is_empty() {
            u.status.clone()
        } else if sr_opt.is_none() {
            // 后端没给档位且无样本 ⇒ 未知，不猜。
            "–".to_string()
        } else if sr >= 85.0 {
            "健康".to_string()
        } else if sr >= 60.0 {
            "抖动".to_string()
        } else {
            "异常".to_string()
        };
        let color = match sr_opt {
            // 未知：中性色（后端已明确"没有样本"）。
            None => "var(--text3)",
            Some(v) if v >= 85.0 => "var(--green)",
            Some(v) if v >= 60.0 => "var(--amber)",
            Some(_) => "var(--red)",
        };
        // 无查询/无延迟数据时显示中性占位，避免 0ms 误导。
        let lat = match u.avg_latency {
            Some(v) if v.is_finite() && u.queries > 0.0 => format!("{:.2} ms", v),
            _ => "–".to_string(),
        };

        /* ---- v2.1.8 自解释列（后端新字段；缺失 → `–`，不 panic） ---- */
        // 熔断：打开 → 红点 + 剩余秒数（无 until_in_s 时只写“熔断”）；关闭 → 绿点“正常”。
        let (breaker, breaker_dot) = match (u.breaker_open, u.until_in_s) {
            (Some(true), Some(s)) if s.is_finite() && s > 0.0 => {
                (format!("熔断 {} s", fmt::num0(s)), "open")
            }
            (Some(true), _) => ("熔断".to_string(), "open"),
            (Some(false), _) => ("正常".to_string(), "ok"),
            // 后端未提供该字段（联调期）：中性占位
            (None, _) => ("–".to_string(), "unknown"),
        };
        let breaker_title = format!(
            "breaker_open={} · until_in_s={} · selectable={}\n\
             两本账：熔断账 breaker_fails={} · 传输账 transport_ok/transport_fail={}/{}\n\
             口径说明：`success_rate` 是传输层成功率（DNS 层 SERVFAIL 也算传输成功），\
             因此它 ≠ DNS 业务成功率；无样本或熔断中时后端给 `null`（页面显示 –）。",
            opt_bool_text(u.breaker_open),
            opt_text(u.until_in_s, |v| format!("{v:.1}")),
            opt_bool_text(u.selectable),
            opt_text(u.breaker_fails.or(u.fails), fmt::group0),
            opt_text(u.transport_ok.or(u.ok), fmt::group0),
            opt_text(u.transport_fail.or(u.fail), fmt::group0),
        );
        // 连续失败：优先 `fails`（新字段），回退后端已有的 `fail`。
        let fails = opt_text(u.fails.or(u.fail), fmt::group0);
        // 等效延迟：优先 `eff_lat_ms`（新字段），回退连接均值/上游均值/探针值。
        let eff_lat = {
            let eff = u
                .eff_lat_ms
                .or(u.conn_avg_lat)
                .or(u.avg_latency)
                .or(u.latency)
                .filter(|v| v.is_finite() && *v > 0.0);
            match eff {
                Some(v) => {
                    let (t, unit) = fmt::lat_auto(v);
                    if unit.is_empty() {
                        t
                    } else {
                        format!("{t} {unit}")
                    }
                }
                None => "–".to_string(),
            }
        };
        // 角色徽标：primary/backup/idle → 首选/后备/闲置。
        let (role, role_class) = match u.role.as_deref().map(|s| s.trim().to_ascii_lowercase()) {
            Some(r) if r == "primary" => ("首选".to_string(), "r-primary"),
            Some(r) if r == "backup" => ("后备".to_string(), "r-backup"),
            Some(r) if r == "idle" => ("闲置".to_string(), "r-idle"),
            Some(r) if !r.is_empty() => (r, "r-none"),
            _ => ("–".to_string(), "r-none"),
        };
        // **2.1.15（决策 2）**：「等效延迟」的数据来源徽标 —— 消费后端早已返回、
        // 此前页面未读的 `eff_lat_measured`（缺失时回退 `latency_measured`）。
        // 口径：`true` = 该延迟来自**实测样本**（成功应答均值，含高失败率惩罚）；
        // `false` = 回退配置里的**静态** `latency`；两者都缺（联调期）→ `–`。
        let (eff_lat_src, eff_lat_src_title) = match u.eff_lat_measured.or(u.latency_measured) {
            Some(true) => (
                "实测".to_string(),
                "eff_lat_measured=true：来自进程内实测样本（成功应答平均延迟，高失败率时含惩罚）",
            ),
            Some(false) => (
                "静态".to_string(),
                "eff_lat_measured=false：尚无实测样本，回退到配置里的静态 latency（不是实测值）",
            ),
            None => (
                "–".to_string(),
                "后端未提供 eff_lat_measured / latency_measured（联调期字段缺失）",
            ),
        };
        let meta_title = format!(
            "探针成功 {} · 探针失败 {} · role={} · selectable={} · 权重={} · 熔断打开次数={}",
            opt_text(u.probe_ok.or(u.ok), fmt::group0),
            opt_text(u.probe_fail, fmt::group0),
            u.role.clone().unwrap_or_else(|| "–".into()),
            opt_bool_text(u.selectable),
            opt_text(u.weight, |v| format!("{v:.2}")),
            opt_text(u.circuit_open_count, fmt::group0),
        );

        rows.push(HealthRow {
            key: format!("{i}:{}:{}", u.name, u.addr),
            name: u.name.clone(),
            // 「完整地址」列：scheme://host[:port][/path]（见 `full_addr`）
            addr: full_addr(u),
            proto: u.proto.clone(),
            breaker,
            breaker_dot,
            breaker_title,
            fails,
            eff_lat,
            // **2.1.15（决策 2）**：`eff_lat_measured` / `latency_measured` 是后端
            // 早已返回、此前页面未消费的健康字段 —— 用「实测 / 静态」小徽标落到
            // 「等效延迟」单元格里（不新增列、不与 title 重复）。
            eff_lat_src,
            eff_lat_src_title,
            queries: fmt::group0(u.queries),
            // **2.1.20（A-20）**：`null`（无样本/熔断中）显示 `–`，**不得**回退成 100.0。
            sr: match sr_opt {
                Some(v) => format!("{v:.1}%"),
                None => "–".to_string(),
            },
            // **2.1.21 第 2 轮（DEF-221-05）**：DNS 业务成功率（A-17 的第三本账）。
            // 与传输层 `sr` **并列展示**，让运维一眼看出"传输 100% 但业务 0%"的上游。
            dsr: opt_text(u.dns_success_rate, |v| format!("{v:.1}%")),
            dsr_title: format!(
                "DNS 业务成功率 = dns_ok/(dns_ok+dns_fail)：\n\
                 dns_ok={} · dns_fail={}（每个物理上游应答记一次，single-flight 不放大）\n\
                 成功 = `rcode ∈ {{NOERROR, NXDOMAIN}}` 且未被截断（NXDOMAIN/NODATA 也算成功）；\n\
                 SERVFAIL/REFUSED/NOTIMP/FORMERR/截断 = 失败。无业务样本 ⇒ `–`。\n\
                 与左列「成功率」不同源：那一列是传输层（SERVFAIL 也算传输成功）。",
                opt_text(u.dns_ok, fmt::group0),
                opt_text(u.dns_fail, fmt::group0),
            ),

            lat,
            status,
            color,
            role,
            role_class,
            meta_title,
        });
    }
    rows
}

/// Top N 统计的三类数据源。
#[derive(Clone, Copy, PartialEq, Eq)]
enum TopKind {
    Domains,
    Clients,
    Upstreams,
}

/// Top N 列表：每项 `名 <span style="color:var(--text3)">次数[单位]</span>`，`<br>` 分隔，
/// 最多 8 项（对齐 refreshTelemetryUI 的 fmtTop / fmtTopUp）。
#[component]
fn TopList(kind: TopKind, unit: &'static str) -> impl IntoView {
    let app = expect_context::<App>();

    let items = move || -> Option<Vec<(String, f64)>> {
        // 对齐 `const stTop = (MODE === 'real' && real.status) ? real.status : null;`
        if app.mode.get() != Mode::Real {
            return None;
        }
        app.status.get().map(|s| match kind {
            TopKind::Domains => s.top_domains,
            TopKind::Clients => s.top_clients,
            TopKind::Upstreams => {
                // top_upstreams 首元素是上游 id，用 snapshot.upstreams 映射成可读名称。
                let names: Vec<(String, String)> = app
                    .snapshot
                    .get()
                    .unwrap_or_default()
                    .upstreams
                    .iter()
                    .map(|u| (u.id.clone(), u.name.clone()))
                    .collect();
                s.top_upstreams
                    .into_iter()
                    .map(|(id, n)| {
                        let name = names
                            .iter()
                            .find(|(i, _)| *i == id)
                            .map(|(_, nm)| nm.clone())
                            .filter(|nm| !nm.is_empty())
                            .unwrap_or_else(|| id.clone());
                        (name, n)
                    })
                    .collect()
            }
        })
    };

    // **2.1.14 修复（审计 ③）**：`top_*` 列表此前用 `<br>` 分隔拼接，实测渲染成
    // `ikuai8.com 770www.baidu.com 15`（相邻条目的名字与次数**直接粘连**，无换行也无空格）——
    // `<br>` 在 flex 容器里不产生换行。现在每条独立成一个 `display:block` 的 `div`
    // （行内样式，不依赖外部 CSS），条目之间恒有视觉分隔。
    view! {
        {move || match items() {
            None => view! { "–" }.into_any(),
            Some(list) if list.is_empty() => view! { "暂无数据 · 等待 DNS 查询流量" }.into_any(),
            Some(list) => {
                let shown: Vec<(String, f64)> = list.into_iter().take(8).collect();
                shown
                    .into_iter()
                    .map(|(name, count)| {
                        view! {
                            <div style="display:block;white-space:nowrap;line-height:1.5">
                                {name} " "
                                <span style="color:var(--text3)">
                                    {format!("{}{}", fmt::num0(count), unit)}
                                </span>
                            </div>
                        }
                    })
                    .collect_view()
                    .into_any()
            }
        }}
    }
}

/// 遥测页（`data-route="telemetry"`）。
#[component]
pub fn TelemetryPage() -> impl IntoView {
    let app = expect_context::<App>();

    // 进入本页时安装 resize 监听并初始化 5 个图表（Effect 只跑一次）。
    Effect::new(move |prev: Option<()>| {
        if prev.is_none() && app.route.get() == Route::Telemetry {
            install_resize_listener();
            spawn_init_charts(app);
        }
    });

    // 快照变化 → 重绘图表（v2.1.7：**只**跟踪 snapshot；图表数据全部来自快照，
    // 不再跟着 2s 的 status 一起重绘，遥测页图表重绘次数因此减半）。
    Effect::new(move |_| {
        let _ = app.snapshot.get();
        draw_charts(app);
    });

    // 卸载：移除 resize 监听 + dispose 图表实例（对齐 initCharts 的防御性 dispose）。
    on_cleanup(|| {
        remove_resize_listener();
        dispose_charts();
    });

    // 规则命中分项与求和（对齐 refreshKpiNums 的 rhSum / 5 个 span）。
    let rh = move || app.status.get().map(|s| s.rule_hits).unwrap_or_default();
    let rh_sum = move || {
        let r = rh();
        fmt::num0(r.block + r.domestic + r.global + r.force_ip + r.allow)
    };

    // **2.1.18（修复项 18：标签-来源一致）**：本卡是**用户态缓存**占用，
    // 因此读 `/api/cache/stats` 的 `used`/`capacity`（= 配置 `cache_size`），
    // **不再**读 `status.map.*` —— 后者是 v1.9.162 的兼容别名（内容就是 cache 摘要），
    // 但旧标题把用户态数字标成内核态占用，属**标签与来源不符**（部署代理 G2 FAIL）。
    let cache_used = move || -> f64 {
        app.status
            .get()
            .map(|s| fmt::n(s.cache.used))
            .unwrap_or(0.0)
    };
    let cache_cap = move || -> f64 {
        app.status
            .get()
            .map(|s| fmt::n(s.cache.capacity))
            .unwrap_or(0.0)
    };
    // 占用百分比（非有限值/容量非正回退 0，上限 100）。
    let map_pct = move || -> f64 {
        match app.status.get() {
            Some(s) => {
                let used = fmt::n(s.cache.used);
                let cap = fmt::n(s.cache.capacity);
                if cap > 0.0 {
                    (used / cap * 100.0).min(100.0)
                } else {
                    0.0
                }
            }
            None => 0.0,
        }
    };

    // 加载态 vs 无数据：尚无首帧 status 时为「加载中」（骨架/脉冲），拿到后才是真实值。
    let loading = move || app.status.get().is_none();

    /// **2.1.49（AUD-09）**：进程指标单元格的**三态**渲染：
    /// - `/api/status` 尚未到（`status=None`）或字段缺失（旧后端）⇒ **“不可用”**；
    /// - 字段存在 ⇒ 明确数值（0 也是有效值）。
    ///
    /// 这里刻意不返回 0 冒充缺失：审计要求“失败时显示不可用而不得整页归零”。
    fn proc_u64(app: &App, pick: fn(&crate::model::ProcessInfo) -> Option<u64>) -> String {
        match app.status.get().as_ref().and_then(|s| pick(&s.process)) {
            Some(v) => fmt::group0(v as f64),
            None => "不可用".to_string(),
        }
    }
    fn proc_bytes(app: &App, pick: fn(&crate::model::ProcessInfo) -> Option<u64>) -> String {
        match app.status.get().as_ref().and_then(|s| pick(&s.process)) {
            Some(v) => fmt::bytes_text(v),
            None => "不可用".to_string(),
        }
    }

    view! {
        <section class="route active" data-route="telemetry">
            <div class="kpi-grid">
                <div class="kpi" class:pending=move || loading() title="进程内累计总查询数">
                    <div class="k">"总查询"</div>
                    {ui::live_span_unit("kpi-total", "v", "", move || {
                        if loading() { "···".into() } else { fmt::group0(app.status_or_default().counters.total) }
                    })}
                </div>
                <div class="kpi" class:pending=move || loading() title="用户态缓存直答次数（= counters.hit）">
                    <div class="k">"缓存命中"</div>
                    {ui::live_span_unit("kpi-hit", "v cy", "", move || {
                        if loading() { "···".into() } else { fmt::group0(app.status_or_default().counters.hit) }
                    })}
                </div>
                <div class="kpi" class:pending=move || loading() title="平均响应延迟（单位 ms；≥1000 ms 显示为 s）">
                    <div class="k">"平均延迟"</div>
                    {ui::live_span("kpi-lat", "v am", move || {
                        if loading() {
                            return "···".to_string();
                        }
                        match app.status_or_default().avg_latency_ms {
                            Some(v) => {
                                let (t, u) = fmt::lat_auto(v);
                                if u.is_empty() { t } else { format!("{t} {u}") }
                            }
                            None => "–".to_string(),
                        }
                    })}
                </div>
                <div class="kpi" class:pending=move || loading() title="逻辑口径：有几次客户端查询真正发过上游（counters.upstream_queries；物理请求见 counters.upstream_requests，线速见 /metrics 的 ebpdns_upstream_wire_requests_total）">
                    <div class="k">"上游请求"</div>
                    {ui::live_span_unit("kpi-up", "v", "", move || {
                        if loading() { "···".into() } else { fmt::group0(app.status_or_default().counters.upstream_queries) }
                    })}
                </div>
                <div class="kpi" class:pending=move || loading() title="内部错误：上游全失败 / 组包失败 / 畸形包（counters.errors，≠客户端看到的 SERVFAIL 数）">
                    <div class="k">"解析失败"</div>
                    {ui::live_span_unit("kpi-err", "v rd", "", move || {
                        if loading() { "···".into() } else { fmt::group0(app.status_or_default().counters.errors) }
                    })}
                </div>
                <div class="kpi" class:pending=move || loading() title=TIP_SERVFAIL>
                    <div class="k">"SERVFAIL"</div>
                    {ui::live_span_unit("kpi-servfail", "v rd", "", move || {
                        // **2.1.18（修复项 8）**：拿到首帧后**必须**渲染明确数值 ——
                        // `0` 就是 `0`（无流量/刚重启时本就该是 0），不得留空、
                        // 不得显示"暂无数据"；只有首帧未到才是加载态 `···`。
                        if loading() { "···".into() } else { fmt::group0(app.status_or_default().counters.servfail_total) }
                    })}
                    <div class="ss" title="5 档互斥归因（counters.servfail_reasons），Σ == 总数；缺失即该后端无分档归因">
                        <span>{move || {
                            if loading() {
                                return "···".to_string();
                            }
                            let kind = kpi_sub_servfail(app.status_or_default().counters.has_servfail_reasons());
                            kpi_sub_text(kind, "servfail").to_string()
                        }}</span>
                    </div>
                </div>
                <div class="kpi" class:pending=move || loading() title=TIP_NEGCACHE>
                    <div class="k">"负缓存命中"</div>
                    {ui::live_span_unit("kpi-neghit", "v cy", "", move || {
                        if loading() { "···".into() } else { fmt::group0(app.status_or_default().counters.negative_hits) }
                    })}
                    <div class="ss" title="负缓存条目参与落盘/恢复（含剩余 TTL）⇒ 重启前后单调不减；无流量时为 0 属正常">
                        <span>{move || {
                            if loading() {
                                return "···".to_string();
                            }
                            let kind = kpi_sub_negcache(app.status.get().is_some());
                            kpi_sub_text(kind, "negcache").to_string()
                        }}</span>
                    </div>
                </div>
                <div class="kpi" class:pending=move || loading() title=TIP_CLI_RCODE2>
                    <div class="k">"客户端 rcode=2"</div>
                    {ui::live_span_unit("kpi-cli-rcode2", "v rd", "", move || {
                        if loading() { "···".into() } else { fmt::group0(app.status_or_default().counters.client_rcode2()) }
                    })}
                    <div class="ss" title="服务端侧自证：与 SERVFAIL 同点打点，二者必须相等（client_rcode[\"2\"] == servfail_total）">
                        <span>{move || {
                            if loading() {
                                return "···".to_string();
                            }
                            let kind = kpi_sub_client_rcode(app.status_or_default().counters.has_client_rcode());
                            kpi_sub_text(kind, "clirccode2").to_string()
                        }}</span>
                    </div>
                </div>
                <div class="kpi kpi-rule" class:pending=move || loading()>
                    <div class="k">"规则命中"</div>
                    {ui::live_span_unit("kpi-rule", "v bl", "", move || {
                        if loading() { "···".into() } else { rh_sum() }
                    })}
                    <div class="rs" id="kpi-rule-sub">
                        <span class="rd">"屏蔽" {move || fmt::group0(rh().block)}</span>
                        <span class="cy">"国内" {move || fmt::group0(rh().domestic)}</span>
                        <span class="am">"海外" {move || fmt::group0(rh().global)}</span>
                        <span class="gy">"强制 IP" {move || fmt::group0(rh().force_ip)}</span>
                        <span class="gy">"放行" {move || fmt::group0(rh().allow)}</span>
                    </div>
                </div>
            </div>
            // **2.1.49（AUD-09）**：最小进程卡片（RSS / threads / open_fds）。
            // 数据源 = `/api/status.process`；失败/旧后端（字段缺失）逐项显示“不可用”，
            // 绝不把整页指标归零。`data-src` 与 `id` 供 CDP 断言使用。
            <div class="card" id="proc-card" style="margin-top:12px">
                <div class="card-hd">
                    <span class="t">"进程资源"</span>
                    <span class="s">"RSS · threads · open_fds（/api/status.process）"</span>
                </div>
                <div class="card-bd">
                    <div class="rs" style="display:flex;gap:22px;flex-wrap:wrap;font-family:var(--font-mono);font-size:13px;color:var(--text3)">
                        <span>"RSS " <b id="proc-rss" data-src="process.resident_memory_bytes" style="color:var(--text)">
                            {move || proc_bytes(&app, |p| p.resident_memory_bytes)}
                        </b></span>
                        <span>"VM " <b id="proc-vm" data-src="process.virtual_memory_bytes" style="color:var(--text)">
                            {move || proc_bytes(&app, |p| p.virtual_memory_bytes)}
                        </b></span>
                        <span>"threads " <b id="proc-threads" data-src="process.threads" style="color:var(--text)">
                            {move || proc_u64(&app, |p| p.threads)}
                        </b></span>
                        <span>"open_fds " <b id="proc-fds" data-src="process.open_fds" style="color:var(--text)">
                            {move || proc_u64(&app, |p| p.open_fds)}
                        </b></span>
                        <span>"缺失 part " <b id="proc-missing" data-src="process.state_missing_parts" style="color:var(--text)">
                            {move || proc_u64(&app, |p| p.state_missing_parts)}
                        </b></span>
                    </div>
                    <div class="hint">"口径：与 /metrics 的 ebpdns_process_* 同源（Linux /proc/self；非 Linux 为 0）。字段缺失=该后端不支持 ⇒ 显示“不可用”，不是 0。"</div>
                </div>
            </div>
            <div class="chart-grid">
                <div class="card">
                    <div class="card-hd">
                        <span class="t">"命中率"</span>
                        <span class="s">"cache hit rate"</span>
                    </div>
                    <div class="card-bd"><div class="chart" id="ch-hit"></div></div>
                </div>
                <div class="card">
                    <div class="card-hd">
                        <span class="t">"吞吐"</span>
                        <span class="s">"QPS"</span>
                    </div>
                    <div class="card-bd"><div class="chart" id="ch-qps"></div></div>
                </div>
                <div class="card">
                    <div class="card-hd">
        <span class="t">"平均延迟"</span>
        <span class="s">"ms / s"</span>
                    </div>
                    <div class="card-bd"><div class="chart" id="ch-lat"></div></div>
                </div>
                <div class="card">
                    <div class="card-hd">
                        <span class="t">"查询类型分布"</span>
                        <span class="s">"qtype"</span>
                    </div>
                    <div class="card-bd"><div class="chart" id="ch-qtypes"></div></div>
                </div>
                <div class="card">
                    <div class="card-hd">
                        <span class="t">"用户态缓存占用"</span>
                        <span class="s">"cache used / capacity"</span>
                    </div>
                    <div class="card-bd">
                        <div
                            class="mapbar"
                            role="progressbar"
                            aria-label="用户态缓存条目占用率（占配置 cache_size 的百分比）"
                            title="用户态缓存条目占用率 = /api/cache/stats.used ÷ capacity × 100%（capacity = 配置 cache_size）。这是用户态缓存。"
                            data-src="cache.used/cache.capacity"
                        >
                            <span id="map-fill" style:width=move || format!("{}%", map_pct())></span>
                        </div>
                        <div class="map-info">
                            <span id="map-used" data-src="cache.used/cache.capacity" title="用户态缓存：当前有效条目数 / 配置容量（cache_size）。已过期条目会在下次 purge 时移除，因此该数可能略高于「剩余 TTL 仍有效」的条目数。">
                                {move || match app.status.get() {
                                    Some(_) => {
                                        format!(
                                            "{} / {}",
                                            fmt::group0(cache_used()),
                                            fmt::group0(cache_cap()),
                                        )
                                    }
                                    None => "– / –".to_string(),
                                }}
                            </span>
                            <span id="map-pct" data-src="cache.pct" title="百分比（0–100，一位小数）：used ÷ capacity × 100%（后端 `cache.pct` 同口径，缺失时前端按同一公式兜底）">
                                {move || match app.status.get() {
                                    // 后端 `cache.pct` 与前端公式同口径；后端缺该字段时兜底计算。
                                    Some(s) if s.cache.pct > 0.0 => format!("{:.1}%", s.cache.pct),
                                    Some(_) => format!("{:.1}%", map_pct()),
                                    None => "–".to_string(),
                                }}
                            </span>
                        </div>
                        <div class="map-info">
                            <span id="cache-segments" data-src="cache.window/cache.probation/cache.protected" title="TinyLFU 三段条目数（不是容量）：window / probation / protected，三者之和 = used。**2.1.43-B**：只有 cache_policy=tinylfu 时后端才采集这三项；其它策略显示「未采集」（不是 0）；tinylfu 下的 0 是**真 0**（空缓存）。">
                                {move || match app.status.get() {
                                    // 没有 `/api/status` ⇒ 真的没有数据（`–`，不是 0）。
                                    None => "–".to_string(),
                                    Some(s) => match s.cache_policy.as_deref() {
                                        // tinylfu：三段是**已采集**口径 ⇒ 全 0 也是真值（空缓存）。
                                        Some("tinylfu") => format!(
                                            "分段（条目数）：window {} · probation {} · protected {}",
                                            fmt::group0(s.cache.window),
                                            fmt::group0(s.cache.probation),
                                            fmt::group0(s.cache.protected),
                                        ),
                                        // lru / partitioned：后端不产出该口径 ⇒ **未采集**，
                                        // 绝不能渲染成 "0"（会与"空分段"混淆）。
                                        Some(p) => {
                                            format!("未采集（cache_policy={p} 无三段口径）")
                                        }
                                        // 字段缺失（旧后端 / 字段类型不符）⇒ 未采集 + 原因。
                                        None => "未采集（后端未下发 cache_policy）".to_string(),
                                    },
                                }}
                            </span>
                        </div>
                        <div class="hint">"数值 = 用户态缓存条目（/api/cache/stats.used）÷ 容量（配置 cache_size）。满时按当前 cache_policy（lru/partitioned/tinylfu）淘汰；命中率与容量、TTL 直接相关。"</div>
                    </div>
                </div>
            </div>
            <div class="card">
                <div class="card-hd">
                    <span class="t">"上游平均延迟"</span>
                    <span class="s">"per upstream"</span>
                </div>
                <div class="card-bd"><div class="chart" id="ch-up"></div></div>
            </div>
            <div class="card">
                <div class="card-hd">
                    <span class="t">"上游健康度"</span>
                    <span class="s">"upstream health"</span>
                </div>
                <div class="card-bd flush">
                    <div style="overflow-x:auto">
                        <table class="tbl" id="up-health" aria-label="上游健康度">
                            // v2.1.7：表头与数据行共用同一套列定义 —— `<colgroup>` 固定各列宽度
                            // （`table-layout:fixed`），表头单元格带与数据单元格**相同**的类
                            // （`ip/addr/mono/num`），数字列的表头也随之右对齐。
                            // v2.1.8 列序（10 列）：上游 | 完整地址 | 协议 | 熔断 | 连续失败 |
                            // 等效延迟 | 查询数 | 成功率 | 平均延迟 | 状态·角色。
                            // 后四列消费后端新字段（breaker_open/until_in_s/fails/eff_lat_ms/
                            // role/selectable/probe_ok/probe_fail），字段缺失时单元格显示 `–`。
                            <colgroup>
                                <col class="c-name" />
                                <col class="c-addr" />
                                <col class="c-proto" />
                                <col class="c-brk" />
                                <col class="c-fail" />
                                <col class="c-eff" />
                                <col class="c-q" />
                                <col class="c-sr" />
                                <col class="c-dsr" />

                                <col class="c-lat" />
                                <col class="c-meta" />
                            </colgroup>
                            <thead>
                                <tr>
                                    <th class="ip">"上游"</th>
                                    <th class="addr">"完整地址"</th>
                                    <th class="mono">"协议"</th>
                                    <th class="mono">"熔断"</th>
                                    <th class="num">"连续失败"</th>
                                    <th class="num" title="生效延迟 = eff_lat_ms（排序键）；徽标为数据来源：实测 = 来自进程内实测样本，静态 = 回退配置 latency">"等效延迟"</th>
                                    <th class="num">"查询数"</th>
                                    <th class="num" title="传输层成功率 = 成功往返/(成功+失败)；DNS 层 SERVFAIL 也算传输成功。无样本或熔断 ⇒ –">"成功率"</th>
                                    <th class="num" title="DNS 业务成功率：rcode ∈ {NOERROR, NXDOMAIN} 且未截断 = 成功（NXDOMAIN/NODATA 也算）；SERVFAIL/REFUSED/NOTIMP/FORMERR/截断 = 失败。每个物理上游应答记一次（single-flight 不放大）。无业务样本 ⇒ –">"业务成功率"</th>

                                    <th class="num">"平均延迟"</th>
                                    <th class="mono">"状态 / 角色"</th>
                                </tr>
                            </thead>
                            <tbody>
                                <For
                                    each=move || {
                                        health_rows(&app.snapshot.get().unwrap_or_default().upstreams)
                                    }
                                    key=|r| r.key.clone()
                                    children=move |r| {
                                        let style = format!("color:{}", r.color);
                                        let dot = format!("brk-dot {}", r.breaker_dot);
                                        let role_cls = format!("role-badge {}", r.role_class);
                                        // 超长值截断 + 原生 title 提示（静态值：key 含 name/addr，
                                        // 名称变化即换行重建，不会残留过期 title）。
                                        let name = fmt::trunc(&r.name, 26);
                                        view! {
                                            <tr class="row-in">
                                                <td class="ip trunc" title=r.name.clone()>{name}</td>
                                                <td class="addr" title=r.addr.clone()>
                                                    {r.addr.clone()}
                                                </td>
                                                <td class="mono">{r.proto.clone()}</td>
                                                <td class="brk mono" title=r.breaker_title.clone()>
                                                    <i class=dot></i>
                                                    {r.breaker.clone()}
                                                </td>
                                                <td class="num">{r.fails.clone()}</td>
                                                <td class="num" title=r.eff_lat_src_title>
                                                    {r.eff_lat.clone()}
                                                    <span class="eff-src">{r.eff_lat_src.clone()}</span>
                                                </td>
                                                <td class="num">{r.queries.clone()}</td>
                                                <td class="num">{r.sr.clone()}</td>
                                                <td class="num" title=r.dsr_title.clone()>{r.dsr.clone()}</td>

                                                <td class="num">{r.lat.clone()}</td>
                                                <td class="meta" title=r.meta_title.clone()>
                                                    <span class="meta-in">
                                                        <span class="mono up-badge" style=style>
                                                            "● " {r.status.clone()}
                                                        </span>
                                                        <span class=role_cls>{r.role.clone()}</span>
                                                    </span>
                                                </td>
                                            </tr>
                                        }
                                    }
                                />
                                {move || {
                                    if app.snapshot.get().is_none() {
                                        view! {
                                            <tr class="empty-row">
                                                <td colspan="10" class="empty">"加载中…"</td>
                                            </tr>
                                        }
                                            .into_any()
                                    } else if health_rows(
                                        &app.snapshot.get().unwrap_or_default().upstreams,
                                    )
                                    .is_empty()
                                    {
                                        view! {
                                            <tr class="empty-row">
                                                <td colspan="10" class="empty">
                                                    "暂无数据 · 没有已启用且产生查询的上游"
                                                </td>
                                            </tr>
                                        }
                                            .into_any()
                                    } else {
                                        ().into_any()
                                    }
                                }}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            <div class="card">
                <div class="card-hd">
                    <span class="t">"Top N 统计"</span>
                    <span class="s">"域名 / 客户端 / 上游"</span>
                </div>
                <div class="card-bd">
                    <div style="display:flex;gap:24px;flex-wrap:wrap">
                        <div style="flex:1 1 260px;min-width:0">
                            <div style="font-weight:600;margin-bottom:6px;color:var(--text2)">
                                "查询最多的域名"
                            </div>
                            <div id="top-domains" style="font-size:12px;color:var(--text2)">
                                <TopList kind=TopKind::Domains unit="" />
                            </div>
                        </div>
                        <div style="flex:1 1 260px;min-width:0">
                            <div style="font-weight:600;margin-bottom:6px;color:var(--text2)">
                                "查询最多的客户端"
                            </div>
                            <div id="top-clients" style="font-size:12px;color:var(--text2)">
                                <TopList kind=TopKind::Clients unit="" />
                            </div>
                        </div>
                        <div style="flex:1 1 260px;min-width:0">
                            <div style="font-weight:600;margin-bottom:6px;color:var(--text2)">
                                "请求最多的上游"
                            </div>
                            <div id="top-ups" style="font-size:12px;color:var(--text2)">
                                <TopList kind=TopKind::Upstreams unit=" 次" />
                            </div>
                        </div>
                    </div>
                    <div class="hint" style="margin-top:8px">
                        "Top N 为进程内累计统计(域名/客户端超 2048 项自动裁剪低频一半), 上游按查询数排序。"
                    </div>
                </div>
            </div>
        </section>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn up(proto: &str, addr: &str, port: f64, url: &str) -> UpstreamStat {
        UpstreamStat {
            proto: proto.into(),
            addr: addr.into(),
            port,
            url: url.into(),
            ..UpstreamStat::default()
        }
    }

    /// **2.1.17（UI 能力核对 · R3）**：`完整地址` 列的渲染器逐分支钉死。
    ///
    /// 判据与用户点名的能力一字对应：
    /// - 协议 scheme 映射 `udp→udp` / `tcp→tcp` / `doh→https` / `doh3→http3` /
    ///   `dot→tls` / `doq→quic`；
    /// - `udp/tcp` **恒带端口**（端口是端点身份）；`doh/doh3` 的 443、`dot/doq` 的
    ///   853 为默认值时**省略**端口，非默认一律带；
    /// - `https/http3` **追加路径**（`/dns-query`），且完整 URL 形式的 `url` 先剥
    ///   `scheme://host` 再取路径；`udp/tcp/dot/doq` 是裸 DNS 端点，**不**拼路径。
    #[test]
    fn full_addr_covers_all_six_protocols_and_default_ports() {
        // udp/tcp：恒带端口（含默认 53）。
        assert_eq!(
            full_addr(&up("udp", "223.5.5.5", 53.0, "")),
            "udp://223.5.5.5:53"
        );
        assert_eq!(
            full_addr(&up("tcp", "223.5.5.5", 53.0, "")),
            "tcp://223.5.5.5:53"
        );
        assert_eq!(
            full_addr(&up("udp", "1.1.1.1", 5353.0, "")),
            "udp://1.1.1.1:5353"
        );
        // doh/doh3：默认 443 省略端口 + 追加路径。
        assert_eq!(
            full_addr(&up("doh", "dns.alidns.com", 443.0, "/dns-query")),
            "https://dns.alidns.com/dns-query"
        );
        assert_eq!(
            full_addr(&up("doh3", "dns.alidns.com", 443.0, "/dns-query")),
            "http3://dns.alidns.com/dns-query"
        );
        // 非默认端口必须带。
        assert_eq!(
            full_addr(&up("doh", "dns.alidns.com", 8443.0, "/dns-query")),
            "https://dns.alidns.com:8443/dns-query"
        );
        // dot/doq：默认 853 省略端口；裸 DNS 端点不拼路径。
        assert_eq!(
            full_addr(&up("dot", "dns.google", 853.0, "")),
            "tls://dns.google"
        );
        assert_eq!(
            full_addr(&up("doq", "dns.alidns.com", 853.0, "")),
            "quic://dns.alidns.com"
        );
        assert_eq!(
            full_addr(&up("doq", "dns.alidns.com", 8853.0, "")),
            "quic://dns.alidns.com:8853"
        );
        // IPv6 方括号 + `url` 里是完整 URL 时先剥 scheme://host 再取路径。
        assert_eq!(
            full_addr(&up(
                "doh",
                "2001:db8::1",
                443.0,
                "https://2001:db8::1/dns-query"
            )),
            "https://[2001:db8::1]/dns-query"
        );
        // addr 为空 → 退回 name（与健康度表同一判据）。
        let mut u = up("udp", "", 53.0, "");
        u.name = "lan-dns".into();
        assert_eq!(full_addr(&u), "udp://lan-dns:53");
    }

    /// **2.1.17（UI 能力核对 · R2）**：「上游平均延迟」图的轴标签必须与
    /// 「完整地址」列**逐字一致**（同一条上游在页面上只有一种写法）。
    ///
    /// 这是用户点名的 R2 回归：旧实现 `up_bars` 只拼 `host:port`，于是图上是
    /// `dns.alidns.com:443`、表里是 `http3://dns.alidns.com/dns-query`。
    #[test]
    fn up_bars_axis_labels_are_full_addresses() {
        let ups = vec![
            UpstreamStat {
                enabled: true,
                latency: Some(12.0),
                ..up("doh3", "dns.alidns.com", 443.0, "/dns-query")
            },
            UpstreamStat {
                enabled: true,
                latency: Some(3.0),
                ..up("udp", "223.5.5.5", 53.0, "")
            },
        ];
        let bars = up_bars(&ups);
        assert_eq!(bars.len(), 2, "两条启用且有延迟的上游都必须进图");
        assert_eq!(
            bars[0].label, "http3://dns.alidns.com/dns-query",
            "轴标签必须是完整地址（与「完整地址」列同口径）"
        );
        assert_eq!(bars[1].label, "udp://223.5.5.5:53");
        // 与「完整地址」列同源校验：逐条相等（不可能漂移）。
        assert_eq!(bars[0].label, full_addr(&ups[0]));
        assert_eq!(bars[1].label, full_addr(&ups[1]));
        // 标签里不得出现省略号（truncate 回归的文本侧证据）。
        for b in &bars {
            assert!(!b.label.contains('…'), "轴标签不得被截断: {}", b.label);
        }
    }

    /// 空地址的上游不得产出空标签（空标签在图上渲染成"缺了几条"的观感）。
    #[test]
    fn up_bars_never_emits_empty_label() {
        let ups = vec![UpstreamStat {
            enabled: true,
            latency: Some(1.0),
            ..UpstreamStat::default()
        }];
        let bars = up_bars(&ups);
        assert_eq!(bars.len(), 1);
        assert!(
            !bars[0].label.trim().is_empty(),
            "空地址必须回退 `–`，不得出空标签"
        );
    }

    /// **2.1.18（修复项 3）**：单一来源 = **后端** `/api/upstreams[].full_addr`。
    ///
    /// 判据：字段存在且非空时，`full_addr(u)` 必须**逐字等于**后端字段，
    /// 且**与本地兜底实现的结果一致**（两条规则不许漂移）。
    ///
    /// 用例集与后端单测
    /// `ebpdns-server::api::tests::full_addr_covers_six_protocols_default_ports_ipv6_and_path`
    /// **逐条对应**（六协议 + 默认端口 ×2 + 非默认端口 + 完整 URL 取路径 +
    /// 重复斜杠 + IPv6 方括号 + 裸协议不拼路径 + host 空退回 name）——
    /// 两边必须同时改，否则其中一侧的测试会红。
    #[test]
    fn full_addr_matches_backend_field_when_present() {
        // (proto, addr, name, port, url, 后端下发的 full_addr)
        let corpus: Vec<(&str, &str, &str, f64, &str, &str)> = vec![
            ("udp", "223.5.5.5", "u1", 53.0, "", "udp://223.5.5.5:53"),
            ("tcp", "223.5.5.5", "u2", 53.0, "", "tcp://223.5.5.5:53"),
            (
                "doh",
                "dns.alidns.com",
                "u3",
                443.0,
                "/dns-query",
                "https://dns.alidns.com/dns-query",
            ),
            (
                "doh3",
                "dns.alidns.com",
                "u4",
                443.0,
                "/dns-query",
                "http3://dns.alidns.com/dns-query",
            ),
            ("dot", "dns.google", "u5", 853.0, "", "tls://dns.google"),
            (
                "doq",
                "dns.alidns.com",
                "u6",
                853.0,
                "",
                "quic://dns.alidns.com",
            ),
            (
                "doh",
                "dns.alidns.com",
                "u7",
                8443.0,
                "/dns-query",
                "https://dns.alidns.com:8443/dns-query",
            ),
            (
                "doq",
                "dns.alidns.com",
                "u8",
                8853.0,
                "",
                "quic://dns.alidns.com:8853",
            ),
            (
                "doh",
                "2001:db8::1",
                "u9",
                443.0,
                "https://2001:db8::1/dns-query",
                "https://[2001:db8::1]/dns-query",
            ),
            (
                "udp",
                "223.5.5.5",
                "u10",
                53.0,
                "/dns-query",
                "udp://223.5.5.5:53",
            ),
            ("", "lan-dns", "lan-dns", 53.0, "", "udp://lan-dns:53"),
        ];
        for (proto, addr, name, port, url, backend) in corpus {
            let mut u = up(proto, addr, port, url);
            u.name = name.to_string();
            // ① 后端字段存在时：输出 == 后端字段（单一来源）。
            u.full_addr = Some(backend.to_string());
            assert_eq!(
                full_addr(&u),
                backend,
                "字段存在时必须直接用后端值（proto={proto} addr={addr} port={port}）"
            );
            // ② 与本地兜底实现一致：两条规则不得漂移。
            assert_eq!(
                local_full_addr(&u),
                backend,
                "本地兜底实现必须与后端规则逐条一致（proto={proto} addr={addr} port={port}）"
            );
            // ③ 字段缺失时：兜底给出同一答案（旧后端仍可用）。
            u.full_addr = None;
            assert_eq!(
                full_addr(&u),
                backend,
                "字段缺失时必须回退本地实现且结果相同（proto={proto}）"
            );
            // ④ 后端给了空串（等价于缺失）：同样回退。
            u.full_addr = Some("   ".to_string());
            assert_eq!(full_addr(&u), backend, "空白字段必须按缺失处理");
        }
    }

    /// **2.1.18（修复项 3）**：「上游平均延迟」图与「健康度表」都必须走
    /// **同一个** `full_addr`（含后端字段优先），因此图/表**不可能**漂移。
    #[test]
    fn up_bars_and_health_rows_share_backend_full_addr() {
        let mut a = up("doh3", "dns.alidns.com", 443.0, "/dns-query");
        a.enabled = true;
        a.latency = Some(12.0);
        a.queries = 5.0;
        a.success_rate = Some(100.0);
        // 故意让"后端字段"与本地推导**不同**，以证明消费的是后端字段
        // （若实现漏读该字段，两条断言都会红）。
        a.full_addr = Some("http3://backend.example/dns-query".to_string());
        let mut b = up("udp", "223.5.5.5", 53.0, "");
        b.enabled = true;
        b.latency = Some(3.0);
        b.queries = 5.0;
        b.success_rate = Some(100.0);
        b.full_addr = Some("udp://backend.example:5353".to_string());
        let ups = vec![a.clone(), b.clone()];

        let bars = up_bars(&ups);
        assert_eq!(bars.len(), 2);
        assert_eq!(bars[0].label, "http3://backend.example/dns-query");
        assert_eq!(bars[1].label, "udp://backend.example:5353");

        let rows = health_rows(&ups);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].addr, "http3://backend.example/dns-query");
        assert_eq!(rows[1].addr, "udp://backend.example:5353");
        // 图与表逐条相等（同一函数 ⇒ 不可能漂移）。
        for (bar, row) in bars.iter().zip(rows.iter()) {
            assert_eq!(bar.label, row.addr, "图标签与表「完整地址」列必须逐字一致");
        }
    }

    /* ======= **2.1.18（修复项 8）**：三张 KPI 的 0 / 无数据 / 加载态口径 ======= */

    /// 三张卡在"拿到首帧且计数为 0"时必须渲染明确的 `"0"`（不是空串、
    /// 不是"暂无数据"）—— 用户实测把 0 读成"无数据/坏了"。
    ///
    /// 这里直接以 KPI 的渲染表达式为断言对象：`loading == false` ⇒
    /// `fmt::group0(0.0) == "0"`。同时断言副标题在**字段存在**时给出
    /// "何时会非 0"的口径文案（而不是留空）。
    #[test]
    fn kpi_zero_is_rendered_as_explicit_zero_not_empty() {
        use crate::model::Counters;
        // 后端 2.1.19：两个结构化口径都在。
        let c = Counters {
            servfail_total: 0.0,
            negative_hits: 0.0,
            client_rcode: (0..16).map(|i| (i.to_string(), 0.0)).collect(),
            servfail_reasons: [
                "upstream_timeout",
                "upstream_no_answer",
                "no_upstream",
                "encode_failed",
                "panic",
            ]
            .iter()
            .map(|k| ((*k).to_string(), 0.0))
            .collect(),
            ..Counters::default()
        };
        // ① 数值必须是明确的 "0"。
        assert_eq!(crate::fmt::group0(c.servfail_total), "0");
        assert_eq!(crate::fmt::group0(c.negative_hits), "0");
        assert_eq!(crate::fmt::group0(c.client_rcode2()), "0");
        assert!(!crate::fmt::group0(0.0).is_empty());
        // ② 字段存在 ⇒ 副标题是"何时非 0"的口径，而不是"无数据"。
        assert_eq!(kpi_sub_servfail(c.has_servfail_reasons()), KpiSub::Explain);
        assert_eq!(kpi_sub_client_rcode(c.has_client_rcode()), KpiSub::Explain);
        assert_eq!(kpi_sub_negcache(true), KpiSub::Explain);
        for (kind, which, expect) in [
            (KpiSub::Explain, "servfail", "rcode=2"),
            (KpiSub::Explain, "negcache", "未回源"),
            (KpiSub::Explain, "clirccode2", "恒等于 SERVFAIL"),
        ] {
            let t = kpi_sub_text(kind, which);
            assert!(t.contains(expect), "{which} 副标题口径丢了 `{expect}`：{t}");
            assert!(
                !t.contains("暂无") && !t.contains("无数据"),
                "{which} 副标题不得出现空态措辞：{t}"
            );
        }
    }

    /// `counters.client_rcode` 整块缺失（旧后端）⇒ 卡片副标题必须显示
    /// **"该后端不支持自证口径"**，而不是静默显示 0；`servfail_reasons`
    /// 缺失同理（"该后端无分档归因"）。
    #[test]
    fn kpi_missing_fields_say_backend_unsupported() {
        use crate::model::Counters;
        let legacy = Counters::default(); // 两个结构化键都缺（旧后端）
        assert!(!legacy.has_client_rcode());
        assert!(!legacy.has_servfail_reasons());
        assert_eq!(legacy.client_rcode2(), 0.0, "缺失时数值仍安全回退 0");
        assert_eq!(
            kpi_sub_text(
                kpi_sub_client_rcode(legacy.has_client_rcode()),
                "clirccode2"
            ),
            "该后端不支持自证口径"
        );
        assert_eq!(
            kpi_sub_text(kpi_sub_servfail(legacy.has_servfail_reasons()), "servfail"),
            "该后端无分档归因"
        );
        // 空表（键在但无槽）也按"不支持"处理（见 `has_client_rcode` 文档）。
        let empty_map = Counters {
            client_rcode: std::collections::HashMap::new(),
            ..Counters::default()
        };
        assert!(!empty_map.has_client_rcode());
    }

    /// 加载态（首帧未到）：三张卡的数值与副标题都必须是 `···`
    /// （源码级断言：`loading()` 分支是渲染表达式的第一支）。
    ///
    /// 这是**契约测试**：`loading = app.status.is_none()`，因此只要"status 为 None
    /// ⇒ 渲染 `···`"这条分支存在，首帧未到就不会显示 0（0 会被误读成真实值）。
    #[test]
    fn kpi_loading_state_is_dots() {
        let src = include_str!("telemetry.rs");
        for id in ["kpi-servfail", "kpi-neghit", "kpi-cli-rcode2"] {
            let at = src
                .find(&format!("\"{id}\""))
                .unwrap_or_else(|| panic!("找不到 KPI {id} 的渲染点"));
            // 该 span 之后 400 字节内必须出现 loading 分支与 `···`。
            let tail = &src[at..(at + 400).min(src.len())];
            assert!(
                tail.contains("loading()") && tail.contains("···"),
                "KPI {id} 必须有 `loading() → ···` 的加载态分支（0 与『首帧未到』必须可区分）"
            );
        }
    }

    /// **2.1.18（修复项 8）**：上游延迟图的空态文案必须区分
    /// "没配上游"与"有上游但还没有延迟样本"。
    #[test]
    fn up_chart_empty_state_distinguishes_no_upstream_from_no_samples() {
        // 没有任何上游 → "暂无上游"。
        assert_eq!(up_empty_msg(&[], &[]), "暂无数据 · 尚未配置上游");
        // 有上游但 up_bars 过滤后为空（禁用 / 无延迟样本）→ "暂无延迟样本"。
        let ups = vec![UpstreamStat {
            enabled: false,
            ..up("udp", "223.5.5.5", 53.0, "")
        }];
        assert!(up_bars(&ups).is_empty(), "禁用且无查询的上游不进图");
        let msg = up_empty_msg(&[], &ups);
        assert_eq!(msg, "暂无数据 · 还没有延迟样本（等待上游流量）");
        assert_ne!(
            msg, "暂无数据 · 尚未配置上游",
            "不得把『还没测到』说成『上游丢了』"
        );
        // 有可画横条 → 无空态文案（title 会被 show=false 隐藏）。
        let mut ok = up("udp", "1.1.1.1", 53.0, "");
        ok.enabled = true;
        ok.latency = Some(1.0);
        let bars = up_bars(&[ok.clone()]);
        assert!(!bars.is_empty());
        assert_eq!(up_empty_msg(&bars, &[ok]), "");
    }
}

#[cfg(test)]
mod card_source_tests {
    /// G2：用户态缓存占用卡必须读 `cache.used/capacity`，且页面中不得再出现
    /// 内核态缓存 / eBPF / XDP 的任何文案或取值来源。
    #[test]
    fn user_cache_card_uses_cache_source_not_map_alias() {
        let ui = include_str!("telemetry.rs");
        assert!(ui.contains("用户态缓存占用"), "卡片必须叫用户态缓存占用");
        assert!(
            !ui.contains("BPF LRU Map 占用"),
            "不得再把用户态数字标成 BPF LRU Map 占用"
        );
        assert!(
            ui.contains(r#"data-src="cache.used/cache.capacity""#),
            "缺 data-src"
        );
        for bad in [
            "ebpf",
            "kernel_cache",
            "kernel_direct",
            "XDP",
            "内核直答",
            "内核态缓存",
        ] {
            assert!(!ui.contains(bad), "页面仍含已移除文案/字段: {bad}");
        }
    }
}

/// **2.1.49（AUD-09）**：进程卡片的三态渲染（独立于 wasm DOM 的纯判定）。
#[cfg(test)]
mod m249_proc_tests {
    use super::*;
    use crate::model::ProcessInfo;

    fn bytes_text(v: Option<u64>) -> String {
        match v {
            Some(v) => fmt::bytes_text(v),
            None => "不可用".to_string(),
        }
    }
    fn count_text(v: Option<u64>) -> String {
        match v {
            Some(v) => fmt::group0(v as f64),
            None => "不可用".to_string(),
        }
    }

    #[test]
    fn m249_proc_card_values_and_unavailable_are_distinct() {
        let p = ProcessInfo {
            resident_memory_bytes: Some(101 * 1024 * 1024),
            threads: Some(11),
            open_fds: Some(39),
            ..Default::default()
        };
        assert_eq!(count_text(p.threads), "11");
        assert_eq!(count_text(p.open_fds), "39");
        assert!(bytes_text(p.resident_memory_bytes).contains("101"));
        // 字段缺失 ⇒ 不可用；0 仍是 0（不得把缺失/真实 0 混为一谈）。
        assert_eq!(count_text(None), "不可用");
        assert_eq!(count_text(Some(0)), "0");
    }
}
