//! 数据面流水线页 —— 逐页复刻 v1.9.162 `web/index.html`：
//! - DOM：第 596–641 行（`section.route[data-route=pipeline]` + `#rail` + 八列日志控制台）
//! - 几何/动画：第 1573–1723 行（ST 常量 / renderPipeline / spawnPacket / frame）
//! - 日志：第 1435–1571 行（appendLogLine / lineMatchesFilters / renderFilteredLogs）
//!
//! 与原件一致的关键行为：
//! - 站点/连线几何全部使用固定百分比常量（容器自适应交给 CSS）。
//! - 数据包：`max 16` 个在飞节点（`_SIM_QUEUE_MAX`），由 rAF 循环按累积段长插值移动，
//!   每批日志只对最后 3 条触发动画，落点/颜色与 `spawnPacket` 完全一致。
//! - 日志：`logline {level}` + 八列 `<span class="lc ...">`；`domain` 空且 `msg` 非空时为
//!   两列系统行（`ts` + `lc lm wide`）；筛选语义照抄 `lineMatchesFilters`。

use std::cell::{Cell, RefCell};

use leptos::prelude::*;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;
use web_sys::{Element, HtmlElement, HtmlInputElement};

use crate::fmt;
use crate::model::{LogEvent, PacketKind};
use crate::state::{App, LogFilters, Mode};

/* ======================= 几何常量（对齐原件 ST / *_WP / *_SEGS） ======================= */

const P_CLIENT: (f64, f64) = (9.0, 28.0);
const P_CACHE: (f64, f64) = (44.0, 28.0);
const P_REPLY: (f64, f64) = (87.0, 28.0);
const P_ENGINE: (f64, f64) = (44.0, 75.0);
const P_UP: [(f64, f64); 3] = [(64.0, 75.0), (77.0, 75.0), (90.0, 75.0)];

const HIT_WP: [(f64, f64); 3] = [P_CLIENT, P_CACHE, P_REPLY];
const ERR_WP: [(f64, f64); 3] = [P_CLIENT, P_CACHE, P_ENGINE];
const HIT_SEGS: [f64; 2] = [70.0, 130.0];
const ERR_SEGS: [f64; 2] = [60.0, 85.0];
const MISS_SEGS: [f64; 7] = [60.0, 60.0, 85.0, 240.0, 340.0, 210.0, 150.0];

/// 在飞数据包队列上限（原件 `_SIM_QUEUE_MAX`，第 1299 行）。
const PACKET_QUEUE_MAX: usize = 16;

/// 连线色（对齐 `.flow.cyan/.amber/.back` 三组 CSS 变量）。
#[derive(Clone, Copy, PartialEq, Eq)]
enum FlowColor {
    Cyan,
    Amber,
    Back,
}

impl FlowColor {
    fn css(self) -> &'static str {
        match self {
            FlowColor::Cyan => "var(--cyan)",
            FlowColor::Amber => "var(--amber)",
            FlowColor::Back => "var(--text3)",
        }
    }
    /// `.flow.back .ln,.flow.back .hd{... opacity:.5}`
    fn extra(self) -> &'static str {
        match self {
            FlowColor::Back => "opacity:.5;",
            _ => "",
        }
    }
}

/// rail 连线（原件 addFlow 调用序列，第 1666–1675 行）：(x1,y1,x2,y2,色,是否纵向)。
const FLOWS: [(f64, f64, f64, f64, FlowColor, bool); 10] = [
    (14.5, 28.0, 38.5, 28.0, FlowColor::Amber, false), // 客户端 → 用户态缓存
    (50.0, 28.0, 81.0, 28.0, FlowColor::Cyan, false),  // 命中: 缓存 → 回包
    (43.0, 41.0, 43.0, 64.0, FlowColor::Amber, true),  // 未命中下行: 缓存 ↓ 引擎
    (50.5, 74.0, 58.5, 74.0, FlowColor::Amber, false), // 引擎 → 上游 1（64-5.5）
    (58.5, 78.0, 50.5, 78.0, FlowColor::Back, false),  // 上游 1 → 引擎（回程）
    (50.5, 74.0, 71.5, 74.0, FlowColor::Amber, false), // 引擎 → 上游 2（77-5.5）
    (71.5, 78.0, 50.5, 78.0, FlowColor::Back, false),  // 上游 2 → 引擎（回程）
    (50.5, 74.0, 84.5, 74.0, FlowColor::Amber, false), // 引擎 → 上游 3（90-5.5）
    (84.5, 78.0, 50.5, 78.0, FlowColor::Back, false),  // 上游 3 → 引擎（回程）
    (45.2, 64.0, 45.2, 41.0, FlowColor::Amber, true),  // 回填缓存: 引擎 ↑ 缓存
];

/* ======================= 数据包 rAF 动画（原件 sim.packets / frame） ======================= */

/// 在飞数据包：DOM 节点 + 途经点 + 分段时长。
struct Fly {
    el: Element,
    waypoints: Vec<(f64, f64)>,
    segs: Vec<f64>,
    start: f64,
    dur: f64,
}

/// rAF 回调句柄类型别名（`Closure<dyn FnMut(f64)>` 直接写进 `RefCell<Option<…>>`
/// 会触发 `clippy::type_complexity`；行为不变）。
type RafCb = RefCell<Option<Closure<dyn FnMut(f64)>>>;

thread_local! {
    /// 在飞数据包队列（≤ PACKET_QUEUE_MAX）。
    static PACKETS: RefCell<Vec<Fly>> = const { RefCell::new(Vec::new()) };
    /// 复用的 rAF 回调（只创建一次，避免每帧泄漏 Closure）。
    static RAF_CB: RafCb = const { RefCell::new(None) };
    /// 循环开关（对齐原件 `_frameRunning`）。
    static LOOP_ON: Cell<bool> = const { Cell::new(false) };
    /// miss 包轮询槽位（对齐 `sim._missSlot`）。
    static MISS_SLOT: Cell<usize> = const { Cell::new(0) };
}

fn document() -> Option<web_sys::Document> {
    web_sys::window().and_then(|w| w.document())
}

fn remove_node(el: &Element) {
    if let Some(parent) = el.parent_node() {
        let _ = parent.remove_child(el);
    }
}

fn ensure_raf() {
    RAF_CB.with(|slot| {
        let need = slot.borrow().is_none();
        if need {
            // 循环体是自由函数，闭包不捕获任何 !Send 值；句柄常驻 thread_local，只分配一次。
            let cb = Closure::<dyn FnMut(f64)>::new(move |now: f64| frame_tick(now));
            *slot.borrow_mut() = Some(cb);
        }
    });
}

fn request_frame() {
    let Some(win) = web_sys::window() else {
        return;
    };
    RAF_CB.with(|slot| {
        if let Some(cb) = slot.borrow().as_ref() {
            // request_animation_frame 的返回值（句柄）不用：停表靠 LOOP_ON 门控。
            let _ = win.request_animation_frame(cb.as_ref().unchecked_ref());
        }
    });
}

/// 启动 rAF 循环（幂等，对齐 `startFrameLoop()`）。
fn start_frame_loop() {
    ensure_raf();
    if LOOP_ON.with(|f| f.get()) {
        return;
    }
    LOOP_ON.with(|f| f.set(true));
    request_frame();
}

/// 停止循环并回收全部在飞节点（对齐 `setRoute()` 离开 pipeline 的清理 + `_rafHandle` 取消）。
fn stop_frame_loop() {
    LOOP_ON.with(|f| f.set(false));
    clear_packets();
}

/// 清空在飞数据包（对齐 `sim.packets.forEach(p => p.el.remove()); sim.packets = []`）。
fn clear_packets() {
    PACKETS.with(|slot| {
        let mut v = slot.borrow_mut();
        for p in v.drain(..) {
            remove_node(&p.el);
        }
    });
}

/// 每帧：按累积段长插值移动 `left/top`，走完即回收；后台标签页仍续排（对齐原件 frame）。
fn frame_tick(_ts: f64) {
    if !LOOP_ON.with(|f| f.get()) {
        return;
    }
    // 时间基统一用 Date.now()：web-sys 未启用 "Performance" feature，
    // 且 start/tick 同一时钟即可保证 `elp = now - start` 语义与 performance.now() 等价。
    let now = js_sys::Date::now();
    let hidden = document().map(|d| d.hidden()).unwrap_or(false);
    if !hidden {
        PACKETS.with(|slot| {
            let mut v = slot.borrow_mut();
            let mut i = v.len();
            while i > 0 {
                i -= 1;
                let elp = now - v[i].start;
                if elp >= v[i].dur {
                    remove_node(&v[i].el);
                    v.remove(i);
                    continue;
                }
                let (x, y) = pos_at(&v[i], elp);
                let _ = v[i]
                    .el
                    .set_attribute("style", &format!("left:{x:.4}%;top:{y:.4}%"));
            }
        });
    }
    request_frame();
}

/// 累积段长插值定位（原件 `posAt`）。
///
/// **2.1.35（wasm panic 修复）**：索引一律用 `get()` + 回退到最后一个航点。
/// 旧实现只要 `segs.len() + 1 != waypoints.len()` 就会在 `waypoints[i + 1]` 越界
/// panic（miss 包恰好 7 段 / 7 点）。现在长度失配只会让数据包「停在最后航点」，
/// 不会 abort 整个 wasm（panic=abort 下还会把 `PACKETS` 的 `RefCell` 永久借走，
/// 引发后续 `RefCell already borrowed` 级联）。
fn pos_at(p: &Fly, elp: f64) -> (f64, f64) {
    pos_at_pts(&p.waypoints, &p.segs, elp)
}

/// [`pos_at`] 的纯函数内核（不依赖 DOM，便于单测覆盖边界）。
fn pos_at_pts(waypoints: &[(f64, f64)], segs: &[f64], elp: f64) -> (f64, f64) {
    let mut acc = 0.0;
    for (i, &d) in segs.iter().enumerate() {
        if !(d > 0.0) {
            continue;
        }
        if elp < acc + d {
            let Some(&a) = waypoints.get(i) else {
                break;
            };
            let b = waypoints.get(i + 1).copied().unwrap_or(a);
            let t = ((elp - acc) / d).clamp(0.0, 1.0);
            return (a.0 + (b.0 - a.0) * t, a.1 + (b.1 - a.1) * t);
        }
        acc += d;
    }
    waypoints.last().copied().unwrap_or(P_REPLY)
}

/// miss 路径：客户端 → 用户态缓存 → 引擎 → 上游 → 引擎 → 缓存 → 回包。
fn miss_wp(up_idx: usize) -> Vec<(f64, f64)> {
    let up = P_UP[up_idx.min(2)];
    // **2.1.35（wasm panic 修复）**：`MISS_SEGS` 是 7 段 ⇒ 必须有 8 个航点。
    // 末尾重复 `P_REPLY`：最后 150 ms 停在回包点（此前只有 7 个点，`pos_at()` 在
    // 最后一段访问 `waypoints[7]` 越界 → 每个 miss 包必 panic，见 patch235_wasm_panic.py）。
    vec![
        P_CLIENT, P_CACHE, P_ENGINE, up, P_ENGINE, P_CACHE, P_REPLY, P_REPLY,
    ]
}

/// 生成一个数据包节点并挂到 `#rail`（原件 `spawnPacket`）。
fn spawn_packet(domain: &str, kind: PacketKind, up_idx: usize) {
    let Some(doc) = document() else {
        return;
    };
    let Some(rail) = doc.get_element_by_id("rail") else {
        return;
    };
    let Ok(el) = doc.create_element("div") else {
        return;
    };
    // 原件只加 `pkt` 类（颜色写在内联样式上），CSS 中不存在 .pkt.hit/.pkt.miss/.pkt.fail。
    let _ = el.set_attribute("class", "pkt");
    let color = match kind {
        PacketKind::Hit => "var(--cyan)",
        PacketKind::Fail => "var(--red)",
        PacketKind::Miss => "var(--amber)",
    };
    if let Ok(dot) = doc.create_element("span") {
        let _ = dot.set_attribute("class", "pkt-dot");
        let _ = dot.set_attribute("style", &format!("background:{color};border-color:{color}"));
        let _ = el.append_child(&dot);
    }
    if let Ok(label) = doc.create_element("span") {
        let _ = label.set_attribute("class", "pkt-label");
        label.set_text_content(Some(&strip_www(domain)));
        let _ = el.append_child(&label);
    }
    if rail.append_child(&el).is_err() {
        return;
    }

    let (waypoints, segs) = match kind {
        PacketKind::Hit => (HIT_WP.to_vec(), HIT_SEGS.to_vec()),
        PacketKind::Fail => (ERR_WP.to_vec(), ERR_SEGS.to_vec()),
        PacketKind::Miss => (miss_wp(up_idx), MISS_SEGS.to_vec()),
    };
    let dur: f64 = segs.iter().sum();
    PACKETS.with(|slot| {
        let mut v = slot.borrow_mut();
        v.push(Fly {
            el,
            waypoints,
            segs,
            start: js_sys::Date::now(),
            dur,
        });
        // 超过上限丢弃最老一帧（原件 `if (sim.packets.length > _SIM_QUEUE_MAX) shift()`）。
        if v.len() > PACKET_QUEUE_MAX {
            let old = v.remove(0);
            remove_node(&old.el);
        }
    });
}

fn strip_www(s: &str) -> String {
    s.strip_prefix("www.").unwrap_or(s).to_string()
}

/// 由一条日志事件触发动画（原件 `renderLogBatch` 内的 spawnPacket 调用）。
fn spawn_for_event(e: &LogEvent) {
    let kind = match e.level.as_str() {
        "hit" => PacketKind::Hit,
        "err" => PacketKind::Fail,
        _ => PacketKind::Miss,
    };
    // miss 包不恒落第 1 槽位：轮询 3 槽位（原件 `sim._missSlot`）。
    let slot = MISS_SLOT.with(|c| {
        let v = c.get();
        c.set((v + 1) % 3);
        v
    });
    let label = if !e.domain.is_empty() {
        e.domain.clone()
    } else {
        e.msg.split(' ').next().unwrap_or("").to_string()
    };
    spawn_packet(&label, kind, slot);
}

/* ======================= 站点模型（原件 renderPipeline） ======================= */

#[derive(Clone, Copy, PartialEq, Eq)]
enum Icon {
    Server,
    Cache,
    Reply,
    Engine,
    Globe,
}

struct Station {
    name: String,
    sub: String,
    cls: &'static str,
    x: f64,
    y: f64,
    w: f64,
    icon: Icon,
}

/// 流水线站点/连线的数据来源（`/api/pipeline` 优先；**无数据时显示 `—`**，不再冒充真值）。
struct RailModel {
    cache_size: String,
    cache_direct_enabled: bool,
    ups: Vec<(String, String)>,
    /// **2.1.15（决策 2）**：规则索引真实条数（`/api/pipeline.rules`）。
    /// 仅为 `None` 时才不存在（无 `/api/pipeline`）；`f64` 包装保持与后端数字契约一致。
    rules: Option<f64>,
    /// **2.1.15（决策 2）**：配置里的上游条数（`/api/pipeline.upstream_count`，含已禁用）。
    upstream_count: Option<f64>,
}

impl RailModel {
    /// 结构签名（对齐原件 `_pipelineSig`）：只有它变化才清在飞数据包。
    fn signature(&self) -> String {
        // 用**具名**占位符（`{hook}` 形式）而不是连续的 `{}~{}`：后者每加一个字段
        // 都要重新数占位符个数，实测漏数一次就是 `7 positional arguments …
        // but there are 6`（编译期就报，不会静默）。具名参数与字段一一对应，改不坏。
        let mut s = format!(
            "{cache}~{cd}~{rules}~{ups_n}",
            cache = self.cache_size,
            cd = if self.cache_direct_enabled {
                "on"
            } else {
                "off"
            },
            rules = self.rules.map(fmt::num0).unwrap_or_else(|| "?".to_string()),
            ups_n = self
                .upstream_count
                .map(fmt::num0)
                .unwrap_or_else(|| "?".to_string()),
        );
        for (n, p) in &self.ups {
            s.push_str(n);
            s.push('|');
            s.push_str(p);
            s.push(';');
        }
        s
    }
}

/// 无数据/接口失败时的统一占位符：**没有数据就是没有数据**，不显示像真值的常量。
const NO_DATA: &str = "—";

/// **2.1.43-B（P2-1）**：**字段缺失**的显式占位 —— 「未知」与「0」是两件事
/// （`/api/pipeline` 不返回 `rules` / `upstream_count` 时不得显示成 0）。
const UNKNOWN: &str = "未知";

fn rail_model(app: App) -> RailModel {
    let pipe = app.pipeline.get();
    // 回退链（对齐原件 R35）：/api/pipeline.cache_size → /api/status.map.capacity。
    let cap = pipe
        .as_ref()
        .map(|p| p.cache_size)
        .filter(|v| v.is_finite() && *v > 0.0)
        .or_else(|| {
            let c = app.status_or_default().map.capacity;
            if c.is_finite() && c > 0.0 {
                Some(c)
            } else {
                None
            }
        });
    let cache_size = cap.map(fmt::num0).unwrap_or_else(|| NO_DATA.to_string());
    let cache_direct_enabled = pipe
        .as_ref()
        .map(|p| p.cache_direct_enabled)
        .unwrap_or(false);
    // **2.1.43-B（P2-1）**：`rules` / `upstream_count` 已是 `Option<f64>`（字段缺失 ⇒ None）
    // ⇒ 这里必须 `and_then`，否则 `Option<Option<f64>>` 会让"没采集到"再次退化成 0。
    let rules = pipe.as_ref().and_then(|p| p.rules);
    let upstream_count = pipe.as_ref().and_then(|p| p.upstream_count);
    let ups = match pipe {
        Some(p) => p
            .upstreams
            .into_iter()
            .take(3)
            .map(|u| (u.name, u.proto))
            .collect(),
        None => Vec::new(),
    };
    RailModel {
        cache_size,
        cache_direct_enabled,
        ups,
        rules,
        upstream_count,
    }
}

/// 站点 + 上游槽位（顺序与原件 append 顺序一致）。
fn stations_view(app: App) -> impl IntoView {
    let m = rail_model(app);
    let mut stations = vec![
        Station {
            name: "客户端".into(),
            sub: "LAN / Pod · 发往 :53".into(),
            cls: "",
            x: P_CLIENT.0,
            y: P_CLIENT.1,
            w: 13.0,
            icon: Icon::Server,
        },
        Station {
            name: "用户态缓存".into(),
            sub: format!(
                "{} 条目{}",
                m.cache_size,
                if m.cache_direct_enabled {
                    " · 缓存直答"
                } else {
                    " · 缓存直答关闭"
                }
            ),
            cls: "hot",
            x: P_CACHE.0,
            y: P_CACHE.1,
            w: 14.0,
            icon: Icon::Cache,
        },
        Station {
            name: "回包".into(),
            sub: "应答返回客户端".into(),
            cls: "",
            x: P_REPLY.0,
            y: P_REPLY.1,
            w: 13.0,
            icon: Icon::Reply,
        },
        Station {
            name: "用户态引擎".into(),
            sub: "ebpdns 守护进程 · SmartDNS 逻辑".into(),
            cls: "warm",
            x: P_ENGINE.0,
            y: P_ENGINE.1,
            w: 15.0,
            icon: Icon::Engine,
        },
    ];
    for (i, &(x, y)) in P_UP.iter().enumerate() {
        match m.ups.get(i) {
            // REAL 模式后端对上游脱敏（只回 name/proto），故子标签为 "PROTO "（原件同样尾部留空）。
            Some((name, proto)) => stations.push(Station {
                name: name.clone(),
                sub: format!(
                    "{} ",
                    if proto.trim().is_empty() {
                        "UDP"
                    } else {
                        proto.as_str()
                    }
                ),
                cls: "warm",
                x,
                y,
                w: 13.0,
                icon: Icon::Globe,
            }),
            None => stations.push(Station {
                name: format!("上游 {}", i + 1),
                sub: "未启用".into(),
                cls: "dim",
                x,
                y,
                w: 13.0,
                icon: Icon::Globe,
            }),
        }
    }
    stations.into_iter().map(station_view).collect_view()
}

/// JS 数字 → 属性串（`28.0` → `"28"`、`14.5` → `"14.5"`，与原件模板拼接一致）。
fn num(v: f64) -> String {
    if v.fract() == 0.0 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

/// 站点卡片（原件 `stnHTML`，第 1588 行）：`.stn` 的背景/边框/排版全部来自 style.css，
/// 因此站点仍用 HTML 盒模型承载（`.ic` 内是真 SVG 图标元素）。
fn station_view(s: Station) -> impl IntoView {
    let cls_str = if s.cls.is_empty() {
        "stn".to_string()
    } else {
        format!("stn {}", s.cls)
    };
    let style_str = format!(
        "left:{}%;top:{}%;width:{}%;transform:translate(-50%,-50%)",
        num(s.x),
        num(s.y),
        num(s.w)
    );
    view! {
        <div class=cls_str style=style_str>
            <div class="ic">
                <svg
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="1.8"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                >
                    {icon_view(s.icon)}
                </svg>
            </div>
            <div class="nm">{s.name}</div>
            <div class="sub">{s.sub}</div>
        </div>
    }
}

/// 站点图标（原件 `STN_ICONS`，路径原样照抄）。
fn icon_view(icon: Icon) -> AnyView {
    match icon {
        Icon::Server => view! {
            <>
                <rect x="4" y="4" width="16" height="6" rx="1.5"></rect>
                <rect x="4" y="14" width="16" height="6" rx="1.5"></rect>
                <path d="M7.5 7h.01M7.5 17h.01"></path>
            </>
        }
        .into_any(),
        Icon::Cache => view! {
            <>
                <ellipse cx="12" cy="6" rx="7" ry="3"></ellipse>
                <path d="M5 6v6c0 1.7 3.1 3 7 3s7-1.3 7-3V6"></path>
                <path d="M5 12v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6"></path>
            </>
        }
        .into_any(),
        Icon::Reply => view! {
            <>
                <path d="M20 9H9l4-4-4-4"></path>
                <path d="M4 21v-8a4 4 0 0 1.6.0h12"></path>
            </>
        }
        .into_any(),
        Icon::Engine => view! {
            <>
                <rect x="6" y="6" width="12" height="12" rx="2"></rect>
                <rect x="10" y="10" width="4" height="4"></rect>
                <path d="M9 3v3M15 3v3M9 18v3M15 18v3M3 9h3M3 15h3M18 9h3M18 15h3"></path>
            </>
        }
        .into_any(),
        Icon::Globe => view! {
            <>
                <circle cx="12" cy="12" r="8"></circle>
                <path d="M4 12h16M12 4c3 2.5 3 13.5 0 16M12 4c-3 2.5-3 13.5 0 16"></path>
            </>
        }
        .into_any(),
    }
}

/// 一条连线 + 箭头菱形（原件 `addFlow`：横向线高 1.6px，箭头落在终点）。
fn flow_view(f: (f64, f64, f64, f64, FlowColor, bool)) -> impl IntoView {
    let (x1, y1, x2, y2, color, _vertical) = f;
    let stroke = format!("stroke:{};{}", color.css(), color.extra());
    let fill = format!("fill:{};{}", color.css(), color.extra());
    // 箭头：以终点为中心的菱形（原件为 7px 旋转 45° 方块，尺寸随容器缩放）。
    let head = format!(
        "{},{} {},{} {},{} {},{}",
        num(x2),
        num(y2 - 0.9),
        num(x2 + 0.45),
        num(y2),
        num(x2),
        num(y2 + 0.9),
        num(x2 - 0.45),
        num(y2)
    );
    view! {
        <>
            <line
                x1=num(x1)
                y1=num(y1)
                x2=num(x2)
                y2=num(y2)
                style=stroke
                stroke-width="1.6"
                vector-effect="non-scaling-stroke"
            ></line>
            <polygon points=head style=fill></polygon>
        </>
    }
}

/* ======================= 日志行（原件 appendLogLine / lineMatchesFilters） ======================= */

/// 单条日志行（已归一，`For` 只做纯渲染）。
#[derive(Clone, PartialEq)]
struct Row {
    /// 唯一 key：**后端 `seq`**（D13）。
    ///
    /// 旧实现用 `seq#缓冲区下标`：`poll.rs` 每轮把超限的头部 `drain` 掉后下标整体平移，
    /// 于是满 300 条之后每一轮所有 key 都变，Leptos `For` 只能全量重建 DOM（300 行 × 每 2s）。
    /// `seq` 由后端单调递增、与缓冲区位置无关，追加/淘汰都保持稳定。
    /// 极端兜底：后端未给 `seq`（异常/旧契约，缺省 0）时退回行号，保证 key 不重复。
    key: String,
    level: String,
    ts: String,
    ip: String,
    dm: String,
    qtype: String,
    up: String,
    an: String,
    lat: Option<f64>,
    rule: String,
    msg: String,
    /// `domain` 空且 `msg` 非空 → 两列系统行。
    sys: bool,
    nx: bool,
    /// v2.1.7：本行是否属于「进入本页之后新增的事件」→ 只对新增行播放入场淡入。
    fresh: bool,
}

/// 日志行 key（D13）：优先 `seq`；`seq` 非正/非有限时退回行号。
fn row_key(e: &LogEvent, idx: usize) -> String {
    if e.seq.is_finite() && e.seq > 0.0 {
        format!("{}", e.seq as i64)
    } else {
        format!("noseq#{idx}")
    }
}

fn row_of(e: &LogEvent, idx: usize, born_after: f64) -> Row {
    let msg = e.msg.clone();
    Row {
        key: row_key(e, idx),
        level: e.level.clone(),
        ts: e.ts.clone(),
        ip: if e.client_ip.is_empty() {
            "-".into()
        } else {
            e.client_ip.clone()
        },
        dm: e.domain.clone(),
        qtype: e.qtype.clone(),
        up: if e.upstream.is_empty() {
            "-".into()
        } else {
            e.upstream.clone()
        },
        an: e.answer.clone(),
        lat: e.lat,
        rule: e.rule.clone(),
        sys: e.domain.is_empty() && !msg.is_empty(),
        nx: e.answer == "NXDOMAIN",
        msg,
        fresh: e.seq.is_finite() && e.seq > born_after,
    }
}

/// 过滤 + 归一（对齐 `renderFilteredLogs`：顺序保持，前端过滤为最终显示依据）。
///
/// 下标只用于 `row_key` 的缺 `seq` 兜底，正常路径下 key 与位置无关（D13）。
/// `born_after` = 进入本页时缓冲里的最大 `seq`：只有它之后的事件才播放入场动画，
/// 首屏（最多 300 行）不会一次性播放 300 个动画。
fn build_rows(app: App, born_after: f64) -> Vec<Row> {
    let logs = app.logs.get();
    let filters = app.filters.get();
    let q = app.global_q.get();
    logs.iter()
        .enumerate()
        .filter(|pair| line_matches_filters(pair.1, &filters, &q))
        .map(|(i, e)| row_of(e, i, born_after))
        .collect()
}

/// 前端过滤（原件 `lineMatchesFilters`，第 1463–1491 行）。
fn line_matches_filters(e: &LogEvent, f: &LogFilters, global_q: &str) -> bool {
    let ts = e.ts.as_str();
    let ip = if e.client_ip.is_empty() {
        "-"
    } else {
        e.client_ip.as_str()
    };
    let dm = e.domain.as_str();
    let qt = e.qtype.as_str();
    let up = if e.upstream.is_empty() {
        "-"
    } else {
        e.upstream.as_str()
    };
    let an = if e.answer.is_empty() {
        "-"
    } else {
        e.answer.as_str()
    };
    let rl = e.rule.as_str();
    let la_text = match e.lat {
        Some(v) if v.is_finite() => format!("{v}"),
        _ => "-".to_string(),
    };

    for (col, val) in [
        ("ts", ts),
        ("ip", ip),
        ("dm", dm),
        ("qt", qt),
        ("up", up),
        ("an", an),
        ("rl", rl),
    ] {
        let pat = f.get(col).trim();
        if pat.is_empty() {
            continue;
        }
        if !fmt::contains_ci(val, pat) {
            return false;
        }
    }

    // 响应时间：纯数字 = 最小值(>= 毫秒)，否则按文本包含
    // （原件该分支会读未定义的 cols.la 抛 TypeError，这里按注释语义实现文本包含）。
    let la_pat = f.get("la").trim();
    if !la_pat.is_empty() {
        match la_pat.parse::<f64>() {
            Ok(n) if n.is_finite() => {
                if !matches!(e.lat, Some(l) if l.is_finite() && l >= n) {
                    return false;
                }
            }
            _ => {
                if !fmt::contains_ci(&la_text, la_pat) {
                    return false;
                }
            }
        }
    }

    // 全局搜索：拼接八列 + msg 后做小写包含（原件 `logGlobalQ` 已 trim+小写）。
    let gq = global_q.trim().to_lowercase();
    if !gq.is_empty() {
        let lat_s = match e.lat {
            Some(v) if v.is_finite() => format!("{v}"),
            _ => String::new(),
        };
        let hay = format!("{ts} {ip} {dm} {qt} {up} {an} {lat_s} {rl} {}", e.msg).to_lowercase();
        if !hay.contains(&gq) {
            return false;
        }
    }
    true
}

/// 单行渲染（原件 `appendLogLine` 的两条 innerHTML 分支）。
///
/// v2.1.7 显示/动画：新增行（`fresh`）带入场淡入；超长列 `title` 提示原文；
/// 响应时间按自适应单位（µs/ms/s）显示，>500ms 标红。
fn row_view(r: Row) -> AnyView {
    let class = format!("logline {}", r.level);
    let fresh = r.fresh;
    if r.sys {
        let msg_full = r.msg.clone();
        let msg_title = msg_full.clone();
        return view! {
            <div class=class class:fresh=move || fresh>
                <span class="lc ts">{r.ts}</span>
                <span class="lc lm wide" title=msg_title>
                    {fmt::trunc(&msg_full, 240)}
                </span>
            </div>
        }
        .into_any();
    }

    let an_full = if r.nx {
        "NXDOMAIN".to_string()
    } else if r.an.is_empty() {
        "-".to_string()
    } else {
        r.an.clone()
    };
    let an: AnyView = if r.nx {
        view! { <span class="nx">"NXDOMAIN"</span> }.into_any()
    } else if r.an.is_empty() {
        "-".to_string().into_any()
    } else {
        fmt::trunc(&an_full, 64).into_any()
    };
    let la: AnyView = match r.lat {
        Some(l) if l.is_finite() => {
            let hi = l > 500.0;
            let (t, u) = fmt::lat_auto(l);
            let txt = if u.is_empty() { t } else { format!("{t} {u}") };
            view! { <span class="latv" class:hi=move || hi>{txt}</span> }.into_any()
        }
        _ => "–".to_string().into_any(),
    };
    let rl: AnyView = if r.rule.is_empty() {
        "-".to_string().into_any()
    } else {
        let rule = r.rule.clone();
        let rule_title = rule.clone();
        view! { <span class="rlb" title=rule_title>{fmt::trunc(&rule, 40)}</span> }.into_any()
    };
    // DNS 行带 msg 时作为弱化副注附在域名列（原件 `dmCell`）。
    let dm_sub: AnyView = if r.msg.is_empty() {
        ().into_any()
    } else {
        let msg = r.msg.clone();
        let msg_title = msg.clone();
        view! {
            <>
                { " " }
                <span class="lm-sub" title=msg_title>{fmt::trunc(&msg, 80)}</span>
            </>
        }
        .into_any()
    };

    let dm = fmt::trunc(&r.dm, 48);
    let dm_title = r.dm.clone();
    let ip = r.ip.clone();
    let ip_title = ip.clone();
    let up = fmt::trunc(&r.up, 40);
    let up_title = r.up.clone();
    let an_title = an_full.clone();
    view! {
        <div class=class class:fresh=move || fresh>
            <span class="lc ts">{r.ts.clone()}</span>
            <span class="lc ip" title=ip_title>{ip}</span>
            <span class="lc dm" title=dm_title>{dm}{dm_sub}</span>
            <span class="lc qt">{r.qtype.clone()}</span>
            <span class="lc up" title=up_title>{up}</span>
            <span class="lc an" title=an_title>{an}</span>
            <span class="lc la">{la}</span>
            <span class="lc rl">{rl}</span>
        </div>
    }
    .into_any()
}

/// `#log-filter-clear`：清空八列筛选 + 全局搜索（并把 `#log-search` 的 DOM value 一并清空）。
fn clear_filters(app: App) {
    // 用 `LogFilters::clear()`（原实现直接 `set(LogFilters::default())`，使该方法
    // 沦为仅测试可达的死代码 → `cargo build` 报 dead_code 告警）。
    app.filters.update(|f| f.clear());
    app.global_q.set(String::new());
    if let Some(el) = document().and_then(|d| d.get_element_by_id("log-search")) {
        if let Ok(inp) = el.dyn_into::<HtmlInputElement>() {
            inp.set_value("");
        }
    }
}

/* ======================= 页面 ======================= */

#[component]
pub fn PipelinePage() -> impl IntoView {
    let app = expect_context::<App>();

    // 数据包动画：进入本页启动 rAF（原件 setRoute('pipeline') → startFrameLoop()），
    // 卸载时停表并回收在飞节点。
    start_frame_loop();
    on_cleanup(stop_frame_loop);

    // 站点结构签名变化 → 清空在飞数据包（原件 renderPipeline 的 `_pipelineSig` 判断）。
    let sig = Memo::new(move |_| rail_model(app).signature());
    Effect::new(move |_| {
        let _ = sig.get();
        clear_packets();
    });

    // 过滤后的日志行（顺序追加；筛选/搜索变化时重建，其余情况按 key 增量追加）。
    // `born_after` = 进入本页时的最大 seq：只有其后的新行播放入场淡入（首屏不整屏闪）。
    let born_after =
        app.logs
            .get_untracked()
            .iter()
            .fold(0.0f64, |m, e| if e.seq > m { e.seq } else { m });
    let rows = Memo::new(move |_| build_rows(app, born_after));

    // 每一批新日志只对最后 3 条触发动画（原件 renderLogBatch，第 1548–1563 行）。
    let last_seq = RwSignal::new(Option::<f64>::None);
    Effect::new(move |_| {
        let logs = app.logs.get();
        let prev = last_seq.get_untracked();
        let max = logs
            .iter()
            .fold(f64::NEG_INFINITY, |m, e| if e.seq > m { e.seq } else { m });
        if let Some(prev) = prev {
            if max > prev {
                let fresh: Vec<&LogEvent> = logs.iter().filter(|e| e.seq > prev).collect();
                let n = fresh.len();
                for (i, e) in fresh.into_iter().enumerate() {
                    if i + 3 >= n {
                        spawn_for_event(e);
                    }
                }
            }
        }
        // 缓冲被清空（清空按钮 / 后端重启 / 401）→ 复位游标，避免下一批误触发整批动画。
        last_seq.set(if max.is_finite() { Some(max) } else { None });
    });

    // 仅当用户停在底部时才自动跟随滚动（原件 `nearBottom` 语义）。
    let stick = RwSignal::new(true);
    Effect::new(move |_| {
        let _ = rows.get();
        if !stick.get_untracked() {
            return;
        }
        if let Some(el) = document()
            .and_then(|d| d.get_element_by_id("console-body"))
            .and_then(|e| e.dyn_into::<HtmlElement>().ok())
        {
            el.set_scroll_top(el.scroll_height());
        }
    });

    // `#log-count`：未筛选时只显示总数（对齐原件计数语义）。
    let count_text = move || {
        let all = app.logs.get().len();
        let shown = rows.get().len();
        let f = app.filters.get();
        if !f.any() && app.global_q.get().trim().is_empty() {
            format!("{all} 条")
        } else {
            format!("{all} 条 · 显示 {shown} 条")
        }
    };

    let pill_run = move || app.mode.get() == Mode::Real;
    let pill_text = move || if pill_run() { "RUNNING" } else { "PAUSED" };

    view! {
        <section class="route active" data-route="pipeline">
            <div class="card pl-card">
                <div class="pl-hd">
                    <div>
                        <div class="t">"数据面流水线"</div>
                        <div class="s">"packet-path 实时推演 · 用户态缓存（cache_policy=lru/partitioned/tinylfu）命中快路径直答"</div>
                        // **2.1.15（决策 2：把已有数据上页展示）**：`/api/pipeline` 早已返回
                        // `rules` / `upstream_count`，页面此前未消费。这里以**行内统计条**
                        // 展示（不新增卡片、不与站点徽标重复），口径见各 `title`：
                        // - 「规则总数」= 规则**索引**条数（本地逐条 + 订阅展开后进索引），
                        //   不是 `config.rules[]` 的长度；
                        // - 「上游数」= 配置里的上游条数（**含已禁用**）。
                        <div class="pl-stats">
                            <span
                                class="pl-stat"
                                id="pl-rules"
                                title="规则索引条数：本地逐条规则 + 全部订阅展开后进入索引的条数（只统计本地逐条规则会显著偏小）。**2.1.43-B**：`/api/pipeline` 缺该键时显示「未知」而不是 0。"
                            >
                                <b>"规则总数"</b>
                                <span class="v">
                                    {move || app
                                        .pipeline
                                        .get()
                                        .and_then(|p| p.rules)
                                        .map(fmt::group0)
                                        .unwrap_or_else(|| UNKNOWN.to_string())}
                                </span>
                                <span class="u">"条"</span>
                            </span>
                            <span
                                class="pl-stat"
                                id="pl-ups"
                                title="配置里的上游条数（含 enabled=false 的条目；实际参与解析的首发/后备/闲置角色见遥测页「上游健康度」）。**2.1.43-B**：缺该键时显示「未知」而不是 0。"
                            >
                                <b>"上游数"</b>
                                <span class="v">
                                    {move || app
                                        .pipeline
                                        .get()
                                        .and_then(|p| p.upstream_count)
                                        .map(fmt::group0)
                                        .unwrap_or_else(|| UNKNOWN.to_string())}
                                </span>
                                <span class="u">"条"</span>
                            </span>
                        </div>
                    </div>
                    <div class="right">
                        <div
                            class="status-pill"
                            class:run=move || pill_run()
                            class:pause=move || !pill_run()
                            id="pill-run"
                        >
                            <span class="dot"></span>
                            <span id="pill-txt">{pill_text}</span>
                        </div>
                        // 2.1.14 清理（审计 ⑥）：删除 SIM 负载档位 `#load-seg`
                        // （`display:none` 的死 DOM —— 按钮存在、可聚焦但永不可见，
                        // 本项目也没有仿真模式；原件残留）。
                    </div>
                </div>
                <div id="pipeline">
                    <div id="rail">
                        // 连线层：真 SVG 元素（viewBox 百分比坐标系，preserveAspectRatio=none
                        // 让百分比直接对应容器纵横比；non-scaling-stroke 保证线宽恒定）。
                        <svg
                            viewBox="0 0 100 100"
                            preserveAspectRatio="none"
                            style="position:absolute;inset:0;width:100%;height:100%;z-index:1;pointer-events:none"
                        >
                            {FLOWS.iter().map(|f| flow_view(*f)).collect_view()}
                        </svg>
                        // 站点层（%坐标 + class="stn ..."，样式来自 style.css）。
                        {move || stations_view(app)}
                    </div>
                </div>
                <div class="pl-legend">
                    <span>
                        <i style="background:var(--cyan)"></i>
                        "缓存命中 · 用户态直答"
                    </span>
                    <span>
                        <i style="background:var(--amber)"></i>
                        "缓存未命中 · 用户态多上游解析"
                    </span>
                    <span>
                        <i style="background:var(--red)"></i>
                        "上游失败 · SERVFAIL"
                    </span>
                </div>
            </div>

            <div class="card">
                <div class="console-hd">
                    <span class="c-dot r"></span>
                    <span class="c-dot y"></span>
                    <span class="c-dot g"></span>
                    <span style="margin-left:8px">"ebpdns · 实时查询日志"</span>
                    <span class="right log-tools">
                        <input
                            class="log-search"
                            id="log-search" aria-label="日志全局搜索"
                            type="text"
                            placeholder="全局搜索：域名 / IP / 上游 / 规则…"
                            spellcheck="false"
                            autocomplete="off"
                            prop:value=move || app.global_q.get()
                            on:input=move |ev| app.global_q.set(event_target_value(&ev))
                        />
                        <button
                            class="btn mini"
                            id="log-filter-clear" aria-label="清空全部筛选条件"
                            title="清空全部筛选"
                            on:click=move |_| clear_filters(app)
                        >
                            "清空筛选"
                        </button>
                        <span id="log-count">{count_text}</span>
                    </span>
                </div>
                <div class="log-head">
                    <div class="lc-col">
                        <span class="lc ts">"查询时间"</span>
                        <input
                            class="lc-filter"
                            data-f="ts"
                            aria-label="按查询时间筛选"
                            placeholder="筛选时间…"
                            spellcheck="false"
                            prop:value=move || app.filters.get().ts
                            on:input=move |ev| app
                                .filters
                                .update(|f| f.set("ts", event_target_value(&ev)))
                        />
                    </div>
                    <div class="lc-col">
                        <span class="lc ip">"客户端 IP"</span>
                        <input
                            class="lc-filter"
                            data-f="ip"
                            aria-label="按客户端 IP 筛选"
                            placeholder="筛选 IP…"
                            spellcheck="false"
                            prop:value=move || app.filters.get().ip
                            on:input=move |ev| app
                                .filters
                                .update(|f| f.set("ip", event_target_value(&ev)))
                        />
                    </div>
                    <div class="lc-col">
                        <span class="lc dm">"域名"</span>
                        <input
                            class="lc-filter"
                            data-f="dm"
                            aria-label="按域名筛选"
                            placeholder="筛选域名…"
                            spellcheck="false"
                            prop:value=move || app.filters.get().dm
                            on:input=move |ev| app
                                .filters
                                .update(|f| f.set("dm", event_target_value(&ev)))
                        />
                    </div>
                    <div class="lc-col">
                        <span class="lc qt">"类型"</span>
                        <input
                            class="lc-filter"
                            data-f="qt"
                            aria-label="按查询类型筛选"
                            placeholder="A/AAAA…"
                            spellcheck="false"
                            prop:value=move || app.filters.get().qt
                            on:input=move |ev| app
                                .filters
                                .update(|f| f.set("qt", event_target_value(&ev)))
                        />
                    </div>
                    <div class="lc-col">
                        <span class="lc up">"上游解析"</span>
                        <input
                            class="lc-filter"
                            data-f="up"
                            aria-label="按上游筛选"
                            placeholder="筛选上游…"
                            spellcheck="false"
                            prop:value=move || app.filters.get().up
                            on:input=move |ev| app
                                .filters
                                .update(|f| f.set("up", event_target_value(&ev)))
                        />
                    </div>
                    <div class="lc-col">
                        <span class="lc an">"解析值 IP"</span>
                        <input
                            class="lc-filter"
                            data-f="an"
                            aria-label="按解析值筛选"
                            placeholder="筛选 IP…"
                            spellcheck="false"
                            prop:value=move || app.filters.get().an
                            on:input=move |ev| app
                                .filters
                                .update(|f| f.set("an", event_target_value(&ev)))
                        />
                    </div>
                    <div class="lc-col">
                        <span class="lc la">"响应时间"</span>
                        <input
                            class="lc-filter"
                            data-f="la"
                            aria-label="按响应时间（最小 ms）筛选"
                            placeholder="≥ ms…"
                            spellcheck="false"
                            prop:value=move || app.filters.get().la
                            on:input=move |ev| app
                                .filters
                                .update(|f| f.set("la", event_target_value(&ev)))
                        />
                    </div>
                    <div class="lc-col">
                        <span class="lc rl">"规则匹配"</span>
                        <input
                            class="lc-filter"
                            data-f="rl"
                            aria-label="按规则筛选"
                            placeholder="筛选规则…"
                            spellcheck="false"
                            prop:value=move || app.filters.get().rl
                            on:input=move |ev| app
                                .filters
                                .update(|f| f.set("rl", event_target_value(&ev)))
                        />
                    </div>
                </div>
                <div
                    id="console-body"
                    role="log"
                    aria-label="实时查询日志"
                    aria-live="off"
                    on:scroll=move |ev| {
                        if let Some(el) = ev
                            .target()
                            .and_then(|t| t.dyn_into::<HtmlElement>().ok())
                        {
                            let near = el.scroll_height() - el.scroll_top() - el.client_height()
                                < 40;
                            stick.set(near);
                        }
                    }
                >
                    <For each=move || rows.get() key=|r| r.key.clone() children=move |r| row_view(r) />
                    // v2.1.7 空态：区分「加载中 / 认证失败 / 后端不可达 / 真的暂无事件」。
                    {move || {
                        if !rows.get().is_empty() {
                            return ().into_any();
                        }
                        let text = match app.mode.get() {
                            Mode::AuthFailed => {
                                "认证失败 · 请在「配置 → 连接设置」填入 API Token"
                            }
                            Mode::Down => "后端不可达 · 等待重连（每 2s 重试）",
                            Mode::Real => {
                                if app.logs.get().is_empty() {
                                    "暂无数据 · 已连接，等待 DNS 查询流量"
                                } else {
                                    "暂无数据 · 当前筛选条件未命中任何事件"
                                }
                            }
                        };
                        view! { <div class="console-empty">{text}</div> }.into_any()
                    }}
                </div>
            </div>
        </section>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(seq: f64, level: &str) -> LogEvent {
        LogEvent {
            seq,
            level: level.into(),
            domain: "example.com".into(),
            answer: "1.2.3.4".into(),
            ..LogEvent::default()
        }
    }

    /// **2.1.35（wasm panic 修复）**：三种包型的航点数必须 = 段数 + 1，
    /// 且 `pos_at_pts()` 在整段时长内（含最后一段、以及 dur 之后）都不得越界 panic。
    #[test]
    fn packet_path_points_and_segments_are_consistent() {
        let kinds: [(&str, Vec<(f64, f64)>, Vec<f64>); 3] = [
            ("hit", HIT_WP.to_vec(), HIT_SEGS.to_vec()),
            ("err", ERR_WP.to_vec(), ERR_SEGS.to_vec()),
            ("miss", miss_wp(0), MISS_SEGS.to_vec()),
        ];
        for (name, wp, segs) in kinds {
            assert_eq!(wp.len(), segs.len() + 1, "{name}: 航点数必须 = 段数 + 1");
            let dur: f64 = segs.iter().sum();
            let mut t = 0.0;
            while t <= dur + 1.0 {
                let (x, y) = pos_at_pts(&wp, &segs, t);
                assert!(x.is_finite() && y.is_finite(), "{name} t={t} -> ({x},{y})");
                t += 17.0;
            }
            // 段末之后必须停在最后一个航点（回包点）。
            assert_eq!(pos_at_pts(&wp, &segs, dur + 10.0), *wp.last().unwrap());
        }
    }

    /// **2.1.35**：退化输入（段比点多、空路径、零段长）同样不得 panic。
    #[test]
    fn pos_at_degrades_without_panicking() {
        assert_eq!(pos_at_pts(&[], &[], 1.0), P_REPLY);
        let wp = [(0.0, 0.0)];
        assert_eq!(pos_at_pts(&wp, &[10.0, 20.0], 5.0), (0.0, 0.0));
        assert_eq!(pos_at_pts(&wp, &[0.0, 10.0], 5.0), (0.0, 0.0));
    }

    /// D13：key 只由 `seq` 决定，缓冲 `drain` 头部导致下标平移时必须**保持不变**。
    #[test]
    fn key_is_stable_across_buffer_drain() {
        let e = ev(77.0, "hit");
        assert_eq!(row_key(&e, 0), "77");
        assert_eq!(row_key(&e, 12), "77", "下标变化不得改变 key");
        assert_eq!(row_key(&e, 299), "77");
        assert_eq!(row_of(&e, 3, 0.0).key, "77");
    }

    #[test]
    fn keys_are_unique_for_distinct_seqs() {
        let logs: Vec<LogEvent> = (1..=300).map(|n| ev(n as f64, "miss")).collect();
        let keys: Vec<String> = logs
            .iter()
            .enumerate()
            .map(|(i, e)| row_key(e, i))
            .collect();
        let mut sorted = keys.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), keys.len(), "seq 唯一时 key 必须唯一");
    }

    /// 异常兜底：后端未给 `seq` 时不能用同一个 key（否则 Leptos `For` 会错乱）。
    #[test]
    fn missing_seq_falls_back_to_index() {
        let e = ev(0.0, "warn");
        assert_eq!(row_key(&e, 0), "noseq#0");
        assert_eq!(row_key(&e, 5), "noseq#5");
        assert_ne!(row_key(&e, 0), row_key(&e, 5));
        let nan = ev(f64::NAN, "warn");
        assert_eq!(row_key(&nan, 2), "noseq#2");
    }

    /// 本地过滤仍作为二次兜底（与后端下推并存，D15）。
    #[test]
    fn local_filter_matches_columns_and_global_q() {
        let mut e = ev(1.0, "hit");
        e.client_ip = "10.0.0.7".into();
        e.qtype = "A".into();
        e.upstream = "u1".into();
        e.rule = "*.ads".into();
        e.lat = Some(30.0);

        let f = LogFilters {
            dm: "example".into(),
            qt: "a".into(),
            ..LogFilters::default()
        };
        assert!(line_matches_filters(&e, &f, ""));

        // 响应时间：数字 = 最小值
        let f = LogFilters {
            la: "31".into(),
            ..LogFilters::default()
        };
        assert!(!line_matches_filters(&e, &f, ""));
        let f = LogFilters {
            la: "30".into(),
            ..LogFilters::default()
        };
        assert!(line_matches_filters(&e, &f, ""));

        // 命中不了的条件必须过滤掉
        let f = LogFilters {
            ip: "192.168.".into(),
            ..LogFilters::default()
        };
        assert!(!line_matches_filters(&e, &f, ""));

        assert!(line_matches_filters(&e, &LogFilters::default(), "ADS"));
        assert!(!line_matches_filters(&e, &LogFilters::default(), "nope"));
    }
}
