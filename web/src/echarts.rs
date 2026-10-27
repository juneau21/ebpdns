//! ECharts（同源 `echarts.min.js`）互操作 + option 构造（v2.1.7 显示效果优化）。
//!
//! 原前端直接以 JS 字面量构造 option；这里用 serde_json 构造等价结构，
//! 再经 `setOption` 下发。函数型 formatter 一律换成 ECharts 模板串（`{b}/{c}/{d}`）。
//!
//! v2.1.7 相对 2.1.6 的图表改动：
//! - **减少重绘**：`setOption(opt, notMerge, lazyUpdate=true)` —— 同一 tick 内 5 张图的
//!   更新被 ECharts 合并到同一帧渲染；首次绘制 `notMerge=true`，之后 `notMerge=false`
//!   走 diff + 过渡动画（不再整图重建）。
//! - **过渡动画**：300ms 全局 / 260ms 更新，`cubicOut`；数据更新是插值而非跳变。
//! - **tooltip 明确单位**：命中率 `%`、吞吐 `QPS`、延迟 `ms`、上游 `ms`，
//!   并把轴指示线样式与主题统一。
//! - **坐标轴**：`hideOverlap`（刻度不重叠）、`splitNumber`、qps/lat 轴 `minInterval:0`，
//!   `grid.containLabel` 防标签被裁；`axisLabel` 用等宽字体与主题色一致。
//! - **自适应容器**：`resize_if_visible` 跳过零尺寸（隐藏页/未布局）容器，
//!   避免 `resize()` 把画布压成 0×0。
use serde_json::{json, Value};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

/// 等宽字体栈（ECharts 画布不吃 CSS 变量，必须给真实字体族）。
const MONO: &str = "JetBrains Mono, ui-monospace, Consolas, monospace";

/// 取全局 `echarts`（未加载 → None）。
fn echarts_global() -> Option<JsValue> {
    let win = web_sys::window()?;
    let g = js_sys::Reflect::get(&win, &JsValue::from_str("echarts")).ok()?;
    if g.is_undefined() || g.is_null() {
        None
    } else {
        Some(g)
    }
}

/// 图表库是否可用。
pub fn available() -> bool {
    echarts_global().is_some()
}

/// `echarts.init(document.getElementById(id))`。
pub fn init(id: &str) -> Option<JsValue> {
    let el = web_sys::window()?.document()?.get_element_by_id(id)?;
    let g = echarts_global()?;
    let f = js_sys::Reflect::get(&g, &JsValue::from_str("init")).ok()?;
    let f: js_sys::Function = f.dyn_into().ok()?;
    f.call1(&g, &el).ok()
}

/// 在容器上写入提示文本（图表库缺失时的兜底，对齐 initCharts）。
pub fn set_text(id: &str, text: &str) {
    if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
        if let Some(el) = doc.get_element_by_id(id) {
            el.set_text_content(Some(text));
        }
    }
}

fn call1_on(obj: &JsValue, name: &str) {
    if let Ok(f) = js_sys::Reflect::get(obj, &JsValue::from_str(name)) {
        if let Ok(f) = f.dyn_into::<js_sys::Function>() {
            let _ = f.call0(obj);
        }
    }
}

/// `chart.setOption(opt, notMerge, lazyUpdate)`
///
/// - `replace=true`：首次绘制（`notMerge=true`，整图重建一次）；
/// - `replace=false`：后续更新走 diff + 过渡动画；
/// - `lazyUpdate=true`：把同一 tick 内多次 `setOption` 合并到同一帧渲染（减少重绘）。
pub fn set_option(chart: &JsValue, opt: &Value, replace: bool) {
    let Ok(f) = js_sys::Reflect::get(chart, &JsValue::from_str("setOption")) else {
        return;
    };
    let Ok(f) = f.dyn_into::<js_sys::Function>() else {
        return;
    };
    let Ok(js) = js_sys::JSON::parse(&opt.to_string()) else {
        return;
    };
    let _ = f.call3(chart, &js, &JsValue::from_bool(replace), &JsValue::TRUE);
}

/// `chart.resize()`（零尺寸容器跳过：隐藏页/未布局时 resize 会把画布压成 0×0）。
pub fn resize_if_visible(id: &str, chart: &JsValue) {
    let visible = web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.get_element_by_id(id))
        .map(|el| el.client_width() > 0)
        .unwrap_or(false);
    if visible {
        call1_on(chart, "resize");
    }
}

/// `chart.dispose()`
pub fn dispose(chart: &JsValue) {
    call1_on(chart, "dispose");
}

/// 全局动画（克制：300ms 首绘 / 260ms 更新，`cubicOut`）。
fn anim() -> Value {
    json!({
        "animation": true,
        "animationDuration": 300,
        "animationDurationUpdate": 260,
        "animationEasing": "cubicOut",
        "animationEasingUpdate": "cubicOut"
    })
}

/// 把 `extra` 的键合并进 `anim()` 基础配置（浅合并，二者都是对象）。
fn with_base(extra: Value) -> Value {
    let mut a = anim();
    if let (Value::Object(am), Value::Object(bm)) = (&mut a, extra) {
        for (k, v) in bm {
            am.insert(k, v);
        }
    }
    a
}

fn base_tooltip(trigger: &str, formatter: &str) -> Value {
    json!({
        "trigger": trigger,
        "confine": true,
        "formatter": formatter,
        "backgroundColor": "#0d141e",
        "borderColor": "#2a3b4f",
        "borderWidth": 1,
        "textStyle": { "color": "#e6eef6", "fontSize": 11, "fontFamily": MONO },
        "padding": [8, 10],
        "axisPointer": { "type": "line",
                         "lineStyle": { "color": "#2a3b4f", "width": 1 },
                         "label": { "backgroundColor": "#16212f", "color": "#93a2b3", "fontSize": 10 } }
    })
}

fn base_axis() -> Value {
    json!({
        "axisLine": { "lineStyle": { "color": "#2a3b4f" } },
        "axisTick": { "show": false },
        "axisLabel": { "color": "#5e6f82", "fontSize": 10, "hideOverlap": true, "fontFamily": MONO },
        "splitLine": { "lineStyle": { "color": "#141e2c" } }
    })
}

fn axis_small() -> Value {
    let mut a = base_axis();
    a["axisLabel"]["fontSize"] = json!(9);
    a
}

/// 折线图公共骨架（命中率 / 吞吐 / 延迟三张折线共用）。
fn line_opt(
    labels: &[String],
    data: &[f64],
    color: &'static str,
    y_formatter: Option<&'static str>,
    tooltip: &str,
    extra_y: Value,
) -> Value {
    let ax = axis_small();
    let mut y = base_axis();
    if let Some(f) = y_formatter {
        y["axisLabel"]["formatter"] = json!(f);
    }
    let mut y_axis = json!({
        "type": "value",
        "splitNumber": 4,
        "axisLine": y["axisLine"],
        "axisTick": y["axisTick"],
        "axisLabel": y["axisLabel"],
        "splitLine": y["splitLine"]
    });
    if let (Value::Object(m), Value::Object(e)) = (&mut y_axis, extra_y) {
        for (k, v) in e {
            m.insert(k, v);
        }
    }
    with_base(json!({
        "grid": { "left": 42, "right": 16, "top": 20, "bottom": 24, "containLabel": true },
        "xAxis": { "type": "category", "data": labels, "boundaryGap": false,
                   "axisLine": ax["axisLine"], "axisTick": ax["axisTick"],
                   "axisLabel": ax["axisLabel"], "splitLine": ax["splitLine"] },
        "yAxis": y_axis,
        "series": [{ "type": "line", "data": data, "smooth": true, "symbol": "none",
                     "sampling": "lttb", "showSymbol": false,
                     "lineStyle": { "color": color, "width": 2 },
                     "areaStyle": { "color": color, "opacity": 0.08 } }],
        "tooltip": base_tooltip("axis", tooltip)
    }))
}

/// `chartHitOpt` —— 缓存命中率折线（0-100%）。
///
/// **口径断言（注释级，勿改）**：`data` 必须已经是 **0..100 的百分数**，本函数
/// **不得**再乘 100，`yAxis` 固定 `min:0 / max:100`、刻度带 `%`。
/// 依据：`/api/snapshot.history[].hit_rate` 由后端 `telemetry.rs:468` 的
/// `hit_rate_pct()` 乘过 100（`(hit_rate*100*10).round()/10`，与 v1.9.162 一致），
/// `pages/telemetry.rs` 也按此口径直接取值。
///
/// **v2.1.7 更正**：`/api/status.hit_rate` 同样是 **0..100 百分数**
/// （`ebpdns-server/src/api.rs:561` 用同一个 `hit_rate_pct()`），顶栏此前误乘 100
/// 会显示成 `6950.0%`；现已改为直接 `pct1(hit_rate)`（见 `main.rs` 顶栏）。
pub fn hit_opt(labels: &[String], data: &[f64]) -> Value {
    line_opt(
        labels,
        data,
        "#2ee6c8",
        Some("{value}%"),
        "{b}<br/>命中率 <b>{c}%</b>",
        json!({ "min": 0, "max": 100 }),
    )
}

/// `chartQpsOpt` —— 吞吐折线（QPS）。
pub fn qps_opt(labels: &[String], data: &[f64]) -> Value {
    line_opt(
        labels,
        data,
        "#5b8def",
        None,
        "{b}<br/>吞吐 <b>{c} QPS</b>",
        json!({ "min": 0, "minInterval": 0 }),
    )
}

/// `chartLatOpt` —— 平均延迟折线（ms）。
pub fn lat_opt(labels: &[String], data: &[f64]) -> Value {
    line_opt(
        labels,
        data,
        "#ffb454",
        Some("{value}ms"),
        "{b}<br/>平均延迟 <b>{c} ms</b>",
        json!({ "min": 0, "minInterval": 0 }),
    )
}

/// `chartQtypesOpt` —— 查询类型分布环形图。
pub fn qtypes_opt(a: f64, aaaa: f64, other: f64) -> Value {
    with_base(json!({
        "tooltip": base_tooltip("item", "{b}: <b>{c}</b> 次 ({d}%)"),
        "legend": { "orient": "vertical", "right": 4, "top": "middle",
                    "textStyle": { "color": "#b8c6d6", "fontSize": 12, "fontFamily": MONO },
                    "itemWidth": 14, "itemHeight": 10, "itemGap": 16 },
        "series": [{
            "type": "pie",
            "radius": ["42%", "72%"],
            "center": ["37%", "48%"],
            "color": ["#2ee6c8", "#5b8def", "#ffb454"],
            "avoidLabelOverlap": true,
            "label": { "show": true, "formatter": "{b}\n{c} ({d}%)", "color": "#e6eef6",
                       "fontSize": 11, "lineHeight": 17, "fontFamily": MONO },
            "labelLine": { "length": 16, "length2": 12, "lineStyle": { "color": "#2a3b4f" } },
            "data": [
                { "name": "A", "value": a },
                { "name": "AAAA", "value": aaaa },
                { "name": "其他", "value": other }
            ]
        }]
    }))
}

/// 上游延迟横条的一项。
pub struct UpBar {
    pub label: String,
    pub avg: f64,
    pub color: &'static str,
}

/// `chartUpOpt` —— 上游平均延迟横向条形图（**历史入口**）。
///
/// **2.1.19**：生产路径改用 [`up_opt_msg`]（空态文案由 `telemetry.rs::up_empty_msg`
/// 按"没配上游 / 还没延迟样本"判定后传入），本函数只剩**单测**在用 ⇒
/// 加 `#[cfg(test)]`，避免 wasm 构建出现 `function up_opt is never used`
/// 的自有代码告警（门禁要求自有代码 0 warning）。
#[cfg(test)]
pub fn up_opt(bars: &[UpBar]) -> Value {
    up_opt_msg(bars, "暂无上游延迟数据")
}

/// **2.1.18（修复项 8）**：`up_opt` 的可定制空态文案版本。
///
/// 为什么需要：空态有两种完全不同的成因（没配上游 vs 有上游但还没延迟样本），
/// 文案由调用方（`telemetry.rs::up_empty_msg`）判定后传入，避免把
/// "刚起来还没测到"显示成"上游丢了"。`bars` 非空时 `empty_msg` **被忽略**
/// （`title.show=false`），因此调用方可以无条件传。
pub fn up_opt_msg(bars: &[UpBar], empty_msg: &str) -> Value {
    let names: Vec<String> = bars.iter().map(|b| b.label.clone()).collect();
    let data: Vec<Value> = bars
        .iter()
        .map(|b| json!({ "value": (b.avg * 10.0).round() / 10.0, "itemStyle": { "color": b.color } }))
        .collect();
    let mut y = base_axis();
    // v2.1.7 修复：这里原先写死 `width: 110, overflow: "truncate"`，把上游地址（DNS/DoH 域名
    // 或 IP:端口）按 110px 硬截断成 `cloudflare-d.…`；而 `containLabel:true` 其实已经按标签
    // 实测宽度预留了空间（实测 155.4px > 110px，即"有地方放却被强行省略"）。去掉宽度上限，
    // 让地址按原始文本完整渲染（标签区仍由 containLabel 自适应，不会压到绘图区）。
    y["axisLabel"] = json!({ "color": "#b8c6d6", "fontSize": 12,
                             "hideOverlap": false, "fontFamily": MONO });
    let mut x = base_axis();
    x["axisLabel"] = json!({ "color": "#5e6f82", "fontSize": 11, "formatter": "{value} ms",
                             "hideOverlap": true, "fontFamily": MONO });
    let mut opt = with_base(json!({
        "grid": { "left": 118, "right": 56, "top": 18, "bottom": 26, "containLabel": true },
        "xAxis": { "type": "value", "min": 0, "minInterval": 0, "axisLine": x["axisLine"],
                   "axisTick": x["axisTick"], "axisLabel": x["axisLabel"], "splitLine": x["splitLine"] },
        "yAxis": { "type": "category", "data": names, "axisLine": y["axisLine"],
                   "axisTick": y["axisTick"], "axisLabel": y["axisLabel"], "splitLine": y["splitLine"] },
        "series": [{ "type": "bar", "data": data, "barWidth": 10, "barCategoryGap": "82%",
                     "label": { "show": true, "position": "right", "color": "#93a2b3",
                                "fontSize": 11, "formatter": "{c} ms", "fontFamily": MONO } }],
        "tooltip": base_tooltip("item", "{b}<br/>平均延迟 <b>{c} ms</b>")
    }));
    // v2.1.8：一条可画的上游都没有时（全部被禁用且从未查询），在画布中央写一句提示，
    // 而不是把一张空坐标轴留在卡片里（用户会读成"卡片坏了"）。
    // 注意：后续更新走 `notMerge=false` 的**合并**语义，所以 title 组件必须**每次都下发**
    // （空态 `show:true`，有数据 `show:false`），否则第一次空态的提示文字会一直留在画布上
    // 盖住后面的条形（实测：合并后 `title[0].text` 仍是提示文案）。
    let empty = bars.is_empty();
    opt["title"] = json!({
        "show": empty,
        "text": if empty { empty_msg } else { "" },
        "left": "center", "top": "middle",
        "textStyle": { "color": "#5e6f82", "fontSize": 12, "fontFamily": MONO }
    });
    opt
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 命中率折线：yAxis 固定 0..100，且**不对入参再做一次 ×100**
    /// （后端已是百分数，重复乘会让 99.9% 变成 9990）。
    #[test]
    fn hit_opt_keeps_percent_scale() {
        let opt = hit_opt(&["12:00:00".to_string()], &[42.5]);
        assert_eq!(opt["yAxis"]["max"], json!(100));
        assert_eq!(opt["yAxis"]["min"], json!(0));
        assert_eq!(opt["yAxis"]["axisLabel"]["formatter"], json!("{value}%"));
        assert_eq!(opt["series"][0]["data"][0], json!(42.5));
        assert_eq!(opt["xAxis"]["data"][0], json!("12:00:00"));
    }

    #[test]
    fn hit_opt_accepts_full_range_samples() {
        let labels: Vec<String> = (0..3).map(|i| format!("t{i}")).collect();
        let opt = hit_opt(&labels, &[0.0, 55.5, 100.0]);
        assert_eq!(opt["series"][0]["data"][0], json!(0.0));
        assert_eq!(opt["series"][0]["data"][2], json!(100.0));
    }

    #[test]
    fn other_options_build_expected_shapes() {
        let labels = vec!["a".to_string()];
        assert_eq!(qps_opt(&labels, &[3.0])["series"][0]["data"][0], json!(3.0));
        assert_eq!(
            lat_opt(&labels, &[1.5])["yAxis"]["axisLabel"]["formatter"],
            json!("{value}ms")
        );
        let pie = qtypes_opt(1.0, 2.0, 3.0);
        assert_eq!(pie["series"][0]["data"][1]["name"], json!("AAAA"));
        let bars = vec![UpBar {
            label: "上游 1".into(),
            avg: 12.34,
            color: "var(--cyan)",
        }];
        let up = up_opt(&bars);
        assert_eq!(up["yAxis"]["data"][0], json!("上游 1"));
        // 一位小数四舍五入（Math.round(v*10)/10 语义）
        assert_eq!(up["series"][0]["data"][0]["value"], json!(12.3));
    }

    /// v2.1.7：图表配置必须带过渡动画与「带单位」的 tooltip。
    #[test]
    fn options_carry_animation_and_units() {
        let labels = vec!["a".to_string()];
        let hit = hit_opt(&labels, &[50.0]);
        assert_eq!(hit["animation"], json!(true));
        assert_eq!(hit["animationDurationUpdate"], json!(260));
        assert!(hit["tooltip"]["formatter"].as_str().unwrap().contains('%'));
        let qps = qps_opt(&labels, &[1.0]);
        assert!(qps["tooltip"]["formatter"]
            .as_str()
            .unwrap()
            .contains("QPS"));
        assert_eq!(qps["yAxis"]["minInterval"], json!(0));
        let lat = lat_opt(&labels, &[1.0]);
        assert!(lat["tooltip"]["formatter"].as_str().unwrap().contains("ms"));
        assert_eq!(lat["xAxis"]["axisLabel"]["hideOverlap"], json!(true));
        let up = up_opt(&[UpBar {
            label: "u".into(),
            avg: 1.0,
            color: "#fff",
        }]);
        assert!(up["tooltip"]["formatter"].as_str().unwrap().contains("ms"));
        assert_eq!(qtypes_opt(1.0, 1.0, 1.0)["animation"], json!(true));
    }

    /// v2.1.7 回归：上游横条的 y 轴地址标签**不得**再带固定宽度 + `truncate`
    /// —— 否则 `cloudflare-dns.com:443` 会被截成 `cloudflare-d.…`（浏览器实测：
    /// `grid.containLabel` 已为标签预留 155.4px，而 `width:110` 把它强行省略）。
    #[test]
    fn up_axis_label_is_not_width_truncated() {
        let up = up_opt(&[UpBar {
            label: "cloudflare-dns.com:443".into(),
            avg: 12.0,
            color: "#fff",
        }]);
        let al = &up["yAxis"]["axisLabel"];
        assert_eq!(al["width"], json!(null), "y 轴标签不得写死宽度");
        assert_eq!(
            al["overflow"],
            json!(null),
            "y 轴标签不得使用 truncate/省略"
        );
        assert_eq!(up["yAxis"]["data"][0], json!("cloudflare-dns.com:443"));
        // 单位统一：轴/条尾标签都用 "ms" 且带空格，与 DOM 明细的 `78.3 ms` 形态一致
        assert_eq!(up["xAxis"]["axisLabel"]["formatter"], json!("{value} ms"));
        assert_eq!(up["series"][0]["label"]["formatter"], json!("{c} ms"));
    }

    /// v2.1.8：没有可画的上游时给画布内提示（避免"卡片坏了"的观感）；
    /// 有数据时同一组件必须 `show:false`——更新是合并语义，只在空态下发 title
    /// 会让提示文字一直盖在条形上。
    #[test]
    fn up_opt_empty_state_has_centered_hint() {
        let empty = up_opt(&[]);
        assert_eq!(empty["series"][0]["data"].as_array().unwrap().len(), 0);
        assert_eq!(empty["title"]["show"], json!(true));
        assert_eq!(empty["title"]["text"], json!("暂无上游延迟数据"));
        assert_eq!(empty["title"]["left"], json!("center"));
        let one = up_opt(&[UpBar {
            label: "dns.alidns.com:443".into(),
            avg: 1.0,
            color: "#fff",
        }]);
        assert_eq!(
            one["title"]["show"],
            json!(false),
            "有数据时必须关掉空态提示"
        );
        assert_eq!(one["title"]["text"], json!(""));
        assert_eq!(one["series"][0]["data"].as_array().unwrap().len(), 1);
    }

    /// **2.1.18（修复项 8）**：空态文案可由调用方定制（区分"没配上游"与
    /// "有上游但还没延迟样本"），且**有数据时定制文案也必须被忽略**。
    #[test]
    fn up_opt_msg_uses_custom_empty_text_only_when_empty() {
        let empty = up_opt_msg(&[], "暂无延迟样本（等待上游流量）");
        assert_eq!(empty["title"]["show"], json!(true));
        assert_eq!(
            empty["title"]["text"],
            json!("暂无延迟样本（等待上游流量）")
        );
        // 有数据：定制文案不得残留（合并语义下会盖住条形）。
        let one = up_opt_msg(
            &[UpBar {
                label: "udp://1.1.1.1:53".into(),
                avg: 2.0,
                color: "#fff",
            }],
            "暂无延迟样本（等待上游流量）",
        );
        assert_eq!(one["title"]["show"], json!(false));
        assert_eq!(one["title"]["text"], json!(""));
        // 兼容包装：`up_opt` 的默认文案不回归。
        assert_eq!(up_opt(&[])["title"]["text"], json!("暂无上游延迟数据"));
    }
}
