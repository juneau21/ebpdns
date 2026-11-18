//! Query 路由：查询控制台（`data-route="query"`）。
//!
//! DOM 逐行复刻 v1.9.162 `web/index.html` 第 643–688 行；交互对齐同文件
//! `runManualQuery`(2070–2127)、`renderManualResult`(2128–2151)、`renderHistory`(2152–2163)
//! 与按钮绑定(3469–3472)。异步取数走 `api::query` / `api::snapshot`，状态放全局 `App`。

use leptos::prelude::*;

use crate::api;
use crate::fmt;
use crate::model::{ManualEntry, QueryResp, TraceStep};
use crate::state::{history_visible, App, NoteKind};

/// 会话记录保留条数（原件 `renderHistory` 的 `.slice(0, 20)`）。
const HIST_MAX: usize = 20;

/// `#q-steps` 里的一行，对应原件
/// `div.className='q-step '+tag` + `st-time/st-tag/st-txt` 三个 span。
#[derive(Clone, Debug, PartialEq)]
struct TraceRow {
    /// `q-step ` 后的 class（原件的 `s.tag` 原样，不改大小写）。
    cls: String,
    /// `st-tag` 文案（原件 `esc(s.tag).toUpperCase()`）。
    tag: String,
    /// `st-time` 文案（含 `+`/`ms`，原件错误行是字面量 `+0ms`）。
    time: String,
    text: String,
}

/// 每一步的累计耗时（D11）。
///
/// 原件是「追加一步 → 记录 `performance.now()-t0` → sleep 120ms」的动画，因此第 i 步
/// （0 基）显示的是「请求耗时本身 + i×120ms 的渲染延时」；本版一次性渲染终态，若照抄
/// `120 + i*120` 就会**丢掉后端返回的真实 `resp.latency`**。改为按真实总延迟均分：
/// 第 i 步 = `total * (i+1) / n`，于是**最后一步恰好等于真实总延迟**，且序列单调递增。
fn step_times(n: usize, total_ms: f64) -> Vec<f64> {
    if n == 0 {
        return Vec::new();
    }
    let total = if total_ms.is_finite() && total_ms > 0.0 {
        total_ms
    } else {
        0.0
    };
    (1..=n).map(|i| total * (i as f64) / (n as f64)).collect()
}

/// trace 展示用总延迟：优先后端真实 `latency`，缺失/非有限时退回本次请求实测耗时。
fn trace_total_ms(r: &QueryResp, fallback_ms: f64) -> f64 {
    if r.latency.is_finite() && r.latency > 0.0 {
        r.latency
    } else if fallback_ms.is_finite() && fallback_ms > 0.0 {
        fallback_ms
    } else {
        0.0
    }
}

/// 把 `resp.trace` 拍平成 `#q-steps` 行。
fn build_rows(trace: &[TraceStep], total_ms: f64) -> Vec<TraceRow> {
    step_times(trace.len(), total_ms)
        .into_iter()
        .zip(trace.iter())
        .map(|(t, s)| TraceRow {
            cls: s.tag.clone(),
            tag: s.tag.to_uppercase(),
            time: format!("+{t:.1}ms"),
            text: s.text.clone(),
        })
        .collect()
}

/// 读 `#q-domain` 的值（原件 `$('#q-domain').value`）。
fn input_value(id: &str) -> String {
    use wasm_bindgen::JsCast;
    web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.get_element_by_id(id))
        .and_then(|e| e.dyn_into::<web_sys::HtmlInputElement>().ok())
        .map(|i| i.value())
        .unwrap_or_default()
}

/// 读 `#q-type` 的值（原件 `$('#q-type').value`）。
fn select_value(id: &str) -> String {
    use wasm_bindgen::JsCast;
    web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.get_element_by_id(id))
        .and_then(|e| e.dyn_into::<web_sys::HtmlSelectElement>().ok())
        .map(|s| s.value())
        .unwrap_or_default()
}

/// JS `String.length`（UTF-16 码元数），用于复刻原件的域名长度校验。
fn js_len(s: &str) -> usize {
    s.encode_utf16().count()
}

#[component]
pub fn QueryPage() -> impl IntoView {
    let app = expect_context::<App>();

    // `#q-steps` 的内容：None = 初始占位提示；Some = 本次查询的步进列表（可能为空 → 不渲染任何子节点）。
    // 首屏直接读取已有结果（切页回来时 `app.query_out` 仍在），保证「直接渲染」。
    let trace: RwSignal<Option<Vec<TraceRow>>> = RwSignal::new(
        app.query_out
            .get_untracked()
            .map(|r| build_rows(&r.trace, trace_total_ms(&r, 0.0))),
    );

    // 发起解析：点击 `#btn-query` 或 `#q-domain` 回车都走这里（对齐 runManualQuery）。
    let run = move || {
        // 防重入（原件 `_queryBusy`）。
        if app.query_busy.get_untracked() {
            return;
        }
        let domain = input_value("q-domain").trim().to_string();
        if domain.is_empty() {
            return;
        }
        // RFC 1035：总长度 ≤253、单标签 ≤63（原件 2082–2084 的本地校验）。
        if js_len(&domain) > 253 {
            app.note_set("域名过长（最多 253 字符）", NoteKind::Err);
            return;
        }
        if domain.split('.').any(|l| js_len(l) > 63) {
            app.note_set("单个标签过长（最多 63 字符）", NoteKind::Err);
            return;
        }
        let mut qtype = select_value("q-type");
        if qtype.is_empty() {
            qtype = "A".to_string();
        }

        app.query_busy.set(true);
        // 清空 `#q-steps` + `#q-result` 去掉 show + `#q-result-empty` 显示。
        trace.set(Some(Vec::new()));
        app.query_out.set(None);

        let t0 = js_sys::Date::now();
        wasm_bindgen_futures::spawn_local(async move {
            match api::query(&domain, &qtype).await {
                Ok(resp) => {
                    let base = (js_sys::Date::now() - t0).max(0.0);
                    // D11：按后端真实 latency 分配各步累计耗时（缺失时退回实测墙钟耗时）。
                    trace.set(Some(build_rows(&resp.trace, trace_total_ms(&resp, base))));
                    app.query_out.set(Some(resp));
                    app.query_busy.set(false);
                    // 对齐原件 2115 行：查询结束后额外拉一次 snapshot 刷新「会话记录」。
                    // v2.1.7：改走轮询中枢 —— 在途时合并（丢弃重复请求），并计入前端埋点。
                    crate::poll::refresh_snapshot(app);
                }
                Err(e) => {
                    app.query_busy.set(false);
                    // 原件 `_onAuthLost()`：切配置页并提示，不再渲染 ERR 步。
                    if e.is_auth_error {
                        crate::poll::on_auth_lost(app, &e.message);
                        return;
                    }
                    // 原件 2091 行的错误步：`q-step warn` + `+0ms` + `ERR`。
                    trace.set(Some(vec![TraceRow {
                        cls: "warn".into(),
                        tag: "ERR".into(),
                        time: "+0ms".into(),
                        text: format!("后端 API 调用失败：{}", e.message),
                    }]));
                    app.note_set(format!("查询失败：{}", e.message), NoteKind::Err);
                }
            }
        });
    };

    // 清空：清结果与处理链路，并记录「当前可见区间」（D16）。
    //
    // 原件 `#btn-qclear`（index.html:3472）：REAL 模式下后端没有清空 `manual_history`
    // 的端点，于是把当前时刻记为 `hiddenHistoryBefore`，此后只渲染不早于它的记录。
    // 本版按同一语义实现：`ts` 与游标同为定宽 `HH:MM:SS.mmm` 本地时间串，字典序即时序。
    let on_clear = move |_| {
        app.query_out.set(None);
        trace.set(None);
        app.hidden_before.set(fmt::now_ts());
    };

    view! {
        <section class="route active" data-route="query">
            <div class="card">
                <div class="card-bd">
                    <div class="q-row">
                        <input
                            class="q-input"
                            id="q-domain"
                            type="text"
                            aria-label="待解析域名"
                            placeholder="输入域名，例如 www.baidu.com"
                            spellcheck="false"
                            autocomplete="off"
                            on:keydown=move |ev: web_sys::KeyboardEvent| {
                                if ev.key() == "Enter" {
                                    run();
                                }
                            }
                        />
                        <select class="q-sel" id="q-type" aria-label="查询类型">
                            <option value="A">"A (IPv4)"</option>
                            <option value="AAAA">"AAAA (IPv6)"</option>
                            <option value="MX">"MX"</option>
                            <option value="TXT">"TXT"</option>
                            <option value="NS">"NS"</option>
                            <option value="CNAME">"CNAME"</option>
                            <option value="SOA">"SOA"</option>
                        </select>
                        <button
                            class="btn primary"
                            id="btn-query"
                            class:busy=move || app.query_busy.get()
                            aria-label="发起解析"
                            disabled=move || app.query_busy.get()
                            on:click=move |_| run()
                        >
                            <svg
                                viewBox="0 0 24 24"
                                fill="none"
                                stroke="currentColor"
                                stroke-width="2.2"
                                stroke-linecap="round"
                                stroke-linejoin="round"
                            >
                                <path d="M3 12h18M14 6l6 6-6 6"></path>
                            </svg>
                            {move || {
                                if app.query_busy.get() { "查询中…" } else { "发起解析" }
                            }}
                        </button>
                        <button class="btn" id="btn-qclear" on:click=on_clear>
                            <svg
                                viewBox="0 0 24 24"
                                fill="none"
                                stroke="currentColor"
                                stroke-width="2"
                                stroke-linecap="round"
                                stroke-linejoin="round"
                            >
                                <path d="M4 7h16M9 7V5h6v2M6 7l1 13h10l1-13"></path>
                            </svg>
                            "清空"
                        </button>
                    </div>
                    <div class="hint" id="query-hint">
                        "手动解析会真实经过用户态缓存 / 多上游 / 测速择优 / 缓存回填全链路（手动查询不计入总量、命中率、QPS 等遥测口径，只推进延迟窗口；这是因为它走控制面 /api/query，不是数据面出口）。"
                    </div>
                </div>
            </div>
            <div class="q-grid">
                <div class="card">
                    <div class="card-hd">
                        <span class="t">"处理链路"</span>
                        <span class="s">"query trace"</span>
                    </div>
                    <div class="q-steps" id="q-steps">
                        {move || match trace.get() {
                            None => {
                                view! {
                                    <div class="empty">
                                        "暂无数据 · 输入域名并点击「发起解析」，查看每一步处理过程。"
                                    </div>
                                }
                                    .into_any()
                            }
                            Some(rows) => {
                                rows
                                    .into_iter()
                                    .map(|r| {
                                        view! {
                                            <div class=format!("q-step {}", r.cls)>
                                                <span class="st-time">{r.time}</span>
                                                <span class="st-tag">{r.tag}</span>
                                                <span class="st-txt">{r.text}</span>
                                            </div>
                                        }
                                    })
                                    .collect_view()
                                    .into_any()
                            }
                        }}
                    </div>
                </div>
                <div class="card">
                    <div class="card-hd">
                        <span class="t">"解析结果"</span>
                        <span class="s">"answer"</span>
                    </div>
                    <div class="card-bd">
                        <div
                            class="q-result"
                            id="q-result"
                            class:show=move || app.query_out.get().is_some()
                        >
                            {move || app.query_out.get().map(result_view)}
                        </div>
                        <div
                            class="empty"
                            id="q-result-empty"
                            style:display=move || {
                                // 对齐原件：`#q-result-empty` 用 `style.display = none/block` 显隐。
                                if app.query_out.get().is_some() {
                                    "none".to_string()
                                } else {
                                    "block".to_string()
                                }
                            }
                        >
                            "暂无数据 · 发起解析后在此显示结果。"
                        </div>
                    </div>
                </div>
            </div>
            <div class="card">
                <div class="card-hd">
                    <span class="t">"会话记录"</span>
                    <span class="s">"recent queries"</span>
                </div>
                <div class="q-history" id="q-history">
                    {move || {
                        // D16：套用「清空」区间过滤（原件 pollSnapshot / runManualQuery 里
                        // 的 `filter(e => !(hiddenHistoryBefore && e.ts && e.ts < hidden))`）。
                        let hidden = app.hidden_before.get();
                        let mut list: Vec<ManualEntry> = app
                            .snapshot_or_default()
                            .manual_history
                            .into_iter()
                            .filter(|e| history_visible(&e.ts, &hidden))
                            .collect();
                        // 原件 renderHistory：`list.slice().reverse().slice(0, 20)` —— 最近在前、上限 20。
                        list.reverse();
                        list.truncate(HIST_MAX);
                        if list.is_empty() {
                            return view! {
                                <div class="empty">"暂无数据 · 尚未发起过手动查询。"</div>
                            }
                                .into_any();
                        }
                        view! {
                            <table class="tbl">
                                <thead>
                                    <tr>
                                        <th>"时间"</th>
                                        <th>"域名"</th>
                                        <th>"类型"</th>
                                        <th>"结果"</th>
                                        <th>"耗时"</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {list
                                        .into_iter()
                                        .map(|e| {
                                            let ManualEntry { ts, domain, qtype, answer, lat, .. } = e;
                                            let ts: String = ts.chars().take(8).collect();
                                            // v2.1.7：延迟自适应单位；超长域名/解析值截断 + title 提示。
                                            let lat_cell = match lat {
                                                Some(v) if v.is_finite() => {
                                                    let (t, u) = fmt::lat_auto(v);
                                                    if u.is_empty() {
                                                        t
                                                    } else {
                                                        format!("{t} {u}")
                                                    }
                                                }
                                                _ => "–".to_string(),
                                            };
                                            let d_show = fmt::trunc(&domain, 40);
                                            let a_show = fmt::trunc(&answer, 40);
                                            view! {
                                                <tr class="row-in">
                                                    <td class="mono">{ts}</td>
                                                    <td class="ip trunc" title=domain.clone()>{d_show}</td>
                                                    <td class="mono">{qtype}</td>
                                                    <td class="mono trunc" title=answer.clone()>{a_show}</td>
                                                    <td class="num">{lat_cell}</td>
                                                </tr>
                                            }
                                        })
                                        .collect_view()}
                                </tbody>
                            </table>
                        }
                            .into_any()
                    }}
                </div>
            </div>
        </section>
    }
}

/// **2.1.43-B（P2-1）**：TTL 文案 —— **缺失必须显示 `TTL –`**，绝不渲染 `TTL 0 s`。
///
/// 旧实现 `ttl_left.or(ttl).unwrap_or(0.0)` 把"后端没给 TTL"（包括旧 `from_value(...)
/// .unwrap_or_default()` 降级出来的全 0 模型）显示成 `TTL 0 s` —— 与"TTL 真的到期"
/// 不可区分，查询页会给出"未命中 · TTL 0 s"的**假结论**。
///
/// 现在：`Some(v)`（含**真 0**）照实显示；`None` ⇒ `TTL –`（未采集/不适用）。
fn ttl_suffix(ttl: Option<f64>) -> String {
    match ttl {
        Some(v) if v.is_finite() && v >= 0.0 => {
            format!(" · TTL {} s", fmt::group0(fmt::n(v)))
        }
        _ => " · TTL –".to_string(),
    }
}

/// `renderManualResult`：结果卡片（`res-head` + 表格或失败提示）。
fn result_view(r: QueryResp) -> impl IntoView {
    let QueryResp {
        domain,
        qtype,
        hit,
        error,
        reason,
        latency,
        ttl_left,
        ttl,
        answers,
        ..
    } = r;

    let tag = if error {
        "err"
    } else if hit {
        "hit"
    } else {
        "miss"
    };
    let tag_txt = if error {
        "SERVFAIL"
    } else if hit {
        "缓存命中 · 缓存直答"
    } else {
        "未命中 · 用户态解析"
    };
    // 原件：`isFinite(latency) ? latency.toFixed(2) : '0.00'`。
    // v2.1.7：按自适应单位显示（<1ms 用 µs，≥1000ms 用 s），并保留两位小数量级。
    // 2.1.37：全站唯一延迟口径（fmt::lat_auto），不再各处自写一套 µs/ms/s。
    let (lat_num, lat_unit) = fmt::lat_auto(fmt::n(latency));
    // **2.1.43-B（P2-1）**：TTL 缺失 ⇒ `TTL –`（**不是** `TTL 0 s`）。原件写法是
    // `Number(ttl_left ?? ttl ?? 0)`，把"没给"与"真的是 0"混成同一个显示。
    let ttl_txt = ttl_suffix(ttl_left.or(ttl));

    let domain_title = domain.clone();
    let head = view! {
        <div class="res-head">
            <span class="domain" title=domain_title>{fmt::trunc(&domain, 60)}</span>
            <span class="rtype">{qtype}</span>
            <span class=format!("res-tag {tag}")>{tag_txt}</span>
            <span class="lat">{format!("{lat_num} {lat_unit}{ttl_txt}")}</span>
        </div>
    };

    if error {
        let reason = reason.unwrap_or_default();
        return view! {
            {head}
            <div class="hint">
                {format!(
                    "解析失败：{reason}。可检查上游是否启用、分流规则是否屏蔽、或网络是否可达。",
                )}
            </div>
        }
        .into_any();
    }

    view! {
        {head}
        <table class="tbl">
            <thead>
                <tr>
                    <th>"地址"</th>
                    <th>"来源上游"</th>
                    <th>"TTL"</th>
                </tr>
            </thead>
            <tbody>
                {answers
                    .into_iter()
                    .enumerate()
                    .map(|(i, a)| {
                        // v2.1.7：超长值截断 + title 提示；TTL 右对齐等宽。
                        let val = a.value.clone();
                        let src = a.from.clone();
                        let v_show = fmt::trunc(&val, 60);
                        let s_show = fmt::trunc(&src, 40);
                        view! {
                            <tr class:choosed=move || i == 0>
                                <td class="ip trunc" title=val.clone()>{v_show}</td>
                                <td class="trunc" title=src.clone()>{s_show}</td>
                                <td class="num">{format!("{} s", fmt::group0(a.ttl))}</td>
                            </tr>
                        }
                    })
                    .collect_view()}
            </tbody>
        </table>
    }
    .into_any()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(tag: &str, text: &str) -> TraceStep {
        TraceStep {
            tag: tag.into(),
            text: text.into(),
        }
    }

    /// D11：最后一步必须等于真实总延迟（旧实现恒为 `120 + i*120`）。
    #[test]
    fn last_step_equals_real_latency() {
        let t = step_times(4, 33.0);
        assert_eq!(t.len(), 4);
        assert_eq!(t[3], 33.0);
        assert!((t[0] - 8.25).abs() < 1e-9, "got {}", t[0]);
        // 单调递增
        for w in t.windows(2) {
            assert!(w[1] > w[0]);
        }
    }

    #[test]
    fn single_step_is_the_total() {
        assert_eq!(step_times(1, 12.5), vec![12.5]);
    }

    #[test]
    fn step_times_edge_cases() {
        assert!(step_times(0, 100.0).is_empty());
        // 非有限/非正总延迟 → 全 0（不伪造 120ms 步进）
        assert_eq!(step_times(3, f64::NAN), vec![0.0, 0.0, 0.0]);
        assert_eq!(step_times(3, -5.0), vec![0.0, 0.0, 0.0]);
        assert_eq!(step_times(2, f64::INFINITY), vec![0.0, 0.0]);
    }

    #[test]
    fn build_rows_uses_total_and_keeps_tags() {
        let trace = vec![step("cache", "miss"), step("upstream", "u1 ok")];
        let rows = build_rows(&trace, 40.0);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].cls, "cache");
        assert_eq!(rows[0].tag, "CACHE");
        assert_eq!(rows[0].time, "+20.0ms");
        assert_eq!(rows[1].time, "+40.0ms");
        assert_eq!(rows[1].text, "u1 ok");
    }

    #[test]
    fn trace_total_prefers_backend_latency() {
        let mut r = QueryResp {
            latency: 18.0,
            ..QueryResp::default()
        };
        assert_eq!(trace_total_ms(&r, 999.0), 18.0);
        // latency 缺失/非有限 → 退回实测耗时
        r.latency = 0.0;
        assert_eq!(trace_total_ms(&r, 999.0), 999.0);
        r.latency = f64::NAN;
        assert_eq!(trace_total_ms(&r, 999.0), 999.0);
        // 两者都无效 → 0（页面显示 +0.0ms，不伪造延时）
        assert_eq!(trace_total_ms(&r, 0.0), 0.0);
    }

    /// **2.1.43-B（P2-1）回归**：TTL **缺失**不得渲染成 `TTL 0 s`
    /// （旧实现 `ttl_left.or(ttl).unwrap_or(0.0)` 会，让"解析失败降级"看起来像"到期"）。
    #[test]
    fn ttl_suffix_distinguishes_missing_from_real_zero() {
        assert_eq!(ttl_suffix(None), " · TTL –", "缺失必须是 `–`，不是 0");
        // 真实 0（缓存即将过期）照实显示：这是"真 0"，不是"没采集到"。
        assert_eq!(ttl_suffix(Some(0.0)), " · TTL 0 s");
        assert_eq!(ttl_suffix(Some(300.0)), " · TTL 300 s");
        // 非有限值按缺失处理（不渲染 NaN/inf）。
        assert_eq!(ttl_suffix(Some(f64::NAN)), " · TTL –");
        assert_eq!(ttl_suffix(Some(f64::INFINITY)), " · TTL –");
        assert_eq!(ttl_suffix(Some(-1.0)), " · TTL –");
        assert!(
            !ttl_suffix(None).contains("TTL 0"),
            "缺失绝不能渲染 `TTL 0 s`（旧缺陷）"
        );
    }
}
