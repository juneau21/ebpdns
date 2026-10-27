//! Config 路由：逐页复刻 v1.9.162 `web/index.html` 第 690–965 行（六张配置卡 + 连接设置
//! + 底部操作卡）。
//!
//! 设计要点（对齐 1.9.162 `renderConfig` / `bindConfigEvents`）：
//! - 标量表单控件是**非受控**的：初值来自 `app.config`，只在 `cfg_epoch` 变化（服务器配置
//!   刷新）时整体重建，避免打字时焦点/光标被信号覆盖；保存时逐项从 DOM 读回。
//! - 上游 / 逐条规则 / 订阅三个列表是**本地暂存**（`RwSignal<Vec<Value>>`），随「应用配置」
//!   一起 `PUT /api/config` 下发；行内编辑照抄原件的 change 语义。
//! - 上游完整地址解析（`parseUpstreamAddr`）与「一键重测速」「订阅」等流程逐行对齐原件。

use crate::api;
use crate::fmt;
use crate::state::{App, NoteKind};
use leptos::prelude::*;
use serde_json::{json, Map, Value};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

/* ============================== 常量与映射 ============================== */

/// 逐条规则列表最多渲染条数（对齐原件 `RULE_RENDER_LIMIT`）。
const RULE_RENDER_LIMIT: usize = 500;
/// 上游协议下拉顺序（对齐原件 `['udp','tcp','doh','dot','doq','doh3']`）。
const PROTO_ORDER: [&str; 6] = ["udp", "tcp", "doh", "dot", "doq", "doh3"];
/// 端口下拉候选（对齐原件 `portOpts`）。
const PORT_OPTS: [i64; 5] = [53, 443, 853, 1053, 5353];
/// **2.1.18（修复项 7）**：**只读 / 服务端管理**的配置键（后端 `api.rs::CFG_READONLY`）。
///
/// 语义：保存时后端**不接受**这些键，它们的**原值保持不变**（不写磁盘也不改内存）。
/// 与"未知键"（`ignored_keys`）是两个不同的桶 —— 后端 2.1.19 起分开回报，
/// 前端因此不再需要本地过滤（旧版本后端会把只读项混进 `ignored_keys`，
/// 那时靠本清单兜底；保留它只为"只读展示区"的标签与旧后端兼容）。
///
/// 每个键"为什么只读 / 要改怎么办"由后端 `readonly_detail[].reason` 给出（优先展示），
/// 本表只提供**离线兜底文案**（旧后端不返回 reason 时用）。
const READONLY_KEYS: [(&str, &str); 8] = [
    ("config_version", "配置 schema 版本，由迁移自动维护"),
    ("listen", "监听地址段：需编辑配置文件后重启"),
    ("api", "控制台监听与 token 段：需编辑配置文件后重启"),
    ("web_root", "静态资源根目录：只读段"),
    (
        "rule_local_file",
        "规则数据文件路径，由服务端按 config.json 同目录推导（不可由控制台改写）",
    ),
    (
        "rule_sub_file",
        "订阅数据文件路径，由服务端按 config.json 同目录推导（不可由控制台改写）",
    ),
    ("cache_file", "缓存落盘路径：只读段"),
    ("dns_port", "DNS 端口旧键（等价 listen.*）：只读段"),
];

/// `true` = 该键属于只读/服务端管理桶（前端只读展示区用）。
fn is_readonly_key(k: &str) -> bool {
    READONLY_KEYS.iter().any(|(n, _)| *n == k)
}

/// **2.1.18（修复项 7）**：保存结果提示语（**纯函数**，单测钉死文案）。
///
/// 为什么必须改写（用户实测的误导）：旧文案是
/// `配置已保存; 忽略未保存的键: config_version, single_flight, warmup, …`
/// —— 把"只读/服务端管理项"和"未知键"混在一起说成"忽略未保存的键"，
/// 用户会以为**保存丢数据**。真实语义是：
/// - 白名单内的键：已保存 + 已生效；
/// - 只读/服务端管理项：**原值保持不变**（不是丢失，是本来就不由控制台改）；
/// - 未知键：才是"不认识、已忽略"。
///
/// 输出（`ro` = 只读项，`ig` = 未知项）：
/// - 两者都空 → `配置已保存到后端 <saved_to>, 新增上游自动测速中…`
/// - 只有只读 → `配置已保存（另有 N 项由配置文件/服务端管理，未在界面暴露，原值保持不变：a, b）`
/// - 有未知键 → 在末尾追加 `；未知键 M 项已忽略：x, y`（这是真的"没保存"）
/// - `ok == false` → 写盘失败的独立文案（调用方自行处理，见 [`save_note`]）
fn save_message(saved_to: &str, readonly: &[String], ignored: &[String]) -> String {
    let mut s = if readonly.is_empty() {
        format!("配置已保存到后端 {saved_to}，新增上游自动测速中…")
    } else {
        format!(
            "配置已保存（另有 {} 项由配置文件/服务端管理，未在界面暴露，原值保持不变：{}）",
            readonly.len(),
            readonly.join(", ")
        )
    };
    if !ignored.is_empty() {
        s.push_str(&format!(
            "；另有 {} 项未知键已忽略（请核对拼写）：{}",
            ignored.len(),
            ignored.join(", ")
        ));
    }
    s
}

/// 保存结果 → `(提示语, 提示级别)`（`ok=false` 的写盘失败优先，见 `act_save`）。
fn save_note(
    ok: bool,
    saved_to: &str,
    readonly: &[String],
    ignored: &[String],
) -> (String, NoteKind) {
    if !ok {
        return (
            "配置已在运行中生效，但写盘失败，重启后将丢失".to_string(),
            NoteKind::Err,
        );
    }
    let kind = if ignored.is_empty() {
        NoteKind::Ok
    } else {
        NoteKind::Warn
    };
    (save_message(saved_to, readonly, ignored), kind)
}

/// **2.1.18（修复项 7）**：只读/服务端管理项的**展示行** `(键, 当前值, 原因)`。
///
/// 值一律从**服务器配置**（`GET /api/config`）取，不取表单值 —— 只读项的意义就是
/// "当前服务端实际用的是什么"，表单里没有它们的控件。`reasons` = 后端
/// `readonly_detail[].reason`（旧后端为空 → 用本地兜底文案）。
fn readonly_rows(
    cfg: &Value,
    reasons: &std::collections::HashMap<String, String>,
) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for (k, fallback) in READONLY_KEYS {
        let v = match cfg.get(k) {
            Some(Value::Object(_)) => "(对象/段，见配置文件)".to_string(),
            Some(Value::Array(_)) => "(数组，见配置文件)".to_string(),
            Some(Value::String(s)) => {
                if s.is_empty() {
                    "(空)".to_string()
                } else {
                    s.clone()
                }
            }
            Some(other) => other.to_string(),
            None => "(未设置)".to_string(),
        };
        let why = reasons
            .get(k)
            .cloned()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| (*fallback).to_string());
        out.push(((*k).to_string(), v, why));
    }
    out
}

fn proto_label(p: &str) -> &'static str {
    match p {
        "udp" => "UDP",
        "tcp" => "TCP",
        "doh" => "DoH",
        "dot" => "DoT",
        "doq" => "DoQ",
        "doh3" => "DoH3",
        _ => "",
    }
}

fn action_label(a: &str) -> &'static str {
    match a {
        "group" => "使用分组",
        "forceIp" => "强制 IP",
        "block" => "屏蔽",
        "allow" => "放行（白名单）",
        _ => "",
    }
}

/// 上游协议默认端口（对齐原件 `UP_PORT_DEFAULT`）。
fn up_port_default(proto: &str) -> i64 {
    match proto {
        "udp" | "tcp" => 53,
        "doh" | "doh3" => 443,
        "dot" | "doq" => 853,
        _ => 53,
    }
}

/* ============================== 配置值读取 ============================== */

fn cfg_str(c: &Value, k: &str) -> String {
    match c.get(k) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

/// 字符串字段：空 → 默认（对齐原件 `c.x || 'default'`）。
fn cfg_str_or(c: &Value, k: &str, d: &str) -> String {
    let s = cfg_str(c, k);
    if s.is_empty() {
        d.to_string()
    } else {
        s
    }
}

fn cfg_bool(c: &Value, k: &str, d: bool) -> bool {
    c.get(k).and_then(Value::as_bool).unwrap_or(d)
}

/// 数字输入框初值（0 是合法值，不做 JS `||` 短路；缺字段才回退默认）。
fn cfg_num_s(c: &Value, k: &str, d: f64) -> String {
    let v = c
        .get(k)
        .and_then(Value::as_f64)
        .filter(|x| x.is_finite())
        .unwrap_or(d);
    num_disp(v)
}

fn cfg_f64(c: &Value, k: &str, d: f64) -> f64 {
    c.get(k)
        .and_then(Value::as_f64)
        .filter(|x| x.is_finite())
        .unwrap_or(d)
}

/// `f64` → 输入框显示串（整数不带 `.0`）。
fn num_disp(v: f64) -> String {
    if v.is_finite() {
        format!("{v}")
    } else {
        "0".to_string()
    }
}

/// 数字字段的 JSON：整数值发整数（对齐 JS `JSON.stringify` 的数字形态）。
fn num_json(v: f64) -> Value {
    if v.is_finite() && v.fract() == 0.0 && v.abs() < 9.007_199_254_740_992e15 {
        json!(v as i64)
    } else if v.is_finite() {
        json!(v)
    } else {
        json!(0)
    }
}

/// 取 `app.config` 里的数组字段（缺省空数组）。
fn cfg_list(c: Option<&Value>, k: &str) -> Vec<Value> {
    c.and_then(|c| c.get(k))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// 可选数值字段的输入框初值：缺字段/null/空串 → 空串（对齐 `!= null && !== ''`）。
fn opt_field_s(v: &Value, k: &str) -> String {
    match v.get(k) {
        Some(Value::Null) | None => String::new(),
        Some(Value::String(s)) if s.is_empty() => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(_) => String::new(),
    }
}

/* ============================== DOM 读取/写入 ============================== */

fn dom_el(id: &str) -> Option<web_sys::Element> {
    web_sys::window()?.document()?.get_element_by_id(id)
}

/// 读 input/select/textarea 的字符串值。
fn dom_val(id: &str) -> String {
    let Some(el) = dom_el(id) else {
        return String::new();
    };
    if let Some(i) = el.dyn_ref::<web_sys::HtmlInputElement>() {
        return i.value();
    }
    if let Some(s) = el.dyn_ref::<web_sys::HtmlSelectElement>() {
        return s.value();
    }
    if let Some(t) = el.dyn_ref::<web_sys::HtmlTextAreaElement>() {
        return t.value();
    }
    String::new()
}

/// 读 number 输入框（`value_as_number`，NaN → None）。
fn dom_num(id: &str) -> Option<f64> {
    let i = dom_el(id)?.dyn_into::<web_sys::HtmlInputElement>().ok()?;
    let v = i.value_as_number();
    if v.is_finite() {
        Some(v)
    } else {
        None
    }
}

/// 读 number 输入框并钳制到 [lo, hi]；空/非法时用默认值。
///
/// **2.1.20（A-02）**：整数配置键请改用 [`dom_clamped_key`]（区间来自后端权威表）；
/// 本函数只留给**不在** `CONFIG_RANGES` 里的键（浮点/枚举派生控件）。
fn dom_clamped(id: &str, lo: f64, hi: f64, d: f64) -> f64 {
    dom_num(id).unwrap_or(d).max(lo).min(hi)
}

/// **2.1.20（A-02 修复）**：按键名取**后端权威区间**并钳制；顺带把区间写进 DOM 的
/// `min`/`max` 属性（浏览器原生校验也随之与后端一致）。
///
/// 区间来源优先级：
/// 1. `/api/status.config_ranges`（**权威**，单一来源 = 后端 `CONFIG_RANGES`）；
/// 2. `fmtnum::CONFIG_RANGE_FALLBACK`（**旧后端兜底**，由机器校验单测钉死与后端同值）。
///
/// 为什么必须这么做（审计 A-02 实测）：2.1.19 的控制台**硬编码**范围，6 个键能摆出后端
/// 必然 400 的值（`cache_size` 下限 1<16、`ttl`/`ttl_min`/`ttl_max` 上限 2^31-1>604800、
/// `stale_ttl` 8640000>604800、`speed_interval_ms` 下限 0<100、
/// `health_check_interval` 604800>86400），而 `PUT /api/config` 是**整份提交**
/// ⇒ 一个坏值让**所有**编辑一起失败。
fn dom_clamped_key(app: App, key: &str, id: &str, d: f64) -> f64 {
    let (lo, hi) = cfg_range(app, key);
    // DOM 属性同步（缺元素时静默跳过 —— 控件可能因路由/条件渲染不在树上）。
    if let Some(el) = dom_el(id).and_then(|e| e.dyn_into::<web_sys::HtmlInputElement>().ok()) {
        el.set_min(&fmt::num0(lo));
        el.set_max(&fmt::num0(hi));
    }
    fmt::clamp_to_range(dom_num(id).unwrap_or(d), lo, hi, d)
}

/// **2.1.20（A-02）**：查一个整数配置键的 `(min, max)`：先看后端下发的权威表，
/// 再看本地兜底表；两者都没有 ⇒ `(0, i64::MAX)`（不钳制，保持旧行为）。
fn cfg_range(app: App, key: &str) -> (f64, f64) {
    let from_api = app
        .status
        .get()
        .and_then(|s| {
            s.config_ranges
                .iter()
                .find(|r| r.key == key)
                .map(|r| (r.min, r.max))
        })
        .filter(|(lo, hi)| hi.is_finite() && *hi >= *lo);
    match from_api {
        Some(v) => v,
        None => match fmt::fallback_range_of(key) {
            Some((lo, hi)) => (lo as f64, hi as f64),
            None => (0.0, 2_147_483_647.0),
        },
    }
}

/// **2.1.18（修复项 7）**：读 number 输入框并钳制到 [lo, hi]，**保留小数**。
///
/// 与 [`dom_clamped`] 的区别：那个专供 `num_json`（整数计数器）使用，会 `round()`；
/// 本函数给 `rating_sr_floor` / `hedge_slowest_factor` 这类**比例因子**用
/// （0.25 / 1.5 必须原样保留，取整会把它们变成 0 / 2 —— 前者会把上游饿死，
/// 后者直接改变选路行为）。
fn dom_clamped_f(id: &str, lo: f64, hi: f64, d: f64) -> f64 {
    dom_num(id).unwrap_or(d).max(lo).min(hi)
}

fn dom_checked(id: &str) -> bool {
    dom_el(id)
        .and_then(|el| el.dyn_into::<web_sys::HtmlInputElement>().ok())
        .map(|i| i.checked())
        .unwrap_or(false)
}

fn dom_set_val(id: &str, v: &str) {
    if let Some(i) = dom_el(id).and_then(|el| el.dyn_into::<web_sys::HtmlInputElement>().ok()) {
        i.set_value(v);
    }
}

fn ev_value(ev: &leptos::ev::Event) -> String {
    ev.target()
        .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
        .map(|e| e.value())
        .unwrap_or_default()
}

fn ev_sel_value(ev: &leptos::ev::Event) -> String {
    ev.target()
        .and_then(|t| t.dyn_into::<web_sys::HtmlSelectElement>().ok())
        .map(|e| e.value())
        .unwrap_or_default()
}

fn ev_checked(ev: &leptos::ev::Event) -> bool {
    ev.target()
        .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
        .map(|e| e.checked())
        .unwrap_or(false)
}

/* ============================== 上游地址解析 ============================== */

struct ParsedUp {
    proto: String,
    addr: String,
    port: i64,
    url: String,
}

/// 上游完整地址（`scheme://host[:port][/path]` → 分字段），对齐原件 `fullAddr`。
fn full_addr(u: &Value) -> String {
    let proto = {
        let p = cfg_str(u, "proto").to_lowercase();
        if p.is_empty() {
            "udp".to_string()
        } else {
            p
        }
    };
    let scheme = match proto.as_str() {
        "udp" => "udp",
        "tcp" => "tcp",
        "doh" => "https",
        "doh3" => "http3",
        "dot" => "tls",
        "doq" => "quic",
        other => other,
    };
    let mut url = cfg_str(u, "url");
    if matches!(proto.as_str(), "doh" | "doh3" | "doq") {
        if !url.is_empty() && !url.starts_with('/') {
            url = format!("/{url}");
        }
        if url.is_empty() {
            url = "/dns-query".to_string();
        }
    } else {
        url.clear();
    }
    format!("{scheme}://{}{url}", cfg_str(u, "addr"))
}

/// 地址里是否显式写了端口（D24：逐分支对齐后端 `api.rs::addr_has_explicit_port`）。
///
/// 与旧实现的差别：先剥离 `scheme://` 前缀、再在第一个 `/` 处截断路径（旧实现扫全串，
/// 会把 URL 路径里的 `:443` 误判成端口），且 `[` 开头的方括号地址不做「裸 IPv6」跳过。
fn has_explicit_port(raw: &str) -> bool {
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
    // 裸 IPv6（多冒号且未方括号包裹）不切端口。
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

/// 解析上游地址（对齐后端 `crates/ebpdns-server/src/api.rs::parse_upstream_addr_local`，D24）。
///
/// 后端该函数逐分支移植自 `crates/ebpdns-upstream/src/addr.rs::parse_upstream_addr`
/// （Python `config.parse_upstream_addr` 的等价实现），前端此前缺若干**拒绝分支**，
/// 导致两侧可接受集合不互为子集。这里补齐为逐分支等价：
/// - scheme 识别（https/http/quic/doq/tls/dot/udp/tcp/doh/doh3/http3/h3），未知 scheme 拒绝；
/// - `http://` 明文默认端口 80；
/// - 路径切分（仅 DoH/DoH3/DoQ 保留 URL）；
/// - 三类端口切分：`[v6]` / `[v6]:port` / 裸 `host:port`；`[v6]` 一律**剥离方括号**
///   （与后端 `host = inner[..rb]` 一致，故 `[::1]:5300` → addr `::1`）；
/// - 新增后端已有的拒绝分支：未闭合 `[`、空 `[]`、`]` 后有多余字符、
///   `[v6]:` 后非数字、host 为空或超 253 字符、切分后残留单冒号（`example.com:` /
///   `host:abc`）、协议枚举非法、端口越界；
/// - host 字符集与后端 `host_char_ok` 相同（字母数字与 `.-_:[]`）。
///
/// 说明：后端 `POST /api/upstreams` 在解析失败时会退到「手动分支」，把原串按
/// `valid_host` 当字面 addr 落库（例如 `1.1.1.1:70000` 会被原样存下）；本前端从不调用
/// 该端点，只把结果 `PUT /api/config`（后端不做逐条 addr 校验），因此本地拒绝越界端口
/// 更安全，且与本文件的 `ParsedUp` 语义一致。
fn parse_upstream_addr(raw: &str, proto_sel: &str) -> Result<ParsedUp, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("地址为空".to_string());
    }
    let mut proto = String::new();
    let mut rest = s.to_string();
    let mut url = String::new();
    let mut plain_http = false;

    if let Some(idx) = s.find("://") {
        let scheme_raw = &s[..idx];
        let scheme_ok = scheme_raw
            .chars()
            .next()
            .map(|c| c.is_ascii_alphabetic())
            .unwrap_or(false)
            && scheme_raw
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'));
        if scheme_ok {
            let scheme = scheme_raw.to_lowercase();
            rest = s[idx + 3..].to_string();
            match scheme.as_str() {
                "https" => {
                    proto = "doh".into();
                    url = "/dns-query".into();
                }
                "http" => {
                    proto = "doh".into();
                    url = "/dns-query".into();
                    plain_http = true;
                }
                "quic" | "doq" => {
                    proto = "doq".into();
                    url = "/dns-query".into();
                }
                "tls" | "dot" => proto = "dot".into(),
                "udp" => proto = "udp".into(),
                "tcp" => proto = "tcp".into(),
                "doh" => {
                    proto = "doh".into();
                    url = "/dns-query".into();
                }
                "doh3" => {
                    proto = "doh3".into();
                    url = "/dns-query".into();
                }
                "http3" | "h3" => {
                    proto = "doh3".into();
                    url = "/dns-query".into();
                }
                other => {
                    return Err(format!(
                        "无法识别的协议前缀 {other}://（支持 https/http/quic/doq/tls/dot/udp/tcp/doh/doh3/http3/h3）"
                    ))
                }
            }
        }
    }

    if proto.is_empty() {
        if !proto_sel.is_empty() && proto_sel != "auto" {
            proto = proto_sel.to_string();
            if matches!(proto.as_str(), "doh" | "doh3" | "doq") {
                url = "/dns-query".into();
            }
        } else {
            proto = "udp".into();
        }
    }
    // 协议枚举（后端 `ALLOWED_UPSTREAM_PROTO`）：无 scheme 时 proto_sel 原样采用，
    // 非法值由这里拒绝（后端同位置返回 400）。
    if !PROTO_ORDER.contains(&proto.as_str()) {
        return Err(format!(
            "无法识别的协议 {proto}（支持 {}）",
            PROTO_ORDER.join("/")
        ));
    }

    // 拆分 host:port 与路径（明文 http:// DoH 默认端口 80）
    let mut host = rest;
    let mut port: i64 = if plain_http {
        80
    } else {
        up_port_default(&proto)
    };
    if let Some(slash) = host.find('/') {
        let p = host[slash..].to_string();
        if matches!(proto.as_str(), "doh" | "doh3" | "doq") {
            url = if p.starts_with('/') {
                p
            } else {
                format!("/{p}")
            };
        }
        host = host[..slash].to_string();
    }
    // 端口切分：三类 host（`[v6]` / `[v6]:port` / 裸 host:port），与后端逐分支一致。
    if let Some(inner) = host.strip_prefix('[') {
        let Some(rb) = inner.find(']') else {
            return Err(format!("IPv6 字面量缺少 ']': {s}"));
        };
        if rb == 0 {
            return Err(format!("IPv6 字面量为空: {s}"));
        }
        let after = inner[rb + 1..].to_string();
        if !after.is_empty() {
            let Some(num) = after.strip_prefix(':') else {
                return Err(format!("方括号地址后有多余字符: {s}"));
            };
            if num.is_empty() || !num.chars().all(|c| c.is_ascii_digit()) {
                return Err(format!("端口必须是数字: {s}"));
            }
            port = parse_port(num)?;
        }
        host = inner[..rb].to_string();
    } else if host.matches(':').count() <= 1 {
        if let Some(colon) = host.rfind(':') {
            if colon > 0 {
                let tail = host[colon + 1..].to_string();
                if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) {
                    port = parse_port(&tail)?;
                    host = host[..colon].to_string();
                }
            }
        }
    }
    let host_len = host.chars().count();
    if host.is_empty() || host_len > 253 {
        return Err(format!(
            "地址长度非法 (要求 1-253 字符, got {host_len}): {s}"
        ));
    }
    let host_ok = host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '[' | ']'));
    if !host_ok {
        return Err(format!("地址格式无法识别: {s}"));
    }
    // 切分后仍残留单冒号（`example.com:` / `host:abc`）→ 畸形（后端同样拒绝）。
    if host.matches(':').count() == 1 {
        return Err(format!("地址含非法单冒号: {s}"));
    }
    if !(1..=65535).contains(&port) {
        return Err(format!("端口必须在 1-65535 之间 (got {port})"));
    }
    if matches!(proto.as_str(), "doh" | "doh3" | "doq") {
        if url.is_empty() {
            url = "/dns-query".to_string();
        }
        if !url.starts_with('/') {
            url = format!("/{url}");
        }
    } else {
        url.clear();
    }
    Ok(ParsedUp {
        proto,
        addr: host,
        port,
        url,
    })
}

/// 端口串 → 数值；越界/非数字一律拒绝（与后端 `num.parse::<u16>()` + 1..=65535 同口径）。
fn parse_port(num: &str) -> Result<i64, String> {
    let p: i64 = num.parse().map_err(|_| format!("端口必须是数字: {num}"))?;
    if !(1..=65535).contains(&p) {
        return Err(format!("端口必须在 1-65535 之间 (got {p})"));
    }
    Ok(p)
}

/// 毫秒时间戳（上游新增 id 用）。
fn now_ms() -> i64 {
    js_sys::Date::now() as i64
}

/// 6 位 base36 随机后缀（对齐 `Math.random().toString(36).slice(2,8)`）。
fn rand36_6() -> String {
    const DIGITS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut v = (js_sys::Math::random() * 2_176_782_336.0) as u64; // 36^6
    let mut out = [b'0'; 6];
    for i in (0..6).rev() {
        out[i] = DIGITS[(v % 36) as usize];
        v /= 36;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// 上游行的连接级健康度（D14）。
///
/// `conn_avg_lat/conn_ok/conn_fail/conn_key` **只**出现在 `/api/snapshot.upstreams[]`
/// （2.0 后端把它们当遥测字段，`PUT /api/config` 回传时会被 `api::upstreams_back` 剥离），
/// 配置页的本地工作副本里永远没有 → 旧实现该列恒显示 `-`。
/// 这里改为从 `app.snapshot` 按 `id`（空则 `addr`+`port`）匹配读取；匹配不到再退回
/// 本地副本的同名字段（兼容旧后端/手工构造），最后才是「待统计」。
struct ConnMetrics {
    lat: Option<f64>,
    ok: f64,
    fail: f64,
    key: String,
}

/// 在 `/api/snapshot.upstreams[]` 中定位某上游：先按 `id`，再按 `addr`(+`port`)。
fn match_snapshot_upstream<'a>(
    snap: Option<&'a crate::model::Snapshot>,
    id: &str,
    addr: &str,
    port: f64,
) -> Option<&'a crate::model::UpstreamStat> {
    let ups = snap?.upstreams.as_slice();
    if !id.is_empty() {
        if let Some(u) = ups.iter().find(|u| u.id == id) {
            return Some(u);
        }
    }
    if addr.is_empty() {
        return None;
    }
    ups.iter()
        .find(|u| u.addr == addr && (u.port - port).abs() < 0.5)
        .or_else(|| ups.iter().find(|u| u.addr == addr))
}

fn conn_metrics(snap: Option<&crate::model::Snapshot>, u: &Value) -> ConnMetrics {
    let id = cfg_str(u, "id");
    let addr = {
        let a = cfg_str(u, "addr");
        if a.is_empty() {
            cfg_str(u, "host")
        } else {
            a
        }
    };
    let port = cfg_f64(u, "port", 0.0);
    if let Some(h) = match_snapshot_upstream(snap, &id, &addr, port) {
        return ConnMetrics {
            lat: h.conn_avg_lat.filter(|v| v.is_finite()),
            ok: if h.conn_ok.is_finite() {
                h.conn_ok
            } else {
                0.0
            },
            fail: if h.conn_fail.is_finite() {
                h.conn_fail
            } else {
                0.0
            },
            key: h.conn_key.clone(),
        };
    }
    ConnMetrics {
        lat: u
            .get("conn_avg_lat")
            .and_then(Value::as_f64)
            .filter(|v| v.is_finite()),
        ok: cfg_f64(u, "conn_ok", 0.0),
        fail: cfg_f64(u, "conn_fail", 0.0),
        key: cfg_str(u, "conn_key"),
    }
}

/// 连接级健康度徽标（对齐 `connBadge`）。
fn conn_badge_view(m: &ConnMetrics) -> AnyView {
    let Some(lat) = m.lat else {
        return view! { <span class="conn-badge" title="连接级健康度待统计">"-"</span> }.into_any();
    };
    let bad = m.fail > m.ok;
    let slow = !bad && lat > 500.0;
    let cls_ok = !bad && !slow;
    let title = format!(
        "连接级健康度：成功 {} / 失败 {} · {}",
        fmt::num0(m.ok),
        fmt::num0(m.fail),
        m.key
    );
    let r = (lat * 10.0).round() / 10.0;
    let lat_txt = if r.is_finite() {
        format!("{r}")
    } else {
        "0".to_string()
    };
    let txt = format!("{lat_txt}ms · {}/{}", fmt::num0(m.ok), fmt::num0(m.fail));
    view! {
        <span class="conn-badge" class:bad=bad class:slow=slow class:ok=cls_ok title=title>
            {txt}
        </span>
    }
    .into_any()
}

/* ============================== 列表暂存工具 ============================== */

fn find_obj_mut<'a>(list: &'a mut [Value], id: &str) -> Option<&'a mut Map<String, Value>> {
    list.iter_mut()
        .find(|x| x.get("id").and_then(Value::as_str) == Some(id))
        .and_then(Value::as_object_mut)
}

/// 上游/规则行内编辑：按 id 写回某字段（本地暂存）。
fn row_set(list: RwSignal<Vec<Value>>, id: &str, key: &str, v: Value) {
    let id = id.to_string();
    let key = key.to_string();
    list.update(move |l| {
        if let Some(o) = find_obj_mut(l, &id) {
            o.insert(key, v);
        }
    });
}

/// 从本地暂存列表里删除一行（上游 / 逐条规则 / 订阅）。
///
/// **审计 ④/⑤ 修复**：`×` 原先无任何确认、也不落盘 —— 一次误点就静默从表单里消失
/// （若随后点「重新载入/热重载」，改动被服务器值覆盖，等于**静默回滚**）。现在：
/// 1. 先 `confirm` 确认；
/// 2. 确认后仍只是本地暂存，提示里说明「点『应用配置』才生效」。
fn row_remove(list: RwSignal<Vec<Value>>, id: &str) {
    match &list_with_kind(list, id) {
        Some((kind, name)) => {
            if let Some(win) = web_sys::window() {
                let ok = win
                    .confirm_with_message(&format!(
                        "确定从待保存列表删除这个{kind}吗？\n{name}\n（仅改本地表单，需再点「应用配置」才会写入后端）"
                    ))
                    .unwrap_or(false);
                if !ok {
                    return;
                }
            }
        }
        None => return,
    }
    let id = id.to_string();
    list.update(move |l| l.retain(|x| x.get("id").and_then(Value::as_str) != Some(id.as_str())));
}

/// `row_remove` 的提示信息：`(类型文案, 展示名)`；找不到该 id 返回 `None`（不删）。
fn list_with_kind(list: RwSignal<Vec<Value>>, id: &str) -> Option<(&'static str, String)> {
    let l = list.get_untracked();
    let o = l
        .iter()
        .find(|x| x.get("id").and_then(Value::as_str) == Some(id))?;
    let kind = if o.get("addr").is_some() || o.get("proto").is_some() {
        "上游"
    } else if o.get("match").is_some() {
        "规则"
    } else {
        "订阅"
    };
    let name = o
        .get("name")
        .or_else(|| o.get("match"))
        .or_else(|| o.get("url"))
        .or_else(|| o.get("addr"))
        .and_then(Value::as_str)
        .unwrap_or(id)
        .to_string();
    Some((kind, name))
}

/* ============================== 页面 ============================== */

#[component]
pub fn ConfigPage() -> impl IntoView {
    let app = expect_context::<App>();

    // 本地暂存的三份列表（上游 / 逐条规则 / 订阅）。
    let ups: RwSignal<Vec<Value>> =
        RwSignal::new(cfg_list(app.config.get_untracked().as_ref(), "upstreams"));
    let rules: RwSignal<Vec<Value>> =
        RwSignal::new(cfg_list(app.config.get_untracked().as_ref(), "rules"));
    let subs: RwSignal<Vec<Value>> = RwSignal::new(cfg_list(
        app.config.get_untracked().as_ref(),
        "rule_subscriptions",
    ));

    // 服务器配置每次刷新（cfg_epoch +1）→ 重置本地暂存。
    Effect::new(move |_| {
        let _ = app.cfg_epoch.get();
        let c = app.config.get_untracked();
        ups.set(cfg_list(c.as_ref(), "upstreams"));
        rules.set(cfg_list(c.as_ref(), "rules"));
        subs.set(cfg_list(c.as_ref(), "rule_subscriptions"));
    });

    // **2.1.18（修复项 5：⑫「配置页未保存可见反馈」）**：表单是否有**未保存**的改动。
    //
    // 为什么需要：旧实现里"改了但没点应用"与"没改过"在界面上**完全一样**，
    // 用户切页/刷新后改动静默丢失且无任何提示（审计 ④/⑤ 的同一类问题）。
    // 实现方式刻意选**一条委托监听**（`.cfg-grid` 上的 `input`/`change` 冒泡），
    // 而不是给几十个控件逐个挂 `on:input` —— 后者既有遗漏风险，又会改动既有
    // 非受控控件的语义（本页刻意保持非受控以免覆盖光标/焦点）。
    //
    // 复位点：①服务器配置刷新（`cfg_epoch` +1）；②`PUT /api/config` 成功。
    // 本地暂存列表（上游/规则/订阅）的行内编辑另在增删改函数里显式置位。
    let dirty = RwSignal::new(false);
    Effect::new(move |_| {
        // 只在服务器配置刷新时复位；`ups/rules/subs` 的本地改动由各自 action 置位。
        let _ = app.cfg_epoch.get();
        dirty.set(false);
    });

    view! {
        <section class="route active" data-route="config">
            // R12 P3-3: 后端 /api/config 不可用时的加载横幅（config 为空时去掉 hidden）
            <div
                id="cfg-loading-banner"
                class="cfg-loading-banner"
                hidden=move || app.config_loaded()
            >
                "配置加载中… 后端 /api/config 暂不可用，将自动重试，成功后自动渲染真实配置。"
            </div>
            {move || {
                // 只在服务器配置刷新时重建整张表单（避免输入焦点/光标被覆盖）。
                let _ = app.cfg_epoch.get();
                let cfg = app.config.get_untracked().unwrap_or(Value::Null);
                view! {
                    <div
                        class="cfg-grid"
                        on:input=move |_| dirty.set(true)
                        on:change=move |_| dirty.set(true)
                    >
                        <CardCache cfg=cfg.clone() />
                        <div class="cfg-col">
                            <CardRules rules=rules subs=subs />
                        </div>
                        <CardSpeed cfg=cfg.clone() />
                        <CardAdv cfg=cfg.clone() />
                        <CardUpstreams ups=ups />
                    </div>
                    <CardConn />
                    <CardFooter ups=ups rules=rules subs=subs dirty=dirty />
                }
                    .into_any()
            }}
        </section>
    }
}

/* ------------------------------ ① 缓存 ------------------------------ */

/// **2.1.19（修复项 3 / R9）**：把落盘现场渲染成只读行（`标签 值`）。
///
/// 取值**只**来自 `app.status.cache.persist`（后端 `cache_persist_info` 的同一份 JSON），
/// 因此"页面显示的值 == API 的值"是**结构性**成立的（不存在第二份计算）。
/// 空态与超期提示都由 [`fmt::persist_rows`] / [`fmt::persist_stale`] 的**纯函数**决定
/// （native 单测覆盖，不依赖 wasm 运行时）。
///
/// 另外两行直接用后端字段，**不做二次加工**：
/// * `mtime_s`（BSD/ISO 形式由后端 epoch 秒换算 → 这里显示原始 epoch 与本地无关的
///   "距今"两列，避免再引入一套时区换算）；
/// * `note`（后端的可读原因/超期提示；为空则不渲染该行）。
fn persist_rows_view(app: App) -> impl IntoView {
    move || {
        let p = app.status_or_default().cache.persist;
        let rows = fmt::persist_rows(
            p.enabled,
            p.exists,
            &p.file,
            p.age_s,
            p.bytes,
            p.entries,
            p.interval_s,
        );
        let stale = fmt::persist_stale(p.age_s, p.interval_s);
        // mtime_s（epoch 秒）只在"文件存在"时有意义；`0` 表示后端也拿不到 mtime。
        let mtime_row = (p.exists && p.mtime_s > 0)
            .then(|| ("落盘时刻(epoch)".to_string(), format!("{}", p.mtime_s)));
        let note_row = (!p.note.trim().is_empty()).then(|| ("提示".to_string(), p.note.clone()));
        rows.into_iter()
            .chain(mtime_row)
            .chain(note_row)
            .map(|(k, v)| {
                // `warn` 只在"最近落盘"这一行、且确实超过 2 个周期时为真；
                // 后端的超期提示行（note）同样标红（两条口径一致：2×interval）。
                let warn = stale && (k == "最近落盘" || k == "提示");
                view! {
                    <div>
                        <span class="persist-k">{k}</span>
                        <span class="persist-v" class:persist-warn=warn>{v}</span>
                    </div>
                }
            })
            .collect_view()
    }
}

#[component]
fn CardCache(cfg: Value) -> impl IntoView {
    let app = expect_context::<App>();

    // A3（2.1.9）：默认缓存条目数 131072 → 16384（≈117kB/条时 131072 投影 ≈15GB）。
    let size = cfg_f64(&cfg, "cache_size", 16384.0);
    let ttl = cfg_f64(&cfg, "ttl", 300.0);
    let cache_file_text = move || {
        app.status
            .get()
            .and_then(|s| s.cache_file)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "—".to_string())
    };
    let cache_file_title = move || {
        app.status
            .get()
            .and_then(|s| s.cache_file)
            .unwrap_or_default()
    };

    view! {
        <div class="card">
            <div class="card-hd">
                <span class="t">"缓存"</span>
            </div>
            <div class="card-bd">
                /* ==== **2.1.21（DEF-220-02 / A-15 修复）：补齐"可写但无控件"的键** ====
                 *
                 * 审计实测：`CFG_WRITABLE` 有 76 个键，控制台只有 57 个写路径，
                 * 19 个键既无控件（其中 15 个在 `web/src` 里连字符串都没有）。
                 * 本块的 13 个控件 + `act_save` 里同名的 `obj.insert` 一起把
                 * **有取值区间的可写键**全部变成"界面上真的能改"。
                 * 剩下的没有区间的键（`cache_partitions` / `edns_client_subnet` /
                 * `adaptive_parallel` / `adaptive_timeout`）在 README 的
                 * 「仅 API / 配置文件可改」表里逐键登记。
                 * 机器门禁：`crates/ebpdns-resolver/tests/a15_key_coverage.rs`。
                 */
                <div class="cfg-row">
                    <div class="lab">
                        "落盘间隔"
                        <small>"s · 缓存周期落盘间隔（0 = 只在优雅退出时落盘）· 0-86400"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-cachesaveint"
                            min="0"
                            max="86400"
                            step="10"
                            prop:value=cfg_num_s(&cfg, "cache_save_interval", 60.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "预取触发阈值"
                        <small>"s · 剩余 TTL 低于或等于该值时才入队并真的发上游续期（0 = 关闭按剩余 TTL 的预取）· 默认 60。与 prefetch_interval 的分工：本键决定什么时候续期，那个决定多久扫一次队列 · 0-604800"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-pftrigger"
                            min="0"
                            max="604800"
                            step="5"
                            prop:value=cfg_num_s(&cfg, "prefetch_trigger", 60.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "预取目标 TTL 上限"
                        <small>"s · 续期回填时的 TTL 上限（0 = 不额外收紧）。例：上游给 600s、本值 300 ⇒ 续期后条目 TTL = 300s · 0-604800"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-pftarget"
                            min="0"
                            max="604800"
                            step="5"
                            prop:value=cfg_num_s(&cfg, "prefetch_target", 300.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "预取扫描周期"
                        <small>"s · 后台消费待预取队列的周期 · 1-86400"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-pfinterval"
                            min="1"
                            max="86400"
                            step="1"
                            prop:value=cfg_num_s(&cfg, "prefetch_interval", 300.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "预取队列上限"
                        <small>"条 · 待预取队列长度上限，超出按最旧驱逐 · 1-1000000"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-pfmax"
                            min="1"
                            max="1000000"
                            step="1"
                            prop:value=cfg_num_s(&cfg, "prefetch_max", 1024.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "负缓存 TTL 上限"
                        <small>"s · 负缓存（NXDOMAIN/NODATA）TTL 硬上限（0 = 关闭上限）· 0-86400"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-negttlmax"
                            min="0"
                            max="86400"
                            step="5"
                            prop:value=cfg_num_s(&cfg, "neg_ttl_max", 60.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "负结论表决票数"
                        <small>"有效票数 · NXDOMAIN/NODATA 需要多少张有效票才写负缓存（SERVFAIL/超时是弃权票，不抬高阈值）· 1-64"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-nxquorum"
                            min="1"
                            max="64"
                            step="1"
                            prop:value=cfg_num_s(&cfg, "nxdomain_quorum", 2.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "EDNS 客户端上限"
                        <small>"B · 从客户端 OPT 里接受的最大 UDP payload（也是出站查询的 bufsize 上限）· 512-65535"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-ednsclimax"
                            min="512"
                            max="65535"
                            step="8"
                            prop:value=cfg_num_s(&cfg, "edns_client_max_size", 1232.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "探针超时"
                        <small>"ms · 健康探针单次超时（0 = 自动 min(health_probe_timeout_ms, timeout_ms)，下限 250ms）· 0-60000"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-probetimeout"
                            min="0"
                            max="60000"
                            step="100"
                            prop:value=cfg_num_s(&cfg, "probe_timeout_ms", 0.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "熔断退避封顶"
                        <small>"s · 连续打开时按 min(open_s × 2^(k-1), 本值) 指数退避，防止长期故障上游反复惊群 · 1-604800"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-cbmax"
                            min="1"
                            max="604800"
                            step="10"
                            prop:value=cfg_num_s(&cfg, "circuit_open_max_s", 120.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "对冲触发时刻"
                        <small>"ms · 自适应并发：健康时先发 1 个上游，超过本值未回再补齐到「并发上游数」· 1-60000（另见对冲因子 hedge_slowest_factor = 候选 p90 × 该因子）"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-hedgeafter"
                            min="1"
                            max="60000"
                            step="10"
                            prop:value=cfg_num_s(&cfg, "hedge_after_ms", 200.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "自适应超时系数 k"
                        <small>"倍率 · 自适应超时 = clamp(k × 该上游实测 p90, 自适应超时下限, timeout_ms)；默认 8.0（出厂默认 min=timeout_ms ⇒ 等效关闭）· 0.1-1000"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-adatk"
                            min="0.1"
                            max="1000"
                            step="0.1"
                            prop:value=cfg_num_s(&cfg, "adaptive_timeout_k", 8.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "自适应超时下限"
                        <small>"ms · 自适应超时 = clamp(k × 该上游实测 p90, 本值, timeout_ms)；默认与 timeout_ms 相等（即默认不收紧）· 1-60000"</small>
                    </div>

                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-adatmintimeout"
                            min="1"
                            max="60000"
                            step="100"
                            prop:value=cfg_num_s(&cfg, "adaptive_timeout_min_ms", 1500.0)
                        />
                    </div>
                </div>

                <div class="cfg-row">
                    <div class="lab">
                        "缓存容量"
                        <small>"条 · 默认 131072（= 后端 default_config 与随包 config.json 的实际值；web/src 里的 16384 只是旧版占位默认）· 超出后按当前缓存策略淘汰 · 滑块上限 100 万条，更大容量请直接在数字框输入"</small>

                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-size"
                            // **2.1.20（A-02）**：静态 min/max 必须与后端 `CONFIG_RANGES`
                            // 一致（此前 `min="1" max="10000000"` ⇒ 后端 [16, 4194304]，
                            // 浏览器允许 1..15 与 4194305..1e7，保存必 400）。
                            // 保存时 `dom_clamped_key` 还会用**运行期**权威表再写一次。
                            min="16"
                            max="4194304"
                            step="16"
                            prop:value=num_disp(size)
                        />
                        <input
                            type="range"
                            id="cfg-size-r"
                            min="16"
                            max="1000000"
                            step="16"
                            prop:value=num_disp(size.min(1000000.0))
                            on:input=move |ev| {
                                // 与左侧数字框双向同步：此前滑块无任何事件处理，
                                // 拖动后保存仍是旧值（用户可见的功能缺陷）。
                                let v = dom_ev_num(&ev).max(16.0);
                                dom_set_val("cfg-size", &format!("{}", v as u64));
                            }
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "默认 TTL"
                        <small>"s · 缓存条目存活时间 · 滑块上限 86400(1天), 更长 TTL 请直接在数字框输入"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-ttl"
                            min="0"
                            max="604800"
                            step="5"
                            prop:value=num_disp(ttl)
                        />
                        <input
                            type="range"
                            id="cfg-ttl-r"
                            min="0"
                            max="86400"
                            step="5"
                            prop:value=num_disp(ttl.min(86400.0))
                            on:input=move |ev| {
                                // 同 cfg-size-r：滑块必须回写数字框，否则保存取不到新值。
                                let v = dom_ev_num(&ev).max(0.0);
                                dom_set_val("cfg-ttl", &format!("{}", v as u64));
                            }
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "域名预取"
                        <small>"TTL 到期前自动重新解析, 保持热点域名热缓存（待预取队列上限 65536，超出本轮自动丢弃）"</small>
                    </div>
                    <div class="val">
                        <label class="switch">
                            <input type="checkbox" id="cfg-prefetch" prop:checked=cfg_bool(&cfg, "prefetch", false) />
                            <span class="sl"></span>
                        </label>
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "缓存直答"
                        <small>"用户态缓存直答开关（配置键 cache_direct_enabled）：开启时缓存命中按 counters.cache_direct 展示，与 counters.hit 同源。"</small>
                    </div>
                    <div class="val">
                        <label class="switch">
                            <input type="checkbox" id="cfg-kdirect" prop:checked=cfg_bool(&cfg, "cache_direct_enabled", false) />
                            <span class="sl"></span>
                        </label>
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "缓存持久化"
                        <small>"总开关 · 关闭后不写盘也不从磁盘恢复（重启即清零，属设计行为）；开启时按下面的路径落盘：每个 cache_save_interval 周期一次（默认 60 s，0 = 关闭周期落盘）+ 优雅退出必落盘，启动时自动恢复。下面一行是运行态实测（来源 = /api/status.cache.persist，与 /api/cache/stats.persist 同源）"</small>
                    </div>
                    <div class="val">
                        <label class="switch">
                            <input type="checkbox" id="cfg-cachepersist" prop:checked=cfg_bool(&cfg, "cache_persist", true) />
                            <span class="sl"></span>
                        </label>
                        <div
                            class="mono"
                            id="cfg-cache-file"
                            style="font-size:11px;color:var(--text3);max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
                            title=cache_file_title
                        >
                            {cache_file_text}
                        </div>
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "最近一次落盘"
                        <small>"路径 / 最近落盘时间 / 内存条目数 / 文件大小（来源 = /api/status.cache.persist）。age_s 只增不减 ⇒ 若它持续超过 2 × cache_save_interval，说明没有按周期落盘（无流量或落盘失败）。两种空态分开显示：未开启持久化 / 已开启但文件不存在。"</small>
                    </div>
                    <div class="val" style="display:block;text-align:left">
                        <div class="mono" id="cfg-persist-rows" style="font-size:11px;line-height:1.7">
                            {persist_rows_view(app)}
                            <div>
                                <span class="persist-k">"启动恢复"</span>
                                <span class="persist-v">
                                    {move || {
                                        let d = app.status_or_default().cache.restore_drops;
                                        fmt::restore_drops_text(
                                            d.expired,
                                            d.legacy,
                                            d.failed,
                                            d.window_unpersisted,
                                        )
                                    }}
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "下发 TTL 下限"
                        <small>"s · 0=不限制; 内网客户端收到的应答 TTL 不低于此值（实际下发受报文格式上限 2147483647 ≈68 年钳制）"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-ttlmin"
                            min="0"
                            max="604800"
                            step="5"
                            placeholder="0"
                            prop:value=cfg_num_s(&cfg, "ttl_min", 0.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "下发 TTL 上限"
                        <small>"s · 0=不限制; 内网客户端收到的应答 TTL 不高于此值（与后端一致, 上限 2147483647 ≈68 年）"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-ttlmax"
                            min="0"
                            max="604800"
                            step="5"
                            placeholder="0"
                            prop:value=cfg_num_s(&cfg, "ttl_max", 0.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "过期缓存兜底"
                        <small>"serve-stale · 缓存过期后窗口内仍返回旧数据并后台刷新, 避免上游抖动时 SERVFAIL"</small>
                    </div>
                    <div class="val">
                        <label class="switch">
                            <input type="checkbox" id="cfg-stale" prop:checked=cfg_bool(&cfg, "serve_stale", false) />
                            <span class="sl"></span>
                        </label>
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "兜底窗口"
                        <small>"s · 过期后最多可返回旧数据的时间(超过则正常 miss)"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-stalettl"
                            min="0"
                            max="604800"
                            step="10"
                            prop:value=cfg_num_s(&cfg, "stale_ttl", 3600.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "持久化 TTL"
                        <small>"s · 0=按保存时剩余 TTL 原样恢复; >0 时重启恢复的缓存统一用此 TTL, 配合预取长期保持"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-persistttl"
                            min="0"
                            max="31536000"
                            step="60"
                            placeholder="0"
                            prop:value=cfg_num_s(&cfg, "persist_ttl", 0.0)
                        />
                    </div>
                </div>
            </div>
        </div>
    }
}

/* ------------------------------ ③ 测速与优选 ------------------------------ */

#[component]
fn CardSpeed(cfg: Value) -> impl IntoView {
    let ipsprobe = cfg_str_or(&cfg, "ip_speed_probe", "both");
    let p_udp53 = ipsprobe == "udp53";
    let p_tcp443 = ipsprobe == "tcp443";
    let p_both = ipsprobe == "both";

    view! {
        <div class="card">
            <div class="card-hd">
                <span class="t">"测速与优选"</span>
                <span class="s">"speed test · smart features"</span>
            </div>
            <div class="card-bd">
                <div class="cfg-row">
                    <div class="lab">
                        "启用测速择优"
                        <small>"对候选 IP 排序, 返回最快地址 (SmartDNS 风格)"</small>
                    </div>
                    <div class="val">
                        <label class="switch">
                            <input type="checkbox" id="cfg-speed" prop:checked=cfg_bool(&cfg, "speed_test", false) />
                            <span class="sl"></span>
                        </label>
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "测速间隔"
                        <small>"ms · 同一域名两次候选 IP 测速之间的最小间隔（默认 2000ms≈2s；范围 0-60000ms=60s，0=每次都测）"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-spint"
                            min="100"
                            max="600000"
                            step="500"
                            prop:value=cfg_num_s(&cfg, "speed_interval_ms", 2000.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "解析失败降级"
                        // v2.1.8：文案随开关实时切换（纯 CSS `:has()`，不改动本页任何
                        // 配置读写/规则/上游 CRUD 逻辑）——开=并发+后备，关=只打最快 1 个、失败即 SERVFAIL。
                        <small class="fb-on">
                            "首选「并发上游数」个并发，失败后再依次尝试后备上游（后备重试开启）"
                        </small>
                        <small class="fb-off">
                            "关闭后备重试：只并发首选的那 N 个上游，全部失败即 SERVFAIL（不再尝试后备上游）"
                        </small>
                    </div>
                    <div class="val">
                        <label class="switch">
                            <input type="checkbox" id="cfg-fallback" prop:checked=cfg_bool(&cfg, "fallback", false) />
                            <span class="sl"></span>
                        </label>
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "并发上游数"
                        <small>"并发上限 N（按延迟取最快的 N 个；自适应并发开启且上游健康时先发 1 个，超过 hedge_after_ms 未回再补齐到 N） · 预取固定用 1 个"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-maxup"
                            min="1"
                            max="16"
                            step="1"
                            prop:value=cfg_num_s(&cfg, "max_parallel_upstreams", 3.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "单上游在途上限"
                        <small>"条 · 每条上游同时进行的查询数上限（0 = 关闭闸门）。超限的查询在本进程内排队（等待计入该次查询延迟，且与该上游的 timeout_ms 共享预算），避免高并发把上游压到排队、进而把实测延迟与对冲频率一起放大。默认 32 的依据：远大于单查询的 fan-out（并发上游数 × 多 IP 并行），并与 DoH/DoT 连接池每键上限 16 同量级。是否真的在排队见 /metrics 的 ebpdns_upstream_inflight_queued_total"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-upinflight"
                            min="0"
                            max="1024"
                            step="1"
                            prop:value=cfg_num_s(&cfg, "upstream_max_inflight", 32.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "超时阈值"
                        // v2.1.8：说明"自适应超时的上限"从哪来 —— 后端**没有**
                        // `adaptive_timeout_max_ms` 这个键（不在 PUT 白名单，会被列入
                        // `ignored_keys`），自适应上限恒为这里的 `timeout_ms`。
                        // 该键在配置页没有任何可编辑控件（CDP 实测 input/select/textarea
                        // 中无 adaptive 相关项），因此只需补这句说明，无需"改成只读/隐藏"。
                        <small>
                            "ms · 单次上游查询超时（也是自适应超时的上限）：自适应开启时实际超时 = clamp(k × 该上游实测延迟, adaptive_timeout_min_ms, 本值)，min 默认等于本值（即默认不收紧）"
                        </small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-timeout"
                            min="1"
                            max="60000"
                            step="100"
                            prop:value=cfg_num_s(&cfg, "timeout_ms", 1500.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "测速探测超时"
                        <small>"ms · 候选 IP 测速单次探测超时(默认 300)"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-speedtimeout"
                            min="1"
                            max="60000"
                            step="50"
                            prop:value=cfg_num_s(&cfg, "speed_timeout_ms", 300.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "候选 IP 探测方式"
                        <small>"udp53=UDP:53 · tcp443=TCP:443 · both=两者并发取最快"</small>
                    </div>
                    <div class="val">
                        <select class="q-sel" id="cfg-ipsprobe" prop:value=ipsprobe.clone()>
                            <option value="udp53" selected=p_udp53>"UDP:53"</option>
                            <option value="tcp443" selected=p_tcp443>"TCP:443"</option>
                            <option value="both" selected=p_both>"两者并发"</option>
                        </select>
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "IP 测速结果缓存"
                        <small>"s · 命中直接复用, 避免重复探测(默认 60, 范围 0-86400)"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-ipscachettl"
                            min="0"
                            max="86400"
                            step="10"
                            prop:value=cfg_num_s(&cfg, "ip_speed_cache_ttl", 60.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "IPv4 优先"
                        <small>"同时存在 A / AAAA 记录时优先返回 A 记录"</small>
                    </div>
                    <div class="val">
                        <label class="switch">
                            <input type="checkbox" id="cfg-v4first" prop:checked=cfg_bool(&cfg, "ipv4_first", false) />
                            <span class="sl"></span>
                        </label>
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "启用 IPv6"
                        <small>"关闭后 AAAA 查询直接判未命中并返回空应答 (全局一刀切)"</small>
                    </div>
                    <div class="val">
                        <label class="switch">
                            <input type="checkbox" id="cfg-v6" prop:checked=cfg_bool(&cfg, "ipv6", false) />
                            <span class="sl"></span>
                        </label>
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "双栈智能 IPv4 优先"
                        <small>"prefer_ipv4 · 仅当域名存在 A 记录(双栈)才屏蔽 AAAA, 纯 IPv6 域名正常解析 — 替代全局 IPv6 开关的精细化方案"</small>
                    </div>
                    <div class="val">
                        <label class="switch">
                            <input type="checkbox" id="cfg-v4smart" prop:checked=cfg_bool(&cfg, "prefer_ipv4", false) />
                            <span class="sl"></span>
                        </label>
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "EDNS UDP size"
                        <small>"出站查询 EDNS0 payload(字节) · 1232=IPv6 MTU 防分片安全值, 减少大应答 UDP 分片被 NAT/防火墙丢弃导致的解析超时"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-ednssize"
                            min="512"
                            max="9000"
                            step="8"
                            placeholder="1232"
                            prop:value=cfg_num_s(&cfg, "edns_udp_size", 1232.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "加密查询填充"
                        <small>"padding · DoT/DoH/DoH3/DoQ 出站报文填充到 128B 块(RFC 8467), 抹平长度指纹防流量分析 — 明文 UDP/TCP 不填充"</small>
                    </div>
                    <div class="val">
                        <label class="switch">
                            <input type="checkbox" id="cfg-padding" prop:checked=cfg_bool(&cfg, "padding", false) />
                            <span class="sl"></span>
                        </label>
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "响应 IP 合法性校验"
                        <small>"防 DNS 劫持/rebinding · 丢弃上游返回的私有/保留/环回地址(10.x/192.168.x/127.x/fc00::/7 等), forceIp 规则豁免"</small>
                    </div>
                    <div class="val">
                        <label class="switch">
                            <input type="checkbox" id="cfg-rebind" prop:checked=cfg_bool(&cfg, "rebind_protection", true) />
                            <span class="sl"></span>
                        </label>
                    </div>
                </div>
            </div>
        </div>
    }
}

/* ------------------------------ ④ 高级选项 ------------------------------ */

#[component]
fn CardAdv(cfg: Value) -> impl IntoView {
    let loglevel = cfg_str_or(&cfg, "log_level", "info");
    let logformat = cfg_str_or(&cfg, "log_format", "text");
    let lv = |v: &str| loglevel == v;
    let lf = |v: &str| logformat == v;

    view! {
        <div class="card adv-card">
            <div class="card-hd">
                <span class="t">"高级选项"</span>
                <span class="s">"advanced"</span>
            </div>
            <div class="card-bd">
                <div class="cfg-row">
                    <div class="lab">
                        "EDNS0 总开关"
                        <small>"出站是否携带 EDNS0 OPT 记录(含 UDP size 扩展)"</small>
                    </div>
                    <div class="val">
                        <label class="switch">
                            <input type="checkbox" id="cfg-edns" prop:checked=cfg_bool(&cfg, "edns", true) />
                            <span class="sl"></span>
                        </label>
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "DNS 0x20 投毒防护"
                        <small>"大小写随机化查询名, 提高缓存投毒难度"</small>
                    </div>
                    <div class="val">
                        <label class="switch">
                            <input type="checkbox" id="cfg-dnssec0x20" prop:checked=cfg_bool(&cfg, "dnssec_0x20", false) />
                            <span class="sl"></span>
                        </label>
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "候选 IP 测速开关"
                        <small>"对 A/AAAA 候选地址做 RTT 测速并择优返回"</small>
                    </div>
                    <div class="val">
                        <label class="switch">
                            <input type="checkbox" id="cfg-ipspeedcheck" prop:checked=cfg_bool(&cfg, "ip_speed_check", false) />
                            <span class="sl"></span>
                        </label>
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "健康检查周期"
                        <small>"s · 0=关闭主动健康检查"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-healthint"
                            min="0"
                            max="86400"
                            step="10"
                            placeholder="0"
                            prop:value=cfg_num_s(&cfg, "health_check_interval", 0.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "规则订阅更新周期"
                        <small>"自动重新拉取上方“规则订阅”链接的规则列表(写入 rules_sub.json 并重建索引) · 0=不自动更新"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-rulesubint"
                            min="0"
                            max="604800"
                            step="60"
                            placeholder="0"
                            prop:value=cfg_num_s(&cfg, "rule_sub_interval", 0.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "Bootstrap DNS"
                        <small>"引导解析 DoH/DoT 主机名用的普通 DNS 地址(仅支持单个, host:port 格式)"</small>
                    </div>
                    <div class="val">
                        <input
                            class="text"
                            type="text"
                            id="cfg-bootstrapdns"
                            placeholder="如 223.5.5.5:53"
                            spellcheck="false"
                            autocomplete="off"
                            prop:value=cfg_str(&cfg, "bootstrap_dns")
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "熔断失败阈值"
                        <small>"连续失败次数后打开熔断(默认 3, 范围 1-100)"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-circfails"
                            min="1"
                            max="100"
                            step="1"
                            prop:value=cfg_num_s(&cfg, "circuit_fails", 3.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "熔断打开时长"
                        <small>"s · 超时后半开探测(默认 30, 范围 1-86400)"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-circopens"
                            min="1"
                            max="86400"
                            step="5"
                            prop:value=cfg_num_s(&cfg, "circuit_open_s", 30.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "健康检查探测域名"
                        <small>"绕过分流规则直连上游, 用于主动健康检查(默认 www.baidu.com)"</small>
                    </div>
                    <div class="val">
                        <input
                            class="text"
                            type="text"
                            id="cfg-healthdomain"
                            placeholder="www.baidu.com"
                            spellcheck="false"
                            autocomplete="off"
                            prop:value=cfg_str_or(&cfg, "health_probe_domain", "www.baidu.com")
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "健康检查探测超时"
                        <small>"ms · 主动健康检查单次探测超时(默认 2000)"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-healthtimeout"
                            min="100"
                            max="60000"
                            step="100"
                            prop:value=cfg_num_s(&cfg, "health_probe_timeout_ms", 2000.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "日志级别"
                        <small>"debug/info/warning/error · 重启后生效"</small>
                    </div>
                    <div class="val">
                        <select class="q-sel" id="cfg-loglevel" prop:value=loglevel.clone()>
                            <option value="debug" selected=lv("debug")>"debug"</option>
                            <option value="info" selected=lv("info")>"info"</option>
                            <option value="warning" selected=lv("warning")>"warning"</option>
                            <option value="error" selected=lv("error")>"error"</option>
                        </select>
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "日志格式"
                        <small>"text=可读文本 · json=结构化 JSON · 重启后生效"</small>
                    </div>
                    <div class="val">
                        <select class="q-sel" id="cfg-logformat" prop:value=logformat.clone()>
                            <option value="text" selected=lf("text")>"text"</option>
                            <option value="json" selected=lf("json")>"json"</option>
                        </select>
                    </div>
                </div>
                /* ---- **2.1.18（修复项 7）：此前不可达的可调键（补控件）** ---- */
                <div class="cfg-row">
                    <div class="lab">
                        "在途查询合并"
                        <small>"同键并发 miss 合并为一次上游扇出 · 默认开启（关闭 = 逐条查上游的旧行为）"</small>
                    </div>
                    <div class="val">
                        <label class="switch">
                            <input type="checkbox" id="cfg-singleflight" prop:checked=cfg_bool(&cfg, "single_flight", true) />
                            <span class="sl"></span>
                        </label>
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "UDP 收包并行度"
                        <small>"每地址 socket/收包循环数 · 0=自动(CPU 核数, 封顶 8) · 1=单 socket 旧行为 · 1-64"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-udpworkers"
                            min="0"
                            max="64"
                            step="1"
                            prop:value=cfg_num_s(&cfg, "udp_workers", 0.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "上游连接池预热"
                        <small>"构造/热重载后为每个启用上游异步发 N 条探测查询(建 TLS/QUIC 会话与滑窗样本)"</small>
                    </div>
                    <div class="val">
                        <label class="switch">
                            <input type="checkbox" id="cfg-warmup-enabled" prop:checked=cfg_warmup_bool(&cfg, "enabled", true) />
                            <span class="sl"></span>
                        </label>
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "预热查询条数"
                        <small>"每上游探测条数 · 1-8（超出只会浪费上游配额）"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-warmup-queries"
                            min="1"
                            max="8"
                            step="1"
                            prop:value=cfg_warmup_num_s(&cfg, "queries", 3.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "预热探测超时"
                        <small>"ms · 预热单次探测超时(默认 3000) · 1-60000"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-warmup-timeout"
                            min="1"
                            max="60000"
                            step="100"
                            prop:value=cfg_warmup_num_s(&cfg, "timeout_ms", 3000.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "RFC 8020 父域负缓存推断"
                        <small>"被查询名的祖先已登记 NXDOMAIN 时直接判负(不发上游) · 默认开启"</small>
                    </div>
                    <div class="val">
                        <label class="switch">
                            <input type="checkbox" id="cfg-rfc8020" prop:checked=cfg_bool(&cfg, "rfc8020_infer", true) />
                            <span class="sl"></span>
                        </label>
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "推断深度上限"
                        <small>"登记的标签数上限，超过不登记也不匹配(防过度泛化) · 1-127"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-rfc8020-labels"
                            min="1"
                            max="127"
                            step="1"
                            prop:value=cfg_num_s(&cfg, "rfc8020_max_labels", 8.0)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "上游评分成功率下限"
                        <small>"score 惩罚分母 max(sr, 本值) · 0.001-1（越小惩罚越重；0 会把上游饿死，故拒绝）"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-ratingsrfloor"
                            min="0.001"
                            max="1"
                            step="0.05"
                            prop:value=cfg_num_s(&cfg, "rating_sr_floor", 0.5)
                        />
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "对冲延迟因子"
                        <small>"对冲时刻 = 候选 p90 × 本值（冷启动用 hedge_after_ms 兜底）· 0.001-100"</small>
                    </div>
                    <div class="val">
                        <input
                            class="num"
                            type="number"
                            id="cfg-hedgeslowest"
                            min="0.001"
                            max="100"
                            step="0.1"
                            prop:value=cfg_num_s(&cfg, "hedge_slowest_factor", 1.0)
                        />
                    </div>
                </div>
                /* ---- **2.1.18（修复项 7）：只读 / 服务端管理项（只读展示）** ---- */
                <details class="cfg-readonly" id="cfg-readonly-box">
                    <summary>
                        {move || {
                            let n = READONLY_KEYS.len();
                            format!("只读 / 服务端管理项（{n} 项 · 保存时原值保持不变 · 点击展开）")
                        }}
                    </summary>
                    <div class="hint" style="margin:6px 0 10px">
                        "这些键由配置文件或服务端管理，控制台不写入它们。需要修改请编辑 /etc/ebpdns/config.json 后重启服务。"
                    </div>
                    <table class="tbl" id="cfg-readonly-tbl">
                        <thead>
                            <tr>
                                <th style="width:170px">"键"</th>
                                <th style="width:220px">"当前值（服务端）"</th>
                                <th>"为什么只读 / 要改怎么办"</th>
                            </tr>
                        </thead>
                        <tbody>
                            {move || {
                                let app = expect_context::<App>();
                                let reasons = app.readonly_reasons.get();
                                readonly_rows(&cfg, &reasons)
                                    .into_iter()
                                    .map(|(k, v, why)| {
                                        view! {
                                            <tr>
                                                <td><code>{k}</code></td>
                                                <td title=v.clone()>{v.clone()}</td>
                                                <td>{why}</td>
                                            </tr>
                                        }
                                    })
                                    .collect_view()
                            }}
                        </tbody>
                    </table>
                </details>
            </div>
        </div>
    }
}

/// `warmup` 对象键的布尔子键（缺失 → 默认；对象缺失 → 默认）。
///
/// **2.1.18（修复项 7）**：`warmup` 是**对象**（`{enabled, queries, timeout_ms}`），
/// 因此不能用 `cfg_bool`（那个只读顶层键）。`main.rs::apply_cfg` 也支持扁平别名
/// `warmup_enabled` / `warmup_queries` / `warmup_timeout_ms`，故这里**优先读子键、
/// 回退别名**，与后端读取口径一致。
fn cfg_warmup_bool(c: &Value, sub: &str, d: bool) -> bool {
    c.get("warmup")
        .and_then(|w| w.get(sub))
        .and_then(Value::as_bool)
        .or_else(|| c.get(format!("warmup_{sub}")).and_then(Value::as_bool))
        .unwrap_or(d)
}

/// `warmup` 对象键的数值子键（缺失 → 默认；回退扁平别名）。
fn cfg_warmup_num_s(c: &Value, sub: &str, d: f64) -> String {
    let v = c
        .get("warmup")
        .and_then(|w| w.get(sub))
        .and_then(Value::as_f64)
        .or_else(|| c.get(format!("warmup_{sub}")).and_then(Value::as_f64))
        .unwrap_or(d);
    if v.fract() == 0.0 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

/* ------------------------------ ⑤ 分流规则 ------------------------------ */

/// **2.1.30**：规则卡片的计数文案 —— 必须同时给出"本地 / 订阅"，不能只显示本地。
///
/// 背景（还原后的真实数据）：`/api/rules.total` 只数本地（0），而订阅展开 102,221 条只在
/// `/api/pipeline.rules` 里体现 ⇒ 只显示一个数字会让用户误以为"规则为 0"。
fn rule_split_text(local: usize, subscription: u64) -> String {
    format!(
        "本地 {} 条 / 订阅 {} 条 · 独立文件 rules_local.json",
        local, subscription
    )
}

/// 订阅条数合计：逐条取 `count`（缺失/非整数按 0；不把整块缺失误报成 0，由调用方另注）。
fn subscription_count_total(subs: &[Value]) -> u64 {
    subs.iter()
        .filter_map(|s| s.get("count").and_then(Value::as_u64))
        .sum()
}

#[component]
fn CardRules(rules: RwSignal<Vec<Value>>, subs: RwSignal<Vec<Value>>) -> impl IntoView {
    let app = expect_context::<App>();
    // 本地 UI 状态（对齐 #sub-action / #import-action 的默认选中值）。
    let sub_action = RwSignal::new("block".to_string());
    let imp_action = RwSignal::new("group".to_string());

    let on_import = move |_| act_import(app);
    let on_subscribe = move |_| act_subscribe(app);

    view! {
        <div class="card rule-card">
            <div class="card-hd">
                <span class="t">"分流规则"</span>
                <span class="s">"domain rules"</span>
            </div>
            <div class="card-bd flush">
                <div class="sub-sec">
                    <div class="sub-hd">
                        "规则订阅 "
                        <small>"链接订阅 · 明细存独立文件 rules_sub.json · 不写入 config.json"</small>
                    </div>
                    <div id="rule-sub-list" class="sub-list">
                        {move || {
                            let list = subs.get();
                            if list.is_empty() {
                                return view! {
                                    <div class="note" style="padding:4px 2px">
                                        "暂无数据 · 在下方输入订阅链接添加"
                                    </div>
                                }
                                    .into_any();
                            }
                            list.into_iter()
                                .map(|s| view! { <SubRow s=s /> })
                                .collect_view()
                                .into_any()
                        }}
                    </div>
                    <div class="cfg-row import-row">
                        <input
                            class="text"
                            id="sub-url-input"
                            placeholder="订阅链接 https://.../list.txt (域名/Adblock/hosts 列表均可)"
                            spellcheck="false"
                            autocomplete="off"
                            style="flex:2;min-width:0"
                            on:keydown=move |ev| {
                                if ev.key() == "Enter" {
                                    act_subscribe(app);
                                }
                            }
                        />
                        <select
                            class="q-sel"
                            id="sub-action"
                            on:change=move |ev| sub_action.set(ev_sel_value(&ev))
                        >
                            <option value="block">"屏蔽"</option>
                            <option value="allow">"放行（白名单）"</option>
                            <option value="group">"使用分组"</option>
                            <option value="forceIp">"强制 IP"</option>
                        </select>
                        <select
                            class="q-sel"
                            id="sub-group"
                            style:display=move || {
                                if sub_action.get() == "group" { "" } else { "none" }
                            }
                        >
                            <option value="domestic">"国内"</option>
                            <option value="global">"海外"</option>
                        </select>
                        <input
                            class="text"
                            id="sub-ip"
                            placeholder="强制 IP（留空默认 1.2.3.4）"
                            style:width="90px"
                            style:flex="0 0 90px"
                            style:display=move || {
                                if sub_action.get() == "forceIp" { "" } else { "none" }
                            }
                            spellcheck="false"
                            autocomplete="off"
                        />
                        <button class="btn primary" id="btn-sub-rule" on:click=on_subscribe>
                            "订阅"
                        </button>
                    </div>
                </div>
                <div class="sub-sec">
                    <div class="sub-hd">
                        "逐条规则 "
                        <small>{move || rule_split_text(rules.get().len(), subscription_count_total(&subs.get()))}</small>
                    </div>
                    <div id="rule-list">
                        {move || {
                            let list = rules.get();
                            let total = list.len();
                            let truncated = total > RULE_RENDER_LIMIT;
                            let visible: Vec<Value> = if truncated {
                                list.into_iter().take(RULE_RENDER_LIMIT).collect()
                            } else {
                                list
                            };
                            view! {
                                {truncated
                                    .then(|| {
                                        view! {
                                            <div
                                                class="empty"
                                                style="padding:14px;text-align:center;color:var(--text3);border-bottom:1px solid var(--line);"
                                            >
                                                "本地规则共 "
                                                <b style="color:var(--amber)">{total}</b>
                                                " 条, 为避免浏览器卡顿仅显示前 500 条。大规模规则请使用上方「规则订阅」方式管理。"
                                            </div>
                                        }
                                    })}
                                {visible
                                    .into_iter()
                                    .map(|r| view! { <RuleRow r=r rules=rules /> })
                                    .collect_view()}
                            }
                        }}
                    </div>
                    <div class="cfg-row import-row">
                        <input
                            class="text"
                            id="import-input"
                            placeholder="输入域名直接添加或批量导入, 如 baidu.com / *.taobao.com (逗号/换行分隔可批量; 默认自动按 *.domain 通配添加)"
                            spellcheck="false"
                            autocomplete="off"
                            on:keydown=move |ev| {
                                if ev.key() == "Enter" {
                                    act_import(app);
                                }
                            }
                        />
                        <select
                            class="q-sel"
                            id="import-action"
                            on:change=move |ev| imp_action.set(ev_sel_value(&ev))
                        >
                            <option value="group">"使用分组"</option>
                            <option value="block">"屏蔽"</option>
                            <option value="forceIp">"强制 IP"</option>
                            <option value="allow">"放行（白名单）"</option>
                        </select>
                        <select
                            class="q-sel"
                            id="import-group"
                            style:display=move || {
                                if imp_action.get() == "group" { "" } else { "none" }
                            }
                        >
                            <option value="domestic">"国内"</option>
                            <option value="global">"海外"</option>
                        </select>
                        <input
                            class="text"
                            id="import-ip"
                            placeholder="强制 IP（留空默认 1.2.3.4）"
                            style:width="90px"
                            style:flex="0 0 90px"
                            style:display=move || {
                                if imp_action.get() == "forceIp" { "" } else { "none" }
                            }
                            spellcheck="false"
                            autocomplete="off"
                        />
                        <button class="btn primary" id="btn-import-rule" on:click=on_import>
                            "导入"
                        </button>
                    </div>
                </div>
                <div class="cfg-actions">
                    <span class="note" style="padding:8px 16px;font-size:13.5px;line-height:2">
                        <b>"规则匹配类型"</b>
                        "（在左侧\"逐条规则\"输入框填写，回车即添加；动作可选\"屏蔽 / 使用分组 / 强制 IP / 放行\"）"
                        <br />
                        "① "
                        <b>"*.example.com"</b>
                        " 通配 —— 匹配 example.com 及其全部子域名"
                        <br />
                        "② "
                        <b>"re:正则"</b>
                        " 正则匹配 —— 如 re:.*\\.ads\\.com$（匹配以 ads.com 结尾的域名）"
                        <br />
                        <b>"匹配优先级：精确 > 通配 > 正则"</b>
                        "；URL 订阅请使用上方订阅栏"
                    </span>
                </div>
            </div>
        </div>
    }
}

/// 订阅响应里的条数（D8）。
///
/// 实读后端（crates/ebpdns-server/src/subscribe.rs）：
/// - `POST /api/rules/subscribe`     → `{"ok":true,"url":url,"count":N,"added":0|1}`（:863）
/// - `POST /api/rules/subscribe/update` → `{"ok":true,"url":url,"count":N}`（:920）
///
/// `count` 非有限/缺失时返回 None——**不能**再 `.unwrap_or(0.0)` 静默显示「0 条」。
fn subscribe_count(v: &Value) -> Option<f64> {
    v.get("count")
        .and_then(Value::as_f64)
        .filter(|n| n.is_finite())
}

/// 订阅响应 → 追加到提示文案的后缀：有计数显示条数，无计数则显示后端原文。
fn subscribe_count_text(v: &Value) -> String {
    match subscribe_count(v) {
        Some(n) => {
            let added = v.get("added").and_then(Value::as_f64);
            if added == Some(1.0) {
                format!(": 新建订阅, {} 条规则", fmt::num0(n))
            } else {
                format!(": {} 条规则", fmt::num0(n))
            }
        }
        None => {
            let raw = v.to_string();
            if raw.is_empty() || raw == "null" {
                "（已提交, 后端未返回计数）".to_string()
            } else {
                format!("（已提交, 后端未返回计数）· 后端响应 {raw}")
            }
        }
    }
}

/// 订阅行（`#rule-sub-list` 内一项）。
#[component]
fn SubRow(s: Value) -> impl IntoView {
    let app = expect_context::<App>();
    let url = cfg_str(&s, "url");
    let count = cfg_f64(&s, "count", 0.0);
    let updated = cfg_str_or(&s, "updated_at", "-");
    let action = cfg_str(&s, "action");
    let action_txt = {
        let l = action_label(&action);
        if l.is_empty() {
            action.clone()
        } else {
            l.to_string()
        }
    };
    let url_update = url.clone();
    let url_del = url.clone();
    let url_del2 = url.clone();
    let url_title = url.clone();

    view! {
        <div class="sub-item">
            <span class="su" title=url_title>
                {url}
            </span>
            <span class="sm">
                <b>{fmt::num0(count)}</b>
                " 条"
            </span>
            <span class="sm">{updated}</span>
            <span class="sm">{action_txt}</span>
            <button
                class="btn"
                data-subupdate=url_update.clone()
                on:click=move |_| {
                    let url = url_update.clone();
                    app.note_set("正在更新订阅…", NoteKind::Info);
                    spawn_local(async move {
                        match api::subscribe_update(&url).await {
                            Ok(v) => {
                                // D8：`count` 取不到时显示后端原文，不再静默显示「0 条」。
                                app.note_set(
                                    format!("订阅更新完成{}", subscribe_count_text(&v)),
                                    NoteKind::Ok,
                                );
                                refresh_config(app).await;
                            }
                            Err(e) => app.note_set(format!("订阅更新失败: {e}"), NoteKind::Err),
                        }
                    });
                }
            >
                "更新"
            </button>
            <button
                class="del"
                data-subdel=url_del.clone()
                on:click=move |_| {
                    let url = url_del2.clone();
                    if let Some(win) = web_sys::window() {
                        let ok = win
                            .confirm_with_message(&format!(
                                "删除订阅 {url}？\n（仅移除订阅，不影响逐条规则）",
                            ))
                            .unwrap_or(false);
                        if !ok {
                            return;
                        }
                    }
                    spawn_local(async move {
                        match api::subscribe_delete(&url).await {
                            Ok(_) => {
                                app.note_set("订阅已删除", NoteKind::Ok);
                                refresh_config(app).await;
                            }
                            Err(e) => app.note_set(format!("删除失败: {e}"), NoteKind::Err),
                        }
                    });
                }
            >
                "×"
            </button>
        </div>
    }
}

/// 逐条规则行（`#rule-list` 内一条，class/id 照抄原件 2352–2375 行）。
#[component]
fn RuleRow(r: Value, rules: RwSignal<Vec<Value>>) -> impl IntoView {
    let id = cfg_str(&r, "id");
    let action = cfg_str_or(&r, "action", "group");
    let group = cfg_str_or(&r, "group", "domestic");
    // 规则级 TTL：留空 = 继承全局（对齐原件 `r.ttl_min != null && r.ttl_min !== ''`）
    let ttl_min = opt_field_s(&r, "ttl_min");
    let ttl_max = opt_field_s(&r, "ttl_max");

    let id_match = id.clone();
    let id_action = id.clone();
    let id_group = id.clone();
    let id_ip = id.clone();
    let id_tmin = id.clone();
    let id_tmax = id.clone();
    let id_del = id.clone();

    view! {
        <div class="cfg-row">
            <input
                class="text"
                data-r="match"
                data-id=id.clone()
                prop:value=cfg_str(&r, "match")
                placeholder="*.example.com"
                style="width:150px"
                on:change=move |ev| row_set(rules, &id_match, "match", json!(ev_value(&ev)))
            />
            <select
                class="q-sel"
                data-r="action"
                data-id=id.clone()
                on:change=move |ev| row_set(rules, &id_action, "action", json!(ev_sel_value(&ev)))
            >
                <option value="group" selected=action == "group">
                    "使用分组"
                </option>
                <option value="forceIp" selected=action == "forceIp">
                    "强制 IP"
                </option>
                <option value="block" selected=action == "block">
                    "屏蔽"
                </option>
                <option value="allow" selected=action == "allow">
                    "放行（白名单）"
                </option>
            </select>
            {if action == "group" {
                let id_g = id_group.clone();
                Some(
                    view! {
                        <select
                            class="q-sel"
                            data-r="group"
                            data-id=id.clone()
                            on:change=move |ev| {
                                row_set(rules, &id_g, "group", json!(ev_sel_value(&ev)))
                            }
                        >
                            <option value="domestic" selected=group == "domestic">
                                "国内"
                            </option>
                            <option value="global" selected=group == "global">
                                "海外"
                            </option>
                        </select>
                    },
                )
            } else {
                None
            }}
            {if action == "forceIp" {
                let id_i = id_ip.clone();
                Some(
                    view! {
                        <input
                            class="text"
                            data-r="ip"
                            data-id=id.clone()
                            prop:value=cfg_str(&r, "ip")
                            placeholder="1.2.3.4"
                            style="width:110px"
                            on:change=move |ev| {
                                row_set(rules, &id_i, "ip", json!(ev_value(&ev)))
                            }
                        />
                    },
                )
            } else {
                None
            }}
            <input
                class="num"
                data-r="ttl_min"
                data-id=id.clone()
                type="number"
                min="0"
                max="2147483647"
                step="5"
                prop:value=ttl_min
                placeholder="TTL↓"
                title="规则级 TTL 下限（s），覆盖全局下发 TTL 下限；留空继承全局"
                style="width:56px"
                on:change=move |ev| {
                    let raw = ev_value(&ev).trim().to_string();
                    let id = id_tmin.clone();
                    rules.update(move |l| {
                        if let Some(o) = find_obj_mut(l, &id) {
                            if raw.is_empty() {
                                o.remove("ttl_min");
                            } else {
                                let v: f64 = raw.parse().unwrap_or(0.0);
                                // `parse("NaN")` 可得到 NaN：max/min 会回退 0，而 clamp 会传播 NaN。
                                #[allow(clippy::manual_clamp)]
                                o.insert("ttl_min".into(), num_json(v.max(0.0).min(2147483647.0)));
                            }
                        }
                    });
                }
            />
            <input
                class="num"
                data-r="ttl_max"
                data-id=id.clone()
                type="number"
                min="0"
                max="2147483647"
                step="5"
                prop:value=ttl_max
                placeholder="TTL↑"
                title="规则级 TTL 上限（s），覆盖全局下发 TTL 上限；留空继承全局"
                style="width:56px"
                on:change=move |ev| {
                    let raw = ev_value(&ev).trim().to_string();
                    let id = id_tmax.clone();
                    rules.update(move |l| {
                        if let Some(o) = find_obj_mut(l, &id) {
                            if raw.is_empty() {
                                o.remove("ttl_max");
                            } else {
                                let v: f64 = raw.parse().unwrap_or(0.0);
                                // 同上：保留 NaN 输入下的 max/min 回退语义。
                                #[allow(clippy::manual_clamp)]
                                o.insert("ttl_max".into(), num_json(v.max(0.0).min(2147483647.0)));
                            }
                        }
                    });
                }
            />
            <button
                class="del"
                data-delrule=id.clone()
                style="margin-left:auto"
                on:click=move |_| row_remove(rules, &id_del)
            >
                "×"
            </button>
        </div>
    }
}

/* ------------------------------ ⑥ 上游服务器 ------------------------------ */

#[component]
fn CardUpstreams(ups: RwSignal<Vec<Value>>) -> impl IntoView {
    let app = expect_context::<App>();
    let on_add = move |_| act_add_up(app, ups);

    view! {
        <div class="card up-card">
            <div class="card-hd">
                <span class="t">"上游服务器"</span>
                <span class="s">"upstreams"</span>
            </div>
            <div class="card-bd flush">
                <div style="padding:4px 16px 0">
                    <div
                        class="up-row"
                        style="border-bottom:1px solid var(--line); padding-bottom:6px; font-family:var(--font-mono); font-size:13px; color:var(--text3); letter-spacing:.6px"
                    >
                        <span></span>
                        <span>"名称"</span>
                        <span>"协议"</span>
                        <span>"完整地址"</span>
                        <span>"端口"</span>
                        <span>"分组"</span>
                        <span>"基础延迟"</span>
                        <span>"高级"</span>
                        <span>"连接健康度"</span>
                        <span></span>
                    </div>
                    <div id="up-list">
                        {move || {
                            ups.get()
                                .into_iter()
                                .map(|u| view! { <UpRow u=u ups=ups /> })
                                .collect_view()
                        }}
                    </div>
                </div>
                <div class="cfg-row up-add-row">
                    <input
                        class="text"
                        id="up-add-addr"
                        placeholder="输入完整地址直接添加, 如 https://doh.opendns.com/dns-query / http3://dns.alidns.com/dns-query / quic://dns.nextns.io / 223.5.5.5（自动识别协议端口; 支持 https/http/quic/doq/tls/dot/udp/tcp/doh/doh3/http3/h3 前缀）"
                        spellcheck="false"
                        autocomplete="off"
                        style="flex:3;min-width:0"
                        on:keydown=move |ev| {
                            if ev.key() == "Enter" {
                                act_add_up(app, ups);
                            }
                        }
                    />
                    <select class="q-sel" id="up-add-proto" prop:value="auto".to_string()>
                        <option value="auto" selected=true>
                            "自动"
                        </option>
                        <option value="udp">"UDP"</option>
                        <option value="tcp">"TCP"</option>
                        <option value="doh">"DoH"</option>
                        <option value="dot">"DoT"</option>
                        <option value="doq">"DoQ"</option>
                        <option value="doh3">"DoH3"</option>
                    </select>
                    <select class="q-sel" id="up-add-group">
                        <option value="domestic">"国内"</option>
                        <option value="global">"海外"</option>
                    </select>
                    <button class="btn primary" id="btn-add-up" on:click=on_add>
                        <svg
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="currentColor"
                            stroke-width="2.2"
                            stroke-linecap="round"
                        >
                            <path d="M12 5v14M5 12h14"></path>
                        </svg>
                        "添加"
                    </button>
                </div>
                <div class="cfg-actions">
                    <button class="btn" id="btn-reprobe" on:click=move |_| act_reprobe(app)>
                        <svg
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="currentColor"
                            stroke-width="2.2"
                            stroke-linecap="round"
                            stroke-linejoin="round"
                        >
                            <path d="M13 2L4.5 12.5H11L9.5 22 19 10.5h-6.5z"></path>
                        </svg>
                        "一键重新测速"
                    </button>
                    <span class="note">"解析时并发全部可用上游做测速择优 · 回车直接添加"</span>
                </div>
            </div>
        </div>
    }
}

/// 上游行（10 列，照抄原件 2296–2351 行 DOM）。
#[component]
fn UpRow(u: Value, ups: RwSignal<Vec<Value>>) -> impl IntoView {
    let app = expect_context::<App>();
    let id = cfg_str(&u, "id");
    let proto_l = {
        let p = cfg_str(&u, "proto").to_lowercase();
        if p.is_empty() {
            "udp".to_string()
        } else {
            p
        }
    };
    let full = full_addr(&u);
    let port = cfg_f64(&u, "port", 53.0);
    let port_i = port as i64;
    let group = cfg_str_or(&u, "group", "domestic");
    let latency = cfg_f64(&u, "latency", 0.0);
    let latency_measured = cfg_bool(&u, "latency_measured", false);
    let enabled = cfg_bool(&u, "enabled", false);
    let weight_s = cfg_num_s(&u, "weight", 1.0);
    let allow_priv = cfg_bool(&u, "allow_private_ip", false);
    let cert = |k: &str| cfg_bool(&u, k, true);

    let id_name = id.clone();
    let id_proto = id.clone();
    let id_full = id.clone();
    let id_port = id.clone();
    let id_group = id.clone();
    let id_lat = id.clone();
    let id_w = id.clone();
    let id_ap = id.clone();
    let id_d1 = id.clone();
    let id_d2 = id.clone();
    let id_d3 = id.clone();
    let id_d4 = id.clone();
    let id_del = id.clone();
    let id_enabled = id.clone();

    let old_proto = proto_l.clone();
    let proto_f = proto_l.clone();
    let old_port = port;
    let restore_full = full.clone();

    // 连接级健康度徽标（对齐 `connBadge`；数据源为 2s `/api/snapshot.upstreams[]`，D14）。
    // 用闭包读取 `app.snapshot` 使其随轮询刷新——snapshot 更新不会重建配置表单
    // （`cfg_epoch` 不变），只重建这一个徽标节点。
    let u_conn = u.clone();
    let conn_badge = move || conn_badge_view(&conn_metrics(app.snapshot.get().as_ref(), &u_conn));

    view! {
        <div class="up-row">
            <label class="switch">
                <input
                    type="checkbox"
                    data-f="enabled"
                    data-id=id.clone()
                    prop:checked=enabled
                    on:change=move |ev| {
                        row_set(ups, &id_enabled, "enabled", json!(ev_checked(&ev)))
                    }
                />
                <span class="sl"></span>
            </label>
            <input
                class="text"
                data-f="name"
                data-id=id.clone()
                prop:value=cfg_str(&u, "name")
                title="上游名称"
                on:change=move |ev| row_set(ups, &id_name, "name", json!(ev_value(&ev)))
            />
            <select
                class="q-sel"
                data-f="proto"
                data-id=id.clone()
                on:change=move |ev| {
                    let np = ev_sel_value(&ev);
                    let id = id_proto.clone();
                    let op = old_proto.clone();
                    let np2 = np.clone();
                    ups.update(move |l| {
                        if let Some(o) = find_obj_mut(l, &id) {
                            o.insert("proto".into(), json!(np2));
                            if (old_port - (up_port_default(&op) as f64)).abs() < f64::EPSILON {
                                o.insert("port".into(), json!(up_port_default(&np)));
                            }
                        }
                    });
                }
            >
                {PROTO_ORDER
                    .iter()
                    .map(|p| {
                        view! {
                            <option value=*p selected=proto_l.as_str() == *p>
                                {proto_label(p)}
                            </option>
                        }
                    })
                    .collect_view()}
            </select>
            <input
                class="text"
                data-f="fulladdr"
                data-id=id.clone()
                prop:value=full.clone()
                spellcheck="false"
                title="完整 DNS 地址, 可直接编辑(如 https://dns.alidns.com/dns-query / http3://dns.alidns.com/dns-query / quic://223.5.5.5 / udp://119.29.29.29; 支持 https/http/quic/doq/tls/dot/udp/tcp/doh/doh3/http3/h3 前缀)"
                on:change=move |ev| {
                    let el = ev.target().and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok());
                    let raw = el.as_ref().map(|e| e.value()).unwrap_or_default();
                    match parse_upstream_addr(&raw, &proto_f) {
                        Err(msg) => {
                            app.note_set(msg, NoteKind::Err);
                            if let Some(e) = el {
                                e.set_value(&restore_full);
                            }
                        }
                        Ok(p) => {
                            let explicit = has_explicit_port(&raw);
                            let id = id_full.clone();
                            ups.update(move |l| {
                                if let Some(o) = find_obj_mut(l, &id) {
                                    o.insert("proto".into(), json!(p.proto));
                                    o.insert("addr".into(), json!(p.addr));
                                    o.insert("url".into(), json!(p.url));
                                    let keep = if explicit {
                                        p.port
                                    } else if old_port > 0.0 {
                                        old_port as i64
                                    } else {
                                        p.port
                                    };
                                    o.insert("port".into(), json!(keep));
                                }
                            });
                        }
                    }
                }
            />
            <select
                class="q-sel"
                data-f="port"
                data-id=id.clone()
                on:change=move |ev| {
                    let v: f64 = ev_sel_value(&ev).parse().unwrap_or(53.0);
                    row_set(ups, &id_port, "port", num_json(v));
                }
            >
                {PORT_OPTS
                    .iter()
                    .map(|p| {
                        view! {
                            <option value=p.to_string() selected=port_i == *p>
                                {p.to_string()}
                            </option>
                        }
                    })
                    .collect_view()}
                {(!PORT_OPTS.contains(&port_i))
                    .then(|| {
                        view! {
                            <option value=port_i.to_string() selected=true>
                                {port_i.to_string()}
                            </option>
                        }
                    })}
            </select>
            <select
                class="q-sel"
                data-f="group"
                data-id=id.clone()
                on:change=move |ev| row_set(ups, &id_group, "group", json!(ev_sel_value(&ev)))
            >
                <option value="domestic" selected=group == "domestic">
                    "国内"
                </option>
                <option value="global" selected=group == "global">
                    "海外"
                </option>
            </select>
            {if latency > 0.0 {
                let id_l = id_lat.clone();
                view! {
                    <input
                        class="num"
                        type="number"
                        data-f="latency"
                        data-id=id.clone()
                        min="1"
                        max="3600000"
                        prop:value=num_disp(latency)
                        title="基础延迟(ms), 实时查询延迟以遥测为准; 上限 3600000ms(1h, 与 JS clamp 一致)"
                        on:change=move |ev| {
                            // `dom_ev_num` 在 DOM 目标非 input 时返回 NaN：max/min 回退 0，
                            // clamp 会传播 NaN，故保留原写法。
                            #[allow(clippy::manual_clamp)]
                            let v = dom_ev_num(&ev).max(0.0).min(3600000.0);
                            row_set(ups, &id_l, "latency", num_json(v));
                        }
                    />
                }
                    .into_any()
            } else {
                view! {
                    <span
                        class="lat-pending"
                        title=if latency_measured {
                            "已实测但延迟读数缺失"
                        } else {
                            "应用配置后自动实测延迟"
                        }
                    >
                        {if latency_measured { "N/A" } else { "待测" }}
                    </span>
                }
                    .into_any()
            }}
            <span class="up-opts">
                <label
                    class="up-opt up-weight-opt"
                    title="权重(加权轮询权重, 范围 1-1000, 默认 1, 支持小数; 小于1无效果, 与1相同; 数值越大被选中概率越高, 与实时延迟 eff_lat 加权计算配合)"
                >
                    <input
                        type="number"
                        class="up-weight"
                        data-f="weight"
                        data-id=id.clone()
                        min="1"
                        max="1000"
                        step="0.1"
                        prop:value=weight_s
                        on:change=move |ev| {
                            let raw = dom_ev_num(&ev);
                            let w = if raw.is_nan() {
                                1.0
                            } else {
                                raw.clamp(1.0, 1000.0)
                            };
                            row_set(ups, &id_w, "weight", num_json(w));
                        }
                    />
                    "权重"
                </label>
                <label
                    class="up-opt"
                    title="允许私网IP: 该上游可解析内网/私有地址(绕过 DNS rebind 防护; 所有协议可用, 后端缺省关闭)"
                >
                    <input
                        type="checkbox"
                        data-f="allow_private_ip"
                        data-id=id.clone()
                        prop:checked=allow_priv
                        on:change=move |ev| {
                            row_set(ups, &id_ap, "allow_private_ip", json!(ev_checked(&ev)))
                        }
                    />
                    "允许私网IP"
                </label>
                <label
                    class="up-opt"
                    title="严格证书校验(DoH, 后端缺省开启; 仅当协议为 DoH 时生效; 运行时读 doh_strict_cert)"
                >
                    <input
                        type="checkbox"
                        data-f="doh_strict_cert"
                        data-id=id.clone()
                        prop:checked=cert("doh_strict_cert")
                        prop:disabled=proto_l != "doh"
                        on:change=move |ev| {
                            row_set(ups, &id_d1, "doh_strict_cert", json!(ev_checked(&ev)))
                        }
                    />
                    "严格证书(DoH)"
                </label>
                <label
                    class="up-opt"
                    title="严格证书校验(DoH3/HTTP3, 后端缺省开启; 仅当协议为 DoH3 时生效; 运行时读 doh3_strict_cert, 与 DoH 的 doh_strict_cert 互不串键)"
                >
                    <input
                        type="checkbox"
                        data-f="doh3_strict_cert"
                        data-id=id.clone()
                        prop:checked=cert("doh3_strict_cert")
                        prop:disabled=proto_l != "doh3"
                        on:change=move |ev| {
                            row_set(ups, &id_d2, "doh3_strict_cert", json!(ev_checked(&ev)))
                        }
                    />
                    "严格证书(DoH3)"
                </label>
                <label
                    class="up-opt"
                    title="严格证书校验(DoT, 后端缺省开启; 仅当协议为 DoT 时生效; 运行时读 dot_strict_cert)"
                >
                    <input
                        type="checkbox"
                        data-f="dot_strict_cert"
                        data-id=id.clone()
                        prop:checked=cert("dot_strict_cert")
                        prop:disabled=proto_l != "dot"
                        on:change=move |ev| {
                            row_set(ups, &id_d3, "dot_strict_cert", json!(ev_checked(&ev)))
                        }
                    />
                    "严格证书(DoT)"
                </label>
                <label
                    class="up-opt"
                    title="严格证书校验(DoQ/QUIC, 后端缺省开启; 仅当协议为 DoQ 时生效; 运行时读 doq_strict_cert)"
                >
                    <input
                        type="checkbox"
                        data-f="doq_strict_cert"
                        data-id=id.clone()
                        prop:checked=cert("doq_strict_cert")
                        prop:disabled=proto_l != "doq"
                        on:change=move |ev| {
                            row_set(ups, &id_d4, "doq_strict_cert", json!(ev_checked(&ev)))
                        }
                    />
                    "严格证书(DoQ)"
                </label>
            </span>
            {conn_badge}
            <button class="del" data-del=id.clone() on:click=move |_| row_remove(ups, &id_del)>
                "×"
            </button>
        </div>
    }
}

/// 事件 → number 输入值（NaN 保留，供 weight 回退默认）。
fn dom_ev_num(ev: &leptos::ev::Event) -> f64 {
    ev.target()
        .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
        .map(|e| e.value_as_number())
        .unwrap_or(f64::NAN)
}

/* ------------------------------ 连接设置 / API Token ------------------------------ */

#[component]
fn CardConn() -> impl IntoView {
    let app = expect_context::<App>();
    let token0 = api::get_token();

    view! {
        <div class="card" id="conn-card">
            <div class="card-hd">
                <span class="t">"连接设置"</span>
                <span class="s">"api auth"</span>
            </div>
            <div class="card-bd">
                <div class="cfg-row">
                    <div class="lab">
                        "API Token"
                        <small>"后端配置了 api.token 时必填 · 仅存本浏览器(localStorage), 随 Authorization: Bearer 头发送 · 留空=不携带认证头"</small>
                    </div>
                    <div class="val" style="flex:2.4;min-width:0">
                        <div style="display:flex;gap:8px;align-items:center">
                            <input
                                class="text"
                                type="password"
                                id="api-token-input"
                                placeholder="粘贴 API Token (后端 config.json 中 api.token)"
                                spellcheck="false"
                                autocomplete="off"
                                style="flex:1;min-width:0;font-family:var(--font-mono)"
                                prop:value=token0
                                on:keydown=move |ev| {
                                    if ev.key() == "Enter" {
                                        act_save_token(app);
                                    }
                                }
                            />
                            <button class="btn primary" id="btn-save-token" on:click=move |_| act_save_token(app)>
                                "保存 Token"
                            </button>
                            <button class="btn" id="btn-clear-token" on:click=move |_| act_clear_token(app)>
                                "清除 Token"
                            </button>
                        </div>
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        "认证状态"
                        <small>"当前 token 是否已配置 + 与后端连通性"</small>
                    </div>
                    <div class="val">
                        <span id="api-token-status" style="font-size:13px;color:var(--text3)">
                            {move || app.token_status.get()}
                        </span>
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        <small style="color:var(--amber)">
                            "安全提示: Token 以明文存于本浏览器 localStorage(跨会话持久化、同源脚本/扩展可读)。 若把 api.host 改为 0.0.0.0 且走明文 HTTP,Bearer 头会在局域网明文传输可被嗅探—— token 泄露=控制台完全控制上游/规则。请仅在可信网络使用, 或经 HTTPS/反代暴露。"
                        </small>
                    </div>
                </div>
                <div class="cfg-row">
                    <div class="lab">
                        <small style="color:var(--amber)">
                            "访问地址提示: 默认 api.host=127.0.0.1 / 端口 8353，浏览器用 http://127.0.0.1:8353 读写。环回互通: api.host 为环回时, 读/写两条路径都把 localhost / 127.x / [::1] 视为等价(读/写两条路径对称; 旧二进制可能仍拒, 被 403 时请改用与 api.host 完全一致的主机名)。若把 api.host 改为局域网/公网 IP, 则地址栏 host:port 必须与后端 api.host 严格一致, 否则写操作(保存配置/删除规则/重启)会被 CSRF 校验拒 403。另: 无 Origin 头的本地工具直连(如 curl)按设计放行。"
                        </small>
                    </div>
                </div>
            </div>
        </div>
    }
}

/* ------------------------------ 底部：缓存策略 + 全局操作 ------------------------------ */

#[component]
fn CardFooter(
    ups: RwSignal<Vec<Value>>,
    rules: RwSignal<Vec<Value>>,
    subs: RwSignal<Vec<Value>>,
    // **2.1.19（修复项 5）**：是否有未保存的改动（由 [`ConfigPage`] 的委托监听置位）。
    // 注：参数位置用普通注释（`///` 在形参上不被 Rust 接受）。
    dirty: RwSignal<bool>,
) -> impl IntoView {
    let app = expect_context::<App>();

    let policy = cfg_str_or(
        &app.config.get_untracked().unwrap_or(Value::Null),
        "cache_policy",
        "lru",
    );
    let policy_text = move || {
        let app2 = app;
        let c = app2.config.get().unwrap_or(Value::Null);
        let s = app2.status.get();
        let cp = s
            .as_ref()
            // **2.1.43-B（P2-1）**：`cache_policy` 现在是 `Option<String>`（缺失 = 未下发）
            // ⇒ `and_then` 保留"缺失"，再用 `filter` 挡空串，最后回退到配置页的本地值。
            .and_then(|s| s.cache_policy.clone())
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| cfg_str(&c, "cache_policy"));
        if cp.is_empty() {
            return "缓存策略：–".to_string();
        }
        let label = match cp.as_str() {
            "tinylfu" => "W-TinyLFU",
            "partitioned" => "分区 LRU",
            _ => "LRU 分区",
        };
        let cap = match s {
            Some(st) if st.map.capacity.is_finite() => fmt::num0(st.map.capacity),
            _ => "–".to_string(),
        };
        format!("缓存策略：{label} · 容量 {cap}")
    };
    let udp_text = move || {
        let app2 = app;
        let n = app2.status.get().map(|s| s.udp_dropped).unwrap_or(0.0);
        format!("UDP 丢弃：{}", fmt::group0(n))
    };
    let note_text = move || app.note.get().text;
    let note_color = move || match app.note.get().kind {
        NoteKind::Ok => "var(--green)",
        NoteKind::Err => "var(--red)",
        NoteKind::Warn => "var(--amber)",
        NoteKind::Info => "",
    };

    // 对齐原件 `note()`：提示 2.6s 后自动回到默认文案（旧定时器以文案比对等效取消）。
    Effect::new(move |_| {
        let cur = app.note.get();
        if cur.kind == NoteKind::Info {
            return;
        }
        let expect = cur.text.clone();
        spawn_local(async move {
            gloo_timers::future::TimeoutFuture::new(2600).await;
            if app.note.get_untracked().text == expect {
                app.note_set(
                    "修改暂存于浏览器，点击「应用配置」下发到后端",
                    NoteKind::Info,
                );
            }
        });
    });

    view! {
            <div class="card">
                <div class="cfg-actions">
                    <span
                        style="font-size:12px;color:var(--text3);align-self:center"
                        id="cache-policy-label"
                    >
                        {policy_text}
                    </span>
                    <span
                        style="font-size:12px;color:var(--amber);align-self:center"
                        id="udp-dropped-label"
                        title="UDP 未命中队列满时丢弃的包数（客户端会重试）"
                    >
                        {udp_text}
                    </span>
                    <select
                        class="q-sel"
                        id="cfg-cache-policy"
                        title="缓存策略热切换 · 应用配置后自动热重载生效"
                        prop:value=policy.clone()
                    >
                        <option value="lru" selected=policy == "lru">
                            "LRU 分区"
                        </option>
                        <option value="partitioned" selected=policy == "partitioned">
                            "分区 LRU (partitioned)"
                        </option>
                        <option value="tinylfu" selected=policy == "tinylfu">
                            "W-TinyLFU"
                        </option>
                    </select>
                    // **2.1.18（修复项 5：⑫「配置页未保存可见反馈」）**：**未保存**的醒目提示。
                    // 未改动时整个节点不渲染（`None`）；一旦有表单输入或本地列表增删即出现
                    // （点击 = 直接保存，与已保存状态的操作路径一致）。
                    {move || {
                        dirty.get().then(|| {
                            view! {
                                <span
                                    id="cfg-dirty-hint"
                                    class="cfg-dirty-hint"
                                    title="表单里有改动尚未下发到服务器；点击这里或「应用配置」下发（切页/刷新会丢失）。"
                                    on:click=move |_| act_save(app, ups, rules, subs, dirty)
                                >
                                    "● 有未保存的更改"
                                </span>
                            }
                        })
                    }}
    // >>> 242B BEGIN P1-12-btn >>> //
                    <button
                        class="btn primary"
                        id="btn-save-cfg"
                        // **2.1.42-B（P1-12）**：配置未加载（首屏 GET 失败/超时）时禁用保存，
                        // 否则会用默认标量 + 空 upstreams/rules 整份 PUT 清空生产配置。
                        disabled=move || !app.config_loaded()
                        on:click=move |_| act_save(app, ups, rules, subs, dirty)
                    >
    // <<< 242B END P1-12-btn <<< //
                        <svg
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="currentColor"
                            stroke-width="2.2"
                            stroke-linecap="round"
                            stroke-linejoin="round"
                        >
                            <path d="M5 3h11.6v14H5z"></path>
                            <path d="M8 3v5h7V3M8 21v-7h8v7"></path>
                        </svg>
                        "应用配置"
                    </button>
                    <button class="btn" id="btn-reset-cfg" on:click=move |_| act_reset(app)>
                        <svg
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="currentColor"
                            stroke-width="2.2"
                            stroke-linecap="round"
                            stroke-linejoin="round"
                        >
                            <path d="M3 12a9 9 0 1 0 3-6.7L3 8"></path>
                            <path d="M3 3v5h5"></path>
                        </svg>
                        "重新载入服务器配置"
                    </button>
                    <button class="btn" id="btn-reload-cfg" on:click=move |_| act_reload(app)>
                        <svg
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="currentColor"
                            stroke-width="2.2"
                            stroke-linecap="round"
                            stroke-linejoin="round"
                        >
                            <path d="M21 2v6h-6"></path>
                            <path d="M3 12a9 9 0 0 1 15-6.7L21 8"></path>
                            <path d="M3 22v-6h6"></path>
                            <path d="M21 12a9 9 0 0 1-15 6.7L3 16"></path>
                        </svg>
                        "热重载"
                    </button>
                    <button class="btn danger" id="btn-restart-svc" on:click=move |_| act_restart(app)>
                        <svg
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="currentColor"
                            stroke-width="2.2"
                            stroke-linecap="round"
                            stroke-linejoin="round"
                        >
                            <path d="M21 12a9 9 0 1 1-3-6.7L21 8"></path>
                            <path d="M21 3v5h-5"></path>
                        </svg>
                        "重启服务"
                    </button>
                    <span class="note" id="cfg-saved-note" style:color=note_color>
                        {note_text}
                    </span>
                </div>
                <div style="padding:12px 20px; background:var(--bg2); border-radius:10px; margin-top:12px; font-size:13px; line-height:1.8; color:var(--text2)">
                    <div style="font-weight:600; color:var(--text, #e6e9ef); margin-bottom:6px">
                        "缓存策略说明"
                    </div>
                    <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px">
                        <div>
                            <b style="color:var(--cyan)">"LRU 分区"</b>
                            "（默认 · lru）"
                            <br />
                            "单实例分片 LRU（Rust LruCache）：全量 key 按哈希分到 8 个分片（每片一把独立锁），分片内用有序映射按最近使用排序；不做 group 分区（要分区请选 partitioned）。适合绝大多数场景。"
                        </div>
                        <div>
                            <b style="color:var(--cyan)">"分区 LRU"</b>
                            "（partitioned）"
                            <br />
                            "按分流 group 分区的缓存（Rust PartitionedCache）：每个 group 一个独立的 8 分片 LRU，总容量按权重分配。权重默认 domestic 0.2 / global 0.2 / default 0.6（cache_partitions=null）；自定义权重写成对象 {\"domestic\":0.5,\"global\":0.3,\"default\":0.2}，负数钳 0 后自动归一化到权重和为 1。只改权重也会触发缓存重建+增量迁移。"
                        </div>
                        <div>
                            <b style="color:var(--cyan)">"W-TinyLFU"</b>
                            "（tinylfu）"
                            <br />
                            "W-TinyLFU 三段式：window 1% → probation 40% → protected 60%（probation 占比以 main = 总容量 − window 为分母）+ 4 行 × 1024 列的 Count-Min Sketch 频率估计（u8 饱和计数，共 4 KiB）。一次性访问在窗口区即被挤出，高频条目受保护，抗扫描污染。本版本未做命中率基准实测，不承诺具体提升幅度。"
                        </div>
                    </div>
                    <div style="margin-top:8px; color:var(--text3); font-size:12px">
                        "切换策略或容量时增量迁移：旧缓存里仍有效的条目会逐条写入新引擎（同键仍可命中，不会清空；过期条目不复活，TinyLFU 的频次结构被预热）。只改 cache_partitions 权重同样会重建并迁移。"
                    </div>
                </div>
            </div>
        }
}

/* ============================== 交互动作 ============================== */

/// 重新拉取 `/api/config` 覆盖本地（并触发整个表单重建）。
async fn refresh_config(app: App) {
    match api::config().await {
        Ok(c) => {
            app.config.set(Some(c));
            app.cfg_epoch.update(|e| *e += 1);
        }
        Err(e) => app.note_set(format!("配置刷新失败: {e}"), NoteKind::Err),
    }
}

/* ---- 保存配置（#btn-save-cfg） ---- */

fn act_save(
    app: App,
    ups: RwSignal<Vec<Value>>,
    rules: RwSignal<Vec<Value>>,
    subs: RwSignal<Vec<Value>>,
    // **2.1.19（修复项 5）**：未保存标记（保存成功后复位）。
    // 注：参数位置只能用普通注释 —— `///` 在形参上会被编译期拒绝
    // （`documentation comments cannot be applied to function parameters`）。
    dirty: RwSignal<bool>,
) {
    // >>> 242B BEGIN P1-12-guard >>> //
    // **2.1.42-B（P1-12）**：**config_loaded 守卫**（UI disabled 之外的第二道）。
    // `WebConfig` 未加载时 `app.config` 为 `None`，旧代码把它当 `Value::Null` 继续
    // 渲染/保存 ⇒ 提交"默认标量 + 空 upstreams + 空 rules"，后端校验通过并整份覆盖。
    if app.config.get_untracked().is_none() {
        app.note_set(
            "配置尚未加载，已拒绝保存（避免用空 upstreams/rules 覆盖服务器配置）",
            NoteKind::Warn,
        );
        return;
    }

    // <<< 242B END P1-12-guard <<< //
    let base = app.config.get_untracked().unwrap_or(Value::Null);
    let mut obj = match base {
        Value::Object(m) => m,
        _ => Map::new(),
    };

    obj.insert(
        "cache_size".into(),
        num_json(dom_clamped_key(app, "cache_size", "cfg-size", 16384.0)),
    );
    obj.insert(
        "ttl".into(),
        num_json(dom_clamped_key(app, "ttl", "cfg-ttl", 300.0)),
    );
    obj.insert("prefetch".into(), json!(dom_checked("cfg-prefetch")));
    obj.insert(
        "cache_direct_enabled".into(),
        json!(dom_checked("cfg-kdirect")),
    );
    obj.insert(
        "ttl_min".into(),
        num_json(dom_clamped_key(app, "ttl_min", "cfg-ttlmin", 0.0)),
    );
    obj.insert(
        "ttl_max".into(),
        num_json(dom_clamped_key(app, "ttl_max", "cfg-ttlmax", 0.0)),
    );
    obj.insert("serve_stale".into(), json!(dom_checked("cfg-stale")));
    obj.insert(
        "stale_ttl".into(),
        num_json(dom_clamped_key(app, "stale_ttl", "cfg-stalettl", 3600.0)),
    );
    obj.insert(
        "persist_ttl".into(),
        num_json(dom_clamped_key(app, "persist_ttl", "cfg-persistttl", 0.0)),
    );
    obj.insert(
        "cache_persist".into(),
        json!(dom_checked("cfg-cachepersist")),
    );
    obj.insert("speed_test".into(), json!(dom_checked("cfg-speed")));
    obj.insert(
        "speed_interval_ms".into(),
        num_json(dom_clamped_key(
            app,
            "speed_interval_ms",
            "cfg-spint",
            2000.0,
        )),
    );
    obj.insert("fallback".into(), json!(dom_checked("cfg-fallback")));
    obj.insert(
        "max_parallel_upstreams".into(),
        num_json(dom_clamped_key(
            app,
            "max_parallel_upstreams",
            "cfg-maxup",
            3.0,
        )),
    );
    // **2.1.15（P1）**：单上游在途上限（0 = 关闭闸门）。缺控件时取默认 32，
    // 与后端 `DEFAULT_UPSTREAM_MAX_INFLIGHT` / 打包模板三处一致。
    obj.insert(
        "upstream_max_inflight".into(),
        num_json(dom_clamped_key(
            app,
            "upstream_max_inflight",
            "cfg-upinflight",
            32.0,
        )),
    );
    obj.insert(
        "timeout_ms".into(),
        num_json(dom_clamped_key(app, "timeout_ms", "cfg-timeout", 1500.0)),
    );
    obj.insert(
        "speed_timeout_ms".into(),
        num_json(dom_clamped_key(
            app,
            "speed_timeout_ms",
            "cfg-speedtimeout",
            300.0,
        )),
    );
    obj.insert(
        "ip_speed_probe".into(),
        json!(cfg_or_dom("cfg-ipsprobe", "both")),
    );
    obj.insert(
        "ip_speed_cache_ttl".into(),
        num_json(dom_clamped_key(
            app,
            "ip_speed_cache_ttl",
            "cfg-ipscachettl",
            60.0,
        )),
    );
    obj.insert("ipv4_first".into(), json!(dom_checked("cfg-v4first")));
    obj.insert("ipv6".into(), json!(dom_checked("cfg-v6")));
    obj.insert("prefer_ipv4".into(), json!(dom_checked("cfg-v4smart")));
    obj.insert(
        "edns_udp_size".into(),
        num_json(dom_clamped_key(
            app,
            "edns_udp_size",
            "cfg-ednssize",
            1232.0,
        )),
    );
    obj.insert("padding".into(), json!(dom_checked("cfg-padding")));
    obj.insert("rebind_protection".into(), json!(dom_checked("cfg-rebind")));
    obj.insert("edns".into(), json!(dom_checked("cfg-edns")));
    obj.insert("dnssec_0x20".into(), json!(dom_checked("cfg-dnssec0x20")));
    obj.insert(
        "ip_speed_check".into(),
        json!(dom_checked("cfg-ipspeedcheck")),
    );
    obj.insert(
        "health_check_interval".into(),
        num_json(dom_clamped_key(
            app,
            "health_check_interval",
            "cfg-healthint",
            0.0,
        )),
    );
    obj.insert(
        "rule_sub_interval".into(),
        num_json(dom_clamped_key(
            app,
            "rule_sub_interval",
            "cfg-rulesubint",
            0.0,
        )),
    );
    obj.insert(
        "bootstrap_dns".into(),
        json!(dom_val("cfg-bootstrapdns").trim()),
    );
    obj.insert(
        "circuit_fails".into(),
        num_json(dom_clamped_key(app, "circuit_fails", "cfg-circfails", 3.0)),
    );
    obj.insert(
        "circuit_open_s".into(),
        num_json(dom_clamped("cfg-circopens", 1.0, 86400.0, 30.0)),
    );
    obj.insert(
        "health_probe_domain".into(),
        json!(dom_val("cfg-healthdomain").trim()),
    );
    obj.insert(
        "health_probe_timeout_ms".into(),
        num_json(dom_clamped_key(
            app,
            "health_probe_timeout_ms",
            "cfg-healthtimeout",
            2000.0,
        )),
    );
    obj.insert(
        "log_level".into(),
        json!(cfg_or_dom("cfg-loglevel", "info")),
    );
    obj.insert(
        "log_format".into(),
        json!(cfg_or_dom("cfg-logformat", "text")),
    );
    obj.insert(
        "cache_policy".into(),
        json!(cfg_or_dom("cfg-cache-policy", "lru")),
    );
    /* ---- **2.1.18（修复项 7）：新纳入白名单的键（此前没有控件 ⇒ 功能不可达）** ---- */
    obj.insert(
        "single_flight".into(),
        json!(dom_checked("cfg-singleflight")),
    );
    obj.insert(
        "udp_workers".into(),
        num_json(dom_clamped_key(app, "udp_workers", "cfg-udpworkers", 0.0)),
    );
    // `warmup` 是**对象键**（后端按整体替换；子键范围由 `validate_write` 校验）。
    obj.insert(
        "warmup".into(),
        json!({
            "enabled": dom_checked("cfg-warmup-enabled"),
            "queries": dom_clamped_key(app, "warmup_queries", "cfg-warmup-queries", 3.0) as i64,
            "timeout_ms": dom_clamped_key(app, "warmup_timeout_ms", "cfg-warmup-timeout", 3000.0) as i64,
        }),
    );
    obj.insert("rfc8020_infer".into(), json!(dom_checked("cfg-rfc8020")));
    obj.insert(
        "rfc8020_max_labels".into(),
        num_json(dom_clamped_key(
            app,
            "rfc8020_max_labels",
            "cfg-rfc8020-labels",
            8.0,
        )),
    );
    // 比例因子必须**保留小数**（见 `dom_clamped_f` 文档）。
    obj.insert(
        "rating_sr_floor".into(),
        json!(dom_clamped_f("cfg-ratingsrfloor", 0.001, 1.0, 0.5)),
    );
    obj.insert(
        "hedge_slowest_factor".into(),
        json!(dom_clamped_f("cfg-hedgeslowest", 0.001, 100.0, 1.0)),
    );
    /* ==== **2.1.21（DEF-220-02 / A-15）**：12 个新控件的写路径 ====
     *
     * 与上面的 `dom_clamped_key` 控件**一一对应**（键名 + `id`）。
     * 机器门禁 `web_config_range_fallback_keys_have_controls` 会读本文件，
     * 断言"兜底表里的每个键都能在这里找到 `dom_clamped_key(app, \"<键>\"`"，
     * 因此**不允许**再加"只有表项、没有控件"的键（DEF-220-02 的病根）。
     */
    obj.insert(
        "cache_save_interval".into(),
        num_json(dom_clamped_key(
            app,
            "cache_save_interval",
            "cfg-cachesaveint",
            60.0,
        )),
    );
    obj.insert(
        "prefetch_trigger".into(),
        num_json(dom_clamped_key(
            app,
            "prefetch_trigger",
            "cfg-pftrigger",
            60.0,
        )),
    );
    obj.insert(
        "prefetch_target".into(),
        num_json(dom_clamped_key(
            app,
            "prefetch_target",
            "cfg-pftarget",
            300.0,
        )),
    );
    obj.insert(
        "prefetch_interval".into(),
        num_json(dom_clamped_key(
            app,
            "prefetch_interval",
            "cfg-pfinterval",
            300.0,
        )),
    );
    obj.insert(
        "prefetch_max".into(),
        num_json(dom_clamped_key(app, "prefetch_max", "cfg-pfmax", 1024.0)),
    );
    obj.insert(
        "neg_ttl_max".into(),
        num_json(dom_clamped_key(app, "neg_ttl_max", "cfg-negttlmax", 60.0)),
    );
    obj.insert(
        "nxdomain_quorum".into(),
        num_json(dom_clamped_key(app, "nxdomain_quorum", "cfg-nxquorum", 2.0)),
    );
    obj.insert(
        "edns_client_max_size".into(),
        num_json(dom_clamped_key(
            app,
            "edns_client_max_size",
            "cfg-ednsclimax",
            1232.0,
        )),
    );
    obj.insert(
        "probe_timeout_ms".into(),
        num_json(dom_clamped_key(
            app,
            "probe_timeout_ms",
            "cfg-probetimeout",
            0.0,
        )),
    );
    obj.insert(
        "circuit_open_max_s".into(),
        num_json(dom_clamped_key(
            app,
            "circuit_open_max_s",
            "cfg-cbmax",
            120.0,
        )),
    );
    obj.insert(
        "hedge_after_ms".into(),
        num_json(dom_clamped_key(
            app,
            "hedge_after_ms",
            "cfg-hedgeafter",
            200.0,
        )),
    );
    obj.insert(
        "adaptive_timeout_min_ms".into(),
        num_json(dom_clamped_key(
            app,
            "adaptive_timeout_min_ms",
            "cfg-adatmintimeout",
            1500.0,
        )),
    );
    // `adaptive_timeout_k` 是**浮点**键（`validate_write` 的 `frng(0.1, 1000.0)`）⇒
    // 用 `dom_clamped_f`（保留小数；`dom_clamped_key` 会 `round()`，0.5 会变成 1）。
    obj.insert(
        "adaptive_timeout_k".into(),
        json!(dom_clamped_f("cfg-adatk", 0.1, 1000.0, 8.0)),
    );

    // 本地暂存的三个列表原样下发
    obj.insert("upstreams".into(), Value::Array(ups.get_untracked()));

    obj.insert("rules".into(), Value::Array(rules.get_untracked()));
    obj.insert(
        "rule_subscriptions".into(),
        Value::Array(subs.get_untracked()),
    );

    let value = Value::Object(obj);
    let app2 = app;
    spawn_local(async move {
        match api::put_config(&value).await {
            Ok(resp) => {
                let ok = resp.get("ok").and_then(Value::as_bool).unwrap_or(true);
                let saved_to = resp
                    .get("saved_to")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                // **2.1.18（修复项 7）**：两个桶分开取 —— `readonly_keys`（只读/服务端
                // 管理，原值不变）与 `ignored_keys`（**未知键**）。旧后端（2.1.17 及以前）
                // 不带 `readonly_keys`，此时把 `ignored_keys` 里已知的只读项**挪到**
                // 只读桶，保证提示语在旧后端上也不误导（本地 `is_readonly_key` 兜底）。
                let str_list = |k: &str| -> Vec<String> {
                    resp.get(k)
                        .and_then(Value::as_array)
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default()
                };
                let mut readonly = str_list("readonly_keys");
                let mut ignored = str_list("ignored_keys");
                if resp.get("readonly_keys").is_none() {
                    let (ro, ig): (Vec<String>, Vec<String>) =
                        ignored.into_iter().partition(|k| is_readonly_key(k));
                    readonly = ro;
                    ignored = ig;
                }
                let (msg, kind) = save_note(ok, &saved_to, &readonly, &ignored);
                // 后端给出的只读原因（`readonly_detail[].reason`）存进全局信号，
                // 供「只读/服务端管理项」只读展示区逐条显示（旧后端为空 → 本地兜底）。
                if let Some(detail) = resp.get("readonly_detail").and_then(Value::as_array) {
                    let mut m = std::collections::HashMap::new();
                    for d in detail {
                        if let (Some(k), Some(r)) = (
                            d.get("key").and_then(Value::as_str),
                            d.get("reason").and_then(Value::as_str),
                        ) {
                            m.insert(k.to_string(), r.to_string());
                        }
                    }
                    if !m.is_empty() {
                        app2.readonly_reasons.set(m);
                    }
                }
                app2.note_set(msg, kind);
                // **2.1.19（修复项 5）**：只有**服务端确认写入**后才清掉"未保存"标记 ——
                // 失败（`ok=false` / 网络错误）时标记必须**继续显示**，否则又回到
                // "改了但没生效却看不出来"的老问题。
                if ok {
                    dirty.set(false);
                }
                refresh_config(app2).await;
            }
            Err(e) => app2.note_set(format!("保存失败: {e}"), NoteKind::Err),
        }
    });
}

/// 读 select 值；空则用默认。
fn cfg_or_dom(id: &str, d: &str) -> String {
    let v = dom_val(id);
    if v.is_empty() {
        d.to_string()
    } else {
        v
    }
}

/* ---- 重新载入服务器配置 / 热重载 / 重启服务 ---- */

/// `#btn-reset-cfg`（D20）。
///
/// 原标题「恢复默认」名不符实：它只是重新 `GET /api/config`，并不会把值还原成后端默认值
/// （前端拿不到后端 DEFAULTS，Rust 侧也没有「下发默认配置」端点）。这里按后端真实语义
/// 改文案为「重新载入服务器配置」，并补二次确认——重载会用服务器配置覆盖表单，
/// 未保存的编辑会丢失。
fn act_reset(app: App) {
    if let Some(win) = web_sys::window() {
        let ok = win
            .confirm_with_message(
                "重新载入服务器配置将覆盖当前表单，未保存的编辑会丢失。确定继续吗？",
            )
            .unwrap_or(false);
        if !ok {
            return;
        }
    }
    app.note_set("正在重新载入服务器配置…", NoteKind::Info);
    spawn_local(async move {
        match api::config().await {
            Ok(c) => {
                app.config.set(Some(c));
                app.cfg_epoch.update(|e| *e += 1);
                app.note_set("已重新载入服务器配置", NoteKind::Info);
            }
            Err(e) => app.note_set(format!("重新载入配置失败: {e}"), NoteKind::Err),
        }
    });
}

fn act_reload(app: App) {
    if let Some(win) = web_sys::window() {
        let ok = win
            .confirm_with_message("热重载将从配置文件重新加载并覆盖当前未保存的编辑，确定继续吗？")
            .unwrap_or(false);
        if !ok {
            return;
        }
    }
    app.note_set("正在热重载配置…", NoteKind::Warn);
    spawn_local(async move {
        match api::reload().await {
            Ok(v) => {
                if v.get("ok").and_then(Value::as_bool) == Some(false) {
                    let err = v
                        .get("error")
                        .and_then(Value::as_str)
                        .unwrap_or("未知错误")
                        .to_string();
                    app.note_set(format!("热重载失败: {err}"), NoteKind::Err);
                    return;
                }
                let changed = v
                    .get("changed")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect::<Vec<_>>()
                            .join("; ")
                    })
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "无实质变更".to_string());
                app.note_set(format!("热重载完成: {changed}"), NoteKind::Ok);
                refresh_config(app).await;
            }
            Err(e) => app.note_set(format!("热重载失败: {e}"), NoteKind::Err),
        }
    });
}

fn act_restart(app: App) {
    if let Some(win) = web_sys::window() {
        let ok = win
            .confirm_with_message(
                "重启 ebpdns 服务将导致 DNS 解析中断约 5-10 s（期间所有依赖本机 DNS 的客户端会解析失败）。确定重启？",
            )
            .unwrap_or(false);
        if !ok {
            return;
        }
    }
    app.note_set("正在重启 ebpdns 服务… 控制台将自动重连", NoteKind::Warn);
    spawn_local(async move {
        match api::restart().await {
            Ok(_) => app.note_set("重启指令已下发, 服务重启中…", NoteKind::Warn),
            Err(e) => app.note_set(format!("重启失败: {e}"), NoteKind::Err),
        }
    });
}

/* ---- 一键重测速 ---- */

fn act_reprobe(app: App) {
    // 审计 ④：本函数末尾会 `refresh_config()` 重新拉取服务器配置并覆盖本地表单
    // （`cfg_epoch` +1 → Effect 重置 ups/rules/subs）—— 未保存的编辑会**静默丢失**。
    // 与「重新载入」「热重载」保持同一门槛：先确认。
    if let Some(win) = web_sys::window() {
        let ok = win
            .confirm_with_message(
                "一键重新测速完成后会重新载入服务器配置，未保存的上游/规则编辑会丢失。确定继续吗？",
            )
            .unwrap_or(false);
        if !ok {
            return;
        }
    }
    app.note_set("正在实测全部上游延迟…", NoteKind::Warn);
    spawn_local(async move {
        match api::reprobe().await {
            Ok(v) => {
                let n = v
                    .get("results")
                    .and_then(Value::as_array)
                    .map(|a| a.len())
                    .unwrap_or(0);
                app.note_set(format!("重新测速完成 ({n} 个上游)"), NoteKind::Ok);
                refresh_config(app).await;
            }
            Err(e) => app.note_set(format!("测速失败: {e}"), NoteKind::Err),
        }
    });
}

/* ---- 规则导入 ---- */

fn act_import(app: App) {
    let input = dom_val("import-input").trim().to_string();
    if input.is_empty() {
        app.note_set("请输入域名列表后再导入", NoteKind::Err);
        return;
    }
    let action = cfg_or_dom("import-action", "group");
    let group = cfg_or_dom("import-group", "domestic");
    let ip = dom_val("import-ip").trim().to_string();
    let (g, i) = match action.as_str() {
        "group" => (Some(group), None),
        "forceIp" => (
            None,
            Some(if ip.is_empty() {
                "1.2.3.4".to_string()
            } else {
                ip
            }),
        ),
        _ => (None, None),
    };
    spawn_local(async move {
        match api::rules_import(&action, g.as_deref(), i.as_deref(), &input).await {
            Ok(v) => {
                let added = v.get("added").and_then(Value::as_f64).unwrap_or(0.0);
                app.note_set(
                    format!("逐条导入完成：新增 {} 条规则", fmt::num0(added)),
                    NoteKind::Ok,
                );
                dom_set_val("import-input", "");
                refresh_config(app).await;
            }
            Err(e) => app.note_set(format!("导入失败: {e}"), NoteKind::Err),
        }
    });
}

/* ---- 规则订阅 ---- */

fn act_subscribe(app: App) {
    let url = dom_val("sub-url-input").trim().to_string();
    if url.is_empty() {
        app.note_set("请输入订阅链接", NoteKind::Err);
        return;
    }
    if !url.to_lowercase().starts_with("https://") {
        app.note_set(
            "仅支持 https:// 订阅链接（明文 http:// 不安全，后端已禁止）",
            NoteKind::Err,
        );
        return;
    }
    let action = cfg_or_dom("sub-action", "block");
    let group = cfg_or_dom("sub-group", "domestic");
    let ip = dom_val("sub-ip").trim().to_string();
    let (g, i) = match action.as_str() {
        "group" => (Some(group), None),
        "forceIp" => (
            None,
            Some(if ip.is_empty() {
                "1.2.3.4".to_string()
            } else {
                ip
            }),
        ),
        _ => (None, None),
    };
    app.note_set("正在订阅…", NoteKind::Info);
    spawn_local(async move {
        match api::subscribe(&url, &action, g.as_deref(), i.as_deref()).await {
            Ok(v) => {
                // D8：`count` 取不到时显示后端原文，不再静默显示「0 条」。
                app.note_set(
                    format!(
                        "订阅成功{}（明细存 rules_sub.json）",
                        subscribe_count_text(&v)
                    ),
                    NoteKind::Ok,
                );
                dom_set_val("sub-url-input", "");
                refresh_config(app).await;
            }
            Err(e) => app.note_set(format!("订阅失败: {e}"), NoteKind::Err),
        }
    });
}

/* ---- 上游新增 ---- */

fn act_add_up(app: App, ups: RwSignal<Vec<Value>>) {
    let raw = dom_val("up-add-addr").trim().to_string();
    if raw.is_empty() {
        app.note_set("请输入上游完整地址后再添加", NoteKind::Err);
        return;
    }
    let proto_sel = cfg_or_dom("up-add-proto", "auto");
    let group = cfg_or_dom("up-add-group", "domestic");
    let parsed = match parse_upstream_addr(&raw, &proto_sel) {
        Ok(p) => p,
        Err(e) => {
            app.note_set(e, NoteKind::Err);
            return;
        }
    };
    let n = ups.get_untracked().len() + 1;
    let id = format!("u{}_{}", now_ms(), rand36_6());
    let disp_scheme = match parsed.proto.as_str() {
        "udp" => "udp",
        "tcp" => "tcp",
        "doh" => "https",
        "doh3" => "http3",
        "dot" => "tls",
        "doq" => "quic",
        other => other,
    };
    let disp = if matches!(parsed.proto.as_str(), "doh" | "doh3" | "doq") {
        format!("{disp_scheme}://{}{}", parsed.addr, parsed.url)
    } else {
        format!("{disp_scheme}://{}:{}", parsed.addr, parsed.port)
    };
    let plabel = {
        let l = proto_label(&parsed.proto);
        if l.is_empty() {
            parsed.proto.to_uppercase()
        } else {
            l.to_string()
        }
    };
    let entry = json!({
        "id": id,
        "name": format!("上游 {n}"),
        "proto": parsed.proto,
        "addr": parsed.addr,
        "port": parsed.port,
        "url": parsed.url,
        "group": group,
        "latency": 0,
        "enabled": true,
    });
    ups.update(|l| l.push(entry));
    dom_set_val("up-add-addr", "");
    // 审计 ④：旧文案「已添加上游 …」(Ok) 让人以为**已经落盘**，实际只写进了本地暂存
    // 信号（真正下盘要再点「应用配置」）。这里如实说明，并统一为 Info 级别。
    app.note_set(
        format!(
            "已把上游 {disp}（{plabel}:{}）加入待保存列表，点「应用配置」后才会写入后端",
            parsed.port
        ),
        NoteKind::Info,
    );
}

/* ---- API Token ---- */

fn act_save_token(app: App) {
    let raw = dom_val("api-token-input");
    let t: String = raw.chars().filter(|c| *c != '\r' && *c != '\n').collect();
    let t = t.trim().to_string();
    api::set_token(&t);
    if t.is_empty() {
        app.note_set("Token 为空, 已改为不携带认证头", NoteKind::Warn);
        app.token_status.set("未配置".into());
        return;
    }
    app.note_set("API Token 已保存到本浏览器", NoteKind::Ok);
    app.token_status.set("验证中…".into());
    spawn_local(async move {
        match api::status().await {
            Ok(_) => {
                app.token_status.set("已配置 · 连通正常".into());
                app.note_set("Token 验证通过", NoteKind::Ok);
            }
            Err(e) => {
                if e.is_auth_error {
                    app.token_status.set("认证失败(401)".into());
                    app.note_set(
                        "认证失败(401): Token 错误或后端未配置/不匹配",
                        NoteKind::Err,
                    );
                } else {
                    app.token_status.set(format!("后端不可达: {e}"));
                    app.note_set(
                        "后端不可达, 网络恢复后请再次点击「保存」重新验证",
                        NoteKind::Err,
                    );
                }
            }
        }
    });
}

fn act_clear_token(app: App) {
    api::set_token("");
    dom_set_val("api-token-input", "");
    app.token_status.set("未配置".into());
    app.note_set("API Token 已清除", NoteKind::Info);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Snapshot, UpstreamStat};

    /// 前端解析结果的四元组（`ParsedUp` 无 PartialEq，测试里按字段比对）。
    fn parse(raw: &str, sel: &str) -> Result<(String, String, i64, String), String> {
        parse_upstream_addr(raw, sel).map(|p| (p.proto, p.addr, p.port, p.url))
    }

    /// D24：与后端 `parse_upstream_addr_local` 逐分支一致（值 + 端口 + URL）。
    #[test]
    fn parse_matches_backend_accepting_branch() {
        let cases: &[(&str, &str, &str, &str, i64, &str)] = &[
            // (输入, proto_sel, 期望 proto, 期望 addr, 期望 port, 期望 url)
            ("1.1.1.1", "auto", "udp", "1.1.1.1", 53, ""),
            ("1.1.1.1:5353", "auto", "udp", "1.1.1.1", 5353, ""),
            ("udp://8.8.8.8:53", "auto", "udp", "8.8.8.8", 53, ""),
            ("tcp://9.9.9.9", "auto", "tcp", "9.9.9.9", 53, ""),
            ("tls://dns.google", "auto", "dot", "dns.google", 853, ""),
            ("dot://dns.google", "auto", "dot", "dns.google", 853, ""),
            (
                "https://dns.google/dns-query",
                "auto",
                "doh",
                "dns.google",
                443,
                "/dns-query",
            ),
            (
                "https://dns.google",
                "auto",
                "doh",
                "dns.google",
                443,
                "/dns-query",
            ),
            ("doh://1.1.1.1", "auto", "doh", "1.1.1.1", 443, "/dns-query"),
            ("http://1.1.1.1", "auto", "doh", "1.1.1.1", 80, "/dns-query"),
            (
                "http://1.1.1.1:8080/x",
                "auto",
                "doh",
                "1.1.1.1",
                8080,
                "/x",
            ),
            (
                "quic://223.5.5.5",
                "auto",
                "doq",
                "223.5.5.5",
                853,
                "/dns-query",
            ),
            (
                "doq://223.5.5.5",
                "auto",
                "doq",
                "223.5.5.5",
                853,
                "/dns-query",
            ),
            (
                "http3://dns.alidns.com/dns-query",
                "auto",
                "doh3",
                "dns.alidns.com",
                443,
                "/dns-query",
            ),
            (
                "h3://dns.alidns.com",
                "auto",
                "doh3",
                "dns.alidns.com",
                443,
                "/dns-query",
            ),
            ("doh3://x/y", "auto", "doh3", "x", 443, "/y"),
            // 无 scheme：proto_sel 生效（auto/空 → udp）
            ("dns.google", "doh", "doh", "dns.google", 443, "/dns-query"),
            (
                "dns.google:8443",
                "doh",
                "doh",
                "dns.google",
                8443,
                "/dns-query",
            ),
            ("dns.google", "auto", "udp", "dns.google", 53, ""),
            ("dns.google", "", "udp", "dns.google", 53, ""),
            // IPv6：`[v6]` 剥离方括号（与后端 stored addr 同形），裸 v6 原样保留
            ("[::1]:5300", "auto", "udp", "::1", 5300, ""),
            ("[2001:db8::1]", "auto", "udp", "2001:db8::1", 53, ""),
            ("::1", "auto", "udp", "::1", 53, ""),
            ("host1:host2:53", "auto", "udp", "host1:host2:53", 53, ""),
        ];
        for (raw, sel, proto, addr, port, url) in cases {
            assert_eq!(
                parse(raw, sel),
                Ok((
                    (*proto).to_string(),
                    (*addr).to_string(),
                    *port,
                    (*url).to_string()
                )),
                "输入 {raw:?} (proto_sel={sel:?})"
            );
        }
    }

    /// D24：补齐的后端拒绝分支（旧实现会放行 `example.com:` / `[]` / 超长 host 等）。
    #[test]
    fn parse_rejects_backend_rejecting_branch() {
        let bad = [
            "",
            "   ",
            "ftp://1.1.1.1", // 未知 scheme（且 '/' 不在 host 字符集）
            "[]",            // 空 IPv6 字面量
            "[",             // 未闭合
            "[::1",          // 未闭合
            "[::1]x",        // ']' 后多余字符
            "[::1]:",        // 冒号后空端口
            "[::1]:abc",     // 非数字端口
            "[a:b]",         // 剥括号后残留单冒号
            "example.com:",  // 残留单冒号
            "host:abc",      // 残留单冒号（非数字尾段）
            "bad host",      // host 字符集外（空格）
            "1.1.1.1:0",     // 端口下界
            "1.1.1.1:65536", // 端口上界
            "1.1.1.1:70000", // 越界端口（后端解析分支同样 None）
        ];
        for raw in bad {
            assert!(
                parse(raw, "auto").is_err(),
                "应拒绝 {raw:?}, 实际 {:?}",
                parse(raw, "auto")
            );
        }
        // 协议枚举（后端 `ALLOWED_UPSTREAM_PROTO`）
        assert!(parse("1.1.1.1", "bogus").is_err());
        // host 长度：253 通过、254 拒绝（与后端 `> 253 → None` 一致）
        assert!(parse(&"a".repeat(253), "auto").is_ok());
        assert!(parse(&"a".repeat(254), "auto").is_err());
    }

    /// D24：`has_explicit_port` 也按后端 `addr_has_explicit_port` 对齐
    /// （先剥 scheme、再在首个 `/` 截断；URL 路径里的 `:443` 不算显式端口）。
    #[test]
    fn explicit_port_matches_backend_helper() {
        assert!(!has_explicit_port("1.1.1.1"));
        assert!(has_explicit_port("1.1.1.1:53"));
        assert!(has_explicit_port("udp://1.1.1.1:53"));
        assert!(!has_explicit_port("https://dns.google/dns-query"));
        assert!(has_explicit_port("https://dns.google:8443/dns-query"));
        // 旧实现会把路径里的 `:443` 误判为显式端口
        assert!(!has_explicit_port("https://dns.google/dns-query:443"));
        assert!(!has_explicit_port("example.com:"));
        // 裸 IPv6 不切端口；方括号地址才看 `:port`
        assert!(!has_explicit_port("::1"));
        assert!(has_explicit_port("[::1]:5300"));
    }

    fn stat(id: &str, addr: &str, port: f64, lat: Option<f64>, ok: f64, fail: f64) -> UpstreamStat {
        UpstreamStat {
            id: id.into(),
            addr: addr.into(),
            port,
            conn_avg_lat: lat,
            conn_ok: ok,
            conn_fail: fail,
            conn_key: format!("{addr}:{port}"),
            ..UpstreamStat::default()
        }
    }

    /// D14：徽标数据源是 `/api/snapshot.upstreams[]`（配置副本里根本没有这些键）。
    #[test]
    fn conn_metrics_reads_snapshot_by_id_then_addr() {
        let snap = Snapshot {
            upstreams: vec![
                stat("u1", "1.1.1.1", 53.0, Some(12.34), 9.0, 1.0),
                stat("u2", "8.8.8.8", 853.0, Some(700.0), 2.0, 5.0),
            ],
            ..Snapshot::default()
        };
        // 按 id
        let m = conn_metrics(
            Some(&snap),
            &json!({"id": "u1", "addr": "1.1.1.1", "port": 53}),
        );
        assert_eq!(m.lat, Some(12.34));
        assert_eq!(m.ok, 9.0);
        assert_eq!(m.fail, 1.0);
        assert_eq!(m.key, "1.1.1.1:53");
        // id 失配 → 按 addr(+port) 兜底
        let m = conn_metrics(
            Some(&snap),
            &json!({"id": "uX", "addr": "8.8.8.8", "port": 853}),
        );
        assert_eq!(m.lat, Some(700.0));
        // host 字段（2.0 原字段）也能匹配
        let m = conn_metrics(
            Some(&snap),
            &json!({"id": "uX", "host": "1.1.1.1", "port": 53}),
        );
        assert_eq!(m.lat, Some(12.34));
        // 取不到 → 回退本地副本，再回退「待统计」
        let m = conn_metrics(
            Some(&snap),
            &json!({"id": "u9", "addr": "9.9.9.9", "port": 53}),
        );
        assert_eq!(m.lat, None);
        let m = conn_metrics(
            Some(&snap),
            &json!({"id": "u9", "addr": "9.9.9.9", "port": 53,
                    "conn_avg_lat": 7.5, "conn_ok": 2, "conn_fail": 1, "conn_key": "k"}),
        );
        assert_eq!(m.lat, Some(7.5));
        assert_eq!(m.ok, 2.0);
        assert_eq!(m.key, "k");
        // 无 snapshot（首屏 2s 内）→ 只能靠本地副本
        let m = conn_metrics(None, &json!({"id": "u1", "conn_avg_lat": 3.0}));
        assert_eq!(m.lat, Some(3.0));
    }

    /// 非有限延迟视同缺字段（走「待统计」分支，不渲染 `NaNms`）。
    #[test]
    fn conn_metrics_treats_non_finite_as_missing() {
        let snap = Snapshot {
            upstreams: vec![stat("u1", "1.1.1.1", 53.0, Some(f64::NAN), 1.0, 0.0)],
            ..Snapshot::default()
        };
        let m = conn_metrics(Some(&snap), &json!({"id": "u1"}));
        assert_eq!(m.lat, None);
    }

    /// **2.1.18（修复项 7）**：保存提示语的**文案**（用户实测的误导必须消失）。
    ///
    /// 旧文案 `配置已保存; 忽略未保存的键: config_version, single_flight, …`
    /// 把"只读/服务端管理项"与"未知键"混为一谈，读起来像**保存丢数据**。
    #[test]
    fn save_message_distinguishes_readonly_from_ignored() {
        let ro = vec!["config_version".to_string(), "rule_local_file".to_string()];
        let ig = vec!["typo_key".to_string()];
        // ① 只有只读项：必须说"原值保持不变"，且**不得**出现"忽略未保存的键"。
        let m = save_message("/etc/ebpdns/config.json", &ro, &[]);
        assert!(
            m.contains("另有 2 项由配置文件/服务端管理，未在界面暴露，原值保持不变"),
            "只读项提示语不对：{m}"
        );
        assert!(
            !m.contains("忽略未保存"),
            "不得再出现『忽略未保存的键』：{m}"
        );
        assert!(m.contains("config_version"), "{m}");
        // ② 有未知键：追加"未知键已忽略"（这才是真的没保存），措辞与只读项不同。
        let m = save_message("/etc/ebpdns/config.json", &ro, &ig);
        assert!(m.contains("未知键已忽略"), "{m}");
        assert!(m.contains("typo_key"), "{m}");
        // ③ 两者都空：保持既有成功文案（不回归）。
        let m = save_message("/etc/ebpdns/config.json", &[], &[]);
        assert_eq!(
            m,
            "配置已保存到后端 /etc/ebpdns/config.json，新增上游自动测速中…"
        );
        // ④ 写盘失败优先（且不谎报成功）。
        let (msg, kind) = save_note(false, "/x", &[], &[]);
        assert_eq!(kind, NoteKind::Err);
        assert!(msg.contains("写盘失败"), "{msg}");
        // ⑤ 只有未知键 ⇒ Warn 级别（提醒但不谎报成功）。
        let (_, kind) = save_note(true, "/x", &[], &ig);
        assert_eq!(kind, NoteKind::Warn);
        let (_, kind) = save_note(true, "/x", &ro, &[]);
        assert_eq!(kind, NoteKind::Ok, "只读项不应把提示降级成告警");
    }

    /// **2.1.18（修复项 7）**：只读键清单必须与后端 `CFG_READONLY` 一致
    /// （本地表只作"旧后端无 `readonly_keys` 字段"时的兜底与展示标签）。
    #[test]
    fn readonly_keys_cover_backend_readonly_set() {
        for k in [
            "config_version",
            "listen",
            "api",
            "web_root",
            "rule_local_file",
            "rule_sub_file",
            "cache_file",
        ] {
            assert!(is_readonly_key(k), "只读键 `{k}` 必须在 READONLY_KEYS 里");
        }
        // 可写键绝不能被误判成只读（否则前端会把它挪出告警桶）。
        for k in [
            "single_flight",
            "udp_workers",
            "warmup",
            "rfc8020_infer",
            "rfc8020_max_labels",
            "rating_sr_floor",
            "hedge_slowest_factor",
        ] {
            assert!(!is_readonly_key(k), "可写键 `{k}` 不得进只读表");
        }
    }

    /// **2.1.18（修复项 7）**：只读展示区逐行取值（键 / 当前值 / 原因）。
    #[test]
    fn readonly_rows_show_current_values_and_reasons() {
        let cfg = json!({
            "config_version": 2,
            "rule_local_file": "/etc/ebpdns/rules_local.json",
            "listen": {"udp": "0.0.0.0:53"},
        });
        let mut reasons = std::collections::HashMap::new();
        reasons.insert("config_version".to_string(), "后端给的原因".to_string());
        let rows = readonly_rows(&cfg, &reasons);
        assert_eq!(rows.len(), READONLY_KEYS.len(), "每个只读键一行");
        let find = |k: &str| {
            rows.iter()
                .find(|(n, _, _)| n == k)
                .cloned()
                .unwrap_or_else(|| panic!("缺只读行 {k}"))
        };
        // 后端 reason 优先。
        assert_eq!(find("config_version").2, "后端给的原因");
        assert_eq!(find("config_version").1, "2");
        // 对象值不展开成 JSON 噪声（只说明"见配置文件"）。
        assert!(find("listen").1.contains("对象"), "{}", find("listen").1);
        // 后端未给 reason 时用本地兜底文案（非空）。
        assert!(!find("rule_local_file").2.is_empty());
        assert!(find("rule_local_file").1.contains("rules_local.json"));
    }

    /// D8：订阅响应缺 `count` 时不得显示「0 条」。
    #[test]
    fn subscribe_count_text_uses_backend_count_or_raw_body() {
        let v = json!({"ok": true, "url": "https://x/l.txt", "count": 12, "added": 1});
        assert_eq!(subscribe_count_text(&v), ": 新建订阅, 12 条规则");
        let v = json!({"ok": true, "url": "https://x/l.txt", "count": 12});
        assert_eq!(subscribe_count_text(&v), ": 12 条规则");
        // 缺 count：退化为「已提交（无计数）」+ 后端原文，而不是 0
        let v = json!({"ok": true, "url": "https://x/l.txt"});
        let t = subscribe_count_text(&v);
        assert!(t.contains("已提交, 后端未返回计数"), "got {t}");
        assert!(t.contains("https://x/l.txt"), "应带后端原文: {t}");
        assert!(!t.contains("0 条"), "不得静默显示 0 条: {t}");
        // count 类型异常（字符串）同样走兜底
        let v = json!({"ok": true, "count": "many"});
        assert!(subscribe_count_text(&v).contains("已提交, 后端未返回计数"));
        assert_eq!(subscribe_count(&json!({"count": 5})), Some(5.0));
        assert_eq!(subscribe_count(&json!({"count": null})), None);
    }

    #[test]
    fn proto_and_port_defaults_match_backend() {
        // 后端 `proto_default_port`
        for (p, port) in [
            ("udp", 53),
            ("tcp", 53),
            ("doh", 443),
            ("doh3", 443),
            ("dot", 853),
            ("doq", 853),
        ] {
            assert_eq!(up_port_default(p), port, "proto {p}");
        }
    }

    #[test]
    fn full_addr_render_round_trips_with_parse() {
        let u = json!({"proto": "doh", "addr": "dns.google", "url": "dns-query"});
        let full = full_addr(&u);
        assert_eq!(full, "https://dns.google/dns-query");
        assert_eq!(
            parse(&full, "auto"),
            Ok((
                "doh".to_string(),
                "dns.google".to_string(),
                443,
                "/dns-query".to_string()
            ))
        );
    }

    /// **2.1.30**：规则卡片必须同时显示"本地 / 订阅"，不能只显示一个数字。
    #[test]
    fn rule_split_text_shows_local_and_subscription_counts() {
        assert_eq!(
            rule_split_text(1, 2),
            "本地 1 条 / 订阅 2 条 · 独立文件 rules_local.json"
        );
        let subs = vec![
            json!({"url": "https://a/r", "count": 2}),
            json!({"url": "https://b/r", "count": 7}),
            json!({"url": "https://meta-only/r"}), // 缺 count ⇒ 0（不 panic）
        ];
        assert_eq!(subscription_count_total(&subs), 9);
    }
}
