//! 统一 HTTP 请求封装 + v1.9.162 契约适配。
//!
//! - token 三入口：localStorage `ebpdns_api_token`；非空则带 `Authorization: Bearer <token>`。
//! - 写操作（POST/PUT/DELETE）走同源 fetch，浏览器自动带同源 Origin/Referer；后端按
//!   host:port 严格一致做 CSRF 校验，前端不额外手动发 CSRF 头（与原实现一致）。
//! - 非 2xx：解析响应体 `{"error": "...", "detail": "..."}` 拼进错误信息。
//! - 401 打标 `is_auth_error`；写操作 403 追加 CSRF 提示。
//! - 超时默认 10s，长耗时端点（reprobe/import/subscribe）由调用方传更大值。
//!
//! 适配层：后端 2.0 在响应里同时给出 v1.9.162 兼容键；本模块再补少量展示级差异
//! （log_format 文案、bootstrap_dns 形状、upstreams `host`↔`addr`、
//! rules `match_raw`↔`match`），使页面代码与 1.9.162 完全一致。

use gloo_net::http::{Request, Response};
use gloo_timers::future::TimeoutFuture;
use serde_json::{json, Map, Value};

use crate::model::{LogsResp, Pipeline, QueryResp, Snapshot, Status};
use crate::state::LogFilters;

/// localStorage 中 API token 的键名（与原前端一致）。
const TOKEN_KEY: &str = "ebpdns_api_token";

#[derive(Debug, Clone)]
pub struct ApiError {
    pub message: String,
    pub is_auth_error: bool,
}

impl ApiError {
    fn new(message: String, is_auth_error: bool) -> Self {
        Self {
            message,
            is_auth_error,
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ApiError {}

/// **2.1.43-B（P2-1）**：`Value` → 类型化模型的**唯一**解码入口（拒绝静默归零）。
///
/// 旧写法 `serde_json::from_value(v).unwrap_or_default()` 在"字段缺失 / 类型不符 /
/// 后端契约漂移"时返回**全 0 模型** ⇒ 页面把"数据不可用"渲染成 `0` / 空表 /
/// "未命中"（比报错更危险）；审计把它列为前端"静默归零"，共 5 处（status / snapshot /
/// pipeline / logs / query）。
///
/// 现在一律走本函数：解析失败 ⇒ 带**端点名 + serde 原因**的 [`ApiError`]，
/// 由 `poll.rs` 写进 `App.errs`，顶栏显示「数据不可用：<原因>」，页面不再显示假 0。
fn decode<T: serde::de::DeserializeOwned>(path: &str, v: Value) -> Result<T, ApiError> {
    serde_json::from_value(v)
        .map_err(|e| ApiError::new(format!("{path} 响应解析失败（数据不可用）: {e}"), false))
}

/// 读取 localStorage token（失败/未配置 → 空串）。
pub fn get_token() -> String {
    storage()
        .and_then(|s| s.get_item(TOKEN_KEY).ok())
        .flatten()
        .unwrap_or_default()
}

/// 写入/清除 localStorage token。
pub fn set_token(t: &str) {
    if let Some(s) = storage() {
        let _ = if t.is_empty() {
            s.remove_item(TOKEN_KEY)
        } else {
            s.set_item(TOKEN_KEY, t)
        };
    }
}

fn storage() -> Option<web_sys::Storage> {
    web_sys::window()?.local_storage().ok().flatten()
}

/// 核心请求：method + path + 可选 JSON body + 超时（毫秒）。
pub async fn req(
    method: &str,
    path: &str,
    body: Option<&Value>,
    timeout_ms: u32,
) -> Result<Value, ApiError> {
    let ms = if timeout_ms > 0 { timeout_ms } else { 10_000 };
    let method_upper = method.to_ascii_uppercase();

    let tok = get_token();
    let builder = match method_upper.as_str() {
        "GET" => Request::get(path),
        "POST" => Request::post(path),
        "PUT" => Request::put(path),
        "DELETE" => Request::delete(path),
        other => return Err(ApiError::new(format!("不支持的 HTTP 方法: {other}"), false)),
    };
    let builder = if !tok.is_empty() {
        builder.header("Authorization", &format!("Bearer {tok}"))
    } else {
        builder
    };

    // body===None 时不带 Content-Type/请求体（对齐原 M2 修复）。
    let req = if let Some(b) = body {
        builder
            .header("Content-Type", "application/json")
            .body(b.to_string())
            .map_err(|e| ApiError::new(e.to_string(), false))?
    } else {
        builder
            .build()
            .map_err(|e| ApiError::new(e.to_string(), false))?
    };

    use futures_lite::future::race;
    let path_owned = path.to_string();
    let send_fut = req.send();
    let resp: Response = match race(
        async {
            send_fut
                .await
                .map_err(|e| ApiError::new(e.to_string(), false))
        },
        async {
            TimeoutFuture::new(ms).await;
            Err::<Response, ApiError>(ApiError::new(
                format!("{path_owned} -> 请求超时 ({ms}ms)"),
                false,
            ))
        },
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return Err(e),
    };

    let status = resp.status();
    if !(200..300).contains(&status) {
        let detail = read_error_detail(&resp).await;
        let base = if detail.is_empty() {
            format!("{path} -> {status}")
        } else {
            format!("{path} -> {status}: {detail}")
        };
        let is_auth = status == 401;
        let mut msg = base;
        if status == 403 && method_upper != "GET" {
            msg.push_str(
                " (可能是 CSRF 拦截: 请检查地址栏 host:port 与后端 api.host 配置是否一致)",
            );
        }
        return Err(ApiError::new(msg, is_auth));
    }

    match resp.json::<Value>().await {
        Ok(v) => Ok(v),
        Err(e) => Err(ApiError::new(
            format!("{path} -> HTTP {status}: 响应不是合法 JSON ({e})"),
            false,
        )),
    }
}

/// 从非 2xx 响应体提取 error/detail。
async fn read_error_detail(resp: &Response) -> String {
    let text = match resp.text().await {
        Ok(t) => t,
        Err(_) => return String::new(),
    };
    if text.trim().is_empty() {
        return String::new();
    }
    if let Ok(v) = serde_json::from_str::<Value>(&text) {
        let mut d = v.get("error").map(jsonx_s).unwrap_or_default();
        if let Some(det) = v.get("detail").map(jsonx_s) {
            if !det.is_empty() {
                d = if d.is_empty() {
                    det
                } else {
                    format!("{d} ({det})")
                };
            }
        }
        return d;
    }
    String::new()
}

fn jsonx_s(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

// ---- 便捷方法 ----
pub async fn get(path: &str) -> Result<Value, ApiError> {
    req("GET", path, None, 10_000).await
}

pub async fn post(path: &str, body: Option<&Value>, ms: u32) -> Result<Value, ApiError> {
    req("POST", path, body, ms).await
}

pub async fn put(path: &str, body: Option<&Value>, ms: u32) -> Result<Value, ApiError> {
    req("PUT", path, body, ms).await
}

#[allow(dead_code)]
pub async fn del(path: &str, ms: u32) -> Result<Value, ApiError> {
    req("DELETE", path, None, ms).await
}

// ======================= 类型化端点 =======================

/// `GET /api/status`
pub async fn status() -> Result<Status, ApiError> {
    let v = get("/api/status").await?;
    // **2.1.43-B（P2-1）**：解析失败 = 显式错误（不再 `unwrap_or_default()` ⇒ 全 0）。
    decode("/api/status", v)
}

/// `GET /api/snapshot`
pub async fn snapshot() -> Result<Snapshot, ApiError> {
    let v = get("/api/snapshot").await?;
    // **2.1.43-B（P2-1）**：同上（历史曲线/KPI/上游健康度全部来自本响应）。
    decode("/api/snapshot", v)
}

/// `GET /api/pipeline`
pub async fn pipeline() -> Result<Pipeline, ApiError> {
    let v = get("/api/pipeline").await?;
    // **2.1.43-B（P2-1）**：同上（规则数/上游数缺失时页面显示「未知」而不是 0）。
    decode("/api/pipeline", v)
}

/// 每轮 `/api/logs` 请求的最大条数（与后端 `LogsQuery::limit` 默认值一致，
/// v1.9.162 语义：<1 → 500，>2000 → 2000）。
const LOG_LIMIT: usize = 500;

/// `/api/logs` 的查询串（D15）。
///
/// 把八列筛选里**可下推**的部分随请求发给后端，先在服务端收敛，再把本地过滤
/// （`pipeline::line_matches_filters`）当二次兜底——否则后端 `limit=500` 只回最近
/// 500 条，本地过滤会因窗口截断而漏掉更早的命中项。
///
/// 参数名实读后端 `LogsQuery`（crates/ebpdns-server/src/api.rs:1699-1723）：
/// `next_seq`(序号游标) / `q` / `level` / `domain` / `qtype` / `ip` / `answer` /
/// `upstream` / `rule` / `min_lat` / `limit`。
/// - `ts`（时间列）后端无对应参数 → 仍纯前端过滤；
/// - `la` 仅在后端可解析为数字时下发 `min_lat`（非数字时留前端文本包含）；
/// - `level` 后端支持，但前端八列里没有「级别」筛选框（级别由行 class 表达），
///   故无值可下发，保持不发送。
pub fn logs_query(since: u64, f: &LogFilters, q: &str, limit: Option<usize>) -> String {
    let mut p = url::form_urlencoded::Serializer::new(String::new());
    p.append_pair("next_seq", &since.to_string());
    let up = |s: &str| s.trim().to_string();
    if !q.trim().is_empty() {
        p.append_pair("q", q.trim());
    }
    if !up(&f.ip).is_empty() {
        p.append_pair("ip", &up(&f.ip));
    }
    if !up(&f.dm).is_empty() {
        p.append_pair("domain", &up(&f.dm));
    }
    if !up(&f.qt).is_empty() {
        p.append_pair("qtype", &up(&f.qt).to_uppercase());
    }
    if !up(&f.up).is_empty() {
        p.append_pair("upstream", &up(&f.up));
    }
    if !up(&f.an).is_empty() {
        p.append_pair("answer", &up(&f.an));
    }
    if !up(&f.rl).is_empty() {
        p.append_pair("rule", &up(&f.rl));
    }
    if let Ok(n) = up(&f.la).parse::<f64>() {
        if n.is_finite() {
            p.append_pair("min_lat", &n.to_string());
        }
    }
    if let Some(l) = limit {
        p.append_pair("limit", &l.to_string());
    }
    p.finish()
}

/// `GET /api/logs?next_seq=<seq>`（附可下推的筛选条件，见 [`logs_query`]）
///
/// 注意：1.9.162 的游标参数名是 `since`（语义为序号）；2.0 后端把 `since` 定义为
/// **时间戳**游标，序号游标是 `next_seq`。这里必须发 `next_seq`，否则每轮都会
/// 把整个事件环重放一遍（日志重复累积）。
pub async fn logs(since: u64, f: &LogFilters, q: &str) -> Result<LogsResp, ApiError> {
    let path = format!("/api/logs?{}", logs_query(since, f, q, Some(LOG_LIMIT)));
    let v = get(&path).await?;
    // **2.1.43-B（P2-1）**：解析失败 = 显式错误（`poll.rs` 会提示，不再静默丢弃整页日志）。
    decode("/api/logs", v)
}

/// `GET /api/config`（归一为 1.9.162 契约）
pub async fn config() -> Result<Value, ApiError> {
    let v = get("/api/config").await?;
    Ok(normalize_config(v))
}

/// `PUT /api/config`：把页面（1.9.162 契约）的工作副本反归一后下发。
/// 返回后端响应（`ignored_keys` 已并入前端剥离的只读段）。
pub async fn put_config(ui: &Value) -> Result<Value, ApiError> {
    let (body, stripped) = denormalize_config(ui);
    let resp = put("/api/config", Some(&body), 15_000).await?;
    let mut ignored: Vec<String> = resp
        .get("ignored_keys")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(jsonx_s).collect())
        .unwrap_or_default();
    for k in stripped {
        if !ignored.contains(&k) {
            ignored.push(k);
        }
    }
    // >>> 242B BEGIN P2-10-put >>> //
    Ok(json!({
        "ok": resp.get("ok").cloned().unwrap_or(Value::Bool(true)),
        "saved_to": resp.get("saved_to").cloned().unwrap_or(Value::Null),
        "ignored_keys": ignored,
        // **2.1.42-B（P2-10）**：适配层此前把后端的三桶回报丢成只剩 ignored_keys ⇒
        // 配置页的只读区永远显示本地兜底文案（后端 reason 到不了 UI）。
        "readonly_keys": resp.get("readonly_keys").cloned().unwrap_or_else(|| json!([])),
        "readonly_detail": resp.get("readonly_detail").cloned().unwrap_or_else(|| json!([])),
        "written_keys": resp.get("written_keys").cloned().unwrap_or_else(|| json!([])),
        "meta_keys": resp.get("meta_keys").cloned().unwrap_or_else(|| json!([])),
    }))
    // <<< 242B END P2-10-put <<< //
}

/// `POST /api/query`
///
/// **2.1.43-B（P2-1）**：解析失败必须变成 `Err` —— 旧实现 `unwrap_or_default()` 会返回
/// `{hit:false, error:false, ttl:None, answers:[]}`，查询页于是渲染
/// 「未命中 · 用户态解析 · TTL 0 s」（**假结论**，用户会以为域名真的没命中）。
/// 现在调用方走 ERR 分支：显示"后端 API 调用失败：…/api/query 响应解析失败（数据不可用）"。
pub async fn query(domain: &str, qtype: &str) -> Result<QueryResp, ApiError> {
    let body = json!({ "domain": domain, "qtype": qtype });
    let v = post("/api/query", Some(&body), 30_000).await?;
    decode("/api/query", v)
}

/// `POST /api/rules/import`
pub async fn rules_import(
    action: &str,
    group: Option<&str>,
    ip: Option<&str>,
    content: &str,
) -> Result<Value, ApiError> {
    let mut body = Map::new();
    body.insert("action".into(), json!(action));
    body.insert("content".into(), json!(content));
    if let Some(g) = group {
        body.insert("group".into(), json!(g));
    }
    if let Some(i) = ip {
        body.insert("ip".into(), json!(i));
    }
    post("/api/rules/import", Some(&Value::Object(body)), 30_000).await
}

/// `POST /api/reload`
pub async fn reload() -> Result<Value, ApiError> {
    post("/api/reload", None, 10_000).await
}

/// `POST /api/restart`
pub async fn restart() -> Result<Value, ApiError> {
    post("/api/restart", Some(&json!({ "confirm": true })), 10_000).await
}

/// `POST /api/reset`
pub async fn reset() -> Result<Value, ApiError> {
    post("/api/reset", Some(&json!({ "confirm": true })), 10_000).await
}

/// `POST /api/reprobe`
///
/// **2.1.14 清理（审计 ⑦）**：删掉了「`note` 字段 → 抛『后端未实现一键重测速』」
/// 的防御分支 —— 那是针对 2.0 桩实现的过期代码，2.1.x 后端早已真实实现
/// （实测 `POST /api/reprobe` → 200 + `{"ok":true,"results":[…]}`，永不返回 `note`）。
pub async fn reprobe() -> Result<Value, ApiError> {
    post("/api/reprobe", None, 30_000).await
}

/// `POST /api/rules/subscribe`
pub async fn subscribe(
    url: &str,
    action: &str,
    group: Option<&str>,
    ip: Option<&str>,
) -> Result<Value, ApiError> {
    let mut body = Map::new();
    body.insert("url".into(), json!(url));
    body.insert("action".into(), json!(action));
    if let Some(g) = group {
        body.insert("group".into(), json!(g));
    }
    if let Some(i) = ip {
        body.insert("ip".into(), json!(i));
    }
    // 2.1.14：同上，删除「`note` → 后端未实现规则订阅」死分支。
    post("/api/rules/subscribe", Some(&Value::Object(body)), 30_000).await
}

/// `POST /api/rules/subscribe/update`
pub async fn subscribe_update(url: &str) -> Result<Value, ApiError> {
    // 2.1.14：同上，删除「`note` → 后端未实现订阅更新」死分支。
    post(
        "/api/rules/subscribe/update",
        Some(&json!({ "url": url })),
        30_000,
    )
    .await
}

/// `DELETE /api/rules/subscribe?url=...`
pub async fn subscribe_delete(url: &str) -> Result<Value, ApiError> {
    let path = format!(
        "/api/rules/subscribe?url={}",
        url::form_urlencoded::byte_serialize(url.as_bytes()).collect::<String>()
    );
    // 2.1.14：同上，删除「`note` → 后端未实现订阅删除」死分支。
    del(&path, 15_000).await
}

// ======================= 展示级归一 =======================

/// `log_format`：后端 `plain` → 1.9.162 页面的 `text`。
pub fn log_format_text(v: &str) -> String {
    match v {
        "plain" => "text".to_string(),
        other => other.to_string(),
    }
}

/// 后端 `log_format` 取值（页面 → 后端）。
pub fn log_format_back(v: &str) -> String {
    match v {
        "text" => "plain".to_string(),
        other => other.to_string(),
    }
}

/// bootstrap_dns：数组 → 单个 "host:port"（1.9.162 页面是单行文本框且只支持单个）。
fn bootstrap_text(v: &Value) -> String {
    let text = match v {
        Value::Array(a) => a
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(" "),
        Value::String(s) => s.clone(),
        _ => String::new(),
    };
    text.split([' ', ',', ';'])
        .map(str::trim)
        .find(|s| !s.is_empty())
        .unwrap_or("")
        .to_string()
}

/// `ip_speed_probe`：2.0 侧可能是任意探测地址；1.9.162 页面只有 udp53/tcp443/both 三态。
fn ip_speed_probe_text(v: &str) -> String {
    match v {
        "udp53" | "tcp443" | "both" => v.to_string(),
        _ => "both".to_string(),
    }
}

/// bootstrap_dns：文本 → 数组（逗号/空格分隔，补默认端口 :53）。
fn bootstrap_list(v: &Value) -> Value {
    let text = match v {
        Value::String(s) => s.clone(),
        Value::Array(a) => a
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(" "),
        _ => String::new(),
    };
    let list: Vec<Value> = text
        .split([',', ' ', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| json!(s))
        .collect();
    Value::Array(list)
}

/// 2.0 响应 → 1.9.162 页面读取的配置形状。
pub fn normalize_config(v: Value) -> Value {
    let Value::Object(mut c) = v else {
        return v;
    };
    if let Some(l) = c
        .get("log_format")
        .and_then(Value::as_str)
        .map(log_format_text)
    {
        c.insert("log_format".into(), json!(l));
    }
    if let Some(b) = c.get("bootstrap_dns") {
        let t = bootstrap_text(b);
        c.insert("bootstrap_dns".into(), json!(t));
    }
    if let Some(p) = c.get("ip_speed_probe").and_then(Value::as_str) {
        let t = ip_speed_probe_text(p);
        c.insert("ip_speed_probe".into(), json!(t));
    }
    if let Some(Value::Array(ups)) = c.get_mut("upstreams") {
        for u in ups.iter_mut() {
            if let Value::Object(o) = u {
                if !o.contains_key("addr") {
                    let host = o
                        .get("host")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    o.insert("addr".into(), json!(host));
                }
                if !o.contains_key("url") {
                    o.insert("url".into(), json!("/dns-query"));
                }
                if !o.contains_key("group") {
                    o.insert("group".into(), json!("domestic"));
                }
            }
        }
    }
    if let Some(Value::Array(rules)) = c.get_mut("rules") {
        for (i, r) in rules.iter_mut().enumerate() {
            if let Value::Object(o) = r {
                if !o.contains_key("match") {
                    let m = o
                        .get("match_raw")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    o.insert("match".into(), json!(m));
                }
                // **必须**补 id：`config.json` 的 `rules[]` 历史上 `id: null`
                // （GET /api/config 原样返回，只有 GET /api/rules 才惰性补 `rmig%d`），
                // 而页面 `row_remove`/`row_set` 按 `data-id` 定位行 —— id 为空时
                // 「逐条规则」的新增/删除/编辑全是**静默 no-op**（用户报告的写/删失败根因）。
                // 用与后端 `ensure_ids` 相同的确定性规则（`rmig<序号>`）补齐，
                // 使回传的 id 稳定、且与 `GET /api/rules` 的 id 一致。
                let has_id = o
                    .get("id")
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.is_empty());
                if !has_id {
                    o.insert("id".into(), json!(format!("rmig{}", i + 1)));
                }
                if !o.contains_key("action") {
                    o.insert("action".into(), json!("group"));
                }
                if !o.contains_key("group") {
                    o.insert("group".into(), json!("domestic"));
                }
                if !o.contains_key("ip") {
                    o.insert("ip".into(), json!(""));
                }
            }
        }
    }
    // 页面读取但 2.0 配置里可能缺失的键，补 1.9.162 默认值。
    let defaults: &[(&str, Value)] = &[
        ("circuit_fails", json!(3)),
        ("circuit_open_s", json!(30)),
        ("speed_timeout_ms", json!(300)),
        ("ip_speed_probe", json!("both")),
        ("ip_speed_cache_ttl", json!(60)),
        ("nxdomain_quorum", json!(2)),
        ("edns_client_max_size", json!(1232)),
        ("rule_sub_interval", json!(3600)),
        ("persist_ttl", json!(0)),
        ("stale_ttl", json!(3600)),
        ("cache_partitions", json!(16)),
        ("udp_dropped", json!(0)),
        ("rule_subscriptions", json!([])),
    ];
    for (k, d) in defaults {
        if !c.contains_key(*k) {
            c.insert((*k).to_string(), d.clone());
        }
    }
    Value::Object(c)
}

/// 页面配置 → 2.0 请求体；返回 (body, 被前端剥离的只读键)。
pub fn denormalize_config(ui: &Value) -> (Value, Vec<String>) {
    let Value::Object(src) = ui else {
        return (ui.clone(), Vec::new());
    };
    let mut out = Map::new();
    let mut stripped: Vec<String> = Vec::new();
    for (k, v) in src.iter() {
        match k.as_str() {
            // 只读段：与 1.9.162 后端一致，改了不生效（并入 ignored_keys）。
            "api" | "listen" | "web_root" | "cache_file" | "udp_dropped" | "dns_port" => {
                stripped.push(k.clone());
            }
            "log_format" => {
                out.insert(k.clone(), json!(log_format_back(v.as_str().unwrap_or(""))));
            }
            "bootstrap_dns" => {
                out.insert(k.clone(), bootstrap_list(v));
            }
            "upstreams" => {
                out.insert(k.clone(), upstreams_back(v));
            }
            "rules" => {
                out.insert(k.clone(), rules_back(v));
            }
            _ => {
                out.insert(k.clone(), v.clone());
            }
        }
    }
    (Value::Object(out), stripped)
}

/// upstreams：`addr` → `host`，剔除只读遥测键。
fn upstreams_back(v: &Value) -> Value {
    let Value::Array(arr) = v else {
        return v.clone();
    };
    let telemetry = [
        "addr",
        "queries",
        "success_rate",
        "avg_latency",
        "status",
        "conn_avg_lat",
        "conn_ok",
        "conn_fail",
        "conn_key",
        "quic_connected",
        "quic_reconnects",
        "quic_fail_seq",
    ];
    let out: Vec<Value> = arr
        .iter()
        .map(|u| {
            let Value::Object(o) = u else {
                return u.clone();
            };
            let mut m = Map::new();
            for (k, val) in o.iter() {
                if telemetry.contains(&k.as_str()) {
                    continue;
                }
                m.insert(k.clone(), val.clone());
            }
            if !m.contains_key("host") {
                let host = o
                    .get("addr")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                m.insert("host".into(), json!(host));
            }
            if !m.contains_key("port") {
                m.insert("port".into(), json!(53));
            }
            if !m.contains_key("proto") {
                m.insert("proto".into(), json!("udp"));
            }
            Value::Object(m)
        })
        .collect();
    Value::Array(out)
}

/// rules：保留 v1.9.162 的 `match` 键（后端 `rule_from_json` 与 `cfg_to_resolver`
/// 都已兼容 `match`；不再改名为历史键 `match_raw`，避免磁盘配置出现只有 `match_raw`
/// 而其它读取方（含 Python 端）读不到的情况）。
fn rules_back(v: &Value) -> Value {
    v.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filters() -> LogFilters {
        LogFilters::default()
    }

    /// D15：八列里可下推的项必须出现在查询串里，参数名与后端 `LogsQuery` 一致。
    #[test]
    fn logs_query_pushes_supported_columns() {
        let f = LogFilters {
            ts: "12:00".into(),      // 后端无对应参数 → 不下发
            ip: " 10.0.0.1 ".into(), // 两侧空白应被裁剪
            dm: " Example.COM ".into(),
            qt: " aaaa ".into(), // 后端精确匹配 → 转大写
            up: "u1".into(),
            an: "1.2.3.4".into(),
            la: "25.5".into(),
            rl: "*.ads".into(),
        };
        let q = logs_query(7, &f, "  err ", Some(500));
        assert_eq!(
            q,
            "next_seq=7&q=err&ip=10.0.0.1&domain=Example.COM&qtype=AAAA&upstream=u1\
             &answer=1.2.3.4&rule=*.ads&min_lat=25.5&limit=500"
        );
        assert!(!q.contains("ts="), "ts 列后端不支持, 不应下发: {q}");
    }

    #[test]
    fn logs_query_empty_filters_only_sends_cursor_and_limit() {
        assert_eq!(
            logs_query(0, &filters(), "", Some(500)),
            "next_seq=0&limit=500"
        );
        // 不传 limit（清空后对齐游标时的等价路径）只剩游标。
        assert_eq!(logs_query(42, &filters(), "", None), "next_seq=42");
    }

    /// `la` 非数字：不下发 `min_lat`，留给前端文本包含兜底。
    #[test]
    fn logs_query_non_numeric_latency_is_not_pushed() {
        let f = LogFilters {
            la: "abc".into(),
            ..LogFilters::default()
        };
        assert_eq!(logs_query(1, &f, "", None), "next_seq=1");
        let f = LogFilters {
            la: "NaN".into(),
            ..LogFilters::default()
        };
        assert_eq!(logs_query(1, &f, "", None), "next_seq=1");
    }

    /// 特殊字符必须被 URL 编码，避免筛选词里的 `&`/`=` 破坏查询串。
    #[test]
    fn logs_query_escapes_special_characters() {
        let f = LogFilters {
            dm: "a&b=c d".into(),
            ..LogFilters::default()
        };
        assert_eq!(logs_query(1, &f, "", None), "next_seq=1&domain=a%26b%3Dc+d");
    }

    #[test]
    fn log_format_text_is_bijective_for_known_values() {
        assert_eq!(log_format_back(&log_format_text("plain")), "plain");
    }

    /// D8 的姊妹项：订阅响应键名（后端 `subscribe.rs:863` / `:920`）。
    #[test]
    fn normalize_config_maps_legacy_keys() {
        let raw = json!({
            "log_format": "plain",
            "bootstrap_dns": ["223.5.5.5:53", "1.1.1.1"],
            "ip_speed_probe": "weird",
            "upstreams": [{"id": "u1", "host": "1.1.1.1", "proto": "udp"}],
            "rules": [{"id": "r1", "match_raw": "*.ads.com"}],
        });
        let n = normalize_config(raw);
        assert_eq!(n["log_format"], json!("text"));
        // bootstrap_dns：数组 → 单个 host:port（页面是单行文本框）
        assert_eq!(n["bootstrap_dns"], json!("223.5.5.5:53"));
        // 非法探测方式回退 both
        assert_eq!(n["ip_speed_probe"], json!("both"));
        // 上游：host → addr，补 url/group
        assert_eq!(n["upstreams"][0]["addr"], json!("1.1.1.1"));
        assert_eq!(n["upstreams"][0]["url"], json!("/dns-query"));
        assert_eq!(n["upstreams"][0]["group"], json!("domestic"));
        assert_eq!(n["upstreams"][0]["host"], json!("1.1.1.1"));
        // 规则：match_raw → match，补 action/group/ip
        assert_eq!(n["rules"][0]["match"], json!("*.ads.com"));
        assert_eq!(n["rules"][0]["action"], json!("group"));
        assert_eq!(n["rules"][0]["ip"], json!(""));
        // 页面读取但后端不发的键 → 补 1.9.162 默认值
        assert_eq!(n["circuit_fails"], json!(3));
        assert_eq!(n["nxdomain_quorum"], json!(2));
        assert_eq!(n["rule_subscriptions"], json!([]));
    }

    #[test]
    fn normalize_config_keeps_existing_values() {
        let raw = json!({
            "bootstrap_dns": "9.9.9.9",
            "ip_speed_probe": "udp53",
            "upstreams": [{"id": "u2", "addr": "8.8.8.8", "url": "/q", "group": "global"}],
            "rules": [{"id": "r2", "match": "x.com", "action": "block", "group": "global", "ip": "1.1.1.1"}],
            "circuit_fails": 5,
        });
        let n = normalize_config(raw.clone());
        assert_eq!(n["bootstrap_dns"], json!("9.9.9.9"));
        assert_eq!(n["ip_speed_probe"], json!("udp53"));
        assert_eq!(n["upstreams"][0]["url"], json!("/q"));
        assert_eq!(n["upstreams"][0]["group"], json!("global"));
        assert_eq!(n["rules"][0]["match"], json!("x.com"));
        assert_eq!(n["rules"][0]["action"], json!("block"));
        assert_eq!(n["circuit_fails"], json!(5), "已有值不得被默认值覆盖");
    }

    /// `denormalize_config` 与 `normalize_config` 的可逆面：只读段被剥离，
    /// log_format/upstreams 反归一。
    #[test]
    fn denormalize_strips_readonly_and_maps_back() {
        let ui = json!({
            "log_format": "text",
            "bootstrap_dns": "223.5.5.5, 1.1.1.1",
            "listen": {"udp": "127.0.0.1:53"},
            "api": {"token": "x"},
            "cache_file": "/tmp/c.json",
            "upstreams": [{
                "id": "u1", "host": "1.1.1.1", "addr": "1.1.1.1", "proto": "udp",
                "port": 53, "conn_avg_lat": 12.0, "conn_ok": 3, "conn_fail": 0,
                "conn_key": "k", "queries": 9, "success_rate": 100.0,
                "avg_latency": 1.0, "status": "ok"
            }],
        });
        let (body, stripped) = denormalize_config(&ui);
        assert_eq!(body["log_format"], json!("plain"));
        assert_eq!(body["bootstrap_dns"], json!(["223.5.5.5", "1.1.1.1"]));
        for k in ["listen", "api", "cache_file"] {
            assert!(body.get(k).is_none(), "{k} 应被剥离");
            assert!(stripped.contains(&k.to_string()), "{k} 应记入 ignored_keys");
        }
        // 遥测键必须剥离，否则 PUT 回传时把服务端统计写回配置。
        let up = &body["upstreams"][0];
        for k in [
            "addr",
            "conn_avg_lat",
            "conn_ok",
            "conn_fail",
            "conn_key",
            "queries",
            "status",
        ] {
            assert!(up.get(k).is_none(), "upstreams[0].{k} 应被剥离: {up}");
        }
        assert_eq!(up["host"], json!("1.1.1.1"));
        assert_eq!(up["port"], json!(53));
        assert_eq!(up["proto"], json!("udp"));
    }

    /// 逐条规则行操作（`row_remove`/`row_set`）按 `data-id` 定位；`config.json` 的
    /// `rules[]` 历史上 `id: null`（GET /api/config 原样返回），若前端不补 id，
    /// 删除/编辑就是静默 no-op —— 这是「逐条规则写入/删除失败」的直接根因。
    #[test]
    fn normalize_config_fills_missing_rule_id() {
        let raw = json!({
            "rules": [
                {"action": "group", "group": "domestic", "id": null, "match": "*.2", "match_raw": "*.2"},
                {"action": "block", "match_raw": "*.3"},
                {"id": "rkeep", "match": "x.com", "action": "block"},
                {"id": "", "match": "y.com", "action": "allow"},
            ],
        });
        let n = normalize_config(raw);
        // 与后端 `ensure_ids` 同口径：`rmig<1-based 序号>`。
        assert_eq!(n["rules"][0]["id"], json!("rmig1"));
        assert_eq!(n["rules"][1]["id"], json!("rmig2"));
        // 已有 id 不得被覆盖。
        assert_eq!(n["rules"][2]["id"], json!("rkeep"));
        // 空串 id 视为缺失。
        assert_eq!(n["rules"][3]["id"], json!("rmig4"));
        // match 仍从 match_raw 补齐。
        assert_eq!(n["rules"][1]["match"], json!("*.3"));
        // 其它默认值不受影响。
        assert_eq!(n["rules"][1]["action"], json!("block"));
        assert_eq!(n["rules"][1]["group"], json!("domestic"));
        assert_eq!(n["rules"][1]["ip"], json!(""));
        // 补出的 id 必须能作为 PUT /api/config 的回传值被后端 `ensure_ids` 接受
        // （非空字符串），否则「保存后 id 又被换掉」→ 行引用失效。
        for i in 0..4 {
            assert!(
                n["rules"][i]["id"].as_str().is_some_and(|s| !s.is_empty()),
                "rules[{i}].id 必须是非空字符串"
            );
        }
    }

    /// **2.1.43-B（P2-1）回归**：`decode` 必须把"类型不符/字段缺失"变成**带端点名 + 原因**
    /// 的 `Err`，而不是 `unwrap_or_default()` 的全 0 模型。
    #[test]
    fn decode_rejects_bad_shape_instead_of_silently_defaulting() {
        // `counters` 类型不符（字符串而非对象）⇒ 必须失败。
        let bad = json!({ "counters": "not-an-object" });
        let err = decode::<crate::model::Status>("/api/status", bad)
            .expect_err("类型不符必须返回 Err（旧实现会得到全 0 Status）");
        assert!(
            err.message.contains("/api/status"),
            "错误必须带端点名：{}",
            err.message
        );
        assert!(
            err.message.contains("数据不可用"),
            "错误必须带统一措辞（顶栏横幅依赖它）：{}",
            err.message
        );
        assert!(!err.is_auth_error, "解析失败不是认证失败");
        // 合法响应仍能解析（不误伤正常路径）。
        let ok = json!({ "app": "ebpdns", "version": "2.1.43", "counters": {} });
        assert!(decode::<crate::model::Status>("/api/status", ok).is_ok());
        // **字段缺失**（`cache_policy` 现在 `Option<String>`）必须解析成 `None` 而不是空串。
        let st: crate::model::Status =
            decode("/api/status", json!({"app": "ebpdns"})).expect("缺字段仍可解析");
        assert_eq!(
            st.cache_policy, None,
            "缺失必须是 None（页面据此显示未采集）"
        );
    }
}

/* ======================= 已删除的前端 API 包装（2.1.14） =======================
 *
 * 随「规则管理」页删除的四个**单条规则 CRUD** 包装（旧 `web/src/api.rs`）：
 *   `list_rules()`         → GET    /api/rules
 *   `create_rule()`        → POST   /api/rules
 *   `delete_rule(id)`      → DELETE /api/rules/{id}
 *   `update_rule(id, …)`   → PUT    /api/rules/{id}
 *
 * **为何确定无人使用**：全仓 grep `list_rules|create_rule|delete_rule|update_rule`
 * 在前端源码目录内只有 `pages/rules.rs`（该页已删除，且它本身编译不过 ——
 * `rules.rs:174` 引用未定义的 `action2/group2/ip2`）。配置页的「分流规则」卡片走的是
 * `PUT /api/config` 全量下发 `rules[]`（config.rs:2708），并用
 * `api::rules_import` / `api::subscribe*`（本文件保留）做导入与订阅。
 *
 * **后端端点保留**：`/api/rules` 的 CRUD 仍在 `rules_admin.rs` 注册（属公开管理面，
 * 非页面死数据），只是前端不再有调用点；如需恢复独立规则页，从这里恢复包装即可。
 */
