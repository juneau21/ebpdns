//! ebpdns-server 错误类型：所有 HTTP/数据面错误一律结构化 JSON 响应，绝不 panic。

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// 服务端错误。`IntoResponse` 统一收口为带安全响应头的 JSON（对齐 api.py `_send`）。
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// 400：请求体/参数非法。
    #[error("{0}")]
    BadRequest(String),
    /// 401：未携带正确 API token。
    #[error("未授权")]
    Unauthorized,
    /// 403：CSRF / 跨源读 / 路径穿越被拒。
    #[error("forbidden")]
    Forbidden(String),
    /// 404。
    #[error("not found")]
    NotFound,
    /// 404 + 自定义文案（对齐 v1.9.162 的 `{"error":"rule not found"}` / `"订阅不存在: <url>"`）。
    #[error("{0}")]
    NotFoundWith(String),
    /// 409：状态冲突（重启防重入等）。
    #[error("{0}")]
    Conflict(String),
    /// **409 + 结构化响应体**（**2.1.23 / DEF-222-16**）。
    ///
    /// 为什么需要它：`Conflict(String)` 只渲染 `{"error": "…"}`，于是"409 带**当前**
    /// revision"这条承诺只在**文本**层面成立、在**机读**层面不成立（客户端只能拿正则
    /// 从文案里抠数字）。本变体让调用方给一个**对象**，直接作为响应体下发 ⇒
    /// 客户端可以 `body["current"]` 自动重读并重试。
    #[error("{}", .0.get("error").and_then(|v| v.as_str()).unwrap_or("conflict"))]
    ConflictWith(serde_json::Value),
    /// 413：请求体或文件过大。
    #[error("{0}")]
    PayloadTooLarge(String),
    /// 502：上游解析失败（不回显内网拓扑）。
    #[error("{0}")]
    BadGateway(String),
    /// 500：未预期内部错误（不回显细节）。
    #[error("internal error")]
    Internal,
    /// **2.1.49（P0）**：500 + **结构化**响应体（reload 失败的可机读原因）。
    ///
    /// 与 [`ServerError::ConflictWith`] 同型：整个对象直接作为响应体，不再包一层
    /// `{"error":"internal error"}` —— 客户端可读 `body["error"]` / `body["detail"]`。
    #[error("{}", .0.get("error").and_then(|v| v.as_str()).unwrap_or("internal error"))]
    InternalWith(serde_json::Value),
}

impl ServerError {
    /// **[历史归因]** 与 Python `_send` 对齐的安全响应头。
    fn with_security_headers<B>(mut resp: Response<B>) -> Response<B> {
        use axum::http::HeaderValue;
        let h = resp.headers_mut();
        h.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
        h.insert(
            "Content-Security-Policy",
            HeaderValue::from_static("frame-ancestors 'none'"),
        );
        h.insert(
            "X-Content-Type-Options",
            HeaderValue::from_static("nosniff"),
        );
        h.insert("Referrer-Policy", HeaderValue::from_static("no-referrer"));
        h.insert("Cache-Control", HeaderValue::from_static("no-store"));
        resp
    }
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            ServerError::BadRequest(m) => (StatusCode::BAD_REQUEST, json!({"error": m})),
            ServerError::Unauthorized => (StatusCode::UNAUTHORIZED, json!({"error": "未授权"})),
            ServerError::Forbidden(m) => (StatusCode::FORBIDDEN, json!({"error": m})),
            ServerError::NotFound => (StatusCode::NOT_FOUND, json!({"error": "not found"})),
            ServerError::NotFoundWith(m) => (StatusCode::NOT_FOUND, json!({"error": m})),
            ServerError::Conflict(m) => (StatusCode::CONFLICT, json!({"error": m})),
            // 结构化 409（2.1.23 / DEF-222-16）：整体作为响应体，不再包一层。
            ServerError::ConflictWith(v) => (StatusCode::CONFLICT, v),
            ServerError::PayloadTooLarge(m) => (StatusCode::PAYLOAD_TOO_LARGE, json!({"error": m})),
            ServerError::BadGateway(m) => (StatusCode::BAD_GATEWAY, json!({"error": m})),
            ServerError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": "internal error"}),
            ),
            // 结构化 500（2.1.49）：整个对象作为响应体（reload 的机读失败原因）。
            ServerError::InternalWith(v) => (StatusCode::INTERNAL_SERVER_ERROR, v),
        };
        let resp = (status, Json(body)).into_response();
        Self::with_security_headers(resp)
    }
}

/// 便捷结果别名。
pub type ServerResult<T> = Result<T, ServerError>;
