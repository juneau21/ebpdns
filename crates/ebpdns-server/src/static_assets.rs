//! 静态资源服务：对齐 api.py `_serve_static`。
//!
//! - `embed-frontend` feature：用 rust-embed 把 `web/dist` 编译进二进制（发布用）；
//! - feature 未开：从磁盘 `web_root` 路径读（开发期，trunk 产出 web/dist 后指向它）；
//! - SPA：未知非 API 路径回退 `index.html`；
//! - 防目录穿越：realpath 校验必须落在根内；文件上限 10MB；正确 MIME；
//!   安全响应头 + 禁缓存。

use std::path::{Path, PathBuf};

// P2（2.1.14）：这两个导入只服务磁盘分支（`serve_disk_file`，仅在
// `not(embed-frontend)` 时编译）→ 精确门禁，开启 feature 的发布构建零告警。
#[cfg(not(feature = "embed-frontend"))]
use std::fs::File;
#[cfg(not(feature = "embed-frontend"))]
use std::io::Read;

use axum::body::Body;
use axum::http::{header, Response, StatusCode, Uri};
use serde_json::json;

/// 文件大小上限（对齐 _serve_static 10MB）。
const MAX_FILE: usize = 10 * 1024 * 1024;

/// rust-embed 嵌入前端（仅 embed-frontend feature）。指向 trunk 产出的 web/dist。
#[cfg(feature = "embed-frontend")]
#[derive(rust_embed::RustEmbed)]
#[folder = "$CARGO_MANIFEST_DIR/../../web/dist"]
struct EmbeddedAssets;

/// MIME 映射（对齐 api.py `_STATIC_MIME`）。
fn mime_of(path: &str) -> &'static str {
    match Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "html" => "text/html; charset=utf-8",
        "js" => "application/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "wasm" => "application/wasm",
        "json" => "application/json",
        _ => "application/octet-stream",
    }
}

/// 带静态安全头的响应构造。
fn build_response(status: StatusCode, ctype: &str, body: Vec<u8>) -> Response<Body> {
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = status;
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        ctype
            .parse()
            .unwrap_or_else(|_| "text/plain".parse().unwrap()),
    );
    h.insert(
        header::CACHE_CONTROL,
        "no-cache, no-store, must-revalidate".parse().unwrap(),
    );
    h.insert("Pragma", "no-cache".parse().unwrap());
    h.insert("Expires", "0".parse().unwrap());
    h.insert("X-Frame-Options", "DENY".parse().unwrap());
    if let Ok(v) = "default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'".parse()
    {
        h.insert("Content-Security-Policy", v);
    }
    h.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    h.insert("Referrer-Policy", "no-referrer".parse().unwrap());
    resp
}

/// **[历史归因]** 文件长度是否超限（严格 `>`，与 Python `size > 10*1024*1024` 一致：恰好 10MB 放行）。
fn over_limit(len: u64) -> bool {
    len > MAX_FILE as u64
}

fn err(status: StatusCode, msg: &str) -> Response<Body> {
    build_response(
        status,
        "application/json",
        serde_json::to_vec(&json!({"error": msg})).unwrap_or_default(),
    )
}

/// 读取一个静态文件。`uri_path` 已去除前导 `/`；`web_root` 为磁盘根（feature 未开时）。
///
/// **P2（2.1.14）**：`web_root` 只在 `not(embed-frontend)` 分支使用；开启 feature 时
/// 它是未使用参数 → 用 `cfg_attr` 精确 allow，保证**两种构建都零告警**。
#[cfg_attr(feature = "embed-frontend", allow(unused_variables))]
pub async fn serve(uri: &Uri, web_root: &Option<PathBuf>) -> Response<Body> {
    let path = uri.path().trim_start_matches('/');

    // ---- embed 路径（feature 开）----
    #[cfg(feature = "embed-frontend")]
    {
        // F28：rust-embed 的 key 必须用 `/` 分隔。此前用
        // `PathBuf::to_string_lossy()` 拼接，Windows 上产出 `assets\x.js` →
        // 与嵌入表里的 `assets/x.js` 不匹配 → 子目录资源 404。
        let key = match normalize_embed_key(path) {
            Some(k) => k,
            None => return err(StatusCode::FORBIDDEN, "forbidden"),
        };
        match EmbeddedAssets::get(&key) {
            Some(file) => {
                // 10MB 上限必须在读入前判定（`file.data` 是嵌入的 `Cow<'static, [u8]>`，
                // 无需 to_vec 即可取长度）。
                let len = file.data.len() as u64;
                if over_limit(len) {
                    return err(StatusCode::PAYLOAD_TOO_LARGE, "file too large (max 10MB)");
                }
                return build_response(StatusCode::OK, mime_of(&key), file.data.to_vec());
            }
            None => {
                // SPA fallback：非静态资源请求回退 index.html。
                if !looks_like_asset(&key) {
                    if let Some(idx) = EmbeddedAssets::get("index.html") {
                        return build_response(
                            StatusCode::OK,
                            "text/html; charset=utf-8",
                            idx.data.to_vec(),
                        );
                    }
                }
                return err(StatusCode::NOT_FOUND, "not found");
            }
        }
    }

    // ---- 磁盘路径（feature 未开）----
    #[cfg(not(feature = "embed-frontend"))]
    {
        let Some(root) = web_root.as_ref() else {
            return err(StatusCode::NOT_FOUND, "not found");
        };
        let root_real = match std::fs::canonicalize(root) {
            Ok(r) => r,
            Err(_) => return err(StatusCode::NOT_FOUND, "not found"),
        };

        // `/`（空 path）或目录请求：直接回退 index.html（SPA 入口）。
        if path.is_empty() {
            let idx = root_real.join("index.html");
            return serve_disk_file(&idx)
                .unwrap_or_else(|| err(StatusCode::NOT_FOUND, "not found"));
        }

        // 目录穿越防护：join 后 canonicalize 必须落在 root 内。
        let target = root_real.join(path);
        let target_real = match std::fs::canonicalize(&target) {
            Ok(t) => t,
            Err(_) => {
                // 文件不存在：SPA fallback（非资源请求回退 index.html）。
                if looks_like_asset(path) {
                    return err(StatusCode::NOT_FOUND, "not found");
                }
                let idx = root_real.join("index.html");
                return serve_disk_file(&idx)
                    .unwrap_or_else(|| err(StatusCode::NOT_FOUND, "not found"));
            }
        };
        if !target_real.starts_with(&root_real) {
            return err(StatusCode::FORBIDDEN, "forbidden");
        }
        // 命中的是目录（如 /dashboard）：回退 index.html。
        if target_real.is_dir() {
            let idx = target_real.join("index.html");
            return serve_disk_file(&idx)
                .unwrap_or_else(|| err(StatusCode::NOT_FOUND, "not found"));
        }
        serve_disk_file(&target_real).unwrap_or_else(|| err(StatusCode::NOT_FOUND, "not found"))
    }
}

/// 读单个磁盘文件（≤10MB）。
///
/// F28/TOC 加固：**先 open 再 fstat 复核**，而不是 `canonicalize()` →
/// `metadata()` → `read()`（三段式之间存在符号链接被替换、文件被换成 FIFO/设备
/// 文件、体积在被替换后膨胀的 TOCTOU 窗口）：
/// 1. `open` 拿到的 fd 指向解析后的最终对象，后续读取不再受路径重定向影响；
/// 2. 打开后用同一个 fd `metadata()` 复核「是常规文件」+「≤10MB」，超限直接 413
/// **[历史归因]**    **不读入**（对齐 Python：先 fstat 判 size 再 read）；
/// 3. 按 `take(MAX_FILE+1)` 有界读取，即使文件在 fstat 后被追加也不会把内存读爆；
/// 4. 读到的字节数与 fstat 结果不一致（写入期间被改写/截断）→ 视为不可信，按 404 处理。
///
/// **P2（2.1.14）**：只在 `not(embed-frontend)` 的磁盘分支被调用 → 精确门禁，
/// 开启 `embed-frontend`（发布构建）时不再产生 `function is never used` 告警。
#[cfg(not(feature = "embed-frontend"))]
fn serve_disk_file(path: &Path) -> Option<Response<Body>> {
    let mut f = File::open(path).ok()?;
    let meta = f.metadata().ok()?;
    // 常规文件校验（排除目录、FIFO、字符/块设备、socket）。
    if !meta.is_file() {
        return None;
    }
    if over_limit(meta.len()) {
        return Some(err(
            StatusCode::PAYLOAD_TOO_LARGE,
            "file too large (max 10MB)",
        ));
    }
    let expected = meta.len() as usize;
    let mut body: Vec<u8> = Vec::with_capacity(expected);
    // 有界读取：最多多读 1 字节即可判定“被追加/超限”。
    if f.by_ref()
        .take(MAX_FILE as u64 + 1)
        .read_to_end(&mut body)
        .is_err()
    {
        return None;
    }
    if over_limit(body.len() as u64) {
        return Some(err(
            StatusCode::PAYLOAD_TOO_LARGE,
            "file too large (max 10MB)",
        ));
    }
    if body.len() != expected {
        // 读取期间文件被改写/截断：fail-closed。
        return None;
    }
    Some(build_response(
        StatusCode::OK,
        mime_of(&path.to_string_lossy()),
        body,
    ))
}

/// 路径规范化（embed 用）：按 `/` 与 `\` 切分，统一产出 `/` 分隔的 rust-embed key。
///
/// F28：Windows 上此前用 `PathBuf::to_string_lossy()` 拼 key → `assets\x.js`，
/// 与嵌入表 `assets/x.js` 不匹配（子目录资源 404）。
///
/// fail-closed 规则（返回 `None` → 403）：
/// - `..` 段（目录穿越，包括 `a/../..` 这类真能上跳的形态）；
/// - 含 NUL / 控制字符的段；
/// - `C:` 这类盘符前缀（绝对路径伪装）。
/// 其余前导 `/`、重复 `/`、`\`、`.` 段一律吸收为规范相对 key（`/etc/passwd`
/// → `etc/passwd`，永远落在静态根内）。
/// 归一 embed key：统一 `/` 分隔、拒绝穿越与非法字符。
///
/// **返回值语义**：`None` = 该路径**被拒绝**（控制字符 / `..` / `:` 等 → 403 fail-closed）；
/// `Some("")` = 空/根路径（`/`、`//`、`/.`）→ 交由调用方的查表 miss + SPA 回退处理
/// （回退 `index.html`）。
///
/// 历史缺陷：早期实现在此处把「归一后为空」也判成 `None` → 访问 `/` 直接 403
/// `{"error":"forbidden"}`（控制台首页打不开）。根路径必须走 SPA 回退，不能 fail-closed。
///
/// **P2（2.1.14）**：本函数只在 `embed-frontend` 构建路径与测试里使用 ——
/// 不加 cfg 会让 `cargo build`（未开 feature，例如 `cargo test --workspace`）
/// 报 `function is never used`。用 `any(feature, test)` 精确门禁，两种构建都零告警。
#[cfg(any(feature = "embed-frontend", test))]
fn normalize_embed_key(path: &str) -> Option<String> {
    if path.contains('\0') {
        return None;
    }
    let mut segs: Vec<&str> = Vec::new();
    for seg in path.split(['/', '\\']) {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return None;
        }
        if seg
            .chars()
            .any(|c| c.is_control() || c == ':' || c == '<' || c == '>' || c == '"' || c == '|')
        {
            return None;
        }
        segs.push(seg);
    }
    // 注意：不做 `segs.is_empty() → None`。空 key 是合法的「根路径」语义，
    // 由调用方的 `EmbeddedAssets::get("")` miss 后回退 index.html。
    Some(segs.join("/"))
}

/// 是否像静态资源（带扩展名）——决定 SPA fallback。
fn looks_like_asset(path: &str) -> bool {
    !path.is_empty() && Path::new(path).extension().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    fn hdr_str(resp: &Response<Body>, name: &str) -> String {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    }

    /// F28：embed key 必须用 `/` 拼接（Windows 上 `\` 曾导致子目录资源 404）。
    #[test]
    fn embed_key_uses_forward_slash() {
        assert_eq!(
            normalize_embed_key("assets/x.js").as_deref(),
            Some("assets/x.js")
        );
        // Windows 风格分隔符 → 归一为 `/`。
        assert_eq!(
            normalize_embed_key("assets\\x.js").as_deref(),
            Some("assets/x.js")
        );
        assert_eq!(
            normalize_embed_key("assets\\sub\\x.js").as_deref(),
            Some("assets/sub/x.js")
        );
        // 前导/重复分隔符与 `.` 段被吸收。
        assert_eq!(normalize_embed_key("/x.js").as_deref(), Some("x.js"));
        assert_eq!(normalize_embed_key("//a//b.js").as_deref(), Some("a/b.js"));
        assert_eq!(normalize_embed_key("./a/./b.js").as_deref(), Some("a/b.js"));
        // `\` 开头同样按相对 key 处理（绝不产出绝对路径）。
        assert_eq!(normalize_embed_key("\\a\\b.js").as_deref(), Some("a/b.js"));
    }

    /// `..` 目录穿越与畸形路径必须 fail-closed（None → 403），不做“pop 上跳”补偿。
    #[test]
    fn embed_key_rejects_traversal_and_malformed() {
        assert_eq!(normalize_embed_key("../secret"), None);
        assert_eq!(normalize_embed_key("a/../../secret"), None);
        assert_eq!(normalize_embed_key("a\\..\\secret"), None);
        assert_eq!(normalize_embed_key(".."), None);
        assert_eq!(normalize_embed_key("a/.."), None);
        // 空/根路径**不是**拒绝：归一为空字符串，由调用方查表 miss 后回退 index.html
        // （旧实现把它判成 None → 首页 403 `{"error":"forbidden"}`）。
        assert_eq!(normalize_embed_key("").as_deref(), Some(""));
        assert_eq!(normalize_embed_key("/").as_deref(), Some(""));
        assert_eq!(normalize_embed_key("./.").as_deref(), Some(""));
        assert_eq!(normalize_embed_key("a\0b.js"), None);
        assert_eq!(normalize_embed_key("C:/win.js"), None);
        assert_eq!(normalize_embed_key("a\nb.js"), None);
        // 绝对路径被“吸收为根内相对 key”，不会逃出静态根。
        assert_eq!(
            normalize_embed_key("/etc/passwd").as_deref(),
            Some("etc/passwd")
        );
    }

    /// **[历史归因]** 10MB 边界：严格 `>`（恰好 10MB 放行，与 Python `size > 10*1024*1024` 一致）。
    #[test]
    fn max_file_boundary() {
        assert_eq!(MAX_FILE, 10 * 1024 * 1024);
        assert!(!over_limit(0));
        assert!(!over_limit(MAX_FILE as u64));
        assert!(over_limit(MAX_FILE as u64 + 1));
        assert!(over_limit(u64::MAX));
    }

    /// MIME 表逐项对齐 `_STATIC_MIME`（另含 wasm/json：WASM 前端需要）。
    #[test]
    fn mime_table_matches_python() {
        assert_eq!(mime_of("index.html"), "text/html; charset=utf-8");
        assert_eq!(mime_of("app.js"), "application/javascript; charset=utf-8");
        assert_eq!(mime_of("style.css"), "text/css; charset=utf-8");
        assert_eq!(mime_of("favicon.svg"), "image/svg+xml");
        assert_eq!(mime_of("logo.png"), "image/png");
        assert_eq!(mime_of("favicon.ico"), "image/x-icon");
        assert_eq!(mime_of("app.wasm"), "application/wasm");
        assert_eq!(mime_of("data.json"), "application/json");
        assert_eq!(mime_of("ARCHIVE.TAR"), "application/octet-stream");
        assert_eq!(mime_of("noext"), "application/octet-stream");
        assert_eq!(mime_of("a/b/c.SVG"), "image/svg+xml");
    }

    /// 静态资源响应头逐项对齐 `_serve_static`：禁缓存 + 安全头 + 全量 CSP。
    #[test]
    fn static_headers_match_python() {
        let resp = build_response(StatusCode::OK, "text/html; charset=utf-8", b"hi".to_vec());
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            hdr_str(&resp, "Cache-Control"),
            "no-cache, no-store, must-revalidate"
        );
        assert_eq!(hdr_str(&resp, "Pragma"), "no-cache");
        assert_eq!(hdr_str(&resp, "Expires"), "0");
        assert_eq!(hdr_str(&resp, "X-Frame-Options"), "DENY");
        assert_eq!(hdr_str(&resp, "X-Content-Type-Options"), "nosniff");
        assert_eq!(hdr_str(&resp, "Referrer-Policy"), "no-referrer");
        let csp = hdr_str(&resp, "Content-Security-Policy");
        assert_eq!(
            csp,
            "default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; \
             style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; \
             connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        );
        // 与 web/index.html 的 meta CSP 指令集一致（仅 frame-ancestors 只能在响应头投递）。
        assert!(csp.contains("object-src 'none'"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(csp.contains("wasm-unsafe-eval"));
    }

    /// 回归：`/`（根路径）必须走 SPA 回退返回首页，而不是 403 forbidden。
    ///
    /// 历史缺陷：`normalize_embed_key` 把「归一后为空」判成 `None` → 首页
    /// 直接 `{"error":"forbidden"}`（控制台打不开）。空 key 属合法的根路径语义。
    #[test]
    fn root_path_normalizes_to_empty_not_rejected() {
        assert_eq!(normalize_embed_key("").as_deref(), Some(""));
        assert_eq!(normalize_embed_key("/").as_deref(), Some(""));
        assert_eq!(normalize_embed_key("//").as_deref(), Some(""));
        assert_eq!(normalize_embed_key("/./").as_deref(), Some(""));
        assert_eq!(
            normalize_embed_key("assets\\x.js").as_deref(),
            Some("assets/x.js")
        );
        // 仍需 fail-closed 的形态。
        assert!(normalize_embed_key("..").is_none());
        assert!(normalize_embed_key("/a/../../b").is_none());
        assert!(normalize_embed_key("C:/windows").is_none());
        assert!(normalize_embed_key("a\0b").is_none());
    }

    #[cfg(feature = "embed-frontend")]
    #[tokio::test]
    async fn root_path_serves_index_html() {
        let resp = serve(&Uri::from_static("/"), &None).await;
        assert_eq!(resp.status(), StatusCode::OK, "根路径必须 200（SPA 首页）");
        assert_eq!(hdr_str(&resp, "Content-Type"), "text/html; charset=utf-8");
    }

    /// 错误分支也带安全头（JSON 错误体）。
    #[test]
    fn error_response_has_security_headers() {
        let resp = err(StatusCode::NOT_FOUND, "not found");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(hdr_str(&resp, "Content-Type"), "application/json");
        assert_eq!(hdr_str(&resp, "X-Frame-Options"), "DENY");
    }

    /// 磁盘路径：正常文件可读、超限 413、目录/缺失返回 None（SPA 由调用方兜底）。
    ///
    /// 与 [`serve_disk_file`] 同样的门禁：该函数在 `embed-frontend` 构建下不编译，
    /// 因此本用例也随之 `cfg`（否则 `cargo test --features embed-frontend` 编译失败）。
    #[cfg(not(feature = "embed-frontend"))]
    #[tokio::test]
    async fn disk_file_read_size_and_regular_file_check() {
        let dir = std::env::temp_dir().join(format!("ebpdns-static-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let small = dir.join("small.js");
        std::fs::write(&small, b"console.log(1)").expect("write small");

        let resp = serve_disk_file(&small).expect("small file served");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            hdr_str(&resp, "Content-Type"),
            "application/javascript; charset=utf-8"
        );
        let body = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
        assert_eq!(body.as_ref(), b"console.log(1)");

        // 目录不是常规文件 → None。
        assert!(serve_disk_file(&dir).is_none());
        // 不存在 → None。
        assert!(serve_disk_file(&dir.join("nope.js")).is_none());

        // 超限文件（稀疏文件，不实际占盘）→ 413，且不整体读入。
        let big = dir.join("big.js");
        let f = File::create(&big).expect("create big");
        f.set_len(MAX_FILE as u64 + 1).expect("set_len");
        drop(f);
        let resp = serve_disk_file(&big).expect("413 response");
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        // **[历史归因]** 恰好 10MB（稀疏）→ 放行（边界对齐 Python `>`）。
        let exact = dir.join("exact.js");
        let f = File::create(&exact).expect("create exact");
        f.set_len(MAX_FILE as u64).expect("set_len");
        drop(f);
        let resp = serve_disk_file(&exact).expect("exact-size file served");
        assert_eq!(resp.status(), StatusCode::OK);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 磁盘路径 SPA：`/` 回退 index.html，带扩展名的缺失资源 404。
    #[tokio::test]
    async fn disk_root_serves_index_and_missing_asset_404() {
        let dir = std::env::temp_dir().join(format!("ebpdns-static-spa-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("index.html"), b"<html></html>").expect("write index");
        let root = Some(dir.clone());

        let resp = serve(&Uri::from_static("/"), &root).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(hdr_str(&resp, "Content-Type"), "text/html; charset=utf-8");

        // SPA：无扩展名未知路径 → index.html。
        let resp = serve(&Uri::from_static("/dashboard"), &root).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // 带扩展名的缺失资源 → 404。
        let resp = serve(&Uri::from_static("/missing.js"), &root).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // 无 web_root → 404（仅嵌入资源模式）。
        let resp = serve(&Uri::from_static("/index.html"), &None).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
