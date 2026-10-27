//! 安全中间件：忠实对齐 api.py 的 token 三入口常量时间比较 + 写操作 CSRF +
//! 读端点 Origin/Referer/Host 同源与 DNS-rebinding 防护 + loopback 判定。
//!
//! 失败方向 **fail-closed**：校验异常一律 403；token 未配置时读放行、写按
//! 无 Origin/Referer 时仅在 loopback 绑定下放行（curl/脚本直连）。

use axum::http::header::{HeaderMap, AUTHORIZATION};

use crate::state::AppState;

const LOOPBACK_TLDS: &[&str] = &[
    ".local",
    ".lan",
    ".home",
    ".internal",
    ".intranet",
    ".localdomain",
];

/// 从请求提取 presented token：Authorization: Bearer → X-Api-Key → ?token=。
/// 对齐 `_presented_api_token`。
pub fn presented_token(headers: &HeaderMap, query: &str) -> String {
    // 1) Authorization: Bearer <tok>
    if let Some(auth) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(rest) = auth
            .strip_prefix("Bearer ")
            .or_else(|| auth.strip_prefix("bearer "))
        {
            let t = rest.trim().to_string();
            if !t.is_empty() {
                return t;
            }
        }
    }
    // 2) X-Api-Key
    if let Some(k) = headers.get("X-Api-Key").and_then(|v| v.to_str().ok()) {
        let t = k.trim().to_string();
        if !t.is_empty() {
            return t;
        }
    }
    // 3) ?token=（query 为原始查询串；URL 解码 %xx）
    for pair in query.split('&') {
        if let Some(v) = pair.strip_prefix("token=") {
            let decoded = percent_decode(v);
            let t = decoded.trim().to_string();
            if !t.is_empty() {
                return t;
            }
        }
    }
    String::new()
}

/// URL 查询串的 percent-decode + `+` → 空格。
///
/// **[历史归因]** F29：Python 侧取 token 走 `urllib.parse.parse_qs`，其按
/// `application/x-www-form-urlencoded` 规则把 `+` 解码为空格；此前本实现只解 `%HH`，
/// 于是 `?token=a+b` 被当成字面 `a+b` 比较而 401。这里对齐 parse_qs：
/// `+` → `' '`，`%HH` → 字节，非法 `%` 原样保留。
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// 常量时间 UTF-8 字节比较（对齐 hmac.compare_digest）。
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// 配置的期望 token（strip）。空串 = 未启用。
pub fn expected_token(state: &AppState) -> String {
    let cfg = state.cfg.read();
    cfg.get("api")
        .and_then(|a| a.get("token"))
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .trim()
        .to_string()
}

/// `_check_api_token`：配置了 token 时校验；未配置即放行。
pub fn token_ok(state: &AppState, presented: &str) -> bool {
    let expected = expected_token(state);
    if expected.is_empty() {
        return true;
    }
    if presented.is_empty() {
        return false;
    }
    constant_time_eq(presented.as_bytes(), expected.as_bytes())
}

/// `_token_authenticated`：是否凭有效 token 通过认证（未配置 token 恒 false）。
pub fn token_authenticated(state: &AppState, presented: &str) -> bool {
    let expected = expected_token(state);
    if expected.is_empty() {
        return false;
    }
    !presented.is_empty() && constant_time_eq(presented.as_bytes(), expected.as_bytes())
}

/// 主机名归一：去首尾空白、去尾随 `.`（FQDN 根点）、小写。
///
/// **[历史归因]** F12：Python `_csrf_ok` / `_origin_ok` 都对 `urlsplit(...).hostname` 与
/// `urlparse(...).hostname` 做 `.lower()` 后才比较，而 `urlsplit().hostname`
/// 自身已剥离尾随点。此前本实现只对小写化的 `parse_origin_url` 结果比较、
/// `parse_host_header` 出来的仍是原始大小写，于是 `Host: EXAMPLE.com:8353` +
/// `Origin: http://example.com:8353` 被判为跨源 → 读端点全部 403。
fn normalize_host(h: &str) -> String {
    h.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// 拆分 `[2001:db8::1]` 形式的方括号。`None` = 方括号不闭合/不匹配（畸形，按不可信处理）。
fn unbracket(h: &str) -> Option<&str> {
    let inner = h.strip_prefix('[')?;
    inner.strip_suffix(']')
}

/// host 是否环回（覆盖 127/8 与 ::1 各种形式）。对齐 `_is_loopback`。
///
/// **[历史归因]** 仅接受 `[v6]` 这种**闭合**方括号形式：`[::1`（未闭合）在 Python
/// `ipaddress.ip_address()` 下抛 ValueError 即判 False，而旧实现
/// `strip_prefix('[')` 后仍能解出 `::1` → 误判为环回并放行（读端点 / 写端点纵深检查）。
pub fn is_loopback_host(host: &str) -> bool {
    let h = normalize_host(host);
    if h == "localhost" {
        return true;
    }
    let norm = if h.starts_with('[') {
        match unbracket(&h) {
            Some(inner) => inner,
            None => return false,
        }
    } else {
        h.as_str()
    };
    norm.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// 是否私网/环回/链路本地（可信本地 IP）。
fn is_trusted_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v) => v.is_loopback() || v.is_private() || v.is_link_local(),
        std::net::IpAddr::V6(v) => {
            v.is_loopback() || v.is_unique_local() || v.is_unicast_link_local()
        }
    }
}

/// 是否未指定地址（0.0.0.0 / ::）。对齐 is_unspecified。
fn is_unspecified(host: &str) -> bool {
    let norm = host.trim();
    norm.parse::<std::net::Ipv4Addr>()
        .map(|v| v.is_unspecified())
        .unwrap_or(false)
        || norm
            .parse::<std::net::Ipv6Addr>()
            .map(|v| v.is_unspecified())
            .unwrap_or(false)
}

/// `_bound_to_loopback`：API 实际绑定是否仅环回。
pub fn bound_to_loopback(state: &AppState) -> bool {
    let host = state.api_host.read().clone();
    is_loopback_host(&host)
}

/// 解析 "Host" 头 → (host_part, port)。对齐 urlsplit("//"+host)。
///
/// host_part 一律小写并去尾随点（F12；urlsplit().hostname 语义 + `.lower()`），
/// **[历史归因]** 使后续 `oh != req_host_part` 的字符串比较与 Python 同口径（大小写无关）。
/// IPv6 必须闭合方括号（`[::1]:8080`）；未闭合的畸形值返回空 host（不可信）。
fn parse_host_header(host: &str) -> (String, Option<u16>) {
    let h = host.trim();
    if h.is_empty() {
        return (String::new(), None);
    }
    // [::1]:8080
    if h.starts_with('[') {
        if let Some(end) = h.find(']') {
            let host = normalize_host(&h[1..end]);
            let port = h[end + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok());
            return (host, port);
        }
        // 方括号不闭合：畸形，按空 host（fail-closed）处理。
        return (String::new(), None);
    }
    // host:port（IPv4 或 hostname）
    if let Some(colon) = h.rfind(':') {
        let (host, port) = h.split_at(colon);
        if let Ok(p) = port[1..].parse::<u16>() {
            return (normalize_host(host), Some(p));
        }
    }
    (normalize_host(h), None)
}

/// 从 Origin/Referer URL 取 (host, port, scheme)。
fn parse_origin_url(url: &str) -> (String, Option<u16>, String) {
    let rest = match url.split_once("://") {
        Some((s, r)) => (s.to_ascii_lowercase(), r),
        None => return (String::new(), None, String::new()),
    };
    let (scheme, path) = rest;
    // 去掉路径
    let authority = path.split('/').next().unwrap_or(path);
    let (host, port) = parse_host_header(authority);
    (host.to_ascii_lowercase(), port, scheme)
}

/// 端口语义归一：None（默认端口）按 scheme → 80/443。
fn eff_port(port: Option<u16>, scheme: &str) -> u16 {
    port.unwrap_or(if scheme == "https" { 443 } else { 80 })
}

/// LAN/读端点的可信 host：环回 / 私网 / 链路本地 IP，或可信本地名（.local/.lan/.../无点短名）。
///
/// **[历史归因]** 对齐 Python `_origin_ok._trusted_host` / `_csrf_ok._is_private_or_loopback_ip` 的
/// **快速路径**：命中私有后缀（.local/.lan/.home/.internal/.intranet/.localdomain）
/// 或无点短名的主机名**不做 DNS 解析即信任**。
///
/// **[历史归因]** # 已接受的 LAN 信任边界（F29，与 Python R17 P3-3 记录一致）
/// 在 `api.host=0.0.0.0/::`（LAN 模式）下，攻击者若控制一个 `*.lan` 名字并经 DNS
/// rebinding 指向本服务（Origin 与 Host 头同为 `evil.lan:8080`），读端点会放行；
/// **环回绑定（默认部署）不受影响**（该分支要求 Origin host 环回或严格等于配置 host）。
/// **[历史归因]** 对齐 Python 时本实现**故意不**对 FQDN 追加 `getaddrinfo`：一是本函数是同步函数、
/// 在 tokio worker 上直接解析会阻塞 runtime（改为 spawn_blocking 需要异步化
/// `origin_ok`/`csrf_ok` 签名，牵连 api.rs —— 本任务不允许改）；二是 split-horizon /
/// 企业内网 DNS 常把 LAN 名解析到公网段地址，按"全部为私网"判定会 403 掉本可用的
/// 控制台写操作。若要加固，需另行引入带缓存+超时的异步解析，属独立任务。
fn trusted_host(h: &str, configured_host: &str) -> bool {
    let h = normalize_host(h);
    if h.is_empty() {
        return false;
    }
    if h == configured_host {
        return true;
    }
    if h == "localhost" {
        return true;
    }
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        return is_trusted_ip(&ip);
    }
    hl_is_trusted_local_name(&h)
}

/// **[历史归因]** 私有后缀 / 无点短名（对齐 Python `h.endswith(_LOCAL_TLDS) or "." not in h`）。
fn hl_is_trusted_local_name(h: &str) -> bool {
    if LOOPBACK_TLDS.iter().any(|t| h.ends_with(t)) {
        return true;
    }
    !h.is_empty() && !h.contains('.')
}

/// `_origin_ok`：读端点同源/rebinding 防护。
///
/// - 请求 Host 头必须可信；
/// - 无 Origin/Referer → 放行（脚本/探针直连）；
/// - 有 Origin/Referer：host 必须可信且与 Host 头自洽（同主机+端口）。
///
/// F12：两侧 host 现在都经 `parse_host_header`（内含 `normalize_host`）归一为
/// **[历史归因]** **小写 + 去尾随点**后再比较，与 Python `_u_host`/`req_host_part` 的 `.lower()` 一致。
///
/// **2.1.15（P2-3）**：环回绑定下 Origin host ↔ Host 头改为**环回别名等价**
/// （`localhost` / `127.0.0.0/8` / `[::1]` 互通），与写路径 [`csrf_ok`] 对称；
/// 非环回绑定（LAN / 显式主机名）仍是字面相等。三例矩阵见单测
/// [`origin_ok_loopback_aliases_are_symmetric`]。
pub fn origin_ok(state: &AppState, headers: &HeaderMap) -> bool {
    let configured_host = normalize_host(&state.api_host.read());
    let configured_port = state.api_port;

    let req_host = headers
        .get("Host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let (req_host_part, req_host_port) = parse_host_header(req_host);
    let lan_mode = configured_host.is_empty() || is_unspecified(&configured_host);

    // **2.1.20（A-10 修复：畸形 `Host` 头被读路径放行）**：Host 头**存在但解析不出主机名**
    // （典型：未闭合方括号 `Host: [::1`）时，下面的"自洽"检查会被整体跳过
    // （`if !req_host_part.is_empty()`），于是只要 Origin 主机可信就放行 ——
    // 审计实测 `Host: [::1` + `Origin: http://[::1]:18453` → **200**，
    // 而写路径 `csrf_ok` 对同一组合是 **403**（读写不对称，属 fail-open）。
    //
    // 修法：**只要 Host 头非空却解析不出主机名，立即拒绝**（fail-closed）。
    // 注意与"完全没有 Host 头"区分：HTTP/1.0 客户端可以不带 Host，那种情况维持既有行为。
    if !req_host.is_empty() && req_host_part.is_empty() {
        tracing::warn!(
            host = req_host,
            "Origin/Referer 校验：Host 头无法解析出主机名（畸形）⇒ 拒绝（fail-closed）"
        );
        return false;
    }

    // Host 头本身必须可信（防投毒/rebinding 指向外部名）。
    if !req_host_part.is_empty() && !trusted_host(&req_host_part, &configured_host) && !lan_mode {
        return false;
    }

    let src = headers
        .get("Origin")
        .and_then(|v| v.to_str().ok())
        .or_else(|| headers.get("Referer").and_then(|v| v.to_str().ok()));
    let Some(src) = src else {
        return true; // 非浏览器直连放行
    };
    let (oh, oport, oscheme) = parse_origin_url(src);
    if oh.is_empty() {
        return false;
    }
    if !trusted_host(&oh, &configured_host) {
        return false;
    }
    // Origin host 必须与请求 Host 头自洽（同主机）。
    //
    // **2.1.15（P2-3）环回别名互通**：环回绑定下（`api.host` 为环回，默认部署）
    // 「自洽」= **双向环回**，不再是字面相等 —— 此前 `Origin: http://localhost:8353`
    // + `Host: 127.0.0.1:8353` 被判跨源 → 读端点 403，而写路径 [`csrf_ok`] 用
    // `is_loopback_host()` 放行 ⇒ 同一份别名在读写两条路径上行为**不对称**，
    // 也与 README「环回互通」矛盾。rebinding 防护不放松：`trusted_host(&oh)`
    // 已保证 Origin 主机可信，下面另加与 `csrf_ok` **同一条**纵深：环回绑定时
    // Host 头自身必须环回。
    let loopback_bind = is_loopback_host(&configured_host);
    if !req_host_part.is_empty() {
        let same_host = if loopback_bind {
            is_loopback_host(&req_host_part)
        } else {
            oh == req_host_part
        };
        if !same_host {
            return false;
        }
    }
    if loopback_bind && !req_host_part.is_empty() && !is_loopback_host(&req_host_part) {
        return false;
    }
    // 端口一致（语义归一）。
    let op = eff_port(oport, &oscheme);
    match req_host_port {
        None => {
            // Host 头无端口 = 协议默认端口；仅当 Origin 也落在默认端口或等于配置端口。
            if op != 80 && op != 443 && op != configured_port {
                return false;
            }
        }
        Some(rp) => {
            if op != rp {
                return false;
            }
        }
    }
    true
}

/// `_csrf_ok`：写操作（POST/PUT/DELETE）CSRF 校验。
///
/// **[历史归因]** F12：Origin/Referer 与 Host 头的 host 均归一为小写（对齐 Python
/// `_origin_host` 的 `.lower()` 与 `req_host_part` 的 `.lower()`）。
pub fn csrf_ok(state: &AppState, headers: &HeaderMap, _query: &str, presented: &str) -> bool {
    let configured_host = normalize_host(&state.api_host.read());
    let configured_port = state.api_port;

    let req_host = headers
        .get("Host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let (req_host_part, req_host_port) = parse_host_header(req_host);
    let lan_mode = configured_host.is_empty() || is_unspecified(&configured_host);

    let check_origin = |src: &str| -> Option<bool> {
        let (oh, oport, oscheme) = parse_origin_url(src);
        if oh.is_empty() {
            return Some(false);
        }
        if lan_mode {
            // 自洽 + 纵深：Origin host == Host 头 host，且 host 私网/环回；端口一致。
            if req_host_part.is_empty() || oh != req_host_part {
                return Some(false);
            }
            let op = eff_port(oport, &oscheme);
            let same = match req_host_port {
                None => op == 80 || op == 443,
                Some(rp) => op == rp,
            };
            if !same {
                return Some(false);
            }
            return Some(trusted_host(&oh, &configured_host));
        }
        // 环回绑定：Origin host 环回即可（localhost/127/8/::1 互通）；
        // 显式非环回配置：严格等于 configured_host。
        if is_loopback_host(&configured_host) {
            if !is_loopback_host(&oh) {
                return Some(false);
            }
        } else if oh != configured_host {
            return Some(false);
        }
        let op = eff_port(oport, &oscheme);
        if op != configured_port {
            return Some(false);
        }
        // 纵深：环回绑定时要求 Host 头也环回。
        if is_loopback_host(&configured_host) && !is_loopback_host(&req_host_part) {
            return Some(false);
        }
        Some(true)
    };

    if let Some(origin) = headers.get("Origin").and_then(|v| v.to_str().ok()) {
        return check_origin(origin).unwrap_or(false);
    }
    if let Some(referer) = headers.get("Referer").and_then(|v| v.to_str().ok()) {
        return check_origin(referer).unwrap_or(false);
    }
    // 无 Origin/Referer：已凭有效 token 或绑定环回即放行。
    if token_authenticated(state, presented) {
        return true;
    }
    bound_to_loopback(state)
}

/// **2.1.43-A（P2：`rebind_blocked` 没有写点）**：控制面写请求的 **Host 头** 是否
/// 指向不可信名字（= DNS-rebinding 形态）。
///
/// 为什么单独抽出来：`csrf_ok` 把「token 缺失/不符」与「Host 不可信」混在同一个
/// `false` 里，调用方无法归因，于是 `counters.rebind_blocked`（控制面 rebinding
/// 拦截）**从来没有自增点**、恒 0 —— 与 `web/INTERFACE.md` 的声明不符。
///
/// 判据与 `csrf_ok` / `origin_ok` 里的 host 维度**同源**（同一 `trusted_host`、
/// 同一 `normalize_host`、同一 `lan_mode` 归一），只回答"Host 这一个维度"：
/// * 无 Host 头（HTTP/1.0 直连）⇒ false（维持既有放行）；
/// * Host 存在但解析不出主机名（如未闭合方括号）⇒ **true**（fail-closed，
///   与 `origin_ok` 对该形态的拒绝同口径）；
/// * `api.host` 为通配/空（`lan_mode`）⇒ false（绑定 LAN 时不按名字判 rebinding）；
/// * 其余 ⇒ `!trusted_host(host, configured_host)`。
pub fn host_untrusted(state: &AppState, headers: &HeaderMap) -> bool {
    let configured_host = normalize_host(&state.api_host.read());
    let req_host = headers
        .get("Host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if req_host.is_empty() {
        return false;
    }
    let (req_host_part, _) = parse_host_header(req_host);
    if req_host_part.is_empty() {
        return true;
    }
    let lan_mode = configured_host.is_empty() || is_unspecified(&configured_host);
    if lan_mode {
        return false;
    }
    !trusted_host(&req_host_part, &configured_host)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::state::{AppState, RestartSignal};
    use ebpdns_resolver::clock::RealClock;
    use ebpdns_resolver::config::ResolverConfig;
    use ebpdns_resolver::query::ScriptedQuerier;
    use ebpdns_resolver::Resolver;
    use parking_lot::RwLock;
    use serde_json::json;
    use std::sync::Arc;

    /// 最小 AppState（不联网）：api.host=127.0.0.1 / api.port=8353 / 无 token。
    fn test_state(api_host: &str, api_port: u16) -> AppState {
        let tel = Arc::new(crate::telemetry::ServerTelemetry::new());
        let q = ScriptedQuerier::new(|_n, _t, _d| Vec::new());
        let resolver = Resolver::new(
            ResolverConfig::default(),
            tel.clone(),
            Arc::new(RealClock::default()),
            Arc::new(q),
        );
        AppState {
            resolver,
            cfg: Arc::new(RwLock::new(
                json!({"api": {"host": api_host, "port": api_port, "token": ""}}),
            )),
            cfg_path: None,
            telemetry: tel,
            api_host: Arc::new(RwLock::new(api_host.to_string())),
            api_port,
            web_root: None,
            restart: Arc::new(RestartSignal::default()),
            endpoints: Arc::new(RwLock::new(Vec::new())),
            on_reload: None,
            restart_notify: Arc::new(tokio::sync::Notify::new()),
            udp_dropped: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            applied: Arc::new(RwLock::new(json!({}))),
            // 2.1.22：本夹具不涉及持久化 ⇒ 旧行为（无统一事务）。
            state: Default::default(),
        }
    }

    fn hm(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).expect("valid header name"),
                axum::http::HeaderValue::from_str(v).expect("valid header value"),
            );
        }
        m
    }

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn loopback_hosts() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("127.0.0.2"));
        assert!(is_loopback_host("[::1]"));
        assert!(is_loopback_host("LOCALHOST"));
        assert!(!is_loopback_host("8.8.8.8"));
        assert!(!is_loopback_host("example.com"));
    }

    /// F29：未闭合方括号 `[::1` 曾被 strip 成 `::1` 误判为环回 → 现在按畸形拒绝。
    #[test]
    fn unclosed_bracket_ipv6_is_not_loopback() {
        assert!(!is_loopback_host("[::1"));
        assert!(is_loopback_host("[::1]"));
        assert!(!is_loopback_host("[127.0.0.1"));
        assert!(!is_loopback_host("[[::1]]"));
        // Host 头解析同样 fail-closed（空 host）。
        let (h, p) = parse_host_header("[::1");
        assert_eq!(h, "");
        assert_eq!(p, None);
        assert_eq!(
            parse_host_header("[::1]:8353"),
            ("::1".to_string(), Some(8353))
        );
    }

    #[test]
    fn unspecified_addrs() {
        assert!(is_unspecified("0.0.0.0"));
        assert!(is_unspecified("::"));
        assert!(!is_unspecified("127.0.0.1"));
    }

    #[test]
    fn origin_parsing() {
        let (h, p, s) = parse_origin_url("https://localhost:8353/foo");
        assert_eq!(h, "localhost");
        assert_eq!(p, Some(8353));
        assert_eq!(s, "https");
    }

    /// F12：Host 头 host 部分小写化（对齐 urlsplit().hostname + .lower()）。
    #[test]
    fn host_header_is_lowercased() {
        assert_eq!(
            parse_host_header("EXAMPLE.com:8353"),
            ("example.com".to_string(), Some(8353))
        );
        assert_eq!(
            parse_host_header("[2001:DB8::1]:8353"),
            ("2001:db8::1".to_string(), Some(8353))
        );
        assert_eq!(
            parse_host_header("Example.COM."),
            ("example.com".to_string(), None)
        );
    }

    /// F12 端到端：`Host: EXAMPLE.com:8353` + `Origin: http://example.com:8353` 必须放行
    /// （此前读端点 403）。
    #[test]
    fn origin_ok_host_case_insensitive() {
        let st = test_state("example.com", 8353);
        let h = hm(&[
            ("Host", "EXAMPLE.com:8353"),
            ("Origin", "http://example.com:8353"),
        ]);
        assert!(origin_ok(&st, &h));
        // 反向：小写 Host + 大写 Origin。
        let h2 = hm(&[
            ("Host", "example.com:8353"),
            ("Origin", "http://EXAMPLE.COM:8353"),
        ]);
        assert!(origin_ok(&st, &h2));
        // 跨源仍拒绝（fail-closed）。
        let h3 = hm(&[
            ("Host", "EXAMPLE.com:8353"),
            ("Origin", "http://evil.example.net:8353"),
        ]);
        assert!(!origin_ok(&st, &h3));
    }

    /// LAN 模式（api.host=0.0.0.0）下大小写不敏感同样成立。
    #[test]
    fn origin_ok_lan_mode_host_case_insensitive() {
        let st = test_state("0.0.0.0", 8353);
        let h = hm(&[
            ("Host", "EBPDNS.lan:8353"),
            ("Origin", "http://ebpdns.LAN:8353"),
        ]);
        assert!(origin_ok(&st, &h));
    }

    /// 端口归一：缺省端口（Host 无端口 / Origin 按 scheme 归一 80/443）。
    #[test]
    fn origin_ok_port_normalization() {
        let st = test_state("example.com", 8353);
        // **[历史归因]** Host 无端口 + Origin 显式 :80 → 同源（Python `op in (80, 443)`）。
        let h = hm(&[("Host", "example.com"), ("Origin", "http://example.com:80")]);
        assert!(origin_ok(&st, &h));
        // Host 无端口 + Origin 无端口（http → 80）。
        let h2 = hm(&[("Host", "example.com"), ("Origin", "http://example.com")]);
        assert!(origin_ok(&st, &h2));
        // Host 无端口 + Origin 无端口（https → 443）。
        let h3 = hm(&[("Host", "example.com"), ("Origin", "https://example.com")]);
        assert!(origin_ok(&st, &h3));
        // Host 显式 :8353 + Origin 缺省端口 → 跨源，拒绝。
        let h4 = hm(&[
            ("Host", "example.com:8353"),
            ("Origin", "http://example.com"),
        ]);
        assert!(!origin_ok(&st, &h4));
        // Host 显式 :8353 + Origin :8353 → 同源。
        let h5 = hm(&[
            ("Host", "EXAMPLE.com:8353"),
            ("Origin", "http://example.com:8353"),
        ]);
        assert!(origin_ok(&st, &h5));
        // 不同显式端口 → 拒绝。
        let h6 = hm(&[
            ("Host", "example.com:8353"),
            ("Origin", "http://example.com:8080"),
        ]);
        assert!(!origin_ok(&st, &h6));
        // Host 无端口 + Origin 非默认且非配置端口 → 拒绝。
        let h7 = hm(&[
            ("Host", "example.com"),
            ("Origin", "http://example.com:9999"),
        ]);
        assert!(!origin_ok(&st, &h7));
        // eff_port 直接单测。
        assert_eq!(eff_port(None, "http"), 80);
        assert_eq!(eff_port(None, "https"), 443);
        assert_eq!(eff_port(Some(8353), "http"), 8353);
    }

    /// 写端点（CSRF）在 LAN 模式下大小写不敏感的 Origin == Host 自洽。
    #[test]
    fn csrf_ok_lan_mode_host_case_insensitive() {
        let st = test_state("0.0.0.0", 8353);
        let h = hm(&[
            ("Host", "EBPDNS.lan:8353"),
            ("Origin", "http://ebpdns.LAN:8353"),
        ]);
        assert!(csrf_ok(&st, &h, "", ""));
        // 自洽但公网 FQDN → 拒绝（LAN 信任模型）。
        let h2 = hm(&[
            ("Host", "evil.example.com:8353"),
            ("Origin", "http://evil.example.com:8353"),
        ]);
        assert!(!csrf_ok(&st, &h2, "", ""));
        // IP 私网 → 放行。
        let h3 = hm(&[
            ("Host", "192.168.1.9:8353"),
            ("Origin", "http://192.168.1.9:8353"),
        ]);
        assert!(csrf_ok(&st, &h3, "", ""));
    }

    /// 环回绑定（默认）：Origin 必须环回，且 Host 头也必须环回（纵深）。
    #[test]
    fn csrf_ok_loopback_binding() {
        let st = test_state("127.0.0.1", 8353);
        let ok = hm(&[
            ("Host", "127.0.0.1:8353"),
            ("Origin", "http://localhost:8353"),
        ]);
        assert!(csrf_ok(&st, &ok, "", ""));
        let bad_host = hm(&[
            ("Host", "evil.com:8353"),
            ("Origin", "http://127.0.0.1:8353"),
        ]);
        assert!(!csrf_ok(&st, &bad_host, "", ""));
        // 无 Origin/Referer + 未配置 token + 环回绑定 → 放行（curl 直连）。
        assert!(csrf_ok(&st, &HeaderMap::new(), "", ""));
    }

    /// **2.1.15（P2-3）**：环回别名在**读路径**（`origin_ok`）与**写路径**（`csrf_ok`）
    /// 上行为一致 —— `localhost` / `127.0.0.1` / `[::1]` 三种 Origin 任意组合都放行。
    ///
    /// 修复前 `origin_ok` 对 Origin host 与 Host 头做**字面相等**比较：
    /// `Origin: http://localhost:8353` + `Host: 127.0.0.1:8353` → 403（读写不对称）。
    #[test]
    fn origin_ok_loopback_aliases_are_symmetric() {
        let st = test_state("127.0.0.1", 8353); // 默认部署：环回绑定
                                                // 三种 Host 头 × 三种 Origin，读/写两条路径都必须放行。
        for host in ["127.0.0.1:8353", "localhost:8353", "[::1]:8353"] {
            for origin in [
                "http://127.0.0.1:8353",
                "http://localhost:8353",
                "http://[::1]:8353",
            ] {
                let h = hm(&[("Host", host), ("Origin", origin)]);
                assert!(
                    origin_ok(&st, &h),
                    "读路径应放行 Host={host} Origin={origin}"
                );
                assert!(
                    csrf_ok(&st, &h, "", ""),
                    "写路径应放行 Host={host} Origin={origin}"
                );
            }
        }
        // 127/8 的其它地址同属环回 → 互通。
        let h = hm(&[
            ("Host", "127.0.0.1:8353"),
            ("Origin", "http://127.0.0.53:8353"),
        ]);
        assert!(origin_ok(&st, &h));
        assert!(csrf_ok(&st, &h, "", ""));
        // rebinding 防护不放松：Host 头指向外部名 → 读写都拒。
        let bad = hm(&[
            ("Host", "evil.example.com:8353"),
            ("Origin", "http://127.0.0.1:8353"),
        ]);
        assert!(!origin_ok(&st, &bad), "Host 头非环回必须拒绝（纵深）");
        assert!(!csrf_ok(&st, &bad, "", ""));
        // 端口不一致 → 读写都拒。
        let badport = hm(&[
            ("Host", "127.0.0.1:8353"),
            ("Origin", "http://localhost:9999"),
        ]);
        assert!(!origin_ok(&st, &badport));
        assert!(!csrf_ok(&st, &badport, "", ""));
        // 非环回绑定（显式主机名）：仍是字面相等，别名不互通。
        let st2 = test_state("api.node9", 8353);
        let alias = hm(&[
            ("Host", "api.node9:8353"),
            ("Origin", "http://127.0.0.1:8353"),
        ]);
        assert!(!origin_ok(&st2, &alias));
        assert!(!csrf_ok(&st2, &alias, "", ""));
    }

    /// **2.1.20（A-10）**：Host 头**存在但解析不出主机名**（未闭合方括号 `[::1`）时，
    /// 读路径必须与写路径一样 **拒绝**（此前读 200 / 写 403，属 fail-open 不对称）。
    #[test]
    fn malformed_host_header_is_rejected_on_read_path() {
        let st = test_state("127.0.0.1", 8353);
        // 决定性的实测组合（审计 A-10）：`Host: [::1` + 环回 Origin。
        let bad = hm(&[("Host", "[::1"), ("Origin", "http://[::1]:8353")]);
        assert!(
            !origin_ok(&st, &bad),
            "畸形 Host（未闭合方括号）必须拒绝 —— 此前读路径放行 200（A-10）"
        );
        assert!(!csrf_ok(&st, &bad, "", ""), "写路径同样拒绝（本来就拒）");
        // 其它畸形形状：空方括号、只有端口冒号、只有方括号。
        for h in ["[", "[]", "[:8353]", ":8353"] {
            let hh = hm(&[("Host", h), ("Origin", "http://127.0.0.1:8353")]);
            assert!(!origin_ok(&st, &hh), "畸形 Host `{h}` 必须拒绝");
        }
        // **反向**：完全不带 Host 头（HTTP/1.0）维持既有行为，不得被这条误伤。
        let no_host = hm(&[("Origin", "http://127.0.0.1:8353")]);
        assert!(origin_ok(&st, &no_host), "没有 Host 头时不得误伤（非畸形）");
        // 正常 Host 头不受影响。
        let ok = hm(&[
            ("Host", "127.0.0.1:8353"),
            ("Origin", "http://127.0.0.1:8353"),
        ]);
        assert!(origin_ok(&st, &ok), "正常 Host 必须放行");
    }

    /// **[历史归因]** F29：`+` 按表单编码解码为空格（对齐 Python parse_qs），`%20` 同理。
    #[test]
    fn percent_decode_plus_and_escapes() {
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("a%2Bb"), "a+b");
        assert_eq!(percent_decode("a%2"), "a%2");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("tok%2Fen"), "tok/en");
    }

    #[test]
    fn presented_token_decodes_plus_and_percent() {
        let h = HeaderMap::new();
        assert_eq!(presented_token(&h, "token=a+b"), "a b");
        assert_eq!(presented_token(&h, "token=sec%2Fret"), "sec/ret");
        assert_eq!(presented_token(&h, "other=1&token=tok2"), "tok2");
        assert_eq!(presented_token(&h, "token="), "");
    }

    /// token 三入口常量时间比较 + 未配置即放行。
    #[test]
    fn token_entrypoints() {
        let h = hm(&[("Authorization", "Bearer secret")]);
        assert_eq!(presented_token(&h, ""), "secret");
        let h2 = hm(&[("X-Api-Key", " secret2 ")]);
        assert_eq!(presented_token(&h2, ""), "secret2");
        let st = test_state("127.0.0.1", 8353);
        assert!(token_ok(&st, "")); // 未配置 token → 放行
        assert!(!token_authenticated(&st, "")); // 未配置 token → 恒 false
    }
}
