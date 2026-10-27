//! **[历史归因]** 上游协议枚举与地址解析（对齐 Python `config.parse_upstream_addr` / `upstream._host_port` / `_is_hostname`）。

use std::net::IpAddr;

use crate::error::{UpstreamError, UpstreamResult};

/// **[历史归因]** 上游传输协议。忠实对齐 Python `up.get("proto")` 的六种取值。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    Udp,
    Tcp,
    /// DNS over HTTPS（HTTP/1.1 over rustls）。
    Doh,
    /// DNS over TLS（rustls over TCP）。
    Dot,
    /// DNS over HTTP/3（quinn + 手写最小 H3）。
    Doh3,
    /// DNS over QUIC（quinn bi-stream）。
    Doq,
}

impl Proto {
    /// **[历史归因]** 从小写协议字符串解析；未知返回 `None`。对齐 Python `str(up.get("proto","udp")).lower()`。
    pub fn from_lower(s: &str) -> Option<Proto> {
        match s {
            "udp" => Some(Proto::Udp),
            "tcp" => Some(Proto::Tcp),
            "doh" => Some(Proto::Doh),
            "dot" => Some(Proto::Dot),
            "doh3" => Some(Proto::Doh3),
            "doq" => Some(Proto::Doq),
            _ => None,
        }
    }

    /// 小写名。
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Udp => "udp",
            Proto::Tcp => "tcp",
            Proto::Doh => "doh",
            Proto::Dot => "dot",
            Proto::Doh3 => "doh3",
            Proto::Doq => "doq",
        }
    }

    /// **[历史归因]** 该协议是否为加密传输（连接池 / bootstrap 预热对象）。对齐 Python bootstrap_resolve_all。
    pub fn is_encrypted(self) -> bool {
        matches!(self, Proto::Doh | Proto::Dot | Proto::Doh3 | Proto::Doq)
    }

    /// 该协议是否需要独立的连接复用池（DoH / DoT）。
    pub fn is_pooled(self) -> bool {
        matches!(self, Proto::Doh | Proto::Dot)
    }

    /// 该协议是否走 QUIC（quinn）。
    pub fn is_quic(self) -> bool {
        matches!(self, Proto::Doh3 | Proto::Doq)
    }

    /// **[历史归因]** 默认端口：对齐 Python `UP_PORT_DEFAULT`。
    pub fn default_port(self) -> u16 {
        match self {
            Proto::Udp | Proto::Tcp => 53,
            Proto::Doh | Proto::Doh3 => 443,
            Proto::Dot | Proto::Doq => 853,
        }
    }
}

/// 把上游配置里的 `url` 字段规范化为 HTTP request-target / H3 `:path`。
///
/// **[历史归因]** 配置语义（对齐 Python `up["url"]`）是**路径**，例如 `/dns-query`。这里同时容忍
/// 三种历史形态，任何一种都不得让完整 URL 泄漏到请求行：
/// - 空串：加密协议（DoH/DoH3）默认 `/dns-query`；纯 udp/tcp 返回空串（不带路径）；
/// - 路径形态：`/dns-query`、`dns-query`；
/// - 完整 URL 形态：`https://dns.alidns.com:443/dns-query` → 取 authority 之后的路径。
///
/// 缺陷背景（真实服务器回归发现）：`ebpdns-resolver::production::upcfg_to_runtime`
/// 曾把该字段写成 `format!("https://{host}:{port}/dns-query")` 整串，而 DoH 的
/// `POST {path} HTTP/1.1` 与 DoH3 的 `:path` 都直接使用它 → 请求行变成
/// `POST /https://dns.alidns.com:443/dns-query HTTP/1.1`，真实服务器一律 404 /
/// H3 协议错误，导致**所有 DoH/DoH3 上游 100% 失败**（未修前实测 alidoh 0/16、
/// alidoh3 0/4；同主机 curl 直连同一服务器 200 OK）。
pub fn request_path(raw: &str, encrypted: bool) -> String {
    // 明文协议（udp/tcp/dot/doq）没有 HTTP 请求路径：一律空串。
    // 这个判断必须在下面任何"补前导斜杠/剥 scheme"逻辑之前——否则配置里存在
    // `url` 的明文上游会拿到一个并不存在的 request-target（回归：up("udp","/dns-query")）。
    if !encrypted {
        return String::new();
    }
    let raw = raw.trim();
    if raw.is_empty() {
        return "/dns-query".to_string();
    }
    // 完整 URL：剥掉 scheme + authority，只保留路径（含 query）。
    let after_scheme = raw
        .strip_prefix("https://")
        .or_else(|| raw.strip_prefix("http://"));
    if let Some(rest) = after_scheme {
        return match rest.find('/') {
            Some(i) => rest[i..].to_string(),
            None => "/dns-query".to_string(),
        };
    }
    if raw.starts_with('/') {
        raw.to_string()
    } else {
        format!("/{raw}")
    }
}

/// **[历史归因]** 上游主机字符集白名单，对齐 Python `_UPSTREAM_HOST_CHARS`。
const HOST_CHARS: &[char] = &[
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
    'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '.', '-', '_', ':', '[', ']',
];

fn host_char_ok(c: char) -> bool {
    HOST_CHARS.contains(&c)
}

/// 判断字符串是否为 hostname（非 IP 地址）。
///
/// **[历史归因]** 对齐 Python `_is_hostname`：能解析成 IPv4/IPv6（剥离 `%scope`）即非 hostname；
/// 否则要求非空且不以 `[` 开头。
pub fn is_hostname(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    // IPv4?
    if s.parse::<std::net::Ipv4Addr>().is_ok() {
        return false;
    }
    // IPv6（剥离 %scope）?
    let core = match s.split_once('%') {
        Some((v6, _)) => v6,
        None => s,
    };
    if core.parse::<std::net::Ipv6Addr>().is_ok() {
        return false;
    }
    !s.starts_with('[')
}

/// **[历史归因]** 判断字符串是否为 IPv6 地址（对齐 Python `_is_v6`，剥离 `%scope`）。
pub fn is_v6(s: &str) -> bool {
    let core = match s.split_once('%') {
        Some((v6, _)) => v6,
        None => s,
    };
    core.parse::<std::net::Ipv6Addr>().is_ok()
}

/// **[历史归因]** 解析上游 addr/port，对齐 Python `upstream._host_port`（upstream.py:594-603）。
///
/// **[历史归因]** 逐条对应 Python：
/// ```python
/// port = int(up.get("port") or 53)
/// if addr.startswith("["):
///     idx = addr.find("]")
///     return addr[1:idx], port      # 裸 [v6] 形态 + 配置端口
/// return addr, port
/// ```
/// **[历史归因]** - `[v6...]` 前缀 → 取方括号内内容作 host（`"].find" == -1` 时 Python 的
///   `addr[1:-1]` 会截掉首尾字符，属畸形输入的既有行为；Rust 侧对未闭合括号
///   保守返回原文，避免产出被悄悄截断的主机名）；
/// - `port_override` 为 None → 协议默认端口（`or 53` 的等价物；本函数用协议
///   默认端口而非硬编码 53，与 `Proto::default_port` 口径一致）。
///
/// **[历史归因]** **已知有意分叉**：Python 此函数**不**解析 addr 内嵌的 `host:port`
/// （`up.get("port")` 才带端口）；Rust 额外支持内嵌 `host:port`，使
/// `host_port("1.1.1.1:5353", None, Udp)` 得到 5353。二者在
/// `parse_upstream_addr` 的调用链上等价（配置层已把内嵌端口切出并写入 `port`），
/// 但直接调用本函数时行为不同，故在此显式记录。
pub fn host_port(addr: &str, port_override: Option<u16>, proto: Proto) -> (String, u16) {
    let port = port_override.unwrap_or_else(|| proto.default_port());
    let trimmed = addr.trim();
    if let Some(inner) = trimmed.strip_prefix('[') {
        if let Some(close) = inner.find(']') {
            // **[历史归因]** Python 只取括号内内容并原样返回配置端口（即便其后还有 `:port`）。
            return (inner[..close].to_string(), port);
        }
    }
    // 内嵌 `host:port`：裸 IPv6（冒号 > 1）不切，避免把 `::1` 切成 host `::` + port 1。
    if trimmed.matches(':').count() == 1 {
        if let Some((h, p)) = trimmed.rsplit_once(':') {
            if !h.is_empty() && !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
                if let Ok(v) = p.parse::<u16>() {
                    return (h.to_string(), v);
                }
            }
        }
    }
    (trimmed.to_string(), port)
}

/// **[历史归因]** 解析后的上游地址（对齐 Python `parse_upstream_addr` 返回的 dict）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAddr {
    pub proto: Proto,
    pub host: String,
    pub port: u16,
    /// DoH/DoH3/DoQ 的 URL 路径（其余协议为空串）。
    pub url: String,
}

fn is_dohish(proto: Proto) -> bool {
    matches!(proto, Proto::Doh | Proto::Doh3 | Proto::Doq)
}

/// **[历史归因]** 从完整地址串自动识别协议/地址/端口/路径，对齐 Python `parse_upstream_addr`。
///
/// `proto_sel`：无 scheme 前缀时强制指定协议（`None` 或 `"auto"` 视为 udp）。
/// **[历史归因]** 无法识别返回 `Err`（Python 返回 None）。
pub fn parse_upstream_addr(raw: &str, proto_sel: Option<&str>) -> UpstreamResult<ParsedAddr> {
    fn bad(msg: &str) -> UpstreamError {
        UpstreamError::InvalidAddr(msg.to_string())
    }
    let s = raw.trim();
    if s.is_empty() {
        return Err(bad("empty upstream address"));
    }

    let mut proto: Option<Proto> = None;
    let mut rest: &str = s;
    let mut url = String::new();
    let mut http_plain = false;

    // 识别 scheme：首个 ":" 后紧跟 "//"。
    if let Some(colon) = s.find(':') {
        let after = &s[colon + 1..];
        if let Some(rest_) = after.strip_prefix("//") {
            let scheme = &s[..colon];
            rest = rest_;
            match scheme.to_ascii_lowercase().as_str() {
                "https" => {
                    proto = Some(Proto::Doh);
                    url = "/dns-query".to_string();
                }
                "http" => {
                    proto = Some(Proto::Doh);
                    url = "/dns-query".to_string();
                    http_plain = true;
                }
                "quic" | "doq" => {
                    proto = Some(Proto::Doq);
                    url = "/dns-query".to_string();
                }
                "tls" | "dot" => proto = Some(Proto::Dot),
                "udp" => proto = Some(Proto::Udp),
                "tcp" => proto = Some(Proto::Tcp),
                "doh" => {
                    proto = Some(Proto::Doh);
                    url = "/dns-query".to_string();
                }
                "doh3" => {
                    proto = Some(Proto::Doh3);
                    url = "/dns-query".to_string();
                }
                "http3" | "h3" => {
                    proto = Some(Proto::Doh3);
                    url = "/dns-query".to_string();
                }
                _ => return Err(bad("unknown scheme")),
            }
        }
    }

    let proto = match proto {
        Some(p) => p,
        None => match proto_sel {
            Some(sel) if sel != "auto" => match Proto::from_lower(sel) {
                Some(p) => {
                    if is_dohish(p) {
                        url = "/dns-query".to_string();
                    }
                    p
                }
                None => return Err(bad("unknown proto_sel")),
            },
            _ => Proto::Udp,
        },
    };

    let mut host = rest.to_string();
    let mut port = proto.default_port();
    if http_plain {
        port = 80;
    }

    // 路径切分（仅 dohish 协议）。
    if let Some(slash) = host.find('/') {
        let p = &host[slash..];
        if is_dohish(proto) {
            url = if p.starts_with('/') {
                p.to_string()
            } else {
                format!("/{p}")
            };
        }
        host.truncate(slash);
    }

    // **[历史归因]** 端口切分：与 Python `config.parse_upstream_addr` 的三类 host 分支**逐条等价**
    // （config.py:291-327）。三类判据与被拒形态：
    //
    //   1) `[v6]` / `[v6]:port`（config.py:299-322）
    // **[历史归因]**      - `[]` 或 `[` 无右括号 → 拒绝（Python `_rb <= 1` ⇔ Rust `rb == 0`，
    //        其中 `rb` 是 `inner` 内下标，故 `inner` 下标 0 ⇒ `host` 下标 1）；
    //      - 右括号后为空 → 裸 `[v6]`，保留默认端口；
    //      - 右括号后 `:` + **全 ASCII 数字**且非空 → 切端口；
    //      - 右括号后以 `:` 开头但后缀空/非纯数字（`[::1]:` / `[::1]:53a`）→ 拒绝；
    //      - 右括号后非空且不以 `:` 开头（`[::1]abc`）→ 拒绝。
    //      对齐点：`isdigit()` 只接受 ASCII 数字（Rust `is_ascii_digit`）；
    // **[历史归因]**      已知分叉：Python `"[::1]:١٢"`（阿拉伯-印度数字）解析成 port=12，
    //      Rust 拒绝——该输入在配置落库前已被端口范围校验与 ASCII host 白名单拦截，
    //      不改变任何可落库配置的结果（见本文件测试注释）。
    //   2) 裸 IPv6（冒号数 > 1，如 `::1` / `2001:db8::1`）→ 整体作 host，用默认端口。
    //      否则 `rfind(':')` 会把 `::1` 的末段 `1` 误切为 port。对齐 config.py:323。
    //   3) 普通 host：`host:port` 切端口；`host:` / `host:abc` 不切 → 落入下方
    //      "残留单冒号"拒绝。对齐 config.py:325 + :341 + :348。
    if let Some(inner) = host.strip_prefix('[') {
        // [v6] / [v6]:port
        let rb = match inner.find(']') {
            Some(i) => i,
            None => return Err(bad("unterminated ipv6 literal")),
        };
        // 方括号之间至少 1 个字符（"[]" / "[" 拒绝）。
        if rb == 0 {
            return Err(bad("empty ipv6 literal"));
        }
        let after = &inner[rb + 1..];
        if !after.is_empty() {
            if let Some(num) = after.strip_prefix(':') {
                if !num.is_empty() && num.chars().all(|c| c.is_ascii_digit()) {
                    port = num.parse().map_err(|_| bad("bad port"))?;
                } else {
                    // **[历史归因]** Python 显式拒绝 `[v6]:` 与 `[v6]:53a`（config.py:315-319）。
                    return Err(bad("garbage after [v6]:"));
                }
            } else {
                // **[历史归因]** Python 显式拒绝 `[v6]abc`（config.py:320-322）。
                return Err(bad("garbage after [v6]"));
            }
        }
        // **[历史归因]** 有意与 Python 的**存储形态**分叉：Python `parse_upstream_addr` 保留方括号
        // （`host = host[:_rb + 1]` ⇒ `"[::1]"`），而这里剥离为裸 `::1`。原因：
        // `UpstreamConfig.host` 的既有契约就是"已剥离 `[`"（config.rs:12），
        // 下游 `tcp::resolve_target` / `udp::resolve_udp_addrs` / `doh::connect_doh`
        // / `quic` 均依赖该形态（带方括号会让 `IpAddr::parse` 与 `getaddrinfo` 双失败）。
        // **[历史归因]** Python 侧之所以能在配置里存 `[::1]`，是因为它每次使用时都经
        // `upstream._host_port()` 再剥一次方括号——Rust 把这次剥离提前到解析期，
        // 端到端的**连接目标**完全一致。此分叉已在 upstream_tests.rs 中显式固化。
        host = inner[..rb].to_string();
    } else if host.matches(':').count() <= 1 {
        if let Some(colon) = host.rfind(':') {
            if colon > 0 {
                let tail = &host[colon + 1..];
                // **[历史归因]** Python `host[colon+1:].isdigit()`：空串为假（不切端口）；
                // `str.isdigit()` 对非 ASCII 数字为真但 `int()` 也能解析，
                // Rust 侧恒用 ASCII 数字，二者对非 ASCII 输入都落入下方拒绝。
                if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) {
                    port = tail.parse().map_err(|_| bad("bad port"))?;
                    host.truncate(colon);
                }
            }
        }
    }

    if host.is_empty() {
        return Err(bad("empty host"));
    }
    if host.len() > 253 {
        return Err(bad("host too long"));
    }
    if !host.chars().all(host_char_ok) {
        return Err(bad("host contains illegal characters"));
    }
    if host.starts_with('[') && host.ends_with(':') {
        return Err(bad("trailing colon after bracketed ipv6"));
    }
    // 切分后仍残留单冒号（如 "example.com:" / "host:abc"）→ 畸形。
    // **[历史归因]** （对齐 Python config.py:348 `if host.count(":") == 1: return None`。）
    if host.matches(':').count() == 1 {
        return Err(bad("single residual colon in host"));
    }
    // **[历史归因]** 端口范围校验：Python 在 :352 拒绝 `not (1 <= port <= 65535)`。此处的 1..=65535
    // 与之一致；因 `port` 是 u16，`>65535` 在上方 `parse::<u16>()` 已经失败，
    // **[历史归因]** 真正生效的只有下界（`host:0` / `[::1]:0` → 拒绝，对齐 Python）。
    if !(1..=65535).contains(&port) {
        return Err(bad("port out of range"));
    }

    if is_dohish(proto) {
        if url.is_empty() {
            url = "/dns-query".to_string();
        } else if !url.starts_with('/') {
            url = format!("/{url}");
        }
    } else {
        url = String::new();
    }

    Ok(ParsedAddr {
        proto,
        host,
        port,
        url,
    })
}

/// 判断解析出的 IP 是否为私有/保留/环回/链路本地/组播/未指定地址（防 rebinding）。
///
/// **[历史归因]** 对齐 Python `resolver._is_private_ip`：非 IP（域名）返回 false 不拦截。
pub fn is_private_ip(ip_str: &str) -> bool {
    match ip_str.parse::<IpAddr>() {
        Ok(ip) => match ip {
            IpAddr::V4(v) => is_private_v4(v),
            IpAddr::V6(v) => is_private_v6(&v),
        },
        Err(_) => false,
    }
}

/// 订阅/握手阶段更宽的非全球单播判定：在 `is_private_ip` 基础上再拒 CGNAT 100.64.0.0/10。
///
/// **[历史归因]** 答案 rebind 过滤仍用 `is_private_ip`（Python 对答案路径放行 100.64）；仅订阅 guard 用本谓词。
pub fn is_non_global_for_subscription(ip_str: &str) -> bool {
    if is_private_ip(ip_str) {
        return true;
    }
    match ip_str.parse::<IpAddr>() {
        Ok(ip) => match ip {
            IpAddr::V4(v) => is_cgnat_v4(v),
            IpAddr::V6(v) => match v.to_ipv4_mapped() {
                Some(v4) => is_cgnat_v4(v4),
                None => false,
            },
        },
        Err(_) => false,
    }
}

/// IPv4 是否落入 CGNAT 100.64.0.0/10。
fn is_cgnat_v4(v: std::net::Ipv4Addr) -> bool {
    let o = v.octets();
    o[0] == 100 && (o[1] & 0xC0) == 0x40
}

/// IPv4 私网/环回/链路本地/组播/保留/未指定/特殊文档段统一判定。
///
/// **[历史归因]** 对齐 Python `ipaddress` 的 `is_private|is_loopback|is_link_local|is_multicast|is_reserved|is_unspecified`。
fn is_private_v4(v: std::net::Ipv4Addr) -> bool {
    v.is_private()
        || v.is_loopback()
        || v.is_link_local()
        || v.is_multicast()
        || is_v4_reserved(v)
        || v.is_unspecified()
        || is_v4_special(v)
}

/// **[历史归因]** IPv4 保留段（240.0.0.0/4，即 240-255），对齐 Python `ipaddress.is_reserved`。
fn is_v4_reserved(v: std::net::Ipv4Addr) -> bool {
    v.octets()[0] >= 240
}

/// **[历史归因]** IPv4 其余 Python 视为 private/reserved 的特殊段（Rust std 未覆盖）。
fn is_v4_special(v: std::net::Ipv4Addr) -> bool {
    let o = v.octets();
    // 0.0.0.0/8 "this network"
    o[0] == 0
        // 192.0.0.0/24 IETF protocol assignments
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        // 192.0.2.0/24 TEST-NET-1
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)
        // 198.18.0.0/15 benchmarking (198.18-198.19)
        || (o[0] == 198 && (o[1] & 0xFE) == 18)
        // 198.51.100.0/24 TEST-NET-2
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        // 203.0.113.0/24 TEST-NET-3
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
}

fn is_private_v6(v: &std::net::Ipv6Addr) -> bool {
    let s = v.segments();
    // v6 原生/保留段：loopback/unspecified/multicast/ULA/link-local/documentation/
    // Teredo/benchmarking/discard/NAT64/6to4 整段保留。
    if v.is_loopback()
        || v.is_unspecified()
        || v.is_multicast()
        || (s[0] & 0xFE00) == 0xFC00 // unique local (fc00::/7)
        || (s[0] & 0xFFC0) == 0xFE80 // link-local fe80::/10
        || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation 2001:db8::/32
        || (s[0] == 0x2001 && s[1] == 0) // Teredo 2001::/32
        || (s[0] == 0x2001 && s[1] == 0x0002) // benchmarking 2001:2::/48
        || (s[0] == 0x0100 && s[1] == 0) // discard prefix 100::/64
        || (s[0] == 0x0064 && s[1] == 0xff9b) // NAT64 64:ff9b::/32 整段 reserved
        || s[0] == 0x2002
    // 6to4 2002::/16 整段 reserved
    {
        return true;
    }
    // IPv4-mapped ::ffff:a.b.c.d（to_ipv4_mapped 仅命中 ::ffff:0:0/96）。
    if let Some(v4) = v.to_ipv4_mapped() {
        return is_private_v4(v4);
    }
    // IPv4-compatible ::/96（::a.b.c.d；::/::1 已被原生 loopback/unspecified 接住）：
    // **[历史归因]** Python 按 is_reserved 整段拒，不委托内嵌 v4 判定（::8.8.8.8 也拒）。
    if s[..6] == [0, 0, 0, 0, 0, 0] {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 期望值取自 `python -c "from ebpdns.config import parse_upstream_addr"` 的实测
    /// 输出（v1.9.162 权威参考实现），逐条固化三类 host 分支的矩阵。
    ///
    /// **[历史归因]** 已知**唯一**有意分叉：Python 对 `[v6]` / `[v6]:port` 保留方括号
    /// （`addr` 字段为 `"[::1]"`），Rust 交付裸 `::1`（见 `parse_upstream_addr` 内注释）。
    #[test]
    fn three_branch_matrix_matches_python() {
        // ---- 分支 1: [v6] / [v6]:port ----
        assert_eq!(
            parse_upstream_addr("[::1]", Some("udp")).unwrap().host,
            "::1"
        );
        assert_eq!(parse_upstream_addr("[::1]", Some("udp")).unwrap().port, 53);
        let p = parse_upstream_addr("[::1]:5300", Some("tcp")).unwrap();
        assert_eq!(p.host, "::1", "裸 v6 主机（Python 存 [::1]，交付层剥括号）");
        assert_eq!(p.port, 5300);
        let p = parse_upstream_addr("[2001:db8::1]:8853", None).unwrap();
        assert_eq!(p.host, "2001:db8::1");
        assert_eq!(p.port, 8853);
        assert_eq!(p.proto, Proto::Udp, "无 scheme + proto_sel=None → udp");
        // **[历史归因]** 空括号 / 无右括号 → 拒绝（Python `_rb <= 1`）。
        assert!(parse_upstream_addr("[]:80", None).is_err());
        assert!(parse_upstream_addr("[]", None).is_err());
        assert!(parse_upstream_addr("[::1", None).is_err());
        // **[历史归因]** 右括号后畸形后缀 → 拒绝（Python config.py:315-322 显式拒绝）。
        assert!(
            parse_upstream_addr("[::1]:", None).is_err(),
            "[v6]: 必须拒绝"
        );
        assert!(parse_upstream_addr("[::1]:53a", None).is_err());
        assert!(parse_upstream_addr("[::1]:abc", None).is_err());
        assert!(parse_upstream_addr("[::1]abc", None).is_err());
        // **[历史归因]** 端口边界：0 与 >65535 拒绝（Python :352 的 1..=65535）。
        assert!(parse_upstream_addr("[::1]:0", None).is_err());
        assert!(parse_upstream_addr("[::1]:65536", None).is_err());
        assert_eq!(
            parse_upstream_addr("[::1]:65535", None).unwrap().port,
            65535
        );
        // **[历史归因]** 非 ASCII 数字：Python `"[::1]:١٢"` 因 `str.isdigit()` 对阿拉伯-印度数字
        // 为真而**解析成 port=12**（实测），Rust 按 ASCII 数字口径拒绝。
        // 属已知边界分叉：非 ASCII 端口在配置落库前已被 `config.validate_config`
        // / `api._validate_upstream` 的 1..=65535 校验与后续 getaddrinfo 拦住，
        // 且 `HOST_CHARS` 白名单本就是 ASCII，故不改变任何可落库配置的结果。
        assert!(parse_upstream_addr("[::1]:١٢", None).is_err());
    }

    #[test]
    fn bare_ipv6_branch_never_splits_port() {
        // ---- 分支 2: 裸 IPv6（冒号 > 1）→ 整体作 host + 默认端口 ----
        let p = parse_upstream_addr("::1", None).unwrap();
        assert_eq!(p.host, "::1");
        assert_eq!(p.port, 53, "不得把 ::1 的末段切成 port=1");
        let p = parse_upstream_addr("2001:db8::1", None).unwrap();
        assert_eq!(p.host, "2001:db8::1");
        assert_eq!(p.port, 53);
        let p = parse_upstream_addr("2001:db8::1:5353", None).unwrap();
        assert_eq!(p.host, "2001:db8::1:5353", "整段保留，不切末段");
        assert_eq!(p.port, 53);
        // 裸 v6 + scheme。
        let p = parse_upstream_addr("quic://2001:db8::1", None).unwrap();
        assert_eq!(p.proto, Proto::Doq);
        assert_eq!(p.host, "2001:db8::1");
        assert_eq!(p.port, 853);
    }

    #[test]
    fn plain_host_branch_splits_only_numeric_port() {
        // ---- 分支 3: 普通 host ----
        let p = parse_upstream_addr("example.com:5353", None).unwrap();
        assert_eq!(p.host, "example.com");
        assert_eq!(p.port, 5353);
        let p = parse_upstream_addr("1.1.1.1:53", Some("udp")).unwrap();
        assert_eq!((p.host.as_str(), p.port), ("1.1.1.1", 53));
        // **[历史归因]** host: 非数字端口 / 尾随冒号 → 拒绝（Python 残留单冒号检查）。
        assert!(
            parse_upstream_addr("example.com:", None).is_err(),
            "host: 必须拒绝"
        );
        assert!(parse_upstream_addr("example.com:abc", None).is_err());
        assert!(parse_upstream_addr("example.com:0", None).is_err());
        assert!(parse_upstream_addr("example.com:65536", None).is_err());
        assert_eq!(
            parse_upstream_addr("example.com:65535", None).unwrap().port,
            65535
        );
        // scheme + host:port。
        let p = parse_upstream_addr("https://dns.google:8443/dns-query", None).unwrap();
        assert_eq!(
            (p.proto, p.host.as_str(), p.port, p.url.as_str()),
            (Proto::Doh, "dns.google", 8443, "/dns-query")
        );
        // **[历史归因]** 非 dohish 协议丢弃路径（对齐 Python :285-290 无条件切掉 `/` 之后）。
        let p = parse_upstream_addr("udp://h/p", None).unwrap();
        assert_eq!((p.host.as_str(), p.url.as_str()), ("h", ""));
    }

    #[test]
    fn scheme_and_defaults_matrix() {
        let p = parse_upstream_addr("https://dns.google/dns-query", None).unwrap();
        assert_eq!(
            (p.proto, p.port, p.url.as_str()),
            (Proto::Doh, 443, "/dns-query")
        );
        let p = parse_upstream_addr("http://dns.google/x", None).unwrap();
        assert_eq!((p.proto, p.port), (Proto::Doh, 80), "明文 http:// 默认 80");
        let p = parse_upstream_addr("tls://1.1.1.1", None).unwrap();
        assert_eq!((p.proto, p.port, p.url.as_str()), (Proto::Dot, 853, ""));
        let p = parse_upstream_addr("h3://dns.google", None).unwrap();
        assert_eq!((p.proto, p.port), (Proto::Doh3, 443));
        let p = parse_upstream_addr("doq://dns.adguard.com:8853", None).unwrap();
        assert_eq!((p.proto, p.port), (Proto::Doq, 8853));
        // proto_sel 生效 / 未知 proto_sel 拒绝。
        let p = parse_upstream_addr("dns.google", Some("doh")).unwrap();
        assert_eq!((p.proto, p.url.as_str()), (Proto::Doh, "/dns-query"));
        let p = parse_upstream_addr("dns.google", Some("auto")).unwrap();
        assert_eq!(p.proto, Proto::Udp);
        assert!(parse_upstream_addr("dns.google", Some("bogus")).is_err());
        assert!(parse_upstream_addr("bogus://h", None).is_err());
        // 空串 / 超长 / 非法字符。
        assert!(parse_upstream_addr("", None).is_err());
        assert!(parse_upstream_addr("  ", None).is_err());
        assert!(parse_upstream_addr(&format!("{}.com", "a".repeat(252)), None).is_err());
        assert!(parse_upstream_addr("bad host", None).is_err());
        assert!(parse_upstream_addr("bad;host", None).is_err());
    }

    #[test]
    fn host_port_strips_brackets_like_python() {
        // **[历史归因]** 对齐 Python `upstream._host_port`：取括号内内容 + 传入端口。
        assert_eq!(
            host_port("[::1]:5300", Some(53), Proto::Udp),
            ("::1".to_string(), 53),
            "Python _host_port 返回 (addr[1:idx], port)，忽略括号后的 :5300"
        );
        assert_eq!(
            host_port("[::1]", None, Proto::Doh),
            ("::1".to_string(), 443)
        );
        assert_eq!(
            host_port("2001:db8::1", Some(53), Proto::Udp),
            ("2001:db8::1".to_string(), 53),
            "裸 v6 不切端口"
        );
        // 未闭合方括号：保守返回原文，不静默截断。
        assert_eq!(
            host_port("[::1", Some(53), Proto::Udp),
            ("[::1".to_string(), 53)
        );
        // 无方括号时的内嵌端口。
        assert_eq!(
            host_port("1.1.1.1:5353", None, Proto::Udp),
            ("1.1.1.1".to_string(), 5353)
        );
        assert_eq!(
            host_port("example.com:abc", Some(53), Proto::Udp),
            ("example.com:abc".to_string(), 53),
            "非数字端口不切"
        );
    }

    #[test]
    fn is_hostname_and_is_v6() {
        assert!(is_hostname("example.com"));
        assert!(!is_hostname("8.8.8.8"));
        assert!(!is_hostname("::1"));
        assert!(
            !is_hostname("[::1]"),
            "带方括号视为非 hostname（避免 getaddrinfo）"
        );
        assert!(!is_hostname(""));
        assert!(is_v6("::1"));
        assert!(is_v6("fe80::1%eth0"), "%scope 必须剥离后再判定");
        assert!(!is_v6("1.2.3.4"));
    }

    /// 回归：`url` 是路径，完整 URL 绝不能整串进入 request-target / H3 `:path`。
    #[test]
    fn request_path_normalizes_url_forms() {
        // 路径形态原样保留。
        assert_eq!(request_path("/dns-query", true), "/dns-query");
        assert_eq!(request_path("dns-query", true), "/dns-query");
        assert_eq!(request_path("/resolve?a=1", true), "/resolve?a=1");
        // 空串：加密协议默认 DoH 路径；明文协议不带路径。
        assert_eq!(request_path("", true), "/dns-query");
        assert_eq!(request_path("   ", true), "/dns-query");
        assert_eq!(request_path("", false), "");
        // 明文协议即使配置里写了路径也必须为空（回归：曾把 udp 也补成 "/dns-query"）。
        assert_eq!(request_path("/dns-query", false), "");
        assert_eq!(request_path("dns-query", false), "");
        assert_eq!(request_path("https://dns.google/dns-query", false), "");
        // 完整 URL 形态（缺陷原样）：只取 authority 之后的路径。
        assert_eq!(
            request_path("https://dns.alidns.com:443/dns-query", true),
            "/dns-query"
        );
        assert_eq!(
            request_path("http://127.0.0.1:8053/dns-query", true),
            "/dns-query"
        );
        assert_eq!(
            request_path("https://dns.google/dns-query?x=1", true),
            "/dns-query?x=1"
        );
        // 无路径的完整 URL → 默认路径。
        assert_eq!(request_path("https://dns.google", true), "/dns-query");
        // 关键不变量：结果永远不以 `//` 或 scheme 开头。
        for raw in [
            "",
            "/dns-query",
            "dns-query",
            "https://dns.alidns.com:443/dns-query",
            "https://dns.google",
        ] {
            let p = request_path(raw, true);
            assert!(p.starts_with('/'), "{raw:?} → {p:?} 必须以 / 开头");
            assert!(!p.starts_with("//"), "{raw:?} → {p:?} 不得以 // 开头");
            assert!(
                !p.contains("://"),
                "{raw:?} → {p:?} 不得含 scheme（缺陷回归）"
            );
        }
    }
}
