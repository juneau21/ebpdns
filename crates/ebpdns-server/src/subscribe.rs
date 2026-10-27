//! 规则订阅：URL 拉取 / 多格式解析 / 独立文件持久化 / 周期更新 / SSRF 防护。
//!
//! **[历史归因]** 忠实对齐 Python v1.9.162：
//! - `api.py:3444-3469` `_api_subscribe_rules`（POST /api/rules/subscribe）；
//! - `api.py:3471-3570` `_api_subscribe_update`（POST /api/rules/subscribe/update）；
//! - `api.py:3572-3626` `_api_subscribe_delete`（DELETE /api/rules/subscribe?url=）；
//! - `api.py:3081-3201` `_do_subscribe_download`（下载 → 解析 → 落盘 → 元信息 → rebuild）；
//! - `api.py:3351-3419` `_load_subs` / `_save_subs`（独立文件 `rules_sub.json`，tmp+fsync+rename）；
//! - `api.py:4200-4302` `_parse_domain_list`（多格式域名列表解析）；
//! - `api.py:467-524` `_sub_url_blocked`（仅 https + 所有解析 IP 必须 `is_global`）；
//! - `api.py:585-611` `_SSRFRedirectHandler`（每跳复检 + 禁非 https 跳转）；
//! - `api.py:628-656` `fetch_subscription_text`（20s 超时 / 16MB 上限 / 流式读取）；
//! - `resolver.py:3391-3411` `_bg_loop` + `resolver.py:3495-3614` `_update_rule_subs_once`
//!   （每 10s tick、`rule_sub_interval` 秒触发一次、逐个串行、失败仅告警）。
//!
//! **[历史归因]** # 数据模型（与 Python 一致，两处存储）
//! - `rules_sub.json`（本模块唯一写者）：
//!   `{"subscriptions":[{url,action,group,ip,updated_at,rules:[{match}],count}]}`
//! - `config.json` 的 `rule_subscriptions[]`：**只存元信息**
//!   `{url,action,group,ip,count,updated_at}`，`updated_at` 形如 `"YYYY-MM-DD HH:MM:SS"`。
//!
//! # 并发（F07）
//! - 拉取用进程级 `tokio::sync::Semaphore(4)`（`std::sync::OnceLock` 持有）限流，
//! **[历史归因]**   对齐 Python `_SUBSCRIBE_SEM`；
//! - **订阅读改写事务**（`subscribe`/`update`/`delete`/后台 `update_once`）与
//!   `rules_admin` 的规则事务**共用同一把**进程级 `tokio::sync::Mutex<()>`
//!   （[`sub_txn`] → `rules_admin::rules_txn`），覆盖「读 `rules_sub.json` → 改 →
//!   写回 → 写 config 元信息 → 重建索引」整段，避免并发互相覆盖与内存/磁盘分叉；
//!   锁序与死锁规避见 `rules_admin::rules_txn` 的文档；
//! - 阻塞 HTTP（ureq）与阻塞文件 IO 一律包在 `tokio::task::spawn_blocking`；
//! - 网络下载（最长 20s）必须在取锁**之前**完成；`cfg` 读改写进
//!   `parking_lot::RwLock` 短临界区（不跨 await）；写盘失败的语义是「内存不变 /
//!   磁盘不变」（内存只在 `rules_sub.json` 落盘成功后才改），细节见 [`commit_sub_txn`]。
//!
//! **[历史归因]** # 与 Python 的有意差异（详见各函数注释）
//! **[历史归因]** 1. 「连接钉 IP」：Python `_PinnedHTTPSConn` 把 TCP 钉到已验公网 IP。ureq 3 没有把
//!    解析器写进 `Config`/`ConfigBuilder`，但 `Agent::with_parts(config, connector,
//!    resolver)` 接受自定义 [`Resolver`]，而 ureq 的连接链**只**使用该解析器返回的地址
//!    （`ureq-3.4.2/src/unversioned/transport/tcp.rs:117-155`：
//!    `TcpStream::connect_timeout(details.addrs[i])`）。本模块据此把域名钉到
//!    [`resolve_checked`] 返回的**已校验 IP** 上（[`PinnedResolver`] + [`PinGuard`]
//!    线程局部钉死表，**进程级单 Agent**，2.1.48 / M-248），`resolve → connect`
//!    之间不再发生第二次 `getaddrinfo`，
//!    TOCTOU / DNS rebinding 窗口为 0。TLS 侧不受影响：SNI 与证书校验仍用 URI 里的
//!    原始主机名（`ureq-3.4.2/src/tls/rustls.rs:62`），钉死 IP 不削弱身份校验。
//! **[历史归因]** 2. 「500 + 文案」：Python 的 `保存订阅文件失败` / `配置写盘失败（已回滚订阅明细）` /
//!    `规则索引重建失败` 都是 **500 + 中文文案**。`ServerError::Internal` 是 unit 变体
//!    （固定渲染 `internal error`），可带文案的变体状态码都不对（`Forbidden` 403 /
//!    `BadGateway` 502），且本任务不允许改 `error.rs`。故这里统一返回
//!    `ServerError::Internal`（状态码 500 正确）+ `tracing::error!`（文案进服务端日志）。
//!    **2.1.48 / AUD-11**：`error.rs` 早已有 `BadGateway(String) -> 502`，订阅**拉取失败**
//!    （网络/TLS/SSRF/非 2xx）按 INTERFACE 契约改回 **502**（见 `subscribe`/`update`）；
//!    写盘/重建失败仍是 500（`Internal` + ERROR 日志）。
//! 3. 「相对路径基准」：`rule_sub_file` 为相对路径时以 **config.json 所在目录** 为基准
//! **[历史归因]**    （Python 相对进程 CWD；本实现按 2.0 口径归一，绝对路径不变，见 F30）。

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ebpdns_rules::{rule_from_json, Rule, RuleSource};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use ureq::unversioned::resolver::{ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{DefaultConnector, NextTimeout};

use crate::error::ServerError;
use crate::rules_admin::{normalize_rule_json, resolve_rel_to_config, rules_txn};
use crate::state::AppState;

/* ---------------- 常量（对齐 Python 取值） ---------------- */

/// **[历史归因]** 拉取总超时（Python `fetch_subscription_text(url, timeout=20)`）。
const FETCH_TIMEOUT: Duration = Duration::from_secs(20);
/// **[历史归因]** 响应体上限 16MB（Python `SUB_TEXT_MAX_BYTES`）。
const SUB_MAX_BYTES: u64 = 16 * 1024 * 1024;
/// **[历史归因]** 每跳复检的最大重定向次数（Python `_SSRFRedirectHandler` 沿用 urllib 默认上限 10）。
const MAX_REDIRECTS: usize = 10;
/// 钉死地址上限：ureq `ResolvedSocketAddrs` 的容量是 16
/// （`ureq-3.4.2/src/unversioned/resolver.rs:55` 的 `MAX_ADDRS`，私有常量），
/// 超出会让 `ArrayVec::push` panic，故在构造钉死表时就截断。
const MAX_PINNED_ADDRS: usize = 16;
/// **[历史归因]** 订阅拉取并发上限（Python `_SUBSCRIBE_SEM` = 4）。
const SUBSCRIBE_CONCURRENCY: usize = 4;
/// **[历史归因]** 周期更新 tick（Python `_bg_loop` → `self._bg_stop.wait(10)`）。
const BG_TICK: Duration = Duration::from_secs(10);
/// **[历史归因]** 默认订阅刷新周期（秒，Python `config.get("rule_sub_interval", 3600)`）。
const DEFAULT_RULE_SUB_INTERVAL: u64 = 3600;
/// `match` 字段字节上限（对齐 `api._validate_rule_dict` / rules `MATCH_MAX_BYTES` = 4096）。
const MATCH_MAX_BYTES: usize = 4096;

/// 订阅拉取信号量（进程级单例）。
fn subscribe_sem() -> &'static Semaphore {
    static SEM: OnceLock<Semaphore> = OnceLock::new();
    SEM.get_or_init(|| Semaphore::new(SUBSCRIBE_CONCURRENCY))
}

/// 订阅面事务锁：**就是** `rules_admin` 的规则事务锁（F07）。
///
/// 两个面共用同一实例 → 订阅 CRUD 与规则 CRUD 相互排斥（此前各持一把锁 = 没有互斥），
/// `rules_sub.json` 与 `config.json` 的「读 → 改 → 写回」不会再互相覆盖。
/// 锁序与死锁规避见 `rules_admin::rules_txn` 的文档（本模块只调用它，不新增锁）。
fn sub_txn() -> &'static tokio::sync::Mutex<()> {
    rules_txn()
}

/* ---------------- 路径 / 时间 ---------------- */

/// 订阅明细文件路径：优先 `cfg["rule_sub_file"]`，否则 `config.json` 同目录 `rules_sub.json`。
///
/// 对齐 `api.py:3348-3349` `_sub_file()`：`cfg.get("rule_sub_file") or
/// config_mod.sub_rules_path(self.app.config_path)`。
/// 返回类型是 `PathBuf`（非 `Option`），故**空串 / 非字符串**的 `rule_sub_file`
/// **[历史归因]** 按「未配置」处理并回退默认路径（与 Python `or` 语义一致）。
/// F30：配置值为相对路径时以 **config.json 所在目录** 为基准（不是进程 CWD）；
/// 绝对路径原样返回。
pub fn subs_path(cfg: &Value, cfg_path: Option<&Path>) -> PathBuf {
    if let Some(p) = cfg.get("rule_sub_file").and_then(Value::as_str) {
        let p = p.trim();
        if !p.is_empty() {
            return resolve_rel_to_config(Path::new(p), cfg_path);
        }
    }
    match cfg_path {
        // 与 ebpdns_rules::load::sub_rules_path 同口径（config.json 同目录 rules_sub.json）。
        Some(p) => ebpdns_rules::load::sub_rules_path(p),
        None => PathBuf::from(ebpdns_rules::load::SUB_RULES_FILE),
    }
}

/// **[历史归因]** `"YYYY-MM-DD HH:MM:SS"`（本地时间，对齐 Python `time.strftime("%Y-%m-%d %H:%M:%S")`）。
fn ts_now() -> String {
    fmt_local_ts(SystemTime::now())
}

/// 本地时间格式化：由 `SystemTime` 手动推导日历（不引入 chrono/time 依赖）。
fn fmt_local_ts(t: SystemTime) -> String {
    fmt_local_ts_with_offset(t, local_utc_offset_secs())
}

/// 注入固定 UTC 偏移的本地时间格式化（`本地 = UTC + offset_secs`）。
///
/// 拆出偏移参数是为了让「偏移 → 时间串」这段可测（F27）：平台相关的偏移获取
/// （`GetTimeZoneInformation` / `localtime_r`）无法在单测里注入。
fn fmt_local_ts_with_offset(t: SystemTime, offset_secs: i64) -> String {
    let secs = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    };
    let local = secs + offset_secs;
    // Howard Hinnant civil_from_days：epoch 起天数 → (y, m, d)。
    let days = local.div_euclid(86_400);
    let rem = local.rem_euclid(86_400);
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02}")
}

/// 本机 UTC 偏移（秒，`本地 = UTC + 偏移`）：Windows 走 Win32 `GetTimeZoneInformation`。
///
/// F27：Win32 的 `Bias`/`StandardBias`/`DaylightBias` 语义是「本地 = UTC - bias」(分钟)，
/// 且两个 Bias 成员**互斥**叠加（夏令时用 `Bias + DaylightBias`，标准时用
/// `Bias + StandardBias`，不生效的一方被忽略）——此前把 `StandardBias` 与
/// `DaylightBias` 连加是错的。拿不到时告警，不静默按 UTC 顶替。
#[cfg(windows)]
fn local_utc_offset_secs() -> i64 {
    #[allow(dead_code)] // 其余字段用于对齐 Win32 ABI（只读 bias / daylight_bias）
    #[repr(C)]
    struct TzInfo {
        bias: i32,
        standard_name: [u16; 32],
        standard_date: [u16; 8],
        standard_bias: i32,
        daylight_name: [u16; 32],
        daylight_date: [u16; 8],
        daylight_bias: i32,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetTimeZoneInformation(info: *mut TzInfo) -> u32;
    }
    let mut info: TzInfo = unsafe { std::mem::zeroed() };
    // TIME_ZONE_ID_INVALID = 0xFFFFFFFF；1 = STANDARD，2 = DAYLIGHT，0 = UNKNOWN。
    let rc = unsafe { GetTimeZoneInformation(&mut info) };
    if rc == 0xFFFF_FFFF {
        tracing::warn!("GetTimeZoneInformation 失败，updated_at 按 UTC 展示");
        return 0;
    }
    let minutes = match rc {
        2 => info.bias + info.daylight_bias,
        1 => info.bias + info.standard_bias,
        // UNKNOWN：本机不使用夏令时，只有 Bias 生效（StandardBias 不参与）。
        _ => info.bias,
    };
    -(minutes as i64) * 60
}

/// 本机 UTC 偏移（秒，`本地 = UTC + 偏移`）：非 Windows 走 libc `localtime_r` 的
/// **[历史归因]** `tm_gmtoff`（含夏令时，等价 Python `time.strftime` 用的本地时区）。
///
/// F27：此前只看 `TZ` 数字、拿不到就返回 0，导致 `TZ` 未设置的环境（Linux 常态）
/// **[历史归因]** `updated_at` 与 Python 本地时间差整个时区。`libc` 不是 `ebpdns-server` 的直接依赖
/// （改 `Cargo.toml` 超出本任务范围），故本文件内按 glibc/musl/BSD/macOS 同 ABI 手工
/// 声明 `struct tm`/`localtime_r`（**未新增任何依赖**）。只有该调用失败时才退回解析
/// `TZ`；两者都拿不到时打 WARN（不静默用 0 掩盖，但返回值只能是 0）。
#[cfg(not(windows))]
fn local_utc_offset_secs() -> i64 {
    if let Some(off) = local_offset_via_localtime() {
        return off;
    }
    if let Some(off) = tz_env_offset() {
        tracing::warn!("localtime_r 失败, 改用 TZ 环境变量推断 UTC 偏移: {off}s");
        return off;
    }
    tracing::warn!("无法确定本机 UTC 偏移(localtime_r 与 TZ 均失败), updated_at 将按 UTC 展示");
    0
}

/// `localtime_r(...).tm_gmtoff`（秒）；`None` = 调用失败。
#[cfg(not(windows))]
fn local_offset_via_localtime() -> Option<i64> {
    // C `long`（`tm_gmtoff` 与 `time_t` 在 glibc 里的类型）：32 位目标是 4 字节。
    #[cfg(target_pointer_width = "64")]
    type CLong = i64;
    #[cfg(not(target_pointer_width = "64"))]
    type CLong = i32;

    /// 与 glibc/musl/BSD/macOS 布局一致的 `struct tm`（只读 `tm_gmtoff`）。
    /// glibc 无论是否定义 `__USE_MISC` 都在同一偏移上保留这两个字段（另一套私有名字）。
    #[allow(dead_code)] // 其余字段用于对齐 ABI
    #[repr(C)]
    struct Tm {
        tm_sec: i32,
        tm_min: i32,
        tm_hour: i32,
        tm_mday: i32,
        tm_mon: i32,
        tm_year: i32,
        tm_wday: i32,
        tm_yday: i32,
        tm_isdst: i32,
        tm_gmtoff: CLong,
        tm_zone: *const i8,
    }
    // **P2（2.1.14）**：libc 符号声明必须与 `telemetry.rs::unix_local_hms` 里的
    // **逐字一致**（都用 `*const c_void` / `*mut c_void`），否则
    // `clashing_extern_declarations` 告警（两处同名的 extern 声明签名不同）。
    extern "C" {
        fn localtime_r(
            timep: *const std::ffi::c_void,
            result: *mut std::ffi::c_void,
        ) -> *mut std::ffi::c_void;
    }
    let now: CLong = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as CLong,
        Err(e) => -(e.duration().as_secs() as CLong),
    };
    let mut tm: Tm = unsafe { std::mem::zeroed() };
    let out = unsafe {
        localtime_r(
            (&now as *const CLong).cast::<std::ffi::c_void>(),
            (&mut tm as *mut Tm).cast::<std::ffi::c_void>(),
        )
    };
    if out.is_null() {
        None
    } else {
        // `i64::from` 而非 `as i64`：`CLong` 在 64 位目标上就是 i64，`as` 会被
        // clippy::unnecessary_cast 判为冗余（`-D warnings` 下直接失败）。
        Some(tm.tm_gmtoff)
    }
}

/// 从 `TZ` 里的字面固定偏移（`+0800` / `-5` / `UTC+8`）推断秒数；判定不了 → `None`。
///
/// 仅作 `localtime_r` 失败后的兜底：POSIX 的 `TZ=XXX+8` 语义其实是 UTC-8（符号相反），
/// 本函数按字面符号解析（与旧实现一致），宁可告警也不要静默按 UTC。
#[cfg(not(windows))]
fn tz_env_offset() -> Option<i64> {
    let tz = std::env::var("TZ").ok()?;
    let digits: String = tz
        .chars()
        .skip_while(|c| !c.is_ascii_digit() && *c != '+' && *c != '-')
        .collect();
    if digits.len() < 2 {
        return None;
    }
    let sign = if digits.starts_with('-') { -1 } else { 1 };
    let n: i64 = digits.trim_start_matches(['+', '-']).parse().ok()?;
    if n > 100 {
        Some(sign * ((n / 100) * 3600 + (n % 100) * 60))
    } else {
        Some(sign * n * 3600)
    }
}

/* ---------------- 解析 ---------------- */

/// 解析订阅文本 → 去重域名列表（不校验、不改写）。
///
/// 直接复用 [`ebpdns_rules::parse::parse_domain_list`]
/// **[历史归因]** （`crates/ebpdns-rules/src/parse.rs:74`），它已逐行对齐 Python `api._parse_domain_list`：
/// 纯域名 / hosts / 逗号分隔 / dnsmasq `address=/a/b/` / SmartDNS `address /域名/#` /
/// Surge `DOMAIN-SUFFIX,...` / Clash `- '+.域名'` / Adblock `||域名^`；跳过 `@@` 例外、
/// 注释（`# ! // ;`）、YAML 顶层键、裸 IP；`re:` 保留并过正则/长度/控制字符闸门。
pub fn parse_domain_list(text: &str) -> Vec<String> {
    ebpdns_rules::parse::parse_domain_list(text)
}

/// 域名列表 → 规则项 `[{match: "*.d"|"re:..."}]`；非法 `re:` 跳过并 warning。
///
/// 对齐 `api.py:3124`：`items = [{"match": "*."+d if not d.startswith(("*.","re:")) else d}]`。
/// 非法 `re:` 的闸门与 `crates/ebpdns-rules/src/index.rs:75-90` 索引期同口径：
/// 空体 / 控制字符 / 超 4096 字节 → 跳过并 warning（非法**正则语法**已由上游
/// `parse_domain_list` 内的 `Regex::new` 预校验剔除，故此处无需再引入 `regex` 依赖）。
///
/// 空输入返回空 `Vec`；`"订阅内容未解析到有效域名"` 由 [`subscribe`](fn@subscribe) /
/// [`update`](fn@update) 在空结果时给出（对齐 `api.py:3121-3122` / `3511-3512`）。
pub fn domains_to_rules(domains: &[String]) -> Vec<Value> {
    let mut items: Vec<Value> = Vec::with_capacity(domains.len());
    for d in domains {
        let d = d.trim();
        if d.is_empty() {
            continue;
        }
        let m = if d.starts_with("*.") || d.starts_with("re:") {
            d.to_string()
        } else {
            format!("*.{d}")
        };
        if m.starts_with("re:") && !re_gate_ok(&m) {
            tracing::warn!("订阅 re: 规则非法（空体/控制字符/超 4096 字节），已跳过: {m}");
            continue;
        }
        items.push(json!({ "match": m }));
    }
    items
}

/// `re:` 结构闸门（与 rules 索引期 `has_control_char` + `MATCH_MAX_BYTES` + 空体同口径）。
fn re_gate_ok(m: &str) -> bool {
    let body = m.strip_prefix("re:").unwrap_or("");
    if body.trim().is_empty() || m.len() > MATCH_MAX_BYTES {
        return false;
    }
    !m.bytes().any(|b| b < 0x20 || b == 0x7f)
}

/* ---------------- SSRF 防护 ---------------- */

/// SSRF 校验：非 https / 私网保留地址 → `Err(原因文案)`；DNS 解析失败也给明确文案。
///
/// 对齐 `api.py:467-524` `_sub_url_blocked`：仅 `https://`；解析主机的**全部** IP，
/// 任一命中 `not is_global or is_multicast or is_reserved` 即整体拒绝（防 DNS rebinding）。
///
/// 就是 [`pinned_targets`] 的 `map(|_| ())`：判据只有一处实现，「校验通过」与
/// 「钉死目标」不可能分叉。
pub fn url_blocked(url: &str) -> Result<(), String> {
    pinned_targets(url).map(|_| ())
}

/// 校验订阅 URL → **钉死目标** `(规范化主机名, 已校验的 SocketAddr 列表)`。
///
/// **[历史归因]** 对齐 `api.py:467-524` + Python `_PinnedHTTPSConn`：与 [`url_blocked`] 同一套判据，
/// 但额外把「已校验的 IP」连同端口一起交出来，供 [`PinnedResolver`] 钉死。
/// 返回的 `SocketAddr` **只**可能来自 [`resolve_checked`]（见 [`pin_socket_addrs`]）。
fn pinned_targets(url: &str) -> Result<(String, Vec<SocketAddr>), String> {
    let parsed = url::Url::parse(url).map_err(|_| "订阅 URL 解析失败".to_string())?;
    if parsed.scheme() != "https" {
        return Err("订阅 URL 仅支持 https:// (http:// 不安全, 已禁止)".to_string());
    }
    let host = parsed
        .host_str()
        .map(|h| h.trim_matches(['[', ']']).to_string())
        .filter(|h| !h.is_empty())
        .ok_or_else(|| "订阅 URL 缺少主机名".to_string())?;
    let port = parsed.port_or_known_default().unwrap_or(443);
    let ips = resolve_checked(&host, port)?;
    Ok((normalize_host(&host), pin_socket_addrs(&ips, port)))
}

/// 主机名规范化（与 [`PinnedResolver`] 比对用）：去 IPv6 方括号 + 小写。
fn normalize_host(host: &str) -> String {
    host.trim_matches(['[', ']']).to_ascii_lowercase()
}

/// 已校验 IP 列表 → 钉死用的 `SocketAddr` 列表（**纯函数**，便于单测断言不变量）。
///
/// 只做「补端口 + 去重 + 截断到 [`MAX_PINNED_ADDRS`]」，**不做任何地址判定、不引入
/// 任何新 IP**：判定已由 [`resolve_checked`] 完成，本函数的结果必然是它的子集。
fn pin_socket_addrs(ips: &[IpAddr], port: u16) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::with_capacity(ips.len());
    for ip in ips {
        let sa = SocketAddr::new(*ip, port);
        if !out.contains(&sa) {
            out.push(sa);
        }
    }
    if out.len() > MAX_PINNED_ADDRS {
        tracing::warn!(
            "订阅主机解析出 {} 个地址, 只钉死前 {MAX_PINNED_ADDRS} 个",
            out.len()
        );
        out.truncate(MAX_PINNED_ADDRS);
    }
    out
}

/// 解析主机 → 全部 IP，逐个过非全球单播闸门；返回**已校验通过**的 IP 列表。
/// **[历史归因]** 对齐 Python：主机名本身是 IP 时不查 DNS，直接判定。
fn resolve_checked(host: &str, port: u16) -> Result<Vec<IpAddr>, String> {
    let ips: Vec<IpAddr> = match host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => {
            let addrs = (host, port)
                .to_socket_addrs()
                .map_err(|_| "订阅主机名解析失败".to_string())?;
            let mut v: Vec<IpAddr> = Vec::new();
            for a in addrs {
                if !v.contains(&a.ip()) {
                    v.push(a.ip());
                }
            }
            v
        }
    };
    check_resolved_all_global(&ips)?;
    Ok(ips)
}

/// 「解析结果必须全是全球可路由地址」闸门（**纯函数**）。
///
/// 拆出来是为了让「同一主机名同时解析出公网 + 私网」（DNS rebinding 的典型形态）
/// 可以在单测里直接注入：**任一**地址非全球单播 → 整体拒绝，绝不「只挑公网的连」。
/// 空列表同样拒绝（`to_socket_addrs` 成功但无地址）。
fn check_resolved_all_global(ips: &[IpAddr]) -> Result<(), String> {
    if ips.is_empty() {
        return Err("订阅主机名无可用 IP".to_string());
    }
    for ip in ips {
        if is_non_global(*ip) {
            return Err("订阅地址指向内网/保留地址, 已拒绝(SSRF 防护)".to_string());
        }
    }
    Ok(())
}

/// **[历史归因]** 非全球可路由地址判定（对齐 Python `not ip.is_global or ip.is_multicast or ip.is_reserved`）。
///
/// 与 `crates/ebpdns-upstream/src/addr.rs:327 is_non_global_for_subscription` 同口径
/// （私网/环回/链路本地/组播/保留/未指定/文档段 + CGNAT 100.64/10），并额外收紧
/// **[历史归因]** Python 3.12 `is_global` 判定不一致的几段（0/8、192.0.0/24、192.88.99/24、198.18/15、
/// `::ffff:0:0/96`、`64:ff9b::/96`、`2001:db8::/32`）——fail-closed 方向。
fn is_non_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => is_non_global_v4(v),
        IpAddr::V6(v) => is_non_global_v6(v),
    }
}

fn is_non_global_v4(v: Ipv4Addr) -> bool {
    if v.is_private()          // 10/8, 172.16/12, 192.168/16
        || v.is_loopback()     // 127/8
        || v.is_link_local()   // 169.254/16
        || v.is_broadcast()    // 255.255.255.255
        || v.is_multicast()    // 224/4
        || v.is_unspecified()  // 0.0.0.0
        || v.is_documentation()
    // 192.0.2/24, 198.51.100/24, 203.0.113/24
    {
        return true;
    }
    let o = v.octets();
    match o[0] {
        0 => true,                       // 0.0.0.0/8 "this network"
        100 => (o[1] & 0xC0) == 0x40,    // 100.64/10 CGNAT
        192 => o[1] == 0 || o[1] == 88,  // 192.0.0/24 IETF 协议段 / 192.88.99/24 6to4 中继
        198 => o[1] == 18 || o[1] == 19, // 198.18.0.0/15 基准测试段
        240..=255 => true,               // 240/4 保留
        _ => false,
    }
}

fn is_non_global_v6(v: Ipv6Addr) -> bool {
    // IPv4-mapped ::ffff:a.b.c.d 与 IPv4-compatible ::a.b.c.d（含 :: 与 ::1）：
    // **[历史归因]** Python 判 is_global=True 但 is_reserved/is_private=True → 按拒绝处理。
    if let Some(v4) = v.to_ipv4_mapped().or_else(|| v.to_ipv4()) {
        return is_non_global_v4(v4) || v4.is_unspecified() || v4.is_loopback();
    }
    if v.is_loopback()            // ::1
        || v.is_unspecified()     // ::
        || v.is_multicast()       // ff00::/8
        || v.is_unique_local()    // fc00::/7
        || v.is_unicast_link_local()
    // fe80::/10
    {
        return true;
    }
    // 全局单播 2000::/3 之外一律拒绝（覆盖 100::/64 丢弃段、2001::/32 Teredo、
    // 2001:db8::/32 文档段、64:ff9b::/96 NAT64、fec0::/10 废弃站点本地等）。
    (v.segments()[0] & 0xE000) != 0x2000
}

/* ---------------- 拉取 ---------------- */

/// 拉取订阅文本（20s 超时、16MB 上限、重定向每跳复检 + **每跳钉死 IP**）。
///
/// 对齐 `api.py:628-656` `fetch_subscription_text`：
/// 1. 仅 `https://`（明文 http 可被中间人篡改规则注入）；
/// 2. 初始 URL 过 [`url_blocked`]（SSRF）取得已验公网 IP；
/// 3. **每跳**重定向重新过 [`url_blocked`] 复检（对齐 `_SSRFRedirectHandler`），
///    非 https 跳转直接拒绝；
/// 4. 流式读取，超过 16MB 立即中止。
///
/// # 真钉死（消除 `resolve → connect` 的 TOCTOU）
/// 每一跳都调 [`pinned_targets`] 拿到**已校验的 SocketAddr**，经 [`PinGuard`] 装进
/// 当前线程的钉死表；进程级唯一 Agent 的 [`PinnedResolver`] 只交出这张表里的地址
/// （2.1.48 / M-248：此前是每跳新建一个一次性 Agent，现改为单 Agent + 线程局部表，
/// 连接池/TLS 配置/会话缓存只建一次）。ureq 的 `Resolver::resolve` 是它获取连接
/// 地址的唯一入口，`TcpConnector` 直接把返回的 `SocketAddr` 交给
/// `TcpStream::connect_timeout` —— 全程没有第二次 `getaddrinfo`，DNS rebinding / TOCTOU
/// 窗口为 0。guard 在循环内安装 ⇒ 钉死作用到**每一跳**，Drop 即清除。
///
/// 其余网关不变：`max_redirects(0)` 关掉 ureq 自带跟随 → 3xx 原样返回，本函数读
/// `Location` 自行解析相对路径（`Url::join`）、再复检、再发请求；`http_status_as_error
/// (false)` 保证 3xx/4xx 不会被转成 `Err` 反而丢掉 `Location`；`https_only(true)` 作为
/// **[历史归因]** 兜底让任何经 ureq 发出的 URL 都必须 https；`proxy(None)` 显式禁代理（对齐 Python
/// `ProxyHandler({})`，代理会自己重解析 DNS 从而绕过本模块的 IP 复检）。
pub fn fetch_subscription_text(url: &str) -> Result<String, String> {
    let mut current = url.trim().to_string();
    for _hop in 0..=MAX_REDIRECTS {
        // 每跳复检：非 https / 私网保留地址 → 立即拒绝；同时取回**已校验**的钉死目标。
        // 关键不变量：下面 Agent 的 TCP 目标只可能来自 `pinned_targets` 的返回值。
        let (host, addrs) = pinned_targets(&current).map_err(|e| {
            tracing::warn!(url = %current, reason = %e, "订阅下载被拒绝(URL/SSRF 校验)");
            e
        })?;
        // 审计证据：本次连接只允许这些 IP（全部来自 `resolve_checked`）。
        tracing::info!(url = %current, host = %host, pinned = ?addrs, "订阅下载: 已校验并钉死连接目标");
        // **2.1.48 / M-248**：复用进程级唯一 Agent（连接池 + rustls ClientConfig/会话缓存）。
        // 旧实现每一跳都 `build_agent` 新建 Agent ⇒ 新 rustls `ClientConfig`（全量根证书
        // 解析）、新连接池、新会话缓存；这些内存在 hot path 上反复分配/释放，glibc 把
        // 碎片留在既有 arena（实测每次订阅刷新 +≈2 MiB，VmData 不涨）。钉死目标改由
        // 线程局部 [`PinGuard`] 承载，Agent 本身不再绑定“本次请求连哪个 IP”。
        let _pin = PinGuard::install(host, addrs);
        let mut resp = subscription_agent()
            .get(&current)
            .header("User-Agent", "ebpdns/subscribe")
            .header("Accept", "*/*")
            .call()
            .map_err(|e| {
                // 文案保持既有语义，具体原因（主机不匹配 / 连接超时 / TLS 失败）进日志。
                tracing::warn!(url = %current, error = %e, "订阅下载失败(连接/传输错误)");
                "订阅下载失败".to_string()
            })?;
        let status = resp.status().as_u16();
        if (300..400).contains(&status) {
            let next = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .and_then(|loc| url::Url::parse(&current).ok()?.join(loc).ok());
            let Some(next) = next else {
                return Err("订阅下载失败".to_string());
            };
            if next.scheme() != "https" {
                tracing::warn!("订阅重定向拒绝非 https 目标: {}", next.as_str());
                return Err("订阅下载失败".to_string());
            }
            current = next.to_string();
            continue;
        }
        if !(200..300).contains(&status) {
            tracing::warn!(%status, url = %current, "订阅下载失败(HTTP 错误)");
            return Err("订阅下载失败".to_string());
        }
        let body = resp.body_mut();
        return read_body_limited(&mut body.with_config().limit(SUB_MAX_BYTES + 1).reader());
    }
    tracing::warn!("订阅重定向次数过多: {url}");
    Err("订阅下载失败".to_string())
}

/// 订阅下载的「钉死解析器」：把 ureq 的「域名 → 地址」解析固定为**本线程当前请求**
/// 已校验的 IP（由 [`PinGuard`] 安装）。
///
/// # 为什么这样就等于真钉死
/// ureq 3 的取址路径是 `Resolver::resolve()` → `ConnectionDetails::addrs` →
/// `TcpConnector` → `TcpStream::connect_timeout(addr)`/`TcpStream::connect(addr)`
/// （`ureq-3.4.2/src/unversioned/transport/tcp.rs:117-155`，`addr` 即 `details.addrs`
/// 的元素）。**地址只在 `resolve()` 里产生，连接只使用它的返回值**：本结构返回什么
/// IP，TCP 就一定连什么 IP，中间没有任何第二次 `getaddrinfo`。
///
/// TLS 侧不受影响：ureq 的 rustls 连接器用 **URI 里的主机名**做 SNI 与证书校验
/// （`ureq-3.4.2/src/tls/rustls.rs:62` 的 `uri.authority()...`），钉死 IP 不削弱身份校验。
///
/// **2.1.48 / M-248**：改为**无状态**解析器 + 线程局部钉死表，使进程只建一个
/// [`ureq::Agent`]（连接池 / TLS 配置 / 会话缓存复用），同时保持“每跳、每请求只连
/// 已校验 IP”的不变量：
/// - [`fetch_subscription_text`] 在 `agent.get(...).call()` **之前**用 [`PinGuard`]
///   把 `(host, addrs)` 装进当前线程；
/// - ureq 在 `call()` 内**同步**调用 `Resolver::resolve`（`ureq-3.4.2/src/run.rs:382`），
///   与安装者同一线程；
/// - 取不到钉死项（guard 已释放 / URI 主机不符）⇒ `HostNotFound`，绝不回退系统 DNS。
#[derive(Debug, Default)]
struct PinnedResolver;

thread_local! {
    /// 当前线程正在拉取的订阅目标（**只**由 [`fetch_subscription_text`] 经 [`PinGuard`] 写入）。
    static PINNED: RefCell<Option<(String, Vec<SocketAddr>)>> = const { RefCell::new(None) };
}

/// 线程局部钉死表的 RAII 安装器：Drop 时清空 —— 错误/提前 return/panic 都不会残留。
struct PinGuard;

impl PinGuard {
    fn install(host: String, addrs: Vec<SocketAddr>) -> Self {
        PINNED.with(|p| *p.borrow_mut() = Some((host, addrs)));
        Self
    }
}

impl Drop for PinGuard {
    fn drop(&mut self) {
        PINNED.with(|p| *p.borrow_mut() = None);
    }
}

impl Resolver for PinnedResolver {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        _config: &ureq::config::Config,
        _timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        // fail-closed：请求的 URI 主机与「本线程被校验过的主机」不一致就拒绝解析，
        // 绝不为别的主机名交出钉死 IP（防止本解析器被复用到非预期目标）。
        let got = normalize_host(uri.authority().map(|a| a.host()).unwrap_or(""));
        let addrs = PINNED.with(|p| {
            p.borrow().as_ref().and_then(|(host, addrs)| {
                if *host == got {
                    Some(addrs.clone())
                } else {
                    None
                }
            })
        });
        let Some(addrs) = addrs else {
            tracing::warn!("订阅钉死目标缺失或与请求主机不一致(got={got}), 拒绝解析");
            return Err(ureq::Error::HostNotFound);
        };
        // `addrs` 已在 `pin_socket_addrs` 截断到 `MAX_PINNED_ADDRS`(= ureq 的容量 16)
        // → `push` 不可能越界 panic。
        let mut out = self.empty();
        for a in &addrs {
            out.push(*a);
        }
        if out.is_empty() {
            return Err(ureq::Error::HostNotFound);
        }
        Ok(out)
    }
}

/// 订阅专用 ureq Agent（`ureq = { version = "3", default-features = false,
/// features = ["rustls"] }` → rustls(ring) + webpki-roots 严格校验，绝不降级不校验）。
///
/// 除 `resolver` 外的配置与旧实现逐项相同（20s 全局/连接/收包超时、5s 解析超时、
/// `max_redirects(0)`、`https_only(true)`、`http_status_as_error(false)`、
/// `proxy(None)`）；`resolver` 决定 TCP 目标，见 [`PinnedResolver`]。
fn build_agent() -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(FETCH_TIMEOUT))
        .timeout_connect(Some(FETCH_TIMEOUT))
        .timeout_resolve(Some(Duration::from_secs(5)))
        .timeout_recv_response(Some(FETCH_TIMEOUT))
        .timeout_recv_body(Some(FETCH_TIMEOUT))
        .max_redirects(0) // 0 = 不跟随；响应原样返回（每跳由本模块自行复检）
        .https_only(true) // 兜底：经 ureq 的请求（含内部拼接）都必须 https
        .http_status_as_error(false) // 3xx/4xx 自行判定，避免 Err 丢掉 Location
        .proxy(None) // 显式禁代理（对齐 Python ProxyHandler({})）
        .user_agent("ebpdns/subscribe")
        .build();
    // `with_parts` 是 ureq 3 的解析器注入点：连接器仍是默认链（TCP + rustls），
    // 只有「域名 → 地址」这一步被换成钉死实现。
    ureq::Agent::with_parts(config, DefaultConnector::default(), PinnedResolver)
}

/// **2.1.48 / M-248**：进程级唯一订阅 Agent（`OnceLock`，首次调用时建）。
///
/// 复用同一 Agent ⇒ **连接池**、**rustls `ClientConfig`**（webpki 根证书只解析一次）、
/// **TLS 会话缓存**都只建一次。旧实现每次刷新/每一跳都 `build_agent` 新建 Agent，
/// 这些结构在 hot path 上反复分配/释放 —— 实测 10 次内容未变的订阅刷新
///（每次都只下载 + 摘要比对，不解析/不落盘/不重建）RSS 仍 +≈2 MiB/次、VmData 不涨。
///
/// 并发安全：`Agent` 内部是 `Arc`（连接池带锁），`Resolver` 是无状态 + 线程局部，
/// 多个 `spawn_blocking` 拉取可同时使用；钉死目标互不串线。
fn subscription_agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(build_agent)
}

/// 流式读取响应体：超过 16MB → `Err`；非法 UTF-8 按替换字符解码
/// **[历史归因]** （对齐 Python `decode("utf-8", "replace")`）。
fn read_body_limited<R: Read>(reader: &mut R) -> Result<String, String> {
    // **2.1.48 / M-248**：预分配 1 MiB（订阅常见 2~4 MB，减少 64 KiB 分片反复 realloc）；
    // 读完把 `Vec<u8>` **移动**进 `String`（合法 UTF-8 时零拷贝，旧实现
    // `from_utf8_lossy(&buf).into_owned()` 会整份再拷一次）。
    let mut buf = Vec::with_capacity(1024 * 1024);
    let mut chunk = [0u8; 65_536];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() as u64 > SUB_MAX_BYTES {
                    return Err("订阅响应超过 16MB 上限, 已中止".to_string());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(_) => return Err("订阅下载失败".to_string()),
        }
    }
    match String::from_utf8(buf) {
        Ok(s) => Ok(s),
        // 非法 UTF-8：保持旧的“替换字符”语义（极少数来源；此路径多一次拷贝可接受）。
        Err(e) => Ok(String::from_utf8_lossy(e.as_bytes()).into_owned()),
    }
}

/* ---------------- 持久化 ---------------- */

/// 读订阅明细文件；缺失 → 空 `Vec`；损坏 → 空 `Vec` + warning。
///
/// 对齐 `api.py:3351-3360`：只读 `subscriptions` 数组；`FileNotFoundError` → 空；
/// 其它异常打 WARNING 后按空处理（不 panic、不阻断）。
pub fn load_subs(path: &Path) -> Vec<Value> {
    let s = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            tracing::warn!(
                "订阅规则文件读取失败 {}: {}, 按空列表处理",
                path.display(),
                e
            );
            return Vec::new();
        }
    };
    // >>> 242B BEGIN P1-11-bom >>> //
    // **2.1.42-B（P1-11）**：BOM 容错（手工编辑常见；旧实现整份当空表）。
    let s = s.trim_start_matches('\u{feff}');
    match serde_json::from_str::<Value>(s) {
        Ok(v) => v
            .get("subscriptions")
            // <<< 242B END P1-11-bom <<< //
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        Err(e) => {
            tracing::warn!(
                "订阅规则文件 JSON 解析失败 {}: {}, 按空列表处理",
                path.display(),
                e
            );
            Vec::new()
        }
    }
}

/// 原子写订阅明细文件：`tmp` 写入 + `fsync` + `rename`（+ 尽力 fsync 父目录）。
///
/// P0（内存）：改为**流式**写（`serde_json::to_writer` 逐条序列化 `subs`），
/// 不再 `json!({"subscriptions": subs})` + `to_vec`——旧实现每次落盘都要
/// 再构造一棵含 10 万条明细的 `Value` 树 + 一个 3.3MB `Vec<u8>`，是订阅路径
/// 峰值内存（实测 VmPeak ≈ 996MB）的主要来源之一。输出字节与旧实现完全一致。
///
/// 失败时清理残留 `.tmp`，绝不留下半截文件（对齐 `api.py:3379-3419` `_save_subs`）。
pub fn save_subs(path: &Path, subs: &[Value]) -> std::io::Result<()> {
    let body = subs_bytes(subs)?;
    atomic_write(path, &body)
}

/// `rules_sub.json` 的**内容字节**（`{"subscriptions":[...]}`，无多余空白）。
///
/// **为什么需要它**：统一事务要求"先把 part 的内容算出来"（`commit_droppable` 收的是
/// `path -> bytes`），而 2.1.21 的 `save_subs` 是**边序列化边写文件**的流式实现。
/// 本函数把同一份字节算进内存 —— 单测 `subs_bytes_matches_streaming_save_subs`
/// 逐字节钉死"两条路径产出同一份文件"。
pub fn subs_bytes(subs: &[Value]) -> std::io::Result<Vec<u8>> {
    let mut b: Vec<u8> = Vec::with_capacity(64 + subs.len() * 32);
    b.extend_from_slice(b"{\"subscriptions\":");
    serde_json::to_writer(&mut b, subs).map_err(serde_to_io)?;
    b.push(b'}');
    Ok(b)
}

/// `serde_json::Error` → `io::Error`（写盘路径统一错误类型）。
fn serde_to_io(e: serde_json::Error) -> std::io::Error {
    std::io::Error::other(e)
}

/// `rules_sub.json` 的**计数视图**条目（P0 内存）：只保留订阅级元信息 + `rules` 长度。
///
/// `rules` 用 `Vec<serde::de::IgnoredAny>` 反序列化：跳过明细而不构造任何
/// `serde_json::Value`（ZST 序列**零分配**）。旧实现每次 `GET /api/rules` 都
/// `load_subs` 把 10 万条明细物化成 `Value` 树（实测单次 ~66MB、10 万条订阅下
/// 控制台轮询会反复触发 66MB 分配/释放 → 堆碎片把 RSS 顶在数百 MB）。
#[derive(serde::Deserialize)]
struct SubCountDe {
    #[serde(default)]
    url: String,
    action: Option<String>,
    group: Option<String>,
    ip: Option<String>,
    updated_at: Option<String>,
    /// `Some(_)` = 文件里有 `rules` 字段（计数以它为准）；`None` = 缺字段（回退 `count`）。
    rules: Option<Vec<serde::de::IgnoredAny>>,
    /// 文件里自带的 `count`（`sub_entry` 写入）。
    count: Option<u64>,
}

#[derive(serde::Deserialize)]
struct SubFileCounts {
    #[serde(default)]
    subscriptions: Vec<SubCountDe>,
}

/// 只读订阅明细文件 → **计数视图**（不物化任何明细 `Value`）。
///
/// 缺失文件 → 空；损坏 → 空 + WARNING（与 [`load_subs`] 同口径，不 panic、不阻断）。
pub fn load_subs_counts(path: &Path) -> Vec<Value> {
    let Ok(f) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let parsed: SubFileCounts = match serde_json::from_reader(std::io::BufReader::new(f)) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                "订阅规则文件读取/JSON 解析失败 {}: {}, 按空列表处理",
                path.display(),
                e
            );
            return Vec::new();
        }
    };
    parsed
        .subscriptions
        .into_iter()
        .map(|s| {
            let n = match &s.rules {
                Some(v) => v.len(),
                None => s.count.unwrap_or(0) as usize,
            };
            json!({
                "url": s.url,
                "action": s.action.unwrap_or_default(),
                "group": s.group.unwrap_or_default(),
                "ip": s.ip.unwrap_or_default(),
                "updated_at": s.updated_at.unwrap_or_default(),
                "count": n,
            })
        })
        .collect()
}

/* ---------------- 订阅明细 → 规则（直接解析，不物化 Value 树） ---------------- */

// >>> 242B BEGIN P1-11-deser >>> //
// ---- **2.1.42-B（P1-11）**：宽容反序列化 ----
//
// 旧实现用严格类型（`match: String` / `Vec<SubItemDe>`）：任一条目类型不符
// （`"match": 123`、`"rules": [null]`、`"action": 1`、文件被截断/带 BOM）会让
// **整份** `rules_sub.json` 解析失败 ⇒ 10 万条订阅规则一次性清空，且本地规则
// 为 0 时 `failed()` 仍为 false ⇒ HTTP 200 假成功（审计 P1-03）。
//
// 现在：字段级宽容（非字符串 → 缺失/空）+ 明细级宽容（坏条目跳过并计 dropped），
// 只有**整份 JSON 语法错误**才判 unreadable（保留旧索引 + 5xx）。

fn de_lenient_string<'de, D>(d: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = <serde_json::Value as serde::Deserialize>::deserialize(d)?;
    Ok(match v {
        serde_json::Value::String(s) => s,
        _ => String::new(),
    })
}

fn de_lenient_opt_string<'de, D>(d: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = <serde_json::Value as serde::Deserialize>::deserialize(d)?;
    Ok(match v {
        serde_json::Value::String(s) => Some(s),
        _ => None,
    })
}

/// `rules` 数组逐条宽容：非对象/类型不符的条目 → `SubItemDe::default()`
/// （`match` 为空 ⇒ 下游按"空 match"计入 dropped，而不是让整份文件解析失败）。
fn de_lenient_items<'de, D>(d: D) -> Result<Vec<SubItemDe>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = <serde_json::Value as serde::Deserialize>::deserialize(d)?;
    let Some(arr) = v.as_array() else {
        return Ok(Vec::new());
    };
    Ok(arr
        .iter()
        .map(|x| serde_json::from_value::<SubItemDe>(x.clone()).unwrap_or_default())
        .collect())
}

/// `rules_sub.json` 的单条明细项（只取 `match`）。
#[derive(serde::Deserialize, Default)]
struct SubItemDe {
    #[serde(rename = "match", default, deserialize_with = "de_lenient_string")]
    m: String,
}

/// `rules_sub.json` 的单条订阅（只取注入规则所需字段）。
#[derive(serde::Deserialize)]
struct SubRuleDe {
    /// **2.1.48 / AUD-03**：配置里已删除的订阅不得继续进索引。
    #[serde(default, deserialize_with = "de_lenient_opt_string")]
    url: Option<String>,
    #[serde(default, deserialize_with = "de_lenient_opt_string")]
    action: Option<String>,
    #[serde(default, deserialize_with = "de_lenient_opt_string")]
    group: Option<String>,
    #[serde(default, deserialize_with = "de_lenient_opt_string")]
    ip: Option<String>,
    #[serde(default, deserialize_with = "de_lenient_items")]
    rules: Vec<SubItemDe>,
}

#[derive(serde::Deserialize)]
struct SubRuleFileDe {
    /// **2.1.48 / AUD-01**：**不加** `#[serde(default)]` —— 缺 `subscriptions` 键
    /// （`{}` / `{"foo":1}` / `{"subscriptions":"x"}`）必须反序列化失败 ⇒
    /// `unreadable=true` ⇒ 端点 5xx + 保留旧索引，绝不静默清空十万条订阅规则。
    subscriptions: Vec<SubRuleDe>,
}
// <<< 242B END P1-11-deser <<< //

/// **[历史归因]** `as_str` 等价：缺失/非字符串/空白 → `default`（对齐 Python `x or default`）。
fn de_pick(v: Option<&str>, default: &str) -> String {
    match v.map(str::trim) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => default.to_string(),
    }
}

/// 一条订阅明细项 + 订阅级配置 → 规则（与 [`rule_json`] + `rule_from_json` 同口径：
/// 每项只做一次小 `Map` 分配，**不构造** 10 万条明细的 `Value` 树）。
fn rule_from_sub_item(sub: &SubRuleDe, item: &SubItemDe) -> Option<Rule> {
    let m = item.m.trim();
    if m.is_empty() {
        return None;
    }
    let action = de_pick(sub.action.as_deref(), "block");
    let mut map = Map::new();
    map.insert("match".to_string(), Value::String(m.to_string()));
    map.insert("action".to_string(), Value::String(action.clone()));
    if action == "group" {
        map.insert(
            "group".to_string(),
            Value::String(de_pick(sub.group.as_deref(), "global")),
        );
    } else if action == "forceIp" {
        map.insert(
            "ip".to_string(),
            Value::String(de_pick(sub.ip.as_deref(), "1.2.3.4")),
        );
    }
    rule_from_json(map, RuleSource::Sub)
}

// >>> 242B BEGIN P1-11-parse >>> //
/// 从磁盘 `rules_sub.json` 直接构建订阅规则（**不物化明细 Value 树**）。
///
/// 返回 `(rules, dropped, unreadable)`：
/// * `unreadable = true` ⇒ 文件存在但**整体不可解析/不可读**。调用方必须
///   **保留旧索引**并返回 5xx（P1-11：先校验后写）；
/// * 单条坏行只计入 `dropped`（不整份清空），UTF-8 BOM 自动剥离。
/// **2.1.48 / AUD-05**：`rules_sub.json` 的**元信息视图** —— 只解析订阅级字段，
/// 明细 `rules` 用 `IgnoredAny` 跳过（零 `Value` 物化）。
///
/// 为什么不能直接用 [`load_subs`]：后者为 10 万条明细构造 `Value` 树（实测单次
/// ~66 MB）。AUD-05 只是要回答“这个 URL 还在不在”，用元信息视图即可；
/// 缺 `subscriptions` 键/语法错误 ⇒ `None`（调用方按自愈路径处理）。
fn sub_urls_strict(path: &Path) -> Option<Vec<String>> {
    #[derive(serde::Deserialize)]
    struct MetaDe {
        #[serde(default)]
        url: String,
    }
    #[derive(serde::Deserialize)]
    struct FileDe {
        subscriptions: Vec<MetaDe>,
    }
    let body = std::fs::read(path).ok()?;
    let body = body
        .strip_prefix(&[0xEF, 0xBB, 0xBF])
        .unwrap_or(body.as_slice());
    let parsed: FileDe = serde_json::from_slice(body).ok()?;
    Some(
        parsed
            .subscriptions
            .into_iter()
            .map(|s| s.url.trim().to_string())
            .filter(|u| !u.is_empty())
            .collect(),
    )
}

/// 带**失败原因**的订阅明细解析（2.1.49：reload 错误通道用）。
fn sub_rules_from_bytes_checked(
    body: &[u8],
    path: &Path,
    allowed: Option<&HashSet<String>>,
) -> (Vec<Rule>, usize, Option<RebuildFailure>) {
    // 手工编辑很容易带上 UTF-8 BOM；serde_json 不接受它（旧实现因此整份失败）。
    let body = body.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(body);
    let parsed: SubRuleFileDe = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            // **2.1.49**：把 serde 的"缺键"与"其它非法"分开 —— 两者都是 5xx，
            // 但机读 code 不同（AUD-01 的判据就是 `{}`/缺 `subscriptions` ⇒ 失败）。
            let msg = e.to_string();
            let failure = if msg.contains("missing field") && msg.contains("subscriptions") {
                RebuildFailure::RulesSubMissingSubscriptions
            } else {
                RebuildFailure::RulesSubInvalid
            };
            tracing::error!(
                "订阅规则文件 JSON 解析失败 {}: {}（code={}）⇒ 本次不替换索引（保留旧真源）",
                path.display(),
                e,
                failure.code()
            );
            return (Vec::new(), 0, Some(failure));
        }
    };
    let mut out: Vec<Rule> = Vec::new();
    let mut dropped = 0usize;
    for sub in &parsed.subscriptions {
        // **2.1.48 / AUD-03**：`config.rule_subscriptions` 是权威清单 —— 配置里已删除的
        // 订阅（多为用户主动删除 block/allow）不得继续从磁盘文件进索引。`allowed=None`
        // 只用于测试/兼容旧调用（不做过滤）。
        if let Some(set) = allowed {
            let u = sub.url.as_deref().unwrap_or("").trim();
            if !u.is_empty() && !set.contains(u) {
                tracing::warn!("规则索引重建: 忽略配置中已删除的订阅 {u}");
                continue;
            }
        }
        for item in &sub.rules {
            match rule_from_sub_item(sub, item) {
                Some(r) => out.push(r),
                None => {
                    tracing::warn!(
                        "规则索引重建: 订阅规则条目被丢弃(空 match / 非法 ip): {:?}",
                        item.m
                    );
                    dropped += 1;
                }
            }
        }
    }
    (out, dropped, None)
}

/// 读路径包装（兼容既有测试调用点；生产重建走字节快照）。
#[cfg(test)]
fn sub_rules_from_path_checked(
    path: &Path,
    allowed: Option<&HashSet<String>>,
) -> (Vec<Rule>, usize, Option<RebuildFailure>) {
    match read_source(path) {
        SourceRead::Body(b) => sub_rules_from_bytes_checked(&b, path, allowed),
        SourceRead::Missing => (Vec::new(), 0, None),
        SourceRead::Failed => {
            tracing::error!(
                "订阅规则文件**不可读** {} ⇒ 本次不替换索引（保留上一份规则快照）",
                path.display()
            );
            (Vec::new(), 0, Some(RebuildFailure::RulesSubUnreadable))
        }
    }
}

/// 兼容包装（既有测试/调用点只需要"是否 unreadable"）。
#[cfg(test)]
fn sub_rules_from_path(path: &Path, allowed: Option<&HashSet<String>>) -> (Vec<Rule>, usize, bool) {
    let (rules, dropped, failure) = sub_rules_from_path_checked(path, allowed);
    (rules, dropped, failure.is_some())
}
// <<< 242B END P1-11-parse <<< //

/// 原子写（文件内容 + 父目录）；供 `save_subs` 与 `config.json` 元信息写回复用。
///
/// **2.1.36（D 批）**：四步协议收敛到 [`crate::io_atomic`]；保留 `<path>.tmp`、
/// 建父目录、失败清理三条既有策略。
fn atomic_write(path: &Path, body: &[u8]) -> std::io::Result<()> {
    crate::io_atomic::atomic_write_bytes_opts(
        path,
        body,
        &crate::io_atomic::WriteOptions::appended(".tmp"),
    )
}

/* ---------------- 条目构造 / 规则合并 ---------------- */

fn as_str(v: &Value, k: &str) -> String {
    v.get(k)
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string()
}

/// 单条订阅 → `rules_sub.json` 明细条目（`api.py:3135-3144` / `3153-3161`）。
///
/// **仅测试使用**（生产路径用 [`sub_entry_owned`] 以移动 `items`，避免明细树翻倍）。
#[allow(dead_code)]
fn sub_entry(
    url: &str,
    action: &str,
    group: &str,
    ip: &str,
    items: &[Value],
    updated_at: &str,
) -> Value {
    json!({
        "url": url,
        "action": action,
        "group": group,
        "ip": ip,
        "updated_at": updated_at,
        "count": items.len(),
        "rules": items,
    })
}

/// 同上，但**接管** `items` 所有权（P0 内存：明细树只有一份）。
fn sub_entry_owned(
    url: &str,
    action: &str,
    group: &str,
    ip: &str,
    items: Vec<Value>,
    updated_at: &str,
) -> Value {
    let n = items.len();
    json!({
        "url": url,
        "action": action,
        "group": group,
        "ip": ip,
        "updated_at": updated_at,
        "count": n,
        "rules": items,
    })
}

/// 单条订阅 → `config.json` 元信息条目（**只**元信息，不含 `rules`）。
fn meta_entry(
    url: &str,
    action: &str,
    group: &str,
    ip: &str,
    count: usize,
    updated_at: &str,
) -> Value {
    json!({
        "url": url,
        "action": action,
        "group": group,
        "ip": ip,
        "count": count,
        "updated_at": updated_at,
    })
}

/// 由 `rules_sub.json` 明细还原 `config.json` 元信息数组。
///
/// **P2（2.1.14）**：只有测试在用（生产路径走 `rebuild`/`load_sub_meta`），
/// 加 `#[cfg(test)]` 消除 `cargo build` 的 dead_code 告警。
#[cfg(test)]
fn meta_from_subs(subs: &[Value]) -> Value {
    Value::Array(
        subs.iter()
            .map(|s| {
                meta_entry(
                    &as_str(s, "url"),
                    &as_str(s, "action"),
                    &as_str(s, "group"),
                    &as_str(s, "ip"),
                    s.get("rules")
                        .and_then(Value::as_array)
                        .map(Vec::len)
                        .unwrap_or(0),
                    &as_str(s, "updated_at"),
                )
            })
            .collect(),
    )
}

/// 订阅条目 + 明细项 → 规则 JSON（action/group/ip 取自订阅级配置）。
/// 对齐 `crates/ebpdns-rules/src/load.rs:84-125` `load_sub_rules_file` 的注入口径。
///
/// **仅测试使用**：生产路径用 [`rule_from_sub_item`]（同样的注入口径，但不物化明细）。
#[allow(dead_code)]
fn rule_json(sub: &Value, item: &Value) -> Option<Map<String, Value>> {
    let m = item.get("match").and_then(Value::as_str)?.trim();
    if m.is_empty() {
        return None;
    }
    let raw_action = as_str(sub, "action");
    let action = if raw_action.is_empty() {
        "block".to_string()
    } else {
        raw_action
    };
    let mut map = Map::new();
    map.insert("match".to_string(), Value::String(m.to_string()));
    map.insert("action".to_string(), Value::String(action.clone()));
    if action == "group" {
        let g = as_str(sub, "group");
        map.insert(
            "group".to_string(),
            Value::String(if g.is_empty() {
                "global".to_string()
            } else {
                g
            }),
        );
    } else if action == "forceIp" {
        let ip = as_str(sub, "ip");
        map.insert(
            "ip".to_string(),
            Value::String(if ip.is_empty() {
                "1.2.3.4".to_string()
            } else {
                ip
            }),
        );
    }
    Some(map)
}

/// 一次索引重建的统计（F20）。
///
/// `dropped` = 在进 `RuleIndex::build` **之前**就被丢弃的条目数（空 `match` /
/// 非法 `re:` / forceIp 缺合法 ip / 非对象条目）。旧实现静默 `filter_map` 丢掉它们且
/// 不计入 `BuildStats::rejected`，于是「全部规则死在进索引之前」会得到
/// `indexed == 0 && rejected == 0`，被当成成功 → 200 但索引为空（静默放行全部域名）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RebuildStats {
    /// 成功进索引的规则数。
    pub indexed: usize,
    /// `RuleIndex::build` 判废的规则数（空体/控制符/超长/正则编译失败等）。
    pub rejected: usize,
    /// 进 `RuleIndex::build` 前即被丢弃的规则数。
    pub dropped: usize,
    /// **2.1.23（DEF-222-01，P0）**：本次重建期间**规则真源存在但读不懂**
    /// （`RulesParse::Unreadable`）。这是 fail-closed 的判据 —— 见 [`RebuildStats::failed`]。
    pub source_unreadable: bool,
}

impl RebuildStats {
    /// 一条规则都没进索引、且存在被拒或被丢弃的规则 → 「规则索引重建失败」。
    /// 空规则集（无被拒/被丢弃）不算失败，避免清空规则时误报。
    ///
    /// **[2.1.23（DEF-222-01）]** 额外把 `source_unreadable` 判为**失败**：
    /// 2.1.22 里"真源存在但 JSON 损坏/形状不认识"会走到"0 条规则"的成功重建
    /// ⇒ 端点 200、`indexed=0`、域名**被放行**（fail-open，安全缺陷）。
    /// 现在这种情形**必然**让端点 500 + ERROR 日志，绝不静默。
    pub fn failed(&self) -> bool {
        self.source_unreadable || (self.indexed == 0 && self.rejected + self.dropped > 0)
    }
}

/// **2.1.49（P0）**：一次重建失败的**机器可读**原因。
///
/// 2.1.48 的 [`RebuildStats::failed`] 只回答"失败与否"，reload 端点无法区分
/// "订阅文件坏 / 缺 `subscriptions` / 本地真源坏 / 规则全部被拒"，更无法把原因
/// 回传给调用方（`on_reload` 当时没有错误通道）。本类型收成**固定 code**，
/// 由 `state::ReloadError` 映射成 `{"ok":false,"error":"<code>","detail":...}`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebuildFailure {
    /// `rules_sub.json` 存在但读不出来（权限/IO）。
    RulesSubUnreadable,
    /// `rules_sub.json` 是合法 JSON 但缺 `subscriptions` 键（2.1.48 / AUD-01）。
    RulesSubMissingSubscriptions,
    /// `rules_sub.json` JSON 语法/形状非法（含 `subscriptions` 类型不对）。
    RulesSubInvalid,
    /// 本地规则真源（`state/rules.json` / 镜像 / `rules_local.json`）读不懂。
    RulesLocalUnreadable,
    /// 合并后的规则集**全部被拒/丢弃**（坏规则），重建判失败。
    AllRulesRejected,
}

impl RebuildFailure {
    /// 机器可读 code（HTTP 5xx 响应体的 `error` 字段）。
    pub fn code(self) -> &'static str {
        match self {
            Self::RulesSubUnreadable => "rules_sub_unreadable",
            Self::RulesSubMissingSubscriptions => "rules_sub_missing_subscriptions",
            Self::RulesSubInvalid => "rules_sub_invalid",
            Self::RulesLocalUnreadable => "rules_local_unreadable",
            Self::AllRulesRejected => "rules_rebuild_failed",
        }
    }

    /// 人类可读 detail（只描述类别，不回显文件内容/内网拓扑）。
    pub fn detail(self) -> &'static str {
        match self {
            Self::RulesSubUnreadable => "订阅规则文件不可读（保留旧规则索引，本次不替换）",
            Self::RulesSubMissingSubscriptions => {
                "订阅规则文件缺 subscriptions 键（保留旧规则索引，本次不替换）"
            }
            Self::RulesSubInvalid => "订阅规则文件 JSON/schema 非法（保留旧规则索引，本次不替换）",
            Self::RulesLocalUnreadable => "本地规则真源无法解析（保留旧规则索引，本次不替换）",
            Self::AllRulesRejected => "合并后的规则全部被拒/丢弃（保留旧规则索引，本次不替换）",
        }
    }
}

/// **2.1.49（P0）**：重建结果 —— `stats` 供既有端点使用，`failure` 是 reload 的错误通道。
#[derive(Debug, Clone, Copy, Default)]
pub struct RebuildOutcome {
    pub stats: RebuildStats,
    pub failure: Option<RebuildFailure>,
}

impl RebuildOutcome {
    /// 失败判据：显式 reason 或旧口径（全部被拒/真源不可读）。
    pub fn failed(&self) -> bool {
        self.failure.is_some() || self.stats.failed()
    }
}

/// 本地规则（**2.1.22：唯一真源 `state/rules.json`**；未启用统一事务时回落
/// `config.json` 同目录 `rules_local.json`，文件缺失再回落 `cfg["rules"]`）
/// → 规则，并统计被丢弃条数（F20）。
///
/// 回退口径与 `api.py:3316-3320` `_local_rules` / `rules_admin::current_rules` 一致；
/// 此前索引重建只读独立文件，文件缺失时会与 GET /api/rules 的规则集分叉
/// （列表有规则、索引里没有）。
///
/// **2.1.22**：改为调用 `rules_admin::local_rules_authoritative` —— 与
/// `rules_payload` 共用**同一个**读取入口（真源优先、镜像仅回落、不一致时 WARN），
/// 两个视角因此不可能分叉。
///
/// **2.1.23（DEF-222-01）**：返回值增加"真源读不懂"标志。判据是
/// `rules_admin::rule_source_unreadable_count()` 在**本次**调用前后的增量 ——
/// 不用绝对值，避免把历史一次损坏永久钉成"永远失败"。
fn local_rules_with_drops(state: &AppState) -> (Vec<Rule>, usize, bool) {
    // >>> 242B BEGIN P1-11-localcheck >>> //
    // **2.1.42-B（P1-11）**：unreadable 由**本次解析**直接给出（不再用全局
    // 计数器前后差 —— 并发重建/并行测试会把别的调用算到本次头上，误判失败）。
    let (raw, unreadable) = crate::rules_admin::local_rules_authoritative_checked(state);
    // <<< 242B END P1-11-localcheck <<< //
    if unreadable {
        tracing::error!(
            rules = raw.len(),
            "规则索引重建：**本地规则真源无法解析** ⇒ 本次重建判为失败（fail-closed，端点 500）"
        );
    }
    let mut out: Vec<Rule> = Vec::with_capacity(raw.len());
    let mut dropped = 0usize;
    for item in &raw {
        match normalize_rule_json(item).and_then(|m| rule_from_json(m, RuleSource::Local)) {
            Some(r) => out.push(r),
            None => {
                tracing::warn!("规则索引重建: 本地规则条目被丢弃(缺 match / 非法 ip): {item}");
                dropped += 1;
            }
        }
    }
    (out, dropped, unreadable)
}

/// 订阅明细 → 规则，并统计被丢弃条数（F20）。
///
/// **仅测试使用**：生产路径走 [`sub_rules_from_bytes_checked`]（从本次读入的字节解析，
/// 不物化 10 万条明细的 `Value` 树）。保留本函数以锁定「空 match / 非对象条目
/// 必须计入 dropped」的既有口径。
#[allow(dead_code)]
fn sub_rules_with_drops(subs: &[Value]) -> (Vec<Rule>, usize) {
    let mut out: Vec<Rule> = Vec::new();
    let mut dropped = 0usize;
    for sub in subs {
        let empty = Vec::new();
        let items = sub.get("rules").and_then(Value::as_array).unwrap_or(&empty);
        for item in items {
            match rule_json(sub, item).and_then(|m| rule_from_json(m, RuleSource::Sub)) {
                Some(r) => out.push(r),
                None => {
                    tracing::warn!("规则索引重建: 订阅规则条目被丢弃(空 match / 非法 ip): {item}");
                    dropped += 1;
                }
            }
        }
    }
    (out, dropped)
}

/// 「本地规则 + 所有订阅展开出的规则」合并后调用 `resolver.rebuild_rules(all)`。
///
/// 对齐 `resolver.py:3638-3647` `_rebuild_rule_index`：`rules = _load_local_rules() +
/// _load_sub_rules()`，**本地在前**（同域名本地规则占位优先，订阅不覆盖），订阅在后。
/// 本地规则来源与 `resolver._load_local_rules` 同口径（`config.json` 同目录
/// `rules_local.json` 独立文件），而非 `resolver.config().rules`——后者会被
/// `/api/rules/import` 回写、混入订阅展开后的规则，重复 rebuild 会不断放大规则集。
/// 返回值带 `dropped` 统计供失败判定（F20）。纯同步、不加锁，可被规则事务持锁调用。
/// 「本地规则 + 磁盘上的订阅规则」合并后调用 `resolver.rebuild_rules(all)`。
///
/// 对齐 `resolver.py:3638-3647` `_rebuild_rule_index`：`rules = _load_local_rules() +
/// _load_sub_rules()`，**本地在前**（同域名本地规则占位优先，订阅不覆盖），订阅在后。
/// 本地规则来源与 `resolver._load_local_rules` 同口径（`config.json` 同目录
/// `rules_local.json` 独立文件），而非 `resolver.config().rules`——后者会被
/// `/api/rules/import` 回写、混入订阅展开后的规则，重复 rebuild 会不断放大规则集。
///
/// P0（内存）：订阅侧直接由 [`sub_rules_from_bytes_checked`] **流式解析** 成 `Rule`，
/// 不再先把 10 万条明细物化成 `Vec<Value>`（旧实现单次重建额外 ~66MB 常驻峰值）。
/// 返回值带 `dropped` 统计供失败判定（F20）。纯同步、不加锁，可被规则事务持锁调用。
// >>> M-247 BEGIN source-fp >>> //
/// **2.1.49（AUD-13/AUD-15）**：一次读取到的规则来源字节快照。
///
/// `sub` 由调用方在进入重建路径时**只读一次**并传入；指纹与解析都消费这同一份
/// `Vec<u8>`，彻底消除“指纹读 A、解析读 B、复算又读回 A”的 TOCTOU。
#[derive(Debug)]
enum SourceRead {
    Missing,
    Body(Vec<u8>),
    Failed,
}

fn read_source(path: &Path) -> SourceRead {
    match std::fs::read(path) {
        Ok(b) => SourceRead::Body(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => SourceRead::Missing,
        Err(e) => {
            tracing::error!(path = %path.display(), error = %e, "规则来源读取失败");
            SourceRead::Failed
        }
    }
}

/// **2.1.49（AUD-13/AUD-15）**：一次重建的**全部规则来源字节快照**。
///
/// 为什么不是“先算指纹、解析时再读文件”：A→B→A 的原子替换会让旧实现把 B 的索引
/// 盖上 A 的章。现在所有来源在进入重建路径时各读一次，指纹与解析消费同一份
/// `Vec<u8>`，章与索引严格同源。
struct RuleSourceSnapshot {
    cfg: Value,
    auth: Option<PathBuf>,
    mirror: PathBuf,
    local: PathBuf,
    reads: HashMap<PathBuf, SourceRead>,
    sub: SourceRead,
}

impl RuleSourceSnapshot {
    fn read(&self, p: &Path) -> &SourceRead {
        self.reads.get(p).unwrap_or(&SourceRead::Missing)
    }
}

fn ensure_source_read(reads: &mut HashMap<PathBuf, SourceRead>, p: &Path) {
    if !reads.contains_key(p) {
        reads.insert(p.to_path_buf(), read_source(p));
    }
}

fn snapshot_rule_sources(state: &AppState, sub_path: &Path) -> RuleSourceSnapshot {
    let cfg = state.cfg.read().clone();
    let auth = crate::rules_admin::authoritative_rules_path(state);
    let mirror = crate::rules_admin::local_rules_path(&cfg, state.cfg_path.as_deref());
    let local = crate::rules_admin::local_rules_path(&cfg, state.cfg_path.as_deref());
    let mut reads = HashMap::new();
    if let Some(p) = auth.as_deref() {
        ensure_source_read(&mut reads, p);
    }
    if auth.as_deref() != Some(mirror.as_path()) {
        ensure_source_read(&mut reads, &mirror);
    }
    ensure_source_read(&mut reads, &local);
    let sub = read_source(sub_path);
    RuleSourceSnapshot {
        cfg,
        auth,
        mirror,
        local,
        reads,
        sub,
    }
}

fn eat_source(h: &mut Sha256, tag: &[u8], read: &SourceRead) {
    fn body(h: &mut Sha256, tag: &[u8], body: Option<&[u8]>) {
        h.update(tag);
        h.update([0xFE]);
        match body {
            Some(b) => {
                h.update([0x01]);
                h.update((b.len() as u64).to_le_bytes());
                h.update(b);
            }
            None => {
                h.update([0x00]);
                h.update(u64::MAX.to_le_bytes());
            }
        }
    }
    match read {
        SourceRead::Body(b) => body(h, tag, Some(b)),
        SourceRead::Missing => body(h, tag, None),
        SourceRead::Failed => body(h, tag, Some(&[0xFFu8][..])), // 调用方先判 Failed
    }
}

/// **2.1.47 / M-247 / 2.1.49（AUD-13/AUD-15）**：规则**来源字节**指纹
/// （SHA-256 前 128 位，确定性、顺序敏感）。全部输入来自 [`RuleSourceSnapshot`]。
fn rule_sources_fingerprint_snapshot(snap: &RuleSourceSnapshot) -> u128 {
    if matches!(snap.sub, SourceRead::Failed) {
        return 0;
    }
    let mut h = Sha256::new();
    if let Some(p) = snap.auth.as_deref() {
        match snap.read(p) {
            SourceRead::Failed => return 0,
            r => eat_source(&mut h, b"auth", r),
        }
    }
    if snap.auth.as_deref() != Some(snap.mirror.as_path()) {
        match snap.read(&snap.mirror) {
            SourceRead::Failed => return 0,
            r => eat_source(&mut h, b"mirror", r),
        }
    }
    let cfg_rules = snap.cfg.get("rules").cloned().unwrap_or(Value::Null);
    let cfg_bytes = serde_json::to_vec(&cfg_rules).unwrap_or_default();
    eat_source(&mut h, b"cfg-rules", &SourceRead::Body(cfg_bytes));
    // **2.1.48 / AUD-03**：订阅**清单**（URL 列表）也是来源的一部分 —— 否则
    // `PUT /api/config` 删除订阅后来源指纹不变，reload 的 fast-path 会复用旧索引。
    let sub_urls: Vec<String> = snap
        .cfg
        .get("rule_subscriptions")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(|m| as_str(m, "url")).collect())
        .unwrap_or_default();
    eat_source(
        &mut h,
        b"sub-urls",
        &SourceRead::Body(sub_urls.join("\n").into_bytes()),
    );
    eat_source(&mut h, b"subs", &snap.sub);
    let digest = h.finalize();
    let v = u128::from_be_bytes(digest[..16].try_into().expect("sha256 32 bytes"));
    if v == 0 {
        1
    } else {
        v
    }
}

/// 测试/诊断用：注入任意订阅字节（其余来源按当前状态快照）。
#[cfg(test)]
fn rule_sources_fingerprint_from(
    state: &AppState,
    sub_body: Option<&[u8]>,
    sub_readable: bool,
) -> u128 {
    let mut snap = snapshot_rule_sources(state, Path::new("__m249_injected_sub__"));
    snap.sub = if !sub_readable {
        SourceRead::Failed
    } else {
        match sub_body {
            Some(b) => SourceRead::Body(b.to_vec()),
            None => SourceRead::Missing,
        }
    };
    rule_sources_fingerprint_snapshot(&snap)
}

enum LocalRead {
    Parsed(Vec<Value>),
    Missing,
    Unreadable,
}

fn parse_local_snapshot(path: &Path, read: &SourceRead) -> LocalRead {
    match read {
        SourceRead::Body(b) => match crate::rules_admin::parse_rules_bytes_ex(b, path, true) {
            crate::rules_admin::RulesParse::Parsed(v) => LocalRead::Parsed(v),
            crate::rules_admin::RulesParse::Missing => LocalRead::Missing,
            crate::rules_admin::RulesParse::Unreadable { .. } => LocalRead::Unreadable,
        },
        SourceRead::Missing => LocalRead::Missing,
        SourceRead::Failed => LocalRead::Unreadable,
    }
}

/// 从**同一份快照**解析本地规则（真源优先、镜像回落、`cfg.rules` 最后兜底）。
/// 语义与 `rules_admin::local_rules_authoritative_checked` 一致，只是不再二次读盘。
fn local_rules_from_snapshot(
    snap: &RuleSourceSnapshot,
    state_on: bool,
) -> (Vec<Rule>, usize, bool) {
    let cfg_rules = || {
        snap.cfg
            .get("rules")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let mut unreadable = false;
    let raw: Vec<Value> = if state_on {
        let mut got: Option<Vec<Value>> = None;
        if let Some(p) = snap.auth.as_deref() {
            match parse_local_snapshot(p, snap.read(p)) {
                LocalRead::Parsed(v) => got = Some(v),
                LocalRead::Unreadable => unreadable = true,
                LocalRead::Missing => {}
            }
        }
        if !unreadable && got.is_none() {
            match parse_local_snapshot(&snap.mirror, snap.read(&snap.mirror)) {
                LocalRead::Parsed(v) => got = Some(v),
                LocalRead::Unreadable => unreadable = true,
                LocalRead::Missing => {}
            }
        }
        if unreadable {
            Vec::new()
        } else {
            got.unwrap_or_else(cfg_rules)
        }
    } else {
        // 2.1.21 遗留路径：独立文件优先；缺失/读不懂 ⇒ `cfg.rules`（不 fail-closed）。
        match parse_local_snapshot(&snap.local, snap.read(&snap.local)) {
            LocalRead::Parsed(v) => v,
            LocalRead::Missing | LocalRead::Unreadable => cfg_rules(),
        }
    };
    let normalized = crate::rules_admin::normalize_rules(raw);
    let mut out: Vec<Rule> = Vec::with_capacity(normalized.len());
    let mut dropped = 0usize;
    for item in normalized {
        let v = Value::Object(item);
        match normalize_rule_json(&v).and_then(|m| rule_from_json(m, RuleSource::Local)) {
            Some(r) => out.push(r),
            None => {
                tracing::warn!("规则索引重建: 本地规则条目被丢弃(缺 match / 非法 ip): {v}");
                dropped += 1;
            }
        }
    }
    (out, dropped, unreadable)
}

// <<< M-247 END source-fp <<< //

// >>> 242B BEGIN P1-11-rebuild >>> //
fn rebuild_all_disk_path(state: &AppState, sub_path: &Path) -> RebuildOutcome {
    // >>> M-247 BEGIN fast-path >>> //
    // **2.1.47 / M-247（P0）**：规则**来源字节**未变化 ⇒ **直接复用现有索引**。
    //
    // 缺陷：旧实现每次 `POST /api/reload` / 每小时订阅刷新都会把 3.4 MB 的
    // `rules_sub.json` 重新解析成 10 万条 `Rule` 并重建 6 张 HashMap（瞬时 ~20 MB）。
    // 旧索引确实被 drop 了，但 glibc 在每个线程一个 arena 的布局下无法把这些
    // 碎片页归还内核（实测 8 核 24+ 个 64 MB arena、VmData 1.5 GB、每次重载
    // VmRSS +4~10 MB 且不回落到基线）——24h soak 142 -> 439 MB 即由此累积。
    //
    // 语义：来源字节逐字节相同 ⇒ 解析结果（`Vec<Rule>`）与索引逐字节相同 ⇒
    // `rule_gen`（内容指纹）不变。因此"跳过重建"对规则生效时延、命中行为、
    // 管理面统计**零影响**；真正的内容变更仍走下面的完整重建。
    // **2.1.49（AUD-15）**：所有来源各只读一次；指纹与解析都用同一份快照。
    // 旧实现 `src_fp` 先读文件、解析时再读、成功后第三次读文件复算 —— A→B→A
    // 时会把 B 的索引盖上 A 的章；现在章永远对应本次解析的那份字节。
    let snap = snapshot_rule_sources(state, sub_path);
    let src_fp = rule_sources_fingerprint_snapshot(&snap);
    if let Some((indexed, rejected, dropped)) = state.resolver.rule_source_last_build(src_fp) {
        tracing::debug!(
            fp = src_fp,
            indexed,
            "规则来源字节未变化 → 复用现有索引（跳过解析/重建）"
        );
        // 仍归还一次空闲页：上一次真实重建/提交可能刚在此之前完成。
        state.resolver.trim_allocator();
        return RebuildOutcome {
            stats: RebuildStats {
                indexed,
                rejected,
                dropped,
                source_unreadable: false,
            },
            failure: None,
        };
    }
    // <<< M-247 END fast-path <<< //
    // **2.1.42-B（P1-11）**：先校验、后替换索引。
    // 旧顺序是 `local(...) + sub(...)` 后**无条件** `rebuild_rules`：真源坏掉时
    // 先把索引替换成"空/仅订阅"，之后才因为 `source_unreadable` 返回 500 ——
    // 数据面已经 fail-open（屏蔽规则静默消失）。现在任一来源 unreadable ⇒
    // **保留旧索引快照**（不调用 rebuild），只回报失败让端点 5xx/日志告警。
    let (mut all, mut dropped, local_unreadable) =
        local_rules_from_snapshot(&snap, state.state.is_on());
    // **2.1.48 / AUD-03**：订阅清单以 `config.rule_subscriptions` 为准（键**缺失** ⇒
    // 兼容旧布局不过滤；键存在但为空 ⇒ 全部过滤，即"删光订阅"）。
    let allowed_subs: Option<HashSet<String>> = state
        .cfg
        .read()
        .get("rule_subscriptions")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|m| as_str(m, "url"))
                .filter(|u| !u.is_empty())
                .collect()
        });
    let (sub_rules, sub_dropped, sub_failure) = match &snap.sub {
        SourceRead::Body(b) => sub_rules_from_bytes_checked(b, sub_path, allowed_subs.as_ref()),
        SourceRead::Missing => (Vec::new(), 0, None),
        SourceRead::Failed => (Vec::new(), 0, Some(RebuildFailure::RulesSubUnreadable)),
    };
    dropped += sub_dropped;
    if local_unreadable {
        tracing::error!(
            dropped,
            "本地规则真源不可读 ⇒ **本次不替换索引**（保留旧规则快照），端点返回 5xx"
        );
        return RebuildOutcome {
            stats: RebuildStats {
                indexed: 0,
                rejected: 0,
                dropped,
                source_unreadable: true,
            },
            failure: Some(RebuildFailure::RulesLocalUnreadable),
        };
    }
    if let Some(failure) = sub_failure {
        tracing::error!(
            code = failure.code(),
            dropped,
            "订阅规则真源非法 ⇒ **本次不替换索引**（保留旧规则快照），端点返回 5xx"
        );
        return RebuildOutcome {
            stats: RebuildStats {
                indexed: 0,
                rejected: 0,
                dropped,
                source_unreadable: true,
            },
            failure: Some(failure),
        };
    }
    all.extend(sub_rules);
    // **2.1.49（P0）**：先构建候选索引，**只有"至少一条进索引"才发布** ——
    // 全部规则被拒/丢弃时旧索引原样保留（2.1.48 会先替换成空索引再报 500）。
    match state.resolver.try_rebuild_rules(all, dropped) {
        Ok(report) => {
            // **2.1.49（AUD-15）**：指纹已经是对**本次实际解析字节**计算的，绝不再
            // 重读文件。成功即盖章：索引与章严格同源（A→B→A 也不会错位）。
            state.resolver.note_rule_source_build(
                src_fp,
                report.stats.indexed,
                report.stats.rejected,
                dropped,
            );
            RebuildOutcome {
                stats: RebuildStats {
                    indexed: report.stats.indexed,
                    rejected: report.stats.rejected,
                    dropped,
                    source_unreadable: false,
                },
                failure: None,
            }
        }
        Err(build_stats) => RebuildOutcome {
            stats: RebuildStats {
                indexed: 0,
                rejected: build_stats.rejected,
                dropped,
                source_unreadable: false,
            },
            failure: Some(RebuildFailure::AllRulesRejected),
        },
    }
}
// <<< 242B END P1-11-rebuild <<< //

/// 订阅明细文件路径（`state.cfg` 短临界区；无 cfg_path → `None`）。
fn subs_file_of(state: &AppState) -> Option<PathBuf> {
    state
        .cfg_path
        .as_deref()
        .map(|p| subs_path(&state.cfg.read(), Some(p)))
}

/// 从磁盘上的 `rules_sub.json` 重读订阅明细，再与本地规则合并重建索引（带统计）。
///
/// 这是**唯一**的权威重建入口：`rules_admin` 的规则 CRUD、订阅 CRUD 与启动装配都调用它，
/// 保证「本地规则 + 订阅规则」始终一起进索引（否则任一侧变更都会把另一侧摘掉）。
/// 明细**只以磁盘为权威**，内存里不保留 10 万条订阅明细。
/// **不加锁**：调用方可能已持有 `rules_admin::rules_txn`（锁序第 3 条）。
pub fn rebuild_all_disk_stats(state: &AppState) -> RebuildStats {
    rebuild_all_disk_checked(state).stats
}

/// **2.1.49（P0）**：带失败原因的重建入口（`on_reload` / reload 端点用）。
///
/// 与 [`rebuild_all_disk_stats`] 的唯一区别是**保留失败原因**：reload 端点据此返回
/// `{"ok":false,"error":"<code>","detail":"..."}` 而不是 200 静默成功。
/// 失败时旧索引**不被替换**（`rebuild_all_disk_path` 与 `Resolver::try_rebuild_rules`）。
pub fn rebuild_all_disk_checked(state: &AppState) -> RebuildOutcome {
    match subs_file_of(state) {
        Some(path) => rebuild_all_disk_path(state, &path),
        None => {
            // 无 cfg_path（纯内存测试态）：只有本地规则。
            // >>> 242B BEGIN P1-11-nocfg >>> //
            let (all, dropped, source_unreadable) = local_rules_with_drops(state);
            if source_unreadable {
                // **2.1.42-B（P1-11）**：同上，校验失败不替换索引。
                return RebuildOutcome {
                    stats: RebuildStats {
                        indexed: 0,
                        rejected: 0,
                        dropped,
                        source_unreadable: true,
                    },
                    failure: Some(RebuildFailure::RulesLocalUnreadable),
                };
            }
            // <<< 242B END P1-11-nocfg <<< //
            match state.resolver.try_rebuild_rules(all, dropped) {
                Ok(report) => RebuildOutcome {
                    stats: RebuildStats {
                        indexed: report.stats.indexed,
                        rejected: report.stats.rejected,
                        dropped,
                        source_unreadable,
                    },
                    failure: None,
                },
                Err(build_stats) => RebuildOutcome {
                    stats: RebuildStats {
                        indexed: 0,
                        rejected: build_stats.rejected,
                        dropped,
                        source_unreadable: false,
                    },
                    failure: Some(RebuildFailure::AllRulesRejected),
                },
            }
        }
    }
}

/// 见 [`rebuild_all_disk_stats`]；`main.rs` 启动装配用（无返回值，失败仅告警）。
pub fn rebuild_all_disk(state: &AppState) {
    let stats = rebuild_all_disk_stats(state);
    if stats.failed() {
        tracing::error!(
            indexed = stats.indexed,
            rejected = stats.rejected,
            dropped = stats.dropped,
            source_unreadable = stats.source_unreadable,
            "规则索引重建失败(全部规则被拒或被丢弃 / 真源无法解析, 详情见服务端日志)"
        );
    }
}

/// 端点用失败判定（F20）：`indexed == 0 && rejected + dropped > 0` → 500
/// 「规则索引重建失败」（对齐 `api.py:3200/3569/3625`）。
///
/// **[历史归因]** 文案走 ERROR 日志：`ServerError::Internal` 不带文案，见文件头「与 Python 的有意差异 2」。
fn check_rebuild(stats: RebuildStats) -> Result<(), ServerError> {
    if stats.failed() {
        tracing::error!(
            indexed = stats.indexed,
            rejected = stats.rejected,
            dropped = stats.dropped,
            "规则索引重建失败(详情见服务端日志)"
        );
        return Err(ServerError::Internal);
    }
    Ok(())
}

/// **2.1.22**：一次订阅/规则提交涉及的**全部持久化 part**（唯一构造点）。
///
/// 顺序与内容都是规范：
/// 1. `config.json`（**去掉 `rules` 镜像键**）—— 订阅元信息 `rule_subscriptions` 在其中；
/// 2. 规则真源 `state/rules.json` + 各镜像路径 —— 与 `rules_admin::rules_plan` 同源，
///    保证"订阅改了 `config.json` 却把规则真源写回旧内容"这种事**不可能**发生。
///
/// `rules_body` 为空 ⇒ 本次只提交 `config.json`。
fn state_plan(
    state: &AppState,
    cfg: &Value,
    rules_body: Option<&[u8]>,
) -> Option<std::collections::BTreeMap<PathBuf, Vec<u8>>> {
    let store = state.state.store()?;
    let _ = store;
    let mut plan = std::collections::BTreeMap::new();
    if let Some(cp) = state.cfg_path.clone() {
        plan.insert(
            cp,
            crate::state_store::StateStore::json_bytes(
                &crate::rules_admin::cfg_without_rules_mirror(cfg),
            ),
        );
    }
    if let Some(rb) = rules_body {
        if let Some(auth) = crate::rules_admin::authoritative_rules_path(state) {
            plan.insert(auth.clone(), rb.to_vec());
            for m in crate::rules_admin::mirror_rules_paths(cfg, state.cfg_path.as_deref(), &auth) {
                plan.insert(m, rb.to_vec());
            }
        }
    }
    Some(plan)
}

/// 把 `cfg["rule_subscriptions"]` 的元信息落盘（**经统一事务**，或旧路径兜底）。
///
/// 缺失此步会导致：①重启后 `config_urls` 为空 → `update_once` 直接 return →
/// `rules_sub.json` 永不加载（订阅彻底失效且控制台不可见）；②`update_once` 的
/// `retain` 会把「文件里有、config 里没有」的订阅当作已删除而从盘上剔除；
/// **[历史归因]** ③`delete` 后重启时旧元信息使订阅"复活"。Python 侧三个端点都调 `save_config`。
fn persist_cfg(state: &AppState, cfg: &Value) -> Result<(), ServerError> {
    let Some(p) = state.cfg_path.as_deref() else {
        return Ok(());
    };
    if let Some(store) = state.state.store() {
        // `rules_body = None`：本函数只负责元信息，规则真源由调用方（规则/订阅事务）
        // 一并纳入**同一个** plan；单独调用时不动规则文件（避免"顺手写回旧规则"）。
        let plan = state_plan(state, cfg, None).unwrap_or_default();
        if !plan.is_empty() {
            crate::state_store::commit_droppable(store, "subscribe:meta", &plan)
                .map_err(crate::rules_admin::commit_err_to_server)?;
            // 同步"上次已生效"快照，避免 /api/reload 把订阅变更误报为 changed。
            *state.applied.write() = cfg.clone();
            return Ok(());
        }
    }
    let body = match serde_json::to_vec_pretty(cfg) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("订阅元信息序列化失败: {e}");
            return Err(ServerError::Internal);
        }
    };
    atomic_write(p, &body).map_err(|e| {
        tracing::error!("订阅元信息写盘失败 {}: {e}", p.display());
        ServerError::Internal
    })?;
    // 同步"上次已生效"快照，避免 /api/reload 把订阅变更误报为 changed。
    *state.applied.write() = cfg.clone();
    Ok(())
}

/* ---------------- 请求参数校验 ---------------- */

/// body 的 `url`：非字符串 / 缺失 → 400 `url must be a string`；非 https → 400。
fn parse_url(body: &Value) -> Result<String, ServerError> {
    let Some(url) = body.get("url").and_then(Value::as_str) else {
        return Err(ServerError::BadRequest("url must be a string".into()));
    };
    let url = url.trim();
    if !url.to_ascii_lowercase().starts_with("https://") {
        return Err(ServerError::BadRequest(
            "仅支持 https:// 订阅链接(http:// 不安全, 已禁止)".into(),
        ));
    }
    Ok(url.to_string())
}

/// `{action, group, ip}` 缺省兜底 + 最小 `_validate_rule_dict` 等价校验。
/// 对齐 `api.py:3459-3467`：action 枚举 allow/block/group/forceIp；
/// `group` 必须是非空字符串；`forceIp` 必须带合法 IP。
fn parse_opts(body: &Value) -> Result<(String, String, String), ServerError> {
    let action = match body.get("action") {
        None | Some(Value::Null) => "block".to_string(),
        Some(Value::String(s)) => {
            let s = s.trim();
            if s.is_empty() {
                "block".to_string()
            } else {
                s.to_string()
            }
        }
        Some(_) => return Err(ServerError::BadRequest("invalid action".into())),
    };
    if !matches!(action.as_str(), "allow" | "block" | "group" | "forceIp") {
        return Err(ServerError::BadRequest("invalid action".into()));
    }
    let group = match body.get("group") {
        None | Some(Value::Null) => "global".to_string(),
        Some(Value::String(s)) => {
            let s = s.trim();
            if s.is_empty() {
                "global".to_string()
            } else {
                s.to_string()
            }
        }
        Some(_) => return Err(ServerError::BadRequest("invalid group".into())),
    };
    let ip = match body.get("ip") {
        None | Some(Value::Null) => "1.2.3.4".to_string(),
        Some(Value::String(s)) => {
            let s = s.trim();
            if s.is_empty() {
                "1.2.3.4".to_string()
            } else {
                s.to_string()
            }
        }
        Some(_) => return Err(ServerError::BadRequest("invalid forceIp ip address".into())),
    };
    if action == "forceIp" && ip.parse::<IpAddr>().is_err() {
        return Err(ServerError::BadRequest("invalid forceIp ip address".into()));
    }
    Ok((action, group, ip))
}

/// 「订阅不存在」：404 + 文案 `订阅不存在: <url>`。
///
/// 走 `ServerError::NotFoundWith`（`error.rs:23-25`，渲染 404 + 自定义文案），
/// **[历史归因]** 对齐 Python `_api_subscribe_update`(3518) / `_api_subscribe_delete`(3590)。
fn not_found_sub(url: &str) -> ServerError {
    ServerError::NotFoundWith(format!("订阅不存在: {url}"))
}

/* ---------------- 网络下载（信号量 + spawn_blocking） ---------------- */

/// 信号量内拉取（并发 ≤ 4），阻塞 HTTP 放 `spawn_blocking`。
async fn fetch_guarded(url: &str) -> Result<String, String> {
    let _permit = subscribe_sem()
        .acquire()
        .await
        .map_err(|_| "订阅下载失败".to_string())?;
    let url_owned = url.to_string();
    tokio::task::spawn_blocking(move || fetch_subscription_text(&url_owned))
        .await
        .map_err(|_| "订阅下载失败".to_string())?
}

// >>> M-247b BEGIN sub-digest >>> //
/// **2.1.47 / M-247**：订阅**内容摘要**（URL -> FNV-1a 64），仅进程内。
///
/// 24h soak 的 RSS 阶梯里，订阅每小时刷新占大头：即使 anti-ad 列表内容完全没变，
/// 旧实现也会把 10 万条明细 `load_subs` 成 `Vec<Value>`（~40 MB）→ 重写 3.4 MB
/// `rules_sub.json` → 全量重建规则索引（~20 MB 瞬时）。这里在**解析之前**先对
/// 下载到的原文做摘要：相同则直接返回（不解析、不落盘、不重建），
/// 把"内容没变的刷新"降到只剩一次 HTTP 下载 + 2 MB 级缓冲。
/// 摘要只存内存：进程重启后第一次刷新会老实重建一次（与旧版行为一致），
/// 之后直到内容真变都不再产生重建 churn。
fn sub_digest_text(text: &str) -> u128 {
    // **2.1.49（AUD-13）**：SHA-256 前 128 位（外部订阅内容，FNV-1a 64 可构造碰撞）。
    let mut h = Sha256::new();
    h.update(text.trim().as_bytes());
    let digest = h.finalize();
    let v = u128::from_be_bytes(digest[..16].try_into().expect("sha256 32 bytes"));
    if v == 0 {
        1
    } else {
        v
    }
}

fn sub_digest_map() -> &'static std::sync::Mutex<HashMap<String, u128>> {
    static M: OnceLock<std::sync::Mutex<HashMap<String, u128>>> = OnceLock::new();
    M.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

fn sub_digest_get(url: &str) -> Option<u128> {
    sub_digest_map()
        .lock()
        .ok()
        .and_then(|m| m.get(url).copied())
}

fn sub_digest_set(url: &str, d: u128) {
    if let Ok(mut m) = sub_digest_map().lock() {
        m.insert(url.to_string(), d);
    }
}

/// **2.1.48 / AUD-05 + AUD-14**：删除订阅时同步清掉摘要，并让摘要表跟随当前配置收敛。
fn sub_digest_remove(url: &str) {
    if let Ok(mut m) = sub_digest_map().lock() {
        m.remove(url);
    }
}

fn sub_digest_retain(urls: &HashSet<String>) {
    if let Ok(mut m) = sub_digest_map().lock() {
        m.retain(|k, _| urls.contains(k));
    }
}
// <<< M-247b END sub-digest <<< //

/// 解析 + 展开规则项；空 → `Err("订阅内容未解析到有效域名")`。
fn items_from_text(text: &str) -> Result<Vec<Value>, ServerError> {
    let domains = parse_domain_list(text);
    let items = domains_to_rules(&domains);
    if items.is_empty() {
        return Err(ServerError::BadRequest("订阅内容未解析到有效域名".into()));
    }
    Ok(items)
}

/// 当前订阅明细文件路径。
fn current_path(state: &AppState) -> PathBuf {
    let cfg = state.cfg.read();
    subs_path(&cfg, state.cfg_path.as_deref())
}

/// 写 `rules_sub.json`（阻塞 IO 出 async 线程）。**未启用统一事务时的兜底路径**
/// （周期自动更新任务）；启用后由 [`commit_sub_txn`] / [`update_once`] 经
/// `state_store::commit_droppable` 提交。
#[allow(dead_code)]
async fn write_subs(path: &Path, subs: Arc<Vec<Value>>) -> std::io::Result<()> {
    let path_owned = path.to_path_buf();
    tokio::task::spawn_blocking(move || save_subs(&path_owned, &subs))
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?
}

/* ---------------- 读改写事务（F07 / F19） ---------------- */

/// 事务回滚载荷。
///
/// P0（内存）：回滚只需要「能还原旧文件」的最小信息，不必为每次写操作都留一份
/// 10 万条明细的完整旧快照（旧实现 subscribe/update/delete 各留一份 → 峰值 3~4 份
/// 明细树，实测单份 ~66MB，VmPeak ≈ 996MB）。
/// 三种情形分别只留：截断长度（首订阅追加）/ 被覆盖的那一条旧值 / 被删的那些条目。
/// 拼接还原**只在失败路径**发生（罕见），代价可接受。
enum SubRollback {
    /// 旧文件 = 新明细的前 `0..n` 条（只追加了尾部条目）→ 回滚只截断。
    Truncate(usize),
    /// 新明细 = 旧明细把第 `idx` 条替换掉 → 回滚换回旧值。
    Replaced { idx: usize, old: Value },
    /// 新明细 = 旧明细删掉若干条目 → 回滚并回被删条目。
    Removed(Vec<Value>),
}

impl SubRollback {
    /// 失败路径：由「新明细 + 回滚载荷」还原旧文件内容。
    fn restore(&self, new_subs: &[Value]) -> Vec<Value> {
        match self {
            SubRollback::Truncate(n) => new_subs[..(*n).min(new_subs.len())].to_vec(),
            SubRollback::Replaced { idx, old } => {
                let mut v = new_subs.to_vec();
                if let Some(slot) = v.get_mut(*idx) {
                    *slot = old.clone();
                }
                v
            }
            SubRollback::Removed(removed) => {
                let mut v = new_subs.to_vec();
                v.extend(removed.iter().cloned());
                v
            }
        }
    }
}

/// 一次订阅读改写事务：明细新值 + 回滚载荷 + 元信息的「旧值 + 新值」快照。
///
/// 在 `sub_txn()` 锁内构造，交给 [`commit_sub_txn`] 按序提交：
/// ① `rules_sub.json` 落盘 → ② 内存元信息 + `config.json` 落盘 → ③ 重建索引。
/// **[历史归因]** 步骤①失败时**内存与磁盘都未变更**（不需要回滚，比 Python 的「先改内存再回滚」更强）；
/// 步骤②失败时把内存元信息与 `rules_sub.json` 一起回滚到旧值（对齐 `api.py:3172-3187`）。
struct SubTxn {
    path: PathBuf,
    /// 新明细。用 `Arc` 持有：`spawn_blocking` 落盘只需克隆 Arc（O(1)），
    /// 不必为「把数据搬进阻塞线程」再深拷贝一份 10 万条明细。
    new_subs: Arc<Vec<Value>>,
    rollback: SubRollback,
    old_meta: Vec<Value>,
    new_meta: Vec<Value>,
}

/// 给订阅/元信息条目设置字段：非对象条目就地升级为对象，绝不 panic
/// （手工编辑过的 `rules_sub.json` 可能含非对象条目，旧实现 `s["k"] = v` 会 panic）。
fn set_field(v: &mut Value, k: &str, val: Value) {
    if !v.is_object() {
        *v = Value::Object(Map::new());
    }
    if let Some(o) = v.as_object_mut() {
        o.insert(k.to_string(), val);
    }
}

/// `cfg["rule_subscriptions"]` 元信息数组（拷贝；缺失 / 非数组 → 空）。
/// **2.1.48 / AUD-08**：内容未变时刷新 `last_checked_at`（只写 config 元信息）。
///
/// 不能改 `updated_at`：它表达“内容最后变化时间”，且 `rules_sub.json` 的字节也是来源
/// 指纹的一部分（改写会触发全量重建）。新增 `last_checked_at` 让 UI 能区分
/// “已检查但内容没变”与“更新器卡死”；不参与任何指纹/规则语义。
fn touch_last_checked(state: &AppState, url: &str) -> Result<(), ServerError> {
    let mut cfg = state.cfg.read().clone();
    let now = ts_now();
    let mut hit = false;
    if let Some(a) = cfg
        .get_mut("rule_subscriptions")
        .and_then(Value::as_array_mut)
    {
        for m in a.iter_mut() {
            if as_str(m, "url") == url {
                set_field(m, "last_checked_at", json!(&now));
                hit = true;
            }
        }
    }
    if hit {
        persist_cfg(state, &cfg)?;
        // **2.1.48 / AUD-08**：persist_cfg 只写盘，必须同步内存快照 —— 否则后续
        // `subscribe`/`update_once` 用旧 cfg 组 meta 时会把 `last_checked_at` 覆盖掉。
        *state.cfg.write() = cfg;
        // **2.1.48 / serving_revision**：config-only 提交且索引未变 ⇒ 已是新世代。
        state.state.mark_serving();
    }
    Ok(())
}

fn cfg_meta(state: &AppState) -> Vec<Value> {
    state
        .cfg
        .read()
        .get("rule_subscriptions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// 把订阅元信息写进 live cfg 的 `rule_subscriptions`（`parking_lot` 短临界区，无 await）。
///
/// `Value` 的 `IndexMut` 在 cfg 不是对象时会 panic，故先做对象化兜底
/// （生产路径不得 `unwrap()/panic!`；`state.cfg` 正常必为对象）。
fn set_cfg_meta(state: &AppState, meta: &[Value]) {
    let mut cfg = state.cfg.write();
    if !cfg.is_object() {
        *cfg = Value::Object(Map::new());
    }
    cfg["rule_subscriptions"] = Value::Array(meta.to_vec());
}

/// 提交订阅读改写事务（调用方必须持有 [`sub_txn`] 锁）。
///
/// **[历史归因]** F19：写盘失败一律返回 `ServerError::Internal`（500，对齐 Python `保存订阅文件失败`）；
/// `ServerError` 无「500 + 文案」变体且不允许改 `error.rs`，文案进 ERROR 日志。
async fn commit_sub_txn(state: &AppState, txn: &SubTxn) -> Result<(), ServerError> {
    // ---- 2.1.22：统一事务路径（`state/` 已启用）----
    //
    // `rules_sub.json` 与 `config.json`（订阅元信息）在**同一个世代**里提交 ⇒
    // 两者的"读改写"要么一起生效、要么一起不生效 —— 2.1.21 需要 `SubRollback`
    // 事后补救的那个窗口（明细已落盘、元信息写失败）在这里**不存在**。
    if let Some(store) = state.state.store() {
        let sub_body = subs_bytes(&txn.new_subs).map_err(|e| {
            tracing::error!("订阅明细序列化失败: {e}");
            ServerError::Internal
        })?;
        // 先算"元信息进内存后的 cfg 快照"，但**先不改内存**（失败即无副作用）。
        let mut snapshot = state.cfg.read().clone();
        if !snapshot.is_object() {
            snapshot = Value::Object(Map::new());
        }
        snapshot["rule_subscriptions"] = Value::Array(txn.new_meta.clone());
        // 规则真源：以**当前磁盘上的**真源为基准原样带入同一世代（内容不变），
        // 这样本世代与上一世代的 rules 摘要一致，`load()` 不会把它判成"变了一半"。
        // 读盘走 `spawn_blocking`（可能是几百 KB 的文件，不占 async 线程）。
        let rules_path = crate::rules_admin::authoritative_rules_path(state);
        let rules_body = match rules_path {
            Some(p) => tokio::task::spawn_blocking(move || std::fs::read(p))
                .await
                .ok()
                .and_then(|r| r.ok()),
            None => None,
        };
        let mut plan = state_plan(state, &snapshot, rules_body.as_deref()).unwrap_or_default();
        plan.insert(txn.path.clone(), sub_body);
        if !plan.is_empty() {
            // **2.1.47 / M-247**：`plan` 含 `rules_sub.json` 全量字节（生产 3.4 MB），
            // 旧实现 `plan.clone()` 每次提交多复制一份；这里直接 move 进阻塞任务。
            let r = tokio::task::spawn_blocking({
                let store = std::sync::Arc::clone(store);
                move || crate::state_store::commit_droppable(&store, "subscribe", &plan)
            })
            .await
            .map_err(|e| {
                tracing::error!("订阅提交任务失败（join error）: {e}");
                ServerError::Internal
            })?;
            match r {
                Ok(_) => {
                    set_cfg_meta(state, &txn.new_meta);
                    *state.applied.write() = state.cfg.read().clone();
                    return Ok(());
                }
                Err(e) => {
                    // 内存与磁盘**都未变更**（提交点没动）⇒ 上一代完好，无需回滚。
                    let se = crate::rules_admin::commit_err_to_server(e);
                    tracing::error!(
                        "订阅持久化提交中止（内存与磁盘均未变更，上一代完好）: {}",
                        txn.path.display()
                    );
                    return Err(se);
                }
            }
        }
    }
    // ---- 旧路径（未启用统一事务）：逐位保留 2.1.21 的两步写 + 回滚 ----
    // ① 明细落盘（阻塞 IO 出 async 线程）。失败 → 内存未改、磁盘未改，无需回滚。
    if let Err(e) = write_subs(&txn.path, Arc::clone(&txn.new_subs)).await {
        tracing::error!(
            "保存订阅文件失败 {}: {e}(内存与磁盘均未变更)",
            txn.path.display()
        );
        return Err(ServerError::Internal);
    }
    // ② 元信息进内存（短临界区，无 await）+ 原子落盘 config.json（live 快照）。
    // **[历史归因]** F02：订阅元信息必须落盘 config.json（Python 三个端点都调 save_config）。
    // 否则重启后 config 里没有该订阅 → update_once 直接 return → rules_sub.json
    // 永不加载（订阅彻底失效且控制台不可见），且 retain 会把明细从盘上剔除。
    set_cfg_meta(state, &txn.new_meta);
    let snapshot = state.cfg.read().clone();
    if let Err(e) = persist_cfg(state, &snapshot) {
        // 回滚：内存元信息 → 旧值；`rules_sub.json` → 旧明细（尽力，失败仅 ERROR）。
        // 回滚是**错误路径**（罕见），此时才做「新明细 + 回滚载荷」的拼接拷贝。
        set_cfg_meta(state, &txn.old_meta);
        let restore = txn.rollback.restore(&txn.new_subs);
        if let Err(e2) = write_subs(&txn.path, Arc::new(restore)).await {
            tracing::error!(
                "回滚 rules_sub.json 写盘失败(明细/元信息可能错位) {}: {e2}",
                txn.path.display()
            );
        }
        return Err(e);
    }
    Ok(())
}

/* ---------------- HTTP 端点 ---------------- */

/// POST /api/rules/subscribe
///
/// 对齐 `_api_subscribe_rules`(3444-3469) → `_do_subscribe_download`(3081-3201)。
/// 成功：`{"ok":true,"url":url,"count":N,"added":0|1}`（`added=1` 表示新建订阅条目）。
/// 网络下载在锁外；「读明细 → 改 → 写回 → 元信息落盘 → 重建索引」整段持 [`sub_txn`]
/// （与规则 CRUD 共用锁，F07）；写盘失败 → 内存与磁盘一起回到旧值，返回 500。
pub async fn subscribe(state: AppState, body: Value) -> Result<Value, ServerError> {
    let url = parse_url(&body)?;
    let (action, group, ip) = parse_opts(&body)?;
    // 下载在锁外（最长 20s 不持锁，锁序第 4 条）。
    let text = fetch_guarded(&url)
        .await
        // **2.1.48 / AUD-11**：上游拉取失败是 **502**（INTERFACE 契约），不是 400。
        .map_err(|_| ServerError::BadGateway("订阅下载失败".into()))?;
    let digest = sub_digest_text(&text);
    let mut items = items_from_text(&text)?;
    let count = items.len();
    let _txn = sub_txn().lock().await;
    let path = current_path(&state);
    let now = ts_now();
    // P0（内存）：旧明细**就地改造**成新明细（只 1 份明细树），回滚载荷只留最小信息。
    let mut subs = load_subs(&path);
    let old_meta = cfg_meta(&state);
    let rollback = match subs.iter().position(|s| as_str(s, "url") == url) {
        Some(i) => {
            // 覆盖已存在订阅：旧值只留被覆盖的那一条。
            let old = subs[i].clone();
            let s = &mut subs[i];
            set_field(s, "action", json!(action));
            set_field(s, "group", json!(group));
            set_field(s, "ip", json!(ip));
            // `items` 移动进条目（旧实现 `items.clone()` 让明细树同时存在两份）。
            set_field(s, "rules", Value::Array(std::mem::take(&mut items)));
            set_field(s, "count", json!(count));
            set_field(s, "updated_at", json!(now));
            SubRollback::Replaced { idx: i, old }
        }
        None => {
            // 新建订阅：追加在尾部 → 回滚只需截断（旧文件 = 新明细前缀）。
            let n = subs.len();
            subs.push(sub_entry_owned(&url, &action, &group, &ip, items, &now));
            SubRollback::Truncate(n)
        }
    };
    // config.json 元信息：只存 {url,action,group,ip,count,updated_at}。
    let mut meta = old_meta.clone();
    let entry = meta_entry(&url, &action, &group, &ip, count, &now);
    match meta.iter_mut().find(|m| as_str(m, "url") == url) {
        Some(m) => *m = entry,
        None => meta.push(entry),
    }
    let added = matches!(&rollback, SubRollback::Truncate(_));
    let txn = SubTxn {
        path,
        new_subs: Arc::new(subs),
        rollback,
        old_meta,
        new_meta: meta,
    };
    commit_sub_txn(&state, &txn).await?;
    // 明细已落盘：后续重建**从磁盘流式解析**（不再依赖内存里的 10 万条明细树），
    // 先把事务载荷丢掉，缩小「明细树 + 新索引」同时在场的峰值窗口。
    drop(txn);
    check_rebuild(rebuild_all_disk_stats(&state))?;
    // **2.1.48 / AUD-05**：新建/覆盖订阅后内容 = 刚落盘的这份 ⇒ 记摘要，后续 update 可
    // 直接 `unchanged`（同时避免旧 stale digest 残留）。
    sub_digest_set(&url, digest);
    state.state.mark_serving();
    state.resolver.trim_allocator();
    Ok(json!({
        "ok": true,
        "url": url,
        "count": count,
        "added": if added { 1 } else { 0 },
    }))
}

/// POST /api/rules/subscribe/update
///
/// 对齐 `_api_subscribe_update`(3471-3570)：重新拉取并覆盖明细；订阅不存在 → 404；
/// 写盘失败 → 回滚内存元信息 + `rules_sub.json`。F19：**下载失败文案是
/// `订阅更新失败`**（`api.py:3495-3508`），不是通用订阅下载文案。
pub async fn update(state: AppState, body: Value) -> Result<Value, ServerError> {
    let url = parse_url(&body)?;
    let text = fetch_guarded(&url)
        .await
        .map_err(|_| ServerError::BadGateway("订阅更新失败".into()))?;
    let digest = sub_digest_text(&text);
    let path = current_path(&state);
    // **2.1.48 / AUD-05**：先确认订阅仍存在，再做摘要短路 —— 旧顺序下
    // “update 成功 → DELETE → 再 update”会返回 200 `unchanged` 而不是 404。
    // 注意：这里只用**元信息视图**（不物化 10 万条明细 Value），否则每次刷新都会
    // 产生 ~66 MB 瞬时分配并把 RSS/VmData 顶上去（与 2.1.47 的内存目标相反）。
    if !sub_urls_strict(&path).is_some_and(|v| v.iter().any(|u| u == &url)) {
        return Err(not_found_sub(&url));
    }
    if sub_digest_get(&url) == Some(digest) {
        // **AUD-08**：内容未变也刷新“最后检查”观测字段（只写 config 元信息，
        // 不碰 rules_sub.json ⇒ 不改变来源指纹、不触发重建）。
        touch_last_checked(&state, &url)?;
        let count = state
            .cfg
            .read()
            .get("rule_subscriptions")
            .and_then(Value::as_array)
            .and_then(|a| a.iter().find(|m| as_str(m, "url") == url))
            .and_then(|m| m.get("count"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        tracing::debug!(%url, count, "订阅内容未变化 → 跳过解析/落盘/索引重建");
        state.resolver.trim_allocator();
        return Ok(json!({"ok": true, "url": url, "count": count, "unchanged": true}));
    }
    let mut items = items_from_text(&text)?;
    let count = items.len();
    let _txn = sub_txn().lock().await;
    let now = ts_now();
    // 内容真变才物化明细（与 2.1.47 相同；正常刷新走上面的摘要短路）。
    let mut subs = load_subs(&path);
    let Some(i) = subs.iter().position(|s| as_str(s, "url") == url) else {
        return Err(not_found_sub(&url));
    };
    let old_meta = cfg_meta(&state);
    let rollback = {
        let old = subs[i].clone();
        let s = &mut subs[i];
        set_field(s, "rules", Value::Array(std::mem::take(&mut items)));
        set_field(s, "count", json!(count));
        set_field(s, "updated_at", json!(&now));
        SubRollback::Replaced { idx: i, old }
    };
    let mut meta = old_meta.clone();
    if let Some(m) = meta.iter_mut().find(|m| as_str(m, "url") == url) {
        set_field(m, "count", json!(count));
        set_field(m, "updated_at", json!(&now));
        set_field(m, "last_checked_at", json!(&now));
    }
    let txn = SubTxn {
        path,
        new_subs: Arc::new(subs),
        rollback,
        old_meta,
        new_meta: meta,
    };
    commit_sub_txn(&state, &txn).await?;
    drop(txn);
    check_rebuild(rebuild_all_disk_stats(&state))?;
    // 落盘 + 重建都成功后才记摘要（失败路径下不记，下轮会重试）。
    sub_digest_set(&url, digest);
    // **2.1.48 / serving_revision**：提交 + 索引重建都成功后才推进 serving。
    state.state.mark_serving();
    state.resolver.trim_allocator();
    Ok(json!({"ok": true, "url": url, "count": count}))
}

/// DELETE /api/rules/subscribe?url=...
///
/// 对齐 `_api_subscribe_delete`(3572-3626)：缺 url → 400 `缺少 url 参数`；
/// 不存在 → 404 `订阅不存在: <url>`；成功 → `{"ok":true,"url":url}`；
/// 写盘失败 → 回滚内存元信息 + `rules_sub.json`。
pub async fn delete(state: AppState, url: &str) -> Result<Value, ServerError> {
    let url = url.trim().to_string();
    if url.is_empty() {
        return Err(ServerError::BadRequest("缺少 url 参数".into()));
    }
    let _txn = sub_txn().lock().await;
    let path = current_path(&state);
    let old_meta = cfg_meta(&state);
    // P0（内存）：**就地摘除**（`Vec::remove` 移动元素，O(1) 次拷贝），
    // 不再 `old_subs.iter().filter(...).cloned()` 整表再深拷贝一份（旧实现 delete
    // 同时存在「完整旧表 + 完整新表 + 写盘拷贝 + 序列化树」约 4 份明细树）。
    // 回滚只需被删掉的那几条（`SubRollback::Removed`）。
    let mut subs = load_subs(&path);
    let mut removed: Vec<Value> = Vec::new();
    let mut i = 0usize;
    while i < subs.len() {
        if as_str(&subs[i], "url") == url {
            removed.push(subs.remove(i));
        } else {
            i += 1;
        }
    }
    if removed.is_empty() {
        return Err(not_found_sub(&url));
    }
    let meta: Vec<Value> = old_meta
        .iter()
        .filter(|m| as_str(m, "url") != url)
        .cloned()
        .collect();
    let txn = SubTxn {
        path,
        new_subs: Arc::new(subs),
        rollback: SubRollback::Removed(removed),
        old_meta,
        new_meta: meta,
    };
    commit_sub_txn(&state, &txn).await?;
    // 丢开事务载荷（含被删订阅的 10 万条明细）再重建索引，让旧明细尽快可回收。
    drop(txn);
    // **2.1.49（AUD-05 + AUD-14）**：摘要必须在**重建之前**清掉。旧顺序把
    // `sub_digest_remove` 放在 `check_rebuild(...)?` 之后：删订阅后若重建失败
    // （例如本地真源同时损坏），函数提前返回，摘要表仍留着已删除 URL 的 stale
    // digest；同 URL 重新订阅且内容相同就会被 `unchanged` 短路。
    sub_digest_remove(&url);
    check_rebuild(rebuild_all_disk_stats(&state))?;
    state.state.mark_serving();
    state.resolver.trim_allocator();
    Ok(json!({"ok": true, "url": url}))
}

/* ---------------- 周期更新 ---------------- */

/// 周期更新任务（由 main 启动）：每 10s tick；距上次 ≥ `rule_sub_interval` 秒则逐个串行更新。
/// `interval` 从 `state.cfg` 实时读取（0=关闭），对齐 `resolver.py:3391-3411` `_bg_loop`。
pub fn spawn_updater(state: AppState) {
    tokio::spawn(async move {
        let mut last: f64 = 0.0;
        loop {
            tokio::time::sleep(BG_TICK).await;
            let interval = read_interval(&state);
            if interval == 0 {
                continue;
            }
            let now = epoch_now();
            if now - last < interval as f64 {
                continue;
            }
            last = now;
            update_once(&state).await;
        }
    });
}

/// 读 `rule_sub_interval`（秒，0 = 关闭）。
///
/// 对齐 `resolver.py:3402` `max(0, _safe_int(cfg.get("rule_sub_interval", 3600), 0))`：
/// **缺键** → 3600（默认周期）；键存在但为 `null` / 非法串 / 负数 → **0（关闭）**。
/// F26：旧实现在这两种情况下都回退 3600，畸形值会让订阅继续联网。
fn read_interval(state: &AppState) -> u64 {
    interval_from_cfg(state.cfg.read().get("rule_sub_interval"))
}

/// `rule_sub_interval` 取值（纯函数，便于单测）。
fn interval_from_cfg(raw: Option<&Value>) -> u64 {
    match raw {
        None => DEFAULT_RULE_SUB_INTERVAL,
        Some(v) => match python_int(v) {
            Some(n) => n.max(0) as u64,
            None => 0,
        },
    }
}

/// **[历史归因]** Python `int(v)` 语义：`None` = 转换失败（TypeError/ValueError → 调用方取默认值）。
///
/// bool 是 int 子类（`int(True) == 1`）；浮点向零截断、非有限值失败；字符串允许
/// 首尾空白与符号（`int(" 60 ") == 60`）。
fn python_int(v: &Value) -> Option<i64> {
    match v {
        Value::Bool(b) => Some(i64::from(*b)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                return Some(i);
            }
            let f = n.as_f64()?;
            if !f.is_finite() {
                return None;
            }
            let t = f.trunc();
            if t < i64::MIN as f64 || t > i64::MAX as f64 {
                return None;
            }
            Some(t as i64)
        }
        Value::String(s) => s.trim().parse::<i64>().ok(),
        _ => None,
    }
}

fn epoch_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// 一轮订阅自动更新（对齐 `resolver.py:3495-3614` `_update_rule_subs_once`）：
/// 网络下载在锁外逐个串行，失败仅告警；成功条目覆盖明细后落盘，最后统一 rebuild。
/// 配置里已删除的订阅从独立文件剔除（防残留规则继续生效）。
///
/// F07：读改写段（含落盘）持 [`sub_txn`]（与规则 CRUD / 订阅 CRUD 共用同一把锁）；
/// 进锁后**重新**读 `config_urls` 与 cfg（对齐 `resolver.py:3530-3532`），
/// 防止后台用下载期间的陈旧快照写回、把并发删除/新增的订阅静默恢复。
async fn update_once(state: &AppState) {
    let urls = config_urls(state);
    // **2.1.48 / AUD-03**：`rules_sub.json` 缺失时不能相信摘要缓存 —— 强制重新下载，
    // 否则文件永远补不回来（旧实现摘要命中就直接 return，删掉的文件不会重建）。
    let path0 = current_path(state);
    let file_present = path0.exists();
    let file_urls0 = sub_urls_strict(&path0);
    let force_refetch = !file_present || file_urls0.is_none();
    let known0: HashSet<String> = file_urls0.clone().unwrap_or_default().into_iter().collect();
    let mut fetched: Vec<(String, Vec<Value>, u128)> = Vec::new();
    for url in &urls {
        match fetch_guarded(url).await {
            Ok(text) => {
                // **2.1.47 / M-247**：原文摘要没变 ⇒ 本次不解析、不读明细、不落盘、不重建。
                let digest = sub_digest_text(&text);
                if !force_refetch && known0.contains(url) && sub_digest_get(url) == Some(digest) {
                    tracing::debug!(%url, bytes = text.len(), "订阅内容未变化 → 跳过本次刷新");
                    continue;
                }
                match items_from_text(&text) {
                    Ok(items) => fetched.push((url.clone(), items, digest)),
                    Err(_) => tracing::warn!(%url, "订阅自动更新: 未解析到有效域名"),
                }
            }
            Err(e) => tracing::warn!(%url, error = %e, "订阅自动更新失败"),
        }
    }
    let refreshed = fetched.len();
    // **2.1.48 / AUD-03**：**不再**因 `fetched.is_empty()` 提前返回 —— prune（配置里删除
    // 的订阅）、占位补齐、`rules_sub.json` 自愈必须每轮执行（2.1.46 行为）。
    let _txn = sub_txn().lock().await;
    let urls = config_urls(state); // 锁内重读，防下载期间配置变化
    let allowed: HashSet<String> = urls.iter().cloned().collect();
    let path = current_path(state);
    let now = ts_now();
    let existed = path.exists();
    let file_urls = sub_urls_strict(&path);
    // **2.1.48 / AUD-03 快速路径**：内容未变 + 文件存在 + URL 集合与配置一致 ⇒
    // 不做 prune/占位，也不需要物化 10 万条明细（只刷新 `last_checked_at`）。
    let same_set = file_urls.as_ref().is_some_and(|v| {
        let have: HashSet<&str> = v.iter().map(String::as_str).collect();
        let want: HashSet<&str> = allowed.iter().map(String::as_str).collect();
        have == want
    });
    if refreshed == 0 && existed && same_set {
        let mut snapshot = state.cfg.read().clone();
        if let Some(meta) = snapshot
            .get_mut("rule_subscriptions")
            .and_then(Value::as_array_mut)
        {
            for m in meta.iter_mut() {
                set_field(m, "last_checked_at", json!(&now));
            }
        }
        if *state.cfg.read() != snapshot {
            match persist_cfg(state, &snapshot) {
                Ok(()) => {
                    // 同步内存快照，避免下一次 subscribe/update 组 meta 时覆盖该字段。
                    *state.cfg.write() = snapshot;
                    // **2.1.48 / serving_revision**：config-only 提交（索引未变）。
                    state.state.mark_serving();
                    tracing::debug!("订阅刷新: 内容未变，仅更新 last_checked_at");
                }
                Err(e) => tracing::error!("订阅 last_checked_at 落盘失败: {e}（下轮重试）"),
            }
        }
        state.resolver.trim_allocator();
        return;
    }
    let mut subs = load_subs(&path);
    let mut structural_changed = !existed || file_urls.is_none();
    // config 有而明细缺失 ⇒ 补空占位（自愈：文件被删/损坏后仍能重建）。
    let placeholders: Vec<Value> = {
        let have: HashSet<String> = subs
            .iter()
            .map(|s| as_str(s, "url"))
            .filter(|u| !u.is_empty())
            .collect();
        let cfg = state.cfg.read();
        cfg.get("rule_subscriptions")
            .and_then(Value::as_array)
            .map(|meta| {
                meta.iter()
                    .filter_map(|m| {
                        let u = as_str(m, "url");
                        if u.is_empty() || have.contains(&u) {
                            return None;
                        }
                        let pick = |k: &str, d: &str| {
                            let v = as_str(m, k);
                            if v.is_empty() {
                                d.to_string()
                            } else {
                                v
                            }
                        };
                        Some(json!({
                            "url": u,
                            "action": pick("action", "block"),
                            "group": pick("group", "global"),
                            "ip": pick("ip", "1.2.3.4"),
                            "count": m.get("count").cloned().unwrap_or(json!(0)),
                            "updated_at": &now,
                            "rules": [],
                        }))
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    if !placeholders.is_empty() {
        structural_changed = true;
        subs.extend(placeholders);
    }
    // 应用本轮真实变化的内容。
    for s in subs.iter_mut() {
        let u = as_str(s, "url");
        if let Some(pos) = fetched.iter().position(|(f, _, _)| *f == u) {
            let items = std::mem::take(&mut fetched[pos].1);
            let count = items.len();
            set_field(s, "rules", Value::Array(items));
            set_field(s, "count", json!(count));
            set_field(s, "updated_at", json!(&now));
        }
    }
    // **AUD-03**：配置里已删除的订阅必须从明细剔除（此步现在每轮都跑）。
    let before = subs.len();
    subs.retain(|s| allowed.contains(&as_str(s, "url")));
    if subs.len() != before {
        structural_changed = true;
    }
    // **AUD-14**：摘要表跟随当前配置收敛（删除的 URL 不再保留 stale digest）。
    sub_digest_retain(&allowed);

    let refreshed = fetched.len();
    let refreshed_digests: Vec<(String, u128)> =
        fetched.iter().map(|(u, _, d)| (u.clone(), *d)).collect();
    drop(fetched);

    // config 元信息：count / updated_at / **last_checked_at（AUD-08，未变也刷新）**。
    let mut snapshot = state.cfg.read().clone();
    if !snapshot.is_object() {
        snapshot = Value::Object(Map::new());
    }
    if let Some(meta) = snapshot
        .get_mut("rule_subscriptions")
        .and_then(Value::as_array_mut)
    {
        for m in meta.iter_mut() {
            let u = as_str(m, "url");
            set_field(m, "last_checked_at", json!(&now));
            if let Some(s) = subs.iter().find(|s| as_str(s, "url") == u) {
                set_field(m, "count", s.get("count").cloned().unwrap_or(json!(0)));
                let su = as_str(s, "updated_at");
                if !su.is_empty() {
                    set_field(m, "updated_at", json!(su));
                }
            }
        }
    }
    let cfg_changed = *state.cfg.read() != snapshot;

    if refreshed == 0 && !structural_changed {
        if !cfg_changed {
            state.resolver.trim_allocator();
            return;
        }
        // 只有观测字段变化 ⇒ 只提交 config（不重写数 MB 明细、不重建索引）。
        match persist_cfg(state, &snapshot) {
            Ok(()) => tracing::debug!("订阅刷新: 内容未变，仅更新 last_checked_at"),
            Err(e) => tracing::error!("订阅 last_checked_at 落盘失败: {e}（下轮重试）"),
        }
        state.resolver.trim_allocator();
        return;
    }

    let subs_bytes_v = match subs_bytes(&subs) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("订阅明细序列化失败: {e}");
            return;
        }
    };
    let mut plan = state_plan(state, &snapshot, None).unwrap_or_default();
    plan.insert(path.clone(), subs_bytes_v);
    let stored_subs = Arc::new(subs);
    let commit: Result<Option<crate::state_store::Commit>, crate::state_store::CommitError> =
        match state.state.store() {
            Some(store) => tokio::task::spawn_blocking({
                let store = std::sync::Arc::clone(store);
                move || crate::state_store::commit_droppable(&store, "subscribe:refresh", &plan)
            })
            .await
            .unwrap_or_else(|e| {
                Err(crate::state_store::CommitError::Io {
                    msg: format!("订阅刷新提交任务失败（join error）: {e}"),
                })
            }),
            None => match write_subs(&path, Arc::clone(&stored_subs)).await {
                Ok(()) => Ok(None),
                Err(e) => Err(crate::state_store::CommitError::Io {
                    msg: format!("订阅刷新落盘失败 {}: {e}", path.display()),
                }),
            },
        };
    match commit {
        Ok(_) => {
            // 磁盘已是新世代 ⇒ 内存元信息与之同源（否则控制台显示过期 count）。
            if state.state.is_on() {
                *state.cfg.write() = snapshot.clone();
            }
            let pruned = before.saturating_sub(stored_subs.len());
            tracing::info!(
                refreshed,
                pruned,
                "规则订阅自动更新完成（含 prune/占位自愈）"
            );
            // 明细已落盘 → 释放内存明细树后从磁盘流式重建索引。
            drop(stored_subs);
            // F20：后台路径失败仅 ERROR 告警（不阻断周期任务，下个周期重试）。
            // **AUD-04**：digest 只在重建成功后写入 —— 失败路径不写，下一周期会重试。
            match check_rebuild(rebuild_all_disk_stats(state)) {
                Ok(()) => {
                    for (u, d) in &refreshed_digests {
                        sub_digest_set(u, *d);
                    }
                    // **2.1.48 / serving_revision**：索引已就绪 ⇒ 推进 serving。
                    state.state.mark_serving();
                }
                Err(e) => tracing::error!(
                    "规则订阅自动更新后索引重建失败: {e:?}（digest 未写，下轮重试）"
                ),
            }
            state.resolver.trim_allocator();
        }
        Err(e) => tracing::error!(
            "规则订阅自动更新落盘失败 {}: {e}（提交未生效，上一代完好；下个周期重试）",
            path.display()
        ),
    }
}

/// 从 `config.json` 元信息取有效订阅 URL（保序、去空）。
fn config_urls(state: &AppState) -> Vec<String> {
    state
        .cfg
        .read()
        .get("rule_subscriptions")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|m| as_str(m, "url"))
                .filter(|u| !u.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/* ---------------- GET /api/rules 的订阅列表（F22） ---------------- */

/// GET /api/rules 的 `subscriptions[]`：以 `rules_sub.json` **明细为准**聚合
/// （对齐 `api.py:3421-3438` `_rules_with_subs` + `_load_subs` 的补齐语义）。
///
/// 旧实现直接回显 `cfg["rule_subscriptions"]`：`count` 用的是可能过期的元信息值，
/// 「文件里有、config 里没有」的订阅完全不显示。
pub fn subscriptions_view(state: &AppState) -> Vec<Value> {
    // cfg 短临界区（拿到路径与元信息后立即释放，文件读不在锁内）。
    let (path, meta) = {
        let cfg = state.cfg.read();
        let path = subs_path(&cfg, state.cfg_path.as_deref());
        let meta = cfg
            .get("rule_subscriptions")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        (path, meta)
    };
    // P0（内存）：走**计数视图**（`rules` 明细零分配跳过），不物化 10 万条明细。
    subscriptions_from(&load_subs_counts(&path), &meta)
}

/// 明细 + config 元信息 → 订阅列表（纯函数，便于单测）。
///
/// - 明细条目：`count = len(rules)`（**不以 config 的旧 count 为准**），
/// **[历史归因]**   action/group/ip/updated_at 缺失时按 Python 的 `or` 回退 meta；
/// - config 有而明细文件没有的订阅：补占位条目（可见、可点「更新」），
/// **[历史归因]**   `count` 回退 meta —— 无明细时只能信 meta（Python `_load_subs` 同样按 meta 补条目）。
pub fn subscriptions_from(subs: &[Value], meta: &[Value]) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::with_capacity(subs.len());
    let mut seen: HashSet<String> = HashSet::new();
    for s in subs {
        let url = as_str(s, "url");
        let m = meta_of(meta, &url);
        out.push(json!({
            "url": url,
            "action": pick_str(s.get("action"), m.and_then(|m| m.get("action")), "block"),
            "group": pick_str(s.get("group"), m.and_then(|m| m.get("group")), ""),
            "ip": pick_str(s.get("ip"), m.and_then(|m| m.get("ip")), ""),
            "count": s.get("rules").and_then(Value::as_array).map(Vec::len)
                .or_else(|| s.get("count").and_then(Value::as_u64).map(|v| v as usize))
                .unwrap_or(0),
            "updated_at": pick_str(
                s.get("updated_at"),
                m.and_then(|m| m.get("updated_at")),
                "",
            ),
        }));
        seen.insert(url);
    }
    for m in meta {
        let url = as_str(m, "url");
        if url.is_empty() || !seen.insert(url.clone()) {
            continue;
        }
        out.push(json!({
            "url": url,
            "action": pick_str(m.get("action"), None, "block"),
            "group": pick_str(m.get("group"), None, "global"),
            "ip": pick_str(m.get("ip"), None, "1.2.3.4"),
            "count": m.get("count").and_then(Value::as_u64).unwrap_or(0),
            "updated_at": pick_str(m.get("updated_at"), None, ""),
        }));
    }
    out
}

/// 按 url 在元信息数组里找条目。
fn meta_of<'a>(meta: &'a [Value], url: &str) -> Option<&'a Value> {
    meta.iter().find(|m| as_str(m, "url") == url)
}

/// **[历史归因]** Python `a or b or default`（falsy = 缺键 / null / 非字符串 / 空串）。
fn pick_str(primary: Option<&Value>, fallback: Option<&Value>, default: &str) -> String {
    for v in [primary, fallback].into_iter().flatten() {
        if let Some(s) = v.as_str() {
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }
    default.to_string()
}

/* ---------------- 测试 ---------------- */

#[cfg(test)]
mod tests {
    use super::*;

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// 纯域名 / hosts / 逗号分隔 / dnsmasq / SmartDNS / Surge / Clash / Adblock。
    #[test]
    fn parse_all_supported_formats() {
        // 纯域名
        let plain = parse_domain_list("example.com\nads.test\n");
        assert!(plain.contains(&"example.com".to_string()), "{plain:?}");
        assert!(plain.contains(&"ads.test".to_string()), "{plain:?}");

        // hosts（IP 域名）——首列裸 IP 必须跳过
        let hosts = parse_domain_list("0.0.0.0 blocked.example\n127.0.0.1 tracker.test\n");
        assert!(hosts.contains(&"blocked.example".to_string()), "{hosts:?}");
        assert!(hosts.contains(&"tracker.test".to_string()), "{hosts:?}");
        assert!(!hosts.iter().any(|d| d.contains("0.0.0.0")), "{hosts:?}");

        // 逗号分隔
        let csv = parse_domain_list("a.com,b.com , c.com\n");
        assert_eq!(csv.len(), 3, "{csv:?}");
        assert!(csv.contains(&"c.com".to_string()), "{csv:?}");

        // dnsmasq：一行多域名 / 单域名
        let dnsmasq = parse_domain_list("address=/ads.com/track.net/\naddress=/one.example/#\n");
        assert!(dnsmasq.contains(&"ads.com".to_string()), "{dnsmasq:?}");
        assert!(dnsmasq.contains(&"track.net".to_string()), "{dnsmasq:?}");
        assert!(dnsmasq.contains(&"one.example".to_string()), "{dnsmasq:?}");

        // SmartDNS：address /域名/#
        let smart = parse_domain_list("address /smart.example/#\n");
        assert_eq!(smart, strs(&["smart.example"]), "{smart:?}");

        // Surge
        let surge = parse_domain_list("DOMAIN-SUFFIX,surge.example\nDOMAIN,exact.example\n");
        assert!(surge.contains(&"surge.example".to_string()), "{surge:?}");
        assert!(surge.contains(&"exact.example".to_string()), "{surge:?}");

        // Clash YAML 列表项
        let clash = parse_domain_list("- '+.clash.example'\n- \"+.quoted.example\"\n");
        assert!(clash.contains(&"clash.example".to_string()), "{clash:?}");
        assert!(clash.contains(&"quoted.example".to_string()), "{clash:?}");

        // Adblock
        let ad = parse_domain_list("||adblock.example^\n");
        assert_eq!(ad, strs(&["adblock.example"]), "{ad:?}");
    }

    /// 注释（`# ! // ;`）、`@@` 例外、YAML 顶层键跳过。
    #[test]
    fn parse_skips_comments_exceptions_and_yaml_keys() {
        let t = "# hash\n! bang\n// slash\n; semi\n@@||allow.example^\npayload:\nrules:\nreal.example\n";
        assert_eq!(parse_domain_list(t), strs(&["real.example"]));
        assert!(
            !parse_domain_list("@@||allow.example^")
                .iter()
                .any(|d| d == "allow.example"),
            "Adblock 例外不得当拦截导入"
        );
    }

    /// 裸 IP（含 IPv6）跳过。
    #[test]
    fn parse_skips_bare_ips() {
        let d = parse_domain_list("1.2.3.4\n::6\n2001:db8::1\nok.example\n");
        assert!(d.contains(&"ok.example".to_string()), "{d:?}");
        for ip in ["1.2.3.4", "::6", "2001:db8::1"] {
            assert!(!d.iter().any(|x| x == ip), "{ip} 不应被当作域名: {d:?}");
        }
    }

    /// 去重（保序）。
    #[test]
    fn parse_dedupes_preserving_order() {
        let d = parse_domain_list("dup.example\nother.example\ndup.example\n");
        assert_eq!(d, strs(&["dup.example", "other.example"]));
    }

    /// SSRF：`http://` / loopback / 私网必须拒绝；明确文案。
    #[test]
    fn url_blocked_rejects_http_and_private() {
        let http = url_blocked("http://example.com/rules").unwrap_err();
        assert!(http.contains("仅支持 https://"), "{http}");
        assert!(url_blocked("ftp://example.com/rules").is_err());
        assert!(url_blocked("not-a-url").is_err());
        assert!(url_blocked("https://127.0.0.1/rules").is_err());
        assert!(url_blocked("https://10.0.0.1/rules").is_err());
        // 其它非全球单播段（CGNAT / 保留 / 组播 / 链路本地 / IPv6）。
        for u in [
            "https://100.64.0.1/rules",
            "https://192.168.1.1/rules",
            "https://169.254.169.254/latest/meta-data",
            "https://224.0.0.1/rules",
            "https://240.0.0.1/rules",
            "https://0.0.0.0/rules",
            "https://198.18.0.1/rules",
            "https://[::1]/rules",
            "https://[fe80::1]/rules",
            "https://[fc00::1]/rules",
            "https://[ff02::1]/rules",
            "https://[64:ff9b::1]/rules",
            "https://[::ffff:10.0.0.1]/rules",
        ] {
            assert!(url_blocked(u).is_err(), "应拒绝 {u}");
        }
    }

    /* ---- 真钉死：SSRF 闸门 / 钉死目标不变量 / 体积上限 / 超时 ---- */

    /// `Resolver::resolve` 的第三个参数（本实现不读它，仅供单测构造）。
    fn next_timeout() -> NextTimeout {
        NextTimeout {
            after: ureq::unversioned::transport::time::Duration::from_secs(20),
            reason: ureq::Timeout::Global,
        }
    }

    /// DNS rebinding：同一主机名解析出「公网 + 私网」混合时必须**整体**拒绝
    /// （不能只挑公网的连），单独出现与空列表同样拒绝。
    #[test]
    fn rebinding_mixed_public_and_private_is_rejected() {
        let public: IpAddr = "93.184.216.34".parse().unwrap();
        let public6: IpAddr = "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap();
        assert!(check_resolved_all_global(&[public]).is_ok());
        assert!(check_resolved_all_global(&[public, public6]).is_ok());
        for bad in [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "198.18.0.1",
            "224.0.0.1",
            "240.0.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
            "::ffff:10.0.0.1",
            "64:ff9b::1",
        ] {
            let bad: IpAddr = bad.parse().unwrap();
            assert!(
                check_resolved_all_global(&[public, bad]).is_err(),
                "公网+{bad} 混合必须整体拒绝(防 rebinding)"
            );
            assert!(
                check_resolved_all_global(&[bad, public]).is_err(),
                "{bad}+公网 混合必须整体拒绝(防 rebinding)"
            );
            assert!(check_resolved_all_global(&[bad]).is_err(), "{bad} 必须拒绝");
        }
        assert!(
            check_resolved_all_global(&[]).is_err(),
            "空解析结果必须拒绝"
        );
        // 「主机名本身就是 IP」的短路路径同样过闸门（不查 DNS）。
        assert!(resolve_checked("10.0.0.1", 443).is_err());
        assert!(resolve_checked("[::1]", 443).is_err());
        assert_eq!(resolve_checked("93.184.216.34", 443).unwrap(), vec![public]);
        // 每跳复检用的 `pinned_targets` 对重定向目标同样生效。
        assert!(pinned_targets("https://10.0.0.1/x.txt").is_err());
        assert!(pinned_targets("http://93.184.216.34/x.txt").is_err());
        let (h, addrs) = pinned_targets("https://93.184.216.34:8443/x.txt").unwrap();
        assert_eq!(h, "93.184.216.34");
        assert_eq!(addrs, vec![SocketAddr::new(public, 8443)]);
    }

    /// 不变量：钉死表 = `resolve_checked` 返回值 + 端口（不多、不少、顺序不变），
    /// 且 ureq 取地址的唯一入口 `Resolver::resolve` 原样交出这张表；主机名不符则 fail-closed。
    #[test]
    fn pinned_targets_are_exactly_the_validated_ips() {
        let ips: Vec<IpAddr> = vec![
            "93.184.216.34".parse().unwrap(),
            "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap(),
        ];
        let pinned = pin_socket_addrs(&ips, 8443);
        assert_eq!(pinned.len(), ips.len());
        for (i, ip) in ips.iter().enumerate() {
            assert_eq!(pinned[i], SocketAddr::new(*ip, 8443));
        }
        // 去重、不新增、不改 IP。
        assert_eq!(
            pin_socket_addrs(&[ips[0], ips[0], ips[1]], 443),
            vec![SocketAddr::new(ips[0], 443), SocketAddr::new(ips[1], 443)]
        );
        let validated: HashSet<IpAddr> = ips.iter().copied().collect();
        assert!(
            pinned.iter().all(|a| validated.contains(&a.ip())),
            "钉死表不得含未校验 IP: {pinned:?}"
        );

        let cfg = ureq::config::Config::default();
        let r = PinnedResolver;
        let uri: ureq::http::Uri = "https://anti-ad.net/adguard.txt".parse().unwrap();
        // **2.1.48 / M-248**：钉死表是线程局部的 —— 未安装时必须 fail-closed。
        assert!(
            r.resolve(&uri, &cfg, next_timeout()).is_err(),
            "没有 PinGuard 时必须拒绝解析（绝不回退系统 DNS）"
        );
        let guard = PinGuard::install("anti-ad.net".to_string(), pinned.clone());
        let got = r.resolve(&uri, &cfg, next_timeout()).unwrap();
        assert_eq!(&got[..], &pinned[..], "resolve 必须原样交出钉死表");
        // 大小写无关；另一主机名一律拒绝（绝不为别的主机名交出钉死 IP）。
        let upper: ureq::http::Uri = "https://ANTI-AD.NET/x".parse().unwrap();
        assert_eq!(
            &r.resolve(&upper, &cfg, next_timeout()).unwrap()[..],
            &pinned[..]
        );
        let evil: ureq::http::Uri = "https://evil.test/x".parse().unwrap();
        assert!(r.resolve(&evil, &cfg, next_timeout()).is_err());
        // 空钉死表 → 拒绝（不会退化成「让 ureq 自己解析」）。
        drop(guard);
        let empty = PinGuard::install("anti-ad.net".to_string(), vec![]);
        assert!(r.resolve(&uri, &cfg, next_timeout()).is_err());
        drop(empty);
        assert!(
            r.resolve(&uri, &cfg, next_timeout()).is_err(),
            "PinGuard 释放后必须立刻回到 fail-closed"
        );
    }

    /// 端到端：Agent 的 TCP 目标**就是**钉死 IP。域名用 `.invalid`（RFC 6761 保留 TLD，
    /// DNS 必然解析不到）→ 唯一可能的连接来源只有钉死表，本机 listener 收到连接即证据。
    #[test]
    fn agent_connects_to_the_pinned_ip_not_dns() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let (tx, rx) = std::sync::mpsc::channel();
        let th = std::thread::spawn(move || {
            if let Ok((stream, peer)) = listener.accept() {
                let _ = tx.send(peer);
                // 立刻断开：TLS 握手必然失败，但 TCP 已连到钉死地址。
                drop(stream);
            }
        });
        // **2.1.48 / M-248**：进程级单例 Agent + 线程局部钉死表（guard 必须活到 call 结束）。
        let _pin = PinGuard::install("pin-test.invalid".to_string(), vec![addr]);
        let err = subscription_agent()
            .get("https://pin-test.invalid/rules.txt")
            .call()
            .expect_err("对端立刻断开,TLS 握手必然失败");
        // listener 只监听 `addr` 这一个地址：收到连接 ⇒ TCP 目标就是钉死地址。
        let peer = rx
            .recv_timeout(Duration::from_secs(20))
            .expect("TCP 必须连到钉死 IP(而不是自行 DNS 解析)");
        assert_eq!(peer.ip(), addr.ip());
        // 反向证据：若地址来自 ureq 自己 DNS 解析，`.invalid`(RFC 6761) 解析不到，
        // 失败原因只会是 `HostNotFound`；实际不是 ⇒ 地址来自钉死表。
        assert!(
            !matches!(err, ureq::Error::HostNotFound),
            "地址来自 DNS 解析而非钉死表: {err:?}"
        );
        let _ = th.join();
    }

    /// 钉死没有改动其它网关：20s 全局/连接/收包超时、5s 解析超时、仅 https、
    /// 不跟随重定向、禁代理全部仍在。
    #[test]
    fn build_agent_keeps_timeouts_and_https_only() {
        let agent = build_agent();
        let c = agent.config();
        assert_eq!(c.timeouts().global, Some(FETCH_TIMEOUT));
        assert_eq!(c.timeouts().connect, Some(FETCH_TIMEOUT));
        assert_eq!(c.timeouts().resolve, Some(Duration::from_secs(5)));
        assert_eq!(c.timeouts().recv_response, Some(FETCH_TIMEOUT));
        assert_eq!(c.timeouts().recv_body, Some(FETCH_TIMEOUT));
        assert!(c.https_only(), "必须仍然 https-only");
        assert_eq!(c.max_redirects(), 0, "必须仍然不跟随重定向");
        assert!(c.proxy().is_none(), "必须仍然禁代理");
    }

    /// 体积上限仍生效：正好 16MB 通过，多 1 字节中止且文案明确。
    #[test]
    fn body_size_limit_still_enforced() {
        let exact = vec![b'a'; SUB_MAX_BYTES as usize];
        let ok = read_body_limited(&mut exact.as_slice()).expect("16MB 整好应通过");
        assert_eq!(ok.len() as u64, SUB_MAX_BYTES);
        let over = std::io::repeat(b'a');
        let e = read_body_limited(&mut over.take(SUB_MAX_BYTES + 1)).unwrap_err();
        assert!(e.contains("16MB"), "文案必须点明上限: {e}");
    }

    /// `*.` 前缀补齐 + `re:` 原样保留（不被包成 `*.re:`）+ 非法 `re:` 跳过。
    #[test]
    fn domains_to_rules_wildcard_and_regex() {
        let items = domains_to_rules(&strs(&[
            "example.com",
            "*.cdn.com",
            "re:^ads\\..*$",
            "re:",
            &format!("re:{}", "a".repeat(MATCH_MAX_BYTES)),
        ]));
        assert_eq!(items.len(), 3, "{items:?}");
        assert_eq!(items[0]["match"], json!("*.example.com"));
        assert_eq!(items[1]["match"], json!("*.cdn.com"));
        assert_eq!(items[2]["match"], json!("re:^ads\\..*$"));
    }

    /// 明细 JSON 形状 + 元信息不含 `rules`（元信息只进 config.json）。
    #[test]
    fn sub_and_meta_entry_shapes() {
        let items = domains_to_rules(&strs(&["a.com"]));
        let s = sub_entry(
            "https://x/r",
            "block",
            "global",
            "1.2.3.4",
            &items,
            "2026-01-02 03:04:05",
        );
        assert_eq!(s["url"], json!("https://x/r"));
        assert_eq!(s["count"], json!(1));
        assert_eq!(s["rules"][0]["match"], json!("*.a.com"));
        assert_eq!(s["updated_at"], json!("2026-01-02 03:04:05"));

        let m = meta_entry(
            "https://x/r",
            "block",
            "global",
            "1.2.3.4",
            1,
            "2026-01-02 03:04:05",
        );
        assert!(m.get("rules").is_none(), "元信息不得含 rules: {m}");
        assert_eq!(m["count"], json!(1));
    }

    /// 规则注入：action=group 带 group、forceIp 带 ip、block 不带。
    #[test]
    fn rule_json_follows_subscription_options() {
        let item = json!({"match": "*.a.com"});
        let g = rule_json(&json!({"action": "group", "group": "domestic"}), &item).unwrap();
        assert_eq!(g["action"], json!("group"));
        assert_eq!(g["group"], json!("domestic"));
        let f = rule_json(&json!({"action": "forceIp", "ip": "1.2.3.4"}), &item).unwrap();
        assert_eq!(f["ip"], json!("1.2.3.4"));
        let b = rule_json(&json!({"action": "block"}), &item).unwrap();
        assert!(b.get("group").is_none() && b.get("ip").is_none());
        // 缺 match → 跳过
        assert!(rule_json(&json!({"action": "block"}), &json!({"match": " "})).is_none());
    }

    /// 路径：`rule_sub_file` 优先，否则 config.json 同目录 rules_sub.json。
    #[test]
    fn subs_path_precedence() {
        // 平台无关路径（旧断言写死 Windows 反斜杠路径，在 Linux 上必然失败：
        // `Path::parent()` 不认 `\` 分隔符）。
        let dir = std::env::temp_dir().join("ebpdns-sub-test");
        let cfgp = dir.join("config.json");
        let cfg = json!({"rule_sub_file": dir.join("custom.json").display().to_string()});
        assert_eq!(
            subs_path(&cfg, Some(cfgp.as_path())),
            dir.join("custom.json")
        );
        let cfg = json!({});
        assert_eq!(
            subs_path(&cfg, Some(cfgp.as_path())),
            dir.join("rules_sub.json")
        );
        // **[历史归因]** 空串按未配置处理（对齐 Python `or`）。
        let cfg = json!({"rule_sub_file": "   "});
        assert_eq!(
            subs_path(&cfg, Some(cfgp.as_path())),
            dir.join("rules_sub.json")
        );
    }

    /// 落盘/读取往返 + 损坏文件按空列表 + 缺失文件按空列表 + `.tmp` 不残留。
    #[test]
    fn save_load_roundtrip_and_corrupt() {
        let dir = std::env::temp_dir().join(format!("ebpdns-sub-test-{}", std::process::id()));
        let path = dir.join("rules_sub.json");
        let _ = std::fs::remove_dir_all(&dir);
        // 缺失 → 空
        assert!(load_subs(&path).is_empty());
        // 往返（自动建目录）
        let items = domains_to_rules(&strs(&["a.com", "b.com"]));
        let subs = vec![sub_entry(
            "https://x/r",
            "block",
            "global",
            "1.2.3.4",
            &items,
            "2026-01-02 03:04:05",
        )];
        save_subs(&path, &subs).expect("保存应成功");
        let mut tmp = path.as_os_str().to_os_string();
        tmp.push(".tmp");
        assert!(!Path::new(&tmp).exists(), "临时文件应已 rename 掉");
        let back = load_subs(&path);
        assert_eq!(back.len(), 1);
        assert_eq!(back[0]["rules"].as_array().unwrap().len(), 2);
        assert_eq!(meta_from_subs(&back)[0]["count"], json!(2));
        // 损坏 → 空（不 panic）
        std::fs::write(&path, b"{ not json").unwrap();
        assert!(load_subs(&path).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 时间戳格式 `YYYY-MM-DD HH:MM:SS`（固定输入，避免时区依赖）。
    #[test]
    fn timestamp_format() {
        let s = fmt_local_ts(UNIX_EPOCH + Duration::from_secs(1_700_000_000));
        assert_eq!(s.len(), 19, "{s}");
        assert_eq!(&s[4..5], "-", "{s}");
        assert_eq!(&s[10..11], " ", "{s}");
        assert!(s.chars().next().unwrap().is_ascii_digit(), "{s}");
        assert_eq!(&s[13..14], ":", "{s}");
    }

    /* ---- F27：updated_at 的本地偏移（可注入固定偏移） ---- */

    #[test]
    fn local_timestamp_offset_is_injectable() {
        let t = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        // 2023-11-14 22:13:20 UTC 为基准。
        assert_eq!(fmt_local_ts_with_offset(t, 0), "2023-11-14 22:13:20");
        assert_eq!(fmt_local_ts_with_offset(t, 8 * 3600), "2023-11-15 06:13:20");
        assert_eq!(
            fmt_local_ts_with_offset(t, -5 * 3600),
            "2023-11-14 17:13:20"
        );
        // 跨日 / 跨月边界（负偏移回退一天、回退到上一年）。
        assert_eq!(
            fmt_local_ts_with_offset(UNIX_EPOCH, 8 * 3600),
            "1970-01-01 08:00:00"
        );
        assert_eq!(
            fmt_local_ts_with_offset(UNIX_EPOCH, -3600),
            "1969-12-31 23:00:00"
        );
        assert_eq!(
            fmt_local_ts_with_offset(UNIX_EPOCH + Duration::from_secs(86_399), 2 * 3600),
            "1970-01-02 01:59:59"
        );
    }

    /* ---- F26：rule_sub_interval 畸形值 → 0（关闭） ---- */

    #[test]
    fn rule_sub_interval_python_safe_int_semantics() {
        // 缺键 → 默认 3600。
        assert_eq!(interval_from_cfg(None), 3600);
        // 存在但非法 / 负数 / null → 0（关闭，不再回退 3600 继续联网）。
        assert_eq!(interval_from_cfg(Some(&json!(null))), 0);
        assert_eq!(interval_from_cfg(Some(&json!("abc"))), 0);
        assert_eq!(interval_from_cfg(Some(&json!(-5))), 0);
        assert_eq!(interval_from_cfg(Some(&json!("-5"))), 0);
        assert_eq!(interval_from_cfg(Some(&json!(-3600.5))), 0);
        assert_eq!(interval_from_cfg(Some(&json!([]))), 0);
        // 合法值（含 0 = 关闭）原样。
        assert_eq!(interval_from_cfg(Some(&json!(0))), 0);
        assert_eq!(interval_from_cfg(Some(&json!(60))), 60);
        assert_eq!(interval_from_cfg(Some(&json!(" 60 "))), 60);
        assert_eq!(interval_from_cfg(Some(&json!(3600.9))), 3600);
        // **[历史归因]** Python `int(True) == 1`。
        assert_eq!(interval_from_cfg(Some(&json!(true))), 1);
    }

    /* ---- F30：相对路径以 config.json 所在目录为基准 ---- */

    #[test]
    fn subs_path_relative_is_config_dir_based() {
        let cfg = json!({"rule_sub_file": "custom/rules_sub.json"});
        assert_eq!(
            subs_path(&cfg, Some(Path::new("conf/config.json"))),
            PathBuf::from("conf").join("custom/rules_sub.json")
        );
        // 无目录信息 / 目录为空 → 退回原值（进程 CWD）。
        assert_eq!(
            subs_path(&cfg, None),
            PathBuf::from("custom/rules_sub.json")
        );
        assert_eq!(
            subs_path(&cfg, Some(Path::new("config.json"))),
            PathBuf::from("custom/rules_sub.json")
        );
        // 绝对路径原样。
        let abs = std::env::temp_dir().join("ebpdns-abs-subs.json");
        let cfg = json!({"rule_sub_file": abs.display().to_string()});
        assert_eq!(subs_path(&cfg, Some(Path::new("conf/config.json"))), abs);
    }

    /* ---- F20：rule_from_json 丢弃计入失败判定 ---- */

    #[test]
    fn rebuild_stats_count_dropped_rules() {
        fn st(indexed: usize, rejected: usize, dropped: usize) -> RebuildStats {
            RebuildStats {
                indexed,
                rejected,
                dropped,
                // 2.1.23：本用例只覆盖"丢条目 ⇒ 失败"的老口径，真源不可解析单列。
                source_unreadable: false,
            }
        }
        let subs = vec![json!({
            "url": "https://x/r",
            "action": "block",
            "rules": [{"match": "  "}, {"match": "*.ok.com"}, "not-an-object"],
        })];
        let (rules, dropped) = sub_rules_with_drops(&subs);
        assert_eq!(rules.len(), 1, "只有 *.ok.com 能进索引");
        assert_eq!(dropped, 2, "空 match 与非对象条目都必须计数");
        // 全部死在进索引之前 → 判失败（旧实现 indexed/rejected 都是 0 → 误判成功）。
        assert!(st(0, 0, 2).failed());
        assert!(st(0, 3, 0).failed());
        assert!(!st(1, 0, 2).failed());
        assert!(!st(0, 0, 0).failed(), "空规则集不算失败");
        assert!(check_rebuild(st(0, 0, 1)).is_err());
        assert!(check_rebuild(st(0, 0, 0)).is_ok());
        // forceIp 缺合法 ip → rule_from_json 丢弃。
        let bad = vec![json!({
            "url": "https://x/r",
            "action": "forceIp",
            "ip": "not-an-ip",
            "rules": [{"match": "*.dead.com"}],
        })];
        let (r, d) = sub_rules_with_drops(&bad);
        assert!(r.is_empty());
        assert_eq!(d, 1);
    }

    /* ---- F22：订阅列表以明细为准 ---- */

    #[test]
    fn subscriptions_view_prefers_details_file() {
        let meta = vec![
            json!({"url": "https://a/r", "action": "block", "group": "global",
                   "ip": "1.2.3.4", "count": 99, "updated_at": "2020-01-01 00:00:00"}),
            json!({"url": "https://meta-only/r", "action": "group", "group": "domestic",
                   "count": 7}),
        ];
        let subs = vec![
            json!({"url": "https://a/r", "action": "block", "group": "global",
                   "ip": "1.2.3.4", "updated_at": "2026-01-02 03:04:05",
                   "rules": [{"match": "*.a.com"}, {"match": "*.b.com"}]}),
            json!({"url": "https://file-only/r", "action": "allow",
                   "rules": [{"match": "*.c.com"}]}),
        ];
        let v = subscriptions_from(&subs, &meta);
        assert_eq!(v.len(), 3, "明细有 / 仅 config 有的订阅都必须出现: {v:?}");
        assert_eq!(v[0]["url"], json!("https://a/r"));
        assert_eq!(v[0]["count"], json!(2), "count 必须取 len(rules)");
        assert_eq!(v[0]["updated_at"], json!("2026-01-02 03:04:05"));
        assert_eq!(v[1]["url"], json!("https://file-only/r"));
        assert_eq!(v[1]["count"], json!(1));
        // **[历史归因]** 明细缺 group/ip → 回退 meta（meta 也没有则空串，对齐 Python `or ""`）。
        assert_eq!(v[1]["group"], json!(""));
        assert_eq!(v[1]["ip"], json!(""));
        assert_eq!(v[2]["url"], json!("https://meta-only/r"));
        assert_eq!(v[2]["count"], json!(7), "无明细时回退 meta");
        assert_eq!(v[2]["group"], json!("domestic"));
        assert_eq!(v[2]["updated_at"], json!(""));
    }

    /* ---- F07：订阅面与规则面共用同一把事务锁 ---- */

    /// 最小 `AppState`（同 `rules_admin` 测试的构造方式，便于订阅端点级测试）。
    fn test_state(cfg_path: Option<PathBuf>) -> AppState {
        use crate::state::RestartSignal;
        use ebpdns_resolver::clock::RealClock;
        use ebpdns_resolver::config::ResolverConfig;
        use ebpdns_resolver::query::ScriptedQuerier;
        use ebpdns_resolver::Resolver;
        use parking_lot::RwLock;
        use std::sync::Arc;

        let tel = Arc::new(crate::telemetry::ServerTelemetry::new());
        let q = ScriptedQuerier::new(|_n, _t, _d| vec![]);
        let resolver = Resolver::new(
            ResolverConfig::default(),
            tel.clone(),
            Arc::new(RealClock::default()),
            Arc::new(q),
        );
        AppState {
            resolver,
            cfg: Arc::new(RwLock::new(json!({"rules": []}))),
            cfg_path,
            telemetry: tel,
            api_host: Arc::new(RwLock::new("127.0.0.1".to_string())),
            api_port: 8353,
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

    /// 订阅面的互斥函数就是 `rules_admin` 的规则事务锁：同一实例 → 相互排斥。
    #[tokio::test]
    async fn subscribe_txn_lock_is_shared_with_rules_transaction() {
        assert!(
            std::ptr::eq(sub_txn(), crate::rules_admin::rules_txn()),
            "订阅面与规则面必须共用同一把锁（两把锁 = 没有互斥）"
        );
        let guard = sub_txn().lock().await;
        assert!(
            crate::rules_admin::rules_txn().try_lock().is_err(),
            "持锁期间规则事务必须被挡住"
        );
        drop(guard);
        // `sub_txn()` 是**进程级静态锁**（rules_admin.rs:74 的 `static`），不能用
        // `try_lock()` 断言「此刻必然空闲」——那是进程属性，不是本用例属性：同一测试
        // 二进制里的兄弟用例会并行持锁（`delete_waits_for_shared_txn_lock` 在
        // subscribe.rs:1951-1957 持锁 ≥50ms；rules_admin.rs:815/890/990 也竞争同一把锁），
        // 于是断言全局静默会与它们互相踩踏（实测 10 次连跑 3 次偶发失败，
        // `--test-threads=1` 恒过、默认多线程 ~30% 失败）。
        // 改为「释放后可再次获取 + 再次持锁期间仍互斥」：验证的仍是「解锁生效」与
        // 「订阅面/规则面共用同一把锁」，但不依赖其它用例的时序假设。
        let again = sub_txn().lock().await;
        assert!(
            sub_txn().try_lock().is_err(),
            "再次持锁期间规则事务必须被挡住"
        );
        drop(again);
    }

    /// 顺序模拟并发：持锁期间订阅 `delete` 必须排队，解锁后才生效。
    #[tokio::test]
    async fn delete_waits_for_shared_txn_lock() {
        let dir = std::env::temp_dir().join(format!("ebpdns-sub-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mk dir");
        let cfg_path = dir.join("config.json");
        let state = test_state(Some(cfg_path.clone()));
        let path = subs_path(&state.cfg.read(), Some(cfg_path.as_path()));
        save_subs(
            &path,
            &[json!({"url": "https://a/r", "action": "block", "rules": []})],
        )
        .expect("save");
        set_cfg_meta(
            &state,
            &[json!({"url": "https://a/r", "action": "block", "count": 0})],
        );

        let guard = sub_txn().lock().await;
        let s2 = state.clone();
        let task = tokio::spawn(async move { delete(s2, "https://a/r").await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!task.is_finished(), "持锁期间订阅 delete 不得完成");
        assert_eq!(load_subs(&path).len(), 1, "持锁期间明细不得被改");
        drop(guard);
        let out = task.await.expect("join").expect("delete ok");
        assert_eq!(out["ok"], json!(true));
        assert!(load_subs(&path).is_empty(), "解锁后 delete 生效");
        assert!(cfg_meta(&state).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // >>> 242B BEGIN T-subs >>> //
    /// **2.1.42-B（P1-11）**：BOM + 单条坏行必须"跳过并计数"，而不是整份清空。
    #[test]
    fn p1_11_bom_and_bad_lines_are_skipped_not_wiped() {
        let dir = std::env::temp_dir().join(format!(
            "ebpdns_sub_242b_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|x| x.as_millis())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("rules_sub.json");
        let body = br#"{"subscriptions":[{"action":"block","rules":[{"match":"ok.test"},null,{"match":123}]}]}"#;
        let mut with_bom = vec![0xEF, 0xBB, 0xBF];
        with_bom.extend_from_slice(body);
        std::fs::write(&p, with_bom).unwrap();
        let (rules, dropped, unreadable) = sub_rules_from_path(&p, None);
        assert!(!unreadable, "BOM 不得被判 unreadable");
        assert_eq!(rules.len(), 1, "只有合法条目进索引");
        assert_eq!(dropped, 2, "两条坏行按单条跳过并计数");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **2.1.42-B（P1-11）**：整份 JSON 语法错误 ⇒ unreadable（调用方保留旧索引 + 5xx）。
    #[test]
    fn p1_11_whole_file_corruption_is_unreadable_not_silent_empty() {
        let dir = std::env::temp_dir().join(format!(
            "ebpdns_sub_242b_bad_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|x| x.as_millis())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("rules_sub.json");
        std::fs::write(&p, br#"{"subscriptions":[{"rules":[}"#).unwrap();
        let (rules, _dropped, unreadable) = sub_rules_from_path(&p, None);
        assert!(unreadable, "语法错误必须 unreadable");
        assert!(rules.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
    // >>> M-247 BEGIN tests >>> //
    /// `/proc/self/statm` 的 RSS（KB；Linux 页 4 KB）。
    #[cfg(target_os = "linux")]
    fn m247_rss_kb() -> u64 {
        std::fs::read_to_string("/proc/self/statm")
            .ok()
            .and_then(|s| {
                s.split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse::<u64>().ok())
            })
            .unwrap_or(0)
            * 4
    }

    /// **2.1.47 / M-247 回归（RSS）**：`reload x10` 的 RSS 增量必须 <= 阈值（默认 10 MB）。
    ///
    /// 隔离实例等价物：独立 `config.json` + 5 万条订阅规则 + 真实重建入口
    /// `rebuild_all_disk_stats`；阈值可用 `EBPDNS_RELOAD_RSS_MAX_MB` 覆盖。
    /// 修复前：每次 reload 全量重建 10 万条规则 -> 10 次约 +40~90 MB（必红）；
    /// 修复后：来源字节未变 -> 第 2~10 次复用索引，RSS 增量 ~0。
    #[cfg(target_os = "linux")]
    #[test]
    fn m247_reload_ten_times_rss_growth_is_bounded() {
        let dir = std::env::temp_dir().join(format!(
            "ebpdns_m247_rss_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|x| x.as_millis())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg_path = dir.join("config.json");
        std::fs::write(&cfg_path, br#"{"rule_sub_interval":0}"#).unwrap();
        let n = 50_000usize;
        let mut items = String::with_capacity(n * 32);
        for i in 0..n {
            if i > 0 {
                items.push(',');
            }
            items.push_str(&format!(r#"{{"match":"m247-{i:06}.example"}}"#));
        }
        let body = format!(
            r#"{{"subscriptions":[{{"url":"https://example.invalid/m247.txt","action":"block","group":"global","count":{n},"rules":[{items}]}}]}}"#
        );
        std::fs::write(dir.join("rules_sub.json"), &body).unwrap();

        let state = test_state(Some(cfg_path));
        *state.cfg.write() = json!({"rules": [], "rule_sub_interval": 0});
        let s0 = rebuild_all_disk_stats(&state);
        assert_eq!(s0.indexed, n, "首轮必须真正建出 5 万条索引");
        assert!(!s0.failed());
        state.resolver.trim_allocator();
        let rss0 = m247_rss_kb();
        for k in 1..=10 {
            let s = rebuild_all_disk_stats(&state);
            assert_eq!(s.indexed, n, "第 {k} 次 reload 必须复用同一规则集");
            assert_eq!(s.rejected, 0, "第 {k} 次 reload 不得判废规则");
        }
        state.resolver.trim_allocator();
        let rss1 = m247_rss_kb();
        let max_kb = std::env::var("EBPDNS_RELOAD_RSS_MAX_MB")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(10)
            * 1024;
        let delta = rss1.saturating_sub(rss0);
        assert!(
            delta <= max_kb,
            "reload x10 的 RSS 增量 {delta} KB 超过阈值 {max_kb} KB（EBPDNS_RELOAD_RSS_MAX_MB 可调）"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **2.1.47 / M-247 回归（语义）**：来源未变 ⇒ `rule_gen`/索引都不变（复用不等于清空）；
    /// 来源**真变** ⇒ 必须触发真正重建并反映新条数。
    #[test]
    fn m247_unchanged_source_keeps_gen_and_changed_source_rebuilds() {
        let dir = std::env::temp_dir().join(format!(
            "ebpdns_m247_sem_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|x| x.as_millis())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg_path = dir.join("config.json");
        std::fs::write(&cfg_path, br#"{"rule_sub_interval":0}"#).unwrap();
        let sub = dir.join("rules_sub.json");
        std::fs::write(
            &sub,
            br#"{"subscriptions":[{"url":"https://example.invalid/x","action":"block","rules":[{"match":"a.m247.example"},{"match":"b.m247.example"}]}]}"#,
        )
        .unwrap();
        let state = test_state(Some(cfg_path));
        *state.cfg.write() = json!({"rules": [], "rule_sub_interval": 0});

        let s1 = rebuild_all_disk_stats(&state);
        assert_eq!(s1.indexed, 2);
        let g1 = state.resolver.rule_gen();
        let s2 = rebuild_all_disk_stats(&state);
        assert_eq!(s2.indexed, 2, "复用路径必须返回同一统计");
        assert_eq!(
            state.resolver.rule_gen(),
            g1,
            "来源未变 ⇒ rule_gen 必须不变"
        );
        assert_eq!(state.resolver.rule_count(), 2, "复用路径不得清空索引");

        std::fs::write(
            &sub,
            br#"{"subscriptions":[{"url":"https://example.invalid/x","action":"block","rules":[{"match":"a.m247.example"},{"match":"b.m247.example"},{"match":"c.m247.example"}]}]}"#,
        )
        .unwrap();
        let s3 = rebuild_all_disk_stats(&state);
        assert_eq!(s3.indexed, 3, "来源真变必须真正重建");
        assert_ne!(
            state.resolver.rule_gen(),
            g1,
            "规则内容变化 ⇒ rule_gen 必须变"
        );
        assert_eq!(state.resolver.rule_count(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }
    // <<< M-247 END tests >>> //

    // >>> M-248 BEGIN tests >>> //
    /// **2.1.48 / M-248 回归（结构）**：Agent 必须是**进程级单例** —— 连续 10 次取用
    /// 返回同一个 `&'static Agent`（旧实现每次刷新/每跳新建一个 ⇒ TLS 配置/连接池 churn）。
    #[test]
    fn m248_subscription_agent_is_process_singleton() {
        let first: *const ureq::Agent = subscription_agent();
        for _ in 0..10 {
            let again: *const ureq::Agent = subscription_agent();
            assert_eq!(again, first, "subscription_agent() 必须是同一个实例");
        }
        // 单例上仍是订阅专用网关（超时/https_only/redirect/proxy 见上一用例）。
        assert!(subscription_agent().config().https_only());
    }

    /// **2.1.48 / M-248 回归（语义）**：线程局部钉死表**只对当前线程、当前请求**生效；
    /// 释放后立刻 fail-closed，且不同线程之间不串（并发拉取互不影响）。
    #[test]
    fn m248_pin_guard_is_thread_local_and_fail_closed() {
        let cfg = ureq::config::Config::default();
        let r = PinnedResolver;
        let uri: ureq::http::Uri = "https://pin-scope.invalid/x".parse().unwrap();
        let addr: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let guard = PinGuard::install("pin-scope.invalid".to_string(), vec![addr]);
        assert_eq!(&r.resolve(&uri, &cfg, next_timeout()).unwrap()[..], &[addr]);

        // 另一个线程没有安装过钉死项 ⇒ 必须拒绝（绝不回退 DNS）。
        let handle = std::thread::spawn(move || {
            let cfg = ureq::config::Config::default();
            let uri: ureq::http::Uri = "https://pin-scope.invalid/x".parse().unwrap();
            PinnedResolver.resolve(&uri, &cfg, next_timeout()).is_err()
        });
        assert!(handle.join().unwrap(), "钉死表不得跨线程泄漏");
        drop(guard);
        assert!(
            r.resolve(&uri, &cfg, next_timeout()).is_err(),
            "guard 释放后必须 fail-closed"
        );
    }
    // <<< M-248 END tests >>> //

    // >>> M-248 AUD BEGIN tests >>> //
    /// **2.1.48 / AUD-01**：缺 `subscriptions` 键的文件必须判 unreadable（5xx + 保留旧索引），
    /// 只有 JSON 语法错误才算坏文件的旧行为会静默清空十万条订阅规则。
    #[test]
    fn m248_aud01_missing_subscriptions_key_is_unreadable() {
        let dir = std::env::temp_dir().join(format!(
            "ebpdns_m248_aud01_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        for (i, body) in ["{}", r#"{"foo":1}"#, r#"{"subscriptions":"x"}"#]
            .iter()
            .enumerate()
        {
            let p = dir.join(format!("bad{i}.json"));
            std::fs::write(&p, body).unwrap();
            let (rules, _d, unreadable) = sub_rules_from_path(&p, None);
            assert!(unreadable, "{body} 必须判 unreadable（不得静默当空表）");
            assert!(rules.is_empty());
        }
        // 显式空数组是合法空表（与“缺键”不同）。
        let p = dir.join("ok.json");
        std::fs::write(&p, r#"{"subscriptions":[]}"#).unwrap();
        let (rules, _d, unreadable) = sub_rules_from_path(&p, None);
        assert!(!unreadable && rules.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **2.1.48 / AUD-03**：配置里删除的订阅不得再从 `rules_sub.json` 进索引。
    #[test]
    fn m248_aud03_config_deleted_subscription_is_not_indexed() {
        let dir = std::env::temp_dir().join(format!(
            "ebpdns_m248_aud03_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg_path = dir.join("config.json");
        std::fs::write(&cfg_path, br#"{"rule_sub_interval":0}"#).unwrap();
        std::fs::write(
            dir.join("rules_sub.json"),
            br#"{"subscriptions":[
                {"url":"https://a.invalid/x","action":"block","rules":[{"match":"*.a.invalid"}]},
                {"url":"https://b.invalid/x","action":"block","rules":[{"match":"*.b.invalid"}]}
            ]}"#,
        )
        .unwrap();
        let state = test_state(Some(cfg_path));
        *state.cfg.write() = json!({
            "rules": [],
            "rule_sub_interval": 0,
            "rule_subscriptions": [{"url": "https://a.invalid/x", "count": 1}]
        });
        let s1 = rebuild_all_disk_stats(&state);
        assert_eq!(s1.indexed, 1, "只应索引仍在 config 中的订阅 a");
        // 配置把 a 也删光 ⇒ 下一轮重建必须变成 0（不许旧订阅继续生效）。
        *state.cfg.write() = json!({
            "rules": [],
            "rule_sub_interval": 0,
            "rule_subscriptions": []
        });
        let s2 = rebuild_all_disk_stats(&state);
        assert_eq!(s2.indexed, 0, "配置已删光订阅 ⇒ 索引不得再有订阅规则");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **2.1.48 / AUD-05 + AUD-14**：摘要表必须能随删除收敛（delete 清 digest）。
    #[test]
    fn m248_aud05_digest_remove_and_retain() {
        sub_digest_set("https://a.invalid/x", 11);
        sub_digest_set("https://b.invalid/x", 22);
        assert_eq!(sub_digest_get("https://a.invalid/x"), Some(11));
        sub_digest_remove("https://a.invalid/x");
        assert_eq!(sub_digest_get("https://a.invalid/x"), None);
        let mut keep = HashSet::new();
        keep.insert("https://b.invalid/x".to_string());
        sub_digest_retain(&keep);
        assert_eq!(sub_digest_get("https://b.invalid/x"), Some(22));
        sub_digest_retain(&HashSet::new());
        assert_eq!(sub_digest_get("https://b.invalid/x"), None);
    }
    // <<< M-248 AUD END tests >>> //

    // <<< 242B END T-subs <<< //

    /// **2.1.49（AUD-13）**：订阅摘要 = SHA-256 前 128 位（标准向量）。
    #[test]
    fn m249_aud13_sub_digest_is_sha256_first_128_bits() {
        assert_eq!(
            format!("{:032x}", sub_digest_text("abc")),
            "ba7816bf8f01cfea414140de5dae2223",
            "2.1.48 的 FNV-1a 值会红"
        );
    }

    /// **2.1.49（AUD-15）**：来源指纹由**传入的订阅字节**决定，A/B 不同且同字节稳定。
    #[test]
    fn m249_aud15_source_fp_is_function_of_supplied_bytes() {
        let dir = std::env::temp_dir().join(format!("ebpdns-m249-fp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mk dir");
        let state = test_state(Some(dir.join("config.json")));
        *state.cfg.write() = json!({"rules": [], "rule_subscriptions": []});
        let a = br#"{"subscriptions":[]}"#;
        let b = br#"{"subscriptions":[{"url":"https://b.invalid/x","rules":[]}]}"#;
        let fa = rule_sources_fingerprint_from(&state, Some(a), true);
        let fb = rule_sources_fingerprint_from(&state, Some(b), true);
        assert_ne!(fa, fb, "A/B 字节必须产生不同指纹");
        assert_eq!(
            fa,
            rule_sources_fingerprint_from(&state, Some(a), true),
            "相同字节必须产生相同指纹"
        );
        assert_eq!(
            rule_sources_fingerprint_from(&state, Some(a), false),
            0,
            "读取失败必须让指纹失效（走完整 fail-closed 路径）"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **2.1.49（AUD-14）**：删除订阅时即使在**重建失败**的路径上也要清掉 digest。
    ///
    /// 2.1.48 把 `sub_digest_remove` 放在 `check_rebuild(...)?` 之后；本用例用一条
    /// 会被丢弃的本地规则让重建失败，旧实现提前返回 ⇒ digest 残留（红）。
    #[tokio::test]
    async fn m249_aud14_delete_removes_digest_before_rebuild() {
        let dir = std::env::temp_dir().join(format!("ebpdns-m249-digest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mk dir");
        let cfg_path = dir.join("config.json");
        let state = test_state(Some(cfg_path.clone()));
        let url = "https://m249.invalid/digest";
        *state.cfg.write() = json!({
            "rules": [{"match": "re:(", "action": "block"}],
            "rule_subscriptions": [{"url": url, "action": "block"}],
        });
        let path = subs_path(&state.cfg.read(), Some(cfg_path.as_path()));
        save_subs(
            &path,
            &[json!({"url": url, "action": "block", "rules": [{"match": "*.m249.invalid"}]})],
        )
        .expect("save subs");
        sub_digest_set(url, 42);
        assert_eq!(sub_digest_get(url), Some(42));

        let err = delete(state, url).await.expect_err("重建失败必须返回 5xx");
        assert!(
            matches!(err, ServerError::Internal),
            "期望 Internal，实际 {err:?}"
        );
        assert_eq!(
            sub_digest_get(url),
            None,
            "重建失败也不得把已删除 URL 的 stale digest 留在表里"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
