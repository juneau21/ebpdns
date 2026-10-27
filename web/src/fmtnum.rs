//! 纯数值/文本展示助手（**不依赖 wasm**）：便于 native 侧复用与验证
//! （`tools/pollsim` 用 `include!` 引入本文件，对同一份代码做断言与输出核对）。
//!
//! `fmt` 模块按 `pub use` 重导出这里的全部名字，因此调用点仍是 `fmt::num0(...)` 等。

/// 数字归一（NaN/Inf → 0），对齐 `_n()`。
pub fn n(v: f64) -> f64 {
    if v.is_finite() {
        v
    } else {
        0.0
    }
}

/// `f64` → 整数字符串的显式边界处理（D21）。
///
/// `f64 as i64` 自 Rust 1.45 起是**饱和转换**：`f64::MAX as i64` 会静默变成
/// `i64::MAX`（9223372036854775807），把一个明显的异常值伪装成合法计数。
/// 超出 i64 可表示范围时改为科学计数法（保留量级信息），绝不静默饱和。
/// 边界：`-2^63`（`i64::MIN`）本身可精确表示，`2^63` 不可（`i64::MAX = 2^63-1`）。
fn i64_text(v: f64) -> String {
    /// 2^63：i64 上界之外、下界（`i64::MIN`）恰好等于 `-2^63`。
    const LIMIT: f64 = 9_223_372_036_854_775_808.0;
    if (-LIMIT..LIMIT).contains(&v) {
        format!("{}", v as i64)
    } else {
        format!("{v:e}")
    }
}

/// 取整显示。
pub fn num0(v: f64) -> String {
    i64_text(n(v).round())
}

/// 一位小数。
pub fn num1(v: f64) -> String {
    format!("{:.1}", n(v))
}

/// Option 一位小数，None/非有限 → `–`。
///
/// `#[allow(dead_code)]`（2.1.14 清零告警）：当前页面统一走 `lat_auto` / `num1`，
/// 本函数只被 fmtnum 自身单测覆盖；保留是因为它是原件同名助手集合的一员，
/// 且 `pollsim` 与本文件共享源码（未来显示改动可直接复用，不必重写）。
#[allow(dead_code)]
pub fn opt_num1(v: Option<f64>) -> String {
    match v {
        Some(x) if x.is_finite() => format!("{x:.1}"),
        _ => "–".into(),
    }
}

/// 百分比一位小数（入参已是 0..100）。
pub fn pct1(v: f64) -> String {
    format!("{:.1}%", n(v))
}

/// 大数字千分位（Top N / 计数器用，1.9.162 为原样输出，这里保持一致不分组）。
///
/// `#[allow(dead_code)]`：与 [`opt_num1`] 同因（原件同名助手，页面改用 `group0`）。
#[allow(dead_code)]
pub fn int(v: f64) -> String {
    i64_text(n(v))
}

/* ===================== v2.1.7 显示效果助手 ===================== */

/// 给纯整数串插入千分位（`-1234567` → `-1,234,567`）。
///
/// 只处理「可选负号 + 全数字」；科学计数法（`1.2e19`）等异常形状原样返回，
/// 保证 D21 的「禁止静默饱和」语义不被破坏。
fn group_digits(s: &str) -> String {
    let (sign, digits) = match s.strip_prefix('-') {
        Some(r) => ("-", r),
        None => ("", s),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return s.to_string();
    }
    let n = digits.len();
    let mut out = String::with_capacity(n + n / 3 + 1);
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (n - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    format!("{sign}{out}")
}

/// 千分位整数（KPI / 表格里的大计数）。
pub fn group0(v: f64) -> String {
    group_digits(&num0(v))
}

/// 千分位 + 1 位小数。
///
/// `#[allow(dead_code)]`：与 [`opt_num1`] 同因（原件同名助手，页面改用 `group0`）。
#[allow(dead_code)]
pub fn group1(v: f64) -> String {
    let s = num1(v);
    match s.split_once('.') {
        Some((a, b)) => format!("{}.{}", group_digits(a), b),
        None => group_digits(&s),
    }
}

/// 延迟统一单位：小于 1000 ms 一律用 ms（2 位小数，如 `0.42 ms`），
/// 1000 ms 及以上用 s（2 位小数）。返回 `(数值文本, 单位)`；非有限/非正值 → `("–", "")`。
pub fn lat_auto(ms: f64) -> (String, &'static str) {
    if !ms.is_finite() || ms <= 0.0 {
        return ("–".to_string(), "");
    }
    if ms < 1000.0 {
        (format!("{ms:.2}"), "ms")
    } else {
        (format!("{:.2}", ms / 1000.0), "s")
    }
}

/// 超长值截断（表格/日志列显示用）：超过 `max` 个字符 → 保留前 `max-1` 个 + `…`。
pub fn trunc(s: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    let n = s.chars().count();
    if n <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// 简易包含匹配（大小写不敏感）。
pub fn contains_ci(hay: &str, needle: &str) -> bool {
    hay.to_lowercase().contains(&needle.to_lowercase())
}

/* ===================== 2.1.19（修复项 3 / R9）：缓存落盘现场 ===================== */

/// `age_s`（距最近一次落盘的秒数）→ 人类可读时长。
///
/// 口径：`<60s` → `Ns`；`<1h` → `Nm Ss`；`<1d` → `Nh Mm`；否则 `Nd Nh`。
/// `age_s == 0` 有两种可能（"刚刚落盘"或"文件不存在 ⇒ 后端下发 0"），
/// 因此**不能**靠本函数区分空态 —— 空态由 [`persist_rows`] 的 `exists`/`enabled` 决定。
pub fn age_text(age_s: u64) -> String {
    if age_s < 60 {
        format!("{age_s}s 前")
    } else if age_s < 3600 {
        format!("{}m {}s 前", age_s / 60, age_s % 60)
    } else if age_s < 86_400 {
        format!("{}h {}m 前", age_s / 3600, (age_s % 3600) / 60)
    } else {
        format!("{}d {}h 前", age_s / 86_400, (age_s % 86_400) / 3600)
    }
}

/// 字节数 → `B` / `KiB` / `MiB`（保留 1 位小数，KiB 以上）。
pub fn bytes_text(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    }
}

/// **R9 的唯一取值口径**：把 `/api/status.cache.persist`（= 后端
/// `api.rs::cache_persist_info` 的**同一份** JSON）渲染成 `(标签, 值)` 行。
///
/// 三种状态各有**互不混淆**的文案（这是 R9 的硬要求）：
/// 1. `enabled == false`            ⇒ 「未开启持久化」+ 路径；
/// 2. `enabled == true, exists==false` ⇒ 「未落盘（文件不存在）」+ 路径；
/// 3. `exists == true`              ⇒ 路径 + 最近落盘时间（`age_text`）+ 条目数 + 文件大小。
///
/// `mem_entries` 是**内存**条目数（后端 `cache.persist.entries`）；文件名条数只有
/// 落盘那一刻才知道，因此本函数把它标成「内存条目」而不是"文件里有多少条"。
pub fn persist_rows(
    enabled: bool,
    exists: bool,
    file: &str,
    age_s: u64,
    bytes: u64,
    mem_entries: u64,
    interval_s: u64,
) -> Vec<(String, String)> {
    let path = if file.trim().is_empty() {
        "—".to_string()
    } else {
        file.to_string()
    };
    if !enabled {
        return vec![
            ("落盘".to_string(), "未开启持久化".to_string()),
            ("路径".to_string(), path),
        ];
    }
    if !exists {
        return vec![
            ("落盘".to_string(), "未落盘（缓存文件不存在）".to_string()),
            ("路径".to_string(), path),
            (
                "周期".to_string(),
                if interval_s == 0 {
                    "仅优雅退出落盘".to_string()
                } else {
                    format!("每 {interval_s} s")
                },
            ),
        ];
    }
    let mut rows = vec![
        ("路径".to_string(), path),
        ("最近落盘".to_string(), age_text(age_s)),
        (
            "内存条目".to_string(),
            format!("{} 条", group0(mem_entries as f64)),
        ),
        ("文件大小".to_string(), bytes_text(bytes)),
    ];
    rows.push((
        "周期".to_string(),
        if interval_s == 0 {
            "仅优雅退出落盘".to_string()
        } else {
            format!("每 {interval_s} s")
        },
    ));
    rows
}

/// `age_s` 是否说明**未按周期落盘**（> 2×interval，且 interval>0）。
///
/// 判据来源：后端 `cache_persist_info` 的 `note` 用的是**同一口径**（2×interval），
/// 这里再算一遍是为了让 UI 能给出红色标记，而不必解析后端文案。
pub fn persist_stale(age_s: u64, interval_s: u64) -> bool {
    interval_s > 0 && age_s > interval_s.saturating_mul(2)
}

/// **2.1.19（修复项 1）**：启动恢复丢弃计数的**一行文案**。
///
/// 输入 = `/api/status.cache.restore_drops`（后端 `DnsCache::last_restore_drops` +
/// `last_restore_window_unpersisted`）。三种状态必须可分辨（2.1.18 这三者只能从多行日志里拼）：
/// * 全 0 ⇒「本次启动无丢弃」；
/// * 只有 `legacy > 0` ⇒ **旧格式**被安全侧丢弃（**符合预期**，并说明下次落盘会写新格式）；
/// * `failed > 0` ⇒ 记录损坏（**需要关注**：文件可能被截断/由不兼容版本写入）。
///
/// **2.1.43-B（P2-4）**：新增 `window_unpersisted`（TinyLFU 恢复只灌 main 段 ⇒ 被挤出的
/// ≈1% window 段条目）。它**不是**"记录损坏"，必须与 `failed` 分开表述，否则运维会去查
/// 磁盘损坏（而实际是设计内的容量口径）。全 0 的判据包含它 ⇒ "无丢弃"不再说谎。
pub fn restore_drops_text(
    expired: u64,
    legacy: u64,
    failed: u64,
    window_unpersisted: u64,
) -> String {
    if expired == 0 && legacy == 0 && failed == 0 && window_unpersisted == 0 {
        return "本次启动无丢弃".to_string();
    }
    let mut parts = Vec::new();
    if legacy > 0 {
        parts.push(format!(
            "旧格式 {legacy} 条（已按安全侧丢弃，下次落盘写新格式）"
        ));
    }
    if expired > 0 {
        parts.push(format!("绝对到期已过 {expired} 条"));
    }
    if failed > 0 {
        parts.push(format!("记录损坏 {failed} 条（文件可能被截断）"));
    }
    if window_unpersisted > 0 {
        parts.push(format!(
            "window 段未回放 {window_unpersisted} 条（≈1% 容量口径，已计入恢复丢失率）"
        ));
    }
    parts.join(" · ")
}

/* ===== 2.1.20（A-02）：整数配置键的**兜底**范围表 + 夹取（native 可测） ===== */

/// **2.1.20（A-02 修复：前端未接线 `/api/status.config_ranges`）**：整数配置键的
/// **本地兜底范围表**（`(键, 最小, 最大)`）。
///
/// ⚠️ **维护方式（2.1.21 第 2 轮 / E12 措辞纠正）**：交付树里它是一份**手工维护的
/// 静态 `const`** —— "由脚本从两处代码派生"只描述了**修复方流水线**的生成方式，
/// 那个派生脚本**不进包**。因此改控制台控件时必须同步改本表；机器门禁
/// `a15_key_coverage.rs` 会**双向**比对（控件键集 == 本表键集 == 后端
/// `CONFIG_RANGES` 里"有控件"的整数键集），改错一边即红。
///
/// 为什么需要它、以及为什么它只是"兜底"而不是"权威"：
/// * 审计 A-02 实测：后端 2.1.19 已下发 30 条 `config_ranges`，但 `grep config_ranges web/src`
///   **0 命中** ⇒ 控制台仍用**硬编码**范围，**6 个键能摆出后端必然 400 的值**
///   （`cache_size` 下限 1<16、`ttl`/`ttl_min`/`ttl_max` 上限 2^31-1>604800、
///   `stale_ttl` 8640000>604800、`speed_interval_ms` 下限 0<100、
///   `health_check_interval` 604800>86400）；而 `PUT /api/config` 是**整份提交**
///   ⇒ **一个坏值让全部编辑一起失败**（用户看到的就是"改配置存不进去"）。
/// * 现在：控制台 `dom_clamped_key` **运行期**读 `/api/status.config_ranges`（权威）；
///   本表只在**旧后端不返回该字段**时兜底，并由机器校验单测钉死
///   **逐键等于后端的 `CONFIG_RANGES`**（`ebpdns-resolver/src/config.rs`）。
///
/// ⚠️ **维护规则（2.1.21 / DEF-220-02 起为双向约束）**：
/// 1. 每一项都必须与后端 `CONFIG_RANGES` **逐键同值**；
/// 2. 每一项都必须**在控制台真的有写路径**（`dom_clamped_key(app, "<键>", …)`）。
///
/// 为什么不许再出现"只在表里、没有控件"的键（审计 DEF-220-02）：2.1.20 的表里有
/// **12 个前端根本不能设的键**（它们只为通过"表对表"单测而存在）⇒ 运维照着
/// 这张表找控件永远找不到。现在 `a15_key_coverage.rs` 的三条单测**双向**钉死：
/// 前端控件键集 == 本表键集 == 后端 `CONFIG_RANGES` 里"有控件"的整数键集。
///
/// 没有区间的可写键（`cache_partitions` / `edns_client_subnet` /
/// `adaptive_parallel` / `adaptive_timeout`）**不进本表**，
/// 它们在 README 的「仅 API / 配置文件可改」表里逐键登记。
pub const CONFIG_RANGE_FALLBACK: &[(&str, i64, i64)] = &[
    // **2.1.21（DEF-220-02 / A-15）**：本表由脚本从**两处代码**派生（不手工维护）：
    //   ① 控制台真的有 clamp 路径的键 = `web/src/pages/config.rs` 的
    //      `dom_clamped_key(app, "<键>", …)`；
    //   ② 后端权威区间 = `ebpdns-resolver/src/config.rs` 的 `CONFIG_RANGES`。
    // 取**交集**并按后者的边界取值 ⇒「表里有键、界面没控件」这种形态结构上不可能
    // 再出现（那正是 DEF-220-02：12 个键只为过『表对表』单测而存在）。
    // 没有区间、只能改 API/配置文件的键（`cache_partitions` /
    // `edns_client_subnet` / `adaptive_parallel` /
    // `adaptive_timeout` / `cb_fails` / `cb_open_s`）见 README 的分类表。
    ("adaptive_timeout_min_ms", 1, 60_000),
    ("cache_save_interval", 0, 86_400),
    ("cache_size", 16, 4_194_304),
    ("circuit_fails", 1, 1000),
    ("circuit_open_max_s", 1, 604_800),
    ("edns_client_max_size", 512, 65_535),
    ("edns_udp_size", 512, 65_535),
    ("health_check_interval", 0, 86_400),
    ("health_probe_timeout_ms", 1, 60_000),
    ("hedge_after_ms", 1, 60_000),
    ("ip_speed_cache_ttl", 0, 86_400),
    ("max_parallel_upstreams", 1, 64),
    ("neg_ttl_max", 0, 86_400),
    ("nxdomain_quorum", 1, 64),
    ("persist_ttl", 0, 31_536_000),
    ("prefetch_interval", 1, 86_400),
    ("prefetch_max", 1, 1_000_000),
    ("prefetch_target", 0, 604_800),
    ("prefetch_trigger", 0, 604_800),
    ("probe_timeout_ms", 0, 60_000),
    ("rfc8020_max_labels", 1, 127),
    ("rule_sub_interval", 0, 604_800),
    ("speed_interval_ms", 100, 600_000),
    ("speed_timeout_ms", 1, 60_000),
    ("stale_ttl", 0, 604_800),
    ("timeout_ms", 1, 60_000),
    ("ttl", 0, 604_800),
    ("ttl_max", 0, 604_800),
    ("ttl_min", 0, 604_800),
    ("udp_workers", 0, 64),
    ("upstream_max_inflight", 0, 4096),
    ("warmup_queries", 1, 8),
    ("warmup_timeout_ms", 1, 60_000),
];

/// **2.1.20（A-02）**：查一个整数键的兜底范围（`(min,max)`；未知键 → `None`）。
pub fn fallback_range_of(key: &str) -> Option<(i64, i64)> {
    CONFIG_RANGE_FALLBACK
        .iter()
        .find(|(k, _, _)| *k == key)
        .map(|(_, lo, hi)| (*lo, *hi))
}

/// **2.1.20（A-02）**：把输入值夹取到 `[lo, hi]`（非有限值 → `default`）。
///
/// 控制台 `dom_clamped_key` 的纯函数核心（**native 可测**，见本文件单测）。
/// 之所以单独抽出来：控制台此前每个控件各自写死区间、没有任何测试兜住
/// ⇒ 与后端分叉 6 个键长期无人发现（审计 A-02）。
pub fn clamp_to_range(v: f64, lo: f64, hi: f64, default: f64) -> f64 {
    if !v.is_finite() {
        return default;
    }
    if v < lo {
        lo
    } else if v > hi {
        hi
    } else {
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn num0_normal_rounding() {
        assert_eq!(num0(0.0), "0");
        assert_eq!(num0(123.4), "123");
        assert_eq!(num0(123.5), "124");
        assert_eq!(num0(-7.6), "-8");
    }

    #[test]
    fn int_truncates_and_normalizes_non_finite() {
        assert_eq!(int(42.9), "42");
        assert_eq!(int(f64::NAN), "0");
        assert_eq!(int(f64::INFINITY), "0");
        assert_eq!(int(f64::NEG_INFINITY), "0");
    }

    /// D21：`f64::MAX as i64` 曾饱和成 i64::MAX；现在必须是科学计数法，
    /// 且不得等于饱和值。
    #[test]
    fn huge_values_do_not_saturate_to_i64_max() {
        let s = num0(f64::MAX);
        assert!(s.contains('e'), "期望科学计数法, got {s}");
        assert_ne!(s, i64::MAX.to_string());
        assert_ne!(s, "9223372036854775807");
        assert!(int(f64::MIN).contains('e'), "f64::MIN 也应走科学计数法");
    }

    #[test]
    fn i64_boundaries_are_exact() {
        assert_eq!(num0(-9_223_372_036_854_775_808.0), i64::MIN.to_string());
        let over = num0(9_223_372_036_854_775_808.0);
        assert!(over.contains('e'), "got {over}");
        let under = num0(9_223_372_036_854_774_784.0);
        assert!(!under.contains('e'), "got {under}");
    }

    #[test]
    fn contains_ci_is_case_insensitive() {
        assert!(contains_ci("Example.COM", "example"));
        assert!(contains_ci("abc", "B"));
        assert!(!contains_ci("abc", "z"));
    }

    #[test]
    fn opt_num1_and_pct1() {
        assert_eq!(opt_num1(None), "–");
        assert_eq!(opt_num1(Some(f64::NAN)), "–");
        assert_eq!(opt_num1(Some(1.25)), "1.2");
        assert_eq!(pct1(0.0), "0.0%");
        assert_eq!(pct1(99.96), "100.0%");
    }

    #[test]
    fn grouping_inserts_thousands_separators() {
        assert_eq!(group0(0.0), "0");
        assert_eq!(group0(999.0), "999");
        assert_eq!(group0(1000.0), "1,000");
        assert_eq!(group0(1234567.0), "1,234,567");
        assert_eq!(group0(-1234567.0), "-1,234,567");
        assert_eq!(group1(1234.5), "1,234.5");
        // 异常量级仍走科学计数法，不被分组破坏
        assert!(group0(f64::MAX).contains('e'));
    }

    #[test]
    fn latency_unit_is_adaptive() {
        assert_eq!(lat_auto(0.42), ("0.42".to_string(), "ms"));
        assert_eq!(lat_auto(1.0), ("1.00".to_string(), "ms"));
        assert_eq!(lat_auto(999.9), ("999.90".to_string(), "ms"));
        assert_eq!(lat_auto(1500.0), ("1.50".to_string(), "s"));
        assert_eq!(lat_auto(0.0), ("–".to_string(), ""));
        assert_eq!(lat_auto(f64::NAN), ("–".to_string(), ""));
    }

    #[test]
    fn trunc_keeps_short_values_and_marks_long_ones() {
        assert_eq!(trunc("abc", 8), "abc");
        assert_eq!(trunc("abcdefgh", 8), "abcdefgh");
        assert_eq!(trunc("abcdefghi", 8), "abcdefg…");
        assert_eq!(trunc("abc", 0), "");
    }

    /* ---------- 2.1.19（修复项 3 / R9）：落盘现场文案 ---------- */

    #[test]
    fn age_text_scales_by_magnitude() {
        assert_eq!(age_text(0), "0s 前");
        assert_eq!(age_text(37), "37s 前");
        assert_eq!(age_text(60), "1m 0s 前");
        assert_eq!(age_text(125), "2m 5s 前");
        assert_eq!(age_text(3600), "1h 0m 前");
        assert_eq!(age_text(86_400), "1d 0h 前");
        assert_eq!(age_text(86_400 + 7200), "1d 2h 前");
    }

    #[test]
    fn bytes_text_units() {
        assert_eq!(bytes_text(0), "0 B");
        assert_eq!(bytes_text(1023), "1023 B");
        assert_eq!(bytes_text(1024), "1.0 KiB");
        assert_eq!(bytes_text(24_134), "23.6 KiB");
        assert_eq!(bytes_text(2 * 1024 * 1024), "2.0 MiB");
    }

    /// R9 的两种**空态文案必须互不混淆**（用户实测的"到底落盘了没有"必须一眼可判）。
    #[test]
    fn persist_rows_distinguishes_the_two_empty_states() {
        // ① 未开启持久化
        let off = persist_rows(false, false, "/var/lib/ebpdns/c.json", 0, 0, 0, 60);
        assert_eq!(off[0].0, "落盘");
        assert_eq!(off[0].1, "未开启持久化");
        assert!(
            !off.iter().any(|(_, v)| v.contains("未落盘")),
            "「未开启持久化」不得复用「未落盘」文案：{off:?}"
        );
        assert_eq!(off[1].1, "/var/lib/ebpdns/c.json", "空态也必须给出路径");

        // ② 已开启但文件不存在
        let miss = persist_rows(true, false, "/var/lib/ebpdns/c.json", 0, 0, 0, 60);
        assert_eq!(miss[0].1, "未落盘（缓存文件不存在）");
        assert!(
            !miss.iter().any(|(_, v)| v.contains("未开启")),
            "「未落盘」不得复用「未开启持久化」文案：{miss:?}"
        );
    }

    /// R9 正路径：路径 / 最近落盘时间 / 条目数 / 文件大小 / 周期都要出现。
    #[test]
    fn persist_rows_full_state_reports_all_four_facts() {
        let rows = persist_rows(
            true,
            true,
            "/var/lib/ebpdns/ebpdns-cache.json",
            37,
            24_134,
            61,
            60,
        );
        let get = |k: &str| {
            rows.iter()
                .find(|(a, _)| a == k)
                .map(|(_, b)| b.clone())
                .unwrap_or_else(|| panic!("缺行 {k}：{rows:?}"))
        };
        assert_eq!(get("路径"), "/var/lib/ebpdns/ebpdns-cache.json");
        assert_eq!(get("最近落盘"), "37s 前");
        assert_eq!(get("内存条目"), "61 条");
        assert_eq!(get("文件大小"), "23.6 KiB");
        assert_eq!(get("周期"), "每 60 s");
    }

    #[test]
    fn persist_rows_marks_single_shot_mode_and_blank_path() {
        let rows = persist_rows(true, false, "  ", 0, 0, 0, 0);
        let get = |k: &str| {
            rows.iter()
                .find(|(a, _)| a == k)
                .map(|(_, b)| b.clone())
                .unwrap_or_default()
        };
        assert_eq!(get("路径"), "—", "空路径必须显示占位符而不是空白");
        assert_eq!(get("周期"), "仅优雅退出落盘", "interval=0 的语义必须显式");
    }

    /// `age_s` 只增不减 ⇒ `persist_stale` 必须在**超过 2 个周期**时才为真
    /// （这正是"页面值 == API 值；age_s 只增不减 ⇒ 未周期落盘"的可判定形式）。
    #[test]
    fn persist_stale_uses_two_interval_rule() {
        assert!(!persist_stale(0, 60));
        assert!(!persist_stale(120, 60), "恰为 2×interval 不算超期");
        assert!(persist_stale(121, 60));
        assert!(
            !persist_stale(9_999, 0),
            "interval=0（仅退出落盘）永远不算超期"
        );
    }

    /* ---------- 2.1.19（修复项 1）：启动恢复丢弃计数文案 ---------- */

    /// 三种状态必须**互不混淆**（2.1.18 只能从多行日志里拼）。
    #[test]
    fn restore_drops_text_distinguishes_legacy_from_corrupt() {
        assert_eq!(restore_drops_text(0, 0, 0, 0), "本次启动无丢弃");
        let legacy_only = restore_drops_text(0, 40, 0, 0);
        assert!(legacy_only.contains("旧格式 40 条"), "{legacy_only}");
        assert!(
            legacy_only.contains("下次落盘写新格式"),
            "旧格式是符合预期的丢弃，必须说清后续行为：{legacy_only}"
        );
        assert!(
            !legacy_only.contains("损坏"),
            "旧格式不是损坏：{legacy_only}"
        );
        let corrupt = restore_drops_text(0, 0, 3, 0);
        assert!(corrupt.contains("记录损坏 3 条"), "{corrupt}");
        assert!(
            !corrupt.contains("旧格式"),
            "损坏与旧格式必须分开表述：{corrupt}"
        );
        let mixed = restore_drops_text(5, 40, 3, 0);
        assert!(
            mixed.contains("旧格式 40 条")
                && mixed.contains("绝对到期已过 5 条")
                && mixed.contains("记录损坏 3 条"),
            "混合态必须逐类列出：{mixed}"
        );
    }

    /// **2.1.43-B（P2-4）**：`window_unpersisted` 必须**单独归类**（不是"记录损坏"），
    /// 且它单独非 0 时不得再说"本次启动无丢弃"（旧实现正是这么说的）。
    #[test]
    fn restore_drops_text_reports_window_unpersisted_separately() {
        let w = restore_drops_text(0, 0, 0, 12);
        assert!(w.contains("window 段未回放 12 条"), "{w}");
        assert!(w.contains("丢失率"), "必须说明它计入丢失率：{w}");
        assert!(!w.contains("损坏"), "window 段挤出不是记录损坏：{w}");
        assert_ne!(w, "本次启动无丢弃", "有 window 丢弃就不得说无丢弃");
        let both = restore_drops_text(0, 0, 2, 12);
        assert!(
            both.contains("记录损坏 2 条") && both.contains("window 段未回放 12 条"),
            "{both}"
        );
    }

    /* ---------- 2.1.20（A-02）：范围兜底表 + 夹取 ---------- */

    /// 兜底表必须覆盖审计点名的 **6 个曾经分叉的键**，且各自区间正确
    /// （这些正是"控制台能摆出后端必然 400 的值"的集合）。
    #[test]
    fn fallback_table_fixes_the_six_divergent_keys() {
        for (k, lo, hi) in [
            ("cache_size", 16i64, 4_194_304i64),
            ("ttl", 0, 604_800),
            ("ttl_min", 0, 604_800),
            ("ttl_max", 0, 604_800),
            ("stale_ttl", 0, 604_800),
            ("speed_interval_ms", 100, 600_000),
            ("health_check_interval", 0, 86_400),
        ] {
            assert_eq!(
                fallback_range_of(k),
                Some((lo, hi)),
                "`{k}` 的兜底区间必须是 [{lo}, {hi}]（否则控制台会摆出后端必然 400 的值）"
            );
        }
        assert_eq!(fallback_range_of("nope_not_a_key"), None);
    }

    /// 夹取语义（含边界与非法输入）。
    #[test]
    fn clamp_to_range_semantics() {
        assert_eq!(
            clamp_to_range(8.0, 16.0, 100.0, 0.0),
            16.0,
            "低于下界 → 夹到 lo"
        );
        assert_eq!(
            clamp_to_range(1000.0, 16.0, 100.0, 0.0),
            100.0,
            "高于上界 → 夹到 hi"
        );
        assert_eq!(clamp_to_range(50.0, 16.0, 100.0, 0.0), 50.0, "区间内原样");
        assert_eq!(clamp_to_range(16.0, 16.0, 100.0, 0.0), 16.0, "下界含");
        assert_eq!(clamp_to_range(100.0, 16.0, 100.0, 0.0), 100.0, "上界含");
        assert_eq!(
            clamp_to_range(f64::NAN, 16.0, 100.0, 42.0),
            42.0,
            "NaN → default"
        );
        assert_eq!(
            clamp_to_range(f64::INFINITY, 16.0, 100.0, 42.0),
            42.0,
            "inf → default"
        );
    }
}
