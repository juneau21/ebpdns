//! **[历史归因]** 与 Python `cache.py` 同型的归一化工具与时钟。

use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

/// **[历史归因]** 当前 epoch 秒（浮点），对齐 Python `time.time()`。
pub fn now_epoch() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// **[历史归因]** Python `_safe_float`：None/无法解析/非有限 → default；否则返回有限值。
///
/// 本侧输入已是 Rust 数值，仅需做有限性校验。
pub fn safe_float(v: f64, default: f64) -> f64 {
    if v.is_finite() {
        v
    } else {
        default
    }
}

/// **[历史归因]** 容量归一化：Python `max(16, _safe_int(n, 1024))`。None → 1024；最小 16。
pub fn clamp_capacity(n: Option<usize>) -> usize {
    let v = n.unwrap_or(1024);
    v.max(16)
}

/// 从 serde_json::Value 取有限 f64；失败/非有限 → default。
pub fn json_f64(v: Option<&serde_json::Value>, default: f64) -> f64 {
    match v.and_then(|x| x.as_f64()) {
        Some(f) if f.is_finite() => f,
        _ => default,
    }
}

/// **2.1.19（修复项 1）**：该持久化记录里是否存在可用的**绝对到期时间**。
///
/// 语义：`expires_at` 字段存在、是有限数、且 > 0。凡不满足者一律视为"没有绝对到期"
/// （缺字段 = 旧版本写的文件；0/负数/非数是损坏值）。
///
/// **为什么要单独成函数**：三条策略（`lru.rs` / `tinylfu.rs` / `partitioned.rs` 委托）
/// 必须在**同一处**用**同一判据**，否则"换 `cache_policy` 就换恢复语义"这类缺陷会复发。
pub fn has_absolute_expiry(e: &serde_json::Value) -> bool {
    let a = json_f64(e.get("expires_at"), f64::NAN);
    a.is_finite() && a > 0.0
}

/// **2.1.19（修复项 1）**：该记录是否为**旧格式**（只有 `remaining`、没有绝对 `expires_at`）。
///
/// 旧格式必须**安全侧丢弃**（无从判断停机了多久），且必须**计数 + WARN**，
/// 绝不静默、绝不用 `now + remaining` 重新锚定 TTL。
pub fn is_legacy_format(e: &serde_json::Value) -> bool {
    !has_absolute_expiry(e) && e.get("remaining").is_some()
}

/// **2.1.19（修复项 1 补漏 · 三策略共享）**：结构不完整的**类别**。
///
/// 为什么必须共享：2.1.18/2.1.19 的 `lru.rs` 与 `tinylfu.rs` **各写了一份**解析与
/// 跳过逻辑 ⇒ `key = [123, 456]`（`domain`/`qtype` 取不出）这一类在 `lru` 被计入
/// `failed`，在 `tinylfu` 却**被当成空字符串接受并真的插进缓存**（既漏计数又写入
/// 垃圾条目）。三条策略必须**只走这一处判定**，否则"换 `cache_policy` 就换恢复语义"
/// 必然复发（有单测 `structural_incomplete_records_are_counted_not_silent` 钉死）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructuralIssue {
    /// `key` 字段缺失或不是数组。
    KeyNotArray,
    /// `key` 长度不是 2（`[domain, qtype]`）或 3（`[group, domain, qtype]`）。
    KeyLenInvalid,
    /// `domain` 或 `qtype` 取不出字符串。
    DomainQtypeMissing,
    /// 缺 `answers` 或 `rcode`（没有它们就没有可复现的答案）。
    AnswersRcodeMissing,
}

impl StructuralIssue {
    /// 类别数（调用方用它开 `[0usize; N]` 计数数组）。
    pub const COUNT: usize = 4;
    /// 在计数数组里的下标（与 [`StructuralIssue::COUNT`] 一致）。
    pub fn idx(self) -> usize {
        match self {
            StructuralIssue::KeyNotArray => 0,
            StructuralIssue::KeyLenInvalid => 1,
            StructuralIssue::DomainQtypeMissing => 2,
            StructuralIssue::AnswersRcodeMissing => 3,
        }
    }
    /// 可读标签（日志逐类归因用；三条策略共用同一组词）。
    pub fn label(self) -> &'static str {
        match self {
            StructuralIssue::KeyNotArray => "key 非数组",
            StructuralIssue::KeyLenInvalid => "key 长度非 2|3",
            StructuralIssue::DomainQtypeMissing => "domain·qtype 取不出",
            StructuralIssue::AnswersRcodeMissing => "缺 answers·rcode",
        }
    }
}

/// **2.1.19（修复项 1 补漏）**：一条持久化记录的**结构化 key**（解析成功的结果）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedKey {
    /// 3 元组 key 的 group 前缀（2 元组为 `None`）。`lru` 会剥掉它（分区已由外层决定），
    /// `tinylfu` 用它填 `CacheKey.group`，`partitioned` 用**空值回退为 `"default"`**。
    pub group: Option<String>,
    pub domain: String,
    pub qtype: String,
    /// 原始 `key` 数组长度（`2` 或 `3`）——`partitioned` 需要它区分"显式 group"。
    pub key_len: usize,
}

/// **2.1.19（修复项 1 补漏）**：**唯一**的"结构完整性"判定（三条策略都必须走这里）。
///
/// 判据（顺序即优先级，测试逐类断言）：
/// 1. `key` 必须是数组，否则 [`StructuralIssue::KeyNotArray`]；
/// 2. 长度必须是 2 或 3，否则 [`StructuralIssue::KeyLenInvalid`]；
/// 3. `domain` / `qtype` 必须是字符串，否则 [`StructuralIssue::DomainQtypeMissing`]
///    （**注意**：这里**不接受**"取不出就当成空串" —— 那会写入垃圾条目）；
/// 4. 必须有 `answers` 与 `rcode`，否则 [`StructuralIssue::AnswersRcodeMissing`]。
///
/// 索引口径：3 元组 = `[group, domain, qtype]`，2 元组 = `[domain, qtype]`
/// （与 `lru.rs` / `tinylfu.rs` / `partitioned.rs` 既有行为逐位一致）。
pub fn structural_check(e: &serde_json::Value) -> Result<ParsedKey, StructuralIssue> {
    let arr = e
        .get("key")
        .and_then(|v| v.as_array())
        .ok_or(StructuralIssue::KeyNotArray)?;
    let key_len = arr.len();
    let (group, di, qi) = match key_len {
        3 => (arr[0].as_str().map(|s| s.to_string()), 1usize, 2usize),
        2 => (None, 0usize, 1usize),
        _ => return Err(StructuralIssue::KeyLenInvalid),
    };
    let domain = arr[di]
        .as_str()
        .ok_or(StructuralIssue::DomainQtypeMissing)?
        .to_string();
    let qtype = arr[qi]
        .as_str()
        .ok_or(StructuralIssue::DomainQtypeMissing)?
        .to_string();
    // `answers`/`rcode` 的"存在性"判定（与既有实现一致：只看存在，不看内容）。
    if e.get("answers").is_none() || e.get("rcode").is_none() {
        return Err(StructuralIssue::AnswersRcodeMissing);
    }
    Ok(ParsedKey {
        group,
        domain,
        qtype,
        key_len,
    })
}

/// **2.1.19（修复项 1 补漏）**：把逐类计数数组渲染成 `标签=条数` 串（日志归因用）。
///
/// 只列出非零类别，便于一眼看出"是哪一类坏了"。
pub fn structural_breakdown(counts: &[usize; StructuralIssue::COUNT]) -> String {
    let all = [
        StructuralIssue::KeyNotArray,
        StructuralIssue::KeyLenInvalid,
        StructuralIssue::DomainQtypeMissing,
        StructuralIssue::AnswersRcodeMissing,
    ];
    let mut parts: Vec<String> = Vec::new();
    for iss in all {
        let n = counts[iss.idx()];
        if n > 0 {
            parts.push(format!("{}={n}", iss.label()));
        }
    }
    if parts.is_empty() {
        "无".to_string()
    } else {
        parts.join(" / ")
    }
}

/// `|v| >= 2^52` 时 f64 网格间距已 >= 1，任何 f64 都是整数，`round(v, 1) == v`。
/// 用它走 `round1` 的零开销快路径，同时把 `{:.1}` 的输出长度压到 <= 20 字节。
const ROUND1_FAST_ABS: f64 = 4_503_599_627_370_496.0; // 2^52

/// 栈上定长格式化缓冲（避免 `format!` 为每次取整分配一个 String）。
struct FmtBuf<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl std::fmt::Write for FmtBuf<'_> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let b = s.as_bytes();
        if self.len + b.len() > self.buf.len() {
            return Err(std::fmt::Error);
        }
        self.buf[self.len..self.len + b.len()].copy_from_slice(b);
        self.len += b.len();
        Ok(())
    }
}

/// **[历史归因]** 对齐 Python `round(v, 1)`：对**二进制真值**做十进制正确舍入，半值取偶（banker's）。
///
/// C-01：旧实现 `(v * 10.0).round() / 10.0` 是"先乘 10 再取整"，乘法的 1 ulp 误差
/// 会把 `.x5` 边界的舍入方向推错（`f64::round` 还是 half-away-from-zero）：
/// **[历史归因]** `round(0.25, 1) == 0.2`（Python）而旧式给 `0.3`。实测 72905 组样本（十进制
/// `.x5` 边界、`i/8`/`i/16`/`i/32`、`used/cap*100`、2.2 万随机值）中旧式错 666 组。
///
/// **[历史归因]** Rust 的 `{:.1}` 定点格式化走精确十进制展开 + 半值取偶，与 CPython
/// `_Py_dg_dtoa(mode=3)` 同规则：同一批样本逐位比对 **0 处不一致**。
///
/// 成本（release 实测，`tests/cache_perf_probe.rs`）：约 456 ns/次（对照旧式
/// 14 ns/次）。调用点只有 `summary()["pct"]`（3 次/请求）与 `serialize()` 的
/// `remaining`（1 次/条，而该路径本身约 8.3 µs/条，占比约 5.5%）；**不在
/// **[历史归因]** `get`/`put` 数据面路径上**，故为 Python 口径一致性接受这点开销。
pub fn round1(v: f64) -> f64 {
    if !v.is_finite() || v.abs() >= ROUND1_FAST_ABS {
        return v;
    }
    let mut raw = [0u8; 32];
    let mut fb = FmtBuf {
        buf: &mut raw,
        len: 0,
    };
    if write!(fb, "{v:.1}").is_err() {
        return v;
    }
    let len = fb.len;
    match std::str::from_utf8(&raw[..len]) {
        Ok(s) => s.parse::<f64>().unwrap_or(v),
        Err(_) => v,
    }
}

/// **2.1.29（缓存持久化 v2）**：恢复后的**绝对到期时间** —— **唯一实现**（M18）。
///
/// `persist_ttl` 的三段语义（**逐字不变**，见 `docs/PROPOSAL-cache-snapshot-wal.md §7.5`
/// 与 `tests/ttl_contract_tests.rs`）：
///
/// | 段 | 形态 | 行为 |
/// |---|---|---|
/// | **0** | `0` / `0.0` / 负数 / `NaN` / `±inf`（经 [`safe_float`] 归一） | 严格绝对到期：`abs <= now` ⇒ `None`（丢弃并计 `expired`）；否则保留 `abs`（停机时长计入 TTL） |
/// | **有限** | `0 < pt <= 31_536_000`（整数写法会被 clamp 到此区间） | **opt-in 统一恢复 TTL**：`now + pt`，**不看**原到期（已过期也复活） |
/// | **"无限"** | `pt > 31_536_000` 的有限 f64（如 `1e12`，只能靠指数/小数写法绕过整型 clamp） | 同一分支，`now + pt` ≈ 永不 expired；溢出由落盘的 `i64` 毫秒**饱和**兜底（§9.6 K2） |
///
/// 重要：这是**只改注释、不改语义**的落地点。`lru.rs` / `tinylfu.rs` 里
/// "`>0` 是剩余 TTL 上限（cap），只可能缩短寿命"的两处旧注释**与代码相反**，
/// 已一并改正为上面的口径（代码本来就对，注释是错的）。
pub fn resolve_restored_expiry(abs: f64, now: f64, pt: f64) -> Option<f64> {
    if pt > 0.0 {
        Some(now + pt)
    } else if abs.is_finite() && abs > now {
        Some(abs)
    } else {
        None
    }
}

/// **2.1.29（缓存持久化 v2）**：写入前的 `expires_at` 毫秒饱和（K2 的唯一入口）。
///
/// v1 的缺陷：`persist_ttl` 取大有限值使 `now + pt` 溢出为 `+inf` 时，`json!(inf)` 写成
/// `null` ⇒ 下次启动 `has_absolute_expiry=false` 且 `remaining` 存在 ⇒ 被判 **legacy 丢弃**。
/// v2 不把"无限"变成"丢"：饱和为 `i64::MAX` 毫秒，语义是"永不过期"（单测
/// `persist_ttl_infinity_saturates_not_null`）。
pub fn secs_to_ms_saturating(v: f64) -> i64 {
    crate::persist::entry_codec::secs_to_ms_saturating(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_restored_expiry_three_segments() {
        // 段 0：严格绝对到期（停机时长计入）。
        assert_eq!(resolve_restored_expiry(200.0, 100.0, 0.0), Some(200.0));
        assert_eq!(resolve_restored_expiry(100.0, 100.0, 0.0), None);
        assert_eq!(resolve_restored_expiry(10.0, 100.0, 0.0), None);
        assert_eq!(resolve_restored_expiry(f64::NAN, 100.0, 0.0), None);
        assert_eq!(resolve_restored_expiry(f64::INFINITY, 100.0, 0.0), None);
        // 段「有限」：now + pt，复活已过期。
        assert_eq!(resolve_restored_expiry(10.0, 100.0, 60.0), Some(160.0));
        assert_eq!(resolve_restored_expiry(1e18, 100.0, 60.0), Some(160.0));
        // 段「无限」：大有限值。
        assert_eq!(
            resolve_restored_expiry(10.0, 100.0, 1e12),
            Some(1e12 + 100.0)
        );
    }

    #[test]
    fn persist_ttl_infinity_saturates_not_null() {
        // K2：v1 会写 null 并在下次启动判 legacy；v2 饱和为 i64::MAX。
        assert_eq!(secs_to_ms_saturating(f64::INFINITY), i64::MAX);
        assert_eq!(secs_to_ms_saturating(f64::NEG_INFINITY), i64::MIN);
        assert_eq!(secs_to_ms_saturating(f64::NAN), 0);
        assert_eq!(secs_to_ms_saturating(1e308), i64::MAX);
        // 正常值不失真。
        assert_eq!(secs_to_ms_saturating(1_700_000_000.25), 1_700_000_000_250);
    }

    #[test]
    fn round1_matches_python_bankers_rounding() {
        // **[历史归因]** 以下期望值取自 CPython `round(v, 1)`（banker's / half-to-even）。
        let cases: [(f64, f64); 12] = [
            (0.25, 0.2),
            (0.75, 0.8),
            (6.25, 6.2),
            (12.25, 12.2),
            (2.25, 2.2),
            (0.15, 0.1), // 0.15 的真值是 0.1499999...
            (0.35, 0.3), // 0.35 的真值是 0.3499999...
            (0.45, 0.5), // 0.45 的真值是 0.4500000...1
            (0.85, 0.8), // 0.85 的真值是 0.8499999...
            (60.0, 60.0),
            (-0.25, -0.2),
            (100.0, 100.0),
        ];
        for (v, want) in cases {
            let got = round1(v);
            assert_eq!(
                got, want,
                "round1({v}) = {got}, 期望 Python round({v},1) = {want}"
            );
        }
    }

    #[test]
    fn round1_half_to_even_differs_from_naive() {
        // 旧 Rust 实现 `(v*10).round()/10`：`f64::round` 是 half-away-from-zero，
        // **[历史归因]** 在精确 `.x5` 上与 Python 的 half-to-even 方向相反（注意 Python 的
        // `round(v*10)/10` 会因自身 banker's 舍入而恰好同值，不能拿它当对照）。
        let naive = |v: f64| (v * 10.0).round() / 10.0;
        assert_eq!(naive(0.25), 0.3);
        assert_eq!(round1(0.25), 0.2);
        assert_ne!(naive(0.25), round1(0.25));
        assert_eq!(naive(6.25), 6.3);
        assert_eq!(round1(6.25), 6.2);
    }

    #[test]
    fn round1_passthrough_and_extremes() {
        assert_eq!(round1(1e300), 1e300); // 快路径，不格式化 300 位数字
        assert_eq!(round1(9.007_199_254_740_993e15), 9.007_199_254_740_993e15);
        assert!(round1(f64::NAN).is_nan());
        assert_eq!(round1(f64::INFINITY), f64::INFINITY);
        assert_eq!(round1(-0.0), -0.0);
        assert_eq!(round1(5e-324), 0.0);
    }

    #[test]
    fn clamp_capacity_lower_bound() {
        assert_eq!(clamp_capacity(None), 1024);
        assert_eq!(clamp_capacity(Some(0)), 16);
        assert_eq!(clamp_capacity(Some(usize::MAX)), usize::MAX);
    }
}
