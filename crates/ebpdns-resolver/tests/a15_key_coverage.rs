//! **2.1.21（DEF-220-02 / A-15）**：控制台可写键可达性的**机器门禁**。
//!
//! 审计 AUDIT-220 的 DEF-220-02 实测：`api.rs::CFG_WRITABLE` 有 **76** 个键，
//! 控制台只有约 **57** 个写路径，**19 个键既无控件**（其中 15 个在 `web/src` 里连
//! 字符串都不存在）；同时 `web/src/fmtnum.rs::CONFIG_RANGE_FALLBACK` 里还有
//! **12 个"前端根本不能设"的键**（它们只为通过"表对表"那条单测而存在）。
//! 这意味着**用户按区间表找控件永远找不到** —— 属"用户可感知的功能不可达"。
//!
//! 本文件的判据（**双向**，改任一侧而不同步改另一侧即红）：
//!
//! | # | 断言 |
//! |---|---|
//! | A1 | 控制台 `dom_clamped_key` 键集 ⊆ 后端 `CONFIG_RANGES` ∪ `EXTRA_PASSTHROUGH_KEYS`（不允许凭空的键） |
//! | A2 | 兜底表（`CONFIG_RANGE_FALLBACK`）的键集 == 控制台 `dom_clamped_key` 键集（**无"只有表项、没有控件"的键**） |
//! | A3 | 兜底表逐键与后端 `CONFIG_RANGES` **同值**（A-02 的既有门禁，本文件加强"键集"维度） |
//! | A4 | 兜底表键集 ⊆ 后端 `CONFIG_RANGES`（不允许 clamp 一个后端不收的键） |
//! | A5 | 控制台键集 ⊆ 后端 `CONFIG_RANGES` ∪ `EXTRA_PASSTHROUGH_KEYS` |
//! | A6 | `EXTRA_PASSTHROUGH_KEYS` 与在 `act_save` 里**原样透传**的键（`addr`/`port`/`proto`/`url`/`config_version`）之外，没有未分类的键 |
//! | A7 | README 的「界面可改」表必须包含控制台键集；「仅 API / 配置文件可改」表必须与 `CFG_WRITABLE` 的补集一致 |
//!
//! 之所以把"前端源码"当作**被读的规范**（而不是把键表搬到 Rust）：控制台的写路径
//! 就是 `web/src/pages/config.rs::act_save` 里的 `obj.insert("键", …)` 语句，
//! 只有解析那份源码才能回答"这个键到底有没有控件"。

use std::collections::BTreeSet;
use std::path::PathBuf;

/// 控制台**原样透传**（不经过任何区间 clamp）的可写键 —— 它们在 `act_save` 里
/// 从 `app.config` 拿到的对象上直接下发，没有 `obj.insert("<键>", …)` 语句。
///
/// 这里显式列出并**逐条给出理由**，是为了让 A6 能够发现"新增了一个透传键却忘了登记"：
/// * `config_version`：schema 版本，服务端管理（`CFG_READONLY`）；
/// * `listen` / `api` / `web_root` / `cache_file` / `rule_local_file` / `rule_sub_file`：
///   只读段（整份回传，后端并入 `readonly_keys`）；
/// * `upstreams` / `rules` / `rule_subscriptions`：三个列表（有各自的编辑器）。
///
/// 注意：本表**只用于"前端集合 ⊆ 后端集合"的方向**，不代表它们"可写"。
const EXTRA_PASSTHROUGH_KEYS: &[&str] = &[
    "config_version",
    "listen",
    "api",
    "web_root",
    "cache_file",
    "rule_local_file",
    "rule_sub_file",
    "upstreams",
    "rules",
    "rule_subscriptions",
    // **2.1.22 阶段一**：统一持久化事务的两个新顶层键。它们**故意没有界面控件**
    // （`state_dir` 是路径类、`state_persist` 是进程级启动参数），在 `api.rs` 里
    // 归 `CFG_READONLY` 桶 ⇒ 控制台整份回传时后端并入 `readonly_keys`。
    // 不登记它们会让 A1/A5 把"合法的只读键"误报成"凭空的键"。
    "state_dir",
    "state_persist",
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root")
        .to_path_buf()
}

/// 后端权威整数范围表的键集。
fn backend_range_keys() -> BTreeSet<String> {
    ebpdns_resolver::config::CONFIG_RANGES
        .iter()
        .map(|(k, _, _)| (*k).to_string())
        .collect()
}

/// 后端**可写**键集（`CFG_WRITABLE`）。它在 `ebpdns-server` 里是私有常量，
/// 因此这里从源码解析（与 `fe_keys.py` 同一手法），并顺带断言解析结果非空，
/// 避免"正则失效 ⇒ 断言真空转"。
fn backend_writable_keys() -> BTreeSet<String> {
    let src = std::fs::read_to_string(repo_root().join("crates/ebpdns-server/src/api.rs"))
        .expect("api.rs");
    let start = src.find("const CFG_WRITABLE").expect("CFG_WRITABLE");
    let body = &src[start..];
    let end = body.find("\n];").expect("CFG_WRITABLE 必须以 `\\n];` 结束");
    let mut out = BTreeSet::new();
    for raw in body[..end].lines() {
        // 去掉行注释后取所有 "字面量"。
        let line = match raw.find("//") {
            Some(i) => &raw[..i],
            None => raw,
        };
        for part in line.split('"').skip(1).step_by(2) {
            let k = part.trim();
            if !k.is_empty()
                && k.chars()
                    .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit())
            {
                out.insert(k.to_string());
            }
        }
    }
    assert!(
        out.len() >= 60,
        "CFG_WRITABLE 解析出 {} 个键（预期 ≥60）—— 正则/格式已变，门禁失效",
        out.len()
    );
    out
}

/// 控制台的整数键写路径：`dom_clamped_key(app, "<键>", "<id>", …)`。
fn console_keyed_controls() -> BTreeSet<String> {
    let src = std::fs::read_to_string(repo_root().join("web/src/pages/config.rs"))
        .expect("web/src/pages/config.rs");
    // 形态（rustfmt 后是多行的）：`dom_clamped_key(\n  app,\n  "键",\n …)`。
    // 逐字符扫描而不是 `split` 字面量：格式化（换行/缩进）一变，字面量就失配，
    // 门禁会**静默失效**（`out.len()` 变小而断言仍可能通过）。
    let mut out = BTreeSet::new();
    let mut rest = src.as_str();
    while let Some(i) = rest.find("dom_clamped_key(") {
        rest = &rest[i + "dom_clamped_key(".len()..];
        let Some(ap) = rest.find("app") else { break };
        let after = rest[ap + 3..].trim_start();
        let Some(after) = after.strip_prefix(',') else {
            continue;
        };
        let after = after.trim_start();
        let Some(after) = after.strip_prefix('"') else {
            continue;
        };
        let Some(end) = after.find('"') else { continue };
        let k = &after[..end];
        if !k.is_empty()
            && k.chars()
                .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit())
        {
            out.insert(k.to_string());
        }
    }
    assert!(
        out.len() >= 25,
        "控制台只解析出 {} 个 dom_clamped_key 控件（预期 ≥25）—— 门禁失效",
        out.len()
    );
    out
}

/// `act_save` 里 `obj.insert("<键>", …)` 直接写入的键（文本/布尔/枚举控件）。
fn console_inserted_keys() -> BTreeSet<String> {
    let src = std::fs::read_to_string(repo_root().join("web/src/pages/config.rs"))
        .expect("web/src/pages/config.rs");
    // 形态：`obj.insert(\n  "键".into(),\n …)` —— 同样对空白/换行不敏感。
    let mut out = BTreeSet::new();
    let mut rest = src.as_str();
    while let Some(i) = rest.find("obj.insert(") {
        rest = &rest[i + "obj.insert(".len()..];
        let after = rest.trim_start();
        let Some(after) = after.strip_prefix('"') else {
            continue;
        };
        let Some(end) = after.find('"') else { continue };
        let k = &after[..end];
        if !k.is_empty()
            && k.chars()
                .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit())
        {
            out.insert(k.to_string());
        }
    }
    assert!(
        out.len() >= 40,
        "控制台只解析出 {} 个 obj.insert 键（预期 ≥40）—— 门禁失效",
        out.len()
    );
    out
}

/// `web/src/fmtnum.rs::CONFIG_RANGE_FALLBACK`（旧后端兜底区间表）。
fn fallback_table() -> Vec<(String, i64, i64)> {
    let src =
        std::fs::read_to_string(repo_root().join("web/src/fmtnum.rs")).expect("web/src/fmtnum.rs");
    let start = src
        .find("pub const CONFIG_RANGE_FALLBACK")
        .expect("CONFIG_RANGE_FALLBACK");
    let body = &src[start..];
    let end = body.find("\n];").expect("数组必须以 `\\n];` 结束");
    let mut out = Vec::new();
    for line in body[..end].lines() {
        let l = line.trim();
        if !l.starts_with("(\"") {
            continue;
        }
        let l = l.trim_end_matches(',');
        let inner = l.trim_start_matches('(').trim_end_matches(')');
        let parts: Vec<&str> = inner.split(',').map(str::trim).collect();
        assert_eq!(parts.len(), 3, "表项形状必须是 (\"key\", lo, hi)：{l}");
        let key = parts[0].trim_matches('"').to_string();
        let lo: i64 = parts[1].replace('_', "").parse().expect("lo 必须是整数");
        let hi: i64 = parts[2].replace('_', "").parse().expect("hi 必须是整数");
        out.push((key, lo, hi));
    }
    assert!(
        out.len() >= 25,
        "兜底表条目过少（{}）—— 疑似被误删",
        out.len()
    );
    out
}

/// `api.rs::CFG_READONLY`（后端**只读**桶：存在于配置里、`GET /api/config` 会返回、
/// 但 `PUT` 不接受 —— 保存时原值不变）。
fn backend_readonly_keys() -> BTreeSet<String> {
    let src = std::fs::read_to_string(repo_root().join("crates/ebpdns-server/src/api.rs"))
        .expect("api.rs");
    let start = src.find("const CFG_READONLY").expect("CFG_READONLY");
    let body = &src[start..];
    let end = body.find("\n];").expect("CFG_READONLY 必须以 `\\n];` 结束");
    let mut out = BTreeSet::new();
    for raw in body[..end].lines() {
        let line = match raw.find("//") {
            Some(i) => &raw[..i],
            None => raw,
        };
        for part in line.split('"').skip(1).step_by(2) {
            let k = part.trim();
            if !k.is_empty()
                && k.chars()
                    .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit())
            {
                out.insert(k.to_string());
            }
        }
    }
    assert!(
        out.len() >= 6,
        "CFG_READONLY 解析出 {} 个键（预期 ≥6）—— 门禁失效",
        out.len()
    );
    out
}

/// 从一个 Markdown 表格小节里抽出第一列里**所有** `` `键` `` 名
/// （一行可以列多个键，例如 `` `ttl` / `ttl_min` / `ttl_max` ``）。
fn markdown_key_section(src: &str, heading: &str, _next_heading: &str) -> BTreeSet<String> {
    let start = src
        .find(heading)
        .unwrap_or_else(|| panic!("README 缺少小节 `{heading}`"));
    // 判据**只看表格行本身**（不依赖后续标题的措辞，也不需要知道下一节叫什么）：
    //   配置键表的首列是 `` `键` `` 或 `` `a` / `b` `c` ``（按 `/` 与反引号切开后全是
    //   `[a-z0-9_]+`）；而「计数器口径逐键表」的表头是 `| 键（`counters.` 前缀） | …`，
    //   含有 `.` 与括号 ⇒ **不是**配置键行，遇到即停。
    //   这条判据把"README 加一节/改标题就会误吞 19 个计数名"的结构性脆弱点去掉了。
    let mut out = BTreeSet::new();
    let mut in_table = false;
    for line in src[start..].split('\n') {
        let l = line.trim();
        if !l.starts_with('|') {
            if in_table && !l.is_empty() {
                break;
            }
            continue;
        }
        if l.starts_with("|---") || l.starts_with("| ---") {
            continue;
        }
        let first = l.trim_matches('|').split('|').next().unwrap_or("").trim();
        if first.is_empty() {
            continue;
        }
        let mut keys: Vec<String> = Vec::new();
        let mut ok = true;
        for chunk in first.split('`').skip(1).step_by(2) {
            for piece in chunk.split('/') {
                let k = piece.trim();
                if k.is_empty() {
                    continue;
                }
                if k.chars()
                    .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit())
                {
                    keys.push(k.to_string());
                } else {
                    ok = false;
                }
            }
        }
        if !ok || keys.is_empty() {
            if in_table {
                break;
            }
            continue;
        }
        in_table = true;
        for k in keys {
            out.insert(k);
        }
    }
    assert!(
        !out.is_empty(),
        "README 小节 `{heading}` 解析出 0 个键 —— 表格格式已变，门禁失效"
    );
    out
}

/* ================================ A1..A5 ================================ */

/// **A5 + A2**：双向一致性 —— 控制台整数控件键集 == 兜底表键集 == 后端范围表键集，
/// 且都 ⊆ 后端可写键集。
#[test]
fn console_controls_and_fallback_table_are_the_same_set() {
    let controls = console_keyed_controls();
    let fallback: BTreeSet<String> = fallback_table().into_iter().map(|(k, _, _)| k).collect();
    let backend_ranges = backend_range_keys();
    let writable = backend_writable_keys();

    // A2（正向）：兜底表的每个键都必须**真的**有控制台写路径。
    let only_in_table: Vec<&String> = fallback.difference(&controls).collect();
    assert!(
        only_in_table.is_empty(),
        "CONFIG_RANGE_FALLBACK 里有 {} 个键**没有**控制台写路径（DEF-220-02 的病根：\
         表项只为过单测而存在，用户按表找控件找不到）：{only_in_table:?}",
        only_in_table.len()
    );
    // A2（反向）：有控件就必须进兜底表（否则旧后端下 clamp 会用硬编码默认值）。
    let only_in_controls: Vec<&String> = controls.difference(&fallback).collect();
    assert!(
        only_in_controls.is_empty(),
        "以下键有控制台控件却不在 CONFIG_RANGE_FALLBACK 里（旧后端下会退回硬编码默认）：\
         {only_in_controls:?}"
    );

    // A3：逐键与后端权威区间同值。
    for (k, lo, hi) in fallback_table() {
        let want = ebpdns_resolver::config::config_range_of(&k)
            .unwrap_or_else(|| panic!("兜底表有后端 CONFIG_RANGES 里没有的键：{k}"));
        assert_eq!(
            (lo, hi),
            (want.0 as i64, want.1 as i64),
            "`{k}` 的兜底区间 ({lo}, {hi}) 与后端权威区间 {want:?} 不一致"
        );
    }

    // A4：兜底表 ⊆ 后端范围表。
    let bad: Vec<&String> = fallback.difference(&backend_ranges).collect();
    assert!(bad.is_empty(), "兜底表含后端范围表里没有的键：{bad:?}");

    // A5：控制台键集 ⊆ 后端可写键集。
    let outside: Vec<&String> = controls.difference(&writable).collect();
    assert!(
        outside.is_empty(),
        "控制台写路径里有后端不接受的键（会被并入 ignored_keys）：{outside:?}"
    );
}

/// **A1 + A6**：`act_save` 下发的每个键都必须被后端**接受或以只读桶回显**，
/// 不允许出现"前端一直在发、后端一直当未知键忽略"的键。
#[test]
fn console_submitted_keys_are_all_known_to_the_backend() {
    let inserted = console_inserted_keys();
    let writable = backend_writable_keys();
    let readonly: BTreeSet<String> = [
        "config_version",
        "listen",
        "api",
        "web_root",
        "rule_local_file",
        "rule_sub_file",
        "cache_file",
        "dns_port",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let mut unknown: Vec<&String> = Vec::new();
    for k in &inserted {
        let pk = k.as_str();
        if writable.contains(pk) || readonly.contains(pk) || EXTRA_PASSTHROUGH_KEYS.contains(&pk) {
            continue;
        }
        unknown.push(k);
    }
    assert!(
        unknown.is_empty(),
        "控制台 `act_save` 下发了后端既不接受、也不在只读桶的键（每次保存都会提示\
         『忽略未保存的键』）：{unknown:?}"
    );
}

/* ================================== A7 ================================== */

/// **A7**：README 的两张表必须与代码一致：
/// * 「界面可改」表 ⊇ 控制台写路径键集；
/// * 「仅 API / 配置文件可改」表 == `CFG_WRITABLE` 减掉「界面可改」表。
///
/// 为什么把 README 也纳入门禁：审计 DEF-220-02 的最后一条要求就是
/// "README 键表逐键标注『界面可改 / 仅 API·配置文件可改』" —— 文档与代码
/// 必须能被同一条命令判定一致，否则下一次改动必然再次漂移。
#[test]
fn readme_key_tables_match_code() {
    let readme = std::fs::read_to_string(repo_root().join("README.md")).expect("README.md");
    let ui = markdown_key_section(
        &readme,
        "#### 界面可改（有控件）",
        "#### 仅 API / 配置文件可改",
    );
    // 结束标记用**计数器小节自己的标题**：它紧跟在「仅 API / 配置文件可改」表之后，
    // 且它的首列是计数名（`total` / `udp_dropped`…）而不是配置键 —— 用 `## ` 二级标题当
    // 结束标记会滑过这张表，把 19 个计数名当成"只能改配置文件的配置键"（2.1.21 实测）。
    let api_only = markdown_key_section(&readme, "#### 仅 API / 配置文件可改", "计数器口径逐键表");

    let controls = console_keyed_controls();
    let inserted = console_inserted_keys();
    let writable = backend_writable_keys();

    // ① 「界面可改」必须覆盖控制台的**整数**控件键（这是本轮的修复目标）。
    let missing: Vec<&String> = controls.difference(&ui).collect();
    assert!(
        missing.is_empty(),
        "README「界面可改（有控件）」表缺这些键（它们已有控件）：{missing:?}"
    );

    // ② 「仅 API / 配置文件可改」== 可写键 − 界面可改 − 有控件的文本/布尔键，
    //    另加**只读桶**（它们也"只能改配置文件"，但 PUT 不接受，属另一类）。
    let ui_all: BTreeSet<String> = ui.union(&inserted).cloned().collect();
    let mut want_api_only: BTreeSet<String> = writable
        .difference(&ui_all)
        .filter(|k| !EXTRA_PASSTHROUGH_KEYS.contains(&k.as_str()))
        .cloned()
        .collect();
    want_api_only.extend(backend_readonly_keys());
    let wrong_in_api_only: Vec<&String> = api_only.difference(&want_api_only).collect();
    assert!(
        wrong_in_api_only.is_empty(),
        "README「仅 API / 配置文件可改」表里有键其实**有控件**（或既不可写也不只读）：\
         {wrong_in_api_only:?}"
    );
    let missing_from_api_only: Vec<&String> = want_api_only.difference(&api_only).collect();
    assert!(
        missing_from_api_only.is_empty(),
        "以下键既没有控件、也没被登记进 README「仅 API / 配置文件可改」表\
         （用户无从知道它只能改配置文件）：{missing_from_api_only:?}"
    );
}

/// 解析器自检：两个"读源码"的解析函数必须能在**当前**树里工作（防"正则失效 ⇒ 真空通过"）。
#[test]
fn source_parsers_are_not_vacuous() {
    let controls = console_keyed_controls();
    for k in [
        "cache_size",
        "ttl",
        "prefetch_trigger",
        "prefetch_target",
        "neg_ttl_max",
        "adaptive_timeout_min_ms",
    ] {
        assert!(
            controls.contains(k),
            "控制台缺少 `{k}` 的 `dom_clamped_key` 写路径（DEF-220-02 回归）"
        );
    }
    let writable = backend_writable_keys();
    for k in [
        "cache_size",
        "prefetch_trigger",
        "cache_direct_enabled",
        "prefetch_max",
    ] {
        assert!(writable.contains(k), "CFG_WRITABLE 解析缺 `{k}`");
    }
}

/* ============================ 注释计数 / 控件键 ============================ */

/// **2.1.29（A-15 注释漂移修复）**：`CardCache` 的 A-15 说明注释写着"N 个控件"。
/// 2.1.28 实测注释写 12、真实控件 13（`patch229_ui` 把 13 个 `.cfg-row` 从 `.card-hd`
/// 搬到 `.card-bd`，却只改了位置没改注释）。本测试**动态**从源码统计：
///
/// * 起点：`本块的 ` 注释；
/// * 终点：原 `card-bd` 第一行（`id="cfg-size"` 所属 `.cfg-row` 的起始 `<div>`）；
/// * 断言：注释里的 N == 该区间的 `.cfg-row` 数 == 区间内 `cfg_num_s(&cfg, "键")` 的键数；
/// * 并逐键断言其 ∈ `CFG_WRITABLE`（浮点键 `adaptive_timeout_k` 不在整数范围表
///   `CONFIG_RANGES` 里，故本测试只校验"后端确实可写"，区间由 A3/A4 的既有断言负责）。
///
/// 这样无论"加一行控件"还是"改注释数字"，只要两侧不同步就会红 —— 不再靠人肉数数。
#[test]
fn cardcache_control_count_matches_comment_and_backend() {
    let src = std::fs::read_to_string(repo_root().join("web/src/pages/config.rs"))
        .expect("web/src/pages/config.rs");
    let start = src.find("本块的 ").expect("CardCache 的 A-15 注释");
    let rest = &src[start..];
    let stated: usize = rest["本块的 ".len()..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .expect("A-15 注释必须写成 `本块的 N 个控件`");

    let id_pos = rest
        .find("id=\"cfg-size\"")
        .expect("找不到 card-bd 首行 id=cfg-size");
    let row_start = rest[..id_pos]
        .rfind("<div class=\"cfg-row\">")
        .expect("找不到 id=cfg-size 所属的 .cfg-row 起始标签");
    let block = &rest[..row_start];

    let rows = block.matches("class=\"cfg-row\"").count();
    assert_eq!(
        stated, rows,
        "A-15 注释写 {stated} 个控件，实测 CardCache 该块有 {rows} 个 .cfg-row"
    );

    let mut keys = BTreeSet::new();
    let mut cursor = block;
    while let Some(i) = cursor.find("cfg_num_s(&cfg, \"") {
        let tail = &cursor[i + "cfg_num_s(&cfg, \"".len()..];
        let Some(end) = tail.find('"') else { break };
        keys.insert(tail[..end].to_string());
        cursor = &tail[end + 1..];
    }
    assert_eq!(
        keys.len(),
        rows,
        "每个 .cfg-row 应恰有一个区间键：rows={rows} keys={keys:?}"
    );

    let writable = backend_writable_keys();
    for k in &keys {
        assert!(
            writable.contains(k),
            "CardCache 控件键 `{k}` 不在 CFG_WRITABLE（保存时会被后端忽略）"
        );
    }
}
