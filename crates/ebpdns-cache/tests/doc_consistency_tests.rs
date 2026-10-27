//! **2.1.18（修复项 11/12/14/16）**：**文档 ↔ 代码 ↔ 运行态**三元一致性的**机器校验**。
//!
//! 为什么要这些用例（用户要求"杜绝类似问题"）：2.1.17 的用户实测发现 Web 控制台的
//! **[历史归因]** 缓存策略说明里写着 **`OrderedDict`**（Python 数据结构）、**额外内存约 512KB**
//! （实际 `SKETCH_D × SKETCH_W = 4 × 1024 = 4 KiB`，差 128 倍）、
//! **命中率通常高 5-15%**（本项目**没有任何实测依据**）等信息 —— 这些数字/术语
//! 都是**人手抄进文案**的，迟早与代码漂移。
//!
//! 本文件的策略是：**能机器校验的不要靠人抄**。
//! ① 数值型声明（分片数、权重、三段比例、sketch 内存）必须与 `ebpdns-cache`
//!    的常量**逐字一致** —— 常量改了而文案没改，本用例立刻 FAIL；
//! **[历史归因]** ② 术语型声明（禁用词表）在**用户可见文案**里出现即 FAIL —— 防止 Python 旧线
//!    术语（`OrderedDict` / `.py` / `v1.9.162` …）再次被抄进界面。
//!
//! 扫描对象（"用户可见文案"的真值集合）：
//! - `web/src/pages/*.rs`（配置页/关于页/实时日志页/KPI 卡片）
//! - `web/index.html`、`web/style.css`（静态文案；CSS `content:` 也算）
//!
//! 注意：`web/INTERFACE.md` / `README.md` 等**文档**允许保留历史归因，
//! 但必须以 `[历史归因]` 显式前缀标注（见 `CONVENTIONS.md` §16）。

use std::fs;
use std::path::PathBuf;

/// 仓库根（`crates/ebpdns-cache` → 上溯两级）。
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root")
        .to_path_buf()
}

/// **用户可见文案源 = `web/src/**` 全量 + 原样下发的静态资源**
/// （**2.1.19 修复项 22 / R10**：此前只列了 6 个文件，`query.rs` 里的旧版本号
/// 因此躲过了扫描 —— 现在改为**递归遍历**，新增文件自动纳入）。
fn ui_sources() -> Vec<String> {
    let mut out = vec!["web/index.html".to_string(), "web/style.css".to_string()];
    let base = repo_root().join("web/src");
    let mut stack = vec![base.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().map(|x| x == "rs").unwrap_or(false) {
                let rel = p
                    .strip_prefix(repo_root())
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push(rel);
            }
        }
    }
    out.sort();
    out
}

fn read_ui(rel: &str) -> String {
    let p = repo_root().join(rel);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("读取 {} 失败: {e}", p.display()))
}

/// **[历史归因]** 禁用词表（**逐条列出，不用通配**）：Python 旧线术语 / 与代码不符的数字。
///
/// 维护规则：往这里加词 = 该词**禁止**出现在用户可见文案里；
/// 若确有必要保留（例如源码注释里的历史归因），必须写在**非 UI 文件**里，
/// 并在文档中用 `[历史归因]` 前缀标注。
const BANNED: [(&str, &str); 10] = [
    (
        "OrderedDict",
        "Python 数据结构名；Rust 侧是有序映射（OrderedMap）",
    ),
    (
        "OrderedMap",
        "Rust 结构名；用户文案应写「有序映射」这类可读说法",
    ),
    (".py", "Python 源文件后缀（用户不需要知道旧线文件）"),
    ("_api_", "Python 旧线内部标识符前缀"),
    ("api.py", "Python 旧线文件名"),
    (
        "v1.9",
        "旧版本号（历史归因只允许留在源码注释/文档并加 [历史归因] 前缀）",
    ),
    ("1.9.162", "旧版本号"),
    ("512KB", "与代码常量不符（实际 sketch = 4 KiB）"),
    ("5-15%", "无实测依据的命中率承诺"),
    (
        "Python",
        "实现语言术语（用户可见文案只描述行为，不提旧线语言）",
    ),
];

/// 注释行判定：**源码/HTML/CSS 注释里的历史归因是允许的**
/// （`CONVENTIONS.md` §16 要求它们必须带 `[历史归因]` 前缀，且不得进 wasm 字符串）。
///
/// 为什么必须区分：Rust 注释**不会**进入 wasm（编译器直接丢弃），因此"用户可见"的
/// 真值是**字符串字面量**；而把注释也算进去会逼着我们把历史归因从源码里删掉，
/// 反而丢失可追溯性。`web/index.html` 与 `web/style.css` 是**原样下发**的静态资源，
/// 所以它们的注释**会**进 dist —— 但 HTML/CSS 注释对用户也不可见，同样豁免。
fn is_comment_line(line: &str) -> bool {
    let s = line.trim_start();
    s.starts_with("//")
        || s.starts_with("/*")
        || s.starts_with('*')
        || s.starts_with("<!--")
        || s.starts_with("*/")
}

/// **白名单（逐条列出，不得用通配）**：禁用词在这些**精确出现位置**是必须保留的。
///
/// - `ebpdns_api_token`：前端 `localStorage` 的 token 键名（`web/src/api.rs`），
///   改名会让既有浏览器里的 token 失效 ⇒ 必须保留；它只是"看起来像" `_api_` 模式。
const ALLOWED: [(&str, &str, &str); 1] = [(
    "ebpdns_api_token",
    "web/src/api.rs",
    "localStorage 的 API token 键名（契约，不可改）",
)];

/// 该行是否命中白名单（**按"行内包含白名单字符串"精确判定**）。
fn whitelisted(rel: &str, line: &str) -> bool {
    ALLOWED
        .iter()
        .any(|(needle, file, _)| rel == *file && line.contains(needle))
}

/// **用例 1**：用户可见文案里**不得**出现任何禁用词（**注释行豁免**，见上）。
#[test]
fn ui_sources_contain_no_banned_lexicon() {
    let mut hits = Vec::new();
    let sources = ui_sources();
    assert!(
        sources.len() >= 15,
        "扫描源数量异常（应覆盖 web/src 全量 + 2 个静态资源）：{}",
        sources.len()
    );
    for rel in &sources {
        let text = read_ui(rel);
        for (line_no, line) in text.lines().enumerate() {
            if is_comment_line(line) {
                continue;
            }
            if whitelisted(rel, line) {
                continue;
            }
            for (word, why) in BANNED {
                if line.contains(word) {
                    hits.push(format!(
                        "{rel}:{} 命中禁用词 `{word}`（{why}）\n      {}",
                        line_no + 1,
                        line.trim()
                    ));
                }
            }
        }
    }
    assert!(
        hits.is_empty(),
        "用户可见文案命中禁用词表（{} 条）：\n{}",
        hits.len(),
        hits.join("\n")
    );
}

/// **用例 2**：配置页里的**数值型声明**必须与 `ebpdns-cache` 常量一致。
///
/// 判据 = 文案里必须出现"由常量算出来的字符串"，因此**常量改了而文案没改 ⇒ FAIL**。
#[test]
fn cache_policy_ui_numbers_match_code_constants() {
    use ebpdns_cache::{lru, partitioned, tinylfu};
    let ui = read_ui("web/src/pages/config.rs");

    // ① LRU 分片数（`lru.rs::SHARDS`）
    let want_shards = format!("{} 个分片", lru::SHARDS);
    assert!(
        ui.contains(&want_shards),
        "配置页必须写明 LRU 分片数 = {}（缺 `{want_shards}`）",
        lru::SHARDS
    );

    // ② 默认分区权重（`partitioned.rs::DEFAULT_PARTITIONS`）
    let want_parts = partitioned::DEFAULT_PARTITIONS
        .iter()
        .map(|(g, w)| format!("{g} {w}"))
        .collect::<Vec<_>>()
        .join(" / ");
    assert!(
        ui.contains(&want_parts),
        "配置页必须写明默认分区权重 = `{want_parts}`"
    );

    // ③ TinyLFU 三段比例（`tinylfu.rs::WINDOW_PCT_DEFAULT` / `PROBATION_PCT_DEFAULT`）
    let win = tinylfu::WINDOW_PCT_DEFAULT;
    let prob = tinylfu::PROBATION_PCT_DEFAULT;
    // **分母注意**：`window` 占总容量；`probation` 占 **main = 总容量 − window**；
    // `protected` 取 main 的余下部分 ⇒ `protected_pct = 100 − probation_pct`（不是
    // `100 − window − probation`，那是"占总容量"的换算：1/40/60 时为 59%）。
    let prot = 100 - prob;
    for want in [
        format!("window {win}%"),
        format!("probation {prob}%"),
        format!("protected {prot}%"),
    ] {
        assert!(
            ui.contains(&want),
            "配置页必须写明 TinyLFU 三段比例（缺 `{want}`）"
        );
    }

    // ④ Count-Min Sketch 内存与规模（`tinylfu.rs::SKETCH_BYTES` = 4 KiB）
    let kib = tinylfu::SKETCH_BYTES / 1024;
    assert!(
        ui.contains(&format!("{kib} KiB")),
        "配置页必须写明 sketch 实际内存 = {} B（{} KiB）",
        tinylfu::SKETCH_BYTES,
        kib
    );
    assert!(
        ui.contains(&format!(
            "{} 行 × {} 列",
            tinylfu::SKETCH_D,
            tinylfu::SKETCH_W
        )),
        "配置页必须写明 sketch 规模 = {} 行 × {} 列",
        tinylfu::SKETCH_D,
        tinylfu::SKETCH_W
    );
}

/// **用例 3**：三种策略都必须被覆盖，且 `lru` 的能力描述不得混入"分区"
/// （2.1.17 的真实漂移：把 partitioned 的 group 分区/权重写给了 lru）。
#[test]
fn cache_policy_ui_covers_all_policies_and_keeps_them_distinct() {
    let ui = read_ui("web/src/pages/config.rs");
    for p in ["lru", "partitioned", "tinylfu"] {
        assert!(ui.contains(p), "配置页必须提到策略 `{p}`");
    }
    assert!(
        ui.contains("不做 group 分区"),
        "`lru` 卡片必须明确「不做 group 分区」（否则用户会以为 lru 自带分区）"
    );
    // 切换语义必须与实现一致：**增量迁移、不清空**。
    assert!(
        ui.contains("增量迁移") && ui.contains("不会清空"),
        "切换说明必须与实现一致（增量迁移 / 不会清空）"
    );
}

/// **用例 4**：缓存持久化文案必须写清**实际语义**（周期 + 退出 + 恢复），
/// 且**不得硬编码文件名**（必须显示配置里的实际 `cache_file` 值）。
#[test]
fn cache_persist_ui_describes_real_semantics() {
    let ui = read_ui("web/src/pages/config.rs");
    for want in ["优雅退出必落盘", "cache_save_interval", "启动时自动恢复"] {
        assert!(
            ui.contains(want),
            "缓存持久化文案必须包含实际语义片段 `{want}`"
        );
    }
    assert!(
        !ui.contains("落盘 cache.json"),
        "不得硬编码文件名（必须显示配置里的 cache_file 实际值）"
    );
}

/* ============ **2.1.19（修复项 5-⑫）**：README 键表默认值 == 随包模板 == 真实出厂默认 ============ */

/// **用例 5（文档 ↔ 配置 三元一致性的漏网项）**：`README.md` 的
/// 「配置键全表（含历史键的最终口径）」把每个键的**默认值**抄了一遍，但此前
/// **没有任何机器校验** ⇒ 2.1.18 实测漂移 9+ 处（`cache_size=16384` 而真实 131072、
/// `persist_ttl=604800` 而真实 0、`stale_ttl=86400` 而真实 604800 …）。
///
/// 本用例把这条路径也钉死：**从 README 表格里解析出默认值，与
/// `packaging/etc/ebpdns/config.json`（= 随包模板 = `default_config()`，另有门禁保证
/// 两者逐键一致）逐键比对**。改默认值而不改文档（或反之）立刻 FAIL。
#[test]
fn readme_config_table_defaults_match_packaging_template() {
    let readme = fs::read_to_string(repo_root().join("README.md")).expect("README.md");
    let tpl: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(repo_root().join("packaging/etc/ebpdns/config.json"))
            .expect("packaging/etc/ebpdns/config.json"),
    )
    .expect("模板必须是合法 JSON");

    // README 表格行形如：`| \`键\` | 类型 | \`默认\` | 口径 |`
    // 只校验**单键**行（多键合并行如 `ttl / ttl_min / ttl_max` 的 `300 / 5 / 300`
    // 形态各一，见下方逐条断言）。
    let mut checked = 0usize;
    for line in readme.lines() {
        let Some(rest) = line.strip_prefix("| `") else {
            continue;
        };
        let Some((key, tail)) = rest.split_once('`') else {
            continue;
        };
        // 只处理"第一个字段是配置键"的行（`**\`key\`**` 加粗行开头不是 `| \``）。
        let cells: Vec<&str> = tail.split('|').map(str::trim).collect();
        if cells.len() < 3 {
            continue;
        }
        let type_cell = cells[1];
        if !type_cell.contains("整数") && !type_cell.contains("布尔") && !type_cell.contains("枚举")
        {
            continue;
        }
        let default_cell = cells[2];
        // 形如 `` `131072` `` / `` `true` `` / `` `tinylfu` `` / `` `null` `` / `` `auto` ``；
        // **多键合并行**形如 `` `300` / `5` / `300` `` ⇒ 只取**第一个 code span**
        // （其余取值由下方"多键合并行"逐条断言覆盖）。
        let dv: String = match default_cell.strip_prefix('`') {
            Some(rest) => match rest.split('`').next() {
                Some(first) if !first.is_empty() => first.to_string(),
                _ => continue,
            },
            None => continue,
        };
        if dv.contains('/') {
            // 防御：真正的"默认值里带斜杠"不存在于本表（`/dns-query` 那类在 url 列）。
            continue;
        }
        let Some(actual) = tpl.get(key) else {
            // **2.1.21 第 2 轮（本门禁被自己的文档改动绊倒）**：本用例的判据是
            // "README 的**默认值** == 随包模板"，因此**只有模板里真的存在的键**才适用。
            // README 里还有三类键**天然不在模板里**，它们必须被**跳过**而不是 panic：
            //   1. **受支持历史别名**（`cb_fails` / `cb_open_s` / `warmup_enabled` ——
            //      模板里只有权威名 `circuit_fails` / `circuit_open_s` / `warmup`）；
            //   2. **派生/新名**（`cache_direct_enabled`，模板里为唯一键）；
            //   3. **对象子键**（`warmup.*`）。
            // 为什么不能 panic：本门禁**不是**"键名白名单"校验（那是
            // `validate_write` / `CONFIG_TOP_LEVEL_KEYS` 的职责，另有单测钉死）。
            // 把别名当"键名拼错"会让任何一次"把别名登记进 README"的文档修复变成红灯
            // —— 第 2 轮就是这样被绊倒的（DEF-221-07 把 `cb_fails` 挪进 API-only 表）。
            const ALIASES: &[&str] = &[
                "cache_direct_enabled",
                "cb_fails",
                "cb_open_s",
                "warmup_enabled",
            ];
            if !ALIASES.contains(&key) && !key.starts_with("warmup.") {
                panic!(
                    "README 列出的键 `{key}` 不在随包模板里，且不是已知别名/派生名/子键                     （键名拼错或已删除？若是新增别名，请加进本用例的 ALIASES）"
                );
            }
            continue;
        };

        let want: serde_json::Value = if dv == "null" {
            serde_json::Value::Null
        } else if dv == "true" || dv == "false" {
            serde_json::json!(dv == "true")
        } else if let Ok(n) = dv.parse::<i64>() {
            serde_json::json!(n)
        } else {
            serde_json::json!(dv)
        };
        assert_eq!(
            actual, &want,
            "README『配置键全表』的默认值与随包模板不一致：键 `{key}` README=``{dv}`` 模板={actual}"
        );
        checked += 1;
    }
    // 至少校验到上表的主要行（防止解析器静默失效变成"永远通过"）。
    assert!(
        checked >= 15,
        "README 键表默认值只校验到 {checked} 条（解析器可能失效，反而成假通过）"
    );

    // 多键合并行（格式为 `a / b / c`，逐一断言，不走上面的单键分支）。
    for (keys, want) in [
        (vec!["ttl", "ttl_min", "ttl_max"], vec![300i64, 5, 300]),
        (vec!["cache_persist", "persist_ttl"], vec![1, 0]), // 1 = true
    ] {
        for (k, w) in keys.iter().zip(want.iter()) {
            let actual = tpl.get(*k).unwrap_or_else(|| panic!("模板缺键 {k}"));
            let got = match actual {
                serde_json::Value::Bool(b) => i64::from(*b),
                serde_json::Value::Number(n) => n.as_i64().expect("整数"),
                other => panic!("{k} 类型意外：{other}"),
            };
            assert_eq!(
                got, *w,
                "README 合并行的默认值与模板不一致：`{k}` README={w} 模板={got}"
            );
        }
    }
    // `serve_stale` / `stale_ttl`。
    assert_eq!(tpl["serve_stale"], serde_json::json!(true));
    assert_eq!(tpl["stale_ttl"], serde_json::json!(604800));
    // **2.1.19（修复项 4）**：出厂默认上游 22 条（README 表 + PACKAGING 表都这么写）。
    assert_eq!(
        tpl["upstreams"].as_array().map(|a| a.len()),
        Some(22),
        "随包模板的 upstreams 必须恰为 22 条（与 README §出厂默认上游列表一致）"
    );
    assert!(
        !tpl["upstreams"]
            .as_array()
            .unwrap()
            .iter()
            .any(|u| u["id"] == serde_json::json!("lan235")
                || u["id"] == serde_json::json!("lan235tcp")),
        "模板不得再含 lan235 / lan235tcp（不在用户原文的 22 条里）"
    );
}
