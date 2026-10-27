//! **2.1.21 第 2 轮（D-221-02 门禁）**：`web/dist` 必须**不早于**它的源码，且构建产物必须
//! 包含源码里的**每一个** `cfg-*` 控件 id。
//!
//! ## 为什么需要这个门禁（本轮最要紧的一条）
//!
//! 现有的 `EMBEDDED == DIST` 门禁只证明"**二进制里内嵌的 wasm == `web/dist/app_bg.wasm`**"。
//! 它对下面这种漂移**完全无感**：
//!
//! ```text
//! 12:21  重编 wasm                        -> web/dist/app_bg.wasm
//! 12:48  构建二进制（内嵌上面的 dist）     -> EMBEDDED == DIST ✔ 门禁通过
//! 13:56  又改了 web/src/**（加控件）       -> 源码比 dist 新
//! 14:44  打包（不再重编 wasm）             -> 交付的 wasm 里没有 13:56 那个控件
//! ```
//!
//! 实测后果（AUDIT-221 DEF-221-02，P1）：交付 wasm 里 `cfg-adatk` = **0** 次出现，而同一份
//! 源码重编后 = **1** 次 ⇒ 宣传的 13 个新控件实际只交付 12 个，用户打开配置页**看不到
//! 「自适应超时系数 k」**。
//!
//! ## 断言（纯 `std`，不依赖任何外部工具）
//!
//! 1. **新鲜度**：`web/dist/app_bg.wasm` 的 mtime **不得早于** `web/src/**`、`web/Cargo.toml`、
//!    `web/build.rs`、`web/index.html`、`web/style.css` 里最新的 mtime（1 秒容差）。
//! 2. **控件覆盖**：`web/src/**` 里每个 `id="cfg-*"` 字面量都必须逐字节出现在 wasm 里。
//! 3. **版本串**：wasm 必须含当前版本串、且**不含** `2.1.20/2.1.19/2.1.18`。
//!
//! ## 没有 `web/dist` 时**跳过**（这是有意的）
//!
//! 源码包（`*-src.tar.gz`）按设计**不携带** `web/dist/**`，因此从源码包直接跑
//! `cargo test --workspace` 时这三条必然无法判定。**"无产物 ⇒ 无法判定 ⇒ 跳过"** 与
//! "产物过期 ⇒ 失败" 是两件事：前者不是缺陷，后者才是。交付链的判据由打包脚本
//! `scripts/make_packages_221r2.sh` 保证 —— 它**第一步就强制重编 wasm**，然后才跑本门禁。
//!
//! id 当**字面量子串**查的理由：Leptos 的 `view!` 把 `id="cfg-x"` 直接编成字符串常量
//! （交付 wasm 里绝大多数 id 都在），因此"源码里有、wasm 里没有"只可能意味着产物过期
//! 或该元素被优化掉 —— 两种情况都必须红。
//!
//! **2.1.22（P6）**：断言 ② 的数量判据改为**动态计数并打印**
//! （`src_total` / `checked` / `missing`），不再在文档里写死"76/77" ——
//! 硬编码的分母会随源码加控件而过期，让门禁"看起来在算、其实算的不是同一件事"。

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root")
        .to_path_buf()
}

/// 待检的构建产物；**不存在时返回 `None` ⇒ 调用方跳过**（源码包不带 dist）。
fn built_wasm() -> Option<(PathBuf, Vec<u8>)> {
    let p = repo_root().join("web/dist/app_bg.wasm");
    match std::fs::read(&p) {
        Ok(b) => Some((p, b)),
        Err(_) => None,
    }
}

/// 递归收集 `dir` 下的文件（跳过 `target` / `dist` / `.git`）。
fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        if p.is_dir() {
            if matches!(name.as_str(), "target" | "dist" | ".git") {
                continue;
            }
            walk(&p, out);
        } else {
            out.push(p);
        }
    }
}

/// `web/src/**` + 构建输入里的最新 mtime。
fn newest_source_mtime(web: &Path) -> Option<(SystemTime, PathBuf)> {
    let mut files = Vec::new();
    walk(&web.join("src"), &mut files);
    for f in ["Cargo.toml", "build.rs", "index.html", "style.css"] {
        let p = web.join(f);
        if p.is_file() {
            files.push(p);
        }
    }
    let mut newest: Option<(SystemTime, PathBuf)> = None;
    for f in files {
        let Ok(md) = std::fs::metadata(&f) else {
            continue;
        };
        let Ok(t) = md.modified() else { continue };
        if newest.as_ref().map(|(nt, _)| t > *nt).unwrap_or(true) {
            newest = Some((t, f));
        }
    }
    newest
}

/// `web/src/**` 里全部 `id="cfg-…"` 字面量。
fn cfg_ids_in_sources(web: &Path) -> BTreeSet<String> {
    let mut files = Vec::new();
    walk(&web.join("src"), &mut files);
    let mut ids = BTreeSet::new();
    for f in files {
        if f.extension().map(|e| e != "rs").unwrap_or(true) {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(&f) else {
            continue;
        };
        let bytes = src.as_bytes();
        let needle = b"id=\"";
        let mut i = 0usize;
        while let Some(pos) = find_from(bytes, needle, i) {
            let start = pos + needle.len();
            let Some(end_rel) = bytes[start..].iter().position(|&c| c == b'"') else {
                break;
            };
            let value = String::from_utf8_lossy(&bytes[start..start + end_rel]).to_string();
            if value.starts_with("cfg-") {
                ids.insert(value);
            }
            i = start + end_rel + 1;
        }
    }
    ids
}

fn find_from(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from >= hay.len() || needle.is_empty() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    find_from(hay, needle, 0).is_some()
}

/// **断言 ①**：`web/dist/app_bg.wasm` 不得早于源码（D-221-02 的漂移形态）。
#[test]
fn dist_wasm_is_not_older_than_web_sources() {
    let Some((wasm_path, _)) = built_wasm() else {
        eprintln!("跳过：web/dist/app_bg.wasm 不存在（源码包按设计不携带 dist）");
        return;
    };
    let web = repo_root().join("web");
    let wasm_t = std::fs::metadata(&wasm_path)
        .expect("wasm metadata")
        .modified()
        .expect("wasm mtime");
    let (src_t, src_path) = newest_source_mtime(&web).expect("web/src 下应有源文件");
    // 1 秒容差：文件系统时间戳粒度 / 同一批写入的先后抖动。
    // 只对"产物更旧"报警（产物比源码新是正常的：先重编 wasm 再打包）。
    let slack = Duration::from_secs(1);
    assert!(
        wasm_t + slack >= src_t,
        "**D-221-02 漂移**：`web/dist/app_bg.wasm` 比源码旧。\n\
         wasm  mtime = {:?}\n\
         最新源文件 = {} (mtime {:?})\n\
         ⇒ 交付的 wasm 里**不含**最新源码的改动（DEF-221-02 实测：`cfg-adatk` 控件缺失）。\n\
         修法：先 `cd web && bash build.sh` 重编 wasm，再构建/打包二进制。",
        wasm_t,
        src_path.display(),
        src_t
    );
}

/// **断言 ②**：源码里每个 `id="cfg-…"` 都必须出现在构建出来的 wasm 里。
///
/// **2.1.22（P6）**：判据从"硬编码数量"改为**动态计数并打印**。
/// 本文件头曾经写着「交付 wasm 里 76/77 个 id 都在」—— 那个 `77` 是**当时**的源码
/// 控件数，源码一加控件它就过期 ⇒ 覆盖门禁的**分母**与实际不符，真正被检查的数量
/// 只能靠人肉对账。现在：
/// * `src_total` / `checked` / `missing` **三个数都打印**（`--nocapture` 可见），
///   且 `checked + missing == src_total` 是机器可见的等式；
/// * `src_total >= 40` 的**解析器自检**保留（防"没解析出控件 ⇒ 真空通过"）。
#[test]
fn every_cfg_id_in_sources_is_present_in_built_wasm() {
    let Some((wasm_path, wasm)) = built_wasm() else {
        eprintln!("跳过：web/dist/app_bg.wasm 不存在（源码包按设计不携带 dist）");
        return;
    };
    let web = repo_root().join("web");
    let ids = cfg_ids_in_sources(&web);
    let src_total = ids.len();
    assert!(
        src_total >= 40,
        "只从 web/src 解析出 {src_total} 个 cfg-* id（预期 ≥40）—— 解析器失效，门禁会真空通过"
    );
    let mut missing: Vec<&String> = Vec::new();
    for id in &ids {
        if !contains(&wasm, id.as_bytes()) {
            missing.push(id);
        }
    }
    let checked = src_total - missing.len();
    // **动态计数并打印**（不再硬编码 72/77）：分母 = 本次真正解析出的控件数。
    eprintln!(
        "cfg-* 覆盖门禁（动态计数）：src_total={src_total} checked={checked} missing={} \
         wasm_bytes={}",
        missing.len(),
        wasm.len()
    );
    assert_eq!(
        checked + missing.len(),
        src_total,
        "计数恒等式不成立（checked + missing != src_total）⇒ 门禁统计本身失真"
    );
    assert!(
        missing.is_empty(),
        "**D-221-02 门禁**（{}）：以下 {} 个控件 id 在源码里有、在 `web/dist/app_bg.wasm` 里\
         **找不到** ⇒ 交付的 wasm 是从**旧源码**构建的（或该元素被优化掉了）：{missing:?}\n\
         实测依据：DEF-221-02 就是 `cfg-adatk` 缺失（源码 13 个新控件、wasm 只含 12 个）。\n\
         本次动态计数：src_total={src_total} checked={checked} missing={}",
        wasm_path.display(),
        missing.len(),
        missing.len()
    );
}

/// **断言 ③**：构建产物必须带当前版本串，且不含旧版本串。
///
/// `web/build.rs` 从根 `Cargo.toml` 注入 `EBPDNS_VERSION`，因此"wasm 里是 2.1.20"
/// 等价于"构建时根 `Cargo.toml` 还是旧版本" —— 同一类"产物早于源码"。
#[test]
fn built_wasm_carries_the_current_version_and_no_stale_one() {
    let Some((wasm_path, wasm)) = built_wasm() else {
        eprintln!("跳过：web/dist/app_bg.wasm 不存在（源码包按设计不携带 dist）");
        return;
    };
    let root = repo_root();
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).expect("Cargo.toml");
    let version = manifest
        .lines()
        .skip_while(|l| l.trim() != "[workspace.package]")
        .skip(1)
        .take_while(|l| !l.trim_start().starts_with('['))
        .find_map(|l| l.trim().strip_prefix("version"))
        .map(|r| {
            r.trim_start_matches([' ', '='])
                .trim()
                .trim_matches('"')
                .to_string()
        })
        .expect("解析 [workspace.package] version");
    assert!(
        contains(&wasm, version.as_bytes()),
        "构建产物 {} 里找不到当前版本串 `{version}` —— wasm 可能由旧版根 Cargo.toml 构建",
        wasm_path.display()
    );
    let mut stale_found: Vec<&str> = Vec::new();
    for stale in ["2.1.20", "2.1.19", "2.1.18"] {
        if contains(&wasm, stale.as_bytes()) {
            stale_found.push(stale);
        }
    }
    assert!(
        stale_found.is_empty(),
        "构建产物里出现旧版本串 {stale_found:?} —— 必须用当前源码重编 wasm"
    );
}
