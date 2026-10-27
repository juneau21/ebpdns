//! **2.1.22（A-3）**：版本一致性门禁 —— 版本字面量必须**同版本**，且与
//! `env!("CARGO_PKG_VERSION")`（= 根 `Cargo.toml` 的 `[workspace.package] version`）一致。
//! **2.1.29**：`docs/EBPF.md` 已随 eBPF/XDP 移除而删除，门禁由八处收敛为七处。
//!
//! ## 为什么需要（本轮实测）
//!
//! 2.1.21 → 2.1.22 的补升只改了根/web `Cargo.toml` 三处：
//! `packaging/systemd/ebpdns.service` 仍写 `(Rust v2.1.21)`、`Makefile` 仍写
//! `PKG := ebpdns-2.1.21`、`packaging/install.sh` 的安装指引与 `docs/PACKAGING.md`
//! 的适用范围也留在旧版本 ⇒ **交付的 systemd unit 自称 2.1.21，而二进制自称 2.1.22**。
//! `Makefile:8` 的注释本来就写着"改版本时本行、`packaging/install.sh`、systemd
//! Description、README 必须同步" —— 也就是说"人工同步"是**已知会失效**的机制。
//! 本门禁把它变成机器硬门：`cargo test` 直接红，`scripts/make_packages_221r2.sh`
//! 第 0/6 步同一判据也会让**打包失败**。
//!
//! 纯 `std`：不需要 python，也不依赖任何外部工具，源码包内一样能跑。

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root")
        .to_path_buf()
}

fn read(root: &Path, rel: &str) -> String {
    let p = root.join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// `[section] version = "X"` 的朴素解析（只认 `version` 一行，够用且无依赖）。
fn section_version(text: &str, section: &str) -> Option<String> {
    let mut inside = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            inside = t == section;
            continue;
        }
        if inside {
            if let Some(rest) = t.strip_prefix("version") {
                let rest = rest.trim_start().trim_start_matches('=').trim();
                let v = rest.trim_matches('"').trim_matches('\'').trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

/// 抓出**面向用户**的包名版本段：`ebpdns-<X.Y.Z>-prod.tar.gz` / `-src.tar.gz`、
/// `cd ebpdns-<X.Y.Z>`、行首目录名 `ebpdns-<X.Y.Z>/`。
///
/// 历史叙述**不算**（例如 README 里 `-C metadata=ebpdns-2.1.19-repro` 的构建元数据串、
/// 或文档引用缺陷原文的 `PKG := ebpdns-2.1.21`）—— 判据窄而客观：
/// **装包指令指向错版本**才是缺陷。
fn user_facing_package_versions(text: &str) -> Vec<String> {
    let needle = "ebpdns-";
    let mut out: Vec<String> = Vec::new();
    let mut search = 0usize;
    while let Some(rel) = text[search..].find(needle) {
        let at = search + rel;
        let rest = &text[at + needle.len()..];
        let mut vlen = 0usize;
        for c in rest.chars() {
            if c.is_ascii_digit() || c == '.' {
                vlen += c.len_utf8();
            } else {
                break;
            }
        }
        let v = &rest[..vlen];
        let after = &rest[vlen..];
        let before = &text[..at];
        let semver = v.matches('.').count() == 2;
        let is_tarball =
            semver && (after.starts_with("-prod.tar.gz") || after.starts_with("-src.tar.gz"));
        let is_cd = semver && before.ends_with("cd ");
        let is_dir = semver && after.starts_with('/') && before.ends_with('\n');
        if (is_tarball || is_cd || is_dir) && !out.contains(&v.to_string()) {
            out.push(v.to_string());
        }
        search = at + needle.len() + vlen.max(1);
    }
    out.sort();
    out
}

/// 括号里 `(Rust vX)` 的版本段。
fn rust_v_version(text: &str) -> Option<String> {
    let key = "Rust v";
    let start = text.find(key)? + key.len();
    let tail = &text[start..];
    let end = tail.find(')')?;
    Some(tail[..end].trim().to_string())
}

#[test]
fn version_matches_the_compiled_crate_version() {
    let root = repo_root();
    let ws = section_version(&read(&root, "Cargo.toml"), "[workspace.package]")
        .expect("root Cargo.toml [workspace.package] version");
    assert_eq!(
        ws,
        env!("CARGO_PKG_VERSION"),
        "根 Cargo.toml 的 workspace 版本必须等于编译期 CARGO_PKG_VERSION"
    );
}

#[test]
fn all_locations_carry_the_same_version() {
    let root = repo_root();
    let v = section_version(&read(&root, "Cargo.toml"), "[workspace.package]")
        .expect("root Cargo.toml [workspace.package] version");

    let web = section_version(&read(&root, "web/Cargo.toml"), "[package]").expect("web version");
    assert_eq!(web, v, "web/Cargo.toml 版本必须等于根 workspace 版本");

    let svc = read(&root, "packaging/systemd/ebpdns.service");
    assert_eq!(
        rust_v_version(&svc).as_deref(),
        Some(v.as_str()),
        "systemd Description 必须写 (Rust v{v})（2.1.22 实测曾残留 v2.1.21）"
    );

    let mk = read(&root, "Makefile");
    assert!(
        mk.contains(&format!("PKG      := ebpdns-{v}"))
            || mk.contains(&format!("PKG := ebpdns-{v}")),
        "Makefile 的 PKG 必须是 ebpdns-{v}"
    );

    for rel in ["packaging/install.sh", "docs/PACKAGING.md", "README.md"] {
        let found = user_facing_package_versions(&read(&root, rel));
        assert_eq!(
            found,
            vec![v.clone()],
            "{rel} 的**装包指令/目录名**版本必须只有 {v}（实测曾残留 ebpdns-2.1.21）"
        );
    }

    let md = read(&root, "docs/PACKAGING.md");
    assert!(
        md.contains(&format!("适用范围：ebpdns {v}")),
        "docs/PACKAGING.md 的适用范围必须是 ebpdns {v}"
    );

    let rm = read(&root, "README.md");
    assert!(
        rm.contains(&format!("**版本 v{v}")),
        "README.md 首页版本行必须是 v{v}"
    );
}
