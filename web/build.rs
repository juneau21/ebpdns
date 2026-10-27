//! 构建脚本：把**根 workspace** 的版本号注入前端编译期常量 `EBPDNS_VERSION`。
//!
//! 为什么需要（审计 ⑤ 的历史缺陷：版本串曾四处漂移，出现过 2.1.1 / 2.1.7 / 2.1.12 / 2.1.13 / 2.1.14）：
//! `web/` 是**独立 workspace**（`[workspace]`，不被根 members 包含），拿不到根
//! `[workspace.package] version`，于是页脚（`web/src/state.rs`）与关于页
//! （`web/src/pages/about.rs`）各自手写版本号，随包发布后必然过期。
//!
//! 现在：**单一来源 = 根 `Cargo.toml` 的 `[workspace.package] version`**，
//! 前端只读 `env!("EBPDNS_VERSION")`，改版本只需改一处 + `web/build.sh` 重跑。
//!
//! **2.1.16（修复项 12）**：本文件此前把版本号写死在注释里（"当前 2.1.15"），
//! 版本一升就是一处 `grep` 出来的"旧版本残留"（且无法被任何门禁发现）。
//! 现在**注释不再写死版本号**：真实版本只在根 `Cargo.toml` 与构建产物里出现，
//! `web/Cargo.toml` 的注释同理（见该文件 `[package] version` 上方）。
//!
//! 健壮性：解析失败时回退 `0.0.0-dev`（构建**不失败**，只是版本显示为开发值），
//! 并输出 `cargo:warning`，让 CI/构建日志可见（不静默）。
use std::path::Path;

fn workspace_version() -> Option<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .join("Cargo.toml");
    let text = std::fs::read_to_string(&root).ok()?;
    let mut in_workspace_package = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_workspace_package = t == "[workspace.package]";
            continue;
        }
        if in_workspace_package {
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

fn main() {
    let root_manifest = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|p| p.join("Cargo.toml"));
    if let Some(p) = &root_manifest {
        println!("cargo:rerun-if-changed={}", p.display());
    }
    let version = match workspace_version() {
        Some(v) => v,
        None => {
            println!(
                "cargo:warning=未能从根 Cargo.toml 解析 [workspace.package] version，\
                 前端版本回退 0.0.0-dev"
            );
            "0.0.0-dev".to_string()
        }
    };
    println!("cargo:rustc-env=EBPDNS_VERSION={version}");
}
