//! **2.1.36（D 批）**：崩溃安全文件 IO 的**单一实现**。
//!
//! 2.1.35 之前，`tmp → fsync(file) → rename → fsync(dir)` 这套四步协议在树里有
//! **9 份**独立实现（`ebpdns/src/main.rs`、`main_state.rs` 两处、`ebpdns-server/src/api.rs`、
//! `state_store.rs`、`subscribe.rs`、`rules_admin.rs` 两处、`ebpdns-cache/src/persist/mod.rs`），
//! `fsync(dir)` 另有 **7 份**内联拷贝。它们对"tmp 名 / 失败是否清理 / 是否建父目录 /
//! 是否保留权限位"各有细微差异 —— 任何一处单独修崩溃语义，其余八处都不会跟着变。
//!
//! 本 crate 只做一件事：把这套协议收成**一个函数** [`atomic_write_with`]，其余入口都是
//! 它的薄封装。调用方通过 [`WriteOptions`] 显式声明自己原先的 tmp 命名与清理策略，
//! 因此**磁盘上的最终字节、提交点、失败时的原文件都逐字节不变**。
//!
//! # 四步协议
//!
//! 1. 写 `<tmp>`（内容由调用方回调提供）；
//! 2. `fsync(<tmp>)` —— 保证 rename 之后读到的是完整内容，而不是空洞；
//! 3. `rename(<tmp>, <path>)` —— 目录项原子切换；**回调或 fsync 失败时绝不 rename**；
//! 4. `fsync(<path 的父目录>)` —— 让目录项本身持久化。目录 fsync 在部分平台/文件系统
//!    （tmpfs、Windows）会返回 `EINVAL/EPERM`，历史语义是**降级不失败**，见
//!    [`fsync_dir_best_effort`]。
//!
//! # 错误
//!
//! 所有失败都返回 [`std::io::Error`]（不 panic、不吞错）；失败时目标文件保持原样。
//! `tracing` 只记录 `debug` 级上下文（路径 / tmp / 阶段），不改变调用方原有的日志口径。

use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// tmp 文件命名策略。**逐调用点保留 2.1.35 的原命名**，避免改变崩溃残留的可观测形态。
#[derive(Clone, Debug)]
pub enum TmpName {
    /// `<name>.<pid>.<单调序号>.tmp`（缓存 v2 的每代独立名；也是本 crate 的默认）。
    Unique,
    /// `path.with_extension(ext)`，例如 `config.json` + `json.tmp` ⇒ `config.json.tmp`。
    WithExtension(&'static str),
    /// 在完整路径后追加字面量，例如 `rules.json` + `.tmp` ⇒ `rules.json.tmp`。
    Suffix(&'static str),
    /// 调用方已经算好的精确 tmp 路径（`state_store` 的 `<part>.<rev>.tmp`、
    /// `main_state::write_cfg_atomic` 的 `<path>.tmp.<pid>`）。
    Explicit(PathBuf),
}

/// 一次原子写的策略。字段全部 `pub`，调用方只覆盖与 2.1.35 不同的部分。
#[derive(Clone, Debug)]
pub struct WriteOptions {
    /// tmp 命名（默认 [`TmpName::Unique`]）。
    pub tmp: TmpName,
    /// 写之前 `create_dir_all(parent)`（规则/订阅写路径为 `true`；配置/状态原路径为 `false`）。
    pub create_parent: bool,
    /// 任一阶段失败时删除 tmp（规则/订阅/缓存为 `true`；`main/api/state_store/main_state`
    /// 历史上**故意保留** tmp 交由启动清理，为 `false`）。
    pub cleanup_on_error: bool,
    /// rename 之前把目标文件原有的权限位复制到 tmp（仅 `main_state::write_cfg_atomic`）。
    pub preserve_mode: bool,
}

impl Default for WriteOptions {
    fn default() -> Self {
        Self {
            tmp: TmpName::Unique,
            create_parent: false,
            cleanup_on_error: false,
            preserve_mode: false,
        }
    }
}

impl WriteOptions {
    /// `path.json.tmp`（`main.rs` / `api.rs` / `main_state::write_rules_source` 的历史命名）。
    pub fn json_tmp() -> Self {
        Self {
            tmp: TmpName::WithExtension("json.tmp"),
            ..Self::default()
        }
    }

    /// `path.tmp` + 建父目录 + 失败清理（`rules_admin` / `subscribe` 的历史语义）。
    pub fn appended(suffix: &'static str) -> Self {
        Self {
            tmp: TmpName::Suffix(suffix),
            create_parent: true,
            cleanup_on_error: true,
            preserve_mode: false,
        }
    }
}

/// 目录 `fsync`（真实错误返回给调用方）。
pub fn fsync_dir(dir: &Path) -> io::Result<()> {
    let d = File::open(dir)?;
    d.sync_all()
}

/// 目录 `fsync` 的**历史 best-effort 口径**：打不开/不支持（tmpfs、Windows）时只记
/// `debug` 日志并继续。2.1.35 的六处内联实现全是这个语义，收敛后由本函数唯一承载。
pub fn fsync_dir_best_effort(dir: &Path) {
    if let Err(e) = fsync_dir(dir) {
        tracing::debug!(
            dir = %dir.display(),
            error = %e,
            "目录 fsync 不可用（按既有语义降级：文件本体已 fsync）"
        );
    }
}

/// 空父路径 → `.`（与树内既有 `dir_of` 同口径）。
fn dir_of(path: &Path) -> PathBuf {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

fn unique_tmp(path: &Path) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = dir_of(path);
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "atomic".to_string());
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    dir.join(format!("{name}.{}.{}.tmp", std::process::id(), n))
}

fn tmp_path(path: &Path, policy: &TmpName) -> PathBuf {
    match policy {
        TmpName::Unique => unique_tmp(path),
        TmpName::WithExtension(ext) => path.with_extension(ext),
        TmpName::Suffix(suffix) => {
            let mut os = path.as_os_str().to_os_string();
            os.push(suffix);
            PathBuf::from(os)
        }
        TmpName::Explicit(p) => p.clone(),
    }
}

/// **唯一实现**：按 [`WriteOptions`] 执行 `tmp → fsync → [chmod] → rename → fsync(dir)`。
///
/// 内容由 `fill` 写入 64 KiB 的 `BufWriter`；回调返回 `Err` ⇒ 不 rename。
pub fn atomic_write_with<F>(path: &Path, opts: &WriteOptions, fill: F) -> io::Result<()>
where
    F: FnOnce(&mut BufWriter<File>) -> io::Result<()>,
{
    let dir = dir_of(path);
    let tmp = tmp_path(path, &opts.tmp);
    let mut stage = "create-parent";
    let mut created = false;
    let res = (|| -> io::Result<()> {
        if opts.create_parent {
            fs::create_dir_all(&dir)?;
        }
        stage = "create-tmp";
        let f = File::create(&tmp)?;
        created = true;
        // 64 KiB 与落盘最小块对齐：既不放大 syscall，也不把整份文件驻留内存。
        let mut w = BufWriter::with_capacity(64 * 1024, f);
        fill(&mut w)?;
        w.flush()?;
        stage = "fsync-file";
        let f = w.into_inner().map_err(|e| e.into_error())?;
        f.sync_all()?;
        #[cfg(unix)]
        if opts.preserve_mode {
            use std::os::unix::fs::PermissionsExt;
            // **2.1.45（P2-7 / REV247 P2-3）**：目标不存在时**不得**沿用 tmp 的默认
            // 0644 —— 安装口径是 0640（`/etc/ebpdns/*` 含上游凭据）。旧实现只在目标
            // 存在时复制权限，于是"回退恢复写回一个不存在的 part / 首次提交"会把权限
            // 放宽成 0644（一次 RolledBack 即放宽 config.json 的可读性）。
            let mode = fs::metadata(path)
                .map(|m| m.permissions().mode() & 0o7777)
                .unwrap_or(0o640);
            let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(mode));
        }
        stage = "rename";
        fs::rename(&tmp, path)?;
        stage = "fsync-dir";
        fsync_dir_best_effort(&dir);
        Ok(())
    })();
    if let Err(e) = &res {
        tracing::debug!(
            path = %path.display(),
            tmp = %tmp.display(),
            stage,
            error = %e,
            "原子写失败（目标文件保持原样）"
        );
        if opts.cleanup_on_error && created {
            let _ = fs::remove_file(&tmp);
        }
    }
    res
}

/// 整块字节的原子写（自定义策略）。
pub fn atomic_write_bytes_opts(path: &Path, bytes: &[u8], opts: &WriteOptions) -> io::Result<()> {
    atomic_write_with(path, opts, |w| w.write_all(bytes))
}

/// 整块字节的原子写（默认 `TmpName::Unique`：`<name>.<pid>.<seq>.tmp`）。
pub fn atomic_write_bytes(path: &Path, bytes: &[u8]) -> io::Result<()> {
    atomic_write_bytes_opts(path, bytes, &WriteOptions::default())
}

/// JSON 的原子写（`serde_json::to_vec_pretty`，默认唯一 tmp 名）。
pub fn atomic_write_json<T: serde::Serialize>(path: &Path, value: &T) -> io::Result<()> {
    let body = serde_json::to_vec_pretty(value).map_err(io::Error::other)?;
    atomic_write_bytes(path, &body)
}

/// 追加写 + `fdatasync`（WAL/审计日志类"只追加、不覆盖"的共用原语）。
///
/// 不改变"打开句柄后批量追加"的既有 WAL 写法（`WalWriter` 需要维护 `valid_len`），
/// 但给一次性追加路径一个不重复实现 fsync 的入口。
pub fn append_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(bytes)?;
    f.flush()?;
    f.sync_data()?;
    Ok(())
}
