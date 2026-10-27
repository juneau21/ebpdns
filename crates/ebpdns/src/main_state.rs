//! **2.1.22 阶段一**：binary 侧的 `state/` 装配（路径解析 / 启动序列 / 离线迁移辅助）。
//!
//! ## 为什么单独成模块
//!
//! `main.rs` 是 3 700 行的守护进程装配，而本阶段新增的是**启动期**的三段式序列：
//!
//! ```text
//! resolve_state_dir(cfg)              // 1) 路径（可配置，默认 /var/lib/ebpdns/state）
//!   → StateStore::open(dir, 2)        // 2) 打开（**不写盘**）
//!   → cleanup_stale_tmp()             // 3) 清理上一个进程崩溃留下的 *.tmp
//!   → load()                          // 4) 四态分派
//!        Legacy      ⇒ 触发迁移（加法导入 → 删 config.json.rules）
//!        Committed   ⇒ 直接用
//!        RolledBack  ⇒ WARN + 用回退后的世代
//!        Torn        ⇒ ERROR（当前与上一代都坏 —— 必须报警）
//! ```
//!
//! 把这段放进 `main_state.rs` 后，`main()` 里只剩一次调用，且**全部路径逻辑**
//! （含"`state_persist=false` ⇒ 不启用"与"目录建不出来 ⇒ 不启用并 WARN"）都可单测。
//!
//! ## 边界（**绝不阻断启动**）
//!
//! 统一事务是**加固**，不是启动前提：`state/` 建不出来（只读文件系统 / 权限不足 /
//! 自定义路径没同步改 systemd `ReadWritePaths`）时，本模块**WARN 并返回 `None`**
//! ⇒ 服务按 2.1.21 的行为起来（各写者各自原子写），而不是起不来。
//! 「配置路径 ≠ 真源」这类**语义**问题则必须 WARN 并**指明权威文件**（不得静默）。

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::Value;

/// `state/` 默认位置（与 `packaging/systemd/ebpdns.service` 的
/// `ReadWritePaths=/etc/ebpdns /var/lib/ebpdns` + `StateDirectory=ebpdns` 一致）。
pub const DEFAULT_STATE_DIR: &str = "/var/lib/ebpdns/state";

/// 历史世代保留数（默认 2；`state_store` 内部还有"至少保底 1"的约束）。
pub const HISTORY_KEEP: usize = 2;

/// `state_dir` 默认值的**允许条件**（**2.1.23 / DEF-222-02**）。
///
/// 默认路径 `/var/lib/ebpdns/state` 是**生产路径**。2.1.22 的 `resolve_state_dir` 在
/// "配置解析失败 ⇒ 用默认配置"时会静默回落到它 ⇒ 隔离实例读写生产状态目录。因此本枚举
/// 把"凭什么可以用默认值"变成**显式输入**：
///
/// * [`StateDirOrigin::Explicit`]：CLI `--state-dir` 或配置里**真的**给了 `state_dir`
///   ⇒ 用它（不是"默认值"，是用户给的）。
/// * [`StateDirOrigin::FreshInstall`]：没有 `commit.json` ⇒ 全新安装，用默认值合理。
/// * [`StateDirOrigin::ConfigUnusable`]：配置不可信（解析失败/不存在）**且**没有显式
///   给出目录 ⇒ 若默认目录里已有 `commit.json`（= 别人在用的状态目录）⇒ **拒绝**。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateDirOrigin {
    /// 显式给出（CLI `--state-dir` 或配置文件里的 `state_dir`）。
    Explicit,
    /// 全新安装（无配置文件且目标目录没有既有 `commit.json`）。
    FreshInstall,
    /// 配置不可信且没有显式目录 ⇒ **不允许**占用既有状态目录。
    ConfigUnusable,
}

/// `state_dir` 解析失败（**fail-closed**）：调用方**必须**拒绝启动。
#[derive(Clone, Debug)]
pub struct StateDirError {
    /// 人类可读原因（进 stderr + 日志）。
    pub reason: String,
}

impl std::fmt::Display for StateDirError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

/// **解析生效的 `state/` 目录（2.1.23：带"凭什么用默认值"的显式判据）**。
///
/// 优先级：CLI `--state-dir` > `cfg["state_dir"]`（非空字符串）> 环境变量
/// `EBPDNS_STATE_DIR` > [`DEFAULT_STATE_DIR`]。相对路径以**进程 CWD** 为基准
/// （`config.json` 的同目录语义不适用于 `state/`：它与 `/etc` 不同目录本就是常态）。
///
/// **关键约束（DEF-222-02，P0）**：最后一档（默认值）在
/// `origin == ConfigUnusable` **且**默认目录里已有 `commit.json` 时**返回 Err** ——
/// 也就是说"配置读不出来 ⇒ 静默落到生产状态目录"这条路被**堵死**。调用方
/// （`main()`）据此拒绝启动并打印明确原因。
pub fn resolve_state_dir_checked(
    cfg: &Value,
    cli_state_dir: Option<&Path>,
    origin: StateDirOrigin,
) -> Result<PathBuf, StateDirError> {
    if let Some(p) = cli_state_dir {
        if !p.as_os_str().is_empty() {
            return Ok(p.to_path_buf());
        }
    }
    if let Some(p) = cfg
        .get("state_dir")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return Ok(PathBuf::from(p));
    }
    if let Ok(p) = std::env::var("EBPDNS_STATE_DIR") {
        let p = p.trim().to_string();
        if !p.is_empty() {
            return Ok(PathBuf::from(p));
        }
    }
    let dflt = PathBuf::from(DEFAULT_STATE_DIR);
    if origin == StateDirOrigin::ConfigUnusable && dflt.join("commit.json").exists() {
        return Err(StateDirError {
            reason: format!(
                "配置不可信（解析失败 / 不存在）且未显式指定 `state_dir`；\
                 默认目录 `{}` 里**已有 `commit.json`**（说明那是**既有实例的状态目录**）\
                 ⇒ 拒绝使用它（否则本次进程会读写别人的提交点与规则真源）。\
                 修法：① 修好配置文件后重启；或 ② `--state-dir <专用目录>` 显式指定。",
                dflt.display()
            ),
        });
    }
    Ok(dflt)
}

/// 解析生效的 `state/` 目录（**兼容形态**：不区分来源，恒返回默认值）。
///
/// **2.1.23 起生产路径一律用 [`resolve_state_dir_checked`]**；本函数只为"只读地看
/// 默认值是什么"的调用点（如 `main.rs::rules_source_hint` 的离线提示）保留。
pub fn resolve_state_dir(cfg: &Value) -> PathBuf {
    resolve_state_dir_checked(cfg, None, StateDirOrigin::Explicit)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_STATE_DIR))
}

/// 统一事务是否按配置启用（`state_persist`；缺键 ⇒ 启用）。
///
/// 缺键即启用是本阶段的取舍：`state_dir` / `state_persist` 是 2.1.22 的新键，
/// 老配置经 `migrate_cfg` 补齐后一定有它们；**没有**它们只可能出现在
/// "手工构造的 cfg"（测试）里，此时按新语义（启用）走更安全。
pub fn enabled_by_cfg(cfg: &Value) -> bool {
    cfg.get("state_persist")
        .map(|v| match v {
            Value::Bool(b) => *b,
            Value::Null => false,
            Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
            Value::String(s) => !matches!(
                s.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "off" | "no"
            ),
            _ => true,
        })
        .unwrap_or(true)
}

/// 打开 `state/` 并跑完**启动序列**（`open` → `cleanup_stale_tmp` → `load`）。
///
/// 返回 `(store, 判定结果)`；`None` = 未启用（见模块头「边界」）。
/// `load()` 的结果由调用方分派（`Legacy` 触发迁移，`Torn` 必须报警）。
pub fn open_state(
    dir: &Path,
) -> Option<(Arc<ebpdns_server::StateStore>, ebpdns_server::LoadState)> {
    let store = match ebpdns_server::StateStore::open(dir, HISTORY_KEEP) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::warn!(
                state_dir = %dir.display(),
                error = %e,
                "**统一持久化事务未启用**：无法打开/创建 `state/` 目录 ⇒ 本次按 2.1.21 行为运行\
                 （各写者各自原子写）。若用的是自定义路径，请同步修改 systemd unit 的 \
                 `ReadWritePaths=`（默认值已覆盖 `/var/lib/ebpdns`）"
            );
            return None;
        }
    };
    // 上一个进程崩溃留下的暂存文件：读方**从不**读它们，删除任意 `*.tmp` 都安全。
    let n = store.cleanup_stale_tmp();
    if n > 0 {
        tracing::info!(
            removed = n,
            state_dir = %dir.display(),
            "启动清理：删除上一次运行残留的暂存文件（`*.tmp`，提交协议中读方从不引用）"
        );
    }
    let state = store.load();
    match &state {
        ebpdns_server::LoadState::Legacy => {
            tracing::info!(
                state_dir = %dir.display(),
                "`state/` 无 `commit.json` ⇒ 2.1.21 布局（或全新安装）：交由迁移处理（**不是错误**）"
            );
        }
        ebpdns_server::LoadState::Committed(c) => {
            tracing::info!(
                revision = c.revision,
                writer = %c.writer,
                parts = c.parts.len(),
                "统一持久化事务已就绪（当前世代校验通过）"
            );
        }
        ebpdns_server::LoadState::RolledBack { broken, restored } => {
            tracing::warn!(
                broken = broken,
                restored = restored.revision,
                "**`state/` 当前世代校验失败 ⇒ 已回退上一代**（读方现在看到的是上一个完整世代）"
            );
        }
        ebpdns_server::LoadState::Torn { reason } => {
            tracing::error!(
                state_dir = %dir.display(),
                reason = %reason,
                "**`state/` 当前世代与上一代都不可用（TORN）** —— 必须人工介入（见 history/）；\
                 服务仍会启动，但持久化世代已失去一致性保证"
            );
        }
    }
    Some((store, state))
}

/// 真源规则文件路径（`<state_dir>/rules.json`）。
pub fn rules_source_path(state_dir: &Path) -> PathBuf {
    state_dir.join("rules.json")
}

/// `state/` 的独占锁文件（**2.1.23 / DEF-222-03**）。
pub const LOCK_FILE: &str = ".lock";

/// `state/` 独占锁的持有者（进程活着期间必须**一直**持有）。
///
/// 审计 DEF-222-03 实测：两个实例共用同一 `state_dir` 时，B 的一次 `PUT /api/config`
/// 就**覆盖了 A 的 `config.json` 与内存配置**（A.cache_size 4242→5555），生产
/// `history/` 里还留下了审查夹具的路径世代。⇒ 默认必须**拒绝**第二个实例。
pub struct StateLock {
    /// 锁文件句柄：**drop 即释放 flock**，因此必须与进程同寿。
    _file: std::fs::File,
    /// 锁文件路径（诊断用）。
    path: PathBuf,
}

impl StateLock {
    /// 锁文件路径。
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// **2.1.29（M25）**：把非阻塞独占 `flock` 泛化成“任意路径”的辅助函数。
///
/// 缓存持久化 v2 用 `flock("<cache_file>.lock")` 保证**单写者**（§6.4）：
/// * 成功 ⇒ 返回锁文件句柄（**drop 即释放**，因此必须与进程同寿）；
/// * 已被别的进程持有 ⇒ `Err(AlreadyLocked)`，cache 侧**不写任何 cache 文件**
///   （仍可只读恢复），DNS 不受影响。
///
/// 为什么复用这里的实现而不是在 cache 侧再写一份 `extern "C"`：常量/错误映射/
/// “同一进程内已持有”的语义只能有一处定义，否则两个锁的行为会漂移。
#[cfg(unix)]
pub fn acquire_flock(path: &Path) -> Result<std::fs::File, LockError> {
    use std::os::unix::io::AsRawFd;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
        .map_err(|e| LockError::Io(format!("{}: {e}", path.display())))?;
    // SAFETY: `flock` 是 libc 的普通系统调用；fd 在 `file` 存活期间有效。
    let rc = unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(EAGAIN) || err.raw_os_error() == Some(EWOULDBLOCK) {
            let holder = std::fs::read_to_string(path).unwrap_or_default();
            return Err(LockError::AlreadyLocked {
                path: path.to_path_buf(),
                holder: holder.trim().to_string(),
            });
        }
        return Err(LockError::Io(format!("flock {}: {err}", path.display())));
    }
    // 持有者身份（诊断用；判据是 flock 本身）。
    {
        use std::io::Write as _;
        let _ = file.set_len(0);
        let mut f = &file;
        let _ = writeln!(
            f,
            "pid={} host={} exe={}",
            std::process::id(),
            hostname_or_unknown(),
            std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "?".into())
        );
    }
    Ok(file)
}

#[cfg(not(unix))]
pub fn acquire_flock(_path: &Path) -> Result<std::fs::File, LockError> {
    Err(LockError::Io(
        "本平台不支持 `flock`：无法保证 cache_file 单写者（请确保单实例运行）".to_string(),
    ))
}

/// **尝试获取 `state/` 的独占锁**（`flock(LOCK_EX | LOCK_NB)`）。
///
/// 判据与语义：
/// * 成功 ⇒ 返回 [`StateLock`]（调用方必须把它存到进程结束）；
/// * 已被**别的进程**持有 ⇒ `Err(AlreadyLocked)`，`main()` 据此**拒绝启动**
///   （可用 `--allow-shared-state-dir` 显式放行）；
/// * 同一进程内重复获取 ⇒ 也算已持有（`flock` 对同一 fd 是递归的；这里用
///   进程内静态标记提前短路，避免"自己挡住自己"）。
///
/// 为什么用 `flock` 而不是 pidfile：`flock` 由内核在 fd 关闭 / 进程退出时**自动释放**，
/// 因此不会留下"陈旧 pidfile 挡住启动"的问题（pidfile 需要额外处理 PID 复用与陈尸）。
#[cfg(unix)]
pub fn acquire_state_lock(dir: &Path) -> Result<StateLock, LockError> {
    use std::os::unix::io::AsRawFd;

    // 同一进程内已持有 ⇒ 直接返回一个新的句柄（不重复 flock，避免自我阻塞）。
    if STATE_LOCK_HELD.load(std::sync::atomic::Ordering::Relaxed) {
        let f = std::fs::OpenOptions::new()
            .read(true)
            .open(dir.join(LOCK_FILE))
            .map_err(|e| LockError::Io(format!("{e}")))?;
        return Ok(StateLock {
            _file: f,
            path: dir.join(LOCK_FILE),
        });
    }
    std::fs::create_dir_all(dir).map_err(|e| LockError::Io(format!("{e}")))?;
    let path = dir.join(LOCK_FILE);
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| LockError::Io(format!("{}: {e}", path.display())))?;
    // SAFETY: `flock` 是 libc 的普通系统调用；fd 在 `file` 存活期间有效。
    let rc = unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(EAGAIN) || err.raw_os_error() == Some(EWOULDBLOCK) {
            // 读一把持有者信息，给运维可执行的提示。
            let holder = std::fs::read_to_string(&path).unwrap_or_default();
            return Err(LockError::AlreadyLocked {
                path,
                holder: holder.trim().to_string(),
            });
        }
        return Err(LockError::Io(format!("flock {}: {err}", path.display())));
    }
    // 写下持有者身份（诊断用；**判据是 flock 本身**，不是文件内容）。
    {
        use std::io::Write as _;
        let mut f = &file;
        let _ = f.set_len(0);
        let _ = write!(
            f,
            "pid={}\nhost={}\nwriter=ebpdns {}\n",
            std::process::id(),
            hostname_or_unknown(),
            // **2.1.24**：版本从 `CARGO_PKG_VERSION` 取，不再硬编码（原来是一个**只有
            // 升级时才暴露**的漂移点：锁文件里会写着上一版的版本号）。
            env!("CARGO_PKG_VERSION")
        );
    }
    STATE_LOCK_HELD.store(true, std::sync::atomic::Ordering::Relaxed);
    Ok(StateLock { _file: file, path })
}

/// 非 Unix 平台的占位（本仓交付目标是 Linux/systemd；Windows 上不做锁）。
#[cfg(not(unix))]
pub fn acquire_state_lock(_dir: &Path) -> Result<StateLock, LockError> {
    Err(LockError::Io(
        "本平台不支持 `flock`：无法保证 `state_dir` 独占（请确保单实例运行）".to_string(),
    ))
}

static STATE_LOCK_HELD: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// **把锁句柄交给进程级守卫**（服务路径**必须**调用，否则 `flock` 会在句柄 drop 时释放）。
///
/// 为什么用静态变量：`flock` 的语义是"**fd 关闭即释放**"。若把 [`StateLock`] 留在
/// `main()` 的局部变量里，它会在 `main()` 返回时（或任何一次 move 之后被 drop 时）
/// 释放锁 ⇒ 保护形同虚设。放进 `OnceLock` 后句柄与**进程同寿**。
///
/// **注意**：离线 CLI（`migrate-config` / `--export-legacy`）走 [`reanchor_state`]，
/// 那里的锁句柄是**局部**的（函数返回即释放）—— 因为 CLI 本来就该跑完就退出，
/// 不应该把状态目录"锁住"留给下一条命令。
pub fn keep_lock_alive(lock: StateLock) {
    static HOLDER: std::sync::OnceLock<std::sync::Mutex<Option<StateLock>>> =
        std::sync::OnceLock::new();
    let slot = HOLDER.get_or_init(|| std::sync::Mutex::new(None));
    if let Ok(mut g) = slot.lock() {
        *g = Some(lock);
    }
}

// `flock(2)` 的常量与原型（避免为两个常量引入 `libc` 依赖）。
#[cfg(unix)]
const LOCK_EX: i32 = 2;
#[cfg(unix)]
const LOCK_NB: i32 = 4;
#[cfg(unix)]
const EAGAIN: i32 = 11;
#[cfg(unix)]
const EWOULDBLOCK: i32 = 11;

#[cfg(unix)]
extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
}

/// **测试用**：对给定 fd 做一次非阻塞独占 `flock`，返回 libc 的返回码（`0` = 成功）。
///
/// 为什么需要它：进程内的"已持有"短路（[`STATE_LOCK_HELD`]）会挡住**同一进程**的
/// 第二次 `acquire_state_lock`，于是"锁到底有没有真的生效"在进程内测不出来。
/// 本函数用**另一个 fd** 直接问内核 ⇒ 能测到真实的互斥。
///
/// `#[cfg(test)]`：非测试构建里没有调用点（留 `pub` 会引入 `dead_code` 警告，
/// 而"零警告"是本项目的门禁之一）。
#[cfg(all(test, unix))]
pub fn test_flock_nonblocking(fd: i32) -> i32 {
    // SAFETY: 调用方保证 `fd` 在本调用期间有效。
    unsafe { flock(fd, LOCK_EX | LOCK_NB) }
}

/// 取锁失败的原因。
#[derive(Clone, Debug)]
pub enum LockError {
    /// 已被**别的进程**持有（`main()` 据此拒绝启动）。
    AlreadyLocked {
        /// 锁文件路径。
        path: PathBuf,
        /// 持有者信息（`pid=…` / `host=…`；可能为空）。
        holder: String,
    },
    /// IO / 平台不支持。
    Io(String),
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockError::AlreadyLocked { path, holder } => write!(
                f,
                "`state/` 目录已被**另一个实例**独占（锁文件 {}；持有者：{}）。\
                 单机必须**单实例**：共用 `state_dir` 会让两个进程互相覆盖 `config.json`\
                 与提交点（实测：B 的一次 PUT 就改掉了 A 的配置）。\
                 修法：① 停掉旧实例；或 ② 给本实例换一个 `state_dir`\
                 （`--state-dir <专用目录>` / 配置里的 `state_dir`）；\
                 或 ③ 确实要共用时显式加 `--allow-shared-state-dir`（危险）。",
                path.display(),
                if holder.is_empty() { "未知" } else { holder }
            ),
            LockError::Io(m) => write!(f, "{m}"),
        }
    }
}

/// 主机名（写进锁文件；失败 ⇒ `unknown`）。
#[cfg(unix)]
fn hostname_or_unknown() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(not(unix))]
fn hostname_or_unknown() -> String {
    "unknown".to_string()
}

/// **`commit.json` 的 part 路径是否与本实例一致**（共享目录的**第二道**判据）。
///
/// `flock` 挡住"同时运行的第二个实例"，但挡不住"上一次是**别的实例**留下的状态目录"
/// （例如隔离实例复用了生产 `state_dir`：进程已退出，锁已释放，但提交点里记的是
/// **别人的** `config.json` 路径）。此时若照常启动，回退点会指向别人的文件、
/// `prev_generation_ok=true` 给出**虚假安全感**（审计 DEF-222-03 的实测后果）。
///
/// 判据：`commit.json` 的 parts 里**必须**包含本实例的 `cfg_path`；
/// 一个都没有 ⇒ 判定"这不是我的状态目录"。
pub fn commit_matches_own_cfg_path(
    store: &ebpdns_server::StateStore,
    cfg_path: Option<&Path>,
) -> Result<(), String> {
    let Some(c) = store.snapshot() else {
        return Ok(()); // 无提交点（Legacy）⇒ 无法判定，交由迁移处理。
    };
    let Some(own) = cfg_path else {
        return Ok(()); // 纯内存态：无 cfg_path 可对。
    };
    let own_s = own.to_string_lossy().to_string();
    if c.parts.iter().any(|p| p.path == own_s) {
        return Ok(());
    }
    let listed: Vec<&str> = c.parts.iter().map(|p| p.path.as_str()).collect();
    Err(format!(
        "`state/` 的提交点里**没有本实例的配置路径**（own={own_s}；\
         提交点记录的 parts={listed:?}）⇒ 这个 `state_dir` 属于**另一个实例**\
         （它记的是别人的 part 路径）。继续使用会让回退点指向别的实例的文件、\
         并给出虚假的 `prev_generation_ok=true`。\
         修法：换一个 `state_dir`（`--state-dir`），或确认无误后用 \
         `--allow-shared-state-dir` 显式放行。"
    ))
}

/// **原子写**一份规则真源（迁移的加法导入用；`tmp → fsync → rename → fsync(dir)`）。
///
/// 与 `state_store` 内部的原语同协议；这里单独实现是因为迁移发生在
/// **store 打开之前/之后但不在提交流程里**（它是"把旧布局搬进新布局"，
/// 之后还会走一次正常提交把 `commit.json` 建起来）。
pub fn write_rules_source(path: &Path, rules: &[Value]) -> std::io::Result<()> {
    let doc = serde_json::json!({
        "version": 1,
        "saved_at": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        "count": rules.len(),
        "rules": rules,
    });
    let body = serde_json::to_vec(&doc)?;
    // **2.1.36（D 批）**：`json.tmp` 命名 + 建父目录 + 失败保留 tmp（既有语义）。
    let opts = ebpdns_fs::WriteOptions {
        create_parent: true,
        ..ebpdns_fs::WriteOptions::json_tmp()
    };
    ebpdns_fs::atomic_write_bytes_opts(path, &body, &opts)
}

/// **启动期旧布局迁移**（`load()` 判为 `Legacy` 时调用）。
///
/// 与 `ebpdns migrate-config` 的 `migrate_v2_to_v3` **同语义**，但发生在**启动**路径上，
/// 因此必须额外保证：
/// * **先备份** `config.json.bak.<ts>`（且只在**确实要改配置**时才写回）；
/// * 加法导入 `state/rules.json`（已存在 ⇒ 不覆盖：磁盘真源永远优先）；
/// * 只有真源**确实存在**（导入成功或本来就有）才删除 `config.json.rules`；
/// * **绝不阻断启动**：出错返回 `Err`，调用方打 ERROR 并按旧行为继续。
///
/// 返回人类可读的步骤列表（写进 INFO 日志，供审计"这台机器是什么时候升格的"）。
pub fn migrate_legacy_rules(
    cfg: &mut Value,
    cfg_path: Option<&Path>,
    state_dir: &Path,
) -> Result<Vec<String>, String> {
    let mut steps: Vec<String> = Vec::new();
    let auth = rules_source_path(state_dir);
    let rules = cfg.get("rules").and_then(Value::as_array).cloned();
    let n = rules.as_ref().map(|a| a.len()).unwrap_or(0);
    let has_mirror = cfg
        .as_object()
        .map(|o| o.contains_key("rules"))
        .unwrap_or(false);
    if n == 0 && !has_mirror {
        steps.push("无需迁移：`config.json` 没有 `rules` 键（规则只可能在独立文件里）".into());
        // 真源缺失但独立规则文件存在（2.1.20 的默认位置）⇒ 也做一次加法导入。
        if !auth.is_file() {
            if let Some(cp) = cfg_path {
                let legacy = ebpdns_rules::load::local_rules_path(cp);
                if let Some(arr) = read_rules_array(&legacy) {
                    if !arr.is_empty() {
                        write_rules_source(&auth, &arr)
                            .map_err(|e| format!("加法导入 {} 失败: {e}", auth.display()))?;
                        steps.push(format!(
                            "加法导入 {} 条规则：{} → {}（2.1.20 的独立规则文件成为真源）",
                            arr.len(),
                            legacy.display(),
                            auth.display()
                        ));
                    }
                }
            }
        }
        return Ok(steps);
    }
    if !auth.is_file() {
        if let Some(arr) = &rules {
            if !arr.is_empty() {
                write_rules_source(&auth, arr)
                    .map_err(|e| format!("加法导入 {} 失败: {e}", auth.display()))?;
                steps.push(format!(
                    "加法导入 {} 条规则：`config.json.rules` → {}（真源；原子写 + fsync）",
                    arr.len(),
                    auth.display()
                ));
            }
        }
    } else {
        steps.push(format!(
            "真源 {} 已存在 ⇒ **不覆盖**（磁盘真源优先于 `config.json.rules`）",
            auth.display()
        ));
        // 此时若两侧不同，说明配置里那份是过期的 ⇒ **WARN 并指明权威文件**（不得静默）。
        if let Some(arr) = &rules {
            let disk = read_rules_array(&auth).unwrap_or_default();
            if !arr.is_empty() && &disk != arr {
                tracing::warn!(
                    config_rules = arr.len(),
                    authoritative_rules = disk.len(),
                    authoritative = %auth.display(),
                    "**`config.json.rules`（{} 条）与真源 {}（{} 条）不一致 ⇒ 以真源为准**\
                     （这是 2.1.22 的单一真源语义；`config.json.rules` 仅供参考，\
                     本次迁移会删除该镜像键）",
                    arr.len(),
                    auth.display(),
                    disk.len()
                );
            }
        }
    }
    if has_mirror {
        if auth.is_file() {
            cfg.as_object_mut().map(|o| o.remove("rules"));
            steps.push(format!(
                "**删除** `config.json.rules` 镜像键（{n} 条已在真源 {} 中）",
                auth.display()
            ));
            // 只有"确实改了配置内容"才写回：备份 → 原子替换。
            if let Some(cp) = cfg_path {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let bak = PathBuf::from(format!("{}.bak.{ts}", cp.display()));
                std::fs::copy(cp, &bak)
                    .map_err(|e| format!("备份 {} 失败（**未改动原文件**）: {e}", cp.display()))?;
                write_cfg_atomic(cp, cfg).map_err(|e| {
                    format!(
                        "写回 {} 失败（原文件已备份在 {}）: {e}",
                        cp.display(),
                        bak.display()
                    )
                })?;
                steps.push(format!(
                    "备份原配置 → {}；并把去掉 `rules` 的配置原子写回 {}",
                    bak.display(),
                    cp.display()
                ));
            }
        } else {
            steps.push("**保留** `config.json.rules`（真源不存在 ⇒ 删了就真丢，宁可留着）".into());
        }
    }
    Ok(steps)
}

/// `config.json` 的原子写回（`tmp → fsync → rename → fsync(dir)`，权限对齐原文件）。
fn write_cfg_atomic(path: &Path, cfg: &Value) -> std::io::Result<()> {
    let body = serde_json::to_vec_pretty(cfg).map_err(std::io::Error::other)?;
    // **2.1.36（D 批）**：`<path>.tmp.<pid>` 命名、失败保留 tmp、**保留原文件权限位**
    // 三条历史语义全部经 `WriteOptions` 显式声明。
    let opts = ebpdns_fs::WriteOptions {
        tmp: ebpdns_fs::TmpName::Explicit(PathBuf::from(format!(
            "{}.tmp.{}",
            path.display(),
            std::process::id()
        ))),
        create_parent: false,
        cleanup_on_error: false,
        preserve_mode: true,
    };
    ebpdns_fs::atomic_write_bytes_opts(path, &body, &opts)
}

/// **离线写回之后"重新锚定提交点"**（**2.1.23 / DEF-222-05**）。
///
/// # 为什么必须有这一步
///
/// `config.json` 是提交点记录的一个 **part**；而运维习惯（以及 `migrate-config` /
/// `--export-legacy` 两条离线路径）都是**直接改那个文件**。2.1.22 的写回绕过 store、
/// 不更新 `commit.json` ⇒ **下一次启动** `load()` 校验失败 ⇒ `WARN 撕裂`；
/// 没有历史世代时甚至 **TORN**（审计实测；这是"必然踩到"的路径，不是边角）。
///
/// 本函数把"外部改写"变成**受支持的操作**：打开 store（**不取锁** —— 离线 CLI 通常
/// 在服务停止时运行；若服务在跑，锁会挡住并给出清晰提示）、然后把当前世代的
/// part 摘要**按磁盘现状重算**并原子写回（revision 不变）。
///
/// 返回：
/// * `Ok(None)` —— `state/` 不存在或没有 `commit.json`（无需重锚，例如全新安装）；
/// * `Ok(Some(true))` —— 已重锚（有 part 摘要变化）；
/// * `Ok(Some(false))` —— 无需重锚（磁盘与提交点已一致）。
pub fn reanchor_state(
    state_dir: &Path,
    allow_shared: bool,
    writer_suffix: &str,
) -> Result<Option<bool>, String> {
    if !state_dir.join("commit.json").is_file() {
        return Ok(None);
    }
    // 服务在跑时 `flock` 会失败 —— 这正是我们要的（离线写回不该在服务运行时做）。
    let _lock = match acquire_state_lock(state_dir) {
        Ok(l) => Some(l),
        Err(e) => {
            if allow_shared {
                tracing::warn!(state_dir = %state_dir.display(), error = %e,
                    "`--allow-shared-state-dir`：跳过独占检查，继续重锚（服务可能在运行！）");
                None
            } else {
                return Err(format!(
                    "{e}\n（离线写回 `config.json` 必须在**服务停止**时进行，否则会与运行中的\
                     提交竞争。请先停服务，或显式加 `--allow-shared-state-dir`。）"
                ));
            }
        }
    };
    let store = ebpdns_server::StateStore::open(state_dir, HISTORY_KEEP)
        .map_err(|e| format!("打开 {} 失败: {e}", state_dir.display()))?;
    ebpdns_server::state_store::reanchor_commit_after_external_write(&store, writer_suffix)
        .map(Some)
        .map_err(|e| format!("重新锚定提交点失败: {e}"))
}

/// 只读地取一个规则文件里的 `rules` 数组（裸数组 / 信封都认；不存在/坏 ⇒ `None`）。
fn read_rules_array(p: &Path) -> Option<Vec<Value>> {
    let b = std::fs::read(p).ok()?;
    match serde_json::from_slice::<Value>(&b).ok()? {
        Value::Array(a) => Some(a),
        v => v.get("rules").and_then(Value::as_array).cloned(),
    }
}

/// **`--export-legacy`**：把 `state/rules.json` **逐字节**导出回 `cfg["rules"]`
/// （并写回 `config.json`，`config_version` 降回 2）⇒ 供 `3 → 2` 回退到 2.1.21 二进制。
///
/// "逐字节"的含义：导出的 `rules` 数组**原样**来自真源文件里的 `rules` 值
/// （`serde_json::Value` 往返，不重新归一化、不补 id、不排序）——
/// 因此 `2.1.21` 读到的就是 `2.1.22` 提交进去的那一份。
///
/// 返回 `(写入的规则条数, 备份路径)`；`Err` = 真源不存在/不可解析（**不改文件**）。
pub fn export_legacy(cfg_path: &Path, state_dir: &Path) -> Result<(usize, PathBuf, u64), String> {
    let auth = rules_source_path(state_dir);
    let raw = std::fs::read(&auth).map_err(|e| {
        format!(
            "真源 {} 不可读: {e}（先跑一次 migrate-config 建立真源）",
            auth.display()
        )
    })?;
    let v: Value = serde_json::from_slice(&raw)
        .map_err(|e| format!("真源 {} 不是合法 JSON: {e}", auth.display()))?;
    let rules = v
        .get("rules")
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| format!("真源 {} 里没有 `rules` 数组（形状不认识）", auth.display()))?;
    let text = std::fs::read_to_string(cfg_path)
        .map_err(|e| format!("配置 {} 不可读: {e}", cfg_path.display()))?;
    let mut cfg: Value = serde_json::from_str(&text)
        .map_err(|e| format!("配置 {} 不是合法 JSON: {e}", cfg_path.display()))?;
    if !cfg.is_object() {
        return Err(format!(
            "配置 {} 根节点必须是 JSON 对象",
            cfg_path.display()
        ));
    }
    {
        let o = cfg.as_object_mut().ok_or("配置不是对象")?;
        o.insert("rules".into(), Value::Array(rules.clone()));
        // 2.1.21 的 `validate_schema` 会拒绝高于它支持的版本 ⇒ 必须降回 2。
        o.insert("config_version".into(), serde_json::json!(2));
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let bak = PathBuf::from(format!("{}.bak.{ts}", cfg_path.display()));
    std::fs::copy(cfg_path, &bak).map_err(|e| format!("备份失败（未改动原文件）: {e}"))?;
    let out = serde_json::to_vec_pretty(&cfg).map_err(|e| e.to_string())?;
    let tmp = PathBuf::from(format!(
        "{}.export.{}",
        cfg_path.display(),
        std::process::id()
    ));
    std::fs::write(&tmp, &out).map_err(|e| format!("写临时文件失败（原文件未改动）: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(md) = std::fs::metadata(cfg_path) {
            let mode = md.permissions().mode() & 0o7777;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode));
        }
    }
    std::fs::rename(&tmp, cfg_path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("原子替换失败（原文件未改动）: {e}")
    })?;
    Ok((rules.len(), bak, ts))
}
