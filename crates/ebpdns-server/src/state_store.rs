//! **2.1.22 阶段一**：`state/` 单目录 + **两阶段提交（TPC）** 的统一持久化层。
//!
//! ## 为什么需要它（2.1.21 实测的碎片化）
//!
//! 2.1.21 的持久化是**四份各自独立的"原子写"实现**，它们互不知道对方是否成功：
//!
//! | 文件 | 实现 | 位置 |
//! |---|---|---|
//! | `config.json` | `atomic_write_json` → `atomic_write_bytes`（tmp+fsync+rename+dirfsync） | `ebpdns-server/src/api.rs:4259/4273` |
//! | `rules_local.json` | `save_local_rules`（tmp+fsync+rename+dirfsync） | `ebpdns-server/src/rules_admin.rs:183` |
//! | `rules_sub.json` | `atomic_write_stream` / `atomic_write` | `ebpdns-server/src/subscribe.rs:739/933` |
//! | `config.json`（启动期/CLI） | `write_json_atomic`（**同一套逻辑的第二份拷贝**） | `ebpdns/src/main.rs:2637` |
//!
//! **2.1.36（D 批）**：上表的四步协议（以及另外 5 处实现）已全部收敛到
//! `crates/ebpdns-fs/src/lib.rs` 的 [`ebpdns_fs::atomic_write_with`]；本模块只保留
//! **两阶段提交**的步骤/顺序与 `<part>.<rev>.tmp` 命名，底层 `fsync/rename` 不再自有实现。
//!
//! 每个文件**单独**是崩溃安全的，但**跨文件没有事务**：`PUT /api/config` 的顺序是
//! 「写 `config.json` → 改内存 → 写规则文件」（`api.rs:485-533`），进程若在两次写之间
//! `kill -9`，磁盘上就是**新一代 `config.json` + 旧一代规则文件** —— 一个**撕裂的世代**。
//! 2.1.21 只能用"失败后按原始字节回滚"来事后补救（`orig_bytes`，`api.rs:472-521`），
//! 而**崩溃**根本没有回滚的机会。
//!
//! ## 目录布局（**跨目录**是常态，不是特例）
//!
//! 任务书裁决（2.1.22）：`config.json` **保持 `/etc/ebpdns/config.json` 原路径**
//! （运维习惯、文档、清单门禁都不变），而 `commit.json` + `history/` 放
//! `state/`（默认 `/var/lib/ebpdns/state/`，**可配置**）。
//!
//! 因此本模块**不假设**"所有 part 与 `commit.json` 同目录"：
//!
//! ```text
//! /etc/ebpdns/config.json              ← part（人类可编辑、可 diff、进 _md5_prod.txt）
//! /var/lib/ebpdns/state/
//!     commit.json                      ← **提交点**（revision + 各 part 的 sha256/长度）
//!     rules.json                       ← part（规则唯一真源）
//!     subscriptions.json               ← part
//!     history/<rev>/                   ← 已提交的历史世代（每个含自己的 commit.json + part 副本）
//!     <part>.<rev>.tmp                 ← 暂存文件（崩溃残留，读方**从不**读）
//! ```
//!
//! ## fsync 顺序（**规范级要求**）
//!
//! ```text
//! for each part:  write <part>.<rev>.tmp → fsync(文件) → **fsync(该 part 所在目录)**
//!                 （跨目录/跨文件系统时，这一步绝不可省：否则"文件内容已 fsync"不代表
//!                   "目录项已落盘"，掉电后 rename 前的目录项可能整体消失）
//! then:           write commit.json.tmp → fsync(文件) → rename → **fsync(state/)**
//! then:           rename 各 part 就位 → **fsync(各 part 目录)** → fsync(state/)
//! ```
//!
//! **part 与 `commit.json` 可以分处不同目录、甚至不同文件系统**（`/etc` 与
//! `/var/lib` 在多数发行版上就是两个挂载点）—— 协议只要求"**先 fsync 各 part 目录**，
//! 再写提交点"，不要求它们在同一个文件系统上。跨文件系统时 rename 不可用（`EXDEV`），
//! 因此 part 的发布用"**同目录 `.tmp` → rename**"（每个 part 在自己的目录里原子替换），
//! 绝不做跨文件系统 rename。有专门的跨目录用例
//! （`cross_directory_parts_are_committed_atomically`）。
//!
//! ## 提交序列与"撕裂态 = 0"的论证
//!
//! 1. **快照旧世代**进 `history/<cur_rev>/`（含 `commit.json` 副本）—— 回退点；
//! 2. **写暂存区**：每个 part 的 `<name>.<rev>.tmp` + `fsync(文件)` + `fsync(目录)`；
//! 3. **写提交记录**（**提交点**）：`commit.json.tmp` → fsync → rename → fsync(state/)；
//! 4. **发布 part**：同目录 rename `.tmp` → 正式名 + fsync 各目录；
//! 5. **清理**：超出 `history_keep` 的最老世代（默认保留 2，**至少 1**）。
//!
//! * 在**第 3 步之前**崩溃 ⇒ `commit.json` 还是旧的 ⇒ 读方看到**旧世代**（一致）；
//! * 在**第 3 步之后、第 4 步之前**崩溃 ⇒ `commit.json` 写着**新 part 的 sha256**、
//!   而正式 part 文件仍是**旧字节** ⇒ 校验失败 ⇒ **回退上一代** ⇒ 得到**旧世代**（一致）；
//! * 在**第 4 步之后**崩溃 ⇒ 新 part 已就位且与 `commit.json` 吻合 ⇒ **新世代**（一致）。
//!
//! 三条路径的落点只有"旧"或"新"，**没有第三种** —— 这就是"撕裂态 = 0"。该论证已被
//! `scripts/run_crash_inject.sh` 的 **100 次**注入实测（4 个阶段 + 外部 `kill -9`）。
//!
//! ## 摘要算法：用 **SHA-256**（复用已在依赖树里的 `sha2`）
//!
//! 任务书原文写的是"各 part 的 md5"，但同一份任务书的补充要求是：
//! **"若 `sha2`/`sha1`/`ring` 的摘要已在依赖树里，优先复用它，避免维护第二份哈希实现"**。
//! 实测：`Cargo.lock` **已含** `sha2 0.11.0`（`quinn` → `rustls` → `ring` 链上的传递依赖），
//! 把它提为 `ebpdns-server` 的直接依赖 **不需要任何新下载**（`cargo check --offline` 通过），
//! `Cargo.lock` 只多一行 `"sha2"`。因此**不自己造哈希**：用 `sha2::Sha256`。
//!
//! **口径（必须写清）**：本摘要只用于**撕裂 / 意外损坏检测**，**不是抗攻击**用途 ——
//! 能改写 part 的攻击者同样能改写 `commit.json`，本层不承担防篡改职责（鉴权在 HTTP 层）。
//! 调用点**只在提交流程**（不在查询热路径）。
//!
//! ## 边界
//!
//! * 无 SQLite、无新功能；新增依赖仅"已在 lock 里的 `sha2`"；
//! * 目录 fsync 在不支持的文件系统上**静默降级**（与既有四处实现同口径）；
//! * 暂存文件名含 `revision` ⇒ 两个写者不会共用任何临时路径；
//!   跨进程的"丢失更新"由 `if-revision`（HTTP 层）负责，本模块提供 `revision` 读值；
//! * 本模块**不解析业务语义**（不知道 `rules`/`config` 长什么样），只做"多 part 的原子世代"。

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use serde::{Deserialize, Serialize};

/// 单个 part 的提交元数据。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartMeta {
    /// part 的**绝对路径**（如 `/etc/ebpdns/config.json`）。
    ///
    /// 用绝对路径而不是"相对 state/ 的路径"，因为裁决 1 要求 `config.json` 留在
    /// `/etc/ebpdns/`（与 `state/` 不同目录、可能不同文件系统）。
    pub path: String,
    /// 内容的 **SHA-256**（十六进制小写，64 字符）。
    ///
    /// 字段名保留 `md5` 会误导（值不是 md5）⇒ 用 `sha256`；2.1.22 是**新格式**，
    /// 没有历史包袱（旧树没有 `commit.json`，会被识别为 `Legacy` 并迁移）。
    pub sha256: String,
    /// 字节数。
    pub bytes: u64,
}

/// `commit.json` 的结构（**提交点**）。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commit {
    /// 单一递增世代号（毫秒时间戳；小于等于当前值时 +1 ⇒ 严格递增）。
    pub revision: u64,
    /// 写者身份（`"api"` / `"subscribe:<id>"` / `"cli:migrate-config"` …）—— 审计用。
    #[serde(default)]
    pub writer: String,
    /// 提交时刻（epoch 秒）。
    #[serde(default)]
    pub committed_at: u64,
    /// 本次提交若由**回退**产生：从哪个坏 revision 退回。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rolled_back_from: Option<u64>,
    /// 各 part（按 `path` 排序 ⇒ `commit.json` 逐字节稳定）。
    pub parts: Vec<PartMeta>,
}

impl Commit {
    pub fn part(&self, path: &str) -> Option<&PartMeta> {
        self.parts.iter().find(|p| p.path == path)
    }
}

/// 打开 `state/` 的判定结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoadState {
    /// 没有 `commit.json`：2.1.21 布局（或全新安装）—— **不是错误**，调用方应迁移。
    Legacy,
    /// `commit.json` + 全部 part 校验通过。
    Committed(Commit),
    /// 当前世代损坏 ⇒ 已回退到上一代。
    RolledBack { broken: u64, restored: Commit },
    /// 当前与上一代都不可用 —— **必须**报警。
    Torn { reason: String },
}

/// 提交阶段名（传给 [`StateStore::crash_hook`]，也是崩溃注入报告的键）。
pub const STAGE_AFTER_STAGE_PARTS: &str = "after-stage-parts";
pub const STAGE_AFTER_COMMIT_JSON: &str = "after-commit-json";
pub const STAGE_AFTER_RENAME_PARTS: &str = "after-rename-parts";
pub const STAGE_AFTER_PRUNE: &str = "after-prune";

/// 读方 / 写方共用的 store。
pub struct StateStore {
    /// `state/`（`commit.json` 与 `history/` 所在）。
    dir: PathBuf,
    /// 保留的历史世代数（默认 2；至少 1）。
    history_keep: usize,
    /// **崩溃注入钩子**（仅验收用）：提交各阶段末尾调用，可在其中 `abort()`。
    /// 生产路径恒为 `None`（一次 `Option` 判空）。
    pub crash_hook: Option<fn(&'static str)>,
    /// **2.1.48 / serving_revision**：读方**当前实际服务**的世代（0 = 无/未知）。
    ///
    /// 旧实现只在启动时把 `LoadStateInfo.serving_revision` 存进 `AppState`（启动快照），
    /// 之后每次订阅刷新都推进 `commit.json.revision`，但 `serving_revision` **永不更新**
    /// ⇒ `/api/status` 长期显示“revision 1792903065113 / serving 1792900985921”。
    /// 现在由各写者在“**提交成功且索引已就绪**”处调用 [`StateStore::mark_serving_current`]；
    /// `persist_info` 读本字段（回退/`Torn` 由 `load()` 写回旧值/0）。
    serving_rev: AtomicU64,
    /// **2.1.48 / AUD-10**：`prev_generation_ok()` 的缓存（0=未算、1=false、2=true）。
    ///
    /// `/api/status` 前端每 2 s 轮询一次；旧实现每次都读历史世代的全部 part 并算
    /// SHA-256（订阅刷新世代含 3.4 MB `rules_sub.json`）⇒ 每周期数 MB 分配 + 阻塞 IO。
    /// 该值只在提交点变化时才会变，因此 commit/replace_commit/prune 时失效即可。
    prev_ok: AtomicU8,
}

/// SHA-256（十六进制小写）。见模块头"摘要算法"一节。
pub fn sha256_hex(body: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(body);
    let out = h.finalize();
    let mut s = String::with_capacity(64);
    for b in out {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 目录 fsync（best-effort；不支持时静默降级，与既有四处实现同口径）。
///
/// **2.1.36（D 批）**：实现收敛到 [`crate::io_atomic::fsync_dir_best_effort`]。
pub fn fsync_dir(dir: &Path) {
    crate::io_atomic::fsync_dir_best_effort(dir);
}

/// 某个文件所在目录（空父路径 → `.`）。
fn dir_of(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

/// 单个文件：`write tmp → fsync(file) → rename → fsync(dir)`。
///
/// **2.1.36（D 批）**：四步协议收敛到 [`crate::io_atomic::atomic_write_bytes_opts`]。
/// tmp 命名逐字保留（`<stem>.<ext>tmp`；无扩展名 ⇒ `<path>.tmp`），失败**不清理** tmp
/// （由启动 `cleanup_stale_tmp` 回收，既有语义）。
fn atomic_write(path: &Path, body: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension(format!(
        "{}tmp",
        path.extension()
            .map(|e| format!("{}.", e.to_string_lossy()))
            .unwrap_or_default()
    ));
    let opts = crate::io_atomic::WriteOptions {
        tmp: crate::io_atomic::TmpName::Explicit(tmp),
        create_parent: false,
        cleanup_on_error: false,
        // **2.1.45（P2-7）**：回退恢复（`restore_history_parts`）也走本函数 ——
        // 必须保留目标原有权限位；目标不存在时 `preserve_mode` 的兜底是 0640。
        preserve_mode: true,
    };
    crate::io_atomic::atomic_write_bytes_opts(path, body, &opts)
}

/// **2.1.43-B（P2-6）**：提交 part 时**保留目标文件原有权限位**（不存在 ⇒ `0640`）。
///
/// # 缺陷（2.1.42）
///
/// `install.sh` 用 `install -m 0640` 安装 `/etc/ebpdns/config.json`；但每次
/// `PUT /api/config` 的提交路径是 `File::create(tmp)`（默认 `0644`，受 umask 影响）
/// → `fsync` → `rename`。**rename 保留 tmp 的权限** ⇒ 第一次保存配置就把
/// `0640` 放宽成 `0644`（配置里有上游地址/凭据，属真实安全回归）。
///
/// # 修法
///
/// 提交前把**目标文件现有**权限位复制到 tmp；目标不存在（例如新增 part / 首次提交）
/// ⇒ 用安装口径 `0640`（绝不是 `0644`）。非 unix 平台为空实现。
#[cfg(unix)]
fn preserve_or_default_part_mode(tmp: &Path, target: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(target)
        .map(|m| m.permissions().mode() & 0o7777)
        .unwrap_or(0o640);
    let _ = fs::set_permissions(tmp, fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn preserve_or_default_part_mode(_tmp: &Path, _target: &Path) {}

impl StateStore {
    /// 打开（或按需创建）`state/` 目录。**不写盘**。
    pub fn open(dir: impl Into<PathBuf>, history_keep: usize) -> std::io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(dir.join("history"))?;
        Ok(Self {
            dir,
            history_keep: history_keep.max(1),
            crash_hook: None,
            serving_rev: AtomicU64::new(0),
            prev_ok: AtomicU8::new(0),
        })
    }

    /// 同 [`StateStore::open`]，但装一个崩溃注入钩子（**仅验收用**）。
    pub fn open_with_crash_hook(
        dir: impl Into<PathBuf>,
        history_keep: usize,
        hook: fn(&'static str),
    ) -> std::io::Result<Self> {
        let mut s = Self::open(dir, history_keep)?;
        s.crash_hook = Some(hook);
        Ok(s)
    }

    fn hit(&self, stage: &'static str) {
        if let Some(h) = self.crash_hook {
            h(stage);
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn history_keep(&self) -> usize {
        self.history_keep
    }

    /// 读当前 `commit.json`（不校验 part）。
    pub fn read_commit(&self) -> Option<Commit> {
        self.read_commit_at(&self.dir)
    }

    fn read_commit_at(&self, dir: &Path) -> Option<Commit> {
        let raw = fs::read(dir.join("commit.json")).ok()?;
        serde_json::from_slice(&raw).ok()
    }

    /// 该 part 是否为**不可缺失**的必需文件（**2.1.46 / REV247 P2-5**）。
    ///
    /// `config.json` 是生效配置；`rules.json` 是 2.1.22 起的规则**唯一真源**。
    /// 其余 part（`rules_local.json` 镜像、订阅文件等）缺失只做告警 + `missing_parts` 上报，
    /// 因为 2.1.23 起交付收尾会正常删除镜像。
    fn is_required_part(path: &str) -> bool {
        matches!(
            Path::new(path).file_name().and_then(|s| s.to_str()),
            Some("config.json" | "rules.json")
        )
    }

    /// 逐 part 比对 sha256/长度。
    ///
    /// **`hist_rev = Some(rev)` 时必须读 `history/<rev>/parts/...` 里的副本，而不是
    /// live 路径** —— 否则"回退"会拿**当前（已损坏）**的文件去校验历史世代，永远失败
    /// （2.1.22 首版实测：`missing_part` / `cross_directory` 两个用例都被误判成 `Torn`）。
    ///
    /// **[2.1.23（DEF-222-11）修法]** `NotFound` **不再**算"损坏"，而是**从判据里剔除**
    /// 该 part（返回时给出清单）。
    ///
    /// 为什么：`NotFound` 与"内容被改坏"是**两类不同的事实**。
    /// * 内容损坏（长度/sha256 不符）⇒ 这一代真的不可信 ⇒ 必须回退；
    /// * **文件不存在** ⇒ 分两种情况：
    ///   ① **回退点本来就不含它**（例如 part 是 2.1.23 才加入提交计划的）⇒ 这一代
    ///   对"当前读方"依然完全可用，判"撕裂"并回退是**误报**；
    ///   ② 文件被外部删掉 ⇒ 回退是**对的**，但应当由调用方按"这一代缺了一个 part"
    ///   的事实决定（`verify` 会把清单交出去）。
    ///
    /// 审计实测的后果就是 ①：交付收尾**故意删除**了 `rules_local.json` 镜像，
    /// 而旧世代 `commit.json` 里仍记着它 ⇒ **每次启动**都刷
    /// `WARN 当前世代校验失败 ⇒ 已回退上一代`（内容其实一条没丢）。
    /// 把 `NotFound` 从"不可信"里剔除之后，只有**内容真的对不上**才会回退。
    ///
    /// 返回值：`Ok(missing)` = 校验通过（`missing` 是"记录里但盘上没有"的**可选**
    /// part 清单，供调用方记录/告警）；`Err(reason)` = 这一代**内容**不可信，或
    /// **必需** part 缺失。
    ///
    /// **2.1.46（REV247 P2-5 / C P1-05）**：`config.json` / `rules.json`（规则真源）
    /// 缺失是**必需 part 缺失** ⇒ 本世代不可信，走回退/ Torn；只有镜像类 part
    /// （`rules_local.json`、订阅文件等）缺失才继续 `Committed + missing_parts`。
    fn verify(&self, c: &Commit, hist_rev: Option<u64>) -> Result<Vec<String>, String> {
        let mut missing: Vec<String> = Vec::new();
        let mut missing_required: Vec<String> = Vec::new();
        for p in &c.parts {
            let path = match hist_rev {
                Some(rev) => self.hist_part_path(rev, &p.path),
                None => PathBuf::from(&p.path),
            };
            let body = match fs::read(&path) {
                Ok(b) => b,
                // 只有 `NotFound` 才走"剔除"；权限/IO 错误仍然是"这一代不可读"。
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    missing.push(p.path.clone());
                    if Self::is_required_part(&p.path) {
                        missing_required.push(p.path.clone());
                    }
                    continue;
                }
                Err(e) => return Err(format!("part `{}` 不可读: {e}", p.path)),
            };
            if body.len() as u64 != p.bytes {
                return Err(format!(
                    "part `{}` 长度不符（磁盘 {} / 记录 {}）",
                    p.path,
                    body.len(),
                    p.bytes
                ));
            }
            let got = sha256_hex(&body);
            if got != p.sha256 {
                return Err(format!(
                    "part `{}` sha256 不符（磁盘 {} / 记录 {}）",
                    p.path, got, p.sha256
                ));
            }
        }
        if !missing_required.is_empty() {
            return Err(format!(
                "必需 part 缺失: {}（config.json / rules.json 是安全与规则真源，\
                 缺失不得降级为 Committed；可选镜像见 missing_parts）",
                missing_required.join(", ")
            ));
        }
        Ok(missing)
    }

    /// 记录里存在、盘上**不存在**的 part（**2.1.23 / DEF-222-11**；端点可观测）。
    ///
    /// 不判"撕裂"（见 [`StateStore::verify`]），但**必须如实回报** ——
    /// 否则"回退到 2.1.21 仍可读"的镜像承诺会静默失效。
    pub fn missing_parts(&self) -> Vec<String> {
        // **2.1.46（REV247 P2-5）**：这里只回答"盘上不存在"，不做全量摘要校验
        // （状态端点每次轮询都调用它，必须 O(parts) 次 stat，而不是读全文件算 sha256）。
        // 必需 part 的存在性由 `load()` 的 `verify()` 另行 fail-closed。
        match self.read_commit() {
            Some(c) => c
                .parts
                .iter()
                .filter(|p| !Path::new(&p.path).exists())
                .map(|p| p.path.clone())
                .collect(),
            None => Vec::new(),
        }
    }

    /// 已提交的历史世代（升序）。
    pub fn history_generations(&self) -> Vec<u64> {
        let mut out = Vec::new();
        if let Ok(rd) = fs::read_dir(self.dir.join("history")) {
            for e in rd.flatten() {
                if e.path().is_dir() {
                    if let Some(n) = e.file_name().to_str().and_then(|s| s.parse::<u64>().ok()) {
                        out.push(n);
                    }
                }
            }
        }
        out.sort_unstable();
        out
    }

    /// **打开时读取并校验**（语义见 [`LoadState`]）。
    ///
    /// **[2.1.23（DEF-222-11）]** 盘上**缺失**的 part 不再判撕裂（见 [`StateStore::verify`]），
    /// 但会打一条 WARN 如实报告 —— 因此"故意删掉 `rules_local.json` 镜像"这类
    /// 正常维护动作不会让每次启动都刷"已回退到上一代"。
    // >>> 242B BEGIN P1-10-restore >>> //
    /// **2.1.42-B（P1-10）**：把 `history/<rev>/parts/...` **真正写回 live 路径**
    /// 并 fsync（不是只返回一个 `RolledBack` 状态）。
    ///
    /// 旧实现只把历史 `Commit` 放进返回值：读方（`config.json` / `state/rules.json`）
    /// 仍读 live 文件 ⇒ 实际服务的是"一部分新、一部分旧"的撕裂世代（P1-10）。
    pub fn restore_history_parts(&self, rev: u64, c: &Commit) -> std::io::Result<()> {
        for p in &c.parts {
            let src = self.hist_part_path(rev, &p.path);
            match fs::read(&src) {
                Ok(body) => {
                    // 原子写回 live；write 内部 fsync 文件并 rename + fsync 目录。
                    atomic_write(Path::new(&p.path), &body)?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // 历史副本缺这个 part ⇒ 保留 live 原样，交给下面的复验判定
                    // （复验发现缺失 ⇒ Torn，而不是"装作回退成功"）。
                }
                Err(e) => return Err(e),
            }
        }
        // **2.1.48 / AUD-06**：回退世代里**没有**的可选 part（`rules_sub.json` 等）也
        // 必须从 live 删除 —— 否则读方会把“回退前的较新订阅文件”与回退后的旧 config
        // 组合使用（混合世代）。`rules.json` 不在此列：旧历史世代可能没有它的副本，
        // 删掉会造成不可恢复的数据丢失（AUD-02 起新世代总会记录它）。
        for name in ["rules_sub.json", "rules_local.json"] {
            let live = self.dir.join(name);
            if c.parts.iter().any(|p| Path::new(&p.path) == live) {
                continue;
            }
            match fs::remove_file(&live) {
                Ok(()) => tracing::warn!(
                    path = %live.display(),
                    "回退清理：删除不在回退世代中的 live part（避免混合世代）"
                ),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    // <<< 242B END P1-10-restore <<< //
    pub fn load(&self) -> LoadState {
        let ls = self.load_inner();
        // **2.1.48 / serving_revision**：启动时把“实际服务的世代”写进原子字段
        // （`Committed` = 当前；`RolledBack` = 恢复的历史；`Legacy`/`Torn` = 无）。
        let serving = match &ls {
            LoadState::Committed(c) => c.revision,
            LoadState::RolledBack { restored, .. } => restored.revision,
            _ => 0,
        };
        self.serving_rev.store(serving, Ordering::Relaxed);
        ls
    }

    fn load_inner(&self) -> LoadState {
        let Some(cur) = self.read_commit() else {
            return LoadState::Legacy;
        };
        let why = match self.verify(&cur, None) {
            Ok(missing) => {
                if !missing.is_empty() {
                    tracing::warn!(
                        revision = cur.revision,
                        missing = ?missing,
                        "`commit.json` 记录的部分 part **在盘上不存在**：本次仍按**当前世代**使用\
                         （内容可校验的 part 全部一致；缺失通常是『计划变更后删掉了旧 part』，\
                         例如 2.1.23 起不再写 `rules_local.json` 镜像）。\
                         若这是误删，请从 history 目录恢复，或重跑一次 `migrate-config`。"
                    );
                }
                return LoadState::Committed(cur);
            }
            Err(e) => e,
        };
        tracing::warn!(
            revision = cur.revision,
            reason = %why,
            "state/ 当前世代校验失败（撕裂）⇒ 回退上一代"
        );
        let mut cands: Vec<u64> = self
            .history_generations()
            .into_iter()
            .filter(|r| *r < cur.revision)
            .collect();
        cands.sort_unstable_by(|a, b| b.cmp(a));
        // >>> 242B BEGIN P1-10-load >>> //
        for rev in cands {
            let hdir = self.dir.join("history").join(rev.to_string());
            if let Some(c) = self.read_commit_at(&hdir) {
                if self.verify(&c, Some(rev)).is_ok() {
                    // **2.1.42-B（P1-10）**：回退必须"落地"—— 先把历史 parts 写回
                    // live 路径，再**复验** live；任何缺失/不符 ⇒ Torn（fail-fast，
                    // 绝不带着混合世代继续服务）。
                    if let Err(e) = self.restore_history_parts(rev, &c) {
                        tracing::error!(broken = cur.revision, restored = rev, error = %e,
                            "回退失败：无法把 history parts 恢复到 live ⇒ TORN");
                        return LoadState::Torn {
                            reason: format!("回退恢复 history/{rev} 失败: {e}"),
                        };
                    }
                    match self.verify(&c, None) {
                        Ok(missing) if missing.is_empty() => {
                            let mut restored = c.clone();
                            restored.rolled_back_from = Some(cur.revision);
                            if let Err(e) = self.replace_commit(&restored) {
                                return LoadState::Torn {
                                    reason: format!("回退已恢复 parts 但提交点写回失败: {e}"),
                                };
                            }
                            tracing::warn!(
                                broken = cur.revision,
                                restored = rev,
                                "已回退到上一代（**live parts 已从 history 恢复并复验通过**）"
                            );
                            return LoadState::RolledBack {
                                broken: cur.revision,
                                restored,
                            };
                        }
                        Ok(missing) => {
                            return LoadState::Torn {
                                reason: format!(
                                    "回退后 live 仍缺失 part（拒绝服务混合世代）: {missing:?}"
                                ),
                            };
                        }
                        Err(e) => {
                            return LoadState::Torn {
                                reason: format!("回退恢复后 live 复验失败: {e}"),
                            };
                        }
                    }
                }
            }
        }
        LoadState::Torn { reason: why }
        // <<< 242B END P1-10-load <<< //
    }

    /// **2.1.48 / serving_revision**：把“当前提交点世代”标记为**正在服务**。
    ///
    /// 只在「提交成功 + 索引已就绪」处调用（config-only 提交在配置生效后调用）。
    /// 返回新 serving 值；无提交点 ⇒ `None`（不改）。
    pub fn mark_serving_current(&self) -> Option<u64> {
        let rev = self.current_revision()?;
        self.serving_rev.store(rev, Ordering::Relaxed);
        Some(rev)
    }

    /// 当前**实际服务**的世代（`None` = 未启用/无提交点/`Torn`）。
    pub fn serving_revision(&self) -> Option<u64> {
        match self.serving_rev.load(Ordering::Relaxed) {
            0 => None,
            v => Some(v),
        }
    }

    /// 当前 revision（无 `commit.json` ⇒ `None`）。
    pub fn current_revision(&self) -> Option<u64> {
        self.read_commit().map(|c| c.revision)
    }

    /// 分配新 revision：严格大于磁盘当前值。
    pub fn next_revision(&self, now_ms: u64) -> u64 {
        match self.current_revision() {
            Some(cur) if now_ms <= cur => cur + 1,
            _ => now_ms,
        }
    }

    /// 历史世代里某个 part 的**备份路径**（把绝对路径扁平化到 history 目录下）。
    fn hist_part_path(&self, rev: u64, part: &str) -> PathBuf {
        // `/etc/ebpdns/config.json` → `history/<rev>/parts/etc/ebpdns/config.json`
        // （去掉前导 `/`，保留目录结构 ⇒ 人可读、可 diff）
        let rel = part.trim_start_matches('/');
        self.dir
            .join("history")
            .join(rev.to_string())
            .join("parts")
            .join(rel)
    }

    /// **两阶段提交**：把 `parts`（`绝对路径 -> 内容`）作为一个世代原子提交。
    ///
    /// `writer` 写进 `commit.json`（审计）。返回新 [`Commit`]。
    ///
    /// **调用方必须**保证 `parts` 的路径是绝对路径（跨目录是本模块的常态，
    /// 见模块头"目录布局"）。相对路径会被解释为相对**进程 CWD**，用于测试。
    /// **2.1.48 / AUD-02**：权威规则真源 `state/rules.json` 必须进**每一次**提交的
    /// `parts`（存在则自动带上；不存在则交由 [`StateStore::verify`] 的独立必需检查拒绝）。
    ///
    /// 旧行为：config-only（前端值未变的“应用配置”、上游 CRUD、`/api/reprobe`、
    /// 订阅刷新）只把 `config.json` 放进 `commit.parts` ⇒ `rules.json` 被删/改坏后
    /// `verify()` 完全看不见，重启仍报 `Committed` 且本地规则为空（安全 fail-open）。
    fn auto_rules_part(
        &self,
        parts: &BTreeMap<PathBuf, Vec<u8>>,
    ) -> std::io::Result<Option<(PathBuf, Vec<u8>)>> {
        let rules = self.dir.join("rules.json");
        if parts.contains_key(&rules) {
            return Ok(None);
        }
        match fs::read(&rules) {
            Ok(b) => Ok(Some((rules, b))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn commit(
        &self,
        parts: &BTreeMap<PathBuf, Vec<u8>>,
        writer: &str,
        now_ms: u64,
        now_s: u64,
    ) -> std::io::Result<Commit> {
        let new_rev = self.next_revision(now_ms);
        let cur = self.read_commit();
        // **2.1.48 / AUD-02**：config-only/订阅提交也把权威 rules.json 纳入本世代。
        let extra_rules = self.auto_rules_part(parts)?;

        // ---- 第 1 步：快照旧世代进 history/<cur_rev>/（回退点）----
        if let Some(c) = &cur {
            for p in &c.parts {
                let dst = self.hist_part_path(c.revision, &p.path);
                if let Some(parent) = dst.parent() {
                    fs::create_dir_all(parent)?;
                }
                if Path::new(&p.path).is_file() {
                    fs::copy(&p.path, &dst)?;
                }
            }
            let hdir = self.dir.join("history").join(c.revision.to_string());
            atomic_write(&hdir.join("commit.json"), &serde_json::to_vec_pretty(c)?)?;
        }

        // ---- 第 2 步：写暂存区 + fsync(文件) + **fsync(该 part 的目录)** ----
        //
        // 暂存文件名含 `new_rev` ⇒ 两个写者（或同一写者的下次提交）不共用临时路径。
        // 跨目录/跨文件系统时，"先 fsync 各 part 目录"是**规范级要求**：否则
        // "文件内容已落盘"不代表"目录项已落盘"。这里对**每个 part 的父目录**都做一次。
        let mut staged: Vec<(PathBuf, PathBuf)> = Vec::new(); // (tmp, final)
        for (path, body) in parts.iter().chain(extra_rules.iter().map(|(p, b)| (p, b))) {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }
            let name = path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "part".into());
            let tmp = dir_of(path).join(format!("{name}.{new_rev}.tmp"));
            {
                let mut f = fs::File::create(&tmp)?;
                f.write_all(body)?;
                f.sync_all()?;
            }
            // **2.1.43-B（P2-6）**：把目标文件现有权限位带进 tmp（不存在 ⇒ 0640），
            // 否则 rename 后的 `config.json` 会被放宽成 File::create 的默认 0644。
            preserve_or_default_part_mode(&tmp, path);
            fsync_dir(dir_of(path)); // ← 每个 part 的目录都 fsync
            staged.push((tmp, path.clone()));
        }
        self.hit(STAGE_AFTER_STAGE_PARTS);

        // ---- 第 3 步：写 commit.json（**提交点**）----
        let mut metas: Vec<PartMeta> = parts
            .iter()
            .chain(extra_rules.iter().map(|(p, b)| (p, b)))
            .map(|(path, body)| PartMeta {
                path: path.to_string_lossy().to_string(),
                sha256: sha256_hex(body),
                bytes: body.len() as u64,
            })
            .collect();
        metas.sort_by(|a, b| a.path.cmp(&b.path));
        let commit = Commit {
            revision: new_rev,
            writer: writer.to_string(),
            committed_at: now_s,
            rolled_back_from: None,
            parts: metas,
        };
        atomic_write(
            &self.dir.join("commit.json"),
            &serde_json::to_vec_pretty(&commit)?,
        )?;
        self.hit(STAGE_AFTER_COMMIT_JSON);

        // ---- 第 4 步：发布 part（**同目录** rename + fsync 各目录）----
        for (tmp, target) in &staged {
            fs::rename(tmp, target)?;
            fsync_dir(dir_of(target));
        }
        fsync_dir(&self.dir);
        self.hit(STAGE_AFTER_RENAME_PARTS);

        // ---- 第 5 步：清理超出上限的历史世代（**无论如何都执行**）----
        //
        // **[2.1.23（DEF-222-09）]** 2.1.22 的第 3/4 步失败会 `return Err` ⇒ 直接跳过
        // 裁剪，于是 `history_keep=2` 却能在盘上留下 3 个世代目录（多出的正是第 1 步
        // 快照 + 第 3 步失败留下的）。现在把裁剪抽成 [`StateStore::prune_history`]
        // 并在**成功路径的末尾**调用；失败路径由**下一次**提交/启动补偿调用。
        self.prune_history();
        self.hit(STAGE_AFTER_PRUNE);
        // **AUD-10**：提交点变化 ⇒ 上一代可回退性缓存失效。
        self.prev_ok.store(0, Ordering::Relaxed);
        Ok(commit)
    }

    /// **裁剪历史世代 + 审计元信息**（**2.1.23：DEF-222-07 + DEF-222-09**）。
    ///
    /// 两件事一起做，因为它们有同一个上限（`history_keep`）：
    /// 1. 世代目录 `history/<rev>/`：超出上限的最老世代 ⇒ 删目录；
    /// 2. **审计元信息** `history/<rev>.meta.json`（2.1.22 引入，`write_meta`）：
    ///    2.1.22 **从不裁剪** ⇒ 生产实测 `history/` 里 86 个 `.meta.json` vs **4** 个
    ///    世代目录（时间跨度约 1 小时）⇒ **无界增长**。
    ///
    /// 判据（保守，宁可多留不可误删）：
    /// * 早于"保留世代里最老的那个"的 meta ⇒ 删（它的世代已经不存在了）；
    /// * **当前 `commit.json` 的 revision 的 meta 永不留**（它属于"正在服役"的世代，
    ///   meta 是旁路证据，不需要与 `commit.json` 争位置）；
    /// * 解析不出数字的 `.meta.json` ⇒ 按"**早于阈值**"处理（临时文件名形态），
    ///   阈值缺失时保守保留。
    ///
    /// 幂等：重复调用只删已经该删的；`history_keep >= 1` 由 [`StateStore::open`] 保证。
    /// 裁剪**保留集合**（**2.1.23：DEF-222-07**）。
    ///
    /// 规则（保守，宁可多留不可误删）：
    /// * **保留**：全部 `history/<rev>/` 世代目录对应的 meta；以及**当前** `commit.json`
    ///   的 revision 的 meta（那是"正在服役世代"的旁证，删了反而丢审计）；
    /// * **删除**：不在保留集合里的 meta（= 世代目录已经被裁掉的那些，以及
    ///   解析不出数字的临时文件名形态）。
    ///
    /// 反例说明为什么不能简单用"早于最老保留世代就删"：
    /// 留 2 代、当前代 = 6000 时的世代目录是 `[4000, 5000]`，而 `4000` 正是**回退点**，
    /// 它的 meta 必须留；`3000` 及更早才是可删的。同理 `6000.meta.json`（当前代）
    /// 不删 —— 读方按"meta ∩ 世代目录"求交即可，多一条当前代的 meta 不含歧义。
    pub fn prune_history(&self) -> usize {
        let mut removed = 0usize;
        let mut hist = self.history_generations();
        while hist.len() > self.history_keep {
            let oldest = hist.remove(0);
            let _ = fs::remove_dir_all(self.dir.join("history").join(oldest.to_string()));
            removed += 1;
        }
        // ---- 审计 meta：只留"保留世代 + 当前代" ----
        let mut keep: std::collections::BTreeSet<u64> = hist.iter().copied().collect();
        if let Some(cur) = self.current_revision() {
            keep.insert(cur);
        }
        let hdir = self.dir.join("history");
        let Ok(rd) = fs::read_dir(&hdir) else {
            return removed;
        };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let Some(rev_s) = name.strip_suffix(".meta.json") else {
                continue;
            };
            // 解析不出数字（临时文件形态 / 已被裁掉的世代）⇒ 删除。
            let doomed = match rev_s.parse::<u64>() {
                Ok(rev) => !keep.contains(&rev),
                Err(_) => true,
            };
            if doomed && fs::remove_file(e.path()).is_ok() {
                removed += 1;
            }
        }
        removed
    }

    /// 读某个 part 的当前内容。
    pub fn read_part(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        fs::read(path)
    }

    /// **崩溃后的可用世代**（"撕裂态 = 0"的**正向**判据）。
    ///
    /// 只要**存在至少一个**校验通过的世代就返回 `Some((revision, 来源))`；
    /// 全部不可用才返回 `None`（= 撕裂）。
    pub fn available_generation(&self) -> Option<(u64, String)> {
        if let Some(c) = self.read_commit() {
            if self.verify(&c, None).is_ok() {
                return Some((c.revision, "current".into()));
            }
        }
        for rev in self.history_generations().into_iter().rev() {
            let hdir = self.dir.join("history").join(rev.to_string());
            if let Some(c) = self.read_commit_at(&hdir) {
                if self.verify(&c, Some(rev)).is_ok() {
                    return Some((rev, format!("history:{rev}")));
                }
            }
        }
        None
    }

    /// 残留的暂存文件（`*.tmp`）。读方**完全不读**它们；崩溃后可能残留（预期行为）。
    ///
    /// **[2.1.23（DEF-222-08）]** 扫描范围 = **`state/` + 提交点记录的全部 part 目录**。
    /// 2.1.22 只扫 `state/`，而暂存文件写在**每个 part 自己的目录**里
    /// （`/etc/ebpdns/config.json.<rev>.tmp`）⇒ ENOSPC 复现后 `/etc` 侧的
    /// `config.json.1792185599074.tmp` **永远没人清**（启动清理只报 `removed=2`，
    /// 两个都在 `state/`）。
    pub fn leftover_tmp(&self) -> Vec<String> {
        let mut roots: Vec<PathBuf> = vec![self.dir.clone()];
        // 提交点里的 part 目录（可能在 /etc 等别处）；再加 rules.json 所在目录
        //（真源与 commit.json 同目录，但显式列出更稳）。
        if let Some(c) = self.read_commit() {
            for p in &c.parts {
                let d = dir_of(Path::new(&p.path)).to_path_buf();
                if !roots.contains(&d) {
                    roots.push(d);
                }
            }
        }
        let mut out: Vec<String> = Vec::new();
        let mut seen: std::collections::BTreeSet<PathBuf> = std::collections::BTreeSet::new();
        for root in roots {
            let mut stack = vec![root.clone()];
            while let Some(d) = stack.pop() {
                let Ok(rd) = fs::read_dir(&d) else { continue };
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        stack.push(p);
                    } else if let Some(n) = p.file_name().and_then(|s| s.to_str()) {
                        if n.ends_with(".tmp") && seen.insert(p.clone()) {
                            // 报告用"绝对路径"（跨目录时相对 `state/` 没有意义）。
                            out.push(p.to_string_lossy().to_string());
                        }
                    }
                }
            }
        }
        out.sort();
        out
    }

    /// 清理**上一个进程崩溃留下的**残留暂存文件，覆盖 `state/` **与全部 part 目录**
    /// （**2.1.23 / DEF-222-08**）。只删 `*.tmp`（读方从不引用它们，因此删除任意
    /// `*.tmp` 都安全）；幂等。生产路径在 `open()` 之后调用一次。
    pub fn cleanup_stale_tmp(&self) -> usize {
        let mut n = 0;
        for abs in self.leftover_tmp() {
            if fs::remove_file(&abs).is_ok() {
                n += 1;
            }
        }
        n
    }

    /// 把任意 JSON 值序列化为 part 字节（**末尾一个换行**：`git diff` / `md5sum` 友好）。
    pub fn json_bytes(v: &serde_json::Value) -> Vec<u8> {
        let mut b = serde_json::to_vec_pretty(v).unwrap_or_default();
        b.push(b'\n');
        b
    }

    /// 当前世代的 `commit.json` 快照（`None` = 无提交点）。
    pub fn snapshot(&self) -> Option<Commit> {
        self.read_commit()
    }

    /// 把某个**已存在的历史世代**（或当前世代）的 `commit.json` **原子替换**为
    /// [`crate::state_store::rollback_generation`] 写的回退记录。
    ///
    /// 只替换提交点、**不动任何 part 字节**：回退的语义是"读方改看上一代"，
    /// 而上一代的 part 副本在 `history/<rev>/parts/...` 里已被
    /// [`StateStore::commit`] 第 1 步完整快照过 ⇒ 不需要重写 live part。
    /// （这与"回退当前世代"的动作等价，但**不需要**写权限之外的任何东西。）
    /// **2.1.48 / AUD-10**：显式失效 `prev_generation_ok` 缓存。
    ///
    /// 生产路径只在 commit/replace_commit 时失效；测试会**带外**修改历史 part
    /// （模拟磁盘损坏），需要显式调用本方法后才能观察到新判据。
    #[doc(hidden)]
    pub fn invalidate_prev_ok(&self) {
        self.prev_ok.store(0, Ordering::Relaxed);
    }

    pub fn replace_commit(&self, c: &Commit) -> std::io::Result<()> {
        let out = atomic_write(
            &self.dir.join("commit.json"),
            &serde_json::to_vec_pretty(c).map_err(std::io::Error::other)?,
        );
        // **AUD-10**：提交点被替换 ⇒ 缓存失效。
        self.prev_ok.store(0, Ordering::Relaxed);
        out
    }

    /// **上一个世代是否完好可回退**（`/api/status.state_persist.prev_generation_ok`）。
    ///
    /// 判据（确定性，不看时间）：
    /// * 没有历史世代 ⇒ `false`（**没有回退点**，如实报告，不假装安全）；
    /// * 有历史世代 ⇒ 最新的那个必须 `verify(.., Some(rev))` 通过。
    ///
    /// 注意 `history/<rev>/` 里可能有**上一次提交留下的**快照（commit 第 1 步写入，
    /// 第 5 步只裁剪超限的最老世代）—— 那是**可用的**回退点，判为 `true` 是对的。
    ///
    /// **2.1.26（B3：去掉冗余的 `commit.json` 解析）** —— 判据完全不变，只改**读法**：
    /// 2.1.25 把 `self.read_commit()` 写在 `filter` 闭包里 ⇒ **每一个历史世代**都要
    /// 重新读盘 + `serde_json` 解析一遍**当前** `commit.json`；`history_keep=2` 时每次
    /// `/api/status` 多解析**两遍**同一个文件，选中的那个世代随后还要**再读一次**。
    /// 现在：当前世代 1 次、历史世代各 1 次，选中的世代**直接用已读到的那份**。
    /// 返回值与 2.1.25 **逐位相同**（`prev_generation_ok_is_unchanged_by_hoisting` 单测
    /// 把三条分支 —— 无历史 / 有历史 / 当前提交点缺失 —— 与旧实现逐条对齐）。
    pub fn prev_generation_ok(&self) -> bool {
        // **2.1.48 / AUD-10**：命中缓存直接返回（status 端点每 2 s 调用一次）。
        match self.prev_ok.load(Ordering::Relaxed) {
            1 => return false,
            2 => return true,
            _ => {}
        }
        let v = self.prev_generation_ok_uncached();
        self.prev_ok.store(if v { 2 } else { 1 }, Ordering::Relaxed);
        v
    }

    fn prev_generation_ok_uncached(&self) -> bool {
        let gens = self.history_generations();
        if gens.is_empty() {
            return false;
        }
        // 当前提交点的**一次**快照（读不到 ⇒ 所有世代都可回退，与旧实现的
        // `read_commit().map(..).unwrap_or(true)` 同义）。
        let cur_rev = self.read_commit().map(|c| c.revision);
        let mut best: Option<(u64, Commit)> = None;
        for r in gens {
            let hdir = self.dir.join("history").join(r.to_string());
            let Some(c) = self.read_commit_at(&hdir) else {
                continue;
            };
            let eligible = match cur_rev {
                Some(cr) => r < cr,
                None => true,
            };
            if !eligible {
                continue;
            }
            if best.as_ref().is_none_or(|(b, _)| r > *b) {
                best = Some((r, c));
            }
        }
        match best {
            Some((rev, c)) => self.verify(&c, Some(rev)).is_ok(),
            None => false,
        }
    }
}

/* ===================================================================== */
/* 2.1.22 阶段一：统一持久化事务（所有写者的唯一入口）                    */
/* ===================================================================== */

/// **进程内唯一串行化点**（`state/` 统一事务）。
///
/// 与 [`crate::rules_admin::rules_txn`] 是**同一把锁**（后者返回本函数的结果）：
/// 2.1.21 的 `rules_txn` 已经是"规则面 + 订阅面共用的读改写锁"
/// （`subscribe::sub_txn()` 直接返回它），本函数把它**提升为统一持久化锁**
/// —— 现在 `PUT /api/config`（`api.rs`）也取它，于是三个面在**同一临界区**里
/// 完成「读旧 + 算新 + 提交」。
///
/// **为什么必须是异步锁**：提交路径要 `spawn_blocking` 落盘（`subscribe` 侧
/// 已经在锁内 `await`），`parking_lot::Mutex` 不能跨 `await` 持有。
///
/// **锁序**（见 `rules_admin.rs` 文件头）：先取本锁 → 再取 `state.cfg`
/// （短临界区，不跨 `await`）→ 持锁期间不得再调用任何会取本锁的入口。
pub fn state_txn() -> &'static tokio::sync::Mutex<()> {
    static TXN: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    TXN.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// 统一事务的失败原因。
///
/// **[可观测性要求]**「**失败必须升 ERROR**，不得静默」——因此每个写者都必须把本
/// 枚举的两个变体分别映射为日志级别：
/// * [`CommitError::Conflict`] ⇒ **WARN**（客户端并发，不是故障；HTTP 层回 409，
///   带当前 `revision` 供客户端重读重试）；
/// * [`CommitError::Io`] ⇒ **ERROR**（含 `ENOSPC` / 权限 / 只读文件系统等
///   **提交中止**场景；上一代完好可回退，`Torn` 仍为 0）。
#[derive(Clone, Debug)]
pub enum CommitError {
    /// 期望世代与磁盘世代不符（丢失更新防护，HTTP 409）。
    Conflict {
        /// 客户端声明的期望世代。
        expected: u64,
        /// 磁盘当前世代（客户端应据此重读）。
        current: u64,
    },
    /// 提交中止（IO / 序列化失败）。`msg` 只进日志，不进 HTTP 响应体。
    Io {
        /// 人类可读原因（含写入器与路径）。
        msg: String,
    },
}

impl std::fmt::Display for CommitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommitError::Conflict { expected, current } => write!(
                f,
                "世代冲突：期望 revision={expected}，磁盘当前 revision={current}"
            ),
            CommitError::Io { msg } => write!(f, "{msg}"),
        }
    }
}

/// 提交失败计数（`/api/status.state_persist.failed_commits`）。
static FAILED_COMMITS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 累计的**提交中止**次数（进程内；不持久化 —— 它是运行态指标，不是状态）。
pub fn failed_commits() -> u64 {
    FAILED_COMMITS.load(std::sync::atomic::Ordering::Relaxed)
}

/// `/api/status.state_persist` 的数据源。
///
/// **只做读盘 + 一次 `stat`**（不校验全部 part 的摘要 —— 那是 `load()` 的活，
/// 不在状态端点的热路径上）。`parts[].sha256` 来自 `commit.json`（**记录值**），
/// `bytes`/`mtime_s` 来自**现场 `stat`** ⇒ 两者不一致时状态端点就能看出来。
///
/// **[2.1.23（DEF-222-04，P1）]** 新增 `load_state` / `serving_revision` /
/// `broken_revision` / `torn` / `torn_reason`：2.1.22 把启动四态的结论**只写进日志**，
/// 于是 `RolledBack`/`Torn` 时端点照报"被拒绝的世代"与 `note="统一事务已启用"`
/// ⇒ **端点无法区分健康 / 已回退 / Torn**（而 `parts[]` 正是文档承诺的判据）。
/// 现在结论由调用方（`main()`）在启动时算好并传入。
pub fn persist_info(
    dir: &Path,
    store: Option<&StateStore>,
    enabled: bool,
    note: &str,
    load_state: Option<&crate::state::LoadStateInfo>,
) -> serde_json::Value {
    let dir_s = dir.to_string_lossy().to_string();
    let ls_kind = load_state.map(|l| l.kind).unwrap_or("Unknown");
    let torn = load_state.map(|l| l.is_torn()).unwrap_or(false);
    let serving = load_state.and_then(|l| l.serving_revision);
    let broken = load_state.and_then(|l| l.broken_revision);
    let torn_reason = load_state.and_then(|l| l.torn_reason.clone());
    // **2.1.48 / serving_revision**：优先用 store 的**实时**值（提交后推进）；
    // 启动快照只作为 store 尚未 load/未启用时的兜底。
    let live_serving = store.and_then(|st| st.serving_revision()).or(serving);
    let Some(store) = store else {
        return serde_json::json!({
            "enabled": enabled,
            "state_dir": dir_s,
            "revision": serde_json::Value::Null,
            // **2.1.41（字段体检修复）**：契约是 18 键（INTERFACE §3.4，2.1.46 起）；
            // 未启用统一事务（store=None）时 2.1.40 及以前**漏发 `writer`** ⇒ 实际 16 键。
            // 空态显式下发 null/[]，键集恒 18（脚本/前端按固定键集解析不再判"字段缺失"）。
            "writer": serde_json::Value::Null,
            "parts": [],
            // **2.1.46（REV247 P2-5）**：键集恒 18（空态下发 []，不省略）。
            "missing_parts": [],
            "prev_generation_ok": false,
            "history_generations": [],
            "failed_commits": failed_commits(),
            "load_state": ls_kind,
            "serving_revision": live_serving,
            "broken_revision": broken,
            "torn": torn,
            "torn_reason": torn_reason,
            "note": note,
        });
    };
    let cur = store.snapshot();
    // **2.1.46（REV247 P2-5）**：把"记录里有、盘上没有"的 part 纳入状态端点。
    // 这里复用下面已经要做的 `stat`，不额外读文件/算摘要（状态端点 1 s 轮询）。
    let mut missing_parts: Vec<String> = Vec::new();
    let parts: Vec<serde_json::Value> = match &cur {
        Some(c) => c
            .parts
            .iter()
            .map(|p| {
                let md = fs::metadata(&p.path).ok();
                if md.is_none() {
                    missing_parts.push(p.path.clone());
                }
                serde_json::json!({
                    "path": p.path,
                    "sha256": p.sha256,
                    "bytes": md.as_ref().map(|m| m.len()).unwrap_or(0),
                    "mtime_s": md
                        .and_then(|m| m.modified().ok())
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                })
            })
            .collect(),
        None => Vec::new(),
    };
    serde_json::json!({
        "enabled": enabled,
        "state_dir": dir_s,
        // `revision` 仍是**原始提交点**的世代（保留 2.1.22 的字段语义），
        // 而读方"**实际服务**的世代"在 `serving_revision`（回退后两者不同）。
        "revision": cur.as_ref().map(|c| c.revision),
        "writer": cur.as_ref().map(|c| c.writer.clone()),
        "parts": parts,
        "missing_parts": missing_parts,
        "prev_generation_ok": store.prev_generation_ok(),
        "history_generations": store.history_generations(),
        "failed_commits": failed_commits(),
        "load_state": ls_kind,
        "serving_revision": live_serving,
        "broken_revision": broken,
        "torn": torn,
        "torn_reason": torn_reason,
        "note": note,
    })
}

/// **提交中止时可安全丢弃的在途变更**（供 IO 失败 ⇒ 回滚内存用）。
///
/// 调用方在取到 [`state_txn`] 之后、调用 [`commit_droppable`] 之前先产出一份它
/// （`pending()`），提交返回 [`CommitError::Io`] 时用 `restore()` 把内存态复位。
/// 取在**锁内**产出，因此不会被并发写者污染。
pub struct ChangeLedger {
    undo: Vec<Box<dyn FnOnce() + Send>>,
}

impl ChangeLedger {
    /// 空账本。
    pub fn new() -> Self {
        Self { undo: Vec::new() }
    }

    /// 追加一个撤销动作（**逆序执行**，先记的先撤销 = 依赖顺序安全）。
    pub fn push<F: FnOnce() + Send + 'static>(&mut self, f: F) {
        self.undo.push(Box::new(f));
    }

    /// 是否有在途变更。
    pub fn is_empty(&self) -> bool {
        self.undo.is_empty()
    }

    /// 执行全部撤销（逆序）。
    pub fn restore(self) {
        for f in self.undo.into_iter().rev() {
            f();
        }
    }
}

impl Default for ChangeLedger {
    fn default() -> Self {
        Self::new()
    }
}

/// **统一提交**：把 `plan` 里的全部 part 作为**一个世代**原子提交。
///
/// 返回新 `revision`。失败时：
/// * [`CommitError::Conflict`] ⇒ **没有写盘**（客户端可重读重试）；
/// * [`CommitError::Io`] ⇒ **提交中止**，`failed_commits` +1，**上一代完好**
///   （`*.tmp` 可能残留，但读方从不读它们，且下次启动 `cleanup_stale_tmp()` 清理）。
///
/// **调用方必须持有 [`state_txn`]**（这是纪律，不是本函数的运行时校验）。
/// `plan` 为空 ⇒ 只记审计直接返回当前世代（不产生新提交）。
pub fn commit_droppable(
    store: &StateStore,
    writer: &str,
    plan: &BTreeMap<PathBuf, Vec<u8>>,
) -> Result<Option<Commit>, CommitError> {
    if plan.is_empty() {
        return Ok(None);
    }
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let now_s = now_ms / 1000;
    let c = store.commit(plan, writer, now_ms, now_s).map_err(|e| {
        FAILED_COMMITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        CommitError::Io {
            msg: format!(
                "**持久化提交中止**（writer={writer}，state={}，{} 个 part）：{e} \
                 —— 本次世代**未提交**，上一代仍然完好（读方看到的仍是上一代）",
                store.dir().display(),
                plan.len()
            ),
        }
    })?;
    // 审计元信息（**提交成功之后**写；它是旁路证据，不是提交点的一部分）。
    if let Err(e) = write_meta(store, &c) {
        tracing::warn!(
            revision = c.revision,
            error = %e,
            "提交成功但审计元信息 history/<rev>.meta.json 写失败（不影响一致性，只影响审计）"
        );
    }
    Ok(Some(c))
}

/// `history/<rev>.meta.json` 的**线上形状**（借用式 `Serialize`，**2.1.25 性能项**）。
///
/// # 为什么不用 `serde_json::json!({...})`
///
/// 2.1.22–2.1.24 的实现是"先造 `Value` 树、再 `to_vec_pretty`"：每个 part 会
/// ①新建一个 `Value::Object`（`Map` 扩容）、②`"path"`/`"sha256"` **各克隆一次
/// `String`**、③再被序列化一遍。审计元信息是**每次提交**都要写的文件，part 数
/// 随 `state_dir` 的 part 增长（config + rules + 各订阅）⇒ 纯属可省的分配。
///
/// 现在：直接借用 `Commit` 里的字段序列化，**不建 `Value` 树、不克隆任何 `String`**。
///
/// # 为什么字段顺序是"字母序"而不是逻辑序
///
/// `serde_json` 的 `Map` 在本工作区**没有**开 `preserve_order`（是 `BTreeMap`）⇒
/// 旧实现的 `json!` 输出键序是**按字母排序**的。派生结构体按**声明顺序**输出，
/// 因此这里刻意按字母序声明（`committed_at` / `parts` / `revision` / `writer`，
/// part 内 `bytes` / `path` / `sha256`）⇒ 新实现写出的字节与旧实现**逐位相同**。
/// 该等价性由 `commit_meta_body_is_byte_identical_to_legacy_json_macro` 单测钉死
/// （若哪天有人给 `serde_json` 打开 `preserve_order`，那条单测会立刻变红）。
#[derive(Serialize)]
struct CommitMetaRef<'a> {
    committed_at: u64,
    parts: Vec<CommitPartRef<'a>>,
    revision: u64,
    writer: &'a str,
}

/// 单个 part 的借用视图（字段顺序见 [`CommitMetaRef`] 的说明）。
#[derive(Serialize)]
struct CommitPartRef<'a> {
    bytes: u64,
    path: &'a str,
    sha256: &'a str,
}

/// `history/<rev>.meta.json` 的**唯一**序列化实现（`write_meta` 与单测共用）。
fn commit_meta_body(c: &Commit) -> std::io::Result<Vec<u8>> {
    let meta = CommitMetaRef {
        committed_at: c.committed_at,
        parts: c
            .parts
            .iter()
            .map(|p| CommitPartRef {
                bytes: p.bytes,
                path: &p.path,
                sha256: &p.sha256,
            })
            .collect(),
        revision: c.revision,
        writer: &c.writer,
    };
    serde_json::to_vec_pretty(&meta).map_err(std::io::Error::other)
}

/// 写 `history/<rev>.meta.json`（写者身份 + 时间 + part 摘要）。
///
/// 位置：`state/history/`（与世代目录同级），而不是 `state/` 根 —— 「新块/新文件
/// 不得占据 `commit.json` 的位置」。
fn write_meta(store: &StateStore, c: &Commit) -> std::io::Result<()> {
    let dir = store.dir().join("history");
    fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.meta.json", c.revision));
    atomic_write(&path, &commit_meta_body(c)?)
}

/// **回退**：把当前世代替换为历史世代 `rev`（其 `commit.json` + part 副本都已在
/// `history/<rev>/` 里）。返回被替换掉（被判定为损坏/回退）的旧世代号。
///
/// 只改提交点，不动 part 字节：读方据此改看 `history/<rev>/`。
pub fn rollback_generation(store: &StateStore, rev: u64) -> std::io::Result<u64> {
    let broken = store.current_revision().unwrap_or(0);
    let hdir = store.dir().join("history").join(rev.to_string());
    let mut c = store
        .read_commit_at(&hdir)
        .ok_or_else(|| std::io::Error::other(format!("历史世代 {rev} 无 commit.json")))?;
    c.rolled_back_from = Some(broken);
    store.replace_commit(&c)?;
    Ok(broken)
}

/// `*.tmp` 一律忽略 + 崩溃残留清理（`state/` **与各 part 目录**）+ 历史/审计补偿裁剪。
///
/// 生产启动序列：`open(state_dir, 2)` → **本函数** → `load()`。
///
/// **[2.1.23（DEF-222-08 / DEF-222-09 / DEF-222-07）]** 本函数现在做**两件**收尾：
/// ① 清残留 `*.tmp`（覆盖全部 part 目录）；
/// ② `prune_history()`：补偿上一次提交**中途失败**时没跑的裁剪（世代目录 + `.meta.json`）。
/// 返回**清掉的 `*.tmp` 数量**（调用方据此打 INFO）。
pub fn startup_cleanup(store: &StateStore) -> usize {
    let n = store.cleanup_stale_tmp();
    let pruned = store.prune_history();
    if pruned > 0 {
        tracing::info!(
            pruned,
            state_dir = %store.dir().display(),
            "启动补偿裁剪：历史世代 / 审计 `.meta.json` 超过上限（上一次提交可能中途失败）"
        );
    }
    n
}

/// **迁移/离线写回后"重新锚定提交点"**（**2.1.23 / DEF-222-05**）。
///
/// # 为什么需要它
///
/// `config.json` 是提交点记录的一个 **part**，而运维习惯是**直接编辑真源文件**
/// （`ebpdns migrate-config` / `--export-legacy` / 手工编辑器都属这一类）。
/// 2.1.22 的离线路径绕过 store 直接原子替换该文件 ⇒ 下一次启动 `load()` 校验失败
/// ⇒ `WARN 撕裂` / 无历史世代时甚至 **TORN**（审计实测）。这是**必然踩到**的路径。
///
/// 本函数把"外部改写"变成**受支持的操作**：把当前 `commit.json` 的 part 摘要
/// **按磁盘现状重算**并原子写回（revision 不变、`writer` 追加 `+reanchor`）。
/// 语义上等价于"承认这次外部修改，把它纳入当前世代"。
///
/// 边界：
/// * 无 `commit.json`（Legacy）⇒ 无事可做，返回 `Ok(false)`；
/// * part 文件**缺失** ⇒ 跳过该 part（不伪造摘要），返回 `Ok(true)` 但记 WARN；
/// * 任何 IO 失败 ⇒ `Err`，调用方应报错（**不要**静默）。
pub fn reanchor_commit_after_external_write(
    store: &StateStore,
    writer_suffix: &str,
) -> std::io::Result<bool> {
    let Some(mut c) = store.read_commit() else {
        return Ok(false);
    };
    let mut changed = 0usize;
    let mut missing: Vec<String> = Vec::new();
    let mut metas: Vec<PartMeta> = Vec::with_capacity(c.parts.len());
    for p in &c.parts {
        match fs::read(&p.path) {
            Ok(b) => {
                let sha = sha256_hex(&b);
                let bytes = b.len() as u64;
                if sha != p.sha256 || bytes != p.bytes {
                    changed += 1;
                }
                metas.push(PartMeta {
                    path: p.path.clone(),
                    sha256: sha,
                    bytes,
                });
            }
            Err(e) => {
                missing.push(format!("{}（{e}）", p.path));
                metas.push(p.clone());
            }
        }
    }
    if !missing.is_empty() {
        tracing::warn!(
            missing = ?missing,
            "重新锚定提交点时发现 part **缺失**：这些 part 的摘要保持原记录（不伪造）；\
             请确认文件是否被误删"
        );
    }
    if changed == 0 && missing.is_empty() {
        return Ok(false); // 磁盘与提交点已一致 ⇒ 无需重锚。
    }
    metas.sort_by(|a, b| a.path.cmp(&b.path));
    c.parts = metas;
    c.writer = format!("{}+{writer_suffix}", c.writer);
    store.replace_commit(&c)?;
    tracing::info!(
        revision = c.revision,
        changed,
        writer = %c.writer,
        "**已把外部改写重新锚定到当前提交点**（part 摘要按磁盘现状重算；revision 不变）\
         ⇒ 下一次启动不会再把它判成撕裂"
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "ebpdns-state-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&d);
        d
    }

    /// **2.1.48 / serving_revision**：提交成功**不等于**已服务 —— 只有显式
    /// `mark_serving_current()`（各写者在“索引已就绪”处调用）才推进；`load()` 按
    /// Committed/RolledBack 初始化，Torn/Legacy 为 None。
    #[test]
    fn m248_serving_revision_tracks_apply_not_commit() {
        let d = tmpdir("serving");
        fs::create_dir_all(&d).unwrap();
        let st = StateStore::open(&d, 3).unwrap();
        let p1 = parts(
            &d,
            &[
                ("config.json", json!({"a": 1})),
                ("rules.json", json!({"rules": []})),
            ],
        );
        let c1 = st.commit(&p1, "test", 1_000, 1).unwrap();
        assert!(matches!(st.load(), LoadState::Committed(_)));
        assert_eq!(
            st.serving_revision(),
            Some(c1.revision),
            "启动后 serving = 当前世代"
        );
        // 新提交但尚未 mark（模拟“已提交、索引还没重建好”）⇒ serving 不得前进。
        let c2 = st.commit(&p1, "test", 2_000, 2).unwrap();
        assert_eq!(
            st.serving_revision(),
            Some(c1.revision),
            "mark_serving_current 之前不得自称已服务新世代"
        );
        assert_eq!(st.mark_serving_current(), Some(c2.revision));
        assert_eq!(st.serving_revision(), Some(c2.revision));
        // 状态端点读的是**实时**值，不是启动快照。
        let info = persist_info(&d, Some(&st), true, "note", None);
        assert_eq!(info["serving_revision"], json!(c2.revision));
        assert_eq!(info["revision"], json!(c2.revision));
        let _ = fs::remove_dir_all(&d);
    }

    /// **2.1.48 / AUD-02**：config-only 提交必须自动把 `state/rules.json` 纳入 parts；
    /// 真源被删后 `load()` 不得再报 `Committed`（旧实现完全看不见）。
    #[test]
    fn m248_aud02_config_only_commit_keeps_rules_required() {
        let d = tmpdir("aud02");
        fs::create_dir_all(&d).unwrap();
        let st = StateStore::open(&d, 2).unwrap();
        let p1 = parts(
            &d,
            &[
                ("config.json", json!({"a": 1})),
                ("rules.json", json!({"rules": []})),
            ],
        );
        let c1 = st.commit(&p1, "test", 1_000, 1).unwrap();
        assert!(c1.parts.iter().any(|p| p.path.ends_with("/rules.json")));
        // config-only：plan 里故意不带 rules.json
        let p2 = parts(&d, &[("config.json", json!({"a": 2}))]);
        let c2 = st.commit(&p2, "test", 2_000, 2).unwrap();
        assert!(
            c2.parts.iter().any(|p| p.path.ends_with("/rules.json")),
            "config-only 提交必须自动带上 rules.json：{:?}",
            c2.parts.iter().map(|p| &p.path).collect::<Vec<_>>()
        );
        // 真源被删：verify 必须失败，load 不得报 Committed。
        fs::remove_file(d.join("rules.json")).unwrap();
        assert!(
            st.verify(&c2, None).is_err(),
            "rules.json 被删后 verify 必须失败"
        );
        assert!(
            !matches!(st.load(), LoadState::Committed(_)),
            "rules.json 被删后 load 不得报 Committed"
        );
        let _ = fs::remove_dir_all(&d);
    }

    /// **2.1.48 / AUD-06**：回退到“只有 config+rules”的世代时，必须删除 live 上
    /// 较新的 `rules_sub.json`（否则旧 config + 新订阅 = 混合世代）。
    #[test]
    fn m248_aud06_rollback_removes_newer_live_subscription_file() {
        let d = tmpdir("aud06");
        fs::create_dir_all(&d).unwrap();
        let st = StateStore::open(&d, 3).unwrap();
        let p1 = parts(
            &d,
            &[
                ("config.json", json!({"a": 1})),
                ("rules.json", json!({"rules": []})),
            ],
        );
        st.commit(&p1, "test", 1_000, 1).unwrap();
        let mut p2 = parts(
            &d,
            &[
                ("config.json", json!({"a": 2})),
                ("rules.json", json!({"rules": []})),
            ],
        );
        p2.insert(
            d.join("rules_sub.json"),
            StateStore::json_bytes(&json!({"subscriptions": []})),
        );
        st.commit(&p2, "test", 2_000, 2).unwrap();
        assert!(d.join("rules_sub.json").is_file());
        // 改坏当前世代 config ⇒ 回退到 rev1（rev1 没有 rules_sub.json）
        fs::write(d.join("config.json"), b"{}").unwrap();
        assert!(matches!(st.load(), LoadState::RolledBack { .. }));
        assert!(
            !d.join("rules_sub.json").exists(),
            "回退后必须清理不在回退世代的 live rules_sub.json"
        );
        let _ = fs::remove_dir_all(&d);
    }

    /// **2.1.48 / AUD-10**：`prev_generation_ok` 缓存必须在提交后失效（结果与实时计算一致）。
    #[test]
    fn m248_aud10_prev_generation_cache_invalidated_on_commit() {
        let d = tmpdir("aud10");
        fs::create_dir_all(&d).unwrap();
        let st = StateStore::open(&d, 3).unwrap();
        assert!(!st.prev_generation_ok(), "无历史世代 ⇒ false");
        let p1 = parts(
            &d,
            &[
                ("config.json", json!({"a": 1})),
                ("rules.json", json!({"rules": []})),
            ],
        );
        st.commit(&p1, "test", 1_000, 1).unwrap();
        assert!(!st.prev_generation_ok(), "仍无历史世代 ⇒ false");
        st.commit(&p1, "test", 2_000, 2).unwrap();
        assert!(
            st.prev_generation_ok(),
            "有完好历史世代 ⇒ true（缓存必须已失效）"
        );
        let _ = fs::remove_dir_all(&d);
    }

    /// **2.1.41 / 2.1.46**：`/api/status.state_persist` 的键集必须恒为 18
    /// （INTERFACE §3.4）。`persist_info` 负责其中 15 键（空态补 `writer:null`、
    /// `missing_parts:[]`），`state_persist_json` 再追加
    /// `lock_held`/`lock_note`/`rule_source_unreadable` 三键 ⇒ 15 + 3 = 18。
    /// 2.1.40 空态漏 `writer` ⇒ 16；2.1.45 及以前无 `missing_parts` ⇒ 17。
    #[test]
    fn persist_info_disabled_state_keeps_writer_null() {
        let v = persist_info(
            Path::new("/tmp/ebpdns-state-none"),
            None,
            true,
            "note",
            None,
        );
        let o = v.as_object().expect("state_persist 必须是对象");
        assert_eq!(o.len(), 15, "persist_info 空态必须 15 键：{o:?}");
        assert!(o.contains_key("writer"), "缺 writer 键：{o:?}");
        assert_eq!(o["writer"], json!(null));
        assert_eq!(o["missing_parts"], json!([]));
    }

    /// 单一目录布局（全部 part 与 commit.json 同目录）。
    fn parts(dir: &Path, pairs: &[(&str, serde_json::Value)]) -> BTreeMap<PathBuf, Vec<u8>> {
        pairs
            .iter()
            .map(|(k, v)| (dir.join(k), StateStore::json_bytes(v)))
            .collect()
    }

    /// **2.1.25（B9）同进程微基准**：`history/<rev>.meta.json` 的两种写法 ——
    /// 旧：`json!` 造 `Value` 树（每 part 克隆 2 个 `String`）再序列化；
    /// 新：借用式 `Serialize` 结构直接序列化（**零 `String` 克隆**）。
    ///
    /// 显式运行：`cargo test --release -p ebpdns-server --lib bench_commit_meta -- --ignored --nocapture`
    #[test]
    #[ignore = "微基准：需显式 --ignored --nocapture 运行"]
    fn bench_commit_meta_body_legacy_vs_borrowed() {
        use std::time::Instant;
        // 4 个 part = 生产典型的规模（config + rules + 订阅 meta）。
        let mut parts = Vec::new();
        for i in 0..4 {
            parts.push(PartMeta {
                path: format!("/var/lib/ebpdns/state/part-{i}.json"),
                sha256: format!("{:x}", i).repeat(64)[..64].to_string(),
                bytes: 1000 + i as u64,
            });
        }
        let c = Commit {
            revision: 7000,
            writer: "api".to_string(),
            committed_at: 1_760_000_000,
            rolled_back_from: None,
            parts,
        };
        let n = 20000;
        let mut ta = Vec::with_capacity(n);
        let mut tb = Vec::with_capacity(n);
        for _ in 0..n {
            let t0 = Instant::now();
            let legacy = serde_json::json!({
                "revision": c.revision,
                "writer": c.writer,
                "committed_at": c.committed_at,
                "parts": c.parts.iter().map(|p| serde_json::json!({
                    "path": p.path, "sha256": p.sha256, "bytes": p.bytes,
                })).collect::<Vec<_>>(),
            });
            std::hint::black_box(serde_json::to_vec_pretty(&legacy).unwrap());
            ta.push(t0.elapsed().as_nanos() as f64 / 1000.0);

            let t1 = Instant::now();
            std::hint::black_box(commit_meta_body(&c).unwrap());
            tb.push(t1.elapsed().as_nanos() as f64 / 1000.0);
        }
        let pct = |v: &mut Vec<f64>, p: f64| {
            v.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let k = ((v.len() - 1) as f64 * p / 100.0) as usize;
            v[k.min(v.len() - 1)]
        };
        let (a50, a99) = (pct(&mut ta, 50.0), pct(&mut ta, 99.0));
        let (b50, b99) = (pct(&mut tb, 50.0), pct(&mut tb, 99.0));
        assert_eq!(
            commit_meta_body(&c).unwrap().len(),
            serde_json::to_vec_pretty(&serde_json::json!({
                "revision": c.revision, "writer": c.writer, "committed_at": c.committed_at,
                "parts": c.parts.iter().map(|p| serde_json::json!({
                    "path": p.path, "sha256": p.sha256, "bytes": p.bytes })).collect::<Vec<_>>(),
            }))
            .unwrap()
            .len()
        );
        println!(
            "\n[B9/meta] parts=4 iters={n}\n  A json!树  : p50={a50:.2}us p99={a99:.2}us\n  B 借用式   : p50={b50:.2}us p99={b99:.2}us\n  ratio(p50) = {:.2}x",
            if b50 > 0.0 { a50 / b50 } else { 0.0 }
        );
    }

    /// **2.1.25（B9 性能项）**：`history/<rev>.meta.json` 的**线上字节**必须与
    /// 2.1.22–2.1.24 的 `json!` 实现**逐位相同** —— 这是"只省分配、不改语义"的护栏。
    ///
    /// 旧实现（`json!` 造 `Value` 树 + 每个 part 克隆两个 `String`）在下面内联保留，
    /// 作为**参照物**：它同时钉死"键序 = 字母序"这一前提（`serde_json::Map` 是
    /// `BTreeMap`；若有人给 serde_json 打开 `preserve_order`，本用例立刻变红）。
    #[test]
    fn commit_meta_body_is_byte_identical_to_legacy_json_macro() {
        let c = Commit {
            revision: 7000,
            writer: "cli:migrate-config".to_string(),
            committed_at: 1_760_000_000,
            rolled_back_from: None,
            parts: vec![
                PartMeta {
                    path: "/etc/ebpdns/config.json".to_string(),
                    sha256: "a".repeat(64),
                    bytes: 7919,
                },
                PartMeta {
                    path: "/var/lib/ebpdns/state/rules.json".to_string(),
                    sha256: "b".repeat(64),
                    bytes: 0,
                },
            ],
        };
        // ---- 参照物：2.1.24 的实现（**逐字照抄**，不要"顺手优化"这里）----
        let legacy = serde_json::json!({
            "revision": c.revision,
            "writer": c.writer,
            "committed_at": c.committed_at,
            "parts": c.parts.iter().map(|p| serde_json::json!({
                "path": p.path, "sha256": p.sha256, "bytes": p.bytes,
            })).collect::<Vec<_>>(),
        });
        let legacy_body = serde_json::to_vec_pretty(&legacy).unwrap();
        let now_body = commit_meta_body(&c).unwrap();
        assert_eq!(
            now_body, legacy_body,
            "meta.json 的字节必须与 2.1.24 逐位相同（只允许减少分配，不允许改形状/键序）"
        );
        // 正向断言：键序确为字母序（不是声明顺序的巧合之外的东西）。
        let text = String::from_utf8(now_body).unwrap();
        let i_ca = text.find("\"committed_at\"").expect("committed_at");
        let i_pa = text.find("\"parts\"").expect("parts");
        let i_re = text.find("\"revision\"").expect("revision");
        let i_wr = text.find("\"writer\"").expect("writer");
        assert!(
            i_ca < i_pa && i_pa < i_re && i_re < i_wr,
            "顶层键必须是字母序 committed_at < parts < revision < writer"
        );
        assert_eq!(text.matches("\"bytes\"").count(), 2, "每个 part 三个键");
    }

    /* ============ **2.1.26（B3：`prev_generation_ok` 去冗余读）** ============ */

    /// 2.1.25 的参考实现（**逐字照抄**）：`read_commit()` 在 `filter` 闭包里 ⇒
    /// 每个历史世代都要重读一遍当前的 `commit.json`，选中的世代还会再读一次。
    fn legacy_prev_generation_ok(s: &StateStore) -> bool {
        let Some(rev) = s
            .history_generations()
            .into_iter()
            .filter_map(|r| {
                let hdir = s.dir.join("history").join(r.to_string());
                s.read_commit_at(&hdir).map(|c| (r, c))
            })
            .filter(|(r, _)| s.read_commit().map(|c| *r < c.revision).unwrap_or(true))
            .map(|(r, _)| r)
            .max()
        else {
            return false;
        };
        let hdir = s.dir.join("history").join(rev.to_string());
        match s.read_commit_at(&hdir) {
            Some(c) => s.verify(&c, Some(rev)).is_ok(),
            None => false,
        }
    }

    /// **2.1.26（B3）**：`prev_generation_ok` 的**返回值**必须与 2.1.25 逐位相同 ——
    /// 只允许少读几遍 `commit.json`，不允许改判据。覆盖全部分支：
    /// 空目录 / 只有一个世代（无历史）/ 两代 / 最老世代被裁剪 / 历史 part 内容损坏 /
    /// 当前提交点缺失 / 历史目录里缺 `commit.json` 的"孤儿"目录。
    #[test]
    fn prev_generation_ok_is_unchanged_by_hoisting() {
        // ① 全新目录：无提交点、无历史 ⇒ false
        let d = tmpdir("pgo-fresh");
        let s = StateStore::open(&d, 2).unwrap();
        assert_eq!(s.prev_generation_ok(), legacy_prev_generation_ok(&s));
        assert!(!s.prev_generation_ok(), "无回退点必须如实报 false");

        // ② 第一次提交：历史为空 ⇒ false（两实现一致）
        let plan1 = parts(&d, &[("config.json", json!({"a": 1}))]);
        s.commit(&plan1, "test", 1000, 1).unwrap();
        assert_eq!(s.prev_generation_ok(), legacy_prev_generation_ok(&s));
        assert!(!s.prev_generation_ok(), "只有一个世代 ⇒ 没有可回退的上一代");

        // ③ 第二次提交 ⇒ history/1000 出现，回退点为 1000 ⇒ true
        let plan2 = parts(&d, &[("config.json", json!({"a": 2}))]);
        s.commit(&plan2, "test", 2000, 2).unwrap();
        assert_eq!(s.prev_generation_ok(), legacy_prev_generation_ok(&s));
        assert!(s.prev_generation_ok(), "上一代完好 ⇒ true");

        // ④ 第三次提交 ⇒ 历史 {1000, 2000}，选最新的 2000
        let plan3 = parts(&d, &[("config.json", json!({"a": 3}))]);
        s.commit(&plan3, "test", 3000, 3).unwrap();
        assert_eq!(s.prev_generation_ok(), legacy_prev_generation_ok(&s));
        assert!(s.prev_generation_ok());

        // ⑤ 历史目录里出现"缺 commit.json"的孤儿目录 ⇒ 两实现都跳过它
        fs::create_dir_all(d.join("history").join("1500")).unwrap();
        s.invalidate_prev_ok();
        assert_eq!(s.prev_generation_ok(), legacy_prev_generation_ok(&s));

        // ⑥ 最新历史世代的 part 内容损坏 ⇒ 两实现都 false（判据仍是 verify）
        //    注意历史布局是 `history/<rev>/parts/<part 的绝对路径去掉前导 />`
        //    （`hist_part_path`）⇒ 用 API 反解，不要手拼。
        let hist2000 = s
            .read_commit_at(&d.join("history").join("2000"))
            .expect("history/2000/commit.json");
        let victim = s.hist_part_path(2000, &hist2000.parts[0].path);
        let before = fs::read(&victim).unwrap();
        if fs::write(&victim, b"{\"a\": 999}").is_ok() {
            s.invalidate_prev_ok();
            assert_eq!(s.prev_generation_ok(), legacy_prev_generation_ok(&s));
            assert!(!s.prev_generation_ok(), "回退点内容损坏 ⇒ false");
            fs::write(&victim, &before).unwrap();
            s.invalidate_prev_ok();
            assert!(s.prev_generation_ok(), "还原后 ⇒ true（判据无副作用）");
        }

        // ⑦ 当前提交点缺失 ⇒ 所有历史世代都可回退（旧实现的 `unwrap_or(true)`）
        let commit_json = d.join("commit.json");
        let saved = fs::read(&commit_json).unwrap();
        fs::remove_file(&commit_json).unwrap();
        s.invalidate_prev_ok();
        assert_eq!(s.prev_generation_ok(), legacy_prev_generation_ok(&s));
        assert!(s.prev_generation_ok(), "无当前提交点 ⇒ 历史世代全部可回退");
        fs::write(&commit_json, &saved).unwrap();
        s.invalidate_prev_ok();
        assert_eq!(s.prev_generation_ok(), legacy_prev_generation_ok(&s));
    }

    /// **2.1.26（B3）同进程微基准**：`/api/status.state_persist` 里 `prev_generation_ok`
    /// 的两种读法（A = 2.1.25 的闭包内 `read_commit()`；B = 2.1.26 的一次快照）。
    ///
    /// 显式运行：
    /// `cargo test --release -p ebpdns-server --lib bench_prev_generation_ok -- --ignored --nocapture`
    #[test]
    #[ignore = "微基准：需显式 --ignored --nocapture 运行"]
    fn bench_prev_generation_ok_legacy_vs_hoisted() {
        use std::time::Instant;
        // 生产规模：4 个 part（config ~8 KB + rules + 2 个订阅材料）、history_keep=2。
        let d = tmpdir("pgo-bench");
        let s = StateStore::open(&d, 2).unwrap();
        let big: String = "x".repeat(8 * 1024);
        for i in 0..3u64 {
            let p = parts(
                &d,
                &[
                    ("config.json", json!({"blob": big, "rev": i})),
                    (
                        "rules.json",
                        json!({"rules": [{"id": "r1", "match": "a.example"}]}),
                    ),
                    (
                        "sub-meta.json",
                        json!({"id": "sub-1", "etag": format!("e{i}")}),
                    ),
                    (
                        "neg.json",
                        json!({"neg": [{"name": "n.example", "ttl": 60}]}),
                    ),
                ],
            );
            s.commit(&p, "api", 1000 * (i + 1), i + 1).unwrap();
        }
        let gens = s.history_generations();
        assert_eq!(gens.len(), 2, "history_keep=2 ⇒ 两个历史世代");
        let n = 2000;
        let mut ta = Vec::with_capacity(n);
        let mut tb = Vec::with_capacity(n);
        for _ in 0..n {
            let t0 = Instant::now();
            std::hint::black_box(legacy_prev_generation_ok(&s));
            ta.push(t0.elapsed().as_nanos() as f64 / 1000.0);

            let t1 = Instant::now();
            std::hint::black_box(s.prev_generation_ok());
            tb.push(t1.elapsed().as_nanos() as f64 / 1000.0);
        }
        let pct = |v: &mut Vec<f64>, p: f64| {
            v.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let k = ((v.len() - 1) as f64 * p / 100.0) as usize;
            v[k.min(v.len() - 1)]
        };
        let (a50, a99, b50, b99) = (
            pct(&mut ta, 50.0),
            pct(&mut ta, 99.0),
            pct(&mut tb, 50.0),
            pct(&mut tb, 99.0),
        );
        println!(
            "\n[B3/prev_generation_ok] parts=4 hist={:?} iters={n}\n  \
             A 2.1.25（闭包内 read_commit）: p50={a50:8.2}us p99={a99:8.2}us\n  \
             B 2.1.26（一次快照）          : p50={b50:8.2}us p99={b99:8.2}us\n  \
             ratio(p50) = {:.2}x  (省 {:.1}%)",
            gens,
            if b50 > 0.0 { a50 / b50 } else { 0.0 },
            if a50 > 0.0 {
                (a50 - b50) / a50 * 100.0
            } else {
                0.0
            }
        );
    }

    #[test]
    fn fresh_dir_is_legacy_and_first_commit_is_committed() {
        let d = tmpdir("fresh");
        let s = StateStore::open(&d, 2).unwrap();
        assert_eq!(
            s.load(),
            LoadState::Legacy,
            "无 commit.json ⇒ Legacy（可迁移）"
        );
        assert_eq!(s.current_revision(), None);
        let c = s
            .commit(
                &parts(&d, &[("config.json", json!({"a": 1}))]),
                "test",
                1000,
                1,
            )
            .unwrap();
        assert_eq!(c.revision, 1000);
        assert_eq!(c.parts.len(), 1);
        assert_eq!(c.parts[0].sha256.len(), 64, "SHA-256 十六进制 = 64 字符");
        match s.load() {
            LoadState::Committed(x) => assert_eq!(x.revision, 1000),
            other => panic!("expected Committed, got {other:?}"),
        }
    }

    /// **跨目录用例**（裁决 1 的直接要求）：`config.json` 在"`/etc` 形"目录、
    /// `rules.json` 与 `commit.json` 在 state 目录 —— 两者是**不同目录**。
    #[test]
    fn cross_directory_parts_are_committed_atomically() {
        let etc = tmpdir("xd-etc");
        let state = tmpdir("xd-state");
        fs::create_dir_all(&etc).unwrap();
        let s = StateStore::open(&state, 2).unwrap();
        let mut p: BTreeMap<PathBuf, Vec<u8>> = BTreeMap::new();
        p.insert(
            etc.join("config.json"),
            StateStore::json_bytes(&json!({"ttl": 300})),
        );
        p.insert(
            state.join("rules.json"),
            StateStore::json_bytes(&json!({"rules": []})),
        );
        let c = s.commit(&p, "api", 1000, 1).unwrap();
        assert_eq!(c.parts.len(), 2);
        // commit.json 在 state/，但它记录的是**绝对路径**（可以指向 /etc）
        assert!(c
            .parts
            .iter()
            .any(|x| x.path.ends_with("/config.json") && x.path.starts_with('/')));
        assert!(matches!(s.load(), LoadState::Committed(_)));
        // 撕裂检测跨目录同样有效：改掉 /etc 里的 part ⇒ 回退
        s.commit(&p, "api", 2000, 2).unwrap();
        fs::write(etc.join("config.json"), b"{\"ttl\": 999}").unwrap();
        match s.load() {
            LoadState::RolledBack { broken, restored } => {
                assert_eq!(broken, 2000);
                assert_eq!(restored.revision, 1000);
            }
            other => panic!("expected RolledBack, got {other:?}"),
        }
    }

    #[test]
    fn commit_is_multi_part_and_manifest_records_every_part() {
        let d = tmpdir("multi");
        let s = StateStore::open(&d, 2).unwrap();
        let c = s
            .commit(
                &parts(
                    &d,
                    &[
                        ("config.json", json!({"ttl": 300})),
                        ("rules.json", json!({"rules": []})),
                        ("subscriptions.json", json!([])),
                    ],
                ),
                "api",
                2000,
                2,
            )
            .unwrap();
        assert_eq!(c.parts.len(), 3);
        let names: Vec<String> = c
            .parts
            .iter()
            .map(|p| p.path.rsplit('/').next().unwrap().to_string())
            .collect();
        assert_eq!(
            names,
            vec!["config.json", "rules.json", "subscriptions.json"]
        );
        for p in &c.parts {
            let body = s.read_part(Path::new(&p.path)).unwrap();
            assert_eq!(body.len() as u64, p.bytes);
            assert_eq!(sha256_hex(&body), p.sha256);
        }
    }

    // >>> 242B BEGIN T-state >>> //
    /// **2.1.42-B（P1-10）**：回退必须把 history parts **真正写回 live** 并复验，
    /// 而不是只返回一个 `RolledBack` 状态继续服务混合世代。
    #[test]
    fn p1_10_rollback_restores_live_parts_and_commit_point() {
        let d = tmpdir("p110");
        let s = StateStore::open(&d, 2).unwrap();
        s.commit(
            &parts(
                &d,
                &[
                    ("config.json", json!({"v": 1})),
                    ("rules.json", json!({"rules": [1]})),
                ],
            ),
            "w",
            1000,
            1,
        )
        .unwrap();
        s.commit(
            &parts(
                &d,
                &[
                    ("config.json", json!({"v": 2})),
                    ("rules.json", json!({"rules": [2]})),
                ],
            ),
            "w",
            2000,
            2,
        )
        .unwrap();
        // 模拟"commit.json 已指向新世代，但 live rules 只 renamed 了一半"的撕裂：
        fs::write(
            d.join("rules.json"),
            StateStore::json_bytes(&json!({"rules": [2]})),
        )
        .unwrap();
        fs::write(
            d.join("config.json"),
            StateStore::json_bytes(&json!({"v": 2})),
        )
        .unwrap();
        // 把 rules 改成与提交点记录的 sha 不符（真正的"内容损坏"）。
        fs::write(
            d.join("rules.json"),
            StateStore::json_bytes(&json!({"rules": [9]})),
        )
        .unwrap();
        // **2.1.45（P2-7）**：模拟安装口径（`install -m 0640`）—— 回退写回必须保留它，
        // 旧实现走 `preserve_mode:false` 的 atomic_write ⇒ 一次 RolledBack 放宽成 0644。
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(d.join("config.json"), fs::Permissions::from_mode(0o640)).unwrap();
        }
        match s.load() {
            LoadState::RolledBack { broken, restored } => {
                assert_eq!(broken, 2000);
                assert_eq!(restored.revision, 1000);
                // live parts 必须已经恢复成 rev1000 的内容。
                assert_eq!(
                    s.read_part(&d.join("config.json")).unwrap(),
                    StateStore::json_bytes(&json!({"v": 1})),
                    "live config 必须恢复为历史世代"
                );
                assert_eq!(
                    s.read_part(&d.join("rules.json")).unwrap(),
                    StateStore::json_bytes(&json!({"rules": [1]})),
                    "live rules 必须恢复为历史世代"
                );
                // **2.1.45（P2-7 / REV247 P2-3）**：回退写回 live part 必须**保留 0640**。
                {
                    use std::os::unix::fs::PermissionsExt;
                    let m = fs::metadata(d.join("config.json"))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777;
                    assert_eq!(m, 0o640, "回退恢复不得把 config.json 放宽成 0644");
                }
                // 提交点也必须是恢复后的世代（读方不会再看到撕裂的 2000）。
                assert_eq!(s.current_revision(), Some(1000));
                assert!(s.verify(&restored, None).unwrap().is_empty());
            }
            other => panic!("expected RolledBack, got {other:?}"),
        }
    }

    #[test]
    fn torn_part_is_detected_and_rolled_back_to_previous_generation() {
        // <<< 242B END T-state <<< //
        let d = tmpdir("torn");
        let s = StateStore::open(&d, 2).unwrap();
        s.commit(
            &parts(&d, &[("config.json", json!({"v": 1}))]),
            "w",
            1000,
            1,
        )
        .unwrap();
        s.commit(
            &parts(&d, &[("config.json", json!({"v": 2}))]),
            "w",
            2000,
            2,
        )
        .unwrap();
        fs::write(
            d.join("config.json"),
            StateStore::json_bytes(&json!({"v": 1})),
        )
        .unwrap();
        match s.load() {
            LoadState::RolledBack { broken, restored } => {
                assert_eq!(broken, 2000);
                assert_eq!(restored.revision, 1000);
            }
            other => panic!("expected RolledBack, got {other:?}"),
        }
    }

    /// **2.1.23（DEF-222-11）口径变更**：part **缺失** ⇒ 如实报告，但**不判撕裂**
    /// （理由与实测见 [`StateStore::verify`] 的文档）。
    ///
    /// 本用例原名 `missing_part_is_torn_and_falls_back`（2.1.22 的行为）。
    /// 它锁的其实**不是**"内容损坏"，而是"**可选镜像**文件不存在" —— 那两件事必须分开：
    /// * 可选镜像不存在（本用例）⇒ `Committed` + `missing_parts()` 报出（**不**回退）；
    /// * **必需** part（`config.json` / `rules.json`）不存在 ⇒ 回退 / Torn；
    /// * **内容**不符（`def222_11_*` / `both_generations_broken_*`）⇒ 回退 / Torn。
    ///
    /// **2.1.46（REV247 P2-5）**：原用例删的是 `rules.json`（规则真源）却断言
    /// `Committed`，正是"整份 required part 被删仍报健康"的缺陷；改用镜像
    /// `rules_local.json` 才符合 2.1.23 的"镜像可删"语义。
    #[test]
    fn def222_11_missing_optional_mirror_is_reported_and_the_generation_stays_usable() {
        let d = tmpdir("missing");
        let s = StateStore::open(&d, 2).unwrap();
        s.commit(
            &parts(
                &d,
                &[
                    ("config.json", json!({"v": 1})),
                    ("rules.json", json!([])),
                    ("rules_local.json", json!({"rules": []})),
                ],
            ),
            "w",
            1000,
            1,
        )
        .unwrap();
        s.commit(
            &parts(
                &d,
                &[
                    ("config.json", json!({"v": 2})),
                    ("rules.json", json!([1])),
                    ("rules_local.json", json!({"rules": [1]})),
                ],
            ),
            "w",
            2000,
            2,
        )
        .unwrap();
        fs::remove_file(d.join("rules_local.json")).unwrap();
        match s.load() {
            LoadState::Committed(c) => assert_eq!(c.revision, 2000, "当前世代仍然可用"),
            other => panic!(
                "**可选镜像缺失不得判撕裂/回退**（2.1.22 在这里每次启动都误报『已回退上一代』）：\
                 {other:?}"
            ),
        }
        let missing = s.missing_parts();
        assert_eq!(missing.len(), 1, "缺失必须被如实报出：{missing:?}");
        assert!(missing[0].ends_with("rules_local.json"), "{missing:?}");
        // **2.1.46（REV247 P2-5）**：同一事实必须进入 `/api/status.state_persist`。
        let info = persist_info(&d, Some(&s), true, "note", None);
        assert_eq!(
            info["missing_parts"],
            json!(missing),
            "state_persist.missing_parts 必须与 missing_parts() 同源"
        );
    }

    /// **2.1.46（REV247 P2-5 / C P1-05）**：删除**必需** part（`rules.json` 真源）
    /// 必须回退到上一代；两代都缺 ⇒ Torn。旧实现只记 `missing` 然后返回 `Committed`，
    /// 本用例在旧实现下会红（第一段拿到 `Committed(2000)`）。
    #[test]
    fn required_rules_missing_rolls_back_or_torn() {
        let d = tmpdir("missing-required");
        let s = StateStore::open(&d, 2).unwrap();
        s.commit(
            &parts(
                &d,
                &[("config.json", json!({"v": 1})), ("rules.json", json!([]))],
            ),
            "w",
            1000,
            1,
        )
        .unwrap();
        s.commit(
            &parts(
                &d,
                &[("config.json", json!({"v": 2})), ("rules.json", json!([1]))],
            ),
            "w",
            2000,
            2,
        )
        .unwrap();
        fs::remove_file(d.join("rules.json")).unwrap();
        match s.load() {
            LoadState::RolledBack { broken, restored } => {
                assert_eq!(broken, 2000, "缺失的当前世代必须被拒绝");
                assert_eq!(restored.revision, 1000, "必须回退到含 rules.json 的上一代");
            }
            other => panic!("必需 part 缺失必须回退，实际 {other:?}"),
        }
        // 两代都缺 ⇒ 没有可信世代。
        fs::remove_file(
            d.join("history/1000/parts").join(
                d.join("rules.json")
                    .to_string_lossy()
                    .trim_start_matches('/'),
            ),
        )
        .unwrap();
        fs::remove_file(d.join("rules.json")).ok();
        match s.load() {
            LoadState::Torn { reason } => assert!(reason.contains("必需 part"), "{reason}"),
            other => panic!("两代都缺必需 part 必须 Torn，实际 {other:?}"),
        }
    }

    #[test]
    fn both_generations_broken_is_torn_and_reported() {
        let d = tmpdir("both");
        let s = StateStore::open(&d, 2).unwrap();
        s.commit(
            &parts(&d, &[("config.json", json!({"v": 1}))]),
            "w",
            1000,
            1,
        )
        .unwrap();
        s.commit(
            &parts(&d, &[("config.json", json!({"v": 2}))]),
            "w",
            2000,
            2,
        )
        .unwrap();
        fs::write(d.join("config.json"), b"{}").unwrap();
        fs::write(
            d.join("history/1000/parts").join(
                d.join("config.json")
                    .to_string_lossy()
                    .trim_start_matches('/'),
            ),
            StateStore::json_bytes(&json!({"v": 999})),
        )
        .unwrap();
        match s.load() {
            LoadState::Torn { reason } => assert!(reason.contains("config.json"), "{reason}"),
            other => panic!("expected Torn, got {other:?}"),
        }
    }

    #[test]
    fn history_is_pruned_to_the_configured_cap_but_keeps_at_least_one() {
        let d = tmpdir("prune");
        let s = StateStore::open(&d, 2).unwrap();
        for i in 1..=5u64 {
            s.commit(
                &parts(&d, &[("config.json", json!({"v": i}))]),
                "w",
                1000 * i,
                i,
            )
            .unwrap();
        }
        assert_eq!(s.history_generations(), vec![3000, 4000], "默认留 2 代");

        let d2 = tmpdir("prune1");
        let s2 = StateStore::open(&d2, 1).unwrap();
        for i in 1..=3u64 {
            s2.commit(
                &parts(&d2, &[("config.json", json!({"v": i}))]),
                "w",
                1000 * i,
                i,
            )
            .unwrap();
        }
        assert_eq!(
            s2.history_generations(),
            vec![2000],
            "上限 1 也必须保底 1 代（回退点）"
        );
    }

    #[test]
    fn next_revision_is_strictly_increasing_even_with_a_backwards_clock() {
        let d = tmpdir("rev");
        let s = StateStore::open(&d, 2).unwrap();
        let a = s
            .commit(&parts(&d, &[("config.json", json!({}))]), "w", 5000, 1)
            .unwrap();
        let b = s
            .commit(
                &parts(&d, &[("config.json", json!({"x": 1}))]),
                "w",
                4000,
                2,
            )
            .unwrap();
        assert!(
            b.revision > a.revision,
            "{:?} > {:?}",
            b.revision,
            a.revision
        );
        assert_eq!(b.revision, 5001);
    }

    #[test]
    fn commit_leaves_no_tmp_when_it_completes() {
        let d = tmpdir("tmp");
        let s = StateStore::open(&d, 2).unwrap();
        let p = parts(
            &d,
            &[("config.json", json!({"a": 1})), ("rules.json", json!([]))],
        );
        s.commit(&p, "w", 1000, 1).unwrap();
        s.commit(&p, "w", 2000, 2).unwrap();
        assert!(
            s.leftover_tmp().is_empty(),
            "正常提交不得残留：{:?}",
            s.leftover_tmp()
        );
    }

    /// 崩溃残留的 `*.tmp` 必须能被 `cleanup_stale_tmp()` 幂等清掉，且**不影响读方**。
    #[test]
    fn stale_tmp_is_ignored_by_readers_and_cleanable() {
        let d = tmpdir("stale");
        let s = StateStore::open(&d, 2).unwrap();
        s.commit(
            &parts(&d, &[("config.json", json!({"a": 1}))]),
            "w",
            1000,
            1,
        )
        .unwrap();
        // 手工制造"崩溃残留"
        fs::write(d.join("config.json.9999.tmp"), b"half-written").unwrap();
        fs::write(d.join("rules.json.9999.tmp"), b"half-written").unwrap();
        assert_eq!(s.load(), s.load());
        assert!(
            matches!(s.load(), LoadState::Committed(_)),
            "残留 tmp 不得影响读方"
        );
        assert_eq!(s.cleanup_stale_tmp(), 2);
        assert_eq!(s.cleanup_stale_tmp(), 0, "幂等");
    }

    /* ================================================================= */
    /* 2.1.23 · DEF-222-07 / 08 / 09：`history/` 的**清理**必须完备       */
    /* ================================================================= */

    /// **DEF-222-07**：审计 `.meta.json` 必须与世代目录**同寿命**（2.1.22 从不裁剪
    /// ⇒ 生产实测 `history/` 里 86 个 meta vs **4** 个世代目录 = 无界增长）。
    #[test]
    fn def222_07_audit_meta_is_pruned_with_history_keep() {
        let d = tmpdir("meta7");
        let s = StateStore::open(&d, 2).unwrap();
        // 6 次提交 ⇒ 5 个历史世代被快照过，但上限是 2 ⇒ 只应剩 2 个世代目录。
        for i in 1..=6u64 {
            let p = parts(&d, &[("config.json", json!({"v": i}))]);
            let c = s.commit(&p, "w", 1000 * i, i).unwrap();
            super::write_meta(&s, &c).expect("write meta");
        }
        assert_eq!(s.history_generations(), vec![4000, 5000], "世代目录留 2 个");
        // 显式再裁剪一次（模拟"上一次提交中途失败"后的补偿路径）。
        s.prune_history();
        let hdir = d.join("history");
        let mut metas: Vec<String> = fs::read_dir(&hdir)
            .unwrap()
            .flatten()
            .filter_map(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.ends_with(".meta.json").then_some(n)
            })
            .collect();
        metas.sort();
        // 保留集合 = 世代目录 {4000,5000} ∪ 当前代 {6000}；更早的（1000..3000）必须删掉。
        // 判据写成"**没有已无世代目录的孤儿 meta**"（2.1.22 会留 6 个，其中 5 个是孤儿）。
        let dirs: Vec<u64> = s.history_generations();
        let cur = s.current_revision().unwrap_or(0);
        for m in &metas {
            let rev: u64 = m.trim_end_matches(".meta.json").parse().expect("数字");
            assert!(
                dirs.contains(&rev) || rev == cur,
                "**孤儿 meta 必须被裁掉**：{m}（保留世代 {dirs:?}，当前代 {cur}）"
            );
        }
        assert!(
            metas.len() <= dirs.len() + 1,
            "meta 数量必须与保留世代 + 当前代同阶（2.1.22 是 6 个）：{metas:?}"
        );
        // 保留世代里最老的那个（= 4000，**回退点**）的 meta 必须**在**。
        assert!(
            hdir.join("4000.meta.json").is_file(),
            "回退点世代的 meta 不得被误删：{metas:?}"
        );
        assert!(
            !hdir.join("3000.meta.json").exists(),
            "已被裁掉的世代的 meta 必须删掉：{metas:?}"
        );
    }

    /// **DEF-222-08**：残留 `*.tmp` 的清理必须覆盖**各 part 目录**（不只是 `state/`）。
    ///
    /// 2.1.22 只扫 `state/`，而暂存文件写在**每个 part 自己的目录**里
    /// （ENOSPC 复现留下 `/etc` 侧的 `config.json.<rev>.tmp` ⇒ 永远没人清）。
    #[test]
    fn def222_08_stale_tmp_cleanup_covers_every_part_directory() {
        let state = tmpdir("tmp8-state");
        let etc = tmpdir("tmp8-etc");
        fs::create_dir_all(&etc).unwrap();
        let cfg = etc.join("config.json");
        let mut p: BTreeMap<PathBuf, Vec<u8>> = BTreeMap::new();
        p.insert(cfg.clone(), StateStore::json_bytes(&json!({"a": 1})));
        p.insert(state.join("rules.json"), StateStore::json_bytes(&json!([])));
        let s = StateStore::open(&state, 2).unwrap();
        s.commit(&p, "w", 1000, 1).unwrap();

        // 崩溃残留：**跨目录**两个（state/ 一个、/etc 形目录一个）。
        fs::write(state.join("rules.json.9999.tmp"), b"half").unwrap();
        fs::write(etc.join("config.json.9999.tmp"), b"half").unwrap();
        // 读方完全不受影响。
        assert!(matches!(s.load(), LoadState::Committed(_)));
        let found = s.leftover_tmp();
        assert_eq!(found.len(), 2, "必须同时发现两处残留：{found:?}");
        assert!(
            found.iter().any(|f| f.contains("config.json.9999.tmp")),
            "**part 目录里的 tmp 必须被发现**（2.1.22 漏掉这一处）：{found:?}"
        );
        assert_eq!(s.cleanup_stale_tmp(), 2, "两处都要清掉");
        assert_eq!(s.cleanup_stale_tmp(), 0, "幂等");
        assert!(!etc.join("config.json.9999.tmp").exists());
        let _ = fs::remove_dir_all(&etc);
    }

    /// **DEF-222-09**：`history/` 的裁剪**不能只看 commit 是否成功** ——
    /// `startup_cleanup` 必须能补偿"上次提交中途失败"留下的超额世代。
    #[test]
    fn def222_09_startup_cleanup_compensates_a_failed_commit() {
        let d = tmpdir("prune9");
        let s = StateStore::open(&d, 2).unwrap();
        for i in 1..=2u64 {
            s.commit(
                &parts(&d, &[("config.json", json!({"v": i}))]),
                "w",
                1000 * i,
                i,
            )
            .unwrap();
        }
        // 手工模拟"第 1 步快照成功、第 3/4 步失败后进程退出"：
        // 多出**两个**世代目录 + 两个 meta（一个不够 —— 上限是 2）。
        for rev in [998u64, 999] {
            let extra = d.join("history").join(rev.to_string());
            fs::create_dir_all(extra.join("parts")).unwrap();
            fs::write(extra.join("commit.json"), b"{}").unwrap();
            fs::write(d.join("history").join(format!("{rev}.meta.json")), b"{}").unwrap();
        }
        let h1 = s.history_generations();
        assert!(
            h1.len() > 2,
            "构造必须真的超出上限（否则本用例没有覆盖补偿路径）：{h1:?}"
        );
        // 启动清理必须把它裁到上限，**且按"最老优先"裁**（保留最新世代 = 回退优先级最高）。
        let removed_tmp = startup_cleanup(&s);
        assert_eq!(removed_tmp, 0, "本例没有 tmp 残留");
        let hist = s.history_generations();
        assert_eq!(
            hist.len(),
            2,
            "启动补偿必须回到上限：{hist:?}（构造前 {h1:?}）"
        );
        assert_eq!(
            hist[0], h1[1],
            "必须裁掉**最老**的那个（998），保留紧随其后的：{hist:?} vs {h1:?}"
        );
        assert!(
            !d.join("history").join("998.meta.json").exists(),
            "被裁世代的 meta 也必须一起删（2.1.22 会留成孤儿）"
        );
        let metas: Vec<String> = fs::read_dir(d.join("history"))
            .unwrap()
            .flatten()
            .filter_map(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.ends_with(".meta.json").then_some(n)
            })
            .collect();
        assert!(metas.len() <= 2, "meta 也必须回到上限内：{metas:?}");
    }

    /// **2.1.23（DEF-222-11）**：`commit.json` 记录了盘上**不存在**的 part ⇒
    /// **不得**判撕裂/回退（2.1.22 每次启动都会误报 `WARN 已回退到上一代`）。
    ///
    /// 复现场景（审计实测）：交付收尾**故意删除**了 `rules_local.json` 镜像，
    /// 而更早的世代 `commit.json` 里仍记着它 ⇒ 内容其实一条没丢，却被判"撕裂"。
    #[test]
    fn def222_11_a_missing_part_is_reported_but_does_not_force_a_rollback() {
        let d = tmpdir("missing11");
        let s = StateStore::open(&d, 2).unwrap();
        let cfg = d.join("config.json");
        let mirror = d.join("rules_local.json");
        // ① 第一代：**含**镜像（模拟 2.1.22 的提交计划）。
        let mut p1: BTreeMap<PathBuf, Vec<u8>> = BTreeMap::new();
        p1.insert(cfg.clone(), StateStore::json_bytes(&json!({"v": 1})));
        p1.insert(
            mirror.clone(),
            StateStore::json_bytes(&json!({"rules": []})),
        );
        s.commit(&p1, "w", 1000, 1).unwrap();
        // ② 第二代：**不含**镜像（模拟 2.1.23 的计划）⇒ 镜像从此不再被刷新/重建。
        let mut p2: BTreeMap<PathBuf, Vec<u8>> = BTreeMap::new();
        p2.insert(cfg.clone(), StateStore::json_bytes(&json!({"v": 2})));
        s.commit(&p2, "w", 2000, 2).unwrap();
        // ③ 运维/交付收尾删掉镜像（这是**正常**动作，不是损坏）。
        fs::remove_file(&mirror).unwrap();
        // ④ 手工把镜像写回**当前**世代的记录里（模拟"上一代的计划含它"这一事实）：
        //    直接改盘上的 commit.json，等价于"旧版本写的提交点 + 新版本读"。
        let mut c = s.read_commit().unwrap();
        c.parts.push(PartMeta {
            path: mirror.to_string_lossy().to_string(),
            sha256: sha256_hex(b"whatever"),
            bytes: 8,
        });
        c.parts.sort_by(|a, b| a.path.cmp(&b.path));
        s.replace_commit(&c).unwrap();

        // ⑤ 读方：**当前世代仍然可用**（不判撕裂、不回退）。
        match s.load() {
            LoadState::Committed(got) => assert_eq!(got.revision, c.revision),
            other => {
                panic!("缺一个 part **不得**判撕裂/回退（2.1.22 在这里每次启动都误报）：{other:?}")
            }
        }
        // ⑥ 但必须**如实回报**（不得静默）。
        let missing = s.missing_parts();
        assert_eq!(
            missing.len(),
            1,
            "缺失的 part 必须被报出来（否则镜像承诺会静默失效）：{missing:?}"
        );
        assert!(missing[0].ends_with("rules_local.json"), "{missing:?}");
        // ⑦ 反证：**内容**被改坏仍然必须回退（判据没有被放松成"永不回退"）。
        fs::write(&cfg, StateStore::json_bytes(&json!({"v": 999}))).unwrap();
        match s.load() {
            LoadState::RolledBack { broken, restored } => {
                assert_eq!(broken, c.revision);
                assert_eq!(restored.revision, 1000);
            }
            other => panic!("内容损坏必须回退，实际 {other:?}"),
        }
    }

    #[test]
    fn legacy_layout_without_commit_json_is_not_an_error() {
        let d = tmpdir("legacy");
        fs::create_dir_all(&d).unwrap();
        fs::write(
            d.join("config.json"),
            StateStore::json_bytes(&json!({"old": true})),
        )
        .unwrap();
        fs::write(
            d.join("rules_local.json"),
            StateStore::json_bytes(&json!([])),
        )
        .unwrap();
        let s = StateStore::open(&d, 2).unwrap();
        assert_eq!(
            s.load(),
            LoadState::Legacy,
            "2.1.21 布局必须是 Legacy（待迁移）"
        );
    }

    #[test]
    fn sha256_matches_known_vectors() {
        // NIST FIPS 180-4 示例
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    /// **2.1.43-B（P2-6）回归**：提交 `config.json` 必须**保留原有权限位**
    /// （安装口径 `0640`），不得因 `File::create(tmp)` 的默认 `0644` 而放宽；
    /// 目标文件不存在时也必须落 `0640`（不是 `0644`）。
    #[cfg(unix)]
    #[test]
    fn commit_preserves_config_json_mode_and_defaults_to_0640() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmpdir("mode");
        fs::create_dir_all(&d).unwrap();
        let s = StateStore::open(&d, 2).unwrap();
        let cfg = d.join("config.json");
        // ① 已存在 0640（= install.sh 装出来的形态）：提交两次都必须仍是 0640。
        fs::write(&cfg, b"{}").unwrap();
        fs::set_permissions(&cfg, fs::Permissions::from_mode(0o640)).unwrap();
        let mut p = BTreeMap::new();
        p.insert(cfg.clone(), StateStore::json_bytes(&json!({"a": 1})));
        s.commit(&p, "test", 1000, 10).unwrap();
        let m1 = fs::metadata(&cfg).unwrap().permissions().mode() & 0o777;
        assert_eq!(m1, 0o640, "提交必须保留 0640（旧实现会放宽成 0644）");
        p.insert(cfg.clone(), StateStore::json_bytes(&json!({"a": 2})));
        s.commit(&p, "test", 2000, 11).unwrap();
        assert_eq!(
            fs::metadata(&cfg).unwrap().permissions().mode() & 0o777,
            0o640,
            "第二次提交同样必须保持 0640"
        );
        // ② 目标不存在（新增 part）：默认 0640（安装口径），不是 0644。
        let fresh = d.join("fresh-part.json");
        let mut p2 = BTreeMap::new();
        p2.insert(fresh.clone(), StateStore::json_bytes(&json!({"b": 1})));
        s.commit(&p2, "test", 3000, 12).unwrap();
        assert_eq!(
            fs::metadata(&fresh).unwrap().permissions().mode() & 0o777,
            0o640,
            "不存在的 part 必须落 0640（不是 File::create 的默认 0644）"
        );
    }
}
