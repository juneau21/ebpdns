//! **2.1.29（缓存持久化 v2：快照 + WAL）** —— 格式层与恢复层的**单一实现**。
//!
//! 设计契约见 `docs/PROPOSAL-cache-snapshot-wal.md`（字节级布局表 §5、可见性 §7.1、
//! 崩溃矩阵 §8、`persist_ttl` 等价表 §7.5、实施清单 §16）。本模块只做**纯数据**：
//! 编码/解码/校验/回放，**不做**任何目录创建、配置读取、日志策略决定 —— 那些在
//! `ebpdns::cache_persist`（actor）里。
//!
//! 文件布局（全部在 `cache_file` 的同一目录，§4.1）：
//!
//! ```text
//! <dir>/<base>                     ← v2 manifest（原子指针；逻辑名 cache.manifest）
//! <dir>/<base>.snap.<seq>          ← 二进制快照（自校验）
//! <dir>/<base>.wal.<base_seq>      ← WAL 段（追加；记录级 CRC32C）
//! <dir>/<base>.v1.bak              ← 一次性迁移保留的原 v1 JSON（永不自动删除）
//! <dir>/<base>.corrupt.<unix_ms>   ← 损坏现场保留（只写一次；读方不读）
//! <dir>/<base>.lock                ← flock 单实例锁
//! ```
//!
//! **读方只信任 manifest 指向的快照 + 其后的完整 CRC 记录**；`*.tmp`、孤儿文件
//! 一律不读（H6/H8）。

pub mod crc32c;
pub mod entry_codec;
pub mod journal;
pub mod manifest;
pub mod recover;
pub mod snapshot;
pub mod wal;

pub use crc32c::{crc32c, crc32c_finalize, crc32c_update};
pub use entry_codec::{AnswerBody, EntryBody};
pub use journal::{CacheJournal, ClearReason, Event, EvictReason};
pub use manifest::Manifest;
pub use recover::{RecoverError, RestorePlan};
pub use snapshot::{SnapshotMeta, SnapshotReader, SnapshotWriter};
pub use wal::{WalItem, WalReader, WalRec, WalWriter};

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

// ---------------- 内部常量（**不是**配置键；H2） ----------------

/// WAL `fdatasync` 的最长间隔 —— 也就是**丢失窗口上界**（§6.2）。
pub const WAL_FSYNC_MS: u64 = 1000;
/// 单批最多合并的事件数。
pub const WAL_BATCH_MAX_EVENTS: usize = 4096;
/// 单批最多字节（估算）。
pub const WAL_BATCH_MAX_BYTES: usize = 256 * 1024;
/// 数据面 → actor 的事件环形缓冲容量（约 1.6–2 MiB）。
pub const JOURNAL_RING: usize = 8192;
/// 单条 WAL body / 快照记录的上限（§5.1）。
pub const MAX_RECORD_BYTES: u32 = 1_048_576;
/// manifest 允许的最大字节数（防坏文件吃内存）。
pub const MANIFEST_MAX_BYTES: u64 = 8192;
/// compaction 的 WAL 阈值下限（实际阈值 = `max(本值, snap_bytes)`）。
///
/// **2.1.37（T1）**：8 MiB → **2 MiB**。同一负载下的隔离实例 A/B 实测：WAL 峰值
/// 8.34 MB → 2.10 MB（−74.8%），合并次数按字节线性增加，快照重写开销 +1.5%；
/// 恢复 p50/p95 不劣化（数字见 `REPORT-2.1.37.md` 的 A/B 表）。
pub const COMPACT_MIN_BYTES: u64 = 2 * 1024 * 1024;

/// **2.1.37（T1）**：字节触发要求的**条目变更比例**下限（千分数）。
///
/// 只在**快照重写很贵**（`snap_bytes > COMPACT_MIN_BYTES`）时生效：此时一次
/// compaction 要重写整份快照，若 WAL 覆盖的变更条目数远少于现存条目数，重写就是纯
/// 写放大 —— 那种情况交给 `wal_hard_max` / 时间节拍兜底。**小快照（≤ 2 MiB）恒放行**，
/// 与 2.1.36 的字节触发口径逐位一致，只把阈值从 8 MiB 降到 2 MiB。
pub const COMPACT_CHANGE_PERMILLE: u64 = 125;
/// compaction 的最短间隔（秒）。
pub const COMPACT_MIN_INTERVAL_S: u64 = 1800;

/// 单段 WAL 的硬上限（随快照大小缩放，§6.2）。
pub fn wal_hard_max(snap_bytes: u64) -> u64 {
    (64 << 20).max(2 * snap_bytes)
}

/// compaction 的 WAL 字节阈值（§6.3.1 规则 1/3）。
pub fn compact_threshold(snap_bytes: u64) -> u64 {
    COMPACT_MIN_BYTES.max(snap_bytes)
}

// ---------------- 可观测枚举 ----------------

/// 当前落盘格式（`/api/status.cache.persist.format`）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    V1,
    V2,
    Unknown,
}

impl Format {
    pub fn as_str(self) -> &'static str {
        match self {
            Format::V1 => "v1",
            Format::V2 => "v2",
            Format::Unknown => "unknown",
        }
    }
    fn code(self) -> u8 {
        match self {
            Format::V1 => 0,
            Format::V2 => 1,
            Format::Unknown => 2,
        }
    }
    fn from_code(c: u8) -> Self {
        match c {
            0 => Format::V1,
            1 => Format::V2,
            _ => Format::Unknown,
        }
    }
}

/// 本次启动实际走了哪条恢复路径（`restore_source`，§10.1）。
///
/// **不残留上次**：启动恢复时**必然**被写一次（成功或失败都写）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RestoreSource {
    /// `cache_persist=false` 或文件不存在且无 `.bak`：空缓存启动。
    None,
    /// v1 JSON（`cache_file` 本体）。
    V1Json,
    /// v1 JSON（`.v1.bak`）。
    V1Bak,
    /// v1 → v2 迁移完成（此后以 v2 运行）。
    Migrated,
    /// v2：纯快照（manifest `wal_count=0`）。
    V2Snapshot,
    /// v2：快照 + WAL 回放。
    V2SnapshotWal,
    /// v2：最后一段 WAL 尾部截断后恢复（保守，不判撕裂）。
    WalTruncated,
    /// 现场损坏（manifest/快照不可用），已保留现场并禁用 v2 写。
    Corrupt,
    /// 未来版本的格式（`version > 2`）：不覆盖、禁用写、空缓存。
    Unsupported,
}

impl RestoreSource {
    pub fn as_str(self) -> &'static str {
        match self {
            RestoreSource::None => "none",
            RestoreSource::V1Json => "v1-json",
            RestoreSource::V1Bak => "v1-bak",
            RestoreSource::Migrated => "migrated",
            RestoreSource::V2Snapshot => "v2-snapshot",
            RestoreSource::V2SnapshotWal => "v2-snapshot+wal",
            RestoreSource::WalTruncated => "wal-truncated",
            RestoreSource::Corrupt => "corrupt",
            RestoreSource::Unsupported => "unsupported",
        }
    }
    fn code(self) -> u8 {
        match self {
            RestoreSource::None => 0,
            RestoreSource::V1Json => 1,
            RestoreSource::V1Bak => 2,
            RestoreSource::Migrated => 3,
            RestoreSource::V2Snapshot => 4,
            RestoreSource::V2SnapshotWal => 5,
            RestoreSource::WalTruncated => 6,
            RestoreSource::Corrupt => 7,
            RestoreSource::Unsupported => 8,
        }
    }
    fn from_code(c: u8) -> Self {
        match c {
            1 => RestoreSource::V1Json,
            2 => RestoreSource::V1Bak,
            3 => RestoreSource::Migrated,
            4 => RestoreSource::V2Snapshot,
            5 => RestoreSource::V2SnapshotWal,
            6 => RestoreSource::WalTruncated,
            7 => RestoreSource::Corrupt,
            8 => RestoreSource::Unsupported,
            _ => RestoreSource::None,
        }
    }
}

// ---------------- 可观测统计（唯一来源，§10.1） ----------------

/// 持久化现场统计。由 [`crate::SwappableCache`] 持有，两 API 端点读**同一份**。
///
/// **不**把统计塞进 `cfg`，也**不**新增第二个“现场来源”（2.1.19 R9 的教训）。
#[derive(Debug)]
pub struct PersistStats {
    format: AtomicU8,
    snap_seq: AtomicU64,
    snap_bytes: AtomicU64,
    wal_bytes: AtomicU64,
    wal_segments: AtomicU64,
    last_commit_ms: AtomicI64,
    manifest_valid: AtomicBool,
    restore_source: AtomicU8,
    /// 当前快照的条目数（对账用）。
    snap_entries: AtomicU64,
    /// **未过期**条目数（"活"条目）。
    ///
    /// 与 `summary().used` 的区别（长稳审计 P3）：`used` = **已分配**条目数，
    /// 含"TTL 已过期但尚未被惰性清理"的条目；`used_live` 只数 `expires_at > now`。
    /// 计算发生在**周期落盘的遍历里**（`for_each_entry` 已经在跑），
    /// 因此 `/api/status` **不增加** O(n) 扫描。
    ///
    /// 用途：**恢复丢失率**必须按 `used_live`/快照条目数算
    /// （`(快照 entries − 恢复后 used_live) / 快照 entries`）；
    /// 按 `used` 算会把"过期未清"误判成"恢复丢了"。
    used_live: AtomicU64,
    /// 恢复时尾部截断的记录数（WARN 用；**不**进 `restore_drops`）。
    tail_records: AtomicU64,
    /// journal 溢出/断连丢弃的事件数（WARN，限流）。
    journal_dropped: AtomicU64,
    /// 最后一个成功 `fdatasync` 的 seq。
    durable_seq: AtomicU64,
    /// **2.1.34（D4）**：当前快照的写入时刻（epoch ms；恢复时取快照文件 mtime）。
    /// 用于 `cache.persist.snapshot_age_s` 与“距上次快照 > TTL/2 ⇒ 强制快照”。
    snap_ms: AtomicI64,
    /// 本进程**是否允许写**（flock 失败 / `.corrupt` 现场 / 未来版本 ⇒ false）。
    write_enabled: AtomicBool,
}

impl Default for PersistStats {
    fn default() -> Self {
        Self {
            format: AtomicU8::new(Format::Unknown.code()),
            snap_seq: AtomicU64::new(0),
            snap_bytes: AtomicU64::new(0),
            wal_bytes: AtomicU64::new(0),
            wal_segments: AtomicU64::new(0),
            last_commit_ms: AtomicI64::new(0),
            manifest_valid: AtomicBool::new(false),
            restore_source: AtomicU8::new(RestoreSource::None.code()),
            snap_entries: AtomicU64::new(0),
            used_live: AtomicU64::new(0),
            tail_records: AtomicU64::new(0),
            journal_dropped: AtomicU64::new(0),
            durable_seq: AtomicU64::new(0),
            snap_ms: AtomicI64::new(0),
            write_enabled: AtomicBool::new(false),
        }
    }
}

impl PersistStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn format(&self) -> Format {
        Format::from_code(self.format.load(Ordering::Relaxed))
    }
    pub fn set_format(&self, f: Format) {
        self.format.store(f.code(), Ordering::Relaxed);
    }
    pub fn snap_seq(&self) -> u64 {
        self.snap_seq.load(Ordering::Relaxed)
    }
    pub fn set_snap_seq(&self, v: u64) {
        self.snap_seq.store(v, Ordering::Relaxed);
    }
    pub fn snap_bytes(&self) -> u64 {
        self.snap_bytes.load(Ordering::Relaxed)
    }
    pub fn set_snap_bytes(&self, v: u64) {
        self.snap_bytes.store(v, Ordering::Relaxed);
    }
    pub fn snap_entries(&self) -> u64 {
        self.snap_entries.load(Ordering::Relaxed)
    }
    pub fn set_snap_entries(&self, v: u64) {
        self.snap_entries.store(v, Ordering::Relaxed);
    }
    pub fn used_live(&self) -> u64 {
        self.used_live.load(Ordering::Relaxed)
    }
    pub fn set_used_live(&self, v: u64) {
        self.used_live.store(v, Ordering::Relaxed);
    }
    pub fn wal_bytes(&self) -> u64 {
        self.wal_bytes.load(Ordering::Relaxed)
    }
    pub fn set_wal_bytes(&self, v: u64) {
        self.wal_bytes.store(v, Ordering::Relaxed);
    }
    pub fn add_wal_bytes(&self, v: u64) {
        self.wal_bytes.fetch_add(v, Ordering::Relaxed);
    }
    pub fn wal_segments(&self) -> u64 {
        self.wal_segments.load(Ordering::Relaxed)
    }
    pub fn set_wal_segments(&self, v: u64) {
        self.wal_segments.store(v, Ordering::Relaxed);
    }
    pub fn last_commit_ms(&self) -> i64 {
        self.last_commit_ms.load(Ordering::Relaxed)
    }
    pub fn set_last_commit_ms(&self, v: i64) {
        self.last_commit_ms.store(v, Ordering::Relaxed);
    }
    pub fn manifest_valid(&self) -> bool {
        self.manifest_valid.load(Ordering::Relaxed)
    }
    pub fn set_manifest_valid(&self, v: bool) {
        self.manifest_valid.store(v, Ordering::Relaxed);
    }
    pub fn restore_source(&self) -> RestoreSource {
        RestoreSource::from_code(self.restore_source.load(Ordering::Relaxed))
    }
    pub fn set_restore_source(&self, v: RestoreSource) {
        self.restore_source.store(v.code(), Ordering::Relaxed);
    }
    pub fn tail_records(&self) -> u64 {
        self.tail_records.load(Ordering::Relaxed)
    }
    pub fn set_tail_records(&self, v: u64) {
        self.tail_records.store(v, Ordering::Relaxed);
    }
    pub fn journal_dropped(&self) -> u64 {
        self.journal_dropped.load(Ordering::Relaxed)
    }
    pub fn note_journal_dropped(&self, n: u64) {
        self.journal_dropped.fetch_add(n, Ordering::Relaxed);
    }
    pub fn durable_seq(&self) -> u64 {
        self.durable_seq.load(Ordering::Relaxed)
    }
    pub fn set_durable_seq(&self, v: u64) {
        self.durable_seq.store(v, Ordering::Relaxed);
    }
    pub fn snap_ms(&self) -> i64 {
        self.snap_ms.load(Ordering::Relaxed)
    }
    pub fn set_snap_ms(&self, v: i64) {
        self.snap_ms.store(v, Ordering::Relaxed);
    }
    pub fn write_enabled(&self) -> bool {
        self.write_enabled.load(Ordering::Relaxed)
    }
    pub fn set_write_enabled(&self, v: bool) {
        self.write_enabled.store(v, Ordering::Relaxed);
    }
}

// ---------------- 错误 ----------------

/// 格式层错误。**一律不 panic**：坏输入 → `Err`，调用方按 §7.4 回退。
#[derive(Debug, thiserror::Error)]
pub enum PersistError {
    #[error("IO 错误：{0}")]
    Io(#[from] std::io::Error),
    #[error("magic 不匹配（不是 {0}）")]
    BadMagic(&'static str),
    #[error("不支持的格式版本 {0}")]
    UnsupportedVersion(u16),
    #[error("校验和失败（{0}）")]
    Crc(&'static str),
    #[error("字段越界/非法（{0}）")]
    BadField(&'static str),
    #[error("文件长度不符（期望 {expect}，实际 {got}）")]
    BadLen { expect: u64, got: u64 },
    #[error("非法文件名（{0}）")]
    BadPath(&'static str),
    #[error("记录 seq 非严格递增（{0}）")]
    SeqOrder(&'static str),
}

pub type Result<T> = std::result::Result<T, PersistError>;

/// 校验 manifest/快照里的**相对文件名**（§4.2）：无 `/`、`\`、`..`、不以 `.` 开头。
pub fn is_safe_leaf(name: &str) -> bool {
    if name.is_empty() || name.len() > 255 {
        return false;
    }
    if name.starts_with('.') {
        return false;
    }
    !name.contains('/') && !name.contains('\\') && name != ".." && name != "."
}

/// 目录 `fsync`（best-effort）。EINVAL/EPERM 静默降级，但**不得跳过调用**（§6.4）。
///
/// **2.1.36（D 批）**：实现收敛到 [`ebpdns_fs::fsync_dir_best_effort`]（全树唯一一份）。
pub fn fsync_dir(dir: &std::path::Path) {
    ebpdns_fs::fsync_dir_best_effort(dir);
}

/// 原子写整块字节：`write(tmp) → fsync(tmp) → rename → fsync(dir)`。
///
/// tmp 名 = `<name>.<pid>.<单调序号>.tmp` —— **每代独立**，修掉 v1 的 D1
/// （固定 `*.json.tmp` + 无写者互斥时两个写者互踩）。
/// 失败时**不 rename**，目标文件保持原样；tmp 由启动清理回收。
///
/// **2.1.36（D 批）**：四步协议收敛到 [`ebpdns_fs::atomic_write_bytes_opts`]；
/// 本函数只固定"缓存 v2 的每代独立 tmp 名 + 失败清理"两条既有策略。
pub fn atomic_write_bytes(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let opts = ebpdns_fs::WriteOptions {
        tmp: ebpdns_fs::TmpName::Unique,
        create_parent: false,
        cleanup_on_error: true,
        preserve_mode: false,
    };
    ebpdns_fs::atomic_write_bytes_opts(path, bytes, &opts)
}
