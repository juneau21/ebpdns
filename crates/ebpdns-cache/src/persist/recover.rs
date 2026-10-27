//! **v2 恢复（`recover_v2`）** —— §7.2 的伪代码逐行落地。
//!
//! 可见集（唯一权威定义，§7.1）：
//!
//! ```text
//! Visible(M) = Snapshot(M.snap_path)
//!            ∪ { r ∈ Records(M.wal_paths[*]) | r 完整且 CRC 通过, r.seq > M.snapshot_seq }
//! ```
//!
//! * `M.seq` **不是**可见性门槛（它只是 manifest 写入时的 durable 水位）；
//! * `*.tmp` / 孤儿文件**从不读**；
//! * 尾部不完整 ⇒ `Tail`（忽略 + 截断），中段损坏 ⇒ 最后一段按尾部处理 + ERROR，
//!   非最后一段丢弃该段及其后所有段（保守前缀）。**任何情况下都不判撕裂。**

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

use super::manifest::Manifest;
use super::snapshot::SnapshotReader;
use super::wal::{WalErr, WalItem, WalOpenErr, WalReader, WalRec};
use super::{PersistError, RestoreSource};
use crate::util::resolve_restored_expiry;
use crate::{CacheEntry, CacheKey};

/// manifest 允许读取的最大字节数（防坏文件吃内存）。
const MANIFEST_READ_CAP: u64 = super::MANIFEST_MAX_BYTES + 1;

/// v2 恢复失败的两类结果（决定 §7.4 的回退方向）。
#[derive(Debug)]
pub enum RecoverError {
    /// manifest / 快照不可用 ⇒ 保留现场 + 尝试 `.v1.bak` → 空缓存 + 禁用 v2 写。
    Corrupt { what: &'static str, detail: String },
    /// `version > 2`：**不覆盖、不删除**，空缓存 + 禁用写（§9.2）。
    Unsupported(u16),
    /// 读失败（权限/IO）⇒ ERROR + 空缓存，**不覆盖**。
    Io(String),
}

impl std::fmt::Display for RecoverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecoverError::Corrupt { what, detail } => write!(f, "{what} 损坏：{detail}"),
            RecoverError::Unsupported(v) => write!(f, "不支持的缓存格式版本 {v}"),
            RecoverError::Io(e) => write!(f, "IO 错误：{e}"),
        }
    }
}

/// 恢复产出：条目 + 计数 + 现场（**回放已完成，TTL 策略已统一应用**）。
#[derive(Debug)]
pub struct RestorePlan {
    pub source: RestoreSource,
    pub snapshot_seq: u64,
    pub manifest_seq: u64,
    pub wal_bytes: u64,
    pub wal_files: u32,
    /// 下一个可用的 `seq`（= 所有已见 seq 的最大值 + 1）。
    pub next_seq: u64,
    /// 最终条目（`entry.seq` 已填；按 `seq` 升序，便于容量截断的确定性）。
    pub entries: Vec<(CacheKey, CacheEntry)>,
    /// `(expired, legacy, failed)` —— 与 v1 **逐字同口径**（§10.2）。
    pub drops: (u64, u64, u64),
    /// 尾部截断/缺失的记录或段数（**不**进 `drops`；只进日志/统计）。
    pub tail_records: u64,
    pub clean_shutdown: bool,
    pub last_commit_ms: i64,
    pub durable_seq: u64,
    /// 需要在追加前截断的段：`(相对文件名, valid_len)`。
    pub wal_truncate: Vec<(String, u64)>,
    // >>> PATCH242A P1-5 plan-gap BEGIN
    /// **2.1.42（P1-5）**：恢复时是否遇到"非最后一段不可读/中段损坏"。
    ///
    /// `true` ⇒ `wal_paths` 只含**实际读完**的前缀段；actor **不得**向旧段追加，
    /// 必须新建段（`base >= next_seq`）续写，否则每次重启都会重复丢这批记录。
    pub wal_gap: bool,
    // <<< PATCH242A P1-5 plan-gap END
    pub wal_paths: Vec<String>,
    pub wal_base_seq: Vec<u64>,
    pub snap_path: String,
    /// **2.1.46（REV247 B P2-11）**：u64，与 manifest v3 同口径。
    pub snap_bytes: u64,
    pub snap_entries: u32,
    pub snap_crc32c: u32,
    /// **2.1.34（D4）**：快照文件 mtime（epoch ms）。0 = 取不到（旧现场/异常）。
    pub snap_ms: i64,
}

fn io_err(e: std::io::Error) -> RecoverError {
    RecoverError::Io(e.to_string())
}

/// 读 manifest（上限 8 KiB + 1）。
fn read_manifest_bytes(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    let f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut buf = Vec::new();
    f.take(MANIFEST_READ_CAP).read_to_end(&mut buf)?;
    Ok(Some(buf))
}

/// 检测 `cache_file` 是否是 v1 JSON（前 8 KiB 里第一个非空白字节是 `[`）。
pub fn looks_like_v1_json(raw: &[u8]) -> bool {
    matches!(raw.iter().find(|b| !b.is_ascii_whitespace()), Some(b'['))
}

/// **v2 恢复**。`Ok(None)` = 该文件不是 v2（不存在 / v1 JSON）⇒ 调用方走 v1 路径。
pub fn recover_v2(
    dir: &Path,
    base: &str,
    persist_ttl: f64,
    now: f64,
    // >>> PATCH242A P1-4 writable BEGIN
    // **2.1.42（P1-4）**：是否持有跨进程写锁。`false`（flock 失败）时本函数
    // **只读**：绝不 `set_len`、绝不写/删/改名任何缓存文件，只返回可恢复前缀。
    writable: bool,
    // <<< PATCH242A P1-4 writable END
) -> Result<Option<RestorePlan>, RecoverError> {
    let raw = match read_manifest_bytes(&dir.join(base)) {
        Ok(Some(b)) => b,
        Ok(None) => return Ok(None),
        Err(e) => return Err(io_err(e)),
    };
    if raw.is_empty() || looks_like_v1_json(&raw) {
        return Ok(None);
    }
    let m = match Manifest::decode(&raw, base) {
        Ok(m) => m,
        Err(PersistError::UnsupportedVersion(v)) => {
            return Err(if v > super::manifest::VERSION {
                RecoverError::Unsupported(v)
            } else {
                RecoverError::Corrupt {
                    what: "manifest",
                    detail: format!("版本 {v} 无效（v1 没有 manifest）"),
                }
            })
        }
        Err(e) => {
            return Err(RecoverError::Corrupt {
                what: "manifest",
                detail: e.to_string(),
            })
        }
    };

    // ---- 1) 打开并校验快照（流式；不建 Value 树）----
    let snap_abs = dir.join(&m.snap_path);
    // **2.1.34（D4）**：快照年龄来自磁盘现场（rename 保留 mtime），用于
    // `cache.persist.snapshot_age_s` 与“按时间触发快照”的起点。
    let snap_ms = std::fs::metadata(&snap_abs)
        .and_then(|md| md.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let snap = match SnapshotReader::open(&snap_abs) {
        Ok(s) => s,
        Err(e) => {
            return Err(RecoverError::Corrupt {
                what: "snapshot",
                detail: format!(
                    "{}：{e}（manifest snap_bytes={} snap_crc32c={:#010x} snap_entries={}）",
                    m.snap_path, m.snap_bytes, m.snap_crc32c, m.snap_entries
                ),
            })
        }
    };
    if snap.file_len() != m.snap_bytes
        || snap.body_crc32c() != m.snap_crc32c
        || snap.entry_count() != m.snap_entries
    {
        return Err(RecoverError::Corrupt {
            what: "snapshot",
            detail: format!(
                "与 manifest 不符：文件 len={} crc={:#010x} entries={}；\
                 manifest 期望 len={} crc={:#010x} entries={}",
                snap.file_len(),
                snap.body_crc32c(),
                snap.entry_count(),
                m.snap_bytes,
                m.snap_crc32c,
                m.snap_entries
            ),
        });
    }

    // ---- 2) 快照 → state ----
    let mut state: HashMap<CacheKey, (CacheEntry, u64)> =
        HashMap::with_capacity((snap.entry_count() as usize).min(1 << 20));
    let mut max_seq = m.snapshot_seq.max(m.seq);
    // >>> PATCH242A P1-2 snapshot-skip BEGIN
    // **2.1.42（P1-2）**：单条记录坏 ⇒ 跳过 + 计数（`drops.failed`），其余条目照常
    // 恢复；只有框架级损坏才返回 `Corrupt`（→ 上层保留现场）。
    let mut failed_records = 0u64;
    let mut cb_failed = 0u64;
    let scan = snap.for_each(&mut |entry_seq, key, body| {
        match body.to_entry() {
            Ok(mut e) => {
                e.seq = entry_seq;
                max_seq = max_seq.max(entry_seq);
                state.insert(key, (e, entry_seq));
            }
            Err(_) => cb_failed = cb_failed.saturating_add(1),
        }
        Ok(())
    });
    match scan {
        Ok(stats) => {
            failed_records = failed_records
                .saturating_add(u64::from(stats.failed))
                .saturating_add(cb_failed);
            if stats.failed > 0 || cb_failed > 0 {
                tracing::warn!(
                    failed_records = stats.failed + cb_failed as u32,
                    ok_records = stats.ok,
                    snapshot = %m.snap_path,
                    "快照含坏记录：已逐条跳过并继续恢复（不再整份判 Corrupt）"
                );
            }
        }
        Err(e) => {
            return Err(RecoverError::Corrupt {
                what: "snapshot",
                detail: e.to_string(),
            });
        }
    }
    // <<< PATCH242A P1-2 snapshot-skip END

    // ---- 3) 回放 WAL（只收 seq > snapshot_seq，完整 + CRC）----
    let mut tail_records = 0u64;
    let mut wal_truncate: Vec<(String, u64)> = Vec::new();
    let mut wal_files_read = 0u32;
    let mut durable_seq = m.seq;
    // **2.1.34（D3）**：manifest 的 `committed_ms` 是**最近一次成功落盘**的时刻；
    // 旧实现从 0 起算、只认 WAL `COMMIT`，恢复后 `mtime_s=0`、`age_s=epoch` ⇒
    // 假“落盘失败”。这里以 manifest 为初值，再与 WAL `COMMIT` 取 max。
    let mut last_commit_ms = m.committed_ms.max(0);
    // **2.1.34（D1）**：WAL 记录先收集、再**按 seq 有序合并**（同 seq 去重）。
    // 旧实现在读取时按文件顺序直接 apply，一旦写侧出现过回退（并发入队）或轮转后
    // 低 seq 落进新段，就会“后写覆盖先写”。排序合并让结果与写入顺序无关。
    let mut wal_recs: Vec<(u64, WalRec)> = Vec::new();
    let mut saw_tail = false;
    // >>> PATCH242A P1-5 gap-state BEGIN
    // **2.1.42（P1-5）**：非最后一段不可读/中段损坏 ⇒ 只信任**已完整读完**的前缀段。
    // `wal_read_end` = 第一个不可信段的索引（之前的段可安全重放）。
    let mut wal_gap = false;
    let mut wal_read_end = m.wal_paths.len();
    // <<< PATCH242A P1-5 gap-state END
    for (i, wp) in m.wal_paths.iter().enumerate() {
        let is_last = i + 1 == m.wal_paths.len();
        let path = dir.join(wp);
        let mut r = match WalReader::open(&path, m.wal_base_seq[i]) {
            Ok(r) => r,
            Err(WalOpenErr::UnsupportedVersion(v)) => {
                return Err(RecoverError::Unsupported(v));
            }
            Err(e) => {
                let why = match e {
                    WalOpenErr::Io(e) => e.to_string(),
                    WalOpenErr::BadHeader(w) => w.to_string(),
                    WalOpenErr::UnsupportedVersion(v) => v.to_string(),
                };
                if is_last {
                    // 最后一段不可用 ⇒ 当作空段（丢 ≤ 一个周期），不判撕裂。
                    tracing::warn!(
                        wal = %wp,
                        error = %why,
                        "manifest 列出的最后一段 WAL 不可用：按空段恢复（**不判撕裂**）"
                    );
                    tail_records += 1;
                    saw_tail = true;
                    continue;
                }
                tracing::error!(
                    wal = %wp,
                    error = %why,
                    "manifest 列出的非最后一段 WAL 不可用：丢弃该段及其后所有段（保守前缀），从新段续写"
                );
                saw_tail = true;
                // >>> PATCH242A P1-5 open-gap BEGIN
                wal_gap = true;
                wal_read_end = i;
                // <<< PATCH242A P1-5 open-gap END
                break;
            }
        };
        wal_files_read += 1;
        loop {
            match r.next() {
                Ok(Some(WalItem::Rec(rec))) => {
                    let seq = rec.seq();
                    max_seq = max_seq.max(seq);
                    if seq <= m.snapshot_seq {
                        // 已在快照里（轮转后的旧段 / 幂等重放）；幂等跳过。
                        continue;
                    }
                    if let WalRec::Commit {
                        seq, committed_ms, ..
                    } = &rec
                    {
                        durable_seq = durable_seq.max(*seq);
                        last_commit_ms = last_commit_ms.max(*committed_ms);
                    } else {
                        wal_recs.push((seq, rec));
                    }
                }
                Ok(Some(WalItem::BadContent)) => {
                    // 框架完好但内容不可用 ⇒ 计 failed 并继续（不中断）。
                    failed_records += 1;
                }
                Ok(None) => break,
                Err(WalErr::Tail { valid_len, .. }) => {
                    tail_records += 1;
                    saw_tail = true;
                    // >>> PATCH242A P1-5 tail-branch BEGIN
                    if is_last {
                        wal_truncate.push((wp.clone(), valid_len));
                    } else {
                        // 非最后一段出现半条记录：后面还有段 ⇒ 不能只截这一段了事，
                        // 标记 gap，由 actor 从新段续写。
                        wal_gap = true;
                        wal_read_end = i;
                    }
                    // <<< PATCH242A P1-5 tail-branch END
                    break;
                }
                Err(WalErr::Corrupt { off, why }) => {
                    if is_last {
                        tracing::error!(
                            wal = %wp,
                            off,
                            why,
                            "WAL 中段 CRC/结构不匹配：最后一段按**尾部截断**处理（保守，不阻断启动）"
                        );
                        tail_records += 1;
                        saw_tail = true;
                        wal_truncate.push((wp.clone(), r.valid_len()));
                        break;
                    }
                    tracing::error!(
                        wal = %wp,
                        off,
                        why,
                        "非最后一段 WAL 中段损坏：丢弃该段及其后所有段（保守前缀），从新段续写"
                    );
                    saw_tail = true;
                    // >>> PATCH242A P1-5 corrupt-gap BEGIN
                    wal_gap = true;
                    wal_read_end = i;
                    // <<< PATCH242A P1-5 corrupt-gap END
                    break;
                }
                Err(WalErr::Io(e)) => {
                    tracing::error!(wal = %wp, error = %e, "WAL 读取 IO 错误：按尾部截断处理");
                    tail_records += 1;
                    saw_tail = true;
                    // >>> PATCH242A P1-5 io-gap BEGIN
                    if is_last {
                        wal_truncate.push((wp.clone(), r.valid_len()));
                    } else {
                        wal_gap = true;
                        wal_read_end = i;
                    }
                    // <<< PATCH242A P1-5 io-gap END
                    break;
                }
            }
        }
        if saw_tail && !is_last {
            break;
        }
    }

    // ---- 3b) **按 seq 有序合并**（D1：非单调/重复记录不再放大成整段截断）----
    //
    // 排序是**稳定**的：同一 seq 的重复记录保持文件顺序，去重时只应用一次；
    // 不同 key 之间没有顺序依赖，但 CLEAR/EVICT 必须在其 seq 之后应用 —— 排序保证这一点。
    wal_recs.sort_by_key(|(seq, _)| *seq);
    let mut applied_seq: Option<u64> = None;
    for (seq, rec) in wal_recs {
        if applied_seq == Some(seq) {
            continue; // 同一条记录重放（跨段/轮转竞态）⇒ 幂等
        }
        applied_seq = Some(seq);
        match rec {
            WalRec::Put { seq, body } => match body.to_entry() {
                Ok(mut e) => {
                    e.seq = seq;
                    state.insert(body.key, (e, seq));
                }
                Err(_) => failed_records += 1,
            },
            WalRec::Evict { key, .. } => {
                state.remove(&key);
            }
            WalRec::Clear { .. } => state.clear(),
            WalRec::Commit { .. } => {}
        }
    }
    if last_commit_ms == 0 {
        // 老 manifest（`committed_ms=0`）兜底：用快照文件 mtime，避免 `mtime_s=0`。
        last_commit_ms = snap_ms;
    }

    // 物理截断（best-effort）：下次追加绝不接在半条后面。
    // >>> PATCH242A P1-4 no-truncate-if-readonly BEGIN
    // **2.1.42（P1-4）**：只有**持有跨进程写锁**的实例才允许 `set_len`。
    // 未拿到 flock 的"只读"实例若截断 WAL，会把正在写的主实例打出零洞 ⇒
    // 主实例后续记录在下次恢复时整段被判尾/损坏（静默丢数据）。
    if !writable {
        if !wal_truncate.is_empty() {
            tracing::warn!(
                segments = wal_truncate.len(),
                "只读恢复（未取得写锁）：跳过 WAL 物理截断，保持现场不变（不写任何缓存文件）"
            );
            wal_truncate.clear();
        }
    } else {
        for (wp, valid) in &wal_truncate {
            let p = dir.join(wp);
            if let Ok(f) = std::fs::OpenOptions::new().write(true).open(&p) {
                if f.set_len(*valid).is_ok() {
                    let _ = f.sync_all();
                }
            }
        }
    }
    // <<< PATCH242A P1-4 no-truncate-if-readonly END

    // ---- 4) 统一 TTL 策略（与 v1 同一个函数，§7.5）----
    let pt = crate::util::safe_float(persist_ttl, 0.0).max(0.0);
    let (expired, legacy) = apply_restore_policy(&mut state, now, pt);

    // ---- 5) 一次性转成恢复条目（按 seq 升序，保证容量截断确定性）----
    let mut entries: Vec<(CacheKey, CacheEntry)> = state
        .into_iter()
        .map(|(k, (mut e, seq))| {
            e.seq = seq;
            (k, e)
        })
        .collect();
    entries.sort_by(|a, b| {
        a.1.seq
            .cmp(&b.1.seq)
            .then_with(|| a.0.domain.cmp(&b.0.domain))
            .then_with(|| a.0.qtype.cmp(&b.0.qtype))
            .then_with(|| a.0.group.cmp(&b.0.group))
    });

    let source = if m.wal_paths.is_empty() {
        RestoreSource::V2Snapshot
    } else if saw_tail {
        RestoreSource::WalTruncated
    } else {
        RestoreSource::V2SnapshotWal
    };

    // >>> PATCH242A P1-5 plan-paths BEGIN
    // **2.1.42（P1-5）**：gap 时 manifest 只能引用**实际读完**的前缀段；后续段
    // 已不可信，actor 必须新建段续写（否则每次重启都从坏段 break、丢掉新段记录）。
    //
    // 新段 `base` 还必须**大于 manifest 里所有段 base**，否则会与未读段同名
    // （`create` 截断同名文件）⇒ 复用 `max(base)+1`。
    let (plan_wal_paths, plan_wal_base_seq, plan_next_seq) = if wal_gap {
        let next = max_seq
            .saturating_add(1)
            .max(
                m.wal_base_seq
                    .iter()
                    .copied()
                    .max()
                    .unwrap_or(0)
                    .saturating_add(1),
            )
            .max(1);
        tracing::warn!(
            unread_segments = m.wal_paths.len().saturating_sub(wal_read_end),
            next_seq = next,
            "WAL 非最后一段损坏：只保留已读完的前缀段，后续写入必须使用新段"
        );
        (
            m.wal_paths[..wal_read_end.min(m.wal_paths.len())].to_vec(),
            m.wal_base_seq[..wal_read_end.min(m.wal_base_seq.len())].to_vec(),
            next,
        )
    } else {
        (
            m.wal_paths.clone(),
            m.wal_base_seq.clone(),
            max_seq.saturating_add(1).max(1),
        )
    };
    // <<< PATCH242A P1-5 plan-paths END

    Ok(Some(RestorePlan {
        source,
        snapshot_seq: m.snapshot_seq,
        manifest_seq: m.seq,
        wal_bytes: m.wal_bytes,
        wal_files: wal_files_read,
        next_seq: plan_next_seq,
        entries,
        drops: (expired, legacy, failed_records),
        tail_records,
        clean_shutdown: m.clean_shutdown(),
        last_commit_ms,
        durable_seq,
        wal_truncate,
        // >>> PATCH242A P1-5 plan-fields BEGIN
        wal_gap,
        wal_paths: plan_wal_paths,
        wal_base_seq: plan_wal_base_seq,
        // <<< PATCH242A P1-5 plan-fields END
        snap_path: m.snap_path.clone(),
        snap_bytes: m.snap_bytes,
        snap_entries: m.snap_entries,
        snap_crc32c: m.snap_crc32c,
        snap_ms,
    }))
}

/// **唯一**的 TTL 决策（三条策略 + v1 迁移 + v2 回放共用）。
///
/// `persist_ttl` 三段逐字不变（§7.5）：
/// * `0`（含 0.0/负数/NaN/±inf 经 `safe_float`）⇒ 严格绝对到期：`abs <= now` 丢弃；
/// * 有限 `> 0` ⇒ `now + pt` 复活（**不看**原到期）；
/// * “无限”（大有限值）⇒ 同一分支，`now + pt` ≈ 永不 expired；溢出由 `i64` 毫秒**饱和**兜底
///   （§9.6 K2：v1 的 `inf → null → legacy 丢弃` 是缺陷，v2 不重演）。
///
/// 返回 `(expired, legacy)`；`legacy` 恒 0（v2 格式不可能产生旧格式记录）。
pub fn apply_restore_policy(
    state: &mut HashMap<CacheKey, (CacheEntry, u64)>,
    now: f64,
    pt: f64,
) -> (u64, u64) {
    if pt > 0.0 {
        // 统一恢复 TTL：已过期也复活（opt-in，README 已标注风险）。
        for (e, _) in state.values_mut() {
            e.expires_at = now + pt;
            e.ttl = pt;
        }
        return (0, 0);
    }
    let mut expired = 0u64;
    state.retain(
        |_, (e, _)| match resolve_restored_expiry(e.expires_at, now, pt) {
            Some(abs) => {
                e.expires_at = abs;
                e.ttl = (abs - now).max(0.0);
                true
            }
            None => {
                expired += 1;
                false
            }
        },
    );
    (expired, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persist::entry_codec::EntryBody;
    use crate::persist::manifest::{FLAG_CLEAN_SHUTDOWN, FLAG_MIGRATED_FROM_V1};
    use crate::persist::snapshot::SnapshotWriter;
    use crate::persist::wal::{encode_clear, encode_commit, encode_evict, encode_put, WalWriter};
    use crate::persist::Manifest;
    use crate::CacheAnswer;

    const BASE: &str = "ebpdns-cache.json";
    const NOW: f64 = 1_700_000_000.0;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "ebpdns-rec-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn ent(name: &str, exp: f64) -> (CacheKey, CacheEntry) {
        let k = CacheKey::new(name, "A");
        let mut e = CacheEntry::new(name, "A", exp - NOW, NOW);
        e.expires_at = exp;
        e.answers = vec![CacheAnswer {
            value: "1.2.3.4".into(),
            ttl: exp - NOW,
            rtype: 1,
            name: None,
        }];
        e.seq = 0;
        (k, e)
    }

    /// 造一套完整 v2 现场：快照 + 一个 WAL 段 + manifest。
    struct Fixture {
        dir: std::path::PathBuf,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            Self { dir: tmpdir(tag) }
        }

        /// `snap_entries` 写快照；`wal` 是一批已编码记录；`wal_base_seq` 段基。
        fn build(
            &self,
            snapshot_seq: u64,
            snap: &[(u64, CacheKey, CacheEntry)],
            wal_base_seq: u64,
            wal: &[Vec<u8>],
            flags: u16,
        ) -> Manifest {
            let snap_name = format!("{BASE}.snap.{snapshot_seq}");
            let tmp = self.dir.join(format!("{snap_name}.tmp"));
            let mut w = SnapshotWriter::create(&tmp, snapshot_seq, 1_700_000_000_000).unwrap();
            for (eseq, k, e) in snap {
                let b = EntryBody::from_entry(k, e).unwrap();
                w.push(*eseq, &b).unwrap();
            }
            let meta = w.finish().unwrap();
            std::fs::rename(&tmp, self.dir.join(&snap_name)).unwrap();

            let wal_name = format!("{BASE}.wal.{wal_base_seq}");
            let mut ww = WalWriter::create(&self.dir.join(&wal_name), wal_base_seq, 1).unwrap();
            let mut n = 0u64;
            let mut bytes = 0u64;
            for r in wal {
                ww.append_bytes(r).unwrap();
                n += 1;
                bytes += r.len() as u64;
            }
            ww.sync_data().unwrap();
            let wal_total = ww.bytes();
            drop(ww);

            let m = Manifest {
                flags,
                seq: snapshot_seq,
                snapshot_seq,
                committed_ms: 1_700_000_000_000,
                snap_bytes: meta.file_len,
                snap_crc32c: meta.body_crc32c,
                snap_entries: meta.entry_count,
                snap_path: snap_name,
                wal_paths: if wal_total > 32 {
                    vec![wal_name]
                } else {
                    vec![]
                },
                wal_base_seq: if wal_total > 32 {
                    vec![wal_base_seq]
                } else {
                    vec![]
                },
                wal_bytes: wal_total.saturating_sub(32),
            };
            let _ = n;
            let _ = bytes;
            super::super::atomic_write_bytes(&self.dir.join(BASE), &m.encode().unwrap()).unwrap();
            m
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn empty_dir_returns_none() {
        let f = Fixture::new("none");
        assert!(matches!(recover_v2(&f.dir, BASE, 0.0, NOW, true), Ok(None)));
    }

    #[test]
    fn v1_json_returns_none() {
        let f = Fixture::new("v1");
        std::fs::write(f.dir.join(BASE), b"[\n  {\"key\": [\"a\",\"A\"]}\n]").unwrap();
        assert!(matches!(recover_v2(&f.dir, BASE, 0.0, NOW, true), Ok(None)));
    }

    #[test]
    fn snapshot_only_roundtrip() {
        let f = Fixture::new("snap");
        let (k1, e1) = ent("a.test", NOW + 100.0);
        let (k2, e2) = ent("b.test", NOW + 200.0);
        f.build(
            5,
            &[(1, k1.clone(), e1.clone()), (2, k2.clone(), e2.clone())],
            6,
            &[],
            FLAG_CLEAN_SHUTDOWN,
        );
        let p = recover_v2(&f.dir, BASE, 0.0, NOW, true).unwrap().unwrap();
        assert_eq!(p.source, RestoreSource::V2Snapshot);
        assert_eq!(p.snapshot_seq, 5);
        assert_eq!(p.entries.len(), 2);
        assert!(p.clean_shutdown);
        assert_eq!(p.drops, (0, 0, 0));
        assert_eq!(p.next_seq, 6);
        let m: HashMap<_, _> = p.entries.into_iter().collect();
        assert_eq!(m[&k1].answers[0].value, "1.2.3.4");
    }

    #[test]
    fn wal_replay_put_evict_clear() {
        let f = Fixture::new("wal");
        let (k1, e1) = ent("a.test", NOW + 100.0);
        let (k2, e2) = ent("b.test", NOW + 100.0);
        let (k3, e3) = ent("c.test", NOW + 100.0);
        let b2 = EntryBody::from_entry(&k2, &e2).unwrap();
        let b3 = EntryBody::from_entry(&k3, &e3).unwrap();
        let wal = vec![
            encode_evict(3, &k1, 1).unwrap(), // 逐出 a
            encode_put(4, &k2, &b2).unwrap(), // 插入 b（覆盖快照值）
            encode_put(5, &k3, &b3).unwrap(), // 插入 c
            encode_commit(5, 1, 3, 100),      // COMMIT（不是可见性门槛）
        ];
        f.build(2, &[(1, k1.clone(), e1)], 3, &wal, FLAG_CLEAN_SHUTDOWN);
        let p = recover_v2(&f.dir, BASE, 0.0, NOW, true).unwrap().unwrap();
        assert_eq!(p.source, RestoreSource::V2SnapshotWal);
        assert_eq!(p.next_seq, 6);
        assert_eq!(p.entries.len(), 2);
        assert_eq!(p.drops.2, 0);
        let keys: Vec<String> = p.entries.iter().map(|(k, _)| k.domain.clone()).collect();
        assert!(!keys.contains(&"a.test".to_string()));
        assert!(keys.contains(&"b.test".to_string()));
        assert!(keys.contains(&"c.test".to_string()));
    }

    /// **2.1.34（D1/D3）**：WAL 里 seq 非单调 + 重复时，恢复必须**按 seq 有序合并**
    /// 并去重；`seq` 回退不得计入 `failed` / 尾部截断。`last_commit_ms` 必须取
    /// manifest 的 `committed_ms`（旧实现只认 WAL `COMMIT`，恢复后 `mtime_s=0`）。
    #[test]
    fn wal_replay_is_seq_ordered_and_idempotent() {
        let f = Fixture::new("order");
        let (k1, e1) = ent("a.test", NOW + 100.0);
        let (k2, e2) = ent("b.test", NOW + 100.0);
        let mut e2b = e2.clone();
        e2b.answers[0].value = "5.6.7.8".to_string();
        let b_old = EntryBody::from_entry(&k2, &e2).unwrap();
        let b_new = EntryBody::from_entry(&k2, &e2b).unwrap();
        let b1 = EntryBody::from_entry(&k1, &e1).unwrap();
        let wal = vec![
            encode_put(9, &k2, &b_new).unwrap(), // 新值（物理在前）
            encode_put(7, &k2, &b_old).unwrap(), // 旧值回退（旧实现判“中段损坏”）
            encode_put(9, &k2, &b_new).unwrap(), // 同 seq 重复（幂等）
            encode_put(8, &k1, &b1).unwrap(),
            encode_commit(9, 1, 3, 100),
        ];
        f.build(5, &[], 6, &wal, 0);
        let p = recover_v2(&f.dir, BASE, 0.0, NOW, true).unwrap().unwrap();
        assert_eq!(p.drops.2, 0, "seq 回退/重复不得计入 failed");
        assert_eq!(p.tail_records, 0, "seq 回退不得判尾部截断");
        assert_eq!(p.source, RestoreSource::V2SnapshotWal);
        let m: HashMap<_, _> = p.entries.into_iter().collect();
        assert_eq!(
            m[&k2].answers[0].value, "5.6.7.8",
            "最终值必须来自最大 seq（有序合并，而非文件顺序）"
        );
        assert_eq!(m[&k1].answers[0].value, "1.2.3.4");
        assert_eq!(
            p.last_commit_ms, 1_700_000_000_000,
            "manifest.committed_ms 必须作为恢复后的落盘时刻（D3）"
        );
        assert_eq!(p.next_seq, 10);
    }

    #[test]
    fn wal_clear_wipes_snapshot_entries() {
        let f = Fixture::new("clear");
        let (k1, e1) = ent("a.test", NOW + 100.0);
        let wal = vec![encode_clear(3, 1)];
        f.build(2, &[(1, k1, e1)], 3, &wal, 0);
        let p = recover_v2(&f.dir, BASE, 0.0, NOW, true).unwrap().unwrap();
        assert!(p.entries.is_empty());
    }

    #[test]
    fn truncated_wal_tail_is_ignored_and_not_tear() {
        let f = Fixture::new("tail");
        let (k1, e1) = ent("a.test", NOW + 100.0);
        let (k2, e2) = ent("b.test", NOW + 100.0);
        let b2 = EntryBody::from_entry(&k2, &e2).unwrap();
        let rec = encode_put(3, &k2, &b2).unwrap();
        f.build(2, &[(1, k1, e1)], 3, &[], 0);
        // 手工追加“半条记录”（只写 5 字节）。
        let wal_path = f.dir.join(format!("{BASE}.wal.3"));
        use std::io::Write;
        let mut fh = std::fs::OpenOptions::new()
            .append(true)
            .open(&wal_path)
            .unwrap();
        fh.write_all(&rec[..5]).unwrap();
        drop(fh);
        // 让 manifest 引用该段（重建 manifest，保留原快照）。
        let raw = std::fs::read(f.dir.join(BASE)).unwrap();
        let mut m = Manifest::decode(&raw, BASE).unwrap();
        m.wal_paths = vec![format!("{BASE}.wal.3")];
        m.wal_base_seq = vec![3];
        m.wal_bytes = std::fs::metadata(&wal_path).unwrap().len() - 32;
        super::super::atomic_write_bytes(&f.dir.join(BASE), &m.encode().unwrap()).unwrap();

        let p = recover_v2(&f.dir, BASE, 0.0, NOW, true).unwrap().unwrap();
        assert_eq!(p.source, RestoreSource::WalTruncated);
        assert_eq!(p.drops.2, 0, "尾部截断**不得**计入 failed");
        assert!(p.tail_records >= 1);
        assert_eq!(p.entries.len(), 1);
        // 物理截断已生效（半条被裁掉）。
        assert_eq!(
            std::fs::metadata(&wal_path).unwrap().len(),
            super::super::wal::HEADER_LEN as u64
        );
    }

    #[test]
    fn snapshot_corruption_is_corrupt_error() {
        let f = Fixture::new("corrupt");
        let (k1, e1) = ent("a.test", NOW + 100.0);
        f.build(2, &[(1, k1, e1)], 3, &[], 0);
        // 破坏快照内容。
        let sp = f.dir.join(format!("{BASE}.snap.2"));
        let mut raw = std::fs::read(&sp).unwrap();
        let n = raw.len();
        raw[n - 20] ^= 0xFF;
        std::fs::write(&sp, &raw).unwrap();
        match recover_v2(&f.dir, BASE, 0.0, NOW, true) {
            Err(RecoverError::Corrupt { what, .. }) => assert_eq!(what, "snapshot"),
            other => panic!("期望 snapshot Corrupt，得到 {other:?}"),
        }
    }

    #[test]
    fn manifest_corruption_is_corrupt_error() {
        let f = Fixture::new("mcorrupt");
        let (k1, e1) = ent("a.test", NOW + 100.0);
        f.build(2, &[(1, k1, e1)], 3, &[], 0);
        let p = f.dir.join(BASE);
        let mut raw = std::fs::read(&p).unwrap();
        raw[10] ^= 0xFF;
        std::fs::write(&p, &raw).unwrap();
        match recover_v2(&f.dir, BASE, 0.0, NOW, true) {
            Err(RecoverError::Corrupt { what, .. }) => assert_eq!(what, "manifest"),
            other => panic!("期望 manifest Corrupt，得到 {other:?}"),
        }
    }

    #[test]
    fn unsupported_future_version() {
        let f = Fixture::new("future");
        let (k1, e1) = ent("a.test", NOW + 100.0);
        f.build(2, &[(1, k1, e1)], 3, &[], 0);
        let p = f.dir.join(BASE);
        let mut raw = std::fs::read(&p).unwrap();
        raw[4..6].copy_from_slice(&9u16.to_le_bytes());
        let n = raw.len();
        let crc = super::super::crc32c(&raw[..n - 4]);
        raw[n - 4..].copy_from_slice(&crc.to_le_bytes());
        std::fs::write(&p, &raw).unwrap();
        match recover_v2(&f.dir, BASE, 0.0, NOW, true) {
            Err(RecoverError::Unsupported(9)) => {}
            other => panic!("期望 Unsupported(9)，得到 {other:?}"),
        }
    }

    // ---- persist_ttl 三段等价（§7.5）----

    #[test]
    fn ttl_zero_drops_expired_keeps_absolute() {
        let f = Fixture::new("pt0");
        let (k1, e1) = ent("a.test", NOW + 100.0);
        let (k2, e2) = ent("b.test", NOW - 1.0); // 已过期
        f.build(2, &[(1, k1.clone(), e1), (2, k2, e2)], 3, &[], 0);
        let p = recover_v2(&f.dir, BASE, 0.0, NOW, true).unwrap().unwrap();
        assert_eq!(p.drops.0, 1, "过期条目必须计入 expired");
        assert_eq!(p.drops.1, 0, "v2 不应产生 legacy");
        assert_eq!(p.entries.len(), 1);
        // 绝对到期时间严格保留（不是 now + remaining）。
        let (_, e) = &p.entries[0];
        assert!((e.expires_at - (NOW + 100.0)).abs() < 0.002);
        assert!((e.ttl - 100.0).abs() < 0.002);
    }

    #[test]
    fn ttl_finite_revives_even_expired() {
        let f = Fixture::new("pt3600");
        let (k1, e1) = ent("a.test", NOW + 100.0);
        let (k2, e2) = ent("b.test", NOW - 5000.0); // 已过期
        f.build(2, &[(1, k1, e1), (2, k2, e2)], 3, &[], 0);
        let p = recover_v2(&f.dir, BASE, 3600.0, NOW, true)
            .unwrap()
            .unwrap();
        assert_eq!(p.drops.0, 0, "pt>0 不丢过期条目");
        assert_eq!(p.entries.len(), 2);
        for (_, e) in &p.entries {
            assert!((e.expires_at - (NOW + 3600.0)).abs() < 0.002);
            assert!((e.ttl - 3600.0).abs() < 0.002);
        }
    }

    #[test]
    fn ttl_huge_finite_saturates_not_dropped() {
        // K2：1e12 秒（大有限值）⇒ now + pt 巨大但有限；writes i64 ms 饱和路径不丢。
        let f = Fixture::new("ptinf");
        let (k1, e1) = ent("a.test", NOW + 100.0);
        f.build(2, &[(1, k1, e1)], 3, &[], 0);
        let p = recover_v2(&f.dir, BASE, 1e12, NOW, true).unwrap().unwrap();
        assert_eq!(p.drops.0, 0);
        assert_eq!(p.entries.len(), 1);
        assert!(p.entries[0].1.expires_at > NOW + 1e11);
        // 极端：now + f64::MAX 溢出 ⇒ 饱和而非 null / 丢弃。
        let p2 = recover_v2(&f.dir, BASE, f64::MAX, NOW, true)
            .unwrap()
            .unwrap();
        assert_eq!(p2.entries.len(), 1);
        assert!(p2.entries[0].1.expires_at.is_finite());
        assert!(p2.entries[0].1.expires_at > 1e15);
    }

    #[test]
    fn policy_is_shared_with_v1_util() {
        // 单一实现：`resolve_restored_expiry` 三段。
        assert_eq!(resolve_restored_expiry(200.0, 100.0, 0.0), Some(200.0));
        assert_eq!(resolve_restored_expiry(10.0, 100.0, 0.0), None);
        assert_eq!(resolve_restored_expiry(10.0, 100.0, 60.0), Some(160.0));
        assert_eq!(resolve_restored_expiry(f64::NAN, 100.0, 0.0), None);
    }

    #[test]
    fn migration_flags_roundtrip() {
        let f = Fixture::new("flags");
        let (k1, e1) = ent("a.test", NOW + 100.0);
        f.build(
            1,
            &[(0, k1, e1)],
            2,
            &[],
            FLAG_MIGRATED_FROM_V1 | FLAG_CLEAN_SHUTDOWN,
        );
        let p = recover_v2(&f.dir, BASE, 0.0, NOW, true).unwrap().unwrap();
        assert!(p.clean_shutdown);
        assert_eq!(p.entries.len(), 1);
    }

    // >>> PATCH242A P1-2/P1-4/P1-5 recovery-tests BEGIN
    /// **2.1.42（P1-2）**：快照里**单条记录**坏（payload 1 bit）⇒ 跳过该条、
    /// 其余条目照常恢复，`drops.failed == 1`；不再整份 Corrupt。
    #[test]
    fn single_bad_snapshot_record_is_skipped() {
        let f = Fixture::new("snap1bad");
        let (k1, e1) = ent("a.test", NOW + 100.0);
        let (k2, e2) = ent("b.test", NOW + 200.0);
        f.build(5, &[(1, k1, e1), (2, k2, e2)], 6, &[], FLAG_CLEAN_SHUTDOWN);
        let sp = f.dir.join(format!("{BASE}.snap.5"));
        let mut raw = std::fs::read(&sp).unwrap();
        // 第二条记录的 payload 起始 = HEADER + (第一条: 8 + plen1 + 4) + 8。
        let off = crate::persist::snapshot::HEADER_LEN;
        let plen1 =
            u32::from_le_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]]) as usize;
        let second = off + 8 + plen1 + 4;
        raw[second + 8 + 2] ^= 0x01; // 破坏 body（不碰长度框架）
        std::fs::write(&sp, &raw).unwrap();

        let p = recover_v2(&f.dir, BASE, 0.0, NOW, true).unwrap().unwrap();
        assert_eq!(p.entries.len(), 1, "好记录必须保留");
        assert_eq!(p.drops.2, 1, "坏记录必须计入 drops.failed");
    }

    /// **2.1.42（P1-4）**：未取得写锁（`writable=false`）的只读恢复**绝不**截 WAL；
    /// 只有写者才允许 `set_len` 去掉半条尾记录。
    #[test]
    fn readonly_recovery_never_truncates_wal() {
        let f = Fixture::new("ro");
        let (k1, e1) = ent("ro.test", NOW + 100.0);
        let body = EntryBody::from_entry(&k1, &e1).unwrap();
        let rec = encode_put(2, &k1, &body).unwrap();
        f.build(1, &[(1, k1.clone(), e1)], 2, &[rec], FLAG_CLEAN_SHUTDOWN);
        let wp = f.dir.join(format!("{BASE}.wal.2"));
        let before = std::fs::metadata(&wp).unwrap().len();
        // 追加半条记录（< REC_HDR_LEN）。
        let mut fh = std::fs::OpenOptions::new().append(true).open(&wp).unwrap();
        use std::io::Write as _;
        fh.write_all(&[1, 2, 3]).unwrap();
        drop(fh);
        let after_append = std::fs::metadata(&wp).unwrap().len();
        assert!(after_append > before);

        // 只读：文件字节数必须**原样不动**，且 plan 不携带截断指令。
        let p = recover_v2(&f.dir, BASE, 0.0, NOW, false).unwrap().unwrap();
        assert!(p.wal_truncate.is_empty(), "只读恢复不得计划截断");
        assert_eq!(
            std::fs::metadata(&wp).unwrap().len(),
            after_append,
            "只读恢复不得 set_len"
        );

        // 写者：允许截到上一条完整记录末尾。
        let p = recover_v2(&f.dir, BASE, 0.0, NOW, true).unwrap().unwrap();
        assert!(!p.wal_truncate.is_empty());
        assert_eq!(std::fs::metadata(&wp).unwrap().len(), before);
    }

    /// **2.1.42（P1-5）**：manifest 引用 [wal.11, wal.21]，wal.11 段头损坏 ⇒
    /// 只保留已读前缀（空），`wal_gap=true`，`next_seq` 必须大于所有旧段 base
    /// （避免新段与未读段同名）。
    #[test]
    fn non_last_wal_corruption_reports_gap_and_new_segment_base() {
        let f = Fixture::new("gap");
        f.build(10, &[], 11, &[], FLAG_CLEAN_SHUTDOWN);
        let (k1, e1) = ent("gap.test", NOW + 100.0);
        let body = EntryBody::from_entry(&k1, &e1).unwrap();
        for base in [11u64, 21] {
            let name = format!("{BASE}.wal.{base}");
            let mut w = WalWriter::create(&f.dir.join(&name), base, 1).unwrap();
            w.append_bytes(&encode_put(base + 1, &k1, &body).unwrap())
                .unwrap();
            w.sync_data().unwrap();
        }
        // 手工把 manifest 改成两段。
        let p = f.dir.join(BASE);
        let raw = std::fs::read(&p).unwrap();
        let mut m = Manifest::decode(&raw, BASE).unwrap();
        m.wal_paths = vec![format!("{BASE}.wal.11"), format!("{BASE}.wal.21")];
        m.wal_base_seq = vec![11, 21];
        super::super::atomic_write_bytes(&p, &m.encode().unwrap()).unwrap();
        // 破坏第一段段头（magic）。
        let w11 = f.dir.join(format!("{BASE}.wal.11"));
        let mut b = std::fs::read(&w11).unwrap();
        b[0] ^= 0xFF;
        std::fs::write(&w11, &b).unwrap();

        let plan = recover_v2(&f.dir, BASE, 0.0, NOW, true).unwrap().unwrap();
        assert!(plan.wal_gap, "非最后一段损坏必须标记 gap");
        assert!(plan.wal_paths.is_empty(), "不可信段不得进入 manifest");
        assert!(
            plan.next_seq > 21,
            "新段 base 必须大于所有旧段 base（实际 {}）",
            plan.next_seq
        );
    }
    // <<< PATCH242A P1-2/P1-4/P1-5 recovery-tests END
}
