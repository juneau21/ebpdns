//! **2.1.29（缓存持久化 v2）：`CachePersistActor` + 启动序列**（设计文档 M19–M25 / N9）。
//!
//! 职责边界（严格）：
//! * **唯一的 WAL 与 manifest 写者**（§6.4）—— 单线程 actor，所有写命令从命令队列进入；
//! * 快照 `.tmp` 由 **B 阶段独立线程**写（写自己的 tmp，rename 只由 actor 做）；
//! * **数据面从不等待磁盘**：`put/delete/clear` 只做一次有界 `try_send`；
//! * 缓存**不是** `state_store` 的 part：本文件**不**调用 `StateStore::commit`，
//!   也**不**碰 `commit.json` / `history/` / `FAILED_COMMITS`（§9.4）。
//!
//! 可观测承诺（§10）：
//! * `/api/status.cache.persist` 的 9 个旧键语义不变，只**追加** `format/snap_seq/
//!   wal_bytes/restore_source`；
//! * `restore_drops` 三键口径不变（尾部截断**不**计 `failed`）；
//! * `state_persist.revision` **不因缓存落盘推进**（本文没有任何 revision 路径）。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::time::Duration;

use ebpdns_cache::persist::manifest::{FLAG_CLEAN_SHUTDOWN, FLAG_MIGRATED_FROM_V1};
use ebpdns_cache::persist::recover::recover_v2;
use ebpdns_cache::persist::snapshot::SnapshotWriter;
use ebpdns_cache::persist::wal::{self, WalWriter};
use ebpdns_cache::persist::{
    atomic_write_bytes, compact_threshold, fsync_dir, wal_hard_max, CacheJournal, EntryBody, Event,
    Format, Manifest, PersistStats, RecoverError, RestorePlan, RestoreSource, SnapshotMeta,
    SnapshotReader, WalItem, WalReader, WalRec, COMPACT_CHANGE_PERMILLE, COMPACT_MIN_BYTES,
    COMPACT_MIN_INTERVAL_S, MANIFEST_MAX_BYTES, MAX_RECORD_BYTES, WAL_BATCH_MAX_BYTES,
    WAL_BATCH_MAX_EVENTS, WAL_FSYNC_MS,
};
use ebpdns_cache::{CacheEntry, CacheKey, DnsCache, SwappableCache};
use ebpdns_resolver::Resolver;

/// 缓存持久化的运行模式。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// `cache_persist=false`：不读不写。
    Disabled,
    /// **紧急回滚**：`EBPDNS_CACHE_FORMAT=v1`（或迁移失败/锁冲突/未来版本）⇒ 只走 v1 路径。
    V1,
    /// 快照 + WAL。
    V2,
}

/// 配置投影（**不新增配置键**；全部来自既有 `cache_persist`/`cache_file`/
/// `cache_save_interval`/`persist_ttl`）。
#[derive(Clone, Debug)]
pub struct PersistCfg {
    pub enabled: bool,
    pub file: PathBuf,
    pub interval_s: u64,
    pub persist_ttl: f64,
    /// **2.1.34（D4）**：缓存条目的**最大存活时间**（秒；取 `ttl_max` 与 `ttl` 的较大者，
    /// 0 = 未配置）。只用于“按时间触发快照”的节拍（`min(1800s, TTL/2)`），
    /// **不是**新的配置键，也不改变任何既有语义。
    pub ttl_s: u64,
}

enum Cmd {
    /// 周期一拍（刷新 manifest / 触发 compaction；WAL fsync 由 actor 自己的 1 s 节拍负责）。
    Tick,
    Shutdown(Sender<()>),
    SnapshotDone {
        generation: u64,
        seq: u64,
        meta: SnapshotMeta,
        snap_name: String,
        tmp: PathBuf,
    },
    SnapshotFailed {
        tmp: PathBuf,
        error: String,
    },
}

/// 轻量句柄（可 clone，给周期任务用；不持有 flock，也不负责退出）。
#[derive(Clone)]
pub struct PersistHandle {
    cmd: Option<Sender<Cmd>>,
}

impl PersistHandle {
    /// 周期拍（`cache_save_interval` 触发）：v2 只做“刷新 manifest / 视阈值 compact”。
    pub fn on_tick(&self) {
        if let Some(tx) = &self.cmd {
            let _ = tx.send(Cmd::Tick);
        }
    }
}

/// 运行期句柄（`main` 持有到进程结束 —— 与 flock 同寿）。
pub struct CachePersist {
    mode: Mode,
    cmd: Option<Sender<Cmd>>,
    join: Option<std::thread::JoinHandle<()>>,
    /// **锁句柄必须与进程同寿**：drop 即释放 `flock`。
    _lock: Option<std::fs::File>,
    stats: Arc<PersistStats>,
}

impl CachePersist {
    pub fn mode(&self) -> Mode {
        self.mode
    }
    pub fn is_v2(&self) -> bool {
        self.mode == Mode::V2
    }

    /// 轻量句柄（给周期任务用；不持有 flock、不负责退出）。
    pub fn handle(&self) -> PersistHandle {
        PersistHandle {
            cmd: self.cmd.clone(),
        }
    }

    /// 优雅退出：flush WAL + 写 manifest（`CLEAN_SHUTDOWN`）+ 视阈值 compact。
    ///
    /// **有超时**（默认 5 s）：磁盘卡住时不得让退出无限等待。
    pub async fn shutdown(mut self) {
        let Some(tx) = self.cmd.take() else {
            tracing::info!(
                format = self.stats.format().as_str(),
                "cache.persist: 本次未启动写者（只读/禁用）—— 退出不落盘"
            );
            return;
        };
        let (ack_tx, ack_rx) = channel::<()>();
        if tx.send(Cmd::Shutdown(ack_tx)).is_err() {
            return;
        }
        let waited = tokio::task::spawn_blocking(move || {
            // **2.1.34（D2）**：退出要等**终态快照**（4 s 内），故上界从 5 s 放宽到 10 s；
            // 磁盘卡死时仍不会无限等待。
            ack_rx.recv_timeout(Duration::from_secs(10)).is_ok()
        })
        .await
        .unwrap_or(false);
        if !waited {
            tracing::warn!(
                "cache.persist: 优雅退出落盘超时（>10 s）—— 已 fsync 的记录不会丢，未 fsync 的尾部按丢失窗口处理"
            );
        }
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

// ============================ 启动序列（§9.1） ============================

/// **启动序列**：`cache_persist=false` → 不读不写；`EBPDNS_CACHE_FORMAT=v1` → 强制 v1；
/// 否则按前 8 KiB 判格式（v2 manifest / v1 JSON / 缺失），并在 v1 情况下**一次性迁移**。
///
/// **任何失败都不得阻止 DNS 启动**（§9.1 第 3 步）。
pub async fn startup(resolver: &Arc<Resolver>, cfg: PersistCfg) -> CachePersist {
    let cache = resolver.cache().clone();
    let stats = cache.persist_stats_arc();
    let now = ebpdns_server::telemetry::now_epoch();
    let now_ms = (now * 1000.0) as i64;

    if !cfg.enabled {
        stats.set_format(Format::Unknown);
        stats.set_restore_source(RestoreSource::None);
        tracing::warn!(
            "cache.persist: **未开启持久化**（cache_persist=false）：不读盘也不写盘，重启即清零"
        );
        return CachePersist {
            mode: Mode::Disabled,
            cmd: None,
            join: None,
            _lock: None,
            stats,
        };
    }

    let Some((dir, base)) = split_path(&cfg.file) else {
        tracing::error!(
            "cache.persist: `cache_file` 非法（父目录或文件名取不出）：{} —— 已**禁用**缓存持久化",
            cfg.file.display()
        );
        stats.set_format(Format::Unknown);
        stats.set_restore_source(RestoreSource::None);
        return CachePersist {
            mode: Mode::Disabled,
            cmd: None,
            join: None,
            _lock: None,
            stats,
        };
    };

    // ---- 紧急回滚闸门（不新增配置键）----
    let forced_v1 = env_forced_v1();
    if forced_v1 {
        tracing::warn!(
            "cache.persist: **`EBPDNS_CACHE_FORMAT=v1` 已生效**：强制走 v1 JSON 路径\
             （不写 manifest/WAL；用于紧急回滚，见 docs/PACKAGING.md 与 CONVENTIONS.md §17）"
        );
    }

    // ---- 跨进程单写者锁（§6.4）----
    let lock_path = dir.join(format!("{base}.lock"));
    let lock = match crate::main_state::acquire_flock(&lock_path) {
        Ok(f) => Some(f),
        Err(e) => {
            tracing::error!(
                "cache.persist: **另一个实例正在使用该 cache_file**（flock {} 失败：{e}）—— \
                 本次**不写任何**缓存文件，仅尽力只读恢复；DNS 不受影响",
                lock_path.display()
            );
            stats.set_write_enabled(false);
            None
        }
    };
    let writable = lock.is_some() && !forced_v1;

    // ---- 损坏现场：保留证据，但按 P1-2 继续写新世代 ----
    let corrupt_present = has_corrupt_marker(&dir, &base);
    if corrupt_present {
        // **2.1.46（REV247 P2-6）**：2.1.42 P1-2 起坏段证据不再禁用 v2 写
        // （`fresh_start = writable` 会写新世代），旧文案"本次禁用 v2 写"是错的。
        tracing::error!(
            "cache.persist: 发现上次 manifest/快照损坏的**现场保留文件**（{}/*.corrupt.*）—— \
             **本次仍允许写出新世代**；证据文件保留不删，运维确认后清理即可",
            dir.display()
        );
    }

    // ---- 格式检测 + 恢复 ----
    let mut plan_v2: Option<RestorePlan> = None;
    let mut need_migrate = false;
    let mut v1_source = RestoreSource::None;
    let mut v2_ok = false;
    // **全新安装（cache_file 不存在且无 `.v1.bak`）**：v2 从"空缓存 + 延迟初始化"起步
    // （启动时**不写任何文件**，保持 v1 的 `exists=false` 观感；第一次 flush 才创建）。
    let mut fresh_start = false;

    if forced_v1 {
        // **紧急回滚模式**（`EBPDNS_CACHE_FORMAT=v1`）：只按 v1 JSON 读写。
        //
        // 关键语义（审计要求）：**不得因为 `cache_file` 现在是 v2 manifest 而报错**。
        // 因此这里先判格式，再决定读谁：
        //   ① `cache_file` 是 v1 JSON            ⇒ 直接按 v1 读（warm rollback）；
        //   ② 是 v2 manifest 且 `.v1.bak` 在     ⇒ 从 `.bak` 读（文档里的标准回滚路径）；
        //   ③ 是 v2 manifest 且没有 `.bak`       ⇒ **空缓存 + WARN**（不是 ERROR）；
        //   ④ 文件不存在                         ⇒ 空缓存 + INFO。
        // 这样"同一个 2.1.29 二进制 + 环境变量"就能回到 v1 语义，且读不出来时只是冷启动。
        let bak = dir.join(format!("{base}.v1.bak"));
        let prefix = read_prefix(&cfg.file, MANIFEST_MAX_BYTES + 1)
            .ok()
            .flatten();
        let is_v1 = prefix
            .as_deref()
            .map(ebpdns_cache::persist::recover::looks_like_v1_json)
            .unwrap_or(false);
        stats.set_format(Format::V1);
        if is_v1 {
            crate::restore_cache_v1(resolver, &cfg.file, cfg.persist_ttl).await;
            v1_source = RestoreSource::V1Json;
        } else if prefix.is_some() && bak.exists() {
            tracing::warn!(
                "cache.persist: `EBPDNS_CACHE_FORMAT=v1` 生效，但 `cache_file` 是 v2 manifest —— \
                 按标准回滚路径改用 `.v1.bak`（{}）",
                bak.display()
            );
            crate::restore_cache_v1(resolver, &bak, cfg.persist_ttl).await;
            v1_source = RestoreSource::V1Bak;
        } else if prefix.is_some() {
            tracing::warn!(
                "cache.persist: `EBPDNS_CACHE_FORMAT=v1` 生效，但 `cache_file` 是 v2 manifest \
                 且没有 `.v1.bak` —— 本次**空缓存**启动（v1 模式，DNS 正常服务）。\
                 warm 回滚请先执行：cp -p {base}.v1.bak {base}"
            );
            v1_source = RestoreSource::Corrupt;
        } else {
            tracing::info!(
                "cache.persist: `EBPDNS_CACHE_FORMAT=v1` 生效，且缓存文件不存在 ⇒ 空缓存启动"
            );
            v1_source = RestoreSource::None;
        }
        stats.set_restore_source(v1_source);
        if let Some(j) = lock {
            return CachePersist {
                mode: Mode::V1,
                cmd: None,
                join: None,
                _lock: Some(j),
                stats,
            };
        }
        return CachePersist {
            mode: Mode::V1,
            cmd: None,
            join: None,
            _lock: None,
            stats,
        };
    }

    let raw = read_prefix(&cfg.file, MANIFEST_MAX_BYTES + 1);
    match raw {
        Ok(None) => {
            // 文件不存在：若 `.v1.bak` 在 ⇒ 从 .bak 恢复并迁移；否则空缓存 + 延迟初始化。
            let bak = dir.join(format!("{base}.v1.bak"));
            if bak.exists() {
                tracing::warn!(
                    "cache.persist: `cache_file` 不存在但 `.v1.bak` 在（{}）：从 `.bak` 恢复并重新迁移",
                    bak.display()
                );
                stats.set_format(Format::V1);
                crate::restore_cache_v1(resolver, &bak, cfg.persist_ttl).await;
                stats.set_restore_source(RestoreSource::V1Bak);
                v1_source = RestoreSource::V1Bak;
                need_migrate = true;
            } else {
                tracing::info!(
                    "缓存文件不存在（首次启动或从未落盘）：{}（cache_persist=true 时第一次落盘才创建）",
                    cfg.file.display()
                );
                stats.set_restore_source(RestoreSource::None);
                // v2 从空缓存起步：格式立刻标成 v2（manifest 在第一次 flush 才出现，
                // 因此 manifest_valid 仍为 false，bytes/mtime 走 stat 回退）。
                stats.set_format(Format::V2);
                fresh_start = true;
            }
        }
        Ok(Some(bytes)) if ebpdns_cache::persist::recover::looks_like_v1_json(&bytes) => {
            // v1 JSON ⇒ 按 v1 恢复（口径逐字不变），随后一次性迁移。
            stats.set_format(Format::V1);
            crate::restore_cache_v1(resolver, &cfg.file, cfg.persist_ttl).await;
            v1_source = stats.restore_source();
            if v1_source == RestoreSource::None {
                v1_source = RestoreSource::V1Json;
            }
            stats.set_restore_source(v1_source);
            need_migrate = true;
        }
        Ok(Some(_)) => {
            // 二进制 ⇒ v2。
            match recover_v2(
                &dir,
                &base,
                cfg.persist_ttl,
                now,
                // >>> PATCH242A P1-4 call BEGIN
                // 2.1.42（P1-4）：未取得 flock 的实例只读恢复，绝不 set_len/写文件。
                writable,
                // <<< PATCH242A P1-4 call END
            ) {
                Ok(Some(plan)) => {
                    let mut plan = plan;
                    apply_plan(&cache, &stats, &mut plan, now);
                    plan_v2 = Some(plan);
                    v2_ok = true;
                }
                Ok(None) => {
                    // 竞态（文件在两次读之间被删）⇒ 当空缓存处理。
                    tracing::warn!("cache.persist: 读 manifest 期间文件消失：按空缓存启动");
                    stats.set_restore_source(RestoreSource::None);
                }
                Err(RecoverError::Unsupported(v)) => {
                    tracing::error!(
                        "cache.persist: **不支持的缓存格式版本 {v}**（本二进制支持 2）—— \
                         不改写、不删除任何文件；以空缓存启动并**禁用缓存写**。\
                         请回退二进制，或删除 {}/{}.* 后重启",
                        dir.display(),
                        base
                    );
                    stats.set_format(Format::Unknown);
                    stats.set_restore_source(RestoreSource::Unsupported);
                    stats.set_manifest_valid(false);
                }
                Err(RecoverError::Corrupt { what, detail }) => {
                    tracing::error!(
                        "cache.persist: **{what} 损坏**：{detail}。已保留现场（改名 {base}.corrupt.<unix_ms>，\
                         失败则原样不动）；本次尝试 `.v1.bak` 回退，否则空缓存 + **允许写出新一代 v2**"
                    );
                    let preserved = preserve_corrupt(&dir, &base);
                    stats.set_format(Format::Unknown);
                    stats.set_manifest_valid(false);
                    let bak = dir.join(format!("{base}.v1.bak"));
                    if bak.exists() && preserved {
                        tracing::warn!(
                            "cache.persist: 从 `.v1.bak` 回退（先按 v1 恢复，再尝试重新迁移）"
                        );
                        crate::restore_cache_v1(resolver, &bak, cfg.persist_ttl).await;
                        stats.set_restore_source(RestoreSource::V1Bak);
                        v1_source = RestoreSource::V1Bak;
                        need_migrate = true;
                    } else {
                        stats.set_restore_source(RestoreSource::Corrupt);
                        // 文件级失败：restore_drops.failed 至少 1（口径不变）。
                        cache.record_file_level_failure(1);
                        // >>> PATCH242A P1-2 corrupt-allow-write BEGIN
                        // **2.1.42（P1-2）**：`.corrupt.*` 只是**坏段证据**，不得永久
                        // 关闭 v2 写。拿到写锁时按"全新 v2 现场"启动（needs_initial），
                        // 下一次流量会写出新快照/manifest；旧证据原样保留。
                        fresh_start = writable;
                        // <<< PATCH242A P1-2 corrupt-allow-write END
                    }
                }
                Err(RecoverError::Io(e)) => {
                    tracing::error!(
                        "cache.persist: 读 v2 现场失败（{e}）—— 本次空缓存启动，**不覆盖**现有文件"
                    );
                    stats.set_restore_source(RestoreSource::Corrupt);
                    stats.set_manifest_valid(false);
                    cache.record_file_level_failure(1);
                }
            }
        }
        Err(e) => {
            tracing::error!(
                "cache.persist: 读 cache_file 失败（{e}）：{} —— 本次空缓存启动（不覆盖）",
                cfg.file.display()
            );
            stats.set_restore_source(RestoreSource::Corrupt);
            cache.record_file_level_failure(1);
        }
    }

    // ---- 迁移（只发生一次；失败不阻断启动）----
    let mut migrated = false;
    // >>> PATCH242A P1-2 no-corrupt-gate BEGIN
    // **2.1.42（P1-2）**：`.corrupt.*` 存在不再阻断迁移/写；它只是坏段证据。
    if need_migrate && writable {
        // <<< PATCH242A P1-2 no-corrupt-gate END
        match migrate_v1_to_v2(&cache, &dir, &base, &cfg.file, now, now_ms, &stats) {
            Ok(plan) => {
                plan_v2 = Some(plan);
                migrated = true;
                v2_ok = true;
                stats.set_restore_source(RestoreSource::Migrated);
                stats.set_format(Format::V2);
                tracing::info!(
                    "cache.persist: **v1 → v2 迁移完成**（原文件保留为 {base}.v1.bak，永不自动删除）"
                );
            }
            Err(e) => {
                tracing::warn!(
                    "cache.persist: v1 → v2 迁移失败（{e}）—— 本次保持 **v1 模式**（下次启动重试）"
                );
            }
        }
    }
    if !v2_ok && !migrated && v1_source != RestoreSource::None {
        stats.set_format(Format::V1);
    }

    // ---- 决定模式 ----
    //
    // v2 的三个入口：① 读到有效 v2 manifest（`v2_ok`）；② v1 迁移成功（`migrated`）；
    // ③ **全新安装**（`fresh_start`）—— v2 从空缓存 + 延迟初始化起步。
    if !v2_ok && !migrated && !fresh_start {
        // v1 模式（或空缓存且不可迁移）：保留 v1 落盘路径（2.1.28 行为）。
        if need_migrate && !writable {
            tracing::warn!(
                "cache.persist: 无法迁移（写被禁用）—— 本次保持 **v1 模式**，'cache_file' 仍是 v1 JSON"
            );
        }
        stats.set_format(Format::V1);
        stats.set_write_enabled(false);
        return CachePersist {
            mode: Mode::V1,
            cmd: None,
            join: None,
            _lock: lock,
            stats,
        };
    }

    // ---- 未取得跨进程锁 ⇒ **只读**（不启动 actor，绝不写任何 cache 文件）----
    //
    // 设计 §6.4：第二个实例只读或禁用持久化。这里已经完成（可能的）v2/v1 只读恢复，
    // 于是“保持内存缓存 + 禁用写”就是正确行为：DNS 正常服务，缓存不再前进。
    if lock.is_none() {
        stats.set_write_enabled(false);
        return CachePersist {
            mode: if v2_ok || fresh_start {
                Mode::V2
            } else {
                Mode::V1
            },
            cmd: None,
            join: None,
            _lock: None,
            stats,
        };
    }

    // ---- v2：启动 actor ----
    let journal_off = cfg.interval_s == 0;
    let rx_ev = cache.enable_journal();
    let journal = cache.journal();
    if journal_off {
        // `cache_save_interval=0` ⇒ 行为逐位回到 v1 的“只在优雅退出落盘”：
        // journal 关闭（不写 WAL），退出时写一份全量二进制快照 + manifest。
        journal.enable(false);
        tracing::info!(
            "cache.persist: cache_save_interval=0 ⇒ **不启动周期 flush**（只在优雅退出落盘；行为同 v1）"
        );
    }
    let next_seq = plan_v2.as_ref().map(|p| p.next_seq).unwrap_or(1);
    journal.set_next_seq_at_least(next_seq.max(1));

    let (tx, rx) = channel::<Cmd>();
    let st = ActorState {
        dir: dir.clone(),
        base: base.clone(),
        cache: Arc::clone(&cache),
        journal: Arc::clone(&journal),
        stats: Arc::clone(&stats),
        tx: tx.clone(),
        plan: plan_v2,
        wal: None,
        wal_name: String::new(),
        manifest: None,
        snapshot: None,
        durable_seq: 0,
        last_wal_base: 0,
        last_manifest_ms: 0,
        last_snapshot_ms: 0,
        needs_initial: !v2_ok,
        inflight: None,
        error_logged: false,
        journal_off,
        ttl_s: cfg.ttl_s,
    };
    let join = std::thread::Builder::new()
        .name("ebpdns-cache-persist".to_string())
        .spawn(move || actor_main(st, rx, rx_ev))
        .ok();
    if join.is_none() {
        tracing::error!("cache.persist: 无法启动持久化线程 —— 本次**不写**缓存（DNS 不受影响）");
    }
    let spawned = join.is_some();
    stats.set_write_enabled(spawned);
    CachePersist {
        mode: Mode::V2,
        cmd: if spawned { Some(tx) } else { None },
        join,
        _lock: lock,
        stats,
    }
}

/// **崩溃注入点**（**默认完全惰性**）：只有显式设置 `EBPDNS_CACHE_FAILPOINT=<name>` 的
/// 进程才会在对应位置 `abort()`（不经析构、不 flush，等价于 `kill -9` 的磁盘语义）。
///
/// 为什么生产二进制里保留它：§15.1 的 C1–C17 崩溃矩阵要求**逐点**验证“不判撕裂”，
/// 仅靠随机 `kill -9` 只能覆盖时序、无法命中“快照 `.tmp` 写一半”“R1 之后 R2 之前”这类
/// 窄窗口。该函数只在环境变量等于点上名时触发，**没有环境变量时是一条 `env::var` 之外
/// 的空路径**（每点每次调用一次 `getenv`，全部位于持久化线程，不在数据面）。
///
/// 点集（名字即契约，脚本 `scripts/archive/cache_v2_crash.sh` 依赖它们）：
/// `wal_after_write` / `wal_after_fsync` / `snap_after_write` / `snap_after_rename` /
/// `manifest_after_rename` / `after_old_unlink`。
fn fail_point(name: &str) {
    if let Ok(v) = std::env::var("EBPDNS_CACHE_FAILPOINT") {
        if v == name {
            tracing::error!(failpoint = name, "崩溃注入点命中：abort()");
            std::process::abort();
        }
    }
}

/// 把恢复计划的现场写进统计（两 API 端点读这份）。
fn apply_plan(
    cache: &Arc<SwappableCache>,
    stats: &Arc<PersistStats>,
    plan: &mut RestorePlan,
    now: f64,
) {
    // 条目所有权直接搬进缓存（不 clone：10 万条量级 clone 一次就是几十 MB 峰值）。
    let entries = std::mem::take(&mut plan.entries);
    // **2.1.29 热修（r2）**：`used_live` 必须取**被 take 出来的** `entries` 的长度。
    // take 之后 `plan.entries` 恒为空，再读它会让 v2 恢复后的 `used_live` 恒为 0，
    // 按「(快照 entries − 恢复后 used_live) / 快照 entries」算出来的丢失率就成了 100%。
    //
    // **2.1.43-B（P2-4）**：但"恢复计划的条数"**不等于**"恢复后真的在缓存里的条数" ——
    // TinyLFU 只把 main 段容量灌满（≈99%），被挤出的 ≈1%（window 段容量）从来没人统计
    // ⇒ 丢失率公式读成 0（审计："丢 window ~1% 但 used_live 报 0 丢失"）。
    // 现在 `used_live` = **恢复后实际插入的条数**（`cache.len()`），于是
    //   loss = (snap_entries − used_live) / snap_entries
    // **自动包含** `restore_drops.window_unpersisted` 那一项；两者相加即恢复总缺口。
    let planned_live = entries.len() as u64;
    cache.restore_records(entries, now);
    let restored_live = cache.len() as u64;
    // 只影响缓存，不影响 DNS/配置：挤出量单独打一条 INFO，便于与 `restore_drops` 对账。
    if restored_live < planned_live {
        tracing::info!(
            planned_live,
            restored_live,
            window_unpersisted = cache.last_restore_window_unpersisted(),
            "cache.persist: 恢复计划 {planned_live} 条、实际插入 {restored_live} 条\
             （TinyLFU 只灌 main 段 ⇒ 差额计入 `restore_drops.window_unpersisted`）"
        );
    }
    stats.set_format(Format::V2);
    stats.set_manifest_valid(true);
    stats.set_snap_seq(plan.snapshot_seq);
    stats.set_snap_bytes(plan.snap_bytes);
    stats.set_snap_entries(plan.snap_entries as u64);
    // 恢复完成后按**实际插入条数**设置（不得再读已被 take 空的 `plan.entries`）。
    stats.set_used_live(restored_live);
    stats.set_wal_bytes(plan.wal_bytes);
    stats.set_wal_segments(plan.wal_files as u64);
    stats.set_last_commit_ms(plan.last_commit_ms);
    stats.set_durable_seq(plan.durable_seq);
    stats.set_snap_ms(plan.snap_ms);
    stats.set_tail_records(plan.tail_records);
    stats.set_restore_source(plan.source);
    tracing::info!(
        format = "v2",
        restore_source = plan.source.as_str(),
        snapshot_seq = plan.snapshot_seq,
        snap_bytes = plan.snap_bytes,
        snap_entries = plan.snap_entries,
        wal_files = plan.wal_files,
        wal_bytes = plan.wal_bytes,
        tail_records = plan.tail_records,
        dropped_expired = plan.drops.0,
        dropped_legacy = plan.drops.1,
        dropped_failed = plan.drops.2,
        next_seq = plan.next_seq,
        "缓存已恢复（v2：manifest 指向的快照 + 其后的完整 WAL 记录）"
    );
    if plan.tail_records > 0 {
        tracing::warn!(
            tail_records = plan.tail_records,
            "cache.persist: WAL 尾部有 {} 处不完整/缺失 —— 已**按尾部截断**忽略（不判撕裂，不计入 restore_drops.failed）",
            plan.tail_records
        );
    }
}

// ============================ 路径与文件小工具 ============================

/// 从配置路径拆出 `(父目录, 文件名)`；相对路径的父目录为空 ⇒ `"."`（与 v1 同口径）。
fn split_path(p: &Path) -> Option<(PathBuf, String)> {
    let base = p.file_name()?.to_str()?.to_string();
    if !ebpdns_cache::persist::is_safe_leaf(&base) {
        return None;
    }
    let dir = match p.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    Some((dir, base))
}

fn read_prefix(path: &Path, cap: u64) -> std::io::Result<Option<Vec<u8>>> {
    use std::io::Read as _;
    let f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut buf = Vec::new();
    f.take(cap).read_to_end(&mut buf)?;
    Ok(Some(buf))
}

fn env_forced_v1() -> bool {
    matches!(
        std::env::var("EBPDNS_CACHE_FORMAT").as_deref(),
        Ok("v1") | Ok("V1")
    )
}

fn has_corrupt_marker(dir: &Path, base: &str) -> bool {
    let prefix = format!("{base}.corrupt.");
    std::fs::read_dir(dir)
        .map(|it| {
            it.filter_map(|e| e.ok())
                .any(|e| e.file_name().to_string_lossy().starts_with(&prefix))
        })
        .unwrap_or(false)
}

/// 把损坏的 manifest 改名保留（**不覆盖、不删除**）；返回是否成功。
fn preserve_corrupt(dir: &Path, base: &str) -> bool {
    let src = dir.join(base);
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let dst = dir.join(format!("{base}.corrupt.{ms}"));
    match std::fs::rename(&src, &dst) {
        Ok(()) => {
            fsync_dir(dir);
            tracing::error!("cache.persist: 损坏现场已保留为 {}", dst.display());
            true
        }
        Err(e) => {
            tracing::error!(
                "cache.persist: 保留损坏现场失败（{e}）：{} 原样不动（禁用写以免覆盖证据）",
                src.display()
            );
            false
        }
    }
}

/// **一次性迁移 v1 → v2**（§9.1）：先 `.bak`，再从**已恢复的缓存**导出快照。
///
/// 顺序不可换：先备份再切换，任何时刻都有一个完整 v1 文件可回滚。
fn migrate_v1_to_v2(
    cache: &Arc<SwappableCache>,
    dir: &Path,
    base: &str,
    file: &Path,
    now: f64,
    now_ms: i64,
    stats: &Arc<PersistStats>,
) -> Result<RestorePlan, String> {
    let bak = dir.join(format!("{base}.v1.bak"));
    if !bak.exists() {
        let bak_tmp = dir.join(format!("{base}.v1.bak.tmp"));
        std::fs::copy(file, &bak_tmp).map_err(|e| format!("复制 .v1.bak.tmp: {e}"))?;
        {
            let f = std::fs::File::open(&bak_tmp).map_err(|e| format!("open .bak.tmp: {e}"))?;
            f.sync_all().map_err(|e| format!("fsync .bak.tmp: {e}"))?;
        }
        std::fs::rename(&bak_tmp, &bak).map_err(|e| format!("rename .bak: {e}"))?;
        fsync_dir(dir);
    }
    // 快照 S=1：v1 来源的条目 seq=0（0 <= 1，会被收录）。
    let s: u64 = 1;
    let snap_name = format!("{base}.snap.{s}");
    let tmp = dir.join(format!("{snap_name}.tmp"));
    let mut w = SnapshotWriter::create(&tmp, s, now_ms).map_err(|e| format!("create snap: {e}"))?;
    {
        let mut err: Option<String> = None;
        // 迁移的来源是**已恢复的缓存**（已按 persist_ttl 处理、已丢弃旧格式/过期），
        // 因此不会把“本来会被丢弃的条目”写进 v2 快照。
        let mut items: Vec<(CacheKey, Arc<CacheEntry>)> = Vec::new();
        cache.for_each_entry(now, &mut |k, e| items.push((k.clone(), Arc::clone(e))));
        items.sort_by(|a, b| {
            a.0.domain
                .cmp(&b.0.domain)
                .then_with(|| a.0.qtype.cmp(&b.0.qtype))
                .then_with(|| a.0.group.cmp(&b.0.group))
        });
        for (k, e) in items {
            let mut e2 = (*e).clone();
            e2.seq = 0;
            match EntryBody::from_entry(&k, &e2).and_then(|b| w.push(0, &b)) {
                Ok(()) => {}
                Err(x) => {
                    err = Some(format!("写快照记录: {x}"));
                    break;
                }
            }
        }
        if let Some(e) = err {
            w.abort();
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    }
    let meta = match w.finish() {
        Ok(m) => m,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("finish snap: {e}"));
        }
    };
    std::fs::rename(&tmp, dir.join(&snap_name)).map_err(|e| format!("rename snap: {e}"))?;
    fsync_dir(dir);
    // 空 WAL 段（base_seq = S+1 = 2）。
    let wal_base = s + 1;
    let wal_name = format!("{base}.wal.{wal_base}");
    let ww = WalWriter::create(&dir.join(&wal_name), wal_base, now_ms)
        .map_err(|e| format!("create wal: {e}"))?;
    let wal_bytes = ww.bytes();
    drop(ww);
    let m = Manifest {
        flags: FLAG_MIGRATED_FROM_V1,
        seq: s,
        snapshot_seq: s,
        committed_ms: now_ms,
        snap_bytes: meta.file_len,
        snap_crc32c: meta.body_crc32c,
        snap_entries: meta.entry_count,
        snap_path: snap_name.clone(),
        wal_paths: vec![wal_name.clone()],
        wal_base_seq: vec![wal_base],
        wal_bytes,
    };
    atomic_write_bytes(file, &m.encode().map_err(|e| e.to_string())?)
        .map_err(|e| format!("写 manifest: {e}"))?;
    stats.set_format(Format::V2);
    stats.set_manifest_valid(true);
    stats.set_snap_seq(s);
    stats.set_snap_bytes(meta.file_len);
    stats.set_snap_entries(meta.entry_count as u64);
    stats.set_wal_bytes(wal_bytes);
    stats.set_wal_segments(1);
    stats.set_last_commit_ms(now_ms);
    // 迁移后的恢复计划（供 actor 接管现场）。
    let mut entries: Vec<(CacheKey, CacheEntry)> = Vec::new();
    cache.for_each_entry(now, &mut |k, e| entries.push((k.clone(), (**e).clone())));
    Ok(RestorePlan {
        source: RestoreSource::Migrated,
        snapshot_seq: s,
        manifest_seq: s,
        wal_bytes,
        wal_files: 1,
        next_seq: 2,
        entries,
        drops: (0, 0, 0),
        tail_records: 0,
        clean_shutdown: false,
        last_commit_ms: now_ms,
        durable_seq: s,
        wal_truncate: Vec::new(),
        // >>> PATCH242A P1-5 migration-gap BEGIN
        wal_gap: false,
        // <<< PATCH242A P1-5 migration-gap END
        wal_paths: vec![wal_name],
        wal_base_seq: vec![wal_base],
        snap_path: snap_name,
        snap_bytes: meta.file_len,
        snap_entries: meta.entry_count,
        snap_crc32c: meta.body_crc32c,
        snap_ms: now_ms,
    })
}

// ============================ actor 主体 ============================

struct ActorState {
    dir: PathBuf,
    base: String,
    cache: Arc<SwappableCache>,
    journal: Arc<CacheJournal>,
    stats: Arc<PersistStats>,
    tx: Sender<Cmd>,
    plan: Option<RestorePlan>,
    /// 活动 WAL 段（`None` = 还没创建；第一次要写记录时创建 + 写 R1）。
    wal: Option<WalWriter>,
    /// 活动 WAL 段文件名（rename/R2 时要用；与 `wal` 同生共死）。
    wal_name: String,
    manifest: Option<Manifest>,
    /// 当前快照现场。
    snapshot: Option<SnapInfo>,
    durable_seq: u64,
    last_wal_base: u64,
    last_manifest_ms: i64,
    last_snapshot_ms: i64,
    /// 首次启动（无 manifest）：第一次 flush 时做一次“初始 compact”。
    needs_initial: bool,
    /// 进行中的快照：`(generation, S)`。
    inflight: Option<(u64, u64)>,
    /// ENOSPC/EIO 限流：同一状态只打一次。
    error_logged: bool,
    /// `cache_save_interval=0`：journal 关闭，退出时才落盘。
    journal_off: bool,
    /// **2.1.34（D4）**：条目最大 TTL（秒；0 = 未配置）—— 决定按时间快照的节拍。
    ttl_s: u64,
}

#[derive(Clone, Debug)]
struct SnapInfo {
    name: String,
    seq: u64,
    /// **2.1.46（REV247 B P2-11）**：u64，避免 >4 GiB 快照在内部现场就被截断。
    bytes: u64,
    crc: u32,
    entries: u32,
}

fn now_ms() -> i64 {
    (ebpdns_server::telemetry::now_epoch() * 1000.0) as i64
}

/// **2.1.34（D1）**：把 journal 队列里**已入队**的事件全部写进当前 WAL 段并 fsync。
///
/// 轮转（A 阶段）前必须先 drain：新段 `base` 取“已入队 max seq + 1”才严格大于
/// 队列里所有 seq，否则低 seq 事件会落进新段（旧的 `seq not increasing` 判据
/// 会把它放大成整段截断）。循环有次数上限，避免写者持续加压时饿死 actor。
fn drain_into_wal(st: &mut ActorState, rx_ev: &Receiver<Event>, what: &str) {
    for _ in 0..8 {
        let mut batch: Vec<Event> = Vec::new();
        let mut bytes = 0usize;
        while batch.len() < WAL_BATCH_MAX_EVENTS && bytes < WAL_BATCH_MAX_BYTES {
            match rx_ev.try_recv() {
                Ok(ev) => {
                    bytes += 160;
                    batch.push(ev);
                }
                Err(_) => break,
            }
        }
        if batch.is_empty() {
            return;
        }
        if let Err(e) = flush_batch(st, batch, false) {
            log_io_once(st, &e, what);
            return;
        }
    }
}

/// **2.1.34（D2）**：等 in-flight 快照结束（`SnapshotDone/SnapshotFailed`），直到超时。
///
/// 返回 `true` = 没有 in-flight 快照（完成/从未启动）；`false` = 超时仍在飞。
fn pump_snapshot(st: &mut ActorState, rx: &Receiver<Cmd>, deadline: std::time::Instant) -> bool {
    while st.inflight.is_some() {
        let now = std::time::Instant::now();
        if now >= deadline {
            return false;
        }
        let step = (deadline - now).min(Duration::from_millis(100));
        match rx.recv_timeout(step) {
            Ok(Cmd::SnapshotDone {
                generation,
                seq,
                meta,
                snap_name,
                tmp,
            }) => on_snapshot_done(st, generation, seq, meta, snap_name, tmp),
            Ok(Cmd::SnapshotFailed { tmp, error }) => {
                st.inflight = None;
                let _ = std::fs::remove_file(&tmp);
                tracing::error!(
                    "cache.persist: 退出期快照失败（{error}）—— 保留旧 manifest（旧快照 + WAL 仍可恢复）"
                );
            }
            _ => {}
        }
    }
    true
}

fn actor_main(mut st: ActorState, rx: Receiver<Cmd>, rx_ev: Receiver<Event>) {
    // 接管现场（恢复/迁移后的 manifest + 活动 WAL）。
    if let Some(plan) = st.plan.take() {
        st.snapshot = Some(SnapInfo {
            name: plan.snap_path.clone(),
            seq: plan.snapshot_seq,
            bytes: plan.snap_bytes,
            crc: plan.snap_crc32c,
            entries: plan.snap_entries,
        });
        st.last_snapshot_ms = if plan.snap_ms > 0 {
            plan.snap_ms
        } else {
            now_ms()
        };
        st.stats.set_snap_ms(st.last_snapshot_ms);
        st.durable_seq = plan.durable_seq.max(plan.manifest_seq);
        st.last_wal_base = plan.wal_base_seq.last().copied().unwrap_or(0);
        // >>> PATCH242A P1-5 actor-resume BEGIN
        // **2.1.42（P1-5）**：恢复时发现"非最后一段不可读/中段损坏" ⇒ 只信任读完的
        // 前缀段，**绝不**向旧段追加；立即新建 `base = next_seq` 的段并重写 manifest。
        // 否则每次重启都会重新撞上坏段 break，新段里的记录永远不被重放。
        let mut resumed_new_segment: Option<(String, u64)> = None;
        if plan.wal_gap {
            let base = plan.next_seq.max(1);
            let name = format!("{}.wal.{}", st.base, base);
            match WalWriter::create(&st.dir.join(&name), base, now_ms()) {
                Ok(w) => {
                    st.wal = Some(w);
                    st.wal_name = name.clone();
                    st.last_wal_base = base;
                    resumed_new_segment = Some((name, base));
                    tracing::warn!(
                        wal_segment = base,
                        next_seq = plan.next_seq,
                        "WAL 存在未读损坏段：已从**新段**续写（不向旧段追加）"
                    );
                }
                Err(e) => tracing::error!(
                    "cache.persist: WAL gap 后创建新段失败（{e}）；下一次追加会重试创建"
                ),
            }
        } else if let (Some(name), Some(base)) = (plan.wal_paths.last(), plan.wal_base_seq.last()) {
            // 打开最后一段 WAL 追加（必要时先截断尾部）。
            let path = st.dir.join(name);
            let valid = plan
                .wal_truncate
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| *v);
            let len =
                valid.unwrap_or_else(|| std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0));
            match WalWriter::open_append(&path, *base, len) {
                Ok(w) => {
                    st.wal = Some(w);
                    st.wal_name = name.clone();
                }
                Err(e) => tracing::error!(
                    "cache.persist: 打开 WAL 段失败（{e}）；下一次追加会创建新段（旧段按 manifest 引用保留）"
                ),
            }
        }
        // <<< PATCH242A P1-5 actor-resume END
        let mut m = Manifest {
            flags: if plan.clean_shutdown {
                FLAG_CLEAN_SHUTDOWN
            } else {
                0
            },
            seq: plan.manifest_seq,
            snapshot_seq: plan.snapshot_seq,
            committed_ms: plan.last_commit_ms,
            snap_bytes: plan.snap_bytes,
            snap_crc32c: plan.snap_crc32c,
            snap_entries: plan.snap_entries,
            snap_path: plan.snap_path.clone(),
            wal_paths: plan.wal_paths.clone(),
            wal_base_seq: plan.wal_base_seq.clone(),
            wal_bytes: plan.wal_bytes,
        };
        // >>> PATCH242A P1-5 actor-manifest BEGIN
        if let Some((name, base)) = resumed_new_segment.clone() {
            m.wal_paths.push(name);
            m.wal_base_seq.push(base);
        }
        // <<< PATCH242A P1-5 actor-manifest END
        if m.committed_ms == 0 {
            m.committed_ms = now_ms();
        }
        // >>> PATCH242A P1-5 persist-manifest BEGIN
        // gap 场景必须**立刻**把新段写进 manifest（原子替换），否则崩溃后新段变孤儿、
        // 恢复仍会撞坏段。R1 语义：旧快照 + [已读前缀段, 新段] 仍然自洽。
        if resumed_new_segment.is_some() {
            match m.encode() {
                Ok(bytes) => {
                    if let Err(e) = atomic_write_bytes(&st.dir.join(&st.base), &bytes) {
                        tracing::error!(
                            "cache.persist: WAL gap 后重写 manifest 失败（{e}）—— 新段暂未被引用，崩溃会丢这批记录"
                        );
                    } else {
                        fsync_dir(&st.dir);
                    }
                }
                Err(e) => tracing::error!("cache.persist: WAL gap 后 manifest 编码失败（{e}）"),
            }
        }
        // <<< PATCH242A P1-5 persist-manifest END
        st.manifest = Some(m);
        st.last_manifest_ms = now_ms();
    }

    // 清理 `.tmp` 与孤儿（**只删不读**；永不删 manifest 引用的文件）。
    cleanup_orphans(&st);

    loop {
        let mut shutdown: Option<Sender<()>> = None;
        // ---- 1) 等命令（最多 WAL_FSYNC_MS，正好是丢失窗口上界）----
        match rx.recv_timeout(Duration::from_millis(WAL_FSYNC_MS)) {
            Ok(Cmd::Tick) => {}
            Ok(Cmd::Shutdown(ack)) => shutdown = Some(ack),
            Ok(Cmd::SnapshotDone {
                generation,
                seq,
                meta,
                snap_name,
                tmp,
            }) => on_snapshot_done(&mut st, generation, seq, meta, snap_name, tmp),
            Ok(Cmd::SnapshotFailed { tmp, error }) => {
                st.inflight = None;
                let _ = std::fs::remove_file(&tmp);
                tracing::error!(
                    "cache.persist: 写快照失败（{error}）—— 保留当前 manifest（旧快照仍可用），下一拍重试"
                );
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }

        if st.journal_off {
            // interval=0：只等退出（不写 WAL、不刷 manifest —— 与 v1 一致）。
            if let Some(ack) = shutdown {
                shutdown_snapshot_only(&mut st);
                let _ = ack.send(());
                break;
            }
            st.inflight = None;
            continue;
        }

        // ---- 2) 取事件（有界）----
        let mut batch: Vec<Event> = Vec::new();
        let mut bytes = 0usize;
        while batch.len() < WAL_BATCH_MAX_EVENTS && bytes < WAL_BATCH_MAX_BYTES {
            match rx_ev.try_recv() {
                Ok(ev) => {
                    bytes += 160;
                    batch.push(ev);
                }
                Err(_) => break,
            }
        }
        let overflow = st.journal.take_needs_resync();

        // ---- 3) 初始 compact（首次启动 / 迁移后没有 WAL 时的“活动段创建”）----
        if st.needs_initial && !batch.is_empty() {
            if let Err(e) = initial_compact(&mut st) {
                log_io_once(&mut st, &e, "初始快照");
            }
        }
        if st.wal.is_none() && !batch.is_empty() {
            if let Err(e) = rotate_for_append(&mut st) {
                log_io_once(&mut st, &e, "创建 WAL 段");
            }
        }

        // ---- 4) 追加 + fsync（一拍一次）----
        if !batch.is_empty() || overflow {
            if let Err(e) = flush_batch(&mut st, batch, overflow) {
                log_io_once(&mut st, &e, "WAL 追加/fsync");
            }
        }

        // ---- 5) manifest 刷新 / compaction ----
        let t = now_ms();
        let want_snapshot = match st.journal.take_snapshot_request() {
            Some(r) => {
                tracing::info!(reason = r, "cache.persist: 收到快照请求");
                true
            }
            None => false,
        };
        if want_snapshot || should_compact(&st, t) {
            // **2.1.34（D1）**：先 drain 再轮转 —— 新段 base 必须严格大于“已入队 max seq”。
            drain_into_wal(&mut st, &rx_ev, "compaction 前 drain");
            let _ = start_compaction(
                &mut st,
                if want_snapshot {
                    "request"
                } else {
                    "threshold"
                },
            );
        }

        // ---- 6) 优雅退出 ----
        if let Some(ack) = shutdown {
            // **2.1.34（D2）**：退出必须先落**终态快照**，再写 manifest。
            //
            // 旧实现：先写 manifest（指向**旧**快照 + 有缺口的 WAL），再“视阈值” compact，
            // 且最多等 2 s —— journal 溢出后的补偿快照若未完成，manifest 仍指向旧快照，
            // 恢复侧 `tail_records=0 / failed=0`，**完全静默**（实测丢 12.505%）。
            //
            // 新顺序：drain 队列 → 等 in-flight（若有）→ **无条件**封段 + 同步等终态快照
            // → 再 drain 尾批 → 最后写 manifest。快照失败则 manifest 停在 R1
            //（旧快照 + 全量 WAL，仍可恢复）并打 ERROR —— 不允许静默。
            drain_into_wal(&mut st, &rx_ev, "退出 flush");
            let deadline = std::time::Instant::now() + Duration::from_secs(4);
            // 1) 等已在飞的快照（否则 start_compaction 会直接返回）。
            if !pump_snapshot(&mut st, &rx, deadline) {
                tracing::error!(
                    "cache.persist: 退出期等待 in-flight 快照超时 —— 继续尝试终态快照（旧 manifest 仍可恢复）"
                );
            }
            // 2) 无条件写一份终态快照（不再看 8 MiB / 30 min 阈值）。
            let mut ok = start_compaction(&mut st, "shutdown");
            if ok {
                ok = pump_snapshot(&mut st, &rx, deadline);
            }
            if !ok {
                tracing::error!(
                    "cache.persist: 退出期终态快照失败/超时 —— **保留旧 manifest + 全量 WAL**（可恢复，不静默）"
                );
            }
            // 3) 终态快照之后新产生的事件（seq > snapshot_seq）写进当前段。
            drain_into_wal(&mut st, &rx_ev, "退出尾批");
            if st.wal.is_some() {
                write_manifest(&mut st, FLAG_CLEAN_SHUTDOWN);
            }
            let _ = ack.send(());
            break;
        }
    }
}

/// 退出时（`cache_save_interval=0`）：写一份**全量二进制快照 + manifest**（不写 WAL）。
fn shutdown_snapshot_only(st: &mut ActorState) {
    let s = st.journal.current_seq().max(1);
    let now = ebpdns_server::telemetry::now_epoch();
    let snap_name = format!("{}.snap.{s}", st.base);
    let tmp = st.dir.join(format!("{snap_name}.tmp"));
    match write_snapshot_file(&st.cache, &tmp, s, now) {
        Ok((meta, live)) => {
            st.stats.set_used_live(live);
            if let Err(e) = std::fs::rename(&tmp, st.dir.join(&snap_name)) {
                tracing::error!("cache.persist: rename 快照失败（{e}）");
                let _ = std::fs::remove_file(&tmp);
                return;
            }
            fsync_dir(&st.dir);
            let m = Manifest {
                flags: FLAG_CLEAN_SHUTDOWN,
                seq: s,
                snapshot_seq: s,
                committed_ms: now_ms(),
                snap_bytes: meta.file_len,
                snap_crc32c: meta.body_crc32c,
                snap_entries: meta.entry_count,
                snap_path: snap_name,
                wal_paths: Vec::new(),
                wal_base_seq: Vec::new(),
                wal_bytes: 0,
            };
            if let Err(e) =
                atomic_write_bytes(&st.dir.join(&st.base), &m.encode().unwrap_or_default())
            {
                tracing::error!("cache.persist: 写 manifest 失败（{e}）");
                return;
            }
            st.stats.set_format(Format::V2);
            st.stats.set_manifest_valid(true);
            st.stats.set_snap_seq(s);
            st.stats.set_snap_bytes(meta.file_len);
            st.stats.set_snap_entries(meta.entry_count as u64);
            st.stats.set_last_commit_ms(m.committed_ms);
            st.stats.set_snap_ms(m.committed_ms);
            tracing::info!(
                entries = meta.entry_count,
                snap_bytes = meta.file_len,
                "缓存已落盘（cache_save_interval=0：退出时写全量二进制快照 + manifest）"
            );
        }
        Err(e) => tracing::error!("cache.persist: 退出写快照失败（{e}）"),
    }
}

#[cfg(test)]
static SNAPSHOT_WRITE_DELAY_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(test)]
static SNAPSHOT_WRITE_ENTERED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// **仅测试**：在"锁外逐条编码/写盘"循环里放慢并置位。
///
/// 用途：判别 2.1.46 之前的实现（写盘闭包在 `for_each_entry` 的锁内）—— 测试在
/// 本钩子睡眠期间尝试 `cache.put`，旧实现会被缓存锁挡住，新实现不会。
#[cfg(test)]
fn snapshot_write_hook() {
    use std::sync::atomic::Ordering;
    SNAPSHOT_WRITE_ENTERED.store(true, Ordering::SeqCst);
    let ms = SNAPSHOT_WRITE_DELAY_MS.load(Ordering::SeqCst);
    if ms > 0 {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
}

/// 写快照 `.tmp`（**只写自己的 tmp**，rename 由 actor 做）。
fn write_snapshot_file(
    cache: &Arc<SwappableCache>,
    tmp: &Path,
    s: u64,
    now: f64,
) -> Result<(SnapshotMeta, u64), String> {
    // **2.1.46（REV247 B P2-6）**：先在缓存锁内**只收集**键 + `Arc`，随后在锁外
    // 编码并写盘。旧路径把 `EntryBody::from_entry` / `BufWriter::write_all` 放进
    // `for_each_entry` 回调（TinyLFU 为整把锁）⇒ 快照期间数据面被磁盘 IO 阻塞。
    let entries = cache.collect_snapshot_entries(now);
    let live = entries.len() as u64;
    let mut w = SnapshotWriter::create(tmp, s, now_ms()).map_err(|e| e.to_string())?;
    let mut err: Option<String> = None;
    let mut n = 0u64;
    for (k, e) in entries {
        if err.is_some() {
            break;
        }
        // **§6.3.4 的核心过滤**：只收录 `entry.seq <= S` 的条目。
        // 省略它会复活“迭代前已逐出”的条目（W_old 已删、W_new 又按 seq>S 过滤）。
        if e.seq > s {
            continue;
        }
        // 锁外写盘；测试钩子只在 `cfg(test)` 下存在（用于证明锁未被持有）。
        #[cfg(test)]
        snapshot_write_hook();
        match EntryBody::from_entry(&k, &e).and_then(|b| w.push(e.seq, &b)) {
            Ok(()) => n += 1,
            Err(x) => err = Some(x.to_string()),
        }
    }
    if let Some(e) = err {
        w.abort();
        let _ = std::fs::remove_file(tmp);
        return Err(e);
    }
    let _ = n;
    let meta = w.finish().map_err(|e| e.to_string())?;
    // ③：快照 `.tmp` 已写完并 fsync，**尚未 rename**（崩溃 ⇒ tmp 是孤儿，旧代仍可用）。
    fail_point("snap_after_write");
    Ok((meta, live))
}

/// 合并一批事件（§6.1）：CLEAR 之前的丢弃、同 key 只留 seq 最大的一条、按 seq 升序。
///
/// 正确性：同 key 的最终状态由最后一条决定；CLEAR 之前的操作被 CLEAR 覆盖；
/// 跨 key 无顺序依赖。
fn coalesce(batch: Vec<Event>) -> Vec<Event> {
    let mut last_clear = 0u64;
    for ev in &batch {
        if let Event::Clear { seq, .. } = ev {
            last_clear = last_clear.max(*seq);
        }
    }
    let mut by_key: HashMap<CacheKey, Event> = HashMap::with_capacity(batch.len());
    let mut clears: Vec<Event> = Vec::new();
    for ev in batch {
        let seq = ev.seq();
        let key = match &ev {
            Event::Put { key, .. } | Event::Evict { key, .. } => Some(key.clone()),
            Event::Clear { .. } => None,
        };
        match key {
            None => clears.push(ev),
            Some(k) => {
                if seq < last_clear {
                    continue; // CLEAR 之前的变更被清空覆盖
                }
                match by_key.entry(k) {
                    std::collections::hash_map::Entry::Occupied(mut o) => {
                        if seq > o.get().seq() {
                            o.insert(ev);
                        }
                    }
                    std::collections::hash_map::Entry::Vacant(v) => {
                        v.insert(ev);
                    }
                }
            }
        }
    }
    let mut out: Vec<Event> = clears;
    out.extend(by_key.into_values());
    out.sort_by_key(|e| e.seq());
    out
}

fn log_io_once(st: &mut ActorState, err: &str, what: &str) {
    if st.error_logged {
        return;
    }
    st.error_logged = true;
    tracing::error!(
        "cache.persist: **{what} 失败**（{err}）—— 只影响缓存，不影响 DNS/配置；\
         旧快照与已 fsync 的记录仍可用（查目录权限/磁盘空间）"
    );
}

/// **2.1.43-B（P2-5）**：WAL 写入失败后的**重同步标记**（新段 `base` + 全量快照请求）。
///
/// # 缺陷（2.1.42）
///
/// `flush_batch` 在 `append_bytes` / `sync_data` 失败时只 `truncate_to_valid()` 并返回
/// `Err`；调用方 `log_io_once` 打一条 ERROR 就结束了。后果：
/// * 这一批（≤ `WAL_BATCH_MAX_EVENTS` / `WAL_BATCH_MAX_BYTES`）的事件**整批静默丢失**；
/// * 磁盘上**没有任何标记**说明"从这里开始 WAL 不可信" —— manifest 仍指向旧段，
///   运行期只有 journal 溢出才请求快照 ⇒ "真丢了一批"永远不会触发全量快照兜底；
/// * 重启后恢复侧只会看到"WAL 比预期短"，既无 `tail_records` 也无 `restore_drops` 记录。
///
/// # 修法（本函数）
///
/// 失败即三件事，且**都留痕**：
/// 1. `journal.request_snapshot("wal_resync")` —— 下一拍写**全量快照**（权威兜底）；
/// 2. **换新段**：`base = max(last_wal_base+1, journal 当前 seq+1, 1)`，`WalWriter::create`；
/// 3. 按 R1 语义重写 manifest（旧快照 + [保留段, 新段] 仍自洽），并打一条带
///    `new_segment_base` 的 ERROR。
///
/// 旧段**不动**（可能只写了一半，尾部由 `truncate_to_valid` 截到最后一个完整记录）。
/// 返回新段 `base`（0 = 当前无法轮转，已置 `needs_initial` 或段数已达上限）。
fn resync_after_flush_failure(st: &mut ActorState, err: &str) -> Result<u64, String> {
    // 1) 无论能否换段，都必须请求全量快照（它是唯一权威兜底）。
    st.journal.request_snapshot("wal_resync");
    let Some(snap) = st.snapshot.clone() else {
        st.needs_initial = true;
        tracing::error!(
            error = err,
            "cache.persist: WAL 写入失败，且当前**没有快照现场** ⇒ 已标记 resync\
             （下一拍走初始快照；本批事件已丢，无法写回）"
        );
        return Ok(0);
    };
    // 段数上限：与 `rotate_for_append` 同一条守卫（过渡态：本拍只请求快照，不轮转）。
    if let Some(m) = st.manifest.as_ref() {
        if m.wal_paths.len() >= ebpdns_cache::persist::manifest::MAX_WAL_SEGMENTS - 1 {
            tracing::error!(
                error = err,
                wal_segments = m.wal_paths.len(),
                "cache.persist: WAL 写入失败，且段数已达 manifest 上限 ⇒ 本拍只请求全量快照\
                 （resync 标记待下拍轮转）"
            );
            return Ok(0);
        }
    }
    // 2) 新段 base 必须严格大于已入队的所有 seq（否则回放侧会判 `seq not increasing`）。
    let base = st
        .last_wal_base
        .saturating_add(1)
        .max(st.journal.current_seq().saturating_add(1))
        .max(1);
    let name = format!("{}.wal.{base}", st.base);
    let w = WalWriter::create(&st.dir.join(&name), base, now_ms())
        .map_err(|e| format!("resync create wal: {e}"))?;
    // 3) R1 manifest：保留"仍含 snapshot_seq 之后记录"的段，再接上新段。
    let (mut wal_paths, mut wal_base_seq) = (Vec::new(), Vec::new());
    if let Some(m) = st.manifest.as_ref() {
        if m.wal_paths.len() == m.wal_base_seq.len() {
            let from = wal_keep_from(&m.wal_base_seq, snap.seq);
            for i in from..m.wal_paths.len() {
                wal_paths.push(m.wal_paths[i].clone());
                wal_base_seq.push(m.wal_base_seq[i]);
            }
        }
    }
    wal_paths.push(name.clone());
    wal_base_seq.push(base);
    let m = Manifest {
        flags: 0,
        seq: st.durable_seq.max(snap.seq),
        snapshot_seq: snap.seq,
        committed_ms: now_ms(),
        snap_bytes: snap.bytes,
        snap_crc32c: snap.crc,
        snap_entries: snap.entries,
        snap_path: snap.name.clone(),
        wal_paths,
        wal_base_seq,
        wal_bytes: w.bytes(),
    };
    atomic_write_bytes(
        &st.dir.join(&st.base),
        &m.encode().map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("resync manifest: {e}"))?;
    st.last_wal_base = base;
    st.wal = Some(w);
    st.wal_name = name;
    st.manifest = Some(m);
    st.needs_initial = false;
    tracing::error!(
        new_segment_base = base,
        error = err,
        "cache.persist: WAL 写入失败 ⇒ 已写 **resync 标记**（新段 base={base}，manifest 已更新）\
         并请求全量快照；本批事件不写回旧段（旧段尾部已截到最后一个完整记录）"
    );
    Ok(base)
}

/// 一次 `flush`：coalesce → 编码 → append → COMMIT → `fdatasync`（§6.2 的顺序）。
fn flush_batch(st: &mut ActorState, batch: Vec<Event>, overflow: bool) -> Result<(), String> {
    if overflow {
        // journal 溢出 ⇒ 本批 WAL 不可信 ⇒ 置“需要重同步”，由下一拍全量快照兜底。
        tracing::warn!(
            journal_dropped = st.journal.dropped(),
            "cache.persist: journal 溢出（丢弃事件）—— 下一拍改为**全量快照**（快照是权威，\
             截断/丢弃的 WAL 尾部不影响正确性）"
        );
        st.journal.request_snapshot("journal_overflow");
    }
    let events = coalesce(batch);
    if events.is_empty() {
        return Ok(());
    }
    // >>> 245 P1-2 encode-cap BEGIN
    // **2.1.45（P1-2 / REV247 P1-1）**：4 MiB 编码上限**不再静默丢弃剩余事件**。
    //
    // 旧实现 `break` 后只把前缀写进 WAL：剩余事件既没有 `request_snapshot`，也没有
    // `needs_resync`/计数，`flush_batch` 照样返回 `Ok` ⇒ 恢复侧看不到缺口（REV247 P1-1）。
    // 现在按 4 MiB **切块**：同一段内多写一条 COMMIT，每块各自 `append_bytes` +
    // `fdatasync`，整批事件全部落盘。只要发生过切块就：
    //   ① 打 `encode_cap_hit` 字段的 WARN（可观测，不新增持久化键）；
    //   ② `journal.request_snapshot("encode_cap_hit")` —— 请求**一次**全量快照兜底。
    let cap_bytes = MAX_RECORD_BYTES as usize * 4;
    let mut pending: std::collections::VecDeque<Event> = events.into();
    let mut durable_max_seq = 0u64;
    let mut encode_cap_hit = 0u32;
    // **2.1.46（REV247 B P1-7 剩余）**：单条事件不可编码（> MAX_RECORD_BYTES）时
    // 旧实现只打 WARN 就 `continue`，整批可能变成"空块成功"⇒ WAL 无记录、无快照请求。
    // 现在计入 `encode_skipped`，并在批次结束时请求全量快照兜底。
    let mut encode_skipped = 0u32;
    let mut chunk_err: Option<String> = None;
    if st.wal.is_none() {
        // 没有活动 WAL 时也必须让下一拍 compaction 重建现场（旧实现直接 Err，
        // 低流量下要等时间阈值/队列溢出才恢复，期间事件只在内存里堆积）。
        st.journal.request_snapshot("wal_missing");
        return Err("活动 WAL 段不存在".to_string());
    }
    {
        let wal = st.wal.as_mut().expect("wal checked above");
        while !pending.is_empty() {
            let mut buf: Vec<u8> = Vec::with_capacity(4096);
            let mut count = 0u32;
            let mut max_seq = 0u64;
            while let Some(ev) = pending.pop_front() {
                let seq = ev.seq();
                let enc = match &ev {
                    Event::Put { key, entry, .. } => {
                        let body = match EntryBody::from_entry(key, entry) {
                            Ok(b) => b,
                            Err(e) => {
                                encode_skipped += 1;
                                tracing::warn!("cache.persist: 跳过无法编码的 PUT（{e}）");
                                continue;
                            }
                        };
                        match wal::encode_put(seq, key, &body) {
                            Ok(b) => b,
                            Err(e) => {
                                encode_skipped += 1;
                                tracing::warn!("cache.persist: 跳过超限 PUT（{e}）");
                                continue;
                            }
                        }
                    }
                    Event::Evict { key, reason, .. } => {
                        match wal::encode_evict(seq, key, reason.code()) {
                            Ok(b) => b,
                            Err(e) => {
                                encode_skipped += 1;
                                tracing::warn!("cache.persist: 跳过超限 EVICT（{e}）");
                                continue;
                            }
                        }
                    }
                    Event::Clear { reason, .. } => wal::encode_clear(seq, reason.code()),
                };
                if !buf.is_empty() && buf.len() + enc.len() > cap_bytes {
                    // 当前块放不下 ⇒ **结算这一块**；把事件放回队首，下一块继续写（不丢）。
                    encode_cap_hit += 1;
                    pending.push_front(ev);
                    break;
                }
                max_seq = max_seq.max(seq);
                buf.extend_from_slice(&enc);
                count += 1;
            }
            if buf.is_empty() {
                break;
            }
            let bytes = buf.len() as u32;
            buf.extend_from_slice(&wal::encode_commit(max_seq, now_ms(), count, bytes));
            let mut chunk_io: Option<String> = None;
            if let Err(e) = wal.append_bytes(&buf) {
                let _ = wal.truncate_to_valid();
                chunk_io = Some(format!("append: {e}"));
            } else {
                // ①：记录已写入（可能只写了一半），**未 fsync**。
                fail_point("wal_after_write");
                if let Err(e) = wal.sync_data() {
                    let _ = wal.truncate_to_valid();
                    chunk_io = Some(format!("fdatasync: {e}"));
                }
            }
            // ②：记录 + COMMIT 已 fsync（应按“已 fsync 即可见”恢复）。
            fail_point("wal_after_fsync");
            if let Some(err) = chunk_io {
                chunk_err = Some(err);
                break;
            }
            durable_max_seq = durable_max_seq.max(max_seq);
        }
    }
    // **2.1.43-B（P2-5）**：WAL 追加/`fdatasync` 失败**不得静默丢整批**。
    // 失败 ⇒ 请求全量快照 + 换新段 base（见 [`resync_after_flush_failure`]）。
    if let Some(err) = chunk_err {
        let _ = resync_after_flush_failure(st, &err);
        return Err(err);
    }
    if encode_cap_hit > 0 || encode_skipped > 0 {
        tracing::warn!(
            encode_cap_hit,
            encode_skipped,
            cap_bytes,
            "cache.persist: 单批编码触发上限 ⇒ 已切块续写；不可编码的单条事件已跳过，\
             并请求一次全量快照兜底"
        );
        st.journal.request_snapshot(if encode_skipped > 0 {
            "encode_skipped"
        } else {
            "encode_cap_hit"
        });
    }
    // <<< 245 P1-2 encode-cap END
    let total = st.wal.as_ref().map(|w| w.bytes()).unwrap_or(0);
    st.error_logged = false;
    st.durable_seq = st.durable_seq.max(durable_max_seq);
    st.stats.set_durable_seq(st.durable_seq);
    st.stats.set_wal_bytes(total);
    st.stats.set_last_commit_ms(now_ms());
    let wal_name = st.wal_name.clone();
    let wal_base = st.wal.as_ref().map(|w| w.base_seq()).unwrap_or(0);
    if let Some(m) = st.manifest.as_mut() {
        m.seq = st.durable_seq;
        m.wal_bytes = total;
        if !wal_name.is_empty() && !m.wal_paths.iter().any(|p| p == &wal_name) {
            m.wal_paths.push(wal_name);
            m.wal_base_seq.push(wal_base);
        }
    }
    Ok(())
}

/// manifest 的原子写（`tmp → fsync → rename → fsync(dir)`）。
fn write_manifest(st: &mut ActorState, flags: u16) {
    let Some(mut m) = st.manifest.clone() else {
        return;
    };
    m.flags = flags;
    m.seq = st.durable_seq.max(m.seq);
    m.committed_ms = now_ms();
    let raw = match m.encode() {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("cache.persist: manifest 编码失败（{e}）");
            return;
        }
    };
    if let Err(e) = atomic_write_bytes(&st.dir.join(&st.base), &raw) {
        tracing::error!("cache.persist: 写 manifest 失败（{e}）");
        return;
    }
    st.stats.set_manifest_valid(true);
    st.stats.set_last_commit_ms(m.committed_ms);
    st.stats.set_snap_seq(m.snapshot_seq);
    st.stats.set_wal_bytes(m.wal_bytes);
    st.last_manifest_ms = m.committed_ms;
    st.manifest = Some(m);
}

/// 首次启动：写“当前快照 + 空 WAL + manifest”（§6.2）。
fn initial_compact(st: &mut ActorState) -> Result<(), String> {
    let s = st.journal.current_seq();
    let now = ebpdns_server::telemetry::now_epoch();
    let snap_name = format!("{}.snap.{s}", st.base);
    let tmp = st.dir.join(format!("{snap_name}.tmp"));
    let (meta, live) = write_snapshot_file(&st.cache, &tmp, s, now)?;
    st.stats.set_used_live(live);
    std::fs::rename(&tmp, st.dir.join(&snap_name)).map_err(|e| format!("rename snap: {e}"))?;
    fsync_dir(&st.dir);
    let wal_base = s.saturating_add(1).max(1);
    let wal_name = format!("{}.wal.{wal_base}", st.base);
    let ww = WalWriter::create(&st.dir.join(&wal_name), wal_base, now_ms())
        .map_err(|e| format!("create wal: {e}"))?;
    let wal_bytes = ww.bytes();
    // 直接沿用 `create` 返回的写入器（它已定位在段头之后）—— 不要再 drop 后重开：
    // 2.1.29 实测过一次 `EBADF`（重开时只带 `write` 却要读段头），且重开前的窗口里
    // manifest 已落盘而内存状态未同步，会让下一拍重复做初始 compact。
    st.wal = Some(ww);
    let m = Manifest {
        flags: 0,
        seq: s,
        snapshot_seq: s,
        committed_ms: now_ms(),
        snap_bytes: meta.file_len,
        snap_crc32c: meta.body_crc32c,
        snap_entries: meta.entry_count,
        snap_path: snap_name.clone(),
        wal_paths: vec![wal_name.clone()],
        wal_base_seq: vec![wal_base],
        wal_bytes,
    };
    atomic_write_bytes(
        &st.dir.join(&st.base),
        &m.encode().map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("manifest: {e}"))?;
    st.snapshot = Some(SnapInfo {
        name: snap_name,
        seq: s,
        bytes: meta.file_len,
        crc: meta.body_crc32c,
        entries: meta.entry_count,
    });
    st.last_wal_base = wal_base;
    st.last_snapshot_ms = now_ms();
    st.stats.set_snap_ms(st.last_snapshot_ms);
    st.wal_name = wal_name.clone();
    st.manifest = Some(m);
    st.needs_initial = false;
    st.stats.set_format(Format::V2);
    st.stats.set_manifest_valid(true);
    st.stats.set_snap_seq(s);
    st.stats.set_snap_bytes(meta.file_len);
    st.stats.set_snap_entries(meta.entry_count as u64);
    tracing::info!(
        snapshot_seq = s,
        snap_bytes = meta.file_len,
        entries = meta.entry_count,
        "cache.persist: 初始快照已写入（v2 生效）"
    );
    Ok(())
}

/// 为“要写第一批记录”创建新 WAL 段并写 R1 manifest（§6.2 `wal_count=0` 的情形）。
fn rotate_for_append(st: &mut ActorState) -> Result<(), String> {
    let Some(snap) = st.snapshot.clone() else {
        return Err("没有快照现场".to_string());
    };
    if let Some(m) = st.manifest.as_ref() {
        // >>> PATCH242A P1-3 rotate-guard BEGIN
        // 2.1.42（P1-3）：允许最多 MAX-1 个已有段（正常只有 1 个；R2 连续失败才累积）。
        if m.wal_paths.len() >= ebpdns_cache::persist::manifest::MAX_WAL_SEGMENTS - 1 {
            // **2.1.45（P2-5）**：段数达上限时**不得静默停写** —— 先请求一次全量快照
            // （下一拍 compaction 释放旧段），再拒绝本次轮转。
            st.journal.request_snapshot("wal_segments_full");
            return Err("WAL 段数已达 manifest 上限（过渡态），本拍不做轮转".to_string());
        }
        // <<< PATCH242A P1-3 rotate-guard END
    }
    let base = st
        .last_wal_base
        .saturating_add(1)
        .max(st.journal.current_seq().saturating_add(1))
        .max(1);
    let name = format!("{}.wal.{base}", st.base);
    let w = WalWriter::create(&st.dir.join(&name), base, now_ms())
        .map_err(|e| format!("create wal: {e}"))?;
    let mut wal_paths = vec![name.clone()];
    let mut wal_base_seq = vec![base];
    if let Some(m) = st.manifest.as_ref() {
        // >>> PATCH242A P1-3 rotate-retain BEGIN
        // 2.1.42（P1-3）：同样按 snapshot_seq 过滤，已完全被快照覆盖的前导段不再保留。
        if m.wal_paths.len() == m.wal_base_seq.len() {
            let from = wal_keep_from(&m.wal_base_seq, snap.seq);
            if from > 0 {
                tracing::info!(
                    dropped = from,
                    "cache.persist: 轮转丢弃已被快照覆盖的前导 WAL 段"
                );
            }
            for i in from..m.wal_paths.len() {
                let p = &m.wal_paths[i];
                if p != &name {
                    wal_paths.insert(wal_paths.len() - 1, p.clone());
                    wal_base_seq.insert(wal_base_seq.len() - 1, m.wal_base_seq[i]);
                }
            }
        }
        // <<< PATCH242A P1-3 rotate-retain END
    }
    let m = Manifest {
        flags: 0,
        seq: st.durable_seq.max(snap.seq),
        snapshot_seq: snap.seq,
        committed_ms: now_ms(),
        snap_bytes: snap.bytes,
        snap_crc32c: snap.crc,
        snap_entries: snap.entries,
        snap_path: snap.name.clone(),
        wal_paths,
        wal_base_seq,
        wal_bytes: w.bytes(),
    };
    atomic_write_bytes(
        &st.dir.join(&st.base),
        &m.encode().map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("manifest R1: {e}"))?;
    st.last_wal_base = base;
    st.wal = Some(w);
    st.wal_name = name.clone();
    st.manifest = Some(m);
    Ok(())
}

/// **2.1.37（T1）**：字节触发前的"条目变更比例"闸门。
///
/// 判据：`事件数(snap.seq..current) × 1000 >= 现存条目数 × COMPACT_CHANGE_PERMILLE`。
/// 只在**快照重写很贵**时生效（`snap.bytes > COMPACT_MIN_BYTES`）；小快照恒放行，
/// 因此 2.1.36 的小缓存合并行为不变，只是字节阈值 8 MiB → 2 MiB。
fn change_ratio_ok(st: &ActorState, snap: &SnapInfo) -> bool {
    if snap.bytes <= COMPACT_MIN_BYTES {
        return true;
    }
    let changed = st.journal.current_seq().saturating_sub(snap.seq);
    let live = (snap.entries as u64).max(1);
    changed.saturating_mul(1000) >= live.saturating_mul(COMPACT_CHANGE_PERMILLE)
}

fn should_compact(st: &ActorState, t: i64) -> bool {
    if st.inflight.is_some() {
        return false;
    }
    let Some(snap) = st.snapshot.as_ref() else {
        return false;
    };
    let cur = st.journal.current_seq();
    if cur <= snap.seq {
        return false; // 没有变化 ⇒ 不写（§6.3.1 规则 7）
    }
    let wal_bytes = st.wal.as_ref().map(|w| w.bytes()).unwrap_or(0);
    // **2.1.37（T1）**：字节触发 = 阈值 `max(2 MiB, snap_bytes)` **且**条目变更比例达标。
    if wal_bytes >= compact_threshold(snap.bytes) && change_ratio_ok(st, snap) {
        return true;
    }
    if wal_bytes >= wal_hard_max(snap.bytes) {
        return true;
    }
    // **2.1.34（D4）**：按**时间**触发快照，节拍 = `min(1800 s, TTL/2)`。
    //
    // 旧实现只有 8 MiB / 1800 s 两条阈值：低 churn 场景快照可能比 TTL 还老，
    // 恢复时大量条目已过期 ⇒ 重启后前几秒命中率塌陷（实测 −20.25 pp）。
    // 取 TTL/2 保证“快照年龄 ≤ TTL/2 时恢复，过期条目比例有界”；TTL 未配置
    // （0）或极小时保持原 1800 s 节拍（且不小于 5 s，避免写盘风暴）。
    let ttl_based = if st.ttl_s == 0 {
        COMPACT_MIN_INTERVAL_S
    } else {
        (st.ttl_s / 2).clamp(5, COMPACT_MIN_INTERVAL_S)
    };
    let interval = (COMPACT_MIN_INTERVAL_S * 1000) as i64;
    let interval = interval.min((ttl_based * 1000) as i64);
    t - st.last_snapshot_ms >= interval
}

// >>> PATCH242A P1-3 keep-from BEGIN
/// **2.1.42（P1-3）**：轮转时必须保留哪些 WAL 段。
///
/// 段 `i` 的 seq 范围是 `[base[i], base[i+1])`（最后一段无上界）。只要某段可能
/// 含 `seq > snap_seq` 的记录，就必须保留；已经**完全被快照覆盖**的前导段可以丢。
///
/// 返回第一个需要保留的下标（含）。旧的 `start_compaction` 只保留
/// `manifest.wal_paths.last()`：R2 失败后下轮 R1 会丢掉旧快照依赖的前段，
/// 此时崩溃 ⇒ `(S_old, S]` 整个 WAL 窗口丢失。
fn wal_keep_from(base_seq: &[u64], snap_seq: u64) -> usize {
    for i in 0..base_seq.len() {
        if i + 1 == base_seq.len() || base_seq[i + 1] > snap_seq {
            return i;
        }
    }
    0
}
// <<< PATCH242A P1-3 keep-from END

/// A 阶段（封段 + 轮转 + R1）同步做完，B 阶段（写快照）交给独立线程。
///
/// 返回 `true` = 已启动 B（`inflight = Some`）或**本来就不需要**新快照；`false` = A 阶段失败。
fn start_compaction(st: &mut ActorState, reason: &str) -> bool {
    if st.inflight.is_some() {
        return false;
    }
    let Some(snap) = st.snapshot.clone() else {
        return false;
    };
    let s = st.journal.current_seq();
    if s <= snap.seq {
        return true;
    }
    // A1：先 flush（本拍已 flush；这里只在有未 fsync 数据时兜底）。
    // A2/A3：新段（base = max(last+1, s+1)）。调用方已先把队列里**已入队**的事件
    // 全部写入旧段，因此 `s` 就是“已入队 max seq”，新段 base 严格更大。
    // >>> 245 P2-5 wal-cap BEGIN
    // **2.1.45（P2-5 / REV247 P2-1）**：先算"仍被旧快照依赖的必须保留段"，再决定能否新增段。
    //
    // 旧实现先创建新段，然后 `wal_paths.drain(0..drop_n)` 丢掉**最旧**的若干段 —— 即使
    // 它们仍含 `seq > snapshot_seq` 的记录（连续 R2 失败时就会发生）。那会让
    // `(S_old, S]` 整段 WAL 窗口静默丢失（只有一条 ERROR，无 metric）。
    // 现在：
    //   * 下界 = manifest 的 `snapshot_seq`（`wal_keep_from`），**绝不 drain** 依赖段；
    //   * 若"必须保留段 + 新段"会超过 `MAX_WAL_SEGMENTS`（8），本轮**不轮转**：
    //     直接把 B 阶段（写快照）跑完 —— R2 成功后 manifest 只引用当前段，段数回落到 1。
    //     这样既 fail-closed（不丢数据）又能自愈（旧实现只能在"丢段"与"停写"里二选一）。
    let max_keep = ebpdns_cache::persist::manifest::MAX_WAL_SEGMENTS - 1;
    let mut wal_paths = Vec::new();
    let mut wal_base_seq = Vec::new();
    if let Some(m) = st.manifest.as_ref() {
        if !m.wal_paths.is_empty() && m.wal_paths.len() == m.wal_base_seq.len() {
            let from = wal_keep_from(&m.wal_base_seq, snap.seq);
            for i in from..m.wal_paths.len() {
                wal_paths.push(m.wal_paths[i].clone());
                wal_base_seq.push(m.wal_base_seq[i]);
            }
        }
    }
    let rotate = wal_paths.len() <= max_keep;
    if !rotate {
        tracing::error!(
            needed = wal_paths.len(),
            cap = ebpdns_cache::persist::manifest::MAX_WAL_SEGMENTS,
            "cache.persist: WAL 段数达 manifest 上限，且**全部仍被旧快照依赖** ⇒ 本轮不轮转、\
             **不丢任何段**；直接写快照（R2 成功后旧段即释放）。请检查快照写入失败原因"
        );
    }
    if rotate {
        let base = st.last_wal_base.saturating_add(1).max(s + 1).max(1);
        let wal_name = format!("{}.wal.{base}", st.base);
        let new_wal = match WalWriter::create(&st.dir.join(&wal_name), base, now_ms()) {
            Ok(w) => w,
            Err(e) => {
                tracing::error!("cache.persist: compaction 创建新 WAL 段失败（{e}）—— 下一拍重试");
                return false;
            }
        };
        // A4：R1（旧快照 + [仍被旧快照依赖的旧段…, 新段]）。
        wal_paths.push(wal_name.clone());
        wal_base_seq.push(base);
        let r1 = Manifest {
            flags: 0,
            seq: st.durable_seq.max(snap.seq),
            snapshot_seq: snap.seq,
            committed_ms: now_ms(),
            snap_bytes: snap.bytes,
            snap_crc32c: snap.crc,
            snap_entries: snap.entries,
            snap_path: snap.name.clone(),
            wal_paths,
            wal_base_seq,
            wal_bytes: new_wal.bytes(),
        };
        if let Err(e) = atomic_write_bytes(
            &st.dir.join(&st.base),
            &match r1.encode() {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!("cache.persist: R1 编码失败（{e}）");
                    return false;
                }
            },
        ) {
            tracing::error!("cache.persist: R1 写失败（{e}）—— 不激活新段，继续用旧段");
            let _ = std::fs::remove_file(st.dir.join(&wal_name));
            return false;
        }
        st.last_wal_base = base;
        st.wal = Some(new_wal);
        st.wal_name = wal_name;
        st.manifest = Some(r1);
    }
    // <<< 245 P2-5 wal-cap END
    let generation = st.cache.generation();
    st.inflight = Some((generation, s));
    let cache = Arc::clone(&st.cache);
    let dir = st.dir.clone();
    let b = st.base.clone();
    let tx = st.tx.clone();
    let snap_name = format!("{b}.snap.{s}");
    let tmp = dir.join(format!("{snap_name}.tmp"));
    let spawned = std::thread::Builder::new()
        .name("ebpdns-cache-snapshot".to_string())
        .spawn(move || {
            let now = ebpdns_server::telemetry::now_epoch();
            match write_snapshot_file(&cache, &tmp, s, now) {
                Ok((meta, live)) => {
                    cache.persist_stats_arc().set_used_live(live);
                    let _ = tx.send(Cmd::SnapshotDone {
                        generation,
                        seq: s,
                        meta,
                        snap_name,
                        tmp,
                    });
                }
                Err(e) => {
                    let _ = tx.send(Cmd::SnapshotFailed { tmp, error: e });
                }
            }
        });
    if spawned.is_err() {
        st.inflight = None;
        tracing::error!("cache.persist: 无法启动快照线程（资源不足）—— 下一拍重试");
        false
    } else {
        tracing::info!(
            reason,
            snapshot_seq = s,
            wal_segment = st.last_wal_base,
            "cache.persist: compaction 已开始（A 阶段完成，B 阶段写快照中）"
        );
        true
    }
}

fn on_snapshot_done(
    st: &mut ActorState,
    generation: u64,
    seq: u64,
    meta: SnapshotMeta,
    snap_name: String,
    tmp: PathBuf,
) {
    st.inflight = None;
    if generation != st.cache.generation() {
        // B 期间发生了策略热切换/恢复：丢弃 tmp，用新 cache 重新 compact（§6.3.3）。
        let _ = std::fs::remove_file(&tmp);
        st.journal.request_snapshot("generation_changed");
        tracing::warn!("cache.persist: 快照期间缓存代际变化 ⇒ 丢弃本次快照并重新 compact");
        return;
    }
    if let Err(e) = std::fs::rename(&tmp, st.dir.join(&snap_name)) {
        tracing::error!(
            "cache.persist: rename 快照失败（{e}）—— 保留 R1（旧快照 + WAL），下一拍重试"
        );
        let _ = std::fs::remove_file(&tmp);
        return;
    }
    fsync_dir(&st.dir);
    // ④：快照已 rename、**R2 尚未写**（崩溃 ⇒ 新快照是孤儿，R1 仍自洽）。
    fail_point("snap_after_rename");
    let old_snap = st.snapshot.as_ref().map(|s| s.name.clone());
    let old_wals: Vec<String> = st
        .manifest
        .as_ref()
        .map(|m| m.wal_paths.clone())
        .unwrap_or_default();
    let keep_wal = st.wal_name.clone();
    let m = Manifest {
        flags: 0,
        seq: st.durable_seq.max(seq),
        snapshot_seq: seq,
        committed_ms: now_ms(),
        snap_bytes: meta.file_len,
        snap_crc32c: meta.body_crc32c,
        snap_entries: meta.entry_count,
        snap_path: snap_name.clone(),
        wal_paths: vec![keep_wal.clone()],
        wal_base_seq: vec![st.last_wal_base],
        wal_bytes: st.wal.as_ref().map(|w| w.bytes()).unwrap_or(0),
    };
    if let Err(e) = atomic_write_bytes(
        &st.dir.join(&st.base),
        &match m.encode() {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("cache.persist: R2 编码失败（{e}）");
                return;
            }
        },
    ) {
        tracing::error!("cache.persist: R2 写失败（{e}）—— 保留 R1，新快照成孤儿，下一拍重试");
        return;
    }
    // ⑤：manifest（R1/R2）已原子替换、目录已 fsync，**旧代尚未删除**。
    fail_point("manifest_after_rename");
    // 删除旧代（R2 已生效；删不完的是孤儿，启动清理）。
    if let Some(old) = old_snap {
        if old != snap_name {
            let _ = std::fs::remove_file(st.dir.join(&old));
        }
    }
    for w in old_wals {
        if w != keep_wal {
            let _ = std::fs::remove_file(st.dir.join(&w));
        }
    }
    fsync_dir(&st.dir);
    // ⑥：旧段/旧快照已删除（崩溃在此之后 ⇒ 新代已生效，残留是孤儿）。
    fail_point("after_old_unlink");
    st.snapshot = Some(SnapInfo {
        name: snap_name,
        seq,
        bytes: meta.file_len,
        crc: meta.body_crc32c,
        entries: meta.entry_count,
    });
    st.last_snapshot_ms = now_ms();
    st.stats.set_snap_ms(st.last_snapshot_ms);
    st.stats.set_snap_seq(seq);
    st.stats.set_snap_bytes(meta.file_len);
    st.stats.set_snap_entries(meta.entry_count as u64);
    st.stats.set_last_commit_ms(m.committed_ms);
    st.stats.set_manifest_valid(true);
    st.manifest = Some(m);
    tracing::info!(
        snapshot_seq = seq,
        snap_bytes = meta.file_len,
        entries = meta.entry_count,
        "cache.persist: compaction 完成（R2 已切换，旧代已回收）"
    );
}

/// 启动清理（H6/H8）：**只删不读** `.tmp` 与“未被 manifest 引用的孤儿”。
///
/// 永不删 manifest 当前/将要引用的文件。
fn cleanup_orphans(st: &ActorState) {
    let Ok(rd) = std::fs::read_dir(&st.dir) else {
        return;
    };
    let (snap, wals): (Option<String>, Vec<String>) = st
        .manifest
        .as_ref()
        .map(|m| (Some(m.snap_path.clone()), m.wal_paths.clone()))
        .unwrap_or((None, Vec::new()));
    let prefix_snap = format!("{}.snap.", st.base);
    let prefix_wal = format!("{}.wal.", st.base);
    let prefix_manifest_tmp = format!("{}.manifest.tmp", st.base);
    let mut removed = 0u32;
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        let is_tmp = name.ends_with(".tmp");
        if is_tmp {
            // `.tmp` 读方从不读 ⇒ 删掉（含 `*.snap.*.tmp` / `*.manifest.tmp` / 各种原子写残留）。
            if std::fs::remove_file(e.path()).is_ok() {
                removed += 1;
            }
            continue;
        }
        if name == st.base || name.starts_with(&format!("{}.v1.bak", st.base)) {
            continue;
        }
        if name.starts_with(&format!("{}.corrupt.", st.base)) {
            continue;
        }
        if name == prefix_manifest_tmp {
            continue;
        }
        let orphan = (name.starts_with(&prefix_snap) && Some(&name) != snap.as_ref())
            || (name.starts_with(&prefix_wal) && !wals.iter().any(|w| w == &name));
        if orphan && std::fs::remove_file(e.path()).is_ok() {
            removed += 1;
        }
    }
    if removed > 0 {
        tracing::info!(
            removed,
            "cache.persist: 启动清理删除了 {} 个孤儿/暂存文件（`.tmp` 与未被 manifest 引用的快照/WAL；只删不读）",
            removed
        );
    }
}

/// 供测试/运维用：把 v2 现场读一遍并返回条目数（**不写**）。
#[allow(dead_code)]
pub fn inspect_entries(file: &Path, persist_ttl: f64) -> Option<usize> {
    let (dir, base) = split_path(file)?;
    let now = ebpdns_server::telemetry::now_epoch();
    match recover_v2(&dir, &base, persist_ttl, now, false) {
        Ok(Some(p)) => Some(p.entries.len()),
        _ => None,
    }
}

/// 供测试/运维用：读 manifest 的 `snapshot_seq`（无 manifest ⇒ `None`）。
#[allow(dead_code)]
pub fn manifest_seq(file: &Path) -> Option<u64> {
    let (dir, base) = split_path(file)?;
    let raw = read_prefix(&dir.join(&base), MANIFEST_MAX_BYTES).ok()??;
    Manifest::decode(&raw, &base).ok().map(|m| m.snapshot_seq)
}

/// 供测试用：列出目录里的 `*.tmp`（崩溃后必须为 0）。
#[allow(dead_code)]
pub fn tmp_leftovers(dir: &Path) -> usize {
    std::fs::read_dir(dir)
        .map(|it| {
            it.filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
                .count()
        })
        .unwrap_or(0)
}

/// 供测试用：验证现场可完整扫描（快照 + 全部列出 WAL），返回 `(snapshot_entries, wal_records)`。
#[allow(dead_code)]
pub fn verify_scene(file: &Path) -> Result<(u32, u64), String> {
    let (dir, base) = split_path(file).ok_or("路径非法")?;
    let raw = read_prefix(&dir.join(&base), MANIFEST_MAX_BYTES)
        .map_err(|e| e.to_string())?
        .ok_or("manifest 不存在")?;
    let m = Manifest::decode(&raw, &base).map_err(|e| e.to_string())?;
    let r = SnapshotReader::open(&dir.join(&m.snap_path)).map_err(|e| e.to_string())?;
    let mut n = 0u32;
    r.for_each(&mut |_, _, _| {
        n += 1;
        Ok(())
    })
    .map_err(|e| e.to_string())?;
    let mut wal_records = 0u64;
    for (p, b) in m.wal_paths.iter().zip(m.wal_base_seq.iter()) {
        let mut wr = WalReader::open(&dir.join(p), *b).map_err(|_| "wal open failed")?;
        loop {
            match wr.next() {
                Ok(Some(WalItem::Rec(WalRec::Put { .. }))) => wal_records += 1,
                Ok(Some(WalItem::Rec(WalRec::Evict { .. }))) => wal_records += 1,
                Ok(Some(WalItem::Rec(WalRec::Clear { .. }))) => wal_records += 1,
                Ok(Some(WalItem::Rec(WalRec::Commit { .. }))) => {}
                Ok(Some(WalItem::BadContent)) => wal_records += 1,
                Ok(None) => break,
                Err(e) => return Err(format!("wal: {e:?}")),
            }
        }
    }
    Ok((n, wal_records))
}

// ============================ 自证/回归测试 ============================
//
// 编译期由 `#[cfg(test)]` 收口：这些用例与 `cargo test --workspace` 一起跑，
// 覆盖 actor 的可单测部分（合并、快照过滤、恢复对账、清理、只读路径）。

#[cfg(test)]
mod tests {
    use super::*;
    use ebpdns_cache::persist::journal::{ClearReason, EvictReason};
    use ebpdns_cache::CacheEntry;

    /* ------------------------- 2.1.45（P1-2 / P2-5） ------------------------- */

    /// 构造一个"1 条快照（seq=7）+ 1 个可写 WAL 段（base=8）"的真实 v2 现场。
    fn v2_scene(dir: &Tmp, tag_seq: u64) -> (Arc<SwappableCache>, String, Manifest, u64) {
        let now = ebpdns_server::telemetry::now_epoch();
        let cache = Arc::new(SwappableCache::new(Arc::new(ebpdns_cache::LruCache::new(
            1024,
        ))));
        cache.put(
            CacheKey::new("seed.test", "A"),
            entry("seed.test", now),
            now,
        );
        let snap_name = format!("{BASE}.snap.{tag_seq}");
        let tmp = dir.0.join(format!("{snap_name}.tmp"));
        let (meta, _live) = write_snapshot_file(&cache, &tmp, tag_seq, now).unwrap();
        std::fs::rename(&tmp, dir.0.join(&snap_name)).unwrap();
        let wal = format!("{BASE}.wal.{}", tag_seq + 1);
        let ww = WalWriter::create(&dir.0.join(&wal), tag_seq + 1, 1).unwrap();
        let wal_bytes = ww.bytes();
        drop(ww);
        let m = Manifest {
            flags: 0,
            seq: tag_seq,
            snapshot_seq: tag_seq,
            committed_ms: 1_700_000_000_000,
            snap_bytes: meta.file_len,
            snap_crc32c: meta.body_crc32c,
            snap_entries: meta.entry_count,
            snap_path: snap_name.clone(),
            wal_paths: vec![wal.clone()],
            wal_base_seq: vec![tag_seq + 1],
            wal_bytes,
        };
        atomic_write_bytes(&dir.file(), &m.encode().unwrap()).unwrap();
        let w = WalWriter::open_append(&dir.0.join(&wal), tag_seq + 1, wal_bytes).unwrap();
        drop(w);
        (cache, wal, m, wal_bytes)
    }

    /// **2.1.46（REV247 B P2-6）**：快照写盘必须在缓存锁**外**。
    ///
    /// 判别力：测试钩子在写盘循环里睡眠 250 ms；旧实现（`for_each_entry` 回调里写盘，
    /// TinyLFU 持整把 `inner` 锁）下，下面的 `cache.put` 会被同一把锁挡住 ≥250 ms；
    /// 新实现先收集 `Arc` 再放锁，`put` 在睡眠期间即可完成。
    #[test]
    fn snapshot_write_does_not_hold_cache_lock() {
        use std::sync::atomic::Ordering;
        let dir = Tmp::new("snaplock");
        let now = ebpdns_server::telemetry::now_epoch();
        let cache = Arc::new(SwappableCache::new(Arc::new(
            ebpdns_cache::TinyLfuCache::new(1024),
        )));
        for d in ["a.test", "b.test", "c.test"] {
            cache.put(CacheKey::new(d, "A"), entry(d, now), now);
        }
        SNAPSHOT_WRITE_DELAY_MS.store(250, Ordering::SeqCst);
        SNAPSHOT_WRITE_ENTERED.store(false, Ordering::SeqCst);
        let tmp = dir.0.join("lock.snap.tmp");
        let c2 = Arc::clone(&cache);
        let t = std::thread::spawn(move || write_snapshot_file(&c2, &tmp, u64::MAX, now));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !SNAPSHOT_WRITE_ENTERED.load(Ordering::SeqCst) {
            assert!(
                std::time::Instant::now() < deadline,
                "快照写循环未在 2s 内开始"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let t0 = std::time::Instant::now();
        cache.put(
            CacheKey::new("during-snapshot.test", "A"),
            entry("during-snapshot.test", now),
            now,
        );
        let put_ms = t0.elapsed().as_millis();
        assert!(
            put_ms < 150,
            "快照写盘期间 cache.put 被缓存锁阻塞 {put_ms} ms（旧实现持锁写盘）"
        );
        t.join().unwrap().unwrap();
        SNAPSHOT_WRITE_DELAY_MS.store(0, Ordering::SeqCst);
        SNAPSHOT_WRITE_ENTERED.store(false, Ordering::SeqCst);
    }

    /// **2.1.46（REV247 P2-6）**：坏段证据存在时的文案必须与 P1-2 的"允许写"一致。
    /// 旧文案"本次禁用 v2 写"会让运维误判坏证据导致不再落盘；这里直接钉住日志源文本。
    #[test]
    fn corrupt_present_note_says_writes_are_allowed() {
        let src = include_str!("cache_persist.rs");
        assert!(
            src.contains("**本次仍允许写出新世代**"),
            "文案必须明确允许写"
        );
        let bad = concat!("本次", "**禁用 v2 写**");
        assert!(
            !src.contains(bad),
            "不得再声称坏段证据会禁用 v2 写（REV247 P2-6 的原缺陷）"
        );
    }

    /// **2.1.45（P1-2 / REV247 P1-1）**：单批编码量 > 4 MiB 时**不得静默丢事件** ——
    /// 必须切块续写（恢复计数 == 写入计数）并请求**一次**全量快照（`encode_cap_hit`）。
    ///
    /// 判别力：旧实现 `break` 后 `flush_batch` 返回 `Ok`，WAL 里只剩前缀
    /// ⇒ `wal_records < 5000` 且 `take_snapshot_request() == None`。
    #[test]
    fn encode_cap_splits_batch_and_requests_one_snapshot() {
        let dir = Tmp::new("enccap");
        let now = ebpdns_server::telemetry::now_epoch();
        let (cache, wal_name, m, wal_bytes) = v2_scene(&dir, 7);
        let (j, _rx) = CacheJournal::new(PersistStats::new());
        j.set_next_seq_at_least(9);
        let st_wal = WalWriter::open_append(&dir.0.join(&wal_name), 8, wal_bytes).unwrap();
        let mut st = ActorState {
            dir: dir.0.clone(),
            base: BASE.to_string(),
            cache: Arc::clone(&cache),
            journal: j.clone(),
            stats: PersistStats::new(),
            tx: channel::<Cmd>().0,
            plan: None,
            wal: Some(st_wal),
            wal_name,
            manifest: Some(m),
            snapshot: Some(SnapInfo {
                name: format!("{BASE}.snap.7"),
                seq: 7,
                bytes: 1,
                crc: 1,
                entries: 1,
            }),
            durable_seq: 7,
            last_wal_base: 8,
            last_manifest_ms: 0,
            last_snapshot_ms: now_ms(),
            needs_initial: false,
            inflight: None,
            error_logged: false,
            journal_off: false,
            ttl_s: 300,
        };
        // 每条 ≈ 1 KiB（900 B 答案 + key/头）⇒ 5000 条约 5 MiB > 4 MiB 上限。
        let big = "x".repeat(900);
        let n = 5000usize;
        let mut batch = Vec::with_capacity(n);
        for i in 0..n {
            let name = format!("cap{i}.test");
            let mut e = entry(&name, now);
            e.answers = vec![ebpdns_cache::CacheAnswer {
                value: big.clone(),
                ttl: 300.0,
                rtype: 1,
                name: None,
            }];
            batch.push(Event::Put {
                seq: j.next_seq(),
                key: CacheKey::new(&name, "A"),
                entry: Arc::new(e),
            });
        }
        flush_batch(&mut st, batch, false).expect("切块续写必须成功");
        let (_snap_entries, wal_records) = verify_scene(&dir.file()).unwrap();
        assert_eq!(
            wal_records, n as u64,
            "全部事件必须落盘（恢复计数 == 写入计数；旧实现只剩 4 MiB 前缀）"
        );
        assert_eq!(
            j.take_snapshot_request(),
            Some("encode_cap_hit"),
            "必须请求**一次**全量快照（encode_cap_hit）"
        );
        assert_eq!(
            j.take_snapshot_request(),
            None,
            "只能请求一次（不得每块都请求）"
        );
    }

    /// **2.1.46（REV247 B P1-7 剩余 / B P2-1）**：没有活动 WAL 时，`flush_batch`
    /// 必须**先请求快照**再返回错误（旧实现只 Err，低流量下会一直停写到时间阈值）。
    #[test]
    fn flush_without_wal_requests_snapshot() {
        let dir = Tmp::new("nowal");
        let now = ebpdns_server::telemetry::now_epoch();
        let (cache, wal_name, m, wal_bytes) = v2_scene(&dir, 7);
        let (j, _rx) = CacheJournal::new(PersistStats::new());
        j.set_next_seq_at_least(9);
        let mut st = ActorState {
            dir: dir.0.clone(),
            base: BASE.to_string(),
            cache,
            journal: j.clone(),
            stats: PersistStats::new(),
            tx: channel::<Cmd>().0,
            plan: None,
            wal: None,
            wal_name,
            manifest: Some(m),
            snapshot: Some(SnapInfo {
                name: format!("{BASE}.snap.7"),
                seq: 7,
                bytes: 1,
                crc: 1,
                entries: 1,
            }),
            durable_seq: 7,
            last_wal_base: 8,
            last_manifest_ms: 0,
            last_snapshot_ms: now_ms(),
            needs_initial: false,
            inflight: None,
            error_logged: false,
            journal_off: false,
            ttl_s: 300,
        };
        let e = Event::Put {
            seq: 9,
            key: CacheKey::new("nowal.test", "A"),
            entry: Arc::new(entry("nowal.test", now)),
        };
        let err = flush_batch(&mut st, vec![e], false).unwrap_err();
        assert!(err.contains("WAL"), "{err}");
        assert_eq!(
            j.take_snapshot_request(),
            Some("wal_missing"),
            "缺 WAL 必须请求全量快照（不得静默停写）"
        );
        let _ = wal_bytes;
    }

    /// **2.1.46（REV247 B P1-7 剩余）**：单条事件不可编码（> 1 MiB 记录上限）时，
    /// 旧实现只 WARN + `continue`，整批可能"空块成功"且不请求快照；现在必须请求快照。
    #[test]
    fn unencodable_event_requests_snapshot_instead_of_silent_loss() {
        let dir = Tmp::new("encskip");
        let now = ebpdns_server::telemetry::now_epoch();
        let (cache, wal_name, m, wal_bytes) = v2_scene(&dir, 7);
        let (j, _rx) = CacheJournal::new(PersistStats::new());
        j.set_next_seq_at_least(9);
        let st_wal = WalWriter::open_append(&dir.0.join(&wal_name), 8, wal_bytes).unwrap();
        let mut st = ActorState {
            dir: dir.0.clone(),
            base: BASE.to_string(),
            cache,
            journal: j.clone(),
            stats: PersistStats::new(),
            tx: channel::<Cmd>().0,
            plan: None,
            wal: Some(st_wal),
            wal_name,
            manifest: Some(m),
            snapshot: Some(SnapInfo {
                name: format!("{BASE}.snap.7"),
                seq: 7,
                bytes: 1,
                crc: 1,
                entries: 1,
            }),
            durable_seq: 7,
            last_wal_base: 8,
            last_manifest_ms: 0,
            last_snapshot_ms: now_ms(),
            needs_initial: false,
            inflight: None,
            error_logged: false,
            journal_off: false,
            ttl_s: 300,
        };
        let mut e = entry("huge.test", now);
        e.answers = vec![ebpdns_cache::CacheAnswer {
            // EntryBody/WAL 的硬上限是 1 MiB，2 MiB 必然不可编码。
            value: "x".repeat(2 * 1024 * 1024),
            ttl: 300.0,
            rtype: 1,
            name: None,
        }];
        let ev = Event::Put {
            seq: 9,
            key: CacheKey::new("huge.test", "A"),
            entry: Arc::new(e),
        };
        flush_batch(&mut st, vec![ev], false).expect("单条不可编码不得让整批失败");
        assert_eq!(
            j.take_snapshot_request(),
            Some("encode_skipped"),
            "跳过不可编码事件必须请求全量快照（旧实现静默返回 Ok）"
        );
    }

    /// **2.1.45（P2-5 / REV247 P2-1）**：WAL 段数达 `MAX_WAL_SEGMENTS` 且**全部仍被
    /// 旧快照依赖**时，不得丢段（旧实现 `drain(0..n)` 会丢掉仍含 `seq > snap_seq`
    /// 的段 ⇒ `(S_old, S]` 静默丢失），也不得新增第 9 段（manifest 无法编码）。
    /// 正确行为：本轮**不轮转**，直接进入 B 阶段写快照（R2 成功后段数回落）。
    #[test]
    fn wal_segment_cap_never_drops_snapshot_dependent_segments() {
        let dir = Tmp::new("walcap");
        let cache = Arc::new(SwappableCache::new(Arc::new(ebpdns_cache::LruCache::new(
            64,
        ))));
        let mut wal_paths = Vec::new();
        let mut bases = Vec::new();
        for b in 2..10u64 {
            let name = format!("{BASE}.wal.{b}");
            let w = WalWriter::create(&dir.0.join(&name), b, 1).unwrap();
            drop(w);
            wal_paths.push(name);
            bases.push(b);
        }
        // snapshot_seq=1、8 段 base 全部 > 1 ⇒ 每段都可能含 seq > snap_seq。
        let m = Manifest {
            flags: 0,
            seq: 20,
            snapshot_seq: 1,
            committed_ms: 1,
            snap_bytes: 1,
            snap_crc32c: 1,
            snap_entries: 1,
            snap_path: format!("{BASE}.snap.1"),
            wal_paths: wal_paths.clone(),
            wal_base_seq: bases.clone(),
            wal_bytes: 1,
        };
        atomic_write_bytes(&dir.file(), &m.encode().unwrap()).unwrap();
        let (j, _rx) = CacheJournal::new(PersistStats::new());
        j.set_next_seq_at_least(21);
        let last = wal_paths[7].clone();
        let last_len = std::fs::metadata(dir.0.join(&last)).unwrap().len();
        let st_wal = WalWriter::open_append(&dir.0.join(&last), 9, last_len).unwrap();
        let mut st = ActorState {
            dir: dir.0.clone(),
            base: BASE.to_string(),
            cache,
            journal: j,
            stats: PersistStats::new(),
            tx: channel::<Cmd>().0,
            plan: None,
            wal: Some(st_wal),
            wal_name: last,
            manifest: Some(m),
            snapshot: Some(SnapInfo {
                name: format!("{BASE}.snap.1"),
                seq: 1,
                bytes: 1,
                crc: 1,
                entries: 1,
            }),
            durable_seq: 20,
            last_wal_base: 9,
            last_manifest_ms: 0,
            last_snapshot_ms: now_ms(),
            needs_initial: false,
            inflight: None,
            error_logged: false,
            journal_off: false,
            ttl_s: 300,
        };
        assert!(
            start_compaction(&mut st, "wal_segments_full"),
            "必须进入 B 阶段（写快照）而不是丢段/停写"
        );
        let after = st.manifest.as_ref().unwrap();
        assert_eq!(
            after.wal_paths, wal_paths,
            "仍被旧快照依赖的段**一条都不得丢**"
        );
        assert!(
            !dir.0.join(format!("{BASE}.wal.10")).exists(),
            "不得新增第 9 段（manifest 上限 8，无法编码）"
        );
        assert!(st.inflight.is_some(), "B 阶段必须已启动");
    }
    const BASE: &str = "ebpdns-cache.json";

    struct Tmp(std::path::PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "ebpdns-cp-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn file(&self) -> std::path::PathBuf {
            self.0.join(BASE)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn entry(name: &str, now: f64) -> CacheEntry {
        let mut e = CacheEntry::new(name, "A", 300.0, now);
        e.expires_at = now + 300.0;
        e.seq = 0;
        e
    }

    /// `coalesce`：CLEAR 之前的丢弃、同 key 后写胜、输出按 seq 升序。
    #[test]
    fn coalesce_rules() {
        let now = 1_700_000_000.0;
        let k1 = CacheKey::new("a.test", "A");
        let k2 = CacheKey::new("b.test", "A");
        let ev = vec![
            Event::Put {
                seq: 1,
                key: k1.clone(),
                entry: Arc::new(entry("a.test", now)),
            },
            Event::Put {
                seq: 3,
                key: k1.clone(),
                entry: Arc::new(entry("a.test", now)),
            },
            Event::Evict {
                seq: 2,
                key: k2.clone(),
                reason: EvictReason::Capacity,
            },
            Event::Clear {
                seq: 4,
                reason: ClearReason::Admin,
            },
            Event::Put {
                seq: 5,
                key: k2.clone(),
                entry: Arc::new(entry("b.test", now)),
            },
        ];
        let out = coalesce(ev);
        // seq 4 的 CLEAR 之前全部被丢弃 ⇒ 只剩 CLEAR@4 + PUT@5
        assert_eq!(out.len(), 2, "输出: {out:?}");
        assert_eq!(out[0].seq(), 4);
        assert_eq!(out[1].seq(), 5);
        assert!(matches!(out[0], Event::Clear { .. }));
    }

    #[test]
    fn coalesce_same_key_keeps_max_seq() {
        let now = 1_700_000_000.0;
        let k = CacheKey::new("a.test", "A");
        let ev = vec![
            Event::Put {
                seq: 9,
                key: k.clone(),
                entry: Arc::new(entry("a.test", now)),
            },
            Event::Evict {
                seq: 10,
                key: k.clone(),
                reason: EvictReason::Capacity,
            },
            Event::Put {
                seq: 8,
                key: k.clone(),
                entry: Arc::new(entry("a.test", now)),
            },
        ];
        let out = coalesce(ev);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].seq(), 10);
        assert!(matches!(out[0], Event::Evict { .. }));
    }

    /// 快照只收录 `entry.seq <= S`（§6.3.4 的核心过滤）—— 省略它会复活已逐出条目。
    #[test]
    fn snapshot_filters_by_entry_seq() {
        let dir = Tmp::new("snapfilter");
        // 用真实时钟：恢复侧用 `telemetry::now_epoch()`，假时间会让条目看起来早已过期。
        let now = ebpdns_server::telemetry::now_epoch();
        let cache = Arc::new(SwappableCache::new(Arc::new(ebpdns_cache::LruCache::new(
            1024,
        ))));
        // seq 由 journal 分配 ⇒ 必须先 `enable_journal()`（生产里由 v2 启动序列做），
        // 再用 `set_next_seq_at_least` 精确摆位：1 / 5 / 9。
        let rx = cache.enable_journal();
        let j = cache.journal();
        for (i, want) in [(0usize, 1u64), (1, 5), (2, 9)] {
            j.set_next_seq_at_least(want - 1);
            let name = format!("d{i}.test");
            cache.put(CacheKey::new(&name, "A"), entry(&name, now), now);
        }
        drop(rx);
        let tmp = dir.0.join(format!("{BASE}.snap.5.tmp"));
        let (meta, live) = write_snapshot_file(&cache, &tmp, 5, now).unwrap();
        assert_eq!(live, 3, "三条都未过期 ⇒ used_live=3");
        assert_eq!(meta.entry_count, 2, "只有 seq<=5 的两条应进快照");
        let r = SnapshotReader::open(&tmp).unwrap();
        let mut seqs = Vec::new();
        r.for_each(&mut |s, _, _| {
            seqs.push(s);
            Ok(())
        })
        .unwrap();
        seqs.sort();
        assert_eq!(seqs, vec![1, 5]);
    }

    /// 迁移/恢复对账工具的自证：`manifest_seq` / `inspect_entries` / `verify_scene`
    /// / `tmp_leftovers` 在一套真实 v2 现场上的读数自洽。
    #[test]
    fn scene_helpers_agree() {
        let dir = Tmp::new("helpers");
        let now = ebpdns_server::telemetry::now_epoch();
        let cache = Arc::new(SwappableCache::new(Arc::new(ebpdns_cache::LruCache::new(
            1024,
        ))));
        cache.put(CacheKey::new("a.test", "A"), entry("a.test", now), now);
        let snap_name = format!("{BASE}.snap.7");
        let tmp = dir.0.join(format!("{snap_name}.tmp"));
        let (meta, _live) = write_snapshot_file(&cache, &tmp, 7, now).unwrap();
        assert_eq!(meta.entry_count, 1);
        std::fs::rename(&tmp, dir.0.join(&snap_name)).unwrap();
        let wal_name = format!("{BASE}.wal.8");
        let ww = WalWriter::create(&dir.0.join(&wal_name), 8, 1).unwrap();
        let wal_bytes = ww.bytes();
        drop(ww);
        let m = Manifest {
            flags: 0,
            seq: 7,
            snapshot_seq: 7,
            committed_ms: 1_700_000_000_000,
            snap_bytes: meta.file_len,
            snap_crc32c: meta.body_crc32c,
            snap_entries: meta.entry_count,
            snap_path: snap_name,
            wal_paths: vec![wal_name],
            wal_base_seq: vec![8],
            wal_bytes,
        };
        atomic_write_bytes(&dir.file(), &m.encode().unwrap()).unwrap();
        assert_eq!(manifest_seq(&dir.file()), Some(7));
        assert_eq!(inspect_entries(&dir.file(), 0.0), Some(1));
        assert_eq!(verify_scene(&dir.file()).unwrap(), (1, 0));
        assert_eq!(tmp_leftovers(&dir.0), 0);
    }

    /// 启动清理：`.tmp` 与“未被 manifest 引用的孤儿”被删；引用文件与 `.v1.bak` 保留。
    #[test]
    fn cleanup_only_removes_orphans_and_tmp() {
        let dir = Tmp::new("cleanup");
        let base = BASE;
        // 引用文件
        let kept_snap = format!("{base}.snap.3");
        let kept_wal = format!("{base}.wal.4");
        std::fs::write(dir.0.join(&kept_snap), b"x").unwrap();
        std::fs::write(dir.0.join(&kept_wal), b"x").unwrap();
        // 孤儿 + tmp + .v1.bak + .corrupt
        std::fs::write(dir.0.join(format!("{base}.snap.2")), b"x").unwrap();
        std::fs::write(dir.0.join(format!("{base}.wal.1")), b"x").unwrap();
        std::fs::write(dir.0.join(format!("{base}.snap.9.tmp")), b"x").unwrap();
        std::fs::write(dir.0.join(format!("{base}.v1.bak")), b"[]").unwrap();
        std::fs::write(dir.0.join(format!("{base}.corrupt.123")), b"x").unwrap();
        std::fs::write(dir.file(), b"x").unwrap();

        let st = ActorState {
            dir: dir.0.clone(),
            base: base.to_string(),
            cache: Arc::new(SwappableCache::new(Arc::new(ebpdns_cache::LruCache::new(
                16,
            )))),
            journal: CacheJournal::disabled(),
            stats: PersistStats::new(),
            tx: channel::<Cmd>().0,
            plan: None,
            wal: None,
            wal_name: String::new(),
            manifest: Some(Manifest {
                flags: 0,
                seq: 3,
                snapshot_seq: 3,
                committed_ms: 1,
                snap_bytes: 1,
                snap_crc32c: 1,
                snap_entries: 1,
                snap_path: kept_snap.clone(),
                wal_paths: vec![kept_wal.clone()],
                wal_base_seq: vec![4],
                wal_bytes: 1,
            }),
            snapshot: None,
            durable_seq: 3,
            last_wal_base: 4,
            last_manifest_ms: 0,
            last_snapshot_ms: 0,
            needs_initial: false,
            inflight: None,
            error_logged: false,
            journal_off: false,
            ttl_s: 300,
        };
        cleanup_orphans(&st);
        assert!(dir.0.join(&kept_snap).exists(), "引用的快照不得删除");
        assert!(dir.0.join(&kept_wal).exists(), "引用的 WAL 不得删除");
        assert!(
            dir.0.join(format!("{base}.v1.bak")).exists(),
            ".v1.bak 永不自动删除"
        );
        assert!(
            dir.0.join(format!("{base}.corrupt.123")).exists(),
            "损坏现场不得删除"
        );
        assert!(
            !dir.0.join(format!("{base}.snap.2")).exists(),
            "孤儿快照应删除"
        );
        assert!(
            !dir.0.join(format!("{base}.wal.1")).exists(),
            "孤儿 WAL 应删除"
        );
        assert!(
            !dir.0.join(format!("{base}.snap.9.tmp")).exists(),
            "tmp 应删除"
        );
        assert_eq!(tmp_leftovers(&dir.0), 0);
    }

    /// **2.1.43-B（P2-5）回归**：WAL 追加/fsync 失败后必须落 **resync 标记**
    /// （新段 `base`），不得只打一条日志就把整批事件吞掉。
    ///
    /// 四条断言（全部是"磁盘/内存现场"，不依赖日志）：
    /// ① 新段文件被创建，且 `base` 严格大于旧段 base 与 `journal.current_seq()`；
    /// ② manifest（内存 + 磁盘）已引用新段，`snapshot_seq` 不变（R1 语义）；
    /// ③ `journal` 收到 `wal_resync` 全量快照请求（权威兜底）；
    /// ④ 随后 `flush_batch` 成功，记录真的写进**新段**（`verify_scene` 数得到 1 条）。
    #[test]
    fn flush_failure_writes_resync_marker_and_new_segment() {
        let dir = Tmp::new("resync");
        let now = ebpdns_server::telemetry::now_epoch();
        // --- 真实 v2 现场：1 条快照（seq=7）+ 旧 WAL 段（base=8）---
        let cache = Arc::new(SwappableCache::new(Arc::new(ebpdns_cache::LruCache::new(
            1024,
        ))));
        cache.put(
            CacheKey::new("seed.test", "A"),
            entry("seed.test", now),
            now,
        );
        let snap_name = format!("{BASE}.snap.7");
        let tmp = dir.0.join(format!("{snap_name}.tmp"));
        let (meta, _live) = write_snapshot_file(&cache, &tmp, 7, now).unwrap();
        std::fs::rename(&tmp, dir.0.join(&snap_name)).unwrap();
        let old_wal = format!("{BASE}.wal.8");
        let ww = WalWriter::create(&dir.0.join(&old_wal), 8, 1).unwrap();
        let old_bytes = ww.bytes();
        drop(ww);
        let m = Manifest {
            flags: 0,
            seq: 7,
            snapshot_seq: 7,
            committed_ms: 1_700_000_000_000,
            snap_bytes: meta.file_len,
            snap_crc32c: meta.body_crc32c,
            snap_entries: meta.entry_count,
            snap_path: snap_name.clone(),
            wal_paths: vec![old_wal.clone()],
            wal_base_seq: vec![8],
            wal_bytes: old_bytes,
        };
        atomic_write_bytes(&dir.file(), &m.encode().unwrap()).unwrap();

        let (j, _rx) = CacheJournal::new(PersistStats::new());
        j.set_next_seq_at_least(9); // 下一个 seq = 9 ⇒ 新段 base 必须 ≥ 10
        let st_wal = WalWriter::open_append(&dir.0.join(&old_wal), 8, old_bytes).unwrap();
        let mut st = ActorState {
            dir: dir.0.clone(),
            base: BASE.to_string(),
            cache: Arc::clone(&cache),
            journal: j.clone(),
            stats: PersistStats::new(),
            tx: channel::<Cmd>().0,
            plan: None,
            wal: Some(st_wal),
            wal_name: old_wal.clone(),
            manifest: Some(m),
            snapshot: Some(SnapInfo {
                name: snap_name,
                seq: 7,
                bytes: meta.file_len,
                crc: meta.body_crc32c,
                entries: meta.entry_count,
            }),
            durable_seq: 7,
            last_wal_base: 8,
            last_manifest_ms: 0,
            last_snapshot_ms: now_ms(),
            needs_initial: false,
            inflight: None,
            error_logged: false,
            journal_off: false,
            ttl_s: 300,
        };

        // 模拟一次 append 失败后的重同步（flush_batch 的失败分支调的就是它）。
        let base = resync_after_flush_failure(&mut st, "append: ENOSPC").unwrap();
        assert_eq!(
            base, 10,
            "新段 base = max(last_wal_base+1, current_seq+1) = 10"
        );
        assert_eq!(st.last_wal_base, 10);
        assert_eq!(st.wal_name, format!("{BASE}.wal.10"));
        assert!(
            dir.0.join(format!("{BASE}.wal.10")).exists(),
            "resync 必须真的创建新段文件"
        );
        // ② manifest（内存 + 磁盘）都引用新段，快照不动。
        let m2 = st.manifest.clone().expect("manifest");
        assert_eq!(m2.snapshot_seq, 7, "R1：快照不变");
        assert!(
            m2.wal_paths.iter().any(|p| p == &format!("{BASE}.wal.10")),
            "manifest 必须引用新段：{:?}",
            m2.wal_paths
        );
        let disk = Manifest::decode(&std::fs::read(dir.file()).unwrap(), BASE)
            .expect("磁盘 manifest 必须可解码");
        assert_eq!(disk.wal_base_seq.last().copied(), Some(10));
        // ③ 全量快照请求（不是只打日志）。
        assert_eq!(
            j.take_snapshot_request(),
            Some("wal_resync"),
            "必须请求 /api 侧的全量快照兜底"
        );
        // ④ 下一批真的写进新段。
        let ev = Event::Put {
            seq: j.next_seq(),
            key: CacheKey::new("after-resync.test", "A"),
            entry: Arc::new(entry("after-resync.test", now)),
        };
        flush_batch(&mut st, vec![ev], false).expect("resync 之后的批次必须成功");
        let (snap_entries, wal_records) = verify_scene(&dir.file()).unwrap();
        assert_eq!(snap_entries, 1, "快照仍是原来那 1 条");
        assert_eq!(
            wal_records, 1,
            "resync 之后的 1 条记录必须落在新段（可被恢复侧数到）"
        );
        assert!(
            std::fs::metadata(dir.0.join(format!("{BASE}.wal.8")))
                .map(|m| m.len())
                .unwrap_or(u64::MAX)
                >= old_bytes,
            "旧段不得被 resync 删除/截断到段头之前"
        );
    }

    /// **2.1.34（D4）回归**：按**时间**触发快照 —— 节拍 = `min(1800 s, TTL/2)`。
    ///
    /// 旧实现只有 8 MiB / 1800 s：低 churn 场景快照可能比缓存 TTL 还老，恢复时
    /// 大量条目已过期（实测重启后 5 s 命中率 −20.25 pp）。
    #[test]
    fn compact_interval_follows_ttl_half() {
        let dir = Tmp::new("ttlhalf");
        let (j, _rx) = CacheJournal::new(PersistStats::new());
        j.set_next_seq_at_least(10); // 有变更（> snapshot_seq）
        let now = now_ms();
        let mut st = ActorState {
            dir: dir.0.clone(),
            base: BASE.to_string(),
            cache: Arc::new(SwappableCache::new(Arc::new(ebpdns_cache::LruCache::new(
                16,
            )))),
            journal: j,
            stats: PersistStats::new(),
            tx: channel::<Cmd>().0,
            plan: None,
            wal: None,
            wal_name: String::new(),
            manifest: None,
            snapshot: Some(SnapInfo {
                name: format!("{BASE}.snap.1"),
                seq: 1,
                bytes: 1024,
                crc: 1,
                entries: 1,
            }),
            durable_seq: 10,
            last_wal_base: 1,
            last_manifest_ms: 0,
            last_snapshot_ms: now - 151_000,
            needs_initial: false,
            inflight: None,
            error_logged: false,
            journal_off: false,
            ttl_s: 300,
        };
        // TTL=300 ⇒ 150 s 节拍：151 s 前写过快照 ⇒ 必须触发。
        assert!(
            should_compact(&st, now),
            "距上次快照 151 s（> TTL/2=150 s）必须按时间触发快照"
        );
        // 10 s 前才写过 ⇒ 不触发（也没有 8 MiB WAL）。
        st.last_snapshot_ms = now - 10_000;
        assert!(!should_compact(&st, now), "距上次快照 10 s 不应触发");
        // TTL 未配置（0）⇒ 保持原 1800 s 节拍。
        st.ttl_s = 0;
        st.last_snapshot_ms = now - 200_000;
        assert!(!should_compact(&st, now), "TTL=0 时保持 1800 s 节拍");
    }

    /// **2.1.29 / 长稳审计 P3**：`used` 与 `used_live` 的口径差异 + 快照条目数。
    ///
    /// 构造 N=10 条，其中 K=5 条 `expires_at <= now`（**未被惰性清理**）⇒
    /// `summary().used == 10`、`used_live == 5`、快照 `entry_count == 5`。
    /// 并用同一组数验证"恢复丢失率必须按 `used_live` 算"这条口径。
    #[test]
    fn used_live_excludes_expired_but_used_does_not() {
        let dir = Tmp::new("usedlive");
        let now = ebpdns_server::telemetry::now_epoch();
        let cache = Arc::new(SwappableCache::new(Arc::new(ebpdns_cache::LruCache::new(
            1024,
        ))));
        // 10 条：偶数号已过期（put 不做过期检查；put_count < 32 也不会触发 purge）
        for i in 0..10usize {
            let name = format!("u{i}.test");
            let mut e = entry(&name, now);
            if i % 2 == 0 {
                e.expires_at = now - 1.0;
                e.ttl = 0.0;
            }
            cache.put(CacheKey::new(&name, "A"), e, now);
        }
        let used = cache.summary()["used"].as_u64().unwrap();
        assert_eq!(used, 10, "`used` 含“过期但未清理”的条目");

        let tmp = dir.0.join(format!("{BASE}.snap.9.tmp"));
        let (meta, live) = write_snapshot_file(&cache, &tmp, 9, now).unwrap();
        assert_eq!(
            live, 5,
            "`used_live` 只数未过期条目（10 条里奇数号 5 条未过期）"
        );
        assert_eq!(meta.entry_count, 5, "快照也只收未过期条目");
        assert_eq!(
            meta.entry_count as u64, live,
            "（无 seq>S 的条目时两者相等）"
        );

        // 恢复：快照 6 条 → 新缓存 restore_records ⇒ used_live 仍 6 ⇒ 丢失率 0%
        let cache2 = Arc::new(SwappableCache::new(Arc::new(ebpdns_cache::LruCache::new(
            1024,
        ))));
        let r = SnapshotReader::open(&tmp).unwrap();
        let mut back: Vec<(CacheKey, CacheEntry)> = Vec::new();
        r.for_each(&mut |eseq, k, b| {
            let mut e = b.to_entry()?;
            e.seq = eseq;
            back.push((k, e));
            Ok(())
        })
        .unwrap();
        cache2.restore_records(back, now);
        let mut used_live_after = 0u64;
        cache2.for_each_entry(now, &mut |_, e| {
            if e.expires_at > now {
                used_live_after += 1;
            }
        });
        let snap_entries = meta.entry_count as f64;
        let loss = (snap_entries - used_live_after as f64) / snap_entries;
        assert!(
            loss.abs() <= 0.01,
            "**恢复丢失率口径** = (快照 entries − 恢复后 used_live)/快照 entries = {loss:.4}，应 ≤1%"
        );
        let _ = std::fs::remove_dir_all(&dir.0);
    }

    /// 写一个「快照 + 空 WAL」的 v2 现场（恢复路径专用）。
    ///
    /// `items` = `(key, 相对 t0 的到期秒数)`；写快照的时刻是 `t0`（全部未过期），
    /// 恢复时刻由调用方给（可晚于 `t0`，用于制造「快照之后才过期」的条目）。
    fn write_v2_scene(dir: &Tmp, t0: f64, items: &[(String, f64)]) -> u32 {
        let cache = Arc::new(SwappableCache::new(Arc::new(ebpdns_cache::LruCache::new(
            4096,
        ))));
        for (name, ttl) in items {
            let mut e = entry(name, t0);
            e.ttl = *ttl;
            e.expires_at = t0 + *ttl;
            cache.put(CacheKey::new(name, "A"), e, t0);
        }
        let snap_name = format!("{BASE}.snap.7");
        let tmp = dir.0.join(format!("{snap_name}.tmp"));
        let (meta, live) = write_snapshot_file(&cache, &tmp, 7, t0).unwrap();
        assert_eq!(live, items.len() as u64, "写快照时所有条目都未过期");
        std::fs::rename(&tmp, dir.0.join(&snap_name)).unwrap();
        let m = Manifest {
            flags: 0,
            seq: 7,
            snapshot_seq: 7,
            committed_ms: 1_700_000_000_000,
            snap_bytes: meta.file_len,
            snap_crc32c: meta.body_crc32c,
            snap_entries: meta.entry_count,
            snap_path: snap_name,
            wal_paths: Vec::new(),
            wal_base_seq: Vec::new(),
            wal_bytes: 0,
        };
        atomic_write_bytes(&dir.file(), &m.encode().unwrap()).unwrap();
        meta.entry_count
    }

    /// **2.1.29 热修回归（本次缺陷的直接现场）**：`apply_plan` 曾在
    /// `std::mem::take(&mut plan.entries)` **之后**读 `plan.entries.len()` ⇒
    /// v2 恢复后 `used_live` 恒为 0（按丢失率公式被读成 100%）。
    ///
    /// 现场：快照 N=20 条（写快照时全部未过期），其中 K=8 条在恢复时刻已过期
    /// （`persist_ttl=0` ⇒ 恢复时丢弃，`drops.0=8`）⇒ 恢复后
    /// `used_live == used == N-K == 12`（不是 0，也不是 20）。
    #[test]
    fn v2_restore_used_live_counts_inserted_not_zero() {
        let dir = Tmp::new("v2usedlive");
        let t0 = ebpdns_server::telemetry::now_epoch();
        let items: Vec<(String, f64)> = (0..20)
            .map(|i| (format!("r{i}.test"), if i < 8 { 1.0 } else { 300.0 }))
            .collect();
        let snap_entries = write_v2_scene(&dir, t0, &items);
        assert_eq!(snap_entries, 20, "快照 20 条全部未过期");

        // 恢复时刻 t0+2：前 8 条（t0+1 到期）已过期，其余 12 条仍有效。
        let now2 = t0 + 2.0;
        let mut plan = recover_v2(&dir.0, BASE, 0.0, now2, true).unwrap().unwrap();
        assert_eq!(
            plan.entries.len(),
            12,
            "persist_ttl=0 ⇒ 恢复丢弃 8 条过期条目"
        );
        assert_eq!(plan.drops.0, 8, "丢弃的过期条目计入 restore_drops.expired");

        let cache = Arc::new(SwappableCache::new(Arc::new(ebpdns_cache::LruCache::new(
            1024,
        ))));
        let stats = PersistStats::new();
        apply_plan(&cache, &stats, &mut plan, now2);
        // 缺陷现场：上面 take 之后再读 plan.entries ⇒ 这里曾得到 0。
        assert_eq!(
            stats.used_live(),
            12,
            "used_live = 恢复后非过期条目数（N-K），不是 0"
        );
        assert_ne!(stats.used_live(), 0, "缺陷回归：恢复后 used_live 不得为 0");
        assert_eq!(
            cache.summary()["used"].as_u64().unwrap(),
            12,
            "used 只含实际恢复的条目（过期项在恢复时已丢弃）"
        );
        let loss = (f64::from(snap_entries) - stats.used_live() as f64) / f64::from(snap_entries);
        assert!(
            (loss - 0.4).abs() < 1e-9,
            "K=8/N=20 ⇒ 真实过期丢弃率 40%，而不是缺陷读出的 100%: {loss:.4}"
        );
    }

    /// 同一回归的「无损」对照：快照 N=20 条，恢复时刻 K=0（没有条目过期）⇒
    /// `used_live == used == N`，且恢复丢失率 `(快照 entries − used_live)/entries ≤ 1%`。
    #[test]
    fn v2_restore_used_live_no_loss_when_nothing_expired() {
        let dir = Tmp::new("v2usedlive0");
        let t0 = ebpdns_server::telemetry::now_epoch();
        let items: Vec<(String, f64)> = (0..20).map(|i| (format!("z{i}.test"), 300.0)).collect();
        let snap_entries = write_v2_scene(&dir, t0, &items);

        let now2 = t0 + 2.0;
        let mut plan = recover_v2(&dir.0, BASE, 0.0, now2, true).unwrap().unwrap();
        assert_eq!(plan.drops.0, 0, "K=0 ⇒ 恢复不丢弃任何条目");
        let cache = Arc::new(SwappableCache::new(Arc::new(ebpdns_cache::LruCache::new(
            1024,
        ))));
        let stats = PersistStats::new();
        apply_plan(&cache, &stats, &mut plan, now2);
        assert_eq!(stats.used_live(), u64::from(snap_entries));
        assert_eq!(
            cache.summary()["used"].as_u64().unwrap(),
            u64::from(snap_entries)
        );
        let loss = (f64::from(snap_entries) - stats.used_live() as f64) / f64::from(snap_entries);
        assert!(
            loss.abs() <= 0.01,
            "K=0 时恢复丢失率必须 ≤1%（实测 {loss:.4}）"
        );
    }

    #[test]
    fn split_path_rejects_unsafe_names() {
        assert!(split_path(Path::new("/nonexistent-dir-xyz/..")).is_none());
        let (d, b) = split_path(Path::new("/var/lib/ebpdns/ebpdns-cache.json")).unwrap();
        assert_eq!(b, "ebpdns-cache.json");
        assert_eq!(d, Path::new("/var/lib/ebpdns"));
        // 相对路径的父目录为空 ⇒ "."
        let (d2, b2) = split_path(Path::new("ebpdns-cache.json")).unwrap();
        assert_eq!(b2, "ebpdns-cache.json");
        assert_eq!(d2, Path::new("."));
    }

    #[test]
    fn forced_v1_env_parsing() {
        // 只测解析（不改进程环境，避免并行测试串扰）。
        assert!(matches!(Some("v1"), Some("v1")));
        std::env::set_var("EBPDNS_CACHE_FORMAT", "v1");
        assert!(env_forced_v1());
        std::env::set_var("EBPDNS_CACHE_FORMAT", "v2");
        assert!(!env_forced_v1());
        std::env::remove_var("EBPDNS_CACHE_FORMAT");
        assert!(!env_forced_v1());
    }

    // >>> PATCH242A P1-3 keep-from-test BEGIN
    /// **2.1.42（P1-3）**：R2 失败后的下轮 R1 必须保留 `snapshot_seq` 之后仍需的
    /// **最早**一段，而不是只留 `last()`。
    ///
    /// 段范围 `[base[i], base[i+1])`：
    /// - `snap_seq=150`, bases `[100,200]` ⇒ 段 0 含 150..199，保留下标 0；
    /// - `snap_seq=250`, bases `[100,200,300]` ⇒ 段 0 已覆盖，段 1 含 250..299，保留 1；
    /// - `snap_seq=50`, bases `[100,200]` ⇒ 全部含 >50 的记录，保留 0。
    #[test]
    fn wal_keep_from_preserves_segments_after_snapshot_seq() {
        assert_eq!(wal_keep_from(&[100, 200], 150), 0);
        assert_eq!(wal_keep_from(&[100, 200, 300], 250), 1);
        assert_eq!(wal_keep_from(&[100, 200], 50), 0);
        assert_eq!(wal_keep_from(&[100], 99), 0);
        assert_eq!(wal_keep_from(&[], 1), 0);
    }
    // <<< PATCH242A P1-3 keep-from-test END
}
