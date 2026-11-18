//! **2.1.22 阶段一**：把"写者 → 统一持久化事务"这一层从 `api.rs` 里分出来。
//!
//! ## 为什么单独成模块
//!
//! `api.rs` 已经是 7 700 行的路由/处理器集合，而本阶段新增的是**横切关注点**：
//! 「取统一事务锁 → 组 part → 提交 → 记录 revision/审计」。把它放进 `api.rs`
//! 会让"谁持锁、锁序如何"更难审计；单独成模块后，`grep state_txn` 就能看到
//! **全部**取锁点。
//!
//! ## 锁序（与 `rules_admin.rs` 文件头同一条，防死锁）
//!
//! 1. 先取 [`crate::state_store::state_txn`]（异步锁，可跨 `await`）；
//! 2. 再取 `state.cfg` / `state.applied`（`parking_lot` 短临界区，**不跨 `await`**）；
//! 3. 持锁期间不得再调用任何会取本锁的入口；
//! 4. 阻塞 IO 必须出 async 线程（`spawn_blocking`）。
//!
//! ## 为什么 `if-revision` 要在**锁内**判定
//!
//! 两个写者的"丢失更新"来自「读 revision → 改 → 写」之间有窗口。把
//! 「比较 revision」与「提交」放进**同一个临界区**之后，窗口消失：
//! 拿到锁的写者一定看到**提交点**的当前世代，不匹配就 409 且**一个字节都不写**。

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::Value;

use crate::error::ServerError;
use crate::state::AppState;
use crate::state_store::{commit_droppable, CommitError, StateStore};

/// `if-revision` 的取值来源（请求体字段优先，其次请求头）。
///
/// 两种写法都接受的理由：脚本用 `curl -H 'if-revision: 42'` 最顺手，
/// 而前端 `act_save` 天生只发 JSON body ⇒ 只支持一种就会让另一端"没法用"。
/// 两者都非法的（非整数 / 负数）⇒ `None`（= 不做乐观并发控制，逐位保留旧行为）。
pub fn if_revision_from(body: &Value, header: Option<&str>) -> Option<u64> {
    let from_body = body.get("if_revision").and_then(|v| match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse::<u64>().ok(),
        _ => None,
    });
    from_body.or_else(|| {
        header
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(|s| s.parse::<u64>().ok())
    })
}

/// 提交失败 ⇒ `ServerError`（**日志级别是本项目的硬要求**：冲突 WARN、中止 ERROR）。
///
/// **这是"提交失败 ⇒ HTTP + 日志级别"的唯一定义处**（2.1.23 / DEF-222-15：
/// `api.rs` 里曾另有一份"先 `error!` 再分流"的实现，使冲突的 WARN 分支**不可达**；
/// 现在那处已删除并改调本函数）。
///
/// 409 的响应体带**结构化**的 `expected` / `current`（2.1.23 / DEF-222-16）：
/// 客户端据此重读重试，不必从文案里正则抠数字。
pub fn commit_err_to_server(e: CommitError) -> ServerError {
    match e {
        CommitError::Conflict { expected, current } => {
            tracing::warn!(
                expected,
                current,
                "持久化提交被拒（`if-revision` 不符）⇒ 409 + 当前 revision（**不是故障，是并发**）"
            );
            ServerError::ConflictWith(serde_json::json!({
                "error": format!(
                    "revision 冲突：期望 {expected}，当前 {current}\
                     （请重读 /api/status.state_persist.revision 后重试）"
                ),
                "expected": expected,
                "current": current,
                "state_persist_url": "/api/status",
            }))
        }
        CommitError::Io { msg } => {
            tracing::error!("{msg}");
            ServerError::Internal
        }
    }
}

/// **`PUT /api/config` 的统一事务提交**（`config.json` + 规则真源 + 镜像 = 一个世代）。
///
/// `if_revision = Some(n)` ⇒ 要求磁盘当前世代**精确等于** `n`，否则
/// [`CommitError::Conflict`] 且**没有任何写盘**（"丢更新 = 0"的另一半：
/// 拒绝过期写者而不是让它覆盖）。
///
/// `state.cfg_path = None`（纯内存态）⇒ 只做 revision 检查后返回（不落盘）。
pub async fn put_config_commit(
    state: &AppState,
    new_cfg: &Value,
    rules_changed: bool,
    if_revision: Option<u64>,
) -> Result<Option<u64>, CommitError> {
    let Some(store) = state.state.store().cloned() else {
        return Ok(None);
    };
    let _txn = crate::state_store::state_txn().lock().await;
    // ---- 锁内：乐观并发校验 ----
    if let Some(expected) = if_revision {
        let current = store.current_revision().unwrap_or(0);
        if expected != current {
            return Err(CommitError::Conflict { expected, current });
        }
    }
    let Some(cp) = state.cfg_path.clone() else {
        // 纯内存态：无 part 可提交（语义与 2.1.21 的"只改内存"一致）。
        return Ok(None);
    };
    // ---- 组 part：`config.json`（**无 `rules` 镜像键**）+ 规则真源 + 镜像 ----
    let cfg_disk = crate::rules_admin::cfg_without_rules_mirror(new_cfg);
    let mut plan: BTreeMap<PathBuf, Vec<u8>> = BTreeMap::new();
    plan.insert(cp, StateStore::json_bytes(&cfg_disk));
    if rules_changed {
        let arr: Vec<Value> = new_cfg
            .get("rules")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        // `rules_plan` 会同时给出 `config.json`（同一份 `cfg_disk`，逐字节相同），
        // 覆盖插入无害且保证"规则文件与 config 出于同一次计算"。
        if let Some(r) = crate::rules_admin::rules_plan(state, &cfg_disk, &arr) {
            plan.extend(r);
        }
    }
    let out = tokio::task::spawn_blocking({
        let store = std::sync::Arc::clone(&store);
        let plan = plan.clone();
        move || commit_droppable(&store, "api:put_config", &plan)
    })
    .await
    .map_err(|e| CommitError::Io {
        msg: format!("配置提交任务失败（join error）: {e}"),
    })??;
    Ok(out.map(|c| c.revision))
}

/// **上游 CRUD / 规则订阅相关写盘**（`POST|PUT|DELETE /api/upstreams`）的统一提交。
///
/// 与 `put_config` 同型但**不带 `if-revision`**：这些端点的并发面是"同一份
/// `upstreams[]` 列表"，由 `state_store::state_txn()` 串行化即可；`if-revision` 是给
/// "外部脚本与配置文件同时改同一键"准备的（见 `CONVENTIONS.md`）。
pub async fn commit_cfg_only(
    state: &AppState,
    writer: &str,
    new_cfg: &Value,
) -> Result<Option<u64>, CommitError> {
    let Some(store) = state.state.store().cloned() else {
        return Ok(None);
    };
    let _txn = crate::state_store::state_txn().lock().await;
    let Some(cp) = state.cfg_path.clone() else {
        return Ok(None);
    };
    let mut plan: BTreeMap<PathBuf, Vec<u8>> = BTreeMap::new();
    plan.insert(
        cp,
        StateStore::json_bytes(&crate::rules_admin::cfg_without_rules_mirror(new_cfg)),
    );
    let out = tokio::task::spawn_blocking({
        let store = std::sync::Arc::clone(&store);
        let plan = plan.clone();
        let writer = writer.to_string();
        move || commit_droppable(&store, &writer, &plan)
    })
    .await
    .map_err(|e| CommitError::Io {
        msg: format!("配置提交任务失败（join error）: {e}"),
    })??;
    // **2.1.48 / serving_revision**：config-only 提交（上游 CRUD / reprobe）不影响索引，
    // 提交成功即视为新世代在服务（调用方随后写回内存 cfg）。
    if out.is_some() {
        state.state.mark_serving();
    }
    Ok(out.map(|c| c.revision))
}

/// `/api/status.state_persist`（**新键，不动既有 `persist` / `restore_drops` /
/// `disk_restored`**）。
///
/// 契约（逐字段）：
/// * `enabled`：是否启用统一事务；
/// * `state_dir`：生效的 `state/` 目录（可配置，默认 `/var/lib/ebpdns/state`）；
/// * `revision`：**磁盘上**当前 `commit.json` 的世代号（`null` = 无提交点）；
/// * `writer`：最后提交者身份（审计）；
/// * `parts[{path,sha256,bytes,mtime_s}]`：`sha256` 来自 **`commit.json` 记录**，
///   `bytes`/`mtime_s` 来自**现场 `stat`** ⇒ 两者不一致时本端点即可看出；
/// * `prev_generation_ok`：**上一个世代是否完好可回退**（无历史世代 ⇒ `false`）；
/// * `history_generations`：`history/<rev>/` 里的世代号（升序）；
/// * `failed_commits`：进程内**提交中止**计数（IO/ENOSPC 等；冲突不计入）；
/// * **`load_state`（2.1.23 / DEF-222-04）**：启动四态
///   `"Legacy" | "Committed" | "RolledBack" | "Torn"`；
/// * **`serving_revision`**：读方**实际服务**的世代（`RolledBack` 时是回退后的世代，
///   与 `revision` 不同 ⇒ 这是 2.1.22 端点"在说谎"的那一点）；
/// * **`broken_revision`**：被判定损坏、因而被拒绝的世代（仅 `RolledBack`）；
/// * **`torn` / `torn_reason`**：`Torn` 必须**可从端点判定**（不是只写日志）；
/// * `lock_held` / `lock_note`（2.1.23 / DEF-222-03）：`state/` 独占锁是否由本进程持有；
/// * `note`：一行人类可读说明。
pub fn state_persist_json(state: &AppState) -> Value {
    let store = state.state.store().map(std::sync::Arc::as_ref);
    let ls = state.state.load_state.as_ref();
    let note = match ls.map(|l| l.kind) {
        Some("Torn") => {
            "**统一事务处于 TORN**：当前世代与上一代都不可用 —— 读方**没有**可信世代，\
             持久化一致性保证已失去，必须人工介入（见 `history/` 与 `torn_reason`）"
        }
        Some("RolledBack") => {
            "**已回退上一代**：当前世代校验失败，读方服务的是 `serving_revision`\
             （与 `revision` 不同）；`broken_revision` 是被拒绝的世代"
        }
        Some("Legacy") if state.state.is_on() => {
            "统一事务已启用，但 `state/` 尚无提交点（Legacy：旧布局或全新安装）"
        }
        Some("Legacy") => "未启用统一事务（旧行为：各写者各自原子写；无可观测的世代号）",
        Some("Committed") => {
            if state
                .state
                .store()
                .map(|s| s.prev_generation_ok())
                .unwrap_or(false)
            {
                "统一事务已启用（当前世代校验通过；上一代可回退）"
            } else {
                "统一事务已启用（当前世代校验通过；**当前没有可回退的上一代**）"
            }
        }
        _ => {
            if state.state.is_on() {
                "统一事务已启用"
            } else {
                "未启用统一事务（旧行为：各写者各自原子写；无可观测的世代号）"
            }
        }
    };
    let mut v =
        crate::state_store::persist_info(state.state.dir(), store, state.state.is_on(), note, ls);
    if let Some(o) = v.as_object_mut() {
        // **2.1.23 / DEF-222-03**：独占锁现场（端点可判"我是不是唯一实例"）。
        o.insert("lock_held".into(), Value::Bool(state.state.lock_held));
        o.insert(
            "lock_note".into(),
            state
                .state
                .lock_note
                .as_ref()
                .map(|s| Value::String(s.clone()))
                .unwrap_or(Value::Null),
        );
        // **2.1.23 / DEF-222-01**：本进程累计遇到多少次"规则真源存在但读不懂"。
        // 它是 fail-closed 的**旁证**：>0 说明真源被改坏过（且已按 fail-closed 处理）。
        o.insert(
            "rule_source_unreadable".into(),
            serde_json::json!(crate::rules_admin::rule_source_unreadable_count()),
        );
    }
    v
}
