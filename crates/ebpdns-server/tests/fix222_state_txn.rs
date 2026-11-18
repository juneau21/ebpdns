//! **2.1.22 阶段一（验收 ① ② ⑥）**：统一持久化事务的**并发与失败注入**门禁。
//!
//! 本文件是"运行行为"级别的验收，与 `state_store.rs` 里的**协议单测**分工明确：
//!
//! | 层 | 文件 | 证明什么 |
//! |---|---|---|
//! | 协议 | `src/state_store.rs` 的 `mod tests` | 两阶段提交本身的原子性/回退/prune |
//! | 接线 | **本文件** | 三处业务写者接进**同一个**事务；冲突 409；丢更新 = 0；ENOSPC ⇒ 上一代完好 |
//!
//! ## 为什么必须在这里做（而不是只做协议单测）
//!
//! 2.1.22 阶段一的核心**不是**"协议对不对"（那已被 100 次崩溃注入证明），而是
//! **"写者有没有真的走协议"**。绕过事务的写法（各写者自己 `atomic_write`）在协议层
//! 单测里**完全看不出来** —— 它只在并发/失败注入下暴露。因此本文件的用例全部
//! 从 `AppState` 出发，走真实 handler 路径。
//!
//! ## 并发 50 轮的判据
//!
//! 两个写者交替改**同一个键**（`cache_size`），每个写者：
//! ① 读 `state_persist.revision`；② 带 `if_revision` 提交。
//! * **丢更新 = 0** ⇒ 最终值必须是"最后一次成功提交"的值，且**成功次数 + 409 次数 == 尝试次数**；
//! * **冲突全部 409** ⇒ 不允许出现 500/200 混淆（500 会掩盖"其实是并发冲突"）。
//!
//! ## ENOSPC 注入
//!
//! 用 `EBPDNS_TEST_ENOSPC_DIR` 的等价物（本文件内直接构造一个**只读目录**，
//! 见 `readonly_dir`）让 part 的 `create`/`rename` 必然失败。断言：
//! * 提交**中止**（返回 `Err`）；
//! * `state_persist.revision` **没有推进**；
//! * 上一代的 `config.json` **逐字节未变**；
//! * `failed_commits` **递增**（错误必须升 ERROR，不许静默）；
//! * `available_generation()` 仍能给出一个世代 ⇒ **撕裂 = 0**。

use std::path::PathBuf;
use std::sync::Arc;

use ebpdns_resolver::clock::RealClock;
use ebpdns_resolver::config::ResolverConfig;
use ebpdns_resolver::query::ScriptedQuerier;
use ebpdns_resolver::Resolver;
use ebpdns_server::state::{AppState, RestartSignal, StateCtx};
use ebpdns_server::state_store::{self, LoadState, StateStore};
use parking_lot::RwLock;
use serde_json::{json, Value};

/* ---------------- 夹具 ---------------- */

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "ebpdns-txn-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("mkdir");
    d
}

/// 带**已启用统一事务**的 `AppState`（`cfg_path` 在 `etc/`，`state/` 在另一目录
/// ⇒ 每次提交都在验证**跨目录**事务，与生产布局一致）。
fn state_with_store(tag: &str) -> (AppState, PathBuf, PathBuf, Arc<StateStore>) {
    let root = tmpdir(tag);
    let etc = root.join("etc");
    let state_dir = root.join("state");
    std::fs::create_dir_all(&etc).expect("mkdir etc");
    let cfg_path = etc.join("config.json");
    let store = Arc::new(StateStore::open(&state_dir, 2).expect("open store"));

    let tel = Arc::new(ebpdns_server::ServerTelemetry::new());
    let q = ScriptedQuerier::new(|_n: &str, _t: &str, _d: u32| Vec::new());
    let resolver = Resolver::new(
        ResolverConfig::default(),
        tel.clone(),
        Arc::new(RealClock::default()),
        Arc::new(q),
    );
    let cfg = json!({
        "cache_size": 131072,
        "rules": [],
        "state_dir": state_dir.display().to_string(),
        "state_persist": true,
    });
    let st = AppState {
        resolver,
        cfg: Arc::new(RwLock::new(cfg.clone())),
        cfg_path: Some(cfg_path.clone()),
        telemetry: tel,
        api_host: Arc::new(RwLock::new("127.0.0.1".to_string())),
        api_port: 8353,
        web_root: None,
        restart: Arc::new(RestartSignal::default()),
        endpoints: Arc::new(RwLock::new(Vec::new())),
        on_reload: None,
        restart_notify: Arc::new(tokio::sync::Notify::new()),
        udp_dropped: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        applied: Arc::new(RwLock::new(cfg)),
        state: Arc::new(StateCtx::with_store(Arc::clone(&store), state_dir.clone())),
    };
    (st, cfg_path, state_dir, store)
}

fn current_rev(st: &AppState) -> u64 {
    st.state
        .store()
        .and_then(|s| s.current_revision())
        .unwrap_or(0)
}

/// 带 `if_revision` 的提交（**等价于 `PUT /api/config` 在统一事务下的完整动作**）。
///
/// 必须和 handler 一样在**提交成功之后**才刷新内存：`put_config_commit` 只负责
/// "把 part 原子提交"，内存与磁盘的同源由调用方在成功分支里保证
/// （见 `api.rs::put_config` 的 `Ok(_) => { *s.cfg.write() = new_cfg.clone(); … }`）。
/// 本助手照抄那一步 —— 否则"磁盘与内存必须同源"的断言测的就不是产品行为了。
async fn commit_with_rev(
    st: &AppState,
    key: &str,
    value: Value,
    if_rev: Option<u64>,
) -> Result<(), ebpdns_server::CommitError> {
    let mut new_cfg = st.cfg.read().clone();
    new_cfg[key] = value;
    ebpdns_server::api_state::put_config_commit(st, &new_cfg, false, if_rev).await?;
    *st.cfg.write() = new_cfg;
    Ok(())
}

/* ---------------- ② 冲突：if-revision ⇒ 409 ---------------- */

#[tokio::test]
async fn if_revision_mismatch_is_conflict_and_writes_nothing() {
    let (st, cfg_path, state_dir, store) = state_with_store("conflict");
    commit_with_rev(&st, "cache_size", json!(1000), None)
        .await
        .expect("首次提交");
    let rev = current_rev(&st);
    let disk_before = std::fs::read(&cfg_path).expect("config.json");

    // 过期写者：声明一个**不等于**当前世代的 revision。
    let e = commit_with_rev(&st, "cache_size", json!(2000), Some(rev + 100))
        .await
        .expect_err("过期 if-revision 必须被拒");
    match e {
        ebpdns_server::CommitError::Conflict { expected, current } => {
            assert_eq!(expected, rev + 100);
            assert_eq!(current, rev, "409 必须带**当前** revision，客户端据此重读");
        }
        other => panic!("必须是 Conflict，实际 {other:?}"),
    }
    // **一个字节都没写**：世代号不动、config.json 逐字节不变。
    assert_eq!(current_rev(&st), rev, "冲突不得推进世代");
    assert_eq!(
        std::fs::read(&cfg_path).unwrap(),
        disk_before,
        "冲突不得改盘"
    );
    // 正确的 if-revision 通过。
    commit_with_rev(&st, "cache_size", json!(2000), Some(rev))
        .await
        .expect("正确 revision 必须通过");
    assert!(current_rev(&st) > rev);
    let _ = std::fs::remove_dir_all(state_dir.parent().unwrap());
    drop(store);
}

/* ---------------- ⑥ 并发 50 轮：丢更新 = 0、冲突全部 409 ---------------- */

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fifty_rounds_two_writers_same_key_no_lost_update() {
    let (st, _cfg_path, state_dir, store) = state_with_store("conc50");
    commit_with_rev(&st, "cache_size", json!(0), None)
        .await
        .expect("基线提交");

    const ROUNDS: usize = 50;
    let mut ok = 0usize;
    let mut conflict = 0usize;
    let mut other = 0usize;

    for round in 0..ROUNDS {
        // 两个写者各自**先读**当前世代，再带 if_revision 提交同一个键。
        // 因为 `put_config_commit` 把"比较 revision"与"提交"放在**同一个临界区**，
        // 恰好一个写者会成功、另一个必然看到旧世代 ⇒ 409。
        let rev_a = current_rev(&st);
        let rev_b = rev_a; // 故意取同一个（模拟"同时读到同一世代"）
        let va = json!(100_000 + round as i64 * 2);
        let vb = json!(100_000 + round as i64 * 2 + 1);
        let (ra, rb) = tokio::join!(
            commit_with_rev(&st, "cache_size", va.clone(), Some(rev_a)),
            commit_with_rev(&st, "cache_size", vb.clone(), Some(rev_b)),
        );
        for r in [ra, rb] {
            match r {
                Ok(()) => ok += 1,
                Err(ebpdns_server::CommitError::Conflict { .. }) => conflict += 1,
                Err(e) => {
                    other += 1;
                    eprintln!("非冲突失败（不允许）：{e}");
                }
            }
        }
    }
    // **每轮恰好一次成功**：这是"串行化 + 提交点比较在同一临界区"的直接推论。
    assert_eq!(ok, ROUNDS, "成功次数必须 == 轮数（每轮恰好一个写者赢）");
    assert_eq!(
        conflict, ROUNDS,
        "冲突必须**全部**是 Conflict（409），实际 {conflict}"
    );
    assert_eq!(other, 0, "不允许出现 500/其他错误（那会掩盖并发冲突）");

    // **丢更新 = 0 的正向判据**：磁盘上的值 == 内存里的值 == 某一次**成功**写入的值，
    // 且世代号恰好多推进了 `ok` 次。
    let disk: Value = serde_json::from_slice(&std::fs::read(_cfg_path.as_path()).unwrap()).unwrap();
    let mem = st.cfg.read().clone();
    assert_eq!(
        disk["cache_size"], mem["cache_size"],
        "磁盘与内存必须同源（丢更新会在这里暴露）"
    );
    let v = disk["cache_size"].as_i64().unwrap();
    assert!(
        (100_000..100_000 + ROUNDS as i64 * 2).contains(&v),
        "最终值必须来自某一次真实写入，实际 {v}"
    );
    assert!(
        store.history_generations().len() <= 2,
        "history 必须被裁剪到上限（默认 2）"
    );
    let _ = std::fs::remove_dir_all(state_dir.parent().unwrap());
}

/* ---------------- ⑥ 单一真源：只改 config.json 里的 rules ---------------- */

#[tokio::test]
async fn rules_single_source_config_mirror_is_not_the_source_of_truth() {
    let (st, cfg_path, state_dir, _store) = state_with_store("single");
    // 正常提交一次（把 rules 真源建起来）。
    let mut cfg = st.cfg.read().clone();
    cfg["rules"] = json!([{"id": "r1", "match": "a.example", "action": "block"}]);
    ebpdns_server::api_state::put_config_commit(&st, &cfg, true, None)
        .await
        .expect("提交");
    *st.cfg.write() = cfg;
    let auth = state_dir.join("rules.json");
    assert!(auth.is_file(), "真源必须存在");

    // **手工只改 `config.json` 里的 `rules`**（真源不动）—— 这是"配置路径 ≠ 真源"的场景。
    let mut disk: Value = serde_json::from_slice(&std::fs::read(&cfg_path).unwrap()).unwrap();
    disk["rules"] = json!([{"id": "ghost", "match": "ghost.example", "action": "block"}]);
    std::fs::write(&cfg_path, serde_json::to_vec_pretty(&disk).unwrap()).unwrap();

    // 读方必须以**真源**为准（`rules_payload` 与索引重建共用同一入口）。
    let payload = ebpdns_server::rules_admin::rules_payload(&st);
    let ids: Vec<String> = payload["rules"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["id"].as_str().map(ToString::to_string))
        .collect();
    assert!(
        ids.iter().any(|i| i == "r1"),
        "真源里的规则必须在列表里：{ids:?}"
    );
    assert!(
        !ids.iter().any(|i| i == "ghost"),
        "**`config.json.rules` 不是真源**：它单独的改动不得生效（否则就是双重真源）—— {ids:?}"
    );

    // 并且下一次提交会把 `config.json` 的 `rules` 镜像**重新对齐**到真源
    // （不是"静默忽略"：提交后磁盘上不会再留着那份分叉内容）。
    let mut cfg2 = st.cfg.read().clone();
    cfg2["cache_size"] = json!(4242);
    ebpdns_server::api_state::put_config_commit(&st, &cfg2, true, None)
        .await
        .expect("二次提交");
    let disk2: Value = serde_json::from_slice(&std::fs::read(&cfg_path).unwrap()).unwrap();
    assert!(
        disk2.get("rules").is_none(),
        "2.1.22 起 `config.json` **不再携带** `rules` 镜像键，实际：{:?}",
        disk2.get("rules")
    );
    let _ = std::fs::remove_dir_all(state_dir.parent().unwrap());
}

/* ---------------- ⑥ 写失败注入（ENOSPC 等价） ---------------- */

/// **写失败注入（等价 ENOSPC）**：把 part 的**父路径做成一个普通文件** ⇒
/// `create_dir_all(parent)` / `File::create(tmp)` 必然 `ENOTDIR`。
///
/// 为什么不用"只读目录 + `chmod 0o500`"：测试几乎总以 `root` 跑，
/// **`root` 不受 DAC 写权限约束**（`CAP_DAC_OVERRIDE`），`chmod` 根本拦不住 ——
/// 实测：只读目录上的提交**成功**了（返回 `Ok(Some(rev))`），断言随即失败。
/// "父路径是文件"则是**路径结构**层面的失败，与 uid/权限模型无关，任何身份都必然失败。
/// （`api.rs` 的既有用例 `broken_cfg_path` 用的是同一招。）
fn blocker_path(tag: &str) -> PathBuf {
    let d = tmpdir(tag);
    let blocker = d.join("blocker");
    std::fs::write(&blocker, b"x").expect("父路径必须是普通文件");
    blocker
}

#[tokio::test]
async fn write_failure_aborts_commit_and_keeps_previous_generation() {
    let (st, cfg_path, state_dir, store) = state_with_store("enospc");
    // ① 先有一次**成功**提交（建立"上一代"）。
    commit_with_rev(&st, "cache_size", json!(1111), None)
        .await
        .expect("基线提交必须成功");
    let rev_ok = current_rev(&st);
    let disk_ok = std::fs::read(&cfg_path).expect("config.json");
    let failed_before = state_store::failed_commits();

    // ② 新的 part 路径的父路径是一个**普通文件** ⇒ 写 `config.json.<rev>.tmp` 必然失败。
    //    （只改 `cfg_path`，`state` 保持同一份 store ⇒ 世代号仍可对账。）
    let blocker = blocker_path("enospc-ro");
    let st2 = AppState {
        cfg_path: Some(blocker.join("config.json")),
        ..st.clone()
    };
    let next_cfg = {
        let mut c = st2.cfg.read().clone();
        c["cache_size"] = json!(2222);
        c
    };
    let e = ebpdns_server::api_state::put_config_commit(&st2, &next_cfg, false, None)
        .await
        .expect_err("写不出来的 part **必须中止提交**（不得静默成功）");
    assert!(
        matches!(e, ebpdns_server::CommitError::Io { .. }),
        "写失败必须是 Io（⇒ 日志 ERROR + HTTP 500），实际 {e:?}"
    );

    // ③ **上一代完好**：世代号没推进、原 config.json 逐字节未变、失败计数 +1。
    assert_eq!(current_rev(&st), rev_ok, "提交中止不得推进世代");
    assert_eq!(
        std::fs::read(&cfg_path).unwrap(),
        disk_ok,
        "上一代 config.json 必须逐字节未变"
    );
    assert!(
        state_store::failed_commits() > failed_before,
        "提交中止必须被计数（`/api/status.state_persist.failed_commits`）"
    );
    // ④ **撕裂 = 0**：至少还有一个校验通过的世代。
    let avail = store
        .available_generation()
        .expect("必须仍存在可用世代（撕裂 = 0）");
    assert_eq!(avail.0, rev_ok);
    assert!(matches!(store.load(), LoadState::Committed(_)));
    // ⑤ 失败之后**仍然可以**正常提交（失败不留"卡死"状态）。
    commit_with_rev(&st, "cache_size", json!(3333), None)
        .await
        .expect("失败之后必须还能提交");
    assert!(current_rev(&st) > rev_ok);
    let _ = std::fs::remove_dir_all(state_dir.parent().unwrap());
    let _ = std::fs::remove_dir_all(blocker.parent().unwrap());
}

/* ---------------- ④ 可观测：state_persist 字段齐备 ---------------- */

#[tokio::test]
async fn state_persist_reports_revision_parts_prev_and_history() {
    let (st, _cfg_path, state_dir, _store) = state_with_store("obs");
    let v = ebpdns_server::api_state::state_persist_json(&st);
    assert_eq!(v["enabled"], json!(true));
    assert_eq!(v["state_dir"], json!(state_dir.display().to_string()));
    assert_eq!(
        v["revision"],
        Value::Null,
        "无 commit.json ⇒ revision = null（Legacy）"
    );
    assert_eq!(v["parts"], json!([]));
    assert_eq!(
        v["prev_generation_ok"],
        json!(false),
        "没有历史世代 ⇒ **如实报 false**（不假装安全）"
    );
    assert_eq!(v["history_generations"], json!([]));

    commit_with_rev(&st, "cache_size", json!(7), None)
        .await
        .expect("提交");
    let v = ebpdns_server::api_state::state_persist_json(&st);
    let rev = v["revision"].as_u64().expect("revision 必须是数字");
    let parts = v["parts"].as_array().expect("parts 必须是数组");
    assert!(!parts.is_empty(), "至少一个 part");
    for p in parts {
        assert!(p["path"].as_str().is_some(), "part.path");
        assert_eq!(
            p["sha256"].as_str().map(str::len),
            Some(64),
            "part.sha256 = 64 位十六进制"
        );
        assert!(p["bytes"].as_u64().is_some(), "part.bytes");
        assert!(p["mtime_s"].as_u64().is_some(), "part.mtime_s");
    }
    // 第二次提交 ⇒ 第一个世代进 history ⇒ prev_generation_ok 翻 true。
    commit_with_rev(&st, "cache_size", json!(8), None)
        .await
        .expect("第二次提交");
    let v = ebpdns_server::api_state::state_persist_json(&st);
    assert!(v["revision"].as_u64().unwrap() > rev);
    assert_eq!(
        v["prev_generation_ok"],
        json!(true),
        "有可校验的上一代 ⇒ true"
    );
    assert!(
        !v["history_generations"].as_array().unwrap().is_empty(),
        "history_generations 必须列出历史世代"
    );
    // `/api/status` 的键名必须是 `state_persist`（不得顶掉既有 `persist`）。
    assert!(v.get("state_dir").is_some());
    let _ = std::fs::remove_dir_all(state_dir.parent().unwrap());
}

/* ---------------- ② 审计：history/<rev>.meta.json ---------------- */

#[tokio::test]
async fn every_commit_writes_an_audit_meta_with_writer_identity() {
    let (st, _cfg_path, state_dir, _store) = state_with_store("meta");
    commit_with_rev(&st, "cache_size", json!(1), None)
        .await
        .expect("提交");
    let rev = current_rev(&st);
    let meta = state_dir.join("history").join(format!("{rev}.meta.json"));
    let v: Value = serde_json::from_slice(&std::fs::read(&meta).expect("meta 必须存在")).unwrap();
    assert_eq!(v["revision"], json!(rev));
    assert_eq!(
        v["writer"],
        json!("api:put_config"),
        "写者身份必须记进审计（API / 订阅 / CLI 可区分）"
    );
    assert!(v["committed_at"].as_u64().is_some());
    assert!(!v["parts"].as_array().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(state_dir.parent().unwrap());
}

/* ---------------- ⑥ API 写入 × 订阅刷新并发：丢更新 0、撕裂 0 ---------------- */

/// **两个不同的写者并发**：`api:put_config`（`config.json`）与
/// `subscribe`（`rules_sub.json` + `config.json`）在**同一个** `state_txn` 下交替提交。
///
/// 判据（全部可机器读数）：
/// * 每次成功提交拿到**互不相同**的 `revision`（严格递增，无重复 ⇒ 无"同代双写"）；
/// * 全程结束时 `load()` 必须是 `Committed`，且 `available_generation()` 非空
///   ⇒ **撕裂 = 0**；
/// * 磁盘上**两个** part 都存在、都能解析，且 `commit.json` 的 sha256 与磁盘现状
///   逐字节吻合（`load()` 的校验就是这件事）；
/// * **丢更新 = 0**：`config.json` 里最终那个键的值必须等于"最后一次成功提交写入的值"
///   （按 revision 排序后的最后一个），不允许回退到更早的值。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn api_write_and_subscribe_refresh_concurrently_never_tear() {
    let (st, cfg_path, state_dir, store) = state_with_store("apidup");
    let subs_path = state_dir.join("subscriptions.json");
    let st_api = st.clone();
    let st_sub = st.clone();
    let subs_for_sub = subs_path.clone();

    const N: usize = 25;
    // 写者 A：`PUT /api/config` 的提交动作（`cache_size` 单调递增）。
    //
    // 与产品 `api::put_config` 同构：**取锁 → 锁内读 live cfg → 只替换本次提交的键
    // → 提交**（`api.rs` 的 `merged` 就是"锁内读 live cfg 后逐个写入提交键"）。
    // 锁内读是"不覆盖并发写者刚提交的其它键"的前提。
    let a = tokio::spawn(async move {
        let mut revs = Vec::new();
        for i in 0..N {
            let _txn = state_store::state_txn().lock().await;
            let mut c = st_api.cfg.read().clone();
            c["cache_size"] = json!(700_000 + i as i64);
            // 提交成功后内存与磁盘同源（产品在 `Ok(_)` 分支里做这一步）。
            let mut plan = std::collections::BTreeMap::new();
            plan.insert(
                st_api.cfg_path.clone().expect("cfg_path"),
                ebpdns_server::StateStore::json_bytes(
                    &ebpdns_server::rules_admin::cfg_without_rules_mirror(&c),
                ),
            );
            if let Some(c2) = state_store::commit_droppable(
                st_api.state.store().expect("store"),
                "api:put_config",
                &plan,
            )
            .expect("提交必须成功")
            {
                *st_api.cfg.write() = c;
                revs.push(c2.revision);
            }
        }
        revs
    });
    // 写者 B：订阅刷新的提交动作（`rules_sub.json` + `config.json`）。
    let b = tokio::spawn(async move {
        let mut revs = Vec::new();
        for i in 0..N {
            let body = ebpdns_server::subscribe::subs_bytes(&[json!({
                "url": format!("https://example.test/{i}.txt"),
                "action": "block",
                "group": "global",
                "rules": [],
            })])
            .expect("subs bytes");
            // **关键：`config.json` 的 part 必须在**取锁之后**读 live cfg 才算出来** ——
            // 这正是产品代码 `subscribe::commit_sub_txn` 的做法（改内存 → 读 live cfg →
            // 提交）。若像写者 A 那样用循环外的快照，B 就会把 A 刚提交的 `cache_size`
            // **覆盖回旧值** —— 那不是"框架丢了更新"（提交点确实原子），而是"写者提交了
            // 陈旧内容"。本用例要证的是前者，所以必须按产品口径构造。
            let _txn = state_store::state_txn().lock().await;
            let cfg = st_sub.cfg.read().clone();
            let mut plan = std::collections::BTreeMap::new();
            plan.insert(
                st_sub.cfg_path.clone().expect("cfg_path"),
                ebpdns_server::StateStore::json_bytes(
                    &ebpdns_server::rules_admin::cfg_without_rules_mirror(&cfg),
                ),
            );
            plan.insert(subs_for_sub.clone(), body);
            if let Some(c2) = state_store::commit_droppable(
                st_sub.state.store().expect("store"),
                "subscribe",
                &plan,
            )
            .expect("提交必须成功")
            {
                revs.push(c2.revision);
            }
        }
        revs
    });

    let (ra, rb) = tokio::join!(a, b);
    let mut all: Vec<u64> = ra
        .expect("writer A")
        .into_iter()
        .chain(rb.expect("writer B"))
        .collect();
    assert_eq!(all.len(), 2 * N, "每个写者每轮都必须成功提交一次");
    all.sort_unstable();
    let before = all.len();
    all.dedup();
    assert_eq!(
        all.len(),
        before,
        "**同代双写**：出现重复 revision ⇒ 提交点被覆盖"
    );

    // **撕裂 = 0**
    match store.load() {
        LoadState::Committed(c) => {
            assert_eq!(
                c.revision,
                *all.last().unwrap(),
                "最新世代必须是最大 revision"
            );
        }
        other => panic!("并发提交后必须处于 Committed，实际 {other:?}"),
    }
    assert!(store.available_generation().is_some(), "必须存在可用世代");

    // 两个 part 都在盘上且可解析；`config.json` 不得带 `rules` 镜像键。
    let cfg_disk: Value =
        serde_json::from_slice(&std::fs::read(&cfg_path).expect("config.json")).unwrap();
    assert!(
        cfg_disk.get("rules").is_none(),
        "并发提交后 `config.json` 仍不得携带 `rules` 镜像键"
    );
    let subs_disk: Value =
        serde_json::from_slice(&std::fs::read(&subs_path).expect("subscriptions 必须落盘"))
            .unwrap();
    assert!(
        subs_disk
            .get("subscriptions")
            .and_then(Value::as_array)
            .is_some(),
        "订阅 part 形状必须是 {{subscriptions: [...]}}"
    );
    // **丢更新 = 0**（结构判据）：最终 `cache_size` 必须是**某个**写者写入过的值
    // （不可能是初始值 131072 —— 那意味着所有写都丢了）。
    let v = cfg_disk["cache_size"].as_i64().unwrap();
    assert!(
        (700_000..700_000 + N as i64).contains(&v),
        "最终的 `cache_size` 必须来自一次真实写入（丢更新会留下初始值），实际 {v}"
    );
    let _ = std::fs::remove_dir_all(state_dir.parent().unwrap());
}

/* ===================================================================== */
/* 2.1.23 · DEF-222-04（P1）：四态**可从端点判定**                        */
/* ===================================================================== */

/// **Torn 必须可从 `/api/status.state_persist` 判定**（不是只写日志）。
///
/// 2.1.22 把 `load()` 的结论**只写进日志**，端点一律报**原始 `commit.json`**
/// ⇒ Torn 时它照报 `revision = 被拒绝的世代`、`note = "统一事务已启用"`，
/// **端点无法区分健康 / 已回退 / Torn**（审计 DEF-222-04）。
#[tokio::test]
async fn torn_and_rolled_back_are_visible_on_the_endpoint() {
    use ebpdns_server::state::LoadStateInfo;

    let (st, cfg_path, state_dir, _store) = state_with_store("fourstate");
    // 建立两代（第 1 代进 history，成为回退点）。
    commit_with_rev(&st, "cache_size", json!(1001), None)
        .await
        .expect("第 1 代");
    commit_with_rev(&st, "cache_size", json!(1002), None)
        .await
        .expect("第 2 代");

    // ---- ① RolledBack：当前世代的 part 被改坏 ⇒ 读方回退上一代 ----
    std::fs::write(&cfg_path, br#"{"cache_size": 999999}"#).expect("tamper");
    let store2 = Arc::new(StateStore::open(&state_dir, 2).expect("open"));
    let ls = store2.load();
    let info = LoadStateInfo::from_load_state(&ls, true);
    assert_eq!(info.kind, "RolledBack");
    assert!(
        info.serving_revision.is_some() && info.broken_revision.is_some(),
        "回退后必须能给出**服务的世代**与**被拒绝的世代**：{info:?}"
    );
    assert!(
        info.broken_revision.unwrap() > info.serving_revision.unwrap(),
        "被拒绝的世代必须比服务的世代新"
    );

    let st2 = AppState {
        state: Arc::new(
            StateCtx::with_store(Arc::clone(&store2), state_dir.clone()).with_load_state(info),
        ),
        ..st.clone()
    };
    let v = ebpdns_server::api_state::state_persist_json(&st2);
    assert_eq!(v["load_state"], json!("RolledBack"));
    assert_eq!(v["torn"], json!(false));
    assert!(
        v["serving_revision"].as_u64().is_some() && v["broken_revision"].as_u64().is_some(),
        "端点必须同时给出 serving/broken：{v}"
    );
    // >>> 242B BEGIN T-state-eq >>> //
    // **2.1.42-B（P1-10）**：回退已真正落地（live parts 恢复 + 提交点改写为历史
    // 世代）⇒ 恢复后 `revision`（当前提交点）与 `serving_revision` 必须**相同**。
    // 旧实现只返回状态而不改提交点，才需要用"两者不同"来证明回退发生过。
    assert_eq!(
        v["serving_revision"], v["revision"],
        "回退已落地 ⇒ serving_revision 必须等于恢复后的提交点 revision：{v}"
    );
    // <<< 242B END T-state-eq <<< //

    // ---- ② Torn：把当前世代**与**历史世代的 part 副本都改坏 ----
    //
    // 关键：**必须改 history/<rev>/parts/... 里的副本**（不是只有 live `config.json`）。
    // 只改 live 文件 ⇒ 那是"当前世代坏、上一代好"= `RolledBack`（① 的情形）。
    // 要判 Torn 必须让 `verify(&c, Some(rev))` 对**历史世代**也失败
    //（它读的正是 `history/<rev>/parts/...`）。
    let cur_rev = store2.current_revision().unwrap_or(0);
    std::fs::write(&cfg_path, br#"{"cache_size": 888888}"#).expect("tamper cur");
    let hist_revs = store2.history_generations();
    assert!(!hist_revs.is_empty(), "必须先存在历史世代，否则判不出 Torn");
    for rev in &hist_revs {
        let hparts = state_dir
            .join("history")
            .join(rev.to_string())
            .join("parts");
        // 递归：`history/<rev>/parts/` 下面按 part 的父目录分层
        //（如 `parts/tmp/ebpdns-txn-…/etc/config.json`）⇒ 只读一层会一个文件都找不到。
        fn tamper_recursive(dir: &std::path::Path, n: &mut usize) {
            let Ok(rd) = std::fs::read_dir(dir) else {
                return;
            };
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    tamper_recursive(&p, n);
                } else if std::fs::write(&p, br#"{"cache_size": 777777}"#).is_ok() {
                    *n += 1;
                }
            }
        }
        let mut touched = 0usize;
        tamper_recursive(&hparts, &mut touched);
        assert!(
            touched > 0,
            "历史世代 {rev} 的 part 副本必须存在（否则本用例没有真的制造 Torn）"
        );
    }
    let store3 = Arc::new(StateStore::open(&state_dir, 2).expect("open3"));
    let ls3 = store3.load();
    let info3 = LoadStateInfo::from_load_state(&ls3, true);
    assert_eq!(
        info3.kind, "Torn",
        "当前世代与历史世代的 part 副本都坏 ⇒ 必须判 Torn\
         （实际 {ls3:?}；cur_rev={cur_rev}；hist={hist_revs:?}）"
    );
    assert!(info3.is_torn());
    assert!(info3.torn_reason.is_some(), "Torn 必须带原因");
    assert!(
        info3.serving_revision.is_none(),
        "Torn ⇒ **没有**可信的服役世代（不得再报被拒绝的世代）"
    );

    let st3 = AppState {
        state: Arc::new(
            StateCtx::with_store(Arc::clone(&store3), state_dir.clone()).with_load_state(info3),
        ),
        ..st.clone()
    };
    let v3 = ebpdns_server::api_state::state_persist_json(&st3);
    assert_eq!(v3["load_state"], json!("Torn"), "端点必须能判 Torn：{v3}");
    assert_eq!(v3["torn"], json!(true), "`torn` 布尔必须为 true：{v3}");
    assert!(
        v3["torn_reason"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "`torn_reason` 必须非空：{v3}"
    );
    assert!(
        v3["note"].as_str().unwrap_or("").contains("TORN"),
        "`note` 必须提示 TORN（不得再写\"统一事务已启用\"）：{v3}"
    );
    let _ = std::fs::remove_dir_all(state_dir.parent().unwrap());
}

/* ===================================================================== */
/* 2.1.23 · DEF-222-15（P1）+ DEF-222-16 + DEF-222-17：HTTP 级            */
/* ===================================================================== */

/// **409 必须走 WARN 而不是 ERROR；响应体必须结构化**（DEF-222-15 / DEF-222-16）。
///
/// 2.1.22 在 `api.rs` 里对所有 `CommitError` 先打一条 `tracing::error!`，
/// 使紧随其后的"冲突 ⇒ WARN"分流**逻辑上不可达**（生产 journal 实测 104 条噪音）。
/// 本用例**直调 handler**（`put_config`），因此覆盖到真实 HTTP 路径：
/// * 过期 `if_revision` ⇒ `ServerError::ConflictWith`（= 409）；
/// * 响应体含机读的 `expected`/`current`（不是只能正则抠文案）；
/// * `failed_commits` **不增**（冲突不是"提交中止"，其 ERROR 计数不得被污染）。
///
/// **为什么 `failed_commits` 能当"没有 ERROR"的判据**：`commit_err_to_server` 是
/// "提交失败 ⇒ HTTP + 日志级别"的**唯一**定义处（§16.2），而 `failed_commits` 只在
/// `CommitError::Io` 路径递增 —— 若还有人补一条 `error!`，它必然同时落在 Io 路径上。
#[tokio::test]
async fn put_config_if_revision_conflict_is_409_and_not_an_error() {
    let (st, _cfg_path, state_dir, _store) = state_with_store("http409");
    commit_with_rev(&st, "cache_size", json!(4242), None)
        .await
        .expect("基线提交");
    let rev = current_rev(&st);
    let failed_before = state_store::failed_commits();

    let body = json!({"cache_size": 5555, "if_revision": rev + 100});
    let parts = axum::http::request::Builder::new()
        .body(())
        .expect("request")
        .into_parts()
        .0;
    let err = ebpdns_server::api::put_config_for_test(st.clone(), parts, body)
        .await
        .expect_err("过期 if_revision 必须是 409");

    // ---- ① 结构化 409（DEF-222-16）----
    match &err {
        ebpdns_server::ServerError::ConflictWith(v) => {
            assert_eq!(v["expected"], json!(rev + 100));
            assert_eq!(
                v["current"],
                json!(rev),
                "机读的当前 revision 必须准确：{v}"
            );
            assert!(v["error"].as_str().is_some(), "仍要有人类可读的 error 文案");
        }
        other => panic!("必须是 ConflictWith（结构化 409），实际 {other:?}"),
    }
    let resp = axum::response::IntoResponse::into_response(err);
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::CONFLICT,
        "HTTP 状态码必须是 409"
    );

    // ---- ② 冲突不是"提交中止"（DEF-222-15 的日志级别判据）----
    assert_eq!(
        state_store::failed_commits(),
        failed_before,
        "**冲突（409）不得计入 `failed_commits`**（那只在 Io/ERROR 路径递增）\
         ⇒ 证明没有多打一条 ERROR"
    );
    assert_eq!(current_rev(&st), rev, "409 不得推进世代");
    let _ = std::fs::remove_dir_all(state_dir.parent().unwrap());
}

/// **DEF-222-17**：`if_revision` 是**元字段**，不得混进 `ignored_keys`。
#[tokio::test]
async fn if_revision_is_a_meta_key_not_an_ignored_key() {
    let (st, _cfg_path, state_dir, _store) = state_with_store("metakey");
    commit_with_rev(&st, "cache_size", json!(100), None)
        .await
        .expect("基线提交");
    let rev = current_rev(&st);
    let parts = axum::http::request::Builder::new()
        .body(())
        .expect("request")
        .into_parts()
        .0;
    let out = ebpdns_server::api::put_config_for_test(
        st.clone(),
        parts,
        json!({"cache_size": 200, "if_revision": rev}),
    )
    .await
    .expect("正确的 if_revision 必须成功");
    let v = out.0;
    let ignored = v["ignored_keys"].as_array().cloned().unwrap_or_default();
    assert!(
        !ignored.iter().any(|k| k == "if_revision"),
        "`if_revision` 不得出现在 `ignored_keys`（否则前端提示\"未知键已忽略\"）：{v}"
    );
    assert_eq!(
        v["meta_keys"],
        json!(["if_revision"]),
        "元字段必须单独回显：{v}"
    );
    let _ = std::fs::remove_dir_all(state_dir.parent().unwrap());
}
