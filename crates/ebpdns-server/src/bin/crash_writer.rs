//! **2.1.22 阶段一验收工具**：崩溃注入写入器（`src/bin/crash_writer.rs`）。
//!
//! 与 `state_store` v2 配套：part 是**绝对路径**（跨目录），摘要用 SHA-256。
//!
//! 用法：
//!
//! ```text
//! crash_writer write <etc_dir> <state_dir> <generation> [<abort_stage>] [--slow [ms]]
//! crash_writer check <etc_dir> <state_dir>
//! ```
//!
//! * `etc_dir`   —— 相当于 `/etc/ebpdns`（`config.json` 在这里）；
//! * `state_dir` —— 相当于 `/var/lib/ebpdns/state`（`commit.json` + `rules.json` +
//!   `subscriptions.json` + `history/` 在这里）⇒ **天然就是跨目录用例**；
//! * `abort_stage`（缺省 = 正常提交完成）取以下值之一时在该阶段末尾 `abort()`
//!   （`SIGABRT`，等价于突然死亡，不给任何清理机会）：
//!
//! | 值 | 阶段 | 此刻磁盘上的状态 |
//! |---|---|---|
//! | `after-stage-parts` | 暂存写完、`commit.json` 仍是旧的 | 旧世代完整可读 |
//! | `after-commit-json` | 提交点已写、part 尚未 rename | **最危险窗口**：必须靠摘要不符回退 |
//! | `after-rename-parts` | 新 part 已发布 | 新世代完整可读 |
//! | `after-prune` | 历史已清理 | 新世代完整可读 |
//!
//! `--slow <ms>`：在提交前 `sleep`，给**外部** `kill -9` 命中"tmp 正在写"的窗口。
//!
//! `check` 的退出码：`0` = 有可用世代（旧或新）；`3` = **撕裂**（必须为 0 次）。

use ebpdns_server::state_store::{
    LoadState, StateStore, STAGE_AFTER_COMMIT_JSON, STAGE_AFTER_PRUNE, STAGE_AFTER_RENAME_PARTS,
    STAGE_AFTER_STAGE_PARTS,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// 崩溃钩子：只 abort 命中的那个阶段。`fn` 指针不能捕获环境 ⇒ 用静态表传递目标。
fn make_hook(target: &'static str) -> fn(&'static str) {
    unsafe {
        TARGET = target;
    }
    hook_impl
}

static mut TARGET: &str = "";

fn hook_impl(stage: &'static str) {
    if unsafe { TARGET } == stage {
        std::process::abort();
    }
}

fn usage() -> ! {
    eprintln!("usage: crash_writer write <etc_dir> <state_dir> <generation> [<abort_stage>] [--slow [ms]]");
    eprintln!("       crash_writer check <etc_dir> <state_dir>");
    eprintln!("       crash_writer cleanup <state_dir>");
    eprintln!("stages: after-stage-parts | after-commit-json | after-rename-parts | after-prune");
    std::process::exit(2);
}

/// 读 part 并按"同一世代内 gen 必须一致"判撕裂（比摘要更强的一层）。
fn check(etc: &Path, state: &Path) -> i32 {
    let store = StateStore::open(state, 2).expect("open");
    let (load, torn) = match store.load() {
        LoadState::Committed(_) => ("Committed", false),
        LoadState::RolledBack { .. } => ("RolledBack", false),
        LoadState::Legacy => ("Legacy", false),
        LoadState::Torn { .. } => ("Torn", true),
    };
    match store.available_generation() {
        None => {
            eprintln!("TEAR: 没有任何可用世代");
            3
        }
        Some((rev, src)) => {
            let cfg = store
                .read_part(&etc.join("config.json"))
                .expect("config.json");
            let rl = store
                .read_part(&state.join("rules.json"))
                .expect("rules.json");
            let sub = store
                .read_part(&state.join("subscriptions.json"))
                .expect("subscriptions.json");
            let g = |b: &[u8]| -> u64 {
                serde_json::from_slice::<serde_json::Value>(b)
                    .expect("part 必须是合法 JSON") // 撕裂会在这里也暴露
                    .get("gen")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
            };
            let (gc, gr, gs) = (g(&cfg), g(&rl), g(&sub));
            if gc != gr || gr != gs {
                eprintln!("TEAR: 同代 gen 不一致 config={gc} rules={gr} subs={gs}");
                return 3;
            }
            println!(
                "OK {rev} {src} gen={gc} tmp={} load={load}",
                store.leftover_tmp().len()
            );
            if torn {
                3
            } else {
                0
            }
        }
    }
}

fn write(etc: &Path, state: &Path, gen: u64, abort_stage: &str, slow_ms: Option<u64>) {
    let stage: &'static str = match abort_stage {
        "" => "",
        "after-stage-parts" | "before-commit-json" => STAGE_AFTER_STAGE_PARTS,
        "after-commit-json" => STAGE_AFTER_COMMIT_JSON,
        "after-rename-parts" => STAGE_AFTER_RENAME_PARTS,
        "after-prune" => STAGE_AFTER_PRUNE,
        other => {
            eprintln!("unknown stage: {other}");
            std::process::exit(2);
        }
    };
    let store = if stage.is_empty() {
        StateStore::open(state, 2).expect("open")
    } else {
        StateStore::open_with_crash_hook(state, 2, make_hook(stage)).expect("open")
    };
    if let Some(ms) = slow_ms {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
    let mut parts: BTreeMap<PathBuf, Vec<u8>> = BTreeMap::new();
    parts.insert(
        etc.join("config.json"),
        StateStore::json_bytes(&json!({ "gen": gen })),
    );
    parts.insert(
        state.join("rules.json"),
        StateStore::json_bytes(&json!({ "gen": gen, "rules": [] })),
    );
    parts.insert(
        state.join("subscriptions.json"),
        StateStore::json_bytes(&json!({ "gen": gen, "subs": [] })),
    );
    let c = store
        .commit(&parts, "crash-writer", 1000 + gen, gen)
        .expect("commit");
    println!("committed revision={} parts={}", c.revision, c.parts.len());
}

fn main() {
    // 子命令各自校验参数个数：**不要**用共享的 `args.len() < N` 守卫 —— `check` 只需要 4 个
    // 参数（程序名 + check + 两个目录），共享守卫会把它误判成用法错误（2.1.22 实测）。
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    match cmd {
        "check" => {
            if args.len() != 4 {
                usage();
            }
            let code = check(&PathBuf::from(&args[2]), &PathBuf::from(&args[3]));
            std::process::exit(code);
        }
        "cleanup" => {
            if args.len() != 3 {
                usage();
            }
            let store = StateStore::open(PathBuf::from(&args[2]), 2).expect("open");
            let n = store.cleanup_stale_tmp();
            println!("CLEANED {n} TMP_LEFT {}", store.leftover_tmp().len());
        }
        "write" => {
            // write <etc> <state> <gen> [stage] [--slow [ms]]
            if args.len() < 5 {
                usage();
            }
            let etc = PathBuf::from(&args[2]);
            let state = PathBuf::from(&args[3]);
            let gen: u64 = args[4].parse().unwrap_or_else(|_| {
                eprintln!("generation 必须是整数: {:?}", args[4]);
                std::process::exit(2);
            });
            // 第 6 个参数只可能是阶段名；`--slow` 及其毫秒参数单独扫描。
            let abort_stage = args
                .get(5)
                .filter(|s| !s.starts_with("--"))
                .cloned()
                .unwrap_or_default();
            let slow_ms = args.iter().position(|a| a == "--slow").map(|i| {
                args.get(i + 1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(300u64)
            });
            write(&etc, &state, gen, &abort_stage, slow_ms);
        }
        _ => usage(),
    }
}
