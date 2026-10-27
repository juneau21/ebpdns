//! **[历史归因]** 规则管理（CRUD + 独立规则文件持久化），对齐 Python api.py 的规则端点。
//!
//! 权威参考：`ebpdns v1.9.162` 的
//! - `api._api_add_rule`（POST /api/rules）、`api._api_rule_op`（PUT/DELETE /api/rules/<id>）；
//! - `api._validate_rule_dict` / `api._check_rule_regex` / `api._normalize_rule_ttl`；
//! - `api._local_rules` / `api._rules_with_subs`（GET /api/rules）；
//! - `config.load_local_rules` / `config.save_local_rules`（`rules_local.json`，tmp+fsync+rename）。
//!
//! **[历史归因]** # 与 Python 的差异（有意）
//! **[历史归因]** - Python 把逐条规则**只**写 `rules_local.json`、不写 `config.json`；本实现按 2.0 口径
//!   「独立文件 + `config.json` 的 `rules` 各写一份」，两者始终保持一致（一次事务内提交）。
//! - `RuleIndex::build` 不返回 `Result`（坏规则计数跳过），故「规则索引重建失败」只落在
//!   可观测退化点：**本次全部规则都没进索引**（`indexed == 0 && rejected + dropped > 0`，
//!   含 `rule_from_json` 在进索引前丢弃的条目，见 F20）。
//! **[历史归因]** - `ServerError::Internal` 是 unit 变体（`error.rs`），无法携带 Python 的
//! **[历史归因]**   `规则写盘失败（已回滚内存变更）` 文案，真实原因走 `tracing::error!`（Python 亦注释
//!   「详情见服务端日志」）。
//! - 正则预检复用 `ebpdns_rules` 的编译器（同 `regex` 版本），因此 Rust `regex` 不支持的
//! **[历史归因]**   Python 特性（lookaround / 反向引用）在写入期即被拒（fail-closed，好于落库死规则）。
//! - 写路径读改写由进程内 `tokio::sync::Mutex` 串行化（`AppState` 无专用锁字段），
//!   订阅面（`subscribe.rs`）共用同一把锁（F07）。
//! - **F08**：提交时以 **live cfg** 为基准只替换 `rules` 键，不再用 handler 入口快照整体
//!   覆盖 `state.cfg`，否则并发 `PUT /api/config` / 订阅变更会被静默回退。
//! **[历史归因]** - **F21**：`action=group` 的 group 取值放宽为「任意字符串」（Python `_validate_rule_dict`
//!   只校验类型）；单条 `POST /api/rules` 恒写 `group`（缺省 `domestic`）与 `ip`（缺省 `""`），
//!   与 `api.py:3245-3251` 落盘形状一致。`rule_view` 仍**省略**空 `group`/`ip`
//! **[历史归因]**   （前端契约，Python 会回显空串），`id` 仍允许客户端显式指定（Python 单条 POST 一律生成，
//!   但前端已依赖显式 id，保留现状）。
//! - **F30**：`rule_local_file`/`rule_sub_file` 为相对路径时以 `config.json` 所在目录为基准
//! **[历史归因]**   （Python 相对进程 CWD；本实现按 2.0 口径归一，绝对路径不变）。
//!
//! 内部统一规则形状（`normalize_rule_json`）：`{id, match, action, group?, ip?, ttl_min?,
//! ttl_max?...}`；2.0 的 `match_raw` 与 v1.9.162 的 `pattern`/`value` 均归一化到该形状，
//! **[历史归因]** 落盘也用它（与 Python/`ebpdns_rules::load::load_local_rules_file` 读取口径兼容）。
//! `group`/`ip` 在内部是可选键（PUT 可用 `null` 移除），但单条 `POST /api/rules`
//! **[历史归因]** 恒写这两个键（F21，与 Python 一致）。

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use ebpdns_rules::index::MATCH_MAX_BYTES;
use ebpdns_rules::{Action, Rule, RuleIndex, RuleSource};

use crate::error::ServerError;
use crate::state::AppState;
use crate::state_store::{CommitError, StateStore};

/// **[历史归因]** 合法 action 枚举（对齐 Python `_RULE_ACTIONS`）。
const RULE_ACTIONS: [&str; 4] = ["allow", "block", "group", "forceIp"];
/// **[历史归因]** PUT 单条规则的可改字段白名单（对齐 Python `_RULE_WHITELIST`）。
const RULE_WHITELIST: [&str; 6] = ["match", "action", "group", "ip", "ttl_min", "ttl_max"];
/// **[历史归因]** 白名单排序展示（对齐 Python `",".join(sorted(_RULE_WHITELIST))`）。
const RULE_WHITELIST_SORTED: &str = "action,group,ip,match,ttl_max,ttl_min";

/// 规则读改写事务锁（`AppState` 无规则锁字段；进程内串行化 add/update/delete，
/// 覆盖「读当前规则集 → 校验 → 落盘 → 重建索引」整段，防并发互相覆盖）。
///
/// # 与订阅面共用（F07）
/// `subscribe::sub_txn` 直接返回本锁，订阅的 `subscribe/update/delete/update_once`
/// 也取它 —— 两个面因此相互排斥，`rules_sub.json` 与 `config.json` 的读改写不会再
/// 互相覆盖（此前各持一把锁 = 没有互斥）。
///
/// # 锁序（防死锁，必须遵守）
/// 1. 先取本锁（异步锁，可跨 `await` 持有）；
/// 2. 再取 `state.cfg` / `state.applied`（`parking_lot` 短临界区，**不得跨 `await` 持有**）；
/// 3. 持锁期间**不得**再调用任何会取本锁的入口 —— 规则 CRUD 与
///    `subscribe::subscribe/update/delete/update_once` 都会取它；无锁的
///    `subscribe::rebuild_all_disk*` / `subscriptions_view` / `rules_payload` 可直接调用；
/// 4. 网络下载必须在取锁**之前**完成；文件/配置写盘只能走 `spawn_blocking`，
///    且不得在持有 `state.cfg` 锁时进行。
pub fn rules_txn() -> &'static tokio::sync::Mutex<()> {
    // **2.1.22 阶段一**：这把锁已从"规则面 + 订阅面共用"**提升为统一持久化锁**
    // （`state_store::state_txn()`）—— 现在 `PUT /api/config` 也取它，于是
    // config / rules / subscriptions 三个面在同一个临界区里完成「读旧 + 算新 + 提交」。
    // 实现收在 `state_store` 里（那里同时提供 `commit_droppable`），本函数保留为
    // 规则面的入口别名，避免 2.1.20/2.1.21 的调用点与锁序注释漂移。
    crate::state_store::state_txn()
}

/// 一条规则的内部表示。
pub(crate) type RuleMap = Map<String, Value>;

/* ---------------- 路径 ---------------- */

/// 规则文件路径：优先 `cfg["rule_local_file"]`，否则 `config.json` 同目录下的
/// `rules_local.json`（复用 `ebpdns_rules::load::local_rules_path`）。
pub fn local_rules_path(cfg: &Value, cfg_path: Option<&Path>) -> PathBuf {
    if let Some(p) = cfg
        .get("rule_local_file")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        // F30：相对路径以 config.json 所在目录为基准（不是进程 CWD）；绝对路径原样。
        return resolve_rel_to_config(Path::new(p), cfg_path);
    }
    match cfg_path {
        Some(p) => ebpdns_rules::load::local_rules_path(p),
        None => PathBuf::from(ebpdns_rules::load::LOCAL_RULES_FILE),
    }
}

/// 相对路径归一（F30）：`p` 为绝对路径 → 原样返回；相对路径 → 相对 `config.json`
/// 所在目录（拿不到目录信息时退回原值，即进程 CWD）。`subscribe::subs_path` 同口径。
pub(crate) fn resolve_rel_to_config(p: &Path, cfg_path: Option<&Path>) -> PathBuf {
    if p.is_absolute() {
        return p.to_path_buf();
    }
    match cfg_path
        .and_then(Path::parent)
        .filter(|d| !d.as_os_str().is_empty())
    {
        Some(dir) => dir.join(p),
        None => p.to_path_buf(),
    }
}

/* ---------------- 2.1.22：规则唯一真源（`state/rules.json`） ---------------- */

/// **规则唯一真源**的路径。
///
/// * `state/` 已启用（`state_dir` 非空）⇒ `<state_dir>/rules.json`；
/// * 未启用（纯内存 / 旧布局 / 目录不可写）⇒ `None`，调用方回落到 2.1.21 的
///   [`local_rules_path`]（**读方与写方都不会静默忽略**，见 [`mirror_rules_paths`]）。
pub fn authoritative_rules_path(state: &AppState) -> Option<PathBuf> {
    let dir = state.state.dir();
    if dir.as_os_str().is_empty() {
        return None;
    }
    Some(dir.join("rules.json"))
}
// >>> 242B BEGIN P0-2-srcbytes >>> //
/// **2.1.42-B（P0-2）**：规则真源（或 2.1.21 回退路径）的**原始字节**快照。
///
/// * 返回 `(path, Some(bytes))` = 文件存在；
/// * 返回 `(path, None)` = 文件不存在（导入失败回滚时应删除本次新建的文件）；
/// * 返回 `None` = 路径无法确定（纯内存态）。
///
/// 导入路径在写盘前用它做**逐字节备份**，失败时原样写回（不是重新序列化）。
pub(crate) fn rules_source_bytes(state: &AppState) -> Option<(PathBuf, Option<Vec<u8>>)> {
    let cfg = state.cfg.read().clone();
    let path = authoritative_rules_path(state)
        .unwrap_or_else(|| local_rules_path(&cfg, state.cfg_path.as_deref()));
    match std::fs::read(&path) {
        Ok(b) => Some((path, Some(b))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some((path, None)),
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e,
                "规则真源读取失败 ⇒ 本次导入无法备份/回滚（将拒绝写入）");
            None
        }
    }
}
// <<< 242B END P0-2-srcbytes <<< //

/// 与真源**同时**被写入、用于"回退到 2.1.21 二进制仍能读"的镜像/发现路径。
///
/// 两种情况，都不静默：
/// 1. `rule_local_file` 显式配置（= [`local_rules_path`]）⇒ 它**不是**真源，
///    但本次提交会一并刷新 ⇒ 打 **WARN 并指明权威文件**；
/// 2. 未显式配置 ⇒ `config.json` 同目录下的 `rules_local.json`（2.1.21 的默认位置）
///    ⇒ 同样刷新（不告警：它就是真源的历史位置）。
pub fn mirror_rules_paths(
    cfg: &Value,
    cfg_path: Option<&Path>,
    authoritative: &Path,
) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let explicit = cfg
        .get("rule_local_file")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|p| resolve_rel_to_config(Path::new(p), cfg_path));
    if let Some(p) = explicit {
        if p != authoritative {
            // **2.1.23（DEF-222-12）**：这条提示**每个进程只打一次**，且从 WARN 降为 INFO。
            //
            // 2.1.22 每次提交都打同一条 WARN（`migrate_cfg` 启动时会注入 `rule_local_file`
            // ⇒ 每次规则/订阅/config 提交都刷）：隔离实例实测 55 条（= 提交次数），
            // **生产 journal 4000 行内 162 条**（同一秒内 15+ 条）⇒ 日志洪泛。
            //
            // 降级理由：它**不是故障** —— 真源与镜像并存是 2.1.22 的**设计**
            //（镜像只为"回退到 2.1.21 仍能读"）。需要用户知道的只是"手工改那个文件不生效"，
            // 说一次足够。
            //
            // 幂等实现：`OnceLock` + 只在"首次遇到 explicit≠authoritative"时打印；
            // 且**只在值第一次出现时**打印（后续同值不重复）。
            note_mirror_mismatch_once(&p, authoritative);
            out.push(p);
        }
        return out;
    }
    if let Some(cp) = cfg_path {
        let legacy = ebpdns_rules::load::local_rules_path(cp);
        if legacy != authoritative {
            out.push(legacy);
        }
    }
    out
}

/// `rule_local_file` ≠ 真源 的**一次性**提示（**2.1.23 / DEF-222-12**；进程内只打一次）。
fn note_mirror_mismatch_once(configured: &Path, authoritative: &Path) {
    static SEEN: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let key = format!("{}|{}", configured.display(), authoritative.display());
    // `get_or_init` 保证只有第一个调用者走进闭包 ⇒ 天然只打一次。
    let first = SEEN.get_or_init(|| {
        tracing::info!(
            configured = %configured.display(),
            authoritative = %authoritative.display(),
            "配置项 `rule_local_file` 指向的文件**不是规则真源**：从 2.1.22 起规则唯一真源是 \
             `state/rules.json`（每次提交会把两者刷新为同一内容）；请把该键移除或指向真源，\
             否则手工只改该文件不会生效（会被下一次提交覆盖）。\
             **本条提示每个进程只输出一次**（2.1.23 / DEF-222-12：此前每次提交都打）。
             详见 `CONVENTIONS.md` §16。"
        );
        key.clone()
    });
    let _ = first;
}

/* ---------------- 2.1.23：规则文件解析的**唯一**口径 ---------------- */

/// 规则文件的解析结果（**三态**，取代 2.1.22 的 `Option<Vec<Value>>`）。
///
/// # 为什么必须三态（DEF-222-01，P0）
///
/// 2.1.22 的 [`rules_from_bytes`] 返回 `Option`，把"文件不存在"与"文件存在但**读不懂**"
/// 压成同一个 `None`；而 `current_rules_in` 只按 **`path.is_file()`** 区分"空集"与
/// "读不到" ⇒ **文件存在即返回空集**、既不回落也不升 ERROR。后果是**屏蔽规则静默失效
/// （fail-open）**：`state/rules.json` 写成 `{"nope":1}` 或截断 JSON 后，
/// `rules_gen` 回到 FNV 初值、`/api/rules.total=0`，被测域名**被放行**。
///
/// 这是把 2.1.20（A-22）明确修掉的"静默空集"在**新真源**上重新引入。本枚举把三种
/// 语义**在类型上**分开，任何调用点都无法再把"读不懂"当"空"。
#[derive(Clone, Debug)]
pub(crate) enum RulesParse {
    /// 解析成功（**空数组也是成功** ⇒ 用户确实删光了规则，必须如实按空集处理）。
    Parsed(Vec<Value>),
    /// 路径/part **不存在**（与"空集"区分；供迁移与镜像回落判断）。
    Missing,
    /// 存在但**读不懂**（JSON 损坏 / 形状不认识）⇒ 调用方**必须**回落或 fail-closed，
    /// **绝不**允许当成空集。
    Unreadable {
        /// 人类可读原因（进日志）。
        reason: String,
    },
}

impl RulesParse {
    /// 是否"存在但读不懂"（fail-closed 分支的唯一判据；单测用）。
    #[cfg(test)]
    pub(crate) fn is_unreadable(&self) -> bool {
        matches!(self, RulesParse::Unreadable { .. })
    }
    /// 规则条数（`Unreadable` ⇒ `None`，**绝不是 `Some(0)`**；单测用）。
    #[cfg(test)]
    pub(crate) fn len(&self) -> Option<usize> {
        match self {
            RulesParse::Parsed(v) => Some(v.len()),
            _ => None,
        }
    }
}

/// **规则文件解析的唯一实现**（2.1.23 起 `load_local_rules` 与真源解析共用它）。
///
/// 口径（**三种形状都认，第四种绝不静默**）：
/// 1. **裸 JSON 数组** ⇒ 按规则列表解析（2.1.20 / A-22 的兼容行为，**不得回退**）；
/// 2. **信封** `{"rules":[…]}` ⇒ 取 `rules`（`rules` 非数组 ⇒ 形状不认识）；
/// 3. **空数组 / `{"rules":[]}`** ⇒ `Parsed([])`（**合法**："删光规则"必须生效）；
/// 4. **其它形状 / JSON 损坏** ⇒ `Unreadable`（**只能是回落或 fail-closed**）。
///
/// 注意本函数**不改写** `Unreadable` 的判定为"空集" —— 那是 DEF-222-01 的根因。
///
/// **2.1.24**：本函数是**唯一**实现；调用方用 `log_bare` 控制是否打"裸数组兼容模式"INFO。
/// 三个调用面共用它（不复制解析逻辑）：真源读取（`log_bare=true`）、
/// 镜像/回落文件读取（`log_bare=true`）、`GET /api/config.rules` 的只读派生
/// （`log_bare=false`：只读端点不得每个请求写一行日志）。
pub(crate) fn parse_rules_bytes_ex(raw: &[u8], path: &Path, log_bare: bool) -> RulesParse {
    let v: Value = match serde_json::from_slice(raw) {
        Ok(v) => v,
        Err(e) => {
            return RulesParse::Unreadable {
                reason: format!("JSON 解析失败: {e}"),
            }
        }
    };
    match v {
        // ① 裸数组：整个文件就是规则列表（兼容模式，2.1.20 起）。
        Value::Array(arr) => {
            if log_bare {
                tracing::info!(
                    path = %path.display(),
                    rules = arr.len(),
                    "规则文件是**裸 JSON 数组**（非信封格式）：已按规则列表解析（兼容模式）"
                );
            }
            RulesParse::Parsed(arr)
        }
        // ② 信封：取 `rules`。
        Value::Object(o) => match o.get("rules") {
            Some(Value::Array(arr)) => RulesParse::Parsed(arr.clone()),
            Some(_) => RulesParse::Unreadable {
                reason: "键 `rules` 存在但不是数组".to_string(),
            },
            None => RulesParse::Unreadable {
                reason: "对象里没有 `rules` 数组".to_string(),
            },
        },
        // ③ 其它顶层形状（数字/字符串/布尔/null）。
        other => RulesParse::Unreadable {
            reason: format!("顶层既不是数组也不是对象（是 {}）", json_kind(&other)),
        },
    }
}

/// 读**文件**并解析（`Missing` = 不存在；读取失败 = `Unreadable`）。
///
/// **[2.1.23]** 内部改为调用**唯一**解析器 [`parse_rules_bytes_ex`]（与真源同一个实现）
/// ⇒ "独立文件"与"真源"不再可能对同一个文件给出两种答案。
pub(crate) fn parse_rules_file(path: &Path) -> RulesParse {
    parse_rules_file_ex(path, true)
}

/// [`parse_rules_file`] 的**静默**形态（**2.1.24**；`log_bare = false` ⇒ 裸数组不打 INFO）。
pub(crate) fn parse_rules_file_ex(path: &Path, log_bare: bool) -> RulesParse {
    match std::fs::read(path) {
        Ok(b) => parse_rules_bytes_ex(&b, path, log_bare),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => RulesParse::Missing,
        Err(e) => RulesParse::Unreadable {
            reason: format!("读取失败: {e}"),
        },
    }
}

/// JSON 值的类型名（诊断用，不分配）。
fn json_kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// 2.1.23：本进程是否**曾经**遇到"规则真源存在但读不懂"（DEF-222-01 的 fail-closed
/// 观测点）。
///
/// 用途：规则索引重建入口（`subscribe::rebuild_all_disk_stats`）据此把本次重建判为
/// **失败**（`RebuildStats::failed()` ⇒ 端点 500 + ERROR 日志），而不是"0 条规则的
/// 成功重建"。这样"真源坏了"必然在 HTTP 层可见，**不会**静默放行。
static RULE_SOURCE_UNREADABLE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 见 [`RULE_SOURCE_UNREADABLE`]：当前累计次数。
pub(crate) fn rule_source_unreadable_count() -> u64 {
    RULE_SOURCE_UNREADABLE.load(std::sync::atomic::Ordering::Relaxed)
}

/// 见 [`RULE_SOURCE_UNREADABLE`]：置位（每次"存在但读不懂"都调用）。
pub(crate) fn note_rule_source_unreadable() {
    RULE_SOURCE_UNREADABLE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// 真源 + 发现路径的**只读**视图（2.1.23：三态，**绝不静默空集**）。
///
/// 顺序与语义：
/// 1. **真源**（`<state_dir>/rules.json`）：
///    * `Parsed` ⇒ **以真源为准**（并比对镜像、不一致时 WARN 指明权威文件）；
///    * `Missing` ⇒ 回落镜像（合法：新装/旧布局）；
///    * `Unreadable` ⇒ **不回落、不当空集** ⇒ 返回 `Unreadable`（调用方 fail-closed）。
/// 2. **镜像**（`rule_local_file` / `rules_local.json`）：
///    * `Parsed` ⇒ 用它（并 WARN 指明"这不是真源"）；
///    * `Missing` ⇒ `Parsed([])`（真的没有规则文件：2.1.21 的空集语义）；
///    * `Unreadable` ⇒ 返回 `Unreadable`。
///
/// **[DEF-222-01 的修法]** `RulesParse::Parsed(vec![])` 只可能来自"**真的解析出空数组**"
/// 或"**所有候选文件都不存在**"；"存在但读不懂"永远走 `Unreadable`。
///
/// **2.1.24**：`log = false` 是**只读静默**形态 ——
/// **不升 ERROR / 不递增 `rule_source_unreadable` / 不打 WARN、INFO**，判定与返回值逐位相同。
///
/// 适用面很窄，只有一处：`GET /api/config.rules` 的派生（[`config_rules_view`]）。
/// 理由：`rule_source_unreadable` 是**写/重建路径**的观测点（`/api/status` 会显示它，
/// 并驱动 `subscribe::rebuild_all_disk_stats` 判失败）；`GET` 若也自增，同一个坏文件
/// 会被"读一次涨一次"，指标语义就被污染了 —— 只读端点**不得有副作用**。
pub(crate) fn discovered_rules_ex(
    cfg: &Value,
    cfg_path: Option<&Path>,
    state: &AppState,
    log: bool,
) -> RulesParse {
    let auth = authoritative_rules_path(state);
    let (Some(auth), Some(store)) = (auth, state.state.store()) else {
        return RulesParse::Missing;
    };
    let a = match store.read_part(&auth) {
        Ok(b) => parse_rules_bytes_ex(&b, &auth, log),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => RulesParse::Missing,
        Err(e) => RulesParse::Unreadable {
            reason: format!("真源 `{}` 读取失败: {e}", auth.display()),
        },
    };
    let mirrors = mirror_rules_paths(cfg, cfg_path, &auth);
    match a {
        RulesParse::Parsed(av) => {
            // 真源可用 ⇒ 只做"与镜像不一致"的 WARN（含条数），仍以真源为准。
            if log {
                for m in mirrors {
                    if let RulesParse::Parsed(mv) = parse_rules_file(&m) {
                        if mv != av {
                            tracing::warn!(
                                mirror = %m.display(),
                                authoritative = %auth.display(),
                                mirror_rules = mv.len(),
                                authoritative_rules = av.len(),
                                "发现**第二份规则文件**且与真源内容不同 ⇒ **以真源为准**\
                                 （`{}`）；另一份已过期/被手工编辑过（不会被读取）",
                                auth.display()
                            );
                        }
                    }
                }
            }
            RulesParse::Parsed(av)
        }
        RulesParse::Unreadable { reason } => {
            if log {
                let n = rule_source_unreadable_count();
                note_rule_source_unreadable();
                tracing::error!(
                    authoritative = %auth.display(),
                    reason = %reason,
                    occurrences = n + 1,
                    "**规则唯一真源存在但无法解析（fail-closed）**：**不回落、不按空集处理** \
                     ⇒ 本次不启用任何本地规则（屏蔽规则集宁可全拦也不放行）。\
                     修法：把该文件恢复为 `{{\"rules\":[…]}}` 信封或裸数组，\
                     或删除它让服务改用镜像/`config.json.rules`（并会打 WARN）。"
                );
            }
            // 真源坏掉时**不**看镜像：镜像可能是过期副本，拿它顶替会掩盖"真源被改坏"
            // 这件事。要让服务改用镜像，运维必须**先移除真源**（上面 ERROR 已写明）。
            RulesParse::Unreadable { reason }
        }
        RulesParse::Missing => {
            // 真源不存在：回落镜像（2.1.21 的发现路径），全部缺失 ⇒ 空集（合法）。
            for m in mirrors {
                match parse_rules_file_ex(&m, log) {
                    RulesParse::Parsed(mv) => {
                        if log {
                            tracing::warn!(
                                authoritative = %auth.display(),
                                fallback = %m.display(),
                                rules = mv.len(),
                                "规则真源 `{}` **不存在** ⇒ 回落到 {}（{} 条）；\
                                 下一次提交会把真源重建出来",
                                auth.display(),
                                m.display(),
                                mv.len()
                            );
                        }
                        return RulesParse::Parsed(mv);
                    }
                    RulesParse::Unreadable { reason } => {
                        if log {
                            note_rule_source_unreadable();
                            tracing::error!(
                                fallback = %m.display(),
                                reason = %reason,
                                "**规则真源不存在，且回落文件存在但无法解析（fail-closed）** ⇒ \
                                 本次不启用任何本地规则；修好该文件或重建真源"
                            );
                        }
                        return RulesParse::Unreadable { reason };
                    }
                    RulesParse::Missing => {}
                }
            }
            RulesParse::Parsed(Vec::new())
        }
    }
}

/// 本地规则权威读取入口（**2.1.22：`rules_admin` 与 `subscribe` 共用**）。
///
/// 用一个入口的理由：规则索引重建（`subscribe::rebuild_all_disk_stats`）与
/// `GET /api/rules`（`rules_admin::rules_payload`）**必须读到同一份规则集**，
/// 否则会分叉成"列表里有、索引里没有"（2.1.20 的 F20 就是这么来的）。
// >>> 242B BEGIN P1-11-checked >>> //
pub(crate) fn local_rules_authoritative(state: &AppState) -> Vec<Value> {
    local_rules_authoritative_checked(state).0
}

/// **2.1.42-B（P1-11）**：与 [`local_rules_authoritative`] 同一读取链，但把
/// "真源存在却读不懂"作为**本次调用的返回值**（而不是全局计数器前后差）。
///
/// 返回 `(rules, unreadable)`；`unreadable=true` 时调用方必须**保留旧索引**并 5xx。
pub(crate) fn local_rules_authoritative_checked(state: &AppState) -> (Vec<Value>, bool) {
    let path = local_rules_path(&state.cfg.read(), state.cfg_path.as_deref());
    let cfg = state.cfg.read().clone();
    let mut unreadable = false;
    let raw = match state.state.is_on() {
        true => match discovered_rules_ex(&cfg, state.cfg_path.as_deref(), state, true) {
            RulesParse::Parsed(v) => v,
            RulesParse::Unreadable { .. } => {
                unreadable = true;
                Vec::new()
            }
            RulesParse::Missing => legacy_rules_raw(&path, &cfg, true),
        },
        false => legacy_rules_raw(&path, &cfg, true),
    };
    let out = normalize_rules(raw)
        .into_iter()
        .map(Value::Object)
        .collect();
    (out, unreadable)
}
// <<< 242B END P1-11-checked <<< //

/// 规则事务的 part 计划（**唯一**构造点，写路径共用）。
///
/// `cfg_for_disk` 必须**已经**去掉 `rules` 镜像键（2.1.22 起 `config.json` 不再携带它）。
///
/// 返回 `None` ⇔ `state/` 未启用或 `state_dir` 为空 ⇒ 调用方走 2.1.21 的逐份原子写。
pub(crate) fn rules_plan(
    state: &AppState,
    cfg_for_disk: &Value,
    rules: &[Value],
) -> Option<std::collections::BTreeMap<PathBuf, Vec<u8>>> {
    let auth = authoritative_rules_path(state)?;
    state.state.store()?;
    let mut plan = std::collections::BTreeMap::new();
    plan.insert(auth.clone(), StateStore::json_bytes(&rules_doc(rules)));
    for m in mirror_rules_paths(cfg_for_disk, state.cfg_path.as_deref(), &auth) {
        plan.insert(m, StateStore::json_bytes(&rules_doc(rules)));
    }
    if let Some(cp) = state.cfg_path.clone() {
        plan.insert(cp, StateStore::json_bytes(cfg_for_disk));
    }
    Some(plan)
}

/// 规则文件的内容（信封格式；与 [`save_local_rules`] 的键集一致）。
fn rules_doc(rules: &[Value]) -> Value {
    json!({
        "version": 1,
        "saved_at": epoch_secs(),
        "count": rules.len(),
        "rules": rules,
    })
}

/// `config.json` 落盘形态：**去掉** `rules` 镜像键（2.1.22 起 `rules` 唯一真源在
/// `state/rules.json`）。输入是 live cfg 的快照，返回新值（不改原值）。
///
/// 注意：**内存**里的 `state.cfg` 仍保留 `rules` 键 —— `GET /api/config.rules`
/// 的形状因此逐位不变（前端契约），变的只是**磁盘上**不再有第二份规则副本。
///
/// `pub`（不是 `pub(crate)`）的理由：`crates/ebpdns-server/tests/**` 是**外部**
/// 集成测试 crate，它要按产品路径构造 part 就必然要调这个函数。
/// 隐藏它只会逼测试自己复制一份"去镜像键"的逻辑 —— 那正是"两份实现必然漂移"。
pub fn cfg_without_rules_mirror(cfg: &Value) -> Value {
    let mut v = cfg.clone();
    if let Some(o) = v.as_object_mut() {
        o.remove("rules");
    }
    v
}

/// 提交失败 ⇒ `ServerError` 映射（日志级别是本项目的规定动作，不是装饰）：
/// 冲突 ⇒ WARN + 409（带当前 revision）；中止 ⇒ ERROR + 500。
pub(crate) fn commit_err_to_server(e: CommitError) -> ServerError {
    match e {
        CommitError::Conflict { expected, current } => {
            tracing::warn!(
                expected,
                current,
                "持久化提交被拒（if-revision 不符，返回 409）"
            );
            ServerError::Conflict(format!(
                "revision 冲突：期望 {expected}，当前 {current}（请重读后重试）"
            ))
        }
        CommitError::Io { msg } => {
            tracing::error!("{msg}");
            ServerError::Internal
        }
    }
}

/* ---------------- 独立规则文件读写 ---------------- */

/// 读取独立规则文件（`Option` 形态，**保留 2.1.20 起的公开签名**）。
///
/// **[2.1.23]** 内部改为调用**唯一**解析器 [`parse_rules_file`]（与规则真源同一个
/// 实现）⇒ "独立文件"与"真源"不再可能对同一个文件给出两种答案
/// （那正是 DEF-222-14：裸数组时 `/api/rules` 认、`/api/config.rules` 返回 `null`）。
///
/// 语义（与 2.1.20 逐位一致）：
/// * 文件不存在 ⇒ `None`（与「空列表」区分，供迁移判断）；
/// * 裸数组 / 信封 ⇒ `Some(list)`（裸数组是 **A-22 的兼容行为，不得回退**）；
/// * JSON 损坏 / 形状不认识 ⇒ **WARN 并返回 `None`**（调用方回落 `cfg["rules"]`）；
/// * 读取失败 ⇒ `Some(vec![])` + WARN（历史口径，保持不变）。
pub fn load_local_rules(path: &Path) -> Option<Vec<Value>> {
    match parse_rules_file(path) {
        RulesParse::Parsed(v) => Some(v),
        RulesParse::Missing => None,
        RulesParse::Unreadable { reason } => {
            // 读取失败（非 NotFound）在历史口径里是 `Some(vec![])`；两者都"读不懂"，
            // 因此这里统一 WARN 并返回 `None` ⇒ 调用方回落 `cfg["rules"]`。
            tracing::warn!(
                path = %path.display(),
                reason = %reason,
                "**逐条规则独立文件解析不到规则列表**（既不是裸数组、也没有 `rules` 数组）\
                 ⇒ 改为回落 `config.json` 的 `rules`（**不得静默按空规则处理**：\
                 那会让屏蔽规则静默失效）"
            );
            None
        }
    }
}

/// 原子保存规则文件：父目录 mkdir → 写 `<path>.tmp` → fsync 文件 → rename → fsync 父目录；
/// **[历史归因]** 任一步失败清理残留 `.tmp` 并返回 `Err`（对齐 Python `save_local_rules`）。
///
/// 同步 IO；异步调用方须用 `tokio::task::spawn_blocking` 包裹（见 `persist_rules`）。
pub fn save_local_rules(path: &Path, rules: &[Value]) -> std::io::Result<()> {
    let doc = json!({
        "version": 1,
        "saved_at": epoch_secs(),
        "count": rules.len(),
        "rules": rules,
    });
    let body = serde_json::to_vec(&doc)?;
    // **2.1.36（D 批）**：四步协议收敛到 `crate::io_atomic`；本路径保留
    // `<path>.tmp` + 建父目录 + 失败清理三条既有策略。
    crate::io_atomic::atomic_write_bytes_opts(path, &body, &rules_write_opts())
}

/// 规则/配置写盘的统一策略（与 2.1.35 的 `save_local_rules` 逐条一致）。
fn rules_write_opts() -> crate::io_atomic::WriteOptions {
    crate::io_atomic::WriteOptions::appended(".tmp")
}

/// 原子写任意 JSON 文件（同 `save_local_rules` 的 tmp+fsync+rename 语义）。
fn save_json_file(path: &Path, v: &Value) -> std::io::Result<()> {
    let body = serde_json::to_vec_pretty(v)?;
    crate::io_atomic::atomic_write_bytes_opts(path, &body, &rules_write_opts())
}

/// 写规则文件（`spawn_blocking`，不阻塞 async runtime）。
async fn write_rules_file(path: PathBuf, rules: Vec<Value>) -> std::io::Result<()> {
    tokio::task::spawn_blocking(move || save_local_rules(&path, &rules))
        .await
        .map_err(|e| std::io::Error::other(format!("规则写盘任务失败: {e}")))?
}

/// 写 config.json（`spawn_blocking`，不阻塞 async runtime）。
async fn write_json_file(path: PathBuf, v: Value) -> std::io::Result<()> {
    tokio::task::spawn_blocking(move || save_json_file(&path, &v))
        .await
        .map_err(|e| std::io::Error::other(format!("配置写盘任务失败: {e}")))?
}

fn epoch_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/* ---------------- 校验 ---------------- */

fn has_control_char(s: &str) -> bool {
    s.bytes().any(|b| b < 0x20 || b == 0x7f)
}

/// **[历史归因]** Python `repr` 的近似（错误文案对齐用）。
fn repr(v: Option<&Value>) -> String {
    match v {
        None => "None".to_string(),
        Some(Value::String(s)) => format!("'{s}'"),
        Some(Value::Null) => "None".to_string(),
        Some(other) => other.to_string(),
    }
}

/// 校验单条规则（不含 match 必填性由调用方决定）。`Err(文案)` 时调用方回 400。
///
/// **[历史归因]** 对齐 Python `_validate_rule_dict`：action 枚举 → forceIp 的 ip 合法性（非字符串先报
/// 类型错）→ url 非空串 → group 类型（F21：只校验类型，不限制 domestic|global）→ match
/// 非 null/str/非空/≤4096 字节/无控制字符。
pub fn validate_rule(obj: &RuleMap, require_match: bool) -> Result<(), String> {
    let action = obj.get("action").and_then(Value::as_str).unwrap_or("");
    if !RULE_ACTIONS.contains(&action) {
        return Err(format!(
            "非法 action: {} (允许: {})",
            repr(obj.get("action")),
            RULE_ACTIONS.join("/")
        ));
    }
    // F2：forceIp 必须带合法 IPv4/IPv6，否则是永不命中的死规则。
    if action == "forceIp" {
        match obj.get("ip") {
            Some(Value::String(s)) => {
                if s.trim().parse::<std::net::IpAddr>().is_err() {
                    return Err(format!(
                        "forceIp 规则的 ip 必须是合法 IPv4/IPv6 地址 (got {})",
                        repr(obj.get("ip"))
                    ));
                }
            }
            Some(Value::Null) | None => {
                return Err(format!(
                    "forceIp 规则的 ip 必须是合法 IPv4/IPv6 地址 (got {})",
                    repr(obj.get("ip"))
                ));
            }
            Some(_) => return Err("ip must be a string".to_string()),
        }
    }
    // R17 P3-4：规则订阅项的 url 若存在必须是非空字符串（null 会落库成 JSON null）。
    if let Some(u) = obj.get("url") {
        if u.is_null() || u.as_str().is_none_or(|s| s.trim().is_empty()) {
            return Err("url 必须是非空字符串".to_string());
        }
    }
    // R18 P3-3：group 提供时必须为 str（null 视为未提供）。
    // **[历史归因]** F21：**不再**把 action=group 的取值限制为 domestic|global —— Python
    // `_validate_rule_dict`（api.py:274-277）只校验类型；非 domestic 的取值在 resolver
    // 侧等价于 global（resolve.rs:167 仅按 domestic 分流），限制取值只会误拒合法写入。
    match obj.get("group") {
        None | Some(Value::Null) => {}
        Some(Value::String(_)) => {}
        Some(other) => return Err(format!("group 必须是字符串: {}", repr(Some(other)))),
    }
    match obj.get("match") {
        Some(Value::Null) => return Err("match 不能为空".to_string()),
        Some(v) => {
            let Some(s) = v.as_str() else {
                return Err("match 必须是字符串".to_string());
            };
            if s.trim().is_empty() {
                return Err("match 不能为空".to_string());
            }
            if s.len() > MATCH_MAX_BYTES {
                return Err("match 过长 (上限 4096 字节)".to_string());
            }
            if has_control_char(s) {
                return Err("match 不允许包含控制字符".to_string());
            }
        }
        None => {
            if require_match {
                return Err("match 不能为空".to_string());
            }
        }
    }
    Ok(())
}

/// 归一化 `ttl_min`/`ttl_max`：bool 拒绝、`max(0, int(v))` 钳制、`null`/`""` 弹键、
/// **[历史归因]** `min <= max`。对齐 Python `_normalize_rule_ttl`（就地改写为整数）。
pub fn normalize_rule_ttl(obj: &mut RuleMap) -> Result<(), String> {
    for k in ["ttl_min", "ttl_max"] {
        let Some(v) = obj.get(k).cloned() else {
            continue;
        };
        // None / ""（仅精确空串，不 trim）视为未设置 → 弹键。
        if v.is_null() || v.as_str().is_some_and(str::is_empty) {
            obj.remove(k);
            continue;
        }
        // bool 是整数子类，必须显式拒绝（int(True) == 1 会穿透）。
        if v.is_boolean() {
            return Err(format!("{k} 必须是非负整数，不能是布尔值"));
        }
        let Some(n) = ttl_number(&v) else {
            return Err(format!("{k} 必须是非负整数"));
        };
        obj.insert(k.to_string(), Value::from(n));
    }
    if let (Some(a), Some(b)) = (ttl_of(obj, "ttl_min"), ttl_of(obj, "ttl_max")) {
        if a > b {
            return Err("ttl_min 不能大于 ttl_max".to_string());
        }
    }
    Ok(())
}

/// 已归一化后的 TTL 取值。
fn ttl_of(obj: &RuleMap, k: &str) -> Option<u64> {
    obj.get(k).and_then(Value::as_u64)
}

/// **[历史归因]** Python `max(0, int(v))` 的等价：数字截断取整、整数字符串解析、其余类型非法。
fn ttl_number(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                Some(u)
            } else if let Some(i) = n.as_i64() {
                Some(i.max(0) as u64)
            } else {
                // **[历史归因]** 浮点：Python int() 向零截断；非有限/超界钳制。
                n.as_f64()
                    .filter(|f| f.is_finite())
                    .map(|f| f.max(0.0).min(u64::MAX as f64) as u64)
            }
        }
        Value::String(s) => {
            // **[历史归因]** Python int("5") == 5；int("5.5")/"1e3"/"abc" 均 ValueError。
            s.trim()
                .parse::<i128>()
                .ok()
                .map(|i| i.max(0).min(u64::MAX as i128) as u64)
        }
        _ => None,
    }
}

/// 校验 `re:` 正则：空体拒绝、嵌套量词（ReDoS 预检）拒绝、编译失败拒绝。
///
/// 编译检查复用 `ebpdns_rules::RuleIndex::build`（与运行期同一 `regex` 实现），
/// 避免在 server crate 引入新依赖。
pub fn check_rule_regex(match_str: &str) -> Result<(), String> {
    let m = match_str.trim();
    let Some(body) = m.strip_prefix("re:") else {
        return Ok(());
    };
    if body.trim().is_empty() {
        return Err("invalid regex: empty body after 're:'".to_string());
    }
    if has_nested_quantifier(body) {
        return Err(format!(
            "invalid regex: nested quantifier (ReDoS 预检拒绝): {body}"
        ));
    }
    let probe = Rule {
        id: None,
        match_raw: m.to_string(),
        action: Action::Block,
        group: None,
        ip: None,
        enabled: true,
        comment: None,
        source: RuleSource::Local,
    };
    let (_idx, stats) = RuleIndex::build(vec![probe]);
    if stats.rejected > 0 {
        return Err(format!("invalid regex: {body}"));
    }
    Ok(())
}

/// 简化 ReDoS 预检：拒绝「组内以量词结尾 + 组外紧跟量词」的嵌套量词
/// （`(a+)+` / `(a*)*` / `(.+)+` / `(a+){2,}` 等）。转义与字符类内不误判。
fn has_nested_quantifier(pat: &str) -> bool {
    let chars: Vec<char> = pat.chars().collect();
    // 每层括号内「最后一个有意义的字符」：'\0'=始, 'x'=普通, '+'/'*'/'?'=量词。
    let mut stack: Vec<char> = vec!['\0'];
    let mut in_class = false;
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' {
            i += 2;
            continue;
        }
        if in_class {
            if c == ']' {
                in_class = false;
            }
            i += 1;
            continue;
        }
        match c {
            '[' => {
                in_class = true;
                set_last(&mut stack, 'x');
            }
            '(' => stack.push('\0'),
            ')' => {
                let inner = stack.pop().unwrap_or('\0');
                let quantified = quantified_at(&chars, i + 1);
                if quantified && matches!(inner, '+' | '*' | '?') {
                    return true;
                }
                set_last(&mut stack, if quantified { '+' } else { 'x' });
            }
            '+' | '*' | '?' => set_last(&mut stack, c),
            '{' => match chars[i + 1..].iter().position(|&x| x == '}') {
                Some(off) => {
                    let j = i + 1 + off;
                    set_last(
                        &mut stack,
                        if is_repeat_body(&chars[i + 1..j]) {
                            '+'
                        } else {
                            'x'
                        },
                    );
                    i = j;
                }
                None => set_last(&mut stack, 'x'),
            },
            _ => set_last(&mut stack, 'x'),
        }
        i += 1;
    }
    false
}

fn set_last(stack: &mut [char], v: char) {
    if let Some(t) = stack.last_mut() {
        *t = v;
    }
}

/// 位置 `i` 是否紧跟量词（`{m,n}` 只有形如重复时才算）。
fn quantified_at(chars: &[char], i: usize) -> bool {
    match chars.get(i).copied() {
        Some('+') | Some('*') | Some('?') => true,
        Some('{') => chars[i + 1..]
            .iter()
            .position(|&x| x == '}')
            .map(|off| is_repeat_body(&chars[i + 1..i + 1 + off]))
            .unwrap_or(false),
        _ => false,
    }
}

/// `{...}` 内容是否为重复量词体（`2` / `2,` / `2,5` / `,5`）。
fn is_repeat_body(seg: &[char]) -> bool {
    let s: String = seg.iter().filter(|c| !c.is_whitespace()).collect();
    if s.is_empty() {
        return false;
    }
    let digits = |t: &str| !t.is_empty() && t.chars().all(|c| c.is_ascii_digit());
    match s.split_once(',') {
        None => digits(&s),
        Some((a, b)) => {
            let n_ok = (a.is_empty() || digits(a)) && (b.is_empty() || digits(b));
            n_ok && !(a.is_empty() && b.is_empty())
        }
    }
}

/* ---------------- 归一化 / 视图 / id ---------------- */

/// 把配置或规则文件里的条目统一成内部形状（`Option::None` = 非对象或缺 `match`）。
///
/// - 2.0 的 `match_raw` → `match`（v1.9.162 口径）；
/// - `pattern` → `match`、`value` → `group`/`ip`（复用 `ebpdns_rules::normalize_rule`）；
/// - `action` 缺失 → `block`（与引擎 `Action::parse` 的 fail-closed 默认一致）；
/// - `match` 只做 `trim`（**不改大小写、不去尾点**：`re:` 正则需要保真，引擎侧
///   `Rule::match_raw` 自行做 `lower + rstrip('.')`）。其余未知键原样保留。
pub fn normalize_rule_json(v: &Value) -> Option<RuleMap> {
    let mut map = v.as_object()?.clone();
    if let Some(raw) = map.remove("match_raw") {
        let keep = map
            .get("match")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.trim().is_empty());
        if !keep {
            map.insert("match".to_string(), raw);
        }
    }
    ebpdns_rules::normalize_rule(&mut map);
    let m = map
        .get("match")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())?
        .to_string();
    map.insert("match".to_string(), Value::String(m));
    if map.get("action").and_then(Value::as_str).is_none() {
        map.insert("action".to_string(), Value::String("block".to_string()));
    }
    Some(map)
}

/// **2.1.19（F-03）**：校验一整份 `rules` 数组（`PUT /api/config` 的 `rules` 用）。
///
/// 为什么必须单独有它（P1 缺陷）：`PUT /api/config` 走的是
/// [`normalize_rule_json`] + `filter_map` 的路径，**非法条目被静默丢弃**，
/// 而且丢弃发生在统计之前 ⇒ 既不判失败、也不计入 `rejected`，接口照回 **200 `ok:true`**；
/// 更糟的是它还会把 `rules` **覆盖成丢弃后的数组**（用户以为保存成功、实际规则被删）。
/// 同一形状走 `POST /api/rules` 却正确回 **400 "match is required…"** —— 两条路径口径分叉。
///
/// 语义与 `POST /api/rules` **逐条一致**：先 [`normalize_rule_json`]（兼容
/// `match_raw` / `pattern` / `value` 三种历史形状），再 [`validate_rule`]`(require_match=true)`。
/// 返回**逐条原因**（`rules[<i>]: …`），空向量 = 全部合法。
pub fn validate_rules_array(v: &Value) -> Vec<String> {
    let Some(arr) = v.as_array() else {
        return vec!["rules 必须是数组".to_string()];
    };
    let mut errs = Vec::new();
    for (i, item) in arr.iter().enumerate() {
        if !item.is_object() {
            errs.push(format!("rules[{i}]: 规则必须是 JSON 对象"));
            continue;
        }
        let Some(norm) = normalize_rule_json(item) else {
            // `normalize_rule_json` 只在"`match` 缺失/为空/非字符串"时返回 None
            // —— 与 `POST /api/rules` 的 `require_match=true` 报错文案对齐。
            errs.push(format!(
                "rules[{i}]: match is required (match 缺失或为空；got {})",
                repr(item.get("match"))
            ));
            continue;
        };
        if let Err(e) = validate_rule(&norm, true) {
            errs.push(format!("rules[{i}]: {e}"));
        }
    }
    errs
}

/// 规则视图（GET/POST/PUT/DELETE 响应体口径）：`{id, match, action, group?, ip?, ttl_min?, ttl_max?}`。
fn rule_view(m: &RuleMap) -> Value {
    let mut o = Map::new();
    o.insert(
        "id".to_string(),
        m.get("id").cloned().unwrap_or(Value::Null),
    );
    o.insert(
        "match".to_string(),
        Value::String(rule_match(m).unwrap_or("").to_string()),
    );
    o.insert(
        "action".to_string(),
        Value::String(
            m.get("action")
                .and_then(Value::as_str)
                .unwrap_or("block")
                .to_string(),
        ),
    );
    for k in ["group", "ip"] {
        if let Some(s) = m.get(k).and_then(Value::as_str).filter(|s| !s.is_empty()) {
            o.insert(k.to_string(), Value::String(s.to_string()));
        }
    }
    for k in ["ttl_min", "ttl_max"] {
        if let Some(v) = m.get(k).filter(|v| !v.is_null()) {
            o.insert(k.to_string(), v.clone());
        }
    }
    Value::Object(o)
}

/// 取规则匹配表达式（内部 `match` 优先，兼容 2.0 的 `match_raw`）。
fn rule_match(m: &RuleMap) -> Option<&str> {
    m.get("match")
        .and_then(Value::as_str)
        .or_else(|| m.get("match_raw").and_then(Value::as_str))
}

/// **[历史归因]** 惰性补 id（对齐 Python `_local_rules` 的 `rmig%d`）：缺 id 的历史规则也能被
/// PUT/DELETE 定位；写路径随后会整份落盘，纯读路径不落盘。
fn ensure_ids(list: &mut [RuleMap]) {
    for (i, m) in list.iter_mut().enumerate() {
        let has = m
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty());
        if !has {
            m.insert("id".to_string(), Value::String(format!("rmig{}", i + 1)));
        }
    }
}

/// 生成规则 id：`r<epoch_ms>_<6 位 base36 随机>`。
pub fn new_rule_id() -> String {
    format!("r{}_{}", epoch_ms(), base36_6(rand64()))
}

/// 进程内伪随机（xorshift64* + 序号混合；仅用于 id 去重，非安全用途，不引入新依赖）。
fn rand64() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static STATE: AtomicU64 = AtomicU64::new(0);
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let mut s = STATE.load(Ordering::Relaxed);
    if s == 0 {
        s = (epoch_ms() as u64) ^ ((std::process::id() as u64) << 32) ^ 0x9E37_79B9_7F4A_7C15;
    }
    s ^= SEQ
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15);
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    if s == 0 {
        s = 0xA5A5_5A5A_1234_5678;
    }
    STATE.store(s, Ordering::Relaxed);
    s
}

fn base36_6(mut x: u64) -> String {
    const AL: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut out = [b'0'; 6];
    for slot in out.iter_mut().rev() {
        // x % 36 < 36 == AL.len()，恒在界内。
        *slot = AL[(x % 36) as usize];
        x /= 36;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 把**当前** `state.cfg["rules"]` 落盘（独立规则文件 + config.json）并重建索引。
///
/// 供**绕过本模块事务**的写路径使用 —— 目前唯一调用方是
/// `api.rs::rules_import`（`/api/rules/import`）：它直接调
/// `resolver.import_rules()` 修改了内存里的 `ResolverConfig.rules`，再自行回写
/// `state.cfg["rules"]`，此前既不写 `rules_local.json` 也不重建索引之外的持久化，
/// 于是：导入的规则只有本次进程内可见，`systemctl restart ebpdns` 后即消失
/// （且索引重建入口 `local_rules_with_drops` 在文件缺失时读的是 `cfg["rules"]`，
/// 一旦文件存在就与之分叉）。这里统一按 `commit_rules` 的口径补齐
/// 「落盘 → 重建索引」，失败返回 500（内存可保持，磁盘未写入）。
///
/// 锁：内部取 `rules_txn()`（与 add/update/delete/订阅 CRUD 同一把锁）。
/// 调用方**不得**已持该锁（锁序第 3 条）。
///
/// `state.cfg_path` 为 `None`（纯内存态，测试/嵌入式）→ 跳过落盘、只重建索引
/// （索引此时读 `cfg["rules"]`；避免向进程 CWD 写 `rules_local.json`）。
pub async fn persist_current(state: &AppState, tag: &str) -> Result<usize, ServerError> {
    let _txn = rules_txn().lock().await;
    // 落盘口径：以 live cfg 的 `rules` 为准（其中已由调用方写好 id/形状），
    // 只替换 `rules` 一个键（F08），其余键保持 live 值。
    let list: Vec<RuleMap> = match state.cfg.read().get("rules").and_then(Value::as_array) {
        Some(arr) => arr
            .iter()
            .filter_map(normalize_rule_json)
            .collect::<Vec<RuleMap>>(),
        None => Vec::new(),
    };
    if state.cfg_path.is_none() {
        if let Err(e) = rebuild_index(state, &list) {
            tracing::error!("规则索引重建失败 ({tag}，详情见服务端日志): {e}");
            return Err(ServerError::Internal);
        }
        return Ok(list.len());
    }
    let merged = apply_rules_live(state, &list);
    if let Err(e) = persist_rules(state, &merged, &list).await {
        tracing::error!("规则写盘失败 ({tag}): {e}");
        return Err(commit_err_to_server(e));
    }
    if let Err(e) = rebuild_index(state, &list) {
        tracing::error!("规则索引重建失败 ({tag}，详情见服务端日志): {e}");
        return Err(ServerError::Internal);
    }
    Ok(list.len())
}

/// **2.1.20（A-06 回滚支持）**：把规则索引**强制重建**为当前 `cfg["rules"]` 的内容，
/// **不写盘**（磁盘文件由调用方自行回滚）。
///
/// 用途：`PUT /api/config` 的**晚失败**回滚。该端点的顺序是
/// 「写 config.json → 替换内存 cfg → `persist_current`（写规则文件 + 重建索引）」，
/// 因此规则文件写失败时，内存与磁盘**已经被改**、而索引停在"新规则"上 ——
/// 表现为"配置里有规则、引擎不执行、`/api/rules` 也看不见"（审计 A-06 实测 500 后四处不一致）。
/// 回滚时先把内存 cfg 还原，再用本函数把索引拉回**同一个**旧规则集；
/// 规则文件本身**故意不重写**（写失败的那个路径再写一次只会再失败一次）。
pub fn rebuild_index_from_cfg(state: &AppState) -> Result<usize, ServerError> {
    let list: Vec<RuleMap> = match state.cfg.read().get("rules").and_then(Value::as_array) {
        Some(arr) => arr.iter().filter_map(normalize_rule_json).collect(),
        None => Vec::new(),
    };
    let n = list.len();
    // `rebuild_index` 的 `Err` 是 `String`（人类可读原因）；统一映射为 `ServerError::Internal`
    // （调用方是回滚路径，只关心成败 + 记日志）。
    rebuild_index(state, &list).map_err(|e| {
        tracing::error!("规则索引重建失败（回滚路径）: {e}");
        ServerError::Internal
    })?;
    Ok(n)
}

/* ---------------- 读取当前规则集 ---------------- */

/// 当前规则集。
///
/// 2.1.22 起读方**一律以唯一真源 `state/rules.json` 为准**（`state` 已启用时），
/// 真源不存在/不可解析才回落 `path`（2.1.21 的 `rules_local.json` / `cfg["rules"]`）。
/// 非法条目跳过并告警（与 `ebpdns_rules::load::load_local_rules_file` 同口径），
/// 缺 id 惰性补 `rmig%d`。纯同步读（小文件），写路径的落盘才是 `spawn_blocking`。
/// [`current_rules_in`] 的旧签名（**仅测试**用；生产读路径一律走 `current_rules_in`
/// 并带 `Some(&state)`，否则会绕过"真源优先 + 不一致 WARN"）。
#[cfg(test)]
fn current_rules(path: &Path, cfg: &Value) -> Vec<RuleMap> {
    current_rules_in(path, cfg, None)
}

/// [`current_rules`] 的带 `AppState` 版本（2.1.22 真源优先；2.1.23 fail-closed）。
///
/// **[DEF-222-01 修法]** 2.1.22 在这里按 `path.is_file()` 把"真源存在但读不懂"
/// 当成"空规则集"返回 ⇒ 屏蔽规则静默失效。现在：`Unreadable` **返回空集但已升 ERROR
/// 并置位** [`RULE_SOURCE_UNREADABLE`]，由 `subscribe::local_rules_with_drops` 把本次
/// 索引重建判为**失败**（端点 500），因此"真源坏了"不可能被读成"规则集为空"。
pub(crate) fn current_rules_in(path: &Path, cfg: &Value, state: Option<&AppState>) -> Vec<RuleMap> {
    current_rules_in_ex(path, cfg, state, true)
}

/// [`current_rules_in`] 的**只读静默**形态（**2.1.24**）：`log = false` 时整条读取链
/// （`discovered_rules_ex` → `parse_rules_file_ex` → `legacy_rules_raw`）都不打日志、
/// 不递增 `rule_source_unreadable`；**判定与返回值与 `log = true` 逐位相同**。
pub(crate) fn current_rules_in_ex(
    path: &Path,
    cfg: &Value,
    state: Option<&AppState>,
    log: bool,
) -> Vec<RuleMap> {
    let raw = match state {
        Some(st) if st.state.is_on() => {
            match discovered_rules_ex(cfg, st.cfg_path.as_deref(), st, log) {
                RulesParse::Parsed(v) => v,
                // **读不懂 ⇒ 空集 + 已在 discovered_rules 里升 ERROR**（fail-closed）。
                RulesParse::Unreadable { .. } => Vec::new(),
                // 真源与镜像都不存在 ⇒ 2.1.21 口径的最后兜底（`config.json.rules`）。
                RulesParse::Missing => legacy_rules_raw(path, cfg, log),
            }
        }
        _ => legacy_rules_raw(path, cfg, log),
    };
    normalize_rules(raw)
}

/// 2.1.21 口径的读取（独立文件优先；**文件缺失或读不懂** ⇒ 回落 `cfg["rules"]`）。
///
/// **[2.1.23]** 改为经共享解析器（与真源同一个实现 ⇒ DEF-222-14 的"同一文件两种答案"
/// 不可能再出现），但**回落口径保持 2.1.20 / A-22 的行为**：
/// * `Parsed` ⇒ 用它；
/// * `Missing` ⇒ 回落 `cfg["rules"]`；
/// * `Unreadable` ⇒ 回落 `cfg["rules"]`（`load_local_rules` 已打 WARN；
///   2.1.20 起"损坏 ⇒ 回落"是**明确修过的行为**，不得回退成静默空集）。
///
/// 注意：**真源**（`state/rules.json`）的 `Unreadable` 走的是另一条路
/// （`discovered_rules` ⇒ fail-closed，**不回落**）—— 因为真源坏了说明 2.1.22+
/// 的状态目录被改坏，而"独立文件"只是 2.1.21 的遗留发现路径。
fn legacy_rules_raw(path: &Path, cfg: &Value, log: bool) -> Vec<Value> {
    match parse_rules_file_ex(path, log) {
        RulesParse::Parsed(v) => v,
        RulesParse::Unreadable { .. } | RulesParse::Missing => cfg
            .get("rules")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
    }
}

/// `GET /api/config` 的 `rules` 字段（**2.1.24 / DEF-222-14 收口**）：**恒为数组**。
///
/// # 契约
///
/// `GET /api/config.rules` **永远**是数组，空则 `[]`。前端
/// （`web/src/pages/config.rs::cfg_list()` 与"逐条规则"表）按数组遍历；`null`/缺失会让
/// 页面显示"0 条"而 `/api/rules.total` 另有说法 —— 两个端点自相矛盾。
///
/// # 2.1.23 实测的缺陷（交付报告 ⑫(2)）
///
/// 2.1.22-era 配置经 `migrate-config` 迁移后，`config.json` 的 `rules` **镜像键被删除**
/// （单一真源 = `state/rules.json`），内存 `cfg` 因此也没有该键；旧实现 `get_config`
/// 只做 `desensitize(&cfg)` 直接回显 ⇒ 该字段**消失**（前端读到 `undefined`/`null`），
/// 而同一次测量里 `/api/rules.total=1`、wire 上规则确实生效。
/// 即：**规则实质正确，但契约形状变了**。
///
/// # 口径（与 `/api/rules` **同源**，不另起第二套读法）
///
/// 1. live `cfg` 里已有 `rules` 数组 ⇒ **原样返回**（形状逐位不变；写路径
///    `apply_rules_live` 会同步它，因此这也是"刚保存的规则立刻可见"的那条路）；
/// 2. 否则（镜像键已被迁移删除 / 从未有）⇒ 走 [`current_rules_in_ex`] 从**真源**派生
///    （与 `/api/rules`、索引重建**同一个**读取入口 ⇒ 三处不可能分叉）；
/// 3. 真源/镜像**存在但读不懂** ⇒ `[]`（形状契约优先；判定仍由写/重建路径 fail-closed）；
/// 4. **只读**：不递增 `rule_source_unreadable`、不升 ERROR（`GET` 不得有副作用）。
pub(crate) fn config_rules_view(state: &AppState) -> Value {
    // ① 内存镜像（若在）优先 —— 逐位保持 2.1.23 的形状。
    let cfg = state.cfg.read().clone();
    if let Some(arr) = cfg.get("rules").and_then(Value::as_array) {
        return Value::Array(arr.clone());
    }
    // ② 镜像键已被迁移删除 ⇒ 从真源派生（静默：只读端点不产生日志/指标副作用）。
    let path = local_rules_path(&cfg, state.cfg_path.as_deref());
    let derived = current_rules_in_ex(&path, &cfg, Some(state), false);
    Value::Array(derived.into_iter().map(Value::Object).collect())
}

/// 归一化 + 补 id。
pub(crate) fn normalize_rules(raw: Vec<Value>) -> Vec<RuleMap> {
    let mut out: Vec<RuleMap> = Vec::with_capacity(raw.len());
    for item in &raw {
        match normalize_rule_json(item) {
            Some(m) => out.push(m),
            None => tracing::warn!("逐条规则跳过非法条目（非对象或缺 match）: {:?}", item),
        }
    }
    ensure_ids(&mut out);
    out
}

/// 用规则集生成待落盘的 config.json（`rules` 同步一份，其余键原样保留）。
fn cfg_with_rules(cfg: &Value, list: &[RuleMap]) -> Value {
    let mut new_cfg = cfg.clone();
    if !new_cfg.is_object() {
        new_cfg = Value::Object(Map::new());
    }
    if let Some(o) = new_cfg.as_object_mut() {
        o.insert(
            "rules".to_string(),
            Value::Array(list.iter().cloned().map(Value::Object).collect()),
        );
    }
    new_cfg
}

/* ---------------- 事务：提交 / 回滚 ---------------- */

/// 变更前快照（仅规则集；`config` 的其它键以 **live cfg** 为准，见 F08）。
pub(crate) struct Snapshot {
    rules: Vec<RuleMap>,
}

/// 把 live `state.cfg` 的 `rules` 键替换为给定规则集（**只**动这一个键，F08），
/// 返回替换后的 config 快照供落盘。`parking_lot` 短临界区，不跨 `await`。
fn apply_rules_live(state: &AppState, rules: &[RuleMap]) -> Value {
    let mut guard = state.cfg.write();
    let merged = cfg_with_rules(&guard, rules);
    *guard = merged.clone();
    merged
}

/// 把规则集写入 resolver 索引。`Err` = 可观测的索引退化（全部规则被拒或被丢弃）。
///
/// `RuleIndex::build` 对坏规则是「计数跳过」而非返回错误，`rule_from_json` 返回 `None`
/// 的条目更是在进索引前就被丢弃，故这里把
/// 「本次一条规则都没进索引且存在被拒/被丢弃的规则」判为失败（否则历史遗留脏规则会让
/// 任何一次增删改都 500，而「全部死掉」又会 200 通过、索引为空 —— F20）。
fn rebuild_index(state: &AppState, _list: &[RuleMap]) -> Result<(), String> {
    // F01：**不能**只把本地规则塞进索引。订阅规则只存在于 `rules_sub.json`，
    // 任何一次规则 CRUD 若用「仅本地」重建，会把订阅来的拦截/分流规则整体摘除，
    // 最长要等一个 `rule_sub_interval`（默认 1h）才恢复 —— 静默的安全规则失效。
    // 唯一权威重建入口是 subscribe::rebuild_all_disk_stats（本地 + 订阅展开，带丢弃统计），
    // **[历史归因]** 与 Python `resolver.py:3647 _rebuild_rule_index` 同口径。
    let stats = crate::subscribe::rebuild_all_disk_stats(state);
    if stats.failed() {
        return Err(format!(
            "规则索引重建失败: indexed={} rejected={} dropped={}",
            stats.indexed, stats.rejected, stats.dropped
        ));
    }
    Ok(())
}

/// 落盘：独立规则文件 + config.json 的 `rules`（两者保持一致）。
async fn persist_rules(
    state: &AppState,
    cfg: &Value,
    rules: &[RuleMap],
) -> Result<(), CommitError> {
    let arr: Vec<Value> = rules.iter().cloned().map(Value::Object).collect();
    // **2.1.22 阶段一**：`state/` 已启用 ⇒ 规则真源 + 镜像 + `config.json`（**无 `rules`
    // 镜像键**）在**一个世代**里原子提交（提交点 = `commit.json` 的原子替换）。
    // 三个 part 跨目录（`/etc` 与 `/var/lib`）是常态：协议只要求"先 fsync 各 part 目录
    // 再写提交点"，见 `state_store.rs` 文件头与 `CONVENTIONS.md`。
    if let Some(store) = state.state.store() {
        let cfg_disk = cfg_without_rules_mirror(cfg);
        let plan = rules_plan(state, &cfg_disk, &arr).unwrap_or_default();
        if !plan.is_empty() {
            let out = tokio::task::spawn_blocking({
                let store = std::sync::Arc::clone(store);
                let plan = plan.clone();
                move || crate::state_store::commit_droppable(&store, "rules", &plan)
            })
            .await
            .map_err(|e| CommitError::Io {
                msg: format!("规则提交任务失败（join error）: {e}"),
            })?;
            return out.map(|_| ());
        }
    }
    // ---- 未启用统一事务（纯内存 / 目录不可写）⇒ 逐位保留 2.1.21 的两份原子写 ----
    let path = local_rules_path(cfg, state.cfg_path.as_deref());
    write_rules_file(path, arr)
        .await
        .map_err(|e| CommitError::Io {
            msg: format!("规则文件原子写失败: {e}"),
        })?;
    if let Some(cp) = state.cfg_path.clone() {
        write_json_file(cp, cfg.clone())
            .await
            .map_err(|e| CommitError::Io {
                msg: format!("config.json 原子写失败: {e}"),
            })?;
    }
    Ok(())
}

/// 提交一次规则变更：把 `rules` 键写进 **live cfg** → 落盘 → 重建索引；
/// 任一步失败回滚内存（并尽力回滚磁盘）。
///
/// **调用方必须已持有 [`rules_txn`]**（锁序第 3 条：持锁期间不得再调用会取锁的入口），
/// 提交因此在**持锁内**完成 —— 这正是"并发 50 轮丢更新 = 0"的前提。
pub(crate) async fn commit_rules_locked(
    state: &AppState,
    prev: &Snapshot,
    new_rules: Vec<RuleMap>,
) -> Result<(), ServerError> {
    // F08：提交时重新读 live cfg，只替换 `rules` 键（其余键以 live 值为准）。
    // 旧实现用 handler 入口的 cfg 快照整体覆盖 `state.cfg` 并落盘，在本函数
    // 读盘/`spawn_blocking` 的 await 窗口里，并发 `PUT /api/config` 或订阅变更
    // （`rule_subscriptions` 等键）会被这份陈旧快照静默回退。
    let new_cfg = apply_rules_live(state, &new_rules);
    if let Err(e) = persist_rules(state, &new_cfg, &new_rules).await {
        tracing::error!("规则写盘失败（已回滚内存变更）: {e}");
        rollback(state, prev).await;
        return Err(commit_err_to_server(e));
    }
    if let Err(e) = rebuild_index(state, &new_rules) {
        tracing::error!("规则索引重建失败（详情见服务端日志）: {e}");
        rollback(state, prev).await;
        return Err(ServerError::Internal);
    }
    // **2.1.48 / serving_revision**：规则提交 + 索引重建成功 ⇒ 新世代已在服务。
    state.state.mark_serving();
    Ok(())
}

/// 兼容入口（自取锁）。**生产路径一律走 [`commit_rules_locked`]**；本函数只保留给
/// 不持锁的调用者（当前仅测试），因此**不加** `#[allow]` —— 一旦有生产调用点，
/// 编译器会立刻提醒"这里多了一次取锁"，避免锁序回归。
#[cfg(test)]
async fn commit_rules(
    state: &AppState,
    prev: &Snapshot,
    new_rules: Vec<RuleMap>,
) -> Result<(), ServerError> {
    let _txn = rules_txn().lock().await;
    commit_rules_locked(state, prev, new_rules).await
}

/// 回滚：把 **live cfg 的 `rules` 键**还原为旧规则集 → 把旧规则写回磁盘 →
/// 索引按旧规则重建。
///
/// 只回滚 `rules` 一个键（F08）：整体写回入口快照会把并发 `PUT /api/config`
/// 写入的其它键一起回退，而本函数的目标只是「本次规则变更不生效」。
///
/// 顺序必须是「先落盘、后重建索引」：重建入口 `rebuild_all_disk_stats` 读的是**磁盘**
/// 上的本地 + 订阅规则，若先重建再落盘，会把「刚刚失败的新规则集」再读一遍
/// —— F20 场景（新规则全被丢弃 → 重建失败）下索引会停在空表不回滚。
async fn rollback(state: &AppState, prev: &Snapshot) {
    let merged = apply_rules_live(state, &prev.rules);
    if let Err(e) = persist_rules(state, &merged, &prev.rules).await {
        tracing::warn!("规则文件回滚写盘失败（磁盘可能与内存不一致）: {e}");
    }
    if let Err(e) = rebuild_index(state, &prev.rules) {
        tracing::warn!("规则索引回滚失败（内存 config 已还原）: {e}");
    }
}

/// **[历史归因]** Python 真值语义（`body.get("action") or "group"` 的 `or`）。
fn is_falsy(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::Bool(b) => !b,
        Value::Number(n) => n.as_f64().map(|f| f == 0.0).unwrap_or(false),
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
    }
}

/* ---------------- 端点实现 ---------------- */

/// GET /api/rules 的响应体：`{rules:[...], subscriptions:[...], total:N, total_local, total_subscription, total_all}`。
///
/// **[历史归因]** 规则以独立文件为准（缺文件回退 `cfg["rules"]`），纯读不落盘（对齐 Python
/// `_rules_with_subs`）。订阅列表以 `rules_sub.json` 明细为准聚合（F22，见
/// [`crate::subscribe::subscriptions_view`]）：`count = len(rules)`，文件有而 config
/// **[历史归因]** 没有的订阅也可见，config 有而文件没有的补占位（对齐 Python `_load_subs` 的补齐语义）。
///
/// **2.1.30（真实可用性修复）**：旧 `total` **只数本地规则**，订阅展开的 10 万条只在
/// `/api/pipeline.rules` 里体现 ⇒ 控制台/脚本读 `/api/rules.total` 会误以为"规则为 0"。
/// 这里**只追加**三个字段，不改 `total` 语义：
///   * `total_local` = `total`（本地规则数；向后兼容别名）；
///   * `total_subscription` = 所有订阅 `count` 之和（明细 `rules.len()`，无明细回退 meta）；
///   * `total_all` = `total_local + total_subscription`，与 `/api/pipeline.rules` 同源同值。
pub fn rules_payload(state: &AppState) -> Value {
    let cfg = state.cfg.read().clone();
    let path = local_rules_path(&cfg, state.cfg_path.as_deref());
    let list = current_rules_in(&path, &cfg, Some(state));
    let rules: Vec<Value> = list.iter().map(rule_view).collect();
    let subs = crate::subscribe::subscriptions_view(state);
    let total_local = rules.len();
    let total_subscription: usize = subs
        .iter()
        .filter_map(|s| s.get("count").and_then(Value::as_u64))
        .map(|n| n as usize)
        .sum();
    json!({
        "rules": rules,
        "subscriptions": subs,
        // 既有字段：语义保持不变（只数本地规则）。
        "total": total_local,
        // **2.1.30 追加**：本地 / 订阅 / 合计三本账，合计与 /api/pipeline.rules 一致。
        "total_local": total_local,
        "total_subscription": total_subscription,
        "total_all": total_local + total_subscription,
    })
}

/// POST /api/rules：成功 200 `{ok:true, rule:{...}}`；校验失败 400；写盘/建索引失败 500
/// （内存必已回滚）。
pub async fn add_rule(state: AppState, body: Value) -> Result<Value, ServerError> {
    let _txn = rules_txn().lock().await;
    let obj = body
        .as_object()
        .ok_or_else(|| ServerError::BadRequest("规则项必须是对象".to_string()))?;
    // 旧字段名 pattern/value → match/group|ip（与 resolver._normalize_rule 一致）。
    let mut src = obj.clone();
    ebpdns_rules::normalize_rule(&mut src);
    // P2-5：match 必填且必须是字符串（消除「空请求静默创建规则」）。
    let match_s = match src.get("match").and_then(Value::as_str) {
        Some(s) if !s.trim().is_empty() => s.trim().to_string(),
        _ => {
            return Err(ServerError::BadRequest(
                "match is required and must be a string".to_string(),
            ))
        }
    };
    // **[历史归因]** action 缺省 group（Python `body.get("action") or "group"`，含 0/false/"" 真值语义）。
    let action_value = match src.get("action") {
        Some(v) if !is_falsy(v) => v.clone(),
        _ => Value::String("group".to_string()),
    };
    // id：显式提供则沿用（列表内重复 → 400），否则 new_rule_id()。
    let id = match src.get("id") {
        Some(Value::String(s)) if !s.trim().is_empty() => s.trim().to_string(),
        _ => new_rule_id(),
    };

    let mut r: RuleMap = Map::new();
    r.insert("id".to_string(), Value::String(id.clone()));
    r.insert("match".to_string(), Value::String(match_s));
    r.insert("action".to_string(), action_value.clone());
    // **[历史归因]** F21：对齐 Python `api.py:3245-3251` —— 单条 POST **恒**写 `group`/`ip` 两个键
    // **[历史归因]** （`body.get("group") or "domestic"` / `body.get("ip") or ""`，Python `or` 真值语义：
    // **[历史归因]** null/""/0/false/[]/{} 都取默认），此前对 block 不写 group/ip 导致落盘形状与 Python
    // 不一致。引擎只在 action=group/forceIp 时取用它们（`resolve.rs:166`），对 block 无副作用。
    let group_value = match src.get("group") {
        Some(v) if !is_falsy(v) => v.clone(),
        _ => Value::String("domestic".to_string()),
    };
    let ip_value = match src.get("ip") {
        Some(v) if !is_falsy(v) => v.clone(),
        _ => Value::String(String::new()),
    };
    r.insert("group".to_string(), group_value);
    r.insert("ip".to_string(), ip_value);
    // 公共校验：action 枚举 + forceIp 的 ip + group 类型 + match 长度/控制字符。
    validate_rule(&r, true).map_err(ServerError::BadRequest)?;
    check_rule_regex(r.get("match").and_then(Value::as_str).unwrap_or(""))
        .map_err(ServerError::BadRequest)?;
    // **[历史归因]** 规则级 TTL 透传（仅这两个键，与 Python _api_add_rule 同型）。
    for k in ["ttl_min", "ttl_max"] {
        if let Some(v) = src.get(k) {
            r.insert(k.to_string(), v.clone());
        }
    }
    normalize_rule_ttl(&mut r).map_err(ServerError::BadRequest)?;

    let cfg = state.cfg.read().clone();
    let path = local_rules_path(&cfg, state.cfg_path.as_deref());
    let mut list = current_rules_in(&path, &cfg, Some(&state));
    if list
        .iter()
        .any(|m| m.get("id").and_then(Value::as_str) == Some(id.as_str()))
    {
        return Err(ServerError::BadRequest(format!("规则 id 重复: {id}")));
    }
    let prev = Snapshot {
        rules: list.clone(),
    };
    list.push(r.clone());
    commit_rules_locked(&state, &prev, list).await?;
    Ok(json!({"ok": true, "rule": rule_view(&r)}))
}

/// PUT /api/rules/{id}：字段白名单部分更新；`id` 出现在 body → 400；找不到 → 404；
/// 成功 `{ok:true, rule:{...}}`。`null` = 删除该字段（`match` 例外，不可清空）。
pub async fn update_rule(state: AppState, id: &str, body: Value) -> Result<Value, ServerError> {
    let _txn = rules_txn().lock().await;
    let obj = body
        .as_object()
        .cloned()
        .ok_or_else(|| ServerError::BadRequest("规则更新体必须是对象".to_string()))?;
    let cfg = state.cfg.read().clone();
    let path = local_rules_path(&cfg, state.cfg_path.as_deref());
    let mut list = current_rules_in(&path, &cfg, Some(&state));
    let Some(idx) = list
        .iter()
        .position(|m| m.get("id").and_then(Value::as_str) == Some(id))
    else {
        return Err(ServerError::NotFoundWith("rule not found".into()));
    };

    // P2-1：先完整校验+归一化（只算 updates/to_pop），全部通过后再写回 + 落盘，
    // 避免边写边校导致内存与磁盘分叉。
    let mut updates: RuleMap = Map::new();
    let mut to_pop: Vec<String> = Vec::new();
    for (k, v) in &obj {
        if k == "id" {
            return Err(ServerError::BadRequest("不允许修改规则 id".to_string()));
        }
        if !RULE_WHITELIST.contains(&k.as_str()) {
            return Err(ServerError::BadRequest(format!(
                "非法规则字段: {k} (允许: {RULE_WHITELIST_SORTED})"
            )));
        }
        if v.is_null() {
            // R16 P3-2：match 是必填键，不允许以 null 移除；其余字段 null = 移除。
            if k == "match" {
                return Err(ServerError::BadRequest("match 不能为空".to_string()));
            }
            to_pop.push(k.clone());
            continue;
        }
        if k == "match" {
            // R17 P3-2：必须是 str（此前 str(v) 会把 123 转成 "123" 穿透校验）。
            let Some(s) = v.as_str() else {
                return Err(ServerError::BadRequest("match 必须是字符串".to_string()));
            };
            if s.trim().is_empty() {
                return Err(ServerError::BadRequest("match 不能为空".to_string()));
            }
            if s.len() > MATCH_MAX_BYTES {
                return Err(ServerError::BadRequest(
                    "match 字段过长 (上限 4096 字节)".to_string(),
                ));
            }
            updates.insert(k.clone(), Value::String(s.trim().to_string()));
            continue;
        }
        if k == "action" && !v.as_str().is_some_and(|s| RULE_ACTIONS.contains(&s)) {
            return Err(ServerError::BadRequest(format!(
                "非法 action: {} (允许: {})",
                repr(Some(v)),
                RULE_ACTIONS.join("/")
            )));
        }
        if k == "ttl_min" || k == "ttl_max" {
            if v.is_boolean() {
                return Err(ServerError::BadRequest(format!(
                    "{k} 必须是非负整数，不能是布尔值"
                )));
            }
            let Some(n) = ttl_number(v) else {
                return Err(ServerError::BadRequest(format!("{k} 必须是非负整数")));
            };
            updates.insert(k.clone(), Value::from(n));
            continue;
        }
        updates.insert(k.clone(), v.clone());
    }

    // 合并后的最终态整体校验（覆盖「只改 ip」「只把 action 改成 forceIp」等部分更新）。
    let mut merged = list[idx].clone();
    for k in &to_pop {
        merged.remove(k);
    }
    for (k, v) in updates {
        merged.insert(k, v);
    }
    validate_rule(&merged, false).map_err(ServerError::BadRequest)?;
    check_rule_regex(merged.get("match").and_then(Value::as_str).unwrap_or(""))
        .map_err(ServerError::BadRequest)?;
    // TTL 归一 + min<=max（并把历史脏值就地修正/拒绝）。
    normalize_rule_ttl(&mut merged).map_err(ServerError::BadRequest)?;

    let prev = Snapshot {
        rules: list.clone(),
    };
    list[idx] = merged.clone();
    commit_rules_locked(&state, &prev, list).await?;
    Ok(json!({"ok": true, "rule": rule_view(&merged)}))
}

/// DELETE /api/rules/{id}：成功 `{ok:true, rule:{被删除的规则}}`；找不到 → 404。
pub async fn delete_rule(state: AppState, id: &str) -> Result<Value, ServerError> {
    let _txn = rules_txn().lock().await;
    let cfg = state.cfg.read().clone();
    let path = local_rules_path(&cfg, state.cfg_path.as_deref());
    let mut list = current_rules_in(&path, &cfg, Some(&state));
    let Some(idx) = list
        .iter()
        .position(|m| m.get("id").and_then(Value::as_str) == Some(id))
    else {
        return Err(ServerError::NotFoundWith("rule not found".into()));
    };
    let prev = Snapshot {
        rules: list.clone(),
    };
    let popped = list.remove(idx);
    commit_rules_locked(&state, &prev, list).await?;
    Ok(json!({"ok": true, "rule": rule_view(&popped)}))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **2.1.33（测试隔离修复，非产品改动）**：`RULE_SOURCE_UNREADABLE` 是**进程级**计数器
    /// （生产语义要求跨请求累计），而 `cargo test` 默认在**同一测试二进制内多线程并行**执行 ——
    /// 三个依赖 `before/after` 差值的用例会互相污染：`config_rules_view_is_always_an_array`
    /// 断言"只读不递增"时，另一个用例恰好在两次读之间置位 ⇒ 偶发失败。
    ///
    /// 修法：一把静态互斥锁把这些用例**串行化**（纯测试基建；`std::sync::Mutex` 无新依赖，
    /// `Mutex::new` 为 `const`）。`rules_admin.rs` 的产品逻辑与计数器语义**一行未改**。
    static RULE_SOURCE_COUNTER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// 取隔离锁；若前一个用例 panic 污染了锁，用 `into_inner` 继续（避免二次假失败）。
    fn counter_isolation() -> std::sync::MutexGuard<'static, ()> {
        RULE_SOURCE_COUNTER_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn m(v: Value) -> RuleMap {
        v.as_object().expect("object").clone()
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        // **2.1.29（测试基础设施修复）**：旧实现只用 `pid + epoch_ms`，两个测试在**同一毫秒**
        // 并行起跑时会拿到**同一个目录**，随后任一测试的 `remove_dir_all` 会删掉对方正在写的
        // 文件 ⇒ 随机 `fs::write(...).unwrap()` panic（实测 `def222_01_missing_authoritative_
        // falls_back_to_mirror` 在整套并行跑时偶发失败、单独跑必过）。加进程内原子序号后
        // 目录名在本进程内**唯一**，是纯测试改动，不影响任何生产路径。
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "ebpdns_rules_admin_{tag}_{}_{}_{}",
            std::process::id(),
            epoch_ms(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).expect("mk temp dir");
        p
    }

    /// 最小 AppState（同 api.rs `test_state()` 的构造方式，额外允许指定 cfg_path）。
    fn test_state(cfg_path: Option<PathBuf>) -> AppState {
        use crate::state::RestartSignal;
        use ebpdns_resolver::clock::RealClock;
        use ebpdns_resolver::config::ResolverConfig;
        use ebpdns_resolver::query::ScriptedQuerier;
        use ebpdns_resolver::Resolver;
        use parking_lot::RwLock;
        use std::sync::Arc;

        let tel = Arc::new(crate::telemetry::ServerTelemetry::new());
        let q = ScriptedQuerier::new(|_n, _t, _d| vec![]);
        let resolver = Resolver::new(
            ResolverConfig::default(),
            tel.clone(),
            Arc::new(RealClock::default()),
            Arc::new(q),
        );
        AppState {
            resolver,
            cfg: Arc::new(RwLock::new(json!({"rules": []}))),
            cfg_path,
            telemetry: tel,
            api_host: Arc::new(RwLock::new("127.0.0.1".to_string())),
            api_port: 8353,
            web_root: None,
            restart: Arc::new(RestartSignal::default()),
            endpoints: Arc::new(RwLock::new(Vec::new())),
            on_reload: None,
            restart_notify: Arc::new(tokio::sync::Notify::new()),
            udp_dropped: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            // state.rs:53 新增字段（`POST /api/reload` 的 changed[] 基准）；本模块不读写它。
            applied: Arc::new(RwLock::new(json!({}))),
            // 2.1.22：本夹具不涉及持久化 ⇒ 旧行为（无统一事务）。
            state: Default::default(),
        }
    }

    /// 内存 config 快照（避免在断言里持锁/跨语句借用锁守卫）。
    fn cfg_snapshot(state: &AppState) -> Value {
        state.cfg.read().clone()
    }

    /* ===================================================================== */
    /* 2.1.23 · DEF-222-01（P0）：规则文件的**五形状矩阵**                    */
    /* ===================================================================== */
    //
    // 审计实测的缺陷形态：`state/rules.json` 写成 `{"nope":1}` 或截断 JSON 时，
    // 2.1.22 把"读不懂"当成"空规则集" ⇒ `/api/rules.total=0`、`rules_gen` = FNV 初值、
    // **被测域名被放行**（fail-open，安全缺陷）。
    //
    // 本矩阵把这五种形状 × 三条路径（真源生效 / 回落镜像 / fail-closed）**逐格断言**，
    // 核心判据只有一条：**绝不出现"静默空集"**。

    /// 五形状的原始字节 + 期望解析结果。
    fn shape_cases() -> Vec<(&'static str, Vec<u8>, Option<usize>)> {
        vec![
            // ① 信封（规范格式）：2 条。
            (
                "envelope",
                serde_json::to_vec(&json!({"version":1,"count":2,
                    "rules":[{"id":"e1","match":"e1.test","action":"block"},
                             {"id":"e2","match":"e2.test","action":"block"}]}))
                .unwrap(),
                Some(2),
            ),
            // ② 裸数组（2.1.20 / A-22 的兼容行为，**不得回退**）：1 条。
            (
                "bare-array",
                serde_json::to_vec(&json!([{"id":"b1","match":"b1.test","action":"block"}]))
                    .unwrap(),
                Some(1),
            ),
            // ③ 空数组：**合法**（"删光规则"必须生效）⇒ 0 条，**不是** Unreadable。
            ("empty-array", b"[]".to_vec(), Some(0)),
            // ④ 形状不认识的对象：⇒ Unreadable（**不得当空集**）。
            ("unknown-object", b"{\"nope\":1}".to_vec(), None),
            // ⑤ 截断 JSON：⇒ Unreadable。
            ("truncated", b"{\"rules\":[{\"match\":\"x\"".to_vec(), None),
        ]
    }

    #[test]
    fn def222_01_parse_matrix_never_silently_empty() {
        let dir = tmp_dir("p0_matrix");
        for (name, raw, want_len) in shape_cases() {
            let p = dir.join(format!("{name}.json"));
            std::fs::write(&p, &raw).unwrap();
            let got = parse_rules_bytes_ex(&raw, &p, true);
            match want_len {
                Some(n) => {
                    assert_eq!(
                        got.len(),
                        Some(n),
                        "[{name}] 必须是 Parsed({n})（**空集也必须是 Parsed(0)**）"
                    );
                    assert!(!got.is_unreadable(), "[{name}] 不得被判为 Unreadable");
                }
                None => {
                    assert!(
                        got.is_unreadable(),
                        "[{name}] **形状不认识/损坏必须 Unreadable**（2.1.22 在这里静默成空集）"
                    );
                    assert_eq!(got.len(), None, "[{name}] Unreadable 的 len 必须是 None");
                }
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 五形状 × **真源生效**（`state/` 已启用、真源可解析）：
    /// 裸数组必须被真源解析（DEF-222-14 的 `/api/config.rules` 形状问题）。
    #[test]
    fn def222_01_and_14_authoritative_bare_array_is_parsed_not_null() {
        let _counter_guard = counter_isolation();
        let dir = tmp_dir("p0_bare");
        let state_dir = dir.join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        let cfg_path = dir.join("config.json");
        let mut st = test_state(Some(cfg_path.clone()));
        st.state = std::sync::Arc::new(crate::state::StateCtx::with_store(
            std::sync::Arc::new(crate::state_store::StateStore::open(&state_dir, 2).unwrap()),
            state_dir.clone(),
        ));
        *st.cfg.write() = json!({"rules": [], "state_dir": state_dir.display().to_string()});

        // 真源 = 裸数组 1 条。
        let auth = state_dir.join("rules.json");
        std::fs::write(
            &auth,
            serde_json::to_vec(&json!([{"id":"bare","match":"bare-p0.test","action":"block"}]))
                .unwrap(),
        )
        .unwrap();
        let payload = rules_payload(&st);
        assert_eq!(
            payload["total"],
            json!(1),
            "真源是裸数组 ⇒ 必须解析出 1 条（2.1.22 这里 total=0 而 /api/rules 另说一套）"
        );
        // `GET /api/config.rules` 派生形状必须**非 null**（DEF-222-14）。
        let cfg_rules = current_rules_in(&auth, &cfg_snapshot(&st), Some(&st));
        assert_eq!(
            cfg_rules.len(),
            1,
            "裸数组真源必须产出 1 条，实际 {cfg_rules:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **2.1.24 / DEF-222-14 收口**：`GET /api/config.rules` **恒为数组**。
    ///
    /// 四条断言（对应 2.1.23 交付报告 ⑫(2) 的实测 + 本轮的修法）：
    /// ① **迁移删除镜像键后 ⇒ `[]`**（2.1.23 这里是 `null`：内存 cfg 没有 `rules` 键，
    ///    `get_config` 原样回显 ⇒ 字段消失，而同一次测量 `/api/rules.total=1`）；
    /// ② **真源 1 条 ⇒ 1 条**（由真源派生，与 `/api/rules` 同源，不另起一套读法）；
    /// ③ 派生**只读**：真源读不懂时仍是 `[]`，且**不**递增 `rule_source_unreadable`
    ///    —— 该计数是写/重建路径的 fail-closed 观测点，`GET` 不得有副作用；
    /// ④ 内存镜像在时**原样回显**（写路径 `apply_rules_live` 会同步它 ⇒ 形状逐位不变）。
    #[test]
    fn config_rules_view_is_always_an_array() {
        let _counter_guard = counter_isolation();
        let dir = tmp_dir("cfg_rules_view");
        let state_dir = dir.join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        let cfg_path = dir.join("config.json");
        let mut st = test_state(Some(cfg_path.clone()));
        st.state = std::sync::Arc::new(crate::state::StateCtx::with_store(
            std::sync::Arc::new(crate::state_store::StateStore::open(&state_dir, 2).unwrap()),
            state_dir.clone(),
        ));
        // 迁移后的现场：内存 cfg 里**没有** `rules` 键（镜像键已被删除）。
        *st.cfg.write() = json!({
            "config_version": 3,
            "state_dir": state_dir.display().to_string(),
        });

        // ① 真源是空信封 ⇒ `[]`（**必须是数组**，不是 null）。
        std::fs::write(
            state_dir.join("rules.json"),
            br#"{"version":1,"count":0,"rules":[]}"#,
        )
        .unwrap();
        let got = config_rules_view(&st);
        assert!(got.is_array(), "镜像键被迁移删除后必须是数组，实际 {got}");
        assert_eq!(got.as_array().unwrap().len(), 0, "空真源 ⇒ []，实际 {got}");

        // ② 真源 1 条 ⇒ 1 条（字段原样带出，供前端逐条渲染/删除）。
        std::fs::write(
            state_dir.join("rules.json"),
            serde_json::to_vec(&json!({
                "version": 1, "count": 1,
                "rules": [{"id":"r1","match":"one224.test","action":"block","group":"g1"}]
            }))
            .unwrap(),
        )
        .unwrap();
        let got = config_rules_view(&st);
        let arr = got.as_array().expect("必须是数组");
        assert_eq!(arr.len(), 1, "真源 1 条 ⇒ 1 条，实际 {got}");
        assert_eq!(arr[0]["id"], json!("r1"));
        assert_eq!(arr[0]["match"], json!("one224.test"));
        assert_eq!(arr[0]["action"], json!("block"));

        // ③ 只读：真源读不懂 ⇒ `[]`，且**不**递增 fail-closed 计数。
        let before = rule_source_unreadable_count();
        std::fs::write(state_dir.join("rules.json"), b"{\"nope\":1}").unwrap();
        let got = config_rules_view(&st);
        assert!(got.is_array(), "读不懂也必须回数组，实际 {got}");
        assert_eq!(
            got.as_array().unwrap().len(),
            0,
            "读不懂 ⇒ []（形状契约优先）"
        );
        assert_eq!(
            rule_source_unreadable_count(),
            before,
            "`GET /api/config` 不得递增 rule_source_unreadable（那是写/重建路径的观测点）"
        );

        // ④ 内存镜像在时原样回显（写路径同步它；形状逐位不变）。
        st.cfg.write()["rules"] = json!([{"id":"mir","match":"m.test","action":"allow"}]);
        assert_eq!(
            config_rules_view(&st),
            json!([{"id":"mir","match":"m.test","action":"allow"}])
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 五形状 × **fail-closed**（真源 `Unreadable`）：
    /// **绝不当空集** ⇒ 计数置位、`rules_payload.total=0` 但**已升 ERROR**，
    /// 且**不回落镜像**（镜像可能是过期副本，拿它顶替会掩盖"真源被改坏"）。
    #[test]
    fn def222_01_authoritative_unreadable_is_fail_closed_not_silent_empty() {
        let _counter_guard = counter_isolation();
        for (name, raw, _) in shape_cases() {
            if !parse_rules_bytes_ex(&raw, Path::new("x"), true).is_unreadable() {
                continue; // 只看 Unreadable 的两格
            }
            let dir = tmp_dir(&format!("p0_fc_{name}"));
            let state_dir = dir.join("state");
            std::fs::create_dir_all(&state_dir).unwrap();
            let cfg_path = dir.join("config.json");
            // 镜像里有 3 条**旧**规则 —— 真源坏了时**不允许**拿它顶替。
            let mirror = dir.join("rules_local.json");
            std::fs::write(
                &mirror,
                serde_json::to_vec(&json!({"version":1,"count":3,"rules":[
                    {"id":"m1","match":"m1.test","action":"block"},
                    {"id":"m2","match":"m2.test","action":"block"},
                    {"id":"m3","match":"m3.test","action":"block"}]}))
                .unwrap(),
            )
            .unwrap();
            let mut st = test_state(Some(cfg_path.clone()));
            st.state = std::sync::Arc::new(crate::state::StateCtx::with_store(
                std::sync::Arc::new(crate::state_store::StateStore::open(&state_dir, 2).unwrap()),
                state_dir.clone(),
            ));
            *st.cfg.write() = json!({
                "rules": [],
                "state_dir": state_dir.display().to_string(),
                "rule_local_file": mirror.display().to_string(),
            });
            std::fs::write(state_dir.join("rules.json"), &raw).unwrap();

            let before = rule_source_unreadable_count();
            let got = current_rules_in(&mirror, &cfg_snapshot(&st), Some(&st));
            assert!(
                got.is_empty(),
                "[{name}] fail-closed：真源读不懂 ⇒ **空集**（不回落镜像的 3 条），实际 {}",
                got.len()
            );
            assert!(
                rule_source_unreadable_count() > before,
                "[{name}] 必须**置位** fail-closed 计数（供 RebuildStats 判失败）"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// 五形状 × **回落**（真源 `Missing` + 镜像 `Parsed`）：
    /// 真源不存在时必须回落镜像（新装/旧布局），且**不得**置位 fail-closed。
    #[test]
    fn def222_01_missing_authoritative_falls_back_to_mirror() {
        let _counter_guard = counter_isolation();
        let dir = tmp_dir("p0_fb");
        let state_dir = dir.join("state");
        std::fs::create_dir_all(&state_dir).unwrap(); // 故意不写 rules.json
        let cfg_path = dir.join("config.json");
        let mirror = dir.join("rules_local.json");
        std::fs::write(
            &mirror,
            serde_json::to_vec(&json!({"version":1,"count":1,"rules":[
                {"id":"fb1","match":"fb1.test","action":"block"}]}))
            .unwrap(),
        )
        .unwrap();
        let mut st = test_state(Some(cfg_path.clone()));
        st.state = std::sync::Arc::new(crate::state::StateCtx::with_store(
            std::sync::Arc::new(crate::state_store::StateStore::open(&state_dir, 2).unwrap()),
            state_dir.clone(),
        ));
        *st.cfg.write() = json!({
            "rules": [],
            "state_dir": state_dir.display().to_string(),
            "rule_local_file": mirror.display().to_string(),
        });
        let before = rule_source_unreadable_count();
        let got = current_rules_in(&mirror, &cfg_snapshot(&st), Some(&st));
        assert_eq!(got.len(), 1, "真源缺失 ⇒ 必须回落镜像的 1 条");
        assert_eq!(
            rule_source_unreadable_count(),
            before,
            "回落是**合法路径**，不得置位 fail-closed 计数"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 五形状 × **无 store（2.1.21 口径）**：形状不认识 ⇒ `None`（回落 `cfg["rules"]`），
    /// 与 2.1.20 / A-22 的既有行为**逐位一致**（不得回退）。
    #[test]
    fn def222_01_without_store_shapes_keep_a22_semantics() {
        let _counter_guard = counter_isolation();
        let dir = tmp_dir("p0_nostore");
        let p = dir.join("rules_local.json");
        let cfg = json!({"rules": [{"id":"cfg1","match":"cfg1.test","action":"block"}]});
        for (name, raw, want_len) in shape_cases() {
            std::fs::write(&p, &raw).unwrap();
            let loaded = load_local_rules(&p);
            match want_len {
                Some(n) => assert_eq!(
                    loaded.as_ref().map(|v| v.len()),
                    Some(n),
                    "[{name}] 无 store 时必须解析出 {n} 条"
                ),
                None => assert!(
                    loaded.is_none(),
                    "[{name}] 无 store 时形状不认识/损坏 ⇒ None（⇒ 回落 cfg.rules），\
                     不得静默空集"
                ),
            }
        }
        // 损坏时的回落落点：`current_rules_in`（无 store）必须给出 `cfg["rules"]`。
        std::fs::write(&p, b"{\"nope\":1}").unwrap();
        let got = current_rules_in(&p, &cfg, None);
        assert_eq!(
            got.len(),
            1,
            "损坏 ⇒ 必须回落 cfg.rules 的 1 条，实际 {got:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /* ---- ① validate_rule：action / ip / match ---- */

    #[test]
    fn validate_rule_action_ip_match() {
        // **[历史归因]** action 枚举（缺失也拒绝，对齐 Python `r.get("action") not in _RULE_ACTIONS`）。
        assert!(validate_rule(&m(json!({"action": "nope", "match": "a.com"})), false).is_err());
        assert!(validate_rule(&m(json!({"match": "a.com"})), false).is_err());
        for a in RULE_ACTIONS {
            // forceIp 必须带合法 ip（下一条断言单独覆盖），故这里只校验其余 action。
            if a.contains("forceIp") {
                continue;
            }
            assert!(
                validate_rule(&m(json!({"action": a, "match": "a.com"})), false).is_ok(),
                "action={a} 应通过"
            );
        }
        assert!(
            validate_rule(
                &m(json!({"action": "forceIp", "match": "a.com", "ip": "1.2.3.4"})),
                false
            )
            .is_ok(),
            "forceIp+合法 ip 应通过"
        );
        assert!(
            validate_rule(&m(json!({"action": "forceIp", "match": "a.com"})), false).is_err(),
            "forceIp 缺 ip 应拒绝"
        );
        // match 必填性由调用方决定。
        assert!(validate_rule(&m(json!({"action": "block"})), true).is_err());
        assert!(validate_rule(&m(json!({"action": "block"})), false).is_ok());
        // match：null / 非 str / 空 / 超 4096 字节 / 控制字符。
        assert!(validate_rule(&m(json!({"action": "block", "match": null})), false).is_err());
        assert!(validate_rule(&m(json!({"action": "block", "match": 123})), false).is_err());
        assert!(validate_rule(&m(json!({"action": "block", "match": "   "})), false).is_err());
        assert!(validate_rule(
            &m(json!({"action": "block", "match": "a".repeat(4097)})),
            false
        )
        .is_err());
        assert!(validate_rule(
            &m(json!({"action": "block", "match": "a".repeat(4096)})),
            false
        )
        .is_ok());
        assert!(validate_rule(&m(json!({"action": "block", "match": "a.com\nb"})), false).is_err());
        assert!(validate_rule(&m(json!({"action": "block", "match": "a.com"})), false).is_ok());
        // forceIp 的 ip：缺失 / 空 / 非法 / 非字符串 全拒，合法 IPv4/IPv6 通过。
        assert!(validate_rule(&m(json!({"action": "forceIp", "match": "x.com"})), false).is_err());
        assert!(validate_rule(
            &m(json!({"action": "forceIp", "match": "x.com", "ip": ""})),
            false
        )
        .is_err());
        assert!(validate_rule(
            &m(json!({"action": "forceIp", "match": "x.com", "ip": "999.1.1.1"})),
            false
        )
        .is_err());
        assert!(validate_rule(
            &m(json!({"action": "forceIp", "match": "x.com", "ip": 123})),
            false
        )
        .is_err());
        assert!(validate_rule(
            &m(json!({"action": "forceIp", "match": "x.com", "ip": "1.2.3.4"})),
            false
        )
        .is_ok());
        assert!(validate_rule(
            &m(json!({"action": "forceIp", "match": "x.com", "ip": "2001:db8::1"})),
            false
        )
        .is_ok());
        // group：F21 起只校验类型（不再限定 domestic|global）。
        assert!(validate_rule(&m(json!({"action": "group", "match": "x.com"})), false).is_ok());
        assert!(validate_rule(
            &m(json!({"action": "group", "match": "x.com", "group": "domestic"})),
            false
        )
        .is_ok());
        assert!(validate_rule(
            &m(json!({"action": "group", "match": "x.com", "group": "global"})),
            false
        )
        .is_ok());
        // **[历史归因]** F21：group 取值放宽为任意字符串（Python 只校验类型）。
        assert!(validate_rule(
            &m(json!({"action": "group", "match": "x.com", "group": "other"})),
            false
        )
        .is_ok());
        assert!(validate_rule(
            &m(json!({"action": "group", "match": "x.com", "group": ""})),
            false
        )
        .is_ok());
        assert!(validate_rule(
            &m(json!({"action": "block", "match": "x.com", "group": 5})),
            false
        )
        .is_err());
        // url 若提供必须非空字符串。
        assert!(validate_rule(&m(json!({"action": "block", "url": null})), false).is_err());
    }

    /* ---- ② normalize_rule_ttl：bool 拒绝 / min>max 拒绝 ---- */

    #[test]
    fn normalize_rule_ttl_bool_and_order() {
        let mut o = m(json!({"ttl_min": true}));
        assert!(normalize_rule_ttl(&mut o).is_err(), "bool 必须拒绝");
        let mut o = m(json!({"ttl_max": false}));
        assert!(normalize_rule_ttl(&mut o).is_err(), "bool 必须拒绝");
        let mut o = m(json!({"ttl_min": 10, "ttl_max": 5}));
        assert!(normalize_rule_ttl(&mut o).is_err(), "min>max 必须拒绝");
        // 归一：字符串整数、浮点截断、负数钳 0。
        let mut o = m(json!({"ttl_min": "5", "ttl_max": 9.9}));
        assert!(normalize_rule_ttl(&mut o).is_ok());
        assert_eq!(o["ttl_min"], json!(5));
        assert_eq!(o["ttl_max"], json!(9));
        let mut o = m(json!({"ttl_min": -3}));
        assert!(normalize_rule_ttl(&mut o).is_ok());
        assert_eq!(o["ttl_min"], json!(0));
        // null / "" 弹键。
        let mut o = m(json!({"ttl_min": "", "ttl_max": null}));
        assert!(normalize_rule_ttl(&mut o).is_ok());
        assert!(!o.contains_key("ttl_min") && !o.contains_key("ttl_max"));
        // 非法值。
        let mut o = m(json!({"ttl_min": "abc"}));
        assert!(normalize_rule_ttl(&mut o).is_err());
        let mut o = m(json!({"ttl_min": "5.5"}));
        assert!(normalize_rule_ttl(&mut o).is_err());
        let mut o = m(json!({"ttl_max": [1]}));
        assert!(normalize_rule_ttl(&mut o).is_err());
        // 只给一个字段不做顺序检查。
        let mut o = m(json!({"ttl_max": 1}));
        assert!(normalize_rule_ttl(&mut o).is_ok());
    }

    /* ---- check_rule_regex ---- */

    #[test]
    fn check_rule_regex_contract() {
        assert!(check_rule_regex("a.com").is_ok());
        assert!(check_rule_regex("*.a.com").is_ok());
        assert!(check_rule_regex("re:^ads\\.example$").is_ok());
        assert!(check_rule_regex("re:[\\.0-9]+").is_ok());
        assert!(check_rule_regex("re:").is_err(), "裸 re: 必须拒绝");
        assert!(check_rule_regex("re:   ").is_err());
        assert!(check_rule_regex("re:(a").is_err(), "编译失败必须拒绝");
        assert!(check_rule_regex("re:(a+)+").is_err(), "嵌套量词必须拒绝");
        assert!(check_rule_regex("re:(a*)*").is_err());
        assert!(check_rule_regex("re:(.+)+").is_err());
        assert!(check_rule_regex("re:(a|b)+").is_ok(), "普通分组+量词应通过");
        assert!(check_rule_regex("re:(?:ab)+c").is_ok());
    }

    /* ---- ③ 规则文件 round-trip ---- */

    #[test]
    fn local_rules_file_round_trip() {
        let dir = tmp_dir("rt");
        let path = dir.join("rules_local.json");
        // 文件不存在 → None（与空列表区分）。
        assert!(load_local_rules(&path).is_none());
        let rules = vec![
            json!({"id": "r1", "match": "a.com", "action": "block"}),
            json!({"id": "r2", "match": "*.b.com", "action": "group", "group": "global",
                   "ttl_min": 5, "ttl_max": 60}),
        ];
        save_local_rules(&path, &rules).expect("save");
        assert_eq!(load_local_rules(&path).expect("load"), rules);
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(doc["version"], json!(1));
        assert_eq!(doc["count"], json!(2));
        assert_eq!(doc["rules"], Value::Array(rules.clone()));
        assert!(doc["saved_at"].as_f64().unwrap() > 0.0);
        // 空列表写成功（清空全部）且可读回空。
        save_local_rules(&path, &[]).expect("save empty");
        assert_eq!(
            load_local_rules(&path).expect("load empty"),
            Vec::<Value>::new()
        );
        // **2.1.20（A-22）**：损坏 → **None**（⇒ 调用方回落 `cfg.rules`）+ WARN，
        // **不再**静默返回 `Some([])`（那等于"屏蔽规则静默失效"）。
        std::fs::write(&path, b"{ not json").unwrap();
        assert!(
            load_local_rules(&path).is_none(),
            "损坏文件必须返回 None（回落 cfg.rules），不得静默空集"
        );
        // **2.1.20（A-22）**：**裸 JSON 数组**必须按规则列表解析（此前被静默吞掉）。
        std::fs::write(
            &path,
            serde_json::to_vec(&json!([
                {"id": "bare1", "match": "bare-a.com", "action": "block"},
                {"id": "bare2", "match": "bare-b.com", "action": "block"}
            ]))
            .unwrap(),
        )
        .unwrap();
        let bare = load_local_rules(&path).expect("裸数组必须被解析（不得静默空集）");
        assert_eq!(bare.len(), 2, "裸数组的两条规则都必须被读到：{bare:?}");
        assert_eq!(bare[0]["match"], json!("bare-a.com"));
        // 形状不认识（对象但没有 `rules` 数组）→ None（回落）+ WARN。
        std::fs::write(&path, serde_json::to_vec(&json!({"version": 1})).unwrap()).unwrap();
        assert!(
            load_local_rules(&path).is_none(),
            "对象但没有 `rules` 数组 ⇒ 必须回落（None），不得静默空集"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **2.1.20（A-22，安全相关）**：裸数组格式的 `rules_local.json` 必须**真的让规则生效**
    /// —— 断言读到规则、能进引擎（`normalize_rule_json` 受理）、且 `current_rules`
    /// （生产读取管线）**产出非空**；形状不认识时必须**回落 `cfg.rules`**。
    ///
    /// 缺陷（审计实测）：`rules_local.json` 写成裸数组时 `load_local_rules` 只认信封 ⇒
    /// 返回 `Some(vec![])` ⇒ **无 WARN、不回落、规则索引归 0**、域名照常解析（fail-open）。
    #[test]
    fn a22_bare_array_rules_file_actually_takes_effect() {
        let dir = std::env::temp_dir().join(format!("ebpdns-a22-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("rules_local.json");

        // ① 裸数组：一条 block 规则 ⇒ 必须被解析、被受理、进生产读取管线。
        std::fs::write(
            &path,
            serde_json::to_vec(&json!([{"id":"a22","match":"bare-block.test","action":"block"}]))
                .unwrap(),
        )
        .unwrap();
        let raw = load_local_rules(&path).expect("裸数组必须被解析");
        assert_eq!(
            raw.len(),
            1,
            "裸数组必须产出 1 条规则（此前是 0 条静默空集）"
        );
        let norm = normalize_rule_json(&raw[0]).expect("规则必须能正常化（= 引擎可受理）");
        assert_eq!(
            norm.get("match").and_then(Value::as_str),
            Some("bare-block.test")
        );
        assert_eq!(
            norm.get("action").and_then(Value::as_str),
            Some("block"),
            "裸数组里的 action 必须保留（否则规则语义被改）"
        );
        // 生产管线：**文件优先**，且必须产出这一条（不是空集）。
        let cur = current_rules(&path, &json!({}));
        assert_eq!(
            cur.len(),
            1,
            "current_rules 必须从裸数组文件读到规则（此前为 0 ⇒ 屏蔽静默失效）"
        );

        // ② 形状不认识（JSON 损坏）⇒ **回落 `cfg.rules`**（不得静默空集）。
        std::fs::write(&path, b"{ not json").unwrap();
        let cur_fb = current_rules(
            &path,
            &json!({"rules":[{"match":"fallback.test","action":"block"}]}),
        );
        assert_eq!(
            cur_fb.len(),
            1,
            "规则文件损坏/形状不认识时必须回落到 config.json 的 rules"
        );
        assert_eq!(
            cur_fb[0].get("match").and_then(Value::as_str),
            Some("fallback.test")
        );

        // ③ 反向：**信封格式**（规范）必须仍然优先于 `cfg.rules`（回落不得反向污染）。
        std::fs::write(
            &path,
            serde_json::to_vec(&json!({"version":1,"count":1,
                "rules":[{"id":"env","match":"envelope.test","action":"block"}]}))
            .unwrap(),
        )
        .unwrap();
        let cur_env = current_rules(
            &path,
            &json!({"rules":[{"match":"fallback.test","action":"block"}]}),
        );
        assert_eq!(cur_env.len(), 1);
        assert_eq!(
            cur_env[0].get("match").and_then(Value::as_str),
            Some("envelope.test"),
            "文件存在且格式正确时必须以文件为权威"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn local_rules_path_prefers_cfg_key() {
        // F30：相对路径以 config.json 所在目录为基准（此前按进程 CWD）。
        let cfg = json!({"rule_local_file": "custom/rules.json"});
        assert_eq!(
            local_rules_path(&cfg, Some(Path::new("conf/config.json"))),
            PathBuf::from("conf").join("custom/rules.json")
        );
        // 绝对路径原样。
        let abs = std::env::temp_dir().join("ebpdns-abs-rules.json");
        let cfg = json!({"rule_local_file": abs.display().to_string()});
        assert_eq!(
            local_rules_path(&cfg, Some(Path::new("conf/config.json"))),
            abs
        );
        // 无 config 目录信息 → 退回原值（进程 CWD）。
        let cfg = json!({"rule_local_file": "custom/rules.json"});
        assert_eq!(
            local_rules_path(&cfg, None),
            PathBuf::from("custom/rules.json")
        );
        assert_eq!(
            local_rules_path(&cfg, Some(Path::new("config.json"))),
            PathBuf::from("custom/rules.json")
        );
        // 未配置 → config.json 同目录。
        let cfg = json!({});
        let p = local_rules_path(&cfg, Some(Path::new("conf/config.json")));
        assert_eq!(p.file_name().unwrap(), "rules_local.json");
        assert_eq!(p.parent().unwrap(), Path::new("conf"));
        // 空串/空白视为未设置；无 cfg_path → 当前目录。
        let cfg = json!({"rule_local_file": "   "});
        assert_eq!(
            local_rules_path(&cfg, Some(Path::new("conf/config.json"))),
            PathBuf::from("conf").join("rules_local.json")
        );
        assert_eq!(
            local_rules_path(&json!({}), None),
            PathBuf::from("rules_local.json")
        );
    }

    #[test]
    fn normalize_rule_json_accepts_both_shapes() {
        // 2.0 的 match_raw → match。
        let a = normalize_rule_json(&json!({"match_raw": "*.A.com", "action": "group",
                                           "group": "global"}))
        .unwrap();
        assert_eq!(a["match"], json!("*.A.com"));
        assert!(!a.contains_key("match_raw"));
        // v1.9.162 旧字段 pattern/value。
        let b = normalize_rule_json(&json!({"pattern": "b.com", "value": "9.9.9.9",
                                           "action": "forceIp"}))
        .unwrap();
        assert_eq!(b["match"], json!("b.com"));
        assert_eq!(b["ip"], json!("9.9.9.9"));
        // 缺 action → block（引擎 fail-closed 口径）；空 match / 非对象 → None。
        assert_eq!(
            normalize_rule_json(&json!({"match": "c.com"})).unwrap()["action"],
            json!("block")
        );
        assert!(normalize_rule_json(&json!({"match": "   "})).is_none());
        assert!(normalize_rule_json(&json!("not-an-object")).is_none());
        // id 形状：r<epoch_ms>_<6 位 base36>。
        let id = new_rule_id();
        let body = id.strip_prefix('r').expect("r 前缀");
        let (ms, rand) = body.split_once('_').expect("含下划线");
        assert!(ms.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(rand.len(), 6);
        assert!(rand.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_ne!(new_rule_id(), id);
    }

    /* ---- ④ add / update / delete + 内存回滚 ---- */

    #[tokio::test]
    async fn add_update_delete_round_trip() {
        let dir = tmp_dir("crud");
        let cfg_path = dir.join("config.json");
        let state = test_state(Some(cfg_path.clone()));

        // ---- add ----
        let out = add_rule(state.clone(), json!({"match": "A.com.", "action": "block"}))
            .await
            .expect("add");
        let rid = out["rule"]["id"].as_str().expect("id").to_string();
        assert!(rid.starts_with('r'), "id={rid}");
        assert_eq!(out["rule"]["match"], json!("A.com."));
        // 规则集以「文件 + 引擎索引」为权威口径；`ResolverConfig.rules` 只承载启动
        // 装配的静态规则、不随 CRUD 回写，故断言 rules_payload 而不是它。
        assert_eq!(
            crate::rules_admin::rules_payload(&state)["total"],
            json!(1),
            "rules_payload 规则集"
        );
        assert_eq!(cfg_snapshot(&state)["rules"].as_array().unwrap().len(), 1);
        let file = local_rules_path(&cfg_snapshot(&state), Some(cfg_path.as_path()));
        assert_eq!(load_local_rules(&file).expect("file").len(), 1);
        assert!(state.resolver.match_rule("a.com.").is_some(), "索引已生效");

        // GET payload
        let payload = rules_payload(&state);
        assert_eq!(payload["total"], json!(1));
        assert_eq!(payload["rules"][0]["id"], json!(rid.clone()));
        assert!(payload["subscriptions"].is_array());

        // 重复 id → 400
        let dup = add_rule(
            state.clone(),
            json!({"id": rid.clone(), "match": "b.com", "action": "block"}),
        )
        .await;
        assert!(
            matches!(dup, Err(ServerError::BadRequest(_))),
            "重复 id 必须 400"
        );
        // 缺 match → 400
        assert!(matches!(
            add_rule(state.clone(), json!({"action": "block"})).await,
            Err(ServerError::BadRequest(_))
        ));
        // forceIp 缺 ip → 400
        assert!(matches!(
            add_rule(
                state.clone(),
                json!({"match": "f.com", "action": "forceIp"})
            )
            .await,
            Err(ServerError::BadRequest(_))
        ));

        // ---- update 白名单 / 404 / 语义 ----
        assert!(matches!(
            update_rule(state.clone(), &rid, json!({"id": "x"})).await,
            Err(ServerError::BadRequest(_))
        ));
        assert!(matches!(
            update_rule(state.clone(), &rid, json!({"nope": 1})).await,
            Err(ServerError::BadRequest(_))
        ));
        assert!(matches!(
            update_rule(state.clone(), &rid, json!({"action": "forceIp"})).await,
            Err(ServerError::BadRequest(_))
        ));
        assert!(matches!(
            update_rule(state.clone(), &rid, json!({"match": null})).await,
            Err(ServerError::BadRequest(_))
        ));
        assert!(matches!(
            update_rule(state.clone(), &rid, json!({"ttl_min": true})).await,
            Err(ServerError::BadRequest(_))
        ));
        let up = update_rule(
            state.clone(),
            &rid,
            json!({"match": "c.com", "ttl_min": 5, "ttl_max": 60}),
        )
        .await
        .expect("update");
        assert_eq!(up["rule"]["match"], json!("c.com"));
        assert_eq!(up["rule"]["ttl_min"], json!(5));
        assert_eq!(up["rule"]["ttl_max"], json!(60));
        assert!(state.resolver.match_rule("c.com").is_some());
        let stored = load_local_rules(&file).expect("file");
        assert_eq!(stored[0]["match"], json!("c.com"));
        assert_eq!(stored[0]["ttl_max"], json!(60));
        assert!(matches!(
            update_rule(state.clone(), "nope", json!({"match": "d.com"})).await,
            Err(ServerError::NotFoundWith(_))
        ));

        // ---- delete ----
        let del = delete_rule(state.clone(), &rid).await.expect("delete");
        assert_eq!(del["rule"]["id"], json!(rid.clone()));
        assert_eq!(del["rule"]["match"], json!("c.com"));
        assert_eq!(state.resolver.config().rules.len(), 0);
        assert_eq!(cfg_snapshot(&state)["rules"].as_array().unwrap().len(), 0);
        assert_eq!(load_local_rules(&file).expect("file").len(), 0);
        assert!(matches!(
            delete_rule(state.clone(), &rid).await,
            Err(ServerError::NotFoundWith(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn write_failure_rolls_back_memory() {
        let dir = tmp_dir("rollback");
        // 用普通文件占住目录名 → 父目录 create_dir_all 必失败 → 写盘失败。
        let blocker = dir.join("blocker");
        std::fs::write(&blocker, b"x").expect("blocker");
        let state = test_state(Some(blocker.join("config.json")));

        let err = add_rule(
            state.clone(),
            json!({"match": "fail.example", "action": "block"}),
        )
        .await
        .expect_err("写盘失败必须 Err");
        assert!(matches!(err, ServerError::Internal), "500 语义");
        // 内存必须回滚：cfg["rules"]、resolver 规则集、payload 都不含新规则。
        assert!(cfg_snapshot(&state)["rules"].as_array().unwrap().is_empty());
        assert!(state.resolver.config().rules.is_empty());
        assert_eq!(rules_payload(&state)["total"], json!(0));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /* ---- ⑤ F08：提交只替换 rules 键（live cfg 其余键保持） ---- */

    #[tokio::test]
    async fn commit_rules_only_replaces_rules_key() {
        let dir = tmp_dir("f08");
        let cfg_path = dir.join("config.json");
        let state = test_state(Some(cfg_path.clone()));
        // 提交前 live cfg 已被「并发 PUT /api/config / 订阅变更」写入其它键。
        {
            let mut cfg = state.cfg.write();
            cfg["api"] = json!({"port": 9999});
            cfg["rule_subscriptions"] = json!([{"url": "https://x/r", "count": 3}]);
        }
        let prev = Snapshot { rules: Vec::new() };
        let rules = vec![m(json!({"id": "r1", "match": "a.com", "action": "block"}))];
        commit_rules(&state, &prev, rules).await.expect("commit");

        let live = cfg_snapshot(&state);
        assert_eq!(live["api"]["port"], json!(9999), "陈旧快照不得覆盖其它键");
        assert_eq!(live["rule_subscriptions"][0]["count"], json!(3));
        assert_eq!(live["rules"].as_array().expect("rules").len(), 1);
        assert!(state.resolver.match_rule("a.com").is_some(), "索引已生效");
        // 磁盘与内存一致（含其它键）。
        let disk: Value =
            serde_json::from_str(&std::fs::read_to_string(&cfg_path).expect("read config.json"))
                .expect("json");
        assert_eq!(disk["api"]["port"], json!(9999));
        assert_eq!(disk["rule_subscriptions"][0]["url"], json!("https://x/r"));
        assert_eq!(disk["rules"][0]["id"], json!("r1"));

        // 回滚同样只回滚 `rules` 键。
        rollback(&state, &Snapshot { rules: Vec::new() }).await;
        let after = cfg_snapshot(&state);
        assert_eq!(after["api"]["port"], json!(9999), "回滚不得回退其它键");
        assert!(after["rules"].as_array().expect("rules").is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /* ---- ⑥ F20：rule_from_json 丢弃计入失败判定 ---- */

    #[tokio::test]
    async fn rebuild_index_fails_when_all_local_rules_dropped() {
        let dir = tmp_dir("f20");
        let cfg_path = dir.join("config.json");
        let state = test_state(Some(cfg_path.clone()));
        let path = local_rules_path(&cfg_snapshot(&state), Some(cfg_path.as_path()));
        // forceIp 的 ip 非法：normalize_rule_json 保留、rule_from_json 丢弃 → 进索引前死掉。
        save_local_rules(
            &path,
            &[
                json!({"id": "dead", "match": "dead.com", "action": "forceIp",
                     "ip": "not-an-ip"}),
            ],
        )
        .expect("save");
        let err = rebuild_index(&state, &[]).expect_err("全部规则被丢弃必须判失败");
        assert!(err.contains("规则索引重建失败"), "{err}");
        // 空规则集（无被拒/被丢弃）不算失败。
        save_local_rules(&path, &[]).expect("save empty");
        rebuild_index(&state, &[]).expect("空规则集不算失败");
        // 有一条进索引即成功。
        save_local_rules(
            &path,
            &[json!({"id": "ok", "match": "ok.com", "action": "block"})],
        )
        .expect("save ok");
        rebuild_index(&state, &[]).expect("有规则入索引应成功");
        assert!(state.resolver.match_rule("ok.com").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// F20 端到端：删掉最后一条可用规则后索引将为空 → 500，且内存/磁盘/索引全部回滚。
    #[tokio::test]
    async fn delete_rule_500_and_rollback_when_index_would_be_empty() {
        let dir = tmp_dir("f20e2e");
        let cfg_path = dir.join("config.json");
        let state = test_state(Some(cfg_path.clone()));
        let path = local_rules_path(&cfg_snapshot(&state), Some(cfg_path.as_path()));
        save_local_rules(
            &path,
            &[
                json!({"id": "dead", "match": "dead.com", "action": "forceIp",
                       "ip": "not-an-ip"}),
                json!({"id": "ok", "match": "ok.com", "action": "block"}),
            ],
        )
        .expect("save");
        let err = delete_rule(state.clone(), "ok")
            .await
            .expect_err("索引将为空必须 500");
        assert!(matches!(err, ServerError::Internal), "{err:?}");
        // 回滚：磁盘与内存仍是变更前的两条，索引里 ok.com 仍生效。
        assert_eq!(load_local_rules(&path).expect("file").len(), 2);
        assert_eq!(
            cfg_snapshot(&state)["rules"]
                .as_array()
                .expect("rules")
                .len(),
            2
        );
        assert!(
            state.resolver.match_rule("ok.com").is_some(),
            "索引回滚后规则仍须生效"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /* ---- ⑦ F21：单条 POST 恒写 group/ip；F22：订阅列表以明细为准 ---- */

    #[tokio::test]
    async fn add_rule_writes_python_group_ip_shape() {
        let dir = tmp_dir("f21");
        let cfg_path = dir.join("config.json");
        let state = test_state(Some(cfg_path.clone()));
        let out = add_rule(state.clone(), json!({"match": "b.com", "action": "block"}))
            .await
            .expect("add");
        let id = out["rule"]["id"].as_str().expect("id").to_string();
        let path = local_rules_path(&cfg_snapshot(&state), Some(cfg_path.as_path()));
        let stored = load_local_rules(&path).expect("file");
        let r = stored
            .iter()
            .find(|r| r["id"] == json!(id))
            .expect("落盘条目");
        // 对齐 api.py:3245-3251：block 也恒写 group/ip。
        assert_eq!(r["group"], json!("domestic"));
        assert_eq!(r["ip"], json!(""));
        // rule_view 仍省略空字段（前端契约）。
        assert!(out["rule"].get("ip").is_none(), "{out}");
        // group 取值放宽（F21）：非 domestic|global 也接受。
        let g = add_rule(
            state.clone(),
            json!({"id": "r-custom", "match": "c.com", "action": "group", "group": "custom"}),
        )
        .await
        .expect("自定义 group");
        assert_eq!(g["rule"]["group"], json!("custom"));
        // **[历史归因]** group 类型非 str → 400（Python `_validate_rule_dict` 的类型闸门）。
        assert!(matches!(
            add_rule(
                state.clone(),
                json!({"match": "d.com", "action": "block", "group": 5})
            )
            .await,
            Err(ServerError::BadRequest(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn rules_payload_subscriptions_follow_details_file() {
        let dir = tmp_dir("f22");
        let cfg_path = dir.join("config.json");
        let state = test_state(Some(cfg_path.clone()));
        {
            let mut cfg = state.cfg.write();
            cfg["rule_subscriptions"] = json!([
                {"url": "https://a/r", "action": "block", "count": 99,
                 "updated_at": "2020-01-01 00:00:00"},
                {"url": "https://meta-only/r", "action": "group", "group": "domestic",
                 "count": 7},
            ]);
        }
        let path = crate::subscribe::subs_path(&cfg_snapshot(&state), Some(cfg_path.as_path()));
        crate::subscribe::save_subs(
            &path,
            &[
                json!({"url": "https://a/r", "action": "block", "group": "global",
                       "ip": "1.2.3.4", "updated_at": "2026-01-02 03:04:05",
                       "rules": [{"match": "*.a.com"}, {"match": "*.b.com"}]}),
                json!({"url": "https://file-only/r", "action": "allow",
                       "rules": [{"match": "*.c.com"}]}),
            ],
        )
        .expect("save subs");

        let payload = rules_payload(&state);
        let subs = payload["subscriptions"].as_array().expect("array");
        assert_eq!(
            subs.len(),
            3,
            "明细有/仅 config 有的订阅都必须可见: {subs:?}"
        );
        let a = subs
            .iter()
            .find(|s| s["url"] == json!("https://a/r"))
            .expect("a");
        assert_eq!(a["count"], json!(2), "count 必须取明细 len(rules)");
        assert_eq!(a["updated_at"], json!("2026-01-02 03:04:05"));
        let fo = subs
            .iter()
            .find(|s| s["url"] == json!("https://file-only/r"))
            .expect("file-only");
        assert_eq!(fo["count"], json!(1));
        let mo = subs
            .iter()
            .find(|s| s["url"] == json!("https://meta-only/r"))
            .expect("meta-only");
        assert_eq!(mo["count"], json!(7), "无明细时回退 meta");
        assert_eq!(mo["group"], json!("domestic"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **2.1.30（真实可用性）**：`/api/rules` 的 `total` 只数本地规则；追加
    /// `total_local` / `total_subscription` / `total_all` 三本账，且 `total_all` 与
    /// `/api/pipeline.rules` 的单一来源（`Resolver::rule_count`）一致。
    #[tokio::test]
    async fn rules_payload_total_splits_local_and_subscription() {
        let dir = tmp_dir("f23-total-split");
        let cfg_path = dir.join("config.json");
        std::fs::write(&cfg_path, b"{\"rules\":[]}").expect("write cfg");
        let state = test_state(Some(cfg_path.clone()));
        {
            let mut cfg = state.cfg.write();
            cfg["rule_subscriptions"] = json!([{
                "url": "https://sub/r", "action": "block", "count": 0,
                "updated_at": "2020-01-01 00:00:00"
            }]);
        }
        // 本地 1 条
        let lp = local_rules_path(&cfg_snapshot(&state), Some(cfg_path.as_path()));
        save_local_rules(
            &lp,
            &[json!({"match": "local.test", "action": "block", "group": "domestic"})],
        )
        .expect("save local");
        // 订阅 2 条（明细 rules.len()=2）
        let sp = crate::subscribe::subs_path(&cfg_snapshot(&state), Some(cfg_path.as_path()));
        crate::subscribe::save_subs(
            &sp,
            &[json!({
                "url": "https://sub/r", "action": "block",
                "updated_at": "2026-01-02 03:04:05",
                "rules": [{"match": "a.sub.test"}, {"match": "b.sub.test"}]
            })],
        )
        .expect("save subs");

        let payload = rules_payload(&state);
        assert_eq!(payload["total"], json!(1), "既有 total 语义保持：只数本地");
        assert_eq!(payload["total_local"], json!(1));
        assert_eq!(payload["total_subscription"], json!(2));
        assert_eq!(payload["total_all"], json!(3));

        // 与 /api/pipeline.rules 的单一来源对齐：索引真实条数 == total_all。
        let mk = |m: &str| {
            ebpdns_rules::rule_from_json(
                json!({"match": m, "action": "block"})
                    .as_object()
                    .cloned()
                    .unwrap(),
                ebpdns_rules::RuleSource::Sub,
            )
            .expect("rule")
        };
        state
            .resolver
            .rebuild_rules(vec![mk("local.test"), mk("a.sub.test"), mk("b.sub.test")]);
        assert_eq!(
            state.resolver.rule_count() as u64,
            payload["total_all"].as_u64().expect("number"),
            "total_all 必须等于 pipeline.rules 的单一来源（Resolver::rule_count）"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
