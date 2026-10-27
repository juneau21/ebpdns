//! **[历史归因]** ebpdns 命令行 / 守护进程装配：忠实对齐 Python `cli.py` 的启动顺序与优雅退出。
//!
//! # 启动顺序（对齐 cli.py run()）
//! 1. tracing 初始化（env-filter + fmt）；
//! 2. load_config（文件 or 默认）+ CLI 端口/host 覆盖；
//! 3. 构造 UpstreamRuntime + RealClock + ServerTelemetry + SharedCircuit + ProductionQuerier；
//! 4. Resolver::new；
//! 6. cache.restore（cache_persist gate + persist_ttl）；
//! 7. 起 DNS UDP/TCP 监听 + API server；
//! 8. spawn resolver 后台任务（预取/测速等）。
//!
//! # 优雅退出（SIGTERM/SIGINT 或 /api/restart）
//! 停 DNS/API → cache.serialize 落盘（cache_persist）→ resolver.shutdown → 退出；
//! /api/restart 路径以退出码 3 退出（systemd on-failure 自动拉起）。

// 2.1.8：`default_config()` 的 `json!({...})` 新增了 9 个 2.1.8 键后，`json_internal!`
// 的递归展开触及 256 上限（编译器明确建议提高该值）；仅影响宏展开深度，无运行时语义。
#![recursion_limit = "512"]

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;

use ebpdns_cache::DnsCache;

use clap::{Parser, ValueEnum};
use ebpdns_resolver::breaker::SharedCircuit;
use ebpdns_resolver::clock::RealClock;
use ebpdns_resolver::config::ResolverConfig;
use ebpdns_resolver::config::{CURRENT_CONFIG_VERSION, LEGACY_CONFIG_VERSION};
use ebpdns_resolver::production::ProductionQuerier;
use ebpdns_resolver::Resolver;
use ebpdns_rules::{rule_from_json, RuleSource};
use ebpdns_server::{AppState, DnsServer, ServerTelemetry, StateCtx, VERSION};
use parking_lot::RwLock;
use serde_json::{json, Value};

/// **2.1.22 阶段一**：`state/` 装配（路径解析 / 启动四态序列 / 离线迁移辅助）。
mod cache_persist;
mod main_state;
use tokio::net::TcpListener;
use tokio::sync::Notify;

/// ebpdns 守护进程。
#[derive(Parser, Debug, Clone)]
#[command(name = "ebpdns", version, about = "ebpdns 本地递归 DNS")]
struct Args {
    /// 子命令（默认 run）。
    #[command(subcommand)]
    cmd: Option<Cmd>,

    /// 配置文件路径。
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// DNS UDP 端口（覆盖配置）。
    #[arg(long = "dns-udp-port")]
    dns_udp_port: Option<u16>,

    /// DNS TCP 端口（覆盖配置）。
    #[arg(long = "dns-tcp-port")]
    dns_tcp_port: Option<u16>,

    /// API 监听端口（覆盖配置）。
    #[arg(long = "api-port")]
    api_port: Option<u16>,

    /// API 监听地址（覆盖配置）。
    #[arg(long = "api-host")]
    api_host: Option<String>,

    /// 前台运行（不 daemonize；本实现始终前台，对齐容器/systemd 用法）。
    #[arg(long)]
    foreground: bool,

    /// 日志级别（trace/debug/info/warn/error）。
    #[arg(long)]
    log_level: Option<String>,

    /// 日志格式：plain / json。
    #[arg(long)]
    log_format: Option<LogFormat>,

    // ---- **2.1.23（DEF-222-02 / DEF-222-03）新增：路径逃逸与共享目录的显式开关** ----
    /// **2.1.23（DEF-222-02）**：`state/` 目录（覆盖配置里的 `state_dir`）。
    ///
    /// 存在意义：配置文件损坏时服务**拒绝启动**（fail-closed，见 `--allow-bad-config`）；
    /// 运维若确实想在这种情况下起来，必须用本参数**显式**给出状态目录 ——
    /// 这样"用默认生产路径"就永远不是**意外**结果。
    ///
    /// **2.1.24**：本参数是 **clap 全局参数**（`global = true`）—— 因此
    /// `ebpdns migrate-config --state-dir <目录>` / `ebpdns migrate-config --export-legacy
    /// --state-dir <目录>` 也能用。2.1.23 只在根参数位接受它，于是 `migrate-config`
    /// 的报错文案建议了一个**它自己用不了**的选项（`error: unexpected argument
    /// '--state-dir' found`，实测 rc=2）。
    #[arg(long = "state-dir", global = true)]
    state_dir: Option<PathBuf>,

    /// **2.1.23（DEF-222-02）**：允许在**配置文件解析失败**时用内置默认配置继续启动。
    ///
    /// 默认（不开本开关）是 **fail-closed**：配置文件存在但读不出/不是合法 JSON ⇒
    /// **拒绝启动**（退出码 2）并打印明确原因。理由（审计 DEF-222-02 实测）：
    /// 2.1.22 只打一条 WARN 就继续，于是 `state_dir` 取不到值 ⇒ 回落到
    /// `/var/lib/ebpdns/state` ⇒ **隔离实例会去读写生产的状态目录并执行回退逻辑**。
    /// 打开本开关时**强制要求** `--state-dir`（否则仍然拒绝启动），
    /// 从机制上排除"配置不可信却落到生产路径"。
    #[arg(long = "allow-bad-config")]
    allow_bad_config: bool,

    /// **2.1.23（DEF-222-03）**：允许**多实例共用同一个 `state_dir`**（危险）。
    ///
    /// 默认行为：启动时对 `<state_dir>/.lock` 取**独占 `flock`**；已被别的进程持有
    /// ⇒ **拒绝启动**。共存实例会直接互相覆盖 `config.json` 与提交点（审计实测：
    /// B 实例一次 `PUT /api/config` 就改掉了 A 实例的配置），因此默认拒绝。
    /// 只有"确实要共用一个状态目录"的场景才开它，且会在启动日志留下 WARN。
    ///
    /// **2.1.24**：与 `--state-dir` 一样改为 **clap 全局参数** —— 离线迁移
    /// （`migrate-config` / `--export-legacy`）在服务运行中重锚提交点时**必须**能显式
    /// 表达"我知道服务在跑，仍要重锚"，否则它给出的唯一出路是"停服"。
    #[arg(long = "allow-shared-state-dir", global = true)]
    allow_shared_state_dir: bool,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum LogFormat {
    Plain,
    Json,
}

#[derive(Parser, Debug, Clone)]
enum Cmd {
    /// 启动守护进程（默认）。
    Run,
    /// **2.1.16（修复项 6）**：离线校验配置（不启动服务）。
    ///
    /// 语义：读 `--config`（缺省 `/etc/ebpdns/config.json`）→ `migrate_cfg` 迁移到
    /// 当前 schema 版本 → 全键类型/范围/枚举校验 + 未知键告警。
    /// **退出码**：0 = 无错误（告警不致命）；2 = 有错误（配置不可用）。
    /// 用法：`ebpdns check-config --config /etc/ebpdns/config.json`
    ///
    /// 注意：`--config` 在**子命令上**也有一份（`config`）——clap 的根参数必须在子命令
    /// **之前**给（`ebpdns --config X check-config`），而运维直觉是写在后面，因此这里
    /// 显式再声明一次，两种写法都支持（子命令上的值优先）。
    #[command(name = "check-config", alias = "check")]
    CheckConfig {
        /// 配置文件路径（缺省 `/etc/ebpdns/config.json`）。
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// **2.1.18（修复项 1②）**：**只做加法**的配置迁移（补齐缺失键，写前备份）。
    ///
    /// 语义：读 `--config`（缺省 `/etc/ebpdns/config.json`）→ 解析 JSON →
    /// 补 `default_config()` 里有而文件里缺的**顶层键**（**绝不**改动/删除用户已给出的
    /// 值）→ 执行 schema 迁移（`config_version` 与 1→2 的新增键）→
    /// 备份到 `config.json.bak.<ts>` → 原子写回 → 打印**逐键差异**（补了哪些）。
    ///
    /// 为什么必须由二进制提供（而不是 install.sh 里用 python/jq 拼）：
    /// "2.1.19 的新键集合"就是 `main.rs::default_config()` 这个**函数**——
    /// 任何外部实现都是它的副本，必然随版本漂移。安装脚本调用本子命令即可，
    /// 不必（也不能）自己维护一份键表。
    ///
    /// **退出码**（**2.1.24 定版**，与旧码兼容 —— 旧码只多不少）：
    /// * `0` = 完成（含"无缺失键"的 no-op 与 `--dry-run`）；
    /// * `1` = 文件系统/备份/写回失败；
    /// * `2` = 配置不是合法 JSON 对象 / 迁移后仍有错误（**不改动**文件）；
    /// * `3` = **未落盘**（新增）：既没有 `--state-dir`、配置里也没有 `state_dir`
    ///   ⇒ 只做**只读报告**，**一个字节都不写**（也**绝不**回落到生产路径
    ///   `/var/lib/ebpdns/state` —— 2.1.23 正是在这里把生产状态目录写坏了）；
    /// * `4` = **配置已写回、但提交点未更新**（新增）：重锚 `state/` 失败（最常见原因：
    ///   服务正在运行、持有 `<state_dir>/.lock` 的独占 flock）。这不是"迁移失败"
    ///   —— 配置文件**已经**是迁移后的内容，缺的只是提交点的重锚。
    ///
    /// `--dry-run` 只打印差异不写文件（退出码语义相同）。
    ///
    /// **`--state-dir` / `--allow-shared-state-dir`（2.1.24）**：本子命令现在也接受
    /// 这两个参数（父级 `Args` 上标了 `global = true`）。2.1.23 的缺陷是
    /// `migrate-config` **没有任何指定状态目录的手段**（`--state-dir` 报
    /// `unexpected argument`，rc=2），于是离线迁移只能落到配置里的值或生产默认值。
    #[command(name = "migrate-config", alias = "migrate")]
    MigrateConfig {
        /// 配置文件路径（缺省 `/etc/ebpdns/config.json`）。
        #[arg(short, long)]
        config: Option<PathBuf>,
        /// 只打印将要补的键与备份路径，**不写**任何文件。
        #[arg(long)]
        dry_run: bool,
        /// **只做校验**（等价于 `check-config`），不迁移、不写回。
        ///
        /// 供 install.sh 在"安装后、enable 之前"用**已安装的二进制**复核目标配置
        /// （此时包内二进制可能因跨平台解包丢执行位而不可用，见 install.sh 文档）。
        #[arg(long)]
        check_only: bool,
        /// **2.1.22 阶段一（3 → 2 回退）**：把 `state/rules.json`（规则唯一真源）
        /// **逐字节**导出回 `config.json` 的 `rules` 键，并把 `config_version`
        /// 降回 2 ⇒ 旧二进制（2.1.16 … 2.1.21）能直接读这份配置。
        ///
        /// 语义：**先备份** `config.json.bak.<ts>` → 原子替换。
        /// 真源不存在/不可解析 ⇒ **不改动任何文件**，退出码 2。
        #[arg(long = "export-legacy")]
        export_legacy: bool,
    },
}

/// **2.1.47 / M-247**：glibc 分配器调参 —— 把每线程 arena 上界压到 2 个。
///
/// 背景：8 核机器上 glibc 默认可为每个竞争线程创建独立 arena（上限 8 x cores）。
/// 实测 2.1.46 长跑 `VmData` 涨到 1.5~1.9 GB（24~30 个 64/128 MB arena），
/// 每次全量规则重建（瞬时十几 MB）都会把新 arena 的页"烧"进 RSS 且 `malloc_trim`
/// 无法跨碎片回收 —— 24h soak 的 RSS 单调上行与此吻合。
///
/// 只影响**分配器策略**，不改变任何协议/规则/缓存语义；非 glibc 平台为 no-op。
fn tune_allocator() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    unsafe {
        extern "C" {
            fn mallopt(param: i32, value: i32) -> i32;
        }
        // glibc malloc.h：M_ARENA_MAX = -8（arena 数量硬上限）、
        // M_MMAP_THRESHOLD = -3（超过阈值走 mmap，free 即归还内核）。
        const M_ARENA_MAX: i32 = -8;
        const M_MMAP_THRESHOLD: i32 = -3;
        // **2.1.48 / AUD-07**：arena 上界可配置（默认 2），便于高并发下做 2/4 的 A/B。
        let arena_max = std::env::var("EBPDNS_MALLOC_ARENA_MAX")
            .ok()
            .and_then(|v| v.trim().parse::<i32>().ok())
            .filter(|v| *v >= 1)
            .unwrap_or(2);
        // 失败不致命（老 glibc / 受限 seccomp 下保持默认策略）；返回值记日志供排查。
        let rc_arena = mallopt(M_ARENA_MAX, arena_max);
        // **M-248**：1 MiB 以上分配恒走 mmap —— 订阅响应体（2~4 MB）free 时直接归还
        // 内核，不再有“动态 mmap 阈值上调后被 heap 留住、RSS 逐次台阶上行”的机制。
        let rc_mmap = mallopt(M_MMAP_THRESHOLD, 1024 * 1024);
        tracing::info!(
            arena_max,
            rc_arena,
            rc_mmap,
            "glibc 分配器调参（mallopt M_ARENA_MAX / M_MMAP_THRESHOLD）"
        );
    }
}

/// **2.1.48 / AUD-07**：`tune_allocator()` 必须在 tokio runtime（及其 worker 线程）
/// 创建**之前**执行 —— `#[tokio::main]` 会先 build runtime 再 `block_on` async body，
/// 旧写法“async 体第一条语句”其实晚于 worker 创建，`M_ARENA_MAX` 约束力无法保证。
fn main() {
    tune_allocator();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("构建 tokio runtime 失败");
    rt.block_on(async_main());
}

async fn async_main() {
    let args = Args::parse();

    // **2.1.16（修复项 6）**：`check-config` 子命令 —— 离线校验，不启动任何监听。
    // 必须在 tracing/配置加载之外**先**处理：它只读文件、只做校验、按退出码汇报。
    // `--config` 允许写在子命令上（运维直觉）或根上（clap 传统位置），子命令优先。
    if let Some(Cmd::CheckConfig { config }) = args.cmd.as_ref() {
        let path = config.clone().or_else(|| args.config.clone());
        std::process::exit(run_check_config(path.as_deref()));
    }
    // **2.1.18（修复项 1②）**：`migrate-config` 子命令 —— 只做加法的补齐 + 备份。
    // 同样在任何监听/日志初始化之前处理（它只读写文件 + 按退出码汇报）。
    if let Some(Cmd::MigrateConfig {
        config,
        dry_run,
        check_only,
        export_legacy,
    }) = args.cmd.as_ref()
    {
        let path = config.clone().or_else(|| args.config.clone());
        // **2.1.24**：把 `--state-dir` 与环境变量显式传下去 —— 离线迁移**绝不**自己
        // 去解析"默认运营路径"（见 `migrate_state_dir` 的文档）。
        let env_state_dir = std::env::var("EBPDNS_STATE_DIR").ok();
        std::process::exit(run_migrate_config(
            path.as_deref(),
            *dry_run,
            *check_only,
            *export_legacy,
            args.allow_shared_state_dir,
            args.state_dir.as_deref(),
            env_state_dir.as_deref(),
        ));
    }
    let _ = args.cmd; // 默认 run

    // 1) tracing 初始化。
    //
    // **2.1.19（F-08 修复：`log_level` / `log_format` 配置键完全不生效）**：
    // 此前只把 **CLI 参数**传进来，而 `init_tracing` 里 `EnvFilter::try_from_default_env()`
    // 让 `RUST_LOG` **无条件覆盖**配置 —— 实测：写 `log_level=debug` 重启后 **0 行 DEBUG**，
    // 而加 `RUST_LOG=debug` 立刻有 ⇒ 配置键是**死键**（文档承诺与运行态不符）。
    //
    // 现在的优先级（**写进 README**）：`--log-level`（CLI） > `RUST_LOG`（环境）
    // > 配置文件 `log_level` > 内置默认 `info`；`log_format` 同理：
    // `--log-format` > 配置 `log_format` > 内置默认 `plain`。
    //
    // 实现注意：必须**在加载完整配置之前**读一次文件（日志初始化要尽早，否则启动期
    // 日志会落在默认级别），因此这里只做"peek"：读文件、取这两个键、**不做任何校验**
    // 也不改动 `cfg`。真正的配置加载仍在下面，语义与顺序不受影响。
    let (cfg_log_level, cfg_log_format) = peek_log_config(args.config.as_deref());
    // **2.1.20（A-01 修复：F-08 的反向回归）**：2.1.19 写成
    // `args.log_level.or(cfg_log_level)` 并把 `Some(l)` 直接 `EnvFilter::new(l)`，
    // 于是**只要配置文件里有 `log_level`（出厂模板恒有 `"info"`）`RUST_LOG` 就完全失效**
    // —— 实测 A/B 两组 `RUST_LOG=debug` 都是 0 行 DEBUG，删掉该键才有 1 行。
    // 真正的优先级（注释与 README 都这么写）是：
    //   `--log-level`（CLI） > `RUST_LOG`（环境） > 配置文件 `log_level` > 内置默认 `info`
    // 现在把"选哪个来源"抽成**纯函数** `pick_log_level`（可单测），并把环境变量显式读进
    // 来参与优先级（不再靠 `try_from_default_env` 的隐式行为）。
    let env_log_level = std::env::var("RUST_LOG").ok();
    let (level_src, level_val) = pick_log_level(
        args.log_level.as_deref(),
        env_log_level.as_deref(),
        cfg_log_level.as_deref(),
    );
    init_tracing(&level_val, level_src, args.log_format.or(cfg_log_format));

    // 2) 加载配置 + CLI 覆盖。
    //
    // **2.1.23（DEF-222-02，P0）**：配置文件**存在但读不出来/不是合法 JSON** ⇒
    // **默认 fail-closed（拒绝启动）**，而不是 2.1.22 的"WARN + 内置默认"。
    // 理由（审计实测）：默认配置里取不到 `state_dir` ⇒ 回落到生产路径
    // `/var/lib/ebpdns/state` ⇒ 隔离实例会去读写**别人的**状态目录并执行回退逻辑。
    // 要在这类情况下启动，必须同时给 `--allow-bad-config` **与** `--state-dir`
    //（见下），让"用哪个状态目录"永远是**显式**决定。
    let loaded = load_config(args.config.as_deref());
    let cfg_origin = loaded.origin;
    let mut cfg = loaded.cfg;
    if cfg_origin == ConfigOrigin::FileBroken {
        if !args.allow_bad_config {
            eprintln!(
                "ERROR: 配置文件无法使用（解析失败 / 不存在 / 不可读）：{}\n\
                 （**拒绝启动**：不允许在'配置不可信'时用内置默认继续跑 —— 那会把 \
                 `state_dir` 静默变成生产路径 `/var/lib/ebpdns/state`。）\n\
                 修法：① 修好该 JSON 后重启；或 ② 显式接受风险：\
                 `--allow-bad-config --state-dir <专用状态目录>`。",
                args.config
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "<默认路径>".to_string())
            );
            std::process::exit(2);
        }
        if args.state_dir.is_none() {
            eprintln!(
                "ERROR: `--allow-bad-config` 必须与 `--state-dir <目录>` 一起使用。\n\
                 理由：配置不可信时**不允许**用默认生产状态目录 `/var/lib/ebpdns/state`\
                 （那会让隔离实例读写生产状态）。请显式给出状态目录。"
            );
            std::process::exit(2);
        }
        tracing::warn!(
            state_dir = %args.state_dir.as_ref().map(|p| p.display().to_string()).unwrap_or_default(),
            "**按 `--allow-bad-config` 用内置默认配置继续启动**（配置文件不可用）；\
             状态目录由 `--state-dir` 显式指定。配置文件修好后请去掉这两个开关。"
        );
    }
    apply_cli_overrides(&mut cfg, &args);
    // 2b) 配置迁移/补键：把 default_config() 作为底座合并进来，保证
    //     v1.9.162 契约里的全部顶层键都存在（老配置文件缺 circuit_fails /
    //     rule_local_file 等键时不再"看不见"），并注入规则/订阅独立文件路径。
    migrate_cfg(&mut cfg, args.config.as_deref());
    // **2.1.20（A-03 修复：启动接受 / 写路径拒绝 ⇒ 之后任何保存都失败）**：
    // 启动期对**同一份** `validate_write` 判据做一次校验，越界值**夹取到合法区间**并打
    // **WARN**（含原值/新值/区间），使"启动成功 ⇒ 之后每次 `PUT /api/config` 都能正常保存"。
    //
    // 为什么选"夹取 + WARN"而不是"拒绝启动"：
    //   * 拒绝启动会让一台**原本能正常服务**的机器因为一个越界键彻底下线（可用性优先）；
    //   * `apply_cfg` 本来就在读的时候夹取/忽略（静默）—— 那正是"启动接受、写路径拒绝"
    //     的根源；现在把**同一件事**显式化：夹取结果进内存（`/api/config` 立即回显新值），
    //     并给出可归因的 WARN。磁盘文件保持原样，直到用户下一次保存时被写回合法值
    //     （也可用 `ebpdns migrate-config` 主动规范化）。
    clamp_out_of_range_config(&mut cfg);

    // ---- **2.1.22 阶段一：`state/` 启动序列**（**2.1.23 加固**）----
    //
    // 位置：在 `migrate_cfg` / `clamp_out_of_range_config` **之后**（`state_dir` 与
    // `state_persist` 这两个新键到这一步一定已补齐）、在 AppState 构造**之前**。
    //
    // 序列（顺序不可换）：
    //   resolve_state_dir_checked → StateStore::open(dir, 2) → acquire_state_lock()
    //     → cleanup_stale_tmp() → load() → 四态分派
    //
    // **2.1.23 的三处加固**（审计 DEF-222-02 / DEF-222-03 / DEF-222-04）：
    // ① `state_dir` 解析带 `origin`：**配置不可信时禁止**落到默认生产路径（fail-closed）；
    // ② 取 `state/` **独占 flock** + 校验提交点的 part 是否含自己的 `cfg_path`
    //    （默认拒绝共用 `state_dir` 的第二个实例）；
    // ③ `load()` 的四态**存进 `StateCtx`**，由 `/api/status.state_persist` 如实下发
    //    （2.1.22 只写日志 ⇒ 端点无法区分健康/已回退/Torn）。
    let sd_origin = if args.state_dir.is_some() {
        main_state::StateDirOrigin::Explicit
    } else {
        match cfg_origin {
            ConfigOrigin::FileOk => main_state::StateDirOrigin::Explicit,
            ConfigOrigin::NoFileFresh => main_state::StateDirOrigin::FreshInstall,
            // 配置不可信 ⇒ 只有"显式 --state-dir"才允许（上面已 exit，这里兜底）。
            ConfigOrigin::FileBroken => main_state::StateDirOrigin::ConfigUnusable,
        }
    };
    let state_dir =
        match main_state::resolve_state_dir_checked(&cfg, args.state_dir.as_deref(), sd_origin) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("ERROR: 无法确定 `state/` 目录：{e}");
                std::process::exit(2);
            }
        };
    let state_on = main_state::enabled_by_cfg(&cfg);
    let mut state_ctx = StateCtx::disabled();
    if state_on {
        // ---- ① 独占锁（DEF-222-03）：默认拒绝第二个实例 ----
        let mut lock_note: Option<String> = None;
        let mut lock_ok = true;
        match main_state::acquire_state_lock(&state_dir) {
            Ok(l) => {
                tracing::info!(
                    state_dir = %state_dir.display(),
                    lock = %l.path().display(),
                    "已取得 `state/` 独占锁（单机单实例保护）"
                );
                // 句柄必须活到进程结束 ⇒ 交给静态守卫（drop 即释放 flock）。
                main_state::keep_lock_alive(l);
            }
            Err(e) => {
                if args.allow_shared_state_dir {
                    tracing::warn!(
                        state_dir = %state_dir.display(),
                        error = %e,
                        "**按 `--allow-shared-state-dir` 放行共用 `state_dir`**（危险）：\
                         两个实例会互相覆盖 `config.json` 与提交点，回退点可能指向别的实例"
                    );
                    lock_note = Some(e.to_string());
                } else {
                    eprintln!("ERROR: {e}");
                    std::process::exit(2);
                }
            }
        }
        if let Some((store, ls)) = main_state::open_state(&state_dir) {
            // ---- ② 归属校验（DEF-222-03 第二道）：提交点里必须有本实例的 cfg_path ----
            if let Err(e) = main_state::commit_matches_own_cfg_path(&store, args.config.as_deref())
            {
                if args.allow_shared_state_dir {
                    tracing::warn!(state_dir = %state_dir.display(), "{e}");
                    lock_note = Some(e);
                } else {
                    tracing::error!(state_dir = %state_dir.display(), "{e}");
                    eprintln!("ERROR: {e}");
                    std::process::exit(2);
                }
            }
            // ---- ③ 四态进 StateCtx（DEF-222-04）----
            let info = ebpdns_server::state::LoadStateInfo::from_load_state(&ls, true);
            // >>> 242B BEGIN P1-10-main >>> //
            // **2.1.42-B（P1-10）**：`RolledBack` 时 `load()` 已把 live parts
            // 从 history 恢复（并复验）。但 `cfg` 是在 state 序列**之前**从
            // （当时还撕裂的）live `config.json` 读的 ⇒ 必须按恢复后的文件重读，
            // 否则内存里仍是混合世代。这里重跑与启动相同的归一化，逐位一致。
            if matches!(ls, ebpdns_server::LoadState::RolledBack { .. }) {
                let reloaded = load_config(args.config.as_deref());
                if reloaded.origin == ConfigOrigin::FileOk {
                    cfg = reloaded.cfg;
                    apply_cli_overrides(&mut cfg, &args);
                    migrate_cfg(&mut cfg, args.config.as_deref());
                    clamp_out_of_range_config(&mut cfg);
                    tracing::warn!(
                        "state 已回退并恢复 live parts ⇒ 内存配置已按恢复后的 config.json 重新读取"
                    );
                }
            }
            // <<< 242B END P1-10-main <<< //
            if matches!(ls, ebpdns_server::LoadState::Legacy) {
                match main_state::migrate_legacy_rules(&mut cfg, args.config.as_deref(), &state_dir)
                {
                    Ok(steps) => {
                        for s in &steps {
                            tracing::info!("state/ 迁移: {s}");
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            state_dir = %state_dir.display(),
                            error = %e,
                            "**state/ 旧布局迁移失败**：本次不删除 `config.json.rules`（规则不会丢），\
                             服务按旧行为继续；修好权限后重启或跑 `ebpdns migrate-config`"
                        );
                    }
                }
            }
            state_ctx = StateCtx::with_store(store, state_dir.clone())
                .with_load_state(info)
                .with_lock(lock_ok && lock_note.is_none(), lock_note);
        }
        let _ = &mut lock_ok;
    } else {
        tracing::warn!("配置 `state_persist=false` ⇒ **统一持久化事务已按配置关闭**（退回 2.1.21 的各写者原子写）");
    }
    if state_ctx.is_on() {
        tracing::info!(
            state_dir = %state_dir.display(),
            "统一持久化事务已启用（config / rules / subscriptions 同一提交点）"
        );
    }

    let api_host = cfg
        .get("api")
        .and_then(|a| a.get("host"))
        .and_then(Value::as_str)
        .unwrap_or("127.0.0.1")
        .to_string();
    let api_port = cfg
        .get("api")
        .and_then(|a| a.get("port"))
        .and_then(Value::as_u64)
        .unwrap_or(8353) as u16;
    // 端口不在这里求值：DNS 端口由 `listen.udp/tcp/*6` 内嵌端口 / CLI / `dns_port` 三者
    // 在下面「起 DNS 监听」处统一决议（旧代码在这里算过一次却从没被读过 → 死代码警告）。
    let cache_persist = cfg
        .get("cache_persist")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    // **2.1.18（修复项 13）**：默认值统一为 **0**（与随包模板
    // `packaging/etc/ebpdns/config.json` 及 `default_config()` 一致）。
    //
    // `persist_ttl` 的**确切语义**（此前 README 写"默认 604800"、模板却是 0，
    // 用户看到"重启后缓存很快失效"就以为缓存没恢复）：
    //   - `> 0`：恢复时给条目一个**额外**的持久化窗口上限（秒），即
    //     `min(条目剩余 TTL, persist_ttl)` 之内仍视为有效；
    //   - `= 0`：**只按条目自身的剩余 TTL 承接**（短 TTL 域名重启后很快过期 ——
    //     这是设计行为，不是"缓存丢了"）。
    let persist_ttl = cfg
        .get("persist_ttl")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let cache_file = cfg
        .get("cache_file")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("./ebpdns-cache.json"));
    // **2.1.18（修复项 10）**：**定期落盘间隔**（秒）。
    //
    // 背景（用户实测）：控制台文案此前写"每 60s + 退出保存"，但实现里**只有优雅退出**
    // 那一次写盘 —— 于是"kill -9 / 崩溃"必然丢缓存，且"每 60s"是**没有实现**的承诺。
    // 现在两个都成立：本值（默认 60，`0` = 关闭周期落盘）驱动一个后台任务，
    // 优雅退出那一次仍然保留（见下面「10) 优雅退出」）。
    let cache_save_interval = cfg
        .get("cache_save_interval")
        .and_then(Value::as_u64)
        .unwrap_or(60);

    // 3-4) 构造 resolver 生产装配。
    let mut resolver_cfg = cfg_to_resolver(&cfg);
    // F03：订阅拉取/规则重建的**唯一权威**是 `subscribe::spawn_updater`
    // （它按「本地规则 + 订阅展开」合并重建）。resolver 内置的 bg_loop 会用
    // 「仅订阅 + 硬编码 block」覆盖整个规则索引，使本地规则静默失效，故这里
    // 清空 ResolverConfig.subscriptions 让内置订阅路径空转。
    resolver_cfg.subscriptions.clear();
    let tel = Arc::new(ServerTelemetry::new());
    // 后台采样任务：每 1.5s 采 hit_rate/qps/lat 写入 history ring（前端 5 图折线）。
    tel.clone().spawn_sampler();
    let clock = Arc::new(RealClock::default());
    let cb = SharedCircuit::new();
    let runtime = Arc::new(ebpdns_upstream::UpstreamRuntime::new());
    // **2.1.15（P1 高并发 P50/P99 线性恶化）**：单上游在途请求上限。
    // 与 `ResolverConfig::upstream_max_inflight` 同源（`apply_config` 已按配置写入），
    // 这里下发到 runtime 的闸门；`0` = 关闭（退回 2.1.14 行为）。
    runtime.set_max_inflight(resolver_cfg.upstream_max_inflight);
    // 保留一份句柄注入 resolver：否则 per-upstream 健康统计与健康检查循环
    // 拿不到 runtime（`Resolver::new` 不会自动持有它）。
    let runtime_for_resolver = runtime.clone();
    // 2.1.8 优化项 3/4：数据面调参句柄（自适应并发/对冲/按上游超时）必须与 Resolver
    // **同一份**，否则控制台改 timeout_ms/adaptive_* 只改 resolver cfg，
    // 已经在跑的 querier 仍用旧值（旧实现的静默失效）。这里先构造句柄、两侧共享。
    let tuning = ebpdns_resolver::production::QuerierTuning::from_config(&resolver_cfg);
    let querier = Arc::new(
        ProductionQuerier::new(
            runtime,
            cb,
            clock.clone(),
            resolver_cfg.timeout_ms,
            resolver_cfg.edns,
            resolver_cfg.edns_udp_size,
            resolver_cfg.padding,
            resolver_cfg.dnssec_0x20,
        )
        .with_tuning(tuning.clone()),
    );
    // **2.1.34（D4）**：缓存条目的最大存活时间（秒）—— 只用于“按时间触发快照”的节拍
    // （`min(1800 s, TTL/2)`），不是新配置键。`ttl_max` 与 `ttl` 取较大者，0 表示未配置。
    let cache_ttl_s = (resolver_cfg.ttl as u64).max(resolver_cfg.ttl_max as u64);
    let resolver = Resolver::new(resolver_cfg, tel.clone(), clock.clone(), querier);
    resolver.set_querier_tuning(tuning);
    resolver.set_runtime(runtime_for_resolver);
    // **2.1.19（F-01 修复：`warmup.*` 与在途 governor 在生产从未接线）**：
    // 这两个后台任务此前**只在** `Resolver::new_production` 里被 spawn，而
    // `new_production` 只被测试调用（`tests/production_tests.rs`）—— 生产装配走的是
    // `Resolver::new` + 手工补 `set_querier_tuning`/`set_runtime` ⇒ **任务从未启动**。
    // 实测：`warmup.enabled=true, queries=3` 启动 8s 内上游收到 **0** 条探测查询，
    // 即"上游连接池预热"与"在途上限 governor"两项功能**契约存在但不可达**。
    //
    // 修法：生产装配在 querier / runtime / tuning **全部就位之后**显式启动（顺序与
    // `new_production` 末尾一致，保证预热发的是真实数据面路径）。两者都是
    // `tokio::spawn` 出去的任务，失败不影响启动；进程退出时由 runtime 自动 abort。
    resolver.spawn_upstream_warmup();
    resolver.spawn_inflight_governor();

    // 6) 缓存恢复 + 持久化启动（**2.1.29：缓存持久化 v2**）。
    //
    // 这一处取代了 2.1.28 的 `restore_cache(...)` 直调：`cache_persist::startup`
    // 内部完成 §9.1 的完整启动序列 —— 取 `<cache_file>.lock` 的 flock、按前 8 KiB
    // 判格式（v2 manifest / v1 JSON / 缺失）、v2 走 `recover_v2`、v1 走**同一份**
    // `restore_cache_v1` 并尝试一次性迁移；任何失败都**不阻止启动**。
    //
    // `EBPDNS_CACHE_FORMAT=v1` 是**紧急回滚**开关（不新增配置键）：强制走 v1 读/写路径。
    let persist_cfg = cache_persist::PersistCfg {
        enabled: cache_persist,
        file: cache_file.clone(),
        interval_s: cache_save_interval,
        persist_ttl,
        ttl_s: cache_ttl_s,
    };
    let persist = cache_persist::startup(&resolver, persist_cfg).await;
    if !cache_persist {
        // **2.1.18（修复项 10）**：`cache_persist=false` 时"重启清零"是**设计行为**，
        // 但必须**显式可见**（用户最容易把"重启后缓存空了"误判成故障）。
        tracing::warn!(
            "cache_persist=false：本次启动**不从磁盘恢复**缓存，缓存仅存在于内存中（重启即清零）"
        );
    }

    // 7) 起 DNS 监听（IPv4 + IPv6 **同时**监听：各自独立 socket，默认同端口）。
    //
    // 地址解析对齐 v1.9.162 的 `listen.udp/tcp` 语义（`host:port`），并**额外**容忍：
    // - 裸主机（`"0.0.0.0"`、`"127.0.0.1"`）——此前 `rsplit_once(':')` 取不到冒号即整条
    //   被丢弃并静默回退 127.0.0.1（用户以为在监听全网卡，实际只有回环）；
    // - IPv6（`"::"`、`"[::]"`、`"[::1]"`、`"2001:db8::1"`）；
    // - 字符串内嵌端口（`"0.0.0.0:53"`）——此前被完全忽略、端口只认 CLI/`dns_port`。
    //
    // `listen.udp6/tcp6`（**默认 `"[::]"`**）与 IPv4 同时监听；显式关闭
    // （`false` / `null` / `""`）→ 不监听 v6，且**不告警**（关闭是配置选择，不是故障）。
    //
    // 端口优先级：CLI `--dns-udp-port/--dns-tcp-port` > 该键内嵌端口 > `dns_port` 键 > 5353；
    // `udp6`/`tcp6` 未写端口时**跟随对应 IPv4 的实际端口**（保证同端口双栈）。
    //
    // **2.1.16（功能 7）**：整段解析抽成 [`listen_binds`]，因此"启动时"与"热更新时"
    // 用的是**同一个**函数 —— 不可能出现"启动按 A 语义、reload 按 B 语义"的漂移。
    let (udp_binds, tcp_binds) = listen_binds(&cfg, &args);
    // 绑定失败（端口被占用 / 无权限 / 地址不可用）必须是**可读的致命错误 + 退出码 1**，
    // 而不是 panic：v1.9.162 走的是 `sys.exit(1)` + 明确文案；panic 会打出 Rust 回溯提示，
    // 对运维（systemd journal）毫无帮助，也违反本项目「生产路径不 panic」的约定。
    // IPv6 失败**不致命**：`DnsServer::start_multi_workers` 内部 WARN 并降级为仅 IPv4。
    //
    // **2.1.16（功能 1）**：走 `start_multi_workers` 并把 `udp_workers` 抖下去
    // （`0` = 自动 = CPU 核数且封顶 8；`1` = 与 2.1.15 逐位等价的单 socket 旧行为；
    // `N>1` = 每个 UDP 地址 N 个 `SO_REUSEPORT` socket，内核按 flow 哈希分流到多核）。
    // 端口占用语义不受影响：多 worker 路径在 bind 前先做显式占用预检，
    // 见 `dns.rs::probe_port_free`（REUSEPORT 会让"重复实例"静默通过）。
    let udp_workers = cfg_to_resolver(&cfg).udp_workers;
    // **2.1.16（功能 7）**：listen 热更新通道（`on_reload` 投递 → 监督任务执行）。
    let (rebind_tx, rebind_rx) = tokio::sync::mpsc::unbounded_channel::<Value>();
    let mut rebind_rx = Some(rebind_rx);
    let dns = match DnsServer::start_multi_workers(
        resolver.clone(),
        tel.clone(),
        &udp_binds,
        &tcp_binds,
        udp_workers,
    )
    .await
    {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(
                udp = ?udp_binds,
                tcp = ?tcp_binds,
                error = %e,
                "DNS 监听失败（端口被占用 / 需要 CAP_NET_BIND_SERVICE / 地址不可用）"
            );
            eprintln!(
                "ebpdns: 无法监听 DNS：{e}\n\
                 提示：53 端口需要 root 或 CAP_NET_BIND_SERVICE；若已有其他 DNS 在运行请先停止它。"
            );
            std::process::exit(1);
        }
    };
    // 「如实」：endpoints 与启动日志一律用**实际绑定成功**的地址，而不是配置意图
    // （v6 绑定失败降级时，快照里就不会出现 udp6/tcp6，不会被伪造成「在监听」）。
    let udp_binds = dns.udp_bound().to_vec();
    let tcp_binds = dns.tcp_bound().to_vec();
    let endpoints = endpoints_of(&udp_binds, &tcp_binds);
    tracing::info!(
        udp = %endpoint_of(&endpoints, "udp"),
        udp6 = %endpoint_of(&endpoints, "udp6"),
        tcp = %endpoint_of(&endpoints, "tcp"),
        tcp6 = %endpoint_of(&endpoints, "tcp6"),
        "DNS 监听已启动（udp/udp6/tcp/tcp6）"
    );

    // 8) AppState + API。
    let restart_notify = Arc::new(Notify::new());
    let restart = Arc::new(ebpdns_server::RestartSignal::default());
    let cfg_arc = Arc::new(RwLock::new(cfg.clone()));
    let cfg_path = args.config.clone();
    let resolver_clone = resolver.clone();
    // F31 运行时基准：`api_host` 与 AppState 共享（RwLock）供 on_reload 热刷新；
    // `web_root` 是启动期固定值（`Option<PathBuf>`），热重载只告警「需重启生效」，
    // 故这里直接求值一次注入 state，不再需要 RwLock 包裹。
    let api_host_live = Arc::new(RwLock::new(api_host.clone()));
    let web_root = ebpdns_server::state::static_root_of(
        &cfg,
        std::env::var("EBPDNS_WEB_ROOT").ok().as_deref(),
    );
    let endpoints_live = Arc::new(RwLock::new(endpoints));
    // 「当前已生效」的只读段快照（listen 段与已 bind 地址同源），供 reload 对比告警。
    let listen_applied = cfg.get("listen").cloned().unwrap_or(Value::Null);
    let mut state = AppState {
        resolver: resolver.clone(),
        cfg: cfg_arc.clone(),
        cfg_path,
        telemetry: tel.clone(),
        api_host: api_host_live.clone(),
        api_port,
        // `web_root` 为启动期固定值（`Option<PathBuf>`）；热重载只在变更时告警需重启。
        web_root,
        restart: restart.clone(),
        endpoints: endpoints_live.clone(),
        on_reload: None,
        restart_notify: restart_notify.clone(),
        udp_dropped: dns.dropped(),
        applied: Arc::new(RwLock::new(cfg.clone())),
        // **2.1.22 阶段一**：`state/` 统一持久化事务（`None` = 按配置关闭/目录不可用）。
        state: Arc::new(state_ctx.clone()),
    };
    {
        // F31：热重载闭包先刷新可热改的运行时基准（`api.host`），否则手工改 api.host 后
        // `/api/reload` 仍按启动快照判定 Origin/CSRF → 合法请求 fail-closed 403。
        // `web_root` / api.port / listen.* 无法热改（静态根为启动期固定值、socket 已 bind），
        // apply_runtime_cfg 内部会记录「需重启生效」告警；故意不刷新 api_port，避免按新
        // 端口把可用请求误判为跨源。
        //
        // 闭包捕获 state 的克隆（内部全是 Arc），因此无需在闭包里重建 AppState；
        // `state.cfg` 已由调用方（PUT /api/config、POST /api/reload）先刷新。
        let hook_state = state.clone();
        let hook_resolver = resolver_clone.clone();
        // **2.1.16（功能 7）**：listen 热更新的投递端。`on_reload` 是同步闭包，
        // 只做"投递"；真正的 bind/替换/回滚由监督任务串行执行（见下方 `dns_slot`）。
        let hook_rebind = rebind_tx.clone();
        state.on_reload = Some(Arc::new(
            move |new_cfg: &Value| -> Result<ebpdns_server::ReloadOutcome, ebpdns_server::ReloadError> {
            let updated = hook_state.apply_runtime_cfg(new_cfg, &listen_applied);
            if updated.is_empty() {
                tracing::debug!("配置热重载：运行时基准无变化");
            }
            // 2.1.16（功能 7）：`listen` 段可能已变 → 交给监督任务做"先 bind 新 socket
            // 成功后原子替换"，失败则回滚保留旧监听（绝不裸奔）。
            if hook_rebind.send(new_cfg.clone()).is_err() {
                tracing::warn!("listen 热更新通道已关闭（退出中），本次改动未生效");
            }
            // 以上次生效配置为基线重建：未被 cfg 覆盖的键保持现状（不再回退硬编码默认值）。
            let base = hook_resolver.config().clone();
            let rc = cfg_to_resolver_from(base, new_cfg);
            hook_resolver.reload(rc);
            // 规则索引：**统一走权威合并重建**（本地规则文件 + 订阅磁盘明细，本地在前）。
            //
            // 缺陷（P0）：此前 `Resolver::reload` 用 `cfg.rules`（只有逐条本地规则）
            // 重建索引，于是每次 `POST /api/reload` / `POST /api/reprobe` /
            // `PUT /api/config` 都会把 101146 条订阅规则从索引里摘掉：
            // 实测 `pipeline.rules` 101147 → 0、`status.rule_hits` 恒为 `{}`。
            // 这里在刷新配置之后按磁盘重建，保证「本地规则 + 订阅规则」始终同时在索引里。
            // **2.1.49（P0）**：重建结果必须回传给 reload 端点 —— 非法订阅/规则、
            // schema 失败、重建失败一律 5xx；`rebuild_all_disk_checked` 在失败时
            // **不替换旧索引**（见 subscribe::rebuild_all_disk_path 与
            // Resolver::try_rebuild_rules）。
            let outcome = ebpdns_server::subscribe::rebuild_all_disk_checked(&hook_state);
            if let Some(failure) = outcome.failure {
                tracing::error!(
                    code = failure.code(),
                    detail = failure.detail(),
                    indexed = outcome.stats.indexed,
                    rejected = outcome.stats.rejected,
                    dropped = outcome.stats.dropped,
                    "配置热重载失败 ⇒ reload 端点返回 5xx（旧规则索引保留）"
                );
                return Err(ebpdns_server::ReloadError::new(
                    failure.code(),
                    failure.detail(),
                ));
            }
            if outcome.stats.failed() {
                tracing::error!("配置热重载失败（旧口径 failed）⇒ reload 端点返回 5xx");
                return Err(ebpdns_server::ReloadError::new(
                    "rules_rebuild_failed",
                    "规则索引重建失败（保留旧索引）",
                ));
            }
            tracing::info!(
                updated = ?updated,
                indexed = outcome.stats.indexed,
                rejected = outcome.stats.rejected,
                dropped = outcome.stats.dropped,
                "配置热重载完成"
            );
            Ok(ebpdns_server::ReloadOutcome {
                indexed: outcome.stats.indexed,
                rejected: outcome.stats.rejected,
                dropped: outcome.stats.dropped,
            })
        }));
    }
    let app = ebpdns_server::build_router(state.clone());
    // 规则订阅周期更新任务（rule_sub_interval 秒，0=关闭）。
    ebpdns_server::subscribe::spawn_updater(state.clone());
    // **[历史归因]** F04：启动期就把「本地规则 + 订阅规则」装进索引（对齐 Python cli.run 的
    // `_load_local_rules() + _load_sub_rules()`）。此前只加载 cfg["rules"]，
    // 规则文件里的规则要等订阅刷新首个 tick（≥10s）才生效；配合订阅元信息
    // 未落盘的缺陷则永不生效。
    ebpdns_server::subscribe::rebuild_all_disk(&state);
    let api_addr: SocketAddr = format!("{api_host}:{api_port}")
        .parse()
        .unwrap_or_else(|_| ([127, 0, 0, 1], api_port).into());
    // 同上：API 绑定失败给可读错误 + exit(1)，不 panic。
    let listener = match TcpListener::bind(api_addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(%api_addr, error = %e, "API 监听失败");
            eprintln!(
                "ebpdns: 无法监听 API {api_addr}：{e}\n\
                 提示：检查 api.port 是否被其他进程占用，或改用其它端口。"
            );
            std::process::exit(1);
        }
    };
    tracing::info!(%api_addr, "API server 已启动");
    // ---- P1-3：启动预热**可配置且默认关闭** ----
    //
    // 旧实现无条件预热 6 个**硬编码**域名，而且调用的是不存在的路径
    // `ebpdns_resolver::ResolveOpts`（`ResolveOpts` 只在 `ebpdns_resolver::resolve`
    // 子模块里，未在 crate 根 re-export），因此 `cargo build --release --bin ebpdns`
    // 直接编译失败（P0-1 的第二个编译错误）。
    //
    // 现在：
    // - 默认**关闭**（不替用户查询任何域名，启动即静默）；
    // - 开启方式：`config.json` →
    //   `"warmup": {"enabled": true, "domains": ["www.example.com", ...]}`；
    // - 只走 `tracing` 日志（不再 `eprintln!` 绕过日志级别）；
    // - 每次预热都是普通缓存未命中查询（`silent=false, counted=true`），
    //   因此 QPS/total 计数与运维侧可观测性一致。
    let warmup_domains: Vec<String> = cfg
        .get("warmup")
        .filter(|w| w.get("enabled").and_then(Value::as_bool).unwrap_or(false))
        .and_then(|w| w.get("domains").and_then(Value::as_array).cloned())
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if warmup_domains.is_empty() {
        // **2.1.20（A-13 修复：日志文案与事实不符）**：此前这里无条件写
        // "启动预热未开启（config: warmup.enabled=false，默认）"，而 `warmup_domains`
        // 的空只说明**域名列表为空** —— 审计实测 `warmup={"enabled":true,"queries":3}`
        // 且无 `domains` 时也打这一行 ⇒ 日志把"enabled=true 但没有域名"说成
        // "enabled=false（默认）"，与配置**直接矛盾**。
        // 现在把 `enabled` 的真值一并打出，并把原因说准（缺 domains ≠ 功能关闭）。
        let warmup_enabled = state.resolver.config().warmup_enabled;
        tracing::debug!(
            warmup_enabled,
            "启动预热跳过：`warmup.domains` 为空（注意：这与 `warmup.enabled` 无关，\
             enabled={warmup_enabled}；如需预热请配置 warmup.domains）"
        );
    } else {
        let resolver_warm = state.resolver.clone();
        let n = warmup_domains.len();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            for d in &warmup_domains {
                let opts = ebpdns_resolver::resolve::ResolveOpts {
                    silent: false,
                    counted: true,
                    force_refresh: false,
                    client_ip: None,
                    depth: 0,
                    trace: false,
                    ttl_cap: None,
                };
                // `resolve(self: Arc<Self>, …)` 按值取 Arc，循环里必须 clone。
                let _ = resolver_warm.clone().resolve(d, "A", opts).await;
            }
            tracing::info!(domains = n, "启动预热完成");
        });
    }

    let api_handle = tokio::spawn(async move {
        if let Err(e) = ebpdns_server::serve_http(app, listener).await {
            tracing::error!("API server 退出: {e}");
        }
    });

    // spawn resolver 后台任务（预取/测速）。
    let mut bg = resolver.spawn_background_tasks();

    // 6b) **周期落盘**（2.1.19 修复项 10）：把控制台承诺的"每 N 秒保存"真正实现。
    //
    // 与"优雅退出落盘"的关系：两者**互补**，不是替代 ——
    //   - 周期任务：进程被 `kill -9` / 崩溃 / 断电时，最多丢 `cache_save_interval` 秒；
    //   - 优雅退出：SIGTERM/SIGINT（`systemctl stop/restart`）时**必落盘**，一条不丢。
    //
    // **2.1.29（v2）**：v2 模式下这一拍只做"刷新 manifest / 视阈值 compact"，
    // WAL 的 `fdatasync` 由 actor 自己的 ≤1 s 节拍负责 ⇒ 丢失窗口从 ≤60 s 收紧到 ≤1 s。
    // `cache_save_interval=0` 时**不启动周期拍**（行为逐位回到 v1：只在优雅退出落盘）。
    if cache_persist && cache_save_interval > 0 && persist.mode() == cache_persist::Mode::V2 {
        let cp = persist.handle();
        let secs = cache_save_interval;
        let bg_save = tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(secs.max(1)));
            // 第一次 tick 立即到期 → 跳过（刚恢复完没必要立刻写一遍）。
            tick.tick().await;
            loop {
                tick.tick().await;
                cp.on_tick();
            }
        });
        bg.push(bg_save);
        tracing::info!(
            interval_s = secs,
            "缓存定期落盘已启用（v2：WAL ≤1 s fsync + 每 {}s 刷新 manifest；0 = 关闭）；文件: {}",
            secs,
            cache_file.display()
        );
    } else if cache_persist && cache_save_interval > 0 {
        // v1 模式（`EBPDNS_CACHE_FORMAT=v1` 或迁移失败）：保留 2.1.28 的全量 JSON 落盘。
        let resolver_bg = resolver.clone();
        let path_bg = cache_file.clone();
        let secs = cache_save_interval;
        let bg_save = tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(secs.max(1)));
            // 第一次 tick 立即到期 → 跳过（刚恢复完没必要立刻写一遍）。
            tick.tick().await;
            loop {
                tick.tick().await;
                save_cache_v1(&resolver_bg, &path_bg).await;
            }
        });
        bg.push(bg_save);
        tracing::info!(
            interval_s = secs,
            "缓存定期落盘已启用（**v1 模式**）；文件: {}",
            cache_file.display()
        );
    } else if cache_persist {
        tracing::info!("缓存定期落盘**未启用**（cache_save_interval=0）：只在优雅退出时落盘");
    }

    // 8b) **2.1.16（功能 7）：listen 热更新监督任务。**
    //
    // `on_reload` 是**同步**闭包（由 API 处理器在持锁时调用），它只能把"新配置"
    // 投进 channel；真正的 `DnsServer::rebind`（async，要 bind socket）在这里**串行**
    // 执行 —— 串行化同时保证连续快速 reload 不会并发 rebind 同一个 `DnsServer`。
    let dns_slot = Arc::new(tokio::sync::Mutex::new(Some(dns)));
    if let Some(mut rx) = rebind_rx.take() {
        let slot = dns_slot.clone();
        let args_for_rebind = args.clone();
        tokio::spawn(async move {
            while let Some(new_cfg) = rx.recv().await {
                let (udp, tcp) = listen_binds(&new_cfg, &args_for_rebind);
                let mut guard = slot.lock().await;
                let Some(server) = guard.as_mut() else { break };
                if server.udp_bound() == udp.as_slice() && server.tcp_bound() == tcp.as_slice() {
                    tracing::debug!("listen 未变化，跳过 rebind");
                    continue;
                }
                match server.rebind(&udp, &tcp).await {
                    Ok(()) => {
                        tracing::info!(udp = ?udp, tcp = ?tcp, "listen 热更新成功（不停机）")
                    }
                    // **失败必须回滚并保留旧监听**：`rebind` 内部保证任何 v4 bind 失败
                    // 都在 spawn 新循环 / 停旧循环**之前**返回 Err，旧 socket 未被触碰。
                    Err(e) => tracing::error!(
                        error = %e,
                        want_udp = ?udp,
                        want_tcp = ?tcp,
                        kept_udp = ?server.udp_bound(),
                        kept_tcp = ?server.tcp_bound(),
                        "listen 热更新失败：已回滚，**旧监听完整保留**（服务未受影响）"
                    ),
                }
            }
        });
    }
    // 9) 等待退出信号（SIGTERM/SIGINT）或 restart 通知。
    let restart_fired = restart_notify.clone();
    let sig = tokio::spawn(shutdown_signal());
    tokio::select! {
        _ = sig => {
            tracing::info!("收到停止信号(SIGTERM/SIGINT)，开始优雅退出");
        }
        _ = restart_fired.notified() => {
            tracing::info!("收到 /api/restart，准备以退出码 3 重启");
        }
    }

    // 10) 优雅退出：停 DNS/API → 缓存落盘 → resolver shutdown。
    if let Some(server) = dns_slot.lock().await.take() {
        server.shutdown().await;
    }
    api_handle.abort();
    for h in bg {
        h.abort();
    }
    if cache_persist {
        // **2.1.29**：v2 = flush WAL + 写 manifest（毫秒级）；v1 = 全量 JSON（与 2.1.28 相同）。
        if persist.is_v2() {
            persist.shutdown().await;
        } else {
            save_cache_v1(&resolver, &cache_file).await;
        }
    } else {
        tracing::warn!("cache_persist=false：退出时**不落盘**缓存（下次启动缓存为空）");
    }
    resolver.shutdown();
    tracing::info!("退出完成");

    // /api/restart → 退出码 3（systemd on-failure 拉起）。
    if restart.requested.load(std::sync::atomic::Ordering::SeqCst) {
        std::process::exit(3);
    }
}

/* ---------------- 配置 ---------------- */

/// 加载配置 JSON（无文件则默认）。
/// **2.1.20（A-03）**：启动期把**整份配置**里越界的**整数键**夹取到权威区间，并逐键 WARN。
///
/// 语义（**与写路径同源**）：判据表 = `ebpdns_resolver::config::CONFIG_RANGES`
/// （`validate_write` 用的同一张表）⇒ "启动接受的域" ≡ "写路径接受的域"。
///
/// 返回被夹取的 `(键, 原值, 新值)` 列表（供单测断言与日志）。
/// 只处理**表里有的整数键**：其它键（枚举/布尔/浮点/嵌套）由 `validate_schema` 在
/// `check-config` 路径逐条诊断；这里的目标是**保证写路径不会因为文件里的历史坏值而失败**。
pub fn clamp_out_of_range_config(cfg: &mut Value) -> Vec<(String, u64, u64)> {
    let mut fixed = Vec::new();
    let Some(obj) = cfg.as_object_mut() else {
        return fixed;
    };
    for (k, lo, hi) in ebpdns_resolver::config::CONFIG_RANGES {
        let Some(v) = obj.get(*k) else { continue };
        // 只动"是整数但越界"的键：类型不对的留给 validate_schema 报错，
        // 悄悄把字符串转成数字反而会掩盖配置错误。
        let Some(n) = v.as_u64() else { continue };
        if n < *lo || n > *hi {
            let new = n.clamp(*lo, *hi);
            obj.insert((*k).to_string(), json!(new));
            tracing::warn!(
                key = k,
                old = n,
                new = new,
                min = lo,
                max = hi,
                "**配置启动校验：`{}` = {} 超出允许区间 [{}, {}] → 已夹取为 {}**。\
                 磁盘文件保持原样，下一次「应用配置」（或 `ebpdns migrate-config`）会写回合法值；\
                 不夹取的话，控制台此后**任何**保存都会被 400 拒绝（整份提交）。",
                k,
                n,
                lo,
                hi,
                new
            );
            fixed.push(((*k).to_string(), n, new));
        }
    }
    fixed
}

/// **2.1.19（F-08）**：在**日志初始化之前**从配置文件里"偷看" `log_level` / `log_format`。
///
/// 为什么需要：`init_tracing` 必须尽早调用（否则启动期日志落在默认级别），
/// 而两个日志键躲在配置文件里 ⇒ 必须**先读一次文件**。这里刻意做成**纯 peek**：
/// 读不到/解析失败/类型不对一律返回 `None`（**绝不报错、绝不改动 `cfg`**），
/// 因此对既有启动路径零影响；真正的配置加载仍在后面按原顺序执行。
///
/// 优先级（见 `init_tracing` 的调用点）：CLI 参数 > `RUST_LOG` 环境变量 >
/// **本函数读到的配置值** > 内置默认。
fn peek_log_config(path: Option<&std::path::Path>) -> (Option<String>, Option<LogFormat>) {
    let Some(p) = path else {
        return (None, None);
    };
    let Ok(s) = std::fs::read_to_string(p) else {
        return (None, None);
    };
    let Ok(v) = serde_json::from_str::<Value>(&s) else {
        return (None, None);
    };
    let level = v
        .get("log_level")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    // `log_format` 接受 `plain`/`text`（等价）与 `json`；其它值忽略（由 `validate_schema`
    // 在正式加载时给出告警，不在 peek 阶段报错）。
    let fmt = match v
        .get("log_format")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("json") => Some(LogFormat::Json),
        Some("plain") | Some("text") => Some(LogFormat::Plain),
        _ => None,
    };
    (level, fmt)
}

/// 配置来源（**2.1.23 / DEF-222-02**）：区分"真的读到了文件"与"回落到内置默认"。
///
/// 为什么需要这个区分：`state_dir` 的默认值是**生产路径**
/// `/var/lib/ebpdns/state`。2.1.22 里"配置解析失败 ⇒ 用默认配置继续"会让
/// `resolve_state_dir` 取不到 `state_dir` ⇒ 静默落到生产目录，**隔离实例因此去读写了
/// 生产状态目录**（审计实测）。默认路径只允许在"配置可信"或"显式指定"时启用。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConfigOrigin {
    /// 配置文件读取并解析成功。
    FileOk,
    /// **没有**给 `--config` 且默认路径不存在（全新安装）⇒ 用内置默认是合法的。
    NoFileFresh,
    /// 配置文件**存在但读不出来 / 不是合法 JSON** ⇒ 配置不可信（默认 fail-closed）。
    FileBroken,
}

/// 配置加载结果。
struct LoadedConfig {
    /// 配置值（`FileBroken` + `--allow-bad-config` 时是内置默认）。
    cfg: Value,
    /// 来源（决定 `state_dir` 是否允许用默认值）。
    origin: ConfigOrigin,
}

/// **2.1.29**：已整体移除的 XDP/eBPF 配置键。
///
/// 旧配置里若仍带有这些键：加载时**直接剔除**、一次性重写 `config.json`
/// （INFO 一行），不保留、不兼容、不升级 `config_version`（仍为 3）。
pub const REMOVED_XDP_CONFIG_KEYS: [&str; 8] = [
    "hook",
    "iface",
    "kernel_cache",
    "kernel_cache_iface",
    "kernel_cache_max",
    "kernel_direct",
    "map_type",
    "percpu",
];

/// 从配置对象中剔除已移除的 XDP 键，返回实际删除的键名（排序稳定）。
pub fn strip_removed_xdp_keys(cfg: &mut Value) -> Vec<String> {
    let Some(obj) = cfg.as_object_mut() else {
        return Vec::new();
    };
    let mut removed = Vec::new();
    for k in REMOVED_XDP_CONFIG_KEYS {
        if obj.remove(k).is_some() {
            removed.push(k.to_string());
        }
    }
    removed
}

fn load_config(path: Option<&std::path::Path>) -> LoadedConfig {
    let Some(p) = path else {
        return LoadedConfig {
            cfg: default_config(),
            origin: ConfigOrigin::NoFileFresh,
        };
    };
    match std::fs::read_to_string(p) {
        Ok(s) => match serde_json::from_str::<Value>(&s) {
            Ok(mut v) => {
                // **2.1.29**：已移除的 XDP/eBPF 键 → 剔除并**一次性重写**配置文件。
                let removed = strip_removed_xdp_keys(&mut v);
                if !removed.is_empty() {
                    let body = serde_json::to_string_pretty(&v)
                        .unwrap_or_else(|_| "{}".to_string())
                        .into_bytes();
                    match write_json_atomic(p, &body) {
                        Ok(()) => tracing::info!(
                            removed = removed.len(),
                            keys = %removed.join(","),
                            "已移除 {} 个 XDP 相关键并重写 config.json",
                            removed.len()
                        ),
                        Err(e) => tracing::warn!(
                            removed = removed.len(),
                            keys = %removed.join(","),
                            error = %e,
                            "已移除 {} 个 XDP 相关键，但重写 config.json 失败（本次仅内存生效）",
                            removed.len()
                        ),
                    }
                }
                LoadedConfig {
                    cfg: v,
                    origin: ConfigOrigin::FileOk,
                }
            }
            Err(e) => {
                tracing::error!("**配置解析失败**({e})：{}", p.display());
                LoadedConfig {
                    cfg: default_config(),
                    origin: ConfigOrigin::FileBroken,
                }
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // 显式给了 `--config` 但文件不存在 ⇒ 同"配置不可信"（用户以为在读它）。
            tracing::error!("**配置文件不存在**：{}（{e}）", p.display());
            LoadedConfig {
                cfg: default_config(),
                origin: ConfigOrigin::FileBroken,
            }
        }
        Err(e) => {
            tracing::error!("**配置文件不可读**：{}（{e}）", p.display());
            LoadedConfig {
                cfg: default_config(),
                origin: ConfigOrigin::FileBroken,
            }
        }
    }
}

/// **[历史归因]** 默认配置（与 Python config.py DEFAULTS 同口径；listen/api/web_root 为只读段）。
fn default_config() -> Value {
    json!({
        "api": {
            "host": "127.0.0.1",
            "port": 8353,
            "token": "",
        },
        "listen": {
            "udp": "0.0.0.0:53",
            "tcp": "0.0.0.0:53",
            "udp6": "[::]:53",
            "tcp6": "[::]:53",
        },
        "web_root": "",
        "dns_port": 53,
        "cache_size": 131072,
        "cache_policy": "tinylfu",
        "cache_partitions": null,
        "cache_save_interval": 60,
        "ttl": 300,
        "ttl_min": 5,
        "ttl_max": 300,
        "neg_ttl_max": 60,
        // 2.1.12 优化项 ①：RFC 8020 父域 NXDOMAIN 推导体。
        // 采纳一次权威 NXDOMAIN 后登记该名字，其后该名字自身或其子域的查询直接回
        // NXDOMAIN 且零上游请求（RFC 8020 §Abstract）。默认开启的理由见
        // `ebpdns-resolver/src/config.rs::rfc8020_infer` 的字段注释；
        // 置 false 与 2.1.11 逐位等价（有单测门禁）。
        "rfc8020_infer": true,
        // 登记/匹配深度上限（标签数）。> 本值不登记也不匹配（防过度泛化）。
        "rfc8020_max_labels": 8,
        // ---- 2.1.16 新增键（schema version 2；迁移见 `migrate_schema`）----
        // 配置 schema 版本：1 = 2.1.0..2.1.15（无本键）；2 = 2.1.16。
        "config_version": ebpdns_resolver::config::CURRENT_CONFIG_VERSION,
        // ① 收包并行化：0 = 自动（CPU 核数，封顶 8）；1 = **退回 2.1.15 单 socket 行为**；
        //    N>1 = 每个 UDP 地址 N 个 SO_REUSEPORT socket（内核按 flow 哈希分流到多核）。
        "udp_workers": 0,
        // ② 在途查询合并：同 CacheKey 的并发 miss 只发一次上游，其余等共享结果。
        "single_flight": true,
        // ⑨ 上游连接池预热：构造/热重载后为每个启用上游异步发 N 条探测查询，
        //    把 TLS/QUIC 会话与上游滑窗样本一次建好（避免首批查询承担握手 RTT）。
        "warmup": { "enabled": true, "queries": 3, "timeout_ms": 3000 },
        "serve_stale": true,
        "stale_ttl": 604800,
        "cache_persist": true,
        "persist_ttl": 0,
        "prefetch": true,
        // **2.1.20（F-02）**：预取调参键（此前 `prefetch_interval` 没有 JSON 键、
        // `prefetch_trigger`/`prefetch_target` 是死字段）；默认值与
        // `ResolverConfig::default()` 逐项一致。
        "prefetch_interval": 300,
        "prefetch_trigger": 60,
        "prefetch_target": 300,
        "prefetch_max": 1024,
        "cache_direct_enabled": false,
        "speed_test": true,
        "speed_interval_ms": 2000,
        "speed_timeout_ms": 300,
        "ip_speed_check": true,
        "ip_speed_probe": "both",
        "ip_speed_cache_ttl": 60,
        "fallback": true,
        "max_parallel_upstreams": 3,
        // **2.1.15（P1）**：单上游在途请求上限（0 = 关闭闸门，退回 2.1.14 行为）。
        // 默认 32：低并发零行为变更；高并发下把排队从上游侧搬回本进程侧。
        "upstream_max_inflight": ebpdns_resolver::config::DEFAULT_UPSTREAM_MAX_INFLIGHT,
        "timeout_ms": 1500,
        "nxdomain_quorum": 2,
        "circuit_fails": 3,
        "circuit_open_s": 30,
        // 2.1.8 优化项 5：连续打开按 min(open_s*2^(k-1), circuit_open_max_s) 指数退避。
        "circuit_open_max_s": 120,
        // 2.1.8 优化项 2：0 = 自动（min(health_probe_timeout_ms, timeout_ms)，下限 250ms）。
        "probe_timeout_ms": 0,
        // 2.1.8 优化项 3：健康时先发 1 个上游，hedge_after_ms 未回再追加剩余候选。
        "adaptive_parallel": true,
        // 2.1.11 优化项 3：本键退化为「冷启动兜底 / p90 不可用时的回退值」——
        // 有实测样本时对冲时刻 = 候选 p90 × hedge_slowest_factor。
        "hedge_after_ms": 200,
        // 2.1.11 优化项 3：逐上游 p90 对冲因子，默认 1.0（零行为风险，见 config.rs 注释）。
        "hedge_slowest_factor": 1.0,
        // 2.1.8 优化项 4：timeout = clamp(k*eff_lat, min_ms, timeout_ms)。
        // **下限默认 = timeout_ms(1500) → 默认不收紧（与 v1.9.162 固定超时等价）**；
        // 实测下限 1000ms 会让 61ms 均值的最快上游失败率 0%→9.5% 并触发熔断级联，
        // 故不作为默认。要启用请下调 adaptive_timeout_min_ms（建议 ≥1000）并自测 A/B。
        "adaptive_timeout": true,
        "adaptive_timeout_k": 8.0,
        "adaptive_timeout_min_ms": 1500,
        // 2.1.12 优化项 ②：上游评分复合键的成功率惩罚下限（默认 0.5 → 惩罚最大 ×2.0）。
        // score = p90 × (1/max(sr, 本值)) × 绝对延迟惩罚（p90 > 800ms 额外 ×1.5，常量）。
        "rating_sr_floor": 0.5,
        "ipv6": true,
        "prefer_ipv4": true,
        "ipv4_first": true,
        "edns": true,
        "edns_udp_size": 1232,
        "edns_client_max_size": 1232,
        "edns_client_subnet": "",
        "padding": true,
        "dnssec_0x20": true,
        "rebind_protection": true,
        "health_check_interval": 30,
        "health_probe_domain": "www.baidu.com",
        "health_probe_timeout_ms": 2000,
        "bootstrap_dns": ["223.5.5.5:53"],
        "log_level": "info",
        "log_format": "plain",
        "rule_sub_interval": 3600,
        "upstreams": [
            {
                "id": "ali-doh3",
                "name": "AliDNS DoH3",
                "proto": "doh3",
                "host": "dns.alidns.com",
                "addr": "dns.alidns.com",
                "port": 443,
                "url": "/dns-query",
                "group": "domestic",
                "enabled": true,
            },
            {
                "id": "dnspod-doh3",
                "name": "DNSPod DoH3",
                "proto": "doh3",
                "host": "doh.pub",
                "addr": "doh.pub",
                "port": 443,
                "url": "/dns-query",
                "group": "domestic",
                "enabled": false,
            },
            {
                "id": "ali-doh",
                "name": "AliDNS DoH",
                "proto": "doh",
                "host": "dns.alidns.com",
                "addr": "dns.alidns.com",
                "port": 443,
                "url": "/dns-query",
                "group": "domestic",
                "enabled": true,
            },
            {
                "id": "dnspod-doh",
                "name": "DNSPod DoH",
                "proto": "doh",
                "host": "doh.pub",
                "addr": "doh.pub",
                "port": 443,
                "url": "/dns-query",
                "group": "domestic",
                "enabled": true,
            },
            {
                "id": "ali-ip-doh",
                "name": "AliDNS IP DoH",
                "proto": "doh",
                "host": "223.5.5.5",
                "addr": "223.5.5.5",
                "port": 443,
                "url": "/dns-query",
                "group": "domestic",
                "enabled": true,
            },
            {
                "id": "dnspod-ip-doh",
                "name": "DNSPod IP DoH",
                "proto": "doh",
                "host": "120.53.53.53",
                "addr": "120.53.53.53",
                "port": 443,
                "url": "/dns-query",
                "group": "domestic",
                "enabled": true,
            },
            {
                "id": "ali-ip2-doh",
                "name": "AliDNS2 IP DoH",
                "proto": "doh",
                "host": "223.6.6.6",
                "addr": "223.6.6.6",
                "port": 443,
                "url": "/dns-query",
                "group": "domestic",
                "enabled": true,
            },
            {
                "id": "cf-doh3",
                "name": "Cloudflare DoH3",
                "proto": "doh3",
                "host": "cloudflare-dns.com",
                "addr": "cloudflare-dns.com",
                "port": 443,
                "url": "/dns-query",
                "group": "global",
                "enabled": true,
            },
            {
                "id": "google-doh3",
                "name": "Google DoH3",
                "proto": "doh3",
                "host": "dns.google",
                "addr": "dns.google",
                "port": 443,
                "url": "/dns-query",
                "group": "global",
                "enabled": false,
            },
            {
                "id": "quad9-doh3",
                "name": "Quad9 DoH3",
                "proto": "doh3",
                "host": "dns.quad9.net",
                "addr": "dns.quad9.net",
                "port": 443,
                "url": "/dns-query",
                "group": "global",
                "enabled": false,
            },
            {
                "id": "cf-ip-doh",
                "name": "Cloudflare IP DoH",
                "proto": "doh",
                "host": "1.1.1.1",
                "addr": "1.1.1.1",
                "port": 443,
                "url": "/dns-query",
                "group": "global",
                "enabled": false,
            },
            {
                "id": "cf-doh",
                "name": "Cloudflare DoH",
                "proto": "doh",
                "host": "cloudflare-dns.com",
                "addr": "cloudflare-dns.com",
                "port": 443,
                "url": "/dns-query",
                "group": "global",
                "enabled": false,
            },
            {
                "id": "google-doh",
                "name": "Google DoH",
                "proto": "doh",
                "host": "dns.google",
                "addr": "dns.google",
                "port": 443,
                "url": "/dns-query",
                "group": "global",
                "enabled": false,
            },
            {
                "id": "google-ip-doh",
                "name": "Google IP DoH",
                "proto": "doh",
                "host": "8.8.8.8",
                "addr": "8.8.8.8",
                "port": 443,
                "url": "/dns-query",
                "group": "global",
                "enabled": false,
            },
            {
                "id": "quad9-doh",
                "name": "Quad9 DoH",
                "proto": "doh",
                "host": "dns.quad9.net",
                "addr": "dns.quad9.net",
                "port": 443,
                "url": "/dns-query",
                "group": "global",
                "enabled": false,
            },
            {
                "id": "nextdns-doh",
                "name": "NextDNS DoH",
                "proto": "doh",
                "host": "dns.nextdns.io",
                "addr": "dns.nextdns.io",
                "port": 443,
                "url": "/4d5525",
                "group": "global",
                "enabled": false,
            },
            {
                "id": "opendns-doh",
                "name": "OpenDNS DoH",
                "proto": "doh",
                "host": "doh.opendns.com",
                "addr": "doh.opendns.com",
                "port": 443,
                "url": "/dns-query",
                "group": "global",
                "enabled": false,
            },
            {
                "id": "dnssb-doh",
                "name": "DNS.SB DoH",
                "proto": "doh",
                "host": "doh.dns.sb",
                "addr": "doh.dns.sb",
                "port": 443,
                "url": "/dns-query",
                "group": "global",
                "enabled": false,
            },
            {
                "id": "adguard-doh",
                "name": "AdGuard DoH",
                "proto": "doh",
                "host": "dns.adguard.com",
                "addr": "dns.adguard.com",
                "port": 443,
                "url": "/dns-query",
                "group": "global",
                "enabled": false,
            },
            {
                "id": "hinet-doh",
                "name": "HiNet DoH",
                "proto": "doh",
                "host": "dns.hinet.net",
                "addr": "dns.hinet.net",
                "port": 443,
                "url": "/dns-query",
                "group": "global",
                "enabled": false,
            },
            {
                "id": "ali-udp",
                "name": "AliDNS UDP",
                "proto": "udp",
                "host": "223.5.5.5",
                "addr": "223.5.5.5",
                "port": 53,
                "url": "",
                "group": "domestic",
                "enabled": false,
            },
            {
                "id": "dnspod-udp",
                "name": "DNSPod UDP",
                "proto": "udp",
                "host": "119.29.29.29",
                "addr": "119.29.29.29",
                "port": 53,
                "url": "",
                "group": "domestic",
                "enabled": false,
            },
        ],
        "rules": [],
        "rule_subscriptions": [
            {
                "url": "https://anti-ad.net/adguard.txt",
                "action": "block",
                "group": "global",
            },
        ],
        "cache_file": "/var/lib/ebpdns/ebpdns-cache.json",
        "cache_save_interval": 60,
        // ---- **2.1.22 阶段一（schema version 3）新增键** ----
        // 统一持久化事务的 `state/` 目录（`commit.json` + `history/` + `rules.json`
        // + `subscriptions.json` 所在）。**可配置**（见 `CONVENTIONS.md`）；默认值
        // 与 systemd unit 的 `ReadWritePaths=/etc/ebpdns /var/lib/ebpdns`
        // （`packaging/systemd/ebpdns.service:53`）**一致** ⇒ 默认部署无需改 unit。
        // 自定义路径时**必须同步改 unit 的 `ReadWritePaths`**，否则服务会被
        // `ProtectSystem=strict` 挡在只读边界外（启动时会有 WARN 指明这一点）。
        "state_dir": "/var/lib/ebpdns/state",
        // 统一持久化事务总开关。`true`（默认）= 三处写者（config / rules /
        // subscriptions）经同一个两阶段提交；`false` = **逐位退回 2.1.21** 的
        // "各写者各自原子写"（供排障/回退用，不推荐长期关闭）。
        "state_persist": true,
    })
}

/// 配置迁移：补齐 `default_config()` 里有而文件里缺的顶层键（缺失才补，不覆盖用户值），
/// 并把 `rule_local_file` / `rule_sub_file` 注入为 config.json 同目录下的独立文件路径
/// （对齐 v1.9.162 `config.py:134-145` 的运行时注入）。
fn migrate_cfg(cfg: &mut Value, cfg_path: Option<&std::path::Path>) {
    let defaults = default_config();
    if let (Some(dst), Some(src)) = (cfg.as_object_mut(), defaults.as_object()) {
        for (k, v) in src {
            // 只读段（api/listen/web_root）也补齐，便于控制台回显。
            if !dst.contains_key(k) {
                dst.insert(k.clone(), v.clone());
            }
        }
    }
    let dir = cfg_path
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    for (key, name) in [
        ("rule_local_file", "rules_local.json"),
        ("rule_sub_file", "rules_sub.json"),
    ] {
        let has = cfg
            .get(key)
            .and_then(Value::as_str)
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        if !has {
            cfg[key] = json!(dir.join(name).display().to_string());
        }
    }
    // ---- **2.1.20（A-07 修复：`config.json.rules` 被静默忽略）** ----
    //
    // 权威来源（`subscribe.rs::local_rules_with_drops`）是**独立规则文件**：
    // 只要 `rules_local.json` **存在**（控制台保存过一次就会有它），就**只**用它，
    // `config.json` 里的 `rules` 只作为"文件缺失时的兜底"。于是：
    //   * 用户手工编辑/恢复 `config.json` 的 `rules` → **完全不生效**，**且没有任何 WARN**；
    //   * 而 `GET /api/config` **照常回显**那份 `rules`，控制台「分流规则」卡片还显示着它们
    //     ⇒ 用户看到"规则在配置里、页面也在显示"，实际引擎里一条都没有（审计 A-07 实测）。
    //
    // 修法（选审计建议的 (b) + (c)）：启动时**对比两侧**，不一致就打**显著 WARN**，
    // 并**明确**写出"哪一侧是权威、如何让 config.json 生效"。不改数据（不做隐式合并：
    // 合并会引入"删除规则删不掉"的语义陷阱，属 2.1.21 的取舍）。
    warn_if_config_rules_are_shadowed(cfg);
    // ---- **2.1.16（修复项 6）**：schema 版本迁移 ----
    // 在"补默认键"之后做：老配置（无 `config_version`）补齐后仍须把版本**显式**
    // 写成当前值，迁移记录按行打到日志，便于审计"这台机器的配置是什么时候被升格的"。
    let (from, steps) = migrate_schema(cfg);
    for s in &steps {
        tracing::info!(from = from, to = CURRENT_CONFIG_VERSION, "配置迁移: {s}");
    }
}

/// **2.1.20（A-07）**：当 `config.json` 的 `rules` 会被独立规则文件**遮蔽**时打 WARN。
///
/// 判据（与权威来源同源）：`rule_local_file` 指向的文件**存在**（`subscribe.rs` 的
/// `local_rules_with_drops` 就是"存在即只用它"）**且** `cfg["rules"]` 非空**且**两侧内容
/// 不同 ⇒ 配置里那份**不会生效**。
///
/// 返回 `(影子条数, 权威文件路径)`（供单测断言；`None` = 没有被遮蔽）。
pub fn warn_if_config_rules_are_shadowed(cfg: &Value) -> Option<(usize, String)> {
    let path = cfg.get("rule_local_file").and_then(Value::as_str)?;
    if path.trim().is_empty() {
        return None;
    }
    if !std::path::Path::new(path).is_file() {
        // 文件不存在 ⇒ `config.json.rules` 正是**生效**的那一份（兜底路径），无需告警。
        return None;
    }
    let cfg_rules = cfg.get("rules").and_then(Value::as_array);
    let n = cfg_rules.map(|a| a.len()).unwrap_or(0);
    if n == 0 {
        return None;
    }
    // 只在"两侧确实不同"时告警（相同 ⇒ 无遮蔽风险，避免每次启动都刷日志）。
    let same = std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .map(|disk| {
            let disk_list = disk
                .get("rules")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let cfg_list = cfg_rules.cloned().unwrap_or_default();
            disk_list == cfg_list
        })
        .unwrap_or(false);
    if same {
        return None;
    }
    tracing::warn!(
        config_rules = n,
        authoritative = path,
        "**`config.json` 里的 `rules`（{n} 条）当前不会生效**：独立规则文件 `{path}` 已存在，\
         规则解析器**只**以该文件为权威（`config.json.rules` 仅在文件缺失时作兜底），\
         而 `GET /api/config` 仍会回显这些规则 ⇒ 控制台显示与实际生效可能不一致。\
         让它们生效的两种做法：① 用控制台「分流规则」/ `POST /api/rules` 写入（写进独立文件）；\
         ② 删除 `{path}` 后重启（此时 `config.json.rules` 成为权威）。"
    );
    Some((n, path.to_string()))
}

/// **2.1.16（修复项 6）**：配置 schema 版本迁移（**只做加法**）。
///
/// 版本表（见 `README.md`「配置 schema 版本与迁移」）：
/// - **1** = 2.1.0 … 2.1.15（无 `config_version` 键）。迁移 1→2：写入显式版本号 +
///   本轮新增键的默认值（`udp_workers=0` / `single_flight=true` / `warmup{...}`）；
/// - **2** = 2.1.16 … 2.1.21（`rules` 镜像键仍在 `config.json` 里）；
/// - **3** = 2.1.22（当前）：规则唯一真源 = `state/rules.json`，
///   `config.json` 的 `rules` 镜像键**在迁移中删除**（见 `migrate_v2_to_v3`）。
///
/// 返回 `(来源版本, 人类可读的迁移步骤列表)`。
///
/// **只做加法**（唯一例外是 2→3 的"删除镜像键"，它是本阶段的验收要求，且
/// **迁移前会先做加法导入**：`config.json.rules` 的内容先落进 `state/rules.json`，
/// 内容不会丢。见 `migrate_v2_to_v3` 的文档）。
/// 未来版本（`> CURRENT`）由 [`validate_schema`] 报错拒绝（旧二进制不得跑新配置）。
fn migrate_schema(cfg: &mut Value) -> (u32, Vec<String>) {
    migrate_schema_at(cfg, None)
}

/// 带 `state_dir` 的版本（迁移 2→3 需要**真源文件路径**才能做加法导入）。
///
/// `state_dir = None`（`check-config` 等离线只读场景）⇒ 只做**无损**的版本与键处理：
/// 补 `state_dir` 默认值、把 `config_version` 提到 3，但**不删除** `rules` 镜像键
/// （没有地方安放它 ⇒ 删了就真丢了）。
fn migrate_schema_at(cfg: &mut Value, state_dir: Option<&std::path::Path>) -> (u32, Vec<String>) {
    migrate_schema_full(cfg, state_dir, false)
}

/// 完整形态：`dry_run = true` ⇒ **不写任何文件**（连"加法导入真源"也不做），
/// 只报告将要做的步骤（`--dry-run` 的承诺是"未写任何文件"，不能偷偷建真源）。
fn migrate_schema_full(
    cfg: &mut Value,
    state_dir: Option<&std::path::Path>,
    dry_run: bool,
) -> (u32, Vec<String>) {
    let from = cfg
        .get("config_version")
        .and_then(v_u64)
        .map(|v| v as u32)
        .unwrap_or(LEGACY_CONFIG_VERSION);
    let mut steps: Vec<String> = Vec::new();
    if from < 2 {
        let obj = match cfg.as_object_mut() {
            Some(o) => o,
            None => return (from, steps),
        };
        if obj.get("udp_workers").is_none() {
            obj.insert("udp_workers".into(), json!(0));
            steps.push("v1→v2: 补 udp_workers=0（自动 = CPU 核数，封顶 8）".into());
        }
        if obj.get("single_flight").is_none() {
            obj.insert("single_flight".into(), json!(true));
            steps.push("v1→v2: 补 single_flight=true（同键并发 miss 合并为一次上游）".into());
        }
        if obj.get("warmup").is_none() {
            obj.insert(
                "warmup".into(),
                json!({"enabled": true, "queries": 3, "timeout_ms": 3000}),
            );
            steps.push("v1→v2: 补 warmup={enabled:true,queries:3,timeout_ms:3000}".into());
        }
        if obj.get("config_version").is_none() {
            steps.push(format!(
                "v1→v2: 写入 config_version={CURRENT_CONFIG_VERSION}"
            ));
        }
        obj.insert("config_version".into(), json!(CURRENT_CONFIG_VERSION));
    }
    // ---- 2.1.22：2 → 3（规则唯一真源 + 删除 `config.json.rules` 镜像）----
    if from < 3 {
        steps.extend(migrate_v2_to_v3(cfg, state_dir, dry_run));
        if let Some(o) = cfg.as_object_mut() {
            o.insert("config_version".into(), json!(CURRENT_CONFIG_VERSION));
        }
        steps.push(format!(
            "v2→v3: 写入 config_version={CURRENT_CONFIG_VERSION}"
        ));
    }
    (from, steps)
}

/// **2.1.22 阶段一：2 → 3 迁移**（规则唯一真源 `state/rules.json`，删除镜像键）。
///
/// 顺序**不可调换**（每一步都是"先加法、后减法"）：
/// 1. 读 `config.json.rules`（内存里那份，可能来自旧文件）；
/// 2. **加法**：`state/rules.json` 不存在且 `rules` 非空 ⇒ 先把它写进真源
///    （并打 INFO；`.bak.<ts>` 由调用方在写回前做）；
/// 3. **减法**：`config.json` 的 `rules` 键**删除**（内容已在真源里；`GET /api/config`
///    仍由真源派生 ⇒ 形状不变）。
///
/// `state_dir = None`（离线 `check-config`）⇒ 只补 `state_dir` 默认值，**不删**
/// `rules` 键（没有安放处，删了就真丢了）—— 并在步骤里写明这一点。
fn migrate_v2_to_v3(
    cfg: &mut Value,
    state_dir: Option<&std::path::Path>,
    dry_run: bool,
) -> Vec<String> {
    let mut steps: Vec<String> = Vec::new();
    if cfg.get("state_dir").is_none() {
        cfg["state_dir"] = json!(crate::main_state::DEFAULT_STATE_DIR);
        steps.push(format!(
            "v2→v3: 补 state_dir={}（可直接改这个键换 state/ 位置）",
            crate::main_state::DEFAULT_STATE_DIR
        ));
    }
    if cfg.get("state_persist").is_none() {
        cfg["state_persist"] = json!(true);
        steps.push("v2→v3: 补 state_persist=true（统一持久化事务开关）".into());
    }
    let rules = cfg.get("rules").and_then(Value::as_array).cloned();
    match state_dir {
        None => {
            if rules.as_ref().map(|a| !a.is_empty()).unwrap_or(false) {
                steps.push(
                    "v2→v3: **跳过删除 `config.json.rules`**（离线只读校验：没有 state/ 路径可安放它）"
                        .into(),
                );
            }
        }
        Some(dir) => {
            let auth = dir.join("rules.json");
            if dry_run {
                let n = rules.as_ref().map(|a| a.len()).unwrap_or(0);
                steps.push(format!(
                    "v2→v3: 【dry-run】将做加法导入：`config.json.rules`（{n} 条）→ {}，\
                     然后删除 `config.json.rules` 镜像键（**本次未写任何文件**）",
                    auth.display()
                ));
                return steps;
            }
            if let Some(arr) = &rules {
                if !arr.is_empty() && !auth.is_file() {
                    match crate::main_state::write_rules_source(&auth, arr) {
                        Ok(()) => steps.push(format!(
                            "v2→v3: **加法导入** {} 条规则 → {}（真源；已 fsync）",
                            arr.len(),
                            auth.display()
                        )),
                        Err(e) => {
                            // 导入失败 ⇒ **绝不删除镜像键**（否则规则只剩内存里一份）。
                            steps.push(format!(
                                "v2→v3: **加法导入失败**（{e}）⇒ 本次**保留** `config.json.rules` \
                                 （{n} 条）以免丢规则；修好权限后重跑 migrate-config",
                                n = arr.len()
                            ));
                            return steps;
                        }
                    }
                }
            }
            if cfg
                .as_object()
                .map(|o| o.contains_key("rules"))
                .unwrap_or(false)
            {
                let n = rules.as_ref().map(|a| a.len()).unwrap_or(0);
                if auth.is_file() {
                    cfg.as_object_mut().map(|o| o.remove("rules"));
                    steps.push(format!(
                        "v2→v3: **删除** `config.json.rules` 镜像键（{n} 条已在真源 {} 中）",
                        auth.display()
                    ));
                } else if n == 0 {
                    cfg.as_object_mut().map(|o| o.remove("rules"));
                    steps.push("v2→v3: 删除空的 `config.json.rules` 镜像键".into());
                } else {
                    steps.push(
                        "v2→v3: **保留** `config.json.rules`（真源不存在且导入未成功）".into(),
                    );
                }
            }
        }
    }
    steps
}

/// **2.1.16（修复项 6）**：离线配置校验（类型 / 范围 / 枚举 / 未知键）。
///
/// 返回 `(warnings, errors)`：
/// - `errors` 非空 ⇒ 配置**不可用**（`check-config` 退出码 2，服务启动也应拒绝）；
/// - `warnings` 只提示（未知键 / 弃用别名），不阻断启动。
///
/// 为什么需要它：2.1.15 及以前，配置里写错一个键名/policy 拼写**完全没有反馈** ——
/// `apply_cfg` 静默忽略未知键、`cache_policy` 的 `_ =>` 兜底成 `lru`，用户以为切了
/// tinylfu 实际跑的仍是 lru（控制台回显也看不出来）。本函数把这类"静默降级"变成
/// 可读错误 + 非零退出码。
///
/// **2.1.18（修复项 7）**：范围/类型/枚举规则**下沉**到
/// [`ebpdns_resolver::config::validate_write`] —— 那是 `PUT /api/config` 的**拒绝判据**，
/// 两处共用同一份实现，因此**不可能**出现"控制台存得进、check-config 报错"（或反向）。
/// 本函数只保留"只有离线校验才关心"的部分：未知键告警、`listen.*` / `api.*` 可解析性、
/// `config_version` 语义、以及 DNS 端口 `dns_port`（它不是 resolver 配置键）。
fn validate_schema(cfg: &Value) -> (Vec<String>, Vec<String>) {
    let mut warn: Vec<String> = Vec::new();
    let mut err: Vec<String> = Vec::new();

    let obj = match cfg.as_object() {
        Some(o) => o,
        None => {
            err.push("配置根节点必须是 JSON 对象".into());
            return (warn, err);
        }
    };

    // ---- 未知顶层键（告警，便于发现拼写错误/过期键）----
    //
    // **2.1.20（A-14 修复：程序自己注入的键被判"未知键"，且保存一次后永久告警）**：
    // 此前 known 集合只取 `default_config()` 的键，而 `migrate_cfg` 会在**运行期**
    // 注入 `rule_local_file` / `rule_sub_file`（还有 `cache_file` 等路径键），
    // `PUT /api/config` 又把 **live cfg 的合并结果**落盘 ⇒ **控制台保存过一次之后**，
    // `config.json` 就永久带着这些键，此后每次 `check-config`（含 install.sh 预检）
    // 都会报"未知配置键 rule_sub_file（将被忽略）" —— 而它正是程序自己写进去的。
    //
    // 现在 known 集合 = `CONFIG_TOP_LEVEL_KEYS`（**规范键集**，与 `/api/config` 的
    // 可写/只读划分**同一份来源**），因此注入键天然在集合内；`default_config()` 的键
    // 也必须是它的子集（另有单测钉死）。
    let known: std::collections::HashSet<&str> = ebpdns_resolver::config::CONFIG_TOP_LEVEL_KEYS
        .iter()
        .copied()
        .collect();
    let mut unknown: Vec<&str> = obj
        .keys()
        .map(|k| k.as_str())
        .filter(|k| !known.contains(k))
        .collect();
    unknown.sort_unstable();
    for k in unknown {
        warn.push(format!("未知配置键 `{k}`（将被忽略；请核对拼写或删除）"));
    }

    // ---- 类型/范围/枚举：与 `PUT /api/config` **同一份规则** ----
    err.extend(ebpdns_resolver::config::validate_write(cfg));

    // ---- 只有离线校验关心的项 ----
    // DNS 端口（不属于 resolver 配置，故不在 validate_write 里）。
    if let Some(v) = obj.get("dns_port") {
        match v_u64(v) {
            Some(n) if (1..=65535).contains(&n) => {}
            Some(n) => err.push(format!("`dns_port` = {n} 超出允许范围 [1, 65535]")),
            None => err.push(format!("`dns_port` 必须是整数，实际为 {v}")),
        }
    }
    // `rpz` 是历史布尔键（不在 validate_write 的集合里：它已无读取点）。
    if let Some(v) = obj.get("rpz") {
        if v_bool(v).is_none() {
            err.push(format!("`rpz` 必须是布尔（true/false），实际为 {v}"));
        }
    }

    // ---- **2.1.18（修复项 20）：语义互斥/风险组合的显式告警** ----
    //
    // 这一组都是"配置合法但语义自相矛盾或高风险"的组合：`check-config` 必须**说出来**，
    // 而不是静默通过（部署代理 E8b/E12 实测的就是"0 条告警"）。
    // 可疑的规则 match（用户实测 `*.3` 这类"纯数字后缀"几乎一定是误操作）。
    if let Some(arr) = obj.get("rules").and_then(Value::as_array) {
        for (i, r) in arr.iter().enumerate() {
            let m = r.get("match").and_then(Value::as_str).unwrap_or("");
            let body = m.trim_start_matches("*.").trim_start_matches('.');
            let suspicious = m.trim().is_empty()
                || body.is_empty()
                || !body.contains('.')
                || body.chars().all(|c| c.is_ascii_digit());
            if suspicious {
                warn.push(format!(
                    "`rules[{i}].match` = {m:?} 可疑：匹配的是**单个标签/纯数字**（如 `*.3`），\
                     通常不会命中任何真实域名。请确认这是有意的（否则删除该规则）"
                ));
            }
        }
    }
    // `ttl_min > 0` 会**抬升**上游 TTL ⇒ 可能向下游提供超过原 TTL 的数据（DNS TTL 契约）。
    if let Some(v) = obj.get("ttl_min").and_then(v_f64) {
        if v > 0.0 {
            warn.push(format!(
                "`ttl_min` = {v} > 0：**抬升**上游返回的低 TTL 记录 ⇒ 可能向下游提供\
                 超过上游原 TTL 的数据（与 DNS TTL 契约冲突）。除非确有必要，建议 `ttl_min=0`"
            ));
        }
    }
    // `serve_stale` 的陈旧窗口（同样"超过原 TTL 仍可应答"）。
    if obj.get("serve_stale").and_then(v_bool).unwrap_or(false) {
        let st = obj.get("stale_ttl").and_then(v_f64).unwrap_or(0.0);
        if st > 0.0 {
            warn.push(format!(
                "`serve_stale=true` + `stale_ttl` = {st}s：过期应答在**最长 {st} 秒**内仍会被返回\
                 （服务于下游时**可能超过原 TTL**）。这是有意行为，请确认下游可接受；\
                 计数见 `counters.stale_served`"
            ));
        }
    }
    // 非回环 API 且无 token ⇒ 局域网内任何人可改配置/规则/重启。
    let api_host = obj
        .get("api")
        .and_then(|a| a.get("host"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let api_token = obj
        .get("api")
        .and_then(|a| a.get("token"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let loopback = matches!(api_host, "127.0.0.1" | "::1" | "localhost" | "");
    if !loopback && api_token.trim().is_empty() {
        warn.push(format!(
            "**安全风险**：`api.host` = {api_host:?} 绑定**非回环**地址且 `api.token` 为空 ⇒ \
             同网段任何人都能读取状态、改配置/规则并重启服务。两种正解：\
             ① `api.host` 改回 `127.0.0.1`（推荐，配合本机反代）；② 设置非空 `api.token`"
        ));
    }
    // `cache_partitions` 旧形状（整数等）现在**被忽略**：必须显式告知。
    if let Some(v) = obj.get("cache_partitions") {
        if !v.is_null() && !v.is_object() {
            warn.push(format!(
                "`cache_partitions` = {v} 不是对象：该键的**正确形状**是 \
                 `{{\"domestic\":0.5,\"global\":0.3,\"default\":0.2}}`（group→权重，\
                 负数钳 0 后归一化到和为 1）；`null` = 用默认 0.2/0.2/0.6。\
                 当前值会被**忽略**（仅对 `cache_policy=partitioned` 生效）"
            ));
        }
    }

    // ---- 枚举 ----
    if let Some(p) = obj.get("cache_policy").and_then(Value::as_str) {
        let n = p.trim().to_ascii_lowercase();
        if !matches!(
            n.as_str(),
            "lru" | "tinylfu" | "w-tinylfu" | "partitioned" | "partition"
        ) {
            err.push(format!(
                "`cache_policy` = {p:?} 不是合法值（允许: lru | tinylfu | partitioned）"
            ));
        }
    }
    // ---- schema 版本 ----
    match obj.get("config_version").and_then(v_u64) {
        Some(v) if v as u32 > CURRENT_CONFIG_VERSION => err.push(format!(
            "`config_version` = {v} 高于本二进制支持的 {CURRENT_CONFIG_VERSION}：\
             拒绝用旧二进制运行新配置（请升级 ebpdns 或还原配置）"
        )),
        Some(v) if (v as u32) < 1 => err.push(format!("`config_version` = {v} 非法（最小 1）")),
        None => warn.push(format!(
            "缺少 `config_version`：按旧版本 {LEGACY_CONFIG_VERSION} 处理并由 migrate_cfg 迁移"
        )),
        _ => {}
    }

    // ---- 监听地址 / API 地址（可解析性）----
    let parse_ep = |key: &str, v: &Value, err: &mut Vec<String>| {
        // 允许三种形态：false/null（显式关闭）/ "ip:port" 字符串。
        if v.is_null() || v == &json!(false) {
            return;
        }
        let s = match v.as_str() {
            Some(s) => s,
            None => {
                err.push(format!(
                    "`{key}` 必须是 \"ip:port\" 字符串或 false/null，实际为 {v}"
                ));
                return;
            }
        };
        if s.trim().is_empty() {
            return; // 空串 = 显式关闭（与 ListenSpec 同口径）
        }
        if s.parse::<std::net::SocketAddr>().is_err() {
            err.push(format!(
                "`{key}` = {s:?} 不是合法的 ip:port（示例 \"0.0.0.0:53\"）"
            ));
        }
    };
    if let Some(l) = obj.get("listen") {
        match l.as_object() {
            Some(lo) => {
                for k in ["udp", "tcp", "udp6", "tcp6"] {
                    if let Some(v) = lo.get(k) {
                        parse_ep(&format!("listen.{k}"), v, &mut err);
                    }
                }
            }
            None => err.push("`listen` 必须是对象（含 udp/tcp/udp6/tcp6）".into()),
        }
    }
    if let Some(a) = obj.get("api") {
        match a.as_object() {
            Some(ao) => {
                if let Some(h) = ao.get("host").and_then(Value::as_str) {
                    if h.trim().parse::<std::net::IpAddr>().is_err() {
                        err.push(format!(
                            "`api.host` = {h:?} 不是合法 IP（示例 \"127.0.0.1\"）"
                        ));
                    }
                }
                if let Some(p) = ao.get("port") {
                    let n = v_u64(p);
                    match n {
                        Some(v) if (1..=65535).contains(&v) => {}
                        _ => err.push(format!("`api.port` = {p} 超出允许范围 [1, 65535]")),
                    }
                }
            }
            None => err.push("`api` 必须是对象（含 host/port/token）".into()),
        }
    }
    // ---- 上游条目最小形状 ----
    // **2.1.18（修复项 7）**：结构/端口/协议校验已下沉到
    // `ebpdns_resolver::config::validate_write`（与 `PUT /api/config` 同一判据）。
    // 这里只把"缺失 id/proto/host"降级为**告警**（离线校验更宽容：运行时会兜底，
    // 而写路径靠 `upstreams_create/update` 的另一套必填校验拒绝）。
    if let Some(ups) = obj.get("upstreams").and_then(Value::as_array) {
        for (i, u) in ups.iter().enumerate() {
            for k in ["id", "proto", "host"] {
                if u.get(k)
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .unwrap_or("")
                    .is_empty()
                {
                    warn.push(format!(
                        "`upstreams[{i}].{k}` 缺失或为空（该上游可能无法使用）"
                    ));
                }
            }
        }
    }
    (warn, err)
}

/// **2.1.16（修复项 6）**：`ebpdns check-config` 的实现。返回进程退出码。
fn run_check_config(path: Option<&std::path::Path>) -> i32 {
    let p = resolve_cfg_path(path);
    let text = match std::fs::read_to_string(&p) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ERROR: 无法读取配置 {}: {e}", p.display());
            return 2;
        }
    };
    let mut cfg: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ERROR: 配置 {} 不是合法 JSON: {e}", p.display());
            return 2;
        }
    };
    // **2.1.29**：已移除的 XDP/eBPF 键只剥离（check-config 只读，不写文件）。
    let removed_xdp = strip_removed_xdp_keys(&mut cfg);
    if !removed_xdp.is_empty() {
        println!("已自动清理 XDP 相关键：{}", removed_xdp.join(", "));
    }
    // **2.1.22**：离线校验**不删** `config.json.rules`（没有 `state/` 安放它），
    // 因此这里传 `state_dir = None` —— 见 `migrate_schema_at` 的文档。
    let (from, steps) = migrate_schema_at(&mut cfg, None);
    let (warn, err) = validate_schema(&cfg);
    for s in &steps {
        println!("MIGRATE: v{from} → v{CURRENT_CONFIG_VERSION}: {s}");
    }
    for w in &warn {
        eprintln!("WARN: {w}");
    }
    for e in &err {
        eprintln!("ERROR: {e}");
    }
    let ver = cfg
        .get("config_version")
        .and_then(v_u64)
        .unwrap_or(LEGACY_CONFIG_VERSION as u64);
    // **2.1.22（验收要求：`check-config` 输出一行提示）**：规则真源的位置与形态。
    println!("{}", rules_source_hint(&p, &cfg));
    if err.is_empty() {
        println!(
            "config OK (version {ver}) — {} 条告警，0 条错误",
            warn.len()
        );
        0
    } else {
        eprintln!("config INVALID (version {ver}) — {} 条错误", err.len());
        2
    }
}

/// **2.1.22**：`check-config` / `migrate-config` 的**一行**规则真源提示。
///
/// 内容必须能回答运维最常问的两个问题：
/// ① 规则到底存在哪个文件？② 配置里如果也有一份 `rules`，谁说了算？
pub fn rules_source_hint(cfg_path: &std::path::Path, cfg: &Value) -> String {
    let dir = main_state::resolve_state_dir(cfg);
    let auth = main_state::rules_source_path(&dir);
    let n = rules_count_in_file(&auth);
    let shadow_n = cfg
        .get("rules")
        .and_then(Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);
    let mirror = cfg
        .get("rule_local_file")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| {
            ebpdns_rules::load::local_rules_path(cfg_path)
                .display()
                .to_string()
        });
    format!(
        "STATE: 规则唯一真源 = {}（state_dir={}，含 {} 条）；镜像/发现路径 = {}；\
         `config.json.rules` = {} 条{}",
        auth.display(),
        dir.display(),
        n,
        mirror,
        shadow_n,
        if shadow_n > 0 {
            "（**仅供参考**：2.1.22 起它以真源为准，真源存在时该键不会被读取）"
        } else {
            ""
        }
    )
}

/// 只读地数一个规则文件里的条数（不存在/不可解析 ⇒ 0）。
fn rules_count_in_file(p: &std::path::Path) -> usize {
    std::fs::read(p)
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .map(|v| match v {
            Value::Array(a) => a.len(),
            other => other
                .get("rules")
                .and_then(Value::as_array)
                .map(|a| a.len())
                .unwrap_or(0),
        })
        .unwrap_or(0)
}

/// 配置路径：显式给出则用之，否则 `/etc/ebpdns/config.json`。
fn resolve_cfg_path(path: Option<&std::path::Path>) -> PathBuf {
    path.map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/etc/ebpdns/config.json"))
}

/// **2.1.18（修复项 1②）**：`default_config()` 里有而 `cfg` 里缺的**顶层键**
/// （= 本版本相对该配置文件"新增的键"）。
///
/// 这是 install.sh 打印"缺少多少 2.1.19 新键"的**唯一**判据来源：
/// 键表就是 `default_config()` 本身，不存在第二份副本可以漂移。
/// 只比较**顶层**键的存在性（不比较值的类型/取值 —— 那些由 `validate_schema` 负责）。
///
/// **[2.1.23 / DEF-222-06] 排除"镜像键"**：`default_config()` 里有 `"rules": []`
/// （出厂模板带一个空数组），但 2.1.22 的 2→3 迁移**故意删除** `config.json.rules`。
/// 2.1.22 里补键发生在迁移**之前**，于是两次 `migrate-config` 会得到不同结果：
/// 第一次删掉 `rules`，第二次又把它当"缺失键"补回空数组 ⇒ **非幂等**
/// （与"`config.json` 不再携带 `rules` 镜像键"这条 KNOWN DIFF 直接矛盾）。
///
/// 现在把 `rules` 从**补键对照集**里排除：它已由真源（`state/rules.json`）承担
/// （见 [`crate::main_state::migrate_legacy_rules`]），不再是"配置顶层键"。
fn missing_default_keys(cfg: &Value) -> Vec<String> {
    /// **不参与补键**的键（由真源/运行期注入管理；补回它们会造成非幂等或语义漂移）。
    ///
    /// * `rules`：2.1.22 起唯一真源是 `state/rules.json`，`config.json.rules` 是**被删除的**
    ///   镜像键（2→3 迁移的减法步骤）；
    /// * `rule_local_file` / `rule_sub_file`：**运行期注入**（`migrate_cfg` 按 `config.json`
    ///   同目录推导），写进文件会把安装机路径固化。
    const NOT_A_MISSING_KEY: &[&str] = &["rules", "rule_local_file", "rule_sub_file"];
    let dft = default_config();
    let (Some(dst), Some(src)) = (cfg.as_object(), dft.as_object()) else {
        return Vec::new();
    };
    let mut missing: Vec<String> = src
        .keys()
        .filter(|k| !dst.contains_key(k.as_str()))
        .filter(|k| !NOT_A_MISSING_KEY.contains(&k.as_str()))
        .cloned()
        .collect();
    missing.sort_unstable();
    missing
}

/* ---------- 2.1.24：`migrate-config` / `--export-legacy` 的退出码常量 ---------- */

/// 完成（含"无缺失键"的 no-op 与 `--dry-run`）。
pub const MIGRATE_RC_OK: i32 = 0;
/// 文件系统/备份/写回失败。
pub const MIGRATE_RC_IO: i32 = 1;
/// 配置不可迁移（不是合法 JSON 对象 / 迁移后仍有错误 / `--check-only` 校验失败）。
pub const MIGRATE_RC_CONFIG: i32 = 2;
/// **未落盘**：既没有 `--state-dir`、配置里也没有 `state_dir` ⇒ 只做只读报告。
///
/// 为什么必须与 `1` 区分：2.1.23 在这条路径上**回落到生产默认路径**
/// `/var/lib/ebpdns/state` 并真的去写规则真源 + 重锚（撞上运行中实例的锁后报 `rc=1`，
/// 看起来像"IO 失败"，实际是"配置已写回、提交点未更新"）。
pub const MIGRATE_RC_NO_STATE_DIR: i32 = 3;
/// **配置已写回、但提交点未更新**：重锚失败（最常见原因 = 服务在运行、持有 `state/.lock`）。
pub const MIGRATE_RC_WRITTEN_NOT_REANCHORED: i32 = 4;

/// `migrate-config` / `--export-legacy` 用哪个 `state/` 目录，以及**凭什么**。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrateStateDirSource {
    /// 显式 `--state-dir`。
    Cli,
    /// 配置文件里的 `state_dir`（非空字符串）。
    Config,
    /// 环境变量 `EBPDNS_STATE_DIR`（非空）。
    Env,
}

/// 解析离线迁移要用的 `state/` 目录 —— **绝不返回默认值**（**2.1.24 / P1-3d**）。
///
/// # 为什么不能复用 `main_state::resolve_state_dir`
///
/// 那条路径的最后一档是 [`main_state::DEFAULT_STATE_DIR`]（`/var/lib/ebpdns/state`，
/// **生产路径**），而离线迁移会**往里写**规则真源 `rules.json` 并重锚提交点。
/// 2.1.23 的实测事故正是这一档：一份**没有** `state_dir` 的 2.1.22-era 配置被
/// "只做加法"补上默认值 ⇒ `migrate-config` **真的**去读了生产状态目录、把测试规则
/// 写进生产真源，并在重锚时撞上运行中实例的 `flock` ⇒ 打印
/// `ERROR: 重新锚定失败：lock held by pid=…`、`rc=1`，而**配置已经写回**
/// （`install.sh --migrate-config` 因此对这类配置**必失败**，且失败原因被误判成 IO）。
///
/// # 判据
///
/// 与 `resolve_state_dir_checked` **同优先级**，只把"默认档"换成 `None`：
/// `--state-dir` > `cfg["state_dir"]`（非空） > `EBPDNS_STATE_DIR`（非空） > **`None`**。
///
/// `None` ⇒ 调用方**只做只读报告**（[`MIGRATE_RC_NO_STATE_DIR`]），一个字节都不写。
pub fn migrate_state_dir(
    cfg: &Value,
    cli: Option<&std::path::Path>,
    env: Option<&str>,
) -> Option<(PathBuf, MigrateStateDirSource)> {
    if let Some(p) = cli.filter(|p| !p.as_os_str().is_empty()) {
        return Some((p.to_path_buf(), MigrateStateDirSource::Cli));
    }
    if let Some(s) = cfg
        .get("state_dir")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return Some((PathBuf::from(s), MigrateStateDirSource::Config));
    }
    if let Some(s) = env.map(str::trim).filter(|s| !s.is_empty()) {
        return Some((PathBuf::from(s), MigrateStateDirSource::Env));
    }
    None
}

/// **2.1.18（修复项 1②）**：`ebpdns migrate-config` 的实现。返回进程退出码
/// （语义见 [`Cmd::MigrateConfig`] 的文档；2.1.24 起有 `3` / `4` 两个新码）。
fn run_migrate_config(
    path: Option<&std::path::Path>,
    dry_run: bool,
    check_only: bool,
    export_legacy: bool,
    allow_shared_state_dir: bool,
    cli_state_dir: Option<&std::path::Path>,
    env_state_dir: Option<&str>,
) -> i32 {
    if check_only {
        // 只做校验：与 `check-config` **完全同一条代码路径**（不重复实现）。
        return run_check_config(path);
    }
    let p = resolve_cfg_path(path);
    let text = match std::fs::read_to_string(&p) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ERROR: 无法读取配置 {}: {e}", p.display());
            return MIGRATE_RC_IO;
        }
    };
    let mut cfg: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ERROR: 配置 {} 不是合法 JSON: {e}", p.display());
            eprintln!("（未改动任何文件；请先修好 JSON 再跑 migrate-config）");
            return MIGRATE_RC_CONFIG;
        }
    };
    if !cfg.is_object() {
        eprintln!(
            "ERROR: 配置 {} 根节点必须是 JSON 对象（未改动任何文件）",
            p.display()
        );
        return MIGRATE_RC_CONFIG;
    }

    // ---- **2.1.24**：先定 `state/` 目录来源（**必须在补默认键之前**取）----
    //
    // 顺序很关键：下面的"只做加法"会把 `state_dir` 补成 `default_config()` 里的值
    // （= 生产路径），一旦补完再判断，就永远看不出"配置本来没有 state_dir"这件事
    // —— 那正是 2.1.23 事故的形状。
    let chosen = migrate_state_dir(&cfg, cli_state_dir, env_state_dir);
    // 配置里**原本**就有 `state_dir` 吗（补键之前）？
    let cfg_had_state_dir = cfg
        .get("state_dir")
        .and_then(Value::as_str)
        .map(str::trim)
        .is_some_and(|s| !s.is_empty());
    // 没有可用的状态目录 ⇒ **只读报告模式**：强制 dry-run，且迁移走
    // "无 state_dir" 的无损口径（不导入规则、不删 `config.json.rules` 镜像键）。
    let report_only = chosen.is_none();
    if report_only {
        eprintln!(
            "WARN: 既没有 `--state-dir`，配置 {} 里也没有 `state_dir` ⇒ \
             **只做只读报告，不改动任何文件**。",
            p.display()
        );
        eprintln!(
            "      理由：离线迁移要向 `state/` 写入规则真源并重锚提交点；没有显式目录时\
             **绝不能**默认落到生产路径 `{}`。",
            crate::main_state::DEFAULT_STATE_DIR
        );
        eprintln!(
            "      请显式给出目录后重跑：ebpdns migrate-config --config {} --state-dir <专用目录>",
            p.display()
        );
        eprintln!("      （隔离/审查实例请务必用专用目录；这与 `run` 的 fail-closed 口径一致。）");
    }
    let effective_dry_run = dry_run || report_only;

    // ---- **2.1.22：`--export-legacy`（3 → 2 回退）走完全独立的一条路径** ----
    //
    // 与迁移方向相反：把 `state/rules.json`（真源）**逐字节**导出回
    // `config.json.rules`，并把 `config_version` 降回 2 ⇒ 2.1.21 二进制能读。
    if export_legacy {
        let Some((dir, src)) = chosen.as_ref() else {
            eprintln!(
                "export-legacy: 未执行（没有可用的 `state/` 目录；**未改动任何文件**）。\
                 请显式给出：ebpdns migrate-config --export-legacy --config {} --state-dir <专用目录>",
                p.display()
            );
            return MIGRATE_RC_NO_STATE_DIR;
        };
        println!(
            "EXPORT-LEGACY-SUMMARY state_dir_source: {}",
            migrate_state_dir_source_label(*src)
        );
        return match main_state::export_legacy(&p, dir) {
            Ok((n, bak, ts)) => {
                println!(
                    "EXPORT-LEGACY-SUMMARY rules={n} config_version=2 state_dir={} backup={}",
                    dir.display(),
                    bak.display()
                );
                println!(
                    "export-legacy：已把 {} 条规则从真源 {} 导出回 {}（**逐字节原样**，\
                     顺带把 config_version 降回 2）；原文件备份在 {}（ts={ts}）",
                    n,
                    main_state::rules_source_path(dir).display(),
                    p.display(),
                    bak.display()
                );
                // **2.1.23（DEF-222-05）**：写回 `config.json` 之后**必须重锚提交点**，
                // 否则下一次启动会把这个（运维常规动作产生的）外部改写判成"撕裂"。
                match main_state::reanchor_state(dir, allow_shared_state_dir, "export-legacy") {
                    Ok(Some(true)) => {
                        println!("EXPORT-LEGACY-SUMMARY reanchor: 已重新锚定提交点（不会判撕裂）")
                    }
                    Ok(Some(false)) => {
                        println!("EXPORT-LEGACY-SUMMARY reanchor: 提交点与磁盘一致")
                    }
                    Ok(None) => {
                        println!("EXPORT-LEGACY-SUMMARY reanchor: `state/` 无提交点，无需重锚")
                    }
                    Err(e) => {
                        eprintln!("WARN: 重新锚定 `state/` 提交点失败：{e}");
                        eprintln!(
                            "（导出**已写回** {}；但提交点没更新 ⇒ 下次启动可能判撕裂。\
                             最常见原因：服务正在运行、持有 {}/.lock。\
                             处理：① 停服后重跑本命令（推荐）；或 ② 加 `--allow-shared-state-dir` 强制重锚（危险）。）",
                            p.display(),
                            dir.display()
                        );
                        return MIGRATE_RC_WRITTEN_NOT_REANCHORED;
                    }
                }
                println!(
                    "提示：回退到 2.1.21 二进制后，`state/` 目录**可以保留**（旧版不读它）；\
                     若要回到 2.1.22+，请把 `config_version` 提回当前值并重跑 migrate-config。"
                );
                MIGRATE_RC_OK
            }
            Err(e) => {
                eprintln!("ERROR: export-legacy 失败（**未改动任何文件**）：{e}");
                MIGRATE_RC_CONFIG
            }
        };
    }

    // ---- 1) 只做加法：补 default_config() 里缺的顶层键 ----
    let missing = missing_default_keys(&cfg);
    if let (Some(dst), Some(src)) = (cfg.as_object_mut(), default_config().as_object()) {
        for k in &missing {
            if let Some(v) = src.get(k) {
                dst.insert(k.clone(), v.clone());
            }
        }
    }
    // ---- **2.1.24**：把"补进去的 `state_dir`"改成**本次真正使用**的目录 ----
    //
    // `default_config()` 里 `state_dir` 的值就是生产路径。若配置**本来没有**这个键，
    // 上面那一步会把它补成生产路径 —— 于是配置从此指向 `/var/lib/ebpdns/state`，
    // 而真源/提交点在 `--state-dir` 给的那个目录里 ⇒ "写着 A、用着 B"。
    // 判据：只在"原本没有该键"时**覆盖**（配置里已有值 = 用户给的值，绝不改动）。
    let mut state_dir_steps: Vec<String> = Vec::new();
    let state_dir: PathBuf = match chosen.as_ref() {
        Some((d, src)) => {
            if !cfg_had_state_dir {
                cfg["state_dir"] = json!(d.display().to_string());
                state_dir_steps.push(format!(
                    "v2→v3: 补 state_dir={}（来源：{}；**不**使用生产默认路径）",
                    d.display(),
                    migrate_state_dir_source_label(*src)
                ));
            } else if cfg
                .get("state_dir")
                .and_then(Value::as_str)
                .map(str::trim)
                .map(PathBuf::from)
                .is_some_and(|p| p != *d)
            {
                // 配置里有值、但本次用的是别处（`--state-dir` / 环境变量）⇒ 必须说清楚。
                eprintln!(
                    "WARN: 本次迁移使用 `state/` = {}（来源：{}），而配置里的 `state_dir` 是 {}。\
                     配置值**保持原样**（只做加法，不改用户给的值）；若想让两者一致，请手工改配置。",
                    d.display(),
                    migrate_state_dir_source_label(*src),
                    cfg.get("state_dir")
                        .and_then(Value::as_str)
                        .unwrap_or("<非字符串>")
                );
            }
            d.clone()
        }
        // 只读报告模式：用"无 state_dir"的无损口径（不导入规则、不删镜像键）。
        // 这里的路径**只用于打印提示**，不会被打包/读写（下面 `effective_dry_run` 保证不落盘）。
        None => PathBuf::from(crate::main_state::DEFAULT_STATE_DIR),
    };
    // ---- 2) schema 版本迁移（1→2 补键；**2→3 加法导入 + 删除 `config.json.rules`**）----
    // **不注入** rule_local_file / rule_sub_file：那两个是**运行时**按 config.json
    // 同目录推导的（见 `migrate_cfg`），写进文件反而会把安装机的路径固化到配置里。
    //
    // 2→3 的加法导入需要**真源路径**：报告模式下传 `None` ⇒ 与 `check-config` 同口径的
    // **无损**迁移（只补键、不导入规则、不删 `config.json.rules`）。
    let schema_state_dir = if report_only {
        None
    } else {
        Some(state_dir.as_path())
    };
    let (from, steps) = migrate_schema_full(&mut cfg, schema_state_dir, effective_dry_run);
    println!(
        "MIGRATE-SUMMARY state_dir: {}{}",
        state_dir.display(),
        if report_only {
            "（**仅用于报告**：未给出 state_dir ⇒ 未读写任何状态目录）"
        } else {
            ""
        }
    );
    for s in &state_dir_steps {
        println!("MIGRATE: {s}");
    }

    // ---- 3) 落盘前先校验：迁移后的配置必须无 ERROR，否则**不写**（避免把坏配置写死）----
    let (warn, err) = validate_schema(&cfg);
    for w in &warn {
        println!("WARN: {w}");
    }
    for e in &err {
        eprintln!("ERROR: {e}");
    }
    if !err.is_empty() {
        eprintln!(
            "migrate-config 中止：迁移后的配置仍有 {} 条错误（**未改动任何文件**）",
            err.len()
        );
        return MIGRATE_RC_CONFIG;
    }

    let ver = cfg
        .get("config_version")
        .and_then(v_u64)
        .unwrap_or(LEGACY_CONFIG_VERSION as u64);
    println!(
        "MIGRATE-SUMMARY config_version: {from} → {ver}（{} 步 schema 迁移）",
        steps.len() + state_dir_steps.len()
    );
    println!("MIGRATE-SUMMARY missing_keys: {}", missing.len());
    if missing.is_empty() {
        println!("MIGRATE-SUMMARY missing_key_names: （无 —— 该配置已含本版本全部顶层键）");
    } else {
        println!("MIGRATE-SUMMARY missing_key_names: {}", missing.join(", "));
    }
    for s in &steps {
        println!("MIGRATE: v{from} → v{ver}: {s}");
    }
    // **2.1.22（验收要求：一行提示）**：迁移后规则真源的位置与形态。
    // **2.1.24**：报告模式（未落盘）下**不打**这一行 —— 它描述的是"这份配置会给服务什么样
    // 的 state_dir"，而本次一个字节都没写（打印它会让人以为配置已经指向那个目录）。
    if report_only {
        println!("STATE: 只读报告（**未落盘**）⇒ 没有生效的 `state_dir`，也没有规则真源");
    } else {
        println!("{}", rules_source_hint(&p, &cfg));
    }

    if report_only {
        eprintln!(
            "migrate-config：**只读报告**（未写任何文件；退出码 {MIGRATE_RC_NO_STATE_DIR}）。\
             请显式给出 state/ 目录后重跑：ebpdns migrate-config --config {} --state-dir <专用目录>",
            p.display()
        );
        return MIGRATE_RC_NO_STATE_DIR;
    }
    if dry_run {
        println!(
            "migrate-config --dry-run：以上为将要补齐的内容（**未写任何文件**；正式执行会先备份到 {}.bak.<ts>）",
            p.display()
        );
        return MIGRATE_RC_OK;
    }
    if missing.is_empty() && steps.is_empty() && state_dir_steps.is_empty() {
        println!(
            "migrate-config：无需迁移（{} 已含本版本全部顶层键，config_version={ver}）",
            p.display()
        );
        return MIGRATE_RC_OK;
    }

    // ---- 4) 备份（写前）→ 原子写回 ----
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let bak = PathBuf::from(format!("{}.bak.{ts}", p.display()));
    if let Err(e) = std::fs::copy(&p, &bak) {
        eprintln!(
            "ERROR: 备份失败（未改动原文件）：{} → {}: {e}",
            p.display(),
            bak.display()
        );
        return MIGRATE_RC_IO;
    }
    println!("MIGRATE-SUMMARY backup: {}", bak.display());

    let out = serde_json::to_vec_pretty(&cfg).unwrap_or_else(|_| b"{}".to_vec());
    let tmp = PathBuf::from(format!("{}.tmp.{}", p.display(), std::process::id()));
    if let Err(e) = std::fs::write(&tmp, &out) {
        eprintln!(
            "ERROR: 写临时文件失败（原文件未改动）：{}: {e}",
            tmp.display()
        );
        return MIGRATE_RC_IO;
    }
    // 权限对齐：先尝试复制原文件模式（0640 是安装脚本设定的值），失败则退 0644。
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(md) = std::fs::metadata(&p) {
            let mode = md.permissions().mode() & 0o7777;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode));
        }
    }
    if let Err(e) = std::fs::rename(&tmp, &p) {
        eprintln!("ERROR: 原子替换失败（原文件未改动）：{}: {e}", p.display());
        let _ = std::fs::remove_file(&tmp);
        return MIGRATE_RC_IO;
    }
    // ---- 5) **重新锚定提交点**（2.1.23 / DEF-222-05）----
    //
    // `config.json` 是提交点记录的一个 part；上面这一步**绕过了 store** 直接改它。
    // 若不重锚，下一次启动 `load()` 会判"撕裂"（无历史世代时甚至 TORN）——
    // 而 `migrate-config` 是**运维常规动作**，不能变成"搞坏状态"的操作。
    match main_state::reanchor_state(&state_dir, allow_shared_state_dir, "migrate-config") {
        Ok(Some(true)) => {
            println!("MIGRATE-SUMMARY reanchor: 已把外部改写重新锚定到当前提交点（不会判撕裂）");
        }
        Ok(Some(false)) => {
            println!("MIGRATE-SUMMARY reanchor: 提交点与磁盘一致（无需重锚）");
        }
        Ok(None) => {
            println!("MIGRATE-SUMMARY reanchor: `state/` 无提交点（全新安装），无需重锚");
        }
        Err(e) => {
            // **2.1.24**：这里失败**不是**"迁移失败" —— 配置**已经**写回了，缺的只是重锚。
            // 2.1.23 把它报成 `rc=1`（与"IO/备份失败"同码），于是
            // `install.sh --migrate-config` 在"服务正在运行"这个**常规**场景下必然失败，
            // 而运维会以为迁移整体没做成（实测：`MIGRATE-RC=1` + `lock held by pid=…`）。
            // 现在：WARN + 专用退出码 `MIGRATE_RC_WRITTEN_NOT_REANCHORED`，并给两条出路
            //（都不再引用本子命令**不支持**的选项 —— `--state-dir` / `--allow-shared-state-dir`
            // 自 2.1.24 起是全局参数，可以直接写在本子命令后面）。
            eprintln!("WARN: 重新锚定 `state/` 提交点失败（**配置已写回，提交点未更新**）：{e}");
            eprintln!(
                "（配置**已写回** {}；但提交点没更新 ⇒ 下次启动可能判撕裂。\
                 最常见原因：服务正在运行、持有 {}/.lock。\
                 处理：① 停服后重跑 `ebpdns migrate-config --config {}`（推荐）；\
                 或 ② 加 `--allow-shared-state-dir` 强制重锚（危险）。）",
                p.display(),
                state_dir.display(),
                p.display()
            );
            return MIGRATE_RC_WRITTEN_NOT_REANCHORED;
        }
    }
    println!(
        "migrate-config：已补齐 {} 个缺失键并写回 {}（原文件备份在 {}）",
        missing.len(),
        p.display(),
        bak.display()
    );
    MIGRATE_RC_OK
}

/// `state/` 目录来源的可读标签（**2.1.24**：让"凭什么用这个目录"出现在输出里）。
fn migrate_state_dir_source_label(src: MigrateStateDirSource) -> &'static str {
    match src {
        MigrateStateDirSource::Cli => "--state-dir",
        MigrateStateDirSource::Config => "config.json.state_dir",
        MigrateStateDirSource::Env => "EBPDNS_STATE_DIR",
    }
}

/// `listen.<key>` 的三种取值形态。///
/// 区分「键缺失」与「显式关闭」是 v6 语义的关键：**缺失** → 用默认地址（v6 默认
/// `"[::]"`）；**显式关闭**（`false`/`null`/`""`）→ 不监听，且**不告警**。
#[derive(Debug, Clone, PartialEq, Eq)]
enum ListenSpec {
    /// 键缺失。
    Missing,
    /// 显式关闭（`false` / `null` / 空串）。
    Off,
    /// 地址串（可能含内嵌端口）。
    Addr(String),
}

/// 读取 `listen.<key>`：区分「键缺失」「显式关闭」「地址串」。
fn listen_spec(cfg: &Value, key: &str) -> ListenSpec {
    match cfg.get("listen").and_then(|l| l.get(key)) {
        None => ListenSpec::Missing,
        Some(Value::Null) | Some(Value::Bool(false)) => ListenSpec::Off,
        // `true` = 启用但用默认地址（与 `""` 区分：`""` 按契约是关闭）。
        Some(Value::Bool(true)) => ListenSpec::Addr(String::new()),
        Some(Value::String(s)) if s.trim().is_empty() => ListenSpec::Off,
        Some(Value::String(s)) => ListenSpec::Addr(s.trim().to_string()),
        Some(_) => ListenSpec::Missing,
    }
}

/// IPv4（`listen.udp/tcp`）解析：键缺失或显式关闭一律回退 `default_host`
/// （与历史行为逐字一致：老配置写 `"udp": false`/缺键时仍监听回环，不会静默变成
/// 「什么都不监听」而把用户的服务直接打死）。
fn parse_listen_any(spec: &ListenSpec, default_host: &str) -> (String, Option<u16>) {
    match spec {
        ListenSpec::Addr(s) if !s.trim().is_empty() => parse_listen_cfg(Some(s.as_str())),
        _ => (default_host.to_string(), None),
    }
}

/// IPv6（`listen.udp6/tcp6`）解析：`None` = **显式关闭**（不监听 v6，且不告警）；
/// `Some((host, 内嵌端口))` = 启用（键缺失 / `true` / `""` 之外的写法 → 默认 `"[::]"`）。
fn parse_listen6(spec: &ListenSpec) -> Option<(String, Option<u16>)> {
    match spec {
        ListenSpec::Off => None,
        ListenSpec::Missing => Some(parse_listen_cfg(Some("[::]"))),
        ListenSpec::Addr(s) if s.trim().is_empty() => Some(parse_listen_cfg(Some("[::]"))),
        ListenSpec::Addr(s) => Some(parse_listen_cfg(Some(s.as_str()))),
    }
}

/// 按给定顺序去重监听地址（`listen.udp="[::]"` 与默认 `listen.udp6="[::]"` 会给出同一
/// 地址；重复绑定同一 `(proto, addr)` 必 `EADDRINUSE`）。
fn dedupe_addrs(addrs: &[Option<SocketAddr>]) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::with_capacity(addrs.len());
    for a in addrs.iter().flatten() {
        if !out.contains(a) {
            out.push(*a);
        }
    }
    out
}

/// **2.1.16（功能 7）**：把 `listen.*` + CLI 解析成**实际要绑定的地址列表**。
///
/// 启动路径与 `/api/reload` 热更新路径**共用本函数**，因此两条路径的语义不可能漂移
/// （端口优先级、裸主机容忍、v6 跟随、`[::]` 去重全部只有一份实现）。
///
/// 语义（与 v1.9.162 对齐，详见调用点的长注释）：
/// - 端口优先级：CLI `--dns-udp-port/--dns-tcp-port` > 该键内嵌端口 > `dns_port` > 5353；
/// - `listen.udp6/tcp6` 未写端口时**跟随对应 IPv4 的实际端口**（保证同端口双栈）；
/// - `listen.udp="[::]"` 与默认 `listen.udp6="[::]"` 给出同一地址 → 去重（否则 `EADDRINUSE`）。
fn listen_binds(cfg: &Value, args: &Args) -> (Vec<SocketAddr>, Vec<SocketAddr>) {
    let udp_spec = listen_spec(cfg, "udp");
    let tcp_spec = listen_spec(cfg, "tcp");
    let (udp_host, udp_port_in_cfg) = parse_listen_any(&udp_spec, "127.0.0.1");
    let (tcp_host, tcp_port_in_cfg) = parse_listen_any(&tcp_spec, "127.0.0.1");
    let udp6 = parse_listen6(&listen_spec(cfg, "udp6"));
    let tcp6 = parse_listen6(&listen_spec(cfg, "tcp6"));
    let dns_port_cfg = cfg
        .get("dns_port")
        .and_then(Value::as_u64)
        .filter(|p| (1..=65535).contains(p))
        .map(|p| p as u16);
    let udp_port = args
        .dns_udp_port
        .or(udp_port_in_cfg)
        .or(dns_port_cfg)
        .unwrap_or(5353);
    let tcp_port = args
        .dns_tcp_port
        .or(tcp_port_in_cfg)
        .or(dns_port_cfg)
        .unwrap_or(5353);
    if args.dns_udp_port.is_some() && udp_port_in_cfg.is_some() {
        tracing::info!(
            cli = ?args.dns_udp_port,
            config = ?udp_port_in_cfg,
            "listen.udp 内嵌端口被 CLI --dns-udp-port 覆盖"
        );
    }
    // v6 端口：CLI > `listen.*6` 内嵌端口 > 跟随同协议 IPv4 端口。
    let udp6_port = args
        .dns_udp_port
        .or(udp6.as_ref().and_then(|(_, p)| *p))
        .unwrap_or(udp_port);
    let tcp6_port = args
        .dns_tcp_port
        .or(tcp6.as_ref().and_then(|(_, p)| *p))
        .unwrap_or(tcp_port);
    let udp_bind_want = resolve_bind(&udp_host, udp_port, "listen.udp");
    let tcp_bind_want = resolve_bind(&tcp_host, tcp_port, "listen.tcp");
    let udp6_bind_want = udp6
        .as_ref()
        .map(|(h, _)| resolve_bind(h, udp6_port, "listen.udp6"));
    let tcp6_bind_want = tcp6
        .as_ref()
        .map(|(h, _)| resolve_bind(h, tcp6_port, "listen.tcp6"));
    let udp_binds = dedupe_addrs(&[Some(udp_bind_want), udp6_bind_want]);
    let tcp_binds = dedupe_addrs(&[Some(tcp_bind_want), tcp6_bind_want]);
    (udp_binds, tcp_binds)
}

/// 实际绑定地址 → `/api/status.endpoints`（`udp` / `udp6` / `tcp` / `tcp6` 四项）。
///
/// 语义固定：`udp`/`udp6` 取 UDP 列表中首个 IPv4 / IPv6 地址，`tcp`/`tcp6` 同理。
/// **如实**：v6 绑定失败（降级为仅 IPv4）或显式关闭的地址**不会**出现在快照里，
/// 绝不把配置意图伪装成「正在监听」。
fn endpoints_of(udp: &[SocketAddr], tcp: &[SocketAddr]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::with_capacity(4);
    for (base, list) in [("udp", udp), ("tcp", tcp)] {
        for (suffix, want_v6) in [("", false), ("6", true)] {
            if let Some(a) = list.iter().find(|a| a.is_ipv6() == want_v6) {
                out.push((format!("{base}{suffix}"), a.to_string()));
            }
        }
    }
    out
}

/// 从 [`endpoints_of`] 的产物里取某个名字的地址（仅启动日志用；缺失 → `"-"`）。
fn endpoint_of<'a>(eps: &'a [(String, String)], name: &str) -> &'a str {
    eps.iter()
        .find(|(n, _)| n == name)
        .map(|(_, a)| a.as_str())
        .unwrap_or("-")
}

/// 解析 `listen.udp/tcp` 的取值 → `(host, 内嵌端口)`。
///
/// 支持的写法（与 v1.9.162 的 `host:port` 契约兼容，并容忍常见简写）：
/// `"0.0.0.0"`（裸主机）/ `"127.0.0.1:53"` / `"[::]"` / `"[::1]:53"` / `"::"` / `"2001:db8::1"`。
/// 无法识别（未闭合 `[`、`host:`、`host:abc`）时把整串当主机名处理，交由
/// [`resolve_bind`] 尽力解析并告警——**绝不静默丢弃整条配置**。
fn parse_listen_cfg(raw: Option<&str>) -> (String, Option<u16>) {
    let s = raw.unwrap_or("").trim();
    if s.is_empty() {
        return ("127.0.0.1".to_string(), None);
    }
    // `[v6]` / `[v6]:port`
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(close) = rest.find(']') {
            let host = &rest[..close];
            let port = rest[close + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok());
            if !host.is_empty() {
                return (host.to_string(), port);
            }
        }
        // 未闭合/空方括号：按主机名处理（后续会解析失败并告警）。
        return (s.to_string(), None);
    }
    // 裸 IPv6（多于一个冒号）——不能再按 `host:port` 切。
    if s.matches(':').count() > 1 {
        return (s.to_string(), None);
    }
    match s.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) if !h.is_empty() => (h.to_string(), Some(port)),
            _ => (s.to_string(), None),
        },
        None => (s.to_string(), None),
    }
}

/// 解析监听地址：IP 字面量直接构造；主机名走一次尽力解析（首个结果）。
/// 解析失败 → 回退 `127.0.0.1` 并**告警**（不静默）。
fn resolve_bind(host: &str, port: u16, key: &str) -> SocketAddr {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return SocketAddr::new(ip, port);
    }
    if let Ok(mut it) = (host, port).to_socket_addrs() {
        if let Some(a) = it.next() {
            return a;
        }
    }
    tracing::warn!(
        key,
        host,
        port,
        "监听地址无法解析（既不是 IP 也不是可解析主机名）→ 回退 127.0.0.1"
    );
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn apply_cli_overrides(cfg: &mut Value, args: &Args) {
    if let Some(p) = args.dns_udp_port {
        cfg["dns_port"] = json!(p);
    }
    if let Some(p) = args.api_port {
        cfg["api"]["port"] = json!(p);
    }
    if let Some(h) = &args.api_host {
        cfg["api"]["host"] = json!(h);
    }
}

/// 配置 JSON → ResolverConfig（以默认值为基线；启动路径用）。
fn cfg_to_resolver(cfg: &Value) -> ResolverConfig {
    let mut rc = ResolverConfig::default();
    apply_cfg(&mut rc, cfg);
    rc
}

/// 配置 JSON → ResolverConfig，**以上次生效配置为基线**（热重载路径用）。
///
/// 关键修复：旧实现每次 `PUT /api/config` 后都从 `ResolverConfig::default()` 重建，
/// 导致所有未被 `cfg_to_resolver` 读取的键（serve_stale / speed_test / padding /
/// health_* / rule_sub_interval / cache_partitions …）被**静默重置为
/// 硬编码默认值**，用户在控制台改了也不生效甚至被回退。现在：
/// 1. 以当前生效配置为基线，仅覆盖配置里明确给出的键；
/// 2. 把 `ResolverConfig` 的全部字段都接线；
/// 3. 数值同时接受数字与数字字符串（旧前端会把端口/权重写成字符串）。
fn cfg_to_resolver_from(base: ResolverConfig, cfg: &Value) -> ResolverConfig {
    let mut rc = base;
    apply_cfg(&mut rc, cfg);
    rc
}

/// 数值读取：接受 JSON number 与数字字符串。
fn v_u64(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_u64().or_else(|| n.as_f64().map(|f| f as u64)),
        Value::String(s) => s.trim().parse::<u64>().ok().or_else(|| {
            s.trim()
                .parse::<f64>()
                .ok()
                .filter(|f| f.is_finite() && *f >= 0.0)
                .map(|f| f as u64)
        }),
        _ => None,
    }
}

fn v_f64(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        _ => None,
    }
}

fn v_bool(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        // 兼容 "true"/"1" 之类字符串形态（旧前端 checkbox 序列化差异）。
        Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Some(true),
            "false" | "0" | "no" | "off" => Some(false),
            _ => None,
        },
        Value::Number(n) => n.as_u64().map(|x| x != 0),
        _ => None,
    }
}

/// 把配置 JSON 覆盖到 `rc`（只覆盖配置里出现的键）。
fn apply_cfg(rc: &mut ResolverConfig, cfg: &Value) {
    let num = |k: &str| cfg.get(k).and_then(v_u64);
    let fnum = |k: &str| cfg.get(k).and_then(v_f64);
    let flag = |k: &str| cfg.get(k).and_then(v_bool);

    /* ---- 缓存 ---- */
    if let Some(v) = num("cache_size") {
        rc.cache_size = v as usize;
    }
    if let Some(v) = cfg.get("cache_policy").and_then(Value::as_str) {
        // **[历史归因]** 词表统一：lru / partitioned / tinylfu（兼容 Python 侧大小写与别名）。
        rc.cache_policy = match v.trim().to_ascii_lowercase().as_str() {
            "partitioned" | "partition" => "partitioned".to_string(),
            "tinylfu" | "w-tinylfu" | "wtinylfu" => "tinylfu".to_string(),
            _ => "lru".to_string(),
        };
    }
    if let Some(v) = cfg.get("cache_partitions") {
        if !v.is_null() {
            rc.cache_partitions = Some(v.clone());
        }
    }
    if let Some(v) = flag("cache_persist") {
        rc.cache_persist = v;
    }
    if let Some(v) = num("persist_ttl") {
        rc.persist_ttl = v as u32;
    }

    /* ---- 编排 ---- */
    if let Some(v) = num("max_parallel_upstreams") {
        rc.max_parallel_upstreams = v.max(1) as usize;
    }
    // **2.1.15**：单上游在途请求上限（`0` = 关闭闸门；默认
    // `DEFAULT_UPSTREAM_MAX_INFLIGHT`=32，依据见 ebpdns-upstream 的常量文档）。
    if let Some(v) = num("upstream_max_inflight") {
        rc.upstream_max_inflight = v as usize;
    }
    if let Some(v) = num("timeout_ms") {
        rc.timeout_ms = v;
    }
    if let Some(v) = num("nxdomain_quorum") {
        rc.nxdomain_quorum = v as usize;
    }
    if let Some(v) = flag("fallback") {
        rc.fallback = v;
    }
    if let Some(v) = flag("rebind_protection") {
        rc.rebind_protection = v;
    }
    if let Some(v) = flag("edns") {
        rc.edns = v;
    }
    if let Some(v) = flag("prefetch") {
        rc.prefetch = v;
    }
    // ---- **2.1.20（F-02 修复：预取调参键没有 JSON 键 / 死字段）** ----
    //
    // 审计 F-02 实测：`prefetch_trigger` / `prefetch_target` 在 `unused_fields` 里
    // （声明了但**没有任何读取点**），而 `prefetch_interval`（周期，默认 300s）
    // **没有对应的 JSON 配置键** ⇒ 用户无法调整预取周期，也无法调整触发阈值。
    // 现在四个键全部可配（`prefetch_max` 见下）：
    //   * `prefetch_interval`：后台续期扫描周期（秒，下限 1）——"多久扫一次队列"；
    //   * `prefetch_trigger`：剩余 TTL **低于或等于**该值才入队**并且**真的发上游续期
    //     （秒；0 = 关闭按剩余 TTL 的预取）。**2.1.21（DEF-220-01）**：入队闸门
    //     （`lib.rs::schedule_prefetch`）与续期闸门（`background.rs::do_prefetch`）
    //     是**同一条判据**；2.1.20 及以前 `do_prefetch` 另有一条**未文档化**的
    //     `left < ttl*0.15` 暗闸门，使 `trigger > ttl`（如 3600/300）时**入队却永不续期**；
    //   * `prefetch_target`：续期回填时的 **TTL 上限**（秒；0 = 不额外收紧）。
    //     **2.1.21（DEF-220-11）**：经 `ResolveOpts::ttl_cap` 传到 `fill_cache`，
    //     真的生效（此前是全树零读取点的死字段）；
    //   * `prefetch_max`：队列上界（原有）。

    if let Some(v) = fnum("prefetch_interval") {
        if v.is_finite() {
            rc.prefetch_interval = v.max(1.0);
        }
    }
    if let Some(v) = fnum("prefetch_trigger") {
        if v.is_finite() && v >= 0.0 {
            rc.prefetch_trigger = v;
        }
    }
    if let Some(v) = fnum("prefetch_target") {
        if v.is_finite() && v >= 0.0 {
            rc.prefetch_target = v;
        }
    }
    if let Some(v) = num("prefetch_max") {
        rc.prefetch_max = v as usize;
    }
    if let Some(v) = flag("speed_test") {
        rc.speed_test = v;
    }
    if let Some(v) = flag("ipv6") {
        rc.ipv6 = v;
    }
    if let Some(v) = flag("prefer_ipv4") {
        rc.prefer_ipv4 = v;
    }
    if let Some(v) = flag("ipv4_first") {
        rc.ipv4_first = v;
    }
    if let Some(v) = num("prefetch_max") {
        rc.prefetch_max = v as usize;
    }

    /* ---- 2.1.16 新增键 ---- */
    // ① 收包并行化：0 = 自动（CPU 核数），1 = 退回旧行为，N>1 = N 个 REUSEPORT socket。
    if let Some(v) = num("udp_workers") {
        rc.udp_workers = v as usize;
    }
    // ② 在途查询合并。
    if let Some(v) = flag("single_flight") {
        rc.single_flight = v;
    }
    // ⑥ 配置 schema 版本（迁移在 `crate::config_version::migrate_cfg` 中先行完成；
    // 这里只把它读进 ResolverConfig 以便 `/api/config` 回显当前生效版本）。
    if let Some(v) = num("config_version") {
        rc.config_version = v as u32;
    }
    // ⑨ 上游连接池预热：优先读嵌套 `warmup` 对象，其次读扁平别名键。
    let warm = cfg.get("warmup");
    if let Some(v) = warm
        .and_then(|w| w.get("enabled"))
        .and_then(v_bool)
        .or_else(|| flag("warmup_enabled"))
    {
        rc.warmup_enabled = v;
    }
    if let Some(v) = warm
        .and_then(|w| w.get("queries"))
        .and_then(v_u64)
        .or_else(|| num("warmup_queries"))
    {
        // 夹取到 [1, 8]：预热是"建立连接 + 喂滑窗样本"，超过 8 条只是浪费配额。
        rc.warmup_queries = (v as usize).clamp(1, 8);
    }
    if let Some(v) = warm
        .and_then(|w| w.get("timeout_ms"))
        .and_then(v_u64)
        .or_else(|| num("warmup_timeout_ms"))
    {
        rc.warmup_timeout_ms = v;
    }
    /* ---- TTL / 过期兜底 ---- */
    if let Some(v) = num("ttl") {
        rc.ttl = v as u32;
    }
    if let Some(v) = num("ttl_min") {
        rc.ttl_min = v as u32;
    }
    if let Some(v) = num("ttl_max") {
        rc.ttl_max = v as u32;
    }
    // P1-2：负缓存 TTL 硬上限（0 = 关闭上限；缺省 60）。
    if let Some(v) = num("neg_ttl_max") {
        rc.neg_ttl_max = v as u32;
    }
    // 2.1.12 优化项 ①：RFC 8020 父域 NXDOMAIN 推断（登记 + 匹配）。
    if let Some(v) = flag("rfc8020_infer") {
        rc.rfc8020_infer = v;
    }
    // 2.1.12 优化项 ①：登记/匹配深度上限（标签数），夹取到 [1, 127]。
    if let Some(v) = num("rfc8020_max_labels") {
        rc.rfc8020_max_labels = (v as usize).clamp(1, 127);
    }
    // 2.1.12 优化项 ②：上游评分成功率惩罚下限，夹取到 (0, 1]。
    // 缺省/非法值（0、NaN、负数）保持默认 0.5 —— 0 会让 `1/sr` 无界，
    // 从而把上游永久饿死（见 config.rs 字段注释）。
    if let Some(v) = fnum("rating_sr_floor") {
        if v.is_finite() && v > 0.0 {
            rc.rating_sr_floor = v.clamp(1e-3, 1.0);
        }
    }
    if let Some(v) = flag("serve_stale") {
        rc.serve_stale = v;
    }
    if let Some(v) = fnum("stale_ttl") {
        rc.stale_ttl = v;
    }

    /* ---- 熔断 ---- */
    // 页面（v1.9.162 契约）写 circuit_fails/circuit_open_s，旧键 cb_* 仍兼容。
    if let Some(v) = num("circuit_fails").or_else(|| num("cb_fails")) {
        rc.circuit_fails = v as u32;
    }
    if let Some(v) = fnum("circuit_open_s").or_else(|| fnum("cb_open_s")) {
        rc.circuit_open_s = v;
    }
    // 2.1.8 优化项 5：指数退避封顶（不得小于首次窗口，否则退化为固定窗口）。
    if let Some(v) = fnum("circuit_open_max_s") {
        rc.circuit_open_max_s = if v.is_finite() && v > 0.0 { v } else { 120.0 };
    }

    /* ---- 2.1.8 数据面自适应（优化项 2/3/4） ---- */
    if let Some(v) = num("probe_timeout_ms") {
        rc.probe_timeout_ms = v;
    }
    if let Some(v) = flag("adaptive_parallel") {
        rc.adaptive_parallel = v;
    }
    if let Some(v) = num("hedge_after_ms") {
        rc.hedge_after_ms = v.max(1);
    }
    // 2.1.11 优化项 3：逐上游 p90 对冲因子（非法/非有限/<=0 → 保持默认 1.0）。
    if let Some(v) = fnum("hedge_slowest_factor") {
        if v.is_finite() && v > 0.0 {
            rc.hedge_slowest_factor = v;
        }
    }
    if let Some(v) = flag("adaptive_timeout") {
        rc.adaptive_timeout = v;
    }
    if let Some(v) = fnum("adaptive_timeout_k") {
        rc.adaptive_timeout_k = if v.is_finite() && v > 0.0 { v } else { 5.0 };
    }
    if let Some(v) = num("adaptive_timeout_min_ms") {
        rc.adaptive_timeout_min_ms = v.max(1);
    }

    /* ---- EDNS / 投毒防护 ---- */
    if let Some(v) = num("edns_udp_size") {
        rc.edns_udp_size = v as u32;
    }
    if let Some(v) = num("edns_client_max_size") {
        rc.edns_client_max_size = v as u16;
    }
    if let Some(v) = cfg.get("edns_client_subnet").and_then(Value::as_str) {
        rc.edns_client_subnet = if v.trim().is_empty() {
            None
        } else {
            Some(v.trim().to_string())
        };
    }
    if let Some(v) = flag("padding") {
        rc.padding = v;
    }
    if let Some(v) = flag("dnssec_0x20") {
        rc.dnssec_0x20 = v;
    }
    // **2.1.43-B（P2-7）**：`cache_direct_enabled` 是**保留键，当前无效果**
    // （不门禁任何行为/计数）；这里仍解析它，只为把值原样回显到 `/api/config` 与
    // `/api/pipeline`（config.json 契约）。删除键会让用户存量配置与键集门禁同时漂移。
    #[allow(deprecated)]
    if let Some(v) = flag("cache_direct_enabled") {
        rc.cache_direct_enabled = v;
    }

    /* ---- 健康检查 ---- */
    if let Some(v) = num("health_check_interval") {
        rc.health_check_interval = v;
    }
    if let Some(v) = cfg.get("health_probe_domain").and_then(Value::as_str) {
        if !v.trim().is_empty() {
            rc.health_probe_domain = v.trim().to_string();
        }
    }
    if let Some(v) = num("health_probe_timeout_ms") {
        rc.health_probe_timeout_ms = v;
    }
    if let Some(v) = num("rule_sub_interval") {
        rc.rule_sub_interval = v;
    }

    /* ---- 候选 IP 测速 ---- */
    if let Some(v) = num("speed_interval_ms") {
        rc.speed_interval_ms = v;
    }
    if let Some(v) = num("speed_timeout_ms") {
        rc.speed_timeout_ms = v;
    }
    if let Some(v) = flag("ip_speed_check") {
        rc.ip_speed_check = v;
    }
    if let Some(v) = cfg.get("ip_speed_probe").and_then(Value::as_str) {
        // 页面词表：both / udp53 / tcp443；其余值（含地址形态）回退 both。
        rc.ip_speed_probe = match v.trim().to_ascii_lowercase().as_str() {
            "udp53" | "udp" => "udp53".to_string(),
            "tcp443" | "tcp" => "tcp443".to_string(),
            _ => "both".to_string(),
        };
    }
    if let Some(v) = num("ip_speed_cache_ttl") {
        rc.ip_speed_cache_ttl = v as u32;
    }

    /* ---- bootstrap DNS ---- */
    // 兼容字符串（"1.2.3.4:53"）与数组（["1.2.3.4", ...]）两种形状；无端口补 53。
    if let Some(v) = cfg.get("bootstrap_dns") {
        let text = match v {
            Value::String(s) => s.clone(),
            Value::Array(a) => a
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" "),
            _ => String::new(),
        };
        if let Some(first) = text
            .split([' ', ',', ';'])
            .map(str::trim)
            .find(|s| !s.is_empty())
        {
            rc.bootstrap_dns = if first.contains(':') {
                first.to_string()
            } else {
                format!("{first}:53")
            };
        }
    }

    /* ---- 规则订阅 URL 列表 ---- */
    if let Some(arr) = cfg.get("rule_subscriptions").and_then(Value::as_array) {
        rc.subscriptions = arr
            .iter()
            .filter_map(|s| {
                s.get("url")
                    .and_then(Value::as_str)
                    .or_else(|| s.as_str())
                    .map(String::from)
            })
            .filter(|s| !s.trim().is_empty())
            .collect();
    }

    /* ---- upstreams ---- */
    // 键名兼容：v1.9.162 用 `addr`，2.0 模板用 `host`；两者都接受（addr 优先）。
    if let Some(arr) = cfg.get("upstreams").and_then(Value::as_array) {
        rc.upstreams = arr
            .iter()
            .filter_map(|u| {
                let obj = u.as_object()?;
                let host = obj
                    .get("host")
                    .and_then(Value::as_str)
                    .or_else(|| obj.get("addr").and_then(Value::as_str))
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if host.is_empty() {
                    return None;
                }
                let proto = obj
                    .get("proto")
                    .and_then(Value::as_str)
                    .unwrap_or("udp")
                    .trim()
                    .to_ascii_lowercase();
                // 端口：数字或数字字符串；缺省按协议给默认值（与 1.9.162 一致）。
                let port = obj
                    .get("port")
                    .and_then(v_u64)
                    .map(|p| p.clamp(1, 65535) as u16)
                    .unwrap_or(match proto.as_str() {
                        "doh" | "doh3" => 443,
                        "dot" | "doq" => 853,
                        _ => 53,
                    });
                Some(ebpdns_resolver::config::UpstreamCfg {
                    id: obj
                        .get("id")
                        .and_then(Value::as_str)
                        .unwrap_or(&host)
                        .to_string(),
                    name: obj
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or(&host)
                        .to_string(),
                    proto,
                    host,
                    port,
                    // DoH/DoH3 请求路径（config.json 的 `url`）。此前该字段**未读取**，
                    // 由 production 侧重建（且重建成了完整 URL）→ 见 request_path 说明。
                    url: obj
                        .get("url")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .trim()
                        .to_string(),
                    enabled: obj.get("enabled").and_then(v_bool).unwrap_or(true),
                    latency: obj.get("latency").and_then(v_u64).unwrap_or(5000) as u32,
                    weight: obj.get("weight").and_then(v_f64).unwrap_or(1.0),
                    group: obj.get("group").and_then(Value::as_str).map(String::from),
                    allow_private_ip: obj
                        .get("allow_private_ip")
                        .and_then(v_bool)
                        .unwrap_or(false),
                })
            })
            .collect();
    }

    // P3 fix: upstream empty warning
    if cfg.get("upstreams").and_then(Value::as_array).is_some() && rc.upstreams.is_empty() {
        eprintln!("WARNING: upstreams configured but all skipped - check host/addr field");
    }

    /* ---- rules ---- */
    // 键名兼容：2.0 内部/落盘用 `match_raw`（`config.json` 的 rules[] 就是它），
    // v1.9.162 与前端用 `match`，更早的旧版用 `pattern`。
    //
    // 缺陷（P0）：此前这里只把 `match` 复制成 `match_raw`，而 `rule_from_json`
    // 读的是 `match`（`normalize_rule` 只认 `pattern`→`match`）→ 磁盘上带
    // `match_raw` 的规则条目**全部解析失败被丢弃**，`Resolver::reload()` 于是把
    // 规则索引重建为空（连 101146 条订阅规则一起丢）：实测 `POST /api/reload`
    // 后 `pipeline.rules` 101147 → 0、`status.rule_hits` 不再增长。
    // 这里统一归一到 `match`，`normalize_rule` 侧也接受 `match_raw`（双保险）。
    if let Some(arr) = cfg.get("rules").and_then(Value::as_array) {
        rc.rules = arr
            .iter()
            .filter_map(|r| {
                let mut m = r.as_object()?.clone();
                let has_match = m
                    .get("match")
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.is_empty());
                if !has_match {
                    let alt = ["match_raw", "pattern"].iter().find_map(|k| {
                        m.get(*k)
                            .and_then(Value::as_str)
                            .filter(|s| !s.is_empty())
                            .map(str::to_string)
                    });
                    if let Some(v) = alt {
                        m.insert("match".into(), Value::String(v));
                    }
                }
                rule_from_json(m, RuleSource::Local)
            })
            .collect();
    }
}

/* ---------------- 缓存落盘 ---------------- */

/// **2.1.16（修复项 4）：崩溃安全的原子写。**
///
/// `write → fsync(file) → rename → fsync(dir)` 四步，缺一不可：
/// - 只 `write` 不 `fsync`：数据还在 page cache 里，`kill -9`（或断电）后
///   **rename 已生效但 tmp 内容未落盘** → 目标文件变成 0 字节 / 半截 JSON。
///   这正是 2.1.15 实测"重启后 `cache.json` 解析失败、缓存整表丢失"的机理。
/// - `rename` 后不 `fsync(dir)`：目录项本身未持久化，崩溃后可能回到旧文件名
///   （旧文件已被 rename 覆盖 → 两个名字都指不到内容）。
///
/// 返回 `Err` 时**目标文件保持原样**（rename 是原子的），绝不会出现半截文件。
pub fn write_json_atomic(path: &std::path::Path, body: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    write_json_atomic_with(path, |w| w.write_all(body))
}

/// **2.1.25（B8 性能项）**：[`write_json_atomic`] 的**流式**版本 —— 四步语义
/// （`write → fsync(file) → rename → fsync(dir)`）逐字不变，只是内容由回调**分块**
/// 写进 64 KiB 的 `BufWriter`，因此调用方**不必**先把整份 JSON 拼进一个 `Vec<u8>`。
///
/// 崩溃安全的那条不变式完全依赖本函数（回调只影响"写什么字节"，不影响
/// "什么时候 fsync / rename"）：回调返回 `Err` ⇒ **不 rename**，目标文件保持原样，
/// 半截的 `.tmp` 会被下次启动的 `startup_cleanup` 清掉。
pub fn write_json_atomic_with<F>(path: &std::path::Path, body: F) -> std::io::Result<()>
where
    F: FnOnce(&mut std::io::BufWriter<std::fs::File>) -> std::io::Result<()>,
{
    // **2.1.36（D 批）**：四步协议由 `ebpdns-fs` 唯一实现；这里只固定
    // `config.json.tmp` 命名（逐字保留）与"失败保留 tmp（由启动清理回收）"。
    ebpdns_fs::atomic_write_with(path, &ebpdns_fs::WriteOptions::json_tmp(), body)
}

/// **2.1.29**：v1 JSON 恢复（**逐字保留** 2.1.28 的 `restore_cache`，作为回退/对拍与
/// `EBPDNS_CACHE_FORMAT=v1` 紧急回滚路径；v2 稳态不调用它）。
pub(crate) async fn restore_cache_v1(
    resolver: &Arc<Resolver>,
    path: &std::path::Path,
    persist_ttl: f64,
) {
    // 文件 IO 放 spawn_blocking，不阻塞 async runtime。
    let path_owned = path.to_path_buf();
    let read = tokio::task::spawn_blocking(move || std::fs::read_to_string(&path_owned)).await;
    let s = match read {
        Ok(Ok(s)) => s,
        // **2.1.18（修复项 10）**：**不再静默**。用户实测"重启缓存全丢"时，
        // 老实现无论"文件不存在""权限拒绝""内容损坏"都是**同一个静默 return**，
        // 于是排障时看不到任何线索。现在三态分开：
        //   ① 文件不存在（首次启动/从未落盘）→ info（正常）；
        //   ② 读失败（权限/IO）→ **ERROR**（这就是"重启丢缓存"最可能的原因）；
        //   ③ JSON 解析失败 → **ERROR**（文件损坏 / 半截写）。
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            // **2.1.19（修复项 1 补漏）**："文件不存在"是**正常首启**，但同样必须把
            // 丢弃计数**重置为本次值**（0,0,0）—— 否则上一次启动的文件级失败会残留，
            // 让本次的 `/api/status.cache.restore_drops` 显示上一次的 `failed`。
            resolver.cache().clear_file_level();
            tracing::info!(
                "缓存文件不存在（首次启动或从未落盘）：{}（cache_persist=true 时退出会写入）",
                path.display()
            );
            return;
        }
        Ok(Err(e)) => {
            // **2.1.19（修复项 1 补漏）**：读失败同样是"本次恢复没有恢复任何条目" ⇒
            // 记录到 `failed`（至少 1）并补一条 WARN（ERROR 保留）。
            resolver.cache().record_file_level_failure(1);
            tracing::error!(
                "**缓存恢复失败（读文件）**：{} —— {e}。请检查 cache_file 路径与运行用户权限\
                 （systemd 需 ReadWritePaths 覆盖该目录）；本次启动缓存为空",
                path.display()
            );
            tracing::warn!(
                dropped_failed = 1,
                "缓存恢复失败（读文件）：本次**一条都未恢复** ⇒ \
                 `/api/status.cache.restore_drops.failed` 记为 1（该值反映本次结果，不是上一次的残留）"
            );
            return;
        }
        Err(e) => {
            resolver.cache().record_file_level_failure(1);
            tracing::error!("缓存恢复任务 join 失败：{e}（本次启动缓存为空）");
            tracing::warn!(
                dropped_failed = 1,
                "缓存恢复任务 join 失败：本次**一条都未恢复** ⇒ `restore_drops.failed` 记为 1"
            );
            return;
        }
    };
    let entries = match serde_json::from_str::<Value>(&s) {
        Ok(v) => v,
        Err(e) => {
            // **2.1.19（修复项 1 补漏：部署代理实测的真实缺陷）**：文件级 JSON 损坏
            // 以前**只** `tracing::error!` 后 `return` —— 既不补 WARN，也**不置位
            // `failed`** ⇒ `DnsCache::last_restore_drops()` 保留**上一次 restore 的陈旧
            // 值**，两端点同时显示 `failed: 0`（**说谎**）。实测：截断 JSON
            // `[{"domain":"trunc...","answers":[` ⇒ ERROR=1、WARN=0、两端口
            // `{"expired":0,"failed":0,"legacy":0}`。
            //
            // 现在：①把本次结果写进外壳的文件级记录（`failed >= 1`）；
            //       ②补一条 WARN（含路径与原因），ERROR 保留；
            //       ③`failed` 的单位在这里是"整个文件"，故取 1（per-entry 路径才是条数）。
            resolver.cache().record_file_level_failure(1);
            tracing::error!(
                "**缓存恢复失败（JSON 解析）**：{} —— {e}。文件可能损坏或被截断；\
                 本次启动缓存为空（下次落盘会重写该文件）",
                path.display()
            );
            tracing::warn!(
                dropped_failed = 1,
                path = %path.display(),
                "**整个缓存文件不可解析**（{e}）：本次**一条都未恢复** ⇒ \
                 `/api/status.cache.restore_drops.failed` 与 `/api/cache/stats.restore_drops.failed` \
                 都会显示 1（此前它们会显示 0 —— 那是上一次 restore 的陈旧值，属说谎）。\
                 文件会被下一次落盘整体重写。"
            );
            return;
        }
    };
    // **2.1.19（修复项 1 补漏）**：JSON 合法但**顶层不是数组**（例如被写成对象/null）
    // 同样是"文件不可用" —— 以前 `unwrap_or_default()` 会静默变成空数组，于是
    // `restore(&[])` 把计数清零并**报告 0 丢弃**（又一次说谎）。现在显式判定。
    let Some(arr) = entries.as_array().cloned() else {
        resolver.cache().record_file_level_failure(1);
        // 形状名用 `is_*` 判定（避免在本作用域里再命名 `serde_json::Value`）。
        let shape = if entries.is_object() {
            "object"
        } else if entries.is_null() {
            "null"
        } else if entries.is_boolean() {
            "bool"
        } else if entries.is_number() {
            "number"
        } else if entries.is_string() {
            "string"
        } else {
            "array"
        };
        tracing::error!(
            "**缓存恢复失败（形状不对）**：{} 的顶层不是 JSON 数组（实为 {}）；\
             本次启动缓存为空（下次落盘会重写该文件）",
            path.display(),
            shape
        );
        tracing::warn!(
            dropped_failed = 1,
            path = %path.display(),
            "**缓存文件顶层不是数组**：本次**一条都未恢复** ⇒ `restore_drops.failed` 记为 1\
             （此前会被静默当成空数组 ⇒ 显示 0，属说谎）"
        );
        return;
    };
    let now = ebpdns_server::telemetry::now_epoch();
    resolver.cache().restore(&arr, now, persist_ttl);
    // **2.1.19（修复项 1）**：把**策略无关**的丢弃计数一并打进"缓存已恢复"这条日志。
    //
    // 为什么必须在这里再打一遍（`lru.rs` / `tinylfu.rs` 内部已经各打一条 WARN）：
    //   ① 内部 WARN 的措辞（`cache.restore:` / `TinyLFU.restore:`）随策略而变，脚本/
    //      运维要按 `cache_policy` 猜前缀；这里给出**统一字段名**，三条策略一致；
    //   ② `last_restore_drops()` 是 trait 方法 ⇒ 无论 `lru` / `partitioned` / `tinylfu`
    //      （含热切换外壳）都有值，2.1.19 只有 `LruCache` 有 ⇒ 生产默认 `tinylfu`
    //      路径**观测不到**；
    //   ③ 字段直接在**同一条** `缓存已恢复` 记录里 ⇒ 抓一条日志就能自证
    //      "旧格式被丢弃了多少条"，不需要扫多行。
    let (dropped_expired, dropped_legacy, dropped_failed) = resolver.cache().last_restore_drops();
    // **2.1.18（修复项 23）**：日志按**实际** `persist_ttl` 分叉 —— 旧实现无论取值都打印
    // "（persist_ttl=0 表示只按条目剩余 TTL 承接）"，与运行态不符（部署代理实测：
    // `persist_ttl=3600` 时仍打印这句，误导排查）。
    if persist_ttl > 0.0 {
        tracing::info!(
            count = arr.len(),
            persist_ttl = persist_ttl,
            dropped_expired = dropped_expired,
            dropped_legacy = dropped_legacy,
            dropped_failed = dropped_failed,
            "缓存已恢复: {}（**opt-in 统一 TTL**：恢复条目一律用 {}s 重新计时，可能超过原 TTL \
             —— 见 README「缓存持久化」）",
            path.display(),
            persist_ttl
        );
    } else {
        tracing::info!(
            count = arr.len(),
            persist_ttl = persist_ttl,
            dropped_expired = dropped_expired,
            dropped_legacy = dropped_legacy,
            dropped_failed = dropped_failed,
            "缓存已恢复: {}（persist_ttl=0：严格遵守文件里的**绝对到期时间**，停机时长计入 \
             TTL，已过期条目已丢弃）",
            path.display()
        );
    }
    // **2.1.19（修复项 1）**：只要真有旧格式记录被丢弃，这里**必定**再打一条 WARN
    // （与策略内部那条互为冗余 —— 冗余是刻意的：这条不依赖任何策略实现的自律）。
    if dropped_legacy > 0 {
        tracing::warn!(
            dropped_legacy = dropped_legacy,
            "**缓存文件是旧格式**：已按安全侧丢弃 {} 条（缺少绝对 `expires_at`，只有 \
             `remaining`）。这是**符合预期**的行为（旧条目不会被复活）；下一次落盘会写成新格式。",
            dropped_legacy
        );
    }
}

/// **2.1.29**：v1 全量 JSON 落盘（**逐字保留** 2.1.28 的 `save_cache`；v2 稳态不调用，
/// 只在 `EBPDNS_CACHE_FORMAT=v1` 紧急回滚模式或迁移失败时生效）。
pub(crate) async fn save_cache_v1(resolver: &Arc<Resolver>, path: &std::path::Path) {
    let now = ebpdns_server::telemetry::now_epoch();
    let path_owned = path.to_path_buf();
    let path_for_log = path.to_path_buf();
    // **2.1.25（B8 性能项：分块流式落盘）**
    //
    // 2.1.24 的实现分两步，**两步都在 async 线程上**做前半段：
    //   ① `resolver.cache().serialize(now)` —— 把**整表**建成 `Vec<Value>`
    //      （每条约 6 键的 `Map` + 若干 `String`），全程**持有缓存锁**；
    //   ② `serde_json::to_vec_pretty(&entries)` —— 再生成**整块** `Vec<u8>`；
    //   ③ 只有"把 body 写文件"这一步在 `spawn_blocking` 里。
    // 于是峰值内存 ≈ 表大小 × (Value 树 + 文本)，而且 ①② 直接占着 tokio 工作线程
    // 与缓存锁（周期落盘时数据面会让路）。
    //
    // 现在：整段搬进 `spawn_blocking`，内容由 `write_snapshot` **逐条**产出、
    // 经 64 KiB `BufWriter` 落盘 ⇒ 峰值内存 O(1)，async 工作线程不再参与序列化。
    // **磁盘字节与 2.1.24 逐字节相同**（`write_snapshot` 的契约，有单测钉死），
    // 崩溃安全窗口也相同（同一个 `write → fsync(file) → rename → fsync(dir)`，
    // 失败时不 rename、目标文件保持原样）。
    let cache = resolver.cache_arc();
    let res = tokio::task::spawn_blocking(move || {
        let mut wrote = 0u64;
        write_json_atomic_with(&path_owned, |w| {
            wrote = cache.write_snapshot(now, w)?;
            Ok(())
        })
        .map(|()| wrote)
    })
    .await;
    match res {
        Ok(Ok(n)) => tracing::info!(
            entries = n,
            "缓存已落盘（fsync 原子写）: {}",
            path.display()
        ),
        // **2.1.18（修复项 10）**：落盘失败以前是 `warn` —— 用户看到"重启后缓存没了"
        // 却在 journal 里搜不到 ERROR。现在**升级为 ERROR** 并给出排查点。
        Ok(Err(e)) => tracing::error!(
            "**缓存落盘失败**：{} —— {e}。请检查目录是否存在、运行用户是否有写权限\
             （systemd 需 `ReadWritePaths` 覆盖该目录）、磁盘是否已满",
            path_for_log.display()
        ),
        Err(e) => tracing::error!("缓存落盘任务 join 失败：{e}（缓存未写入磁盘）"),
    }
}

/* ---------------- tracing ---------------- */

/// 等待 SIGINT 或 SIGTERM（对齐 cli.py 信号优雅退出）。
#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                "无法安装 SIGTERM 信号处理器: {e}（可能 fd 耗尽），服务继续运行但将无法优雅退出"
            );
            // **2.1.24**：`loop {}` 会被 `clippy::empty_loop` 告警（建议 `sleep` 或 `panic!`）。
            // 这里**必须**"永久挂起"而不是 panic / 空转：`shutdown_signal()` 是被
            // `tokio::select!` 等待的 future，只要它永不完成，服务就继续运行（这正是
            // "信号处理器装不上 ⇒ 不能优雅退出"的语义）。用 `pending()` 表达同一语义，
            // 且**不占 CPU**（`loop {}` 在单线程 executor 上会空转）。
            std::future::pending::<tokio::signal::unix::Signal>().await
        }
    };
    let mut int = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                "无法安装 SIGINT 信号处理器: {e}（可能 fd 耗尽），服务继续运行但将无法优雅退出"
            );
            // 同上：永久挂起但不空转。
            std::future::pending::<tokio::signal::unix::Signal>().await
        }
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

/// **2.1.20（A-01）**：日志级别的来源与取值（**纯函数**，可单测）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogLevelSource {
    /// `--log-level`（CLI，最高优先级）。
    Cli,
    /// `RUST_LOG` 环境变量。
    Env,
    /// 配置文件 `log_level`。
    Config,
    /// 内置默认 `info`。
    Default,
}

/// **2.1.20（A-01 修复）**：按**声明的**优先级选出日志级别：`CLI > 环境 > 配置 > 默认`。
///
/// 返回 `(来源, 取值)`，调用方把它交给 [`init_tracing`]。
/// 抽成纯函数是为了**可断言**：2.1.19 的反向回归（有配置键 ⇒ `RUST_LOG` 失效）
/// 正是"优先级只在注释里、没有任何单测"造成的。
fn pick_log_level(
    cli: Option<&str>,
    env: Option<&str>,
    cfg: Option<&str>,
) -> (LogLevelSource, String) {
    let nonempty = |s: Option<&str>| {
        s.map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
    };
    if let Some(v) = nonempty(cli) {
        return (LogLevelSource::Cli, v);
    }
    if let Some(v) = nonempty(env) {
        return (LogLevelSource::Env, v);
    }
    if let Some(v) = nonempty(cfg) {
        return (LogLevelSource::Config, v);
    }
    (LogLevelSource::Default, "info".to_string())
}

/// **2.1.19（F-08）/ 2.1.20（A-01）**：初始化 tracing。
///
/// 优先级（**与 `pick_log_level` 和 README 完全一致**）：`--log-level`（CLI）>
/// `RUST_LOG`（环境）> 配置文件 `log_level` > 内置默认 `info`；`log_format` 同理
/// （`--log-format` > 配置 `log_format` > 内置默认 `plain`）。
///
/// **2.1.19 的反向回归（A-01，已修）**：那一版写成
/// `args.log_level.or(cfg_log_level)` + `Some(l) => EnvFilter::new(l)` ⇒
/// **只要配置文件里有 `log_level`（出厂模板恒有 `"info"`）`RUST_LOG` 就完全失效**。
/// 现在级别由 [`pick_log_level`] 决定并把来源打进启动日志，便于现场核对。
fn init_tracing(level: &str, src: LogLevelSource, fmt: Option<LogFormat>) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::new(level);
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    match fmt {
        Some(LogFormat::Json) => builder.json().init(),
        _ => builder.init(),
    }
    tracing::info!(
        level = level,
        source = ?src,
        "ebpdns v{VERSION} 启动（日志级别来源：CLI > RUST_LOG > 配置 log_level > 默认 info）"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /* ===================================================================== */
    /* 2.1.23 · DEF-222-02（P0）：配置不可信 ⇒ 禁止落到默认生产 state_dir     */
    /* ===================================================================== */

    /// 一个**只属于本测试**的临时目录。
    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "ebpdns-p023-{tag}-{}-{}",
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

    /// **DEF-222-02**：`load_config` 必须**区分**"读到文件"与"文件坏了"。
    ///
    /// 2.1.22 只有一条 WARN + 默认配置，返回类型里**没有**任何东西能表达"这份配置
    /// 不可信" ⇒ 调用方无从 fail-closed。
    #[test]
    fn def222_02_load_config_reports_a_broken_file_as_broken() {
        let d = tmp_dir("cfgload");
        // ① 截断 JSON ⇒ FileBroken（不是"用默认值就完事"）。
        let broken = d.join("broken.json");
        std::fs::write(&broken, br#"{"api":"#).unwrap();
        let l = load_config(Some(&broken));
        assert_eq!(
            l.origin,
            ConfigOrigin::FileBroken,
            "截断的 config.json 必须是 FileBroken（2.1.22 只打 WARN 就当没事）"
        );
        // ② 显式给了 `--config` 但文件不存在 ⇒ 同样不可信（用户以为在读它）。
        let missing = d.join("nope.json");
        assert_eq!(load_config(Some(&missing)).origin, ConfigOrigin::FileBroken);
        // ③ 完全没有 `--config` ⇒ 全新安装（合法用默认值）。
        assert_eq!(load_config(None).origin, ConfigOrigin::NoFileFresh);
        // ④ 合法文件 ⇒ FileOk，且值就是文件里的（没有被默认值覆盖）。
        let good = d.join("good.json");
        std::fs::write(&good, br#"{"cache_size": 12345}"#).unwrap();
        let l = load_config(Some(&good));
        assert_eq!(l.origin, ConfigOrigin::FileOk);
        assert_eq!(l.cfg["cache_size"], json!(12345));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// **DEF-222-02**：配置不可信时**不得**占用"已有 `commit.json`"的目录（= 别人的状态目录）。
    #[test]
    fn def222_02_config_unusable_must_not_fall_back_to_a_live_state_dir() {
        let d = tmp_dir("statedir");
        let live = d.join("state");
        std::fs::create_dir_all(&live).unwrap();
        // "别人的状态目录"：里面有提交点。
        std::fs::write(live.join("commit.json"), b"{}").unwrap();

        // ① 显式给出目录 ⇒ 一律用它（哪怕配置不可信）。
        let got = main_state::resolve_state_dir_checked(
            &json!({}),
            Some(live.as_path()),
            main_state::StateDirOrigin::ConfigUnusable,
        )
        .expect("显式 --state-dir 必须无条件生效");
        assert_eq!(got, live);

        // ② 配置里**真的**给了 `state_dir` ⇒ 也是显式来源，用它。
        let got = main_state::resolve_state_dir_checked(
            &json!({"state_dir": live.display().to_string()}),
            None,
            main_state::StateDirOrigin::ConfigUnusable,
        )
        .expect("配置里给了 state_dir（且解析成功）⇒ 用它");
        assert_eq!(got, live);

        // ③ 配置不可信 + **没有**任何显式目录 + 默认目录里**已有** commit.json
        //    ⇒ **必须报错**（这正是审计实测的"隔离实例写生产状态目录"路径）。
        //
        // 用一个**临时**默认目录做不到（默认是写死的 `/var/lib/ebpdns/state`），
        // 因此这里直接针对真实默认路径断言"该判据存在且按 commit.json 是否存在开关"：
        // 若真实默认目录存在提交点，就必须报错；否则允许（全新安装）。
        let dflt = PathBuf::from(main_state::DEFAULT_STATE_DIR);
        let res = main_state::resolve_state_dir_checked(
            &json!({}),
            None,
            main_state::StateDirOrigin::ConfigUnusable,
        );
        if dflt.join("commit.json").exists() {
            let e = res.expect_err(
                "默认目录里已有提交点（= 别人的状态目录）时，配置不可信**必须**拒绝使用它",
            );
            assert!(
                e.reason.contains("commit.json") && e.reason.contains("拒绝"),
                "错误信息必须点名原因与结论：{}",
                e.reason
            );
        } else {
            assert_eq!(res.expect("无既有提交点 ⇒ 允许用默认值"), dflt);
        }

        // ④ 配置可信（`FileOk`）⇒ 即便默认目录里有提交点，也允许（单机单实例的正常重启）。
        assert_eq!(
            main_state::resolve_state_dir_checked(
                &json!({}),
                None,
                main_state::StateDirOrigin::Explicit
            )
            .expect("配置可信 ⇒ 允许默认值"),
            dflt
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /* ===================================================================== */
    /* 2.1.23 · DEF-222-03（P0）：state/ 独占 + 归属校验                      */
    /* ===================================================================== */

    /// **DEF-222-03 ①**：`state/.lock` 真的被 **`flock` 独占** ——
    /// 用**第二个 `fd`**（绕开进程内短路）验证"别人拿不到"。
    #[cfg(unix)]
    #[test]
    fn def222_03_state_lock_is_really_exclusive_at_the_fd_level() {
        use std::os::unix::io::AsRawFd;
        let d = tmp_dir("lock");
        let l = main_state::acquire_state_lock(&d).expect("首次取锁必须成功");
        let lp = l.path().to_path_buf();
        assert!(lp.is_file(), "锁文件必须被创建：{}", lp.display());
        let body = std::fs::read_to_string(&lp).unwrap_or_default();
        assert!(
            body.contains("pid=") && body.contains("host="),
            "锁文件必须写下持有者身份（pid/host）供诊断：{body:?}"
        );

        // 第二个 fd（**不是**进程内那条短路路径）必须拿不到 ⇒ 证明 flock 真的生效。
        let f2 = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lp)
            .expect("open lock");
        // 帮助函数内部已经 `unsafe`（`flock` 是 libc 调用）；这里不再套一层。
        let rc = main_state::test_flock_nonblocking(f2.as_raw_fd());
        assert_ne!(
            rc, 0,
            "同一把 `state/.lock` 的第二个 fd **必须**取锁失败（否则独占保护形同虚设）"
        );
        drop(f2);
        drop(l);
        // 释放之后必须又能取到（`flock` 在 fd 关闭时自动释放 ⇒ 不留"陈尸锁"）。
        let again = main_state::acquire_state_lock(&d).expect("释放后必须能重新取锁");
        drop(again);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// **DEF-222-03 ②**：`commit.json` 的 parts **不含**本实例 `cfg_path` ⇒ 判定"不是我的"。
    ///
    /// 这条挡的是 `flock` 挡不住的那一半：上一次是**别的实例**留下的状态目录
    ///（进程已退出、锁已释放，但提交点记的是别人的路径）。
    #[test]
    fn def222_03_commit_point_must_contain_our_own_cfg_path() {
        let d = tmp_dir("own");
        let state = d.join("state");
        std::fs::create_dir_all(&state).unwrap();
        let other_cfg = d.join("other").join("config.json");
        std::fs::create_dir_all(other_cfg.parent().unwrap()).unwrap();
        let mine = d.join("etc").join("config.json");
        std::fs::create_dir_all(mine.parent().unwrap()).unwrap();

        let store = ebpdns_server::StateStore::open(&state, 2).expect("open");
        // 提交一份**只含别人 cfg_path** 的 part 集合。
        let mut plan = std::collections::BTreeMap::new();
        plan.insert(other_cfg.clone(), b"{}".to_vec());
        store
            .commit(&plan, "other-instance", 1000, 1)
            .expect("commit");

        // 用**我的** cfg_path 去对 ⇒ 必须不符（这就是"别人的状态目录"）。
        let e = main_state::commit_matches_own_cfg_path(&store, Some(&mine))
            .expect_err("提交点里没有本实例的 cfg_path ⇒ 必须判定不匹配");
        assert!(
            e.contains("另一个实例") && e.contains(&mine.to_string_lossy().to_string()),
            "错误信息必须点名『这是别人的状态目录』并给出判据：{e}"
        );
        // 用**它记录的**那个路径去对 ⇒ 匹配（说明判据不是"永远报错"）。
        main_state::commit_matches_own_cfg_path(&store, Some(&other_cfg))
            .expect("提交点里含该 cfg_path ⇒ 必须匹配");
        // 无提交点（Legacy）⇒ 不判定（交给迁移）。
        let empty_state = d.join("state2");
        let s2 = ebpdns_server::StateStore::open(&empty_state, 2).expect("open2");
        main_state::commit_matches_own_cfg_path(&s2, Some(&mine))
            .expect("没有提交点 ⇒ 无法判定，必须放行（Legacy 走迁移）");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// F28：`web_root` 取值优先级单测在 `ebpdns_server::state`（`static_root_of`，
    /// 启动注入与热重载告警共用实现）；这里只锁死本文件依赖的默认值口径。
    #[test]
    fn default_config_has_empty_web_root() {
        assert_eq!(default_config().get("web_root"), Some(&json!("")));
        // 默认配置 → 无外部磁盘根（发布包走嵌入资源）。
        assert_eq!(
            ebpdns_server::state::static_root_of(&default_config(), None),
            None
        );
    }

    /// **2.1.18（修复项 7）**：`default_config()` 的顶层键集必须与
    /// [`ebpdns_resolver::config::CONFIG_TOP_LEVEL_KEYS`]（**规范键集**）
    /// **逐键相等**。
    ///
    /// 为什么需要它：那份规范键集是"可写 / 只读"划分完备性门禁的参照物
    /// （见 `ebpdns-server` 的 `cfg_writable_covers_all_default_top_level_keys`）。
    /// 若新增配置键却忘了同步它，控制台可达性门禁就会**漏判** —— 本测试把
    /// "加键必须同时更新规范键集"变成硬约束。
    #[test]
    fn config_top_level_keys_are_a_superset_of_default_config() {
        use std::collections::BTreeSet;
        let dft = default_config();
        let actual: BTreeSet<String> = dft
            .as_object()
            .expect("default_config 必须是对象")
            .keys()
            .cloned()
            .collect();
        let spec: BTreeSet<String> = ebpdns_resolver::config::CONFIG_TOP_LEVEL_KEYS
            .iter()
            .map(|s| s.to_string())
            .collect();
        // ① 规范键集必须**包含** `default_config()` 的全部键（不漏键）。
        let missing: Vec<&String> = actual.difference(&spec).collect();
        assert!(
            missing.is_empty(),
            "default_config() 有而规范键集没有（漏登记 ⇒ 控制台可达性门禁会漏判）：{missing:?}"
        );
        // ② 规范键集里"多出来"的键必须**只能是**以下两类：
        //    ① 运行期注入的路径键（不进 `default_config()`，归只读桶）；
        //    ② **历史别名**（`apply_cfg` 真的读，但与权威名同义 ⇒ 不能同时出现在
        //       出厂配置里，否则同一状态有两个键、读写分叉）。
        //
        // **2.1.20（A-12）**：`cb_fails` / `cb_open_s`（`circuit_*` 的别名）与
        // `warmup_enabled` / `warmup_queries` / `warmup_timeout_ms`（`warmup.*` 对象的
        // 扁平别名）属第 ② 类 —— 它们此前连规范键集都没有，于是被报"未知键"。
        let allowed_extra = [
            "rule_local_file",
            "rule_sub_file",
            "cache_file",
            "cb_fails",
            "cb_open_s",
            "warmup_enabled",
            "warmup_queries",
            "warmup_timeout_ms",
        ];
        let extra: Vec<&String> = spec.difference(&actual).collect();
        let unexpected: Vec<&&String> = extra
            .iter()
            .filter(|k| !allowed_extra.contains(&k.as_str()))
            .collect();
        assert!(
            unexpected.is_empty(),
            "规范键集含既不在 default_config() 也不在允许的运行期注入键里的键：{unexpected:?}"
        );
    }

    /* ---------- 预配置（DoH/DoH3 服务器清单）契约 ---------- */
    /// 逐键 diff：`assert_eq!` 对 `Value` 的 Debug 输出是整块 JSON，真出现漂移时读不出
    /// 改了哪个键。这里给出「配置路径 → 两边取值」的可读清单。
    fn value_diffs(path: &str, a: &Value, b: &Value, out: &mut Vec<String>) {
        match (a, b) {
            (Value::Object(ma), Value::Object(mb)) => {
                for (k, va) in ma {
                    match mb.get(k) {
                        Some(vb) => value_diffs(&format!("{path}.{k}"), va, vb, out),
                        None => out.push(format!("{path}.{k}: 仅 default_config() 有 = {va}")),
                    }
                }
                for (k, vb) in mb {
                    if !ma.contains_key(k) {
                        out.push(format!("{path}.{k}: 仅打包模板有 = {vb}"));
                    }
                }
            }
            (Value::Array(xa), Value::Array(xb)) => {
                if xa.len() != xb.len() {
                    out.push(format!("{path}: 数组长度 {} vs {}", xa.len(), xb.len()));
                }
                for (i, (va, vb)) in xa.iter().zip(xb.iter()).enumerate() {
                    value_diffs(&format!("{path}[{i}]"), va, vb, out);
                }
            }
            _ => {
                if a != b {
                    out.push(format!("{path}: {a} vs {b}"));
                }
            }
        }
    }

    /// 预配置上游清单：数量 / 唯一 id / 协议合法 / 组别 / 端口与路径契约。
    ///
    /// 这份清单既是 install.sh 装到 `/etc/ebpdns/config.json` 的内容，也是无配置文件时
    /// 的兜底；任何一条漂移都会让真机行为与「预配置」不一致，故逐字段锁死。
    ///
    /// **2.1.20（A-01）**：日志级别来源优先级必须是 **CLI > `RUST_LOG` > 配置 > 默认**。
    ///
    /// 审计 A-01 实测（2.1.19 的反向回归）：只要配置文件里有 `log_level`（出厂模板恒有
    /// `"info"`），`RUST_LOG=debug` **完全失效**（0 行 DEBUG）；删掉该键才有 1 行。
    /// 根因是把配置值塞进了"CLI 位置"再用 `EnvFilter::new` 直接吃下。
    /// 现在优先级由纯函数 [`pick_log_level`] 决定，本用例逐组钉死。
    #[test]
    fn a01_log_level_priority_is_cli_env_config_default() {
        use LogLevelSource::*;
        // CLI 最高（可覆盖环境与配置）。
        assert_eq!(
            pick_log_level(Some("warn"), Some("debug"), Some("trace")),
            (Cli, "warn".to_string())
        );
        // **关键回归点**：没有 CLI 时，**环境必须压过配置**（2.1.19 在这里反了）。
        assert_eq!(
            pick_log_level(None, Some("debug"), Some("info")),
            (Env, "debug".to_string()),
            "有配置项时 `RUST_LOG` 必须仍然生效（A-01 的反向回归点）"
        );
        // 环境缺失 → 用配置。
        assert_eq!(
            pick_log_level(None, None, Some("debug")),
            (Config, "debug".to_string())
        );
        // 三者皆无 → 内置默认 info。
        assert_eq!(
            pick_log_level(None, None, None),
            (Default, "info".to_string())
        );
        // 空串/空白等同"未提供"（否则空 `RUST_LOG` 会把级别吃成空过滤器）。
        assert_eq!(
            pick_log_level(Some("  "), Some(""), Some("debug")),
            (Config, "debug".to_string())
        );
        assert_eq!(
            pick_log_level(Some(""), Some(""), Some("")),
            (Default, "info".to_string())
        );
    }

    /// **2.1.20（A-03）**：启动期必须把越界整数键**夹取**到权威区间，使
    /// "启动接受的值" ≡ "写路径接受的值"（否则文件里一个坏值会让控制台此后**任何**保存都 400）。
    #[test]
    fn a03_startup_clamps_out_of_range_keys_to_the_authoritative_table() {
        // 审计 A-03 的决定性输入：`ttl=1000000`（后端区间 [0, 604800]）。
        let mut cfg = default_config();
        cfg["ttl"] = json!(1_000_000);
        cfg["cache_size"] = json!(8); // 低于下界 16
        cfg["health_check_interval"] = json!(100_000); // 高于上界 86400
        cfg["speed_interval_ms"] = json!(50); // 低于下界 100
        let fixed = clamp_out_of_range_config(&mut cfg);
        let mut keys: Vec<String> = fixed.iter().map(|(k, _, _)| k.clone()).collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "cache_size",
                "health_check_interval",
                "speed_interval_ms",
                "ttl"
            ],
            "四个越界键都必须被夹取并汇报"
        );
        assert_eq!(cfg["ttl"], json!(604_800));
        assert_eq!(cfg["cache_size"], json!(16));
        assert_eq!(cfg["health_check_interval"], json!(86_400));
        assert_eq!(cfg["speed_interval_ms"], json!(100));
        // **核心不变量**：夹取之后，写路径对**整份配置**不再有任何越界错误
        // ⇒ "启动成功 ⇒ 之后每次保存都能成功"。
        let errs = ebpdns_resolver::config::validate_write(&cfg);
        assert!(
            errs.is_empty(),
            "夹取后整份配置必须能通过写路径校验（否则控制台还是存不进去）：{errs:?}"
        );
        // 反向：合法值必须原样保留（不得误改）。
        let mut ok = default_config();
        ok["ttl"] = json!(300);
        assert!(
            clamp_out_of_range_config(&mut ok).is_empty(),
            "合法配置不得被改动"
        );
        assert_eq!(ok["ttl"], json!(300));
    }

    /// **2.1.20（A-14）**：程序自己注入的规则文件路径（`rule_local_file` / `rule_sub_file`）
    /// 必须在 `check-config` 的**已知键集**里 —— 否则 `check-config` 会对出厂模板报
    /// "未知键"，而这两个键是 `migrate_cfg` 自己写进去的（"自己的键自己不认识"）。
    #[test]
    fn a14_injected_rule_file_keys_are_known() {
        for k in ["rule_local_file", "rule_sub_file"] {
            assert!(
                ebpdns_resolver::config::CONFIG_TOP_LEVEL_KEYS.contains(&k),
                "`{k}` 由 `migrate_cfg` 注入，必须在规范键集里（否则 check-config 报未知键）"
            );
        }
    }

    /// **2.1.19（修复项 4）**：出厂默认上游**必须与用户原文的 22 条逐条一致** ——
    /// 2.1.19 的 24 条里多了 `lan235` / `lan235tcp`（**不在**用户列表里）。
    /// 它们已从 `default_config()` 与 `packaging/etc/ebpdns/config.json` **一并移除**
    /// （用户原文没有站点私有内网上游；把它留在出厂默认里既超出用户列表，
    /// 又让"新装 == 模板 == 默认"这条门禁携带与用户无关的地址）。
    #[test]
    fn default_config_upstreams_contract() {
        let c = default_config();
        let ups = c
            .get("upstreams")
            .and_then(Value::as_array)
            .expect("upstreams 必须是数组");
        assert_eq!(ups.len(), 22, "预配置必须恰好是用户原文的 22 条上游");

        // 取值帮手：**必须**是带显式生命周期的 `fn` 而不是闭包——`|u: &Value, k: &str|`
        // 的返回引用无法与入参生命周期绑定（`error: lifetime may not live long enough`），
        // 会让整个 `cargo test` 在编译期就失败（`ebpdns` bin 的 test target 编不出来）。
        fn s<'a>(u: &'a Value, k: &str) -> &'a str {
            u.get(k).and_then(Value::as_str).unwrap_or("")
        }
        let mut ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut n = [0usize; 4]; // doh3 / doh / udp / tcp
        for u in ups {
            let id = u.get("id").and_then(Value::as_str).expect("id 必须存在");
            assert!(ids.insert(id.to_string()), "id 重复: {id}");
            assert!(!s(u, "name").is_empty(), "{id}: name 不得为空");
            let proto = s(u, "proto");
            n[match proto {
                "doh3" => 0,
                "doh" => 1,
                "udp" => 2,
                "tcp" => 3,
                other => panic!("{id}: 非法 proto {other}"),
            }] += 1;
            let group = s(u, "group");
            assert!(
                group == "domestic" || group == "global",
                "{id}: 非法 group {group}（引擎词表只有 domestic/global）"
            );
            // `host` 是运行期连接目标 + TLS 证书名；`addr` 是 v1.9.162 契约字段名
            // （`/api/reprobe` 与 `/api/upstreams` 优先读它）——两者必须同值，否则
            // 「探针测的」与「解析时用的」会不是同一个地址。
            let host = s(u, "host");
            assert_eq!(host, s(u, "addr"), "{id}: host 与 addr 必须同值");
            assert!(!host.is_empty(), "{id}: host 不得为空");
            assert!(
                u.get("enabled").and_then(Value::as_bool).is_some(),
                "{id}: enabled 必须是布尔"
            );
            let port = u.get("port").and_then(Value::as_u64).expect("port");
            let url = s(u, "url");
            if proto == "doh" || proto == "doh3" {
                assert_eq!(port, 443, "{id}: DoH/DoH3 端口必须是 443");
                assert!(
                    url.starts_with('/') && !url.contains("://"),
                    "{id}: url 必须是路径（不得是完整 URL），实为 {url:?}"
                );
                // 规范化必须幂等：完整 URL 一旦进入 request-target / H3 `:path`，
                // 真实服务器会 100% 失败（历史缺陷：alidoh 0/16）。
                assert_eq!(
                    ebpdns_upstream::request_path(url, true),
                    url,
                    "{id}: request_path 规范化后必须与配置一致"
                );
            } else {
                assert_eq!(port, 53, "{id}: 明文协议端口必须是 53");
                assert_eq!(url, "", "{id}: 明文协议不得带 HTTP 路径");
                assert_eq!(
                    ebpdns_upstream::request_path(url, false),
                    "",
                    "{id}: 明文协议 request_path 必须为空"
                );
            }
        }
        assert_eq!(
            n,
            [5, 15, 2, 0],
            "doh3/doh/udp/tcp 条数（用户原文：doh3 = ali-doh3/dnspod-doh3/cf-doh3/\
             google-doh3/quad9-doh3 = **5**；doh 15；udp 2；tcp 0；实得 {n:?}）"
        );

        // **用户原文的 22 条 id，逐条与顺序一起锁死**（顺序 = 用户列的先后）。
        let want_ids = [
            "ali-doh3",
            "dnspod-doh3",
            "ali-doh",
            "dnspod-doh",
            "ali-ip-doh",
            "dnspod-ip-doh",
            "ali-ip2-doh",
            "cf-doh3",
            "google-doh3",
            "quad9-doh3",
            "cf-ip-doh",
            "cf-doh",
            "google-doh",
            "google-ip-doh",
            "quad9-doh",
            "nextdns-doh",
            "opendns-doh",
            "dnssb-doh",
            "adguard-doh",
            "hinet-doh",
            "ali-udp",
            "dnspod-udp",
        ];
        let got_ids: Vec<&str> = ups
            .iter()
            .map(|u| u.get("id").and_then(Value::as_str).unwrap_or(""))
            .collect();
        assert_eq!(
            got_ids, want_ids,
            "出厂默认上游必须与用户原文 22 条**逐条同序**一致"
        );
        for id in want_ids {
            assert!(ids.contains(id), "缺少上游 {id}");
        }
        // 用户原文里**没有**站点私有内网上游 ⇒ 必须彻底不在默认清单里。
        for id in ["lan235", "lan235tcp"] {
            assert!(
                !ids.contains(id),
                "{id}: 不在用户原文的 22 条里，必须从出厂默认移除"
            );
        }
        let find = |id: &str| {
            ups.iter()
                .find(|u| u.get("id").and_then(Value::as_str) == Some(id))
                .unwrap_or_else(|| panic!("缺少上游 {id}"))
        };
        // IP 形态 DoH：host 用 IP（TLS 校验走 IP SAN，不发 SNI），路径固定 /dns-query。
        for (id, ip) in [
            ("ali-ip-doh", "223.5.5.5"),
            ("dnspod-ip-doh", "120.53.53.53"),
            ("ali-ip2-doh", "223.6.6.6"),
            ("cf-ip-doh", "1.1.1.1"),
            ("google-ip-doh", "8.8.8.8"),
        ] {
            assert_eq!(
                s(find(id), "host"),
                ip,
                "{id}: IP 形态 DoH 的 host 必须是 IP"
            );
            assert_eq!(
                s(find(id), "url"),
                "/dns-query",
                "{id}: 路径固定 /dns-query"
            );
        }
        assert_eq!(
            s(find("nextdns-doh"), "url"),
            "/4d5525",
            "NextDNS 订阅 ID 路径必须保留 /4d5525"
        );
        assert_eq!(s(find("nextdns-doh"), "host"), "dns.nextdns.io");
        // 明文 UDP 上游：用户原文两条（端口 53、无 HTTP 路径）。
        assert_eq!(s(find("ali-udp"), "proto"), "udp");
        assert_eq!(s(find("dnspod-udp"), "proto"), "udp");
        for (id, ip) in [("ali-udp", "223.5.5.5"), ("dnspod-udp", "119.29.29.29")] {
            assert_eq!(s(find(id), "host"), ip, "{id}: host");
            assert_eq!(
                find(id).get("port").and_then(Value::as_u64),
                Some(53),
                "{id}: port"
            );
        }
        // 组别：国内 9 条（7 加密 + 2 UDP）/ 国外 13 条（3 DoH3 + 10 DoH）。
        let domestic = ups.iter().filter(|u| s(u, "group") == "domestic").count();
        let global = ups.iter().filter(|u| s(u, "group") == "global").count();
        assert_eq!((domestic, global), (9, 13), "国内/国外条数（9+13=22）");

        // 配置 JSON → ResolverConfig 的接线（键名兼容层）也必须成立。
        let rc = cfg_to_resolver(&c);
        assert_eq!(
            rc.cache_policy, "tinylfu",
            "cache_policy 必须生效为 tinylfu"
        );
        assert_eq!(rc.upstreams.len(), 22);
        assert_eq!(rc.upstreams.iter().filter(|u| u.proto == "doh3").count(), 5);
        assert_eq!(rc.upstreams.iter().filter(|u| u.proto == "doh").count(), 15);
        assert_eq!(rc.upstreams.iter().filter(|u| u.proto == "udp").count(), 2);
        assert_eq!(rc.upstreams.iter().filter(|u| u.proto == "tcp").count(), 0);
        // **2.1.19（修复项 4）**：启用集 = 用户原文标注 **on** 的 7 条
        // （`ali-doh3` / `ali-doh` / `dnspod-doh` / `ali-ip-doh` / `dnspod-ip-doh` /
        // `ali-ip2-doh` / `cf-doh3`），其余 15 条 off。
        let enabled: Vec<&str> = rc
            .upstreams
            .iter()
            .filter(|u| u.enabled)
            .map(|u| u.id.as_str())
            .collect();
        let disabled: Vec<&str> = rc
            .upstreams
            .iter()
            .filter(|u| !u.enabled)
            .map(|u| u.id.as_str())
            .collect();
        assert_eq!(
            enabled,
            vec![
                "ali-doh3",
                "ali-doh",
                "dnspod-doh",
                "ali-ip-doh",
                "dnspod-ip-doh",
                "ali-ip2-doh",
                "cf-doh3"
            ],
            "启用集必须与用户原文的 7 条 on 一致"
        );
        assert_eq!(
            disabled.len(),
            15,
            "禁用集大小（2.1.19：7 条启用 / 15 条禁用 = 22）"
        );
        for id in [
            "dnspod-doh3",
            "google-doh3",
            "quad9-doh3",
            "cf-ip-doh",
            "cf-doh",
            "google-doh",
            "google-ip-doh",
            "quad9-doh",
            "nextdns-doh",
            "opendns-doh",
            "dnssb-doh",
            "adguard-doh",
            "hinet-doh",
            "ali-udp",
            "dnspod-udp",
        ] {
            assert!(disabled.contains(&id), "{id}: 必须禁用");
        }
        let nx = rc
            .upstreams
            .iter()
            .find(|u| u.id == "nextdns-doh")
            .expect("nextdns-doh 必须进 ResolverConfig");
        assert_eq!(nx.url, "/4d5525", "url 必须原样进 ResolverConfig");
        assert_eq!(
            rc.bootstrap_dns, "223.5.5.5:53",
            "2.1.19 出厂默认 bootstrap_dns = [\"223.5.5.5:53\"]，归一后必须是带 53 端口的 host:port"
        );
        assert!(
            rc.serve_stale && rc.prefetch && rc.fallback && rc.ipv4_first && rc.dnssec_0x20,
            "serve_stale/prefetch/fallback/ipv4_first/dnssec_0x20 都必须为真"
        );
        // **2.1.18（修复项 21）**：出厂默认 stale_ttl 由 120 改为 604800
        // （见 README「出厂默认的已知取舍」：默认最长 7 天提供陈旧数据）。
        assert_eq!(rc.stale_ttl, 604800.0);
        assert_eq!(rc.ttl_min, 5, "2.1.19 起出厂默认 ttl_min = 5");
        assert_eq!(rc.ttl_max, 300, "2.1.19 起出厂默认 ttl_max = 300");
        assert_eq!(rc.timeout_ms, 1500);
        assert_eq!(rc.max_parallel_upstreams, 3);
        // 2.1.8 优化项 2/3/4/5：新键必须能被 cfg_to_resolver 读到（不是"只写进 json 的装饰"）。
        assert_eq!(rc.circuit_open_max_s, 120.0, "熔断指数退避封顶（项 5）");
        assert_eq!(
            rc.probe_timeout_ms, 0,
            "0 = 自动 min(probe, timeout)（项 2）"
        );
        assert_eq!(
            rc.effective_probe_timeout_ms(),
            1500,
            "默认探针超时收敛到 timeout_ms"
        );
        assert!(rc.adaptive_parallel, "自适应并发默认开启（项 3）");
        assert_eq!(rc.hedge_after_ms, 200);
        assert!(rc.adaptive_timeout, "按上游自适应超时默认开启（项 4）");
        assert!((rc.adaptive_timeout_k - 8.0).abs() < 1e-9);
        assert_eq!(
            rc.adaptive_timeout_min_ms, rc.timeout_ms,
            "默认下限必须等于 timeout_ms（默认不收紧，零行为变更）"
        );
        assert_eq!(rc.health_check_interval, 30);
        assert_eq!(rc.rule_sub_interval, 3600);
        // **2.1.43-B（P2-7）**：保留键仍必须有出厂默认值（键在，效果无）。
        #[allow(deprecated)]
        {
            assert!(
                !rc.cache_direct_enabled,
                "出厂默认 cache_direct_enabled 必须为 false"
            );
        }
        assert_eq!(
            rc.subscriptions,
            vec!["https://anti-ad.net/adguard.txt".to_string()],
            "订阅 URL 必须进 ResolverConfig.subscriptions"
        );

        // 订阅元信息：install.sh 装完后真机 10s 内自动拉取（action=block / group=global）。
        let subs = c
            .get("rule_subscriptions")
            .and_then(Value::as_array)
            .expect("rule_subscriptions 必须是数组");
        assert_eq!(subs.len(), 1, "必须预置 1 条规则订阅");
        assert_eq!(s(&subs[0], "url"), "https://anti-ad.net/adguard.txt");
        assert_eq!(s(&subs[0], "action"), "block");
        assert_eq!(s(&subs[0], "group"), "global");
        assert_eq!(
            c.get("cache_policy").and_then(Value::as_str),
            Some("tinylfu")
        );
    }

    /// 预配置一致性：`default_config()`（无配置文件时的兜底）必须与 install.sh 安装的
    /// `packaging/etc/ebpdns/config.json` **逐键一致**——两者漂移会产生「真机部署行为与
    /// 代码内默认值不同」且只在打包后才暴露的缺陷。
    #[test]
    fn default_config_matches_packaging_template() {
        let tpl: Value =
            serde_json::from_str(include_str!("../../../packaging/etc/ebpdns/config.json"))
                .expect("packaging/etc/ebpdns/config.json 必须是合法 JSON");
        let dft = default_config();
        let mut diffs = Vec::new();
        value_diffs("$", &dft, &tpl, &mut diffs);
        assert!(
            diffs.is_empty(),
            "default_config() 与打包模板漂移：\n{}",
            diffs.join("\n")
        );
    }

    /// **2.1.18（修复项 21）**：**新装后的 `/etc/ebpdns/config.json` 逐键 ==
    /// 包内模板 == `default_config()`**。
    ///
    /// 与 [`default_config_matches_packaging_template`] 的关系：那条只比较
    /// "代码默认 vs 包内模板"；本用例把**第三条腿**也钉住 —— `install.sh` 安装时
    /// 写盘的 `/etc/ebpdns/config.json` 就是**包内模板的原样拷贝**（`install.sh`
    /// 的 `install -m 0640 "$SRC/etc/ebpdns/config.json" ...`），因此"新装 == 模板"
    /// 属于安装脚本契约，必须在测试里显式声明，避免以后有人在 install.sh 里
    /// 做"字段裁剪/注入"而让三者漂移。
    ///
    /// 判据：
    /// ①`default_config()` 与模板逐键一致（同 `value_diffs`；重复断言一次是为了
    ///   让本用例单独跑也能定位）；
    /// ②模板本身**不含运行时元数据**（`rule_subscriptions[].count` /
    ///   `updated_at`），避免把"别人的订阅统计"带给新装用户；
    /// ③模板可被 `check-config` 判为合法（这里用 `validate_write` 做等价校验，
    ///   因为 `check-config` 的 CLI 分支不在 bin 单测的调用范围内）；
    #[test]
    fn new_install_config_matches_default_and_template() {
        let raw = include_str!("../../../packaging/etc/ebpdns/config.json");
        let tpl: Value = serde_json::from_str(raw).expect("模板必须是合法 JSON");
        let dft = default_config();

        // ① 三腿一致（代码默认 == 包内模板）。
        let mut diffs = Vec::new();
        value_diffs("$", &dft, &tpl, &mut diffs);
        assert!(
            diffs.is_empty(),
            "新装一致性失败（默认 vs 模板）：
{}",
            diffs.join(
                "
"
            )
        );

        // ② 不得携带运行时元数据。
        let subs = tpl
            .get("rule_subscriptions")
            .and_then(Value::as_array)
            .expect("rule_subscriptions 必须是数组");
        for (i, s) in subs.iter().enumerate() {
            assert!(
                s.get("count").is_none(),
                "rule_subscriptions[{i}] 不得写死 count（运行时元数据）"
            );
            assert!(
                s.get("updated_at").is_none(),
                "rule_subscriptions[{i}] 不得写死 updated_at（运行时元数据）"
            );
        }

        // ③ 模板必须通过"写路径"校验（与 `PUT /api/config`、`check-config` 同一份规则）。
        let errs = ebpdns_resolver::config::validate_write(&tpl);
        assert!(
            errs.is_empty(),
            "出厂模板必须通过 validate_write：
{}",
            errs.join(
                "
"
            )
        );

        assert_eq!(
            tpl.get("cache_direct_enabled").and_then(Value::as_bool),
            Some(false),
            "出厂默认 cache_direct_enabled 必须为 false"
        );
        assert_eq!(
            tpl.get("cache_size").and_then(Value::as_u64),
            Some(131072),
            "2.1.19 起出厂默认 cache_size = 131072（见 README「出厂默认的已知取舍」）"
        );
        assert_eq!(
            tpl.get("ttl_min").and_then(Value::as_u64),
            Some(5),
            "2.1.19 起出厂默认 ttl_min = 5"
        );
        assert_eq!(
            tpl.get("stale_ttl").and_then(Value::as_u64),
            Some(604800),
            "2.1.19 起出厂默认 stale_ttl = 604800"
        );
    }

    /// F31 端到端：热重载刷新 `api.host` 后，**Origin/CSRF 判定基准立刻跟着变**。
    /// 手工改 `api.host` + `/api/reload` 不再沿用启动快照（旧行为：新 host 的合法
    /// 请求被 fail-closed 403）。
    #[test]
    fn reload_refreshes_security_basis_end_to_end() {
        use ebpdns_resolver::clock::RealClock;
        use ebpdns_resolver::config::ResolverConfig;
        use ebpdns_resolver::query::ScriptedQuerier;
        use ebpdns_resolver::Resolver as Res;
        use ebpdns_server::axum::http::{HeaderMap, HeaderValue};
        use ebpdns_server::security::{csrf_ok, origin_ok};
        use ebpdns_server::ServerTelemetry;

        fn hdr(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
            let mut m = HeaderMap::new();
            for (k, v) in pairs {
                // 用 `from_bytes` 而非 `from_static`：后者对非法 token 字节会 panic
                // （测试里若出现下划线等非 token 字符会直接崩测试进程）。
                if let (Ok(name), Ok(val)) = (
                    ebpdns_server::axum::http::HeaderName::from_bytes(k.as_bytes()),
                    HeaderValue::from_bytes(v.as_bytes()),
                ) {
                    m.insert(name, val);
                }
            }
            m
        }

        let tel = Arc::new(ServerTelemetry::new());
        let q = ScriptedQuerier::new(|_n: &str, _t: &str, _d: u32| Vec::new());
        let resolver = Res::new(
            ResolverConfig::default(),
            tel.clone(),
            Arc::new(RealClock::default()),
            Arc::new(q),
        );
        let api_host = Arc::new(RwLock::new("127.0.0.1".to_string()));
        let st = AppState {
            resolver,
            cfg: Arc::new(RwLock::new(default_config())),
            cfg_path: None,
            telemetry: tel,
            api_host: api_host.clone(),
            api_port: 8353,
            web_root: None,
            restart: Arc::new(ebpdns_server::RestartSignal::default()),
            endpoints: Arc::new(RwLock::new(Vec::new())),
            on_reload: None,
            restart_notify: Arc::new(Notify::new()),
            udp_dropped: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            applied: Arc::new(RwLock::new(json!({}))),
            state: Default::default(),
        };

        let new_cfg = json!({"api": {"host": "0.0.0.0", "port": 9999}});
        // 公网域名（非回环、非私有 TLD、非配置 host）→ 旧基准下不可信 → 拒绝。
        // 注意：不能用 `*.lan` 之类的私有 TLD 做「应被拒绝」的样本——参考实现
        // `_trusted_host` 对私有 TLD/无点短名**不做 DNS 解析即信任**（已接受的
        // LAN 信任边界），用它断言「拒绝」会与参考行为矛盾。
        let hdr_pub = hdr(&[
            ("Host", "example.com:8353"),
            ("Origin", "http://example.com:8353"),
        ]);
        assert!(!origin_ok(&st, &hdr_pub));
        assert!(!csrf_ok(&st, &hdr_pub, "", ""));

        // 热重载：刷新 api.host（此时进入 LAN 模式：origin==host 自洽 + 可信本地名）。
        let listen = json!({"udp": "127.0.0.1", "tcp": "127.0.0.1"});
        let updated = st.apply_runtime_cfg(&new_cfg, &listen);
        assert_eq!(updated, vec!["api.host"], "updated={updated:?}");
        assert_eq!(api_host.read().clone(), "0.0.0.0");
        // 端口不可热改：仍是 bind 端口。
        assert_eq!(st.api_port, 8353);
        // web_root 是启动期固定值（`Option<PathBuf>`）：不在热刷新范围内。
        assert_eq!(st.web_root, None);

        // 新基准（LAN 模式 = 配置 host 为未指定地址）下，同一私网名请求被接受。
        let headers = hdr(&[
            ("Host", "ebpdns.lan:8353"),
            ("Origin", "http://ebpdns.lan:8353"),
        ]);
        assert!(origin_ok(&st, &headers));
        assert!(csrf_ok(&st, &headers, "", ""));
    }

    /* ---------- F32: listen.udp6/tcp6 双栈监听 ---------- */

    /// `parse_listen_cfg` 对 `[::]` / `::` / `[::]:53` / `::1` / 裸 IPv4 / `host:port`
    /// 的解析口径（端口可内嵌；裸 IPv6 绝不按 `host:port` 切）。
    #[test]
    fn parse_listen_cfg_handles_ipv6_and_host_port() {
        for (raw, want_host, want_port) in [
            ("[::]", "::", None),
            ("[::]:53", "::", Some(53)),
            ("[::1]", "::1", None),
            ("[::1]:5353", "::1", Some(5353)),
            ("::", "::", None),
            ("::1", "::1", None),
            ("2001:db8::1", "2001:db8::1", None),
            ("0.0.0.0", "0.0.0.0", None),
            ("0.0.0.0:53", "0.0.0.0", Some(53)),
            ("127.0.0.1", "127.0.0.1", None),
            ("127.0.0.1:5353", "127.0.0.1", Some(5353)),
            ("dns.example:5353", "dns.example", Some(5353)),
        ] {
            assert_eq!(
                parse_listen_cfg(Some(raw)),
                (want_host.to_string(), want_port),
                "parse_listen_cfg({raw:?})"
            );
        }
        // 空/缺省 → 回环（历史默认，不变）。
        assert_eq!(parse_listen_cfg(None), ("127.0.0.1".to_string(), None));
        assert_eq!(
            parse_listen_cfg(Some("   ")),
            ("127.0.0.1".to_string(), None)
        );
    }

    /// `listen.udp6/tcp6`：键缺失 → 默认 `[::]`（启用）；`false`/`null`/`""` → 关闭
    /// （不监听 v6，**不告警**）；显式地址照常解析。
    #[test]
    fn listen6_defaults_to_all_v6_and_off_is_silent() {
        let none = json!({"listen": {"udp": "0.0.0.0:53", "tcp": "0.0.0.0:53"}});
        assert_eq!(listen_spec(&none, "udp6"), ListenSpec::Missing);
        assert_eq!(listen_spec(&none, "tcp6"), ListenSpec::Missing);
        let (h, p) = parse_listen6(&listen_spec(&none, "udp6")).expect("键缺失 → 默认启用 v6");
        assert_eq!((h.as_str(), p), ("::", None));

        for raw in [json!(null), json!(false), json!(""), json!("   ")] {
            let cfg = json!({"listen": {"udp6": raw.clone(), "tcp6": raw}});
            for k in ["udp6", "tcp6"] {
                assert_eq!(listen_spec(&cfg, k), ListenSpec::Off, "{k}={raw}");
                assert!(
                    parse_listen6(&listen_spec(&cfg, k)).is_none(),
                    "{k}={raw} 必须不监听（且不告警）"
                );
            }
        }

        // 显式地址（含内嵌端口）照常启用；`true` = 启用 + 默认地址 `[::]`。
        let cfg = json!({"listen": {"udp6": "[::1]:5353", "tcp6": true}});
        assert_eq!(
            parse_listen6(&listen_spec(&cfg, "udp6")),
            Some(("::1".to_string(), Some(5353)))
        );
        assert_eq!(
            parse_listen6(&listen_spec(&cfg, "tcp6")),
            Some(("::".to_string(), None))
        );

        // IPv4 侧：键缺失/显式关闭一律回退历史默认 127.0.0.1（不改变既有行为）。
        let cfg = json!({"listen": {"udp": false}});
        assert_eq!(
            parse_listen_any(&listen_spec(&cfg, "udp"), "127.0.0.1"),
            ("127.0.0.1".to_string(), None)
        );
        assert_eq!(
            parse_listen_any(&listen_spec(&cfg, "tcp"), "127.0.0.1"),
            ("127.0.0.1".to_string(), None)
        );
    }

    /// `endpoints` 快照必须**如实**列出 `udp` / `udp6` / `tcp` / `tcp6` 四项。
    #[test]
    fn endpoints_snapshot_lists_four_slots() {
        let dual: Vec<SocketAddr> = vec!["0.0.0.0:53".parse().unwrap(), "[::]:53".parse().unwrap()];
        let eps = endpoints_of(&dual, &dual);
        assert_eq!(
            eps,
            vec![
                ("udp".to_string(), "0.0.0.0:53".to_string()),
                ("udp6".to_string(), "[::]:53".to_string()),
                ("tcp".to_string(), "0.0.0.0:53".to_string()),
                ("tcp6".to_string(), "[::]:53".to_string()),
            ],
            "四项顺序固定：udp/udp6/tcp/tcp6"
        );
        assert_eq!(endpoint_of(&eps, "udp6"), "[::]:53");
        assert_eq!(endpoint_of(&eps, "tcp6"), "[::]:53");
        // 降级（仅 IPv4，v6 绑定失败）时**不伪造** v6 条目：快照只剩两项。
        let only4: Vec<SocketAddr> = vec!["0.0.0.0:53".parse().unwrap()];
        let eps4 = endpoints_of(&only4, &only4);
        assert_eq!(eps4.len(), 2);
        assert_eq!(endpoint_of(&eps4, "udp6"), "-");
        assert_eq!(endpoint_of(&eps4, "tcp6"), "-");
    }

    /// 同一地址在 `udp` 与 `udp6` 两处重复出现 → 只绑一次（否则 `EADDRINUSE`）。
    #[test]
    fn dedupe_addrs_keeps_first_occurrence() {
        let any6: SocketAddr = "[::]:53".parse().unwrap();
        let any4: SocketAddr = "0.0.0.0:53".parse().unwrap();
        assert_eq!(dedupe_addrs(&[Some(any6), Some(any6)]), vec![any6]);
        assert_eq!(dedupe_addrs(&[Some(any4), Some(any6)]), vec![any4, any6]);
        assert_eq!(dedupe_addrs(&[Some(any4), None]), vec![any4]);
        assert!(dedupe_addrs(&[None, None]).is_empty());
    }

    /// 默认配置：`listen` 段必须回显四项（控制台可见，且 `udp6/tcp6` 默认 `[::]`）。
    #[test]
    fn default_config_exposes_dual_stack_listen() {
        let l = default_config().get("listen").cloned().unwrap_or_default();
        // 双栈必须**显式**给出四项（v2.1.6 预配置契约）：`udp6/tcp6` 允许
        // "[::]"（端口跟随 IPv4）与 "[::]:53"（内嵌端口）两种等价写法。
        for k in ["udp", "tcp", "udp6", "tcp6"] {
            assert!(
                l.get(k).and_then(Value::as_str).is_some(),
                "listen.{k} 必须存在"
            );
        }
        for k in ["udp6", "tcp6"] {
            let (host, _p) = parse_listen_cfg(l.get(k).and_then(Value::as_str));
            assert_eq!(host, "::", "listen.{k} 必须是 v6 通配");
        }
    }

    /* ============ **2.1.22 阶段一（验收 ③）**：schema 2 → 3 迁移的前进/回退 **============ */

    /* ---------- **2.1.24 / P1-3d**：`migrate-config` 的 `state_dir` 语义 ---------- */
    //
    // 2.1.23 交付报告 ⑫(3) 登记的三条缺陷（P1，不阻塞交付但**已实测污染生产**）：
    //   ① `migrate-config` **不接受** `--state-dir`（`error: unexpected argument`，rc=2）
    //      ⇒ 离线迁移没有任何"指定状态目录"的手段；
    //   ② 没有 `state_dir` 的 2.1.22-era 配置会被"只做加法"补成**生产默认路径**
    //      并**真的去读写** `/var/lib/ebpdns/state`（把测试规则写进生产真源）；
    //   ③ `reanchor` 撞上运行中实例的 `flock` 时报 **rc=1**（与"IO/备份失败"同码），
    //      而事实上"配置**已写回**、提交点未更新"，`install.sh --migrate-config`
    //      因此对这种（常规）场景**必失败**且原因被误判。

    /// ① 决策函数：**绝不回落到生产默认路径**（三种显式来源 + 优先级 + 空白串不算来源）。
    #[test]
    fn migrate_state_dir_never_falls_back_to_the_production_default() {
        // 没有任何来源 ⇒ `None`（调用方据此只做只读报告，rc=3）。
        assert_eq!(
            migrate_state_dir(&json!({}), None, None),
            None,
            "没有任何显式来源时必须返回 None —— 这就是 2.1.23 事故的判据"
        );
        // 空白串不算来源（与 `resolve_state_dir_checked` 的 trim 口径一致）。
        assert_eq!(
            migrate_state_dir(&json!({"state_dir": "   "}), None, None),
            None
        );
        assert_eq!(migrate_state_dir(&json!({}), None, Some("  ")), None);
        // 配置里有 ⇒ `Config`。
        let (p, src) = migrate_state_dir(&json!({"state_dir": "/srv/a"}), None, None).unwrap();
        assert_eq!(
            (p.to_str().unwrap(), src),
            ("/srv/a", MigrateStateDirSource::Config)
        );
        // `--state-dir` 优先于配置。
        let (p, src) = migrate_state_dir(
            &json!({"state_dir": "/srv/a"}),
            Some(std::path::Path::new("/srv/b")),
            None,
        )
        .unwrap();
        assert_eq!(
            (p.to_str().unwrap(), src),
            ("/srv/b", MigrateStateDirSource::Cli)
        );
        // 配置文件里没有 ⇒ 环境变量（仍是**显式**来源，不是默认值）。
        let (p, src) = migrate_state_dir(&json!({}), None, Some("/srv/c")).unwrap();
        assert_eq!(
            (p.to_str().unwrap(), src),
            ("/srv/c", MigrateStateDirSource::Env)
        );
    }

    /// ② **无 `--state-dir` 且配置里无 `state_dir` ⇒ 只读报告**（rc=3）：一个字节都不写。
    ///
    /// 2.1.23 在这里会：补 `state_dir=/var/lib/ebpdns/state` → 加法导入规则 →
    /// 重锚（撞锁）→ 报 `rc=1`，而配置**已经被改写**。
    #[test]
    fn migrate_config_without_state_dir_never_writes_anything() {
        let root = mig_tmp("nostate");
        let cfg_path = root.join("config.json");
        let before = serde_json::to_vec_pretty(&json!({
            "config_version": 2,
            "rules": [{"id": "r1", "match": "n1.example", "action": "block"}],
        }))
        .unwrap();
        std::fs::write(&cfg_path, &before).unwrap();
        let rc = run_migrate_config(Some(&cfg_path), false, false, false, false, None, None);
        assert_eq!(
            rc, MIGRATE_RC_NO_STATE_DIR,
            "必须返回专用退出码 3（不是 1/2/0）：既没落盘也没 IO 失败"
        );
        assert_eq!(
            std::fs::read(&cfg_path).unwrap(),
            before,
            "只读报告**不得**改写配置（逐字节比较）"
        );
        let mut names: Vec<String> = std::fs::read_dir(&root)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec!["config.json".to_string()],
            "不得产生 .bak / .tmp / 任何 state 目录：{names:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// ③ **显式 `--state-dir` ⇒ 只写该目录**，且写回的配置里 `state_dir` = 该目录
    /// （**不得**把生产默认路径写进配置）。2.1.23 拒绝这个参数（rc=2）。
    #[test]
    fn migrate_config_with_explicit_state_dir_writes_only_that_dir() {
        let root = mig_tmp("cli");
        let state_dir = root.join("state-cli");
        let cfg_path = root.join("config.json");
        std::fs::write(
            &cfg_path,
            serde_json::to_vec_pretty(&json!({
                "config_version": 2,
                "rules": [{"id": "r9", "match": "cli.example", "action": "block"}],
            }))
            .unwrap(),
        )
        .unwrap();
        let rc = run_migrate_config(
            Some(&cfg_path),
            false,
            false,
            false,
            false,
            Some(state_dir.as_path()),
            None,
        );
        assert_eq!(rc, MIGRATE_RC_OK, "显式给目录时必须成功（rc=0）");
        let src = state_dir.join("rules.json");
        let v: Value =
            serde_json::from_slice(&std::fs::read(&src).expect("真源必须写在 `--state-dir` 里"))
                .unwrap();
        assert_eq!(v["count"], json!(1), "加法导入必须落到显式目录");
        let after: Value = serde_json::from_slice(&std::fs::read(&cfg_path).unwrap()).unwrap();
        assert_eq!(
            after["state_dir"],
            json!(state_dir.display().to_string()),
            "补进去的 `state_dir` 必须是**本次真正使用**的目录，不是生产默认路径"
        );
        assert_eq!(after["config_version"], json!(3));
        assert!(after.get("rules").is_none(), "镜像键必须删除（真源已建立）");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// ④ 配置里**有** `state_dir` ⇒ 用它（不需要 `--state-dir`），且配置里的值**原样不动**。
    #[test]
    fn migrate_config_uses_state_dir_from_the_config_file() {
        let root = mig_tmp("cfgdir");
        let state_dir = root.join("state-cfg");
        let cfg_path = root.join("config.json");
        std::fs::write(
            &cfg_path,
            serde_json::to_vec_pretty(&json!({
                "config_version": 2,
                "state_dir": state_dir.display().to_string(),
                "rules": [{"id": "r2", "match": "cfg.example", "action": "block"}],
            }))
            .unwrap(),
        )
        .unwrap();
        let rc = run_migrate_config(Some(&cfg_path), false, false, false, false, None, None);
        assert_eq!(rc, MIGRATE_RC_OK);
        let v: Value = serde_json::from_slice(
            &std::fs::read(state_dir.join("rules.json")).expect("真源写在配置给的目录里"),
        )
        .unwrap();
        assert_eq!(v["count"], json!(1));
        let after: Value = serde_json::from_slice(&std::fs::read(&cfg_path).unwrap()).unwrap();
        assert_eq!(
            after["state_dir"],
            json!(state_dir.display().to_string()),
            "配置里已有的 `state_dir` 不得被改写（只做加法）"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    fn mig_tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "ebpdns-mig-{tag}-{}-{}",
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

    /// **前进**：`config_version=2` + 带 `rules` 的 `config.json` ⇒
    /// ① 加法导入 `state/rules.json`（内容**逐字节**保留）；
    /// ② 删除 `config.json.rules` 镜像键；③ 版本提到 3。
    #[test]
    fn migrate_v2_to_v3_imports_rules_then_drops_the_mirror() {
        let root = mig_tmp("fwd");
        let state_dir = root.join("state");
        let cfg_path = root.join("config.json");
        let rules = json!([
            {"id": "r1", "match": "a.example", "action": "block"},
            {"id": "r2", "match": "b.example", "action": "group", "group": "domestic"}
        ]);
        let mut cfg = json!({
            "config_version": 2,
            "cache_size": 131072,
            "rules": rules.clone(),
        });
        std::fs::write(&cfg_path, serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();

        let (from, steps) = migrate_schema_at(&mut cfg, Some(state_dir.as_path()));
        assert_eq!(from, 2, "来源版本必须是 2");
        assert_eq!(cfg["config_version"], json!(3), "必须提到 3");
        assert!(
            cfg.get("rules").is_none(),
            "必须删除 `config.json.rules` 镜像键（2→3 的减法步骤）"
        );
        assert_eq!(cfg["state_dir"], json!("/var/lib/ebpdns/state"));
        assert_eq!(cfg["state_persist"], json!(true));
        assert!(!steps.is_empty());

        // ① 真源：**逐字节**保留规则数组（不归一化、不排序、不补 id）。
        let src = state_dir.join("rules.json");
        let v: Value = serde_json::from_slice(&std::fs::read(&src).expect("真源必须存在")).unwrap();
        assert_eq!(
            v.get("rules").unwrap(),
            &rules,
            "加法导入必须逐元素原样（不得重排/补字段）"
        );
        assert_eq!(v["count"], json!(2));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// **幂等**：已经是 v3 且真源已存在 ⇒ 不再产生任何迁移步骤。
    #[test]
    fn migrate_v2_to_v3_is_idempotent_when_already_migrated() {
        let root = mig_tmp("idem");
        let state_dir = root.join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        let rules = json!([{"id": "r1", "match": "a.example", "action": "block"}]);
        std::fs::write(
            state_dir.join("rules.json"),
            serde_json::to_vec(&json!({"version": 1, "count": 1, "rules": rules})).unwrap(),
        )
        .unwrap();
        let mut cfg = json!({"config_version": 3, "state_dir": state_dir.display().to_string()});
        let (from, steps) = migrate_schema_at(&mut cfg, Some(state_dir.as_path()));
        assert_eq!(from, 3);
        assert!(steps.is_empty(), "v3 且无镜像键 ⇒ 无步骤，实际 {steps:?}");
        assert!(cfg.get("rules").is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// **2.1.23（DEF-222-05）**：外部改写 `config.json` 之后**重新锚定提交点** ⇒
    /// 下一次启动**不再**判撕裂（2.1.22 会；无历史世代时甚至 TORN）。
    #[test]
    fn def222_05_reanchor_after_out_of_band_write_prevents_a_false_tear() {
        use ebpdns_server::state_store::StateStore;
        let root = mig_tmp("reanchor");
        let state_dir = root.join("state");
        let cfg_path = root.join("config.json");
        std::fs::create_dir_all(&state_dir).unwrap();
        let store = StateStore::open(&state_dir, 2).expect("open");

        // ① 建立一代（提交点里记的是 config.json 的初始内容）。
        let mut plan = std::collections::BTreeMap::new();
        plan.insert(
            cfg_path.clone(),
            serde_json::to_vec_pretty(&json!({"a": 1})).unwrap(),
        );
        store.commit(&plan, "test", 1000, 1).expect("commit");
        assert!(matches!(
            store.load(),
            ebpdns_server::state_store::LoadState::Committed(_)
        ));

        // ② 模拟 `migrate-config` / `--export-legacy`：**绕过 store** 直接改 config.json。
        std::fs::write(
            &cfg_path,
            serde_json::to_vec_pretty(&json!({"a": 2})).unwrap(),
        )
        .unwrap();

        // ③ **不改锚点**：下一次启动必然判撕裂（这就是 2.1.22 的缺陷路径）。
        let s_before = StateStore::open(&state_dir, 2).expect("open2");
        assert!(
            matches!(
                s_before.load(),
                ebpdns_server::state_store::LoadState::Torn { .. }
                    | ebpdns_server::state_store::LoadState::RolledBack { .. }
            ),
            "**前提**：未重锚时外部改写必须被判成撕裂/回退（否则本用例没有覆盖缺陷）"
        );

        // ④ 重锚 ⇒ 提交点按磁盘现状重算摘要。
        let changed = ebpdns_server::state_store::reanchor_commit_after_external_write(
            &s_before,
            "migrate-config",
        )
        .expect("重锚必须成功");
        assert!(changed, "外部改写与提交点不一致 ⇒ 必须报告 changed=true");

        // ⑤ 再启动必须**健康**（Committed，且 revision 不变 —— 重锚不是新提交）。
        let s_after = StateStore::open(&state_dir, 2).expect("open3");
        match s_after.load() {
            ebpdns_server::state_store::LoadState::Committed(c) => {
                assert_eq!(c.revision, 1000, "重锚**不得**推进 revision");
                assert!(
                    c.writer.contains("migrate-config"),
                    "重锚必须留下审计痕迹（writer 追加后缀）：{}",
                    c.writer
                );
            }
            other => panic!("重锚后必须判 Committed，实际 {other:?}"),
        }
        // ⑥ 幂等：磁盘已与提交点一致 ⇒ 第二次重锚报告"无需变更"。
        assert!(
            !ebpdns_server::state_store::reanchor_commit_after_external_write(
                &s_after,
                "migrate-config"
            )
            .expect("二次重锚"),
            "已一致 ⇒ 必须报告 changed=false（幂等）"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// **2.1.23（DEF-222-06）**：`missing_default_keys` 必须**排除镜像/运行期键**
    /// ⇒ 两次 `migrate-config` 结果一致（2.1.22 会在第二次把 `rules: []` 补回来）。
    #[test]
    fn def222_06_missing_keys_exclude_the_rules_mirror_so_migration_is_idempotent() {
        // 一份"刚被 2→3 迁移删掉 rules 镜像键"的配置。
        let cfg = json!({"config_version": 3, "cache_size": 131072});
        let missing = missing_default_keys(&cfg);
        assert!(
            !missing.iter().any(|k| k == "rules"),
            "`rules` 是**被迁移删除的镜像键**，不得再当『缺失键』补回（那正是非幂等的根源）：{missing:?}"
        );
        assert!(
            !missing
                .iter()
                .any(|k| k == "rule_local_file" || k == "rule_sub_file"),
            "运行期注入的路径键不得写进配置文件：{missing:?}"
        );
        // 但它**仍然是** `default_config()` 的顶层键（键集一致性不受影响）。
        assert!(
            default_config().get("rules").is_some(),
            "`default_config()` 仍应带 `rules: []`（出厂模板的键集不变）"
        );
        // 反证：真·缺失键仍会被报出来（判据不是"永远返回空"）。
        let old = json!({"config_version": 2});
        let m2 = missing_default_keys(&old);
        assert!(
            m2.iter().any(|k| k == "cache_size" || k == "udp_workers"),
            "真正的缺失键必须仍被报出：{m2:?}"
        );
    }

    /// **回退（3 → 2）**：`--export-legacy` 把真源**逐字节**导回 `config.json.rules`，
    /// 并把 `config_version` 降回 2 ⇒ 2.1.21 二进制能读。
    #[test]
    fn export_legacy_round_trips_rules_byte_exact_and_downgrades_version() {
        let root = mig_tmp("back");
        let state_dir = root.join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        // 真源里的规则**故意带奇怪形状**（键顺序、空串、多余键），验证"逐字节"。
        let raw_rules = json!([
            {"action": "block", "match": "z.example", "id": "rz", "extra": {"深": "值"}},
            {"match": "a.example", "action": "group", "group": "", "ip": ""}
        ]);
        std::fs::write(
            state_dir.join("rules.json"),
            serde_json::to_vec(&json!({
                "version": 1, "saved_at": 1, "count": 2, "rules": raw_rules.clone()
            }))
            .unwrap(),
        )
        .unwrap();
        let cfg_path = root.join("config.json");
        std::fs::write(
            &cfg_path,
            serde_json::to_vec_pretty(&json!({"config_version": 3, "cache_size": 131072})).unwrap(),
        )
        .unwrap();

        let (n, bak, _ts) = main_state::export_legacy(&cfg_path, &state_dir).expect("导出必须成功");
        assert_eq!(n, 2);
        assert!(bak.is_file(), "必须先备份原文件");
        let out: Value = serde_json::from_slice(&std::fs::read(&cfg_path).unwrap()).unwrap();
        assert_eq!(out["config_version"], json!(2), "必须降到 2 供旧二进制读");
        assert_eq!(
            out["rules"], raw_rules,
            "导出的规则必须与真源**逐字节等价**（Value 往返不得改写形状）"
        );
        assert_eq!(out["cache_size"], json!(131072), "其它键必须原样保留");

        // 真源不存在 ⇒ **不改动任何文件**（fail-closed）。
        let cfg2 = root.join("config2.json");
        std::fs::write(&cfg2, b"{\"config_version\":3}").unwrap();
        let before = std::fs::read(&cfg2).unwrap();
        let e = main_state::export_legacy(&cfg2, &root.join("nope")).expect_err("必须报错");
        assert!(e.contains("不可读"), "错误必须指明真源不可读：{e}");
        assert_eq!(std::fs::read(&cfg2).unwrap(), before, "失败时不得改文件");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// **启动期迁移**（`load()` 判为 `Legacy` 时走它）：删镜像键**且**写回磁盘、
    /// 并留 `.bak.<ts>`；真源缺失时**保留**镜像键（宁可留着也不丢规则）。
    #[test]
    fn startup_legacy_migration_writes_back_and_keeps_backup() {
        let root = mig_tmp("startup");
        let state_dir = root.join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        let cfg_path = root.join("config.json");
        let rules = json!([{"id": "r1", "match": "a.example", "action": "block"}]);
        let mut cfg = json!({"config_version": 2, "rules": rules.clone()});
        std::fs::write(&cfg_path, serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();

        let steps =
            main_state::migrate_legacy_rules(&mut cfg, Some(cfg_path.as_path()), &state_dir)
                .expect("迁移必须成功");
        assert!(cfg.get("rules").is_none(), "内存里的镜像键必须删掉");
        let disk: Value = serde_json::from_slice(&std::fs::read(&cfg_path).unwrap()).unwrap();
        assert!(
            disk.get("rules").is_none(),
            "磁盘上的 `config.json` 也必须去掉镜像键"
        );
        let baks: Vec<_> = std::fs::read_dir(&root)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".bak."))
            .collect();
        assert_eq!(baks.len(), 1, "必须留一份 .bak.<ts>，步骤：{steps:?}");
        let src: Value =
            serde_json::from_slice(&std::fs::read(state_dir.join("rules.json")).unwrap()).unwrap();
        assert_eq!(src["rules"], rules);

        // 真源写不出来 ⇒ **保留**镜像键（fail-closed，不丢规则）。
        let root2 = mig_tmp("startup2");
        let cfg_path2 = root2.join("config.json");
        std::fs::write(
            &cfg_path2,
            serde_json::to_vec_pretty(&json!({"rules": rules})).unwrap(),
        )
        .unwrap();
        let mut cfg2 = json!({"rules": rules});
        // state_dir 指向一个**建不出来的**路径（路径上是一个普通文件）。
        let blocker = root2.join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        let _ = main_state::migrate_legacy_rules(&mut cfg2, Some(cfg_path2.as_path()), &blocker);
        assert!(
            cfg2.get("rules").is_some(),
            "真源写不出来时必须保留 `config.json.rules`（否则规则只剩内存一份）"
        );
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&root2);
    }

    /// `state_dir` 解析优先级 + `state_persist` 真值语义。
    #[test]
    fn state_dir_precedence_and_state_persist_truth() {
        assert_eq!(
            main_state::resolve_state_dir(&json!({"state_dir": "/srv/ebpdns/state"})),
            PathBuf::from("/srv/ebpdns/state")
        );
        assert_eq!(
            main_state::resolve_state_dir(&json!({})),
            PathBuf::from(main_state::DEFAULT_STATE_DIR)
        );
        assert_eq!(
            main_state::resolve_state_dir(&json!({"state_dir": "   "})),
            PathBuf::from(main_state::DEFAULT_STATE_DIR),
            "空白串必须按'未配置'处理（不得相对 CWD 建目录）"
        );
        // `state_persist` 的真值语义（缺键 ⇒ 启用）。
        assert!(main_state::enabled_by_cfg(&json!({})));
        assert!(main_state::enabled_by_cfg(&json!({"state_persist": true})));
        assert!(!main_state::enabled_by_cfg(
            &json!({"state_persist": false})
        ));
        assert!(!main_state::enabled_by_cfg(
            &json!({"state_persist": "off"})
        ));
        assert!(!main_state::enabled_by_cfg(&json!({"state_persist": null})));
    }

    /// **3 → 2 回归启动一次**：`--export-legacy` 之后的 `config.json` 必须能通过
    /// `check-config` 的同一套判据（`validate_schema`），即"旧二进制真的能读"。
    #[test]
    fn exported_legacy_config_passes_schema_validation() {
        let root = mig_tmp("exportschema");
        let state_dir = root.join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        let rules = json!([{"id": "r1", "match": "a.example", "action": "block"}]);
        std::fs::write(
            state_dir.join("rules.json"),
            serde_json::to_vec(&json!({"version": 1, "count": 1, "rules": rules})).unwrap(),
        )
        .unwrap();
        let cfg_path = root.join("config.json");
        let mut base = default_config();
        base["config_version"] = json!(3);
        std::fs::write(&cfg_path, serde_json::to_vec_pretty(&base).unwrap()).unwrap();
        main_state::export_legacy(&cfg_path, &state_dir).expect("导出");

        let mut out: Value = serde_json::from_slice(&std::fs::read(&cfg_path).unwrap()).unwrap();
        // 与 `run_check_config` 同一条路径：`migrate_schema_at(None)` + `validate_schema`。
        let (from, _steps) = migrate_schema_at(&mut out, None);
        assert_eq!(from, 2, "导出后来源版本必须是 2");
        let (_warn, err) = validate_schema(&out);
        assert!(err.is_empty(), "导出的 legacy 配置必须无 ERROR：{err:?}");
        // `check-config` 的一行提示必须**指明权威文件**。
        let hint = rules_source_hint(&cfg_path, &out);
        assert!(hint.contains("规则唯一真源"), "提示必须写明真源：{hint}");
        assert!(
            hint.contains("rules.json"),
            "提示必须给出真源文件名：{hint}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
