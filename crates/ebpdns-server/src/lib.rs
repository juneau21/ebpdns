//! ebpdns-server：DNS UDP/TCP 数据面监听 + HTTP/REST/WebSocket API + 静态资源服务。
//!

// **2.1.24（B4：clippy 清零）**：`clippy::doc_lazy_continuation` 在本 crate **整片允许**，
// 理由是可核查的，不是"关掉告警换清静"：
//   * 命中的全是**中文**文档注释（29 处，逐条清单见 `docs/CLIPPY.md`）。该 lint 用
//     Markdown 的"列表项缩进"规则判连续性，而中文条目里的 `*`/`-` 后面常跟全角标点
//     （`：`/`、`/`⇒`），clippy 据此把**同一个句子的续行**判成"新的段落缺少空行"。
//   * 按它的建议逐行加缩进或空行，会把**已经排好版的中文说明**改写成另一种排版，
//     既不改变任何代码行为，也让 `git diff` 里真正要审的改动被 29 处纯排版噪声淹没。
//   * 真正有害的文档缺陷（缺链接目标、缺 `# Safety` 等）**不在**这条 lint 里，
//     因此允许它不会掩盖真问题。
// 复现：`cargo clippy --workspace --all-targets` 不再报告该 lint；逐条位置见 docs/CLIPPY.md。

#![allow(clippy::doc_lazy_continuation)]
//! **[历史归因]** 忠实对齐 Python `ebpdns/server.py` + `ebpdns/api.py`：
//! - [`dns`]：UDP/TCP 监听器（有界并发、fail-closed、优雅退出）；
//! - [`api`]：axum 路由（与 api.py 一一对应，见下表）；
//! - [`security`]：token 三入口常量时间比较 + CSRF + Origin/rebinding 防护；
//! - [`static_assets`]：rust-embed（embed-frontend feature）或磁盘 fallback + SPA；
//! - [`telemetry`]：实现 resolver `Telemetry`，同时供 /api/status、/metrics、/api/logs。
//!
//! # 路由 ↔ api.py 对应表
//!
//! | 方法 | 路径 | api.py 处理器 |
//! |---|---|---|
//! | GET | /api/health | _health（免 token） |
//! | GET | /api/config | _get_config（token 脱敏 ***） |
//! | PUT | /api/config | _api_update_config（白名单+ignored_keys+原子写） |
//! | POST | /api/query | _api_query（严格白名单） |
//! | GET | /api/snapshot | _api_snapshot |
//! | GET | /api/upstreams | _upstreams_with_health |
//! | POST/PUT/DEL | /api/upstreams(/<id>) | 程序化面上游 CRUD |
//! | GET | /api/status | _api_status |
//! | GET | /api/logs?next_seq= | _api_logs（增量） |
//! | GET | /api/pipeline | _api_pipeline |
//! | GET | /metrics | _metrics（Prometheus） |
//! | POST | /api/rules/import | _api_rules_import |
//! | POST/DEL | /api/rules/subscribe | _api_rules_subscribe(_delete) |
//! | POST | /api/rules/subscribe/update | _api_rules_subscribe_update |
//! | POST | /api/reprobe | _api_reprobe |
//! | POST | /api/reload | _api_reload |
//! | POST | /api/restart | _api_restart（退出码 3） |
//! | POST | /api/reset | _api_reset（reset_runtime_state） |
//! | GET/POST | /api/rules(/<id>) | 程序化面规则 CRUD |
//! | GET | /api/cache/stats | _api_cache_stats |
//! | POST | /api/profile | _api_profile |
//! | * | 其他 | _serve_static（SPA fallback） |

pub mod api;
pub mod api_state;
pub mod dns;
pub mod error;
pub mod io_atomic;
pub mod rules_admin;
pub mod security;
pub mod state;
pub mod state_store;
pub mod static_assets;
pub mod subscribe;
pub mod telemetry;

pub use api::{build_router, serve_http, VERSION};
/// 重导出 axum：二进制 crate（`ebpdns`）不直接依赖 axum，测试/装配需要构造
/// `HeaderMap` 等类型时经此处引用，避免为一个测试新增顶层依赖。
pub use axum;
pub use dns::DnsServer;
pub use error::{ServerError, ServerResult};
pub use state::{AppState, ReloadError, ReloadOutcome, RestartSignal, StateCtx};
pub use state_store::{Commit, CommitError, LoadState, PartMeta, StateStore};
pub use telemetry::ServerTelemetry;
