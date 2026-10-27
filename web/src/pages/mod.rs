//! 五个路由页面。
//!
//! **2.1.14**：独立的「规则管理」页（`rules.rs` / `RulesPage`）已删除 —— 它在
//! `main.rs` 的渲染 match 里被重复三次、从未挂载，且 `rules.rs:174` 引用了不存在的
//! `action2/group2/ip2`（编译不过）。分流规则能力保留在**配置页的「分流规则」卡片**。

pub mod about;
pub mod config;
pub mod pipeline;
pub mod query;
pub mod telemetry;

pub use about::AboutPage;
pub use config::ConfigPage;
pub use pipeline::PipelinePage;
pub use query::QueryPage;
pub use telemetry::TelemetryPage;
