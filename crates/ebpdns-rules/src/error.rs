//! `RulesError`：规则引擎错误。
//!
//! 数据面/加载期遇到畸形输入一律 [`Err`] 或显式跳过（fail-closed），绝不 panic、
//! 绝不产出错误规则数据（对齐 CONVENTIONS §1）。

/// 规则引擎错误。
#[derive(Debug, thiserror::Error)]
pub enum RulesError {
    /// 规则列表文件不是预期的 JSON 对象 / 数组结构。
    #[error("规则文件结构非法: {0}")]
    InvalidStructure(String),

    /// 文件读取 / JSON 反序列化失败。
    #[error("规则文件 IO / 解析失败: {0}")]
    Io(#[from] std::io::Error),

    /// JSON 反序列化失败。
    #[error("JSON 解析失败: {0}")]
    Json(#[from] serde_json::Error),
}
