//! ebpdns-cache 错误类型。

use thiserror::Error;

/// 缓存层错误。数据面/恢复路径对畸形输入一律 fail-closed（跳过），
/// 本错误主要用于显式可观测的失败场景。
#[derive(Debug, Error)]
pub enum CacheError {
    #[error("序列化失败: {0}")]
    Serialize(#[from] serde_json::Error),

    #[error("恢复记录超限截断: limit={limit}, got={got}")]
    RestoreTruncated { limit: usize, got: usize },
}

/// 结果别名。
pub type CacheResult<T> = Result<T, CacheError>;
