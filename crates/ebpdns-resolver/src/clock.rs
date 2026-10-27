//! 时钟抽象：`time.time()`（epoch 秒，缓存 TTL 口径）与 `time.monotonic()`（延迟口径）。
//! 生产用真实时钟；测试可注入 mock 时钟保证确定性。

use std::time::{SystemTime, UNIX_EPOCH};

/// 时钟 trait。
pub trait Clock: Send + Sync + 'static {
    /// **[历史归因]** epoch 秒（对齐 Python `time.time()`）。
    fn epoch(&self) -> f64;
    /// **[历史归因]** 单调毫秒（对齐 Python `time.monotonic()*1000`，仅用于延迟统计）。
    fn monotonic_ms(&self) -> f64;
}

/// 真实时钟（SystemTime + 启动基准）。
pub struct RealClock {
    boot: std::time::Instant,
}

impl Default for RealClock {
    fn default() -> Self {
        Self {
            boot: std::time::Instant::now(),
        }
    }
}

impl Clock for RealClock {
    fn epoch(&self) -> f64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0)
    }
    fn monotonic_ms(&self) -> f64 {
        self.boot.elapsed().as_secs_f64() * 1000.0
    }
}

/// 静态时钟（测试注入）：epoch 固定，monotonic 固定。
pub struct MockClock {
    pub epoch: std::sync::atomic::AtomicU64,
}

impl MockClock {
    pub fn new(epoch_secs: f64) -> Self {
        Self {
            epoch: std::sync::atomic::AtomicU64::new((epoch_secs * 1000.0) as u64),
        }
    }
    pub fn set_epoch(&self, secs: f64) {
        self.epoch
            .store((secs * 1000.0) as u64, std::sync::atomic::Ordering::Relaxed);
    }
    pub fn advance(&self, secs: f64) {
        self.epoch
            .fetch_add((secs * 1000.0) as u64, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Clock for MockClock {
    fn epoch(&self) -> f64 {
        self.epoch.load(std::sync::atomic::Ordering::Relaxed) as f64 / 1000.0
    }
    fn monotonic_ms(&self) -> f64 {
        // 测试用：monotonic 与 epoch 同步推进，仅延迟统计用。
        self.epoch.load(std::sync::atomic::Ordering::Relaxed) as f64
    }
}
