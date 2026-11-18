//! 展示格式助手（对齐 v1.9.162 前端的 nowTs / _n / toFixed 系列）。
//!
//! 纯数值/文本部分挪到 `fmtnum`（无 wasm 依赖，可 native 复用与验证），
//! 这里按 `pub use` 重导出，调用点仍是 `fmt::num0(...)`；本模块只保留需要
//! `js_sys::Date` 的本地时间格式化。
use js_sys::Date;

pub use crate::fmtnum::*;

fn pad2(n: u32) -> String {
    if n < 10 {
        format!("0{n}")
    } else {
        n.to_string()
    }
}

// 2.1.14 清理（审计 ⑥）：删除 `hms(epoch)`——全仓零调用者（仅 `hms_ms` 在用，
// 时间列统一走毫秒精度格式，`hms` 是历史遗留的第二套实现）。

/// epoch 秒 → 本地 `HH:MM:SS.mmm`
pub fn hms_ms(epoch: f64) -> String {
    if !epoch.is_finite() || epoch <= 0.0 {
        return "--:--:--.---".into();
    }
    let d = Date::new(&(epoch * 1000.0).into());
    format!(
        "{}:{}:{}.{:03}",
        pad2(d.get_hours()),
        pad2(d.get_minutes()),
        pad2(d.get_seconds()),
        d.get_milliseconds()
    )
}

/// 当前本地时间 `HH:MM:SS.mmm`（对齐 nowTs()）。
pub fn now_ts() -> String {
    let d = Date::new_0();
    format!(
        "{}:{}:{}.{:03}",
        pad2(d.get_hours()),
        pad2(d.get_minutes()),
        pad2(d.get_seconds()),
        d.get_milliseconds()
    )
}
