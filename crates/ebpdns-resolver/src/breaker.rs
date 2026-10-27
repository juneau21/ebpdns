//! 熔断器：per-upstream 失败计数 + 打开窗口 + 指数退避 + 独立探针计数。
//!
//! **[历史归因]** 对齐 Python `_cb_fail/_cb_ok/_cb_is_open`：连续失败达 `cb_fails` 次打开 `cb_open_s` 秒。
//! 本版（2.1.8 优化项 2/5/6）在保持该语义的前提下增加三点：
//!
//! 1. **指数退避**：第 k 次连续打开 → `min(open_s * 2^(k-1), circuit_open_max_s)`，
//!    默认 30 → 60 → 120（封顶 120），只有**数据面确认成功**（`ok`）才复位退避级别。
//! 2. **探针与数据面解耦**：健康探针成功/失败走 [`SharedCircuit::probe_ok`] /
//!    [`SharedCircuit::probe_fail`]，**不再**计入 `fails`（打开判定只看数据面），
//!    探针失败只累加独立计数 `probe_fail`（配合 `UpstreamStats` 的失败率惩罚降权重）。
//! 3. **「全部熔断」可观测**：[`SharedCircuit::note_all_open`] 记录兜底放行次数与被放行的
//!    上游 id 列表，供 `/api/status.counters.breaker_all_open` 与日志使用。
//!
//! [`SharedCircuit`] 为 `Arc` 可共享句柄：Resolver 与生产 [`crate::production::ProductionQuerier`]
//! 共享同一套熔断态，热路径记录成功/失败、选择上游时跳过打开态。

use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// 指数退避的最大翻倍次数（2^4 = 16 倍后不再翻倍，仍受 `circuit_open_max_s` 封顶）。
const OPEN_BACKOFF_MAX_SHIFT: u32 = 4;

/// 单个上游的熔断状态。
#[derive(Clone, Debug)]
pub struct CircuitState {
    pub fails: u32,
    /// 打开截止时刻（epoch 秒）；0 = 未打开。
    pub until: f64,
    /// 连续打开次数（指数退避指数；任何 `ok`/`probe_ok` 复位为 0）。
    pub open_count: u32,
    /// 健康探针成功次数（独立计数，与数据面 `fails` 解耦）。
    pub probe_ok: u64,
    /// 健康探针失败次数（独立计数；**不**触发熔断打开）。
    pub probe_fail: u64,
}

impl Default for CircuitState {
    fn default() -> Self {
        Self {
            fails: 0,
            until: 0.0,
            open_count: 0,
            probe_ok: 0,
            probe_fail: 0,
        }
    }
}

/// 熔断只读视图（供 `/api/upstreams` 展示）。
#[derive(Clone, Copy, Debug, Default)]
pub struct CbView {
    /// 连续（数据面）失败数。
    pub fails: u32,
    /// 打开剩余秒数（未打开 = 0）。
    pub until_in_s: f64,
    /// 连续打开次数。
    pub open_count: u32,
    /// 探针成功/失败累计。
    pub probe_ok: u64,
    pub probe_fail: u64,
}

/// 可共享的熔断器集合。parking_lot 短临界区，持锁不 await。
#[derive(Default)]
pub struct SharedCircuit {
    map: Mutex<HashMap<String, CircuitState>>,
    /// 「全部上游处于打开态 → 兜底放行」累计次数（优化项 6 的可观测计数）。
    all_open: AtomicU64,
    /// 最近一次兜底放行的上游 id 列表（诊断用）。
    last_all_open: Mutex<Vec<String>>,
}

impl SharedCircuit {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// 记录一次**数据面**失败：fails++，达阈值则按连续打开次数指数退避打开。
    ///
    /// `open_s` = 首次打开窗口；`max_open_s` = 退避封顶（`<= open_s` 时退化为固定窗口）。
    ///
    /// **每次失败都刷新窗口**（`until = now + win`），但 `open_count` 仍**只在
    /// 「未打开 → 打开」转移时** +1（`until <= now` 判定）。两处语义缺一不可：
    ///
    /// 1. 刷新窗口修的是 2.1.8 的既有缺陷：旧实现在 `until <= now` 成立时才写
    ///    `until`，于是**同一 `now` 下的第 2、3 次失败**（`fails_threshold=3` 的
    ///    同一批并发失败）只把 `fails` 加到 3 却不再刷新窗口 —— 若前两次失败与
    ///    第三次之间已经跨过了一个窗口（`circuit_open_s` 很小时极易发生），末次
    ///    失败后 `until` 可能**已经过期** ⇒ `is_open=false`，熔断根本没打开，
    ///    失败上游继续被派发。回归用例见
    ///    `tests/adv218_breaker.rs::probe_ok_resets_backoff_and_until_then_next_round_starts_at_base_window`。
    /// 2. 只有转移时才 `open_count += 1`：否则一个持续失败的上游会把退避级别
    ///    每失败一次就顶一级（实测 `open_count` 冲到 ~400，计数完全失真），
    ///    也与"熔断窗口按连续打开次数指数退避"的语义相悖。
    pub fn fail(&self, uid: &str, now: f64, fails_threshold: u32, open_s: f64, max_open_s: f64) {
        let mut g = self.map.lock();
        let s = g.entry(uid.to_string()).or_default();
        s.fails = s.fails.saturating_add(1);
        if s.fails < fails_threshold {
            return;
        }
        // 退避级别只在「未打开 → 打开」转移时递增（`until <= now` = 当前未打开）。
        if s.until <= now {
            s.open_count = s.open_count.saturating_add(1);
        }
        let shift = s.open_count.saturating_sub(1).min(OPEN_BACKOFF_MAX_SHIFT);
        let factor = 1u32 << shift;
        let cap = if max_open_s.is_finite() && max_open_s > 0.0 {
            max_open_s.max(open_s)
        } else {
            open_s
        };
        let win = (open_s * f64::from(factor)).min(cap);
        // 每次失败都刷新窗口：末次失败之后窗口必然还有 `win` 秒，`is_open` 必为 true。
        // `win` 非有限/<=0 时退化为 `open_s`（生产路径不得 panic，也不得写出 NaN）。
        let win = if win.is_finite() && win > 0.0 {
            win
        } else {
            open_s
        };
        s.until = now + win;
    }

    /// 记录一次数据面成功：复位失败计数、打开态与退避级别。
    pub fn ok(&self, uid: &str) {
        if let Some(s) = self.map.lock().get_mut(uid) {
            s.fails = 0;
            s.until = 0.0;
            s.open_count = 0;
        }
    }

    /// 健康探针成功：累加独立计数，并**立即恢复**（清打开态与退避级别）。
    ///
    /// 这是主动半开探测的落点：探针证明上游可用即不再等退避窗口自然过期。
    pub fn probe_ok(&self, uid: &str) -> bool {
        let mut g = self.map.lock();
        let s = g.entry(uid.to_string()).or_default();
        s.probe_ok = s.probe_ok.saturating_add(1);
        let recovered = s.until > 0.0 || s.fails > 0;
        s.fails = 0;
        s.until = 0.0;
        s.open_count = 0;
        recovered
    }

    /// 健康探针失败：只累加独立计数，**不**计入 `fails`、**不**打开熔断。
    ///
    /// 返回当前探针失败累计（供日志/断言）。
    pub fn probe_fail(&self, uid: &str) -> u64 {
        let mut g = self.map.lock();
        let s = g.entry(uid.to_string()).or_default();
        s.probe_fail = s.probe_fail.saturating_add(1);
        s.probe_fail
    }

    /// 是否处于打开态（until 未过期）。
    pub fn is_open(&self, uid: &str, now: f64) -> bool {
        match self.map.lock().get(uid) {
            Some(s) => s.until > now,
            None => false,
        }
    }

    /// 只读熔断视图（`now` 为单调秒，与喂点同口径）。
    pub fn view(&self, uid: &str, now: f64) -> CbView {
        let g = self.map.lock();
        match g.get(uid) {
            Some(s) => CbView {
                fails: s.fails,
                until_in_s: (s.until - now).max(0.0),
                open_count: s.open_count,
                probe_ok: s.probe_ok,
                probe_fail: s.probe_fail,
            },
            None => CbView::default(),
        }
    }

    /// 记录一次「全部上游打开 → 兜底放行」并保存被放行的 id 列表。
    ///
    /// 返回累计次数（调用方据此打 `tracing::warn!`，只在此处计数，避免双计）。
    pub fn note_all_open(&self, ids: &[String]) -> u64 {
        *self.last_all_open.lock() = ids.to_vec();
        self.all_open.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// 「全部熔断兜底放行」累计次数（`/api/status.counters.breaker_all_open`）。
    pub fn all_open_count(&self) -> u64 {
        self.all_open.load(Ordering::Relaxed)
    }

    /// 最近一次兜底放行的上游 id 列表。
    pub fn last_all_open_ids(&self) -> Vec<String> {
        self.last_all_open.lock().clone()
    }

    /// 当前处于打开态的上游 id（`now` 为单调秒）。
    pub fn open_ids(&self, now: f64) -> Vec<String> {
        let g = self.map.lock();
        let mut v: Vec<String> = g
            .iter()
            .filter(|(_, s)| s.until > now)
            .map(|(k, _)| k.clone())
            .collect();
        v.sort();
        v
    }

    /// 仅保留 `keep` 中的上游条目（reload 时清理已删除上游的死条目）。
    pub fn retain(&self, keep: &HashSet<String>) {
        self.map.lock().retain(|k, _| keep.contains(k));
    }

    /// 清空（reset_runtime_state 对称清理）。
    // >>> 242B BEGIN P1-8-breaker >>> //
    pub fn clear(&self) {
        self.map.lock().clear();
        self.last_all_open.lock().clear();
        // **2.1.42-B（P1-8）**：累计量也是"运行时状态"，reset 必须一并归零，
        // 否则 `/api/reset` 后 `counters.breaker_all_open` 仍显示历史值。
        self.all_open.store(0, Ordering::Relaxed);
    }
    // <<< 242B END P1-8-breaker <<< //

    /// 测试：读熔断器条目。
    pub fn get(&self, uid: &str) -> Option<CircuitState> {
        self.map.lock().get(uid).cloned()
    }

    /// 测试：注入熔断器死条目。
    pub fn inject(&self, uid: &str, fails: u32, until: f64) {
        self.map.lock().insert(
            uid.to_string(),
            CircuitState {
                fails,
                until,
                ..Default::default()
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_window_backs_off_exponentially_and_caps() {
        let cb = SharedCircuit::default();
        let now = 1000.0;
        // 第 1 次打开：open_s=30 → until = now+30。
        for _ in 0..3 {
            cb.fail("u", now, 3, 30.0, 120.0);
        }
        assert!((cb.get("u").unwrap().until - (now + 30.0)).abs() < 1e-6);
        assert_eq!(cb.get("u").unwrap().open_count, 1);
        // 打开期间继续失败：**窗口刷新**（缺陷 4 修复：末次失败后必然仍在打开态），
        // 但 `open_count` 不增加（退避级别不被失真）。
        for _ in 0..5 {
            cb.fail("u", now + 1.0, 3, 30.0, 120.0);
        }
        assert!(
            (cb.get("u").unwrap().until - (now + 1.0 + 30.0)).abs() < 1e-6,
            "每次失败都刷新窗口：until = 末次失败 + open_s"
        );
        assert_eq!(cb.get("u").unwrap().open_count, 1);
        assert!(cb.is_open("u", now + 1.0), "末次失败后必须处于打开态");
        // 窗口过期后再失败 → 第 2 次打开：60（退避级别只在转移时递增）。
        let now2 = now + 1.0 + 31.0;
        cb.fail("u", now2, 3, 30.0, 120.0);
        assert!((cb.get("u").unwrap().until - (now2 + 60.0)).abs() < 1e-6);
        assert_eq!(cb.get("u").unwrap().open_count, 2);
        // 第 3 次打开：120（= cap）。
        let now3 = now2 + 61.0;
        cb.fail("u", now3, 3, 30.0, 120.0);
        assert!((cb.get("u").unwrap().until - (now3 + 120.0)).abs() < 1e-6);
        // 第 4 次打开：仍封顶 120，不再翻倍。
        let now4 = now3 + 121.0;
        cb.fail("u", now4, 3, 30.0, 120.0);
        assert!((cb.get("u").unwrap().until - (now4 + 120.0)).abs() < 1e-6);
        assert_eq!(cb.get("u").unwrap().open_count, 4);
        // 成功复位退避级别。
        cb.ok("u");
        let now5 = now4 + 1.0;
        for _ in 0..3 {
            cb.fail("u", now5, 3, 30.0, 120.0);
        }
        assert!((cb.get("u").unwrap().until - (now5 + 30.0)).abs() < 1e-6);
        assert_eq!(cb.get("u").unwrap().open_count, 1);
    }

    #[test]
    fn probe_failures_never_open_circuit() {
        let cb = SharedCircuit::default();
        let now = 500.0;
        for _ in 0..50 {
            cb.probe_fail("u");
        }
        assert!(!cb.is_open("u", now), "探针失败不得打开熔断（解耦）");
        assert_eq!(cb.get("u").unwrap().fails, 0, "探针失败不计入数据面 fails");
        assert_eq!(cb.view("u", now).probe_fail, 50);
    }

    #[test]
    fn probe_ok_recovers_open_circuit_immediately() {
        let cb = SharedCircuit::default();
        let now = 500.0;
        for _ in 0..3 {
            cb.fail("u", now, 3, 30.0, 120.0);
        }
        assert!(cb.is_open("u", now + 1.0));
        assert!(cb.probe_ok("u"), "打开态探针成功应报告已恢复");
        assert!(!cb.is_open("u", now + 1.0));
        assert_eq!(cb.view("u", now + 1.0).probe_ok, 1);
        assert_eq!(cb.get("u").unwrap().open_count, 0);
        // 打开态但探针成功时（未处于打开窗口内）不报告恢复。
        assert!(!cb.probe_ok("u2"), "本来就没打开/没失败 → 不算恢复");
    }

    #[test]
    fn all_open_fallback_is_counted_and_ids_recorded() {
        let cb = SharedCircuit::default();
        assert_eq!(cb.all_open_count(), 0);
        let ids = vec!["a".to_string(), "b".to_string()];
        assert_eq!(cb.note_all_open(&ids), 1);
        assert_eq!(cb.note_all_open(&ids), 2);
        assert_eq!(cb.all_open_count(), 2);
        assert_eq!(cb.last_all_open_ids(), ids);
    }

    #[test]
    fn open_ids_lists_only_open_entries() {
        let cb = SharedCircuit::default();
        let now = 10.0;
        cb.inject("open", 3, now + 5.0);
        cb.inject("expired", 3, now - 5.0);
        assert_eq!(cb.open_ids(now), vec!["open".to_string()]);
    }
}
