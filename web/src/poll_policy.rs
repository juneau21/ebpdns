//! 轮询调度策略（纯逻辑：不依赖 wasm / web-sys / leptos）——「统一 2s + 按需 + 去重」。
//!
//! 设计目标（v2.1.32 / poll2s）：
//! 1. **单一 2s 节拍**：`TICK_MS = 2000`，整个前端只有一个 `TimeoutFuture` 调度循环；
//!    每次 tick 只拉取当前路由按需的端点，同一 tick 内每端点至多一次。
//! 2. **按需**：`/api/status` 全局；`/api/snapshot` 仅遥测页；`/api/pipeline` 与
//!    `/api/logs` 仅流水线页。切页立刻补一轮，离开的页面不再发请求。
//! 3. **失败退避**：连续失败按 2s→4s→8s→16s→30s 倍增封顶（`BACKOFF_MAX_MS`），
//!    任一成功立即回到 2s；退避只影响该端点，不改变全局 2s 节拍。
//! 4. **可见性**：标签页隐藏时调度循环只等可见性通知、不取数；回前台立即补一轮。
//!
//! 本文件被 `web/src/poll.rs`（前端运行时）与 `tools/pollsim`（native 仿真统计）
//! 同时使用：仿真直接 `#[path]` 引入本文件、以假时钟驱动同一份代码。
//! **注意**：`tools/pollsim` 里仍写着 v2.1.7 的「空闲降频 / 32s / 80s」断言，
//! 本次按要求只改 `web/`，该开发工具需在后续单独同步（不影响产品构建）。

/// 路由标识（与 `state::Route` 一一对应；本文件不引入 leptos，故另立枚举）。
///
/// **2.1.14**：`Rules` 变体随「规则管理」页一并删除（该页从未挂载、且编译不过）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteId {
    Pipeline,
    Query,
    Config,
    Telemetry,
    About,
}

/// 受调度的后端端点。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ep {
    Status,
    Snapshot,
    Pipeline,
    Logs,
}

impl Ep {
    pub const ALL: [Ep; 4] = [Ep::Status, Ep::Snapshot, Ep::Pipeline, Ep::Logs];

    pub fn idx(self) -> usize {
        match self {
            Ep::Status => 0,
            Ep::Snapshot => 1,
            Ep::Pipeline => 2,
            Ep::Logs => 3,
        }
    }

    /// 统一基准间隔：所有端点都是 2s（poll2s）。
    pub fn base_ms(self) -> u32 {
        TICK_MS
    }

    /// **按需**：该端点是否需要在当前路由上轮询。
    pub fn needed_on(self, route: RouteId) -> bool {
        match self {
            Ep::Status => true,
            Ep::Snapshot => route == RouteId::Telemetry,
            Ep::Pipeline | Ep::Logs => route == RouteId::Pipeline,
        }
    }
}

/// 前端唯一调度节拍：2000ms。
pub const TICK_MS: u32 = 2_000;

/// 网络失败退避上限：30s（2s→4s→8s→16s→30s 封顶）。
pub const BACKOFF_MAX_MS: u32 = 30_000;

/// 失败退避的倍增档位上限（2^4 × 2s = 32s，再由 [`BACKOFF_MAX_MS`] 截到 30s）。
pub const FAIL_SHIFT_CAP: u32 = 4;

/// 连续失败 `streak` 次后的重试间隔（2s 倍增，封顶 30s）。
pub fn fail_interval_ms(fail_streak: u32) -> u32 {
    let shift = fail_streak.min(FAIL_SHIFT_CAP);
    TICK_MS.saturating_mul(1u32 << shift).min(BACKOFF_MAX_MS)
}

/// 一次请求的结果类别（决定退避/认证失效）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delta {
    /// 数据有变化 → 失败计数清零，保持 2s。
    Changed,
    /// 数据无变化 → 失败计数清零，保持 2s（不再空闲降频）。
    Same,
    /// 请求失败（非 401）→ 失败计数 +1，按 [`fail_interval_ms`] 退避。
    Failed,
    /// 401：认证失效，调用方停机并切配置页。
    AuthFail,
}

/// 端点调度器（纯状态机，时间单位统一为毫秒单调时钟）。
#[derive(Clone, Debug)]
pub struct Scheduler {
    next_due: [u64; 4],
    fails: [u32; 4],
    in_flight: [bool; 4],
    last_route: Option<RouteId>,
}

impl Scheduler {
    /// 新建调度器：全部端点立即到期（首屏第一轮）。
    pub fn new(now_ms: u64) -> Self {
        Scheduler {
            next_due: [now_ms; 4],
            fails: [0; 4],
            in_flight: [false; 4],
            last_route: None,
        }
    }

    /// 本 tick 需要请求的端点（**每端点至多一次**，仅含当前路由按需且在途为假的）。
    pub fn due(&mut self, route: RouteId, now_ms: u64) -> Vec<Ep> {
        if self.last_route != Some(route) {
            self.last_route = Some(route);
            for ep in Ep::ALL {
                if ep.needed_on(route) {
                    self.next_due[ep.idx()] = now_ms;
                }
            }
        }
        let mut out = Vec::new();
        for ep in Ep::ALL {
            let i = ep.idx();
            if !ep.needed_on(route) || self.in_flight[i] {
                continue;
            }
            if self.next_due[i] <= now_ms {
                self.in_flight[i] = true;
                out.push(ep);
            }
        }
        out
    }

    /// 回填一次请求结果并安排下次到期时间。
    ///
    /// `tick_ms` 必须是**本 tick 的计划时刻**（不是请求完成时刻），否则「完成时刻 +
    /// 2s」会把下一次到期推到下下个 tick，实际间隔变成 4s。
    pub fn note(&mut self, ep: Ep, delta: Delta, tick_ms: u64) {
        let i = ep.idx();
        self.in_flight[i] = false;
        match delta {
            Delta::Changed | Delta::Same => {
                self.fails[i] = 0;
                self.next_due[i] = tick_ms.saturating_add(ep.base_ms() as u64);
            }
            Delta::Failed => {
                self.fails[i] = self.fails[i].saturating_add(1);
                let wait = fail_interval_ms(self.fails[i]) as u64;
                self.next_due[i] = tick_ms.saturating_add(wait);
            }
            Delta::AuthFail => {
                // 停机路径：时间不再重要，置到远期避免被再次调度。
                self.next_due[i] = tick_ms.saturating_add(BACKOFF_MAX_MS as u64);
            }
        }
    }

    /// 交互 / 回到前台 / 手动刷新：全部立即到期 + 失败计数归零。
    pub fn kick(&mut self, now_ms: u64) {
        for i in 0..4 {
            self.fails[i] = 0;
            self.next_due[i] = now_ms;
        }
    }

    /// 当前端点实际间隔（失败退避时取退避档位，否则 2s）。
    pub fn interval_of(&self, ep: Ep) -> u32 {
        let i = ep.idx();
        if self.fails[i] > 0 {
            fail_interval_ms(self.fails[i])
        } else {
            ep.base_ms()
        }
    }

    /// 是否有端点处于失败退避（页脚提示用）。
    pub fn backing_off(&self, route: RouteId) -> bool {
        Ep::ALL
            .iter()
            .any(|ep| ep.needed_on(route) && self.fails[ep.idx()] > 0)
    }

    /// 页脚节奏文案：正常 `2s`；有端点退避时 `退避 {最长间隔}s`。
    pub fn cadence_text(&self, route: RouteId) -> String {
        if !self.backing_off(route) {
            return "2s".into();
        }
        let mut worst = TICK_MS;
        for ep in Ep::ALL {
            if !ep.needed_on(route) {
                continue;
            }
            worst = worst.max(self.interval_of(ep));
        }
        format!("退避 {:.0}s", worst as f64 / 1000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_endpoints_tick_at_two_seconds() {
        for ep in Ep::ALL {
            assert_eq!(ep.base_ms(), 2_000, "{ep:?}");
            assert_eq!(Scheduler::new(0).interval_of(ep), 2_000, "{ep:?}");
        }
    }

    #[test]
    fn one_request_per_endpoint_per_tick() {
        let mut s = Scheduler::new(0);
        let first = s.due(RouteId::Pipeline, 0);
        assert_eq!(
            first,
            vec![Ep::Status, Ep::Pipeline, Ep::Logs],
            "流水线页首 tick 只应有三个按需端点"
        );
        assert!(s.due(RouteId::Pipeline, 0).is_empty(), "同 tick 不得重复");
        for ep in first {
            s.note(ep, Delta::Same, 0);
        }
        assert!(s.due(RouteId::Pipeline, 1_999).is_empty(), "未到 2s");
        assert_eq!(s.due(RouteId::Pipeline, 2_000).len(), 3, "2s 后整轮");
    }

    #[test]
    fn failure_backoff_doubles_to_30s_then_recovers() {
        let mut s = Scheduler::new(0);
        let want = [4_000u32, 8_000, 16_000, 30_000, 30_000];
        for w in want {
            s.note(Ep::Status, Delta::Failed, 0);
            assert_eq!(s.interval_of(Ep::Status), w, "失败退避应倍增封顶 30s");
        }
        s.note(Ep::Status, Delta::Changed, 0);
        assert_eq!(s.interval_of(Ep::Status), 2_000, "成功后立即回 2s");
        assert!(!s.backing_off(RouteId::Pipeline));
    }

    #[test]
    fn route_switch_refreshes_only_new_route() {
        let mut s = Scheduler::new(0);
        let _ = s.due(RouteId::Pipeline, 0);
        for ep in Ep::ALL {
            s.note(ep, Delta::Same, 0);
        }
        assert_eq!(
            s.due(RouteId::Telemetry, 10),
            vec![Ep::Status, Ep::Snapshot],
            "遥测页不应拉 pipeline/logs"
        );
        assert_eq!(s.due(RouteId::Query, 20), vec![Ep::Status]);
    }

    #[test]
    fn kick_makes_everything_due_again() {
        let mut s = Scheduler::new(0);
        let _ = s.due(RouteId::Pipeline, 0);
        for ep in Ep::ALL {
            s.note(ep, Delta::Same, 0);
        }
        s.kick(500);
        assert_eq!(s.due(RouteId::Pipeline, 500).len(), 3);
    }
}
