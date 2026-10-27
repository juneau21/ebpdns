//! pollsim —— 轮询请求数仿真（native，无需 wasm/浏览器）。
//!
//! 关键点：**不是重新实现一遍策略**，而是 `include!` 前端运行时使用的同一份
//! `web/src/poll_policy.rs`（`Scheduler`/`Ep`/`RouteId`/`Delta`），用假时钟驱动它
//! 统计「单位时间 /api/* 请求数」。因此仿真数字与前端运行时的调度逐字一致，可复算：
//!
//! ```text
//! cd <repo>/tools/pollsim && cargo run --release
//! ```
//!
//! 「2.1.6 改前」基线由 `Legacy` 转写自 2.1.6 `web/src/poll.rs` 的四条独立循环
//! （status 恒 2s；snapshot 恒 5s 且**不按路由**；logs/pipeline 仅流水线页；各循环
//! 「先 sleep 再拉」，隐藏时只睡不拉），并在同一驱动条件下统计。

/// 前端运行时同一份策略源码（`#[path]` 直接按模块加载同一份文件；
/// 用 `#[path]` 而非 `include!`，这样文件顶部的 `//!` 模块文档注释也合法）。
#[path = "../../../web/src/poll_policy.rs"]
mod policy;

/// 纯数值/展示助手（同一份源码，用于核对显示效果改动）。
#[path = "../../../web/src/fmtnum.rs"]
mod fmtnum;

use fmtnum::{group0, lat_auto, trunc};
use policy::*;

/* ======================= 基线：2.1.6 的四条独立循环 ======================= */

/// 2.1.6 `web/src/poll.rs` 的调度行为（逐条转写）。
struct Legacy {
    next: [u64; 4],
    /// status 连续失败次数（2.1.6 的 2s/5s/10s/30s 退避表）。
    status_fails: u32,
}

impl Legacy {
    /// 各循环都是「先 sleep 再拉」：首个请求在 base 之后。
    fn new(now: u64) -> Self {
        Legacy {
            next: [
                now + Ep::Status.base_ms() as u64,
                now + Ep::Snapshot.base_ms() as u64,
                now + Ep::Pipeline.base_ms() as u64,
                now + Ep::Logs.base_ms() as u64,
            ],
            status_fails: 0,
        }
    }

    /// 隐藏时四条循环都只 `continue`（不取数、不推进到期时间）。
    fn due(&mut self, route: RouteId, hidden: bool, now: u64, failing: bool) -> Vec<Ep> {
        let mut out = Vec::new();
        for ep in Ep::ALL {
            let i = ep.idx();
            if hidden || now < self.next[i] {
                continue;
            }
            // 2.1.6：`ms = match fails { 0|1 => 2s, 2 => 5s, 3 => 10s, _ => 30s }`
            //（只有 status 有退避；其余三条循环失败时仍按固定 5s 重试）。
            let iv: u64 = if failing && ep == Ep::Status {
                self.status_fails += 1;
                match self.status_fails {
                    1 => 2_000,
                    2 => 5_000,
                    3 => 10_000,
                    _ => 30_000,
                }
            } else {
                ep.base_ms() as u64
            };
            self.next[i] = now + iv;
            let gated = match ep {
                Ep::Logs | Ep::Pipeline => route != RouteId::Pipeline,
                _ => false,
            };
            if !gated {
                out.push(ep);
            }
        }
        out
    }
}

/* ======================= 统计 ======================= */

#[derive(Clone, Copy, Default)]
struct Counts([u64; 4]);

impl Counts {
    fn add(&mut self, ep: Ep) {
        self.0[ep.idx()] += 1;
    }
    fn total(&self) -> u64 {
        self.0.iter().sum()
    }
    fn get(&self, ep: Ep) -> u64 {
        self.0[ep.idx()]
    }
}

/// 仿真条件。
#[derive(Clone, Copy)]
struct Scenario {
    name: &'static str,
    route: RouteId,
    secs: u64,
    /// 有流量（数据每轮都变化）→ 不降频；否则空闲 → 逐档降频。
    active: bool,
    /// 后端不可达（每轮都失败）→ 走失败退避。
    failing: bool,
    /// 隐藏窗口（秒）：`Some((from, to))` 表示该区间内标签页不可见。
    hidden: Option<(u64, u64)>,
}

/// 改后：用运行时同一份 `Scheduler`（boot 另有 `/api/config` 一次，计入 status 桶以对齐口径）。
fn sim_new(s: &Scenario) -> Counts {
    let mut sched = Scheduler::new(0);
    let mut c = Counts::default();
    let mut t: u64 = 0;
    while t <= s.secs * 1000 {
        let hid = s.hidden.map(|(a, b)| t >= a * 1000 && t < b * 1000).unwrap_or(false);
        if !hid {
            let due = sched.due(s.route, t);
            for ep in &due {
                c.add(*ep);
            }
            for ep in due {
                let d = if s.failing {
                    Delta::Failed
                } else if s.active {
                    Delta::Changed
                } else {
                    Delta::Same
                };
                sched.note(ep, d, t);
            }
        }
        t += 100;
    }
    c.add(Ep::Status); // boot 首拉 /api/config
    c
}

/// 改前：2.1.6 四条循环；boot 另有 `/api/config` + `/api/status` 各一次。
fn sim_legacy(s: &Scenario) -> Counts {
    let mut l = Legacy::new(0);
    let mut c = Counts::default();
    let mut t: u64 = 0;
    while t <= s.secs * 1000 {
        let hid = s.hidden.map(|(a, b)| t >= a * 1000 && t < b * 1000).unwrap_or(false);
        for ep in l.due(s.route, hid, t, s.failing) {
            c.add(ep);
        }
        t += 100;
    }
    c.add(Ep::Status); // boot 首拉 /api/status
    c.add(Ep::Status); // boot 首拉 /api/config（同属 /api/*，为可比计入 status 桶）
    c
}

/* ======================= 输出 ======================= */

fn main() {
    println!("=== pollsim · ebpdns 2.1.7 轮询请求数仿真（同一份 poll_policy.rs）===\n");

    // ---- 纯策略性质断言（改后的调度语义） ----
    let mut s = Scheduler::new(0);
    let d1 = s.due(RouteId::Pipeline, 0);
    let d2 = s.due(RouteId::Pipeline, 0);
    assert_eq!(d1.len(), 3, "流水线页首 tick 应为 status+pipeline+logs");
    assert!(d2.is_empty(), "同一 tick 内同一端点不得重复请求");
    let mut s2 = Scheduler::new(0);
    assert_eq!(s2.due(RouteId::Query, 0), vec![Ep::Status], "查询页只轮询 status");
    let mut s3 = Scheduler::new(0);
    assert_eq!(s3.due(RouteId::Telemetry, 0), vec![Ep::Status, Ep::Snapshot]);
    let mut s4 = Scheduler::new(0);
    let _ = s4.due(RouteId::Pipeline, 0);
    for ep in Ep::ALL {
        s4.note(ep, Delta::Same, 0);
    }
    assert_eq!(s4.interval_of(Ep::Status), 4_000, "空闲 1 档 → 4s");
    for ep in Ep::ALL {
        s4.note(ep, Delta::Same, 4_000);
    }
    assert_eq!(s4.interval_of(Ep::Status), 8_000, "空闲 2 档 → 8s（封顶）");
    for ep in Ep::ALL {
        s4.note(ep, Delta::Same, 8_000);
    }
    assert_eq!(s4.interval_of(Ep::Logs), 20_000, "日志空闲封顶 20s");
    s4.kick(20_000);
    assert_eq!(s4.interval_of(Ep::Status), 2_000, "交互/回前台 → 复位基准");
    assert!(s4.due(RouteId::Pipeline, 20_000).len() == 3, "kick 后立即补一轮");
    // 失败退避：status 连续失败逐档放大到 32s（覆盖 2.1.6 的 2s/5s/10s/30s），
    // 其余端点 5s→…→80s（2.1.6 这三条循环失败时完全不退避）。
    let mut s5 = Scheduler::new(0);
    for (i, want) in [4_000u32, 8_000, 16_000, 32_000, 32_000].iter().enumerate() {
        s5.note(Ep::Status, Delta::Failed, 0);
        assert_eq!(s5.interval_of(Ep::Status), *want, "status 失败第 {} 次退避", i + 1);
    }
    for (i, want) in [10_000u32, 20_000, 40_000, 80_000, 80_000].iter().enumerate() {
        s5.note(Ep::Logs, Delta::Failed, 0);
        assert_eq!(s5.interval_of(Ep::Logs), *want, "logs 失败第 {} 次退避", i + 1);
    }
    s5.note(Ep::Status, Delta::Changed, 0);
    assert_eq!(s5.interval_of(Ep::Status), 2_000, "成功后退避立即复位");
    println!("[OK] 策略性质: 同 tick 去重 / 按需路由 / 空闲降频(2s→4s→8s, 5s→10s→20s) / kick 升频");
    println!("[OK] 失败退避: status 2s→4s→8s→16s→32s 封顶; logs 5s→10s→20s→40s→80s 封顶; 成功即复位\n");

    // ---- 显示效果（同一份 fmtnum.rs） ----
    println!("[显示] group0(1234567)={} group0(4096)={}", group0(1234567.0), group0(4096.0));
    println!("[显示] lat_auto(0.42)={:?} lat_auto(12.34)={:?} lat_auto(1500.0)={:?}", lat_auto(0.42), lat_auto(12.34), lat_auto(1500.0));
    println!("[显示] trunc(\"a-very-long-domain-name.example.com\", 20)={}\n", trunc("a-very-long-domain-name.example.com", 20));

    // ---- 场景对比 ----
    let scenarios = [
        Scenario { name: "流水线页 · 有流量", route: RouteId::Pipeline, secs: 60, active: true, failing: false, hidden: None },
        Scenario { name: "遥测页 · 有流量", route: RouteId::Telemetry, secs: 60, active: true, failing: false, hidden: None },
        Scenario { name: "查询页 · 有流量", route: RouteId::Query, secs: 60, active: true, failing: false, hidden: None },
        Scenario { name: "配置页 · 有流量", route: RouteId::Config, secs: 60, active: true, failing: false, hidden: None },
        Scenario { name: "架构页 · 有流量", route: RouteId::About, secs: 60, active: true, failing: false, hidden: None },
        Scenario { name: "流水线页 · 空闲(无变化)", route: RouteId::Pipeline, secs: 60, active: false, failing: false, hidden: None },
        Scenario { name: "遥测页 · 空闲(无变化)", route: RouteId::Telemetry, secs: 60, active: false, failing: false, hidden: None },
        Scenario { name: "流水线页 · 后端不可达(全失败)", route: RouteId::Pipeline, secs: 60, active: false, failing: true, hidden: None },
        Scenario { name: "流水线页 · 30s可见+30s后台+30s可见", route: RouteId::Pipeline, secs: 90, active: true, failing: false, hidden: Some((30, 60)) },
    ];

    println!("| 场景(60s 窗口, 后台 30s 场景为 90s) | 2.1.6 请求数 | 2.1.7 请求数 | 降幅 | 2.1.6 明细 st/sn/pl/lg | 2.1.7 明细 st/sn/pl/lg |");
    println!("|---|---|---|---|---|---|");
    for sc in scenarios.iter() {
        let a = sim_legacy(sc);
        let b = sim_new(sc);
        let drop = if a.total() == 0 { 0.0 } else { (1.0 - b.total() as f64 / a.total() as f64) * 100.0 };
        println!(
            "| {} | {} | {} | {:.0}% | {}/{}/{}/{} | {}/{}/{}/{} |",
            sc.name,
            a.total(),
            b.total(),
            drop,
            a.get(Ep::Status),
            a.get(Ep::Snapshot),
            a.get(Ep::Pipeline),
            a.get(Ep::Logs),
            b.get(Ep::Status),
            b.get(Ep::Snapshot),
            b.get(Ep::Pipeline),
            b.get(Ep::Logs),
        );
    }

    // ---- 每分钟均值汇总 ----
    println!("\n每分钟 /api/* 请求数（请求数 / 分钟）:");
    for sc in scenarios.iter() {
        let a = sim_legacy(sc);
        let b = sim_new(sc);
        let mins = sc.secs as f64 / 60.0;
        println!(
            "  {:<38} 2.1.6 {:>6.1}/min   2.1.7 {:>6.1}/min",
            sc.name,
            a.total() as f64 / mins,
            b.total() as f64 / mins
        );
    }

    // ---- 渲染代理指标：每 tick 状态写入次数 ----
    println!("\n每 tick 状态写入次数（渲染代理指标，越小越好）:");
    println!("  2.1.6 status tick: mode + uptime_text + token_status + status = 4 次写 / 2s");
    println!("        另: snapshot tick 1 次 / 5s（与 status 交错 → 2 次独立渲染时机 / 5s 窗口）");
    println!("  2.1.7 status tick: status 1 次 + (mode/token 仅在变化时写) = 1 次 / 2s(空闲 8s)");
    println!("        另: snapshot/pipeline/logs 与本 tick 的 status 合并为同一次渲染时机");
    println!("        页脚时钟: 本地 1s 外推（0 次网络请求）");
}
