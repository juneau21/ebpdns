//! 2.1.8 对抗性审查单测（熔断器，只读审查附带证明用例）。
//!
//! 目标：
//! - 指数退避只在「未打开 → 打开」转移时递增 `open_count`（并发压力下验证）；
//! - `probe_ok` 恢复后 `open_count` 归零、`until` 清空；
//! - `probe_fail` 在任何并发路径下都不打开熔断；
//! - `until` 与主动半开探测的交互（探针成功 → 立即恢复，不等窗口过期）；
//! - `retain` 清理已删除上游；`view` 在过期后 `until_in_s` 归零（不为负）。

use std::collections::HashSet;

use ebpdns_resolver::breaker::SharedCircuit;

#[test]
fn open_count_increments_only_on_transition_under_concurrency() {
    let cb = SharedCircuit::new();
    let now = 1000.0;
    // 16 线程 × 20 次 fail，全部落在同一时间点：只有第一次应发生「未打开 → 打开」。
    let mut hs = Vec::new();
    for _ in 0..16 {
        let cb = cb.clone();
        hs.push(std::thread::spawn(move || {
            for _ in 0..20 {
                cb.fail("u", now, 3, 30.0, 120.0);
            }
        }));
    }
    for h in hs {
        h.join().unwrap();
    }
    let s = cb.get("u").unwrap();
    assert!(s.fails >= 3, "fail 计数不得丢失: {}", s.fails);
    assert_eq!(s.open_count, 1, "打开期间再失败不得增加 open_count");
    assert!(
        (s.until - (now + 30.0)).abs() < 1e-6,
        "打开期间再失败必须把窗口刷新到「末次失败 + open_s」: until={}",
        s.until
    );
}

#[test]
fn probe_ok_resets_backoff_and_until_then_next_round_starts_at_base_window() {
    let cb = SharedCircuit::new();
    let mut now = 1000.0;
    // 连续 3 轮打开 → open_count 3，窗口 30/60/120（退避级别只在「未打开→打开」转移时 +1）。
    let mut win = 30.0f64;
    for i in 0..3 {
        for _ in 0..3 {
            cb.fail("u", now, 3, 30.0, 120.0);
        }
        let s = cb.get("u").unwrap();
        assert_eq!(
            s.open_count,
            i + 1,
            "第 {} 轮必须恰好发生一次「未打开→打开」转移",
            i + 1
        );
        assert!(
            (s.until - (now + win)).abs() < 1e-6,
            "第 {} 轮窗口必须 = 末次失败时刻 + {}s（每次失败都刷新）: until={}",
            i + 1,
            win,
            s.until
        );
        assert!(
            cb.is_open("u", now),
            "第 {} 轮末次失败后必须在打开态",
            i + 1
        );
        // 跨过本窗口（严格越过终点），才能进入下一轮退避。
        now += win + 1.0;
        win = (win * 2.0).min(120.0);
    }
    // 复位后再次打开 → 回到基础窗口 30s（不是 120s）。
    assert!(cb.probe_ok("u"), "打开态探针成功应报告已恢复");
    assert!(!cb.is_open("u", now));
    assert_eq!(cb.get("u").unwrap().open_count, 0);
    for _ in 0..3 {
        cb.fail("u", now, 3, 30.0, 120.0);
    }
    assert!(
        (cb.get("u").unwrap().until - (now + 30.0)).abs() < 1e-6,
        "probe_ok 复位后必须回到基础窗口"
    );
}

/// **缺陷 4 回归锁（2.1.11）**：`SharedCircuit::fail` 必须**每次失败都刷新窗口**。
///
/// 旧实现只在 `until <= now` 成立时写 `until`：一旦熔断已经打开（`until > now`），
/// 打开期间继续到来的失败**既不刷新窗口也不加 open_count** —— 于是"持续失败"的上游
/// 反而会在窗口自然到期后**自动关闭熔断**（`is_open=false`），继续被派发。
///
/// 时序构造（`open_s=30`，全部时间点都在同一窗口内）：
/// - `t=1000` 3 次失败 → 打开，`until=1030`，`open_count=1`；
/// - `t=1020`（窗口内）再失败 → 新实现刷新到 `until=1050`；旧实现保持 1030；
/// - `t=1040`（旧实现的窗口已过期）再失败。
///   * **新实现**：`until=1070 > 1040` ⇒ `is_open=true`（持续失败的上游保持熔断）；
///   * **旧实现**：`until` 仍是 1030（`1030 <= 1040` 时为真但会重新 `open_count+=1`
///     → 记成第 2 轮次而不是「窗口内的失败」）⇒ 本用例在旧实现下对
///     `t=1020` 那一步的 `until` 断言即失败。
#[test]
fn fail_refreshes_until_on_every_failure_while_open() {
    let cb = SharedCircuit::new();
    // t=1000：3 次失败 → 打开（until=1030, open_count=1）。
    for _ in 0..3 {
        cb.fail("u", 1000.0, 3, 30.0, 120.0);
    }
    let s = cb.get("u").unwrap();
    assert_eq!(s.open_count, 1);
    assert!((s.until - 1030.0).abs() < 1e-9);

    // t=1020：窗口内再失败一次 → 窗口必须刷新到 1050（旧实现保持在 1030）。
    cb.fail("u", 1020.0, 3, 30.0, 120.0);
    let s = cb.get("u").unwrap();
    assert_eq!(
        s.open_count, 1,
        "窗口内再失败不得增加 open_count（退避级别只在转移时递增）"
    );
    assert!(
        (s.until - 1050.0).abs() < 1e-9,
        "缺陷 4：每次失败都必须刷新窗口，旧实现会停在 1030：until={}",
        s.until
    );
    assert!(
        cb.is_open("u", 1040.0),
        "窗口被刷新后 t=1040 必须仍在打开态"
    );

    // t=1040：再来一次 → 刷新到 1070；持续失败的上游**不得**在 1050 处自动闭合。
    cb.fail("u", 1040.0, 3, 30.0, 120.0);
    let s = cb.get("u").unwrap();
    assert!((s.until - 1070.0).abs() < 1e-9, "until={}", s.until);
    assert_eq!(s.open_count, 1, "仍是同一轮打开，open_count 不得增长");
    assert!(
        cb.is_open("u", 1060.0),
        "持续失败期间熔断必须在 1060 仍为打开态（旧实现此时已自动闭合）"
    );
}

#[test]
fn probe_fail_never_opens_even_with_many_threads() {
    let cb = SharedCircuit::new();
    let mut hs = Vec::new();
    for _ in 0..16 {
        let cb = cb.clone();
        hs.push(std::thread::spawn(move || {
            for _ in 0..100 {
                cb.probe_fail("u");
            }
        }));
    }
    for h in hs {
        h.join().unwrap();
    }
    assert_eq!(cb.get("u").unwrap().probe_fail, 1600);
    assert_eq!(
        cb.get("u").unwrap().fails,
        0,
        "探针失败不得污染数据面 fails"
    );
    assert!(!cb.is_open("u", 9_999_999.0), "探针失败永不打开熔断");
}

/// `until_in_s` 边界：窗口过期后必须为 0（不得为负）；窗口内为正且单调递减。
#[test]
fn view_until_in_s_is_clamped_non_negative() {
    let cb = SharedCircuit::new();
    cb.inject("u", 3, 1000.0 + 10.0);
    let v = cb.view("u", 1000.0);
    assert!((v.until_in_s - 10.0).abs() < 1e-9);
    let v2 = cb.view("u", 1010.0);
    assert_eq!(v2.until_in_s, 0.0, "有效但已过期 → 0（不得为负）");
    let v3 = cb.view("u", 999_999.0);
    assert_eq!(v3.until_in_s, 0.0);
    // 不存在的上游 → 全零视图（不 panic、不建条目）。
    let d = cb.view("nope", 1000.0);
    assert_eq!(d.fails, 0);
    assert_eq!(d.until_in_s, 0.0);
    assert!(cb.get("nope").is_none(), "只读 view 不得建条目");
}

/// `retain` 清理已删除上游；被保留的开放态条目不受影响。
#[test]
fn retain_drops_removed_upstreams_only() {
    let cb = SharedCircuit::new();
    cb.inject("keep", 3, 1e9);
    cb.inject("drop", 3, 1e9);
    let mut keep = HashSet::new();
    keep.insert("keep".to_string());
    cb.retain(&keep);
    assert!(cb.get("keep").is_some());
    assert!(cb.get("drop").is_none(), "已删除上游的熔断条目必须清掉");
    assert_eq!(cb.open_ids(1000.0), vec!["keep".to_string()]);
}

/// **已修（2.1.11）**：`/api/upstreams` 的投影必须来自**同一次加锁读**。
///
/// 缺陷（2.1.8 起）：`api.rs` 对同一上游分两次加锁读取（先 `cb_is_open`、后 `cb_view`）
/// 再派生 `selectable`；两次读之间若发生「探针成功恢复」（`background.rs` 的半开探测），
/// 同一响应里就会出现 `breaker_open=true, until_in_s=0, fails=0, circuit_open_count=0`
/// 的自相矛盾快照（反向的「数据面失败打开熔断」则给出
/// `breaker_open=false, selectable=true, until_in_s>0`）。
///
/// 修复后 `breaker_open` 由**同一份** `view()` 快照的 `until_in_s` 派生
/// （`until_in_s > 0.0` 与旧 `is_open(uid, now)` 逐位等价：同一个 `now`、同一个 `until`，
/// IEEE754 减法保序），因此矛盾组合在构造上不可能出现。
///
/// 用例名沿用 2.1.8 的登记名以保持追溯链；断言已改为修复后的**不变量**。
/// 端到端（真实 `upstream_views` + 并发喂点）回归在
/// `crates/ebpdns-server/src/api.rs::upstream_views_breaker_fields_come_from_one_snapshot`。
#[test]
fn api_projection_can_emit_self_contradictory_snapshot() {
    let cb = SharedCircuit::new();
    let now = 1000.0;
    for _ in 0..3 {
        cb.fail("u", now, 3, 30.0, 120.0);
    }

    // api.rs 修复后的读取顺序：**一次**加锁读，所有熔断字段同源派生。
    let project = |cb: &SharedCircuit, now: f64| {
        let v = cb.view("u", now); // 唯一的加锁读
        let breaker_open = v.until_in_s > 0.0; // == cb.is_open("u", now)，但不二次加锁
        let selectable = true && !breaker_open; // enabled 恒为 true（本用例）
        (
            breaker_open,
            v.until_in_s,
            selectable,
            v.fails,
            v.open_count,
        )
    };

    let before = project(&cb, now);
    // 打开态：fails=3（达阈值）、窗口 30s、open_count=1。
    assert_eq!(before, (true, 30.0, false, 3, 1));

    // ---- 响应生成期间被并发改动：健康探针成功（生产路径 background.rs:167）----
    assert!(cb.probe_ok("u"));

    let after = project(&cb, now);
    assert_eq!(after, (false, 0.0, true, 0, 0));

    // 关键不变量：任何一次快照内 breaker_open ⇔ until_in_s > 0，且 selectable == !breaker_open。
    for (open, until_in_s, selectable, fails, open_count) in [before, after] {
        assert_eq!(
            open,
            until_in_s > 0.0,
            "breaker_open 必须由同一份快照的 until_in_s 派生（open={open} until_in_s={until_in_s} fails={fails} open_count={open_count}）"
        );
        assert_eq!(
            selectable, !open,
            "selectable 必须与同一份快照的 breaker_open 互补（selectable={selectable} open={open}）"
        );
    }
    // 旧实现产出的两种矛盾组合，在单快照投影下都不可能出现。
    assert_ne!(
        before,
        (true, 0.0, true, 0, 0),
        "两次加锁的陈旧组合不得复现"
    );
    assert_ne!(
        after,
        (false, 30.0, true, 3, 1),
        "两次加锁的反向陈旧组合不得复现"
    );
    // 单次 view 的 until_in_s 与 is_open 在同一时刻必须一致（api 投影的等价性前提）。
    assert_eq!(cb.view("u", now).until_in_s > 0.0, cb.is_open("u", now));
}
