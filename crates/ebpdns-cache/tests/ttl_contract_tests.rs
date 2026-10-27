//! **2.1.18（修复项 17）：DNS TTL 契约 —— 恢复不得重新锚定 TTL**。
//!
//! 缺陷（部署代理隔离实测）：夹具 TTL=20s、优雅停 → 文件 5200 条 → **停 25 秒**
//! （已超过原 TTL）→ 启动 → **5200/5200 全命中**。根因是
//! `lru.rs::restore_refs` 在 `persist_ttl == 0` 且文件里有 `remaining` 时执行
//! `expires_at = now + remaining`（把"剩余时长"当成**新窗口**重新计时）。
//!
//! 裁决：**DNS TTL 是与下游客户的契约，缓存不得比原 TTL 活得久**。
//! 本文件的用例把新口径钉死：
//! ①绝对 `expires_at` 优先（停机时长计入 TTL），已过期 ⇒ 丢弃；
//! ②旧格式（只有 `remaining`、无绝对到期时间）⇒ **安全侧丢弃**（不重新锚定）；
//! ③`persist_ttl > 0` 是**剩余 TTL 上限（cap）**：只可能缩短，不可能延长。

use ebpdns_cache::{CacheAnswer, CacheEntry, CacheKey, DnsCache, LruCache, TinyLfuCache};
use serde_json::{json, Value};

/// 构造一条"文件里的记录"：`expires_at` 绝对到期（epoch 秒），可选带 `remaining`。
fn rec(key: &str, expires_at: f64, with_abs: bool) -> Value {
    // `CacheEntry` 没有 `Default`（字段全是必填的真值），逐字段构造。
    let e = CacheEntry {
        domain: key.to_string(),
        qtype: "A".to_string(),
        answers: vec![CacheAnswer {
            value: "1.2.3.4".to_string(),
            ttl: 20.0,
            rtype: 1,
            name: None,
        }],
        chosen: "1.2.3.4".to_string(),
        ttl: 20.0,
        rcode: 0,
        expires_at,
        rule_gen: 0,

        seq: 0,
    };
    let mut v = serde_json::to_value(&e).unwrap();
    let m = v.as_object_mut().unwrap();
    m.insert("key".to_string(), json!([key.to_string(), "A".to_string()]));
    // 旧版本文件只有 remaining；新版本两者都有。
    m.insert(
        "remaining".to_string(),
        json!((expires_at - 1000.0).max(0.0)),
    );
    if !with_abs {
        m.remove("expires_at");
    }
    v
}

/// **E9b**：停机时长 > 剩余 TTL ⇒ 必须**丢弃**（不得 `now + remaining` 重新锚定）。
#[test]
fn restore_respects_absolute_expiry_across_downtime() {
    let c = LruCache::new(1024);
    let now = 10_000.0;
    // 文件的绝对到期 = 9_980（已过 20 秒）⇒ 停机期间到期，必须丢弃。
    let entries = [rec("expired.test.", 9_980.0, true)];
    let refs: Vec<&Value> = entries.iter().collect();
    c.restore_refs(&refs, now, 0.0);
    assert_eq!(
        c.len(),
        0,
        "已过绝对到期时间的条目必须被丢弃（不得重新锚定）"
    );
    // 反向：绝对到期在未来 ⇒ 保留，且 expires_at **不被重写**。
    let c2 = LruCache::new(1024);
    let entries2 = [rec("alive.test.", 10_005.0, true)];
    let refs2: Vec<&Value> = entries2.iter().collect();
    c2.restore_refs(&refs2, now, 0.0);
    assert_eq!(c2.len(), 1, "未到期条目必须恢复");
    let got = c2
        .get(&CacheKey::new("alive.test.", "A"), now)
        .expect("命中");
    assert!(
        (got.expires_at - 10_005.0).abs() < 1e-6,
        "恢复必须保留文件里的绝对 expires_at（实测 {}）",
        got.expires_at
    );
}

/// **D8**：旧格式（剥掉绝对 `expires_at`、只留 `remaining`）⇒ 丢弃（安全侧）。
#[test]
fn restore_drops_legacy_remaining_only_records() {
    let c = LruCache::new(1024);
    let entries = [rec("legacy.test.", 10_500.0, false)];
    let refs: Vec<&Value> = entries.iter().collect();
    c.restore_refs(&refs, 10_000.0, 0.0);
    assert_eq!(
        c.len(),
        0,
        "旧格式（无绝对到期时间）必须按安全侧丢弃，不得用 remaining 重新计时"
    );
}

/// **`persist_ttl > 0` = 用户显式 opt-in 的"统一恢复 TTL"**：
/// 所有恢复条目一律用 `now + persist_ttl`（**不做 cap**），因此它**会**让缓存
/// 比原 TTL 活得更久 —— 这是配置页/README 明确标注过的知情选择。
#[test]
fn persist_ttl_opt_in_unifies_restored_ttl() {
    let now = 10_000.0;
    // ① 绝对到期已在过去（停机期间过期），但用户显式给了 persist_ttl=300
    //    ⇒ 按"统一 TTL"恢复（opt-in 延长的语义）。
    let c = LruCache::new(1024);
    let entries = [rec("expired.test.", now - 100.0, true)];
    let refs: Vec<&Value> = entries.iter().collect();
    c.restore_refs(&refs, now, 300.0);
    let e = c
        .get(&CacheKey::new("expired.test.", "A"), now)
        .expect("opt-in 延长 ⇒ 恢复为 now+300");
    assert!(
        (e.expires_at - (now + 300.0)).abs() < 1e-6,
        "persist_ttl>0 必须统一到 now+persist_ttl（实测 {}）",
        e.expires_at
    );
    // ② 绝对到期更近（+10s）⇒ 同样被"统一"到 now+300（显式选择，文档已警示）。
    let c2 = LruCache::new(1024);
    let entries2 = [rec("short.test.", now + 10.0, true)];
    let refs2: Vec<&Value> = entries2.iter().collect();
    c2.restore_refs(&refs2, now, 300.0);
    let e2 = c2
        .get(&CacheKey::new("short.test.", "A"), now)
        .expect("命中");
    assert!(
        (e2.expires_at - (now + 300.0)).abs() < 1e-6,
        "persist_ttl>0 是显式 opt-in：统一 TTL（实测 {}）",
        e2.expires_at
    );
}

/// **集成口径**：TTL=20s、停 25s、`persist_ttl=0` ⇒ 恢复后命中率必须为 0
/// （对应部署代理"命中率应 ≤10%"的判据；此用例是更严的 0）。
#[test]
fn twenty_second_ttl_surviving_twenty_five_second_downtime_yields_zero_hits() {
    let stop_at = 1_000_000.0;
    let entries: Vec<Value> = (0..200)
        .map(|i| rec(&format!("f{i}.test."), stop_at + 20.0, true))
        .collect();
    let refs: Vec<&Value> = entries.iter().collect();
    let c = LruCache::new(4096);
    // 停机 25 秒后恢复（> 20s TTL）。
    let now = stop_at + 25.0;
    c.restore_refs(&refs, now, 0.0);
    assert_eq!(c.len(), 0, "全部条目在停机期间过期 ⇒ 一条都不该恢复");
    let hits = (0..200)
        .filter(|i| {
            c.get(&CacheKey::new(format!("f{i}.test."), "A"), now)
                .is_some()
        })
        .count();
    assert_eq!(hits, 0, "重启后命中率必须为 0（实测 {hits}/200）");
}

/* ================= 2.1.18（修复项 23）：丢弃分支可观测量 + opt-in 命中率 ================= */

/// **项 2**：旧格式文件（只有 `remaining`、无绝对 `expires_at`）⇒ 必须走"丢弃 + WARN"分支。
///
/// 断言方式：读 [`ebpdns_cache::lru::last_restore_drops`]（与 `tracing::warn!` 在**同一个
/// 代码块**里赋值）。为什么不用 `tracing` subscriber 抓日志：测试环境没有全局订阅者时
/// 抓取会**假通过**（拿到空串），而计数断言直接钉住"分支被走到"，更硬。
#[test]
fn legacy_format_restore_takes_the_drop_and_warn_branch() {
    let entries = [
        rec("legacy.test.", 10_500.0, false),
        rec("legacy2.test.", 10_500.0, false),
    ];
    let refs: Vec<&Value> = entries.iter().collect();
    let c = LruCache::new(256);
    c.restore_refs(&refs, 10_000.0, 0.0);
    assert_eq!(c.len(), 0, "旧格式必须丢弃（安全侧）");
    let (expired, legacy, failed) = c.last_restore_drops();
    assert_eq!(
        legacy, 2,
        "必须走 legacy 丢弃分支（该分支同时打 WARN『已丢弃 N 条』）"
    );
    assert_eq!(expired, 0, "本用例不应有绝对到期丢弃");
    // 旧格式**不是**损坏：`expired` / `legacy` / `failed` 三类必须分开计数（2.1.19 起）。
    // 断言消息里不写版本号 —— 版本只应出现在根 `Cargo.toml`（门禁：`_version_consistency.py`）。
    assert_eq!(failed, 0, "旧格式**不是**损坏：两类必须分开计数");
}

/// **项 1（cache 侧对应分支）**：绝对到期已过 ⇒ 走"丢弃 + INFO 汇总"分支。
#[test]
fn expired_restore_takes_the_drop_and_info_branch() {
    let entries = [rec("exp.test.", 9_000.0, true)];
    let refs: Vec<&Value> = entries.iter().collect();
    let c = LruCache::new(256);
    c.restore_refs(&refs, 10_000.0, 0.0);
    assert_eq!(c.len(), 0);
    let (expired, legacy, failed) = c.last_restore_drops();
    assert_eq!(
        expired, 1,
        "必须走 expired 丢弃分支（该分支同时打 INFO 汇总）"
    );
    assert_eq!(
        legacy, 0,
        "绝对到期已过**不是**旧格式（2.1.19 起两类分开计数）"
    );
    assert_eq!(failed, 0);
}

/* ============ 2.1.19（修复项 1）：旧格式判定**前移** + 三策略同源 + 不依赖 tracing ============ */

/// **2.1.19 修复项 1（本版最高优先）**：`persist_ttl > 0` 时旧格式条目**同样**必须
/// 被丢弃并计数 —— 2.1.19 把判定挂在 `if pt <= 0.0` 之内，`pt > 0` 时旧格式会被
/// `now + persist_ttl` **复活**（违反"旧格式只能安全侧丢弃"的契约），且不计数。
#[test]
fn legacy_format_is_dropped_even_when_persist_ttl_is_positive() {
    let entries = [
        rec("legacy-pt.test.", 10_500.0, false),
        rec("legacy-pt2.test.", 10_500.0, false),
    ];
    let refs: Vec<&Value> = entries.iter().collect();
    let c = LruCache::new(256);
    // persist_ttl = 3600（显式 opt-in 延长）：旧格式仍然不得被复活。
    c.restore_refs(&refs, 10_000.0, 3600.0);
    assert_eq!(
        c.len(),
        0,
        "旧格式条目在 persist_ttl>0 时也不得被复活（2.1.19 缺陷：被 now+pt 重新计时）"
    );
    let (expired, legacy, failed) = c.last_restore_drops();
    assert_eq!(
        legacy, 2,
        "persist_ttl>0 时旧格式同样必须计数（WARN 含条数）"
    );
    assert_eq!((expired, failed), (0, 0));
}

/// **2.1.19 修复项 1**：`tinylfu` 是**出厂默认策略**（`cache_policy=tinylfu`）⇒
/// 它必须有与 `lru` 逐项一致的旧格式丢弃 + 计数（2.1.19 该分支只有裸 `continue`，
/// 既不计数也不打日志 —— 这才是生产上"计数恒 0 / WARN 不触发"的真实根因）。
#[test]
fn tinylfu_drops_and_counts_legacy_records_like_lru() {
    for pt in [0.0_f64, 3600.0] {
        let entries = [
            rec("tlf-legacy.test.", 10_500.0, false),
            rec("tlf-legacy2.test.", 10_500.0, false),
        ];
        let c = TinyLfuCache::new(256);
        // `TinyLfuCache` 的恢复入口就是 `DnsCache::restore`（无借用切片变体）。
        c.restore(&entries, 10_000.0, pt);
        assert_eq!(c.len(), 0, "tinylfu: 旧格式必须丢弃（persist_ttl={pt}）");
        let (expired, legacy, failed) = c.last_restore_drops();
        assert_eq!(legacy, 2, "tinylfu 必须计数旧格式丢弃（persist_ttl={pt}）");
        assert_eq!((expired, failed), (0, 0), "tinylfu: 本用例不应有其它类丢弃");
    }
}

/// **2.1.19 修复项 1**：损坏记录（既无绝对到期、也无 `remaining`）与旧格式**分开计数**
/// —— 2.1.19 两者都落在"静默丢弃"，运维无法区分"文件被截断"与"版本较旧"。
#[test]
fn corrupt_records_are_counted_separately_from_legacy() {
    let mut bad = rec("corrupt.test.", 10_500.0, true);
    // 同时去掉绝对到期与 remaining ⇒ 既不是旧格式、也不可用。
    {
        let m = bad.as_object_mut().unwrap();
        m.remove("expires_at");
        m.remove("remaining");
    }
    let entries = [bad, rec("legacy-mix.test.", 10_500.0, false)];
    let refs: Vec<&Value> = entries.iter().collect();
    let c = LruCache::new(256);
    c.restore_refs(&refs, 10_000.0, 0.0);
    assert_eq!(c.len(), 0);
    let (expired, legacy, failed) = c.last_restore_drops();
    assert_eq!(
        (expired, legacy, failed),
        (0, 1, 1),
        "损坏 vs 旧格式必须分开计数"
    );
}

/// **2.1.19 修复项 1**：`PartitionedCache` 是**委托路径**（按 group 分组后调内层
/// `LruCache::restore_refs`）⇒ 计数必须**聚合**回来，否则"换策略即失去可观测性"。
#[test]
fn partitioned_cache_aggregates_legacy_drops() {
    use ebpdns_cache::PartitionedCache;
    // 3 元组 key（带 group 前缀）——正是 PartitionedCache 的文件格式。
    let mk = |g: &str, d: &str| {
        let mut v = rec(d, 10_500.0, false);
        v.as_object_mut()
            .unwrap()
            .insert("key".to_string(), json!([g, d, "A"]));
        v
    };
    let entries = [mk("default", "p1.test."), mk("default", "p2.test.")];
    let c = PartitionedCache::new(256, None);
    c.restore(&entries, 10_000.0, 0.0);
    let (_e, legacy, _f) = c.last_restore_drops();
    assert_eq!(
        legacy, 2,
        "PartitionedCache 必须把各分区的旧格式丢弃计数聚合出来"
    );

    // **2.1.19（修复项 1 补漏）**：分组阶段就被跳过的条目（key 非数组 / 长度非法）
    // 从未进入任何分区 ⇒ 必须显式计入 `failed`，否则又是静默丢弃。
    let mut bad_key = rec("p3.test.", 10_500.0, true);
    bad_key
        .as_object_mut()
        .unwrap()
        .insert("key".into(), json!("p3.test."));
    let mut bad_len = rec("p4.test.", 10_500.0, true);
    bad_len
        .as_object_mut()
        .unwrap()
        .insert("key".into(), json!(["only"]));
    let c2 = PartitionedCache::new(256, None);
    c2.restore(&[bad_key, bad_len], 10_000.0, 0.0);
    assert_eq!(
        c2.last_restore_drops().2,
        2,
        "分组阶段跳过的条目必须计入 failed（此前完全静默）"
    );
}

/* ===== 2.1.19（修复项 1 补漏）：四个曾静默的裸 continue + 文件级损坏的"说谎" ===== */

/// **2.1.19（修复项 1 补漏）**：`restore_refs` 开头**四类结构不完整**此前是裸 `continue`
/// （实测 WARN=0、`failed=0`）⇒ 现在**逐类计数**并计入对外暴露的 `failed`。
///
/// 逐类各造一条：①`key` 不是数组；②`key` 长度非 2|3；③`domain`/`qtype` 取不出；
/// ④缺 `answers` 或 `rcode`。四类合计必须 == `failed`，且**每一类单独**都要被计数
/// （把 `failed` 拆成 4 个独立用例，任何一类回归都会被指名）。
#[test]
fn structural_incomplete_records_are_counted_not_silent() {
    // ① key 非数组
    let mut a = rec("s1.test.", 10_500.0, true);
    a.as_object_mut()
        .unwrap()
        .insert("key".into(), json!("s1.test."));
    // ② key 长度非 2|3
    let mut b = rec("s2.test.", 10_500.0, true);
    b.as_object_mut()
        .unwrap()
        .insert("key".into(), json!(["s2.test."]));
    // ③ domain/qtype 取不出（非字符串）
    let mut c = rec("s3.test.", 10_500.0, true);
    c.as_object_mut()
        .unwrap()
        .insert("key".into(), json!([123, 456]));
    // ④ 缺 answers
    let mut d = rec("s4.test.", 10_500.0, true);
    d.as_object_mut().unwrap().remove("answers");
    // ④b 缺 rcode
    let mut e = rec("s5.test.", 10_500.0, true);
    e.as_object_mut().unwrap().remove("rcode");

    for (label, bad) in [
        ("① key 非数组", a.clone()),
        ("② key 长度非法", b.clone()),
        ("③ domain/qtype 取不出", c.clone()),
        ("④a 缺 answers", d.clone()),
        ("④b 缺 rcode", e.clone()),
    ] {
        let refs = [&bad];
        let lru = LruCache::new(256);
        lru.restore_refs(&refs, 10_000.0, 0.0);
        assert_eq!(lru.len(), 0, "{label}: 必须被丢弃");
        let (exp, leg, failed) = lru.last_restore_drops();
        assert_eq!(
            (exp, leg, failed),
            (0, 0, 1),
            "{label}: 必须计入 failed=1（此前 WARN=0 且 failed=0 —— 静默丢弃）"
        );
        // tinylfu 同源：同一份夹具必须给出同一结果（否则"换策略就换语义"）。
        let tlf = TinyLfuCache::new(256);
        tlf.restore(&[bad], 10_000.0, 0.0);
        assert_eq!(
            tlf.last_restore_drops(),
            (0, 0, 1),
            "{label}: tinylfu 必须与 lru 同口径"
        );
    }

    // 四类混在一起 ⇒ `failed` == 总条数（一个都不能漏）。
    let all = [a, b, c, d, e];
    let refs: Vec<&Value> = all.iter().collect();
    let lru = LruCache::new(256);
    lru.restore_refs(&refs, 10_000.0, 0.0);
    assert_eq!(
        lru.last_restore_drops().2,
        5,
        "5 条结构不完整记录必须全部计入 failed（不得漏计）"
    );
}

/// **2.1.19（修复项 1 补漏：部署代理实测的"说谎"缺陷）**：**整个文件不可解析**时
/// per-entry 的 `restore()` 根本不会被调用 ⇒ 内层计数会保留**上一次**的值。
/// 外壳 `SwappableCache` 的文件级记录必须让 `last_restore_drops()` 反映**本次**结果。
///
/// 判据（不依赖 `tracing` 订阅者，纯计数）：
/// ①先做一次"真损坏"恢复 ⇒ `failed == 1`（陈旧值）；
/// ②再模拟文件级失败（`record_file_level_restore_failure(1)`）⇒ 必须仍是"本次"的
///   `failed == 1` 而**不是**旧的 per-entry 明细；
/// ③随后一次真正的 `restore()` 必须**清掉**文件级记录（否则又是新的说谎方式）。
#[test]
fn file_level_failure_overrides_stale_per_entry_counts() {
    use ebpdns_cache::SwappableCache;
    use std::sync::Arc;

    let inner: Arc<dyn DnsCache> = Arc::new(LruCache::new(256));
    let sw = SwappableCache::new(inner);

    // ① 先制造一个"上一次 restore"的陈旧结果：2 条旧格式 + 1 条损坏。
    let mut corrupt = rec("fl-corrupt.test.", 10_500.0, true);
    corrupt.as_object_mut().unwrap().remove("answers");
    let stale = [rec("fl-legacy.test.", 10_500.0, false), corrupt];
    sw.restore(&stale, 10_000.0, 0.0);
    assert_eq!(
        sw.last_restore_drops(),
        (0, 1, 1),
        "前置条件：per-entry 恢复应得 legacy=1 / failed=1"
    );

    // ② 文件级失败（整个文件不可解析）⇒ 必须是本次的 (0,0,1)，而不是陈旧的 (0,1,1)。
    sw.record_file_level_restore_failure(1);
    assert_eq!(
        sw.last_restore_drops(),
        (0, 0, 1),
        "文件级失败必须覆盖陈旧值：两端点此前会显示 failed:0（说谎）"
    );
    // `0` 也会被提升到 `1`（"整个文件"至少算一条不可用记录）。
    sw.record_file_level_restore_failure(0);
    assert_eq!(sw.last_restore_drops().2, 1, "文件级失败至少记 1");

    // ③ 一次真正的 restore 必须清掉文件级记录。
    sw.restore(&[], 10_000.0, 0.0);
    assert_eq!(
        sw.last_restore_drops(),
        (0, 0, 0),
        "真正的 per-entry 恢复后不得再返回文件级失败（新的说谎方式）"
    );

    // ④ 换成"文件不存在"路径：清理后同样是本次的 0,0,0。
    sw.record_file_level_restore_failure(1);
    sw.clear_file_level();
    assert_eq!(sw.last_restore_drops(), (0, 0, 0), "clear 后必须是本次的 0");
}

/// **项 3③**：`persist_ttl > 0` ⇒ 跨越同样停机（25s > 原 TTL 20s）仍应 **≥90% 命中**
/// （opt-in 统一 TTL）；`= 0` ⇒ 绝对到期（**≤10%**）。
#[test]
fn persist_ttl_opt_in_survives_downtime_while_zero_does_not() {
    let stop_at = 1_000_000.0;
    let n = 200usize;
    let entries: Vec<Value> = (0..n)
        .map(|i| rec(&format!("o{i}.test."), stop_at + 20.0, true))
        .collect();
    let refs: Vec<&Value> = entries.iter().collect();
    let now = stop_at + 25.0; // 停机 25s > 原 TTL 20s

    // opt-in：统一 TTL=3600 ⇒ 全部存活（≥90%）
    let c1 = LruCache::new(4096);
    c1.restore_refs(&refs, now, 3600.0);
    let hit1 = (0..n)
        .filter(|i| {
            c1.get(&CacheKey::new(format!("o{i}.test."), "A"), now)
                .is_some()
        })
        .count();
    assert!(
        hit1 * 100 >= n * 90,
        "persist_ttl>0 必须 ≥90% 命中（实测 {hit1}/{n}）"
    );

    // 默认：绝对到期 ⇒ ≤10%
    let c2 = LruCache::new(4096);
    c2.restore_refs(&refs, now, 0.0);
    let hit2 = (0..n)
        .filter(|i| {
            c2.get(&CacheKey::new(format!("o{i}.test."), "A"), now)
                .is_some()
        })
        .count();
    assert!(
        hit2 * 100 <= n * 10,
        "persist_ttl=0 必须 ≤10% 命中（实测 {hit2}/{n}）"
    );
}
