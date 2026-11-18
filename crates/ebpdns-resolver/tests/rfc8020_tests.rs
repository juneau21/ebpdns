//! **2.1.12 优化项 ①**：RFC 8020 父域 NXDOMAIN 推导体（负缓存复用扩展）的
//! 确定性回归测试。
//!
//! 覆盖（与交付清单一一对应）：
//! 1. 父 NXDOMAIN → 子域**直接** NXDOMAIN 且**零上游请求**（`upstream_zero_after_parent`）；
//! 2. **祖先不得被登记**（安全边界：`w1.qq.com` 的 NXDOMAIN 不得泛化到 `qq.com`）；
//! 3. SERVFAIL / REFUSED / 超时 / NODATA **都不登记**；
//! 4. TTL 过期后恢复查询（`neg_ttl_max` 夹取 + mock 时钟推进）；
//! 5. 超深域名不登记 / 超深查询不匹配（`rfc8020_max_labels`）；
//! 6. `rfc8020_infer=false` 时逐位等价 2.1.11（子域照旧发上游）；
//! 7. P2-B 一致：**预取链路不登记**；规则屏蔽的 NXDOMAIN 不登记；规则集变更立即失效；
//!    答案缓存（含负缓存）**优先于**推断。
//!
//! 全部确定性：脚本化上游 + mock 时钟，不联网 / 不起服 / 不加载内核态缓存。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use ebpdns_proto::constants::{RCODE_NOERROR, RCODE_NXDOMAIN, RCODE_SERVFAIL, TYPE_A};
use ebpdns_resolver::clock::MockClock;
use ebpdns_resolver::config::{ResolverConfig, UpstreamCfg};
use ebpdns_resolver::query::ParallelQuerier;
use ebpdns_resolver::resolve::ResolveOpts;
use ebpdns_resolver::telemetry::NoopTelemetry;
use ebpdns_resolver::types::{ResolveAnswer, UpstreamAnswer};
use ebpdns_resolver::Resolver;
use ebpdns_rules::{rule_from_json, RuleSource};
use parking_lot::Mutex;
use serde_json::json;

const EPOCH: f64 = 1_700_000_000.0;

/// NXDOMAIN 应答（不带 SOA → 负 TTL 走 `min(cfg.ttl, 60)` = 60s）。
fn nx(up: &str) -> UpstreamAnswer {
    UpstreamAnswer {
        rcode: Some(RCODE_NXDOMAIN),
        up_name: up.into(),
        ..Default::default()
    }
}

/// NOERROR 无答案（NODATA）。
fn nodata(up: &str) -> UpstreamAnswer {
    UpstreamAnswer {
        rcode: Some(RCODE_NOERROR),
        up_name: up.into(),
        ..Default::default()
    }
}

/// 传输失败 / 超时（`rcode=None`）。
fn fail(up: &str) -> UpstreamAnswer {
    UpstreamAnswer {
        rcode: None,
        up_name: up.into(),
        ..Default::default()
    }
}

/// 显式 rcode 的失败应答（SERVFAIL / REFUSED）。
fn rcode(up: &str, rc: u8) -> UpstreamAnswer {
    UpstreamAnswer {
        rcode: Some(rc),
        up_name: up.into(),
        ..Default::default()
    }
}

/// 脚本化应答处理器（**2.1.24**：抽成 alias，避免 `clippy::type_complexity`）。
type AnswerHandler = Box<dyn Fn(&str) -> Vec<UpstreamAnswer> + Send + Sync>;

/// 计数 + 脚本化 querier：记录每一次 `query_parallel` 的 `(qname, 上游 id 列表)`。
struct CountingQuerier {
    calls: Mutex<Vec<String>>,
    count: AtomicU64,
    handler: AnswerHandler,
}

impl CountingQuerier {
    fn new<F>(handler: F) -> Arc<Self>
    where
        F: Fn(&str) -> Vec<UpstreamAnswer> + Send + Sync + 'static,
    {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            count: AtomicU64::new(0),
            handler: Box::new(handler),
        })
    }
    fn calls(&self) -> Vec<String> {
        self.calls.lock().clone()
    }
    fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl ParallelQuerier for CountingQuerier {
    async fn query_parallel(
        &self,
        _ups: &[UpstreamCfg],
        qname: &str,
        _qtype: &str,
        _depth: u32,
    ) -> Vec<UpstreamAnswer> {
        self.calls.lock().push(qname.to_string());
        self.count.fetch_add(1, Ordering::Relaxed);
        (self.handler)(qname)
    }
}

/// 测试基座：2 个上游，quorum=2（单票即采纳，见 `quorum_threshold`），mock 时钟。
/// `infer` 显式设定 `rfc8020_infer`（`test_default` 里它是 `false` = 2.1.11 基线）。
fn base<F>(infer: bool, handler: F) -> (Arc<Resolver>, Arc<CountingQuerier>, Arc<MockClock>)
where
    F: Fn(&str) -> Vec<UpstreamAnswer> + Send + Sync + 'static,
{
    let ups = vec![UpstreamCfg::test_up("u1"), UpstreamCfg::test_up("u2")];
    let mut cfg = ResolverConfig::test_default(ups, vec![], 2);
    cfg.rfc8020_infer = infer;
    let q = CountingQuerier::new(handler);
    let clock = Arc::new(MockClock::new(EPOCH));
    let r = Resolver::new(cfg, Arc::new(NoopTelemetry), clock.clone(), q.clone());
    (r, q, clock)
}

/* ==================== 1. 父 NXDOMAIN → 子域零上游直答 ==================== */

#[tokio::test]
async fn parent_nxdomain_makes_child_nxdomain_with_zero_upstream() {
    let (r, q, _c) = base(true, |_| vec![nx("u1"), nx("u2")]);

    // 第 1 次：真 miss → 上游 → 采纳 NXDOMAIN → 登记「NXDOMAIN 域」。
    let r1 = r
        .clone()
        .resolve("nxd212.example", "A", ResolveOpts::default())
        .await;
    assert_eq!(r1.rcode, RCODE_NXDOMAIN, "父域首查必须 NXDOMAIN");
    assert!(!r1.hit, "首查是真 miss，不得标 hit");
    assert_eq!(q.count(), 1, "首查必须发一轮上游");
    assert_eq!(r.rfc8020_len(), 1, "采纳 NXDOMAIN 后必须登记 1 条");
    assert_eq!(r.rfc8020_registrations(), 1);
    assert_eq!(r.rfc8020_hits(), 0);

    // 第 2/3 次：**子域**（不同名字 → 答案缓存必然 miss）→ 推断直答，零上游。
    for child in ["a.nxd212.example", "b.c.nxd212.example"] {
        let res = r.clone().resolve(child, "A", ResolveOpts::default()).await;
        assert_eq!(res.rcode, RCODE_NXDOMAIN, "{child} 必须由推断判负");
        assert!(res.hit, "{child} 是本地负缓存复用 → hit=true");
        assert_eq!(res.up_name, "RFC8020 推断");
        assert!(
            res.ttl_left > 0.0 && res.ttl_left <= 60.0,
            "负 TTL 受 neg_ttl_max=60 夹取，实际 {}",
            res.ttl_left
        );
    }
    assert_eq!(
        q.count(),
        1,
        "推断路径**不得**发出任何上游请求（实际调用 {} 次）",
        q.count()
    );
    assert_eq!(q.calls(), vec!["nxd212.example".to_string()]);
    assert_eq!(r.rfc8020_hits(), 2);
}

/// qtype 无关：NXDOMAIN 是"名字不存在"，与 RR 类型无关 —— AAAA/MX 的子域查询同样直答。
#[tokio::test]
async fn rfc8020_inference_is_qtype_agnostic() {
    let (r, q, _c) = base(true, |_| vec![nx("u1"), nx("u2")]);
    let _ = r
        .clone()
        .resolve("qt.example", "A", ResolveOpts::default())
        .await;
    let res = r
        .clone()
        .resolve("a.qt.example", "AAAA", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_NXDOMAIN);
    assert_eq!(q.count(), 1, "AAAA 子域查询也不得发上游");
}

/* ==================== 2. 安全边界：祖先绝不登记 ==================== */

/// **安全边界（最关键）**：`w1.qq.com` 的 NXDOMAIN 只能证明 `w1.qq.com` 及其**子域**
/// 不存在；**不能**反推 `qq.com` / `com`（RFC 8020 只给"向下"的蕴含）。
/// 若实现去登记祖先链，则会退化成"一次随机子域 NXDOMAIN → 整个 `.com` 60s 判负"。
#[tokio::test]
async fn ancestors_are_never_registered() {
    let (r, q, _c) = base(true, |_| vec![nx("u1"), nx("u2")]);
    let _ = r
        .clone()
        .resolve("w1.qzone212.test", "A", ResolveOpts::default())
        .await;
    assert_eq!(r.rfc8020_len(), 1, "只登记被查询名本身");

    // 兄弟域：**不在** `w1.qzone212.test` 之下 → 不得由推断直答。
    // （顺序要紧：祖先一旦被登记，它们的子域就都会命中，故先查兄弟域。）
    let sib = r
        .clone()
        .resolve("w2.qzone212.test", "A", ResolveOpts::default())
        .await;
    assert!(!sib.hit, "兄弟域不是子域，不得由推断直答");

    // 祖先必须照旧发上游（并拿到它自己的 NXDOMAIN）。
    for anc in ["qzone212.test", "test"] {
        let res = r.clone().resolve(anc, "A", ResolveOpts::default()).await;
        assert_eq!(res.rcode, RCODE_NXDOMAIN);
        assert_ne!(
            res.up_name, "RFC8020 推断",
            "{anc} 是祖先，**不得**由推断直答"
        );
        assert!(!res.hit, "{anc} 必须真发上游");
    }
    assert_eq!(
        q.calls(),
        vec![
            "w1.qzone212.test".to_string(),
            "w2.qzone212.test".to_string(),
            "qzone212.test".to_string(),
            "test".to_string(),
        ],
        "祖先/兄弟域都必须真发上游"
    );
    assert_eq!(r.rfc8020_hits(), 0);
}

/* ==================== 3. 非 NXDOMAIN 永不登记 ==================== */

#[tokio::test]
async fn servfail_refused_timeout_and_nodata_never_register() {
    // SERVFAIL（上游返回 rcode=2）
    let (r, _q, _c) = base(true, |_| {
        vec![rcode("u1", RCODE_SERVFAIL), rcode("u2", RCODE_SERVFAIL)]
    });
    let res = r
        .clone()
        .resolve("sf212.example", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_SERVFAIL);
    assert_eq!(r.rfc8020_len(), 0, "SERVFAIL 不得登记");
    assert_eq!(r.rfc8020_registrations(), 0);

    // 超时 / 构造失败（rcode=None）
    let (r, _q, _c) = base(true, |_| vec![fail("u1"), fail("u2")]);
    let res = r
        .clone()
        .resolve("to212.example", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_SERVFAIL);
    assert_eq!(r.rfc8020_len(), 0, "超时不得登记");

    // REFUSED（rcode=5）—— 同为"无票"，不得当作 NXDOMAIN 证据。
    let (r, _q, _c) = base(true, |_| vec![rcode("u1", 5), rcode("u2", 5)]);
    let res = r
        .clone()
        .resolve("rf212.example", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_SERVFAIL);
    assert_eq!(r.rfc8020_len(), 0, "REFUSED 不得登记");

    // NODATA（NOERROR + 空答案段）
    let (r, _q, _c) = base(true, |_| vec![nodata("u1"), nodata("u2")]);
    let res = r
        .clone()
        .resolve("nd212.example", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_NOERROR);
    assert!(res.empty);
    assert_eq!(r.rfc8020_len(), 0, "NODATA 不得登记");
}

/// 规则屏蔽产生的 NXDOMAIN 是**本地策略**而非权威 NXDOMAIN → 不登记。
#[tokio::test]
async fn rule_block_nxdomain_is_not_registered() {
    let ups = vec![UpstreamCfg::test_up("u1"), UpstreamCfg::test_up("u2")];
    let mut cfg = ResolverConfig::test_default(ups, vec![], 2);
    cfg.rfc8020_infer = true;
    let mut obj = serde_json::Map::new();
    obj.insert("match".into(), json!("blocked212.example"));
    obj.insert("action".into(), json!("block"));
    cfg.rules = vec![rule_from_json(obj, RuleSource::Local).expect("rule")];
    let q = CountingQuerier::new(|_| vec![nx("u1"), nx("u2")]);
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(EPOCH)),
        q.clone(),
    );
    let res = r
        .clone()
        .resolve("blocked212.example", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_NXDOMAIN);
    assert_eq!(q.count(), 0, "规则屏蔽不发上游");
    assert_eq!(r.rfc8020_len(), 0, "规则屏蔽的 NXDOMAIN 不得登记");
}

/* ==================== 4. TTL 过期恢复 + P2-B 预取不登记 ==================== */

#[tokio::test]
async fn ttl_expiry_resumes_upstream_queries() {
    let (r, q, clock) = base(true, |_| vec![nx("u1"), nx("u2")]);
    let _ = r
        .clone()
        .resolve("exp212.example", "A", ResolveOpts::default())
        .await;
    let _ = r
        .clone()
        .resolve("a.exp212.example", "A", ResolveOpts::default())
        .await;
    assert_eq!(q.count(), 1, "有效期内零上游");

    // `test_default` 的 `serve_stale=false` → 过期即彻底失效（无 stale 窗口兜底）。
    // 子域负 TTL = min(cfg.ttl, 60) = 60s，推进 61s。
    clock.advance(61.0);
    let res = r
        .clone()
        .resolve("a.exp212.example", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_NXDOMAIN, "过期后仍应是真上游给的 NXDOMAIN");
    assert!(!res.hit, "过期后必须真发上游（不得继续推断直答）");
    assert_eq!(q.count(), 2, "TTL 过期后必须恢复上游查询");
    assert_eq!(r.rfc8020_hits(), 1, "只有过期前那一次推断命中");

    // 过期条目已被惰性清理：换一个**全新的**子域 → 必须再次真发上游
    // （若父条目还留在表里，这一步会被推断直答、不产生上游请求）。
    let fresh = r
        .clone()
        .resolve("b.exp212.example", "A", ResolveOpts::default())
        .await;
    assert!(!fresh.hit, "父条目过期后不得再推断");
    assert_eq!(q.count(), 3, "父条目过期 → 新子域照旧发上游");

    // 而刚刚重查过的子域已按**新证据**重新登记 → 它的子域可以零上游推断直答。
    let deep = r
        .clone()
        .resolve("z.a.exp212.example", "A", ResolveOpts::default())
        .await;
    assert!(deep.hit, "重新登记后的名字其子域应可推断直答");
    assert_eq!(deep.up_name, "RFC8020 推断");
    assert_eq!(q.count(), 3, "重新登记后仍是零上游");
}

/// 规则集指纹变化 → 推断表立即失效（P1-1 同口径：规则 CRUD 不等 TTL）。
#[tokio::test]
async fn rule_generation_change_invalidates_registry() {
    let (r, q, _c) = base(true, |_| vec![nx("u1"), nx("u2")]);
    let _ = r
        .clone()
        .resolve("gen212.example", "A", ResolveOpts::default())
        .await;
    let _ = r
        .clone()
        .resolve("a.gen212.example", "A", ResolveOpts::default())
        .await;
    assert_eq!(q.count(), 1);

    r.test_bump_gen();
    let res = r
        .clone()
        .resolve("a.gen212.example", "A", ResolveOpts::default())
        .await;
    assert!(!res.hit, "规则集指纹变化后不得再推断直答");
    assert_eq!(q.count(), 2, "规则集变化 → 立即回上游");
}

/// **P2-B 一致**：预取链路不写负缓存，**同样不登记** RFC 8020 域。
#[tokio::test]
async fn prefetch_path_never_registers() {
    let (r, _q, _c) = base(true, |_| vec![nx("u1"), nx("u2")]);
    let res = r
        .clone()
        .resolve_prefetch("pf212.example", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_NXDOMAIN);
    assert_eq!(r.rfc8020_len(), 0, "预取链路不得登记 RFC 8020 域");
    assert_eq!(r.rfc8020_registrations(), 0);
}

/* ==================== 5. 深度上限 ==================== */

#[tokio::test]
async fn over_deep_name_is_not_registered() {
    let ups = vec![UpstreamCfg::test_up("u1"), UpstreamCfg::test_up("u2")];
    let mut cfg = ResolverConfig::test_default(ups, vec![], 2);
    cfg.rfc8020_infer = true;
    cfg.rfc8020_max_labels = 4;
    let q = CountingQuerier::new(|_| vec![nx("u1"), nx("u2")]);
    let r = Resolver::new(
        cfg,
        Arc::new(NoopTelemetry),
        Arc::new(MockClock::new(EPOCH)),
        q.clone(),
    );
    // 5 标签 > 上限 4 → 不登记。
    let _ = r
        .clone()
        .resolve("a.b.c.d212.example", "A", ResolveOpts::default())
        .await;
    assert_eq!(r.rfc8020_len(), 0, "超深域名不得登记");
    let _ = r
        .clone()
        .resolve("x.a.b.c.d212.example", "A", ResolveOpts::default())
        .await;
    assert_eq!(q.count(), 2, "未登记 → 子域必须照旧发上游");

    // 4 标签（= 上限）→ 登记；但超过上限的查询**不匹配**。
    let _ = r
        .clone()
        .resolve("a.b.c212.example", "A", ResolveOpts::default())
        .await;
    assert_eq!(r.rfc8020_len(), 1, "恰好等于上限应登记");
    let res = r
        .clone()
        .resolve("z.a.b.c212.example", "A", ResolveOpts::default())
        .await;
    assert!(!res.hit, "5 标签查询超过上限 → 不得推断直答");
    assert_eq!(q.count(), 4, "超上限查询必须照旧发上游");
    let res = r
        .clone()
        .resolve("y.z.a.b.c212.example", "A", ResolveOpts::default())
        .await;
    assert!(!res.hit, "6 标签查询超过上限 → 不得推断直答");
    assert_eq!(q.count(), 5);
}

/* ==================== 6. 关闭时逐位等价 2.1.11 ==================== */

/// `rfc8020_infer=false`（`test_default` 的默认值）→ **零行为差异**：
/// 推断表恒空、子域照旧发上游、读数恒 0。
#[tokio::test]
async fn infer_disabled_is_equivalent_to_2_1_11() {
    let (r, q, _c) = base(false, |_| vec![nx("u1"), nx("u2")]);
    let _ = r
        .clone()
        .resolve("off212.example", "A", ResolveOpts::default())
        .await;
    let res = r
        .clone()
        .resolve("a.off212.example", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_NXDOMAIN);
    assert!(!res.hit, "关闭时子域必须走真上游（2.1.11 口径）");
    assert_eq!(res.up_name, "u1", "获胜上游应为脚本化的首个上游");
    assert_eq!(q.count(), 2, "关闭时每个名字各发一轮上游");
    assert_eq!(r.rfc8020_len(), 0);
    assert_eq!(r.rfc8020_hits(), 0);
    assert_eq!(r.rfc8020_registrations(), 0);

    // 关闭时**连登记入口都不执行**（即使上游给 NXDOMAIN）。
    for _ in 0..3 {
        let _ = r
            .clone()
            .resolve("off212b.example", "A", ResolveOpts::default())
            .await;
    }
    assert_eq!(r.rfc8020_len(), 0);
}

/* ==================== 7. 缓存优先 + reset 清理 ==================== */

/// 答案缓存（含负缓存）**永远优先**于推断：同名重复查询的 `hit` / `ttl_left` /
/// `up_name="缓存直答"` 口径与 2.1.11 完全一致（RFC 8020 只补"没进过缓存"的长尾）。
#[tokio::test]
async fn answer_cache_takes_precedence_over_inference() {
    let (r, q, _c) = base(true, |_| vec![nx("u1"), nx("u2")]);
    let _ = r
        .clone()
        .resolve("pri212.example", "A", ResolveOpts::default())
        .await;
    let again = r
        .clone()
        .resolve("pri212.example", "A", ResolveOpts::default())
        .await;
    assert_eq!(again.up_name, "缓存直答", "同名重复查询必须走负缓存");
    assert!(again.hit);
    assert_eq!(q.count(), 1);
    assert_eq!(r.rfc8020_hits(), 0, "缓存直答不占 RFC 8020 命中计数");
}

/// `/api/reset`（`reset_runtime_state`）必须同时清 RFC 8020 表。
#[tokio::test]
async fn reset_clears_rfc8020_registry() {
    let (r, q, _c) = base(true, |_| vec![nx("u1"), nx("u2")]);
    let _ = r
        .clone()
        .resolve("rst212.example", "A", ResolveOpts::default())
        .await;
    assert_eq!(r.rfc8020_len(), 1);
    r.reset_runtime_state();
    assert_eq!(r.rfc8020_len(), 0, "reset 必须清 RFC 8020 表");
    let res = r
        .clone()
        .resolve("a.rst212.example", "A", ResolveOpts::default())
        .await;
    assert!(!res.hit, "reset 后必须回上游");
    assert_eq!(q.count(), 2);
}

/// 正向答案不受影响（回归护栏）：推断表只对 NXDOMAIN 生效。
#[tokio::test]
async fn positive_answers_are_unaffected() {
    let (r, _q, _c) = base(true, |_| {
        vec![UpstreamAnswer::ok(
            "u1",
            0,
            vec![ResolveAnswer::new("1.1.1.1", 60.0, TYPE_A)],
            Vec::new(),
        )]
    });
    let _ = r
        .clone()
        .resolve("pos212.example", "A", ResolveOpts::default())
        .await;
    let res = r
        .clone()
        .resolve("a.pos212.example", "A", ResolveOpts::default())
        .await;
    assert_eq!(res.rcode, RCODE_NOERROR);
    assert!(!res.answers.is_empty(), "正向答案必须正常返回");
    assert_eq!(r.rfc8020_len(), 0);
}
