//! **RFC 8020 父域 NXDOMAIN 推导体**（2.1.12 优化项 ①，负缓存复用扩展）。
//!
//! # 问题（2.1.11 真机实测）
//! 压测窗口内 **85%（9308/10954）** 的应答是 NXDOMAIN，但负缓存命中增量
//! `hit_delta` 仅 **45** —— 绝大多数被查询的名字**只被查一次**（随机子域长尾），
//! 答案缓存对"每个名字只查一次"的形态结构上无效。
//!
//! # 语义（RFC 8020 §Abstract，2016-11）
//! > 解析器收到 NXDOMAIN 后，必须把它当作"**被查询名及其以下所有名字都不存在**"
//! > 的绝对陈述。
//!
//! 因此采纳一次 NXDOMAIN 之后，把**被查询名本身**登记为「NXDOMAIN 域」；后续查询
//! 只要**自身或某个祖先**落在该登记集合里，就可以直接回 NXDOMAIN，**不发上游**。
//!
//! ## 为什么**不**登记祖先（与任务书措辞的有意收敛，在此登记）
//! 任务书初稿写的是"登记该名字**及其祖先链**"。按 RFC 8020 的原文口径，NXDOMAIN
//! **不能**反推祖先：`w123456.qq.com` 返回 NXDOMAIN 并不蕴含 `qq.com` / `com`
//! 不存在。若真去登记祖先链，一次 `w123456.qq.com` 的 NXDOMAIN 会让
//! `qq.com`（2 标签）乃至 `com`（1 标签）整体进入 NXDOMAIN 集合 → **所有 `.com`
//! 查询在 60s 内被本地判负**（实测夹具 N5 就是 120 个 `w%06x.<12 个 .com 域名>`，
//! 第一次之后全部短路），这是灾难性过度泛化，与"安全边界"要求直接冲突。
//! 故本实现=**只登记被查询名本身**，**沿祖先链匹配**（这正是任务书给出的判据
//! "命中已登记的 NXDOMAIN 域（**自身或某祖先**）"以及单测"父 NXDOMAIN → 子域直接
//! NXDOMAIN"所要求的行为）。
//!
//! # 安全边界
//! - **只登记确实 NXDOMAIN 的名字**：登记点唯一 —— [`crate::resolve`] 的
//!   `finish_resolve` 中「NXDOMAIN 负缓存写入」那一支（`rcode == 3` 且已达 quorum）。
//!   SERVFAIL / REFUSED / 超时（`rcode = None`）/ NODATA / 截断**永不登记**；
//! - **规则屏蔽（block）产生的 NXDOMAIN 不登记**：那是本地策略而非权威 NXDOMAIN，
//!   且规则本身已覆盖该名字（无收益、只有误伤风险）；
//! - **CNAME→NXDOMAIN 路径不登记外层名字**：外层名字**存在**（有 CNAME RR），
//!   只是链尾不存在，故 `*.外层` 并无 NXDOMAIN 证据；链尾目标由子链自己的
//!   `finish_resolve` 登记；
//! - **预取链路（P2-B）不登记**：与"预取不得写负缓存"同口径（`prefetch=true` 分支）；
//! - **P1-1 规则门禁**：条目盖章 `rule_gen`（规则集指纹）；指纹变化 → 条目立即
//!   失效并被删除（与答案缓存同口径，规则 CRUD 无需等 TTL）；
//! - **深度上限** `rfc8020_max_labels`（默认 8）：标贴数超过上限的名字**不登记**，
//!   超过上限的查询也**不匹配**（防深名污染/过度泛化）；
//! - 表上界 [`RFC8020_MAX_ENTRIES`]，超限按"最早过期"驱逐到 3/4 水位；
//! - TTL 与负缓存完全同源（`neg_ttl_of` 的结果，已被 `neg_ttl_max` 夹取）；
//!   过期后按 `serve_stale` / `stale_ttl` 与答案缓存**同口径**兜底（并可触发后台刷新）。

use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use ebpdns_proto::constants::RCODE_NXDOMAIN;

use crate::resolve::TraceSink;
use crate::types::ResolveResult;
use crate::Resolver;

/// 登记表上界（条数）。每条 ≈ 1 个 `String`（域名）+ 16B，65536 条约 3–4MB，
/// 与 `ip_speed`（65536）/`prefetch_max`（65536）同量级。
pub(crate) const RFC8020_MAX_ENTRIES: usize = 65_536;

/// 标签计数（空标签忽略，防 `a..b` 之类畸形输入把深度算高）。
pub(crate) fn label_count(d: &str) -> usize {
    d.split('.').filter(|l| !l.is_empty()).count()
}

/// 一条「NXDOMAIN 域」登记项。
#[derive(Clone, Copy, Debug)]
pub(crate) struct Entry {
    /// 过期时刻（epoch 秒，与答案缓存/负缓存同一时间轴）。
    pub expires_at: f64,
    /// 登记时的**规则集指纹**（P1-1 门禁：指纹变化 → 立即失效）。
    pub rule_gen: u64,
}

/// 一次命中的结果。
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Hit {
    /// 剩余 TTL（秒）；serve-stale 兜底时为 0。
    pub ttl_left: f64,
    /// 是否走 serve-stale 窗口（已过期但仍在 `stale_ttl` 内）。
    pub stale: bool,
}

/// 「NXDOMAIN 域」登记表（自身即被推断为 NXDOMAIN 的名字集合）。
#[derive(Default)]
pub(crate) struct Rfc8020Domains {
    map: Mutex<HashMap<String, Entry>>,
}

impl Rfc8020Domains {
    /// 登记 `name`（过期时刻 `expires_at`）。
    ///
    /// 返回 `true` 表示本次**新增/更新**了一条有效登记（用于独立计数，避免把
    /// "同一名字重复登记"重复计数——重复登记在长尾压测里很常见）。
    pub(crate) fn register(
        &self,
        now: f64,
        name: &str,
        expires_at: f64,
        rule_gen: u64,
        max_labels: usize,
    ) -> bool {
        if name.is_empty() || !expires_at.is_finite() || expires_at <= now {
            return false;
        }
        // 深度上限：超深名字不登记（防过度泛化）。
        if label_count(name) > max_labels.max(1) {
            return false;
        }
        let fresh = Entry {
            expires_at,
            rule_gen,
        };
        let mut m = self.map.lock();
        let changed = match m.get_mut(name) {
            Some(slot) => {
                // 同代际取"更晚过期"；跨代际（规则已变）直接覆盖为新代际。
                if slot.rule_gen != rule_gen || expires_at > slot.expires_at {
                    *slot = fresh;
                    true
                } else {
                    false
                }
            }
            None => {
                m.insert(name.to_string(), fresh);
                true
            }
        };
        if m.len() > RFC8020_MAX_ENTRIES {
            // 按"最早过期"驱逐到 3/4 水位（复用 lib.rs 的通用驱逐器）。
            crate::evict_oldest_by_ts(&mut m, RFC8020_MAX_ENTRIES * 3 / 4, |e: &Entry| {
                e.expires_at
            });
        }
        changed
    }

    /// 沿 `d` 的祖先链匹配（自身 → 逐个去掉最左标签 → TLD）。
    ///
    /// 未命中时顺手删除链上"已彻底过期"或"跨规则代际"的条目（惰性清理，无后台任务）。
    pub(crate) fn lookup(
        &self,
        now: f64,
        d: &str,
        rule_gen: u64,
        serve_stale: bool,
        stale_ttl: f64,
        max_labels: usize,
    ) -> Option<Hit> {
        if d.is_empty() {
            return None;
        }
        // 匹配深度上限：超深查询不参与推断。
        if label_count(d) > max_labels.max(1) {
            return None;
        }
        let stale_window = if serve_stale { stale_ttl.max(0.0) } else { 0.0 };
        let mut m = self.map.lock();
        let mut cur = d;
        let mut hit: Option<Hit> = None;
        let mut drop_key: Option<String> = None;
        loop {
            if let Some(e) = m.get(cur) {
                // 条目自身也要过深度上限（配置把上限调小后旧条目不得继续命中）。
                if e.rule_gen != rule_gen || label_count(cur) > max_labels.max(1) {
                    drop_key = Some(cur.to_string());
                } else {
                    let left = e.expires_at - now;
                    if left > 0.0 {
                        hit = Some(Hit {
                            ttl_left: left,
                            stale: false,
                        });
                        break;
                    }
                    if stale_window > 0.0 && left + stale_window > 0.0 {
                        hit = Some(Hit {
                            ttl_left: 0.0,
                            stale: true,
                        });
                        break;
                    }
                    // 彻底过期（连 stale 窗口都出了）→ 删除。
                    drop_key = Some(cur.to_string());
                }
            }
            match cur.find('.') {
                Some(i) => cur = &cur[i + 1..],
                None => break,
            }
        }
        if let Some(k) = drop_key {
            m.remove(&k);
        }
        hit
    }

    pub(crate) fn len(&self) -> usize {
        self.map.lock().len()
    }

    pub(crate) fn clear(&self) {
        self.map.lock().clear();
    }
}

impl Resolver {
    /// RFC 8020 推断**命中**次数（独立观测口径，2.1.12）。
    ///
    /// 与通用 `counters.hit` / `cache_direct` 的差异：本计数**只**统计"由父域
    /// NXDOMAIN 推断直接判负、完全未发上游"的次数，供 `/api/status.counters`
    /// 与 Prometheus 独立暴露（便于把 RFC 8020 的收益从普通缓存命中里分离出来）。
    pub fn rfc8020_hits(&self) -> u64 {
        self.rfc8020_hits.load(Ordering::Relaxed)
    }

    /// RFC 8020 **登记**次数（有效新增/更新条数，2.1.12）。
    pub fn rfc8020_registrations(&self) -> u64 {
        self.rfc8020_registrations.load(Ordering::Relaxed)
    }

    /// 当前登记表条数（可观测 / 单测用）。
    pub fn rfc8020_len(&self) -> usize {
        self.rfc8020.len()
    }

    /// 登记一次「NXDOMAIN 域」（`d` 已被规范化）。
    ///
    /// 调用点唯一：`finish_resolve` 的 NXDOMAIN 负缓存写入分支（非预取）。
    pub(crate) fn rfc8020_register(&self, d: &str, ttl: u32) {
        let (on, max_labels, cap) = {
            let c = self.cfg.read();
            (c.rfc8020_infer, c.rfc8020_max_labels, c.neg_ttl_max)
        };
        if !on {
            return;
        }
        // 防御性二次夹取：负缓存 TTL 已被 `neg_ttl_of` 夹过，这里再保证
        // "RFC 8020 条目的 TTL ≤ neg_ttl_max" 这一不变量与本函数耦合在一起。
        let ttl = if cap > 0 { ttl.min(cap) } else { ttl };
        if ttl == 0 {
            return;
        }
        let now = self.clock.epoch();
        if self
            .rfc8020
            .register(now, d, now + f64::from(ttl), self.rule_gen(), max_labels)
        {
            self.rfc8020_registrations.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                target: "ebpdns::rfc8020",
                name = %d,
                ttl,
                labels = label_count(d),
                "RFC 8020：登记 NXDOMAIN 域（其下所有名字必然 NXDOMAIN）"
            );
        }
    }

    /// 沿祖先链查「NXDOMAIN 域」（`d` 已规范化）。返回 `None` = 不推断。
    ///
    /// **P1-2（2.1.14）**：RFC 8020 推断表里的条目**全部是负结论**（NXDOMAIN），
    /// 因此**不使用 serve-stale 窗口**（`serve_stale=false, stale_ttl=0`）：
    /// 过期即失效、回到正常解析链路。旧实现在 `serve_stale=true` 时会把已过期的
    /// 推断条目继续当"零上游直答 NXDOMAIN"用 —— 与 `neg_ttl_max` 的硬上限语义
    /// （「任何负缓存写入路径都夹取到 [0, neg_ttl_max]」）直接矛盾，也是实测
    /// 「负缓存 +195s/+680s 仍 0.08ms 直答」的成因之一。
    pub(crate) fn rfc8020_lookup(&self, d: &str) -> Option<Hit> {
        let (on, max_labels) = {
            let c = self.cfg.read();
            (c.rfc8020_infer, c.rfc8020_max_labels)
        };
        if !on {
            return None;
        }
        let now = self.clock.epoch();
        self.rfc8020
            .lookup(now, d, self.rule_gen(), false, 0.0, max_labels)
    }

    /// 由 RFC 8020 推断直接给出 NXDOMAIN 应答（**零上游请求**）。
    ///
    /// 与 `serve_from_cache` 的负缓存命中分支同形状：`rcode=3`、`hit=true`
    /// （数据面按"缓存直答"记 `hit`/`cache_direct`，与"负缓存复用扩展"的定位一致）、
    /// `up_name="RFC8020 推断"`（日志「上游」列可区分）、`ttl_left` = 剩余负 TTL。
    /// AA 位由数据面组包决定（本路径不置 AA，即 AA=0）。
    pub(crate) fn rfc8020_serve(
        self: &Arc<Self>,
        d: &str,
        qtype: &str,
        hit: Hit,
        mut trace: TraceSink,
        t0: f64,
    ) -> ResolveResult {
        self.rfc8020_hits.fetch_add(1, Ordering::Relaxed);
        let lat = self.clock.monotonic_ms() - t0;
        if hit.stale {
            // 与答案缓存的 serve-stale 同口径：TTL=0 直答 + 触发后台刷新去重。
            trace.push_str(
                "cache",
                "RFC8020 serve-stale: 父域 NXDOMAIN 推断（已过期窗口内）",
            );
            self.trigger_stale_refresh(d, qtype);
        } else {
            trace.push_with(|| {
                crate::types::TraceEvent::new(
                    "cache",
                    format!("RFC8020 父域 NXDOMAIN 推断命中, 剩余 {:.0}s", hit.ttl_left),
                )
            });
        }
        ResolveResult {
            domain: d.to_string(),
            qtype: qtype.to_string(),
            rcode: RCODE_NXDOMAIN,
            hit: true,
            latency: lat,
            ttl_left: hit.ttl_left,
            trace: trace.into_vec(),
            up_name: "RFC8020 推断".to_string(),
            ..Default::default()
        }
    }

    /// 规则复查（与 `serve_from_cache` 同口径）：命中 `block` / `forceIp` 时
    /// **不走** RFC 8020 推断，交回正常链路（文案/计数口径不变）。
    ///
    /// 这是"规则优先于推断"的必要护栏：`block` 规则会自己回 NXDOMAIN（结果相同，
    /// 但 `rule_hits` 计数与 `level="rule"` 事件文案必须保留）；`forceIp` 规则会
    /// 合成答案，若被推断短路就会**静默失效**（例如 `*.w1.example` 有 forceIp 而
    /// `w1.example` 已登记为 NXDOMAIN 域时）。
    pub(crate) fn rfc8020_rule_bypass(&self, d: &str) -> bool {
        matches!(
            self.match_rule(d).map(|r| r.action),
            Some(ebpdns_rules::Action::Block) | Some(ebpdns_rules::Action::ForceIp)
        )
    }
}
