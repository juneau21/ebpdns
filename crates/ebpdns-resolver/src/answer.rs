//! UDP/TCP 数据面入口：`answer_fast`（缓存热路径）/`answer_raw`。
//! 命中缓存即直接编码响应回客户端；未命中返回 None 交用户态 resolve。
//! 异常 fail-closed：任何错误不 panic，返回 None 或 SERVFAIL。

use ebpdns_cache::DnsCache;
use ebpdns_proto::constants::{CLASS_IN, TYPE_A};
use ebpdns_proto::message::parse_message;
use ebpdns_proto::record::AnswerInput;
use ebpdns_proto::response::{build_simple_response, build_udp_response, UdpResp};

use crate::resolve::AaaaPolicy;
use crate::Resolver;

/// **2.1.42（P1-1）**：数据面快路径命中来源。
///
/// 缓存直答与本地策略过滤必须区分：后者只计 `policy_filtered_total`，
/// 不得冒充 `hit`/`cache_direct`（负缓存命中判据也依赖 `is_cache_direct`）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FastKind {
    Cache,
    PolicyFiltered,
}

impl Resolver {
    /// UDP 热路径：命中缓存 → 直接编码响应；未命中 → None。
    pub fn answer_fast(&self, raw: &[u8]) -> Option<Vec<u8>> {
        self.answer_fast_ex(raw).map(|(resp, _)| resp)
    }

    /// **2.1.42（P1-1）**：带命中来源的 UDP 热路径。
    ///
    /// 与 [`Resolver::answer_fast`] 同一条路径；数据面用本函数区分
    /// "缓存直答" 与 "本地策略过滤（AAAA）"，避免策略应答被计成 hit。
    pub fn answer_fast_ex(&self, raw: &[u8]) -> Option<(Vec<u8>, FastKind)> {
        // **[历史归因]** 预检（对齐 Python resolver.py:1383/1388/1392）：查询包不该置 QR；opcode≠0
        // （最终 NOTIMP）；qclass≠IN。任一不满足 → 返回 None 交完整路径。
        if raw.len() < 12 {
            return None;
        }
        if raw[2] & 0x80 != 0 {
            return None; // QR 位被置（这是响应包）
        }
        if (raw[2] >> 3) & 0x0F != 0 {
            return None; // opcode≠0
        }

        let msg = parse_message(raw).ok()?;
        let q = msg.questions.first()?;
        if q.qclass != CLASS_IN {
            return None;
        }
        let d = q.name.trim_end_matches('.').to_ascii_lowercase();
        // P0-4：**不支持/未知 qtype 一律不查缓存**（旧实现 `_ => "A"` 会让
        // `AXFR(252)`/`ANY(255)`/`TYPE65280` 命中同名 A 条目并直接回 A 记录）。
        // 这里返回 None → 交完整路径，由 `dns.rs` 统一回 `NOTIMP`。
        let qtype: &'static str = type_name(q.qtype)?;
        let now = self.clock.epoch();
        // >>> PATCH242A P1-1 fast-policy BEGIN
        // **2.1.42（P1-1）**：快路径必须与慢路径**同一判定函数** —— 已缓存的 AAAA
        // 不能绕过 `ipv6=false` / `prefer_ipv4`。命中策略 ⇒ 直接 NODATA（rcode=0、
        // 答案段空），并以 `FastKind::PolicyFiltered` 交数据面计 `policy_filtered`；
        // `prefer_ipv4` 但 A 不在缓存时返回 None ⇒ 慢路径 `probe_a_record` 探 A。
        match self.aaaa_policy_cached(&d, qtype, now) {
            Some(AaaaPolicy::Ipv6Disabled) | Some(AaaaPolicy::PreferIpv4) => {
                return Some((build_simple_response(raw, 0)?, FastKind::PolicyFiltered));
            }
            // prefer_ipv4 且 A 尚未确认：必须交回慢路径 probe，不能直接发 AAAA。
            Some(AaaaPolicy::PreferIpv4Probe) => return None,
            None => {}
        }
        // <<< PATCH242A P1-1 fast-policy END
        // `d` 已去尾点+j小写、`qtype` 已大写 → 用 normalized 版本省 2 次 String 分配。
        let key = self.ckey_normalized(&d, qtype);
        let entry = self.cache.get(&key, now)?;

        // **2.1.19（P1-1 规则集指纹门禁的**真实漏洞**）**：本路径（UDP/TCP 数据面热路径）
        // 此前**完全没有**规则集指纹门禁 —— `resolve.rs` 里那处 `stale_rule` 检查
        // （`resolve.rs:417-424`）只在 `answer_fast` 返回 `None` 之后才会执行，而
        // **缓存命中时本函数直接返回**，永远不会走到那里。
        //
        // 后果（部署代理隔离实例三组独立实验互证，2.1.17 引入的功能回归）：
        //   ①改规则 → `rule_gen` 从 G1 变 G2；
        //   ②紧接着查同域名 ⇒ 本函数用**盖章 G1 的旧答案**直接应答 ⇒ `hit=1 / miss=0`；
        //   ③`cache.used` 也不下降（没有任何 `delete`）——"规则内容/顺序变了 ⇒ 旧答案立即
        //     失效（无需 `/api/reset`）"这条 `lib.rs` 文档承诺因此**未生效**。
        //
        // 修法：把与 `resolve.rs` **逐字同口径**的门禁前移到本路径的**唯一**缓存命中点：
        // 指纹不一致 ⇒ 删除该条目并返回 `None`（降级到完整路径；`resolve()` 会按新规则
        // 重新判定并重新解析）。这样两条命中路径（快路径 / 完整路径）不可能再分叉。
        //
        // 为什么只看 `rule_gen` 而不看别的：`rule_gen` 在 P1-1 起就是**规则集指纹**
        // （内容/顺序敏感），重启与"内容未变的重复 rebuild"都不改变它，因此不会误伤
        // `cache_persist` 恢复出来的缓存。
        if entry.rule_gen != self.rule_gen() {
            self.cache.delete(&key);
            return None;
        }

        // **[历史归因]** 规则复查 fast 路径（对齐 Python resolver.py:1425）：
        // - Uncertain（进入正则阶段未求值）→ 返回 None，降级 resolve 完整求值，
        //   避免在 UDP recv 线程同步遍历正则造成 head-of-line 阻塞；
        // - Block 命中 → 也返回 None，降级走 resolve→serve_from_cache 做复查 + 完整
        // **[历史归因]**   block 遥测（对齐 Python，不内联吞掉 NXDOMAIN）。
        match self.match_rule_fast(&d) {
            ebpdns_rules::MatchOutcome::Uncertain => return None,
            ebpdns_rules::MatchOutcome::Hit(r) if r.action == ebpdns_rules::Action::Block => {
                return None;
            }
            _ => {}
        }

        // **[历史归因]** 命中 TTL 按剩余时间衰减（对齐 Python answer_fast:1494）。
        let ttl_left = (entry.expires_at - now).clamp(0.0, 2_147_483_647.0);

        // **2.1.21 第 2 轮（DEF-221-03 修复：数据面快路径也必须入队）**
        //
        // 缺陷（AUDIT-221 DEF-221-03，P2）：本函数是 **UDP/TCP 命中**的唯一出口，
        // 此前直接编码应答返回、**从不入队**；全树唯一入队点在完整路径
        // （`resolve.rs::serve_from_cache`），而它只在 `answer_fast` 返回 `None` 时才走到
        // ⇒ `prefetch_trigger` / `prefetch_target` 对**真实客户端流量**完全无效
        // （实测：`trigger=3600, ttl=300` 时 UDP 命中两次、等 3.4s，夹具只收到首次 miss
        // 的 1 条查询，没有续期；同序列走 `POST /api/query` 才有 2 条）。
        //
        // 判据**完全复用** `Resolver::schedule_prefetch`（内部即
        // `ttl_left <= cfg.prefetch_trigger`），因此与完整路径、与 `do_prefetch` 三者
        // 仍是**同一条判据**，不存在"这里入队、那里不发"的分叉；`prefetch` 关闭或
        // `ttl_left > trigger` 时它立即返回（无副作用）。
        //
        // 位置说明：放在"命中即返回的三个出口"（NXDOMAIN / NODATA / 正常答案）**之前**，
        // 因为三类命中都值得续期（负缓存的 NXDOMAIN/NODATA 同样是"即将过期的热点"）；
        // 放在 `match_rule_fast` 的 block/uncertain 早退**之后**，因为那两条路径会降级到
        // 完整路径、由 `serve_from_cache` 统一入队（避免同一客户端查询重复入队）。
        // 热路径成本：`schedule_prefetch` 先读一次 `cfg`（parking_lot 读锁、无 await），
        // 超出阈值即返回；入队本身是 `prefetch` 队列的一次 `HashMap`/`OrderedDict` 插入
        // （顺序表按 `prefetch_max` 有界）。
        self.schedule_prefetch(&d, qtype, ttl_left);

        if entry.rcode == 3 {
            return Some((build_simple_response(raw, 3)?, FastKind::Cache));
        }
        if entry.answers.is_empty() {
            return Some((build_simple_response(raw, 0)?, FastKind::Cache));
        }

        // 编码 answer section，透传缓存 owner 名（CNAME 链逐跳 owner）。
        let inputs: Vec<AnswerInput> = entry
            .answers
            .iter()
            .map(|a| AnswerInput {
                rtype: a.rtype,
                value: &a.value,
                ttl: Some(ttl_left as u32),
                name: a.name.as_deref(),
            })
            .collect();

        // 与 miss 路径共用 build_udp_response：EDNS bufsize 截断 + 逐条丢尾 + 置 TC +
        // MAX_ANSWERS 上限 + OPT 回显。bufsize_cap = 客户端配置上限。
        let info = ebpdns_proto::edns::question_edns_info(raw);
        // **2.1.24（热路径分配）**：原地借用 `info.qbytes` —— 原实现 `clone()` 一份再取
        // 引用，于是**每次缓存命中**多一次 `Vec` 分配（`info` 本来就活到本函数结束）。
        let qbytes = info.qbytes.as_deref();
        let client_cap = self.cfg.read().edns_udp_size;
        build_udp_response(&UdpResp {
            raw_query: raw,
            qbytes,
            answers: &inputs,
            rcode: entry.rcode,
            abody: None,
            abody_count: None,
            owner_name: Some(&d),
            fallback_type: TYPE_A,
            ttl_override: None,
            bufsize_cap: Some(client_cap.min(u16::MAX as u32) as u16),
            force_truncated: false,
            enc_owner: None,
            edns_info: Some(&info),
        })
        .map(|resp| (resp, FastKind::Cache))
    }

    /// TCP 数据面入口（长度前缀帧）。当前复用 answer_fast 逻辑。
    pub async fn answer_raw(&self, raw: &[u8]) -> Option<Vec<u8>> {
        self.answer_fast(raw)
    }
}

/// 类型码 → 名字（用于 ckey 反查）。
///
/// **P0-4**：单一来源 = [`ebpdns_proto::constants::qtype_name`]；不支持的 qtype 返回
/// `None`（调用方 [`Resolver::answer_fast`] 据此放弃快路径，交完整路径回 `NOTIMP`）。
/// 旧实现 `_ => "A"` 会把未知类型当成 A 去查缓存。
///
/// **[2.1.24 / 热路径分配]** 返回 `&'static str` 而不是 `String`：`qtype_name` 的表本身就是
/// 静态字符串，原来每次查询都要 `to_string()` 复制一份（命中与未命中路径都要）。
fn type_name(t: u16) -> Option<&'static str> {
    ebpdns_proto::constants::qtype_name(t)
}
