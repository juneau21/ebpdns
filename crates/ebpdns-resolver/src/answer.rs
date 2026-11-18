//! UDP/TCP 数据面入口：`answer_fast`（缓存热路径）/`answer_raw`。
//! 命中缓存即直接编码响应回客户端；未命中返回 None 交用户态 resolve。
//! 异常 fail-closed：任何错误不 panic，返回 None 或 SERVFAIL。

use ebpdns_cache::DnsCache;
use ebpdns_proto::constants::{CLASS_IN, MAX_ANSWERS, TYPE_A};
use ebpdns_proto::message::parse_message;
use ebpdns_proto::record::AnswerInput;
use ebpdns_proto::response::{build_simple_response_into, build_udp_response_into, UdpResp};

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
        let mut out = Vec::with_capacity(512);
        let kind = self.answer_fast_into(raw, &mut out)?;
        Some((out, kind))
    }

    /// **PERF-9**：命中路径直接写入调用方缓冲（数据面复用 Vec，零额外分配）。
    pub fn answer_fast_into(&self, raw: &[u8], out: &mut Vec<u8>) -> Option<FastKind> {
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

        // **PERF-10**：取走 question 的所有权 —— 直接复用 `q.name` 的 String 做原地小写化，
        // 不再 `trim_end_matches(..).to_ascii_lowercase()` 额外分配一份（每包省 1 次分配）。
        let mut msg = parse_message(raw).ok()?;
        let q = msg.questions.drain(..).next()?;
        if q.qclass != CLASS_IN {
            return None;
        }
        // P0-4：**不支持/未知 qtype 一律不查缓存**（旧实现 `_ => "A"` 会让
        // `AXFR(252)`/`ANY(255)`/`TYPE65280` 命中同名 A 条目并直接回 A 记录）。
        // 这里返回 None → 交完整路径，由 `dns.rs` 统一回 `NOTIMP`。
        let qtype: &'static str = type_name(q.qtype)?;
        let mut d = q.name;
        while d.ends_with('.') {
            d.pop();
        }
        d.make_ascii_lowercase();
        let now = self.clock.epoch();
        // **阶段 3-14**：DNSSEC（EDNS `DO`）变体位 —— 从**查询报文**解析（无 EDNS ⇒
        // false）。它必须参与缓存键：带 DO 的客户端可能拿到 RRSIG（有无/内容不同），
        // 与非 DO 客户端共用条目就是"串条目"。
        //
        // 解析位置的三个约束：
        // 1. **早于任何缓存访问**（下面的 `aaaa_policy_cached` 会查 A 条目）；
        // 2. 零分配（`query_do_bit` 只扫一遍 additional 段，不复制 qbytes/opt_bytes）；
        // 3. 必须在 `parse_message` 之后仍用**原始 raw**（本条已 drain 出 question，
        //    但 raw 未被修改）。
        let dnssec = ebpdns_proto::edns::query_do_bit(raw);
        // >>> PATCH242A P1-1 fast-policy BEGIN
        // **2.1.42（P1-1）**：快路径必须与慢路径**同一判定函数** —— 已缓存的 AAAA
        // 不能绕过 `ipv6=false` / `prefer_ipv4`。命中策略 ⇒ 直接 NODATA（rcode=0、
        // 答案段空），并以 `FastKind::PolicyFiltered` 交数据面计 `policy_filtered`；
        // `prefer_ipv4` 但 A 不在缓存时返回 None ⇒ 慢路径 `probe_a_record` 探 A。
        match self.aaaa_policy_cached(&d, qtype, now, dnssec) {
            Some(AaaaPolicy::Ipv6Disabled) | Some(AaaaPolicy::PreferIpv4) => {
                build_simple_response_into(raw, 0, out)?;
                return Some(FastKind::PolicyFiltered);
            }
            // prefer_ipv4 且 A 尚未确认：必须交回慢路径 probe，不能直接发 AAAA。
            Some(AaaaPolicy::PreferIpv4Probe) => return None,
            None => {}
        }
        // <<< PATCH242A P1-1 fast-policy END
        // `d` 已去尾点+j小写、`qtype` 已大写 → 用 normalized 版本省 2 次 String 分配。
        // **阶段 3-14**：`ckey_variant` 是**唯一**的键构造入口（DO 维由配置开关决定）。
        let key = self.ckey_variant(&d, qtype, dnssec);
        // **2.1.49-p6（hot replica 接线）**：数据面命中也走 `get_arc`。
        //
        // 旧实现调 `DnsCache::get`：命中后**克隆整条 entry**（`Vec<CacheAnswer>` + 若干
        // `String`，每包 4~6 次堆分配），且不经过 `S3FifoCache` 的 hot 只读副本 ——
        // 阶段 1.4 的优化实际只在迁移/测试/快照路径生效，长稳 `hot_replicas` 恒 0。
        //
        // `get_arc` 与 `get` 的**命中语义完全一致**（同一个内层 `LruCache::get_arc` +
        // 相同的 TTL/惰性删除判定），区别只在于：返回 `Arc<CacheEntry>`（零克隆），
        // 并由 `S3FifoCache::get_arc` 负责按频率晋升只读副本。下游只读字段一律经
        // `Deref` 借用（`entry.xxx`），**不得**为了类型把整条 entry 克隆回来。
        let entry = self.cache.get_arc(&key, now)?;

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
        // **2.1.50（FIX-TTL-ADVERTISE）**：对外 TTL 不得超过 `ttl_max`。
        // 典型场景：`persist_ttl=864000`（本地保存 10 天）复活的条目剩余 TTL 可达 10 天，
        // 原样回给客户端会让它本地缓存 10 天。内部过期时间不变，只封顶"对外宣称"的 TTL。
        let ttl_cap = {
            let m = self.cfg.read().ttl_max;
            // ttl_max == 0 表示不封顶（测试基座/旧语义），与 fill_cache 的钳制口径一致。
            if m > 0 {
                f64::from(m)
            } else {
                f64::INFINITY
            }
        };
        let ttl_left = (entry.expires_at - now)
            .min(ttl_cap)
            .clamp(0.0, 2_147_483_647.0);

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
        self.schedule_prefetch(&d, qtype, ttl_left, dnssec);

        // **2.1.49-p3（wire-format 打包缓存）**：命中优先复用原始响应字节，只改 ID/RD/TTL，
        // 省掉结构化重编码；长度必须放得进客户端缓冲，否则回退到 build_udp_response_into。
        //
        // **审查修复（round 1）**：wire 里存的是**别的客户端**那次查询的响应，因此
        // question（大小写）与 EDNS OPT（COOKIE/ECS/NSID…）必须用**当前查询**的字节覆盖；
        // 长度不一致等不可安全替换的情形返回 `false` ⇒ 回退结构化编码（正确性优先）。
        let info = ebpdns_proto::edns::question_edns_info(raw);
        let client_cap = self.cfg.read().edns_udp_size;
        let wire_limit = usize::from(
            info.bufsize
                .min(client_cap.min(u32::from(u16::MAX)) as u16)
                .max(512),
        );
        if let Some(w) = self.cache.get_wire(&key) {
            if w.bytes.len() <= wire_limit {
                if let Some(qbytes) = info.qbytes.as_deref() {
                    let id = u16::from_be_bytes([raw[0], raw[1]]);
                    let rd = raw[2] & 0x01 != 0;
                    if w.render(
                        out,
                        id,
                        rd,
                        now,
                        (entry.expires_at - now).max(0.0),
                        qbytes,
                        info.opt_bytes.as_deref(),
                    ) {
                        return Some(FastKind::Cache);
                    }
                }
            }
        }

        if entry.rcode == 3 {
            build_simple_response_into(raw, 3, out)?;
            return Some(FastKind::Cache);
        }
        if entry.rrsets.is_empty() {
            build_simple_response_into(raw, 0, out)?;
            return Some(FastKind::Cache);
        }

        // **阶段 B-2（RRset 对象级缓存）**：直接遍历 `rrsets` 生成 `AnswerInput`，
        // **不再分配中间 `Vec<AnswerInput>`**（旧实现 `collect()` 每命中一次分配一份）。
        // `AnswerInput` 借用 `&str`（value/name 来自共享的 `Arc<str>`），这里把它们
        // 填进栈上的 `[AnswerInput; MAX_ANSWERS]`；超过 `MAX_ANSWERS` 的部分按旧行为
        // 截断并置 TC（`force_truncated`）。
        //
        // 逐条 TTL 仍统一用命中的剩余 TTL（对齐 Python answer_fast:1494）；owner 名
        // 逐条透传（CNAME 链逐跳 owner）——`name=None` 的条目回落到查询名。
        let total = entry.answers_len();
        let mut inputs: [AnswerInput; MAX_ANSWERS] = std::array::from_fn(|_| AnswerInput {
            rtype: 0,
            value: "",
            ttl: None,
            name: None,
        });
        let mut n_in = 0usize;
        'encode: for rs in &entry.rrsets {
            for a in &rs.values {
                if n_in == MAX_ANSWERS {
                    break 'encode;
                }
                inputs[n_in] = AnswerInput {
                    rtype: a.rtype,
                    value: a.value.as_ref(),
                    ttl: Some(ttl_left as u32),
                    name: a.name.as_deref(),
                };
                n_in += 1;
            }
        }
        let truncated_by_count = total > MAX_ANSWERS;

        // 与 miss 路径共用 build_udp_response：EDNS bufsize 截断 + 逐条丢尾 + 置 TC +
        // MAX_ANSWERS 上限 + OPT 回显。bufsize_cap = 客户端配置上限。
        // **2.1.49-p3**：info / client_cap 已在 wire 尝试前算好，这里直接复用。
        // **2.1.24（热路径分配）**：原地借用 info.qbytes，避免每次缓存命中多一次 Vec 分配。
        let qbytes = info.qbytes.as_deref();
        build_udp_response_into(
            &UdpResp {
                raw_query: raw,
                qbytes,
                answers: &inputs[..n_in],
                rcode: entry.rcode,
                abody: None,
                abody_count: None,
                owner_name: Some(&d),
                fallback_type: TYPE_A,
                ttl_override: None,
                bufsize_cap: Some(client_cap.min(u16::MAX as u32) as u16),
                force_truncated: truncated_by_count,
                enc_owner: None,
                edns_info: Some(&info),
            },
            out,
        )
        .map(|()| FastKind::Cache)
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
