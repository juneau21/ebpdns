//! **2.1.49-p3**：wire-format（打包）缓存条目：直接保存响应报文字节 + TTL 字段偏移，
//! 命中时只拷贝 + 改写 ID / RD / 各 RR 的 TTL，省掉结构化重编码。
//!
//! 约束（安全闸门）：
//! * 只对**单次响应 ≤ [`WIRE_MAX_BYTES`]（4096，覆盖常见 EDNS 4096 响应）** 的响应建 wire；
//!   **2.1.49-p5**：上限从 1232 提升到 4096（更大的响应仍回退结构化编码）；
//! * 命中时再校验 `len ≤ 客户端 bufsize`（无 EDNS ⇒ 512），否则调用方必须回退到结构化编码；
//! * 只解析并改写 **question/answer/authority** 段里 RR 的 TTL（OPT 在 additional，无 TTL）；
//! * **只缓存"本服务自己构造的"响应形态**：question + answer/authority + 可选的**末条 OPT**。
//!   additional 段出现任何其它记录（其 TTL 不会被改写）⇒ 放弃 wire（返回 `None`）。
//!
//! # 审查修复（round 1）：wire 不再"整段原样重放"
//!
//! 旧实现把**第一个客户端**的完整响应字节（含它的 question 大小写与 EDNS OPT，例如
//! COOKIE/ECS/NSID）原样缓存并在命中时整段复制 —— 于是后续客户端会收到别人的
//! question 字节与 OPT。更严重的是旧代码把 wire 的写点放进了**命中路径**，命中一次就把
//! "已衰减的 TTL + 旧报文"重新盖一次时间戳：结构化条目过期并被上游刷新后，wire 里的
//! 旧答案仍会以 `TTL=1` 无限延续（实测：q4 返回旧 IP / TTL=1）。
//!
//! 现在：
//! * [`WireEntry`] 记录 question 段长度与 OPT 起点；[`WireEntry::render`] 用**当前客户端**
//!   的 question/OPT 替换这两段（长度必须一致，否则返回 `false` 让调用方回退结构化编码）；
//! * 写入点移到 **miss 解析成功之后**（`dns.rs::spawn_miss`），且结构化条目 `put` 时
//!   会**失效同键 wire**（见 `s3fifo.rs`）—— 旧报文不可能活过它所属的结构化条目。

use std::sync::Arc;

/// wire 缓存单条上限（字节）。
///
/// **2.1.49-p5（阶段 1.3）**：1232 → **4096** —— 覆盖常见 EDNS 4096 响应；更大的响应
/// （极少见）仍回退结构化编码。命中时还会再校验 `len <= 客户端 bufsize`。
pub const WIRE_MAX_BYTES: usize = 4096;

/// OPT RR 固定头长度：name(1) + type(2) + class(2) + ttl(4) + rdlen(2)。
const OPT_FIXED_LEN: usize = 11;
/// OPT 的 RR type。
const TYPE_OPT: u16 = 41;

/// 打包缓存条目。
#[derive(Debug)]
pub struct WireEntry {
    /// 原始响应报文（插入时的字节，ID/TTL 还是旧值）。
    pub bytes: Arc<[u8]>,
    /// 每个 RR 的 TTL 字段偏移（4 字节大端）与插入时的 TTL 值。
    pub ttls: Vec<(u16, u32)>,
    /// 插入时间（epoch 秒），用于 TTL 线性衰减。
    pub inserted_at: f64,
    /// question 段的字节长度（从 offset 12 到 question 结束，含 qtype/qclass）。
    qbytes_len: u16,
    /// answer/authority 段的结束偏移（= 原 OPT 的起点；无 OPT 时 = 报文长度）。
    body_end: u16,
}

impl WireEntry {
    /// 从完整响应报文构造；格式不合法 / 超长 / additional 段不合规 ⇒ `None`
    /// （调用方跳过 wire 缓存）。
    ///
    /// # 只接受本服务构造的响应形态
    ///
    /// 本服务的响应 = header(qd=1) + question + answer/authority + 可选**末条 OPT**。
    /// 任何其它 additional 记录（例如上游透传的 glue）都不会被 [`Self::render`] 改 TTL，
    /// 缓存它等于把过期 TTL 发给下游 ⇒ 直接拒绝，退回结构化编码（正确性优先）。
    pub fn from_response(msg: &[u8], now: f64) -> Option<Self> {
        if msg.len() < 12 || msg.len() > WIRE_MAX_BYTES {
            return None;
        }
        let qd = be16(msg, 4)? as usize;
        let an = be16(msg, 6)? as usize;
        let ns = be16(msg, 8)? as usize;
        let ar = be16(msg, 10)? as usize;
        // 只缓存"单 question"的响应（本服务数据面只会这样构造；畸形查询的 FORMERR 不缓存）。
        if qd != 1 {
            return None;
        }
        let mut pos = 12usize;
        pos = skip_name(msg, pos)?;
        pos = pos.checked_add(4)?; // qtype + qclass
        if pos > msg.len() {
            return None;
        }
        let qbytes_len = pos - 12;
        let mut ttls = Vec::with_capacity(an + ns);
        for _ in 0..(an + ns) {
            pos = skip_name(msg, pos)?;
            if pos + 10 > msg.len() {
                return None;
            }
            // type(2) class(2) ttl(4) rdlen(2) rdata(rdlen)
            let ttl_off = pos + 4;
            let ttl = u32::from_be_bytes([
                msg[ttl_off],
                msg[ttl_off + 1],
                msg[ttl_off + 2],
                msg[ttl_off + 3],
            ]);
            let rdlen = be16(msg, pos + 8)? as usize;
            ttls.push((ttl_off as u16, ttl));
            pos = pos.checked_add(10)?.checked_add(rdlen)?;
            if pos > msg.len() {
                return None;
            }
        }
        // additional 段：只允许 0 条，或恰好一条 root-owner 的 OPT 且为报文末条。
        let body_end = if ar == 0 {
            if pos != msg.len() {
                return None; // 尾部有未解析字节：不是本服务构造的形态
            }
            msg.len()
        } else if ar == 1 {
            let opt_start = pos;
            // owner 必须是根（单字节 0）；否则不是 OPT（或压缩指针），拒绝。
            if *msg.get(pos)? != 0 {
                return None;
            }
            let p = pos + 1;
            if p + (OPT_FIXED_LEN - 1) > msg.len() {
                return None;
            }
            if be16(msg, p)? != TYPE_OPT {
                return None;
            }
            let rdlen = be16(msg, p + 8)? as usize;
            let end = p + 10 + rdlen;
            if end != msg.len() {
                return None; // OPT 不是末条 / 长度不符
            }
            opt_start
        } else {
            return None; // 多条 additional：TTL 不会被改写 ⇒ 不缓存
        };
        Some(Self {
            bytes: Arc::from(msg),
            ttls,
            inserted_at: now,
            qbytes_len: qbytes_len as u16,
            body_end: body_end as u16,
        })
    }

    /// 渲染到 `out`：拷贝字节 → 用**当前客户端**的 question/OPT 替换对应段 → 改写
    /// ID、RD 位、TTL（按 `now - inserted_at` 衰减）。
    ///
    /// * `qbytes`：当前查询的第一个 question 原始字节（含 qname 终止 0 + qtype + qclass），
    ///   长度必须与原 question 完全一致（同一缓存键 ⇒ 只有大小写可能不同）；
    /// * `opt`：当前查询的 OPT RR 原始字节；`None` 表示当前查询无 EDNS（输出 arcount=0）。
    ///
    /// 返回 `false` 表示"本条 wire 不适合当前查询"（长度不一致 / 内部偏移异常），
    /// 调用方**必须**回退到结构化编码。
    #[allow(clippy::too_many_arguments)]
    pub fn render(
        &self,
        out: &mut Vec<u8>,
        id: u16,
        rd: bool,
        now: f64,
        max_remaining_s: f64,
        qbytes: &[u8],
        opt: Option<&[u8]>,
    ) -> bool {
        let qlen = self.qbytes_len as usize;
        let body_end = self.body_end as usize;
        if qbytes.len() != qlen || body_end < 12 + qlen || body_end > self.bytes.len() {
            out.clear();
            return false;
        }
        let opt = opt.unwrap_or(&[]);
        let tail = &self.bytes[12 + qlen..body_end];
        out.clear();
        out.reserve(12 + qbytes.len() + tail.len() + opt.len());
        out.extend_from_slice(&self.bytes[..12]);
        // 报文 ≥12 字节（from_response 已保证）
        out[0] = (id >> 8) as u8;
        out[1] = (id & 0xFF) as u8;
        // flags 字节：保留 QR/opcode/AA/TC/RD/RA 等，只按查询覆盖 RD 位。
        if rd {
            out[2] |= 0x01;
        } else {
            out[2] &= !0x01;
        }
        // arcount：只保留当前查询的 OPT（旧实现会把第一个客户端的 OPT 原样带回）。
        let ar_count: u16 = if opt.is_empty() { 0 } else { 1 };
        out[10..12].copy_from_slice(&ar_count.to_be_bytes());
        out.extend_from_slice(qbytes);
        out.extend_from_slice(tail);
        out.extend_from_slice(opt);
        let elapsed = (now - self.inserted_at).max(0.0);
        let cap = max_remaining_s.max(1.0);
        for &(off, orig) in &self.ttls {
            let off = off as usize;
            if off + 4 > out.len() {
                continue;
            }
            let remain = (f64::from(orig) - elapsed).min(cap);
            let ttl = if remain <= 0.0 {
                1
            } else {
                remain.floor() as u32
            };
            out[off..off + 4].copy_from_slice(&ttl.to_be_bytes());
        }
        true
    }
}

/// 解析 question/answer/authority 段中每个 RR 的 `(TTL 字段偏移, TTL 值)`。
///
/// 只支持无压缩指针的 owner 名（服务端编码的响应通常已压缩 —— 压缩指针**不跳转**，
/// 仅按 2 字节对待，因此偏移计算仍正确；压缩只影响名字长度解析）。
fn be16(msg: &[u8], off: usize) -> Option<u16> {
    if off + 2 > msg.len() {
        return None;
    }
    Some(u16::from_be_bytes([msg[off], msg[off + 1]]))
}

/// 跳过 owner name：长度字节为 0 终止；压缩指针（0xC0）占 2 字节即结束。
fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let b = *msg.get(pos)?;
        if b == 0 {
            return Some(pos + 1);
        }
        if b & 0xC0 == 0xC0 {
            return Some(pos + 2);
        }
        pos = pos.checked_add(1 + b as usize)?;
        if pos > msg.len() {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 手工构造：header(12) + 1 question + 2 answers（A + CNAME）。
    fn sample() -> Vec<u8> {
        let mut m = Vec::new();
        // id=0x1234 flags=0x8180 qd=1 an=2 ns=0 ar=0
        m.extend_from_slice(&[0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0, 0, 0, 0]);
        // question: www.example.com A IN（21 字节：17 名字 + 4）
        m.extend_from_slice(&[
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0,
        ]);
        m.extend_from_slice(&[0, 1, 0, 1]);
        // answer1: CNAME 指针 c0 0c, ttl=300, rdata=example.com
        m.extend_from_slice(&[0xC0, 0x0C, 0, 5, 0, 1, 0, 0, 1, 44, 0, 13]);
        m.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        // answer2: A 指针 c0 0c, ttl=120, rdata=1.2.3.4
        m.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 1, 2, 3, 4]);
        m
    }

    /// question 段 = sample 的 `[12..33]`。
    fn question(m: &[u8]) -> Vec<u8> {
        m[12..33].to_vec()
    }

    /// 给响应追加一条 OPT（owner=root, class=4096, ttl=0, rdata 任意）。
    fn with_opt(mut m: Vec<u8>, rdata: &[u8]) -> Vec<u8> {
        m[10..12].copy_from_slice(&1u16.to_be_bytes()); // arcount=1
        m.push(0);
        m.extend_from_slice(&41u16.to_be_bytes()); // type OPT
        m.extend_from_slice(&4096u16.to_be_bytes()); // class = bufsize
        m.extend_from_slice(&0u32.to_be_bytes()); // ttl
        m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        m.extend_from_slice(rdata);
        m
    }

    /// 构造当前客户端的 question（大小写可变，长度不变）。
    fn qbytes_for(name: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for part in name.split('.') {
            v.push(part.len() as u8);
            v.extend_from_slice(part.as_bytes());
        }
        v.push(0);
        v.extend_from_slice(&[0, 1, 0, 1]);
        v
    }

    #[test]
    fn parses_two_ttls() {
        let m = sample();
        let w = WireEntry::from_response(&m, 1000.0).expect("wire");
        assert_eq!(w.ttls.len(), 2);
        assert_eq!(w.ttls[0].1, 300);
        assert_eq!(w.ttls[1].1, 120);
    }

    #[test]
    fn render_patches_id_ttl_and_keeps_rest() {
        let m = sample();
        let w = WireEntry::from_response(&m, 1000.0).expect("wire");
        let mut out = Vec::new();
        // 100 秒后：TTL 300→200，120→20
        assert!(w.render(&mut out, 0xBEEF, true, 1100.0, 600.0, &question(&m), None));
        assert_eq!(&out[0..2], &[0xBE, 0xEF]);
        assert_eq!(
            u32::from_be_bytes([
                out[w.ttls[0].0 as usize],
                out[w.ttls[0].0 as usize + 1],
                out[w.ttls[0].0 as usize + 2],
                out[w.ttls[0].0 as usize + 3]
            ]),
            200
        );
        assert_eq!(
            u32::from_be_bytes([
                out[w.ttls[1].0 as usize],
                out[w.ttls[1].0 as usize + 1],
                out[w.ttls[1].0 as usize + 2],
                out[w.ttls[1].0 as usize + 3]
            ]),
            20
        );
        // 除 ID/TTL 外逐字节相同（把 expect 的 TTL 也改成同样的衰减值再整体比较）。
        let mut expect = m.clone();
        expect[0..2].copy_from_slice(&[0xBE, 0xEF]);
        for (off, ttl) in [
            (w.ttls[0].0 as usize, 200u32),
            (w.ttls[1].0 as usize, 20u32),
        ] {
            expect[off..off + 4].copy_from_slice(&ttl.to_be_bytes());
        }
        assert_eq!(out, expect);
    }

    /// **审查修复**：命中时必须回显**当前客户端**的 question 大小写与 OPT（cookie），
    /// 绝不能重放第一个客户端的字节。
    #[test]
    fn render_uses_current_question_and_opt() {
        let cookie_a = [0, 10, 0, 4, b'A', b'A', b'A', b'A']; // EDNS option code=10(COOKIE), len=4
        let m = with_opt(sample(), &cookie_a);
        let w = WireEntry::from_response(&m, 1000.0).expect("带 OPT 的响应应可缓存");
        let cur_q = qbytes_for("WWW.EXAMPLE.COM"); // 与 sample 同长度、不同大小写
        let cookie_b = [0, 10, 0, 4, b'B', b'B', b'B', b'B'];
        let mut out = Vec::new();
        assert!(w.render(
            &mut out,
            0x1111,
            false,
            1000.0,
            300.0,
            &cur_q,
            Some(&cookie_b)
        ));
        // question 是 B 的字节
        assert_eq!(
            &out[12..12 + cur_q.len()],
            cur_q.as_slice(),
            "question 必须来自当前客户端"
        );
        // OPT 是 B 的 cookie，A 的 cookie 不得出现在报文里
        assert!(out.ends_with(&cookie_b), "OPT 必须是当前客户端的 cookie");
        assert!(
            !out.windows(4).any(|x| x == *b"AAAA"),
            "不得泄漏上一个客户端的 cookie"
        );
        assert_eq!(u16::from_be_bytes([out[10], out[11]]), 1);
        // answer TTL 仍按插入时间衰减
        assert_eq!(
            u32::from_be_bytes([
                out[w.ttls[1].0 as usize],
                out[w.ttls[1].0 as usize + 1],
                out[w.ttls[1].0 as usize + 2],
                out[w.ttls[1].0 as usize + 3]
            ]),
            120
        );
        // 当前查询无 EDNS ⇒ 输出不得带 OPT，arcount=0
        assert!(w.render(&mut out, 1, false, 1000.0, 300.0, &cur_q, None));
        assert_eq!(u16::from_be_bytes([out[10], out[11]]), 0);
        assert!(
            !out.windows(4).any(|x| x == *b"AAAA"),
            "无 EDNS 时不得带出旧 OPT"
        );
    }

    /// question 长度不一致 ⇒ 拒绝（调用方回退结构化编码），不得输出半截报文。
    #[test]
    fn render_rejects_question_length_mismatch() {
        let w = WireEntry::from_response(&sample(), 1000.0).expect("wire");
        let long = qbytes_for("WWW.EXAMPLE.COM.X");
        let mut out = vec![9, 9, 9];
        assert!(!w.render(&mut out, 1, false, 1000.0, 300.0, &long, None));
        assert!(out.is_empty(), "拒绝时不得留下半截输出");
    }

    /// additional 出现非 OPT 记录（其 TTL 不会被改写）⇒ 不缓存 wire。
    #[test]
    fn rejects_additional_non_opt_record() {
        let mut m = sample();
        m[10..12].copy_from_slice(&1u16.to_be_bytes()); // ar=1
                                                        // 追加一条 A 记录（owner=root, type=1, class=1, ttl=300, rdlen=4）
        m.extend_from_slice(&[0]);
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&300u32.to_be_bytes());
        m.extend_from_slice(&4u16.to_be_bytes());
        m.extend_from_slice(&[1, 2, 3, 4]);
        assert!(
            WireEntry::from_response(&m, 0.0).is_none(),
            "非 OPT additional 的 TTL 不会被改写 ⇒ 必须拒绝"
        );
    }

    #[test]
    fn rejects_oversize_or_malformed() {
        assert!(WireEntry::from_response(&[0u8; 11], 0.0).is_none());
        let mut big = sample();
        big.resize(WIRE_MAX_BYTES + 1, 0);
        assert!(WireEntry::from_response(&big, 0.0).is_none());
        // qd=0 不缓存
        let mut noq = sample();
        noq[4..6].copy_from_slice(&0u16.to_be_bytes());
        assert!(WireEntry::from_response(&noq, 0.0).is_none());
    }
}
