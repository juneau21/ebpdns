//! **条目编解码（`EntryBody`）** —— 快照记录与 WAL `PUT` 共用（§5.3.2 / §5.4.2）。
//!
//! 关键点（§5.5）：
//! * **域名/qtype 用 UTF-8 展示串**（不是 DNS wire name）—— 它们是缓存键的一部分，
//!   wire 编解码会改大小写/尾点/转义 ⇒ 键不等 ⇒ 命中率下降；
//! * rdata 优先用 **wire**，写前做一次 `decode(encode(v)) == v` 的往返校验，
//!   不等则回退 **presentation**（保证恢复后 `value` 逐字节相同）；
//! * `expires_at` 存 **i64 毫秒**（绝对时间），`ttl` 存 `u32` 毫秒；
//!   `remaining` **不存**（读时由 `expires_at - now` 现算）。

use super::{PersistError, Result};
use crate::{CacheAnswer, CacheEntry, CacheKey};

/// 单条答案的磁盘形态。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnswerBody {
    /// `0 = WIRE`（`encode_rdata` 的字节）、`1 = PRESENTATION`（UTF-8 展示串）。
    pub rdata_fmt: u8,
    pub rtype: u16,
    pub ttl_ms: u32,
    pub name: Option<String>,
    pub rdata: Vec<u8>,
}

/// 单条缓存条目的磁盘形态（**不含** `entry_seq`：快照在外面多写一个 `entry_seq`，
/// WAL PUT 用记录头的 `seq`）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryBody {
    pub key: CacheKey,
    pub answers: Vec<AnswerBody>,
    pub chosen: String,
    pub ttl_ms: u32,
    pub rcode: u8,
    pub rule_gen: u64,
    pub expires_at_ms: i64,
}

// ---------------- 上限（§5.1） ----------------

const MAX_DOMAIN: usize = 255;
const MAX_QTYPE: usize = 32;
const MAX_GROUP: usize = 255;
const MAX_ANSWERS: usize = 256;
const MAX_CHOSEN: usize = 1024;
const MAX_NAME: usize = 255;
const MAX_RDATA: usize = 65535;

/// f64 秒 → i64 毫秒，**饱和**而不是溢出成 `null`/未定义（§9.6 K2）。
///
/// 这是 v1 缺陷的修正：`persist_ttl` 取大有限值使 `now + pt` 溢出为 `+inf` 时，
/// v1 的 `json!(inf)` 会写 `null`，下次启动被判 legacy 丢弃；v2 饱和为 `i64::MAX`，
/// 语义是“永不过期”，**绝不丢**。
pub fn secs_to_ms_saturating(v: f64) -> i64 {
    if v.is_nan() {
        return 0;
    }
    let ms = v * 1000.0;
    if ms >= i64::MAX as f64 {
        i64::MAX
    } else if ms <= i64::MIN as f64 {
        i64::MIN
    } else {
        ms.round() as i64
    }
}

/// i64 毫秒 → f64 秒（恢复侧唯一入口）。
pub fn ms_to_secs(ms: i64) -> f64 {
    ms as f64 / 1000.0
}

/// f64 秒 → u32 毫秒（`ttl_ms` 只作展示/兼容；`persist_ttl>0` 时恢复仍用配置的 f64）。
pub fn secs_to_ttl_ms(v: f64) -> u32 {
    if !v.is_finite() || v <= 0.0 {
        return 0;
    }
    let ms = v * 1000.0;
    if ms >= u32::MAX as f64 {
        u32::MAX
    } else {
        ms.round() as u32
    }
}

// ---------------- 低层读写 ----------------

pub(crate) fn put_u8(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}
pub(crate) fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}
pub(crate) fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}
pub(crate) fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}
pub(crate) fn put_i64(out: &mut Vec<u8>, v: i64) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// 带长度前缀（`u16` 字节数）的 UTF-8 串。
pub(crate) fn put_bytes16(out: &mut Vec<u8>, v: &[u8], what: &'static str) -> Result<()> {
    if v.len() > u16::MAX as usize {
        return Err(PersistError::BadField(what));
    }
    put_u16(out, v.len() as u16);
    out.extend_from_slice(v);
    Ok(())
}

/// 只读游标；所有读取都做边界检查（**绝不**越界、**绝不** panic）。
pub(crate) struct Cur<'a> {
    pub buf: &'a [u8],
    pub pos: usize,
}

impl<'a> Cur<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
    pub fn u8(&mut self) -> Result<u8> {
        if self.remaining() < 1 {
            return Err(PersistError::BadField("u8 越界"));
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }
    pub fn u16(&mut self) -> Result<u16> {
        if self.remaining() < 2 {
            return Err(PersistError::BadField("u16 越界"));
        }
        let v = u16::from_le_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }
    pub fn u32(&mut self) -> Result<u32> {
        if self.remaining() < 4 {
            return Err(PersistError::BadField("u32 越界"));
        }
        let mut b = [0u8; 4];
        b.copy_from_slice(&self.buf[self.pos..self.pos + 4]);
        self.pos += 4;
        Ok(u32::from_le_bytes(b))
    }
    pub fn u64(&mut self) -> Result<u64> {
        if self.remaining() < 8 {
            return Err(PersistError::BadField("u64 越界"));
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_le_bytes(b))
    }
    pub fn i64(&mut self) -> Result<i64> {
        Ok(self.u64()? as i64)
    }
    pub fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(PersistError::BadField(what));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    pub fn bytes16(&mut self, what: &'static str) -> Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n, what)
    }
    pub fn str16(&mut self, what: &'static str) -> Result<String> {
        let b = self.bytes16(what)?;
        std::str::from_utf8(b)
            .map(|s| s.to_string())
            .map_err(|_| PersistError::BadField(what))
    }
}

// ---------------- key 编解码（EVICT 与 EntryBody 共用） ----------------

/// `group_len`(0 = 二元组) + group + `domain_len` + domain + `qtype_len` + qtype。
pub(crate) fn encode_key(key: &CacheKey, out: &mut Vec<u8>) -> Result<()> {
    match &key.group {
        None => put_u16(out, 0),
        Some(g) => {
            let b = g.as_bytes();
            if b.is_empty() || b.len() > MAX_GROUP {
                return Err(PersistError::BadField("group 长度非法"));
            }
            put_u16(out, b.len() as u16);
            out.extend_from_slice(b);
        }
    }
    let d = key.domain.as_bytes();
    if d.is_empty() || d.len() > MAX_DOMAIN {
        return Err(PersistError::BadField("domain 长度非法"));
    }
    put_u16(out, d.len() as u16);
    out.extend_from_slice(d);
    let q = key.qtype.as_bytes();
    if q.is_empty() || q.len() > MAX_QTYPE {
        return Err(PersistError::BadField("qtype 长度非法"));
    }
    put_u16(out, q.len() as u16);
    out.extend_from_slice(q);
    Ok(())
}

pub(crate) fn decode_key(cur: &mut Cur<'_>) -> Result<CacheKey> {
    let glen = cur.u16()? as usize;
    if glen > MAX_GROUP {
        return Err(PersistError::BadField("group_len 越界"));
    }
    let group = if glen == 0 {
        None
    } else {
        let b = cur.take(glen, "group 越界")?;
        Some(
            std::str::from_utf8(b)
                .map_err(|_| PersistError::BadField("group 非 UTF-8"))?
                .to_string(),
        )
    };
    let dlen = cur.u16()? as usize;
    if dlen == 0 || dlen > MAX_DOMAIN {
        return Err(PersistError::BadField("domain_len 越界"));
    }
    let domain = std::str::from_utf8(cur.take(dlen, "domain 越界")?)
        .map_err(|_| PersistError::BadField("domain 非 UTF-8"))?
        .to_string();
    let qlen = cur.u16()? as usize;
    if qlen == 0 || qlen > MAX_QTYPE {
        return Err(PersistError::BadField("qtype_len 越界"));
    }
    let qtype = std::str::from_utf8(cur.take(qlen, "qtype 越界")?)
        .map_err(|_| PersistError::BadField("qtype 非 UTF-8"))?
        .to_string();
    Ok(CacheKey {
        group,
        domain,
        qtype,
    })
}

// ---------------- 答案：wire/presentation 往返校验 ----------------

/// 把一条展示串 rdata 编码成磁盘形态：**往返相等才用 WIRE**，否则回退 PRESENTATION。
///
/// 为什么必须校验：TXT 的引号/转义、未知类型的 hex 透传经 wire 往返**不保证逐字节
/// 相同**；直接写 wire 会让恢复后的 `value` 与缓存里的值不同（命中率/下游数据漂移）。
pub fn encode_answer_value(rtype: u16, value: &str) -> (u8, Vec<u8>) {
    if let Some(wire) = ebpdns_proto::rdata::encode_rdata(rtype, value) {
        let back = ebpdns_proto::rdata::parse_rdata(&wire, 0, rtype, wire.len() as u16)
            .map(|r| r.as_display());
        if back.as_deref() == Some(value) && wire.len() <= MAX_RDATA {
            return (0, wire);
        }
    }
    (1, value.as_bytes().to_vec())
}

/// 磁盘形态 → 展示串。WIRE 解不出 ⇒ `None`（调用方计 `failed` 并跳过）。
pub fn decode_answer_value(fmt: u8, rtype: u16, rdata: &[u8]) -> Option<String> {
    match fmt {
        0 => {
            if rdata.len() > u16::MAX as usize {
                return None;
            }
            ebpdns_proto::rdata::parse_rdata(rdata, 0, rtype, rdata.len() as u16)
                .map(|r| r.as_display())
        }
        1 => std::str::from_utf8(rdata).ok().map(|s| s.to_string()),
        _ => None,
    }
}

// ---------------- EntryBody ----------------

impl EntryBody {
    /// 从内存条目构造（做 rdata 往返校验与各字段上限检查）。
    pub fn from_entry(key: &CacheKey, e: &CacheEntry) -> Result<Self> {
        if e.answers.len() > MAX_ANSWERS {
            return Err(PersistError::BadField("answers 超过 256"));
        }
        if e.chosen.len() > MAX_CHOSEN {
            return Err(PersistError::BadField("chosen 超过 1024"));
        }
        let mut answers = Vec::with_capacity(e.answers.len());
        for a in &e.answers {
            let (fmt, rdata) = encode_answer_value(a.rtype, &a.value);
            if let Some(n) = &a.name {
                if n.len() > MAX_NAME {
                    return Err(PersistError::BadField("name 超过 255"));
                }
            }
            answers.push(AnswerBody {
                rdata_fmt: fmt,
                rtype: a.rtype,
                ttl_ms: secs_to_ttl_ms(a.ttl),
                name: a.name.clone(),
                rdata,
            });
        }
        Ok(Self {
            key: key.clone(),
            answers,
            chosen: e.chosen.clone(),
            ttl_ms: secs_to_ttl_ms(e.ttl),
            rcode: e.rcode,
            rule_gen: e.rule_gen,
            expires_at_ms: secs_to_ms_saturating(e.expires_at),
        })
    }

    /// 回到内存条目（`seq` 由调用方按快照 `entry_seq` / WAL 记录 `seq` 填）。
    pub fn to_entry(&self) -> Result<CacheEntry> {
        let mut answers = Vec::with_capacity(self.answers.len());
        for a in &self.answers {
            let value = decode_answer_value(a.rdata_fmt, a.rtype, &a.rdata)
                .ok_or(PersistError::BadField("rdata 解不出展示串"))?;
            answers.push(CacheAnswer {
                value,
                ttl: a.ttl_ms as f64 / 1000.0,
                rtype: a.rtype,
                name: a.name.clone(),
            });
        }
        Ok(CacheEntry {
            domain: self.key.domain.clone(),
            qtype: self.key.qtype.clone(),
            answers,
            chosen: self.chosen.clone(),
            ttl: self.ttl_ms as f64 / 1000.0,
            rcode: self.rcode,
            expires_at: ms_to_secs(self.expires_at_ms),
            rule_gen: self.rule_gen,
            seq: 0,
        })
    }

    /// 编码 body（不含记录头）。
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        encode_key(&self.key, out)?;
        put_u32(out, self.answers.len() as u32);
        for a in &self.answers {
            put_u16(out, a.rdata.len().min(u16::MAX as usize) as u16);
            put_u8(out, a.rdata_fmt);
            put_u16(out, a.rtype);
            put_u32(out, a.ttl_ms);
            match &a.name {
                None => {
                    put_u8(out, 0);
                    put_u16(out, 0);
                }
                Some(n) => {
                    put_u8(out, 1);
                    put_bytes16(out, n.as_bytes(), "name")?;
                }
            }
            out.extend_from_slice(&a.rdata);
        }
        put_bytes16(out, self.chosen.as_bytes(), "chosen")?;
        put_u32(out, self.ttl_ms);
        put_u8(out, self.rcode);
        put_u64(out, self.rule_gen);
        put_i64(out, self.expires_at_ms);
        if out.len() > super::MAX_RECORD_BYTES as usize {
            return Err(PersistError::BadField("单条记录超过 1 MiB"));
        }
        Ok(())
    }

    /// 解码 body。任何越界/非法值 → `Err`（调用方计 `failed` 并跳过该条，**不中断**）。
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() > super::MAX_RECORD_BYTES as usize {
            return Err(PersistError::BadField("记录超过 1 MiB"));
        }
        let mut cur = Cur::new(buf);
        let key = decode_key(&mut cur)?;
        let n = cur.u32()? as usize;
        if n > MAX_ANSWERS {
            return Err(PersistError::BadField("answers 超过 256"));
        }
        let mut answers = Vec::with_capacity(n.min(64));
        for _ in 0..n {
            let rlen = cur.u16()? as usize;
            let rdata_fmt = cur.u8()?;
            if rdata_fmt > 1 {
                return Err(PersistError::BadField("rdata_fmt 非法"));
            }
            let rtype = cur.u16()?;
            let ttl_ms = cur.u32()?;
            let name_present = cur.u8()?;
            let name_len = cur.u16()? as usize;
            if name_present > 1 {
                return Err(PersistError::BadField("name_present 非法"));
            }
            if name_present == 0 && name_len != 0 {
                return Err(PersistError::BadField("name_present=0 但 name_len!=0"));
            }
            if name_len > MAX_NAME {
                return Err(PersistError::BadField("name_len 越界"));
            }
            let name = if name_present == 1 {
                Some(
                    std::str::from_utf8(cur.take(name_len, "name 越界")?)
                        .map_err(|_| PersistError::BadField("name 非 UTF-8"))?
                        .to_string(),
                )
            } else {
                None
            };
            if rlen > MAX_RDATA {
                return Err(PersistError::BadField("rdata_len 越界"));
            }
            let rdata = cur.take(rlen, "rdata 越界")?.to_vec();
            answers.push(AnswerBody {
                rdata_fmt,
                rtype,
                ttl_ms,
                name,
                rdata,
            });
        }
        let chosen = cur.str16("chosen 越界")?;
        if chosen.len() > MAX_CHOSEN {
            return Err(PersistError::BadField("chosen 超过 1024"));
        }
        let ttl_ms = cur.u32()?;
        let rcode = cur.u8()?;
        let rule_gen = cur.u64()?;
        let expires_at_ms = cur.i64()?;
        if cur.remaining() != 0 {
            return Err(PersistError::BadField("记录尾部有多余字节"));
        }
        Ok(Self {
            key,
            answers,
            chosen,
            ttl_ms,
            rcode,
            rule_gen,
            expires_at_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_entry(domain: &str, qtype: &str, answers: Vec<(&str, u16)>) -> (CacheKey, CacheEntry) {
        let key = CacheKey::new(domain, qtype);
        let ans: Vec<CacheAnswer> = answers
            .iter()
            .map(|(v, t)| CacheAnswer {
                value: (*v).to_string(),
                ttl: 300.0,
                rtype: *t,
                name: None,
            })
            .collect();
        let e = CacheEntry {
            domain: domain.to_string(),
            qtype: qtype.to_string(),
            chosen: ans.first().map(|a| a.value.clone()).unwrap_or_default(),
            answers: ans,
            ttl: 300.0,
            rcode: 0,
            expires_at: 1_700_000_000.5,
            rule_gen: 7,
            seq: 0,
        };
        (key, e)
    }

    fn roundtrip(key: &CacheKey, e: &CacheEntry) -> CacheEntry {
        let body = EntryBody::from_entry(key, e).expect("from_entry");
        let mut buf = Vec::new();
        body.encode(&mut buf).expect("encode");
        let back = EntryBody::decode(&buf).expect("decode");
        assert_eq!(back.key, *key);
        back.to_entry().expect("to_entry")
    }

    #[test]
    fn roundtrip_a_aaaa() {
        for (v, t) in [("1.2.3.4", 1u16), ("2001:db8::1", 28)] {
            let (k, e) = mk_entry(
                "example.test",
                if t == 1 { "A" } else { "AAAA" },
                vec![(v, t)],
            );
            let got = roundtrip(&k, &e);
            assert_eq!(got.answers[0].value, v);
            assert_eq!(got.answers.len(), 1);
            assert_eq!(got.rule_gen, 7);
            assert!((got.expires_at - e.expires_at).abs() <= 0.001);
        }
    }

    #[test]
    fn roundtrip_unknown_type_falls_back_to_presentation() {
        // TYPE65 的展示串是 hex；encode_rdata 未必支持 ⇒ 必须回退 presentation 且值不变。
        let (k, e) = mk_entry("x.test", "TYPE65", vec![("000100000100", 65)]);
        let body = EntryBody::from_entry(&k, &e).unwrap();
        let got = body.to_entry().unwrap();
        assert_eq!(got.answers[0].value, "000100000100");
    }

    #[test]
    fn roundtrip_txt_quotes_preserved() {
        // TXT 的展示串带引号；wire 往返后必须逐字节相同（否则回退 presentation）。
        let (k, e) = mk_entry("t.test", "TXT", vec![("\"v=spf1 -all\"", 16)]);
        let got = roundtrip(&k, &e);
        assert_eq!(got.answers[0].value, "\"v=spf1 -all\"");
    }

    #[test]
    fn roundtrip_zero_answers_negative_cache() {
        let (k, mut e) = mk_entry("nx.test", "A", vec![]);
        e.rcode = 3;
        e.chosen = String::new();
        let got = roundtrip(&k, &e);
        assert!(got.answers.is_empty());
        assert_eq!(got.rcode, 3);
    }

    #[test]
    fn roundtrip_group_and_unicode() {
        let key = CacheKey::with_group("分组一", "例子.测试", "A");
        let mut e = CacheEntry::new("例子.测试", "A", 60.0, 1_700_000_000.0);
        e.chosen = "1.2.3.4".into();
        let got = roundtrip(&key, &e);
        assert_eq!(got.answers[0].value, "1.2.3.4");
        let body = EntryBody::from_entry(&key, &e).unwrap();
        assert_eq!(body.key.group.as_deref(), Some("分组一"));
    }

    #[test]
    fn roundtrip_answer_name_and_max_domain() {
        let d = "a".repeat(255);
        let (k, mut e) = mk_entry(&d, "A", vec![("9.9.9.9", 1)]);
        e.answers[0].name = Some("cname.example.test".into());
        let got = roundtrip(&k, &e);
        assert_eq!(got.answers[0].name.as_deref(), Some("cname.example.test"));
        assert_eq!(got.domain.len(), 255);
    }

    #[test]
    fn ms_saturation_never_nulls() {
        // K2：`now + pt` 溢出成 +inf 时必须饱和成 i64::MAX，而不是 null/未定义。
        assert_eq!(secs_to_ms_saturating(f64::INFINITY), i64::MAX);
        assert_eq!(secs_to_ms_saturating(f64::NEG_INFINITY), i64::MIN);
        assert_eq!(secs_to_ms_saturating(1e308), i64::MAX);
        assert_eq!(secs_to_ms_saturating(f64::NAN), 0);
        let max = EntryBody {
            key: CacheKey::new("a.test", "A"),
            answers: vec![],
            chosen: String::new(),
            ttl_ms: u32::MAX,
            rcode: 0,
            rule_gen: 0,
            expires_at_ms: secs_to_ms_saturating(f64::INFINITY),
        };
        let mut buf = Vec::new();
        max.encode(&mut buf).unwrap();
        let back = EntryBody::decode(&buf).unwrap();
        assert_eq!(back.expires_at_ms, i64::MAX);
        // 饱和值 → 秒，仍是“永不 expired”的大数。
        assert!(ms_to_secs(back.expires_at_ms) > 1e15);
    }

    #[test]
    fn ttl_ms_saturation() {
        assert_eq!(secs_to_ttl_ms(0.0), 0);
        assert_eq!(secs_to_ttl_ms(-5.0), 0);
        assert_eq!(secs_to_ttl_ms(f64::NAN), 0);
        assert_eq!(secs_to_ttl_ms(f64::INFINITY), 0);
        assert_eq!(secs_to_ttl_ms(1e12), u32::MAX);
        assert_eq!(secs_to_ttl_ms(300.0), 300_000);
    }

    #[test]
    fn decode_rejects_malformed_without_panic() {
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            vec![0, 0],
            // group_len=0, domain_len=0（非法）
            vec![0, 0, 0, 0, 0],
            // group_len=0, domain_len=4 "a.te", qtype_len=1 "A", answers=257
            {
                let mut v = Vec::new();
                v.extend_from_slice(&0u16.to_le_bytes());
                v.extend_from_slice(&4u16.to_le_bytes());
                v.extend_from_slice(b"a.te");
                v.extend_from_slice(&1u16.to_le_bytes());
                v.extend_from_slice(b"A");
                v.extend_from_slice(&257u32.to_le_bytes());
                v
            },
            // 合法头 + 尾随垃圾
            {
                let (k, e) = mk_entry("a.test", "A", vec![("1.1.1.1", 1)]);
                let b = EntryBody::from_entry(&k, &e).unwrap();
                let mut v = Vec::new();
                b.encode(&mut v).unwrap();
                v.push(0xFF);
                v
            },
        ];
        for c in cases {
            assert!(EntryBody::decode(&c).is_err(), "应拒绝 {}", c.len());
        }
    }

    #[test]
    fn decode_fuzz_prefixes_never_panic() {
        let (k, e) = mk_entry("a.test", "A", vec![("1.1.1.1", 1), ("2.2.2.2", 1)]);
        let b = EntryBody::from_entry(&k, &e).unwrap();
        let mut v = Vec::new();
        b.encode(&mut v).unwrap();
        for cut in 0..v.len() {
            let _ = EntryBody::decode(&v[..cut]);
        }
        // 随机位翻转：不允许 panic，只允许 Err 或“值仍然自洽”。
        for i in 0..v.len() {
            for bit in [0u8, 3, 7] {
                let mut w = v.clone();
                w[i] ^= 1 << bit;
                let _ = EntryBody::decode(&w);
            }
        }
    }
}
