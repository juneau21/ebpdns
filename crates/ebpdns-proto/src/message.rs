//! 完整 DNS 报文解析（`parse_message`）。

use crate::constants::*;
use crate::error::ProtoError;
use crate::name::decode_name;
use crate::rdata::parse_rdata;
use crate::record::{Question, ResourceRecord};
use crate::ProtoResult;

/// 解析后的 DNS 报文。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub flags: u16,
    pub qd: u16,
    pub an: u16,
    pub ns: u16,
    pub ar: u16,
    pub rcode: u8,
    pub opcode: u8,
    pub truncated: bool,
    pub ra: bool,
    pub rd: bool,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authority: Vec<ResourceRecord>,
    pub additional: Vec<ResourceRecord>,
}

impl Message {
    /// **[历史归因]** 响应 question 段数量（Python `answer_count`）。
    pub fn answer_count(&self) -> u16 {
        self.an
    }
}

fn be_u16(data: &[u8], pos: usize) -> Option<u16> {
    data.get(pos..pos + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
}

fn be_u32(data: &[u8], pos: usize) -> Option<u32> {
    data.get(pos..pos + 4)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// 解析完整 DNS 报文。OPT RR 跳过（不入 additional）；畸形 rdata 的 RR 丢弃（fail-closed）。
pub fn parse_message(data: &[u8]) -> ProtoResult<Message> {
    if data.len() < 12 {
        return Err(ProtoError::truncated("message too short"));
    }
    let id = be_u16(data, 0).ok_or_else(|| ProtoError::malformed("bad header"))?;
    let flags = be_u16(data, 2).ok_or_else(|| ProtoError::malformed("bad header"))?;
    let qd = be_u16(data, 4).ok_or_else(|| ProtoError::malformed("bad header"))?;
    let an = be_u16(data, 6).ok_or_else(|| ProtoError::malformed("bad header"))?;
    let ns = be_u16(data, 8).ok_or_else(|| ProtoError::malformed("bad header"))?;
    let ar = be_u16(data, 10).ok_or_else(|| ProtoError::malformed("bad header"))?;

    let rcode = (flags & FLAG_RCODE_MASK) as u8;
    let opcode = ((flags & FLAG_OPCODE_MASK) >> 11) as u8;
    let truncated = (flags & FLAG_TC) != 0;
    let rd = (flags & FLAG_RD) != 0;
    let ra = (flags & FLAG_RA) != 0;

    let mut pos = 12usize;

    // ---- question 段 ----
    let mut questions = Vec::new();
    for _ in 0..qd {
        let (name, np) = decode_name(data, pos)?;
        pos = np;
        if pos + 4 > data.len() {
            return Err(ProtoError::truncated("truncated question section"));
        }
        let qtype = be_u16(data, pos).ok_or_else(|| ProtoError::truncated("truncated question"))?;
        let qclass =
            be_u16(data, pos + 2).ok_or_else(|| ProtoError::truncated("truncated question"))?;
        pos += 4;
        questions.push(Question {
            name,
            qtype,
            qclass,
        });
    }

    // ---- answer / authority / additional 三段 ----
    let mut answers = Vec::new();
    let mut authority = Vec::new();
    let mut additional = Vec::new();

    parse_section(data, &mut pos, an, &mut answers)?;
    parse_section(data, &mut pos, ns, &mut authority)?;
    parse_section(data, &mut pos, ar, &mut additional)?;

    Ok(Message {
        id,
        flags,
        qd,
        an,
        ns,
        ar,
        rcode,
        opcode,
        truncated,
        ra,
        rd,
        questions,
        answers,
        authority,
        additional,
    })
}

fn parse_section(
    data: &[u8],
    pos: &mut usize,
    count: u16,
    out: &mut Vec<ResourceRecord>,
) -> ProtoResult<()> {
    for _ in 0..count {
        let (name, np) = decode_name(data, *pos)?;
        *pos = np;
        // RR 头固定 10 字节。
        if *pos + 10 > data.len() {
            return Err(ProtoError::truncated("truncated RR header"));
        }
        let rtype = be_u16(data, *pos).ok_or_else(|| ProtoError::truncated("truncated RR hdr"))?;
        let rclass =
            be_u16(data, *pos + 2).ok_or_else(|| ProtoError::truncated("truncated RR hdr"))?;
        let ttl =
            be_u32(data, *pos + 4).ok_or_else(|| ProtoError::truncated("truncated RR hdr"))?;
        let rdlen =
            be_u16(data, *pos + 8).ok_or_else(|| ProtoError::truncated("truncated RR hdr"))?;
        *pos += 10;

        if rtype == TYPE_OPT {
            if *pos + rdlen as usize > data.len() {
                return Err(ProtoError::truncated("truncated OPT rdata"));
            }
            *pos += rdlen as usize;
            continue;
        }

        if *pos + rdlen as usize > data.len() {
            return Err(ProtoError::truncated("truncated RR rdata"));
        }
        let value = parse_rdata(data, *pos, rtype, rdlen);
        *pos += rdlen as usize;
        match value {
            Some(rdata) => out.push(ResourceRecord {
                name,
                rtype,
                rclass,
                ttl,
                rdata,
            }),
            // 结构化类型长度不符 / 解码异常 → 整条 RR 丢弃，不降级为 hex。
            None => continue,
        }
    }
    Ok(())
}
