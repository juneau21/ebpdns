//! DNS over TCP / TLS 长度前缀帧（2 字节大端长度）。

use crate::error::ProtoError;
use crate::ProtoResult;

/// 构造 TCP 帧：2 字节大端长度前缀 + payload。
///
/// 长度前缀是 u16：`payload` 超过 65535 字节时**无法**表达，旧实现用 `as u16` 静默
/// 截断高位、却仍追加全部 payload → 产出「声明长度 ≠ 实际字节数」的非法帧，
/// 对端解析后残留垃圾字节并污染后续查询。这里返回 `Err`，由调用方按 TC 截断
/// 或重建响应处理（DNS over TCP 合法报文最大 65535）。
pub fn tcp_frame(payload: &[u8]) -> ProtoResult<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(ProtoError::truncated("tcp frame payload exceeds 65535"));
    }
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend((payload.len() as u16).to_be_bytes());
    out.extend(payload);
    Ok(out)
}

/// 从 TCP 流中提取一条 DNS 报文，返回 `(dns_bytes, rest)`。
///
/// - 不足 2 字节头 → `Err("incomplete frame header")`；
/// - 声明长度超过剩余字节 → `Err("incomplete frame body")`（等续，不吞字节）。
pub fn parse_tcp_frame(data: &[u8]) -> ProtoResult<(Vec<u8>, Vec<u8>)> {
    if data.len() < 2 {
        return Err(ProtoError::truncated("incomplete frame header"));
    }
    let length = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + length {
        return Err(ProtoError::truncated("incomplete frame body"));
    }
    Ok((data[2..2 + length].to_vec(), data[2 + length..].to_vec()))
}
