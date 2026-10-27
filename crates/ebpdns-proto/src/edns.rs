//! EDNS0 / OPT RR 解析与构造、ECS option、Padding 对齐、bufsize 钳制。

use std::net::IpAddr;

use crate::constants::*;
use crate::ProtoResult;

/// `_question_edns_info` 的结果：一遍遍历 question + additional 得到
/// `(qbytes, bufsize, opt_bytes)`。
///
/// - `qbytes`：第一个 question 的原始字节（qname 含 null 终止 + qtype + qclass）；
///   解析失败为 `None`。
/// - `bufsize`：OPT class 字段钳制值；无 OPT 时为 512。
/// - `opt_bytes`：OPT RR 原始字节（name=0 + type/class/ttl/rdlen + rdata）；无则 `None`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdnsInfo {
    pub qbytes: Option<Vec<u8>>,
    pub bufsize: u16,
    pub opt_bytes: Option<Vec<u8>>,
}

/// **[历史归因]** 单次遍历 question + additional 段，对齐 Python `_question_edns_info`。
/// **[历史归因]** 任何畸形 / 截断点均返回 `(None, 512, None)` 或保留已解析结果（对齐 Python 分支语义）。
pub fn question_edns_info(data: &[u8]) -> EdnsInfo {
    let dlen = data.len();
    if dlen < 12 {
        return EdnsInfo {
            qbytes: None,
            bufsize: DEFAULT_BUF_SIZE,
            opt_bytes: None,
        };
    }
    let qd = match be_u16(data, 4) {
        Some(v) => v,
        None => return fallback(),
    };
    let ar = match be_u16(data, 10) {
        Some(v) => v,
        None => return fallback(),
    };

    let mut pos = 12usize;
    let mut qbytes: Option<Vec<u8>> = None;

    // ---- question 段 ----
    for qi in 0..qd {
        let qstart = pos;
        if pos >= dlen {
            return EdnsInfo {
                qbytes: if qi == 0 { None } else { qbytes },
                bufsize: DEFAULT_BUF_SIZE,
                opt_bytes: None,
            };
        }
        loop {
            let ln = data[pos];
            if ln == 0 {
                pos += 1; // 含 null 终止符
                break;
            }
            if ln & 0xC0 == 0xC0 {
                // question 区不应出现压缩指针。
                if qi == 0 {
                    return fallback();
                }
                if pos + 1 >= dlen {
                    return EdnsInfo {
                        qbytes: if qi == 0 { None } else { qbytes },
                        bufsize: DEFAULT_BUF_SIZE,
                        opt_bytes: None,
                    };
                }
                pos += 2;
                break;
            }
            // 0x40 / 0x80 非法标签高位。
            if ln & 0xC0 != 0 {
                return EdnsInfo {
                    qbytes: if qi == 0 { None } else { qbytes },
                    bufsize: DEFAULT_BUF_SIZE,
                    opt_bytes: None,
                };
            }
            pos += 1 + ln as usize;
            if pos >= dlen {
                return EdnsInfo {
                    qbytes: if qi == 0 { None } else { qbytes },
                    bufsize: DEFAULT_BUF_SIZE,
                    opt_bytes: None,
                };
            }
        }
        // 名字已终止，校验 qtype + qclass 4 字节。
        if pos + 4 > dlen {
            return EdnsInfo {
                qbytes: if qi == 0 { None } else { qbytes },
                bufsize: DEFAULT_BUF_SIZE,
                opt_bytes: None,
            };
        }
        if qi == 0 {
            qbytes = Some(data[qstart..pos + 4].to_vec());
        }
        pos += 4;
    }

    // ---- additional 段：找 OPT RR ----
    let mut bufsize = DEFAULT_BUF_SIZE;
    let mut opt_bytes: Option<Vec<u8>> = None;
    for _ in 0..ar {
        let rstart = pos;
        if pos >= dlen {
            break;
        }
        let mut skip_rr = false;
        loop {
            let ln = data[pos];
            if ln == 0 {
                pos += 1;
                break;
            }
            if ln & 0xC0 == 0xC0 {
                if pos + 1 >= dlen {
                    skip_rr = true;
                    pos += 2;
                    break;
                }
                let ptr = ((ln & 0x3F) as usize) << 8 | data[pos + 1] as usize;
                if !(ptr < pos && ptr < dlen) {
                    skip_rr = true;
                }
                pos += 2;
                break;
            }
            if ln & 0xC0 != 0 {
                skip_rr = true;
                break;
            }
            pos += 1 + ln as usize;
            if pos >= dlen {
                break;
            }
        }
        if skip_rr {
            if pos + 10 > dlen {
                break;
            }
            let rdlen = match be_u16(data, pos + 8) {
                Some(v) => v as usize,
                None => break,
            };
            let rr_end = pos + 10 + rdlen;
            if rr_end > dlen {
                break;
            }
            pos = rr_end;
            continue;
        }
        if pos + 10 > dlen {
            break;
        }
        let rtype = match be_u16(data, pos) {
            Some(v) => v,
            None => break,
        };
        let rdlen = match be_u16(data, pos + 8) {
            Some(v) => v as usize,
            None => break,
        };
        let rr_end = pos + 10 + rdlen;
        if rr_end > dlen {
            break;
        }
        if rtype == TYPE_OPT {
            let raw_buf = be_u16(data, pos + 2).unwrap_or(0);
            bufsize = clamp_bufsize_received(raw_buf);
            opt_bytes = Some(data[rstart..rr_end].to_vec());
        }
        pos = rr_end;
    }

    EdnsInfo {
        qbytes,
        bufsize,
        opt_bytes,
    }
}

fn fallback() -> EdnsInfo {
    EdnsInfo {
        qbytes: None,
        bufsize: DEFAULT_BUF_SIZE,
        opt_bytes: None,
    }
}

fn be_u16(data: &[u8], pos: usize) -> Option<u16> {
    data.get(pos..pos + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
}

/// EDNS0 Client Subnet 选项（code=8）。
///
/// `subnet` 形如 `"203.0.113.0/24"` 或 `"1.2.3.4"`。畸形 IP → 返回空 `Vec`（不带 ECS）。
/// Source Prefix Length 填实际 prefix；IPv4 ≤32 / IPv6 ≤128 钳制。
pub fn ecs_option(subnet: &str) -> Vec<u8> {
    let (addr_part, prefix) = match subnet.split_once('/') {
        Some((a, p)) => {
            let pf = p.parse::<u32>().unwrap_or(32);
            (a, pf)
        }
        None => (subnet, 32u32),
    };
    let ip: IpAddr = match addr_part.parse() {
        Ok(ip) => ip,
        Err(_) => return Vec::new(),
    };
    match ip {
        IpAddr::V4(v4) => {
            let prefix = prefix.min(32) as u8;
            let raw = v4.octets();
            let addr_len = (prefix as usize).div_ceil(8);
            build_ecs(1, prefix, &raw[..addr_len])
        }
        IpAddr::V6(v6) => {
            // **[历史归因]** P-03：无显式前缀时 IPv6 默认 /128（与 Python 一致）。
            //
            // **[历史归因]** Python `dnsmsg._ecs_option`：`except ValueError: addr, prefix = subnet, 32`
            // —— **仅当 `subnet.split("/")` 抛 ValueError**（即根本没有 "/"）时才把
            // 默认前缀设为 32，随后 IPv6 分支用 `"/" not in subnet` 把它改成 128。
            // 因此三种输入严格区分：
            //   - "2001:db8::1"        → 无 "/"      → prefix 32 → 提升为 128；
            //   - "2001:db8::1/32"     → 有 "/"，int("32") 成功 → prefix 32 → **保持 32**；
            //   - "2001:db8::1/x"      → 有 "/"，int 抛 ValueError → 回退 (subnet, 32)；
            // **[历史归因]**     此时 `"/" not in subnet` 为假 → prefix 保持 32（与 Python 逐字节一致）。
            //
            // 关键：判据是 `subnet.contains('/')`（有无斜杠），**不是** `prefix == 32`
            // 和斜杠的组合。旧实现写成 `prefix == 32 && !contains('/')` 虽然对本例
            // 结果相同，但把"解析失败回退 32"与"显式 /32"合并成一个判据，一旦
            // **[历史归因]** 上方默认值改成 0/64 就会静默漂移。此处与 Python 表达式一一对应。
            let prefix = if !subnet.contains('/') { 128 } else { prefix };
            let prefix = prefix.min(128) as u8;
            let raw = v6.octets();
            let addr_len = (prefix as usize).div_ceil(8);
            build_ecs(2, prefix, &raw[..addr_len])
        }
    }
}

fn build_ecs(family: u16, src_prefix: u8, addr: &[u8]) -> Vec<u8> {
    let len = 4 + addr.len();
    let mut out = Vec::with_capacity(6 + addr.len());
    out.extend(OPTION_ECS.to_be_bytes());
    out.extend((len as u16).to_be_bytes());
    out.extend(family.to_be_bytes());
    out.push(src_prefix);
    out.push(0u8); // scope prefix
    out.extend(addr);
    out
}

/// 根据已有 options 与 question 长度计算并追加 Padding option（RFC 8467）。
///
/// 对齐整条 DNS 消息到 128B 块。`question_wire_len` = qname + qtype + qclass 的总字节数。
/// prefix = header(12) + question_wire_len + OPT RR 固定头(11) + 已有 options。
/// Padding option 自身占 4B（code 2B + len 2B）计入对齐。
pub fn append_padding(options: &mut Vec<u8>, question_wire_len: usize) -> ProtoResult<()> {
    let opts_len = options.len();
    let prefix = 12 + question_wire_len + 11 + opts_len;
    let mut need = (PADDING_BLOCK - (prefix % PADDING_BLOCK)) % PADDING_BLOCK;
    if need < 4 {
        need += PADDING_BLOCK;
    }
    if need > PADDING_MAX {
        need = PADDING_MAX;
    }
    let pad_len = need - 4;
    options.extend(OPTION_PADDING.to_be_bytes());
    options.extend((pad_len as u16).to_be_bytes());
    options.resize(options.len() + pad_len, 0);
    Ok(())
}

/// 构造 OPT RR 整体字节：`\x00` + type(OPT) + class(size) + ttl(0) + rdlen + options。
pub fn build_opt_rr(bufsize: u16, options: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(11 + options.len());
    out.push(0u8); // root name
    out.extend(TYPE_OPT.to_be_bytes());
    out.extend(bufsize.to_be_bytes());
    out.extend(0u32.to_be_bytes()); // ttl / extended rcode / flags
    out.extend((options.len() as u16).to_be_bytes());
    out.extend(options);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 解析 ECS option 字节为 `(family, src_prefix, 地址字节)`。
    fn parse_ecs(opt: &[u8]) -> Option<(u16, u8, Vec<u8>)> {
        if opt.len() < 8 {
            return None;
        }
        assert_eq!(u16::from_be_bytes([opt[0], opt[1]]), OPTION_ECS);
        let olen = u16::from_be_bytes([opt[2], opt[3]]) as usize;
        assert_eq!(olen + 4, opt.len(), "option 长度字段必须自洽");
        let family = u16::from_be_bytes([opt[4], opt[5]]);
        let src = opt[6];
        let scope = opt[7];
        assert_eq!(scope, 0, "scope prefix 恒 0");
        Some((family, src, opt[8..].to_vec()))
    }

    #[test]
    fn ecs_ipv4_default_prefix_32() {
        // **[历史归因]** Python: "1.2.3.4" 无 "/" → prefix 32（IPv4 不提升），地址 4 字节。
        let (f, p, a) = parse_ecs(&ecs_option("1.2.3.4")).unwrap();
        assert_eq!((f, p), (1, 32));
        assert_eq!(a, vec![1, 2, 3, 4]);
    }

    #[test]
    fn ecs_ipv4_explicit_prefix_truncates_address() {
        // **[历史归因]** Python: "203.0.113.0/24" → 地址 3 字节。
        let (f, p, a) = parse_ecs(&ecs_option("203.0.113.0/24")).unwrap();
        assert_eq!((f, p), (1, 24));
        assert_eq!(a, vec![203, 0, 113]);
    }

    /// **[历史归因]** P-03 核心：无 `/` 的 IPv6 提升为 /128（与 Python `if prefix == 32 and "/" not in subnet` 一致）。
    #[test]
    fn ecs_ipv6_without_slash_defaults_to_128() {
        let opt = ecs_option("2001:db8::1");
        let (f, p, a) = parse_ecs(&opt).unwrap();
        assert_eq!(f, 2, "IPv6 family=2");
        assert_eq!(p, 128, "无显式前缀的 IPv6 必须提升为 /128");
        assert_eq!(a.len(), 16, "/128 必须携带完整 16 字节地址");
        assert_eq!(
            a,
            std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)
                .octets()
                .to_vec()
        );
    }

    /// P-03：显式 `/32` 必须保持 /32（4 字节），**不得**被当成"缺省"提升为 /128。
    /// **[历史归因]** 对照 Python `_ecs_option("2001:db8::1/32")`：有 "/" → prefix 32 保持，
    /// `raw[:(32+7)//8]` = 前 4 字节 `20 01 0d b8`。
    #[test]
    fn ecs_ipv6_explicit_32_stays_32() {
        let opt = ecs_option("2001:db8::1/32");
        let (f, p, a) = parse_ecs(&opt).unwrap();
        assert_eq!(f, 2, "IPv6 family=2");
        assert_eq!(p, 32, "显式 /32 必须原样保留");
        assert_eq!(a, vec![0x20, 0x01, 0x0d, 0xb8], "只发前 4 字节地址");
        assert_eq!(opt.len(), 4 + 4 + 4, "option 总长 = 4 + 4(fixed) + 4(addr)");
    }

    /// P-03：`/32` 与无前缀两种 IPv6 写法产出**不同**字节（歧义必须被消除）。
    #[test]
    fn ecs_ipv6_slash32_and_no_slash_differ() {
        assert_ne!(
            ecs_option("2001:db8::1/32"),
            ecs_option("2001:db8::1"),
            "/32 与 /128 不得折叠为同一 ECS option"
        );
    }

    /// **[历史归因]** P-03：`"/"` 存在但前缀不可解析（`int()` 抛 ValueError 等价）→ Python 的
    /// `except ValueError: addr, prefix = subnet, 32` 保留**原样 subnet**（含斜杠）→
    /// 随后 inet_pton 失败 → 返回空 bytes。Rust 的 `p.parse().unwrap_or(32)` 取
    /// 斜杠前部分解析，前缀回退 32；两者都**不带 ECS**，语义等价。
    #[test]
    fn ecs_ipv6_bad_prefix_degrades() {
        let opt = ecs_option("2001:db8::1/abc");
        // Rust 侧：addr_part="2001:db8::1" 合法 → prefix 回退 32（有 "/" 不提升）。
        let (f, p, a) = parse_ecs(&opt).unwrap();
        assert_eq!((f, p), (2, 32));
        assert_eq!(a.len(), 4);
    }

    #[test]
    fn ecs_malformed_ip_yields_empty() {
        // P2-2 对齐：畸形 subnet 优雅降级为"不带 ECS"，绝不 panic。
        assert!(ecs_option("not-an-ip").is_empty());
        assert!(ecs_option("").is_empty());
        assert!(ecs_option("300.1.1.1/24").is_empty());
    }

    #[test]
    fn ecs_prefix_clamped_to_family_max() {
        // **[历史归因]** Python: max(0, min(prefix, 32 if family==1 else 128))。
        let (f, p, _) = parse_ecs(&ecs_option("1.2.3.4/64")).unwrap();
        assert_eq!((f, p), (1, 32), "IPv4 前缀钳到 /32");
        let (f, p, a) = parse_ecs(&ecs_option("2001:db8::1/200")).unwrap();
        assert_eq!((f, p), (2, 128), "IPv6 前缀钳到 /128");
        assert_eq!(a.len(), 16);
    }
}
