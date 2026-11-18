//! 移植自 review161/tests/test_dnsmsg.py 的全部测试向量。
//! 纯逻辑、确定性、不联网。

use ebpdns_proto::constants::*;
use ebpdns_proto::edns::question_edns_info;
use ebpdns_proto::message::parse_message;
use ebpdns_proto::name::{decode_name, encode_name};
use ebpdns_proto::query::{build_query, check_0x20, extract_qname};
use ebpdns_proto::rdata::encode_rdata;
use ebpdns_proto::record::AnswerInput;
use ebpdns_proto::response::build_response_body_answers;
use ebpdns_proto::tcp::{parse_tcp_frame, tcp_frame};

// **[历史归因]** ---------- 打包小工具（对齐 Python struct.pack）----------

fn hdr(id: u16, flags: u16, qd: u16, an: u16, ns: u16, ar: u16) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(id.to_be_bytes());
    b.extend(flags.to_be_bytes());
    b.extend(qd.to_be_bytes());
    b.extend(an.to_be_bytes());
    b.extend(ns.to_be_bytes());
    b.extend(ar.to_be_bytes());
    b
}

/// RR 头：type/class/ttl/rdlen。
fn rr_head(rtype: u16, rclass: u16, ttl: u32, rdlen: u16) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(rtype.to_be_bytes());
    b.extend(rclass.to_be_bytes());
    b.extend(ttl.to_be_bytes());
    b.extend(rdlen.to_be_bytes());
    b
}

fn qtype_class(qtype: u16) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(qtype.to_be_bytes());
    b.extend(CLASS_IN.to_be_bytes());
    b
}

fn zeros(n: usize) -> Vec<u8> {
    vec![0u8; n]
}

// ================= TestNameCodec =================

#[test]
fn encode_decode_roundtrip() {
    for name in ["example.com", "www.baidu.com", "a.b.c.example.org"] {
        let wire = encode_name(name).unwrap();
        let (decoded, pos) = decode_name(&wire, 0).unwrap();
        assert_eq!(decoded, name);
        assert_eq!(pos, wire.len());
    }
}

#[test]
fn encode_rejects_overlong() {
    // 5 个 60 字节标签 + ".com"：单标签均 ≤63，但展开名线格式 >255 → Err。
    let seg = "a".repeat(60);
    let long_name = format!("{}.com", [seg.as_str(); 5].join("."));
    assert!(encode_name(&long_name).is_err());
}

#[test]
fn decode_rejects_compression_loop() {
    let data = [0xc0u8, 0x00];
    assert!(decode_name(&data, 0).is_err());
}

#[test]
fn decode_rejects_forward_pointer() {
    // \x03www\xc0\x02 —— 必然畸形（前向/截断），decode 必 Err。
    let data = [0x03u8, b'w', b'w', b'w', 0xc0, 0x02];
    assert!(decode_name(&data, 0).is_err());
}

// ================= TestBuildParseQuery =================

fn query(name: &str, qtype: u16) -> Vec<u8> {
    build_query(name, qtype, None, true, None, Some(1232), false)
        .unwrap()
        .0
}

#[test]
fn query_roundtrip() {
    let qb = query("example.com", TYPE_A);
    let msg = parse_message(&qb).unwrap();
    assert_eq!(msg.questions[0].name, "example.com");
    assert_eq!(msg.questions[0].qtype, TYPE_A);
}

#[test]
fn extract_qname_works() {
    let qb = query("test.example.com", TYPE_A);
    let raw = extract_qname(&qb).unwrap();
    let (name, _) = decode_name(&raw, 0).unwrap();
    assert_eq!(name, "test.example.com");
}

#[test]
fn parse_short_message() {
    assert!(parse_message(&[0u8; 5]).is_err());
}

// ================= TestSOABoundary =================

fn soa_packet(mname: &str, rname: &str, rdlen_override: Option<usize>) -> Vec<u8> {
    let mut q = encode_name("example.com").unwrap();
    q.extend(qtype_class(TYPE_SOA));
    let mut rdata = encode_name(mname).unwrap();
    rdata.extend(encode_name(rname).unwrap());
    for n in [1u32, 2, 3, 4, 5] {
        rdata.extend(n.to_be_bytes());
    }
    if let Some(cut) = rdlen_override {
        rdata.truncate(cut);
    }
    let h = hdr(0x1234, 0x8180, 1, 1, 0, 0);
    let mut rr = encode_name("example.com").unwrap();
    rr.extend(rr_head(TYPE_SOA, CLASS_IN, 300, rdata.len() as u16));
    rr.extend(&rdata);
    let mut pkt = h;
    pkt.extend(q);
    pkt.extend(rr);
    pkt
}

#[test]
fn valid_soa() {
    let pkt = soa_packet("ns.example.com", "hostmaster.example.com", None);
    let msg = parse_message(&pkt).unwrap();
    assert_eq!(msg.answers.len(), 1);
    assert!(msg.answers[0].rdata_str().contains("ns.example.com"));
}

#[test]
fn soa_rdlen_too_small_dropped() {
    let mut full = encode_name("ns.example.com").unwrap();
    full.extend(encode_name("hostmaster.example.com").unwrap());
    for n in [1u32, 2, 3, 4, 5] {
        full.extend(n.to_be_bytes());
    }
    let q = {
        let mut q = encode_name("example.com").unwrap();
        q.extend(qtype_class(TYPE_SOA));
        q
    };
    let h = hdr(0x1234, 0x8180, 1, 1, 0, 0);
    let owner = encode_name("example.com").unwrap();
    let mut rr = owner;
    rr.extend(rr_head(TYPE_SOA, CLASS_IN, 300, 6));
    rr.extend(&full[..6]);
    let mut pkt = h;
    pkt.extend(q);
    pkt.extend(rr);
    pkt.extend(&full[6..]);
    let msg = parse_message(&pkt).unwrap();
    assert!(msg.answers.is_empty());
}

// ================= TestInvalidARdata =================

#[test]
fn invalid_a_rdata_returns_none() {
    assert!(encode_rdata(TYPE_A, "abcd").is_none());
    assert!(encode_rdata(TYPE_A, "not-an-ip").is_none());
}

#[test]
fn valid_a_rdata() {
    assert_eq!(encode_rdata(TYPE_A, "1.2.3.4").unwrap(), vec![1, 2, 3, 4]);
}

#[test]
fn invalid_aaaa_rdata_returns_none() {
    assert!(encode_rdata(TYPE_AAAA, "zzzz").is_none());
}

#[test]
fn answer_body_skips_bad_rdata() {
    let answers = [
        AnswerInput::new(TYPE_A, "1.2.3.4").with_ttl(60),
        AnswerInput::new(TYPE_A, "abcd").with_ttl(60),
    ];
    let (body, n) = build_response_body_answers(&answers, Some("example.com"), 0, None, None);
    assert_eq!(n, 1);
    assert_eq!(body.windows(4).filter(|w| *w == [1, 2, 3, 4]).count(), 1);
    assert!(!body.windows(4).any(|w| w == b"abcd"));
}

// ================= TestTCPFrame =================

#[test]
fn tcp_roundtrip() {
    let mut payload = vec![0x12u8, 0x34, 0x00];
    payload.extend(zeros(20));
    let frame = tcp_frame(&payload).unwrap();
    let (msg, rest) = parse_tcp_frame(&frame).unwrap();
    assert_eq!(msg, payload);
    assert!(rest.is_empty());
    // 超 65535 的 payload 必须报错而不是发非法帧（长度前缀 u16 无法表达）。
    assert!(tcp_frame(&vec![0u8; 65536]).is_err());
}

#[test]
fn tcp_incomplete() {
    let frame = tcp_frame(&[b'x'; 100]).unwrap();
    assert!(parse_tcp_frame(&frame[..10]).is_err());
}

// ================= TestInvalidLabelLength (_question_edns_info) =================

#[test]
fn question_invalid_label_0x40_returns_none() {
    let mut pkt = hdr(0x1234, 0x0100, 1, 0, 0, 0);
    pkt.push(0x40);
    pkt.extend(zeros(12));
    let info = question_edns_info(&pkt);
    assert!(info.qbytes.is_none());
    assert_eq!(info.bufsize, 512);
    assert!(info.opt_bytes.is_none());
}

#[test]
fn question_invalid_label_0x80_returns_none() {
    let mut pkt = hdr(0x1234, 0x0100, 1, 0, 0, 0);
    pkt.push(0x80);
    pkt.extend(zeros(12));
    let info = question_edns_info(&pkt);
    assert!(info.qbytes.is_none());
    assert_eq!(info.bufsize, 512);
}

#[test]
fn additional_invalid_label_skips_rr() {
    let mut q = encode_name("example.com").unwrap();
    q.extend(qtype_class(TYPE_A));
    let mut bad_rr = vec![0x40u8];
    bad_rr.extend(zeros(10));
    let h = hdr(0x1234, 0x8180, 1, 0, 0, 1);
    let mut pkt = h;
    pkt.extend(q);
    pkt.extend(bad_rr);
    let info = question_edns_info(&pkt);
    assert!(info.qbytes.is_some());
    assert!(info.opt_bytes.is_none());
    assert_eq!(info.bufsize, 512);
}

// ================= TestForwardPointer =================

#[test]
fn decode_rejects_genuine_forward_pointer() {
    // 偏移 4 处指针指向偏移 6（前向引用）。
    let mut data = vec![0x03u8, b'a', b'b', b'c'];
    data.extend([0xc0, 0x06, 0x00]);
    assert!(decode_name(&data, 0).is_err());
}

#[test]
fn backward_pointer_still_allowed() {
    // 偏移 5 处指针指向偏移 0 的完整名称。
    let mut data = vec![0x03u8, b'a', b'b', b'c', 0x00];
    data.extend([0xc0, 0x00]);
    let (name, _end) = decode_name(&data, 5).unwrap();
    assert_eq!(name, "abc");
}

// ================= TestExtractQnameInvalidLabel =================

#[test]
fn qname_label_0x40_returns_none() {
    let mut pkt = hdr(0x1234, 0x0100, 1, 0, 0, 0);
    pkt.push(0x40);
    pkt.extend(zeros(20));
    assert!(extract_qname(&pkt).is_none());
}

#[test]
fn qname_label_0x80_returns_none() {
    let mut pkt = hdr(0x1234, 0x0100, 1, 0, 0, 0);
    pkt.push(0x80);
    pkt.extend(zeros(20));
    assert!(extract_qname(&pkt).is_none());
}

#[test]
fn qname_label_0xc0_compression_returns_none() {
    let mut pkt = hdr(0x1234, 0x0100, 1, 0, 0, 0);
    pkt.extend([0xc0, 0x0c]);
    pkt.extend(qtype_class(TYPE_A));
    assert!(extract_qname(&pkt).is_none());
}

#[test]
fn qname_normal_label_still_works() {
    let qb = build_query("example.com", TYPE_A, None, false, None, None, false)
        .unwrap()
        .0;
    let raw = extract_qname(&qb).unwrap();
    let (name, _) = decode_name(&raw, 0).unwrap();
    assert_eq!(name, "example.com");
}

// ================= TestCheck0x20Side =================

#[test]
fn response_malformed_question_fail_closed() {
    let qb = build_query("example.com", TYPE_A, None, false, None, None, false)
        .unwrap()
        .0;
    let mut resp = hdr(0x1234, 0x8180, 1, 0, 0, 0);
    resp.extend([0xc0, 0x0c]);
    resp.extend(qtype_class(TYPE_A));
    assert!(!check_0x20(&qb, &resp));
}

#[test]
fn query_malformed_fail_open() {
    let mut bad_q = hdr(0x1234, 0x0100, 1, 0, 0, 0);
    bad_q.extend([0xc0, 0x0c]);
    bad_q.extend(qtype_class(TYPE_A));
    let mut resp = hdr(0x1234, 0x8180, 1, 0, 0, 0);
    resp.extend([0xc0, 0x0c]);
    resp.extend(qtype_class(TYPE_A));
    assert!(check_0x20(&bad_q, &resp));
}

// ================= TestEDNSPadding =================

#[test]
fn padding_aligns_entire_message() {
    for domain in [
        "a.com",
        "example.com",
        "www.example.org",
        "a.b.c.d.e.f.example.co.uk",
        &format!("{}.com", "x".repeat(50)),
    ] {
        let qb = build_query(domain, TYPE_A, None, true, None, Some(1232), true)
            .unwrap()
            .0;
        assert_eq!(qb.len() % 128, 0, "domain={domain} len={}", qb.len());
    }
}

#[test]
fn padding_with_ecs() {
    let qb = build_query(
        "example.com",
        TYPE_A,
        None,
        true,
        Some("203.0.113.0/24"),
        Some(1232),
        true,
    )
    .unwrap()
    .0;
    assert_eq!(qb.len() % 128, 0, "padding+ecs len={}", qb.len());
}

#[test]
fn padding_option_present() {
    let qb = build_query("example.com", TYPE_A, None, true, None, Some(1232), true)
        .unwrap()
        .0;
    assert!(
        qb.windows(2).any(|w| w == [0x00, 0x0c]),
        "padding code 12 not found"
    );
}

#[test]
fn no_padding_no_alignment() {
    let qb = build_query("example.com", TYPE_A, None, true, None, Some(1232), false)
        .unwrap()
        .0;
    assert!(!qb.is_empty());
}

#[test]
fn padding_no_edns() {
    let qb = build_query("example.com", TYPE_A, None, false, None, None, true)
        .unwrap()
        .0;
    assert!(!qb.is_empty());
}

// ================= IDNA（非 ASCII 域名） =================

#[test]
fn idna_non_ascii_encodes_to_punycode() {
    // 德语变音符号域名：bücher.example.com → bücher 标签编码为 xn--bcher-kva。
    let wire = encode_name("bücher.example.com").unwrap();
    // 线格式应含 punycode 前缀 xn--。
    assert!(
        wire.windows(4).any(|w| w == b"xn--"),
        "wire 不含 xn--: {wire:?}"
    );
    // decode 回来：第一个标签是 punycode ASCII 串，后缀 example.com 不变。
    let (name, pos) = decode_name(&wire, 0).unwrap();
    assert_eq!(pos, wire.len());
    assert_eq!(name, "xn--bcher-kva.example.com");
}

#[test]
fn idna_chinese_domain_roundtrip() {
    // 中文域名：例子 → xn--fsqu00a。
    let wire = encode_name("例子").unwrap();
    let (name, _) = decode_name(&wire, 0).unwrap();
    assert_eq!(name, "xn--fsqu00a");
}

#[test]
fn idna_invalid_label_errors() {
    // 私用区码点 U+E000 是 UTS-46 禁止字符 → 逐标签 IDNA 编码失败 → InvalidName。
    assert!(encode_name("example.com").is_ok());
    assert!(encode_name("example.com\u{E000}").is_err());
}

#[test]
fn ascii_encoding_bytes_regression_case_preserved() {
    // ASCII 快路径字节与历史一致且保留大小写（0x20 熵不得被小写化）。
    let wire = encode_name("Example.COM").unwrap();
    assert_eq!(
        wire,
        vec![7, b'E', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'C', b'O', b'M', 0]
    );
    let (name, pos) = decode_name(&wire, 0).unwrap();
    assert_eq!(name, "Example.COM");
    assert_eq!(pos, wire.len());
}
