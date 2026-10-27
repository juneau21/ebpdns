//! ebpdns-proto 热路径基准（criterion）。
//!
//! 覆盖每查询热路径：parse_message（压缩/rdata）、build_query（EDNS/padding）、
//! build_response / build_udp_response、encode_name（ASCII + IDNA）。

use criterion::{criterion_group, criterion_main, Criterion, Throughput};

use ebpdns_proto::constants::*;
use ebpdns_proto::message::parse_message;
use ebpdns_proto::name::encode_name;
use ebpdns_proto::query::build_query;
use ebpdns_proto::record::AnswerInput;
use ebpdns_proto::response::{
    build_response, build_response_body_answers, build_simple_response, build_udp_response, UdpResp,
};

// ---------- 构造真实报文 ----------

/// 构造一个典型 A 响应：1 question + 8 条 A answer（owner 用压缩指针）+ NS authority + OPT。
fn realistic_response() -> Vec<u8> {
    // header: id=0x1234, flags=0x8180, qd=1, an=8, ns=1, ar=1
    let mut p = Vec::with_capacity(256);
    p.extend(0x1234u16.to_be_bytes());
    p.extend(0x8180u16.to_be_bytes());
    p.extend(1u16.to_be_bytes()); // qd
    p.extend(8u16.to_be_bytes()); // an
    p.extend(1u16.to_be_bytes()); // ns
    p.extend(1u16.to_be_bytes()); // ar

    // question（位于 offset 12）
    let qname = encode_name("example.com").unwrap();
    p.extend(&qname);
    p.extend(TYPE_A.to_be_bytes());
    p.extend(CLASS_IN.to_be_bytes());

    // 8 条 A 记录：owner 压缩指针指向 question qname（offset 12 = 0xc00c）
    for i in 0..8u8 {
        p.extend(0xc00cu16.to_be_bytes()); // owner pointer
        p.extend(TYPE_A.to_be_bytes());
        p.extend(CLASS_IN.to_be_bytes());
        p.extend(300u32.to_be_bytes());
        p.extend(4u16.to_be_bytes()); // rdlen
        p.extend([10u8, i + 1, 1, 1]); // 10.x.1.1
    }

    // authority: NS 记录（owner 压缩指针指向 com 末尾？简化为指针到 qname）
    p.extend(0xc00cu16.to_be_bytes());
    p.extend(TYPE_NS.to_be_bytes());
    p.extend(CLASS_IN.to_be_bytes());
    p.extend(86400u32.to_be_bytes());
    let ns = encode_name("ns1.example.com").unwrap();
    p.extend((ns.len() as u16).to_be_bytes());
    p.extend(&ns);

    // additional: OPT RR
    p.push(0u8); // root name
    p.extend(TYPE_OPT.to_be_bytes());
    p.extend(1232u16.to_be_bytes()); // UDP payload
    p.extend(0u32.to_be_bytes());
    p.extend(0u16.to_be_bytes()); // rdlen
    p
}

/// 一个带 EDNS+ECS+padding 的查询报文（用于 response 系基准的 raw_query）。
fn edns_query() -> Vec<u8> {
    build_query(
        "www.example.com",
        TYPE_A,
        Some(0x1234),
        true,
        Some("203.0.113.0/24"),
        Some(1232),
        true,
    )
    .unwrap()
    .0
}

// ---------- benchmarks ----------

fn bench_parse_message(c: &mut Criterion) {
    let pkt = realistic_response();
    eprintln!("response packet len = {}", pkt.len());
    let mut group = c.benchmark_group("proto");
    group.throughput(Throughput::Bytes(pkt.len() as u64));
    group.bench_function("parse_message/8A+NS+OPT", |b| {
        b.iter(|| parse_message(&pkt).unwrap());
    });
    group.finish();
}

fn bench_build_query(c: &mut Criterion) {
    let mut group = c.benchmark_group("proto");
    group.bench_function("build_query/edns+ecs+padding", |b| {
        b.iter(|| {
            build_query(
                "www.example.com",
                TYPE_A,
                Some(0x1234),
                true,
                Some("203.0.113.0/24"),
                Some(1232),
                true,
            )
            .unwrap()
        });
    });
    group.bench_function("build_query/edns_nopad", |b| {
        b.iter(|| {
            build_query(
                "www.example.com",
                TYPE_A,
                Some(0x1234),
                true,
                None,
                Some(1232),
                false,
            )
            .unwrap()
        });
    });
    group.finish();
}

fn bench_build_response(c: &mut Criterion) {
    let query = edns_query();
    let ips: Vec<String> = (0..8).map(|i| format!("10.0.0.{i}")).collect();
    let answers: Vec<AnswerInput> = ips
        .iter()
        .map(|s| AnswerInput::new(TYPE_A, s).with_ttl(300))
        .collect();
    let mut group = c.benchmark_group("proto");
    group.bench_function("build_response/8A", |b| {
        b.iter(|| {
            build_response(
                &query,
                "www.example.com",
                TYPE_A,
                &answers,
                0,
                None,
                None,
                false,
            )
            .unwrap()
        });
    });
    group.bench_function("build_udp_response/8A", |b| {
        b.iter(|| {
            build_udp_response(&UdpResp {
                raw_query: &query,
                qbytes: None,
                answers: &answers,
                rcode: 0,
                abody: None,
                abody_count: None,
                owner_name: Some("www.example.com"),
                fallback_type: TYPE_A,
                ttl_override: None,
                bufsize_cap: None,
                force_truncated: false,
                enc_owner: None,
                edns_info: None,
            })
            .unwrap()
        });
    });
    group.bench_function("build_simple_response/nxdomain", |b| {
        b.iter(|| build_simple_response(&query, 3).unwrap());
    });
    group.bench_function("build_response_body_answers/8A", |b| {
        b.iter(|| {
            build_response_body_answers(&answers, Some("www.example.com"), TYPE_A, None, None)
        });
    });
    group.finish();
}

fn bench_encode_name(c: &mut Criterion) {
    let mut group = c.benchmark_group("proto");
    group.bench_function("encode_name/ascii", |b| {
        b.iter(|| encode_name("www.example.com").unwrap());
    });
    group.bench_function("encode_name/idna", |b| {
        b.iter(|| encode_name("bücher.example.com").unwrap());
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_parse_message,
    bench_build_query,
    bench_build_response,
    bench_encode_name
);
criterion_main!(benches);
