//! **[历史归因]** UDP 上游收发（对齐 Python `upstream._udp_query`）。
//!
//! 校验链：源 IP/端口 + qid + 长度下限(12) + header-only(QDCOUNT!=1) + 0x20 大小写。
//! hostname 解析出多个 IP 时向前两个并行发送，先到的合法响应获胜；单 IP 仅发一个 socket。

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use futures::future::{select_all, FutureExt};

use crate::config::UpstreamConfig;
use crate::header_check::{evaluate_x20, is_header_only, qid_of};
use crate::runtime::UpstreamRuntime;

/// UDP 查询。返回 `(ok, data)`。
pub(crate) async fn udp_query(
    rt: &UpstreamRuntime,
    cfg: &UpstreamConfig,
    query: &[u8],
    timeout: Duration,
) -> (bool, Option<Vec<u8>>) {
    let now = std::time::Instant::now();
    let deadline = now + timeout;
    rt.x20.maybe_recover(&cfg.id, now);
    let qid = qid_of(query);

    // 确定目标 IP 集合与 expect_ips。
    let ips: Vec<IpAddr> = if !crate::addr::is_hostname(&cfg.host) {
        match cfg.host.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => return (false, None),
        }
    } else {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return (false, None);
        }
        rt.bootstrap.resolve_udp_addrs(&cfg.host, cfg.port).await
    };

    if ips.is_empty() {
        // hostname 解析失败：不阻塞在 getaddrinfo，直接失败走备用上游。
        return (false, None);
    }

    // 多 IP：取前两个并行；expect_ips 收窄为实际发送集合。单 IP 直接用。
    let targets: Vec<IpAddr> = if ips.len() > 2 {
        ips[..2].to_vec()
    } else {
        ips.clone()
    };
    let expect: std::collections::HashSet<IpAddr> = targets.iter().copied().collect();

    // 每查询最多计一次 0x20 失配。
    let counted = Arc::new(parking_lot::Mutex::new(false));

    let mut tasks = Vec::new();
    for ip in &targets {
        let sock = match bind_udp(*ip).await {
            Ok(s) => s,
            Err(_) => continue,
        };
        // A7：多 IP 并行时**每个 IP 各发一份**，这才是真实线速请求数
        // （`upstream_dispatch` 只 +1）。
        rt.record_wire_request();
        let _ = sock.send_to(query, &SocketAddr::new(*ip, cfg.port)).await;
        let expect = expect.clone();
        let counted = counted.clone();
        let cfg_id = cfg.id.clone();
        let query = query.to_vec();
        let fut = async move {
            let mut buf = [0u8; 65535];
            loop {
                let remain = deadline.saturating_duration_since(std::time::Instant::now());
                if remain.is_zero() {
                    return None;
                }
                match tokio::time::timeout(remain, sock.recv_from(&mut buf)).await {
                    Ok(Ok((n, src))) => {
                        let packet = buf[..n].to_vec();
                        if validate_packet(
                            rt, &cfg_id, &query, &expect, cfg.port, qid, &packet, src, &counted,
                        ) {
                            return Some(packet);
                        }
                        // 校验未过：继续等下一条。
                    }
                    _ => return None, // 超时 / recv 错误：该 socket 失败。
                }
            }
        }
        .boxed();
        tasks.push(fut);
    }

    if tasks.is_empty() {
        return (false, None);
    }

    // select_all：任一任务返回 Some 即胜；落选任务随 drop 取消。
    let mut set = tasks;
    loop {
        if set.is_empty() {
            return (false, None);
        }
        match select_all(set).await {
            (Some(packet), _idx, _remaining) => {
                // **[历史归因]** TC=1 截断 → 对同一上游有界 TCP 回退（对齐 Python resolver）。
                if tc_bit(&packet) {
                    let budget = deadline.saturating_duration_since(std::time::Instant::now());
                    if !budget.is_zero() {
                        // A7：TC=1 触发的 TCP 回退是**额外一次**真实上游请求
                        // （由 tcp_query 内部记账，此处不重复计）。
                        if let (true, Some(full)) =
                            crate::tcp::tcp_query(rt, cfg, query, budget).await
                        {
                            // 仅当 TCP 完整帧 rcode∈{0(NOERROR),3(NXDOMAIN)} 才采用；
                            // **[历史归因]** SERVFAIL(2)/REFUSED(5) 等沿用原 UDP 截断帧（对齐 Python resolver）。
                            let rc = rcode(&full);
                            if rc == 0 || rc == 3 {
                                return (true, Some(full));
                            }
                        }
                    }
                    // TCP 回退失败/错误 rcode：保留原截断应答（上层据 TC 位处理）。
                }
                return (true, Some(packet));
            }
            (None, _idx, remaining) => set = remaining,
        }
    }
}

/// 应答 flags 的 TC 位（flags 高字节 byte2 & 0x02）。TC=1 表示 UDP 应答被截断。
fn tc_bit(packet: &[u8]) -> bool {
    packet.len() >= 3 && (packet[2] & 0x02) != 0
}

/// 应答 rcode（flags 低字节低 4 位）。0=NOERROR, 3=NXDOMAIN。
fn rcode(packet: &[u8]) -> u8 {
    if packet.len() >= 4 {
        packet[3] & 0x0F
    } else {
        0
    }
}

/// 绑一个随机本地 UDP socket（按目标地址族选 v4/v6）。
async fn bind_udp(ip: IpAddr) -> std::io::Result<tokio::net::UdpSocket> {
    let bind: SocketAddr = match ip {
        IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        IpAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    tokio::net::UdpSocket::bind(bind).await
}

/// 校验一条 UDP 响应是否可接受（源 IP/端口 + qid + 长度 + header-only + 0x20）。
#[allow(clippy::too_many_arguments)]
fn validate_packet(
    rt: &UpstreamRuntime,
    up_id: &str,
    query: &[u8],
    expect: &std::collections::HashSet<IpAddr>,
    port: u16,
    qid: Option<u16>,
    packet: &[u8],
    src: SocketAddr,
    counted: &Arc<parking_lot::Mutex<bool>>,
) -> bool {
    // 源 IP/端口校验。
    if !expect.is_empty() && !expect.contains(&src.ip()) {
        return false;
    }
    if src.port() != port {
        return false;
    }
    // 长度下限（fail-closed，不受 0x20 降级影响）。
    if packet.len() < 12 {
        return false;
    }
    // header-only（QDCOUNT!=1）拒绝。
    if is_header_only(packet) {
        return false;
    }
    // qid 校验（防乱序/投毒）。
    if let Some(rq) = qid {
        if qid_of(packet) != Some(rq) {
            return false;
        }
    }
    // 0x20 大小写校验（含自适应降级）。
    let mut c = counted.lock();
    evaluate_x20(
        &rt.x20,
        up_id,
        query,
        packet,
        std::time::Instant::now(),
        &mut c,
    )
}
