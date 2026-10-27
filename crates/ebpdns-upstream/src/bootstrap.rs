//! 上游主机名解析：UDP 热路径地址缓存（300s TTL）+ bootstrap DNS 解析（域名上游 IP 预热）。
//!
//! **[历史归因]** 对齐 Python `upstream.py` 的 `_addr_cache` / `_bootstrap_cache` / `bootstrap_resolve` /
//! `_cached_udp_addrs` / `_resolve_host_once`。全部缓存有界（256 条），防无界增长。

use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

const ADDR_CACHE_TTL: Duration = Duration::from_secs(300);
const ADDR_CACHE_MAX: usize = 256;
const BOOTSTRAP_TTL: Duration = Duration::from_secs(600);
const BOOTSTRAP_CACHE_MAX: usize = 256;

struct Entry<T> {
    val: T,
    expire: Instant,
}

/// 域名上游解析器：UDP 地址缓存 + bootstrap DNS IP 缓存。
pub struct BootstrapResolver {
    /// host -> (IP 集合, 过期时刻)
    addr_cache: Mutex<HashMap<String, Entry<Vec<IpAddr>>>>,
    /// host -> (IP, 过期时刻)
    bootstrap_cache: Mutex<HashMap<String, Entry<IpAddr>>>,
}

impl Default for BootstrapResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl BootstrapResolver {
    pub fn new() -> Self {
        BootstrapResolver {
            addr_cache: Mutex::new(HashMap::new()),
            bootstrap_cache: Mutex::new(HashMap::new()),
        }
    }

    /// 解析 hostname 的 IP 集合（带 300s TTL 缓存）。
    ///
    /// **[历史归因]** 返回 IP 列表（先 A 后 AAAA，对齐 Python `_cached_udp_addrs`）。解析失败返回空 Vec。
    pub async fn resolve_udp_addrs(&self, host: &str, port: u16) -> Vec<IpAddr> {
        let now = Instant::now();
        if let Some(e) = self.addr_cache.lock().get(host) {
            if e.expire > now {
                return e.val.clone();
            }
        }
        let ips = lookup_host(host, port).await;
        if ips.is_empty() {
            return ips;
        }
        let mut g = self.addr_cache.lock();
        g.insert(
            host.to_string(),
            Entry {
                val: ips.clone(),
                expire: now + ADDR_CACHE_TTL,
            },
        );
        evict_if_over(&mut g, ADDR_CACHE_MAX, now);
        ips
    }

    /// **[历史归因]** 取 bootstrap 缓存 IP（无缓存/过期返回 None）。对齐 Python `_bootstrap_ip`。
    pub fn bootstrap_ip(&self, host: &str) -> Option<IpAddr> {
        if !crate::addr::is_hostname(host) {
            // 已是 IP 字面量。
            return host.parse::<IpAddr>().ok();
        }
        let now = Instant::now();
        let mut g = self.bootstrap_cache.lock();
        let hit = g.get(host)?;
        // expire 存"过期时刻"（写入时刻 + TTL）；过期即淘汰重解析。
        if hit.expire <= now {
            g.remove(host);
            return None;
        }
        Some(hit.val)
    }

    /// **[历史归因]** 写回 bootstrap 缓存（建连成功后）。对齐 Python `_bootstrap_set`。
    pub fn set_bootstrap(&self, host: &str, ip: IpAddr) {
        if host.is_empty() || !crate::addr::is_hostname(host) {
            return;
        }
        let now = Instant::now();
        let mut g = self.bootstrap_cache.lock();
        g.insert(
            host.to_string(),
            Entry {
                val: ip,
                expire: now + BOOTSTRAP_TTL,
            },
        );
        evict_if_over(&mut g, BOOTSTRAP_CACHE_MAX, now);
    }

    /// **[历史归因]** 连接失败时失效 bootstrap / addr 缓存。对齐 Python `_bootstrap_invalidate`。
    pub fn invalidate(&self, host: &str) {
        if host.is_empty() || !crate::addr::is_hostname(host) {
            return;
        }
        self.bootstrap_cache.lock().remove(host);
        self.addr_cache.lock().remove(host);
    }

    /// 删除上游时清理缓存。
    pub fn discard_host(&self, host: &str) {
        self.bootstrap_cache.lock().remove(host);
        self.addr_cache.lock().remove(host);
    }
}

fn evict_if_over<T>(g: &mut HashMap<String, Entry<T>>, max: usize, now: Instant) {
    if g.len() <= max {
        return;
    }
    // 先清过期项。
    let expired: Vec<String> = g
        .iter()
        .filter(|(_, e)| e.expire <= now)
        .map(|(k, _)| k.clone())
        .collect();
    for k in expired {
        g.remove(&k);
    }
    if g.len() > max {
        // 仍超限：按过期时刻淘汰最旧的 1/4。
        let mut items: Vec<(String, Instant)> =
            g.iter().map(|(k, e)| (k.clone(), e.expire)).collect();
        items.sort_by_key(|(_, exp)| *exp);
        let drop = items.len() / 4;
        for (k, _) in items.into_iter().take(drop) {
            g.remove(&k);
        }
    }
}

/// 异步解析 hostname 到 IP 列表（先 IPv4 后 IPv6）。
pub async fn lookup_host(host: &str, port: u16) -> Vec<IpAddr> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    if let Ok(iter) = tokio::net::lookup_host((host, port)).await {
        for sa in iter {
            match sa.ip() {
                IpAddr::V4(a) => v4.push(IpAddr::V4(a)),
                IpAddr::V6(a) => v6.push(IpAddr::V6(a)),
            }
        }
    }
    v4.extend(v6);
    v4
}
