"""配置加载 / 保存 / 默认值。支持 /etc/ebpdns/config.json 与本地 config.json。"""

import copy
import json
import logging
import os
import sys
import time

# 默认配置（与前端控制台语义对齐）
DEFAULTS = {
    "listen": {
        "udp": "0.0.0.0:53",
        "tcp": "0.0.0.0:53",
        "udp6": "[::]:53",   # IPv6 UDP 监听(可选; 无 IPv6 栈环境自动跳过仅告警)
        "tcp6": "[::]:53",   # IPv6 TCP 监听(可选)
    },
    "api": {
        "host": "127.0.0.1",
        "port": 8080,
    },
    "cache_size": 131072,
    "cache_policy": "lru",           # 缓存淘汰策略: lru(按分流group分区) / tinylfu(W-TinyLFU 高频保留)
    "cache_partitions": None,        # 分区容量比例 {domestic,global,default}, None=默认 0.2/0.2/0.6
    "health_check_interval": 30,     # 上游主动健康检查周期(秒), 0=关闭
    "health_probe_domain": "www.baidu.com",  # 健康检查探测域名(绕过分流规则直连上游)
    "health_probe_timeout_ms": 2000, # 健康检查探测超时(毫秒)
    "circuit_fails": 3,               # 熔断器连续失败阈值(达到后打开熔断)
    "circuit_open_s": 30,             # 熔断打开持续时间(秒), 超时后半开探测
    "bootstrap_dns": "223.5.5.5:53", # DoH/DoT hostname 预解析用的 UDP bootstrap DNS, 摆脱系统DNS依赖
    "rule_sub_interval": 3600,       # 规则订阅自动更新周期(秒), 0=关闭
    "ttl": 300,
    "ttl_min": 0,                # 下发 TTL 下限(秒), 0=不限制; 内网客户端收到的应答 TTL 不低于此值
    "ttl_max": 0,                # 下发 TTL 上限(秒), 0=不限制; 内网客户端收到的应答 TTL 不高于此值
    "serve_stale": False,        # 过期缓存兜底: 缓存过期后在 stale 窗口内仍返回旧数据并后台刷新
    "stale_ttl": 3600,           # 过期兜底窗口(秒), 超过后过期条目视为失效进入正常 miss
    "persist_ttl": 0,            # 持久化缓存恢复后的独立 TTL(秒), 0=按保存时剩余 TTL 原样恢复
    "prefetch": True,
    "kernel_direct": True,          # 缓存命中语义标记"内核直答"（真实 XDP 数据面时启用）
    "speed_test": True,             # 测速择优
    "speed_interval_ms": 2000,
    "speed_timeout_ms": 300,
    "ip_speed_check": True,         # 候选 IP 测速: 对多 IP 答案并发探测 RTT 并按速度排序
    "ip_speed_probe": "both",       # 探测方式: udp53 / tcp443 / both(取最快)
    "ip_speed_cache_ttl": 60,       # IP 测速结果缓存(秒), 命中直接复用避免重复探测
    "fallback": True,               # 上游失败降级
    "ipv4_first": True,             # A/AAAA 同时存在时优先 A
    "ipv6": True,                   # 关闭后 AAAA 直接返回空应答(全局一刀切)
    "prefer_ipv4": False,           # 双栈智能(替代全局 ipv6 开关): 有 A 记录的域名屏蔽 AAAA, 纯 IPv6 域名不误伤
    "edns": True,                   # 携带 EDNS0
    "edns_udp_size": 1232,          # 出站查询 EDNS0 UDP payload(字节): 1232=防分片安全值, 减少 UDP 分片丢失导致的超时
    "padding": False,               # 加密查询(DNS over TLS/HTTPS/QUIC)报文填充: 对齐 128B 块抹平长度指纹, 仅加密协议生效
    "rebind_protection": True,      # 响应 IP 合法性校验: 丢弃上游返回的私有/保留/环回地址(防 DNS 劫持/DNS rebinding), forceIp 规则豁免
    "edns_client_subnet": None,     # 如 "203.0.113.0/24"
    "hook": "XDP 原生",
    "map_type": "LRU_HASH",
    "percpu": True,
    "dnssec_0x20": True,            # DNS 0x20 投毒防护: 明文 UDP/TCP 查询名大小写随机(约+26bit熵)
    "log_format": "text",           # 日志格式: text=可读文本 / json=结构化 JSON lines(可观测性)
    "timeout_ms": 1500,             # 上游单次查询超时
    "max_parallel_upstreams": 3,    # 工作线程池估算基数(解析已改为并发全部可用上游)
    "log_level": "info",
    "web_root": None,               # None = 自动定位到包内 web/ 目录
    "upstreams": [
        {"id": "ali-doh3", "name": "AliDNS DoH3", "proto": "doh3", "addr": "dns.alidns.com", "port": 443, "url": "/dns-query", "group": "domestic", "latency": 30, "enabled": True, "latency_measured": False},
        {"id": "dnspod-doh3", "name": "DNSPod DoH3", "proto": "doh3", "addr": "doh.pub", "port": 443, "url": "/dns-query", "group": "domestic", "latency": 40, "enabled": True, "latency_measured": False},
        {"id": "ali-doh", "name": "AliDNS DoH", "proto": "doh", "addr": "dns.alidns.com", "port": 443, "url": "/dns-query", "group": "domestic", "latency": 30, "enabled": True, "latency_measured": False},
        {"id": "dnspod-doh", "name": "DNSPod DoH", "proto": "doh", "addr": "doh.pub", "port": 443, "url": "/dns-query", "group": "domestic", "latency": 40, "enabled": True, "latency_measured": False},
        {"id": "ali-ip-doh", "name": "AliDNS IP DoH", "proto": "doh", "addr": "223.5.5.5", "port": 443, "url": "/dns-query", "group": "domestic", "latency": 30, "enabled": True, "latency_measured": False},
        {"id": "dnspod-ip-doh", "name": "DNSPod IP DoH", "proto": "doh", "addr": "120.53.53.53", "port": 443, "url": "/dns-query", "group": "domestic", "latency": 40, "enabled": True, "latency_measured": False},
        {"id": "ali-ip2-doh", "name": "AliDNS2 IP DoH", "proto": "doh", "addr": "223.6.6.6", "port": 443, "url": "/dns-query", "group": "domestic", "latency": 30, "enabled": True, "latency_measured": False},
        {"id": "cf-doh3", "name": "Cloudflare DoH3", "proto": "doh3", "addr": "cloudflare-dns.com", "port": 443, "url": "/dns-query", "group": "global", "latency": 150, "enabled": False, "latency_measured": False},
        {"id": "google-doh3", "name": "Google DoH3", "proto": "doh3", "addr": "dns.google", "port": 443, "url": "/dns-query", "group": "global", "latency": 160, "enabled": False, "latency_measured": False},
        {"id": "quad9-doh3", "name": "Quad9 DoH3", "proto": "doh3", "addr": "dns.quad9.net", "port": 443, "url": "/dns-query", "group": "global", "latency": 180, "enabled": False, "latency_measured": False},
        {"id": "cf-ip-doh", "name": "Cloudflare IP DoH", "proto": "doh", "addr": "1.1.1.1", "port": 443, "url": "/dns-query", "group": "global", "latency": 150, "enabled": False, "latency_measured": False},
        {"id": "cf-doh", "name": "Cloudflare DoH", "proto": "doh", "addr": "cloudflare-dns.com", "port": 443, "url": "/dns-query", "group": "global", "latency": 150, "enabled": False, "latency_measured": False},
        {"id": "google-doh", "name": "Google DoH", "proto": "doh", "addr": "dns.google", "port": 443, "url": "/dns-query", "group": "global", "latency": 160, "enabled": True, "latency_measured": False},
        {"id": "google-ip-doh", "name": "Google IP DoH", "proto": "doh", "addr": "8.8.8.8", "port": 443, "url": "/dns-query", "group": "global", "latency": 160, "enabled": False, "latency_measured": False},
        {"id": "quad9-doh", "name": "Quad9 DoH", "proto": "doh", "addr": "dns.quad9.net", "port": 443, "url": "/dns-query", "group": "global", "latency": 180, "enabled": True, "latency_measured": False},
        {"id": "nextdns-doh", "name": "NextDNS DoH", "proto": "doh", "addr": "dns.nextdns.io", "port": 443, "url": "/4d5525", "group": "global", "latency": 200, "enabled": False, "latency_measured": False},
        {"id": "opendns-doh", "name": "OpenDNS DoH", "proto": "doh", "addr": "doh.opendns.com", "port": 443, "url": "/dns-query", "group": "global", "latency": 200, "enabled": True, "latency_measured": False},
        {"id": "dnssb-doh", "name": "DNS.SB DoH", "proto": "doh", "addr": "doh.dns.sb", "port": 443, "url": "/dns-query", "group": "global", "latency": 220, "enabled": False, "latency_measured": False},
        {"id": "adguard-doh", "name": "AdGuard DoH", "proto": "doh", "addr": "dns.adguard.com", "port": 443, "url": "/dns-query", "group": "global", "latency": 220, "enabled": True, "latency_measured": False},
        {"id": "hinet-doh", "name": "HiNet DoH", "proto": "doh", "addr": "dns.hinet.net", "port": 443, "url": "/dns-query", "group": "global", "latency": 200, "enabled": False, "latency_measured": False},
        {"id": "ali-udp", "name": "AliDNS UDP", "proto": "udp", "addr": "223.5.5.5", "port": 53, "url": "", "group": "domestic", "latency": 8, "enabled": True, "latency_measured": False},
        {"id": "dnspod-udp", "name": "DNSPod UDP", "proto": "udp", "addr": "119.29.29.29", "port": 53, "url": "", "group": "domestic", "latency": 10, "enabled": True, "latency_measured": False},
    ],
    "rules": [
        {"id": "r1", "match": "*.baidu.com", "action": "group", "group": "domestic"},
        {"id": "r2", "match": "*.google.com", "action": "group", "group": "global"},
        {"id": "r3", "match": "update.microsoft.com", "action": "group", "group": "global"},
    ],
    # 规则订阅源元信息(仅存链接/动作/更新时间, 订阅的域名明细存独立文件 rules_sub.json)
    "rule_subscriptions": [],
}


def deep_merge(base, override):
    """递归合并配置字典（override 优先）。"""
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def sub_rules_path(config_path=None):
    """订阅规则独立文件路径: 与 config.json 同目录的 rules_sub.json。
    订阅的域名明细不写入 config.json, 由本文件单独存放, 便于大列表读写与更新。"""
    base = config_path or "/etc/ebpdns/config.json"
    return os.path.join(os.path.dirname(os.path.abspath(base)), "rules_sub.json")


def local_rules_path(config_path=None):
    """逐条规则独立文件路径: 与 config.json 同目录的 rules_local.json。
    用户逐条添加/导入的域名规则不写入 config.json, 由本文件单独存放。"""
    base = config_path or "/etc/ebpdns/config.json"
    return os.path.join(os.path.dirname(os.path.abspath(base)), "rules_local.json")


def load_local_rules(config_path=None):
    """读取逐条规则独立文件。文件不存在返回 None(与"空列表"区分, 供迁移判断);
    JSON 损坏返回 [] 并告警, 不静默吞错。"""
    path = local_rules_path(config_path)
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("rules") or []
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        logging.warning("逐条规则独立文件读取失败 %s: %s", path, e)
        return []


def save_local_rules(rules, config_path=None):
    """原子写逐条规则独立文件(不写入 config.json)。返回写入条数; 失败 0 并告警。"""
    path = local_rules_path(config_path)
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        data = json.dumps({
            "version": 1,
            "saved_at": time.time(),
            "count": len(rules),
            "rules": rules,
        }, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        return len(rules)
    except Exception as e:
        logging.warning("保存逐条规则独立文件失败 %s: %s", path, e)
        return 0


UP_PORT_DEFAULT = {"udp": 53, "tcp": 53, "doh": 443, "dot": 853, "doq": 853, "doh3": 443}


def parse_upstream_addr(raw, proto_sel=None):
    """从完整地址自动识别上游协议/地址/端口/路径（与前端规则一致）。

    支持: https://host/path  http://host/path  quic://host  tls://host
          dot://host  udp://host  tcp://host  doh://host  doh3://host
          host:port  host  ip  ip:port
    proto_sel 非空且非 'auto' 时强制指定协议(无 scheme 前缀时生效)。
    返回 dict{proto,addr,port,url}; 无法识别返回 None。
    """
    if not raw:
        return None
    s = str(raw).strip()
    if not s:
        return None
    proto, rest, url = None, s, ""
    m = None
    for i, ch in enumerate(s):
        if ch == ":":
            m = (s[:i], s[i + 1:])
            break
    if m and m[1].startswith("//"):
        scheme = m[0].lower()
        rest = m[1][2:]
        if scheme == "https":
            proto, url = "doh", "/dns-query"
        elif scheme == "http":
            proto, url = "doh", "/dns-query"
        elif scheme == "quic":
            proto, url = "doq", "/dns-query"
        elif scheme in ("tls", "dot"):
            proto, url = "dot", ""
        elif scheme == "udp":
            proto, url = "udp", ""
        elif scheme == "tcp":
            proto, url = "tcp", ""
        elif scheme == "doh":
            proto, url = "doh", "/dns-query"
        elif scheme == "doh3":
            proto, url = "doh3", "/dns-query"
        else:
            return None
    elif proto_sel and proto_sel != "auto":
        proto = proto_sel
        if proto in ("doh", "doh3", "doq"):
            url = "/dns-query"
    else:
        proto = "udp"
    host = rest
    port = UP_PORT_DEFAULT.get(proto, 53)
    slash = host.find("/")
    if slash >= 0:
        p = host[slash:]
        if proto in ("doh", "doh3", "doq"):
            url = p if p.startswith("/") else "/" + p
        host = host[:slash]
    colon = host.rfind(":")
    if colon > 0 and host[colon + 1:].isdigit():
        port = int(host[colon + 1:])
        host = host[:colon]
    if not host:
        return None
    # 宽松校验 host: IP / 域名 / IPv6 字面量(带括号)
    if not all(c.isalnum() or c in ".-_:[]" for c in host):
        return None
    if proto in ("doh", "doh3", "doq"):
        if not url:
            url = "/dns-query"
        if not url.startswith("/"):
            url = "/" + url
    else:
        url = ""
    return {"proto": proto, "addr": host, "port": port, "url": url}


def default_config():
    return copy.deepcopy(DEFAULTS)


def default_paths():
    """返回候选配置路径列表（按优先级）。"""
    cands = []
    env = os.environ.get("EBPDNS_CONFIG")
    if env:
        cands.append(env)
    cands.append("/etc/ebpdns/config.json")
    workdir = os.getcwd()
    cands.append(os.path.join(workdir, "config.json"))
    here = os.path.dirname(os.path.abspath(__file__))
    cands.append(os.path.join(os.path.dirname(here), "etc", "ebpdns.conf.json"))
    return cands


def load_config(path=None):
    cfg = default_config()
    chosen = path
    if not chosen:
        for p in default_paths():
            if os.path.isfile(p):
                chosen = p
                break
    if chosen and os.path.isfile(chosen):
        try:
            with open(chosen, "r", encoding="utf-8") as f:
                data = json.load(f)
            cfg = deep_merge(cfg, data)
        except Exception as e:
            sys.stderr.write("warning: 读取配置失败 %s: %s\n" % (chosen, e))
    if cfg.get("web_root") is None:
        cfg["web_root"] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "web")
    return cfg


def save_config(cfg, path=None):
    target = path
    if not target:
        # 优先 /etc/ebpdns/config.json；不可写则当前目录
        candidates = ["/etc/ebpdns/config.json", os.path.join(os.getcwd(), "config.json")]
        for c in candidates:
            try:
                with open(c, "r", encoding="utf-8") as _:
                    pass
                target = c
                break
            except Exception:
                try:
                    parent = os.path.dirname(c)
                    if parent and not os.path.isdir(parent):
                        os.makedirs(parent, exist_ok=True)
                    with open(c, "w", encoding="utf-8") as f:
                        json.dump({}, f)
                    target = c
                    break
                except Exception:
                    continue
        if not target:
            target = os.path.join(os.getcwd(), "config.json")
    os.makedirs(os.path.dirname(os.path.abspath(target)) or ".", exist_ok=True)
    # 规则/上游数量大时用 compact 格式: indent=2 会让 10 万规则的 config 达 15MB+,
    # 每次全量保存都很慢。compact(分隔符无空格) 体积约减半, 序列化/写盘快约 2.5x。
    big = len(cfg.get("rules", [])) > 5000 or len(cfg.get("upstreams", [])) > 100
    _dumps = lambda: (json.dumps(cfg, ensure_ascii=False, separators=(",", ":")) if big
                      else json.dumps(cfg, ensure_ascii=False, indent=2))
    try:
        # 原子写入：临时文件 + rename，避免崩溃留下半截 JSON
        tmp = target + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(_dumps())
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, target)
    except OSError:
        # tmp 写失败(受限文件系统/磁盘满)时降级直接写目标文件, 避免配置保存失败中断 API
        with open(target, "w", encoding="utf-8") as f:
            f.write(_dumps())
            f.flush()
            os.fsync(f.fileno())
    return target
