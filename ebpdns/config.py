"""配置加载 / 保存 / 默认值。支持 /etc/ebpdns/config.json 与本地 config.json。"""

import copy
import ipaddress
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
        # P1-1: IPv6 默认不监听。此前默认值 [::]:53 会让磁盘未显式写 udp6/tcp6 的
        # 配置(deep_merge 保留默认)在所有 IPv6 接口监听 53, 成为隐蔽的开放解析器。
        # 改为 None: 仅当用户在配置中显式写出 udp6/tcp6 才绑定 IPv6(server.py 对
        # None/空跳过绑定并仅告警)。
        "udp6": None,   # IPv6 UDP 监听(可选; 需用户显式配置, 如 "[::1]:53")
        "tcp6": None,   # IPv6 TCP 监听(可选; 需用户显式配置, 如 "[::1]:53")
    },
    "api": {
        "host": "127.0.0.1",   # API 监听地址, 默认仅本机回环(天然安全, 无需 token)
        "port": 8080,
        # P2-24: 可选 API 认证 token。空字符串=不启用(默认, 仅本机回环时安全)。
        # 绑定非回环地址时建议设置, 客户端需带 Authorization: Bearer <token> 或
        # X-Api-Key: <token> 头。最长 256 字符。
        "token": "",
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
    """原子写逐条规则独立文件(不写入 config.json)。
    R2-P1: 返回 bool 成功/失败, 不再返回写入条数。
    旧实现返回 len(rules) —— 空规则(清空全部)成功也返回 0, 与写盘失败(0)无法区分,
    调用方用 `saved_cnt==0 and len(rules)>0` 兜底, 导致清空规则时写盘失败被静默吞掉。
    改为 True/False 后, 空规则写成功=True, 写失败=False, 语义明确无歧义。"""
    path = local_rules_path(config_path)
    # R37 P3-1: tmp 提到 try 外, 与 save_config(R36 P3-2) 同型, 便于 except 分支清理残留 .tmp
    tmp = path + ".tmp"
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        data = json.dumps({
            "version": 1,
            "saved_at": time.time(),
            "count": len(rules),
            "rules": rules,
        }, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            # P3-2(R5): 与 cli._save_cache 持久性承诺对齐。os.replace 仅保证目录项原子
            # 切换, 不保证文件内容已落物理介质; rename 后到内核回写前掉电会丢已返回 200
            # 的规则。save 非热路径, fsync 一次耗时可忽略, 不影响 QPS。
            os.fsync(f.fileno())
        os.replace(tmp, path)
        # R6 P4-1: 与 save_config 原子路径一致, 此处目录项持久化属已知权衡(见
        # save_config 内注释); 该文件为本地规则副本, 可由 config 重建, 不强制目录 fsync。
        return True
    except Exception as e:
        # R37 P3-1: 原子写失败(如 os.replace 跨设备/只读/磁盘满)时清理残留 .tmp,
        # 与 save_config(R36 P3-2) 同型。open 失败时 tmp 可能不存在,
        # exists 判断 + 内层 try/except 保证清理自身不抛错。
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
        logging.warning("保存逐条规则独立文件失败 %s: %s", path, e)
        return False


UP_PORT_DEFAULT = {"udp": 53, "tcp": 53, "doh": 443, "dot": 853, "doq": 853, "doh3": 443}


# R30 P3-6: 上游 host 字符集白名单, 与 api._HOST_RE ([a-zA-Z0-9._:\[\]-]{1,253}) 对齐。
# 用集合 O(1) 成员判定, 避免 str.isalnum() 接受 Unicode 字母导致 IDN 域名未 punycode 即落库。
_UPSTREAM_HOST_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:[]"
)


def parse_upstream_addr(raw, proto_sel=None):
    """从完整地址自动识别上游协议/地址/端口/路径（与前端规则一致）。

    支持: https://host/path  http://host/path  quic://host  doq://host  tls://host
          dot://host  udp://host  tcp://host  doh://host  doh3://host
          http3://host/path  h3://host/path (DoH3/HTTP3 别名)
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
    _http_plain = False   # http:// 明文 DoH: 端口默认 80 (区别于 https:// 的 443)
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
            _http_plain = True
            # P3-14: 明文 DoH (http://) 不加密, 可被中间人窃听/篡改 DNS 应答。
            # 不禁止(内网/测试场景可能需要), 但给出明确警告。
            logging.warning("明文 DoH (http://) 可被中间人窃听/篡改, 建议使用 https:// (上游 %s)", raw)
        elif scheme == "quic":
            proto, url = "doq", "/dns-query"
        elif scheme == "doq":
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
        elif scheme in ("http3", "h3"):
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
    if _http_plain:
        port = 80   # 明文 http:// DoH 走 80, 不沿用 doh 的 443 默认
    slash = host.find("/")
    if slash >= 0:
        p = host[slash:]
        if proto in ("doh", "doh3", "doq"):
            url = p if p.startswith("/") else "/" + p
        host = host[:slash]
    # 端口切分: 先排除裸 IPv6 字面量(含多个冒号且未用方括号包裹),
    # 否则 rfind(":") 会把 2606:4700::1 的末段 ":1" 误切为 port=1。
    # 裸 IPv6 整体作为 host, 不切端口; 带方括号形式 [v6]:port 由 _host_port 解析。
    if not (host.count(":") > 1 and not host.startswith("[")):
        colon = host.rfind(":")
        if colon > 0 and host[colon + 1:].isdigit():
            port = int(host[colon + 1:])
            host = host[:colon]
    if not host:
        return None
    # 宽松校验 host: IP / 域名 / IPv6 字面量(带括号)
    # R30 P3-6: 与 api._valid_host 的 ASCII 白名单 [a-zA-Z0-9._:[\]-] 对齐。
    # 此前用 str.isalnum() 接受 Unicode 字母(如 éxample.com), 而 API 手动/PUT/bulk 路径
    # 走严格 ASCII 白名单——自动解析分支接受的 host 字符集比手动分支宽。IDN 域名未做
    # punycode 转换即落库, 后续 DNS 查询用非 ASCII 主机名会失败。统一为 ASCII 白名单。
    if not host or len(host) > 253:
        return None
    if not all(c in _UPSTREAM_HOST_CHARS for c in host):
        return None
    # R44 P3-1: 方括号 IPv6 字面量带尾随冒号(如 "[::1]:") 的冒号总数为 3,
    # 穿透下方 count(":")==1 拦截。配置期拦截, 避免运行时 getaddrinfo("[::1]:") 才失败。
    if host.startswith("[") and host.endswith(":"):
        return None
    # R43 P3-2: 端口切分未命中时残留的单冒号必为畸形 host(如 "example.com:" 尾随冒号,
    # 或 "example.com:abc" 非数字端口)。单冒号在纯主机名中唯一合法用途即 host:port,
    # 上方已按"冒号后纯数字"切分; 切分后仍残留单冒号说明后缀为空/非数字, 配置期拦截,
    # 避免运行时 getaddrinfo 才报错。多冒号裸 IPv6 字面量由上方 count(":")>1 分支整体保留,
    # count 远大于 1, 不受此判断影响。
    if host.count(":") == 1:
        return None
    # P2-5: 端口范围校验。_NUM_RANGES 里的 "port" 注释自称"仅顶层", 实际从不匹配
    # 嵌套在上游/api 内的 port; 这里在解析处兜底, 拒绝 port=0 / 99999 等非法值。
    if not isinstance(port, int) or not (1 <= port <= 65535):
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


# ---- 加载期字段类型/范围校验(防坏配置把服务静默改坏) ----
# 数值字段: (下限, 上限); None 表示该方向不限
_NUM_RANGES = {
    "cache_size": (1, 10_000_000),
    "ttl": (0, None),
    "ttl_min": (0, None),
    "ttl_max": (0, None),
    "timeout_ms": (1, 60000),
    # P3-9: 删除从未使用的顶层 "port" 键(顶层配置无 port, port 仅嵌套在上游/api 内,
    # 由 parse_upstream_addr 与 _validate_upstream_dict 分别校验)。
    "health_check_interval": (0, None),
    "max_parallel_upstreams": (1, 16),
    "stale_ttl": (0, None),
    "persist_ttl": (0, None),
    "speed_interval_ms": (0, None),
    "speed_timeout_ms": (1, 60000),
    # v1.9.84 P2: 补齐此前漏校验的用户可调数值键
    "edns_udp_size": (512, 9000),
    "health_probe_timeout_ms": (100, 60000),
    "rule_sub_interval": (0, None),
    # v1.9.89 P3-1(第八轮): 补齐 circuit breaker / IP 速度缓存 TTL 的数值范围校验
    "circuit_fails": (1, 100),
    "circuit_open_s": (1, 86400),
    "ip_speed_cache_ttl": (0, 86400),
}
# 枚举字段: 合法取值集合
_ENUM_VALUES = {
    "log_level": {"debug", "info", "warning", "error"},
    "log_format": {"text", "json"},
    "cache_policy": {"lru", "partitioned", "tinylfu"},
    # ip_speed_probe 是字符串枚举(udp53/tcp443/both), 不是布尔; 误放入
    # _BOOL_KEYS 会导致每次启动把用户值回退为默认 "both" 并刷一条告警。
    "ip_speed_probe": {"udp53", "tcp443", "both"},
}
# 布尔字段
_BOOL_KEYS = {
    "prefetch", "serve_stale", "kernel_direct", "speed_test", "fallback",
    "ipv4_first", "ipv6", "edns", "padding", "rebind_protection",
    "ip_speed_check", "dnssec_0x20", "prefer_ipv4",
}


def _fallback(cfg, key):
    """把 key 还原为 DEFAULTS 默认值并告警。"""
    cfg[key] = copy.deepcopy(DEFAULTS.get(key))
    logging.warning("配置字段 %s 非法, 已回退默认值 %r", key, cfg[key])


# v7 P2-2: rule_subscriptions[] 合法 action 枚举(与 api._RULE_ACTIONS 一致)。
# config.py 不导入 api.py(循环依赖), 在此独立维护一份轻量校验。
_RULE_SUB_ACTIONS = ("allow", "block", "group", "forceIp")


def _validate_rule_subscription_item(item):
    """轻量校验单个 rule_subscriptions[] 项(加载期/热重载调用)。
    检查: 必须是 dict; url 非空且 https:// 开头; action 在枚举内;
    forceIp 时 ip 必须是合法 IPv4/IPv6。返回 True=通过, False=非法(调用方跳过)。
    不抛异常, 不中断启动。"""
    if not isinstance(item, dict):
        return False
    url = str(item.get("url") or "").strip()
    if not url or not url.lower().startswith("https://"):
        return False
    if item.get("action") not in _RULE_SUB_ACTIONS:
        return False
    if item.get("action") == "forceIp":
        ip = str(item.get("ip") or "").strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return False
    return True


def _validate_cfg(cfg):
    """加载后对顶层标量字段做类型/范围校验; 非法值回退默认并告警,
    不抛异常中断启动。"""
    for key, (lo, hi) in _NUM_RANGES.items():
        if key not in cfg:
            continue   # 顶层无此键(如 port 仅嵌套在上游/api 内), 不注入
        v = cfg.get(key)
        # R2-P3: bool 是 int 子类, int(True)==1 会穿透到合法值。
        # 与 api._validate_cfg_update / 规则 ttl 校验同型 bug, 加载期也需排除。
        if isinstance(v, bool):
            _fallback(cfg, key)
            continue
        try:
            iv = int(v)
        except (TypeError, ValueError, OverflowError):
            _fallback(cfg, key)
            continue
        if (lo is not None and iv < lo) or (hi is not None and iv > hi):
            _fallback(cfg, key)
            continue
        cfg[key] = iv
    for key, allowed in _ENUM_VALUES.items():
        if key not in cfg:
            continue
        v = cfg.get(key)
        if not isinstance(v, str) or v.lower() not in allowed:
            _fallback(cfg, key)
        else:
            cfg[key] = v.lower()
    for key in _BOOL_KEYS:
        if key not in cfg:
            continue
        if not isinstance(cfg.get(key), bool):
            _fallback(cfg, key)
    # P2-4(R3): edns_client_subnet 加载期校验。与 api._validate_cfg_update 对齐:
    # 非空时必须是合法 CIDR 网络, 前缀钳制到地址族合法范围(v4≤32 / v6≤128),
    # 非法时回退为 None 并告警。此前仅 API 写入路径有校验, 手编 config.json 写
    # 入非法 CIDR 启动时静默生效, 运行时 resolver 解析才报错。
    if "edns_client_subnet" in cfg:
        ecs = cfg.get("edns_client_subnet")
        if ecs is not None and str(ecs).strip() != "":
            try:
                # P3-2(R4): /33、/129 等越界前缀在 ip_network 构造时即抛 ValueError,
                # 此前"构造后再判 prefixlen 钳制"的分支不可达(死代码), 已删除。
                # 越界/非法 CIDR 统一走 except 回退 None(与 api 写入路径 400 拒绝语义对齐)。
                net = ipaddress.ip_network(str(ecs).strip(), strict=False)
            except ValueError:
                logging.warning("edns_client_subnet 非法/越界 CIDR, 已回退为 None: %r", ecs)
                cfg["edns_client_subnet"] = None
            else:
                cfg["edns_client_subnet"] = str(net)
        else:
            # P3-3(R4): 空值统一归一为 None(与默认值、api 写入路径对齐), 不再写空串 ""。
            cfg["edns_client_subnet"] = None
    # v1.9.84 P3: upstreams/rules 必须是列表, 防止用户配置把它们写成 dict/标量
    # 导致后续遍历/保存处类型错误(deep_merge 对 list→dict 不会报错)。
    for key in ("upstreams", "rules"):
        if key in cfg and not isinstance(cfg.get(key), list):
            _fallback(cfg, key)
    # P3-1(第八轮): cache_partitions 各分区权重加载期校验。API 写入路径
    # (_validate_cfg_update) 已 400 拒绝非数值权重; 手编 config.json 写入
    # {"domestic": "abc"} 之类畸形值时, 启动期这里回退整个 cache_partitions 为
    # 默认(None)并告警, 不让坏权重进入 resolver 加权计算。
    # R28 P3-1: 与 API 写入路径(R27 P3-5)对齐 —— 追加负权重 <0 判断。此前加载期/
    # 热重载同段只查类型不查符号, 手编 config.json + SIGHUP 可穿透, 负权重进入
    # resolver 加权分区容量分配导致异常。
    _cp = cfg.get("cache_partitions")
    if _cp is not None and not isinstance(_cp, dict):
        logging.warning("cache_partitions 不是对象也不是 null, 已回退默认: %r", _cp)
        cfg["cache_partitions"] = None
    elif isinstance(_cp, dict):
        for _ck, _cv in _cp.items():
            if isinstance(_cv, bool) or not isinstance(_cv, (int, float)) or _cv < 0:
                logging.warning("cache_partitions[%r] 权重非法(非数字/布尔/负数, got %r), 整个分区配置回退默认",
                                _ck, _cv)
                cfg["cache_partitions"] = None
                break
    # v7 P2-2: rule_subscriptions[] 逐项轻量校验(加载期/热重载)。此前只校验是 list,
    # 不对项内容校验——手改/损坏配置可落库 url=http://、非法 action、forceIp 缺 ip 的
    # 死订阅项。非法项跳过并告警, 不中断启动(config.py 不导入 api.py, 独立实现)。
    subs = cfg.get("rule_subscriptions", [])
    if not isinstance(subs, list):
        logging.warning("rule_subscriptions 不是列表, 已置空: %r", subs)
        cfg["rule_subscriptions"] = []
    else:
        kept = []
        for i, item in enumerate(subs):
            if _validate_rule_subscription_item(item):
                kept.append(item)
            else:
                logging.warning("rule_subscriptions[%d] 非法( url 非 https/action 非法/ip 非法), 已跳过: %r", i, item)
        cfg["rule_subscriptions"] = kept
    # P3-1(R40): listen 必须是 dict, 与 api/upstreams/rules 同型防御。手编 config.json 写
    # "listen": "foo" 时 deep_merge 会把默认 dict 覆盖为标量(非 dict 走 else 直接 deepcopy),
    # build_app 的 listen.get(k)(cli.py:288) 与 --dns-udp/--dns-tcp 覆盖路径(cli.py:649)
    # 均抛未捕获 AttributeError 致启动崩溃。这里回退默认并告警。
    if "listen" in cfg and not isinstance(cfg.get("listen"), dict):
        logging.warning("listen 不是对象, 已回退默认: %r", cfg.get("listen"))
        cfg["listen"] = copy.deepcopy(DEFAULTS["listen"])
    # P3-1(R41): listen 子表值(udp/tcp/udp6/tcp6)必须是字符串。手编 config.json 写
    # "listen": {"udp": 123} 时 deep_merge 会把默认字符串覆盖为 int, _validate_cfg 的
    # dict 防御通过, 启动时 server.py parse_bind(int) 抛 AttributeError(非 OSError,
    # start() 不捕获)致进程崩溃。这里逐键校验为 str, 非字符串回退默认并告警。
    if isinstance(cfg.get("listen"), dict):
        for _lk in ("udp", "tcp", "udp6", "tcp6"):
            _v = cfg["listen"].get(_lk)
            if _v is not None and not isinstance(_v, str):
                logging.warning("listen.%s 不是字符串, 已回退默认: %r", _lk, _v)
                cfg["listen"][_lk] = copy.deepcopy(DEFAULTS["listen"].get(_lk))
    # P2-24: api.token 校验。必须是字符串且不超过 256 字符; 非字符串类型
    # (数字/列表等)回退为空串(不启用认证), 防止把畸形值带入请求头比较路径。
    # P3-1(R39): api 必须是 dict, 与 upstreams/rules 同型防御。手编 config.json 写
    # "api": "foo" 时 deep_merge 会把默认 dict 覆盖为标量(非 dict 走 else 直接 deepcopy),
    # 下方 api 校验块因 not isinstance(api_cfg, dict) 整体跳过, 随后 cli.run 在
    # api_cfg.get("host") 抛未捕获 AttributeError 致启动崩溃。这里回退默认并告警。
    if "api" in cfg and not isinstance(cfg.get("api"), dict):
        logging.warning("api 不是对象, 已回退默认: %r", cfg.get("api"))
        cfg["api"] = copy.deepcopy(DEFAULTS["api"])
    api_cfg = cfg.get("api")
    if isinstance(api_cfg, dict):
        tok = api_cfg.get("token", "")
        if not isinstance(tok, str):
            logging.warning("api.token 不是字符串, 已置空(不启用认证): %r", tok)
            api_cfg["token"] = ""
        elif len(tok) > 256:
            logging.warning("api.token 超过 256 字符, 已截断")
            api_cfg["token"] = tok[:256]
        elif tok and not tok.isascii():
            # P2-1(R5): 非 ASCII token 此前会让 hmac.compare_digest(str,str) 抛
            # TypeError。比较路径已改为 UTF-8 bytes 比较(见 api._check_api_token),
            # 非 ASCII token 仍可工作; 但记录 warning 提示运维使用 ASCII, 避免
            # 跨语言/终端复制粘贴引入隐藏字符。不强制清空, 保持向后兼容。
            logging.warning("api.token 含非 ASCII 字符, 建议改为可打印 ASCII "
                            "(比较路径已按 UTF-8 bytes 兼容, 仍可认证): len=%d", len(tok))
        # P3-2(R41): api.host 必须是字符串。手编 config.json 写 "api": {"host": 123} 时
        # _validate_cfg 通过(api 是 dict, token/port 走默认), cli.run 把 int 传给
        # ThreadingHTTPServer → socket.bind((int, port)) 抛 TypeError(非 OSError,
        # cli.py 不捕获)致进程崩溃。与 api.token/api.port 同型: 非字符串回退默认并告警。
        _raw_host = api_cfg.get("host", "127.0.0.1")
        if not isinstance(_raw_host, str):
            logging.warning("api.host 不是字符串, 已回退默认 127.0.0.1: %r", _raw_host)
            api_cfg["host"] = "127.0.0.1"
        # P3-3(R5): 嵌套 api.port 加载期数值校验。此前 _validate_cfg 只碰顶层标量键,
        # 手编 config.json 写 "port":"abc" 或 null 时, cli.run 里 int(...) 直接
        # ValueError 崩溃, 无回退无友好提示。此处与 api.host 处理对齐: 非法回退 8080 并告警。
        raw_port = api_cfg.get("port", 8080)
        if isinstance(raw_port, bool):
            # bool 是 int 子类, int(True)==1 会穿透到合法端口; 显式拒绝。
            logging.warning("api.port 是布尔值, 已回退默认 8080: %r", raw_port)
            api_cfg["port"] = 8080
        else:
            try:
                iv_port = int(raw_port)
            except (TypeError, ValueError, OverflowError):
                iv_port = None
            if iv_port is None or not (1 <= iv_port <= 65535):
                logging.warning("api.port 非法(%r), 已回退默认 8080", raw_port)
                api_cfg["port"] = 8080
            else:
                api_cfg["port"] = iv_port


def load_config(path=None, persist=True):
    """加载配置。

    参数:
      path: 配置文件路径(None 则按 default_paths() 探测)。
      persist: 是否允许"启动期自动把 config 内 rules 落盘到 rules_local.json"这一
        写盘副作用。True(默认)仅由 run() 启动路径使用; 只读 CLI 子命令(status/
        config-print/config-path)与热重载(_reload_body)必须传 False, 避免:
        (P3-1) 只读命令意外写盘; (P3-4) 热重载时 rules_local.json 被外部删除后
        从陈旧 config.json 静默复活已被用户丢弃的旧规则。

    返回:
      - 正常: 合并后的配置 dict。
      - 文件不存在: 返回内置默认配置(启动场景合理)。
      - 文件存在但解析失败(JSONDecodeError/空文件/半截写): 返回 None。
        调用方(热重载)必须据此保留当前运行配置, 绝不能静默采用内置默认——
        否则一次瞬时读错(并发写盘/rename 窗口)就会把整套上游/监听/缓存
        全部替换成默认值(R9-R3 P1: 实测 reload 读到空文件后上游被换成默认
        DoH 集、listen 变 0.0.0.0:53、cache_size 翻倍)。
    """
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
            if not isinstance(data, dict):
                raise ValueError("顶层不是 JSON 对象")
            cfg = deep_merge(cfg, data)
        except Exception as e:
            # R9-R3 P1: 文件存在但读/解析失败 → 返回 None, 不再静默回退默认。
            # stderr 打 ERROR 醒目提示, logging.error 进 journald。
            sys.stderr.write("ERROR: 读取配置失败 %s: %s —— 热重载将保留当前运行配置, 不回退默认\n" % (chosen, e))
            logging.error("加载配置失败 %s: %r, 返回 None(调用方应保留旧配置)", chosen, e)
            return None
    # 加载后校验数值/枚举/布尔字段类型与范围, 非法值回退默认并告警
    _validate_cfg(cfg)
    # P2-1(R4): resolver/API 规则回退语义对齐。
    # 背景: resolver 按 rule_local_file 读 rules_local.json, 文件缺失时 FileNotFoundError→[],
    # 不回退 cfg["rules"]; 而 API._local_rules() 文件缺失时回退 cfg["rules"]。迁移失败 boot
    # 窗口内控制台显示规则、真实 DNS 分流却为空。resolver.py 不在本模块范围, 这里在 resolver
    # 构造(build_app)之前, 检测"rules_local.json 缺失但 config 内仍有旧 rules"时自动把内存
    # rules 落盘, 让 resolver 启动即按文件读到规则, 消除该不一致。
    # 仅在文件确实缺失(not isfile)且 cfg["rules"] 非空时触发, 不覆盖已存在(含损坏)的独立文件。
    # 写盘失败(磁盘满/只读)时 save_local_rules 内部已告警, 保持现状由 cli.run 迁移逻辑重试。
    # P3-1/P3-4(R5): 仅 persist=True(run 启动路径)才执行该写盘副作用。只读 CLI 与热重载
    # 传 persist=False 时跳过; 若恰好处在"rules_local.json 缺失但 config 仍有 rules"的窗口,
    # 热重载不应从陈旧 config.json 复活已被用户删除的旧规则, 仅记 warning 提示运维。
    if chosen and os.path.isfile(chosen):
        try:
            _lr_path = local_rules_path(chosen)
            _would_migrate = (not os.path.isfile(_lr_path)) and bool(cfg.get("rules"))
            if not persist:
                if _would_migrate:
                    logging.warning("rules_local.json 缺失但 config 仍含 %d 条规则; "
                                    "当前为只读/热重载路径(persist=False), 不自动落盘复活旧规则",
                                    len(cfg["rules"]))
            elif _would_migrate:
                if save_local_rules(cfg["rules"], chosen):
                    logging.info("启动时自动把 config 内 %d 条规则落盘到独立文件 %s "
                                 "(对齐 resolver 文件读取语义)", len(cfg["rules"]), _lr_path)
        except Exception as e:
            logging.warning("启动时自动落盘规则到独立文件失败: %r", e)
    # P2-24: api.token 现在是受支持的可选认证字段(默认空串=不启用), 不再 pop。
    if cfg.get("web_root") is None:
        cfg["web_root"] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "web")
    return cfg


def save_config(cfg, path=None):
    target = path
    if not target:
        # 优先 /etc/ebpdns/config.json；不可写则当前目录。
        # P3: 旧实现为探测可写, 会真的往候选路径写一个空 `{}` 文件作副作用 —— 选路径这个
        # 只读意图在磁盘上留了空 config, 中途崩溃会丢失用户配置。改用 os.access 判可写,
        # 不再为探测而落盘。
        candidates = ["/etc/ebpdns/config.json", os.path.join(os.getcwd(), "config.json")]
        chosen = None
        for c in candidates:
            parent = os.path.dirname(c) or "."
            try:
                if os.path.isfile(c):
                    if os.access(c, os.W_OK):
                        chosen = c
                        break
                else:
                    if not os.path.isdir(parent):
                        os.makedirs(parent, exist_ok=True)
                    if os.access(parent, os.W_OK):
                        chosen = c
                        break
            except Exception:
                continue
        target = chosen or os.path.join(os.getcwd(), "config.json")
    # 规则/上游数量大时用 compact 格式: indent=2 会让 10 万规则的 config 达 15MB+,
    # 每次全量保存都很慢。compact(分隔符无空格) 体积约减半, 序列化/写盘快约 2.5x。
    # R37 P3-2: 逐条规则已迁移到独立文件 rules_local.json(cli.py 启动时 cfg["rules"]=[]),
    # 此处不再检查 rules 数量; 仅 upstreams 仍常驻 config.json, 作为 compact 触发条件。
    big = len(cfg.get("upstreams", [])) > 100
    payload = (json.dumps(cfg, ensure_ascii=False, separators=(",", ":")) if big
               else json.dumps(cfg, ensure_ascii=False, indent=2))
    # R36 P3-2: tmp 提到 try 外, 便于 except 分支清理残留 .tmp
    tmp = target + ".tmp"
    try:
        # R38 P3-2: 父目录创建移入 try 内, makedirs 失败(OSError)走 except 兜底
        # 直写路径并 return False, 避免异常穿透到单资源端点的未保护调用方。
        os.makedirs(os.path.dirname(os.path.abspath(target)) or ".", exist_ok=True)
        # 原子写入：临时文件 + rename，避免崩溃留下半截 JSON
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(payload)
            f.flush()
            # P3-2(R5): 与 _save_cache/save_local_rules 对齐, rename 前 fsync 文件内容,
            # 防掉电丢已返回 200 的配置。save 非热路径, 不影响 QPS。
            os.fsync(f.fileno())
        os.replace(tmp, target)
        # R6 P4-1: rename 后对父目录 fsync, 确保目录项(新文件名)本身落盘。此前只
        # fsync 文件内容, rename 后到目录项回写前掉电最坏会"已返回 20 但该次写入丢失,
        # 旧文件仍在"(无损坏/无半截文件)。save 非热路径, 多一次 fsync 可忽略。
        try:
            _dd = os.open(os.path.dirname(os.path.abspath(target)) or ".", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(_dd)
            finally:
                os.close(_dd)
        except OSError:
            # 某些文件系统(如 tmpfs/网络盘)不支持目录 fsync, 静默降级为已知权衡。
            pass
    except OSError:
        # R36 P3-2: 原子写失败(如 os.replace 跨设备/只读/磁盘满)时清理残留 .tmp,
        # 避免 config 目录下永久堆积 config.json.tmp。open 失败时 tmp 可能不存在,
        # exists 判断 + 内层 try/except 保证清理自身不抛错。
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
        # tmp 写失败(受限文件系统/磁盘满/ProtectSystem 只读)时降级直接写目标文件,
        # 避免配置保存失败中断 API。P3-4(第八轮): 兜底直写也包一层 try/except OSError,
        # 失败时 log.warning 并返回 False, 避免异常穿透导致 500。
        try:
            with open(target, "w", encoding="utf-8") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
        except OSError as e:
            logging.warning("save_config: 兜底直写 %s 失败: %r", target, e)
            return False
    return target
