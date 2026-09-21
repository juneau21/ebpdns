"""HTTP JSON API + 静态控制台服务（内置 http.server，零依赖）。"""

import hmac
import itertools
import json
import os
import re
import ssl
import ipaddress
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import http.client
import socket as _socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__, config as config_mod
import logging
from .probe import probe_upstream_latencies

log = logging.getLogger("ebpdns.api")
from . import upstream, quic_upstream, dnsmsg
from .telemetry import _now_ts

# 上游/规则 id 生成器: 毫秒时间戳 + 进程内自增后缀, 消除同一毫秒 POST 两个
# 上游/规则拿到相同 id 的碰撞窗口(按 id next(...) 定位只会命中第一个)。
_id_seq = itertools.count(1)
_id_seq_lock = threading.Lock()
# v1.9.74 P2-8: profile 全局单飞锁(cProfile 进程级单例, 同时只允许一个采样)
_PROFILE_LOCK = threading.Lock()

# P2-14: 并发订阅下载信号量。订阅下载是同步网络 I/O(最长 20s), 在 HTTP worker
# 线程内执行会占满 ThreadingHTTPServer 的 256 线程槽位。限制最多 4 个并发下载,
# 超额在信号量上排队(不消耗线程槽以外的额外资源), 防止突发批量订阅把 API 卡死。
_SUBSCRIBE_SEM = threading.BoundedSemaphore(4)

# P3-12: /api/restart 防重入标志。重启是延迟触发(1s 后后台线程 exec/systemctl),
# 两次连点会派生两个重启线程, 后者可能在前者已 exec 后再执行一次导致异常。
# 首个请求 set() 后, 后续请求直接 409。
_RESTART_STARTED = threading.Event()

# P1-1: _read_json 的"已自行回包"哨兵。_read_json 在 413/读 body 失败时自身已
# 发送响应(或连接已不可用), 必须用一个不可与 None/{} 混淆的对象返回, 让调用方
# 区分"已回包, 禁止再发响应/再改状态"与"body 为空/非法 JSON"。否则调用方 `or {}`
# 会把哨兵当空 body, 超大请求反而新建默认上游/规则并落库, _api_update_config 还会
# 在 413 之后再发一次 400 造成双重回包污染 keep-alive 管道。
_SENTINEL = object()

# 规则合法 action 枚举(与 resolver._rule_label/match_rule 分流逻辑一致)。
# PUT /api/rules/<id> 已做枚举校验; POST /api/rules(新增)此前漏校, 任意字符串
# action(如 "frobnicate")会被静默落库成一条永不命中的死规则。提取为共享常量,
# 新增/编辑两条入口统一校验, 避免两处字面量日后漂移。
_RULE_ACTIONS = ("allow", "block", "group", "forceIp")

# 上游合法协议枚举(与 PUT /api/upstreams/<id> 及 config.parse_upstream_addr 一致)。
# POST /api/upstreams(新建)此前漏校: parse_upstream_addr 的 proto_sel 与手动分支都
# 不做枚举校验, 任意字符串(如 "bogus")被静默落库成永不工作的死上游。提取为共享常量,
# 新建/编辑两条入口统一校验, 避免两处字面量日后漂移。
_ALLOWED_UPSTREAM_PROTO = ("udp", "tcp", "doh", "dot", "doq", "doh3")

# P3-5(第八轮): 静态资源 MIME 映射提升为模块级常量。此前该 dict 定义在 _serve_static
# 函数体内, 每次请求(控制台首页/JS/CSS 热路径)都重新构造一次字面量 dict——虽小但属
# 无谓的热路径分配, 且模块级常量也便于阅读。下表覆盖控制台前端实际用到的类型。
_STATIC_MIME = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
}


def _validate_upstream_dict(u):
    """校验单个上游 dict 的 proto 枚举与 port 范围。

    POST /api/upstreams、PUT /api/upstreams/<id> 此前已硬化; 第六轮审查发现
    PUT /api/config 整体覆盖 upstreams[] 时绕过了同样校验(GET 回传整组数组,
    手构造 body 可落库 proto=bogus/port=99999 的死上游)。抽出此公共校验, 三个
    入口复用。返回 None=通过, 否则错误串。
    P3-1(R4-S7/F2): 补充 weight/latency/name 范围与长度校验, 与单条 PUT 对齐,
    彻底消除单条/bulk 路径漂移。"""
    if not isinstance(u, dict):
        return "上游项必须是对象: %r" % (u,)
    proto = str(u.get("proto") or "").lower()
    if proto not in _ALLOWED_UPSTREAM_PROTO:
        return "非法 proto: %r (允许: %s)" % (u.get("proto"), "/".join(_ALLOWED_UPSTREAM_PROTO))
    # R6 P3-2: 与 weight/latency 同型, 显式排除 bool(bool 是 int 子类,
    # int(True)==1 会穿透范围校验落库为 port=1)。
    _raw_port = u.get("port")
    if isinstance(_raw_port, bool):
        return "port 不允许是布尔值: %r" % (_raw_port,)
    try:
        port = int(_raw_port)
    except (TypeError, ValueError):
        return "port 必须是整数: %r" % (u.get("port"),)
    if not (1 <= port <= 65535):
        return "port 必须在 1-65535 之间 (got %r)" % (u.get("port"),)
    # P3-1: weight 范围 0-1000, 必须是数值且排除 bool(True/False 是 int 子类)
    w = u.get("weight")
    if w is not None:
        if not isinstance(w, (int, float)) or isinstance(w, bool):
            return "weight 必须是数字: %r" % (w,)
        if not (0 <= w <= 1000):
            return "weight 必须在 0-1000 之间 (got %r)" % (w,)
    # P3-1: latency 范围 0-3600000ms
    lat = u.get("latency")
    if lat is not None:
        if not isinstance(lat, (int, float)) or isinstance(lat, bool):
            return "latency 必须是数字: %r" % (lat,)
        if not (0 <= lat <= 3600000):
            return "latency 必须在 0-3600000 之间 (got %r)" % (lat,)
    # R18 P3-1: name 类型校验——提供时必须为 str, 与 POST/PUT 单条/addr/group 对齐。
    # 此前只校验长度(isinstance 门控跳过非 str), 传 {"name": 123} 或 {"name": true}
    # 会落成非字符串类型, 后续字符串操作/索引异常。
    name = u.get("name")
    if name is not None and not isinstance(name, str):
        return "name 必须是字符串: %r" % (name,)
    if isinstance(name, str) and len(name) > 256:
        return "name 过长 (上限 256 字符)"
    # R18 P3-2: group 类型校验——提供时必须为 str, 与 POST 新建/PUT 单条对齐。
    # 此前 bulk 路径遗漏 group 类型校验, 传 {"group": 123} 穿透 `or "domestic"`
    # 落库为非 str, 后续分组逻辑(str 比较/索引)异常。
    grp = u.get("group")
    if grp is not None and not isinstance(grp, str):
        return "group 必须是字符串: %r" % (grp,)
    # R9-R2: addr 字符集校验, 与 POST /api/upstreams 手动分支对齐。
    # 此前 bulk PUT /api/config 内嵌 upstreams[] 绕过 _valid_host, 可写入含
    # 空格/分号/换行的 addr(日志注入面)。非字符串/空值保持宽松(自动解析分支
    # 可能临时缺 addr, 后续 POST 路径兜底), 字符串值必须过白名单。
    addr = u.get("addr")
    if addr is not None and addr != "":
        if not isinstance(addr, str):
            return "addr 必须是字符串: %r" % (addr,)
        if not _valid_host(addr.strip()):
            return "非法 addr: %r (仅允许 IPv4/IPv6/主机名字符集)" % (addr,)
    # R9-R4 P2: url 控制字符校验, 与 PUT 单条编辑/POST 新建分支对齐。
    url = u.get("url")
    if not _valid_url_path(url):
        return "非法 url: %r (不允许包含控制字符)" % (url,)
    # R19 P3-3: 布尔字段归一化——bulk 路径此前只校验不归一, 字符串 "false"/"0"
    # 被原样落库(字符串 "false" 是真值), 与单条 PUT 路径 _as_bool 归一不一致。
    # 在全部校验通过后就地归一(函数入参 u 是引用, 修改后调用方 deep_merge 生效)。
    for _bk, _bd in (("allow_private_ip", False),
                     ("doh_strict_cert", False),
                     ("dot_strict_cert", False)):
        if _bk in u:
            u[_bk] = _as_bool(u[_bk], _bd)
    return None


# P3-5(第八轮): 手动添加上游分支未校验 addr 字符集。抽取公共校验: 允许
# IPv4/IPv6/主机名字符集 [a-zA-Z0-9._:-], 长度 1-253。含空格/分号/引号等
# 危险字符的 addr 会被拒绝, 防止命令注入/日志注入。
# P3-4(R4-F4): 字符集白名单放宽到含 IPv6 字符 ':' 和 '[]' (RFC 5952 字面量形式
# 如 [::1]), 与 parse_upstream_addr 对 IPv6 的支持对齐。真正的 IPv6 语义解析由
# 后续 socket 连接处理, 这里只做字符集白名单。
_HOST_RE = re.compile(r"^[a-zA-Z0-9._:\[\]-]{1,253}$")


def _valid_host(host):
    """校验上游 addr 字段字符集: 允许 IPv4/IPv6/主机名字符集, 长度 1-253。"""
    if not host or not isinstance(host, str):
        return False
    return bool(_HOST_RE.match(host))


# R9-R4 P2: DoH/DoH3/DoQ 的 url(路径) 控制字符白名单。PUT 单条编辑路径
# (_api_upstream_op) 早已拒绝 ord<32 的控制字符; 但 POST 新建(自动解析 host:port/scheme
# 分支与手动分支)与 PUT /api/config bulk 内嵌 upstreams[] 三条写入路径此前未做该校验,
# 手构造 body 可把换行(\n)等控制字符写进 url——日志注入面(日志按 url 原文打印时换行
# 会伪造下一条日志)且会产生畸形 HTTP 请求目标。抽出公共判定, 四条路径统一收口。
def _valid_url_path(url):
    """DoH url 路径合法性: 必须是字符串且不含控制字符(含 \\r\\n 与 0x7f DEL)。
    空字符串允许(udp/tcp 协议 url 恒为空)。"""
    if url is None:
        return True
    if not isinstance(url, str):
        return False
    return all(ord(c) >= 0x20 and ord(c) != 0x7f for c in url)


def _addr_has_explicit_port(raw):
    """判断上游 addr 字符串是否内嵌了 host:port(此时端口以 parse_upstream_addr
    解析为准, body 显式 port 不应覆盖)。镜像 config.parse_upstream_addr 的端口切分
    逻辑: 去 scheme/path 后, 裸 IPv6(多冒号且未方括号)不切端口, 末尾 :digits 才算。
    P3-2(第七轮): 自动解析分支据此决定是否用 body 显式 port 覆盖解析默认端口。"""
    s = str(raw or "").strip()
    if not s:
        return False
    if "://" in s:
        s = s.split("://", 1)[1]
    slash = s.find("/")
    if slash >= 0:
        s = s[:slash]
    if not s:
        return False
    if s.count(":") > 1 and not s.startswith("["):
        return False
    colon = s.rfind(":")
    return colon > 0 and s[colon + 1:].isdigit()



def _validate_rule_dict(r, require_match=False):
    """校验单条规则/订阅项的 action 枚举。

    规则 import/subscribe 与单条规则增改已校验 action; 第六轮审查发现
    PUT /api/config 内嵌 rules[]/rule_subscriptions[] 整体保存时绕过。抽出此
    公共校验统一复用。返回 None=通过, 否则错误串。
    P2-6(R4-F1/S8): 补充 match 字段 4096 字节上限校验, 与单条 POST/PUT 路径对齐,
    彻底消除单条/bulk 路径漂移(此前 PUT /api/config 内嵌 rules[] 可绕过长度限制)。
    R17 P3-3: match 必填+非null+str类型校验; R18 P3-4: match 4096 字节上限
    不受 require_match 门控(只要 match 键存在且为 str 即校验长度)。
    R17 P3-4: url 字段若非 null 必须为非空字符串, 与单条 PUT/bulk 路径对齐。
    此前 {"url": null} 可落库为 JSON null, 后续订阅拉取出错。"""
    if not isinstance(r, dict):
        return "规则项必须是对象: %r" % (r,)
    if r.get("action") not in _RULE_ACTIONS:
        return "非法 action: %r (允许: %s)" % (r.get("action"), "/".join(_RULE_ACTIONS))
    # F2: forceIp 规则必须带合法 IPv4/IPv6, 否则规则永不命中成死规则。
    # 前端已有 isValidIp, 直接 API 调用可绕过; 后端在此统一兜底, 所有写入路径复用。
    if r.get("action") == "forceIp":
        # R8-F1: ip 必须是字符串。非字符串真值(如 JSON 数组/对象)直接调 .strip()
        # 会抛 AttributeError → 500。先做类型兜底。
        ip = r.get("ip")
        if ip is not None and not isinstance(ip, str):
            return "ip must be a string"
        ip = (ip or "").strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return "forceIp 规则的 ip 必须是合法 IPv4/IPv6 地址 (got %r)" % (r.get("ip"),)
    # R17 P3-4: url 字段非null+非空str校验(若提供了 url 字段)。
    # 规则订阅项 url:null 会落库为 JSON null, 后续拉取时 urlparse(None) 出错。
    if "url" in r:
        url = r["url"]
        if url is None or not isinstance(url, str) or not url.strip():
            return "url 必须是非空字符串"
    # R18 P3-3: 规则 group 字段类型校验——提供时必须为 str, 与上游 group 校验对齐。
    # 此前规则 group 在所有编辑路径(POST 新建/PUT 单条/bulk)均无类型校验,
    # 传 {"group": 123} 穿透 `or "domestic"` 落库为非 str, 后续分组逻辑异常。
    # 本函数被 POST /api/rules、PUT /api/rules/<id>、bulk rules[]/rule_subscriptions[]
    # 四条路径复用, 一处添加全覆盖。
    if "group" in r:
        grp = r["group"]
        if grp is not None and not isinstance(grp, str):
            return "group 必须是字符串: %r" % (grp,)
    # R17 P3-3 / R18 P3-4: match 字段校验。
    # - match 键存在时: 必须非null、为 str、非空、≤4096 字节(4096 长度校验不受
    #   require_match 门控——只要 match 键存在且为 str 即校验, 导入/订阅路径中有
    #   match 键的规则也会被校验长度)。
    # - require_match=True(bulk rules[]): match 键缺失也拒绝。
    # - require_match=False(订阅项/局部 action+ip 预检): match 键缺失放行。
    if "match" in r:
        match = r["match"]
        if match is None:
            return "match 不能为空"
        if not isinstance(match, str):
            return "match 必须是字符串"
        if not match.strip():
            return "match 不能为空"
        # P2-6: match 字段 4096 字节上限, 防止超大正则/字符串落库膨胀规则索引
        if len(match.encode("utf-8")) > 4096:
            return "match 过长 (上限 4096 字节)"
    elif require_match:
        return "match 不能为空"
    return None


def _check_rule_regex(match):
    """R28 P2-1: 校验 match 以 re: 开头时的正则合法性, 返回 None=通过, 否则错误串。
    单条 POST /api/rules、单条 PUT /api/rules/<id>、bulk PUT /api/config 内嵌 rules[]
    三条写入路径共用此函数, 避免三处字面量漂移。非法正则编译失败时直接 400,
    避免落库一条永不命中且报错难以定位的死规则(与 P3-5/R4-F5 初衷一致)。"""
    if isinstance(match, str) and match.startswith("re:"):
        body = match[3:]
        # R30 P3-2: 拒绝裸 re:(空正则体)。re.compile("") 合法但 re.search("", 任意域名)
        # 恒命中零宽位置, 语义上等于"匹配全部域名"。订阅源 dnsmasq 格式 address=/re:/x.com/
        # 会被 _parse_domain_list 切成 ["re:", "x.com"], 裸 re: 若 action=block 将屏蔽全域。
        if not body.strip():
            return "invalid regex: empty body after 're:'"
        try:
            re.compile(body)
        except re.error as e:
            return "invalid regex: %s" % e
    return None


def _normalize_rule_ttl(r):
    """R27 P2-1: bulk PUT /api/config 内嵌 rules[] 的 ttl_min/ttl_max 校验与就地归一,
    与单条 POST /api/rules(_api_add_rule)、PUT /api/rules/<id>(_api_rule_op)完全同型:
    bool 排除 + int 归一 + max(0,...) 非负钳制 + ttl_min<=ttl_max 顺序检查。
    此前 bulk 路径只调 _validate_rule_dict(不触碰 TTL 字段), 可落库
    ttl_min:"abc"/-5/true 等非法值, resolver 命中规则时做 TTL 算术/比较抛 TypeError。
    就地把合法值改写为 int, 空串/None 视为未设置(弹出键, 与 POST 路径"不加入 r"一致);
    返回 None=通过, 否则错误串。"""
    for k in ("ttl_min", "ttl_max"):
        if k not in r:
            continue
        v = r[k]
        if v is None or v == "":
            r.pop(k, None)
            continue
        # bool 是 int 子类, int(True)==1 会穿透到合法值, 显式拒绝。
        if isinstance(v, bool):
            return "%s 必须是非负整数，不能是布尔值" % k
        try:
            r[k] = max(0, int(v))
        except (TypeError, ValueError):
            return "%s 必须是非负整数" % k
    # 两者都提供(且未被上面的 None/空跳过)时检查顺序, 与单条路径一致。
    _tmin = r.get("ttl_min")
    _tmax = r.get("ttl_max")
    if _tmin is not None and _tmax is not None and _tmin > _tmax:
        return "ttl_min 不能大于 ttl_max"
    return None


def _new_id(prefix):
    with _id_seq_lock:
        seq = next(_id_seq)
    return "%s%d%04x" % (prefix, int(time.time() * 1000), seq & 0xFFFF)


def _default_upstream_name(upstreams):
    """R30 P3-5: 生成不与现有上游重名的默认名 "上游 %d"。
    此前按 len(upstreams)+1 计算, 删除若干上游后再新增会因 len 回退导致新名与现存名重复
    (纯展示层重名, 不影响 id 路由)。从 len+1 起递增探测, 跳过已占用名, 保证新名唯一。"""
    used = {u.get("name") for u in upstreams if isinstance(u, dict)}
    n = len(upstreams) + 1
    while True:
        cand = "上游 %d" % n
        if cand not in used:
            return cand
        n += 1


# 域名列表导入里 "re:" 高级规则前缀判定, 模块级编译一次避免每次导入重编译。
_PREFIX_RE = re.compile(r"^re:")


def _pl_escape(s):
    """#2 [严重]: Prometheus 标签值转义。标签值(规则名/上游 id)若含反斜杠、引号、
    换行/回车, 未转义会破坏 exposition 文本格式(metric 行被截断/引号不闭合),
    导致 Prometheus 抓取失败或指标解析错乱。按 Prometheus 文本格式规范转义。"""
    return str(s).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")


def _conn_key(u):
    """telemetry.conn_stats 的键: proto|addr|port|url。
    与 telemetry 写入侧(upstream_ok_conn_ok/conn_ok)及 _upstreams_with_health 展示
    侧格式严格一致, 删除/变更上游时用它精确 pop 旧连接维度统计(防泄漏)。"""
    u = u or {}
    return "%s|%s|%s|%s" % (str(u.get("proto", "")).lower(),
                             u.get("addr", ""), u.get("port", ""), u.get("url", ""))


def _as_bool(v, default=True):
    """宽松布尔解析。JSON/表单里字符串 "false"/"0"/"off"/"no" 必须判为 False,
    不能用裸 bool("false") (恒 True)。None 走 default 缺省。"""
    if isinstance(v, bool):
        return v
    if v is None:
        return default
    if isinstance(v, (int, float)):
        return v != 0
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on")
    return bool(v)


def _sub_url_blocked(url):
    """SSRF 防护: 解析订阅 URL 的主机名, 拒绝指向私有/环回/链路本地地址。
    解析出的任何一个 IP 命中即拒绝(防止 DNS rebinding 到内网)。
    返回 (block_reason_or_None, [validated_public_ips]):
      block_reason 非 None 表示拒绝; 否则第二个元素为该 hostname 解析出的全部公网 IP,
      供连接层钉死(TCP 直连该 IP, Host/SNI 仍用原 hostname), 消除检查→连接间的
      DNS rebinding TOCTOU 窗口。"""
    # R30 P3-3: 删除函数内冗余 `import ipaddress`(模块顶部 line 9 已导入)。
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return "订阅 URL 解析失败", []
    host = parsed.hostname or ""
    if not host:
        return "订阅 URL 缺少主机名", []
    # 主机名本身就是 IP: 直接判定
    try:
        ips = [ipaddress.ip_address(host)]
    except ValueError:
        ips = []
        try:
            for fam, _t, _p, _c, sa in _socket.getaddrinfo(host, parsed.port or 80):
                try:
                    ips.append(ipaddress.ip_address(sa[0]))
                except ValueError:
                    pass
        except OSError:
            return "订阅主机名解析失败", []
    if not ips:
        return "订阅主机名无可用 IP", []
    for ip in ips:
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            return "订阅地址指向内网/保留地址, 已拒绝(SSRF 防护)", []
    return None, [str(ip) for ip in ips]


class _PinnedHTTPConn(http.client.HTTPConnection):
    """TCP 直连"已通过 SSRF 校验的公网 IP", 而非让 urllib 二次解析 hostname。

    钉死 IP 后, 检查时刻(公网)与连接时刻(同一公网 IP)不再有 DNS rebinding 窗口;
    Host 头仍由 urllib 按原 hostname 发送, 虚拟主机/反向代理路由不受影响。
    pinned_ip 由 per-request 子类属性注入(见 _PinnedHTTPHandler), 线程安全。"""
    pinned_ip = None

    def connect(self):
        self.sock = _socket.create_connection(
            (self.pinned_ip or self.host, self.port), timeout=self.timeout)


class _PinnedHTTPSConn(http.client.HTTPSConnection):
    """HTTPS 版本: TCP 钉到已验公网 IP, TLS 握手 server_hostname=原 hostname
    (SNI + 证书按 hostname 校验, 与 DoH 手工 TLS 路径一致)。"""
    pinned_ip = None

    def connect(self):
        raw = _socket.create_connection(
            (self.pinned_ip or self.host, self.port), timeout=self.timeout)
        try:
            ctx = ssl.create_default_context()
            self.sock = ctx.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            # P3-1(第七轮): wrap_socket 抛异常(TLS 握手失败/证书错误)时, 裸 raw socket
            # 未被 close, 泄漏 fd。确保异常路径关闭底层 socket 后再向上抛。
            try:
                raw.close()
            except Exception:
                pass
            raise


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    """用钉死 IP 的连接类发起 http 请求。"""

    def http_open(self, req):
        pinned = getattr(req, "pinned_ip", None)

        class C(_PinnedHTTPConn):
            pinned_ip = pinned

        return self.do_open(C, req)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    """用钉死 IP 的连接类发起 https 请求(SNI=原 hostname)。"""

    def https_open(self, req):
        pinned = getattr(req, "pinned_ip", None)

        class C(_PinnedHTTPSConn):
            pinned_ip = pinned

        return self.do_open(C, req)


class _SSRFRedirectHandler(urllib.request.HTTPRedirectHandler):
    """每跳重定向都重新过 SSRF 检查: 初始 URL 在外网但 302 跳到内网
    (http://169.254.169.254/ 云元数据等) 时, 必须在 redirect_request 拦截。
    复检通过后把该跳新 hostname 已验公网 IP 钉到新请求, 复用初始请求的防
    rebinding 逻辑。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # R22 P3-3: 订阅重定向此前每跳只复检目标 IP(SSRF), 不校验 scheme。初始 URL 已在
        # fetch_subscription_text 强制 https, 但 302 跳到明文 http:// 仍会被跟随, 订阅规则
        # 体改走明文, 中间人可篡改注入。与初始"仅 https://"策略一致, 拒绝非 https 重定向
        # 目标并记 warning。不破坏现有功能: 合法订阅均为 https→https 跳转, 不受影响。
        new_scheme = (urllib.parse.urlparse(newurl).scheme or "").lower()
        if new_scheme != "https":
            log.warning("订阅重定向拒绝非 https 目标 (scheme=%s): %s",
                        new_scheme or "(empty)", newurl)
            raise urllib.error.HTTPError(
                req.full_url, code,
                "redirect blocked: non-https scheme (%s)" % (new_scheme or "(empty)"),
                headers, fp)
        blocked, ips = _sub_url_blocked(newurl)
        if blocked:
            raise urllib.error.HTTPError(
                req.full_url, code, "redirect blocked: %s" % blocked, headers, fp)
        new_req = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_req is not None:
            new_req.pinned_ip = ips[0] if ips else None
        return new_req


# 模块级复用: 带 SSRF 重定向校验 + IP 钉死的 opener(替代默认 urlopen)。
# 显式禁用代理(ProxyHandler({})): 走代理会由代理重新解析 DNS, 既破坏 IP 钉死,
# 也可能被恶意配置的代理绕过 SSRF 检查; 订阅拉取必须直连已验公网 IP。
# 残余风险说明: 多 IP 轮询域名只钉第一个已验公网 IP; 若该 IP 当时可达即可,
# 后续不再二次解析。已检查-连接间的 rebinding 窗口被消除; 不引入新的连接失败
# (pinned_ip 为空时回退原 hostname 直连, 行为与改造前一致)。
_SSRF_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    _SSRFRedirectHandler, _PinnedHTTPHandler, _PinnedHTTPSHandler)

# 订阅响应大小上限: 16MB, 防止恶意/损坏订阅把整份内容读入内存(OOM)
SUB_TEXT_MAX_BYTES = 16 * 1024 * 1024


def fetch_subscription_text(url, timeout=20):
    """拉取订阅文本(共享实现, 所有调用路径统一收口):
    1. 强制 https:// 协议(v7 P1-2): 明文 http 可被中间人篡改规则注入。此前仅
       POST subscribe/import 两条初始添加路径校验, PUT /api/config 的
       rule_subscriptions[]、subscribe/update、后台周期更新、冷启动补下载均绕过;
       此处一处收口覆盖全部路径。
    2. 初始 URL 过 SSRF 检查(拒绝内网/环回/链路本地)并取得已验公网 IP;
    3. 用带每跳重定向复检 + IP 钉死的 opener 打开, 防 302 跳内网 & DNS rebinding;
    4. 流式 read(65536) 累积, 超过 SUB_TEXT_MAX_BYTES(16MB) 立即中止。
    返回解码后的 str; 被阻止或超限时抛 ValueError。"""
    if not url.lower().startswith("https://"):
        raise ValueError("订阅 URL 仅支持 https:// (http:// 不安全, 已禁止)")
    blocked, ips = _sub_url_blocked(url)
    if blocked:
        raise ValueError(blocked)
    req = urllib.request.Request(url, headers={"User-Agent": "ebpdns/subscribe"})
    req.pinned_ip = ips[0] if ips else None
    with _SSRF_OPENER.open(req, timeout=timeout) as r:
        chunks = []
        total = 0
        while True:
            chunk = r.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > SUB_TEXT_MAX_BYTES:
                raise ValueError("订阅响应超过 16MB 上限, 已中止")
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", "replace")

# PUT /api/config 允许写入的顶层配置键白名单: 从 DEFAULTS 提取, 排除
# listen(监听地址)/api(API 绑定)/web_root(静态根) 这些需重启才能生效的字段。
# 防止前端 JSON 回传时注入任意键(如覆盖 listen 指向别的地址)。
_CFG_WRITABLE_KEYS = (
    set(config_mod.DEFAULTS.keys()) - {"listen", "api", "web_root"}
)

# P3-1: 运行时派生键(cache_file/rule_sub_file/rule_local_file)由 cli.py 启动时注入,
# 不在 _CFG_WRITABLE_KEYS 白名单内。前端保存配置时会把它们一起回传, 若仍计入
# ignored_keys 会每次保存都提示用户"未保存", 纯 UX 噪音。过滤 ignored_keys 时跳过。
_RUNTIME_KEYS = {"cache_file", "rule_sub_file", "rule_local_file"}

# P3-5(第七轮): 需重启生效的服务器绑定键(listen/api/web_root)被 _CFG_WRITABLE_KEYS
# 白名单主动排除(防注入), 但前端每次保存都会把它们一起回传, 此前每次都落入 dropped
# 弹琥珀色"忽略未保存的键: listen, api, web_root"提示, 纯 UX 噪音。它们不是用户
# 误填的键, 而是设计上不可热写的键, 从 dropped 中排除。
_SERVER_KEYS = {"listen", "api", "web_root"}


class AppContext:
    """应用上下文：解析引擎 / 遥测 / 缓存 / 配置 / DNS 服务器引用。"""

    def __init__(self, resolver, telemetry, cfg, config_path=None, dns_server=None, resolver_holder=None):
        self.resolver = resolver
        self.telemetry = telemetry
        self.cfg = cfg
        self.config_path = config_path
        self.dns_server = dns_server
        self.resolver_holder = resolver_holder  # 若解析器可热重建，放这里
        self._lock = threading.Lock()

    def reload(self):
        """热重载入口(H-2): 全程持 self._lock, 与 _api_update_config 串行化,
        避免 reload 与写配置竞争——原 reload 不持锁, 可在 HTTP 线程读 old_cfg
        与进锁之间替换 self.cfg, 导致 deep_merge 基于陈旧 base 而丢配置变更。
        SIGHUP 经此入口调用时会短暂阻塞等待持锁方, 读文件+换引用耗时可忽略。"""
        with self._lock:
            return self._reload_body()

    def _reload_body(self):
        """热重载: 重新读取 config.json 并增量应用(无需重启进程)。

        1) 重新 load_config(保留运行时注入键 cache_file/rule_sub_file/rule_local_file)
        2) resolver.reload: 替换 cfg 引用 + 缓存容量/策略 + 规则索引
        3) 回收已删除上游的 DoH/DoT 连接池条目
        4) 替换 app.cfg(API 后续请求读新配置)
        返回变更摘要列表。"""
        try:
            # P3-1/P3-4(R5): 热重载传 persist=False, 不触发"rules_local.json 缺失即从
            # config.json 复活旧规则"的写盘副作用。用户手动删除 rules_local.json 后触发
            # reload 视为主动清空, 不再静默恢复陈旧 config 内的历史 rules。
            new_cfg = config_mod.load_config(self.config_path, persist=False)
        except Exception as e:
            log.error("热重载配置加载失败: %r", e)
            return {"ok": False, "error": "配置加载失败: %s" % e}
        # R9-R3 P1: load_config 在文件存在但解析失败时返回 None(读到空/半截文件)。
        # 此时必须保留当前运行配置, 绝不能采用内置默认(会整套替换上游/监听/缓存)。
        if new_cfg is None:
            log.error("热重载: 配置文件读取/解析失败, 保留当前运行配置不变")
            return {"ok": False, "error": "配置文件读取失败, 已保留当前运行配置(未应用变更)"}
        old_cfg = self.cfg
        # 运行时派生键沿用当前进程的值(不随文件重读丢失)
        for k in ("cache_file", "rule_sub_file", "rule_local_file"):
            if k in old_cfg:
                new_cfg[k] = old_cfg[k]
        # 回收新配置中已删除/变更上游的连接池/遥测/熔断条目(防内存泄漏)。
        # v1.9.86 P2-1: 与 _api_update_config 的 stale_victims 逻辑对齐——
        #   (a) 既回收"整条删除"(id 不在新集合), 也回收"端点变更"(同 id 但
        #       proto/addr/port/url 任一变化, 旧端点连接池/QUIC/conn_stats 失效);
        #   (b) 整条删除才清 per_upstream/_cb(上游仍在时保留累积统计);
        #   (c) 端点变更只清旧端点的连接池/QUIC/conn_stats。
        # 此前 reload 只调 discard_upstream_conns + quic_upstream.discard_upstream,
        # 二者不触碰 telemetry.per_upstream/conn_stats 与 resolver._cb, 且漏端点变更,
        # 导致文件/SIGHUP 反复增删改上游后这些条目缓慢残留。
        try:
            new_ups = new_cfg.get("upstreams", [])
            new_ids = {u.get("id") for u in new_ups}
            new_by_id = {u.get("id"): u for u in new_ups}
            for o in old_cfg.get("upstreams", []):
                uid = o.get("id")
                nu = new_by_id.get(uid)
                if nu is None:
                    # (a) 整条删除: 上游级统计 + 熔断 + 连接维度 + 连接池 + QUIC 全清
                    try:
                        self.telemetry.drop_upstream(uid)
                    except Exception:
                        pass
                    try:
                        # R3-C1: 与写侧 _cb_fail/_cb_ok/_cb_is_open 一致, 持 _cb_lock
                        # 清理熔断条目, 避免与在途查询写侧竞态残留已删上游条目。
                        with self.resolver._cb_lock:
                            self.resolver._cb.pop(uid, None)
                    except Exception:
                        pass
                    try:
                        self.telemetry.drop_conn(_conn_key(o))
                    except Exception:
                        pass
                    try:
                        upstream.discard_upstream_conns(o)
                    except Exception:
                        pass
                    try:
                        quic_upstream.discard_upstream(o)
                    except Exception:
                        pass
                elif (str(o.get("proto", "")).lower() != str(nu.get("proto", "")).lower()
                        or o.get("addr") != nu.get("addr")
                        or o.get("port") != nu.get("port")
                        or (o.get("url") or "") != (nu.get("url") or "")):
                    # (b) 端点变更(同 id): 只回收旧端点的连接池/QUIC/conn_stats,
                    #     保留 per_upstream/_cb(上游仍在累积健康/熔断统计)。
                    try:
                        self.telemetry.drop_conn(_conn_key(o))
                    except Exception:
                        pass
                    try:
                        upstream.discard_upstream_conns(o)
                    except Exception:
                        pass
                    try:
                        quic_upstream.discard_upstream(o)
                    except Exception:
                        pass
        except Exception:
            pass
        try:
            changed = self.resolver.reload(new_cfg, self.config_path)
        except Exception as e:
            log.error("热重载 resolver 应用失败: %r", e)
            return {"ok": False, "error": "热重载失败: %s" % e}
        # 监听地址变更无法热生效(需要重建 socket), 提示走 /api/restart。
        # R6 P3-3: 此前只比对 listen, 漏了 api.host/api.port —— API socket 同样在
        # 启动时 bind, reload 不重绑, 手编 config.json 改 api.port 后 reload 会让
        # GET /api/config 返回新 port 但实际仍监听旧 port, 运维易困惑。
        # R6-P3-2(第七轮 重评估): 拆分 api 子表比对——host/port 在启动时 bind,
        # reload 不重绑, 变化需重启; 而 api.token 在每次请求时从 self.app.cfg 读取
        # (_check_api_token), reload 换 cfg 引用后即时生效, 不应再提示"需重启"。
        old_api = old_cfg.get("api") or {}
        new_api = new_cfg.get("api") or {}
        api_bind_changed = (old_api.get("host") != new_api.get("host")
                            or old_api.get("port") != new_api.get("port"))
        api_token_changed = old_api.get("token") != new_api.get("token")
        if (old_cfg.get("listen") != new_cfg.get("listen")
                or api_bind_changed or api_token_changed):
            changed = list(changed or [])
            if old_cfg.get("listen") != new_cfg.get("listen"):
                changed.append("listen(监听地址变更需重启生效)")
            if api_bind_changed:
                changed.append("api(API 监听地址/端口变更需重启生效)")
            if api_token_changed:
                changed.append("api.token(已即时生效, 下次请求起即校验新 token)")
        self.cfg = new_cfg
        log.info("配置热重载完成: %s", " / ".join(changed) if changed else "(无实质变更)")
        return {"ok": True, "changed": changed}

    def restart(self):
        """重启 daemon 服务。

        systemd 托管时调用 `systemctl restart ebpdns`（systemd 先 SIGTERM 当前
        进程再拉起新实例）；手动运行时用 os.execv 以相同参数替换自身进程
        （Python socket 默认 CLOEXEC，exec 后端口自动释放可重新 bind）。
        本方法在调用方线程中执行，调用前应先返回 HTTP 响应（延迟触发）。
        """
        # systemd 托管检测：INVOCATION_ID / JOURNAL_STREAM 由 systemd 注入
        if os.environ.get("INVOCATION_ID") or os.environ.get("JOURNAL_STREAM"):
            try:
                subprocess.Popen(
                    ["systemctl", "restart", "ebpdns"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                return
            except Exception:
                pass
        # 手动运行兜底：exec 替换自身。
        # 不依赖 sys.argv(可能是相对路径/无 -m 前缀), 用绝对路径重建命令:
        #   python3 -m ebpdns run --config <绝对路径>
        # 并固定 PYTHONPATH=src 目录 + cwd=src, 保证任意启动方式下重启确定性成功
        # (曾现: execv 继承的空 PYTHONPATH/相对 -c 路径导致 ImportError 后进程退出)。
        try:
            import ebpdns as _pkg
            src_dir = os.path.dirname(os.path.dirname(os.path.abspath(_pkg.__file__)))
            cfg_abs = os.path.abspath(self.config_path or "")
            env = dict(os.environ)
            env["PYTHONPATH"] = src_dir + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
            cmd = [sys.executable, "-m", "ebpdns", "run", "--config", cfg_abs]
            log.info("服务重启: %s (cwd=%s)", " ".join(cmd), src_dir)
            os.chdir(src_dir)
            os.execvpe(sys.executable, cmd, env)
        except Exception as e:
            log.error("服务重启失败: %r", e)
            os._exit(1)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ebpdns/" + __version__

    # ---------- helpers ----------
    @property
    def app(self):
        return self.server.app

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, OSError):
            pass  # 客户端已提前断开连接, 静默忽略

    # v1.9.76 P1-2: 请求体上限分级。普通接口 4MB(足以应付绝大多数配置/规则增量);
    # rules/import(粘贴海量域名)与 rules/subscribe 单独 16MB。超限直接 413 不 drain。
    MAX_BODY = 4 * 1024 * 1024          # 普通接口默认上限 4MB
    MAX_BODY_BIG = 16 * 1024 * 1024     # rules/import、rules/subscribe 上限 16MB

    def handle(self):
        # P1-1: APIServer.process_request 对连接设置了 15s 读/空闲超时(防慢滴 body
        # 或 keep-alive 空闲连接占满 256 槽位造成控制面 DoS, 与 DNS TCP 路径对称)。
        # 读请求行/头或 body 超时会抛 socket.timeout/TimeoutError, 此处静默断连,
        # 不打印 traceback(慢滴攻击连接每次超时都打栈会淹近日志)。body 读路径的
        # IO 异常已由 _read_json 统一吞掉并回 _SENTINEL。
        try:
            super().handle()
        except (_socket.timeout, TimeoutError, ConnectionResetError,
                 BrokenPipeError, EOFError):
            pass

    def _read_json(self, expect_dict=True, limit=None):
        try:
            if limit is None:
                limit = getattr(self, "_body_limit", self.MAX_BODY)
            # R51 P3-1: Content-Length 为非数值字符串(如 "abc")时 int() 抛 ValueError,
            # 此前未被 handle() 捕获会冒泡到 socketserver 打 traceback(仅日志噪音)。
            # 这里主动回 400 并返回 _SENTINEL(与 413 路径一致, 调用方静默 return),
            # 避免 traceback 噪音/日志洪泛。
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except (TypeError, ValueError):
                self._send(400, {"error": "bad Content-Length"})
                self.close_connection = True
                return _SENTINEL
            if n <= 0:
                return None
            # 超限直接 413, 不 drain body(大请求体不预读, 拒绝后连接由 handler 关闭)。
            # P1-1: 已自行回包 → 返回 _SENTINEL 并标记短连接, 调用方不得再发响应/落库。
            if n > limit:
                self._send(413, {"error": "request body too large (limit %d bytes)" % limit})
                self.close_connection = True
                return _SENTINEL
            obj = json.loads(self.rfile.read(n).decode("utf-8"))
            # 防御: 绝大多数端点期望 JSON 对象; 收到数组等非对象时返回 None,
            # 配合调用方 `or {}` 避免 body.get() 触发 AttributeError。
            if expect_dict and not isinstance(obj, dict):
                return None
            return obj
        except json.JSONDecodeError as e:
            # v1.9.80: JSON 语法错误 → 调用方按空 dict 处理最终返回 400
            log.debug("JSON decode error: %s", e)
            return None
        except Exception as e:
            # 其他错误(IO/连接重置): 连接已不可用, 无法可靠再发 JSON 错误。
            # P1-1: 返回 _SENTINEL 让调用方静默 return, 不得再落库/再发响应。
            log.warning("read body error: %r", e)
            try:
                self.close_connection = True
            except Exception:
                pass
            return _SENTINEL

    def _csrf_ok(self):
        """CSRF 防护: 对非 GET 写操作校验 Origin/Referer。
        v7 P1-1: 修 DNS Rebinding 绕过。原实现把 Origin host 与请求 Host 头做"自洽"
        比较, 而 DNS rebinding 攻击中两者都被攻击者控制为 evil.com:8080, 自洽即通过。
        新逻辑:
        - api.host 为环回(127.0.0.1/::1/localhost): Origin 的 host 必须等于配置的
          api.host(而非请求 Host 头); 同时要求请求 Host 头的 host 部分必须是环回地址,
          拒绝非环回 hostname 的 Host 头(纵深防御)。
        - api.host 为 0.0.0.0/::(监听全部地址的局域网访问场景): 回退原自洽检查
          (Origin host == Host 头 host, 或等于配置的 api host:port)。
        - 无 Origin 但有 Referer: 按同源规则同样校验。
        - 两者都没有(curl/脚本直连): 放行, 兼容命令行工具。"""
        api_cfg = self.app.cfg.get("api", {}) or {}
        configured_host = str(api_cfg.get("host", "127.0.0.1") or "127.0.0.1").strip().lower()
        configured_port = api_cfg.get("port", 8080)

        # 请求 Host 头的 host 部分(剥离端口, 兼容 IPv6 [::1]:8080 → "::1")
        req_host = self.headers.get("Host", "") or ""
        _req_parsed = urllib.parse.urlsplit("//" + req_host)
        req_host_part = (_req_parsed.hostname or "").lower()
        req_host_port = _req_parsed.port

        def _origin_host(url):
            try:
                return (urllib.parse.urlparse(url).hostname or "").lower()
            except Exception:
                return ""

        def _origin_port(url):
            """解析 URL 的端口; 显式端口返回 int, 默认端口(http→80/https→443)返回 None。"""
            try:
                return urllib.parse.urlparse(url).port
            except Exception:
                return None

        def _origin_scheme(url):
            try:
                return (urllib.parse.urlparse(url).scheme or "").lower()
            except Exception:
                return ""

        def _ports_same(origin_url, req_port):
            """LAN 模式 Origin/Referer 端口与请求 Host 头端口的对称比较。
            P3-2(第八轮): 此前 `oport != req_host_port` 让"Origin 无端口(http://host,
            urlparse.port 返回 None)"与"Host 头显式 host:80"这种语义同源(都是 80)被判为
            跨源。urlparse 对缺省端口恒返回 None, 不会按 scheme 归一, 故这里把 Origin 侧的
            None 按 scheme 归一为 80/443; Host 头侧 None 表示连接走默认端口, 仅当 Origin
            归一值也在 80/443 才算同源。显式端口直接相等比较。
            安全性不削弱: 浏览器对非默认端口总会在 Origin/Host 里显式带端口, 此归一只影响
            "同协议默认端口"这一种语义本就同源的情形; 同 IP 不同显式端口仍被拒绝。"""
            p = _origin_port(origin_url)
            if p is None:
                p = 443 if _origin_scheme(origin_url) == "https" else 80
            if req_port is None:
                # Host 头未带端口 = 连接走协议默认端口; 仅当 Origin 也落在默认端口
                return p in (80, 443)
            return p == req_port

        def _is_private_or_loopback_ip(host):
            """LAN 模式 CSRF 自洽回退的纵深检查: 要求 host 是私网段/环回/链路本地 IP,
            拒绝裸公网域名(如 evil.ddns.net)。LAN 模式下管理应通过 IP 访问。"""
            if not host:
                return False
            try:
                ip = ipaddress.ip_address(host)
            except ValueError:
                return False   # 是主机名, 不是 IP — 拒绝
            return ip.is_private or ip.is_loopback or ip.is_link_local

        # R23 P3-1: 环回判定——取代硬编码 _LOOPBACK 元组。IP 字符串走
        # ipaddress.is_loopback, 覆盖全部 127/8 与 ::1(此前只认 127.0.0.1/::1,
        # 绑定 127.0.0.2 等其它 127/8 时浏览器写操作被纵深检查误拒 403); 额外保留
        # "localhost" 字符串匹配(浏览器对 http://localhost:port 访问控制台的情形)。
        # 非 IP 的 hostname(如 LAN 域名)解析失败返回 False, 拒绝放行。
        def _is_loopback(host):
            if not host:
                return False
            if host == "localhost":
                return True
            try:
                return ipaddress.ip_address(host).is_loopback
            except ValueError:
                return False

        # 监听全部地址(局域网访问)→ 要求自洽 + host 必须是私网/环回 IP;
        # 否则按配置的 api.host 严格校验
        lan_mode = configured_host in ("0.0.0.0", "::", "::0", "")

        origin = self.headers.get("Origin")
        if origin:
            ohost = _origin_host(origin)
            if not ohost:
                return False
            oport = _origin_port(origin)
            if lan_mode:
                # P2-1(第八轮): 自洽检查 + 纵深 — Origin host 必须等于请求 Host 头 host,
                # 且该 host 必须是私网/环回/链路本地 IP(拒绝 DNS rebinding 公网域名)。
                # R2-S1 [P3]: 同时比较端口, 防止同 IP 另一端口托管页面绕过 CSRF。
                # P3-2(第八轮): 端口比较改走 _ports_same 对称归一, 修复 Origin 无端口
                # (None) vs Host 显式 :80 这种语义同源被误判跨源的不对称。
                if not (req_host_part and ohost == req_host_part):
                    return False
                if not _ports_same(origin, req_host_port):
                    return False
                return _is_private_or_loopback_ip(ohost)
            # 环回绑定: Origin host 必须等于配置的 api.host。
            # R22 P3-2: 严格字符串相等导致默认绑 127.0.0.1 时, 用 http://localhost:8080
            # 访问控制台(Origin 主机名=localhost)被误判跨源 → 403。配置为环回地址时放宽为
            # Origin host 命中 _is_loopback 即可(localhost/任意 127/8/::1 互通);
            # 配置为非环回地址(显式 LAN/公网 IP)时仍严格相等。安全不削弱: 配置环回时
            # 非环回 Origin host 仍被 `not _is_loopback(ohost)` 拒绝。
            if _is_loopback(configured_host):
                if not _is_loopback(ohost):
                    return False
            elif ohost != configured_host:
                return False
            # R2-S1 [P3]: 端口也必须匹配; Origin 不带端口(oport=None)时按 scheme
            # 归一为 80(http)/443(https)再与 configured_port 比较。
            # P3-2(第八轮): 此处与 LAN 模式的严格 `_ports_same` 不对称是有意保留——环回模式
            # 只在 api.host=127.0.0.1 时生效, 浏览器对非默认端口(如 :8080)总会在 Origin 里
            # 显式带端口(oport 非 None), 真正访问配置端口时 oport==configured_port 必然成立。
            # R49 P3-1: 原实现 `oport is not None and oport != configured_port` 在
            # oport=None 时整体跳过端口比较——这覆盖了"浏览器从 http://localhost(默认 80,
            # 不显式带端口)跨域 fetch 到 127.0.0.1:8080"的窄场景(本机 80 端口服务已被攻陷
            # 注入内容时可 CSRF 管理口)。修复: oport=None 时按 scheme 归一为默认端口再比较,
            # 不影响合法访问(浏览器访问 :8080 时 Origin 显式带 :8080, 走原路径)。
            _eff_port = oport if oport is not None else (
                443 if _origin_scheme(origin) == "https" else 80)
            if _eff_port != configured_port:
                return False
            # 纵深: 仅当 configured_host 是环回地址时, 才要求请求 Host 头 host 也必须是
            # 环回(拒绝 Host 头里出现非环回 hostname, 如 evil.ddns.net)。
            # R48 P2-1: 原实现无条件检查 req_host_part 环回, 导致 API 绑定到具体
            # LAN IP(如 192.168.1.10)时, Host 头即该 IP 本身(非环回)被误拒 → 全部
            # 写操作 403。绑定具体 IP 时 Origin/Referer 已按 configured_host 精确
            # 自洽(见上), 无需再对 Host 头做强环回约束。
            if _is_loopback(configured_host) and not _is_loopback(req_host_part):
                return False
            return True
        referer = self.headers.get("Referer")
        if referer:
            rhost = _origin_host(referer)
            if not rhost:
                return False
            rport = _origin_port(referer)
            if lan_mode:
                if not (req_host_part and rhost == req_host_part):
                    return False
                # P3-2(第八轮): 与 Origin 分支一致, 端口走 _ports_same 对称归一。
                if not _ports_same(referer, req_host_port):
                    return False
                return _is_private_or_loopback_ip(rhost)
            # R22 P3-2: 与 Origin 分支一致——配置环回时 Referer host 命中 _is_loopback
            # 即可, 否则严格等于 configured_host。
            if _is_loopback(configured_host):
                if not _is_loopback(rhost):
                    return False
            elif rhost != configured_host:
                return False
            # R49 P3-1: 与 Origin 分支一致, rport=None 时按 scheme 归一为 80/443 再比较。
            _eff_rport = rport if rport is not None else (
                443 if _origin_scheme(referer) == "https" else 80)
            if _eff_rport != configured_port:
                return False
            # R48 P2-1: 同 Origin 分支, 仅在环回绑定时要求 Host 头环回;
            # 绑定具体 LAN IP 时不再误拒。
            if _is_loopback(configured_host) and not _is_loopback(req_host_part):
                return False
            return True
        return True

    def _check_api_token(self):
        """P2-24: 可选 API token 认证。配置了 api.token(非空)时, 校验请求头
        Authorization: Bearer <token> 或 X-Api-Key: <token>。使用 hmac.compare_digest
        常量时间比较防时序攻击。返回 True=放行, False=未授权(调用方回 401)。
        未配置 token(空串)时始终放行。"""
        api_cfg = self.app.cfg.get("api", {}) or {}
        # P2-3(R3): expected 也 strip, 与 presented 对齐。用户手编 config.json 时
        # 末尾常带换行/空格(编辑器自动加换行), 不 strip 会导致 token 永远不匹配 → 401。
        expected = str(api_cfg.get("token") or "").strip()
        if not expected:
            return True   # 未启用认证
        # 取 Authorization: Bearer xxx 或 X-Api-Key: xxx
        presented = ""
        auth = self.headers.get("Authorization", "") or ""
        if auth.lower().startswith("bearer "):
            presented = auth[7:].strip()
        if not presented:
            presented = (self.headers.get("X-Api-Key", "") or "").strip()
        if not presented:
            return False
        # P2-1(R5): hmac.compare_digest 对 str 形式要求两端均为 ASCII-only, 任一含
        # 非 ASCII(如中文 token)即抛 TypeError, 导致所有已认证写请求断连且无 JSON 错误。
        # 统一按 UTF-8 bytes 比较, 规避 ASCII 限制并保持常量时间语义。
        return hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))

    def _rebuild_rule_index_timed(self):
        """重建规则索引并记录耗时。返回 (ok, err)。
        P1-6: 失败时返回 (False, str(e)), 关键路径据此返回 500(而非静默吞错回 200)。
        P2-13: rebuild_rule_index 内部持 resolver._prefetch_lock 读盘+建索引,
        期间走预取路径的 DNS 查询会短暂阻塞——这是已知性能瓶颈。真正的双缓冲
        (锁外构建新索引 + 锁内原子替换元组)需 resolver.py 支持, 本层无法实现。
        此处记录耗时(ms)供运维观测。调用时机: 规则文件已落盘之后。"""
        t0 = time.monotonic()
        try:
            self.app.resolver.rebuild_rule_index()
            dt = (time.monotonic() - t0) * 1000.0
            log.info("rebuild_rule_index took %.2fms", dt)
            return True, ""
        except Exception as e:
            dt = (time.monotonic() - t0) * 1000.0
            log.warning("rebuild_rule_index failed (%.2fms): %s", dt, e)
            return False, str(e)

    def _route(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        method = self.command

        # P2-24: 可选 API token 认证。配置了 api.token(非空)时, 除静态资源与
        # /api/health 外, 所有 /api/* 与 /metrics 端点必须携带
        # Authorization: Bearer <token> 或 X-Api-Key: <token>。
        # 静态资源豁免: 浏览器初始导航加载 JS 无法携带自定义请求头;
        # /api/health 豁免供容器/编排探活(无凭据)。未配置 token 时始终放行。
        if (path.startswith("/api/") or path == "/metrics") and path != "/api/health":
            if not self._check_api_token():
                return self._send(401, {"error": "未授权"})

        # v1.9.76 P1-2: rules/import(粘贴海量域名)与 rules/subscribe 单独放宽到 16MB,
        # 其余接口默认 4MB。_read_json 未显式传 limit 时读取此实例属性。
        self._body_limit = (self.MAX_BODY_BIG
                            if (path in ("/api/rules/import", "/api/rules/subscribe")
                                and method == "POST")
                            else self.MAX_BODY)

        # 静态资源
        if path in ("/", "/index.html"):
            return self._serve_static("index.html")
        if path == "/echarts.min.js":
            return self._serve_static("echarts.min.js")
        if path.startswith("/static/"):
            return self._serve_static(path[len("/static/"):])

        # ---------- API ----------
        # P3: 纯读端点限定 GET。非 GET(POST/PUT/DELETE/...)落到末尾 404,
        # 与显式 method 校验的写端点风格一致, 误调用不再被静默当作正常读。
        if path == "/api/health" and method == "GET":
            tel = self.app.telemetry
            return self._send(200, {
                "status": "ok",
                "running": True,
                "version": __version__,
                "uptime_s": int(time.time() - tel.boot_time),
            })
        if path == "/api/cache/stats" and method == "GET":
            # 缓存统计独立端点(功能测试要求): 透传 cache.summary() + 补充大小
            cache = self.app.resolver.cache
            try:
                summ = cache.summary()
            except Exception as e:
                return self._send(500, {"error": "cache stats failed: %s" % e})
            try:
                summ["size"] = cache.size()
            except Exception:
                pass
            return self._send(200, summ)
        if path == "/api/status" and method == "GET":
            return self._send(200, self._status())
        if path == "/api/snapshot" and method == "GET":
            return self._send(200, self._snapshot())
        if path == "/api/query" and method == "POST":
            return self._api_query()
        if path == "/api/config" and method == "GET":
            # 逐条规则已独立存储(rules_local.json): 返回配置时注入, 前端直接展示
            # P3: 纯读 GET 不触发惰性补 id 落盘(避免只读请求在锁外写盘)。
            cfg_out = dict(self.app.cfg)
            cfg_out["rules"] = self._local_rules(persist=False)
            return self._send(200, cfg_out)
        if path == "/api/config" and method == "PUT":
            return self._api_update_config()
        if path == "/api/upstreams" and method == "GET":
            return self._send(200, {"upstreams": self._upstreams_with_health()})
        if path == "/api/upstreams" and method == "POST":
            return self._api_add_upstream()
        if path.startswith("/api/upstreams/") and method in ("PUT", "DELETE"):
            return self._api_upstream_op(path[len("/api/upstreams/"):])
        if path == "/api/rules" and method == "GET":
            return self._send(200, self._rules_with_subs())
        if path == "/api/rules" and method == "POST":
            return self._api_add_rule()
        if path == "/api/rules/import" and method == "POST":
            return self._api_import_rules()
        if path == "/api/rules/subscribe" and method == "POST":
            return self._api_subscribe_rules()
        if path == "/api/rules/subscribe/update" and method == "POST":
            return self._api_subscribe_update()
        if path == "/api/rules/subscribe" and method == "DELETE":
            return self._api_subscribe_delete(query)
        if path.startswith("/api/rules/") and method in ("PUT", "DELETE"):
            return self._api_rule_op(path[len("/api/rules/"):])
        if path == "/api/reset" and method == "POST":
            self.app.telemetry.reset()
            self.app.resolver.cache.clear()
            return self._send(200, {"ok": True})
        if path == "/api/reprobe" and method == "POST":
            return self._api_reprobe()
        if path == "/api/restart" and method == "POST":
            return self._api_restart()
        if path == "/api/reload" and method == "POST":
            return self._send(200, self.app.reload())
        # v7 P3-1: 性能剖析有副作用(cProfile 进程级 hook, 采样期间有性能开销), 且会
        # 阻塞线程 N 秒。此前任意方法(含 GET)都触发, 一个 <img> 标签/浏览器预取即可
        # 静默启动采样。改为仅 POST(写操作, 经 do_POST 的 CSRF 校验)。
        if path == "/api/profile" and method == "POST":
            return self._api_profile(query)
        if path == "/api/logs" and method == "GET":
            return self._send(200, self._logs(query))
        if path == "/api/pipeline" and method == "GET":
            return self._send(200, self._pipeline())
        if path == "/metrics" and method == "GET":
            return self._metrics()
        self._send(404, {"error": "not found"})

    # ---------- handlers ----------
    def _status(self):
        app = self.app
        tel = app.telemetry
        cache = app.resolver.cache
        _counters, _rule_hits, _hit_rate, _qps, _avg_lat = tel.counters_snapshot()
        # R35 P3-1: 与 /api/cache/stats 同型包裹 cache.summary(), 失败时回退空 dict,
        # 避免异常穿透 _route → do_GET 导致客户端断连而非 JSON 响应。
        try:
            _cache_map = cache.summary()
        except Exception:
            _cache_map = {}
        return {
            "app": "ebpdns",
            "version": __version__,
            "uptime_s": int(time.time() - tel.boot_time),
            "running": True,
            "qps": _qps,
            "hit_rate": round(_hit_rate, 1),
            "avg_latency_ms": round(_avg_lat, 1) if _avg_lat is not None else None,
            # 锁内拷贝 counters/rule_hits, 避免 reset 瞬间读到不自洽中间态
            "counters": _counters,
            "rule_hits": _rule_hits,
            "map": _cache_map,
            "cache_policy": str(self.app.cfg.get("cache_policy", "lru")).lower(),
            "health_check_interval": int(self.app.cfg.get("health_check_interval", 30) or 0),
            "rule_sub_interval": int(self.app.cfg.get("rule_sub_interval", 3600) or 0),
            "cache_file": (app.cfg.get("cache_file") or ""),
            # H-3: 共享容器迭代必须走加锁快照, 否则并发 count_top/upstream_ok
            # 触发 RuntimeError: dictionary changed size during iteration
            "top_domains": tel.top_domains_snapshot(10),
            "top_clients": tel.top_clients_snapshot(10),
            "top_upstreams": sorted(
                ((u, st.get("ok", 0) + st.get("fail", 0)) for u, st in tel.upstreams_snapshot()),
                key=lambda x: x[1], reverse=True)[:10],
            "config_path": app.config_path,
            "endpoints": app.dns_server.endpoints() if app.dns_server else None,
            # #6 UDP 池满丢弃计数(udp4+udp6), 前端遥测页展示
            "udp_dropped": app.dns_server.udp_dropped() if app.dns_server else 0,
        }

    def _snapshot(self):
        s = self.app.telemetry.snapshot()
        # /api/snapshot 快照轮询: events 截断为最近 20 条避免 500 条全量序列化
        # (完整实时日志走 /api/logs 增量拉取, 前端不消费 snapshot.events)
        s["events"] = s["events"][-20:]
        # R35 P3-1: 与 /api/cache/stats 同型包裹 cache.summary(), 失败时回退空 dict。
        try:
            s["map"] = self.app.resolver.cache.summary()
        except Exception:
            s["map"] = {}
        s["upstreams"] = self._upstreams_with_health()
        s["config_snippet"] = {
            "hook": self.app.cfg.get("hook"),
            "map_type": self.app.cfg.get("map_type"),
            "kernel_direct": self.app.cfg.get("kernel_direct"),
            "cache_size": self.app.cfg.get("cache_size"),
            "ttl": self.app.cfg.get("ttl"),
            "prefetch": self.app.cfg.get("prefetch"),
            "speed_test": self.app.cfg.get("speed_test"),
            "ipv6": self.app.cfg.get("ipv6"),
            "edns": self.app.cfg.get("edns"),
            "fallback": self.app.cfg.get("fallback"),
            "ipv4_first": self.app.cfg.get("ipv4_first"),
            "percpu": self.app.cfg.get("percpu"),
        }
        return s

    def _api_query(self):
        body = self._read_json()
        if body is _SENTINEL:
            return
        body = body or {}
        # P2-1(R4-S1): domain/qtype 必须是字符串, 数字/数组/对象时 .strip()/.upper() 抛
        # AttributeError 导致 500。显式 isinstance 校验, 非法类型直接 400。
        domain = body.get("domain")
        if not isinstance(domain, str):
            return self._send(400, {"error": "domain must be a string"})
        domain = domain.strip()
        qtype = body.get("qtype") or "A"
        if not isinstance(qtype, str):
            return self._send(400, {"error": "qtype must be a string"})
        qtype = qtype.upper()
        if not domain:
            return self._send(400, {"error": "domain required"})
        if len(domain) > 253:
            return self._send(400, {"error": "domain too long (max 253)"})
        # P3-3(R4-S9): 逐标签长度校验——单标签超过 63 字符的域名(如 a*64.com)在 DNS
        # 协议层非法, 此前会穿透到 resolver 触发 502。在此 400 拒绝。
        if any(len(lbl) > 63 for lbl in domain.split(".")):
            return self._send(400, {"error": "domain label too long (max 63 chars)"})
        # qtype 必须是已知类型名, 未知类型(畸形/拼写错误)直接 400
        if dnsmsg.type_code(qtype) == 0:
            return self._send(400, {"error": "bad qtype: %r" % (qtype,)})
        try:
            res = self.app.resolver.resolve(domain, qtype, silent=False, client_ip="查询控制台")
        except Exception as e:
            return self._send(502, {"error": "resolve failed", "detail": str(e)})
        tel = self.app.telemetry
        tel.add_manual_entry({
            "ts": _now_ts(),
            "domain": res["domain"],
            "qtype": res["qtype"],
            "answer": res.get("chosen") or "NXDOMAIN",
            "lat": res.get("latency", 0),
        })
        return self._send(200, res)

    def _api_reprobe(self):
        """一键重新测速：强制对所有启用上游重新实测延迟并写回配置。"""
        # 网络探测在锁外进行(避免多上游时阻塞所有 API 操作数秒),
        # 锁内按 id 合并回写(与 _api_add_upstream 的 app_ctx 范式对齐,
        # probe.py 内部已实现进锁重读最新 cfg + 按 id 合并 + save_config)。
        # P2-3: probe 可能抛 ValueError(SSRF 拒绝)/网络/getaddrinfo 异常, 不包裹会
        # 穿透到 socketserver 线程导致连接重置而非 JSON 错误(其它 handler 已 502 包裹)。
        try:
            results = probe_upstream_latencies(self.app.cfg, self.app.config_path,
                                               force=True, tag="重新测速", app_ctx=self.app)
        except Exception as e:
            log.warning("reprobe failed: %r", e)
            return self._send(502, {"error": "reprobe failed: %s" % e})
        return self._send(200, {"ok": True, "results": results})

    def _api_profile(self, query):
        """性能剖析端点: GET/POST /api/profile?seconds=N (默认 3, 上限 10)。
        对运行中流量采样 N 秒(cProfile 全局 hook), 返回按累计耗时排序的
        Top 函数统计——定位热点用。注意: 采样期间有性能开销, 按需调用。
        v1.9.74 P2-8: 全局单飞(threading.Lock), 同时只允许一个采样——cProfile
        是进程级单例, 并发两次采样会互相 enable/disable 污染统计; 第二个请求直接
        409 拒绝, 不排队阻塞。"""
        if not _PROFILE_LOCK.acquire(blocking=False):
            return self._send(409, {"error": "已有 profile 采样进行中, 请稍后再试"})
        try:
            try:
                seconds = min(10, max(1, int((query.get("seconds") or ["3"])[0])))
            except Exception:
                seconds = 3
            import cProfile
            import io as _io
            import pstats
            prof = cProfile.Profile()
            log.info("性能剖析启动: 采样 %d 秒(期间有 cProfile 开销)", seconds)
            prof.enable()
            try:
                time.sleep(seconds)
            finally:
                prof.disable()
            buf = _io.StringIO()
            try:
                pstats.Stats(prof, stream=buf).sort_stats("cumulative").print_stats(25)
            except Exception:
                buf.write("(无采样数据, 采样期间可能无查询流量)")
            return self._send(200, "ebpdns profile (%ds):\n" % seconds + buf.getvalue(),
                              ctype="text/plain; charset=utf-8")
        finally:
            _PROFILE_LOCK.release()

    def _api_restart(self):
        """重启 daemon：先返回响应，1 秒后由后台线程触发重启。"""
        # P3-12: 防重入。重启是延迟触发(1s 后后台 exec/systemctl), 两次连点会
        # 派生两个重启线程, 后者可能在前者已替换进程后再次执行导致异常。
        # 首个请求置位后, 后续请求直接 409。
        if _RESTART_STARTED.is_set():
            return self._send(409, {"error": "重启已在进行中"})
        _RESTART_STARTED.set()
        def _do():
            time.sleep(1.0)  # 确保 HTTP 响应已发出
            try:
                self.app.restart()
            except Exception as e:
                # P3-3(第八轮): 重启抛异常(未走到 exec/_exit)时, 进程仍在但 Event 已置位,
                # 不 clear 则后续所有 /api/restart 永久 409。立即 clear 允许运维重试。
                log.warning("重启触发失败: %r, 释放 _RESTART_STARTED 允许重试", e)
                _RESTART_STARTED.clear()
                return
            # restart() 正常返回仅发生在 systemd Popen 成功分支(进程未被替换)。
            # 若 systemctl 实际失败(service 未安装/权限不足), 本进程仍在运行,
            # 但 Event 已置位 → 后续重启请求被永久 409。加看门狗: 30s 后本进程仍存活
            # (说明既没被 exec 替换也没被 systemd 拉起), 则 clear Event 允许再次重启。
            # 真正重启成功的话旧进程已退出, 此看门狗线程随之销毁, 对新进程无副作用
            # (Event 是模块级单例, 新进程重新 import 即为初始未置位状态)。
            def _watchdog():
                time.sleep(30.0)
                _RESTART_STARTED.clear()
                log.info("重启看门狗: 进程仍存活(疑似 systemctl 未生效), 已清除 _RESTART_STARTED 允许再次重启")
            threading.Thread(target=_watchdog, daemon=True, name="svc-restart-watchdog").start()
        threading.Thread(target=_do, daemon=True, name="svc-restart").start()
        return self._send(200, {"ok": True, "restarting": True})

    def _validate_cfg_update(self, data):
        """PUT /api/config 增量字段校验(P2-1)。

        config._validate_cfg 的数值/枚举/布尔校验只在 load_config()(启动 + 文件热重载)
        跑; PUT 之前直接 deep_merge, 导致 timeout_ms:0 / ttl_max:-5 / 字符串布尔等
        越界值立即生效并落盘, 重启才被回退。这里在 deep_merge 前对增量 data 做等价
        校验: 非法字段直接 400 拒绝(而非静默回退默认), 布尔键统一 _as_bool 归一。
        原地归一 data(数值 int 化 / 枚举小写 / 布尔 bool 化)。返回 None=通过, 否则错误串。"""
        # 布尔键归一: "false"/"0"/"off"/"no" 必须判为 False, 否则非空字符串被
        # `if cfg["ipv6"]` 误判为真(正是 _as_bool 要防的问题, 此前只在 upstream 编辑处用)。
        for k in config_mod._BOOL_KEYS:
            if k in data:
                data[k] = _as_bool(data[k], bool(config_mod.DEFAULTS.get(k, False)))
        for k, (lo, hi) in config_mod._NUM_RANGES.items():
            if k not in data:
                continue
            v = data[k]
            # R2-P2: bool 是 int 子类, int(True)==1 会穿透到合法值。
            # 与 P2-17(规则 ttl)同型 bug —— 配置数值字段此前未排除布尔。
            if isinstance(v, bool):
                return "bad %s: 必须是整数，不能是布尔值 (%r)" % (k, v)
            try:
                iv = int(v)
            except (TypeError, ValueError, OverflowError):
                return "bad %s: 必须是整数 (%r)" % (k, v)
            if (lo is not None and iv < lo) or (hi is not None and iv > hi):
                return "bad %s: 超出范围 [%s, %s] (got %r)" % (k, lo, hi, iv)
            data[k] = iv
        # P3-3(第八轮): edns_client_subnet 写入路径无类型/前缀校验。非空时必须是
        # 合法 CIDR 网络, 前缀钳制到地址族合法范围(v4≤32 / v6≤128), 规范化后写回。
        if "edns_client_subnet" in data:
            ecs = data["edns_client_subnet"]
            if ecs is not None and str(ecs).strip() != "":
                try:
                    # P3-2(R4): /33、/129 等越界前缀在 ip_network 构造时即 ValueError,
                    # 此前"构造后再判 prefixlen 钳制"的分支不可达(死代码), 已删除; 越界直接 400 拒绝。
                    net = ipaddress.ip_network(str(ecs).strip(), strict=False)
                except ValueError:
                    return "bad edns_client_subnet: 必须是合法 CIDR 网络 (got %r)" % (ecs,)
                data["edns_client_subnet"] = str(net)
            else:
                # P3-3(R4): 空值统一归一为 None(与加载期/默认值对齐), 不再写空串 ""。
                data["edns_client_subnet"] = None
        # P2-2(第七轮): dict 类型字段(cache_partitions)此前无类型校验, PUT 可写入
        # string 等畸形值, deep_merge 后 resolver 后续 .items() 崩溃。非 None 时必须是 dict。
        if "cache_partitions" in data and data["cache_partitions"] is not None:
            cp = data["cache_partitions"]
            if not isinstance(cp, dict):
                return "bad cache_partitions: 必须是对象或 null"
            # P3-1(第八轮): dict 内各分区权重此前未校验为数值。R7 P2-2 只校验外层是
            # dict, 手构造 body 可写入 {"domestic": "abc", "global": true} 这种畸形值,
            # 穿透 deep_merge 后 resolver 加权计算时 TypeError。遍历值, 非数值(排除 bool)
            # 直接 400 拒绝, 与本函数其它字段"非法即拒绝"语义一致, 不静默回退。
            for _ck, _cv in cp.items():
                if isinstance(_cv, bool) or not isinstance(_cv, (int, float)):
                    return ("bad cache_partitions: 分区 %r 的权重必须是数字(不能是布尔/字符串) "
                            "(got %r)" % (_ck, _cv))
                # R27 P3-5: 权重必须非负 —— 负权重进入 resolver 加权分区容量分配会导致
                # 分区容量分配异常。此前只校验为数值(排除 bool), 不校验 >=0。
                if _cv < 0:
                    return ("bad cache_partitions: 分区 %r 的权重不能为负数 (got %r)" % (_ck, _cv))
        for k, allowed in config_mod._ENUM_VALUES.items():
            if k not in data:
                continue
            v = data[k]
            if not isinstance(v, str) or v.lower() not in allowed:
                return "bad %s: 必须是 %s 之一 (got %r)" % (
                    k, "/".join(sorted(allowed)), v)
            data[k] = v.lower()
        return None

    def _api_update_config(self):
        data = self._read_json()
        if data is _SENTINEL:
            return
        if not isinstance(data, dict):
            return self._send(400, {"error": "bad config"})
        # 白名单: 只允许写配置主体中既有的顶层键(排除 listen/api/web_root)。
        # 防止 deep_merge 把攻击者注入的任意键(如伪装 listen/钩子字段)写回。
        # #5 记录被白名单过滤掉的键, 回传 ignored_keys 供前端 note() 提示用户:
        # 哪些提交的键未被保存(避免静默丢弃让用户误以为已生效)。
        # P3-1: 运行时派生键(cache_file/rule_sub_file/rule_local_file)不计入 ignored_keys,
        # 否则每次保存都提示纯噪音; 它们本就不该落盘, 下方 data 过滤仍按白名单剔除。
        dropped = [k for k in data.keys()
                   if k not in _CFG_WRITABLE_KEYS
                   and k not in _RUNTIME_KEYS
                   and k not in _SERVER_KEYS]
        data = {k: v for k, v in data.items() if k in _CFG_WRITABLE_KEYS}
        # 防御: cache_size 仅在请求中显式传入时校验; 未传则保留现有值。
        # 显式 null/非整数/越界均拒绝, 否则后续 int(None) 崩溃或容量被静默清空。
        if "cache_size" in data:
            cs = data["cache_size"]
            if cs is None or not (isinstance(cs, int) and not isinstance(cs, bool)
                                  and 1 <= cs <= 10_000_000):
                return self._send(400, {"error": "bad cache_size: %r" % (cs,)})
        # upstreams 必须是列表, 否则后续遍历/保存会类型错误
        if "upstreams" in data and not isinstance(data["upstreams"], list):
            return self._send(400, {"error": "bad upstreams: must be a list"})
        # P2-1(第六轮): 整体覆盖 upstreams[] 时逐项校验 proto 枚举 + port 范围,
        # 与 POST/PUT 单上游对齐。此前只校验"是 list", 手构造 body 可落库死上游。
        if "upstreams" in data:
            for i, u in enumerate(data["upstreams"]):
                verr = _validate_upstream_dict(u)
                if verr:
                    return self._send(400, {"error": "upstreams[%d]: %s" % (i, verr)})
        # P2-1: deep_merge 前对增量 data 做数值范围/枚举/布尔校验, 非法 400 拒绝。
        err = self._validate_cfg_update(data)
        if err:
            return self._send(400, {"error": err})
        # 逐条规则独立存储: 前端回传的 rules 从配置主体剥离, 单独写 rules_local.json
        # (config.json 不再保存逐条规则; 避免 deep_merge 把前端 rules 写回 config)
        # P3-3(R41): rules 必须是 list, 与 upstreams 同型。此前非 list(如字符串)会
        # 被 isinstance 检查静默跳过, 函数继续返回 200 但用户 rules 完全未保存, 与
        # upstreams 的 400 校验不一致。这里 pop 前显式类型检查。
        if "rules" in data and not isinstance(data["rules"], list):
            return self._send(400, {"error": "bad rules: must be a list"})
        data_rules = data.pop("rules", None)
        # P2-2(第六轮): 内嵌 rules[] 与 rule_subscriptions[] 逐项校验 action 枚举,
        # 与 import/subscribe/单条增改对齐。此前直接落盘可落库永不命中的死规则。
        if isinstance(data_rules, list):
            for i, r in enumerate(data_rules):
                # R17 P3-3: require_match=True —— bulk rules[] 必须带合法 match,
                # 拦截 match:null / 缺 match 键 / 非 str 类型的畸形规则入库。
                rerr = _validate_rule_dict(r, require_match=True)
                if rerr:
                    return self._send(400, {"error": "rules[%d]: %s" % (i, rerr)})
                # R28 P2-1: 与单条 POST/PUT 路径对齐 —— match 以 re: 开头时预编译正则,
                # 编译失败直接 400。此前 bulk 循环只调 _validate_rule_dict(仅校验 str/
                # 非空/≤4096 字节) + _normalize_rule_ttl, 坏正则会先落盘再让 rebuild
                # 失败/残留死规则。复用 _check_rule_regex 公共函数, 避免三处字面量漂移。
                rerr = _check_rule_regex(r.get("match", ""))
                if rerr:
                    return self._send(400, {"error": "rules[%d]: %s" % (i, rerr)})
                # R27 P2-1: TTL 字段校验与单条 POST/PUT 路径同型(bool 排除 + int 归一 +
                # 非负 + ttl_min<=ttl_max 顺序检查), 就地归一; 此前 bulk 只调
                # _validate_rule_dict 不触碰 TTL 字段, 可落库 "abc"/-5/true 非法值。
                terr = _normalize_rule_ttl(r)
                if terr:
                    return self._send(400, {"error": "rules[%d]: %s" % (i, terr)})
                # R27 P3-1: 与单条 POST /api/rules 对齐 —— 缺 id 的规则补一个新 id,
                # 避免落库后按 id 的 PUT/DELETE 在首次惰性迁移(_local_rules)前 404。
                if not r.get("id"):
                    r["id"] = _new_id("r")
        # P2-1(第七轮): rule_subscriptions 与 upstreams 同型守卫——此前漏了 isinstance
        # 检查, 非 list 畸形值(如 string/dict)穿透下方 `isinstance(..., list)` 分支被跳过,
        # 随 deep_merge 污染运行态, resolver 后续遍历触发 AttributeError。
        if "rule_subscriptions" in data and not isinstance(data["rule_subscriptions"], list):
            return self._send(400, {"error": "bad rule_subscriptions: must be a list"})
        if isinstance(data.get("rule_subscriptions"), list):
            for i, s in enumerate(data["rule_subscriptions"]):
                serr = _validate_rule_dict(s)
                if serr:
                    return self._send(400, {"error": "rule_subscriptions[%d]: %s" % (i, serr)})
                # P2(第八轮): 与加载期 config._validate_rule_subscription_item 对齐,
                # 复用其 url 必须 https:// 的强制校验, 消除 api/config 双份维护。
                # _validate_rule_dict 已覆盖 action 枚举/forceIp-ip/match 长度, 但不校验
                # 订阅 url 的 scheme; 此前 PUT /api/config 内嵌 rule_subscriptions[] 漏校,
                # http:// 订阅被接受后在拉取期才被拒绝(accepted-then-silently-dropped,
                # 不构成 SSRF——实际拉取仍强制 https——但校验强度与加载期不一致)。
                # 此处直接复用加载期同一判定函数, 任一分支未来加严都自动同步。
                if not config_mod._validate_rule_subscription_item(s):
                    return self._send(400, {
                        "error": "rule_subscriptions[%d]: 非法订阅项( url 必须以 https:// 开头 / action 非法 / forceIp 缺合法 ip ): %r" % (i, s)})
        # 合并前先快照旧上游列表, 用于事后 diff: 被删除/地址变更的上游要回收
        # DoH/DoT 连接池、QUIC 常驻连接与遥测统计, 否则随控制台"删除+保存"泄漏。
        # H-2: old_cfg / old_ups / old_policy 必须在锁内读取, 否则与 reload() 竞争——
        # 锁外读 old_cfg=v1, reload 中途把 self.cfg 换成 v2, 进锁后 deep_merge(v1)
        # 会把 v2 的变更覆盖丢失。
        old_policy = "lru"
        old_ups = []
        old_cfg = None
        old_cache = None
        old_capacity = None
        # P1-4/P1-6: 在锁外初始化保存/索引重建状态, 供锁后判断回 500
        saved = None
        idx_ok = True
        idx_err = ""
        saved_rules_ok = True   # R2-P1: bool 成功/失败, True=本次无 rules 需保存或已成功
        try:
            with self.app._lock:
                old_cfg = self.app.cfg   # 回滚用: 合并失败时还原旧配置引用
                old_ups = list(old_cfg.get("upstreams", []))
                old_policy = str(old_cfg.get("cache_policy", "lru")).lower()
                # 回滚用: cache.capacity 可能已在下方被改, cache 对象可能被
                # switch_cache_policy 整体替换; 异常时必须一并还原, 否则缓存策略/容量
                # 停留在半应用状态, 与回滚后的 cfg 不一致。
                old_cache = self.app.resolver.cache
                old_capacity = getattr(old_cache, "capacity", None)
                self.app.cfg = config_mod.deep_merge(old_cfg, data)
                # deep_merge 返回新 dict, resolver/DNSServer 持有旧引用。
                # 必须重绑定, 否则除 cache_size 外的配置(ttl/预取/测速/超时/IPv6/
                # 规则/上游/fallback/ipv4_first)都不会即时生效, 需重启才生效。
                self.app.resolver.cfg = self.app.cfg
                # 同步缓存容量
                self.app.resolver.cache.capacity = int(self.app.cfg.get("cache_size", 1024))
                # 缓存策略变更立即重建容器(保存即生效, 不必等 /api/reload)。
                # switch_cache_policy 按实际对象类型判定, 幂等。
                new_policy = str(self.app.cfg.get("cache_policy", "lru")).lower()
                if new_policy != old_policy:
                    try:
                        self.app.resolver.switch_cache_policy(new_policy)
                    except Exception as e:
                        log.warning("switch_cache_policy(%s) failed: %s", new_policy, e)
                # P1-2: switch_cache_policy 整体替换 cache 对象, 新对象按默认容量初始化,
                # 不继承上方刚写入的 cache_size。无论是否切换策略, 都要在切换后再按
                # cache_size 重设一次新 cache 的容量(切换失败时新对象即原对象, 重设幂等)。
                self.app.resolver.cache.capacity = int(self.app.cfg.get("cache_size", 1024))
                # 上游 diff: 找出"被整条删除"或"proto/addr/port/url 变更"的旧上游。
                # P2-4: 这些上游的统计/连接池清理必须推迟到 save_config 成功之后再执行。
                # 若在 save 之前就 pop per_upstream/_cb 并丢连接, 而随后 save_config 抛错,
                # except 分支只能回滚 cfg/cache 引用, 已被 pop 的统计/已丢连接无法补偿,
                # 造成"配置回滚了但该上游的统计/连接已丢失"的不一致。先只收集 victim,
                # save 成功后统一清理(此时配置已落盘, 删除/变更被确认)。
                new_ups = self.app.cfg.get("upstreams", [])
                new_ids = {u.get("id") for u in new_ups}
                # 记录 (old_upstream, is_deleted)。端点"变更"(同 id 改 proto/addr/port/url)
                # 时 is_deleted=False: 上游仍存在, 只能回收旧端点的连接池/conn_stats,
                # 绝不能 pop per_upstream/_cb(那会清掉该上游仍在累积的健康/熔断统计)。
                stale_victims = []
                for o in old_ups:
                    uid = o.get("id")
                    if uid not in new_ids:
                        stale_victims.append((o, True))   # 整条删除
                        continue
                    nu = next((x for x in new_ups if x.get("id") == uid), None)
                    if nu is None:
                        continue
                    if (str(o.get("proto", "")).lower() != str(nu.get("proto", "")).lower()
                            or o.get("addr") != nu.get("addr")
                            or o.get("port") != nu.get("port")
                            or (o.get("url") or "") != (nu.get("url") or "")):
                        stale_victims.append((o, False))   # 端点变更, 旧连接池 key 失效
                # 规则可能整体替换 → 重建索引
                saved = config_mod.save_config(self.app.cfg, self.app.config_path)
                # 逐条规则单独持久化(若前端回传了 rules)
                if isinstance(data_rules, list):
                    # R2-P1: 直接检查 bool 成功/失败, 空规则写成功=True
                    saved_rules_ok = self._save_local_rules(data_rules)
                # R2-P2: 只在所有配置(含规则)落盘后重建一次索引。
                # 旧实现此处先 rebuild 一次(基于"新配置+旧磁盘规则"混合态),
                # 然后如果有 rules 再 rebuild 一次 —— 第一次结果立即被第二次覆盖,
                # 10万条规则时阻塞 API/DNS 路径翻倍。移除第一次冗余 rebuild。
                # P1-6/P2-13: 用带耗时的辅助方法, 失败时记录 idx_ok/idx_err
                # P3-4(R4): 规则写盘失败时跳过 rebuild —— 磁盘上仍是旧规则, 从旧文件全量
                # 重建索引是无意义 I/O(10万规则数百ms 且持 app._lock), 与 import/DELETE/PUT 三处对齐。
                if saved_rules_ok:
                    idx_ok, idx_err = self._rebuild_rule_index_timed()
                else:
                    idx_ok, idx_err = True, ""
                # R26 P2-1: 与 DELETE 路径(R25 P3-2)对齐 —— save_config 写盘失败时,
                # 磁盘仍保留旧上游(被整条删除/端点变更的旧上游仍在 config.json 里)。
                # 此前 stale_victims 清理循环(含 drop_upstream/_cb.pop 清上游级健康/熔断
                # 统计、drop_conn/discard 清连接)在锁内先跑, 而 `if saved is False` 的 500
                # 兜底在锁外才判; save 失败时磁盘保留旧上游、但遥测/熔断统计已被清空, 正是
                # R25 要消除的"磁盘有上游但统计清零"。故先判 saved is False 返回 500, 确认
                # 删除/变更落盘后再回收, 不执行任何清理。
                if saved is False:
                    return self._send(500, {
                        "error": "配置写盘失败（运行态已生效，重启后将丢失）",
                        "ok": False, "saved_to": False, "ignored_keys": dropped})
                # P2-4: save_config 已成功, 配置变更被确认 —— 此刻才回收被删除/变更
                # 上游的连接池/QUIC 常驻连接; 整条删除才清 per_upstream/_cb 统计。
                # P2-2: 同时 pop 连接维度 telemetry.conn_stats(此前漏清, 随编辑上游缓慢泄漏)。
                for o, is_deleted in stale_victims:
                    uid = o.get("id")
                    if is_deleted:
                        # 整条删除: 连上游级健康/熔断统计一起清掉
                        # v1.9.86: 改用持锁 drop_upstream(与 drop_conn 对称), 不再裸 pop
                        try:
                            self.app.telemetry.drop_upstream(uid)
                        except Exception:
                            pass
                        try:
                            # R3-C1: 持 _cb_lock 清理熔断条目, 与写侧加锁纪律对齐
                            with self.app.resolver._cb_lock:
                                self.app.resolver._cb.pop(uid, None)
                        except Exception:
                            pass
                    # 端点变更(同 id)只回收旧端点的连接池/conn_stats, 保留上游级统计。
                    # 用 telemetry.drop_conn(持锁)而非裸 conn_stats.pop(未持 telemetry 锁),
                    # 与 conn_ok/conn_summary 的写侧加锁纪律一致, 避免锁外改共享 dict。
                    try:
                        self.app.telemetry.drop_conn(_conn_key(o))
                    except Exception:
                        pass
                    try:
                        upstream.discard_upstream_conns(o)
                    except Exception:
                        pass
                    try:
                        quic_upstream.discard_upstream(o)
                    except Exception:
                        pass
        except Exception as e:
            # 合并/应用过程中任何异常: 回滚配置引用, 避免半应用状态。
            # R31 P3-4: 回滚赋值必须重新持 _lock, 否则与 SIGHUP reload 等并发
            # 持锁替换 self.app.cfg 的路径存在理论竞态(锁外回写会覆盖新配置)。
            log.exception("更新配置失败, 回滚到旧配置: %r", e)
            with self.app._lock:
                self.app.cfg = old_cfg
                try:
                    self.app.resolver.cfg = old_cfg
                except Exception:
                    pass
                # 还原缓存容量与 cache 对象(switch_cache_policy 可能已整体替换)
                try:
                    if old_cache is not None:
                        if old_capacity is not None:
                            old_cache.capacity = old_capacity
                        self.app.resolver.cache = old_cache
                except Exception:
                    pass
            return self._send(500, {"error": "apply config failed: %s" % e})
        # 新增上游自动实测延迟: 只测启用且未实测过的上游(新添加的), 后台线程不阻塞响应
        try:
            from . import probe
            if any(u.get("enabled", True) and not u.get("latency_measured", False)
                   for u in self.app.cfg.get("upstreams", [])):
                def _probe():
                    try:
                        probe.probe_upstream_latencies(self.app.cfg, self.app.config_path,
                                                       force=False, tag="新增测速",
                                                       app_ctx=self.app)
                    except Exception:
                        pass
                threading.Thread(target=_probe, daemon=True, name="newup-probe").start()
        except Exception:
            pass
        # R26 P2-1: `if saved is False` 500 兜底已上移进锁内、stale_victims 清理循环之前
        # (见上方 with self.app._lock 内); 此处不再重复判。运行态配置已 deep_merge 生效
        # (在锁内完成), 不回滚; 仅告知前端写盘失败。能走到这里说明 save 已成功。
        # R2-P1: 逐条规则写盘失败 —— 直接检查 bool, 空规则(清空全部)写成功=True
        if isinstance(data_rules, list) and not saved_rules_ok:
            return self._send(500, {
                "error": "规则写盘失败（运行态已生效，重启后将丢失）",
                "ok": False, "ignored_keys": dropped})
        # P1-6: 规则索引重建失败(使用旧索引)
        if not idx_ok:
            return self._send(500, {
                "ok": False, "error": "规则索引重建失败", "detail": idx_err,
                "ignored_keys": dropped})
        return self._send(200, {"ok": True, "saved_to": saved, "ignored_keys": dropped})

    def _upstreams_with_health(self):
        cfg = self.app.cfg
        tel = self.app.telemetry
        # QUIC 连接诊断(doq/doh3): proto+host+port+path -> (connected, reconnects)
        # 与 quic_upstream.get_quic_upstream 的 key 对齐(含 path)
        qst = {}
        try:
            for q in quic_upstream.stats():
                path = str(q.get("path") or "")
                qst[(q["proto"], q["host"], q["port"], path)] = q
        except Exception:
            pass
        conns = tel.conn_summary()   # 连接维度健康度(proto|addr|port|url)
        out = []
        # R25 P3-1: 锁外迭代 cfg["upstreams"] 期间, 并发 POST append / DELETE pop
        # 会改变列表长度。CPython list 按索引迭代(GIL 保护下无 use-after-free), 不会
        # 崩溃, 但可能跳过或重复条目(纯展示层瞬时最终一致性)。此处入口做一次浅拷贝
        # 快照, 迭代期间结构稳定, 消除跳过/重复; 元素 dict 引用仍与活配置共享,
        # 单条 PUT 已由 R23 P2-1 原子引用交换保证不触发 dict 扩容 RuntimeError。
        ups_snapshot = list(cfg.get("upstreams", []))
        for u in ups_snapshot:
            # R22 P3-1: upstream_stat() 持锁返回的是 per_upstream 活字典引用, 此处随后
            # 在锁外连续读 ok/fail/lat_sum/last 四个字段, 会读到并发 upstream_ok/upstream_fail
            # 的撕裂中间态(纯展示瞬时撕裂, 无功能影响)。改用 upstream_eff_lat_read():
            # 它在 telemetry._lock 内 dict(st) 拷贝出快照后再返回, 与 resolver 延迟排序的
            # 锁内拷贝收口一致。无统计条目返回 None 时给零值默认, 展示路径不 setdefault
            # (避免在只读展示里向 telemetry 写入空条目)。
            st = tel.upstream_eff_lat_read(u.get("id")) or {
                "ok": 0, "fail": 0, "lat_sum": 0, "last": 0}
            total = st["ok"] + st["fail"]
            # 显式三元: total>0 时按真实比例计算(含 0%), 避免 `and/or` 把 0% 误判为假值落到兜底分支
            sr = (st["ok"] / total * 100.0) if total else (100.0 if u.get("enabled", True) else 0.0)
            base_lat = u.get("latency")
            base_lat = base_lat if isinstance(base_lat, (int, float)) else 0   # None 防护
            avg = st["lat_sum"] / st["ok"] if st["ok"] else base_lat
            status = "待命" if not total else ("健康" if sr >= 85 else ("抖动" if sr >= 60 else "异常"))
            # 连接维度健康(该上游各端点的独立成功率/延迟, 前端可精确到端点排障)
            proto = str(u.get("proto", "")).lower()
            ckey = "%s|%s|%s|%s" % (proto, u.get("addr", ""), u.get("port", ""), u.get("url", ""))
            cst = conns.get(ckey)
            item = {
                **u,
                "queries": total,
                "success_rate": round(sr, 1),
                "avg_latency": round(avg, 1) if isinstance(avg, (int, float)) else None,
                "status": status,
                "last_latency": st["last"],
                "conn_ok": cst["ok"] if cst else None,
                "conn_fail": cst["fail"] if cst else None,
                "conn_avg_lat": cst["avg_lat_ms"] if cst else None,
                "conn_key": ckey,
            }
            # QUIC 上游附加连接诊断（proto 复用上方连接健康块已算的值，避免重复计算）
            addr = str(u.get("addr", ""))
            try:
                port = int(u.get("port") or (853 if proto == "doq" else 443))
            except Exception:
                port = 853 if proto == "doq" else 443
            path = str(u.get("url") or "/dns-query")
            if not path.startswith("/"):
                path = "/" + path
            q = qst.get((proto, addr, port, path))
            if q is not None:
                item["quic_connected"] = q.get("connected", False)
                item["quic_reconnects"] = q.get("reconnects", 0)
                item["quic_fail_seq"] = q.get("fail_seq", 0)
            out.append(item)
        return out

    def _api_add_upstream(self):
        body = self._read_json()
        if body is _SENTINEL:
            return
        body = body or {}
        # P2-4(R4-S2): 畸形 JSON 被 _read_json 吞成 None → `or {}` 变空 dict, 然后用
        # 默认值(addr=223.5.5.5)静默创建默认上游。要求必须提供 addr 或 name 字段,
        # 缺失直接 400, 消除"空请求静默创建资源"。
        if not body.get("addr") and not body.get("name"):
            return self._send(400, {"error": "addr or name is required"})
        # R17 P3-1: name 长度上限 256, 与 PUT 单条编辑 / bulk _validate_upstream_dict
        # 对齐。此前 POST 新建上游路径遗漏, 超长 name 可直接落库膨胀配置/索引。
        # R18 P3-1: name 类型校验——提供时必须为 str, 与 group/addr 对齐。
        # 传 {"name": 123} 或 {"name": true} 会落成非字符串类型。
        _name_v = body.get("name")
        if _name_v is not None and not isinstance(_name_v, str):
            return self._send(400, {"error": "name 必须是字符串"})
        if isinstance(_name_v, str) and len(_name_v) > 256:
            return self._send(400, {"error": "name 过长 (上限 256 字符)"})
        # R17 P3-5: group 字段类型校验——若提供了 group 必须为 str, 与 PUT/bulk 对齐。
        # 此前 POST 新建上游不校验 group 类型, 传 {"group": 123} 之类非字符串真值
        # 会穿透 `or "domestic"` 落库为非 str, 后续分组逻辑(str 比较/索引)异常。
        _group_v = body.get("group")
        if _group_v is not None and not isinstance(_group_v, str):
            return self._send(400, {"error": "group 必须是字符串"})
        cfg = self.app.cfg
        # 完整地址自动识别（与前端一致）: addr 含 scheme:// 或 host:port 时解析出
        # proto/addr/port/url; 纯 IP/域名则按 body 字段原样使用。
        parsed = None
        # R19 P3-2: 自动解析分支此前对非字符串 addr 静默 str() 转换(如 {"addr": 123}
        # → "123"), 而手动分支有显式类型校验返回 400。此处补齐, 与手动分支对齐。
        _addr_v = body.get("addr")
        if _addr_v is not None and not isinstance(_addr_v, str):
            return self._send(400, {"error": "addr must be a string"})
        addr_raw = _addr_v or ""
        if addr_raw:
            parsed = config_mod.parse_upstream_addr(addr_raw, body.get("proto"))
        if parsed is not None:
            # P2-1: 自动识别分支的 proto 也必须在白名单内。parse_upstream_addr 的
            # proto_sel 分支不做枚举校验(任意 proto_sel 原样采用), 这里兜底拒绝。
            if str(parsed["proto"]).lower() not in _ALLOWED_UPSTREAM_PROTO:
                return self._send(400, {"error": "非法 proto: %r (允许: %s)" % (
                    parsed["proto"], "/".join(_ALLOWED_UPSTREAM_PROTO))})
            # R9-R4 P3: body 显式提供的 port 此前被自动解析分支静默忽略(裸 host 时
            # 恒用 53/443/853)。若用户显式给了越界 port, 显式 400 拒绝(而非静默落默认),
            # 与手动/PUT 路径对齐。addr 内嵌 host:port 的端口解析仍以 parse_upstream_addr 为准。
            _bp = body.get("port")
            if _bp is not None:
                # R6 P3-2: 显式排除 bool, 与手动/PUT/bulk 路径对齐。
                if isinstance(_bp, bool):
                    return self._send(400, {"error": "port 不允许是布尔值"})
                try:
                    _bpv = int(_bp)
                except (TypeError, ValueError):
                    return self._send(400, {"error": "port 必须是整数"})
                if not (1 <= _bpv <= 65535):
                    return self._send(400, {"error": "port 必须在 1-65535 之间 (got %d)" % _bpv})
                # P3-2(第七轮): 此前 body 显式 port 经范围校验后被丢弃, 上游恒用
                # parsed["port"](裸 host 时为协议默认 53/443/853), 与手动分支不一致。
                # 仅当 addr 字符串未内嵌 host:port 时, 才用 body 显式 port 覆盖解析默认端口;
                # 内嵌端口(如 8.8.8.8:5353)仍以 parse_upstream_addr 为准。
                if not _addr_has_explicit_port(addr_raw):
                    parsed["port"] = _bpv
            # R9-R4 P2: 自动解析出的 url(路径) 不得含控制字符, 与手动/PUT/bulk 对齐。
            if not _valid_url_path(parsed["url"]):
                return self._send(400, {"error": "非法 url: %r (不允许包含控制字符)" % (parsed["url"],)})
            u = {
                "id": _new_id("u"),
                "proto": parsed["proto"],
                "addr": parsed["addr"],
                "port": parsed["port"],
                "url": parsed["url"],
                "group": body.get("group") or "domestic",
                "latency": 0,               # 0 = 未测速, 待后台实测写回真实延迟
                "latency_measured": False,
                "enabled": _as_bool(body.get("enabled", True)),
            }
            saved = None
            with self.app._lock:
                cfg = self.app.cfg   # 重新取最新引用, 防止持旧 cfg 覆盖并发更新
                # P3-2: 默认名在锁内按最新 upstreams 计算, 避免并发连点两次
                # "添加上游"时用进锁前旧 cfg 长度算出重复默认名。
                # R30 P3-5: 改用 _default_upstream_name 去重, 删除上游后再新增不会重名。
                u["name"] = body.get("name") or _default_upstream_name(cfg["upstreams"])
                cfg["upstreams"].append(u)
                saved = config_mod.save_config(cfg, self.app.config_path)
            # 新上游后台实测延迟并写回
            try:
                from . import probe
                threading.Thread(target=probe.probe_upstream_latencies,
                                 args=(cfg, self.app.config_path),
                                 kwargs={"force": False, "tag": "新增测速",
                                         "app_ctx": self.app},
                                 daemon=True, name="newup-probe").start()
            except Exception:
                pass
            # P1-4: 写盘失败返回 500(运行态已生效, 但重启后丢失)
            if saved is False:
                return self._send(500, {"error": "配置写盘失败（运行态已生效，重启后将丢失）", "ok": False})
            return self._send(200, {"ok": True, "upstream": u, "auto_parsed": True})
        proto = str(body.get("proto") or "udp").lower()
        _default_port = {"udp": 53, "tcp": 53, "doh": 443, "dot": 853, "doq": 853, "doh3": 443}
        # P2-1: 与 PUT /api/upstreams/<id> 同型校验——proto 枚举 + port 1-65535。
        # 此前手动分支仅 int() 校验 port, 任意 proto/越界端口被静默落库成死上游。
        if proto not in _ALLOWED_UPSTREAM_PROTO:
            return self._send(400, {"error": "非法 proto: %r (允许: %s)" % (
                proto, "/".join(_ALLOWED_UPSTREAM_PROTO))})
        try:
            # 区分"未传 port"(用默认)与"显式传 0": `body.get("port") or 默认` 会把
            # 显式 0 当缺失静默改成默认 53, 与 PUT 路径(显式 0 被 400)不一致。仅当
            # 键缺失(None)时才用默认, 显式 0/越界值走下方范围校验。
            _pv = body.get("port")
            _lv = body.get("latency")
            if isinstance(_pv, bool) or isinstance(_lv, bool):
                return self._send(400, {"error": "port/latency 不能是布尔值"})
            port = int(_pv) if _pv is not None else _default_port.get(proto, 53)
            int(_lv or 20)  # 仅校验合法性; 新上游延迟统一 0=待后台实测写回
        except (TypeError, ValueError):
            return self._send(400, {"error": "port/latency 必须是整数"})
        if not (1 <= port <= 65535):
            return self._send(400, {"error": "port 必须在 1-65535 之间 (got %d)" % port})
        # P3-5(第八轮): 手动分支校验 addr 字符集, 拒绝含空格/分号/引号等危险字符。
        # R8-F2: addr 必须是字符串。非字符串真值(如 JSON 数组)穿透自动识别分支后
        # 在此 .strip() 会抛 AttributeError → 500。先做类型兜底。
        addr_val = body.get("addr")
        if addr_val is not None and not isinstance(addr_val, str):
            return self._send(400, {"error": "addr must be a string"})
        addr = (addr_val or "223.5.5.5").strip()
        if not _valid_host(addr):
            return self._send(400, {"error": "非法 addr: %r (仅允许 IPv4/IPv6/主机名字符集)" % (addr,)})
        if proto in ("doh", "doh3", "doq"):
            url = body.get("url") or "/dns-query"
        else:
            url = ""
        # R9-R4 P2: 手动分支 url 控制字符校验, 与 PUT 单条编辑/自动解析/bulk 对齐。
        if not _valid_url_path(url):
            return self._send(400, {"error": "非法 url: %r (不允许包含控制字符)" % (url,)})
        u = {
            "id": _new_id("u"),
            "proto": proto,
            "addr": addr,
            "port": port,
            "url": url,
            "group": body.get("group") or "domestic",
            "latency": 0,               # 0 = 未测速, 待后台实测写回真实延迟
            "latency_measured": False,
            "enabled": _as_bool(body.get("enabled", True)),
        }
        saved = None
        with self.app._lock:
            cfg = self.app.cfg   # 重新取最新引用, 防止持旧 cfg 覆盖并发更新
            # P3-2: 默认名在锁内按最新 upstreams 计算(与自动识别分支对齐)。
            # R30 P3-5: 改用 _default_upstream_name 去重, 删除上游后再新增不会重名。
            u["name"] = body.get("name") or _default_upstream_name(cfg["upstreams"])
            cfg["upstreams"].append(u)
            saved = config_mod.save_config(cfg, self.app.config_path)
        # 新上游后台实测延迟并写回
        try:
            from . import probe
            threading.Thread(target=probe.probe_upstream_latencies,
                             args=(cfg, self.app.config_path),
                             kwargs={"force": False, "tag": "新增测速",
                                     "app_ctx": self.app},
                             daemon=True, name="newup-probe").start()
        except Exception:
            pass
        # P1-4: 写盘失败返回 500(运行态已生效, 但重启后丢失)
        if saved is False:
            return self._send(500, {"error": "配置写盘失败（运行态已生效，重启后将丢失）", "ok": False})
        return self._send(200, {"ok": True, "upstream": u})

    def _api_upstream_op(self, up_id):
        # #1 [严重]: body 读取(_read_json 阻塞读 socket/解析 JSON)必须移出 app._lock。
        # 否则慢客户端上传 body 期间持全局锁, 阻塞所有 DNS 解析与其它 API。
        # R16 P3-4: handler 无 do_PATCH 分发方法(仅 GET/POST/PUT/DELETE), PATCH 请求
        # 根本到不了 _route(), 原 ("PUT","PATCH") 判定为死代码。单条 PUT 本身已是
        # "只更新 body 中出现的字段"的部分更新语义, 与 PATCH 等价, 故移除 PATCH 分支。
        if self.command == "PUT":
            body = self._read_json()
            if body is _SENTINEL:
                return
            body = body or {}
        else:
            body = {}
        with self.app._lock:
            cfg = self.app.cfg
            ups = cfg.get("upstreams", [])
            idx = next((i for i, u in enumerate(ups) if u.get("id") == up_id), None)
            if idx is None:
                return self._send(404, {"error": "upstream not found"})
            if self.command == "DELETE":
                removed = ups[idx]   # pop 前保存引用, 供连接池清理使用
                ups.pop(idx)
                saved = config_mod.save_config(cfg, self.app.config_path)
                # R25 P3-2: 与 bulk PUT stale_victims 模式对齐 —— 遥测/熔断/连接池
                # 清理必须推迟到 save_config 成功确认之后。若 save 失败(磁盘只读/满),
                # 磁盘仍保留该上游, 重启后从磁盘恢复; 此前若已 drop_upstream/discard
                # 连接, 重启后历史遥测统计与连接对象丢失, 造成"磁盘有上游但统计清零"。
                # 故先判 saved is False 返回 500, 确认删除落盘后再回收。
                # P1-4: 写盘失败返回 500(运行态已生效, 但重启后丢失)
                if saved is False:
                    return self._send(500, {"error": "配置写盘失败（运行态已生效，重启后将丢失）", "ok": False})
                # 同步清理该上游的遥测统计 + DoH/DoT 连接池 + QUIC 常驻连接
                # (防 per_upstream/_pool 残留已删除上游的统计与连接对象/线程)
                # v1.9.86: 改用持锁 drop_upstream(与 drop_conn 对称), 不再裸 pop
                try:
                    self.app.telemetry.drop_upstream(up_id)
                except Exception:
                    pass
                try:
                    # R3-C1: 持 _cb_lock 清理熔断条目, 与写侧加锁纪律对齐
                    with self.app.resolver._cb_lock:
                        self.app.resolver._cb.pop(up_id, None)
                except Exception:
                    pass
                # P2-2: 同步清理连接维度遥测统计(proto|addr|port|url), 与 per_upstream
                # 对称 —— 此前漏清, 每次删除上游旧 conn_stats 条目永久残留导致内存缓涨。
                # 用持锁的 drop_conn 而非裸 conn_stats.pop, 与写侧加锁纪律一致。
                try:
                    self.app.telemetry.drop_conn(_conn_key(removed))
                except Exception:
                    pass
                try:
                    upstream.discard_upstream_conns(removed)
                except Exception:
                    pass
                try:
                    quic_upstream.discard_upstream(removed)
                except Exception:
                    pass
                return self._send(200, {"ok": True})
            # v1.9.74 P2-7: 字段白名单 + proto 枚举校验, 禁止改 id / 灌入任意字段
            # (防误改内部字段如 latency_measured/健康检查状态, 或注入非法 proto)。
            _UPSTREAM_WHITELIST = {"name", "proto", "addr", "url", "port",
                                   "enabled", "latency", "group", "weight",
                                   "allow_private_ip",
                                   # R12 P2: R8 新增的 DoH/DoT 上游级证书校验 kill switch
                                   # (upstream.py:884/1196 读取), 此前仅可经 bulk PUT /api/config
                                   # 写入; 单条编辑表单提交时字段被白名单静默丢弃。与
                                   # allow_private_ip 同型(bool 归一)补齐, 消除 API 表面不一致。
                                   "doh_strict_cert", "dot_strict_cert"}
            # P2-18: 删除函数内重复的 _ALLOWED_PROTO, 统一用模块级
            # _ALLOWED_UPSTREAM_PROTO(与 POST 新建/parse_upstream_addr 同源), 防漂移。
            # P2-1: 先完整校验+归一化 body(只算到局部 updates, 不碰 cfg), 全部通过后
            # 再统一写回 ups[idx] + save_config。避免此前"边写边校"在第 N 个字段非法时
            # 已把前 N-1 个字段写进内存 cfg 却未落盘, 造成内存/磁盘分叉。
            updates = {}
            for k, v in body.items():
                if k == "id":
                    return self._send(400, {"error": "不允许修改上游 id"})
                if k not in _UPSTREAM_WHITELIST:
                    return self._send(400, {"error": "非法字段: %s (允许: %s)" % (
                        k, ",".join(sorted(_UPSTREAM_WHITELIST)))})
                if k in ("port", "latency"):
                    # R6 P3-2: 显式排除 bool(True/False 是 int 子类), 与 bulk
                    # _validate_upstream_dict 内 latency 已确立的纪律对齐。
                    if isinstance(v, bool):
                        return self._send(400, {"error": "%s 不允许是布尔值" % k})
                    try:
                        v = int(v)
                    except (TypeError, ValueError):
                        return self._send(400, {"error": "%s 必须是整数" % k})
                # R18 P3-5: weight 与 bulk _validate_upstream_dict 对齐——允许 int/float
                # (weight 用于加权轮询, float 有意义), 排除 bool, 不再强制 int 转换。
                # 此前 PUT 路径把 weight 和 port/latency 一起 int(v) 截断 float,
                # 而 bulk 路径允许 float, 两路径行为不一致。
                if k == "weight":
                    if isinstance(v, bool) or not isinstance(v, (int, float)):
                        return self._send(400, {"error": "weight 必须是数字 (不能是布尔值)"})
                    if not (0 <= v <= 1000):
                        return self._send(400, {"error": "weight 必须在 0-1000 之间 (got %r)" % (v,)})
                # P2-5: 上游 port 范围校验(嵌套 port 不被顶层 _NUM_RANGES 覆盖)
                if k == "port" and not (1 <= v <= 65535):
                    return self._send(400, {"error": "port 必须在 1-65535 之间 (got %d)" % v})
                # v7 P2-1: latency 此前只做 int() 转换未做范围校验, 非法值(负数/
                # 超大)可直接透传落库。latency 0-3600000ms。
                if k == "latency" and not (0 <= v <= 3600000):
                    return self._send(400, {"error": "latency 必须在 0-3600000 ms 之间 (got %d)" % v})
                if k == "enabled":
                    v = _as_bool(v, True)
                if k == "allow_private_ip":
                    v = _as_bool(v, False)
                # R12 P2: doh_strict_cert/dot_strict_cert 与 allow_private_ip 同型,
                # 宽松 bool 归一(字符串 "true"/"1" → True, 默认 False 保持兼容)。
                if k in ("doh_strict_cert", "dot_strict_cert"):
                    v = _as_bool(v, False)
                if k == "proto" and str(v).lower() not in _ALLOWED_UPSTREAM_PROTO:
                    return self._send(400, {"error": "proto 必须是 %s 之一" % "/".join(sorted(_ALLOWED_UPSTREAM_PROTO))})
                # P3-2(R4-S6): addr 字符集校验——复用 _valid_host, 拒绝含空格/分号/引号等
                # 危险字符的 addr, 防命令注入/日志注入。与 POST /api/upstreams 手动分支对齐。
                if k == "addr":
                    if not isinstance(v, str) or not _valid_host(v):
                        return self._send(400, {"error": "非法 addr: %r (仅允许 IPv4/IPv6/主机名字符集)" % (v,)})
                # P3-2(R4-S6): url 不允许含控制字符, 防日志注入/协议混淆。
                # R5: 统一调用 _valid_url_path() 与其余三条路径对齐(含 0x7F DEL 拒绝)。
                if k == "url":
                    if not _valid_url_path(v):
                        return self._send(400, {"error": "非法 url: 不允许包含控制字符"})
                # R16 P3-1 / R18 P3-1: name 长度上限 256 + 类型校验, 与 bulk
                # _validate_upstream_dict / POST 新建对齐。此前单条 PUT 上游编辑
                # 缺类型校验, 传 {"name": 123} 会落成非字符串类型。
                if k == "name":
                    if not isinstance(v, str):
                        return self._send(400, {"error": "name 必须是字符串"})
                    if len(v) > 256:
                        return self._send(400, {"error": "name 过长 (上限 256 字符)"})
                # R18 P3-2: group 类型校验——提供时必须为 str, 与 POST 新建/bulk
                # _validate_upstream_dict 对齐。此前 PUT 单条编辑遗漏 group 类型校验。
                if k == "group" and v is not None and not isinstance(v, str):
                    return self._send(400, {"error": "group 必须是字符串"})
                updates[k] = v
            # R15 P2: 先快照旧端点, 端点字段(proto/addr/port/url)变更后用于回收
            # 旧端点的连接池/conn_stats/QUIC。此前单条 PUT 漏回收, 与 DELETE/bulk PUT/
            # reload 三条已硬化写路径不一致, 导致旧连接池条目与连接维度遥测残留。
            old_up = dict(ups[idx])
            # R23 P2-1: 原子引用交换取代原地 ups[idx][k]=v。GET /api/upstreams 的
            # _upstreams_with_health() 在锁外做 {**u} 浅拷贝, 原地给 dict 加新 key(如
            # weight)会触发 dict 扩容 → 并发迭代 RuntimeError: dictionary changed size
            # during iteration(GET 偶发 500/断连)。先以 old_up 快照为底, updates 覆盖后
            # 整体替换 ups[idx] 引用, GET 侧 {**u} 要么读到旧引用要么读到新引用, 不在迭代
            # 中途遇 dict 扩容; 与代码库原子引用交换 / cfg 整体发布模式对齐。必须在
            # save_config 之前完成引用交换, 且下方端点变更回收仍基于 old_up 快照。
            new_up = {**old_up, **updates}
            ups[idx] = new_up
            saved = config_mod.save_config(cfg, self.app.config_path)
            # R26 P3-1: 与 P2-1/DELETE 路径(R25 P3-2)对齐 —— save_config 写盘失败时,
            # 磁盘仍保留旧端点配置。端点变更回收(drop_conn/discard 旧端点连接)必须推迟到
            # 落盘确认之后; 否则 save 失败而旧端点 conn_stats/连接已被回收, 重启后从磁盘
            # 恢复旧端点时连接池为空。影响面小(只清 conn_stats/连接, 不丢上游级
            # per_upstream/_cb 历史统计), 但为一致性先判 saved is False 返回 500 再回收。
            # P1-4: 写盘失败返回 500(运行态已生效, 但重启后丢失)
            if saved is False:
                return self._send(500, {"error": "配置写盘失败（运行态已生效，重启后将丢失）", "ok": False})
            # R15 P2: 端点变更(同 id)只回收旧端点的连接池/conn_stats/QUIC, 保留
            # per_upstream/_cb(上游仍在, 累积健康/熔断统计不丢)。与 reload 端点变更
            # 分支、bulk PUT stale_victims、DELETE 三处已确立的纪律对齐。
            if (str(old_up.get("proto", "")).lower() != str(new_up.get("proto", "")).lower()
                    or old_up.get("addr") != new_up.get("addr")
                    or old_up.get("port") != new_up.get("port")
                    or (old_up.get("url") or "") != (new_up.get("url") or "")):
                try:
                    self.app.telemetry.drop_conn(_conn_key(old_up))
                except Exception:
                    pass
                try:
                    upstream.discard_upstream_conns(old_up)
                except Exception:
                    pass
                try:
                    quic_upstream.discard_upstream(old_up)
                except Exception:
                    pass
            return self._send(200, {"ok": True, "upstream": ups[idx]})

    def _api_import_rules(self):
        """导入分流规则。URL 走规则订阅(独立文件 rules_sub.json, 卡片只显示链接);
        直接粘贴域名列表走逐条规则(独立文件 rules_local.json, 卡片展开显示)。
        body: {url|content, action, group, wildcard, ip}
        """
        body = self._read_json()
        if body is _SENTINEL:
            return
        body = body or {}
        # P2-2(R4-S4): url/content 必须是字符串, 数字/数组/对象时 .strip() 抛异常。
        # 显式 isinstance 校验, 非法类型直接 400。
        src = body.get("url")
        if src is not None and not isinstance(src, str):
            return self._send(400, {"error": "url must be a string"})
        src = (src or "").strip()
        if src:
            # URL → 规则订阅通道: 明细不写入 config.json
            return self._api_subscribe_rules_body(body)
        text = body.get("content")
        if text is not None and not isinstance(text, str):
            return self._send(400, {"error": "content must be a string"})
        text = text or ""
        domains = _parse_domain_list(text)
        if not domains:
            return self._send(400, {"error": "未解析到有效域名"})
        action = body.get("action") or "group"
        # P2-2/F2: 走公共校验——action 枚举 + forceIp 时 ip 格式。
        # 批量导入是单一 action/ip 应用到全部域名, 非法即整体 400 拒绝。
        # R19 P2-2: 补 group 类型校验——导入路径此前不经过 _validate_rule_dict 的
        # group 检查(R18 P3-3 已加), {"group": 123} 穿透 `or "global"` 落库成死规则。
        verr = _validate_rule_dict({"action": action, "ip": body.get("ip"),
                                    "group": body.get("group")})
        if verr:
            return self._send(400, {"error": verr})
        group = body.get("group") or "global"
        # P1-5: wildcard 必须用 _as_bool 解析, 否则字符串 "false"/"0" 被裸
        # bool() 判为 True, 与前端语义不一致。
        wildcard = _as_bool(body.get("wildcard", True), True)
        # 读改写全程持 app._lock: 并发导入/加规则时, 两线程同时读到旧规则集
        # 各自 append 后落盘会互相覆盖静默丢规则(与上游 CRUD 加锁范式对齐)。
        with self.app._lock:
            rules = self._local_rules()
            existing = {r.get("match") for r in rules}
            added = 0
            for d in domains:
                m = d
                is_advanced = d.startswith("re:")
                if wildcard and not d.startswith("*.") and not is_advanced:
                    m = "*." + d
                if m in existing:
                    continue
                r = {"id": _new_id("r"), "match": m, "action": action}
                if action == "group":
                    r["group"] = group
                elif action == "forceIp":
                    r["ip"] = body.get("ip") or "1.2.3.4"
                rules.append(r)
                existing.add(m)
                added += 1
            saved_rules_ok = True
            idx_ok, idx_err = True, ""
            if added:
                # R2-P1: 直接检查 bool 成功/失败
                saved_rules_ok = self._save_local_rules(rules)
                # P3-1(R3): 写盘失败时跳过 rebuild(从磁盘重载旧索引是无意义 I/O)
                if saved_rules_ok:
                    idx_ok, idx_err = self._rebuild_rule_index_timed()
                else:
                    idx_ok, idx_err = True, ""
            if added and not saved_rules_ok:
                return self._send(500, {"error": "规则写盘失败（运行态已生效，重启后将丢失）", "ok": False})
            if not idx_ok:
                return self._send(500, {"ok": False, "error": "规则索引重建失败", "detail": idx_err})
            return self._send(200, {"added": added, "total": len(rules)})

    def _do_subscribe_download(self, url, action, group, ip):
        """P2-11: 订阅下载公共逻辑(供 _api_subscribe_rules_body 与 _api_subscribe_rules 复用)。
        下载订阅 → 解析域名 → 持锁写 rules_sub.json → 写 config 元信息 → 重建规则索引。
        P2-14: 下载阶段用 _SUBSCRIBE_SEM 限制并发(最多 4), 防止同步网络 I/O 耗尽
        ThreadingHTTPServer 的 256 线程槽位。
        P1-4/P1-6: 保存与索引重建失败返回 500。
        返回 (http_code, body_dict), 由调用方 self._send。"""
        # P2-14: 同步下载(最长 20s)放在信号量内
        try:
            with _SUBSCRIBE_SEM:
                text = self._fetch_sub_text(url)
        except Exception as e:
            return 400, {"error": "订阅下载失败: %s" % e}
        domains = _parse_domain_list(text)
        if not domains:
            return 400, {"error": "订阅内容未解析到有效域名"}
        # #3 订阅 re: 规则: 已带 *. 或已是 re: 正则的域名不加通配前缀(否则 re: 规则被破坏)
        items = [{"match": ("*." + d if not d.startswith(("*.", "re:")) else d)} for d in domains]
        # 读改写全程持 app._lock(网络下载已在锁外完成), 与 _api_update_config/reload
        # 串行化, 防持旧 cfg 引用被并发整体替换后 save_config 静默覆盖丢配置。
        with self.app._lock:
            cfg = self.app.cfg   # 进锁后重新取最新引用
            subs = self._load_subs()
            existed = False
            for s in subs:
                if s.get("url") == url:
                    s["action"], s["group"], s["ip"] = action, group, ip
                    s["rules"] = items
                    s["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                    existed = True
                    break
            if not existed:
                subs.append({"url": url, "action": action, "group": group, "ip": ip,
                             "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"), "rules": items})
            ok, err = self._save_subs(subs)
            if not ok:
                return 500, {"error": "保存订阅文件失败: %s" % err}
            meta = cfg.setdefault("rule_subscriptions", [])
            for m in meta:
                if m.get("url") == url:
                    m.update({"action": action, "group": group, "ip": ip, "count": len(items),
                              "updated_at": time.strftime("%Y-%m-%d %H:%M:%S")})
                    break
            else:
                meta.append({"url": url, "action": action, "group": group, "ip": ip,
                             "count": len(items), "updated_at": time.strftime("%Y-%m-%d %H:%M:%S")})
            # P1-4: 检查配置写盘返回值
            saved = config_mod.save_config(cfg, self.app.config_path)
            if saved is False:
                return 500, {"error": "配置写盘失败（运行态已生效，重启后将丢失）", "ok": False}
            # P1-6/P2-13: 带耗时的索引重建
            idx_ok, idx_err = self._rebuild_rule_index_timed()
        if not idx_ok:
            return 500, {"ok": False, "error": "规则索引重建失败", "detail": idx_err}
        return 200, {"ok": True, "url": url, "count": len(items), "added": 0 if existed else 1}

    def _api_subscribe_rules_body(self, body):
        """订阅 body 处理(供 /api/rules/import url 复用): 委托公共下载逻辑。"""
        url = (body.get("url") or "").strip()
        action = body.get("action") or "block"
        group = body.get("group") or "global"
        ip = body.get("ip") or "1.2.3.4"
        # v1.9.74 P2-10: 规则订阅只允许 https://(明文 http 可被中间人篡改规则注入)
        if not url.lower().startswith("https://"):
            return self._send(400, {"error": "仅支持 https:// 订阅链接(http:// 不安全, 已禁止)"})
        # P2-2/F2: action 枚举 + forceIp 时 ip 格式。在下载前校验, 避免为非法值白下载。
        # R19 P2-2: 补 group 类型校验——订阅 body 路径此前不经过 _validate_rule_dict 的
        # group 检查(R18 P3-3 已加), {"group": 123} 穿透 `or "global"` 落库成死规则。
        verr = _validate_rule_dict({"action": action, "ip": ip, "group": group})
        if verr:
            return self._send(400, {"error": verr})
        code, resp = self._do_subscribe_download(url, action, group, ip)
        if code == 200:
            resp["subscribed"] = True
        return self._send(code, resp)

    def _api_add_rule(self):
        body = self._read_json()
        if body is _SENTINEL:
            return
        body = body or {}
        # 兼容旧字段名 pattern→match / value→group|ip (与 resolver._normalize_rule 一致)。
        # 原实现只读 body.get("match")/get("ip"), 旧客户端用 pattern/value 提交时:
        #   pattern 被丢弃 → match 落成默认 "*.example.com";
        #   value   被丢弃 → ip/group 落成空值。
        # 用户意图的域名与目标 IP 丢失, 还会误建一条影响所有 *.example.com 的全局规则。
        if isinstance(body, dict):
            try:
                self.app.resolver._normalize_rule(body)
            except Exception:
                pass
        # P2-5(R4-S3): 畸形 JSON 被 _read_json 吞成 None → `or {}` 变空 dict, 然后用
        # 默认 match="*.example.com" 静默创建规则。要求必须提供 match 字段且为字符串,
        # 消除"空请求静默创建资源"。
        match = body.get("match")
        if not match or not isinstance(match, str):
            return self._send(400, {"error": "match is required and must be a string"})
        action = body.get("action") or "group"
        r = {
            "id": _new_id("r"),
            "match": match,
            "action": action,
            "group": body.get("group") or "domestic",
            "ip": body.get("ip") or "",
        }
        # 公共校验: action 枚举 + forceIp 时 ip 格式(校验对象即即将落库的 r)。
        verr = _validate_rule_dict(r)
        if verr:
            return self._send(400, {"error": verr})
        # R19 P3-1: 移除不可达的 match 4096 字节死代码——_validate_rule_dict 已在上方
        # 统一校验 match ≤4096 字节(R18 P3-4), 此处重复检查永不命中, 徒增漂移面。
        # P3-5(R4-F5): 非法正则编译失败静默落库。match 以 re: 开头时预编译正则,
        # 编译失败直接 400, 避免落库一条永不命中且报错难以定位的死规则。
        # R28 P2-1: 抽取为 _check_rule_regex 公共函数, 与单条 PUT/bulk 路径共用。
        rerr = _check_rule_regex(r["match"])
        if rerr:
            return self._send(400, {"error": rerr})
        # 规则级 TTL 透传(可选): 命中规则时覆盖全局 ttl_min/ttl_max
        ttl_min = body.get("ttl_min")
        ttl_max = body.get("ttl_max")
        for k in ("ttl_min", "ttl_max"):
            v = body.get(k)
            if v is not None and v != "":
                # R2-P2-17: bool 是 int 子类, int(True)==1 会穿透到合法值。
                # PUT /api/rules/<id> 已修复, POST /api/rules 新增路径漏了同样检查。
                if isinstance(v, bool):
                    return self._send(400, {"error": "%s 必须是非负整数，不能是布尔值" % k})
                try:
                    r[k] = max(0, int(v))
                except (TypeError, ValueError):
                    # v7 P3-3: 此前非法值静默丢弃(pass), 与 PUT 路径(返回 400)不一致,
                    # 手构造 body 可注入 "abc"/null 类值而不报错。对齐 PUT 路径返回 400。
                    return self._send(400, {"error": "%s 必须是非负整数" % k})
        # P3-6(R4-F6): ttl_min > ttl_max 无校验。两者都提供时检查顺序, 非法直接 400。
        if "ttl_min" in r and "ttl_max" in r and r["ttl_min"] > r["ttl_max"]:
            return self._send(400, {"error": "ttl_min 不能大于 ttl_max"})
        # 读改写全程持 app._lock, 防并发加规则互相覆盖静默丢失(同 _api_import_rules)。
        with self.app._lock:
            rules = self._local_rules()
            rules.append(r)
            # R2-P1: 直接检查 bool 成功/失败
            saved_rules_ok = self._save_local_rules(rules)
            # P1-6/P2-13: 带耗时的索引重建, 失败返回 500
            # P3-4(R4): 规则写盘失败时跳过 rebuild —— 磁盘上仍是旧规则(未含本次新增),
            # 从旧文件全量重建索引无意义且持锁数百ms, 与 import/DELETE/PUT/update_config 对齐。
            if saved_rules_ok:
                idx_ok, idx_err = self._rebuild_rule_index_timed()
            else:
                idx_ok, idx_err = True, ""
        # R2-P1: 规则写盘失败
        if not saved_rules_ok:
            return self._send(500, {"error": "规则写盘失败（运行态已生效，重启后将丢失）", "ok": False})
        # P1-6: 索引重建失败
        if not idx_ok:
            return self._send(500, {"ok": False, "error": "规则索引重建失败", "detail": idx_err})
        return self._send(200, {"ok": True, "rule": r})

    # ---- 逐条规则(独立文件 rules_local.json, 不写入 config.json) ----
    def _local_rules(self, persist=True):
        """读逐条规则独立文件; 文件不存在时回退 cfg['rules'](旧 config 迁移期兼容), 并惰性迁移。
        P0-2: 配置文件迁移来的历史规则没有 id 字段, 而 DELETE/PUT /api/rules/{id}
        按 id 定位。这里对缺 id 的规则惰性补一个稳定 id 并落盘, 保证列表展示与
        按 id 删除/编辑都可用, 不再触发 KeyError: 'id'。
        P3: GET 只读路径(persist=False)不触发写盘 —— 否则一次只读 GET 会在锁外改写
        rules_local.json, 与持锁的写操作竞争"后写覆盖"。id 按 enumerate 序号稳定生成,
        补 id 不落盘也不影响后续 PUT/DELETE 定位。"""
        lr = config_mod.load_local_rules(self.app.config_path)
        if lr is None:
            rules = list(self.app.cfg.get("rules", []))
        else:
            rules = lr
        changed = False
        for i, r in enumerate(rules):
            if isinstance(r, dict) and not r.get("id"):
                r["id"] = "rmig%d" % (i + 1)
                changed = True
        if changed and persist:
            # P3-4(第七轮): 迁移(补 id)这步写盘不额外包 try/except 再打一层 WARNING ——
            # 本函数的 persist=True 调用方(POST/PUT/DELETE 规则)随后都会正式
            # _save_local_rules(rules) 保存同一文件; 若正式保存也失败会在该处(500)告警。
            # P3-4(第八轮)注释勘误: 此前注释称"迁移写盘失败时静默", 与实际不符——
            # 下方 config_mod.save_local_rules 内部失败时仍会 logging.warning(见 config.py),
            # 本 wrapper 只是不再叠加第二层告警(避免同一文件连打两条 WARNING)。
            self._save_local_rules(rules)
        return rules

    def _save_local_rules(self, rules):
        # R2-P1: 返回 bool 成功/失败(save_local_rules 成功=True, 失败=False)。
        # 旧实现返回写入条数, 空规则成功=0 与写盘失败=0 无法区分,
        # 调用方 `saved_cnt==0 and len(rules)>0` 兜底导致清空规则时写失败被静默吞掉。
        # 现在直接返回 bool, 空规则写成功=True, 写失败=False, 语义明确。
        return config_mod.save_local_rules(rules, self.app.config_path)

    # ---- 规则订阅(独立文件 rules_sub.json, 不写入 config.json) ----
    def _sub_file(self):
        return self.app.cfg.get("rule_sub_file") or config_mod.sub_rules_path(self.app.config_path)

    def _load_subs(self):
        try:
            with open(self._sub_file(), encoding="utf-8") as f:
                subs = json.load(f).get("subscriptions", [])
        except FileNotFoundError:
            subs = []
        except Exception as e:
            # R2-P3: 订阅文件损坏/读失败时打 WARNING, 不再静默吞掉。
            # 与 config.load_local_rules 的告警风格对齐, 方便运维发现文件损坏。
            log.warning("订阅规则文件读取失败 %s: %r, 按空列表处理", self._sub_file(), e)
            subs = []
        # 与 config 元信息对齐: config 中已有但独立文件缺失的订阅补空明细
        # (升级 / 文件丢失场景), 保证前端列表与"更新"按钮不丢订阅
        meta = {m.get("url"): m for m in self.app.cfg.get("rule_subscriptions", [])}
        have = {s.get("url") for s in subs}
        for url, m in meta.items():
            if url and url not in have:
                subs.append({
                    "url": url,
                    "action": m.get("action", "block"),
                    "group": m.get("group", "global"),
                    "ip": m.get("ip") or "1.2.3.4",
                    "count": m.get("count", 0),
                    "updated_at": m.get("updated_at", ""),
                    "rules": [],
                })
        return subs

    def _save_subs(self, subs):
        """原子写订阅独立文件。返回 (ok, error_msg); 调用方据此回 500 并透出真实原因。"""
        path = self._sub_file()
        # R37 P3-1: tmp 提到 try 外, 与 save_config(R36 P3-2) 同型, 便于 except 分支清理残留 .tmp
        tmp = path + ".tmp"
        try:
            d = os.path.dirname(os.path.abspath(path)) or "."
            os.makedirs(d, exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"subscriptions": subs}, f, ensure_ascii=False)
                f.flush()
                # P3-2(R5): 与 config.save_config/save_local_rules、cli._save_cache
                # 持久性承诺对齐, rename 前 fsync 文件内容, 防掉电丢订阅明细。
                # save 非热路径, 不影响 QPS。
                os.fsync(f.fileno())
            os.replace(tmp, path)
            return True, ""
        except Exception as e:
            # R37 P3-1: 原子写失败(如 os.replace 跨设备/只读/磁盘满)时清理残留 .tmp,
            # 与 save_config(R36 P3-2) 同型。open 失败时 tmp 可能不存在,
            # exists 判断 + 内层 try/except 保证清理自身不抛错。
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass
            msg = "%s: %s" % (path, e)
            log.warning("保存订阅文件失败 %s", msg)
            return False, msg

    def _rules_with_subs(self):
        """GET /api/rules: 逐条规则 + 订阅源元信息(只显示链接/规则数/更新时间, 不展开明细)。
        订阅列表以独立文件 rules_sub.json 实际内容为准(与 config.json 元信息自动对齐)。"""
        cfg = self.app.cfg
        meta = {m.get("url"): m for m in cfg.get("rule_subscriptions", [])}
        subs = []
        for s in self._load_subs():
            m = meta.get(s.get("url"), {})
            subs.append({
                "url": s.get("url", ""),
                "action": s.get("action") or m.get("action", "block"),
                "group": s.get("group") or m.get("group", ""),
                "ip": s.get("ip") or m.get("ip", ""),
                "count": len(s.get("rules") or []),
                "updated_at": s.get("updated_at") or m.get("updated_at", ""),
            })
        # P3: GET /api/rules 纯读, 不触发惰性补 id 落盘。
        return {"rules": self._local_rules(persist=False), "subscriptions": subs}

    def _fetch_sub_text(self, url):
        # 共享实现: SSRF 初始校验 + 每跳重定向复检 + 16MB 流式上限(见 fetch_subscription_text)
        return fetch_subscription_text(url, timeout=20)

    def _api_subscribe_rules(self):
        """POST /api/rules/subscribe {url, action, group, ip}: 添加规则订阅。
        委托 _do_subscribe_download 公共逻辑(P2-11 去重)。"""
        body = self._read_json()
        if body is _SENTINEL:
            return
        body = body or {}
        # P2-3(R4-S5): url 必须是字符串, 数字/数组时 .strip() 抛异常。
        url = body.get("url")
        if not isinstance(url, str):
            return self._send(400, {"error": "url must be a string"})
        url = url.strip()
        # v1.9.74 P2-10: 规则订阅只允许 https://(明文 http 可被中间人篡改规则注入)
        if not url or not url.lower().startswith("https://"):
            return self._send(400, {"error": "仅支持 https:// 订阅链接(http:// 不安全, 已禁止)"})
        action = body.get("action") or "block"
        group = body.get("group") or "global"
        ip = body.get("ip") or "1.2.3.4"
        # P2-2/F2: action 枚举 + forceIp 时 ip 格式(下载前校验, 避免白下载)。
        # R19 P2-2: 补 group 类型校验——订阅 rules 路径此前不经过 _validate_rule_dict 的
        # group 检查(R18 P3-3 已加), {"group": 123} 穿透 `or "global"` 落库成死规则。
        verr = _validate_rule_dict({"action": action, "ip": ip, "group": group})
        if verr:
            return self._send(400, {"error": verr})
        code, resp = self._do_subscribe_download(url, action, group, ip)
        return self._send(code, resp)

    def _api_subscribe_update(self):
        """POST /api/rules/subscribe/update {url}: 重新拉取订阅并覆盖明细。"""
        body = self._read_json()
        if body is _SENTINEL:
            return
        body = body or {}
        # P2-3(R4-S5): url 必须是字符串, 数字/数组时 .strip() 抛异常。
        url = body.get("url")
        if not isinstance(url, str):
            return self._send(400, {"error": "url must be a string"})
        url = url.strip()
        # P2-3: 删除锁外存在性预检。此前先锁外判存在再锁外下载(最长 20s), 若下载期间
        # 另一线程删除了该订阅, 已为一个即将不存在的订阅白白完成一次完整下载。直接下载,
        # 进锁后由下方 target 判空兜底返回 404(与其它订阅端点范式一致)。
        # P2-14: 同步下载在信号量内, 限制并发订阅下载数。
        try:
            with _SUBSCRIBE_SEM:
                text = self._fetch_sub_text(url)
        except Exception as e:
            return self._send(400, {"error": "订阅更新失败: %s" % e})
        domains = _parse_domain_list(text)
        if not domains:
            return self._send(400, {"error": "订阅内容未解析到有效域名"})
        # 读改写全程持 app._lock(下载在锁外), 进锁后重新取 subs/cfg 最新引用。
        with self.app._lock:
            subs = self._load_subs()
            target = next((s for s in subs if s.get("url") == url), None)
            if not target:
                return self._send(404, {"error": "订阅不存在: %s" % url})
            # #3 订阅刷新同样保护 re: 规则不被加通配前缀
            target["rules"] = [{"match": ("*." + d if not d.startswith(("*.", "re:")) else d)} for d in domains]
            target["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            ok, err = self._save_subs(subs)
            if not ok:
                return self._send(500, {"error": "保存订阅文件失败: %s" % err})
            cfg = self.app.cfg
            for m in cfg.setdefault("rule_subscriptions", []):
                if m.get("url") == url:
                    m["count"] = len(domains)
                    m["updated_at"] = target["updated_at"]
                    break
            # P1-4: 检查配置写盘返回值
            saved = config_mod.save_config(cfg, self.app.config_path)
            if saved is False:
                return self._send(500, {"error": "配置写盘失败（运行态已生效，重启后将丢失）", "ok": False})
            # P1-6/P2-13: 带耗时的索引重建
            idx_ok, idx_err = self._rebuild_rule_index_timed()
        if not idx_ok:
            return self._send(500, {"ok": False, "error": "规则索引重建失败", "detail": idx_err})
        return self._send(200, {"ok": True, "url": url, "count": len(domains)})

    def _api_subscribe_delete(self, query):
        """DELETE /api/rules/subscribe?url=...: 移除订阅(明细与元信息一并删除)。"""
        # P2-2: 前端 encodeURIComponent 编码一次 → parse_qs 已自动解码一次, 此处再
        # unquote 是双重解码, 含字面 '%' 的订阅 URL 会被错误二次解码导致匹配失败。
        # 直接用 parse_qs 解码后的值, 不再二次 unquote。
        url = (query.get("url") or [""])[0].strip()
        if not url:
            return self._send(400, {"error": "缺少 url 参数"})
        # 读改写全程持 app._lock, 进锁后重新取 subs/cfg 最新引用。
        with self.app._lock:
            subs = self._load_subs()
            n = len(subs)
            subs = [s for s in subs if s.get("url") != url]
            if len(subs) == n:
                return self._send(404, {"error": "订阅不存在: %s" % url})
            ok, err = self._save_subs(subs)
            if not ok:
                return self._send(500, {"error": "保存订阅文件失败: %s" % err})
            cfg = self.app.cfg
            cfg["rule_subscriptions"] = [m for m in cfg.get("rule_subscriptions", []) if m.get("url") != url]
            # P1-4: 检查配置写盘返回值
            saved = config_mod.save_config(cfg, self.app.config_path)
            if saved is False:
                return self._send(500, {"error": "配置写盘失败（运行态已生效，重启后将丢失）", "ok": False})
            # P1-6/P2-13: 带耗时的索引重建
            idx_ok, idx_err = self._rebuild_rule_index_timed()
        if not idx_ok:
            return self._send(500, {"ok": False, "error": "规则索引重建失败", "detail": idx_err})
        return self._send(200, {"ok": True, "url": url})

    def _api_rule_op(self, rid):
        # #1 [严重]: 同样把 body 读取移出 app._lock, 避免持锁期间阻塞读 socket。
        # R16 P3-4: 同 _api_upstream_op —— handler 无 do_PATCH, PATCH 到不了 _route(),
        # 原 ("PUT","PATCH") 判定为死代码; 单条 PUT 已是部分更新语义, 移除 PATCH 分支。
        if self.command == "PUT":
            body = self._read_json()
            if body is _SENTINEL:
                return
            body = body or {}
        else:
            body = {}
        # 读改写全程持 app._lock: 与 add/import 串行化, 防并发改删规则基于陈旧快照
        # 互相覆盖(同上游 CRUD)。
        with self.app._lock:
            rules = self._local_rules()
            # P0-2: 用 .get("id") 防御——_local_rules 已为迁移规则补 id,
            # 但直接索引 r["id"] 遇无 id 规则仍会抛 KeyError 导致连接重置。
            idx = next((i for i, r in enumerate(rules) if isinstance(r, dict) and (r.get("id") or "") == rid), None)
            if idx is None:
                return self._send(404, {"error": "rule not found"})
            if self.command == "DELETE":
                rules.pop(idx)
                # R2-P1: 直接检查 bool 成功/失败(删除后可能为空列表)
                saved_rules_ok = self._save_local_rules(rules)
                # P3-1(R3): 写盘失败时跳过 rebuild(从磁盘重载旧索引是无意义 I/O)
                if saved_rules_ok:
                    idx_ok, idx_err = self._rebuild_rule_index_timed()
                else:
                    idx_ok, idx_err = True, ""
                if not saved_rules_ok:
                    return self._send(500, {"error": "规则写盘失败（运行态已生效，重启后将丢失）", "ok": False})
                if not idx_ok:
                    return self._send(500, {"ok": False, "error": "规则索引重建失败", "detail": idx_err})
                return self._send(200, {"ok": True})
            # P3: 字段白名单(与上游 PUT 硬化对齐), 禁止把任意键灌进 rules_local.json;
            # ttl_min/ttl_max 归一为非负整数; match 不允许清空。
            _RULE_WHITELIST = {"match", "action", "group", "ip", "ttl_min", "ttl_max"}
            # P2-1: 先完整校验+归一化(只算到局部 updates/to_pop, 不碰 rules[idx]),
            # 全部通过后再统一写回 + _save_local_rules。避免边写边校在第 N 个字段非法
            # 时已 pop/改了前 N-1 个字段, 造成内存 rules 与磁盘分叉。
            updates = {}
            to_pop = set()
            for k, v in body.items():
                # P2-12: 与上游 PUT 对齐——body 含 id 字段直接 400, 不再静默忽略。
                if k == "id":
                    return self._send(400, {"error": "不允许修改规则 id"})
                if k not in _RULE_WHITELIST:
                    return self._send(400, {"error": "非法规则字段: %s (允许: %s)" % (
                        k, ",".join(sorted(_RULE_WHITELIST)))})
                if v is None:
                    # R16 P3-2: match 是规则必填键, 不允许以 null 移除/清空——此前
                    # 通用 null→to_pop 分支让 match:null 绕过下方"match 不能为空"校验,
                    # 最终 merged 缺 match 键落库成死规则。其余字段(ttl_min/ttl_max 等)
                    # null 语义仍是移除该字段, 保持原行为。
                    if k == "match":
                        return self._send(400, {"error": "match 不能为空"})
                    # null 语义 = 移除该字段(如规则 ttl_min/ttl_max 留空), 避免 config 残留 null
                    to_pop.add(k)
                    continue
                # R17 P3-2: match 必须为 str 类型——此前用 str(v).strip() 把 int 123
                # 转成 "123" 穿透校验, 落成 int 死规则(后续字符串匹配永不命中)。
                # 与 bulk _validate_rule_dict 的 match 类型校验对齐。
                if k == "match" and not isinstance(v, str):
                    return self._send(400, {"error": "match 必须是字符串"})
                if k in ("ttl_min", "ttl_max"):
                    # P2-17: bool 是 int 子类, int(True)==1 会穿透到合法值。
                    # 显式拒绝布尔, 与上游 weight/latency 的 bool 校验对齐。
                    if isinstance(v, bool):
                        return self._send(400, {"error": "%s 必须是非负整数，不能是布尔值" % k})
                    try:
                        v = max(0, int(v))
                    except (TypeError, ValueError):
                        return self._send(400, {"error": "%s 必须是非负整数" % k})
                if k == "match" and not str(v).strip():
                    return self._send(400, {"error": "match 不能为空"})
                # v7 P3-2: match 字段长度上限 4096 字节, 防止超大正则/字符串落库膨胀索引
                if k == "match" and len(str(v).encode("utf-8")) > 4096:
                    return self._send(400, {"error": "match 字段过长 (上限 4096 字节)"})
                # action 枚举校验(与 resolver 分流逻辑一致): 未知 action 静默落库
                # 后既不分流也不报错, 与上游 PUT 的 proto 枚举硬化对齐。
                if k == "action" and v not in _RULE_ACTIONS:
                    return self._send(400, {"error": "非法 action: %r (允许: %s)" % (
                        v, "/".join(_RULE_ACTIONS))})
                updates[k] = v
            # F2: 应用前按合并后的最终规则态校验(action 枚举 + forceIp 时 ip 格式),
            # 覆盖"只改 ip"或"只把 action 改成 forceIp"的部分更新场景。
            merged = {k: v for k, v in rules[idx].items() if k not in to_pop}
            merged.update(updates)
            verr = _validate_rule_dict(merged)
            if verr:
                return self._send(400, {"error": verr})
            # P3-5(R4-F5): 非法正则编译失败静默落库。match 以 re: 开头时预编译正则,
            # 编译失败直接 400, 避免落库一条永不命中且报错难以定位的死规则。
            # R28 P2-1: 抽取为 _check_rule_regex 公共函数, 与单条 POST/bulk 路径共用。
            _merr = _check_rule_regex(merged.get("match", ""))
            if _merr:
                return self._send(400, {"error": _merr})
            # P3-6(R4-F6): ttl_min > ttl_max 无校验。两者都提供时检查顺序, 非法直接 400。
            _tmin = merged.get("ttl_min")
            _tmax = merged.get("ttl_max")
            if _tmin is not None and _tmax is not None and _tmin > _tmax:
                return self._send(400, {"error": "ttl_min 不能大于 ttl_max"})
            for k in to_pop:
                rules[idx].pop(k, None)
            rules[idx].update(updates)
            # R2-P1: 直接检查 bool 成功/失败
            saved_rules_ok = self._save_local_rules(rules)
            # P3-1(R3): 写盘失败时跳过 rebuild(从磁盘重载旧索引是无意义 I/O)
            if saved_rules_ok:
                idx_ok, idx_err = self._rebuild_rule_index_timed()
            else:
                idx_ok, idx_err = True, ""
            if not saved_rules_ok:
                return self._send(500, {"error": "规则写盘失败（运行态已生效，重启后将丢失）", "ok": False})
            if not idx_ok:
                return self._send(500, {"ok": False, "error": "规则索引重建失败", "detail": idx_err})
            return self._send(200, {"ok": True, "rule": rules[idx]})

    def _logs(self, query):
        """实时查询日志接口, 支持过滤参数:
        since     增量游标(seq)
        q         全局关键字(匹配 域名/IP/上游/解析值/规则/消息)
        level     hit/miss/rule/err/sys/warn
        qtype     A/AAAA/MX...
        ip        客户端 IP 包含
        domain    域名包含
        upstream 上游包含
        rule     规则包含
        min_lat   响应时间下限(ms)
        """
        try:
            since = int((query.get("since") or ["0"])[0])
        except (ValueError, TypeError):
            since = 0
        # P2-16: 走 telemetry.events_snapshot() 加锁拷贝, 不再直接访问私有 tm._lock。
        tm = self.app.telemetry
        snap = tm.events_snapshot()
        events = [e for e in snap if e.get("seq", 0) > since]
        q = (query.get("q") or [""])[0].strip().lower()
        level = (query.get("level") or [""])[0].strip().lower()
        qtype = (query.get("qtype") or [""])[0].strip().upper()
        ipf = (query.get("ip") or [""])[0].strip().lower()
        dmf = (query.get("domain") or [""])[0].strip().lower()
        upf = (query.get("upstream") or [""])[0].strip().lower()
        rlf = (query.get("rule") or [""])[0].strip().lower()
        try:
            min_lat = float((query.get("min_lat") or ["0"])[0])
        except (ValueError, TypeError):
            min_lat = 0
        # P3-6(第八轮): API 层条数上限, 防止无参请求把整个环形缓冲全量返回。
        # 默认 500, 上限 2000。
        try:
            limit = int((query.get("limit") or ["500"])[0])
        except (ValueError, TypeError):
            limit = 500
        if limit < 1:
            limit = 500
        if limit > 2000:
            limit = 2000
        if q or level or qtype or ipf or dmf or upf or rlf or min_lat > 0:
            f = []
            for e in events:
                if level and str(e.get("level") or "").lower() != level:
                    continue
                if qtype and str(e.get("qtype") or "").upper() != qtype:
                    continue
                if ipf and ipf not in str(e.get("client_ip") or "").lower():
                    continue
                if dmf and dmf not in str(e.get("domain") or "").lower():
                    continue
                if upf and upf not in str(e.get("upstream") or "").lower():
                    continue
                if rlf and rlf not in str(e.get("rule") or "").lower():
                    continue
                if min_lat > 0 and (e.get("lat") is None or e.get("lat") < min_lat):
                    continue
                if q:
                    hay = " ".join(str(e.get(k) or "") for k in
                                    ("domain", "client_ip", "upstream", "answer", "rule", "msg", "qtype")).lower()
                    if q not in hay:
                        continue
                f.append(e)
            events = f
        # P3-6(第八轮): 对最终 events 做条数上限切片(取最新的 limit 条)。
        if len(events) > limit:
            events = events[-limit:]
        return {"events": events, "total": len(snap),
                # R30 P3-4: 列表推导改生成器+default, 省去中间 list 构造(snap 上限 500 条, 开销可忽略, 仅风格对齐)。
                "next_seq": max((e.get("seq", 0) for e in snap), default=0)}

    def _pipeline(self):
        cfg = self.app.cfg
        # R26 P3-2: 与 R25 P3-1(_upstreams_with_health)对齐 —— 锁外迭代活 upstreams 列表,
        # 并发 POST append / DELETE pop 会改变列表长度, 可能跳过或重复条目(纯展示层瞬时
        # 最终一致性)。入口做一次浅拷贝快照, 迭代期间结构稳定; 元素 dict 引用仍与活配置
        # 共享, 单条 PUT 已由 R23 P2-1 原子引用交换保证不触发 dict 扩容 RuntimeError。
        enabled = [u for u in list(cfg.get("upstreams", [])) if u.get("enabled", True)][:3]
        # P3-10: 上游配置含 addr/port/url 等内部拓扑细节, 本端点面向调试/概览,
        # 脱敏只返回 proto/name/id, 不暴露上游地址与端口(避免内网/上游情报外泄)。
        masked = [{"proto": u.get("proto"), "name": u.get("name"), "id": u.get("id")}
                  for u in enabled]
        return {
            "hook": cfg.get("hook"),
            "map_type": cfg.get("map_type"),
            "cache_size": cfg.get("cache_size"),
            "kernel_direct": cfg.get("kernel_direct"),
            "upstreams": masked,
        }

    # ---------- Prometheus metrics(可观测性) ----------
    def _metrics(self):
        app = self.app
        tel = app.telemetry
        cache = app.resolver.cache
        c, rh, _hr, _qps, _al = tel.counters_snapshot()
        # R36 P3-1: 与 R35 _status()/_snapshot() 同型包裹 cache.size()/capacity,
        # 失败回退 0, 避免未来 cache 内部结构变化导致 /metrics 500 断连。
        try:
            _cache_entries = cache.size()
        except Exception:
            _cache_entries = 0
        try:
            _cache_capacity = cache.capacity
        except Exception:
            _cache_capacity = 0
        lines = [
            "# HELP ebpdns_queries_total 累计查询总数",
            "# TYPE ebpdns_queries_total counter",
            "ebpdns_queries_total %d" % c.get("total", 0),
            "# HELP ebpdns_cache_hits_total 缓存命中数",
            "# TYPE ebpdns_cache_hits_total counter",
            "ebpdns_cache_hits_total %d" % c.get("hit", 0),
            "# HELP ebpdns_cache_misses_total 缓存未命中数",
            "# TYPE ebpdns_cache_misses_total counter",
            "ebpdns_cache_misses_total %d" % c.get("miss", 0),
            "# HELP ebpdns_errors_total 错误数",
            "# TYPE ebpdns_errors_total counter",
            "ebpdns_errors_total %d" % c.get("errors", 0),
            "# HELP ebpdns_upstream_queries_total 上游查询数",
            "# TYPE ebpdns_upstream_queries_total counter",
            "ebpdns_upstream_queries_total %d" % c.get("upstream_queries", 0),
            "# HELP ebpdns_stale_served_total 过期兜底应答数",
            "# TYPE ebpdns_stale_served_total counter",
            "ebpdns_stale_served_total %d" % c.get("stale_served", 0),
            "# HELP ebpdns_hit_rate 命中率",
            "# TYPE ebpdns_hit_rate gauge",
            "ebpdns_hit_rate %s" % round(_hr, 3),
            "# HELP ebpdns_qps 每秒查询数",
            "# TYPE ebpdns_qps gauge",
            "ebpdns_qps %s" % round(_qps, 3),
            "# HELP ebpdns_avg_latency_ms 平均延迟毫秒",
            "# TYPE ebpdns_avg_latency_ms gauge",
            "ebpdns_avg_latency_ms %s" % (round(_al, 3) if _al is not None else 0),
            "# HELP ebpdns_cache_entries 缓存条目数",
            "# TYPE ebpdns_cache_entries gauge",
            "ebpdns_cache_entries %d" % _cache_entries,
            "# HELP ebpdns_cache_capacity 缓存容量",
            "# TYPE ebpdns_cache_capacity gauge",
            "ebpdns_cache_capacity %d" % _cache_capacity,
            "# HELP ebpdns_uptime_seconds 运行秒数",
            "# TYPE ebpdns_uptime_seconds gauge",
            "ebpdns_uptime_seconds %d" % int(time.time() - tel.boot_time),
            "# HELP ebpdns_rule_hits 规则命中统计",
            "# TYPE ebpdns_rule_hits gauge",
        ]
        for k, v in rh.items():
            lines.append('ebpdns_rule_hits{rule="%s"} %d' % (_pl_escape(k), v))
        lines.append("# HELP ebpdns_upstream_health 上游健康度(成功次数, 延迟ms)")
        lines.append("# TYPE ebpdns_upstream_health gauge")
        # H-1: 加锁快照, 避免并发 setdefault 触发 dict changed size
        for uid, st in tel.upstreams_snapshot():
            ok = st.get("ok", 0)
            avg = (st.get("lat_sum", 0) / ok) if ok else 0
            lines.append('ebpdns_upstream_health{upstream="%s",result="ok"} %d' % (_pl_escape(uid), ok))
            lines.append('ebpdns_upstream_health{upstream="%s",result="avg_latency_ms"} %s' % (_pl_escape(uid), round(avg, 2)))
        try:
            import resource
            rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            lines.append("# HELP ebpdns_process_maxrss_kb 进程峰值内存KB")
            lines.append("# TYPE ebpdns_process_maxrss_kb gauge")
            lines.append("ebpdns_process_maxrss_kb %d" % rss)
        except Exception:
            pass
        body = "\n".join(lines) + "\n"
        return self._send(200, body, ctype="text/plain; version=0.0.4; charset=utf-8")

    def _serve_static(self, name):
        root = os.path.abspath(self.app.cfg.get("web_root") or os.path.join(os.path.dirname(__file__), "..", "web"))
        root_real = os.path.realpath(root)
        target = os.path.realpath(os.path.join(root_real, name))
        if not (target == root_real or target.startswith(root_real + os.sep)):
            return self._send(403, {"error": "forbidden"})
        if not os.path.isfile(target):
            return self._send(404, {"error": "not found"})
        # P3-11: 文件大小上限 10MB, 防止把超大文件一次性读入内存(OOM)。
        # R2-P3: read() 也包一层 try/except —— fstat 成功后 read 仍可能因磁盘错误/
        # 文件被删除而抛 OSError, 此前异常穿透到 handler 导致连接裸崩。
        try:
            with open(target, "rb") as f:
                size = os.fstat(f.fileno()).st_size
                if size > 10 * 1024 * 1024:
                    return self._send(413, {"error": "file too large (max 10MB)"})
                body = f.read()
        except OSError as e:
            log.warning("静态文件读取失败 %s: %r", name, e)
            return self._send(404, {"error": "not found"})
        # P3-3(第七轮): 补全静态资源 MIME 映射。此前只识别 .html/.js, 其余一律
        # application/octet-stream —— 浏览器把 .css 当二进制下载而非样式表, .svg/.png
        # 也无法正常渲染。补充 css/svg/png/ico 常见前端资源类型。
        # P3-5(第八轮): 映射表已提升为模块级常量 _STATIC_MIME(见文件头), 此处不再
        # 每次请求重建 dict。
        ext = os.path.splitext(name)[1].lower()
        ctype = _STATIC_MIME.get(ext, "application/octet-stream")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # 静态资源禁用缓存: web 单文件迭代快, 防止浏览器/代理缓存旧 JS 导致
        # "改代码后界面不刷新"、hash 直达失效等历史问题
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, OSError):
            pass  # 客户端已提前断开, 静默忽略

    # ---------- BaseHTTPRequestHandler ----------
    def do_GET(self):
        self._route()

    def do_POST(self):
        if not self._csrf_ok():
            return self._send(403, {"error": "CSRF check failed"})
        self._route()

    def do_PUT(self):
        if not self._csrf_ok():
            return self._send(403, {"error": "CSRF check failed"})
        self._route()

    def do_DELETE(self):
        if not self._csrf_ok():
            return self._send(403, {"error": "CSRF check failed"})
        self._route()

    def log_message(self, fmt, *args):
        # 静默访问日志（避免刷屏），可通过环境变量开启
        if os.environ.get("EBPDNS_DEBUG_LOG"):
            super().log_message(fmt, *args)


class APIServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    # 并发连接上限: ThreadingHTTPServer 每连接一线程, 无界会被海量短连接/慢连接
    # 耗尽线程。用有界信号量限流(与 DNS TCPDNSServer 一致), 满了在 accept 线程
    # 阻塞形成背压, 而不是无界派生线程。
    _conn_slots = threading.BoundedSemaphore(256)

    def __init__(self, app_ctx, host, port):
        self.app = app_ctx
        super().__init__((host, port), _Handler)
        # API 默认监听 127.0.0.1 回环地址, 仅本机可达。
        # 若显式绑定非回环地址, 提醒用户局域网/公网暴露风险。
        _host = str(host or "127.0.0.1").strip().lower()
        if _host not in ("127.0.0.1", "::1", "localhost"):
            log.warning("API 绑定非回环地址 %s —— 局域网/公网主机可访问写接口, 请确保网络隔离", host)

    def process_request(self, request, client_address):
        self._conn_slots.acquire()
        try:
            # P1-1: 对每个 accept 到的连接设置 15s 读/空闲超时, 防止慢滴 body 或
            # keep-alive 空闲连接占满 256 槽位造成控制面 DoS(与 DNS TCP 路径的
            # sock.settimeout(5)+30s 生命周期对称)。超时后 rfile.read/readline 抛
            # socket.timeout, _Handler.handle 静默断连, _read_json 亦统一吞掉。
            try:
                request.settimeout(15)
            except Exception:
                pass
            super().process_request(request, client_address)
        except Exception:
            self._conn_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._conn_slots.release()

    def start_thread(self):
        t = threading.Thread(target=self.serve_forever, name="http-api", daemon=True)
        t.start()
        return t


def _parse_domain_list(text):
    """解析域名列表文本 -> 去重后的域名列表（含 *. 通配保留）。

    支持常见列表格式:
      - 纯域名 / hosts("IP 域名") / 逗号分隔
      - dnsmasq:      address=/域名/  或  address=/域名/域名/
      - SmartDNS:     address /域名/#
      - Surge:        DOMAIN-SUFFIX,域名 / DOMAIN,域名
      - Clash YAML:   - '+.域名'
      - Adblock:      ||域名^   (@@ 例外规则跳过: 语义是放行, 不能当拦截导入)
      - 注释: # ! ;
    """
    # P2-15: 删除函数内 `import re as _re`, 直接用模块顶部(line 6)已导入的 re。
    out = []
    seen = set()

    def _add(tok):
        tok = tok.strip().strip("[]()").strip(".").lower()
        if not tok:
            return
        # #4 [严重]: 裸 IPv4/IPv6 不是域名, 识别为合法 IP 则跳过。
        # (hosts 单行 "127.0.0.1" 过去会被域名正则误收为域名)
        try:
            ipaddress.ip_address(tok.strip("[]"))
            return
        except ValueError:
            pass
        # 高级规则前缀(re:)原样保留 —— 不能被域名清洗切成前缀词。
        if _PREFIX_RE.match(tok):
            # R29 P3-1: 与 bulk PUT /api/config、单条 POST /api/rules、PUT /api/rules/<id>
            # 三条写入路径对齐, 复用 _check_rule_regex 预编译闸门。批量导入(/api/rules/import)、
            # 订阅下载(_do_subscribe_download)、订阅刷新(_api_subscribe_update)、冷启动补下载
            # 此前原样保留 re: 落库非法正则, resolver 对非法正则告警后静默跳过(rebuild 仍成功),
            # 即"接受后静默丢弃"的死规则——R28 想消除的问题漂移到了批量解析入口。
            # 非法正则记录 warning 并跳过该条规则, 不影响列表中其它合法域名。
            # R30 P3-1: 与 _validate_rule_dict 的 match 4096 字节上限对齐。批量导入路径
            # (_api_import_rules) 的 _validate_rule_dict 预检对象不含 match 字段, 长度
            # 上限在此被绕过; 超长 re: 行落库后规则索引膨胀、resolver 侧 re.compile 长串占内存。
            blen = len(tok.encode("utf-8"))
            if blen > 4096:
                log.warning("skip overly long re: rule in domain list (len=%d > 4096)",
                            blen)
                return
            rerr = _check_rule_regex(tok)
            if rerr:
                log.warning("skip invalid re: rule in domain list: %s (%s)", tok, rerr)
                return
            if tok not in seen:
                seen.add(tok)
                out.append(tok)
            return
        tok = tok.split("/")[0].split(":")[0].strip(".")
        if not re.fullmatch(r"(\*\.)?[a-z0-9_\-]+(\.[a-z0-9_\-]+)*", tok):
            return
        if tok in seen:
            return
        seen.add(tok)
        out.append(tok)

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "!", "//", ";")):
            continue
        if line.startswith("@@"):
            continue
        # YAML 顶层键（payload:/rules: 等）非域名, 跳过
        if re.match(r"^[a-z_]+\s*:\s*$", line):
            continue
        # #3 [严重]: dnsmasq 一行 address=/a.com/b.com/ 可含多个域名。
        # 正则捕获整条路径(到行尾空白前), 再按 "/" 切分, 不再只取第一个域名。
        m = re.search(r"address\s*=\s*/([^\s]+)", line)
        if m:
            for seg in m.group(1).strip("/").split("/"):
                _add(seg)
            continue
        m = re.search(r"^address\s+/([^/\s]+)", line)
        if m:
            _add(m.group(1))
            continue
        m = re.search(r"^(?:DOMAIN-SUFFIX|DOMAIN|DOMAIN-KEYWORD|HOST-SUFFIX|HOST)\s*,\s*(.+)$", line)
        if m:
            _add(m.group(1))
            continue
        m = re.search(r'^- *["\'+]*\.?([A-Za-z0-9_.-]+)', line)
        if m:
            _add(m.group(1))
            continue
        m = re.search(r"^\|\|([^/^]+)", line)
        if m:
            _add(m.group(1).rstrip("^"))
            continue
        parts = line.split()
        tok = parts[-1] if parts else ""
        for seg in tok.split(","):
            _add(seg)
    return out