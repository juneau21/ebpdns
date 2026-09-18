"""HTTP JSON API + 静态控制台服务（内置 http.server，零依赖）。"""

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


def _new_id(prefix):
    with _id_seq_lock:
        seq = next(_id_seq)
    return "%s%d%04x" % (prefix, int(time.time() * 1000), seq & 0xFFFF)


# 域名列表导入里 "re:" 高级规则前缀判定, 模块级编译一次避免每次导入重编译。
_PREFIX_RE = re.compile(r"^re:")


def _pl_escape(s):
    """#2 [严重]: Prometheus 标签值转义。标签值(规则名/上游 id)若含反斜杠、引号、
    换行/回车, 未转义会破坏 exposition 文本格式(metric 行被截断/引号不闭合),
    导致 Prometheus 抓取失败或指标解析错乱。按 Prometheus 文本格式规范转义。"""
    return str(s).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")


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
    import ipaddress
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
        ctx = ssl.create_default_context()
        self.sock = ctx.wrap_socket(raw, server_hostname=self.host)


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
    """拉取订阅文本(共享实现, 三处共用):
    1. 初始 URL 过 SSRF 检查(拒绝内网/环回/链路本地)并取得已验公网 IP;
    2. 用带每跳重定向复检 + IP 钉死的 opener 打开, 防 302 跳内网 & DNS rebinding;
    3. 流式 read(65536) 累积, 超过 SUB_TEXT_MAX_BYTES(16MB) 立即中止。
    返回解码后的 str; 被阻止或超限时抛 ValueError。"""
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
            new_cfg = config_mod.load_config(self.config_path)
        except Exception as e:
            log.error("热重载配置加载失败: %r", e)
            return {"ok": False, "error": "配置加载失败: %s" % e}
        old_cfg = self.cfg
        # 运行时派生键沿用当前进程的值(不随文件重读丢失)
        for k in ("cache_file", "rule_sub_file", "rule_local_file"):
            if k in old_cfg:
                new_cfg[k] = old_cfg[k]
        # 回收新配置中已删除/停用上游的连接池条目(防内存泄漏)
        # 注意: 基准是 new_cfg 的 id 集合, 旧配置里"仍存在"的上游不能回收
        try:
            new_ids = {u.get("id") for u in new_cfg.get("upstreams", [])}
            for u in old_cfg.get("upstreams", []):
                if u.get("id") not in new_ids:
                    upstream.discard_upstream_conns(u)
                    try:
                        from . import quic_upstream
                        quic_upstream.discard_upstream(u)
                    except Exception:
                        pass
        except Exception:
            pass
        try:
            changed = self.resolver.reload(new_cfg, self.config_path)
        except Exception as e:
            log.error("热重载 resolver 应用失败: %r", e)
            return {"ok": False, "error": "热重载失败: %s" % e}
        # 监听地址变更无法热生效(需要重建 socket), 提示走 /api/restart
        if old_cfg.get("listen") != new_cfg.get("listen"):
            changed = list(changed or [])
            changed.append("listen(监听地址变更需重启生效)")
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

    def _read_json(self, expect_dict=True, limit=None):
        try:
            if limit is None:
                limit = getattr(self, "_body_limit", self.MAX_BODY)
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0:
                return None
            # 超限直接 413, 不 drain body(大请求体不预读, 拒绝后连接由 handler 关闭)
            if n > limit:
                self._send(413, {"error": "request body too large (limit %d bytes)" % limit})
                return None
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
            # 其他错误(IO/连接重置) → 500, 不静默吞
            log.warning("read body error: %r", e)
            return None

    def _csrf_ok(self):
        """CSRF 防护: 对非 GET 写操作校验 Origin/Referer。
        - 有 Origin: 其 host 必须等于浏览器实际访问的 Host(任意绑定地址/IP 访问都通过),
          或等于配置的 api host:port
        - 无 Origin 但有 Referer: 其 host 必须与 Host 头一致, 或以配置的 api host:port/ 开头
        - 两者都没有(curl/脚本直连): 放行, 兼容命令行工具。"""
        api_cfg = self.app.cfg.get("api", {}) or {}
        configured = "http://%s:%s" % (api_cfg.get("host", "127.0.0.1"),
                                       api_cfg.get("port", 8080))
        expected_host = self.headers.get("Host", "") or ""

        def _netloc(url):
            try:
                return urllib.parse.urlparse(url).netloc
            except Exception:
                return ""

        origin = self.headers.get("Origin")
        if origin:
            onetloc = _netloc(origin)
            # 浏览器同源请求: Origin 的 host 必然等于请求 Host(含反向代理/局域网 IP 访问)
            if onetloc and expected_host and onetloc == expected_host:
                return True
            return origin.rstrip("/") == configured.rstrip("/")
        referer = self.headers.get("Referer")
        if referer:
            rnetloc = _netloc(referer)
            if rnetloc and expected_host and rnetloc == expected_host:
                return True
            return referer.startswith(configured.rstrip("/") + "/")
        return True

    def _route(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        method = self.command

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
        if path == "/api/health":
            tel = self.app.telemetry
            return self._send(200, {
                "status": "ok",
                "running": True,
                "version": __version__,
                "uptime_s": int(time.time() - tel.boot_time),
            })
        if path == "/api/cache/stats":
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
        if path == "/api/status":
            return self._send(200, self._status())
        if path == "/api/snapshot":
            return self._send(200, self._snapshot())
        if path == "/api/query" and method == "POST":
            return self._api_query()
        if path == "/api/config" and method == "GET":
            # 逐条规则已独立存储(rules_local.json): 返回配置时注入, 前端直接展示
            cfg_out = dict(self.app.cfg)
            cfg_out["rules"] = self._local_rules()
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
        if path == "/api/profile":
            return self._api_profile(query)
        if path == "/api/logs":
            return self._send(200, self._logs(query))
        if path == "/api/pipeline":
            return self._send(200, self._pipeline())
        if path == "/metrics":
            return self._metrics()
        self._send(404, {"error": "not found"})

    # ---------- handlers ----------
    def _status(self):
        app = self.app
        tel = app.telemetry
        cache = app.resolver.cache
        _counters, _rule_hits, _hit_rate, _qps, _avg_lat = tel.counters_snapshot()
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
            "map": cache.summary(),
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
        s["map"] = self.app.resolver.cache.summary()
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
        body = self._read_json() or {}
        domain = (body.get("domain") or "").strip()
        qtype = (body.get("qtype") or "A").upper()
        if not domain:
            return self._send(400, {"error": "domain required"})
        if len(domain) > 253:
            return self._send(400, {"error": "domain too long (max 253)"})
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
        results = probe_upstream_latencies(self.app.cfg, self.app.config_path,
                                           force=True, tag="重新测速", app_ctx=self.app)
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
        def _do():
            time.sleep(1.0)  # 确保 HTTP 响应已发出
            try:
                self.app.restart()
            except Exception:
                pass
        threading.Thread(target=_do, daemon=True, name="svc-restart").start()
        return self._send(200, {"ok": True, "restarting": True})

    def _api_update_config(self):
        data = self._read_json()
        if not isinstance(data, dict):
            return self._send(400, {"error": "bad config"})
        # 白名单: 只允许写配置主体中既有的顶层键(排除 listen/api/web_root)。
        # 防止 deep_merge 把攻击者注入的任意键(如伪装 listen/钩子字段)写回。
        # #5 记录被白名单过滤掉的键, 回传 ignored_keys 供前端 note() 提示用户:
        # 哪些提交的键未被保存(避免静默丢弃让用户误以为已生效)。
        dropped = [k for k in data.keys() if k not in _CFG_WRITABLE_KEYS]
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
        # 逐条规则独立存储: 前端回传的 rules 从配置主体剥离, 单独写 rules_local.json
        # (config.json 不再保存逐条规则; 避免 deep_merge 把前端 rules 写回 config)
        data_rules = data.pop("rules", None)
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
                # 上游 diff: 删除的回收连接/统计; 保留但 proto/addr/port/url 变更的
                # 旧连接池 key 已失效, 一并回收(与 AppContext.reload 路径行为一致)
                new_ups = self.app.cfg.get("upstreams", [])
                new_ids = {u.get("id") for u in new_ups}
                for o in old_ups:
                    uid = o.get("id")
                    if uid not in new_ids:
                        # 整条删除
                        try:
                            self.app.telemetry.per_upstream.pop(uid, None)
                        except Exception:
                            pass
                        try:
                            self.app.resolver._cb.pop(uid, None)
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
                        continue
                    nu = next((x for x in new_ups if x.get("id") == uid), None)
                    if nu is None:
                        continue
                    if (str(o.get("proto", "")).lower() != str(nu.get("proto", "")).lower()
                            or o.get("addr") != nu.get("addr")
                            or o.get("port") != nu.get("port")
                            or (o.get("url") or "") != (nu.get("url") or "")):
                        try:
                            upstream.discard_upstream_conns(o)
                        except Exception:
                            pass
                        try:
                            quic_upstream.discard_upstream(o)
                        except Exception:
                            pass
                # 规则可能整体替换 → 重建索引
                try:
                    self.app.resolver.rebuild_rule_index()
                except Exception:
                    pass
                saved = config_mod.save_config(self.app.cfg, self.app.config_path)
                # 逐条规则单独持久化(若前端回传了 rules)
                if isinstance(data_rules, list):
                    self._save_local_rules(data_rules)
                    try:
                        self.app.resolver.rebuild_rule_index()
                    except Exception:
                        pass
        except Exception as e:
            # 合并/应用过程中任何异常: 回滚配置引用, 避免半应用状态
            log.exception("更新配置失败, 回滚到旧配置: %r", e)
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
        return self._send(200, {"ok": True, "saved_to": saved, "ignored_keys": dropped})

    def _upstreams_with_health(self):
        cfg = self.app.cfg
        tel = self.app.telemetry
        # QUIC 连接诊断(doq/doh3): proto+host+port+path -> (connected, reconnects)
        # 与 quic_upstream.get_quic_upstream 的 key 对齐(含 path)
        qst = {}
        try:
            from . import quic_upstream as qu
            for q in qu.stats():
                path = str(q.get("path") or "")
                qst[(q["proto"], q["host"], q["port"], path)] = q
        except Exception:
            pass
        conns = tel.conn_summary()   # 连接维度健康度(proto|addr|port|url)
        out = []
        for u in cfg.get("upstreams", []):
            st = tel.upstream_stat(u.get("id"))
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
            # QUIC 上游附加连接诊断
            proto = str(u.get("proto", "")).lower()
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
        body = self._read_json() or {}
        cfg = self.app.cfg
        # 完整地址自动识别（与前端一致）: addr 含 scheme:// 或 host:port 时解析出
        # proto/addr/port/url; 纯 IP/域名则按 body 字段原样使用。
        parsed = None
        addr_raw = str(body.get("addr") or "")
        if addr_raw:
            parsed = config_mod.parse_upstream_addr(addr_raw, body.get("proto"))
        if parsed is not None:
            u = {
                "id": _new_id("u"),
                "name": body.get("name") or "上游 %d" % (len(cfg["upstreams"]) + 1),
                "proto": parsed["proto"],
                "addr": parsed["addr"],
                "port": parsed["port"],
                "url": parsed["url"],
                "group": body.get("group") or "domestic",
                "latency": 0,               # 0 = 未测速, 待后台实测写回真实延迟
                "latency_measured": False,
                "enabled": _as_bool(body.get("enabled", True)),
            }
            with self.app._lock:
                cfg = self.app.cfg   # 重新取最新引用, 防止持旧 cfg 覆盖并发更新
                cfg["upstreams"].append(u)
                config_mod.save_config(cfg, self.app.config_path)
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
            return self._send(200, {"ok": True, "upstream": u, "auto_parsed": True})
        proto = str(body.get("proto") or "udp").lower()
        _default_port = {"udp": 53, "tcp": 53, "doh": 443, "dot": 853, "doq": 853, "doh3": 443}
        try:
            port = int(body.get("port") or _default_port.get(proto, 53))
            int(body.get("latency") or 20)  # 仅校验合法性; 新上游延迟统一 0=待后台实测写回
        except (TypeError, ValueError):
            return self._send(400, {"error": "port/latency 必须是整数"})
        if proto in ("doh", "doh3", "doq"):
            url = body.get("url") or "/dns-query"
        else:
            url = ""
        u = {
            "id": _new_id("u"),
            "name": body.get("name") or "上游 %d" % (len(cfg["upstreams"]) + 1),
            "proto": proto,
            "addr": body.get("addr") or "223.5.5.5",
            "port": port,
            "url": url,
            "group": body.get("group") or "domestic",
            "latency": 0,               # 0 = 未测速, 待后台实测写回真实延迟
            "latency_measured": False,
            "enabled": _as_bool(body.get("enabled", True)),
        }
        with self.app._lock:
            cfg = self.app.cfg   # 重新取最新引用, 防止持旧 cfg 覆盖并发更新
            cfg["upstreams"].append(u)
            config_mod.save_config(cfg, self.app.config_path)
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
        return self._send(200, {"ok": True, "upstream": u})

    def _api_upstream_op(self, up_id):
        # #1 [严重]: body 读取(_read_json 阻塞读 socket/解析 JSON)必须移出 app._lock。
        # 否则慢客户端上传 body 期间持全局锁, 阻塞所有 DNS 解析与其它 API。
        # DELETE 不需要 body; 仅 PUT/PATCH 读 body, 读完再进锁做读改写。
        if self.command in ("PUT", "PATCH"):
            body = self._read_json() or {}
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
                config_mod.save_config(cfg, self.app.config_path)
                # 同步清理该上游的遥测统计 + DoH/DoT 连接池 + QUIC 常驻连接
                # (防 per_upstream/_pool 残留已删除上游的统计与连接对象/线程)
                try:
                    self.app.telemetry.per_upstream.pop(up_id, None)
                except Exception:
                    pass
                try:
                    self.app.resolver._cb.pop(up_id, None)
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
                                   "allow_private_ip"}
            _ALLOWED_PROTO = {"udp", "tcp", "doh", "dot", "doq", "doh3"}
            for k, v in body.items():
                if k == "id":
                    return self._send(400, {"error": "不允许修改上游 id"})
                if k not in _UPSTREAM_WHITELIST:
                    return self._send(400, {"error": "非法字段: %s (允许: %s)" % (
                        k, ",".join(sorted(_UPSTREAM_WHITELIST)))})
                if k == "port" or k == "latency":
                    try:
                        v = int(v)
                    except (TypeError, ValueError):
                        return self._send(400, {"error": "%s 必须是整数" % k})
                if k == "enabled":
                    v = _as_bool(v, True)
                if k == "allow_private_ip":
                    v = _as_bool(v, False)
                if k == "proto" and str(v).lower() not in _ALLOWED_PROTO:
                    return self._send(400, {"error": "proto 必须是 %s 之一" % "/".join(sorted(_ALLOWED_PROTO))})
                ups[idx][k] = v
            config_mod.save_config(cfg, self.app.config_path)
            return self._send(200, {"ok": True, "upstream": ups[idx]})

    def _api_import_rules(self):
        """导入分流规则。URL 走规则订阅(独立文件 rules_sub.json, 卡片只显示链接);
        直接粘贴域名列表走逐条规则(独立文件 rules_local.json, 卡片展开显示)。
        body: {url|content, action, group, wildcard, ip}
        """
        body = self._read_json() or {}
        src = (body.get("url") or "").strip()
        if src:
            # URL → 规则订阅通道: 明细不写入 config.json
            return self._api_subscribe_rules_body(body)
        text = body.get("content") or ""
        domains = _parse_domain_list(text)
        if not domains:
            return self._send(400, {"error": "未解析到有效域名"})
        action = body.get("action") or "group"
        group = body.get("group") or "global"
        wildcard = body.get("wildcard", True)
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
            if added:
                self._save_local_rules(rules)
                try:
                    self.app.resolver.rebuild_rule_index()
                except Exception:
                    pass
            return self._send(200, {"added": added, "total": len(rules)})

    def _api_subscribe_rules_body(self, body):
        """订阅 body 处理(供 /api/rules/import url 复用): 下载→写独立文件→重建索引。"""
        url = (body.get("url") or "").strip()
        action = body.get("action") or "block"
        group = body.get("group") or "global"
        ip = body.get("ip") or "1.2.3.4"
        # v1.9.74 P2-10: 规则订阅只允许 https://(明文 http 可被中间人篡改规则注入)
        if not url.lower().startswith("https://"):
            return self._send(400, {"error": "仅支持 https:// 订阅链接(http:// 不安全, 已禁止)"})
        try:
            text = self._fetch_sub_text(url)
        except Exception as e:
            return self._send(400, {"error": "订阅下载失败: %s" % e})
        domains = _parse_domain_list(text)
        if not domains:
            return self._send(400, {"error": "订阅内容未解析到有效域名"})
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
            self._save_subs(subs)
            meta = cfg.setdefault("rule_subscriptions", [])
            for m in meta:
                if m.get("url") == url:
                    m.update({"action": action, "group": group, "ip": ip, "count": len(items),
                              "updated_at": time.strftime("%Y-%m-%d %H:%M:%S")})
                    break
            else:
                meta.append({"url": url, "action": action, "group": group, "ip": ip,
                             "count": len(items), "updated_at": time.strftime("%Y-%m-%d %H:%M:%S")})
            config_mod.save_config(cfg, self.app.config_path)
            try:
                self.app.resolver.rebuild_rule_index()
            except Exception as e:
                import logging as _lg
                _lg.exception("rebuild_rule_index 失败: %s", e)
        return self._send(200, {"ok": True, "subscribed": True, "url": url,
                                "count": len(items), "added": 0 if existed else 1})

    def _api_add_rule(self):
        body = self._read_json() or {}
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
        r = {
            "id": _new_id("r"),
            "match": body.get("match") or "*.example.com",
            "action": body.get("action") or "group",
            "group": body.get("group") or "domestic",
            "ip": body.get("ip") or "",
        }
        # 规则级 TTL 透传(可选): 命中规则时覆盖全局 ttl_min/ttl_max
        for k in ("ttl_min", "ttl_max"):
            v = body.get(k)
            if v is not None and v != "":
                try:
                    r[k] = max(0, int(v))
                except (TypeError, ValueError):
                    pass
        # 读改写全程持 app._lock, 防并发加规则互相覆盖静默丢失(同 _api_import_rules)。
        with self.app._lock:
            rules = self._local_rules()
            rules.append(r)
            self._save_local_rules(rules)
            try:
                self.app.resolver.rebuild_rule_index()
            except Exception as e:
                import logging as _lg
                _lg.exception("rebuild_rule_index 失败: %s", e)
        return self._send(200, {"ok": True, "rule": r})

    # ---- 逐条规则(独立文件 rules_local.json, 不写入 config.json) ----
    def _local_rules(self):
        """读逐条规则独立文件; 文件不存在时回退 cfg['rules'](旧 config 迁移期兼容), 并惰性迁移。
        P0-2: 配置文件迁移来的历史规则没有 id 字段, 而 DELETE/PUT /api/rules/{id}
        按 id 定位。这里对缺 id 的规则惰性补一个稳定 id 并落盘, 保证列表展示与
        按 id 删除/编辑都可用, 不再触发 KeyError: 'id'。"""
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
        if changed:
            self._save_local_rules(rules)
        return rules

    def _save_local_rules(self, rules):
        config_mod.save_local_rules(rules, self.app.config_path)

    # ---- 规则订阅(独立文件 rules_sub.json, 不写入 config.json) ----
    def _sub_file(self):
        return self.app.cfg.get("rule_sub_file") or config_mod.sub_rules_path(self.app.config_path)

    def _load_subs(self):
        try:
            with open(self._sub_file(), encoding="utf-8") as f:
                subs = json.load(f).get("subscriptions", [])
        except Exception:
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
        os.makedirs(os.path.dirname(os.path.abspath(self._sub_file())) or ".", exist_ok=True)
        tmp = self._sub_file() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"subscriptions": subs}, f, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._sub_file())

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
        return {"rules": self._local_rules(), "subscriptions": subs}

    def _fetch_sub_text(self, url):
        # 共享实现: SSRF 初始校验 + 每跳重定向复检 + 16MB 流式上限(见 fetch_subscription_text)
        return fetch_subscription_text(url, timeout=20)

    def _api_subscribe_rules(self):
        """POST /api/rules/subscribe {url, action, group, ip}: 添加规则订阅。
        下载域名列表 → 写入独立文件 rules_sub.json → 重建索引(不写入 config.json 明细)。"""
        body = self._read_json() or {}
        url = (body.get("url") or "").strip()
        # v1.9.74 P2-10: 规则订阅只允许 https://(明文 http 可被中间人篡改规则注入)
        if not url or not url.lower().startswith("https://"):
            return self._send(400, {"error": "仅支持 https:// 订阅链接(http:// 不安全, 已禁止)"})
        action = body.get("action") or "block"
        group = body.get("group") or "global"
        ip = body.get("ip") or "1.2.3.4"
        try:
            text = self._fetch_sub_text(url)
        except Exception as e:
            return self._send(400, {"error": "订阅下载失败: %s" % e})
        domains = _parse_domain_list(text)
        if not domains:
            return self._send(400, {"error": "订阅内容未解析到有效域名"})
        # #3 订阅 re: 规则: 已带 *. 或已是 re: 正则的域名不加通配前缀(否则 re: 规则被破坏)
        items = [{"match": ("*." + d if not d.startswith(("*.", "re:")) else d)} for d in domains]
        # 读改写全程持 app._lock(下载在锁外), 与本地规则 CRUD/upstream CRUD 同型。
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
            self._save_subs(subs)
            # 元信息写入 config.json(仅链接/动作/数量/时间, 不含域名明细)
            meta = cfg.setdefault("rule_subscriptions", [])
            for m in meta:
                if m.get("url") == url:
                    m.update({"action": action, "group": group, "ip": ip, "count": len(items),
                              "updated_at": time.strftime("%Y-%m-%d %H:%M:%S")})
                    break
            else:
                meta.append({"url": url, "action": action, "group": group, "ip": ip,
                             "count": len(items), "updated_at": time.strftime("%Y-%m-%d %H:%M:%S")})
            config_mod.save_config(cfg, self.app.config_path)
            try:
                self.app.resolver.rebuild_rule_index()
            except Exception as e:
                import logging as _lg
                _lg.exception("rebuild_rule_index 失败: %s", e)
        return self._send(200, {"ok": True, "url": url, "count": len(items),
                                "added": 0 if existed else 1})

    def _api_subscribe_update(self):
        """POST /api/rules/subscribe/update {url}: 重新拉取订阅并覆盖明细。"""
        body = self._read_json() or {}
        url = (body.get("url") or "").strip()
        # 下载前的存在性快速预检(锁外, 仅优化; 权威判定在进锁后重做)
        subs_pre = self._load_subs()
        if not any(s.get("url") == url for s in subs_pre):
            return self._send(404, {"error": "订阅不存在: %s" % url})
        try:
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
            self._save_subs(subs)
            cfg = self.app.cfg
            for m in cfg.setdefault("rule_subscriptions", []):
                if m.get("url") == url:
                    m["count"] = len(domains)
                    m["updated_at"] = target["updated_at"]
                    break
            config_mod.save_config(cfg, self.app.config_path)
            try:
                self.app.resolver.rebuild_rule_index()
            except Exception as e:
                import logging as _lg
                _lg.exception("rebuild_rule_index 失败: %s", e)
        return self._send(200, {"ok": True, "url": url, "count": len(domains)})

    def _api_subscribe_delete(self, query):
        """DELETE /api/rules/subscribe?url=...: 移除订阅(明细与元信息一并删除)。"""
        url = urllib.parse.unquote((query.get("url") or [""])[0]).strip()
        if not url:
            return self._send(400, {"error": "缺少 url 参数"})
        # 读改写全程持 app._lock, 进锁后重新取 subs/cfg 最新引用。
        with self.app._lock:
            subs = self._load_subs()
            n = len(subs)
            subs = [s for s in subs if s.get("url") != url]
            if len(subs) == n:
                return self._send(404, {"error": "订阅不存在: %s" % url})
            self._save_subs(subs)
            cfg = self.app.cfg
            cfg["rule_subscriptions"] = [m for m in cfg.get("rule_subscriptions", []) if m.get("url") != url]
            config_mod.save_config(cfg, self.app.config_path)
            try:
                self.app.resolver.rebuild_rule_index()
            except Exception as e:
                import logging as _lg
                _lg.exception("rebuild_rule_index 失败: %s", e)
        return self._send(200, {"ok": True, "url": url})

    def _api_rule_op(self, rid):
        # #1 [严重]: 同样把 body 读取移出 app._lock, 避免持锁期间阻塞读 socket。
        # DELETE 不需要 body; 仅 PUT/PATCH 读 body, 读完再进锁做读改写。
        if self.command in ("PUT", "PATCH"):
            body = self._read_json() or {}
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
                self._save_local_rules(rules)
                try:
                    self.app.resolver.rebuild_rule_index()
                except Exception:
                    pass
                return self._send(200, {"ok": True})
            for k, v in body.items():
                if k == "id":
                    continue
                if v is None:
                    # null 语义 = 移除该字段(如规则 ttl_min/ttl_max 留空), 避免 config 残留 null
                    rules[idx].pop(k, None)
                else:
                    rules[idx][k] = v
            self._save_local_rules(rules)
            try:
                self.app.resolver.rebuild_rule_index()
            except Exception as e:
                import logging as _lg
                _lg.exception("rebuild_rule_index 失败: %s", e)
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
        # 在 telemetry 锁内取一份 events 快照, 避免无锁迭代 deque 时与写入交错
        # (CPython deque 迭代 GIL 安全不会崩, 但 total/next_seq 两次读可能不一致)。
        tm = self.app.telemetry
        with tm._lock:
            snap = list(tm.events)
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
        return {"events": events, "total": len(snap),
                "next_seq": max([e.get("seq", 0) for e in snap] or [0])}

    def _pipeline(self):
        cfg = self.app.cfg
        enabled = [u for u in cfg.get("upstreams", []) if u.get("enabled", True)][:3]
        return {
            "hook": cfg.get("hook"),
            "map_type": cfg.get("map_type"),
            "cache_size": cfg.get("cache_size"),
            "kernel_direct": cfg.get("kernel_direct"),
            "upstreams": enabled,
        }

    # ---------- Prometheus metrics(可观测性) ----------
    def _metrics(self):
        app = self.app
        tel = app.telemetry
        cache = app.resolver.cache
        c, rh, _hr, _qps, _al = tel.counters_snapshot()
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
            "ebpdns_cache_entries %d" % cache.size(),
            "# HELP ebpdns_cache_capacity 缓存容量",
            "# TYPE ebpdns_cache_capacity gauge",
            "ebpdns_cache_capacity %d" % cache.capacity,
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
        with open(target, "rb") as f:
            body = f.read()
        ctype = "text/html; charset=utf-8" if name.endswith(".html") else (
            "application/javascript; charset=utf-8" if name.endswith(".js") else "application/octet-stream")
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
    import re as _re
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
            if tok not in seen:
                seen.add(tok)
                out.append(tok)
            return
        tok = tok.split("/")[0].split(":")[0].strip(".")
        if not _re.fullmatch(r"(\*\.)?[a-z0-9_\-]+(\.[a-z0-9_\-]+)*", tok):
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
        if _re.match(r"^[a-z_]+\s*:\s*$", line):
            continue
        # #3 [严重]: dnsmasq 一行 address=/a.com/b.com/ 可含多个域名。
        # 正则捕获整条路径(到行尾空白前), 再按 "/" 切分, 不再只取第一个域名。
        m = _re.search(r"address\s*=\s*/([^\s]+)", line)
        if m:
            for seg in m.group(1).strip("/").split("/"):
                _add(seg)
            continue
        m = _re.search(r"^address\s+/([^/\s]+)", line)
        if m:
            _add(m.group(1))
            continue
        m = _re.search(r"^(?:DOMAIN-SUFFIX|DOMAIN|DOMAIN-KEYWORD|HOST-SUFFIX|HOST)\s*,\s*(.+)$", line)
        if m:
            _add(m.group(1))
            continue
        m = _re.search(r'^- *["\'+]*\.?([A-Za-z0-9_.-]+)', line)
        if m:
            _add(m.group(1))
            continue
        m = _re.search(r"^\|\|([^/^]+)", line)
        if m:
            _add(m.group(1).rstrip("^"))
            continue
        parts = line.split()
        tok = parts[-1] if parts else ""
        for seg in tok.split(","):
            _add(seg)
    return out