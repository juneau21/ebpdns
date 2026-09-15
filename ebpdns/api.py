"""HTTP JSON API + 静态控制台服务（内置 http.server，零依赖）。"""

import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__, config as config_mod
import logging
from .probe import probe_upstream_latencies

log = logging.getLogger("ebpdns.api")
from . import upstream, quic_upstream


def _sub_url_blocked(url):
    """SSRF 防护: 解析订阅 URL 的主机名, 拒绝指向私有/环回/链路本地地址。
    解析出的任何一个 IP 命中即拒绝(防止 DNS rebinding 到内网)。
    返回 None 表示放行, 返回错误字符串表示拒绝原因。"""
    import ipaddress
    import socket
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return "订阅 URL 解析失败"
    host = parsed.hostname or ""
    if not host:
        return "订阅 URL 缺少主机名"
    # 主机名本身就是 IP: 直接判定
    try:
        ips = [ipaddress.ip_address(host)]
    except ValueError:
        ips = []
        try:
            for fam, _t, _p, _c, sa in socket.getaddrinfo(host, parsed.port or 80):
                try:
                    ips.append(ipaddress.ip_address(sa[0]))
                except ValueError:
                    pass
        except OSError:
            return "订阅主机名解析失败"
    if not ips:
        return "订阅主机名无可用 IP"
    for ip in ips:
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            return "订阅地址指向内网/保留地址, 已拒绝(SSRF 防护)"
    return None

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
        self.wfile.write(body)

    MAX_BODY = 64 * 1024 * 1024   # 64MB: 容纳数十万条分流规则的大配置

    def _read_json(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0:
                return None
            # 超限: 必须先消费(drain)body 再拒绝, 否则客户端仍在上行、
            # 服务端提前回响应导致 TCP 半关闭 BrokenPipe
            if n > self.MAX_BODY:
                remaining = n
                while remaining > 0:
                    chunk = self.rfile.read(min(65536, remaining))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                return None
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except Exception:
            return None

    def _route(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        method = self.command

        # 静态资源
        if path in ("/", "/index.html"):
            return self._serve_static("index.html")
        if path == "/echarts.min.js":
            return self._serve_static("echarts.min.js")
        if path.startswith("/static/"):
            return self._serve_static(path[len("/static/"):])

        # ---------- API ----------
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
        return {
            "app": "ebpdns",
            "version": __version__,
            "uptime_s": int(time.time() - tel.boot_time),
            "running": True,
            "qps": tel.current_qps(),
            "hit_rate": round(tel.hit_rate(), 1),
            "avg_latency_ms": round(tel.avg_latency(), 1) if tel.avg_latency() is not None else None,
            "counters": dict(tel.counters),
            "rule_hits": dict(tel.rule_hits),
            "map": cache.summary(),
            "cache_policy": str(self.app.cfg.get("cache_policy", "lru")).lower(),
            "health_check_interval": int(self.app.cfg.get("health_check_interval", 30) or 0),
            "rule_sub_interval": int(self.app.cfg.get("rule_sub_interval", 3600) or 0),
            "cache_file": (app.cfg.get("cache_file") or ""),
            "top_domains": tel.top_domains.most_common(10),
            "top_clients": tel.top_clients.most_common(10),
            "top_upstreams": sorted(
                ((u, st.get("ok", 0) + st.get("fail", 0)) for u, st in tel.per_upstream.items()),
                key=lambda x: x[1], reverse=True)[:10],
            "config_path": app.config_path,
            "endpoints": app.dns_server.endpoints() if app.dns_server else None,
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
        res = self.app.resolver.resolve(domain, qtype, silent=False, client_ip="查询控制台")
        tel = self.app.telemetry
        tel.manual_history.append({
            "ts": _now_ts(),
            "domain": res["domain"],
            "qtype": res["qtype"],
            "answer": res.get("chosen") or "SERVFAIL",
            "lat": res.get("latency", 0),
        })
        if len(tel.manual_history) > 20:
            tel.manual_history = tel.manual_history[-20:]
        return self._send(200, res)

    def _api_reprobe(self):
        """一键重新测速：强制对所有启用上游重新实测延迟并写回配置。"""
        with self.app._lock:
            results = probe_upstream_latencies(self.app.cfg, self.app.config_path,
                                               force=True, tag="重新测速")
        return self._send(200, {"ok": True, "results": results})

    def _api_profile(self, query):
        """性能剖析端点: GET/POST /api/profile?seconds=N (默认 5, 上限 30)。
        对运行中流量采样 N 秒(cProfile 全局 hook), 返回按累计耗时排序的
        Top 函数统计——定位热点用。注意: 采样期间有性能开销, 按需调用。"""
        try:
            seconds = min(30, max(1, int((query.get("seconds") or ["5"])[0])))
        except Exception:
            seconds = 5
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
        # 防御: cache_size 必须为 1..10,000,000 的整数(防止前端部分回传/坏值
        # 把 LRU 容量静默改坏, 例如默认 1024 覆盖 131072)
        cs = data.get("cache_size")
        if cs is not None and not (isinstance(cs, int) and 1 <= cs <= 10_000_000):
            return self._send(400, {"error": "bad cache_size: %r" % (cs,)})
        # 逐条规则独立存储: 前端回传的 rules 从配置主体剥离, 单独写 rules_local.json
        # (config.json 不再保存逐条规则; 避免 deep_merge 把前端 rules 写回 config)
        data_rules = data.pop("rules", None)
        with self.app._lock:
            self.app.cfg = config_mod.deep_merge(self.app.cfg, data)
            # deep_merge 返回新 dict, resolver/DNSServer 持有旧引用。
            # 必须重绑定, 否则除 cache_size 外的配置(ttl/预取/测速/超时/IPv6/
            # 规则/上游/fallback/ipv4_first)都不会即时生效, 需重启才生效。
            self.app.resolver.cfg = self.app.cfg
            # 同步缓存容量
            self.app.resolver.cache.capacity = int(self.app.cfg.get("cache_size", 1024))
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
        # 新增上游自动实测延迟: 只测启用且未实测过的上游(新添加的), 后台线程不阻塞响应
        try:
            from . import probe
            if any(u.get("enabled", True) and not u.get("latency_measured", False)
                   for u in self.app.cfg.get("upstreams", [])):
                def _probe():
                    try:
                        probe.probe_upstream_latencies(self.app.cfg, self.app.config_path,
                                                       force=False, tag="新增测速")
                    except Exception:
                        pass
                threading.Thread(target=_probe, daemon=True, name="newup-probe").start()
        except Exception:
            pass
        return self._send(200, {"ok": True, "saved_to": saved})

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
            st = tel.upstream_stat(u["id"])
            total = st["ok"] + st["fail"]
            sr = total and st["ok"] / total * 100 or (100 if u.get("enabled", True) else 0)
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
                "id": "u%d" % int(time.time() * 1000),
                "name": body.get("name") or "上游 %d" % (len(cfg["upstreams"]) + 1),
                "proto": parsed["proto"],
                "addr": parsed["addr"],
                "port": parsed["port"],
                "url": parsed["url"],
                "group": body.get("group") or "domestic",
                "latency": 0,               # 0 = 未测速, 待后台实测写回真实延迟
                "latency_measured": False,
                "enabled": bool(body.get("enabled", True)),
            }
            cfg["upstreams"].append(u)
            config_mod.save_config(cfg, self.app.config_path)
            # 新上游后台实测延迟并写回
            try:
                from . import probe
                threading.Thread(target=probe.probe_upstream_latencies,
                                 args=(cfg, self.app.config_path),
                                 kwargs={"force": False, "tag": "新增测速"},
                                 daemon=True, name="newup-probe").start()
            except Exception:
                pass
            return self._send(200, {"ok": True, "upstream": u, "auto_parsed": True})
        try:
            port = int(body.get("port") or 53)
            int(body.get("latency") or 20)  # 仅校验合法性; 新上游延迟统一 0=待后台实测写回
        except (TypeError, ValueError):
            return self._send(400, {"error": "port/latency 必须是整数"})
        proto = str(body.get("proto") or "udp").lower()
        if proto in ("doh", "doh3", "doq"):
            url = body.get("url") or "/dns-query"
        else:
            url = ""
        u = {
            "id": "u%d" % int(time.time() * 1000),
            "name": body.get("name") or "上游 %d" % (len(cfg["upstreams"]) + 1),
            "proto": proto,
            "addr": body.get("addr") or "223.5.5.5",
            "port": port,
            "url": url,
            "group": body.get("group") or "domestic",
            "latency": 0,               # 0 = 未测速, 待后台实测写回真实延迟
            "latency_measured": False,
            "enabled": bool(body.get("enabled", True)),
        }
        cfg["upstreams"].append(u)
        config_mod.save_config(cfg, self.app.config_path)
        # 新上游后台实测延迟并写回
        try:
            from . import probe
            threading.Thread(target=probe.probe_upstream_latencies,
                             args=(cfg, self.app.config_path),
                             kwargs={"force": False, "tag": "新增测速"},
                             daemon=True, name="newup-probe").start()
        except Exception:
            pass
        return self._send(200, {"ok": True, "upstream": u})

    def _api_upstream_op(self, up_id):
        cfg = self.app.cfg
        ups = cfg.get("upstreams", [])
        idx = next((i for i, u in enumerate(ups) if u["id"] == up_id), None)
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
                upstream.discard_upstream_conns(removed)
            except Exception:
                pass
            try:
                quic_upstream.discard_upstream(removed)
            except Exception:
                pass
            return self._send(200, {"ok": True})
        body = self._read_json() or {}
        for k, v in body.items():
            if k == "id":
                continue
            if k == "port" or k == "latency":
                try:
                    v = int(v)
                except (TypeError, ValueError):
                    return self._send(400, {"error": "%s 必须是整数" % k})
            if k == "enabled":
                v = bool(v)
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
        rules = self._local_rules()
        existing = {r.get("match") for r in rules}
        base = int(time.time() * 1000)
        added = 0
        for d in domains:
            m = d
            is_advanced = d.startswith("re:")
            if wildcard and not d.startswith("*.") and not is_advanced:
                m = "*." + d
            if m in existing:
                continue
            r = {"id": "r%d" % (base + added), "match": m, "action": action}
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
        if not url.lower().startswith(("http://", "https://")):
            return self._send(400, {"error": "仅支持 http/https 订阅链接"})
        try:
            text = self._fetch_sub_text(url)
        except Exception as e:
            return self._send(400, {"error": "订阅下载失败: %s" % e})
        domains = _parse_domain_list(text)
        if not domains:
            return self._send(400, {"error": "订阅内容未解析到有效域名"})
        items = [{"match": ("*." + d if not d.startswith("*.") else d)} for d in domains]
        cfg = self.app.cfg
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
        r = {
            "id": "r%d" % int(time.time() * 1000),
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
        """读逐条规则独立文件; 文件不存在时回退 cfg['rules'](旧 config 迁移期兼容), 并惰性迁移。"""
        lr = config_mod.load_local_rules(self.app.config_path)
        if lr is not None:
            return lr
        # 独立文件尚未建立: 用 config 里的旧 rules(迁移逻辑由 cli.run 执行, 此处兜底)
        return list(self.app.cfg.get("rules", []))

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
        # SSRF 防护: 拒绝指向内网/环回/链路本地的订阅地址
        blocked = _sub_url_blocked(url)
        if blocked:
            raise ValueError(blocked)
        req = urllib.request.Request(url, headers={"User-Agent": "ebpdns/subscribe"})
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.read().decode("utf-8", "replace")

    def _api_subscribe_rules(self):
        """POST /api/rules/subscribe {url, action, group, ip}: 添加规则订阅。
        下载域名列表 → 写入独立文件 rules_sub.json → 重建索引(不写入 config.json 明细)。"""
        body = self._read_json() or {}
        url = (body.get("url") or "").strip()
        if not url or not url.lower().startswith(("http://", "https://")):
            return self._send(400, {"error": "仅支持 http/https 订阅链接"})
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
        items = [{"match": ("*." + d if not d.startswith("*.") else d)} for d in domains]
        cfg = self.app.cfg
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
        subs = self._load_subs()
        target = next((s for s in subs if s.get("url") == url), None)
        if not target:
            return self._send(404, {"error": "订阅不存在: %s" % url})
        try:
            text = self._fetch_sub_text(url)
        except Exception as e:
            return self._send(400, {"error": "订阅更新失败: %s" % e})
        domains = _parse_domain_list(text)
        if not domains:
            return self._send(400, {"error": "订阅内容未解析到有效域名"})
        target["rules"] = [{"match": ("*." + d if not d.startswith("*.") else d)} for d in domains]
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
        rules = self._local_rules()
        idx = next((i for i, r in enumerate(rules) if r["id"] == rid), None)
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
        body = self._read_json() or {}
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
        events = [e for e in self.app.telemetry.events if e.get("seq", 0) > since]
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
        return {"events": events, "total": len(self.app.telemetry.events),
                "next_seq": max([e.get("seq", 0) for e in self.app.telemetry.events] or [0])}

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
        c = tel.counters
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
            "ebpdns_hit_rate %s" % round(tel.hit_rate(), 3),
            "# HELP ebpdns_qps 每秒查询数",
            "# TYPE ebpdns_qps gauge",
            "ebpdns_qps %s" % round(tel.current_qps(), 3),
            "# HELP ebpdns_avg_latency_ms 平均延迟毫秒",
            "# TYPE ebpdns_avg_latency_ms gauge",
            "ebpdns_avg_latency_ms %s" % (round(tel.avg_latency(), 3) if tel.avg_latency() is not None else 0),
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
        for k, v in (tel.rule_hits or {}).items():
            lines.append('ebpdns_rule_hits{rule="%s"} %d' % (k, v))
        lines.append("# HELP ebpdns_upstream_health 上游健康度(成功次数, 延迟ms)")
        lines.append("# TYPE ebpdns_upstream_health gauge")
        for uid, st in (tel.per_upstream or {}).items():
            ok = st.get("ok", 0)
            avg = (st.get("lat_sum", 0) / ok) if ok else 0
            lines.append('ebpdns_upstream_health{upstream="%s",result="ok"} %d' % (uid, ok))
            lines.append('ebpdns_upstream_health{upstream="%s",result="avg_latency_ms"} %s' % (uid, round(avg, 2)))
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
        target = os.path.realpath(os.path.join(root, name))
        if not target.startswith(os.path.realpath(root) + os.sep) and target != os.path.realpath(root):
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
        self.wfile.write(body)

    # ---------- BaseHTTPRequestHandler ----------
    def do_GET(self):
        self._route()

    def do_POST(self):
        self._route()

    def do_PUT(self):
        self._route()

    def do_DELETE(self):
        self._route()

    def log_message(self, fmt, *args):
        # 静默访问日志（避免刷屏），可通过环境变量开启
        if os.environ.get("EBPDNS_DEBUG_LOG"):
            super().log_message(fmt, *args)


class APIServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, app_ctx, host, port):
        self.app = app_ctx
        super().__init__((host, port), _Handler)

    def start_thread(self):
        t = threading.Thread(target=self.serve_forever, name="http-api", daemon=True)
        t.start()
        return t


def _now_ts():
    t = time.localtime()
    ms = int(time.time() * 1000) % 1000
    return "%02d:%02d:%02d.%03d" % (t.tm_hour, t.tm_min, t.tm_sec, ms)


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

    _PREFIX_RE = _re.compile(r"^re:")
    def _add(tok):
        tok = tok.strip().strip("[]()").strip(".").lower()
        if not tok:
            return
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
        m = _re.search(r"address\s*=\s*/([^/\s]+)", line)
        if m:
            for seg in m.group(1).split("/"):
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