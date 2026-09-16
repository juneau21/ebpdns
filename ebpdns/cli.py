"""命令行入口：ebpdns run / status / config-path / version。"""

import argparse
import json
import logging
import os
import signal
import sys
import threading
import time
import urllib.request

from . import __version__
from . import config as config_mod
from .api import APIServer, AppContext, _parse_domain_list
from .probe import start_first_probe
from .resolver import Resolver
from .server import DNSServer
from .telemetry import Telemetry

# ---- 缓存持久化（重启后恢复 DNS 缓存） ----
_CACHE_SAVE_INTERVAL = 60  # 秒


def _sync_sub_meta(cfg, config_path=None):
    """启动时对齐规则订阅元信息: 以独立文件 rules_sub.json 为准,
    把 config.json 缺失/过期的 rule_subscriptions 补齐(不写入订阅明细)。"""
    try:
        path = cfg.get("rule_sub_file") or ""
        if not path or not os.path.isfile(path):
            return
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        file_subs = {s.get("url"): s for s in data.get("subscriptions", []) if s.get("url")}
        if not file_subs:
            return
        meta = cfg.setdefault("rule_subscriptions", [])
        have = {m.get("url") for m in meta}
        for url, s in file_subs.items():
            if url not in have:
                meta.append({
                    "url": url,
                    "action": s.get("action", "block"),
                    "group": s.get("group", ""),
                    "ip": s.get("ip", ""),
                    "count": len(s.get("rules") or []),
                    "updated_at": s.get("updated_at", ""),
                })
        if meta and config_path:
            config_mod.save_config(cfg, config_path)
    except Exception:
        logging.exception("同步订阅元信息失败")


def _default_cache_file(cfg, config_path):
    """推导缓存文件默认路径（与配置文件同目录）。

    相对路径基于 config 文件所在目录解析(而非进程 cwd), 避免 cwd 变化导致
    持久化写入失败; 未配置时默认 <config目录>/cache.json。
    """
    existing = cfg.get("cache_file")
    if existing:
        if os.path.isabs(existing):
            return existing
        base = "/etc/ebpdns"
        if config_path:
            base = os.path.dirname(os.path.abspath(config_path))
        return os.path.join(base, existing)
    base = "/etc/ebpdns"
    if config_path:
        base = os.path.dirname(os.path.abspath(config_path))
    return os.path.join(base, "cache.json")


def _save_cache(cfg, config_path, cache):
    """原子写缓存快照到磁盘（tmp + fsync + rename）。"""
    path = _default_cache_file(cfg, config_path)
    try:
        entries = cache.serialize()
        data = json.dumps({
            "version": 1,
            "saved_at": time.time(),
            "count": len(entries),
            "entries": entries,
        }, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        return len(entries)
    except Exception as e:
        log.warning("保存缓存失败 %s: %s", path, e)
        return 0


def _load_cache(cfg, config_path, cache):
    """启动时从磁盘载入缓存（过滤已过期条目）。返回载入条数。"""
    path = _default_cache_file(cfg, config_path)
    try:
        if not os.path.isfile(path):
            return 0
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        entries = data.get("entries", []) if isinstance(data, dict) else []
        persist_ttl = cfg.get("persist_ttl", 0)
        cache.restore(entries, persist_ttl=persist_ttl)
        if persist_ttl and persist_ttl > 0:
            log.info("持久化缓存 TTL 单独控制: persist_ttl=%ss (覆盖保存时剩余 TTL)", persist_ttl)
        n = len(cache)
        log.info("已从磁盘载入缓存 %d 条 (文件 %s)", n, path)
        return n
    except Exception as e:
        log.warning("载入缓存失败 %s: %s", path, e)
        return 0



log = logging.getLogger("ebpdns")


def _setup_logging(level="info", fmt="text"):
    """日志输出配置。fmt=json 时输出结构化 JSON lines(可观测性):
    每行 {time, level, logger, msg, exc?, 额外字段}, 便于对接日志采集系统。
    fmt=text 保持原可读格式。第三方库(quic/http3)仍固定 WARNING 以上。"""
    if str(fmt).lower() == "json":
        class _JsonFormatter(logging.Formatter):
            def format(self, record):
                import json as _j
                entry = {
                    "time": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
                    "level": record.levelname,
                    "logger": record.name,
                    "msg": record.getMessage(),
                }
                if record.exc_info:
                    entry["exc"] = self.formatException(record.exc_info)
                for k, v in getattr(record, "extra_fields", {}).items():
                    entry[k] = v
                return _j.dumps(entry, ensure_ascii=False)
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(_JsonFormatter())
        root = logging.getLogger()
        root.setLevel(getattr(logging, level.upper(), logging.INFO))
        root.handlers.clear()
        root.addHandler(handler)
    else:
        logging.basicConfig(
            level=getattr(logging, level.upper(), logging.INFO),
            format="%(asctime)s %(levelname)-7s %(message)s",
            datefmt="%H:%M:%S",
            stream=sys.stderr,
        )
    # 过滤第三方库(尤其 aioquic)的 DEBUG 日志: 其内部 "Stream discarded /
    # max_streams_bidi raised" 在 debug 级别下每毫秒刷屏, 抢占 CPU 拖垮
    # DNS 吞吐(实测 QPS 从 1.1万 骤降到几十)。库日志与 ebpdns 无关,
    # 固定 WARNING 以上才输出; ebpdns 自身日志仍按 log_level 全量开放
    # (ERROR/WARNING/DEBUG 均可见, 满足"不屏蔽任何异常")。
    # aioquic 实际使用顶层 logger "quic" / "http3" (非 aioquic.xxx 命名)
    for _name in ("quic", "http3"):
        lg = logging.getLogger(_name)
        lg.setLevel(logging.WARNING)


def build_app(cfg, config_path=None):
    """按配置构建 resolver / telemetry / cache / dns / api。"""
    telemetry = Telemetry()
    # 不传预建 cache: 让 Resolver 按 cache_policy 自行创建
    # (PartitionedCache / TinyLFUCache), 否则 LRUCache 占位会使策略选择失效。
    resolver = Resolver(cfg, telemetry, cache=None)

    dns_server = None
    endpoints = {}
    listen = cfg.get("listen", {})
    if any(listen.get(k) for k in ("udp", "tcp", "udp6", "tcp6")):
        dns_server = DNSServer(resolver, cfg)
        dns_server.start()
        endpoints = dns_server.endpoints()

    app_ctx = AppContext(resolver, telemetry, cfg, config_path=config_path, dns_server=dns_server)
    return app_ctx, endpoints


def _ensure_subs_downloaded(cfg, config_path, app_ctx):
    """订阅冷启动自动补下载(可靠性增强)。

    场景: 换机 / rules_sub.json 丢失或损坏 / 首次部署——config.json 里只有
    订阅元信息(url/action), 独立文件无明细 → 订阅规则空窗到 rule_sub_interval
    (默认 1h)周期任务才生效。本函数在启动 30s 后后台拉取一次缺失明细,
    下载成功即重建规则索引; 失败静默(下次周期任务重试), 不阻塞启动。
    """
    def _do():
        try:
            time.sleep(30)
            sub_path = cfg.get("rule_sub_file") or ""
            if not sub_path:
                return
            have = set()
            try:
                with open(sub_path, encoding="utf-8") as f:
                    for s in json.load(f).get("subscriptions", []):
                        if s.get("rules"):
                            have.add(s.get("url"))
            except Exception:
                pass
            for m in cfg.get("rule_subscriptions", []):
                url = m.get("url")
                if not url or url in have:
                    continue
                try:
                    from .api import fetch_subscription_text
                    try:
                        text = fetch_subscription_text(url, timeout=20)
                    except ValueError as _ve:
                        log.warning("订阅冷启动补下载跳过被阻止的 URL: %s (%s)", url, _ve)
                        continue
                    domains = _parse_domain_list(text)
                    if not domains:
                        continue
                    items = [{"match": ("*." + d if not d.startswith("*.") else d)} for d in domains]
                    subs = []
                    try:
                        with open(sub_path, encoding="utf-8") as f:
                            subs = json.load(f).get("subscriptions", [])
                    except Exception:
                        subs = []
                    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
                    for s in subs:
                        if s.get("url") == url:
                            s["rules"] = items
                            s["count"] = len(items)
                            s["updated_at"] = stamp
                            break
                    else:
                        subs.append({"url": url,
                                     "action": m.get("action", "block"),
                                     "group": m.get("group", "global"),
                                     "ip": m.get("ip") or "1.2.3.4",
                                     "count": len(items),
                                     "updated_at": stamp,
                                     "rules": items})
                    os.makedirs(os.path.dirname(os.path.abspath(sub_path)) or ".", exist_ok=True)
                    tmp = sub_path + ".tmp"
                    with open(tmp, "w", encoding="utf-8") as f:
                        json.dump({"subscriptions": subs}, f, ensure_ascii=False)
                        f.flush()
                        os.fsync(f.fileno())
                    os.replace(tmp, sub_path)
                    try:
                        app_ctx.resolver.rebuild_rule_index()
                    except Exception:
                        log.exception("订阅补下载后规则索引重建失败")
                    log.info("订阅冷启动补下载: %s → %d 条", url, len(items))
                except Exception as e:
                    log.warning("订阅冷启动补下载失败 %s: %s", url, e)
        except Exception:
            log.exception("订阅冷启动补下载线程异常")
    threading.Thread(target=_do, daemon=True, name="sub-boot-dl").start()


def run(cfg, config_path=None):
    _setup_logging(cfg.get("log_level", "info"), cfg.get("log_format", "text"))
    # 先注入运行时路径键, 再构建 app —— 否则 resolver 初始化重建规则索引时
    # 读不到 rule_sub_file/rule_local_file, 会退回旧 cfg['rules'] + 空订阅,
    # 导致启动后订阅/逐条规则不生效(仅靠 1h 周期任务或手动操作才恢复)。
    cache_file = _default_cache_file(cfg, config_path)
    cfg["cache_file"] = cache_file  # 供 API/控制台展示实际落盘路径
    cfg["rule_sub_file"] = config_mod.sub_rules_path(config_path)  # 订阅规则独立文件
    cfg["rule_local_file"] = config_mod.local_rules_path(config_path)  # 逐条规则独立文件
    app_ctx, endpoints = build_app(cfg, config_path)
    _sync_sub_meta(cfg, config_path)  # 订阅元信息与独立文件对齐(文件为准, 避免重启后界面空/规则仍生效)
    # 逐条规则独立文件(rules_local.json): 首次启动迁移 config.json 的 rules 到独立文件,
    # 之后 config.json 不再保存 rules(与订阅规则同样的"独立存放"模型)。
    try:
        _lr = config_mod.load_local_rules(config_path)
        if _lr is None and cfg.get("rules"):
            # 独立文件不存在但 config 里有旧规则 → 迁移写入独立文件, 防止用户既有规则丢失
            config_mod.save_local_rules(cfg["rules"], config_path)
            log.info("已迁移 %d 条逐条规则到独立文件 %s",
                     len(cfg["rules"]), cfg["rule_local_file"])
        cfg["rules"] = []  # config 主体不再持有逐条规则(以独立文件为准)
    except Exception:
        log.exception("逐条规则独立文件初始化失败")
    # 注入/迁移完成后重建规则索引: 保证订阅与迁移规则在启动时立即生效
    try:
        app_ctx.resolver.rebuild_rule_index()
    except Exception:
        log.exception("启动规则索引重建失败")
    # 订阅冷启动补下载: 独立文件缺失/明细空时 30s 后后台拉取, 防规则空窗
    try:
        _ensure_subs_downloaded(cfg, config_path, app_ctx)
    except Exception:
        log.exception("订阅冷启动补下载调度失败")
    n = _load_cache(cfg, config_path, app_ctx.resolver.cache)
    if n:
        # 持久化缓存与域名预取配合: 恢复条目重新纳入预取调度
        try:
            app_ctx.resolver.rearm_prefetch()
        except Exception:
            pass
    api_cfg = cfg.get("api", {})
    host = api_cfg.get("host", "127.0.0.1")
    port = int(api_cfg.get("port", 8080))

    try:
        api_server = APIServer(app_ctx, host, port)
    except OSError as e:
        log.error("HTTP API 监听失败 %s:%s : %s", host, port, e)
        sys.exit(1)

    # 遥测采样线程（兼做缓存定时持久化）
    _save_tick = 0

    def _sampler():
        nonlocal _save_tick
        while True:
            try:
                app_ctx.telemetry.sample()
            except Exception:
                pass
            _save_tick += 1
            if _save_tick >= _CACHE_SAVE_INTERVAL:
                _save_tick = 0
                try:
                    n = _save_cache(cfg, config_path, app_ctx.resolver.cache)
                    if n:
                        log.info("缓存持久化 %d 条 → %s", n, cache_file)
                except Exception:
                    pass
            time.sleep(1)

    st = threading.Thread(target=_sampler, name="telemetry-sampler", daemon=True)
    st.start()

    log.info("ebpdns v%s 启动", __version__)
    log.info("DNS  监听  UDP=%s UDP6=%s TCP=%s TCP6=%s",
             endpoints.get("udp"), endpoints.get("udp6"),
             endpoints.get("tcp"), endpoints.get("tcp6"))
    log.info("HTTP API   http://%s:%s  (控制台 http://%s:%s/)", host, port, host, port)
    log.info("缓存 LRU=%d · TTL=%ds · 预取=%s · 测速=%s · 上游=%d 个",
             cfg.get("cache_size"), cfg.get("ttl"), cfg.get("prefetch"),
             cfg.get("speed_test"), len([u for u in cfg.get("upstreams", []) if u.get("enabled")]))
    log.info("按 Ctrl+C 退出")
    log.info("缓存持久化 → %s (每 %ds 保存 + 退出时保存, 重启自动恢复)", cache_file, _CACHE_SAVE_INTERVAL)

    api_server.start_thread()

    # 首次启动: 对未实测过的上游自动实测延迟并写回(后台, 不阻塞)
    start_first_probe(cfg, config_path)

    stop = threading.Event()

    def _sig(signum, frame):
        log.info("收到信号 %s, 正在退出...", signum)
        stop.set()

    def _hup(signum, frame):
        # SIGHUP: 配置热重载(不重启进程), 与 POST /api/reload 等价
        log.info("收到 SIGHUP, 触发配置热重载...")
        try:
            app_ctx.reload()
        except Exception as e:
            log.error("SIGHUP 热重载失败: %r", e)

    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, _hup)
    stop.wait()
    # 先停 DNS server: 立即释放 53 端口, 让 systemd 重启/新实例能尽早 bind 接管,
    # 大幅缩短高负载下的服务中断窗口(旧进程收尾期间新实例已可监听应答)。
    try:
        app_ctx.dns_server.stop() if app_ctx.dns_server else None
    except Exception:
        pass
    # 再保存持久化缓存(此时 DNS 已停止, 不占用服务中断时间)
    try:
        _save_cache(cfg, config_path, app_ctx.resolver.cache)
    except Exception:
        pass
    # 停止预取/线程池(阻止解释器退出时 join 阻塞)
    try:
        app_ctx.resolver.shutdown()
    except Exception:
        pass
    try:
        api_server.shutdown()
        api_server.server_close()
    except Exception:
        pass
    log.info("ebpdns 已退出")
    # 强制进程退出, 跳过解释器对 ThreadPoolExecutor 非 daemon worker 的 join。
    # 背景: worker 若正阻塞在慢 DoH HTTPS / getaddrinfo(系统 DNS 解析无超时) 上,
    # 即使 pool.shutdown(wait=False) 也无法中断正在执行的任务, 解释器退出时会
    # join 这些 worker 直至 socket 超时叠加(负载期可达数秒~十几秒), 导致
    # systemd stop-sigterm 超时 SIGKILL(result=timeout, 非优雅退出)。
    # 此处优雅收尾(持久化缓存/停 server/停池)已完成, 直接终止进程即可。
    os._exit(0)


def cmd_status(cfg, config_path=None):
    import urllib.request
    api_cfg = cfg.get("api", {})
    url = "http://%s:%s/api/status" % (api_cfg.get("host"), api_cfg.get("port"))
    try:
        with urllib.request.urlopen(url, timeout=2) as r:
            data = r.read().decode("utf-8")
        print(data)
    except Exception as e:
        print("无法连接控制面 API: %s" % e, file=sys.stderr)
        sys.exit(1)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="ebpdns",
        description="ebpdns —— 基于 eBPF 理念的 SmartDNS 型 DNS 解析器 (Debian 可部署)",
    )
    parser.add_argument("--version", action="version", version="ebpdns %s" % __version__)
    parser.add_argument("-c", "--config", help="配置文件路径 (默认按优先级探测 /etc/ebpdns/config.json 等)")
    sub = parser.add_subparsers(dest="cmd")

    p_run = sub.add_parser("run", help="启动 DNS + HTTP API 服务")
    p_run.add_argument("-c", "--config", help="配置文件路径")
    p_run.add_argument("--dns-udp", help="覆盖 UDP 监听, 如 0.0.0.0:53")
    p_run.add_argument("--dns-tcp", help="覆盖 TCP 监听, 如 0.0.0.0:53")
    p_run.add_argument("--api-host", help="覆盖 API 监听地址")
    p_run.add_argument("--api-port", type=int, help="覆盖 API 端口")

    p_status = sub.add_parser("status", help="查询运行状态 (JSON)")
    p_status.add_argument("-c", "--config", help="配置文件路径")
    p_cfg = sub.add_parser("config-path", help="打印配置文件路径")
    p_cfg.add_argument("-c", "--config", help="配置文件路径")
    p_print = sub.add_parser("config-print", help="打印当前生效配置")
    p_print.add_argument("-c", "--config", help="配置文件路径")

    args = parser.parse_args(argv)
    config_path = getattr(args, "config", None) or args.config
    if not config_path:
        # 未显式指定时探测实际路径（含 EBPDNS_CONFIG 环境变量指向），
        # 以便缓存文件等派生路径落在配置同目录
        for p in config_mod.default_paths():
            if os.path.isfile(p):
                config_path = p
                break
    cfg = config_mod.load_config(config_path)

    if args.cmd == "run" or args.cmd is None:
        if getattr(args, "dns_udp", None):
            cfg["listen"]["udp"] = args.dns_udp
        if getattr(args, "dns_tcp", None):
            cfg["listen"]["tcp"] = args.dns_tcp
        if getattr(args, "api_host", None):
            cfg["api"]["host"] = args.api_host
        if getattr(args, "api_port", None):
            cfg["api"]["port"] = args.api_port
        run(cfg, config_path)
    elif args.cmd == "status":
        cmd_status(cfg, config_path)
    elif args.cmd == "config-path":
        chosen = None
        for p in config_mod.default_paths():
            if os.path.isfile(p):
                chosen = p
                break
        print(chosen or "未找到配置文件, 将使用内置默认值")
    elif args.cmd == "config-print":
        import json
        print(json.dumps(cfg, ensure_ascii=False, indent=2))
    else:
        parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
