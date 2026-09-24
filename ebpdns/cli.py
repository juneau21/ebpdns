"""命令行入口：ebpdns run / status / config-path / version。"""

import argparse
import json
import logging
import os
import signal
import sys
import threading
import time

from . import __version__
from . import config as config_mod
from .api import APIServer, AppContext, _parse_domain_list
from .probe import start_first_probe
from .resolver import Resolver
from .server import DNSServer
from .telemetry import Telemetry

# ---- 缓存持久化（重启后恢复 DNS 缓存） ----
_CACHE_SAVE_INTERVAL = 60  # 秒

# ---- 内存修剪（仅 PYTHONMALLOC=malloc + glibc 模式下有效） ----
_TRIM_INTERVAL = 300          # 秒: 每 5 分钟检查一次
_TRIM_ABS_MIN_MB = 300        # RSS 低于此值绝对不 trim
_TRIM_REL_GROWTH_PCT = 10     # 距上次 trim 后 RSS 增长超过此百分比才再 trim
_TRIM_LOG_THRESHOLD_MS = 20   # trim 耗时超过此值打 WARNING 日志


def _rss_mb():
    """当前进程 RSS (MB)。

    P1-2: 必须读 /proc/self/status 的 VmRSS(当前常驻集), 而非
    resource.getrusage(...).ru_maxrss。ru_maxrss 是历史峰值高水位, 单调不减,
    malloc_trim 把页还给 OS 后它也不降 —— 会导致相对阈值 `cur < last*1.1` 恒真
    (永远不 trim), 且 trim 前后 RSS 差值恒为 0, 日志指标完全失真。
    VmRSS 是此刻真实驻留物理内存, 才是有意义的"归还量"。"""
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    # 形如 "VmRSS:   123456 kB", split()[1] 单位为 kB
                    return int(line.split()[1]) / 1024.0
    except Exception:
        pass
    return 0.0


def _using_jemalloc():
    """通过 mallctl 探针检测是否使用 jemalloc(比检查 LD_PRELOAD 更可靠)。
    jemalloc 导出 mallctl 符号且 mallctl('version') 返回 0; glibc 不导出 mallctl。
    jemalloc 有自动 decay, 不需要手动 trim。"""
    try:
        import ctypes
        lib = ctypes.CDLL(None)
        if not hasattr(lib, "mallctl"):
            return False
        buf = ctypes.create_string_buffer(64)
        sz = ctypes.c_size_t(64)
        return lib.mallctl(b"version", buf, ctypes.byref(sz), None, 0) == 0
    except Exception:
        return False


_TRIM_STOP_EVENT = threading.Event()
_TRIM_THREAD = None  # trim 线程引用, 用于退出时 join


def stop_trim_thread(timeout=2.0):
    """v1.9.83: 主线程退出前通知 trim 线程停止并等待(避免 trim 进行中被 SIGTERM 打断)。
    malloc_trim 内部持有 malloc 锁, 被打断理论上没问题, 但优雅等待更安全。
    join 带超时: trim 偶发卡住时最多等 2s, 避免 systemd TimeoutStopSec 内无法退出。"""
    _TRIM_STOP_EVENT.set()
    if _TRIM_THREAD is not None and _TRIM_THREAD.is_alive():
        _TRIM_THREAD.join(timeout=timeout)


def _trim_loop():
    """v1.9.83: 相对阈值触发的内存修剪线程。
    仅在 PYTHONMALLOC=malloc 且非 jemalloc 时启动。
    触发条件: RSS > 300MB 且 距上次 trim 后增长 > 10%。
    不调用 gc.collect(): 验证显示 166MB 堆上 gc.collect() 全量扫描 88ms 且回收 0 对象
    (长期存活对象不可回收, 临时对象已被年轻代自动回收), STW 代价远大于收益。
    malloc_trim(0) 直接归还 glibc 堆中已 free 但未归还 OS 的空闲页。
    尖刺降级: 若上次 trim 耗时 > 50ms, 下次用 malloc_trim(1<<20) 保留 1MB 余量,
    减少归还后重新分配引发的 brk 抖动。
    验证数据: 152MB 堆首次 trim 6.2ms, 后续 1.1-1.3ms。"""
    if os.environ.get("PYTHONMALLOC") != "malloc":
        return
    if _using_jemalloc():
        return
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6")
        libc.malloc_trim.argtypes = [ctypes.c_size_t]
    except Exception:
        return
    last_trim_rss = 0.0
    trim_pad = 0  # 0 = 全量归还; 尖刺大时降级为 1<<20
    SPIKE_MS = 50.0
    while not _TRIM_STOP_EVENT.wait(_TRIM_INTERVAL):
        cur = _rss_mb()
        if cur < _TRIM_ABS_MIN_MB:
            continue
        # 相对阈值: 距上次 trim 后增长 > 10% 才再 trim, 避免稳态下每 5 分钟空转
        if last_trim_rss > 0 and cur < last_trim_rss * (1 + _TRIM_REL_GROWTH_PCT / 100.0):
            continue
        t0 = time.monotonic()
        try:
            libc.malloc_trim(trim_pad)
        except Exception:
            pass
        dt = (time.monotonic() - t0) * 1000
        after = _rss_mb()
        last_trim_rss = after
        # 尖刺降级: 本次 > 50ms 则下次保留 1MB 余量; 本次 < 20ms 则恢复全量
        if dt > SPIKE_MS:
            trim_pad = 1 << 20
        elif dt < 20.0 and trim_pad != 0:
            trim_pad = 0
        if dt > _TRIM_LOG_THRESHOLD_MS:
            log.warning("malloc_trim 耗时 %.0fms (VmRSS=%.0fMB -> %.0fMB, pad=%d)",
                        dt, cur, after, trim_pad)


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
            # P1-2(R3): 检查 save_config 返回值, 失败时打 WARNING(运行态已生效但重启后丢失)
            if config_mod.save_config(cfg, config_path) is False:
                logging.warning("订阅元信息写盘失败(运行态已生效, 重启后丢失)")
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


# R43 P3-1: 缓存写盘串行锁。sampler 线程每 60s 在其循环内调用 _save_cache, 退出主线程
# 也在收尾时调用同一函数。退出序列中 st.join(timeout=2.0) 是带超时的 best-effort(为不阻塞
# systemd TimeoutStopSec 而有意为之): 若 sampler 正阻塞在一次极慢 _save_cache(serialize +
# json.dump + fsync, 极端慢盘/百万级缓存 >2s), join 超时返回, 此后主线程的显式 _save_cache
# 会与 sampler 在途写并发 open("cache.json.tmp","w") → 内容交错/损坏。此锁让两次写在文件
# 操作上互斥: 主线程等待 sampler 在途写完成再写, 绝不并发; 仅在该极端竞态下多阻塞"一次
# 在途写的剩余时间"(有界, 非无限), 正常退出(锁空闲)零额外开销。两个调用方互不重入, 无死锁。
_cache_save_lock = threading.Lock()


def _save_cache(cfg, config_path, cache):
    """原子写缓存快照到磁盘（tmp + fsync + rename）。
    v1.9.83: 改用 json.dump 直写文件, 避免在内存中构建完整 JSON 字符串+bytes,
    65536 条缓存时瞬时峰值省 ~15MB (验证: json.dumps+encode 119.6MB → json.dump 104.2MB)。"""
    path = _default_cache_file(cfg, config_path)
    # R38 P3-1: tmp 提到 try 外, 与 save_config/save_local_rules/_save_subs 同型,
    # 便于 except 分支清理残留 .tmp
    tmp = path + ".tmp"
    with _cache_save_lock:
        try:
            entries = cache.serialize()
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({
                    "version": 1,
                    "saved_at": time.time(),
                    "count": len(entries),
                    "entries": entries,
                }, f, ensure_ascii=False, separators=(",", ":"))
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
            return len(entries)
        except Exception as e:
            # R38 P3-1: 原子写失败时清理残留 .tmp, 与 save_config/save_local_rules 同型
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass
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
    # 反向注入 app_ctx 给 resolver: 后台周期订阅更新(_update_rule_subs_once)需在
    # app._lock 内做读改写, 与 API 订阅 CRUD/reload 串行化(修 M1)。reload 只替换
    # resolver.cfg 引用不重建 resolver 对象, 故注入一次即跨 reload 存活。
    resolver._app_ctx = app_ctx
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
            # P3: 不闭包持有启动时的 cfg 引用 —— 30s 内可能发生 SIGHUP/PUT reload,
            # app_ctx.cfg 已是新 dict; 读最新引用避免按过期 rule_subscriptions 补下载。
            live_cfg = app_ctx.cfg
            sub_path = live_cfg.get("rule_sub_file") or ""
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
            for m in live_cfg.get("rule_subscriptions", []):
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
                    # R19 P2-1: 冷启动补下载此前只检查 *. 前缀, 漏了 re: 正则前缀,
                    # 导致订阅中的正则规则被错误拼成 *.re:... 变成死规则。
                    # 与 api.py:1979/2286 两条订阅路径(startswith(("*.", "re:")))对齐。
                    items = [{"match": ("*." + d if not d.startswith(("*.", "re:")) else d)} for d in domains]
                    # 读改写 rules_sub.json + rebuild_rule_index 全程持 app_ctx._lock,
                    # 与 API 订阅 CRUD/reload 串行化(同 _update_rule_subs_once 修法);
                    # 网络下载已在锁外完成(见上方 fetch_subscription_text)。
                    # R38 P3-1: tmp 提到 try 外, 与 save_config/save_local_rules 同型,
                    # 便于 except 分支清理残留 .tmp
                    tmp = sub_path + ".tmp"
                    try:
                        with app_ctx._lock:
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
                            with open(tmp, "w", encoding="utf-8") as f:
                                json.dump({"subscriptions": subs}, f, ensure_ascii=False)
                                f.flush()
                                os.fsync(f.fileno())
                            os.replace(tmp, sub_path)
                            app_ctx.resolver.rebuild_rule_index()
                    except Exception:
                        # R38 P3-1: 原子写失败时清理残留 .tmp, 与 save_config 同型
                        try:
                            if os.path.exists(tmp):
                                os.remove(tmp)
                        except OSError:
                            pass
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
    # 注入 UDP 致命回调: 网络栈连续接收失败时, 先持久化缓存再非零退出
    # (systemd Restart=on-failure 自动重启), 不再硬退出丢失缓存状态。
    def _fatal_exit():
        try:
            # v1.9.139: 用 app_ctx.cfg 而非闭包捕获的启动期 cfg, 与 reload 后状态对齐
            # (cache_file 路径在 reload 时可能变更)
            _save_cache(app_ctx.cfg, config_path, app_ctx.resolver.cache)
        except Exception:
            pass
        os._exit(1)
    if app_ctx.dns_server is not None:
        app_ctx.dns_server.fatal_callback = _fatal_exit
        app_ctx.dns_server.udp.fatal_callback = _fatal_exit
        if app_ctx.dns_server.udp6:
            app_ctx.dns_server.udp6.fatal_callback = _fatal_exit
    _sync_sub_meta(cfg, config_path)  # 订阅元信息与独立文件对齐(文件为准, 避免重启后界面空/规则仍生效)
    # 逐条规则独立文件(rules_local.json): 首次启动迁移 config.json 的 rules 到独立文件,
    # 之后 config.json 不再保存 rules(与订阅规则同样的"独立存放"模型)。
    try:
        _lr = config_mod.load_local_rules(config_path)
        if _lr is None and cfg.get("rules"):
            # 独立文件不存在但 config 里有旧规则 → 迁移写入独立文件, 防止用户既有规则丢失
            # P0-1(R3): 检查写盘返回值, 失败时保留内存规则不清除, 防止数据永久丢失。
            # save_local_rules 内部 catch 所有异常并返回 False, 外层 try/except 无法感知失败。
            if not config_mod.save_local_rules(cfg["rules"], config_path):
                log.error("规则迁移写盘失败, 保留内存规则不清除(下次启动重试), "
                          "规则数量=%d, 目标文件=%s", len(cfg["rules"]), cfg["rule_local_file"])
            else:
                log.info("已迁移 %d 条逐条规则到独立文件 %s",
                         len(cfg["rules"]), cfg["rule_local_file"])
                cfg["rules"] = []  # 写盘成功后才清空内存规则
        else:
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
    # P3-2(R39): 显式停止事件, 退出收尾时通知采样线程退出, 避免其在 glob(*.tmp)
    # 清理窗口内仍在写 cache.json.tmp 被误删(详见退出序列注释)。
    _sampler_stop = threading.Event()

    def _sampler():
        nonlocal _save_tick
        while not _sampler_stop.is_set():
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
            # 用 wait 代替 sleep: 收到停止事件立即唤醒退出, 无需等待满 1s 才检查。
            _sampler_stop.wait(timeout=1)

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

    # v1.9.83: 内存修剪线程(仅 PYTHONMALLOC=malloc 时实际运行)
    global _TRIM_THREAD
    _TRIM_THREAD = threading.Thread(target=_trim_loop, name="mem-trim", daemon=True)
    _TRIM_THREAD.start()

    # 首次启动: 对未实测过的上游自动实测延迟并写回(后台, 不阻塞)。
    # 透传 app_ctx(M1 修复): 落盘进 app._lock 按 id 合并, 避免启动旧 cfg 整体
    # 落盘覆盖 API 已启动后并发 PUT /api/config 的新变更。
    start_first_probe(cfg, config_path, app_ctx)

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
    # 先通知 trim 线程停止(避免 trim 进行中被后续清理打断)
    stop_trim_thread()
    # 先停 DNS server: 立即释放 53 端口, 让 systemd 重启/新实例能尽早 bind 接管,
    # 大幅缩短高负载下的服务中断窗口(旧进程收尾期间新实例已可监听应答)。
    try:
        app_ctx.dns_server.stop() if app_ctx.dns_server else None
    except Exception:
        pass
    # P3-1(R42): 显式停止 telemetry 采样线程并 join, 必须在下方显式 _save_cache 之前。
    # 此前顺序为 先 _save_cache(line 533) 后 _sampler_stop(line 541), 存在理论竞态:
    # sampler 每 60s 在其循环内调用同一个 _save_cache, 若恰好被唤醒且 _save_tick>=60,
    # 两线程会同时 open("cache.json.tmp","w")(O_TRUNC), 各自 write 到独立 fd, 文件内容
    # 交错/损坏, 先到的 os.replace 成功, 后到的抛 FileNotFoundError(被 except 吞掉)。
    # 影响: cache.json 可能写入交错数据, 下次启动 _load_cache 解析失败 → 缓存冷启动。
    # 理论概率约 0.08%(50ms/60000ms)。这里先停采样线程再做显式缓存写盘, 消除该竞态。
    # 同时在下方 glob(*.tmp) 清理窗口前停掉采样线程, 避免 glob 误删在写 tmp →
    # os.replace 抛 FileNotFoundError(join 带超时, 采样线程正在写盘时最多等 2s,
    # 不阻塞 systemd 超时退出)。
    _sampler_stop.set()
    if st.is_alive():
        st.join(timeout=2.0)
    # 再保存持久化缓存(此时 DNS 已停止, 不占用服务中断时间)。
    # R43 P3-1: 上方 join(timeout=2.0) 为 best-effort, 极端慢盘下 sampler 可能仍在途写;
    # 但 _save_cache 已由 _cache_save_lock 互斥, 此处会等待在途写完成再写, 不会并发写同一 tmp。
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
    # P3-3: os._exit 是硬终止, 不跑解释器清理。若收尾期间某 worker 正 _save_cache
    # 写一半(tmp + fsync + rename), 硬终止会留下 cache.json.tmp 残留(下次启动读
    # 不到正式文件, 缓存丢失)。退出前清理缓存 tmp, 清理失败不影响退出。
    # M7 修复: 原 glob("*.tmp") 范围过宽, 会连带删除 rules_sub.json.tmp /
    # rules_local.json.tmp——后台订阅下载线程可能正在原子写这两个文件(tmp+rename),
    # 误删会导致订阅/本地规则回滚到旧版甚至丢失。这里只精确清理 cache.json.tmp
    # (缓存落盘由 _cache_save_lock + 上方显式 _save_cache 串行, 不存在在途写)。
    try:
        _cache_path = _default_cache_file(cfg, config_path)
        _cache_tmp = _cache_path + ".tmp"
        if os.path.isfile(_cache_tmp):
            os.remove(_cache_tmp)
    except Exception:
        pass
    # S1 修复: /api/restart 在 systemd 托管时把 restart_exit_code 置 3, 使
    # Restart=on-failure 触发拉起新实例; 正常退出(0) 不重启。
    _exit_code = getattr(app_ctx, "restart_exit_code", 0) or 0
    os._exit(_exit_code)


def cmd_status(cfg, config_path=None):
    import urllib.request
    api_cfg = cfg.get("api", {})
    # R51 P3-2: host 为 IPv6 字面量(如 ::1)时, URL 必须包成 [::1], 否则
    # http://::1:8080/api/status 无法被 urllib 解析。含冒号即视为 IPv6 字面量,
    # 与 api.py 中 URL 构造约定保持一致; 已是 [..] 字面量或主机名(无冒号)原样使用。
    _host = str(api_cfg.get("host") or "127.0.0.1")
    if ":" in _host and not _host.startswith("["):
        _host = "[%s]" % _host
    url = "http://%s:%s/api/status" % (_host, api_cfg.get("port"))
    req = urllib.request.Request(url)
    # R16 P3-3: 服务端配置了 api.token 时, 除 /api/health 外所有 /api/* 均要求
    # Authorization: Bearer <token> (见 api._check_api_token)。此前 status 裸 GET 不带
    # 凭据, 一旦用户配置 token 即 401, 诊断命令失效。这里与服务端取值同步 strip,
    # 未配置 token(空串)时不加头, 保持原无认证行为。
    token = str(api_cfg.get("token") or "").strip()
    if token:
        req.add_header("Authorization", "Bearer %s" % token)
    try:
        with urllib.request.urlopen(req, timeout=2) as r:
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
    # P1-3: 子parser 的 -c 用 default=SUPPRESS。旧实现子parser 默认 None, 会在
    # `ebpdns -c config.json run` 时把子parser 的空值覆盖掉顶层值, 导致 args.config=None
    # 而错误加载默认配置(端口 53)。SUPPRESS 表示"命令行没给 -c 就不写该属性", 保留顶层值;
    # 同时 `ebpdns run -c x` 形式仍被子parser 正常解析。
    p_run.add_argument("-c", "--config", help="配置文件路径", default=argparse.SUPPRESS)
    p_run.add_argument("--dns-udp", help="覆盖 UDP 监听, 如 0.0.0.0:53")
    p_run.add_argument("--dns-tcp", help="覆盖 TCP 监听, 如 0.0.0.0:53")
    p_run.add_argument("--api-host", help="覆盖 API 监听地址")
    p_run.add_argument("--api-port", type=int, help="覆盖 API 端口")

    p_status = sub.add_parser("status", help="查询运行状态 (JSON)")
    p_status.add_argument("-c", "--config", help="配置文件路径", default=argparse.SUPPRESS)
    p_cfg = sub.add_parser("config-path", help="打印配置文件路径")
    p_cfg.add_argument("-c", "--config", help="配置文件路径", default=argparse.SUPPRESS)
    p_print = sub.add_parser("config-print", help="打印当前生效配置")
    p_print.add_argument("-c", "--config", help="配置文件路径", default=argparse.SUPPRESS)

    args = parser.parse_args(argv)
    config_path = args.config
    if not config_path:
        # 未显式指定时探测实际路径（含 EBPDNS_CONFIG 环境变量指向），
        # 以便缓存文件等派生路径落在配置同目录
        for p in config_mod.default_paths():
            if os.path.isfile(p):
                config_path = p
                break
    # P3-1(R5): 只读子命令(status/config-print/config-path)不得触发 load_config 内嵌的
    # "rules_local.json 缺失即从 config 自动落盘"写盘副作用。仅 run/无参启动(真正起进程)
    # 才允许该迁移写盘; 只读命令传 persist=False, 避免非 root 只读 /etc 时打 warning 干扰诊断,
    # 也保证"打印配置/查状态"语义纯净。
    _readonly_cmds = ("status", "config-path", "config-print")
    cfg = config_mod.load_config(config_path, persist=(args.cmd not in _readonly_cmds))
    # R9-R3 P1: 文件存在但解析失败时 load_config 返回 None; 启动阶段回退内置默认
    # (与历史行为一致, 保证进程能起来), 热重载路径(api._reload_body)则保留旧配置。
    if cfg is None:
        log.error("启动: 配置文件 %s 解析失败, 回退内置默认配置", config_path)
        cfg = config_mod.default_config()

    if args.cmd == "run" or args.cmd is None:
        if getattr(args, "dns_udp", None):
            # M3: 与 --api-port 覆盖同型。--dns-udp 为 host:port 字符串, 覆盖发生在
            # load_config 之后, 绕过 config.py listen 绑定串校验。这里补 host:port 拆分
            # 与端口范围校验(IPv6 [::1]:53 由 parse_upstream_addr 处理); 非法/越界直接
            # stderr 报错并 exit(2), 不让坏绑定串带入 server.bind 在运行时才崩。
            _up = config_mod.parse_upstream_addr(args.dns_udp)
            if _up is None or not (1 <= _up["port"] <= 65535):
                print("--dns-udp 绑定串非法(host:port 格式/端口越界, got %r)" % (args.dns_udp,),
                      file=sys.stderr)
                sys.exit(2)
            cfg["listen"]["udp"] = args.dns_udp
        if getattr(args, "dns_tcp", None):
            _tp = config_mod.parse_upstream_addr(args.dns_tcp)
            if _tp is None or not (1 <= _tp["port"] <= 65535):
                print("--dns-tcp 绑定串非法(host:port 格式/端口越界, got %r)" % (args.dns_tcp,),
                      file=sys.stderr)
                sys.exit(2)
            cfg["listen"]["tcp"] = args.dns_tcp
        if getattr(args, "api_host", None):
            cfg["api"]["host"] = args.api_host
        if getattr(args, "api_port", None) is not None:
            # R6 P3-1: --api-port 覆盖发生在 load_config 之后, 绕过了 config.py 内的
            # 加载期 port 范围/bool 校验。这里补同型校验: type=int 已保证非数字,
            # 但 --api-port 0 会静默绑临时端口(日志打印 :0 不可达), 越界值靠
            # bind OSError 兜底报错。统一在此拦截 0/越界, 给出明确退出。
            # R6-P3-3(第七轮 重评估): argparse type=int 不可能产出 bool,
            # 原 `isinstance(p, bool)` 检查为死代码, 已移除以减少困惑。
            p = args.api_port
            if not (1 <= int(p) <= 65535):
                print("--api-port 必须在 1-65535 之间 (got %r)" % (p,),
                      file=sys.stderr)
                sys.exit(2)
            cfg["api"]["port"] = int(p)
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
