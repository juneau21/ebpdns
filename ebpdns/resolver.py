"""解析引擎：多上游并发、测速择优、域名分流、LRU 缓存、预取。
对外核心接口:
  - Resolver.resolve(domain, qtype)  -> 结构化结果 (含 trace)
  - Resolver.answer_raw(query_bytes) -> 面向 DNS 服务器的完整响应报文

2026-09-01 优化:
  - 延迟全部实测 (time.monotonic), 移除仿真随机延迟
  - NXDOMAIN / NODATA 正确区分 (不再一律 SERVFAIL), 支持负缓存
  - 共享上游查询线程池 (避免每次查询新建线程池)
  - 预取改为单一后台线程扫描 (避免每域名一个 Timer 线程)
"""
import json
import logging
import random
import re
import threading
import time
import urllib.request
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED, as_completed

from . import dnsmsg

# match_rule 缓存哨兵: 区分"未缓存"与"命中 None"(无规则)
_MISS = object()
from .cache import PartitionedCache, TinyLFUCache
from .upstream import probe_ip, probe_tcp, query_upstream, _tcp_query


class _BoundedExecutor:
    """有界线程池：队列深度 = max_workers + max_pending，防止高负载下任务
    无界堆积耗尽内存。

    根因（VM 实测 737MB）：上游全为 DoH/DoH3 慢协议（每查询至多
    timeout_ms=1500ms 才超时）+ fallback 全并发时，提交速率可远超处理速率
    （慢池约 11 worker → 每秒约 7 个 miss），原 ThreadPoolExecutor 无界队列
    submit 后任务无限排队，future/报文对象堆积导致长期运行内存增长。

    - submit(): 队列满则阻塞调用线程（反压）。关键路径（上游查询）用——
      让客户端自然排队而非内存爆炸。
    - submit_drop(): 队列满则直接丢弃返回 None。统计/预取类后台任务用——
      错过一轮统计或下轮预取无副作用，但避免无界堆积。
    """
    def __init__(self, max_workers, max_pending, name):
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix=name)
        self._sem = threading.BoundedSemaphore(max_workers + max_pending)

    def _submit(self, fn, args, kwargs):
        fut = self._pool.submit(fn, *args, **kwargs)
        def _release(_f):
            self._sem.release()
        fut.add_done_callback(_release)
        return fut

    def submit(self, fn, *args, **kwargs):
        """队列满则阻塞（反压）。"""
        self._sem.acquire()
        try:
            return self._submit(fn, args, kwargs)
        except Exception:
            self._sem.release()
            raise

    def submit_drop(self, fn, *args, **kwargs):
        """队列满则丢弃，返回 None。"""
        if not self._sem.acquire(blocking=False):
            return None
        try:
            return self._submit(fn, args, kwargs)
        except Exception:
            self._sem.release()
            return None

    def shutdown(self, *a, **k):
        try:
            self._pool.shutdown(*a, **k)
        except Exception:
            pass

    @property
    def _work_queue(self):
        return self._pool._work_queue


def _looks_like_ip(s):
    """粗略判断字符串是否为可读 IP(v4/v6), 用于日志展示过滤 hex 乱码。"""
    if not s:
        return False
    if ":" in s:  # IPv6
        return all(c in "0123456789abcdefABCDEF:." for c in s)
    parts = s.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or not (0 <= int(p) <= 255):
            return False
    return True


TRACE_TAGS = ("xdp", "bpf", "rule", "eng", "ans", "ans-fail", "ok", "warn")


log = logging.getLogger("ebpdns")


class Resolver:
    def __init__(self, cfg, telemetry, cache=None):
        self.cfg = cfg
        self.tel = telemetry
        # 启动预热重试: 冷启动/重启后上游 TLS 冷握手未就绪, 首查易全部失败返回
        # SERVFAIL。启动早期(45s)内全部失败时延迟重试一次(全局至多 3 次), 改善
        # "刚重启/刚部署首查失败"体验; 稳态(>45s)完全不受影响。
        self._boot_ts = time.monotonic()
        self._boot_retries = 0
        self._boot_retry_lock = threading.Lock()
        # 缓存策略: lru(默认, 按分流 group 分区隔离) / tinylfu(W-TinyLFU 高频保留)
        _policy = str(cfg.get("cache_policy", "lru")).lower()
        if _policy == "tinylfu":
            self.cache = cache if cache is not None else TinyLFUCache(cfg.get("cache_size", 1024))
        else:
            self.cache = cache if cache is not None else PartitionedCache(
                cfg.get("cache_size", 1024), cfg.get("cache_partitions"))
        self._speed_lock = threading.Lock()
        # 候选 IP 测速结果缓存: ip -> (rtt_ms, ts)。命中直接复用, 避免重复探测。
        self._ip_speed_cache = {}
        self._ip_speed_lock = threading.Lock()
        # 测速节流表: 按域名记录最近测速时间, 用 OrderedDict 限长(防长时压测
        # 随机域名导致 dict 无限增长的内存泄漏)
        self._last_speed_test = OrderedDict()   # domain -> ts
        self._speed_hist_max = 4096
        self._prefetch_lock = threading.Lock()
        self._prefetch_pending = set()
        self._stale_refreshing = set()      # serve-stale 后台刷新去重
        # 分流规则索引: 10 万条规则线性扫描每查询 20ms+ 严重拖慢 miss 吞吐。
        # 精确规则按域名哈希, 通配规则按 core 后缀哈希; 规则变更时 rebuild。
        self._rule_exact = {}               # lower_domain -> rule
        self._rule_wild = {}                # core -> rule  (匹配 core 及其全部子域)
        self._rule_suffix_wild = {}         # 中缀通配(*x*.com): 固定后缀 -> [(compiled, rule)]
        self._rule_regex = []               # [(compiled, rule)]  re: 前缀(按序首个命中)
        self._rule_allow_exact = {}         # 白名单精确匹配(优先于 block)
        self._rule_allow_wild = {}          # 白名单通配匹配(优先于 block)
        self._rule_match_cache = {}         # domain -> rule/None(哨兵), 规则重建时清空
        self._rule_cache_max = 8192
        self._rebuild_rule_index()
        # Bootstrap 预解析: 用 UDP 上游解析所有 DoH/DoT hostname, 缓存 IP,
        # 后续连接用 IP+SNI, 彻底摆脱系统 /etc/resolv.conf 依赖(限制2解决)。
        # 解析失败的上游回退系统 getaddrinfo, 不影响启动。
        try:
            from . import upstream as _up_mod
            _bs = cfg.get("bootstrap_dns", "223.5.5.5:53")
            _n = _up_mod.bootstrap_resolve_all(cfg.get("upstreams", []), _bs)
            if _n:
                log.info("bootstrap 预解析 %d 个 DoH/DoT hostname → IP+SNI (bootstrap=%s)", _n, _bs)
        except Exception as _e:
            log.warning("bootstrap 预解析失败(回退系统DNS): %s", _e)
        # 上游熔断器: 连续失败达阈值则临时跳过该上游(open 期间), 防止单个
        # 不可达/故障上游拖垮所有 miss 查询; 成功后自动重置。
        self._cb_lock = threading.Lock()
        self._cb = {}  # up_id -> {"fails": int, "until": float}
        self._cb_fails = int(cfg.get("circuit_fails", 3))
        self._cb_open_s = int(cfg.get("circuit_open_s", 30))
        # 限速错误上报: silent 模式下(真实 DNS 流量)查询级错误也必须进
        # events(控制台可见)与 journal(可审计), 但压测/故障高峰每秒可能
        # 数十条同类错误, 不限速会刷爆 events deque 与 systemd journal。
        # 按错误类别每 5s 最多上报一条, 既保留异常可见性又防刷屏。
        self._err_log_ts = {}
        self._err_log_lock = threading.Lock()
        # 共享上游查询线程池：miss 吞吐受限于 worker 数 x 上游并发。
        # 每 miss 并行占用 max_par 个 worker, 池太小会让并发 miss 排队拖垮吞吐。
        # 默认 4 倍余量 -> 单查询并发 x 8, 下限 16, 上限 48, 防止过载时无界排队。
        # 有界队列: 队列满时 submit 阻塞(反压), 防止慢协议高峰任务无界堆积内存。
        up_workers = min(48, max(16, int(cfg.get("max_parallel_upstreams", 3)) * 8))
        self._up_pool = _BoundedExecutor(max_workers=up_workers, max_pending=up_workers * 2,
                                         name="upstream")
        # DoH/DoT/DoQ/DoH3 独立慢池: HTTPS/TLS/QUIC 往返 70-3000ms(含超时), 与
        # UDP 快查询共池会占满 worker 拖垮 miss 吞吐; 分离后 UDP 快路径不受慢
        # 协议阻塞(DoQ/DoH3 的 query 同步阻塞至多 timeout 秒, 若不分离会持续
        # 占用主池 worker, 高并发 miss 时严重挤占 UDP 并发处理能力)。
        # 慢池 worker 按启用慢上游(DoH/DoT/DoQ/DoH3)弹性伸缩: 每个慢上游并发查询
        # 占用一个 worker 至多 timeout 秒, 固定 8 worker 在大量 DoH 上游(如 VM 17
        # 个)时会让慢查询排队, 拖高 miss 延迟。上限 48 防过载无界排队。
        # 容量必须明显大于 并发miss数×慢上游数, 否则 _query_parallel 的阻塞式
        # submit 会卡在慢池队列空位上, 让已完成的 UDP 首答无法及时返回(实测
        # 16 并发全冷域名时 p50 被拖到 754ms)。
        slow_ups = sum(
            1 for u in (cfg.get("upstreams") or [])
            if str(u.get("proto", "")).lower() in ("doh", "dot", "doq", "doh3")
            and u.get("enabled", True)
        )
        doh_workers = min(48, max(12, 12 + slow_ups * 3))
        self._doh_pool = _BoundedExecutor(max_workers=doh_workers, max_pending=doh_workers * 2,
                                          name="up-slow")
        # 预取池: 满则丢弃(错过下轮再取), 避免预取任务无界堆积。
        self._prefetch_pool = _BoundedExecutor(max_workers=4, max_pending=256, name="prefetch")
        # 共享后台收尾池（首答即返后收集其余上游结果）+ 测速探测池
        # 收集池满则丢弃(纯统计, 无副作用), 防止高 miss 率下 _collect_rest 无界堆积
        # (原 4 worker 每秒只能处理约 2.7 个, 提交速率远超则队列无限增长内存)。
        self._collect_pool = _BoundedExecutor(max_workers=4, max_pending=64, name="up-collect")
        # 候选 IP 后台探测池: 零阻塞模式下 miss 查询每遇到无缓存 IP 提交一次探测,
        # 容量需覆盖高峰并发(16 worker × 800ms 超时 ≈ 每秒 20 次探测), 队列满丢弃
        # (下轮/下个域名再测), 不影响查询路径。
        self._probe_pool = _BoundedExecutor(max_workers=16, max_pending=256, name="probe")
        self._prefetch_interval = 1.0
        self._prefetch_scan_idx = 0          # 预取扫描轮转游标(分批扫描, 防大缓存卡顿)
        self._prefetch_batch = 2000          # 每 tick 最多扫描的 key 数(大容量缓存时保证预取时效)
        # 退出停止标志: 防止 interpreter shutdown 时 ThreadPoolExecutor 的
        # threading._shutdown join 因预取持续 submit 新任务而永久阻塞
        # (systemd stop 会因 SIGTERM 后进程不退 90s 超时被 SIGKILL)。
        self._prefetch_stop = threading.Event()
        self._prefetch_thread = threading.Thread(target=self._prefetch_loop, name="prefetch-scan", daemon=True)
        self._prefetch_thread.start()
        # 周期任务线程: 上游健康检查 + 规则/geo 订阅自动更新
        # 间隔秒数可配置(0=关闭); 热重载后下一轮 tick 自动按新配置生效
        self._hc_off = 0  # 健康检查轮转游标(每轮探测不同上游, 防固定前 N 个永不被探)
        self._bg_stop = threading.Event()
        self._bg_thread = threading.Thread(target=self._bg_loop, name="bg-tasks", daemon=True)
        self._bg_thread.start()

    # ---------------- 公共 ---------------- #
    def resolve(self, domain, qtype, silent=False, counted=True, force_refresh=False, client_ip=None, _depth=0):
        """核心解析流程。返回结构化结果 dict (含 rcode)。

        force_refresh=True: 跳过缓存命中直接重新解析(供预取在 TTL 到期前刷新)。
        client_ip: 查询来源客户端 IP, 用于实时查询日志展示; 后台任务(预取/刷新)传 None。
        """
        d = self._normalize(domain)
        qtype = str(qtype).upper()
        if not d:
            return self._error(None, qtype, "empty-domain", "空域名", silent)
        key = self._ckey(d, qtype)
        cfg = self.cfg
        tel = self.tel
        now = time.time()
        t0 = time.monotonic()
        trace = []
        if counted:
            tel.count_query(tel.qtype_cat(qtype))
            tel.count_top(domain=d, client=client_ip)
        trace.append({"tag": "xdp", "text": "XDP Hook 捕获 %s %s 查询 (UDP/53), 提取 (qname, qtype)" % (d, qtype)})
        # ---- IPv6 关闭: AAAA 直接空应答 ----
        if qtype == "AAAA" and not cfg.get("ipv6", True):
            lat = (time.monotonic() - t0) * 1000
            trace.append({"tag": "warn", "text": "IPv6 已禁用 → AAAA 返回空应答 (NODATA)"})
            tel.push_latency(lat)
            if not silent:
                tel.log(d, qtype, "warn", "IPv6 禁用 → NODATA", lat,
                        client_ip=client_ip, upstream="-", answer="")
            return self._result(d, qtype, [], None, False, False, "ipv6-disabled",
                                latency=lat, trace=trace, ttl_left=0, empty=True, rcode=0)
        # ---- 双栈智能 (prefer_ipv4): 替代全局 ipv6 开关的精细化版本 ----
        # 先探测域名是否有 A 记录: 有(双栈) → 屏蔽 AAAA 返回 NODATA(客户端走 IPv4);
        # 无(纯 IPv6 域名) → 正常解析 AAAA。相比 ipv6:false 全局一刀切, 纯 v6
        # 域名不再被误伤。A 探测走缓存快判, 无缓存才查上游(仅首次 AAAA 查询多一次)。
        if qtype == "AAAA" and cfg.get("prefer_ipv4", False):
            if self._probe_a_record(d, trace):
                lat = (time.monotonic() - t0) * 1000
                tel.push_latency(lat)
                trace.append({"tag": "warn", "text": "双栈域名(有 A 记录) → AAAA 屏蔽 (prefer_ipv4)"})
                if not silent:
                    tel.log(d, qtype, "warn", "双栈域名 → AAAA NODATA (prefer_ipv4)", lat,
                            client_ip=client_ip, upstream="双栈判断", answer="")
                return self._result(d, qtype, [], None, False, False, "prefer-ipv4",
                                    latency=lat, trace=trace, ttl_left=0, empty=True, rcode=0)
            trace.append({"tag": "eng", "text": "纯 IPv6 域名(无 A 记录) → 正常解析 AAAA"})
        # ---- BPF LRU 缓存 ----
        # serve-stale 先取过期条目(cache.get 会删除过期条目, 必须先查 stale)
        stale_entry = None
        if not force_refresh and cfg.get("serve_stale", False):
            stale_entry = self.cache.get_stale(key, now, int(cfg.get("stale_ttl", 3600)))
        c = self.cache.get(key, now)
        if c is not None and not force_refresh:
            # 规则复查: 屏蔽规则优先级高于缓存(含内核直答/负缓存/过期兜底), 防止规则添加前已缓存的答案绕过屏蔽
            _rule = self.match_rule(d)
            if _rule and _rule.get("action") == "block":
                tel.inc("errors")
                tel.inc_rule("block")
                lat = (time.monotonic() - t0) * 1000
                trace.append({"tag": "rule", "text": "分流规则 [%s] 命中(缓存命中复查): 屏蔽该域名 → SERVFAIL" % _rule.get("match")})
                if not silent:
                    tel.log(d, qtype, "rule", "规则屏蔽(缓存命中复查) → SERVFAIL", lat,
                            client_ip=client_ip, upstream="规则屏蔽", answer="", rule=self._rule_label(_rule))
                self._err_report(key, d, qtype, "SERVFAIL (规则屏蔽 %s)" % _rule.get("match"), lat,
                                 client_ip=client_ip, upstream="规则屏蔽", answer="")
                return self._result(d, qtype, [], None, False, True, "blocked",
                                    latency=lat, trace=trace, ttl_left=0, rcode=2)
            lat = (time.monotonic() - t0) * 1000
            if counted:
                tel.inc("hit")
            if cfg.get("kernel_direct", True) and c.get("rcode", 0) == 0:
                tel.inc("kernel_direct")
            ttl_left = max(0, int(c["expires_at"] - now))
            tel.push_latency(lat)
            if c.get("rcode") == 3:
                # 负缓存 NXDOMAIN
                trace.append({"tag": "bpf", "text": "BPF LRU map 命中 (负缓存 NXDOMAIN, TTL 剩余 %ds)" % ttl_left})
                trace.append({"tag": "ok", "text": "应答 NXDOMAIN  耗时 %.2fms" % lat})
                if not silent:
                    tel.log(d, qtype, "hit", "缓存直答 NXDOMAIN", lat,
                            client_ip=client_ip, upstream="缓存直答", answer="NXDOMAIN",
                            rule=self._rule_label(_rule) if _rule else None)
                return self._result(d, qtype, [], None, True, False, None,
                                    latency=lat, trace=trace, ttl_left=ttl_left, rcode=3)
            mode = "内核直接构造应答" if cfg.get("kernel_direct", True) else "用户态直答(内核直答已关闭)"
            trace.append({"tag": "bpf", "text": "BPF LRU map 命中 (TTL 剩余 %ds), %s" % (ttl_left, mode)})
            trace.append({"tag": "ok", "text": "应答 %s  耗时 %.2fms (%s)" % (c["chosen"], lat, "内核直答" if cfg.get("kernel_direct", True) else "缓存直答")})
            if not silent:
                tel.log(d, qtype, "hit", "内核直答 → %s" % c["chosen"], lat,
                        client_ip=client_ip,
                        upstream="内核直答" if cfg.get("kernel_direct", True) else "缓存直答",
                        answer=c["chosen"], rule=self._rule_label(_rule) if _rule else None)
            self.schedule_prefetch(key, d, qtype, ttl_left)  # 命中即续入预取队列(与持久化恢复配合)
            return self._result(d, qtype, c["answers"], c["chosen"], True, False, None,
                                latency=lat, trace=trace, ttl_left=ttl_left, rcode=0)
        # ---- 过期缓存兜底 (serve-stale): 缓存过期但在 stale 窗口内 ----
        if stale_entry is not None:
            _rule = self.match_rule(d)
            if _rule and _rule.get("action") == "block":
                tel.inc("errors")
                tel.inc_rule("block")
                lat = (time.monotonic() - t0) * 1000
                trace.append({"tag": "rule", "text": "分流规则 [%s] 命中(过期缓存复查): 屏蔽该域名 → SERVFAIL" % _rule.get("match")})
                if not silent:
                    tel.log(d, qtype, "rule", "规则屏蔽(过期缓存复查) → SERVFAIL", lat,
                            client_ip=client_ip, upstream="规则屏蔽", answer="", rule=self._rule_label(_rule))
                self._err_report(key, d, qtype, "SERVFAIL (规则屏蔽 %s)" % _rule.get("match"), lat,
                                 client_ip=client_ip, upstream="规则屏蔽", answer="")
                return self._result(d, qtype, [], None, False, True, "blocked",
                                    latency=lat, trace=trace, ttl_left=0, rcode=2)
            lat = (time.monotonic() - t0) * 1000
            if counted:
                tel.inc("hit")
                tel.inc("stale_served")
            tel.push_latency(lat)
            rcode = stale_entry.get("rcode", 0)
            if rcode == 3:
                trace.append({"tag": "bpf", "text": "过期缓存兜底: NXDOMAIN 负缓存(已过期, TTL 0s)"})
                trace.append({"tag": "ok", "text": "应答 NXDOMAIN(serve-stale)  耗时 %.2fms" % lat})
                if not silent:
                    tel.log(d, qtype, "hit", "serve-stale NXDOMAIN", lat,
                            client_ip=client_ip, upstream="serve-stale", answer="")
                return self._result(d, qtype, [], None, True, False, None,
                                    latency=lat, trace=trace, ttl_left=0, rcode=3)
            ans = [dict(a, ttl=0) for a in stale_entry.get("answers", [])]  # 下发 TTL=0: 告知客户端勿缓存
            chosen = stale_entry.get("chosen", "") or (ans[0]["value"] if ans else "")
            trace.append({"tag": "bpf", "text": "过期缓存兜底 serve-stale: 返回旧数据 %s (TTL 0s), 后台刷新中" % chosen})
            trace.append({"tag": "ok", "text": "应答 %s(serve-stale)  耗时 %.2fms" % (chosen, lat)})
            if not silent:
                tel.log(d, qtype, "hit", "serve-stale → %s" % chosen, lat,
                        client_ip=client_ip, upstream="serve-stale", answer=chosen)
            self._trigger_stale_refresh(key, d, qtype)
            return self._result(d, qtype, ans, chosen, True, False, None,
                                latency=lat, trace=trace, ttl_left=0, rcode=0)
        if counted:
            tel.inc("miss")
        trace.append({"tag": "bpf", "text": "BPF LRU map 未命中 → 转交用户态解析引擎"})
        # ---- 分流规则 ----
        rule = self.match_rule(d)
        # ---- 白名单(allow): 命中即放行, 跳过 block 检查, 正常走上游解析 ----
        if rule and rule.get("action") == "allow":
            tel.inc_rule("allow")
            trace.append({"tag": "rule", "text": "白名单 [%s] 命中: 放行, 正常解析" % rule.get("match")})
            if not silent:
                tel.log(d, qtype, "rule", "白名单放行 → 正常解析", 0,
                        client_ip=client_ip, upstream="白名单", answer="", rule=self._rule_label(rule))
            rule = None  # 置空, 后续 block/group/forceIp 分支均不触发
        if rule and rule.get("action") == "block":
            tel.inc("errors")
            tel.inc_rule("block")
            lat = (time.monotonic() - t0) * 1000
            trace.append({"tag": "rule", "text": "分流规则 [%s] 命中: 屏蔽该域名 → 返回 SERVFAIL" % rule.get("match")})
            if not silent:
                tel.log(d, qtype, "rule", "规则屏蔽 → SERVFAIL", lat,
                        client_ip=client_ip, upstream="规则屏蔽", answer="", rule=self._rule_label(rule))
            self._err_report(key, d, qtype, "SERVFAIL (规则屏蔽 %s)" % rule.get("match"), lat,
                             client_ip=client_ip, upstream="规则屏蔽", answer="")
            return self._result(d, qtype, [], None, False, True, "blocked",
                                latency=lat, trace=trace, ttl_left=0, rcode=2)
        ups = [u for u in cfg.get("upstreams", []) if u.get("enabled", True)]
        if rule and rule.get("action") == "group":
            g = rule.get("group")
            tel.inc_rule("domestic" if g == "domestic" else "global")
            filtered = [u for u in ups if u.get("group") == g]
            if filtered:
                ups = filtered
            trace.append({"tag": "rule", "text": "分流规则 [%s] 命中: 仅使用「%s」组上游" % (rule.get("match"), g)})
            if not silent:
                tel.log(d, qtype, "rule", "分流规则 → 「%s」组" % g, 0,
                        client_ip=client_ip, upstream="分流规则", answer="", rule=self._rule_label(rule))
        if rule and rule.get("action") == "forceIp":
            tel.inc_rule("forceIp")
            ip = rule.get("ip", "")
            rtype = self._guess_type(ip, qtype)
            lat = (time.monotonic() - t0) * 1000
            rttl = self._clamp_ttl(cfg.get("ttl", 300), rule)   # 规则级 TTL 覆盖
            ans = [{"value": ip, "from": "分流规则", "ttl": rttl, "type": rtype}]
            self._fill_cache(key, d, qtype, ans, rule=rule)
            trace.append({"tag": "rule", "text": "分流规则 [%s] 强制 IP: %s (TTL %ds)" % (rule.get("match"), ip, rttl)})
            trace.append({"tag": "ok", "text": "应答 %s  耗时 %.2fms" % (ip, lat)})
            if not silent:
                tel.log(d, qtype, "rule", "分流规则 → %s" % ip, lat,
                        client_ip=client_ip, upstream="分流规则", answer=ip, rule=self._rule_label(rule))
            return self._result(d, qtype, ans, ip, False, False, None,
                                latency=lat, trace=trace, ttl_left=rttl, rcode=0)
        if not ups:
            tel.inc("errors")
            lat = (time.monotonic() - t0) * 1000
            trace.append({"tag": "warn", "text": "无可用上游 (全部被禁用) → SERVFAIL"})
            self._err_report(key, d, qtype, "SERVFAIL (无上游)", lat,
                             client_ip=client_ip, upstream="无上游", answer="")
            return self._result(d, qtype, [], None, False, True, "no-upstream",
                                latency=lat, trace=trace, ttl_left=0, rcode=2)
        if cfg.get("fallback", True):
            # 全部可用上游并发查询, 首答即返(测速择优): 不再截断前 N 个
            trace.append({"tag": "eng", "text": "解析失败降级开 → 并发查询全部 %d 个可用上游: %s" % (len(ups), " / ".join(u["name"] for u in ups))})
        else:
            ups = ups[:1]
            trace.append({"tag": "warn", "text": "解析失败降级关 → 仅用首选上游 %s (失败即 SERVFAIL)" % ups[0]["name"]})
        # ---- 构造查询（EDNS + 防分片 + 加密填充） ----
        # 按上游协议分组构造: 明文 UDP/TCP 用不填充报文; DoT/DoH/DoH3/DoQ 等
        # 加密协议在 EDNS OPT 中携带 Padding 选项(抹平长度指纹, RFC 8467)。
        # EDNS UDP size 全部钳制到 edns_udp_size(默认 1232 防分片安全值)。
        qmap = self._build_query_map(d, qtype)
        query_bytes = qmap["default"]
        # ---- 多上游并发 ----
        results = self._query_parallel(ups, query_bytes, d, qtype, trace, qmap=qmap)
        tel.inc("upstream_queries", len(ups))
        ok_results = [r for r in results if r.get("answers")]
        if not ok_results:
            # 全部无答案 → 区分 NXDOMAIN / NODATA / 真失败
            nx = [r for r in results if r.get("rcode") == 3]
            if nx:
                lat = (time.monotonic() - t0) * 1000
                # 负缓存 TTL: 默认 [10,60] 秒, 再经 _clamp_ttl 统一受 ttl_min/ttl_max 管控。
                # 修复: 旧逻辑 max(neg_ttl, min(mn,60)) 在 ttl_max 生效时会"抬高"而非钳制,
                # 导致负缓存 TTL 不服从 TTL 管控(如 ttl_max=30 时负缓存仍 45s)。
                neg_ttl = max(10, self._clamp_ttl(min(int(cfg.get("ttl", 300)), 60), rule))
                self.cache.put(key, {
                    "domain": d, "qtype": qtype, "answers": [], "chosen": "",
                    "ttl": neg_ttl, "rcode": 3,
                    "expires_at": time.time() + neg_ttl, "access_at": time.time(),
                })
                tel.push_latency(lat)
                trace.append({"tag": "eng", "text": "上游确认域名不存在 (NXDOMAIN), 负缓存 %ds" % neg_ttl})
                if not silent:
                    tel.log(d, qtype, "miss", "NXDOMAIN (负缓存)", lat,
                            client_ip=client_ip,
                            upstream=" / ".join(r.get("up_name", "?") for r in nx[:3]),
                            answer="")
                # 负缓存不预取: 域名不存在, 重复解析无意义, 也避免预取风暴
                return self._result(d, qtype, [], None, False, False, None,
                                    latency=lat, trace=trace, ttl_left=neg_ttl, rcode=3)
            # ---- CNAME 链跟踪: 上游返回 CNAME 但无目标类型答案 → 展开到终点 ----
            cname_res = [r for r in results if r.get("cnames")]
            if cname_res and qtype in ("A", "AAAA") and _depth < 8:
                lat = (time.monotonic() - t0) * 1000
                tgt, tgt_ttl = cname_res[0]["cnames"][0]
                chain = [{"value": tgt, "ttl": self._clamp_ttl(tgt_ttl, rule),
                          "type": dnsmsg.TYPE_CNAME}]
                sub = self.resolve(tgt, qtype, silent=silent, counted=False,
                                   client_ip=client_ip, _depth=_depth + 1)
                sub_ans = sub.get("answers") or []
                if not sub.get("error") and sub_ans:
                    answers = chain + sub_ans
                    self._fill_cache(key, d, qtype, answers, rule=rule)
                    tel.push_latency(lat)
                    trace.append({"tag": "eng",
                                  "text": "CNAME 链展开 %s → %s (%d 条答案)" % (d, tgt, len(sub_ans))})
                    if not silent:
                        tel.log(d, qtype, "miss", "CNAME 展开 → %s" % sub.get("chosen", tgt), lat,
                                client_ip=client_ip,
                                upstream=" / ".join(r.get("up_name", "?") for r in cname_res[:3]),
                                answer=sub.get("chosen", ""), rule=self._rule_label(rule))
                    return self._result(d, qtype, answers, answers[-1]["value"],
                                        False, False, None, latency=lat,
                                        trace=trace, ttl_left=answers[-1].get("ttl", 0), rcode=0)
                # 展开失败(目标无答案/出错): 退回 NODATA 语义继续
                trace.append({"tag": "warn", "text": "CNAME 链展开失败 %s → %s (NODATA)" % (d, tgt)})
            nodata = [r for r in results if r.get("rcode") == 0]
            if nodata:
                # IPv4 优先: AAAA 查询无记录时回退查询 A（命中缓存或上游）
                if qtype == "AAAA" and cfg.get("ipv4_first", True):
                    fall = self._ipv4_fallback(d, ups, cfg, trace)
                    if fall:
                        lat = (time.monotonic() - t0) * 1000
                        tel.push_latency(lat)
                        tel.inc("ipv4_fallback")
                        if not silent:
                            tel.log(d, qtype, "miss", "IPv4 回退 → %s" % fall[0]["value"], lat,
                                    client_ip=client_ip,
                                    upstream="IPv4回退:" + fall[0].get("from", "?"),
                                    answer=fall[0]["value"])
                        return self._result(d, qtype, fall, fall[0]["value"], False, False, None,
                                            latency=lat, trace=trace, ttl_left=cfg.get("ttl", 300), rcode=0)
                lat = (time.monotonic() - t0) * 1000
                tel.push_latency(lat)
                trace.append({"tag": "eng", "text": "上游无该类型记录 (NODATA) → 空应答 NOERROR"})
                if not silent:
                    tel.log(d, qtype, "miss", "NODATA", lat,
                            client_ip=client_ip,
                            upstream=" / ".join(r.get("up_name", "?") for r in nodata[:3]),
                            answer="")
                return self._result(d, qtype, [], None, False, False, None,
                                    latency=lat, trace=trace, ttl_left=0, empty=True, rcode=0)
            # ---- 启动预热重试: 冷启动/重启早期(45s)上游 TLS 未就绪, 全部失败时
            #      延迟 1s 重试一次, 避免用户刚部署/重启就遇到 SERVFAIL。全局至多
            #      3 次, 稳态完全不受影响(压测/故障高峰不会放大延迟)。
            boot_warm = (time.monotonic() - self._boot_ts) < 45
            if boot_warm:
                retry = False
                with self._boot_retry_lock:
                    if self._boot_retries < 4:
                        self._boot_retries += 1
                        retry = True
                if retry:
                    trace.append({"tag": "warn", "text": "启动预热: 上游未就绪, 2s 后重试"})
                    time.sleep(2.0)
                    return self.resolve(d, qtype, silent=silent, counted=False,
                                        force_refresh=force_refresh,
                                        client_ip=client_ip, _depth=_depth + 1)
            tel.inc("errors")
            lat = (time.monotonic() - t0) * 1000
            tel.push_latency(lat)
            trace.append({"tag": "warn", "text": "全部上游失败 → 返回 SERVFAIL"})
            self._err_report(key, d, qtype, "SERVFAIL (上游全部失败)", lat,
                             client_ip=client_ip,
                             upstream=" / ".join(r.get("up_name", "?") for r in results[:3]),
                             answer="")
            return self._result(d, qtype, [], None, False, True, "no-answer",
                                latency=lat, trace=trace, ttl_left=0, rcode=2)
        # ---- 汇总候选（去重） ----
        cand = {}
        for r in ok_results:
            for a in r["answers"]:
                v = a["value"]
                if v not in cand:
                    proto = str(r.get("proto", "udp")).lower()
                    cand[v] = {"value": v, "from": [], "ttl": a.get("ttl", cfg.get("ttl", 300)),
                               "type": a.get("type", dnsmsg.type_code(qtype)), "lat": r["lat"],
                               "probe": "tcp443" if proto in ("doh", "dot", "doq", "doh3") else "udp53"}
                if r["up_name"] not in cand[v]["from"]:
                    cand[v]["from"].append(r["up_name"])
                cand[v]["ttl"] = min(cand[v]["ttl"], a.get("ttl", cand[v]["ttl"]))
        cand_list = list(cand.values())
        # ---- 测速择优 ----
        if cfg.get("speed_test", True) and len(cand_list) > 1:
            cand_list = self._speed_sort(cand_list, query_bytes, d)
            trace.append({"tag": "eng", "text": "测速择优(EWMA+加权随机): 首选 %s (%dms)" % (cand_list[0]["value"], cand_list[0].get("measured", 0))})
        else:
            trace.append({"tag": "eng", "text": "按序应答, 首选 %s" % cand_list[0]["value"]})
        answers = [{"value": a["value"], "from": "+".join(a["from"]),
                    "ttl": a["ttl"], "type": a["type"]} for a in cand_list]
        chosen = answers[0]["value"]
        # ---- 回填缓存 ----
        raw_ttl = min(cfg.get("ttl", 300), min((a["ttl"] for a in answers), default=cfg.get("ttl", 300)))
        ttl = self._clamp_ttl(raw_ttl, rule)   # 规则级 TTL 覆盖全局 ttl_min/ttl_max
        self._fill_cache(key, d, qtype, answers, rule=rule)
        lat = (time.monotonic() - t0) * 1000
        tel.push_latency(lat)
        trace.append({"tag": "bpf", "text": "回填 BPF LRU map (TTL %ds, 当前占用 %d/%d)" % (ttl, self.cache.size(), self.cache.capacity)})
        trace.append({"tag": "ok", "text": "应答 %s  总耗时 %.1fms" % (chosen, lat)})
        if not silent:
            tel.log(d, qtype, "miss", "多上游解析 → %s" % chosen, lat,
                    client_ip=client_ip,
                    upstream=" / ".join(a["from"] for a in answers[:3]) or results[0].get("up_name", "?"),
                    answer=chosen)
        self.schedule_prefetch(key, d, qtype, ttl)
        return self._result(d, qtype, answers, chosen, False, False, None,
                            latency=lat, trace=trace, ttl_left=ttl, rcode=0)

    # ---------------- DNS 服务器入口 ---------------- #
    def answer_fast(self, raw_query, client_addr=None, msg=None):
        """缓存命中快路径：主线程直接查 LRU 并构造应答, 避免线程池调度与完整
        解析流水线开销。命中返回应答 bytes；未命中返回 None（调用方转交完整路径）。
        仅缓存命中时更新遥测, miss 不计数以免与完整路径重复。
        msg 可传入已解析报文（server 主循环解析一次, miss 时传给完整路径避免重复解析）。"""
        if msg is None:
            try:
                msg = dnsmsg.parse_message(raw_query)
            except Exception:
                return None
        if not msg["questions"]:
            return None
        if isinstance(client_addr, (tuple, list)) and client_addr:
            client_addr = client_addr[0]   # server 传 (host, port), 日志只显示 IP
        q = msg["questions"][0]
        if q["qclass"] != dnsmsg.CLASS_IN:
            return None
        domain, qtype_name = q["name"], dnsmsg.type_name(q["qtype"])
        key = self._ckey(domain, qtype_name)
        t0 = time.monotonic()
        now = time.time()
        # serve-stale 先取过期条目(cache.get 会删除过期条目, 必须先查 stale)
        stale_entry = None
        if self.cfg.get("serve_stale", False):
            stale_entry = self.cache.get_stale(key, now, int(self.cfg.get("stale_ttl", 3600)))
        c = self.cache.get(key, now)
        stale = False
        if c is None and stale_entry is not None:
            # 过期缓存兜底: 返回旧数据(TTL=0)并触发后台刷新, 避免上游故障/网络抖动
            # 时内网客户端拿到 SERVFAIL; 刷新完成后恢复新鲜缓存。
            c = stale_entry
            stale = True
        if c is None:
            return None
        tel = self.tel
        rcode = c.get("rcode", 0)
        if stale:
            tel.inc("stale_served")
            self._trigger_stale_refresh(key, domain, qtype_name)
        # 预编码响应体缓存: 同一缓存条目的 question+answer section 固定,
        # 只随 qid 变化的 header 每次重拼。首答时编码一次存入条目, 后续命中
        # 直接复用, 省去 encode_name/encode_rdata 热路径开销。
        # serve-stale 不复用(须下发 TTL=0, 且旧预编码不应污染缓存条目)。
        if rcode == 3:
            body = c.get("resp_body")
            if body is None or stale:
                body = dnsmsg.build_response_body(domain, q["qtype"], [])
                if not stale:
                    c["resp_body"] = body
            resp = dnsmsg.build_response_header(raw_query, 3, 0) + body
            tel.fast_hit(qtype_name, len(raw_query), len(resp) if resp else 0,
                         (time.monotonic() - t0) * 1000)
            # 快路径命中 → 实时查询日志(带客户端IP), 与完整路径事件同构
            try:
                tel.log(domain, qtype_name, "hit", "缓存直答 NXDOMAIN",
                        (time.monotonic() - t0) * 1000,
                        client_ip=client_addr, upstream="缓存直答", answer="NXDOMAIN")
            except Exception:
                pass
            return resp
        if rcode == 0:
            if stale:
                # serve-stale: 下发 TTL=0(告知客户端勿缓存), 后台刷新中
                body = dnsmsg.build_response_body(domain, q["qtype"],
                                                  [dict(a, ttl=0) for a in c["answers"]])
            else:
                body = c.get("resp_body")
                if body is None:
                    body = dnsmsg.build_response_body(domain, q["qtype"], c["answers"])
                    c["resp_body"] = body
            resp = dnsmsg.build_response_header(raw_query, 0, len(c["answers"])) + body
            tel.fast_hit(qtype_name, len(raw_query), len(resp) if resp else 0,
                         (time.monotonic() - t0) * 1000,
                         kernel_direct=self.cfg.get("kernel_direct", True) and not stale)
            # 快路径命中 → 实时查询日志(带客户端IP)
            try:
                chosen = c.get("chosen", "") or (c["answers"][0]["value"] if c.get("answers") else "")
                tel.log(domain, qtype_name, "hit",
                        ("serve-stale → %s" if stale else "内核直答 → %s") % chosen,
                        (time.monotonic() - t0) * 1000,
                        client_ip=client_addr,
                        upstream="serve-stale" if stale else ("内核直答" if self.cfg.get("kernel_direct", True) else "缓存直答"),
                        answer=chosen)
            except Exception:
                pass
            return resp
        return None

    def answer_raw(self, raw_query, client_addr=None, parsed=None):
        """解析一条原始 DNS 查询报文，返回响应报文 bytes。
        parsed 可传入预解析结果（server 快路径已解析时避免重复解析）。"""
        if isinstance(client_addr, (tuple, list)) and client_addr:
            client_addr = client_addr[0]   # server 传 (host, port), 日志只显示 IP
        if parsed is None:
            try:
                msg = dnsmsg.parse_message(raw_query)
            except Exception:
                return dnsmsg.build_error_response(raw_query, 2)
        else:
            msg = parsed
        if not msg["questions"]:
            return dnsmsg.build_error_response(raw_query, 1)
        q = msg["questions"][0]
        domain, qtype = q["name"], q["qtype"]
        qtype_name = dnsmsg.type_name(qtype)
        if q["qclass"] != dnsmsg.CLASS_IN:
            return dnsmsg.build_error_response(raw_query, 4)
        res = self.resolve(domain, qtype_name, silent=False, client_ip=client_addr)
        self.tel.inc("bytes_in", len(raw_query))
        rcode = res.get("rcode", 2)
        if res.get("error"):
            return dnsmsg.build_error_response(raw_query, 2 if rcode == 2 else rcode)
        answers = res.get("answers", [])
        resp = dnsmsg.build_response(raw_query, domain, qtype, answers, rcode=rcode)
        if resp:
            self.tel.inc("bytes_out", len(resp))
        return resp

    # ---------------- 内部 ---------------- #
    def _err_report(self, key, d, qtype, msg, lat, interval=5.0, client_ip=None,
                    upstream=None, answer=""):
        """限速错误上报: 查询级错误写 events + journal, 每 key 5s 最多一条。

        silent=True 的真实 DNS 流量路径(server 线程)同样上报——"不屏蔽任何
        异常"要求 journal 可见查询级错误; 限速保证压测/上游故障高峰不刷屏。
        """
        now = time.monotonic()
        with self._err_log_lock:
            last = self._err_log_ts.get(key, 0)
            if now - last < interval:
                return
            self._err_log_ts[key] = now
            # 限长: 长时间压测随机域名时错误类别 key 无限增长(内存泄漏防护)
            if len(self._err_log_ts) > 8192:
                try:
                    self._err_log_ts.popitem(last=False)
                except Exception:
                    pass
        log.warning("%s %s: %s (%.1fms)", d, qtype, msg, lat)
        try:
            self.tel.log(d, qtype, "err", msg, round(lat, 1),
                         client_ip=client_ip, upstream=upstream, answer=answer)
        except Exception:
            pass

    def _cb_fail(self, up_id):
        """上游查询失败: 失败计数++, 达阈值打开熔断。"""
        with self._cb_lock:
            st = self._cb.setdefault(up_id, {"fails": 0, "until": 0.0})
            st["fails"] += 1
            if st["fails"] >= self._cb_fails:
                st["until"] = time.time() + self._cb_open_s

    def _cb_ok(self, up_id):
        """上游查询成功: 关闭熔断, 计数清零。"""
        with self._cb_lock:
            self._cb[up_id] = {"fails": 0, "until": 0.0}

    def _cb_is_open(self, up_id):
        with self._cb_lock:
            st = self._cb.get(up_id)
            if not st:
                return False
            if st["until"] and time.time() < st["until"]:
                return True
            return False

    def _build_query_map(self, d, qtype):
        """按上游协议分组构造查询报文。

        - 明文 UDP/TCP: 不填充(填充只增大报文无收益)
        - 加密 DoT/DoH/DoH3/DoQ: EDNS OPT 携带 Padding 选项, 抹平长度指纹
          (RFC 8467), 防流量分析通过报文长度推断查询内容
        - 全部协议: EDNS UDP size 钳制到 edns_udp_size(默认 1232 防分片安全值)
        返回 {proto: bytes, "default": bytes}; default 供无协议上下文时使用。
        """
        cfg = self.cfg
        edns = bool(cfg.get("edns", True))
        size = int(cfg.get("edns_udp_size", 1232) or 1232)
        pad = bool(cfg.get("padding", False))
        qt = dnsmsg.type_code(qtype)
        # DNS 0x20 投毒防护: 明文 UDP/TCP 查询名做大小写随机(默认开启), 增加
        # 约 26bit 熵; 加密协议(DoT/DoH/DoH3/DoQ)无投毒面不需要。
        use0x20 = bool(cfg.get("dnssec_0x20", True))
        qd = dnsmsg.random_case_name(d) if use0x20 else d
        plain, _q1 = dnsmsg.build_query(qd, qt, edns=edns,
                                        edns_client_subnet=cfg.get("edns_client_subnet"),
                                        udp_size=size, padding=False)
        enc, _q2 = dnsmsg.build_query(d, qt, edns=edns,
                                      edns_client_subnet=cfg.get("edns_client_subnet"),
                                      udp_size=size, padding=pad)
        return {"udp": plain, "tcp": plain, "doh": enc, "dot": enc, "doq": enc,
                "doh3": enc, "default": enc if pad else plain}

    def _probe_a_record(self, d, trace):
        """双栈探测: 判断域名是否有 A 记录(供 prefer_ipv4 屏蔽 AAAA 用)。

        先查 (d,"A") 缓存(快判零上游开销): 有答案 → 双栈; NXDOMAIN/NODATA 负
        缓存 → 纯 v6。无缓存才向上游查 A(仅首次 AAAA 查询多一次上游往返),
        有答案回填 A 缓存供后续快判。查询失败按纯 v6 处理(不误伤 v6 域名)。
        """
        key = self._ckey(d, "A")
        now = time.time()
        c = self.cache.get(key, now)
        if c is not None:
            if c.get("rcode") == 0 and c.get("answers"):
                trace.append({"tag": "eng", "text": "双栈探测: A 缓存命中 → 双栈域名"})
                return True
            trace.append({"tag": "eng", "text": "双栈探测: A 缓存确认无 A 记录 → 纯 IPv6 域名"})
            return False
        ups = [u for u in self.cfg.get("upstreams", []) if u.get("enabled", True)]
        if not ups:
            trace.append({"tag": "warn", "text": "双栈探测: 无可用上游, 按纯 IPv6 处理"})
            return False
        qmap = self._build_query_map(d, "A")
        rs = self._query_parallel(ups, qmap["default"], d, "A", trace, qmap=qmap)
        ok = [r for r in rs if r.get("answers")]
        if ok:
            ans, seen = [], set()
            for r in ok:
                for a in r["answers"]:
                    v = a["value"]
                    if v not in seen:
                        seen.add(v)
                        ans.append({"value": v, "from": r["up_name"],
                                    "ttl": a.get("ttl", 300), "type": a.get("type", 1)})
            self._fill_cache(key, d, "A", ans)
            trace.append({"tag": "eng", "text": "双栈探测: 上游确认有 A 记录 → 双栈域名"})
            return True
        trace.append({"tag": "eng", "text": "双栈探测: 上游无 A 记录 → 按纯 IPv6 处理"})
        return False

    def _ipv4_fallback(self, d, ups, cfg, trace):
        """IPv4 优先: AAAA 查询无记录时回退查询 A 记录。命中缓存则直取。"""
        now = time.time()
        c = self.cache.get(self._ckey(d, "A"), now)
        if c and c.get("answers"):
            trace.append({"tag": "eng", "text": "IPv4 优先回退: AAAA NODATA, 命中 A 缓存 → %s" % c["answers"][0]["value"]})
            return c["answers"]
        qmap = self._build_query_map(d, "A")
        a_q = qmap["default"]
        rs = self._query_parallel(ups, a_q, d, "A", trace, qmap=qmap)
        ok = [r for r in rs if r.get("answers")]
        if not ok:
            trace.append({"tag": "warn", "text": "IPv4 回退: 上游也无 A 记录 → 维持 NODATA"})
            return None
        cand = {}
        for r in ok:
            for a in r["answers"]:
                v = a["value"]
                if v not in cand:
                    cand[v] = {"value": v, "from": r["up_name"], "ttl": a.get("ttl", 300),
                               "type": a.get("type", 1)}
        ans = list(cand.values())
        self._fill_cache(self._ckey(d, "A"), d, "A", ans)
        trace.append({"tag": "eng", "text": "IPv4 优先回退: AAAA NODATA, 上游查得 A → %s" % ans[0]["value"]})
        return ans

    def _query_parallel(self, ups, query_bytes, d, qtype, trace, qmap=None):
        """并发查询多个上游，首个有效应答（NOERROR 且有答案）即返回。

        熔断打开的上游会被临时跳过（不参与并发）; 若全部被跳过则兜底全部重试。
        qmap: 可选按协议分组的查询报文 {proto: bytes, default: bytes}——
              加密协议(DoT/DoH/DoH3/DoQ)用带 Padding 填充的报文, 明文用普通报文。

        不再等待所有上游（避免被最慢/超时上游拖累, 降低 miss 查询延迟）;
        未完成的上游结果交给后台线程收集, 仅用于遥测统计, 不阻塞客户端。
        返回列表, 每项: {ok, up_name, lat, rcode, answers, nodata}
        rcode: 0=NOERROR  3=NXDOMAIN  None=网络失败/超时
        """
        timeout = int(self.cfg.get("timeout_ms", 1500))
        # 慢上游降级: 滚动平均延迟明显高于超时阈值(>timeout*0.6 且 >800ms)的上游
        # 不参与常规查询(测速/健康度展示仍保留, 熔断恢复探测不受影响), 防止慢上游
        # 持续占用慢池 worker(每个查询至多 timeout 秒)拖垮高并发 miss 吞吐——
        # 实测 opendns 等国外 DoH 国内直连 1.5s+, 若不禁用会在高峰期把 DoH 池占满,
        # 其他上游查询排队超时, 平均延迟从几百 ms 飙到几千 ms。
        _tel = self.tel
        SLOW_THRESH = max(800, int(timeout * 0.6))

        def _is_slow_up(u):
            try:
                st = _tel.upstream_stat(u.get("id"))
            except Exception:
                return False
            if not st or st.get("ok", 0) < 10:  # 采样不足不判定, 避免单次抖动误杀
                return False
            return st["lat_sum"] / st["ok"] > SLOW_THRESH

        healthy = [u for u in ups if not self._cb_is_open(u.get("id")) and not _is_slow_up(u)]
        if not healthy:
            healthy = [u for u in ups if not self._cb_is_open(u.get("id"))]  # 全部偏慢则降级为仅熔断过滤
        if not healthy:
            healthy = ups  # 全部熔断时兜底仍尝试, 上游可能已恢复
        fut2u = {}
        for u in healthy:
            if str(u.get("proto", "udp")).lower() in ("doh", "dot", "doq", "doh3"):
                pool = self._doh_pool
            else:
                pool = self._up_pool
            qb = query_bytes
            if qmap:
                qb = qmap.get(str(u.get("proto", "udp")).lower(), qmap.get("default", query_bytes))
            fut2u[pool.submit(query_upstream, u, qb, timeout)] = u
        pending = set(fut2u)
        out = []
        while pending:
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for fut in done:
                out.append(self._classify_one(fut2u[fut], fut, qtype, trace, query_bytes))
            if any(r.get("answers") for r in out):
                # 有答案 → 首答即返: 其余由后台线程收尾(仅统计)
                if pending:
                    self._collect_rest_in_background(pending, fut2u, qtype, trace)
                    pending = set()
                return out
            if any(r.get("rcode") == 3 for r in out):
                # NXDOMAIN 也是确定性结论(域名不存在): 无需等其余上游,
                # 避免虚构/不存在域名被慢/不可达上游拖到超时(严重拉低 miss 吞吐)
                if pending:
                    self._collect_rest_in_background(pending, fut2u, qtype, trace)
                    pending = set()
                return out
        return out

    @staticmethod
    def _conn_key(u):
        """连接维度健康度 key: proto|addr|port|url(同上游多协议/多 IP 各自独立统计)。"""
        return "%s|%s|%s|%s" % (str(u.get("proto", "")).lower(),
                                u.get("addr", ""), u.get("port", ""), u.get("url", ""))

    def _classify_one(self, u, fut, qtype, trace, query_bytes=None):
        """处理单个上游查询结果: 解析、分类、更新遥测统计。"""
        timeout = int(self.cfg.get("timeout_ms", 1500))
        try:
            ok, data, lat, _ = fut.result()
        except Exception:
            ok, data, lat = False, None, timeout
        if ok and data:
            try:
                parsed = dnsmsg.parse_message(data)
            except Exception:
                parsed = None
            # ---- UDP 截断(TC=1)自动 TCP 回退: 大响应(如 DNSSEC/大量A记录)UDP 装不下时,
            # 上游返回 truncated 标志, 自动切 TCP 重查同一上游获取完整应答 ----
            if parsed is not None and parsed.get("truncated") and str(u.get("proto", "udp")).lower() == "udp":
                trace.append({"tag": "eng", "text": "%-12s UDP 应答截断(TC=1) → TCP 回退重查" % u["name"][:12]})
                try:
                    tcp_ok, tcp_data = _tcp_query(u, query_bytes, timeout)
                except Exception:
                    tcp_ok, tcp_data = False, None
                if tcp_ok and tcp_data:
                    try:
                        parsed = dnsmsg.parse_message(tcp_data)
                    except Exception:
                        parsed = None
                    trace.append({"tag": "ok", "text": "%-12s TCP 回退成功, 应答 %d bytes" % (u["name"][:12], len(tcp_data))})
                else:
                    trace.append({"tag": "warn", "text": "%-12s TCP 回退失败, 沿用截断应答" % u["name"][:12]})
            if parsed is not None:
                rcode = parsed.get("rcode")
                if rcode == 0:
                    ans = self._extract_answers(parsed, qtype)
                    if ans:
                        self.tel.upstream_ok(u["id"], lat)
                        self.tel.conn_ok(self._conn_key(u), lat)
                        self._cb_ok(u["id"])
                        for a in ans:
                            trace.append({"tag": "ans", "text": "%-12s %s  %dms" % (u["name"][:12], a["value"], lat)})
                        return {"ok": True, "up_name": u["name"], "lat": lat,
                                "proto": str(u.get("proto", "udp")).lower(),
                                "rcode": 0, "answers": ans}
                    # 无目标类型答案: 若应答含 CNAME 链 → 交给 CNAME 跟踪展开
                    if parsed.get("answers"):
                        _cns = [a for a in parsed.get("answers", []) if a["type"] == dnsmsg.TYPE_CNAME]
                        if _cns:
                            self.tel.upstream_ok(u["id"], lat)
                            self.tel.conn_ok(self._conn_key(u), lat)
                            self._cb_ok(u["id"])
                            trace.append({"tag": "ans", "text": "%-12s CNAME 链 → %s (%dms)" % (
                                u["name"][:12], _cns[0].get("rdata", ""), lat)})
                            return {"ok": True, "up_name": u["name"], "lat": lat,
                                    "rcode": 0, "answers": [], "cnames": [
                                        (str(_cns[0].get("rdata", "")).rstrip(".").lower(),
                                         max(1, int(_cns[0].get("ttl", 300))))]}
                    # NOERROR 但无目标答案 = NODATA
                    self.tel.upstream_ok(u["id"], lat)
                    self.tel.conn_ok(self._conn_key(u), lat)
                    self._cb_ok(u["id"])
                    trace.append({"tag": "ans-fail", "text": "%-12s 无该类型记录 (NODATA) %dms" % (u["name"][:12], lat)})
                    return {"ok": True, "up_name": u["name"], "lat": lat,
                            "rcode": 0, "answers": [], "nodata": True}
                if rcode == 3:
                    self.tel.upstream_ok(u["id"], lat)
                    self.tel.conn_ok(self._conn_key(u), lat)
                    self._cb_ok(u["id"])
                    trace.append({"tag": "ans-fail", "text": "%-12s NXDOMAIN (域名不存在) %dms" % (u["name"][:12], lat)})
                    return {"ok": True, "up_name": u["name"], "lat": lat,
                            "rcode": 3, "answers": []}
            # rcode 其它（如 SERVFAIL/REFUSED）视为失败
        self.tel.upstream_fail(u["id"])
        self.tel.conn_fail(self._conn_key(u))
        self._cb_fail(u["id"])
        trace.append({"tag": "ans-fail", "text": "%-12s 查询失败 / 超时 (%dms)" % (u["name"][:12], lat)})
        return {"ok": False, "up_name": u["name"], "lat": lat, "rcode": None, "answers": []}

    def _collect_rest_in_background(self, pending, fut2u, qtype, trace):
        """后台收集未完成上游的结果：仅用于遥测统计, 不阻塞客户端。
        提交到共享收集池, 避免每次 miss 新建线程导致堆积。
        收集窗口与上游查询超时对齐: 慢协议(DoH/DoH3)超时可达 timeout_ms,
        固定 1s 会过早放弃导致大量上游成功率统计缺失(显示"待命")。
        注意: 首答已返回客户端, 后台收集的 trace 条目无意义, 用空列表丢弃,
        避免向已返回的 trace 对象继续 append(污染调用方引用)。"""
        timeout = int(self.cfg.get("timeout_ms", 1500)) / 1000.0
        # 有界队列: 收集池满则丢弃本次后台收集(纯统计, 无副作用)。
        # 原无界 submit 在 miss 高峰会无限堆积(4 worker 每秒约 2.7 个),
        # 是 VM 长期运行内存增长的元凶之一。
        self._collect_pool.submit_drop(self._collect_rest, pending, fut2u, qtype, [], timeout)

    def _collect_rest(self, pending, fut2u, qtype, trace, timeout=1.0):
        """后台收集未完成上游结果(仅遥测统计)。

        as_completed 带 timeout 兜底: 极端情况下(上游查询 future 因 pool 已
        shutdown / 排队未执行等未能完成)避免 worker 无限等待, 否则进程退出时
        threading._shutdown join 该 worker 会永久阻塞(systemd stop-sigterm 超时)。
        """
        try:
            for fut in as_completed(pending, timeout=timeout):
                try:
                    self._classify_one(fut2u[fut], fut, qtype, trace)
                except Exception as e:
                    log.debug("后台收集上游结果异常: %r", e)
        except Exception as e:
            # 超时未完成: 记录诊断信息后放弃, 不让后台线程无限阻塞
            if isinstance(e, TimeoutError):
                # 慢上游长时间未完成是常态(客户端已拿到首答), 仅 DEBUG 记录,
                # 不打扰运维日志(压测高峰上游排队时会周期性出现, 非错误)
                allinfo = []
                for f in pending:
                    st = getattr(f, "_state", "?")
                    u = fut2u.get(f)
                    allinfo.append("%s=%s" % (u.get("name") if u else "?", st))
                log.debug("上游结果收集超时 pending=%d: %s", len(pending), allinfo)
            # 清理已提交但未完成的查询(避免悬挂)
            for f in pending:
                if not f.done():
                    try:
                        f.cancel()
                    except Exception:
                        pass
    def _extract_answers(self, parsed, qtype):
        """从解析后的上游响应中提取目标类型答案。"""
        ans, _cnames = self._extract_answers_full(parsed, qtype)
        return ans

    def _extract_answers_full(self, parsed, qtype):
        """提取目标类型答案 + CNAME 链记录(供 CNAME 链跟踪展开)。

        返回 (answers, cnames): answers 为 qtype 目标答案; cnames 为
        [(target, ttl), ...] 按出现顺序(首个即最接近查询名的 CNAME)。"""
        target = dnsmsg.type_code(qtype)
        out = []
        seen = set()
        cnames = []
        for a in parsed.get("answers", []):
            if a["type"] == dnsmsg.TYPE_CNAME:
                cnames.append((str(a.get("rdata", "")).rstrip(".").lower(),
                               max(1, int(a.get("ttl", 300)))))
                continue
            if a["type"] != target:
                continue
            v = a["rdata"]
            if v in seen:
                continue
            seen.add(v)
            out.append({"value": v, "ttl": max(1, int(a.get("ttl", 300))), "type": target})
        return out, cnames

    def _mark_speed_test(self, d, now):
        """记录域名测速时间并限长(长时压测随机域名时防止 dict 无限增长泄漏)。"""
        self._last_speed_test[d] = now
        if len(self._last_speed_test) > self._speed_hist_max:
            self._last_speed_test.popitem(last=False)

    def _speed_sort(self, cand_list, query_bytes, d):
        """候选 IP 测速择优（零阻塞版）。

        相比旧实现（查询路径同步探测、固定 80ms 总超时、恒选最快、both 一刀切）：
        1) 查询路径零阻塞: 有新鲜 EWMA 缓存(默认 300s)直接用; 无则用上游延迟兜底
           排序并立即返回, 后台探测池异步补数据;
        2) EWMA 平滑: 探测结果以 0.7*旧 + 0.3*新 回写缓存, 抗单次抖动;
        3) 加权随机选优: 权重=1/(rtt+10), 快的 IP 概率性排前, 避免恒选最快造成
           单 IP 热点过载;
        4) 探测协议按上游类型分流: UDP 上游返回的 IP → udp53 探测;
           DoH/DoH3/DoT/DoQ 上游返回的 IP → tcp443 探测(更贴近真实访问路径)。
        """
        # 候选 IP 测速总开关: 关闭则保持上游返回顺序（不重排）
        if not self.cfg.get("ip_speed_check", True):
            return cand_list
        now = time.monotonic()
        interval = float(self.cfg.get("speed_interval_ms", 2000)) / 1000.0
        with self._speed_lock:
            last = self._last_speed_test.get(d, 0)
            if now - last < interval:
                return cand_list  # 间隔内复用上次排序
            self._mark_speed_test(d, now)
        cache_ttl = float(self.cfg.get("ip_speed_cache_ttl", 300))
        work = cand_list[:8]
        for a in work:
            ip = a["value"]
            with self._ip_speed_lock:
                hit = self._ip_speed_cache.get(ip)
            if hit is not None and now - hit[1] < cache_ttl:
                a["measured"] = hit[0]
            else:
                a["measured"] = a.get("lat", 999)
                with self._ip_speed_lock:
                    if hit is None:
                        self._ip_speed_cache[ip] = (a["measured"], now)  # 初值兜底
                        if len(self._ip_speed_cache) > 65536:
                            _items = sorted(self._ip_speed_cache.items(), key=lambda kv: kv[1][1])
                            for _k, _v in _items[: max(1, len(_items) // 4)]:
                                self._ip_speed_cache.pop(_k, None)
                self._probe_pool.submit_drop(
                    self._probe_candidate_ip, ip, query_bytes,
                    a.get("probe", "udp53"), 800)
        # 加权随机选优(不放回抽样): 权重=1/(rtt+10), 快 IP 概率性优先
        out = []
        pool = list(work)
        while pool:
            ws = [1.0 / (it.get("measured", 999) + 10) for it in pool]
            total = sum(ws)
            r = random.random() * total
            acc = 0.0
            pick = 0
            for i, w in enumerate(ws):
                acc += w
                if r <= acc:
                    pick = i
                    break
            out.append(pool.pop(pick))
        rest = cand_list[8:]
        for a in rest:
            a["measured"] = a.get("lat", 999)
        return out + rest

    def _probe_candidate_ip(self, ip, query_bytes, mode, timeout_ms):
        """后台探测候选 IP 的 RTT（探测模式由上游类型分流: udp53 / tcp443）。

        结果以 EWMA(0.7*旧 + 0.3*新)回写缓存抗抖动; 缓存上限 65536, 超限按
        测速时间删除最旧 1/4(长时压测随机 IP 时防 dict 无限增长)。
        """
        rtts = []
        if mode in ("both", "udp53", ""):
            r = probe_ip(ip, query_bytes, timeout_ms)
            if r is not None:
                rtts.append(r)
        if mode in ("both", "tcp443"):
            r = probe_tcp(ip, timeout_ms=timeout_ms)
            if r is not None:
                rtts.append(r)
        if not rtts:
            return None
        rtt = min(rtts)
        _now = time.monotonic()
        with self._ip_speed_lock:
            old = self._ip_speed_cache.get(ip)
            if old is not None and _now - old[1] < 3600:
                ewma = 0.7 * old[0] + 0.3 * rtt
            else:
                ewma = rtt
            self._ip_speed_cache[ip] = (ewma, _now)
            if len(self._ip_speed_cache) > 65536:
                _items = sorted(self._ip_speed_cache.items(), key=lambda kv: kv[1][1])
                for _k, _v in _items[: max(1, len(_items) // 4)]:
                    self._ip_speed_cache.pop(_k, None)
        return rtt

    def _clamp_ttl(self, ttl, rule=None):
        """下发 TTL 管控: 把 TTL 钳制到配置的 [ttl_min, ttl_max] 区间(0=不限)。

        作用于下发给内网客户端的应答 TTL, 同时作为缓存存活时长(与预取节奏一致):
        - ttl_min>0: 客户端缓存不少于该值(降低查询频率)
        - ttl_max>0: 客户端缓存不超过该值(避免缓存过久, 利于及时刷新)
        rule: 命中规则可带 ttl_min/ttl_max 覆盖全局值(规则级 TTL)——CDN/动态
              域名保持短 TTL 及时更新, 稳定域名拉长 TTL 提升命中率。
              规则设置任一 ttl 边界时, 规则区间【整体替换】全局区间:
              未显式设置的边界按 0(不限制), 避免与全局边界产生矛盾
              (如全局下限 30 与规则上限 20 互相打架)。
        """
        try:
            mn = max(0, int(self.cfg.get("ttl_min", 0) or 0))
        except Exception:
            mn = 0
        try:
            mx = max(0, int(self.cfg.get("ttl_max", 0) or 0))
        except Exception:
            mx = 0
        if rule and (rule.get("ttl_min") not in (None, "") or rule.get("ttl_max") not in (None, "")):
            mn, mx = 0, 0   # 规则区间整体替换全局
            try:
                if rule.get("ttl_min") not in (None, ""):
                    mn = max(0, int(rule.get("ttl_min")) or 0)
            except Exception:
                pass
            try:
                if rule.get("ttl_max") not in (None, ""):
                    mx = max(0, int(rule.get("ttl_max")) or 0)
            except Exception:
                pass
        t = int(ttl)
        if mn > 0 and t < mn:
            t = mn
        if mx > 0 and t > mx:
            t = mx
        return max(0, t)

    def _fill_cache(self, key, d, qtype, answers, rule=None):
        now = time.time()
        raw_ttl = min(self.cfg.get("ttl", 300), min((a.get("ttl", 300) for a in answers), default=self.cfg.get("ttl", 300)))
        ttl = self._clamp_ttl(raw_ttl, rule)
        # 下发 TTL 管控: 统一钳制答案 TTL(响应报文编码用), 保证下发给
        # 内网客户端的 TTL 与缓存存活时间一致, 也避免预编码 resp_body 失真
        for a in answers:
            a["ttl"] = ttl
        # chosen 取链尾真实目标 IP(跳过 CNAME 链头), 保证缓存命中返回最终解析 IP
        chosen = ""
        if answers:
            for a in reversed(answers):
                if a.get("type", 1) in (1, 28):   # A / AAAA 为真实终点
                    chosen = a["value"]
                    break
            if not chosen:
                chosen = answers[-1]["value"]
        self.cache.put(key, {
            "domain": d, "qtype": qtype, "answers": answers,
            "chosen": chosen,
            "ttl": ttl, "rcode": 0,
            "expires_at": now + ttl, "access_at": now,
        })
        # 过期条目清理已由 cache.put 概率式内部处理（消除计数器无锁读竞态）

    # ---- 预取：单一后台线程扫描（替代每域名一个 Timer） ----
    def _trigger_stale_refresh(self, key, d, qtype):
        """serve-stale 命中后触发后台强制刷新(去重)。

        与预取配合: 正常预取在 TTL 到期前刷新, serve-stale 是兜底路径——
        仅在缓存已过期(预取关闭/预取失败/恢复缓存过期)时触发, 保证下次
        查询能回到新鲜缓存。同一 key 并发去重, 避免高 QPS 下刷新风暴。
        """
        if not self.cfg.get("prefetch", True):
            return
        with self._prefetch_lock:
            if key in self._prefetch_pending or key in self._stale_refreshing:
                return
            self._stale_refreshing.add(key)
        try:
            self._prefetch_pool.submit_drop(self._do_stale_refresh, key, d, qtype)
        except Exception as e:
            log.warning("提交 stale 刷新异常 %s %s: %r", d, qtype, e)
            with self._prefetch_lock:
                self._stale_refreshing.discard(key)

    def _do_stale_refresh(self, key, d, qtype):
        try:
            r = self.resolve(d, qtype, silent=True, counted=False, force_refresh=True)
            if r and not r.get("error"):
                chosen = str(r.get("chosen") or "")
                desc = chosen if _looks_like_ip(chosen) else "记录 %d 条" % len(r.get("answers") or [])
                self.tel.log(d, qtype, "sys", "serve-stale 后台刷新 → %s" % desc, r.get("latency"),
                             client_ip=None, upstream="后台刷新", answer=chosen)
        except Exception as e:
            log.warning("serve-stale 后台刷新异常 %s %s: %r", d, qtype, e)
        finally:
            with self._prefetch_lock:
                self._stale_refreshing.discard(key)
                self._prefetch_pending.discard(key)

    def schedule_prefetch(self, key, d, qtype, ttl):
        """标记该 key 需要在过期前预取（由后台扫描线程统一调度）。"""
        if not self.cfg.get("prefetch", True):
            return
        with self._prefetch_lock:
            self._prefetch_pending.add(key)

    def rearm_prefetch(self):
        """重启恢复持久化缓存后, 把恢复的未过期条目重新纳入预取调度。

        与缓存持久化配合: 恢复的缓存同样在 TTL 到期前被自动刷新, 避免
        恢复后变成"一次性"缓存(过期即 miss 且不再预取)。
        负缓存(NXDOMAIN)不纳入——域名不存在, 重复解析无意义。
        """
        if not self.cfg.get("prefetch", True):
            return 0
        now = time.time()
        added = 0
        for key in self.cache.snapshot_keys():
            entry = self.cache.get(key, now)
            if entry is None:
                continue
            if entry.get("rcode", 0) == 3:      # NXDOMAIN 负缓存不预取
                continue
            ttl = entry.get("ttl", 0)
            if ttl < 5:
                continue                        # 过短 TTL 不值得预取
            key = key[1:] if len(key) == 3 else key   # 分区 key 去掉 group 维
            with self._prefetch_lock:
                if key not in self._prefetch_pending:
                    self._prefetch_pending.add(key)
                    added += 1
        if added:
            self.tel.log("", "", "sys", "预取重调度: 恢复缓存 %d 条纳入预取队列" % added, 0)
            log.info("预取重调度: 恢复缓存 %d 条纳入预取队列", added)
        else:
            log.info("预取重调度: 无恢复缓存纳入 (%d 条缓存, prefetch=%s)", len(self.cache), self.cfg.get("prefetch"))
        return added

    def _prefetch_loop(self):
        while not self._prefetch_stop.is_set():
            try:
                self._scan_prefetch()
            except Exception as e:
                # 关键后台循环异常必须可见(否则预取静默失效)
                log.error("预取扫描异常: %r", e)
            time.sleep(self._prefetch_interval)

    def _scan_prefetch(self):
        cfg = self.cfg
        if not cfg.get("prefetch", True):
            return
        now = time.time()
        due = []
        with self._prefetch_lock:
            pending = list(self._prefetch_pending)
        # 分批轮转扫描: 大容量缓存(持久化恢复可能上万条)时避免每 tick 全量遍历
        if len(pending) > self._prefetch_batch:
            n = len(pending)
            start = self._prefetch_scan_idx % n
            window = pending[start:start + self._prefetch_batch]
            self._prefetch_scan_idx = (start + self._prefetch_batch) % n
        else:
            window = pending
        for key in window:
            entry = self.cache.get(key, now)
            if entry is None:
                with self._prefetch_lock:
                    self._prefetch_pending.discard(key)
                continue
            ttl = entry.get("ttl", 0)
            expires = entry.get("expires_at", 0)
            # 已过 85% TTL 且未过期 → 预取
            if 0 < expires - now < max(1.0, ttl * 0.15):
                due.append(key)
        if not due:
            return
        for key in due:
            entry = self.cache.get(key, now)
            if entry is None:
                continue
            if len(key) == 3:
                key = key[1:]
            d, qtype = key
            with self._prefetch_lock:
                self._prefetch_pending.discard(key)
            self._prefetch_pool.submit_drop(self._do_prefetch, d, qtype)

    def _do_prefetch(self, d, qtype):
        try:
            log.debug("预取触发 %s %s (强制刷新)", d, qtype)
            r = self.resolve(d, qtype, silent=True, counted=False, force_refresh=True)
            if r and not r.get("error"):
                chosen = str(r.get("chosen") or "")
                # 只展示可读结果: 合法 IP 直接显示; rdata 无法解析(hex 乱码/未知类型)时
                # 用记录数摘要, 避免把原始 hex 当答案输出
                desc = chosen if _looks_like_ip(chosen) else "记录 %d 条" % len(r.get("answers") or [])
                self.tel.log(d, qtype, "sys", "预取完成 → %s" % desc, r.get("latency"),
                             client_ip=None, upstream="预取", answer=chosen)
        except Exception as e:
            log.warning("预取异常 %s %s: %r", d, qtype, e)

    def shutdown(self):
        """停止后台预取与全部上游线程池(退出时调用)。

        背景: ThreadPoolExecutor 的 worker 是非 daemon 线程, Python 退出时
        threading._shutdown 会 join 它们; 若预取线程还在持续 submit 新任务,
        worker 永远不空闲导致进程无法退出(systemd stop-sigterm 90s 超时强杀)。
        显式 shutdown 各池并停止预取循环, 保证退出时不再有新的池任务入队。
        """
        self._prefetch_stop.set()
        try:
            self._prefetch_thread.join(timeout=2.0)
        except Exception:
            pass
        self._bg_stop.set()
        try:
            self._bg_thread.join(timeout=2.0)
        except Exception:
            pass
        for pool in (self._up_pool, self._doh_pool, self._prefetch_pool,
                     self._collect_pool, self._probe_pool):
            try:
                # cancel_futures=True: 取消队列中未开始的任务。否则负载期积压的
                # 慢查询(如 DoH 每个 3s)会让 worker 处理完才退出, 导致
                # systemd stop-sigterm 超时被 SIGKILL。
                pool.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass

    # ---------------- 缓存分区 group 判定 ---------------- #
    def _ckey(self, d, qtype):
        """构造分区缓存 key: (group, domain, qtype)。
        group 按分流规则: 命中 group 规则 → domestic/global; 其余(含 block/无规则)→ default。
        规则匹配走 _rule_match_cache(O(1)), 热路径额外开销可忽略。"""
        g = "default"
        try:
            r = self.match_rule(d)
            if r and r.get("action") == "group" and r.get("group") in ("domestic", "global"):
                g = r["group"]
        except Exception:
            pass
        return (g, d, qtype)

    # ---------------- 配置热重载 ---------------- #
    def reload(self, new_cfg, config_path=None):
        """热重载: 替换运行配置并重建受影响资源, 不重启进程。

        - 配置 dict 整体原子替换(self.cfg 引用), 后续查询自然使用新值
        - 缓存容量变更即时调整(分区/单区均支持)
        - 规则索引重建(逐条/订阅独立文件为准)
        - 缓存策略变更(仅 cache_policy 切换)需要重建缓存容器
        返回变更摘要 dict。"""
        changed = []
        old_cfg = self.cfg
        self.cfg = new_cfg
        # 缓存容量
        try:
            old_cap = int(old_cfg.get("cache_size", 1024))
            new_cap = int(new_cfg.get("cache_size", 1024))
            if new_cap != old_cap:
                self.cache.capacity = new_cap
                changed.append("cache_size %d→%d" % (old_cap, new_cap))
        except Exception:
            pass
        # 缓存策略切换(lru <-> tinylfu): 重建容器(保留容量)
        old_p = str(old_cfg.get("cache_policy", "lru")).lower()
        new_p = str(new_cfg.get("cache_policy", "lru")).lower()
        if old_p != new_p:
            cap = self.cache.capacity
            # 策略不同步迁移数据(新旧算法频率语义不同), 直接重建容器, 冷启动短暂
            # 命中率下降是热重载低频操作下的可接受代价
            if new_p == "tinylfu":
                self.cache = TinyLFUCache(cap)
            else:
                self.cache = PartitionedCache(cap, new_cfg.get("cache_partitions"))
            changed.append("cache_policy %s→%s (缓存已重建)" % (old_p, new_p))
        # 规则索引(独立文件为准)
        try:
            self.rebuild_rule_index()
            changed.append("规则索引已重建")
        except Exception as e:
            log.error("热重载规则索引重建失败: %r", e)
        return changed

    # ---------------- 周期任务: 健康检查 + 订阅自动更新 ---------------- #
    def _bg_loop(self):
        """后台周期任务循环: 每 10s tick, 按各自间隔触发
        上游健康检查 / 规则订阅更新。间隔可配(0=关闭),
        热重载后新配置在下一 tick 生效(每次读 self.cfg)。"""
        _last_h = _last_r = 0.0
        while not self._bg_stop.is_set():
            try:
                now = time.time()
                cfg = self.cfg
                hi = max(0, int(cfg.get("health_check_interval", 30) or 0))
                ri = max(0, int(cfg.get("rule_sub_interval", 3600) or 0))
                if hi and now - _last_h >= hi:
                    _last_h = now
                    self._health_check_once()
                if ri and now - _last_r >= ri:
                    _last_r = now
                    self._update_rule_subs_once()
            except Exception as e:
                log.error("后台周期任务异常: %r", e)
            self._bg_stop.wait(10)

    def _health_check_once(self):
        """上游主动健康检查: 对所有启用上游发一次探测查询(绕过分流规则,
        直连 query_upstream), 成功/失败喂入熔断器(与查询路径一致)。

        探测域名用配置的 health_probe_domain(默认 www.baidu.com), 超时
        health_probe_timeout_ms(默认 2000)。探测结果只更新熔断器与日志,
        不进入 conn_stats(避免污染真实查询延迟统计)。"""
        cfg = self.cfg
        ups = [u for u in cfg.get("upstreams", []) if u.get("enabled", True)]
        if not ups:
            return
        dom = str(cfg.get("health_probe_domain", "www.baidu.com") or "www.baidu.com")
        timeout = max(500, int(cfg.get("health_probe_timeout_ms", 2000) or 2000))
        qt = dnsmsg.type_code("A")
        qd = dnsmsg.random_case_name(dom) if cfg.get("dnssec_0x20", True) else dom
        qbytes, _q = dnsmsg.build_query(qd, qt, edns=True, udp_size=1232, padding=False)
        ups2 = list(ups)
        if len(ups2) > 1:
            # 每轮探测 3 个并轮转游标, 保证所有启用上游都被周期探测
            # (固定取前 N 个会让靠后的上游永不被主动健康检查)
            n = self._hc_off
            ups2 = (ups2 + ups2)[n:n + 3]
            self._hc_off = (n + 3) % len(ups)
        for u in ups2:
            try:
                ok, _data, _lat, _e = query_upstream(u, qbytes, timeout)
                if ok:
                    self._cb_ok(u["id"])
                    log.debug("健康检查 OK  %s (%s)", u["name"], u.get("addr"))
                else:
                    self._cb_fail(u["id"])
                    log.info("健康检查失败 %s (%s): %s", u["name"], u.get("addr"), _e or "无应答")
            except Exception as e:
                self._cb_fail(u["id"])
                log.debug("健康检查异常 %s: %r", u.get("name"), e)

    def _fetch_sub_text(self, url, timeout=20):
        """拉取订阅文本(与 api 实现一致, resolver 后台更新独立使用)。"""
        req = urllib.request.Request(url, headers={"User-Agent": "ebpdns/subscribe"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")

    def _update_rule_subs_once(self):
        """规则订阅自动更新: 对 config 元信息中的订阅链接重新拉取并覆盖
        独立文件明细(rules_sub.json), 然后重建规则索引。

        与手动 /api/rules/subscribe/update 共用同一数据模型(独立文件为准),
        更新失败仅告警不中断(下个周期重试)。"""
        cfg = self.cfg
        meta = cfg.get("rule_subscriptions") or []
        urls = [m.get("url") for m in meta if m.get("url")]
        if not urls:
            return
        path = cfg.get("rule_sub_file") or ""
        try:
            with open(path, encoding="utf-8") as f:
                subs = json.load(f).get("subscriptions", [])
        except Exception:
            subs = []
        n_ok = 0
        for s in subs:
            url = s.get("url") or ""
            if url not in urls:
                continue
            try:
                text = self._fetch_sub_text(url)
                items = [{"match": ("*." + d if not d.startswith("*.") else d)}
                         for d in self._parse_domain_list(text)]
                if not items:
                    continue
                s["rules"] = items
                s["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                n_ok += 1
            except Exception as e:
                log.warning("订阅自动更新失败 %s: %r", url, e)
        # 配置已删除的订阅从独立文件剔除(防残留规则继续生效, 与 config 保持同步)
        before = len(subs)
        subs = [s for s in subs if (s.get("url") or "") in urls]
        if len(subs) != before:
            log.info("订阅自动更新: 剔除 %d 个已删除订阅", before - len(subs))
        if (n_ok or len(subs) != before) and path:
            try:
                import os as _os
                _os.makedirs(_os.path.dirname(_os.path.abspath(path)) or ".", exist_ok=True)
                tmp = path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump({"subscriptions": subs}, f, ensure_ascii=False)
                    f.flush()
                    _os.fsync(f.fileno())
                _os.replace(tmp, path)
                self.rebuild_rule_index()
                log.info("规则订阅自动更新: %d 个订阅已刷新", n_ok)
            except Exception as e:
                log.error("规则订阅自动更新落盘失败: %r", e)

    @staticmethod
    def _parse_domain_list(text):
        """从订阅文本提取域名行(与 api._parse_domain_list 同规则)。"""
        out = []
        seen = set()
        for line in (text or "").splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "!", "//", ";")):
                continue
            if line.startswith("@@"):
                continue
            if line.startswith("||"):
                line = line[2:]
            line = line.split("^")[0].split("/")[0].strip().lower()
            if not line or line.startswith("*."):
                continue
            if line in seen:
                continue
            seen.add(line)
            out.append(line)
        return out

    def _rebuild_rule_index(self):
        """从独立文件(逐条 rules_local.json) + 订阅规则文件(独立存储) 重建分流规则索引。
        订阅规则排在逐条规则之后; 两者明细均不写入 config.json。
        allow(白名单)规则单独建索引, 匹配时优先于 block/group/forceIp——
        白名单是例外规则, 命中即放行, 不再被屏蔽规则拦截。"""
        exact, wild = {}, {}
        allow_exact, allow_wild = {}, {}
        regex = []
        suffix_wild = {}   # 中缀/前缀通配(*ac*.com / *foo.net): 按固定后缀分组索引
        rules = self._load_local_rules() + self._load_sub_rules()
        for r in rules:
            m = (r.get("match") or "").strip().lower()
            if not m:
                continue
            is_allow = r.get("action") == "allow"
            if m.startswith("re:"):
                pat = m[3:]
                try:
                    c = re.compile(pat)
                except re.error:
                    logging.warning("正则规则编译失败 %r, 已忽略", m)
                    continue
                regex.append((c, r))
            elif m.startswith("*.") and "*" not in m[2:]:
                # 纯后缀通配: *.core → 剥离匹配 O(1)
                core = m[2:].strip(".")
                if core:
                    if is_allow:
                        allow_wild[core] = r
                    else:
                        wild[core] = r
            elif "*" in m:
                # 中缀/前缀通配(如 *.ac*.786ip.com / *ads.com): 转正则并按固定后缀
                # 分组(取最后两级), 查询时先按剥离后缀定位小组, 再逐条正则匹配,
                # 避免 9 万+ 条中缀规则全部进全局正则列表导致每次 miss 全量扫描。
                body = m.lstrip("*.")
                parts = body.split(".")
                suffix = ".".join(parts[-2:]) if len(parts) >= 2 else ""
                try:
                    c = re.compile("^" + re.escape(m).replace(r"\*", ".*") + "$")
                except re.error:
                    logging.warning("通配规则编译失败 %r, 已忽略", m)
                    continue
                if suffix:
                    suffix_wild.setdefault(suffix, []).append((c, r))
                else:
                    # 无固定后缀(单段通配如 *ads): 只能全局逐条, 归入正则列表兜底
                    regex.append((c, r))
            else:
                if is_allow:
                    allow_exact[m] = r
                else:
                    exact[m] = r
        self._rule_exact = exact
        self._rule_wild = wild
        self._rule_allow_exact = allow_exact
        self._rule_allow_wild = allow_wild
        self._rule_suffix_wild = suffix_wild
        self._rule_regex = regex
        self._rule_match_cache = {}   # 规则集变更, 全部缓存结论失效

    def _load_local_rules(self):
        """从逐条规则独立文件(rules_local.json)加载规则明细(不写入 config.json)。
        未配置独立文件(单元测试/旧配置兼容场景)回退 cfg['rules'];
        仅文件不存在视为空; JSON 损坏告警并返回空, 不静默吞错。"""
        path = self.cfg.get("rule_local_file") or ""
        if not path:
            return list(self.cfg.get("rules", []))
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            return data.get("rules") or []
        except FileNotFoundError:
            return []
        except (OSError, ValueError) as e:
            logging.warning("逐条规则独立文件读取失败 %s: %s", path, e)
            return []

    def _load_sub_rules(self):
        """从规则订阅独立文件加载订阅规则明细(不写入 config.json)。
        仅文件不存在/JSON 损坏视为空订阅; 其余异常如实上抛, 不静默吞错。"""
        path = self.cfg.get("rule_sub_file") or ""
        if not path:
            return []
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            return []
        except (OSError, ValueError) as e:
            logging.warning("订阅规则文件读取失败 %s: %s", path, e)
            return []
        out = []
        for sub in data.get("subscriptions", []) or []:
            action = sub.get("action") or "block"
            group = sub.get("group") or "global"
            ip = sub.get("ip") or "1.2.3.4"
            for item in sub.get("rules", []) or []:
                m = (item.get("match") or "").strip()
                if not m:
                    continue
                r = {"match": m, "action": action}
                if action == "group":
                    r["group"] = group
                elif action == "forceIp":
                    r["ip"] = ip
                out.append(r)
        return out

    def rebuild_rule_index(self):
        with self._prefetch_lock:
            self._rebuild_rule_index()

    @staticmethod
    def _rule_label(rule):
        """规则命中显示标签: 「放行 *.cdn.com」/「屏蔽 *.ads.com」/「国内 *.cn」/「国外 *.com」/「强制IP 1.2.3.4」"""
        if not rule:
            return None
        act = rule.get("action")
        match = rule.get("match", "")
        if act == "allow":
            return "放行 " + match
        if act == "block":
            return "屏蔽 " + match
        if act == "forceIp":
            return "强制IP " + match
        if act == "group":
            return ("国内 " if rule.get("group") == "domestic" else "国外 ") + match
        return match

    def match_rule(self, domain):
        """分流规则匹配(域名级)。优先级:
        精确规则 O(1) 哈希 → 通配规则后缀最长匹配(逐级剥离子域)
        → re: 正则(按序首个命中)。
        性能: 结果按域名缓存(规则不变时结论不变), 重建规则时清空;
        热路径(缓存命中复查 + miss 分流)避免重复遍历正则。"""
        n = domain.lower()
        # 规则缓存优先: allow 检查结果也在缓存中, 避免 hot path 每次遍历
        cache = self._rule_match_cache
        hit = cache.get(n, _MISS)
        if hit is not _MISS:
            return hit if hit is not None else None
        # ---- 白名单(allow)优先: 仅缓存未命中时检查 ----
        r = self._rule_allow_exact.get(n)
        if r is not None:
            self._cache_rule(n, r)
            return r
        core = n
        while core:
            r = self._rule_allow_wild.get(core)
            if r is not None:
                self._cache_rule(n, r)
                return r
            idx = core.find(".")
            if idx == -1:
                break
            core = core[idx + 1:]
        r = self._rule_exact.get(n)
        if r is not None:
            self._cache_rule(n, r)
            return r
        # 通配: *.core 匹配 core 及其全部子域。从完整域名自身开始逐级剥离
        # (最长匹配优先): a.b.deep.sub.com -> deep.sub.com -> sub.com -> com
        wild = self._rule_wild
        core = n
        while core:
            r = wild.get(core)
            if r is not None:
                self._cache_rule(n, r)
                return r
            idx = core.find(".")
            if idx == -1:
                break
            core = core[idx + 1:]
        # 中缀/前缀通配(*ac*.com 等): 同一剥离路径按固定后缀定位小组后逐条正则
        sw = self._rule_suffix_wild
        core = n
        while core:
            group = sw.get(core)
            if group:
                for c, rule in group:
                    try:
                        if c.match(n):
                            self._cache_rule(n, rule)
                            return rule
                    except Exception:
                        continue
            idx = core.find(".")
            if idx == -1:
                break
            core = core[idx + 1:]
        # 正则规则: 编译已缓存, 按配置顺序首个命中生效
        for c, rule in self._rule_regex:
            try:
                if c.search(n):
                    self._cache_rule(n, rule)
                    return rule
            except Exception:
                continue
        self._cache_rule(n, None)
        return None

    def _cache_rule(self, n, rule):
        cache = self._rule_match_cache
        if len(cache) >= self._rule_cache_max:
            cache.clear()   # 满则整体清空(简单且有界; 规则集远小于缓存容量时很少触发)
        cache[n] = rule

    def _guess_type(self, value, qtype):
        v = value.strip()
        if ":" in v:
            return dnsmsg.TYPE_AAAA
        if v.replace(".", "").isdigit():
            return dnsmsg.TYPE_A
        return dnsmsg.type_code(qtype) or dnsmsg.TYPE_A

    @staticmethod
    def _normalize(domain):
        d = (domain or "").strip().rstrip(".").lower()
        return d

    def _result(self, d, qtype, answers, chosen, hit, error, reason, latency, trace, ttl_left, empty=False, rcode=0):
        return {
            "domain": d, "qtype": qtype,
            "answers": answers, "chosen": chosen or "",
            "hit": hit, "error": error, "reason": reason,
            "rcode": rcode,
            "latency": round(latency, 2), "ttl_left": ttl_left,
            "trace": trace, "empty": empty,
        }

    def _error(self, d, qtype, reason, text, silent):
        trace = [{"tag": "warn", "text": text}]
        return self._result(d or "", qtype, [], None, False, True, reason, 0, trace, 0, rcode=2)
