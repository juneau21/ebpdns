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
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED, as_completed
import concurrent.futures as _cf   # M2: 3.10 兼容 as_completed 超时抛 _cf.TimeoutError(3.11+ 才别名 builtin TimeoutError)
import ipaddress

from . import dnsmsg

# match_rule 缓存哨兵: 区分"未缓存"与"命中 None"(无规则)
_MISS = object()

# 正则匹配超时保护: 防止恶意正则规则(如 (a+)+$)配合长域名导致 ReDoS 阻塞 worker
_REGEX_TIMEOUT_SEC = 0.5
# v1.9.74 P1-6: 2 worker 是 ReDoS 保护池瓶颈(高并发规则匹配时请求排队等槽位)。
# R3-P3-1: 提到 6 worker(原 4), 降低灾难性正则占满全部运行槽位的概率;
# 超时仍 0.5s——即使被恶意正则占满, 也只占 6 槽位, 主解析线程池不受影响。
# R5/P3-3: _REGEX_POOL 是模块级单例, 跨所有 Resolver 实例共享。这是有意设计:
# 正则匹配是纯 CPU、无状态操作, 全进程共享一个有界池(6 worker)避免每个 Resolver
# 实例各开 6 个线程导致线程膨胀。当前架构 Resolver 为单实例(热重载原地更新配置,
# 不重建 Resolver 对象), 因此 shutdown() 关闭此池后不会再有第二个实例 submit。
# 若未来支持多 Resolver 实例/测试隔离, 需把本池下沉为实例属性(届时本注释即
# 设计约束)。shutdown() 处(P3-4)统一用 wait=False+cancel_futures 退出, 见下。
_REGEX_POOL = ThreadPoolExecutor(max_workers=6, thread_name_prefix="regex-safe")
# v1.9.76 2.9: 正则池有界。原 ThreadPoolExecutor 无界队列, 高并发规则匹配时
# submit 任务无限排队(每个被 ReDoS 占满的 worker 跑满 0.5s 超时), 内存与调度
# 无界增长。用信号量把在飞任务(已 submit 未完成)钳到 max_workers+8, 满则放弃
# 本次匹配(返回 None=不匹配), 绝不阻塞/排队。
# R3-P3-1: worker 从 4 提到 6, 降低灾难性正则占满全部运行槽位的概率;
# 0.5s 超时已在 _regex_search_safe / _regex_match_safe 两条路径均生效
# (fut.result(timeout=0.5) 超时抛 TimeoutError → except 兜底返回 None)。
# 注意: Python re 无内部取消, 超时后 worker 线程仍跑至自然结束, 但调用线程
# 不阻塞; 信号量上限 6+8=14 有界, 残留 blast radius 可控。
_REGEX_MAX_PENDING = 8
_REGEX_SEM = threading.BoundedSemaphore(6 + _REGEX_MAX_PENDING)

def _safe_int(v, default=0):
    """R4-P3-1/R5: 安全 int() 转换, 畸形配置值(非数值字符串)不抛 ValueError。
    对齐 probe.py / cache.py _safe_int(default=0): miss 热路径裸
    int(self.cfg.get("timeout_ms")) 若热重载把 timeout_ms 填成 "abc" 会
    ValueError → 全量 SERVFAIL。

    R7/P3-1: 旧默认值 default=1500 为死代码——全部 30+ 调用点均显式传第二参数
    (已 grep 确认无单参调用), 统一改为 default=0 与 probe.py/cache.py 对齐。

    R5 修正: 旧实现 `int(v or default)` 把 falsy 的 0 也替换成 default——
    0 是合法的"禁用超时/关闭"语义值(如 timeout_ms=0), 不应被静默改成 default。
    现严格区分: 仅当 v is None(键缺失/显式 null)或无法解析时才回退 default;
    可解析值(含整数 0)原样返回 int(v)。"""
    if v is None:
        return default
    try:
        return int(v)
    except (TypeError, ValueError):
        return default

def _safe_float(v, default=0.0):
    """R6/P2-2: 安全 float() 转换, 与 _safe_int 同模式。
    R5 清扫全量 grep 了 int() 却漏了 float()——测速路径 _speed_sort 内
    float(self.cfg.get("speed_interval_ms"))/float(...("ip_speed_cache_ttl"))
    对配置值裸 float(), 畸形串("abc")抛 ValueError 穿透 miss 主路径。
    None 或无法解析时回退 default; 可解析值(含 0.0)原样返回。"""
    if v is None:
        return default
    try:
        return float(v)
    except (TypeError, ValueError):
        return default

def _parse_braces_quant(pat, j):
    """若 pat[j] 是合法 {n,m}/{n,}/{n} 量词, 返回 (lo, hi, end); hi=None 表示无上限,
    end 为 '}' 之后的下标。否则返回 None(j 指向 '{')。
    用于区分"有界重复"与"无界重复"。"""
    n = len(pat)
    if j >= n or pat[j] != '{':
        return None
    k = j + 1
    lo_s = ""
    while k < n and '0' <= pat[k] <= '9':   # R43/P2-1: 收窄为 ASCII 数字, 拒绝 ²/① 等 Unicode 数字
        lo_s += pat[k]
        k += 1
    if not lo_s:
        return None
    lo = int(lo_s)
    hi = lo
    if k < n and pat[k] == ',':
        k += 1
        hi_s = ""
        while k < n and '0' <= pat[k] <= '9':   # R43/P2-1: 同上收窄
            hi_s += pat[k]
            k += 1
        hi = int(hi_s) if hi_s else None  # {n,} 无上限
    if k < n and pat[k] == '}':
        return (lo, hi, k + 1)
    return None


def _skip_char_class(pat, j):
    """从 j(pat[j]=='[') 跳到闭合 ']' 之后, 返回新位置。类内字面括号/竖线不参与
    组深度与交替判定(R2-P3-4)。处理转义右括号与前导 ] 字面的常见情形。"""
    n = len(pat)
    k = j + 1
    if k < n and pat[k] == ']':
        k += 1  # [] 或 []a] 中首个 ] 视为字面字符
    while k < n and pat[k] != ']':
        if pat[k] == '\\':
            k += 2
        else:
            k += 1
    if k < n:
        k += 1  # 跳过闭合 ']'
    return k


def _detect_catastrophic_regex(pat):
    """静态检测可能引发灾难性回溯的正则模式(嵌套量词/交替重复组)。
    返回 True 表示高风险, 调用方应拒绝或强警告。

    启发式判定(R2 重写): 灾难性指数回溯必须同时满足——
      (1) 一个 (...) 组被"无界重复量词"重复: 外层为 * / + 或 {n,}(无上限);
      (2) 组内存在可歧义分区的子结构: 组内本身含量词(嵌套量词, 如 (a+)+),
          或组内含交替 |(如 (a|b)*)。
    据此精确化, 减少误报面:
      - 外层为 ?(0/1 次可选)不重复, 绝不指数回溯, 不判(如 (https?://)?);
      - 外层为有界 {n} / {n,m}(上限有限)是线性/低阶多项式, 对短 DNS 名安全,
        不判(如标准 IPv4 的 ([0-9]{1,3}\\.){3}[0-9]{1,3]);
      - 纯固定字符串(无任何正则元字符)直接放行。
    R2-P3-4: 字符类 [...] 内容不参与组深度/交替判定, 类内字面 ( ) | 不再污染统计。
    漏报由 _regex_search_safe 0.5s 超时兜底(超时返回 None=不匹配, 不阻塞 worker);
    误报是安全侧拒绝(注释已声明用户可手改规则绕过)。"""
    if not pat:
        return False
    # 纯固定字符串(无正则元字符)直接放行, 不走组分析
    _META = set("\\.^$*+?()[]{}|")
    if not any(c in _META for c in pat):
        return False
    n = len(pat)
    i = 0
    while i < n:
        c = pat[i]
        if c == '\\':
            i += 2
            continue
        if c == '[':
            i = _skip_char_class(pat, i)
            continue
        if c != '(':
            i += 1
            continue
        # 解析一个 (...) 组, 跟踪深度, 记录组内是否含量词/交替
        depth = 1
        j = i + 1
        has_quant_inside = False
        has_alternation = False
        while j < n and depth > 0:
            cj = pat[j]
            if cj == '\\':
                j += 2
                continue
            if cj == '[':
                j = _skip_char_class(pat, j)
                continue
            if cj == '?' and j == i + 1:
                # 组起始位置的 ? 是组指令标记(?: (?= (?! (?<= (?<! (?> ...)),
                # 不是量词。跳过指令字符, 不计入 has_quant_inside(如 (?:x)+ 不误报)。
                j += 1  # 跳过 '?'
                if j < n and pat[j] == ':':
                    j += 1
                elif j < n and pat[j] in '=!':
                    j += 1
                elif j < n and pat[j] == '<':
                    j += 1
                    if j < n and pat[j] in '=!':
                        j += 1
                continue
            if cj == '(':
                depth += 1
            elif cj == ')':
                depth -= 1
                if depth == 0:
                    break
            elif cj == '|':
                # 仅在当前组深度(外层)记交替; 内层嵌套组内的 | 也计入(保守)
                has_alternation = True
            elif cj in '+*?':
                # 组内任意量词(+ * ?)都计为可歧义分区的嵌套量词(如 (a*)*)
                has_quant_inside = True
            elif cj == '{':
                q = _parse_braces_quant(pat, j)
                if q is not None:
                    has_quant_inside = True
                    j = q[2] - 1  # 跳过整段 {..}(循环尾再 +1)
            j += 1
        # 组结束(j 指向闭合 ')')。检查外层量词是否为"无界重复"。
        if j + 1 < n:
            outer = pat[j + 1]
            if outer in '*+':
                # 无界重复量词 * / +
                if has_quant_inside or has_alternation:
                    return True
            elif outer == '{':
                q = _parse_braces_quant(pat, j + 1)
                # 仅 {n,}(hi=None 无上限)视为无界重复; {n}/{n,m} 有界不判
                if q is not None and q[1] is None:
                    if has_quant_inside or has_alternation:
                        return True
            # outer == '?'(0/1 可选)绝不指数回溯, 故意不判
        i = j + 1
    return False

def _regex_search_safe(pattern, text, timeout=_REGEX_TIMEOUT_SEC):
    """带超时的正则搜索, 防止 ReDoS。三态返回:
    - True  = 正则执行完成且命中
    - False = 正则执行完成且不匹配
    - None  = 结果不确定(池满/超时/执行异常)。调用方对屏蔽类规则必须
      fail-closed(当作命中), 不得当"不匹配"放行。
    v1.9.76 2.9: 池满(_REGEX_SEM 耗尽)放弃本次匹配, 不排队。

    安全语义(已从 fail-open 改为 fail-closed): 灾难性正则把 worker 占满/池耗尽
    时, 依赖正则命中的 block 规则不再按放行处理, 而是由 match_rule 对该规则
    fail-closed 屏蔽对应查询, 防止 ReDoS 窗口内屏蔽规则被绕过。超时后 worker
    线程仍在后台跑至自然结束(Python re 不可取消), 信号量有界(6+8), blast radius
    可控。"""
    if not _REGEX_SEM.acquire(blocking=False):
        return None
    try:
        fut = _REGEX_POOL.submit(pattern.search, text)
    except Exception:
        _REGEX_SEM.release()
        return None
    fut.add_done_callback(lambda _f: _REGEX_SEM.release())
    try:
        return bool(fut.result(timeout=timeout))
    except Exception:
        return None

def _regex_match_safe(pattern, text, timeout=_REGEX_TIMEOUT_SEC):
    """带超时的正则匹配(match), 防止 ReDoS。三态与 _regex_search_safe 完全一致
    (True=命中 / False=不匹配 / None=不确定, 屏蔽规则 fail-closed)。"""
    if not _REGEX_SEM.acquire(blocking=False):
        return None
    try:
        fut = _REGEX_POOL.submit(pattern.match, text)
    except Exception:
        _REGEX_SEM.release()
        return None
    fut.add_done_callback(lambda _f: _REGEX_SEM.release())
    try:
        return bool(fut.result(timeout=timeout))
    except Exception:
        return None
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
        # R7/P3-9: add_done_callback 仅注册 list.append(self._done_callbacks),
        # 自身不抛异常(即使回调 _release 内部抛 BoundedSemaphore ValueError 也只在
        # future 完成时的工作线程内抛出, 不影响已 acquire 的信号量计数)。信号量不会
        # 因注册回调失败而泄漏——_release 是唯一释放点, 与 submit() 的 acquire 配对。
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
        # R43/P3-1: 收窄为 ASCII 数字(拒绝 ²/① 等 Unicode 数字, 避免 int() 抛 ValueError)。
        # 空串 p 由 `not p` 短路拒绝, 与原 p.isdigit()(空串返回 False)语义一致。
        if not p or not all('0' <= c <= '9' for c in p) or not (0 <= int(p) <= 255):
            return False
    return True


TRACE_TAGS = ("xdp", "bpf", "rule", "eng", "ans", "ans-fail", "ok", "warn")


log = logging.getLogger("ebpdns")


class Resolver:
    def __init__(self, cfg, telemetry, cache=None):
        self.cfg = cfg
        self.tel = telemetry
        # v1.9.76 2.4: ECS 入缓存 key。配置 edns_client_subnet 时把归一化子网前缀
        # 并入缓存 key, 否则带 ECS 的响应(按子网分地域)与不带 ECS 的响应会互相污染。
        # 归一化到网络地址(/24 等由 ip_network strict=False 完成); reload 时重算。
        self._ecs_key = self._normalize_ecs_key(cfg)
        # 启动预热重试: 冷启动/重启后上游 TLS 冷握手未就绪, 首查易全部失败返回
        # SERVFAIL。启动早期(45s)内全部失败时延迟重试一次(全局至多 3 次), 改善
        # "刚重启/刚部署首查失败"体验; 稳态(>45s)完全不受影响。
        self._boot_ts = time.monotonic()
        self._boot_retries = 0
        self._boot_retry_lock = threading.Lock()
        # P2-2: 只允许一个查询实际执行 sleep+重试。多个并发查询同时失败时,
        # 仅第一个进入重试, 其余直接 SERVFAIL 不重复阻塞 worker(原锁内只做计数,
        # 所有查询都通过计数检查后各自 sleep 0.5s 重试, 放大冷启动延迟)。
        self._boot_retry_in_progress = threading.Event()
        # 缓存策略: lru(默认, 按分流 group 分区隔离) / tinylfu(W-TinyLFU 高频保留)
        _policy = str(cfg.get("cache_policy", "lru")).lower()
        if _policy == "tinylfu":
            # R6/P2-3: __init__ 路径原裸传 cfg.get("cache_size") 给缓存构造器,
            # 与 reload 路径(:2136/:2137 已包 _safe_int)行为不一致——畸形串
            # 启动即 ValueError 崩溃。这里对齐 reload, 统一 _safe_int 包裹。
            self.cache = cache if cache is not None else TinyLFUCache(_safe_int(cfg.get("cache_size", 1024), 1024))
        else:
            self.cache = cache if cache is not None else PartitionedCache(
                _safe_int(cfg.get("cache_size", 1024), 1024), cfg.get("cache_partitions"))
        # v1.9.74 P1-2: 把 serve-stale 窗口下发到缓存层, 过期窗口内条目保留不被
        # get/purge 删除(上游故障期间可反复兜底); 超窗口死条目仍正常清除。
        try:
            # v1.9.82: serve_stale=false 时不保留过期条目, 避免白占内存
            # R6/P3-1: stale_ttl 默认值统一为 3600(与 .get("stale_ttl",3600)
            # 键缺失默认一致)。原 __init__/reload 用 0 兜底、miss/answer_fast 用
            # 3600 兜底, 导致"畸形值→缓存层 purge 窗口 0 秒但 get_stale 服务窗口
            # 3600 秒"的双窗口分裂。五处统一 3600: 畸形→用 3600s 兜底而非关闭。
            self.cache.stale_window = _safe_int(cfg.get("stale_ttl", 3600), 3600) if cfg.get("serve_stale", False) else 0
        except Exception:
            pass
        self._speed_lock = threading.Lock()
        # 客户端侧 EDNS bufsize 上限: 钳制客户端声明的 UDP payload, 防开放解析器
        # 放大攻击(客户端可自声明 65535)。应答超限走 TC→TCP。
        self._client_bufsize_cap = _safe_int(cfg.get("edns_client_max_size", 1232), 1232)
        # 候选 IP 测速结果缓存: ip -> (rtt_ms, ts)。命中直接复用, 避免重复探测。
        self._ip_speed_cache = {}
        self._ip_speed_lock = threading.Lock()
        # 上游延迟排序缓存: 避免每次 miss 都对所有上游做 sorted() + 多次 _upstream_eff_lat 调用。
        # 延迟值变化较慢(EWMA), 缓存排序结果 5s 刷新一次即可, 减少 miss 热路径开销。
        # P1-1: 三字段打包为单元素元组原子发布, 避免读端看到混合态。
        # 元组结构: (sorted_list, ts, key)
        self._sorted_ups = None             # (sorted_list, ts, key) 原子发布的缓存元组
        # 测速节流表: 按域名记录最近测速时间, 用 OrderedDict 限长(防长时压测
        # 随机域名导致 dict 无限增长的内存泄漏)
        self._last_speed_test = OrderedDict()   # domain -> ts
        self._speed_hist_max = 4096
        self._prefetch_lock = threading.Lock()
        self._prefetch_pending = set()
        # v1.9.86 P2-1: 预取待调度队列硬上限。与其它有界累积结构对齐
        # (_ip_speed_cache 65536 / _err_log_ts 8192 / _rule_match_cache 8192)。
        # 极端随机域名洪泛下(唯一域名速率 > 扫描消化速率 2000/tick)裸 set 会
        # 无界增长可达数十万条; 满则放弃本次标记, 下轮扫描自然消化。
        self._prefetch_pending_max = 65536
        self._stale_refreshing = set()      # serve-stale 后台刷新去重
        # 分流规则索引: 10 万条规则线性扫描每查询 20ms+ 严重拖慢 miss 吞吐。
        # 精确规则按域名哈希, 通配规则按 core 后缀哈希; 规则变更时 rebuild。
        # H-4: 六个索引引用打包为单个元组, 重建时单次原子赋值。match_rule 一次
        # 解包得到一致快照, 绝不会读到"旧 exact + 新 wild"的混合状态。
        # 元组布局: (exact, wild, allow_exact, allow_wild, suffix_wild, regex)
        self._rule_index = ({}, {}, {}, {}, {}, [])
        self._rule_match_cache = {}         # domain -> rule/None(哨兵), 规则重建时清空
        self._rule_cache_max = 8192
        # v1.9.76 2.10: match_rule 缓存普通 dict, 多 worker 线程并发读写(读热路径 +
        # 淘汰迭代)无锁。CPython GIL 下单次 get/set 安全, 但 _cache_rule 的"满则迭代
        # list 半量淘汰"在并发下可能读到中间态/重复淘汰。加锁保护缓存读与写。
        self._rule_cache_lock = threading.Lock()
        self._has_group_rules = False       # 有无 group 分流规则: 无则 _ckey 跳过 match_rule
        self._rebuild_rule_index()
        # Bootstrap 预解析: 用 UDP 上游解析所有 DoH/DoT hostname, 缓存 IP,
        # 后续连接用 IP+SNI, 彻底摆脱系统 /etc/resolv.conf 依赖(限制2解决)。
        # 解析失败的上游回退系统 getaddrinfo, 不影响启动。
        try:
            from . import upstream as _up_mod
            _bs = cfg.get("bootstrap_dns", "223.5.5.5:53")
            _total = len([u for u in cfg.get("upstreams", [])
                          if str(u.get("proto", "")).lower() in ("doh","dot","doh3","doq")
                          and _up_mod._is_hostname(_up_mod._host_port(u)[0])])
            _n = _up_mod.bootstrap_resolve_all(cfg.get("upstreams", []), _bs)
            log.info("bootstrap 预解析: %d/%d 个 DoH/DoT hostname → IP+SNI (bootstrap=%s, 并发≤5s)", _n, _total, _bs)
        except Exception as _e:
            log.warning("bootstrap 预解析失败(回退系统DNS): %s", _e)
        # 上游熔断器: 连续失败达阈值则临时跳过该上游(open 期间), 防止单个
        # 不可达/故障上游拖垮所有 miss 查询; 成功后自动重置。
        self._cb_lock = threading.Lock()
        self._cb = {}  # up_id -> {"fails": int, "until": float}
        self._cb_fails = _safe_int(cfg.get("circuit_fails", 3), 3)
        self._cb_open_s = _safe_int(cfg.get("circuit_open_s", 30), 30)
        # 限速错误上报: silent 模式下(真实 DNS 流量)查询级错误也必须进
        # events(控制台可见)与 journal(可审计), 但压测/故障高峰每秒可能
        # 数十条同类错误, 不限速会刷爆 events deque 与 systemd journal。
        # 按错误类别每 5s 最多上报一条, 既保留异常可见性又防刷屏。
        self._err_log_ts = OrderedDict()  # OrderedDict: popitem(last=False) 淘汰最旧项(原 plain dict 不支持该参数导致内存泄漏)
        self._err_log_lock = threading.Lock()
        # 共享上游查询线程池：miss 吞吐受限于 worker 数 x 上游并发。
        # 每 miss 并行占用 max_par 个 worker, 池太小会让并发 miss 排队拖垮吞吐。
        # 默认 4 倍余量 -> 单查询并发 x 8, 下限 16, 上限 48, 防止过载时无界排队。
        # 有界队列: 队列满时 submit 阻塞(反压), 防止慢协议高峰任务无界堆积内存。
        up_workers = min(48, max(16, _safe_int(cfg.get("max_parallel_upstreams", 3), 3) * 8))
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
    def resolve(self, domain, qtype, silent=False, counted=True, force_refresh=False, client_ip=None, _depth=0, max_upstreams=None):
        """核心解析流程。返回结构化结果 dict (含 rcode)。

        force_refresh=True: 跳过缓存命中直接重新解析(供预取在 TTL 到期前刷新)。
        client_ip: 查询来源客户端 IP, 用于实时查询日志展示; 后台任务(预取/刷新)传 None。
        max_upstreams: 限制并发查询的上游数量(None=用配置 max_parallel_upstreams); 预取时传 1 只用最快上游。
        """
        d = self._normalize(domain)
        qtype = str(qtype).upper()
        if not d:
            return self._error(None, qtype, "empty-domain", "空域名", silent)
        # R32/P3-2: 标签长度预检。encode_name 对 >63 字节标签/总长 >255 抛
        # DNSError, 该异常原本会从 _build_query_map 一路穿透到 server 层; 内部路径
        # (配置规则/预取/CNAME 串)可能带入超长标签。此处按 RFC 1035 §3.3 预检,
        # 超限直接返回 FORMERR(rcode=1), 不再让异常上抛导致 worker 线程退出。
        _wire_len = 1  # 根终止符
        _bad_label = False
        for _lab in d.split("."):
            ll = len(_lab)
            _wire_len += 1 + ll
            if ll > 63 or _wire_len > 255:
                _bad_label = True
                break
        if _bad_label:
            trace = [{"tag": "warn",
                      "text": "域名标签非法(单标签>63字节或线格式总长>255) → FORMERR"}]
            return self._result(d, qtype, [], None, False, True, "formerr",
                                0, trace, 0, empty=True, rcode=1)
        # R33/P3-2: 上方按 Python len()(Unicode 码点数)预检, 对纯 ASCII 标签
        # (99%+ 真实查询)与线格式字节长度等价, 可快速拦截; 但非 ASCII 标签经
        # encode_name 的 IDNA/punycode 编码后字节长度可能大于码点数(非 ASCII 字符
        # punycode 膨胀后单标签 >63 字节), 上述按码点数的预检会漏放。以 encode_name
        # 实际编码结果为权威兜底: 编码抛 DNSError → FORMERR, 不再让异常从
        # _build_query_map 穿透出 resolve()。仅对非 ASCII 域名付出额外一次编码
        # 开销(ASCII 快速通道已由上方预检覆盖, 不增加热路径成本)。
        if not d.isascii():
            try:
                dnsmsg.encode_name(d)
            except dnsmsg.DNSError:
                trace = [{"tag": "warn",
                          "text": "域名标签非法(IDNA 编码后单标签>63字节或线格式总长>255) → FORMERR"}]
                return self._result(d, qtype, [], None, False, True, "formerr",
                                    0, trace, 0, empty=True, rcode=1)
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
            stale_entry = self.cache.get_stale(key, now, _safe_int(cfg.get("stale_ttl", 3600), 3600))
        c = self.cache.get(key, now)
        if c is not None and not force_refresh:
            # 规则复查: 屏蔽规则优先级高于缓存(含内核直答/负缓存/过期兜底), 防止规则添加前已缓存的答案绕过屏蔽
            _rule = self.match_rule(d)
            if _rule and _rule.get("action") == "block":
                tel.inc_rule("block")
                lat = (time.monotonic() - t0) * 1000
                trace.append({"tag": "rule", "text": "分流规则 [%s] 命中(缓存命中复查): 屏蔽该域名 → NXDOMAIN" % _rule.get("match")})
                if not silent:
                    tel.log(d, qtype, "rule", "规则屏蔽(缓存命中复查) → NXDOMAIN", lat,
                            client_ip=client_ip, upstream="规则屏蔽", answer="", rule=self._rule_label(_rule))
                self._err_report(key, d, qtype, "NXDOMAIN (规则屏蔽 %s)" % _rule.get("match"), lat,
                                 client_ip=client_ip, upstream="规则屏蔽", answer="")
                return self._result(d, qtype, [], None, False, False, "blocked",
                                    latency=lat, trace=trace, ttl_left=0, rcode=3)
            lat = (time.monotonic() - t0) * 1000
            if counted:
                tel.inc("hit")
            if cfg.get("kernel_direct", True) and c.get("rcode", 0) == 0:
                tel.inc("kernel_direct")
            # R42/P2-1: 与 answer_fast 快路径(:1128)同型补 uint32(int32) 上限钳制。
            # R41 只钳了快路径 ttl_override, 本完整路径缓存命中漏了。persist_ttl 手配
            # > 2147483647 且 QR-bit 异常报文落入 resolve() 缓存命中时, ttl_left ≈ 5e9
            # 经 answer_raw → build_response → _RR_HDR.pack(">I", ...) 抛 struct.error。
            ttl_left = min(2147483647, max(0, int(c["expires_at"] - now)))
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
            if not c.get("answers"):
                # 负缓存 NODATA (rcode=0 但无答案)
                trace.append({"tag": "bpf", "text": "BPF LRU map 命中 (负缓存 NODATA, TTL 剩余 %ds)" % ttl_left})
                trace.append({"tag": "ok", "text": "应答 NODATA  耗时 %.2fms" % lat})
                if not silent:
                    tel.log(d, qtype, "hit", "缓存直答 NODATA", lat,
                            client_ip=client_ip, upstream="缓存直答", answer="NODATA",
                            rule=self._rule_label(_rule) if _rule else None)
                return self._result(d, qtype, [], None, True, False, None,
                                    latency=lat, trace=trace, ttl_left=ttl_left, empty=True, rcode=0)
            mode = "内核直接构造应答" if cfg.get("kernel_direct", True) else "用户态直答(内核直答已关闭)"
            trace.append({"tag": "bpf", "text": "BPF LRU map 命中 (TTL 剩余 %ds), %s" % (ttl_left, mode)})
            trace.append({"tag": "ok", "text": "应答 %s  耗时 %.2fms (%s)" % (c["chosen"], lat, "内核直答" if cfg.get("kernel_direct", True) else "缓存直答")})
            if not silent:
                tel.log(d, qtype, "hit", "内核直答 → %s" % c["chosen"], lat,
                        client_ip=client_ip,
                        upstream="内核直答" if cfg.get("kernel_direct", True) else "缓存直答",
                        answer=c["chosen"], rule=self._rule_label(_rule) if _rule else None)
            self.schedule_prefetch(key, d, qtype)  # 命中即续入预取队列(与持久化恢复配合)
            # v1.9.81: TTL 随剩余时间衰减, 不直接复用写入时的固定 ttl
            hit_answers = [dict(a, ttl=ttl_left) for a in c["answers"]]
            return self._result(d, qtype, hit_answers, c["chosen"], True, False, None,
                                latency=lat, trace=trace, ttl_left=ttl_left, rcode=0)
        # ---- 过期缓存兜底 (serve-stale): 缓存过期但在 stale 窗口内 ----
        if stale_entry is not None:
            _rule = self.match_rule(d)
            if _rule and _rule.get("action") == "block":
                tel.inc_rule("block")
                lat = (time.monotonic() - t0) * 1000
                trace.append({"tag": "rule", "text": "分流规则 [%s] 命中(过期缓存复查): 屏蔽该域名 → NXDOMAIN" % _rule.get("match")})
                if not silent:
                    tel.log(d, qtype, "rule", "规则屏蔽(过期缓存复查) → NXDOMAIN", lat,
                            client_ip=client_ip, upstream="规则屏蔽", answer="", rule=self._rule_label(_rule))
                self._err_report(key, d, qtype, "NXDOMAIN (规则屏蔽 %s)" % _rule.get("match"), lat,
                                 client_ip=client_ip, upstream="规则屏蔽", answer="")
                return self._result(d, qtype, [], None, False, False, "blocked",
                                    latency=lat, trace=trace, ttl_left=0, rcode=3)
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
            if not stale_entry.get("answers"):
                # 过期 NODATA 负缓存兜底
                trace.append({"tag": "bpf", "text": "过期缓存兜底: NODATA 负缓存(已过期, TTL 0s)"})
                trace.append({"tag": "ok", "text": "应答 NODATA(serve-stale)  耗时 %.2fms" % lat})
                if not silent:
                    tel.log(d, qtype, "hit", "serve-stale NODATA", lat,
                            client_ip=client_ip, upstream="serve-stale", answer="")
                self._trigger_stale_refresh(key, d, qtype)
                return self._result(d, qtype, [], None, True, False, None,
                                    latency=lat, trace=trace, ttl_left=0, empty=True, rcode=0)
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
            tel.inc_rule("block")
            lat = (time.monotonic() - t0) * 1000
            trace.append({"tag": "rule", "text": "分流规则 [%s] 命中: 屏蔽该域名 → 返回 NXDOMAIN" % rule.get("match")})
            if not silent:
                tel.log(d, qtype, "rule", "规则屏蔽 → NXDOMAIN", lat,
                        client_ip=client_ip, upstream="规则屏蔽", answer="", rule=self._rule_label(rule))
            self._err_report(key, d, qtype, "NXDOMAIN (规则屏蔽 %s)" % rule.get("match"), lat,
                             client_ip=client_ip, upstream="规则屏蔽", answer="")
            return self._result(d, qtype, [], None, False, False, "blocked",
                                latency=lat, trace=trace, ttl_left=0, rcode=3)
        ups = [u for u in cfg.get("upstreams", []) if u.get("enabled", True)]
        if rule and rule.get("action") == "group":
            g = rule.get("group")
            tel.inc_rule("domestic" if g == "domestic" else "global")
            filtered = [u for u in ups if u.get("group") == g]
            if filtered:
                ups = filtered
                trace.append({"tag": "rule", "text": "分流规则 [%s] 命中: 仅使用「%s」组上游 (%d 个)" % (rule.get("match"), g, len(filtered))})
            else:
                trace.append({"tag": "warn", "text": "分流规则 [%s] 命中: 「%s」组无启用上游, 回退全部上游" % (rule.get("match"), g)})
            if not silent:
                tel.log(d, qtype, "rule", "分流规则 → 「%s」组" % g, 0,
                        client_ip=client_ip, upstream="分流规则", answer="", rule=self._rule_label(rule))
        if rule and rule.get("action") == "forceIp":
            tel.inc_rule("forceIp")
            ip = rule.get("ip", "")
            rtype = self._guess_type(ip, qtype)
            lat = (time.monotonic() - t0) * 1000
            # 查询类型与强制 IP 类型不匹配(如 AAAA 查询但配置 IPv4) → 返回 NODATA
            qtype_code = dnsmsg.type_code(qtype) or dnsmsg.TYPE_A
            if rtype != qtype_code:
                trace.append({"tag": "rule", "text": "分流规则 [%s] 强制 IP %s 与查询类型 %s 不匹配 → NODATA" % (rule.get("match"), ip, qtype)})
                # M2: 写空 answers 负缓存(与 NODATA 负缓存格式一致), 避免每次同类型
                # 不匹配查询都走完整 miss 路径。
                neg_ttl = max(1, self._clamp_ttl(min(_safe_int(cfg.get("ttl", 300), 300), 60), rule))
                now_neg = time.time()
                self.cache.put(key, {
                    "domain": d, "qtype": qtype, "answers": [], "chosen": "",
                    "ttl": neg_ttl, "rcode": 0,
                    "expires_at": now_neg + neg_ttl,
                })
                if not silent:
                    tel.log(d, qtype, "rule", "forceIp 类型不匹配 → NODATA", lat,
                            client_ip=client_ip, upstream="分流规则", answer="", rule=self._rule_label(rule))
                return self._result(d, qtype, [], None, False, False, None,
                                    latency=lat, trace=trace, ttl_left=neg_ttl, empty=True, rcode=0)
            # R6/P2-1: 原裸 cfg.get("ttl",300) 直传 _clamp_ttl(后者 int(ttl)),
            # 畸形串("abc")在 forceIp 规则路径抛 ValueError。统一 _safe_int 包裹。
            rttl = self._clamp_ttl(_safe_int(cfg.get("ttl", 300), 300), rule)   # 规则级 TTL 覆盖
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
            # 按实测延迟排序(无实测时回退配置静态延迟), 先并发最快 max_upstreams 个
            # 全部失败时自动回退到剩余上游(保持旧版容错性, 同时减少正常场景的上游请求)
            _n = max_upstreams if max_upstreams is not None else _safe_int(cfg.get("max_parallel_upstreams", 3), 3)
            _n = max(1, min(_n, len(ups)))
            # 排序缓存: 延迟值变化慢(EWMA), 5s 刷新一次避免每次 miss 都做 sorted()
            _now_sort = time.monotonic()
            _ups_sig = tuple(u.get("id", "") for u in ups)
            # P1-1: 单次读取元组后解包, 单次原子赋值发布新元组, 杜绝混合态。
            _cached = self._sorted_ups
            if (_cached is None
                    or _cached[2] != _ups_sig
                    or _now_sort - _cached[1] > 5.0):
                _sorted_list = sorted(ups, key=self._upstream_eff_lat)
                self._sorted_ups = (_sorted_list, _now_sort, _ups_sig)
                _all_ups = _sorted_list
            else:
                _all_ups = _cached[0]
            ups = _all_ups[:_n]
            _backup_ups = _all_ups[_n:] if _n < len(_all_ups) else []
            trace.append({"tag": "eng", "text": "解析失败降级开 → 先并发最快 %d/%d 个上游(实测延迟排序): %s%s" % (
                _n, len(_all_ups), " / ".join(u.get("name") or u.get("id", "?") for u in ups),
                (" (失败回退 %d 个)" % len(_backup_ups)) if _backup_ups else "")})
        else:
            ups = ups[:1]
            _backup_ups = []
            trace.append({"tag": "warn", "text": "解析失败降级关 → 仅用首选上游 %s (失败即 SERVFAIL)" % (
                ups[0].get("name") or ups[0].get("id", "?"))})
        # ---- 构造查询（EDNS + 防分片 + 加密填充） ----
        # 按上游协议分组构造: 明文 UDP/TCP 用不填充报文; DoT/DoH/DoH3/DoQ 等
        # 加密协议在 EDNS OPT 中携带 Padding 选项(抹平长度指纹, RFC 8467)。
        # EDNS UDP size 全部钳制到 edns_udp_size(默认 1232 防分片安全值)。
        qmap = self._build_query_map(d, qtype)
        query_bytes = qmap["default"]
        # ---- 多上游并发 ----
        results = self._query_parallel(ups, query_bytes, d, qtype, trace, qmap=qmap)
        if counted:
            tel.inc("upstream_queries", len(ups))
        ok_results = [r for r in results if r.get("answers")]
        # ---- 最快N个全部失败 → 回退剩余上游(仅真失败, NXDOMAIN/NODATA不回退) ----
        if not ok_results and _backup_ups:
            _all_fail = all(not r.get("answers") and r.get("rcode") not in (0, 3) for r in results)
            if _all_fail:
                trace.append({"tag": "warn", "text": "最快 %d 个上游全部失败 → 回退剩余 %d 个上游" % (len(ups), len(_backup_ups))})
                _bk = self._query_parallel(_backup_ups, query_bytes, d, qtype, trace, qmap=qmap)
                if counted:
                    tel.inc("upstream_queries", len(_backup_ups))
                results.extend(_bk)
                ok_results = [r for r in results if r.get("answers")]
        if not ok_results:
            # 全部无答案 → 区分 NXDOMAIN / NODATA / 真失败
            nx = [r for r in results if r.get("rcode") == 3]
            # 超时路径同样套用 NXDOMAIN 多数表决(与 _query_parallel 提前返回的
            # quorum 语义一致): 仅当一致 NXDOMAIN 的上游数 >= quorum 才确认域名
            # 不存在。quorum 钳到实际参与并发的上游数(len(results)), 单上游配置
            # 恒为 1。此前全部等待结束后只要 1 个 NXDOMAIN、其余网络失败即缓存
            # NXDOMAIN, 单个被劫持上游可在其他上游不可达时注入否定结果。
            _nx_quorum = max(1, min(_safe_int(cfg.get("nxdomain_quorum", 2), 1), len(results)))
            if nx and len(nx) >= _nx_quorum:
                lat = (time.monotonic() - t0) * 1000
                # v1.9.76 2.7: authority 段有 SOA 时优先用其 minimum(负缓存权威 TTL);
                # 否则默认 [10,60] 秒。再经 _clamp_ttl 受 ttl_min/ttl_max 管控。
                neg_ttl = self._neg_ttl(nx, rule, cfg)
                now_neg = time.time()
                self.cache.put(key, {
                    "domain": d, "qtype": qtype, "answers": [], "chosen": "",
                    "ttl": neg_ttl, "rcode": 3,
                    "expires_at": now_neg + neg_ttl,
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
                                   client_ip=client_ip, _depth=_depth + 1,
                                   max_upstreams=max_upstreams)
                sub_ans = sub.get("answers") or []
                if not sub.get("error") and sub_ans:
                    # P3/R25: sub_ans 的 dict 与子缓存共享引用(resolve miss 路径
                    # 返回的 answers 即子缓存 _fill_cache 入库的同一批 dict)。
                    # _fill_cache 会就地改写 ttl, 浅拷贝隔离父子, 避免污染子缓存条目。
                    answers = chain + [dict(a) for a in sub_ans]
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
                # v1.9.74 P2-3: AAAA 查询 NODATA 时, ipv4_first 模式绝不能把 A 记录
                # 塞进 AAAA 应答——类型错配(客户端问 AAAA 却收到 A 记录)破坏 DNS 语义。
                # _ipv4_fallback 仅用于预热 A 缓存与 trace/日志观测, 应答仍为空 NODATA。
                if qtype == "AAAA" and cfg.get("ipv4_first", True):
                    fall = self._ipv4_fallback(d, ups, cfg, trace)
                    if fall:
                        tel.inc("ipv4_fallback")
                        trace.append({"tag": "eng",
                                      "text": "AAAA NODATA(类型隔离): 观测到 A=%s, 仅记录不塞 AAAA 应答" % fall[0]["value"]})
                        if not silent:
                            lat_obs = (time.monotonic() - t0) * 1000
                            tel.log(d, qtype, "miss", "AAAA NODATA (观测 A=%s 仅记录)" % fall[0]["value"], lat_obs,
                                    client_ip=client_ip,
                                    upstream="IPv4观测:" + str(fall[0].get("from", "?")),
                                    answer="")
                lat = (time.monotonic() - t0) * 1000
                # NODATA 负缓存: 与 NXDOMAIN 一致; SOA minimum 优先, 否则默认 [10,60]。
                neg_ttl = self._neg_ttl(nodata, rule, cfg)
                now_neg = time.time()
                self.cache.put(key, {
                    "domain": d, "qtype": qtype, "answers": [], "chosen": "",
                    "ttl": neg_ttl, "rcode": 0,
                    "expires_at": now_neg + neg_ttl,
                })
                tel.push_latency(lat)
                trace.append({"tag": "eng", "text": "上游无该类型记录 (NODATA), 负缓存 %ds → 空应答 NOERROR" % neg_ttl})
                if not silent:
                    tel.log(d, qtype, "miss", "NODATA (负缓存)", lat,
                            client_ip=client_ip,
                            upstream=" / ".join(r.get("up_name", "?") for r in nodata[:3]),
                            answer="")
                return self._result(d, qtype, [], None, False, False, None,
                                    latency=lat, trace=trace, ttl_left=neg_ttl, empty=True, rcode=0)
            # ---- 启动预热重试: 冷启动/重启早期(45s)上游 TLS 未就绪, 全部失败时
            #      延迟 1s 重试一次, 避免用户刚部署/重启就遇到 SERVFAIL。全局至多
            #      3 次, 稳态完全不受影响(压测/故障高峰不会放大延迟)。
            boot_warm = (time.monotonic() - self._boot_ts) < 45
            if boot_warm:
                retry = False
                # R2-P3 [P2-3]: 把 Event is_set() 检查与预算扣减放进同一锁块,
                # 消除原"锁内只扣计数、锁外才查 Event"的预算漂移——两查询线程可同时
                # 扣计数(0→1、1→2), 随后一个 set Event, 另一个查 set 而放弃重试,
                # 导致已扣预算却未执行真实重试(全局"至多 3 次"实际只跑 2 次)。
                # 锁内同时完成"Event 状态确认 + 预算检查 + 扣减 + set Event", 原子化。
                with self._boot_retry_lock:
                    if (not self._boot_retry_in_progress.is_set()
                            and self._boot_retries < 3):
                        self._boot_retry_in_progress.set()
                        self._boot_retries += 1
                        retry = True
                if retry:
                    try:
                        trace.append({"tag": "warn", "text": "启动预热: 上游未就绪, 500ms 后重试"})
                        # R-04: 缩短阻塞时间 1s→500ms, 减少 worker 线程占用。
                        # R-03: boot 重试不消耗 CNAME 深度(原 _depth+1 会导致深层 CNAME
                        # 链在 boot 重试时达到深度上限被截断为 NODATA)。
                        time.sleep(0.5)
                        return self.resolve(d, qtype, silent=silent, counted=False,
                                            force_refresh=force_refresh,
                                            client_ip=client_ip, _depth=_depth)
                    finally:
                        self._boot_retry_in_progress.clear()
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
        # v1.9.76 2.2: rebind_protection 按上游开关。上游配置 allow_private_ip:true
        # 的, 其返回的私有 IP 答案不过滤(内网自建解析场景需要)。按上游名统计豁免集合。
        _allow_priv_names = {u.get("name") for u in (cfg.get("upstreams") or [])
                             if u.get("allow_private_ip")}
        cand = {}
        for r in ok_results:
            for a in r["answers"]:
                v = a["value"]
                if v not in cand:
                    proto = str(r.get("proto", "udp")).lower()
                    # R6/P2-1: cand["ttl"] 兜底原裸 cfg.get("ttl",300); 上游答案缺
                    # ttl 键时 :889 min(cand[v]["ttl"], ...) 会拿畸形串与 int 比较
                    # 抛 TypeError。统一 _safe_int 兜底为 int。
                    cand[v] = {"value": v, "from": [], "ttl": a.get("ttl", _safe_int(cfg.get("ttl", 300), 300)),
                               "type": a.get("type", dnsmsg.type_code(qtype)), "lat": r["lat"],
                               "probe": "tcp443" if proto in ("doh", "dot", "doq", "doh3") else "udp53",
                               "allow_private": False}
                if r["up_name"] not in cand[v]["from"]:
                    cand[v]["from"].append(r["up_name"])
                # 任一贡献该答案的上游豁免私有 IP → 该答案整体豁免
                if r.get("up_name") in _allow_priv_names:
                    cand[v]["allow_private"] = True
                cand[v]["ttl"] = min(cand[v]["ttl"], a.get("ttl", cand[v]["ttl"]))
        cand_list = list(cand.values())
        # ip_speed_probe 配置控制探测协议: udp53/tcp443/both(按上游协议决定)
        _probe_cfg = str(self.cfg.get("ip_speed_probe", "both")).lower()
        if _probe_cfg in ("udp53", "tcp443"):
            for _c in cand_list:
                _c["probe"] = _probe_cfg
        # ---- 响应 IP 合法性校验(防 DNS 劫持/rebinding): 过滤私有/保留地址 ----
        # 上游返回的 A/AAAA 若为内网/保留地址(如 10.x/192.168.x/127.x/fc00::/7),
        # 视为劫持响应或 DNS rebinding 攻击, 丢弃该答案。forceIp 规则与
        # allow_private_ip:true 的上游豁免。
        # 注意: 仅对 A/AAAA 类型做 rebind 防护, MX/SRV/TXT 等类型目标为域名
        # 后续仍需解析, 风险低, 不做 IP 过滤。
        if cfg.get("rebind_protection", True) and qtype in ("A", "AAAA") and not (rule and rule.get("action") == "forceIp"):
            _before = len(cand_list)
            cand_list = [a for a in cand_list if a.get("allow_private") or not self._is_private_ip(a["value"])]
            if len(cand_list) < _before:
                _dropped = _before - len(cand_list)
                trace.append({"tag": "warn", "text": "IP 合法性校验: 丢弃 %d 个私有/保留地址答案" % _dropped})
                tel.inc("rebind_blocked")
                if not cand_list:
                    # 全部答案都是私有 IP → NODATA(不返回劫持结果)
                    tel.inc("errors")
                    lat = (time.monotonic() - t0) * 1000
                    tel.push_latency(lat)
                    trace.append({"tag": "warn", "text": "全部答案为私有/保留地址 → 返回 NODATA"})
                    if not silent:
                        tel.log(d, qtype, "err", "rebind_protection: 全部答案为私有IP", lat,
                                client_ip=client_ip, upstream=" / ".join(r.get("up_name", "?") for r in ok_results[:3]),
                                answer="")
                    return self._result(d, qtype, [], None, False, False, None,
                                        latency=lat, trace=trace, ttl_left=0, empty=True, rcode=0)
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
        # R6/P2-1: 原裸 cfg.get("ttl",300) 进 min(), 畸形串与 int 比较抛 TypeError
        # 穿透 resolve→answer_raw, 每次成功 miss 都 SERVFAIL(主路径全域名受影响)。
        # 两处 cfg.get("ttl") 均 _safe_int 兜底为 int。
        raw_ttl = min(_safe_int(cfg.get("ttl", 300), 300), min((a["ttl"] for a in answers), default=_safe_int(cfg.get("ttl", 300), 300)))
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
        self.schedule_prefetch(key, d, qtype)
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
        # R-01: QR 位在 flags 高字节(byte 2), 原误查 byte 3(RA 位)。
        # 非递归服务器响应 RA=0 时会漏过此检查被当查询处理。
        if len(raw_query) > 3 and (raw_query[2] & 0x80):
            return None
        if isinstance(client_addr, (tuple, list)) and client_addr:
            client_addr = client_addr[0]   # server 传 (host, port), 日志只显示 IP
        q = msg["questions"][0]
        if q["qclass"] != dnsmsg.CLASS_IN:
            return None
        # v1.9.76 2.5: opcode!=0(AXFR/NOTIFY/UPDATE 等)不走快路径缓存直答,
        # 落到 answer_raw 返回 NOTIMP(4)。否则被缓存命中会误返 NOERROR。
        if msg.get("opcode", 0) != 0:
            return None
        # DNS 名不区分大小写: parse_message 返回的 name 保留线上大小写(0x20 随机大小写),
        # 必须小写后做缓存 key, 否则 "WWW.BAIDU.COM" 与 "www.baidu.com" 命中不同缓存条目。
        domain = q["name"].lower()
        qtype_name = q.get("qtype_name") or dnsmsg.type_name(q["qtype"])
        key = self._ckey(domain, qtype_name)
        t0 = time.monotonic()
        now = time.time()
        # serve-stale 先取过期条目(cache.get 会删除过期条目, 必须先查 stale)
        stale_entry = None
        if self.cfg.get("serve_stale", False):
            stale_entry = self.cache.get_stale(key, now, _safe_int(self.cfg.get("stale_ttl", 3600), 3600))
        c = self.cache.get(key, now)
        stale = False
        if c is None and stale_entry is not None:
            # 过期缓存兜底: 返回旧数据(TTL=0)并触发后台刷新, 避免上游故障/网络抖动
            # 时内网客户端拿到 SERVFAIL; 刷新完成后恢复新鲜缓存。
            c = stale_entry
            stale = True
        if c is None:
            return None
        # H1: 快路径缓存命中后复查 block 规则——管理员新增 block 规则后, 已缓存的
        # 被屏蔽域名不能仍由快路径直接返回答案。命中 block 则 fallthrough 到完整路径
        # 走 block 分支(match_rule 有结果缓存, O(1) 热路径开销可接受)。
        _rule = self.match_rule(domain)
        if _rule and _rule.get("action") == "block":
            return None
        tel = self.tel
        rcode = c.get("rcode", 0)
        if stale:
            tel.inc("stale_served")
            self._trigger_stale_refresh(key, domain, qtype_name)
        lat = (time.monotonic() - t0) * 1000
        kd = self.cfg.get("kernel_direct", True) and not stale
        # v1.9.74 P0-2: question 段必须原样回显客户端查询字节(含 0x20 大小写)。
        # 旧实现用小写化 domain 编码 question 段并把 question+answer 一起缓存进
        # resp_body, 导致响应 question 大小写与查询不一致 → 上游 check_0x20 判投毒
        # 丢弃。现: question 段每次从 raw_query 原样切片; resp_body 只缓存 answer 段。
        # v1.9.85: 一遍遍历同时拿到 qbytes + bufsize + opt(原 extract_question 一遍,
        # build_udp_response 内部 _edns_bufsize + _opt_rr_bytes 又两遍 question 段)。
        qbytes, _limit, opt = dnsmsg._question_edns_info(raw_query)
        # 钳制客户端声明的 bufsize 上限(防放大攻击)
        _limit = min(_limit, self._client_bufsize_cap)
        _edns = (_limit, opt)
        if qbytes is None:
            # R5/P3-2: 切片失败兜底(极罕见, 仅当 question 段畸形/截断时触发, 正常包
            # 走不到)。domain 在上方已 .lower() 做缓存 key, 此处用它重编码 question 段
            # 会丢失客户端原始大小写 → 破坏 0x20 投毒防护熵。权衡: 该分支本就是防御性
            # 兜底, 客户端发畸形 question 时上游 0x20 校验语义已不成立; 重编码小写是
            # 可接受的降级(与 build_simple_response 的 b"" 兜底一致)。正常包走 raw_query
            # 原样切片路径(:1006), 0x20 大小写完整保留, 不受影响。
            qbytes = dnsmsg.build_response_body(domain, q["qtype"], [])
        if rcode == 3:
            # NXDOMAIN 无 answer 段; v1.9.76 2.5 回显 OPT(复用已算好的 qbytes/opt,
            # 不再让 build_simple_response 重新遍历 question/additional 段)
            resp = (dnsmsg.build_response_header(raw_query, 3, 0, False, 1 if opt else 0)
                    + qbytes + (opt or b""))
            # 合并 fast_hit + log: 一次加锁(原两次锁竞争)
            tel.fast_hit_logged(qtype_name, len(raw_query), len(resp) if resp else 0, lat,
                                domain, "缓存直答 NXDOMAIN",
                                upstream="缓存直答", answer="NXDOMAIN")
            return resp
        if rcode == 0:
            # v1.9.85: TTL 衰减通过 _ttl_override 下推到编码器, 不再每命中一次
            # [dict(a, ttl=...) for a in answers] 拷贝整条 answers list + 每答案一个
            # 新 dict(热路径临时对象/GC 压力)。直接读原始 c["answers"](只读不改)。
            if stale:
                # serve-stale: 下发 TTL=0(告知客户端勿缓存), 后台刷新中; 不写回缓存
                ttl_override = 0
            else:
                # v1.9.81: TTL 随剩余时间衰减, 不再缓存含绝对 TTL 的 resp_body
                # (旧实现客户端在第 299 秒仍收到 TTL=300)。answers ≤8 条, 重编码微秒级。
                # R41/P3-1: R38 _clamp_ttl 只覆盖 _fill_cache 写入缓存路径, 快路径直接
                # 读 expires_at - now 不经过钳制。persist_ttl 手配 > 4294967295 时重启
                # 恢复后命中, 此处 ttloverride 可达 1e12, 进 _rr_hdr.pack(">I", ...) 抛
                # struct.error。补与 _clamp_ttl 一致的 int32 上限钳制。
                ttl_override = min(2147483647, max(0, int(c["expires_at"] - now)))
            # P3-1: 答案数超 MAX_ANSWERS 时 abody 含被丢弃的多余记录, 构造它是无效工作。
            # 超限时直接传 abody=None, 走 build_udp_response 的逐条重编码截断路径。
            if len(c["answers"]) <= dnsmsg.MAX_ANSWERS:
                abody = dnsmsg.build_response_body_answers(
                    c["answers"], owner_name=domain, fallback_type=q["qtype"],
                    _ttl_override=ttl_override)
            else:
                abody = None
            # v1.9.76 P0-1: 快路径统一走 build_udp_response 做 UDP 截断(>bufsize 逐条
            # 丢尾部置 TC)+ 回显 OPT。TTL 衰减通过 _ttl_override 下推, 截断兜底路径
            # 重编码也用剩余 TTL(原 R-02 传衰减后副本, 现等价语义零拷贝)。
            resp = dnsmsg.build_udp_response(raw_query, qbytes, c["answers"], 0,
                                             abody=abody, owner_name=domain,
                                             fallback_type=q["qtype"], _edns=_edns,
                                             _ttl_override=ttl_override)
            chosen = c.get("chosen", "") or (c["answers"][0]["value"] if c.get("answers") else "")
            _up = "serve-stale" if stale else ("内核直答" if kd else "缓存直答")
            _msg = ("serve-stale → %s" if stale else "内核直答 → %s") % chosen
            # 合并 fast_hit + log: 一次加锁(原两次锁竞争)
            tel.fast_hit_logged(qtype_name, len(raw_query), len(resp) if resp else 0, lat,
                                domain, _msg, upstream=_up, answer=chosen,
                                kernel_direct=kd)
            # 快路径缓存命中也调度预取(原仅 resolve() 完整路径调度, UDP 主线程快路径
            # 直接返回导致预取对大部分缓存命中永不触发)
            if not stale:
                try:
                    self.schedule_prefetch(key, domain, qtype_name)
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
                # L5: 报文解析失败按 RFC 应返回 FORMERR(1), 而非 SERVFAIL(2)
                return dnsmsg.build_error_response(raw_query, 1)
        else:
            msg = parsed
        if not msg["questions"]:
            return dnsmsg.build_error_response(raw_query, 1)
        q = msg["questions"][0]
        domain, qtype = q["name"], q["qtype"]
        qtype_name = dnsmsg.type_name(qtype)
        if q["qclass"] != dnsmsg.CLASS_IN:
            return dnsmsg.build_error_response(raw_query, 4)
        # v1.9.76 2.5: 非标准查询(zone transfer/notify/update 等 opcode!=0)返回
        # NOTIMP(4), 不进入递归解析; 同时回显 OPT(保留 DO 位)。
        if msg.get("opcode", 0) != 0:
            return dnsmsg.build_simple_response(raw_query, 4)
        res = self.resolve(domain, qtype_name, silent=False, client_ip=client_addr)
        self.tel.inc("bytes_in", len(raw_query))
        rcode = res.get("rcode", 2)
        if res.get("error"):
            return dnsmsg.build_error_response(raw_query, 2 if rcode == 2 else rcode)
        answers = res.get("answers", [])
        resp = dnsmsg.build_response(raw_query, domain, qtype, answers, rcode=rcode,
                                     bufsize_cap=self._client_bufsize_cap)
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
        """上游查询失败: 失败计数++, 达阈值打开熔断。

        阈值(circuit_fails)与熔断时长(circuit_open_s)每次失败时实时从 cfg 读取,
        使控制台修改后经 PUT /api/config 或 /api/reload 热重载即时生效,
        不必重启进程(原实现 __init__ 缓存为标量, 热重载后仍用旧值)。
        """
        cb_fails = _safe_int(self.cfg.get("circuit_fails", self._cb_fails), self._cb_fails)
        cb_open_s = _safe_int(self.cfg.get("circuit_open_s", self._cb_open_s), self._cb_open_s)
        with self._cb_lock:
            st = self._cb.setdefault(up_id, {"fails": 0, "until": 0.0})
            st["fails"] += 1
            if st["fails"] >= cb_fails:
                st["until"] = time.time() + cb_open_s

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
        # R5/P2-2: 原 `int(cfg.get("edns_udp_size",1232) or 1232)` 只兜 None 不兜
        # "abc"; 畸形值 ValueError 穿透 miss 路径 → 每次查询 SERVFAIL。改 _safe_int。
        size = _safe_int(cfg.get("edns_udp_size", 1232), 1232)
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
            # P1/R25: rebind_protection 过滤, 与主路径 :945 对齐——
            # 预热 A 缓存不得旁路私有/保留地址过滤, 否则 AAAA NODATA 路径
            # 可被攻击者权威返回 169.254.169.254 预热缓存, 后续 A 查询命中即 rebinding。
            if self.cfg.get("rebind_protection", True):
                _allow_priv = {u.get("name") for u in (self.cfg.get("upstreams") or [])
                               if u.get("allow_private_ip")}
                ans = [a for a in ans if a["from"] in _allow_priv or not self._is_private_ip(a["value"])]
            if ans:
                self._fill_cache(key, d, "A", ans)
                trace.append({"tag": "eng", "text": "双栈探测: 上游确认有 A 记录 → 双栈域名"})
                return True
            trace.append({"tag": "warn", "text": "双栈探测: rebind 过滤后无可用 A 记录 → 按纯 IPv6 处理"})
            return False
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
        # P1/R25: rebind_protection 过滤, 与主路径 :945 对齐——
        # ipv4_first 回退预热 A 缓存不得旁路私有/保留地址过滤。
        if cfg.get("rebind_protection", True):
            _allow_priv = {u.get("name") for u in (cfg.get("upstreams") or [])
                           if u.get("allow_private_ip")}
            ans = [a for a in ans if a["from"] in _allow_priv or not self._is_private_ip(a["value"])]
        if not ans:
            trace.append({"tag": "warn", "text": "IPv4 回退: rebind 过滤后无可用 A 记录 → 维持 NODATA"})
            return None
        self._fill_cache(self._ckey(d, "A"), d, "A", ans)
        trace.append({"tag": "eng", "text": "IPv4 优先回退: AAAA NODATA, 上游查得 A → %s" % ans[0]["value"]})
        return ans

    @staticmethod
    def _soa_minimum(parsed):
        """v1.9.76 2.7: 从响应 authority 段提取 SOA minimum(负缓存权威 TTL)。
        SOA rdata 解析为 "mname rname serial refresh retry expire minimum",
        minimum 为末段。无 SOA 返回 None(调用方回退默认 neg TTL)。"""
        try:
            for rr in (parsed or {}).get("authority", []):
                if rr.get("type") == dnsmsg.TYPE_SOA:
                    parts = str(rr.get("rdata", "")).split()
                    if len(parts) == 7:
                        return max(1, int(parts[6]))
        except Exception:
            pass
        return None

    def _neg_ttl(self, results, rule, cfg):
        """负缓存 TTL: authority 段有 SOA 时取其 minimum(最小值, 权威负 TTL);
        否则默认 min(cfg.ttl, 60)。统一经 _clamp_ttl 受 ttl_min/ttl_max 管控。"""
        soa_vals = [r["neg_ttl"] for r in results
                    if r.get("neg_ttl")]
        base = min(soa_vals) if soa_vals else min(_safe_int(cfg.get("ttl", 300), 300), 60)
        return max(1, self._clamp_ttl(base, rule))

    def _upstream_eff_lat(self, u):
        """上游有效延迟: 优先实测平均延迟, 无实测时回退配置静态延迟。
        失败率>50%的上游惩罚性排后(加 500ms), 避免频繁选到故障上游。"""
        try:
            st = self.tel.upstream_eff_lat_read(u.get("id", ""))
            if st and st.get("ok", 0) > 0:
                avg = st["lat_sum"] / st["ok"]
                total = st["ok"] + st.get("fail", 0)
                if total > 10 and st.get("fail", 0) / total > 0.5:
                    return avg + 500.0  # 高失败率惩罚
                return avg
        except Exception:
            pass
        # R6/P2-2: u 是上游配置 dict, latency 为配置静态延迟; 原裸 float()
        # 对畸形串抛 ValueError。统一 _safe_float 兜底 9999(最差排后)。
        return _safe_float(u.get("latency", 9999), 9999.0)
    @staticmethod
    def _is_private_ip(ip_str):
        """判断 IP 是否为私有/保留/环回/链路本地地址(防 DNS 劫持/rebinding)。
        覆盖 RFC1918/环回/链路本地/共享地址/文档地址/组播/保留, 以及 IPv6 对应段。"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_multicast or ip.is_reserved or ip.is_unspecified)
        except (ValueError, TypeError):
            return False  # 非 IP(如 CNAME 目标域名) 不拦截

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
        timeout = _safe_int(self.cfg.get("timeout_ms", 1500), 1500)
        # 慢上游降级: 滚动平均延迟明显高于超时阈值(>timeout*0.6 且 >800ms)的上游
        # 不参与常规查询(测速/健康度展示仍保留, 熔断恢复探测不受影响), 防止慢上游
        # 持续占用慢池 worker(每个查询至多 timeout 秒)拖垮高并发 miss 吞吐——
        # 实测 opendns 等国外 DoH 国内直连 1.5s+, 若不禁用会在高峰期把 DoH 池占满,
        # 其他上游查询排队超时, 平均延迟从几百 ms 飙到几千 ms。
        _tel = self.tel
        SLOW_THRESH = max(800, int(timeout * 0.6))

        # 批量读取熔断状态(一次加锁, 避免每个上游一次锁竞争)
        with self._cb_lock:
            _cb_snapshot = {uid: (st.get("until", 0.0) and time.time() < st.get("until", 0.0))
                            for uid, st in self._cb.items()}

        def _is_cb_open(u):
            return _cb_snapshot.get(u.get("id", ""), False)

        def _is_slow_up(u):
            # 与 _upstream_eff_lat 对齐: 走锁内快照 upstream_eff_lat_read(),
            # 不再锁外直接读 _tel.per_upstream.get()——并发 upstream_ok 在两次
            # 读取(ok / lat_sum)之间可能半更新, 导致慢上游判定读到中间态。
            try:
                st = _tel.upstream_eff_lat_read(u.get("id"))
            except Exception:
                return False
            if not st or st.get("ok", 0) < 10:  # 采样不足不判定, 避免单次抖动误杀
                return False
            # #3 慢上游恢复窗口: telemetry per_upstream 已在成功路径记录 last=最近一次
            # 成功延迟(upstream_ok/upstream_ok_conn_ok 均写 st["last"])。若最近一次成功
            # 延迟已低于阈值, 视为已恢复, 不判慢——原逻辑只看 lat_sum/ok 滚动均值, 上游
            # 恢复后需积累大量快样本才能把均值拉回阈值下, 期间持续被屏蔽; 现给一次快速
            # 成功即放行, 缩短恢复窗口。
            last_lat = st.get("last")
            if last_lat is not None and last_lat < SLOW_THRESH:
                return False
            return st["lat_sum"] / st["ok"] > SLOW_THRESH

        healthy = [u for u in ups if not _is_cb_open(u) and not _is_slow_up(u)]
        if not healthy:
            healthy = [u for u in ups if not _is_cb_open(u)]  # 全部偏慢则降级为仅熔断过滤
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
        # P1-1: wait() 无 timeout 时, 若上游 future 永不完成(如连接池 hang/排队未
        # 执行), worker 线程永久阻塞。加超时兜底(上游查询超时 + 0.5s 余量), 超时后
        # cancel 剩余 pending future 并退出循环走已有"部分结果"路径(out 中若有
        # 成功响应已在循环内 return, 无则由调用方走 SERVFAIL)。与 _collect_rest 中
        # as_completed(timeout=...) 的超时兜底模式对齐。
        _wait_timeout = _safe_int(self.cfg.get("timeout_ms", 1500), 1500) / 1000.0 + 0.5
        while pending:
            done, pending = wait(pending, return_when=FIRST_COMPLETED,
                                 timeout=_wait_timeout)
            for fut in done:
                out.append(self._classify_one(fut2u[fut], fut, qtype, trace, query_bytes))
            if not done:
                # R2-P2 [P2-1]: wait() 超时未等到任何新完成。不能直接 cancel 丢弃——
                # 被取消/仍在跑的 future 无人 _classify_one, 上游熔断计数器与遥测会
                # 缺失这些超时样本(死上游在高负载下熔断永不打开)。统一兜底:
                #   - 竞态期间刚好 done() 的 → 轻量分类(skip_tcp, 正确记成功/失败);
                #   - 仍未完成的 → 按 timeout 喂失败回调(upstream_fail + _cb_fail),
                #     再 cancel 清理。主线程反正走 SERVFAIL, 不增加客户端延迟。
                for f in pending:
                    u = fut2u.get(f)
                    if u is None:
                        continue
                    if f.done():
                        try:
                            self._classify_one(u, f, qtype, [], query_bytes, skip_tcp=True)
                        except Exception:
                            pass
                    else:
                        _uid = u.get("id") or u.get("name") or "?"
                        # R3-P3-3: TOCTOU 微秒级竞态修复。原代码在 else 分支无条件
                        # 喂 fail 回调, 再用 if not f.done() 守卫 cancel。若 f 在
                        # 上一行 if f.done() 检查后恰好完成(成功), 会被误记一次
                        # fail 样本, 且其真实成功结果不再分类。此处把 fail 回调也
                        # 移入 done() 二次确认守卫内——仅确认仍未完成才喂 fail 并
                        # cancel。cancel() 对已完成 future 本就是空操作, 此处的
                        # 二次确认仅为保证遥测 fail 计数精确。
                        if not f.done():
                            try:
                                self.tel.upstream_fail_conn_fail(_uid, self._conn_key(u))
                                self._cb_fail(_uid)
                            except Exception:
                                pass
                            try:
                                f.cancel()
                            except Exception:
                                pass
                            # R7/P3-8: 已知微秒级竞态(不改代码)。cancel() 调用前与
                            # f.done() 二次确认之间仍有窗口: future 恰在此刻完成,
                            # 会被误记一次 fail 样本。后果仅为单次遥测计数偏差, 不影响
                            # 路由/熔断正确性(R3-P3-3 已把 fail 回调移入 done() 守卫,
                            # 窗口缩到最小); 为这点精度再加锁会把 miss 主路径拖慢, 不值得。
                pending = set()
                break
            if any(r.get("answers") for r in out):
                # 有答案 → 首答即返: 其余由后台线程收尾(仅统计)
                if pending:
                    # #7 透传 query_bytes: 后台 TCP 回退 _tcp_query 需要原始查询报文
                    self._collect_rest_in_background(pending, fut2u, qtype, query_bytes)
                    pending = set()
                return out
            # v1.9.76 2.1: NXDOMAIN 多数表决。首个 NXDOMAIN 即返可能被单个撒谎/故障
            # 上游误导(域名其实存在)。需 >=nxdomain_quorum(默认 2)个上游一致 NXDOMAIN
            # 才提前返回; 否则继续等其他上游答案/超时。nxdomain_quorum=1 恢复旧行为。
            # v1.9.77 R1: quorum 不得超过实际可用上游数。单上游配置下 quorum=2 永远
            # 达不到, 每个 NXDOMAIN 查询都会死等满 timeout; 钳到 len(ups) 即修复。
            # R5: 改 _safe_int。旧 `int(... or 1)` 把 0 也改成 1; 现保留显式 0
            # (语义=首个 NXDOMAIN 即提前返回), 仅 None/"abc" 回退 1。
            # R7/P2-3: quorum 上限应对齐实际参与并发的 healthy 上游数(而非配置的
            # len(ups))——熔断/慢上游降级后 fut2u 只含 healthy, 用 len(ups) 钳制会使
            # quorum 高于实际可投票数, NXDOMAIN 提前返回条件永不满足, 死等满 timeout。
            # healthy 为空时上方已有兜底(降级到 ups), 此处 healthy 必非空。
            _nx_quorum = min(_safe_int(self.cfg.get("nxdomain_quorum", 2), 1), len(healthy))
            if sum(1 for r in out if r.get("rcode") == 3) >= max(1, _nx_quorum):
                if pending:
                    self._collect_rest_in_background(pending, fut2u, qtype, query_bytes)
                    pending = set()
                return out
        return out

    @staticmethod
    def _conn_key(u):
        """连接维度健康度 key: proto|addr|port|url(同上游多协议/多 IP 各自独立统计)。"""
        return "%s|%s|%s|%s" % (str(u.get("proto", "")).lower(),
                                u.get("addr", ""), u.get("port", ""), u.get("url", ""))

    def _classify_one(self, u, fut, qtype, trace, query_bytes=None, skip_tcp=False):
        """处理单个上游查询结果: 解析、分类、更新遥测统计。
        skip_tcp=True: 轻量分类(主线程对已完成 future 用)——只喂遥测/熔断器,
        不做阻塞的 TCP 回退(_tcp_query 最多阻塞 timeout 秒)。TC=1 的 TCP 回退仅在
        后台完整分类路径需要; 轻量路径下该上游已应答(仅截断), 标记 ok 即可喂熔断。"""
        timeout = _safe_int(self.cfg.get("timeout_ms", 1500), 1500)
        # 上游展示名: 历史/手写配置可能缺 name 字段, 直接 u["name"] 在 miss/失败
        # 路径抛 KeyError 中断解析(API 包装成 502, UDP 路径则丢应答)。回退 id。
        _uname = u.get("name") or u.get("id", "?")
        # P2-1: 用户手编 config.json 漏写 id 时 u["id"] 抛 KeyError, 与展示名防御对齐
        _uid = u.get("id") or u.get("name") or "?"
        try:
            # P2-10: 防御性解包。上游 query_upstream 返回值理论上是 4 元组
            # (ok, data, lat, err), 但异常/未来变更可能返回短元组, 直接解包
            # 会 ValueError。按需取前 3 个元素。
            result = fut.result()
            ok = result[0] if len(result) > 0 else False
            data = result[1] if len(result) > 1 else None
            lat = result[2] if len(result) > 2 else 0
        except Exception:
            ok, data, lat = False, None, timeout
        if ok and data:
            try:
                parsed = dnsmsg.parse_message(data)
            except Exception:
                parsed = None
            # ---- UDP 截断(TC=1)自动 TCP 回退: 大响应(如 DNSSEC/大量A记录)UDP 装不下时,
            # 上游返回 truncated 标志, 自动切 TCP 重查同一上游获取完整应答 ----
            # R2-P1: skip_tcp(轻量/主线程路径)跳过阻塞的 _tcp_query, 避免主线程 I/O。
            if (not skip_tcp and parsed is not None and parsed.get("truncated")
                    and str(u.get("proto", "udp")).lower() == "udp"):
                trace.append({"tag": "eng", "text": "%-12s UDP 应答截断(TC=1) → TCP 回退重查" % _uname[:12]})
                try:
                    tcp_ok, tcp_data = _tcp_query(u, query_bytes, timeout)
                except Exception:
                    tcp_ok, tcp_data = False, None
                if tcp_ok and tcp_data:
                    try:
                        parsed = dnsmsg.parse_message(tcp_data)
                    except Exception:
                        parsed = None
                    trace.append({"tag": "ok", "text": "%-12s TCP 回退成功, 应答 %d bytes" % (_uname[:12], len(tcp_data))})
                else:
                    trace.append({"tag": "warn", "text": "%-12s TCP 回退失败, 沿用截断应答" % _uname[:12]})
            if parsed is not None:
                rcode = parsed.get("rcode")
                if rcode == 0:
                    ans = self._extract_answers(parsed, qtype)
                    _ck = self._conn_key(u)
                    if ans:
                        self.tel.upstream_ok_conn_ok(_uid, _ck, lat)
                        self._cb_ok(_uid)
                        for a in ans:
                            trace.append({"tag": "ans", "text": "%-12s %s  %dms" % (_uname[:12], a["value"], lat)})
                        return {"ok": True, "up_name": _uname, "lat": lat,
                                "proto": str(u.get("proto", "udp")).lower(),
                                "rcode": 0, "answers": ans}
                    # 无目标类型答案: 若应答含 CNAME 链 → 交给 CNAME 跟踪展开
                    if parsed.get("answers"):
                        _cns = [a for a in parsed.get("answers", []) if a["type"] == dnsmsg.TYPE_CNAME]
                        if _cns:
                            self.tel.upstream_ok_conn_ok(_uid, _ck, lat)
                            self._cb_ok(_uid)
                            trace.append({"tag": "ans", "text": "%-12s CNAME 链 → %s (%dms)" % (
                                _uname[:12], _cns[0].get("rdata", ""), lat)})
                            return {"ok": True, "up_name": _uname, "lat": lat,
                                    "rcode": 0, "answers": [], "cnames": [
                                        (str(_cns[0].get("rdata", "")).rstrip(".").lower(),
                                         max(1, int(_cns[0].get("ttl", 300))))]}
                    # NOERROR 但无目标答案 = NODATA
                    self.tel.upstream_ok_conn_ok(_uid, _ck, lat)
                    self._cb_ok(_uid)
                    trace.append({"tag": "ans-fail", "text": "%-12s 无该类型记录 (NODATA) %dms" % (_uname[:12], lat)})
                    return {"ok": True, "up_name": _uname, "lat": lat,
                            "rcode": 0, "answers": [], "nodata": True,
                            "neg_ttl": self._soa_minimum(parsed)}
                if rcode == 3:
                    self.tel.upstream_ok_conn_ok(_uid, self._conn_key(u), lat)
                    self._cb_ok(_uid)
                    trace.append({"tag": "ans-fail", "text": "%-12s NXDOMAIN (域名不存在) %dms" % (_uname[:12], lat)})
                    return {"ok": True, "up_name": _uname, "lat": lat,
                            "rcode": 3, "answers": [], "neg_ttl": self._soa_minimum(parsed)}
            # rcode 其它（如 SERVFAIL/REFUSED）视为失败
        self.tel.upstream_fail_conn_fail(_uid, self._conn_key(u))
        self._cb_fail(_uid)
        trace.append({"tag": "ans-fail", "text": "%-12s 查询失败 / 超时 (%dms)" % (_uname[:12], lat)})
        return {"ok": False, "up_name": _uname, "lat": lat, "rcode": None, "answers": []}

    def _collect_rest_in_background(self, pending, fut2u, qtype, query_bytes=None):
        """后台收集未完成上游的结果：仅用于遥测统计, 不阻塞客户端。
        提交到共享收集池, 避免每次 miss 新建线程导致堆积。
        #10 提交后台前先同步分类已完成 future(首答返回与提交之间又有上游完成的,
        无需再等), 仅把仍未完成的剩余 future 提交后台; 后台收集 timeout 对齐
        timeout_ms(默认 1.5s), 等待到上游查询自然完成/超时时刻才退出(见下方 P2-6)。
        #8 [中等]: 后台收集阶段各上游的分类诊断条目(TCP 回退/NODATA/失败等)
        不进主 trace——主线程首答返回后已在向主 trace 并发 append, 后台 worker 若
        共享同一 list 会与主线程竞争, API 层序列化时可能触发 RuntimeError。
        故后台收集统一传独立空列表(见下方 R2-C1), 遥测仍由 self.tel 独立记录,
        观测不丢。
        #7 [中] query_bytes 透传: _classify_one 内 UDP 失败会做 TCP 回退
        _tcp_query(u, query_bytes, ...); 原后台路径不传 query_bytes(=None)
        导致后台 TCP 回退拿到 None 报文而静默失败/异常, 观测丢失。"""
        # P2-6: 后台收集 timeout 对齐上游查询超时(timeout_ms), 不再用 1.0s 硬上限。
        # 原 min(1.0, ...) 在 timeout_ms=1500 时只等 1s, 超时后 f.cancel() 对已在
        # worker 线程中运行的 future 是空操作(cancel 仅能取消"未启动"的 future),
        # 运行中的上游查询继续跑到自身 1.5s 超时, 悬挂占用 worker 槽位与连接池资源。
        # 对齐后 collect 等待到上游查询自然完成/超时时刻才退出, 此时 cancel 只命中
        # 尚未启动(真正可取消)的 queued future, 消除 cancel 后的悬挂窗口。
        # (收集池为有界丢帧语义, 占时长略增仅影响遥测吞吐, 无副作用。)
        timeout = _safe_int(self.cfg.get("timeout_ms", 1500), 1500) / 1000.0
        # R2-P1 [P1]: 恢复混合模式, 修复 P1-2 全量后台提交引入的"池满丢任务→
        # 熔断/遥测失明"。已 done() 的 future 在主线程做轻量分类(skip_tcp=True,
        # 只喂遥测/熔断, 无 I/O 不阻塞), 即使丢帧池打满也绝不丢这部分样本;
        # 仅把仍在 pending 的 future 提交后台池(后台才做完整分类含 TCP 回退)。
        # 主线程轻量分类无阻塞(fut.result() 对 done() 立即返回), 且丢帧池打满时
        # 已完成上游的成败仍会喂 _cb_fail/_cb_ok 与遥测, 死上游熔断不再失明。
        done_now = set(f for f in pending if f.done())
        still_pending = set(pending) - done_now
        for f in done_now:
            u = fut2u.get(f)
            if u is None:
                continue
            try:
                # 轻量分类: skip_tcp=True, 不做阻塞 TCP 回退
                self._classify_one(u, f, qtype, [], query_bytes, skip_tcp=True)
            except Exception as e:
                log.debug("主线程轻量分类已完成上游结果异常: %r", e)
        if not still_pending:
            return
        # 有界队列: 收集池满则丢弃本次后台收集(纯统计, 无副作用)。
        # 原无界 submit 在 miss 高峰会无限堆积(4 worker 每秒约 2.7 个),
        # 是 VM 长期运行内存增长的元凶之一。
        # R2-C1 [P2]: 传给后台任务的 trace 改为独立空列表, 避免后台 worker 与
        # 主线程并发 append 同一列表(主线程首答返回后已在向 trace 追加),
        # 防止 API 层序列化时触发 RuntimeError。后台收集的遥测统计仍由
        # self.tel 记录, trace 诊断条目不进主 trace 不影响功能。
        self._collect_pool.submit_drop(self._collect_rest, still_pending, fut2u, qtype, [], timeout, query_bytes)

    def _collect_rest(self, pending, fut2u, qtype, trace, timeout=1.0, query_bytes=None):
        """后台收集未完成上游结果(仅遥测统计)。

        as_completed 带 timeout 兜底: 极端情况下(上游查询 future 因 pool 已
        shutdown / 排队未执行等未能完成)避免 worker 无限等待, 否则进程退出时
        threading._shutdown join 该 worker 会永久阻塞(systemd stop-sigterm 超时)。
        """
        try:
            for fut in as_completed(pending, timeout=timeout):
                try:
                    self._classify_one(fut2u[fut], fut, qtype, trace, query_bytes)
                except Exception as e:
                    log.debug("后台收集上游结果异常: %r", e)
        except Exception as e:
            # 超时未完成: 记录诊断信息后放弃, 不让后台线程无限阻塞
            # M2: Py3.10 的 concurrent.futures.TimeoutError 与 builtin TimeoutError 是
            # 两个类(3.11+ 才别名), isinstance(e, TimeoutError) 在 3.10 不命中, 超时诊断
            # 分支被跳过。同时兼容两者。
            if isinstance(e, (TimeoutError, _cf.TimeoutError)):
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
        # v1.9.80: 热点域名再次记录时 move_to_end, 避免按首次插入时间被过早淘汰
        if d in self._last_speed_test:
            self._last_speed_test.move_to_end(d)
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
        # R6/P2-2: 原裸 float(self.cfg.get(...)), R5 只 grep int() 漏了 float()。
        # 畸形串("abc")抛 ValueError 穿透 _speed_sort→resolve(miss 主路径)。
        interval = _safe_float(self.cfg.get("speed_interval_ms", 2000), 2000.0) / 1000.0
        with self._speed_lock:
            last = self._last_speed_test.get(d, 0)
            if now - last < interval:
                return cand_list  # 间隔内复用上次排序
            self._mark_speed_test(d, now)
        cache_ttl = _safe_float(self.cfg.get("ip_speed_cache_ttl", 60), 60.0)
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
                        # setdefault 原子初值写入: 两线程并发初值写入时, 后到者不再用
                        # 粗略延迟估计覆盖先到者(或 _probe_candidate_ip 已写入的实测
                        # EWMA)。仅在槽位真空时写入, 消除两次持锁之间的 TOCTOU。
                        self._ip_speed_cache.setdefault(ip, (a["measured"], now))
                        # R-05: 利用 dict 插入序(Py3.7+)从头弹出最旧条目, 避免 O(n log n)
                        # 排序在锁内执行。保留 3/4 条目作为水位线, 防止频繁触发淘汰。
                        if len(self._ip_speed_cache) > 65536:
                            _target = 65536 * 3 // 4
                            while len(self._ip_speed_cache) > _target:
                                self._ip_speed_cache.pop(next(iter(self._ip_speed_cache)), None)
                self._probe_pool.submit_drop(
                    self._probe_candidate_ip, ip, query_bytes,
                    a.get("probe", "udp53"), _safe_int(self.cfg.get("speed_timeout_ms", 300), 300))
        # 加权随机选优(不放回抽样): 权重=1/(rtt+10), 快 IP 概率性优先
        # R42/P3-3: measured 为实测延迟(ms), 下界 0(lat 不可能为负), 故 measured+10 >= 10,
        # 每项权重 >= 0.1 > 0, sum(ws) >= 0.1*len(pool) > 0, 除零与 total==0 均不可达。
        # 此处不额外加防御性除零分支(死代码); 若未来有人把 +10 改为 +0 需重新评估。
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
            # 注: probe_ip 签名为 (ip, query_bytes, port=53, timeout_ms=800),
            # 必须用关键字传 timeout_ms, 否则超时值会被位置实参误传到 port 形参,
            # 导致探测发到错误端口(如 300)而永远超时。
            r = probe_ip(ip, query_bytes, port=53, timeout_ms=timeout_ms)
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
            # R-05: 同上, dict 插入序从头弹出最旧条目, 避免 O(n log n) 排序锁内阻塞。
            if len(self._ip_speed_cache) > 65536:
                _target = 65536 * 3 // 4
                while len(self._ip_speed_cache) > _target:
                    self._ip_speed_cache.pop(next(iter(self._ip_speed_cache)), None)
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
        # R5: 用 _safe_int 统一, 移除冗余 try/except(二者等价, _safe_int 内部已兜
        # None/TypeError/ValueError)。max(0,...) 仍负责把负值钳到 0。
        mn = max(0, _safe_int(self.cfg.get("ttl_min", 0), 0))
        mx = max(0, _safe_int(self.cfg.get("ttl_max", 0), 0))
        if rule and (rule.get("ttl_min") not in (None, "") or rule.get("ttl_max") not in (None, "")):
            mn, mx = 0, 0   # 规则区间整体替换全局
            if rule.get("ttl_min") not in (None, ""):
                mn = max(0, _safe_int(rule.get("ttl_min"), 0))
            if rule.get("ttl_max") not in (None, ""):
                mx = max(0, _safe_int(rule.get("ttl_max"), 0))
        t = int(ttl)
        if mn > 0 and t < mn:
            t = mn
        if mx > 0 and t > mx:
            t = mx
        # v1.9.87 P2-1: ttl_min 钳制上推路径可把 t 推过 uint32 wire 字段上限
        # (如全局/规则级 ttl_min 配成 5e9, config 校验对 ttl_min 上限为 None 不拦)。
        # build_response_body_answers 用 >I 打包 TTL, 超出会 struct.error 导致受影响
        # 域名恒 SERVFAIL。这里在唯一 return 前统一钳到 int32 安全域(约 68 年,
        # 远超任何合理 TTL), 覆盖全局与规则级两条钳制上推路径。
        t = min(t, 2147483647)
        return max(0, t)

    def _fill_cache(self, key, d, qtype, answers, rule=None):
        """回填缓存条目。R-06: 注意此方法会原地修改传入 answers 列表中每个 dict 的
        ttl 字段(统一钳制到配置/规则 TTL)。所有调用方均依赖此行为。"""
        now = time.time()
        # R6/P2-1: 同 :931, 原裸 self.cfg.get("ttl",300) 进 min(), 畸形串
        # 与 int 比较抛 TypeError。两处均 _safe_int 兜底为 int。
        raw_ttl = min(_safe_int(self.cfg.get("ttl", 300), 300), min((a.get("ttl", 300) for a in answers), default=_safe_int(self.cfg.get("ttl", 300), 300)))
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
            "expires_at": now + ttl,
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
            fut = self._prefetch_pool.submit_drop(self._do_stale_refresh, key, d, qtype)
            # H2: submit_drop 在信号量满时返回 None(不是异常), except 分支不执行,
            # 必须显式回滚 _stale_refreshing 标记, 否则该 key 永远无法再次触发刷新。
            if fut is None:
                with self._prefetch_lock:
                    self._stale_refreshing.discard(key)
        except Exception as e:
            log.warning("提交 stale 刷新异常 %s %s: %r", d, qtype, e)
            with self._prefetch_lock:
                self._stale_refreshing.discard(key)

    def _do_stale_refresh(self, key, d, qtype):
        try:
            r = self.resolve(d, qtype, silent=True, counted=False, force_refresh=True, max_upstreams=1)
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
                # 不再 discard _prefetch_pending: resolve(force_refresh=True) 末尾会经
                # schedule_prefetch 把本 key 重新加入 pending, 这里若立即删除会把刚写入
                # 的预取调度抹掉。pending 条目由 _scan_prefetch 自然处理。

    def schedule_prefetch(self, key, d, qtype):
        """标记该 key 需要在过期前预取（由后台扫描线程统一调度）。

        R7/P3-2: 移除从未引用的 ttl 形参(旧签名 (key, d, qtype, ttl) 中 ttl 在
        函数体内零引用——预取时机由后台 _scan_prefetch 扫描 pending 队列决定, 与
        调用点传入的剩余 TTL 无关)。同步更新全部 3 处调用点。"""
        if not self.cfg.get("prefetch", True):
            return
        # P2-3: 移除锁外 check-then-act。原实现先无锁判断 key in pending 再抢锁,
        # 两线程对同一 key 可同时通过锁外检查导致重复预取。现将成员判断整体移入
        # _prefetch_lock 内, 热路径多一次锁竞争(~100ns)但彻底消除竞态。
        with self._prefetch_lock:
            if key in self._prefetch_pending:
                return
            # v1.9.86 P2-1: 硬上限兜底。队列已满时放弃本次标记(不阻塞查询热路径),
            # 已入队的 due/过期 key 由 _scan_prefetch 每 tick 2000 条自然消化。
            if len(self._prefetch_pending) >= self._prefetch_pending_max:
                return
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
            # 保持完整分区 key (group, domain, qtype): 存入 pending 后由 _scan_prefetch
            # 按原 key 查缓存(PartitionedCache 据此路由到 domestic/global/default 分区),
            # 剥离 group 会导致非 default 分区条目查不到、预取调度静默丢失。
            with self._prefetch_lock:
                # v1.9.86 P2-1: 与 schedule_prefetch 一致的硬上限(启动恢复路径)
                if (key not in self._prefetch_pending
                        and len(self._prefetch_pending) < self._prefetch_pending_max):
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
            # 快照正在被 serve-stale 后台刷新的 key: 这些 key 虽仍在 pending 中
            # (_do_stale_refresh 完成后才会从 pending 移除), 若本扫描也选中并
            # 提交 _do_prefetch, 会与正在跑的 force_refresh 并发打重复上游请求。
            # 跳过它们并保留在 pending 中, 等刷新完成后由下一轮扫描自然处理。
            stale_refreshing = set(self._stale_refreshing)
        # 分批轮转扫描: 大容量缓存(持久化恢复可能上万条)时避免每 tick 全量遍历
        if len(pending) > self._prefetch_batch:
            n = len(pending)
            start = self._prefetch_scan_idx % n
            window = pending[start:start + self._prefetch_batch]
            self._prefetch_scan_idx = (start + self._prefetch_batch) % n
        else:
            window = pending
        for key in window:
            if key in stale_refreshing:
                continue
            entry = self.cache.get(key, now)
            if entry is None:
                with self._prefetch_lock:
                    # P2-8: TOCTOU——cache.get() 在锁外执行, 持锁前另一线程可能已
                    # 移除并重新加入该 key。重新确认 key 仍在 pending 中才 discard,
                    # 避免误删其他线程刚调度的同 key 预取。
                    if key in self._prefetch_pending:
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
            # 先按原始(分区)key 从待预取集合移除, 再剥离 group 得到 (d, qtype)。
            # 原实现先把 key 重绑定为 2 元组再 discard, 而 _prefetch_pending 存的
            # 是 3 元组 (group, key_d, qtype), discard(2元组) 永远 miss, 旧 key 残留。
            with self._prefetch_lock:
                self._prefetch_pending.discard(key)
            if len(key) == 3:
                _key_d, qtype = key[1], key[2]
            else:
                _key_d, qtype = key[0], key[1]
            # R9R1-P2: ECS 前缀还原。_ckey 把归一化 edns_client_subnet 并入
            # key_d(ecs_key|domain), 从缓存 key 反查待预取域名时必须剥掉前缀,
            # 否则会拿 "10.0.0.0/8|www.x.com" 这种含 | 的字面量去向上游发 DNS 查询
            # (无效域名恒 NXDOMAIN, 预取空转浪费上游查询, 遥测域名列也被污染)。
            d = self._strip_ecs_prefix(_key_d)
            self._prefetch_pool.submit_drop(self._do_prefetch, d, qtype)

    def _do_prefetch(self, d, qtype):
        try:
            log.debug("预取触发 %s %s (强制刷新, 单上游)", d, qtype)
            r = self.resolve(d, qtype, silent=True, counted=False, force_refresh=True, max_upstreams=1)
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
        # R4-P3-2/R5/P3-4: 模块级 _REGEX_POOL 是唯一未在 shutdown() 中关闭的 ThreadPoolExecutor。
        # 其 worker 为非 daemon 线程, Python 退出时 threading._shutdown 会 join 所有
        # 非 daemon 线程; 若 ReDoS 正则仍在运行(re 模块不可中断), 进程退出被阻塞。
        # R5 决策(为何不把 worker 设为 daemon): ThreadPoolExecutor 不公开线程工厂,
        # 线程惰性创建于首次 submit, 构造后遍历私有 _threads 设 daemon=True 在 Py 版本间
        # 脆弱且不可靠。改以 shutdown(wait=False, cancel_futures=True) 作为指定退出路径:
        # wait=False 不阻塞 shutdown(); cancel_futures=True 取消队列中未开始的任务;
        # 正在运行的正则由 _detect_catastrophic_regex 静态检测 + fut.result(timeout=0.5)
        # 双层兜底, 最多 0.5s 自然结束。即便解释器退出时 join 残留 worker, 最坏延迟也是
        # 秒级(6 worker × 0.5s 有界), 不影响运行态。blast radius 已钳制, 可接受。
        try:
            _REGEX_POOL.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass

    # ---------------- 缓存分区 group 判定 ---------------- #
    @staticmethod
    def _normalize_ecs_key(cfg):
        """把 edns_client_subnet 归一化为 key 组件(网络地址形式, 如 203.0.113.0/24)。
        未配置返回空串(不并入 key, 保持旧缓存布局)。解析失败回退原始字符串。"""
        sub = (cfg or {}).get("edns_client_subnet")
        if not sub:
            return ""
        try:
            return str(ipaddress.ip_network(str(sub), strict=False))
        except Exception:
            return str(sub)

    def _strip_ecs_prefix(self, key_d):
        """R9R1-P2: 从 _ckey 生成的 key_d(ecs_key|domain) 还原原始域名。
        未配置 ECS 或无匹配前缀时原样返回。预取/恢复路径从缓存 key 反查
        待解析域名时调用, 避免拿 ECS 前缀串去向上游发查询。"""
        ecs = self._ecs_key
        if ecs and isinstance(key_d, str) and key_d.startswith(ecs + "|"):
            return key_d[len(ecs) + 1:]
        return key_d

    def _ckey(self, d, qtype):
        """构造分区缓存 key: (group, domain, qtype)。
        group 按分流规则: 命中 group 规则 → domestic/global; 其余(含 block/无规则)→ default。
        无 group 规则时直接用 default, 跳过 match_rule 查表(热路径省一次函数调用+dict查找)。
        v1.9.76 2.4: 配置 ECS 时把归一化子网前缀作为域名前缀并入 key, 实现 ECS 缓存隔离。"""
        ecs = self._ecs_key
        key_d = (ecs + "|" + d) if ecs else d
        if not self._has_group_rules:
            return ("default", key_d, qtype)
        g = "default"
        try:
            r = self.match_rule(d)
            if r and r.get("action") == "group" and r.get("group") in ("domestic", "global"):
                g = r["group"]
        except Exception:
            pass
        return (g, key_d, qtype)

    # ---------------- 配置热重载 ---------------- #
    def switch_cache_policy(self, policy):
        """按目标策略重建缓存容器(保留当前容量)。

        以【实际缓存对象类型】与目标策略比对, 而非 cfg 字符串新旧值——
        PUT /api/config 可能已先把 cfg.cache_policy 改掉并重绑定 resolver.cfg,
        此时 reload() 里 old_cfg/new_cfg 的字符串相同会漏检。本方法看
        self.cache 真实类型(PartitionedCache vs TinyLFUCache), 与目标不一致
        就重建。幂等: 类型已匹配则 no-op。返回是否发生了切换。"""
        policy = str(policy or "lru").lower()
        want_tinylfu = (policy == "tinylfu")
        is_tinylfu = isinstance(self.cache, TinyLFUCache)
        if want_tinylfu == is_tinylfu:
            return False
        cap = self.cache.capacity
        # 策略不同步迁移数据(新旧算法频率语义不同), 直接重建容器, 冷启动短暂
        # 命中率下降是热重载低频操作下的可接受代价
        if want_tinylfu:
            self.cache = TinyLFUCache(cap)
        else:
            self.cache = PartitionedCache(cap, self.cfg.get("cache_partitions"))
        log.info("缓存策略切换 %s → %s (容量 %d, 容器已重建)",
                 "tinylfu" if is_tinylfu else "lru", policy, cap)
        return True

    def reload(self, new_cfg, config_path=None):
        """热重载: 替换运行配置并重建受影响资源, 不重启进程。

        - 配置 dict 整体原子替换(self.cfg 引用), 后续查询自然使用新值
        - 缓存容量变更即时调整(分区/单区均支持)
        - 规则索引重建(逐条/订阅独立文件为准)
        - 缓存策略变更(仅 cache_policy 切换)需要重建缓存容器
        返回变更摘要 dict。"""
        changed = []
        old_cfg = self.cfg
        # P2-5: 先算好新 _ecs_key(在 self.cfg = new_cfg 之前), 再与 self.cfg
        # 紧挨着同时更新, 消除"cfg 已切新而 _ecs_key 仍是旧"的不一致窗口——
        # 期间并发查询用新 cfg 但旧 ecs_key 拼缓存 key, 与新 key 命名空间错配。
        try:
            new_ecs_key = self._normalize_ecs_key(new_cfg)
        except Exception:
            new_ecs_key = self._ecs_key
        _old_ecs = self._ecs_key
        # R2-P3 [P3-1]: 改为单条元组赋值(GIL 下属性引用发布原子), 消除两条相邻
        # 赋值之间"新 cfg + 旧 ecs_key"的 bytecode 窗口(原虽相邻仍有微秒级窗口)。
        # 与同文件 _rule_index(line 2211)的"元组单次发布"模式对齐。
        self.cfg, self._ecs_key = new_cfg, new_ecs_key
        # v1.9.76 2.4: ECS 配置变更时重算 key 组件(旧 key 自然过期)
        # v1.9.77 R2: _ecs_key 变化后旧 key 条目与新 key 命名空间不兼容——旧条目占内存
        # 且新 key 查不到(命中率 0)。比较新旧 key, 不同则整体清空缓存, 避免脏读/内存泄漏。
        if self._ecs_key != _old_ecs:
            self.cache.clear()
            changed.append("ecs_key 变化(%r→%r), 缓存已清空" % (_old_ecs, self._ecs_key))
        # 缓存容量
        try:
            old_cap = _safe_int(old_cfg.get("cache_size", 1024), 1024)
            new_cap = _safe_int(new_cfg.get("cache_size", 1024), 1024)
            if new_cap != old_cap:
                self.cache.capacity = new_cap
                changed.append("cache_size %d→%d" % (old_cap, new_cap))
        except Exception:
            pass
        # v1.9.74 P1-2: 热重载同步 serve-stale 窗口到缓存层
        try:
            self.cache.stale_window = _safe_int(new_cfg.get("stale_ttl", 3600), 3600) if new_cfg.get("serve_stale", False) else 0
        except Exception:
            pass
        # 热重载同步客户端 bufsize 上限
        self._client_bufsize_cap = _safe_int(new_cfg.get("edns_client_max_size", 1232), 1232)
        # 缓存策略切换(lru <-> tinylfu): 以实际缓存对象类型与目标策略比对重建,
        # 不依赖 cfg 新旧字符串(因 PUT 可能已先改 cfg)
        new_p = str(new_cfg.get("cache_policy", "lru")).lower()
        try:
            if self.switch_cache_policy(new_p):
                changed.append("cache_policy → %s (缓存已重建)" % new_p)
                # 重建后新缓存容器也要下发 stale 窗口
                try:
                    self.cache.stale_window = _safe_int(new_cfg.get("stale_ttl", 3600), 3600) if new_cfg.get("serve_stale", False) else 0
                except Exception:
                    pass
        except Exception as e:
            log.error("缓存策略切换失败: %r", e)
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
                # R5: 全配置驱动 int() 清扫, 统一 _safe_int(畸形值不再抛)。
                hi = max(0, _safe_int(cfg.get("health_check_interval", 30), 0))
                ri = max(0, _safe_int(cfg.get("rule_sub_interval", 3600), 0))
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
        # R5/P3-5: 原裸 int(...) or 2000 虽有 bg loop 外层 try 兜底, 但仍不健壮;
        # 统一 _safe_int, 畸形值回退 2000 不再抛 ValueError。
        timeout = max(500, _safe_int(cfg.get("health_probe_timeout_ms", 2000), 2000))
        qt = dnsmsg.type_code("A")
        qd = dnsmsg.random_case_name(dom) if cfg.get("dnssec_0x20", True) else dom
        qbytes, _q = dnsmsg.build_query(qd, qt, edns=True, udp_size=1232, padding=False)
        ups2 = list(ups)
        if len(ups2) > 1:
            # v1.9.80: 每轮探测数量随上游数自适应, 保证单上游被探周期约 3 个间隔内。
            # R7/P3-6: 旧 max(3, (n+2)//3) 对 len=2 得 n_probe=3, 切片 (ups2+ups2)[n:n+3]
            # 会把 up0 重复探测两次(冗余且挤占探测槽)。改为 min(3, len(ups2)):
            # len=2→2(两上游各探一次), len>=3→3, 不重复探测同一上游。
            n_probe = min(3, len(ups2))
            n = self._hc_off
            ups2 = (ups2 + ups2)[n:n + n_probe]
            self._hc_off = (n + n_probe) % len(ups)
        for u in ups2:
            # P2-1: 与 _classify_one 对齐, 漏写 id 时回退 name, 防 KeyError
            _uid = u.get("id") or u.get("name") or "?"
            try:
                ok, _data, _lat, _e = query_upstream(u, qbytes, timeout)
                if ok:
                    self._cb_ok(_uid)
                    log.debug("健康检查 OK  %s (%s)", u.get("name") or u.get("id", "?"), u.get("addr"))
                else:
                    self._cb_fail(_uid)
                    log.info("健康检查失败 %s (%s): %s", u.get("name") or u.get("id", "?"), u.get("addr"), _e or "无应答")
            except Exception as e:
                self._cb_fail(_uid)
                # R7/P2-2: 与同函数其他日志(:2260/:2263)对齐, name 缺失时回退 id。
                log.debug("健康检查异常 %s: %r", u.get("name") or u.get("id", "?"), e)

    def _fetch_sub_text(self, url, timeout=20):
        """拉取订阅文本(共享实现): SSRF 初始+每跳重定向校验, 16MB 流式上限。"""
        from .api import fetch_subscription_text
        return fetch_subscription_text(url, timeout=timeout)

    def _update_rule_subs_once(self):
        """规则订阅自动更新: 对 config 元信息中的订阅链接重新拉取并覆盖
        独立文件明细(rules_sub.json), 然后重建规则索引。

        与手动 /api/rules/subscribe/update 共用同一数据模型(独立文件为准),
        更新失败仅告警不中断(下个周期重试)。

        并发范式(与 API 订阅 CRUD 一致, 修 M1): 网络下载在锁外完成(20s HTTP
        不持锁, 避免阻塞 DNS 查询与其他写操作), 按 url 收集结果; "读 subs→应用
        结果→剔除已删→落盘→rebuild"的读改写段进 app._lock, 进锁后重新取最新 cfg
        与 urls, 防止后台用旧快照写回导致并发 DELETE/PUT 的订阅被静默恢复。"""
        cfg = self.cfg
        meta = cfg.get("rule_subscriptions") or []
        urls = [m.get("url") for m in meta if m.get("url")]
        if not urls:
            return
        # 网络下载在锁外, 按 url 收集解析结果(不触碰共享文件/锁)
        fetched = {}
        for url in urls:
            try:
                text = self._fetch_sub_text(url)
                # R30 P3-7: 与 cli.py:335(冷启动补下载)、api.py:2136/2445(订阅下载/更新)对齐,
                # 判定前缀时同时跳过 "re:" 高级规则——否则周期刷新会把 "re:..." 错包成 "*.re:..." 死规则。
                items = [{"match": ("*." + d if not d.startswith(("*.", "re:")) else d)}
                         for d in self._parse_domain_list(text)]
                if items:
                    fetched[url] = items
            except Exception as e:
                log.warning("订阅自动更新失败 %s: %r", url, e)
        app_ctx = getattr(self, "_app_ctx", None)
        if app_ctx is None:
            return
        # 读改写段进 app._lock: 与 API 订阅 CRUD / reload 串行化
        with app_ctx._lock:
            cfg = app_ctx.cfg   # 重新取最新引用(reload/PUT 可能已替换 self.cfg)
            meta = cfg.get("rule_subscriptions") or []
            urls = [m.get("url") for m in meta if m.get("url")]
            path = cfg.get("rule_sub_file") or ""
            try:
                with open(path, encoding="utf-8") as f:
                    subs = json.load(f).get("subscriptions", [])
            except Exception:
                subs = []
            # P3/R31: rules_sub_file 被删除/损坏时 subs 为空, 但 config.rule_subscriptions
            # 仍配置了订阅 URL 且本次已在锁外成功 HTTP 拉取(fetched 非空)。若不补建空条目,
            # 下方循环空转 → n_ok=0, 已拉取规则被静默丢弃且文件永不重建。
            # 与 api._load_subs 的"config 有而独立文件缺失则补空明细"对齐: 按 meta 补建
            # 占位条目, 随后正常挂载 fetched 规则并落盘。
            if fetched:
                have = {(s.get("url") or "") for s in subs}
                for m in meta:
                    u = m.get("url") or ""
                    if u and u not in have:
                        subs.append({
                            "url": u,
                            "action": m.get("action", "block"),
                            "group": m.get("group", "global"),
                            "ip": m.get("ip") or "1.2.3.4",
                            "count": m.get("count", 0),
                            "updated_at": m.get("updated_at", ""),
                            "rules": [],
                        })
            now_str = time.strftime("%Y-%m-%d %H:%M:%S")
            n_ok = 0
            for s in subs:
                url = s.get("url") or ""
                if url not in urls:
                    continue
                items = fetched.get(url)
                if not items:
                    continue
                s["rules"] = items
                s["updated_at"] = now_str
                n_ok += 1
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
            if not isinstance(r, dict):
                # 畸形规则文件含非 dict 条目(如手工写成 [123, "foo"]): 跳过而非
                # 让 r.get() 抛 AttributeError 把整个启动搞崩。
                log.warning("规则索引跳过非 dict 条目: %r", type(r).__name__)
                continue
            self._normalize_rule(r)   # P0-1: 兼容配置文件 pattern/value 旧字段名
            m = (r.get("match") or "").strip().lower()
            if not m:
                continue
            is_allow = r.get("action") == "allow"
            if m.startswith("re:"):
                pat = m[3:]
                # R43/P2-1 纵深防御: 静态预检对任意规则本应不抛异常; 即使内部出现
                # 未预期异常, 也按"坏规则优雅跳过"设计降级(与下方 re.compile 失败同型),
                # 而非穿透 Resolver.__init__(:424) 的裸调用点致 daemon 启动崩溃。
                try:
                    risky = _detect_catastrophic_regex(pat)
                except Exception:
                    log.warning("正则规则 %r 静态预检异常, 按高风险忽略", m)
                    continue
                if risky:
                    log.warning("正则规则 %r 含嵌套量词(疑似 ReDoS 风险), 已忽略", m)
                    continue
                try:
                    c = re.compile(pat)
                except re.error:
                    log.warning("正则规则编译失败 %r, 已忽略", m)
                    continue
                regex.append((c, r))
            elif m.startswith("*.") and "*" not in m[2:]:
                # 纯后缀通配: *.core → 剥离匹配 O(1)
                core = m[2:].strip(".")
                if core:
                    if is_allow:
                        # #4 本地规则优先: rules=local+sub, setdefault 让先加载的本地
                        # 规则占位, 后加载的订阅规则不再覆盖同域名本地规则
                        allow_wild.setdefault(core, r)
                    else:
                        wild.setdefault(core, r)
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
                    log.warning("通配规则编译失败 %r, 已忽略", m)
                    continue
                if suffix:
                    suffix_wild.setdefault(suffix, []).append((c, r))
                else:
                    # 无固定后缀(单段通配如 *ads): 只能全局逐条, 归入正则列表兜底
                    regex.append((c, r))
            else:
                if is_allow:
                    # #4 本地规则优先: 同 exact 域名本地规则先加载占位, 订阅不覆盖
                    allow_exact.setdefault(m, r)
                else:
                    exact.setdefault(m, r)
        # H-4: 六个索引引用打包成元组, 单次赋值原子发布。Python 元组赋值是
        # 原子的, match_rule 读取时要么看到旧快照要么看到新快照, 无混合状态。
        self._rule_index = (exact, wild, allow_exact, allow_wild, suffix_wild, regex)
        # v1.9.81: 持锁 clear() 而非替换对象, 避免 _cache_rule 写入旧 dict 后丢失
        with self._rule_cache_lock:
            self._rule_match_cache.clear()
        # 检测是否有 group 分流规则: 无则 _ckey 直接用 default 分区, 跳过 match_rule
        old_has_group = getattr(self, "_has_group_rules", False)
        self._has_group_rules = any(
            isinstance(r, dict) and r.get("action") == "group" for r in rules
        )
        # v1.9.80: group 规则有无发生变化时, _ckey 的分区归属会变(旧条目在错误分区),
        # 必须整体清缓存, 否则命中率下降且旧分区条目滞留到自然过期。
        if old_has_group != self._has_group_rules:
            try:
                self.cache.clear()
            except Exception as e:
                # P3-3: 不再静默吞异常, 记录 warning 便于排查缓存清理失败
                log.warning("cache clear failed during rule rebuild: %s", e)

    @staticmethod
    def _normalize_rule(r):
        """P0-1: 兼容配置文件旧字段名。历史配置/迁移文件用 pattern/value, 新代码与
        前端用 match/ip/group。在规则入库前原地归一化:
          pattern -> match   (域名匹配表达式)
          value   -> 按 action 落到对应参数字段:
                     forceIp -> ip (目标 IP)
                     group   -> group (上游组名)
                     其它     -> ip (block/allow 无此参数, 映射无害)
        已有 match/ip 的规则保持不变, 两种写法都可用。"""
        if not isinstance(r, dict):
            return
        if not r.get("match") and r.get("pattern"):
            r["match"] = r.pop("pattern")
        if "value" in r:
            act = r.get("action")
            if act == "group":
                if not r.get("group"):
                    r["group"] = r.pop("value")
            else:
                if not r.get("ip"):
                    r["ip"] = r.pop("value")

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
            # R7/P3-3: 文件不存在不再静默 return []——启动时留一条 info, 便于区分
            # "未配置/文件尚未生成"与"规则加载逻辑被跳过", 排障时可确认走的是空规则分支。
            log.info("逐条规则文件 %s 不存在，按空规则启动", path)
            return []
        except (OSError, ValueError) as e:
            log.warning("逐条规则独立文件读取失败 %s: %s", path, e)
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
            log.warning("订阅规则文件读取失败 %s: %s", path, e)
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
        # H-4: 单次解包原子快照——整次匹配看到的是同一份规则索引, 重建期间
        # 不会读到混合状态。解包开销为 O(1)(六个引用), 远小于字典查找本身。
        exact, wild, allow_exact, allow_wild, suffix_wild, regex = self._rule_index
        # 规则缓存优先: allow 检查结果也在缓存中, 避免 hot path 每次遍历
        # v1.9.85: 读路径无锁。CPython GIL 下单次 dict.get 原子; _cache_rule 淘汰
        # 期间读到的旧/缺失结果只是多做一次正确匹配, 绝不返回错误结论。
        # 原每次命中都 _rule_cache_lock 取/放锁, 热路径(每 QPS 一次)锁开销显著。
        cache = self._rule_match_cache
        hit = cache.get(n, _MISS)
        if hit is not _MISS:
            # R-09: hit 要么是规则 dict, 要么是 None(缓存未命中), 直接返回即可。
            return hit
        # ---- 白名单(allow)优先: 仅缓存未命中时检查 ----
        r = allow_exact.get(n)
        if r is not None:
            self._cache_rule(n, r)
            return r
        core = n
        while core:
            r = allow_wild.get(core)
            if r is not None:
                self._cache_rule(n, r)
                return r
            idx = core.find(".")
            if idx == -1:
                break
            core = core[idx + 1:]
        r = exact.get(n)
        if r is not None:
            self._cache_rule(n, r)
            return r
        # 通配: *.core 匹配 core 及其全部子域。从完整域名自身开始逐级剥离
        # (最长匹配优先): a.b.deep.sub.com -> deep.sub.com -> sub.com -> com
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
        core = n
        while core:
            group = suffix_wild.get(core)
            if group:
                for c, rule in group:
                    m = _regex_match_safe(c, n)
                    if m is True:
                        self._cache_rule(n, rule)
                        return rule
                    # 结果不确定(ReDoS/池满)且该规则为屏蔽规则 → fail-closed,
                    # 按命中处理, 不把被屏蔽域名放行。
                    if m is None and rule.get("action") == "block":
                        self._cache_rule(n, rule)
                        return rule
            idx = core.find(".")
            if idx == -1:
                break
            core = core[idx + 1:]
        # 正则规则: 编译已缓存, 按配置顺序首个命中生效(带 ReDoS 超时保护)
        for c, rule in regex:
            m = _regex_search_safe(c, n)
            if m is True:
                self._cache_rule(n, rule)
                return rule
            # 结果不确定(ReDoS/池满)且该规则为屏蔽规则 → fail-closed 屏蔽,
            # 防止 ReDoS 窗口内 re: block 规则被绕过。
            if m is None and rule.get("action") == "block":
                self._cache_rule(n, rule)
                return rule
        self._cache_rule(n, None)
        return None

    def _cache_rule(self, n, rule):
        with self._rule_cache_lock:
            cache = self._rule_match_cache
            if len(cache) >= self._rule_cache_max:
                # 满时淘汰最早插入的一半(OrderedDict 语义保持插入序), 而非整体清空,
                # 避免突发查询把整表命中结论打散造成回源风暴。
                for _k in list(cache)[: len(cache) // 2]:
                    cache.pop(_k, None)
            cache[n] = rule

    def _guess_type(self, value, qtype):
        value = str(value or "")  # 类型兜底: config.json 手改写入数字等非字符串时避免 value.strip() 抛 AttributeError
        v = value.strip()
        if ":" in v:
            return dnsmsg.TYPE_AAAA
        # R44/P3-1: 收窄为 ASCII 数字(拒绝 ²/①/١ 等 Unicode 数字, 对齐 R43 同文件另外两处收窄)。
        # 空串由 `v.replace(".","")` 显式非空短路排除, 与原 isdigit()(空串返回 False)语义一致。
        _digits = v.replace(".", "")
        if _digits and all('0' <= c <= '9' for c in _digits):
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
