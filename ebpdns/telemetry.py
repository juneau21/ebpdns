"""遥测：计数器、QPS 窗口、延迟采样、历史序列、日志事件队列。"""

import threading
import time
import random
from collections import Counter, deque


class Telemetry:
    def __init__(self):
        self.boot_time = time.time()
        self.counters = {
            "total": 0, "hit": 0, "miss": 0, "kernel_direct": 0,
            "upstream_queries": 0, "errors": 0, "ipv4_fallback": 0, "stale_served": 0,
            "bytes_in": 0, "bytes_out": 0, "rebind_blocked": 0,
        }
        # 分流规则命中统计(按 action/group 归类)
        self.rule_hits = {"domestic": 0, "global": 0, "block": 0, "forceIp": 0}
        self.qtype_dist = {"A": 0, "AAAA": 0, "other": 0}
        self.qps_window = deque(maxlen=600)
        self.latency_window = deque(maxlen=400)
        self.history = []          # 每秒采样 [{label, hit_rate, qps, lat}]
        self.events = deque(maxlen=500)   # 实时日志事件
        self.per_upstream = {}     # up_id -> {ok, fail, lat_sum, last}
        self.conn_stats = {}       # 连接维度 (proto|addr|port|url) -> 健康度
        self.manual_history = []   # 手动查询记录
        # Top N 统计(域名/客户端), 有界 Counter(超限裁剪, 防长时运行内存增长)
        self.top_domains = Counter()
        self.top_clients = Counter()
        self._top_max = 2048
        self._qtype_cat_map = {"A": "A", "AAAA": "AAAA"}
        self._lock = threading.Lock()
        # 日志事件全局递增序号: 事件 deque 满 500 会弹出最旧条目, 前端若用
        # 位置索引轮询(since=N 直接切片)会在 deque 弹出后错位——新事件永远
        # 拉不到, 日志静默停更。改用 seq 过滤: 前端传上次收到的 seq, 后端
        # 返回 seq>since 的事件与最新 next_seq, 彻底消除错位。
        self._ev_seq = 0

    # ---- 计数器（原子自增，避免高并发丢计数） ----
    def inc(self, name, n=1):
        with self._lock:
            self.counters[name] += n

    def inc_rule(self, cat, n=1):
        """分流规则命中统计: cat ∈ domestic / global / block / forceIp"""
        with self._lock:
            self.rule_hits[cat] = self.rule_hits.get(cat, 0) + n

    def inc_qtype(self, cat, n=1):
        with self._lock:
            self.qtype_dist[cat] += n
    def count_top(self, domain=None, client=None):
        """Top N 统计(域名/客户端): 命中与 miss 路径都调用。
        有界: 超过 _top_max 时裁剪掉低频一半(保留高频), 防随机域名压测
        让 Counter 无限增长的内存泄漏。裁剪后计数近似(仅影响 Top N 展示)。
        自增与裁剪必须统一持锁: 原来自增在锁外, 两线程同时 +=1 会丢计数,
        且裁剪会整体替换 Counter 对象, 锁外自增旧对象的增量会随旧对象一起
        被 GC 丢弃(彻底丢失)。一次加锁完成自增+裁剪, 避免上述竞态。"""
        with self._lock:
            if domain:
                self.top_domains[domain] += 1
            if client:
                self.top_clients[client] += 1
            if len(self.top_domains) > self._top_max:
                self.top_domains = Counter(dict(self.top_domains.most_common(self._top_max // 2)))
            if len(self.top_clients) > self._top_max:
                self.top_clients = Counter(dict(self.top_clients.most_common(self._top_max // 2)))

    def count_query(self, cat):
        """miss 路径合并计数: total+qtype 一次加锁(替代 inc+inc_qtype 两次),
        qps_window 无锁 append(原子)。高并发 miss 下减少锁竞争。"""
        with self._lock:
            self.counters["total"] += 1
            self.qtype_dist[cat] += 1
        self.qps_window.append(time.time())

    def set_counters(self, counters, qtype_dist):
        with self._lock:
            self.counters = dict(counters)
            self.qtype_dist = dict(qtype_dist)

    # ---- QPS ----
    def add_qps(self, t=None):
        self.qps_window.append(t if t is not None else time.time())

    def current_qps(self):
        now = time.time()
        # v1.9.81: popleft 竞态防护(另一线程可能同时弹)
        while self.qps_window and now - self.qps_window[0] > 1.0:
            try:
                self.qps_window.popleft()
            except IndexError:
                break
        return len(self.qps_window)

    # ---- 延迟 ----
    def push_latency(self, ms):
        self.latency_window.append(ms)

    def avg_latency(self):
        if not self.latency_window:
            return None
        return sum(self.latency_window) / len(self.latency_window)

    # ---- 命中率 ----
    def hit_rate(self):
        if not self.counters["total"]:
            return 0.0
        return self.counters["hit"] / self.counters["total"] * 100

    def qtype_cat(self, qtype):
        return self._qtype_cat_map.get(qtype, "other")

    # ---- 上游统计 ----
    def upstream_stat(self, up_id):
        with self._lock:
            return self.per_upstream.setdefault(up_id, {"ok": 0, "fail": 0, "lat_sum": 0, "last": 0})

    def upstream_eff_lat_read(self, up_id):
        """加锁读取单上游统计快照(只读, 不 setdefault), 供 resolver 延迟排序用。
        避免锁外 .get() 读到并发 upstream_ok/upstream_fail 的半更新状态。"""
        with self._lock:
            st = self.per_upstream.get(up_id)
            if st is None:
                return None
            return dict(st)

    def upstream_ok(self, up_id, lat_ms):
        with self._lock:
            st = self.per_upstream.setdefault(up_id, {"ok": 0, "fail": 0, "lat_sum": 0, "last": 0})
            st["ok"] += 1
            st["lat_sum"] += lat_ms
            st["last"] = lat_ms

    def upstream_fail(self, up_id):
        with self._lock:
            st = self.per_upstream.setdefault(up_id, {"ok": 0, "fail": 0, "lat_sum": 0, "last": 0})
            st["fail"] += 1

    def upstream_ok_conn_ok(self, up_id, conn_key, lat_ms):
        """合并 upstream_ok + conn_ok: 一次加锁更新两个统计, 减少 _classify_one 热路径锁竞争。"""
        with self._lock:
            st = self.per_upstream.setdefault(up_id, {"ok": 0, "fail": 0, "lat_sum": 0, "last": 0})
            st["ok"] += 1
            st["lat_sum"] += lat_ms
            st["last"] = lat_ms
            cst = self.conn_stats.setdefault(conn_key, {"ok": 0, "fail": 0, "lat_sum": 0, "last": 0})
            cst["ok"] += 1
            cst["lat_sum"] += lat_ms
            cst["last"] = lat_ms

    def upstream_fail_conn_fail(self, up_id, conn_key):
        """合并 upstream_fail + conn_fail: 一次加锁更新两个统计。"""
        with self._lock:
            st = self.per_upstream.setdefault(up_id, {"ok": 0, "fail": 0, "lat_sum": 0, "last": 0})
            st["fail"] += 1
            cst = self.conn_stats.setdefault(conn_key, {"ok": 0, "fail": 0, "lat_sum": 0, "last": 0})
            cst["fail"] += 1

    # ---- 连接维度健康度细化 (proto|addr|port|url) ----
    # 多 IP 上游/多协议同上游场景下, 按 ID 聚合会掩盖单连接劣化(如某 IP 故障
    # 拖低整上游均值)。按连接独立统计, 测速/健康判断可精确到具体端点。
    def conn_stat(self, key):
        with self._lock:
            return self.conn_stats.setdefault(key, {"ok": 0, "fail": 0, "lat_sum": 0, "last": 0})

    def conn_ok(self, key, lat_ms):
        with self._lock:
            st = self.conn_stats.setdefault(key, {"ok": 0, "fail": 0, "lat_sum": 0, "last": 0})
            st["ok"] += 1
            st["lat_sum"] += lat_ms
            st["last"] = lat_ms

    def conn_fail(self, key):
        with self._lock:
            st = self.conn_stats.setdefault(key, {"ok": 0, "fail": 0, "lat_sum": 0, "last": 0})
            st["fail"] += 1

    def conn_summary(self):
        """连接健康度汇总: 返回 {key: {ok, fail, avg_lat_ms, last_lat_ms}}。"""
        with self._lock:
            out = {}
            for k, st in self.conn_stats.items():
                ok = st.get("ok", 0)
                out[k] = {
                    "ok": ok,
                    "fail": st.get("fail", 0),
                    "avg_lat_ms": round(st["lat_sum"] / ok, 1) if ok else None,
                    "last_lat_ms": st.get("last"),
                }
            return out

    # ---- H-1/H-3: 共享容器的线程安全快照 ----
    def counters_snapshot(self):
        """counters/rule_hits + 派生比率的一次锁内快照。

        返回 (counters, rule_hits, hit_rate, qps, avg_latency_ms)。
        reset() 在锁内整体替换 counters/rule_hits 并清空 qps/latency 窗口;
        同一次持锁拷贝保证单条响应内计数与派生指标自洽——不再出现
        counters.total=100(旧值) 而 hit_rate=0(reset 后 live 值) 的混合态。
        /metrics 与 /api/status 统一走此方法, 派生指标不再锁外读 live 引用。"""
        with self._lock:
            counters = dict(self.counters)
            rule_hits = dict(self.rule_hits)
            total = counters["total"]
            hit_rate = (counters["hit"] / total * 100) if total else 0.0
            now = time.time()
            while self.qps_window and now - self.qps_window[0] > 1.0:
                self.qps_window.popleft()
            qps = len(self.qps_window)
            alen = len(self.latency_window)
            avg_lat = (sum(self.latency_window) / alen) if alen else None
            return counters, rule_hits, hit_rate, qps, avg_lat

    def upstreams_snapshot(self):
        """per_upstream.items() 的加锁拷贝。直接在锁外 .items() 迭代时, 并发
        upstream_ok() 的 setdefault 新增 key 会抛 RuntimeError: dictionary
        changed size during iteration (Prometheus /metrics 抓取 500)。"""
        with self._lock:
            return list(self.per_upstream.items())

    def top_domains_snapshot(self, n=10):
        """top_domains.most_common(n) 的加锁拷贝。Counter 整体替换 / 新域名自增
        与 most_common 内部迭代并发时同样会抛 RuntimeError。"""
        with self._lock:
            return self.top_domains.most_common(n)

    def top_clients_snapshot(self, n=10):
        with self._lock:
            return self.top_clients.most_common(n)

    def add_manual_entry(self, entry):
        """手动查询历史: append + 截断统一在锁内, 避免并发 append 丢记录。"""
        with self._lock:
            self.manual_history.append(entry)
            if len(self.manual_history) > 20:
                self.manual_history = self.manual_history[-20:]
    # ---- 缓存命中快路径（一次加锁完成所有遥测更新, 减少热路径锁竞争）----
    @staticmethod
    def _should_sample_event(level):
        """v1.9.76: 真实流量(hit/miss)日志按 10% 采样进 events deque, 降低高 QPS
        下锁内 append 开销; err/warn/rule/sys 等低频事件全量保留。"""
        if level in ("hit", "miss"):
            return random.random() < 0.1
        return True

    def fast_hit(self, qtype, raw_len, resp_len, lat_ms, kernel_direct=False):
        with self._lock:
            self.counters["total"] += 1
            self.counters["hit"] += 1
            if kernel_direct:
                self.counters["kernel_direct"] += 1
            self.counters["bytes_in"] += raw_len
            self.counters["bytes_out"] += resp_len
            self.qtype_dist[self.qtype_cat(qtype)] += 1
        self.qps_window.append(time.time())
        self.latency_window.append(lat_ms)

    def fast_hit_logged(self, qtype, raw_len, resp_len, lat_ms, domain, msg,
                        upstream, answer, kernel_direct=False, level="hit"):
        """合并 fast_hit + log: 一次加锁完成计数器更新与事件记录。
        原 fast_hit + log 各获取一次锁, 热路径(每 QPS 两次锁竞争)减半。"""
        with self._lock:
            self.counters["total"] += 1
            self.counters["hit"] += 1
            if kernel_direct:
                self.counters["kernel_direct"] += 1
            self.counters["bytes_in"] += raw_len
            self.counters["bytes_out"] += resp_len
            self.qtype_dist[self.qtype_cat(qtype)] += 1
            # v1.9.76: 真实流量(hit)事件 10% 采样进 events, 计数器仍全量更新
            if self._should_sample_event(level):
                self._ev_seq += 1
                self.events.append({
                    "seq": self._ev_seq,
                    "ts": _now_ts(),
                    "domain": domain,
                    "qtype": qtype,
                    "level": level,
                    "msg": msg,
                    "lat": lat_ms,
                    "client_ip": None,
                    "upstream": upstream,
                    "answer": answer,
                    "rule": None,
                })
        self.qps_window.append(time.time())
        self.latency_window.append(lat_ms)

    # ---- 日志事件 ----
    def log(self, domain, qtype, level, msg, lat=None, client_ip=None, upstream=None, answer=None, rule=None):
        """level: hit / miss / rule / err / sys / warn。

        client_ip: 查询来源客户端 IP(内网/公网地址字符串, 后台任务为 None)
        upstream:  实际应答来源(缓存直答/内核直答/serve-stale/分流规则/上游名列表)
        answer:    解析值 IP(应答的 chosen IP, 无答案如 NXDOMAIN 为 '')
        rule:      命中的分流规则 match(未命中为 None)
        v1.9.76: 真实流量(hit/miss)事件 10% 采样, 其余全量。
        """
        with self._lock:
            if not self._should_sample_event(level):
                return
            self._ev_seq += 1
            self.events.append({
                "seq": self._ev_seq,
                "ts": _now_ts(),
                "domain": domain,
                "qtype": qtype,
                "level": level,
                "msg": msg,
                "lat": lat,
                "client_ip": client_ip,
                "upstream": upstream,
                "answer": answer,
                "rule": rule,
            })

    # ---- 每秒采样 ----
    def sample(self):
        self.history.append({
            "label": time.strftime("%H:%M:%S"),
            "hit_rate": round(self.hit_rate(), 1),
            "qps": self.current_qps(),
            "lat": round(self.avg_latency(), 1) if self.avg_latency() is not None else 0,
        })
        if len(self.history) > 120:
            self.history = self.history[-120:]
        return self.history[-1]

    # ---- 快照（API 用）----
    def snapshot(self):
        # 读路径统一持锁: counters/rule_hits/qtype_dist/per_upstream/conn_stats/events/
        # top_* 均由各写方法在锁内更新。snapshot 不加锁时, 并发 count_top() 整体
        # 替换 top_domains 或新域名自增会让 most_common() 迭代中 "dict changed
        # size" 抛 RuntimeError; 锁内一次性拷贝保证读一致性。被调方法(hit_rate/
        # current_qps/avg_latency)自身不再获取 _lock, 无重入死锁。
        with self._lock:
            al = self.avg_latency()
            return {
                "uptime_s": int(time.time() - self.boot_time),
                "running": True,
                "counters": dict(self.counters),
                "rule_hits": dict(self.rule_hits),
                "qtype_dist": dict(self.qtype_dist),
                "qps": self.current_qps(),
                "hit_rate": round(self.hit_rate(), 1),
                "avg_latency_ms": round(al, 1) if al is not None else None,
                "history": self.history[-60:],
                "events": list(self.events),
                "manual_history": list(self.manual_history[-20:]),
                "top_domains": self.top_domains.most_common(10),
                "top_clients": self.top_clients.most_common(10),
                "top_upstreams": sorted(
                    ((u, st.get("ok", 0) + st.get("fail", 0)) for u, st in self.per_upstream.items()),
                    key=lambda x: x[1], reverse=True)[:10],
            }

    def reset(self):
        # 所有清状态操作统一持锁, 避免与并发查询/快照交错读到半重置状态。
        # 注意: 内联计数器重置而非调用 set_counters(它也会抢同一把非可重入锁,
        # 在外层 with 内再 acquire 会死锁)。
        with self._lock:
            self.counters = {k: 0 for k in self.counters}
            self.qtype_dist = {"A": 0, "AAAA": 0, "other": 0}
            self.rule_hits = {"domestic": 0, "global": 0, "block": 0, "forceIp": 0}
            self.qps_window.clear()
            self.latency_window.clear()
            self.history = []
            self.events.clear()
            self.per_upstream.clear()
            self.conn_stats.clear()
            self.manual_history = []
            self.top_domains.clear()
            self.top_clients.clear()


def _now_ts():
    """带秒级缓存的时间戳格式化: time.localtime() 是系统调用, 每查询日志都调用在
    高 QPS 下是显著开销。同一秒内复用 localtime 结果; 毫秒位每次现算(v1.9.76:
    原实现连毫秒一起按秒缓存, 同一秒内 ms 位冻结成首个调用值, 时间戳失真)。"""
    now = time.time()
    sec = int(now)
    cached = _now_ts._cache
    if cached is not None and cached[0] == sec:
        hhmmss = cached[1]
    else:
        t = time.localtime(now)
        hhmmss = "%02d:%02d:%02d" % (t.tm_hour, t.tm_min, t.tm_sec)
        _now_ts._cache = (sec, hhmmss)
    ms = int(now * 1000) % 1000
    return "%s.%03d" % (hhmmss, ms)

_now_ts._cache = None
