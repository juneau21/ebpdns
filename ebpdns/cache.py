"""用户态 LRU 缓存 —— 模拟 BPF_MAP_TYPE_LRU_HASH 语义。

- key:  (domain_lower, qtype)
- value: {answers:[{value, from, ttl}], chosen, expires_at, access_at}
- 满容量按最近最少使用淘汰；支持惰性清理过期条目。
"""

import threading
import time
from collections import OrderedDict


class LRUCache:
    """分桶 LRU 缓存：内部 _SHARDS 个独立分桶，每桶独立锁+OrderedDict。
    按 key hash 路由分桶——不同域名的查询可并行读写不同分桶，
    消除单锁高并发瓶颈(原单锁在 6 万 QPS 下所有线程串行等待)。"""

    _SHARDS = 8

    def __init__(self, capacity=1024):
        self._caps = [max(16, capacity // self._SHARDS)] * self._SHARDS
        self._maps = [OrderedDict() for _ in range(self._SHARDS)]
        self._locks = [threading.Lock() for _ in range(self._SHARDS)]
        self._cap = max(16, capacity)
        self._puts = 0

    def _shard(self, key):
        return hash(key) & (self._SHARDS - 1)

    @property
    def capacity(self):
        return self._cap

    @capacity.setter
    def capacity(self, n):
        n = max(16, int(n))
        per = n // self._SHARDS
        self._cap = n
        for i in range(self._SHARDS):
            with self._locks[i]:
                self._caps[i] = per
                self._evict_locked(i)

    def get(self, key, now=None):
        now = now if now is not None else time.time()
        i = self._shard(key)
        with self._locks[i]:
            entry = self._maps[i].get(key)
            if not entry:
                return None
            if entry.get("expires_at", 0) <= now:
                self._maps[i].pop(key, None)
                return None
            self._maps[i].move_to_end(key)
            return entry

    def put(self, key, value, now=None):
        now = now if now is not None else time.time()
        i = self._shard(key)
        with self._locks[i]:
            self._maps[i][key] = value
            self._maps[i].move_to_end(key)
            self._evict_locked(i)
            self._puts += 1
            if (self._puts & 0x1F) == 0:
                self._purge_expired_locked(i, now)

    def delete(self, key):
        i = self._shard(key)
        with self._locks[i]:
            self._maps[i].pop(key, None)

    def get_stale(self, key, now=None, stale_window=3600):
        now = now if now is not None else time.time()
        i = self._shard(key)
        with self._locks[i]:
            entry = self._maps[i].get(key)
            if not entry:
                return None
            exp = entry.get("expires_at", 0)
            if exp > now:
                return None
            if now - exp > stale_window:
                self._maps[i].pop(key, None)
                return None
            return entry

    def _evict_locked(self, i):
        while len(self._maps[i]) > self._caps[i]:
            self._maps[i].popitem(last=False)

    def purge_expired(self, now=None):
        now = now if now is not None else time.time()
        total = 0
        for i in range(self._SHARDS):
            with self._locks[i]:
                total += self._purge_expired_locked(i, now)
        return total

    def _purge_expired_locked(self, i, now):
        # LRU 顺序下(OrderedDict: 队首=最久未访问), 过期条目集中在队首。
        # 只从队首向后扫描到首个未过期条目即停, 避免每 32 次 put 做全表扫描
        # (高容量下全表扫描在锁内执行会阻塞 get/put 热路径)。
        cnt = 0
        while self._maps[i]:
            k, e = next(iter(self._maps[i].items()))
            if e.get("expires_at", 0) > now:
                break
            self._maps[i].pop(k, None)
            cnt += 1
        return cnt

    def clear(self):
        for i in range(self._SHARDS):
            with self._locks[i]:
                self._maps[i].clear()

    def __len__(self):
        return sum(len(self._maps[i]) for i in range(self._SHARDS))

    def snapshot_keys(self):
        out = []
        for i in range(self._SHARDS):
            with self._locks[i]:
                out.extend(self._maps[i].keys())
        return out

    def size(self):
        return len(self)

    def keys(self):
        return self.snapshot_keys()

    def summary(self):
        used = len(self)
        return {
            "used": used,
            "capacity": self._cap,
            "pct": round(used / max(1, self._cap) * 100, 1),
        }

    # ---- 持久化（重启恢复） ----
    def serialize(self, now=None):
        now = now if now is not None else time.time()
        out = []
        for i in range(self._SHARDS):
            with self._locks[i]:
                for k, e in self._maps[i].items():
                    if e.get("expires_at", 0) <= now:
                        continue
                    d = dict(e)
                    d.pop("resp_body", None)
                    d["remaining"] = max(0, round(e.get("expires_at", 0) - now, 1))
                    out.append({"key": [k[0], k[1]], **d})
        return out

    def restore(self, entries, now=None, persist_ttl=0):
        now = now if now is not None else time.time()
        pt = 0
        try:
            pt = max(0, float(persist_ttl or 0))
        except Exception:
            pt = 0
        for i in range(self._SHARDS):
            with self._locks[i]:
                self._maps[i].clear()
        for e in entries or []:
            try:
                k = tuple(e.get("key") or [])
                if len(k) != 2:
                    continue
                if "answers" not in e or "rcode" not in e:
                    continue
                e = dict(e)
                if pt > 0:
                    e["expires_at"] = now + pt
                    e["ttl"] = pt
                elif "remaining" in e:
                    if e["remaining"] <= 0:
                        continue
                    e["expires_at"] = now + float(e["remaining"])
                elif e.get("expires_at", 0) <= now:
                    continue
                e.pop("resp_body", None)
                i = self._shard(k)
                with self._locks[i]:
                    self._maps[i][k] = e
            except Exception:
                continue
        for i in range(self._SHARDS):
            with self._locks[i]:
                self._evict_locked(i)

# ============================================================================
# 缓存分区 (PartitionedCache): 按分流 group 隔离缓存池
# - key 统一为 3 元组 (group, domain_lower, qtype), group ∈ domestic/global/default
# - 内部按 group 各自维护 LRUCache, 容量按比例分配(可配置)
# - 对外接口与 LRUCache 完全一致(get/put/get_stale/...), 仅 key 多一个 group 维
# ============================================================================
_DEFAULT_PARTITIONS = {"domestic": 0.2, "global": 0.2, "default": 0.6}


class PartitionedCache:
    def __init__(self, capacity=1024, partitions=None):
        self._cap = max(16, int(capacity))
        self._parts = dict(_DEFAULT_PARTITIONS if partitions is None else partitions)
        self._groups = sorted(self._parts)
        # 每分区至少 16 条, 剩余按比例分配
        self._caches = {}
        for g in self._groups:
            share = max(16, int(self._cap * self._parts[g]))
            self._caches[g] = LRUCache(share)

    def _split(self, key):
        """key 3 元组 (group, domain, qtype); 兼容旧 2 元组(归 default)。"""
        if len(key) == 3:
            g, k = key[0], key[1:]
        else:
            g, k = "default", tuple(key)
        if g not in self._caches:
            g = "default"
        return g, k

    @property
    def capacity(self):
        return self._cap

    @capacity.setter
    def capacity(self, n):
        self._cap = max(16, int(n))
        for g, c in self._caches.items():
            share = max(16, int(self._cap * self._parts.get(g, 0.1)))
            c.capacity = share

    def get(self, key, now=None):
        g, k = self._split(key)
        return self._caches[g].get(k, now)

    def put(self, key, value, now=None):
        g, k = self._split(key)
        return self._caches[g].put(k, value, now)

    def get_stale(self, key, now=None, stale_window=3600):
        g, k = self._split(key)
        return self._caches[g].get_stale(k, now, stale_window)

    def delete(self, key):
        g, k = self._split(key)
        return self._caches[g].delete(k)

    def clear(self):
        for c in self._caches.values():
            c.clear()

    def __len__(self):
        return sum(len(c) for c in self._caches.values())

    def snapshot_keys(self):
        out = []
        for g, c in self._caches.items():
            for k in c.snapshot_keys():
                out.append((g,) + k)
        return out

    def size(self):
        return len(self)

    def keys(self):
        return self.snapshot_keys()

    def summary(self):
        used = len(self)
        return {
            "used": used,
            "capacity": self._cap,
            "pct": round(used / max(1, self._cap) * 100, 1),
            "partitions": {g: c.summary() for g, c in self._caches.items()},
        }

    def serialize(self, now=None):
        out = []
        for g, c in self._caches.items():
            for e in c.serialize(now):
                e["key"] = [g] + list(e.get("key") or [])
                out.append(e)
        return out

    def restore(self, entries, now=None, persist_ttl=0):
        # 按 group 聚合条目后每组只调用一次内层 restore。
        # 旧实现逐条调用 self._caches[g].restore([e], ...), 而 LRUCache.restore
        # 开头会 clear() 整个 shard, 导致每个 group 只保留最后一条。
        groups = {}
        for e in entries or []:
            k = e.get("key") or []
            if len(k) == 3:
                g = k[0] if k[0] in self._caches else "default"
                kk = (k[1], k[2])
            elif len(k) == 2:
                g = "default"
                kk = tuple(k)
            else:
                continue
            try:
                groups.setdefault(g, []).append({**e, "key": list(kk)})
            except Exception:
                continue
        for g, es in groups.items():
            try:
                self._caches[g].restore(es, now, persist_ttl)
            except Exception:
                continue


# ============================================================================
# W-TinyLFU 淘汰策略 (TinyLFUCache): 比 LRU 命中率更高的工程版实现
# - window(1%) + main(99%) 双区: 新条目先进 window, 淘汰时与 main 队首候选
#   按 Count-Min Sketch 频率估计做准入决策(高频才进 main)
# - main 用 OrderedDict(LRU 顺序) + sketch 频率记录; 访问 move_to_end
# - 老化: 每 2^16 次计数后全表减半(防频率长期累积失真)
# 纯 Python 实现有常数开销, 由 cache_policy 配置选择(lru 默认, tinylfu 可选)
# ============================================================================
class _CMSketch:
    """Count-Min Sketch: 4 行 x 1024 列, 8bit 饱和计数, 老化时减半。"""
    _D = 4
    _W = 1024

    def __init__(self):
        self._t = [[0] * self._W for _ in range(self._D)]
        self._ops = 0

    def inc(self, k, n=1):
        self._ops += n
        if self._ops >= 65536:
            self._age()
        # 各行的列来自不同种子, 统一按行写入
        h1 = hash(k)
        for i in range(_CMSketch._D):
            h = (h1 >> (i * 8)) | (i * 2654435761)
            col = (h & 0x7FFFFFFF) % _CMSketch._W
            nv = self._t[i][col] + n
            self._t[i][col] = nv if nv < 255 else 255

    def freq(self, k):
        mn = 255
        h1 = hash(k)
        for i in range(_CMSketch._D):
            h = (h1 >> (i * 8)) | (i * 2654435761)
            col = (h & 0x7FFFFFFF) % _CMSketch._W
            v = self._t[i][col]
            if v < mn:
                mn = v
        return mn

    def _age(self):
        self._ops = 0
        for row in self._t:
            for i in range(_CMSketch._W):
                row[i] >>= 1


class TinyLFUCache:
    """W-TinyLFU 工程版(Caffeine 分段式): window → probation → protected。

    三段结构(Caffeine 默认比例):
      - window      1%    : 新条目入口(LRU 顺序), 吸收突发流量
      - protected   约 80%: 命中即晋升的高频区, 受保护不被轻易淘汰
      - probation   约 20%: 晋升候选区, 真正的淘汰发生在这里

    淘汰链: window 超容 → 队首与 probation 队首比频率(freq), 高者进 probation;
    protected 超容 → 队首挤回 probation; probation 超容 → 丢队首(淘汰)。
    相比上一版(单 main 区), protected 段让高频条目即使短期未命中也不会
    被同频/低频条目从 LRU 队尾挤出, 长尾热点保持性更强。
    """
    def __init__(self, capacity=1024):
        self._cap = max(64, int(capacity))
        self._win_cap = self._prob_cap = self._prot_cap = self._main_cap = 16
        self._window = OrderedDict()      # 新条目窗口区
        self._probation = OrderedDict()   # 晋升候选区
        self._protected = OrderedDict()   # 高频保护区
        self._sketch = _CMSketch()
        self._lock = threading.Lock()
        self._puts = 0
        self._repartition_locked()

    @property
    def capacity(self):
        return self._cap

    @capacity.setter
    def capacity(self, n):
        with self._lock:
            self._cap = max(64, int(n))
            self._repartition_locked()
            self._evict_locked()

    def _repartition_locked(self):
        """按 Caffeine 比例重算三段容量: window 1% / probation 40% / protected 60%(main 内)。
        probation 从 20% 提到 40%: DNS 负载下新条目从 window 溢出后需要足够
        缓冲等待下一次命中晋升 protected, 20% 过窄导致刚进 probation 的条目
        未及晋升就被后续溢出挤掉(实测 Zipf 命中率 93.9%→93.4%, 40% 恢复)。"""
        win = max(16, self._cap // 100)
        main = self._cap - win
        prob = max(16, main * 2 // 5)
        prot = main - prob
        self._win_cap, self._prob_cap, self._prot_cap, self._main_cap = win, prob, prot, main

    def get(self, key, now=None):
        now = now if now is not None else time.time()
        with self._lock:
            e = self._window.get(key)
            if e is not None:
                if e.get("expires_at", 0) <= now:
                    self._window.pop(key, None)
                    return None
                self._window.move_to_end(key)
                self._sketch.inc(key)
                return e
            e = self._probation.get(key)
            if e is not None:
                if e.get("expires_at", 0) <= now:
                    self._probation.pop(key, None)
                    return None
                # 命中即晋升 protected(受保护段), protected 满则挤队首回 probation
                self._probation.pop(key)
                if len(self._protected) >= self._prot_cap and self._protected:
                    pk, pv = self._protected.popitem(last=False)
                    self._probation[pk] = pv
                self._protected[key] = e
                self._protected.move_to_end(key)
                self._sketch.inc(key)
                return e
            e = self._protected.get(key)
            if e is not None:
                if e.get("expires_at", 0) <= now:
                    self._protected.pop(key, None)
                    return None
                self._protected.move_to_end(key)
                self._sketch.inc(key)
                return e
            return None

    def put(self, key, value, now=None):
        now = now if now is not None else time.time()
        with self._lock:
            if key in self._protected:
                self._protected[key] = value
                self._protected.move_to_end(key)
            elif key in self._probation:
                self._probation[key] = value
                self._probation.move_to_end(key)
            elif key in self._window:
                self._window[key] = value
                self._window.move_to_end(key)
            else:
                self._window[key] = value
            # recordWrite 语义: 写入也计频(Caffeine 一致), 否则首次写入的新条目
            # freq≈0, 准入比较时必输给已多次访问的旧条目, 永远无法晋升
            self._sketch.inc(key)
            self._evict_locked()
            self._puts += 1
            if (self._puts & 0x1F) == 0:
                self._purge_expired_locked(now)

    def get_stale(self, key, now=None, stale_window=3600):
        now = now if now is not None else time.time()
        with self._lock:
            for store in (self._window, self._probation, self._protected):
                e = store.get(key)
                if not e:
                    continue
                exp = e.get("expires_at", 0)
                if exp > now:
                    return None
                if now - exp > stale_window:
                    store.pop(key, None)
                    return None
                return e
            return None

    def delete(self, key):
        with self._lock:
            self._window.pop(key, None)
            self._probation.pop(key, None)
            self._protected.pop(key, None)

    def clear(self):
        with self._lock:
            self._window.clear()
            self._probation.clear()
            self._protected.clear()
            self._sketch = _CMSketch()

    def _evict_locked(self):
        # 1) window 超容 → 队首进入 main:
        #    a. probation 有空位 → 直进 probation(冷启动/低占用)
        #    b. probation 满但 main 总容量未满 → 直进 protected(回填, 防总条目流失:
        #       准入比较会拒绝低频 candidate, window 少 1 且无回填 → 缓存永久缩水,
        #       实测 300 容量缩到 129)
        #    c. main 满 → 与 probation 队首(victim)频率准入: 高频 candidate 替换
        #       低频 victim; candidate 输则被淘汰(window 少 1, 下次 put 由 b 回填)
        while len(self._window) > self._win_cap:
            wk, wv = self._window.popitem(last=False)
            if len(self._probation) < self._prob_cap:
                self._probation[wk] = wv
                continue
            if len(self._probation) + len(self._protected) < self._main_cap:
                self._protected[wk] = wv
                continue
            mk, _mv = next(iter(self._probation.items()))
            if self._sketch.freq(wk) >= self._sketch.freq(mk):
                self._probation.pop(mk, None)
                self._probation[wk] = wv
        # 2) protected 超容 → 队首挤回 probation(由 1 的准入裁决保护)
        while len(self._protected) > self._prot_cap:
            pk, pv = self._protected.popitem(last=False)
            self._probation[pk] = pv
        # 3) probation 超容 → 丢队首(真正淘汰点)
        while len(self._probation) > self._prob_cap:
            self._probation.popitem(last=False)

    def _purge_expired_locked(self, now):
        for store in (self._window, self._probation, self._protected):
            expired = [k for k, e in store.items() if e.get("expires_at", 0) <= now]
            for k in expired:
                store.pop(k, None)

    def __len__(self):
        with self._lock:
            return len(self._window) + len(self._probation) + len(self._protected)

    def snapshot_keys(self):
        with self._lock:
            return (list(self._window.keys()) + list(self._probation.keys())
                    + list(self._protected.keys()))

    def keys(self):
        return self.snapshot_keys()

    def size(self):
        return len(self)

    def summary(self):
        return {
            "used": len(self),
            "capacity": self._cap,
            "pct": round(len(self) / max(1, self._cap) * 100, 1),
            "window": len(self._window),
            "probation": len(self._probation),
            "protected": len(self._protected),
        }

    def serialize(self, now=None):
        now = now if now is not None else time.time()
        with self._lock:
            out = []
            for k, e in (list(self._window.items()) + list(self._probation.items())
                         + list(self._protected.items())):
                if e.get("expires_at", 0) <= now:
                    continue
                d = dict(e)
                d.pop("resp_body", None)
                d["remaining"] = max(0, round(e.get("expires_at", 0) - now, 1))
                out.append({"key": [k[0], k[1]], **d})
            return out

    def restore(self, entries, now=None, persist_ttl=0):
        now = now if now is not None else time.time()
        pt = 0
        try:
            pt = max(0, float(persist_ttl or 0))
        except Exception:
            pt = 0
        with self._lock:
            self._window.clear()
            self._probation.clear()
            self._protected.clear()
            for e in entries or []:
                try:
                    k = tuple(e.get("key") or [])
                    if len(k) != 2 or "answers" not in e or "rcode" not in e:
                        continue
                    e = dict(e)
                    if pt > 0:
                        e["expires_at"] = now + pt
                        e["ttl"] = pt
                    elif "remaining" in e:
                        if e["remaining"] <= 0:
                            continue
                        e["expires_at"] = now + float(e["remaining"])
                    elif e.get("expires_at", 0) <= now:
                        continue
                    e.pop("resp_body", None)
                    self._window[k] = e
                except Exception:
                    continue
            self._evict_locked()
