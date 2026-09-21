"""用户态 LRU 缓存 —— 模拟 BPF_MAP_TYPE_LRU_HASH 语义。

- key:  (domain_lower, qtype)
- value: {answers:[{value, from, ttl}], chosen, expires_at, access_at}
- 满容量按最近最少使用淘汰；支持惰性清理过期条目。
"""

import threading
import time
from collections import OrderedDict


def _safe_int(v, default=0):
    """R6/P3-2: 与 resolver._safe_int 同模式(本地副本, 避免循环 import)。
    旧 stale_window setter 用 `int(v or 0)` falsy 模式——0 被改写、畸形串
    直接 ValueError。现严格区分: None/无法解析→default, 可解析值(含 0)保留。
    """
    if v is None:
        return default
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _safe_float(v, default=0.0):
    """R7/P2-4: 与 resolver._safe_float 同模式(本地副本, 避免循环 import)。
    restore() 内裸 float(persist_ttl or 0) 对畸形串抛 ValueError 被 try/except
    兜底成 pt=0——冗余且吞错。改 _safe_float: None/无法解析→default, 可解析值保留。"""
    if v is None:
        return default
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


class LRUCache:
    """分桶 LRU 缓存：内部 _SHARDS 个独立分桶，每桶独立锁+OrderedDict。
    按 key hash 路由分桶——不同域名的查询可并行读写不同分桶，
    消除单锁高并发瓶颈(原单锁在 6 万 QPS 下所有线程串行等待)。"""

    _SHARDS = 8

    def __init__(self, capacity=1024):
        # cache_size=null/None 归一化: 配置显式设为 null 时 cfg.get 返回 None
        # (key 存在), 直接 None//8 会 TypeError 崩溃。None 按默认容量。
        # 先 max(16,...) 钳到最小容量再 divmod: LRU 内部分 8 shard, 容量<8 时
        # divmod 会让部分 shard 得 0 容量(put 后立即被 _evict_locked 淘汰), 这些
        # shard 上的 key 永远缓存不住。min-16 保证每 shard 至少 2 条, 是 8-shard
        # 设计的安全下限。PartitionedCache 的小容量分配份额经此钳制后生效(R48/P3-1)。
        if capacity is None:
            capacity = 1024
        # R6/P2-3 全量清扫: 原仅 None 归一化, 畸形串仍 int() 抛 ValueError。
        # resolver 侧已 _safe_int 包裹, 缓存层自身也防御性兜底。
        capacity = max(16, _safe_int(capacity, 1024))
        # #9 分桶余数同 setter: divmod 分摊余数, 总容量恰为 capacity
        _base, _rem = divmod(capacity, self._SHARDS)
        self._caps = [_base + (1 if i < _rem else 0) for i in range(self._SHARDS)]
        self._maps = [OrderedDict() for _ in range(self._SHARDS)]
        self._locks = [threading.Lock() for _ in range(self._SHARDS)]
        self._cap = capacity
        # P3-7(第八轮): 全局 _puts 跨 shard 读-改-写存在 lost update。改为每分桶
        # 独立计数器, 在各自 shard 锁内自增, 消除竞态。
        self._put_counts = [0] * self._SHARDS
        # v1.9.74 P1-2: >0 时保留"过期但在 stale_window 内"的条目(serve-stale 兜底),
        # 由 resolver 用 cfg stale_ttl 下发。0 = 旧行为(get/purge 见到过期即删)。
        self._stale_window = 0

    @property
    def stale_window(self):
        return self._stale_window

    @stale_window.setter
    def stale_window(self, v):
        # R6/P3-2: 旧 `int(v or 0)` 是 R5 已修掉的 falsy-0 模式——畸形串("abc")
        # `or` 后仍是 "abc" → int() 抛 ValueError。改用本地 _safe_int(None/畸形→0,
        # 0 保留), max(0,...) 钳负值。LRUCache 与 TinyLFUCache 两处 setter 同型。
        self._stale_window = max(0, _safe_int(v, 0))

    def _shard(self, key):
        return hash(key) & (self._SHARDS - 1)

    @property
    def capacity(self):
        return self._cap

    @capacity.setter
    def capacity(self, n):
        if n is None:
            n = 1024
        n = max(16, _safe_int(n, 1024))
        self._cap = n
        # #9 LRU 分桶余数: divmod 把余数分摊到前 rem 个分桶, 使各桶容量之和恰为 n
        # (原 n//SHARDS 丢弃余数, 总容量 = n - 余数, 与配置 cache_size 不一致)
        base, rem = divmod(n, self._SHARDS)
        for i in range(self._SHARDS):
            with self._locks[i]:
                self._caps[i] = base + (1 if i < rem else 0)
                self._evict_locked(i)

    def get(self, key, now=None):
        if now is None:
            now = time.time()
        i = self._shard(key)
        with self._locks[i]:
            m = self._maps[i]
            entry = m.get(key)
            if entry is None:
                return None
            # 所有回填/恢复路径均保证 expires_at 字段存在, 直接索引比 .get() 省一次
            # 默认值查找(热路径每 QPS 一次, dict.get 占 cProfile 显著比例)。
            if entry["expires_at"] <= now:
                # v1.9.74 P1-2: 过期不 pop。由 get_stale() 决定"窗口内保留/窗口外清除",
                # 否则 serve-stale 条目在首次过期命中后即被删除, 上游故障期间只能兜底一次。
                return None
            m.move_to_end(key)
            return entry

    def put(self, key, value, now=None):
        now = now if now is not None else time.time()
        i = self._shard(key)
        with self._locks[i]:
            self._maps[i][key] = value
            self._maps[i].move_to_end(key)
            self._evict_locked(i)
            self._put_counts[i] += 1
            if (self._put_counts[i] & 0x1F) == 0:
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
            # v1.9.74 P1-2: 窗口内保留, 并移到队尾保护(防 LRU 淘汰立即清掉活跃 stale 条目)
            self._maps[i].move_to_end(key)
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
        # v1.9.74 P1-2: stale_window>0 时, 窗口内的过期条目保留(serve-stale 兜底用),
        # 只清超窗口的死条目。
        cnt = 0
        sw = self._stale_window
        while self._maps[i]:
            k, e = next(iter(self._maps[i].items()))
            exp = e.get("expires_at", 0)
            if exp > now:
                break
            if sw and (now - exp) <= sw:
                break
            self._maps[i].pop(k, None)
            cnt += 1
        return cnt

    def clear(self):
        for i in range(self._SHARDS):
            with self._locks[i]:
                self._maps[i].clear()

    def __len__(self):
        # P2-3: 原无锁读取 len(self._maps[i]) 与并发 put/delete 的 OrderedDict
        # 操作竞争, 可能抛 RuntimeError(dict changed size during iteration)或读到
        # 不一致长度。逐 shard 持锁读取后求和。
        total = 0
        for i in range(self._SHARDS):
            with self._locks[i]:
                total += len(self._maps[i])
        return total

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
        # R7/P2-4: 原裸 float(persist_ttl or 0) + try/except 兜底成 pt=0——冗余吞错。
        # 改用本地 _safe_float(None/畸形串→0.0), 再 max(0,...) 钳负值。
        pt = max(0, _safe_float(persist_ttl, 0.0))
        # C-01: 先在锁外为每个 shard 构建全新 OrderedDict, 再逐 shard 原子替换引用。
        # 旧实现先逐 shard clear(每清完一个 shard 就释放锁), 另一个线程可能在
        # shard0 已清而 shard1..N 未清时命中 shard0 的 get() → 对调用方表现为
        # "缓存丢失"。改为: 新 maps 在锁外构造完毕后, 逐 shard 持锁替换引用,
        # 读线程要么看到完整旧 map, 要么看到完整新 map, 不存在"半清"中间态。
        new_maps = [OrderedDict() for _ in range(self._SHARDS)]
        for e in entries or []:
            try:
                k = tuple(e.get("key") or [])
                # 兼容 PartitionedCache 序列化出的 3 元组 [group, domain, qtype]:
                # 剥掉 group 前缀还原为 (domain, qtype)。v1.9.x 热切换策略迁移
                # (partitioned -> lru) 时若拒绝 len==3 会丢全部数据。
                if len(k) == 3:
                    k = (k[1], k[2])
                elif len(k) != 2:
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
                    e["expires_at"] = now + _safe_float(e.get("remaining", 0.0), 0.0)
                elif e.get("expires_at", 0) <= now:
                    continue
                e.pop("resp_body", None)
                i = self._shard(k)
                new_maps[i][k] = e
            except Exception:
                continue
        # 逐 shard 持锁替换引用 + 按新容量淘汰。引用替换是原子的(单字节指针写),
        # 读线程持锁后读到的要么是旧 map 要么是新 map, 二者都自洽。
        for i in range(self._SHARDS):
            with self._locks[i]:
                self._maps[i] = new_maps[i]
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
        # cache_size=null/None 归一化(见 LRUCache.__init__ 说明): int(None) 会崩溃。
        if capacity is None:
            capacity = 1024
        self._cap = max(16, _safe_int(capacity, 1024))
        self._parts = dict(_DEFAULT_PARTITIONS if partitions is None else partitions)
        # M1(第六份review): 自定义 partitions 可能是原始权重(如 {a:2,b:3,c:5} 未归一),
        # 不归一化则 self._cap * self._parts[g] 会溢出总容量。统一归一化到和为 1,
        # __init__ 建分区与 capacity setter 共用此已归一化字典。
        # R7/P3-7: 负分区权重未校验。配置手误可能给出负权重, 归一化后负权重会使该分区
        # 分到负容量(_allocate 内 max(16,...) 虽掩盖下限, 但比例失真、总容量分裂)。
        # 先把每个权重钳到 >=0.0 再求和/归一化; 全 0/全负时 sum==0 → 回退 1.0 防除零。
        self._parts = {g: max(0.0, _safe_float(v, 0.0)) for g, v in self._parts.items()}
        _total = sum(self._parts.values()) or 1.0
        self._parts = {g: v / _total for g, v in self._parts.items()}
        self._groups = sorted(self._parts)
        # v1.9.76 2.11: 小容量重分配。原 max(16, cap*ratio) 在 cap 很小时(如 cap=16)
        # 每个分区都被抬到 16, 3 分区总容量膨胀到 48(远超配置)。改为: 先给每分区 16
        # (仅当总容量足够), 剩余按比例分; 总容量不足 16*分区数时按比例直接分(每分区
        # 至少 1)。
        # R48/P3-1: 小容量分支的份额(如 1/3/9)传入内层 LRUCache 后仍被其 min-16
        # 下限钳到 16(见 LRUCache.__init__ 说明: 8 shard 设计要求每 shard≥2 条)。
        # 故 cap<16*分区数 时实际各分区均为 16, 本分支只保证"按比例的相对大小"在
        # 容量≥16*分区数 时生效; 小容量下的总容量膨胀是有意安全下限, 非 bug。
        self._caches = {}
        for g, share in self._allocate(self._cap).items():
            self._caches[g] = LRUCache(share)

    def _allocate(self, cap):
        """按归一化权重把总容量 cap 分配到各分区, 总和恰为 cap。
        每分区下限 16 仅在总容量足够(>=16*分区数)时施加; 否则按比例直接分(每分区
        至少 1)。R48/P3-1: 小份额(1/3/9)传入 LRUCache 后仍被其 min-16 下限钳制,
        实际每分区至少 16 条——这是 LRUCache 8-shard 设计的安全下限, 有意保留。"""
        n = len(self._groups)
        if n == 0:
            return {}
        out = {}
        if cap >= 16 * n:
            base = 16
            rem = cap - 16 * n
            # 剩余按权重分配, divmod 余数给前若干组, 总和恰为 cap
            raw = {g: rem * self._parts[g] for g in self._groups}
            floored = {g: int(raw[g]) for g in self._groups}
            leftover = cap - 16 * n - sum(floored.values())
            order = sorted(self._groups, key=lambda g: raw[g] - floored[g], reverse=True)
            for i in range(leftover):
                floored[order[i % n]] += 1
            for g in self._groups:
                out[g] = base + floored[g]
        else:
            # 总容量太小: 按比例分, 每分区至少 1, divmod 凑整
            raw = {g: cap * self._parts[g] for g in self._groups}
            floored = {g: max(1, int(raw[g])) for g in self._groups}
            diff = cap - sum(floored.values())
            order = sorted(self._groups, key=lambda g: raw[g] - floored[g], reverse=True)
            i = 0
            while diff > 0:
                floored[order[i % n]] += 1
                diff -= 1
                i += 1
            while diff < 0:
                found = False
                for _ in range(n):
                    g = order[i % n]
                    if floored[g] > 1:
                        floored[g] -= 1
                        diff += 1
                        found = True
                        if diff >= 0:
                            break
                    i += 1
                if not found:
                    break
            out = floored
        return out

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

    @property
    def stale_window(self):
        c = next(iter(self._caches.values()), None)
        return getattr(c, "_stale_window", 0) if c else 0

    @stale_window.setter
    def stale_window(self, v):
        # P2-4: 原直接写 c._stale_window 绕过 LRUCache.stale_window setter
        # (line 45-47), 绕过了 int(v or 0) 归一化逻辑。走 setter 保持一致。
        for c in self._caches.values():
            c.stale_window = v

    @capacity.setter
    def capacity(self, n):
        if n is None:
            n = 1024
        self._cap = max(16, _safe_int(n, 1024))
        shares = self._allocate(self._cap)
        for g, c in self._caches.items():
            c.capacity = shares.get(g, 16)

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
    # P2-4: 老化触发间隔。原实现每 65536 次 inc 一次性减半 4 行(4096 cells)。
    # 改为分片: 每 65536/_D 次 inc 只减半一行(1024 cells), 4 次触发凑齐全表。
    # 每行仍按原节奏(累计 65536 ops)减半一次, 衰减语义不变, 单次持锁操作降为 1/4。
    _AGE_INTERVAL = 65536 // _D

    def __init__(self):
        self._t = [[0] * self._W for _ in range(self._D)]
        self._ops = 0
        self._age_row = 0   # P2-4: 下一个待减半的行号(循环 0..D-1)

    # 每行使用独立的乘同余常数(黄金比例衍生), 行间互不相关, 避免单一 hash(k)
    # 经移位/OR 派生导致的行间强相关与碰撞退化。
    _ROW_MULTS = (
        0x9E3779B97F4A7C15,
        0xBF58476D1CE4E5B9,
        0x94D049BB133111EB,
        0xC2B2AE3D27D4EB4F,
    )

    def inc(self, k, n=1):
        self._ops += n
        # P2-4: 达到阈值只分片老化一行, 不再在持锁时全表扫描 4096 cells。
        if self._ops >= _CMSketch._AGE_INTERVAL:
            self._ops = 0
            self._age_one_row()
        h1 = hash(k) & 0xFFFFFFFFFFFFFFFF
        # C-02: 局部绑定 _D 避免每次迭代类属性查找。
        D = _CMSketch._D
        rows = self._t
        mults = self._ROW_MULTS
        W = _CMSketch._W
        for i in range(D):
            h = (h1 * mults[i]) & 0xFFFFFFFFFFFFFFFF
            col = (h >> 32) % W
            nv = rows[i][col] + n
            rows[i][col] = nv if nv < 255 else 255

    def freq(self, k):
        mn = 255
        h1 = hash(k) & 0xFFFFFFFFFFFFFFFF
        D = _CMSketch._D
        rows = self._t
        mults = self._ROW_MULTS
        W = _CMSketch._W
        for i in range(D):
            h = (h1 * mults[i]) & 0xFFFFFFFFFFFFFFFF
            col = (h >> 32) % W
            v = rows[i][col]
            if v < mn:
                mn = v
        return mn

    def _age_one_row(self):
        """P2-4: 每次只老化一行(1024 cells)并轮转行号。
        原 _age() 在持有 TinyLFUCache._lock 时一次性减半 4×1024=4096 cells,
        每 65536 次 inc 阻塞所有 get/put。分片后单次持锁最多 1024 cells, 且每行
        仍按原节奏(每 65536 ops)减半一次, 衰减语义不变; 仅在行错位窗口内有可
        自校正的微小频率估计抖动, 不影响 TinyLFU 准入正确性。"""
        row = self._t[self._age_row]
        for i in range(_CMSketch._W):
            row[i] >>= 1
        self._age_row = (self._age_row + 1) % _CMSketch._D


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
        # cache_size=null/None 归一化(见 LRUCache.__init__ 说明): int(None) 会崩溃。
        if capacity is None:
            capacity = 1024
        # v1.9.76 2.12: 容量下限统一 16(原 TinyLFU 64 与 LRU/Partitioned 16 不一致)。
        # 内部 win/main/prob/prot 最小 16 的分段逻辑保持不变。
        self._cap = max(16, _safe_int(capacity, 1024))
        self._win_cap = self._prob_cap = self._prot_cap = self._main_cap = 16
        self._window = OrderedDict()      # 新条目窗口区
        self._probation = OrderedDict()   # 晋升候选区
        self._protected = OrderedDict()   # 高频保护区
        self._sketch = _CMSketch()
        self._lock = threading.Lock()
        self._puts = 0
        self._stale_window = 0   # v1.9.74 P1-2: >0 保留过期窗口内条目(serve-stale)
        self._repartition_locked()

    @property
    def stale_window(self):
        return self._stale_window

    @stale_window.setter
    def stale_window(self, v):
        # R6/P3-2: 旧 `int(v or 0)` 是 R5 已修掉的 falsy-0 模式——畸形串("abc")
        # `or` 后仍是 "abc" → int() 抛 ValueError。改用本地 _safe_int(None/畸形→0,
        # 0 保留), max(0,...) 钳负值。LRUCache 与 TinyLFUCache 两处 setter 同型。
        self._stale_window = max(0, _safe_int(v, 0))

    @property
    def capacity(self):
        return self._cap

    @capacity.setter
    def capacity(self, n):
        if n is None:
            n = 1024
        with self._lock:
            self._cap = max(16, _safe_int(n, 1024))
            self._repartition_locked()
            self._evict_locked()

    def _repartition_locked(self):
        """按 Caffeine 比例重算三段容量: window 1% / probation 40% / protected 60%(main 内)。
        probation 从 20% 提到 40%: DNS 负载下新条目从 window 溢出后需要足够
        缓冲等待下一次命中晋升 protected, 20% 过窄导致刚进 probation 的条目
        未及晋升就被后续溢出挤掉(实测 Zipf 命中率 93.9%→93.4%, 40% 恢复)。
        v1.9.76: 容量下限降到 16 后, 总容量很小(<48)时不再强行每段 16(会致
        prot 为负), 改为按比例分且各段至少 1; 正常容量保持 min 16 逻辑。"""
        cap = self._cap
        if cap < 48:
            win = max(1, cap // 100) or 1
            main = cap - win
            prob = max(1, main * 2 // 5)
            prot = max(1, main - prob)
            self._win_cap, self._prob_cap, self._prot_cap, self._main_cap = win, prob, prot, main
            return
        win = max(16, cap // 100)
        main = cap - win
        prob = max(16, main * 2 // 5)
        prot = main - prob
        self._win_cap, self._prob_cap, self._prot_cap, self._main_cap = win, prob, prot, main

    def get(self, key, now=None):
        now = now if now is not None else time.time()
        with self._lock:
            e = self._window.get(key)
            if e is not None:
                if e.get("expires_at", 0) <= now:
                    return None  # P1-2: 过期不 pop, 由 get_stale/purge 决定
                self._window.move_to_end(key)
                self._sketch.inc(key)
                return e
            e = self._probation.get(key)
            if e is not None:
                if e.get("expires_at", 0) <= now:
                    return None  # P1-2: 过期不 pop
                # 命中即晋升 protected(受保护段), protected 满则挤队首回 probation
                self._probation.pop(key)
                if len(self._protected) >= self._prot_cap and self._protected:
                    pk, pv = self._protected.popitem(last=False)
                    self._probation[pk] = pv
                    # #2 Caffeine 语义: protected 挤下的条目进 probation 队首
                    # (最久未使用, 下次优先被挤走), 直接赋值默认落队尾与之相反
                    self._probation.move_to_end(pk, last=False)
                self._protected[key] = e
                self._protected.move_to_end(key)
                self._sketch.inc(key)
                return e
            e = self._protected.get(key)
            if e is not None:
                if e.get("expires_at", 0) <= now:
                    return None  # P1-2: 过期不 pop
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
                # C-05: 窗口内保留并 move_to_end 保护, 与 LRUCache.get_stale 行为一致。
                store.move_to_end(key)
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
        #       main 未满时无需准入比较——准入比较会拒绝低频 candidate, window 少 1
        #       且无回填 → 缓存永久缩水, 实测 300 容量缩到 129。这是防缓存缩水的
        #       设计选择: main 段有空闲槽位时直接吸收 window 溢出条目。)
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
            # 严格 >: 频率相等时保留 probation 已有条目(Caffeine 标准语义),
            # 平局不允许新条目挤掉旧条目。
            if self._sketch.freq(wk) > self._sketch.freq(mk):
                self._probation.pop(mk, None)
                self._probation[wk] = wv
        # 2) protected 超容 → 队首挤回 probation(由 1 的准入裁决保护)
        while len(self._protected) > self._prot_cap:
            pk, pv = self._protected.popitem(last=False)
            self._probation[pk] = pv
            # #2 同晋升路径: 挤下的 protected 条目进 probation 队首(最久未使用)
            self._probation.move_to_end(pk, last=False)
        # 3) probation 超容 → 丢队首(真正淘汰点)
        while len(self._probation) > self._prob_cap:
            self._probation.popitem(last=False)

    def _purge_expired_locked(self, now):
        # OrderedDict LRU 序(队首=最久未访问): 过期条目集中在队首方向。
        # 从队首向后扫到首个未过期条目即停, 避免每 32 次 put 对三段全表做列表推导
        # (cap=4096 时每次 ~1.2 万次 dict 项遍历, 锁内阻塞 get/put 热路径, cProfile 实测
        # 占 TinyLFU put 累计时间 ~50%)。漏扫到的过期条目由 get 的惰性清理兜底, 不丢数据。
        # v1.9.74 P1-2: stale_window>0 时窗口内过期条目保留, 只清超窗口死条目。
        cnt = 0
        sw = self._stale_window
        for store in (self._window, self._probation, self._protected):
            if not store:
                continue
            while store:
                k, e = next(iter(store.items()))
                exp = e.get("expires_at", 0)
                if exp > now:
                    break
                if sw and (now - exp) <= sw:
                    break
                store.pop(k, None)
                cnt += 1
        return cnt

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
            # C-03: 用生成器遍历避免三段 list 拼接产生大临时列表。
            for store in (self._window, self._probation, self._protected):
                for k, e in store.items():
                    if e.get("expires_at", 0) <= now:
                        continue
                    d = dict(e)
                    d.pop("resp_body", None)
                    d["remaining"] = max(0, round(e.get("expires_at", 0) - now, 1))
                    out.append({"key": list(k), **d})
            return out

    def restore(self, entries, now=None, persist_ttl=0):
        now = now if now is not None else time.time()
        # R7/P2-4: 原裸 float(persist_ttl or 0) + try/except 兜底成 pt=0——冗余吞错。
        # 改用本地 _safe_float(None/畸形串→0.0), 再 max(0,...) 钳负值。
        pt = max(0, _safe_float(persist_ttl, 0.0))
        with self._lock:
            self._window.clear()
            self._probation.clear()
            self._protected.clear()
            # P1-3: restore() 清了三个 OrderedDict 但未重置 sketch, 旧频率计数残留
            # 会影响新恢复条目的准入决策(已淘汰域名的频率仍偏高, 挤掉真实高频条目)。
            # 与 clear() 方法保持一致, 重新初始化空 sketch。
            self._sketch = _CMSketch()
            for e in entries or []:
                try:
                    k = tuple(e.get("key") or [])
                    # S1(第六份review): TinyLFU 是顶层缓存, 不经 PartitionedCache._split,
                    # 运行期 resolver._ckey 始终返回 3 元组 (group,domain,qtype), serialize
                    # 也写 3 元组。restore 必须原样保留 3 元组, 否则重启后 key 错配全 miss。
                    # 仅兼容历史 2 元组旧条目(无 group)。
                    if len(k) != 3 and len(k) != 2:
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
                        e["expires_at"] = now + _safe_float(e.get("remaining", 0.0), 0.0)
                    elif e.get("expires_at", 0) <= now:
                        continue
                    e.pop("resp_body", None)
                    self._window[k] = e
                except Exception:
                    continue
            self._evict_locked()
