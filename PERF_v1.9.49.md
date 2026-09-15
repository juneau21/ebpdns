# eBPFDNS v1.9.49 性能与内存优化报告

> 基于 v1.9.48 代码库，热路径分析 + 安全优化实施。
> 优化原则：安全优先，不改变 API 行为，不确定的优化跳过。

---

## 一、基准性能数据

### 测试环境
- Python 3.12，单线程基准（`time.perf_counter()` 微基准）
- 模拟混合查询：缓存命中 / 规则匹配 / DNS 编解码 / 遥测
- 预热 2000 次后正式测量 50K–100K 次

### 基准（优化前）

| 指标 | P50 (ms) | P95 (ms) | P99 (ms) | QPS |
|------|----------|----------|----------|-----|
| `answer_fast` (缓存命中快路径) | 0.004 | 0.004 | 0.005 | 261,399 |
| `dnsmsg.parse_message` | 0.009 | 0.009 | 0.016 | 106,600 |
| `dnsmsg.build_query` | 0.002 | 0.002 | 0.003 | 408,342 |
| `dnsmsg.build_response_body` | 0.002 | 0.002 | 0.003 | 482,570 |
| `cache.get` (LRU 命中) | 0.001 | 0.001 | 0.001 | 1,397,654 |
| `match_rule` (精确命中) | ~0.000 | ~0.000 | ~0.000 | 3,568,878 |
| `tel.fast_hit` | 0.001 | 0.001 | 0.001 | 1,601,176 |

### 优化后

| 指标 | P50 (ms) | P95 (ms) | P99 (ms) | QPS | 变化 |
|------|----------|----------|----------|-----|------|
| `answer_fast` (缓存命中快路径) | 0.004 | 0.004 | 0.006 | **270,020** | **+3.3%** |
| `dnsmsg.parse_message` | 0.009 | 0.009 | 0.017 | 108,233 | +1.5% |
| `dnsmsg.build_query` | 0.002 | 0.002 | 0.004 | 402,213 | noise |
| `dnsmsg.build_response_body` | 0.002 | 0.002 | 0.003 | 466,091 | noise |
| `cache.get` (LRU 命中) | 0.001 | 0.001 | 0.001 | 1,397,029 | noise |
| `match_rule` (精确命中) | ~0.000 | ~0.000 | ~0.000 | 3,494,321 | noise |
| `tel.fast_hit` | 0.001 | 0.001 | 0.001 | 1,580,316 | noise |

> 注：单线程微基准中大多数子操作已在亚微秒级，提升幅度在噪声范围内。
> 主要收益集中在 `answer_fast` 快路径（+3.3% QPS），以及多线程生产环境下的
> 锁竞争减少和系统调用消除（基准为单线程，未体现多线程收益）。

---

## 二、热路径分析 (cProfile)

对 `answer_fast` 缓存命中快路径（生产模式，预解析 msg 传入，500K 次调用）：

```
ncalls  tottime  cumtime  function
500K    1.996s   6.198s   answer_fast (自身字节码)
500K    0.591s   0.948s   telemetry.fast_hit (锁+计数器)
500K    0.449s   0.850s   cache.get (分片锁+OrderedDict)
500K    0.385s   0.713s   telemetry.log (锁+dict创建)
500K    0.193s   1.204s   PartitionedCache.get → LRUCache.get
500K    0.183s   0.491s   build_response_header (struct pack/unpack)
500K    0.155s   0.202s   _now_ts (时间格式化)
500K    0.151s   0.199s   type_name (dict lookup)
500K    0.121s   0.160s   _split (分区key路由)
```

**关键发现**：
1. `answer_fast` 自身字节码占 32%——Python 函数调用开销，无法进一步压缩
2. 两次独立的 telemetry 锁获取（`fast_hit` + `log`）——可合并但风险中等
3. `_now_ts()` 调用 `time.localtime()` 系统调用——已优化为缓存
4. `type_name()` 重复计算——parse_message 已计算，直接复用
5. `_ckey()` 调用 `match_rule()`——无 group 规则时可跳过

---

## 三、优化点详情

### 3.1 遥测时间戳缓存 (telemetry.py)

**问题**：`_now_ts()` 每次日志都调用 `time.localtime()`（系统调用），
在高 QPS 下是显著开销。`tel.log()` 在每次缓存命中时都被调用。

**优化**：缓存时间戳字符串，同一秒内复用。仅在秒数变化时重新调用 `localtime()`。

**影响**：消除了每次查询一次的 `time.localtime()` 系统调用。
在单线程基准中收益被缓存检查开销掩盖（0.202s→0.155s），
在多线程生产环境中减少系统调用和锁竞争更明显。

**风险**：极低。时间戳精度到毫秒，同一秒内缓存不影响正确性。

---

### 3.2 缓存 get 移除冗余写入 (cache.py)

**问题**：`LRUCache.get()` 每次命中都执行 `entry["access_at"] = now`，
这是在锁内的 dict 写操作。但 `access_at` 从未被任何逻辑读取——
仅在 put 时写入，serialize 时也不使用（用 `expires_at`）。

**优化**：移除 `entry["access_at"] = now` 写入。

**影响**：每次缓存命中减少一次锁内 dict mutation。
在多线程环境下减少锁持有时间。

**风险**：极低。`access_at` 字段仍在 put 时写入，只是 get 时不再更新。
任何外部代码依赖 get 后 access_at 变化的逻辑均不存在。

---

### 3.3 无 group 规则时跳过 match_rule (resolver.py)

**问题**：`_ckey()` 每次缓存查找都调用 `match_rule(domain)` 来判断分区组
（domestic/global/default）。即使规则缓存命中（O(1) dict 查找），
仍需一次函数调用 + 缓存查找 + 条件判断。

**优化**：在 `_rebuild_rule_index()` 时检测是否存在 `action=="group"` 的规则。
若无，`_ckey()` 直接返回 `("default", d, qtype)`，跳过 `match_rule()`。

**影响**：每次缓存命中/查找节省一次函数调用和多次 dict 操作。
在无分流规则的部署中（大多数场景），这是纯收益。

**风险**：低。规则热重载时 `_rebuild_rule_index()` 自动重新检测标志。
有 group 规则时行为完全不变。

---

### 3.4 build_response_header 避免冗余 unpack (dnsmsg.py)

**问题**：`_response_header_bits()` 用 `struct.unpack(">HHHHHH", query_data[:12])`
解出全部 6 个字段，然后 `build_response_header` 又把 qid pack 回去。
qid 本身就是大端 2 字节，直接截取即可，无需 unpack+repack。

**优化**：`qid_bytes = query_data[0:2]` 直接截取，只 unpack flags（2 字节）。

**影响**：每次缓存命中响应构造减少一次 6 字段 unpack 和一次 6 字段 pack。

**风险**：低。qid 是网络字节序（大端），直接截取等价于 unpack+pack。
已通过功能测试验证 qid 往返正确。

---

### 3.5 build_response_body 使用 bytearray (dnsmsg.py)

**问题**：`build_response_body()` 用 `answer_section = b""` 然后在循环中
`answer_section += ...`，每次 `+=` 创建新的 bytes 对象（不可变）。
多条答案时产生多个中间对象。

**优化**：改用 `bytearray` 累积，最后 `bytes(out)` 一次转换。

**影响**：多条答案的响应体构造减少中间 bytes 分配。
单条答案（常见情况）影响微小，多条答案（DNSSEC/多 A 记录）收益更明显。

**风险**：极低。bytearray += bytes 是原地操作，语义等价。

---

### 3.6 answer_fast 减少重复计算 (resolver.py)

**问题**：
1. `type_name(q["qtype"])` 被重复计算——`parse_message()` 已在 question dict 中
   存了 `qtype_name`，但 `answer_fast` 又调用一次 `type_name()`。
2. `(time.monotonic() - t0) * 1000` 被计算 3 次（fast_hit + log + log）。
3. `self.cfg.get("kernel_direct", True)` 被调用 2 次。

**优化**：
1. 直接使用 `q.get("qtype_name") or dnsmsg.type_name(q["qtype"])`。
2. 计算一次 `lat = (time.monotonic() - t0) * 1000`，后续复用。
3. 缓存 `kd = self.cfg.get("kernel_direct", True) and not stale`。

**影响**：每次缓存命中减少 1 次 dict 查找 + 2 次 time.monotonic() 系统调用
+ 1 次 dict.get()。

**风险**：极低。纯计算优化，不改变逻辑。

---

### 3.7 DoH 请求头常量化 (upstream.py)

**问题**：`_doh_query()` 每次查询创建新的 `headers` dict（3 个键值对）。
`http.client.HTTPConnection.request()` 内部会 copy 这个 dict。

**优化**：提取为模块级常量 `_DOH_HEADERS`，所有 DoH 查询共享。

**影响**：每次 DoH 上游查询减少一次 dict 创建（miss 路径）。

**风险**：低。`http.client.request()` 会 copy headers，不会修改原始 dict。

---

### 3.8 _cached_udp_addrs 返回 frozenset (upstream.py)

**问题**：每次调用返回 `set(hit[0])`，拷贝整个 IP 集合。
调用方仅做成员检查（`src[0] not in expect_ips`），不需要可变集合。

**优化**：内部存 frozenset，直接返回不拷贝。

**影响**：UDP miss 热路径每次上游查询减少一次 set 拷贝。

**风险**：低。调用方不修改返回值（仅做 `in` 检查）。

---

### 3.9 import ipaddress 移至模块级 (resolver.py)

**问题**：`_is_private_ip()` 每次调用都 `import ipaddress`（Python 会查
sys.modules 但仍有字典查找开销）。

**优化**：移至模块顶部 import。

**影响**：每次答案 IP 合法性检查减少一次 import 语句开销。

**风险**：无。

---

### 3.10 build_error_response 使用 bytearray (dnsmsg.py)

**问题**：错误响应构造中 `question += encode_name(name) + ...` 在循环中
创建中间 bytes 对象。

**优化**：改用 bytearray。

**影响**：错误路径（非热路径）微小优化。

**风险**：无。

---

## 四、跳过的优化点（收益小或风险大）

| 优化点 | 跳过原因 |
|--------|----------|
| 合并 `fast_hit` + `log` 为单次锁 | 需重构 Telemetry 接口，风险中等，单线程基准收益不明显 |
| 预过滤 enabled upstreams 列表 | API 可动态启用/禁用上游，需失效逻辑，风险高收益低 |
| `trace` 列表在 silent=True 时跳过 | 影响后台预取路径，非用户热路径；需修改大量 append 点 |
| UDP socket 池复用 | UDP socket 创建/关闭成本可控，池化复杂度高风险大 |
| `__slots__` 优化高频类 | 缓存条目是 dict（API 序列化依赖），改 slots 破坏兼容性 |
| 读写锁替代互斥锁 | Python `threading.RLock` 已够快，`rwlock` 库引入第三方依赖 |
| `TinyLFUCache` 分片锁 | 可选策略（非默认），单锁在单进程内瓶颈不显著 |

---

## 五、内存优化验证

### 有界数据结构审计

| 数据结构 | 上限 | 淘汰策略 | 状态 |
|----------|------|----------|------|
| `events` deque | 500 | deque maxlen | ✅ 有界 |
| `qps_window` deque | 600 | deque maxlen | ✅ 有界 |
| `latency_window` deque | 400 | deque maxlen | ✅ 有界 |
| `history` list | 120 | 超长按切片裁剪 | ✅ 有界 |
| `top_domains` Counter | 2048 | 超限保留 top 50% | ✅ 有界 |
| `top_clients` Counter | 2048 | 超限保留 top 50% | ✅ 有界 |
| `_rule_match_cache` dict | 8192 | 满则整体 clear | ✅ 有界 |
| `_err_log_ts` dict | 8192 | FIFO popitem(last=False) | ✅ 有界 |
| `_ip_speed_cache` dict | 65536 | 超限删最旧 1/4 | ✅ 有界 |
| `_last_speed_test` OrderedDict | 4096 | popitem(last=False) | ✅ 有界 |
| `_prefetch_pending` set | 无硬限 | 预取完成即 discard | ✅ 有界（预取池有界队列） |
| `manual_history` list | 20 | api.py 切片裁剪 | ✅ 有界 |

### 长期运行内存增长测试

模拟 100,000 次 `answer_fast` 缓存命中：

```
初始内存追踪后 → 100K 次后：
  总增长: 1.0 KB（全部为 tracemalloc 自身开销）
  Events deque: 500/500 (有界)
  QPS window: 600/600 (有界)
  Latency window: 400/400 (有界)
  Rule cache: 0 (无新规则匹配)
  Err log: 0 (无错误)
```

**结论**：无内存泄漏。所有长期运行数据结构均有硬上限。
`access_at` 字段从 get 路径移除后，每次命中不再产生新的 dict 写入压力。

---

## 六、修改文件清单

| 文件 | 修改内容 |
|------|----------|
| `ebpdns/telemetry.py` | `_now_ts()` 秒级缓存，消除 `time.localtime()` 系统调用 |
| `ebpdns/cache.py` | `LRUCache.get()` 移除 `access_at` 冗余写入 |
| `ebpdns/resolver.py` | 模块级 `import ipaddress`；`_has_group_rules` 标志跳过 `match_rule`；`answer_fast` 复用 `qtype_name`/缓存延迟/缓存配置查找 |
| `ebpdns/dnsmsg.py` | `build_response_header` 直接截取 qid bytes；`build_response_body` 用 bytearray；`build_error_response` 用 bytearray |
| `ebpdns/upstream.py` | DoH headers 提为模块常量；`_cached_udp_addrs` 返回 frozenset 不拷贝 |

---

## 七、功能验证

- [x] `python3 -c "import ebpdns; print('OK')"` 通过
- [x] DNS 查询构造/解析往返正确（A 记录、NXDOMAIN、错误响应）
- [x] qid 透传正确（build_response_header 优化后）
- [x] 缓存命中快路径返回正确应答
- [x] 规则匹配（精确/通配/白名单）功能不变
- [x] 分区缓存 key 构造正确（有/无 group 规则两种场景）
- [x] 版本号保持 1.9.48
- [x] 未修改任何 API 接口或配置字段
