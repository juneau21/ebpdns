# W-TinyLFU 缓存深度校验与优化报告

> 范围: 仅 `ebpdns/cache.py`。测试脚本位于 `tests_cache/`。
> 工作负载: 20000 keyspace, Zipf(s=0.99) 模拟热点, 200k 查询, warmup 30%。

## 1. 修复 Bug 清单

| # | 文件 | 行号 | 问题 | 修复方式 |
|---|------|------|------|----------|
| 1 | `ebpdns/cache.py` | 170-176 (`LRUCache.restore`) | 硬编码 `if len(k) != 2: continue`, 拒绝 `PartitionedCache.serialize` 产出的 3 元组 `[group, domain, qtype]`。跨策略热切换(partitioned→lru)迁移时全部数据被丢弃。 | 改为: `len(k)==3` 时剥掉 group 前缀还原为 `(domain, qtype)`; `len==2` 保持; 其余跳过。与 `PartitionedCache.restore`(300行)口径一致。 |
| 2 | `ebpdns/cache.py` | 526-543 (`TinyLFUCache._purge_expired_locked`) | 每次每 32 次 put 对 window/probation/protected 三段**全表**做列表推导收集过期项。cap=4096 时 cProfile 实测占 put 累计时间 ~50%(0.327s/0.645s), 锁内阻塞热路径。 | 改为队首分段扫描: OrderedDict LRU 序下过期条目集中队首方向, 扫到首个未过期即停; 空段跳过; 漏扫项由 `get` 的惰性过期清理兜底, 不丢数据。 |

> 注: `resolver.py` 的 `reload()`(1476行)在切 `cache_policy` 时**显式不迁移数据**(直接 new 容器, 代码注释说明冷启动可接受)。按任务约束不改该文件; 本次修复项 1 保证了 cache.py 接口层迁移兼容, 一旦 resolver 侧选择 serialize/restore 迁移即可直接复用。

## 2. 校验项结果

| 校验项 | 结果 | 测试脚本 |
|--------|------|----------|
| 三段式逻辑(容量比例/淘汰链/准入/晋升/降级/满容不缩水) | ✅ 通过 | `test_tinylfu_segments.py` |
| CMSketch(哈希公式/饱和255/老化右移/min估计) | ✅ 通过 | `test_cmsketch.py` |
| 持久化 qtype 保留(回归 v1.9.50) | ✅ 通过 | `test_persistence_qtype.py` |
| 热切换 lru↔tinylfu↔partitioned 数据迁移 | ✅ 通过 | `test_hot_switch.py` |
| 线程安全(16线程×5万 get/put, 无死锁/异常) | ✅ 通过 | `test_thread_safety.py` |

### 关键正确性结论
- **容量比例** (cap=1024): window=16 (1%), main=1008, probation=403 (40% main), protected=605 (60% main), 合计=1024。
- **满容不缩水**: 填满后稳态再写 2000 条, `len` 恒等于 cap, 各段不超容(±1 容差内)。
- **准入**: `candidate.freq >= victim.freq` 才替换; 高频 victim 抗低频 candidate 洪峰。
- **晋升/降级**: probation 命中晋升 protected; protected 满则队首挤回 probation(确定性测试验证)。
- **CMSketch**: inc 后 freq 递增; 饱和封顶 255; `_ops>=65536` 触发全表右移(100→50); freq 为各行最小值(上界)。
- **qtype 回归**: `(domain,"A")` 与 `(domain,"AAAA")` 两条经 serialize→restore 互不混淆, qtype 完整保留。
- **热切换**: lru→tinylfu→partitioned→lru 全链 40/40 条保留; partitioned 分组(domestic/global/default)迁移后仍按组路由。

## 3. 三策略命中率/延迟基准对比

| 容量 | 策略 | 命中率 | p50 get | p99 get | 条目数 | 序列化字节 |
|------|------|--------|---------|---------|--------|------------|
| 1024 | lru | 60.14% | 0.53µs | 0.90µs | 1024 | 64 KB |
| 1024 | partitioned | 53.99% | 0.71µs | 1.15µs | 608 | 39 KB |
| 1024 | **tinylfu** | **64.77%** | 1.49µs | 2.48µs | 1024 | 64 KB |
| 4096 | lru | 77.51% | 0.54µs | 1.00µs | 4096 | 252 KB |
| 4096 | partitioned | 70.95% | 0.72µs | 1.10µs | 2456 | 156 KB |
| 4096 | **tinylfu** | **79.07%** | 1.57µs | 2.94µs | 4096 | 252 KB |

**解读:**
- **TinyLFU 命中率最高**: 1024 档比 LRU +4.6pp, 4096 档 +1.6pp。W-TinyLFU 的 protected 段对长尾热点保持性更强, 代价是单锁 + CMSketch 常数开销(p50 ~3x LRU, 绝对值仍 <1.6µs, 对 DNS 解析可忽略)。
- **Partitioned 命中率偏低**是预期行为: 容量被切到 domestic/global/default 三个池(默认 20/20/60), 本测试负载全部走 default 池(仅 60% 容量), 用命中率换分流隔离, 不是缺陷。
- **内存**: 三策略条目数≈容量; partitioned 因分池实际占用更少。

## 4. 性能优化效果 (cProfile, cap=4096, 50k ops)

| 指标 | 优化前 | 优化后 | 变化 |
|------|--------|--------|------|
| `_purge_expired_locked` 累计耗时 | 0.327s | 0.001s | **~300x** |
| 总 profile 耗时 | 0.645s | 0.305s | **-53%** |
| 函数调用数 | 2.07M | 0.78M | -62% |
| TinyLFU 命中率 | 79.14% | 79.07% | 无回归 |

剩余热点为固有开销: `get` 三段 dict 查询(0.136s)、CMSketch `inc`(0.066s, 每次访问必计频)、`_evict_locked`(0.050s)。`hash(k)` 仅 6.6 万次, 占比小, 未做哈希缓存(避免引入额外 dict 内存与查找开销)。

## 5. 复现方式

```bash
cd ebdns-v1931
python3 tests_cache/test_tinylfu_segments.py
python3 tests_cache/test_cmsketch.py
python3 tests_cache/test_persistence_qtype.py
python3 tests_cache/test_hot_switch.py
python3 tests_cache/test_thread_safety.py
python3 tests_cache/bench_cache.py
python3 -m py_compile ebpdns/cache.py   # 语法检查
```
