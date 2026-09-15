# ebpdns v1.9.51 代码审查 + 性能优化 + 内存优化报告

**审查日期**: 2026-09-15  
**审查范围**: 全部 13 个 .py 文件（~6700 行）  
**基线版本**: v1.9.50 → **目标版本**: v1.9.51

---

## 一、语法检查结果

对全部 13 个文件运行 `python3 -m py_compile`，**0 错误**。

| 文件 | 行数 | 编译 |
|------|------|------|
| `__init__.py` | 11 | OK |
| `__main__.py` | 8 | OK |
| `api.py` | 1176 | OK |
| `cache.py` | 596 | OK |
| `cli.py` | 478 | OK |
| `config.py` | 325 | OK |
| `dnsmsg.py` | 448 | OK |
| `probe.py` | 105 | OK |
| `quic_upstream.py` | 388 | OK |
| `resolver.py` | 1892 | OK |
| `server.py` | 342 | OK |
| `telemetry.py` | 254 | OK |
| `upstream.py` | 622 | OK |

---

## 二、v1.9.50 回归检查

### 2.1 DoH3 地址格式修复验证

`config.py` 的 `parse_upstream_addr` 函数对以下前缀的映射全部正确：

| 输入前缀 | 映射 proto | 验证 |
|----------|-----------|------|
| `https://host/path` | `doh` | ✅ |
| `http://host/path` | `doh` | ✅ |
| `doh3://host` | `doh3` | ✅ |
| `http3://host/path` | `doh3` | ✅ |
| `h3://host` | `doh3` | ✅ |
| `doq://host:853` | `doq` | ✅ |
| `tls://` / `dot://` | `dot` | ✅ |
| `udp://host:53` | `udp` | ✅ |

**结论**: v1.9.50 的 DoH3 前缀修复无回归问题。`http3://` 和 `h3://` 均正确映射到 `proto="doh3"`。

### 2.2 配置页四栏布局 / 缓存策略说明

后端配置处理逻辑无对应变更引入的 bug。`DEFAULTS` 字典与 `deep_merge` 逻辑兼容。

---

## 三、逻辑 Bug 修复

### Bug #1: `_err_log_ts` 内存泄漏（严重）

- **文件**: `resolver.py` 第 170 行
- **问题**: `self._err_log_ts = {}` 使用普通 dict，但第 758 行调用 `self._err_log_ts.popitem(last=False)`。Python 普通 dict 不支持 `last` 关键字参数，抛出 `TypeError`。该异常被 `except Exception: pass` 静默吞掉，导致淘汰逻辑完全失效——在长时间故障/压测场景下，错误日志时间戳字典无限增长，造成内存泄漏。
- **修复**: 改为 `OrderedDict()`（第 170 行），使 `popitem(last=False)` 正常工作。`OrderedDict` 已在文件头部导入（第 19 行）。

### Bug #2: 快路径缓存命中不调度预取（功能性）

- **文件**: `resolver.py` `answer_fast()` 方法
- **问题**: `answer_fast()` 是 UDP 主线程的缓存命中快路径，直接构造响应返回，**不经过** `resolve()` 方法。而 `schedule_prefetch()` 仅在 `resolve()` 的缓存命中分支（第 316 行）和缓存回填分支（第 619 行）调用。这意味着占缓存命中绝大多数的 UDP 快路径命中**从不调度预取**，预取机制对热点域名形同虚设。
- **修复**: 在 `answer_fast()` 的 rcode==0 分支（非 stale）末尾，添加 `self.schedule_prefetch(key, domain, qtype_name, ttl_left)` 调用。

### Bug #3: `upstream.py` TCP/DoT 响应累积 O(n²)

- **文件**: `upstream.py` 第 404-409 行（`_dot_query._exchange`）、第 523-528 行（`_tcp_query`）
- **问题**: `buf = b""` 后 `buf += chunk` 在 bytes 对象上反复拼接，每次分配新内存并拷贝。DNS 响应虽小（<64KB），但高并发下累积开销显著。
- **修复**: 改用 `bytearray()` + `buf.extend(chunk)`，解析时 `bytes(buf)` 转换。

### Bug #4: 死代码 `_resolve_host`

- **文件**: `upstream.py` 第 182-193 行
- **问题**: `_resolve_host()` 函数定义后从未被任何代码调用（grep 确认仅定义处出现）。`_cached_udp_addrs()` 和 `bootstrap_resolve()` 已覆盖其功能。
- **修复**: 移除。

### Bug #5: 负缓存写入重复 `time.time()` 调用

- **文件**: `resolver.py` 第 465 行
- **问题**: `"expires_at": time.time() + neg_ttl, "access_at": time.time()` 调用两次 `time.time()`，两次系统调用间存在微小时间差。
- **修复**: 提取为单次 `now_neg = time.time()`。

---

## 四、性能优化

### 4.1 优化总览

| 优化点 | 文件 | 效果 |
|--------|------|------|
| `decode_name` 缓存 `len(data)` | `dnsmsg.py` | 减少 38% 的 `len()` 调用 |
| `_response_header_bits` 用 `int.from_bytes` 替代 `struct.unpack` | `dnsmsg.py` | 27% 提速 |
| 合并 telemetry 双锁为单次 `fast_hit_logged` | `telemetry.py` + `resolver.py` | 锁竞争减半 |
| TCP/DoT 缓冲 `bytearray` 替代 `bytes +=` | `upstream.py` | 消除 O(n²) 拼接 |
| 负缓存单次时间获取 | `resolver.py` | 减少系统调用 |

### 4.2 cProfile 前后对比

测试脚本: `profile_test.py`（模拟混合 DNS 查询负载）

#### 场景 1: `answer_fast` 缓存命中快路径（200,000 次）

| 指标 | 优化前 | 优化后 | 变化 |
|------|--------|--------|------|
| 总耗时 | 6.160s | 4.581s | **-25.6%** |
| 函数调用数 | 14,673,397 | 13,953,385 | -4.9% |
| `parse_message` 累计 | 2.334s | 1.584s | **-32.1%** |
| `decode_name` 累计 | 1.103s | 0.634s | **-42.5%** |
| telemetry 合计 | 0.953s | 0.640s | **-32.8%** |
| `build_response_header` | 0.291s | 0.228s | **-21.6%** |
| `_response_header_bits` | 0.135s | 0.099s | -26.7% |
| `len()` 调用数 | 2,920,358 | 1,800,358 | **-38.3%** |

#### 场景 2: `match_rule` 规则匹配（100,000 次）

| 指标 | 优化前 | 优化后 | 变化 |
|------|--------|--------|------|
| 总耗时 | 0.067s | 0.050s | **-25.4%** |

#### 场景 3: 缓存 get/put 混合（100,000 次）

| 指标 | 优化前 | 优化后 | 变化 |
|------|--------|--------|------|
| 总耗时 | 0.486s | 0.432s | **-11.1%** |

#### 场景 4: `parse_message` 响应解析（100,000 次）

| 指标 | 优化前 | 优化后 | 变化 |
|------|--------|--------|------|
| 总耗时 | 2.409s | 1.622s | **-32.7%** |
| 函数调用数 | 7,200,001 | 5,400,004 | -25.0% |
| `decode_name` 累计 | 1.241s | 0.707s | **-42.2%** |

### 4.3 优化点详细说明

#### 4.3.1 `decode_name` 缓存长度（dnsmsg.py）

**原实现**: 每次循环迭代调用 `len(data)`（Python 内置函数，虽 O(1) 但仍有函数调用开销）。  
**优化**: 在函数入口缓存 `dlen = len(data)`，循环内全部使用 `dlen`。  
**效果**: `len()` 调用从 292 万次降至 180 万次（场景1），`decode_name` 自身耗时降 42%。

#### 4.3.2 `_response_header_bits` 替代 struct.unpack（dnsmsg.py）

**原实现**: `struct.unpack(">H", query_data[2:4])[0]` — 切片 + unpack。  
**优化**: `int.from_bytes(query_data[2:4], "big")` — 直接整数解析。  
**效果**: 该函数耗时降 27%。

#### 4.3.3 合并 telemetry 锁（telemetry.py + resolver.py）

**原实现**: `answer_fast()` 每次缓存命中调用 `fast_hit()`（获取锁）+ `log()`（再次获取锁），两次锁竞争。  
**优化**: 新增 `fast_hit_logged()` 方法，一次加锁完成计数器更新 + 事件追加。  
**效果**: telemetry 相关总耗时从 0.953s 降至 0.640s（-32.8%），20 万次调用节省约 0.31s。

---

## 五、内存优化

### 5.1 修复的内存泄漏

| 问题 | 文件 | 影响 |
|------|------|------|
| `_err_log_ts` dict 淘汰失效 | `resolver.py:170` | 长时间故障/压测下无限增长 |
| `_resolve_host` 死代码 | `upstream.py:182` | 无害但增加代码维护负担 |

### 5.2 已有的内存安全机制（审查确认无需修改）

- **`_ip_speed_cache`**: 上限 65536 条目，超限按时间淘汰最旧 1/4 ✅
- **`_rule_match_cache`**: 上限 8192 条目，满则整体清空 ✅
- **`_last_speed_test`**: OrderedDict 限长 4096 ✅
- **`top_domains`/`top_clients`**: Counter 限长 2048，超限裁剪 ✅
- **`events` deque**: maxlen=500 自动淘汰 ✅
- **`_prefetch_pending`/`_stale_refreshing`**: set 去重，条目过期后自然移除 ✅
- **QUIC `_streams`/`_doq`**: 查询结束即 pop ✅
- **`_ConnPool._MAX_IDLE`**: 30s 空闲连接惰性回收 ✅
- **`history` list**: 限长 120 ✅
- **TCP 缓冲上限**: 1MB 单连接上限 ✅

### 5.3 缓存条目存储审查

缓存条目字段: `domain, qtype, answers, chosen, ttl, rcode, expires_at, access_at, resp_body`。
- `resp_body` 为预编码响应体（约 50-200 字节/条目），在 `serialize()` 时正确移除（`d.pop("resp_body", None)`），不落盘。
- `access_at` 字段在 LRU 淘汰中未被读取（LRU 由 OrderedDict 顺序维护），但保留用于调试/未来扩展。非冗余。
- **无循环引用**: 缓存条目为纯数据 dict，不持有对 Resolver/Cache 的反向引用。

---

## 六、修改文件清单

| 文件 | 修改内容 |
|------|----------|
| `ebpdns/__init__.py` | 版本号 1.9.50 → 1.9.51 |
| `ebpdns/resolver.py` | Bug#1: `_err_log_ts` 改 OrderedDict<br>Bug#2: `answer_fast` 添加 `schedule_prefetch`<br>Bug#5: 负缓存单次 `time.time()`<br>优化: `answer_fast` 改用 `fast_hit_logged` |
| `ebpdns/dnsmsg.py` | 优化: `decode_name` 缓存 `len(data)`<br>优化: `_response_header_bits` 用 `int.from_bytes` |
| `ebpdns/telemetry.py` | 优化: 新增 `fast_hit_logged()` 合并锁方法 |
| `ebpdns/upstream.py` | Bug#3: `_dot_query`/`_tcp_query` 改 bytearray<br>Bug#4: 移除死代码 `_resolve_host` |

---

## 七、向后兼容性确认

- ✅ 配置文件格式未改变
- ✅ 外部 API 接口未改变
- ✅ `parse_upstream_addr` 前缀映射完全向后兼容
- ✅ 缓存条目结构未改变（新增 `fast_hit_logged` 为 telemetry 内部方法，不影响序列化）
- ✅ `OrderedDict` 替换 plain dict 不影响序列化/反序列化行为
- ✅ `bytearray` 替换 `bytes` 仅为内部实现，对外接口返回 `bytes` 类型不变
- ✅ 所有修改通过 `py_compile` 验证

---

## 八、遗留建议（未修改，供后续版本参考）

1. **`server.py` TCP handler `buf += chunk`**: 仍使用 bytes 拼接，虽然缓冲上限 1MB 限制了影响，但高并发 TCP 场景可改 bytearray。
2. **`TinyLFUCache._purge_expired_locked`**: 全表扫描过期条目，不像 LRU 那样从队首优化。容量大时可考虑分代清理。
3. **`_is_slow_up` 每 miss 调用 telemetry 锁**: 可缓存慢上游决策 5 秒，减少每 miss N 次锁获取。
4. **`cand[v]["from"]` 列表去重**: 使用 `if r["up_name"] not in list` 是 O(n)，可改 set。上游数 <25 时影响可忽略。
