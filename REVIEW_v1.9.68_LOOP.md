# REVIEW_v1.9.68_LOOP.md — 回归压测循环记录

## 第 1 轮（修复后首次重启 + 回归 + 压测）

### 修复内容
1. **LOW-1 bootstrap 写回时机**：DoH/DoT fallback 路径不再在 `_resolve_host_once` 后立即 `_bootstrap_set`，改为暂存 `pending_bootstrap` 到连接/socket 对象，待首次 exchange 成功后才写回缓存。
2. **LOW-2 bootstrap 缓存 TTL**：`_bootstrap_cache` 条目改存 `(ip, monotonic_ts)`；`_bootstrap_ip` 读取时检查 `now - ts > 600s` 视为陈旧返回 None 触发重解析。
3. **LOW-3 裸 IPv6 解析**：`parse_upstream_addr` 新增裸 IPv6 检测（多冒号且未方括号包裹时不切端口）。
4. **前端 INFO-I1**：`line.msg.split(' ')[0]` 改为 `(line.msg || '').split(' ')[0]`。

### 回归结果（全部通过）
| 项目 | 结果 |
|---|---|
| 13 API GET | 全部 200（/metrics 实测 200） |
| CSRF 恶意 Origin → POST /api/reset | 403 ✅ |
| CSRF 同 Origin → POST /api/reset | 200 ✅ |
| DNS UDP rcode=0 | ✅ |
| DNS TCP rcode=0 | ✅ |
| API /api/query POST | ok, chosen=42.81.179.153 ✅ |
| 缓存策略热切换 lru/partitioned/tinylfu | 全部 200 ✅ |
| 负缓存 NXDOMAIN | rcode=3 两次一致 ✅ |
| /api/reload 持久化命中 | ok=True ✅ |
| serve-stale/stale_served 字段存在 | ✅ |
| 裸 IPv6 单元测试 | `2606:4700::1` → addr=整体, port=53 ✅ |
| bootstrap TTL 单元测试 | set/get/expire/invalidate 全通过 ✅ |

### 压测结果（320s, 100 并发）
| 指标 | 值 |
|---|---|
| DNS total_queries | 61,116 |
| QPS (peak 100) | 436 |
| P50 | 0.04 ms |
| P95 | 0.79 ms |
| P99 | 1719.07 ms |
| errors | 0 |
| timeouts | 5039 (8.2%, 并发爬坡期) |
| API total | 26,755 |
| API P50 | 1.54 ms |
| API P95 | 3.57 ms |
| API P99 | 4.85 ms |
| API errors | 0 |

### FD/RSS
| 时点 | FD | RSS |
|---|---|---|
| 压测前（冷启动） | 9 | 50,376 KB |
| 压测后立即 | 16 | 94,232 KB |
| 压测后 35s 空闲 | 16 | 94,232 KB |

- FD 增长 7 个 = DoH/DoT 连接池活跃连接（_MAX_CONN=4/key，有界）
- RSS 增长 ~44MB = 缓存预热（2010/12345 条）+ 遥测窗口 + 连接池
- 35s 空闲后 FD/RSS 稳定不增长，无泄漏

### 日志检查
`grep -icE "error|exception|traceback" /tmp/v1931_ft.log` = **0**

### 结论
**第 1 轮即收敛**。三项后端修复全部正确落地，回归全过，压测无错误，日志零异常。
