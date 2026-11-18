# ebpdns 2.1.49-p1 源码审查报告（第二轮，含修复与复测）

- 审查对象：`ebpdns-2.1.49` 源码树（8 个 crate，约 10.3 万行 Rust）+ Leptos 前端
- 方法：静态模式扫描（panic/unsafe/锁序/时间/容量）→ 关键路径精读 → 动态验证
  （畸形输入、内存浸泡、微基准）→ **修复 → 复测 → 再审** 闭环
- 结论：本轮 4 项发现**全部修复并复测**，复测未发现新问题。

---

## 一、发现与处置（4 项，全部已修）

### 1（P1）`partitioned::sample_keys` 第二轮回填会重复 —— 已修

**位置**：`crates/ebpdns-cache/src/partitioned.rs`

第一轮按分区配额取不满时进入回填，旧实现用 `if i < q { continue; }` 跳过"第一轮已取过的
前缀"。该假设只在"按迭代序取前 N 个"时成立；2.1.50 改成**等距跨步采样**后步长随请求量
变化，两次采样集合不同 ⇒ 既**漏**也**重**。

**修复**：按 `CacheKey` 去重收集（`HashSet`），回填照常取 `q + need`，重复跳过。
**测试**：`sample_keys_dedups_when_one_partition_is_empty`。

### 2（P3）`/api/rules/import` 对非法 JSON 静默降级 —— 已修

**位置**：`crates/ebpdns-server/src/api.rs`

旧行为：`serde_json::from_str` 失败即按纯文本导入，于是 `Content-Type: application/json`
+ body `not json xyz` → **200 OK**，并写入 `*.not` / `*.json` / `*.xyz` 三条垃圾规则。

**修复**（FIX-IMPORT-JSON）：handler 读 `Content-Type`；当声明 JSON、或 body 以 `{`/`[`
开头时，解析失败一律 **400**，错误信息里提示"纯文本请用 text/plain"。真·纯文本导入
（`text/plain` 或不带 Content-Type）行为不变。

**测试**：`rules_import_invalid_json_is_400`（400 + 规则数不变 + 纯文本路径仍可用）。

### 3（P4）`peek` 的惰性删除清空 stale 池且不入 journal —— 已修

**位置**：`crates/ebpdns-cache/src/{lru.rs,tinylfu.rs}`

上一轮已给 `peek` 加了 `stale_window` 保护（避免清空 serve-stale 池），但
`stale_window <= 0` 时仍会删除，且**不写 journal**（内存与 WAL 分叉，重启回放可能复活）。

**修复**（FIX-PEEK-PURE）：`peek` 改为**纯只读** —— 命中返回条目，过期返回 `None`，
**既不晋升也不删除**。清理职责归写路径：`purge_expired_locked`（每 32 次 put，尊重
`stale_window`）与 `get_arc`（stale 关闭时）。

**测试**：`peek_is_pure_even_without_serve_stale`、`peek_is_pure_and_keeps_expired_entries`，
并同步修正 2 个旧断言（2.1.45 的"peek 必须移除过期项"语义已作废）。

### 4（P4）TopN 修剪持锁 0.7-1.1 ms 的尖刺 —— 已优化

**位置**：`crates/ebpdns-server/src/telemetry.rs`（`trim_low_counts`）

`domain_hits`/`client_hits` 达 2048 时会裁剪到一半。旧实现对 2048 项**全排序**
（O(n log n)），且在**数据面热路径**上持 `Mutex` 执行。

**修复**（FIX-TOPN-TRIM）：只需"前 keep 名"，改用 `select_nth_unstable_by`（O(n) 选择），
取舍语义不变。

**实测（`bench_domain_hits_trim`，release，同机对比）**：

| 指标 | 修复前 | 修复后 | 提升 |
|---|---|---|---|
| 单次裁剪 p50 | 717.85 µs | **244.44 µs** | 2.9× |
| 单次裁剪 p99 | 1131.32 µs | **325.38 µs** | 3.5× |
| 摊还/新域名 p50 | 0.20 µs | 0.20 µs | — |

---

## 二、复测记录（修复后重新跑）

| 项目 | 结果 |
|---|---|
| `cargo clippy --workspace --all-targets -D warnings` | **0 warning**（rc=0） |
| `cargo test -p ebpdns-cache` | **104 passed** |
| `cargo test -p ebpdns-server --lib` | **324 passed** |
| `cargo test --workspace` | **1027 passed / 0 failed**（51 个套件） |
| `/api/rules/import` 非法 JSON | **400** + 规则数不变（修复前 200 + 写入 3 条） |
| `/api/rules/import` 纯文本 / 合法 JSON | 200，仍可正常导入 |
| `/api/snapshot` ×12 | `used` 1196 → **1249（增长）**，不再掉缓存 |
| DNS 畸形包 8 类 | 全部 FORMERR/正常应答，0 挂起 0 panic |
| HTTP 畸形参数 19 项 | **0 个 5xx** |
| 内存浸泡（遥测页轮询 96 s） | RSS **恒定 138.2 MB**（缓存同期 +945 条），无泄漏 |
| 锁序检查 | 未发现反向获取 |

---

## 三、第三轮：并发查询 / IP 测速优选路径审查

针对"DNS 并发查询 + 结果 IP 测速优选"专项审查（详见《并发查询与IP测速优选-实现审查》），
发现并修复 1 个缺陷：

### 5（P3）`chosen` 字段 miss / 命中 语义不一致 —— 已修（FIX-CHOSEN-PARITY）

- miss 路径：`chosen = cand_list.first()`（测速优选后的首个 IP）；
- 命中路径：`chosen = entry.chosen`，而缓存写入时取的是 `answers.iter().rev().find(A/AAAA)`
  ⇒ **最后一个 A**。
- 实测（www.douban.com，3 条 A）：miss chosen=120.53.130.158（=answers[0]），
  hit chosen=81.70.124.99（=answers[-1]）；客户端 `dig` 顺序不受影响。
- 修复：`fill_cache_capped` 改为正序 `find` 首个 A/AAAA（CNAME 链语义不变）。
- 验证：4/4 域名 miss == hit == answers[0]；新增 2 项回归测试。
- 附带验证：40 线程 × 25 查询（1000 次）**全部成功、0 超时、1757 qps、无 panic**；
  混合压测 miss=457 → upstream_requests=1146（≈2.5×，quorum=2 + fallback，符合设计）。

## 四、第四轮：配置与 TTL 对外口径

按"开启全部推荐开关 + 缓存保存 10 天"落配置时发现并修复 1 个缺陷：

### 8（P3）`persist_ttl` 复活的 10 天 TTL 会直接回给客户端 —— 已修（FIX-TTL-ADVERTISE）

- 复现路径：`persist_ttl=864000` → 重启 → 命中复活条目 → 应答 TTL 可达 864000s；
- 客户端会把记录缓存 10 天（比本地还久），且 prefetch 在 10 天内不会触发；
- 修复：对外 TTL 一律封顶 `ttl_max`（快/慢两条命中路径），内部过期时间不变；
- 验证：重启后命中 `www.qq.com`，`ttl_left=600.0`，`dig` 显示 TTL 600；
  新增回归测试 `hit_ttl_is_capped_by_ttl_max`。

## 五、结论

- 四轮审查共发现 **8 个问题**（首轮 2 个 + 第二轮 4 个 + 第三轮 1 个），全部修复并有回归测试覆盖：
  1. `/api/snapshot` 清空 serve-stale 缓存池（P0）；
  2. `sample_keys` 采样偏差（P2）；
  3. `partitioned` 回填重复（P1）；
  4. `/api/rules/import` 非法 JSON 静默降级（P3）；
  5. `peek` 非 journaled 删除（P4）；
  6. TopN 裁剪持锁尖刺（P4）；
  7. `chosen` miss/hit 语义不一致（P3，第三轮）；
  8. 复活条目的 10 天 TTL 直接外泄（P3，第四轮）。
- 复测后未发现新的正确性/安全问题；数据面与控制面的健壮性、内存、锁序均通过。
- 仍属"产品级建议"（非缺陷，未改）：把 `/api/snapshot` 的前端轮询从 1.75 s 放宽到 5-10 s、
  加 ETag；`partitioned` 在单分组流量下容量利用率仅 59%，选型建议见《缓存策略命中率对比》。
