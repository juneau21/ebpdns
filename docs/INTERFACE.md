# ebpdns 2.2.3 Web 控制台（Leptos）页面实现接口约定

本文是**前端与后端的唯一字段契约**，同时是四道机器门禁的输入：

- `scripts/_interface_keys.py`：从本文件的 `STATUS_KEYS` / `COUNTERS_KEYS` / `RULES_KEYS` /
  `METRICS` 标记块、`cache.persist` 字段表、Pipeline 结构、qtype 表解析契约，与**隔离实例**的
  实际响应逐键比对；
- `scripts/_config_keys.py`：解析 `CONFIG_KEYS` 标记块的三个人工声明数字；
- `scripts/_doc_counts.py`：`check_interface()` 断言"声明数字 == 标记块行数 == 字段表行数"，
  并断言 qtype 受理/拒绝名单与 `ebpdns_proto::constants` 逐名一致；
- `scripts/_version_consistency.py`：本文件必须逐字包含"部署约束"与"规则契约"两条措辞。

> **数字口径**：本文件出现的 36（`/api/status` 顶层）/ 38（`counters`）/ 6（`/api/rules` 顶层）/
> 15（`cache.persist`）/ 13（`status.cache`）/ 7（`/api/pipeline`）/ 57（`/metrics` HELP family）/
> 20 / 12（qtype 受理 / 拒绝）全部是**实测值**，由上述门禁
> （2.1.40：`status.counters` 34 → **35**、`/metrics` HELP family 45 → **46**；2.1.41 **键集不变**，
> 只修复 `qps` 恒 0、`upstream_queries` 本地规则直答误计、`/metrics` 的
> `ebpdns_upstream_requests_total_by_id` 样本名/逐上游延迟虚假序列；2.1.42-B：
> `status.counters` 35 → **36**，新增本地规则直答 `rule`（block / forceIp / no-upstream 不再计
> `miss`，改计 `rule`）；**2.1.43-A**：`counters` 36 → **37**（只增 `probe_upstream_queries`）、
> `/metrics` 46 → **47**（只增 `ebpdns_breaker_all_open_total`），`ipv4_fallback` / `rebind_blocked`
> 补齐唯一写点（此前恒 0）；**2.1.49-p5（第二轮审查）**：`status.cache` 8 → **13** 键
> （新增 `hot_replicas`，删除已不存在的 `window`/`probation`/`protected`）、
> `/api/cache/stats` → **27** 键（s3fifo；2.2.0 +8：四类淘汰原因 / ghost_hits / shard_max·min·imbalance）、`/metrics` → **57** family；其余键集不变。）
> 在每次 `check_all` 时重算。任何新增/删除字段都必须同步标记块与声明数字，否则门禁直接红。

---

## 0. 调用约定

| 项 | 约定 |
|---|---|
| Base URL | 来自配置 `api.host` / `api.port`（出厂模板 `0.0.0.0:8353`；模板 `token` 为空，部署后请设置 token 或改回环），**不是固定端口** |
| 鉴权 | 除 `/api/health` 外全部需要 token（`/metrics` 也要）：`Authorization: Bearer <token>` 或 `?token=` |
| 写操作 | `POST`/`PUT`/`DELETE` 还要过 CSRF/同源校验；无 `Origin` 的非浏览器客户端按设计放行 |
| 读操作 | `Host` 必须可信（环回/私网/`.local`）；有 `Origin` 时按同源判定 |
| 响应 | 一律 JSON；错误体 `{"error": "<文案>"}`（409 结构化体例外，见 §5） |
| 缓存头 | 所有错误响应带 `Cache-Control: no-store` 与 CSP/XCTO 等安全头 |

**版本来源**：`/api/status.version` 与 `/api/about` 均取 `env!("CARGO_PKG_VERSION")`，
前端版本串由 `web/build.rs` 注入的 `EBPDNS_VERSION` 提供，二者同源于根 `Cargo.toml`。

---

## 1. 端点总表（21 条路径 / 27 个方法+路径组合）

| # | 路径 | 方法 | 用途 | 鉴权 |
|---:|---|---|---|---|
| 1 | `/api/health` | GET | 存活探针 | 免 |
| 2 | `/api/config` | GET / PUT | 读配置 / 保存配置 | 需 |
| 3 | `/api/query` | POST | 手动解析（带 trace） | 需 |
| 4 | `/api/snapshot` | GET | 遥测快照 | 需 |
| 5 | `/api/upstreams` | GET / POST | 上游列表 / 新增 | 需 |
| 6 | `/api/upstreams/{id}` | PUT / DELETE | 上游更新 / 删除 | 需 |
| 7 | `/api/status` | GET | 主状态 | 需 |
| 8 | `/api/logs` | GET | 事件环增量 | 需 |
| 9 | `/api/pipeline` | GET | 流水线摘要 | 需 |
| 10 | `/metrics` | GET | Prometheus 文本 | 需 |
| 11 | `/api/rules/import` | POST | 规则文本导入 | 需 |
| 12 | `/api/rules/subscribe` | POST / DELETE | 新增订阅 / 删除订阅 | 需 |
| 13 | `/api/rules/subscribe/update` | POST | 立即刷新订阅 | 需 |
| 14 | `/api/reprobe` | POST | 重新探测上游延迟 | 需 |
| 15 | `/api/reload` | POST | 从磁盘重载配置 | 需 |
| 16 | `/api/restart` | POST | 重启进程（需 `confirm`） | 需 |
| 17 | `/api/reset` | POST | 清空缓存/计数 | 需 |
| 18 | `/api/rules` | GET / POST | 规则列表 / 新增 | 需 |
| 19 | `/api/rules/{id}` | PUT / DELETE | 规则更新 / 删除 | 需 |
| 20 | `/api/cache/stats` | GET | 缓存统计 | 需 |
| 21 | `/api/profile` | POST | 能力边界占位 | 需 |

未知 `/api/*` 路径先过守卫 ⇒ 无 token 时回 **401**（不是 404）；带 token 才回 404。

**`/api/history`：无此端点。** 历史曲线只存在于 **`/api/snapshot.history[]`**
（2.1.43-B 据此明确：不存在 `/api/history`；也不存在 `/api/telemetry/history`）。
2.1.41 实测：两者均 **404 + `{"error":"not found"}`**（带 token 时；无 token 先过守卫回 401）。
历史数据的**唯一真实来源**是
`GET /api/snapshot` 的 `history[]`（元素 `{label, label_text, ts, qps, hit_rate, lat}`，
最近 60 点，采样周期 1.5 s）；前端 `web/src` 也只调 `/api/snapshot`（`web/src/api.rs`
的 `snapshot()`），不调用任何 `/api/history*`。未知 `/api/*` 必须保持 404 JSON
（fail-closed，绝不落 SPA 回退）—— 拼错的接口不会静默返回 `index.html`。

---

## 2. `GET /api/health`（3 字段）

| 字段 | 类型 | 含义 |
|---|---|---|
| `status` | string | 固定 `"ok"` |
| `running` | bool | 固定 `true` |
| `uptime_s` | int | 进程运行秒数 |

---

## 3. `GET /api/status`（顶层 36 键）

顶层字段（**2.1.30 实测：36 个键**）。2.1.49 新增 `process`（原 35 个顶层键）。

> 键集由 `scripts/_interface_keys.py` 与隔离实例实际响应逐键比对；本文按字母序维护。

<!-- STATUS_KEYS_BEGIN -->
app
avg_latency_ms
cache
cache_file
cache_policy
config_path
config_ranges
counters
counters_monotonic_ms
endpoints
errors
health_check_interval
hit
hit_rate
map
miss
process
qps
rule_hits
rule_sub_interval
rules_gen
running
snapshot_epoch_ms
snapshot_monotonic_ms
snapshot_seq
snapshot_uptime_s
state_persist
status
top_clients
top_domains
top_upstreams
total
udp_dropped
uptime
uptime_s
version
<!-- STATUS_KEYS_END -->

| 字段 | 类型 | 含义 / 边界 |
|---|---|---|
| `app` | string | 固定 `"ebpdns"` |
| `status` / `running` | string / bool | 固定 `"running"` / `true` |
| `version` | string | 二进制版本（`CARGO_PKG_VERSION`） |
| `uptime_s` / `uptime` | int | 运行秒数（两键同值，历史兼容） |
| `config_path` | string \| null | 生效配置文件路径 |
| `cache_file` | string \| null | 缓存落盘路径 |
| `cache_policy` | string | 生效策略，**2.2.0 起恒为 `s3fifo`**（`lru`/`tinylfu`/`partitioned` 已移除：启动/`PUT` 均拒绝，不再回退） |
| `total` / `hit` / `miss` / `errors` | int | 数据面计数；`total` = Σ `client_rcode`（含策略应答与规则直答），<!-- >>> 242B BEGIN P1-6-doc-eq2 >>> -->
`hit`/`miss` 只含缓存/上游决策。**2.1.42-B 起口径**：`total == hit + miss + policy_filtered_total + rule`，其中 `rule` = block/forceIp/no-upstream 的本地规则直答数；`rule_hits` 是**正交维度**（block / allow / group / forceIp 都计数），只有 allow/group 会真正发上游，**不得**把 `sum(rule_hits)` 再加进上面的等式（会双计） |
<!-- <<< 242B END P1-6-doc-eq2 <<< -->
| `hit_rate` | float | **2.1.40 起** `hit / (hit + miss) × 100`（0..100，保留 1 位）；分母**只含真正的缓存/上游决策**，本地策略应答（AAAA 屏蔽 / IPv6 关闭）不计入。读法见 **§3.0** |
| `qps` | float | 最近 1 秒滑动窗口 QPS（数据面客户端查询；**2.1.41 起**由出口 `note_client_query` 每查询**恰好推进一次**，与 `total` / `neg_telemetry` 解耦；策略/规则/畸形包应答也计入，控制面 `/api/query` 不计；**2.1.49-p2 起不再被旧 deque 的 600 上限截断**） |
| `avg_latency_ms` | float \| null | **只数据面**（2.1.43-A 统一）：最近 **400 条**数据面应答（级别 hit/miss/err/warn，唯一写点 `dns.rs::log_and_count`）的算术平均。**不含**控制面 `POST /api/query`（其延迟只在 `manual_history[].latency_ms` / `/api/query` 响应里），也不含纯规则直答（未实测耗时）；无样本 ⇒ `null`。与 `/metrics` 的 `ebpdns_query_latency_ms` 是**同一窗口** |
| `cache` | object | 缓存摘要（27 键，见 §3.1） |
| `map` | object | `cache` 的三键兼容副本：`used`/`capacity`/`pct` |
<!-- >>> 242B BEGIN P1-6-doc-row >>> -->
| `counters` | object | 同代计数器表，**43 个键**（见 §3.2；2.1.40 新增 `policy_filtered_total`；2.1.42-B 新增 `rule`；2.2.5 新增 `negative_mixed_degraded`；2.2.6 把 `probe_upstream_ok`/`probe_upstream_fail` 拆成**传输层** `probe_transport_ok`/`probe_transport_fail` 与**验证层** `probe_valid_ok`/`probe_valid_fail` 两本账） |
<!-- <<< 242B END P1-6-doc-row <<< -->
| `counters_monotonic_ms` / `snapshot_monotonic_ms` | int | 同一次取数的单调时钟（ms） |
| `snapshot_epoch_ms` / `snapshot_uptime_s` | int | 同一取数时刻的 epoch ms / 运行秒 |
| `snapshot_seq` | int | 同代计数器快照的**写入代数**（每次计数写入 +1；**读取不推进** —— 两次连续抓取之间无写入时必须相等，有写入则严格变大） |
| `endpoints` | array | 已绑定 DNS 端点，元素 `[proto, "ip:port"]` |
| `config_ranges` | array | 整数键权威区间，元素 `{key,min,max}` |
| `rule_hits` | object | 规则命中一维聚合（可空对象） |
| `rules_gen` | int(u64) | 规则索引指纹（内容 + 顺序敏感） |
| `rule_sub_interval` / `health_check_interval` | int | 配置回显（秒） |
| `top_clients` / `top_domains` / `top_upstreams` | array | Top N，元素 `[name, count]` |
| `process` | object | **2.1.49（AUD-09）**：进程自观测（5 键；与 `/metrics` 同源）：`resident_memory_bytes`（VmRSS，字节）、`virtual_memory_bytes`（VmSize，字节）、`threads`（OS 线程数）、`open_fds`（`/proc/self/fd` 条目数）、`state_missing_parts`（`state_persist.missing_parts` 的条数）。非 Linux / 读取失败时为 0；前端以字段**缺失**（旧后端）显示“不可用”，不把 0 当缺失。 |
| `udp_dropped` | int | UDP 收包闸门丢包。**2.1.43-A 起与 `counters.udp_dropped` 是同一个原子**（`ServerTelemetry::udp_dropped_handle()`，`DnsServer`/`AppState`/遥测三方共享），因此两处**恒等**（单测用 `Arc::ptr_eq` + 端点相等双重钉死） |
| `state_persist` | object | 统一事务现场（18 键，见 §3.4） |

### 3.0 命中率（`hit_rate`）口径：**按"真正的缓存/上游决策"计**（2.1.40 起）

`hit` / `miss` 是**数据面出口**的分类计数（`crates/ebpdns-server/src/dns.rs` 的
`log_and_count`）：`hit` 只代表"由用户态缓存直答"（`answer_fast`），`miss` 只代表
"真的走到了缓存未命中 / 上游解析"。

**2.1.40 起，本地策略短路单独成类**：`prefer_ipv4=true` 且域名有 A 时的 AAAA 屏蔽、
`ipv6=false` 时的 AAAA 恒 NODATA，都发生在缓存键构造之前（`resolve.rs:405`）——
**既没查缓存、也没发上游**。`resolve.rs` 现在给它们显式 `reason="policy_filtered"`，
数据面据此归到 `AnswerSource::PolicyFiltered`：

- **不计** `hit` / `miss` / `upstream_queries` / `errors`；
- 只自增 `counters.policy_filtered_total`（`/metrics` 同名 `ebpdns_policy_filtered_total`）；
- `/api/logs` 事件落 `level="policy"`（**不再冒充 `miss`**），`msg="本地策略应答(未发上游)"`，
  `upstream` 列仍是 `本地判定（prefer_ipv4 屏蔽 AAAA）` / `本地判定（IPv6 已关闭）`。

| 配置 | 代码路径 | AAAA 行为 | 入缓存 | 2.1.39 计数（缺陷） | **2.1.40 计数（修复）** |
|---|---|---|---|---|---|
| `ipv6=false` | `ebpdns-resolver/src/resolve.rs:362-377` | 恒回 NOERROR/NODATA（空） | 否 | `miss` + `Upstream` | **`policy_filtered_total`** |
| `prefer_ipv4=true` 且该域名有 A | `resolve.rs:380-399`（探测 `:383`） | 回 NOERROR/NODATA（"AAAA 屏蔽"） | 否 | `miss` + `Upstream` | **`policy_filtered_total`** |
| AAAA 真正到达缓存 | `resolve.rs:405` 之后 | 正常应答 | 是 | `hit` / `miss` | `hit` / `miss`（不变） |

**指标口径（2.1.40 起，单测钉死）**：

```text
total     = Σ client_rcode          # 全部数据面应答（含策略应答与 Rule 本地判定）
hit_rate  = hit / (hit + miss)      # 分母只含"真正的缓存/上游决策"
total     = hit + miss + policy_filtered_total + (Rule 本地判定数)
```

`hit + miss == 0`（纯策略 / 控制面流量）⇒ `hit_rate = 0.0`（不产生 NaN）。
**2.1.39 及以前**是 `hit_rate = hit / total`，策略应答被算进分母：生产实测
`miss/total = 19.75% ≈ AAAA 占比 19.95%`，而 `counters.upstream_requests` 只有 `miss`
的 **16%**（84% 的 miss 从未发出上游包）；2.1.39 压缩协议里 AAAA 表面命中率 7.6%
（清洁缓存下 0%）就是这么被"摊薄"出来的，**不代表 AAAA 缓存失效**。

`reason` / `level` 取值表（与本节同源）：

| 字段 | 取值 | 含义 |
|---|---|---|
| `POST /api/query` 响应的 `reason` | `null` | 正常解析（命中缓存或上游成功） |
| | `policy_filtered` | **2.1.40 新增**：本地策略短路（AAAA 屏蔽 / IPv6 关闭） |
| | `no-upstream` | 规则/配置导致没有可发的上游 |
| | 其它字符串 | 上游错误原因（`no-answer` / `timeout` / `wire-parse-failed` …） |
| `/api/logs` 事件的 `level` | `hit` | 缓存直答 |
| | `miss` | 真上游解析（含 NXDOMAIN/NODATA） |
| | `policy` | **2.1.40 新增**：本地策略应答（未查缓存、未发上游） |
| | `rule` | 规则判定（未发上游） |
| | `err` | 解析失败 |
| | `warn` | 运行告警（如代理/探测等系统事件） |
| | `sys` | 系统性事件（无域名） |

2.1.39 隔离实例实测（**历史基线**，每轮 2000 次、同一批域名；fake upstream 注入已知 A/AAAA，
TTL 300；私网 `state_dir`，DNS `127.0.0.1:18913` / API `127.0.0.1:19913`）：

| 场景 | A 次轮命中 | AAAA 次轮命中 | AAAA 首轮上游包 | 缓存条目 |
|---|---|---|---|---|
| 双栈域名（先 A 后 AAAA），`prefer_ipv4=true`（出厂默认，生产同型） | 100% | **0%** | 0 | 无 AAAA |
| 同上，`prefer_ipv4=false` | 100% | **100%** | 2000 | 有 AAAA |
| 纯 v6 域名（上游无 A），`prefer_ipv4=true` | — | **100%** | 2000（+2000 A 探测） | 有 AAAA |
| 上游 A/AAAA 皆无（负缓存），`prefer_ipv4=true` | — | **100%**（`negative_hits` +2000） | — | 有负条目 |
| `ipv6=false` | 100% | **0%**（全部本地 NODATA） | 0 | 无 AAAA |

生产 2.1.39 的同型佐证（**修复前**）：`/api/logs` 500 条事件中 A 命中 386 条，AAAA
**全部** `level=miss` 且 `upstream="本地判定（prefer_ipv4 屏蔽 AAAA）"`（114 条）；
`/api/snapshot.qtype_dist` 的 A:AAAA ≈ 80:20，而 `miss/total = 19.75%` ≈ AAAA 占比，
`counters.upstream_requests` 只有 `miss` 的 16% —— 即绝大多数 `miss` 从未发出上游包。

**2.1.40 修复后（同口径实测，见交付报告 §4）**：`prefer_ipv4=true` 下 2000 次 AAAA
只让 `policy_filtered_total` +2000，`miss` 增量 **0**、`hit` 增量 0、`upstream_queries`
增量 0，`hit_rate` 与修复前同负载的 A 命中率一致（不再被 AAAA 摊薄）。

**按 qtype 读命中率的做法（仍然推荐，用于交叉核对）**：

1. 分母用 `/api/snapshot.qtype_dist`（`A`/`AAAA`/`other` 查询占比）；
2. 逐类型命中用 `/api/logs` 的 `level` + `upstream` 标签区分（2.1.40 起策略应答是
   `level="policy"`，`upstream` 为 `本地判定（prefer_ipv4 屏蔽 AAAA）` 或
   `本地判定（IPv6 已关闭）`）；
3. 交叉核对 `counters.policy_filtered_total` 与 `counters.upstream_requests` 增量：
   策略应答**不产生上游包**；2.1.40 起 `miss` 里不再混入策略应答，若仍出现
   "`miss` 增量 ≫ `upstream_requests` 增量"，说明存在**另一条**未归类路径（应报缺陷）。

> 若确实希望 AAAA 走缓存（上游有 AAAA 且需要缓存收益），把 `prefer_ipv4` 设为
> `false`；实测该配置下双栈域名 AAAA 次轮命中率为 100%。「AAAA 缓存是否失效」与
> `hit_rate` 高低**解耦**：2.1.40 起策略应答不再进入命中率分母。


### 3.1 `status.cache`（**27 键**；= `summary()` + `persist` + `restore_drops`）

| 字段 | 类型 | 含义 |
|---|---|---|
| `used` | int | 当前内存条目数（**含**已过期但未被惰性清理的条目） |
| `segment_s` / `segment_m` / `segment_g` | int | **S3-FIFO**：S/M/G 三段队列长度（2.2.0 唯一策略） |
| `used_bytes` / `bytes_cap` / `max_entry_bytes` / `rejected_large` | int | **s3fifo**：字节预算用量/上限、单条上限、超大条目拒绝数 |
| `capacity` | int | 容量上限（= `cache_size`） |
| `pct` | float | `used / capacity × 100` |
| `policy_keys` | int | **s3fifo**：策略层跟踪的键数（正常恒等于 `used`；不等即 inner→policy 漂移） |
| `evict_expired` / `purge_expired` / `evict_capacity` / `evict_negative` / `evict_bytes` | int | **s3fifo**：淘汰原因计数；`purge_expired` = 写路径轮转 TTL purge（见 §4.4 口径） |
| `removed_delete` / `removed_delete_bytes` / `removed_clear` / `removed_clear_bytes` | int | **s3fifo**：显式删除/清空移除的条目数与字节数 |
| `ghost_hits` | int | **s3fifo**：ghost 队列命中数 |
| `shard_max` / `shard_min` / `shard_imbalance` | int/float | **s3fifo**：分片条目数的最大/最小/均衡度 `(max-min)/avg` |
| `hot_replicas` | int | **仅 `s3fifo`**：内部只读热点副本当前条目数（命中加速层，best-effort，上限 = 容量/64 钳制到 [64,4096]）。**不是可配置的 "hot top-K" 策略**：无配置键、不参与淘汰决策 |
| `persist` | object | 落盘现场（15 键，见 §3.3） |
| `restore_drops` | object | 本次启动恢复的计数（5 键：`expired`/`legacy`/`failed`/`window_unpersisted`/`note`） |

> **2.2.0（S3-FIFO 唯一策略）**：`window` / `probation` / `protected` 三个 tinylfu 时代
> 兼容键**不再下发**；`status.cache` 恒为 **27 键**（无 `lru` 变体）。
> `restore_drops.window_unpersisted` 仍存在但恒 0（仅为不改响应形状）。
>
> **2.2.5（P2-A9）口径确认**：`/api/status.cache` 与 `/api/cache/stats` **共用同一份
> `summary()`**（`s3fifo::summary()` 内含 `policy_stats()`），因此也带 `purge_expired`
> —— 这与既有 `evict_*` 模式一致，不是"多出来的键"。两处一致性是**构造性**的：
> `cache.stats` = `status.cache` 的 27 键 **+ 8 个只读展示键**（`size`/`partitions`/
> `policy`/`policy_doc`/`rrset_interned`/`rrset_hits`/`rrset_str_interned`/
> `rrset_str_hits`）= **35 键**；`status.cache` 的每个键在 `cache.stats` 中**同源同值**。

<!-- >>> 242B BEGIN P1-6-doc-h2 >>> -->
### 3.2 `status.counters`（41 键）
<!-- <<< 242B END P1-6-doc-h2 <<< -->

<!-- COUNTERS_KEYS_BEGIN -->
breaker_all_open
bytes_in
bytes_out
cache_direct
cache_skipped_private_total
client_rcode
control_hits
control_queries
errors
hit
ipv4_fallback
miss
negative_hits
negative_single_vote_accepted
negative_mixed_degraded
no_response_total
passthrough_qtype_total
policy_filtered_total
prefetch_all_open
prefetch_degraded_total
probe_upstream_queries
probe_transport_ok
probe_transport_fail
probe_valid_ok
probe_valid_fail
rebind_blocked
rfc8020_hits
rfc8020_len
rfc8020_registrations
rule
servfail_reasons
servfail_total
stale_gen_dropped
stale_served
total
udp_dropped
upstream_dispatch
upstream_early_return
upstream_hedge
upstream_inflight_queued_gave_up
upstream_queries
upstream_requests
upstream_wire_requests
<!-- COUNTERS_KEYS_END -->

| 字段 | 类型 | 口径 |
|---|---|---|
<!-- >>> 242B BEGIN P1-6-doc-eq >>> -->
| `total` | int | 数据面应答总数（控制面 `/api/query` 不计；= Σ `client_rcode`，含策略应答）；`total == hit + miss + policy_filtered_total + rule`（2.1.42-B 起；`rule` = 本地规则直答数） |
<!-- <<< 242B END P1-6-doc-eq <<< -->
| `hit` / `miss` | int | 数据面缓存直答 / 真未命中（2.1.40 起**不含**本地策略应答） |
| `policy_filtered_total` | int | **2.1.40**：本地策略短路次数（AAAA 屏蔽 / IPv6 关闭）；不计 hit/miss/upstream |
<!-- >>> 242B BEGIN P1-6-doc-rulerow >>> -->
| `rule` | int | **2.1.42-B**：本地规则直答次数（block / forceIp / no-upstream 本地判定）；不计 hit/miss/upstream/errors，恢复 `total == hit + miss + policy_filtered_total + rule` |
<!-- <<< 242B END P1-6-doc-rulerow <<< -->
| `cache_direct` | int | 用户态缓存直答数；恒等于 `hit` |
| `errors` | int | 数据面错误数（含 SERVFAIL 与编码失败） |
| `client_rcode` | object | 16 个键 `"0".."15"` 的 rcode 分布；`Σ == total` |
| `servfail_total` | int | 回给客户端的 SERVFAIL 数；`== client_rcode["2"]` |
| `servfail_reasons` | object | 5 键归因：`encode_failed`/`no_upstream`/`panic`/`upstream_no_answer`/`upstream_timeout`；`Σ == servfail_total` |
| `upstream_requests` | int | **物理**上游请求数（含预热/探针/预取/控制面） |
| `upstream_queries` | int | 数据面**真正把包发往上游**的查询数（**2.1.41 起**排除 block/forceIp 等本地规则直答；这些仍计 `miss` 但不发上游）。恒 `<= upstream_requests`（后者含预取/重试/健康探测等物理请求）。**2.1.43-A 起**不含 `prefer_ipv4` 双栈探测（探针不是客户端查询，见下一行） |
| `probe_upstream_queries` | int | **2.1.43-A 新增（只追加）/ 2.2.4 接线 / 2.2.5（P2-A8）口径改为「完成数」/ 2.2.6（P2-A9）拆两本账**：后台探针**完成后**的查询次数（成功 + 失败，**不再计「派发尝试」**）。写点两处：① `prefer_ipv4` 双栈探测（`resolve.rs::probe_a_record`，`query_parallel` 返回后 +1）；② **健康探针**（`background.rs::health_check_once_limited`，`rt.query` 返回后 +1）。硬等式：`probe_upstream_queries == probe_transport_ok + probe_transport_fail` 且 `probe_transport_ok == probe_valid_ok + probe_valid_fail`。与 `upstream_queries` **互不重叠**（探针不是客户端查询）。**不含** IP 测速探测：它直接向"候选答案 IP"发 UDP/TCP 探测，目标不是配置上游（口径不同，避免污染"上游"维度） |
| `probe_transport_ok` | int | **2.2.6（P2-A9，改名自 `probe_upstream_ok`）**：探针**传输层成功** = 收到合法 DNS 响应（健康探针 `QueryOutcome.ok`；双栈探测=至少一个上游回了带 rcode 的应答，**SERVFAIL/NXDOMAIN/截断也算传输成功**）。传输成功但业务不可用的次数由验证层另计 |
| `probe_transport_fail` | int | **2.2.6（P2-A9，改名自 `probe_upstream_fail`）**：探针**传输层失败**（超时/连接失败/无响应）。`probe_transport_ok + probe_transport_fail == probe_upstream_queries` |
| `probe_valid_ok` | int | **2.2.6（P2-A9）新增**：探针**验证层成功** = 传输成功后响应为 **NOERROR + ANCOUNT>0**（健康探针按报文头；双栈探测=未截断非空 A 答案）。这是"上游真的能答"的口径，与 `dns_ok/dns_fail` 的 rcode 账分开 |
| `probe_valid_fail` | int | **2.2.6（P2-A9）新增**：探针**验证层失败** = 传输成功但 SERVFAIL/NXDOMAIN/NODATA/截断。`probe_valid_ok + probe_valid_fail == probe_transport_ok` |
| `upstream_dispatch` | int | 扇出调度次数（含对冲/重试） |
| `upstream_wire_requests` | int | 实际上线的上游报文数（含 DoH h2/h1 连接复用后的每请求） |
| `upstream_early_return` | int | 首个有效应答提前返回次数 |
| `upstream_hedge` | int | 对冲请求次数 |
| `upstream_inflight_queued_gave_up` | int | 在途闸门排队超时放弃次数 |
| `negative_hits` | int | 缓存直答中的负应答条数 |
| `negative_single_vote_accepted` | int | 负结论仅 1 张有效票即被采纳的次数 |
| `negative_mixed_degraded` | int | **2.2.5（P2-A2）新增**：**混合负票降级**次数 —— 所有有效票都是负票、票源数已达 `nxdomain_quorum`，但 NXDOMAIN/NODATA 各占一部分（任一种都未单独达标）时，按"可得票数"降级为较弱结论 **NODATA** 的次数。典型场景：仅 2 个上游且 q=2，对端一个 NXDOMAIN、一个 NODATA。降级**不登记 RFC 8020**（避免把存在性分歧固化成子树否定）；票源不足（< q）时**不降级**，仍 fail-closed SERVFAIL |
| `no_response_total` | int | 进入出口却无可发送应答的条数（解释 `total` 与 rcode 分布之差）。**唯一写点** = `telemetry.rs::note_data_plane_outcome` 的 `rcode=None` 分支。**正常为 0 的业务语义**：只有畸形包 / 空 question / 组包失败（`resp.len() < 12`）时 +1；恒等式 `#(出口登记) == total + no_response_total` |
| `passthrough_qtype_total` | int | 未知类型透传次数 |
| `stale_served` | int | serve-stale 实际回给客户端的次数 |
| `stale_gen_dropped` | int | **规则代际丢弃**：上游/预取结果准备写回缓存时，入队时的 `rule_gen` 与当前不一致（期间规则被重建）⇒ 结果被丢弃的条数。唯一写点 = 解析器的写回代际门禁（2.1.45 P1-3/P1-4）。正常为 0，规则频繁热更新时增长 |
| `rfc8020_hits` / `rfc8020_registrations` / `rfc8020_len` | int | RFC8020 命中 / 登记 / 当前登记深度 |
| `cache_skipped_private_total` | int | 数据面被重绑定防护丢弃的私有地址答案条数 |
| `rebind_blocked` | int | **控制面**拦截的 DNS-rebinding 写请求数（数据面恒 0）。**唯一写点** = `api.rs::guard` 的 **CSRF 失败分支**：写请求先被 CSRF/同源判据拒绝、**且** `Host` 头不可信（判据 `security::host_untrusted`，与 `csrf_ok`/`origin_ok` 的 host 维度同源）时才 +1。**2.1.49-p5 澄清**：凭有效 token 且无 `Origin` 的写请求会通过 CSRF，紧随其后的读路径 `origin_ok` 仍以 403 `origin check failed` 拒绝不可信 `Host`，但**那条路径不计本计数** —— 本字段的口径是"CSRF 分支拦截的 rebinding 形态"，不是"所有 Host 不可信的 403"。**正常为 0 的业务语义**：浏览器/脚本用合法 `Host` 时永不触发；2.1.42 及以前**没有任何写点**（恒 0，属不可观测而非业务罕见），2.1.43-A 补齐 |
| `control_queries` / `control_hits` | int | `POST /api/query` 次数 / 其中缓存直答次数 |
| `udp_dropped` | int | UDP 收包闸门丢包数。**唯一写点** = `dns.rs::udp_loop` 的 `try_acquire_owned` 失败分支（`drop_cnt.fetch_add`），而 `drop_cnt` **就是** `ServerTelemetry` 的那个原子（2.1.43-A 起共享 `Arc`）⇒ 与 `/api/status.udp_dropped`、`/api/snapshot.counters.udp_dropped`、`/metrics` 的 `ebpdns_udp_dropped_total` 同源同值 |
| `bytes_in` / `bytes_out` | int | 数据面字节数 |
| `breaker_all_open` | int | **累计 counter（2.1.43-A 起口径统一为 `u64` 只增）**：因"**全部**启用上游的熔断器都打开"而兜底放行的次数。**不是** 0/1 瞬时状态（旧文档把它与 `prefetch_all_open` 并列写成 `bool`，与实现矛盾）—— 瞬时状态看 `prefetch_all_open`；`/metrics` 同步为 `ebpdns_breaker_all_open_total`（`# TYPE counter`） |
| `prefetch_all_open` | bool | 瞬时 gauge（0/1）：预取时"全部上游熔断打开"；与 `prefetch_degraded_total`（累计**进入**次数）配成"状态 + 累计" |
| `prefetch_degraded_total` | int | 累计进入"全部熔断"降级状态的次数 |
| `ipv4_fallback` | int | 双栈回退到 IPv4 的次数。**唯一写点** = `resolve.rs::ipv4_fallback` 的**预热成功**分支（真的发了上游 A 查询、拿到答案并回填缓存）。**正常为 0 的业务语义**：只有 `ipv4_first=true` 且 AAAA 上游 NODATA quorum 之后才会走该分支（未开该开关恒 0；命中 A 缓存 / 上游无 A / 私网答案被过滤都不计）。2.1.42 及以前**没有任何写点**（恒 0），2.1.43-A 补齐 |

### `/api/status.cache.persist` 字段字典（**2.1.30 共 15 键**）

> 与 `/api/cache/stats.persist` **逐字段相同**（同一实现 `cache_persist_info`，有单测钉死）。
> v2 下 `bytes` = **当前快照字节数**，不是 `stat(cache_file).len()`（manifest 只有几百字节）。

| 字段 | 类型 | 含义 | 空态/边界 |
|---|---|---|---|
| `enabled` | bool | 配置 `cache_persist` 总开关 | `false` ⇒ 不读不写 |
| `interval_s` | int | 配置 `cache_save_interval` | `0` ⇒ 不写 WAL，只在优雅退出落盘 |
| `file` | string | 实际落盘路径 | 缺键 ⇒ `./ebpdns-cache.json` |
| `exists` | bool | 文件是否存在 | `false` ⇒ 后三键为 0 |
| `bytes` | int | v2 = 快照字节数；v1 = 文件字节数 | `exists=false` ⇒ 0 |
| `mtime_s` | int | v2 = manifest `committed_ms` 的秒值；v1 = 文件 mtime | 取不到 ⇒ 0 |
| `age_s` | int | `now − mtime_s`，只增不减 | `> 2 × interval_s` ⇒ `note` 提示超期 |
| `entries` | int | **当前内存**条目数（= `cache.used`，含未清理过期项） | 不是快照条数 |
| `note` | string | 可读提示（空态/超期/单次落盘） | 正常新鲜时为空串 |
| `format` | string | `"v1"` / `"v2"` / `"unknown"` | 未开启/未来版本 ⇒ `unknown` |
| `snap_seq` | int | v2 当前快照 seq 水位；v1 恒 0 | — |
| `wal_bytes` | int | v2 当前 WAL 占用；v1 恒 0 | 与磁盘短暂不一致正常 |
| `restore_source` | string | 本次启动实际恢复路径：`none`/`v1-json`/`v1-bak`/`migrated`/`v2-snapshot`/`v2-snapshot+wal`/`wal-truncated`/`corrupt`/`unsupported` | 不残留上次 |
| `used_live` | int | **最近一次快照写入时**的未过期条目数（用于恢复丢失率：`(快照 entries − 恢复后 used_live) / 快照 entries`）；**2.1.43-B 起**恢复后该值 = **实际插入缓存的条数**（当前策略在恢复时按容量/负缓存配额逐出的差额已包含在内；兼容字段 `restore_drops.window_unpersisted` 恒 0）；不是"当前内存未过期条目数"（当前值看 `cache.used`） | 与 `entries` 不同口径，不可互替 |
| `snapshot_age_s` | int | 当前快照年龄（秒）= `now − 快照 mtime`；v1/取不到 ⇒ 0 | 节拍 `min(1800 s, TTL/2)`；长期 ≥ TTL ⇒ 告警 |

**配置页两种空态文案**（纯函数 `fmtnum::persist_rows` 生成）：

- `enabled=false` ⇒「未开启持久化」+ 路径；
- `enabled=true, exists=false` ⇒「未落盘（缓存文件不存在）」+ 路径 + 周期；
- `exists=true` ⇒ 路径 / 最近落盘 / 内存条目 / 文件大小 / 周期。

**恢复丢失率（唯一口径）**：

```text
loss = (快照头记录的 snap_entries − 恢复后 used_live) / 快照头记录的 snap_entries
```

**2.1.43-B（P2-4）**：`used_live` = **恢复后实际插入缓存**的条数（不是恢复计划的条数）。
差额来自当前策略在恢复时按容量/负缓存配额逐出，因此上式的 `loss` **已经包含**它。

**2.2.0（S3-FIFO 唯一策略）**：`tinylfu` 时代已结束；`s3fifo` 是唯一实现。
`restore_drops.window_unpersisted` 是 tinylfu 时代的兼容字段，**恒 0**；保留只为不改已发布响应形状。

`restore_drops` 的 `expired`/`legacy`/`failed`/`window_unpersisted` 只数记录条数，
不是字节数。v2 快照只写未过期条目 ⇒ 正常恢复 `expired` 通常为 0；`legacy` 在 v2 下恒 0；
WAL 尾部截断记在日志 `tail_records`，不混入 `failed`。

### 3.4 `status.state_persist`（18 键）

| 字段 | 类型 | 含义 |
|---|---|---|
| `enabled` | bool | 配置 `state_persist`（进程级启动参数） |
| `state_dir` | string | 生效目录：`--state-dir` > 配置 > `EBPDNS_STATE_DIR` > 默认 |
| `revision` | int \| null | 磁盘提交点世代；无 `commit.json` ⇒ `null` |
| `serving_revision` | int \| null | 读方实际服务世代；`RolledBack` 时与 `revision` 不同；`Torn`/`Legacy` ⇒ `null` |
| `broken_revision` | int \| null | 被判损坏而拒绝的世代（仅 `RolledBack` 非空） |
| `writer` | string | 最后一次提交的写者身份（如 `api:put_config`） |
| `parts` | array | 当前世代各 part：`{path,sha256,bytes,mtime_s}` |
| `missing_parts` | array | **2.1.46 新增**：`commit.json` 记录但盘上不存在的 part 路径。可选镜像（如 `rules_local.json`）缺失时 `load_state` 仍 `Committed`，但本字段非空；`config.json` / `rules.json` 缺失则按**必需 part** 处理（回退 / Torn），不会停留在 `Committed` |
| `prev_generation_ok` | bool | 上一世代是否完好可回退 |
| `history_generations` | array | `history/<rev>/` 保留的世代号（升序） |
| `failed_commits` | int | 进程内提交中止数（IO/ENOSPC；409 不计） |
| `load_state` | string | `Legacy`/`Committed`/`RolledBack`/`Torn` |
| `torn` / `torn_reason` | bool / string\|null | Torn 时 `torn=true` 且原因非空 |
| `lock_held` / `lock_note` | bool / string\|null | 是否持有 `state_dir` 独占锁；共享模式/不支持 flock 时 note 非空 |
| `rule_source_unreadable` | int | 累计"真源存在但读不懂"次数（fail-closed 已生效） |
| `note` | string | 一行人类可读说明 |

> **键集恒 18 键（2.1.46）**：未启用统一事务（`store=None`）时 `writer` 显式下发
> `null`、`missing_parts` 下发 `[]`；2.1.45 及以前只有 17 键（无 `missing_parts`），
> 2.1.40 及以前空态还漏 `writer`（16 键）。`/api/snapshot.cache` 实测 **11 键**
> （`used`/`capacity`/`pct`/`segment_s`/`segment_m`/`segment_g`/`used_bytes`/`bytes_cap`/
> `max_entry_bytes`/`rejected_large`/`hot_replicas`），**不含** `persist` / `restore_drops`
> （= `/api/status.cache` 的 27 键减去 `persist`/`restore_drops` 两个对象键，即 **25 键**）；`/api/snapshot.map` 同为 **25 键**。

> `load_state ∈ {RolledBack, Torn}` 时**不得**把 `revision` 当"正在服务的世代"，权威字段是 `serving_revision`。

---

## 4. 其余读端点

### 4.1 `GET /api/config`（82 键）

**动态口径**：

<!-- CONFIG_KEYS_BEGIN -->
- 随包模板键数：**80**
- 运行期自动补的键数：**2**（`rule_local_file` / `rule_sub_file`）
- `/api/config` 顶层键数：**82**（= 模板 80 + 运行期 2）
<!-- CONFIG_KEYS_END -->

磁盘 `config.json` 通常 81 键：模板 80 减去 `rules`（v2→v3 迁到 `state/rules.json`）+ 2 个运行期路径键。
`/api/config.rules` 由真源派生后补回，所以 API 比磁盘多 1 键。

> **2.2.6（P2-A2）**：模板新增 `negative_mixed_policy`（`nodata` 默认 / `servfail`），
> 因此模板 79→**80**、API 81→**82**；生产配置随部署补齐该键（显式默认，不改变行为）。

> **2.2.0**：缓存策略只剩 `s3fifo`。`partitioned`（含 `partition`）与 `tinylfu`
> （含 `w-tinylfu` / `wtinylfu`）以及 `lru` 在启动、`check-config`、`PUT /api/config`
> 三处**明确拒绝**（提示 `ebpdns migrate-config`），不再 WARN 回退；`cache_partitions`
> 键已删除，旧配置残留按未知键忽略。旧缓存快照/WAL 按 v2 格式正常恢复。

| 归属 | 数量 | 说明 |
|---|---:|---|
| 可写（`CFG_WRITABLE` 的非别名额，全部在模板内） | 72 | `PUT` 生效并落盘（= 82 − 10 只读） |
| 只读（`CFG_READONLY`） | 10 | 模板内 8（`api` / `cache_file` / `config_version` / `dns_port` / `listen` / `state_dir` / `state_persist` / `web_root`）+ 运行期注入 2（`rule_local_file` / `rule_sub_file`）；保存时**不改内存与磁盘**，响应里单列 `readonly_keys` + `readonly_detail` |
| 受支持别名（可写、不回显） | 5 | `cb_fails` / `cb_open_s` / `warmup_enabled` / `warmup_queries` / `warmup_timeout_ms`（**不在** `/api/config` 键集里，也不计入 81） |

> 历史版本移除的配置键不再逐一点名：旧配置里残留的未知顶层键按**通用规则**处理
> （`check-config`/启动只 WARN 并忽略，不改写配置文件）。

**82 键表（类型 / 出厂值 / 归属）**：

| 键 | 类型 | 出厂值 | 归属 |
|---|---|---|---|
| `adaptive_parallel` | bool | `true` | 可写 |
| `adaptive_timeout` | bool | `true` | 可写 |
| `adaptive_timeout_k` | float | `8.0` | 可写 |
| `adaptive_timeout_min_ms` | int | `1500` | 可写 |
| `api` | object | `{"host":"0.0.0.0","port":8353,"token":""}` | 只读 |
| `bootstrap_dns` | array | `["223.5.5.5:53"]` | 可写 |
| `cache_file` | str | `/var/lib/ebpdns/ebpdns-cache.json` | 只读 |
| `cache_persist` | bool | `true` | 可写 |
| `cache_bytes` | int | `268435456` | 可写 |
| `cache_policy` | str | `"s3fifo"` | 可写但**只接受 `s3fifo`**（`lru`/`tinylfu`/`partitioned` 均 400） |
| `cache_save_interval` | int | `60` | 可写 |
| `cache_size` | int | `131072` | 可写 |
| `max_entry_bytes` | int | `65536` | 可写 |
| `negative_pct` | int | `20` | 可写 |
| `circuit_fails` | int | `3` | 可写 |
| `circuit_open_max_s` | int | `120` | 可写 |
| `circuit_open_s` | int | `30` | 可写 |
| `config_version` | int | `3` | 只读 |
| `dns_port` | int | `53` | 只读 |
| `dnssec_0x20` | bool | `true` | 可写 |
| `dnssec_cache_variants` | bool | `true` | 可写（**阶段 3-14**：DO 位参与缓存键；`false` = 退回"共用条目"旧行为） |
| `ecs_cache_variants` | bool | `false` | 可写（**阶段 3-14**：**ECS 不外发** ⇒ 置 `true` 只 WARN，不按客户端子网分裂缓存） |
| `edns` | bool | `true` | 可写 |
| `edns_client_max_size` | int | `1232` | 可写 |
| `edns_client_subnet` | str | `""` | 可写 |
| `edns_udp_size` | int | `1232` | 可写 |
| `fallback` | bool | `true` | 可写 |
| `health_check_interval` | int | `60` | 可写 |
| `health_probe_domain` | str | `"www.baidu.com"` | 可写 |
| `health_probe_timeout_ms` | int | `2000` | 可写 |
| `hedge_after_ms` | int | `300` | 可写 |
| `hedge_slowest_factor` | float | `1.0` | 可写 |
| `ip_speed_cache_ttl` | int | `60` | 可写 |
| `ip_speed_check` | bool | `true` | 可写 |
| `ip_speed_probe` | str | `"both"` | 可写 |
| `ipv4_first` | bool | `true` | 可写 |
| `ipv6` | bool | `true` | 可写 |
| `listen` | object | `{"udp":"0.0.0.0:53","tcp":"0.0.0.0:53","udp6":"[::]:53","tcp6":"[::]:53"}` | 只读 |
| `log_format` | str | `"plain"` | 可写 |
| `log_level` | str | `"info"` | 可写 |
| `max_parallel_upstreams` | int | `4` | 可写 |
| `neg_ttl_max` | int | `300` | 可写 |
| `nxdomain_quorum` | int | `2` | 可写 |
| `padding` | bool | `true` | 可写 |
| `persist_ttl` | int | `864000` | 可写 |
| `prefer_ipv4` | bool | `false` | 可写 |
| `prefetch` | bool | `true` | 可写 |
| `prefetch_interval` | int | `60` | 可写 |
| `prefetch_max` | int | `4096` | 可写 |
| `prefetch_target` | int | `600` | 可写 |
| `prefetch_trigger` | int | `400` | 可写 |
| `probe_timeout_ms` | int | `0` | 可写 |
| `rating_sr_floor` | float | `0.5` | 可写 |
| `rebind_protection` | bool | `true` | 可写 |
| `rfc8020_infer` | bool | `true` | 可写 |
| `rfc8020_max_labels` | int | `8` | 可写 |
| `rule_sub_interval` | int | `3600` | 可写 |
| `rule_subscriptions` | array | `[{...}]` | 可写 |
| `rules` | array | `[]` | 可写 |
| `serve_stale` | bool | `true` | 可写 |
| `single_flight` | bool | `true` | 可写 |
| `speed_interval_ms` | int | `5000` | 可写（**2.2.1**：默认 2000 → 5000，降低每域名候选 IP 重排频率） |
| `speed_test` | bool | `true` | 可写 |
| `speed_timeout_ms` | int | `300` | 可写 |
| `stale_ttl` | int | `3600` | 可写 |
| `state_dir` | str | `/var/lib/ebpdns/state` | 只读 |
| `state_persist` | bool | `true` | 只读 |
| `timeout_ms` | int | `1500` | 可写 |
| `ttl` | int | `600` | 可写 |
| `ttl_max` | int | `600` | 可写 |
| `ttl_min` | int | `5` | 可写 |
| `udp_workers` | int | `0` | 可写 |
| `upstream_max_inflight` | int | `32` | 可写 |
| `upstreams` | array | `[34 条默认上游：237 现网实测，29 enabled / 5 disabled；品牌分组、组内 DoH3 优先]` | 可写 |
| `warmup` | object | `{"enabled":true,"queries":2,"timeout_ms":3000}` | 可写 |
| `web_root` | str | `""` | 只读 |
| `rule_local_file` | str | `/etc/ebpdns/rules_local.json` | 只读 |
| `rule_sub_file` | str | `/etc/ebpdns/rules_sub.json` | 只读 |

**`PUT /api/config`**

请求：JSON 对象；只有 `CFG_WRITABLE` 内的键生效；`if_revision`（body 字段优先，其次 `if-revision`
请求头）是元字段，不作为配置键。**先校验后写入**：任何非法取值、非法 `rules` 条目、非法
`listen`/`api` 形状（只读段也校验）⇒ **400 + 零副作用**（不写盘、不改内存）。

**2.2.1（P2-04）语义收紧**：

* 请求里出现**未知键**（既不在 `CFG_WRITABLE` 也不在 `CFG_READONLY`）⇒ **400**
  （不再 200 `ok:true` 把未知键列进 `ignored_keys`）；
* 请求里**没有任何可写键**（只含只读/服务端管理键）⇒ **400**，且不返回 `saved_to`
  —— 2.2.0 对 `{"config_version":999,"listen":"0.0.0.0"}` 回 200 `ok:true` + `saved_to`，
  脚本会误判为"已保存并生效"；
* 前端「应用配置」提交的是整份配置（含只读键）：只要**同时**带可写键就照常 200，
  只读键原值保持不变并在 `readonly_keys` / `readonly_detail` 中逐条回报。

响应字段（成功 = 200，且至少写入一个可写键）：

| 字段 | 类型 | 含义 |
|---|---|---|
| `ok` | bool | 成功响应固定 `true`（拒绝走 400 `{error}`，没有 `ok`/`saved_to`） |
| `ignored_keys` | array | 保留字段：成功路径下恒为 `[]`（未知键已改为 400） |
| `readonly_keys` / `readonly_detail` | array | 本次提交里被忽略的只读键 / `[{key,reason}]` |
| `written_keys` | array | 本次实际写入的键（**非空**） |
| `writable_keys` | array | 白名单快照（供前端自检） |
| `saved_to` | string | 落盘路径 |
| `revision` | int \| null | 提交点世代（与 `/api/status.state_persist.revision` 同源）；未启用统一事务时为 `null`。**2.1.49-p5 补登记**（实测响应里有该键，旧文档漏写） |
| `meta_keys` | array | 元字段（`if_revision`）回显 |

**`if-revision` 冲突** ⇒ **409** + `{error, expected, current}`；**一个字节都不写**（详见 §5）。

### 4.2 `GET /api/rules` 的三本账（**2.1.30：6 个顶层键**）

| 字段 | 类型 | 含义 |
|---|---|---|
| `rules` | array | 本地逐条规则 |
| `subscriptions` | array | 订阅明细（每项 6 键：`action`/`count`/`group`/`ip`/`updated_at`/`url`） |
| `total` | int | **本地规则数**（语义不变，`== total_local`） |
| `total_local` | int | 本地规则数显式别名 |
| `total_subscription` | int | 各订阅 `count` 之和 |
| `total_all` | int | `total_local + total_subscription`，**== `/api/pipeline.rules`** |

<!-- RULES_KEYS_BEGIN -->
rules
subscriptions
total
total_local
total_subscription
total_all
<!-- RULES_KEYS_END -->

> 判断"到底多少条规则生效"必须读 `total_all`（或 `pipeline.rules`）；`total` 只是本地逐条数。
> `subscriptions[].count` 是**活源**：由订阅刷新写回，与 `/api/config.rule_subscriptions[].count` 同源。
> **2.1.48 / AUD-08**：`/api/config.rule_subscriptions[]` 另含 `last_checked_at`（`YYYY-MM-DD HH:MM:SS`）——每次刷新（含内容未变）都更新，用于区分“已检查但未变”与“更新器卡死”；`updated_at` 仍只在内容变化时更新，且不参与规则来源指纹。

### 4.3 `GET /api/pipeline`（7 字段）

`Pipeline{cache_size,cache_policy,upstreams:Vec<PipeUpstream{id,name,proto}>,upstream_count,rules,prefetch_len,rule_gen}`
（**7 个字段**，由 `_interface_keys.py` 对 `/api/pipeline` 实测 `len()` 断言）

| 字段 | 类型 | 含义 |
|---|---|---|
| `cache_size` | int | 容量 |
| `cache_policy` | str | 策略 |
| `upstreams` | array | `[{id,name,proto}]`（含 disabled 条目） |
| `upstream_count` | int | 上游总数 |
| `rules` | int | 生效规则总数（= `/api/rules.total_all`） |
| `prefetch_len` | int | 预取队列长度 |
| `rule_gen` | int(u64) | 规则指纹 |

### 4.4 `GET /api/cache/stats`（**35 键**，S3-FIFO 唯一策略）

| 字段 | 类型 | 含义 |
|---|---|---|
| `capacity` / `size` / `used` | int | 容量 / 配置容量 / 当前条目 |
| `pct` | float | 使用率 |
| `partitions` | object | 每分组 `{capacity,used,pct,pct_of_total}` |
| `policy` | str | 生效策略 |
| `policy_doc` | object | 策略文档（1 键，见下） |
| `persist` / `restore_drops` | object | 与 `/api/status.cache.*` 逐字段相同 |
| `rrset_interned` / `rrset_hits` | int | **阶段 B-2（RRset 对象级缓存）**：RRset 弱引用表的表项数 / 复用命中次数（`ebpdns_cache::rrset::stats()`，只读 O(1) 诊断）。一个 RRset = `(owner, rtype, 取值集合)`；`interned` 远小于"条目数 × 每条约 RRset 数"即说明链尾 A/AAAA 在**跨消息**共享（阶段 A/B-1 的同一对键已迁移到该口径）。**只在 `/api/cache/stats` 下发**，`/api/status.cache` 键集不变 |
| `rrset_str_interned` / `rrset_str_hits` | int | **阶段 B-1（RDATA 字符串级去重）**：`CacheAnswer.value` / `name` / `Rrset.owner` 的字符串 intern 表项数 / 复用命中次数（`ebpdns_cache::rrset::stats_str()`；口径同上，表与 RRset 表**分开计数**、上限 65,536）。`rrset_str_interned` 远小于"答案条数"即说明相同 RDATA/owner 串在跨条目/跨 RRset 共享；`rrset_str_hits` 随每次写入/恢复的每条答案增长。**只在 `/api/cache/stats` 下发** |
| `segment_s` / `segment_m` / `segment_g` | int | **仅 `s3fifo`**：S/M/G 三段当前长度 |
| `policy_keys` | int | **仅 `s3fifo`（2.2.2/P2-F 补文档）**：策略簿记跟踪的键数；正常应恒等于 `size`。与 `segment_s+segment_m` 一起用于判定 inner→policy 是否漂移（三者不相等 = 有 bug/竞态） |
| `used_bytes` / `bytes_cap` / `max_entry_bytes` / `rejected_large` / `hot_replicas` | int | **仅 `s3fifo`**：字节预算现场 / 单条上限 / 超大条目拒绝数 / 热点副本数 |
| `evict_expired` / `evict_capacity` / `evict_negative` | int | **仅 `s3fifo`**：按原因的**淘汰条目数**（互不重叠；`/api/reset` 不清，累计量）。`evict_expired` = 轮转 TTL purge + 读路径惰性删除 |
| `purge_expired` | int | **仅 `s3fifo`（2.2.4/P2-G）**：`evict_expired` 中由**写路径轮转 TTL purge**（每 32 次 put 扫一次）删除的条目数；读路径惰性删除**不计**。生产 `serve_stale=true + stale_ttl=3600` 时，条目必须过期满 3600s 才会被 purge 扫到 ⇒ 该计数长期为 0 是**预期**（不是指标未接线）；短 TTL/短 stale 窗口实例可直接观测其增长 |
| `evict_bytes` | int | **仅 `s3fifo`（2.2.3/P2-D 语义修正）**：上述淘汰事件实际释放的**真实字节数**（2.2.2 及以前是"字节超预算次数"，名实不符）。恒等于被淘汰条目 `entry_size` 之和，可与三个条目计数互相校验 |
| `removed_delete` / `removed_delete_bytes` | int | **仅 `s3fifo`（2.2.3/P2-D）**：显式 `delete` 删除的条目数 / 释放字节；**不计入** `evict_*`（显式删除不是淘汰） |
| `removed_clear` / `removed_clear_bytes` | int | **仅 `s3fifo`（2.2.3/P2-D）**：`clear()` 清空的条目数 / 释放字节；同样**不计入** `evict_*` |
| `ghost_hits` | int | **仅 `s3fifo`**：被淘汰键再次写入时命中幽灵队列（直接进 M 队列）的次数 |
| `shard_max` / `shard_min` / `shard_imbalance` | int/float | 8 个策略分片的键数最大值 / 最小值 / `(max-min)/avg`（0 = 完全均衡） |

<!-- CACHE_STATS_KEYS_BEGIN -->
capacity
size
used
pct
partitions
policy
policy_doc
persist
restore_drops
rrset_interned
rrset_hits
rrset_str_interned
rrset_str_hits
segment_s
segment_m
segment_g
policy_keys
used_bytes
bytes_cap
max_entry_bytes
rejected_large
hot_replicas
evict_expired
purge_expired
evict_capacity
evict_negative
evict_bytes
removed_delete
removed_delete_bytes
removed_clear
removed_clear_bytes
ghost_hits
shard_max
shard_min
shard_imbalance
<!-- CACHE_STATS_KEYS_END -->

`policy_doc`：只保留 `lru_shards`（历史诊断名，值 = 8 个策略分片）。**2.2.0**：`tinylfu_*` 与
`window` / `probation` / `protected` 兼容键组随策略移除，**不再下发**。

### 4.5 `GET /api/upstreams`（`upstreams[]` **57 字段**；2.2.4/P2-G 重算后，2.2.5/P2-A4 再 +2 个 GOAWAY 空闲/在途分账字段，2.2.6/P2-A1 把在途拆成连接级 + stream 级两字段（净 +1））

| 字段 | 类型 | 含义 |
|---|---|---|
| `id` / `name` / `proto` | str | 标识 / 展示名 / 协议（`udp`/`tcp`/`doh`/`doh3`） |
| `host` / `port` / `url` / `addr` / `full_addr` | str/int | 目标与展示地址（`full_addr` 后端单一来源） |
| `group` | str | 分组（`domestic`/`global`/自定义） |
| `enabled` / `selectable` | bool | 启用 / 可被选路 |
| `role` / `weight` | str/num | 选路角色 / 权重 |
| `latency` / `latency_measured` | int/bool | 配置延迟 / 是否实测 |
| `last_latency` / `avg_latency` / `eff_lat_ms` / `eff_lat_measured` | num/bool | 最近 / 均值 / 生效延迟及其来源 |
| `ok` / `fail` / `fails` | int | 探测成功 / 失败 / 连续失败 |
| `queries` | int | 该上游累计查询数 |
| `success_rate` / `dns_success_rate` | float\|null | 总成功率 / DNS 层成功率 |
| `status` | str | 健康状态（健康/待命/抖动/异常） |
| `breaker_fails` / `breaker_open` / `circuit_open_count` / `until_in_s` | int/bool | 熔断现场 |
| `conn_key` / `conn_ok` / `conn_fail` / `conn_avg_lat` | str/int/num | 连接池键与统计 |
| `transport_ok` / `transport_fail` | int | 传输层成功/失败 |
| `dns_ok` / `dns_fail` | int | DNS 层成功/失败 |
| `probe_ok` / `probe_fail` | int | 主动探测成功/失败 |
| `allow_private_ip` | bool | 私有地址豁免 |
| `doh_transport` | str \| null | **2.2.2 / 2.2.4 语义重申**：DoH 出站传输形态（`"h2"` / `"http/1.1"` = **last-known**（连接关闭后仍保留）/ `"idle"` = 从未有连接样本）。**`proto≠doh` 恒 `null`，语义是"不适用"而非"没有数据"**：`doh3`（QUIC/HTTP3）没有 h2/h1 传输形态、`udp`/`tcp` 也没有 TLS 传输层，因此为 `null`；只有 `proto=doh` 才会出现上述三个字符串。前端不得把 `null` 渲染成"未知/异常" |
| `doh_h2_conns_open` / `doh_h2_streams_active` | int | **2.2.0**：当前 h2 连接数 / 在途 stream 数（gauge；与 `/metrics` 的 `ebpdns_doh_h2_*` 同源，`proto≠doh` 恒 0） |
| `doh_h2_streams_total` / `doh_h2_goaway_total` / `doh_h2_fallback_h1_total` | int | **2.2.0**：累计 h2 stream 数 / 被对端终止（GOAWAY/关闭/中途 IO 断开）并重连的连接数 / ALPN 只协商到 http/1.1 的新建连接数（`/api/reset` 清零累计量，gauge 不清） |
| `doh_h2_goaway_{peer,io,protocol}_total` / `doh_h2_goaway_local_idle_total` / `doh_h2_goaway_idle_total` / `doh_h2_goaway_conn_inflight_total` / `doh_h2_goaway_streams_lost_total` / `doh_h2_conns_closed_total` / `doh_h2_conns_idle_reclaimed_total` / `doh_h2_conn_life_ms_avg` | int | **2.2.3（P2-E）/ 2.2.5（P2-A4）/ 2.2.6（P2-A1）**：GOAWAY 原因细分（对端 GOAWAY/EOF / 请求中途 IO 断开 / h2 协议错误 / 本地空闲回收，本地回收**不计入** `goaway_total`）与连接寿命。**2.2.5 新增** `goaway_idle_total`（终止瞬间**无在途 stream** = 对端空闲回收，**不是请求失败**）与在途分账；**2.2.6** 把在途拆成 `goaway_conn_inflight_total`（**连接级**：一条连接 N 个在途也只记 1；改名自 `goaway_inflight_total`）与 `goaway_streams_lost_total`（**stream 级**：受影响请求数，`>= conn_inflight`）；恒等式 `doh_h2_goaway_total == idle + conn_inflight`。`conns_closed_total` 只统计**真实连接**（承载过 stream 或非空闲终止）；从未使用的空闲回收单独进 `conns_idle_reclaimed_total`，不参与平均寿命。`/metrics` 同名 `ebpdns_doh_h2_*` 系列 |

`POST /api/upstreams` 与 `PUT /api/upstreams/{id}`：body 为上游对象；成功 `{ok:true,upstream:{...}}`，
`POST` 在可自动解析地址时附 `auto_parsed:true`；`DELETE` ⇒ `{ok:true}`。

**2.1.49-p5 实测口径**：`POST` 以 **`addr`** 为准（`addr` 可带 `host:port` 或 scheme 前缀，
解析结果覆盖 body 里的 `proto`/`port`/`url` 默认值）；**`host` 不参与创建**（只回显）——
缺 `addr`、只给 `name` 的请求会走"手动分支"，把 `addr` 兜底成 `223.5.5.5`（历史 Python 行为），
所以只给 `host` 会**静默建成 223.5.5.5**；`addr` 与 `name` 都没有 ⇒ 400 `addr or name is required`。
`DELETE /api/upstreams/{id}` 不存在 ⇒ 404 `upstream not found`。


### 4.6 `GET /api/logs`（4 顶层键 + 事件 12 字段）

| 顶层字段 | 类型 | 含义 |
|---|---|---|
| `events` | array | 事件（最多 `limit` 条；`limit` 缺省/0 时取 500，夹在 1..=2000） |
| `seq` / `next_seq` | int | **2.1.43-A 起语义统一**：`next_seq` = "下一条要取的起始 seq" = `max(本批最后一条 seq + 1, 入参游标)`；**空批时原地不动**（2.1.42 会回退到 1 ⇒ 前端整段重放）。`seq` 与 `next_seq` 恒同值 |
| `total` | int | 事件环内的事件总数（与本次过滤结果无关；环容量 500） |

事件字段：`seq`(int)、`ts`(float epoch)、`ts_text`(HH:MM:SS.mmm)、`level`(hit/miss/**policy**/err/warn/rule/sys)、
`msg`(string)、`domain`、`qtype`、`client_ip`、`upstream`、`answer`、`rule`、`lat`(float|null)。

查询参数：`next_seq` / `since`（**完全同义**，都是事件序号游标 = "下一条起始 seq"，
判据 `seq >= cursor`；同一响应里的 `next_seq` 可直接回填）、`since_ts`（时间戳游标，
仅在没有序号游标时生效）、`limit`、`level`、`domain`、`qtype`、`ip`、`answer`、
`upstream`、`rule`、`min_lat`、`q`（全局子串）。

### 4.7 `GET /api/snapshot`（22 顶层键）

`avg_latency_ms`、`cache`（11 键，见 §3.4 注）、`config_snippet`（8 键：
`cache_size`/`edns`/`fallback`/`ipv4_first`/`ipv6`/`prefetch`/`speed_test`/`ttl`）、
`counters`（**39 键** = `/api/status.counters` 的 38 + `snapshot_seq`）、
`counters_monotonic_ms`、`entries`（前 500 条缓存条目；每项 6 键
`domain`/`qtype`/`rcode`/`chosen`/`ttl`/`ttl_stored`）、`events`、
`history`（`[{label,label_text,ts,qps,hit_rate,lat}]`）、
`hit_rate`、`manual_history`、`map`（11 键）、`qps`、`qtype_dist`（`A`/`AAAA`/`other`）、`rule_hits`、
`running`、`snapshot_seq`、`top_clients`、`top_domains`、`top_upstreams`、`total`、`upstreams`（**57 字段/项**，与 `/api/upstreams[]` 同源）、
`uptime_s`。

---

## 4.8 `/metrics` 指标名全表（**2.2.6：68 个 HELP family**）

> **2.2.0（能力 4）**：新增 5 个 DoH h2 family（共 57），冷/热态 family 集合不随流量漂移。
> **2.2.3（P2-E）**：GOAWAY 原因拆为 peer/io/protocol + 本地空闲回收；新增
> `doh_h2_conns_idle_reclaimed_total`（从未使用的空闲回收，不计入平均寿命）。
> **2.2.5（P2-A4）**：再把对端终止按"终止瞬间是否有在途 stream"拆为
> `doh_h2_goaway_idle_total`（空闲回收，**不是请求失败**）与
> `doh_h2_goaway_conn_inflight_total`（请求受影响的**连接数**）；
> `goaway_total == idle + conn_inflight`，因此"GOAWAY 数"不再被误读成"失败请求数"。
> **2.2.6（P2-A1）**：`doh_h2_goaway_inflight_total` 改名 `doh_h2_goaway_conn_inflight_total`
> 明确"连接级"口径，并新增 `doh_h2_goaway_streams_lost_total`（**stream 级**受影响请求数，
> `streams_lost >= conn_inflight`）；`negative_mixed_degraded_total` 上 `/metrics`（2.2.6/P2-A8）。

权威取法：

```bash
curl -fsS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8353/metrics \
  | grep '^# HELP' | sed 's/^# HELP //; s/ .*//' | sort
```

热态 **68** 个；冷启动 **66** 个（`ebpdns_upstream_latency_ms` 与 `ebpdns_upstream_latency_ms_quantile`
两个上游延迟 family 懒加载，首个上游 RTT 样本后出现）。判据是 `# HELP` 名；直方图的
`_bucket`/`_sum`/`_count` 同属一个 family，不重复计数。

<!-- METRICS_BEGIN -->
ebpdns_queries_total
ebpdns_cache_hits_total
ebpdns_cache_misses_total
ebpdns_errors_total
ebpdns_uptime_seconds
ebpdns_bytes_in_total
ebpdns_bytes_out_total
ebpdns_udp_dropped_total
ebpdns_upstream_dispatch_total
ebpdns_upstream_wire_requests_total
ebpdns_upstream_requests_total
ebpdns_upstream_early_return_total
ebpdns_upstream_hedge_total
ebpdns_doh_h2_conns_open
ebpdns_doh_h2_streams_active
ebpdns_doh_h2_streams_total
ebpdns_doh_h2_goaway_total
ebpdns_doh_h2_fallback_h1_total
ebpdns_doh_h2_goaway_peer_total
ebpdns_doh_h2_goaway_io_total
ebpdns_doh_h2_goaway_protocol_total
ebpdns_doh_h2_goaway_local_idle_total
ebpdns_doh_h2_goaway_idle_total
ebpdns_doh_h2_goaway_conn_inflight_total
ebpdns_doh_h2_goaway_streams_lost_total
ebpdns_doh_h2_conns_closed_total
ebpdns_doh_h2_conns_idle_reclaimed_total
ebpdns_doh_h2_conn_life_ms_avg
ebpdns_cache_entries
ebpdns_cache_capacity
ebpdns_cache_direct_total
ebpdns_cache_negative_hits_total
ebpdns_negcache_hit_ratio
ebpdns_negative_single_vote_accepted_total
ebpdns_negative_mixed_degraded_total
ebpdns_servfail_total
ebpdns_servfail_reasons_total
ebpdns_upstream_inflight_limit
ebpdns_upstream_inflight_acquired_total
ebpdns_upstream_inflight_queued_total
ebpdns_upstream_inflight_rejected_total
ebpdns_upstream_inflight_queued_gave_up_total
ebpdns_query_latency_ms
ebpdns_rule_hits_total
ebpdns_negative_cache_hits_total
ebpdns_cache_skipped_private_total
ebpdns_no_response_total
ebpdns_control_queries_total
ebpdns_control_hits_total
ebpdns_passthrough_qtype_total
ebpdns_policy_filtered_total
ebpdns_client_rcode_total
ebpdns_rfc8020_hits_total
ebpdns_rfc8020_registrations_total
ebpdns_prefetch_all_open
ebpdns_prefetch_degraded_total
ebpdns_breaker_all_open_total
ebpdns_stale_served_total
ebpdns_upstream_requests_total_by_id
ebpdns_upstream_success_rate
ebpdns_upstream_dns_success_rate
ebpdns_upstream_latency_ms
ebpdns_upstream_latency_ms_quantile
ebpdns_process_resident_memory_bytes
ebpdns_process_virtual_memory_bytes
ebpdns_process_threads
ebpdns_process_open_fds
ebpdns_state_missing_parts
<!-- METRICS_END -->

---

## 4.9 支持的 qtype（受理并缓存 20 型；12 类一律 `NOTIMP`）

判定单一来源 = `ebpdns_proto::constants`。数据面对每个查询走且只走一支；API/前端只消费名字，
新增类型不需要页面适配。当前实测：**受理并缓存 20 型**；**12 类一律 `NOTIMP`**。

| 分支 | 类型 | 语义 |
|---|---|---|
| **受理并缓存（20 型）** | `A NS CNAME SOA PTR MX TXT AAAA SRV`、`NAPTR(35)`、`DS(43)`、`SSHFP(44)`、`DNSKEY(48)`、`TLSA(52)`、`CDS(59)`、`CDNSKEY(60)`、`SVCB(64)`、`HTTPS(65)`、`URI(256)`、`CAA(257)` | 解析 + 重编码 + 正常 TTL 缓存 |
| **未知/其他合法类型** | 不在上表也不在下表（如实验/私有类型、`MAILA(254)`/`MAILB(253)`） | 原样透传、**不缓存**、不解析 RDATA |
| **一律拒绝（NOTIMP，12 类）** | `TYPE0`、`NULL(10)`、`OPT(41)`、`RRSIG(46)`、`NSEC(47)`、`NSEC3(50)`、`NSEC3PARAM(51)`、`TKEY(249)`、`TSIG(250)`、`IXFR(251)`、`AXFR(252)`、`ANY(255)` | 回 `NOTIMP`，绝不降级成 A |

`opcode≠0` 与非 `IN` class 同样回 `NOTIMP`（与本表无关的既有分支）。

---

## 5. 写 / 动作端点

| 端点 | 请求 | 成功响应 | 主要错误 |
|---|---|---|---|
| `POST /api/query` | `{domain, qtype?}`（qtype 默认 `A`，只接受受理集合） | `QueryResp{domain,qtype,rcode,error,hit,miss,chosen,latency,latency_ms,reason,trace[],answers[],empty,truncated,ttl_left}` | 400 域名非法/类型不受理；500 |
| `POST /api/rules/import` | `{action,group?,ip?,content}`（`action` 只接受 `allow`/`block`/`group`/`forceIp`；`?mode=replace` 才是整份覆盖） | `{ok,added,imported,total,mode}` | 400 动作/内容非法（**2.1.49-p5 修复 R2-01**：此前未知 action 会 200 落盘） |
| `POST /api/rules` | 规则对象（`{action,match,group?,ip?}`；**`note` 不被接受**：POST 静默丢弃、PUT 回 400） | `{ok,rule:{...}}` | 400 校验失败 |
| `PUT /api/rules/{id}` | 同上（可部分字段；**仅** `match`/`action`/`group`/`ip`/`ttl_min`/`ttl_max`，其它字段 ⇒ 400 `非法规则字段`） | `{ok,rule:{...}}` | 404 / 400 |
| `DELETE /api/rules/{id}` | — | `{ok:true, rule:{...}}`（实测回显被删规则） | 404 |
| `POST /api/rules/subscribe` | `{url,action?,group?,ip?}`（仅 `https://`） | `{ok,url,count,added}` | 400 非 https/SSRF；502 拉取失败 |
| `DELETE /api/rules/subscribe` | `?url=<percent-encoded>`（查询参数；body 可省，不再强制 JSON） | `{ok,url}` | 404 |
| `POST /api/rules/subscribe/update` | `{url}` | `{ok,url,count}` | 404 / 502 |
| `POST /api/reprobe` | — | `{ok,results:[{id,name,proto,addr,old,new,ok}]}`（`new` = 本次实测延迟 ms，`old` = 配置原值） | 502 |
| `POST /api/reload` | 任意/空 body | `{ok:true,changed:[],source:"file"\|"memory",rules:N,unchanged:bool}` | 成功 200；**失败 500** `{ok:false,error:"rules_sub_unreadable"\|"rules_sub_missing_subscriptions"\|"rules_sub_invalid"\|"rules_local_unreadable"\|"rules_rebuild_failed",detail:"..."}`（旧规则索引保留） |
| `POST /api/restart` | `{"confirm":true}` | `{ok:true}`，随后进程退出码 3 | 400 缺确认；409 已在重启 |
| `POST /api/reset` | `{"confirm":true}` | `{ok:true}` | 400 |
| `POST /api/profile` | 任意 JSON | `{ok:true,note:"profiling not available"}` | 415 缺 Content-Type；400 非 JSON |

**`POST /api/reload` 的失败语义（2.1.49）**：`on_reload` 现在返回 `Result`。`rules_sub.json`
不可读/非法/缺 `subscriptions`、本地规则真源不可解析、或合并后规则全部被拒 ⇒ **500**
（不是 200），响应体 `{"ok":false,"error":"<code>","detail":"..."}`，且**旧规则索引不被替换**
（`pipeline.rules` / `rule_gen` 保持不变）。成功仍为 200，并补 `rules`（重建后索引条数）
与 `unchanged`（本次无变化）两个字段；订阅刷新端点的 `unchanged:true` 仍为 200。

---

## 6. 错误码与 409 语义

| 码 | 触发 | 响应体 |
|---|---|---|
| 200 | 成功 | 端点字段 |
| 400 | 参数/JSON/取值非法；`rules` 逐条校验失败；restart/reset 缺 `confirm` | `{"error":"<逐条原因>"}` |
| 401 | 缺 token / token 错误（含未知 `/api/*` 路径） | `{"error":"未授权"}` |
| 403 | CSRF / Origin / 路径穿越被拒 | `{"error":"..."}` |
| 404 | 规则/订阅 ID 不存在；带 token 的未知路径 | `{"error":"not found"}` / 自定义文案 |
| 405 | 方法不允许（如 `GET /api/profile`） | 空体（axum 方法矩阵） |
| 409 | ①`PUT /api/config` 的 `if-revision` 与锁内当前世代不符；②`/api/restart` 重入 | ①`{error,expected,current,state_persist_url}`（`state_persist_url` = `/api/status`，指"去哪里读当前 revision"）；②`{"error":"重启已在进行中"}` |
| 413 | 请求体/文件过大 | `{"error":"..."}` |
| 415 | `Content-Type` 不是 `application/json` | 空体（`Json` 提取器） |
| 502 | 上游/订阅拉取/探测失败 | `{"error":"..."}`（不回显内网拓扑） |
| 500 | 未预期内部错误；`/api/reload` 的规则真源非法/重建失败 | `{"error":"internal error"}`；reload 为 `{"ok":false,"error":"<code>","detail":"..."}` |

**写路径的校验顺序（2.1.49-p5 实测）**：`CSRF/同源` → `token` → 读路径 `Origin`。因此同一条写请求
可能出现三种结果，排障时不要只看状态码猜原因：

- 无 `Origin`/`Referer` 且 API 绑定环回 ⇒ CSRF 放行 → 缺/错 token 回 **401**；
- 带跨源 `Origin`/`Referer` ⇒ **403 `CSRF check failed`**（**先于** token 校验）；
- API 绑定非环回且无 `Origin`、无有效 token ⇒ **403**（CSRF 分支，不是 401）。

读端点顺序固定为 `token`（401）→ `Origin`（403，含不可信/畸形 `Host`）；`/api/health` 两者都豁免。

**409 的语义**：`if-revision` 是**乐观并发控制**，不是故障。冲突时提交在**取锁后、任何写之前**被拒，
`config.json`、内存配置、规则真源、提交点逐字节不变；`failed_commits` 不增加；日志级别 WARN（不是 ERROR）。
客户端应重读 `current`、合并后再带新 `if-revision` 重试。

---

## 7. 前端刷新模型

| 规则 | 实现 |
|---|---|
| 单一调度器 | 全前端只有一个 `TimeoutFuture` 循环，节拍 `TICK_MS=2000`；同一 tick 每端点至多一次 |
| 按需取数 | `/api/status` 全局；`/api/snapshot` 仅遥测页；`/api/pipeline` + `/api/logs` 仅流水线页；切页立刻补一轮 |
| 隐藏暂停 | `document.visibilityState=hidden` 时循环只等可见性通知、不取数；回前台立即补一轮 |
| 失败退避 | 2s→4s→8s→16s→30s（`BACKOFF_MAX_MS`）；任一成功立即回 2s；退避只影响该端点 |
| 401 | 停机并切配置页，避免继续打无效请求 |
| 手动刷新 | 页头刷新按钮 / 交互 ⇒ `kick()`：全部端点立即到期、失败计数归零 |
| 时长口径 | `next_due = 本 tick 计划时刻 + 间隔`（不是完成时刻），否则实际间隔会翻倍 |
| 页脚文案 | 正常 `2s`；有端点退避时 `退避 {最长间隔}s` |

`tools/pollsim` 用 `#[path]` 复用同一份 `poll_policy.rs` 做 native 请求数复算，不参与产品构建。

---

## 8. 字段与文档一致性门禁

| 门 | 脚本 | 判据 |
|---|---|---|
| 接口键集 | `_interface_keys.py` | 四个标记块 + persist 表 + `Pipeline{}` + qtype 名单 == 隔离实例逐键 |
| 配置键集 | `_config_keys.py` | 模板 **79** + 运行期 2 == `/api/config` **81**；`README` 配置表登记三个运行期只读键 |
| 文档计数 | `_doc_counts.py` | 声明数字 == 标记块行数 == 字段表行数；qtype 总数 == `constants.rs` |
| 版本/契约 | `_version_consistency.py` | 七处同版本 + 四条文档各含两条契约 |

任何字段改名/增删都必须同时改：标记块、声明数字、字段表、前端 `model.rs`、`_interface_keys.py`
的比对（后者自动跟随，无需改代码）。只改一边 ⇒ `check_all` 第 10/11 项红。

---

**部署约束：单机单实例**（`state_dir` 独占锁；第二实例会被拒；隔离实例必须显式 `--state-dir`）。

**规则契约：`/api/config.rules` 在任何情况下都恒为数组，由真源派生（无规则时为 `[]`，不是 `null`）。**
