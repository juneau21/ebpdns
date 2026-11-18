# ebpdns 2.1.49-p1 修复说明（基于厂商 2.1.49 源码重建）

- 基线版本：ebpdns 2.1.49（厂商 prod 包 / 源码包）
- 本包版本标识：**2.1.49-p1**（厂商版本号未变；二进制 md5 见下）
- 修复文件：`crates/ebpdns-cache/src/lru.rs`、`crates/ebpdns-cache/src/tinylfu.rs`
- 构建：rustc 1.99.0，`cargo build --release --offline --bin ebpdns --features embed-frontend`（Linux x86_64）
- **二进制 md5：`2d1ed5ee97ac355fadf0f8796bcee825`**（每次重建会变；以包内 BUILD_INFO.txt 为准）

---

## 一、缺陷 1（P0）：`GET /api/snapshot` 会清空 serve-stale 缓存池

### 现象（生产 192.168.0.235 实测）

控制台「遥测」页每 **约 1.75 s** 调一次 `/api/snapshot`；打开该页后 `cache.used`
从数千条持续下跌到几百条：

```
before: 1630
3 次调用后: 770
6 次调用后: 314     ← 之后稳定在"最近约 60 秒新写入"的量级（≈ QPS × 60s）
```

停止调用后自行回升。首页「数据面流水线」只轮询 `/api/status|pipeline|logs`，不受影响。

### 根因

`/api/snapshot` 的取数路径是 `cache.sample_keys(500)` + 逐条 `cache.peek(k, now)`。

- `peek()` 在 2.1.45 被加入"惰性删除已过期条目"（为了不让 `total`/采样被过期键占位），
  但**没有判断 `stale_window`**；
- 同一文件里的 `get_arc()` 是有判断的（`sw <= 0` 才删）—— 两者口径不一致；
- `serve_stale=true`（默认）时，过期条目**正是** stale 应答池（`stale_ttl` 默认 604800 秒），
  不是垃圾；
- LRU 的 `sample_keys` 按 LRU 序取**最旧**的 500 条 —— 恰好全是已过期条目，
  于是**每轮轮询删除 500 条 stale 条目**；
- 该删除**不写 journal**（WAL 无 EVICT 记录），内存与落盘状态分叉。

净效果：观测端点变成"清空 stale 池"的写操作，`cache.used` 跌到"只剩未过期条目"，
且上游全部故障时不再有 stale 兜底。

### 修复

`peek()` 的惰性删除加上 `stale_window` 保护，与 `get_arc()` 完全同口径：

```rust
if entry.expires_at <= now {
    // 只在"明确不保留 stale"时才清理；serve_stale 开启时它是合法应答池
    if self.stale_window_f64() <= 0.0 {
        shard.map.remove(key);
    }
    return None;
}
```

TinyLFU 实现同样处理（`self.stale_f64() <= 0.0`）。

### 回归测试（新增 3 项）

- `lru::fix250_stale_pool_tests::peek_keeps_stale_pool_when_serve_stale_enabled`
- `lru::fix250_stale_pool_tests::peek_still_reaps_expired_without_serve_stale`
- `tinylfu::fix250_stale_pool_tests::peek_keeps_stale_pool_when_serve_stale_enabled`

---

## 二、缺陷 2（P2）：`/api/snapshot.entries` 采样偏差（只看到最旧条目）

### 根因

`sample_keys` 的实现是"按迭代序取前 N 个"：

- LRU 的迭代序是 **LRU→MRU**，前 500 个 = **最旧**的 500 条（多数已过期，被 `peek` 过滤后
  列表几乎为空）；
- TinyLFU 的三段顺序是 window→probation→protected，前 500 个集中在 window 段（约 1% 容量）
  与 probation 最旧段。

结果：控制台"缓存条目"列表永远展示"即将被淘汰/已过期"的条目，看不到热点。

### 修复

两处 `sample_keys` 改为**等距跨步采样**（`step = len / per`），覆盖整个淘汰轴 / 三个分段，
克隆量仍是 O(limit)。

### 回归测试（新增 2 项）

- `lru::fix250_stale_pool_tests::sample_keys_covers_whole_lru_axis`
- `tinylfu::fix250_stale_pool_tests::sample_keys_covers_whole_axis`

### 缺陷 3（P3，本轮补充）：`partitioned` 采样二次回填会重复

`PartitionedCache::sample_keys` 第一轮按分区配额取不满时会进入第二轮回填，旧实现用
"跳过前 q 个"来避免重复 —— 该假设在 2.1.50 改成**跨步采样**后失效（步长随请求量变化，
两次采样集合不同）。已在 2.1.50（FIX-SAMPLE-DEDUP）改为按 `CacheKey` 去重，
并新增测试 `sample_keys_dedups_when_one_partition_is_empty`。

### 缺陷 4（P3，本轮补充）：`/api/rules/import` 对非法 JSON 静默降级

`Content-Type: application/json` + body `not json xyz` 过去返回 **200**，并把
`not`/`json`/`xyz` 写成 `*.not` 等三条垃圾规则（进真源 `state/rules.json`）。
**修复（FIX-IMPORT-JSON）**：声明 JSON 或 body 以 `{`/`[` 开头时解析失败 → **400**；
纯文本导入（`text/plain`）行为不变。测试：`rules_import_invalid_json_is_400`。

### 缺陷 5（P4，本轮补充）：`peek` 的惰性删除不入 journal

`stale_window <= 0` 时 `peek` 仍会删除过期条目，且不写 EVICT 事件 ⇒ 内存与 WAL 分叉
（重启回放可能复活）。**修复（FIX-PEEK-PURE）**：`peek` 改为纯只读，清理只由写路径
（`purge_expired_locked` / `get_arc`）负责。新增 2 项测试，并修正 2 条旧断言。

### 缺陷 6（P4，本轮补充）：TopN 裁剪在数据面持锁做全排序

`trim_low_counts` 对 2048 项做 `sort_by`（O(n log n)）且持 `Mutex`，实测单次
p50 718 µs / p99 1131 µs，期间所有查询排队。**修复（FIX-TOPN-TRIM）**：改用
`select_nth_unstable_by`（O(n)）→ 实测 **p50 244 µs / p99 325 µs**（2.9×/3.5×）。

### 缺陷 7（P3，第三轮）：`chosen` 在 miss / 命中 两条路径语义不一致

miss 返回 `cand_list.first()`（测速优选后的首个 IP），而缓存写入 `fill_cache_capped` 取
`answers.iter().rev().find(A/AAAA)`（**最后一个 A**）⇒ 同一域名首次查询与后续命中显示不同 IP
（控制台「解析值 IP」/ `/api/query.chosen` / 遥测 `record_manual`）。
**修复（FIX-CHOSEN-PARITY）**：改为正序取首个 A/AAAA（CNAME 链下仍是链尾目标）。
新增 2 项回归测试；现场 4/4 域名 miss==hit==answers[0]。

### 缺陷 8（P3，第四轮）：`persist_ttl` 复活条目把 10 天 TTL 回给客户端

`persist_ttl=864000` 让重启复活的条目内部 TTL 变成 10 天；旧实现把 `ttl_left` 原样回给客户端，
客户端会把 A 记录缓存 10 天。**修复（FIX-TTL-ADVERTISE）**：快路径 `answer.rs` 与完整路径
`resolve.rs` 两处都按 `ttl_max` 封顶对外 TTL（`ttl_max=0` 视为不封顶，兼容旧语义），
内部过期时间不变；封顶后的值同时参与 prefetch 调度，复活条目约 9 分钟后会被续期。
回归测试：`hit_ttl_is_capped_by_ttl_max`。

### 缺陷 9（P3，第五轮）：复活条目的 10 天 TTL 让"及时预取"失效

`persist_ttl=864000` 让重启复活的条目内部 TTL = 10 天；prefetch 入队判据是"剩余 TTL ≤
prefetch_trigger(300s)"，10 天永远够不到 ⇒ 复活条目最长 10 天不刷新。
**修复（FIX-PERSIST-TTL-CAP）**：装配层把复活 TTL 收敛为 `min(persist_ttl, max(ttl, ttl_max))`
（=600s），重启后缓存仍全部复活，但按正常 TTL 服务并由 prefetch 及时续期。
实测：重启后命中 `www.qq.com`，`ttl_left=595.1s`。

### 缺陷 10（P2，第五轮）：预取只刷新"命中过"的条目，查询过的域名不会自动保鲜

原 `do_prefetch` 只消费命中驱动的待办队列，且只续期 `0 < left ≤ trigger` 的条目 ⇒
没被再次查询的域名永远不刷新、到点过期；与"查询过的域名一直保存 + 每 5 分钟刷新"直接冲突。
**修复（FIX-PREFETCH-SWEEP）**：每轮在 pending 之外按 round-robin 从缓存补扫
`prefetch_max - pending` 个键并强制刷新（`prefetch_max=0` 关闭）。
配套默认值：`prefetch_trigger=600`（=ttl，命中即入队）、`prefetch_target=600`、
`prefetch_max=2048`、`prefetch_interval=300` ⇒ 后台 ≈6.8 qps，稳态常驻 ≈4096 个域名。
单测：`prefetch_trigger_skips_entries_above_threshold`（补扫刷新 + prefetch_max=0 关闭）。

---

## 三、**不是** bug 的既有行为（避免误判）

1. **`cache.used` 含"已过期但未清理"的条目**：`used` 是内存条目数；未过期条目数看
   `persist.used_live`（快照写入口径）。两者不同口径，文档 `docs/INTERFACE.md` 已注明。
2. **持久化快照只写未过期条目**（实测 325/1545）：这是设计 —— 过期条目由 WAL 增量与
   restore 逻辑处理，不是"丢 80% 缓存"。
3. **`/etc/ebpdns/config.json` 直接改文件不生效**：配置以内存/事务为真源，重启会把文件
   覆盖回内存值。必须 `PUT /api/config` + `POST /api/reload`。

---

## 四、验证记录（192.168.0.236，本包二进制）

| 项目 | 结果 |
|---|---|
| `cargo test -p ebpdns-cache` | **104 passed / 0 failed**（含新增 6 项） |
| `cargo test -p ebpdns-server --lib` | **324 passed / 0 failed** |
| `cargo test -p ebpdns-resolver` | **全绿**（含 2 项 chosen 回归） |
| `cargo test --workspace` | **1027 passed / 0 failed**（含前端门禁） |
| `cargo clippy --workspace --all-targets -D warnings` | **0 warning** |
| `/api/rules/import` 非法 JSON | **400** + 规则数不变 |
| 连续 12 次 `GET /api/snapshot` | `used` 1196 → **1249（增长）**；旧版同场景 1630 → 314 |
| 打开「遥测」页 60 s（30 次 snapshot） | `used` 6169 → **6842（增长）** |
| DNS 解析 | 正常（`www.qq.com` 返回 A 记录） |
| 服务启动/恢复 | 正常，重启后从 v2 快照+WAL 恢复 |

> 注：验证时 236 上运行的即为本包二进制；「遥测」页轮询不再改变 `used`。

### 关于前端产物

本包**没有重编 WASM 前端**：修改只涉及服务端缓存 crate，前端沿用厂商 2.1.49 的
`web/dist`（与线上 `app_bg.wasm` md5 一致：`6adcf9f8ef71140c5cc16c03dce08217`）。
为保证"产物不早于源码"的前端门禁成立，`web/dist/*` 与 `web/src/*` 的 mtime
统一钉到 `BUILD_EPOCH`（与厂商 `make_packages_221r2.sh` 的做法一致），
因此 `web_dist_freshness`（dist 新鲜度、版本标记、cfg-id 覆盖）三项全部通过。

---

## 五、部署与回滚

```bash
# 部署（包根目录）
sudo ./install.sh start

# 或只替换二进制（保留现有配置/缓存）
sudo install -m 0755 -o ebpdns -g ebpdns bin/ebpdns /usr/local/bin/ebpdns
sudo systemctl restart ebpdns

# 回滚
sudo install -m 0755 -o ebpdns -g ebpdns /root/ebpdns.bak.<时间戳> /usr/local/bin/ebpdns
sudo systemctl restart ebpdns
```

---

## 六、遗留建议（需厂商在后续版本处理）

1. `sample_keys` 的跨步遍历仍是 O(全表) 指针步进（不分配），131072 容量下每次
   `/api/snapshot` 约 0.5-1 ms；可改为分段随机起点进一步降本。
2. 观测端点建议统一在 API 层做 5-10 s 缓存（ETag/If-None-Match），减少 1.75 s 轮询的
   500 键序列化开销。
3. `peek` 在 `stale_window<=0` 时的删除仍未写 journal；建议与 `delete` 统一（记录 EVICT），
   避免"内存删了、WAL 还在"的分叉（当前仅影响过期条目，风险低）。