# ebpdns Rust workspace 开发约定（所有 crate 必须遵守，冻结）

本文件是**规范**，不是历史记录：只保留"现在必须怎么做"与"为什么这样做"的判据。
版本号只在根 `Cargo.toml` 的 `[workspace.package] version` 出现一次；正文不写"某版本当时如何"。

适用对象：`crates/` 下 7 个 workspace 成员、`web/` 独立 WASM workspace、`scripts/` 与 `packaging/`。

---

## 0. 与参考实现的关系（功能真实性）

- 以 Python v1.9.162 的**可观测行为**为参照：路由表、字段名、错误码、计数口径、规则语义。
- 不以"看起来像"为完成标准：每个能力必须有**可执行判据**（单测/集成/CDP/门禁脚本），
  文档只描述已被判据覆盖的行为。
- 不得为了"对齐历史"引入与当前实现冲突的开关；历史键只作为**兼容面**保留，并在文档标注归属。

## 1. 错误处理

- 库层用 `thiserror` 定义错误；HTTP 层统一 `ServerError` → JSON 响应，**绝不 panic**。
- 5xx 必须"无副作用"：先做完全部校验，再写盘/换内存；失败回滚必须**逐字节**还原。
- 数据面任何异常路径都必须有**可归因计数**（SERVFAIL 5 档），不得只打日志。

## 2. unsafe

- `unsafe` 只允许出现在：`flock`、Win32 时区 API、`localtime_r`、必要的分配器适配。
- 每处 `unsafe` 必须有 `// SAFETY:` 注释，说明前置条件与所有权；新增 `unsafe` 需在评审中单列。
- 当前没有独立的 `SAFETY.md`；以"代码内 SAFETY 注释 + 评审清单"为准（不虚构文件）。

## 3. 命名与模块

- crate 名 `ebpdns-*`，模块用短名（`api`/`dns`/`state_store`/`cache_persist`）。
- 文件名与职责一致；单文件超过约 800 行不是硬红线，但新职责必须新模块，
  且拆分时**测试跟随模块**，不得为了减行数把测试搬走。
- 公开 API 必须有文档注释；内部 helper 不导出。

## 4. 并发

- 热路径不持锁做 I/O；锁内只做内存替换/指针交换。
- 多锁必须固定顺序；跨分片操作不得形成反向锁序（缓存 `seq` 分配 + 入队同临界区是范例）。
- 异步任务必须有界：队列、在途、重试都要有上限与丢弃计数。

## 5. 资源与容量

- `cache_size` 是**条目数**上限，不是字节数；每条约 117 kB 常驻，容量要按内存评估。
- 事件环 500 条；延迟窗口 400 条；历史环 120 点；订阅拉取 16 MB 上限。
- 所有队列（UDP 槽位、在途闸门、WAL 批次）必须有明确上限与"满了怎么办"的计数。

## 6. DNS 行为要点（跨 crate 一致）

- 受理/拒绝/透传三分派**单一来源** = `ebpdns_proto::constants`；控制面 `POST /api/query` 与数据面同表。
- 拒绝路径绝不把查询降级成 A；`opcode≠0` 与非 `IN` class 回 `NOTIMP`。
- CNAME 链有深度门禁；bailiwick 锚定防投毒；负结论按**有效票**表决。
- 私有/保留地址答案按 `rebind_protection` 丢弃且不写缓存，计 `cache_skipped_private_total`。

## 7. 测试

- 每个行为变更至少一个单测；跨 crate 契约用集成测试钉死。
- 契约测试命名要表达**不变量**（如 `status_and_cache_stats_expose_identical_persist_block`）。
- 崩溃安全类改动必须有 kill -9 / fail-point 证据脚本（手工执行，归档在 `scripts/archive/`）。
- 测试不得依赖生产端口/生产 `state_dir`；隔离实例必须显式 `--state-dir`。

## 8. 质量门

合入前必须跑 `bash scripts/check_all.sh`（13 项，见 §19.5），全绿；只跑 `cargo test` 不算过门。

## 9. 编译

- 工具链由 `rust-toolchain.toml` 固定；`cargo` 使用 workspace 默认 target。
- `web/` 是**独立 workspace**（根 `Cargo.toml` 用 `exclude` 排除），构建走手写的 `web/build.sh` +
  `wasm-bindgen` 流水线，不依赖任何前端构建器；web 的 fmt/clippy 必须单独跑（`env -u CARGO_TARGET_DIR`）。
- `[profile.release]` 是性能档位，任何"为了可复现"的改动都不得动它。

## 10. 负结论表决：有效票 / 弃权 / 矛盾

- 有效票 = 明确返回 NXDOMAIN 或 NODATA 且通过 bailiwick/一致性检查的应答；
  超时、SERVFAIL、被丢弃的私网答案、格式错误都**不是**有效票。
- quorum 分母是**有效票数**，不是候选上游数；只有 1 张有效票被采纳时计
  `negative_single_vote_accepted`，用于量化暴露面。
- 正负票矛盾时按"可用性优先"：至少一张有效正票 ⇒ 正；全负且达到 quorum ⇒ 负；
  否则 SERVFAIL（可归因），不得凭空合成 NXDOMAIN。

## 11. 计数与可观测口径

- 计数器必须**同代快照**：`/api/status`、`/api/status.counters`、`/api/snapshot`、`/metrics`
  必须来自同一次取数；跨代逐字段差分是禁止的。
- 硬等式（有单测）：`total == Σ client_rcode`、
  `total == hit + miss + policy_filtered_total + rule`
  （2.1.40 起本地策略应答不计 hit/miss；**2.1.42-B**：block/forceIp 等本地规则直答
  计入 `rule`，**不再**计 `miss` ⇒ `rule_hits` 与 `miss` 不重叠；`rule_hits` 仍是
  正交维度（allow/group 会真正发上游），**不得**把 `sum(rule_hits)` 再加进等式）、
  `hit_rate == hit / (hit + miss)`、
  `client_rcode["2"] == servfail_total == Σ servfail_reasons`、`cache_direct == hit`、
  `avg_latency_ms == query_latency_ms_sum / _count`。
- **2.1.41**：`qps` 的**唯一**推进点是数据面出口的 `note_client_query`（每客户端查询
  恰好一次，与 `total`/`neg_telemetry` 解耦）；`upstream_queries` 只数**真正发过上游**
  的查询（本地规则直答不计），因此恒 `<= upstream_requests`。
- "计数"与"开关"不得混用：`cache_direct_enabled` 不门禁任何计数；
  `rebind_blocked`（控制面）与 `cache_skipped_private_total`（数据面）不得相加。
- 0 值 KPI 必须能区分"真的是 0"与"没有这个口径"（键存在性 + 空对象语义）。

## 12. 配置写入语义

- 每个配置键必须同时在 `default_config()`、随包模板、`CFG_WRITABLE` 或 `CFG_READONLY` 中登记；
  新增键不登记归属 ⇒ 控制台不可达（门禁 `cfg_writable_covers_all_default_top_level_keys`）。
- 只读桶不是"未知键"：响应分 `ignored_keys` / `readonly_keys` / `readonly_detail` 三桶，
  每个只读键给**原因**与"要改怎么办"。
- 路径类键（`rule_local_file`/`rule_sub_file`/`cache_file`/`state_dir`）与进程级键
  （`state_persist`）永远只读：开放写入等于允许任意路径读写或制造"配置说开了、实际没开"。
- 保存顺序：校验 → 写盘（原子）→ 内存替换 → 规则索引重建 → reload hook；
  任一步失败按**原始字节**回滚。
- `config_version` 恒为 **3**，由 `migrate_cfg` / `migrate-config` 维护，属只读键；手工改会让
  "旧二进制跑新配置"的保护失效。

## 13. Web

- 字段契约以 `web/INTERFACE.md` 的标记块为准；前端 `model.rs` 是手写镜像，改字段必须同步。
- 页面只轮询按需端点，单一 2 s 调度器；失败退避 2→30 s；隐藏暂停。
- 渲染级断言优先于 rc：DOM 结构/id/数值格式都是契约（CSS 与 CDP 验收依赖）。

## 14. 规则与订阅

- 规则指纹（`rule_gen`）对**内容 + 顺序**敏感；规则变更必须让 `rules_gen` 变化并可观测。
- 订阅只接受 `https://`；SSRF 校验、逐跳重定向复检、16 MB 上限、禁代理。
- 订阅刷新内容未变时**不清缓存、不重建索引**；变化时整体替换并更新 `count/updated_at`。
- 规则真源（`state/rules.json`）三态：不存在 ⇒ 空规则；可解析 ⇒ 使用；存在但读不懂 ⇒
  **fail-closed**（请求 500，`rule_source_unreadable += 1`），绝不静默空集。

## 15. 版本

- 单一来源 = 根 `Cargo.toml` `[workspace.package] version`；七处必须同版本（§19.1）。
- 前端版本经 `web/build.rs` 注入；后端经 `env!("CARGO_PKG_VERSION")`；不得手写字符串。

---

## 16. 统一持久化事务（配置 / 规则真源 / 订阅明细）

### 16.0 布局

```text
<state_dir>/
├── commit.json          # 提交点：revision + 每个 part 的 {path,sha256,bytes}
├── rules.json           # 规则唯一真源
├── .lock                # 进程级 flock 独占锁
└── history/<rev>/       # 回退点（最少保底 1 代）
    └── <rev>.meta.json  # writer / committed_at / parts[]
```

`state_dir` 优先级：`--state-dir` > `config.json.state_dir` > `EBPDNS_STATE_DIR` > 默认
`/var/lib/ebpdns/state`。默认路径只在配置可信或显式给出时启用。

### 16.1 parts 与提交点

- 每个 part 可以是不同目录/不同文件系统；**先 content-fsync 每个 part，再原子替换 `commit.json`**，
  目录项由 rename 后的目录 fsync 保证。
- `commit.json` 是**唯一提交点**；读方只认它，`*.tmp` 一律忽略。
- part 的 `sha256` 来自提交点记录，`bytes/mtime_s` 来自现场 `stat`；两者不一致时端点可直接看出。

### 16.2 任何持久化写者不得绕过

- 写 `config.json` / `rules.json` / 订阅明细的在线路径必须走 `state_store` 的提交点。
- 例外（离线写回）：`install.sh --migrate-config`、`ebpdns migrate-config --export-legacy`。
  它们必须"先改真源、再重锚提交点"，失败按退出码 3/4 如实报告，**不得**默认落到生产路径。

### 16.3 读方四态

`load_state ∈ {Legacy, Committed, RolledBack, Torn}`：

- `Legacy`：没有 `commit.json`（旧布局/全新安装）；
- `Committed`：提交点校验通过，`serving_revision == revision`；
- `RolledBack`：当前世代损坏，已回退到上一代，`serving_revision != revision`；
- `Torn`：提交点与 parts 不自洽且无法回退，`torn=true` + 原因，`serving_revision=null`。

`load_state ∈ {RolledBack, Torn}` 时**不得**把 `revision` 当"正在服务的世代"。

### 16.4 幂等判据

- 幂等判断必须**整文件内容比较**（字节或 sha256），禁止子串标记、禁止"文件存在即视为已完成"。
- 迁移/写回补丁必须"跑第二遍零改动"；`patch235_docs.py` 一类脚本以 `run1>0 / run2=0` 验收。

### 16.5 可观测口径

- `/api/status.state_persist` 必须如实回报：`enabled/state_dir/revision/serving_revision/
  broken_revision/writer/parts/prev_generation_ok/history_generations/failed_commits/
  load_state/torn/torn_reason/lock_held/lock_note/rule_source_unreadable/note`。
- `failed_commits` 只数 IO/ENOSPC 等中止，`if-revision` 冲突（409）**不计入**。

### 16.8 单机单实例

**部署约束：单机单实例**（`state_dir` 独占锁；第二实例会被拒；隔离实例必须显式 `--state-dir`）。

- 同一个 `state_dir` 上的第二个实例启动时 `flock` 失败 ⇒ 拒绝启动（退出码 2）。
- 共享模式 `--allow-shared-state-dir` 只用于明确的调试场景，启动日志必须 WARN；
  `lock_held=false` + `lock_note` 非空是该模式的观测面。
- 审查/联调/A-B 实例必须显式给专用 `--state-dir`，不得沿用生产默认路径。

### 16.9 配置不可信时 fail-closed

- 配置文件存在但解析失败 ⇒ **拒绝启动**（退出码 2），除非同时给
  `--allow-bad-config --state-dir <目录>`。
- 理由：配置不可信时若回落到默认 `state_dir`，隔离实例会读写生产状态并执行回退逻辑。

### 16.10 规则真源三态与 `/api/config.rules`

- 真源不存在 ⇒ 空规则集（`[]`）；可解析 ⇒ 使用；存在但读不懂 ⇒ fail-closed（500）。
- `GET /api/config` 的 `rules` 必须由真源派生，不信任 `config.json` 里的旧值。

**规则契约：`/api/config.rules` 在任何情况下都恒为数组，由真源派生（无规则时为 `[]`，不是 `null`）。**

---

## 17. 原子写、fsync 顺序与生产护栏

### 17.1 四步顺序（不可交换）

```text
写 tmp（同目录，名字含 pid/seq 或固定 .tmp）
→ fsync(file)
→ rename(tmp, target)
→ fsync(dir)
```

- 只 `write` 不 `fsync(file)`：`kill -9` 后可能 rename 已生效而内容仍在 page cache ⇒ 0 字节/半截 JSON。
- rename 后不 `fsync(dir)`：目录项本身可能未持久化。
- 失败时**不得 rename**；tmp 由启动清理"只删不读"。
- 跨文件系统 `rename` 会 `EXDEV`：part 必须写在自己的目录内，禁止跨设备 rename。
- **2.1.36（D 批）**：四步协议全树只有**一份**实现 ——
  `crates/ebpdns-fs/src/lib.rs::atomic_write_with`。各调用点只通过 `WriteOptions`
  声明自己的 tmp 命名 / 失败清理 / 建父目录 / 权限位策略，**不得再复制协议本身**。

### 17.2 `*.tmp` 规则

- 读方**永不读** `*.tmp`（manifest/snapshot/WAL/commit 同理）。
- 启动清理只删两类：`*.tmp`、未被当前 manifest/提交点引用的孤儿；**永不删**被引用的文件与 `.v1.bak`。
- 损坏现场保留为 `*.corrupt.<unix_ms>`，只写一次，读方不读。

### 17.3 生产护栏（prod guard）

- 压测/隔离脚本必须**硬拒绝**生产端点：DNS 53、API 8353、生产 `state_dir`；
  示例：`scripts/f216-ladder.sh` 的硬断言、`t-conc50.py` 要求显式 `--state-dir/--api/--dns-port`。
- 任何"自动发现配置"的脚本都不得把缺省值解析成生产路径；缺参数 ⇒ 报错退出，不得猜。
- 文档中的复现命令必须能在隔离实例上原样执行，不要求读者先改生产。

### 17.4 可观测

- 落盘失败必须 ERROR + 计数/字段（不静默）；恢复丢弃必须分 `expired/legacy/failed` 三计数。
- 文件级损坏（整个文件不可解析）至少让 `failed >= 1`，且只反映**本次启动**。

---

## 18. 缓存持久化 v2（快照 + WAL）

### 18.1 文件与格式

| 文件 | 格式 |
|---|---|
| `<cache_file>` | manifest：magic `EBPC`、version 3（2.1.46 起；52 B 头、`snap_bytes: u64`）、flags（`CLEAN_SHUTDOWN` / `MIGRATED_FROM_V1`）、快照名/字节/CRC、WAL 段列表、durable seq；上限 8 KiB。**读方兼容 version 2（48 B 头、u32 snap_bytes）**，写方只写 version 3 |
| `<base>.snap.<seq>` | `EBPCSNP2` + 64 B 头 + 记录（12 B 开销 + 记录级 CRC32C）+ `EBPCEOF2` 尾 40 B |
| `<base>.wal.<base_seq>` | `EBPCWAL2` + 32 B 头 + `PUT/EVICT/CLEAR/COMMIT`（9 B 记录头 + CRC32C） |
| `<base>.v1.bak` | v1 JSON，永不自动删除 |
| `<base>.lock` | `flock(LOCK_EX\|LOCK_NB)` 单写者 |

WAL 容量参数：`WAL_FSYNC_MS=1000`、`WAL_BATCH_MAX_EVENTS=4096`、`WAL_BATCH_MAX_BYTES=256 KiB`、
`JOURNAL_RING=8192`、`MAX_RECORD_BYTES=1 MiB`、`MAX_WAL_SEGMENTS=2`。
快照阈值：`COMPACT_MIN_BYTES=2 MiB`（**2.1.37 起**；2.1.36 及以前为 8 MiB）、
`COMPACT_MIN_INTERVAL_S=1800`、条目变更比例闸门 `COMPACT_CHANGE_PERMILLE=125`
（12.5%，只在 `snap_bytes > 2 MiB` 时生效）。

### 18.2 WAL 总序（不可回退）

- `seq` 分配与事件入队必须在**同一临界区**（缓存锁 + journal 总序锁），保证入队顺序 == `seq` 顺序。
- 恢复时按 `seq` **有序合并/去重**；`seq` 回退**不再判损坏**，不得按尾部截断（旧实现会静默丢 0.75–59%）。
- 只有 CRC 失败/结构不完整才截断；截断条数记日志 `tail_records`，不混入 `failed`。

### 18.3 恢复冲突与可见集

- manifest 指向的快照 + 其后的完整 WAL 记录构成可见集；快照 seq 之后的记录按 seq 合并。
- 同一 seq 重复 ⇒ 去重；不同 seq 但同 key ⇒ 后者胜（按 seq 顺序）。
- 恢复只承接**未过期**条目；`persist_ttl` 决定是否复活过期条目。

### 18.4 退出终态（顺序不可换）

```text
停止接新事件 → drain 已入队事件到 WAL 并 fsync
→ 写终态快照（全量）并 fsync
→ 写 manifest（FLAG_CLEAN_SHUTDOWN）
→ （可选）按阈值 compact
```

- 终态快照失败 ⇒ **保留旧 manifest + 全量 WAL**（可恢复、不静默），不得先写 manifest 指向旧快照。
- 退出等待上限 10 s（磁盘卡死不得无限等）；`cache_save_interval=0` 时只走"退出写全量快照"。

### 18.5 快照年龄策略

- 快照按时间重写：节拍 = `min(1800 s, TTL/2)`，`TTL = max(ttl, ttl_max)`；TTL 未配置 ⇒ 1800 s；
  下限 5 s（避免写盘风暴）。
- `/api/status.cache.persist.snapshot_age_s` = `now − 快照 mtime`；v1/取不到 ⇒ 0。
- 恢复命中率取决于 `snapshot_age_s` 与 TTL 的关系，**不是** `cache_save_interval`：
  `snapshot_age_s ≤ TTL/2` ⇒ 重启后 5 s 内命中率与重启前基本一致（实测差 ≤ 5 pp）。

### 18.6 丢失率口径（唯一）

```text
loss = (快照头 snap_entries − 恢复后 used_live) / 快照头 snap_entries
```

- `used_live` = 未过期条目数；**2.1.43-B 起**恢复后该值 = **实际插入缓存的条数**
  （TinyLFU 恢复只灌 main 段，被挤出的 ≈1% window 段计入 `restore_drops.window_unpersisted`，
  因此上式已经包含这一项）；`entries`/`cache.used` 是内存条目数（含未清理过期项），**不能**当分母/分子。
- 非优雅退出丢失窗口 = WAL fsync 间隔 ≤ 1 s；`cache_save_interval=0` 时 = 整个运行期（只在优雅退出落盘）。
- `restore_drops.expired/legacy/failed/window_unpersisted` 是记录条数，不是字节数；`legacy` 在 v2 下恒 0。

### 18.7 与统一事务隔离

- 缓存**不是** `state_store` 的 part：不写 `commit.json`、不写 `history/`、不推进 `state_persist.revision`。
- 两套锁互不复用：缓存 `flock(<base>.lock)` 与状态目录 `flock(<state_dir>/.lock)` 独立。

### 18.8 回滚

- 数据回滚：恢复 `.v1.bak` 后删除 `.snap.*` / `.wal.*` / `.manifest.tmp`，再启动。
- 紧急回滚：`EBPDNS_CACHE_FORMAT=v1` 强制走 v1 读写；读不出 v2 manifest 时起动空缓存（不崩）。
- 旧二进制读 v2 manifest ⇒ ERROR + 空缓存（不崩），下一次落盘会覆盖成 v1 JSON。

---

## 19. 文档一致性

### 19.1 六张受门禁保护的表

| # | 表 | 权威来源 | 门禁 |
|---:|---|---|---|
| 1 | 版本七处 | 根 `Cargo.toml` | `_version_consistency.py` |
| 2 | 接口键集（status/counters/rules/metrics/persist/pipeline/qtype） | 隔离实例 + `constants.rs` | `_interface_keys.py` / `_doc_counts.py` |
| 3 | 配置键（模板 73 + 运行期 2 = 75） | 模板 + `default_config()` + `migrate_cfg()` | `_config_keys.py` |
| 4 | 清单作用域四行 + prod 文件数 | 真实包产物 | `_doc_counts.py`（`--require-pkgs`） |
| 5 | `check_all` 13 项 | `scripts/check_all.sh` | 脚本自身 |
| 6 | 文档契约（2 条 × 4 文件 + 清单 1 文件 + 提案） | 本文件 / PACKAGING | `_version_consistency.py` |

### 19.2 数字必须实测

- 文档里任何键数/行数/指标数/类型数/门禁项数都必须来自**当次实测**，并写成可被脚本重算的形式。
- 禁止"当前树有多少个文件"这类常数；一律用清单行数/包内实测/标记块行数反算。
- 改错数字必须变红、改回必须变绿（负向对照由 `check_all_selftest.sh` 自动跑）。

### 19.3 订阅活源口径

- `rule_subscriptions[].count` 是**活源**：由每次订阅刷新写回，不是静态配置；
- `/api/rules.subscriptions[].count` 与 `/api/config.rule_subscriptions[].count` 同源；
- `total_subscription` = 各 `count` 之和；`total_all == /api/pipeline.rules`；
- 只读 `/api/rules.total` 得到的是**本地逐条**数，订阅规模再大也不会进这个数。

### 19.4 文档契约（逐字）

- 四条文件（README / INTERFACE / PACKAGING / 本文）各含"单机单实例"与"规则恒为数组"两条措辞；
- PACKAGING 另含"清单作用域"一条；
- 两份 `docs/PROPOSAL-*.md` 必须写"仅提案，本版不实现"，且不得出现版本锁定承诺。
- 措辞只允许加粗/行内代码（门禁会去掉 `**` 与反引号后逐字比较），**不许改词序/换标点**。

### 19.5 门禁单入口

```bash
OFFLINE=1 RELEASE=1 JOBS=1 bash scripts/check_all.sh
```

13 项：版本+文档 / 文档计数 / 离线重建等价 / fmt / clippy（`--all-targets --offline -- -D warnings`）/ test / web_dist_freshness /
web fmt / web clippy / 接口键集 / 配置键集 / 安装矩阵 / install start 运行语义。
缺夹具（无二进制/无包产物/非 root）时打印 SKIP 而不是假绿；交付前必须让 SKIP 项在具备夹具的环境重跑。
