# ebpdns

**版本 v2.2.6**

ebpdns 是一个**单机、用户态**的本地递归 DNS 解析器 + Web 控制台：

- DNS 数据面全部在用户态完成（tokio 异步、UDP/TCP 双栈），DNS 报文编解码为自研实现，不依赖 hickory；
- 控制面是 HTTP REST + Leptos/WASM 单页控制台（五个页面：流水线 / 查询 / 配置 / 遥测 / 关于）；
- **不含内核态缓存**（历史版本已移除；旧配置里残留的未知顶层键按通用规则 WARN 并忽略，不改写配置）；
- 部署模型是**单机单实例**：一个 `state_dir` 只允许一个进程持有，第二实例启动即被拒。

本文只描述**当前实现真实具备**的能力与口径。所有键数、指标数、类型数均由
`scripts/_version_consistency.py` / `_doc_counts.py` / `_interface_keys.py` / `_config_keys.py`
对**实测值**做硬断言；包内清单由 `scripts/_pack_verify.py` 在出包时逐行校验。
文档不再写"历史版本当时是多少"。

---

## 1. 功能清单（只列实现里真有的）

**上游与解析**

- **四种上游协议**：UDP、TCP、DoH（HTTP/1.1 + **HTTP/2 多路复用**）、DoH3（自研最小 HTTP/3 + QPACK）。
  **2.2.0 起 DoT / DoQ 上游已移除**：`tls://` / `dot://` / `quic://` / `doq://` 与 `proto=dot|doq`
  在**库层解析 / `check-config` / 启动 / API** 四个入口一律拒绝，绝不静默降级成 UDP
  （迁移见 [`docs/MIGRATION-2.2.0.md`](docs/MIGRATION-2.2.0.md)）。
- 解析编排：CNAME 链与深度门禁、bailiwick 锚定、NXDOMAIN/NODATA quorum 表决（分母是**有效票**）、
  规则代际（`rule_gen`）写回门禁、双栈 fallback、候选 IP 测速择优、预取、熔断、单飞（single-flight）、
  逐上游 p90 对冲、自适应超时、RFC 8020 父域推断、serve-stale、连接池预热。
- 上游选路：按 `eff_lat / max(1, weight)` 排序；`upstream_max_inflight` 单上游在途闸门（先于连接池生效）。
- EDNS：OPT/ECS、128 B Padding、出站 bufsize 钳制、0x20 大小写熵（按上游自适应降级）。
- 重绑定防护：上游应答里的私有/保留地址 A/AAAA 答案丢弃且**不写缓存**，并计入
  `counters.cache_skipped_private_total`（数据面）——与 `counters.rebind_blocked`（控制面）严格分开。

**缓存**

- **唯一策略**：`s3fifo`（S3-FIFO，SOSP'23；S/M/G 三 FIFO + 2-bit 频率 + 8 分片 + 每分片 TTL 堆）。
  **2.2.0 起 `lru` / `tinylfu` / `partitioned` 全部移除**：`check-config` rc=2、启动 exit 2、
  `PUT /api/config` 400，并提示 `ebpdns migrate-config`。策略不可热切换（没有第二种策略），
  容量/字节预算/负配额可热重载。
- TTL 钳制（`ttl`/`ttl_min`/`ttl_max`）、负缓存上限（`neg_ttl_max`）、serve-stale（`stale_ttl`）。
- 持久化 v2：**二进制快照 + WAL**（`EBPCSNP2` / `EBPCWAL2`，记录级 CRC32C），丢失窗口 ≤ 1 s（WAL 每 1 s
  `fdatasync`）；`persist_ttl` 三段语义；快照按时间重写，节拍 `min(1800 s, TTL/2)`；保留 v1 回滚路径。

**规则**

- 动作：`block` / `allow` / `group` / `forceIp`；匹配：精确、`*.` 通配、中缀通配、`re:` 正则。
- 本地规则（`rules_local.json`）+ 订阅规则（`rules_sub.json`）；订阅支持 hosts / dnsmasq / SmartDNS /
  Surge / Clash / Adblock 文本；订阅只接受 `https://`，带 SSRF 校验、逐跳重定向复检、16 MB 上限。
- 订阅每小时刷新（`rule_sub_interval=3600`，可调）；内容未变不清缓存、不重建索引。
- `block` fail-closed；规则真源三态解析，真源存在但读不懂 ⇒ 请求 500，绝不静默空规则集。

**管理面与可观测**

- HTTP REST：**21 条路径 / 27 个方法+路径组合**；token 鉴权、写操作 CSRF/同源校验、读端点 Origin 校验、
  CSP 等安全响应头。
- 五个控制台页面；前端**单一 2 s 调度器**、按路由取数、标签页隐藏暂停、失败退避 2→30 s。
- `/metrics` **66 个 HELP family**（hot；冷态 64，两个上游延迟 family 懒加载；含进程 RSS/虚拟内存/线程/fd、`state_missing_parts` 与 14 个 `ebpdns_doh_h2_*`）；
  `/api/status.counters` **38 键**；`/api/status` **36 键**；`/api/config` **82 键**；
  `/api/cache/stats` **35 键**；`/api/rules` **6 键**；`/api/pipeline` **7 字段**。
- 500 条实时事件环（`seq` 游标增量拉取）；客户端可见 SERVFAIL 5 档归因
  （`encode_failed` / `no_upstream` / `panic` / `upstream_no_answer` / `upstream_timeout`）。

**持久化与部署**

- 统一持久化事务：配置 + 规则真源 + 订阅明细走 `state/` 的 `commit.json` + `history/`；
  任何持久化写者都不得绕过；`*.tmp` 一律忽略；`if-revision` 乐观并发，冲突 409。
- 缓存 v2 与 `state_store` **完全独立**（缓存不推进 `state_persist.revision`）。
- prod 包 26 个文件（见 `docs/PACKAGING.md`）；`install.sh` 支持安装 / 启动 / 卸载 / 迁移 / 干净机降级。

---

## 2. 快速安装

### 2.1 前置条件

| 项 | 要求 / 缺失时的行为 |
|---|---|
| 架构与 libc | Linux x86_64，**glibc ≥ 2.34**（交付 bin 最高符号 `GLIBC_2.34`）。安装前用临时副本执行 `--version` 预检，失败即 rc=1 并打印缺失符号；**不提供 musl 静态构建**。 |
| root | 必须。非 root 直接 rc=1（演练用 `EBP_INSTALL_ROOT` 前缀到临时目录）。 |
| systemd | **可选**。`systemctl` 不存在或系统非 running/degraded/starting ⇒ 只装文件并打印手动启动命令，rc=0。 |
| `passwd` 包（`groupadd`/`useradd`） | **可选**。按 `groupadd→addgroup→直接追加 /etc/group`、`useradd→adduser→直接追加 /etc/passwd` 分级回退；全失败只 WARN：`chown` 退化 `root:root`，unit 退化 `User=root`。 |
| 端口 | `dns_port`（默认 53）与 `api.port`（默认 8353）必须空闲。被**别的进程**占用 ⇒ rc=1 且在任何写操作之前退出；被**自家旧实例**占用时 `start` 默认先停后启（rc=0）。 |
| 解包权限 | 用保留权限的方式解包（Linux `tar -xzf`）。包内二进制缺执行位时安装器会自愈（临时 0755 副本）。 |
| 磁盘 | 二进制 + 前端约 30 MB；缓存文件按 `cache_size` 估算（每条约 117 kB 常驻，出厂 131072 条约 15 GB 投影，小内存机请下调）。 |

### 2.2 安装动作与开关

```bash
tar -xzf ebpdns-2.2.6-prod.tar.gz
cd ebpdns-2.2.6
sudo ./install.sh                     # 安装 + enable，不自动启动
sudo ./install.sh start               # 安装 + enable + 启动（旧实例先停后启）
sudo ./install.sh --dry-run start     # 只打印动作，不改系统
sudo ./install.sh uninstall           # 卸载，保留 /etc/ebpdns 与 state_dir
sudo ./install.sh --uninstall --purge # 连配置与 state_dir 一起删除
sudo ./install.sh --help              # 全部开关与退出码
```

| 开关 | 语义 |
|---|---|
| `--strict-config` | 配置预检/装后复核报 ERROR 时中止（退出码 2） |
| `--migrate-config` | 已有配置**只做加法**补齐缺失键；写前备份 `config.json.bak.<ts>` |
| `--state-dir <DIR>` | 仅对 `--migrate-config` 生效：显式透传给 `migrate-config`；缺省只用配置里的 `state_dir`，两者都没有 ⇒ rc=3 且零写入 |
| `--adopt-new-defaults` | 备份后用包内模板覆盖配置（会丢本地改动） |
| `--restart` | 显式先停后启（`start` 的默认行为已如此） |
| `--keep-running` | 只更新文件，不停止/不重启进程（pid 不变，下次重启生效） |
| `--dry-run` | 只打印计划（账号/目录/文件/停止或启动），仍做只读预检 |
| `--purge` | 仅与 uninstall 同用：删除 `/etc/ebpdns` 与 `state_dir` |
| `-h`, `--help` | 打印用法后退出，不写任何文件 |

**退出码**：`0` 成功（含账号降级、无 systemd、旧实例先停后启、`--keep-running` 跳过重启）；
`1` 前置失败（非 root / 缺 `bin/ebpdns` / 用法错误 / 端口被别的进程占用 / 旧实例停不掉 /
GLIBC 不满足 / 系统命令失败）；`2` 布局预检失败或 strict 配置检查失败；
`3` `--migrate-config` 未落盘（无 `state_dir` 且未给 `--state-dir`）；
`4` 配置已写回但提交点未重锚（最常见：服务在运行、持有 `state/.lock`）。

---

## 3. 配置要点

### 3.1 键数是动态的

| 口径 | 数量 | 说明 |
|---|---:|---|
| 随包模板 `packaging/etc/ebpdns/config.json` | 79 | 与 `default_config()` 逐键一致；含 `rules` 镜像键 |
| 运行期 `migrate_cfg()` 注入 | 2 | `rule_local_file` / `rule_sub_file`（按 `config.json` 同目录推导，**只读**） |
| `GET /api/config` | **81** | 模板 79 + 运行期 2；`rules` 恒为数组 |
| 磁盘 `config.json` | 通常 80 | v2→v3 迁移把 `rules` 从文件删除（真源在 `state/rules.json`），运行期再补回内存 |
| 可写键 | 71 | `CFG_WRITABLE` 的非别名额（= 81 − 10 只读；另有 5 个受支持别名，见下且**不计入**键集） |
| 只读键 | 10 | `config_version` / `listen` / `api` / `web_root` / `rule_local_file` / `rule_sub_file` / `cache_file` / `dns_port` / `state_dir` / `state_persist` |

`/api/config.rules` 是**镜像键**：真源是 `state/rules.json`，读取时派生，写入时整体替换（逐条校验，非法即 400 且零副作用）。

**受支持别名（可写、不回显）**：`cb_fails`（= `circuit_fails`）、`cb_open_s`（= `circuit_open_s`）、
`warmup_enabled` / `warmup_queries` / `warmup_timeout_ms`（= `warmup.*` 的扁平形式）。

**未知顶层键（通用规则）**：历史版本移除的键与拼写错误的键一样，启动/`check-config` 只 WARN
并忽略，**不逐一点名、不改写配置文件**；`config_version` 保持 3。

### 3.2 归属速查

| 键 | 归属 | 语义 |
|---|---|---|
| `rules` | 可写 | 规则镜像数组；恒为数组，真源派生 |
| `rule_local_file` | 只读 | 本地规则文件路径，由服务端推导；开放写入等于允许任意路径读写 |
| `rule_sub_file` | 只读 | 订阅规则文件路径，同上 |
| `listen` / `api` / `web_root` | 只读 | 监听/控制台/静态资源段；改后需重启 |
| `cache_file` / `state_dir` | 只读 | 路径类；改后需重启，并同步 systemd `ReadWritePaths=` |
| `dns_port` | 只读 | 旧键，等价 `listen.*`，需要重建 socket |
| `state_persist` | 只读 | 进程级启动参数；进程内改不生效 |

完整 **82 键**表（API 口径 = 80 个随包模板键 + `rule_local_file` / `rule_sub_file` 两个运行期注入的只读路径键）见 [`docs/INTERFACE.md`](docs/INTERFACE.md) §4.1。

> **直接编辑 `config.json` 后重启的安全姿势（2.2.0 终审实测）**：已存在 `state/commit.json`
> 的实例会把"与提交点不一致的 config part"判为**撕裂**，启动时可能**回滚到上一代**
> （2026-11-17 生产实测：直接改文件后重启被回滚，值变回旧值）。正确做法二选一：
> ① 用 `PUT /api/config`（推荐，提交点与磁盘一起更新）；② 停服后编辑文件，先运行
> `ebpdns migrate-config --config /etc/ebpdns/config.json`（把外部改写**重锚**到当前提交点），
> 再 `systemctl start`。只读段（`listen` / `api` / `cache_file` / `state_dir` / `web_root` /
> `config_version` / `state_persist`）只能走 ②。

### 3.3 配置键全表（机器门禁解析）

> 本表由 `crates/ebpdns-cache/tests/doc_consistency_tests.rs::readme_config_table_defaults_match_packaging_template`
> 逐行解析（默认值 == 随包模板）；下方两张可达性表由 `crates/ebpdns-resolver/tests/a15_key_coverage.rs::readme_key_tables_match_code`
> 解析。改默认值/归属必须同步本表，否则 `cargo test` 直接红。

**配置键全表（含历史键的最终口径；`check-config` 覆盖的键见「`ebpdns check-config`」一节）**：

| 键 | 类型 | 默认 | 口径 / 生效方式 |
|---|---|---|---|
| `cache_size` | 整数 | `131072` | 缓存条目上限（≥16）。**热切换不清空**：仅容量变化走增量 resize（增长一条不丢、收缩按当前策略淘汰）。 |
| `cache_policy` | 枚举 | `s3fifo` | **唯一合法值 `s3fifo`**（S3-FIFO，SOSP'23：S/M/G 三 FIFO + 2-bit 频率 + 8 分片 + 每分片 TTL 堆；抗扫描且小容量更省 miss）。**2.2.0 起 `lru` / `tinylfu` / `partitioned` 全部移除**：`check-config` rc=2、启动 exit 2、`PUT /api/config` 400，并提示 `ebpdns migrate-config`（它会把该键就地改写为 `s3fifo`）。 |
| `cache_bytes` | 整数（字节） | `268435456` | **2.1.49-p3**：字节预算（0 = 关闭；仅 `s3fifo` 生效）。超预算时按条目估算大小淘汰，防大 TXT/长 CNAME 链打爆内存。 |
| `max_entry_bytes` | 整数（字节） | `65536` | **2.1.49-p3**：单条大小上限（0 = 关闭；仅 `s3fifo` 生效）。超限条目不缓存（计入 `cache.summary.rejected_large`）。 |
| `cache_save_interval` | 整数（秒） | `60` | 周期落盘间隔（`0` = 只在优雅退出时落盘）。见 README「出厂默认的已知取舍」与 `docs/PACKAGING.md` §1c 的落盘边界。 |
| `ttl` / `ttl_min` / `ttl_max` | 整数（秒） | `600` / `5` / `600` | 答案 TTL 与钳制区间（2.1.50 起 300 → 600：上游 TTL 常为 300-600，旧的 300 会白丢一半新鲜度）。 |
| `neg_ttl_max` | 整数（秒） | `300` | 负缓存 TTL 硬上限（`0` = 关闭上限；2.2.0 A/B 后 120 → 300，与 2.1.50 推荐一致：120 档 qps −1.8%、命中 −0.6pp）。 |
| `serve_stale` / `stale_ttl` | 布尔 / 整数 | `true` / `3600` | RFC 8767 serve-stale（**负缓存不走 serve-stale**；2.1.50 起兜底窗口 7 天 → 1 小时）。 |
| `cache_persist` / `persist_ttl` | 布尔 / 整数 | `true` / `864000` | 缓存落盘与持久化窗口（出厂默认 864000 = 本地保存 10 天）；写盘为崩溃安全的四步写（`write→fsync(file)→rename→fsync(dir)`）。**`persist_ttl=0` = 严格遵守文件里的绝对到期时间**（停机时长计入 TTL，已过期丢弃）；`>0`（出厂 864000）是**显式 opt-in** 的"统一恢复 TTL"，但装配层会收敛为 `min(persist_ttl, max(ttl, ttl_max))`，避免复活条目 10 天不刷新（见 `docs/CONFIG-RECOMMENDED.md`）。 |
| `prefetch` | 布尔 | `true` | 命中后异步预取（固定只用 1 个上游）。 |
| `speed_test` / `ip_speed_check` | 布尔 | `true` | 候选 IP 测速择优（EWMA + 加权随机）。 |
| `ip_speed_probe` | 字符串 | `both` | `udp53` / `tcp443` / `both`（`both` = 两种都探，取更优者）。 |
| `fallback` | 布尔 | `true` | `true` = 首选 N 个并发、失败后依次尝试后备上游；`false` = **只**并发首选的那 N 个，全失败即 SERVFAIL（不启用后备上游）。 |
| `max_parallel_upstreams` | 整数 | `4` | 并发上游数**上限** N（按延迟取最快 N 个；自适应并发先发 1 个，超 `hedge_after_ms` 未回再补齐到 N）。2.2.0 A/B：3 档 qps −1.6%。 |
| **`upstream_max_inflight`** | 整数 | `32` | 单上游在途闸门（见上表与「高并发与排队治理」）。 |
| `timeout_ms` | 整数（ms） | `1500` | 单次上游查询超时（也是**自适应超时的上限**：`adaptive_timeout_max_ms` 后端无此键，恒取本值）。 |
| `nxdomain_quorum` | 整数 | `2` | 负结论表决所需有效票数（`negative_single_vote_accepted` 计数用于量化单票暴露面）。**2.2.5（P2-A2）**：所有有效票都是负票、票源数 ≥ q 但 NXDOMAIN/NODATA 种类分歧（任一种都未单独达标）时，按可得票数**降级为 NODATA**（不登记 RFC 8020，计 `negative_mixed_degraded`）；票源 < q 时仍 fail-closed SERVFAIL。仅 2 个上游且对端 NX/NODATA 不一致时不再永久 SERVFAIL。 |
| `udp_workers` | 整数 | `0` | 每地址 UDP socket / 收包循环数（`0`=自动、`1`=旧行为）。**重启级**键（`rebind` 不改既有地址的 worker 数）。 |
| `single_flight` | 布尔 | `true` | 同 `CacheKey` 并发 miss 合并为一次上游扇出（`false` 逐位退回旧行为）。 |
| `warmup.enabled` / `warmup.queries` / `warmup.timeout_ms` | 布尔 / 整数 / 整数 | `true` / `2` / `3000` | 上游连接池预热（扁平别名 `warmup_enabled` / `warmup_queries` / `warmup_timeout_ms`）。 |
| `config_version` | 整数 | `3` | 配置 schema 版本（见「配置 schema 版本与迁移」）。**2.1.22 起为 3**：新增 `state_dir` / `state_persist`，并把规则唯一真源移到 `state/rules.json`（2→3 迁移先做**加法导入**，再删除 `config.json` 的 `rules` 镜像键）。 |
| `state_dir` | 字符串 | `/var/lib/ebpdns/state` | **2.1.22 新增**：统一持久化事务的 `state/` 目录（`commit.json` + `history/` + 规则真源 `rules.json`）。路径类**只读**键；自定义路径需同步改 systemd unit 的 `ReadWritePaths=`（默认值已覆盖 `/var/lib/ebpdns`）。 |
| `state_persist` | 布尔 | `true` | **2.1.22 新增**：统一持久化事务开关（`config` / `rules` / `subscriptions` 同一提交点）。进程级启动参数 ⇒ 改了要重启；置 `false` 逐位退回 2.1.21 的各写者原子写。现场见 `/api/status.state_persist`。 |
| `tls_min_version` | 枚举 | `1.2` | **2.2.0 新增**：出站加密上游（DoH / DoH3）的 TLS 版本下限，只接受 `1.2` / `1.3`。DoH3（QUIC）**恒 1.3**（配 `1.2` 时自动按 1.3 处理）。 |
| `tls_ca_file` | 字符串（路径） | `""` | **2.2.0 新增**：自定义 CA（PEM，可含多张证书；空 = 只用系统根）。**fail-closed**：不可读 / 不是 PEM / 不含 `CERTIFICATE` ⇒ `check-config` rc=2、启动 exit 2、`PUT /api/config` 400。 |
| `tls_use_system_roots` | 布尔 | `true` | **2.2.0 新增**：是否加载系统 CA bundle（可与 `tls_ca_file` **并存**）。置 `false` 时必须给出 `tls_ca_file`，否则没有任何信任根（拒绝启动）。**证书链 + 主机名/SAN + 有效期始终严格校验，没有"跳过校验"开关**。 |
| `rule_local_file` | 路径 | `<config.json 同目录>/rules_local.json` | **只读（运行期注入）**：`migrate_cfg()` 按配置同目录推导，**不在**随包模板/`default_config()` 里；开放写入等于允许任意路径读写 ⇒ 归 `CFG_READONLY`。要改请编辑配置文件后先 `migrate-config` 重锚再重启（见 §3.2 注）。 |
| `rule_sub_file` | 路径 | `<config.json 同目录>/rules_sub.json` | **只读（运行期注入）**：订阅明细真源路径，同 `rule_local_file` 归 `CFG_READONLY`；`state_persist.parts` 含它。 |
| `rules` | 数组 | `[]` | **可写（镜像键）**：2.1.22 / schema v3 起不落盘（规则真源 = `state/rules.json`），但 `default_config()` 仍有该键 ⇒ `GET /api/config` 回显；`/api/config.rules` 恒为数组。**2.1.31 核准：它正是 `/api/config` 比落盘 `config.json` 多的那 1 个键。** |

#### 配置键可达性分类（**2.1.21 / DEF-220-02 / A-15：双向机器门禁**）

> 判据：`CFG_WRITABLE`（后端可写白名单）里的每个键，必须**要么**在控制台有写路径，
> **要么**出现在下面的「仅 API / 配置文件可改」表里。两侧由
> `crates/ebpdns-resolver/tests/a15_key_coverage.rs` **双向**断言，
> 改一边不改另一边即红（表格本身也被解析，因此"文档漂移"同样会红）。

#### 界面可改（有控件）

| 键 | 控件 | 取值区间（后端 `CONFIG_RANGES`） |
|---|---|---|
| `cache_size` | 数字 | 16 – 4194304 |
| `cache_save_interval` | 数字（**2.1.21 新增控件**） | 0 – 86400 |
| `ttl` / `ttl_min` / `ttl_max` | 数字 | 0 – 604800 |
| `neg_ttl_max` | 数字（**2.1.21 新增控件**） | 0 – 86400 |
| `stale_ttl` / `persist_ttl` | 数字 | 0 – 604800 / 0 – 31536000 |
| `prefetch_trigger` | 数字（**2.1.21 新增控件**） | 0 – 604800 |
| `prefetch_target` | 数字（**2.1.21 新增控件**） | 0 – 604800 |
| `prefetch_interval` | 数字（**2.1.21 新增控件**） | 1 – 86400 |
| `prefetch_max` | 数字（**2.1.21 新增控件**；**2.1.49-p2 起**每轮补扫预算 = `max(prefetch_max/4, 64)`，与命中待办队列解耦） | 1 – 1000000 |
| `speed_interval_ms` / `speed_timeout_ms` / `ip_speed_cache_ttl` | 数字 | 100 – 600000 / 1 – 60000 / 0 – 86400 |
| `max_parallel_upstreams` / `upstream_max_inflight` | 数字 | 1 – 64 / 0 – 4096 |
| `timeout_ms` | 数字 | 1 – 60000 |
| `nxdomain_quorum` | 数字（**2.1.21 新增控件**） | 1 – 64 |
| `udp_workers` | 数字 | 0 – 64 |
| `rfc8020_max_labels` | 数字 | 1 – 127 |
| `warmup_queries` / `warmup_timeout_ms` | 数字 | 1 – 8 / 1 – 60000 |
| `edns_udp_size` | 数字 | 512 – 65535 |
| `edns_client_max_size` | 数字（**2.1.21 新增控件**） | 512 – 65535 |
| `health_check_interval` | 数字 | 0 – 86400 |
| `health_probe_timeout_ms` | 数字 | 1 – 60000 |
| `rule_sub_interval` | 数字 | 0 – 604800 |
| `circuit_fails` | 数字 | 1 – 1000 |
| `probe_timeout_ms` | 数字（**2.1.21 新增控件**） | 0 – 60000 |
| `hedge_after_ms` | 数字（**2.1.21 新增控件**） | 1 – 60000 |
| `adaptive_timeout_min_ms` | 数字（**2.1.21 新增控件**） | 1 – 60000 |
| `adaptive_timeout_k` | 数字（**2.1.21 新增控件**，浮点键 0.1–1000，默认 8.0） | — |
| `circuit_open_s` | 数字（浮点键，前端自带区间 1–86400） | — |
| `circuit_open_max_s` | 数字（**2.1.21 新增控件**，浮点键 1–604800） | — |
| `rating_sr_floor` / `hedge_slowest_factor` | 数字（浮点键） | — |
| `log_level` / `log_format` / `ip_speed_probe` / `bootstrap_dns` / `health_probe_domain` | 枚举 / 文本 | — |
| `prefetch` / `serve_stale` / `cache_persist` / `speed_test` / `fallback` / `ipv4_first` / `ipv6` / `prefer_ipv4` / `padding` / `rebind_protection` / `edns` / `dnssec_0x20` / `ip_speed_check` / `single_flight` / `rfc8020_infer` / `warmup` | 开关 / 对象 | — |
| `upstreams` / `rules` / `rule_subscriptions` | 列表编辑器 | — |

#### 仅 API / 配置文件可改

> 这些键在 `CFG_WRITABLE` 内（可直接 `PUT /api/config`，或编辑
> `/etc/ebpdns/config.json` 后重启），但控制台**没有控件** —— 原因是它们
> **没有可 clamp 的数值区间**（枚举 / 字符串 / 布尔 / 对象 / 数组），或语义上
> 属于"部署形态"而非"运行调参"。**2.1.21 起没有任何"有区间却无控件"的键**
> （那正是 DEF-220-02 的缺陷形态）。

| 键 | 类型 | 默认 | 为什么不做控件 |
|---|---|---|---|
| `cache_bytes` / `max_entry_bytes` | 整数（字节） | `268435456` / `65536` | **2.1.49-p3（S3-FIFO）**：字节预算 / 单条上限（0 = 关闭）。数值有区间但**控制台暂无控件**（先走 API / 配置文件）；超限条目拒绝缓存，预算超限按条目大小淘汰 |
| `negative_pct` | 整数（%） | `20` | **2.1.49-p5**：负缓存配额（0 = 不限制）。控制台暂无控件；超配额时优先淘汰 NXDOMAIN/NODATA 条目，避免负缓存挤空正缓存 |
| `cache_policy` | 枚举 | `s3fifo` | **2.2.0 起控制台不再提供控件**：服务端固定为 S3-FIFO（唯一合法值），只读展示在配置页「只读 / 服务端管理项」；`PUT /api/config` 仍只接受 `s3fifo`，其它值 400（旧配置由 `migrate-config` 归一）。 |
| `edns_client_subnet` | 字符串 | `""` | ECS 地址（`1.2.3.0/24`）；空 = 不外发 |
| `dnssec_cache_variants` | 布尔 | `true` | **阶段 3-14**：DNSSEC（EDNS `DO`）是否参与缓存键。`true` = 带 DO 的查询与不带 DO 的查询是**两条独立条目**（上游对 DNSSEC 感知的查询可能返回 `RRSIG`，共用条目会把 DNSSEC 记录串给普通客户端）；`false` = 退回旧行为（两者共用一条）。键编码：旧键 `[domain, qtype]`，DO 键追加 `"DO"` 元素，旧缓存文件照旧恢复为 `dnssec=false` |
| `ecs_cache_variants` | 布尔 | `false` | **阶段 3-14**：ECS 是否参与缓存键。**当前 ECS 不外发**：`edns_client_subnet` 只落配置，上游查询恒不带 ECS option（见 `crates/ebpdns-resolver/src/production.rs::spawn_one` 的 `build_query(..., ecs=None, ...)`）⇒ 置 `true` 只打一条 **WARN**（"ECS 未外发，键不按 ECS 分裂"），**不**按客户端子网分裂缓存（避免无意义碎片）。将来若真的外发 ECS，必须同时实现按规范化 subnet 的键变体 |
| `cb_fails` / `cb_open_s` | 整数 / 浮点 | `3` / `30` | `circuit_fails` / `circuit_open_s` 的**受支持历史别名**（v1.9.162 控制台用的是 `cb_*`）。控制台控件只挂在**权威名**上 ⇒ 这两个别名只能走 API / 配置文件（`validate_write` 对两套名字都校验）。**2.1.21 第 2 轮（DEF-221-07）**：它们此前被错列在「界面可改」表里，而门禁只查"控件 ⊆ 表"单向 ⇒ 漏过；现在门禁双向，本表才改对。 |
| `warmup_enabled` | 布尔 | `true` | `warmup.enabled` 的**扁平别名**（`apply_cfg` 真的读）。控制台控件挂在对象键 `warmup` 上 ⇒ 扁平别名只能走 API / 配置文件。 |
| `adaptive_parallel` | 布尔 | `true` | 自适应并发总开关（细调旋钮 `hedge_after_ms` 已有控件） |
| `adaptive_timeout` | 布尔 | `true` | 自适应超时总开关（细调旋钮 `adaptive_timeout_min_ms` 已有控件） |
| `dns_port` | 整数 | — | **只读**（旧键，等价 `listen`，改需重建 socket） |
| `config_version` | 整数 | `3` | **只读**（`migrate-cfg` 管理） |
| `state_dir` | 路径 | `/var/lib/ebpdns/state` | **只读（2.1.22 新增）**：统一持久化事务的 `state/` 目录（`commit.json` + `history/` + 规则真源 `rules.json`）。路径类键不开放写入；**自定义路径还要同步改 systemd unit 的 `ReadWritePaths=`**（默认值已覆盖 `/var/lib/ebpdns`，见 `packaging/systemd/ebpdns.service`）。 |
| `state_persist` | 布尔 | `true` | **只读（2.1.22 新增）**：统一持久化事务开关。进程级启动参数（`AppState` 的 store 句柄在启动时装配）⇒ 改了要重启；置 `false` 逐位退回 2.1.21 的"各写者各自原子写"。现场见 `/api/status.state_persist`。 |
| `listen` / `api` / `web_root` / `cache_file` / `rule_local_file` / `rule_sub_file` | 段 / 路径 | — | **只读**（只读段或服务端推导路径，见 `CFG_READONLY`） |
> **上表的默认值口径（2.1.19 起）**：一律以**根 `Cargo.toml` 所在源码树的
> `crates/ebpdns/src/main.rs::default_config()` 与 `packaging/etc/ebpdns/config.json`
> 为准**（两者逐键一致，有门禁）。2.1.18 及以前本表曾有 9 处过期值，已逐项对齐
> 实际出厂默认；2.2.0 起不再保留任何"旧策略可选"的表述。


---

## 4. 支持的类型（qtype 三分派）

判定单一来源 = `ebpdns_proto::constants`：`SUPPORTED_QTYPES`（受理）/ `qtype_must_reject`（拒绝）/
`qtype_passthrough`（其余透传）。数据面对每个查询走且只走一支。

### 4.1 受理并缓存（20 型）

`A NS CNAME SOA PTR MX TXT AAAA SRV`、`NAPTR`、`DS`、`SSHFP`、`DNSKEY`、`TLSA`、`CDS`、`CDNSKEY`、
`SVCB`、`HTTPS`、`URI`、`CAA`。这些类型会被真正解析、重新编码并写入缓存（非法 RDATA 丢弃该 RR，fail-closed）。

### 4.2 透传、不缓存（其余合法类型）

既不在受理名单、也不在拒绝名单的类型（含实验/私有类型、`MAILA(254)`/`MAILB(253)` 这类元查询）：

- 按请求原始 `u16` 组包发上游，响应只改 12 字节头 + 回显客户端 question 原始字节；
  **不解析、不重编码 RDATA、不读缓存、不写缓存、不做负缓存、不 serve-stale**；
- 规则仍**先判决**（未知类型不得绕过 block/allow/group/forceIp）；
- 计数：成功 = `miss` + `upstream_queries` + `passthrough_qtype_total`（不计 `error`）；
  失败另加 `error` + `servfail_total`（归因 `upstream_timeout` 等）。

### 4.3 一律拒绝（`NOTIMP`，12 类）

`TYPE0`、`NULL(10)`、`OPT(41)`、`RRSIG(46)`、`NSEC(47)`、`NSEC3(50)`、`NSEC3PARAM(51)`、
`TKEY(249)`、`TSIG(250)`、`IXFR(251)`、`AXFR(252)`、`ANY(255)`。
`opcode≠0` 与非 `IN` class 同样回 `NOTIMP`；所有拒绝路径**绝不**把查询降级成 A。

---

## 5. 缓存策略与持久化 v2

### 5.1 内存

- `cache_policy`：**只有 `s3fifo`**（2.2.0 起 `lru` / `tinylfu` / `partitioned` 全部移除；旧值被拒绝并提示 `ebpdns migrate-config`）；
- S3-FIFO：小队列 10%（新对象）→ 主队列 90%（复用对象），被淘汰键进 ghost；命中只递增 2-bit 频率；
  另支持 `cache_bytes`（字节预算）与 `max_entry_bytes`（单条上限），淘汰时**优先回收已过期条目**；
- 兼容字段：`restore_drops.window_unpersisted` 保留但恒 0（tinylfu 时代口径，策略已移除）；
- `hot_replicas` 是**内部只读热点副本**（命中加速层，best-effort、容量 = 缓存容量/64 且钳制
  到 [64,4096]），**不是**可配置的 "hot top-K" 缓存策略；没有对应配置键，也不参与淘汰决策。
- `cache_size` 出厂 **131072** 条；`counters.cache_direct` 是 `counters.hit` 的兼容投影（同源恒等，不单独门禁）。

### 5.2 落盘文件（都在 `cache_file` 同目录）

| 文件 | 作用 |
|---|---|
| `<cache_file>` | v2 **manifest**（原子指针）：快照名/字节数/CRC、WAL 段列表、durable seq、flags |
| `<base>.snap.<seq>` | 二进制快照：`EBPCSNP2` 头（64 B）+ 记录级 CRC32C + `EBPCEOF2` 尾（40 B） |
| `<base>.wal.<base_seq>` | WAL 段：`EBPCWAL2` 头（32 B）+ `PUT/EVICT/CLEAR/COMMIT` 记录（9 B 记录头 + CRC32C） |
| `<base>.v1.bak` | v1 迁移时保留的原 JSON，**永不自动删除**（回滚点） |
| `<base>.corrupt.<unix_ms>` | manifest/快照损坏时的现场保留 |
| `<base>.lock` | `flock(LOCK_EX\|LOCK_NB)` 单写者锁（第二实例只读） |

### 5.3 语义与判据

- **丢失窗口**：WAL 每 `WAL_FSYNC_MS=1000` 一次 `fdatasync` ⇒ 非优雅退出最多丢 ≤ 1 s；
  `cache_save_interval=0` 保持旧语义：不写 WAL，只在优雅退出时写全量二进制快照。
- **WAL 总序**：`seq` 分配与事件入队在同一临界区；恢复按 `seq` **有序合并/去重**，
  `seq` 回退不再判损坏 ⇒ 不再静默丢条目。
- **退出终态**：优雅退出先 drain 尾批 → 写终态快照并 fsync → 最后写 manifest（`FLAG_CLEAN_SHUTDOWN`）；
  快照失败则保留旧 manifest + 全量 WAL（可恢复，不静默）。
- **`persist_ttl` 三段**：`0` = 严格绝对到期（停机时长计入 TTL）；有限 `>0` = `now + pt` 统一复活；
  大有限值 = 事实上的"无限"。`now+pt` 溢出时 `expires_at` 饱和为 `i64::MAX` 毫秒（不是 `null`）。
- **`snapshot_age_s` 与 TTL**：快照按时间重写，节拍 = `min(1800 s, TTL/2)`（`TTL = max(ttl, ttl_max)`，
  下限 5 s）；`/api/status.cache.persist.snapshot_age_s` 是当前快照年龄。经验判据：`snapshot_age_s ≤ TTL/2`
  时重启后 5 s 内命中率与重启前基本一致（实测差 ≤ 5 pp）；长期接近/超过 TTL ⇒ 快照节拍未生效。
- **崩溃安全原语**：`tmp → fsync(file) → rename → fsync(dir)` 四步，任何一步失败都不 rename；
  2.1.36 起全树只有一份实现（`crates/ebpdns-fs`），各调用点仅声明 tmp 命名与清理策略。

### 5.4 回滚

```bash
# ① 数据回滚（保留 warm cache）
systemctl stop ebpdns
cd /var/lib/ebpdns
cp -p ebpdns-cache.json.v1.bak ebpdns-cache.json
rm -f ebpdns-cache.json.snap.* ebpdns-cache.json.wal.* ebpdns-cache.json.manifest.tmp
systemctl start ebpdns

# ② 紧急回滚（同一个二进制强制走 v1 读写路径）
systemctl stop ebpdns
EBPDNS_CACHE_FORMAT=v1 systemctl start ebpdns
```

`EBPDNS_CACHE_FORMAT=v1` 读不出 v2 manifest 时起动**空缓存**（不报错、不崩）；要保留 warm cache 必须先恢复 `.v1.bak`。

---

## 6. 可观测性

### 6.1 端点

| 端点 | 用途 |
|---|---|
| `GET /api/health` | 存活（免鉴权），`{status,running,uptime_s}` |
| `GET /api/status` | 36 键主状态 + `counters`（41 键）+ `cache`（27 键）+ `cache.persist`（15 键）+ `state_persist`（18 键；含 `missing_parts`） |
| `GET /api/config` | 82 键配置（token 脱敏） |
| `GET /api/rules` | 6 键三本账（`total` / `total_local` / `total_subscription` / `total_all`） |
| `GET /api/pipeline` | 7 字段流水线 |
| `GET /api/cache/stats` | **35 键**（S3-FIFO 唯一策略；含 `evict_expired/capacity/negative`、**`evict_bytes`（真实字节）**、`removed_delete*/removed_clear*`、`ghost_hits`、`policy_keys`、`shard_*`、`rrset_*`、`persist`）+ `policy_doc`（1 键：`lru_shards`，历史诊断名） |
| `GET /metrics` | Prometheus 文本（**66 family** 热态 / 64 冷态，两个上游延迟 family 懒加载） |
| `GET /api/logs` | 事件环增量（`since` / `limit`） |
| `GET /api/upstreams` / `GET /api/snapshot` | 上游明细 / 遥测快照（缓存条目只回前 500 条） |

完整字段字典与写端点见 [`docs/INTERFACE.md`](docs/INTERFACE.md)。

### 6.2 指标分组（66 family）

- **查询/缓存**：`queries_total`、`cache_hits_total`、`cache_misses_total`、`cache_entries`、`cache_capacity`、
  `cache_direct_total`、`cache_negative_hits_total`、`negative_cache_hits_total`、`negcache_hit_ratio`、
  `negative_single_vote_accepted_total`、`cache_skipped_private_total`、
  `policy_filtered_total`；
- **错误/SERVFAIL**：`errors_total`、`servfail_total`、`servfail_reasons_total`、`no_response_total`、`udp_dropped_total`；
- **上游**：`upstream_dispatch_total`、`upstream_wire_requests_total`、`upstream_requests_total`、
  `upstream_requests_total_by_id`、`upstream_early_return_total`、`upstream_hedge_total`、
  `upstream_success_rate`、`upstream_dns_success_rate`、`upstream_latency_ms`、`upstream_latency_ms_quantile`、
  `upstream_inflight_limit`、`upstream_inflight_acquired_total`、`upstream_inflight_queued_total`、
  `upstream_inflight_rejected_total`、`upstream_inflight_queued_gave_up_total`；
- **规则/RFC8020**：`rule_hits_total`、`rfc8020_hits_total`、`rfc8020_registrations_total`；
- **DoH h2**（前缀 `ebpdns_`，14 个）：`doh_h2_conns_open`、`doh_h2_streams_active`、`doh_h2_streams_total`、
  `doh_h2_goaway_total`、`doh_h2_goaway_{peer,io,protocol}_total`、`doh_h2_goaway_local_idle_total`、
  `doh_h2_goaway_idle_total`、`doh_h2_goaway_inflight_total`、`doh_h2_conns_closed_total`、
  `doh_h2_conns_idle_reclaimed_total`、`doh_h2_conn_life_ms_avg`、`doh_h2_fallback_h1_total`；
- **进程**：`process_{resident_memory_bytes,virtual_memory_bytes,threads,open_fds}`、`state_missing_parts`；
- **运行时**：`uptime_seconds`、`bytes_in_total`、`bytes_out_total`、`control_queries_total`、`control_hits_total`、
  `passthrough_qtype_total`、`client_rcode_total`、`prefetch_all_open`、`prefetch_degraded_total`、
  `stale_served_total`、`query_latency_ms`。

### 6.3 硬等式（同代快照）

- `total == Σ client_rcode`；`hit_rate == hit / (hit + miss)`（2.1.40 起分母不含本地策略应答）；
- `total == hit + miss + policy_filtered_total + rule`（`rule` = 本地规则直答数）
  （**2.1.42 澄清**：`rule_hits` 是正交维度，block/forceIp 已改计 `rule`、**不再**落 `miss`；
  仍不得把 `sum(rule_hits)` 再加进等式 —— 它含 allow/group 等**仍会发上游**的命中）；
- `client_rcode["2"] == servfail_total == Σ servfail_reasons`；
- `cache_direct == hit`（用户态缓存直答）；
- `avg_latency_ms == query_latency_ms_sum / _count`（同一窗口、同一抓取时刻；窗口 400 条，不是生命周期均值）。

**事件与历史**：事件环 500 条；真实流量的 `hit`/`miss` 事件按 **10%** 采样入环（`seq` 仍连续推进），
计数器与 TopN **全量**统计；`sys` 事件全量入环；遥测历史环 120 点（`/api/snapshot.history` 回尾部 60 点）。

---

## 7. 运维

### 7.1 升级

1. 备份 `/etc/ebpdns/config.json`、`/var/lib/ebpdns/state/`、缓存文件与其 `.snap.*` / `.wal.*` / `.v1.bak`；
2. 解包新 prod 包，`sudo ./install.sh start`（检测到旧实例会先停后启；不想中断用 `--keep-running`）；
3. 确认 `/api/status.version`、`--version`、systemd `Description`、包目录名四处一致。

> **2.2.0 起缓存策略只有 `s3fifo`**：`lru` / `tinylfu` / `partitioned` 等旧值在
> 启动、`check-config`、`PUT /api/config` 三处一律被拒绝并提示 `ebpdns migrate-config`
> （绝不静默换引擎）；`cache_partitions` 键已删除，旧配置里残留按未知键忽略。

### 7.2 回滚

- **二进制回滚**：保留上一版 `bin/ebpdns` 直接替换后重启；配置 schema 用
  `ebpdns migrate-config --export-legacy` 逐字节导出 `state/rules.json` 回 `config.json` 并降 `config_version`；
- **缓存回滚**：见 §5.4；
- **配置回滚**：安装器的 `config.json.bak.<ts>`，或 `state/history/` 的上一世代。

### 7.3 在线重载与订阅

- `POST /api/reload`：**优先从磁盘重读 `config.json`**，失败回退内存；返回 `{ok,changed[],source}`。
  `changed` 含顶层键差异；规则指纹变化时追加合成项 `rules_file`。
  路径类与进程级键（`listen` / `api` / `web_root` / `state_dir` / `state_persist` / `udp_workers` /
  `cache_persist` / `cache_save_interval` / `persist_ttl`）不会因 reload 生效，需重启
  （后三者决定缓存落盘 actor 的启动参数，控制台已标注「重启后生效」）。
  **改这些键（以及任何直接编辑 `config.json`）后，重启前必须先 `migrate-config` 重锚
  `state/commit.json`**，否则已启用 `state_persist` 的实例可能把外部改写判为撕裂并回滚到
  上一代（见 §3.2 注）；用 `PUT /api/config` 则无需额外步骤。
- 订阅刷新：每 `rule_sub_interval` 秒（默认 3600）拉取；内容未变不动缓存/索引。
  `rule_subscriptions[].count` 是**活源**：由每次刷新写回，`/api/rules.subscriptions[].count` 与它同源；
  `total_subscription` = 各 `count` 之和；`total_all == /api/pipeline.rules`。
- `POST /api/restart` 需要 `{"confirm":true}`，重复请求 409；进程以退出码 3 退出交由 systemd 拉起。
- `POST /api/reset`：清空缓存与计数（需 `{"confirm":true}` 的语义与 restart 一致）。

### 7.4 备份

最小备份集：`/etc/ebpdns/config.json`、`/etc/ebpdns/rules_local.json`、`/etc/ebpdns/rules_sub.json`、
`/var/lib/ebpdns/state/`（`commit.json` + `history/` + `rules.json`）、缓存文件及 `*.snap.*` / `*.wal.*`。
`*.tmp` 与 `*.corrupt.*` 不需要备份（前者读方忽略，后者是损坏现场）。

---

## 8. 能力边界与已知限制

**未实现（不要按"应该有"来排障）**

| 能力 | 现状 |
|---|---|
| DNSSEC 验证 | 只解析/透传 DNSSEC 记录类型；**不做链式验证**，`RRSIG/NSEC/NSEC3/NSEC3PARAM` 查询一律 `NOTIMP` |
| 加密入口 | 只做**加密上游客户端**（DoH / DoH3）；**不监听** DoH/DoH3 服务端端口；DoT/DoQ 上游已移除 |
| 权威解析 | 纯递归/转发，无 zone、无 AXFR/IXFR |
| ipset / nftset | 不写内核集合 |
| OpenTelemetry | 只有 Prometheus 文本端点，无 OTLP 导出 |
| RRL / 响应速率限制 | 无 |
| SQLite / 外部数据库 | 无；持久化只有 JSON/二进制文件与 `state/` 事务 |
| 多实例 / HA | 明确禁止；`state_dir` 独占锁，第二实例被拒 |
| 多平台 | 只交付 Linux x86_64 glibc；无 musl、无 Windows/macOS |
| 容器矩阵 | 验收脚本有第 10 行（`debian:13-slim`），但打包环境无 docker/podman ⇒ **未真实执行**，如实记 SKIP |

**边界澄清**

- `SO_REUSEPORT` **仅用于单实例内部的 UDP 多 worker 分流**（`udp_workers>0`），不是多实例共享端口；
  端口占用预检在 bind 之前显式执行，避免 REUSEPORT 让重复实例静默通过。
- DoH 出站优先 **HTTP/2 多路复用**（ALPN `h2`，每键 ≤4 连接、流级并发），服务端只支持
  HTTP/1.1 时自动回退；`/api/upstreams[].doh_transport` 可见实际形态（`h2` / `http/1.1` / `idle`，空闲时保留 last-known）。
- `/api/profile` 是能力边界占位端点：`POST` + JSON ⇒ `200 {"ok":true,"note":"profiling not available"}`；
  `GET` ⇒ 405；缺 `Content-Type` / 非 JSON ⇒ 415 / 400（刻意保持的方法矩阵）。
- `/api/snapshot` 的缓存条目只回前 500 条（页面不需要全量）。
- `avg_latency_ms` 是最近 400 条的算术平均（不是 EWMA、不是生命周期均值）；低流量下必须同时看
  `query_latency_ms_count`。

---

## 9. 开发与验证

### 9.1 一条命令跑完 14 项

```bash
OFFLINE=1 RELEASE=1 JOBS=1 bash scripts/check_all.sh
```

14 项顺序（前一步失败不中断后续）：

1. 版本 + 文档一致（七处同版本 + 两条契约各四处）
2. 文档计数（接口键集/包内文件数 == 动态实测）
3. 离线重建等价（上一版源码包 + 补丁 == 本树）
4. `cargo fmt --all --check`
5. `cargo clippy --workspace --all-targets --offline -- -D warnings`
6. `cargo test --workspace --no-fail-fast`
7. `web_dist_freshness`（dist 不早于 `web/src`；每个 `cfg-*` id 都在 wasm 里）
8. `web/` 独立 workspace `cargo fmt --all --check`
9. `web/` wasm32 clippy（`-D warnings`）
10. 接口键集（`_interface_keys.py` == 隔离实例实测）
11. 配置键集（`_config_keys.py`：模板 + `default_config` + 运行期注入 == 实测）
12. 干净机安装矩阵（1–9；10 视容器能力 SKIP）
13. `install.sh start` 运行语义（旧实例先停后启 / keep / dry / foreign）
14. 包权限规范化（`t-pkg-modes.sh`：无 world-writable、`*.sh`/`*.py` 0755、数据 0644、目录 0755、`install.sh`/`bin/ebpdns` 0755）

### 9.2 构建配方（交付字节的唯一口径）

- RUSTFLAGS 单一来源 = `scripts/_repro_flags.sh <tree> [--wasm]`，输出三条 remap：
  `<tree>=/build/ebpdns`、`<cargo registry>=/cargo/registry`、`$HOME/.rustup=/rust`；
- `SOURCE_DATE_EPOCH = BUILD_EPOCH`：`rust-embed` 会把 dist 文件的 `last_modified`/`created`
  编进二进制，不设它则同一份源码两轮构建字节不同；
- 交付链把源码树复制到**固定路径 `/build/ebpdns`** 再构建（`EBP_BUILD_ROOT` 可覆盖），
  wasm 必须在固定路径下重编；
- `[profile.release]` 一行不可改（`opt-level=3` / `lto="thin"` / `codegen-units=1` / `debug=false`）。

验证命令：

```bash
bash scripts/_repro_crosspath.sh     # 异路径/同路径双构建 + 路径残留计数 + 行为面比对
bash scripts/make_packages_221r2.sh  # 交付链：重编 wasm → 二进制 → 包内清单 → prod/src 两包
```

**可复现口径（实测）**：设置 `SOURCE_DATE_EPOCH` + 固定构建路径后，**wasm 逐字节相同**、
**bin 跨路径逐字节相同**（`X_PATH_BIN_IDENTICAL=YES`）、同路径重复构建逐字节相同；
二进制内不残留 `/root/...` 构建机路径（工具链路径归一为 `/rust/...`）。

---

## 10. 文档索引

**版本单一来源** = 根 `Cargo.toml` 的 `[workspace.package] version`（当前 **2.2.5**）：
后端 `VERSION` 取 `env!("CARGO_PKG_VERSION")`，前端页脚/关于页取 `web/build.rs` 注入的
`EBPDNS_VERSION`；`Makefile` 的 `PKG`、`packaging/install.sh`、systemd `Description`、
包目录名必须与之同步（七处版本门禁）。

- [`docs/INTERFACE.md`](docs/INTERFACE.md)：端点/字段字典、配置键表、错误码、前端刷新模型、键集门禁；
- [`CONVENTIONS.md`](CONVENTIONS.md)：开发约定、统一事务 §16/§17、缓存 v2 §18、文档一致性 §19；
- [`docs/PACKAGING.md`](docs/PACKAGING.md)：产物形态、安装/卸载、包内清单自校验、六道打包门、14 项门禁；
- [`docs/CLIPPY.md`](docs/CLIPPY.md)：clippy 判据与允许清单的实际状态；
- [`docs/PROPOSAL-cache-incremental.md`](docs/PROPOSAL-cache-incremental.md) /
  [`docs/PROPOSAL-domain_hits.md`](docs/PROPOSAL-domain_hits.md)：两份提案（均标注实现状态）；
- [`CONTRIBUTING.md`](CONTRIBUTING.md)：提交流程。

---

**部署约束：单机单实例**（`state_dir` 独占锁；第二实例会被拒；隔离实例必须显式 `--state-dir`）。

**规则契约：`/api/config.rules` 在任何情况下都恒为数组，由真源派生（无规则时为 `[]`，不是 `null`）。**
