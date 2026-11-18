# ebpdns 2.2.0：升级、迁移与回滚

> 2.2.0 是**基于 2.1.49 最终快照重做**的一版：只包含 5 项能力（S3-FIFO 唯一缓存 /
> RRset 去重 + 持久化 v2 / 仅 UDP·TCP·DoH·DoH3 / DoH HTTP/2 多路复用 / TLS 策略），
> **不包含** DNSSEC 验证、RFC 5011、RPZ 导入、加密策略（strict/require_encrypted）、
> bootstrap 四模式、SPKI pin。从 2.1.50+ 线降/升到 2.2.0 时请按本文件处理差异。

## 1. 行为差异（相对 2.1.49）

| 项 | 2.1.49 | 2.2.0 |
|---|---|---|
| 缓存策略 | `s3fifo`（默认）/ `lru` | **只有 `s3fifo`**（`lru`/`tinylfu`/`partitioned` 被拒绝） |
| 缓存持久化 | v2（快照 + WAL） | v2（绝对 `expires_at`；启动校验/丢弃计数；优雅退出强制快照） |
| 上游协议 | UDP/TCP/DoH/DoT/DoH3/DoQ | **UDP/TCP/DoH/DoH3**（`dot`/`doq`/`tls://`/`quic://` 一律拒绝） |
| DoH 出站 | HTTP/1.1（每连接单请求） | **HTTP/2 流级复用**（ALPN `h2`；探测失败自动回退 h1） |
| TLS | 固定版本 + webpki 根 | **`tls_min_version` / `tls_ca_file` / `tls_use_system_roots`**；始终严格校验 |
| 配置键 | 76 | **79**（+3 TLS；`/api/config` 81 = 79 + 运行期 2） |
| `/metrics` | 52 family | **57**（+5 DoH h2） |
| `/api/upstreams[]` | 41 字段 | **47**（+6 DoH h2） |

## 2. 升级步骤（就地）

```bash
sudo systemctl stop ebpdns
sudo cp -a /usr/local/bin/ebpdns /root/backup-220/ebpdns        # 备份旧 bin
sudo cp -a /etc/ebpdns        /root/backup-220/etc-ebpdns      # 备份配置
sudo cp -a /var/lib/ebpdns    /root/backup-220/var-lib-ebpdns  # 备份 state + 缓存
# 2.1.49 的缓存（v1 JSON）与 2.2.0 的 v2 不兼容：可保留（2.2.0 会丢弃并 WARN+计数），
# 也可直接移走以获得干净的冷启动：
sudo mv /var/lib/ebpdns/ebpdns-cache.json* /root/backup-220/cache-old/ 2>/dev/null || true
sudo install -m 755 ebpdns-2.2.0/bin/ebpdns /usr/local/bin/ebpdns
sudo cp ebpdns-2.2.0/etc/ebpdns/config.json /etc/ebpdns/config.json
sudo chown root:ebpdns /etc/ebpdns/config.json && sudo chmod 640 /etc/ebpdns/config.json
# **2.2.0 终审**：已有 state/commit.json 的实例必须先把外部改写重锚到提交点，
# 否则启动时可能把新配置判为"撕裂"并回滚到上一代（幂等；已一致时 rc=0 且不改内容）。
sudo /usr/local/bin/ebpdns migrate-config --config /etc/ebpdns/config.json
sudo systemctl start ebpdns
```

**先预检**（零中断，不启动服务）：`ebpdns check-config --config /etc/ebpdns/config.json`
—— 退出码 `0` 才算可以替换 binary；`2` 表示配置有问题（会逐条打印）。

## 3. 必须手工处理的配置差异

1. **`cache_policy`**：若不是 `s3fifo`，`check-config` rc=2 / 启动 exit 2 / `PUT` 400。
   修复：改成 `"s3fifo"`，或 `ebpdns migrate-config --config <路径>`（会就地改写并备份）。
2. **上游 `proto=dot|doq`**：被拒绝（逐条点名 `upstreams[i] (id=…)`），**不会自动删除**。
   修复：改为 `tcp`/`doh`/`doh3` 或删除该条。
3. **`tls_ca_file`**：必须是可读 PEM 且至少含一张 `CERTIFICATE`；否则拒绝启动
   （fail-closed：不退回系统根）。`tls_use_system_roots=false` 时必须给 `tls_ca_file`。
4. **2.1.50+ 的键**（`dnssec*` / `bootstrap_mode` / `upstream_encryption_policy` /
   `require_encrypted_upstreams` / `rpz_*` …）在 2.2.0 里**不存在**：启动时按"未知键"
   WARN 并忽略。请用 2.2.0 的出厂模板（79 键）重生成配置，或逐键手工剔除。

## 4. 回滚到 2.1.49（或任意 2.1.x）

```bash
sudo systemctl stop ebpdns
# **必须**先清掉 v2 缓存副产物（旧版本不认识 .wal.* / .manifest / .snap.*）
sudo rm -f /var/lib/ebpdns/ebpdns-cache.json.wal.* \
           /var/lib/ebpdns/ebpdns-cache.json.manifest \
           /var/lib/ebpdns/ebpdns-cache.json.snap.*
# 可选：连快照一起删（旧版本会把它当坏文件丢弃并 WARN）
sudo rm -f /var/lib/ebpdns/ebpdns-cache.json
sudo cp -a /root/backup-220/ebpdns /usr/local/bin/ebpdns
sudo cp -a /root/backup-220/etc-ebpdns/config.json /etc/ebpdns/config.json
sudo systemctl start ebpdns
/usr/local/bin/ebpdns --version     # 期望旧版本号
```

保留 `*.wal.*` 不会损坏配置/规则，但旧版本会持续报"缓存文件无法解析"。

## 5. 验证清单（升级后）

```bash
curl -fsS http://127.0.0.1:8353/api/health
curl -fsS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8353/api/config | python3 -c 'import json,sys;print(len(json.load(sys.stdin)))'   # 81
curl -fsS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8353/metrics | grep -c '^# HELP'   # 57
curl -fsS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8353/api/upstreams | python3 -c 'import json,sys;print(sorted({u["proto"] for u in json.load(sys.stdin)["upstreams"]}))'
dig @127.0.0.1 www.baidu.com A +short          # 有 A 记录
dig @127.0.0.1 no-such.example.com A           # status: NXDOMAIN
dig @127.0.0.1 www.baidu.com A +tcp +short     # TCP 同样可用
curl -fsS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8353/api/cache/stats | grep -o '"segment_[smg]"'
```

- `ebpdns_doh_h2_conns_open >= 1` 表示 DoH 已按 ALPN 协商到 h2；
- `doh_transport` 字段为 `"h2"` / `"http/1.1"`（**last-known**，连接关闭后仍保留）/ `"idle"`（从未有连接样本；2.2.2 起不再回 `null`）；
- 缓存重启保留：重启前 `cache.used > 0`，重启后仍 `> 0`（优雅退出写快照 + WAL 重放）。

## 6. 2.2.2 的行为变化（升级前必读）

| 项 | 2.2.1 | 2.2.2 |
|---|---|---|
| `listen.udp6/tcp6` 缺省 | 一律 `[::]`（v4 只绑回环时仍对 v6 全网卡开放） | **按 v4 智能映射、保留双栈**：v4 wildcard/具体地址 ⇒ `[::]`；v4 回环（`127.0.0.1`/`localhost`）⇒ `[::1]` |
| 显式关闭 v6 | `false` / `null` / `""` | 同上，另接受 `"off"` / `"none"` / `"disabled"`（大小写不敏感） |
| 旧配置上游缺 `id/proto/host` | 启动 `exit 2`（升级即起不来） | **启动跳过该条并 WARN**（磁盘配置不改动）；`check-config` 仍按原判据报 **ERROR**，请补全或删除 |
| 预取补扫 | 每轮预算 `max(prefetch_max/4,64)`，空闲也自转 | 低流量（每轮客户端查询 <20）**跳过补扫**；单轮补扫硬上限 **64**；`health_check_interval` 默认 30→**60**（空闲时再降为每 3 轮一探） |
| `evict_expired` / `segment_*` | 内层 TTL purge 不通知 S3FIFO ⇒ `segment_s+segment_m` 可远大于 `size`、`evict_expired` 恒 0 | inner→policy **实时对账**：`segment_s+segment_m == size`（无 ghost）、purge/容量淘汰按原因记账 |
| `doh_transport` | 连接关闭后 `null` | `h2` / `http/1.1`（last-known）/ `idle`；新增 GOAWAY 原因与连接寿命指标 |
| INFO「在途上限…」 | effective 变化即打印（10↔15 振荡可绕过） | 幅度 >50% 且 ≥120s、或 ≥360s 才打印，**滚动小时 ≤10 条** |

> **双栈默认保留**：2.2.2 **不会**因为 v4 是回环就关闭 IPv6，只把 v6 收敛到 `[::1]`。
> 需要完全关闭 v6 时显式写 `"udp6": false, "tcp6": false`（或 `"off"`）。
> `check-config` 对「v4 回环 + 显式 `[::]`」给 **WARN**（不阻断启动）；非法 v6 地址仍 ERROR。

## 7. 2.2.3 的行为变化（升级前必读）

| 项 | 2.2.2 | 2.2.3 |
|---|---|---|
| 旧配置上游缺 `proto` | 无 DoH 特征也默认补 `udp`（可能把 DoH 静默降级成明文） | **只在明确 DoH 特征时补 `doh`**（`url` 含 `/dns-query`、端口 443、host 为域名）；否则**启动跳过该条并 WARN**，`check-config` 仍 ERROR。不再默认 udp |
| `listen` 使用主机名 | 只识别字面量 `127.0.0.1`/`localhost`/`::1`；其它解析到回环的 hosts 名会映射 `[::]` | **启动时解析主机名**：解析结果全部为 loopback ⇒ v6 仍绑 `[::1]`（**保持双栈，不回退 `[::]`**）；解析失败按回环处理（与 v4 回退一致） |
| 命中驱动预取（pending） | 突发后一轮全排（实测 107 次/2min） | **单轮上限 24 条 + 每秒 ≤8 条 + 热 key 优先**；剩余重新入队。低流量时单轮上限进一步降为 **4** 条；连续 3 轮低流量后**暂停 pending 出队**（队列保留，有流量立即恢复） |
| 健康探针 | 低流量每 3 轮全探 | 低流量每 6 轮、每轮最多 **1** 个目标（打开态优先，保留恢复探测） |
| `evict_bytes` | **次数**（"淘汰时同时超字节预算"） | **真实字节**（Σ 被淘汰条目大小，与三个原因计数同源）。显式 `delete`/`clear` 单独计入 `removed_delete*` / `removed_clear*`，不与 `evict_*` 重叠 |
| h2 GOAWAY 归因 | `peer` / `io` / `driver-end`（后两者混着 EOF/协议/本地回收） | `peer` / `io` / `protocol` / `local_idle` 四类；`local_idle` 不计入 `goaway_total`；**平均寿命只统计真实连接**（承载过 stream 或非空闲终止） |
| h2 空闲复用 | 连接空闲 ≤90s 复用 | **空闲 ≥20s 不再复用**（`H2_REUSE_IDLE_GUARD`），主动换新连接以避开对端 ~30s 空闲回收；`H2_MAX_IDLE` 90→20s |
| quinn 日志 | 底层 `quinn` WARN 与 ebpdns DoH3 失败 WARN 混在一起 | `quinn`/`quinn_proto` 固定压到 **ERROR**（只调日志过滤，协议行为不变）；ebpdns 自己的 DoH3 分类 WARN 保持 |

> **双栈语义不变**：2.2.3 仍然**不会**因为 v4 是回环就关闭 IPv6；主机名解析为 loopback 时只把
> v6 收敛到 `[::1]`。需要完全关闭 v6 时仍显式写 `"udp6": false, "tcp6": false`（或 `"off"`）。

## 8. 2.2.4 的行为变化（升级前必读）

| 项 | 2.2.3 | 2.2.4 |
|---|---|---|
| 旧配置上游缺 `proto` 的 DoH 推断 | `url` 只认 `/dns-query`；`host` 为域名即补 `doh` | `url` 认**任意非空 DoH 路径**（`/custom`、`https://host/doh` 等，路径优先于端口）；`port=443`；`host`/`addr` 为 **FQDN** 且未显式写非 443 端口。**显式 `port=53/853` + 无 URL 路径 ⇒ 不推断 DoH**（跳过 + WARN，`check-config` 仍 ERROR），避免把明文误判成 DoH。单标签主机名（`localhost`）不再算 DoH 特征 |
| h2 连接复用 | 空闲 ≥20s 不再复用；`H2_MAX_IDLE=20s` | 空闲 ≥**30s** 不再复用；**新增按连接年龄退休 `H2_MAX_AGE=40s`** + **按 stream 预算退休 `H2_MAX_STREAMS_LIFETIME=400`**（50qps 实测对端在 ~22.6s / ~565 stream 时回收，40s 年龄上限来不及；400 stream 预算在 ~16s 主动换新）。`H2_MAX_IDLE=60s`。高 QPS 用预算消除 peer GOAWAY，低 QPS（25s 间隔）仍复用 ⇒ 空闲握手 11→5、p50 330→154ms（自测） |
| 前缀安装 × 真 systemd | `EBP_INSTALL_ROOT` 下仍调用宿主 `systemctl enable` ⇒ **rc=1** | **纯文件模式**：只写前缀内 unit + 打印离线 enable 命令，**不调用宿主 systemd**，安装 **rc=0**；`uninstall` 语义不变 |
| `/api/cache/stats` | 34 键 | **35 键**：新增 `purge_expired`（仅写路径轮转 TTL purge；`evict_expired` 仍含惰性删除）。生产 `stale_ttl=3600` 时 `purge_expired` 长期 0 属预期 |
| `probe_upstream_queries` | 只接 `prefer_ipv4` 探测 ⇒ 生产恒 0 | 健康探针（每目标 +1）也计入 ⇒ 生产可见；IP 测速探测仍不计（目标不是配置上游） |
| 负票 quorum | NXDOMAIN + NODATA 混算"票够" ⇒ 1 NX + 1 NODATA 在 q=2 时提前收口、剩余上游被取消 ⇒ `upstream_no_answer` SERVFAIL | NXDOMAIN / NODATA **按种类分别计数**：任一种独立达到 quorum 才收口；未达标继续补查剩余上游（合成随机子域突发不再批量误报 SERVFAIL） |
| `/api/upstreams` 文档 | 表头写 "47 字段"（2.2.0 历史值） | 重算为 **54 字段**（`/api/snapshot.upstreams[]` 同源），`_interface_keys.py` 门禁新增字段数校验 |

> **双栈语义不变（2.2.4）**：生产仍同时监听 `0.0.0.0:53` 与 `[::]:53`；安装器前缀模式与 h2
> 改动都不触碰监听逻辑。`doh3` 上游的 `doh_transport=null` 语义仍为"不适用"（DoH3 走 QUIC，
> 没有 h2/h1 传输形态）；仅 `proto=doh` 会返回 `h2`/`http/1.1`/`idle` 字符串。

## 9. 2.2.5 的行为变化（升级前必读）

| 项 | 2.2.4 | 2.2.5 |
|---|---|---|
| CNAME + NODATA 负票 | 扇出层把"带 CNAME 的空答案"算成 NODATA 负票（确认层却要求 `cnames.is_empty()`）⇒ q=2 时可能提前 abort 后 `upstream_no_answer` | 扇出层与确认层**同口径**：带 CNAME 的空答案**不计负票**，交给 CNAME 链继续跟到链尾（与 TC/混票修复同类） |
| 仅 2 上游 + `nxdomain_quorum=2` 的混合负票 | 一个 NXDOMAIN + 一个 NODATA ⇒ 两种各 1 票、永远凑不满 q=2 ⇒ fail-closed SERVFAIL（2 上游部署等于永久故障） | **按可得票数降级**：所有有效票都是负票、票源数 ≥ q、但种类分歧时任一种都未单独达标 ⇒ 返回**较弱结论 NODATA**（不登记 RFC 8020），计数 `counters.negative_mixed_degraded`。票源 < q 时**仍 fail-closed**（不放松少票确认） |
| `probe_upstream_queries` | 计"派发尝试"（连接立刻失败也算） | 改为**完成数**（成功+失败），并新增 `probe_upstream_ok` / `probe_upstream_fail`；`queries == ok + fail` |
| h2 GOAWAY 观测 | `goaway_total` 混着"对端空闲回收"与"请求在途失败"，26 次 GOAWAY 被误读成 26 次失败 | 新增 `doh_h2_goaway_idle_total`（无在途 stream = 空闲回收，**不是失败**）与 `doh_h2_goaway_inflight_total`（有在途 stream = 请求受影响）；`/api/upstreams[]` **56 字段**、`/metrics` **66 family** |
| h2 stream 预算 | `H2_MAX_STREAMS_LIFETIME=400`（消除 GOAWAY，但 50qps p99 251→287ms） | **512**（仍低于实测对端 ~565 stream 回收阈值，留 ~9% 边界）：握手次数按比例下降，目标 GOAWAY 仍为 0 且 p99 不劣于 2.2.4；`H2_MAX_AGE=40s` / `H2_REUSE_IDLE_GUARD=30s` / `H2_MAX_IDLE=60s` 不变 |
| 前缀安装 / 卸载 | 建议用户跑 `systemctl --root enable`（生成宿主绝对路径的**悬空** symlink）；`uninstall --purge` 保留空父目录 | 安装器在前缀内创建**相对路径** symlink（`../<unit>`，不悬空，`systemctl --root is-enabled` 可识别）；卸载用 `rmdir` **回收派生空父目录**（只删空目录，不碰用户文件） |
| `check-config` 的 `ttl_min` / `serve_stale` WARN | 容易被当成必须消除的缺陷 | 行为不变；WARN 文案明确标注"**显式配置选择，可忽略（非缺陷）**" |
| `status.cache` 的 `purge_expired` | 与 `/api/cache/stats` 同源 summary（35 键）；生产 `stale_ttl=3600` 时长期 0 | 口径不变（`status.cache` 仍带 `purge_expired`，属既有 `evict_*` 模式）；用短 TTL 受控实例验证其增长，生产**不**改 `stale_ttl` |

> **双栈语义不变（2.2.5）**：生产仍同时监听 `0.0.0.0:53` 与 `[::]:53`；本轮所有改动
> （负票/探针/观测/安装器）都不触碰监听逻辑。`doh3` 的 `doh_transport=null` 仍为"不适用"。

## 10. 2.2.6 的行为变化（升级前必读）

| 项 | 2.2.5 | 2.2.6 |
|---|---|---|
| h2 GOAWAY 在途口径 | `doh_h2_goaway_inflight_total` 是**连接级布尔量**（一条连接 N 个在途 stream 也只记 1），"几个请求被打到"无法回答 | 改名 `doh_h2_goaway_conn_inflight_total`（仍是连接级，语义写死）+ 新增 `doh_h2_goaway_streams_lost_total`（**stream 级**受影响请求数）；恒等式 `goaway_total == idle + conn_inflight`、`streams_lost >= conn_inflight`。`/api/upstreams[]` 56→**57 字段**，`/metrics` 66→**68 family**（另加 `negative_mixed_degraded_total`） |
| GOAWAY `total` 的语义 | `goaway_total` 含"对端空闲回收"（idle），运维容易把总次数读成失败数 | 语义不变（`total == idle + conn_inflight`，idle 仍计入 total），但**文档与 API/metrics HELP 文案统一写死**"idle 不是请求失败"；要"请求受影响"请看 `conn_inflight`（连接）与 `streams_lost`（请求） |
| 混合负票策略 | 固定降级 NODATA（2 上游 q=2 不再永久 SERVFAIL） | 新增可选键 `negative_mixed_policy`（`"nodata"` 默认 / `"servfail"`）。`servfail` = 不降级、严格 fail-closed。非法值 fail-closed（`PUT` 400 / `check-config` rc=2 / 启动 exit 2），**不静默回落**。配置模板 **79→80 键**、API `CONFIG_KEYS` **81→82** |
| 探针成功口径 | 一对 `probe_upstream_ok/fail`，判据是传输成功（SERVFAIL 也算成功），与 `dns_ok/dns_fail` 矛盾 | 拆成**两本账**：`probe_transport_ok/fail`（是否收到应答）与 `probe_valid_ok/fail`（是否 NOERROR+ANCOUNT>0）；硬等式 `queries == transport_ok+transport_fail`、`transport_ok == valid_ok+valid_fail`。`status.counters` **41→43 键** |
| SERVFAIL 突发降噪 | 每轮对全部 enabled 上游发探针；数据面排序只看累计成功率（长跑后 99.9% 的上游连丢 20 包仍排前面） | **探针退避**：连续探针失败 ≥2 的上游按 2/4/8/16 轮跳过（打开态必探、成功即恢复）；**数据面快速降权**：连续传输失败 ≥2 的上游在排序里稳定后移到健康组之后（成功一次即恢复，不剔除候选）。两者都不改 P1-03（境外 DoH3）本身 |
| h2 stream 预算 640/768 | 512（实测对端 ~565 回收阈值，~9% 边界） | **保持 512**：640/768 均**高于**实测对端阈值 ⇒ 会重新引入 peer GOAWAY（请求失败），与"稳值"目标相反；详见 `doh_h2.rs` 常量注释与报告 §A6 |
| 源码包体积 | 5.08 MB（`packaging/prev` 含上一版 2.0 MB 源码包 + 2.6 MB 补丁） | 压缩/去重 `packaging/prev`（保留 `_rebuild_equiv` 输入与可执行性），体积见 `docs/PACKAGING.md`/报告 §5 |
| 生产 `purge_expired=0` | 已文档化为预期（`stale_ttl=3600`） | 语义不变、**不改 `stale_ttl`**；INTERFACE §4.4 与报告再次写明"生产长期 0 是预期，隔离短 TTL 已验证增长" |
| 安装器 `t-install-running` A1–A6 | 前缀安装=纯文件模式，旧 shim systemd 启动语义 SKIP | 新增 **A7 真 systemd transient unit** 覆盖（`systemd-run` 起真实服务、验 active/端口/停止释放，隔离单元不碰宿主），A1–A6 保留显式 SKIP 理由与 `EBP_TIR_FORCE_SYSTEMD=1` 逃生口 |

> **双栈语义不变（2.2.6）**：仍同时监听 `0.0.0.0:53` 与 `[::]:53`（UDP/TCP），
> 本轮改动不触碰监听/绑定逻辑；P1-03（境外 DoH3）按指示**未修**。



