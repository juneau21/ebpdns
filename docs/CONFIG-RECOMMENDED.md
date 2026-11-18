# ebpdns 2.2.0 推荐配置与实测记录

> 适用范围：LAN / 企业递归解析器（单机或双机）。本文件的数值与
> `packaging/etc/ebpdns/config.json`（= `default_config()`，两者有逐键门禁）**一致**；
> 新装即生效。2.2.0 的 A/B 口径与结果见 §六（237 真机，真实域名 8k，同机串行）。
>
> **2.2.0 能力边界**：缓存只有 **S3-FIFO**（`lru`/`tinylfu`/`partitioned` 已移除并拒绝）；
> 上游只有 **UDP / TCP / DoH / DoH3**（DoT/DoQ 移除，四入口拒绝）；DoH 出站优先
> **HTTP/2 多路复用**并回退 HTTP/1.1；出站 TLS 受 `tls_min_version` / `tls_ca_file` /
> `tls_use_system_roots` 三键约束且**始终严格校验**。不做 DNSSEC 验证 / RFC 5011 / RPZ /
> SPKI pin / hot top-K。

## 一、结论（最关心的 16 项）

| 需求 | 配置键 | 值 |
|---|---|---|
| 缓存容量 131072 条 | `cache_size` | **131072** |
| 唯一缓存策略 | `cache_policy` | **s3fifo** |
| 字节预算 / 单条上限 / 负配额 | `cache_bytes` / `max_entry_bytes` / `negative_pct` | **268435456** / **65536** / **20** |
| 开启持久化 | `cache_persist` | **true**（`persist_ttl=864000`，落盘窗口 10 天） |
| 开启 IPv6 | `ipv6` | **true** |
| 过期缓存兜底 | `serve_stale` | **true**（`stale_ttl=3600` = 1 小时） |
| 开启域名预取 | `prefetch` | **true** |
| 启用测速择优 | `speed_test` | **true** |
| 解析失败降级 | `fallback` | **true** |
| 加密查询填充 | `padding` | **true** |
| 响应 IP 合法性校验 | `rebind_protection` | **true** |
| EDNS0 总开关 | `edns` | **true** |
| DNS 0x20 投毒防护 | `dnssec_0x20` | **true** |
| 候选 IP 测速 | `ip_speed_check` | **true**（`ip_speed_probe=both`） |
| 在途查询合并 | `single_flight` | **true** |
| 出站 TLS | `tls_min_version` / `tls_ca_file` / `tls_use_system_roots` | **1.2** / **""** / **true** |

## 二、完整推荐值

### 缓存

| 键 | 值 | 说明 |
|---|---|---|
| `cache_size` | **131072** | 条目上限；生产实测占用 <2%，容量充足 |
| `cache_policy` | **s3fifo** | **唯一合法值**（S/M/G 三 FIFO + 2-bit 频率 + 8 分片 + 每分片 TTL 堆） |
| `cache_bytes` / `max_entry_bytes` | **268435456** / **65536** | 字节预算 256 MiB / 单条 64 KiB；超限不缓存或淘汰 |
| `negative_pct` | **20** | 负缓存配额（%）；超配额优先淘汰 NXDOMAIN/NODATA，防挤空正缓存 |
| `ttl` / `ttl_min` / `ttl_max` | **600 / 5 / 600** | `ttl` 是缺省与续期上限；`ttl_min=5` 尊重上游短 TTL；`ttl_max=600` 也是对外宣称 TTL 的封顶 |
| `neg_ttl_max` | **300** | 负缓存 TTL 硬上限（`0` = 关闭上限）；A/B：120 档 qps −1.8%、命中 −0.6pp |
| `serve_stale` / `stale_ttl` | **true / 3600** | 上游全挂时用 1 小时内旧答案兜底（负缓存不参与） |
| `cache_persist` / `persist_ttl` / `cache_save_interval` | **true / 864000 / 60** | v2 快照+WAL；`persist_ttl` 是"最多保存 10 天"，装配层收敛为 `min(persist_ttl, max(ttl, ttl_max))`。**三项均为重启级参数**（控制台已标注） |
| `prefetch` / `prefetch_trigger` / `prefetch_target` | **true / 400 / 600** | 命中后异步续期；`trigger=400 < ttl_max=600`，命中条目在到期前 200 s 入队 |
| `prefetch_max` / `prefetch_interval` | **4096 / 60** | 每轮补扫预算 4096（≈85 qps 后台刷新，只在上游侧可见），每 60 秒一轮 |

### 解析与协议

| 键 | 值 | 说明 |
|---|---|---|
| `ipv6` / `prefer_ipv4` / `ipv4_first` | **true / false / true** | 双栈；不因有 A 就屏蔽 AAAA；AAAA NODATA 时预热 A |
| `edns` / `edns_udp_size` / `edns_client_max_size` | **true / 1232 / 1232** | EDNS0 + 安全 MTU |
| `edns_client_subnet` | **""** | 不外发 ECS（`ecs_cache_variants` 保持 false） |
| `padding` | **true** | 仅加密上游（DoH/DoH3）按 RFC 8467 填充；明文 UDP/TCP 不填充 |
| `dnssec_0x20` / `dnssec_cache_variants` | **true / true** | 0x20 大小写熵；DO 位参与缓存键 |
| `rebind_protection` | **true** | 丢弃私网/保留地址应答 |
| `rfc8020_infer` / `rfc8020_max_labels` | **true / 8** | 父域 NXDOMAIN 推断，减少无效上游查询 |
| `nxdomain_quorum` | **2** | 至少 2 票确认才采信 NXDOMAIN（可信内网上游可降为 1，见 §五） |

### 并发与上游

| 键 | 值 | 说明 |
|---|---|---|
| `single_flight` | **true** | 同 CacheKey 并发 miss 合并为一次上游扇出 |
| `max_parallel_upstreams` | **4** | 首个候选先发，超时/对冲后补齐到 4（A/B：3 档 qps −1.6%） |
| `upstream_max_inflight` | **32** | 单上游在途闸门 |
| `timeout_ms` | **1500** | 单次上游硬超时（也是自适应超时上限） |
| `adaptive_parallel` / `hedge_after_ms` / `hedge_slowest_factor` | **true / 300 / 1.0** | 有 p90 样本时按 max(p90)×factor 对冲；无样本时 300 ms 兜底 |
| `adaptive_timeout` / `_k` / `_min_ms` | **true / 8.0 / 1500** | 下限 = 硬超时 ⇒ 默认不收紧 |
| `circuit_fails` / `circuit_open_s` / `circuit_open_max_s` | **3 / 30 / 120** | 熔断与指数退避 |
| `health_check_interval` / `health_probe_domain` / `health_probe_timeout_ms` | **60 / www.baidu.com / 2000** | 健康探针；实际探针超时 = `min(本值, timeout_ms)`（显式 `probe_timeout_ms` 优先） |
| `probe_timeout_ms` | **0** | 0 = 自动（`min(2000, 1500)=1500` ms） |
| `warmup` | **{enabled:true, queries:2, timeout_ms:3000}** | 启动/重载后为每个启用上游异步预热（2 条足以建连） |
| `speed_test` / `ip_speed_check` / `ip_speed_probe` / `speed_interval_ms` / `speed_timeout_ms` / `ip_speed_cache_ttl` | **true / true / both / 5000 / 300 / 60** | 候选 IP 测速（UDP53 与 TCP443，EWMA） |
| `bootstrap_dns` | **["223.5.5.5:53"]** | DoH/DoH3 主机名引导解析（不依赖系统解析器） |
| `tls_min_version` / `tls_ca_file` / `tls_use_system_roots` | **1.2 / "" / true** | 严格链 + 主机名/SAN + 有效期；非法 CA fail-closed |

> **出厂上游清单（2.2.6 预设，来自 237 现网）**：**34 条** = 7 条 DoH3 + 27 条 DoH
> （29 `enabled` / 5 `disabled`）；按品牌分组（`domestic` 10 / `global` 24）、组内 DoH3 优先，
> 顺序与 237 `/api/config` 完全一致。清单真源 = `packaging/etc/ebpdns/config.json`
> = `default_config()`（逐键门禁）。5 条 disabled 为实测不可用或仅作备用：
> `dnspod-doh` / `google-doh3` / `quad9-doh3` / `adguard-doh` / `dnssb-doh`。

### 运维

| 键 | 值 |
|---|---|
| `state_persist` | true（启动参数，进程内改不生效，需重启） |
| `rule_sub_interval` | 3600 |
| `log_level` / `log_format` | info / plain（重启后生效） |
| `udp_workers` | 0（按 CPU 自动；重启级） |
| `rating_sr_floor` | 0.5 |
| `api` / `listen` / `cache_file` / `state_dir` / `web_root` | 保持安装默认（只读段） |

## 三、2.2.0 与 2.1.5x 出厂默认的关键差异

| 键 | 2.1.5x | 2.2.0 | 理由 |
|---|---|---|---|
| `cache_policy` | s3fifo（可选 lru/tinylfu/partitioned） | **s3fifo（唯一）** | 能力收敛；旧值拒绝并提示 `migrate-config` |
| 上游协议 | 六种（含 DoT/DoQ） | **四种（UDP/TCP/DoH/DoH3）** | DoT/DoQ 移除，四入口拒绝 |
| DoH 传输 | HTTP/1.1 每连接单请求 | **HTTP/2 多路复用 + h1 回退** | 连接数与握手成本大幅下降 |
| TLS | 固定版本 + webpki 根 | **三键策略（min/CA/system roots）** | 企业 CA / 版本下限 |
| `/metrics` | 52 family | **57**（+5 DoH h2） | 可观测 |
| `/api/config` | 78 键 | **81**（模板 79 + 运行期 2） | 配置键表 |
| 缓存统计 | 19 键（s3fifo）+ lru 11 键 | **35 键（仅 s3fifo）** | 四类淘汰原因/ghost/shard/rrset/purge_expired |

## 四、应用到已有实例

```bash
# 1) 只提交要改的键（PUT 是合并语义；token 见 /etc/ebpdns/config.json）
curl -s -X PUT http://127.0.0.1:8353/api/config \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"ttl_max":600,"neg_ttl_max":300,"max_parallel_upstreams":4}'
# 2) 让解析器重新应用（规则/上游集合变化时也需要）
curl -s -X POST http://127.0.0.1:8353/api/reload \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"confirm":true}'
# 3) 校验
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8353/api/config | python3 -m json.tool | head
```

> 重启级键（`cache_persist` / `cache_save_interval` / `persist_ttl` / `udp_workers` /
> `state_persist` / `listen` / `api` / `web_root` / `state_dir`）PUT 成功后**写入配置文件**，
> 但要 `systemctl restart ebpdns` 才改变运行期行为。
>
> **直接编辑 `/etc/ebpdns/config.json` 时**：已存在 `state/commit.json` 的实例会把它判为
> "与提交点不一致的 part"，启动时可能**回滚到上一代**。停服编辑后先运行
> `ebpdns migrate-config --config /etc/ebpdns/config.json`（重锚提交点）再启动；
> 或者直接用 `PUT /api/config`（推荐）。只读段（listen/api/路径类）只能走前者。

## 五、取舍与风险

- **`nxdomain_quorum=2`**：更安全（防单票投毒/误报），可信单上游内网可降 1；降 1 会放大
  RFC 8020 的误判面。
- **`serve_stale=true` + `stale_ttl=3600`**：上游全挂时返回最长 1 小时旧答案，客户端会看到
  超过原 TTL 的应答；不能接受请置 false/调小。
- **`prefetch_trigger=400` / `prefetch_target=ttl_max=600`**：命中且剩余 TTL ≤400 s 时入队续期，
  后台 QPS ≈ `(prefetch_max + prefetch_max/4)/prefetch_interval = 5120/60 ≈ 85`（仅上游侧）；
  容量按 `(prefetch_max+prefetch_max/4)/interval×ttl ≈ 5120/60×600 ≈ 51200` 个常驻域名估算。
- **`ttl_min=5`**：只抬升极短 TTL；不要设为 300 这类大值 —— 会向下游提供超过上游原 TTL 的
  数据（`check-config` 会 WARN）。
- **DoS 面**：`cache_bytes`/`max_entry_bytes` 限制大 TXT/长链；`prefetch_max` 限制随机子域放大。

## 六、2.2.0 A/B 实测（237，真实域名 8k，300 qps）

> 方法：隔离实例（`:15353`/`:28353`，临时 state/cache，不继承生产规则）；每档
> **清空缓存 → 50 s@300 qps 预热 → 90 s@300 qps 测量**，同机串行；指标 = 客户端
> qps/lost/SERVFAIL/p50/p95/p99 + `/api/status` 计数增量 + `/proc` RSS。
> 基线 = `base`（默认值）与 `base_end`（末次复跑）两次的均值：qps **295.5**、
> p99 **145.9 ms**、SERVFAIL **0.220%**、lost **0.030%**。
> 两次基线本身 qps 差 **−1.1%** ⇒ **|Δqps| < 1.5% 视为同相噪声**。

| 档位（相对默认） | qps | Δqps | lost% | SERVFAIL% | p99 ms | avg ms | hit% | RSS MB |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| base（默认） | 297.0 | +0.5% | 0.026 | 0.224 | 178.7 | 10.67 | 79.8 | 56.0 |
| base_end（复跑） | 294.0 | −0.5% | 0.034 | 0.216 | 113.2 | 7.86 | 80.1 | 57.4 |
| `max_parallel_upstreams=3` | 292.2 | −1.1% | 0.049 | 0.191 | 137.9 | 8.53 | 79.7 | 57.9 |
| `hedge_after_ms=100` | 297.0 | +0.5% | 0.041 | 0.242 | 132.4 | 8.52 | 80.1 | 53.1 |
| `timeout_ms=2000` | 294.4 | −0.4% | 0.068 | 0.203 | 141.8 | 8.17 | 80.2 | 53.7 |
| `health_check_interval=60` | 295.7 | +0.1% | 0.056 | 0.180 | 153.2 | 8.90 | 80.1 | 57.2 |
| `stale_off` | 295.6 | +0.1% | 0.075 | 0.237 | 144.8 | 9.18 | 80.0 | 53.3 |
| `single_flight=false` | 293.9 | −0.5% | 0.087 | 0.249 | 152.7 | 9.10 | 79.8 | 52.9 |
| `rfc8020_infer=false` | 293.7 | −0.6% | 0.102 | 0.178 | 141.9 | 8.35 | 80.1 | 59.4 |
| `ipv4_first=false` | 297.6 | +0.7% | 0.034 | 0.216 | 117.6 | 7.28 | 79.9 | 54.7 |
| `tls_min_version=1.3` | 299.1 | +1.2% | 0.004 | **0.337** | 104.6 | 7.17 | 80.3 | 52.9 |
| `edns=false` | 297.2 | +0.6% | 0.034 | 0.232 | 140.9 | 7.99 | 80.1 | 54.0 |
| `padding=false` | 295.6 | +0.1% | 0.056 | 0.175 | 151.8 | 7.57 | 80.4 | 54.1 |
| `max_entry_bytes=4096` | 296.3 | +0.3% | 0.041 | 0.225 | 119.2 | 7.85 | 80.2 | 51.2 |
| `nxdomain_quorum=1` | 296.9 | +0.5% | 0.049 | 0.168 | **88.9** | **6.76** | 80.5 | 53.7 |
| `prefetch=false` | 295.8 | +0.1% | 0.056 | 0.191 | 139.9 | 8.25 | 80.1 | 52.4 |
| `prefetch_trigger=600` | 294.4 | −0.4% | 0.037 | 0.265 | 133.3 | 7.66 | 80.1 | 54.6 |
| `ttl_min=0` | 293.1 | −0.8% | 0.011 | 0.264 | 200.5 | 9.66 | 79.7 | 58.0 |
| `ttl_min=60` | 294.5 | −0.3% | 0.053 | 0.260 | 187.0 | 10.21 | 79.2 | 55.7 |
| `ttl_max=1800` | 296.2 | +0.3% | 0.007 | 0.272 | 147.5 | 8.57 | 80.0 | 53.2 |
| `neg_ttl_max=120` | 291.8 | −1.2% | 0.060 | 0.191 | 147.0 | 9.66 | **79.2** | 56.2 |
| `cache_bytes=64MiB` | 296.9 | +0.5% | 0.037 | 0.231 | 135.8 | 7.58 | 80.3 | 52.8 |
| `negative_pct=10` | 295.8 | +0.1% | 0.052 | 0.214 | 141.1 | 8.43 | 80.3 | 54.0 |

**采纳**（写入本文件与随包模板）：

| 键 | 旧值 | 新值 | 依据 |
|---|---:|---:|---|
| `max_parallel_upstreams` | 3 | **4** | 3 档 qps −1.1%，且 2.1.50 同口径 A/B 亦为 −7% |
| `hedge_after_ms` | 200 | **300** | 与 2.1.50 推荐一致；100 档未见稳定收益 |
| `neg_ttl_max` | 120 | **300** | 120 档 qps −1.2%、hit −0.6pp |
| `prefetch_trigger` | 600 | **400** | 600 档 qps −0.4%、SERVFAIL +0.045pp；400 < ttl_max 留 200 s 续期窗口 |
| `prefetch_max` | 2048 | **4096** | 与 2.1.50 一致（补扫预算；本机 RSS 无压力） |
| `prefetch_interval` | 300 | **60** | 与 2.1.50 一致（5 分钟→1 分钟；条目保鲜） |
| `warmup.queries` | 3 | **2** | 与 2.1.50 一致；预热只影响启动首批，2 条已建连 |

**明确否决**：`tls_min_version=1.3`（SERVFAIL 0.22%→0.34%，部分上游仅 1.2）、
`ttl_min=0/60`（qps/hit 无收益，p99 更差）、`ttl_max=1800`（SERVFAIL 升高，长跑还会破坏
`prefetch_trigger < ttl_max` 窗口）、`single_flight=false`、`stale_off`、`rfc8020_infer=false`
（lost 0.03%→0.10%，无收益）、`edns/padding=false`（无收益且损失协议特性）、
`cache_bytes=64MiB` / `negative_pct=10` / `max_entry_bytes=4096`（本负载用量远低于上限，
无可测收益，保持更宽松的安全边界）。

> `nxdomain_quorum=1` 的 p99/avg 明显更好（88.9/6.76 vs 145.9/9.27），但它把
> NXDOMAIN 的信任门槛降到**单票**，属于安全取舍；出厂仍保持 **2**，可信单上游内网
> 可显式下调（见 §五）。
>
> 调优实例日志里的 1 条 `ERROR` 是脚本每次改写 `config.json` 导致的
> `state/ 世代长度不符（TORN）`（测试夹具现象，不是服务缺陷；生产不触发）。


## 七、回滚

```bash
sudo cp /etc/ebpdns/config.json.bak.<ts> /etc/ebpdns/config.json   # 安装器/迁移备份
sudo systemctl restart ebpdns
# 二进制回滚见 docs/MIGRATION-2.2.0.md §4
```
