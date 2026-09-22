# ebpdns —— SmartDNS 式智能 DNS 解析器（Debian 13 可部署）

请注意！！！所有代码来源于豆包模型，软件已稳定运行.**真实可部署的 DNS 解析软件**。

- 真实监听 `UDP/TCP :53`（IPv4/IPv6 可选），真实多上游并发解析（UDP / TCP / DoH / DoT / **DoQ / DoH3**）
- 复刻 SmartDNS 的**测速择优、域名分流、TTL 缓存、预取、IPv4 优先、失败降级**等智能逻辑
- 三种缓存淘汰策略：**LRU**（8 分桶锁，默认）/ **Partitioned**（按分流 group 隔离）/ **W-TinyLFU**（三段式抗扫描污染）
- 默认数据面运行在**用户态**：以**用户态 LRU 缓存模拟 BPF LRU_HASH Map**，命中由 daemon 快路径直接回包，**无需内核权限**即可完整运行
- 内置 **HTTP JSON API + Web 控制台**：控制台连上后端即为真实数据（REAL 模式），后端不可达时自动降级为浏览器内仿真（SIM 模式）
- 可选 **eBPF XDP 内核旁路**（`bpf/`）：`bpf/` 目录为参考实现、当前**未集成**到 daemon 运行路径，默认部署即为上方用户态路径
- 纯 Python 标准库、零强制第三方依赖（DoQ/DoH3 可选装 aioquic）；systemd 一键托管
- **生产级加固**：CSRF/DNS Rebinding 防护、API Token 认证（可选）、TLS 证书验证 kill switch、systemd 安全沙箱（15+ 项硬化）、内存自动归还（PYTHONMALLOC + malloc_trim）、Prometheus 指标

WEB运行截图
<img width="2560" height="1294" alt="8b7fd55aebaabd3c6b02dbf5cebad588" src="https://github.com/user-attachments/assets/04e6dcbb-b222-491a-80c7-118b15af7561" />

<img width="2560" height="1294" alt="a83d7ef15e3db57cb7e31a933e20700d" src="https://github.com/user-attachments/assets/1cb773c9-506b-420a-86f4-cc0b5c3a22e2" />

<img width="2560" height="2769" alt="c5d0918474cc61c6cdda6f962fbbd6e4" src="https://github.com/user-attachments/assets/a0075bfb-ce7b-4090-ae4a-5937c73e6efe" />

<img width="2560" height="1755" alt="229f9d952d7ac82736bd199e083c2f31" src="https://github.com/user-attachments/assets/8da11ddf-6bf2-4736-9e3e-ba876defbdc7" />

<img width="2560" height="1294" alt="b1677fd9bb0a07c0fc65f6625fa16d42" src="https://github.com/user-attachments/assets/be6a213b-14f7-4fc8-8668-9085595c41a6" />




---

## 1. 架构（实际实现路径）

```
   DNS 客户端 ──UDP/TCP :53──▶  ebpdns daemon (Python3, 纯标准库)
                                ├─ 报文入口   (server.py)
                                │    解析 (qname, qtype) → 查用户态 LRU
                                │    命中 ──▶ 快路径直接回包(响应体预编码, 仅重拼 qid)
                                │    miss  ──▶ 进解析引擎
                                ├─ 用户态缓存 (cache.py)
                                │    LRU / Partitioned / TinyLFU, 模拟 BPF_MAP_TYPE_LRU_HASH
                                │    TTL 钳制 · serve-stale 过期兜底 · 剩余 TTL 落盘持久化
                                ├─ 解析引擎   (resolver.py)
                                │    分流规则 · 多上游并发 · 测速择优 · 预取 · 负缓存 · 熔断
                                ├─ 上游适配   (upstream.py / quic_upstream.py / probe.py)
                                │    UDP/TCP/DoH/DoT · 连接复用 · 0x20 校验 · Bootstrap 预解析
                                │    DoQ/DoH3 (aioquic, 常驻连接多路复用, 断线指数退避重连)
                                └─ HTTP API   (api.py :8080)  + 遥测 (telemetry.py)
                                          │
                                          ▼ 上游查询 (UDP/TCP/DoH/DoT/DoQ/DoH3)
                          AliDNS / DNSPod / Cloudflare / Google ...
```

| 层 | 实现 |
|---|---|
| 用户态守护进程 | Python 3.10+（零强制第三方依赖；DoQ/DoH3 需 aioquic） |
| 缓存语义 | 用户态 LRU/Partitioned/TinyLFU 模拟 `BPF_MAP_TYPE_LRU_HASH`（命中计数计入遥测 `kernel_direct`） |
| 上游协议 | UDP / TCP / DoH (HTTPS) / DoT (TLS) / DoQ (QUIC, RFC 9250) / DoH3 (HTTP/3) |
| 管理接口 | HTTP JSON API（28 端点）+ Web 控制台（内置 ECharts，本地化无外网依赖）+ Prometheus `/metrics` |
| 安全加固 | CSRF Origin/Referer 校验（含 LAN IP/端口归一化）、可选 API Token、DNS Rebinding 防护、0x20 投毒防护、路径遍历防护、systemd 沙箱 |
| 可选内核数据面 | C + libbpf (XDP)，`bpf/` 目录参考实现（预留接口，未集成） |

**数据面说明**：默认所有解析与缓存均在用户态完成——缓存命中由 daemon 主线程直接回包（不查询上游），语义上等价于 SmartDNS 的内存缓存，并计入「内核直答」遥测计数；`bpf/` 目录提供真实 XDP 内核旁路的参考 C 源码，仅在需要把命中下沉到网卡内核直答时另行集成（见 §9）。

---

## 2. 快速部署（Debian 13）

```bash
# 1. 准备（Python 3 已内置；仅当要编译真实 XDP 数据面才装编译工具）
sudo apt update && sudo apt install -y python3 python3-pip
#    （可选）启用 DoQ / DoH3（DNS over QUIC / HTTP3）上游时需要 aioquic
sudo pip3 install aioquic          # 或 Debian 源: sudo apt install -y python3-aioquic
# 2. 安装（拷贝到 /opt/ebpdns、生成 /etc/ebpdns/config.json、注册 systemd + 每日重启 timer）
sudo ./install.sh
#    install.sh 自动检测 python3/aioquic 依赖（apt→pip 三级回退），EBPDNS_SKIP_DEPS=1 可跳过
# 3. 按需编辑配置
sudo nano /etc/ebpdns/config.json
# 4. 启动 / 状态
sudo systemctl start ebpdns
sudo systemctl status ebpdns
# 5. 验证
dig @127.0.0.1 www.baidu.com
curl -s http://127.0.0.1:8080/api/status
# 6. 浏览器打开控制台
#    http://<服务器IP>:8080/
```

> **53 端口冲突**：Debian 的 `systemd-resolved` 默认占用 `127.0.0.53:53`（监听回环地址，通常不冲突）。
> 若你的机器另有 DNS 占用 `0.0.0.0:53`，可先 `sudo systemctl stop systemd-resolved`，
> 或在 `/etc/ebpdns/config.json` 里把 `listen` 改成其它端口（如 `0.0.0.0:5353`）。
> 53 端口需 root 权限；非 root 本地调试可用 `127.0.0.1:1053` 等非特权端口。

### 手动部署（不走 install.sh）

```bash
sudo mkdir -p /opt/ebpdns
sudo cp -r bin ebpdns web etc /opt/ebpdns/
sudo mkdir -p /etc/ebpdns
sudo cp etc/ebpdns.conf.json /etc/ebpdns/config.json
sudo cp systemd/ebpdns.service systemd/ebpdns-restart.service systemd/ebpdns-restart.timer \
     /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ebpdns
sudo systemctl enable --now ebpdns-restart.timer   # 每日 04:30 低峰重启（可选）
```

### 卸载

```bash
sudo systemctl stop ebpdns && sudo systemctl disable ebpdns
sudo systemctl disable --now ebpdns-restart.timer 2>/dev/null
sudo rm -f /etc/systemd/system/ebpdns.service \
          /etc/systemd/system/ebpdns-restart.service \
          /etc/systemd/system/ebpdns-restart.timer
sudo systemctl daemon-reload
sudo rm -rf /opt/ebpdns /etc/ebpdns
```

---

## 3. 命令行

```bash
/opt/ebpdns/bin/ebpdns run                # 启动 DNS + HTTP API
/opt/ebpdns/bin/ebpdns run --dns-udp 0.0.0.0:5353 --dns-tcp 0.0.0.0:5353 --api-port 8081
/opt/ebpdns/bin/ebpdns status             # 打印运行状态 JSON
/opt/ebpdns/bin/ebpdns config-print       # 打印当前生效配置
/opt/ebpdns/bin/ebpdns config-path        # 打印配置文件位置
```

也可用 `EBPNDS_CONFIG=<路径>` 环境变量指定配置文件。

---

## 4. 配置说明（/etc/ebpdns/config.json）

### 4.1 监听与管理

| 键 | 默认 | 说明 |
|---|---|---|
| `listen.udp` / `listen.tcp` | `0.0.0.0:53` | IPv4 DNS 监听地址 |
| `listen.udp6` / `listen.tcp6` | `null`（不监听） | IPv6 DNS 监听；需显式写出地址（如 `[::1]:53` 或 `[::]:53`）才开启，避免未配置时成为隐蔽的开放 IPv6 解析器 |
| `api.host` / `api.port` | `127.0.0.1` / `8080` | API 与控制台监听（install.sh 模板为 `0.0.0.0:8080`，绑非回环地址会打安全 WARNING） |
| `api.token` | `""`（空=不启用） | 可选 API Token 认证（Bearer/ X-API-Token）；设置后写操作与敏感读操作需带 token，控制台弹窗输入并持久化到 localStorage |
| `web_root` | null | 自定义控制台静态资源目录（null=内置） |

### 4.2 缓存

| 键 | 默认 | 说明 |
|---|---|---|
| `cache_size` | 131072 | 缓存容量（范围 1–10000000，越界 API 返回 400） |
| `cache_policy` | `lru` | `lru`=8 分桶 LRU（全局共享池，开销最低）；`partitioned`=按分流 group 隔离独立池（互不挤占）；`tinylfu`=W-TinyLFU 三段式 window1%/probation20%/protected80%+Count-Min Sketch（抗扫描污染，命中率通常高 5-15%，额外内存约 512KB）。切换自动热重载重建缓存 |
| `cache_partitions` | null | partitioned 模式各 group 容量比例（如 `{"domestic":0.6,"global":0.3,"default":0.1}`），仅 partitioned 生效 |
| `ttl` | 300 | 缓存默认 TTL（秒），实际取上游返回 TTL 与它的较小值 |
| `ttl_min` / `ttl_max` | 0 / 0 | 下发 TTL 管控：应答 TTL 钳制到该区间（0=不限制），同时作为缓存存活时长 |
| `serve_stale` / `stale_ttl` | false / 3600 | 过期缓存兜底：过期后窗口内仍返回旧数据（下发 TTL=0）并后台强制刷新，避免上游抖动 SERVFAIL |
| `persist_ttl` | 0 | 持久化恢复后的独立 TTL（秒）；0=按保存时剩余 TTL 原样恢复 |
| `prefetch` | true | TTL 到期前 85% 自动预取刷新（跳过 NXDOMAIN 负缓存；恢复缓存自动重排入预取队列；预取队列有界 65536 防堆积） |
| `kernel_direct` | true | 用户态缓存命中即计为「内核直答」遥测计数（真实 XDP 集成时保持语义一致） |
| `cache_file` | `/etc/ebpdns/cache.json` | 缓存持久化路径（每 60s + 退出时保存，重启自动恢复；json.dump 直写降低瞬时内存峰值） |

### 4.3 测速与上游选择

| 键 | 默认 | 说明 |
|---|---|---|
| `speed_test` / `speed_interval_ms` | true / 2000 | 上游测速择优；两次主动探测最小间隔 |
| `ip_speed_check` | true | 候选 IP 测速：对多 IP 答案并发探测 RTT 并按速度排序（SmartDNS 风格），关=保持上游返回顺序 |
| `ip_speed_probe` | both | 探测方式：`udp53` / `tcp443` / `both`（默认 both 取最快；TCP:443 更贴近真实访问） |
| `ip_speed_cache_ttl` | 60 | 候选 IP 测速结果缓存（秒） |
| `speed_timeout_ms` | 300 | 测速探测超时上限（毫秒） |
| `fallback` | true | 上游失败自动降级到其余上游（关=仅用首选，失败即 SERVFAIL） |
| `timeout_ms` | 1500 | 单次上游查询超时（全路径统一 deadline，含连接/解析/收发） |
| `max_parallel_upstreams` | 3 | 单查询并发上游数（fallback 时按延迟排序取最快 N 个） |

### 4.4 协议与网络

| 键 | 默认 | 说明 |
|---|---|---|
| `ipv4_first` | true | 同时存在 A/AAAA 时优先 A；AAAA 无记录时回退查 A（`ipv4_fallback` 计数） |
| `ipv6` | true | 关闭后 AAAA 查询直接返回空应答（全局一刀切） |
| `prefer_ipv4` | false | 双栈智能：仅当域名存在 A 记录（双栈）才屏蔽 AAAA 返回 NODATA，纯 IPv6 域名（无 A）正常解析——替代全局 `ipv6` 的精细化方案，不误伤 v6-only 域名 |
| `edns` / `edns_client_subnet` | true / null | 携带 EDNS0 OPT；可填 `203.0.113.0/24` 启用 ECS（支持 IPv4/IPv6 前缀，越界拒绝） |
| `edns_udp_size` | 1232 | 出站 EDNS0 UDP payload（字节），钳制 [512,9000]。1232=IPv6 最小 MTU 防分片安全值，超限应答置 TC 位由客户端走 TCP |
| `padding` | false | RFC 8467 加密查询填充：DoT/DoH/DoH3/DoQ 出站 OPT 填充到 128B 块（上限 512），抹平长度指纹；明文 UDP/TCP 不填充 |
| `dnssec_0x20` | true | DNS 0x20 投毒防护：明文 UDP/TCP 查询名大小写随机（约 +26bit 熵），响应校验 qname 大小写，失败自适应降级 |
| `rebind_protection` | true | DNS Rebinding/劫持防护：上游 A/AAAA 若为私有/保留/环回地址自动丢弃，全部为私有 IP 时返回 NODATA；forceIp 规则豁免 |
| `bootstrap_dns` | `223.5.5.5:53` | Bootstrap 解析器：启动时用该 UDP 上游预解析 DoH/DoT/DoQ/DoH3 的 hostname 为 IP（IP+SNI 连接），摆脱系统 /etc/resolv.conf 依赖 |

### 4.5 健康检查与熔断

| 键 | 默认 | 说明 |
|---|---|---|
| `health_check_interval` | 30 | 周期健康探测间隔（秒），轮转探测启用上游；0=关闭 |
| `health_probe_domain` | `www.baidu.com` | 健康探测域名 |
| `health_probe_timeout_ms` | 2000 | 健康探测超时 |
| `circuit_fails` / `circuit_open_s` | 3 / 30 | 连续失败 N 次熔断跳过该上游 M 秒（半开后下次查询试探恢复） |

### 4.6 规则与订阅

| 键 | 默认 | 说明 |
|---|---|---|
| `rules[]` | 见模板 | `match`: 精确域名或 `*.example.com` 通配；`action`: `group`/`forceIp`/`block`/`allow`；哈希索引 O(1)（10 万条级）。可带 `ttl_min`/`ttl_max`（规则级 TTL，命中时整体替换全局区间）、`group`、`ip`（forceIp，校验合法 IP） |
| `rule_sub_interval` | 3600 | 规则订阅自动更新间隔（秒），0=关闭；订阅明细独立存 `rules_sub.json`（不写 config.json） |
| `log_level` | info | 日志级别（debug/info/warning/error） |
| `log_format` | text | `text`=可读文本 / `json`=结构化 JSON lines（便于日志采集） |

### 4.7 上游对象字段（upstreams[]）

| 字段 | 说明 |
|---|---|
| `proto` | `udp` / `tcp` / `doh` / `dot` / `doq` / `doh3` |
| `addr` + `port` | IP 或域名 + 端口（DoH/DoT 域名经 Bootstrap 预解析） |
| `url` | DoH/DoH3 路径（如 `/dns-query`） |
| `group` | `domestic` / `global`（分流规则引用） |
| `latency` / `latency_measured` | 基础延迟 / 是否已实测（首次启动自动实测写回） |
| `enabled` | 是否启用 |
| `weight` | 可选权重 |
| `doh_strict_cert` / `dot_strict_cert` | 证书验证 kill switch（默认 false=证书错误时降级为 IP 直连/系统解析并标记；true=严格模式证书错误直接失败）。bulk 配置与单条编辑 API 均可写 |
| `allow_private_ip` | 允许该上游返回私有 IP（豁免 rebind 防护） |

> **默认上游**：内置 2 个国内 UDP 兜底 + 15+ 个 DoH/DoH3 端点（AliDNS/DNSPod 域名与 IP 直连、Cloudflare/Google/Quad9/NextDNS/OpenDNS/DNS.SB/AdGuard/HiNet），国内项默认启用，海外端点写入但默认 `enabled:false` 可按需启用。
>
> **DoQ / DoH3（可选依赖 aioquic）**：`proto:"doq"`（DNS over QUIC，RFC 9250，端口 853）与 `proto:"doh3"`（HTTP/3 DoH，端口 443）。每上游一条常驻连接（断线指数退避重连 2s→60s、查询多路复用、idle 60s）；未装 aioquic 时返回「aioquic 未安装」错误，不影响其他协议。安装：`sudo pip3 install aioquic`（或 `sudo apt install python3-aioquic`）。

配置可在**控制台「配置」页**在线编辑并「应用配置」持久化；除 `cache_size`/监听地址外基本即时生效（PUT /api/config 或 POST /api/reload 热重载，无需重启）。所有写接口对配置做类型/范围/枚举校验，非法值返回 400 与中文错误原因。`hook` / `map_type` / `percpu` 为 eBPF 数据面预留语义标记（真实 XDP 未集成）。

---

## 5. Web 控制台（http://<IP>:8080/）

| 页面 | 功能 |
|---|---|
| 数据面流水线 | 缓存命中（用户态直答）/ 未命中（多上游解析）/ 失败（SERVFAIL）的实时推演与日志，真实日志驱动 |
| 查询控制台 | 手动输入域名发起真实解析，逐步展示 入口 → 缓存 → 分流 → 多上游并发 → 测速择优 → 回填 完整链路 |
| 配置 | 缓存与策略（LRU/Partitioned/TinyLFU、TTL 管控、预取、serve-stale、持久化）· 测速与优选 · 上游服务器（增删改/一键重新测速/证书 kill switch）· 分流规则（添加/导入/URL 订阅），应用即持久化；规则列表超 500 条分页截断渲染（配置数组仍提交全量） |
| 遥测 | 命中率、QPS、延迟、查询类型分布、上游健康度、缓存占用（ECharts） |
| 架构说明 | 实际数据面路径与模块职责、技术栈、部署方式 |

控制台自动检测后端：连接成功显示 REAL 模式（真实数据）；后端未启动时显示 SIM 模式（内置仿真兜底，便于演示）。配置加载失败时显示横幅提示并自动重拉兜底。可用 `?route=telemetry` 等参数深链直达页面（`pipeline` / `query` / `config` / `telemetry` / `about`）。所有用户输入与后端返回均做 HTML 转义防 XSS。

---

## 6. HTTP API

写操作（POST/PUT/DELETE）带 **CSRF 防护**：校验 `Origin`/`Referer` 的 host:port 与监听地址一致（含 LAN IP、localhost 默认端口 80/443 归一化），无 Origin 的非浏览器请求（curl）放行。设置 `api.token` 后需带 `Authorization: Bearer <token>` 或 `X-API-Token`。所有写接口对输入做类型/范围/枚举/控制字符校验，非法值返回 400 与 JSON `{"error": "中文原因"}`。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/health` | 轻量健康检查（不经 CSRF/认证），供监控探活 |
| GET | `/api/status` | 运行状态、QPS、命中率、延迟、计数器、缓存占用、版本号 |
| GET | `/api/cache/stats` | 缓存明细统计（策略、容量、各分桶/分段占用） |
| GET | `/api/snapshot` | 完整快照：历史序列、日志事件、上游健康、手动查询记录 |
| POST | `/api/query` | `{domain, qtype}` 手动解析，返回完整 trace |
| GET/PUT | `/api/config` | 读写配置（PUT 全量校验+持久化，白名单外字段返回 ignored_keys，非法值 400） |
| POST | `/api/reload` | 热重载配置（等价 SIGHUP）：原子换配置、缓存容量/策略调整、规则索引重建、上游 diff 回收连接 |
| GET/POST | `/api/upstreams` | 上游列表 / 新增（逐项校验 proto/port/字段） |
| PUT/DELETE | `/api/upstreams/<id>` | 修改 / 删除上游（含 doh_strict_cert/dot_strict_cert；变更端点回收旧连接池/QUIC 连接/遥测） |
| GET/POST | `/api/rules` | 分流规则列表 / 新增（校验 action/ip/字段类型） |
| PUT/DELETE | `/api/rules/<id>` | 修改 / 删除规则 |
| POST | `/api/rules/import` | `{url}` 或 `{text}` 批量导入域名列表（URL 强制 https，支持 anti-ad 等规则源） |
| POST | `/api/rules/subscribe` | 新增规则订阅（URL，独立存 rules_sub.json） |
| POST | `/api/rules/subscribe/update` | 立即拉取更新订阅（错误透出真实文件路径与异常） |
| DELETE | `/api/rules/subscribe` | 删除订阅 |
| POST | `/api/reprobe` | 一键重新测速：对所有启用上游并发实测延迟并写回配置 |
| POST | `/api/restart` | 重启服务（systemd 用 `systemctl restart`；手动运行用 `os.execv`） |
| POST | `/api/reset` | 重置遥测计数与缓存 |
| POST | `/api/profile` | cProfile 采样 N 秒（1–10），返回 Top 25 热点（全局单实例锁，409 互斥） |
| GET | `/api/logs?since=N` | 增量日志（环形缓冲，断点续传） |
| GET | `/api/pipeline` | 流水线站点信息（上游 addr 脱敏） |
| GET | `/metrics` | Prometheus 文本指标（ebpdns_* 系列，含上游健康度，标签转义） |
| GET | `/` `/index.html` `/echarts.min.js` `/static/*` | 控制台静态资源（realpath 防路径遍历） |

---

## 7. 稳定性、安全与运维

### 7.1 systemd 托管与内存治理

- **崩溃自启**：`Restart=on-failure` + `RestartSec=5`；进程异常退出（含 SIGKILL/OOM）约 5s 自动重启，重启后从磁盘载入持久化缓存、恢复规则/上游并重排预取。
- **优雅退出**：`KillSignal=SIGTERM` + `TimeoutStopSec=5`。SIGTERM 先停 DNS 释放端口→保存缓存→停线程池（`cancel_futures`、连接锁/`as_completed` 超时兜底）→通知 trim 线程停止（join 超时 2s）→`os._exit(0)`，正常 <1s 完成，避免 join 卡在慢 DoH/getaddrinfo 上。
- **内存自动归还（v1.9.83）**：systemd unit 内置 `PYTHONMALLOC=malloc`（Python 小对象直接走 glibc，free 后可归还 OS）+ `MALLOC_ARENA_MAX=2`（压多线程 arena 分裂）+ `MALLOC_MMAP/TRIM_THRESHOLD_=131072`。daemon 内 `cli.py` 起 trim 线程：每 300s 检查，**RSS > 300MB 且距上次 trim 增长 > 10%** 才调 `malloc_trim(0)`（基线取 trim 后 RSS、jemalloc 经 mallctl 探针检测到则自动跳过、trim 耗时 >20ms 记日志、尖刺 >50ms 降级 `malloc_trim(1<<20)`；不含 gc.collect 因实测 88ms STW 且回收 0 对象）。生产实测长期 RSS 稳定在 ~45–47MB（缓存 131072 配置下）。
- **内存兜底**：`MemoryHigh=1G`（触发回收压力）+ `MemoryMax=1.5G`（超限被 OOM 选中后 systemd 自动重启）。
- **每日低峰重启**：`ebpdns-restart.timer` 每天 04:30（随机延迟 0–300s）重启一次做内存卫生，install.sh 自动注册；`systemctl stop ebpdns-restart.timer` 可临时关闭。
- **Plan B（jemalloc）**：若 glibc 方案 trim 有尖刺或 sys CPU 升高，unit 注释中给出 jemalloc 切换方式（`LD_PRELOAD` + `MALLOC_CONF=background_thread,dirty_decay_ms:5000`），trim 线程会自动跳过。

### 7.2 安全沙箱（systemd unit 内置 15+ 项硬化）

`NoNewPrivileges`、`ProtectSystem=strict`（仅 `ReadWritePaths=/etc/ebpdns`）、`ProtectHome`、`PrivateTmp`、`PrivateDevices`、`ProtectKernelTunables/Modules/ControlGroups`、`RestrictAddressFamilies=AF_INET/AF_INET6/AF_UNIX`、`RestrictRealtime/SUIDSGID/Namespaces`、`LockPersonality`、`ProtectProc=invisible`、`MemoryDenyWriteExecute`（W^X）；能力仅保留 `CAP_NET_BIND_SERVICE`（绑定 53），移除 `CAP_NET_RAW`；`UMask=0027`、`LimitNOFILE=65536`。

### 7.3 应用层防护

- **CSRF / DNS Rebinding**：写操作校验 Origin/Referer 的 host:port（LAN 私网/回环 IP + localhost 默认 80/443 端口归一化）。
- **DNS Rebinding 应答防护**：`rebind_protection` 丢弃上游返回的私有/保留/环回 IP（forceIp 与 `allow_private_ip` 豁免）。
- **0x20 投毒防护**：查询名大小写随机 + 响应 qname 校验，失败自适应降级；UDP 响应校验 qid + 源 IP 集合。
- **DoS 防御**：UDP miss 队列有界信号量（池满丢弃，客户端重试）；`decode_name` 压缩指针 32 跳上限；请求体 64MB 上限并 drain；应答上限 + TC 位；TCP 连接信号量限流 + 1MB 缓冲上限；ReDoS 正则信号量 + 0.5s 超时 + 灾难性正则（嵌套量词）预检拒绝。
- **TLS 证书**：DoH/DoT 默认证书错误时降级（bootstrap 缓存 IP→系统解析→IP 字面量三路径，降级连接标记 `_ebpdns_degraded` 不入连接池、30s 不复用），`doh_strict_cert`/`dot_strict_cert=true` 可切严格模式（fail-closed）；DoQ/DoH3 不降级（fail-closed）。
- **配置安全**：所有写接口白名单 + 类型/范围/枚举/控制字符校验；配置加载失败不静默回退默认值（防热重载清空上游/监听）；保存用原子写（tmp+fsync+rename）。
- **静态资源**：realpath 解析防路径遍历；响应带 `X-Content-Type-Options: nosniff`。

### 7.4 上游可靠性

- **Bootstrap 预解析**：启动时用 `bootstrap_dns`（UDP）并发预解析所有加密上游 hostname（总上限 5s），后续 IP+SNI 连接，不依赖系统 DNS；连接失败按阶段失效/保留缓存（建连失败失效、传输期抖动不误删）。
- **熔断**：连续失败 `circuit_fails`（默认 3）次跳过该上游 `circuit_open_s`（默认 30s），半开后下次查询试探；`health_check_interval` 周期主动探测喂入熔断器。
- **连接池**：DoH/DoT 每 key 连接复用 + 30s 空闲回收；降级连接即弃；上游变更/删除/reload 按端点 diff 回收连接池、QUIC 连接与遥测。
- **QUIC**：DoQ/DoH3 常驻连接多路复用，断线指数退避重连（2s→60s，稳定存活 60s 才复位），查询超时取消协程释放引用。

---

## 8. 性能实测

### 8.1 当前版本（v1.9.135）端到端压测

测试配置：`test/perf_config.json`（监听 127.0.0.1:15365，cache_size 65536，上游 AliDNS 223.5.5.5:53 UDP），`test/perf_compare.py` 8 线程，2×5 分钟：

| 指标 | Run1 | Run2 |
|---|---|---|
| 平均 QPS | ~40,276 | ~40,146 |
| 错误数 | **0** | **0** |
| P99 延迟 | 0.59ms | 0.52ms |
| 服务 RSS | 44→47MB（稳定，无爬升） | |
| 运行时日志 | 0 ERROR（上游瞬时 SERVFAIL 为正常告警） | |

53 轮迭代累计压测 20 亿+ 查询，服务端 0 错误；缓存策略 lru/partitioned/tinylfu 三模式、6 协议上游、热重载/上游增删/订阅等并发操作（每轮上百次）均验证无回归。

### 8.2 缓存命中吞吐（历史微基准，供量级参考）

早期版本在 2 核 / 4GB 类虚拟机上对同一域名反复查询（纯缓存命中快路径）测得：单并发 ≈41,000 QPS（p50 0.03ms）、8 并发 ≈73,000 QPS（p99 0.19ms）、32 并发 ≈63,000 QPS；200 域名 32 并发 ≈76,000 QPS，错误率 0。该微基准脚本已演进并入 `test/` 压测体系，**当前版本性能以 §8.1 端到端压测为准**。缓存命中路径 p50 ≈ 0.03–0.6ms。

**首次解析（真实 miss）延迟**：受外网上游延迟限制，UDP 上游 ≈6–9ms；多 IP 域名（含测速择优）≈60ms。

### 8.3 长时间稳定性

- 缓存填满配置容量后 RSS 进入平台期不再增长，无内存泄漏；malloc_trim 机制下长期运行空闲页归还 OS（§8.1 的 ~44–47MB 为 cache_size 65536 压测配置下的数据；实际 RSS 随缓存容量、规则数与上游数量上升，属存活对象，trim 不回收）。
- 高负载 SIGKILL → 数秒内 systemd 自动重启，重启后配置/规则/上游/缓存全部恢复。
- 高负载 SIGTERM 优雅退出 <1s（先停 DNS 释放端口→存缓存→停池）。

---

## 9. 进阶：真实 eBPF XDP 内核旁路（可选，预留接口）

默认软件以纯用户态运行（无需内核权限）。`bpf/` 目录提供「缓存命中由网卡内核直答」的 XDP 参考实现：

```bash
sudo apt install clang llvm libbpf-dev linux-libc-dev bpftool
cd /opt/ebpdns/bpf
make
sudo ./load.sh eth0            # 将 XDP 程序挂到目标网卡
sudo ip link set dev eth0 xdp off   # 卸载
```

要点：
- **当前为参考实现，未集成到 daemon**：即使编译挂载，内核 `dns_cache` map 因无用户态回填而恒为空，不会产生加速；需另行开发 daemon 侧 libbpf/bcc 回填集成
- 内核 ≥ 5.4（建议 5.15+），开启 BTF，网卡驱动支持原生 XDP（云虚拟机 virtio 网卡通常不支持）
- 未命中 `XDP_PASS` 转用户态 daemon；命中 `XDP_TX` 内核回包。map 名/键值布局见 `ebpdns_xdp.h`
- 详见 `bpf/README.md`

---

## 10. 本地开发 / 测试

```bash
# 以非特权端口本地运行（DNS 1053 / API 8081）
python3 -m ebpdns run --dns-udp 127.0.0.1:1053 --dns-tcp 127.0.0.1:1053 --api-port 8081
#   也可用环境变量 EBPDNS_CONFIG=<路径> 指定配置
#
# 压测（先用 test/perf_config.json 在高端口起一个测试实例）
python3 test/perf_compare.py          # 8 线程端到端压测
# 边界 / 功能 / 并发回归
python3 test/boundary_test_v1987.py
python3 test/functional_v1989.py
python3 test/concurrent_ops.py        # 热重载/上游增删/订阅并发操作
#
# 自研客户端验证真实解析
python3 - <<'EOF'
from ebpdns import dnsmsg
import socket
q, _ = dnsmsg.build_query('www.baidu.com', dnsmsg.type_code('A'))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
s.sendto(q, ('127.0.0.1', 1053)); data, _ = s.recvfrom(4096)
print(dnsmsg.parse_message(data)['answers'])
EOF
# 打包（剔除 test/、开发文档、__pycache__；用法 ./package.sh <version>）
./package.sh 1.9.135
```

---

## 11. 目录结构

```
ebpdns/
├── bin/ebpdns              # 可执行入口
├── ebpdns/                 # Python 包（纯标准库；DoQ/DoH3 可选 aioquic）
│   ├── __main__.py         # python -m ebpdns 入口
│   ├── cli.py              # 命令行/daemon 装配 + malloc_trim 内存治理线程
│   ├── config.py           # 配置加载/校验/原子保存（DEFAULTS、类型范围枚举校验）
│   ├── dnsmsg.py           # DNS 报文编解码（EDNS/压缩指针/TC/边界守卫）
│   ├── cache.py            # LRU / Partitioned / W-TinyLFU 三策略缓存
│   ├── upstream.py         # UDP/TCP/DoH/DoT（连接池、Bootstrap、0x20、证书降级、熔断）
│   ├── quic_upstream.py    # DoQ/DoH3（aioquic 常驻连接、多路复用、退避重连）
│   ├── probe.py            # 上游延迟并发探测
│   ├── resolver.py         # 解析引擎（分流索引/并发/测速/预取/负缓存/fallback/健康检查）
│   ├── server.py           # UDP/TCP DNS 服务器（命中快路径、有界队列）
│   ├── telemetry.py        # 遥测计数/QPS/延迟窗口/事件采样
│   └── api.py              # HTTP JSON API（28 端点）+ CSRF/Token + 静态服务
├── web/
│   ├── index.html          # 控制台单页（REAL/SIM 双模式，ECharts 本地化）
│   └── echarts.min.js      # 图表库（本地，无外网依赖）
├── bpf/                    # 可选 eBPF XDP 内核旁路（参考实现，未集成）
├── systemd/
│   ├── ebpdns.service      # 主服务（内存治理 + 15+ 项沙箱硬化）
│   ├── ebpdns-restart.timer  # 每日 04:30 低峰重启
│   └── ebpdns-restart.service
├── etc/ebpdns.conf.json    # 配置模板
├── install.sh              # 安装脚本（依赖自动检测、注册服务与 timer）
├── package.sh              # 打包脚本（剔除测试与开发文档）
├── test/                   # 压测/边界/功能/并发回归脚本（打包时剔除）
├── Makefile / LICENSE / CONTRIBUTING.md
└── README.md
```

---

## 12. 已知限制与设计取舍

- 解析结果为"精简应答"（SmartDNS 风格，只返回目标类型地址并择优），不完整透传 CNAME 链；对大多数客户端无影响（CNAME 链在 miss 路径内部跟踪展开到链尾 A/AAAA 落缓存）。
- 未实现 DNSSEC 签名验证（转发型解析器典型取舍）；EDNS DO 位可透传，但不做本地验签。
- DoH/DoT/DoQ/DoH3 的 hostname 经 Bootstrap 解析器（v1.9.42，启动时 UDP 预解析 + 缓存 + 失败回退系统解析），不强依赖系统 `/etc/resolv.conf`。
- DoQ/DoH3 证书错误不做降级（fail-closed，与 DoH/DoT 的可配 kill switch 不同）；未安装 aioquic 时这两类上游直接报错，不影响其他协议。
- 真实 XDP 内核直答需内核 ≥5.4（建议 5.15+，开启 BTF）与原生 XDP 网卡驱动支持，属预留/进阶选项（`bpf/` 参考实现未集成到 daemon，云虚拟机 virtio 网卡通常不支持原生 XDP）。
- 单进程 + 有界线程池模型（Python GIL 下多进程会各自独立缓存/统计、降低命中率，SO_REUSEPORT 多进程收益有限）；高并发通过分桶锁、有界队列反压与快路径预编码保证。
- HTTP/2 多路复用未引入（零第三方依赖偏好）；DoH/DoT 以每 key 连接池（多连接 + 30s 空闲回收）覆盖主要复用收益。

---

## 13. 版本历史（要点）

> v1.9.48–v1.9.135 期间历经数十轮高强度代码审查→修复→压测迭代（累计修复数百项，压测累计 20 亿+ 查询 0 服务端错误），以下只列关键里程碑；更早历史见本节后半部分。

- **v1.9.135**：**连续两轮高强度审查全模块零问题（生产就绪基线）**。后期关键修复：CSRF 对具体 LAN IP 绑定误拒全部写操作（自早期引入、潜伏 25 轮的深层 bug，绑定 `192.168.x.x` 时 POST/PUT/DELETE 一律 403）、localhost 默认端口（80/443）CSRF 归一化、Content-Length 非数值兜底 400、cli.py IPv6 地址加方括号、前端 CSS 变量名与死变量清理。网络模块连续 11 轮、核心连续 5 轮审查零问题。压测 QPS ~40k、0 错误、P99 <0.6ms、RSS 44→47MB 稳定。

- **v1.9.100 前后（输入校验与配置安全闭环）**：全 7 条规则写入路径统一 `_validate_rule_dict`、上游写入统一 `_validate_upstream_dict`（bulk PUT 不再绕过 proto/port/action/ip 校验）；forceIp 的 ip 做 ipaddress 合法性校验；DNS TC 位掩码笔误修正（0x7B10→0x7910）；遥测白名单补 QUIC 字段；前端测速/导入/订阅后改为按 id 合并配置（不再整体覆盖丢失未保存编辑），非 2xx 响应解析后端中文错误体，规则列表 500 条分页截断（配置数组仍提交全量）。

- **v1.9.98（DoH 证书错误降级三路径）**：DoH/DoT 上游证书错误（如自签/CDN 证书问题）从直接失败改为可配降级——依次尝试 Bootstrap 缓存 IP、系统解析 IP、IP 字面量（SNI/Host 保留），降级连接打 `_ebpdns_degraded` 标记不入池、30s 不复用；新增上游级 `doh_strict_cert`/`dot_strict_cert` kill switch（true=严格 fail-closed）。修复降级标记未传递到连接池外层、IP 字面量路径不可达、pollStatus 配置重拉不闭环等迭代问题。

- **v1.9.92（缓存三模式文档与干净打包）**：前端缓存策略说明从 2 种补全为 3 种（lru 全局共享池 / partitioned 按 group 隔离 / tinylfu 三段式），修正"lru 与 partitioned 行为一致"的错误描述；README 补 cache_policy/cache_partitions；打包脚本 package.sh 剔除 test/ 与全部开发过程文档（find -prune + tar --no-recursion，git 包先出 /tmp 防管道竞态）。

- **v1.9.89–v1.9.91（安全与可靠性加固）**：CSRF 校验防 DNS Rebinding（Origin/Referer host:port 比对，含 LAN 私网/回环 IP 与端口归一化）；订阅 https 强制在全部 4 条路径补齐；`_sorted_ups_cache` 三字段非原子赋值修复；systemd 安全沙箱（15+ 项硬化，见 §7.2）；配置文件权限 600；0x20 失败计数竞态、QUIC 关闭标志可见性、TinyLFU 老化持锁全表扫描、UDP fd 泄漏等修复；**配置加载失败不再静默回退默认值**（防热重载把上游/监听/缓存整套替换为默认导致服务中断）；ECS 前缀污染预取修复；DoH url 控制字符注入在 3 条遗漏路径补齐。生产环境"订阅更新 500（磁盘满/权限）"热修复：移除 tmpfs/overlayfs 上会失败的 os.fsync，保存错误透出真实文件路径与异常。

- **v1.9.85–v1.9.88（多轮深度校验）**：PartitionedCache `_allocate` 容量分配死循环（P1）、API 无读超时的控制面 DoS（P1）、切换缓存策略丢失 cache_size（P1）、DoT 重试路径 TLS socket fd 泄漏（P1）、前端 PUT 后轮询覆盖未保存编辑（P1）、预取队列无硬上限（补 65536 有界）、热重载漏清已删/变更上游的遥测与连接（与 API 写路径对齐）；**默认配置不再隐藏绑定 `[::]:53`（隐蔽开放 IPv6 解析器，P1）**，udp6/tcp6 默认 null 需显式开启。

- **v1.9.84（性能与正确性大修）**：cProfile 驱动热路径优化，QPS 17,620→26,867（+52.5%，struct.Struct 预编译、LRUCache.get 快路径、计数锁合并等）；修复 VmRSS 指标误读（ru_maxrss 与 /proc VmRSS 混淆）、QR 位字节、TTL 衰减截断、ECS prefix 硬编码、probe_ip port 形参错位回归、_read_json 超限 413 早期返回等约 80 项（9 P1、28 P2）。

- **v1.9.83（长期运行内存治理，生产 831MB 问题）**：定位到默认 pymalloc arena 中已 free 空闲页不归还 OS（malloc_trim 在默认模式仅降 1.9MB，PYTHONMALLOC=malloc 下可降 109MB）。落地：systemd 设 `PYTHONMALLOC=malloc` + `MALLOC_ARENA_MAX=2` + MMAP/TRIM 阈值；cli.py 阈值触发 trim 线程（RSS>300MB 且增长>10%、最小间隔 5min、jemalloc 探针自动跳过、尖刺降级、耗时日志；gc.collect 因 88ms STW 且回收 0 对象而移除）；cache.json 改 json.dump 直写省 ~15.6MB 瞬时峰值；优雅退出 Event+join(2s)；MemoryHigh/Max 兜底；每日 04:30 低峰重启 timer；jemalloc 作为 unit 注释中的 Plan B。压测 QPS 仅 -2%（噪声内）。

- **v1.9.47**：**响应 IP 合法性校验（防 DNS 劫持/rebinding）**。上游返回的 A/AAAA 若为私有/保留/环回地址（10.x/192.168.x/127.x/169.254.x/fc00::/7 等）自动丢弃，全部答案均为私有 IP 时返回 NODATA；forceIp 规则豁免。配置项 `rebind_protection`（默认开启），前端可开关。

- **v1.9.46**：**实测延迟排序（修复 v1.9.45 延迟升高）**。上游选择从"配置静态延迟排序"改为"实测平均延迟优先"，无实测时回退静态延迟；失败率>50%的上游加 500ms 惩罚排后。解决 v1.9.45 中配置延迟不准确（如 DNSPod DoH3 配置 1232ms 但实测 40ms）导致最快上游被排到后面、平均延迟从 24ms 升至 62ms 的问题。
- **v1.9.45**：**上游请求爆炸修复（4889万→6.7万）**。三大优化：① 尊重 `max_parallel_upstreams` 配置——fallback=True 时按延迟排序取最快 N 个并发（默认 3），替代旧版"并发全部上游"；② 预取/serve-stale 后台刷新只用最快 1 个上游（`max_upstreams=1`），不需要测速择优；③ `upstream_queries` 计数加 `counted` 判断，预取/内部调用不再污染统计。生产环境 56 小时上游请求从 4889 万降至预计 ~1000 万（减少 80%），延迟和内存同步改善。
- **v1.9.44**：**Bootstrap 并发解析（修复启动延迟 46 秒）**。Bootstrap 预解析从串行改为线程池并发，单查询超时 2s，总上限 5s；不可达 DNS 时 15 个 hostname 从 45 秒降至 5 秒。日志始终输出 `X/Y` 解析结果（0 个也输出，方便排查）。
- **v1.9.43**：**TCP 端口冲突自愈**。TCP 服务器新增三重机制解决重启时 `Address already in use`：① SO_REUSEPORT 允许新旧进程同时绑定（内核负载均衡，零停机切换）；② 绑定失败自动重试 3 次（间隔 200ms，覆盖 TIME_WAIT 场景）；③ 关闭时 SO_LINGER=0 避免 TIME_WAIT 占用端口。TCP6/TCP 重启不再端口冲突。
- **v1.9.42**：**Bootstrap 解析器（解决已知限制2）**。启动时用 UDP 上游（默认 223.5.5.5:53，可配置 `bootstrap_dns`）预解析所有 DoH/DoT 的 hostname，缓存 IP；后续 DoH/DoT 连接直接用 IP + SNI，彻底摆脱系统 `/etc/resolv.conf` 依赖。解析失败的上游自动回退系统 getaddrinfo，不影响启动。修复 `_is_hostname` 对 IPv6 地址的误判。
- **v1.9.41**：全面检查与性能优化。① 规则匹配性能优化——allow 白名单检查移到规则缓存未命中后，hot path 不再每次遍历 allow 通配；② 10 分钟压测验证：3509 万查询 0 错误，QPS 58484，p50 0.1ms，峰值内存 160MB 稳定；③ API 联动性全量检查（10 端点全部正常）、缓存持久化+预取+规则联动验证、日志实时性验证、遥测数据一致性验证。
- **v1.9.40**：Python GIL/性能优化。LRUCache 单锁改 8 分桶锁——不同域名的查询并行读写不同分桶，消除高并发缓存命中时的全局锁竞争。DoH/DoT 连接复用经核实已实现（_ConnPool 4 连接/key，30s 空闲回收，失效自动重建）。
- **v1.9.39**：基于 v1.9.31 干净基线，新增两项功能。① **截断 TCP 回退**：UDP 上游返回 TC=1（truncated）时自动用 TCP 重试同一上游，获取完整应答（DNSSEC/大记录场景）；② **白名单动作**（allow）：allow 规则单独建索引，匹配时优先于 block/group/forceIp，命中即放行。前端逐条规则/导入下拉框均已加"放行(白名单)"选项。负缓存和 Top N 经核实 v1.9.31 已有。
- **v1.9.17**：**TinyLFU protected 段（Caffeine 分段式）**。TinyLFUCache 三段化 window(1%)/probation(40% main)/protected(60% main)：① 命中即晋升（probation 命中→protected，protected 满挤队首回 probation）；② 准入逻辑修复——probation 有空间直进、main 总容量未满直进 protected 回填（修复"准入比较拒绝低频 candidate 后 window 少 1 且无回填→缓存永久缩水"，实测 300 容量缩水至 129，修复后满 300）、main 满才与 probation 队首做 CMS 频率准入（修复"低频突发流量绕过比较冲刷高频候选"）；③ recordWrite 语义：put 也计频（Caffeine 一致，新条目首次写入不再以 freq≈0 在准入中必输）。实测：Zipf(400域名/300容量压力) LRU 94.1% vs TinyLFU 93.9% 持平；80%热点/500容量 98.9% 持平；高频 key 经 2000 个低频突发域名冲击仍驻留 protected（保护段生效）。验证：新增 test_tinylfu_protected_segment 单测（晋升/保护/容量守恒/序列化兼容），35 单测全 PASS，ft28 39/39（tinylfu 配置下），热重载 lru→tinylfu 缓存重建端到端 OK；7127 轮压测零 ERROR/零重启/12-17k q/s。
- **v1.9.16**：九项增强功能"选最优实现"落地（前段 v1.9.14/v1.9.15 为 geosite/geoip 分流、0x20 投毒防护、JSON 日志+metrics、高级规则、连接级健康度、Python 性能优化，交付未发版记录）。① **配置热重载**（POST /api/reload 与 SIGHUP 等价）：原子换配置引用、缓存容量即时调整、cache_policy 切换重建容器、geo 数据文件变化重建 GeoDB、规则索引重建，返回 changed 明细；② **上游熔断周期化**：`health_check_interval` 周期主动探测（前 3 个启用上游轮转探测 health_probe_domain，2s 超时），喂入既有熔断器（circuit_fails=3 / circuit_open_s=30），0=关闭；③ **规则订阅自动更新**（rule_sub_interval，0=关闭）：按 config 元信息重拉订阅覆盖 rules_sub.json 明细（独立文件，不写 config.json）；④ **CNAME 链跟踪/展开**：上游 NODATA 含 CNAME 回链、A/AAAA miss 路径递归展开（深度<8 防环）、`_fill_cache` 取链尾真实 A/AAAA 落缓存（修复缓存命中返回 CNAME 链头 bug）；⑤ **缓存分区**：PartitionedCache（默认 group 分区：domestic/global/其余，serialize 3 元组 key，restore 兼容旧 2 元组）；⑥ **DoH 连接复用**（_ConnPool 空闲超龄 30s 惰性回收；HTTP/2 多路复用未引入——环境无 h2 库、零依赖偏好下连接复用已覆盖主要收益，README 记录取舍）；⑦ **Top N 统计**（top_domains/top_clients/top_upstreams，Counter 上限 2048 超限裁剪低频一半防随机域名无限增长）；⑧ **TinyLFU/W-TinyLFU 淘汰**（`cache_policy: "tinylfu"`，Count-Min Sketch 频率估计 + W-TinyLFU 分段，命中率与 LRU 相当（20k 查询/80% 热点均 98.5%），Zipf 单测 TinyLFU 93.9% vs LRU 94.1% 无显著差异）；⑨ **多进程/multi-worker 与性能剖析**：选最优为"单进程 + 有界线程池"（Python GIL 下多进程各自独立缓存/统计 = 命中率下降，SO_REUSEPORT 多进程收益有限且复杂度高）+ `/api/profile` 性能剖析端点（cProfile 采样 N 秒默认 5 上限 30，返回 Top 25）。附带：api.py 历史隐患 `log` 未定义修复（AppContext.reload 触发 NameError）、doctest 前 end-to-end 验证（Top N/热重载/订阅自动更新/geo 自动更新/CNAME 链展开）。新增单测 test_new_features.py 6 用例全 PASS，既有单测全过，ft28 39/39。
- **v1.8.7**：控制台「重启服务」按钮取消 confirm 确认框，点击直接调用后端异步重启（立即返回、控制台自动重连）。
- **v1.8.6**：控制台「分流规则」取消 prompt 弹窗，改为卡片内单行直接添加（域名输入框 + 添加按钮，支持逗号分隔批量、回车触发），已浏览器实测批量添加两条规则即时入列。
- **v1.8.5**：install.sh 依赖自动检测与自动安装。启动时 0/4 步检测 python3（缺失自动 apt 安装）与 aioquic（DoQ/DoH3 需要，缺失按 apt python3-aioquic → python3 -m pip → pip3 三级自动安装）；`EBPDNS_SKIP_DEPS=1` 可跳过自动安装。自动安装失败仅降级 DoQ/DoH3（UDP/TCP/DoH/DoT 不受影响）。已在沙箱实测自动安装 aioquic 1.3.0 成功。
- **v1.8.4**：全面代码审查（逐文件逐条）。install.sh 就地安装增加关键文件完整性校验并提示 aioquic 依赖；API /status 返回 config_path、前端取消硬编码路径；新增 7 项高级单测（分流规则 1 万条匹配、熔断器开/重置/超时恢复、候选 IP 测速缓存命中与上限清理、block/forceIp 动作）。发布前综合测试 3 轮：每轮全新部署 + 27 项全功能联合测试 + 5 分钟压测（557-599 万查询 100%、QPS 18.5k-19.9k、p99 6.7-7.2ms、RSS 稳定）+ 高负载重启（总中断 1.4-2.4s）+ kill -9 崩溃自动重启恢复。
- **v1.8.3**：缓存持久化写盘改为 compact JSON（大缓存退出保存提速），配合退出路径优化进一步缩短高负载重启总中断。3 轮 QA 循环验证：每轮 5 分钟 540 万+ 查询 100% 成功（QPS 17,900-18,000）、RSS 稳定无泄漏、60 次响应探测无假死、kill -9 后 systemd 自动重启、高负载 SIGTERM 重启总中断 1.0-1.9s。
- **v1.8.2**：性能与重启优化。① DoQ/DoH3 慢协议查询原走主 UDP 池（超时 3s 会占满 worker 拖垮 miss 吞吐）——归入独立慢池（8 workers），实测 6 协议上游 miss 保持 12k QPS、5 分钟 542 万查询 100% 成功 QPS 17,999；② 合并 miss 路径遥测计数锁（count_query 一次加锁替代两次）；③ 退出路径改为「先停 DNS 释放端口→再存缓存→再停池」，高负载 SIGTERM 后 DNS 停止应答 421ms、进程退出 823ms、systemctl restart 式重启总中断 1.0-1.5s（压测中 40 线程 15.5 万查询 99.92% 成功）；④ 清理未使用导入。
- **v1.8.1**：QA 循环修复。① UDP 上游 host 为域名时源地址校验失效（域名 vs IP 字符串恒不匹配导致所有响应被丢弃→超时）——改为解析出全部 A 记录作 IP 集合校验，解析失败则靠 qid 兜底；② DoH3 `_streams` 状态字典每次查询建条目从不清理，长期运行内存泄漏——查询结束即删除；③ 移除无效配置项 `live_rate` 与 `config-path` 多余输出。实测：命中 32 线程 27,365 QPS、混合 45s 48 线程 78.8 万查询 100% 成功、5 分钟 485 万查询 100% 成功（QPS 16,126 / p50 1.2ms / p99 7.8ms）、RSS 稳定 32MB 零增长、60 次响应性探测全 OK 无假死、kill -9 后 systemd 2s 自动重启恢复正常。
- **v1.8.0**：新增 QUIC 传输上游（可选依赖 aioquic）。`proto:"doq"`（DNS over QUIC, RFC 9250, 端口 853）与 `proto:"doh3"`（HTTP/3 DoH, 端口 443）内置实现：每上游常驻 QUIC 连接（断线自动重连 + 查询失败主动重建 + idle_timeout 20s），多查询连接上多路复用；实测本地 DoQ 复用 9ms / 并发 20/20 成功 32ms，DoH3 阿里 20ms / 并发 10/10 成功 10ms。候选 IP 测速增强为 SmartDNS 风格：`ip_speed_check` 开关 + `ip_speed_probe`（udp53/tcp443/both）+ `ip_speed_cache_ttl` 探测结果缓存（实测 223.5.5.5 测到 6ms 排最前、二次查询缓存命中免探测）。前端上游协议下拉新增 DoQ/DoH3（端口联动 853/443）。压测：48 线程 45s 79.5 万查询 100% 成功、内存零增长（56.8MB 恒定）、线程稳定 65、SIGTERM 1s 优雅退出。
- **v1.7.8**：修复 systemd 停止超时（stop-sigterm timeout → SIGKILL）。根因：主线程优雅收尾完成后，解释器退出时会 join ThreadPoolExecutor 的非 daemon worker；负载期 worker 若阻塞在慢 DoH HTTPS / getaddrinfo（系统 DNS 解析无超时）上，join 会挂起数秒~十几秒导致 systemd 超时强杀。修复：收尾完成后 `os._exit(0)` 直接终止进程（持久化缓存/停 server/停池均已完成），实测 40 线程 DoH 高负载下 SIGTERM 1 秒内退出、exit code=0、无 SIGKILL。
- **v1.9.13**：新增三项协议级功能（用户从差距分析 P1 清单中选定）。① **加密查询填充 + EDNS0 UDP size 防碎片**：出站查询按上游协议分组构造——明文 UDP/TCP 用普通报文，DoT/DoH/DoH3/DoQ 在 EDNS OPT 中携带 RFC 8467 Padding 选项（128B 块对齐、上限 512，抹平长度指纹防流量分析）；EDNS UDP payload 钳制到 `edns_udp_size`（默认 1232=IPv6 MTU 防分片安全值，大应答不再被 NAT/PPPoE 丢弃分片）。② **双栈智能 AAAA**（`prefer_ipv4`）：仅当域名存在 A 记录（双栈）才屏蔽 AAAA 返回 NODATA，纯 IPv6 域名正常解析——替代全局 `ipv6:false` 一刀切；A 探测走缓存快判（NXDOMAIN 负缓存直接确认纯 v6），无缓存才查上游并回填。③ **规则级 TTL**（`rules[].ttl_min/ttl_max`）：命中规则时整体替换全局 TTL 区间（未设边界=0 不限制，避免与全局下限矛盾），CDN/动态域名短 TTL 及时更新、稳定域名长 TTL 提升命中率；控制台规则行直接填写，留空继承全局。附带：`_api_add_rule` 透传规则 TTL 字段、PUT 规则 null 值删除字段（防 config 残留）、hash 路由直达（`#telemetry` 等刷新/重启后停留在原页）。**实测**：35 单测 + 35 errcheck + 28 项全功能联测全 PASS；100 并发纯 miss 压测 1174 q/s 成功 99.5%；15 分钟 60 线程持续压测 1482+ 轮全部 0 错误、缓存命中态 1-2.2 万 q/s、daemon RSS 稳定 61MB 零泄漏、运行期日志零 ERROR/WARNING。
- **v1.9.12**：缓存规则复查漏洞修复（mcs.zijieapi.com HTTPS 被屏蔽、同域名 A 查询却"内核直答"放出 IP——规则添加前已缓存的答案在缓存命中路径不查规则）；resolve() 三处缓存路径（命中/负缓存/过期兜底）统一返回前 match_rule 复查 block。新测速引擎 `_speed_sort` 零阻塞重写（EWMA 0.7/0.3 回写、加权随机选优权重=1/(rtt+10)、协议分流 udp53/tcp443 探测、16/256 worker 探测池）；慢上游降级 `_is_slow_up`（滚动延迟>max(800,timeout×0.6) 且 ok≥10 的上游退出查询，全慢时仅熔断过滤）。实测 100 并发×60 冷域名 9734 q/s 0 错误 p95 18ms（修复前 1161 q/s 571 错误）。
- **v1.9.11**：三项 UI 微调。① 实时查询日志上游解析列加宽、规则匹配列在域名前加规则名前缀（国内/国外/屏蔽）；② KPI 区 7 卡同排（新增规则命中卡细分：屏蔽/国内/国外/强制IP，字号加大）；③ 粘贴域名列表输入框加长、导入按钮同排对齐。
- **v1.9.10**：规则订阅改造。订阅明细独立存放 `rules_sub.json`（不写入 config.json），分流规则卡只显示订阅链接 + 更新按钮；逐条域名添加方式保留；实时查询日志新增第 8 栏「规则匹配」；新增规则命中数量卡（国内/国外/屏蔽）。
- **v1.9.9**：实时查询日志卡片改造。新增客户端 IP/上游解析/域名/类型/解析值/响应时间/查询时间列；地址栏与 URL 栏合并显示完整 DNS 地址（https://dns.alidns.com/dns-query）且保留端口列；每列加宽。
- **v1.9.4**：VM 长稳场景（用户真实配置：6 个慢 DoH/DoH3 上游 + fallback 全并发 + debug 日志）连续 3 轮×1 小时共 180 分钟高强度压测后修复。
  ① **修复高内存根因（VM 1h24min 涨至 737MB）**：`_doh_pool`/`_collect_pool` 为无界 ThreadPoolExecutor，高 miss 率 + 慢上游（UDP 全禁用、6 个 doh3/doh 上游、timeout 1500ms）下任务队列无限堆积。新增 `_BoundedExecutor`（BoundedSemaphore 限队列深度 = workers×2；`submit()` 满则阻塞反压、`submit_drop()` 满则丢弃），替换全部 5 个池（up/doh 用反压，collect max_pending=64、prefetch=256、probe=32 用丢弃）。
  ② **5 处被吞异常补日志**（`_prefetch_loop` ERROR、`_do_stale_refresh`/`_do_prefetch`/`_trigger_stale_refresh` WARNING、`_collect_rest` DEBUG）。
  ③ **修复 debug 日志刷屏拖垮吞吐（QPS 从 1.1 万骤降到几十）**：`log_level=debug` 时 aioquic 内部 "Stream discarded / max_streams_bidi raised" 每毫秒刷屏，占用 CPU 打满日志 IO。新增对顶层 logger `"quic"`/`"http3"` 的 WARNING 过滤——第三方库日志不再刷屏，ebpdns 自身 ERROR/WARNING/DEBUG 全量保留（不屏蔽任何异常）。
  ④ QUIC 连接失败日志 `%s`→`%r`（显示异常类型，aioquic 的 str(e) 常为空）。
  **实测（VM 场景复现：64 线程、30 真实域名+60 虚构负缓存+AAAA，log_level=debug 全量日志）**：3 轮各 1 小时共 180 分钟，累计查询数亿次，RSS 稳定 63-70MB（对比修复前 VM 737MB，**内存下降 90%+**），QPS 稳定 0.85-1.7 万，成功率 99.8-100%，全程零 ERROR 零 Traceback；仅 2 个网络不可达上游（doh.pub/120.53.53.53）的前 3 次连接失败 WARNING（fail_seq 限频，第 4 次起降为 DEBUG），非异常。

- **v1.9.3**：逐文件逐行二次全量审查 + 一小时极限压测后的修复与优化。① **补上 v1.9.2 遗漏的慢池弹性**(`_doh_pool` worker 按启用慢上游 8→32)——上一轮因断言失败整段脚本未写入, 实际未生效; ② 修复 NXDOMAIN 负缓存 TTL 逻辑 bug——旧 `max(neg_ttl, min(mn,60))` 在 ttl_max 生效时会"抬高"而非钳制, 负缓存不服从 TTL 管控, 改为 `max(10, _clamp_ttl(...))`; ③ `_ip_speed_cache` 超限清理从"只删过期项"(随机 IP 压测下永不缩小)改为按测速时间删最旧 1/4; ④ 后台结果收集 `_collect_rest` 不再向已返回客户端的 trace 继续 append(污染引用); ⑤ API 上游增/改的 port/latency 非法值从 500 崩溃降级为 400 明确报错; ⑥ QUIC 连接失败日志从 `%s` 改 `%r`(aioquic 的 str(e) 常为空, 原日志"连接失败:"后无详情无法排错)。**实测(1 小时 48 线程真实域名+AAAA+负缓存混合压测)**: 累计 5119 万次查询, 成功率 100.0%, QPS 稳定 1.3-1.5 万, RSS 72→130MB(极限 QPS 下 Python 分配器常态, 10 分钟 40 线程对照压测 RSS 稳定 58MB 证实结构零泄漏——所有诊断结构均在限长内: ip_speed_cache=0、各线程池 pending=0、deque 到上限即停), 日志全程零 ERROR 零 WARNING, QUIC 连接 45 分钟零重连。
- **v1.9.2**：全面代码审查(逐文件逐行)后的修复与优化。① DoH 连接池 `_ConnPool` key 补 path——同一 host:port 不同 DoH 路径(如 NextDNS /4d5525 vs /dns-query)不再复用错连接; ② QUIC 连接管理器 `get_quic_upstream` key 补 path——DoH3 同问题修复, API QUIC 诊断 key 同步对齐并给 stats() 补 path 字段; ③ server.py TCP 绑定失败从 raise 致命降级为 WARNING(仅 UDP 服务)——修复 TCP:53 被占时整个 daemon 起不来的问题(原注释称"不致命"但代码实际致命); ④ 慢池 `_doh_pool` worker 数按 DoH/DoT/DoQ/DoH3 启用上游弹性(8→32)——用户 VM 大量 DoH 上游时固定 8 worker 导致慢查询排队拖高 miss 延迟; ⑤ 后台结果收集 `_collect_rest` 超时从固定 1s 对齐到上游查询超时(timeout_ms)——避免慢协议(DoH/DoH3)结果过早放弃导致上游成功率统计缺失(显示"待命")。
- **v1.9.1**：修复用户 VM 实测 v1.9.0 仍存在的高内存(4.5 小时 810M)。根因: `_STABLE_SEC=15s` 过短——用户 VM 的 QUIC 连接存活约 20-30s(被上游空闲关闭/偶发失败), 超过 15s 阈值被判"稳定"导致退避反复复位 2s, 每 30s 重连一次, 4.5h 多个 DoH3 上游累积上千次重连; 且 `query()` 超时后未取消悬挂在事件循环上的协程(future), 协程持续持有旧连接 proto 引用, 旧 QuicConnection 对象无法被 GC 回收累积。修复: ① `_STABLE_SEC=60.0`——连接存活不足 60s 一律视为不稳定, 退避持续指数递增至 60s 封顶(重连频率降低约 3 倍); ② `query()` 超时后主动 `fut.cancel()` 取消悬挂协程, 释放对旧连接的引用; ③ 退避较大时主动 `gc.collect()` 回收 aioquic 连接对象循环引用(protocol↔quic↔http)。实测: 3 个不稳定 DoQ 上游(服务器每 8/15/30s 强制断开全部连接)持续查询 15 分钟, 45 次重连下 RSS 全程稳定 47→48MB 零泄漏(修复前同场景内存线性增长); 48 线程 5 分钟压测 476 万查询 100% 成功 RSS 60MB 稳定。
- **v1.9.0**：修复长期运行内存泄漏(用户 VM 6 小时 1.7G)与 QUIC 重连风暴。① `_maintain` 退避逻辑 bug——`backoff=2.0` 在进入 connect 块时复位导致不稳定上游(连接建立后短时断开)形成 2s 一次无限重连风暴, 修复为退避只在"连接稳定存活 >=15s"后复位, 否则持续指数递增到 60s 封顶(实测 5s 断连的极端场景 180s 重连从 36 次降至 6 次); ② `_exchange` 查询"业务失败"(超时/HTTP 非 200)不再主动关闭整个连接(连接可复用), 仅连续 3 次失败才触发重建, 消除偶发超时引发的重连风暴; ③ 修复 `_H3Client._streams` 泄漏——对端对已结束流的数据包不再重建条目, 流状态字典不再无限增长; ④ aioquic 连接关闭期残留 timer 噪音(`NoneType sendto` / `call_exception_handler` None)通过 loop exception handler 统一降噪; ⑤ API 上游列表新增 QUIC 连接诊断(connected/reconnects/fail_seq), 控制台可实时观察 DoQ/DoH3 上游健康度。实测: 3 分钟 64 线程 332 万查询 100% 成功, daemon RSS 57→62MB 收敛; 极端不稳定上游(每 5s 强制断连)180s 内存稳定 44MB 无泄漏; 稳定 DoQ 75s 6.3 万查询 100% 成功。
- **v1.8.19**：QA 循环收尾。① 清理全部 pyflakes 未使用变量(resolver/upstream 共 5 处), 静态检查零告警; ② 后台上游结果收集超时 WARNING 降为 DEBUG(慢上游排队是常态, 客户端已拿到首答, 压测高峰不再打扰运维日志), 收集超时 3s→1s 更快释放后台线程; ③ install.sh 已含 aioquic 自动检测安装(apt→pip 三级回退)。实测: 26 单测全过; 27 项联合测试(6 协议上游/分流/负缓存/TTL/API/规则导入/持久化/一键重测速)全 PASS; 5 分钟 64 线程 373 万查询 100% 成功 QPS 12,332 p99 16.7ms RSS 峰值 63MB 零泄漏无崩溃; 高负载 SIGKILL 后 0.2s 重启立即恢复查询 成功率 99.99%; 日志零 WARNING/ERROR。
- **v1.8.18**：DoQ/DoH3 数据面重写——修复 v1.8.17 引入的 `_H3Client` 类体缩进错误(方法落在类外, DoH3 完全失效); DoQ 从 asyncio `create_stream()`/StreamWriter 改为底层 QUIC 流管理(`_DoQClient`), 彻底消除 QUIC 连接断开/重连后残留 StreamWriter 在 `__del__` 时对失效连接 `send_stream_data` 抛 `ValueError: Cannot send data on peer-initiated unidirectional stream` 的刷屏; 连接关闭期 loop 清理噪音(`call_exception_handler` None)降为 DEBUG。实测: 本地 DoQ 服务器 8/8 成功、DoH3 dns.alidns.com 5/5 成功, 无残留流异常。
- **v1.8.17**：QUIC/DoH3 连接维护优化——失败/断开指数退避重连(2s→60s 封顶)替代固定 2s 无脑重试, 连续失败降 DEBUG 日志避免刷屏, idle_timeout 20s→60s 减少空闲频繁断开重连; 后台上游结果收集超时 WARNING 60s 限频(慢上游卡住是常态, 客户端已拿到首答); 修复无 aioquic 时 import quic_upstream 崩溃。
- **v1.8.16**：控制台分流规则卡片加宽——`grid-column:3/-1` 从测速后的第 3 列延伸到行尾, 宽屏 4 列下占满第 3、4 两列(修复 auto/-1 只落最后一列导致中间列空白的问题)。
- **v1.8.15**：控制台分流规则卡片铺满右边空位——`grid-column:auto/-1` 从测速与优选之后延伸至行尾剩余列, 任意列数下都铺满右侧空位(宽屏 4 列时占第 3、4 列)。
- **v1.8.14**：一键重新测速改为实测全部上游 DNS（含禁用上游）——便于评估所有上游质量后决定启用哪些; 首次启动仍只测启用且未实测过的上游。
- **v1.8.13**：控制台配置页卡片宽度加宽到满屏——分流规则卡片恢复跨满整行(`grid-column:1/-1`), 消除窄屏下卡片右侧大片空白(布局: 缓存|测速 第1行, 分流 第2行跨行, 上游 第3行跨行)。
- **v1.8.12**：取消全部浏览器弹窗——「一键重新测速」移除 confirm 点击直接实测; 「导入域名列表」由 4 个 prompt 改为分流卡片内内联导入行(输入框+动作下拉+分组下拉+IP 输入+导入按钮, 回车/点击直接执行)。
- **v1.8.11**：控制台配置页布局调整——分流规则卡片不再跨行独占, 排入测速与优选右侧空白位（第 1 行三列: 缓存 → 测速 → 分流; 上游服务器仍跨满整行）。
- **v1.8.10**：控制台配置页布局调整——分流规则卡片移到测速与优选之后、上游服务器之前（DOM 顺序: 缓存 → 测速 → 分流 → 上游）。
- **v1.8.9**：解析时测速择优由「并发取前 3 个可用上游」改为「并发全部可用上游」——上游选择不再截断前 N 个, 全部启用上游同时参与并发查询, 首答即返取最快; `max_parallel_upstreams` 保留用于工作线程池估算基数(不再限制解析并发数)。
- **v1.8.8**：上游服务器卡片跨满整行 + 地址列 minmax(150px) 保底宽度（修复地址显示不全）；「添加上游」改为卡片内单行直接添加（协议下拉 UDP/TCP/DoH/DoT/DoQ/DoH3，端口随协议自动映射，回车/点击添加）。
- **v1.7.7**：默认上游扩充为 17 个（2 UDP 兜底 + 15 DoH，含 AliDNS/DNSPod 域名与 IP 直连、Cloudflare/Google/Quad9/NextDNS/OpenDNS/DNS.SB/AdGuard/HiNet）；国内 7 项默认启用（实测 7/7 通过、延迟写回），海外 10 项写入但默认关闭可按需启用；server-http3 端点与同名 DoH 合并为 `proto:"doh"`（HTTP/3 传输层未实现，按 HTTPS 使用）。
- **v1.7.5**：分流规则哈希索引（10 万规则 23.37ms → 0.0004ms/次，并修复 `*.core` 通配匹配 core 本身漏匹配）；测速节流表限长修复内存泄漏；`_read_json` 上限 8MB→64MB 并超限 drain body（修复大配置 PUT BrokenPipe，导入 10 万 anti-ad 规则后前端保存设置失败）；PUT config 对 `cache_size` 非法值返回 400（防默认值误覆盖）；全功能联测 + 5 分钟混合压测 0 错误 + 200 线程 612 万查询暴力压测 + 崩溃自启 3.5s 验证；README/控制台「架构说明」按实际实现重写。
- **v1.7.4**：下发 TTL 管控（`ttl_min`/`ttl_max`）；过期缓存兜底（`serve_stale`/`stale_ttl`，先 stale 后 get 的顺序修复）；持久化缓存 TTL 单独控制（`persist_ttl`）；三项联动核查。
- **v1.7.3**：修复 systemd stop 超时被 SIGKILL（预取线程池取消积压 + DoH/DoT 锁超时 + as_completed 超时兜底，SIGTERM 退出 60s+ → 1-3s）。
- **v1.7.2**：修复配置「即时生效」bug（PUT /api/config 后 resolver 重绑定 cfg）。
- **v1.7.1**：域名预取 × 缓存持久化配合（force_refresh、重启后 rearm 预取）。
- **v1.7.0 / v1.6.9**：配置页整合；fallback 开关真实接入；IPv4 优先真实实现；移除 eBPF 数据面死参数卡片。
- **v1.6.8**：数据面表述准确化（XDP/TC 标注预留、未集成）。
- **v1.6.7**：持久缓存改为剩余 TTL 语义（重启间隙不消耗缓存寿命）。
- **v1.6.6**：一键重新测速（POST /api/reprobe）。
- **v1.6.5**：首次启动自动实测上游延迟并写回。
- **v1.6.4**：LRU 容量上限放宽到 131072。
- **v1.6.2**：上游熔断器；DoH/DoT 独立慢池；上游池扩容；20 分钟长压测验证。
- **v1.6.1**：响应体预编码缓存；UDP miss 队列有界信号量；预取不污染遥测。
- **v1.6.0**：遥测锁合并；上游统计加锁；快路径报文只解析一次；NXDOMAIN 首答即返；cache 概率式清理。
- **v1.5.6**：UDP 缓存命中快路径（吞吐约 3 倍提升）；修复压缩指针环 DoS（32 跳上限）。
- **v1.4.0**：DNS 解析缓存持久化（cache.json，每 60s + 退出时保存，重启自动恢复）。
- **v1.3.0**：控制台「重启服务」按钮（systemd restart / os.execv）。
- **v1.2.0**：首答即返；测速择优加超时上限；NXDOMAIN 负缓存不预取；后台线程池化。
- **v1.1.0**：真实延迟统计；NXDOMAIN 负缓存；DoH/DoT 连接复用；UDP 上游 qid/源校验；预取后台线程。
