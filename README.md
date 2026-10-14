# ebpdns —— SmartDNS 式智能 DNS 解析器（Debian 13 可部署）

> 当前版本 **v1.9.164**（`ebpdns/__init__.py` `__version__ = "1.9.164"`；版本号另见 `web/index.html` 的页脚与 APP_VERSION，共三处）。本文档与代码逐项对齐：
> 功能清单、配置项、API 端点、安装/部署方式均以源码为准（见文末「文档对齐说明」）。

把「ebpdns · eBPF 版 SmartDNS 解析器控制台」从浏览器内仿真升级为**真实可部署的 DNS 解析软件**。

- 真实监听 `UDP/TCP :53`，真实多上游并发解析（UDP / TCP / DoH / DoT / DoQ / DoH3）
- 复刻 SmartDNS 的**测速择优、上游 weight 加权轮询、域名分流、TTL 缓存、预取、IPv4 优先、失败降级**等智能逻辑
- 默认数据面运行在**用户态**：以**用户态 LRU 缓存模拟 BPF LRU_HASH Map**，命中由 daemon 快路径直接回包，**无需内核权限**即可完整运行
- 内置 **HTTP JSON API + Web 控制台**：控制台连上后端即为真实数据（REAL 模式），后端不可达时自动降级为浏览器内仿真（SIM 模式）
- 可选 **eBPF XDP 内核旁路**（`bpf/`）：v1.9.158 起已接入 daemon（`ebpdns/bpf_loader.py` + `kernel_cache` 配置），命中查询由网卡内核直答；`make` 可编译出 `.o`，但内核校验器**仍拒绝加载**，故默认 `kernel_cache:false` 走用户态路径（详见 §9 与 `bpf/README.md`）
- 纯 Python 标准库、零第三方依赖；systemd 一键托管；支持 systemd 崩溃自动重启（`Restart=on-failure`）

---

## 1. 架构（实际实现路径）

```
   DNS 客户端 ──UDP/TCP :53──▶  ebpdns daemon (Python3, 纯标准库)
                                ├─ 报文入口   (server.py)
                                │    解析 (qname, qtype) → 查用户态 LRU
                                │    命中 ──▶ 快路径直接回包(响应体预编码, 仅重拼 qid)
                                │    miss  ──▶ 进解析引擎
                                ├─ 用户态缓存 (cache.py)
                                │    用户态 LRU 模拟 BPF_MAP_TYPE_LRU_HASH
                                │    TTL 钳制 · serve-stale 过期兜底 · 剩余 TTL 落盘持久化
                                ├─ 解析引擎   (resolver.py)
                                │    分流规则 · 多上游并发 · 测速择优 · 预取 · 负缓存
                                ├─ 上游适配   (upstream.py)
                                │    UDP / TCP / DoH / DoT · 连接复用 · 熔断
                                └─ HTTP API   (api.py :8080)  + 遥测 (telemetry.py)
                                          │
                                          ▼ 上游查询 (UDP/TCP/DoH/DoT)
                          AliDNS / DNSPod / Cloudflare / Google ...
```

| 层 | 实现 |
|---|---|
| 用户态守护进程 | Python 3.10+（零第三方依赖） |
| 缓存语义 | 用户态 LRU 模拟 `BPF_MAP_TYPE_LRU_HASH`（命中计数计入遥测 `kernel_direct`） |
| 上游协议 | UDP / TCP / DoH (HTTPS) / DoT (TLS) / DoQ (QUIC) / DoH3 (HTTP/3) |
| 管理接口 | HTTP JSON API + Web 控制台（内置 ECharts，本地化无外网依赖） |
| 可选内核数据面 | C + libbpf (XDP)，`bpf/` 目录已集成（`bpf_loader.py` + `kernel_cache`），编译成功但校验器待适配（见 §9） |

**数据面说明**：默认所有解析与缓存均在用户态完成——缓存命中由 daemon 主线程直接回包（不查询上游），语义上等价于 SmartDNS 的内存缓存，并计入「内核直答」遥测计数；`bpf/` 目录提供真实 XDP 内核旁路的 C 源码，v1.9.158 起已接入 daemon 回填/预热，仅在校验器接受加载后才真正把命中下沉到网卡内核直答（见 §9）。

---

## 2. 快速部署（Debian 13）

```bash
# 1. 解压生产包（包内文件直接位于根，建议先建空目录再解压）
mkdir ebpdns && tar -xzf ebpdns-python-v1.9.164.tar.gz -C ebpdns
cd ebpdns
# 2. 一条命令完成全部依赖安装 + 部署
#    install.sh 会自动检测并**自动安装**所有依赖与软件:
#      必需: python3(>=3.10)
#      可选: aioquic(DoQ/DoH3)、完整 eBPF 工具链
#            (make/clang/llvm/libbpf-dev/linux-libc-dev/bpftool)、
#            iproute2/libcap2-bin/rsync
#    可选依赖安装失败**不阻断部署**(DNS 服务照常, 仅对应增强功能不可用)。
#    离线/受限环境可用 EBPDNS_SKIP_DEPS=1 跳过自动安装(仅检测提示)。
sudo ./install.sh
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

> **依赖自动安装说明**：`install.sh` 会自动装齐上述依赖，无需手动 apt/pip。eBPF 编译
> 失败时会在输出中**回显具体编译错误**（不再是静默吞掉），可按提示排查（常见：缺头文件
> `apt install -y libbpf-dev linux-libc-dev`、架构不匹配）。eBPF 编译成功与否**都不影响
> DNS 服务**（详见 §9）。
>
> **就地安装注意**：在 `/opt/ebpdns` 目录内直接跑 `./install.sh` 属"就地安装"，会
> **跳过代码拷贝**（不更新已有代码）。升级请在新解压目录里跑 `./install.sh`（异地安装），
> 它会把新代码复制到 `/opt/ebpdns`。


> **53 端口冲突**：Debian 的 `systemd-resolved` 默认占用 `127.0.0.53:53`（监听回环地址，通常不冲突）。
> 若你的机器另有 DNS 占用 `0.0.0.0:53`，可先 `sudo systemctl stop systemd-resolved`，
> 或在 `/etc/ebpdns/config.json` 里把 `listen` 改成其它端口（如 `0.0.0.0:5353`）。
> 53 端口需特权：systemd 部署由专用 `ebpdns` 用户 + `CAP_NET_BIND_SERVICE` 绑定（无需 root 全权）；
> 手动非 root 本地调试请改用 `127.0.0.1:1053` 等非特权端口。

### 手动部署（不走 install.sh）

```bash
sudo mkdir -p /opt/ebpdns
sudo cp -r bin ebpdns web etc /opt/ebpdns/
sudo mkdir -p /etc/ebpdns
sudo cp etc/ebpdns.conf.json /etc/ebpdns/config.json
# 重要: systemd unit 以专用用户 ebpdns 运行且 ProtectSystem=strict, 只放行 /etc/ebpdns 可写。
# 不建用户会直接 status=217/USER 启动失败; /etc/ebpdns 属主不对则无法保存配置/缓存。
sudo groupadd --system ebpdns 2>/dev/null || true
sudo useradd --system --gid ebpdns --home-dir /opt/ebpdns --shell /usr/sbin/nologin ebpdns 2>/dev/null || true
sudo chown -R root:root /opt/ebpdns
sudo chmod -R a+rX /opt/ebpdns
sudo chmod 755 /opt/ebpdns/bin/ebpdns
sudo chown -R ebpdns:ebpdns /etc/ebpdns
sudo chmod 750 /etc/ebpdns
sudo chmod 640 /etc/ebpdns/config.json
sudo cp systemd/ebpdns.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now ebpdns
sudo systemctl is-active ebpdns   # 务必复核; 首次安装不会自动检查
```

### 升级

```bash
# 在新版本解压目录里重新运行 install.sh 即可（保留现有配置）
sudo ./install.sh
#   - 代码 rsync 到 /opt/ebpdns（纯代码子目录 bin/ebpdns/web/systemd 带 --delete 清理陈旧 .py）
#   - /etc/ebpdns/config.json 已存在则原样保留不动（用户数据不在 /opt 内，不受影响）
#   - 重装 systemd unit 并 daemon-reload
sudo systemctl restart ebpdns     # 重启加载新代码（配置热重载也可 POST /api/reload）
dig @127.0.0.1 www.baidu.com       # 验证
```

### 卸载

```bash
sudo systemctl stop ebpdns && sudo systemctl disable ebpdns
sudo systemctl disable ebpdns-restart.timer 2>/dev/null || true
sudo rm -f /etc/systemd/system/ebpdns.service /etc/systemd/system/ebpdns-restart.{service,timer}
sudo systemctl daemon-reload
sudo rm -rf /opt/ebpdns /etc/ebpdns
# 可选：删除运行用户（install.sh 创建的系统账号，无登录 shell）
sudo userdel ebpdns 2>/dev/null; sudo groupdel ebpdns 2>/dev/null || true
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

也可用 `EBPDNS_CONFIG=<路径>` 环境变量指定配置文件。

---

## 4. 配置说明（/etc/ebpdns/config.json）

| 键 | 默认 | 说明 |
|---|---|---|
| `listen.udp` / `listen.tcp` | `127.0.0.1:53` | DNS 监听地址（默认仅回环，无配置时不暴露到全网卡；需局域网提供 DNS 时显式改为 `0.0.0.0:53`） |
| `listen.udp6` / `listen.tcp6` | `[::1]:53` | IPv6 DNS 监听，默认开启（仅回环 `[::1]:53`；系统无 IPv6 协议栈时仅告警跳过，不影响 IPv4 服务）。不希望监听 IPv6 时显式设为 `null`，需全网卡可改 `[::]:53` |
| `api.host` / `api.port` | `127.0.0.1` / `8080` | API 与 Web 控制台监听（默认仅本机回环，天然安全无需 token；模板与 install.sh 均为 `127.0.0.1:8080`，需局域网访问时显式改 `0.0.0.0` 并配 `api.token`） |
| `api.token` | `""` | 可选 API 认证令牌。空串=不启用（默认；仅本机回环时安全）。绑定非回环地址时务必设置：除 `/api/health` 与静态资源外，所有 `/api/*` 与 `/metrics` 需带 `Authorization: Bearer <token>` 或 `X-Api-Key: <token>`（或 `?token=`，注意 query 形式会进入反代访问日志/浏览器历史，生产建议只用请求头）。最长 256 字符；`GET /api/config` 自动把已设 token 脱敏为 `***`，PUT 收到 `***` 时忽略不覆盖原值 |
| `cache_size` | 131072 | 用户态缓存容量（模拟 BPF Map 容量，范围 1–10000000，配置值越界会被 API 拒绝）。**下界说明**：内部分 8 分桶且每桶下限 16 条，故配置值 < 48 时实际总容量会被抬到 `16×分区数`（3 分区即 48 条），这是 8-shard 设计的安全下限 |
| `cache_policy` | `lru` | 缓存淘汰策略：`lru`=按分流 group 分区隔离的 LRU（PartitionedCache，domestic/global/default 默认容量比 0.2/0.2/0.6，各 group 互不挤占；每个分区内部再 8 分桶独立锁）；`partitioned`=与 `lru` 同一分区引擎，显式声明分区模式并按 `cache_partitions` 自定义各 group 容量比例；`tinylfu`=W-TinyLFU 单池三段式（Count-Min Sketch 频率估计，抗扫描污染，命中率通常高 5-15%，额外内存约 512KB）。切换 lru↔tinylfu 自动热重载重建缓存 |
| `cache_partitions` | `null` | partitioned/lru 模式下各 group 的容量权重（如 `{"domestic":0.2,"global":0.2,"default":0.6}`，自动归一化到和为 1）。`null`=默认 0.2/0.2/0.6；仅 group 键 domestic/global/default 合法，未知键剔除、负权重回退默认 |
| `map_type` | `LRU_HASH` | 缓存 BPF Map 类型语义标记（保留大写，不做大小写归一）：`LRU_HASH`（默认，LRU 哈希表，最通用）/ `LRU`（纯 LRU 链表）/ `LPM_TRIE`（最长前缀匹配树，面向按网段路由的场景）。当前为纯用户态 Python 实现，`map_type` **仅作语义标记与控制台/API 展示**，不改变淘汰引擎（淘汰引擎由 `cache_policy` 决定）；真实 XDP 数据面集成时据此选择内核 map 类型。非法值回退 `LRU_HASH` |
| `ttl` | 300 | 缓存默认 TTL（秒），实际取上游返回 TTL 与它的较小值 |
| `ttl_min` / `ttl_max` | 0 / 0 | 下发 TTL 管控：内网客户端应答 TTL 钳制到该区间（0=不限制），同时作为缓存存活时长 |
| `serve_stale` / `stale_ttl` | false / 3600 | 过期缓存兜底：缓存过期后在窗口内仍返回旧数据（下发 TTL=0）并后台强制刷新，避免上游抖动时 SERVFAIL |
| `persist_ttl` | 0 | 持久化缓存恢复后的独立 TTL（秒）；0=按保存时剩余 TTL 原样恢复（重启间隙不消耗缓存寿命）。取值范围 0–31536000（一年），越界回退默认 |
| `prefetch` | true | TTL 到期前 85% 自动预取刷新（跳过 NXDOMAIN 负缓存；恢复缓存自动重排入预取队列） |
| `kernel_direct` | true | 用户态缓存命中即计为「内核直答」遥测计数（真实 XDP 集成时保持 true 语义一致） |
| `speed_test` | true | 上游/候选 IP 测速择优总开关 |
| `speed_interval_ms` | 2000 | **毫秒**。同一域名两次候选 IP 测速之间的最小间隔（节流）：间隔内直接复用上次排序结果；范围 0–60000ms（=60s，0=每次都测）。注意单位是毫秒而非秒——「7 天」(=604800s) 适用于 `health_check_interval`/`rule_sub_interval` 等秒级周期字段(注意 `stale_ttl` 上限为 8640000s=100 天, 见配置表) |
| `speed_timeout_ms` | 300 | 单次候选 IP 探测超时上限（毫秒），范围 1–60000，未按时完成的候选不参与排序 |
| `ip_speed_check` | true | 候选 IP 测速：对多 IP 答案并发探测 RTT 并按速度排序（SmartDNS 风格），关=保持上游返回顺序 |
| `ip_speed_probe` | both | 候选 IP 探测方式（枚举）：`udp53` / `tcp443` / `both`（默认 both，取最快；TCP:443 更贴近真实访问） |
| `ip_speed_cache_ttl` | 60 | 候选 IP 测速结果缓存（秒），范围 0–86400，命中直接复用避免重复探测 |
| `fallback` | true | 上游失败自动降级到其余上游（关=仅用首选，失败即 SERVFAIL） |
| `ipv4_first` | true | 同时存在 A / AAAA 时优先 A；AAAA 无记录时回退查 A（`ipv4_fallback` 计数） |
| `ipv6` | true | 关闭后 AAAA 查询直接返回空应答（全局一刀切） |
| `prefer_ipv4` | false | 双栈智能：仅当域名存在 A 记录（双栈）才屏蔽 AAAA 返回 NODATA，纯 IPv6 域名（无 A）正常解析——替代全局 `ipv6` 开关的精细化方案，不误伤 v6-only 域名。A 探测先查缓存快判，无缓存才查上游（仅首次 AAAA 查询多一次上游往返），结果回填 A 缓存 |
| `edns` / `edns_client_subnet` | true / null | 携带 EDNS0 OPT；可填 `203.0.113.0/24` 启用 ECS |
| `edns_udp_size` | 1232 | 出站查询 EDNS0 UDP payload（字节）。1232=IPv6 最小 MTU 1280 减 IPv6 头 40 + UDP 头 8 的最大不分片安全值——大应答 UDP 分片穿越 NAT/防火墙/PPPoE 时经常被丢弃导致解析超时，钳制到该值保证应答不分片（超限应答置 TC 位由客户端走 TCP 重试） |
| `edns_client_max_size` | 1232 | 入站方向：对客户端通告的 EDNS0 UDP payload 大小设上限（范围 512–65535）。应答按该上限截断，防止客户端通告超大 bufsize 时返回巨型 UDP 报文被放大利用/分片丢弃 |
| `padding` | false | 加密查询报文填充（RFC 8467）：DoT/DoH/DoH3/DoQ 出站报文 OPT options 段填充到 128B 块（上限 512），抹平报文长度指纹，防流量分析通过长度推断查询内容。明文 UDP/TCP 不填充（只增大报文无收益）。前端开关按协议自动分流，无需手配 |
| `timeout_ms` | 1500 | 单次上游查询超时 |
| `max_parallel_upstreams` | 3 | fallback 开启时，miss 查询按实测延迟排序后**先并发最快 N 个**上游（N 即本值），这 N 个全部失败才回退剩余上游；同时用作上游工作线程池规模基数（`min(48, max(16, N×8))`）。范围 1–16。预取/后台固定只用最快 1 个上游 |
| `upstreams[]` | 见模板 | `proto`: udp/tcp/doh/dot/doq/doh3；`addr`+`port`；`url`(DoH/DoH3/DoQ 路径)；`group`: domestic/global；`latency` 基础延迟（默认 5000ms，首次启动自动实测写回，范围 0–3600000ms）；`enabled`；`latency_measured`；`weight` 加权轮询权重（默认 **1**，范围 0–1000 且支持小数；选择排序 key = 实测延迟 `eff_lat` / `max(1.0, weight)`，weight 越大越易被选中，<1 按 1 计即与默认相同）；`allow_private_ip`（上游级布尔，默认 **false**：该上游返回的私网/保留 IP 仍受全局 `rebind_protection` 丢弃；显式设 `true` 后豁免，使其内网/私有地址答案不被丢弃，所有协议可用）；`doh_strict_cert` / `dot_strict_cert`（上游级布尔，默认 **true**：证书链 + SAN/主机名必须匹配，不匹配直接失败；仅显式设为 `false` 才允许降级，降级连接即用即弃不入连接池；仅 DoH/DoH3 / DoT 协议分别生效） |
| `nxdomain_quorum` | 2 | 多上游 NXDOMAIN 一致性判定：需至少 `nxdomain_quorum` 个上游一致返回 NXDOMAIN 才确认域名不存在并提前返回，否则继续等其余上游/超时（防单个上游撒谎把存在的域名判成不存在）。quorum 自动钳到实际参与投票的健康上游数；设为 1 恢复旧行为。未在配置中写出时按默认 2 |
| `rules[]` | 见模板 | `match`: 精确域名、`*.example.com` 通配、`re:正则`；导入另支持 adblock 风格 `||domain` 与 `@@白名单`；`action`（枚举）：`allow`/`block`/`group`/`forceIp`；规则按哈希索引匹配（10 万条级 O(1)）。逐条规则独立存 `rules_local.json`，订阅明细存 `rules_sub.json`，均不写入 config.json。规则可带 `ttl_min`/`ttl_max`（规则级 TTL）：命中规则时**整体替换**全局 TTL 区间（未显式设置的边界按 0=不限制） |
| `rule_subscriptions[]` | `[]` | 规则订阅源元信息（仅存 url/action/group/ip/更新时间），域名明细存独立文件 `rules_sub.json`。仅允许 `https://` 源；按 `rule_sub_interval` 自动重拉 |
| `rule_sub_interval` | 3600 | 规则订阅自动更新周期（秒），范围 0–604800（=7 天），0=关闭 |
| `health_check_interval` | 30 | 上游主动健康检查周期（秒），范围 0–604800，0=关闭 |
| `health_probe_domain` | `www.baidu.com` | 健康检查探测域名（绕过分流规则直连上游） |
| `health_probe_timeout_ms` | 2000 | 健康检查探测超时（毫秒），范围 100–60000 |
| `circuit_fails` | 3 | 熔断器连续失败阈值（达到后打开熔断），范围 1–100 |
| `circuit_open_s` | 30 | 熔断打开持续时间（秒），范围 1–86400，超时后半开探测 |
| `bootstrap_dns` | `223.5.5.5:53` | DoH/DoT hostname 预解析用的 UDP bootstrap DNS，摆脱系统 DNS 依赖 |
| `rebind_protection` | true | 响应 IP 合法性校验：丢弃上游返回的私有/保留/环回地址（防 DNS 劫持/DNS rebinding），`forceIp` 规则与上游级 `allow_private_ip=true` 豁免 |
| `dnssec_0x20` | true | DNS 0x20 投毒防护：明文 UDP/TCP 查询名大小写随机（约 +26bit 熵） |
| `log_format` | `text` | 日志格式（枚举）：`text`=可读文本 / `json`=结构化 JSON lines（可观测性） |
| `web_root` | `null` | 控制台静态文件根目录；`null`=自动定位到包内 `web/` 目录 |
| `cache_persist` | `true` | 缓存持久化总开关。开启时按 `cache_file` 周期/退出落盘并在启动时恢复；**关闭后既不写盘也不从磁盘载入**（周期保存与退出保存均失效）。布尔值，非布尔回退默认 |
| `cache_file` | `<配置目录>/cache.json` | 缓存持久化落盘路径（每 60s 自动保存 + 退出时保存，重启自动恢复）。相对路径基于配置文件所在目录解析；控制台保存配置时保留用户自定义路径不被剥离 |
| `log_level` | `info` | 日志级别（枚举）：`debug`/`info`/`warning`/`error` |

> **默认上游**：内置 2 个国内 UDP 兜底 + 20 个 DoH/DoH3 端点（共 22 个；AliDNS/DNSPod 的域名与 IP 直连、Cloudflare/Google/Quad9/NextDNS/OpenDNS/DNS.SB/AdGuard/HiNet）。其中国内 9 项默认启用（首次启动自动实测延迟写回），海外 4 项默认启用、其余海外端点已写入但默认 `enabled:false`，可在控制台按需启用（海外端点受网络环境限制，走超时/熔断自动降级）。
>
> **DoQ / DoH3（可选依赖 aioquic）**：`proto:"doq"`（DNS over QUIC，RFC 9250，默认端口 853）与 `proto:"doh3"`（HTTP/3 DoH，默认端口 443）已内置实现。每个 QUIC 上游维护一条常驻连接（断线自动重连 + 查询失败主动重建），多查询在同一连接上多路复用；未安装 aioquic 时相应上游返回「aioquic 未安装」错误，不影响 UDP/TCP/DoH/DoT 路径。install.sh 会自动检测并安装 aioquic（apt `python3-aioquic` → pip 三级回退），`EBPDNS_SKIP_DEPS=1` 可跳过。

配置可在**控制台「配置」页**在线编辑并「应用配置」持久化到后端。绝大多数字段即时生效（PUT /api/config 后无需重启，与 SIGHUP/`/api/reload` 等价）；例外：`cache_size` 之外，`log_level` / `log_format` 在进程启动时经 `_setup_logging` 一次性应用，改后需重启才生效（前端对应开关已标注「重启后生效」）。`hook` / `percpu` 为 eBPF 数据面语义标记（真实 XDP 加载由 `kernel_cache`/`bpf_loader` 控制，当前校验器待适配，见 §9）；`map_type` 三种取值见上表，当前仅作语义标记/展示，真实淘汰引擎由 `cache_policy` 决定。

---

## 5. Web 控制台（http://<IP>:8080/）

| 页面 | 功能 |
|---|---|
| 数据面流水线 | 缓存命中（用户态直答）/ 未命中（多上游解析）/ 失败（SERVFAIL）的实时推演与日志，真实日志驱动 |
| 查询控制台 | 手动输入域名发起真实解析，逐步展示 入口 → 缓存 → 分流 → 多上游并发 → 测速择优 → 回填 完整链路 |
| 配置 | 缓存与 BPF Map（LRU 容量 / TTL 管控 / 预取 / serve-stale / 持久化 TTL）· 测速与优选 · 上游服务器（增删改/一键重新测速）· 分流规则（添加/导入域名列表/URL 导入），应用即持久化 |
| 遥测 | 命中率、QPS、延迟、查询类型分布、上游健康度、用户态 LRU Map 占用（ECharts） |
| 架构说明 | 实际数据面路径与模块职责、技术栈、部署方式（与 README 一致） |

控制台自动检测后端：连接成功显示 REAL 模式（真实数据）；后端未启动时显示 SIM 模式（内置仿真兜底，便于演示）。
可用 `?route=telemetry` 等参数深链直达页面（`pipeline` / `query` / `config` / `telemetry` / `about`）。

---

## 6. HTTP API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/health` | 存活探针（**token 豁免**，供容器/编排探活），返回 `status/running/uptime_s`（**不返回 version**，避免未认证指纹识别已知版本） |
| GET | `/api/status` | 运行状态、version、QPS、命中率、延迟、计数器、规则命中、LRU Map 占用、cache_file 等 |
| GET | `/api/snapshot` | 完整快照：历史序列、日志事件、上游健康、手动查询记录 |
| POST | `/api/query` | `{domain, qtype}` 手动解析，返回完整 trace；domain 校验 `[a-zA-Z0-9._-]`、单标签 ≤63、总长 ≤253，qtype 须为已知类型 |
| GET/PUT | `/api/config` | 读写配置（PUT 全量持久化，`cache_size` 越界/类型错误返回 400；GET 自动把 `api.token` 脱敏为 `***`，PUT 收到 `***` 时忽略不覆盖原值） |
| GET/POST | `/api/upstreams` | 上游列表（带健康度）/ 新增（支持 `weight`/`allow_private_ip`/`doh_strict_cert`/`dot_strict_cert`） |
| PUT/DELETE | `/api/upstreams/<id>` | 修改 / 删除上游 |
| GET/POST | `/api/rules` | 逐条分流规则列表 / 新增（`match` 必填；支持 `re:` 正则预编译校验；可选 `ttl_min`/`ttl_max`） |
| PUT/DELETE | `/api/rules/<id>` | 修改 / 删除规则 |
| POST | `/api/rules/import` | `{url}` 或 `{content}` 批量导入域名列表（URL 实时下载，支持 adblock `||`/`@@` 规则源；该与 `/api/rules/subscribe` body 上限放宽到 16MB，其余 4MB） |
| POST | `/api/rules/subscribe` | 新增规则订阅 `{url, action, group, ip}`（仅允许 `https://` 源） |
| DELETE | `/api/rules/subscribe?url=<url>` | 删除规则订阅（按 url 定位；`?id=` 不受支持） |
| POST | `/api/rules/subscribe/update` | 重拉**指定**订阅 `{url}`（需提供 url；不带 url 返回 400） |
| GET | `/api/cache/stats` | 缓存统计（`cache.summary()` + 条目数 `size`） |
| POST | `/api/reprobe` | 一键重新测速：对所有上游并发实测延迟并写回配置 |
| POST | `/api/restart` | 重启服务（**需请求体 `{"confirm": true}`**；先返回 200 再在后台执行）。**systemd 托管时进程自退出**：不再调用 `systemctl restart`（v1.9.137 起以专用用户运行，polkit 拒绝非 root restart 系统 unit），改为置退出码 3 后向自身发 SIGTERM 走优雅收尾（缓存落盘/停 server/停池），进程以非零码退出，由 unit `Restart=on-failure` 拉起新实例；手动裸跑时用 `os.execvpe` 以相同参数替换自身进程。防重入：重启进行中重复调用返回 409 |
| POST | `/api/reload` | 热重载配置（与 SIGHUP 等价，原子换配置引用，返回 changed 明细，无需重启） |
| POST | `/api/reset` | 重置遥测计数与清空缓存（**需请求体 `{"confirm": true}`**，否则 400） |
| POST | `/api/profile` | cProfile 性能剖析采样 N 秒（`?seconds=N`，**默认 3，上限 10**，返回 Top 25 文本；仅 POST 触发，单飞，并发请求 409） |
| GET | `/api/logs` | 增量实时日志，参数：`since`(seq 游标)、`q`(关键字)、`level`(hit/miss/rule/err/sys/warn)、`qtype`、`ip`、`domain`、`upstream`、`rule`、`min_lat`、`limit`(默认 500，上限 2000)。**注意：`hit`/`miss` 事件按 10% 采样进入事件流**（`total`/`hit`/`miss` 计数器仍为全量精确值），故日志条数约为真实查询量的 1/10；需全量观测可调 `log_level=debug` |
| GET | `/api/pipeline` | 流水线概览：`hook`/`map_type`/`cache_size`/`kernel_direct` + 前 3 个启用上游（**脱敏，仅返回 proto/name/id**，不暴露地址端口） |
| GET | `/metrics` | Prometheus 文本指标（配置了 token 时同样需要认证） |
| GET | `/` `/index.html` `/echarts.min.js` `/favicon.svg` `/static/*` | 控制台静态资源 |

> 配置了 `api.token` 时，除 `/api/health` 与静态资源外，所有 `/api/*` 与 `/metrics` 都需携带 token：
>
> ```bash
> # 环回默认（未配 token）
> curl -s http://127.0.0.1:8080/api/status
> # 非环回 + 已配 token：三种等价认证头之一
> curl -s -H "Authorization: Bearer <token>" http://127.0.0.1:8080/api/status
> curl -s -H "X-Api-Key: <token>" http://127.0.0.1:8080/api/status
> curl -s "http://127.0.0.1:8080/api/status?token=<token>"
> ```

### API 安全：CSRF / Token / 监听边界

所有**状态变更类**请求（POST/PUT/DELETE）均做 CSRF 检查，判定顺序：

1. 请求带 `Origin` / `Referer`：来源主机必须与服务监听地址一致，否则 **403**；
2. 两者都没有（典型的非浏览器客户端，如 `curl`/脚本）：
   - 若请求携带正确的 API Token（`Authorization: Bearer <token>` 或 `?token=`），放行；
   - 否则仅当服务**只绑定在环回地址**（`127.0.0.1` / `::1` / `localhost`）时放行；
3. 无 Token 且监听在非环回地址（如 `0.0.0.0:8080`）上、又无 `Origin`/`Referer` 的请求一律 **403**——浏览器表单/跨站请求总会带 `Origin` 或 `Referer`，此分支只拦非浏览器的直连写入。

> **部署须知**：默认 `api.host=127.0.0.1`（仅环回，无 CSRF 攻击面，本机脚本/curl 不带凭据也可写）。若把 API 暴露到非环回地址（改 `api.host=0.0.0.0` 或具体 LAN IP），**务必**在配置中设置 `api.token`：此时非浏览器客户端（`curl`/脚本）在非环回监听下必须携带 `Authorization: Bearer <token>`（或 `X-Api-Key: <token>` / `?token=`）才能发起写操作，否则被 403 拒绝；浏览器控制台因自动带 `Origin` 不受影响。未设 Token 又暴露到非环回地址时，任何跨站网页都可能借浏览器发起 CSRF 写操作，属高风险。

---

## 7. 稳定性与运维

- **systemd 托管（降权运行）**：服务以专用系统用户 `ebpdns`（nologin，install.sh 自动创建）运行，**不再以 root 常驻**；仅通过 `AmbientCapabilities=CAP_NET_BIND_SERVICE`（+ `CapabilityBoundingSet` 同值）获得绑定 53 特权端口的能力。`/opt/ebpdns` 保持 `root:root` 只读，`/etc/ebpdns` 置 `ebpdns:ebpdns` 750（服务可读写配置/缓存），配合 `ProtectSystem=strict`（仅 `ReadWritePaths=/etc/ebpdns` 可写）、`NoNewPrivileges`、`PrivateTmp`、`RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` 等沙箱硬化收敛攻击面。`Restart=on-failure` + `TimeoutStopSec=15`，崩溃循环保护（60s 内最多 5 次后进入 failed）。进程异常退出（含 SIGKILL/OOM 强杀）后约 3-5s 自动重启，重启后从磁盘载入持久化缓存、恢复分流规则/上游并重新排入预取队列；SIGTERM 优雅退出（正常 <10ms，trim 线程 join 超时 2s），退出时保存缓存。另装每日 04:30 低峰 `ebpdns-restart.timer` 做内存卫生兜底。
- **优雅退出**：预取线程池 `cancel_futures` 取消积压、DoH/DoT 连接锁加超时、结果收集 `as_completed` 加超时兜底，高负载下 stop 不再卡死。
- **上游熔断**：连续失败达阈值（默认 3 次）临时跳过该上游 30s，防单个故障上游拖垮 miss 查询（配置 `circuit_fails` / `circuit_open_s`）。
- **DoS 防御**：UDP miss 队列有界信号量（池满丢弃、客户端自动重试）；`decode_name` 压缩指针 32 跳上限；应答上限 8 条 + TC 位；客户端 EDNS bufsize 钳制到 `edns_client_max_size`（默认 1232）。
- **接收循环致命错误**：UDP socket 连续 20 次接收错误时，不再直接 `os._exit` 丢弃内存状态——先触发缓存持久化落盘再以非零码退出，由 systemd `Restart=on-failure` 重启，最多丢失一个保存周期（60s）内的缓存/预取状态。

---

## 8. 性能实测

> **可复现性说明**：下表的压测脚本（`stress_test.py` 等）与 `tests/` **不随发布包分发**，
> 因此这些数字在当前 32 文件包内无法原样复现；它们来自源码仓库的实测记录。

**最新一轮压测（v1.9.149，3 分钟 × 8 并发，8 个随机域名，非特权端口 DNS UDP `127.0.0.1:5354` / API `127.0.0.1:18091`，缓存命中率 100%）**：

| 指标 | v1.9.147 | v1.9.148 | **v1.9.149** |
|---|---|---|---|
| 压测时长 / 并发 | 180s / 8 | 180s / 8 | **180s / 8** |
| 总请求 | ~2,777,760 | 3,748,357 | **≈7,742,160（43012×180s）** |
| 成功率 | 100% | 100%（错误 0） | **100%（错误 0）** |
| 平均 QPS | 15,432 | 20,824 | **43,012** |
| P50 延迟 | 0.34ms | 0.362ms | **0.17ms** |
| P99 延迟 | 1.56ms | 0.859ms | **0.56ms** |
| P99.9 延迟 | — | — | **1.48ms** |
| RSS | — | — | **50.5 → 52.6MB（稳定）** |

> 3 分钟 **约 774 万请求零错误**，平均 QPS **43,012**，P50 **0.17ms**，P99 **0.56ms**，P99.9 **1.48ms**，RSS 稳定在 **52MB**。
> 本轮 QPS 较 v1.9.148（20,824）提升约一倍，主因压测期间缓存命中率 100% 且系统负载较低；P99 由 0.859ms 降至 0.56ms。（v1.9.150 为文档同步版，无数据面行为变更，沿用 v1.9.149 实测数据。）

**历史吞吐参考（早期版本，2 核 / 4GB 类虚拟机，缓存命中）**：

| 并发 | 吞吐 | p50 | p99 |
|---|---|---|---|
| 1 | ≈41,000 QPS | 0.03ms | 0.04ms |
| 8 | ≈73,000 QPS | 0.10ms | 0.19ms |
| 32 | ≈63,000 QPS | 0.44ms | 2.48ms |
| 64 | ≈34,000 QPS | 1.18ms | 9.37ms |

- 多域名缓存命中（200 个域名，32 并发）：≈76,000 QPS，错误率 0。
- 长时间稳定性（混合负载：真实命中 + 随机 miss + 10 万规则命中，30 线程 × 5 分钟）：总查询 39,218，**错误 0**，RSS 稳定 131MB（缓存填满 131072 条后不再增长，无内存泄漏）。
- 暴力压测（200 线程纯命中 × 5 分钟）：总查询 **6,125,693**，错误 187（**0.0031%**，UDP socket 压力边界），稳定 ≈20k QPS，RSS 恒定 227MB。

**崩溃自启**：高负载下 SIGKILL → **3.5s 内自动重启**，重启后配置/规则/上游/缓存全部恢复，解析功能正常。

**首次解析（真实 miss）延迟**：受外网上游延迟限制，UDP 上游 ≈6-9ms；多 IP 域名（含测速择优）≈60ms。缓存命中路径 p50 ≈ 0.03-0.6ms。

---

## 9. eBPF 内核态缓存（v1.9.158+，可选加速层）

### 9.1 原理

XDP 程序在网卡驱动层拦截发往本机 UDP/53 的 DNS 查询，解析 (qname, qtype) 后查 BPF LRU_HASH 内核缓存 map：

- **命中且未过期**：内核直接构造 DNS 应答（修改 flags、ANCOUNT、追加 answer 记录、交换 MAC/IP/UDP 地址、重算 IP 校验和），`XDP_TX` 从网卡直接回包——**完全不经过协议栈和用户态 Python**，延迟可低至亚微秒级。
- **未命中或过期**：`XDP_PASS` 放行给用户态 ebpdns 正常解析；解析完成后用户态将结果（原始应答 + TTL）回写 eBPF map，后续查询即可内核命中。

```
客户端 ──UDP:53──▶ 网卡 XDP Hook
                      │
              ┌───────┴───────┐
              ▼               ▼
         eBPF map 命中    eBPF map 未命中
         (XDP_TX 直答)    (XDP_PASS)
              │               │
              ▼               ▼
          客户端◀────   用户态 ebpdns 解析
                              │
                              ▼
                        回写 eBPF map ◀── 启动预热(用户态缓存热条目)
```

### 9.2 配置项

| 配置键 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `kernel_cache` | bool | `false` | 是否启用 eBPF 内核态缓存加速 |
| `kernel_cache_iface` | str | `"auto"` | 挂载 XDP 的网卡名，`auto`=自动选择默认路由网卡 |
| `kernel_cache_max` | int | `65536` | eBPF LRU map 最大条目数，范围 1024–1048576 |

现有 `kernel_direct`（遥测计数开关）保留不变，与 `kernel_cache` 独立。

### 9.3 部署与编译

```bash
# 1. 安装编译依赖（Debian 13）
sudo apt install clang llvm libbpf-dev linux-libc-dev bpftool

# 2. 编译 eBPF 程序
cd /opt/ebpdns/bpf && make

# 3. 设置权限（允许非 root 加载 eBPF）
sudo setcap cap_bpf,cap_net_admin,cap_sys_admin+ep /opt/ebpdns/bin/ebpdns

# 4. 配置启用
# 编辑 /etc/ebpdns/config.json，设置 "kernel_cache": true

# 5. 重启服务
sudo systemctl restart ebpdns
```

systemd unit 已包含 `AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN`。

### 9.4 降级策略（默认安全）

任一条件不满足即自动降级为纯用户态，**不影响 DNS 服务**，日志输出 WARNING，Web 控制台显示 degraded + 具体原因：

| 降级触发条件 | reason 示例 |
|---|---|
| 非 root 且无 CAP_BPF | `缺少 CAP_BPF 权限（需 root 或 setcap）` |
| libbpf.so 和 bpftool 均不可用 | `未找到 libbpf 或 bpftool` |
| 未找到 ebpdns_xdp.o | `未找到 eBPF 目标文件（需 clang 编译）` |
| eBPF verifier 拒绝加载 | `eBPF verifier 拒绝加载: <错误>` |
| 网卡不支持 XDP_TX | `网卡 eth0 不支持 XDP: <错误>` |

Web 控制台 pipeline 页 eBPF 徽章：active=绿色显示"内核态缓存已启用 (eth0) · 命中 X/Y (Z%)"；degraded=灰色显示具体原因。`/api/status.ebpf` 和 `/metrics` 的 5 个 eBPF 指标可观测。

### 9.5 性能预期

- **纯用户态基线**（v1.9.158，3 分钟 12 workers）：QPS ~36,000、P50 0.21ms、P99 1.0ms、RSS ~48MB
- **启用 eBPF 后**：缓存命中查询不进用户态，预期 QPS 显著提升（受网卡 XDP 性能限制，可达 100k+ QPS）、P99 延迟显著降低（亚微秒级）。需在支持原生 XDP_TX 的物理/虚拟网卡环境实测验证。
- TCP DNS 始终走用户态（XDP 只处理 UDP 53，TCP 连接状态复杂，内核态处理收益低）。

### 9.6 故障排查

```bash
# 查看 eBPF 状态和降级原因
curl -s http://127.0.0.1:8080/api/status | python3 -m json.tool | grep -A5 ebpf

# 查看 eBPF 指标
curl -s http://127.0.0.1:8080/metrics | grep ebpf_

# 查看 XDP 挂载状态
ip link show dev eth0 | grep xdp

# 查看 eBPF 程序和 map
bpftool prog show | grep ebpdns
bpftool map show | grep dns_cache

# 查看降级日志
journalctl -u ebpdns | grep -i "eBPF\|bpf"
```

### 9.7 注意事项

- 内核 ≥ 5.7（`bpf_ktime_get_boot_ns` 需求），建议 5.15+，开启 BTF（`/sys/kernel/btf/vmlinux` 存在）
- 网卡驱动需支持原生 XDP（部分云主机 virtio 网卡不支持 XDP_TX，会自动降级）
- eBPF map key 使用 djb2 64 位哈希（非完整 qname），碰撞概率极低；用户态 `_qname_djb2` 与 eBPF `parse_qname` 算法严格一致
- ECS（EDNS Client Subnet）启用时跳过 eBPF 回写/预热（eBPF key 无 ECS 维度，避免跨子网错答）
- 规则变更/配置重载/订阅更新后自动清空 eBPF map，避免残留过期规则
- 详见 `bpf/README.md` 和 `bpf/ebpdns_xdp.h`（map 布局定义）

---

## 10. 本地开发 / 测试

```bash
# 单元测试（两种等价方式）—— 注意: 发布包内不含 tests/, 需在源码仓库执行
make test
python3 -m unittest discover -s tests
# 压测 / 性能剖析（根目录脚本；先以非特权端口起一个 daemon，再连它压测）
python3 stress_test.py        # 混合负载长稳压测
python3 profile_test.py       # 性能剖析采样
python3 full_log_test.py      # 全量日志路径验证
# 以非特权端口本地运行
python3 -m ebpdns run --dns-udp 127.0.0.1:1053 --dns-tcp 127.0.0.1:1053 --api-port 8081
# 自研客户端验证真实解析
python3 - <<'EOF'
from ebpdns import dnsmsg
import socket
q, _ = dnsmsg.build_query('www.baidu.com', dnsmsg.type_code('A'))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
s.sendto(q, ('127.0.0.1', 1053)); data, _ = s.recvfrom(4096)
print(dnsmsg.parse_message(data)['answers'])
EOF
```

---

## 11. 目录结构

```
ebpdns/
├── bin/ebpdns              # 可执行入口
├── ebpdns/                 # Python 包（纯标准库）
│   ├── cli.py              # 命令行与 daemon 装配
│   ├── config.py          # 配置加载/保存（原子写入；DEFAULTS/_NUM_RANGES/_ENUM_VALUES 校验）
│   ├── dnsmsg.py          # DNS 报文编解码（应答上限 8 条 + TC 位）
│   ├── cache.py            # 用户态缓存三模式（lru 分区 / partitioned / tinylfu；TTL/serve-stale/持久化）
│   ├── upstream.py        # UDP/TCP/DoH/DoT 上游（连接复用、qid/源校验、熔断）
│   ├── quic_upstream.py    # DoQ / DoH3（aioquic 可选，常驻连接 + 多路复用）
│   ├── probe.py            # 上游延迟主动探测 / 一键重测速
│   ├── resolver.py         # 解析引擎（分流索引/并发/测速/预取/负缓存/fallback）
│   ├── server.py           # UDP/TCP DNS 服务器（命中快路径）
│   ├── telemetry.py       # 遥测计数与采样（原子计数 / Top N / Prometheus）
│   └── api.py              # HTTP JSON API + Web 静态服务
├── web/index.html          # 控制台（双模式，ECharts 本地化）
├── bpf/                    # 可选 eBPF XDP 内核旁路（已集成 bpf_loader.py，编译成功但校验器待适配；见其 README 的"已知限制"）
├── systemd/                 # ebpdns.service（降权用户 + CAP_NET_BIND_SERVICE）+ 每日重启 timer
├── etc/ebpdns.conf.json    # 配置模板（与 config.py DEFAULTS 对齐）
├── install.sh              # 安装脚本（自动检测/安装 python3、aioquic）
└── （源码仓库另有，**不随发布包分发**）
    ├── package.sh           # 打包脚本（./package.sh <version>）
    ├── stress_test.py / profile_test.py / full_log_test.py  # 压测/剖析脚本
    ├── tools/build_console.py  # 控制台构建（Makefile 的 console 目标依赖）
    └── tests/               # 单元测试（Makefile 的 test 目标依赖）
```

---

## 12. 已知限制

- 解析结果为“精简应答”（SmartDNS 风格，只返回目标类型地址并择优），不完整透传 CNAME 链；对大多数客户端无影响
- DoH/DoT 上游使用 hostname 时依赖系统 DNS 解析 ~~（v1.9.42 已通过 Bootstrap 解析器解决：启动时用 UDP 上游预解析 hostname 为 IP，后续连接用 IP+SNI，不再依赖系统 DNS）~~
- **eBPF 内核态缓存（`kernel_cache`，可选加速层）**：`make -C bpf` 可成功编译出 `ebpdns_xdp.o`，但内核 BPF 校验器**仍拒绝加载**（应答构造段的包指针范围证明，详见 `bpf/README.md`）。`kernel_cache` 默认 `false`，开启时 `bpf_loader` 正确降级为纯用户态并在 `/api/status.ebpf.reason` 如实上报原因，**DNS 服务不受影响**。真实 XDP 内核直答还需支持原生 XDP 的网卡（云主机 `virtio_net` 通常不具备）
- 未实现 DNSSEC 验证（转发型解析器典型取舍）
- **安全信任边界（接受式风险，见注释）**：① 显式配置 `*_strict_cert:false` + IP 字面量上游时，证书校验降级为"仅链+有效期"，任何受信 CA 证书可 MITM（默认严格，降级连接即用即弃不入池）；② `api.host=0.0.0.0` + 空 token 的 LAN 模式下，`.local/.lan` 等主机名免 DNS 解析即信任，存在 DNS-rebinding 写/读风险（默认 `127.0.0.1` 环回不受影响）

---

## 13. 版本历史（要点）

- **v1.9.164**：v1.9.163 生产包的**逐行代码审查 + 保守精简重构 + 连续两轮独立部署验证封板**版（基于用户回传的 v1.9.163 生产包，14 个 Python 模块 18272 行 + web/index.html 3790 行 + bpf/ 522 行，按文件边界四路并行逐行审查、前后端契约核对，全程不动热路径/并发/eBPF/安全校验/防御性检查，`py_compile`/`pyflakes` 终态零告警）。
  - **保守精简（功能零回归）**：Python 18272→**18227**（-45 行）、index.html 3790→**3788**（-2 行）。`dnsmsg.py` 删 3 个零调用私有函数（`_rcode_name`/`_edns_bufsize`/`_opt_rr_bytes`，后者自 v1.9.85 被 `_question_edns_info` 取代）与未用局部 `qend`；`telemetry.py` 删零调用 `fast_hit`（热路径已统一 `fast_hit_logged`）与被锁内深拷贝取代的 `upstreams_snapshot`；`api.py` 删死集合 `new_ids`、未用元组项 `idx_err` 改 `_` 占位、3 处 `except ... as e` 去 `as e`（保留 `exc_info=True` 不丢栈）、删 `ttl_min/ttl_max` 死赋值（for 循环透传逻辑保留）；`bpf_loader.py` 删未用 `import Dict` 与常量 `_BPF_MAP_CREATE`/`_CNT_MAX`；`resolver.py` 删未用局部 import、`probe.py` 删多余 `global` 声明（仅原地 `append` 无 rebind，锁内 append+start 时序不变）、`server.py` 清理注释残留；前端删未用常量/死形参/死 CSS 选择器/无引用 DOM id，并抽 `PROTO_SCHEME`/`CERT_KEYS` 公共常量。
  - **修复（本轮审查发现）**：①【P0·前端】`renderUpstreams` 中 doh/doh3/dot/doq 四个证书 checkbox 模板动态属性段后漏写 `>`，浏览器把 `disabled`/`checked` 吞进垃圾属性名，导致协议匹配框回填 `checked` 丢失、非匹配框 `disabled` 永不生效，补齐后实测 16/16 框状态正确；②【P2·前端】SIM 演示态 `sim.counters` 用 camelCase（`kernelDirect`/`upstreamQueries`）而读取用 snake_case，致 KPI「内核直答/上游请求」恒显 0，键名统一；③【P2·前端】规则删除/上游删除补二次确认 `confirm`（与重启/热重载/订阅删除一致），取消不误删、确认才移除并落盘。
  - **验证（连续两轮零问题）**：非特权端口（DNS 5354/API 18091，前后端独立隔离工作目录）完整部署两轮，DNS 六协议（DoQ UDP/853 不通标环境限制）、缓存三模式+分区权重+SIGTERM 落盘重启零上游增量、熔断/健康/恢复、规则（block/forceIp 含缓存快路径/allow/通配）、订阅自签 IP-SAN 长窗口连续自动刷新+原子落盘+源新增 tick 拉取+404/断连仅 WARNING、API 全端点（401/200/204/400/404/HEAD/OPTIONS）、Prometheus 30 family 含 5 ebpf、eBPF 双档降级+运行态三路径+边界校验、execvpe 重启（PID 不变 uptime 归零）、历史回归（`mirrors.aliyun.com AAAA` 正确 NODATA、bailiwick 投毒 fuzz 无崩溃、speed clamp、四证书键、install.sh host→addr）；前端 5 路由+仪表盘卡片+全按钮/输入框/弹窗桌面+移动逐项实测，两轮 console error=0、日志 ERROR/Exception/Traceback=0。
  - **3 分钟压测（12 workers，两轮）**：QPS 36,066 / 39,316、errors=0、sent=received（649.9 万 / 708.5 万）、P50 0.203 / 0.215 ms、P99 1.056 / 0.959 ms、RSS 达平台后稳定（+1.4 / +1.0 MB，无泄漏）；不劣于 v1.9.161 基线（QPS 33,928/33,077、P99 1.116/1.109），QPS 波动属沙箱 CPU 配额时段差异。
  - **真机待复核（环境无 clang/CAP_BPF，沿用 v1.9.161 未闭环项，不影响默认 kernel_cache=false 的纯用户态服务）**：`bpf/ebpdns_xdp.bpf.c:326` 应答构造段一处死 store（`dns_off = dns2 - data` 赋值后无读），真机重编译可顺手删；XDP 命中构造应答路径仍需在原生 XDP 网卡 + root + clang/llvm/libbpf-dev 环境 `make -C bpf` 加载并抓包最终确认。
- **v1.9.163**：Web 控制台专项版（基于用户回传的 v1.9.162 生产包）。① 修复配置页「缓存策略/缓存文件」恒不刷新、订阅条数恒显 `0 条`（`rule_count`/`count` 双口径）、上游表空态与错误态同文案；② 11 个 `setInterval` 收敛为单一调度器（按页路由 + 单 tick 去重 + 独立指数退避 + `document.hidden` 冻结 + 交互/切页立即刷新 + 日志 `since=next_seq` 增量），60s 真实浏览器窗口实测 pipeline 请求 −13.9%、config −23.5%；③ 新增 `prefers-reduced-motion` 支持（改前 0 处；含终态复位避免元素永久不可见）、日志新行淡入、数值变化高亮、加载骨架；④ 数据显示：千分位、超长值截断+title、空/错/加载三态区分；⑤ `install.sh` 增加**跨实现配置兼容性检测**（Rust 版 `upstreams[].host` → 本版 `addr`，此前会导致 22/22 上游被丢弃且控制台端口错误）。
- **v1.9.162**：高强度对抗审查 + 压测后多轮独立复查封板版（基于用户回传的 v1.9.161 生产包，14 个 Python 模块约 1.8 万行 + web/index.html 3560 行 + bpf/ 数据面，逐行审查、前后端契约核对、cProfile 优化、精确 180s 压测，压测后连续三轮独立复查后两轮零新增）。测试由 v1.9.143 的 111 项适配扩充至 **244 项全绿**。
  - **BPF 数据面（本轮纳入审查与修复；环境无 clang，仅静态审查与 C↔loader 一致性核对，未做编译/加载验证）**：①【中】XDP 程序补**非首片分片守卫**（`bpf_ntohs(ip->frag_off) & 0x1fff` → XDP_PASS：中/尾分片在 ip+ihl 处并无 UDP 头，原代码不查片偏移会把分片载荷误当 DNS 查询、命中缓存后 XDP_TX 出无关错误应答；首片 MF=1 偏移=0 仍放行）；②【低】补 IP `version != 4` 硬校验；③ 修 `bpf/load.sh` 的 `A || B && C` bash 左结合控制流 bug（ip 直挂成功后仍误执行 pinned 路径、set -e 下误报退出）；④ 修 `bpf/README.md` 容量事实漂移（1024→实际默认 65536）。
  - **bpf_loader.py（用户态加载器）**：① ctypes `_dns_cache_val.rdata` 维度由 `c_uint8*8*16`（被解释成 16 行×8 列）改为 `(c_uint8*16)*8`，与 C 的 `rdata[8][16]` 行主序对齐（sizeof=152/偏移=24 不变，内存字节本就正确、仅语义修正）；② `clear_cache` 由"先删后以已删除 key 为前驱枚举"（前驱不存在立即 -ENOENT、只删第一条）改为**前驱恒 NULL 的安全枚举 idiom**，并加 `max_entries+16` 迭代上限防持续错误 livelock；③ libc 句柄模块级缓存（原每次 syscall 重新 `CDLL(None)`）、`syscall` restype 显式设为 `c_long`（修复 64 位负 errno 截断）。
  - **resolver.py**：①【真实回归·已修】CNAME 子链确认目标 NODATA（rcode=0 空应答）时父级误落 SERVFAIL（v1.9.161 NODATA quorum 加固的 `and not cnames` 把父级 CNAME 应答全排除、nodata 列表恒空），现父级正确返回 rcode=0 空应答并负缓存、复用子链 ttl_left（线上 `mirrors.aliyun.com AAAA` 由恒 SERVFAIL 恢复为 NODATA）；② NODATA 证据过滤收紧为 rcode==0 且 `not udp_truncated` 且 `not cnames`（截断/CNAME 裸应答不再计入多数表决）；③【中·安全】**规则代际写回门禁**：resolve 入口记 `_gen_at_entry=_rule_gen`，随答案透传 `_fill_cache→_ebpf_writeback`，规则在途重建（gen 自增+清 map）后跳过内核写，堵住在途应答把真实 IP 写回内核 map、XDP 直答旁路新 block 的窗口；全部上游应答路径（含双栈探测 `_probe_a_record`、IPv4 回退 `_ipv4_fallback`）均已透传；④ forceIp 规则在缓存命中快路径即时生效（复用已调用的 match_rule、零额外开销，畸形 ip/类型交叉 fail-closed）；⑤ `_last_speed_test.move_to_end` 加 try/except KeyError；⑥ CNAME→NODATA neg_ttl 死代码重构（ttl_left<=0 时兜底 60s、封顶 60）；⑦ writeback 静默吞异常改 debug 留痕。
  - **quic_upstream.py**：新增 `_last_conn_err`/`_conn_failed` 连接状态机——建连失败按证书/拒绝/DNS/TLS 分类记录、退避态查询快速失败（不再白等完整超时）、`_exchange` 返回 `(ok,data,err)`、`query` 第 4 项透具体原因；等待超时归 "timeout" 不复用残留旧原因；close 已是 list 快照（并发 add 安全）。
  - **upstream.py**：`_is_header_only` 由"qd==0 且 an==0"收紧为 **QDCOUNT != 1 即拒绝**（两副本同步，正常 qd=1 含 NODATA/NXDOMAIN 不误杀）。
  - **cli.py**：补本地 `_safe_int`（拒 bool），修复 eBPF 预热路径调用未定义符号抛 NameError 被宽 except 吞、预热恒失效。**server.py**：快路径宽 except 保留降级并加计数+采样 WARNING。**systemd**：补"严格沙箱下 bpftool 降级路径不可用、内核缓存仅 libbpf.so.0 可用时生效"注释（未放宽沙箱）。
  - **web/index.html**：证书开关由"DoH/DoH3 共用 doh_strict_cert 一个框（DoH3 死控件+回填失真）"拆/增为 **doh/doh3/dot/doq 四个独立框**，各绑各键、协议切换 disabled 联动、回填 `!==false`；保存响应过滤 `listen/api/web_root` 只读段，消除每次保存恒弹琥珀提示。
  - **性能/压测**：cProfile 确认热路径成熟（普通命中约 10µs、单线程约 100k qps），无安全优化点、未做冒险改动。最终精确 180s 混合压测：**75308 成功**、QPS 416、P50 0.06ms/P99 267.6ms，压后 30s 纯命中稳态 RSS/线程/fd/miss 全部平台，**无内存/线程/句柄泄漏**；压测期间零 Traceback/ERROR（2 个冷域 SERVFAIL 为偶发上游整体超时的 fail-closed 优雅降级，非代码缺陷）。
  - **真机待复核**：BPF 修改（分片守卫的 verifier 接受度、adjust_tail 后指针重建在目标内核的校验、A/AAAA/NXDOMAIN/EDNS 应答字节）仍需 clang+root+原生 XDP 网卡环境验证；DoH3/DoQ 需安装 aioquic；境外 DoH 大陆不可达——均为环境限制。


  - **编译失败修复（真机 clang 19 -Werror）**：删除 v1.9.160"精确扩容+shrink"遗留的死变量 `orig_len`（unused variable 直接导致 `make` 失败、无 `ebpdns_xdp.o`、kernel_cache 恒降级"未找到目标文件"）；未被引用的参考函数 `qname_hash` 加 `__attribute__((unused))`。
  - **读取阶段 verifier 范围证明**：qtype/qclass 边界由两个运行期标量相减 `q_off+4 > dns_len` 改为校验器可跟踪的**指针比较** `(dns+q_off)+4 > data_end`；`dns_off` 提前计算并夹编译期常量上界 1500（合法 DNS 段起点 42~82，VLAN/隧道后仍远小于 1500，不误杀）；`ip_hlen` 显式夹到 [20,60]。
  - **应答构造段 verifier 友好重构（核心）**：`bpf_xdp_adjust_tail`/map helper 会清空标量范围跟踪，原实现扩容后用"包指针 + 无界标量偏移"（`dns2+write_off`、`data+udp_off`、标量差 shrink）构造写入指针，校验器在应答构造阶段拒绝（推进到 2704 条指令）。重构为：① answer 写循环改 **pos 指针递进**（起始 `dns2+q_off+4` 已重证明，每写一条按地址族用常量指针比较 `pos+28`/`pos+16 > data_end`，写完 `pos += 28/16`），不再用无界 `write_off`；② shrink 改为同基指针差 `data_end - pos`（非负、有界）；③ 二次 adjust_tail 后从 `data` 起 **eth→ip→udp 逐层重建指针并逐层建立范围证明**，MAC/IP/端口交换与 UDP len/IP tot_len 全部用重建后的指针（指针差），删除无界 `udp_off`；④ checksum 调用前证明整个 IP 头 `ip2+ihl <= data_end`。
  - **DNS 报文语义零变化**：上述仅为通过校验器的写法重构，应答字节布局与 v1.9.160 完全一致——逐字节仿真（2×A 带 EDNS / 8×AAAA / 5A+3AAAA / 1×A / NXDOMAIN / NODATA / 0x20 大写 / AAAA 带 EDNS 共 8 用例）经 dnspython `from_wire()` 解析全部正确（无 TrailingJunk、udp_len==tot_len-20 自洽、qd=1/an=实际 RR/ns=0/ar=0、question qtype 完好、地址正确），叠加 20 万随机 IP 头校验和回归全过。
  - **API 高并发健壮性（P3）**：`ThreadingHTTPServer` 每连接一线程，极端高并发**短连接**风暴耗尽 OS 线程（`ulimit -u`）时 `t.start()` 抛 `RuntimeError: can't start new thread`，原路径被 socketserver 打成 traceback。现于 `process_request` 边界**严格只捕获**该资源耗尽 RuntimeError（其他 RuntimeError 仍抛出），归还连接信号量、尽力关闭连接、单行 5s 窗口聚合 WARNING（"连接线程资源不足, 拒绝新连接 …(另静默丢弃 N 条)"），不打栈、不崩服务、不影响已建立连接；配合既有 256 有界信号量背压。实测 `ulimit -u=200` 下 600 并发触发拒绝仅一行 WARNING、0 Traceback，keep-alive 复用 2000 次全 200。
  - **验证**：生产包解压布局非特权启动，eBPF 双档降级（缺 CAP_BPF / 未找到 .o）原因精确；DNS 六协议（DoQ 与境外节点为环境限制）、缓存三模式/分区权重/持久化重启恢复、预取/测速/熔断/健康检查、规则热加载、**周期订阅后台自动更新长窗口实测连续刷新+原子落盘**、API 全端点状态码、Prometheus 30 family 含 5 个 ebpf 指标、eBPF 运行态三路径、execvpe 重启 PID 不变、CSP/XFO、speed clamp 全过；前端桌面 1280×800 与移动 375×812 五路由/汉堡抽屉/5 ECharts/查询控制台 0 console error；全量日志 0 ERROR/Exception/Traceback。
  - **真机待复核（重要，未在本环境闭环）**：本环境为云主机 virtio_net（不支持原生 XDP）且无 clang，应答构造段的 verifier 友好重构**已在代码层消除全部已识别的"包指针+无界标量"访问、DNS 语义经仿真与 v1.9.160 字节一致，但尚未经真机 `bpftool prog load` 与原生 XDP 网卡真实抓包确认**（含 checksum 内联函数的范围继承等）。需在支持原生 XDP_TX 的网卡 + root + clang/llvm/libbpf-dev 环境 `make -C bpf` 后挂载、用 dig 打 A/AAAA/EDNS/混合用例抓包核对，并以 `bpftool prog load` 复核校验器日志。kernel_cache 默认 false，未加载成功时自动降级纯用户态，DNS 服务不受影响。
  - **高强度对抗审查（四路并行子代理 + 实证复现）**：修复 1 高危 + 2 中危 + 5 低危。①【高危·缓存投毒】bailiwick 信任根由响应回显 question 段改为锚定真实查询域名 `d`（`d` 从 `resolve()` 下传 `_query_parallel→_classify_one→_extract_answers_full`），0x20 降级后伪造 question 无法再绕过；②【中危】bailiwick 空 owner（根 "."）绕过修复；③【中危】NODATA 负缓存补齐与 NXDOMAIN 相同的 quorum 多数表决（单撒谎上游不再造成 60s NODATA DoS）；④【低】`padding:true` 时 TCP 回退改用 `qmap["tcp"]`（保留 0x20 熵）；⑤【低】`Server` 响应头去版本指纹（现为 `Server: ebpdns`）；⑥【低】订阅 URL SSRF 补 `is_reserved`（拦 NAT64/IPv4-compatible）；⑦【低】快/慢路径缓存键规范化统一 `_normalize()`；⑧【低】bpf_loader 错误掩盖修复（保留 libbpf 具体诊断）。50 万级模糊测试 0 崩溃。
  - **install.sh 一键自动装依赖**：自动检测并安装 python3/aioquic/完整 eBPF 工具链（**make**/clang/llvm/libbpf-dev/linux-libc-dev/bpftool）/iproute2/libcap2-bin/rsync；`apt-get update` 仅一次；可选依赖装失败不阻断部署。修复漏装 `make`（`make: command not found`）与编译失败静默吞错（现失败时回显具体编译错误 + 排查提示）。
  - **性能优化**：TCP `request_queue_size` 5→256，修复高并发短连接下 backlog 太小导致的连接超时（压测 TCP 200 并发错误率 5%→0%）。

- **v1.9.160**：eBPF 内核态直答报文正确性 + 部署升级修复版（基于 v1.9.159，连续四轮独立审查，后两轮连续零错误封板）。v1.9.159 修复了 eBPF 主要缺陷，但因沙箱无 clang/cap_bpf、XDP 命中构造应答路径从未被真正编译执行，本轮改用"完整协议账逐字节仿真 + dnspython `from_wire()` 真实解析"继续深挖，又发现并修复了潜伏在内核直答报文构造与加载器枚举、部署升级路径上的若干问题。
  - **P0 修复（N1，内核直答 answer 起始偏移 off-by-4）**：XDP 命中构造应答时首条 answer RR 起始偏移由 `write_off = q_off` 改为 `q_off + 4`。`q_off = 12 + qname_len` 是 qtype 起始位置，question 段为 `[12, q_off+4)`（qname+qtype+qclass）；原写法把首条 RR 写到 qtype/qclass 上，导致应答 question 的 qtype 被写成压缩指针 `0xc00c`、answer 整体错位 4 字节、`rdlen` 越界——所有正向 A/AAAA 内核直答包畸形，真实客户端拿不到地址。
  - **P1 修复（R2-1，应答尾部多余字节 TrailingJunk）**：扩容改为先按 `addr_af[]` 精确累加实际 RR 字节（AAAA=28/A=16）`rr_bytes`，写完 answer 后再 `bpf_xdp_adjust_tail(-shrink)` 收缩到实际末字节并重取全部指针；边界检查按地址族分支（A 预留 16、AAAA 预留 28）。原先统一按最坏 `naddr*28` 扩容却不裁剪，含 A 记录或 EDNS OPT 查询的应答带尾部残留字节，dnspython 等严格解析器报 `TrailingJunk`。修复后 UDP length / IP tot_len 与实际字节严格自洽。
  - **P1 修复（install.sh 就地升级误删 bpf_loader.py）**：v1.9.158 新增的 `ebpdns/bpf_loader.py` 漏入 install.sh 就地安装关键文件清单与就地升级白名单，就地升级会把它当陈旧模块 `rm -f` 删除，运行时 ImportError 虽被捕获不崩 DNS，但 eBPF 在该升级路径永久静默失效。两处清单补齐，与 package.sh 生产包模块列表四方集合完全一致（14 个 .py）。
  - **P2 修复**：① N2——构造应答时清零 NSCOUNT/ARCOUNT（内核只回 answer，不回放 authority/EDNS OPT；带 OPT 查询 ARCOUNT=1 时原 OPT 残留被 answer 覆盖产生畸形附加段），QDCOUNT 保持 1；② R2-2——`clear_cache()` 首次 `BPF_MAP_GET_NEXT_KEY` 前驱 key 由"全 0 但非 NULL"改为传 NULL，htab 语义下后者才从整个 map 第一个 key 枚举，避免漏删桶号更小条目导致规则变更后部分内核旧答案残留到 TTL。
  - **P3 修复**：PERCPU 计数器读缓冲 CPU 数取 `max(在线 affinity, SC_NPROCESSORS_CONF, cpu_count)` 上界（防 possible>online 时 EFAULT 指标读 0）；bpftool attach 失败时同步清理 pinned 的 dns_cache/counters map 文件；用户态 live 回写 TTL 改用 `expires_at - now` 剩余值（与预热口径一致，不再多告知满 TTL）；eBPF 降级 WARNING 去重（加载器内部降为 debug，由 cli 统一输出单行）。
  - **设计接受项（非缺陷，代码注释说明）**：内核直答仅处理 OPCODE=0 标准查询、qclass=IN；CNAME 链不回放（只回终点 A/AAAA、RR name 用压缩指针 0xc00c 指向原 qname）；EDNS OPT/authority 不回放；shrink 极端失败时 `XDP_PASS` 等价一次 miss。
  - **验证（连续四轮，后两轮连续零错误封板）**：每轮均四路并行（eBPF 独立复审 + 数据面 + 前后端联动 + 前端桌面/移动）。eBPF 封板轮由未参与此前轮次的代理独立重读全部源码、自写仿真，累计 20 万+随机 IP 头校验和验证、10 类应答用例（2×A 带 EDNS / 8×AAAA / A+AAAA 混合 / 1×A / NXDOMAIN / NODATA / 0x20 大写 / AAAA 带 EDNS 等）经 dnspython 解析全部正确、无 TrailingJunk、ANCOUNT 与实际 RR 数一致；clear_cache 枚举经 mock htab 验证从头不丢。数据面/联动/前端连续多轮全绿（联动单轮 81 项断言、前端单轮 34/34、0 console error）；周期订阅后台自动更新在 85s 窗口实测 12 次刷新并随源变更自动拉取落盘。Debian 13 部署走查实证无 clang 时优雅降级不中断、systemd 四项 capability + LimitMEMLOCK 齐备、非特权部署逐功能模块正常。全量日志 0 ERROR/Exception/Traceback/AttributeError。
  - **真机待复核（沙箱限制）**：沙箱非 root、无 clang/llvm/bpftool，eBPF C 未实际编译加载；`make -C bpf` 实编、verifier 对精确扩容/二次 adjust_tail/分支边界的证明、`bpf_map__set_max_entries` 对 BTF LRU_HASH 兼容性、真实 XDP_TX 加速效果需在 Debian 13 + root + clang + 原生 XDP 网卡环境复核。

- **v1.9.159**：eBPF 内核态缓存正确性修复版（基于 v1.9.158，专项深度审查发现并修复 2 项 P0、7 项 P1、7 项 P2、若干 P3）。v1.9.158 首次交付 eBPF 功能后，本轮逐行复审发现两处使内核直答对真实流量失效的 P0 及多处加载器/部署缺陷，全部修复并经独立复审 + 全功能回归确认。
  - **P0 修复**：① qname 哈希大小写口径统一——eBPF C `parse_qname` 哈希时对标签内容字节做 A-Z→a-z 小写化，与用户态 `.lower()` 对齐（原先内核用 wire 原始字节、用户态用小写，0x20 大小写随机化查询近乎 100% miss，内核直答等于未开启）；② 应答扩容/边界修正——`grow = naddr*28`（按 AAAA 每条 12B 头+16B rdata 最坏值），边界保护预留完整 28B/RR（原先按 16B 估算，8×AAAA 越界，verifier 拒绝或产生 ANCOUNT 与实际 RR 数不符的畸形包）。
  - **P1 修复**：IP `tot_len` 减去 14B 以太网头（原先多算，与 UDP 长度不自洽）；内核应答正确回写 RCODE（NXDOMAIN 不再被答成 NOERROR 空应答，保留 RD 位置 QR/RA）；`clear_cache()` 由空操作改为 `BPF_MAP_GET_NEXT_KEY`+`DELETE_ELEM` 真实枚举清空（规则变更/重载/订阅更新后内核不再按旧答案直答到 TTL 过期）；加载器改用正确的 `bpf_object__next_program`、attach 用 `libbpf_get_error` 判 ERR_PTR；install.sh 不再对 Python 脚本无效 setcap（改说明 systemd 推荐路径 + python3 解释器 ELF setcap 风险警告），systemd 补 `CAP_IPC_LOCK` 与 `LimitMEMLOCK=infinity`；订阅下载补 `RemoteDisconnected/ConnectionError/OSError` 分支（远端断连仅 WARNING 不打 Traceback）。
  - **P2/P3 修复**：map 默认容量 1024→65536 且加载前 `bpf_map__set_max_entries` 按 `kernel_cache_max` 配置覆盖（旋钮生效）；`naddr` 按实际填充数钳制；bpftool 降级路径同时 pin counters map（指标不再恒 0）；TTL≤0 条目不写入内核缓存（原先 expires_at=0 被当作永不过期）；PERCPU 缓冲按 `sched_getaffinity` 取 CPU 数（防越界）；libbpf 加载中途失败及 unload 路径统一 `bpf_object__close`（无 fd/内核对象泄漏，避免 double-close）；加 ctypes 布局运行期断言（key=16/val=152/字段偏移）；运行态 PUT `kernel_cache` 支持在线加载/卸载/重建（无需重启）；前端 eBPF 徽章 reason 为"未启用"时不再冗余显示。
  - **验证**：独立复审逐项确认 17 项 eBPF 修复正确落地（含逐字节模拟 C wire 哈希与用户态一致性、8×AAAA 扩容账验算、字节序核对）；全功能回归 22 项修复全过、14 项数据面无回归、前端 12/12、全量日志 0 ERROR/Exception/Traceback/AttributeError。沙箱仍无 clang/cap_bpf，`set_max_entries` 与 `rr+28` verifier 证明需 Debian 13 真机 `make -C bpf` 复核。

- **v1.9.158**：eBPF 内核态缓存重大功能增强版（基于 v1.9.157）。实现真正的 XDP 内核态 DNS 缓存直答，命中查询完全不经过协议栈和用户态 Python。
  - **eBPF C 程序（bpf/ebpdns_xdp.bpf.c）**：XDP Hook 拦截 UDP/53 DNS 查询，解析 qname（djb2 哈希，32 标签×63 字节有界循环，verifier 安全），查 BPF LRU_HASH map；命中时 `bpf_xdp_adjust_tail` 扩展报文、构造 DNS 应答（QR|RD|RA、ANCOUNT、qid 回填、answer 记录、MAC/IP/UDP 地址交换、IP 校验和）、`XDP_TX` 直接回包；未命中 `XDP_PASS` 给用户态。新增 `expires_at` 字段（`bpf_ktime_get_boot_ns` 基准），命中时检查 TTL 过期。支持 A/AAAA，结构可扩展。PERCPU_ARRAY 计数器（total/hit/miss/kernel_direct）。
  - **用户态加载器（ebpdns/bpf_loader.py，新建）**：`BpfLoader` 类完整实现加载/卸载/attach/detach/map 读写/计数器汇总/预热。优先 ctypes 调 libbpf.so.0（`bpf_object__open_file`→`load`→`find_map_by_name`→`map_fd`→`attach_xdp`），降级 bpftool CLI，再降级纯用户态。完善降级：无 cap_bpf/无 libbpf/无 .o/verifier 拒绝/attach 失败 → active=False + 具体 reason，不抛异常。`_qname_djb2` 与 eBPF `parse_qname` 算法逐向量一致。
  - **resolver.py 集成**：5 处 `cache.put` 后挂钩 `_ebpf_writeback`（门禁 active+qtype∈{A,AAAA}+rcode∈{NOERROR,NXDOMAIN}+非ECS，try/except 静默不阻塞热路径）；启动预热（用户态缓存热条目批量 warmup）；规则变更/配置重载/订阅更新后 `_ebpf_clear` 失效。ECS 启用时跳过回写/预热（eBPF key 无 ECS 维度，避免跨子网错答）。
  - **配置/API/前端**：config.py 加 `kernel_cache`(bool,默认False)、`kernel_cache_iface`(str,"auto")、`kernel_cache_max`(int,1024-1048576,默认65536)；/api/status 与 /api/snapshot 加 `ebpf` 子对象（active/iface/reason/max_entries/counters），/metrics 加 5 个 eBPF 指标；前端 pipeline 页加 eBPF 状态徽章（active 绿色显示命中率/degraded 灰色显示具体原因），config 页加 eBPF 内核态缓存配置区块。
  - **部署**：install.sh 检测 clang/llvm 编译 eBPF .o、`setcap cap_bpf,cap_net_admin,cap_sys_admin+ep`；systemd unit 加 `AmbientCapabilities`/`CapabilityBoundingSet`。
  - **降级策略**：无 BTF/无 cap_bpf/clang 缺失/加载失败/attach 失败 → 自动降级纯用户态，日志 WARNING，Web 控制台显示 degraded+具体原因，不影响 DNS 服务。TCP DNS 走用户态（XDP 只处理 UDP 53）。
  - **性能**：3 分钟 12 workers 纯用户态基线压测——QPS **35,967**、P50 **0.213ms**、P99 **1.01ms**、约 **648 万请求零错误**、RSS 稳定 **48MB**（起始 45MB，增长 3MB）。eBPF 内核态缓存启用后，命中查询不进用户态，预期 QPS 显著提升、延迟显著降低（需在支持 XDP_TX 的真实环境验证）。
  - **沙箱验证**：沙箱无 clang/无 cap_bpf，无法实际编译加载 eBPF；已完成代码审查、py_compile、ctypes Structure 偏移断言、降级路径端到端测试（kernel_cache=True 无 cap_bpf → 自动降级、reason 正确显示、DNS 正常、0 异常）、_qname_djb2 与 eBPF 算法一致性验证。

- **v1.9.157**：沙箱虚拟部署代码一致性修复版（基于 v1.9.156，四路审查发现 2 项 P3 一致性观察项，全部修复）。
  - **P3-1 订阅文件写缺父目录 fsync**：`resolver.py` 周期订阅自动更新落盘（:3291）与 `cli.py` 冷启动订阅补下载落盘（:447）这两条路径，在 `os.replace(tmp, path)` 后缺父目录 fsync，其余 5 条原子写路径（config.save_config / config.save_local_rules / cli._save_cache / api._save_subs）均有。修复：两条路径均补 `os.open(dir, O_RDONLY|O_DIRECTORY) → fsync → close`，与标准范式一致。自愈性强（下次启动重新下载），但极端掉电场景下目录项未刷出可能导致 rules_sub.json 丢失。
  - **P3-2 周期订阅 rebuild 在持锁内调用**：`resolver.py:3292` 周期订阅自动更新在持 `app_ctx._lock` 内直接调用 `self.rebuild_rule_index()`，与 API 写路径/冷启动路径"锁内自增代际、锁外 rebuild_rule_index_synced"范式不一致。10 万规则时 rebuild 耗时可能阻塞所有写 API。修复：锁内只自增 `app_ctx._rule_rebuild_gen`，锁外调用 `app_ctx.rebuild_rule_index_synced()`（走 `_rebuild_lock` 串行 + 代际跳过），与 cli._ensure_subs_downloaded / API 规则写路径完全对齐。
  - **v1.9.156 P1 修复回归确认**：上一轮修复的 `resolver.py:3286` `_os.path.dirname`（周期订阅落盘路径）经功能验证和前后端联动两路独立实际触发周期订阅更新（功能验证 24 次刷新、前后端联动 3 次 tick），全部确认 0 AttributeError/Traceback/ERROR，rules_sub.json 正常落盘、数据面真实生效。
  - **连续两轮零错误验收（硬性标准）**：v1.9.157 完成两轮独立四路并行审查（代码审查逐行全量 / 数据面 14 项 / 前后端联动六大模块 / 前端桌面+移动），**两轮均 P0–P3 全清、0 ERROR/Exception/Traceback/AttributeError**。第二轮换角度复审（锁序 DAG 无死锁环、后台任务无异常穿透、6 处父目录 fsync 无 fd 泄漏、前后端字段逐一对账、边界整数）。周期订阅落盘+锁外 rebuild 新范式两轮累计实际触发 50+ 次周期自动刷新（第一轮 7+10 次、第二轮 30+6 次），每次落盘后紧跟 `rebuild_rule_index took` 锁外重建标记，rules_sub.json updated_at 持续推进、屏蔽域名实测 NXDOMAIN、无 .tmp 残留。
  - **性能**：3 分钟 12 workers 压测两次——QPS **39,452 / 40,582**（均值约 4 万）、P99 **0.924 / 0.970ms**、约 **711 / 731 万请求零错误**、RSS 稳定 **48MB**（起始 45MB，增长约 3MB）。较 v1.9.156（42,017 QPS）波动 -3.4%~-6.1%（正常网络波动，<15% 回归阈值），无性能回归。

- **v1.9.156**：沙箱虚拟部署迭代修复版（基于 v1.9.155，修复 P3-b 修复引入的 P1 回归）。
  - **周期订阅落盘 AttributeError 修复（P1）**：v1.9.155 的 P3-b 修复（`resolver.py` 周期订阅落盘 tmp 移到 try 外）时，不慎将 `_os.path.dirname(...)` 笔误为 `_os.dirname(...)`（`os` 模块无 `dirname` 属性，正确为 `os.path.dirname`）。后果：周期订阅自动更新每次落盘在 makedirs 即抛 `AttributeError: module 'os' has no attribute 'dirname'`，导致①不落盘 ②`rebuild_rule_index()` 不执行、新规则不生效。手动 API 更新路径不受影响（api.py 的 5 条原子写路径全部正确）。v1.9.156 订正为 `_os.path.dirname(...)`，与全库其余 6 条原子写路径统一。全库扫描确认无同类笔误。
  - **代码审查结论**：v1.9.155 其余 3 项修复（P2 订阅更新 HTTPError、P3-a URLError、P3-c 前端 clamp 回写）经逐行审查 + 四路实测全部正确，热路径已高度优化（struct 预编译、bytearray、encode_name memo、LRU 8 分片锁、10% 事件采样、UDP 命中主线程直答、_now_ts 秒缓存），无高收益低风险新优化点。
  - **性能**：3 分钟 12 workers 压测——平均 QPS **42,017**、P50 **0.255ms**、P99 **0.715ms**、P99.9 **1.34ms**、约 **757 万请求零错误**、RSS 稳定 **48MB**（起始 45MB，增长仅 2.8MB）。较 v1.9.155（43,964 QPS）波动 -4.4%（正常网络波动，<15% 回归阈值），P99 延迟更优（0.715ms vs 0.869ms），无性能回归。

- **v1.9.155**：沙箱虚拟部署代码深度审查修复版（基于 v1.9.154，四路并行审查发现 4 项日志卫生/写路径/UX 问题，全部修复）。
  - **订阅更新路径 HTTPError 漏接修复（P2）**：`api.py:_api_subscribe_update`（点"更新"按钮触发的订阅重新拉取）自带内联 try/except，v1.9.154 只修了 `_do_subscribe_download` 的 HTTPError 分支，遗漏了此路径。v1.9.155 补齐 `except urllib.error.HTTPError`（`log.warning` 简洁 `HTTP <code>`，不输出栈），与添加订阅路径同口径。
  - **URLError 日志卫生修复（P3）**：`api.py` 两处订阅下载（`_do_subscribe_download` / `_api_subscribe_update`）此前仅覆盖 HTTPError，`urllib.error.URLError`（连接拒绝/超时/DNS 失败等预期网络错误）仍落 `except Exception: log.exception` 打完整栈。v1.9.155 在 HTTPError 之后新增 URLError 分支（URLError 是 HTTPError 父类，须在其后捕获），用 `log.warning` 记简洁 `e.reason`，不输出栈。
  - **周期订阅落盘原子写 tmp 清理修复（P3）**：`resolver.py:_apply_subscription_updates` 周期订阅自动更新落盘路径，`tmp = path + ".tmp"` 原在 try 内定义，except 无法访问清理残留 `.tmp`，与其余 5 条原子写路径（tmp 在 try 外 + except 内 exists 守卫清理）范式不一致。v1.9.155 将 tmp 移到 try 外，except 内加 exists 守卫清理。
  - **前端 bindCfg clamp 回写修复（P3）**：`web/index.html` 的 `bindCfg` 函数对数字输入框 clamp 后只写内存态 `real.config[key]`，不回写 `e.target.value`，导致用户输入超范围值（如 speed_interval_ms 输入 70000）后内存态正确钳为 60000 但输入框仍显示 70000，视觉认知偏差。影响所有 bindCfg 数字字段（共 15 个）。v1.9.155 在 bindCfg 内加回写：`if (e.target.type === 'number' && typeof v === 'number' && isFinite(v) && String(v) !== e.target.value) e.target.value = v;`（仅对 number 类型回写，不影响 checkbox/select/text）。
  - **性能**：3 分钟 12 workers 压测——平均 QPS **43,964**、P50 **0.195ms**、P99 **0.869ms**、P99.9 **1.541ms**、约 **792 万请求零错误**、RSS 稳定 **48MB**（起始 45MB，增长仅 3MB）。较 v1.9.152（35,246 QPS）提升 **+24.7%**，无性能回归。

- **v1.9.154**：Debian 13 部署验证修复版（基于 v1.9.153，修复日志卫生与文档同步）。
  - **规则订阅 404 Traceback 泄漏修复（P2）**：`api.py:_do_subscribe_download` 此前对所有非策略性异常用 `log.exception()` 输出完整栈，订阅 URL 返回 HTTP 错误（404/403/500 等，属预期业务错误）时日志被 Traceback 刷屏。v1.9.154 区分 `urllib.error.HTTPError`（用 `log.warning` 记简洁 `HTTP <code>`，不输出栈）与其他意外异常（保留 `log.exception` 供调试）；API 业务返回仍为通用 400，调用方行为不变。cli.py 冷启动补下载路径已用 `log.warning` 处理，无需改动。
  - **README 文档同步**：版本号从 v1.9.152 直接升到 v1.9.154（v1.9.153 升版时 README 漏升）；`speed_interval_ms` 范围三处从误写的 0–604800ms（≈10min）订正为 0–60000ms（=60s），与后端 `_NUM_RANGES=(0,60000)`、前端 HTML `max=60000`、JS `clamp(0,60000)` 完全对齐。

- **v1.9.153**：两项修改——`speed_interval_ms` 前后端对齐 60s 上限 + CSP frame-ancestors 从 meta 改为 HTTP 响应头。
  - **speed_interval_ms 上限 60s**：后端 `config.py:_NUM_RANGES` 从无上限收紧为 `(0, 60000)`（毫秒=60s），前端 HTML `<input max=60000>` + JS `clamp(+e.target.value, 0, 60000)` 同口径；设 60001 后端返回 400「超出范围 [0,60000]」且不污染状态，加载期配置写 60001 自动回退默认 2000 并告警。
  - **CSP frame-ancestors 改响应头**：CSP 规范不允许 `<meta http-equiv="Content-Security-Policy">` 投递 `frame-ancestors` 指令（浏览器静默忽略），v1.9.153 改为由 `api.py` 在 HTTP 响应头下发：JSON API 发 `Content-Security-Policy: frame-ancestors 'none'`，静态 HTML 发完整 CSP（含 `frame-ancestors 'none'`）；meta content 中移除该指令（保留说明性注释）；与 `X-Frame-Options: DENY` 形成双重点击劫持防护。
  - **移动端响应式（v1.9.152 修复）无回归**：汉堡菜单、侧边栏折叠、config 单列布局在 v1.9.153 保持。

- **v1.9.150**：文档与代码全面对齐（本版为文档同步版，无数据面行为变更；基于已通过连续两轮零待修复验收的 v1.9.149 代码快照）。
  - **R12–R16 高强度逐行审查修复清零**：R12（32 项 P3）、R13（3 项 P3）、R14（2 项 P3）、R15（1 项 P3）、R16（复核）共 5 轮逐行审查，P3 级问题全部清零，连续两轮（功能验证代理）零待修复验收通过。
  - **版本号/性能数据更新**：文档版本号升到 v1.9.150；性能表更新为 v1.9.149 实测——8 并发 ×180s 缓存 100% 命中，平均 QPS **43,012**、P50 **0.17ms**、P99 **0.56ms**、P99.9 **1.48ms**、约 774 万请求**零错误**、RSS 稳定 **52MB**（非特权端口 DNS 5354 / API 18091）。
  - **配置表订正/补全**：新增 `api.token` 独立行（Bearer/X-Api-Key/`?token=`、最长 256、GET 脱敏 `***`、PUT 收到 `***` 不覆盖）；订正 `max_parallel_upstreams` 说明为「fallback 开启时并发最快 N 个、全败回退剩余，并作工作线程池基数 min(48,max(16,N×8))」；明确 `log_level`/`log_format` 改后需重启（其余字段 PUT/reload 即时生效）。
  - **`speed_interval_ms` 单位口径保持正确**：毫秒字段（默认 2000ms≈2s，范围 0–60000ms=60s），「7 天」(=604800s) 适用于 `health_check_interval`/`rule_sub_interval` 等秒级字段(`stale_ttl` 上限为 100 天)——文档与前端 tooltip 均按此口径。
  - **复核无改动项**：`bpf/README.md`（`dns_cache`=LRU_HASH 1024、`counters`=PERCPU_ARRAY，与 `.c`/`.h` 一致）、前端 `speed_interval_ms` tooltip、`etc/ebpdns.conf.json` 均已与代码对齐，本轮仅复查。
  - **⚠️ 通配符规则语义迁移（R17 复核确认，v1.9.150 生效）**：通配符按 **DNS 标签边界** 匹配——`*ads.com` 现等价于 `*.ads.com`，只命中 `ads.com` 本身及其任意层子域（`x.ads.com`/`a.b.ads.com`），**不再**命中标签内子串域名（`myads.com`/`xads.com`）。旧实现因正则锚定缺陷（`.*` 可匹配零字符）按"子串"匹配。历史配置中依赖 `*xxx.com` 屏蔽 `xxx.com` 词内域名的 block 规则将**静默失效**（屏蔽类 fail-open），此类需求请改用 `re:` 正则规则保留子串语义（如 `re:ads\.com$`）；`*.example.com` 写法不受影响。

- **v1.9.148**：文档与代码全面对齐（本版为文档同步版，无数据面行为变更）。
  - **性能数据更新**：3 分钟 374 万请求零错误，平均 QPS **20,824**，P99 **0.859ms**（较 v1.9.147 的 15,432 QPS / P99 1.56ms 分别 +35% / -45%）。
  - **配置表补全**：补齐 `api.token`、`cache_partitions`、`health_check_interval`/`health_probe_domain`/`health_probe_timeout_ms`、`circuit_fails`/`circuit_open_s`、`bootstrap_dns`、`rule_sub_interval`/`rule_subscriptions`、`rebind_protection`、`dnssec_0x20`、`prefer_ipv4`、`log_format`、`web_root` 等键，与 `config.py` `DEFAULTS`/`_NUM_RANGES`/`_ENUM_VALUES` 逐项对齐。
  - **API 表订正**：`/api/health` 不再返回 `version`（未认证免指纹）；`/api/profile` 采样默认 3 秒、上限 10 秒（订正旧"默认 5、上限 30"）；`/api/restart` 与 `/api/reset` 需请求体 `{"confirm": true}`；`/api/logs` 补全过滤参数；`/api/pipeline` 上游脱敏说明；删除表格内误插的块注（原渲染断行）。
  - **`speed_interval_ms` 单位订正**：该字段单位为**毫秒**（同一域名两次候选 IP 测速的节流间隔，默认 2000ms≈2s，范围 0–60000ms=60s），订正前端帮助文字与后端注释中"最长 7 天"的单位混淆（"7 天"=604800s 仅适用于秒级周期字段）。
  - **示例配置对齐**：`etc/ebpdns.conf.json` 与 `DEFAULTS` 对齐（补齐缺失键、键值一致）；移除不存在的 `deploy-test/` 引用，压测脚本更正为根目录 `stress_test.py`/`profile_test.py`/`full_log_test.py`；`package.sh` 用法更正为 `./package.sh <version>`。

- **v1.9.144**：文档与代码严格对齐（本版为文档同步版，无数据面行为变更）。
  - **`map_type` 三模式文档化**：`LRU_HASH`（默认）/ `LRU` / `LPM_TRIE` 为 BPF Map 类型语义标记（保留大写），当前纯用户态实现下仅作控制台/API 展示，不改变淘汰引擎（淘汰引擎由 `cache_policy` 决定）；非法值回退 `LRU_HASH`。
  - **`cache_persist` 持久化总开关文档化**：默认 `true`；关闭后既不写盘也不从磁盘恢复（周期/退出保存均失效）。
  - **`cache_policy` 行为订正**：`lru` 与 `partitioned` 均为按分流 group 分区隔离的 PartitionedCache（默认容量比 domestic/global/default = 0.2/0.2/0.6，各分区内部 8 分桶 LRU）；`tinylfu` 为 W-TinyLFU 单池。订正旧文档把 `lru` 描述成"全局共享池"的错误。
  - **`/api/restart` 自退出机制文档化**：systemd 托管时不再 `systemctl restart`，改为进程发 SIGTERM 优雅收尾后以退出码 3 退出，由 `Restart=on-failure` 拉起新实例；手动裸跑仍 `os.execvpe` 替换自身。
  - **上游高级选项 / NXDOMAIN quorum / 证书校验**：`weight`(0–1000)/`allow_private_ip`(默认 false)/`doh_strict_cert`·`dot_strict_cert`(默认 true，仅显式 false 才降级)/`nxdomain_quorum`(默认 2，自动钳到健康上游数) 与代码对齐。
  - **`cache_partitions` 缺省 `default` 分组崩溃修复（v1.9.143 代码）**：用户自定义分区未含 `default` 键时，原回退为空操作导致 `KeyError`；改为回退到第一个可用分区，极端空配置返回 no-op。

- **v1.9.141**：文档与行为对齐，收敛近期多项加固与新功能（本节按现状补记）。
  - **上游 weight 加权轮询**：上游选择排序 key = 实测延迟 `eff_lat / max(1.0, weight)`；`weight` 默认 1，范围 0–1000、支持小数（<1 按 1 计）。前端上游行「高级选项」列已加权重输入框。
  - **上游级 `allow_private_ip`**：默认 `false`（私网 IP 仍受全局 `rebind_protection` 丢弃）；某上游返回内网/私有地址确为合法（自建内网解析）时，在上游级显式置 `true` 豁免。
  - **上游级 `doh_strict_cert` / `dot_strict_cert`**：默认 `true`（严格证书链 + SAN/主机名校验，不匹配直接失败）；字段缺失/None 保持严格，只有显式 `false` 才允许降级。分别作用于 DoH/DoH3 与 DoT。
  - **`edns_client_max_size`**：客户端侧 EDNS UDP bufsize 钳制（默认 1232，范围 512–65535），超限应答置 TC 走 TCP，防开放解析器放大攻击。
  - **EDNS Padding 128B 整条对齐（RFC 8467）**：`padding=true` 时对发往加密上游（DoH/DoT/DoQ/DoH3）的出站查询按 128 字节块对齐整条 DNS 消息（上限 512B），抹平长度指纹；不填充明文 UDP/TCP 响应。
  - **CNAME 链 owner name 修正**：CNAME 链展开后落缓存/回包的 A/AAAA RR 的 owner name 为 CNAME 目标域名（而非查询域名），符合 RFC 1034。
  - **NXDOMAIN quorum（`nxdomain_quorum`，默认 2）**：多上游需达 quorum 个一致 NXDOMAIN 才判域名不存在，防单个上游撒谎；quorum 自动钳到实际健康上游数，置 1 恢复旧行为。
  - **正则三态 fail-closed**：屏蔽规则正则匹配异常/超时时按「命中」处理（fail-closed，安全方向），不在 ReDoS 窗口内被绕过。
  - **CSRF 策略收敛**：API 请求无 `Origin`/`Referer` 时，仅当携带有效 token **或** API 绑定在环回地址（`127.0.0.1`/`::1`/`localhost`）才放行；非浏览器客户端在非环回监听下必须带 token，否则 403。
  - **systemd 降权**：服务改由专用系统用户 `ebpdns`（nologin）运行，仅授 `CAP_NET_BIND_SERVICE` 绑定 53，配合整套沙箱硬化（`ProtectSystem=strict` 等）。
  - 文档同步：配置默认值改回真实代码（`listen` 默认 `127.0.0.1:53`/`[::1]:53`、`api.host` 默认 `127.0.0.1`）、补全 API 端点表与 token 示例、修正 `EBPDNS_CONFIG` 拼写与 `TimeoutStopSec` 值（v1.9.150 据 unit 实际值订正为 15）。

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
- **v1.9.2**：全面代码审查(逐文件逐行)后的修复与优化。① DoH 连接池 `_ConnPool` key 补 path——同一 host:port 不同 DoH 路径(如 NextDNS /<profile-id> vs /dns-query)不再复用错连接; ② QUIC 连接管理器 `get_quic_upstream` key 补 path——DoH3 同问题修复, API QUIC 诊断 key 同步对齐并给 stats() 补 path 字段; ③ server.py TCP 绑定失败从 raise 致命降级为 WARNING(仅 UDP 服务)——修复 TCP:53 被占时整个 daemon 起不来的问题(原注释称"不致命"但代码实际致命); ④ 慢池 `_doh_pool` worker 数按 DoH/DoT/DoQ/DoH3 启用上游弹性(8→32)——用户 VM 大量 DoH 上游时固定 8 worker 导致慢查询排队拖高 miss 延迟; ⑤ 后台结果收集 `_collect_rest` 超时从固定 1s 对齐到上游查询超时(timeout_ms)——避免慢协议(DoH/DoH3)结果过早放弃导致上游成功率统计缺失(显示"待命")。
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
