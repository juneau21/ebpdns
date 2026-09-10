# ebpdns —— SmartDNS 式智能 DNS 解析器（Debian 13 可部署）

把「ebpdns · eBPF 版 SmartDNS 解析器控制台」从浏览器内仿真升级为**真实可部署的 DNS 解析软件**。

- 真实监听 `UDP/TCP :53`，真实多上游并发解析（UDP / TCP / DoH / DoT）
- 复刻 SmartDNS 的**测速择优、域名分流、TTL 缓存、预取、IPv4 优先、失败降级**等智能逻辑
- 默认数据面运行在**用户态**：以**用户态 LRU 缓存模拟 BPF LRU_HASH Map**，命中由 daemon 快路径直接回包，**无需内核权限**即可完整运行
- 内置 **HTTP JSON API + Web 控制台**：控制台连上后端即为真实数据（REAL 模式），后端不可达时自动降级为浏览器内仿真（SIM 模式）
- 可选 **eBPF XDP 内核旁路**（`bpf/`）：`bpf/` 目录为参考实现、当前**未集成**到 daemon 运行路径，默认部署即为上方用户态路径
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
| 上游协议 | UDP / TCP / DoH (HTTPS) / DoT (TLS) |
| 管理接口 | HTTP JSON API + Web 控制台（内置 ECharts，本地化无外网依赖） |
| 可选内核数据面 | C + libbpf (XDP)，`bpf/` 目录参考实现（预留接口，未集成） |

**数据面说明**：默认所有解析与缓存均在用户态完成——缓存命中由 daemon 主线程直接回包（不查询上游），语义上等价于 SmartDNS 的内存缓存，并计入「内核直答」遥测计数；`bpf/` 目录提供真实 XDP 内核旁路的参考 C 源码，仅在需要把命中下沉到网卡内核直答时另行集成（见 §9）。

---

## 2. 快速部署（Debian 13）

```bash
# 1. 准备（Python 3 已内置；仅当要编译真实 XDP 数据面才装编译工具）
sudo apt update && sudo apt install -y python3 python3-pip
#    （可选）启用 DoQ / DoH3（DNS over QUIC / HTTP3）上游时需要 aioquic
sudo pip3 install aioquic
# 2. 安装（拷贝到 /opt/ebpdns、生成 /etc/ebpdns/config.json、注册 systemd）
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
sudo cp systemd/ebpdns.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now ebpdns
```

### 卸载

```bash
sudo systemctl stop ebpdns && sudo systemctl disable ebpdns
sudo rm -f /etc/systemd/system/ebpdns.service && sudo systemctl daemon-reload
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

| 键 | 默认 | 说明 |
|---|---|---|
| `listen.udp` / `listen.tcp` | `0.0.0.0:53` | DNS 监听地址 |
| `api.host` / `api.port` | `127.0.0.1` / `8080` | API 与控制台监听（install.sh 模板为 `0.0.0.0:8080`） |
| `cache_size` | 1024 | 用户态 LRU 容量（模拟 BPF Map 容量，上限 131072，配置值越界会被 API 拒绝） |
| `ttl` | 300 | 缓存默认 TTL（秒），实际取上游返回 TTL 与它的较小值 |
| `ttl_min` / `ttl_max` | 0 / 0 | 下发 TTL 管控：内网客户端应答 TTL 钳制到该区间（0=不限制），同时作为缓存存活时长 |
| `serve_stale` / `stale_ttl` | false / 3600 | 过期缓存兜底：缓存过期后在窗口内仍返回旧数据（下发 TTL=0）并后台强制刷新，避免上游抖动时 SERVFAIL |
| `persist_ttl` | 0 | 持久化缓存恢复后的独立 TTL（秒）；0=按保存时剩余 TTL 原样恢复（重启间隙不消耗缓存寿命） |
| `prefetch` | true | TTL 到期前 85% 自动预取刷新（跳过 NXDOMAIN 负缓存；恢复缓存自动重排入预取队列） |
| `kernel_direct` | true | 用户态缓存命中即计为「内核直答」遥测计数（真实 XDP 集成时保持 true 语义一致） |
| `speed_test` / `speed_interval_ms` | true / 2000 | 上游测速择优；两次主动探测最小间隔 |
| `ip_speed_check` | true | 候选 IP 测速：对多 IP 答案并发探测 RTT 并按速度排序（SmartDNS 风格），关=保持上游返回顺序 |
| `ip_speed_probe` | both | 候选 IP 探测方式：`udp53` / `tcp443` / `both`（默认 both，取最快；TCP:443 更贴近真实访问） |
| `ip_speed_cache_ttl` | 60 | 候选 IP 测速结果缓存（秒），命中直接复用避免重复探测 |
| `speed_timeout_ms` | 300 | 测速探测超时上限（毫秒），未按时完成的候选 IP 不参与排序 |
| `fallback` | true | 上游失败自动降级到其余上游（关=仅用首选，失败即 SERVFAIL） |
| `ipv4_first` | true | 同时存在 A / AAAA 时优先 A；AAAA 无记录时回退查 A（`ipv4_fallback` 计数） |
| `ipv6` | true | 关闭后 AAAA 查询直接返回空应答（全局一刀切） |
| `prefer_ipv4` | false | 双栈智能：仅当域名存在 A 记录（双栈）才屏蔽 AAAA 返回 NODATA，纯 IPv6 域名（无 A）正常解析——替代全局 `ipv6` 开关的精细化方案，不误伤 v6-only 域名。A 探测先查缓存快判，无缓存才查上游（仅首次 AAAA 查询多一次上游往返），结果回填 A 缓存 |
| `edns` / `edns_client_subnet` | true / null | 携带 EDNS0 OPT；可填 `203.0.113.0/24` 启用 ECS |
| `edns_udp_size` | 1232 | 出站查询 EDNS0 UDP payload（字节）。1232=IPv6 最小 MTU 1280 减 IPv6 头 40 + UDP 头 8 的最大不分片安全值——大应答 UDP 分片穿越 NAT/防火墙/PPPoE 时经常被丢弃导致解析超时，钳制到该值保证应答不分片（超限应答置 TC 位由客户端走 TCP 重试） |
| `padding` | false | 加密查询报文填充（RFC 8467）：DoT/DoH/DoH3/DoQ 出站报文 OPT options 段填充到 128B 块（上限 512），抹平报文长度指纹，防流量分析通过长度推断查询内容。明文 UDP/TCP 不填充（只增大报文无收益）。前端开关按协议自动分流，无需手配 |
| `timeout_ms` | 1500 | 单次上游查询超时 |
| `max_parallel_upstreams` | 3 | 单查询并发上游数 |
| `upstreams[]` | 见模板 | `proto`: udp/tcp/doh/dot/doq/doh3；`addr`+`port`；`url`(DoH/DoH3 路径)；`group`: domestic/global；`latency` 基础延迟（首次启动自动实测写回）；`enabled`；`latency_measured` |

> **默认上游**（v1.7.7）：内置 2 个国内 UDP 兜底 + 15 个 DoH 端点（AliDNS/DNSPod 的域名与 IP 直连、Cloudflare/Google/Quad9/NextDNS/OpenDNS/DNS.SB/AdGuard/HiNet）。其中国内 7 项默认启用（首次启动自动实测延迟写回），海外 10 项已写入但默认 `enabled:false`，可在控制台按需启用（海外端点受网络环境限制，走超时/熔断自动降级）。
> **DoQ / DoH3（v1.8.0，可选依赖 aioquic）**：`proto:"doq"`（DNS over QUIC，RFC 9250，默认端口 853）与 `proto:"doh3"`（HTTP/3 DoH，默认端口 443）已内置实现。每个 QUIC 上游维护一条常驻连接（断线自动重连 + 查询失败主动重建），多查询在同一连接上多路复用；未安装 aioquic 时相应上游返回「aioquic 未安装」错误，不影响 UDP/TCP/DoH/DoT 路径。安装：`sudo pip3 install aioquic`（Debian 13 用户级安装 `pip3 install --user aioquic`）。`server-http3` 端点可直接配置为 `proto:"doh3"`。
| `rules[]` | 见模板 | `match`: 精确域名或 `*.example.com` 通配；`action`: group/forceIp/block；规则按哈希索引匹配（10 万条级 O(1)）。规则可带 `ttl_min`/`ttl_max`（规则级 TTL）：命中规则时**整体替换**全局 TTL 区间（未显式设置的边界按 0=不限制），用于 CDN/动态域名保持短 TTL 及时更新、稳定域名拉长 TTL 提升命中率。逐条规则在控制台规则行直接填写，留空继承全局 |
| `cache_file` | `/etc/ebpdns/cache.json` | 缓存持久化落盘路径（每 60s 自动保存 + 退出时保存，重启自动恢复） |
| `log_level` | info | 日志级别 |

配置可在**控制台「配置」页**在线编辑并「应用配置」持久化到后端；除 `cache_size` 外全部即时生效（PUT /api/config 后无需重启）。`hook` / `map_type` / `percpu` 为 eBPF 数据面预留语义标记（真实 XDP 未集成）。

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
| GET | `/api/status` | 运行状态、QPS、命中率、延迟、计数器、LRU Map 占用 |
| GET | `/api/snapshot` | 完整快照：历史序列、日志事件、上游健康、手动查询记录 |
| POST | `/api/query` | `{domain, qtype}` 手动解析，返回完整 trace |
| GET/PUT | `/api/config` | 读写配置（PUT 全量持久化，`cache_size` 越界返回 400） |
| GET/POST | `/api/upstreams` | 上游列表 / 新增 |
| PUT/DELETE | `/api/upstreams/<id>` | 修改 / 删除上游 |
| GET/POST | `/api/rules` | 分流规则列表 / 新增 |
| PUT/DELETE | `/api/rules/<id>` | 修改 / 删除规则 |
| POST | `/api/rules/import` | `{url}` 或 `{text}` 批量导入域名列表（URL 实时下载，支持 anti-ad 等规则源） |
| POST | `/api/reprobe` | 一键重新测速：对所有启用上游并发实测延迟并写回配置 |
| POST | `/api/restart` | 重启服务（systemd 托管用 `systemctl restart`；手动运行时 `os.execv` 重启自身） |
| POST | `/api/reset` | 重置遥测计数与缓存 |
| GET | `/api/logs?since=N` | 增量日志 |
| GET | `/api/pipeline` | 流水线站点信息 |
| GET | `/` `/index.html` `/echarts.min.js` | 控制台静态资源 |

---

## 7. 稳定性与运维

- **systemd 托管**：`Restart=on-failure` + `TimeoutStopSec=15`。进程异常退出（含 SIGKILL/OOM 强杀）后约 3s 自动重启，重启后从磁盘载入持久化缓存、恢复分流规则/上游并重新排入预取队列；SIGTERM 优雅退出 1-3s 完成（退出时保存缓存）。
- **优雅退出**：预取线程池 `cancel_futures` 取消积压、DoH/DoT 连接锁加超时、结果收集 `as_completed` 加超时兜底，高负载下 stop 不再卡死。
- **上游熔断**：连续失败达阈值（默认 3 次）临时跳过该上游 30s，防单个故障上游拖垮 miss 查询（配置 `circuit_fails` / `circuit_open_s`）。
- **DoS 防御**：UDP miss 队列有界信号量（池满丢弃、客户端自动重试）；`decode_name` 压缩指针 32 跳上限；应答上限 8 条 + TC 位。

---

## 8. 性能实测（v1.7.5，2 核 / 4GB 类虚拟机）

**缓存命中吞吐**（`deploy-test/bench.py`，同一域名反复查询）：

| 并发 | 吞吐 | p50 | p99 |
|---|---|---|---|
| 1 | ≈41,000 QPS | 0.03ms | 0.04ms |
| 8 | ≈73,000 QPS | 0.10ms | 0.19ms |
| 32 | ≈63,000 QPS | 0.44ms | 2.48ms |
| 64 | ≈34,000 QPS | 1.18ms | 9.37ms |

多域名缓存命中（200 个域名，32 并发）：≈76,000 QPS。错误率 0。

**长时间稳定性**（混合负载：真实命中 + 随机 miss + 10 万规则命中，30 线程 × 5 分钟）：
- 总查询 39,218，**错误 0（0.0000%）**，API 全程可用（无假死），崩溃 0 次
- RSS 稳定 131MB（缓存填满 131072 条后不再增长，无内存泄漏）

**暴力压测**（200 线程纯命中 × 5 分钟）：
- 总查询 **6,125,693**，错误 187（**0.0031%**，UDP socket 压力边界）
- 稳定 ≈20k QPS，RSS 恒定 227MB（无泄漏），无假死

**崩溃自启**：高负载下 SIGKILL → **3.5s 内自动重启**，重启后配置/规则/上游/缓存全部恢复，解析功能正常。

**首次解析（真实 miss）延迟**：受外网上游延迟限制，UDP 上游 ≈6-9ms；多 IP 域名（含测速择优）≈60ms。缓存命中路径 p50 ≈ 0.03-0.6ms。

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
# 单元测试
python3 -m unittest discover -s tests
# 部署自检
python3 deploy-test/errcheck.py     # 错误检查（协议/边界/fuzz/API/并发）
python3 deploy-test/bench.py        # 性能压测（缓存命中吞吐）
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
│   ├── config.py           # 配置加载/保存（原子写入，大规则 compact 序列化）
│   ├── dnsmsg.py           # DNS 报文编解码（应答上限 8 条 + TC 位）
│   ├── cache.py            # 用户态 LRU（模拟 BPF Map；TTL 钳制/serve-stale/持久化）
│   ├── upstream.py         # UDP/TCP/DoH/DoT 上游（连接复用、qid/源校验、熔断）
│   ├── resolver.py         # 解析引擎（分流索引/并发/测速/预取/负缓存/fallback）
│   ├── server.py           # UDP/TCP DNS 服务器（命中快路径）
│   ├── telemetry.py        # 遥测计数与采样（原子计数）
│   └── api.py              # HTTP JSON API + 静态服务
├── web/index.html          # 控制台（双模式，ECharts 本地化）
├── bpf/                    # 可选 eBPF XDP 内核旁路（参考实现，未集成）
├── systemd/ebpdns.service  # systemd 单元（Restart=on-failure, TimeoutStopSec=15）
├── etc/ebpdns.conf.json    # 配置模板
├── install.sh              # 安装脚本
├── deploy-test/            # 部署自检：errcheck.py + bench.py
└── tests/                  # 单元测试
```

---

## 12. 已知限制

- 解析结果为“精简应答”（SmartDNS 风格，只返回目标类型地址并择优），不完整透传 CNAME 链；对大多数客户端无影响
- DoH/DoT 上游使用 hostname 时依赖系统 DNS 解析（daemon 自身即可作为其解析来源，建议保留一个 UDP 上游）
- 真实 XDP 内核直答需内核与网卡支持，属预留/进阶选项（`bpf/` 参考实现未集成到 daemon）
- 未实现 DNSSEC 验证（转发型解析器典型取舍）

---

## 13. 版本历史（要点）

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
