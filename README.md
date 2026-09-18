# ebpdns —— SmartDNS 式智能 DNS 解析器（Debian 13 可部署）

请注意！！！所有代码来源于豆包模型，软件已稳定运行，后续几乎不会更新

- 真实监听 `UDP/TCP :53`，真实多上游并发解析（UDP / TCP / DoH / DoT）
- 复刻 SmartDNS 的**测速择优、域名分流、TTL 缓存、预取、IPv4 优先、失败降级**等智能逻辑
- 默认数据面运行在**用户态**：以**用户态 LRU 缓存模拟 BPF LRU_HASH Map**，命中由 daemon 快路径直接回包，**无需内核权限**即可完整运行
- 内置 **HTTP JSON API + Web 控制台**：控制台连上后端即为真实数据（REAL 模式），后端不可达时自动降级为浏览器内仿真（SIM 模式）
- 可选 **eBPF XDP 内核旁路**（`bpf/`）：`bpf/` 目录为参考实现、当前**未集成**到 daemon 运行路径，默认部署即为上方用户态路径
- 纯 Python 标准库、零第三方依赖；systemd 一键托管；支持 systemd 崩溃自动重启（`Restart=on-failure`）


- **六协议上游**：UDP/TCP/DoH/DoT/DoQ/DoH3，连接复用 + 熔断
- **智能解析**：测速择优、域名分流、TTL 管控、预取、负缓存、双栈智能
- **零依赖**：纯 Python 标准库，systemd 一键部署
- **Web 控制台**：实时遥测、查询控制台、配置管理、分流规则
- **高性能**：缓存命中 p50 0.1ms，QPS 5.8 万，10 分钟 3500 万查询 0 错误
- **稳定**：崩溃自动重启、缓存持久化跨重启恢复、上游熔断降级

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
- DoH/DoT 上游使用 hostname 时依赖系统 DNS 解析 ~~（v1.9.42 已通过 Bootstrap 解析器解决：启动时用 UDP 上游预解析 hostname 为 IP，后续连接用 IP+SNI，不再依赖系统 DNS）~~
- 真实 XDP 内核直答需内核与网卡支持，属预留/进阶选项（`bpf/` 参考实现未集成到 daemon）
- 未实现 DNSSEC 验证（转发型解析器典型取舍）

---

