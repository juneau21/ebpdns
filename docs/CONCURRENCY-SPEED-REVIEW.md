# ebpdns 解析引擎：并发查询 与 结果 IP 测速优选 —— 实现审查

> 代码基线：`ebpdns-2.1.49`（crates/ebpdns-resolver 为主）
> 线上实测：192.168.0.236（本包二进制），2026-11-02
> 行号均指 `crates/ebpdns-resolver/src/` 下文件

---

## 一、总览：一次查询经过什么

```
客户端 :53
   │  dns.rs（数据面：EDNS/0x20/padding、TCP/UDP、超时预算）
   ▼
Resolver::resolve()                        resolve.rs
   │
   ├─ ① 缓存快路径  get()/peek()  ──命中──▶ 直接应答（TTL 递减）
   │     └ 过期但 stale 窗口内 → serve-stale（后台刷新）
   ├─ ② 规则引擎（block / forceIp / group / prefer_ipv4 / ipv6）
   ├─ ③ 上游选择  select_upstreams()          lib.rs:1454
   │     rating = (实测p90 × 成功率惩罚 × 慢惩罚) / max(1,weight)，5s 排序缓存
   │     熔断 open 的跳过；全 open 时兜底放行全部
   ├─ ④ 并发扇出  query_parallel_code()       production.rs:758
   │     首发 1 个 → 对冲(hedge) → 首正即返回 / 负票 quorum
   │     （同 key 并发 miss 先被 singleflight 合并）
   ├─ ⑤ 答案归并（保序去重、TTL 取 min、rebind 私网过滤）
   ├─ ⑥ **IP 测速优选**  speed_sort()          lib.rs:1664
   ├─ ⑦ 回填缓存 fill_cache_capped()          lib.rs:2043（存的是重排后的顺序）
   └─ ⑧ 失败路径：fallback 波 / F-NX 补查 / SERVFAIL
```

---

## 二、并发查询是怎么并发的（4 个并发点）

### 1) 单飞：同 key 只发一次上游扇出 — `singleflight.rs`

- 每个 `CacheKey+mode` 一个 `tokio::sync::OnceCell`；第一个到达者执行 `f()`，
  其余 `await` 同一个 cell，**不重复打上游**。
- 发起者被取消（future drop/abort）：`OnceCell` 丢弃未完成初始化，下一个等待者接手重跑，
  等待者不会挂死、也拿不到半截结果。
- `RefGuard` 引用计数归零时摘表 ⇒ 表**不会无界增长**。
- 只合并"最贵的纯幂等段"（上游扇出结果），`finish_resolve` 之后的负缓存/serve-stale/
  规则复查仍逐调用方执行。

### 2) 上游扇出：首发 1 个 + 对冲 + 首正即返回 — `production.rs:758`

```
selected = enabled − 重复id − 熔断open        （全 open → 兜底放行全部）
首发 selected[0]
hedge 时刻 = max(各候选实测 p90) × hedge_slowest_factor(默认1.0)
            夹到 [1ms, timeout_ms]；一个样本都没有 → hedge_after_ms(200ms)
循环 select!:
  ├─ 收到正向答案(NOERROR+有答案+未截断) → 立即返回，abort 其余（省时省连接）
  ├─ 收到负票(NXDOMAIN/NODATA):
  │     negative_votes < quorum(默认2) → **立即把剩余候选全部发出**，继续等
  │     negative_votes ≥ quorum        → abort 其余，返回负结果
  ├─ hedge 计时到 → 追加剩余候选
  └─ 全部答完 → 返回已有结果（resolve 侧按候选数判定可信度）
```

要点：
- **正向** 走"最快者赢"（延迟优先）；**负向** 走"投票确认"（正确性优先），
  避免单台上游抖动就写 NXDOMAIN 并触发 RFC 8020 子树放大。
- **未知 qtype 透传**：任何有效 DNS 响应（任意 rcode）即返回，原字节透传。
- `JoinSet`：单个上游任务 panic/取消不影响其余。
- 每上游**自适应超时**：`clamp(max(p90×8, p90×1.2), min_ms, timeout_ms)`；
  连续 3 次超时 → 丢弃 p90 滑窗、回退 `timeout_ms`（`record_result` / `timeout_for`）。

### 3) 波次并发：primary → fallback → F-NX — `resolve.rs`（fetch 段）

`fallback=true`（默认）时先打最快 `max_parallel_upstreams`(3) 个，其余作备份；
首选全灭或负票不足 quorum 时再发备份波。`fallback=false` 只打最快 1 个，失败即 SERVFAIL。

### 4) 在途闸门

`upstream_max_inflight`(默认 32) + 自适应 p90 收敛（慢上游 → 整体降 cap），
避免"越慢越好冲"的正反馈。

---

## 三、结果 IP 测速优选（`speed_sort`，lib.rs:1664）

### 触发条件

```
speed_test && ip_speed_check && 候选IP数 > 1 && 本次是 miss 路径
（规则命中 / 缓存命中 / serve-stale 不走这里）
```

线上生效值：`speed_test=true, ip_speed_check=true, ip_speed_probe=both,
speed_timeout_ms=300, ip_speed_cache_ttl=60, speed_interval_ms=2000`。

### 算法（5 步）

1. **节流**：同域名在 `speed_interval_ms`(2s) 内再次 miss → **直接返回原序**（不重排）。
   节流表 `last_speed_test` 上界 4096，超 1h 记录整体回收。
2. **取窗口**：只对**前 8 个候选**（`SPEED_SORT_WINDOW`）打分，第 9 个起保持原序。
3. **每个候选的延迟值**（优先级从高到低）：
   - `ip_speed` 表里**新鲜**样本（探测时间 < `ip_speed_cache_ttl`=60s）→ 用 EWMA；
   - 否则用**静态兜底**：贡献该答案的上游本次应答延迟（缺省 999ms），
     并把它 `setdefault` 写进 `ip_speed` 表，同时**提交一次后台探测**。
4. **权重**：`w = 1 / (measured_ms + 10)`（越快权重越大）。
5. **加权随机不放回抽样**（`weighted_sample_order`）决定前 8 的顺序；抽完再拼回第 9+。

### 后台探测（不阻塞查询）

```
submit_ip_probe → ProbePool::try_submit（Semaphore 8 并发，**满即丢**）
   ↓ tokio::spawn
probe_candidate_ip_once(ip, mode):
   udp53  : 向 ip:53 发一条 A 查询（固定 health_probe_domain），校验源 IP/端口/qid，
            成功返回 max(1, RTT ms)                       （lib.rs:1833）
   tcp443 : TcpStream::connect(ip:443) 的握手 RTT          （lib.rs:1642）
   both   : 两者都测，取 min                                （lib.rs:1795）
   ↓
record_ip_speed: EWMA = 0.7×旧 + 0.3×新；旧样本 >3600s 直接取新值
                 表上界 65536，超限按探测时间驱逐到 3/4 水位线
```

### 语义要点（容易被误解的地方）

- **"优选"是概率性的，不是确定性排序**：最快 IP 只是**最可能**排第一。
  同一域名 TTL(300s) 过期后重新解析会重新抽签 ⇒ 首选 IP 可能变化，这是设计行为。
- **冷启动第一轮按"上游快慢"而不是"IP 快慢"排序**：没有实测样本时用的是
  `static_lat`（贡献该答案的上游应答延迟），探测结果要等 60s 缓存过期后的下一次 miss 才生效。
- **探测目标是固定域名**（`health_probe_domain`，默认 www.baidu.com）：
  `udp53` 测的是"到该 IP 的 53 端口 + 该域名"的可用性，不必然代表目标站点的真实可达性；
  `tcp443` 只测握手，不代表 TLS/HTTP 可用。
- 全部 fail-safe：非有限值不写表、探测失败不写、无 tokio runtime 静默跳过。

### 现场实测（236）

| 域名 | 结果 |
|---|---|
| www.douban.com（miss，3 个 A） | trace：`测速择优(EWMA+加权随机): 首选 120.53.130.158`，answers[0] 同值 |
| www.pconline.com.cn（miss，5 个 A） | 首选 106.227.26.33，answers[0] 同值 |
| www.icloud.com（miss，2 个 A） | 首选 17.253.87.206 |
| www.apple.com（miss，8 个 A） | 首选 117.40.89.52 |

---

## 四、审查发现

### 发现 1（P3，**已修复** FIX-CHOSEN-PARITY）：`chosen` 字段在 miss / 命中 两条路径语义不同

| 路径 | chosen 的取值 | 实测 |
|---|---|---|
| **miss（首次解析）** | `cand_list.first()` = 测速优选后的第一个 = `answers[0]` | www.douban.com：chosen=120.53.130.158=answers[0] |
| **cache hit / serve-stale** | `entry.chosen`，而它在 `fill_cache_capped` 里是 **反向扫描首个 A/AAAA ⇒ 最后一个 A** | www.akamai.com(hit)：chosen=23.199.232.205，answers=[23.199.232.208, 23.199.232.205] |

代码：`lib.rs:2088-2094`（fill 时 `answers.iter().rev().find(rtype∈{1,28})`）
vs `resolve.rs:2016`（miss 时 `cand_list.first()`）；命中路径原样回填 `entry.chosen`
（`resolve.rs:948`、`resolve.rs:1099`）。

**影响**：控制台「解析值 IP」、`/api/query.chosen`、`record_manual` 遥测在"首次查询"
与"后续命中"之间显示**不同 IP**；数据面应答顺序不受影响（客户端拿到的第一条仍是优选 IP）。

**修复（已实施）**：`fill_cache_capped` 改为**正序**取首个 A/AAAA：

```rust
// lib.rs（2.1.50 / FIX-CHOSEN-PARITY）
let chosen = answers
    .iter()
    .find(|a| a.rtype == 1 || a.rtype == 28)   // 原来是 .rev().find()
    .map(|a| a.value.clone())
    .unwrap_or_else(|| answers.first().map(|a| a.value.clone()).unwrap_or_default());
```

CNAME 链（先 CNAME 后 A）下首个 A 仍是链尾目标，语义不变；多条 A 时与 miss 路径的
`cand_list.first()` 一致。

**回归测试**（`crates/ebpdns-resolver/tests/followup_tests.rs`）：
- `fill_cache_chosen_is_first_a_record`：3 条 A → chosen = 第 1 条（旧实现是第 3 条）；
- `fill_cache_chosen_is_chain_tail_a_after_cname`：CNAME + 2 条 A → chosen = 首个 A。

**现场验证（236，重启后冷缓存）**：

| 域名 | miss 的 chosen | 随后 hit 的 chosen | answers[0] | 结果 |
|---|---|---|---|---|
| www.bing.com | 202.89.233.101 | 202.89.233.101 | 202.89.233.101 | 一致 |
| www.sogou.com | 114.222.112.92 | 114.222.112.92 | 114.222.112.92 | 一致 |
| www.zhihu.com | 106.225.239.65 | 106.225.239.65 | 106.225.239.65 | 一致 |
| www.douban.com | 81.70.124.99 | 81.70.124.99 | 81.70.124.99 | 一致 |

> 修复前同一域名：miss=answers[0]（优选 IP），hit=answers[-1]（末条 A），例：
> douban miss=120.53.130.158 / hit=81.70.124.99。

### 发现 2（P4，设计取舍）：2s 节流 + 概率抽样 ⇒ 首选 IP 非确定

同域名 2s 内重复解析不重排；TTL 到期重解析会重新抽签。若期望"每次都是同一个最快 IP"，
需要把 `speed_interval_ms` 调大（缓存排序更久）或改用确定性 `speed_choose`（当前仅供管理面/测试）。

### 发现 3（P4，冷启动偏差）：首轮权重来自上游 RTT 而非 IP RTT

见上文"语义要点"第 2 条。首轮"优选"实质是"哪个上游先答就排前面"。

### 发现 4（观察项）：探测使用的固定域名可能不代表真实业务

见"语义要点"第 3 条；如需更贴近业务，可把 `health_probe_domain` 设为自有域（被探测 IP 需能应答）。

---

## 五、参数速查（线上 236 取值）

| 键 | 值 | 作用 |
|---|---|---|
| `speed_test` | true | 总开关（关 ⇒ 不重排） |
| `ip_speed_check` | true | 是否按 IP 实测重排（与上者同时为真才生效） |
| `ip_speed_probe` | both | udp53 / tcp443 / both(min) |
| `speed_timeout_ms` | 300 | 单次探测超时 |
| `ip_speed_cache_ttl` | 60 | EWMA 样本有效期 |
| `speed_interval_ms` | 2000 | 同域名重排节流 |
| `max_parallel_upstreams` | 3 | fallback 首选波并发数 |
| `hedge_after_ms` / `hedge_slowest_factor` | 200 / 1.0 | 对冲时刻（无样本时用前者，有 p90 时用后者） |
| `adaptive_timeout` / `adaptive_timeout_k` / `_min_ms` | true / 8.0 / 1500 | 每上游自适应超时 |
| `timeout_ms` | 1500 | 单次上游硬超时 |
| `nxdomain_quorum` | 2 | 负票确认数 |
| `fallback` | true | 首选波失败是否回退备份波 |
| `single_flight` | true | 同 key 并发合并 |

---

## 六、如何自己验证

```bash
# 1) 看一次解析的完整决策链（含"测速择优"事件）
curl -s -X POST http://127.0.0.1:8353/api/query -H 'Content-Type: application/json' \
  -d '{"domain":"www.douban.com","qtype":"A"}' | python3 -m json.tool | grep -A2 trace

# 2) 看客户端实际拿到的顺序（第一个就是优选 IP）
dig +short @127.0.0.1 www.douban.com A
```


---

## 七、本轮复测（修复后）

| 项目 | 结果 |
|---|---|
| `cargo test -p ebpdns-resolver` | **全绿**（含新增 2 项 chosen 回归） |
| `cargo test --workspace` | 见《代码审查报告》最新一版（含本修复） |
| 现场 chosen 一致性 | 4/4 域名 miss == hit == answers[0] |
| 并发压测（40 线程 × 25 查询 = 1000） | **1000/1000 成功，0 超时 0 错误，1757 qps**，无 panic |
| 混合压测（30s，热点/唯一/重复名） | 372/372 应答，rcodes {NOERROR:201, NXDOMAIN:171}，0 超时 |
| 物理/逻辑放大 | miss=457 → upstream_requests=1146 ≈ **2.5×**（quorum=2 + fallback 波，符合设计） |
