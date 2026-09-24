# ebpdns Web 控制台控件逐项核对报告（v1.9.31）

审查范围：`web/index.html`（3097 行单文件应用）对照 `ebpdns/config.py`（DEFAULTS + 校验）、`ebpdns/api.py`（PUT /api/config 白名单与校验）、`ebpdns/resolver.py` / `upstream.py` / `server.py` / `cache.py`（运行时实际读取）。

审查方式：纯静态代码核对，未修改任何代码。

---

## 一、总体结论

**前端控件与后端配置键的对齐度很高：没有发现真正意义上的"死控件"（前端有输入但后端不认识/不存储）。**
所有静态配置控件都通过 `bindConfigEvents()` 写回 `real.config.<key>`，保存时整对象 `JSON.stringify(real.config)` PUT 给 `/api/config`，后端白名单 `_CFG_WRITABLE_KEYS = DEFAULTS.keys() - {listen,api,web_root}` 全部放行；`renderConfig()` 加载时逐一回填。加载—保存—回显闭环完整。

发现的问题集中在三类：
1. **范围/UI 不一致**（2 处中低危）：上游 latency 输入框 `max=500` 与默认值 5000/JS 范围 0–3600000 矛盾；健康检查周期 HTML spinner 上限与 JS clamp 不一致。
2. **后端可写但前端无入口 / 后端生效但前端不可见**（后端侧能力缺口，非死控件）：上游级 `weight` 是"僵尸配置键"（API 全链路支持并校验，但 resolver 从不读取）；`allow_private_ip` / `doh_strict_cert` / `dot_strict_cert` 已生效但控制台无开关。
3. **纯展示僵尸键**（3 个）：`hook` / `map_type` / `percpu` 只被回显到 pipeline 可视化，运行时从不消费。

---

## 二、前端控件逐项核对表

### A. 全局配置控件（配置页 4 张卡片，36 项）

| # | 控件 ID | 类型 | 所在卡片 | 绑定配置键 | 后端键存在 | 默认值一致 | 范围一致 | 可提交 | 可回显 | 后端生效 | 联动正确 | 结论 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | cfg-size / cfg-size-r | number+range | 缓存与BPF Map | cache_size | ✅ DEFAULTS:31 | ✅ 131072 | ✅ 1–1e7 / step16 = 后端(1,1e7) | ✅ | ✅ L1892 | ✅ resolver.py:389 | — | 正常 |
| 2 | cfg-ttl / cfg-ttl-r | number+range | 缓存与BPF Map | ttl | ✅ :41 | ✅ 300 | ✅ 前端0–86400 ⊂ 后端(0,∞) | ✅ | ✅ L1893 | ✅ 66处 | — | 正常 |
| 3 | cfg-prefetch | checkbox | 缓存与BPF Map | prefetch | ✅ :47 | ✅ True | ✅ bool | ✅ | ✅ L1894 | ✅ resolver.py | — | 正常 |
| 4 | cfg-kdirect | checkbox | 缓存与BPF Map | kernel_direct | ✅ :48 | ✅ True | ✅ bool | ✅ | ✅ L1894 | ✅ 14处 | — | 正常 |
| 5 | cfg-ttlmin | number | 缓存与BPF Map | ttl_min | ✅ :42 | ✅ 0(placeholder) | ✅ 前端0–86400 ⊂ 后端(0,∞) | ✅ | ✅ L1895 | ✅ 12处 | — | 正常 |
| 6 | cfg-ttlmax | number | 缓存与BPF Map | ttl_max | ✅ :43 | ✅ 0(placeholder) | ✅ 前端0–86400 ⊂ 后端(0,∞) | ✅ | ✅ L1895 | ✅ 10处 | — | 正常 |
| 7 | cfg-stale | checkbox | 缓存与BPF Map | serve_stale | ✅ :44 | ✅ False | ✅ bool | ✅ | ✅ L1896 | ✅ 6处 | — | 正常 |
| 8 | cfg-stalettl | number | 缓存与BPF Map | stale_ttl | ✅ :45 | ✅ 3600 | ✅ 前端0–86400 ⊂ 后端(0,∞) | ✅ | ✅ L1896 | ✅ 7处 | — | 正常 |
| 9 | cfg-persistttl | number | 缓存与BPF Map | persist_ttl | ✅ :46 | ✅ 0(placeholder) | ✅ 0–31536000 = 后端(0,31536000) | ✅ | ✅ L1897 | ✅ 15处 | — | 正常 |
| 10 | cfg-speed | checkbox | 测速与优选 | speed_test | ✅ :49 | ✅ True | ✅ bool | ✅ | ✅ L1898 | ✅ resolver.py:1062 | — | 正常 |
| 11 | cfg-spint | number | 测速与优选 | speed_interval_ms | ✅ :50 | ✅ 2000 | ✅ 前端0–60000 ⊂ 后端(0,604800) | ✅ | ✅ L1898 | ✅ resolver.py:1899 | — | 正常 |
| 12 | cfg-fallback | checkbox | 测速与优选 | fallback | ✅ :55 | ✅ True | ✅ bool | ✅ | ✅ L1899 | ✅ 9处 | — | 正常 |
| 13 | cfg-maxup | number | 测速与优选 | max_parallel_upstreams | ✅ :71 | ✅ 3 | ✅ 1–16 = 后端(1,16) | ✅ | ✅ L1899 | ✅ resolver.py:482,812 | — | 正常 |
| 14 | cfg-timeout | number | 测速与优选 | timeout_ms | ✅ :70 | ✅ 1500 | ✅ 1–60000 = 后端(1,60000) | ✅ | ✅ L1902 | ✅ 54处 | — | 正常 |
| 15 | cfg-speedtimeout | number | 测速与优选 | speed_timeout_ms | ✅ :51 | ✅ 300 | ✅ 1–60000 = 后端(1,60000) | ✅ | ✅ L1909 | ✅ resolver.py:1935 | — | 正常 |
| 16 | cfg-ipsprobe | select | 测速与优选 | ip_speed_probe | ✅ :53 | ✅ both | ✅ 枚举 udp53/tcp443/both = _ENUM_VALUES | ✅ | ✅ L1910 | ✅ resolver.py:1935 | — | 正常 |
| 17 | cfg-ipscachettl | number | 测速与优选 | ip_speed_cache_ttl | ✅ :54 | ✅ 60 | ✅ 0–86400 = 后端(0,86400) | ✅ | ✅ L1911 | ✅ resolver.py:76 | — | 正常 |
| 18 | cfg-v4first | checkbox | 测速与优选 | ipv4_first | ✅ :56 | ✅ True | ✅ bool | ✅ | ✅ L1899 | ✅ 3处 | — | 正常 |
| 19 | cfg-v6 | checkbox | 测速与优选 | ipv6 | ✅ :57 | ✅ True | ✅ bool | ✅ | ✅ L1900 | ✅ 4处 | — | 正常 |
| 20 | cfg-v4smart | checkbox | 测速与优选 | prefer_ipv4 | ✅ :58 | ✅ False | ✅ bool | ✅ | ✅ L1900 | ✅ 5处 | — | 正常 |
| 21 | cfg-ednssize | number | 测速与优选 | edns_udp_size | ✅ :60 | ✅ 1232(placeholder) | ✅ 512–9000 = 后端(512,9000) | ✅ | ✅ L1901 | ✅ 4处 | — | 正常 |
| 22 | cfg-padding | checkbox | 测速与优选 | padding | ✅ :62 | ✅ False | ✅ bool | ✅ | ✅ L1901 | ✅ 8处 | — | 正常 |
| 23 | cfg-rebind | checkbox | 测速与优选 | rebind_protection | ✅ :63 | ✅ True(!==false) | ✅ bool | ✅ | ✅ L1901 | ✅ 7处 | — | 正常 |
| 24 | cfg-edns | checkbox | 高级选项 | edns | ✅ :59 | ✅ True(!==false) | ✅ bool | ✅ | ✅ L1904 | ✅ 8处 | — | 正常 |
| 25 | cfg-dnssec0x20 | checkbox | 高级选项 | dnssec_0x20 | ✅ :68 | ✅ True | ✅ bool | ✅ | ✅ L1904 | ✅ resolver.py | — | 正常 |
| 26 | cfg-ipspeedcheck | checkbox | 高级选项 | ip_speed_check | ✅ :52 | ✅ True | ✅ bool | ✅ | ✅ L1905 | ✅ resolver.py:1894 | — | 正常 |
| 27 | cfg-healthint | number | 高级选项 | health_check_interval | ✅ :34 | ✅ 30 | ⚠️ HTML max=3600 但 JS clamp=86400，后端(0,604800) | ✅ | ✅ L1906 | ✅ resolver.py:2487 | — | **范围不一致(低)** |
| 28 | cfg-rulesubint | number | 高级选项 | rule_sub_interval | ✅ :40 | ✅ 3600 | ⚠️ HTML/JS max=86400 < 后端上限604800 | ✅ | ✅ L1907 | ✅ resolver.py:2488 | — | **UI上限偏紧(低)** |
| 29 | cfg-bootstrapdns | text | 高级选项 | bootstrap_dns | ✅ :39 | ✅ 223.5.5.5:53 | ✅ host:port 校验 config.py:504 | ✅ | ✅ L1908 | ✅ 10处 | — | 正常 |
| 30 | cfg-circfails | number | 高级选项 | circuit_fails | ✅ :37 | ✅ 3 | ✅ 1–100 = 后端(1,100) | ✅ | ✅ L1912 | ✅ 3处 | — | 正常 |
| 31 | cfg-circopens | number | 高级选项 | circuit_open_s | ✅ :38 | ✅ 30 | ✅ 1–86400 = 后端(1,86400) | ✅ | ✅ L1913 | ✅ 3处 | — | 正常 |
| 32 | cfg-healthdomain | text | 高级选项 | health_probe_domain | ✅ :35 | ✅ www.baidu.com | ✅ ≤253 可打印串 config.py:515 | ✅ | ✅ L1914 | ✅ 2处 | — | 正常 |
| 33 | cfg-healthtimeout | number | 高级选项 | health_probe_timeout_ms | ✅ :36 | ✅ 2000 | ✅ 100–60000 = 后端(100,60000) | ✅ | ✅ L1915 | ✅ 2处 | — | 正常 |
| 34 | cfg-loglevel | select | 高级选项 | log_level | ✅ :72 | ✅ info | ✅ 4 枚举 = _ENUM_VALUES | ✅ | ✅ L1916 | ✅ cli.py:408 | — | 正常 |
| 35 | cfg-logformat | select | 高级选项 | log_format | ✅ :69 | ✅ text | ✅ text/json = _ENUM_VALUES | ✅ | ✅ L1917 | ✅ cli.py:408 | — | 正常 |
| 36 | cfg-cache-policy | select | 底部栏 | cache_policy | ✅ :32 | ✅ lru | ✅ lru/partitioned/tinylfu = _ENUM_VALUES | ✅ | ✅ L1903 | ✅ resolver.py:2370 | — | 正常 |

### B. 上游行内控件（renderUpstreams 动态渲染，每行 7 个字段）

| # | data-f | 类型 | 配置键路径 | 后端键存在 | 默认值一致 | 范围一致 | 可提交 | 可回显 | 后端生效 | 联动正确 | 结论 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 37 | enabled | checkbox | upstreams[].enabled | ✅ | ✅ True | ✅ bool | ✅ 白名单:2097 | ✅ | ✅ resolver 选上游 | — | 正常 |
| 38 | name | text | upstreams[].name | ✅ | ✅ | ✅ ≤256 api.py:124 | ✅ | ✅ | ✅ 遥测/展示 | — | 正常 |
| 39 | proto | select | upstreams[].proto | ✅ | ✅ | ✅ 6 枚举 _ALLOWED_UPSTREAM_PROTO | ✅ | ✅ | ✅ 连接池分流 | ✅ 切协议联动默认端口 L2337 | 正常 |
| 40 | fulladdr | text | upstreams[].addr+.url（解析拆写） | ✅ | ✅ | ✅ parseUpstreamAddr 校验 | ✅ | ✅ | ✅ upstream 连接 | ✅ 解析后同步 proto/port 下拉 L2312 | 正常 |
| 41 | port | select | upstreams[].port | ✅ | ✅ | ✅ 1–65535 | ✅ | ✅ | ✅ | — | 正常 |
| 42 | group | select | upstreams[].group | ✅ | ✅ domestic | ✅ str | ✅ | ✅ | ✅ 缓存分区分流 | — | 正常 |
| 43 | latency | number | upstreams[].latency | ✅ | ✅ 5000 | ⚠️ **HTML max=500 但默认值=5000，JS clamp=0–3600000 = 后端(0,3600000)** | ✅ | ✅ | ✅ probe.py | — | **范围不一致(中)** |

### C. 上游"添加行"控件（静态）

| # | 控件 ID | 类型 | 用途 | 提交端点 | 结论 |
|---|---|---|---|---|---|
| 44 | up-add-addr | text | 完整地址自动解析 | POST /api/upstreams（推入 real.config 后随 PUT 落盘） | 正常 |
| 45 | up-add-proto | select | auto/udp/tcp/doh/dot/doq/doh3 | 同上 | 正常 |
| 46 | up-add-group | select | domestic/global | 同上 | 正常 |

### D. 逐条规则行内控件（renderRules 动态渲染，每行 6 个字段）

| # | data-r | 类型 | 配置键路径 | 后端键存在 | 范围一致 | 可提交 | 可回显 | 后端生效 | 联动正确 | 结论 |
|---|---|---|---|---|---|---|---|---|---|---|
| 47 | match | text | rules[].match | ✅ | ✅ ≤4096B api.py:269 | ✅ | ✅ | ✅ 规则索引 | — | 正常 |
| 48 | action | select | rules[].action | ✅ | ✅ 4 枚举 _RULE_ACTIONS | ✅ | ✅ | ✅ | ✅ 切换后 renderRules 重渲染 L2239 | 正常 |
| 49 | group | select | rules[].group（仅 action=group 时渲染） | ✅ | ✅ str | ✅ | ✅ | ✅ | ✅ **条件渲染** L2024 | 正常 |
| 50 | ip | text | rules[].ip（仅 action=forceIp 时渲染） | ✅ | ✅ IP 校验 api.py:235 | ✅ | ✅ | ✅ | ✅ **条件渲染** L2025 | 正常 |
| 51 | ttl_min | number | rules[].ttl_min | ✅ | ✅ 前端0–86400，后端 max(0,∞) | ✅ | ✅ | ✅ | — | 正常 |
| 52 | ttl_max | number | rules[].ttl_max | ✅ | ✅ 同上 | ✅ | ✅ | ✅ | — | 正常 |

### E. 规则订阅 / 导入输入控件（静态）

| # | 控件 ID | 类型 | 用途 | 提交端点 | 联动 | 结论 |
|---|---|---|---|---|---|---|
| 53 | sub-url-input | text | 订阅 URL | POST /api/rules/subscribe | — | 正常（前端强制 https:// L2529） |
| 54 | sub-action | select | block/group/forceIp | 同上 | ✅ group→显示 sub-group；forceIp→显示 sub-ip L2520 | **缺 allow 选项(低)** |
| 55 | sub-group | select(条件) | domestic/global | 同上 | 同上 | 正常 |
| 56 | sub-ip | text(条件) | 强制 IP | 同上 | 同上；isValidIp 校验 L2535 | 正常 |
| 57 | import-input | text | 域名批量导入 | POST /api/rules/import | — | 正常 |
| 58 | import-action | select | group/block/forceIp/allow | 同上 | ✅ L2482 | 正常 |
| 59 | import-group | select(条件) | domestic/global | 同上 | 同上 | 正常 |
| 60 | import-ip | text(条件) | 强制 IP | 同上 | 同上 | 正常 |

### F. 其他控件（非配置项）

| # | 控件 ID | 类型 | 说明 | 结论 |
|---|---|---|---|---|
| 61 | api-token-input | password | 仅存浏览器 localStorage，随 Authorization 头发送；**不写后端 api.token**（注释 L756-758 明确） | 非配置控件，正常 |
| — | q-domain / q-type | text/select | 手动查询页，POST /api/query，不参与配置 | 非配置控件 |
| — | log-search / lc-filter[data-f] | text | 日志页前端筛选，不提交后端 | 非配置控件 |
| — | cfg-cache-file | div(只读) | 展示 real.status.cache_file，非输入 | 只读展示 |

---

## 三、问题清单（按严重度分级）

### 🔴 严重
**无。** 未发现会导致"用户改了不生效"或"前端提交被后端 400 拒绝"的断链/死控件。

### 🟡 中

**M1. 上游 latency 输入框范围自相矛盾（前端误导）**
- 位置：`web/index.html:2004`（渲染模板 `min="1" max="500"`），对比 `:2348`（JS `clamp(+el.value,0,3600000)`），默认值 `config.py:75` `latency:5000`。
- 根因：输入框 HTML 属性 `max=500` 是早期遗留；默认上游 latency=5000，渲染时 `value="5000"` 直接溢出 max=500，浏览器会把该 number 框标记为非法状态。JS change 处理器实际按 0–3600000 收敛（与后端 api.py:116 一致），所以**不会被后端拒绝**，但 spinner 箭头最多只能加到 500，与框里显示的 5000 矛盾，用户改 latency 时体验混乱。
- 修复建议：把模板里的 `max="500"` 改为 `max="3600000"`（或干脆去掉 max 交给 JS clamp），与 `:2348` 及后端对齐。

**M2. 上游级 `weight` 是"僵尸配置键"（后端可写但运行时从不读取）**
- 位置：写入侧 `api.py:105-110`（bulk 校验 0–1000）、`api.py:386-392`（POST 新建透传）、`api.py:2098,2130-2134`（单条 PUT 白名单+校验）；注释 `api.py:2127` 自称"weight 用于加权轮询"。
- 根因：全仓 grep `u.get("weight")` / `["weight"]` 在 resolver.py / upstream.py / server.py **零命中**（唯一的 `weights=rw` 在 resolver.py:1949 是按 RTT 加权选 IP，与上游 weight 无关；dnsmsg.py:404 的 weight 是 SRV 记录字段）。即：用户/API 可以给上游设置 0–1000 的 weight 并落盘，但 resolver 选上游时完全不读它。
- 影响：这是后端侧僵尸键（前端 UI 未提供 weight 输入框，所以不构成"死控件"），但 API 表面承诺了一个不工作的加权能力。
- 修复建议：二选一——(a) 在 resolver 上游选优路径真正读取 `u.get("weight",1)` 做加权；(b) 从 `_UPSTREAM_WHITELIST`、`_validate_upstream_dict`、POST 新建透传中移除 weight，避免假承诺。

### 🟢 低

**L1. 健康检查周期 HTML spinner 上限与 JS clamp 不一致**
- 位置：`web/index.html:656` `max="3600"`（1 小时），`:2292` JS `clamp(...,0,86400)`，后端 `config.py:356` `(0,604800)`。
- 根因：三处上限都不一样。spinner 只能调到 3600，但手动输入 5000 时 JS clamp 放行（≤86400），后端也放行（≤604800）。不构成提交拒绝，但 UI 暗示"最大 1 小时"与实际可填值不符；且若用户手编 config.json 设了 604800，回显到 max=3600 的框里会溢出标记非法。
- 修复建议：把 `max` 改为 `604800`（与后端对齐），JS clamp 同步。

**L2. 规则订阅更新周期 UI 上限(24h)小于后端上限(7 天)**
- 位置：`web/index.html:658` `max="86400"`，`:2293` JS clamp 0–86400，后端 `config.py:366` `(0,604800)`。
- 根因：前端只能配到 24 小时，后端支持 7 天。前端是后端的子集，**不会被拒绝**，但用户无法通过控制台把订阅周期设到 1–7 天。
- 修复建议：`max` 提到 `604800`。

**L3. 订阅动作下拉缺 "allow"(放行)选项**
- 位置：`web/index.html:683-687` sub-action 只有 block/group/forceIp；后端 `config.py:401` `_RULE_SUB_ACTIONS=("allow","block","group","forceIp")`。
- 根因：逐条规则的 import-action（`:705`）有 allow 选项，但订阅下拉漏了。后端允许 allow 订阅，控制台却建不出来。
- 修复建议：在 sub-action 增加 `<option value="allow">放行(白名单)</option>`。

**L4. 上游级 allow_private_ip / doh_strict_cert / dot_strict_cert 后端已生效但控制台无开关**
- 位置：生效侧 `resolver.py:1009,1422,1459`（allow_private_ip）、`upstream.py:1036`（doh_strict_cert）、`upstream.py:1367`（dot_strict_cert）；白名单 `api.py:2097-2104` 已允许写入。
- 根因：`renderUpstreams`（`:1996-2007`）只渲染 enabled/name/proto/fulladdr/port/group/latency 七个字段，没有这三个开关。用户只能手编 config.json。
- 说明：这不是死控件（根本没有控件），是"后端能力未暴露到 UI"的缺口。如需自签证书/内网上游，建议在上游行加折叠的高级开关。

### ⚪ 信息项（僵尸展示键 / 未暴露键，非缺陷）

**I1. `hook` / `map_type` / `percpu` 是纯展示键，运行时从不消费**
- 位置：`config.py:65-67` DEFAULTS；全仓仅在 `api.py:1300-1311, 2881-2882` 被 `.get()` 取出回显给前端 pipeline 图（`index.html:1470` 用于画拓扑/算 cache sig）。resolver/server/cache 零读取。
- config.py:381-383 注释自述"当前 Python 态仅作语义标记/控制台展示"。前端无编辑控件（pipeline 页只读展示）。属已知设计，列出备查。

**I2. `edns_client_max_size` / `edns_client_subnet` / `cache_partitions` 后端生效但前端无编辑入口**
- 生效侧：`resolver.py:404,2418`（edns_client_max_size）、resolver 10 处（edns_client_subnet）、`resolver.py:389,2370`（cache_partitions）。
- 前端：grep 无对应控件。它们随整对象 PUT 往返保留（不会丢），但用户无法在控制台调整。

**I3. listen.udp/tcp/udp6/tcp6、api.host/port/token、web_root 故意不在控制台暴露**
- `_CFG_WRITABLE_KEYS`（api.py:572-574）显式排除这三项（需重启生效/防注入），前端也无对应输入框。api-token-input 仅操作浏览器 localStorage，不写后端 api.token。符合设计。

---

## 四、死控件清单（前端有输入、后端不认识/不存储）

**空。** 经逐一核对，所有绑定到 `real.config` 的控件键均存在于 `config.py DEFAULTS` 并在 `_CFG_WRITABLE_KEYS` 白名单内；上游行字段全部在 `_UPSTREAM_WHITELIST`（api.py:2097）内；规则行字段全部被 `_validate_rule_dict` / `_normalize_rule_ttl` 接受。没有发现"前端输入了但后端静默丢弃"的控件。

唯一接近"死"的反向情况是 M2（后端支持 weight 但不消费），方向相反，已列入中危。

## 五、不生效开关清单（后端存储但运行时从不读取）

| 配置键 | 层级 | 写入路径 | 运行时读取 | 说明 |
|---|---|---|---|---|
| `weight` | upstreams[].weight | POST/PUT/bulk 全链路支持并校验 0–1000 | **无（resolver/upstream 零读取）** | M2，真僵尸 |
| `hook` | 顶层 | DEFAULTS + PUT 白名单 | 仅 api.py 回显展示，resolver 不读 | I1，已知语义标记 |
| `map_type` | 顶层 | DEFAULTS + PUT 白名单 | 仅 api.py 回显展示，resolver 不读 | I1 |
| `percpu` | 顶层 | DEFAULTS + PUT 白名单 | 仅 api.py 回显展示，resolver 不读 | I1 |

> 注：`allow_private_ip` / `doh_strict_cert` / `dot_strict_cert` 虽无 UI 开关，但后端确实读取生效（见 L4），**不算僵尸**。

---

## 六、统计

| 指标 | 数量 |
|---|---|
| 登记的配置相关控件总数 | **61**（全局 36 + 上游行 7 + 上游添加 3 + 规则行 6 + 订阅/导入 8 + 认证 1；另有 4 组非配置控件已排除） |
| 正常闭环（加载/保存/回显/生效/联动全通） | **56** |
| 范围不一致（中） | **1**（上游 latency max=500 vs 默认 5000） |
| 范围不一致（低） | **2**（health_check_interval spinner 上限；rule_sub_interval UI 上限偏紧） |
| 缺选项（低） | **1**（sub-action 缺 allow） |
| 后端能力未暴露 UI（低/信息） | **3**（allow_private_ip/doh/dot_strict_cert）+ 3 个未暴露生效键 |
| 死控件（前端有、后端无） | **0** |
| 僵尸配置键（后端存/写、运行时不读） | **4**（weight + hook + map_type + percpu） |
