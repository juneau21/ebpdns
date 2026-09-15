# v1.9.48 逐行复核 + 前后端配置对应检查报告

> 版本：v1.9.48（`ebpdns/__init__.py` `__version__ = "1.9.48"`）
> 复核日期：2026-09-14
> 复核范围：后端 16 项修复 + 前端 9 项修复 + 全量配置项三列映射

---

## 第一部分：v1.9.48 修复逐项验证

### 后端修复（16 项）

#### 1. rebind_blocked 计数器 — ✅ 通过

- **修复位置**：`ebpdns/resolver.py:577`、`ebpdns/telemetry.py:14`
- **修复代码摘要**：
  - `telemetry.py:14`：`counters` 字典初始化时包含 `"rebind_blocked": 0`
  - `resolver.py:577`：当 rebind 过滤命中时调用 `self._tel.inc("rebind_blocked")`
  - `telemetry.py:210`：`snapshot()` 返回 `"counters": dict(self.counters)`，自然包含 `rebind_blocked`
- **验证结论**：计数器正确初始化、正确递增、正确暴露到 `/api/status` 和 `/api/snapshot`。

---

#### 2. build_app 缓存策略 — ✅ 通过

- **修复位置**：`ebpdns/cli.py:166-182`、`ebpdns/api.py:1047-1067`
- **修复代码摘要**：
  - `cli.py:171`：`build_app` 调用 `Resolver(cfg, telemetry, cache=None)`，不传预建 cache，让 Resolver 根据 `cache_policy` 自行选择 `PartitionedCache` 或 `TinyLFUCache`
  - `cli.py:169-170` 注释明确说明："不传预建 cache: 让 Resolver 按 cache_policy 自行创建，否则 LRUCache 占位会使策略选择失效"
  - `api.py:1063-1065`：静态文件响应头设置 `Cache-Control: no-cache, no-store, must-revalidate` + `Pragma: no-cache` + `Expires: 0`
- **验证结论**：缓存策略选择逻辑正确，静态资源缓存头策略正确。

---

#### 3. PartitionedCache.restore — ✅ 通过

- **修复位置**：`ebpdns/cache.py:289-312`
- **修复代码摘要**：
  - 旧 bug：逐条调用 `self._caches[g].restore([e], ...)`，而 `LRUCache.restore` 开头会 `clear()` 整个 shard，导致每个 group 只保留最后一条
  - 新实现（`cache.py:293-297`）：先按 group 分组 `by_g = {}; for e in entries: by_g.setdefault(e.get("g",""), []).append(e)`，再逐组调用 `self._caches[g].restore(es, now, persist_ttl)`
- **验证结论**：分组恢复逻辑正确，修复了旧版多 group 条目互相覆盖的 bug。

---

#### 4. TLS 证书校验恢复 — ✅ 通过

- **修复位置**：`ebpdns/upstream.py:380-382`（DoT）、`ebpdns/upstream.py:510-512`（TCP-TLS）
- **修复代码摘要**：
  - DoT（`upstream.py:380`）：`ctx = ssl.create_default_context()` 然后 `ctx.wrap_socket(sock, server_hostname=host if _is_hostname(host) else None)`
  - TCP-TLS（`upstream.py:511`）：同样使用 `ssl.create_default_context()`
  - `ssl.create_default_context()` 默认 `verify_mode = ssl.CERT_REQUIRED`、`check_hostname = True`
- **验证结论**：证书校验未被禁用，`verify_mode` 不是 `CERT_NONE`。

---

#### 5. UDP getaddrinfo 缓存 — ✅ 通过

- **修复位置**：`ebpdns/upstream.py:27-52`
- **修复代码摘要**：
  - `upstream.py:28-30`：`_addr_cache = {}`、`_ADDR_CACHE_LOCK = threading.Lock()`、`_ADDR_CACHE_TTL = 300.0`
  - `upstream.py:34-50`：`_cached_udp_addrs(host)` 函数先查缓存（带 TTL 检查），未命中才调用 `socket.getaddrinfo` 并写入缓存
  - `upstream.py:471`：`_udp_query` 中使用 `_cached_udp_addrs(host)` 获取地址列表
- **验证结论**：UDP 上游域名解析有 300 秒 TTL 缓存，避免每次查询都做 DNS 解析。

---

#### 6. bootstrap socket 泄漏 — ✅ 通过

- **修复位置**：`ebpdns/upstream.py:87-93`
- **修复代码摘要**：
  ```python
  s = socket.socket(addr[0], socket.SOCK_DGRAM)
  try:
      s.settimeout(...)
      s.sendto(...)
      data, _ = s.recvfrom(...)
  finally:
      s.close()
  ```
- **验证结论**：socket 通过 try/finally 确保关闭，无泄漏。

---

#### 7. 环境变量名 — ✅ 通过

- **修复位置**：`ebpdns/config.py:243`、`ebpdns/api.py:117`、`ebpdns/api.py:1084`
- **修复代码摘要**：
  - `config.py:243`：`os.environ.get("EBPDNS_CONFIG")` — 配置文件路径
  - `api.py:117`：`os.environ.get("INVOCATION_ID")` / `os.environ.get("JOURNAL_STREAM")` — systemd 检测
  - `api.py:1084`：`os.environ.get("EBPDNS_DEBUG_LOG")` — 调试日志
- **验证结论**：所有环境变量名一致且正确，无拼写错误。

---

#### 8. telemetry _ev_seq 锁 — ✅ 通过

- **修复位置**：`ebpdns/telemetry.py:36`、`ebpdns/telemetry.py:176-177`
- **修复代码摘要**：
  - `telemetry.py:36`：`self._ev_seq = 0`
  - `telemetry.py:176-177`：`with self._lock: self._ev_seq += 1`
- **验证结论**：`_ev_seq` 的递增在 `self._lock` 保护下进行，并发安全。

---

#### 9. TCP 异常兜底 — ✅ 通过

- **修复位置**：`ebpdns/server.py:179-193`
- **修复代码摘要**：
  ```python
  try:
      resp = self.server.resolver.answer_raw(msg, self.client_address)
  except Exception:
      try:
          resp = dnsmsg.build_error_response(msg, 2)  # SERVFAIL
      except Exception:
          resp = None
  ```
  外层还有 `except (socket.timeout, OSError): pass` 兜底连接异常。
- **验证结论**：TCP 处理有完整异常兜底，不会因 resolver 异常而崩溃。

---

#### 10. 订阅 SSRF — ⚠️ 部分通过（存在绕过路径）

- **修复位置**：`ebpdns/api.py:22-54`（`_sub_url_blocked`）、`ebpdns/api.py:774`（手动订阅调用点）
- **修复代码摘要**：
  - `api.py:22-54`：`_sub_url_blocked(url)` 检查 localhost、私有 IP 段（127/8、10/8、172.16/12、192.168/16、169.254/16）、IPv6 链路本地/唯一本地
  - `api.py:774`：手动订阅 API 路径调用 `blocked = _sub_url_blocked(url)`
- **发现问题**：以下两条后台自动路径**未调用** `_sub_url_blocked`，存在 SSRF 绕过：
  1. **`ebpdns/resolver.py:1564-1568`**：`_fetch_sub_text()` 直接 `urllib.request.urlopen(req, timeout=timeout)`，无 SSRF 检查。被 `_update_rule_subs_once()`（`resolver.py:1593`）周期调用——这是规则订阅的自动更新路径。
  2. **`ebpdns/cli.py:212-213`**：`_ensure_subs_downloaded()` 冷启动补下载直接 `urllib.request.urlopen(req, timeout=20)`，无 SSRF 检查。
- **验证结论**：手动订阅 API 有 SSRF 防护，但后台自动更新和冷启动补下载两条路径完全绕过了防护。

---

#### 11. 启动预热重试 — ✅ 通过

- **修复位置**：`ebpdns/resolver.py:527-543`
- **修复代码摘要**：
  - `resolver.py:527`：`if (time.monotonic() - self._boot_ts) < 45 and self._boot_retries < 3:`
  - 预热成功后 `self._boot_retries = 99`（标记完成）
  - 在 `with self._lock:` 保护下执行，避免并发重复预热
- **验证结论**：启动预热有 3 次重试、45 秒窗口、锁保护。

---

#### 12. parse_message 边界 — ✅ 通过

- **修复位置**：`ebpdns/dnsmsg.py:284-331`
- **修复代码摘要**：
  - `dnsmsg.py:286-287`：`if len(data) < 12: raise DNSError("message too short")`
  - `dnsmsg.py:306-307`：`if pos + 10 > len(data): raise DNSError("truncated RR header")`
  - `dnsmsg.py:315-316`：`if pos + rdlen > len(data): raise DNSError("truncated RR rdata")`
  - `dnsmsg.py:95-96`：`if jumps > 32: raise DNSError("compression loop")` — 压缩指针跳转限幅
- **验证结论**：parse_message 有完整的边界检查和压缩指针防环。

---

#### 13. DoT 缓冲上限 — ⚠️ 部分通过（明文 TCP 缺失）

- **修复位置**：`ebpdns/upstream.py:403-404`（DoT）
- **修复代码摘要**：
  - DoT（`upstream.py:403`）：`if len(buf) > 65536: return None` — 有 64KB 上限
  - 明文 TCP 上游 `_tcp_query`（`upstream.py:502-535`）：`buf += chunk` 循环**没有**大小上限检查
- **发现问题**：明文 TCP 上游（proto=tcp）的接收缓冲区无上限。恶意或故障上游可发送无限数据流导致内存耗尽。
- **验证结论**：DoT 有缓冲上限，但明文 TCP 上游 `_tcp_query` 缺少同样的保护。

---

#### 14. 缓存过期清理 — ✅ 通过

- **修复位置**：`ebpdns/cache.py:51-53, 66-67, 93-112`
- **修复代码摘要**：
  - 惰性清理：`LRUCache.get()` 命中时检查 `v.expires_at < now` 则删除（`cache.py:51-53`）
  - 概率清理：`LRUCache.put()` 每 32 次写入触发一次 `_purge_expired_locked`（`cache.py:66-67`）
  - 主动清理：`purge_expired()` 方法可外部调用（`cache.py:93-99`）
  - `_purge_expired_locked()` 从 head（最旧）扫描，遇到第一个未过期条目即停止（`cache.py:101-112`）
  - TinyLFUCache 同样有概率清理（`cache.py:462-463`）
- **验证结论**：缓存过期清理逻辑完整，惰性+概率+主动三种机制并存。

---

#### 15. speed_timeout_ms 死配置 — ❌ 问题

- **位置**：`ebpdns/config.py:40` 定义 `"speed_timeout_ms": 300`
- **发现**：全局搜索确认该字段**从未被任何代码读取**。实际测速探测超时硬编码在 `resolver.py:1168`：`timeout_ms = 800`。
- **影响**：用户在配置文件中设置 `speed_timeout_ms` 不会产生任何效果，造成误导。

---

#### 16. ip_speed_probe 死配置 — ❌ 问题

- **位置**：`ebpdns/config.py:42` 定义 `"ip_speed_probe": "both"`
- **发现**：全局搜索确认该字段**从未被任何代码读取**。探测方式由上游协议决定（`resolver.py:563`：`use_tls = proto in ("dot", "doh", "doh3")`）。
- **影响**：用户配置 `ip_speed_probe` 不产生任何效果。

---

### 前端修复（9 项）

#### F1. 事件监听器重复绑定 — ✅ 通过

- **修复位置**：`web/index.html:1728-1735`
- **修复代码摘要**：
  ```javascript
  let _configEventsBound = false;
  function bindConfigEvents(){
    if (_configEventsBound) return;
    _configEventsBound = true;
    // ... 所有绑定只执行一次
  ```
  注释明确说明："这里只在初始化时绑一次, 避免每次 renderConfig 后监听器累积导致一次保存触发 N 次 PUT /api/config"
- **验证结论**：`bindConfigEvents` 通过 `_configEventsBound` 标志位确保只绑定一次。

---

#### F2. 导入按钮重复 — ✅ 通过

- **修复位置**：`web/index.html:1924-1925, 1954`
- **修复代码摘要**：
  - 绑定位置：`$('#btn-import-rule').addEventListener('click', runImport)`（行 1924）
  - 注释确认：`// (P0-2: 原先此处重复绑定 #btn-import-rule / #import-input, 已删除——两者在上方各绑一次即可)`（行 1954）
- **验证结论**：导入按钮只绑定一次，旧的重复绑定已删除。

---

#### F3. Top N XSS — ✅ 通过

- **修复位置**：`web/index.html:1476`
- **修复代码摘要**：
  ```javascript
  const fmtTop = (arr, unit) => (arr && arr.length
    ? arr.slice(0,8).map(x => esc(x[0]) + ' <span...' + x[1] + unit + '</span>').join('<br>')
    : '暂无数据');
  ```
  域名/客户端名通过 `esc(x[0])` 转义后再拼入 innerHTML。
- **验证结论**：Top N 渲染使用 `esc()` 转义，无 XSS 风险。

---

#### F4. cache_policy 控件 — ✅ 通过

- **修复位置**：`web/index.html:729-732`（HTML）、`1566`（赋值）、`1767`（事件绑定）
- **修复代码摘要**：
  - HTML：`<select id="cfg-cache-policy">` 含 `lru` 和 `tinylfu` 两个选项
  - 赋值：`$('#cfg-cache-policy').value = c.cache_policy || 'lru'`
  - 事件：`$('#cfg-cache-policy').addEventListener('change', ...)` 设置 `_cachePolicyDirty = true`，保存后自动 `/api/reload`
- **验证结论**：控件存在、字段对应、热切换逻辑完整。

---

#### F5. 高级选项卡片 — ✅ 通过

- **修复位置**：`web/index.html:708-724`
- **修复代码摘要**：高级选项卡片包含 EDNS0 开关、DNS 0x20 开关、IP 测速开关、健康检查间隔、规则订阅间隔、bootstrap DNS 输入。
- **验证结论**：卡片结构正确，所有高级选项控件完整。

---

#### F6. cache_size 范围统一 — ⚠️ 不匹配

- **修复位置**：`web/index.html:580`（前端）、`ebpdns/api.py:379`（后端）
- **发现**：
  - 前端 HTML：`min="16" max="1048576" step="16"`（行 580）
  - 前端 JS clamp：`clamp(+e.target.value, 16, 1048576)`（行 1736）
  - 后端校验：`1 <= cs <= 10_000_000`（`api.py:379`）
- **影响**：后端允许 1~10,000,000，但前端只允许 16~1,048,576。用户通过 API 可设置前端无法显示/编辑的值。
- **验证结论**：前后端范围不一致。

---

#### F7. fetch 超时 — ✅ 通过

- **修复位置**：`web/index.html:912-927`
- **修复代码摘要**：
  ```javascript
  req(path, method, body){
    const ctrl = new AbortController();
    const tid = setTimeout(() => ctrl.abort(), 10000);
    return fetch(url, { method, signal: ctrl.signal, ... })
      .finally(() => clearTimeout(tid));
  }
  ```
  所有 API 调用（get/post/put/del）都经过 `req()`，统一 10 秒超时。
- **验证结论**：所有 fetch 调用都有 AbortController 超时保护。

---

#### F8. note 竞态 — ✅ 通过

- **修复位置**：`web/index.html:2010-2012`
- **修复代码摘要**：
  ```javascript
  let _noteTimer = null;
  function note(txt, color){
    const el = $('#cfg-saved-note');
    el.textContent = txt; el.style.color = color;
    if (_noteTimer) clearTimeout(_noteTimer);
    _noteTimer = setTimeout(() => { ... }, 2600);
  }
  ```
  新 note 调用前先清除旧定时器，避免快速连续调用时定时器互相覆盖。
- **验证结论**：note 函数有竞态防护。

---

#### F9. 清空游标同步 — ✅ 通过

- **修复位置**：`web/index.html:2109-2121`
- **修复代码摘要**：
  ```javascript
  $('#btn-clear').addEventListener('click', async () => {
    if (MODE === 'real'){
      try { await API.post('/api/reset'); } catch(e){}
      real.logs = []; clearLogUI();
      try {
        const r = await API.get('/api/logs?since=' + real.logSeq);
        real.logSeq = (r && r.next_seq != null) ? r.next_seq : real.logSeq;
      } catch(e){ real.logSeq = 0; }
    }
  });
  ```
  清空后用当前游标重新拉取一次，同步到后端新的 `next_seq`，避免旧事件重新涌入。
- **验证结论**：清空游标同步逻辑正确。

---

## 第二部分：前后端配置项完整映射表

> 三列：前端控件 ↔ 后端 config 字段 ↔ 实际生效代码路径

### 2.1 全局参数配置

| # | 前端控件 ID | 前端字段名 | 后端 config 字段 | 后端默认值 | 实际使用位置 | 状态 |
|---|------------|-----------|-----------------|-----------|-------------|------|
| 1 | `#cfg-size` / `#cfg-size-r` | `cache_size` | `cache_size` | `1024` | `resolver.py:104` 初始化；`api.py:391` 运行时调容量；`resolver.py:1476` reload | ✅ |
| 2 | `#cfg-cache-policy` | `cache_policy` | `cache_policy` | `"lru"` | `resolver.py:117-122` 选择缓存实现；`resolver.py:1487-1497` reload 切换 | ✅ |
| 3 | `#cfg-ttl` / `#cfg-ttl-r` | `ttl` | `ttl` | `300` | `resolver.py:640,1300` 写入缓存时使用 | ✅ |
| 4 | `#cfg-ttlmin` | `ttl_min` | `ttl_min` | `60` | `resolver.py:649-650,1302` `_clamp_ttl` 下限 | ✅ |
| 5 | `#cfg-ttlmax` | `ttl_max` | `ttl_max` | `86400` | `resolver.py:649-650,1302` `_clamp_ttl` 上限 | ✅ |
| 6 | `#cfg-stale` | `serve_stale` | `serve_stale` | `true` | `resolver.py:685-692` 缓存过期后返回 stale | ✅ |
| 7 | `#cfg-stalettl` | `stale_ttl` | `stale_ttl` | `3600` | `resolver.py:687` stale 过期上限 | ✅ |
| 8 | `#cfg-persistttl` | `persist_ttl` | `persist_ttl` | `604800` | `cache.py:293,431` restore 时持久化存活期 | ✅ |
| 9 | `#cfg-prefetch` | `prefetch` | `prefetch` | `true` | `resolver.py:720,1314` TTL 前 1/10 触发预取 | ✅ |
| 10 | `#cfg-kdirect` | `kernel_direct` | `kernel_direct` | `true` | `resolver.py:599,1378` BPF map 直答 | ✅ |
| 11 | `#cfg-speed` | `speed_test` | `speed_test` | `true` | `resolver.py:734,1328` 多 IP 测速择优 | ✅ |
| 12 | `#cfg-spint` | `speed_interval_ms` | `speed_interval_ms` | `2000` | `resolver.py:1143` `_speed_sort` 缓存有效期 | ✅ |
| 13 | `#cfg-fallback` | `fallback` | `fallback` | `true` | `resolver.py:883,928,1384` 全失败时 fallback | ✅ |
| 14 | `#cfg-maxup` | `max_parallel_upstreams` | `max_parallel_upstreams` | `3` | `resolver.py:916` 并行查询上游数上限 | ✅ |
| 15 | `#cfg-v4first` | `ipv4_first` | `ipv4_first` | `true` | `resolver.py:737` AAAA 后追加 A 查询 | ✅ |
| 16 | `#cfg-v6` | `ipv6` | `ipv6` | `true` | `resolver.py:742` AAAA 开关 | ✅ |
| 17 | `#cfg-v4smart` | `prefer_ipv4` | `prefer_ipv4` | `false` | `resolver.py:960-966` 双栈择优 | ✅ |
| 18 | `#cfg-ednssize` | `edns_udp_size` | `edns_udp_size` | `1232` | `resolver.py:791` EDNS0 UDP 负载大小 | ✅ |
| 19 | `#cfg-padding` | `padding` | `padding` | `false` | `resolver.py:794` EDNS0 PADDING 选项 | ✅ |
| 20 | `#cfg-rebind` | `rebind_protection` | `rebind_protection` | `true` | `resolver.py:573-577` 私网 IP 过滤 | ✅ |
| 21 | `#cfg-timeout` | `timeout_ms` | `timeout_ms` | `1500` | `resolver.py:914` 上游查询超时 | ✅ |
| 22 | `#cfg-edns` | `edns` | `edns` | `true` | `resolver.py:790` EDNS0 总开关 | ✅ |
| 23 | `#cfg-dnssec0x20` | `dnssec_0x20` | `dnssec_0x20` | `true` | `resolver.py:785` 0x20 随机化 | ✅ |
| 24 | `#cfg-ipspeedcheck` | `ip_speed_check` | `ip_speed_check` | `true` | `resolver.py:1148,1336` IP 级测速 | ✅ |
| 25 | `#cfg-healthint` | `health_check_interval` | `health_check_interval` | `0` | `resolver.py:1125,1517` 周期健康检查 | ✅ |
| 26 | `#cfg-rulesubint` | `rule_sub_interval` | `rule_sub_interval` | `3600` | `resolver.py:1522-1523` 规则订阅自动更新 | ✅ |
| 27 | `#cfg-bootstrapdns` | `bootstrap_dns` | `bootstrap_dns` | `""` | `resolver.py:156-159` 解析上游域名 | ✅ |

### 2.2 高级 / 无前端控件的后端配置

| # | 后端 config 字段 | 后端默认值 | 实际使用位置 | 前端控件 | 状态 |
|---|-----------------|-----------|-------------|---------|------|
| 28 | `cache_partitions` | `["domestic","global"]` | `resolver.py:113` 分区缓存分组 | ❌ 无 | ⚠️ 后端有前端无 |
| 29 | `health_probe_domain` | `"example.com"` | `resolver.py:1131` 健康探测域名 | ❌ 无 | ⚠️ 后端有前端无 |
| 30 | `health_probe_timeout_ms` | `2000` | `resolver.py:1134` 健康探测超时 | ❌ 无 | ⚠️ 后端有前端无 |
| 31 | `speed_timeout_ms` | `300` | **从未被读取**（硬编码 800ms 在 `resolver.py:1168`） | ❌ 无 | ❌ 死配置 |
| 32 | `ip_speed_probe` | `"both"` | **从未被读取**（由 proto 决定，`resolver.py:563`） | ❌ 无 | ❌ 死配置 |
| 33 | `ip_speed_cache_ttl` | `300` | `resolver.py:1149` IP 测速缓存有效期 | ❌ 无 | ⚠️ 后端有前端无 |
| 34 | `edns_client_subnet` | `""` | `resolver.py:803` EDNS0 ECS 选项 | ❌ 无 | ⚠️ 后端有前端无 |
| 35 | `hook` | `"xdp" / "socket"` | `resolver.py:127-133` BPF hook 模式 | ❌ 无（仅展示） | ⚠️ 展示用 |
| 36 | `map_type` | `"lru" / "tinylfu"` | `resolver.py:135` BPF map 类型 | ❌ 无（仅展示） | ⚠️ 展示用 |
| 37 | `percpu` | `true` | `resolver.py:140` BPF map per-CPU | ❌ 无 | ⚠️ 后端有前端无 |
| 38 | `log_format` | `"text"` | `cli.py:260` 日志格式 | ❌ 无 | ⚠️ 后端有前端无 |
| 39 | `log_level` | `"info"` | `cli.py:260` 日志级别 | ❌ 无 | ⚠️ 后端有前端无 |
| 40 | `web_root` | `""` | `api.py:1048` 静态文件根目录 | ❌ 无 | ⚠️ 部署用 |
| 41 | `listen.udp` | `0.0.0.0:53` | `server.py:24-33` UDP 监听 | ❌ 无 | ⚠️ 部署用 |
| 42 | `listen.tcp` | `0.0.0.0:53` | `server.py:24-33` TCP 监听 | ❌ 无 | ⚠️ 部署用 |
| 43 | `listen.udp6` | `:::53` | `server.py:24-33` UDP6 监听 | ❌ 无 | ⚠️ 部署用 |
| 44 | `listen.tcp6` | `:::53` | `server.py:24-33` TCP6 监听 | ❌ 无 | ⚠️ 部署用 |
| 45 | `api.host` | `127.0.0.1` | `api.py` HTTP API 监听 | ❌ 无 | ⚠️ 部署用 |
| 46 | `api.port` | `8080` | `api.py` HTTP API 端口 | ❌ 无 | ⚠️ 部署用 |
| 47 | `circuit_fails` | **不在 DEFAULTS** | `resolver.py:162` 硬编码默认 3 | ❌ 无 | ❌ 不在 config.py |
| 48 | `circuit_open_s` | **不在 DEFAULTS** | `resolver.py:163` 硬编码默认 30 | ❌ 无 | ❌ 不在 config.py |

### 2.3 结构化配置（上游 / 规则 / 订阅）

| # | 前端控件 | 后端 config 字段 | 实际使用位置 | 状态 |
|---|---------|-----------------|-------------|------|
| 49 | `#up-list` 行内编辑 | `upstreams[]`（id/name/proto/addr/port/url/group/latency/enabled） | `resolver.py:896` 查询上游；`resolver.py:1089` 健康检查 | ✅ |
| 50 | `#rule-list` 行内编辑 | `rules[]`（match/action/group/ip/ttl_min/ttl_max）→ 存 `rules_local.json` | `resolver.py:485-496` 规则索引匹配 | ✅ |
| 51 | `#rule-sub-list` | `rule_subscriptions[]`（url/action/group/ip）→ 明细存 `rules_sub.json` | `resolver.py:1570-1600` 订阅规则加载 | ✅ |

---

## 第三部分：发现的问题清单（按严重程度排序）

### 🔴 高严重度

#### H1. 订阅 SSRF 绕过 — 后台自动更新路径无防护

**位置**：
- `ebpdns/resolver.py:1564-1568` — `_fetch_sub_text()` 无 `_sub_url_blocked` 调用
- `ebpdns/cli.py:212-213` — `_ensure_subs_downloaded()` 冷启动补下载无 `_sub_url_blocked` 调用

**影响**：手动订阅 API 有 SSRF 防护（`api.py:774`），但以下两条后台路径完全绕过：
1. 周期自动更新（`resolver.py:1523` → `_update_rule_subs_once()` → `_fetch_sub_text()`）
2. 冷启动补下载（`cli.py:193` → `_do()` → `urlopen()`）

攻击者可在订阅 URL 中填入 `http://169.254.169.254/latest/meta-data/` 等云元数据地址，通过后台定时任务或重启触发 SSRF 攻击内网。

---

#### H2. 明文 TCP 上游接收缓冲区无上限

**位置**：`ebpdns/upstream.py:515-524`

**影响**：DoT 路径有 `if len(buf) > 65536: return None` 保护（`upstream.py:403`），但明文 TCP 上游 `_tcp_query()` 的 `buf += chunk` 循环没有大小上限。恶意或故障 TCP 上游可发送无限数据流，导致内存耗尽。

---

### 🟡 中严重度

#### M1. cache_size 前后端范围不一致

**位置**：
- 前端：`web/index.html:580` `min="16" max="1048576"`；JS clamp `clamp(+v, 16, 1048576)`（行 1736）
- 后端：`ebpdns/api.py:379` 校验 `1 <= cs <= 10_000_000`

**影响**：后端接受 1~10,000,000，但前端 UI 只允许 16~1,048,576。通过 API 直接设置的值在前端无法正确显示和编辑。

---

#### M2. `speed_timeout_ms` 死配置字段

**位置**：`ebpdns/config.py:40` 定义 `"speed_timeout_ms": 300`

**影响**：该字段从未被任何代码读取。实际测速探测超时硬编码为 800ms（`resolver.py:1168`）。用户配置此字段无效。

---

#### M3. `ip_speed_probe` 死配置字段

**位置**：`ebpdns/config.py:42` 定义 `"ip_speed_probe": "both"`

**影响**：该字段从未被任何代码读取。探测方式由上游协议决定（`resolver.py:563`）。用户配置此字段无效。

---

### 🟢 低严重度

#### L1. `circuit_fails` / `circuit_open_s` 不在 config.py DEFAULTS 中

**位置**：`ebpdns/resolver.py:162-163` 读取 `circuit_fails`（默认 3）和 `circuit_open_s`（默认 30），但 `config.py` 的 `DEFAULTS` 字典中没有这两个键。

**影响**：这两个参数不在 API 配置视图中，用户无法通过 Web UI 或 config.json 调整熔断器参数（虽然代码中 `cfg.get()` 有默认值，功能正常）。

---

## 第四部分：具体修复代码

### H1. 修复订阅 SSRF 绕过

#### 修复 1a：resolver.py `_fetch_sub_text` 增加 SSRF 检查

**文件**：`ebpdns/resolver.py`

**原代码**（行 1564-1568）：
```python
    def _fetch_sub_text(self, url, timeout=20):
        req = urllib.request.Request(url, headers={"User-Agent": "ebpdns/subscribe"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")
```

**修改后**：
```python
    def _fetch_sub_text(self, url, timeout=20):
        from .api import _sub_url_blocked
        if _sub_url_blocked(url):
            raise ValueError("subscription URL blocked (private/loopback address): %s" % url)
        req = urllib.request.Request(url, headers={"User-Agent": "ebpdns/subscribe"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")
```

#### 修复 1b：cli.py `_ensure_subs_downloaded` 增加 SSRF 检查

**文件**：`ebpdns/cli.py`

**原代码**（行 211-214）：
```python
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "ebpdns/subscribe"})
                    with urllib.request.urlopen(req, timeout=20) as r:
                        text = r.read().decode("utf-8", "replace")
```

**修改后**：
```python
                try:
                    from .api import _sub_url_blocked
                    if _sub_url_blocked(url):
                        log.warning("订阅冷启动补下载跳过被阻止的 URL (私有/回环地址): %s", url)
                        continue
                    req = urllib.request.Request(url, headers={"User-Agent": "ebpdns/subscribe"})
                    with urllib.request.urlopen(req, timeout=20) as r:
                        text = r.read().decode("utf-8", "replace")
```

---

### H2. 修复明文 TCP 上游接收缓冲区无上限

**文件**：`ebpdns/upstream.py`

**原代码**（行 515-524）：
```python
        buf = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                return False, None
            buf += chunk
            try:
                msg, _ = parse_tcp_frame(buf)
            except Exception:
                continue
```

**修改后**：
```python
        buf = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                return False, None
            buf += chunk
            if len(buf) > 65536:
                return False, None
            try:
                msg, _ = parse_tcp_frame(buf)
            except Exception:
                continue
```

---

### M1. 统一 cache_size 前后端范围

**方案 A（推荐）：前端放宽到与后端一致**

**文件**：`web/index.html`

**原代码**（行 580）：
```html
        <input class="num" type="number" id="cfg-size" min="16" max="1048576" step="16" value="1024">
```

**修改后**：
```html
        <input class="num" type="number" id="cfg-size" min="1" max="10000000" step="16" value="1024">
```

**文件**：`web/index.html`

**原代码**（行 1736）：
```javascript
  $('#cfg-size').addEventListener('change', e => { if (MODE==='real') real.config.cache_size = clamp(+e.target.value,16,1048576); else config.cacheSize = clamp(+e.target.value,16,1048576); $('#cfg-size-r').value = e.target.value; });
```

**修改后**：
```javascript
  $('#cfg-size').addEventListener('change', e => { if (MODE==='real') real.config.cache_size = clamp(+e.target.value,1,10000000); else config.cacheSize = clamp(+e.target.value,1,10000000); $('#cfg-size-r').value = e.target.value; });
```

---

### M2. 修复 `speed_timeout_ms` 死配置

**方案：让代码实际读取该配置**

**文件**：`ebpdns/resolver.py`

**原代码**（行 1168 附近）：
```python
        timeout_ms = 800
```

**修改后**：
```python
        timeout_ms = float(self.cfg.get("speed_timeout_ms", 800))
```

> 注意：config.py 默认值为 300，但代码硬编码 800ms。建议将 config.py 默认值改为 800，或保持 300 并让代码读取。此处选择让代码读取配置，默认值 800 作为 fallback（与当前硬编码行为一致）。

---

### M3. 修复 `ip_speed_probe` 死配置

**方案：让代码实际读取该配置控制探测协议**

**文件**：`ebpdns/resolver.py`

**原代码**（行 563 附近，在 `_speed_sort` 方法内）：
```python
            use_tls = proto in ("dot", "doh", "doh3")
```

**修改后**：
```python
            probe_mode = str(self.cfg.get("ip_speed_probe", "both")).lower()
            if probe_mode == "udp53":
                use_tls = False
            elif probe_mode == "tcp443":
                use_tls = True
            else:  # "both" — 按上游协议决定
                use_tls = proto in ("dot", "doh", "doh3")
```

---

### L1. 将 `circuit_fails` / `circuit_open_s` 加入 config.py DEFAULTS

**文件**：`ebpdns/config.py`

**在 DEFAULTS 字典中添加**（建议放在 `health_check_interval` 附近）：
```python
    "circuit_fails": 3,
    "circuit_open_s": 30,
```

---

## 总结

| 类别 | 总数 | 通过 | 部分通过 | 问题 |
|------|------|------|---------|------|
| 后端修复 | 16 | 12 | 2 | 2 |
| 前端修复 | 9 | 8 | 1 | 0 |
| **合计** | **25** | **20** | **3** | **2** |

**关键发现**：
1. v1.9.48 的 25 项修复中，20 项完全正确，3 项部分正确（SSRF 绕过、DoT 缓冲不完整、cache_size 范围不匹配），2 项是死配置字段（`speed_timeout_ms`、`ip_speed_probe`）。
2. 最严重的安全问题是**订阅 SSRF 在后台自动更新路径被绕过**——手动 API 有防护，但周期任务和冷启动补下载两条路径完全缺失。
3. 明文 TCP 上游缺少 DoT 已有的 64KB 缓冲区上限，存在内存耗尽风险。
4. 两个配置字段（`speed_timeout_ms`、`ip_speed_probe`）定义了但从未生效，属于配置误导。
