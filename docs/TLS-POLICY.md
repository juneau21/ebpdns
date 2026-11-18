# ebpdns 2.2.0：出站 TLS 策略

> 适用：DoH（HTTPS）与 DoH3（QUIC）两类**出站加密上游**。明文 UDP/TCP 不经过本策略。

## 1. 三个顶层配置键

| 键 | 类型 | 默认 | 含义 |
|---|---|---|---|
| `tls_min_version` | 枚举 | `"1.2"` | 协议版本下限，只接受 `"1.2"` / `"1.3"`。**DoH3（QUIC）恒 TLS 1.3**：配 `"1.2"` 时按 1.3 处理（QUIC 的硬要求）。 |
| `tls_ca_file` | 字符串（路径） | `""` | 自定义 CA（PEM，可含多张证书；空串 = 只用系统根）。**fail-closed**：不可读 / 不是 PEM / 不含 `CERTIFICATE` ⇒ `check-config` rc=2、启动 exit 2、`PUT /api/config` 400。相对路径按**进程工作目录**解析，生产请用绝对路径。 |
| `tls_use_system_roots` | 布尔 | `true` | 是否加载系统 CA bundle（`SSL_CERT_FILE` 优先，其次常见发行版路径；都读不到时回退编译内置的 Mozilla 根）。可与 `tls_ca_file` **并存**；置 `false` 时必须给 `tls_ca_file`，否则没有任何信任根（拒绝启动）。 |

## 2. 始终严格校验（没有"跳过校验"开关）

三条判据**恒定生效**，不存在放宽入口：

1. **证书链**：必须能追溯到受信根（系统根 + 自定义 CA 的并集）；
2. **主机名/SAN**：`ServerName` 由配置里的 `host` 生成（IP 字面量走 IP SAN，域名走 DNS SAN + SNI）；
3. **有效期**：`notBefore ≤ now ≤ notAfter`。

2.1.49 里每上游的 `doh_strict_cert` / `doh3_strict_cert` / `dot_strict_cert` /
`doq_strict_cert` 四个开关（"关闭 strict"入口）**已随 2.2.0 整体移除**；它们已经不在
上游可写字段白名单里：`POST /api/upstreams` **不会落库这些字段**（按未知键丢弃），
`PUT /api/upstreams/{id}` 走单条校验会 **400**。两条路径都**不可能**降低校验强度；
旧配置里残留的键在启动时按未知键 WARN。

> **SPKI pin 不在 2.2.0 范围内**（将来若加，必须在链校验通过之后检查，且不得成为
> "绕过链校验"的替代品）。

## 3. 错误分类（日志 + `/api/upstreams` 可见）

| 前缀 | 触发 |
|---|---|
| `tls-chain` | 未知签发者 / 签名失败 / 编码非法 / 已吊销 |
| `tls-hostname` | 证书名称与上游主机不匹配 |
| `tls-expired` | 证书过期或尚未生效 |
| `tls-version` | 协议版本不兼容（如 `min=1.3` 连仅支持 1.2 的服务端） |
| `tls-handshake` | 其它握手层错误 |

实现：`crates/ebpdns-upstream/src/tls.rs::describe_tls_error`；构造点唯一：
`build_client_config`（`for_quic=true` 时强制 TLS 1.3，`alpn` 由传输层传入）。

## 4. 常见部署

```jsonc
// ① 只要系统根 + 最低 1.2（默认）
"tls_min_version": "1.2", "tls_ca_file": "", "tls_use_system_roots": true

// ② 企业私有 CA + 系统根并存
"tls_min_version": "1.3", "tls_ca_file": "/etc/ebpdns/private-ca.pem", "tls_use_system_roots": true

// ③ 只信私有 CA（内网 DoH），不允许任何公网根
"tls_min_version": "1.2", "tls_ca_file": "/etc/ebpdns/private-ca-root.pem", "tls_use_system_roots": false
```

**证书轮换**：`tls_ca_file` 的内容被原地替换（同一路径、新内容）后无需重启 —— 运行时按
`(路径, mtime, len)` 作为 TLS 配置缓存键，下一次需要新建连接时自动重建（已建立的连接
继续用旧配置直到自然关闭/回收，这是连接池的既有语义）。

**回滚**：三个键都有默认值，删掉它们即回到"系统根 + 1.2"；旧版本（2.1.49）不认识这三个
键，会按未知键 WARN 并忽略（不会阻止启动）。
