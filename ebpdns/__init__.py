"""ebpdns —— 基于 eBPF 理念的 SmartDNS 型 DNS 解析器（Debian 可部署版）。

真实数据面 + 控制面：
  - DNS 服务器:  UDP/TCP 监听 53 (可配置端口)
  - 解析引擎:    多上游并发 (UDP/TCP/DoH/DoT)、测速择优、域名分流、TTL 缓存、预取
  - 缓存语义:    用户态 LRU Map（模拟 BPF LRU_HASH），可选真实 eBPF XDP 数据面
  - 控制台:      内置 HTTP JSON API + Web 控制台
"""

__version__ = "1.9.54"
__appname__ = "ebpdns"
