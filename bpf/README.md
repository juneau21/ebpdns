# ebpdns eBPF XDP 数据面（预留接口 · 占位参考）

> **状态说明**：本组件为**占位参考实现**，当前 daemon（Python 用户态 LRU 数据面）**尚未集成**——即使编译挂载，内核 `dns_cache` map 因无用户态回填而恒为空，不会产生任何加速。启用需另行开发 daemon 侧 libbpf/bcc 回填集成，且需网卡支持**原生 XDP**（云虚拟机 virtio 网卡通常不支持）。

> ## ⚠️ 已知限制：当前无法通过内核 BPF 校验器（v1.9.150 实测）
>
> **已修复的部分**（相对原始版本）：
> 1. **编译失败** —— 原版 `-Werror` 下因 `unused function 'qname_hash'` 与运行期变长
>    `__builtin_memcpy`（降级为 libc `memcpy`，BPF 禁止）**根本无法编译**；现已可编译。
> 2. **DNS 事务 ID 未回填** —— 应答未显式保留请求 ID，客户端会因 ID 不匹配丢弃应答。
> 3. **`XDP_TX` 前未交换地址** —— 以太网 MAC / IP 源目的 / UDP 端口均未交换，回包不可能被客户端接受。
> 4. **循环上界取自 map value** —— 校验器要求编译期可知上界，已改为 `EBP_MAX_ADDRS` 定界。
> 5. **`parse_qname` 越界检查缺失** —— 已改为两层有界循环 + 逐步指针比较校验。
>
> **2026-10-08 在 Debian 13（内核 6.12.101+deb13-cloud-amd64，clang 19.1.7，bpftool 7.5.0）实测**
> 结果：
>
> | 项目 | 结果 |
> |---|---|
> | `make` 编译 | ✅ **通过**（产出 `ebpdns_xdp.o` 与 `ebpdns_xdp.skel.h`） |
> | `bpftool prog load` 内核校验器 | ❌ **拒绝**（见下方卡点与建议） |
>
> **卡点**：`parse_qname()` 内以**变量下标**读取包数据（`pkt[off]`，并处于可变次数循环中），
> 校验器无法为"变量下标 + 循环"建立包范围证明。`bpf_xdp_adjust_tail()` 与变量包偏移的组合
> 是 eBPF 公认难点；标准解法需改写为**固定展开的逐字节扫描**或改用 `bpf_loop`。
>
> ### 第二轮修复进展（同一环境复测）
>
> 已把 `parse_qname` 改写为**两层有界循环**（外层 ≤32 标签、内层 ≤63 字节，`len > 63` 先钳制），
> 每次读取前用指针比较表达边界，并去掉超出 clang 一元展开预算的 `#pragma unroll`
> （原写法直接报 `loop not unrolled ... -Wpass-failed`）。效果：
>
> - 编译：**通过**（`ebpdns_xdp.o` 34 944 B）
> - 校验器：从"第 60 条指令即拒绝"推进到**处理 1970 条指令**后才拒绝，卡点后移至：
>
> ```
> ebpdns_xdp.bpf.c:202  q_qclass = *(__u16 *)(dns + q_off + 2)
> invalid access to packet, off=100 size=2, R2(id=3,off=100,r=97)
> R2 offset is outside of the packet
> ```
>
> **剩余卡点分析（留给维护者的具体线索）**：校验器跟踪的包区间上界是 **97**，而 `q_qclass`
> 需要读到 100。原因是 `parse_qname` 用的是**独立传入的 `pkt_end`**，校验器不会把它与
> `data_end` 归并为同一区间；且 `q_off`（≤ `dns_len`）与 `dns_len`（= `data_end - dns`）
> 两条边界校验器无法合并成"≤ 包尾"。
>
> **建议的下一步（候选实现）**：把 `parse_qname` 改为**只返回解析出的 name 长度**（不做任何
> 包读取之外的副作用），并让所有包读取都直接用**已证明有界的 `dns` 指针**
> （形如 `dns + n`，`n` 为常量或有界变量），用与上层相同的 `(void *)(p) + k > data_end`
> 指针比较；必要时把 qtype/qclass 的读取移到 `parse_qname` 内部、在同一个已证明有界的
> 作用域内完成。参考 `samples/bpf/xdp1_kern.c` 一类"单函数、指针递进"的写法通常更易通过。
>
> **结论**：本参考实现**仍不可加载**。需 eBPF 专项维护者按上述线索完成，并在**支持原生
> XDP 的网卡 + 真实流量**下做端到端验证（判断回包正确性必须抓包）。**该限制不影响默认部署** ——
> 默认数据面为纯用户态 Python LRU，不依赖本组件。

让「缓存命中由网卡内核直答」的真实 eBPF 数据面加速组件。

## 前提（Debian 13）

- Linux 内核 ≥ 5.4（建议 5.15+），开启 BTF
- 网卡驱动支持**原生 XDP**（`ethtool -S eth0 | grep -i xdp` 或 `ip link show eth0`）
- 工具链：

```bash
sudo apt install clang llvm libbpf-dev linux-libc-dev bpftool
```

## 编译与挂载

```bash
cd /opt/ebpdns/bpf
make                 # 生成 ebpdns_xdp.o 与 ebpdns_xdp.skel.h
sudo ./load.sh eth0  # 挂载到 eth0
```

## 工作原理

- 在 XDP Hook 拦截发往本机 `UDP/53` 的 DNS 查询
- 解析 `(qname_hash, qtype)` → 查询 `dns_cache`（`BPF_MAP_TYPE_LRU_HASH`，容量 1024）
- **命中**：在内核旁路直接构造应答（追加 answer、更新 UDP/IP 长度与校验和）→ `XDP_TX` 回包，不经过用户态与协议栈
- **未命中**：`XDP_PASS`，交给用户态 daemon 解析并回填
- `counters`（`BPF_MAP_TYPE_PERCPU_ARRAY`）记录 total/hit/miss/kernel_direct

## 与用户态 daemon 的协同

- 本项目默认以**用户态 LRU** 运行（无需本组件）。若启用 XDP 直答，需让 daemon 把未命中结果写进同名 `dns_cache` map 才能被内核命中：
  - Map 键值布局见 `ebpdns_xdp.h`（`dns_cache_key` / `dns_cache_val`）
  - 可用 `bpftool map update` 手工回填，或用 libbpf（C）/ bcc（Python）在 daemon 内集成
- 直答模式下建议将 `/etc/ebpdns/config.json` 的 `kernel_direct` 保持 `true`（语义与遥测一致）

## `map_type` 配置（BPF Map 类型语义标记）

`/etc/ebpdns/config.json` 的 `map_type` 字段对齐 BPF map 类型命名，合法值（保留大写）：

| `map_type` | BPF map 类型 | 适用场景 |
|---|---|---|
| `LRU_HASH`（默认） | `BPF_MAP_TYPE_LRU_HASH` | 哈希表 + LRU 自动淘汰，DNS 缓存最通用，本参考实现即此类型 |
| `LRU` | `BPF_MAP_TYPE_LRU` | 纯 LRU 链表（无哈希，按键遍历语义不同，DNS 缓存一般不用） |
| `LPM_TRIE` | `BPF_MAP_TYPE_LPM_TRIE` | 最长前缀匹配树，面向按网段路由的 key（如按目的 IP 网段分流） |

> **重要**：当前 daemon 为纯用户态 Python 实现，`map_type` **仅作语义标记与控制台/API 展示**，不改变实际淘汰引擎——淘汰策略由 `cache_policy`（`lru` / `partitioned` / `tinylfu`）决定。仅在把命中真正下沉到本 `bpf/` 内核数据面时，`map_type` 才对应到实际创建的 BPF map 类型。非法值启动时回退默认 `LRU_HASH` 并告警。

## 卸载

```bash
sudo ip link set dev eth0 xdp off
```

## 备注

`ebpdns_xdp.bpf.c` 为参考实现，请按你的内核版本与网卡适配（校验和、包长、加载方式等）。
该组件不参与默认部署；控制台「架构说明」将其标注为「可选内核数据面（预留）」节点。
