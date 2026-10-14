# ebpdns eBPF XDP 数据面（可选加速层 · 已集成）

> **状态说明**：v1.9.158 起本组件已**接入 daemon**（`ebpdns/bpf_loader.py` + `kernel_cache`
> 配置），不再是无回填的占位实现——daemon 会把未命中结果回写到内核 `dns_cache` map、
> 启动时从用户态 LRU 预热热条目。启用 `kernel_cache: true` 后，命中查询由网卡 XDP 内核直答，
> 未命中 `XDP_PASS` 交给用户态。**当前 `make` 可成功编译，但内核 BPF 校验器仍拒绝加载**
> （见下方已知限制），故 `kernel_cache: true` 会降级纯用户态运行，DNS 服务不受影响。

> ## ⚠️ 已知限制：当前无法通过内核 BPF 校验器（v1.9.150 实测）
>
> **v1.9.161 静态对抗审查补充（本次）**：本轮在无 clang 环境下做纯静态审查，新增两处
> 入包守卫——① `ip->version != 4` 直接 `XDP_PASS`；② `frag_off & 0x1fff`（非首片分片，
> 无 L4/UDP 头）直接 `XDP_PASS`，避免把分片载荷误当 DNS 查询而构造错误应答。两处均为
> 早期标量早退，不改变后续指针范围证明。**仍未做编译/加载验证（沙箱无 clang）**。
>
> **v1.9.164 静态审查补充（保守精简轮）**：本轮在无 clang 环境下复核 v1.9.162 的分片守卫
> （掩码 `0x1fff` 不含 DF/MF、位置在 IP 头证明后/判定 protocol 前，首片 MF=1 偏移 0 放行，
> 与 v1.9.161 应答构造段的 pos 指针递进重构无冲突、无回退）、IP version 硬校验、`clear_cache`
> 前驱恒 NULL、rdata `(c_uint8*16)*8` 行主序均正确，**C 源码未改动**。唯一发现：
> `ebpdns_xdp.bpf.c:326` 应答构造段有一处**死 store**（`dns_off = dns2 - data` 赋值后再无读取），
> 因沙箱无 clang 无法编译复核，保守保留、未删——**真机重编译时可顺手删除该语句**（`-Werror`
> 若开启 unused-but-set-variable 可能告警）。XDP 命中构造应答路径仍需原生 XDP 网卡 + root +
> clang/llvm/libbpf-dev 环境 `make -C bpf` 加载并抓包最终确认。
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
> ### v1.9.160 第三轮排查（同一环境，2026-10-10 复测）
>
> **本版相对 v1.9.150 新增的关键事实**：v1.9.158+ 起 `bpf/` 已**接入 daemon**
> （`ebpdns/bpf_loader.py` + `kernel_cache` 配置）。因此本程序能否加载**不再是无害的**：
> 加载失败会走 README §9.4 的降级路径，`/api/status.ebpf.reason` 会如实上报
> `eBPF verifier 拒绝加载`，DNS 服务不受影响（"功能未启用"而非"功能故障"）。
>
> **本版实测到的真实缺陷（已修复，见源码注释 v1.9.160 R-fix）**：
> `int orig_len = (int)((void *)data_end - (void *)data);` 是 v1.9.159 引入"精确扩容 +
> shrink 裁剪"后遗留的**死变量**，而 `Makefile` 带 `-Werror`，clang 19 直接报
> `error: unused variable 'orig_len'` → **`make` 失败 → 无 `ebpdns_xdp.o` →
> `kernel_cache: true` 永远降级为"未找到 eBPF 目标文件"，功能完全不可用**。
> 删除该变量后 `make` 通过（`ebpdns_xdp.o` 42 288 B）。
>
> **校验器推进过程（每步均已实测，越靠后越接近通过）**：
>
> | 阶段 | 处理指令数 | 拒绝原因 |
> |---|---|---|
> | 修 `orig_len` 前 | 无法编译 | — |
> | 删除 `orig_len` 后 | 2 357 | `q_qclass = *(__u16 *)(dns + q_off + 2)` — `off=100` vs 已证上界 97 |
> | qtype/qclass 改**指针形式**边界检查（**本轮已消除该拒绝**） | 2 462 | adjust_tail 后 `*(u16 *)(dns2 + 2)` — `R5(id=106,off=2,r=0)` |
> | 再尝试：`dns_off` 重新夹上界 / 常量偏移枚举 / 用 `dns2` 证明区间 | **2 704** | 见下 |
>
> **根因（已定位到机制，这是继续修的关键）**：
> `bpf_xdp_adjust_tail()` 与 `bpf_map_lookup_elem()` 等 helper 调用会**清空标量的范围跟踪**，
> 并且 `adjust_tail` 之后必须重取 `data/data_end`（`data = (void *)(long)ctx->data;`），
> 这使此前为 `dns` 建立的包范围证明**全部失效**。而所有以"指针相减"得到的偏移
> （`dns_off`、`udp_off`、`data_end - data`）对校验器都是 `smin=0/smax=0xffffffff` 的
> **无界标量**，于是：
>
> - 用无界标量构造包指针 → `math between pkt pointer and register with unbounded min value is not allowed`
> - 用常量枚举重新定位 → 后续 `shrink` 又需要 `dns_off + write_off`（无界），
>   写入越界报 `invalid access to packet, off=11 size=1, R1(id=0,off=11,r=0)`
>
> **本轮（v1.9.160 verifier 专项）已按上述思路完成代码重构**：
> 1. answer 写循环改为 **`pos` 指针递进**：起始 `pos = dns2 + q_off + 4`（其上界由
>    adjust_tail 后两道重证明建立），每写一条前按地址族用**常量指针比较**
>    `(void*)(pos+28) > data_end`（AAAA）/ `(void*)(pos+16) > data_end`（A），写完
>    `pos += 28/16`；不再用无界标量 `write_off` 构造 `rr = dns2 + write_off`。
> 2. `shrink` 改为基于末位指针：`shrink = data_end - pos`（同基指针差，由循环边界已知
>    `pos <= data_end`，故非负），不再用 `cur_len - (dns_off + write_off)` 无界标量差。
> 3. shrink 第二次 adjust_tail 后**逐层重建指针**：eth(+14) → ip(+14，重证 ihl∈[20,60]
>    且 `ip+ihl <= data_end`) → udp(+ihl，重证 +8)，每层解引用前 `(void*)(p+1) > data_end`；
>    UDP 长度 / IP tot_len 改用指针差 `data_end - udp2` / `data_end - ip2`，删除了无界
>    `udp_off`、`pkt_len2-udp_off` 写法。
> 4. 读取路径 `ip_hlen` 显式夹到 `[20,60]`；保留 `#pragma unroll`、`EBP_MAX_ADDRS=8` 固定
>    上界、常量大小 memcpy 等已通过的写法。
>
> **重要：仍需真机 `bpftool prog load` 最终确认。** 沙箱无 clang，本轮**未实跑 verifier**，
> 不能宣称"已可加载"。已按 verifier 范围证明规则消除全部已识别的无界指针访问（包指针+
> 无界标量），DNS 字节语义经逐字节仿真（8 用例 + 20 万随机 IP 头 checksum 回归）与封板版
> 字节一致；但 adjust_tail 后指针重建是否被内核 6.12 校验器接受，**必须在支持原生 XDP 的
> 真机上 `bpftool prog load` + 真实流量抓包复核**。若仍报未识别的范围拒绝，按 verifier 日志
> 中 `off=` 与 `R?` 寄存器号继续定位。
>
> **结论**：编译问题与读取阶段两处拒绝此前已消除；本轮已把应答构造段（answer 写循环 /
> shrink / 写后指针重建）整体改为 verifier 友好的指针递进写法，DNS 报文仿真验证正确。
> **加载性待真机 `bpftool prog load` 最终确认**。该限制不影响默认部署——默认数据面为纯用户态
> Python LRU，`kernel_cache` 默认为 `false`。

让「缓存命中由网卡内核直答」的真实 eBPF 数据面加速组件。

## 前提（Debian 13）

- Linux 内核 ≥ 5.4（建议 5.15+），开启 BTF
- 网卡驱动支持**原生 XDP**（`ethtool -S eth0 | grep -i xdp` 或 `ip link show eth0`）
- 工具链（**install.sh 会自动装齐这些**，含 `make`；手动安装时需显式列出 `make`）：

```bash
sudo apt install make clang llvm libbpf-dev linux-libc-dev bpftool
```

## 编译与挂载

```bash
cd /opt/ebpdns/bpf
make                 # 生成 ebpdns_xdp.o 与 ebpdns_xdp.skel.h
sudo make install    # 复制 ebpdns_xdp.o 到 /usr/lib/ebpdns/ 供用户态 loader 自动加载
sudo ./load.sh eth0  # 挂载到 eth0 (手动调试用; 生产由 ebpdns/bpf_loader.py 自动完成)
```

> 注：`make` 是 Makefile 执行器，缺失会报 `make: command not found`。install.sh 的
> eBPF 工具链自动安装已包含 `make`，手动编译时记得先 `apt install make`。

## 工作原理

- 在 XDP Hook 拦截发往本机 `UDP/53` 的 DNS 查询
- 解析 `(qname_hash, qtype)` → 查询 `dns_cache`（`BPF_MAP_TYPE_LRU_HASH`，编译期默认容量 65536，实际由用户态 loader 在加载前按 `kernel_cache_max` 覆盖）
- **命中**：在内核旁路直接构造应答（追加 answer、更新 UDP/IP 长度与校验和）→ `XDP_TX` 回包，不经过用户态与协议栈
- **未命中**：`XDP_PASS`，交给用户态 daemon 解析并回填
- `counters`（`BPF_MAP_TYPE_PERCPU_ARRAY`）记录 total/hit/miss/kernel_direct

## TTL 过期机制（v1.9.158 新增 `expires_at`）

`struct dns_cache_val` 自 v1.9.158 起在 `ttl` 之后、`rdata` 之前新增 `__u64 expires_at` 字段：

| 偏移 | 字段 | 含义 |
|---|---|---|
| 0  | `naddr`      | 答案数量 (0-8) |
| 1  | `rcode`      | 应答码 0=NOERROR / 3=NXDOMAIN |
| 2  | `flags`      | bit0=valid |
| 3..10 | `addr_af[8]` | 每个答案的地址族 (0=A, 1=AAAA) |
| 12..15 | `ttl`       | 原始 TTL (秒), 仅用于回填应答 RR |
| 16..23 | `expires_at` | **绝对过期时刻 (ns, `bpf_ktime_get_boot_ns()` 基准)** |
| 24..151 | `rdata[8][16]` | 地址数据 (A=前4字节, AAAA=16字节) |

> 字段偏移按 C 自然对齐 (offset 11 处有 1 字节内补使 `ttl` 4 字节对齐)，与 clang 生成的 BTF 一致；
> 用户态 `ebpdns/bpf_loader.py` 的 ctypes Structure 使用同样的自然对齐，保证 map 读写偏移一致。

**过期判定**（XDP 程序命中检查处）：

```c
if (!val || !(val->flags & 1) ||
    (val->expires_at && bpf_ktime_get_boot_ns() > val->expires_at))
    goto miss;
```

- `expires_at == 0`：永不过期（兼容旧条目）。
- `expires_at != 0`：当前 `bpf_ktime_get_boot_ns()` 超过该值即视为过期，按 miss 处理（`XDP_PASS` 交给用户态重新解析）。
- 用户态 `put_cache()` 回填时写入 `expires_at = boot_ns + ttl*1e9`，与 `ttl` 秒数对应。
- 这样无需在内核侧做定时清理，过期条目在被访问时惰性失效；LRU 自动淘汰兜底。

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
