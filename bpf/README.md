# ebpdns eBPF XDP 数据面（预留接口 · 占位参考）

> **状态说明**：本组件为**占位参考实现**，当前 daemon（Python 用户态 LRU 数据面）**尚未集成**——即使编译挂载，内核 `dns_cache` map 因无用户态回填而恒为空，不会产生任何加速。启用需另行开发 daemon 侧 libbpf/bcc 回填集成，且需网卡支持**原生 XDP**（云虚拟机 virtio 网卡通常不支持）。

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

## 卸载

```bash
sudo ip link set dev eth0 xdp off
```

## 备注

`ebpdns_xdp.bpf.c` 为参考实现，请按你的内核版本与网卡适配（校验和、包长、加载方式等）。
该组件不参与默认部署；控制台「架构说明」将其标注为「可选内核数据面（预留）」节点。
