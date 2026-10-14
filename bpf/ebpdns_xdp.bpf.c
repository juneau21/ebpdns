/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ebpdns —— eBPF XDP 数据面: DNS 缓存内核直答
 *
 * 功能: 在网卡 XDP Hook 拦截发往本机 UDP/53 的 DNS 查询,
 *       解析 (qname, qtype) 后查询 BPF LRU_HASH 缓存;
 *       命中时在内核旁路直接构造应答并 XDP_TX 回包,
 *       不经过用户态与协议栈; 未命中则 XDP_PASS 交给用户态 daemon。
 *
 * 编译: 见 Makefile (需 clang + libbpf-dev + linux-libc-dev + bpftool)
 * 加载: 见 load.sh / README.md
 *
 * 注意: 这是参考数据面实现, 请按你的内核版本与网卡适配;
 *       默认软件(纯用户态)不依赖本程序也能完整工作。
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "ebpdns_xdp.h"

char LICENSE[] SEC("license") = "GPL";

/* ---------- BPF Maps ---------- */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	/* v1.9.158 P2-1: 编译期默认容量。实际容量由用户态 loader 在
	 * bpf_object__load 前用 bpf_map__set_max_entries(map, cfg.kernel_cache_max)
	 * 覆盖(BTF-defined map 支持 load 前改容量)；此值仅作未覆盖时的兜底。 */
	__uint(max_entries, 65536);
	__type(key, struct dns_cache_key);
	__type(value, struct dns_cache_val);
} dns_cache SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, CNT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

/* ---------- 工具函数 ---------- */
/* v1.9.150 R-fix: 加 __attribute__((unused))。此前该函数未被引用, 而 Makefile 带
 * -Werror, Debian 13 的 clang 19 会以 "unused function 'qname_hash'" 直接编译失败,
 * 使本参考实现**根本编译不出来**。保留函数(与 daemon 哈希口径一致的参考)但不参与构建告警。 */
static __always_inline __attribute__((unused)) __u64 qname_hash(const __u8 *name, __u32 n)
{
	/* djb2 —— 与用户态 daemon 保持一致 */
	__u64 h = 5381;
	__u32 i;
	for (i = 0; i < n && name[i]; i++)
		h = ((h << 5) + h) + name[i];
	return h;
}

static __always_inline __u16 checksum(const void *buf, __u32 len, __u32 sum)
{
	const __u16 *p = buf;
	while (len > 1) {
		sum += *p++;
		len -= 2;
	}
	if (len)
		sum += *(const __u8 *)p;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return ~(__u16)sum;
}

/* 解析 DNS question 中的 qname, 返回其字节长度(含根标签, 相对 pkt 起点从 off 起算)
 *
 * v1.9.150 R-fix(verifier, 第二轮): 前一轮把越界检查放进 `while (off < end)` 循环,
 * 但 `off` 仍是**运行期变量**, 且内层 `pkt[off + 1 + i]` 是变量下标包读取, 校验器
 * 无法建立范围证明, 实测(Debian 13 / kernel 6.12, clang 19)仍拒绝:
 *   invalid access to packet, off=34 size=1, R3(id=3,off=34,r=34)
 *   R3 offset is outside of the packet
 * 关键事实: 本机最小 XDP 程序可正常加载, 故是**本结构的证明问题**而非主机限制。
 *
 * 现改为 eBPF 惯例的**固定深度展开扫描**: 外层按标签推进(最多 32 个),
 * 内层按标签内字节推进(最多 63 个), 两层都以编译期常量作为上界并 #pragma unroll。
 * 每次读取前用 `(void *)(p + n) > data_end` 形式的**指针比较**表达边界 ——
 * 这是校验器能跟踪的写法(与本文件 eth/ip/udp 各层的检查同型)。
 * 任一越界/压缩指针/非法标签即返回 -1(保守 miss, 交给用户态 daemon)。
 * 哈希算法与 daemon 保持一致: djb2, 涵盖标签长度字节与标签内容。 */
static __always_inline int parse_qname(const __u8 *pkt, __u32 off, __u32 end,
				       __u64 *hash, const __u8 *pkt_end)
{
	__u64 h = 5381;
	__u32 start = off;

	/* 不写 #pragma unroll: 32×63 两层展开会超出 clang 的一元展开预算并报
	 * "loop not unrolled ... -Wpass-failed"(实测)。内核 6.12 支持有界循环,
	 * 故把每个循环的**最大行程**做成可证明的小常量即可, 由校验器自行验证。 */
	for (int lab = 0; lab < 32; lab++) {
		if (off >= end)
			return -1;
		if ((const void *)(pkt + off) + 1 > (const void *)pkt_end)
			return -1;
		__u8 len = pkt[off];
		if (len == 0) {
			off++;
			break;
		}
		if ((len & 0xc0) == 0xc0)
			return -1;          /* 压缩指针: 查询中不应出现, 保守放弃 */
		if (len > 63)
			return -1;          /* 标签长度上限 RFC 1035 */
		h = ((h << 5) + h) + len;
		off++;

		/* 行程上界 63: len 已由上面 `len > 63` 的检查夹到 [1,63] */
		for (int i = 0; i < 63; i++) {
			if (i >= (int)len)
				break;
			if (off >= end)
				return -1;
			if ((const void *)(pkt + off) + 1 > (const void *)pkt_end)
				return -1;
			/* v1.9.158 P0-1: DNS 查询名大小写不敏感。用户态 daemon 回写 key 前
			 * 先对每个标签 .lower()，此处哈希内容字节必须同步小写化，否则 0x20
			 * 大小写随机化或非全小写查询的 wire 原始字节哈希与用户态小写 key 不一致，
			 * 内核 lookup 永不命中(整套路由直答形同虚设)。标签长度字节(0..63)无需小写。 */
			__u8 cb = pkt[off];
			if (cb >= 'A' && cb <= 'Z')
				cb += 32;
			h = ((h << 5) + h) + cb;
			off++;
		}
	}
	*hash = h;
	return (int)(off - start);
}

/* ---------- XDP 入口 ---------- */
SEC("xdp")
int ebpdns_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u32 idx;

	/* 计数 total */
	idx = CNT_TOTAL;
	__u64 *total = bpf_map_lookup_elem(&counters, &idx);
	if (total)
		__sync_fetch_and_add(total, 1);

	/* 以太网帧 */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	/* IPv4 */
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;
	/* 版本硬校验: 以太网类型已是 ETH_P_IP, 正常包 version 恒为 4; 此处显式拒绝
	 * 非 IPv4 报文(畸形/伪装包), 避免按 IPv4 布局误读后续字段。 */
	if (ip->version != 4)
		return XDP_PASS;
	/* 非首片分片守卫: 片偏移(frag_off 低 13 bit)非 0 的中/尾分片**不含 L4 头**,
	 * ip+ihl 处并不是 UDP。若不拒绝, 会把分片载荷误当 UDP/53 查询解析, 命中缓存后
	 * 在内核侧构造并 XDP_TX 出一个与真实会话无关的错误应答。这类包一律放过交协议栈。
	 * (首片 MF=1 但片偏移=0, 仍含完整 UDP 头, 不在此拒绝。) */
	if (bpf_ntohs(ip->frag_off) & 0x1fff)
		return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;
	__u32 ip_hlen = ip->ihl * 4;
	/* ihl 为 4 bit → 0..15 → *4 = 0..60。下界 <20 拒绝 ihl<5(无选项);
	 * v1.9.160 R-fix: 显式加上界 >60, 让校验器把 ip_hlen 夹进 [20,60] 常量域。 */
	if (ip_hlen < 20 || ip_hlen > 60)
		return XDP_PASS;

	/* UDP */
	struct udphdr *udp = (void *)ip + ip_hlen;
	if ((void *)(udp + 1) > data_end)
		return XDP_PASS;
	if (udp->dest != bpf_htons(53))
		return XDP_PASS;

	/* v1.9.150 R-fix(verifier): 一律使用"字典序比较 + 有界偏移"的标准写法,
	 * 不再用 (__u8*)data + dns_off 这类由 32 位标量推导出的包指针。
	 * v1.9.160 R-fix: 删除 `udp_off = udp - data`。该标量后续在 shrink 后用
	 * `data + udp_off` 重建 UDP 指针, 属"包指针 + 无界标量", 被校验器拒绝;
	 * 改为 shrink 后从 data 逐层(eth->ip->udp)用指针比较重建, 见命中路径末尾。 */

	/* DNS 头 12 字节: 以字节指针表达, 但由已证明有界的 udp 推导 */
	__u8 *dns = (__u8 *)udp + sizeof(struct udphdr);
	if (dns + 12 > (__u8 *)data_end)
		return XDP_PASS;

	/* v1.9.160 R-fix(verifier): 记录 dns 相对包头的偏移, 并夹到编译期常量上界。
	 * 该校验必须在 dns 定义之后。原偏移由指针相减得出, 校验器对纯标量差值不给范围
	 * (smax=0xffffffff), 于是 adjust_tail 之后用 `(__u8*)data + dns_off` 重建的
	 * 写入指针无法被证明落在包内, 报:
	 *   invalid access to packet, off=2 size=2, R5(id=74,off=2,r=0)
	 * 合法 DNS 报文的 DNS 段起点必然远小于以太网 MTU, 用宽松但编译期可知的常量
	 * 把它纳入可证明范围; 超过即视为异常包放过(交用户态 daemon, 不影响正确性)。 */
	__u32 dns_off = (__u32)(dns - (__u8 *)data);
	if (dns_off > 1500)
		return XDP_PASS;

	__u16 flags = bpf_ntohs(*(__u16 *)((__u8 *)udp + sizeof(struct udphdr) + 2));
	__u16 qdcount = bpf_ntohs(*(__u16 *)((__u8 *)udp + sizeof(struct udphdr) + 4));
	if (qdcount != 1)
		return XDP_PASS;

	/* DNS 段可用长度(整包减去 DNS 头偏移)。question 段的读取相对它做检查。 */
	__u32 dns_len = (__u32)((__u8 *)data_end - dns);

	/* question: qname + qtype + qclass */
	__u64 hash;
	int qlen = parse_qname(dns, 12, dns_len, &hash, (const __u8 *)data_end);
	if (qlen < 0)
		return XDP_PASS;
	/* parse_qname 返回的是"从 off 起算"的消耗长度, 故 question 结束处 = 12 + qlen */
	__u32 q_off = 12 + (__u32)qlen;
	/* v1.9.160 R-fix(verifier): qtype/qclass 的边界检查改用**指针形式**。
	 * 原写法 `if (q_off + 4 > dns_len)` 中 q_off 是运行期标量、dns_len 又是
	 * `data_end - dns` 推导出的另一个标量, 校验器无法把两条边界归并成"读取落在
	 * 包内"的证明, 于是 qname 较长时在 `*(__u16 *)(dns + q_off + 2)` 处报
	 *   invalid access to packet, off=100 size=2, R2(id=3,off=100,r=97)
	 * 即"已证明的包范围上界 97 < 需要读到 100"。改为先算出 question 结束位置的
	 * 字节指针, 再用与本文件各层一致的 `(void *)(p) > data_end` 比较 —— 该形式
	 * 校验器可以跟踪, 从而把 dns..dns+q_off+4 纳入同一已证明区间。 */
	if ((const void *)(dns + q_off) + 4 > (const void *)data_end)
		return XDP_PASS;
	__u16 qtype = bpf_ntohs(*(__u16 *)(dns + q_off));
	__u16 q_qclass = bpf_ntohs(*(__u16 *)(dns + q_off + 2));
	if (q_qclass != 1)   /* 仅处理 IN 类 */
		return XDP_PASS;

	/* dns_off 已在上方声明并夹到 1500 上界(供 adjust_tail 之后重新定位:
	 * adjust_tail 会使 data/data_end 重定位, 之前取得的包指针必须按偏移重新推导)。 */

	struct dns_cache_key key = {
		.qname_hash = hash,
		.qtype = qtype,
	};
	struct dns_cache_val *val = bpf_map_lookup_elem(&dns_cache, &key);
	/* v1.9.158: 命中三重检查 ——
	 *   1) val 非空 (lookup 未命中 LRU)
	 *   2) flags bit0=1 (valid, 用户态回填时置位)
	 *   3) expires_at 为 0 (永不过期) 或当前 boot_ns 尚未超过过期时间。
	 *      过期条目按 miss 处理: XDP_PASS 交给用户态重新解析, 由用户态
	 *      回写新条目时刷新 expires_at。bpf_ktime_get_boot_ns() 自内核 5.7
	 *      起可用, Debian 13 的 6.12 满足要求。
	 * 注意: 本判断在 bpf_xdp_adjust_tail 之前, 无指针越界风险, verifier 安全。 */
	if (!val || !(val->flags & 1) ||
	    (val->expires_at && bpf_ktime_get_boot_ns() > val->expires_at))
		goto miss;

	/* ============ 命中: 构造应答并直接回包 ============ */
	/* v1.9.158 P0-2: 每条应答 RR 线长 = 12(头: name2+type2+class2+ttl4+rdlen2)
	 * + rdata(AAAA=16 / A=4)。v1.9.159 R2-1: 按地址族精确累加实际 RR 字节(AAAA=28 /
	 * A=16)扩容, 写完后再 shrink 到实际 write_off —— 彻底消除尾部:
	 *   - 纯 A 应答不再每条预留 28 只写 16 留下垃圾尾;
	 *   - EDNS 查询的 OPT(ARCOUNT=1) 残留在 question 之后, answer 从 q_off+4 覆写,
	 *     未被覆盖的 OPT 尾部也由 shrink 裁掉。
	 * 这样 UDP len / IP tot_len 精确等于实际写入末字节, 严格解析器(dnspython)
	 * from_wire 不再报 TrailingJunk。 */
	/* v1.9.160 R-fix: 删除未使用的 orig_len。原为
	 *   `int orig_len = (int)((void *)data_end - (void *)data);`
	 * 但下方 shrink 分支自行用 cur_len 重算当前长度, orig_len 从未被读取。
	 * 在 Makefile 的 -Werror 下 clang 19 直接报
	 *   "error: unused variable 'orig_len' [-Werror,-Wunused-variable]"
	 * 导致 ebpdns_xdp.o 编译失败 → bpf_loader 找不到目标文件 → kernel_cache
	 * 恒降级为"未找到 eBPF 目标文件", 功能完全不可用(实测 Debian 13)。 */
	int rr_bytes = 0;
#pragma unroll
	for (int i = 0; i < EBP_MAX_ADDRS; i++) {
		if (i >= (int)val->naddr)
			break;
		rr_bytes += (val->addr_af[i] == 1) ? 28 : 16;
	}
	int grow = rr_bytes;
	if (bpf_xdp_adjust_tail(ctx, grow) < 0)
		goto miss;
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	/* v1.9.161 R-fix(verifier, 决定性): 用**编译期常量偏移**定位 DNS 段。
	 *
	 * 实测失败机理(Debian 13 / kernel 6.12 / clang 19):
	 *   dns_off 由 `dns - data` 指针相减得出, 校验器只当它是普通标量。而
	 *     bpf_map_lookup_elem()  (缓存查询)
	 *     bpf_xdp_adjust_tail()  (扩容)
	 *   这两次 helper 调用**清空所有标量的范围跟踪**, dns_off 恢复成
	 *   smin=0/smax=0xffffffff; 且它被溢出到栈后取回(fp-56), 范围信息彻底丢失,
	 *   表现为 `R5(id=73,off=2,r=0)` —— **r=0 表示该包指针完全无范围**。
	 *   于是 `data + dns_off` 属"包指针 + 最小值无界的寄存器", 校验器直接拒绝:
	 *     invalid access to packet, off=2 size=2, R5(id=73,off=2,r=0)
	 *   (实测: 在其后**再夹一次** `if (dns_off > 1500)` 也无效 —— 因为被夹取的
	 *    仍是同一个已丢范围的栈槽, 校验器不认。)
	 *
	 * 修法: 不再用变量偏移构造包指针。dns 段起点只可能是
	 *     eth(14) + ip_hlen(20..60, 4 的倍数) + udp(8)
	 * 用**常量**逐个枚举(11 种 ip_hlen 取值), 与读取阶段取得的 dns 指针比较,
	 * 命中者即 dns_off。全程只有"包指针 + 常量子"与常量指针比较, 校验器只需对
	 * 每个常量做一次 range 检查, 无需任何标量范围推断。
	 * 找不到即视为异常包, 交用户态处理(miss)。 */
	__u8 *dns2 = NULL;
#pragma unroll
	for (__u32 _ihl = 20; _ihl <= 60; _ihl += 4) {
		if (dns2)
			continue;
		__u32 _off = sizeof(struct ethhdr) + _ihl + sizeof(struct udphdr);
		/* 该常量偏移处必须容纳 DNS 头与 question 段 */
		if ((void *)((__u8 *)data + _off) + 12 > data_end)
			continue;
		if ((void *)((__u8 *)data + _off + q_off) + 4 > data_end)
			continue;
		if ((__u8 *)data + _off == (__u8 *)dns)
			dns2 = (__u8 *)data + _off;
	}
	if (!dns2)
		goto miss;
	/* 供后续 shrink 计算使用(此时该值与 dns2 一致, 仅作标量记录) */
	dns_off = (__u32)((__u8 *)dns2 - (__u8 *)data);
	/* dns2 已在上面用常量偏移 + 指针比较建立区间; 此处无需再派生 */

	/* v1.9.158 P1-2: 应答 flags。host 序下:
	 *   - 保留查询 RD(0x0100);
	 *   - 置 QR(0x8000) | RA(0x0080) = 0x8080;
	 *   - 写 RCODE 低 4 位 = val->rcode(0=NOERROR / 3=NXDOMAIN)。
	 * 原实现只 OR 0x8080,RCODE 原样回显自查询(恒 0),导致 NXDOMAIN 负缓存被内核
	 * 答成 NOERROR 空应答(NODATA 语义),破坏否定缓存。 */
	flags = (flags & 0x0100) | 0x8080 | (val->rcode & 0x000f);
	*(__u16 *)(dns2 + 2) = bpf_htons(flags);
	*(__u16 *)(dns2 + 6) = bpf_htons(val->naddr);
	/* v1.9.159 N2: 本程序只回 answer, 不回放 authority / EDNS OPT。查询常带
	 * OPT(ARCOUNT=1), answer 覆写会覆盖原 OPT 位置, 必须把 NSCOUNT/ARCOUNT 清零,
	 * 否则客户端按附加段解析会读到错位字节。QDCOUNT(dns2+4) 保持查询值 1 不动。 */
	*(__u16 *)(dns2 + 8) = 0;    /* NSCOUNT */
	*(__u16 *)(dns2 + 10) = 0;   /* ARCOUNT */

	/* v1.9.158 P3-2: DNS 事务 ID(dns2+0)随 question 段原样保留, 全程未改动 ——
	 * 客户端按 ID 匹配即可。原先在此回读再写回同一值是 no-op, 已删除。 */

	/* v1.9.150 R-fix: question 段必须完整保留(0x20 大小写也要保留), 不改动。 */

	/* 在 question 后追加 answer 记录。
	 * v1.9.150 R-fix(verifier): 原来以 map value 的 val->naddr 作为循环上界
	 * (`for (i = 0; i < val->naddr; i++)`), BPF 校验器要求循环上界编译期可知,
	 * 否则**直接拒绝加载**。改为固定上界 EBP_MAX_ADDRS + 显式边界检查,
	 * 并对循环加 #pragma unroll 便于校验器展开。 */
	/* v1.9.159 N1: q_off=12+qlen 是 qname 结束位置 = qtype 起始偏移。question 段为
	 * [12, q_off+4)(qname + qtype2 + qclass2), 首条 answer RR 必须从 q_off+4 起写,
	 * 否则会覆盖 qtype/qclass(question qtype 被写成 0xc00c, 客户端解析错位)。 */
	/* v1.9.160 R-fix(verifier): answer 写循环改为 **pos 指针递进**。
	 * 起始 pos = dns2 + q_off + 4, 其上界(<= data_end)已由上方两道重证明建立。
	 * 原写法 `rr = dns2 + write_off`、边界 `write_off+28 > (data_end-data)-dns_off`
	 * 是无界标量差比较, 校验器无法据此证明 rr 在包内(报 math between pkt pointer and
	 * register with unbounded min value)。改为每写一条前按地址族用**常量指针比较**
	 * `(void*)(pos+28) > data_end` / `(void*)(pos+16) > data_end`, 写完 pos += 28/16。
	 * 校验器可跟踪 pos 单调推进, 且每次解引用前都有指针证明。 */
	__u8 *pos = dns2 + q_off + 4;
#pragma unroll
	for (int i = 0; i < EBP_MAX_ADDRS; i++) {
		if (i >= (int)val->naddr)
			break;
		__u16 rtype, rdlen;
		if (val->addr_af[i] == 1) {          /* AAAA: 12 头 + 16 rdata = 28 */
			if ((void *)(pos + 28) > data_end)
				break;
			rtype = 28; rdlen = 16;
		} else {                             /* A: 12 头 + 4 rdata = 16 */
			if ((void *)(pos + 16) > data_end)
				break;
			rtype = 1; rdlen = 4;
		}
		/* name: 压缩指针指向 header 起始(0xC00C 指向报文 12 字节处) */
		*(__u16 *)pos = bpf_htons(0xc00c);
		*(__u16 *)(pos + 2) = bpf_htons(rtype);
		*(__u16 *)(pos + 4) = bpf_htons(1); /* IN */
		*(__u32 *)(pos + 6) = bpf_htonl(val->ttl);
		*(__u16 *)(pos + 10) = bpf_htons(rdlen);
		/* 按地址族分支的常量大小拷贝(内联加载/存储, 校验器接受)。 */
		if (rdlen == 16) {
			__builtin_memcpy(pos + 12, val->rdata[i], 16);
		} else {
			__builtin_memcpy(pos + 12, val->rdata[i], 4);
		}
		pos += (rdlen == 16) ? 28 : 16;
	}

	/* v1.9.160 R-fix(verifier): shrink 到 pos(实际写入末字节)。
	 * grow=rr_bytes 扩容后, EDNS OPT 残留 / 纯 A 预留余量位于 pos..data_end。
	 * 由循环边界已知 pos <= data_end, 故 shrink = data_end - pos >= 0(同基指针差,
	 * 非无界标量)。二次 adjust_tail 后 data/data_end 重定位, 旧指针全部失效。 */
	if ((void *)pos < (void *)data_end) {
		long shrink = (long)((__u8 *)data_end - pos);
		if (shrink > 0) {
			if (bpf_xdp_adjust_tail(ctx, -shrink) < 0)
				goto miss;
			data = (void *)(long)ctx->data;
			data_end = (void *)(long)ctx->data_end;
		}
	}

	/* v1.9.160 R-fix(verifier): shrink 后**逐层重建指针并建立范围证明**。
	 * shrink 只裁 answer 尾部, eth/ip/udp 头不变; 但 adjust_tail 使旧指针失效,
	 * 必须从 data 起每层解引用前用 `(void*)(p+1) > data_end` 重新证明, 不再用
	 * `data + udp_off`(无界标量)构造指针。 */
	struct ethhdr *eth2 = data;
	if ((void *)(eth2 + 1) > data_end)
		goto miss;
	struct iphdr *ip2 = (void *)(eth2 + 1);
	if ((void *)(ip2 + 1) > data_end)
		goto miss;
	/* ihl 已在读取路径夹到 [20,60]; 此处重证 ip2+ihl <= data_end(供 checksum 读)。 */
	if (ip2->ihl < 5 || ip2->ihl > 15)
		goto miss;
	{
		__u32 ihl = (__u32)ip2->ihl * 4;
		if ((void *)((__u8 *)ip2 + ihl) > data_end)
			goto miss;
		struct udphdr *udp2 = (void *)((__u8 *)ip2 + ihl);
		if ((void *)(udp2 + 1) > data_end)
			goto miss;

		/* MAC 交换 */
		__u8 tmp_mac[ETH_ALEN];
		__builtin_memcpy(tmp_mac, eth2->h_source, ETH_ALEN);
		__builtin_memcpy(eth2->h_source, eth2->h_dest, ETH_ALEN);
		__builtin_memcpy(eth2->h_dest, tmp_mac, ETH_ALEN);

		/* IP 交换 */
		__be32 tmp_ip = ip2->saddr;
		ip2->saddr = ip2->daddr;
		ip2->daddr = tmp_ip;

		/* port 交换 */
		__be16 tmp_port = udp2->source;
		udp2->source = udp2->dest;
		udp2->dest = tmp_port;

		/* UDP 长度 = data_end - udp2(指针差, 已证 udp2 <= data_end); 不用 pkt_len2-udp_off。 */
		udp2->len = bpf_htons((__u16)((__u8 *)data_end - (__u8 *)udp2));
		udp2->check = 0; /* IPv4 UDP checksum 可置 0 */

		/* IP tot_len = data_end - ip2; checksum 基于已证明在界内的 ip2..ip2+ihl。 */
		ip2->tot_len = bpf_htons((__u16)((__u8 *)data_end - (__u8 *)ip2));
		ip2->check = 0;
		ip2->check = checksum(ip2, ihl, 0);
	}

	/* 计数 */
	idx = CNT_HIT;
	__u64 *hit = bpf_map_lookup_elem(&counters, &idx);
	if (hit)
		__sync_fetch_and_add(hit, 1);
	idx = CNT_KERNEL_DIRECT;
	__u64 *kd = bpf_map_lookup_elem(&counters, &idx);
	if (kd)
		__sync_fetch_and_add(kd, 1);

	return XDP_TX;

miss:
	idx = CNT_MISS;
	__u64 *m = bpf_map_lookup_elem(&counters, &idx);
	if (m)
		__sync_fetch_and_add(m, 1);
	return XDP_PASS;
}
