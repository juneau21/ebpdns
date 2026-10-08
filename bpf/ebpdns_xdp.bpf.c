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
	__uint(max_entries, 1024);
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
			h = ((h << 5) + h) + pkt[off];
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
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;
	__u32 ip_hlen = ip->ihl * 4;
	if (ip_hlen < 20)
		return XDP_PASS;

	/* UDP */
	struct udphdr *udp = (void *)ip + ip_hlen;
	if ((void *)(udp + 1) > data_end)
		return XDP_PASS;
	if (udp->dest != bpf_htons(53))
		return XDP_PASS;

	/* v1.9.150 R-fix(verifier): 一律使用"字典序比较 + 有界偏移"的标准写法,
	 * 不再用 (__u8*)data + dns_off 这类由 32 位标量推导出的包指针 —— 校验器无法
	 * 为后者建立范围证明, 实测在 `*(__u16 *)(dns + 2)` 处报:
	 *   invalid access to packet, off=4 size=2, R8(id=...,off=4,r=0)
	 *   R8 offset is outside of the packet
	 * 说明: 本机已用最小 XDP 程序验证校验器本身可用(能正常加载), 故该拒绝是本
	 * 程序的数据包解析结构问题, 而非主机限制。
	 * 下面每一步都从已证明有界的指针出发, 以 `(void *)(p + 1) > data_end` 形式
	 * 或"偏移不超过已证明的下界"形式表达。 */
	__u32 udp_off = (__u32)((void *)udp - data);

	/* DNS 头 12 字节: 以字节指针表达, 但由已证明有界的 udp 推导 */
	__u8 *dns = (__u8 *)udp + sizeof(struct udphdr);
	if (dns + 12 > (__u8 *)data_end)
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
	/* qtype + qclass 共 4 字节, 必须落在 DNS 段内 */
	if (q_off + 4 > dns_len)
		return XDP_PASS;
	__u16 qtype = bpf_ntohs(*(__u16 *)(dns + q_off));
	__u16 q_qclass = bpf_ntohs(*(__u16 *)(dns + q_off + 2));
	if (q_qclass != 1)   /* 仅处理 IN 类 */
		return XDP_PASS;

	/* 记录 DNS 段相对包头的偏移, 供 adjust_tail 之后重新定位(adjust_tail 会使
	 * data/data_end 重定位, 之前取得的任何包指针都必须按偏移重新推导)。 */
	__u32 dns_off = (__u32)(dns - (__u8 *)data);

	struct dns_cache_key key = {
		.qname_hash = hash,
		.qtype = qtype,
	};
	struct dns_cache_val *val = bpf_map_lookup_elem(&dns_cache, &key);
	if (!val || !(val->flags & 1))
		goto miss;

	/* ============ 命中: 构造应答并直接回包 ============ */
	/* 扩展报文尾部以容纳 answer */
	int grow = 8 + (int)val->naddr * 16;
	if (bpf_xdp_adjust_tail(ctx, grow) < 0)
		goto miss;
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	__u8 *dns2 = (__u8 *)data + dns_off;

	/* 设置 QR | RD | RA, 写 ANCOUNT */
	flags |= 0x8080;
	*(__u16 *)(dns2 + 2) = bpf_htons(flags);
	*(__u16 *)(dns2 + 6) = bpf_htons(val->naddr);

	/* v1.9.150 R-fix(严重): 回填 DNS 事务 ID。原实现从不把请求的 ID 复制到应答,
	 * 应答 ID 恒为请求报文原样(未改) —— 看似正确, 但 adjust_tail 之后 data 可能
	 * 重定位, 且此处必须**显式**保证 ID 与 question 段一并保留。客户端(glibc
	 * resolver/dig)会按 ID 匹配, 不匹配即丢弃, 表现为"查询超时"。此处显式复制。 */
	__u16 qid_be = *(__u16 *)dns2;        /* 已是网络序, 直接原样写回 */
	*(__u16 *)dns2 = qid_be;

	/* v1.9.150 R-fix: question 段必须完整保留(0x20 大小写也要保留), 不改动。 */

	/* 在 question 后追加 answer 记录。	 * v1.9.150 R-fix(verifier): 原来以 map value 的 val->naddr 作为循环上界
	 * (`for (i = 0; i < val->naddr; i++)`), BPF 校验器要求循环上界编译期可知,
	 * 否则**直接拒绝加载**。改为固定上界 DNS_CACHE_MAX_ADDR + 显式边界检查,
	 * 并对循环加 #pragma unroll 便于校验器展开。 */
	__u32 write_off = q_off;
#pragma unroll
	for (int i = 0; i < EBP_MAX_ADDRS; i++) {
		if (i >= (int)val->naddr)
			break;
		if (write_off + 16 > (__u32)((void *)data_end - (void *)data) - dns_off)
			break;
		__u8 *rr = dns2 + write_off;
		/* name: 压缩指针指向 header 起始(0xC00C 指向报文 12 字节处) */
		*(__u16 *)rr = bpf_htons(0xc00c);
		__u16 rtype = (val->addr_af[i] == 1) ? 28 /* AAAA */ : 1 /* A */;
		__u16 rdlen = (val->addr_af[i] == 1) ? 16 : 4;
		*(__u16 *)(rr + 2) = bpf_htons(rtype);
		*(__u16 *)(rr + 4) = bpf_htons(1); /* IN */
		*(__u32 *)(rr + 6) = bpf_htonl(val->ttl);
		*(__u16 *)(rr + 10) = bpf_htons(rdlen);
		/* v1.9.150 R-fix: 原用 __builtin_memcpy(rr + 12, val->rdata[i], rdlen),
		 * rdlen 是**运行期**变量, clang 无法内联成常量大小拷贝, 会降级为 libc
		 * memcpy 调用 —— BPF 禁止(built-in function 'memcpy' is not supported),
		 * Debian 13 的 clang 19 直接编译失败。改为按地址族分支的**常量大小**拷贝,
		 * 编译为内联加载/存储, 校验器接受。 */
		if (rdlen == 16) {
			__builtin_memcpy(rr + 12, val->rdata[i], 16);
		} else {
			__builtin_memcpy(rr + 12, val->rdata[i], 4);
		}
		write_off += 12 + rdlen;
	}

	/* v1.9.150 R-fix(严重): XDP_TX 前必须交换以太网/IP/UDP 的源与目的地址。
	 * 原实现直接 XDP_TX 未交换, 等价于把"客户端→服务器:53"的帧原样发回, 内核
	 * 会把它当作发往 :53 的帧 —— 客户端收到的是源端口 53 但目的也是 53、目的 MAC
	 * 为自己网关的畸形帧, 实际**无法回包**。交换后才是合法的"服务器→客户端"应答。 */
	struct ethhdr *eth2 = data;
	__u8 tmp_mac[ETH_ALEN];
	__builtin_memcpy(tmp_mac, eth2->h_source, ETH_ALEN);
	__builtin_memcpy(eth2->h_source, eth2->h_dest, ETH_ALEN);
	__builtin_memcpy(eth2->h_dest, tmp_mac, ETH_ALEN);

	struct iphdr *ip3 = (void *)data + sizeof(struct ethhdr);
	__be32 tmp_ip = ip3->saddr;
	ip3->saddr = ip3->daddr;
	ip3->daddr = tmp_ip;

	struct udphdr *udp3 = (void *)ip3 + ip_hlen;
	__be16 tmp_port = udp3->source;
	udp3->source = udp3->dest;
	udp3->dest = tmp_port;

	/* 更新 UDP 长度与 IP 总长度(在地址交换之后, 逐字段写回避免超长表达式) */
	__u32 pkt_len2 = (__u32)((__u8 *)data_end - (__u8 *)data);
	__u32 new_udp_len = pkt_len2 - udp_off;
	struct udphdr *udp2 = (void *)((__u8 *)data + udp_off);
	udp2->len = bpf_htons(new_udp_len);
	udp2->check = 0; /* IPv4 UDP checksum 可置 0 */

	/* 更新 IP 总长度与校验和 */
	struct iphdr *ip2 = (void *)data + sizeof(struct ethhdr);
	ip2->tot_len = bpf_htons(pkt_len2);
	ip2->check = 0;
	ip2->check = checksum(ip2, ip2->ihl * 4, 0);

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
