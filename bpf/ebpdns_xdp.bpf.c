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
static __always_inline __u64 qname_hash(const __u8 *name, __u32 n)
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

/* 解析 DNS question 中的 qname, 返回其字节长度(不含根) */
static __always_inline int parse_qname(const __u8 *pkt, __u32 off, __u32 end,
				       __u64 *hash)
{
	__u64 h = 5381;
	__u32 start = off;
	while (off < end) {
		__u8 len = pkt[off];
		if (len == 0) {
			off++;
			break;
		}
		if ((len & 0xc0) == 0xc0) {
			/* 压缩指针(查询中极少见), 保守返回 0 */
			return -1;
		}
		if (off + 1 + len > end)
			return -1;
		/* 哈希包含标签长度字节, 保证与 daemon 一致 */
		h = ((h << 5) + h) + len;
		for (__u32 i = 0; i < len; i++)
			h = ((h << 5) + h) + pkt[off + 1 + i];
		off += 1 + len;
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

	__u32 l4_off = (__u32)((void *)ip - data) + ip_hlen;
	__u32 dns_off = l4_off + 8;
	if (dns_off + 12 > (__u32)((void *)data_end - (void *)data))
		return XDP_PASS;

	/* DNS header */
	__u8 *dns = (__u8 *)data + dns_off;
	__u16 flags = bpf_ntohs(*(__u16 *)(dns + 2));
	__u16 qdcount = bpf_ntohs(*(__u16 *)(dns + 4));
	if (qdcount != 1)
		return XDP_PASS;

	/* question: qname + qtype + qclass */
	__u64 hash;
	int qlen = parse_qname(dns + 12, 0, 255, &hash);
	if (qlen < 0)
		return XDP_PASS;
	__u32 q_off = 12 + (__u32)qlen;
	if (q_off + 4 > (__u32)((void *)data_end - (void *)data) - dns_off)
		return XDP_PASS;
	__u16 qtype = bpf_ntohs(*(__u16 *)(dns + q_off));

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

	/* 在 question 后追加 answer 记录 */
	__u32 write_off = q_off;
	for (__u32 i = 0; i < val->naddr; i++) {
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
		__builtin_memcpy(rr + 12, val->rdata[i], rdlen);
		write_off += 12 + rdlen;
	}

	/* 更新 UDP 长度 */
	__u32 new_len = dns_off + (__u32)((void *)data_end - (void *)data) - l4_off;
	struct udphdr *udp2 = (void *)data + l4_off;
	udp2->len = bpf_htons(new_len);
	udp2->check = 0; /* IPv4 UDP checksum 可置 0 */

	/* 更新 IP 总长度与校验和 */
	struct iphdr *ip2 = (void *)data + sizeof(struct ethhdr);
	__u32 tot = (__u32)((void *)data_end - (void *)data);
	ip2->tot_len = bpf_htons(tot);
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
