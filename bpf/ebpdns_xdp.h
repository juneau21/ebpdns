/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ebpdns —— eBPF 数据面共享定义 (ebpdns_xdp.h)
 * 本头文件被 ebpdns_xdp.bpf.c 与用户态 daemon 引用, 描述 BPF Map 布局。
 *
 * 部署要求: Linux 内核 >= 5.4 (建议 5.15+), 开启 BTF, 网卡驱动支持原生 XDP。
 */
#ifndef __EBPDNS_XDP_H
#define __EBPDNS_XDP_H

#include <linux/types.h>
#include <linux/bpf.h>

/* 缓存键: (qname 哈希, qtype) —— 与用户态 daemon 约定一致 */
struct dns_cache_key {
	__u64 qname_hash;
	__u16 qtype;
	__u16 pad;
};

/* 缓存值: 答案集合 (最多 8 个地址) */
#define EBP_MAX_ADDRS 8
struct dns_cache_val {
	__u8  naddr;          /* 答案数量 */
	__u8  rcode;          /* 应答码 0=NOERROR 2=SERVFAIL 3=NXDOMAIN */
	__u8  flags;          /* bit0: valid */
	__u8  addr_af[EBP_MAX_ADDRS]; /* 0=IPv4(A) 1=IPv6(AAAA) */
	__u32 ttl;
	__u8  rdata[EBP_MAX_ADDRS][16];
};

/* 计数器索引 (PERCPU_ARRAY) */
enum {
	CNT_TOTAL = 0,
	CNT_HIT   = 1,
	CNT_MISS  = 2,
	CNT_KERNEL_DIRECT = 3,
	CNT_MAX,
};

#endif /* __EBPDNS_XDP_H */
