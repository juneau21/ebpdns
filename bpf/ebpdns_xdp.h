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
	__u32 ttl;            /* 原始 TTL (秒), 仅用于回填应答 RR */
	/* 绝对过期时间 (ns, 启动后单调时钟 bpf_ktime_get_boot_ns 基准)。
	 * 用户态回填时写 = boot_ns + ttl*1e9; 0 表示永不过期。
	 * 命中检查: 若 expires_at 非零且当前 boot_ns > expires_at 则按 miss 处理。
	 * 放在 ttl 之后、rdata 之前, 与用户态 ctypes Structure 严格对齐。 */
	__u64 expires_at;
	__u8  rdata[EBP_MAX_ADDRS][16]; /* A=前4字节有效, AAAA=16字节 */
};
/* 布局校验: 字段原始长度和 = 1+1+1+8+4+8+128 = 151;
 * C 自然对齐 ABI sizeof = 152 (offset 11 处 1 字节内补使 ttl 4 字节对齐),
 * 与用户态 ctypes Structure (自然对齐) 严格一致。 */

/* 计数器索引 (PERCPU_ARRAY) */
enum {
	CNT_TOTAL = 0,
	CNT_HIT   = 1,
	CNT_MISS  = 2,
	CNT_KERNEL_DIRECT = 3,
	CNT_MAX,
};

#endif /* __EBPDNS_XDP_H */
