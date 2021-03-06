/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"
#include "kern_define.h"

#define bpf_printk(fmt, ...)                                    \
({                                                              \
	char ____fmt[] = fmt;                                   \
	bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                        \
})

#ifndef classify
#define classify 0
#endif

#ifndef transport 
#define transport 0
#endif

#ifndef port
#define port 0
#endif

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + 1 > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;
//数字为1时过滤显示传输层协议为UDP的数据包；数字为2时过滤显示传输层协议为TCP的数据包；数字为3时过滤显示网络层为IP协议的数据包。
//网络流量控制规则由NET,TRANSORT,PORT共同组成。NET默认为0,表示不过滤网络层数据包，为1时表示只接收网络层为IP协议的数据包；TRANSPORT默认为0,表示不过滤传输层数据包，为1时表示只接受传输层为UDP的数据包，为2时表示只接受传输层为TCP的数据包；PORT默认为0,表示未指定接收固定端口，其余表示指定接受某个端口的数据包。指定端口需要指定传输层协议。

	return eth->h_proto; /* network-byte-order */
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
				       void *data_end,
				       struct iphdr **iphdr)
{
	struct iphdr *iph = nh->pos;
	int hdrsize;

	if (iph + 1 > data_end)
		return -1;

	hdrsize = iph->ihl * 4;
	/* Sanity check packet field is valid */
	if(hdrsize < sizeof(*iph))
		return -1;

	/* Variable-length IPv4 header, need to use byte-based arithmetic */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*iphdr = iph;

	return iph->protocol;
}

/*
 * parse_tcphdr: parse and return the length of the tcp header
 */
static __always_inline int parse_tcphdr(struct hdr_cursor *nh,
					void *data_end,
					struct tcphdr **tcphdr)
{
	int flag = 1;
	int len;
	struct tcphdr *h = nh->pos;

	if (h + 1 > data_end)
		return -1;

	len = h->doff * 4;
	/* Sanity check packet field is valid */
	if(len < sizeof(*h))
		return -1;

	/* Variable-length TCP header, need to use byte-based arithmetic */
	if (nh->pos + len > data_end)
		return -1;

	bpf_printk("tcp: %d %d", bpf_ntohs(h->source), bpf_ntohs(h->dest));
	
	if (transport == 2 && port != 0) {
		flag = -1;
		 if (h->dest == bpf_htons(port) || h->source == bpf_htons(port) ) {
	        return 1;
   	 }
	}

	nh->pos += len;
	*tcphdr = h;

	// return len;
	return flag;
}


/*
 * parse_udphdr: parse the udp header and return the length of the udp payload
 */
static __always_inline int parse_udphdr(struct hdr_cursor *nh,
					void *data_end,
					struct udphdr **udphdr)
{
	int len;
	struct udphdr *h = nh->pos;

	if (h + 1 > data_end)
		return -1;

	nh->pos  = h + 1;
	*udphdr = h;

	len = bpf_ntohs(h->len) - sizeof(struct udphdr);
	if (len < 0)
		return -1;

	bpf_printk("udp: %d %d", bpf_ntohs(h->source), bpf_ntohs(h->dest));
	if (transport == 1 && port != 0) {
		 if (h->dest == bpf_htons(port) || h->source == bpf_htons(port) ) {
	        return -1;
   	 	}
	}
	return 1;
}

// /* to u64 in host order */
// static inline __u64 ether_addr_to_u64(const __u8 *addr)
// {
// 	__u64 u = 0;
// 	int i;

// 	for (i = ETH_ALEN - 1; i >= 0; i--)
// 		u = u << 8 | addr[i];
// 	return u;
// }

SEC("xdp")
int  xdp_prog_simple(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *iphdr;
	// struct ipv6hdr *ipv6hdr;
	struct udphdr *udphdr;
	struct tcphdr *tcphdr;
	__u64 offset = sizeof(*eth);

	if ((void *)eth + offset > data_end)
		return 0;

	// bpf_printk("src: %llu, dst: %llu, proto: %u\n",
	// 	   ether_addr_to_u64(eth->h_source),
	// 	   ether_addr_to_u64(eth->h_dest),
	// 	   bpf_ntohs(eth->h_proto));

	struct hdr_cursor nh;
	int nh_type;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	__u32 action = XDP_DROP; 
	nh_type = parse_ethhdr(&nh, data_end, &eth);

	if (nh_type == bpf_htons(ETH_P_IP)) {
		nh_type = parse_iphdr(&nh, data_end, &iphdr);
		// bpf_printk("ip");
		if (classify != 1 && nh_type == IPPROTO_TCP) {
			if (transport != 1  && parse_tcphdr(&nh, data_end, &tcphdr) > 0) {
				action = XDP_PASS;
			} 
		} else if (classify != 2 && nh_type == IPPROTO_UDP) {
			if (transport != 2 && parse_udphdr(&nh, data_end, &udphdr) > 0) {
				action = XDP_PASS;
			}
		}
	} else {
		action = XDP_PASS;
	}
	// bpf_printk("nh_type: 0x%x", nh_type);
	return xdp_stats_record_action(ctx, action);
	// return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
