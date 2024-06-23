// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("tc")
int l2_direct_access(struct __sk_buff *skb)
{
	struct ethhdr *eth;
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	eth = (struct ethhdr *)data;
	if (eth + 1 > (struct ethhdr *)data_end)
		return 0;
	__u8 mac_dst[6];
	__builtin_memcpy(mac_dst, eth->h_dest, 6);
	__u8 mac_src[6];
	__builtin_memcpy(mac_src, eth->h_source, 6);
	if (eth->h_proto == 0x0800)
		return 1;
	return 0;
}

SEC("tc")
int l2_helper(struct __sk_buff *skb)
{
	struct ethhdr eth = {};
	if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)))
		return 0;
	__u8 mac_dst[6];
	__builtin_memcpy(mac_dst, eth.h_dest, 6);
	__u8 mac_src[6];
	__builtin_memcpy(mac_src, eth.h_source, 6);
	if (eth.h_proto == 0x0800)
		return 1;
	return 0;
}
