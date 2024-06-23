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
	__u16 l3proto = eth->h_proto;
	if (l3proto == 0x86dd)
		return 1;
	return 0;
}

SEC("tc")
int l2_helper(struct __sk_buff *skb)
{
	struct ethhdr eth = {};
	if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)))
		return 0;
	__u16 l3proto = eth.h_proto;
	if (l3proto == 0x86dd)
		return 1;
	return 0;
}
