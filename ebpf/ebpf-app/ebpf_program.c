
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <common.h>

// Define a map to store the port number
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u16);n
    __uint(max_entries, 1);
} drop_port SEC(".maps");

// XDP program to drop TCP packets for a given port
SEC("xdp")
int drop_tcp_packets(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    tcp = (struct tcphdr *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // Retrieve the port number from the map
    __u32 key = 0;
    __u16 *port = bpf_map_lookup_elem(&drop_port, &key);
    if (!port)
        return XDP_PASS;

    if (tcp->dest == __constant_htons(*port))
        return XDP_DROP;

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
