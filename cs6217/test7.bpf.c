#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define EPHEMERAL_PORT_START 32768
#define ETH_P_IP 0x0800

// Key structure for tracking packet types
struct packet_key {
    __u16 eth_type;     // Ethernet type
    __u8 ip_proto;      // IP protocol
    __u16 dst_port;     // Destination port
};

// Value structure to count packets
struct packet_stats {
    __u64 count;
};

// Hash map to store packet statistics
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct packet_key);
    __type(value, struct packet_stats);
} packet_count_map SEC(".maps");

SEC("xdp")
int parse_packets(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Check if it's an IP packet
    if (eth->h_proto != (__be16)__builtin_bswap16(ETH_P_IP))
        return XDP_PASS;

    // IP header
    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    // TCP/UDP header parsing
    void *transport_header = data + sizeof(*eth) + (iph->ihl * 4);
    struct tcphdr *tcph = transport_header;
    
    if ((void *)(tcph + 1) > data_end)
        return XDP_PASS;

    // Skip ephemeral ports
    __u16 dst_port = __builtin_bswap16(tcph->dest);
    if (dst_port >= EPHEMERAL_PORT_START)
        return XDP_PASS;

    // Prepare key for map
    struct packet_key key = {
        .eth_type = __builtin_bswap16(eth->h_proto),
        .ip_proto = iph->protocol,
        .dst_port = dst_port
    };

    // Update packet count
    struct packet_stats *stats = bpf_map_lookup_elem(&packet_count_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->count, 1);
    } else {
        struct packet_stats new_stats = { .count = 1 };
        bpf_map_update_elem(&packet_count_map, &key, &new_stats, BPF_NOEXIST);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";