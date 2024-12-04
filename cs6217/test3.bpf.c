#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_ENTRIES 10240

// Key structure for tracking skb free events
struct skb_key {
    __u16 eth_proto;    // Ethernet protocol
    __u8 ip_proto;      // IP protocol
    __u16 src_port;     // Source port
    __u16 dst_port;     // Destination port
    __u32 drop_reason;  // Reason for freeing skb
};

// Value structure to count events
struct skb_stats {
    __u64 count;
};

// Hash map to store skb free statistics
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct skb_key);
    __type(value, struct skb_stats);
} skb_free_stats SEC(".maps");

SEC("kprobe/kfree_skb")
int BPF_PROG(trace_kfree_skb, struct sk_buff *skb, unsigned int reason)
{
    struct skb_key key = {};
    struct skb_stats *stats;
    
    // Skip if skb is NULL
    if (!skb)
        return 0;

    // Extract Ethernet protocol (use direct conversion instead of bpf_ntohs)
    key.eth_proto = (__u16)skb->protocol;

    // Extract IP information if available
    if (skb->network_header) {
        struct iphdr *iph = (struct iphdr *)(skb->head + skb->network_header);
        key.ip_proto = iph->protocol;

        // Extract ports if possible
        if (key.ip_proto == IPPROTO_TCP || key.ip_proto == IPPROTO_UDP) {
            struct tcphdr *tcph = (struct tcphdr *)(skb->head + skb->transport_header);
            key.src_port = tcph->source;
            key.dst_port = tcph->dest;
        }
    }

    // Store drop reason
    key.drop_reason = reason;

    // Increment or initialize counter
    stats = bpf_map_lookup_elem(&skb_free_stats, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->count, 1);
    } else {
        struct skb_stats new_stats = { .count = 1 };
        bpf_map_update_elem(&skb_free_stats, &key, &new_stats, BPF_NOEXIST);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";