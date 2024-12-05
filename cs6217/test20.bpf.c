#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/if_ether.h>

// Hash map to store TCP SYN backlog count
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} tcp_syn_backlog SEC(".maps");

// Configuration map for multiplier
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} multiplier_map SEC(".maps");

// BPF program section for IPv4 TCP SYN kprobe
SEC("kprobe/tcp_v4_syn")
int trace_tcp_v4_syn(struct pt_regs *ctx)
{
    __u32 key = 0;
    __u32 *multiplier;

    // Lookup multiplier configuration
    multiplier = bpf_map_lookup_elem(&multiplier_map, &key);
    if (!multiplier || *multiplier == 0) {
        return 0;
    }

    // Update SYN packet count
    __u64 *count = bpf_map_lookup_elem(&tcp_syn_backlog, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 initial_count = 1;
        bpf_map_update_elem(&tcp_syn_backlog, &key, &initial_count, BPF_NOEXIST);
    }

    return 0;
}

// BPF program section for IPv6 TCP SYN kprobe
SEC("kprobe/tcp_v6_syn")
int trace_tcp_v6_syn(struct pt_regs *ctx)
{
    __u32 key = 0;
    __u32 *multiplier;

    // Lookup multiplier configuration
    multiplier = bpf_map_lookup_elem(&multiplier_map, &key);
    if (!multiplier || *multiplier == 0) {
        return 0;
    }

    // Update SYN packet count
    __u64 *count = bpf_map_lookup_elem(&tcp_syn_backlog, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 initial_count = 1;
        bpf_map_update_elem(&tcp_syn_backlog, &key, &initial_count, BPF_NOEXIST);
    }

    return 0;
}

// License required for BPF programs
char _license[] SEC("license") = "GPL";