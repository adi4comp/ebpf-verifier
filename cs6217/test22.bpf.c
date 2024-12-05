#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>

// Map to store UDP packet counts per local port
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, __u64);
} udp_port_counts SEC(".maps");

// BPF program section for tracing UDP receive
SEC("kprobe/udp_rcv")
int trace_udp_recv(void *ctx)
{
    __u16 local_port = 0;
    
    // Read local port from context
    bpf_probe_read(&local_port, sizeof(local_port), ctx + sizeof(void *) + sizeof(__u16));
    
    // Exclude ephemeral ports (above 32768)
    if (local_port > 0 && local_port <= 32768) {
        // Increment packet count for this port
        __u64 *count = bpf_map_lookup_elem(&udp_port_counts, &local_port);
        if (count) {
            __sync_fetch_and_add(count, 1);
        } else {
            __u64 initial_count = 1;
            bpf_map_update_elem(&udp_port_counts, &local_port, &initial_count, BPF_NOEXIST);
        }
    }
    
    return 0;
}

// License required for BPF programs
char _license[] SEC("license") = "GPL";