#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Hash map to store timer start counts
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} timer_start_counts SEC(".maps");

// BPF program section for tracing timer starts
SEC("kprobe/timer_start")
int trace_timer_start(void *ctx)
{
    // Default key for total count
    __u32 key = 0;
    
    // Increment or initialize the count
    __u64 *count = bpf_map_lookup_elem(&timer_start_counts, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 initial_count = 1;
        bpf_map_update_elem(&timer_start_counts, &key, &initial_count, BPF_NOEXIST);
    }
    
    return 0;
}

// License required for BPF programs
char _license[] SEC("license") = "GPL";