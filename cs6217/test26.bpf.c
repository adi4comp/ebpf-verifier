#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Per-CPU hash map to track softirq invocations
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 10);  // Number of softirq types
    __type(key, __u32);       // softirq type
    __type(value, __u64);     // invocation count
} softirq_counts SEC(".maps");

// BPF program section for tracing softirq entry
SEC("kprobe/__softirq_entry")
int trace_softirq_entry(void *ctx)
{
    __u32 softirq_type = 0;
    
    // Read softirq type from context
    bpf_probe_read(&softirq_type, sizeof(softirq_type), ctx + sizeof(void *));
    
    // Increment count for this softirq type
    __u64 *count = bpf_map_lookup_elem(&softirq_counts, &softirq_type);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 initial_count = 1;
        bpf_map_update_elem(&softirq_counts, &softirq_type, &initial_count, BPF_NOEXIST);
    }
    
    return 0;
}

// License required for BPF programs
char _license[] SEC("license") = "GPL";