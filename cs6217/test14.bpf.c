#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Number of latency buckets
#define LATENCY_BUCKETS 6

// Hash map to store latency distribution
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // CPU ID
    __type(value, __u64[LATENCY_BUCKETS]); // Latency buckets
} shrink_node_latency SEC(".maps");

// Kernel function entry and exit tracing context
struct trace_entry_exit {
    __u64 enter_time;
    __u64 exit_time;
};

// Per-CPU map to track function entry times
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);   // Unique key (can be thread ID or address)
    __type(value, struct trace_entry_exit); // Entry/exit times
} shrink_node_trace_map SEC(".maps");

// eBPF program to track shrink_node function latency
SEC("kprobe/shrink_node")
int trace_shrink_node_entry(void *ctx) {
    // Get current CPU ID
    __u32 cpu_id = bpf_get_smp_processor_id();
    
    // Generate unique key (using current timestamp)
    __u64 key = bpf_ktime_get_ns();
    
    // Create entry time record
    struct trace_entry_exit entry = {
        .enter_time = bpf_ktime_get_ns(),
        .exit_time = 0
    };
    
    // Store entry time
    bpf_map_update_elem(&shrink_node_trace_map, &key, &entry, BPF_ANY);
    
    return 0;
}

// eBPF program for function exit tracing
SEC("kretprobe/shrink_node")
int trace_shrink_node_exit(void *ctx) {
    // Get current CPU ID
    __u32 cpu_id = bpf_get_smp_processor_id();
    
    // Get current timestamp
    __u64 exit_time = bpf_ktime_get_ns();
    
    // Find most recent entry
    __u64 key = exit_time;
    struct trace_entry_exit *entry = bpf_map_lookup_elem(&shrink_node_trace_map, &key);
    
    if (!entry) {
        return 0;
    }
    
    // Calculate duration
    __u64 duration = exit_time - entry->enter_time;
    
    // Determine latency bucket
    __u32 bucket_index = 0;
    if (duration <= 1000) {               // <= 1 µs
        bucket_index = 0;
    } else if (duration <= 10000) {        // 1-10 µs
        bucket_index = 1;
    } else if (duration <= 100000) {       // 10-100 µs
        bucket_index = 2;
    } else if (duration <= 1000000) {      // 100 µs - 1 ms
        bucket_index = 3;
    } else if (duration <= 10000000) {     // 1-10 ms
        bucket_index = 4;
    } else {                               // > 10 ms
        bucket_index = 5;
    }

    // Lookup or create entry for this CPU
    __u64 (*latency_counts)[LATENCY_BUCKETS] = bpf_map_lookup_elem(&shrink_node_latency, &cpu_id);
    
    if (latency_counts) {
        // Safely increment the appropriate bucket
        __sync_fetch_and_add(&((*latency_counts)[bucket_index]), 1);
    } else {
        // Initialize new entry for this CPU
        __u64 initial_counts[LATENCY_BUCKETS] = {0};
        initial_counts[bucket_index] = 1;
        bpf_map_update_elem(&shrink_node_latency, &cpu_id, &initial_counts, BPF_NOEXIST);
    }
    
    // Clean up the trace entry
    bpf_map_delete_elem(&shrink_node_trace_map, &key);
    
    return 0;
}

// Required license for eBPF programs
char _license[] SEC("license") = "GPL";