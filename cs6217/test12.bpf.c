#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Latency buckets definition
#define LATENCY_BUCKETS 6

// Define a hash map to store latency histogram
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // CPU ID
    __type(value, __u64[LATENCY_BUCKETS]);  // Latency buckets
} block_io_latency SEC(".maps");

// Tracepoint structure for block I/O request tracking
struct block_rq_complete_args {
    __u64 pad;
    __u32 dev;  // Changed from dev_t to __u32
    __u64 sector;
    __u64 nr_sec;
    __u64 error;
    __u64 start_time;
    __u64 duration;
};

// eBPF program to track block I/O request latency
SEC("tracepoint/block/block_rq_complete")
int track_block_io_latency(struct block_rq_complete_args *ctx) {
    // Get current CPU ID
    __u32 cpu_id = bpf_get_smp_processor_id();

    // Validate request duration
    __u64 duration_ns = ctx->duration;
    if (duration_ns == 0) {
        return 0;
    }

    // Determine latency bucket
    __u32 bucket_index = 0;
    if (duration_ns <= 1000) {               // <= 1 µs
        bucket_index = 0;
    } else if (duration_ns <= 10000) {        // 1-10 µs
        bucket_index = 1;
    } else if (duration_ns <= 100000) {       // 10-100 µs
        bucket_index = 2;
    } else if (duration_ns <= 1000000) {      // 100 µs - 1 ms
        bucket_index = 3;
    } else if (duration_ns <= 10000000) {     // 1-10 ms
        bucket_index = 4;
    } else {                                  // > 10 ms
        bucket_index = 5;
    }

    // Lookup or create entry for this CPU
    __u64 (*latency_counts)[LATENCY_BUCKETS] = bpf_map_lookup_elem(&block_io_latency, &cpu_id);
    
    if (latency_counts) {
        // Increment the appropriate bucket
        __sync_fetch_and_add(&((*latency_counts)[bucket_index]), 1);
    } else {
        // Initialize new entry for this CPU
        __u64 initial_counts[LATENCY_BUCKETS] = {0};
        initial_counts[bucket_index] = 1;
        bpf_map_update_elem(&block_io_latency, &cpu_id, &initial_counts, BPF_NOEXIST);
    }

    return 0;
}

// Required license for eBPF programs
char _license[] SEC("license") = "GPL";