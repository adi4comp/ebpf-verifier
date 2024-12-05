#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/perf_event.h>

// Define hash maps with fixed sizes to prevent verification issues
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // CPU ID
    __type(value, __u64); // Accumulated count
} llc_misses_total SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // CPU ID
    __type(value, __u64); // Accumulated count
} llc_references_total SEC(".maps");

// Perf event sample format for LLC tracking
struct cache_event {
    __u64 config;     // Event configuration
    __u64 value;      // Count value
};

// Fully define the perf event data structure
struct bpf_perf_event_data {
    __u64 addr;
    __u64 size;
    void *data;
};

// eBPF program to track LLC events
SEC("perf_event")
int track_llc_events(struct bpf_perf_event_data *ctx) {
    // Bounds-checked event data extraction
    struct cache_event *event = (struct cache_event *)ctx->data;
    if (event == NULL) {
        return 0;
    }

    // Get current CPU ID safely
    __u32 cpu_id = bpf_get_smp_processor_id();

    // Validate event configuration
    if (event->config == PERF_COUNT_HW_CACHE_MISSES) {
        // Safely update LLC misses map
        __u64 *misses_count = bpf_map_lookup_elem(&llc_misses_total, &cpu_id);
        if (misses_count) {
            // Carefully increment with overflow prevention
            __sync_fetch_and_add(misses_count, event->value);
        } else {
            // First entry for this CPU
            __u64 initial_count = event->value;
            bpf_map_update_elem(&llc_misses_total, &cpu_id, &initial_count, BPF_NOEXIST);
        }
    } 
    else if (event->config == PERF_COUNT_HW_CACHE_REFERENCES) {
        // Safely update LLC references map
        __u64 *references_count = bpf_map_lookup_elem(&llc_references_total, &cpu_id);
        if (references_count) {
            // Carefully increment with overflow prevention
            __sync_fetch_and_add(references_count, event->value);
        } else {
            // First entry for this CPU
            __u64 initial_count = event->value;
            bpf_map_update_elem(&llc_references_total, &cpu_id, &initial_count, BPF_NOEXIST);
        }
    }

    return 0;
}

// Required license for eBPF programs
char _license[] SEC("license") = "GPL";