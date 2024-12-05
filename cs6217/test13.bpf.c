#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Hash map to store malloc call counts
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // Process ID
    __type(value, __u64); // Call count
} libc_malloc_calls_total SEC(".maps");

// Context structure for USDT probe
struct malloc_args {
    __u64 pad;
    void *ptr;     // Returned malloc pointer
    __u64 size;    // Requested allocation size
};

// eBPF program to track malloc calls
SEC("usdt/libc:malloc")
int track_malloc_calls(struct malloc_args *ctx) {
    // Get current process ID
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Bound-check the allocation size
    if (ctx->size == 0 || ctx->size > 1024 * 1024 * 128) {
        return 0;
    }

    // Lookup or create entry for this PID
    __u64 *call_count = bpf_map_lookup_elem(&libc_malloc_calls_total, &pid);
    
    if (call_count) {
        // Safely increment call count
        __sync_fetch_and_add(call_count, 1);
    } else {
        // Initialize first entry for this PID
        __u64 initial_count = 1;
        bpf_map_update_elem(&libc_malloc_calls_total, &pid, &initial_count, BPF_NOEXIST);
    }

    return 0;
}

// Required license for eBPF programs
char _license[] SEC("license") = "GPL";