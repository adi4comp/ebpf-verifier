#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

// Define the BPF map for syscall counts
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // System call ID as key
    __type(value, __u64); // Count as value
} syscalls_total SEC(".maps");

// Syscall entry tracepoint program
SEC("tp/syscalls/sys_enter")
int syscall_counter(void *ctx)
{
    // Extract system call ID from the context
    __u32 syscall_id;
    bpf_probe_read_kernel(&syscall_id, sizeof(syscall_id), ctx + 8);

    // Increment the counter for this syscall ID
    __u64 *count, initial_count = 1;
    count = bpf_map_lookup_elem(&syscalls_total, &syscall_id);

    if (count) {
        // If entry exists, increment
        __sync_fetch_and_add(count, 1);
    } else {
        // If no entry, create with initial count of 1
        bpf_map_update_elem(&syscalls_total, &syscall_id, &initial_count, BPF_NOEXIST);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";