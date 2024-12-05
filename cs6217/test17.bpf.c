#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Define a map to store the filter process ID
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} pid_filter SEC(".maps");

// Trace event structure for openat system call
struct open_event {
    __u64 pid;
    __u64 timestamp;
};

// Perf event map to send trace events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
} events SEC(".maps");

// BPF program section for tracing syscall entry
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_entry(void *ctx)
{
    // Get current process ID
    __u64 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Check if a specific PID filter is set
    __u32 *filter = bpf_map_lookup_elem(&pid_filter, &pid);
    if (filter && pid != *filter) {
        return 0;
    }
    
    // Prepare trace event
    struct open_event event = {
        .pid = pid,
        .timestamp = bpf_ktime_get_ns()
    };
    
    // Submit event to perf buffer
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

// License required for BPF programs
char _license[] SEC("license") = "GPL";