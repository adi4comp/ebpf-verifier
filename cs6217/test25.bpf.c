#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Map to store filter process ID
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} pid_filter SEC(".maps");

// Perf event map to send trace events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
} write_events SEC(".maps");

// Write event structure
struct write_event {
    __u64 pid;
    __u64 fd;
    __u64 count;
};

// BPF program section for tracing write syscall entry
SEC("tracepoint/syscalls/sys_enter_write")
int trace_write_entry(void *ctx)
{
    // Get current process ID
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    // Check if PID filter is set
    __u32 *filter = bpf_map_lookup_elem(&pid_filter, &pid);
    if (filter) {
        struct write_event event = {0};
        event.pid = pid;
        
        // Retrieve file descriptor and write count
        bpf_probe_read(&event.fd, sizeof(event.fd), ctx + sizeof(void *));
        bpf_probe_read(&event.count, sizeof(event.count), ctx + (2 * sizeof(void *)));
        
        // Send event to userspace
        bpf_perf_event_output(ctx, &write_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    }
    
    return 0;
}

// License required for BPF programs
char _license[] SEC("license") = "GPL";