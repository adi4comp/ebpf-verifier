#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define FILENAME_MAX 256

// Structure to store unlink event details
struct unlink_event {
    __u64 pid;
    char filename[FILENAME_MAX];
    __s64 ret_value;
};

// Perf event map to send unlink events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
} unlink_events SEC(".maps");

// BPF program section for tracing do_unlinkat entry
SEC("kprobe/do_unlinkat")
int trace_unlinkat_entry(void *ctx)
{
    // Get current process ID
    __u64 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Prepare unlink event
    struct unlink_event event = {
        .pid = pid
    };
    
    // Read filename from kernel context
    __u64 filename_ptr;
    bpf_probe_read(&filename_ptr, sizeof(filename_ptr), ctx + sizeof(void *) + sizeof(__u64));
    bpf_probe_read_str(event.filename, sizeof(event.filename), (void *)filename_ptr);
    
    // Send event to userspace
    bpf_perf_event_output(ctx, &unlink_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

// BPF program section for tracing do_unlinkat return
SEC("kretprobe/do_unlinkat")
int trace_unlinkat_return(void *ctx)
{
    // Get current process ID
    __u64 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Prepare unlink event
    struct unlink_event event = {
        .pid = pid
    };
    
    // Read return value from context
    bpf_probe_read(&event.ret_value, sizeof(event.ret_value), ctx + sizeof(void *));
    
    // Send event to userspace
    bpf_perf_event_output(ctx, &unlink_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

// License required for BPF programs
char _license[] SEC("license") = "GPL";