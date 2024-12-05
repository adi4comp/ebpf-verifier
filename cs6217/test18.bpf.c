#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Exit event structure
struct exit_event {
    __u64 pid;
    __u64 tid;
    __u64 exit_status;
    __u64 timestamp;
};

// Perf event map to send exit events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
} exit_events SEC(".maps");

// BPF program section for tracing process exit
SEC("tracepoint/sched/sched_process_exit")
int trace_process_exit(void *ctx)
{
    // Get current process and thread IDs
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 pid = pid_tgid >> 32;
    __u64 tid = pid_tgid & 0xFFFFFFFF;
    
    // Prepare exit event
    struct exit_event event = {
        .pid = pid,
        .tid = tid,
        .exit_status = 0,  // Cannot directly get exit code in this tracepoint
        .timestamp = bpf_ktime_get_ns()
    };
    
    // Submit event to perf buffer
    bpf_perf_event_output(ctx, &exit_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

// License required for BPF programs
char _license[] SEC("license") = "GPL";