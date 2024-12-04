#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Perf event output map
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} readline_events SEC(".maps");

// Structure to pass readline event data
struct readline_event {
    __u32 pid;
    char comm[16];
    char line[256];
};

SEC("uprobe/bash_readline")
int BPF_PROG(trace_bash_readline, char *line)
{
    struct readline_event event = {};
    
    // Get process information
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;

    // Get command name
    bpf_get_current_comm(event.comm, sizeof(event.comm));

    // Read the input line
    bpf_probe_read_user_str(event.line, sizeof(event.line), line);

    // Output event to perf buffer
    bpf_perf_event_output(ctx, &readline_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

char _license[] SEC("license") = "GPL";