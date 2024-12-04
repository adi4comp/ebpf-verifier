#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Perf event output map
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} execve_events SEC(".maps");

// Structure to pass execve event data
struct execve_event {
    __u32 pid;
    __u32 uid;
    __u32 ppid;
    char comm[16];
    char filename[256];
};

SEC("tp_btf/sys_enter")
int BPF_PROG(trace_execve_enter, struct pt_regs *regs, long id)
{
    // Only process execve syscall
    if (id != 59) // 59 is execve syscall number on x86_64
        return 0;

    struct execve_event event = {};
    
    // Get process information
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // Get parent PID manually
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct task_struct *parent;
        bpf_probe_read_kernel(&parent, sizeof(parent), &task->parent);
        if (parent) {
            bpf_probe_read_kernel(&event.ppid, sizeof(event.ppid), &parent->pid);
        }
    }

    // Get command name
    bpf_get_current_comm(event.comm, sizeof(event.comm));

    // Get executable filename
    bpf_probe_read_user_str(event.filename, sizeof(event.filename), (const char *)PT_REGS_PARM1(regs));

    // Output event to perf buffer
    bpf_perf_event_output(ctx, &execve_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

char _license[] SEC("license") = "GPL";