#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Define kill syscall number (typically 62 on x86_64)
#define SYS_KILL 62

// Define a structure to store kill syscall information
struct kill_event {
    __u32 pid;           // Sender's PID
    __u32 target_pid;    // Receiver's PID
    __u32 signal;        // Signal number
    __s32 ret_value;     // Return value of the syscall
    __u64 timestamp_ns;  // Timestamp of the event
};

// Create a hash map to store kill events
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);  // Use PID as key
    __type(value, struct kill_event);
} kill_events SEC(".maps");

// Tracing program for kill syscall entry
SEC("tp_btf/sys_enter")
int BPF_PROG(trace_kill_enter, struct pt_regs *regs, long id)
{
    // Check if this is the kill syscall
    if (id != SYS_KILL)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    // Retrieve syscall arguments
    __s32 target_pid = (int)PT_REGS_PARM1(regs);
    __u32 signal = (__u32)PT_REGS_PARM2(regs);

    // Prepare event structure
    struct kill_event event = {
        .pid = pid,
        .target_pid = target_pid,
        .signal = signal,
        .timestamp_ns = bpf_ktime_get_ns()
    };

    // Store the event in the hash map
    bpf_map_update_elem(&kill_events, &pid, &event, BPF_ANY);

    return 0;
}

// Tracing program for kill syscall exit
SEC("tp_btf/sys_exit")
int BPF_PROG(trace_kill_exit, struct pt_regs *regs, long id, long ret)
{
    // Check if this is the kill syscall
    if (id != SYS_KILL)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // Lookup the existing event and update return value
    struct kill_event *event = bpf_map_lookup_elem(&kill_events, &pid);
    if (event) {
        event->ret_value = (__s32)ret;
    }

    return 0;
}

char _license[] SEC("license") = "GPL";