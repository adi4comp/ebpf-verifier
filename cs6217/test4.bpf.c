#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Map to store OOM kill counts per cgroup
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);    // cgroup_id
    __type(value, __u64);  // kill count
} oom_kills_total SEC(".maps");

// Perf event output map
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} perf_oom_events SEC(".maps");

// Structure to pass OOM kill event data
struct oom_kill_event {
    __u64 cgroup_id;
    __u32 pid;
    char comm[16];
};

SEC("kprobe/oom_kill_process")
int BPF_PROG(trace_oom_kill, struct task_struct *task, struct mem_cgroup *memcg)
{
    __u64 cgroup_id;
    struct oom_kill_event event = {};

    // Get cgroup_id 
    bpf_probe_read_kernel(&cgroup_id, sizeof(cgroup_id), &memcg);

    // Prepare event data
    event.cgroup_id = cgroup_id;
    event.pid = task->pid;
    bpf_probe_read_kernel_str(event.comm, sizeof(event.comm), task->comm);

    // Increment kill count in map
    __u64 *count = bpf_map_lookup_elem(&oom_kills_total, &cgroup_id);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init_count = 1;
        bpf_map_update_elem(&oom_kills_total, &cgroup_id, &init_count, BPF_NOEXIST);
    }

    // Send event to perf buffer
    bpf_perf_event_output(ctx, &perf_oom_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

char _license[] SEC("license") = "GPL";