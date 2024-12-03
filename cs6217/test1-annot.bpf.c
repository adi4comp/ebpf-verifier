#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/sched.h>

// Define an LRU hash map to track migration counts
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);   // cgroup ID as key
    __type(value, __u64); // migration count as value
} cgroup_migrations SEC(".maps");

// Tracepoint program for sched_migrate_task
SEC("tracepoint/sched/sched_migrate_task")
int handle_task_migration(struct trace_event_raw_sched_migrate_task *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u64 *count, initial_count = 1;

    

    // Lookup or initialize counter for this cgroup
    count = bpf_map_lookup_elem(&cgroup_migrations, &cgroup_id);
    
    if (!count) {
        // If no entry exists, create one
        // Invariant: cgroup_migrations map should not exceed max_entries
        sassert(bpf_map_size(&cgroup_migrations) < 10240);
        bpf_map_update_elem(&cgroup_migrations, &cgroup_id, &initial_count, BPF_NOEXIST);
    } else {
        // Increment existing counter
        __u64 new_count = *count + 1;

        // Invariant: new_count should not overflow
        sassert(new_count > *count);

        bpf_map_update_elem(&cgroup_migrations, &cgroup_id, &new_count, BPF_EXIST);
    }

    // Postcondition: Ensure the migration count is consistent
    count = bpf_map_lookup_elem(&cgroup_migrations, &cgroup_id);
    sassert(count && *count >= initial_count);

    return 0;
}

// Ensure no uninitialized memory reads
__VERIFIER_assert_no_uninit_reads();

char _license[] SEC("license") = "GPL";
