#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Hash map to store function call counts
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // Process ID
    __type(value, __u64); // Function call count
} python_function_calls SEC(".maps");

// Context structure for Python function call tracing
struct python_function_args {
    __u64 pad;
    const char *module_name;
    const char *function_name;
};

// eBPF program to track Python function calls
SEC("usdt/python:function__entry")
int track_python_function_calls(struct python_function_args *ctx) {
    // Get current process ID
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Validate function name pointer
    if (!ctx->function_name) {
        return 0;
    }

    // Lookup or create entry for this PID
    __u64 *call_count = bpf_map_lookup_elem(&python_function_calls, &pid);
    
    if (call_count) {
        // Safely increment call count
        __sync_fetch_and_add(call_count, 1);
    } else {
        // Initialize first entry for this PID
        __u64 initial_count = 1;
        bpf_map_update_elem(&python_function_calls, &pid, &initial_count, BPF_NOEXIST);
    }

    return 0;
}

// Required license for eBPF programs
char _license[] SEC("license") = "GPL";