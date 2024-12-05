#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Map to track JIT page allocations
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u64);
} jit_page_map SEC(".maps");

// Structure to track JIT allocation details
struct jit_alloc_info {
    __u64 addr;
    __u64 size;
};

// BPF program section for tracing BPF JIT binary allocation
SEC("kprobe/bpf_jit_binary_alloc")
int trace_jit_alloc(void *ctx)
{
    struct jit_alloc_info info = {0};
    
    // Retrieve allocation address and size from kernel function arguments
    bpf_probe_read(&info.addr, sizeof(info.addr), ctx + sizeof(void *));
    bpf_probe_read(&info.size, sizeof(info.size), ctx + (2 * sizeof(void *)));
    
    // Only track valid allocations
    if (info.addr && info.size) {
        bpf_map_update_elem(&jit_page_map, &info.addr, &info.size, BPF_ANY);
    }
    
    return 0;
}

// BPF program section for tracing BPF JIT binary free
SEC("kprobe/bpf_jit_binary_free")
int trace_jit_free(void *ctx)
{
    __u64 addr = 0;
    
    // Retrieve address to free
    bpf_probe_read(&addr, sizeof(addr), ctx + sizeof(void *));
    
    // Remove the allocation from tracking map
    if (addr) {
        bpf_map_delete_elem(&jit_page_map, &addr);
    }
    
    return 0;
}

// License required for BPF programs
char _license[] SEC("license") = "GPL";