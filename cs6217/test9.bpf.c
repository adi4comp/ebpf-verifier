#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[64]);   
    __type(value, __u64); 
} page_cache_ops_total SEC(".maps");

SEC("kprobe/mark_page_accessed")
int mark_page_accessed_counter(struct pt_regs *ctx)
{
    char key[] = "mark_page_accessed";
    __u64 *count, initial_count = 1;

    count = bpf_map_lookup_elem(&page_cache_ops_total, key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        bpf_map_update_elem(&page_cache_ops_total, key, &initial_count, BPF_NOEXIST);
    }
    return 0;
}

SEC("kprobe/add_to_page_cache_lru")
int add_to_page_cache_lru_counter(struct pt_regs *ctx)
{
    char key[] = "add_to_page_cache_lru";
    __u64 *count, initial_count = 1;

    count = bpf_map_lookup_elem(&page_cache_ops_total, key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        bpf_map_update_elem(&page_cache_ops_total, key, &initial_count, BPF_NOEXIST);
    }
    return 0;
}

SEC("kprobe/folio_mark_accessed")
int folio_mark_accessed_counter(struct pt_regs *ctx)
{
    char key[] = "folio_mark_accessed";
    __u64 *count, initial_count = 1;

    count = bpf_map_lookup_elem(&page_cache_ops_total, key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        bpf_map_update_elem(&page_cache_ops_total, key, &initial_count, BPF_NOEXIST);
    }
    return 0;
}

char _license[] SEC("license") = "GPL";