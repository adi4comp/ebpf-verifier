
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>


#define LATENCY_BUCKETS 10

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);  // Listening port
    __type(value, __u64[LATENCY_BUCKETS]);
} accept_latency_histogram SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);  // Listening port
    __type(value, __u64);
} accept_total_calls SEC(".maps");

struct accept_event {
    __u64 start_time;
    __u16 port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct accept_event);
} accept_events SEC(".maps");

SEC("kprobe/inet_csk_accept")
int inet_csk_accept_entry(struct pt_regs *ctx)
{
    __u64 current_time = bpf_ktime_get_ns();
    __u16 port = 0;
    unsigned long sk_addr;
    bpf_probe_read_kernel(&sk_addr, sizeof(sk_addr), &PT_REGS_PARM1(ctx));
    bpf_probe_read_kernel(&port, sizeof(port), (void *)(sk_addr + 0x2C));
    
    struct accept_event event = {
        .start_time = current_time,
        .port = port
    };
    
    __u64 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_map_update_elem(&accept_events, &pid, &event, BPF_NOEXIST);
    
    __u64 *total_calls = bpf_map_lookup_elem(&accept_total_calls, &port);
    if (total_calls) {
        __sync_fetch_and_add(total_calls, 1);
    } else {
        __u64 initial_count = 1;
        bpf_map_update_elem(&accept_total_calls, &port, &initial_count, BPF_NOEXIST);
    }
    
    return 0;
}

SEC("kretprobe/inet_csk_accept")
int inet_csk_accept_exit(struct pt_regs *ctx)
{
    __u64 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    struct accept_event *event = bpf_map_lookup_elem(&accept_events, &pid);
    
    if (!event) {
        return 0;
    }
    
    __u64 current_time = bpf_ktime_get_ns();
    __u64 latency = current_time - event->start_time;
    
    __u64 *latency_hist = bpf_map_lookup_elem(&accept_latency_histogram, &event->port);
    
    if (latency_hist) {
        __u32 bucket = latency < 1000 ? 0 :
                       latency < 10000 ? 1 :
                       latency < 100000 ? 2 :
                       latency < 1000000 ? 3 :
                       latency < 10000000 ? 4 :
                       latency < 100000000 ? 5 :
                       latency < 1000000000 ? 6 :
                       latency < 10000000000 ? 7 :
                       latency < 100000000000 ? 8 : 9;
        
        __sync_fetch_and_add(&latency_hist[bucket], 1);
    } else {
        __u64 new_latency_hist[LATENCY_BUCKETS] = {0};
        __u32 bucket = latency < 1000 ? 0 :
                       latency < 10000 ? 1 :
                       latency < 100000 ? 2 :
                       latency < 1000000 ? 3 :
                       latency < 10000000 ? 4 :
                       latency < 100000000 ? 5 :
                       latency < 1000000000 ? 6 :
                       latency < 10000000000 ? 7 :
                       latency < 100000000000 ? 8 : 9;
        
        new_latency_hist[bucket] = 1;
        bpf_map_update_elem(&accept_latency_histogram, &event->port, new_latency_hist, BPF_NOEXIST);
    }
    
    bpf_map_delete_elem(&accept_events, &pid);
    
    return 0;
}

char _license[] SEC("license") = "GPL";