#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Define a map to store the count of sockets with low receive slow start threshold
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   // PID or Socket ID
    __type(value, __u64); // Count of low rcv_ssthresh instances
} low_rcv_ssthresh SEC(".maps");

// Threshold value for receive slow start threshold (configurable)
#define RCV_SSTHRESH_THRESHOLD 1024

// Kernel function tracing structure for fentry/fexit and kprobe compatibility
struct trace_event_raw_tcp_rcv {
    __u64 pad;
    struct sock *sk;
};

// Helper function to process receive slow start threshold
static __always_inline int process_rcv_ssthresh(struct sock *sk) {
    if (!sk) {
        return 0;
    }

    // Safely access rcv_ssthresh using BPF helpers
    __u32 rcv_ssthresh = 0;
    bpf_probe_read_kernel(&rcv_ssthresh, sizeof(rcv_ssthresh), 
                          (void *)((unsigned long)sk + offsetof(struct tcp_sock, rcv_ssthresh)));

    // Check if rcv_ssthresh is below threshold
    if (rcv_ssthresh < RCV_SSTHRESH_THRESHOLD) {
        __u32 pid = bpf_get_current_pid_tgid() >> 32;
        __u64 *count = bpf_map_lookup_elem(&low_rcv_ssthresh, &pid);

        if (count) {
            // Increment existing count with atomic operation
            __sync_fetch_and_add(count, 1);
        } else {
            // Initialize count to 1
            __u64 init_count = 1;
            bpf_map_update_elem(&low_rcv_ssthresh, &pid, &init_count, BPF_NOEXIST);
        }
    }

    return 0;
}

// fentry/fexit tracing program
SEC("fentry/tcp_rcv_established")
int BPF_PROG(fentry_tcp_rcv, struct sock *sk) {
    return process_rcv_ssthresh(sk);
}

SEC("fexit/tcp_rcv_established")
int BPF_PROG(fexit_tcp_rcv, struct sock *sk, int ret) {
    return process_rcv_ssthresh(sk);
}

// kprobe tracing program
SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(kprobe_tcp_rcv, struct sock *sk) {
    return process_rcv_ssthresh(sk);
}

// License required for kernel module loading
char _license[] SEC("license") = "GPL";