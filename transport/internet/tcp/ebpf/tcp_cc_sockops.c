// +build ignore

#include <linux/bpf.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

// Policy map configured from userspace
struct cc_policy_config {
    __u32 rtt_us_threshold;     // Switch to BBR if smoothed RTT > threshold
    __u32 loss_pct_threshold;   // Switch to CUBIC if loss% > threshold
    __u8  prefer_bbr;           // 1: prefer BBR when unsure; 0: prefer CUBIC
    __u8  enable_bbr;           // 1: allow selecting BBR
    __u8  enable_cubic;         // 1: allow selecting CUBIC
    __u8  init_cwnd_pkts;       // Optional: initial cwnd packets (if kernel supports TCP_BPF_IW)
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cc_policy_config);
} tcp_cc_policy SEC(".maps");

// Read TCP_INFO from kernel for this socket
static __always_inline int get_tcp_info(struct bpf_sock_ops *skops, struct tcp_info *info) {
    int optlen = sizeof(*info);
    return bpf_getsockopt(skops, IPPROTO_TCP, TCP_INFO, info, optlen);
}

// Attempt to set congestion control algorithm
static __always_inline void set_cc(struct bpf_sock_ops *skops, const char *name, int len) {
    // bpf_setsockopt copies the buffer; string must be in BPF program memory
    bpf_setsockopt(skops, IPPROTO_TCP, TCP_CONGESTION, (void *)name, len);
}

SEC("sockops")
int tcp_cc_sockops(struct bpf_sock_ops *skops) {
    __u32 key = 0;
    struct cc_policy_config *cfg = bpf_map_lookup_elem(&tcp_cc_policy, &key);
    struct tcp_info info = {0};

    // Defaults if map not yet configured
    __u32 rtt_thr = cfg ? cfg->rtt_us_threshold : 30000;       // 30ms
    __u32 loss_thr = cfg ? cfg->loss_pct_threshold : 2;        // 2%
    __u8 prefer_bbr = cfg ? cfg->prefer_bbr : 1;
    __u8 enable_bbr = cfg ? cfg->enable_bbr : 1;
    __u8 enable_cubic = cfg ? cfg->enable_cubic : 1;

    // Predeclare names to keep them in BPF prog memory
    const char cubic[] = "cubic";
    const char bbr[] = "bbr";

    switch (skops->op) {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        // On establish: set initial cc based on preference
        if (enable_bbr && prefer_bbr) {
            set_cc(skops, bbr, sizeof(bbr));
        } else if (enable_cubic) {
            set_cc(skops, cubic, sizeof(cubic));
        }
#ifdef TCP_BPF_IW
        if (cfg && cfg->init_cwnd_pkts > 0) {
            __u32 iw = cfg->init_cwnd_pkts;
            bpf_setsockopt(skops, SOL_TCP, TCP_BPF_IW, &iw, sizeof(iw));
        }
#endif
        break;

    case BPF_SOCK_OPS_RTO_CB:
    case BPF_SOCK_OPS_STATE_CB:
        // Periodically evaluate RTT/loss and adjust CC
        if (get_tcp_info(skops, &info) == 0) {
            // tcpi_rtt is usec, tcpi_total_retrans approximates loss
            // If RTT high and BBR enabled -> switch to BBR
            if (enable_bbr && info.tcpi_rtt > rtt_thr) {
                set_cc(skops, bbr, sizeof(bbr));
            }
            // If high retrans or loss threshold hit -> switch to CUBIC (more conservative)
            // Loss percent not directly available; use retrans/packets heuristic if present
#ifdef TCP_CA_NAME_MAX
#endif
            if (enable_cubic) {
                // If reordering/loss signals present
                if (info.tcpi_total_retrans > 0 && info.tcpi_rtt < rtt_thr / 2) {
                    set_cc(skops, cubic, sizeof(cubic));
                }
            }
        }
        break;
    default:
        break;
    }
    return 0;
}

char _license[] SEC("license") = "GPL";


