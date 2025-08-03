// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// 简化的TCP连接状态
struct tcp_basic_state {
    __u32 cwnd;              // 拥塞窗口大小
    __u32 ssthresh;          // 慢启动阈值
    __u8 state;              // 状态: 0=slow_start, 1=congestion_avoidance
    __u64 last_update;       // 最后更新时间
} __attribute__((packed));

// 基础统计
struct basic_stats {
    __u64 total_packets;
    __u64 tcp_packets;
    __u64 connections;
};

// eBPF Maps
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);
    __type(value, struct tcp_basic_state);
} tcp_basic_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct basic_stats);
} basic_stats_map SEC(".maps");

// 计算连接ID
static __always_inline __u64 calc_conn_id(__u32 saddr, __u16 sport, __u32 daddr, __u16 dport) {
    return ((__u64)saddr << 32) | ((__u64)daddr) | ((__u64)sport << 16) | dport;
}

// 更新统计
static __always_inline void update_stats(__u32 stat_type) {
    __u32 key = 0;
    struct basic_stats *stats = bpf_map_lookup_elem(&basic_stats_map, &key);
    if (stats) {
        switch (stat_type) {
            case 0: stats->total_packets++; break;
            case 1: stats->tcp_packets++; break;
            case 2: stats->connections++; break;
        }
    }
}

// 简化的慢启动
static __always_inline void basic_slow_start(struct tcp_basic_state *state, __u32 mss) {
    if (state->state != 0) return;
    
    state->cwnd += mss;
    if (state->cwnd >= state->ssthresh) {
        state->state = 1;
    }
}

// 简化的拥塞避免
static __always_inline void basic_congestion_avoidance(struct tcp_basic_state *state, __u32 mss) {
    if (state->state != 1) return;
    
    // 避免除零错误
    if (state->cwnd > 0) {
        state->cwnd += (mss * mss) / state->cwnd;
    }
}

// 基础TCP拥塞控制XDP程序
SEC("xdp")
int tcp_congestion_basic_xdp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 基本验证
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;
    
    // 安全地访问以太网头部
    __u16 eth_proto;
    if (bpf_xdp_load_bytes(ctx, 12, &eth_proto, sizeof(eth_proto)) < 0)
        return XDP_PASS;
    if (eth_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    // 安全地访问IP协议字段
    __u8 ip_proto;
    if (bpf_xdp_load_bytes(ctx, 14 + 9, &ip_proto, sizeof(ip_proto)) < 0)
        return XDP_PASS;
    if (ip_proto != IPPROTO_TCP)
        return XDP_PASS;
    
    update_stats(1); // TCP包计数
    
    // 安全地访问IP和TCP头部字段
    __u32 saddr, daddr;
    __u16 sport, dport;
    
    if (bpf_xdp_load_bytes(ctx, 14 + 12, &saddr, sizeof(saddr)) < 0 ||
        bpf_xdp_load_bytes(ctx, 14 + 16, &daddr, sizeof(daddr)) < 0 ||
        bpf_xdp_load_bytes(ctx, 14 + 20 + 0, &sport, sizeof(sport)) < 0 ||
        bpf_xdp_load_bytes(ctx, 14 + 20 + 2, &dport, sizeof(dport)) < 0) {
        return XDP_PASS;
    }
    
    __u64 conn_id = calc_conn_id(saddr, bpf_ntohs(sport), 
                                 daddr, bpf_ntohs(dport));
    
    struct tcp_basic_state *state = bpf_map_lookup_elem(&tcp_basic_states, &conn_id);
    if (!state) {
        struct tcp_basic_state new_state = {0};
        new_state.cwnd = 10 * 1460;
        new_state.ssthresh = 65535;
        new_state.state = 0;
        new_state.last_update = bpf_ktime_get_ns() / 1000;
        
        bpf_map_update_elem(&tcp_basic_states, &conn_id, &new_state, BPF_ANY);
        update_stats(2); // 新连接计数
        return XDP_PASS;
    }
    
    // 简化的拥塞控制
    __u32 mss = 1460;
    
    if (state->state == 0) {
        basic_slow_start(state, mss);
    } else if (state->state == 1) {
        basic_congestion_avoidance(state, mss);
    }
    
    state->last_update = bpf_ktime_get_ns() / 1000;
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL"; 