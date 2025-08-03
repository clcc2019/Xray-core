// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// TCP拥塞控制状态
struct tcp_congestion_state {
    __u32 cwnd;              // 拥塞窗口大小
    __u32 ssthresh;          // 慢启动阈值
    __u32 rtt;               // 往返时间
    __u32 rtt_min;           // 最小RTT
    __u8 state;              // 状态: 0=slow_start, 1=congestion_avoidance
    __u8 dup_ack_count;      // 重复ACK计数
    __u32 last_ack;          // 最后ACK序列号
    __u64 last_update;       // 最后更新时间
    __u32 retransmit_count;  // 重传计数
    __u32 loss_rate;         // 丢包率
    __u8 ecn_enabled;        // ECN启用标志
    __u8 bbr_enabled;        // BBR启用标志
    __u32 bbr_bw;            // BBR带宽估计
    __u32 bbr_min_rtt;       // BBR最小RTT
} __attribute__((packed));

// 拥塞控制统计
struct congestion_stats {
    __u64 total_connections;
    __u64 slow_start_count;
    __u64 congestion_avoidance_count;
    __u64 retransmit_count;
    __u64 ecn_marks;
    __u64 avg_cwnd;
    __u64 avg_rtt;
};

// eBPF Maps
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __u64);
    __type(value, struct tcp_congestion_state);
} tcp_congestion_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct congestion_stats);
} congestion_statistics SEC(".maps");

// 计算连接ID
static __always_inline __u64 calc_connection_id(__u32 saddr, __u16 sport, __u32 daddr, __u16 dport) {
    return ((__u64)saddr << 32) | ((__u64)daddr) | ((__u64)sport << 16) | dport;
}

// 更新统计信息
static __always_inline void update_congestion_stats(__u32 stat_type) {
    __u32 key = 0;
    struct congestion_stats *stats = bpf_map_lookup_elem(&congestion_statistics, &key);
    if (!stats) {
        struct congestion_stats new_stats = {0};
        bpf_map_update_elem(&congestion_statistics, &key, &new_stats, BPF_ANY);
        stats = bpf_map_lookup_elem(&congestion_statistics, &key);
    }
    if (stats) {
        switch (stat_type) {
            case 0: stats->total_connections++; break;
            case 1: stats->slow_start_count++; break;
            case 2: stats->congestion_avoidance_count++; break;
            case 3: stats->retransmit_count++; break;
            case 4: stats->ecn_marks++; break;
        }
    }
}

// 慢启动算法
static __always_inline void slow_start_algorithm(struct tcp_congestion_state *state, __u32 mss) {
    if (state->state != 0) return;
    
    state->cwnd += mss;
    
    if (state->cwnd >= state->ssthresh) {
        state->state = 1;
        update_congestion_stats(2);
    }
}

// 拥塞避免算法
static __always_inline void congestion_avoidance_algorithm(struct tcp_congestion_state *state, __u32 mss) {
    if (state->state != 1) return;
    
    state->cwnd += (mss * mss) / state->cwnd;
}

// 简化的BBR算法
static __always_inline void bbr_algorithm(struct tcp_congestion_state *state, __u32 mss, __u32 rtt) {
    if (!state->bbr_enabled) return;
    
    // 更新最小RTT
    if (state->bbr_min_rtt == 0 || rtt < state->bbr_min_rtt) {
        state->bbr_min_rtt = rtt;
    }
    
    // 简化的带宽估计（避免复杂除法）
    if (rtt > 0 && rtt < 1000000) { // 限制RTT范围避免溢出
        __u32 new_bw = state->cwnd * 1000 / rtt;
        if (new_bw > state->bbr_bw) {
            state->bbr_bw = new_bw;
        }
    }
    
    // 简化的拥塞窗口调整
    if (state->bbr_bw > 0 && state->bbr_min_rtt > 0) {
        __u32 bbr_cwnd = state->bbr_bw * state->bbr_min_rtt / 1000000;
        if (bbr_cwnd > 0 && bbr_cwnd < state->cwnd) {
            state->cwnd = bbr_cwnd;
        }
    }
}

// 简化的ECN处理
static __always_inline void handle_ecn(struct tcp_congestion_state *state, __u8 ecn_bits) {
    if (!state->ecn_enabled) return;
    
    if (ecn_bits & 0x03) {
        // 简化的拥塞响应
        state->cwnd = state->cwnd * 3 / 4;
        if (state->cwnd < 1460) state->cwnd = 1460;
        
        if (state->ssthresh > state->cwnd) {
            state->ssthresh = state->cwnd;
        }
        
        if (state->state == 0) {
            state->state = 1;
        }
    }
}

// TCP拥塞控制XDP程序
SEC("xdp")
int tcp_congestion_control_xdp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;
    
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;
    
    // 安全地访问以太网头部
    __u16 eth_proto;
    if (bpf_xdp_load_bytes(ctx, 12, &eth_proto, sizeof(eth_proto)) < 0)
        return XDP_PASS;
    if (eth_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;
    
    // 安全地访问IP协议字段
    __u8 ip_proto;
    if (bpf_xdp_load_bytes(ctx, 14 + 9, &ip_proto, sizeof(ip_proto)) < 0)
        return XDP_PASS;
    if (ip_proto != IPPROTO_TCP)
        return XDP_PASS;
    
    struct tcphdr *tcp = (void *)(ip + 1);
    
    // 安全地访问IP和TCP头部字段
    __u32 saddr, daddr;
    __u16 sport, dport;
    
    if (bpf_xdp_load_bytes(ctx, 14 + 12, &saddr, sizeof(saddr)) < 0 ||
        bpf_xdp_load_bytes(ctx, 14 + 16, &daddr, sizeof(daddr)) < 0 ||
        bpf_xdp_load_bytes(ctx, 14 + 20 + 0, &sport, sizeof(sport)) < 0 ||
        bpf_xdp_load_bytes(ctx, 14 + 20 + 2, &dport, sizeof(dport)) < 0) {
        return XDP_PASS;
    }
    
    __u64 conn_id = calc_connection_id(saddr, bpf_ntohs(sport), 
                                      daddr, bpf_ntohs(dport));
    
    struct tcp_congestion_state *state = bpf_map_lookup_elem(&tcp_congestion_states, &conn_id);
    if (!state) {
        struct tcp_congestion_state new_state = {0};
        new_state.cwnd = 10 * 1460;
        new_state.ssthresh = 65535;
        new_state.state = 0;
        new_state.ecn_enabled = 1;
        new_state.bbr_enabled = 1;
        new_state.last_update = bpf_ktime_get_ns() / 1000;
        
        bpf_map_update_elem(&tcp_congestion_states, &conn_id, &new_state, BPF_ANY);
        state = bpf_map_lookup_elem(&tcp_congestion_states, &conn_id);
        update_congestion_stats(0);
    }
    
    if (!state) return XDP_PASS;
    
    __u64 current_time = bpf_ktime_get_ns() / 1000;
    __u32 mss = 1460;
    
    // 安全地访问TCP标志位
    __u8 tcp_flags;
    __u32 ack_seq;
    
    if (bpf_xdp_load_bytes(ctx, 14 + 20 + 13, &tcp_flags, sizeof(tcp_flags)) < 0 ||
        bpf_xdp_load_bytes(ctx, 14 + 20 + 8, &ack_seq, sizeof(ack_seq)) < 0) {
        return XDP_PASS;
    }
    
    if ((tcp_flags & 0x10) && !(tcp_flags & 0x02) && !(tcp_flags & 0x01) && !(tcp_flags & 0x04)) {
        ack_seq = bpf_ntohl(ack_seq);
        
        if (ack_seq == state->last_ack) {
            state->dup_ack_count++;
            
            if (state->dup_ack_count >= 3) {
                state->dup_ack_count = 0;
                state->cwnd = state->cwnd / 2;
                if (state->cwnd < mss) state->cwnd = mss;
            }
        } else {
            state->dup_ack_count = 0;
            state->last_ack = ack_seq;
            
            // 简化的RTT计算
            if (current_time > state->last_update) {
                __u32 rtt = (__u32)(current_time - state->last_update);
                if (rtt < 1000000) { // 限制RTT范围
                    if (state->rtt_min == 0 || rtt < state->rtt_min) {
                        state->rtt_min = rtt;
                    }
                    state->rtt = rtt;
                }
            }
            
            // 简化的拥塞控制
            if (state->state == 0) {
                slow_start_algorithm(state, mss);
            } else if (state->state == 1) {
                congestion_avoidance_algorithm(state, mss);
            }
            
            // 简化的BBR
            if (state->bbr_enabled && state->rtt > 0) {
                bbr_algorithm(state, mss, state->rtt);
            }
        }
    }
    
    if (tcp_flags & 0x02 && !(tcp_flags & 0x10)) {
        state->state = 0;
        state->cwnd = mss;
        state->ssthresh = 65535;
    }
    
    if (tcp_flags & 0x04) {
        bpf_map_delete_elem(&tcp_congestion_states, &conn_id);
        return XDP_PASS;
    }
    
    if (state->ecn_enabled) {
        __u8 tos;
        if (bpf_xdp_load_bytes(ctx, 14 + 1, &tos, sizeof(tos)) >= 0) {
            __u8 ecn_bits = (tos & 0x03);
            handle_ecn(state, ecn_bits);
        }
    }
    
    state->last_update = current_time;
    
    // 简化的统计更新
    __u32 key = 0;
    struct congestion_stats *stats = bpf_map_lookup_elem(&congestion_statistics, &key);
    if (stats && state->cwnd > 0) {
        stats->avg_cwnd = (stats->avg_cwnd + state->cwnd) / 2;
        if (state->rtt > 0) {
            stats->avg_rtt = (stats->avg_rtt + state->rtt) / 2;
        }
    }
    
    return XDP_PASS;
}

// TCP拥塞控制TC程序
SEC("tc/ingress")
int tcp_congestion_control_tc(struct __sk_buff *skb) {
    __u32 key = 0;
    struct congestion_stats *stats = bpf_map_lookup_elem(&congestion_statistics, &key);
    if (stats) {
        stats->total_connections++;
    }
    
    return TC_ACT_OK;
} 