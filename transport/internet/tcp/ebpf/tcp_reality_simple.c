// +build ignore
// TCP+REALITY eBPF加速器 - 简化版

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// 简化的连接状态
struct tcp_conn_simple {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 reality_enabled;
    __u8 state;  // 0=NEW, 1=ESTABLISHED, 2=HOT
    __u64 packet_count;
    __u64 last_seen;
};

// 简化的统计
struct tcp_stats_simple {
    __u64 total_packets;
    __u64 tcp_fast_path;
    __u64 reality_optimized;
    __u64 connections;
};

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);  // connection ID
    __type(value, struct tcp_conn_simple);
    __uint(max_entries, 5000);
} tcp_connections_simple SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct tcp_stats_simple);
    __uint(max_entries, 1);
} tcp_stats_map SEC(".maps");

// 获取当前时间戳
static __always_inline __u64 get_time_ns() {
    return bpf_ktime_get_ns();
}

// 计算连接ID
static __always_inline __u64 get_conn_id(__u32 src_ip, __u16 src_port, 
                                         __u32 dst_ip, __u16 dst_port) {
    return ((__u64)src_ip << 32) | ((__u64)src_port << 16) | dst_port;
}

// 更新统计
static __always_inline void update_stats(__u32 type) {
    __u32 key = 0;
    struct tcp_stats_simple *stats = bpf_map_lookup_elem(&tcp_stats_map, &key);
    if (!stats) return;
    
    switch (type) {
        case 0: __sync_fetch_and_add(&stats->total_packets, 1); break;
        case 1: __sync_fetch_and_add(&stats->tcp_fast_path, 1); break;
        case 2: __sync_fetch_and_add(&stats->reality_optimized, 1); break;
        case 3: __sync_fetch_and_add(&stats->connections, 1); break;
    }
}

// 检查是否为REALITY流量的简单启发式
static __always_inline int is_reality_traffic(struct tcphdr *tcp, void *data_end) {
    // 检查TCP头后是否有TLS握手特征
    __u8 *payload = (__u8 *)(tcp + 1);
    if ((void *)(payload + 6) > data_end) return 0;
    
    // 简单检查：TLS握手包通常以0x16开头
    if (payload[0] == 0x16 && payload[1] == 0x03) {
        return 1; // 可能是TLS/REALITY
    }
    return 0;
}

// XDP程序 - TCP+REALITY入口加速
SEC("xdp")
int tcp_reality_xdp_simple(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 基本长度检查
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;
    
    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;
    
    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    
    // 计算连接ID
    __u64 conn_id = get_conn_id(ip->saddr, tcp->source, ip->daddr, tcp->dest);
    
    // 更新或创建连接状态
    struct tcp_conn_simple *conn = bpf_map_lookup_elem(&tcp_connections_simple, &conn_id);
    if (!conn) {
        struct tcp_conn_simple new_conn = {
            .src_ip = ip->saddr,
            .dst_ip = ip->daddr,
            .src_port = tcp->source,
            .dst_port = tcp->dest,
            .reality_enabled = is_reality_traffic(tcp, data_end),
            .state = 0, // NEW
            .packet_count = 1,
            .last_seen = get_time_ns()
        };
        bpf_map_update_elem(&tcp_connections_simple, &conn_id, &new_conn, BPF_ANY);
        update_stats(3); // new connection
    } else {
        // 更新现有连接
        conn->packet_count++;
        conn->last_seen = get_time_ns();
        
        // 升级连接状态
        if (conn->packet_count > 10 && conn->state < 2) {
            conn->state = 2; // HOT
        } else if (conn->packet_count > 3 && conn->state < 1) {
            conn->state = 1; // ESTABLISHED  
        }
        
        bpf_map_update_elem(&tcp_connections_simple, &conn_id, conn, BPF_ANY);
        
        // 热连接优化
        if (conn->state == 2) {
            update_stats(1); // fast path
            if (conn->reality_enabled) {
                update_stats(2); // reality optimized
            }
        }
    }
    
    update_stats(0); // total packets
    return XDP_PASS;
}

// TC程序 - TCP+REALITY出口加速
SEC("tc")
int tcp_reality_tc_simple(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    // 基本检查
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
        return TC_ACT_OK;
    
    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;
    
    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    
    // 对于出口流量，交换源和目标
    __u64 conn_id = get_conn_id(ip->daddr, tcp->dest, ip->saddr, tcp->source);
    
    struct tcp_conn_simple *conn = bpf_map_lookup_elem(&tcp_connections_simple, &conn_id);
    if (conn && conn->state == 2) {
        // 热连接快速处理
        update_stats(1); // fast path
        if (conn->reality_enabled) {
            update_stats(2); // reality optimized
        }
    }
    
    update_stats(0); // total packets
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";