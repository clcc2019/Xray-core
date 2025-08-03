// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// QUIC连接状态
struct quic_connection {
    __u32 local_ip;               // 本地IP
    __u32 remote_ip;              // 远程IP
    __u16 local_port;             // 本地端口
    __u16 remote_port;            // 远程端口
    __u8 state;                   // 连接状态: 0=init, 1=handshake, 2=established
    __u64 connection_id;          // QUIC连接ID
    __u32 stream_id;              // 流ID
    __u64 last_activity;          // 最后活动时间
    __u32 bytes_sent;             // 发送字节数
    __u32 bytes_received;         // 接收字节数
    __u8 version;                 // QUIC版本
    __u8 encryption_level;        // 加密级别
} __attribute__((packed));

// QUIC统计
struct quic_stats {
    __u64 total_packets;
    __u64 handshake_packets;
    __u64 data_packets;
    __u64 connections;
    __u64 streams;
};

// eBPF Maps
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);
    __type(value, struct quic_connection);
} quic_connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct quic_stats);
} quic_statistics SEC(".maps");

// 计算连接ID
static __always_inline __u64 calc_quic_conn_id(__u32 saddr, __u16 sport, __u32 daddr, __u16 dport) {
    return ((__u64)saddr << 32) | ((__u64)daddr) | ((__u64)sport << 16) | dport;
}

// 更新统计
static __always_inline void update_quic_stats(__u32 stat_type) {
    __u32 key = 0;
    struct quic_stats *stats = bpf_map_lookup_elem(&quic_statistics, &key);
    if (stats) {
        switch (stat_type) {
            case 0: stats->total_packets++; break;
            case 1: stats->handshake_packets++; break;
            case 2: stats->data_packets++; break;
            case 3: stats->connections++; break;
            case 4: stats->streams++; break;
        }
    }
}

// 简化的QUIC检测 - 基于端口和协议
static __always_inline int detect_quic_traffic(__u16 sport, __u16 dport) {
    // 检查QUIC常用端口
    if (sport == 443 || sport == 80 || sport == 8080 ||
        dport == 443 || dport == 80 || dport == 8080) {
        return 1;
    }
    return 0;
}

// QUIC XDP程序
SEC("xdp")
int quic_accelerator_xdp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 基本验证
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
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
    if (ip_proto != IPPROTO_UDP)
        return XDP_PASS;
    
    // 安全地访问IP和UDP头部字段
    __u32 saddr, daddr;
    __u16 sport, dport;
    
    if (bpf_xdp_load_bytes(ctx, 14 + 12, &saddr, sizeof(saddr)) < 0 ||
        bpf_xdp_load_bytes(ctx, 14 + 16, &daddr, sizeof(daddr)) < 0 ||
        bpf_xdp_load_bytes(ctx, 14 + 20 + 0, &sport, sizeof(sport)) < 0 ||
        bpf_xdp_load_bytes(ctx, 14 + 20 + 2, &dport, sizeof(dport)) < 0) {
        return XDP_PASS;
    }
    
    // 检查QUIC端口 (443, 80, 8080等)
    __u16 udp_sport = bpf_ntohs(sport);
    __u16 udp_dport = bpf_ntohs(dport);
    
    if (detect_quic_traffic(udp_sport, udp_dport)) {
        update_quic_stats(0); // total_packets
        
        __u64 conn_id = calc_quic_conn_id(saddr, udp_sport, daddr, udp_dport);
        
        struct quic_connection *conn = bpf_map_lookup_elem(&quic_connections, &conn_id);
        if (!conn) {
            struct quic_connection new_conn = {0};
            new_conn.local_ip = saddr;
            new_conn.remote_ip = daddr;
            new_conn.local_port = udp_sport;
            new_conn.remote_port = udp_dport;
            new_conn.state = 1; // handshake
            new_conn.connection_id = conn_id;
            new_conn.last_activity = bpf_ktime_get_ns() / 1000;
            new_conn.version = 1;
            new_conn.encryption_level = 0;
            
            bpf_map_update_elem(&quic_connections, &conn_id, &new_conn, BPF_ANY);
            update_quic_stats(3); // connections
        } else {
            conn->last_activity = bpf_ktime_get_ns() / 1000;
            if (conn->state == 1) {
                conn->state = 2; // established
            }
        }
        
        update_quic_stats(2); // data_packets
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL"; 