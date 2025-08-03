// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// 零拷贝连接状态
struct zerocopy_connection {
    __u32 local_ip;               // 本地IP
    __u32 remote_ip;              // 远程IP
    __u16 local_port;             // 本地端口
    __u16 remote_port;            // 远程端口
    __u8 protocol;                // 协议: 6=TCP, 17=UDP
    __u8 state;                   // 状态: 0=init, 1=established, 2=optimized
    __u32 packet_size;            // 数据包大小
    __u64 last_activity;          // 最后活动时间
    __u32 bytes_sent;             // 发送字节数
    __u32 bytes_received;         // 接收字节数
    __u32 splice_count;           // splice操作次数
    __u32 readv_count;            // readv操作次数
} __attribute__((packed));

// 零拷贝统计
struct zerocopy_stats {
    __u64 total_packets;
    __u64 tcp_packets;
    __u64 udp_packets;
    __u64 optimized_connections;
    __u64 splice_operations;
    __u64 readv_operations;
    __u64 bytes_optimized;
};

// eBPF Maps
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);
    __type(value, struct zerocopy_connection);
} zerocopy_connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct zerocopy_stats);
} zerocopy_statistics SEC(".maps");

// 计算连接ID
static __always_inline __u64 calc_zerocopy_conn_id(__u32 saddr, __u16 sport, __u32 daddr, __u16 dport) {
    return ((__u64)saddr << 32) | ((__u64)daddr) | ((__u64)sport << 16) | dport;
}

// 更新统计
static __always_inline void update_zerocopy_stats(__u32 stat_type) {
    __u32 key = 0;
    struct zerocopy_stats *stats = bpf_map_lookup_elem(&zerocopy_statistics, &key);
    if (stats) {
        switch (stat_type) {
            case 0: stats->total_packets++; break;
            case 1: stats->tcp_packets++; break;
            case 2: stats->udp_packets++; break;
            case 3: stats->optimized_connections++; break;
            case 4: stats->splice_operations++; break;
            case 5: stats->readv_operations++; break;
        }
    }
}

// 零拷贝优化决策
static __always_inline int should_optimize_zerocopy(__u32 packet_size, __u8 protocol) {
    // 对于大包和TCP连接优先使用splice
    if (packet_size > 1024 && protocol == IPPROTO_TCP) {
        return 1; // 使用splice
    }
    
    // 对于小包和UDP连接使用readv
    if (packet_size <= 1024 && protocol == IPPROTO_UDP) {
        return 2; // 使用readv
    }
    
    return 0; // 不优化
}

// 零拷贝XDP程序
SEC("xdp")
int zerocopy_optimizer_xdp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 基本验证
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
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
    if (ip_proto != IPPROTO_TCP && ip_proto != IPPROTO_UDP)
        return XDP_PASS;
    
    // 安全地访问IP头部字段
    __u32 saddr, daddr;
    __u16 sport, dport;
    
    if (bpf_xdp_load_bytes(ctx, 14 + 12, &saddr, sizeof(saddr)) < 0 ||
        bpf_xdp_load_bytes(ctx, 14 + 16, &daddr, sizeof(daddr)) < 0) {
        return XDP_PASS;
    }
    
    // 根据协议访问端口
    if (ip_proto == IPPROTO_TCP) {
        if (bpf_xdp_load_bytes(ctx, 14 + 20 + 0, &sport, sizeof(sport)) < 0 ||
            bpf_xdp_load_bytes(ctx, 14 + 20 + 2, &dport, sizeof(dport)) < 0) {
            return XDP_PASS;
        }
        update_zerocopy_stats(1); // tcp_packets
    } else if (ip_proto == IPPROTO_UDP) {
        if (bpf_xdp_load_bytes(ctx, 14 + 20 + 0, &sport, sizeof(sport)) < 0 ||
            bpf_xdp_load_bytes(ctx, 14 + 20 + 2, &dport, sizeof(dport)) < 0) {
            return XDP_PASS;
        }
        update_zerocopy_stats(2); // udp_packets
    }
    
    __u16 src_port = bpf_ntohs(sport);
    __u16 dst_port = bpf_ntohs(dport);
    
    // 计算数据包大小
    __u32 packet_size = (__u32)(data_end - data);
    
    __u64 conn_id = calc_zerocopy_conn_id(saddr, src_port, daddr, dst_port);
    
    struct zerocopy_connection *conn = bpf_map_lookup_elem(&zerocopy_connections, &conn_id);
    if (!conn) {
        struct zerocopy_connection new_conn = {0};
        new_conn.local_ip = saddr;
        new_conn.remote_ip = daddr;
        new_conn.local_port = src_port;
        new_conn.remote_port = dst_port;
        new_conn.protocol = ip_proto;
        new_conn.state = 1; // established
        new_conn.packet_size = packet_size;
        new_conn.last_activity = bpf_ktime_get_ns() / 1000;
        
        bpf_map_update_elem(&zerocopy_connections, &conn_id, &new_conn, BPF_ANY);
        conn = bpf_map_lookup_elem(&zerocopy_connections, &conn_id);
    }
    
    if (!conn) return XDP_PASS;
    
    // 更新连接信息
    conn->packet_size = packet_size;
    conn->last_activity = bpf_ktime_get_ns() / 1000;
    
    // 零拷贝优化决策
    int optimize_type = should_optimize_zerocopy(packet_size, ip_proto);
    
    if (optimize_type == 1) { // splice优化
        conn->splice_count++;
        update_zerocopy_stats(4); // splice_operations
        conn->state = 2; // optimized
        update_zerocopy_stats(3); // optimized_connections
    } else if (optimize_type == 2) { // readv优化
        conn->readv_count++;
        update_zerocopy_stats(5); // readv_operations
        conn->state = 2; // optimized
        update_zerocopy_stats(3); // optimized_connections
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL"; 