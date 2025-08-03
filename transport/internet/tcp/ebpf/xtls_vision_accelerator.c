// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/string.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// XTLS Vision入站连接状态
struct xtls_vision_inbound {
    __u32 client_ip;
    __u32 server_ip;
    __u16 client_port;
    __u16 server_port;
    __u8 state;              // 0=init, 1=reality_handshake, 2=tls_handshake, 3=vision_active
    __u8 reality_verified;   // REALITY握手是否完成
    __u8 tls_version;        // TLS版本
    __u8 vision_enabled;     // XTLS Vision是否启用
    __u64 handshake_time;    // 握手完成时间
    __u64 bytes_received;    // 接收字节数（客户端->服务端）
    __u64 bytes_sent;        // 发送字节数（服务端->客户端）
    __u32 splice_count;      // splice操作次数
    __u32 vision_packets;    // Vision处理的数据包数
    __u64 last_activity;     // 最后活动时间
    __u32 dest_ip;           // 目标IP（用于REALITY）
    __u16 dest_port;         // 目标端口（用于REALITY）
} __attribute__((packed));

// XTLS Vision统计信息
struct xtls_vision_stats {
    __u64 total_inbound_connections;
    __u64 reality_connections;
    __u64 vision_connections;
    __u64 handshake_count;
    __u64 splice_count;
    __u64 vision_packets;
    __u64 total_bytes_received;
    __u64 total_bytes_sent;
    __u64 avg_handshake_time;
};

// 映射表定义
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, __u64);    // 连接ID
    __type(value, struct xtls_vision_inbound);
} xtls_inbound_connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, __u32);    // 统计ID (0)
    __type(value, struct xtls_vision_stats);
} xtls_stats SEC(".maps");

// 热点连接缓存
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);    // 连接ID
    __type(value, __u64);  // 访问时间
} hot_connections SEC(".maps");

// 获取当前时间戳
static __always_inline __u64 get_current_time() {
    return bpf_ktime_get_ns() / 1000000000; // 转换为秒
}

// 计算连接ID
static __always_inline __u64 get_connection_id(__u32 saddr, __u16 sport, __u32 daddr, __u16 dport) {
    return ((__u64)saddr << 32) | ((__u64)daddr) | ((__u64)sport << 48) | ((__u64)dport << 32);
}

// 更新统计信息
static __always_inline void update_stats(__u32 stat_type) {
    __u32 key = 0;
    struct xtls_vision_stats *stats = bpf_map_lookup_elem(&xtls_stats, &key);
    if (!stats) {
        struct xtls_vision_stats new_stats = {0};
        bpf_map_update_elem(&xtls_stats, &key, &new_stats, BPF_ANY);
        stats = bpf_map_lookup_elem(&xtls_stats, &key);
    }
    if (stats) {
        switch (stat_type) {
            case 0: // total_inbound_connections
                stats->total_inbound_connections++;
                break;
            case 1: // reality_connections
                stats->reality_connections++;
                break;
            case 2: // vision_connections
                stats->vision_connections++;
                break;
            case 3: // handshake_count
                stats->handshake_count++;
                break;
            case 4: // splice_count
                stats->splice_count++;
                break;
            case 5: // vision_packets
                stats->vision_packets++;
                break;
        }
    }
}

// 检测REALITY握手
static __always_inline int detect_reality_handshake(const void *data, const void *data_end) {
    if (data + 5 > data_end) return 0;
    
    const unsigned char *ptr = data;
    
    // 检查TLS记录类型 (0x16 = Handshake)
    if (ptr[0] != 0x16) return 0;
    
    // 检查TLS版本 (0x0304 = TLS 1.3)
    __u16 version = bpf_ntohs(*(__u16*)(ptr + 1));
    if (version != 0x0304) return 0;
    
    // 检查数据长度
    __u16 length = bpf_ntohs(*(__u16*)(ptr + 3));
    if (length < 10) return 0;
    
    // REALITY通常有特定的ClientHello模式
    if (data + 10 > data_end) return 0;
    
    // 检查ClientHello特征
    if (ptr[5] == 0x01) { // Handshake type = ClientHello
        return 1;
    }
    
    return 0;
}

// 检测XTLS Vision特征
static __always_inline int detect_xtls_vision(const void *data, const void *data_end) {
    if (data + 10 > data_end) return 0;
    
    const unsigned char *ptr = data;
    
    // 检查TLS Application Data (0x17)
    if (ptr[0] != 0x17) return 0;
    
    // 检查TLS 1.3版本
    __u16 version = bpf_ntohs(*(__u16*)(ptr + 1));
    if (version != 0x0304) return 0;
    
    // 检查数据长度
    __u16 length = bpf_ntohs(*(__u16*)(ptr + 3));
    if (length < 5) return 0;
    
    // 检查XTLS Vision特征字节
    if (data + 9 > data_end) return 0;
    
    // Vision通常有特定的数据模式
    if (ptr[5] == 0x01 && ptr[6] == 0x00) return 1; // Vision命令
    
    return 0;
}

// 优化入站XTLS Vision数据包
static __always_inline int optimize_inbound_vision_packet(struct xdp_md *ctx, 
                                                        struct xtls_vision_inbound *conn) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;
    
    struct iphdr *ip = data + sizeof(struct ethhdr);
    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    
    // 检查是否是XTLS Vision数据包
    if (detect_xtls_vision(tcp + 1, data_end)) {
        conn->vision_packets++;
        conn->last_activity = get_current_time();
        
        // 更新统计
        update_stats(5); // vision_packets
        
        // 对于Vision数据包，启用零拷贝优化
        if (conn->state == 3) { // vision_active
            conn->splice_count++;
            update_stats(4); // splice_count
            
            // 更新字节计数
            __u32 packet_size = bpf_ntohs(ip->tot_len);
            conn->bytes_received += packet_size;
            
            return XDP_TX; // 零拷贝转发
        }
    }
    
    return XDP_PASS;
}

// 主XDP程序 - XTLS Vision入站加速器
SEC("xdp")
int xtls_vision_inbound_accelerator_xdp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 基本验证
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;
    
    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;
    
    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    
    // 只处理目标端口443的流量（REALITY服务）
    if (tcp->dest != bpf_htons(443))
        return XDP_PASS;
    
    // 计算连接标识符
    __u64 conn_id = get_connection_id(ip->saddr, tcp->source, ip->daddr, tcp->dest);
    
    // 查找连接状态
    struct xtls_vision_inbound *conn = bpf_map_lookup_elem(&xtls_inbound_connections, &conn_id);
    
    // 处理SYN包 - 创建新入站连接
    if (tcp->syn && !tcp->ack) {
        if (!conn) {
            struct xtls_vision_inbound new_conn = {
                .client_ip = ip->saddr,
                .server_ip = ip->daddr,
                .client_port = tcp->source,
                .server_port = tcp->dest,
                .state = 0, // init
                .reality_verified = 0,
                .tls_version = 0,
                .vision_enabled = 0,
                .handshake_time = 0,
                .bytes_received = 0,
                .bytes_sent = 0,
                .splice_count = 0,
                .vision_packets = 0,
                .last_activity = get_current_time(),
                .dest_ip = 0,
                .dest_port = 0
            };
            bpf_map_update_elem(&xtls_inbound_connections, &conn_id, &new_conn, BPF_ANY);
            update_stats(0); // total_inbound_connections
        }
        return XDP_PASS;
    }
    
    // 处理已建立的连接
    if (conn) {
        conn->last_activity = get_current_time();
        
        // 检测REALITY握手
        if (conn->state == 0 && detect_reality_handshake(tcp + 1, data_end)) {
            conn->state = 1; // reality_handshake
            conn->tls_version = 0x04; // TLS 1.3
            update_stats(1); // reality_connections
        }
        
        // 检测TLS握手完成
        if (conn->state == 1) {
            // 检查是否有TLS Application Data
            if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + 5 <= data_end) {
                const unsigned char *ptr = (const unsigned char*)(tcp + 1);
                if (ptr[0] == 0x17) { // Application Data
                    conn->state = 2; // tls_handshake
                    conn->reality_verified = 1;
                }
            }
        }
        
        // 检测XTLS Vision
        if (conn->state == 2 && detect_xtls_vision(tcp + 1, data_end)) {
            conn->state = 3; // vision_active
            conn->vision_enabled = 1;
            conn->handshake_time = get_current_time();
            update_stats(2); // vision_connections
            update_stats(3); // handshake_count
        }
        
        // 优化Vision数据包
        if (conn->vision_enabled) {
            return optimize_inbound_vision_packet(ctx, conn);
        }
        
        // 更新字节计数
        __u32 packet_size = bpf_ntohs(ip->tot_len);
        if (ip->saddr == conn->client_ip) {
            conn->bytes_received += packet_size;
        } else {
            conn->bytes_sent += packet_size;
        }
    }
    
    return XDP_PASS;
}

// TC程序 - 入站出口优化
SEC("tc")
int xtls_vision_inbound_accelerator_tc(struct __sk_buff *skb) {
    // 简化的TC程序，只更新基本统计
    __u32 key = 0;
    struct xtls_vision_stats *stats = bpf_map_lookup_elem(&xtls_stats, &key);
    if (stats) {
        // 可以在这里添加更详细的统计信息
    }
    
    return TC_ACT_OK;
} 