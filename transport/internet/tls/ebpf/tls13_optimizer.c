// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// TLS 1.3连接状态
struct tls13_connection {
    __u32 local_ip;               // 本地IP
    __u32 remote_ip;              // 远程IP
    __u16 local_port;             // 本地端口
    __u16 remote_port;            // 远程端口
    __u8 state;                   // 连接状态: 0=init, 1=client_hello, 2=server_hello, 3=established
    __u8 handshake_type;          // 握手类型
    __u16 tls_version;            // TLS版本
    __u32 cipher_suite;           // 加密套件
    __u64 last_activity;          // 最后活动时间
    __u32 bytes_sent;             // 发送字节数
    __u32 bytes_received;         // 接收字节数
    __u8 resumption;              // 会话恢复标志
} __attribute__((packed));

// TLS 1.3统计
struct tls13_stats {
    __u64 total_connections;
    __u64 client_hellos;
    __u64 server_hellos;
    __u64 established;
    __u64 resumptions;
    __u64 cipher_suites[10];      // 常用加密套件统计
};

// eBPF Maps
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);
    __type(value, struct tls13_connection);
} tls13_connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tls13_stats);
} tls13_statistics SEC(".maps");

// 计算连接ID
static __always_inline __u64 calc_tls13_conn_id(__u32 saddr, __u16 sport, __u32 daddr, __u16 dport) {
    return ((__u64)saddr << 32) | ((__u64)daddr) | ((__u64)sport << 16) | dport;
}

// 更新统计
static __always_inline void update_tls13_stats(__u32 stat_type) {
    __u32 key = 0;
    struct tls13_stats *stats = bpf_map_lookup_elem(&tls13_statistics, &key);
    if (stats) {
        switch (stat_type) {
            case 0: stats->total_connections++; break;
            case 1: stats->client_hellos++; break;
            case 2: stats->server_hellos++; break;
            case 3: stats->established++; break;
            case 4: stats->resumptions++; break;
        }
    }
}

// TLS 1.3握手类型检测
static __always_inline __u8 detect_tls13_handshake(void *data, void *data_end) {
    if (data + 6 > data_end) return 0;
    
    __u8 handshake_type;
    if (bpf_xdp_load_bytes(data, 5, &handshake_type, sizeof(handshake_type)) < 0)
        return 0;
    
    return handshake_type;
}

// TLS版本检测
static __always_inline __u16 detect_tls_version(void *data, void *data_end) {
    if (data + 4 > data_end) return 0;
    
    __u16 version;
    if (bpf_xdp_load_bytes(data, 1, &version, sizeof(version)) < 0)
        return 0;
    
    return bpf_ntohs(version);
}

// 加密套件检测
static __always_inline __u32 detect_cipher_suite(void *data, void *data_end) {
    if (data + 50 > data_end) return 0;
    
    __u16 cipher_suite;
    if (bpf_xdp_load_bytes(data, 43, &cipher_suite, sizeof(cipher_suite)) < 0)
        return 0;
    
    return bpf_ntohs(cipher_suite);
}

// TLS 1.3 XDP程序
SEC("xdp")
int tls13_optimizer_xdp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 基本验证
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + 6 > data_end)
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
    
    // 安全地访问IP和TCP头部字段
    __u32 saddr, daddr;
    __u16 sport, dport;
    
    if (bpf_xdp_load_bytes(ctx, 14 + 12, &saddr, sizeof(saddr)) < 0 ||
        bpf_xdp_load_bytes(ctx, 14 + 16, &daddr, sizeof(daddr)) < 0 ||
        bpf_xdp_load_bytes(ctx, 14 + 20 + 0, &sport, sizeof(sport)) < 0 ||
        bpf_xdp_load_bytes(ctx, 14 + 20 + 2, &dport, sizeof(dport)) < 0) {
        return XDP_PASS;
    }
    
    // 检查TLS端口 (443, 993, 995等)
    __u16 tcp_sport = bpf_ntohs(sport);
    __u16 tcp_dport = bpf_ntohs(dport);
    
    if (tcp_dport != 443 && tcp_dport != 993 && tcp_dport != 995 && 
        tcp_sport != 443 && tcp_sport != 993 && tcp_sport != 995) {
        return XDP_PASS;
    }
    
    // 访问TLS负载
    void *tls_payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
    
    // 检测TLS版本
    __u16 tls_version = detect_tls_version(tls_payload, data_end);
    if (tls_version != 0x0304) { // TLS 1.3
        return XDP_PASS;
    }
    
    // 检测握手类型
    __u8 handshake_type = detect_tls13_handshake(tls_payload, data_end);
    
    __u64 conn_id = calc_tls13_conn_id(saddr, tcp_sport, daddr, tcp_dport);
    
    struct tls13_connection *conn = bpf_map_lookup_elem(&tls13_connections, &conn_id);
    if (!conn) {
        struct tls13_connection new_conn = {0};
        new_conn.local_ip = saddr;
        new_conn.remote_ip = daddr;
        new_conn.local_port = tcp_sport;
        new_conn.remote_port = tcp_dport;
        new_conn.tls_version = tls_version;
        new_conn.last_activity = bpf_ktime_get_ns() / 1000;
        
        bpf_map_update_elem(&tls13_connections, &conn_id, &new_conn, BPF_ANY);
        update_tls13_stats(0); // total_connections
        conn = bpf_map_lookup_elem(&tls13_connections, &conn_id);
    }
    
    if (!conn) return XDP_PASS;
    
    // 处理握手类型
    switch (handshake_type) {
        case 0x01: // Client Hello
            conn->state = 1;
            conn->handshake_type = handshake_type;
            conn->cipher_suite = detect_cipher_suite(tls_payload, data_end);
            update_tls13_stats(1); // client_hellos
            break;
            
        case 0x02: // Server Hello
            conn->state = 2;
            conn->handshake_type = handshake_type;
            update_tls13_stats(2); // server_hellos
            break;
            
        case 0x14: // Finished
            conn->state = 3; // established
            update_tls13_stats(3); // established
            break;
            
        case 0x04: // New Session Ticket (会话恢复)
            conn->resumption = 1;
            update_tls13_stats(4); // resumptions
            break;
    }
    
    conn->last_activity = bpf_ktime_get_ns() / 1000;
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL"; 