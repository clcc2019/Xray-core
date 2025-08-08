// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// 改进版REALITY连接状态
struct reality_improved_conn {
    __u32 client_ip;
    __u32 server_ip;
    __u16 client_port;
    __u16 server_port;
    __u8 state;                    // 0=init, 1=hello_sent, 2=verified, 3=established
    __u8 handshake_stage;          // 0=start, 1=client_hello, 2=server_hello, 3=complete
    __u64 session_id;              // 会话ID
    __u64 handshake_start_time;    // 握手开始时间
    __u64 last_activity;           // 最后活动时间
    __u32 packet_count;            // 数据包计数
    __u64 bytes_transferred;       // 传输字节数
    __u8 is_valid_connection;      // 有效连接标志
    __u8 retry_count;              // 重试次数
    __u32 uuid_hash;               // UUID哈希值
} __attribute__((packed));

// 改进版统计信息
struct reality_improved_stats {
    __u64 total_connections;
    __u64 valid_connections;
    __u64 invalid_connections;
    __u64 successful_handshakes;
    __u64 failed_handshakes;
    __u64 retry_attempts;
    __u64 zero_copy_operations;
    __u64 security_violations;
} __attribute__((packed));

// eBPF映射表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, __u64);    // 连接ID
    __type(value, struct reality_improved_conn);
} reality_improved_connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, __u32);    // 统计ID
    __type(value, struct reality_improved_stats);
} reality_improved_stats SEC(".maps");

// UUID白名单映射表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, __u32);    // UUID哈希
    __type(value, __u8);   // 是否有效
} uuid_whitelist SEC(".maps");

// 安全事件映射表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, __u32);    // 事件类型
    __type(value, __u64);  // 事件计数
} security_events SEC(".maps");

// 辅助函数
static __always_inline __u64 get_current_time() {
    return bpf_ktime_get_ns();
}

static __always_inline __u64 get_connection_id(__u32 saddr, __u16 sport, __u32 daddr, __u16 dport) {
    return ((__u64)saddr << 32) | ((__u64)daddr) | ((__u64)sport << 48) | ((__u64)dport << 32);
}

// 计算UUID哈希
static __always_inline __u32 calculate_uuid_hash(const void *data, const void *data_end) {
    if (data + 16 > data_end) {
        return 0;
    }
    
    __u32 hash = 0;
    for (int i = 0; i < 16; i++) {
        hash = hash * 31 + ((__u8*)data)[i];
    }
    return hash;
}

// 记录安全事件
static __always_inline void record_security_event(__u32 event_type) {
    __u64 *count = bpf_map_lookup_elem(&security_events, &event_type);
    if (count) {
        (*count)++;
        bpf_map_update_elem(&security_events, &event_type, count, BPF_ANY);
    } else {
        __u64 initial_count = 1;
        bpf_map_update_elem(&security_events, &event_type, &initial_count, BPF_ANY);
    }
}

// 更新统计信息
static __always_inline void update_improved_stats(__u32 stat_type) {
    __u32 key = 0;
    struct reality_improved_stats *stats = bpf_map_lookup_elem(&reality_improved_stats, &key);
    if (!stats) {
        struct reality_improved_stats new_stats = {0};
        bpf_map_update_elem(&reality_improved_stats, &key, &new_stats, BPF_ANY);
        stats = bpf_map_lookup_elem(&reality_improved_stats, &key);
    }
    if (stats) {
        switch (stat_type) {
            case 0: // total_connections
                stats->total_connections++;
                break;
            case 1: // valid_connections
                stats->valid_connections++;
                break;
            case 2: // invalid_connections
                stats->invalid_connections++;
                break;
            case 3: // successful_handshakes
                stats->successful_handshakes++;
                break;
            case 4: // failed_handshakes
                stats->failed_handshakes++;
                break;
            case 5: // retry_attempts
                stats->retry_attempts++;
                break;
            case 6: // zero_copy_operations
                stats->zero_copy_operations++;
                break;
            case 7: // security_violations
                stats->security_violations++;
                break;
        }
        bpf_map_update_elem(&reality_improved_stats, &key, stats, BPF_ANY);
    }
}

// 检测改进的REALITY握手
static __always_inline int detect_improved_reality_handshake(const void *data, const void *data_end) {
    if (data + 5 > data_end) {
        return 0;
    }
    
    // 检查TLS ClientHello
    __u8 *tls_data = (__u8*)data;
    if (tls_data[0] != 0x16) { // TLS Handshake
        return 0;
    }
    
    if (tls_data[5] != 0x01) { // ClientHello
        return 0;
    }
    
    // 检查SessionId长度
    if (data + 43 > data_end) {
        return 0;
    }
    
    __u8 session_id_len = tls_data[43];
    if (session_id_len == 0 || session_id_len > 32) {
        return 0;
    }
    
    // 检查SessionId内容（REALITY特征）
    if (data + 44 + session_id_len > data_end) {
        return 0;
    }
    
    // 简单的REALITY检测：检查SessionId是否包含特定模式
    for (int i = 0; i < session_id_len; i++) {
        if (tls_data[44 + i] == 0x00) {
            return 1; // 可能是REALITY
        }
    }
    
    return 0;
}

// 验证UUID白名单
static __always_inline int verify_uuid_whitelist(__u32 uuid_hash) {
    __u8 *valid = bpf_map_lookup_elem(&uuid_whitelist, &uuid_hash);
    return valid ? *valid : 0;
}

// 改进的安全验证
static __always_inline int verify_improved_security(const void *data, const void *data_end, 
                                                   struct reality_improved_conn *conn) {
    if (!conn) {
        return 0;
    }
    
    // 检查连接状态
    if (conn->state > 3) {
        record_security_event(1); // 无效状态
        return 0;
    }
    
    // 检查重试次数
    if (conn->retry_count > 5) {
        record_security_event(2); // 重试过多
        return 0;
    }
    
    // 检查时间戳
    __u64 current_time = get_current_time();
    if (current_time - conn->handshake_start_time > 30000000000) { // 30秒超时
        record_security_event(3); // 握手超时
        return 0;
    }
    
    return 1;
}

// XDP程序：改进的REALITY加速器
SEC("xdp")
int reality_improved_accelerator_xdp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // 基本边界检查
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end) {
        return XDP_PASS;
    }
    
    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (ip->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }
    
    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    __u64 conn_id = get_connection_id(ip->saddr, bpf_ntohs(tcp->source), 
                                     ip->daddr, bpf_ntohs(tcp->dest));
    
    // 查找或创建连接
    struct reality_improved_conn *conn = bpf_map_lookup_elem(&reality_improved_connections, &conn_id);
    if (!conn) {
        // 创建新连接
        struct reality_improved_conn new_conn = {
            .client_ip = ip->saddr,
            .server_ip = ip->daddr,
            .client_port = bpf_ntohs(tcp->source),
            .server_port = bpf_ntohs(tcp->dest),
            .state = 0,
            .handshake_stage = 0,
            .session_id = 0,
            .handshake_start_time = get_current_time(),
            .last_activity = get_current_time(),
            .packet_count = 1,
            .bytes_transferred = data_end - data,
            .is_valid_connection = 0,
            .retry_count = 0,
            .uuid_hash = 0
        };
        
        bpf_map_update_elem(&reality_improved_connections, &conn_id, &new_conn, BPF_ANY);
        update_improved_stats(0); // total_connections
        
        conn = bpf_map_lookup_elem(&reality_improved_connections, &conn_id);
        if (!conn) {
            return XDP_PASS;
        }
    } else {
        // 更新现有连接
        conn->last_activity = get_current_time();
        conn->packet_count++;
        conn->bytes_transferred += data_end - data;
        bpf_map_update_elem(&reality_improved_connections, &conn_id, conn, BPF_ANY);
    }
    
    // 检测REALITY握手
    if (detect_improved_reality_handshake(data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr), data_end)) {
        if (conn->handshake_stage == 0) {
            conn->handshake_stage = 1;
            conn->handshake_start_time = get_current_time();
            
            // 计算UUID哈希
            __u32 uuid_hash = calculate_uuid_hash(data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + 44, data_end);
            conn->uuid_hash = uuid_hash;
            
            // 验证UUID白名单
            if (verify_uuid_whitelist(uuid_hash)) {
                conn->is_valid_connection = 1;
                update_improved_stats(1); // valid_connections
                bpf_trace_printk("REALITY: Valid connection detected, conn_id: %llu\n", 1, conn_id);
            } else {
                conn->is_valid_connection = 0;
                update_improved_stats(2); // invalid_connections
                bpf_trace_printk("REALITY: Invalid connection detected, conn_id: %llu\n", 1, conn_id);
            }
            
            bpf_map_update_elem(&reality_improved_connections, &conn_id, conn, BPF_ANY);
        }
    }
    
    // 安全验证
    if (!verify_improved_security(data, data_end, conn)) {
        conn->retry_count++;
        update_improved_stats(5); // retry_attempts
        bpf_map_update_elem(&reality_improved_connections, &conn_id, conn, BPF_ANY);
        return XDP_PASS;
    }
    
    // 对于有效连接，启用零拷贝
    if (conn->is_valid_connection && conn->handshake_stage >= 1) {
        update_improved_stats(6); // zero_copy_operations
        bpf_trace_printk("REALITY: Zero-copy enabled for valid connection %llu\n", 1, conn_id);
        return XDP_TX; // 零拷贝转发
    }
    
    return XDP_PASS;
}

// TC程序：改进的REALITY统计
SEC("classifier")
int reality_improved_accelerator_tc(struct __sk_buff *skb) {
    __u32 stats_key = 0;
    struct reality_improved_stats *stats = bpf_map_lookup_elem(&reality_improved_stats, &stats_key);
    if (stats) {
        // 更新总连接数
        stats->total_connections++;
        bpf_map_update_elem(&reality_improved_stats, &stats_key, stats, BPF_ANY);
    }
    
    return TC_ACT_OK;
} 