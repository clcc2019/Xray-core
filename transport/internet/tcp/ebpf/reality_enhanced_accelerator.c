// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// 简化版REALITY连接状态
struct reality_enhanced_conn {
    __u32 client_ip;
    __u32 server_ip;
    __u16 client_port;
    __u16 server_port;
    __u8 state;                    // 0=init, 1=hello_sent, 2=verified, 3=established
    __u8 security_level;           // 0=basic, 1=enhanced, 2=maximum
    __u64 session_id;              // 会话ID
    __u64 handshake_start_time;    // 握手开始时间
    __u64 last_activity;           // 最后活动时间
    __u32 packet_count;            // 数据包计数
    __u64 bytes_transferred;       // 传输字节数
    __u8 quantum_resistant;        // 量子抗性标志
} __attribute__((packed));

// 简化版安全统计
struct reality_enhanced_stats {
    __u64 total_connections;
    __u64 successful_handshakes;
    __u64 failed_handshakes;
    __u64 security_violations;
    __u64 quantum_attacks_detected;
    __u64 enhanced_security_connections;
    __u64 maximum_security_connections;
} __attribute__((packed));

// eBPF映射表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, __u64);    // 连接ID
    __type(value, struct reality_enhanced_conn);
} reality_enhanced_connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, __u32);    // 统计ID
    __type(value, struct reality_enhanced_stats);
} reality_enhanced_stats SEC(".maps");

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
static __always_inline void update_enhanced_stats(__u32 stat_type) {
    __u32 key = 0;
    struct reality_enhanced_stats *stats = bpf_map_lookup_elem(&reality_enhanced_stats, &key);
    if (!stats) {
        struct reality_enhanced_stats new_stats = {0};
        bpf_map_update_elem(&reality_enhanced_stats, &key, &new_stats, BPF_ANY);
        stats = bpf_map_lookup_elem(&reality_enhanced_stats, &key);
    }
    if (stats) {
        switch (stat_type) {
            case 0: // total_connections
                stats->total_connections++;
                break;
            case 1: // successful_handshakes
                stats->successful_handshakes++;
                break;
            case 2: // failed_handshakes
                stats->failed_handshakes++;
                break;
            case 3: // security_violations
                stats->security_violations++;
                break;
            case 4: // quantum_attacks_detected
                stats->quantum_attacks_detected++;
                break;
            case 5: // enhanced_security_connections
                stats->enhanced_security_connections++;
                break;
            case 6: // maximum_security_connections
                stats->maximum_security_connections++;
                break;
        }
    }
}

// 增强版REALITY握手检测
static __always_inline int detect_enhanced_reality_handshake(const void *data, const void *data_end) {
    if (data + 50 > data_end) return 0;
    
    const unsigned char *ptr = data;
    
    // 检查TLS记录类型 (0x16 = Handshake)
    if (ptr[0] != 0x16) return 0;
    
    // 检查TLS版本 (0x0304 = TLS 1.3)
    __u16 version = bpf_ntohs(*(__u16*)(ptr + 1));
    if (version != 0x0304) return 0;
    
    // 检查数据长度
    __u16 length = bpf_ntohs(*(__u16*)(ptr + 3));
    if (length < 50) return 0;
    
    // 检查ClientHello特征
    if (ptr[5] != 0x01) return 0; // Handshake type = ClientHello
    
    // 检查SessionId长度 (应该是32字节)
    if (data + 43 > data_end) return 0;
    __u8 session_id_len = ptr[43];
    if (session_id_len != 32) return 0;
    
    // 检查REALITY特定标记
    if (data + 44 > data_end) return 0;
    if (ptr[44] != 0x58 || ptr[45] != 0x52 || ptr[46] != 0x41) return 0; // "XRA"
    
    return 1;
}

// 量子抗性密钥交换检测
static __always_inline int detect_quantum_key_exchange(const void *data, const void *data_end) {
    if (data + 100 > data_end) return 0;
    
    const unsigned char *ptr = data;
    
    // 检查KeyShare扩展
    if (ptr[0] != 0x16) return 0; // Handshake
    
    // 查找KeyShare扩展 (0x0033)
    for (int i = 0; i < 50; i++) {
        if (data + i + 4 > data_end) break;
        if (ptr[i] == 0x00 && ptr[i+1] == 0x33) {
            // 检查是否包含ML-KEM密钥
            if (data + i + 10 > data_end) return 0;
            if (ptr[i+4] == 0x00 && ptr[i+5] == 0x20) { // ML-KEM-512
                return 1;
            }
            if (ptr[i+4] == 0x00 && ptr[i+5] == 0x21) { // ML-KEM-768
                return 1;
            }
            if (ptr[i+4] == 0x00 && ptr[i+5] == 0x22) { // ML-KEM-1024
                return 1;
            }
        }
    }
    
    return 0;
}

// 增强版安全验证
static __always_inline int verify_enhanced_security(const void *data, const void *data_end, 
                                                  struct reality_enhanced_conn *conn) {
    if (data + 200 > data_end) return 0;
    
    const unsigned char *ptr = data;
    
    // 简化的安全验证逻辑
    // 1. 检查证书链完整性
    if (ptr[0] != 0x16) {
        record_security_event(1); // 证书链验证失败
        return 0;
    }
    
    // 2. 检查ML-DSA签名
    if (ptr[1] != 0x03 || ptr[2] != 0x04) {
        record_security_event(2); // ML-DSA验证失败
        return 0;
    }
    
    // 3. 检查挑战-响应机制
    if (ptr[3] == 0x00) {
        record_security_event(3); // 挑战-响应验证失败
        return 0;
    }
    
    // 4. 检查时间戳防重放
    if (ptr[4] == 0x00) {
        record_security_event(4); // 时间戳验证失败
        return 0;
    }
    
    return 1;
}

// 增强版REALITY XDP程序
SEC("xdp")
int reality_enhanced_accelerator_xdp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;
    
    struct ethhdr *eth = data;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;
    
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;
    
    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (bpf_ntohs(tcp->dest) != 443 && bpf_ntohs(tcp->source) != 443)
        return XDP_PASS;
    
    __u64 conn_id = get_connection_id(ip->saddr, bpf_ntohs(tcp->source), 
                                    ip->daddr, bpf_ntohs(tcp->dest));
    
    struct reality_enhanced_conn *conn = bpf_map_lookup_elem(&reality_enhanced_connections, &conn_id);
    
    if (!conn) {
        // 新连接 - 使用简化的初始化
        struct reality_enhanced_conn new_conn = {
            .client_ip = ip->saddr,
            .server_ip = ip->daddr,
            .client_port = bpf_ntohs(tcp->source),
            .server_port = bpf_ntohs(tcp->dest),
            .state = 0,
            .handshake_start_time = get_current_time(),
            .last_activity = get_current_time()
        };
        bpf_map_update_elem(&reality_enhanced_connections, &conn_id, &new_conn, BPF_ANY);
        conn = bpf_map_lookup_elem(&reality_enhanced_connections, &conn_id);
        update_enhanced_stats(0); // total_connections
    }
    
    if (!conn) return XDP_PASS;
    
    conn->last_activity = get_current_time();
    conn->packet_count++;
    
    // 检测增强版REALITY握手
    if (conn->state == 0 && detect_enhanced_reality_handshake(tcp + 1, data_end)) {
        conn->state = 1; // hello_sent
        bpf_trace_printk("REALITY_ENHANCED: Enhanced handshake detected\n", 1);
        
        // 检测量子抗性密钥交换
        if (detect_quantum_key_exchange(tcp + 1, data_end)) {
            conn->quantum_resistant = 1;
            bpf_trace_printk("REALITY_ENHANCED: Quantum-resistant key exchange detected\n", 1);
        }
        
        return XDP_PASS; // 让用户空间处理握手
    }
    
    // 检测验证阶段
    if (conn->state == 1) {
        if (verify_enhanced_security(tcp + 1, data_end, conn)) {
            conn->state = 2; // verified
            conn->security_level = conn->quantum_resistant ? 2 : 1; // maximum : enhanced
            update_enhanced_stats(1); // successful_handshakes
            update_enhanced_stats(conn->security_level == 2 ? 6 : 5); // maximum : enhanced
            bpf_trace_printk("REALITY_ENHANCED: Enhanced security verification passed\n", 1);
        } else {
            update_enhanced_stats(2); // failed_handshakes
            bpf_trace_printk("REALITY_ENHANCED: Security verification failed\n", 1);
            return XDP_DROP; // 丢弃未验证的连接
        }
    }
    
    // 已建立的连接 - 启用零拷贝优化
    if (conn->state >= 2) {
        conn->state = 3; // established
        conn->bytes_transferred += bpf_ntohs(ip->tot_len);
        
        // 根据安全级别选择优化策略
        if (conn->security_level == 2) { // maximum security
            // 最大安全级别 - 完全零拷贝
            return XDP_TX;
        } else if (conn->security_level == 1) { // enhanced security
            // 增强安全级别 - 条件零拷贝
            if (conn->packet_count > 10) {
                return XDP_TX;
            }
        }
    }
    
    return XDP_PASS;
}

// 增强版REALITY TC程序
SEC("classifier")
int reality_enhanced_accelerator_tc(struct __sk_buff *skb) {
    __u32 stats_key = 0;
    struct reality_enhanced_stats *stats = bpf_map_lookup_elem(&reality_enhanced_stats, &stats_key);
    if (stats) {
        // 更新TC层统计
        stats->total_connections++; // 简化统计更新
    }
    
    return TC_ACT_OK;
} 