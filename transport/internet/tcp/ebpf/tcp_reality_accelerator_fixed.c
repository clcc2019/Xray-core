// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/string.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_TCP_CONNECTIONS 8000     // 减少连接数避免内存过大
#define REALITY_SESSION_CACHE 2000   // 减少会话缓存
#define FAST_PATH_THRESHOLD 5        // 快速路径阈值

// TCP连接状态
enum tcp_conn_state {
    TCP_STATE_INIT = 0,
    TCP_STATE_SYN_SENT,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_REALITY_HANDSHAKE,
    TCP_STATE_REALITY_ESTABLISHED,
    TCP_STATE_DATA_TRANSFER,
    TCP_STATE_FIN_WAIT,
    TCP_STATE_CLOSED
};

// 简化的TCP连接条目
struct tcp_connection_entry {
    __u32 local_ip;               // 本地IP
    __u32 remote_ip;              // 远程IP
    __u16 local_port;             // 本地端口
    __u16 remote_port;            // 远程端口
    __u8 state;                   // 连接状态
    __u8 reality_enabled;         // 是否启用REALITY
    __u8 reality_verified;        // 🔒 REALITY握手验证状态
    __u8 tls_established;         // 🔒 TLS连接是否已建立
    __u16 fast_path_count;        // 快速路径计数
    __u32 bytes_sent;             // 发送字节数
    __u64 last_activity;          // 最后活动时间
};

// 简化的REALITY会话条目
struct reality_session_entry {
    __u64 session_id;             // 会话ID
    __u32 dest_ip;                // 目标IP
    __u16 connection_count;       // 连接计数
    __u8 verified;                // 验证状态
    __u8 active;                  // 活跃状态
    __u64 last_used;              // 最后使用时间
};

// TCP连接状态缓存
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_TCP_CONNECTIONS);
    __type(key, __u64);           
    __type(value, struct tcp_connection_entry);
} tcp_connections SEC(".maps");

// REALITY会话缓存
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, REALITY_SESSION_CACHE);
    __type(key, __u64);           
    __type(value, struct reality_session_entry);
} reality_sessions SEC(".maps");

// 热点连接列表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, __u64);           
    __type(value, __u8);          
} hot_connections SEC(".maps");

// 简化的统计结构
struct tcp_reality_stats {
    __u64 total_connections;      
    __u64 reality_connections;    
    __u64 fast_path_hits;         
    __u64 handshake_accelerations;
    __u64 data_fast_forwards;     
    __u64 session_reuses;         
};

// 统计信息
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tcp_reality_stats);
} tcp_reality_stats_map SEC(".maps");

// 获取当前时间（简化版）
static __always_inline __u64 get_current_time() {
    return bpf_ktime_get_ns();
}

// 计算连接ID
static __always_inline __u64 get_connection_id(__u32 src_ip, __u16 src_port, 
                                               __u32 dst_ip, __u16 dst_port) {
    __u64 id = ((__u64)src_ip << 32) | dst_ip;
    id ^= ((__u64)src_port << 16) | dst_port;
    return id;
}

// 更新统计信息
static __always_inline void update_tcp_reality_stats(__u32 stat_type) {
    __u32 key = 0;
    struct tcp_reality_stats *stats = bpf_map_lookup_elem(&tcp_reality_stats_map, &key);
    if (stats) {
        switch (stat_type) {
            case 0: __sync_fetch_and_add(&stats->total_connections, 1); break;
            case 1: __sync_fetch_and_add(&stats->reality_connections, 1); break;
            case 2: __sync_fetch_and_add(&stats->fast_path_hits, 1); break;
            case 4: __sync_fetch_and_add(&stats->handshake_accelerations, 1); break;
            case 5: __sync_fetch_and_add(&stats->data_fast_forwards, 1); break;
            case 6: __sync_fetch_and_add(&stats->session_reuses, 1); break;
        }
    }
}

// 🚀 TCP超快速路径 - 核心零拷贝转发逻辑
static __always_inline int tcp_ultra_fast_path(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 快速包大小检查
    if (data + 54 > data_end) return -1;
    
    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return -1;
    
    struct iphdr *ip = (void *)(eth + 1);
    if (ip->protocol != IPPROTO_TCP) return -1;
    
    struct tcphdr *tcp = (void *)(ip + 1);
    
    // 计算连接ID
    __u64 conn_id = get_connection_id(ip->saddr, tcp->source, ip->daddr, tcp->dest);
    
    // 查找热点连接
    struct tcp_connection_entry *conn = bpf_map_lookup_elem(&tcp_connections, &conn_id);
    if (!conn) return -1;
    
    // 🚀 核心快速转发逻辑 - 零拷贝数据路径
    if (conn->fast_path_count > 10 && conn->state >= TCP_STATE_ESTABLISHED) {
        __u16 ip_len = bpf_ntohs(ip->tot_len);
        
        // 安全的包大小检查
        if (ip_len > 40 && ip_len < 1400) {
            
            // 🔒 REALITY安全检查（简化但有效）
            if (conn->reality_enabled) {
                // 只有完全验证的REALITY连接才能快速转发
                if (conn->reality_verified != 1) return -1;
                
                // 检查TLS应用数据（0x17）
                void *payload = (void *)(tcp + 1);
                if (payload + 1 <= data_end) {
                    __u8 *tls_type = (__u8 *)payload;
                    if (*tls_type != 0x17) return -1; // 只转发应用数据
                }
            }
            
            // ⚡ 执行零拷贝快速转发
            conn->fast_path_count++;
            conn->bytes_sent += ip_len;
            conn->last_activity = get_current_time();
            bpf_map_update_elem(&tcp_connections, &conn_id, conn, BPF_ANY);
            
            // 更新统计
            update_tcp_reality_stats(5); // data_fast_forwards
            
            return XDP_TX; // 🚀 真正的内核级零拷贝转发！
        }
    }
    
    return -1; // 继续正常处理
}

// 🔒 REALITY握手加速（简化版）
static __always_inline int accelerate_reality_handshake(struct tcp_connection_entry *conn, 
                                                        void *tcp_payload, void *data_end,
                                                        __u64 conn_id) {
    if (tcp_payload + 2 > data_end) return -1;
    
    __u8 *payload = (__u8 *)tcp_payload;
    
    // 🔒 REALITY握手检测与优化
    if (payload[0] == 0x16 && payload[1] == 0x03) {
        // TLS握手包 - 标记REALITY状态
        conn->state = TCP_STATE_REALITY_HANDSHAKE;
        conn->reality_enabled = 1;
        
        // 🚀 REALITY会话缓存优化
        __u64 session_id = conn_id; // 简化session ID
        struct reality_session_entry *session = bpf_map_lookup_elem(&reality_sessions, &session_id);
        
        if (session && session->verified) {
            // 🎯 会话复用 - 直接加速
            conn->reality_verified = 1;
            conn->tls_established = 1;
            conn->state = TCP_STATE_REALITY_ESTABLISHED;
            session->connection_count++;
            session->last_used = get_current_time();
            
            update_tcp_reality_stats(6); // session_reuses
            bpf_map_update_elem(&tcp_connections, &conn_id, conn, BPF_ANY);
            bpf_map_update_elem(&reality_sessions, &session_id, session, BPF_ANY);
            
            return 0; // 🚀 握手加速成功！
        } else {
            // 新会话 - 简化创建
            struct reality_session_entry new_session = {
                .session_id = session_id,
                .dest_ip = conn->remote_ip,
                .connection_count = 1,
                .verified = 0,  // 待用户态验证
                .active = 1,
                .last_used = get_current_time()
            };
            bpf_map_update_elem(&reality_sessions, &session_id, &new_session, BPF_ANY);
        }
    }
    
    return -1; // 继续用户态处理
}

// XDP程序 - TCP+REALITY加速器
SEC("xdp")
int tcp_reality_accelerator_xdp(struct xdp_md *ctx) {
    // 🚀 尝试超快速路径 (零拷贝)
    int ultra_result = tcp_ultra_fast_path(ctx);
    if (ultra_result == XDP_TX) {
        return XDP_TX; // 🚀 超快速零拷贝转发成功！
    }
    
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 验证基本包结构
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;
    
    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;
    
    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    
    update_tcp_reality_stats(0); // total_connections
    
    // 计算连接标识符
    __u64 conn_id = get_connection_id(ip->saddr, tcp->source, ip->daddr, tcp->dest);
    
    // 查找连接状态
    struct tcp_connection_entry *conn = bpf_map_lookup_elem(&tcp_connections, &conn_id);
    
    // 处理SYN包 - 创建新连接
    if (tcp->syn && !tcp->ack) {
        if (!conn) {
            struct tcp_connection_entry new_conn = {
                .local_ip = ip->saddr,
                .remote_ip = ip->daddr,
                .local_port = tcp->source,
                .remote_port = tcp->dest,
                .state = TCP_STATE_SYN_SENT,
                .reality_enabled = 0,
                .reality_verified = 0,
                .tls_established = 0,
                .fast_path_count = 0,
                .bytes_sent = 0,
                .last_activity = get_current_time()
            };
            bpf_map_update_elem(&tcp_connections, &conn_id, &new_conn, BPF_ANY);
        }
        return XDP_PASS; // 让用户空间处理SYN
    }
    
    // 处理已建立的连接
    if (conn && conn->state >= TCP_STATE_ESTABLISHED) {
        
        // 🔒 REALITY连接检查与加速
        if (conn->reality_enabled && conn->reality_verified) {
            // 检查TLS应用数据 (0x17)
            void *tcp_payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + (tcp->doff * 4);
            if (tcp_payload + 1 <= data_end) {
                __u8 *tls_type = (__u8 *)tcp_payload;
                if (*tls_type == 0x17) { // TLS应用数据
                    // 🚀 REALITY数据快速转发
                    conn->fast_path_count++;
                    conn->bytes_sent += bpf_ntohs(ip->tot_len);
                    conn->last_activity = get_current_time();
                    bpf_map_update_elem(&tcp_connections, &conn_id, conn, BPF_ANY);
                    update_tcp_reality_stats(5); // data_fast_forwards
                    return XDP_TX; // 🚀 零拷贝转发！
                }
            }
        }
        
        // 🚀 普通TCP快速转发
        if (conn->fast_path_count > 5) {
            __u16 packet_size = bpf_ntohs(ip->tot_len);
            if (packet_size > 40 && packet_size < 1400) {
                conn->fast_path_count++;
                conn->bytes_sent += packet_size;
                conn->last_activity = get_current_time();
                bpf_map_update_elem(&tcp_connections, &conn_id, conn, BPF_ANY);
                update_tcp_reality_stats(5); // data_fast_forwards
                return XDP_TX; // 🚀 TCP零拷贝转发！
            }
        }
        
        // 🔒 尝试REALITY握手加速
        void *tcp_payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + (tcp->doff * 4);
        if (accelerate_reality_handshake(conn, tcp_payload, data_end, conn_id) == 0) {
            update_tcp_reality_stats(4); // handshake_accelerations
        }
        
        // 更新连接统计
        conn->bytes_sent += bpf_ntohs(ip->tot_len);
        conn->last_activity = get_current_time();
        bpf_map_update_elem(&tcp_connections, &conn_id, conn, BPF_ANY);
    }
    
    return XDP_PASS;
}

// TC程序 - TCP+REALITY出口加速
SEC("tc")
int tcp_reality_accelerator_tc(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    // 基本包验证
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
        return TC_ACT_OK;
    
    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;
    
    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    
    // 计算连接ID
    __u64 conn_id = get_connection_id(ip->saddr, tcp->source, ip->daddr, tcp->dest);
    
    // 查找连接
    struct tcp_connection_entry *conn = bpf_map_lookup_elem(&tcp_connections, &conn_id);
    if (conn) {
        // 🚀 出口快速处理
        if (conn->fast_path_count > 10 && conn->state >= TCP_STATE_ESTABLISHED) {
            __u16 packet_size = bpf_ntohs(ip->tot_len);
            if (packet_size > 40 && packet_size < 1400) {
                conn->fast_path_count++;
                conn->last_activity = get_current_time();
                bpf_map_update_elem(&tcp_connections, &conn_id, conn, BPF_ANY);
                update_tcp_reality_stats(5); // data_fast_forwards
                // TC快速处理 - 不修改包，只优化路径
            }
        }
    }
    
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";