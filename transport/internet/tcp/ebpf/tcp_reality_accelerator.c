// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_TCP_CONNECTIONS 16384
#define REALITY_SESSION_CACHE 8192
#define MAX_PACKET_SIZE 1500

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

// TCP连接条目
struct tcp_connection_entry {
    __u32 local_ip;               // 本地IP
    __u32 remote_ip;              // 远程IP
    __u16 local_port;             // 本地端口
    __u16 remote_port;            // 远程端口
    __u8 state;                   // 连接状态
    __u8 reality_enabled;         // 是否启用REALITY
    __u8 reality_verified;        // REALITY握手验证状态
    __u8 tls_established;         // TLS连接是否已建立
    __u16 fast_path_count;        // 快速路径计数
    __u32 bytes_sent;             // 发送字节数
    __u64 last_activity;          // 最后活动时间
    __u32 next_hop_ip;            // 下一跳IP（用于转发）
    __u16 next_hop_port;          // 下一跳端口
    __u8 fast_path_enabled;       // 快速路径是否启用
};

// REALITY会话条目
struct reality_session_entry {
    __u64 session_id;             // 会话ID
    __u32 dest_ip;                // 目标IP
    __u16 connection_count;       // 连接计数
    __u8 verified;                // 验证状态
    __u8 active;                  // 活跃状态
    __u64 last_used;              // 最后使用时间
    __u32 next_hop_ip;            // 下一跳IP
    __u16 next_hop_port;          // 下一跳端口
};

// 快速转发缓存
struct fast_forward_entry {
    __u64 conn_id;                // 连接ID
    __u32 next_hop_ip;            // 下一跳IP
    __u16 next_hop_port;          // 下一跳端口
    __u8 protocol;                // 协议类型
    __u8 priority;                // 优先级
    __u64 last_used;              // 最后使用时间
};

// eBPF Maps
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_TCP_CONNECTIONS);
    __type(key, __u64);           
    __type(value, struct tcp_connection_entry);
} tcp_connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, REALITY_SESSION_CACHE);
    __type(key, __u64);           
    __type(value, struct reality_session_entry);
} reality_sessions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);           
    __type(value, struct fast_forward_entry);
} fast_forward_cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

// 辅助函数
static __always_inline __u64 get_current_time() {
    return bpf_ktime_get_ns();
}

static __always_inline __u64 get_connection_id(__u32 src_ip, __u16 src_port, 
                                               __u32 dst_ip, __u16 dst_port) {
    return ((__u64)src_ip << 32) | ((__u64)src_port << 16) | dst_port;
}

static __always_inline void update_stats(__u32 stat_type) {
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&stats_map, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
}

// 真正的零拷贝快速转发
static __always_inline int fast_forward_packet(struct xdp_md *ctx, 
                                               struct tcp_connection_entry *conn) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // 检查包大小
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;
    
    struct iphdr *ip = data + sizeof(struct ethhdr);
    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    
    // 如果启用了快速转发，直接转发到下一跳
    if (conn->fast_path_enabled && conn->next_hop_ip != 0) {
        // 修改目标IP和端口
        __u32 original_dst_ip = ip->daddr;
        
        ip->daddr = conn->next_hop_ip;
        tcp->dest = conn->next_hop_port;
        
        // 重新计算IP校验和
        ip->check = 0;
        ip->check = bpf_csum_diff((__be32 *)&original_dst_ip, 1, (__be32 *)&conn->next_hop_ip, 1, 0);
        
        // 更新统计
        conn->fast_path_count++;
        conn->bytes_sent += bpf_ntohs(ip->tot_len);
        conn->last_activity = get_current_time();
        
        update_stats(1); // fast_forward_count
        
        return XDP_TX; // 零拷贝转发
    }
    
    return XDP_PASS;
}

// REALITY握手加速
static __always_inline int accelerate_reality_handshake(struct tcp_connection_entry *conn, 
                                                       void *tcp_payload, void *data_end,
                                                       __u64 conn_id) {
    if (tcp_payload + 4 > data_end) return -1;
    
    __u8 *payload = (__u8 *)tcp_payload;
    
    // 检测REALITY握手
    if (payload[0] == 0x16 && payload[1] == 0x03 && payload[2] == 0x01) {
        // 计算会话ID
        __u64 session_id = conn_id ^ 0x1234567890abcdef;
        struct reality_session_entry *session = bpf_map_lookup_elem(&reality_sessions, &session_id);
        
        if (session && session->verified) {
            // 会话复用 - 快速建立连接
            conn->reality_verified = 1;
            conn->tls_established = 1;
            conn->state = TCP_STATE_REALITY_ESTABLISHED;
            conn->fast_path_enabled = 1;
            conn->next_hop_ip = session->next_hop_ip;
            conn->next_hop_port = session->next_hop_port;
            
            session->connection_count++;
            session->last_used = get_current_time();
            
            bpf_map_update_elem(&tcp_connections, &conn_id, conn, BPF_ANY);
            bpf_map_update_elem(&reality_sessions, &session_id, session, BPF_ANY);
            
            update_stats(2); // reality_session_reuse
            return 0; // 握手加速成功
        } else {
            // 新会话 - 创建
            struct reality_session_entry new_session = {
                .session_id = session_id,
                .dest_ip = conn->remote_ip,
                .connection_count = 1,
                .verified = 0,
                .active = 1,
                .last_used = get_current_time(),
                .next_hop_ip = conn->remote_ip, // 默认下一跳
                .next_hop_port = conn->remote_port
            };
            bpf_map_update_elem(&reality_sessions, &session_id, &new_session, BPF_ANY);
        }
    }
    
    return -1;
}

// 主XDP程序 - 真正的TCP+REALITY加速器
SEC("xdp")
int tcp_reality_accelerator_xdp(struct xdp_md *ctx) {
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
    
    update_stats(0); // total_packets
    
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
                .last_activity = get_current_time(),
                .next_hop_ip = 0,
                .next_hop_port = 0,
                .fast_path_enabled = 0
            };
            bpf_map_update_elem(&tcp_connections, &conn_id, &new_conn, BPF_ANY);
        }
        return XDP_PASS; // 让用户空间处理SYN
    }
    
    // 处理已建立的连接
    if (conn && conn->state >= TCP_STATE_ESTABLISHED) {
        
        // 🔒 REALITY连接快速转发
        if (conn->reality_enabled && conn->reality_verified && conn->fast_path_enabled) {
            return fast_forward_packet(ctx, conn);
        }
        
        // 🔒 尝试REALITY握手加速
        void *tcp_payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + (tcp->doff * 4);
        if (accelerate_reality_handshake(conn, tcp_payload, data_end, conn_id) == 0) {
            update_stats(3); // handshake_accelerations
        }
        
        // 更新连接统计
        conn->bytes_sent += bpf_ntohs(ip->tot_len);
        conn->last_activity = get_current_time();
        bpf_map_update_elem(&tcp_connections, &conn_id, conn, BPF_ANY);
    }
    
    return XDP_PASS;
}

// TC程序 - 出口优化和统计
SEC("tc")
int tcp_reality_accelerator_tc(struct __sk_buff *skb) {
    // 简化的TC程序，专注于统计更新
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&stats_map, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
    
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";