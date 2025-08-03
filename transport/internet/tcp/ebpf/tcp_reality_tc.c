// +build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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

// eBPF Maps
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);           
    __type(value, struct tcp_connection_entry);
} tcp_connections SEC(".maps");

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
    return ((__u64)src_ip << 32) | ((__u64)dst_ip << 16) | src_port | ((__u64)dst_port << 32);
}

static __always_inline void update_stats(__u32 stat_type) {
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&stats_map, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
}

// TC程序 - 完整的TCP+REALITY加速器
SEC("tc/ingress")
int tcp_reality_accelerator_tc(struct __sk_buff *skb) {
    // 获取数据包信息
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // 基本验证
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
        return TC_ACT_OK;
    
    // 解析以太网头部
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    // 只处理IPv4包
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    // 解析IP头部
    struct iphdr *ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > data_end)
        return TC_ACT_OK;
    
    // 只处理TCP包
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;
    
    // 解析TCP头部
    struct tcphdr *tcp = (void*)(ip + 1);
    if ((void*)(tcp + 1) > data_end)
        return TC_ACT_OK;
    
    // 更新统计
    update_stats(0); // total_packets
    
    // 计算连接标识符
    __u64 conn_id = get_connection_id(bpf_ntohl(ip->saddr), bpf_ntohs(tcp->source),
                                     bpf_ntohl(ip->daddr), bpf_ntohs(tcp->dest));
    
    // 查找连接状态
    struct tcp_connection_entry *conn = bpf_map_lookup_elem(&tcp_connections, &conn_id);
    
    // 处理SYN包 - 创建新连接
    if (tcp->syn && !tcp->ack) {
        if (!conn) {
            struct tcp_connection_entry new_conn = {
                .local_ip = bpf_ntohl(ip->saddr),
                .remote_ip = bpf_ntohl(ip->daddr),
                .local_port = bpf_ntohs(tcp->source),
                .remote_port = bpf_ntohs(tcp->dest),
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
            update_stats(1); // new_connections
        }
        return TC_ACT_OK;
    }
    
    // 处理已建立的连接
    if (conn && conn->state >= TCP_STATE_ESTABLISHED) {
        // 更新连接统计
        conn->bytes_sent += bpf_ntohs(ip->tot_len);
        conn->last_activity = get_current_time();
        bpf_map_update_elem(&tcp_connections, &conn_id, conn, BPF_ANY);
        
        // REALITY连接优化
        if (conn->reality_enabled && conn->reality_verified) {
            update_stats(2); // reality_packets
            conn->fast_path_count++;
        }
        
        // TLS连接优化
        if (conn->tls_established) {
            update_stats(3); // tls_packets
        }
    }
    
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL"; 