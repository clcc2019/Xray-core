// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

// 连接状态常量
#define CONN_STATE_ACTIVE       0
#define CONN_STATE_READY_CLOSE  1
#define CONN_STATE_PEER_CLOSED  2
#define CONN_STATE_TERMINATING  3
#define CONN_STATE_TERMINATED   4

// 协议类型常量
#define PROTOCOL_TCP    6
#define PROTOCOL_UDP    17

// 最大连接数
#define MAX_CONNECTIONS 65536
#define MAX_USERS       8192

// 连接状态结构
struct connection_state {
    __u64 user_uuid_high;           // UserUUID高64位
    __u64 user_uuid_low;            // UserUUID低64位
    __u32 connection_id;            // 连接ID
    __u32 protocol;                 // 协议类型(TCP/UDP)
    __u64 uplink_bytes;             // 上行字节数
    __u64 downlink_bytes;           // 下行字节数
    __u64 uplink_packets;           // 上行包数
    __u64 downlink_packets;         // 下行包数
    __u64 start_time;               // 连接开始时间(ns)
    __u64 last_active;              // 最后活跃时间(ns)
    __u32 local_ip;                 // 本地IP地址
    __u32 remote_ip;                // 远程IP地址
    __u16 local_port;               // 本地端口
    __u16 remote_port;              // 远程端口
    __u8 state;                     // 连接状态
    __u8 is_tls;                    // 是否TLS连接
    __u8 enable_xtls;               // 是否启用XTLS
    __u8 direction;                 // 数据方向(0=inbound, 1=outbound)
};

// 流量状态结构
struct traffic_state {
    __u32 number_of_packet_to_filter;
    __u16 cipher;
    __u8 is_tls12_or_above;
    __u8 is_tls;
    __s32 remaining_server_hello;
    // Inbound state
    __u8 within_padding_buffers_in;
    __u8 uplink_reader_direct_copy;
    __s32 remaining_command_in;
    __s32 remaining_content_in;
    __s32 remaining_padding_in;
    __u32 current_command_in;
    __u8 is_padding_in;
    __u8 downlink_writer_direct_copy;
    // Outbound state  
    __u8 within_padding_buffers_out;
    __u8 downlink_reader_direct_copy;
    __s32 remaining_command_out;
    __s32 remaining_content_out;
    __s32 remaining_padding_out;
    __u32 current_command_out;
    __u8 is_padding_out;
    __u8 uplink_writer_direct_copy;
    __u8 padding[2];                // 对齐填充
};

// 用户统计结构
struct user_stats {
    __u64 user_uuid_high;
    __u64 user_uuid_low;
    __u64 total_uplink_bytes;
    __u64 total_downlink_bytes;
    __u64 total_uplink_packets;
    __u64 total_downlink_packets;
    __u32 active_connections;
    __u32 total_connections;
    __u64 first_seen;
    __u64 last_seen;
};

// 连接键结构
struct connection_key {
    __u32 connection_id;
};

// 用户键结构
struct user_key {
    __u64 user_uuid_high;
    __u64 user_uuid_low;
};

// eBPF Maps定义

// 连接状态映射表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct connection_key);
    __type(value, struct connection_state);
    __uint(max_entries, MAX_CONNECTIONS);
} connection_states SEC(".maps");

// 流量状态映射表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct connection_key);
    __type(value, struct traffic_state);
    __uint(max_entries, MAX_CONNECTIONS);
} traffic_states SEC(".maps");

// 用户统计映射表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct user_key);
    __type(value, struct user_stats);
    __uint(max_entries, MAX_USERS);
} user_statistics SEC(".maps");

// 全局统计映射表
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 16);
} global_stats SEC(".maps");

// 统计索引常量
#define STAT_TOTAL_CONNECTIONS     0
#define STAT_ACTIVE_CONNECTIONS    1
#define STAT_TOTAL_UPLINK_BYTES    2
#define STAT_TOTAL_DOWNLINK_BYTES  3
#define STAT_TOTAL_UPLINK_PACKETS  4
#define STAT_TOTAL_DOWNLINK_PACKETS 5
#define STAT_TLS_CONNECTIONS       6
#define STAT_XTLS_CONNECTIONS      7

// 简化的辅助函数
static __always_inline void update_simple_stat(__u32 index, __u64 delta) {
    __u64 *value = bpf_map_lookup_elem(&global_stats, &index);
    if (value) {
        *value += delta;
    }
}

// Socket程序：跟踪连接创建
SEC("socket")
int track_socket_create(struct __sk_buff *skb) {
    return 0;  // 占位符，实际实现需要更复杂的逻辑
}

// Tracepoint程序：跟踪连接状态变化
SEC("tracepoint/sock/inet_sock_set_state")
int track_connection_state_change(void *ctx) {
    return 0;  // 占位符，实际实现需要更复杂的逻辑
}

// 简化的TC程序：基础流量统计
SEC("tc")
int track_network_traffic(struct __sk_buff *skb) {
    if (!skb) {
        return TC_ACT_OK;
    }
    
    __u32 packet_size = skb->len;
    if (packet_size == 0) {
        return TC_ACT_OK;
    }
    
    // 使用简化的统计更新
    update_simple_stat(STAT_TOTAL_UPLINK_BYTES, packet_size);
    update_simple_stat(STAT_TOTAL_UPLINK_PACKETS, 1);
    
    return TC_ACT_OK;
}

// 许可证声明
char _license[] SEC("license") = "GPL";