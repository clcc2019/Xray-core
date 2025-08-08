// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/ipv6.h>
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
    __u8 user_uuid[16];      // 用户UUID
    __u8 command;            // 当前命令
    __u16 content_len;       // 内容长度
    __u16 padding_len;       // 填充长度
    __u8 parsing_state;      // 解析状态
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
    __u64 zero_copy_packets;
    __u64 padding_optimized;
    __u64 command_parsed;
    __u64 tc_total_packets;
    __u64 tc_accelerated_packets;
};

// 映射表定义
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, __u64);    // 连接ID
    __type(value, struct xtls_vision_inbound);
} xtls_inbound_connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
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

// 连接复用统计
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, __u64);    // 连接ID
    __type(value, __u32);  // 复用次数
} connection_reuse_stats SEC(".maps");

// 安全事件统计
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, __u32);    // 事件类型
    __type(value, __u64);  // 事件计数
} security_events SEC(".maps");

// 事件 RingBuf（用于用户态消费关键事件）
struct xtls_event {
    __u32 type;   // 1: reality_handshake, 2: tls_complete, 3: vision_active
    __u64 conn_id;
    __u64 ts_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB ring buffer
} xtls_vision_events SEC(".maps");

static __always_inline void emit_xtls_event(__u32 type, __u64 conn_id) {
    struct xtls_event *e = bpf_ringbuf_reserve(&xtls_vision_events, sizeof(*e), 0);
    if (!e) return;
    e->type = type;
    e->conn_id = conn_id;
    e->ts_ns = bpf_ktime_get_ns();
    bpf_ringbuf_submit(e, 0);
}

// 用户UUID白名单
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, __u64);    // UUID哈希
    __type(value, __u8);   // 是否有效
} user_uuid_whitelist SEC(".maps");

// 获取当前时间戳
static __always_inline __u64 get_current_time() {
    return bpf_ktime_get_ns() / 1000000000; // 转换为秒
}

// 计算连接ID
static __always_inline __u64 get_connection_id(__u32 saddr, __u16 sport, __u32 daddr, __u16 dport) {
    return ((__u64)saddr << 32) | ((__u64)daddr) | ((__u64)sport << 48) | ((__u64)dport << 32);
}

// 计算UUID哈希
static __always_inline __u64 get_uuid_hash(const __u8 *uuid) {
    __u64 hash = 0;
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        hash = hash * 31 + uuid[i];
    }
    return hash;
}

// 更新统计信息
static __always_inline void update_stats(__u32 stat_type) {
    __u32 key = 0;
    struct xtls_vision_stats *stats = bpf_map_lookup_elem(&xtls_stats, &key);
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
            case 6: // zero_copy_packets
                stats->zero_copy_packets++;
                break;
            case 7: // padding_optimized
                stats->padding_optimized++;
                break;
            case 8: // command_parsed
                stats->command_parsed++;
                break;
        }
    }
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
    if (length < 21) return 0; // Vision协议至少需要21字节
    
    // 检查Vision协议格式
    if (data + 21 > data_end) return 0;
    
    // 检查命令字节 (第17字节)
    __u8 command = ptr[16];
    if (command == 0x00 || command == 0x01 || command == 0x02) {
        return 1; // Vision命令
    }
    
    return 0;
}

// 检测TLS 1.3 Application Data并优化padding处理
static __always_inline int detect_tls13_application_data(const void *data, const void *data_end) {
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
    
    // 对于TLS 1.3 Application Data，我们可以进行padding优化
    return 1;
}

// 优化XTLS padding处理
static __always_inline int optimize_xtls_padding(const void *data, const void *data_end, 
                                               struct xtls_vision_inbound *conn) {
    if (data + 21 > data_end) return 0;
    
    const unsigned char *ptr = data;
    
    // 解析padding信息
    __u16 content_len = (ptr[17] << 8) | ptr[18];
    __u16 padding_len = (ptr[19] << 8) | ptr[20];
    __u8 command = ptr[16];
    
    // 更新连接状态
    conn->content_len = content_len;
    conn->padding_len = padding_len;
    conn->command = command;
    
    // 如果padding比例很高，标记为需要优化
    if (padding_len > content_len * 2) {
        conn->parsing_state = 3; // padding_optimization_needed
        update_stats(9); // padding_optimized
        bpf_trace_printk("XTLS_EBPF: High padding ratio detected: content=%d padding=%d ratio=%d\n", 3, content_len, padding_len, padding_len/content_len);
        return 1;
    }
    
    // 极端高padding比例优化 (如content 74 padding 865)
    if (padding_len > content_len * 10) {
        conn->parsing_state = 4; // extreme_padding_optimization
        update_stats(9); // padding_optimized
        bpf_trace_printk("XTLS_EBPF: Extreme padding ratio: content=%d padding=%d ratio=%d\n", 3, content_len, padding_len, padding_len/content_len);
        return 2; // 特殊优化标记
    }
    
    return 0;
}

// 解析Vision协议头部 - 增强安全性
static __always_inline int parse_vision_header(const void *data, const void *data_end, 
                                             struct xtls_vision_inbound *conn) {
    if (data + 21 > data_end) return 0;
    
    const unsigned char *ptr = data;
    
    // 提取UserUUID (前16字节) - 增强边界检查
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        if (data + i >= data_end) return 0;
        conn->user_uuid[i] = ptr[i];
    }
    
    // 提取命令字节 - 严格命令验证
    if (data + 16 >= data_end) return 0;
    conn->command = ptr[16];
    
    // 验证命令类型 - 只允许有效的Vision命令
    if (conn->command != 0x00 && conn->command != 0x01 && conn->command != 0x02) {
        bpf_trace_printk("XTLS_EBPF: Invalid command detected: %d\n", 1, conn->command);
        record_security_event(1); // 无效命令事件
        return 0;
    }
    
    // 提取内容长度 (2字节，大端序) - 增强长度验证
    if (data + 18 >= data_end) return 0;
    conn->content_len = (ptr[17] << 8) | ptr[18];
    
    // 验证内容长度合理性 - 防止异常长度攻击
    if (conn->content_len > 8192 || conn->content_len == 0) {
        bpf_trace_printk("XTLS_EBPF: Invalid content length: %d\n", 1, conn->content_len);
        record_security_event(2); // 异常内容长度事件
        return 0;
    }
    
    // 提取填充长度 (2字节，大端序) - 增强长度验证
    if (data + 20 >= data_end) return 0;
    conn->padding_len = (ptr[19] << 8) | ptr[20];
    
    // 验证填充长度合理性 - 防止异常padding攻击
    if (conn->padding_len > 16384) {
        bpf_trace_printk("XTLS_EBPF: Excessive padding length: %d\n", 1, conn->padding_len);
        record_security_event(3); // 异常padding长度事件
        return 0;
    }
    
    // 验证UUID是否在白名单中 - 增强安全验证
    __u64 uuid_hash = get_uuid_hash(conn->user_uuid);
    __u8 *valid = bpf_map_lookup_elem(&user_uuid_whitelist, &uuid_hash);
    if (!valid || *valid != 1) {
        bpf_trace_printk("XTLS_EBPF: Unauthorized UUID detected\n", 1);
        record_security_event(4); // 未授权UUID事件
        return 0; // UUID不在白名单中
    }
    
    update_stats(8); // command_parsed
    return 1;
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
        
        // 解析Vision协议头部
        if (parse_vision_header(tcp + 1, data_end, conn)) {
            // 根据命令类型进行优化
            switch (conn->command) {
                case 0x00: // CommandPaddingContinue
                    // 继续填充，保持当前状态
                    break;
                case 0x01: // CommandPaddingEnd
                    // 结束填充，可以优化后续数据包
                    conn->parsing_state = 1;
                    update_stats(7); // padding_optimized
                    break;
                case 0x02: // CommandPaddingDirect
                    // 直接复制模式，启用零拷贝
                    conn->parsing_state = 2;
                    update_stats(6); // zero_copy_packets
                    return XDP_TX; // 零拷贝转发
                default:
                    break;
            }
        }
        
        // 更新统计
        update_stats(5); // vision_packets
        
        // 对于已建立的Vision连接，启用零拷贝优化
        if (conn->state == 3 && conn->parsing_state == 2) { // vision_active + direct_copy
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

// 主XDP程序 - XTLS Vision入站加速器（仅服务端）
SEC("xdp")
int xtls_vision_inbound_accelerator_xdp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 基本验证
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;
    
    struct ethhdr *eth = data;

    // IPv4 分支
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(struct ethhdr);
        if ((void *)ip + sizeof(*ip) > data_end) return XDP_PASS;
        if (ip->protocol != IPPROTO_TCP) return XDP_PASS;
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) > data_end) return XDP_PASS;
        if (tcp->dest != bpf_htons(443)) return XDP_PASS;
    
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
                .dest_port = 0,
                .command = 0,
                .content_len = 0,
                .padding_len = 0,
                .parsing_state = 0
            };
            bpf_map_update_elem(&xtls_inbound_connections, &conn_id, &new_conn, BPF_ANY);
            update_stats(0); // total_inbound_connections
            bpf_trace_printk("XTLS_EBPF: SYN packet processed, new connection created\n", 1);
        }
        return XDP_PASS;
    }
    
    // 处理已建立的连接 - 增强连接管理
    if (conn) {
        __u64 current_time = get_current_time();
        
        // 连接超时检查 - 防止资源泄漏
        if (current_time - conn->last_activity > 300) { // 5分钟超时
            bpf_trace_printk("XTLS_EBPF: Connection timeout, removing: %llu\n", 1, conn_id);
            bpf_map_delete_elem(&xtls_inbound_connections, &conn_id);
            bpf_map_delete_elem(&hot_connections, &conn_id);
            bpf_map_delete_elem(&connection_reuse_stats, &conn_id);
            return XDP_PASS; // 让用户空间处理
        }
        
        conn->last_activity = current_time;
        
        // 连接复用优化：检查是否是热点连接
        __u64 *last_access = bpf_map_lookup_elem(&hot_connections, &conn_id);
        if (last_access) {
            // 更新访问时间
            bpf_map_update_elem(&hot_connections, &conn_id, &current_time, BPF_ANY);
            
            // 检查连接复用统计
            __u32 *reuse_count = bpf_map_lookup_elem(&connection_reuse_stats, &conn_id);
            if (reuse_count) {
                (*reuse_count)++;
                bpf_map_update_elem(&connection_reuse_stats, &conn_id, reuse_count, BPF_ANY);
                bpf_trace_printk("XTLS_EBPF: Connection reused: ID=%llu count=%d\n", 2, conn_id, *reuse_count);
            }
        } else {
            // 新热点连接，添加到缓存
            bpf_map_update_elem(&hot_connections, &conn_id, &current_time, BPF_ANY);
            __u32 initial_count = 1;
            bpf_map_update_elem(&connection_reuse_stats, &conn_id, &initial_count, BPF_ANY);
        }
        
        // 检测REALITY握手 - 增强状态机安全验证
        if (conn->state == 0 && detect_reality_handshake(tcp + 1, data_end)) {
            conn->state = 1; // reality_handshake
            conn->tls_version = 0x04; // TLS 1.3
            update_stats(1); // reality_connections
            bpf_trace_printk("XTLS_EBPF: REALITY handshake detected in XDP\n", 1);
        } else if (conn->state == 0 && !detect_reality_handshake(tcp + 1, data_end)) {
            // 状态机攻击检测：在init状态收到非REALITY握手数据
            bpf_trace_printk("XTLS_EBPF: State machine attack detected in init state\n", 1);
            return XDP_DROP; // 丢弃可疑数据包
        }
        
        // 检测TLS握手完成 - 增强状态机安全验证
        if (conn->state == 1) {
            // 检查是否有TLS Application Data
            if ((void *)(tcp + 1) + 5 <= data_end) {
                const unsigned char *ptr = (const unsigned char*)(tcp + 1);
                if (ptr[0] == 0x17) { // Application Data
                    conn->state = 2; // tls_handshake
                    conn->reality_verified = 1;
                    emit_xtls_event(2, conn_id);
                } else if (ptr[0] == 0x16) { // Handshake
                    // 正常的TLS握手过程，继续等待
                } else {
                    // 状态机攻击检测：在reality_handshake状态收到非TLS数据
                    return XDP_DROP; // 丢弃可疑数据包
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
            emit_xtls_event(3, conn_id);
            
            // 解析Vision头部并优化padding
            if (parse_vision_header(tcp + 1, data_end, conn)) {
                optimize_xtls_padding(tcp + 1, data_end, conn);
            // padding 优化事件无需频繁打印
            }
        }
        
        // 检测TLS 1.3 Application Data并优化
        if (conn->state >= 2 && detect_tls13_application_data(tcp + 1, data_end)) {
            // 对于TLS 1.3 Application Data，进行padding优化
            if (conn->vision_enabled) {
                optimize_xtls_padding(tcp + 1, data_end, conn);
            }
        }
        
        // 优化Vision数据包 - 增强性能优化
        if (conn->vision_enabled) {
            // 增强零拷贝优化：根据连接状态和padding比例决定
            if (conn->parsing_state == 2 || conn->parsing_state == 4) {
                // 直接复制模式或极端padding优化模式
                return XDP_TX; // 零拷贝转发
            }
            
            // 新增：智能零拷贝决策
            // 1. 对于高频复用连接，优先使用零拷贝
            __u32 *reuse_count = bpf_map_lookup_elem(&connection_reuse_stats, &conn_id);
            if (reuse_count && *reuse_count > 5) {
                return XDP_TX; // 零拷贝转发
            }
            
            // 2. 对于低padding比例连接，启用零拷贝
            if (conn->padding_len < conn->content_len) {
                return XDP_TX; // 零拷贝转发
            }
            
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
    // IPv6 分支（基础支持：识别并统计，保持转发）
    else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = data + sizeof(struct ethhdr);
        if ((void *)ip6 + sizeof(*ip6) > data_end) return XDP_PASS;
        if (ip6->nexthdr != IPPROTO_TCP) return XDP_PASS;
        struct tcphdr *tcp6 = (void *)ip6 + sizeof(*ip6);
        if ((void *)tcp6 + sizeof(*tcp6) > data_end) return XDP_PASS;
        if (tcp6->dest != bpf_htons(443)) return XDP_PASS;

        update_stats(5); // 计一次 vision_packets，作为基础统计
        return XDP_PASS;
    }
    
    return XDP_PASS;
}

// TC程序 - 极简版本，仅做基础统计
SEC("classifier")
int xtls_vision_inbound_accelerator_tc(struct __sk_buff *skb) {
    // TC程序的极简版本，主要功能已转移到XDP层
    // 仅更新基础统计计数
    __u32 stats_key = 0;
    struct xtls_vision_stats *stats = bpf_map_lookup_elem(&xtls_stats, &stats_key);
    if (stats) {
        stats->tc_total_packets++;
        bpf_trace_printk("XTLS_EBPF: TC program packet processed\n", 1);
    }
    
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL"; 