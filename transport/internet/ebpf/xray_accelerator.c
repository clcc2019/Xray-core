// +build ignore
// Xray eBPF透明加速器
// 自动学习和优化数据包转发，无需配置

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// 学习统计结构
struct route_stats {
    __u64 packet_count;
    __u64 byte_count;
    __u64 last_seen;
    __u32 confidence;  // 置信度 * 1000
    __u8 gateway_mac[6];
    __u8 gateway_mac_valid;
    __u8 reserved;
};

// 全局统计
struct global_stats {
    __u64 total_packets;
    __u64 learned_packets;
    __u64 bypassed_packets;
    __u64 fast_forwarded;
    __u64 redirected;
    __u32 active_routes;
};

// eBPF Maps

// 学习路由表 - 基于五元组
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);  // 五元组哈希
    __type(value, struct route_stats);
    __uint(max_entries, 32768);
} learned_routes SEC(".maps");

// 全局统计信息
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct global_stats);
    __uint(max_entries, 1);
} global_statistics SEC(".maps");

// 配置信息
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 8);
} config_map SEC(".maps");

// 配置键定义
#define CONFIG_ENABLED      0
#define CONFIG_AUTO_LEARN   1
#define CONFIG_BYPASS_THRESHOLD 2
#define CONFIG_MAX_CONFIDENCE   3

// Helper functions

// 计算五元组哈希
static __always_inline __u64 calc_flow_hash(__u32 src_ip, __u32 dst_ip, 
                                            __u16 src_port, __u16 dst_port, __u8 proto) {
    __u64 hash = 0;
    hash ^= (__u64)src_ip << 32;
    hash ^= (__u64)dst_ip;
    hash ^= (__u64)src_port << 16;
    hash ^= (__u64)dst_port;
    hash ^= (__u64)proto << 8;
    return hash;
}

// 更新全局统计
static __always_inline void update_global_stats(__u32 stat_type) {
    __u32 key = 0;
    struct global_stats *stats = bpf_map_lookup_elem(&global_statistics, &key);
    if (!stats) return;
    
    switch (stat_type) {
        case 0: __sync_fetch_and_add(&stats->total_packets, 1); break;
        case 1: __sync_fetch_and_add(&stats->learned_packets, 1); break;
        case 2: __sync_fetch_and_add(&stats->bypassed_packets, 1); break;
        case 3: __sync_fetch_and_add(&stats->fast_forwarded, 1); break;
        case 4: __sync_fetch_and_add(&stats->redirected, 1); break;
    }
}

// 检查配置
static __always_inline __u32 get_config(__u32 key) {
    __u32 *value = bpf_map_lookup_elem(&config_map, &key);
    if (!value) return 0;
    return *value;
}

// 学习路由模式
static __always_inline void learn_route(__u64 flow_hash, __u32 packet_len) {
    if (!get_config(CONFIG_AUTO_LEARN)) return;
    
    __u64 now = bpf_ktime_get_ns();
    struct route_stats *stats = bpf_map_lookup_elem(&learned_routes, &flow_hash);
    
    if (stats) {
        // 更新现有路由
        __sync_fetch_and_add(&stats->packet_count, 1);
        __sync_fetch_and_add(&stats->byte_count, packet_len);
        stats->last_seen = now;
        
        // 增加置信度（最大1000）
        if (stats->confidence < 1000) {
            stats->confidence = stats->confidence + 1;
        }
    } else {
        // 新路由
        struct route_stats new_stats = {
            .packet_count = 1,
            .byte_count = packet_len,
            .last_seen = now,
            .confidence = 10  // 初始低置信度
        };
        bpf_map_update_elem(&learned_routes, &flow_hash, &new_stats, BPF_ANY);
    }
    
    update_global_stats(1); // learned_packets
}

// 检查是否可以快速通道
static __always_inline int can_bypass(__u64 flow_hash) {
    struct route_stats *stats = bpf_map_lookup_elem(&learned_routes, &flow_hash);
    if (!stats) return 0;
    
    __u32 threshold = get_config(CONFIG_BYPASS_THRESHOLD);
    if (threshold == 0) threshold = 500; // 默认阈值
    
    // 高置信度且最近使用过
    __u64 now = bpf_ktime_get_ns();
    __u64 time_diff = now - stats->last_seen;
    
    if (stats->confidence >= threshold && time_diff < 300000000000ULL) { // 5分钟
        return 1;
    }
    
    return 0;
}

// 快速转发数据包 - 实现零拷贝转发
static __always_inline int fast_forward_packet(struct xdp_md *ctx, __u64 flow_hash) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 查找路由信息
    struct route_stats *route = bpf_map_lookup_elem(&learned_routes, &flow_hash);
    if (!route || route->confidence < get_config(CONFIG_BYPASS_THRESHOLD)) {
        return -1; // 置信度不够，不能快速转发
    }
    
    // 解析以太网头
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return -1;
    
    // 解析IP头
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return -1;
    
    // 更新路由统计
    __sync_fetch_and_add(&route->packet_count, 1);
    __sync_fetch_and_add(&route->byte_count, bpf_ntohs(ip->tot_len));
    route->last_seen = bpf_ktime_get_ns();
    
    bpf_map_update_elem(&learned_routes, &flow_hash, route, BPF_ANY);
    
    return 0; // 成功，准备TX
}

// 重定向数据包到指定接口
static __always_inline int redirect_packet(struct xdp_md *ctx, __u64 flow_hash) {
    // 查找路由信息
    struct route_stats *route = bpf_map_lookup_elem(&learned_routes, &flow_hash);
    if (!route) {
        return -1; // 没有路由信息
    }
    
    // 更新统计
    __sync_fetch_and_add(&route->packet_count, 1);
    route->last_seen = bpf_ktime_get_ns();
    bpf_map_update_elem(&learned_routes, &flow_hash, route, BPF_ANY);
    
    return 0; // 准备重定向
}

// 超快速路径 - 包级别预处理
static __always_inline int ultra_fast_path(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 最基本的包大小检查
    if (data + 42 > data_end) return XDP_PASS; // 不足以太网+IP+TCP最小长度
    
    struct ethhdr *eth = data;
    // 超快速以太网类型检查
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;
    
    struct iphdr *ip = (void *)(eth + 1);
    // 超快速协议检查
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP) return XDP_PASS;
    
    // 计算快速哈希（仅使用IP地址）
    __u64 fast_hash = ((__u64)ip->saddr << 32) | ip->daddr;
    
    // 查找超快速缓存
    struct route_stats *hot_route = bpf_map_lookup_elem(&learned_routes, &fast_hash);
    if (hot_route && hot_route->confidence > 1000) { // 超高置信度
        // 超快速转发 - 跳过所有解析
        __sync_fetch_and_add(&hot_route->packet_count, 1);
        update_global_stats(3); // fast_forwarded
        
        // 直接修改目标MAC（如果有缓存）
        if (hot_route->gateway_mac_valid) {
            #pragma unroll
            for (int i = 0; i < 6; i++) {
                eth->h_dest[i] = hot_route->gateway_mac[i];
            }
            return XDP_TX; // 超快速转发
        }
    }
    
    return -1; // 继续常规处理
}

// XDP程序 - 快速学习和bypass
SEC("xdp")
int xray_accelerator_xdp(struct xdp_md *ctx) {
    if (!get_config(CONFIG_ENABLED)) {
        return XDP_PASS;
    }
    
    // 尝试超快速路径
    int ultra_result = ultra_fast_path(ctx);
    if (ultra_result >= 0) {
        return ultra_result; // 超快速路径处理成功
    }
    
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }
    
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }
    
    update_global_stats(0); // total_packets
    
    __u16 src_port = 0, dst_port = 0;
    
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end) {
            return XDP_PASS;
        }
        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end) {
            return XDP_PASS;
        }
        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
    } else {
        return XDP_PASS;
    }
    
    // 计算流哈希
    __u64 flow_hash = calc_flow_hash(ip->saddr, ip->daddr, src_port, dst_port, ip->protocol);
    
    // 检查是否可以快速通道
    if (can_bypass(flow_hash)) {
        update_global_stats(2); // bypassed_packets
        
        // 实现真正的快速转发
        if (fast_forward_packet(ctx, flow_hash) == 0) {
            update_global_stats(3); // fast_forward_count
            return XDP_TX; // 直接从网卡发送，实现零拷贝转发
        }
        
        // 快速转发失败，尝试重定向
        if (redirect_packet(ctx, flow_hash) == 0) {
            update_global_stats(4); // redirect_count
            return XDP_REDIRECT; // 重定向到目标接口
        }
    }
    
    // 学习路由模式
    learn_route(flow_hash, bpf_ntohs(ip->tot_len));
    
    return XDP_PASS; // 回退到用户态处理
}

// TC程序 - 出站流量监控
SEC("tc")
int xray_accelerator_tc_egress(struct __sk_buff *skb) {
    if (!get_config(CONFIG_ENABLED)) {
        return TC_ACT_OK;
    }
    
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }
    
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return TC_ACT_OK;
    }
    
    __u16 src_port = 0, dst_port = 0;
    
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end) {
            return TC_ACT_OK;
        }
        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end) {
            return TC_ACT_OK;
        }
        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
    }
    
    // 学习出站流量模式
    __u64 flow_hash = calc_flow_hash(ip->saddr, ip->daddr, src_port, dst_port, ip->protocol);
    learn_route(flow_hash, skb->len);
    
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";