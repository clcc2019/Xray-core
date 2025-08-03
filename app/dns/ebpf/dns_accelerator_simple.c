// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_DOMAIN_LEN 64  // 减小域名长度限制
#define MAX_ENTRIES 10000  // 减小映射大小

// 简化的DNS缓存条目
struct dns_cache_entry {
    __u32 ip;
    __u32 ttl;
    __u64 expire_time;
    __u32 hit_count;
};

// 简化的DNS统计
struct dns_stats {
    __u64 total_queries;
    __u64 cache_hits;
    __u64 cache_misses;
    __u64 blocked_queries;
};

// 简化的配置
struct dns_config {
    __u32 cache_enabled;
    __u32 filter_enabled;
    __u32 rate_limit_enabled;
    __u32 max_qps;
};

// eBPF Maps - 简化版本

// DNS缓存 - 使用较小的LRU缓存
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);  // 域名哈希
    __type(value, struct dns_cache_entry);
} dns_cache_simple SEC(".maps");

// 恶意域名黑名单 - 简化版
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, __u64);  // 域名哈希
    __type(value, __u8);  // 威胁级别
} malicious_domains_simple SEC(".maps");

// 统计信息
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct dns_stats);
} dns_stats_simple SEC(".maps");

// 配置
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct dns_config);
} dns_config_simple SEC(".maps");

// 速率限制
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000);
    __type(key, __u32);  // 客户端IP
    __type(value, __u32); // 查询计数
} rate_limit_simple SEC(".maps");

// 临时域名缓冲区 - 使用per-cpu数组避免栈溢出
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[MAX_DOMAIN_LEN]);
} domain_buffer SEC(".maps");

// 简化的字符串哈希函数
__attribute__((unused)) static __always_inline __u64 simple_hash(const char *str, int len) {
    __u64 hash = 5381;
    
    // 限制循环次数，避免验证器问题
    if (len > MAX_DOMAIN_LEN) len = MAX_DOMAIN_LEN;
    
    #pragma unroll
    for (int i = 0; i < 32; i++) {  // 固定循环次数
        if (i >= len) break;
        hash = ((hash << 5) + hash) + (unsigned char)str[i];
    }
    return hash;
}

// 获取配置
static __always_inline struct dns_config* get_config() {
    __u32 key = 0;
    return bpf_map_lookup_elem(&dns_config_simple, &key);
}

// 更新统计
static __always_inline void update_stats(__u32 type) {
    __u32 key = 0;
    struct dns_stats *stats = bpf_map_lookup_elem(&dns_stats_simple, &key);
    if (!stats) return;
    
    switch (type) {
        case 0: __sync_fetch_and_add(&stats->total_queries, 1); break;
        case 1: __sync_fetch_and_add(&stats->cache_hits, 1); break;
        case 2: __sync_fetch_and_add(&stats->cache_misses, 1); break;
        case 3: __sync_fetch_and_add(&stats->blocked_queries, 1); break;
    }
}

// 速率限制检查
static __always_inline int check_rate_limit(__u32 client_ip) {
    struct dns_config *config = get_config();
    if (!config || !config->rate_limit_enabled) return 0;
    
    __u32 *count = bpf_map_lookup_elem(&rate_limit_simple, &client_ip);
    if (count) {
        if (*count >= config->max_qps) {
            return 1; // 超过限制
        }
        __sync_fetch_and_add(count, 1);
    } else {
        __u32 initial = 1;
        bpf_map_update_elem(&rate_limit_simple, &client_ip, &initial, BPF_ANY);
    }
    return 0;
}

// 检查恶意域名
static __always_inline int is_malicious(__u64 domain_hash) {
    struct dns_config *config = get_config();
    if (!config || !config->filter_enabled) return 0;
    
    __u8 *threat_level = bpf_map_lookup_elem(&malicious_domains_simple, &domain_hash);
    return threat_level ? *threat_level : 0;
}

// 查找缓存
static __always_inline struct dns_cache_entry* lookup_cache(__u64 domain_hash) {
    struct dns_config *config = get_config();
    if (!config || !config->cache_enabled) return NULL;
    
    struct dns_cache_entry *entry = bpf_map_lookup_elem(&dns_cache_simple, &domain_hash);
    if (entry) {
        __u64 current_time = bpf_ktime_get_ns() / 1000000000; // 转换为秒
        if (current_time < entry->expire_time) {
            __sync_fetch_and_add(&entry->hit_count, 1);
            return entry;
        } else {
            // 缓存过期，删除
            bpf_map_delete_elem(&dns_cache_simple, &domain_hash);
        }
    }
    return NULL;
}

// DNS响应构造 - 在内核直接构造DNS响应包
static __always_inline int construct_dns_response(struct xdp_md *ctx, 
                                                  struct dns_cache_entry *cache_entry,
                                                  const void *dns_data) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 解析以太网头
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return -1;
    
    // 解析IP头
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return -1;
    
    // 解析UDP头
    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end) return -1;
    
    // DNS头指针
    void *dns_header = (void *)(udp + 1);
    if (dns_header + 12 > data_end) return -1;
    
    // 构造DNS响应
    // 1. 交换源和目标MAC地址
    unsigned char temp_mac[6];
    #pragma unroll
    for (int i = 0; i < 6; i++) {
        temp_mac[i] = eth->h_dest[i];
        eth->h_dest[i] = eth->h_source[i];
        eth->h_source[i] = temp_mac[i];
    }
    
    // 2. 交换源和目标IP地址
    __u32 temp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = temp_ip;
    
    // 3. 交换源和目标端口
    __u16 temp_port = udp->source;
    udp->source = udp->dest;
    udp->dest = temp_port;
    
    // 4. 修改DNS头 - 设置响应标志
    unsigned char *dns_flags = (unsigned char *)dns_header + 2;
    if ((void *)(dns_flags + 2) > data_end) return -1;
    
    dns_flags[0] |= 0x80; // QR=1 (响应)
    dns_flags[0] |= 0x04; // AA=1 (权威)
    dns_flags[1] &= 0xF0; // RCODE=0 (无错误)
    
    // 5. 设置应答数量
    unsigned char *ancount = (unsigned char *)dns_header + 6;
    if ((void *)(ancount + 2) > data_end) return -1;
    ancount[0] = 0x00;
    ancount[1] = 0x01; // 1个应答记录
    
    // 6. 构造应答记录（简化版本，假设查询域名后直接添加A记录）
    // 跳过查询部分，添加应答记录
    void *answer_start = dns_header + 12;
    
    // 跳过查询名称（简化处理，假设原始查询名称长度固定）
    void *answer_name = answer_start;
    if (answer_name + 32 > data_end) return -1; // 预留足够空间
    
    // 域名压缩指针指向查询部分
    unsigned char *name_ptr = (unsigned char *)answer_name;
    name_ptr[0] = 0xc0;  // 压缩指针标志
    name_ptr[1] = 0x0c;  // 指向DNS头后的查询名称
    
    // 应答记录的其他字段
    void *answer_fields = answer_name + 2;
    if (answer_fields + 10 > data_end) return -1;
    
    unsigned char *fields = (unsigned char *)answer_fields;
    fields[0] = 0x00; fields[1] = 0x01; // TYPE = A
    fields[2] = 0x00; fields[3] = 0x01; // CLASS = IN
    
    // TTL (4字节)
    __u32 ttl = cache_entry->ttl;
    fields[4] = (ttl >> 24) & 0xFF;
    fields[5] = (ttl >> 16) & 0xFF;
    fields[6] = (ttl >> 8) & 0xFF;
    fields[7] = ttl & 0xFF;
    
    fields[8] = 0x00; fields[9] = 0x04; // RDLENGTH = 4 (IPv4地址)
    
    // IP地址 (4字节)
    void *ip_addr = answer_fields + 10;
    if (ip_addr + 4 > data_end) return -1;
    
    __u32 cached_ip = cache_entry->ip;
    unsigned char *ip_bytes = (unsigned char *)ip_addr;
    ip_bytes[0] = cached_ip & 0xFF;
    ip_bytes[1] = (cached_ip >> 8) & 0xFF;
    ip_bytes[2] = (cached_ip >> 16) & 0xFF;
    ip_bytes[3] = (cached_ip >> 24) & 0xFF;
    
    // 7. 重新计算包长度
    __u16 new_udp_len = 8 + 12 + 32 + 16; // UDP头 + DNS头 + 查询 + 应答
    __u16 new_ip_len = 20 + new_udp_len;   // IP头 + UDP包
    
    udp->len = bpf_htons(new_udp_len);
    ip->tot_len = bpf_htons(new_ip_len);
    
    // 8. 重新计算校验和
    ip->check = 0;
    udp->check = 0;
    
    // 简化：不计算校验和（某些网卡会自动计算）
    
    return 0; // 成功构造响应
}

// 简化的域名解析 - 避免复杂循环
static __always_inline int parse_domain_simple(const void *dns_data, const void *data_end, __u64 *domain_hash) {
    const unsigned char *ptr = (const unsigned char*)dns_data;
    
    // 检查最小DNS头长度
    if (ptr + 12 > (unsigned char*)data_end) return -1;
    
    // 跳过DNS头，开始解析域名
    ptr += 12;
    
    // 简化的域名哈希计算 - 直接对原始字节计算哈希
    __u64 hash = 5381;
    
    #pragma unroll
    for (int i = 0; i < 32; i++) {  // 限制循环次数
        if (ptr + i >= (unsigned char*)data_end) break;
        
        unsigned char c = ptr[i];
        if (c == 0) break;  // 域名结束
        
        hash = ((hash << 5) + hash) + c;
    }
    
    *domain_hash = hash;
    return 0;
}

// 超快速DNS响应构造
static __always_inline int ultra_construct_dns_response(struct xdp_md *ctx,
                                                       struct dns_cache_entry *cache_entry,
                                                       const void *dns_data) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 基本包结构检查
    if (data + 70 > data_end) return -1; // 预留足够空间
    
    struct ethhdr *eth = data;
    struct iphdr *ip = (void *)(eth + 1);
    struct udphdr *udp = (void *)(ip + 1);
    void *dns_header = (void *)(udp + 1);
    
    // 超快速地址交换
    unsigned char temp_mac[6];
    #pragma unroll
    for (int i = 0; i < 6; i++) {
        temp_mac[i] = eth->h_dest[i];
        eth->h_dest[i] = eth->h_source[i];
        eth->h_source[i] = temp_mac[i];
    }
    
    __u32 temp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = temp_ip;
    
    __u16 temp_port = udp->source;
    udp->source = udp->dest;
    udp->dest = temp_port;
    
    // 设置DNS响应标志（超简化）
    unsigned char *dns_flags = (unsigned char *)dns_header + 2;
    if ((void *)(dns_flags + 2) > data_end) return -1;
    
    dns_flags[0] |= 0x80; // QR=1 (响应)
    dns_flags[1] &= 0xF0; // RCODE=0
    
    // 设置应答计数
    unsigned char *ancount = (unsigned char *)dns_header + 6;
    if ((void *)(ancount + 2) > data_end) return -1;
    ancount[1] = 0x01; // 1个应答
    
    // 简化：假设固定长度响应，直接在预定位置写入IP
    void *answer_ip = dns_header + 50; // 简化的固定偏移
    if (answer_ip + 4 > data_end) return -1;
    
    __u32 cached_ip = cache_entry->ip;
    unsigned char *ip_bytes = (unsigned char *)answer_ip;
    ip_bytes[0] = cached_ip & 0xFF;
    ip_bytes[1] = (cached_ip >> 8) & 0xFF;
    ip_bytes[2] = (cached_ip >> 16) & 0xFF;
    ip_bytes[3] = (cached_ip >> 24) & 0xFF;
    
    // 重新计算长度（简化）
    __u16 new_udp_len = 8 + 54; // UDP头 + 简化DNS响应
    __u16 new_ip_len = 20 + new_udp_len;
    
    udp->len = bpf_htons(new_udp_len);
    ip->tot_len = bpf_htons(new_ip_len);
    
    // 清零校验和让硬件计算
    ip->check = 0;
    udp->check = 0;
    
    return 0;
}

// DNS超快速路径 - 包级别预处理
static __always_inline int dns_ultra_fast_path(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 最小包大小检查（以太网+IP+UDP+DNS头）
    if (data + 42 + 12 > data_end) return XDP_PASS;
    
    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;
    
    struct iphdr *ip = (void *)(eth + 1);
    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;
    
    struct udphdr *udp = (void *)(ip + 1);
    
    // 超快速DNS端口检查
    if (udp->dest != bpf_htons(53)) return XDP_PASS;
    
    // 计算超简单域名哈希（基于UDP载荷前8字节）
    void *dns_data = (void *)(udp + 1);
    if (dns_data + 20 > data_end) return XDP_PASS;
    
    __u64 ultra_hash = 0;
    unsigned char *dns_bytes = (unsigned char *)dns_data;
    
    // 使用DNS ID和前几个字节快速计算哈希
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        ultra_hash = (ultra_hash << 8) | dns_bytes[i + 12]; // 跳过DNS头
    }
    
    // 查找超快速DNS缓存
    struct dns_cache_entry *ultra_entry = bpf_map_lookup_elem(&dns_cache_simple, &ultra_hash);
    if (ultra_entry) {
        // 超快速DNS响应构造（简化版本）
        if (ultra_construct_dns_response(ctx, ultra_entry, dns_data) == 0) {
            update_stats(1); // cache_hits
            return XDP_TX; // 超快速DNS响应
        }
    }
    
    return -1; // 继续常规处理
}

// XDP程序 - 简化版DNS加速器
SEC("xdp")
int dns_accelerator_simple_xdp(struct xdp_md *ctx) {
    // 尝试超快速路径
    int ultra_result = dns_ultra_fast_path(ctx);
    if (ultra_result >= 0) {
        return ultra_result; // 超快速路径处理成功
    }
    
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 解析以太网头
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }
    
    // 只处理IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    
    // 解析IP头
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }
    
    // 只处理UDP
    if (ip->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }
    
    // 解析UDP头
    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end) {
        return XDP_PASS;
    }
    
    // 检查是否是DNS查询 (端口53)
    if (udp->dest != bpf_htons(53)) {
        return XDP_PASS;
    }
    
    // 获取客户端IP
    __u32 client_ip = ip->saddr;
    
    // 速率限制检查
    if (check_rate_limit(client_ip)) {
        update_stats(3); // blocked_queries
        return XDP_DROP;
    }
    
    update_stats(0); // total_queries
    
    // 解析域名哈希
    void *dns_data = (void *)(udp + 1);
    __u64 domain_hash = 0;
    
    if (parse_domain_simple(dns_data, data_end, &domain_hash) < 0) {
        return XDP_PASS;
    }
    
    // 恶意域名检查
    if (is_malicious(domain_hash)) {
        update_stats(3); // blocked_queries
        return XDP_DROP;
    }
    
    // 查找缓存
struct dns_cache_entry *cache_entry = lookup_cache(domain_hash);
if (cache_entry) {
    update_stats(1); // cache_hits
    // 缓存命中 - 直接在内核构造DNS响应
    if (construct_dns_response(ctx, cache_entry, dns_data) == 0) {
        return XDP_TX;  // 直接从网卡发送响应，实现真正加速
    }
    // 如果构造失败，回退到用户态处理
    return XDP_PASS;
}
    
    update_stats(2); // cache_misses
    return XDP_PASS;
}

// TC程序 - 简化版DNS响应处理
SEC("tc")
int dns_accelerator_simple_tc(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    // 解析以太网头
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }
    
    // 只处理IPv4 DNS响应
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end || ip->protocol != IPPROTO_UDP) {
        return TC_ACT_OK;
    }
    
    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end || udp->source != bpf_htons(53)) {
        return TC_ACT_OK;
    }
    
    // 简化版本：只更新统计，不做复杂处理
    update_stats(0);
    
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";