// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/string.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_DOMAIN_LEN 128         // 减少域名长度限制
#define MAX_CACHE_SIZE 3000        // 缓存大小，只存储热点域名
#define MIN_ACCESS_COUNT 2         // 最小访问次数才缓存
#define CACHE_TTL_SECONDS 600      // 缓存过期时间10分钟

// 域名哈希结构
struct domain_hash_key {
    __u64 hash;                    // 域名哈希值
};

// 动态GeoSite缓存条目
struct geosite_cache_entry {
    __u64 domain_hash;             // 域名哈希
    __u8 site_code;                // 站点代码
    __u32 access_count;            // 访问次数
    __u64 last_access_time;        // 最后访问时间
    __u32 ttl;                     // 生存时间
};

// 动态GeoSite缓存 (LRU)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CACHE_SIZE);
    __type(key, __u64);            // 域名哈希
    __type(value, struct geosite_cache_entry);
} geosite_dynamic_cache SEC(".maps");

// 域名访问频率统计
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CACHE_SIZE * 2);  // 统计更多域名的访问频率
    __type(key, __u64);            // 域名哈希
    __type(value, __u32);          // 访问次数
} domain_access_stats SEC(".maps");

// 热点域名列表 (经常访问的域名)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 800);      // 最多800个热点域名
    __type(key, __u64);            // 域名哈希
    __type(value, __u8);           // 1表示是热点域名
} hot_domain_list SEC(".maps");

// GeoSite动态配置
struct geosite_dynamic_config {
    __u32 cache_enabled;           // 是否启用缓存
    __u32 min_access_count;        // 最小访问次数
    __u32 max_cache_size;          // 最大缓存大小
    __u32 ttl_seconds;             // TTL秒数
};

// 配置map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct geosite_dynamic_config);
} geosite_config_dynamic SEC(".maps");

// 统计信息
struct geosite_dynamic_stats {
    __u64 total_queries;           // 总查询数
    __u64 cache_hits;              // 缓存命中数
    __u64 cache_misses;            // 缓存未命中数
    __u64 dynamic_adds;            // 动态添加数
    __u64 hot_domain_promotions;   // 热点域名提升数
    __u64 dns_packets;             // DNS包数量
};

// 统计map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct geosite_dynamic_stats);
} geosite_stats_dynamic SEC(".maps");

// 简单的字符串哈希函数
static __always_inline __u64 simple_domain_hash(const char *str, int len) {
    __u64 hash = 5381;
    
    #pragma unroll
    for (int i = 0; i < 32 && i < len; i++) {
        if (str[i] == 0) break;
        hash = ((hash << 5) + hash) + str[i];
    }
    
    return hash;
}

// 获取当前时间戳（简化实现）
static __always_inline __u64 get_current_time_geosite() {
    return bpf_ktime_get_ns() / 1000000000; // 转换为秒
}

// 更新统计信息
static __always_inline void update_geosite_stats(int stat_type) {
    __u32 key = 0;
    struct geosite_dynamic_stats *stats = bpf_map_lookup_elem(&geosite_stats_dynamic, &key);
    if (stats) {
        switch (stat_type) {
            case 0: __sync_fetch_and_add(&stats->total_queries, 1); break;
            case 1: __sync_fetch_and_add(&stats->cache_hits, 1); break;
            case 2: __sync_fetch_and_add(&stats->cache_misses, 1); break;
            case 3: __sync_fetch_and_add(&stats->dynamic_adds, 1); break;
            case 4: __sync_fetch_and_add(&stats->hot_domain_promotions, 1); break;
            case 5: __sync_fetch_and_add(&stats->dns_packets, 1); break;
        }
    }
}

// 检查域名是否为热点域名
static __always_inline int is_hot_domain(__u64 domain_hash) {
    return bpf_map_lookup_elem(&hot_domain_list, &domain_hash) != NULL;
}

// 更新域名访问统计
static __always_inline void update_domain_access(__u64 domain_hash) {
    __u32 *count = bpf_map_lookup_elem(&domain_access_stats, &domain_hash);
    if (count) {
        __u32 new_count = *count + 1;
        bpf_map_update_elem(&domain_access_stats, &domain_hash, &new_count, BPF_ANY);
        
        // 如果访问次数达到阈值，标记为热点域名
        if (new_count >= MIN_ACCESS_COUNT) {
            __u8 hot = 1;
            bpf_map_update_elem(&hot_domain_list, &domain_hash, &hot, BPF_ANY);
            update_geosite_stats(4); // hot_domain_promotions
        }
    } else {
        __u32 init_count = 1;
        bpf_map_update_elem(&domain_access_stats, &domain_hash, &init_count, BPF_ANY);
    }
}

// 动态添加到缓存
__attribute__((unused))
static __always_inline void add_to_geosite_cache(__u64 domain_hash, __u8 site_code) {
    // 只缓存热点域名
    if (!is_hot_domain(domain_hash)) {
        return;
    }
    
    struct geosite_cache_entry entry = {
        .domain_hash = domain_hash,
        .site_code = site_code,
        .access_count = 1,
        .last_access_time = get_current_time_geosite(),
        .ttl = CACHE_TTL_SECONDS
    };
    
    bpf_map_update_elem(&geosite_dynamic_cache, &domain_hash, &entry, BPF_ANY);
    update_geosite_stats(3); // dynamic_adds
}

// 从动态缓存查找
static __always_inline __u8 lookup_geosite_cache(__u64 domain_hash) {
    struct geosite_cache_entry *entry = bpf_map_lookup_elem(&geosite_dynamic_cache, &domain_hash);
    if (!entry) {
        return 0; // 未找到
    }
    
    __u64 current_time = get_current_time_geosite();
    
    // 检查TTL
    if (current_time - entry->last_access_time > entry->ttl) {
        bpf_map_delete_elem(&geosite_dynamic_cache, &domain_hash);
        return 0; // 已过期
    }
    
    // 更新访问信息
    entry->access_count++;
    entry->last_access_time = current_time;
    bpf_map_update_elem(&geosite_dynamic_cache, &domain_hash, entry, BPF_ANY);
    
    return entry->site_code;
}

// 简单的域名解析（从DNS包中提取）
static __always_inline int parse_dns_domain(const void *dns_data, const void *data_end, __u64 *domain_hash) {
    if (dns_data + 12 > data_end) // DNS头最少12字节
        return -1;
    
    const char *domain_start = (const char *)dns_data + 12; // 跳过DNS头
    if ((const void *)domain_start >= data_end)
        return -1;
    
    // 简化：直接计算前32字节的哈希
    char domain_buffer[32] = {0};
    
    #pragma unroll
    for (int i = 0; i < 31 && (const void *)(domain_start + i) < data_end; i++) {
        domain_buffer[i] = domain_start[i];
        if (domain_buffer[i] == 0) break;
    }
    
    *domain_hash = simple_domain_hash(domain_buffer, 32);
    return 0;
}

// XDP程序 - GeoSite动态匹配
SEC("xdp")
int geosite_dynamic_match_xdp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 基本包验证
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;
    
    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    // 验证IP头
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;
    
    struct iphdr *ip = data + sizeof(struct ethhdr);
    
    // 只处理UDP包（DNS通常是UDP）
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;
    
    // 验证UDP头
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
        return XDP_PASS;
    
    struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    
    // 检查是否是DNS查询（端口53）
    if (udp->dest != bpf_htons(53) && udp->source != bpf_htons(53))
        return XDP_PASS;
    
    update_geosite_stats(0); // total_queries
    update_geosite_stats(5); // dns_packets
    
    // 解析域名并计算哈希
    void *dns_data = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    __u64 domain_hash = 0;
    
    if (parse_dns_domain(dns_data, data_end, &domain_hash) == 0 && domain_hash != 0) {
        // 更新域名访问统计
        update_domain_access(domain_hash);
        
        // 尝试从动态缓存查找
        __u8 site_code = lookup_geosite_cache(domain_hash);
        
        if (site_code) {
            update_geosite_stats(1); // cache_hits
        } else {
            update_geosite_stats(2); // cache_misses
            
            // 这里在实际实现中，会调用用户空间程序进行完整匹配
            // 然后根据结果更新缓存
        }
    }
    
    return XDP_PASS;
}

// TC程序 - GeoSite动态匹配
SEC("tc")
int geosite_dynamic_match_tc(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    // 基本包验证
    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_OK;
    
    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    // 验证IP头
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return TC_ACT_OK;
    
    struct iphdr *ip = data + sizeof(struct ethhdr);
    
    // 只处理UDP包
    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;
    
    // 验证UDP头
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
        return TC_ACT_OK;
    
    struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    
    // 检查是否是DNS查询
    if (udp->dest != bpf_htons(53) && udp->source != bpf_htons(53))
        return TC_ACT_OK;
    
    update_geosite_stats(0); // total_queries
    update_geosite_stats(5); // dns_packets
    
    // 解析域名并计算哈希
    void *dns_data = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    __u64 domain_hash = 0;
    
    if (parse_dns_domain(dns_data, data_end, &domain_hash) == 0 && domain_hash != 0) {
        // 更新域名访问统计
        update_domain_access(domain_hash);
        
        // 检查动态缓存
        __u8 site_code = lookup_geosite_cache(domain_hash);
        
        if (site_code) {
            update_geosite_stats(1); // cache_hits
        } else {
            update_geosite_stats(2); // cache_misses
        }
    }
    
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";