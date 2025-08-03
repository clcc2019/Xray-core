// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/string.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// GeoIP匹配映射表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);    // IPv4地址
    __type(value, __u8);   // 国家代码
} geoip_v4_map SEC(".maps");

// IPv6 GeoIP匹配映射表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 50000);
    __type(key, __u64);    // IPv6地址（高64位）
    __type(value, struct geoip_v6_entry);   // IPv6条目
} geoip_v6_map SEC(".maps");

// IPv6条目结构
struct geoip_v6_entry {
    __u64 low;             // IPv6地址低64位
    __u8 country_code;     // 国家代码
    __u8 prefix_len;       // 前缀长度
    __u8 reverse_match;    // 反向匹配标志
    __u8 reserved;         // 保留字段
};

// CIDR范围映射表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);    // 网络地址
    __type(value, struct cidr_entry);   // CIDR条目
} cidr_v4_map SEC(".maps");

// CIDR条目结构
struct cidr_entry {
    __u8 prefix_len;       // 前缀长度
    __u8 country_code;     // 国家代码
    __u8 reverse_match;    // 反向匹配标志
    __u8 reserved;         // 保留字段
};

// 统计信息映射表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, __u32);    // 国家代码
    __type(value, __u64);  // 匹配次数
} geoip_stats SEC(".maps");

// 简单的字符串哈希函数
static __always_inline __u32 hash_string(const char *str, int len) {
    __u32 hash = 5381;
    for (int i = 0; i < len && i < 32; i++) {
        hash = ((hash << 5) + hash) + str[i];
    }
    return hash;
}

// 检查IPv4地址是否在CIDR范围内
static __always_inline int check_ipv4_cidr(__u32 ip, __u32 network, __u8 prefix_len) {
    __u32 mask = 0xFFFFFFFF << (32 - prefix_len);
    return (ip & mask) == (network & mask);
}

// 检查IPv6地址是否在CIDR范围内
static __always_inline int check_ipv6_cidr(const __u64 *ip, const __u64 *network, __u8 prefix_len) {
    if (prefix_len <= 64) {
        __u64 mask = 0xFFFFFFFFFFFFFFFFULL << (64 - prefix_len);
        return (ip[0] & mask) == (network[0] & mask);
    } else {
        __u64 mask = 0xFFFFFFFFFFFFFFFFULL << (128 - prefix_len);
        return (ip[0] == network[0]) && ((ip[1] & mask) == (network[1] & mask));
    }
}

// IPv4 GeoIP匹配
static __always_inline __u8 match_ipv4_geoip(__u32 ip) {
    // 首先检查精确匹配
    __u8 *country_code = bpf_map_lookup_elem(&geoip_v4_map, &ip);
    if (country_code) {
        return *country_code;
    }
    
    // 检查CIDR范围匹配
    struct cidr_entry *entry;
    __u32 network;
    
    // 遍历可能的网络地址
    for (int prefix_len = 32; prefix_len >= 8; prefix_len--) {
        __u32 mask = 0xFFFFFFFF << (32 - prefix_len);
        network = ip & mask;
        
        entry = bpf_map_lookup_elem(&cidr_v4_map, &network);
        if (entry && entry->prefix_len == prefix_len) {
            // 更新统计信息
            __u64 *count = bpf_map_lookup_elem(&geoip_stats, &entry->country_code);
            if (count) {
                (*count)++;
            }
            return entry->country_code;
        }
    }
    
    return 0; // 未匹配
}

// IPv6 GeoIP匹配
static __always_inline __u8 match_ipv6_geoip(const __u64 *ip) {
    // 检查IPv6映射表
    struct geoip_v6_entry *entry = bpf_map_lookup_elem(&geoip_v6_map, &ip[0]);
    if (entry && entry->low == ip[1]) {
        // 更新统计信息
        __u64 *count = bpf_map_lookup_elem(&geoip_stats, &entry->country_code);
        if (count) {
            (*count)++;
        }
        return entry->country_code;
    }
    
    return 0; // 未匹配
}

// 更新统计信息
static __always_inline void update_stats(__u8 country_code) {
    if (country_code != 0) {
        __u64 *count = bpf_map_lookup_elem(&geoip_stats, &country_code);
        if (count) {
            (*count)++;
        } else {
            __u64 new_count = 1;
            bpf_map_update_elem(&geoip_stats, &country_code, &new_count, BPF_ANY);
        }
    }
}

// XDP程序入口点 - 用于网络包级别的GeoIP匹配
SEC("xdp")
int geoip_match_xdp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 解析以太网头部
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end) {
        return XDP_PASS;
    }
    
    // 只处理IPv4包
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    
    // 解析IP头部
    struct iphdr *ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > data_end) {
        return XDP_PASS;
    }
    
    // 提取源IP地址
    __u32 src_ip = bpf_ntohl(ip->saddr);
    
    // 执行GeoIP匹配
    __u8 country_code = match_ipv4_geoip(src_ip);
    
    // 更新统计信息
    update_stats(country_code);
    
    // 可以根据匹配结果进行不同的处理
    // 例如：标记数据包、重定向等
    
    return XDP_PASS;
}

// 许可证声明
char _license[] SEC("license") = "GPL"; 