// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// 简化的DNS响应数据结构
struct dns_response {
    __u32 ip;              // 单个IP地址
    __u32 ttl;             // TTL值
    __u64 expire_time;     // 过期时间戳
} __attribute__((packed));

// DNS缓存映射表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);    // 简化的域名哈希
    __type(value, struct dns_response);
} dns_cache SEC(".maps");

// DNS查询统计映射表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 5000);
    __type(key, __u32);    // 简化的域名哈希
    __type(value, __u32);  // 查询次数
} dns_stats SEC(".maps");

// DNS头部结构
struct dns_header {
    __u16 id;
    __u16 flags;
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 arcount;
};

// 极简的字符串哈希函数 - 只处理前4个字节
static __always_inline __u32 simple_hash(const char *str, int len) {
    __u32 hash = 0;
    int max_len = len > 4 ? 4 : len;
    
    // 手动展开，避免循环
    if (max_len >= 1) hash = (hash << 8) | str[0];
    if (max_len >= 2) hash = (hash << 8) | str[1];
    if (max_len >= 3) hash = (hash << 8) | str[2];
    if (max_len >= 4) hash = (hash << 8) | str[3];
    
    return hash;
}

// 极简的DNS查询解析 - 只提取前16个字节作为域名标识
static __always_inline int parse_dns_simple(const void *data, const void *data_end, 
                                          char *domain, int max_len) {
    const struct dns_header *dns = data;
    if ((void*)(dns + 1) > data_end) {
        return -1;
    }
    
    const unsigned char *ptr = (const unsigned char*)(dns + 1);
    int domain_len = 0;
    
    // 只复制前16个字节，避免复杂解析
    int copy_len = 16;
    if (copy_len > max_len - 1) copy_len = max_len - 1;
    
    // 手动展开复制，避免循环
    if (copy_len >= 1 && (void*)(ptr + 1) <= data_end) domain[domain_len++] = ptr[0];
    if (copy_len >= 2 && (void*)(ptr + 2) <= data_end) domain[domain_len++] = ptr[1];
    if (copy_len >= 3 && (void*)(ptr + 3) <= data_end) domain[domain_len++] = ptr[2];
    if (copy_len >= 4 && (void*)(ptr + 4) <= data_end) domain[domain_len++] = ptr[3];
    if (copy_len >= 5 && (void*)(ptr + 5) <= data_end) domain[domain_len++] = ptr[4];
    if (copy_len >= 6 && (void*)(ptr + 6) <= data_end) domain[domain_len++] = ptr[5];
    if (copy_len >= 7 && (void*)(ptr + 7) <= data_end) domain[domain_len++] = ptr[6];
    if (copy_len >= 8 && (void*)(ptr + 8) <= data_end) domain[domain_len++] = ptr[7];
    if (copy_len >= 9 && (void*)(ptr + 9) <= data_end) domain[domain_len++] = ptr[8];
    if (copy_len >= 10 && (void*)(ptr + 10) <= data_end) domain[domain_len++] = ptr[9];
    if (copy_len >= 11 && (void*)(ptr + 11) <= data_end) domain[domain_len++] = ptr[10];
    if (copy_len >= 12 && (void*)(ptr + 12) <= data_end) domain[domain_len++] = ptr[11];
    if (copy_len >= 13 && (void*)(ptr + 13) <= data_end) domain[domain_len++] = ptr[12];
    if (copy_len >= 14 && (void*)(ptr + 14) <= data_end) domain[domain_len++] = ptr[13];
    if (copy_len >= 15 && (void*)(ptr + 15) <= data_end) domain[domain_len++] = ptr[14];
    if (copy_len >= 16 && (void*)(ptr + 16) <= data_end) domain[domain_len++] = ptr[15];
    
    // 确保以null结尾
    if (domain_len < max_len) {
        domain[domain_len] = '\0';
    }
    
    return domain_len;
}

// 检查DNS缓存
static __always_inline int check_dns_cache(const char *domain, int domain_len) {
    __u32 domain_hash = simple_hash(domain, domain_len);
    
    // 查找DNS缓存
    struct dns_response *response = bpf_map_lookup_elem(&dns_cache, &domain_hash);
    if (!response) {
        return -1;
    }
    
    // 检查是否过期
    __u64 current_time = bpf_ktime_get_ns() / 1000000000; // 转换为秒
    if (current_time > response->expire_time) {
        bpf_map_delete_elem(&dns_cache, &domain_hash);
        return -1;
    }
    
    return 0; // 缓存命中
}

// 更新DNS统计信息
static __always_inline void update_dns_stats(const char *domain, int domain_len) {
    __u32 domain_hash = simple_hash(domain, domain_len);
    __u32 *count = bpf_map_lookup_elem(&dns_stats, &domain_hash);
    
    if (count) {
        (*count)++;
    } else {
        __u32 new_count = 1;
        bpf_map_update_elem(&dns_stats, &domain_hash, &new_count, BPF_ANY);
    }
}

// XDP程序入口点
SEC("xdp")
int dns_cache_xdp(struct xdp_md *ctx) {
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
    
    // 只处理UDP包
    if (ip->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }
    
    // 解析UDP头部
    struct udphdr *udp = (void*)(ip + 1);
    if ((void*)(udp + 1) > data_end) {
        return XDP_PASS;
    }
    
    // 只处理DNS查询 (端口53)
    if (udp->dest != bpf_htons(53)) {
        return XDP_PASS;
    }
    
    // 解析DNS头部
    struct dns_header *dns = (void*)(udp + 1);
    if ((void*)(dns + 1) > data_end) {
        return XDP_PASS;
    }
    
    // 只处理查询包 (QR=0)
    if (bpf_ntohs(dns->flags) & 0x8000) {
        return XDP_PASS;
    }
    
    // 解析域名
    char domain[32];
    int domain_len = parse_dns_simple(dns, data_end, domain, sizeof(domain));
    if (domain_len <= 0) {
        return XDP_PASS;
    }
    
    // 更新统计信息
    update_dns_stats(domain, domain_len);
    
    // 检查缓存
    if (check_dns_cache(domain, domain_len) == 0) {
        // 缓存命中，可以在这里实现缓存响应逻辑
        // 由于eBPF限制，这里只是记录命中
    }
    
    return XDP_PASS;
} 