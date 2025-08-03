#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/string.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// DNS响应数据结构（必须在maps定义之前）
struct dns_response {
    __u32 ip_count;        // IP地址数量
    __u32 ips[8];          // 最多8个IP地址
    __u32 ttl;             // TTL值
    __u64 expire_time;     // 过期时间戳
    __u16 rcode;           // 响应码
} __attribute__((packed));

// DNS缓存映射表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 50000);
    __type(key, __u64);    // 域名哈希
    __type(value, __u32);  // IP地址
} dns_cache SEC(".maps");

// DNS查询统计映射表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);    // 域名哈希
    __type(value, __u64);  // 查询次数
} dns_stats SEC(".maps");

// DNS响应缓存映射表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);    // 域名哈希
    __type(value, struct dns_response);  // DNS响应数据
} dns_responses SEC(".maps");

// DNS头部结构
struct dns_header {
    __u16 id;
    __u16 flags;
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 arcount;
};

// 简单的字符串哈希函数
static __always_inline __u64 hash_string(const char *str, int len) {
    __u64 hash = 5381;
    for (int i = 0; i < len && i < 64; i++) {
        hash = ((hash << 5) + hash) + str[i];
    }
    return hash;
}

// 解析DNS查询域名 (eBPF兼容版本)
static __always_inline int parse_dns_query(const void *data, const void *data_end, 
                                         char *domain, int max_len) {
    const struct dns_header *dns = data;
    if ((void*)(dns + 1) > data_end) {
        return -1;
    }
    
    const unsigned char *ptr = (const unsigned char*)(dns + 1);
    int domain_len = 0;
    int labels_processed = 0;
    const int MAX_LABELS = 32; // 限制最大标签数量
    
    // 边界检查
    if ((void*)(ptr + 1) > data_end) {
        return -1;
    }
    
    int label_len = *ptr;
    
    // 使用有界循环处理DNS标签
    while (label_len > 0 && domain_len < max_len - 1 && labels_processed < MAX_LABELS) {
        ptr++;
        
        // 确保不会越界
        if ((void*)(ptr + label_len) > data_end || label_len > 63) {
            break;
        }
        
        // 限制每个标签的复制，使用展开的循环来避免eBPF验证器问题
        int copy_len = (label_len < (max_len - domain_len - 1)) ? label_len : (max_len - domain_len - 1);
        if (copy_len > 63) copy_len = 63; // DNS标签最大长度
        
        // 手动展开前几个字节的复制以帮助eBPF验证器
        #pragma unroll
        for (int i = 0; i < 64; i++) {
            if (i >= copy_len || domain_len >= max_len - 1) break;
            if ((void*)(ptr + i) >= data_end) break;
            
            domain[domain_len] = ptr[i];
            domain_len++;
        }
        
        ptr += label_len;
        labels_processed++;
        
        // 添加点分隔符
        if (domain_len < max_len - 1) {
            domain[domain_len] = '.';
            domain_len++;
        }
        
        // 检查下一个标签长度
        if ((void*)(ptr + 1) > data_end) {
            break;
        }
        label_len = *ptr;
    }
    
    // 移除末尾的点
    if (domain_len > 0 && domain[domain_len - 1] == '.') {
        domain_len--;
    }
    
    // 确保以null结尾
    if (domain_len < max_len) {
        domain[domain_len] = '\0';
    }
    
    return domain_len;
}

// 检查DNS缓存
static __always_inline int check_dns_cache(const char *domain, int domain_len) {
    __u64 domain_hash = hash_string(domain, domain_len);
    
    // 查找DNS响应缓存
    struct dns_response *response = bpf_map_lookup_elem(&dns_responses, &domain_hash);
    if (!response) {
        return -1;
    }
    
    // 检查是否过期
    __u64 current_time = bpf_ktime_get_ns() / 1000000000; // 转换为秒
    if (current_time > response->expire_time) {
        bpf_map_delete_elem(&dns_responses, &domain_hash);
        return -1;
    }
    
    return 0; // 缓存命中
}

// 更新DNS统计信息
static __always_inline void update_dns_stats(const char *domain, int domain_len) {
    __u64 domain_hash = hash_string(domain, domain_len);
    __u64 *count = bpf_map_lookup_elem(&dns_stats, &domain_hash);
    
    if (count) {
        (*count)++;
    } else {
        __u64 new_count = 1;
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
    
    // 检查是否是DNS查询（端口53）
    if (bpf_ntohs(udp->dest) != 53) {
        return XDP_PASS;
    }
    
    // 解析DNS查询
    char domain[256];
    int domain_len = parse_dns_query((void*)(udp + 1), data_end, domain, sizeof(domain));
    if (domain_len <= 0) {
        return XDP_PASS;
    }
    
    // 更新统计信息
    update_dns_stats(domain, domain_len);
    
    // 检查DNS缓存
    if (check_dns_cache(domain, domain_len) == 0) {
        // 缓存命中，可以在这里实现快速响应
        // 由于XDP的限制，我们只能标记数据包用于后续处理
        return XDP_PASS;
    }
    
    return XDP_PASS;
}

// 许可证声明
char _license[] SEC("license") = "GPL"; 