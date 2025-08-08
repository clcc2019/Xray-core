// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef __maybe_unused
#define __maybe_unused __attribute__((unused))
#endif

// DNS A 记录缓存条目（IPv4）
struct dns_response_v4 {
    __u32 ip;              // IPv4 地址（网络序）
    __u32 ttl;             // TTL（秒）
    __u64 expire_time;     // 过期时间（秒）
} __attribute__((packed));

// DNS AAAA 记录缓存条目（IPv6）
struct dns_response_v6 {
    __u64 ip_high;         // IPv6 高 64 位（网络序）
    __u64 ip_low;          // IPv6 低 64 位（网络序）
    __u32 ttl;             // TTL（秒）
    __u64 expire_time;     // 过期时间（秒）
} __attribute__((packed));

// DNS缓存映射表（IPv4，名称与用户态保持兼容）
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 50000);
    __type(key, __u32);    // 域名哈希（FNV-1a 32bit）
    __type(value, struct dns_response_v4);
} dns_cache SEC(".maps");

// DNS缓存映射表（IPv6）
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 25000);
    __type(key, __u32);    // 域名哈希（FNV-1a 32bit）
    __type(value, struct dns_response_v6);
} dns_cache_v6 SEC(".maps");

// DNS查询统计映射表（按域名哈希计数）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 20000);
    __type(key, __u32);    // 域名哈希
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

// tolower（仅 A-Z）
static __always_inline char lower_char(char c) {
    if (c >= 'A' && c <= 'Z') return c + 32;
    return c;
}

// FNV-1a 32 位哈希（小缓冲）
static __always_inline __maybe_unused __u32 fnv1a32(const char *buf, int len) {
    const __u32 FNV_PRIME = 16777619U;
    __u32 hash = 2166136261U;
    for (int i = 0; i < len && i < 128; i++) {
        hash ^= (unsigned char)buf[i];
        hash *= FNV_PRIME;
    }
    return hash;
}

// 仅计算 QNAME 的 FNV-1a 哈希，并读取 QTYPE（避免使用可变偏移栈访问）
static __always_inline int parse_qname_hash_qtype(struct xdp_md *ctx, __u32 dns_start_off,
                                                 __u32 *hash_out, __u16 *qtype_out) {
    const __u32 FNV_PRIME = 16777619U;
    __u32 hash = 2166136261U;
    __u32 pos = 12;         // QNAME 相对 DNS 头起始偏移
    __u32 limit = 160;      // 最大解析范围保护

    // 最多解析 10 个 label，每个 label 最多读取 32 字节
    #pragma clang loop unroll(disable)
    for (int lbl = 0; lbl < 10; lbl++) {
        if (pos + 1 > limit) return -1;
        unsigned char labellen = 0;
        if (bpf_xdp_load_bytes(ctx, dns_start_off + pos, &labellen, 1) < 0) return -1;
        pos += 1;
        if (labellen == 0) {
            // 读取 QTYPE（网络序）
            __u16 qtype_be = 0;
            if (bpf_xdp_load_bytes(ctx, dns_start_off + pos, &qtype_be, sizeof(qtype_be)) < 0) return -1;
            *qtype_out = (__u16)((qtype_be >> 8) | (qtype_be << 8));
            *hash_out = hash;
            return 0;
        }
        if (pos + labellen > limit) return -1;
        #pragma clang loop unroll(disable)
        for (int i = 0; i < 32; i++) {
            if (i >= labellen) break;
            unsigned char ch = 0;
            if (bpf_xdp_load_bytes(ctx, dns_start_off + pos + i, &ch, 1) < 0) return -1;
            char lc = lower_char((char)ch);
            hash ^= (unsigned char)lc;
            hash *= FNV_PRIME;
        }
        pos += labellen;
    }
    return -1;
}

// 检查DNS缓存
static __always_inline int check_dns_cache_v4_hash(__u32 key) {
    struct dns_response_v4 *resp = bpf_map_lookup_elem(&dns_cache, &key);
    if (!resp) return -1;
    __u64 now = bpf_ktime_get_ns() / 1000000000ULL;
    if (now > resp->expire_time) {
        bpf_map_delete_elem(&dns_cache, &key);
        return -1;
    }
    return 0;
}

static __always_inline int check_dns_cache_v6_hash(__u32 key) {
    struct dns_response_v6 *resp = bpf_map_lookup_elem(&dns_cache_v6, &key);
    if (!resp) return -1;
    __u64 now = bpf_ktime_get_ns() / 1000000000ULL;
    if (now > resp->expire_time) {
        bpf_map_delete_elem(&dns_cache_v6, &key);
        return -1;
    }
    return 0;
}

// 更新DNS统计信息
static __always_inline void update_dns_stats_hash(__u32 domain_hash) {
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
    
    // 只处理IPv4包（UDP/53 查询）
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
    
    // 只处理DNS查询 (目标端口53，QR=0)
    if (udp->dest != bpf_htons(53)) {
        return XDP_PASS;
    }
    
    // 解析DNS头部与 QNAME/QTYPE
    // 计算 DNS 头起始偏移，使用 IHL 以避免固定 20 字节假设
    __u8 vihl = 0;
    if (bpf_xdp_load_bytes(ctx, 14, &vihl, 1) < 0) return XDP_PASS;
    __u32 ihl = (vihl & 0x0F) * 4; // 字节
    __u32 udp_off = 14 + ihl;
    __u16 flags = 0;
    if (bpf_xdp_load_bytes(ctx, udp_off + 8 + 2, &flags, sizeof(flags)) < 0) return XDP_PASS; // DNS flags 位于 DNS 头偏移 2
    if ((flags & bpf_htons(0x8000)) != 0) return XDP_PASS; // 只处理查询（QR=0）

    __u32 domain_hash = 0;
    __u16 qtype = 0;
    if (parse_qname_hash_qtype(ctx, udp_off + 8, &domain_hash, &qtype) < 0) return XDP_PASS;

    update_dns_stats_hash(domain_hash);

    // 根据类型检查缓存（命中仅统计，真正响应仍由用户态完成）
    if (qtype == 1 /*A*/ ) {
        (void)check_dns_cache_v4_hash(domain_hash);
    } else if (qtype == 28 /*AAAA*/ ) {
        (void)check_dns_cache_v6_hash(domain_hash);
    }
    
    return XDP_PASS;
} 

// 许可证声明
char _license[] SEC("license") = "GPL";