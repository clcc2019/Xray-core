// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// 极简化的DNS统计结构
struct dns_minimal_stats {
    __u64 total_queries;
    __u64 cache_hits;
    __u64 cache_misses;
    __u64 blocked_queries;
};

// 极简化的Maps
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct dns_minimal_stats);
} dns_minimal_stats SEC(".maps");

// 更新统计
static __always_inline void update_minimal_stats(__u32 type) {
    __u32 key = 0;
    struct dns_minimal_stats *stats = bpf_map_lookup_elem(&dns_minimal_stats, &key);
    if (!stats) return;
    
    switch (type) {
        case 0: __sync_fetch_and_add(&stats->total_queries, 1); break;
        case 1: __sync_fetch_and_add(&stats->cache_hits, 1); break;
        case 2: __sync_fetch_and_add(&stats->cache_misses, 1); break;
        case 3: __sync_fetch_and_add(&stats->blocked_queries, 1); break;
    }
}

// 极简化的XDP程序 - 只做DNS流量统计
SEC("xdp")
int dns_minimal_xdp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 最基本的长度检查
    if (data + 42 > data_end) {  // 最小以太网+IP+UDP头
        return XDP_PASS;
    }
    
    // 基本检查：看起来像UDP包
    struct ethhdr *eth = data;
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(struct ethhdr);
        if ((void *)(ip + 1) <= data_end && ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)(ip + 1);
            if ((void *)(udp + 1) <= data_end) {
                // DNS流量检测（端口53）
                if (udp->dest == bpf_htons(53) || udp->source == bpf_htons(53)) {
                    update_minimal_stats(0); // total_queries
                }
            }
        }
    }
    
    return XDP_PASS;
}

// 极简化的TC程序
SEC("tc")
int dns_minimal_tc(struct __sk_buff *skb) {
    // 只做最基本的协议检查
    if (skb->protocol == bpf_htons(ETH_P_IP)) {
        update_minimal_stats(0); // total_queries
    }
    
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";