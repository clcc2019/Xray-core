// +build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

// 简化的统计结构
struct simple_stats {
    __u64 packet_count;
    __u64 byte_count;
    __u64 connection_count;
};

// 统计map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct simple_stats);
} tc_stats SEC(".maps");

// 简化的TC程序 - 只做基本统计
SEC("tc/ingress")
int tcp_stats_tc(struct __sk_buff *skb) {
    __u32 key = 0;
    struct simple_stats *stats = bpf_map_lookup_elem(&tc_stats, &key);
    
    if (stats) {
        stats->packet_count++;
        stats->byte_count += skb->len;
    }
    
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL"; 