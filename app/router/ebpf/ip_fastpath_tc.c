// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct ip_hint_v4 {
    __u32 mark;
    __u64 expire_sec; // 0 means no-expire
};

struct ip_hint_v6 {
    __u32 mark;
    __u64 expire_sec; // 0 means no-expire
};

struct ipv6_key { __u64 hi; __u64 lo; } __attribute__((packed));

// IPv4 fastpath hint: dst_ip -> {mark, expire}
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);
    __type(value, struct ip_hint_v4);
} route_ip_v4_hint SEC(".maps");

// IPv6 fastpath hint: dst_ip -> {mark, expire}
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 80000);
    __type(key, struct ipv6_key);
    __type(value, struct ip_hint_v6);
} route_ip_v6_hint SEC(".maps");

// Global enable switch (array[0]): 0 = off (default), 1 = on
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} ip_fastpath_enable SEC(".maps");

static __always_inline int is_enabled() {
    __u32 k = 0; __u32 *v = bpf_map_lookup_elem(&ip_fastpath_enable, &k);
    return v && *v != 0;
}

static __always_inline __u64 now_sec() {
    return bpf_ktime_get_ns() / 1000000000ULL;
}

SEC("tc")
int ip_fastpath_tc(struct __sk_buff *skb) {
    if (!is_enabled()) return TC_ACT_OK;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end) return TC_ACT_OK;

    __u16 proto = eth->h_proto;
    if (proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void*)(eth + 1);
        if ((void*)(ip + 1) > data_end) return TC_ACT_OK;

        __u32 dst = ip->daddr; // network byte order
        struct ip_hint_v4 *h = bpf_map_lookup_elem(&route_ip_v4_hint, &dst);
        if (h) {
            if (h->expire_sec == 0 || now_sec() < h->expire_sec) {
                skb->mark = h->mark;
            } else {
                bpf_map_delete_elem(&route_ip_v4_hint, &dst);
            }
        }
        return TC_ACT_OK;
    } else if (proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (void*)(eth + 1);
        if ((void*)(ip6 + 1) > data_end) return TC_ACT_OK;

        struct ipv6_key key = {0};
        __builtin_memcpy(&key.hi, &ip6->daddr.s6_addr[0], 8);
        __builtin_memcpy(&key.lo, &ip6->daddr.s6_addr[8], 8);

        struct ip_hint_v6 *h6 = bpf_map_lookup_elem(&route_ip_v6_hint, &key);
        if (h6) {
            if (h6->expire_sec == 0 || now_sec() < h6->expire_sec) {
                skb->mark = h6->mark;
            } else {
                bpf_map_delete_elem(&route_ip_v6_hint, &key);
            }
        }
        return TC_ACT_OK;
    }
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";


