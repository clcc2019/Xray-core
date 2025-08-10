// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// XSK map: AF_XDP socket redirection
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);   // rx queue index
    __type(value, __u32);
} xsk_udp_map SEC(".maps");

// Per-queue enable flags to avoid redirect when no userspace XSK is bound
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} udp_xdp_queues_enable SEC(".maps");

// Filter flags: bit0 enable port whitelist; bit1 enable hot dst filter
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} udp_filter_enable SEC(".maps");

// UDP allowed destination ports (whitelist)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);
    __type(value, __u8);
} udp_allowed_ports SEC(".maps");

// Hot destination caches
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);   // IPv4 dst
    __type(value, __u8);
} udp_hot_dst_v4 SEC(".maps");

struct v6key { __u64 hi; __u64 lo; };
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct v6key);
    __type(value, __u8);
} udp_hot_dst_v6 SEC(".maps");

static __always_inline int parse_udp_ipv4(void *data, void *data_end)
{
    if (data + sizeof(struct iphdr) > data_end)
        return 0;
    struct iphdr *ip4 = (struct iphdr *)data;
    if (ip4->version != 4 || ip4->protocol != IPPROTO_UDP)
        return 0;
    if (data + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
        return 0;
    return 1;
}

static __always_inline int parse_udp_ipv6(void *data, void *data_end, __u16 *out_dport)
{
    if (data + sizeof(struct ipv6hdr) > data_end)
        return 0;
    struct ipv6hdr *ip6 = (struct ipv6hdr *)data;
    if (ip6->version != 6)
        return 0;
    __u8 nexthdr = ip6->nexthdr;
    __u16 off = sizeof(struct ipv6hdr);
    // limited ext header walk
    #pragma clang loop unroll(disable)
    for (int i = 0; i < 3; i++) {
        if (nexthdr == IPPROTO_UDP) break;
        if (nexthdr == 0 || nexthdr == 43 || nexthdr == 60 || nexthdr == 51) {
            if (data + off + 2 > data_end) return 0;
            __u8 nh = *(__u8 *)(data + off);
            __u8 hdrlen = *(__u8 *)(data + off + 1);
            __u16 extlen = (hdrlen + 1) * 8;
            if (data + off + extlen > data_end) return 0;
            nexthdr = nh; off += extlen; continue;
        } else if (nexthdr == 44) {
            if (data + off + 8 > data_end) return 0;
            __u8 nh = *(__u8 *)(data + off);
            nexthdr = nh; off += 8; continue;
        } else {
            return 0;
        }
    }
    if (nexthdr != IPPROTO_UDP) return 0;
    if (data + off + sizeof(struct udphdr) > data_end) return 0;
    __u16 dport_be = *(__u16 *)(data + off + 2);
    *out_dport = bpf_ntohs(dport_be);
    return 1;
}

SEC("xdp")
int xdp_udp_fastpath(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;
    struct ethhdr *eth = (struct ethhdr *)data;
    __u16 h_proto = bpf_ntohs(eth->h_proto);
    __u32 flags = 0, k0 = 0;
    __u32 *pf = bpf_map_lookup_elem(&udp_filter_enable, &k0);
    if (pf) flags = *pf;

    __u16 dport = 0;
    int is_v6 = 0;
    if (h_proto == ETH_P_IP) {
        if (!parse_udp_ipv4(data + sizeof(struct ethhdr), data_end))
            return XDP_PASS;
        // dport for v4
        __u8 vhl = *(__u8 *)(data + sizeof(struct ethhdr));
        __u8 ihl = (vhl & 0x0F) * 4;
        __u16 dport_be = *(__u16 *)(data + sizeof(struct ethhdr) + ihl + 2);
        dport = bpf_ntohs(dport_be);
    } else if (h_proto == ETH_P_IPV6) {
        is_v6 = 1;
        if (!parse_udp_ipv6(data + sizeof(struct ethhdr), data_end, &dport))
            return XDP_PASS;
    } else {
        return XDP_PASS;
    }

    // Port whitelist
    if (flags & 0x1) {
        __u8 *ok = bpf_map_lookup_elem(&udp_allowed_ports, &dport);
        if (!ok) return XDP_PASS;
    }

    // Hot destination filter
    if (flags & 0x2) {
        if (!is_v6) {
            if (data + sizeof(struct ethhdr) + 16 > data_end) return XDP_PASS;
            __u32 dst = *(__u32 *)(data + sizeof(struct ethhdr) + 16);
            __u8 *hot = bpf_map_lookup_elem(&udp_hot_dst_v4, &dst);
            if (!hot) return XDP_PASS;
        } else {
            if (data + sizeof(struct ethhdr) + offsetof(struct ipv6hdr, daddr) + sizeof(struct in6_addr) > data_end)
                return XDP_PASS;
            struct v6key k6;
            __u64 *p = (__u64 *)(data + sizeof(struct ethhdr) + offsetof(struct ipv6hdr, daddr));
            k6.hi = *p; k6.lo = *(p + 1);
            __u8 *hot6 = bpf_map_lookup_elem(&udp_hot_dst_v6, &k6);
            if (!hot6) return XDP_PASS;
        }
    }

    __u32 q = ctx->rx_queue_index;
    if (q >= 64)
        return XDP_PASS;
    // Check enable flag
    __u32 *en = bpf_map_lookup_elem(&udp_xdp_queues_enable, &q);
    if (!en || *en == 0)
        return XDP_PASS;

    // Redirect to AF_XDP socket bound to this queue
    return bpf_redirect_map(&xsk_udp_map, q, 0);
}

char _license[] SEC("license") = "GPL";


