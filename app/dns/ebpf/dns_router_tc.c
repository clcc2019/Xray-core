// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef __maybe_unused
#define __maybe_unused __attribute__((unused))
#endif

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
} __attribute__((packed));

struct flow6_key {
    __u64 src_hi;
    __u64 src_lo;
    __u64 dst_hi;
    __u64 dst_lo;
    __u16 src_port;
    __u16 dst_port;
} __attribute__((packed));

// domain hash -> route mark
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 50000);
    __type(key, __u32);
    __type(value, __u32);
} dns_route_map SEC(".maps");

// anomalies map: flow_key -> flags
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 20000);
    __type(key, struct flow_key);
    __type(value, __u32);
} dns_anomalies SEC(".maps");

// anomalies for IPv6
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 20000);
    __type(key, struct flow6_key);
    __type(value, __u32);
} dns_anomalies6 SEC(".maps");

// default protocol marks: index 1 => DoT, 2 => DoH
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} dns_proto_marks SEC(".maps");

// DoH endpoints allowlist: v4 key ip(32)<<16 | port(16)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);
    __type(value, __u32); // mark
} doh_endpoints_v4 SEC(".maps");

// DoH endpoints allowlist: v6 key {ip_hi, ip_lo, port}
struct doh_v6_key { __u64 hi; __u64 lo; __u16 port; } __attribute__((packed));
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct doh_v6_key);
    __type(value, __u32); // mark
} doh_endpoints_v6 SEC(".maps");

// global enable switch (default 0 = disabled)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} dns_router_enable SEC(".maps");

static __always_inline int dns_router_is_enabled() {
    __u32 k = 0; __u32 *v = bpf_map_lookup_elem(&dns_router_enable, &k);
    return v && *v != 0;
}

// DNS header
struct dns_header {
    __u16 id;
    __u16 flags;
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 arcount;
};

// anomaly flags
#define DNS_ANOM_ANY_QTYPE     (1u << 0)
#define DNS_ANOM_MULTI_QD      (1u << 1)
#define DNS_ANOM_LABEL_TOO_MANY (1u << 2)
#define DNS_ANOM_QNAME_TOO_LONG (1u << 3)
#define DNS_ANOM_OPCODE_NONZERO (1u << 4)

static __always_inline char lower_char(char c) {
    if (c >= 'A' && c <= 'Z') return c + 32;
    return c;
}

// FNV-1a 32-bit
static __always_inline __u32 fnv1a32_step(__u32 hash, unsigned char v) {
    const __u32 FNV_PRIME = 16777619U;
    hash ^= v;
    hash *= FNV_PRIME;
    return hash;
}

// parse QNAME only and compute hash and qtype; limit loops
static __always_inline int parse_qname_hash_qtype_tc(void *data, void *data_end, __u32 l4_off, __u32 *hash_out, __u16 *qtype_out, __u32 *flags_out) {
    struct dns_header *dh = (void*)(data + l4_off);
    if ((void*)(dh + 1) > data_end) return -1;
    __u16 flags = bpf_ntohs(dh->flags);
    if ((flags & 0x8000) != 0) return -1; // response
    if (((flags >> 11) & 0xF) != 0) { // opcode non-zero
        *flags_out |= DNS_ANOM_OPCODE_NONZERO;
    }
    __u16 qdcount = bpf_ntohs(dh->qdcount);
    if (qdcount != 1) {
        *flags_out |= DNS_ANOM_MULTI_QD;
    }
    __u32 pos = l4_off + sizeof(struct dns_header);
    __u32 hash = 2166136261U;
    __u32 labels = 0;
    __u32 total_len = 0;
    #pragma clang loop unroll(disable)
    for (int lbl = 0; lbl < 10; lbl++) {
        if (pos + 1 > (__u32)(data_end - data)) return -1;
        unsigned char labellen = 0;
        if ((void*)(data + pos + 1) > data_end) return -1;
        labellen = *(unsigned char*)(data + pos);
        pos += 1;
        if (labellen == 0) {
            // qtype is next 2 bytes
            if (pos + 2 > (__u32)(data_end - data)) return -1;
            __u16 qtype = *(__u16*)(data + pos);
            qtype = bpf_ntohs(qtype);
            *qtype_out = qtype;
            *hash_out = hash;
            if (qtype == 255) {
                *flags_out |= DNS_ANOM_ANY_QTYPE;
            }
            if (labels >= 10) {
                *flags_out |= DNS_ANOM_LABEL_TOO_MANY;
            }
            if (total_len > 253) {
                *flags_out |= DNS_ANOM_QNAME_TOO_LONG;
            }
            return 0;
        }
        labels++;
        total_len += labellen + 1;
        if (pos + labellen > (__u32)(data_end - data)) return -1;
        #pragma clang loop unroll(disable)
        for (int i = 0; i < 32; i++) {
            if (i >= labellen) break;
            unsigned char ch = *(__u8*)(data + pos + i);
            char lc = lower_char((char)ch);
            hash = fnv1a32_step(hash, (unsigned char)lc);
        }
        pos += labellen;
    }
    return -1;
}

SEC("classifier")
int dns_router_tc(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // L2
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end) return TC_ACT_OK;

    __u16 proto = eth->h_proto;
    if (proto == bpf_htons(ETH_P_IP)) {
        // IPv4
        struct iphdr *ip = (void*)(eth + 1);
        if ((void*)(ip + 1) > data_end) return TC_ACT_OK;

        __u32 ihl = ip->ihl * 4;

        if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void*)((void*)ip + ihl);
            if ((void*)(udp + 1) > data_end) return TC_ACT_OK;

            if (udp->dest != bpf_htons(53)) return TC_ACT_OK; // DNS/UDP

            __u32 domain_hash = 0; __u16 qtype = 0; __u32 aflags = 0;
            if (parse_qname_hash_qtype_tc(data, data_end, ihl + 8, &domain_hash, &qtype, &aflags) < 0) return TC_ACT_OK;

            if (aflags) {
                struct flow_key k = { .src_ip = ip->saddr, .dst_ip = ip->daddr, .src_port = udp->source, .dst_port = udp->dest };
                __u32 *exist = bpf_map_lookup_elem(&dns_anomalies, &k);
                if (exist) { *exist |= aflags; } else { bpf_map_update_elem(&dns_anomalies, &k, &aflags, BPF_ANY); }
            }

            if (dns_router_is_enabled()) {
                __u32 *mark = bpf_map_lookup_elem(&dns_route_map, &domain_hash);
                if (mark) { skb->mark = *mark; }
            }
            return TC_ACT_OK;
        } else if (ip->protocol == IPPROTO_TCP) {
            // DoT: TCP/853
            struct tcphdr { __u16 source, dest; } *tcp;
            tcp = (void*)((void*)ip + ihl);
            if ((void*)(tcp + 1) > data_end) return TC_ACT_OK;
            if (tcp->dest == bpf_htons(853) && dns_router_is_enabled()) {
                __u32 idx = 1, *dot_mark = bpf_map_lookup_elem(&dns_proto_marks, &idx);
                if (dot_mark) { skb->mark = *dot_mark; }
                return TC_ACT_OK;
            }
            // DoH allowlist on 443
            if (tcp->dest == bpf_htons(443) && dns_router_is_enabled()) {
                __u64 key = ((__u64)ip->daddr << 16) | 443;
                __u32 *m = bpf_map_lookup_elem(&doh_endpoints_v4, &key);
                if (m) { skb->mark = *m; }
            }
            return TC_ACT_OK;
        }
        return TC_ACT_OK;
    } else if (proto == bpf_htons(ETH_P_IPV6)) {
        // IPv6 (no extensions handled)
        struct ipv6hdr *ip6 = (void*)(eth + 1);
        if ((void*)(ip6 + 1) > data_end) return TC_ACT_OK;
        __u8 nexthdr = ip6->nexthdr;
        __u32 off = sizeof(struct ipv6hdr);
        if (nexthdr == IPPROTO_UDP) {
            struct udphdr *udp = (void*)((void*)ip6 + off);
            if ((void*)(udp + 1) > data_end) return TC_ACT_OK;
            if (udp->dest != bpf_htons(53)) return TC_ACT_OK;
            __u32 domain_hash = 0; __u16 qtype = 0; __u32 aflags = 0;
            if (parse_qname_hash_qtype_tc(data, data_end, off + 8, &domain_hash, &qtype, &aflags) < 0) return TC_ACT_OK;
            if (aflags) {
                struct flow6_key k6 = {0};
                __builtin_memcpy(&k6.src_hi, &ip6->saddr.s6_addr[0], 8);
                __builtin_memcpy(&k6.src_lo, &ip6->saddr.s6_addr[8], 8);
                __builtin_memcpy(&k6.dst_hi, &ip6->daddr.s6_addr[0], 8);
                __builtin_memcpy(&k6.dst_lo, &ip6->daddr.s6_addr[8], 8);
                k6.src_port = udp->source; k6.dst_port = udp->dest;
                __u32 *exist = bpf_map_lookup_elem(&dns_anomalies6, &k6);
                if (exist) { *exist |= aflags; } else { bpf_map_update_elem(&dns_anomalies6, &k6, &aflags, BPF_ANY); }
            }
            if (dns_router_is_enabled()) {
                __u32 *mark = bpf_map_lookup_elem(&dns_route_map, &domain_hash);
                if (mark) { skb->mark = *mark; }
            }
            return TC_ACT_OK;
        } else if (nexthdr == IPPROTO_TCP) {
            struct tcphdr6 { __u16 source, dest; } *tcp;
            tcp = (void*)((void*)ip6 + off);
            if ((void*)(tcp + 1) > data_end) return TC_ACT_OK;
            if (tcp->dest == bpf_htons(853) && dns_router_is_enabled()) {
                __u32 idx = 1, *dot_mark = bpf_map_lookup_elem(&dns_proto_marks, &idx);
                if (dot_mark) { skb->mark = *dot_mark; }
                return TC_ACT_OK;
            }
            if (tcp->dest == bpf_htons(443) && dns_router_is_enabled()) {
                struct doh_v6_key k = {0};
                __builtin_memcpy(&k.hi, &ip6->daddr.s6_addr[0], 8);
                __builtin_memcpy(&k.lo, &ip6->daddr.s6_addr[8], 8);
                k.port = bpf_htons(443);
                __u32 *m = bpf_map_lookup_elem(&doh_endpoints_v6, &k);
                if (m) { skb->mark = *m; }
            }
            return TC_ACT_OK;
        }
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";


