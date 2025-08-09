// +build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Enable switch (array[0]): 0=off(default), 1=on
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} skl_redirect_enable SEC(".maps");

static __always_inline int skl_enabled() {
    __u32 k = 0; __u32 *v = bpf_map_lookup_elem(&skl_redirect_enable, &k);
    return v && *v != 0;
}

// IPv4 redirect map: key=dst ip (u32), value=redirect port (u16) [host order stored in u16]
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);
    __type(value, __u16);
} route_ip_v4_redirect SEC(".maps");

// IPv6 redirect map: key={hi,lo}, value=port
struct ipv6_key { __u64 hi; __u64 lo; } __attribute__((packed));
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 80000);
    __type(key, struct ipv6_key);
    __type(value, __u16);
} route_ip_v6_redirect SEC(".maps");

// sk_lookup: try redirect to local listening socket on specified port
SEC("sk_lookup")
int sk_lookup_redirect(struct bpf_sk_lookup *ctx) {
    if (!skl_enabled()) return SK_PASS;

    // Only TCP
    if (ctx->protocol != IPPROTO_TCP) return SK_PASS;

    __u16 *pport = 0;
    if (ctx->family == AF_INET) {
        // ctx->local_ip4 is in network byte order
        __u32 dip = ctx->local_ip4; // dest ip
        pport = bpf_map_lookup_elem(&route_ip_v4_redirect, &dip);
    } else if (ctx->family == AF_INET6) {
        struct ipv6_key k = {0};
        __builtin_memcpy(&k.hi, ctx->local_ip6, 8);
        __builtin_memcpy(&k.lo, ((char*)ctx->local_ip6)+8, 8);
        pport = bpf_map_lookup_elem(&route_ip_v6_redirect, &k);
    }
    if (!pport) return SK_PASS;

    __u16 rport = *pport;
    if (rport == 0) return SK_PASS;

    // Lookup a local listening socket on 127.0.0.1:rport (for IPv4) or ::1 for IPv6
    struct bpf_sock *sk = 0;
    if (ctx->family == AF_INET) {
        __u32 lip = bpf_htonl(0x7f000001); // 127.0.0.1
        sk = bpf_sk_lookup_tcp(ctx, &lip, 0, &ctx->local_ip4, bpf_htons(rport), 0);
    } else if (ctx->family == AF_INET6) {
        __u8 lip6[16] = {0}; lip6[15] = 1; // ::1
        sk = bpf_sk_lookup_tcp(ctx, lip6, 0, ctx->local_ip6, bpf_htons(rport), 0);
    }
    if (!sk) return SK_PASS;
    bpf_sk_assign(ctx, sk, 0);
    bpf_sk_release(sk);
    return SK_PASS;
}

char _license[] SEC("license") = "GPL";

// +build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Redirect table: match dest port -> new local port (host order)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);   // destination port (host order)
    __type(value, __u16); // redirect port (host order)
} skl_redirect_table SEC(".maps");

SEC("sk_lookup")
int skl_redirect_prog(struct bpf_sk_lookup *ctx) {
    // Only handle IPv4 TCP for now
    if (ctx->protocol != IPPROTO_TCP)
        return SK_PASS;
    if (ctx->family != AF_INET)
        return SK_PASS;

    __u16 dport_host = bpf_ntohs(ctx->local_port);

    // Exact port match
    __u16 *redir = bpf_map_lookup_elem(&skl_redirect_table, &dport_host);

    // Fallback: 0 means match any port
    __u16 zero = 0;
    if (!redir) {
        redir = bpf_map_lookup_elem(&skl_redirect_table, &zero);
    }

    if (redir && *redir != 0 && *redir != dport_host) {
        ctx->local_port = bpf_htons(*redir);
        // Kernel will re-run lookup with updated local_port
        return SK_PASS;
    }

    return SK_PASS;
}

char _license[] SEC("license") = "GPL";
