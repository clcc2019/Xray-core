// +build ignore

#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Map: Xray 监听端口集合（与 socket_direct_cgroup.c 一致）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, __u8);
} xray_listen_ports SEC(".maps");

// 可选反馈：按端口(v4/v6区分)的 bias 值（由用户态/其他 eBPF 写入），用于扰动选择
// key 布局: 高16位端口，bit0 表示 is_v6，其余位保留
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);
    __type(key, __u32);
    __type(value, __u32);
} reuseport_feedback SEC(".maps");

static __always_inline int parse_dport_ipv4(void *data, void *data_end, __u16 *out_dport)
{
    // data assumed to start at IPv4 header in sk_reuseport_md
    if (data + 1 > data_end)
        return 0;
    __u8 vhl = *(__u8 *)data;
    __u8 version = vhl >> 4;
    if (version != 4)
        return 0;
    // Protocol at offset 9
    if (data + 10 > data_end)
        return 0;
    __u8 proto = *(__u8 *)(data + 9);
    if (proto != IPPROTO_TCP)
        return 0;
    __u8 ihl = (vhl & 0x0F) * 4;
    if (ihl < sizeof(struct iphdr))
        return 0;
    if (data + ihl + 4 > data_end) // need dst port at offset 2 of TCP header
        return 0;
    __u16 dport_be = *(__u16 *)(data + ihl + 2);
    *out_dport = bpf_ntohs(dport_be);
    return 1;
}

static __always_inline int parse_dport_ipv6(void *data, void *data_end, __u16 *out_dport)
{
    // IPv6 fixed header 40 bytes
    if (data + sizeof(struct ipv6hdr) > data_end)
        return 0;
    struct ipv6hdr *ip6 = (struct ipv6hdr *)data;
    if (ip6->version != 6)
        return 0;

    __u8 nexthdr = ip6->nexthdr;
    __u16 off = sizeof(struct ipv6hdr);

    // Walk a few extension headers (bounded loop for verifier)
    #pragma clang loop unroll(disable)
    for (int i = 0; i < 3; i++) {
        if (nexthdr == IPPROTO_TCP) {
            break;
        }
        // Known extension headers: hop-by-hop(0), routing(43), fragment(44), dst(60), auth(51)
        if (nexthdr == 0 || nexthdr == 43 || nexthdr == 60 || nexthdr == 51) {
            // ext header has: next header (1B) + hdrlen (1B, unit of 8 bytes, excluding first 8 bytes)
            if (data + off + 2 > data_end)
                return 0;
            __u8 nh = *(__u8 *)(data + off);
            __u8 hdrlen = *(__u8 *)(data + off + 1);
            __u16 extlen = (hdrlen + 1) * 8;
            if (data + off + extlen > data_end)
                return 0;
            nexthdr = nh;
            off += extlen;
            continue;
        } else if (nexthdr == 44) { // fragment has fixed 8 bytes after base
            if (data + off + 8 > data_end)
                return 0;
            __u8 nh = *(__u8 *)(data + off);
            nexthdr = nh;
            off += 8;
            continue;
        } else {
            // Unknown next header, bail out
            return 0;
        }
    }

    if (nexthdr != IPPROTO_TCP)
        return 0;
    if (data + off + 4 > data_end)
        return 0;
    __u16 dport_be = *(__u16 *)(data + off + 2);
    *out_dport = bpf_ntohs(dport_be);
    return 1;
}

SEC("sk_reuseport")
int xray_reuseport_selector(struct sk_reuseport_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u16 dport = 0;
    // 优先尝试 IPv4，再尝试 IPv6
    if (!parse_dport_ipv4(data, data_end, &dport)) {
        if (!parse_dport_ipv6(data, data_end, &dport)) {
            // 非 IPv4/IPv6 TCP，保持内核默认
            return SK_PASS;
        }
    }
    // 仅对 Xray 监听端口生效
    __u8 *present = bpf_map_lookup_elem(&xray_listen_ports, &dport);
    if (!present) {
        return SK_PASS;
    }

    // 简单自适应：混入 CPU ID 与随机数，使多队列/多监听器更均衡
    __u32 cpu = bpf_get_smp_processor_id();
    __u32 rnd = bpf_get_prandom_u32();
    ctx->hash ^= cpu * 0x9e3779b9u;
    ctx->hash ^= rnd;

    // eBPF 反馈：若存在端口级 bias，则再扰动一次（v4 key）
    __u32 k = ((__u32)dport << 16) | 0u;
    __u32 *bias = bpf_map_lookup_elem(&reuseport_feedback, &k);
    if (bias) {
        ctx->hash ^= *bias;
    }

    // 可扩展：根据 eBPF 反馈或队列压力调整 ctx->hash（预留占位）
    // TODO: 结合连接热度/直拷提示进行偏置

    return SK_PASS;
}

char _license[] SEC("license") = "GPL";


