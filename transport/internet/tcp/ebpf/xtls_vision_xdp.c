// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct xtls_vision_inbound {
    __u32 client_ip;
    __u32 server_ip;
    __u16 client_port;
    __u16 server_port;
    __u8 state;
    __u8 reality_verified;
    __u8 tls_version;
    __u8 vision_enabled;
    __u64 handshake_time;
    __u64 bytes_received;
    __u64 bytes_sent;
    __u32 splice_count;
    __u32 vision_packets;
    __u64 last_activity;
    __u32 dest_ip;
    __u16 dest_port;
    __u8 user_uuid[16];
    __u8 command;
    __u16 content_len;
    __u16 padding_len;
    __u8 parsing_state;
} __attribute__((packed));

struct xtls_vision_stats {
    __u64 total_inbound_connections;
    __u64 reality_connections;
    __u64 vision_connections;
    __u64 handshake_count;
    __u64 splice_count;
    __u64 vision_packets;
    __u64 total_bytes_received;
    __u64 total_bytes_sent;
    __u64 avg_handshake_time;
    __u64 zero_copy_packets;
    __u64 padding_optimized;
    __u64 command_parsed;
    __u64 tc_total_packets;
    __u64 tc_accelerated_packets;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, __u64);
    __type(value, struct xtls_vision_inbound);
} xtls_inbound_connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xtls_vision_stats);
} xtls_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);
    __type(value, __u64);
} hot_connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, __u64);
    __type(value, __u32);
} connection_reuse_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, __u32);
    __type(value, __u64);
} security_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u8);
} xtls_direct_copy_hint SEC(".maps");

struct xtls_event { __u32 type; __u64 conn_id; __u64 ts_ns; };
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} xtls_vision_events SEC(".maps");

static __always_inline __u64 get_current_time() {
    return bpf_ktime_get_ns() / 1000000000ULL;
}

static __always_inline __u64 get_connection_id(__u32 saddr, __u16 sport, __u32 daddr, __u16 dport) {
    return ((__u64)saddr << 32) | ((__u64)daddr) | ((__u64)sport << 48) | ((__u64)dport << 32);
}

static __always_inline void update_stats(__u32 stat_type) {
    __u32 key = 0;
    struct xtls_vision_stats *stats = bpf_map_lookup_elem(&xtls_stats, &key);
    if (stats) {
        if (stat_type == 0) stats->total_inbound_connections++;
        else if (stat_type == 5) stats->vision_packets++;
    }
}

SEC("xdp")
int xtls_vision_inbound_accelerator_xdp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;
    struct ethhdr *eth = data;
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(struct ethhdr);
        if ((void *)ip + sizeof(*ip) > data_end) return XDP_PASS;
        if (ip->protocol != IPPROTO_TCP) return XDP_PASS;
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) > data_end) return XDP_PASS;
        if (tcp->dest != bpf_htons(443)) return XDP_PASS;

        __u64 conn_id = get_connection_id(ip->saddr, tcp->source, ip->daddr, tcp->dest);
        struct xtls_vision_inbound *conn = bpf_map_lookup_elem(&xtls_inbound_connections, &conn_id);
        if (!conn && tcp->syn && !tcp->ack) {
            struct xtls_vision_inbound new_conn = {0};
            new_conn.client_ip = ip->saddr;
            new_conn.server_ip = ip->daddr;
            new_conn.client_port = tcp->source;
            new_conn.server_port = tcp->dest;
            new_conn.last_activity = get_current_time();
            bpf_map_update_elem(&xtls_inbound_connections, &conn_id, &new_conn, BPF_ANY);
            update_stats(0);
        }
        update_stats(5);
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";


