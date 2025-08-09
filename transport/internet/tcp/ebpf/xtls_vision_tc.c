// +build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct xtls_vision_inbound { __u32 client_ip; __u32 server_ip; __u16 client_port; __u16 server_port; __u8 state; __u8 reality_verified; __u8 tls_version; __u8 vision_enabled; __u64 handshake_time; __u64 bytes_received; __u64 bytes_sent; __u32 splice_count; __u32 vision_packets; __u64 last_activity; __u32 dest_ip; __u16 dest_port; __u8 user_uuid[16]; __u8 command; __u16 content_len; __u16 padding_len; __u8 parsing_state; } __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, __u64);
    __type(value, struct xtls_vision_inbound);
} xtls_inbound_connections SEC(".maps");

static __always_inline __u64 get_current_time() { return bpf_ktime_get_ns() / 1000000000ULL; }
static __always_inline __u64 get_connection_id(__u32 saddr, __u16 sport, __u32 daddr, __u16 dport) { return ((__u64)saddr << 32) | ((__u64)daddr) | ((__u64)sport << 48) | ((__u64)dport << 32); }

SEC("tc")
int xtls_vision_inbound_accelerator_tc(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data; void *data_end = (void *)(long)skb->data_end;
    if (data + sizeof(struct ethhdr) > data_end) return TC_ACT_OK;
    struct ethhdr *eth = data;
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) return TC_ACT_OK;
        struct iphdr *ip = data + sizeof(struct ethhdr);
        if (ip->protocol != IPPROTO_TCP) return TC_ACT_OK;
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end) return TC_ACT_OK;
        struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if (tcp->dest != bpf_htons(443)) return TC_ACT_OK;
        __u64 conn_id = get_connection_id(ip->saddr, tcp->source, ip->daddr, tcp->dest);
        struct xtls_vision_inbound *conn = bpf_map_lookup_elem(&xtls_inbound_connections, &conn_id);
        if (tcp->syn && !tcp->ack) {
            if (!conn) {
                struct xtls_vision_inbound new_conn = {0};
                new_conn.client_ip = ip->saddr; new_conn.server_ip = ip->daddr; new_conn.client_port = tcp->source; new_conn.server_port = tcp->dest; new_conn.state = 0; new_conn.last_activity = get_current_time();
                bpf_map_update_elem(&xtls_inbound_connections, &conn_id, &new_conn, BPF_ANY);
            }
            return TC_ACT_OK;
        }
        if (conn) { conn->last_activity = get_current_time(); }
        return TC_ACT_OK;
    }
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";


