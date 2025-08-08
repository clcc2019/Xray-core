// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Define TCP flag bits if not provided by headers
#ifndef TH_FIN
#define TH_FIN 0x01
#endif
#ifndef TH_SYN
#define TH_SYN 0x02
#endif
#ifndef TH_RST
#define TH_RST 0x04
#endif
#ifndef TH_PUSH
#define TH_PUSH 0x08
#endif
#ifndef TH_URG
#define TH_URG 0x20
#endif
#ifndef TH_ACK
#define TH_ACK 0x10
#endif

struct sd_config {
    __u8 drop_null;
    __u8 drop_xmas;
    __u8 drop_syn_fin;
    __u8 drop_syn_rst;
    __u32 syn_rate_limit;     // per-src SYN without ACK per second threshold
    __u32 tls_bad_limit;      // per-src bad TLS ClientHello per second threshold
    __u32 block_ttl_sec;      // seconds to block when threshold exceeded
} __attribute__((packed));

// Ports of Xray listeners (key: u16 dest port in host byte order, value: u8 dummy)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, __u8);
} xray_listen_ports SEC(".maps");

// Global config
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct sd_config);
} sockdf_config SEC(".maps");

// Per-source tracking
struct syn_tls_state {
    __u32 last_sec_syn;
    __u32 syn_count;
    __u32 last_sec_tls;
    __u32 tls_bad_count;
    __u64 block_until_sec;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);              // IPv4 src
    __type(value, struct syn_tls_state);
} src_state SEC(".maps");

static __always_inline int match_tcp_invalid(__u8 flags, const struct sd_config *cfg) {
    // NULL scan: no flags set
    if (cfg && cfg->drop_null && flags == 0) return 1;
    // XMAS scan: FIN|PSH|URG all set
    if (cfg && cfg->drop_xmas && (flags & (TH_FIN|TH_PUSH|TH_URG)) == (TH_FIN|TH_PUSH|TH_URG)) return 1;
    // SYN+FIN
    if (cfg && cfg->drop_syn_fin && (flags & (TH_SYN|TH_FIN)) == (TH_SYN|TH_FIN)) return 1;
    // SYN+RST
    if (cfg && cfg->drop_syn_rst && (flags & (TH_SYN|TH_RST)) == (TH_SYN|TH_RST)) return 1;
    return 0;
}

SEC("cgroup_skb/ingress")
int socket_direct_filter(struct __sk_buff *skb) {
    __u32 key = 0;
    struct sd_config *cfg = bpf_map_lookup_elem(&sockdf_config, &key);

    // Parse IPv4 fast path
    __u8 ipverihl;
    if (bpf_skb_load_bytes(skb, 0, &ipverihl, 1) < 0)
        return 1; // SK_PASS
    __u8 version = ipverihl >> 4;
    if (version != 4) return 1;

    __u32 saddr;
    if (bpf_skb_load_bytes(skb, 12, &saddr, 4) < 0) return 1;
    // Check blocklist
    struct syn_tls_state *st = bpf_map_lookup_elem(&src_state, &saddr);
    __u64 now_sec = bpf_ktime_get_ns() / 1000000000ULL;
    if (st && st->block_until_sec && now_sec < st->block_until_sec) {
        return 0; // SK_DROP
    }

    __u8 proto;
    if (bpf_skb_load_bytes(skb, 9, &proto, 1) < 0) return 1;
    if (proto != IPPROTO_TCP) return 1;

    __u8 ihl = (ipverihl & 0x0F) * 4;
    __u16 dport_be;
    if (bpf_skb_load_bytes(skb, ihl + 2, &dport_be, 2) < 0) return 1;
    __u16 dport = bpf_ntohs(dport_be);

    // Only act on ports we care about
    __u8 *present = bpf_map_lookup_elem(&xray_listen_ports, &dport);
    if (!present) return 1;

    __u8 flags;
    if (bpf_skb_load_bytes(skb, ihl + 13, &flags, 1) < 0) return 1;

    if (match_tcp_invalid(flags, cfg)) {
        return 0; // SK_DROP
    }

    // SYN flood mitigation (SYN without ACK)
    if ((flags & TH_SYN) && !(flags & TH_ACK)) {
        if (!st) {
            struct syn_tls_state init = {0};
            bpf_map_update_elem(&src_state, &saddr, &init, BPF_NOEXIST);
            st = bpf_map_lookup_elem(&src_state, &saddr);
        }
        if (st && cfg && cfg->syn_rate_limit) {
            if (st->last_sec_syn != (__u32)now_sec) {
                st->last_sec_syn = (__u32)now_sec;
                st->syn_count = 0;
            }
            st->syn_count++;
            if (st->syn_count > cfg->syn_rate_limit) {
                st->block_until_sec = now_sec + cfg->block_ttl_sec;
                return 0; // drop
            }
        }
    }

    // Basic TLS ClientHello sanity for TCP/443 first payload
    if (dport == 443) {
        // TCP data offset
        __u8 doff_byte;
        if (bpf_skb_load_bytes(skb, ihl + 12, &doff_byte, 1) == 0) {
            __u8 doff = (doff_byte >> 4) * 4;
            __u8 rec_type;
            // TLS record header at payload offset
            if (bpf_skb_load_bytes(skb, ihl + doff + 0, &rec_type, 1) == 0) {
                if (rec_type != 0x16) { // not Handshake
                    // count bad TLS
                    if (!st) {
                        struct syn_tls_state init = {0};
                        bpf_map_update_elem(&src_state, &saddr, &init, BPF_NOEXIST);
                        st = bpf_map_lookup_elem(&src_state, &saddr);
                    }
                    if (st && cfg && cfg->tls_bad_limit) {
                        if (st->last_sec_tls != (__u32)now_sec) {
                            st->last_sec_tls = (__u32)now_sec;
                            st->tls_bad_count = 0;
                        }
                        st->tls_bad_count++;
                        if (st->tls_bad_count > cfg->tls_bad_limit) {
                            st->block_until_sec = now_sec + cfg->block_ttl_sec;
                            return 0; // drop
                        }
                    }
                } else {
                    __u8 ver[2];
                    if (bpf_skb_load_bytes(skb, ihl + doff + 1, &ver, 2) == 0) {
                        // allow 0x0301..0x0304; else count as bad
                        if (!((ver[0] == 0x03) && (ver[1] >= 0x01 && ver[1] <= 0x04))) {
                            if (!st) {
                                struct syn_tls_state init = {0};
                                bpf_map_update_elem(&src_state, &saddr, &init, BPF_NOEXIST);
                                st = bpf_map_lookup_elem(&src_state, &saddr);
                            }
                            if (st && cfg && cfg->tls_bad_limit) {
                                if (st->last_sec_tls != (__u32)now_sec) {
                                    st->last_sec_tls = (__u32)now_sec;
                                    st->tls_bad_count = 0;
                                }
                                st->tls_bad_count++;
                                if (st->tls_bad_count > cfg->tls_bad_limit) {
                                    st->block_until_sec = now_sec + cfg->block_ttl_sec;
                                    return 0;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return 1; // SK_PASS
}

char _license[] SEC("license") = "GPL";


