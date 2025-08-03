// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// HTTP/3流状态
struct http3_stream {
    __u64 stream_id;              // 流ID
    __u32 local_ip;               // 本地IP
    __u32 remote_ip;              // 远程IP
    __u16 local_port;             // 本地端口
    __u16 remote_port;            // 远程端口
    __u8 state;                   // 流状态: 0=idle, 1=open, 2=closed
    __u8 frame_type;              // 帧类型
    __u32 payload_length;         // 负载长度
    __u64 last_activity;          // 最后活动时间
    __u32 bytes_sent;             // 发送字节数
    __u32 bytes_received;         // 接收字节数
} __attribute__((packed));

// HTTP/3统计
struct http3_stats {
    __u64 total_frames;
    __u64 headers_frames;
    __u64 data_frames;
    __u64 settings_frames;
    __u64 goaway_frames;
    __u64 streams;
    __u64 connections;
};

// eBPF Maps
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 5000);
    __type(key, __u64);
    __type(value, struct http3_stream);
} http3_streams SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct http3_stats);
} http3_statistics SEC(".maps");

// 更新统计
static __always_inline void update_http3_stats(__u32 stat_type) {
    __u32 key = 0;
    struct http3_stats *stats = bpf_map_lookup_elem(&http3_statistics, &key);
    if (stats) {
        switch (stat_type) {
            case 0: stats->total_frames++; break;
            case 1: stats->headers_frames++; break;
            case 2: stats->data_frames++; break;
            case 3: stats->settings_frames++; break;
            case 4: stats->goaway_frames++; break;
            case 5: stats->streams++; break;
            case 6: stats->connections++; break;
        }
    }
}

// HTTP/3帧类型检测
static __always_inline __u8 detect_http3_frame_type(void *data, void *data_end) {
    if (data + 8 > data_end) return 0;
    
    __u8 frame_type;
    if (bpf_xdp_load_bytes(data, 0, &frame_type, sizeof(frame_type)) < 0)
        return 0;
    
    return frame_type;
}

// HTTP/3流ID提取
static __always_inline __u64 extract_stream_id(void *data, void *data_end) {
    if (data + 8 > data_end) return 0;
    
    __u64 stream_id;
    if (bpf_xdp_load_bytes(data, 1, &stream_id, sizeof(stream_id)) < 0)
        return 0;
    
    return stream_id & 0x3FFFFFFFFFFFFFFF; // 移除最高两位
}

// HTTP/3 XDP程序
SEC("xdp")
int http3_optimizer_xdp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 基本验证
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + 8 > data_end)
        return XDP_PASS;
    
    // 安全地访问以太网头部
    __u16 eth_proto;
    if (bpf_xdp_load_bytes(ctx, 12, &eth_proto, sizeof(eth_proto)) < 0)
        return XDP_PASS;
    if (eth_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    // 安全地访问IP协议字段
    __u8 ip_proto;
    if (bpf_xdp_load_bytes(ctx, 14 + 9, &ip_proto, sizeof(ip_proto)) < 0)
        return XDP_PASS;
    if (ip_proto != IPPROTO_UDP)
        return XDP_PASS;
    
    // 安全地访问IP和UDP头部字段
    __u32 saddr, daddr;
    __u16 sport, dport;
    
    if (bpf_xdp_load_bytes(ctx, 14 + 12, &saddr, sizeof(saddr)) < 0 ||
        bpf_xdp_load_bytes(ctx, 14 + 16, &daddr, sizeof(daddr)) < 0 ||
        bpf_xdp_load_bytes(ctx, 14 + 20 + 0, &sport, sizeof(sport)) < 0 ||
        bpf_xdp_load_bytes(ctx, 14 + 20 + 2, &dport, sizeof(dport)) < 0) {
        return XDP_PASS;
    }
    
    // 检查HTTP/3端口 (443, 80等)
    __u16 udp_sport = bpf_ntohs(sport);
    __u16 udp_dport = bpf_ntohs(dport);
    
    if (udp_dport != 443 && udp_dport != 80 && 
        udp_sport != 443 && udp_sport != 80) {
        return XDP_PASS;
    }
    
    update_http3_stats(0); // total_frames
    
    // 访问HTTP/3负载
    void *http3_payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    
    // 检测HTTP/3帧类型
    __u8 frame_type = detect_http3_frame_type(http3_payload, data_end);
    __u64 stream_id = extract_stream_id(http3_payload, data_end);
    
    // 更新帧类型统计
    switch (frame_type) {
        case 0x01: // HEADERS
            update_http3_stats(1);
            break;
        case 0x00: // DATA
            update_http3_stats(2);
            break;
        case 0x04: // SETTINGS
            update_http3_stats(3);
            break;
        case 0x07: // GOAWAY
            update_http3_stats(4);
            break;
    }
    
    // 处理流
    if (stream_id > 0) {
        __u64 conn_id = ((__u64)saddr << 32) | ((__u64)daddr) | ((__u64)udp_sport << 16) | udp_dport;
        __u64 stream_key = (conn_id << 32) | (stream_id & 0xFFFFFFFF);
        
        struct http3_stream *stream = bpf_map_lookup_elem(&http3_streams, &stream_key);
        if (!stream) {
            struct http3_stream new_stream = {0};
            new_stream.stream_id = stream_id;
            new_stream.local_ip = saddr;
            new_stream.remote_ip = daddr;
            new_stream.local_port = udp_sport;
            new_stream.remote_port = udp_dport;
            new_stream.state = 1; // open
            new_stream.frame_type = frame_type;
            new_stream.last_activity = bpf_ktime_get_ns() / 1000;
            
            bpf_map_update_elem(&http3_streams, &stream_key, &new_stream, BPF_ANY);
            update_http3_stats(5); // streams
        } else {
            stream->frame_type = frame_type;
            stream->last_activity = bpf_ktime_get_ns() / 1000;
            
            if (frame_type == 0x07) { // GOAWAY
                stream->state = 2; // closed
            }
        }
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL"; 