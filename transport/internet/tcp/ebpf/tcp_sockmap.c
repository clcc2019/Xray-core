// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// 规则：所有资源 pin 到 /sys/fs/bpf/xray/

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65536);
    __type(key, __u64);    // (sid << 1) | dir
    __type(value, __u32);  // socket fd
} tcp_sockhash SEC(".maps");

// cookie->(sid,dir) 由用户态填充，sockops 用于写入 sk_storage
struct sock_session {
    __u64 sid;
    __u32 dir; // 0 或 1
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 131072);
    __type(key, __u64);             // socket cookie
    __type(value, struct sock_session);
} tcp_cookie_to_sid SEC(".maps");

// 每socket存储 sid/dir，供 sk_msg 快速获取对端 key
struct sk_meta {
    __u64 sid;
    __u32 dir;
};

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __type(value, struct sk_meta);
} tcp_sk_storage SEC(".maps");

// per-CPU 统计
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} tcp_sock_stats SEC(".maps");

// ringbuf 事件（轻量调试/观测）
struct tcp_sock_event {
    __u64 ts;
    __u32 type;
    __u64 val;
};

enum tcp_sock_evt_type {
    EVT_SOCKOPS_ESTABLISHED = 1,
    EVT_SKMSG_REDIRECT_OK   = 2,
    EVT_SKMSG_REDIRECT_FAIL = 3,
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} tcp_sock_events SEC(".maps");

static __always_inline void stat_inc(__u32 idx) {
    __u32 key = 0;
    __u64 *v = bpf_map_lookup_elem(&tcp_sock_stats, &key);
    if (v) {
        __sync_fetch_and_add(v, 1);
    }
}

static __always_inline void emit_evt(__u32 type, __u64 val) {
    struct tcp_sock_event ev = {
        .ts = bpf_ktime_get_ns(),
        .type = type,
        .val = val,
    };
    bpf_ringbuf_output(&tcp_sock_events, &ev, sizeof(ev), 0);
}

// 在连接建立时把 socket 放入 sockhash，并设置 sk_storage 元数据
SEC("sockops")
int tcp_sockops(struct bpf_sock_ops *ops) {
    if (!ops)
        return 0;

    int op = (int)ops->op;
    if (op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB && op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB)
        return 0;

    __u64 cookie = bpf_get_socket_cookie_ops(ops);
    struct sock_session *sess = bpf_map_lookup_elem(&tcp_cookie_to_sid, &cookie);
    if (!sess)
        return 0;

    // 设置 sk_storage（存在则覆盖）
    __u64 flags = BPF_SK_STORAGE_GET_F_CREATE;
    struct sk_meta *meta = bpf_sk_storage_get(&tcp_sk_storage, ops->sk, &flags, 0);
    if (meta) {
        meta->sid = sess->sid;
        meta->dir = sess->dir;
    }

    __u64 key = (sess->sid << 1) | (sess->dir & 1);
    // 将当前 socket 插入 sockhash
    int ret = bpf_sock_hash_update(&tcp_sockhash, ops, &key, BPF_ANY);
    if (ret == 0) {
        emit_evt(EVT_SOCKOPS_ESTABLISHED, key);
    }
    return 0;
}

// 在发送路径上做基于 sockhash 的重定向，实现内核态搬运
SEC("sk_msg")
int tcp_sockmsg(struct sk_msg_md *msg) {
    if (!msg)
        return SK_PASS;

    struct sk_meta *meta = bpf_sk_storage_get(&tcp_sk_storage, msg->sk, 0, 0);
    if (!meta) {
        return SK_PASS;
    }

    __u64 rev_key = (meta->sid << 1) | ((meta->dir ^ 1) & 1);
    int rc = bpf_msg_redirect_hash(msg, &tcp_sockhash, &rev_key, 0);
    if (rc == SK_PASS) {
        emit_evt(EVT_SKMSG_REDIRECT_OK, rev_key);
        stat_inc(0);
        return SK_PASS;
    }
    emit_evt(EVT_SKMSG_REDIRECT_FAIL, rev_key);
    return SK_PASS;
}

char _license[] SEC("license") = "GPL";

