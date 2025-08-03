// +build ignore

typedef unsigned int __u32;

#define XDP_PASS 2
#define SEC(name) __attribute__((section(name), used))

struct xdp_md {
    __u32 data;
    __u32 data_end;
};

SEC("xdp")
int loadbalancer_xdp(struct xdp_md *ctx) {
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";