
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

#define MAX_TARGETS 4096

#define MAX_GLOBAL_BANS 65536

#define MAX_SRC_BANS 262144

struct target_key {
    __u32 dst_ip;
};

struct global_ban_key {
    __u32 prefixlen;
    __u32 src_ip;
};

struct src_ban_key {
    __u32 prefixlen;
    __u32 target_id;
    __u32 src_ip;
};

struct ban_value {
    __u64 expires_at;
    __u64 hits;
    __u32 rule_id;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct global_ban_key);
    __type(value, struct ban_value);
    __uint(max_entries, MAX_GLOBAL_BANS);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} src_ban_global SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct target_key);
    __type(value, __u32);
    __uint(max_entries, MAX_TARGETS);
} target_hosts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct src_ban_key);
    __type(value, struct ban_value);
    __uint(max_entries, MAX_SRC_BANS);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} src_ban SEC(".maps");

enum {
    CNT_DROPPED = 0,
    CNT_PASSED,
    CNT_EXPIRED,
    CNT_NOT_TARGET,
    CNT_MAX,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, CNT_MAX);
} counters SEC(".maps");

static __always_inline void bump(__u32 idx)
{
    __u64 *c = bpf_map_lookup_elem(&counters, &idx);
    if (c)
        (*c)++;
}

static __always_inline int is_expired(struct ban_value *bv)
{
    return bv->expires_at != 0 && bpf_ktime_get_ns() > bv->expires_at;
}

SEC("xdp")
int xdp_filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    struct global_ban_key gk = {
        .prefixlen = 32,
        .src_ip    = ip->saddr,
    };
    struct ban_value *gv = bpf_map_lookup_elem(&src_ban_global, &gk);
    if (gv) {
        if (is_expired(gv)) {
            bump(CNT_EXPIRED);
            return XDP_PASS;
        }
        gv->hits++;
        bump(CNT_DROPPED);
        return XDP_DROP;
    }

    struct target_key tk = { .dst_ip = ip->daddr };
    __u32 *tid = bpf_map_lookup_elem(&target_hosts, &tk);
    if (!tid) {
        bump(CNT_NOT_TARGET);
        return XDP_PASS;
    }

    struct src_ban_key sk = {
        .prefixlen = 64,
        .target_id = *tid,
        .src_ip    = ip->saddr,
    };
    struct ban_value *bv = bpf_map_lookup_elem(&src_ban, &sk);
    if (!bv) {
        bump(CNT_PASSED);
        return XDP_PASS;
    }

    if (is_expired(bv)) {
        bump(CNT_EXPIRED);
        return XDP_PASS;
    }

    bv->hits++;
    bump(CNT_DROPPED);
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
