#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct bpf_iter__tcp {
    struct bpf_iter_meta *meta;
    struct sock_common *sk_common;
    __u32 uid __attribute__((aligned(8)));
} __attribute__((preserve_access_index));
struct possible_net___stats { struct net *net; } __attribute__((preserve_access_index));
struct sock_common___stats { struct possible_net___stats skc_net; } __attribute__((preserve_access_index));
struct sock___stats { struct sock_common___stats __sk_common; } __attribute__((preserve_access_index));

struct tcp_sample {
    __u64 inode;
    __u32 netns, family;
    __u8 local[16], remote[16];
    __u16 local_port, remote_port;
    __u32 rtt_us, rttvar_us, cwnd_segments, retransmissions, reserved;
};
_Static_assert(sizeof(struct tcp_sample) == 72, "TCP sample ABI");

SEC("iter/tcp")
int tcp_stats(struct bpf_iter__tcp *ctx)
{
    struct sock_common *common = ctx->sk_common;
    if (!common)
        return 0;
    struct tcp_sock *tp = bpf_skc_to_tcp_sock(common);
    if (!tp)
        return 0;
    struct sock *sk = (struct sock *)tp;
    if (BPF_CORE_READ(sk, __sk_common.skc_state) != 1)
        return 0;
    struct tcp_sample s = {};
    s.inode = BPF_CORE_READ(sk, sk_socket, file, f_inode, i_ino);
    s.family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (!s.inode || (s.family != 2 && s.family != 10))
        return 0;
    struct sock___stats *local = (void *)sk;
    if (bpf_core_field_exists(local->__sk_common.skc_net.net))
        s.netns = BPF_CORE_READ(local, __sk_common.skc_net.net, ns.inum);
    s.local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    s.remote_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    if (s.family == 2) {
        __u32 source = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __u32 destination = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(s.local, &source, sizeof(source));
        __builtin_memcpy(s.remote, &destination, sizeof(destination));
    } else {
        BPF_CORE_READ_INTO(&s.local, sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&s.remote, sk, __sk_common.skc_v6_daddr);
    }
    s.rtt_us = BPF_CORE_READ(tp, srtt_us) >> 3;
    s.rttvar_us = BPF_CORE_READ(tp, mdev_us) >> 2;
    s.cwnd_segments = BPF_CORE_READ(tp, snd_cwnd);
    s.retransmissions = BPF_CORE_READ(tp, total_retrans);
    bpf_seq_write(ctx->meta->seq, &s, sizeof(s));
    return 0;
}
char LICENSE[] SEC("license") = "Dual BSD/GPL";
