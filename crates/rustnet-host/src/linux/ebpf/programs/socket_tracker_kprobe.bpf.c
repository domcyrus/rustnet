#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "socket_tracker_helpers.h"

/*
 * A return probe cannot read function arguments directly. Keep the socket
 * pointer per thread between connect entry and return so the final tuple can
 * be recorded after automatic binding and route selection.
 */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct sock *);
} pending_connect SEC(".maps");

static __always_inline int remember_connect_socket(struct sock *sk)
{
    if (!sk)
        return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    return bpf_map_update_elem(&pending_connect, &pid_tgid, &sk, BPF_ANY);
}

static __always_inline struct sock *take_connect_socket(void)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock **socket = bpf_map_lookup_elem(&pending_connect, &pid_tgid);
    struct sock *sk = socket ? *socket : NULL;
    bpf_map_delete_elem(&pending_connect, &pid_tgid);
    return sk;
}

SEC("kprobe/tcp_connect")
int trace_tcp_connect_entry(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1_CORE(ctx);
    remember_connect_socket(sk);
    return 0;
}

SEC("kretprobe/tcp_connect")
int trace_tcp_connect_exit(struct pt_regs *ctx)
{
    struct sock *sk = take_connect_socket();
    if (PT_REGS_RC_CORE(ctx) == 0)
        track_tcp_socket(sk);
    return 0;
}

SEC("kprobe/tcp_v6_connect")
int trace_tcp_v6_connect_entry(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1_CORE(ctx);
    remember_connect_socket(sk);
    return 0;
}

SEC("kretprobe/tcp_v6_connect")
int trace_tcp_v6_connect_exit(struct pt_regs *ctx)
{
    struct sock *sk = take_connect_socket();
    if (PT_REGS_RC_CORE(ctx) == 0)
        track_tcp_v6(sk);
    return 0;
}

SEC("kprobe/udp_sendmsg")
int trace_udp_sendmsg(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1_CORE(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2_CORE(ctx);
    track_udp_v4(sk, msg);
    return 0;
}

SEC("kprobe/udpv6_sendmsg")
int trace_udp_v6_sendmsg(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1_CORE(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2_CORE(ctx);
    track_udp_v6(sk, msg);
    return 0;
}

/*
 * A return probe is required here. At function entry the first argument is
 * the listening socket. The returned pointer is the connected child socket.
 */
SEC("kretprobe/inet_csk_accept")
int trace_tcp_accept(struct pt_regs *ctx)
{
    struct sock *accepted = (struct sock *)PT_REGS_RC_CORE(ctx);
    track_accepted_socket(accepted);
    return 0;
}

SEC("kprobe/ping_v4_sendmsg")
int trace_ping_v4_sendmsg(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1_CORE(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2_CORE(ctx);
    track_ping_v4(sk, msg);
    return 0;
}

SEC("kprobe/ping_v6_sendmsg")
int trace_ping_v6_sendmsg(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1_CORE(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2_CORE(ctx);
    track_ping_v6(sk, msg);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
