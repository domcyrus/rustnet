#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "socket_tracker_helpers.h"

/*
 * tcp_connect is the last step of every TCP connect: tcp_v4_connect and
 * tcp_v6_connect both call it after binding the source port and selecting the
 * route, so the socket already carries the final tuple at function entry and
 * track_tcp_socket picks the key family from the socket itself. Probing this
 * single entry point covers IPv4, IPv6, and dual-stack IPv4-mapped connects
 * without a return probe — a kretprobe would be dropped once the kernel's
 * maxactive limit is reached during a burst of concurrent connects, silently
 * losing those connections.
 */
SEC("kprobe/tcp_connect")
int trace_tcp_connect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1_CORE(ctx);
    track_tcp_socket(sk);
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
