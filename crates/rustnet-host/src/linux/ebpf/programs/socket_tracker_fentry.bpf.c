#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "socket_tracker_helpers.h"

SEC("fexit/tcp_connect")
int BPF_PROG(trace_tcp_connect, struct sock *sk, int result)
{
    if (result == 0)
        track_tcp_socket(sk);
    return 0;
}

SEC("fexit/tcp_v6_connect")
int BPF_PROG(trace_tcp_v6_connect, struct sock *sk, struct sockaddr *address,
             int address_length, int result)
{
    if (result == 0)
        track_tcp_v6(sk);
    return 0;
}

SEC("fentry/udp_sendmsg")
int BPF_PROG(trace_udp_sendmsg, struct sock *sk, struct msghdr *msg,
             size_t len)
{
    track_udp_v4(sk, msg);
    return 0;
}

SEC("fentry/udpv6_sendmsg")
int BPF_PROG(trace_udp_v6_sendmsg, struct sock *sk, struct msghdr *msg,
             size_t len)
{
    track_udp_v6(sk, msg);
    return 0;
}

/*
 * inet_csk_accept used four parameters through Linux 6.8. Newer kernels use
 * proto_accept_arg. Userspace enables exactly one variant after inspecting
 * the running kernel's BTF function prototype.
 */
SEC("fexit/inet_csk_accept")
int BPF_PROG(trace_tcp_accept_legacy_signature, struct sock *listener,
             int flags, int *err, bool kern, struct sock *accepted)
{
    track_accepted_socket(accepted);
    return 0;
}

SEC("fexit/inet_csk_accept")
int BPF_PROG(trace_tcp_accept_proto_arg, struct sock *listener,
             struct proto_accept_arg *arg, struct sock *accepted)
{
    track_accepted_socket(accepted);
    return 0;
}

SEC("fentry/ping_v4_sendmsg")
int BPF_PROG(trace_ping_v4_sendmsg, struct sock *sk, struct msghdr *msg,
             size_t len)
{
    track_ping_v4(sk, msg);
    return 0;
}

SEC("fentry/ping_v6_sendmsg")
int BPF_PROG(trace_ping_v6_sendmsg, struct sock *sk, struct msghdr *msg,
             size_t len)
{
    track_ping_v6(sk, msg);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
