#ifndef RUSTNET_SOCKET_TRACKER_HELPERS_H
#define RUSTNET_SOCKET_TRACKER_HELPERS_H

#include "socket_tracker_types.h"

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct conn_key);
    __type(value, struct conn_info);
} socket_map SEC(".maps");

/*
 * Minimal CO-RE view of task_struct. Referencing the full generated type makes
 * older clang versions emit BTF that skeleton generation cannot consume.
 */
struct task_struct___local
{
    struct task_struct___local *group_leader;
    char comm[TASK_COMM_LEN];
} __attribute__((preserve_access_index));

static __always_inline void get_process_info(struct conn_info *info)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    info->tgid = pid_tgid >> 32;
    info->tid = (__u32)pid_tgid;
    info->uid = (__u32)uid_gid;
    info->gid = uid_gid >> 32;
    info->timestamp = bpf_ktime_get_ns();

    struct task_struct___local *task =
        (struct task_struct___local *)bpf_get_current_task();
    long err = BPF_CORE_READ_STR_INTO(&info->comm, task, group_leader, comm);
    if (err <= 0 || info->comm[0] == '\0')
    {
        bpf_get_current_comm(&info->comm, sizeof(info->comm));
    }
}

static __always_inline int store_connection(struct conn_key *key)
{
    struct conn_info info = {};
    get_process_info(&info);
    return bpf_map_update_elem(&socket_map, key, &info, BPF_ANY);
}

static __always_inline void fill_socket_ports(struct sock *sk,
                                               struct conn_key *key)
{
    key->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    key->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
}

static __always_inline void fill_socket_v4_addresses(struct sock *sk,
                                                     struct conn_key *key)
{
    key->saddr[0] = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key->daddr[0] = BPF_CORE_READ(sk, __sk_common.skc_daddr);
}

static __always_inline void fill_socket_v6_addresses(struct sock *sk,
                                                     struct conn_key *key)
{
    struct in6_addr saddr = {};
    struct in6_addr daddr = {};

    BPF_CORE_READ_INTO(&saddr, sk, __sk_common.skc_v6_rcv_saddr);
    BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_v6_daddr);
    __builtin_memcpy(key->saddr, &saddr, sizeof(saddr));
    __builtin_memcpy(key->daddr, &daddr, sizeof(daddr));
}

static __always_inline int track_tcp_v4(struct sock *sk)
{
    if (!sk)
        return 0;

    struct conn_key key = {};
    fill_socket_v4_addresses(sk, &key);
    fill_socket_ports(sk, &key);
    key.proto = IPPROTO_TCP;
    key.family = AF_INET;
    return store_connection(&key);
}

static __always_inline int track_tcp_v6(struct sock *sk)
{
    if (!sk)
        return 0;

    struct conn_key key = {};
    fill_socket_v6_addresses(sk, &key);
    fill_socket_ports(sk, &key);
    key.proto = IPPROTO_TCP;
    key.family = AF_INET6;
    return store_connection(&key);
}

/*
 * A dual-stack AF_INET6 socket connected to an IPv4 peer keeps sk_family ==
 * AF_INET6 while the kernel records the peer as ::ffff:a.b.c.d and mirrors the
 * plain IPv4 addresses into skc_rcv_saddr / skc_daddr. Only IPv4 packets appear
 * on the wire, so userspace builds an AF_INET key; the tuple must be stored
 * under that key rather than the mapped IPv6 one.
 */
static __always_inline bool tcp_socket_is_v4_mapped(struct sock *sk)
{
    struct in6_addr daddr = {};
    BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_v6_daddr);
    return daddr.in6_u.u6_addr32[0] == 0 && daddr.in6_u.u6_addr32[1] == 0 &&
           daddr.in6_u.u6_addr32[2] == bpf_htonl(0x0000ffff);
}

static __always_inline int track_tcp_socket(struct sock *sk)
{
    if (!sk)
        return 0;

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family == AF_INET6)
        return tcp_socket_is_v4_mapped(sk) ? track_tcp_v4(sk) : track_tcp_v6(sk);
    if (family == AF_INET)
        return track_tcp_v4(sk);
    return 0;
}

static __always_inline int track_accepted_socket(struct sock *accepted)
{
    return track_tcp_socket(accepted);
}

static __always_inline int track_udp_v4(struct sock *sk, struct msghdr *msg)
{
    if (!sk || !msg)
        return 0;

    struct conn_key key = {};
    fill_socket_v4_addresses(sk, &key);
    fill_socket_ports(sk, &key);

    struct sockaddr_in *dest = BPF_CORE_READ(msg, msg_name);
    if (dest)
    {
        bpf_probe_read_kernel(&key.daddr[0], sizeof(key.daddr[0]),
                              &dest->sin_addr.s_addr);
        __u16 dport = 0;
        bpf_probe_read_kernel(&dport, sizeof(dport), &dest->sin_port);
        key.dport = bpf_ntohs(dport);
    }

    if (key.daddr[0] == 0)
        return 0;

    key.proto = IPPROTO_UDP;
    key.family = AF_INET;
    return store_connection(&key);
}

static __always_inline int track_udp_v6(struct sock *sk, struct msghdr *msg)
{
    if (!sk || !msg)
        return 0;

    struct conn_key key = {};
    fill_socket_v6_addresses(sk, &key);
    fill_socket_ports(sk, &key);

    struct sockaddr_in6 *dest = BPF_CORE_READ(msg, msg_name);
    if (dest)
    {
        struct in6_addr daddr = {};
        bpf_probe_read_kernel(&daddr, sizeof(daddr), &dest->sin6_addr);
        __builtin_memcpy(key.daddr, &daddr, sizeof(daddr));
        __u16 dport = 0;
        bpf_probe_read_kernel(&dport, sizeof(dport), &dest->sin6_port);
        key.dport = bpf_ntohs(dport);
    }

    key.proto = IPPROTO_UDP;
    key.family = AF_INET6;
    return store_connection(&key);
}

static __always_inline int track_ping_v4(struct sock *sk, struct msghdr *msg)
{
    if (!sk || !msg)
        return 0;

    struct conn_key key = {};
    fill_socket_v4_addresses(sk, &key);
    key.sport = BPF_CORE_READ(sk, __sk_common.skc_num);

    struct sockaddr_in *dest = BPF_CORE_READ(msg, msg_name);
    if (dest)
        bpf_probe_read_kernel(&key.daddr[0], sizeof(key.daddr[0]),
                              &dest->sin_addr.s_addr);

    if (key.daddr[0] == 0)
        return 0;

    key.proto = IPPROTO_ICMP;
    key.family = AF_INET;
    return store_connection(&key);
}

static __always_inline int track_ping_v6(struct sock *sk, struct msghdr *msg)
{
    if (!sk || !msg)
        return 0;

    struct conn_key key = {};
    fill_socket_v6_addresses(sk, &key);
    key.sport = BPF_CORE_READ(sk, __sk_common.skc_num);

    struct sockaddr_in6 *dest = BPF_CORE_READ(msg, msg_name);
    if (dest)
    {
        struct in6_addr daddr = {};
        bpf_probe_read_kernel(&daddr, sizeof(daddr), &dest->sin6_addr);
        __builtin_memcpy(key.daddr, &daddr, sizeof(daddr));
    }

    key.proto = IPPROTO_ICMPV6;
    key.family = AF_INET6;
    return store_connection(&key);
}

#endif
