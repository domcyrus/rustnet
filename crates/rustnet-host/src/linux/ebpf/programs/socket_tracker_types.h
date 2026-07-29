#ifndef RUSTNET_SOCKET_TRACKER_TYPES_H
#define RUSTNET_SOCKET_TRACKER_TYPES_H

#define MAX_ENTRIES 32768
#define TASK_COMM_LEN 16

/* Network constants are not included in every generated vmlinux.h. */
#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMPV6 58

#define CONN_KEY_SIZE 40
#define CONN_INFO_SIZE 40

/*
 * Map ABI shared with maps_libbpf.rs. Explicit trailing padding keeps the
 * structure naturally aligned without relying on packed field accesses.
 */
struct conn_key
{
    __u32 saddr[4];
    __u32 daddr[4];
    __u16 sport;
    __u16 dport;
    __u8 proto;
    __u8 family;
    __u8 padding[2];
};

struct conn_info
{
    __u32 tgid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    __u64 timestamp;
};

_Static_assert(sizeof(struct conn_key) == CONN_KEY_SIZE,
               "conn_key map ABI size changed");
_Static_assert(sizeof(struct conn_info) == CONN_INFO_SIZE,
               "conn_info map ABI size changed");

#endif
