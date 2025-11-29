// Socket tracker eBPF program
// CO-RE (Compile Once - Run Everywhere) version using BTF

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define MAX_ENTRIES 32768
#define TASK_COMM_LEN 16

// Network constants not included in vmlinux.h
#define AF_INET 2      /* IPv4 */
#define AF_INET6 10    /* IPv6 */
#define IPPROTO_TCP 6  /* TCP */
#define IPPROTO_UDP 17 /* UDP */

// Connection key for socket tracking (supports both IPv4 and IPv6)
struct conn_key
{
    __u32 saddr[4]; // IPv4 uses only saddr[0], IPv6 uses all 4
    __u32 daddr[4]; // IPv4 uses only daddr[0], IPv6 uses all 4
    __u16 sport;
    __u16 dport;
    __u8 proto;  // IPPROTO_TCP or IPPROTO_UDP
    __u8 family; // AF_INET or AF_INET6
} __attribute__((packed));

// Process information
struct conn_info
{
    __u32 pid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    __u64 timestamp;
} __attribute__((packed));

// Socket tracking map
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct conn_key);
    __type(value, struct conn_info);
} socket_map SEC(".maps");

// Helper to populate process information
static __always_inline void get_process_info(struct conn_info *info)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    info->pid = pid_tgid >> 32;
    info->uid = uid_gid >> 32;
    info->timestamp = bpf_ktime_get_ns();

    bpf_get_current_comm(&info->comm, sizeof(info->comm));
}

// TCP connect tracking - use tcp_connect for better address capture
SEC("kprobe/tcp_connect")
int trace_tcp_connect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1_CORE(ctx);
    if (!sk)
    {
        return 0;
    }

    struct conn_key key = {};
    struct conn_info info = {};

    // Read socket information for IPv4 using CO-RE
    key.saddr[0] = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key.daddr[0] = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    key.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    key.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

    key.dport = bpf_ntohs(key.dport);
    key.proto = IPPROTO_TCP;
    key.family = AF_INET;

    get_process_info(&info);

    int ret = bpf_map_update_elem(&socket_map, &key, &info, BPF_ANY);
    if (ret != 0)
    {
        bpf_printk("tcp_connect: map update failed ret=%d", ret);
    }
    return 0;
}

// TCP accept tracking
SEC("kprobe/inet_csk_accept")
int trace_tcp_accept(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1_CORE(ctx);
    if (!sk)
    {
        return 0;
    }

    struct conn_key key = {};
    struct conn_info info = {};

    key.saddr[0] = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key.daddr[0] = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    key.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    key.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

    key.dport = bpf_ntohs(key.dport);
    key.proto = IPPROTO_TCP;
    key.family = AF_INET;

    get_process_info(&info);

    int ret = bpf_map_update_elem(&socket_map, &key, &info, BPF_ANY);
    if (ret != 0)
    {
        bpf_printk("inet_csk_accept: map update failed ret=%d", ret);
    }
    return 0;
}

// UDP sendmsg tracking - extract destination from msghdr
SEC("kprobe/udp_sendmsg")
int trace_udp_sendmsg(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1_CORE(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2_CORE(ctx);

    if (!sk || !msg)
    {
        return 0;
    }

    struct conn_key key = {};
    struct conn_info info = {};

    // Get source address from socket
    key.saddr[0] = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key.sport = BPF_CORE_READ(sk, __sk_common.skc_num);

    // Try to get destination from msghdr->msg_name (sockaddr_in)
    struct sockaddr_in *dest_addr = NULL;
    bpf_probe_read_kernel(&dest_addr, sizeof(dest_addr), &msg->msg_name);

    if (dest_addr)
    {
        bpf_probe_read_kernel(&key.daddr[0], sizeof(__u32), &dest_addr->sin_addr.s_addr);
        bpf_probe_read_kernel(&key.dport, sizeof(__u16), &dest_addr->sin_port);
    }
    else
    {
        // Fallback to socket fields (might be zero for unconnected UDP)
        key.daddr[0] = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        key.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    }

    // Only skip if destination is zero (source might be unbound for UDP)
    if (key.daddr[0] == 0)
    {
        return 0;
    }

    key.dport = bpf_ntohs(key.dport);
    key.proto = IPPROTO_UDP;
    key.family = AF_INET;

    get_process_info(&info);

    int ret = bpf_map_update_elem(&socket_map, &key, &info, BPF_ANY);
    if (ret != 0)
    {
        bpf_printk("udp_sendmsg: map update failed ret=%d", ret);
    }
    return 0;
}

// IPv6 TCP connect tracking
SEC("kprobe/tcp_v6_connect")
int trace_tcp_v6_connect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1_CORE(ctx);
    if (!sk)
        return 0;

    struct conn_key key = {};
    struct conn_info info = {};

    // Read socket information for IPv6 using CO-RE
    // Use temporary variables to avoid packed member warnings
    struct in6_addr temp_saddr, temp_daddr;
    BPF_CORE_READ_INTO(&temp_saddr, sk, __sk_common.skc_v6_rcv_saddr);
    BPF_CORE_READ_INTO(&temp_daddr, sk, __sk_common.skc_v6_daddr);

    // Copy to packed structure
    __builtin_memcpy(key.saddr, &temp_saddr, sizeof(temp_saddr));
    __builtin_memcpy(key.daddr, &temp_daddr, sizeof(temp_daddr));
    key.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    key.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

    key.dport = bpf_ntohs(key.dport);
    key.proto = IPPROTO_TCP;
    key.family = AF_INET6;

    get_process_info(&info);

    bpf_map_update_elem(&socket_map, &key, &info, BPF_ANY);
    return 0;
}

// IPv6 UDP sendmsg tracking
SEC("kprobe/udpv6_sendmsg")
int trace_udp_v6_sendmsg(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1_CORE(ctx);
    if (!sk)
        return 0;

    struct conn_key key = {};
    struct conn_info info = {};

    // Use temporary variables to avoid packed member warnings
    struct in6_addr temp_saddr, temp_daddr;
    BPF_CORE_READ_INTO(&temp_saddr, sk, __sk_common.skc_v6_rcv_saddr);
    BPF_CORE_READ_INTO(&temp_daddr, sk, __sk_common.skc_v6_daddr);

    // Copy to packed structure
    __builtin_memcpy(key.saddr, &temp_saddr, sizeof(temp_saddr));
    __builtin_memcpy(key.daddr, &temp_daddr, sizeof(temp_daddr));
    key.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    key.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

    key.dport = bpf_ntohs(key.dport);
    key.proto = IPPROTO_UDP;
    key.family = AF_INET6;

    get_process_info(&info);

    bpf_map_update_elem(&socket_map, &key, &info, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
