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
#define IPPROTO_ICMP 1   /* ICMP */
#define IPPROTO_TCP 6    /* TCP */
#define IPPROTO_UDP 17   /* UDP */
#define IPPROTO_ICMPV6 58 /* ICMPv6 */

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

// IPv4 ICMP ping tracking - uses same socket_map as TCP/UDP
SEC("kprobe/ping_v4_sendmsg")
int trace_ping_v4_sendmsg(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1_CORE(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2_CORE(ctx);

    if (!sk || !msg)
        return 0;

    struct conn_key key = {};
    struct conn_info info = {};

    // Source address and ICMP ID from socket
    key.saddr[0] = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key.sport = BPF_CORE_READ(sk, __sk_common.skc_num); // ICMP echo ID

    // Destination from msghdr (same pattern as udp_sendmsg)
    struct sockaddr_in *dest_addr = NULL;
    bpf_probe_read_kernel(&dest_addr, sizeof(dest_addr), &msg->msg_name);

    if (dest_addr)
    {
        bpf_probe_read_kernel(&key.daddr[0], sizeof(__u32), &dest_addr->sin_addr.s_addr);
    }
    else
    {
        // Fallback to socket destination
        key.daddr[0] = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    }

    if (key.daddr[0] == 0)
        return 0;

    key.dport = 0; // ICMP has no destination port
    key.proto = IPPROTO_ICMP;
    key.family = AF_INET;

    get_process_info(&info);

    bpf_map_update_elem(&socket_map, &key, &info, BPF_ANY);
    return 0;
}

// IPv6 ICMP ping tracking
SEC("kprobe/ping_v6_sendmsg")
int trace_ping_v6_sendmsg(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1_CORE(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2_CORE(ctx);

    if (!sk || !msg)
        return 0;

    struct conn_key key = {};
    struct conn_info info = {};

    // Source address from socket (IPv6)
    struct in6_addr temp_saddr;
    BPF_CORE_READ_INTO(&temp_saddr, sk, __sk_common.skc_v6_rcv_saddr);
    __builtin_memcpy(key.saddr, &temp_saddr, sizeof(temp_saddr));

    key.sport = BPF_CORE_READ(sk, __sk_common.skc_num); // ICMP echo ID

    // Destination from msghdr
    struct sockaddr_in6 *dest_addr = NULL;
    bpf_probe_read_kernel(&dest_addr, sizeof(dest_addr), &msg->msg_name);

    if (dest_addr)
    {
        struct in6_addr temp_daddr;
        bpf_probe_read_kernel(&temp_daddr, sizeof(temp_daddr), &dest_addr->sin6_addr);
        __builtin_memcpy(key.daddr, &temp_daddr, sizeof(temp_daddr));
    }
    else
    {
        struct in6_addr temp_daddr;
        BPF_CORE_READ_INTO(&temp_daddr, sk, __sk_common.skc_v6_daddr);
        __builtin_memcpy(key.daddr, &temp_daddr, sizeof(temp_daddr));
    }

    key.dport = 0;
    key.proto = IPPROTO_ICMPV6;
    key.family = AF_INET6;

    get_process_info(&info);

    bpf_map_update_elem(&socket_map, &key, &info, BPF_ANY);
    return 0;
}

// bpf_iter__tcp is not exported in all vmlinux.h versions, define it explicitly
struct bpf_iter__tcp {
    union { struct bpf_iter_meta *meta; };
    union { struct sock_common *sk_common; };
    uid_t uid;
};

// Output record written to userspace via bpf_seq_write
struct tcp_stats
{
    __u64 bytes_sent;
    __u64 bytes_received;
    __u32 saddr[4];
    __u32 daddr[4];
    __u32 rtt_us;       // smoothed RTT (srtt_us >> 3)
    __u32 rtt_var_us;   // RTT variance (mdev_us >> 2)
    __u32 snd_cwnd;     // congestion window (segments)
    __u32 snd_ssthresh; // slow-start threshold
    __u32 total_retrans;
    __u16 sport;
    __u16 dport;
    __u8  family;       // AF_INET or AF_INET6
    __u8  state;        // TCP state (1=ESTABLISHED, …)
    __u8  _pad[2];
} __attribute__((packed));

// Pull-based TCP stats dump — no trap overhead.
// Userspace triggers a scan by calling read() on the iter fd; the kernel
// walks every tcp_sock and calls this program once per socket.
SEC("iter/tcp")
int dump_tcp_sockets(struct bpf_iter__tcp *ctx)
{
    struct sock_common *skc = ctx->sk_common;
    if (!skc)
        return 0;

    struct tcp_sock *tp = bpf_skc_to_tcp_sock(skc);
    if (!tp)
        return 0;

    struct tcp_stats stats = {};

    __u16 family = BPF_CORE_READ(skc, skc_family);
    stats.family = (__u8)family;
    stats.state  = BPF_CORE_READ(skc, skc_state);

    if (family == AF_INET) {
        stats.saddr[0] = BPF_CORE_READ(skc, skc_rcv_saddr);
        stats.daddr[0] = BPF_CORE_READ(skc, skc_daddr);
    } else if (family == AF_INET6) {
        struct in6_addr tmp;
        BPF_CORE_READ_INTO(&tmp, skc, skc_v6_rcv_saddr);
        __builtin_memcpy(stats.saddr, &tmp, sizeof(tmp));
        BPF_CORE_READ_INTO(&tmp, skc, skc_v6_daddr);
        __builtin_memcpy(stats.daddr, &tmp, sizeof(tmp));
    }

    stats.sport = BPF_CORE_READ(skc, skc_num);
    stats.dport = bpf_ntohs(BPF_CORE_READ(skc, skc_dport));

    // srtt_us stores RTT * 8; mdev_us stores variance * 4
    stats.rtt_us       = BPF_CORE_READ(tp, srtt_us) >> 3;
    stats.rtt_var_us   = BPF_CORE_READ(tp, mdev_us) >> 2;
    stats.snd_cwnd     = BPF_CORE_READ(tp, snd_cwnd);
    stats.snd_ssthresh = BPF_CORE_READ(tp, snd_ssthresh);
    stats.total_retrans = BPF_CORE_READ(tp, total_retrans);
    stats.bytes_sent    = BPF_CORE_READ(tp, bytes_sent);
    stats.bytes_received = BPF_CORE_READ(tp, bytes_received);

    bpf_seq_write(ctx->meta->seq, &stats, sizeof(stats));
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
