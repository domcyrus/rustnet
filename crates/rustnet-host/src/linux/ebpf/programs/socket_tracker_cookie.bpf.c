#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

/* Supplementary records have a separate, smaller memory budget. */
#define MAX_ENTRIES 8192
#include "socket_tracker_helpers.h"

/* Optional cgroup observer. Every hook permits traffic. Socket identity is
 * captured only in process context, never from the task handling an skb. */
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct conn_info);
} cookie_owners SEC(".maps");

static __noinline void remember_owner(__u64 cookie)
{
    if (!cookie)
        return;
    __u32 zero = 0;
    struct identity_scratch *scratch = bpf_map_lookup_elem(&identity_buffer, &zero);
    if (!scratch || scratch->busy)
        return;
    scratch->busy = 1;
    __builtin_memset(&scratch->info, 0, sizeof(scratch->info));
    get_process_info(&scratch->info);
    bpf_map_update_elem(&cookie_owners, &cookie, &scratch->info, BPF_ANY);
    scratch->busy = 0;
}

SEC("cgroup/sock_create")
int cookie_socket_create(struct bpf_sock *ctx)
{
    if ((ctx->family == AF_INET || ctx->family == AF_INET6) &&
        (ctx->protocol == IPPROTO_TCP || ctx->protocol == IPPROTO_UDP))
        remember_owner(bpf_get_socket_cookie(ctx));
    return 1;
}

SEC("cgroup/sock_release")
int cookie_socket_release(struct bpf_sock *ctx)
{
    __u64 cookie = bpf_get_socket_cookie(ctx);
    bpf_map_delete_elem(&cookie_owners, &cookie);
    /* Retain tuple records for delayed enrichment, as the live tracker does. */
    return 1;
}

static __always_inline int remember_actor(struct bpf_sock_addr *ctx)
{
    if (ctx->protocol == IPPROTO_TCP || ctx->protocol == IPPROTO_UDP)
        remember_owner(bpf_get_socket_cookie(ctx));
    return 1;
}

SEC("cgroup/connect4")
int cookie_connect4(struct bpf_sock_addr *ctx)
{
    return remember_actor(ctx);
}

SEC("cgroup/connect6")
int cookie_connect6(struct bpf_sock_addr *ctx)
{
    return remember_actor(ctx);
}

SEC("cgroup/sendmsg4")
int cookie_sendmsg4(struct bpf_sock_addr *ctx)
{
    return remember_actor(ctx);
}

SEC("cgroup/sendmsg6")
int cookie_sendmsg6(struct bpf_sock_addr *ctx)
{
    return remember_actor(ctx);
}

static __always_inline int correlate_packet(struct __sk_buff *skb, bool inbound)
{
    __u64 cookie = bpf_get_socket_cookie(skb);
    if (!cookie)
        return 1;
    struct conn_info *owner = bpf_map_lookup_elem(&cookie_owners, &cookie);
    if (!owner)
        return 1;

    struct conn_key key = {};
    __u32 transport_offset;
    if (skb->protocol == bpf_htons(0x0800))
    {
        struct iphdr ip;
        if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip)) ||
            ip.version != 4 || ip.ihl < 5 || (ip.frag_off & bpf_htons(0x1fff)))
            return 1;
        key.family = AF_INET;
        key.proto = ip.protocol;
        key.saddr[0] = inbound ? ip.daddr : ip.saddr;
        key.daddr[0] = inbound ? ip.saddr : ip.daddr;
        transport_offset = ip.ihl * 4;
    }
    else if (skb->protocol == bpf_htons(0x86dd))
    {
        struct ipv6hdr ip;
        if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip)) || ip.version != 6)
            return 1;
        key.family = AF_INET6;
        key.proto = ip.nexthdr;
        if (inbound)
        {
            __builtin_memcpy(key.saddr, &ip.daddr, sizeof(ip.daddr));
            __builtin_memcpy(key.daddr, &ip.saddr, sizeof(ip.saddr));
        }
        else
        {
            __builtin_memcpy(key.saddr, &ip.saddr, sizeof(ip.saddr));
            __builtin_memcpy(key.daddr, &ip.daddr, sizeof(ip.daddr));
        }
        transport_offset = sizeof(ip);
        /* Bound extension traversal. Unsupported or incomplete headers leave
         * attribution to the existing tracing/procfs backends. */
        for (int i = 0; i < 6; i++)
        {
            if (key.proto == IPPROTO_TCP || key.proto == IPPROTO_UDP)
                break;
            struct { __u8 next; __u8 len; __u16 fragment; } extension;
            if (bpf_skb_load_bytes(skb, transport_offset, &extension, sizeof(extension)))
                return 1;
            if (key.proto == 44)
            {
                if (extension.fragment & bpf_htons(0xfff8))
                    return 1;
                transport_offset += 8;
            }
            else if (key.proto == 0 || key.proto == 43 || key.proto == 60)
                transport_offset += ((__u32)extension.len + 1) * 8;
            else
                return 1;
            key.proto = extension.next;
        }
    }
    else
        return 1;

    if (key.proto != IPPROTO_TCP && key.proto != IPPROTO_UDP)
        return 1;
    struct { __u16 source; __u16 dest; } ports;
    if (bpf_skb_load_bytes(skb, transport_offset, &ports, sizeof(ports)))
        return 1;
    key.sport = bpf_ntohs(inbound ? ports.dest : ports.source);
    key.dport = bpf_ntohs(inbound ? ports.source : ports.dest);
    owner->timestamp = bpf_ktime_get_ns();
    bpf_map_update_elem(&socket_map, &key, owner, BPF_ANY);
    return 1;
}

SEC("cgroup_skb/egress")
int cookie_packet_egress(struct __sk_buff *ctx)
{
    return correlate_packet(ctx, false);
}

SEC("cgroup_skb/ingress")
int cookie_packet_ingress(struct __sk_buff *ctx)
{
    return correlate_packet(ctx, true);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
