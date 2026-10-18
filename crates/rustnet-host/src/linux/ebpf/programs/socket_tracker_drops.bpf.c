#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 262144);
} drop_events SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} delivery_loss SEC(".maps");
struct drop_event { __u64 monotonic_ns; __u32 reason, ifindex; };

/* Host-scope evidence only. No current-task PID or guessed flow attribution. */
SEC("tp_btf/kfree_skb")
int BPF_PROG(observe_drop, struct sk_buff *skb, void *location,
             enum skb_drop_reason reason)
{
    if (reason == SKB_NOT_DROPPED_YET || reason == SKB_CONSUMED)
        return 0;
    struct drop_event *event = bpf_ringbuf_reserve(&drop_events, sizeof(*event), 0);
    if (!event) {
        __u32 key = 0;
        __u64 *lost = bpf_map_lookup_elem(&delivery_loss, &key);
        if (lost)
            __sync_fetch_and_add(lost, 1);
        return 0;
    }
    event->monotonic_ns = bpf_ktime_get_ns();
    event->reason = reason;
    event->ifindex = BPF_CORE_READ(skb, dev, ifindex);
    bpf_ringbuf_submit(event, 0);
    return 0;
}
char LICENSE[] SEC("license") = "Dual BSD/GPL";
