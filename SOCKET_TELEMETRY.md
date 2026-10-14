[English](SOCKET_TELEMETRY.md) | [简体中文](SOCKET_TELEMETRY.zh-CN.md) | [日本語](SOCKET_TELEMETRY.ja.md)

# Kernel socket telemetry

**Development feature, unreleased.** Linux reads TCP and UDP socket diagnostics
every five seconds through `NETLINK_SOCK_DIAG`. Process attribution continues to
use fentry/fexit, its kprobe compatibility fallback, or procfs. Diagnostics do
not require BPF capabilities; packet capture still needs its usual permissions.
Other platforms currently leave these measurements unavailable.

Details shows local TCP kernel state, RTT and variation, minimum RTT,
retransmission timeout, congestion control, congestion window and slow-start
threshold (segments), retransmissions, queues and transport byte counters.
The Health section paginates on smaller terminals. Kernel counters describe the
socket lifetime, which can begin before capture. Sent bytes may include
retransmissions; acknowledged bytes are separate. These counters never replace
or add to captured traffic totals or packet-derived RTT/retransmission analytics.

Host shows listener backlog occupancy/limit and UDP receive/send memory queues
with socket drops. UDP memory includes kernel overhead, not just payload bytes.
UDP counters stay at socket scope because one socket can serve multiple peers.
TCP receive/send queues count unread/unacknowledged bytes. Unsent bytes are a
separate TCP metric. Missing fields display as unavailable, not zero.

Headless schema version 1 adds `connections[].kernel_stats` and `host_sockets`.
The latter is the host inventory and is independent of the connection `--filter`.
Each sample includes its source, timestamp, age, stale flag, socket cookie and
network namespace identity when available. `queues.kind` is `bytes`,
`memory_bytes` or `backlog`; for backlog, `receive` is pending accepts and `send`
is the limit. TCP JSON durations use milliseconds and byte fields name their
units. Older producers may omit these additive fields.

Collection covers the current network namespace, not every container namespace.
Connection enrichment requires an unambiguous exact TCP tuple and a socket
cookie. Conflicting owners and changes to an already sampled socket identity
are rejected. A tuple reused before the first sample cannot be distinguished
reliably. Polling can miss short-lived sockets entirely.

Samples become stale after ten seconds. A disappeared socket keeps its last
connection sample with its original timestamp. Diagnostic failures fall back
to the procfs table for that family/protocol, and the inventory reports partial
or unavailable telemetry. A full scan has a 500 ms diagnostic deadline, with
bounded message sizes and record counts. Kernel support and local security
policy can limit coverage. No additional privileges are retained at runtime.
