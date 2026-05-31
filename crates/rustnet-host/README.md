# rustnet-host

Host-OS integration layer for [RustNet](https://github.com/domcyrus/rustnet):
the metadata about a connection that only the operating system / kernel can
tell us, behind one trait per concern.

Today this is **per-connection process attribution** — given a
`rustnet_core` `Connection`, find the owning process (pid + name) — using the
best strategy each platform offers, with graceful fallbacks:

- **Linux** — eBPF socket tracking (with the `ebpf` feature) and a procfs fallback.
- **macOS** — PKTAP packet metadata when available (no lookup needed), else `lsof`.
- **Windows** — the IP Helper API (`GetExtendedTcpTable` / `...UdpTable`).
- **FreeBSD** — `sockstat`.

```rust
use rustnet_host::create_process_lookup;

let lookup = create_process_lookup(/* use_pktap = */ false)?;
if let Some((pid, name)) = lookup.get_process_for_connection(&conn) {
    println!("{conn:?} owned by {name} ({pid})");
}
```

When a platform can't use its optimal method, `ProcessLookup::get_degradation_reason`
reports why (e.g. missing `CAP_BPF`, no root for PKTAP) via `DegradationReason`,
which front-ends can surface to the user.

## Scope

The crate is named `rustnet-host` rather than `rustnet-process` on purpose: it's
the home for *all* host/kernel-derived connection metadata. Process ownership is
the first inhabitant; kernel TCP/UDP counters, socket states, and
cgroup/container info are natural future additions that share the same eBPF and
OS-query machinery.

It depends only on `rustnet-core` (for `Connection`/`Protocol`) and, on macOS,
`rustnet-capture` (to learn whether PKTAP is active). No UI or capture-loop
dependency, so headless tools can attribute processes the same way the `rustnet`
TUI does.

## License

Apache-2.0
