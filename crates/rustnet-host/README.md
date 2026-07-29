# rustnet-host

Host-OS integration layer for [RustNet](https://github.com/domcyrus/rustnet):
the metadata about a connection that only the operating system / kernel can
tell us, behind one trait per concern.

Today this is **per-connection process attribution**: given a
`rustnet_core` `Connection`, find the owning process (pid + name), using the
best strategy each platform offers, with graceful fallbacks:

- **Linux**: fentry/fexit eBPF, legacy kprobes, then procfs.
- **macOS**: PKTAP packet metadata when available (no lookup needed), else `lsof`.
- **Windows**: kernel ETW events with an IP Helper API
  (`GetExtendedTcpTable` / `...UdpTable`) fallback.
- **FreeBSD**: `sockstat`.

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

Linux callers can inspect `ProcessLookup::get_attribution_backend()` and
`ProcessLookup::get_attribution_capabilities()` to distinguish fentry/fexit,
legacy kprobes, procfs, and partial protocol coverage. Existing
`get_process_for_connection()` callers remain unchanged.

Both Linux BPF objects use CO-RE for safe socket field access and therefore
require usable target BTF. A compatible target-BTF kernel tries fentry/fexit
first and legacy kprobes second. A kernel without usable target BTF falls
directly to procfs rather than relying on fixed structure offsets.

## Linux eBPF integration matrix

The ignored root test covers outbound TCP, accepted TCP, connected UDP, and
unconnected UDP for IPv4 and IPv6. It also verifies TGID/TID, UID/GID, `comm`,
and monotonic timestamps.

```bash
sudo -E cargo test -p rustnet-host --features ebpf -- \
  --ignored --exact \
  linux::ebpf::tracker_libbpf::integration_tests::socket_attribution_matrix \
  --nocapture

sudo -E cargo test -p rustnet-host --features ebpf -- \
  --ignored --exact \
  linux::ebpf::tracker_libbpf::integration_tests::legacy_kprobe_socket_attribution_matrix \
  --nocapture
```

## Scope

The crate is named `rustnet-host` rather than `rustnet-process` on purpose: it's
the home for *all* host/kernel-derived connection metadata. Process ownership is
the first inhabitant; kernel TCP/UDP counters, socket states, and
cgroup/container info are natural future additions that share the same eBPF and
OS-query machinery.

It depends only on `rustnet-core` (for `Connection`/`Protocol`); it does not
depend on `rustnet-capture`. On macOS the application injects whether PKTAP is
active rather than this crate querying capture. No UI or capture-loop
dependency, so headless tools can attribute processes the same way the `rustnet`
TUI does.

## License

Apache-2.0
