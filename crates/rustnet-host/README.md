# rustnet-host

Host-OS integration layer for [RustNet](https://github.com/domcyrus/rustnet):
the metadata about a connection that only the operating system / kernel can
tell us, behind one trait per concern.

Today this is **per-connection process attribution**: given a
`rustnet_core` `Connection`, find the owning process (pid + name), using the
best strategy each platform offers, with graceful fallbacks:

- **Linux**: fentry/fexit eBPF, legacy kprobes, then procfs.
- **macOS**: PKTAP packet metadata plus libproc when available, else `lsof`
  plus libproc.
- **Windows**: kernel ETW events with an IP Helper API
  (`GetExtendedTcpTable` / `...UdpTable`) fallback.
- **FreeBSD**: `sockstat`, enriched through native `sysctl` process metadata.

```rust
use rustnet_host::create_process_lookup;

let lookup = create_process_lookup(/* use_pktap = */ false)?;
if let Some((pid, name)) = lookup.get_process_for_connection(&conn) {
    println!("{conn:?} owned by {name} ({pid})");
}
```

Callers that want more than a pid and a name ask for a `ProcessAttribution`
instead:

```rust
if let Some(attribution) = lookup.get_process_attribution(&conn) {
    println!(
        "{} ({}) ppid={:?} uid={:?} exe={:?} lineage={:?} via {} ({} match)",
        attribution.name,
        attribution.tgid,
        attribution.ppid,
        attribution.uid,
        attribution.executable,
        attribution.lineage,
        attribution.backend,
        attribution.quality,
    );
}
```

`MatchQuality` records how the connection was matched, so a relaxed
wildcard/listener guess is never mistaken for a proven 4-tuple hit; use
`quality.is_exact()` to tell them apart. Linux resolves PPID from procfs for
both socket-table and eBPF matches. The eBPF backends also fill in the
effective UID/GID. The executable path is resolved once from
`/proc/<tgid>/exe`; an unreadable link yields `executable: None` and never
fails the attribution.

Every platform also resolves up to four parent processes, ordered from the
oldest retained ancestor to the direct parent. Each entry includes its PID,
name, executable path, and Unix start time when the OS exposes them. A
truncation flag marks chains capped before another known parent.

On macOS, PKTAP supplies an exact PID and process name with each packet. Libproc
adds the PPID, executable path, and effective UID/GID. The fallback parses
numeric UIDs from `lsof -l` and uses libproc for the other process details.
PKTAP reports
`AttributionBackend::Pktap` with `MatchQuality::ExactTuple`; lsof reports whether
its socket-table match was exact, wildcard-bound, or a listener.

On FreeBSD, `sockstat` supplies the socket owner and native `sysctl` queries add
the PPID, effective UID/GID, and executable path. Process details are cached by
PID for each socket-table refresh.

On Windows, Tool Help supplies parent relationships and process names, while
`QueryFullProcessImageNameW` and `GetProcessTimes` add executable paths and
creation times. Connection match quality remains `MatchQuality::Unspecified`.

When a platform can't use its optimal method, `ProcessLookup::get_degradation_reason`
reports why (e.g. missing `CAP_BPF`, no root for PKTAP) via `DegradationReason`,
which front-ends can surface to the user.

Linux callers can inspect `ProcessLookup::get_attribution_backend()` to
distinguish fentry/fexit, legacy kprobes, and procfs.

Both Linux BPF objects use CO-RE for safe socket field access and therefore
require usable target BTF. A compatible target-BTF kernel tries fentry/fexit
first and legacy kprobes second. A kernel without usable target BTF falls
directly to procfs rather than relying on fixed structure offsets.

## Linux eBPF integration matrix

The ignored root test covers outbound TCP, accepted TCP, connected UDP, and
unconnected UDP for IPv4 and IPv6. It also verifies TGID/TID, UID/GID, `comm`,
monotonic timestamps, match quality, `/proc/<tgid>/exe` resolution, and that a
socket opened by a worker thread is attributed to that thread rather than to the
group leader.

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
