# rustnet-capture

The packet-capture backend of [RustNet](https://github.com/domcyrus/rustnet),
built on `libpcap` / `Npcap` via the [`pcap`](https://crates.io/crates/pcap)
crate.

This crate owns all of RustNet's pcap-based capture:

- network device selection (with sensible defaults that skip virtual/loopback
  adapters),
- BPF-filter setup,
- the macOS **PKTAP** fast path that attaches process metadata to packets,
- TUN/TAP interface handling,
- and a simple [`PacketReader`] that yields raw link-layer frames plus the
  libpcap data-link type (DLT).

## Why a separate crate?

It is intentionally decoupled from the analysis core (`rustnet-core`) and the
`rustnet` application so you can compose them differently:

- pair `rustnet-capture` + `rustnet-core` to build a **headless** tool (e.g. a
  Prometheus exporter) with no terminal UI (see `examples/headless.rs` in the
  repository for a runnable pairing);
- or swap `rustnet-capture` out for a **bespoke capture path** (for example a
  root-free macOS pktap helper) while still using `rustnet-core` for parsing.

Capture produces bytes; turning those bytes into connections, DPI results, and
GeoIP/DNS lookups is `rustnet-core`'s job.

## Capture waiting

`PacketReader` uses nonblocking reads with a bounded idle wait. It does not
sleep between available packets. The implementation has three small layers:

- `lib.rs`: shared packet reading and timestamp conversion, without OS-specific
  waiting branches. The application still owns shutdown and batch deadlines.
- `capture_wait.rs`: shared 10 ms idle budget, error/unsupported-backend fallback,
  and protection against readiness notifications that yield no packet.
- `capture_wait/unix.rs` and `capture_wait/windows.rs`: native readiness only,
  using libpcap's selectable descriptor or Npcap's event. These adapters neither
  read packets nor close the capture-owned descriptor/event.

Adapters are selected at compile time, without trait objects, extra threads,
or a public backend API. Linux, macOS, and FreeBSD use the same Unix adapter.
Captures without usable readiness fall back to bounded sleep polling. The
10 ms budget lets the application check shutdown and flush partial batches;
it is not a per-packet delay or a hard real-time scheduling guarantee.

Shared policy tests run on every supported OS. Native tests use Unix sockets
or Windows events without requiring capture privileges or an Npcap driver.
The ignored `live_capture` tests additionally exercise actual Unix loopback
capture and require packet-capture permissions.

## License

Apache-2.0
