# QUIC inspection

[English](QUIC.md) | [简体中文](QUIC.zh-CN.md) | [日本語](QUIC.ja.md)

**Available since v1.7.0:** RustNet assembles the client Initial CRYPTO stream to extract
ClientHello metadata, including SNI, ALPN, and TLS version. Finding SNI alone
does not stop assembly because later fragments can carry ALPN.

The inspection window covers offsets 0 through 65,535, with at most 256
disjoint ranges. Adjacent ranges coalesce, including reverse-order arrival.
Overlapping retransmissions add missing bytes and preserve the first observed
value where bytes overlap. Empty fragments and offsets outside the window are
ignored or rejected. Oversized and excessively sparse handshakes may yield
only partial metadata.

Handshake bytes are released after the complete ClientHello is inspected, its
64 KiB window is filled, or connection closure is merged. Incomplete handshakes
otherwise remain bounded until the live connection expires. UI and history
snapshots retain extracted metadata without copying CRYPTO buffers. STREAM
application bytes are skipped. Raw capture exports still contain packet data.

For library consumers, `CryptoFrameReassembler::get_fragments()` now returns an
iterator of `(u64, &[u8])` instead of a borrowed `BTreeMap`. A wrapped deque can
yield two adjacent slices with their actual stream offsets.
`add_fragment()` and `get_contiguous_data()` retain their signatures.

QUIC wire lengths use checked conversions and offset arithmetic. SNMP BER
outer and nested lengths are also bounded by their declared containers.
Regression tests cover overlaps, reverse order, late ALPN, buffer release, and
32-bit length boundaries in debug and release CI.
