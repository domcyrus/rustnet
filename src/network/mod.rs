//! Networking layer for the `rustnet` binary.
//!
//! The analysis core, including parsers, DPI, protocol/connection types,
//! connection merging, GeoIP/DNS/OUI lookups, and interface-stats providers,
//! lives in the [`rustnet_core`] library crate and is re-exported here so
//! existing `crate::network::*` paths keep resolving unchanged.
//!
//! The host-tied binary modules are the `rustnet-host` process-lookup wiring
//! ([`platform`]) and the [`privileges`] preflight check. libpcap-based packet
//! capture lives in the [`rustnet_capture`] crate and is re-exported here as
//! [`capture`]; sandboxing and the root uid drop live in `rustnet-sandbox`.

#[cfg(feature = "kubernetes")]
pub mod kubernetes;
pub mod platform;
pub mod privileges;

// pcap-based capture moved to the `rustnet-capture` crate; re-export it under
// the historical path so the app, tests, and platform code are unchanged.
pub use rustnet_capture as capture;

// Re-export the analysis core. Keeps `crate::network::types`, `::parser`,
// `::dpi`, `::link_layer`, etc. working for the rest of the binary, the
// integration tests, and the benches without touching their imports.
// `allow(unused_imports)`: the `rustnet` bin doesn't touch every module
// directly, but the `rustnet_monitor` lib re-exports the full facade for
// tests, benches, and external consumers.
#[allow(unused_imports)]
pub use rustnet_core::network::{
    bogon, dns, dpi, geoip, interface_stats, link_layer, merge, neighbors, oui, parser,
    process_activity, protocol, services, tracker, types, util,
};
