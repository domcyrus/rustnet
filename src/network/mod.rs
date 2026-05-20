//! Networking layer for the `rustnet` binary.
//!
//! The platform-independent analysis core — parsers, DPI, protocol/connection
//! types, connection merging, GeoIP/DNS/OUI lookups, and interface-stats
//! traits — lives in the [`rustnet_core`] library crate and is re-exported here
//! so existing `crate::network::*` paths keep resolving unchanged.
//!
//! The modules that remain in the binary are the ones tied to the running host:
//! platform-specific process attribution and sandboxing ([`platform`]) and the
//! [`privileges`] preflight check. libpcap-based packet capture now lives in the
//! [`rustnet_capture`] crate and is re-exported here as [`capture`] so existing
//! `crate::network::capture::*` paths keep resolving.

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
    bogon, dns, dpi, geoip, interface_stats, link_layer, merge, oui, parser, protocol, services,
    tracker, types,
};
