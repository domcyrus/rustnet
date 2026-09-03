//! Networking layer for the `rustnet` binary.
//!
//! The analysis core lives in the [`rustnet_core`] library crate. Modules used
//! by the binary are re-exported here to keep its `crate::network::*` paths
//! concise.
//!
//! The host-tied binary modules are the `rustnet-host` process-lookup wiring
//! ([`platform`]) and the [`privileges`] preflight check. libpcap-based packet
//! capture lives in the [`rustnet_capture`] crate and is re-exported here as
//! [`capture`]; sandboxing and the root uid drop live in `rustnet-sandbox`.

#[cfg(feature = "kubernetes")]
pub mod kubernetes;
pub mod platform;
pub mod privileges;

// Re-exported under the historical path.
pub use rustnet_capture as capture;

// Re-export the analysis modules used by the binary and its tests.
pub use rustnet_core::network::{
    bogon, dns, geoip, interface_stats, link_layer, neighbors, oui, parser, process_activity,
    services, tracker, types, util,
};
