//! Shared connection and protocol types: connection identity and state,
//! per-protocol DPI info, traffic history, rate tracking, and RTT
//! measurement.

/// Give a fieldless enum a fixed name per variant: emits `as_str` returning
/// the `&'static str` and a `Display` impl that writes it.
///
/// Optional attributes before the enum name (typically a doc comment) are
/// applied to the generated `as_str`. Writing `Enum(self)` instead of `Enum`
/// makes `as_str` take its receiver by value, for `Copy` enums whose public
/// signature is already by value.
macro_rules! static_names {
    (@display $Enum:ident) => {
        impl ::std::fmt::Display for $Enum {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
    ($Enum:ident $(($recv:tt))? { $($Variant:ident => $name:literal),+ $(,)? }) => {
        static_names! {
            /// Fixed name of this variant, as `Display` renders it.
            $Enum $(($recv))? { $($Variant => $name),+ }
        }
    };
    ($(#[$meta:meta])+ $Enum:ident (self) { $($Variant:ident => $name:literal),+ $(,)? }) => {
        impl $Enum {
            $(#[$meta])+
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$Variant => $name,)+
                }
            }
        }
        static_names!(@display $Enum);
    };
    ($(#[$meta:meta])+ $Enum:ident { $($Variant:ident => $name:literal),+ $(,)? }) => {
        impl $Enum {
            $(#[$meta])+
            pub const fn as_str(&self) -> &'static str {
                match self {
                    $(Self::$Variant => $name,)+
                }
            }
        }
        static_names!(@display $Enum);
    };
}

mod connection;
mod graph;
mod identity;
mod protocol_info;
mod rates;
mod rtt;

pub use connection::*;
pub use graph::*;
pub use identity::*;
pub use protocol_info::*;
pub use rates::*;
pub use rtt::*;

/// Fixture builders shared by the unit tests of this module: socket
/// addresses and connection keys from `"ip:port"` literals, minimal
/// connections, and the DPI payloads the state/timeout tests exercise.
#[cfg(test)]
pub(crate) mod test_support {
    use super::{
        ApplicationProtocol, Connection, ConnectionKey, DnsInfo, DnsQueryType, DpiInfo, Protocol,
        ProtocolState, QuicInfo,
    };
    use std::net::SocketAddr;

    /// Parse an `"ip:port"` literal into a socket address.
    pub(crate) fn addr(literal: &str) -> SocketAddr {
        literal
            .parse()
            .unwrap_or_else(|e| panic!("invalid test address {literal:?}: {e}"))
    }

    /// Connection key from `"ip:port"` literals.
    pub(crate) fn key(protocol: Protocol, local: &str, remote: &str) -> ConnectionKey {
        ConnectionKey::new(protocol, addr(local), addr(remote))
    }

    /// Fresh connection from `"ip:port"` literals.
    pub(crate) fn conn(
        protocol: Protocol,
        local: &str,
        remote: &str,
        state: ProtocolState,
    ) -> Connection {
        Connection::new(protocol, addr(local), addr(remote), state)
    }

    /// Fresh UDP connection from `"ip:port"` literals.
    pub(crate) fn udp_conn(local: &str, remote: &str) -> Connection {
        conn(Protocol::Udp, local, remote, ProtocolState::Udp)
    }

    /// An A query for `example.com` (txid 0x1234), or its NOERROR response
    /// carrying one address.
    pub(crate) fn dns_info(is_response: bool) -> DnsInfo {
        DnsInfo {
            query_name: Some("example.com".to_string()),
            query_type: Some(DnsQueryType::A),
            response_ips: if is_response {
                vec!["93.184.216.34".parse().unwrap()]
            } else {
                Vec::new()
            },
            is_response,
            txid: 0x1234,
            rcode: is_response.then_some(0),
            nodata: is_response.then_some(false),
        }
    }

    /// DPI info wrapping a QUIC connection.
    pub(crate) fn quic_dpi(info: QuicInfo) -> DpiInfo {
        DpiInfo {
            application: ApplicationProtocol::Quic(Box::new(info)),
        }
    }
}
