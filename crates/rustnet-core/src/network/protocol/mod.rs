//! Transport layer protocol parsing
//!
//! This module handles transport layer protocols (Layer 4 of the OSI model):
//! - TCP (Transmission Control Protocol)
//! - UDP (User Datagram Protocol)
//! - ICMP (Internet Control Message Protocol)
//! - ICMPv6 (Internet Control Message Protocol for IPv6)
//! - IGMP (Internet Group Management Protocol)
//! - NDP (Neighbor Discovery Protocol, link-layer address extraction only)

pub(crate) mod icmp;
pub(crate) mod igmp;
pub(crate) mod ndp;
pub mod tcp;
pub(crate) mod udp;

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

/// Common parameters for transport layer parsing
/// Note: Direction (is_outgoing) is determined by the protocol parsers
/// based on local_ips, not passed as a parameter
#[derive(Clone)]
pub(crate) struct TransportParams {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub packet_len: usize,
    pub process_name: Option<String>,
    pub process_id: Option<u32>,
}

impl TransportParams {
    pub(crate) fn new(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        packet_len: usize,
        process_name: Option<String>,
        process_id: Option<u32>,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            packet_len,
            process_name,
            process_id,
        }
    }
}

pub(super) fn orient_endpoints(
    params: &TransportParams,
    src_port: u16,
    dst_port: u16,
    local_ips: &HashSet<IpAddr>,
) -> (SocketAddr, SocketAddr, bool) {
    let is_outgoing = local_ips.contains(&params.src_ip);
    let source = SocketAddr::new(params.src_ip, src_port);
    let destination = SocketAddr::new(params.dst_ip, dst_port);
    if is_outgoing {
        (source, destination, true)
    } else {
        (destination, source, false)
    }
}
