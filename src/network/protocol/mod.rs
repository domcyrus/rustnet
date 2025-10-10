//! Transport layer protocol parsing
//!
//! This module handles transport layer protocols (Layer 4 of the OSI model):
//! - TCP (Transmission Control Protocol)
//! - UDP (User Datagram Protocol)
//! - ICMP (Internet Control Message Protocol)
//! - ICMPv6 (Internet Control Message Protocol for IPv6)

pub mod icmp;
pub mod tcp;
pub mod udp;

use std::net::IpAddr;

/// Common parameters for transport layer parsing
/// Note: Direction (is_outgoing) is determined by the protocol parsers
/// based on local_ips, not passed as a parameter
#[derive(Clone)]
pub struct TransportParams {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub packet_len: usize,
    pub process_name: Option<String>,
    pub process_id: Option<u32>,
}

impl TransportParams {
    pub fn new(
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
