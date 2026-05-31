//! LLMNR (Link-Local Multicast Name Resolution) Deep Packet Inspection
//!
//! Parses LLMNR packets according to RFC 4795.
//! LLMNR uses UDP port 5355 and shares the same wire format as DNS.

use crate::network::types::LlmnrInfo;

use super::dns;

/// Analyze an LLMNR packet and extract key information.
///
/// LLMNR uses the same packet format as DNS, so we reuse the DNS parser.
/// Returns `None` if the packet cannot be parsed as DNS.
pub fn analyze_llmnr(payload: &[u8]) -> Option<LlmnrInfo> {
    // Reuse DNS parser - LLMNR has the same wire format
    let dns_info = dns::analyze_dns(payload)?;

    Some(LlmnrInfo {
        query_name: dns_info.query_name,
        query_type: dns_info.query_type,
        is_response: dns_info.is_response,
        response_ips: dns_info.response_ips,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::types::DnsQueryType;

    fn build_llmnr_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut packet = Vec::new();

        // DNS header (12 bytes)
        packet.extend_from_slice(&[0x00, 0x01]); // Transaction ID
        packet.extend_from_slice(&[0x00, 0x00]); // Flags (query)
        packet.extend_from_slice(&[0x00, 0x01]); // Questions: 1
        packet.extend_from_slice(&[0x00, 0x00]); // Answer RRs: 0
        packet.extend_from_slice(&[0x00, 0x00]); // Authority RRs: 0
        packet.extend_from_slice(&[0x00, 0x00]); // Additional RRs: 0

        // Question section - encode name (single label for LLMNR)
        packet.push(name.len() as u8);
        packet.extend_from_slice(name.as_bytes());
        packet.push(0x00); // Null terminator

        // Query type and class
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x01]); // Class: IN

        packet
    }

    fn build_llmnr_response(name: &str, qtype: u16) -> Vec<u8> {
        let mut packet = Vec::new();

        // DNS header (12 bytes)
        packet.extend_from_slice(&[0x00, 0x01]); // Transaction ID
        packet.extend_from_slice(&[0x80, 0x00]); // Flags (response)
        packet.extend_from_slice(&[0x00, 0x01]); // Questions: 1
        packet.extend_from_slice(&[0x00, 0x00]); // Answer RRs: 0
        packet.extend_from_slice(&[0x00, 0x00]); // Authority RRs: 0
        packet.extend_from_slice(&[0x00, 0x00]); // Additional RRs: 0

        // Question section
        packet.push(name.len() as u8);
        packet.extend_from_slice(name.as_bytes());
        packet.push(0x00);
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x01]);

        packet
    }

    #[test]
    fn test_llmnr_query() {
        let packet = build_llmnr_query("workstation", 1); // A query
        let info = analyze_llmnr(&packet).expect("should parse");
        assert_eq!(info.query_name, Some("workstation".to_string()));
        assert_eq!(info.query_type, Some(DnsQueryType::A));
        assert!(!info.is_response);
    }

    #[test]
    fn test_llmnr_response() {
        let packet = build_llmnr_response("fileserver", 1);
        let info = analyze_llmnr(&packet).expect("should parse");
        assert_eq!(info.query_name, Some("fileserver".to_string()));
        assert!(info.is_response);
    }

    #[test]
    fn test_llmnr_aaaa_query() {
        let packet = build_llmnr_query("mypc", 28); // AAAA query
        let info = analyze_llmnr(&packet).expect("should parse");
        assert_eq!(info.query_type, Some(DnsQueryType::AAAA));
    }

    #[test]
    fn test_llmnr_too_short() {
        let packet = [0u8; 8];
        assert!(analyze_llmnr(&packet).is_none());
    }

    /// Build an LLMNR response that echoes the question and supplies an A
    /// record. RFC 4795 §2.1: LLMNR responses re-include the question.
    fn build_llmnr_response_with_a(name: &str, ip: [u8; 4]) -> Vec<u8> {
        let mut packet = Vec::new();
        // Header: txid 1, flags response, qdcount=1, ancount=1, ns=0, ar=0.
        packet.extend_from_slice(&[0x00, 0x01, 0x80, 0x00, 0x00, 0x01, 0x00, 0x01]);
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // Question (single label).
        packet.push(name.len() as u8);
        packet.extend_from_slice(name.as_bytes());
        packet.push(0x00);
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE A, QCLASS IN
        // Answer: NAME pointer back to offset 12, TYPE A, CLASS IN, TTL, RDLENGTH 4, RDATA.
        packet.extend_from_slice(&[
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04,
        ]);
        packet.extend_from_slice(&ip);
        packet
    }

    #[test]
    fn test_llmnr_response_populates_response_ips() {
        let packet = build_llmnr_response_with_a("workstation", [192, 168, 1, 42]);
        let info = analyze_llmnr(&packet).expect("should parse");
        assert!(info.is_response);
        assert_eq!(info.query_name, Some("workstation".to_string()));
        assert_eq!(
            info.response_ips,
            vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                192, 168, 1, 42
            ))]
        );
    }

    #[test]
    fn test_llmnr_query_leaves_response_ips_empty() {
        let packet = build_llmnr_query("workstation", 1);
        let info = analyze_llmnr(&packet).expect("should parse");
        assert!(!info.is_response);
        assert!(info.response_ips.is_empty());
    }
}
