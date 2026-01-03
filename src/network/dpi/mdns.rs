//! mDNS (Multicast DNS) Deep Packet Inspection
//!
//! Parses mDNS packets according to RFC 6762.
//! mDNS uses UDP port 5353 and shares the same wire format as DNS.

use crate::network::types::MdnsInfo;

use super::dns;

/// Analyze an mDNS packet and extract key information.
///
/// mDNS uses the same packet format as DNS, so we reuse the DNS parser.
/// Returns `None` if the packet cannot be parsed as DNS.
pub fn analyze_mdns(payload: &[u8]) -> Option<MdnsInfo> {
    // Reuse DNS parser - mDNS has the same wire format
    let dns_info = dns::analyze_dns(payload)?;

    Some(MdnsInfo {
        query_name: dns_info.query_name,
        query_type: dns_info.query_type,
        is_response: dns_info.is_response,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::types::DnsQueryType;

    fn build_mdns_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut packet = Vec::new();

        // DNS header (12 bytes)
        packet.extend_from_slice(&[0x00, 0x00]); // Transaction ID
        packet.extend_from_slice(&[0x00, 0x00]); // Flags (query)
        packet.extend_from_slice(&[0x00, 0x01]); // Questions: 1
        packet.extend_from_slice(&[0x00, 0x00]); // Answer RRs: 0
        packet.extend_from_slice(&[0x00, 0x00]); // Authority RRs: 0
        packet.extend_from_slice(&[0x00, 0x00]); // Additional RRs: 0

        // Question section - encode domain name
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0x00); // Null terminator

        // Query type and class
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x01]); // Class: IN

        packet
    }

    fn build_mdns_response(name: &str, qtype: u16) -> Vec<u8> {
        let mut packet = Vec::new();

        // DNS header (12 bytes)
        packet.extend_from_slice(&[0x00, 0x00]); // Transaction ID
        packet.extend_from_slice(&[0x84, 0x00]); // Flags (response, authoritative)
        packet.extend_from_slice(&[0x00, 0x01]); // Questions: 1
        packet.extend_from_slice(&[0x00, 0x00]); // Answer RRs: 0
        packet.extend_from_slice(&[0x00, 0x00]); // Authority RRs: 0
        packet.extend_from_slice(&[0x00, 0x00]); // Additional RRs: 0

        // Question section
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0x00);
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x01]);

        packet
    }

    #[test]
    fn test_mdns_query() {
        let packet = build_mdns_query("_http._tcp.local", 12); // PTR query
        let info = analyze_mdns(&packet).expect("should parse");
        assert_eq!(info.query_name, Some("_http._tcp.local".to_string()));
        assert_eq!(info.query_type, Some(DnsQueryType::PTR));
        assert!(!info.is_response);
    }

    #[test]
    fn test_mdns_response() {
        let packet = build_mdns_response("mydevice.local", 1); // A record
        let info = analyze_mdns(&packet).expect("should parse");
        assert_eq!(info.query_name, Some("mydevice.local".to_string()));
        assert_eq!(info.query_type, Some(DnsQueryType::A));
        assert!(info.is_response);
    }

    #[test]
    fn test_mdns_too_short() {
        let packet = [0u8; 5];
        assert!(analyze_mdns(&packet).is_none());
    }

    #[test]
    fn test_mdns_srv_query() {
        let packet = build_mdns_query("_printer._tcp.local", 33); // SRV query
        let info = analyze_mdns(&packet).expect("should parse");
        assert_eq!(info.query_name, Some("_printer._tcp.local".to_string()));
        assert_eq!(info.query_type, Some(DnsQueryType::SRV));
    }
}
