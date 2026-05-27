//! mDNS (Multicast DNS) Deep Packet Inspection
//!
//! Parses mDNS packets according to RFC 6762.
//! mDNS uses UDP port 5353 and shares the same wire format as DNS.

use crate::network::types::MdnsInfo;

use super::dns;

/// Analyze an mDNS packet and extract key information.
///
/// mDNS uses the same packet format as DNS, so we reuse the DNS parser.
/// We route through the mDNS-aware variant so the answer walk also runs
/// when `qdcount == 0` (RFC 6762 §6) and so the parser also walks
/// ADDITIONAL records, where mDNS frequently carries A / AAAA rdata.
///
/// Returns `None` if the packet cannot be parsed as DNS.
pub fn analyze_mdns(payload: &[u8]) -> Option<MdnsInfo> {
    let dns_info = dns::analyze_dns_for_mdns(payload)?;

    Some(MdnsInfo {
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

    /// Build an mDNS announcement (RFC 6762 §6: qdcount=0, ancount>=1).
    /// `name` is encoded uncompressed inside each answer record.
    fn build_mdns_announcement_a(name: &str, ip: [u8; 4]) -> Vec<u8> {
        let mut packet = Vec::new();
        // Header: txid 0, flags response, qdcount=0, ancount=1, nscount=0, arcount=0.
        packet.extend_from_slice(&[0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01]);
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // Answer: NAME uncompressed.
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0x00);
        // TYPE A, CLASS IN (cache-flush bit cleared), TTL 120, RDLENGTH 4, RDATA.
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04]);
        packet.extend_from_slice(&ip);
        packet
    }

    #[test]
    fn test_mdns_announcement_with_qdcount_zero_collects_a_record() {
        // RFC 6762 §6: typical mDNS announcement has qdcount=0 and ancount>=1.
        // Pre-#333 the answer walk lived inside `qdcount > 0`, so this
        // packet returned an empty `response_ips`.
        let packet = build_mdns_announcement_a("printer.local", [192, 168, 1, 50]);
        let info = analyze_mdns(&packet).expect("should parse");
        assert!(info.is_response);
        assert!(info.query_name.is_none());
        assert_eq!(
            info.response_ips,
            vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                192, 168, 1, 50
            ))]
        );
    }

    #[test]
    fn test_mdns_collects_a_record_from_additional_section() {
        // mDNS often carries A / AAAA in the ADDITIONAL section (arcount)
        // rather than answers — e.g. when responding to a PTR with the
        // SRV target's address records. Build: qdcount=0, ancount=1
        // (PTR), nscount=0, arcount=1 (A).
        let mut packet = Vec::new();
        packet.extend_from_slice(&[0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01]);
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        // ANSWER: PTR "_http._tcp.local" → "mybox._http._tcp.local"
        let ptr_name = "_http._tcp.local";
        for label in ptr_name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0x00);
        // TYPE PTR (12), CLASS IN, TTL, RDLENGTH 2 (compressed pointer back).
        packet.extend_from_slice(&[0x00, 0x0C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x02]);
        packet.extend_from_slice(&[0xC0, 0x0C]);
        // ADDITIONAL: A record for "host.local" → 10.0.0.5.
        let a_name = "host.local";
        for label in a_name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0x00);
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04]);
        packet.extend_from_slice(&[10, 0, 0, 5]);

        let info = analyze_mdns(&packet).expect("should parse");
        assert_eq!(
            info.response_ips,
            vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 5))]
        );
    }

    #[test]
    fn test_mdns_query_packet_response_ips_empty() {
        // Even if the wire has bytes after the question that look
        // answer-shaped, a query (QR bit clear) must not surface IPs.
        let packet = build_mdns_query("_http._tcp.local", 12);
        let info = analyze_mdns(&packet).expect("should parse");
        assert!(!info.is_response);
        assert!(info.response_ips.is_empty());
    }
}
