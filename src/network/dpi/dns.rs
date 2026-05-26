use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::network::types::{DnsInfo, DnsQueryType};

/// Maximum DNS name length per RFC 1035 section 2.3.4
const MAX_DNS_NAME_LEN: usize = 253;

/// Cap on how many answer records we will walk for a single packet. Real
/// resolver answers are well under this; the bound is here to keep a
/// malformed `ancount` from spinning the parser.
const MAX_ANSWERS_TO_PARSE: usize = 64;

/// Cap on response IPs we surface per packet. The UI only renders a short
/// list anyway, and the merge layer dedups across the flow, so anything
/// beyond this is noise we'd rather drop than allocate for.
const MAX_RESPONSE_IPS_PER_PACKET: usize = 16;

/// Cap on how many pointer indirections we follow while skipping a name in
/// the answer section. Per RFC 1035 these must not form cycles; this cap
/// keeps a crafted packet from looping forever.
const MAX_NAME_POINTER_HOPS: usize = 16;

/// Walk a DNS name in the answer section and return the offset of the
/// byte immediately after the name (where TYPE / CLASS / TTL / RDLENGTH
/// start). Compression pointers (0xC0-prefixed two-byte sequences) terminate
/// the name in-place, so the returned offset is two past the start of the
/// pointer. Returns `None` if the name is malformed or runs off the end of
/// the payload.
fn skip_dns_name(payload: &[u8], start: usize) -> Option<usize> {
    let mut offset = start;
    let mut hops = 0;
    loop {
        if offset >= payload.len() {
            return None;
        }
        let label_len = payload[offset] as usize;
        if label_len == 0 {
            return Some(offset + 1);
        }
        if label_len & 0xC0 == 0xC0 {
            // Pointer: two bytes total, name ends here at the call site.
            if offset + 1 >= payload.len() {
                return None;
            }
            hops += 1;
            if hops > MAX_NAME_POINTER_HOPS {
                return None;
            }
            return Some(offset + 2);
        }
        // Reject reserved length-octet top bits (0x40 / 0x80) — neither
        // standard label nor pointer.
        if label_len & 0xC0 != 0 {
            return None;
        }
        let next = offset.checked_add(1)?.checked_add(label_len)?;
        if next > payload.len() {
            return None;
        }
        offset = next;
    }
}

pub fn analyze_dns(payload: &[u8]) -> Option<DnsInfo> {
    if payload.len() < 12 {
        return None;
    }

    let mut info = DnsInfo {
        query_name: None,
        query_type: None,
        response_ips: Vec::new(),
        is_response: false,
    };

    // DNS header flags
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    info.is_response = (flags & 0x8000) != 0; // QR bit

    // Question count
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);

    if qdcount > 0 {
        // Parse first question
        let mut offset = 12;
        let mut name = String::new();

        // Parse domain name
        while offset < payload.len() {
            let label_len = payload[offset] as usize;
            if label_len == 0 {
                offset += 1;
                break;
            }

            if label_len >= 0xC0 {
                // Compressed name - skip for simplicity
                offset += 2;
                break;
            }

            if offset + 1 + label_len > payload.len() {
                break;
            }

            if !name.is_empty() {
                name.push('.');
            }

            if let Ok(label) = std::str::from_utf8(&payload[offset + 1..offset + 1 + label_len]) {
                name.push_str(label);
            }

            // Enforce RFC 1035 maximum name length
            if name.len() > MAX_DNS_NAME_LEN {
                break;
            }

            offset += 1 + label_len;
        }

        if !name.is_empty() {
            info.query_name = Some(name);
        }

        // Query type
        if offset + 2 <= payload.len() {
            let qtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
            info.query_type = Some(match qtype {
                1 => DnsQueryType::A,
                2 => DnsQueryType::NS,
                5 => DnsQueryType::CNAME,
                6 => DnsQueryType::SOA,
                12 => DnsQueryType::PTR,
                13 => DnsQueryType::HINFO,
                15 => DnsQueryType::MX,
                16 => DnsQueryType::TXT,
                17 => DnsQueryType::RP,
                18 => DnsQueryType::AFSDB,
                24 => DnsQueryType::SIG,
                25 => DnsQueryType::KEY,
                28 => DnsQueryType::AAAA,
                29 => DnsQueryType::LOC,
                33 => DnsQueryType::SRV,
                35 => DnsQueryType::NAPTR,
                36 => DnsQueryType::KX,
                37 => DnsQueryType::CERT,
                39 => DnsQueryType::DNAME,
                42 => DnsQueryType::APL,
                43 => DnsQueryType::DS,
                44 => DnsQueryType::SSHFP,
                45 => DnsQueryType::IPSECKEY,
                46 => DnsQueryType::RRSIG,
                47 => DnsQueryType::NSEC,
                48 => DnsQueryType::DNSKEY,
                49 => DnsQueryType::DHCID,
                50 => DnsQueryType::NSEC3,
                51 => DnsQueryType::NSEC3PARAM,
                52 => DnsQueryType::TLSA,
                53 => DnsQueryType::SMIMEA,
                55 => DnsQueryType::HIP,
                59 => DnsQueryType::CDS,
                60 => DnsQueryType::CDNSKEY,
                61 => DnsQueryType::OPENPGPKEY,
                62 => DnsQueryType::CSYNC,
                63 => DnsQueryType::ZONEMD,
                64 => DnsQueryType::SVCB,
                65 => DnsQueryType::HTTPS,
                108 => DnsQueryType::EUI48,
                109 => DnsQueryType::EUI64,
                249 => DnsQueryType::TKEY,
                250 => DnsQueryType::TSIG,
                256 => DnsQueryType::URI,
                257 => DnsQueryType::CAA,
                32768 => DnsQueryType::TA,
                32769 => DnsQueryType::DLV,
                other => DnsQueryType::Other(other),
            });
            // Advance past QTYPE (2) and QCLASS (2) so the answer-section
            // walk below starts at the first answer record. If QCLASS runs
            // past the payload, the answer walk's bounds checks will
            // short-circuit cleanly.
            offset = offset.saturating_add(4);
        }

        // Answer-section walk for A / AAAA records. Only runs on responses
        // (QR bit set), since the original DnsInfo.response_ips field is
        // only meaningful for resolver answers.
        if info.is_response {
            let ancount = u16::from_be_bytes([payload[6], payload[7]]) as usize;
            let ancount = ancount.min(MAX_ANSWERS_TO_PARSE);
            for _ in 0..ancount {
                let after_name = match skip_dns_name(payload, offset) {
                    Some(o) => o,
                    None => break,
                };
                // Fixed-size answer fields: TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2) = 10
                if after_name
                    .checked_add(10)
                    .map(|e| e > payload.len())
                    .unwrap_or(true)
                {
                    break;
                }
                let atype = u16::from_be_bytes([payload[after_name], payload[after_name + 1]]);
                let rdlength =
                    u16::from_be_bytes([payload[after_name + 8], payload[after_name + 9]]) as usize;
                let rdata_start = after_name + 10;
                let rdata_end = match rdata_start.checked_add(rdlength) {
                    Some(e) if e <= payload.len() => e,
                    _ => break,
                };

                if info.response_ips.len() < MAX_RESPONSE_IPS_PER_PACKET {
                    match (atype, rdlength) {
                        (1, 4) => {
                            // A record
                            let octets: [u8; 4] = payload[rdata_start..rdata_end]
                                .try_into()
                                .expect("rdlength==4 and bounds checked above");
                            info.response_ips.push(IpAddr::V4(Ipv4Addr::from(octets)));
                        }
                        (28, 16) => {
                            // AAAA record
                            let octets: [u8; 16] = payload[rdata_start..rdata_end]
                                .try_into()
                                .expect("rdlength==16 and bounds checked above");
                            info.response_ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
                        }
                        _ => {
                            // CNAME, NS, SOA, etc. — not surfaced through
                            // response_ips; skip rdata and continue.
                        }
                    }
                }

                offset = rdata_end;
            }
        }
    }

    Some(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_payload_safe() {
        assert!(analyze_dns(&[]).is_none());
    }

    #[test]
    fn test_short_payload_safe() {
        assert!(analyze_dns(&[0; 5]).is_none());
    }

    #[test]
    fn test_dns_name_length_limit() {
        // Build a DNS packet with many 63-byte labels (exceeding 253 chars)
        let mut payload = vec![0u8; 12]; // DNS header
        // Set qdcount = 1
        payload[5] = 1;
        // Add 10 labels of 63 bytes each (630+ chars total, exceeds 253)
        for _ in 0..10 {
            payload.push(63); // label length
            payload.extend_from_slice(&[b'a'; 63]);
        }
        payload.push(0); // null terminator
        payload.extend_from_slice(&[0, 1, 0, 1]); // QTYPE A, QCLASS IN

        let info = analyze_dns(&payload).unwrap();
        if let Some(name) = &info.query_name {
            // Name should be truncated near the RFC limit, not the full 630+ chars
            assert!(name.len() <= MAX_DNS_NAME_LEN + 63 + 1);
        }
    }

    #[test]
    fn test_normal_dns_query() {
        // Build a simple query for "example.com"
        let mut payload = vec![0u8; 12]; // DNS header
        payload[5] = 1; // qdcount = 1
        // "example" label
        payload.push(7);
        payload.extend_from_slice(b"example");
        // "com" label
        payload.push(3);
        payload.extend_from_slice(b"com");
        // null terminator
        payload.push(0);
        // QTYPE A (1), QCLASS IN (1)
        payload.extend_from_slice(&[0, 1, 0, 1]);

        let info = analyze_dns(&payload).unwrap();
        assert_eq!(info.query_name, Some("example.com".to_string()));
        assert_eq!(info.query_type, Some(DnsQueryType::A));
        assert!(!info.is_response);
    }

    /// Helper: build a baseline question-section payload for `example.com / A`.
    /// Returns the payload and the offset that points at the byte right after
    /// the question section, where answer records start.
    fn make_example_question(qr_bit: bool, ancount: u16) -> (Vec<u8>, usize) {
        let mut payload = vec![0u8; 12];
        // Flags: QR bit when this is a response
        if qr_bit {
            payload[2] = 0x80;
        }
        // qdcount = 1
        payload[4] = 0;
        payload[5] = 1;
        // ancount
        payload[6..8].copy_from_slice(&ancount.to_be_bytes());
        // "example"
        payload.push(7);
        payload.extend_from_slice(b"example");
        // "com"
        payload.push(3);
        payload.extend_from_slice(b"com");
        // null terminator
        payload.push(0);
        // QTYPE A (1), QCLASS IN (1)
        payload.extend_from_slice(&[0, 1, 0, 1]);
        let answers_start = payload.len();
        (payload, answers_start)
    }

    #[test]
    fn test_response_with_single_a_record_populates_ip() {
        // Response with one A record pointing to 93.184.216.34 (the public
        // example.com address). The answer name uses a compression pointer
        // back to the question, which is the common wire shape.
        let (mut payload, _answers_start) = make_example_question(true, 1);

        // NAME: pointer to offset 12 (start of question name).
        payload.extend_from_slice(&[0xC0, 0x0C]);
        // TYPE A, CLASS IN, TTL 60, RDLENGTH 4
        payload.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        // RDATA: 93.184.216.34
        payload.extend_from_slice(&[93, 184, 216, 34]);

        let info = analyze_dns(&payload).unwrap();
        assert!(info.is_response);
        assert_eq!(
            info.response_ips,
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
        );
    }

    #[test]
    fn test_response_with_aaaa_record_populates_ipv6() {
        let (mut payload, _) = make_example_question(true, 1);
        payload.extend_from_slice(&[0xC0, 0x0C]); // pointer to question name
        // TYPE AAAA (28), CLASS IN, TTL 60, RDLENGTH 16
        payload.extend_from_slice(&[0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
        payload.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);

        let info = analyze_dns(&payload).unwrap();
        assert_eq!(info.response_ips.len(), 1);
        assert!(matches!(info.response_ips[0], IpAddr::V6(_)));
    }

    #[test]
    fn test_response_mixed_records_collects_a_and_aaaa_skips_cname() {
        // Three answers: CNAME (skipped — not surfaced via response_ips),
        // A, AAAA. Order matters; the parser must walk past CNAME's
        // rdata correctly to reach the IP records.
        let (mut payload, _) = make_example_question(true, 3);

        // 1) CNAME record. RDATA = pointer to "example.com" at offset 12 (2 bytes).
        payload.extend_from_slice(&[0xC0, 0x0C]); // NAME
        payload.extend_from_slice(&[0, 5, 0, 1, 0, 0, 0, 60, 0, 2]); // TYPE CNAME (5), CLASS IN, TTL, RDLENGTH 2
        payload.extend_from_slice(&[0xC0, 0x0C]); // RDATA: compressed name pointer

        // 2) A record 1.2.3.4
        payload.extend_from_slice(&[0xC0, 0x0C]);
        payload.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        payload.extend_from_slice(&[1, 2, 3, 4]);

        // 3) AAAA record ::1
        payload.extend_from_slice(&[0xC0, 0x0C]);
        payload.extend_from_slice(&[0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
        payload.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        let info = analyze_dns(&payload).unwrap();
        assert_eq!(
            info.response_ips,
            vec![
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ]
        );
    }

    #[test]
    fn test_query_packet_leaves_response_ips_empty() {
        // QR bit clear ⇒ this is a question, not a response. Even if a
        // (malformed) packet stuffs answer-shaped bytes after the question,
        // the parser must not surface any IPs because the field is only
        // meaningful for resolver answers.
        let (mut payload, _) = make_example_question(false, 1);
        payload.extend_from_slice(&[0xC0, 0x0C]);
        payload.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        payload.extend_from_slice(&[8, 8, 8, 8]);

        let info = analyze_dns(&payload).unwrap();
        assert!(!info.is_response);
        assert!(info.response_ips.is_empty());
    }

    #[test]
    fn test_truncated_rdata_does_not_panic() {
        // Claims RDLENGTH 4 but only supplies 2 bytes of rdata. The walk
        // must stop cleanly, not panic on the slice access.
        let (mut payload, _) = make_example_question(true, 1);
        payload.extend_from_slice(&[0xC0, 0x0C]);
        payload.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        payload.extend_from_slice(&[1, 2]); // only 2 bytes of rdata

        let info = analyze_dns(&payload).unwrap();
        assert!(info.response_ips.is_empty());
    }

    #[test]
    fn test_response_ips_capped_per_packet() {
        // Build a response with more A records than the per-packet cap.
        // The parser must surface at most MAX_RESPONSE_IPS_PER_PACKET IPs
        // even when ancount and the wire payload are both larger.
        let n: u16 = (MAX_RESPONSE_IPS_PER_PACKET as u16) + 4;
        let (mut payload, _) = make_example_question(true, n);
        for i in 0..n {
            payload.extend_from_slice(&[0xC0, 0x0C]);
            payload.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
            payload.extend_from_slice(&[10, 0, 0, (i & 0xFF) as u8]);
        }

        let info = analyze_dns(&payload).unwrap();
        assert_eq!(info.response_ips.len(), MAX_RESPONSE_IPS_PER_PACKET);
    }
}
