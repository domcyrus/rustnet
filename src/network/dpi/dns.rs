use crate::network::types::{DnsInfo, DnsQueryType};

/// Maximum DNS name length per RFC 1035 section 2.3.4
const MAX_DNS_NAME_LEN: usize = 253;

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
}
