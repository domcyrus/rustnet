use crate::network::types::{DnsInfo, DnsQueryType};

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
                28 => DnsQueryType::AAAA,
                5 => DnsQueryType::CNAME,
                15 => DnsQueryType::MX,
                16 => DnsQueryType::TXT,
                other => DnsQueryType::Other(other),
            });
        }
    }

    Some(info)
}
