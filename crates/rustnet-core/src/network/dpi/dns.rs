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

/// Parse a single question section and return `(query_name, query_type,
/// offset_after_question)`. The offset advances past QNAME + QTYPE (2) +
/// QCLASS (2); if QTYPE / QCLASS run off the end the offset still moves to
/// keep skip-only callers (qdcount > 1) bounds-safe.
fn parse_question(payload: &[u8], start: usize) -> (Option<String>, Option<DnsQueryType>, usize) {
    let mut offset = start;
    let mut name = String::new();
    let mut name_over_limit = false;

    // Parse domain name (label-by-label, with light pointer handling — we
    // only need to terminate the walk, not fully resolve compressed labels).
    while offset < payload.len() {
        let label_len = payload[offset] as usize;
        if label_len == 0 {
            offset += 1;
            break;
        }

        if label_len & 0xC0 == 0xC0 {
            // Compressed name — skip for simplicity.
            offset += 2;
            break;
        }

        // Reject reserved length-octet top bits (0x40 / 0x80) — neither a
        // standard label nor a pointer (RFC 1035 §3.3). Stop the walk so the
        // invalid bytes are not pulled into the name, matching skip_dns_name.
        if label_len & 0xC0 != 0 {
            break;
        }

        if offset + 1 + label_len > payload.len() {
            break;
        }

        if !name_over_limit {
            if !name.is_empty() {
                name.push('.');
            }

            if let Ok(label) = std::str::from_utf8(&payload[offset + 1..offset + 1 + label_len]) {
                name.push_str(label);
            }

            // Enforce RFC 1035 maximum name length: stop accumulating, but
            // keep walking the remaining labels so `offset` ends up past the
            // whole QNAME — otherwise QTYPE/QCLASS would be read from name
            // bytes and report a fabricated query type.
            if name.len() > MAX_DNS_NAME_LEN {
                name_over_limit = true;
            }
        }

        offset += 1 + label_len;
    }

    let query_name = if name.is_empty() { None } else { Some(name) };

    let mut query_type = None;
    if offset + 2 <= payload.len() {
        let qtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        query_type = Some(match qtype {
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
    // Advance past QTYPE (2) and QCLASS (2). If they run past the payload,
    // downstream walks' bounds checks will short-circuit cleanly.
    offset = offset.saturating_add(4);

    (query_name, query_type, offset)
}

/// Walk `count` resource records starting at `offset`, pushing A / AAAA
/// rdata into `ips` (subject to [`MAX_RESPONSE_IPS_PER_PACKET`]). Returns
/// the offset of the byte immediately after the last record successfully
/// walked, so callers can chain a second walk (e.g. ANCOUNT then ARCOUNT
/// for mDNS).
fn walk_a_aaaa_records(payload: &[u8], start: usize, count: usize, ips: &mut Vec<IpAddr>) -> usize {
    let mut offset = start;
    let count = count.min(MAX_ANSWERS_TO_PARSE);
    for _ in 0..count {
        let after_name = match skip_dns_name(payload, offset) {
            Some(o) => o,
            None => return offset,
        };
        // Fixed-size RR fields: TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2) = 10.
        if after_name
            .checked_add(10)
            .map(|e| e > payload.len())
            .unwrap_or(true)
        {
            return offset;
        }
        let atype = u16::from_be_bytes([payload[after_name], payload[after_name + 1]]);
        let rdlength =
            u16::from_be_bytes([payload[after_name + 8], payload[after_name + 9]]) as usize;
        let rdata_start = after_name + 10;
        let rdata_end = match rdata_start.checked_add(rdlength) {
            Some(e) if e <= payload.len() => e,
            _ => return offset,
        };

        if ips.len() < MAX_RESPONSE_IPS_PER_PACKET {
            match (atype, rdlength) {
                (1, 4) => {
                    let octets: [u8; 4] = payload[rdata_start..rdata_end]
                        .try_into()
                        .expect("rdlength==4 and bounds checked above");
                    ips.push(IpAddr::V4(Ipv4Addr::from(octets)));
                }
                (28, 16) => {
                    let octets: [u8; 16] = payload[rdata_start..rdata_end]
                        .try_into()
                        .expect("rdlength==16 and bounds checked above");
                    ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
                }
                _ => {
                    // CNAME, NS, SOA, PTR, SRV, TXT, … — not surfaced.
                }
            }
        }

        offset = rdata_end;
    }
    offset
}

/// Parsed DNS-shaped header counts. Surfaced as a thin internal helper so
/// the mDNS / LLMNR wrappers can also reach ARCOUNT without re-decoding.
pub(super) struct DnsHeaderCounts {
    pub is_response: bool,
    pub qdcount: u16,
    pub ancount: u16,
    pub arcount: u16,
}

/// Decode the four 16-bit counts at the start of a DNS-shaped header.
pub(super) fn dns_header_counts(payload: &[u8]) -> Option<DnsHeaderCounts> {
    if payload.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    Some(DnsHeaderCounts {
        is_response: (flags & 0x8000) != 0,
        qdcount: u16::from_be_bytes([payload[4], payload[5]]),
        ancount: u16::from_be_bytes([payload[6], payload[7]]),
        arcount: u16::from_be_bytes([payload[10], payload[11]]),
    })
}

/// Walk `qdcount` question sections starting at offset 12 and return the
/// `(query_name, query_type, offset_after_all_questions)` triple. The name
/// and type are taken from the **first** question (matching prior behaviour
/// and the DNS / mDNS / LLMNR convention of one question per packet);
/// subsequent questions are skipped only so the answer-walk starts at the
/// correct offset (#333: multi-question packets used to leave the offset
/// misaligned, which could surface bogus IPs from the answer walk).
pub(super) fn parse_questions_starting_at_header(
    payload: &[u8],
    qdcount: u16,
) -> (Option<String>, Option<DnsQueryType>, usize) {
    let mut offset = 12;
    let mut query_name = None;
    let mut query_type = None;
    for i in 0..qdcount {
        let (name, qtype, next) = parse_question(payload, offset);
        if i == 0 {
            query_name = name;
            query_type = qtype;
        }
        offset = next;
        if offset > payload.len() {
            break;
        }
    }
    (query_name, query_type, offset)
}

pub fn analyze_dns(payload: &[u8]) -> Option<DnsInfo> {
    let header = dns_header_counts(payload)?;
    let (query_name, query_type, mut offset) =
        parse_questions_starting_at_header(payload, header.qdcount);

    let mut info = DnsInfo {
        query_name,
        query_type,
        response_ips: Vec::new(),
        is_response: header.is_response,
    };

    // Answer-section walk for A / AAAA records. Only runs on responses
    // (QR bit set), since `DnsInfo.response_ips` is only meaningful for
    // resolver answers.
    if header.is_response {
        offset = walk_a_aaaa_records(
            payload,
            offset,
            header.ancount as usize,
            &mut info.response_ips,
        );
        // `offset` is now positioned for callers that want to keep walking
        // (e.g. mDNS's additional-records pass — see `analyze_dns_for_mdns`).
        let _ = offset;
    }

    Some(info)
}

/// mDNS-specific variant of [`analyze_dns`]: like the DNS path but also
/// walks the **additional records** (ARCOUNT) and tolerates packets with
/// `qdcount == 0` (RFC 6762 §6 — typical mDNS announcements carry only
/// answers / additionals, no questions). The DNS / LLMNR path keeps the
/// stricter behaviour because their responses always echo the question.
pub(super) fn analyze_dns_for_mdns(payload: &[u8]) -> Option<DnsInfo> {
    let header = dns_header_counts(payload)?;
    let (query_name, query_type, mut offset) =
        parse_questions_starting_at_header(payload, header.qdcount);

    let mut info = DnsInfo {
        query_name,
        query_type,
        response_ips: Vec::new(),
        is_response: header.is_response,
    };

    if header.is_response {
        offset = walk_a_aaaa_records(
            payload,
            offset,
            header.ancount as usize,
            &mut info.response_ips,
        );
        // RFC 6762: mDNS responses frequently place A / AAAA in the
        // ADDITIONAL section (NSEC / negative responses, "known-answer
        // suppression"-related additionals, etc.). Skip NSCOUNT (the
        // authority section) records before reaching ADDITIONAL.
        if let Some(after_authority) = skip_records(payload, offset, header_nscount(payload)) {
            let _ = walk_a_aaaa_records(
                payload,
                after_authority,
                header.arcount as usize,
                &mut info.response_ips,
            );
        }
    }

    Some(info)
}

/// Decode the NSCOUNT (authority-records count) at bytes 8-9 of the header.
fn header_nscount(payload: &[u8]) -> u16 {
    if payload.len() < 12 {
        return 0;
    }
    u16::from_be_bytes([payload[8], payload[9]])
}

/// Skip `count` resource records starting at `offset` without collecting
/// rdata. Returns `None` on a malformed record so callers can stop chasing
/// trailing sections (e.g. don't walk ADDITIONAL if AUTHORITY is busted).
fn skip_records(payload: &[u8], start: usize, count: u16) -> Option<usize> {
    let mut offset = start;
    let count = (count as usize).min(MAX_ANSWERS_TO_PARSE);
    for _ in 0..count {
        let after_name = skip_dns_name(payload, offset)?;
        if after_name.checked_add(10)? > payload.len() {
            return None;
        }
        let rdlength =
            u16::from_be_bytes([payload[after_name + 8], payload[after_name + 9]]) as usize;
        let rdata_end = after_name.checked_add(10)?.checked_add(rdlength)?;
        if rdata_end > payload.len() {
            return None;
        }
        offset = rdata_end;
    }
    Some(offset)
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
        // The walk must still consume the whole QNAME so QTYPE is read from
        // the right offset — not fabricated from mid-name bytes.
        assert_eq!(info.query_type, Some(DnsQueryType::A));
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

    #[test]
    fn test_question_rejects_reserved_label_bits() {
        // A label octet whose top two bits are 01 (0x40) or 10 (0x80) is neither
        // a standard label nor a compression pointer (RFC 1035 §3.3). The name
        // walk must stop at it instead of reading it as a 64+ byte label and
        // pulling the following bytes into query_name. skip_dns_name already
        // rejects these; parse_question must be consistent.
        let mut payload = vec![0u8; 12];
        payload[5] = 1; // qdcount = 1
        // valid "abc" label
        payload.push(3);
        payload.extend_from_slice(b"abc");
        // reserved-bit label octet (0x40) followed by 64 bytes that must not be
        // absorbed into the name
        payload.push(0x40);
        payload.extend_from_slice(&[b'x'; 64]);
        // null terminator + QTYPE A / QCLASS IN
        payload.push(0);
        payload.extend_from_slice(&[0, 1, 0, 1]);

        let info = analyze_dns(&payload).unwrap();
        // Only the valid label before the reserved octet is kept.
        assert_eq!(info.query_name, Some("abc".to_string()));
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
    fn test_multi_question_offset_lands_on_first_answer() {
        // Two questions, one answer (A 1.2.3.4) for question 1.
        // Pre-#333 only the first question was skipped, so the answer-walk
        // offset would land inside the second question's bytes — usually
        // either bailing out via skip_dns_name or, worse, surfacing bogus
        // IPs. With multi-question skipping the parser must land on the
        // real answer and return exactly one IP.
        let mut payload = vec![0u8; 12];
        payload[2] = 0x80; // QR bit
        payload[5] = 2; // qdcount = 2
        payload[7] = 1; // ancount = 1
        // Q1: "example.com" / A
        payload.push(7);
        payload.extend_from_slice(b"example");
        payload.push(3);
        payload.extend_from_slice(b"com");
        payload.push(0);
        payload.extend_from_slice(&[0, 1, 0, 1]);
        // Q2: "test.net" / AAAA
        payload.push(4);
        payload.extend_from_slice(b"test");
        payload.push(3);
        payload.extend_from_slice(b"net");
        payload.push(0);
        payload.extend_from_slice(&[0, 28, 0, 1]);
        // Answer: pointer to Q1 name, A, IN, TTL 60, RDLENGTH 4, 1.2.3.4.
        payload.extend_from_slice(&[0xC0, 0x0C]);
        payload.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        payload.extend_from_slice(&[1, 2, 3, 4]);

        let info = analyze_dns(&payload).unwrap();
        // First question wins for query_name / query_type — matches the
        // single-question convention. The two-question hardening is purely
        // about answer-walk offset correctness.
        assert_eq!(info.query_name, Some("example.com".to_string()));
        assert_eq!(info.query_type, Some(DnsQueryType::A));
        assert_eq!(
            info.response_ips,
            vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]
        );
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
