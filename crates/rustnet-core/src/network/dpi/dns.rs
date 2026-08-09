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
        query_type = Some(DnsQueryType::from_wire(qtype));
    }
    // Advance past QTYPE (2) and QCLASS (2). If they run past the payload,
    // downstream walks' bounds checks will short-circuit cleanly.
    offset = offset.saturating_add(4);

    (query_name, query_type, offset)
}

/// Walk `count` resource records starting at `offset`, pushing A / AAAA
/// rdata into `ips` (subject to [`MAX_RESPONSE_IPS_PER_PACKET`]) and counting
/// records whose TYPE matches `queried_type` into `matched` (for NODATA
/// detection; pass `None` to skip counting, e.g. on the mDNS additional-records
/// walk where the concept does not apply). Returns the offset of the byte
/// immediately after the last record successfully walked (so callers can
/// chain a second walk, e.g. ANCOUNT then ARCOUNT for mDNS) together with
/// the number of records fully walked (so callers can tell a complete walk
/// from one that bailed on a malformed or truncated record).
fn walk_a_aaaa_records(
    payload: &[u8],
    start: usize,
    count: usize,
    ips: &mut Vec<IpAddr>,
    queried_type: Option<DnsQueryType>,
    matched: &mut usize,
) -> (usize, usize) {
    let mut offset = start;
    let mut walked = 0;
    let count = count.min(MAX_ANSWERS_TO_PARSE);
    for _ in 0..count {
        let after_name = match skip_dns_name(payload, offset) {
            Some(o) => o,
            None => return (offset, walked),
        };
        // Fixed-size RR fields: TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2) = 10.
        if after_name
            .checked_add(10)
            .map(|e| e > payload.len())
            .unwrap_or(true)
        {
            return (offset, walked);
        }
        let atype = u16::from_be_bytes([payload[after_name], payload[after_name + 1]]);
        let rdlength =
            u16::from_be_bytes([payload[after_name + 8], payload[after_name + 9]]) as usize;
        let rdata_start = after_name + 10;
        let rdata_end = match rdata_start.checked_add(rdlength) {
            Some(e) if e <= payload.len() => e,
            _ => return (offset, walked),
        };

        if queried_type.is_some() && queried_type == Some(DnsQueryType::from_wire(atype)) {
            *matched += 1;
        }

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
        walked += 1;
    }
    (offset, walked)
}

/// RFC 2308 §2.2: a NODATA response carries an SOA record in the authority
/// section (types 1 and 2) or an empty authority section (type 3). NS
/// records without an SOA are a referral instead, which says nothing about
/// whether the queried type exists at the name. Returns true only when the
/// authority section parses completely and has a NODATA shape.
fn authority_marks_nodata(payload: &[u8], start: usize, count: usize) -> bool {
    if count == 0 {
        return true;
    }
    if count > MAX_ANSWERS_TO_PARSE {
        return false;
    }
    let mut offset = start;
    let mut has_soa = false;
    for _ in 0..count {
        let after_name = match skip_dns_name(payload, offset) {
            Some(o) => o,
            None => return false,
        };
        if after_name
            .checked_add(10)
            .map(|e| e > payload.len())
            .unwrap_or(true)
        {
            return false;
        }
        let atype = u16::from_be_bytes([payload[after_name], payload[after_name + 1]]);
        let rdlength =
            u16::from_be_bytes([payload[after_name + 8], payload[after_name + 9]]) as usize;
        let rdata_end = match (after_name + 10).checked_add(rdlength) {
            Some(e) if e <= payload.len() => e,
            _ => return false,
        };
        if atype == 6 {
            has_soa = true;
        }
        offset = rdata_end;
    }
    has_soa
}

/// Parsed DNS-shaped header counts. Surfaced as a thin internal helper so
/// the mDNS / LLMNR wrappers can also reach ARCOUNT without re-decoding.
pub(super) struct DnsHeaderCounts {
    pub is_response: bool,
    /// TC bit: the response was cut to fit the transport, so section counts
    /// may promise records the payload does not carry.
    pub truncated: bool,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
    pub txid: u16,
    pub rcode: u8,
}

/// Decode the four 16-bit counts at the start of a DNS-shaped header.
pub(super) fn dns_header_counts(payload: &[u8]) -> Option<DnsHeaderCounts> {
    if payload.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    Some(DnsHeaderCounts {
        is_response: (flags & 0x8000) != 0,
        truncated: (flags & 0x0200) != 0,
        qdcount: u16::from_be_bytes([payload[4], payload[5]]),
        ancount: u16::from_be_bytes([payload[6], payload[7]]),
        nscount: u16::from_be_bytes([payload[8], payload[9]]),
        arcount: u16::from_be_bytes([payload[10], payload[11]]),
        txid: u16::from_be_bytes([payload[0], payload[1]]),
        rcode: (flags & 0x000F) as u8,
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
        txid: header.txid,
        rcode: header.is_response.then_some(header.rcode),
        nodata: None,
    };

    // Answer-section walk for A / AAAA records. Only runs on responses
    // (QR bit set), since `DnsInfo.response_ips` is only meaningful for
    // resolver answers.
    if header.is_response {
        let mut matched = 0;
        let (after_answers, answers_walked) = walk_a_aaaa_records(
            payload,
            offset,
            header.ancount as usize,
            &mut info.response_ips,
            info.query_type,
            &mut matched,
        );
        offset = after_answers;
        // NODATA: the resolver said NOERROR but the answer section holds no
        // record of the queried type (empty, or e.g. a CNAME chain that ends
        // without one). A parsed record of the queried type proves the data
        // exists; its absence proves NODATA only when the whole answer
        // section parsed, the response is not truncated (TC), and the
        // authority section has RFC 2308 §2.2's NODATA shape (SOA or empty)
        // rather than a referral's NS-without-SOA. Ambiguous responses leave
        // the flag unset.
        if header.rcode == 0 && info.query_type.is_some() {
            if matched > 0 {
                info.nodata = Some(false);
            } else if !header.truncated
                && answers_walked == header.ancount as usize
                && authority_marks_nodata(payload, offset, header.nscount as usize)
            {
                info.nodata = Some(true);
            }
        }
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
        txid: header.txid,
        rcode: header.is_response.then_some(header.rcode),
        // NODATA is a unicast-DNS concept; mDNS negative responses use NSEC
        // (RFC 6762 §6.1) and announcements carry no question to compare
        // against, so the flag stays unset on this path.
        nodata: None,
    };

    if header.is_response {
        let mut matched = 0;
        let (after_answers, _) = walk_a_aaaa_records(
            payload,
            offset,
            header.ancount as usize,
            &mut info.response_ips,
            None,
            &mut matched,
        );
        offset = after_answers;
        // RFC 6762: mDNS responses frequently place A / AAAA in the
        // ADDITIONAL section (NSEC / negative responses, "known-answer
        // suppression"-related additionals, etc.). Skip NSCOUNT (the
        // authority section) records before reaching ADDITIONAL.
        if let Some(after_authority) = skip_records(payload, offset, header.nscount) {
            let _ = walk_a_aaaa_records(
                payload,
                after_authority,
                header.arcount as usize,
                &mut info.response_ips,
                None,
                &mut matched,
            );
        }
    }

    Some(info)
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
    fn test_query_parses_txid_and_has_no_rcode() {
        let (mut payload, _) = make_example_question(false, 0);
        payload[0] = 0xAB;
        payload[1] = 0xCD;

        let info = analyze_dns(&payload).unwrap();
        assert_eq!(info.txid, 0xABCD);
        assert_eq!(
            info.rcode, None,
            "a query carries no response code even though the header bits are zero"
        );
    }

    #[test]
    fn test_response_parses_txid_and_rcode() {
        let (mut payload, _) = make_example_question(true, 0);
        payload[0] = 0xAB;
        payload[1] = 0xCD;
        payload[3] = 0x03; // RCODE = NXDOMAIN

        let info = analyze_dns(&payload).unwrap();
        assert_eq!(info.txid, 0xABCD);
        assert_eq!(info.rcode, Some(3));
        assert_eq!(
            info.nodata, None,
            "NODATA only applies to NOERROR responses; NXDOMAIN says it all"
        );
    }

    #[test]
    fn test_noerror_response_has_rcode_zero() {
        let (payload, _) = make_example_question(true, 0);
        let info = analyze_dns(&payload).unwrap();
        assert_eq!(info.rcode, Some(0));
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
        assert_eq!(
            info.nodata,
            Some(false),
            "the answer contains a record of the queried type"
        );
    }

    #[test]
    fn test_noerror_response_without_queried_type_flags_nodata() {
        // NOERROR answer holding only a CNAME for an A question: the name
        // exists but has no record of the queried type (NODATA). This is
        // the shape of e.g. an HTTPS-type lookup for an aliased name with
        // no HTTPS record at the target.
        let (mut payload, _) = make_example_question(true, 1);
        payload.extend_from_slice(&[0xC0, 0x0C]); // NAME: pointer to question
        payload.extend_from_slice(&[0, 5, 0, 1, 0, 0, 0, 60, 0, 2]); // CNAME, IN, TTL 60, RDLENGTH 2
        payload.extend_from_slice(&[0xC0, 0x0C]); // RDATA: compressed name

        let info = analyze_dns(&payload).unwrap();
        assert_eq!(info.rcode, Some(0));
        assert_eq!(info.nodata, Some(true));
        assert!(info.response_ips.is_empty());
    }

    #[test]
    fn test_soa_authority_confirms_nodata() {
        // NOERROR, empty answer, SOA in authority: the canonical NODATA
        // shape (RFC 2308 §2.2 types 1 and 2).
        let (mut payload, _) = make_example_question(true, 0);
        payload[8..10].copy_from_slice(&1u16.to_be_bytes()); // nscount = 1
        payload.extend_from_slice(&[0xC0, 0x0C]); // NAME: pointer to question
        // SOA, IN, TTL 60, RDLENGTH 24: MNAME + RNAME as pointers + 5 u32 timers
        payload.extend_from_slice(&[0, 6, 0, 1, 0, 0, 0, 60, 0, 24]);
        payload.extend_from_slice(&[0xC0, 0x0C, 0xC0, 0x0C]);
        payload.extend_from_slice(&[0u8; 20]);

        let info = analyze_dns(&payload).unwrap();
        assert_eq!(info.rcode, Some(0));
        assert_eq!(info.nodata, Some(true));
    }

    #[test]
    fn test_referral_response_leaves_nodata_unset() {
        // NOERROR with an empty answer and an NS record but no SOA in the
        // authority section is a referral (RFC 2308 §2.2), not NODATA: the
        // responder is pointing at another server, not denying the record.
        let (mut payload, _) = make_example_question(true, 0);
        payload[8..10].copy_from_slice(&1u16.to_be_bytes()); // nscount = 1
        payload.extend_from_slice(&[0xC0, 0x0C]); // NAME: pointer to question
        payload.extend_from_slice(&[0, 2, 0, 1, 0, 0, 0, 60, 0, 2]); // NS, IN, TTL 60, RDLENGTH 2
        payload.extend_from_slice(&[0xC0, 0x0C]); // RDATA: compressed name

        let info = analyze_dns(&payload).unwrap();
        assert_eq!(info.rcode, Some(0));
        assert_eq!(info.nodata, None);
    }

    #[test]
    fn test_truncated_response_leaves_nodata_unset() {
        // TC=1 with an empty answer section: the full answer goes over TCP,
        // so the empty section proves nothing about the queried name.
        let (mut payload, _) = make_example_question(true, 0);
        payload[2] |= 0x02; // TC bit

        let info = analyze_dns(&payload).unwrap();
        assert_eq!(info.rcode, Some(0));
        assert_eq!(info.nodata, None);
    }

    #[test]
    fn test_unparseable_answer_section_leaves_nodata_unset() {
        // ANCOUNT promises a record the payload does not carry (e.g. a
        // capture snap length cutting the packet without the TC bit set):
        // failing to parse records is not evidence of NODATA.
        let (payload, _) = make_example_question(true, 1);

        let info = analyze_dns(&payload).unwrap();
        assert_eq!(info.rcode, Some(0));
        assert_eq!(info.nodata, None);
        assert!(info.response_ips.is_empty());
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
        assert_eq!(info.nodata, None, "a query cannot claim NODATA");
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
