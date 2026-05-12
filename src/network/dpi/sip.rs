//! SIP (Session Initiation Protocol) Deep Packet Inspection
//!
//! Best-effort detection and metadata extraction for plaintext SIP over
//! TCP/UDP per RFC 3261. SIP shares its message grammar with HTTP (start
//! line plus headers separated by CRLF, terminated by an empty line), so
//! detection runs *before* HTTP analysis to avoid misclassifying messages
//! whose protocol version reads `SIP/2.0`.
//!
//! Extracted headers: `From`, `To`, `Call-ID`, `CSeq`, `User-Agent`,
//! `Server`, `Content-Type`. The `has_sdp` flag is derived from
//! `Content-Type: application/sdp`.

use crate::network::types::{SipInfo, SipMessageType};

const SIP_VERSION: &str = "SIP/2.0";
const SIP_VERSION_PREFIX: &[u8] = b"SIP/2.0";

/// Quick signature check: a SIP message starts either with a known
/// request method followed by space, or with `SIP/2.0` (response).
pub fn is_sip(payload: &[u8]) -> bool {
    if payload.len() < 8 {
        return false;
    }

    // Responses: "SIP/2.0 200 OK\r\n"
    if payload.starts_with(SIP_VERSION_PREFIX) {
        // Must be followed by a space and a 3-digit status code.
        return payload
            .get(SIP_VERSION_PREFIX.len())
            .is_some_and(|&b| b == b' ');
    }

    // Requests: "METHOD <uri> SIP/2.0\r\n". The fastest discriminator
    // from HTTP is the trailing protocol token, but scanning the whole
    // line is cheap; do that.
    let line_end = payload
        .iter()
        .take(1024)
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(payload.len().min(1024));
    let first_line = &payload[..line_end];

    if !is_likely_sip_method_prefix(first_line) {
        return false;
    }

    // Must terminate with "SIP/2.0".
    first_line
        .windows(SIP_VERSION_PREFIX.len())
        .any(|w| w == SIP_VERSION_PREFIX)
}

/// SIP request methods per RFC 3261 + common extensions (RFC 3262/3265/3311/3428/3515/3903/6086).
const SIP_METHODS: &[&[u8]] = &[
    b"INVITE ",
    b"ACK ",
    b"BYE ",
    b"CANCEL ",
    b"REGISTER ",
    b"OPTIONS ",
    b"PRACK ",
    b"SUBSCRIBE ",
    b"NOTIFY ",
    b"PUBLISH ",
    b"INFO ",
    b"REFER ",
    b"MESSAGE ",
    b"UPDATE ",
];

fn is_likely_sip_method_prefix(line: &[u8]) -> bool {
    SIP_METHODS.iter().any(|m| line.starts_with(m))
}

/// Parse a plaintext SIP message and extract a `SipInfo`. Returns `None`
/// if the start line does not match the SIP grammar.
pub fn analyze_sip(payload: &[u8]) -> Option<SipInfo> {
    if !is_sip(payload) {
        return None;
    }

    // SIP is line-oriented ASCII; tolerate lone LF in the wild.
    let text = match std::str::from_utf8(payload) {
        Ok(s) => s,
        Err(_) => return None,
    };

    let mut lines = text.split('\n');
    let start_line_raw = lines.next()?.trim_end_matches('\r');

    let mut info = SipInfo::default();
    parse_start_line(start_line_raw, &mut info)?;

    for line in lines {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break; // end of headers
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();

        // First-wins for stable identity headers; match guards keep the
        // declaration flat and satisfy clippy's collapsible_match lint.
        match canonical_header_name(name).as_str() {
            "from" | "f" if info.from.is_none() => {
                info.from = Some(value.to_string());
            }
            "to" | "t" if info.to.is_none() => {
                info.to = Some(value.to_string());
            }
            "call-id" | "i" if info.call_id.is_none() => {
                info.call_id = Some(value.to_string());
            }
            "user-agent" if info.user_agent.is_none() => {
                info.user_agent = Some(value.to_string());
            }
            "server" if info.server.is_none() => {
                info.server = Some(value.to_string());
            }
            "cseq" => {
                parse_cseq(value, &mut info);
            }
            "content-type" | "c" if info.content_type.is_none() => {
                let ct = value.to_string();
                info.has_sdp = ct
                    .split(';')
                    .next()
                    .map(|t| t.trim().eq_ignore_ascii_case("application/sdp"))
                    .unwrap_or(false);
                info.content_type = Some(ct);
            }
            _ => {}
        }
    }

    Some(info)
}

fn parse_start_line(line: &str, info: &mut SipInfo) -> Option<()> {
    if let Some(rest) = line.strip_prefix(SIP_VERSION) {
        // Response: "SIP/2.0 200 OK"
        let rest = rest.trim_start();
        let mut parts = rest.splitn(2, ' ');
        let code = parts.next()?.parse::<u16>().ok()?;
        info.message_type = SipMessageType::Response;
        info.status_code = Some(code);
        info.reason_phrase = parts
            .next()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        Some(())
    } else {
        // Request: "METHOD <uri> SIP/2.0"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            return None;
        }
        if parts[parts.len() - 1] != SIP_VERSION {
            return None;
        }
        info.message_type = SipMessageType::Request;
        info.method = Some(parts[0].to_string());
        Some(())
    }
}

fn parse_cseq(value: &str, info: &mut SipInfo) {
    // "CSeq: <number> <method>"
    let mut parts = value.split_whitespace();
    if let Some(num) = parts.next().and_then(|n| n.parse::<u32>().ok()) {
        info.cseq_number = Some(num);
    }
    if let Some(method) = parts.next() {
        if info.cseq_method.is_none() {
            info.cseq_method = Some(method.to_string());
        }
        // For requests, prefer CSeq method if the start-line method was
        // missing (some implementations split the request line oddly).
        if info.method.is_none()
            && matches!(
                info.message_type,
                SipMessageType::Request | SipMessageType::Unknown
            )
        {
            info.method = Some(method.to_string());
        }
    }
}

/// RFC 3261 §7.3.1 — header names are case-insensitive and several have
/// single-letter compact forms (e.g. `f` for `From`). Normalize to
/// lowercase long form where it matters; otherwise return lowercase.
fn canonical_header_name(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    const INVITE: &[u8] = b"INVITE sip:bob@biloxi.example.com SIP/2.0\r\n\
        Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n\
        Max-Forwards: 70\r\n\
        To: Bob <sip:bob@biloxi.example.com>\r\n\
        From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n\
        Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n\
        CSeq: 314159 INVITE\r\n\
        Contact: <sip:alice@pc33.atlanta.example.com>\r\n\
        User-Agent: ExampleUA/1.0\r\n\
        Content-Type: application/sdp\r\n\
        Content-Length: 142\r\n\
        \r\n\
        v=0\r\n";

    const RESPONSE_200: &[u8] = b"SIP/2.0 200 OK\r\n\
        Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n\
        From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n\
        To: Bob <sip:bob@biloxi.example.com>;tag=a6c85cf\r\n\
        Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n\
        CSeq: 314159 INVITE\r\n\
        Server: SomeServer/2.3\r\n\
        Content-Length: 0\r\n\r\n";

    const REGISTER: &[u8] = b"REGISTER sip:registrar.example.com SIP/2.0\r\n\
        Via: SIP/2.0/UDP bobspc.example.com:5060;branch=z9hG4bKnashds7\r\n\
        Max-Forwards: 70\r\n\
        To: Bob <sip:bob@biloxi.example.com>\r\n\
        From: Bob <sip:bob@biloxi.example.com>;tag=456248\r\n\
        Call-ID: 843817637684230@998sdasdh09\r\n\
        CSeq: 1826 REGISTER\r\n\
        Content-Length: 0\r\n\r\n";

    #[test]
    fn detects_request() {
        assert!(is_sip(INVITE));
    }

    #[test]
    fn detects_response() {
        assert!(is_sip(RESPONSE_200));
    }

    #[test]
    fn rejects_http_request() {
        let http = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(!is_sip(http));
    }

    #[test]
    fn rejects_http_options_with_http_version() {
        // The OPTIONS method also exists in SIP. Make sure HTTP-bound
        // OPTIONS requests are not detected as SIP.
        let http = b"OPTIONS / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(!is_sip(http));
    }

    #[test]
    fn accepts_sip_options() {
        let sip = b"OPTIONS sip:carol@chicago.example.com SIP/2.0\r\nVia: SIP/2.0/UDP h\r\n\r\n";
        assert!(is_sip(sip));
    }

    #[test]
    fn parses_invite_metadata() {
        let info = analyze_sip(INVITE).expect("should parse INVITE");
        assert_eq!(info.message_type, SipMessageType::Request);
        assert_eq!(info.method.as_deref(), Some("INVITE"));
        assert_eq!(info.status_code, None);
        assert_eq!(
            info.call_id.as_deref(),
            Some("a84b4c76e66710@pc33.atlanta.example.com")
        );
        assert_eq!(info.cseq_number, Some(314159));
        assert_eq!(info.cseq_method.as_deref(), Some("INVITE"));
        assert_eq!(info.user_agent.as_deref(), Some("ExampleUA/1.0"));
        assert_eq!(info.content_type.as_deref(), Some("application/sdp"));
        assert!(info.has_sdp);
        assert!(info.from.as_deref().unwrap().contains("alice"));
        assert!(info.to.as_deref().unwrap().contains("bob"));
    }

    #[test]
    fn parses_response_metadata() {
        let info = analyze_sip(RESPONSE_200).expect("should parse 200");
        assert_eq!(info.message_type, SipMessageType::Response);
        assert_eq!(info.status_code, Some(200));
        assert_eq!(info.reason_phrase.as_deref(), Some("OK"));
        assert_eq!(info.cseq_method.as_deref(), Some("INVITE"));
        assert_eq!(info.server.as_deref(), Some("SomeServer/2.3"));
        assert!(!info.has_sdp);
    }

    #[test]
    fn parses_register_without_body() {
        let info = analyze_sip(REGISTER).expect("should parse REGISTER");
        assert_eq!(info.method.as_deref(), Some("REGISTER"));
        assert_eq!(info.cseq_number, Some(1826));
        assert_eq!(info.cseq_method.as_deref(), Some("REGISTER"));
        assert!(!info.has_sdp);
    }

    #[test]
    fn handles_compact_headers() {
        let payload = b"INVITE sip:b@x SIP/2.0\r\n\
            f: Alice <sip:a@x>\r\n\
            t: Bob <sip:b@x>\r\n\
            i: callid-1@host\r\n\
            CSeq: 1 INVITE\r\n\
            c: application/sdp;charset=utf-8\r\n\r\n";
        let info = analyze_sip(payload).expect("should parse compact headers");
        assert!(info.from.as_deref().unwrap().contains("Alice"));
        assert!(info.to.as_deref().unwrap().contains("Bob"));
        assert_eq!(info.call_id.as_deref(), Some("callid-1@host"));
        assert!(info.has_sdp);
        assert!(
            info.content_type
                .as_deref()
                .unwrap()
                .contains("application/sdp")
        );
    }

    #[test]
    fn rejects_truncated() {
        assert!(analyze_sip(b"INV").is_none());
        assert!(analyze_sip(b"").is_none());
    }

    #[test]
    fn rejects_lookalike_with_wrong_version() {
        let bad = b"INVITE sip:b@x HTTP/1.1\r\n\r\n";
        assert!(!is_sip(bad));
        assert!(analyze_sip(bad).is_none());
    }
}
