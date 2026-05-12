//! SIP (Session Initiation Protocol) Deep Packet Inspection
//!
//! Parses plaintext SIP requests and responses over UDP/TCP.
//! This intentionally focuses on high-value start-line and header fields.

use crate::network::types::SipInfo;

const MIN_SIP_SIZE: usize = 12;
const SIP_VERSION: &str = "SIP/2.0";

struct SipStartLine {
    is_response: bool,
    method: Option<String>,
    request_uri: Option<String>,
    status_code: Option<u16>,
    reason_phrase: Option<String>,
}

/// Quick check if payload looks like a SIP message.
pub fn is_likely_sip(payload: &[u8]) -> bool {
    if payload.len() < MIN_SIP_SIZE {
        return false;
    }

    if !payload
        .iter()
        .take(32)
        .all(|&b| b.is_ascii_graphic() || matches!(b, b' ' | b'\r' | b'\n' | b'\t'))
    {
        return false;
    }

    let Ok(text) = std::str::from_utf8(payload) else {
        return false;
    };
    let Some(first_line) = text.lines().next() else {
        return false;
    };

    parse_start_line(first_line.trim()).is_some()
}

/// Analyze a SIP request/response and extract key fields.
pub fn analyze_sip(payload: &[u8]) -> Option<SipInfo> {
    if !is_likely_sip(payload) {
        return None;
    }

    let text = std::str::from_utf8(payload).ok()?;
    let first_line = text.lines().next()?.trim();
    let start_line = parse_start_line(first_line)?;

    let mut info = SipInfo {
        is_response: start_line.is_response,
        method: start_line.method,
        request_uri: start_line.request_uri,
        status_code: start_line.status_code,
        reason_phrase: start_line.reason_phrase,
        from: None,
        to: None,
        call_id: None,
        user_agent: None,
        server: None,
    };

    for line in text.lines().skip(1) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }

        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }

        match name.trim().to_ascii_lowercase().as_str() {
            "from" | "f" => {
                if info.from.is_none() {
                    info.from = Some(value.to_string());
                }
            }
            "to" | "t" => {
                if info.to.is_none() {
                    info.to = Some(value.to_string());
                }
            }
            "call-id" | "i" => {
                if info.call_id.is_none() {
                    info.call_id = Some(value.to_string());
                }
            }
            "user-agent" => {
                if info.user_agent.is_none() {
                    info.user_agent = Some(value.to_string());
                }
            }
            "server" => {
                if info.server.is_none() {
                    info.server = Some(value.to_string());
                }
            }
            _ => {}
        }
    }

    Some(info)
}

fn parse_start_line(first_line: &str) -> Option<SipStartLine> {
    if let Some(rest) = first_line.strip_prefix("SIP/2.0 ") {
        let mut parts = rest.split_whitespace();
        let status_code = parts.next()?.parse::<u16>().ok()?;
        let reason_phrase = rest
            .split_once(' ')
            .and_then(|(_, reason)| (!reason.trim().is_empty()).then(|| reason.trim().to_string()));
        return Some(SipStartLine {
            is_response: true,
            method: None,
            request_uri: None,
            status_code: Some(status_code),
            reason_phrase,
        });
    }

    let mut parts = first_line.split_whitespace();
    let method = parts.next()?;
    let request_uri = parts.next()?;
    let version = parts.next()?;

    if !is_known_sip_method(method) || version != SIP_VERSION {
        return None;
    }

    Some(SipStartLine {
        is_response: false,
        method: Some(method.to_string()),
        request_uri: Some(request_uri.to_string()),
        status_code: None,
        reason_phrase: None,
    })
}

fn is_known_sip_method(method: &str) -> bool {
    matches!(
        method,
        "INVITE"
            | "ACK"
            | "BYE"
            | "CANCEL"
            | "REGISTER"
            | "OPTIONS"
            | "PRACK"
            | "SUBSCRIBE"
            | "NOTIFY"
            | "PUBLISH"
            | "INFO"
            | "REFER"
            | "MESSAGE"
            | "UPDATE"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sip_invite_request() {
        let packet = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776asdhds\r\n\
From: Alice <sip:alice@example.com>;tag=1928301774\r\n\
To: Bob <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710@pc33.example.com\r\n\
User-Agent: Softphone/1.0\r\n\
\r\n";

        let info = analyze_sip(packet).expect("should parse");
        assert!(!info.is_response);
        assert_eq!(info.method.as_deref(), Some("INVITE"));
        assert_eq!(info.request_uri.as_deref(), Some("sip:bob@example.com"));
        assert_eq!(
            info.call_id.as_deref(),
            Some("a84b4c76e66710@pc33.example.com")
        );
        assert_eq!(info.user_agent.as_deref(), Some("Softphone/1.0"));
    }

    #[test]
    fn test_sip_response() {
        let packet = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP server.example.com;branch=z9hG4bK74bf9\r\n\
From: Alice <sip:alice@example.com>;tag=9fxced76sl\r\n\
To: Bob <sip:bob@example.com>;tag=8321234356\r\n\
Call-ID: 3848276298220188511@atlanta.example.com\r\n\
Server: PBX/2.1\r\n\
\r\n";

        let info = analyze_sip(packet).expect("should parse");
        assert!(info.is_response);
        assert_eq!(info.status_code, Some(200));
        assert_eq!(info.reason_phrase.as_deref(), Some("OK"));
        assert_eq!(info.server.as_deref(), Some("PBX/2.1"));
    }

    #[test]
    fn test_sip_compact_headers() {
        let packet = b"REGISTER sip:registrar.example.com SIP/2.0\r\n\
f: <sip:alice@example.com>\r\n\
t: <sip:alice@example.com>\r\n\
i: 12345@client.example.com\r\n\
\r\n";

        let info = analyze_sip(packet).expect("should parse");
        assert_eq!(info.method.as_deref(), Some("REGISTER"));
        assert_eq!(info.from.as_deref(), Some("<sip:alice@example.com>"));
        assert_eq!(info.to.as_deref(), Some("<sip:alice@example.com>"));
        assert_eq!(info.call_id.as_deref(), Some("12345@client.example.com"));
    }

    #[test]
    fn test_http_not_sip() {
        let packet = b"OPTIONS / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(!is_likely_sip(packet));
        assert!(analyze_sip(packet).is_none());
    }

    #[test]
    fn test_binary_not_sip() {
        let packet = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03];
        assert!(!is_likely_sip(&packet));
    }

    #[test]
    fn test_invalid_start_line() {
        let packet = b"HELLO sip:bob@example.com SIP/2.0\r\n\r\n";
        assert!(!is_likely_sip(packet));
        assert!(analyze_sip(packet).is_none());
    }
}
