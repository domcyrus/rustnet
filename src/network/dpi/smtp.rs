//! SMTP (Simple Mail Transfer Protocol) Deep Packet Inspection
//!
//! Parses the plaintext SMTP control channel (RFC 5321, RFC 1869 ESMTP,
//! RFC 3207 STARTTLS, RFC 4954 AUTH). Detection is keyed off ports 25, 587,
//! 465, and 2525 plus a cheap start-line signature so non-standard SMTP
//! ports are still caught. Once STARTTLS upgrades the channel, subsequent
//! bytes are TLS and will be claimed by the HTTPS/TLS analyzer instead.

use crate::network::types::{SmtpInfo, SmtpMessageType};

/// Maximum bytes scanned for the signature check.
const MAX_SNIFF_BYTES: usize = 1024;

/// RFC 5321 / 1869 / 3207 / 4954 verbs. Matched case-insensitively against the
/// first whitespace-delimited token on the first line of the payload.
const SMTP_COMMANDS: &[&str] = &[
    "HELO", "EHLO", "MAIL", "RCPT", "DATA", "RSET", "NOOP", "QUIT", "VRFY", "EXPN", "HELP",
    "STARTTLS", "AUTH", "BDAT", "ETRN",
];

/// Cheap heuristic: returns `true` when the payload's first line plausibly
/// belongs to an SMTP exchange. Distinct from FTP only in the verb set.
pub fn is_smtp(payload: &[u8]) -> bool {
    let line = first_line(payload);
    if line.is_empty() {
        return false;
    }
    if is_response_prefix(line) {
        return true;
    }
    let upper = first_token_upper(line);
    !upper.is_empty() && SMTP_COMMANDS.iter().any(|cmd| cmd.as_bytes() == upper)
}

/// Parse an SMTP payload. Returns `None` when the payload does not look like
/// SMTP.
pub fn analyze_smtp(payload: &[u8]) -> Option<SmtpInfo> {
    let line = first_line(payload);
    if line.is_empty() {
        return None;
    }

    if is_response_prefix(line) {
        let code = std::str::from_utf8(&line[0..3]).ok()?.parse::<u16>().ok()?;
        let message = std::str::from_utf8(&line[4..])
            .ok()
            .map(|s| s.trim().to_string());
        // RFC 5321 §4.2: 220 service-ready greeting carries the host/software
        // banner; 250 EHLO replies often echo the host name and capabilities.
        let server_software = if code == 220 || code == 250 {
            message.as_deref().map(extract_software_token)
        } else {
            None
        };
        return Some(SmtpInfo {
            message_type: SmtpMessageType::Response,
            command: None,
            args: None,
            response_code: Some(code),
            response_message: message,
            sender: None,
            recipient: None,
            server_software,
        });
    }

    let upper = first_token_upper(line);
    if upper.is_empty() {
        return None;
    }
    if !SMTP_COMMANDS.iter().any(|cmd| cmd.as_bytes() == upper) {
        return None;
    }
    let command = std::str::from_utf8(&upper).ok()?.to_string();
    let args = std::str::from_utf8(line)
        .ok()
        .map(|s| s.trim())
        .and_then(|s| {
            s.split_once(char::is_whitespace)
                .map(|(_, rest)| rest.trim())
        })
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    // RFC 5321 §4.1.1.2 / §4.1.1.3: `MAIL FROM:<addr>` and `RCPT TO:<addr>`
    // carry the envelope sender/recipient. Pull the address out of the
    // angle brackets for the connection-table column.
    let sender = if command == "MAIL" {
        args.as_deref().and_then(extract_envelope_address)
    } else {
        None
    };
    let recipient = if command == "RCPT" {
        args.as_deref().and_then(extract_envelope_address)
    } else {
        None
    };

    Some(SmtpInfo {
        message_type: SmtpMessageType::Request,
        command: Some(command),
        args,
        response_code: None,
        response_message: None,
        sender,
        recipient,
        server_software: None,
    })
}

fn is_response_prefix(line: &[u8]) -> bool {
    line.len() >= 4
        && line[0].is_ascii_digit()
        && line[1].is_ascii_digit()
        && line[2].is_ascii_digit()
        && (line[3] == b' ' || line[3] == b'-')
}

fn first_line(payload: &[u8]) -> &[u8] {
    let sniff = &payload[..payload.len().min(MAX_SNIFF_BYTES)];
    match sniff.iter().position(|&b| b == b'\n') {
        Some(end) => {
            if end > 0 && sniff[end - 1] == b'\r' {
                &sniff[..end - 1]
            } else {
                &sniff[..end]
            }
        }
        None => sniff,
    }
}

fn first_token_upper(line: &[u8]) -> Vec<u8> {
    let token_end = line
        .iter()
        .position(|&b| b == b' ' || b == b'\t' || b == b'\r' || b == b':')
        .unwrap_or(line.len());
    let token = &line[..token_end];
    if token.is_empty() || token.len() > 9 {
        // SMTP verbs top out at "STARTTLS" (8 chars); cap at 9 to keep
        // upper-casing cheap on hostile traffic.
        return Vec::new();
    }
    if !token.iter().all(|b| b.is_ascii_alphabetic()) {
        return Vec::new();
    }
    token.iter().map(|b| b.to_ascii_uppercase()).collect()
}

fn extract_envelope_address(args: &str) -> Option<String> {
    // Accept "FROM:<a@b>", "FROM: <a@b>", or bare "<a@b>".
    let after_colon = args.split_once(':').map(|(_, rest)| rest).unwrap_or(args);
    let trimmed = after_colon.trim();
    let inner = trimmed
        .strip_prefix('<')
        .and_then(|s| s.strip_suffix('>'))
        .unwrap_or(trimmed);
    if inner.is_empty() {
        None
    } else {
        Some(inner.to_string())
    }
}

fn extract_software_token(message: &str) -> String {
    // Greeting banners are free-form. Heuristic: skip the host name (first
    // token) when present, then return the next token that contains a letter.
    // Falls back to the first alphabetic token, then the full message.
    let mut tokens = message
        .split_whitespace()
        .map(|t| t.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.'));
    let first = tokens.next();
    for token in tokens {
        if token.chars().any(|c| c.is_ascii_alphabetic()) && !token.eq_ignore_ascii_case("ESMTP") {
            return token.to_string();
        }
    }
    first.map(|s| s.to_string()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_server_greeting() {
        let payload = b"220 mail.example.com ESMTP Postfix\r\n";
        assert!(is_smtp(payload));
        let info = analyze_smtp(payload).expect("should parse");
        assert!(matches!(info.message_type, SmtpMessageType::Response));
        assert_eq!(info.response_code, Some(220));
        assert_eq!(info.server_software.as_deref(), Some("Postfix"));
    }

    #[test]
    fn detects_ehlo_continuation_response() {
        let payload = b"250-mail.example.com Hello\r\n250-SIZE 14680064\r\n250 STARTTLS\r\n";
        let info = analyze_smtp(payload).expect("should parse");
        assert_eq!(info.response_code, Some(250));
    }

    #[test]
    fn parses_ehlo_request() {
        let payload = b"EHLO client.example.org\r\n";
        let info = analyze_smtp(payload).expect("should parse");
        assert_eq!(info.command.as_deref(), Some("EHLO"));
        assert_eq!(info.args.as_deref(), Some("client.example.org"));
    }

    #[test]
    fn parses_mail_from_envelope() {
        let payload = b"MAIL FROM:<alice@example.com>\r\n";
        let info = analyze_smtp(payload).expect("should parse");
        assert_eq!(info.command.as_deref(), Some("MAIL"));
        assert_eq!(info.sender.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn parses_rcpt_to_envelope() {
        let payload = b"RCPT TO: <bob@example.org>\r\n";
        let info = analyze_smtp(payload).expect("should parse");
        assert_eq!(info.command.as_deref(), Some("RCPT"));
        assert_eq!(info.recipient.as_deref(), Some("bob@example.org"));
    }

    #[test]
    fn parses_starttls() {
        let payload = b"STARTTLS\r\n";
        let info = analyze_smtp(payload).expect("should parse");
        assert_eq!(info.command.as_deref(), Some("STARTTLS"));
    }

    #[test]
    fn parses_data_response() {
        let payload = b"354 End data with <CR><LF>.<CR><LF>\r\n";
        let info = analyze_smtp(payload).expect("should parse");
        assert_eq!(info.response_code, Some(354));
        // 354 is not a banner — should not extract software.
        assert!(info.server_software.is_none());
    }

    #[test]
    fn parses_lowercase_command() {
        let payload = b"quit\r\n";
        let info = analyze_smtp(payload).expect("should parse");
        assert_eq!(info.command.as_deref(), Some("QUIT"));
    }

    #[test]
    fn rejects_http_request() {
        let payload = b"GET /mail HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(!is_smtp(payload));
        assert!(analyze_smtp(payload).is_none());
    }

    #[test]
    fn rejects_unknown_verb() {
        assert!(!is_smtp(b"WOOSH foo\r\n"));
        assert!(analyze_smtp(b"WOOSH foo\r\n").is_none());
    }

    #[test]
    fn rejects_short_payload() {
        assert!(!is_smtp(b"220"));
        assert!(analyze_smtp(b"22").is_none());
    }
}
