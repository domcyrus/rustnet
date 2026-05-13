//! IMAP (Internet Message Access Protocol) Deep Packet Inspection
//!
//! Parses the plaintext IMAP4rev1 control channel (RFC 3501, RFC 7888 LITERAL+,
//! RFC 2595 STARTTLS, RFC 4978 COMPRESS). Detection is keyed off port 143 plus
//! a cheap start-line signature; port 993 (IMAPS) is TLS-wrapped and is
//! claimed by the HTTPS/TLS analyzer instead.
//!
//! Client lines are tag-prefixed (`<tag> COMMAND <args>`), server lines are
//! either tagged (`<tag> OK/NO/BAD …`), untagged (`* …`), or continuations
//! (`+ …`). This module recognises all three.

use crate::network::types::{ImapInfo, ImapMessageType};

/// Maximum bytes scanned for the signature check.
const MAX_SNIFF_BYTES: usize = 1024;

/// RFC 3501 / 7888 / 2595 / 4978 / 5161 verbs. Matched case-insensitively
/// against the command token (the second whitespace-delimited field of a
/// client request line).
const IMAP_COMMANDS: &[&str] = &[
    // RFC 3501 — any-state
    "CAPABILITY",
    "NOOP",
    "LOGOUT",
    // RFC 3501 — not-authenticated
    "AUTHENTICATE",
    "LOGIN",
    "STARTTLS",
    // RFC 3501 — authenticated
    "SELECT",
    "EXAMINE",
    "CREATE",
    "DELETE",
    "RENAME",
    "SUBSCRIBE",
    "UNSUBSCRIBE",
    "LIST",
    "LSUB",
    "STATUS",
    "APPEND",
    // RFC 3501 — selected
    "CHECK",
    "CLOSE",
    "EXPUNGE",
    "SEARCH",
    "FETCH",
    "STORE",
    "COPY",
    "UID",
    // RFC 2971 / 5161 / 2177
    "ID",
    "ENABLE",
    "IDLE",
    "DONE",
    // RFC 4978
    "COMPRESS",
];

/// Returns `true` when the first line of the payload looks like an IMAP
/// frame. Used for signature-based detection on non-standard ports.
pub fn is_imap(payload: &[u8]) -> bool {
    let line = first_line(payload);
    if line.is_empty() {
        return false;
    }
    // Server untagged response (`* OK ...`, `* PREAUTH ...`, `* CAPABILITY …`).
    if line.starts_with(b"* ") {
        return true;
    }
    // Continuation (`+ <text>`).
    if line.starts_with(b"+ ") || line == b"+" {
        return true;
    }
    // Tagged frame: `<tag> <token>` where `<token>` is OK/NO/BAD/BYE/PREAUTH
    // (server) or a known IMAP command (client).
    let (tag, rest) = match split_tag(line) {
        Some(v) => v,
        None => return false,
    };
    if tag.is_empty() {
        return false;
    }
    let token_upper = first_token_upper(rest);
    if token_upper.is_empty() {
        return false;
    }
    matches!(
        token_upper.as_slice(),
        b"OK" | b"NO" | b"BAD" | b"BYE" | b"PREAUTH"
    ) || IMAP_COMMANDS
        .iter()
        .any(|cmd| cmd.as_bytes() == token_upper)
}

/// Parse an IMAP payload. Returns `None` when the payload does not look like
/// IMAP.
pub fn analyze_imap(payload: &[u8]) -> Option<ImapInfo> {
    let line = first_line(payload);
    if line.is_empty() {
        return None;
    }

    // Untagged response (`* <status-or-data> …`).
    if let Some(rest) = line.strip_prefix(b"* ") {
        let status_upper = first_token_upper(rest);
        let status = std::str::from_utf8(&status_upper)
            .ok()
            .map(|s| s.to_string());
        let message = std::str::from_utf8(rest).ok().map(|s| s.trim().to_string());
        // RFC 3501 §7.1.1 / §11: the `* OK` / `* PREAUTH` greeting carries
        // the server software banner.
        let server_software = match status.as_deref() {
            Some("OK") | Some("PREAUTH") => message.as_deref().map(extract_software_token),
            _ => None,
        };
        return Some(ImapInfo {
            message_type: ImapMessageType::UntaggedResponse,
            tag: None,
            command: None,
            args: None,
            status,
            response_message: message,
            username: None,
            server_software,
        });
    }

    // Continuation response (`+ <text>`).
    if line == b"+" || line.starts_with(b"+ ") {
        let message = std::str::from_utf8(&line[1..])
            .ok()
            .map(|s| s.trim().to_string());
        return Some(ImapInfo {
            message_type: ImapMessageType::Continuation,
            tag: None,
            command: None,
            args: None,
            status: None,
            response_message: message,
            username: None,
            server_software: None,
        });
    }

    // Tagged frame.
    let (tag, rest) = split_tag(line)?;
    if tag.is_empty() {
        return None;
    }
    let tag_str = std::str::from_utf8(tag).ok()?.to_string();
    let token_upper = first_token_upper(rest);
    if token_upper.is_empty() {
        return None;
    }

    // Tagged response: `<tag> OK/NO/BAD ...`.
    if matches!(token_upper.as_slice(), b"OK" | b"NO" | b"BAD" | b"BYE") {
        let status = std::str::from_utf8(&token_upper)
            .ok()
            .map(|s| s.to_string());
        let message = std::str::from_utf8(rest).ok().and_then(|s| {
            s.split_once(char::is_whitespace)
                .map(|(_, rest)| rest.trim().to_string())
        });
        return Some(ImapInfo {
            message_type: ImapMessageType::TaggedResponse,
            tag: Some(tag_str),
            command: None,
            args: None,
            status,
            response_message: message,
            username: None,
            server_software: None,
        });
    }

    // Tagged request: `<tag> COMMAND <args>`.
    if !IMAP_COMMANDS
        .iter()
        .any(|cmd| cmd.as_bytes() == token_upper)
    {
        return None;
    }
    let command = std::str::from_utf8(&token_upper).ok()?.to_string();
    let args = std::str::from_utf8(rest).ok().and_then(|s| {
        s.split_once(char::is_whitespace)
            .map(|(_, rest)| rest.trim().to_string())
            .filter(|v| !v.is_empty())
    });
    // RFC 3501 §6.2.3: `LOGIN <user> <pass>` puts the username in the first
    // argument (plaintext until STARTTLS, hence already exposed on the wire).
    let username = if command == "LOGIN" {
        args.as_deref()
            .and_then(|s| s.split_whitespace().next())
            .map(extract_quoted)
    } else {
        None
    };

    Some(ImapInfo {
        message_type: ImapMessageType::Request,
        tag: Some(tag_str),
        command: Some(command),
        args,
        status: None,
        response_message: None,
        username,
        server_software: None,
    })
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

/// Split `<tag> <rest>` once. RFC 3501 §2.2.1 says tags are non-empty
/// printable ASCII excluding space, control, `(`, `)`, `{`, `*`, `%`, `\`,
/// `"`. We enforce a tight length cap to keep this cheap on hostile traffic.
fn split_tag(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let space = line.iter().position(|&b| b == b' ')?;
    let tag = &line[..space];
    if tag.is_empty() || tag.len() > 32 {
        return None;
    }
    if !tag.iter().all(|&b| {
        b.is_ascii_graphic() && !matches!(b, b'(' | b')' | b'{' | b'%' | b'*' | b'\\' | b'"')
    }) {
        return None;
    }
    Some((tag, &line[space + 1..]))
}

fn first_token_upper(line: &[u8]) -> Vec<u8> {
    let token_end = line
        .iter()
        .position(|&b| b == b' ' || b == b'\t' || b == b'\r')
        .unwrap_or(line.len());
    let token = &line[..token_end];
    if token.is_empty() || token.len() > 16 {
        return Vec::new();
    }
    if !token.iter().all(|b| b.is_ascii_alphabetic()) {
        return Vec::new();
    }
    token.iter().map(|b| b.to_ascii_uppercase()).collect()
}

fn extract_software_token(message: &str) -> String {
    // `OK [CAPABILITY ...] Server ready` — the first token is the status
    // word (OK / PREAUTH / BYE). Walk past it, skip any bracketed
    // capability list, and return the next plain word containing a letter.
    let mut inside_bracket = false;
    let mut current = String::new();
    let mut seen_first = false;
    let mut best = String::new();
    for c in message.chars() {
        match c {
            '[' => inside_bracket = true,
            ']' => inside_bracket = false,
            _ if inside_bracket => {}
            c if c.is_whitespace() => {
                if !current.is_empty() {
                    if seen_first {
                        if best.is_empty() && is_software_candidate(&current) {
                            best = current.clone();
                        }
                    } else {
                        seen_first = true;
                    }
                    current.clear();
                }
            }
            _ => current.push(c),
        }
    }
    if best.is_empty() && !current.is_empty() && seen_first && is_software_candidate(&current) {
        best = current;
    }
    if best.is_empty() {
        message.trim().to_string()
    } else {
        best
    }
}

fn is_software_candidate(token: &str) -> bool {
    let trimmed = token.trim_matches(|c: char| !c.is_ascii_alphanumeric());
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("IMAP4rev1") {
        return false;
    }
    trimmed.chars().any(|c| c.is_ascii_alphabetic())
}

fn extract_quoted(token: &str) -> String {
    token.trim_matches('"').trim_matches('\'').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_server_greeting() {
        let payload = b"* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR] Dovecot ready.\r\n";
        assert!(is_imap(payload));
        let info = analyze_imap(payload).expect("should parse");
        assert!(matches!(
            info.message_type,
            ImapMessageType::UntaggedResponse
        ));
        assert_eq!(info.status.as_deref(), Some("OK"));
        assert_eq!(info.server_software.as_deref(), Some("Dovecot"));
    }

    #[test]
    fn detects_preauth_greeting() {
        let payload = b"* PREAUTH IMAP4rev1 server ready\r\n";
        let info = analyze_imap(payload).expect("should parse");
        assert_eq!(info.status.as_deref(), Some("PREAUTH"));
    }

    #[test]
    fn parses_login_request_with_username() {
        let payload = b"a001 LOGIN alice secret\r\n";
        let info = analyze_imap(payload).expect("should parse");
        assert!(matches!(info.message_type, ImapMessageType::Request));
        assert_eq!(info.tag.as_deref(), Some("a001"));
        assert_eq!(info.command.as_deref(), Some("LOGIN"));
        assert_eq!(info.username.as_deref(), Some("alice"));
    }

    #[test]
    fn parses_login_with_quoted_username() {
        let payload = b"a001 LOGIN \"alice@example.com\" secret\r\n";
        let info = analyze_imap(payload).expect("should parse");
        assert_eq!(info.username.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn parses_select_request() {
        let payload = b"a002 SELECT INBOX\r\n";
        let info = analyze_imap(payload).expect("should parse");
        assert_eq!(info.command.as_deref(), Some("SELECT"));
        assert_eq!(info.args.as_deref(), Some("INBOX"));
        assert!(info.username.is_none());
    }

    #[test]
    fn parses_uid_fetch_request() {
        let payload = b"a003 UID FETCH 1:* (FLAGS RFC822.SIZE)\r\n";
        let info = analyze_imap(payload).expect("should parse");
        assert_eq!(info.command.as_deref(), Some("UID"));
        assert_eq!(info.args.as_deref(), Some("FETCH 1:* (FLAGS RFC822.SIZE)"));
    }

    #[test]
    fn parses_tagged_response() {
        let payload = b"a002 OK [READ-WRITE] SELECT completed\r\n";
        let info = analyze_imap(payload).expect("should parse");
        assert!(matches!(info.message_type, ImapMessageType::TaggedResponse));
        assert_eq!(info.tag.as_deref(), Some("a002"));
        assert_eq!(info.status.as_deref(), Some("OK"));
    }

    #[test]
    fn parses_no_response() {
        let payload = b"a004 NO [AUTHENTICATIONFAILED] Authentication failed.\r\n";
        let info = analyze_imap(payload).expect("should parse");
        assert_eq!(info.status.as_deref(), Some("NO"));
    }

    #[test]
    fn parses_untagged_data() {
        let payload = b"* 23 EXISTS\r\n";
        let info = analyze_imap(payload).expect("should parse");
        assert!(matches!(
            info.message_type,
            ImapMessageType::UntaggedResponse
        ));
        // "23" is not alphabetic so status_upper is empty — that's fine.
        assert!(info.status.is_none() || info.status.as_deref() == Some(""));
    }

    #[test]
    fn parses_continuation() {
        let payload = b"+ Ready for additional command text\r\n";
        let info = analyze_imap(payload).expect("should parse");
        assert!(matches!(info.message_type, ImapMessageType::Continuation));
    }

    #[test]
    fn rejects_http_request() {
        let payload = b"GET /mail HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(!is_imap(payload));
        assert!(analyze_imap(payload).is_none());
    }

    #[test]
    fn rejects_bare_tag_without_command() {
        assert!(!is_imap(b"a001\r\n"));
    }

    #[test]
    fn rejects_unknown_command() {
        assert!(!is_imap(b"a001 FOOBAR baz\r\n"));
    }

    #[test]
    fn parses_starttls() {
        let payload = b"a005 STARTTLS\r\n";
        let info = analyze_imap(payload).expect("should parse");
        assert_eq!(info.command.as_deref(), Some("STARTTLS"));
    }
}
