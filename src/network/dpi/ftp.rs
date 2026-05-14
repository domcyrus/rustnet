//! FTP (File Transfer Protocol) Deep Packet Inspection
//!
//! Parses the plaintext FTP control channel (RFC 959, RFC 2389, RFC 2428).
//! Detection is keyed off port 21 plus a cheap start-line signature so non-
//! standard ports are still caught. The data channel (port 20 / passive) is
//! deliberately not inspected — payloads are arbitrary file bytes.

use crate::network::types::{FtpInfo, FtpMessageType};

/// Maximum bytes we ever scan to decide whether a payload looks like FTP.
const MAX_SNIFF_BYTES: usize = 1024;

/// Commands defined by RFC 959 / 2389 / 2428 / 4217. Matched case-insensitively
/// against the first whitespace-delimited token on the first line of the
/// payload.
const FTP_COMMANDS: &[&str] = &[
    // RFC 959 access control
    "USER", "PASS", "ACCT", "CWD", "CDUP", "SMNT", "QUIT", "REIN",
    // RFC 959 transfer parameters
    "PORT", "PASV", "TYPE", "STRU", "MODE", // RFC 959 service
    "RETR", "STOR", "STOU", "APPE", "ALLO", "REST", "RNFR", "RNTO", "ABOR", "DELE", "RMD", "MKD",
    "PWD", "LIST", "NLST", "SITE", "SYST", "STAT", "HELP", "NOOP",
    // RFC 2389 (FEAT/OPTS)
    "FEAT", "OPTS", // RFC 2428 (extended passive / port for IPv6)
    "EPSV", "EPRT", // RFC 4217 (FTP over TLS)
    "AUTH", "PBSZ", "PROT", "CCC", // RFC 3659 (size/mdtm/mlsd)
    "SIZE", "MDTM", "MLSD", "MLST",
];

/// Cheap heuristic that returns `true` when a payload's first line plausibly
/// belongs to the FTP control channel. Used so non-standard-port flows can
/// still be classified.
pub fn is_ftp(payload: &[u8]) -> bool {
    let line = first_line(payload);
    if line.is_empty() {
        return false;
    }
    // Server response: 3-digit code, then space or '-' (continuation marker).
    if line.len() >= 4
        && line[0].is_ascii_digit()
        && line[1].is_ascii_digit()
        && line[2].is_ascii_digit()
        && (line[3] == b' ' || line[3] == b'-')
    {
        return true;
    }
    // Client request: known command (case-insensitive) followed by space, CRLF,
    // or end-of-line.
    let upper = first_token_upper(line);
    if upper.is_empty() {
        return false;
    }
    FTP_COMMANDS.iter().any(|cmd| cmd.as_bytes() == upper)
}

/// Parse an FTP control-channel payload. Returns `None` when the payload does
/// not look like FTP.
pub fn analyze_ftp(payload: &[u8]) -> Option<FtpInfo> {
    let line = first_line(payload);
    if line.is_empty() {
        return None;
    }

    // Server response branch: `CCC <text>` or `CCC-<text>` where CCC is a
    // 3-digit reply code. A trailing `-` is the RFC 959 §4.2 continuation
    // marker, signalling that the payload is multi-line.
    if line.len() >= 4
        && line[0].is_ascii_digit()
        && line[1].is_ascii_digit()
        && line[2].is_ascii_digit()
        && (line[3] == b' ' || line[3] == b'-')
    {
        let code = std::str::from_utf8(&line[0..3]).ok()?.parse::<u16>().ok()?;
        let is_continuation = line[3] == b'-';
        let message = std::str::from_utf8(&line[4..])
            .ok()
            .map(|s| s.trim().to_string());

        // Software / system-type extraction is skipped on continuation lines
        // (`220-Welcome to the FTP service.\r\n220 ProFTPD ...\r\n`) because
        // the first line is human-greeting prose. vsftpd, ProFTPD, and
        // Pure-FTPd all emit multi-line greetings by default, so honouring
        // the continuation marker is critical — without it we tag
        // `server_software = "Welcome"` on most real servers.
        let server_software = if code == 220 && !is_continuation {
            // RFC 959 §5.4 — service-ready greetings typically embed the
            // FTP server software in the first whitespace-delimited token
            // (`220 ProFTPD 1.3.7 ...`).
            message.as_deref().map(extract_software_token)
        } else {
            None
        };
        // RFC 959 §4.2 — code 215 carries the system / OS name (`UNIX`,
        // `Windows_NT`), NOT the FTP server software. Keeping the two
        // separate avoids labelling "UNIX" under "Server Software" in the
        // TUI.
        let system_type = if code == 215 && !is_continuation {
            message.as_deref().map(extract_software_token)
        } else {
            None
        };
        return Some(FtpInfo {
            message_type: FtpMessageType::Response,
            command: None,
            args: None,
            response_code: Some(code),
            response_message: message,
            username: None,
            server_software,
            system_type,
        });
    }

    // Client request branch.
    let upper = first_token_upper(line);
    if upper.is_empty() {
        return None;
    }
    let is_command = FTP_COMMANDS.iter().any(|cmd| cmd.as_bytes() == upper);
    if !is_command {
        return None;
    }
    let command = std::str::from_utf8(&upper).ok()?.to_string();
    // Trim leading command + whitespace to expose the argument.
    let args = std::str::from_utf8(line)
        .ok()
        .map(|s| s.trim())
        .and_then(|s| {
            s.split_once(char::is_whitespace)
                .map(|(_, rest)| rest.trim())
        })
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    // RFC 959 §5.4: `USER` carries the login name, useful as a per-flow
    // identity hint (plaintext anyway — FTP-AUTH/TLS encrypts later).
    let username = if command == "USER" {
        args.clone()
    } else {
        None
    };

    Some(FtpInfo {
        message_type: FtpMessageType::Request,
        command: Some(command),
        args,
        response_code: None,
        response_message: None,
        username,
        server_software: None,
        system_type: None,
    })
}

fn first_line(payload: &[u8]) -> &[u8] {
    let sniff = &payload[..payload.len().min(MAX_SNIFF_BYTES)];
    match sniff.iter().position(|&b| b == b'\n') {
        Some(end) => {
            // Strip trailing CR if present.
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
        .position(|&b| b == b' ' || b == b'\t' || b == b'\r')
        .unwrap_or(line.len());
    let token = &line[..token_end];
    if token.is_empty() || token.len() > 6 {
        // FTP commands are 3-4 letters; cap at 6 to keep the cost of
        // upper-casing tight on hostile traffic.
        return Vec::new();
    }
    if !token.iter().all(|b| b.is_ascii_alphabetic()) {
        return Vec::new();
    }
    token.iter().map(|b| b.to_ascii_uppercase()).collect()
}

fn extract_software_token(message: &str) -> String {
    // The greeting line is free-form. Heuristic: take the first whitespace-
    // delimited token that contains a letter, strip surrounding punctuation.
    // Falls back to the full message when no clean token is found.
    for token in message.split_whitespace() {
        let trimmed = token.trim_matches(|c: char| !c.is_ascii_alphanumeric());
        if trimmed.chars().any(|c| c.is_ascii_alphabetic()) {
            return trimmed.to_string();
        }
    }
    message.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_server_greeting() {
        let payload = b"220 ProFTPD 1.3.7 Server (Example) [::ffff:10.0.0.1]\r\n";
        assert!(is_ftp(payload));
        let info = analyze_ftp(payload).expect("should parse");
        assert!(matches!(info.message_type, FtpMessageType::Response));
        assert_eq!(info.response_code, Some(220));
        assert_eq!(info.server_software.as_deref(), Some("ProFTPD"));
    }

    #[test]
    fn detects_continuation_response() {
        let payload = b"220-Welcome to the FTP service.\r\n220 Ready.\r\n";
        assert!(is_ftp(payload));
        let info = analyze_ftp(payload).expect("should parse");
        assert_eq!(info.response_code, Some(220));
    }

    #[test]
    fn skips_software_extraction_on_220_continuation() {
        // Default greeting on vsftpd / ProFTPD / Pure-FTPd is multi-line:
        // the first line is `220-` continuation prose ("Welcome to..."),
        // followed by `220 <software>` on a later line. We only see the
        // first line at the DPI layer, so we must not pull "Welcome" out of
        // it and label it as server software.
        let payload = b"220-Welcome to the FTP service.\r\n220 ProFTPD 1.3.7\r\n";
        let info = analyze_ftp(payload).expect("should parse");
        assert_eq!(info.response_code, Some(220));
        assert!(
            info.server_software.is_none(),
            "continuation lines must not populate server_software, got {:?}",
            info.server_software
        );
    }

    #[test]
    fn parses_user_request() {
        let payload = b"USER alice\r\n";
        let info = analyze_ftp(payload).expect("should parse");
        assert!(matches!(info.message_type, FtpMessageType::Request));
        assert_eq!(info.command.as_deref(), Some("USER"));
        assert_eq!(info.username.as_deref(), Some("alice"));
        assert_eq!(info.args.as_deref(), Some("alice"));
    }

    #[test]
    fn parses_retr_request() {
        let payload = b"RETR /pub/file.iso\r\n";
        let info = analyze_ftp(payload).expect("should parse");
        assert_eq!(info.command.as_deref(), Some("RETR"));
        assert_eq!(info.args.as_deref(), Some("/pub/file.iso"));
        assert!(info.username.is_none());
    }

    #[test]
    fn parses_noop_without_args() {
        let payload = b"NOOP\r\n";
        let info = analyze_ftp(payload).expect("should parse");
        assert_eq!(info.command.as_deref(), Some("NOOP"));
        assert!(info.args.is_none());
    }

    #[test]
    fn parses_lowercase_command() {
        let payload = b"quit\r\n";
        let info = analyze_ftp(payload).expect("should parse");
        assert_eq!(info.command.as_deref(), Some("QUIT"));
    }

    #[test]
    fn parses_system_type_response() {
        // RFC 959 §4.2: a `215` reply returns the OS / system type, NOT the
        // FTP server software. Previously we tagged "UNIX" under
        // `server_software`, which surfaced under the "Server Software"
        // column in the TUI alongside greetings like "ProFTPD". They are
        // different things; route 215 to a dedicated `system_type` field
        // and confirm `server_software` stays unset for this reply.
        let payload = b"215 UNIX Type: L8\r\n";
        let info = analyze_ftp(payload).expect("should parse");
        assert_eq!(info.response_code, Some(215));
        assert!(
            info.server_software.is_none(),
            "215 must not populate server_software"
        );
        assert_eq!(info.system_type.as_deref(), Some("UNIX"));
    }

    #[test]
    fn rejects_unknown_request() {
        assert!(!is_ftp(b"FOOBAR baz\r\n"));
        assert!(analyze_ftp(b"FOOBAR baz\r\n").is_none());
    }

    #[test]
    fn rejects_http_payload() {
        // OPTIONS is a real HTTP method; its argument must be a path, not a
        // 3-digit token. The FTP detector should reject it.
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(!is_ftp(payload));
        assert!(analyze_ftp(payload).is_none());
    }

    #[test]
    fn rejects_short_response() {
        assert!(!is_ftp(b"220"));
        assert!(analyze_ftp(b"220").is_none());
    }

    #[test]
    fn rejects_non_digit_prefix() {
        // Looks like response prefix but first char is alphabetic.
        assert!(!is_ftp(b"2X0 hello\r\n"));
    }

    #[test]
    fn parses_epsv_extended_passive() {
        let payload = b"EPSV\r\n";
        let info = analyze_ftp(payload).expect("should parse");
        assert_eq!(info.command.as_deref(), Some("EPSV"));
    }
}
