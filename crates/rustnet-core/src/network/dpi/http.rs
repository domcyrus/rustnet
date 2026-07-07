use crate::network::types::{HttpInfo, HttpVersion};

/// Analyze payload for HTTP protocol
pub fn analyze_http(payload: &[u8]) -> Option<HttpInfo> {
    if !is_likely_http(payload) {
        return None;
    }

    let mut info = HttpInfo {
        version: HttpVersion::Http11,
        method: None,
        host: None,
        path: None,
        status_code: None,
        user_agent: None,
    };

    // Safe string conversion for HTTP parsing
    let text = String::from_utf8_lossy(payload);
    // Drive the line iterator directly: the request/status line is the first
    // element and headers are everything after it. Collecting into a `Vec<&str>`
    // just to index `[0]` and `skip(1)` allocates one heap slice per parse.
    let mut lines = text.lines();
    let first_line = lines.next()?;
    // Consume the first-line tokens lazily via iterator to avoid the
    // `split_whitespace().collect::<Vec<_>>()` heap allocation. Requests
    // have exactly 3 SP-delimited tokens; responses have 2 or 3 since the
    // reason phrase is optional (RFC 9112 §4).
    let mut tokens = first_line.split_whitespace();
    let (tok0, tok1) = match (tokens.next(), tokens.next()) {
        (Some(a), Some(b)) => (a, b),
        _ => return None,
    };

    if first_line.starts_with("HTTP/") {
        // Response line: HTTP/1.1 200 OK — the reason phrase may be empty,
        // but the status code must be a 3-digit number.
        info.version = parse_http_version(tok0)?;
        info.status_code = Some(
            tok1.parse::<u16>()
                .ok()
                .filter(|c| (100..=599).contains(c))?,
        );
    } else if is_http_method(tok0) {
        // Request line: GET /path HTTP/1.1. The version token is required:
        // SIP and RTSP share the same verbs ("OPTIONS sip:bob@example.com
        // SIP/2.0"), so a method match alone is not HTTP.
        info.version = parse_http_version(tokens.next()?)?;
        info.method = Some(tok0.to_string());
        info.path = Some(tok1.to_string());
    } else {
        return None; // Not valid HTTP
    }

    // Parse headers. HTTP field-names are case-insensitive (RFC 7230 §3.2),
    // so compare in place with `eq_ignore_ascii_case` instead of allocating a
    // lowercased copy of every header name just to match two ASCII literals.
    for line in lines {
        if line.is_empty() {
            break; // End of headers
        }

        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();

            if key.eq_ignore_ascii_case("host") {
                info.host = Some(value.to_string());
            } else if key.eq_ignore_ascii_case("user-agent") {
                info.user_agent = Some(value.to_string());
            }
        }
    }

    Some(info)
}

/// Quick check if payload might be HTTP
fn is_likely_http(payload: &[u8]) -> bool {
    if payload.len() < 4 {
        return false;
    }

    // HTTP request methods
    payload.starts_with(b"GET ") ||
    payload.starts_with(b"POST ") ||
    payload.starts_with(b"PUT ") ||
    payload.starts_with(b"DELETE ") ||
    payload.starts_with(b"HEAD ") ||
    payload.starts_with(b"OPTIONS ") ||
    payload.starts_with(b"CONNECT ") ||
    payload.starts_with(b"TRACE ") ||
    payload.starts_with(b"PATCH ") ||
    // HTTP responses
    payload.starts_with(b"HTTP/1.0 ") ||
    payload.starts_with(b"HTTP/1.1 ") ||
    payload.starts_with(b"HTTP/2 ")
}

fn is_http_method(s: &str) -> bool {
    matches!(
        s,
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "CONNECT" | "TRACE" | "PATCH"
    )
}

fn parse_http_version(s: &str) -> Option<HttpVersion> {
    match s {
        "HTTP/1.0" => Some(HttpVersion::Http10),
        "HTTP/1.1" => Some(HttpVersion::Http11),
        "HTTP/2" => Some(HttpVersion::Http2),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_request() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let info = analyze_http(payload).unwrap();

        assert_eq!(info.method.as_deref(), Some("GET"));
        assert_eq!(info.path.as_deref(), Some("/index.html"));
        assert_eq!(info.host.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_http_response() {
        let payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
        let info = analyze_http(payload).unwrap();

        assert_eq!(info.status_code, Some(200));
        assert!(info.method.is_none());
    }

    #[test]
    fn test_http_start_line_token_extraction() {
        // Lock the lazy-iterator token extraction: all three tokens from a
        // well-formed request line must be parsed without a Vec allocation.
        let req = b"POST /api/v1/upload HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        let info = analyze_http(req).expect("POST request should parse");
        assert_eq!(info.method.as_deref(), Some("POST"));
        assert_eq!(info.path.as_deref(), Some("/api/v1/upload"));
        assert_eq!(info.host.as_deref(), Some("api.example.com"));

        // A truncated request line must be rejected: requests need all
        // three tokens (method, target, version).
        let truncated: [&[u8]; 2] = [
            b"GET /index.html\r\n\r\n", // only 2 tokens
            b"GET\r\n\r\n",             // only 1 token
        ];
        for payload in &truncated {
            assert!(
                analyze_http(payload).is_none(),
                "truncated start line should not parse: {:?}",
                std::str::from_utf8(payload).unwrap_or("<invalid utf8>")
            );
        }
    }

    #[test]
    fn test_http_response_without_reason_phrase() {
        // RFC 9112 §4: the reason phrase is optional. Real servers emit
        // `HTTP/1.1 200 \r\n` (empty phrase) and some omit the trailing
        // space entirely; both are valid responses.
        for payload in [b"HTTP/1.1 200\r\n\r\n".as_slice(), b"HTTP/1.1 200 \r\n\r\n"] {
            let info = analyze_http(payload).expect("reason phrase is optional");
            assert_eq!(info.status_code, Some(200));
        }
    }

    #[test]
    fn test_non_http_text_protocols_rejected() {
        // SIP and RTSP share request verbs with HTTP; the version token
        // must be validated so they are not misclassified.
        let sip = b"OPTIONS sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/TCP host\r\n\r\n";
        assert!(analyze_http(sip).is_none());

        let rtsp = b"OPTIONS rtsp://cam.local/stream RTSP/1.0\r\nCSeq: 1\r\n\r\n";
        assert!(analyze_http(rtsp).is_none());

        // A response-shaped line with a non-numeric status is not HTTP.
        assert!(analyze_http(b"HTTP/1.1 OK 200\r\n\r\n").is_none());
    }

    #[test]
    fn test_http_mixed_case_host_and_user_agent_headers() {
        // HTTP/1.1 §3.2 makes field-names case-insensitive. Real-world traffic
        // varies in capitalisation (`Host`, `HOST`, `host`, etc.) and the
        // `eq_ignore_ascii_case` refactor relies on this invariant — lock it
        // here so a future change that drops the case-insensitive compare
        // fails this test instead of silently regressing.
        let host_variants: [&[u8]; 4] = [
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            b"GET / HTTP/1.1\r\nhost: example.com\r\n\r\n",
            b"GET / HTTP/1.1\r\nHOST: example.com\r\n\r\n",
            b"GET / HTTP/1.1\r\nhOsT: example.com\r\n\r\n",
        ];
        for payload in &host_variants {
            let info = analyze_http(payload).expect("should parse");
            assert_eq!(info.host.as_deref(), Some("example.com"));
        }

        let ua_variants: [&[u8]; 4] = [
            b"GET / HTTP/1.1\r\nUser-Agent: curl/8.5\r\n\r\n",
            b"GET / HTTP/1.1\r\nuser-agent: curl/8.5\r\n\r\n",
            b"GET / HTTP/1.1\r\nUSER-AGENT: curl/8.5\r\n\r\n",
            b"GET / HTTP/1.1\r\nUser-AGENT: curl/8.5\r\n\r\n",
        ];
        for payload in &ua_variants {
            let info = analyze_http(payload).expect("should parse");
            assert_eq!(info.user_agent.as_deref(), Some("curl/8.5"));
        }
    }
}
