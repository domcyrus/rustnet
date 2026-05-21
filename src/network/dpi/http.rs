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
    let lines: Vec<&str> = text.lines().collect();

    if lines.is_empty() {
        return None;
    }

    // Parse first line
    let first_line = lines[0];
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() >= 3 {
        if first_line.starts_with("HTTP/") {
            // Response line: HTTP/1.1 200 OK
            info.version = parse_http_version(parts[0]);
            info.status_code = parts[1].parse::<u16>().ok();
        } else if is_http_method(parts[0]) {
            // Request line: GET /path HTTP/1.1 — outer `parts.len() >= 3`
            // already guarantees `parts[2]` is in bounds.
            info.method = Some(parts[0].to_string());
            info.path = Some(parts[1].to_string());
            info.version = parse_http_version(parts[2]);
        } else {
            return None; // Not valid HTTP
        }
    } else {
        return None;
    }

    // Parse headers. HTTP field-names are case-insensitive (RFC 7230 §3.2),
    // so compare in place with `eq_ignore_ascii_case` instead of allocating a
    // lowercased copy of every header name just to match two ASCII literals.
    for line in lines.iter().skip(1) {
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

fn parse_http_version(s: &str) -> HttpVersion {
    match s {
        "HTTP/1.0" => HttpVersion::Http10,
        "HTTP/1.1" => HttpVersion::Http11,
        "HTTP/2" => HttpVersion::Http2,
        _ => HttpVersion::Http11,
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
