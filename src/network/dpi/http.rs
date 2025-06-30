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
            // Request line: GET /path HTTP/1.1
            info.method = Some(parts[0].to_string());
            info.path = Some(parts[1].to_string());
            if parts.len() >= 3 {
                info.version = parse_http_version(parts[2]);
            }
        } else {
            return None; // Not valid HTTP
        }
    } else {
        return None;
    }

    // Parse headers
    for line in lines.iter().skip(1) {
        if line.is_empty() {
            break; // End of headers
        }

        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim().to_lowercase();
            let value = value.trim();

            match key.as_str() {
                "host" => info.host = Some(value.to_string()),
                "user-agent" => info.user_agent = Some(value.to_string()),
                _ => {}
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
}
