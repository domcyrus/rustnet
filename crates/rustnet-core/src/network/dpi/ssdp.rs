//! SSDP (Simple Service Discovery Protocol) Deep Packet Inspection
//!
//! Parses SSDP packets used for UPnP device discovery.
//! SSDP uses UDP port 1900 and has an HTTP-like text format.

use crate::network::types::{SsdpInfo, SsdpMethod};

/// Minimum SSDP packet size for detection
const MIN_SSDP_SIZE: usize = 10;

/// Analyze an SSDP packet and extract key information.
///
/// SSDP uses HTTP-like text format with methods like M-SEARCH and NOTIFY.
/// Returns `None` if the packet is not valid SSDP.
pub fn analyze_ssdp(payload: &[u8]) -> Option<SsdpInfo> {
    if payload.len() < MIN_SSDP_SIZE {
        return None;
    }

    // SSDP is ASCII text - check if it looks like text
    if !payload.iter().take(20).all(|&b| b.is_ascii()) {
        return None;
    }

    // Convert to string for parsing
    let text = std::str::from_utf8(payload).ok()?;
    let first_line = text.lines().next()?;

    // Detect method from first line
    let method = if first_line.starts_with("M-SEARCH") {
        SsdpMethod::MSearch
    } else if first_line.starts_with("NOTIFY") {
        SsdpMethod::Notify
    } else if first_line.starts_with("HTTP/1.1 200") || first_line.starts_with("HTTP/1.0 200") {
        SsdpMethod::Response
    } else {
        return None;
    };

    // Extract service type from ST or NT header. Compare the 3-byte prefix
    // with `eq_ignore_ascii_case` so we don't allocate a lowercased copy
    // of every header line just to check two ASCII names.
    let mut service_type = None;
    for line in text.lines().skip(1) {
        let is_st_or_nt = line.get(..3).is_some_and(|prefix| {
            prefix.eq_ignore_ascii_case("st:") || prefix.eq_ignore_ascii_case("nt:")
        });
        if is_st_or_nt {
            // Extract value after the colon
            if let Some(value) = line.get(3..) {
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    service_type = Some(trimmed.to_string());
                    break;
                }
            }
        }
    }

    Some(SsdpInfo {
        method,
        service_type,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssdp_msearch() {
        let packet = b"M-SEARCH * HTTP/1.1\r\n\
            HOST: 239.255.255.250:1900\r\n\
            MAN: \"ssdp:discover\"\r\n\
            MX: 3\r\n\
            ST: ssdp:all\r\n\
            \r\n";
        let info = analyze_ssdp(packet).expect("should parse");
        assert_eq!(info.method, SsdpMethod::MSearch);
        assert_eq!(info.service_type, Some("ssdp:all".to_string()));
    }

    #[test]
    fn test_ssdp_notify() {
        let packet = b"NOTIFY * HTTP/1.1\r\n\
            HOST: 239.255.255.250:1900\r\n\
            CACHE-CONTROL: max-age=1800\r\n\
            LOCATION: http://192.168.1.1:80/desc.xml\r\n\
            NT: upnp:rootdevice\r\n\
            NTS: ssdp:alive\r\n\
            \r\n";
        let info = analyze_ssdp(packet).expect("should parse");
        assert_eq!(info.method, SsdpMethod::Notify);
        assert_eq!(info.service_type, Some("upnp:rootdevice".to_string()));
    }

    #[test]
    fn test_ssdp_response() {
        let packet = b"HTTP/1.1 200 OK\r\n\
            CACHE-CONTROL: max-age=1800\r\n\
            ST: urn:schemas-upnp-org:device:MediaRenderer:1\r\n\
            LOCATION: http://192.168.1.100:8080/desc.xml\r\n\
            \r\n";
        let info = analyze_ssdp(packet).expect("should parse");
        assert_eq!(info.method, SsdpMethod::Response);
        assert_eq!(
            info.service_type,
            Some("urn:schemas-upnp-org:device:MediaRenderer:1".to_string())
        );
    }

    #[test]
    fn test_ssdp_no_service_type() {
        let packet = b"M-SEARCH * HTTP/1.1\r\n\
            HOST: 239.255.255.250:1900\r\n\
            MAN: \"ssdp:discover\"\r\n\
            \r\n";
        let info = analyze_ssdp(packet).expect("should parse");
        assert_eq!(info.method, SsdpMethod::MSearch);
        assert!(info.service_type.is_none());
    }

    #[test]
    fn test_ssdp_too_short() {
        let packet = b"M-SEA";
        assert!(analyze_ssdp(packet).is_none());
    }

    #[test]
    fn test_ssdp_not_text() {
        let packet = [0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00];
        assert!(analyze_ssdp(&packet).is_none());
    }

    #[test]
    fn test_ssdp_not_ssdp() {
        let packet = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(analyze_ssdp(packet).is_none());
    }

    #[test]
    fn test_ssdp_mixed_case_st_and_nt_headers() {
        // SSDP / UPnP servers in the wild use varied capitalisation for
        // header names (HTTP §3.2 lets the field-name be case-insensitive).
        // Lock the invariant the `eq_ignore_ascii_case` refactor relies on:
        // any case mix on the 2-byte field-name still extracts the value.
        let st_variants = [
            b"M-SEARCH * HTTP/1.1\r\nST: ssdp:all\r\n\r\n".to_vec(),
            b"M-SEARCH * HTTP/1.1\r\nSt: ssdp:all\r\n\r\n".to_vec(),
            b"M-SEARCH * HTTP/1.1\r\nsT: ssdp:all\r\n\r\n".to_vec(),
            b"M-SEARCH * HTTP/1.1\r\nst: ssdp:all\r\n\r\n".to_vec(),
        ];
        for packet in &st_variants {
            let info = analyze_ssdp(packet).expect("should parse");
            assert_eq!(info.service_type, Some("ssdp:all".to_string()));
        }

        let nt_variants = [
            b"NOTIFY * HTTP/1.1\r\nNT: upnp:rootdevice\r\n\r\n".to_vec(),
            b"NOTIFY * HTTP/1.1\r\nNt: upnp:rootdevice\r\n\r\n".to_vec(),
            b"NOTIFY * HTTP/1.1\r\nnT: upnp:rootdevice\r\n\r\n".to_vec(),
            b"NOTIFY * HTTP/1.1\r\nnt: upnp:rootdevice\r\n\r\n".to_vec(),
        ];
        for packet in &nt_variants {
            let info = analyze_ssdp(packet).expect("should parse");
            assert_eq!(info.service_type, Some("upnp:rootdevice".to_string()));
        }
    }
}
