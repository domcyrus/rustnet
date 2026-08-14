use crate::network::types::{HttpsInfo, TlsInfo, TlsVersion};
use log::debug;

/// Maximum TLS extensions to parse. Defense-in-depth against crafted packets
/// with many zero-length extensions designed to waste CPU.
const MAX_TLS_EXTENSIONS: usize = 100;

pub fn is_tls_handshake(payload: &[u8]) -> bool {
    if payload.len() < 5 {
        return false;
    }

    // TLS record header:
    // - Content type (1 byte): 0x16 for handshake
    // - Version (2 bytes): 0x0301-0x0304 for TLS 1.0-1.3
    // - Length (2 bytes)
    payload[0] == 0x16 && // Handshake content type
        payload[1] == 0x03 && // Major version 3
        (payload[2] >= 0x01 && payload[2] <= 0x04) // Minor version 1-4
}

pub fn analyze_https(payload: &[u8]) -> Option<HttpsInfo> {
    // Need at least 5 bytes for the TLS record header
    if payload.len() < 5 {
        return None;
    }

    let mut info = TlsInfo::new();

    // Check content type
    let content_type = payload[0];

    if content_type != 0x16 {
        // Not a handshake record - still extract version
        let record_version = version_from_bytes(payload[1], payload[2]);
        info.version = record_version;
        return Some(HttpsInfo {
            tls_info: Some(info),
        });
    }

    // Record layer version
    let record_version = version_from_bytes(payload[1], payload[2]);
    info.version = record_version;

    // Get record length
    let record_length = u16::from_be_bytes([payload[3], payload[4]]) as usize;

    // Sanity check
    if record_length > 16384 + 2048 {
        return Some(HttpsInfo {
            tls_info: Some(info),
        });
    }

    // Calculate available data (handle fragmentation gracefully)
    let available_data = (payload.len() - 5).min(record_length);

    if available_data < 4 {
        return Some(HttpsInfo {
            tls_info: Some(info),
        });
    }

    // Skip TLS record header (5 bytes)
    let handshake_data = &payload[5..5 + available_data];

    let handshake_type = handshake_data[0];

    // Quick validation
    if !matches!(handshake_type, 0x00..=0x18 | 0xfe) {
        return Some(HttpsInfo {
            tls_info: Some(info),
        });
    }

    let handshake_length =
        u32::from_be_bytes([0, handshake_data[1], handshake_data[2], handshake_data[3]]) as usize;

    // Sanity check
    if handshake_length > 16384 {
        return Some(HttpsInfo {
            tls_info: Some(info),
        });
    }

    // Calculate how much handshake data we actually have
    let handshake_available = (handshake_data.len() - 4).min(handshake_length);

    if handshake_available == 0 {
        return Some(HttpsInfo {
            tls_info: Some(info),
        });
    }

    match handshake_type {
        0x01 => {
            // Client Hello - this is where SNI and ALPN are
            parse_client_hello(
                &handshake_data[4..4 + handshake_available],
                &mut info,
                record_version,
            );
        }
        0x02 => {
            // Server Hello
            parse_server_hello(&handshake_data[4..4 + handshake_available], &mut info);
        }
        _ => {
            // Other handshake types we don't parse
        }
    }

    if info.sni.is_some() || !info.alpn.is_empty() {
        debug!("TLS: Found SNI={:?}, ALPN={:?}", info.sni, info.alpn);
    }
    Some(HttpsInfo {
        tls_info: Some(info),
    })
}

fn version_from_bytes(major: u8, minor: u8) -> Option<TlsVersion> {
    match (major, minor) {
        (0x03, 0x01) => Some(TlsVersion::Tls10),
        (0x03, 0x02) => Some(TlsVersion::Tls11),
        (0x03, 0x03) => Some(TlsVersion::Tls12),
        (0x03, 0x04) => Some(TlsVersion::Tls13),
        _ => None,
    }
}

fn parse_client_hello(data: &[u8], info: &mut TlsInfo, record_version: Option<TlsVersion>) {
    // Need at least 2 bytes for version
    if data.len() < 2 {
        return;
    }

    // Client version
    let client_version = version_from_bytes(data[0], data[1]);
    info.version = client_version.or(record_version);

    // Need at least 34 bytes for version + random
    if data.len() < 34 {
        return;
    }

    // Skip random (32 bytes)
    let mut offset = 34;

    // Session ID - be lenient with bounds
    if offset >= data.len() {
        return;
    }
    let session_id_len = data[offset] as usize;
    offset += 1 + session_id_len;

    if offset >= data.len() {
        return;
    }

    // Cipher suites
    if offset + 2 > data.len() {
        return;
    }
    let cipher_suites_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2 + cipher_suites_len;

    if offset >= data.len() {
        return;
    }

    // Compression methods
    if offset >= data.len() {
        return;
    }
    let compression_len = data[offset] as usize;
    offset += 1 + compression_len;

    if offset >= data.len() {
        return;
    }

    // Extensions - this is what we really want
    if offset + 2 > data.len() {
        return;
    }
    let extensions_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    // Parse whatever extension data we have
    if offset < data.len() {
        let available_ext_data = &data[offset..data.len().min(offset + extensions_len)];
        if !available_ext_data.is_empty() {
            parse_extensions(available_ext_data, info, true);
        }
    }
}

fn parse_server_hello(data: &[u8], info: &mut TlsInfo) {
    if data.len() < 2 {
        return;
    }

    // Server version
    let server_version = version_from_bytes(data[0], data[1]);
    info.version = server_version;

    if data.len() < 34 {
        return;
    }

    // Skip random (32 bytes)
    let mut offset = 34;

    // Session ID length
    if offset >= data.len() {
        return;
    }
    let session_id_len = data[offset] as usize;
    offset += 1 + session_id_len;

    if offset >= data.len() {
        return;
    }

    // Cipher suite (2 bytes)
    if offset + 2 > data.len() {
        return;
    }
    let cipher = u16::from_be_bytes([data[offset], data[offset + 1]]);
    info.cipher_suite = Some(cipher);
    offset += 2;

    // Compression method (1 byte)
    if offset >= data.len() {
        return;
    }
    offset += 1;

    // Extensions (optional)
    if offset + 2 > data.len() {
        return;
    }

    let extensions_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    // Parse whatever extension data we have
    if offset < data.len() {
        let available_ext_data = &data[offset..data.len().min(offset + extensions_len)];
        if !available_ext_data.is_empty() {
            parse_extensions(available_ext_data, info, false);
        }
    }
}

fn parse_extensions(data: &[u8], info: &mut TlsInfo, is_client_hello: bool) {
    let mut offset = 0;
    let mut extensions_parsed = 0;

    while offset + 4 <= data.len() {
        extensions_parsed += 1;
        if extensions_parsed > MAX_TLS_EXTENSIONS {
            break;
        }
        let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let ext_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;

        // Calculate how much extension data we actually have
        let available_ext_len = data.len().saturating_sub(offset + 4);
        let ext_data_len = ext_len.min(available_ext_len);

        if ext_data_len > 0 {
            let ext_data = &data[offset + 4..offset + 4 + ext_data_len];

            match ext_type {
                0x0000 if is_client_hello => {
                    // SNI (Server Name Indication)
                    if let Some(sni) = parse_sni_extension_resilient(ext_data) {
                        info.sni = Some(sni);
                    }
                }
                0x0010 => {
                    // ALPN (Application-Layer Protocol Negotiation)
                    if let Some(alpn) = parse_alpn_extension_resilient(ext_data)
                        && !alpn.is_empty()
                    {
                        info.alpn = alpn;
                    }
                }
                0x002b => {
                    // Supported Versions
                    if let Some(version) =
                        parse_supported_versions_resilient(ext_data, is_client_hello)
                    {
                        info.version = Some(version);
                    }
                }
                _ => {
                    // Skip unknown extensions
                }
            }
        }

        // Move to next extension (use declared length, not actual)
        offset += 4 + ext_len;

        // But stop if we've gone past available data
        if offset > data.len() {
            break;
        }
    }
}

fn parse_sni_extension_resilient(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }

    // Server name list length (2 bytes)
    let _list_len = u16::from_be_bytes([data[0], data[1]]) as usize;

    // Check name type (should be 0x00 for hostname)
    if data[2] != 0x00 {
        return None;
    }

    // Name length
    let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;

    // Extract whatever hostname data we have
    let available_len = data.len().saturating_sub(5);
    let actual_len = name_len.min(available_len);

    if actual_len > 0 {
        let hostname_bytes = &data[5..5 + actual_len];

        // Try to parse as UTF-8
        if let Ok(hostname) = std::str::from_utf8(hostname_bytes) {
            // Basic validation - at least check it looks like a hostname
            if hostname.chars().all(|c| c.is_ascii_graphic() || c == '.') {
                let result = if actual_len < name_len {
                    format!("{}[PARTIAL]", hostname)
                } else {
                    hostname.to_string()
                };
                return Some(result);
            }
        }
    }

    None
}

fn parse_alpn_extension_resilient(data: &[u8]) -> Option<Vec<String>> {
    if data.len() < 2 {
        return None;
    }

    let mut protocols = Vec::new();

    // ALPN list length
    let alpn_len = u16::from_be_bytes([data[0], data[1]]) as usize;

    let mut offset = 2;
    let list_end = 2 + alpn_len.min(data.len() - 2);

    while offset < list_end && offset < data.len() {
        let proto_len = data[offset] as usize;
        offset += 1;

        let available_len = list_end
            .saturating_sub(offset)
            .min(data.len().saturating_sub(offset));
        let actual_len = proto_len.min(available_len);

        if actual_len > 0
            && let Ok(proto) = std::str::from_utf8(&data[offset..offset + actual_len])
        {
            if actual_len < proto_len {
                protocols.push(format!("{}[PARTIAL]", proto));
            } else {
                protocols.push(proto.to_string());
            }
        }

        offset += proto_len;

        if offset >= data.len() {
            break;
        }
    }

    if protocols.is_empty() {
        None
    } else {
        Some(protocols)
    }
}

fn parse_supported_versions_resilient(data: &[u8], is_client_hello: bool) -> Option<TlsVersion> {
    if is_client_hello {
        // Client sends a list of supported versions
        if data.is_empty() {
            return None;
        }

        let list_len = data[0] as usize;
        let mut offset = 1;
        let mut best_version: Option<TlsVersion> = None;

        while offset + 1 < data.len() && offset < 1 + list_len {
            if let Some(version) = version_from_bytes(data[offset], data[offset + 1]) {
                best_version = match (best_version, version) {
                    (None, v) => Some(v),
                    (Some(v1), v2) => {
                        // Simple comparison - return the higher version
                        if version_to_priority(v2) > version_to_priority(v1) {
                            Some(v2)
                        } else {
                            Some(v1)
                        }
                    }
                };
            }
            offset += 2;
        }

        best_version
    } else {
        // Server sends a single selected version
        if data.len() < 2 {
            return None;
        }
        version_from_bytes(data[0], data[1])
    }
}

fn version_to_priority(version: TlsVersion) -> u8 {
    match version {
        TlsVersion::Tls10 => 1,
        TlsVersion::Tls11 => 2,
        TlsVersion::Tls12 => 3,
        TlsVersion::Tls13 => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_hex(hex: &str) -> Vec<u8> {
        let cleaned: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        cleaned
            .as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    /// RFC 9001 Appendix A.2 ClientHello (the payload of the client Initial's
    /// CRYPTO frame): SNI example.com, ALPN "alpn", TLS 1.3 via
    /// supported_versions.
    fn rfc9001_client_hello() -> Vec<u8> {
        from_hex(
            "010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868\
             04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578\
             616d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e\
             0005000501000000000033002600\
             24001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e9\
             94ec74d748002b0003020304000d0010000e04030503060302030804080508\
             06002d00020101001c00024001003900320408ffffffffffffffff0504800\
             0ffff07048000ffff0801100104800075300901100f088394c8f03e5157080\
             6048000ffff",
        )
    }

    /// Wrap a handshake message in a TLS record header.
    fn tls_record(handshake: &[u8]) -> Vec<u8> {
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(handshake);
        record
    }

    #[test]
    fn test_analyze_https_client_hello_end_to_end() {
        let payload = tls_record(&rfc9001_client_hello());
        assert!(is_tls_handshake(&payload));

        let info = analyze_https(&payload).unwrap().tls_info.unwrap();
        assert_eq!(info.sni, Some("example.com".to_string()));
        assert_eq!(info.alpn, vec!["alpn".to_string()]);
        assert_eq!(info.version, Some(TlsVersion::Tls13));
    }

    #[test]
    fn test_analyze_https_server_hello_end_to_end() {
        // Synthetic TLS 1.3 ServerHello: legacy version 0x0303, cipher
        // TLS_AES_128_GCM_SHA256, supported_versions selecting 1.3.
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session id length
        body.extend_from_slice(&[0x13, 0x01]); // cipher suite
        body.push(0); // compression method
        let extensions = from_hex("002b00020304");
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = vec![0x02];
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);

        let info = analyze_https(&tls_record(&handshake))
            .unwrap()
            .tls_info
            .unwrap();
        assert_eq!(info.cipher_suite, Some(0x1301));
        assert_eq!(info.version, Some(TlsVersion::Tls13));
    }

    #[test]
    fn test_analyze_https_truncated_client_hello() {
        // A ClientHello cut inside the SNI hostname still yields a partial
        // SNI on the TCP path (the record can never be completed later).
        let handshake = rfc9001_client_hello();
        // SNI extension content starts at the "example.com" bytes; cut after
        // "exampl" (the hostname starts at offset 0x2e + some header bytes).
        let sni_pos = handshake
            .windows(11)
            .position(|w| w == b"example.com")
            .unwrap();
        let truncated = &handshake[..sni_pos + 6];

        let info = analyze_https(&tls_record(truncated))
            .unwrap()
            .tls_info
            .unwrap();
        let sni = info.sni.expect("partial SNI should be extracted");
        assert!(sni.starts_with("exampl"));
        assert!(sni.contains("PARTIAL"));
    }

    #[test]
    fn test_analyze_https_non_handshake_record() {
        // Application data record: only the record version is extracted.
        let payload = [0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5];
        let info = analyze_https(&payload).unwrap().tls_info.unwrap();
        assert_eq!(info.version, Some(TlsVersion::Tls12));
        assert_eq!(info.sni, None);
        assert!(info.alpn.is_empty());
    }

    #[test]
    fn test_partial_sni_extraction() {
        // Simulate a truncated SNI extension
        let partial_sni = vec![
            0x00, 0x10, // List length: 16
            0x00, // Name type: host_name
            0x00, 0x0d, // Name length: 13
            b'e', b'x', b'a', b'm', b'p', // Only 5 bytes of "example.com"
        ];

        let result = parse_sni_extension_resilient(&partial_sni);
        assert!(result.is_some());
        let sni = result.unwrap();
        assert!(sni.starts_with("examp"));
        assert!(sni.contains("PARTIAL"));
    }

    #[test]
    fn test_partial_alpn_extraction() {
        // Simulate a truncated ALPN extension
        let partial_alpn = vec![
            0x00, 0x0e, // List length: 14
            0x08, b'h', b't', b't', b'p', // Only partial "http/1.1"
        ];

        let result = parse_alpn_extension_resilient(&partial_alpn);
        assert!(result.is_some());
        let protocols = result.unwrap();
        assert!(!protocols.is_empty());
        assert!(protocols[0].contains("PARTIAL"));
    }
}
