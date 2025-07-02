use crate::network::types::{TlsInfo, TlsVersion};

pub fn is_tls_handshake(payload: &[u8]) -> bool {
    if payload.len() < 6 {
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

pub fn analyze_tls(payload: &[u8]) -> Option<TlsInfo> {
    if !is_tls_handshake(payload) || payload.len() < 9 {
        return None;
    }

    let mut info = TlsInfo::new();

    // Record layer version (may be legacy for TLS 1.3)
    let record_version = version_from_bytes(payload[1], payload[2]);

    // Get record length
    let record_length = u16::from_be_bytes([payload[3], payload[4]]) as usize;

    // Validate record length
    if payload.len() < 5 + record_length {
        return None;
    }

    // Skip TLS record header (5 bytes)
    let handshake_data = &payload[5..5 + record_length];

    if handshake_data.len() < 4 {
        return Some(info);
    }

    let handshake_type = handshake_data[0];
    let handshake_length =
        u32::from_be_bytes([0, handshake_data[1], handshake_data[2], handshake_data[3]]) as usize;

    // Validate handshake length
    if handshake_data.len() < 4 + handshake_length {
        return Some(info);
    }

    match handshake_type {
        0x01 => {
            // Client Hello
            parse_client_hello(
                &handshake_data[4..4 + handshake_length],
                &mut info,
                record_version,
            );
        }
        0x02 => {
            // Server Hello
            parse_server_hello(&handshake_data[4..4 + handshake_length], &mut info);
        }
        0x0b => {
            // Certificate
            parse_certificate(&handshake_data[4..4 + handshake_length], &mut info);
        }
        _ => {}
    }

    Some(info)
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

fn parse_client_hello(
    data: &[u8],
    info: &mut TlsInfo,
    record_version: Option<TlsVersion>,
) -> Option<()> {
    if data.len() < 34 {
        return None;
    }

    // Client version (legacy, real version might be in supported_versions extension)
    let client_version = version_from_bytes(data[0], data[1]);
    info.version = client_version.or(record_version);

    // Skip random (32 bytes)
    let mut offset = 34;

    // Session ID
    if offset >= data.len() {
        return None;
    }
    let session_id_len = data[offset] as usize;
    offset += 1 + session_id_len;

    // Cipher suites
    if offset + 2 > data.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2 + cipher_suites_len;

    // Compression methods
    if offset >= data.len() {
        return None;
    }
    let compression_len = data[offset] as usize;
    offset += 1 + compression_len;

    // Extensions
    if offset + 2 > data.len() {
        return Some(());
    }
    let extensions_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    if offset + extensions_len > data.len() {
        return Some(());
    }

    parse_extensions(&data[offset..offset + extensions_len], info, true);
    Some(())
}

fn parse_server_hello(data: &[u8], info: &mut TlsInfo) -> Option<()> {
    if data.len() < 35 {
        return None;
    }

    // Server version
    let server_version = version_from_bytes(data[0], data[1]);

    // For TLS 1.3, check if this is really TLS 1.2 (0x0303) which means we need to look at extensions
    if let Some(TlsVersion::Tls12) = server_version {
        // Will be updated by supported_versions extension if present
        info.version = server_version;
    } else {
        info.version = server_version;
    }

    // Skip random (32 bytes)
    let mut offset = 34;

    // Session ID length
    if offset >= data.len() {
        return None;
    }
    let session_id_len = data[offset] as usize;
    offset += 1 + session_id_len;

    // Cipher suite (2 bytes)
    if offset + 2 > data.len() {
        return None;
    }
    info.cipher_suite = Some(u16::from_be_bytes([data[offset], data[offset + 1]]));
    offset += 2;

    // Compression method (1 byte)
    offset += 1;

    // Extensions (if present)
    if offset + 2 <= data.len() {
        let extensions_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if offset + extensions_len <= data.len() {
            parse_extensions(&data[offset..offset + extensions_len], info, false);
        }
    }

    Some(())
}

fn parse_extensions(data: &[u8], info: &mut TlsInfo, is_client_hello: bool) -> Option<()> {
    let mut offset = 0;

    while offset + 4 <= data.len() {
        let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let ext_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;

        if offset + 4 + ext_len > data.len() {
            break;
        }

        let ext_data = &data[offset + 4..offset + 4 + ext_len];

        match ext_type {
            0x0000 => {
                // SNI (Server Name Indication)
                if is_client_hello {
                    info.sni = parse_sni_extension(ext_data);
                }
            }
            0x0010 => {
                // ALPN (Application-Layer Protocol Negotiation)
                info.alpn = parse_alpn_extension(ext_data);
            }
            0x002b => {
                // Supported Versions
                if let Some(version) = parse_supported_versions_extension(ext_data, is_client_hello)
                {
                    info.version = Some(version);
                }
            }
            _ => {}
        }

        offset += 4 + ext_len;
    }

    Some(())
}

fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }

    // Server name list length (2 bytes)
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return None;
    }

    let mut offset = 2;

    while offset + 3 <= data.len() {
        let name_type = data[offset];
        let name_len = u16::from_be_bytes([data[offset + 1], data[offset + 2]]) as usize;

        if name_type == 0x00 {
            // host_name
            if offset + 3 + name_len <= data.len() {
                let hostname_bytes = &data[offset + 3..offset + 3 + name_len];
                if let Ok(hostname) = std::str::from_utf8(hostname_bytes) {
                    return Some(hostname.to_string());
                }
            }
        }

        offset += 3 + name_len;
    }

    None
}

fn parse_alpn_extension(data: &[u8]) -> Vec<String> {
    let mut protocols = Vec::new();

    if data.len() < 2 {
        return protocols;
    }

    // ALPN extension length
    let alpn_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + alpn_len {
        return protocols;
    }

    let mut offset = 2;

    while offset < data.len() {
        let proto_len = data[offset] as usize;
        if offset + 1 + proto_len <= data.len() {
            if let Ok(proto) = std::str::from_utf8(&data[offset + 1..offset + 1 + proto_len]) {
                protocols.push(proto.to_string());
            }
        }
        offset += 1 + proto_len;
    }

    protocols
}

fn parse_supported_versions_extension(data: &[u8], is_client_hello: bool) -> Option<TlsVersion> {
    if is_client_hello {
        // Client sends a list of supported versions
        if data.len() < 1 {
            return None;
        }
        let list_len = data[0] as usize;
        if data.len() < 1 + list_len || list_len < 2 {
            return None;
        }

        // Return the first (highest priority) version
        version_from_bytes(data[1], data[2])
    } else {
        // Server sends a single selected version
        if data.len() < 2 {
            return None;
        }
        version_from_bytes(data[0], data[1])
    }
}

fn parse_certificate(data: &[u8], info: &mut TlsInfo) -> Option<()> {
    if data.len() < 3 {
        return None;
    }

    // Certificate list length (3 bytes)
    let cert_list_len = u32::from_be_bytes([0, data[0], data[1], data[2]]) as usize;
    if data.len() < 3 + cert_list_len {
        return None;
    }

    let mut offset = 3;

    // Parse only the first certificate (server's certificate)
    if offset + 3 <= data.len() {
        let cert_len =
            u32::from_be_bytes([0, data[offset], data[offset + 1], data[offset + 2]]) as usize;
        offset += 3;

        if offset + cert_len <= data.len() {
            let cert_data = &data[offset..offset + cert_len];
            parse_x509_certificate(cert_data, info);
        }
    }

    Some(())
}

fn parse_x509_certificate(cert_data: &[u8], info: &mut TlsInfo) {
    // This is a simplified X.509 parser that looks for CN and SAN
    // In production, you'd want to use a proper X.509 parsing library like x509-parser

    // Look for common patterns in certificates
    // CN is typically preceded by the OID 2.5.4.3 (0x55, 0x04, 0x03)
    // SAN extension has OID 2.5.29.17 (0x55, 0x1D, 0x11)

    // Search for Common Name
    let cn_oid = [0x55, 0x04, 0x03];
    if let Some(pos) = cert_data.windows(3).position(|w| w == cn_oid) {
        if pos + 5 < cert_data.len() {
            // Skip OID and tag
            let len = cert_data[pos + 4] as usize;
            if pos + 5 + len <= cert_data.len() {
                if let Ok(cn) = std::str::from_utf8(&cert_data[pos + 5..pos + 5 + len]) {
                    info.certificate_cn = Some(cn.to_string());
                }
            }
        }
    }

    // Search for Subject Alternative Names
    // This is a simplified approach - real implementation would need proper ASN.1 parsing
    let san_oid = [0x55, 0x1D, 0x11];
    if let Some(pos) = cert_data.windows(3).position(|w| w == san_oid) {
        // SAN parsing is complex due to ASN.1 encoding
        // In production, use a proper X.509 library
        // This is just a placeholder
        info.certificate_san
            .push("Use x509-parser for proper SAN extraction".to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_version_parsing() {
        assert_eq!(version_from_bytes(0x03, 0x01), Some(TlsVersion::Tls10));
        assert_eq!(version_from_bytes(0x03, 0x02), Some(TlsVersion::Tls11));
        assert_eq!(version_from_bytes(0x03, 0x03), Some(TlsVersion::Tls12));
        assert_eq!(version_from_bytes(0x03, 0x04), Some(TlsVersion::Tls13));
        assert_eq!(version_from_bytes(0x02, 0x00), None);
    }

    #[test]
    fn test_is_tls_handshake() {
        let valid_handshake = [0x16, 0x03, 0x03, 0x00, 0x50, 0x01];
        assert!(is_tls_handshake(&valid_handshake));

        let invalid_type = [0x17, 0x03, 0x03, 0x00, 0x50, 0x01];
        assert!(!is_tls_handshake(&invalid_type));

        let too_short = [0x16, 0x03];
        assert!(!is_tls_handshake(&too_short));
    }
}
