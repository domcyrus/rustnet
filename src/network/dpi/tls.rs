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

    let mut info = TlsInfo {
        version: None,
        sni: None,
        alpn: Vec::new(),
        cipher_suite: None,
    };

    // Record layer version
    let record_version = match payload[2] {
        0x01 => Some(TlsVersion::Tls10),
        0x02 => Some(TlsVersion::Tls11),
        0x03 => Some(TlsVersion::Tls12),
        0x04 => Some(TlsVersion::Tls13),
        _ => None,
    };

    // Skip TLS record header (5 bytes)
    let handshake_data = &payload[5..];

    if handshake_data.len() < 4 {
        return Some(info);
    }

    let handshake_type = handshake_data[0];

    match handshake_type {
        0x01 => {
            // Client Hello
            info.version = record_version;
            if let Some((sni, alpn)) = parse_client_hello_extensions(handshake_data) {
                info.sni = sni;
                info.alpn = alpn;
            }
        }
        0x02 => {
            // Server Hello
            info.version = record_version;
            // Could parse cipher suite here if needed
        }
        _ => {}
    }

    Some(info)
}

/// Parse Client Hello extensions for SNI and ALPN
fn parse_client_hello_extensions(handshake_data: &[u8]) -> Option<(Option<String>, Vec<String>)> {
    if handshake_data.len() < 38 {
        return None;
    }

    // Skip to extensions:
    // - Handshake type (1) + Length (3) + Version (2) + Random (32) = 38
    let mut offset = 38;

    // Session ID
    if offset >= handshake_data.len() {
        return None;
    }
    let session_id_len = handshake_data[offset] as usize;
    offset += 1 + session_id_len;

    // Cipher suites
    if offset + 2 > handshake_data.len() {
        return None;
    }
    let cipher_suites_len =
        u16::from_be_bytes([handshake_data[offset], handshake_data[offset + 1]]) as usize;
    offset += 2 + cipher_suites_len;

    // Compression methods
    if offset >= handshake_data.len() {
        return None;
    }
    let compression_len = handshake_data[offset] as usize;
    offset += 1 + compression_len;

    // Extensions length
    if offset + 2 > handshake_data.len() {
        return None;
    }
    let extensions_len =
        u16::from_be_bytes([handshake_data[offset], handshake_data[offset + 1]]) as usize;
    offset += 2;

    if offset + extensions_len > handshake_data.len() {
        return None;
    }

    // Parse extensions
    let mut sni = None;
    let mut alpn = Vec::new();
    let extensions_data = &handshake_data[offset..offset + extensions_len];
    let mut ext_offset = 0;

    while ext_offset + 4 <= extensions_data.len() {
        let ext_type =
            u16::from_be_bytes([extensions_data[ext_offset], extensions_data[ext_offset + 1]]);
        let ext_len = u16::from_be_bytes([
            extensions_data[ext_offset + 2],
            extensions_data[ext_offset + 3],
        ]) as usize;

        if ext_offset + 4 + ext_len > extensions_data.len() {
            break;
        }

        match ext_type {
            0x0000 => {
                // SNI
                sni =
                    parse_sni_extension(&extensions_data[ext_offset + 4..ext_offset + 4 + ext_len]);
            }
            0x0010 => {
                // ALPN
                alpn = parse_alpn_extension(
                    &extensions_data[ext_offset + 4..ext_offset + 4 + ext_len],
                );
            }
            _ => {}
        }

        ext_offset += 4 + ext_len;
    }

    Some((sni, alpn))
}

fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }

    // Skip server name list length (2 bytes)
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

/// Parse ALPN extension
fn parse_alpn_extension(data: &[u8]) -> Vec<String> {
    let mut protocols = Vec::new();

    if data.len() < 2 {
        return protocols;
    }

    // Skip ALPN extension length
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
