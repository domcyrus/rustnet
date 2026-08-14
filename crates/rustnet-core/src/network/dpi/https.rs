use super::tls_common::{self, TlsParseOptions};
use crate::network::types::{HttpsInfo, TlsInfo};
use log::debug;

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

    // Record layer version (kept even for non-handshake records)
    info.version = tls_common::version_from_bytes(payload[1], payload[2]);

    if payload[0] != 0x16 {
        // Not a handshake record - still extract version
        return Some(HttpsInfo {
            tls_info: Some(info),
        });
    }

    // Get record length
    let record_length = u16::from_be_bytes([payload[3], payload[4]]) as usize;

    // Sanity check
    if record_length > 16384 + 2048 {
        return Some(HttpsInfo {
            tls_info: Some(info),
        });
    }

    // Calculate available data (handle fragmentation gracefully) and hand
    // the handshake bytes to the shared parser. A handshake larger than one
    // record is parsed from the prefix we have.
    let available_data = (payload.len() - 5).min(record_length);
    tls_common::parse_handshake(
        &payload[5..5 + available_data],
        &mut info,
        TlsParseOptions::tcp(),
    );

    if info.sni.is_some() || !info.alpn.is_empty() {
        debug!("TLS: Found SNI={:?}, ALPN={:?}", info.sni, info.alpn);
    }
    Some(HttpsInfo {
        tls_info: Some(info),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::types::TlsVersion;

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
}
