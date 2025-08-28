//! TLS Cipher Suite mappings
//!
//! This module provides mappings from cipher suite codes to their human-readable names.
//! The mappings are based on the IANA TLS Cipher Suite Registry and include commonly
//! used cipher suites from TLS 1.0 through TLS 1.3.

use std::collections::HashMap;
use std::sync::LazyLock;

/// Static mapping of cipher suite codes to their names
static CIPHER_SUITE_MAP: LazyLock<HashMap<u16, &'static str>> = LazyLock::new(|| {
    let mut map = HashMap::new();

    // TLS 1.3 Cipher Suites (RFC 8446)
    map.insert(0x1301, "TLS_AES_128_GCM_SHA256");
    map.insert(0x1302, "TLS_AES_256_GCM_SHA384");
    map.insert(0x1303, "TLS_CHACHA20_POLY1305_SHA256");
    map.insert(0x1304, "TLS_AES_128_CCM_SHA256");
    map.insert(0x1305, "TLS_AES_128_CCM_8_SHA256");

    // TLS 1.2 ECDHE Cipher Suites (RFC 5289, RFC 7905)
    map.insert(0xc02b, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
    map.insert(0xc02c, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
    map.insert(0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
    map.insert(0xc030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
    map.insert(0xc009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA");
    map.insert(0xc00a, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA");
    map.insert(0xc013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
    map.insert(0xc014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA");
    map.insert(0xc023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256");
    map.insert(0xc024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
    map.insert(0xc027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256");
    map.insert(0xc028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384");

    // ChaCha20-Poly1305 (RFC 7905)
    map.insert(0xcca9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256");
    map.insert(0xcca8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256");
    map.insert(0xccaa, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256");

    // DHE Cipher Suites
    map.insert(0x009e, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256");
    map.insert(0x009f, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384");
    map.insert(0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA");
    map.insert(0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA");
    map.insert(0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256");
    map.insert(0x006b, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256");

    // RSA Cipher Suites (less preferred but still common)
    map.insert(0x009c, "TLS_RSA_WITH_AES_128_GCM_SHA256");
    map.insert(0x009d, "TLS_RSA_WITH_AES_256_GCM_SHA384");
    map.insert(0x002f, "TLS_RSA_WITH_AES_128_CBC_SHA");
    map.insert(0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA");
    map.insert(0x003c, "TLS_RSA_WITH_AES_128_CBC_SHA256");
    map.insert(0x003d, "TLS_RSA_WITH_AES_256_CBC_SHA256");

    // 3DES (Legacy)
    map.insert(0x000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA");
    map.insert(0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA");
    map.insert(0xc008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA");
    map.insert(0xc012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA");

    // RC4 (Deprecated but still seen)
    map.insert(0x0004, "TLS_RSA_WITH_RC4_128_MD5");
    map.insert(0x0005, "TLS_RSA_WITH_RC4_128_SHA");
    map.insert(0xc007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA");
    map.insert(0xc011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA");

    // PSK Cipher Suites (RFC 4279, RFC 5487)
    map.insert(0x008c, "TLS_PSK_WITH_AES_128_CBC_SHA");
    map.insert(0x008d, "TLS_PSK_WITH_AES_256_CBC_SHA");
    map.insert(0x00a8, "TLS_PSK_WITH_AES_128_GCM_SHA256");
    map.insert(0x00a9, "TLS_PSK_WITH_AES_256_GCM_SHA384");

    // ECDHE-PSK
    map.insert(0xc035, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA");
    map.insert(0xc036, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA");
    map.insert(0xc037, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256");
    map.insert(0xc038, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384");

    // ARIA Cipher Suites (RFC 6209)
    map.insert(0xc03c, "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256");
    map.insert(0xc03d, "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384");
    map.insert(0xc060, "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256");
    map.insert(0xc061, "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384");

    // Camellia Cipher Suites (RFC 5932)
    map.insert(0xc072, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256");
    map.insert(0xc073, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384");
    map.insert(0xc076, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256");
    map.insert(0xc077, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384");

    // NULL encryption (for testing/debugging)
    map.insert(0x0001, "TLS_RSA_WITH_NULL_MD5");
    map.insert(0x0002, "TLS_RSA_WITH_NULL_SHA");
    map.insert(0x003b, "TLS_RSA_WITH_NULL_SHA256");

    map
});

/// Get the human-readable name for a cipher suite code
///
/// # Arguments
/// * `code` - The cipher suite code (u16)
///
/// # Returns
/// * Some(name) if the cipher suite is known
/// * None if the cipher suite is not in our mapping
pub fn get_cipher_suite_name(code: u16) -> Option<&'static str> {
    CIPHER_SUITE_MAP.get(&code).copied()
}

/// Format a cipher suite code with its name if known
///
/// # Arguments
/// * `code` - The cipher suite code (u16)
///
/// # Returns
/// * A formatted string like "TLS_AES_128_GCM_SHA256 (0x1301)" if known
/// * Just the hex code like "0x1234" if unknown
pub fn format_cipher_suite(code: u16) -> String {
    match get_cipher_suite_name(code) {
        Some(name) => format!("{} (0x{:04X})", name, code),
        None => format!("0x{:04X}", code),
    }
}

/// Check if a cipher suite is considered secure by modern standards
///
/// # Arguments
/// * `code` - The cipher suite code (u16)
///
/// # Returns
/// * true if the cipher suite is considered secure
/// * false if it's deprecated or insecure
pub fn is_secure_cipher_suite(code: u16) -> bool {
    match code {
        // TLS 1.3 suites are all secure
        0x1301..=0x1305 => true,
        // Modern TLS 1.2 ECDHE suites with AEAD
        0xc02b | 0xc02c | 0xc02f | 0xc030 => true, // ECDHE + AES-GCM
        0xcca8..=0xccaa => true,                   // ChaCha20-Poly1305
        0x009e | 0x009f => true,                   // DHE-RSA with AES-GCM
        // Everything else is either legacy or insecure
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls13_cipher_suites() {
        assert_eq!(
            get_cipher_suite_name(0x1301),
            Some("TLS_AES_128_GCM_SHA256")
        );
        assert_eq!(
            get_cipher_suite_name(0x1302),
            Some("TLS_AES_256_GCM_SHA384")
        );
        assert_eq!(
            get_cipher_suite_name(0x1303),
            Some("TLS_CHACHA20_POLY1305_SHA256")
        );
    }

    #[test]
    fn test_format_cipher_suite() {
        assert_eq!(
            format_cipher_suite(0x1301),
            "TLS_AES_128_GCM_SHA256 (0x1301)"
        );
        assert_eq!(format_cipher_suite(0x9999), "0x9999");
    }

    #[test]
    fn test_security_classification() {
        assert!(is_secure_cipher_suite(0x1301)); // TLS 1.3
        assert!(is_secure_cipher_suite(0xc02f)); // ECDHE-RSA-AES128-GCM-SHA256
        assert!(!is_secure_cipher_suite(0x0004)); // RC4
        assert!(!is_secure_cipher_suite(0x000a)); // 3DES
    }

    #[test]
    fn test_unknown_cipher_suite() {
        assert_eq!(get_cipher_suite_name(0xFFFF), None);
        assert_eq!(format_cipher_suite(0xFFFF), "0xFFFF");
    }
}
