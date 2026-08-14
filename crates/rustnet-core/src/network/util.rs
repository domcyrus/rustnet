//! Small shared formatting helpers used across the analysis layer.

use std::fmt::Write as _;

/// Encode bytes as a lowercase hex string, with `separator` between bytes
/// ("" for a compact digest, ":" for MAC/connection-ID style).
pub fn hex_encode(bytes: &[u8], separator: &str) -> String {
    let mut out = String::with_capacity(bytes.len() * (2 + separator.len()));
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push_str(separator);
        }
        // write! to a String never fails.
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0xDE, 0xAD, 0xBE, 0xEF], ""), "deadbeef");
        assert_eq!(hex_encode(&[0x00, 0xFF], ""), "00ff");
    }

    #[test]
    fn test_hex_encode_lowercase_20_byte_info_hash() {
        // A representative 20-byte info-hash (the size BitTorrent always uses).
        let info_hash: [u8; 20] = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x00, 0xff, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        ];
        assert_eq!(
            hex_encode(&info_hash, ""),
            "123456789abcdef000ff0102030405060708090a"
        );
    }

    #[test]
    fn test_hex_encode_empty_slice() {
        assert_eq!(hex_encode(&[], ""), "");
    }

    #[test]
    fn test_hex_encode_pads_single_digit_bytes() {
        // Locks the `{:02x}` padding contract: 0x00..=0x0f stay two chars.
        assert_eq!(hex_encode(&[0x00, 0x0a, 0x0f, 0x10], ""), "000a0f10");
    }

    #[test]
    fn test_hex_encode_with_separator() {
        assert_eq!(
            hex_encode(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], ":"),
            "aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(hex_encode(&[0x01], ":"), "01");
    }
}
