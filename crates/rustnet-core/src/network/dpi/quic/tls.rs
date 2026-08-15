use crate::network::dpi::tls_common::{
    self, TlsParseOptions, is_partial_sni, parse_sni_extension, parse_sni_header,
};
use crate::network::types::{CryptoFrameReassembler, TlsInfo};
use log::debug;

use super::salvage::{try_parse_unencrypted_crypto_frames, try_reconstruct_sni_from_fragments};

/// Check if SNI is complete (not partial)
fn is_complete_sni(sni: &Option<String>) -> bool {
    match sni {
        Some(s) => !is_partial_sni(s),
        None => false,
    }
}

/// Strategy 1: Try to extract TLS info from contiguous reassembled data
fn try_extract_from_contiguous(
    reassembler: &CryptoFrameReassembler,
    allow_partial: bool,
) -> Option<TlsInfo> {
    let reassembled = reassembler.get_contiguous_data()?;

    debug!(
        "QUIC: Attempting to parse {} bytes of contiguous crypto data (allow_partial={})",
        reassembled.len(),
        allow_partial
    );

    // Only attempt to parse if we have enough data for a reasonable ClientHello
    // Use lower threshold (50 bytes) when allowing partial extraction
    let threshold = if allow_partial { 50 } else { 100 };
    if reassembled.len() < threshold {
        debug!(
            "QUIC: Only {} contiguous bytes available, waiting for more data before parsing",
            reassembled.len()
        );
        return None;
    }

    let tls_info = parse_partial_tls_handshake(&reassembled, allow_partial)?;

    // Check if we have the essential info (SNI and ALPN)
    if tls_info.sni.is_none() && tls_info.alpn.is_empty() {
        return None;
    }

    let sni_is_complete = is_complete_sni(&tls_info.sni);
    debug!(
        "QUIC: Found TLS info from contiguous data (complete={})",
        sni_is_complete
    );
    Some(tls_info)
}

/// Strategy 2: Try to parse individual fragments with proper TLS headers
fn try_extract_from_fragments(
    reassembler: &CryptoFrameReassembler,
    allow_partial: bool,
) -> Option<TlsInfo> {
    debug!("QUIC: Trying to parse individual crypto fragments with proper TLS headers");

    for (&offset, fragment_data) in reassembler.get_fragments() {
        debug!(
            "QUIC: Trying fragment at offset {} with {} bytes",
            offset,
            fragment_data.len()
        );

        // Only try to parse fragments that look like they contain complete TLS structures
        // Check if fragment starts with TLS handshake header (0x01 for ClientHello)
        if fragment_data.len() >= 4
            && fragment_data[0] == 0x01
            && let Some(tls_info) = parse_partial_tls_handshake(fragment_data, allow_partial)
            && (tls_info.sni.is_some() || !tls_info.alpn.is_empty())
        {
            let sni_is_complete = is_complete_sni(&tls_info.sni);
            debug!(
                "QUIC: Found TLS info from individual fragment at offset {} (complete={})",
                offset, sni_is_complete
            );
            return Some(tls_info);
        }

        // Also try direct TLS pattern matching, but only for fragments that look like TLS records
        if fragment_data.len() >= 6
            && fragment_data[0] == 0x16
            && let Some(tls_info) = try_parse_unencrypted_crypto_frames(fragment_data)
            && (tls_info.sni.is_some() || !tls_info.alpn.is_empty())
        {
            let sni_is_complete = is_complete_sni(&tls_info.sni);
            debug!(
                "QUIC: Found TLS info from pattern matching in fragment at offset {} (complete={})",
                offset, sni_is_complete
            );
            return Some(tls_info);
        }

        debug!(
            "QUIC: Skipping fragment at offset {} - doesn't start with TLS header",
            offset
        );
    }

    None
}

/// Strategy 3: Try greedy SNI extraction from all fragments and contiguous data
fn try_extract_greedy_from_reassembler(reassembler: &CryptoFrameReassembler) -> Option<TlsInfo> {
    debug!("QUIC: Attempting greedy SNI extraction as final fallback");

    // Try greedy extraction on fragments
    for fragment_data in reassembler.get_fragments().values() {
        if let Some(sni) = scan_for_sni_extension(fragment_data, true, SniScanStrictness::Lenient) {
            let mut tls_info = TlsInfo::new();
            tls_info.sni = Some(sni);
            debug!("QUIC: Greedy extraction succeeded from fragment");
            return Some(tls_info);
        }
    }

    // Also try on contiguous data if available
    if let Some(contiguous) = reassembler.get_contiguous_data()
        && let Some(sni) = scan_for_sni_extension(&contiguous, true, SniScanStrictness::Lenient)
    {
        let mut tls_info = TlsInfo::new();
        tls_info.sni = Some(sni);
        debug!("QUIC: Greedy extraction succeeded from contiguous data");
        return Some(tls_info);
    }

    None
}

/// Try to extract TLS information from reassembled fragments
///
/// The `allow_partial` parameter controls whether partial SNI extraction is allowed:
/// - `false`: Only return complete SNI (used during initial packet parsing)
/// - `true`: Return partial SNI as fallback (used during merge/re-extraction)
///
/// This function orchestrates multiple extraction strategies in order of preference:
/// 1. Check cache for complete SNI
/// 2. Parse contiguous data
/// 3. Parse individual fragments with TLS headers
/// 4. Reconstruct SNI from fragmented data
/// 5. Greedy fallback extraction
pub fn try_extract_tls_from_reassembler(
    reassembler: &mut CryptoFrameReassembler,
    allow_partial: bool,
) -> Option<TlsInfo> {
    // Strategy 0: Check cache for complete SNI
    if let Some(tls_info) = reassembler.get_cached_tls_info() {
        if is_complete_sni(&tls_info.sni) {
            return Some(tls_info.clone());
        }
        debug!("QUIC: Cached SNI is partial, attempting to find complete SNI");
    }

    // Strategy 1: Try to parse contiguous data
    if let Some(tls_info) = try_extract_from_contiguous(reassembler, allow_partial) {
        if is_complete_sni(&tls_info.sni) {
            reassembler.set_complete_tls_info(tls_info.clone());
        }
        return Some(tls_info);
    }

    // Strategy 2: Try parsing individual fragments with TLS headers
    if let Some(tls_info) = try_extract_from_fragments(reassembler, allow_partial) {
        if is_complete_sni(&tls_info.sni) {
            reassembler.set_complete_tls_info(tls_info.clone());
        }
        return Some(tls_info);
    }

    // Strategy 3: Try fragment reconstruction (requires reasonable data amount)
    let total_fragment_size: usize = reassembler.get_fragments().values().map(|v| v.len()).sum();
    if total_fragment_size >= 100 {
        debug!(
            "QUIC: Have {} total bytes in fragments, attempting reconstruction",
            total_fragment_size
        );
        if let Some(sni) = try_reconstruct_sni_from_fragments(reassembler) {
            let mut tls_info = TlsInfo::new();
            let sni_is_complete = !is_partial_sni(&sni);
            tls_info.sni = Some(sni);
            debug!(
                "QUIC: Reconstructed SNI from fragmented data (complete={})",
                sni_is_complete
            );
            if sni_is_complete {
                reassembler.set_complete_tls_info(tls_info.clone());
            }
            return Some(tls_info);
        }
    } else {
        debug!(
            "QUIC: Only {} total bytes in fragments, not enough for reliable SNI extraction",
            total_fragment_size
        );
    }

    // Strategy 4: Greedy fallback extraction
    if let Some(tls_info) = try_extract_greedy_from_reassembler(reassembler) {
        reassembler.set_complete_tls_info(tls_info.clone());
        return Some(tls_info);
    }

    debug!("QUIC: No TLS info could be extracted from reassembler");
    None
}

/// Parse a TLS handshake from reassembled data
pub(super) fn parse_partial_tls_handshake(data: &[u8], allow_partial: bool) -> Option<TlsInfo> {
    let mut info = TlsInfo::new();
    if !tls_common::parse_handshake(data, &mut info, TlsParseOptions::quic(allow_partial)) {
        return None;
    }

    debug!(
        "QUIC: Parsed TLS info - SNI={:?}, ALPN={:?}, version={:?}",
        info.sni, info.alpn, info.version
    );

    if info.sni.is_some() || !info.alpn.is_empty() || info.version.is_some() {
        Some(info)
    } else {
        debug!("QUIC: No useful TLS info extracted");
        None
    }
}

/// Validation strictness applied to SNI extension candidates found by raw byte scanning
#[derive(Clone, Copy)]
pub(super) enum SniScanStrictness {
    /// Accept any candidate whose server name list fits within the extension length
    Lenient,
    /// Require a plausible server name list length, tolerating truncated extension data
    Moderate,
    /// Require the full extension to be present with exactly consistent header lengths
    Strict,
}

/// Try to match an SNI extension at position `i` in raw scan data
///
/// SNI extension structure:
/// - 0x00 0x00 - extension type (SNI)
/// - 2 bytes - extension length
/// - 2 bytes - server name list length
/// - 0x00 - name type (hostname)
/// - 2 bytes - hostname length
/// - N bytes - hostname
pub(super) fn match_sni_extension_at(
    data: &[u8],
    i: usize,
    allow_partial: bool,
    strictness: SniScanStrictness,
) -> Option<String> {
    let min_tail = match strictness {
        SniScanStrictness::Lenient => 9,
        SniScanStrictness::Moderate => 10,
        SniScanStrictness::Strict => 20,
    };
    if i + min_tail >= data.len() {
        return None;
    }

    // Look for SNI extension type marker
    if data[i] != 0x00 || data[i + 1] != 0x00 {
        return None;
    }

    // Sanity check extension length (5-300 bytes is reasonable for SNI)
    let ext_len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
    if !(5..=300).contains(&ext_len) {
        return None;
    }

    let ext_data = match strictness {
        SniScanStrictness::Lenient => &data[i + 4..],
        SniScanStrictness::Moderate => {
            if i + 4 + ext_len <= data.len() {
                &data[i + 4..i + 4 + ext_len]
            } else {
                &data[i + 4..]
            }
        }
        SniScanStrictness::Strict => {
            if i + 4 + ext_len > data.len() {
                return None;
            }
            &data[i + 4..i + 4 + ext_len]
        }
    };

    // Parse SNI header using unified helper
    let header = parse_sni_header(ext_data)?;
    let list_len = header.list_len as usize;

    let header_plausible = match strictness {
        SniScanStrictness::Lenient => list_len <= ext_len,
        SniScanStrictness::Moderate => (3..=256).contains(&list_len),
        SniScanStrictness::Strict => {
            (3..=256).contains(&list_len) && list_len == header.name_len as usize + 3
        }
    };
    if !header_plausible {
        return None;
    }

    parse_sni_extension(ext_data, allow_partial)
}

/// Scan raw data for an SNI extension pattern
/// This works even when full ClientHello parsing fails due to incomplete data
///
/// The `allow_partial` parameter controls whether partial SNI extraction is allowed:
/// - `false`: Only return complete SNI
/// - `true`: Return partial SNI as fallback when full hostname is truncated
pub(super) fn scan_for_sni_extension(
    data: &[u8],
    allow_partial: bool,
    strictness: SniScanStrictness,
) -> Option<String> {
    (0..data.len()).find_map(|i| match_sni_extension_at(data, i, allow_partial, strictness))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::dpi::tls_common::test_fixtures::build_sni_extension;

    #[test]
    fn test_greedy_sni_extraction_complete() {
        let sni_ext = build_sni_extension("www.example.com");
        // allow_partial doesn't matter when full hostname is available
        let result = scan_for_sni_extension(&sni_ext, false, SniScanStrictness::Lenient);
        assert_eq!(result, Some("www.example.com".to_string()));
    }

    #[test]
    fn test_greedy_sni_extraction_with_prefix() {
        // Add some random bytes before the SNI extension
        let mut data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        data.extend(build_sni_extension("api.google.com"));
        let result = scan_for_sni_extension(&data, false, SniScanStrictness::Lenient);
        assert_eq!(result, Some("api.google.com".to_string()));
    }

    #[test]
    fn test_greedy_sni_extraction_partial() {
        // Build partial SNI extension (hostname truncated)
        // With fragmented QUIC packets, we need to extract partial SNI
        let mut data = Vec::new();
        data.push(0x00); // ext type
        data.push(0x00);
        data.extend_from_slice(&20u16.to_be_bytes()); // ext_len (full would be 20)
        data.extend_from_slice(&18u16.to_be_bytes()); // list_len
        data.push(0x00); // name type
        data.extend_from_slice(&15u16.to_be_bytes()); // name_len (15 chars)
        data.extend_from_slice(b"www.examp"); // only 9 chars provided

        // With allow_partial=false, returns None
        let result = scan_for_sni_extension(&data, false, SniScanStrictness::Lenient);
        assert_eq!(result, None);

        // With allow_partial=true, returns partial SNI
        let result = scan_for_sni_extension(&data, true, SniScanStrictness::Lenient);
        assert_eq!(result, Some("www.examp[PARTIAL]".to_string()));
    }

    #[test]
    fn test_greedy_extraction_ignores_invalid_patterns() {
        // Data with 0x00 0x00 but invalid SNI structure
        let data = vec![0x00, 0x00, 0x00, 0x01, 0x00]; // ext_len = 1 (too short)
        let result = scan_for_sni_extension(&data, true, SniScanStrictness::Lenient);
        assert_eq!(result, None);
    }

    #[test]
    fn test_greedy_extraction_multiple_zeros() {
        // Data with multiple 0x00 0x00 sequences, only one valid
        let mut data = vec![0x00, 0x00, 0x00, 0x02, 0xFF]; // Invalid SNI
        data.extend(build_sni_extension("valid.example.com"));
        let result = scan_for_sni_extension(&data, false, SniScanStrictness::Lenient);
        assert_eq!(result, Some("valid.example.com".to_string()));
    }
}
