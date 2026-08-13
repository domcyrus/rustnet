use crate::network::types::{CryptoFrameReassembler, TlsInfo, TlsVersion};
use log::debug;

use super::salvage::{try_parse_unencrypted_crypto_frames, try_reconstruct_sni_from_fragments};

// ============================================================================
// SNI Validation and Parsing Helpers
// ============================================================================

/// Minimum length for partial SNI extraction
const PARTIAL_SNI_MIN_LENGTH: usize = 3;

/// Marker suffix for partial SNI values
const PARTIAL_SNI_MARKER: &str = "[PARTIAL]";

/// Validate if a string looks like a valid complete hostname
///
/// This is the unified hostname validation function used across all SNI extraction methods.
/// Rules:
/// - Length between 4 and 253 characters
/// - Contains at least one '.'
/// - Only ASCII alphanumeric, '.', and '-' characters
/// - Doesn't start or end with '.' or '-'
/// - No consecutive dots '..'
/// - Has at least one alphabetic character
/// - Each label is non-empty and at most 63 characters
pub(super) fn is_valid_hostname(hostname: &str) -> bool {
    // Length check
    if hostname.len() < 4 || hostname.len() > 253 {
        return false;
    }

    // Must contain at least one dot
    if !hostname.contains('.') {
        return false;
    }

    // Check for valid hostname characters only
    if !hostname
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return false;
    }

    // Must not start or end with a dot or hyphen
    if hostname.starts_with('.')
        || hostname.ends_with('.')
        || hostname.starts_with('-')
        || hostname.ends_with('-')
    {
        return false;
    }

    // Must not contain consecutive dots
    if hostname.contains("..") {
        return false;
    }

    // Must have at least one alphabetic character (not just numbers and dots)
    if !hostname.chars().any(|c| c.is_ascii_alphabetic()) {
        return false;
    }

    // Each label must be non-empty and at most 63 characters
    if !hostname
        .split('.')
        .all(|part| !part.is_empty() && part.len() <= 63)
    {
        return false;
    }

    true
}

/// Validate if a string looks like a valid partial hostname
///
/// Partial hostnames have relaxed rules since they may be truncated:
/// - Minimum length (PARTIAL_SNI_MIN_LENGTH)
/// - Only ASCII alphanumeric, '.', and '-' characters
/// - Has at least one alphabetic character
/// - Doesn't start with '.' or '-'
fn is_valid_partial_hostname(hostname: &str) -> bool {
    if hostname.len() < PARTIAL_SNI_MIN_LENGTH {
        return false;
    }

    // Check for valid hostname characters only
    if !hostname
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return false;
    }

    // Must have at least one alphabetic character
    if !hostname.chars().any(|c| c.is_ascii_alphabetic()) {
        return false;
    }

    // Must not start with '.' or '-'
    if hostname.starts_with('.') || hostname.starts_with('-') {
        return false;
    }

    true
}

/// Mark an SNI value as partial by appending the marker
fn mark_partial_sni(hostname: &str) -> String {
    format!("{}{}", hostname, PARTIAL_SNI_MARKER)
}

/// Check if an SNI value is marked as partial
pub fn is_partial_sni(sni: &str) -> bool {
    sni.ends_with(PARTIAL_SNI_MARKER)
}

/// Parsed SNI extension header
struct SniHeader {
    /// Server name list length
    list_len: u16,
    /// Hostname length
    name_len: u16,
}

/// Parse the SNI extension header from raw data
///
/// Expects data starting at the SNI extension content (after extension type and length):
/// - 2 bytes: server name list length
/// - 1 byte: name type (0x00 = hostname)
/// - 2 bytes: hostname length
///
/// Returns None if data is too short or name type is not hostname
fn parse_sni_header(data: &[u8]) -> Option<SniHeader> {
    if data.len() < 5 {
        return None;
    }

    let list_len = u16::from_be_bytes([data[0], data[1]]);
    let name_type = data[2];
    let name_len = u16::from_be_bytes([data[3], data[4]]);

    // Name type must be 0x00 (hostname)
    if name_type != 0x00 {
        return None;
    }

    // Validate hostname length is reasonable
    if name_len == 0 || name_len > 253 {
        return None;
    }

    Some(SniHeader { list_len, name_len })
}

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
    if data.len() < 4 {
        debug!("QUIC: TLS handshake data too short: {} bytes", data.len());
        return None;
    }

    let handshake_type = data[0];
    let handshake_length = u32::from_be_bytes([0, data[1], data[2], data[3]]) as usize;

    debug!(
        "QUIC: TLS handshake type=0x{:02x}, declared_length={}, available_data={}, allow_partial={}",
        handshake_type,
        handshake_length,
        data.len() - 4,
        allow_partial
    );

    let mut info = TlsInfo::new();

    let available_data = &data[4..];
    let parse_length = handshake_length.min(available_data.len());

    // Sanity check the handshake length
    if handshake_length > 65536 {
        debug!(
            "QUIC: Handshake length {} seems too large, skipping",
            handshake_length
        );
        return None;
    }

    match handshake_type {
        0x01 => {
            // Client Hello
            debug!("QUIC: Parsing ClientHello with {} bytes", parse_length);
            parse_partial_client_hello(&available_data[..parse_length], &mut info, allow_partial);
        }
        0x02 => {
            // Server Hello
            debug!("QUIC: Parsing ServerHello with {} bytes", parse_length);
            parse_partial_server_hello(&available_data[..parse_length], &mut info);
        }
        _ => {
            debug!(
                "QUIC: Unknown/unsupported handshake type: 0x{:02x}",
                handshake_type
            );
            return None;
        }
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

/// Parse a partial Client Hello
fn parse_partial_client_hello(data: &[u8], info: &mut TlsInfo, allow_partial: bool) {
    debug!(
        "QUIC: Parsing ClientHello with {} bytes (allow_partial={})",
        data.len(),
        allow_partial
    );

    if data.len() < 34 {
        debug!(
            "QUIC: ClientHello too short: {} bytes (need at least 34)",
            data.len()
        );
        return;
    }

    // Skip version (2) + random (32)
    let mut offset = 34;
    debug!(
        "QUIC: ClientHello - skipping version and random, offset now={}",
        offset
    );

    // Session ID
    if offset >= data.len() {
        return;
    }
    let session_id_len = data[offset] as usize;
    offset += 1 + session_id_len;

    if offset + 2 > data.len() {
        return;
    }

    // Cipher suites
    let cipher_suites_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2 + cipher_suites_len;

    if offset >= data.len() {
        return;
    }

    // Compression methods
    let compression_len = data[offset] as usize;
    offset += 1 + compression_len;

    if offset + 2 > data.len() {
        return;
    }

    // Extensions
    let extensions_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    debug!(
        "QUIC: ClientHello extensions - declared_len={}, available_data={}",
        extensions_len,
        data.len() - offset
    );

    let available_ext_len = (data.len() - offset).min(extensions_len);
    if available_ext_len > 0 {
        debug!("QUIC: Parsing {} bytes of extensions", available_ext_len);
        parse_tls_extensions(
            &data[offset..offset + available_ext_len],
            info,
            true,
            allow_partial,
        );
    } else {
        debug!("QUIC: No extensions data available");
    }
}

/// Parse a partial Server Hello
fn parse_partial_server_hello(data: &[u8], info: &mut TlsInfo) {
    if data.len() < 34 {
        return;
    }

    // Skip version (2) + random (32)
    let mut offset = 34;

    // Session ID
    if offset >= data.len() {
        return;
    }
    let session_id_len = data[offset] as usize;
    offset += 1 + session_id_len;

    if offset + 2 > data.len() {
        return;
    }

    // Cipher suite
    let cipher = u16::from_be_bytes([data[offset], data[offset + 1]]);
    info.cipher_suite = Some(cipher);
    offset += 2;

    // Compression method
    if offset >= data.len() {
        return;
    }
    offset += 1;

    // Extensions
    if offset + 2 > data.len() {
        return;
    }

    let extensions_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    let available_ext_len = (data.len() - offset).min(extensions_len);
    if available_ext_len > 0 {
        parse_tls_extensions(
            &data[offset..offset + available_ext_len],
            info,
            false,
            false,
        );
    }
}

/// Parse TLS extensions
fn parse_tls_extensions(data: &[u8], info: &mut TlsInfo, is_client: bool, allow_partial: bool) {
    let mut offset = 0;
    debug!(
        "QUIC: Parsing {} bytes of TLS extensions (is_client={}, allow_partial={})",
        data.len(),
        is_client,
        allow_partial
    );

    while offset + 4 <= data.len() {
        let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let ext_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;

        debug!(
            "QUIC: Extension type=0x{:04x}, length={}",
            ext_type, ext_len
        );

        if offset + 4 + ext_len > data.len() {
            // Extension data is incomplete
            if allow_partial && ext_type == 0x0000 && is_client {
                // Try to extract partial SNI as fallback
                let available_ext_len = data.len() - offset - 4;
                if available_ext_len > 5 {
                    debug!(
                        "QUIC: SNI extension is incomplete (need {} bytes, have {}), attempting partial extraction",
                        ext_len, available_ext_len
                    );
                    let ext_data = &data[offset + 4..];
                    if let Some(sni) = parse_sni_extension(ext_data, true) {
                        debug!("QUIC: Extracted partial SNI as fallback: {}", sni);
                        info.sni = Some(sni);
                    }
                }
            } else {
                debug!(
                    "QUIC: Extension 0x{:04x} is incomplete (need {} bytes, have {}), waiting for more data",
                    ext_type,
                    ext_len,
                    data.len() - offset - 4
                );
            }
            break;
        }

        let ext_data = &data[offset + 4..offset + 4 + ext_len];

        match ext_type {
            0x0000 if is_client => {
                // SNI
                debug!("QUIC: Found SNI extension with {} bytes", ext_len);
                if let Some(sni) = parse_sni_extension(ext_data, allow_partial) {
                    debug!("QUIC: Successfully parsed SNI: {}", sni);
                    info.sni = Some(sni);
                } else {
                    debug!("QUIC: Failed to parse SNI extension");
                }
            }
            0x0010 => {
                // ALPN
                debug!("QUIC: Found ALPN extension with {} bytes", ext_len);
                if let Some(alpn) = parse_alpn_extension(ext_data) {
                    debug!("QUIC: Successfully parsed ALPN: {:?}", alpn);
                    info.alpn = alpn;
                } else {
                    debug!("QUIC: Failed to parse ALPN extension");
                }
            }
            0x002b => {
                // Supported Versions
                debug!(
                    "QUIC: Found Supported Versions extension with {} bytes",
                    ext_len
                );
                if let Some(version) = parse_supported_versions(ext_data, is_client) {
                    debug!("QUIC: Successfully parsed version: {:?}", version);
                    info.version = Some(version);
                }
            }
            _ => {
                debug!("QUIC: Skipping unknown extension type 0x{:04x}", ext_type);
            }
        }

        offset += 4 + ext_len;
    }

    debug!(
        "QUIC: Finished parsing extensions - found SNI={:?}, ALPN={:?}",
        info.sni, info.alpn
    );
}

/// Parse SNI extension
fn parse_sni_extension(data: &[u8], allow_partial: bool) -> Option<String> {
    debug!(
        "QUIC: Parsing SNI extension with {} bytes (allow_partial={}): {:02x?}",
        data.len(),
        allow_partial,
        &data[..data.len().min(20)]
    );

    // Parse the SNI header using the unified helper
    let header = match parse_sni_header(data) {
        Some(h) => h,
        None => {
            debug!(
                "QUIC: Failed to parse SNI header (data len: {})",
                data.len()
            );
            return None;
        }
    };

    debug!(
        "QUIC: SNI header - list_len: {}, name_len: {}",
        header.list_len, header.name_len
    );

    let name_len = header.name_len as usize;
    let hostname_start = 5; // After header (2 + 1 + 2 bytes)

    if hostname_start + name_len <= data.len() {
        // Full hostname available
        let sni_data = &data[hostname_start..hostname_start + name_len];
        debug!("QUIC: SNI data: {:02x?}", sni_data);

        match std::str::from_utf8(sni_data) {
            Ok(sni) => {
                if is_valid_hostname(sni) {
                    debug!("QUIC: Successfully parsed complete SNI: {}", sni);
                    Some(sni.to_string())
                } else {
                    debug!("QUIC: SNI doesn't look like a valid hostname: {}", sni);
                    None
                }
            }
            Err(e) => {
                debug!("QUIC: SNI data is not valid UTF-8: {}", e);
                None
            }
        }
    } else if allow_partial && data.len() > hostname_start {
        // Extract partial SNI as fallback when allowed
        let available = &data[hostname_start..];
        debug!(
            "QUIC: SNI name extends beyond available data (need {}, have {}), extracting partial",
            hostname_start + name_len,
            data.len()
        );

        if let Ok(partial) = std::str::from_utf8(available)
            && is_valid_partial_hostname(partial)
        {
            debug!("QUIC: Extracted partial SNI: {}", mark_partial_sni(partial));
            return Some(mark_partial_sni(partial));
        }
        None
    } else {
        // SNI data is incomplete - don't extract partial, wait for more data
        debug!(
            "QUIC: SNI name extends beyond available data (need {}, have {}), waiting for more data",
            hostname_start + name_len,
            data.len()
        );
        None
    }
}

/// Parse ALPN extension
pub(super) fn parse_alpn_extension(data: &[u8]) -> Option<Vec<String>> {
    if data.len() < 2 {
        return None;
    }

    let mut protocols = Vec::new();
    let alpn_len = u16::from_be_bytes([data[0], data[1]]) as usize;

    let mut offset = 2;
    let list_end = 2 + alpn_len.min(data.len() - 2);

    while offset < list_end && offset < data.len() {
        let proto_len = data[offset] as usize;
        offset += 1;

        if offset + proto_len <= data.len()
            && let Ok(proto) = std::str::from_utf8(&data[offset..offset + proto_len])
        {
            protocols.push(proto.to_string());
        }

        offset += proto_len;
    }

    if protocols.is_empty() {
        None
    } else {
        Some(protocols)
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

/// Parse supported versions extension
fn parse_supported_versions(data: &[u8], is_client: bool) -> Option<TlsVersion> {
    if is_client {
        if data.is_empty() {
            return None;
        }

        let list_len = data[0] as usize;
        let mut offset = 1;

        while offset + 1 < data.len() && offset < 1 + list_len {
            if data[offset] == 0x03 && data[offset + 1] == 0x04 {
                return Some(TlsVersion::Tls13);
            }
            offset += 2;
        }
    } else if data.len() >= 2 && data[0] == 0x03 && data[1] == 0x04 {
        return Some(TlsVersion::Tls13);
    }

    // QUIC always uses TLS 1.3
    Some(TlsVersion::Tls13)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal SNI extension structure
    fn build_sni_extension(hostname: &str) -> Vec<u8> {
        let name_bytes = hostname.as_bytes();
        let name_len = name_bytes.len() as u16;
        let list_len = name_len + 3; // name_type (1) + name_len (2)
        let ext_len = list_len + 2; // list_len (2)

        let mut data = Vec::new();
        // Extension type: SNI (0x0000)
        data.push(0x00);
        data.push(0x00);
        // Extension length
        data.extend_from_slice(&ext_len.to_be_bytes());
        // Server name list length
        data.extend_from_slice(&list_len.to_be_bytes());
        // Name type: hostname (0x00)
        data.push(0x00);
        // Name length
        data.extend_from_slice(&name_len.to_be_bytes());
        // Hostname
        data.extend_from_slice(name_bytes);

        data
    }

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
    fn test_parse_sni_extension_complete() {
        // Build SNI extension data (without the extension type/length header)
        let hostname = "test.example.org";
        let name_bytes = hostname.as_bytes();
        let name_len = name_bytes.len() as u16;
        let list_len = name_len + 3;

        let mut data = Vec::new();
        data.extend_from_slice(&list_len.to_be_bytes());
        data.push(0x00); // name type
        data.extend_from_slice(&name_len.to_be_bytes());
        data.extend_from_slice(name_bytes);

        let result = parse_sni_extension(&data, false);
        assert_eq!(result, Some("test.example.org".to_string()));
    }

    #[test]
    fn test_parse_sni_extension_partial() {
        // Build partial SNI extension data
        let mut data = Vec::new();
        data.extend_from_slice(&20u16.to_be_bytes()); // list_len
        data.push(0x00); // name type
        data.extend_from_slice(&15u16.to_be_bytes()); // declared name_len
        data.extend_from_slice(b"example.co"); // only 10 chars

        // With allow_partial=false, returns None
        let result = parse_sni_extension(&data, false);
        assert_eq!(result, None);

        // With allow_partial=true, returns partial SNI
        let result = parse_sni_extension(&data, true);
        assert_eq!(result, Some("example.co[PARTIAL]".to_string()));
    }

    #[test]
    fn test_parse_alpn_extension() {
        // Build ALPN extension data (without the extension type/length header)
        let mut data = Vec::new();
        let protocols = vec!["h3", "h2"];

        let mut proto_list = Vec::new();
        for proto in &protocols {
            proto_list.push(proto.len() as u8);
            proto_list.extend_from_slice(proto.as_bytes());
        }

        data.extend_from_slice(&(proto_list.len() as u16).to_be_bytes());
        data.extend_from_slice(&proto_list);

        let result = parse_alpn_extension(&data);
        assert_eq!(result, Some(vec!["h3".to_string(), "h2".to_string()]));
    }

    #[test]
    fn test_is_valid_hostname() {
        assert!(is_valid_hostname("example.com"));
        assert!(is_valid_hostname("www.example.com"));
        assert!(is_valid_hostname("sub.domain.example.org"));
        assert!(is_valid_hostname("my-site.io"));

        // Invalid hostnames
        assert!(!is_valid_hostname("com")); // No dot
        assert!(!is_valid_hostname(".example.com")); // Starts with dot
        assert!(!is_valid_hostname("example.com.")); // Ends with dot
        assert!(!is_valid_hostname("-example.com")); // Starts with hyphen
        assert!(!is_valid_hostname("example..com")); // Consecutive dots
        assert!(!is_valid_hostname("ab")); // Too short
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
