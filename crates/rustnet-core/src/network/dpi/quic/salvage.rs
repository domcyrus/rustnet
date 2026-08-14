use crate::network::types::{CryptoFrameReassembler, TlsInfo};
use log::debug;

use super::tls::{
    SniScanStrictness, match_sni_extension_at, parse_partial_tls_handshake,
    scan_for_sni_extension,
};
use crate::network::dpi::tls_common::{is_partial_sni, is_valid_hostname, parse_alpn_extension};

/// Try to extract TLS information from unencrypted parts of QUIC packets
/// Some QUIC implementations may have plaintext or partially encrypted data
pub(super) fn try_parse_unencrypted_crypto_frames(payload: &[u8]) -> Option<TlsInfo> {
    // This is a best-effort attempt to find TLS ClientHello in the packet
    // Look for TLS handshake patterns in the payload

    debug!(
        "QUIC: Searching for unencrypted TLS data in {} byte payload",
        payload.len()
    );

    let mut offset = 0;
    while offset + 10 < payload.len() {
        // Need at least 10 bytes for meaningful TLS data
        // Look for TLS handshake record header (0x16 0x03 0x01-0x04)
        if payload[offset] == 0x16 && offset + 5 < payload.len() {
            let tls_version_major = payload[offset + 1];
            let tls_version_minor = payload[offset + 2];

            // Check for reasonable TLS version (3.1 = TLS 1.0, 3.2 = TLS 1.1, 3.3 = TLS 1.2, 3.4 = TLS 1.3)
            if tls_version_major == 0x03 && (0x01..=0x04).contains(&tls_version_minor) {
                let record_length =
                    u16::from_be_bytes([payload[offset + 3], payload[offset + 4]]) as usize;

                debug!(
                    "QUIC: Found TLS record at offset {} with length {}",
                    offset, record_length
                );

                if offset + 5 + record_length <= payload.len() {
                    let handshake_data = &payload[offset + 5..offset + 5 + record_length];

                    // Check if this is a ClientHello (handshake type 0x01)
                    if !handshake_data.is_empty() && handshake_data[0] == 0x01 {
                        debug!("QUIC: Found potential TLS ClientHello at offset {}", offset);

                        if let Some(tls_info) = parse_partial_tls_handshake(handshake_data, false) {
                            debug!(
                                "QUIC: Successfully parsed TLS from unencrypted data - SNI={:?}",
                                tls_info.sni
                            );
                            return Some(tls_info);
                        }
                    }
                }
            }
        }

        // Also try looking for direct handshake data (without TLS record wrapper)
        if payload[offset] == 0x01 && offset + 4 < payload.len() {
            // Direct handshake message starting with ClientHello (0x01)
            let handshake_length = u32::from_be_bytes([
                0,
                payload[offset + 1],
                payload[offset + 2],
                payload[offset + 3],
            ]) as usize;

            // Sanity check the length
            if handshake_length > 0
                && handshake_length < 65536
                && offset + 4 + handshake_length <= payload.len()
            {
                debug!(
                    "QUIC: Found potential direct handshake at offset {} with length {}",
                    offset, handshake_length
                );

                if let Some(tls_info) = parse_partial_tls_handshake(
                    &payload[offset..offset + 4 + handshake_length],
                    false,
                ) {
                    debug!(
                        "QUIC: Successfully parsed TLS from direct handshake - SNI={:?}",
                        tls_info.sni
                    );
                    return Some(tls_info);
                }
            }
        }

        // Look for SNI extension pattern directly (0x00 0x00 for SNI type)
        // Strict validation reduces false positives from encrypted data
        if let Some(sni) = match_sni_extension_at(payload, offset, false, SniScanStrictness::Strict)
        {
            debug!("QUIC: Found SNI directly in packet: {}", sni);
            let mut tls_info = TlsInfo::new();
            tls_info.sni = Some(sni);
            return Some(tls_info);
        }

        // Look for ALPN extension pattern (0x00 0x10 for ALPN type)
        if offset + 10 < payload.len() && payload[offset] == 0x00 && payload[offset + 1] == 0x10 {
            let ext_len = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
            if ext_len > 2 && offset + 4 + ext_len <= payload.len() {
                let ext_data = &payload[offset + 4..offset + 4 + ext_len];
                if let Some(alpn) = parse_alpn_extension(ext_data, false) {
                    debug!("QUIC: Found ALPN directly in packet: {:?}", alpn);
                    let mut tls_info = TlsInfo::new();
                    tls_info.alpn = alpn;
                    return Some(tls_info);
                }
            }
        }

        offset += 1;
    }

    debug!("QUIC: No unencrypted TLS data found in packet");
    None
}

/// Try to reconstruct SNI from fragmented crypto data
/// This looks for hostname patterns across fragment boundaries
pub(super) fn try_reconstruct_sni_from_fragments(
    reassembler: &CryptoFrameReassembler,
) -> Option<String> {
    debug!("QUIC: Attempting SNI reconstruction from fragments");

    let fragments = reassembler.get_fragments();
    let mut sorted_offsets: Vec<_> = fragments.keys().collect();
    sorted_offsets.sort();

    // First try: look for SNI extension patterns in individual fragments and reconstruct
    // IMPORTANT: Only look in fragments that include the beginning of the ClientHello
    // Otherwise we might find partial SNI data that's cut off at fragment boundaries
    for &offset in &sorted_offsets {
        // Skip fragments that don't start near the beginning of the ClientHello
        // The SNI extension typically appears after ~70-150 bytes in the ClientHello
        if *offset > 200 {
            debug!(
                "QUIC: Skipping fragment at offset {} - too far from ClientHello start",
                offset
            );
            continue;
        }

        if let Some(data) = fragments.get(offset) {
            debug!(
                "QUIC: Scanning fragment at offset {} ({} bytes) for SNI patterns",
                offset,
                data.len()
            );

            // Look for SNI extension header patterns in this fragment
            // Be more restrictive to avoid false positives from encrypted data
            if let Some(sni) = scan_for_sni_extension(data, true, SniScanStrictness::Moderate) {
                if is_partial_sni(&sni) {
                    debug!("QUIC: Found partial SNI in fragment: {}", sni);
                } else {
                    debug!("QUIC: Found complete SNI in fragment: {}", sni);
                }
                return Some(sni);
            }
        }
    }

    // Second try: smart fragment combination - try to fill gaps and maintain order
    debug!("QUIC: Smart combining fragments for hostname pattern search");

    // Check if we have fragments that include the ClientHello beginning
    // We need at least one fragment starting at or very close to offset 0
    let has_beginning = sorted_offsets.iter().any(|&offset| *offset <= 10);

    if !has_beginning {
        debug!(
            "QUIC: No fragment near offset 0 (first at {:?}) - missing ClientHello beginning, skipping SNI extraction",
            sorted_offsets.first()
        );
        return None;
    }

    let mut all_data = Vec::new();
    let mut expected_offset = 0u64;
    let mut has_significant_gaps = false;

    for &offset in &sorted_offsets {
        if let Some(data) = fragments.get(offset) {
            debug!(
                "QUIC: Processing fragment at offset {} ({} bytes), expected offset was {}",
                offset,
                data.len(),
                expected_offset
            );

            // If there's a gap, be more careful about continuing
            if *offset > expected_offset {
                let gap_size = *offset - expected_offset;
                debug!("QUIC: Gap detected of {} bytes between fragments", gap_size);

                // Gaps in the first 100 bytes are critical as they likely contain SNI
                // The SNI extension typically appears between bytes 70-200 of the ClientHello
                // Relaxed threshold from 20 to 50 bytes to be less aggressive
                if expected_offset < 100 && gap_size > 50 {
                    has_significant_gaps = true;
                    debug!("QUIC: Gap in critical ClientHello region - SNI might be incomplete");
                }

                // Large gaps anywhere might indicate missing data
                // Relaxed threshold from 200 to 300 bytes
                if gap_size > 300 {
                    has_significant_gaps = true;
                    debug!(
                        "QUIC: Large gap detected ({} bytes) - data might be incomplete",
                        gap_size
                    );
                }

                // For smaller gaps, add minimal padding to maintain data alignment
                if gap_size <= 100 && !all_data.is_empty() {
                    // Add minimal padding to maintain structure
                    all_data.resize(all_data.len() + gap_size as usize, 0);
                    debug!("QUIC: Added {} bytes of padding for small gap", gap_size);
                }
            }

            all_data.extend_from_slice(data);
            expected_offset = *offset + data.len() as u64;
        }
    }

    if all_data.len() < 10 {
        debug!(
            "QUIC: Not enough data for SNI reconstruction ({} bytes)",
            all_data.len()
        );
        return None;
    }

    debug!(
        "QUIC: Searching for hostname patterns in {} bytes of combined data",
        all_data.len()
    );
    let candidates = find_hostname_candidates(&all_data);

    // Process candidates to detect truncation and mark incomplete ones
    let mut processed_candidates = Vec::new();

    // If we have significant gaps (missing fragments), don't trust ANY hostname candidates
    // as they are likely incomplete or corrupted
    if has_significant_gaps {
        debug!("QUIC: Not returning any hostname candidates due to significant gaps in fragments");
        // We could still look for very long, complete-looking hostnames, but it's safer to wait
        for candidate in &candidates {
            // Only accept very long, complete-looking hostnames when gaps exist
            if candidate.len() >= 15 && candidate.matches('.').count() >= 2 {
                debug!(
                    "QUIC: Accepting long candidate '{}' despite gaps",
                    candidate
                );
                if is_valid_hostname(candidate) {
                    processed_candidates.push(candidate.clone());
                }
            } else {
                debug!(
                    "QUIC: Rejecting candidate '{}' due to fragment gaps",
                    candidate
                );
            }
        }
    } else {
        // No significant gaps - process normally
        // Only accept complete valid hostnames
        for candidate in candidates {
            if is_valid_hostname(&candidate) {
                processed_candidates.push(candidate);
            }
            // Don't try to mark truncated hostnames - wait for complete data
        }
    }

    // Sort by length (longer first) to prefer complete hostnames, but prioritize unmarked ones
    processed_candidates.sort_by(|a, b| {
        let a_is_partial = is_partial_sni(a) || a.contains("...");
        let b_is_partial = is_partial_sni(b) || b.contains("...");

        // Prefer complete hostnames over truncated/partial ones
        match (a_is_partial, b_is_partial) {
            (false, true) => std::cmp::Ordering::Less, // a is complete, prefer it
            (true, false) => std::cmp::Ordering::Greater, // b is complete, prefer it
            _ => b.len().cmp(&a.len()),                // both same type, prefer longer
        }
    });

    if let Some(candidate) = processed_candidates.first() {
        debug!("QUIC: Found hostname candidate: {}", candidate);
        return Some(candidate.clone());
    }

    None
}

/// Find potential hostname strings in binary data
fn find_hostname_candidates(data: &[u8]) -> Vec<String> {
    let mut candidates = Vec::new();

    let mut i = 0;
    while i < data.len() {
        // Look for sequences that might be hostnames
        if data[i].is_ascii_alphanumeric() {
            let mut end = i;
            let mut has_dot = false;
            let mut dot_count = 0;

            // Extend while we have valid hostname characters
            while end < data.len()
                && (data[end].is_ascii_alphanumeric() || data[end] == b'.' || data[end] == b'-')
            {
                if data[end] == b'.' {
                    has_dot = true;
                    dot_count += 1;
                }
                end += 1;
            }

            // Extract potential hostname if it looks reasonable
            if end > i + 3 && has_dot && dot_count <= 10 {
                // At least 4 chars with a dot, max 10 dots
                if let Ok(candidate) = String::from_utf8(data[i..end].to_vec()) {
                    // Clean up the candidate
                    let cleaned = candidate
                        .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '-');

                    // Additional validation: check for reasonable hostname structure
                    if !cleaned.is_empty()
                        && !cleaned.starts_with('.')
                        && !cleaned.ends_with('.')
                        && !cleaned.contains("..")
                    {
                        debug!("QUIC: Found hostname candidate: {}", cleaned);
                        candidates.push(cleaned.to_string());

                        // Also look for sub-patterns within longer strings
                        // This helps catch cases where we have "prefix.hostname.suffix"
                        let parts: Vec<&str> = cleaned.split('.').collect();
                        if parts.len() > 2 {
                            // Try combinations of consecutive parts
                            for start_idx in 0..parts.len() {
                                for end_idx in (start_idx + 2)..=parts.len() {
                                    let sub_candidate = parts[start_idx..end_idx].join(".");
                                    if sub_candidate != cleaned && sub_candidate.len() >= 4 {
                                        debug!(
                                            "QUIC: Found sub-hostname candidate: {}",
                                            sub_candidate
                                        );
                                        candidates.push(sub_candidate);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            i = end;
        } else {
            i += 1;
        }
    }

    // Remove duplicates while preserving order
    let mut unique_candidates = Vec::new();
    for candidate in candidates {
        if !unique_candidates.contains(&candidate) {
            unique_candidates.push(candidate);
        }
    }

    unique_candidates
}
