//! NTP (Network Time Protocol) Deep Packet Inspection
//!
//! Parses NTP packets according to RFC 5905.
//! NTP uses UDP port 123.

use crate::network::types::{NtpInfo, NtpMode};

/// Minimum NTP packet size (48 bytes for NTPv3/v4)
const MIN_NTP_PACKET_SIZE: usize = 48;

/// Analyze an NTP packet and extract key information.
///
/// Returns `None` if the packet is too small or has invalid version.
pub(super) fn analyze_ntp(payload: &[u8]) -> Option<NtpInfo> {
    // Early size check - NTP packets are at least 48 bytes
    if payload.len() < MIN_NTP_PACKET_SIZE {
        return None;
    }

    // First byte contains: LI (2 bits) | VN (3 bits) | Mode (3 bits)
    let first_byte = payload[0];
    let version = (first_byte >> 3) & 0x07;
    let mode = first_byte & 0x07;
    let stratum = payload[1];

    // Validate version (1-4 are valid, 3 and 4 are common)
    if !(1..=4).contains(&version) {
        return None;
    }

    // A server echoes the client's transmit timestamp back as the originate
    // timestamp (RFC 5905 §8), which is what pairs a request with its
    // response for round-trip timing.
    let origin_timestamp = read_u64(payload, 24);
    let transmit_timestamp = read_u64(payload, 40);

    Some(NtpInfo {
        version,
        mode: NtpMode::from(mode),
        stratum,
        origin_timestamp,
        transmit_timestamp,
    })
}

/// Read a big-endian u64 at `offset`; the caller guarantees the bounds via
/// the minimum packet size check.
fn read_u64(payload: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&payload[offset..offset + 8]);
    u64::from_be_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_ntp_packet(version: u8, mode: u8, stratum: u8) -> [u8; 48] {
        let mut packet = [0u8; 48];
        // LI=0 (2 bits), VN=version (3 bits), Mode=mode (3 bits)
        packet[0] = (version << 3) | mode;
        packet[1] = stratum;
        packet
    }

    #[test]
    fn test_ntp_modes_and_versions() {
        for (version, mode, stratum, expected) in [
            (4, 3, 0, NtpMode::Client),
            (4, 4, 2, NtpMode::Server),
            (3, 5, 1, NtpMode::Broadcast),
            (4, 1, 3, NtpMode::SymmetricActive),
            (4, 2, 3, NtpMode::SymmetricPassive),
        ] {
            let packet = build_ntp_packet(version, mode, stratum);
            let info = analyze_ntp(&packet).expect("valid NTP mode and version");
            assert_eq!(
                (info.version, info.mode, info.stratum),
                (version, expected, stratum),
                "mode {mode}"
            );
        }
    }

    #[test]
    fn test_ntp_extracts_origin_and_transmit_timestamps() {
        let mut packet = build_ntp_packet(4, 4, 2);
        packet[24..32].copy_from_slice(&0x1122_3344_5566_7788u64.to_be_bytes());
        packet[40..48].copy_from_slice(&0x99AA_BBCC_DDEE_FF00u64.to_be_bytes());
        let info = analyze_ntp(&packet).expect("should parse");
        assert_eq!(info.origin_timestamp, 0x1122_3344_5566_7788);
        assert_eq!(info.transmit_timestamp, 0x99AA_BBCC_DDEE_FF00);
    }

    #[test]
    fn test_ntp_too_short() {
        let packet = [0x23; 10]; // Too short
        assert!(analyze_ntp(&packet).is_none());
    }

    #[test]
    fn test_ntp_invalid_versions() {
        for version in [0, 7] {
            let packet = build_ntp_packet(version, 3, 0);
            assert!(analyze_ntp(&packet).is_none(), "version {version}");
        }
    }
}
