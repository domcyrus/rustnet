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
pub fn analyze_ntp(payload: &[u8]) -> Option<NtpInfo> {
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

    Some(NtpInfo {
        version,
        mode: NtpMode::from(mode),
        stratum,
    })
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
    fn test_ntp_client_request() {
        let packet = build_ntp_packet(4, 3, 0); // v4, client mode, stratum 0
        let info = analyze_ntp(&packet).expect("should parse");
        assert_eq!(info.version, 4);
        assert_eq!(info.mode, NtpMode::Client);
        assert_eq!(info.stratum, 0);
    }

    #[test]
    fn test_ntp_server_response() {
        let packet = build_ntp_packet(4, 4, 2); // v4, server mode, stratum 2
        let info = analyze_ntp(&packet).expect("should parse");
        assert_eq!(info.version, 4);
        assert_eq!(info.mode, NtpMode::Server);
        assert_eq!(info.stratum, 2);
    }

    #[test]
    fn test_ntp_v3_broadcast() {
        let packet = build_ntp_packet(3, 5, 1); // v3, broadcast mode, stratum 1
        let info = analyze_ntp(&packet).expect("should parse");
        assert_eq!(info.version, 3);
        assert_eq!(info.mode, NtpMode::Broadcast);
        assert_eq!(info.stratum, 1);
    }

    #[test]
    fn test_ntp_too_short() {
        let packet = [0x23; 10]; // Too short
        assert!(analyze_ntp(&packet).is_none());
    }

    #[test]
    fn test_ntp_invalid_version_zero() {
        let packet = build_ntp_packet(0, 3, 0); // Invalid version 0
        assert!(analyze_ntp(&packet).is_none());
    }

    #[test]
    fn test_ntp_invalid_version_high() {
        let packet = build_ntp_packet(7, 3, 0); // Invalid version 7
        assert!(analyze_ntp(&packet).is_none());
    }

    #[test]
    fn test_ntp_symmetric_active() {
        let packet = build_ntp_packet(4, 1, 3);
        let info = analyze_ntp(&packet).expect("should parse");
        assert_eq!(info.mode, NtpMode::SymmetricActive);
    }

    #[test]
    fn test_ntp_symmetric_passive() {
        let packet = build_ntp_packet(4, 2, 3);
        let info = analyze_ntp(&packet).expect("should parse");
        assert_eq!(info.mode, NtpMode::SymmetricPassive);
    }
}
