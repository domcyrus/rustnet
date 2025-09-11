use crate::network::types::{SshConnectionState, SshInfo, SshVersion};
use log::debug;

/// Analyze payload for SSH protocol
/// is_outgoing: true if this packet is from client to server
pub fn analyze_ssh(payload: &[u8], is_outgoing: bool) -> Option<SshInfo> {
    if !is_likely_ssh(payload) {
        return None;
    }

    let mut info = SshInfo {
        version: None,
        client_software: None,
        server_software: None,
        connection_state: SshConnectionState::Banner,
        algorithms: Vec::new(),
        auth_method: None,
    };

    // Convert payload to string for banner analysis
    let text = String::from_utf8_lossy(payload);
    let lines: Vec<&str> = text.lines().collect();

    if lines.is_empty() {
        return None;
    }

    // Parse SSH banner(s) and assign based on packet direction
    for line in lines {
        if let Some(banner_info) = parse_ssh_banner(line) {
            // Use packet direction to distinguish client vs server
            if is_outgoing {
                // Outgoing packet: client to server, so this banner is from client
                if info.client_software.is_none() {
                    info.client_software = Some(banner_info.software);
                    info.version = Some(banner_info.version);
                }
            } else {
                // Incoming packet: server to client, so this banner is from server  
                if info.server_software.is_none() {
                    info.server_software = Some(banner_info.software);
                    info.version = Some(banner_info.version);
                }
            }
        }
    }

    // Detect SSH message types for connection state
    // Look for SSH packet structures throughout the payload
    let mut found_packet_state = false;
    for i in 0..payload.len().saturating_sub(6) {
        if payload.len() >= i + 6 {
            // Validate this looks like a real SSH packet structure
            if is_valid_ssh_packet_at_offset(payload, i) {
                let msg_type = payload[i + 5];

                match msg_type {
                    20 => {
                        info.connection_state = SshConnectionState::KeyExchange;
                        debug!("SSH: Detected KEXINIT message at offset {}", i);
                        found_packet_state = true;
                        break;
                    }
                    21 => {
                        info.connection_state = SshConnectionState::KeyExchange;
                        debug!("SSH: Detected NEWKEYS message at offset {}", i);
                        found_packet_state = true;
                        break;
                    }
                    50 => {
                        info.connection_state = SshConnectionState::Authentication;
                        debug!("SSH: Detected USERAUTH_REQUEST message at offset {}", i);
                        found_packet_state = true;
                        break;
                    }
                    51 => {
                        info.connection_state = SshConnectionState::Authentication;
                        debug!("SSH: Detected USERAUTH_FAILURE message at offset {}", i);
                        found_packet_state = true;
                        break;
                    }
                    52 => {
                        info.connection_state = SshConnectionState::Established;
                        debug!("SSH: Detected USERAUTH_SUCCESS message at offset {}", i);
                        found_packet_state = true;
                        break;
                    }
                    90..=127 => {
                        info.connection_state = SshConnectionState::Established;
                        debug!("SSH: Detected connection protocol message at offset {}", i);
                        found_packet_state = true;
                        break;
                    }
                    _ => {
                        // Continue searching
                    }
                }
            }
        }
    }

    // If we didn't find a packet state and we have banner info, default to Banner state
    if !found_packet_state && (info.server_software.is_some() || info.client_software.is_some()) {
        info.connection_state = SshConnectionState::Banner;
    }

    // Try to extract algorithm information from KEXINIT messages or any payload
    if payload.len() > 20 && payload[5] == 20 {
        if let Some(algorithms) = parse_kexinit_algorithms(payload) {
            info.algorithms = algorithms;
        }
    } else {
        // Also try to extract algorithms from banner/text content
        if let Some(algorithms) = parse_kexinit_algorithms(payload) {
            info.algorithms = algorithms;
        }
    }

    debug!("SSH analysis result: {:?}", info);
    Some(info)
}

/// Check if payload might be SSH
pub fn is_likely_ssh(payload: &[u8]) -> bool {
    if payload.len() < 4 {
        return false;
    }

    // SSH banner identification string
    payload.starts_with(b"SSH-1.") || 
    payload.starts_with(b"SSH-2.") ||
    // Sometimes we might see SSH packets without banners
    is_ssh_packet_structure(payload)
}

/// Parse SSH banner line
fn parse_ssh_banner(line: &str) -> Option<BannerInfo> {
    if !line.starts_with("SSH-") {
        return None;
    }

    let parts: Vec<&str> = line.splitn(3, '-').collect();
    if parts.len() < 2 {
        return None;
    }

    let version = match parts[1] {
        "1.99" | "2.0" => SshVersion::V2,
        v if v.starts_with("1.") => SshVersion::V1,
        _ => SshVersion::V2, // Default to V2 for unknown versions
    };

    let software = if parts.len() >= 3 {
        parts[2].trim().to_string()
    } else {
        "Unknown".to_string()
    };

    Some(BannerInfo { version, software })
}

/// Check if payload has SSH packet structure
fn is_ssh_packet_structure(payload: &[u8]) -> bool {
    if payload.len() < 6 {
        return false;
    }

    is_valid_ssh_packet_at_offset(payload, 0)
}

/// Check if there's a valid SSH packet structure at the given offset
fn is_valid_ssh_packet_at_offset(payload: &[u8], offset: usize) -> bool {
    if payload.len() < offset + 6 {
        return false;
    }

    // SSH packet format:
    // 4 bytes: packet length
    // 1 byte: padding length
    // 1+ bytes: payload (message type + data)
    // N bytes: padding

    let packet_length = u32::from_be_bytes([
        payload[offset],
        payload[offset + 1],
        payload[offset + 2],
        payload[offset + 3],
    ]);
    let padding_length = payload[offset + 4] as u32;

    // Basic sanity checks
    if packet_length > 35000 || padding_length > 255 {
        return false;
    }

    // Message type should be in valid range
    let msg_type = payload[offset + 5];
    matches!(msg_type, 1..=127)
}

/// Parse algorithms from KEXINIT message
fn parse_kexinit_algorithms(payload: &[u8]) -> Option<Vec<String>> {
    // This is a simplified version - full KEXINIT parsing is quite complex
    // We'll just try to extract some common algorithm names
    let text = String::from_utf8_lossy(payload);
    let mut algorithms = Vec::new();

    // Look for common SSH algorithms
    let common_algos = [
        "diffie-hellman-group14-sha256",
        "ecdh-sha2-nistp256",
        "aes128-ctr",
        "aes256-ctr",
        "aes128-gcm",
        "aes256-gcm",
        "ssh-rsa",
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "hmac-sha2-256",
        "hmac-sha2-512",
    ];

    for algo in &common_algos {
        if text.contains(algo) {
            algorithms.push(algo.to_string());
        }
    }

    if algorithms.is_empty() {
        None
    } else {
        Some(algorithms)
    }
}

/// Helper struct for banner parsing
struct BannerInfo {
    version: SshVersion,
    software: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openssh_banner() {
        let payload = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n";
        let info = analyze_ssh(payload, false).unwrap();

        assert_eq!(info.version, Some(SshVersion::V2));
        assert_eq!(
            info.server_software.as_deref(),
            Some("OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")
        );
        assert_eq!(info.connection_state, SshConnectionState::Banner);
    }

    #[test]
    fn test_putty_banner() {
        let payload = b"SSH-2.0-PuTTY_Release_0.76\r\n";
        let info = analyze_ssh(payload, false).unwrap();

        assert_eq!(info.version, Some(SshVersion::V2));
        assert_eq!(info.server_software.as_deref(), Some("PuTTY_Release_0.76"));
    }

    #[test]
    fn test_ssh1_banner() {
        let payload = b"SSH-1.99-libssh_0.8.9\r\n";
        let info = analyze_ssh(payload, false).unwrap();

        assert_eq!(info.version, Some(SshVersion::V2)); // 1.99 maps to V2
        assert_eq!(info.server_software.as_deref(), Some("libssh_0.8.9"));
    }

    #[test]
    fn test_kexinit_detection() {
        // Simplified KEXINIT packet structure
        let mut payload = vec![0, 0, 0, 100]; // packet length
        payload.push(10); // padding length  
        payload.push(20); // SSH_MSG_KEXINIT
        payload.extend_from_slice(&[0; 94]); // rest of packet

        let info = analyze_ssh(&payload, false).unwrap();
        assert_eq!(info.connection_state, SshConnectionState::KeyExchange);
    }

    #[test]
    fn test_userauth_success() {
        let mut payload = vec![0, 0, 0, 20]; // packet length
        payload.push(5); // padding length
        payload.push(52); // SSH_MSG_USERAUTH_SUCCESS
        payload.extend_from_slice(&[0; 14]); // padding

        let info = analyze_ssh(&payload, false).unwrap();
        assert_eq!(info.connection_state, SshConnectionState::Established);
    }

    #[test]
    fn test_non_ssh_payload() {
        let payload = b"HTTP/1.1 200 OK\r\n";
        assert!(analyze_ssh(payload, false).is_none());
    }

    #[test]
    fn test_partial_ssh_banner() {
        let payload = b"SSH-2.0-Open";
        let info = analyze_ssh(payload, false).unwrap();
        assert_eq!(info.version, Some(SshVersion::V2));
    }

    #[test]
    fn test_ssh_banner_parsing() {
        assert!(parse_ssh_banner("SSH-2.0-OpenSSH_8.9").is_some());
        assert!(parse_ssh_banner("SSH-1.5-oldversion").is_some());
        assert!(parse_ssh_banner("HTTP/1.1 200 OK").is_none());
        assert!(parse_ssh_banner("").is_none());
    }

    #[test]
    fn test_is_likely_ssh() {
        assert!(is_likely_ssh(b"SSH-2.0-OpenSSH"));
        assert!(is_likely_ssh(b"SSH-1.99-libssh"));
        assert!(!is_likely_ssh(b"HTTP/1.1"));
        assert!(!is_likely_ssh(b"GET /"));
        assert!(!is_likely_ssh(b""));
    }

    #[test]
    fn test_ssh_packet_structure() {
        // Valid SSH packet structure
        let valid_packet = vec![0, 0, 0, 20, 5, 50, 0, 0, 0, 0]; // packet_len=20, padding_len=5, msg_type=50
        assert!(is_ssh_packet_structure(&valid_packet));

        // Invalid packet structure
        let invalid_packet = vec![255, 255, 255, 255, 255, 255]; // unrealistic lengths
        assert!(!is_ssh_packet_structure(&invalid_packet));
    }

    #[test]
    fn test_various_ssh_implementations() {
        // Test different SSH software banners
        let test_cases = vec![
            ("SSH-2.0-OpenSSH_7.4", SshVersion::V2, "OpenSSH_7.4"),
            ("SSH-2.0-libssh2_1.9.0", SshVersion::V2, "libssh2_1.9.0"),
            (
                "SSH-2.0-WinSCP_release_5.19.6",
                SshVersion::V2,
                "WinSCP_release_5.19.6",
            ),
            ("SSH-2.0-Paramiko_2.8.0", SshVersion::V2, "Paramiko_2.8.0"),
            ("SSH-1.99-Cisco-1.25", SshVersion::V2, "Cisco-1.25"), // 1.99 maps to V2
            ("SSH-1.5-1.2.27", SshVersion::V1, "1.2.27"),
        ];

        for (banner, expected_version, expected_software) in test_cases {
            let payload = format!("{}\r\n", banner).into_bytes();
            let info = analyze_ssh(&payload, false).unwrap();

            assert_eq!(
                info.version,
                Some(expected_version),
                "Failed for banner: {}",
                banner
            );
            assert_eq!(
                info.server_software.as_deref(),
                Some(expected_software),
                "Failed for banner: {}",
                banner
            );
            assert_eq!(info.connection_state, SshConnectionState::Banner);
        }
    }

    #[test]
    fn test_ssh_connection_states() {
        // Test KEXINIT detection
        let mut kexinit_packet = vec![0, 0, 0, 100, 10, 20]; // packet_len, padding_len, SSH_MSG_KEXINIT
        kexinit_packet.extend(vec![0; 94]); // fill the packet
        let info = analyze_ssh(&kexinit_packet, false).unwrap();
        assert_eq!(info.connection_state, SshConnectionState::KeyExchange);

        // Test USERAUTH_REQUEST
        let mut userauth_packet = vec![0, 0, 0, 50, 8, 50]; // SSH_MSG_USERAUTH_REQUEST
        userauth_packet.extend(vec![0; 44]);
        let info = analyze_ssh(&userauth_packet, false).unwrap();
        assert_eq!(info.connection_state, SshConnectionState::Authentication);

        // Test USERAUTH_SUCCESS
        let mut success_packet = vec![0, 0, 0, 20, 5, 52]; // SSH_MSG_USERAUTH_SUCCESS
        success_packet.extend(vec![0; 14]);
        let info = analyze_ssh(&success_packet, false).unwrap();
        assert_eq!(info.connection_state, SshConnectionState::Established);

        // Test connection protocol message
        let mut conn_packet = vec![0, 0, 0, 30, 6, 95]; // Some connection protocol message
        conn_packet.extend(vec![0; 24]);
        let info = analyze_ssh(&conn_packet, false).unwrap();
        assert_eq!(info.connection_state, SshConnectionState::Established);
    }

    #[test]
    fn test_malformed_ssh_packets() {
        // Empty payload
        assert!(analyze_ssh(&[], false).is_none());

        // Too short payload
        assert!(analyze_ssh(&[1, 2, 3], false).is_none());

        // Invalid SSH banner
        let invalid_banner = b"HTTP/1.1 200 OK\r\n";
        assert!(analyze_ssh(invalid_banner, false).is_none());

        // Malformed SSH banner (missing parts)
        let malformed_banner = b"SSH-\r\n";
        assert!(analyze_ssh(malformed_banner, false).is_none());
    }

    #[test]
    fn test_algorithm_detection() {
        // Create a payload that contains some SSH algorithms in the text
        let payload_with_algos =
            b"SSH-2.0-test\r\nsome data aes128-ctr ssh-ed25519 hmac-sha2-256 more data";
        let info = analyze_ssh(payload_with_algos, false).unwrap();

        assert!(!info.algorithms.is_empty());
        // Should contain some of the algorithms we look for
        assert!(info.algorithms.iter().any(|a| a.contains("aes128-ctr")));
    }

    #[test]
    fn test_edge_cases() {
        // Banner with no software info
        let minimal_banner = b"SSH-2.0\r\n";
        let info = analyze_ssh(minimal_banner, false);
        // Should still parse successfully but with minimal info
        assert!(info.is_some());

        // Very long banner (should still work)
        let long_banner = format!("SSH-2.0-{}\r\n", "x".repeat(200)).into_bytes();
        let info = analyze_ssh(&long_banner, false);
        assert!(info.is_some());

        // Banner with special characters
        let special_banner = b"SSH-2.0-OpenSSH_8.9p1-Ubuntu-3~20.04.3\r\n";
        let info = analyze_ssh(special_banner, false).unwrap();
        assert_eq!(info.version, Some(SshVersion::V2));
    }

    #[test]
    fn test_client_server_software_distinction() {
        // Test server banner (incoming packet)
        let server_banner = b"SSH-2.0-OpenSSH_9.9\r\n";
        let server_info = analyze_ssh(server_banner, false).unwrap();
        assert!(server_info.server_software.is_some());
        assert!(server_info.client_software.is_none());
        assert_eq!(server_info.server_software.as_ref().unwrap(), "OpenSSH_9.9");

        // Test client banner (outgoing packet)
        let client_banner = b"SSH-2.0-OpenSSH_9.8\r\n";
        let client_info = analyze_ssh(client_banner, true).unwrap();
        assert!(client_info.client_software.is_some());
        assert!(client_info.server_software.is_none());
        assert_eq!(client_info.client_software.as_ref().unwrap(), "OpenSSH_9.8");
    }

    #[test]
    fn test_mixed_content() {
        // Test payload that has both banner and packet data
        // Banner: "SSH-2.0-OpenSSH_8.9\r\n" (21 bytes)
        // Packet: \x00\x00\x00\x14\x05\x32 (packet_len=20, padding_len=5, msg_type=50/0x32)
        let mixed_payload = b"SSH-2.0-OpenSSH_8.9\r\n\x00\x00\x00\x14\x05\x32additional data here";
        let info = analyze_ssh(mixed_payload, false).unwrap();

        assert_eq!(info.version, Some(SshVersion::V2));
        assert!(info.server_software.is_some());
        // The packet structure starts at offset 21, so message type is at offset 26
        // Should detect the SSH_MSG_USERAUTH_REQUEST (50/0x32) in the packet data
        assert_eq!(info.connection_state, SshConnectionState::Authentication);
    }
}
