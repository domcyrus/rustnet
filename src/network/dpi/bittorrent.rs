use crate::network::types::{BitTorrentInfo, BitTorrentType};

/// BitTorrent protocol handshake prefix: length byte (19) + "BitTorrent protocol"
const BT_HANDSHAKE_PREFIX: &[u8] = b"\x13BitTorrent protocol";

/// Full handshake length: 1 (pstrlen) + 19 (pstr) + 8 (reserved) + 20 (info_hash) + 20 (peer_id)
const BT_HANDSHAKE_LEN: usize = 68;

/// Reserved byte bit positions for extension flags
const DHT_BIT_BYTE: usize = 7; // Byte 7, bit 0x01
const FAST_BIT_BYTE: usize = 7; // Byte 7, bit 0x04
const EXTENSION_BIT_BYTE: usize = 5; // Byte 5, bit 0x10

/// uTP header size (BEP 29)
const UTP_HEADER_LEN: usize = 20;

/// Maximum DHT method name length. Standard methods are short
/// (e.g., "ping", "find_node", "get_peers", "announce_peer").
const MAX_DHT_METHOD_LEN: usize = 64;

// --- TCP: Peer Handshake ---

/// Check if the payload starts with a BitTorrent peer handshake.
pub fn is_bittorrent_handshake(payload: &[u8]) -> bool {
    payload.starts_with(BT_HANDSHAKE_PREFIX)
}

/// Analyze a BitTorrent TCP handshake payload and extract protocol details.
pub fn analyze_bittorrent(payload: &[u8]) -> Option<BitTorrentInfo> {
    if !is_bittorrent_handshake(payload) {
        return None;
    }

    let reserved = if payload.len() >= 28 {
        Some(&payload[20..28])
    } else {
        None
    };

    let supports_dht = reserved.is_some_and(|r| r[DHT_BIT_BYTE] & 0x01 != 0);
    let supports_fast = reserved.is_some_and(|r| r[FAST_BIT_BYTE] & 0x04 != 0);
    let supports_extension = reserved.is_some_and(|r| r[EXTENSION_BIT_BYTE] & 0x10 != 0);

    let info_hash = if payload.len() >= 48 {
        let hash_bytes = &payload[28..48];
        Some(hex_encode(hash_bytes))
    } else {
        None
    };

    let client = if payload.len() >= BT_HANDSHAKE_LEN {
        let peer_id = &payload[48..68];
        decode_client_name(peer_id)
    } else {
        None
    };

    Some(BitTorrentInfo {
        protocol_type: BitTorrentType::Peer,
        info_hash,
        client,
        dht_method: None,
        supports_dht,
        supports_extension,
        supports_fast,
    })
}

// --- UDP: DHT + uTP ---

/// Analyze a UDP payload for BitTorrent DHT or uTP traffic.
/// Tries DHT first (higher confidence), then uTP.
pub fn analyze_udp_bittorrent(payload: &[u8]) -> Option<BitTorrentInfo> {
    if let Some(info) = analyze_dht(payload) {
        return Some(info);
    }
    analyze_utp(payload)
}

/// Analyze a UDP payload for BitTorrent DHT (bencoded dictionary messages).
///
/// DHT messages are bencoded dicts containing:
/// - `y`: message type — `q` (query), `r` (response), `e` (error)
/// - `q`: method name (for queries) — `ping`, `find_node`, `get_peers`, `announce_peer`
/// - `t`: transaction ID
fn analyze_dht(payload: &[u8]) -> Option<BitTorrentInfo> {
    // Must start with 'd' (bencoded dict) and end with 'e'
    if payload.len() < 10 || payload[0] != b'd' || payload[payload.len() - 1] != b'e' {
        return None;
    }

    // Must contain the message type key "1:y1:" followed by q/r/e
    let pos = find_subsequence(payload, b"1:y1:")?;
    if pos + 6 > payload.len() {
        return None;
    }
    let msg_type_char = payload[pos + 5];
    if msg_type_char != b'q' && msg_type_char != b'r' && msg_type_char != b'e' {
        return None;
    }

    // Extract DHT method for queries
    let dht_method = if msg_type_char == b'q' {
        extract_dht_method(payload)
    } else if msg_type_char == b'r' {
        Some("response".to_string())
    } else {
        Some("error".to_string())
    };

    Some(BitTorrentInfo {
        protocol_type: BitTorrentType::Dht,
        info_hash: None,
        client: None,
        dht_method,
        supports_dht: false,
        supports_extension: false,
        supports_fast: false,
    })
}

/// Extract the DHT query method name from a bencoded payload.
/// Looks for "1:q" followed by a bencoded string like "4:ping" or "9:find_node".
fn extract_dht_method(payload: &[u8]) -> Option<String> {
    let pos = find_subsequence(payload, b"1:q")?;
    let after = pos + 3;
    if after >= payload.len() {
        return None;
    }

    // Parse the bencoded string length: digits followed by ':'
    let mut len_end = after;
    while len_end < payload.len() && payload[len_end].is_ascii_digit() {
        len_end += 1;
    }
    if len_end == after || len_end >= payload.len() || payload[len_end] != b':' {
        return None;
    }

    let len_str = std::str::from_utf8(&payload[after..len_end]).ok()?;
    let str_len: usize = len_str.parse().ok()?;
    if str_len > MAX_DHT_METHOD_LEN {
        return None;
    }
    let str_start = len_end + 1;
    let str_end = str_start + str_len;
    if str_end > payload.len() {
        return None;
    }

    std::str::from_utf8(&payload[str_start..str_end])
        .ok()
        .map(String::from)
}

/// Analyze a UDP payload for BitTorrent uTP (Micro Transport Protocol, BEP 29).
///
/// uTP header (20 bytes):
/// - Byte 0: type (upper 4 bits) | version (lower 4 bits, must be 1)
/// - Byte 1: extension
/// - Bytes 2-3: connection_id
/// - Bytes 4-7: timestamp_microseconds
/// - Bytes 8-11: timestamp_difference_microseconds
/// - Bytes 12-15: wnd_size
/// - Bytes 16-17: seq_nr
/// - Bytes 18-19: ack_nr
fn analyze_utp(payload: &[u8]) -> Option<BitTorrentInfo> {
    if payload.len() < UTP_HEADER_LEN {
        return None;
    }

    let first_byte = payload[0];
    let version = first_byte & 0x0F;
    let pkt_type = (first_byte >> 4) & 0x0F;
    let extension = payload[1];

    // Version must be 1
    if version != 1 {
        return None;
    }

    // Type must be 0-4: ST_DATA, ST_FIN, ST_STATE, ST_RESET, ST_SYN
    if pkt_type > 4 {
        return None;
    }

    // Extension byte should be small (0=none, 1=selective ack, 2=extension bits)
    if extension > 2 {
        return None;
    }

    // Window size sanity check — 0 is valid for ST_RESET but otherwise should be non-zero
    let wnd_size = u32::from_be_bytes([payload[12], payload[13], payload[14], payload[15]]);
    if pkt_type != 3 && wnd_size == 0 {
        // ST_SYN with zero window is also suspicious
        return None;
    }

    Some(BitTorrentInfo {
        protocol_type: BitTorrentType::Utp,
        info_hash: None,
        client: None,
        dht_method: None,
        supports_dht: false,
        supports_extension: false,
        supports_fast: false,
    })
}

// --- Helpers ---

/// Decode the BitTorrent client name from a 20-byte peer_id using the Azureus-style convention.
///
/// Azureus-style: `-XX1234-............` where XX is the client ID and 1234 is the version.
fn decode_client_name(peer_id: &[u8]) -> Option<String> {
    if peer_id.len() >= 8 && peer_id[0] == b'-' && peer_id[7] == b'-' {
        let client_id = std::str::from_utf8(&peer_id[1..3]).ok()?;
        let version_bytes = &peer_id[3..7];

        let name = match client_id {
            "qB" => "qBittorrent",
            "TR" => "Transmission",
            "DE" => "Deluge",
            "UT" => "uTorrent",
            "lt" => "libtorrent",
            "LT" => "libtorrent",
            "AZ" => "Azureus",
            "BT" => "BitTorrent",
            "BI" => "BiglyBT",
            "FD" => "Free Download Manager",
            "KT" => "KTorrent",
            "RB" => "rtorrent",
            "WW" => "WebTorrent",
            "FL" => "Flud",
            "SD" => "Xunlei",
            "TL" => "Tribler",
            _ => client_id,
        };

        let version = format_version(version_bytes);
        Some(format!("{name} {version}"))
    } else if peer_id[0].is_ascii_alphanumeric() {
        let id_char = peer_id[0] as char;
        let name = match id_char {
            'M' => "Mainline",
            'S' => "Shadow",
            'T' => "BitTornado",
            'A' => "ABC",
            _ => return None,
        };
        Some(name.to_string())
    } else {
        None
    }
}

/// Format version bytes into a dotted version string.
fn format_version(bytes: &[u8]) -> String {
    bytes
        .iter()
        .filter_map(|&b| {
            if b.is_ascii_digit() {
                Some((b - b'0').to_string())
            } else if b.is_ascii_alphanumeric() {
                Some((b as char).to_string())
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Encode bytes as a lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Find the first occurrence of a subsequence in a byte slice.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- TCP Handshake Tests ---

    fn build_handshake(reserved: [u8; 8], info_hash: [u8; 20], peer_id: &[u8; 20]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(BT_HANDSHAKE_LEN);
        payload.extend_from_slice(BT_HANDSHAKE_PREFIX);
        payload.extend_from_slice(&reserved);
        payload.extend_from_slice(&info_hash);
        payload.extend_from_slice(peer_id);
        payload
    }

    #[test]
    fn test_handshake_detection() {
        let payload = build_handshake([0; 8], [0xAB; 20], b"-qB4250-xxxxxxxxxxxx");
        assert!(is_bittorrent_handshake(&payload));
    }

    #[test]
    fn test_non_bittorrent_payloads() {
        assert!(!is_bittorrent_handshake(b"GET / HTTP/1.1\r\n"));
        assert!(!is_bittorrent_handshake(b"SSH-2.0-OpenSSH_8.9\r\n"));
        assert!(!is_bittorrent_handshake(&[0x16, 0x03, 0x01, 0x00]));
        assert!(!is_bittorrent_handshake(b""));
        assert!(!is_bittorrent_handshake(&[0x13]));
    }

    #[test]
    fn test_analyze_qbittorrent() {
        let payload = build_handshake([0; 8], [0xDE; 20], b"-qB4250-xxxxxxxxxxxx");
        let info = analyze_bittorrent(&payload).unwrap();

        assert_eq!(info.protocol_type, BitTorrentType::Peer);
        assert_eq!(info.client.as_deref(), Some("qBittorrent 4.2.5.0"));
        assert_eq!(
            info.info_hash.as_deref(),
            Some("dededededededededededededededededededede") // 20 bytes = 40 hex chars
        );
        assert!(!info.supports_dht);
        assert!(!info.supports_extension);
        assert!(!info.supports_fast);
    }

    #[test]
    fn test_analyze_transmission() {
        let payload = build_handshake([0; 8], [0; 20], b"-TR3000-xxxxxxxxxxxx");
        let info = analyze_bittorrent(&payload).unwrap();
        assert_eq!(info.client.as_deref(), Some("Transmission 3.0.0.0"));
    }

    #[test]
    fn test_analyze_deluge() {
        let payload = build_handshake([0; 8], [0; 20], b"-DE0018-xxxxxxxxxxxx");
        let info = analyze_bittorrent(&payload).unwrap();
        assert_eq!(info.client.as_deref(), Some("Deluge 0.0.1.8"));
    }

    #[test]
    fn test_analyze_utorrent() {
        let payload = build_handshake([0; 8], [0; 20], b"-UT3560-xxxxxxxxxxxx");
        let info = analyze_bittorrent(&payload).unwrap();
        assert_eq!(info.client.as_deref(), Some("uTorrent 3.5.6.0"));
    }

    #[test]
    fn test_analyze_libtorrent() {
        let payload = build_handshake([0; 8], [0; 20], b"-lt0D60-xxxxxxxxxxxx");
        let info = analyze_bittorrent(&payload).unwrap();
        assert_eq!(info.client.as_deref(), Some("libtorrent 0.D.6.0"));
    }

    #[test]
    fn test_dht_flag() {
        let mut reserved = [0u8; 8];
        reserved[7] = 0x01;
        let payload = build_handshake(reserved, [0; 20], b"-qB4250-xxxxxxxxxxxx");
        let info = analyze_bittorrent(&payload).unwrap();
        assert!(info.supports_dht);
        assert!(!info.supports_extension);
        assert!(!info.supports_fast);
    }

    #[test]
    fn test_extension_flag() {
        let mut reserved = [0u8; 8];
        reserved[5] = 0x10;
        let payload = build_handshake(reserved, [0; 20], b"-qB4250-xxxxxxxxxxxx");
        let info = analyze_bittorrent(&payload).unwrap();
        assert!(!info.supports_dht);
        assert!(info.supports_extension);
        assert!(!info.supports_fast);
    }

    #[test]
    fn test_fast_flag() {
        let mut reserved = [0u8; 8];
        reserved[7] = 0x04;
        let payload = build_handshake(reserved, [0; 20], b"-qB4250-xxxxxxxxxxxx");
        let info = analyze_bittorrent(&payload).unwrap();
        assert!(!info.supports_dht);
        assert!(!info.supports_extension);
        assert!(info.supports_fast);
    }

    #[test]
    fn test_all_flags() {
        let mut reserved = [0u8; 8];
        reserved[5] = 0x10;
        reserved[7] = 0x05;
        let payload = build_handshake(reserved, [0; 20], b"-qB4250-xxxxxxxxxxxx");
        let info = analyze_bittorrent(&payload).unwrap();
        assert!(info.supports_dht);
        assert!(info.supports_extension);
        assert!(info.supports_fast);
    }

    #[test]
    fn test_partial_handshake_prefix_only() {
        let payload = BT_HANDSHAKE_PREFIX.to_vec();
        let info = analyze_bittorrent(&payload).unwrap();
        assert!(info.info_hash.is_none());
        assert!(info.client.is_none());
        assert!(!info.supports_dht);
    }

    #[test]
    fn test_partial_handshake_with_hash() {
        let mut payload = Vec::new();
        payload.extend_from_slice(BT_HANDSHAKE_PREFIX);
        payload.extend_from_slice(&[0u8; 8]);
        payload.extend_from_slice(&[0xAB; 20]);
        let info = analyze_bittorrent(&payload).unwrap();
        assert!(info.info_hash.is_some());
        assert!(info.client.is_none());
    }

    #[test]
    fn test_unknown_client_id() {
        let payload = build_handshake([0; 8], [0; 20], b"-ZZ1234-xxxxxxxxxxxx");
        let info = analyze_bittorrent(&payload).unwrap();
        assert_eq!(info.client.as_deref(), Some("ZZ 1.2.3.4"));
    }

    #[test]
    fn test_non_bt_returns_none() {
        assert!(analyze_bittorrent(b"GET / HTTP/1.1\r\n").is_none());
        assert!(analyze_bittorrent(b"SSH-2.0-OpenSSH\r\n").is_none());
        assert!(analyze_bittorrent(b"").is_none());
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
        assert_eq!(hex_encode(&[0x00, 0xFF]), "00ff");
    }

    #[test]
    fn test_format_version() {
        assert_eq!(format_version(b"4250"), "4.2.5.0");
        assert_eq!(format_version(b"3000"), "3.0.0.0");
        assert_eq!(format_version(b"0D60"), "0.D.6.0");
    }

    // --- DHT Tests ---

    #[test]
    fn test_dht_ping_query() {
        let payload = b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe";
        let info = analyze_dht(payload).unwrap();
        assert_eq!(info.protocol_type, BitTorrentType::Dht);
        assert_eq!(info.dht_method.as_deref(), Some("ping"));
    }

    #[test]
    fn test_dht_find_node_query() {
        let payload = b"d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe";
        let info = analyze_dht(payload).unwrap();
        assert_eq!(info.dht_method.as_deref(), Some("find_node"));
    }

    #[test]
    fn test_dht_get_peers_query() {
        let payload = b"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe";
        let info = analyze_dht(payload).unwrap();
        assert_eq!(info.dht_method.as_deref(), Some("get_peers"));
    }

    #[test]
    fn test_dht_announce_peer_query() {
        let payload = b"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz1234564:porti6881e5:token8:aoeusnthe1:q13:announce_peer1:t2:aa1:y1:qe";
        let info = analyze_dht(payload).unwrap();
        assert_eq!(info.dht_method.as_deref(), Some("announce_peer"));
    }

    #[test]
    fn test_dht_response() {
        let payload = b"d1:rd2:id20:0123456789abcdefghij5:nodes208:...e1:t2:aa1:y1:re";
        let info = analyze_dht(payload).unwrap();
        assert_eq!(info.protocol_type, BitTorrentType::Dht);
        assert_eq!(info.dht_method.as_deref(), Some("response"));
    }

    #[test]
    fn test_dht_error() {
        let payload = b"d1:eli201e23:A Generic Error Ocurrede1:t2:aa1:y1:ee";
        let info = analyze_dht(payload).unwrap();
        assert_eq!(info.dht_method.as_deref(), Some("error"));
    }

    #[test]
    fn test_dht_rejects_non_bencode() {
        assert!(analyze_dht(b"GET / HTTP/1.1\r\n").is_none());
        assert!(analyze_dht(b"").is_none());
        assert!(analyze_dht(b"d").is_none());
        // Starts with 'd' but no message type key
        assert!(analyze_dht(b"d3:foo3:bare").is_none());
    }

    // --- uTP Tests ---

    /// Build a minimal uTP header.
    fn build_utp_header(pkt_type: u8, version: u8, extension: u8, wnd_size: u32) -> Vec<u8> {
        let mut payload = vec![0u8; UTP_HEADER_LEN];
        payload[0] = (pkt_type << 4) | (version & 0x0F);
        payload[1] = extension;
        // wnd_size at bytes 12-15
        payload[12..16].copy_from_slice(&wnd_size.to_be_bytes());
        payload
    }

    #[test]
    fn test_utp_data_packet() {
        let payload = build_utp_header(0, 1, 0, 65535); // ST_DATA
        let info = analyze_utp(&payload).unwrap();
        assert_eq!(info.protocol_type, BitTorrentType::Utp);
    }

    #[test]
    fn test_utp_syn_packet() {
        let payload = build_utp_header(4, 1, 0, 65535); // ST_SYN
        let info = analyze_utp(&payload).unwrap();
        assert_eq!(info.protocol_type, BitTorrentType::Utp);
    }

    #[test]
    fn test_utp_state_packet() {
        let payload = build_utp_header(2, 1, 0, 32768); // ST_STATE (ACK)
        let info = analyze_utp(&payload).unwrap();
        assert_eq!(info.protocol_type, BitTorrentType::Utp);
    }

    #[test]
    fn test_utp_fin_packet() {
        let payload = build_utp_header(1, 1, 0, 1024); // ST_FIN
        let info = analyze_utp(&payload).unwrap();
        assert_eq!(info.protocol_type, BitTorrentType::Utp);
    }

    #[test]
    fn test_utp_reset_zero_window() {
        // ST_RESET with zero window is valid
        let payload = build_utp_header(3, 1, 0, 0);
        let info = analyze_utp(&payload).unwrap();
        assert_eq!(info.protocol_type, BitTorrentType::Utp);
    }

    #[test]
    fn test_utp_with_selective_ack() {
        let payload = build_utp_header(0, 1, 1, 65535); // extension=1 (SACK)
        assert!(analyze_utp(&payload).is_some());
    }

    #[test]
    fn test_utp_rejects_wrong_version() {
        let payload = build_utp_header(0, 0, 0, 65535);
        assert!(analyze_utp(&payload).is_none());
        let payload = build_utp_header(0, 2, 0, 65535);
        assert!(analyze_utp(&payload).is_none());
    }

    #[test]
    fn test_utp_rejects_invalid_type() {
        let payload = build_utp_header(5, 1, 0, 65535); // type 5 is invalid
        assert!(analyze_utp(&payload).is_none());
    }

    #[test]
    fn test_utp_rejects_bad_extension() {
        let payload = build_utp_header(0, 1, 10, 65535); // extension=10 is suspicious
        assert!(analyze_utp(&payload).is_none());
    }

    #[test]
    fn test_utp_rejects_zero_window_non_reset() {
        let payload = build_utp_header(0, 1, 0, 0); // ST_DATA with zero window
        assert!(analyze_utp(&payload).is_none());
    }

    #[test]
    fn test_utp_rejects_too_short() {
        assert!(analyze_utp(&[0x01; 10]).is_none());
        assert!(analyze_utp(&[]).is_none());
    }

    // --- Combined UDP analyzer ---

    #[test]
    fn test_udp_prefers_dht_over_utp() {
        // A DHT message should be detected as DHT, not uTP
        let payload = b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe";
        let info = analyze_udp_bittorrent(payload).unwrap();
        assert_eq!(info.protocol_type, BitTorrentType::Dht);
    }

    #[test]
    fn test_udp_falls_through_to_utp() {
        let payload = build_utp_header(4, 1, 0, 65535);
        let info = analyze_udp_bittorrent(&payload).unwrap();
        assert_eq!(info.protocol_type, BitTorrentType::Utp);
    }

    #[test]
    fn test_udp_returns_none_for_unknown() {
        assert!(analyze_udp_bittorrent(b"GET / HTTP/1.1\r\n").is_none());
    }
}
