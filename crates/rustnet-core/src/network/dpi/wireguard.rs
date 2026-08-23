use crate::network::types::{WireGuardInfo, WireGuardPacketType};

const HANDSHAKE_INITIATION_LEN: usize = 148;
const HANDSHAKE_RESPONSE_LEN: usize = 92;
const COOKIE_REPLY_LEN: usize = 64;
const TRANSPORT_HEADER_LEN: usize = 16;
const AUTH_TAG_LEN: usize = 16;

/// Identify a WireGuard UDP message from its fixed wire shape.
///
/// Every message starts with a little-endian type word whose upper three
/// bytes are reserved and zero. Handshake and cookie messages have fixed
/// lengths. Transport messages contain a 16-byte header followed by a
/// possibly empty, block-padded ciphertext and a 16-byte authentication tag.
pub(super) fn analyze_wireguard(payload: &[u8]) -> Option<WireGuardInfo> {
    if payload.get(1..4)? != [0, 0, 0] {
        return None;
    }

    let packet_type = match (payload[0], payload.len()) {
        (1, HANDSHAKE_INITIATION_LEN) => WireGuardPacketType::HandshakeInitiation,
        (2, HANDSHAKE_RESPONSE_LEN) => WireGuardPacketType::HandshakeResponse,
        (3, COOKIE_REPLY_LEN) => WireGuardPacketType::CookieReply,
        (4, len) if len >= TRANSPORT_HEADER_LEN + AUTH_TAG_LEN && len.is_multiple_of(16) => {
            WireGuardPacketType::TransportData
        }
        _ => return None,
    };

    Some(WireGuardInfo { packet_type })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(message_type: u8, len: usize) -> Vec<u8> {
        let mut payload = vec![0x5a; len];
        payload[..4].copy_from_slice(&[message_type, 0, 0, 0]);
        payload
    }

    #[test]
    fn recognizes_all_message_types() {
        let cases = [
            (1, 148, WireGuardPacketType::HandshakeInitiation),
            (2, 92, WireGuardPacketType::HandshakeResponse),
            (3, 64, WireGuardPacketType::CookieReply),
            (4, 32, WireGuardPacketType::TransportData),
            (4, 1440, WireGuardPacketType::TransportData),
        ];

        for (message_type, len, expected) in cases {
            let info = analyze_wireguard(&message(message_type, len)).unwrap();
            assert_eq!(info.packet_type, expected);
        }
    }

    #[test]
    fn rejects_reserved_bytes_and_wrong_lengths() {
        let mut reserved = message(1, HANDSHAKE_INITIATION_LEN);
        reserved[2] = 1;
        assert!(analyze_wireguard(&reserved).is_none());

        assert!(analyze_wireguard(&message(1, HANDSHAKE_INITIATION_LEN - 1)).is_none());
        assert!(analyze_wireguard(&message(2, HANDSHAKE_RESPONSE_LEN + 1)).is_none());
        assert!(analyze_wireguard(&message(3, COOKIE_REPLY_LEN - 1)).is_none());
        assert!(analyze_wireguard(&message(4, 31)).is_none());
        assert!(analyze_wireguard(&message(4, 33)).is_none());
        assert!(analyze_wireguard(&message(5, 64)).is_none());
        assert!(analyze_wireguard(&[]).is_none());
    }
}
