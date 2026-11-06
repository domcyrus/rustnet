use crate::network::types::{OpenVpnInfo, OpenVpnPacketType};

const OPCODE_SHIFT: u8 = 3;
const KEY_ID_MASK: u8 = 0x07;
const SESSION_ID_LEN: usize = 8;
const CONTROL_HEADER_LEN: usize = 1 + SESSION_ID_LEN;
const DATA_V1_MIN_LEN: usize = 1 + 16;
const DATA_V2_MIN_LEN: usize = 1 + 3 + 16;

/// Analyze one OpenVPN UDP packet.
///
/// On the registered port, the opcode and minimum packet shape provide a
/// useful classification without pretending to decrypt the payload. Away
/// from that port, only the highly distinctive plaintext or tls-auth V2 hard
/// reset exchange is accepted. A tls-crypt packet on an alternate port is
/// intentionally not guessed from its first random-looking byte alone.
pub(super) fn analyze_openvpn_udp(
    payload: &[u8],
    uses_registered_port: bool,
) -> Option<OpenVpnInfo> {
    analyze_packet(payload, uses_registered_port)
}

/// Analyze an OpenVPN packet carried in its two-byte TCP length frame.
pub(super) fn analyze_openvpn_tcp(
    payload: &[u8],
    uses_registered_port: bool,
) -> Option<OpenVpnInfo> {
    let declared_len = usize::from(u16::from_be_bytes([*payload.first()?, *payload.get(1)?]));
    if declared_len == 0 || payload.len() < declared_len + 2 {
        return None;
    }

    analyze_packet(&payload[2..2 + declared_len], uses_registered_port)
}

fn analyze_packet(payload: &[u8], uses_registered_port: bool) -> Option<OpenVpnInfo> {
    let header = *payload.first()?;
    let opcode = header >> OPCODE_SHIFT;
    let key_id = header & KEY_ID_MASK;
    let packet_type = OpenVpnPacketType::from_opcode(opcode)?;

    let plausible = match packet_type {
        OpenVpnPacketType::DataV1 => payload.len() >= DATA_V1_MIN_LEN,
        OpenVpnPacketType::DataV2 => payload.len() >= DATA_V2_MIN_LEN,
        _ => {
            payload.len() >= CONTROL_HEADER_LEN
                && payload[1..CONTROL_HEADER_LEN].iter().any(|byte| *byte != 0)
        }
    };
    if !plausible {
        return None;
    }

    if !uses_registered_port && !is_distinctive_hard_reset(payload, packet_type, key_id) {
        return None;
    }

    Some(OpenVpnInfo {
        packet_type,
        key_id,
    })
}

fn is_distinctive_hard_reset(payload: &[u8], packet_type: OpenVpnPacketType, key_id: u8) -> bool {
    if key_id != 0 {
        return false;
    }

    match packet_type {
        // An unwrapped client reset, and a tls-auth client reset after its
        // HMAC fields, both end in an empty ACK array and message ID zero.
        OpenVpnPacketType::ControlHardResetClientV2 => {
            payload.len() >= CONTROL_HEADER_LEN + 5 && payload.ends_with(&[0; 5])
        }
        // The unwrapped server reset ACKs client packet zero, carries the
        // client's non-zero session ID, and sends its own message ID zero.
        OpenVpnPacketType::ControlHardResetServerV2 => {
            payload.len() >= 26
                && payload[9] == 1
                && payload[10..14] == [0; 4]
                && payload[14..22].iter().any(|byte| *byte != 0)
                && payload[22..26] == [0; 4]
        }
        _ => false,
    }
}

impl OpenVpnPacketType {
    fn from_opcode(opcode: u8) -> Option<Self> {
        match opcode {
            3 => Some(Self::ControlSoftReset),
            4 => Some(Self::Control),
            5 => Some(Self::Ack),
            6 => Some(Self::DataV1),
            7 => Some(Self::ControlHardResetClientV2),
            8 => Some(Self::ControlHardResetServerV2),
            9 => Some(Self::DataV2),
            10 => Some(Self::ControlHardResetClientV3),
            11 => Some(Self::ControlWithWrappedKey),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn control_packet(opcode: u8, key_id: u8, len: usize) -> Vec<u8> {
        let mut payload = vec![0x5a; len];
        payload[0] = (opcode << OPCODE_SHIFT) | key_id;
        payload
    }

    fn client_reset_v2() -> Vec<u8> {
        let mut payload = control_packet(7, 0, 14);
        payload[9..].fill(0);
        payload
    }

    #[test]
    fn recognizes_registered_port_udp_packets() {
        let control = control_packet(4, 3, CONTROL_HEADER_LEN);
        let info = analyze_openvpn_udp(&control, true).unwrap();
        assert_eq!(info.packet_type, OpenVpnPacketType::Control);
        assert_eq!(info.key_id, 3);

        let data_v1 = control_packet(6, 1, DATA_V1_MIN_LEN);
        assert_eq!(
            analyze_openvpn_udp(&data_v1, true).unwrap().packet_type,
            OpenVpnPacketType::DataV1
        );

        let data_v2 = control_packet(9, 7, DATA_V2_MIN_LEN);
        assert_eq!(
            analyze_openvpn_udp(&data_v2, true).unwrap().packet_type,
            OpenVpnPacketType::DataV2
        );
    }

    #[test]
    fn recognizes_complete_tcp_frame() {
        let packet = client_reset_v2();
        let mut frame = Vec::with_capacity(packet.len() + 2);
        frame.extend_from_slice(&(packet.len() as u16).to_be_bytes());
        frame.extend_from_slice(&packet);

        let info = analyze_openvpn_tcp(&frame, false).unwrap();
        assert_eq!(
            info.packet_type,
            OpenVpnPacketType::ControlHardResetClientV2
        );

        frame[1] += 1;
        assert!(analyze_openvpn_tcp(&frame, true).is_none());
    }

    #[test]
    fn alternate_port_requires_distinctive_reset() {
        assert!(analyze_openvpn_udp(&client_reset_v2(), false).is_some());

        let mut tls_auth_reset = control_packet(7, 0, 42);
        let len = tls_auth_reset.len();
        tls_auth_reset[len - 5..].fill(0);
        assert!(analyze_openvpn_udp(&tls_auth_reset, false).is_some());

        assert!(analyze_openvpn_udp(&control_packet(4, 0, 32), false).is_none());
        assert!(analyze_openvpn_udp(&control_packet(7, 1, 14), false).is_none());
    }

    #[test]
    fn recognizes_unwrapped_server_reset_off_port() {
        let mut payload = control_packet(8, 0, 26);
        payload[9] = 1;
        payload[10..14].fill(0);
        payload[14..22].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        payload[22..26].fill(0);
        assert!(analyze_openvpn_udp(&payload, false).is_some());

        payload[10] = 1;
        assert!(analyze_openvpn_udp(&payload, false).is_none());
    }

    #[test]
    fn rejects_invalid_packets() {
        assert!(analyze_openvpn_udp(&[], true).is_none());
        assert!(analyze_openvpn_udp(&control_packet(2, 0, 32), true).is_none());

        let mut zero_session = control_packet(7, 0, 14);
        zero_session[1..CONTROL_HEADER_LEN].fill(0);
        assert!(analyze_openvpn_udp(&zero_session, true).is_none());

        assert!(analyze_openvpn_udp(&control_packet(6, 0, DATA_V1_MIN_LEN - 1), true).is_none());
        assert!(analyze_openvpn_udp(&control_packet(9, 0, DATA_V2_MIN_LEN - 1), true).is_none());
    }
}
