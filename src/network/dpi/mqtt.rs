use crate::network::types::{MqttInfo, MqttPacketType, MqttVersion};
use log::debug;

/// Quick check if payload looks like an MQTT packet.
pub fn is_mqtt_packet(payload: &[u8]) -> bool {
    if payload.len() < 2 {
        return false;
    }

    let packet_type = payload[0] >> 4;
    let flags = payload[0] & 0x0F;

    // Valid MQTT packet types are 1-14
    if !(1..=14).contains(&packet_type) {
        return false;
    }

    // Validate flags for packet types with fixed flag requirements (MQTT spec §2.1.2)
    match packet_type {
        1 | 2 | 4 | 6 | 7 | 8 | 9 | 11 | 12 | 13 | 14 => {
            // CONNECT, CONNACK, PUBACK, PUBREL, PUBCOMP, SUBACK, UNSUBACK, PINGREQ/RESP, DISCONNECT
            // must have flags = 0, except SUBSCRIBE(8), UNSUBSCRIBE(10) which must have 0x02
            let expected = match packet_type {
                8 | 10 => 0x02, // SUBSCRIBE, UNSUBSCRIBE require bit 1 set
                _ => 0x00,
            };
            if flags != expected {
                return false;
            }
        }
        _ => {} // PUBLISH(3), PUBREC(5) — flags carry DUP/QoS/RETAIN
    }

    // Validate remaining length encoding and check it's plausible
    let Some((remaining_len, header_bytes)) = decode_remaining_length(payload, 1) else {
        return false;
    };

    // The total packet size should match what we see
    let total = 1 + header_bytes + remaining_len;
    if total > payload.len() + 4 {
        // Allow a small overshoot since we may have a partial payload,
        // but reject wildly wrong lengths (e.g. HTTP text decoded as huge length)
        return false;
    }

    // Only CONNECT packets have a strong enough signature for port-independent detection
    // (they contain "MQTT" or "MQIsdp" protocol name string).
    // All other types (PINGREQ, UNSUBSCRIBE, etc.) have weak 2-byte signatures that
    // easily match random binary data (e.g. BitTorrent file transfers).
    // Those types are still detected via port-based matching (port 1883) in the caller.
    packet_type == 1 && has_mqtt_protocol_name(payload)
}

/// Full MQTT packet analysis.
pub fn analyze_mqtt(payload: &[u8]) -> Option<MqttInfo> {
    if payload.len() < 2 {
        return None;
    }

    let type_byte = payload[0] >> 4;
    let flags = payload[0] & 0x0F;

    let (remaining_len, header_len) = decode_remaining_length(payload, 1)?;

    let packet_type = match type_byte {
        1 => MqttPacketType::Connect,
        2 => MqttPacketType::Connack,
        3 => MqttPacketType::Publish,
        4 => MqttPacketType::Puback,
        8 => MqttPacketType::Subscribe,
        9 => MqttPacketType::Suback,
        10 => MqttPacketType::Unsubscribe,
        11 => MqttPacketType::Unsuback,
        12 => MqttPacketType::Pingreq,
        13 => MqttPacketType::Pingresp,
        14 => MqttPacketType::Disconnect,
        _ => return None,
    };

    let var_start = 1 + header_len;
    let packet_end = var_start + remaining_len;

    // Clamp to actual payload size
    let available = &payload[..payload.len().min(packet_end)];

    let mut info = MqttInfo {
        version: None,
        packet_type,
        client_id: None,
        topic: None,
        qos: None,
    };

    match packet_type {
        MqttPacketType::Connect => {
            parse_connect(available, var_start, &mut info);
        }
        MqttPacketType::Publish => {
            let qos = (flags >> 1) & 0x03;
            info.qos = Some(qos);
            parse_publish_topic(available, var_start, &mut info);
        }
        MqttPacketType::Subscribe => {
            info.qos = Some(1); // SUBSCRIBE always uses QoS 1
        }
        MqttPacketType::Pingreq | MqttPacketType::Pingresp => {
            // No variable header or payload
        }
        _ => {}
    }

    debug!("MQTT analysis result: {:?}", info);
    Some(info)
}

/// Decode MQTT variable-length encoding starting at `offset`.
/// Returns (decoded_length, bytes_consumed).
fn decode_remaining_length(payload: &[u8], offset: usize) -> Option<(usize, usize)> {
    let mut multiplier: usize = 1;
    let mut value: usize = 0;

    for i in 0..4 {
        let idx = offset + i;
        if idx >= payload.len() {
            return None;
        }
        let byte = payload[idx] as usize;
        value += (byte & 0x7F) * multiplier;
        multiplier *= 128;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None // More than 4 bytes is invalid
}

/// Check if payload contains "MQTT" or "MQIsdp" protocol name in a CONNECT packet.
fn has_mqtt_protocol_name(payload: &[u8]) -> bool {
    if payload.len() < 8 {
        return false;
    }

    let (_, header_len) = decode_remaining_length(payload, 1).unwrap_or((0, 1));
    let var_start = 1 + header_len;

    // Protocol name is a length-prefixed string
    if var_start + 2 > payload.len() {
        return false;
    }

    let name_len = u16::from_be_bytes([payload[var_start], payload[var_start + 1]]) as usize;
    let name_start = var_start + 2;
    let name_end = name_start + name_len;

    if name_end > payload.len() {
        return false;
    }

    let name = &payload[name_start..name_end];
    name == b"MQTT" || name == b"MQIsdp"
}

/// Parse a CONNECT packet to extract version, client ID.
fn parse_connect(payload: &[u8], var_start: usize, info: &mut MqttInfo) {
    // Protocol Name (length-prefixed string)
    if var_start + 2 > payload.len() {
        return;
    }
    let name_len = u16::from_be_bytes([payload[var_start], payload[var_start + 1]]) as usize;
    let after_name = var_start + 2 + name_len;

    // Protocol Level byte
    if after_name >= payload.len() {
        return;
    }
    let level = payload[after_name];
    info.version = match level {
        3 => Some(MqttVersion::V31),
        4 => Some(MqttVersion::V311),
        5 => Some(MqttVersion::V50),
        _ => None,
    };

    // Connect Flags (1 byte) + Keep Alive (2 bytes) = 3 bytes after level
    let payload_start = after_name + 4; // level(1) + flags(1) + keepalive(2)

    // For MQTT v5, skip properties length
    let payload_start = if level == 5 {
        skip_mqtt5_properties(payload, payload_start)
    } else {
        payload_start
    };

    // Client ID (length-prefixed string)
    if payload_start + 2 > payload.len() {
        return;
    }
    let client_id_len =
        u16::from_be_bytes([payload[payload_start], payload[payload_start + 1]]) as usize;
    let client_id_start = payload_start + 2;
    let client_id_end = client_id_start + client_id_len;

    if client_id_end > payload.len() {
        return;
    }

    if let Ok(client_id) = std::str::from_utf8(&payload[client_id_start..client_id_end])
        && !client_id.is_empty()
    {
        info.client_id = Some(client_id.to_string());
    }
}

/// Parse the topic from a PUBLISH packet.
fn parse_publish_topic(payload: &[u8], var_start: usize, info: &mut MqttInfo) {
    if var_start + 2 > payload.len() {
        return;
    }

    let topic_len = u16::from_be_bytes([payload[var_start], payload[var_start + 1]]) as usize;
    let topic_start = var_start + 2;
    let topic_end = topic_start + topic_len;

    if topic_end > payload.len() {
        return;
    }

    if let Ok(topic) = std::str::from_utf8(&payload[topic_start..topic_end])
        && !topic.is_empty()
    {
        info.topic = Some(topic.to_string());
    }
}

/// Skip MQTT v5 properties section, returning the new offset.
fn skip_mqtt5_properties(payload: &[u8], offset: usize) -> usize {
    if let Some((prop_len, consumed)) = decode_remaining_length(payload, offset) {
        offset + consumed + prop_len
    } else {
        offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a CONNECT packet.
    fn build_connect(protocol_name: &[u8], level: u8, client_id: &str) -> Vec<u8> {
        let name_len = protocol_name.len();
        // variable header: name_len(2) + name + level(1) + flags(1) + keepalive(2) + client_id_len(2) + client_id
        let var_len = 2 + name_len + 1 + 1 + 2 + 2 + client_id.len();

        let mut pkt = Vec::new();
        pkt.push(0x10); // CONNECT type (1 << 4)
        // Remaining length (simple single-byte for test payloads < 128)
        pkt.push(var_len as u8);
        // Protocol name
        pkt.extend_from_slice(&(name_len as u16).to_be_bytes());
        pkt.extend_from_slice(protocol_name);
        // Protocol level
        pkt.push(level);
        // Connect flags (clean session)
        pkt.push(0x02);
        // Keep alive
        pkt.extend_from_slice(&60u16.to_be_bytes());
        // Client ID
        pkt.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
        pkt.extend_from_slice(client_id.as_bytes());
        pkt
    }

    /// Helper: build a PUBLISH packet.
    fn build_publish(topic: &str, qos: u8, payload_data: &[u8]) -> Vec<u8> {
        let flags = (qos & 0x03) << 1;
        let packet_id_len = if qos > 0 { 2 } else { 0 };
        let var_len = 2 + topic.len() + packet_id_len + payload_data.len();

        let mut pkt = Vec::new();
        pkt.push(0x30 | flags); // PUBLISH type (3 << 4) | flags
        pkt.push(var_len as u8);
        // Topic
        pkt.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        pkt.extend_from_slice(topic.as_bytes());
        // Packet ID (for QoS > 0)
        if qos > 0 {
            pkt.extend_from_slice(&1u16.to_be_bytes());
        }
        pkt.extend_from_slice(payload_data);
        pkt
    }

    #[test]
    fn test_empty_payload_safe() {
        // This simulates a potential DoS attack with an empty packet
        // Should return None, not panic
        assert!(analyze_mqtt(&[]).is_none());
    }

    #[test]
    fn test_connect_v311() {
        let pkt = build_connect(b"MQTT", 4, "my-client");
        assert!(is_mqtt_packet(&pkt));

        let info = analyze_mqtt(&pkt).unwrap();
        assert_eq!(info.packet_type, MqttPacketType::Connect);
        assert_eq!(info.version, Some(MqttVersion::V311));
        assert_eq!(info.client_id.as_deref(), Some("my-client"));
    }

    #[test]
    fn test_connect_v31_mqisdp() {
        let pkt = build_connect(b"MQIsdp", 3, "old-device");
        assert!(is_mqtt_packet(&pkt));

        let info = analyze_mqtt(&pkt).unwrap();
        assert_eq!(info.packet_type, MqttPacketType::Connect);
        assert_eq!(info.version, Some(MqttVersion::V31));
        assert_eq!(info.client_id.as_deref(), Some("old-device"));
    }

    #[test]
    fn test_connect_v50() {
        // Build a v5 CONNECT with properties length = 0
        let mut pkt = Vec::new();
        pkt.push(0x10); // CONNECT
        // We'll fill remaining length at the end
        let var_header_start = pkt.len();
        pkt.push(0); // placeholder

        // Protocol name
        pkt.extend_from_slice(&4u16.to_be_bytes());
        pkt.extend_from_slice(b"MQTT");
        // Level 5
        pkt.push(5);
        // Flags
        pkt.push(0x02);
        // Keep alive
        pkt.extend_from_slice(&60u16.to_be_bytes());
        // Properties length = 0
        pkt.push(0);
        // Client ID
        let client = "v5-client";
        pkt.extend_from_slice(&(client.len() as u16).to_be_bytes());
        pkt.extend_from_slice(client.as_bytes());

        // Fix remaining length
        pkt[var_header_start] = (pkt.len() - var_header_start - 1) as u8;

        let info = analyze_mqtt(&pkt).unwrap();
        assert_eq!(info.version, Some(MqttVersion::V50));
        assert_eq!(info.client_id.as_deref(), Some("v5-client"));
    }

    #[test]
    fn test_connack() {
        // CONNACK: type 2, remaining length 2, session present=0, return code=0
        // Not detected by is_mqtt_packet (only CONNECT has strong signature),
        // but analyze_mqtt still parses it (used via port-based detection path)
        let pkt = vec![0x20, 0x02, 0x00, 0x00];
        assert!(!is_mqtt_packet(&pkt));

        let info = analyze_mqtt(&pkt).unwrap();
        assert_eq!(info.packet_type, MqttPacketType::Connack);
    }

    #[test]
    fn test_publish_qos0() {
        let pkt = build_publish("home/temp", 0, b"22.5");

        let info = analyze_mqtt(&pkt).unwrap();
        assert_eq!(info.packet_type, MqttPacketType::Publish);
        assert_eq!(info.topic.as_deref(), Some("home/temp"));
        assert_eq!(info.qos, Some(0));
    }

    #[test]
    fn test_publish_qos1() {
        let pkt = build_publish("sensors/humidity", 1, b"65");

        let info = analyze_mqtt(&pkt).unwrap();
        assert_eq!(info.packet_type, MqttPacketType::Publish);
        assert_eq!(info.topic.as_deref(), Some("sensors/humidity"));
        assert_eq!(info.qos, Some(1));
    }

    #[test]
    fn test_subscribe() {
        // SUBSCRIBE: type 8, flags 0x02, packet id, topic filter
        let topic = "home/#";
        let var_len = 2 + 2 + topic.len() + 1; // packet_id + topic_len + topic + qos
        let mut pkt = vec![0x82, var_len as u8];
        pkt.extend_from_slice(&1u16.to_be_bytes()); // packet ID
        pkt.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        pkt.extend_from_slice(topic.as_bytes());
        pkt.push(0x01); // QoS 1

        let info = analyze_mqtt(&pkt).unwrap();
        assert_eq!(info.packet_type, MqttPacketType::Subscribe);
        assert_eq!(info.qos, Some(1));
    }

    #[test]
    fn test_pingreq() {
        let pkt = vec![0xC0, 0x00];
        assert!(!is_mqtt_packet(&pkt));

        let info = analyze_mqtt(&pkt).unwrap();
        assert_eq!(info.packet_type, MqttPacketType::Pingreq);
    }

    #[test]
    fn test_pingresp() {
        let pkt = vec![0xD0, 0x00];
        assert!(!is_mqtt_packet(&pkt));

        let info = analyze_mqtt(&pkt).unwrap();
        assert_eq!(info.packet_type, MqttPacketType::Pingresp);
    }

    #[test]
    fn test_disconnect() {
        let pkt = vec![0xE0, 0x00];
        let info = analyze_mqtt(&pkt).unwrap();
        assert_eq!(info.packet_type, MqttPacketType::Disconnect);
    }

    #[test]
    fn test_invalid_type() {
        // Type 0 is reserved/invalid
        let pkt = vec![0x00, 0x00];
        assert!(!is_mqtt_packet(&pkt));
        assert!(analyze_mqtt(&pkt).is_none());
    }

    #[test]
    fn test_type_15_invalid() {
        // Type 15 is reserved
        let pkt = vec![0xF0, 0x00];
        assert!(!is_mqtt_packet(&pkt));
        assert!(analyze_mqtt(&pkt).is_none());
    }

    #[test]
    fn test_too_short() {
        assert!(!is_mqtt_packet(&[]));
        assert!(!is_mqtt_packet(&[0x10]));
        assert!(analyze_mqtt(&[]).is_none());
    }

    #[test]
    fn test_connect_without_mqtt_name_rejected() {
        // CONNECT type but garbage protocol name
        let pkt = vec![0x10, 0x08, 0x00, 0x04, b'X', b'Y', b'Z', b'W', 4, 0];
        assert!(!is_mqtt_packet(&pkt));
    }

    #[test]
    fn test_non_connect_not_detected_by_signature() {
        // Non-CONNECT packets are not detected by is_mqtt_packet (signature-based).
        // They are only detected via port 1883 matching in the caller.
        let pkt = vec![0x20, 0x02, 0x00, 0x00]; // CONNACK
        assert!(!is_mqtt_packet(&pkt));
    }

    #[test]
    fn test_multibyte_remaining_length() {
        // Non-CONNECT with multi-byte length should NOT be detected by signature
        let mut pkt = vec![0xC0, 0xC8, 0x01]; // PINGREQ with 200-byte remaining
        pkt.extend(vec![0; 200]);
        assert!(!is_mqtt_packet(&pkt));

        // Multi-byte remaining length decoding is still exercised via analyze_mqtt
        let info = analyze_mqtt(&pkt).unwrap();
        assert_eq!(info.packet_type, MqttPacketType::Pingreq);
    }

    #[test]
    fn test_invalid_remaining_length() {
        // All continuation bits set (> 4 bytes) — invalid
        let pkt = vec![0x20, 0x80, 0x80, 0x80, 0x80, 0x01];
        assert!(!is_mqtt_packet(&pkt));
    }

    #[test]
    fn test_connect_empty_client_id() {
        let pkt = build_connect(b"MQTT", 4, "");
        let info = analyze_mqtt(&pkt).unwrap();
        assert_eq!(info.packet_type, MqttPacketType::Connect);
        assert_eq!(info.client_id, None); // empty string stored as None
    }

    #[test]
    fn test_http_not_mqtt() {
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(!is_mqtt_packet(payload));
    }

    #[test]
    fn test_binary_data_not_false_positive_mqtt() {
        // Bytes resembling MQTT PINGREQ from random BitTorrent file transfer data
        assert!(!is_mqtt_packet(&[0xC0, 0x00]));
        assert!(!is_mqtt_packet(&[0xC0, 0x00, 0xDE, 0xAD, 0xBE, 0xEF]));

        // Bytes resembling MQTT UNSUBSCRIBE
        assert!(!is_mqtt_packet(&[0xA2, 0x05, 0x00, 0x01, 0x00, 0x01, 0x00]));

        // Bytes resembling MQTT PUBLISH
        assert!(!is_mqtt_packet(&[
            0x30, 0x0A, 0x00, 0x04, b't', b'e', b's', b't'
        ]));

        // Bytes resembling MQTT DISCONNECT
        assert!(!is_mqtt_packet(&[0xE0, 0x00]));
    }
}
