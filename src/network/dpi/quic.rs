pub fn is_quic_packet(payload: &[u8]) -> bool {
    if payload.len() < 5 {
        return false;
    }

    // Check for QUIC long header (bit 7 set)
    if (payload[0] & 0x80) != 0 {
        // Check version
        let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);

        // Known QUIC versions
        return version == 0x00000001 || // QUIC v1
                   version == 0x6b3343cf || // QUIC v2
                   version == 0x51303530 || // Google QUIC
                   version == 0; // Version negotiation
    }

    // Could be short header QUIC packet
    // These are harder to identify definitively, but if we see them on port 443 UDP,
    // they're likely QUIC
    true
}
