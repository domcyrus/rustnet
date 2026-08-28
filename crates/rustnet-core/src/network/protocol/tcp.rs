//! TCP (Transmission Control Protocol) parsing

use crate::network::dpi;
use crate::network::parser::{ParsedPacket, ParserConfig};
use crate::network::protocol::{TransportParams, orient_endpoints};
use crate::network::types::{Protocol, ProtocolState, TcpState};

// Define TCP flags as bit masks
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

/// TCP flags from the TCP header
#[derive(Debug, Clone, Copy)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub ack: bool,
}

/// TCP header information extracted from the packet
#[derive(Debug, Clone, Copy)]
pub struct TcpHeaderInfo {
    pub seq: u32,         // Sequence number
    pub ack: u32,         // Acknowledgment number
    pub window: u16,      // Window size
    pub flags: TcpFlags,  // TCP flags
    pub payload_len: u32, // Actual TCP payload length (not including headers)
    /// Window-scale verdict from the SYN's options (RFC 7323). Only ever
    /// `Some` on a SYN segment; the option is illegal elsewhere.
    pub window_scale: Option<SynWindowScale>,
}

/// What a SYN's options said about window scaling. `Absent` is a proven
/// negative (the options were walked completely and carried no window-scale
/// option), which is different from `Unknown` (truncated or malformed
/// options), where no conclusion may be drawn: treating an unexamined SYN
/// as a refusal would permanently disable scaling for the connection even
/// when a complete retransmitted SYN later shows the option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SynWindowScale {
    /// The SYN offered window scaling with this shift.
    Present(u8),
    /// The options were fully examined and carry no window-scale option.
    Absent,
    /// The options could not be fully examined (capture truncation or a
    /// malformed option); nothing can be concluded.
    Unknown,
}

/// Highest shift RFC 7323 permits; larger advertised values are clamped.
const MAX_WINDOW_SCALE: u8 = 14;

/// Extract the window-scale verdict (option kind 3) from a SYN's option bytes.
fn parse_window_scale(options: &[u8]) -> SynWindowScale {
    let mut i = 0;
    while i < options.len() {
        match options[i] {
            0 => return SynWindowScale::Absent, // End of option list
            1 => i += 1,                        // NOP
            kind => {
                let Some(&len) = options.get(i + 1) else {
                    return SynWindowScale::Unknown; // kind byte without length
                };
                let len = len as usize;
                if len < 2 || i + len > options.len() {
                    return SynWindowScale::Unknown; // Malformed, stop walking
                }
                if kind == 3 {
                    // Kind 3 is exactly three bytes (RFC 7323); any other
                    // length is a malformed option (RFC 9293) and proves
                    // nothing, so it must not end the walk in Absent.
                    return if len == 3 {
                        SynWindowScale::Present(options[i + 2].min(MAX_WINDOW_SCALE))
                    } else {
                        SynWindowScale::Unknown
                    };
                }
                i += len;
            }
        }
    }
    SynWindowScale::Absent
}

/// Parse TCP flags from the flags byte
pub(crate) fn parse_tcp_flags(flags: u8) -> TcpFlags {
    TcpFlags {
        fin: (flags & TCP_FIN) != 0,
        syn: (flags & TCP_SYN) != 0,
        rst: (flags & TCP_RST) != 0,
        ack: (flags & TCP_ACK) != 0,
    }
}

/// Parse a TCP packet
pub(crate) fn parse(
    transport_data: &[u8],
    params: TransportParams,
    config: &ParserConfig,
    local_ips: &std::collections::HashSet<std::net::IpAddr>,
) -> Option<ParsedPacket> {
    if transport_data.len() < 20 {
        return None;
    }

    let src_port = u16::from_be_bytes([transport_data[0], transport_data[1]]);
    let dst_port = u16::from_be_bytes([transport_data[2], transport_data[3]]);

    // Extract TCP header fields
    let seq = u32::from_be_bytes([
        transport_data[4],
        transport_data[5],
        transport_data[6],
        transport_data[7],
    ]);
    let ack = u32::from_be_bytes([
        transport_data[8],
        transport_data[9],
        transport_data[10],
        transport_data[11],
    ]);
    let window = u16::from_be_bytes([transport_data[14], transport_data[15]]);
    let flags = transport_data[13];

    let tcp_flags = parse_tcp_flags(flags);

    // Calculate actual TCP payload length. A data offset below 5 is invalid
    // (RFC 9293 §3.1) — treating it as a header length would make the
    // payload overlap the header itself.
    let tcp_header_len = ((transport_data[12] >> 4) as usize) * 4;
    if tcp_header_len < 20 {
        return None;
    }
    let tcp_payload_len = transport_data.len().saturating_sub(tcp_header_len) as u32;

    // The window-scale option only appears on SYN segments. A capture
    // truncated before the declared data offset (snaplen) cannot prove the
    // option absent, so it yields Unknown rather than Absent.
    let window_scale = if tcp_flags.syn {
        Some(if transport_data.len() < tcp_header_len {
            SynWindowScale::Unknown
        } else if tcp_header_len > 20 {
            parse_window_scale(&transport_data[20..tcp_header_len])
        } else {
            SynWindowScale::Absent
        })
    } else {
        None
    };

    let tcp_header = TcpHeaderInfo {
        seq,
        ack,
        window,
        flags: tcp_flags,
        payload_len: tcp_payload_len,
        window_scale,
    };

    // Log TCP flags for debugging
    log::trace!(
        "TCP flags: FIN={} SYN={} RST={} ACK={}",
        tcp_flags.fin,
        tcp_flags.syn,
        tcp_flags.rst,
        tcp_flags.ack
    );

    let (local_addr, remote_addr, is_outgoing) =
        orient_endpoints(&params, src_port, dst_port, local_ips);

    // Perform DPI if enabled and there's payload
    let dpi_result = if config.enable_dpi {
        if transport_data.len() > tcp_header_len {
            let payload = &transport_data[tcp_header_len..];
            dpi::analyze_tcp_packet(payload, local_addr.port(), remote_addr.port(), is_outgoing)
        } else {
            None
        }
    } else {
        None
    };

    let mut packet = ParsedPacket::new(
        Protocol::Tcp,
        local_addr,
        remote_addr,
        ProtocolState::Tcp(TcpState::Unknown),
        is_outgoing,
        params.packet_len,
        params.process_name,
        params.process_id,
    );
    packet.tcp_header = Some(tcp_header);
    packet.dpi_result = dpi_result;
    Some(packet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_flags_parsing() {
        let flags = parse_tcp_flags(0x02); // SYN
        assert!(flags.syn);
        assert!(!flags.ack);
        assert!(!flags.fin);

        let flags = parse_tcp_flags(0x12); // SYN + ACK
        assert!(flags.syn);
        assert!(flags.ack);

        let flags = parse_tcp_flags(0x11); // FIN + ACK
        assert!(flags.fin);
        assert!(flags.ack);
    }

    #[test]
    fn window_scale_option_parsed() {
        // MSS (kind 2, len 4), NOP, window scale (kind 3, len 3, shift 7)
        let options = [2, 4, 0x05, 0xb4, 1, 3, 3, 7];
        assert_eq!(parse_window_scale(&options), SynWindowScale::Present(7));
    }

    #[test]
    fn window_scale_proven_absent() {
        // MSS only, then end-of-options: a complete walk is a proven negative.
        let options = [2, 4, 0x05, 0xb4, 0, 0, 0, 0];
        assert_eq!(parse_window_scale(&options), SynWindowScale::Absent);
        // Fully walked without hitting end-of-list is also proven.
        let options = [2, 4, 0x05, 0xb4];
        assert_eq!(parse_window_scale(&options), SynWindowScale::Absent);
    }

    #[test]
    fn window_scale_clamped_to_rfc_max() {
        let options = [3, 3, 60];
        assert_eq!(parse_window_scale(&options), SynWindowScale::Present(14));
    }

    #[test]
    fn window_scale_unknown_on_malformed_options() {
        // Malformed options prove nothing: they must not read as a refusal.
        // Option claims a length running past the buffer
        let options = [2, 40, 0x05];
        assert_eq!(parse_window_scale(&options), SynWindowScale::Unknown);
        // Zero-length option must not loop forever
        let options = [5, 0, 3, 3, 7];
        assert_eq!(parse_window_scale(&options), SynWindowScale::Unknown);
        // Truncated: kind byte with no length byte
        let options = [3];
        assert_eq!(parse_window_scale(&options), SynWindowScale::Unknown);
    }

    #[test]
    fn window_scale_with_illegal_length_is_unknown() {
        // Kind 3 is exactly three bytes; other lengths are malformed and
        // must not read as a proven absence.
        let options = [3, 2];
        assert_eq!(parse_window_scale(&options), SynWindowScale::Unknown);
        let options = [3, 4, 7, 0];
        assert_eq!(parse_window_scale(&options), SynWindowScale::Unknown);
    }
}
