// PKTAP (Packet Tap) support for macOS
// Provides process identification for network packets
use log::{debug, warn};
use std::mem;

/// PKTAP header structure as defined by Apple
/// Based on the LINKTYPE_PKTAP specification and Apple's pktap.h
#[repr(C)]
#[derive(Debug, Clone)]
pub struct PktapHeader {
    pub pth_length: u32,            // Total header length (minimum 108 bytes)
    pub pth_type_next: u32,         // Type of next header
    pub pth_dlt: u32,               // DLT type of actual packet (e.g., DLT_EN10MB)
    pub pth_ifname: [u8; 24],       // Interface name (null-terminated)
    pub pth_flags: u32,             // Flags
    pub pth_protocol_family: u16,   // Protocol family (e.g., PF_INET)
    pub pth_frame_pre_length: u16,  // Frame prefix length
    pub pth_frame_post_length: u16, // Frame postfix length
    pub pth_iftype: u16,            // Interface type
    pub pth_unit: u16,              // Interface unit
    pub pth_epid: u32,              // Effective process ID
    pub pth_comm: [u8; 20],         // Command name (process name)
    pub pth_svc_class: u32,         // Service class
    pub pth_flowid: u32,            // Flow ID
    pub pth_ipproto: u32,           // IP protocol (e.g., IPPROTO_TCP)
    pub pth_pid: u32,               // Process ID
    pub pth_e_comm: [u8; 20],       // Effective command name
                                    // Note: There may be additional fields after this
}

impl PktapHeader {
    /// Parse PKTAP header from raw packet data
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        // Check minimum size
        if data.len() < mem::size_of::<PktapHeader>() {
            debug!("Packet too small for PKTAP header: {} bytes", data.len());
            return None;
        }

        // Parse the header as little-endian. PKTAP is macOS-only (Apple's DLT_PKTAP),
        // and all macOS platforms (x86_64 and ARM64) are little-endian.
        let length = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

        // Sanity check the length field
        if length < 108 || length as usize > data.len() {
            debug!(
                "Invalid PKTAP header length: {} (packet size: {})",
                length,
                data.len()
            );
            return None;
        }

        // SAFETY: We verified data.len() >= size_of::<PktapHeader>() above.
        // Using read_unaligned because data (&[u8]) may not satisfy PktapHeader's
        // alignment requirement from its u32 fields. PKTAP is macOS-only and the
        // wire format is little-endian, so reading the struct natively on a
        // little-endian host already yields the correct field values — no
        // explicit byte-swap is required.
        let header = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const PktapHeader) };

        Some(header)
    }

    /// Extract process information from the header using the correct offsets
    /// Based on our successful test: process name at offset 56, PID at offset 52
    pub fn get_process_info(&self) -> (Option<String>, Option<u32>) {
        // Extract process name from pth_comm (offset 56, length 20)
        let process_name = extract_process_name_from_bytes(&self.pth_comm);

        // Extract PID - use pth_epid which is at the right offset (52)
        // Based on our test, the PID was consistently at offset 52
        let pid = if self.pth_epid != 0 && self.pth_epid < 65535 {
            Some(self.pth_epid)
        } else if self.pth_pid != 0 && self.pth_pid < 65535 {
            Some(self.pth_pid)
        } else {
            None
        };

        // Also try effective command name if regular one is empty
        let final_process_name = if process_name.is_none() {
            extract_process_name_from_bytes(&self.pth_e_comm)
        } else {
            process_name
        };

        debug!(
            "PKTAP process info: name={:?}, pid={:?}",
            final_process_name, pid
        );
        (final_process_name, pid)
    }

    /// Get the interface name
    pub fn get_interface(&self) -> String {
        std::str::from_utf8(&self.pth_ifname)
            .unwrap_or("")
            .trim_end_matches('\0')
            .trim()
            .to_string()
    }

    /// Get the offset where the actual packet data starts
    pub fn payload_offset(&self) -> usize {
        self.pth_length as usize
    }

    /// Get the DLT type of the inner packet
    pub fn inner_dlt(&self) -> u32 {
        self.pth_dlt
    }

    /// Check if this PKTAP header looks valid
    pub fn is_valid(&self) -> bool {
        // Basic sanity checks
        self.pth_length >= 108 &&
        self.pth_length <= 4096 && // Reasonable upper bound
        self.pth_dlt > 0 &&
        self.pth_dlt < 1000 // Reasonable DLT range
    }
}

/// Extract and normalize process name from raw PKTAP bytes
/// Handles all types of padding: null bytes, spaces, tabs, and other whitespace
fn extract_process_name_from_bytes(bytes: &[u8; 20]) -> Option<String> {
    // First, find the actual string content
    let mut end_pos = bytes.len();
    for (i, &byte) in bytes.iter().enumerate() {
        if byte == 0 {
            end_pos = i;
            break;
        }
    }

    // Convert bytes to string, handling invalid UTF-8
    let raw_str = std::str::from_utf8(&bytes[..end_pos]).ok()?;

    // Apply aggressive normalization: treat every whitespace/control char as a
    // separator, collapse runs into a single space, and trim the ends. Done in
    // one pass into a single String (the previous chain allocated a String, then
    // a Vec<&str>, then the joined String).
    let mut normalized = String::with_capacity(raw_str.len());
    for c in raw_str.chars() {
        if c.is_whitespace() || c.is_control() {
            if !normalized.is_empty() && !normalized.ends_with(' ') {
                normalized.push(' ');
            }
        } else {
            normalized.push(c);
        }
    }
    if normalized.ends_with(' ') {
        normalized.pop();
    }

    if normalized.is_empty() || !normalized.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        debug!(
            "🚫 Rejected PKTAP process name: raw='{:?}', normalized='{}'",
            raw_str, normalized
        );
        None
    } else {
        debug!(
            "✅ Extracted PKTAP process name: raw='{:?}' -> normalized='{}'",
            raw_str, normalized
        );
        Some(normalized)
    }
}

/// Check if the given linktype represents PKTAP data
pub fn is_pktap_linktype(linktype: i32) -> bool {
    match linktype {
        149 => true, // DLT_USER2 (Apple's PKTAP on Darwin)
        258 => true, // DLT_PKTAP (standard)
        _ => false,
    }
}

/// Try to extract PKTAP metadata and payload from a packet
pub fn parse_pktap_packet(data: &[u8]) -> Option<(PktapHeader, &[u8])> {
    let header = PktapHeader::from_bytes(data)?;

    if !header.is_valid() {
        warn!("Invalid PKTAP header detected");
        return None;
    }

    let payload_offset = header.payload_offset();
    if data.len() <= payload_offset {
        warn!(
            "PKTAP header claims payload at offset {} but packet is only {} bytes",
            payload_offset,
            data.len()
        );
        return None;
    }

    let payload = &data[payload_offset..];
    debug!(
        "PKTAP: header_len={}, inner_dlt={}, payload_len={}",
        header.pth_length,
        header.pth_dlt,
        payload.len()
    );

    Some((header, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pktap_linktype_detection() {
        assert!(is_pktap_linktype(149)); // DLT_USER2
        assert!(is_pktap_linktype(258)); // DLT_PKTAP
        assert!(!is_pktap_linktype(1)); // DLT_EN10MB
        assert!(!is_pktap_linktype(12)); // DLT_RAW
    }

    #[test]
    fn test_pktap_header_size() {
        // Ensure our struct size matches expectations
        assert!(mem::size_of::<PktapHeader>() >= 108);
    }

    fn name_bytes(s: &[u8]) -> [u8; 20] {
        let mut b = [0u8; 20];
        let n = s.len().min(20);
        b[..n].copy_from_slice(&s[..n]);
        b
    }

    #[test]
    fn test_extract_process_name_null_padded() {
        assert_eq!(
            extract_process_name_from_bytes(&name_bytes(b"firefox")),
            Some("firefox".to_string())
        );
    }

    #[test]
    fn test_extract_process_name_trims_and_collapses() {
        // Leading/trailing padding plus an internal run of mixed whitespace
        // collapse to single spaces with trimmed ends.
        assert_eq!(
            extract_process_name_from_bytes(&name_bytes(b"  Google\t  Chrome  ")),
            Some("Google Chrome".to_string())
        );
    }

    #[test]
    fn test_extract_process_name_control_chars_are_separators() {
        // A non-null control byte acts as a separator, not part of the name.
        assert_eq!(
            extract_process_name_from_bytes(&name_bytes(b"ab\x01cd")),
            Some("ab cd".to_string())
        );
    }

    #[test]
    fn test_extract_process_name_all_whitespace_rejected() {
        assert!(extract_process_name_from_bytes(&name_bytes(b"   \t  ")).is_none());
        assert!(extract_process_name_from_bytes(&name_bytes(b"")).is_none());
    }

    #[test]
    fn test_invalid_pktap_data() {
        // Too small
        let small_data = [0u8; 50];
        assert!(PktapHeader::from_bytes(&small_data).is_none());

        // Invalid length field
        let mut bad_data = [0u8; 200];
        bad_data[0] = 50; // Length too small
        assert!(PktapHeader::from_bytes(&bad_data).is_none());
    }
}
