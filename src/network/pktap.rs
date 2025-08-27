// PKTAP (Packet Tap) support for macOS
// Provides process identification for network packets
use log::{debug, warn};
use std::mem;

/// PKTAP header structure as defined by Apple
/// Based on the LINKTYPE_PKTAP specification and Apple's pktap.h
#[repr(C)]
#[derive(Debug, Clone)]
pub struct PktapHeader {
    pub pth_length: u32,           // Total header length (minimum 108 bytes)
    pub pth_type_next: u32,        // Type of next header  
    pub pth_dlt: u32,              // DLT type of actual packet (e.g., DLT_EN10MB)
    pub pth_ifname: [u8; 24],      // Interface name (null-terminated)
    pub pth_flags: u32,            // Flags
    pub pth_protocol_family: u16,  // Protocol family (e.g., PF_INET)
    pub pth_frame_pre_length: u16, // Frame prefix length
    pub pth_frame_post_length: u16,// Frame postfix length
    pub pth_iftype: u16,           // Interface type
    pub pth_unit: u16,             // Interface unit
    pub pth_epid: u32,             // Effective process ID
    pub pth_comm: [u8; 20],        // Command name (process name)
    pub pth_svc_class: u32,        // Service class
    pub pth_flowid: u32,           // Flow ID
    pub pth_ipproto: u32,          // IP protocol (e.g., IPPROTO_TCP)
    pub pth_pid: u32,              // Process ID
    pub pth_e_comm: [u8; 20],      // Effective command name
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
        
        // Parse the header (assuming little-endian for now)
        // TODO: Handle endianness properly based on system
        let length = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        
        // Sanity check the length field
        if length < 108 || length as usize > data.len() {
            debug!("Invalid PKTAP header length: {} (packet size: {})", length, data.len());
            return None;
        }
        
        // Parse the full header
        unsafe {
            let header_ptr = data.as_ptr() as *const PktapHeader;
            let mut header = (*header_ptr).clone();
            
            // Convert from network byte order if needed
            header.pth_length = u32::from_le_bytes(header.pth_length.to_le_bytes());
            header.pth_type_next = u32::from_le_bytes(header.pth_type_next.to_le_bytes());
            header.pth_dlt = u32::from_le_bytes(header.pth_dlt.to_le_bytes());
            header.pth_pid = u32::from_le_bytes(header.pth_pid.to_le_bytes());
            header.pth_epid = u32::from_le_bytes(header.pth_epid.to_le_bytes());
            
            Some(header)
        }
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
        
        debug!("PKTAP process info: name={:?}, pid={:?}", final_process_name, pid);
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
    
    /// Get protocol family (e.g., IPv4, IPv6)
    pub fn protocol_family(&self) -> u16 {
        self.pth_protocol_family
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
    
    // Apply aggressive normalization
    let normalized = raw_str
        .chars()
        .map(|c| {
            if c.is_whitespace() {
                ' ' // Convert all whitespace to regular space
            } else if c.is_control() {
                ' ' // Convert control characters to space too
            } else {
                c
            }
        })
        .collect::<String>()
        .split_whitespace() // Split on any whitespace
        .collect::<Vec<&str>>()
        .join(" "); // Join with single spaces
    
    if normalized.is_empty() || !normalized.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        debug!("🚫 Rejected PKTAP process name: raw='{:?}', normalized='{}'", raw_str, normalized);
        None
    } else {
        debug!("✅ Extracted PKTAP process name: raw='{:?}' -> normalized='{}'", raw_str, normalized);
        Some(normalized)
    }
}

/// Normalize process name by collapsing consecutive whitespace to single spaces
/// This ensures consistent formatting between PKTAP and lsof sources
fn normalize_process_name(name: &str) -> String {
    name.split_whitespace().collect::<Vec<&str>>().join(" ")
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
        warn!("PKTAP header claims payload at offset {} but packet is only {} bytes", 
              payload_offset, data.len());
        return None;
    }
    
    let payload = &data[payload_offset..];
    debug!("PKTAP: header_len={}, inner_dlt={}, payload_len={}", 
           header.pth_length, header.pth_dlt, payload.len());
    
    Some((header, payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pktap_linktype_detection() {
        assert!(is_pktap_linktype(149)); // DLT_USER2
        assert!(is_pktap_linktype(258)); // DLT_PKTAP
        assert!(!is_pktap_linktype(1));  // DLT_EN10MB
        assert!(!is_pktap_linktype(12)); // DLT_RAW
    }
    
    #[test]
    fn test_pktap_header_size() {
        // Ensure our struct size matches expectations
        assert!(mem::size_of::<PktapHeader>() >= 108);
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