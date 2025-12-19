// network/capture.rs - Packet capture setup and utilities
use anyhow::{Result, anyhow};
use pcap::{Active, Capture, Device, Error as PcapError};

/// Packet capture configuration
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    /// Network interface name (None for default)
    pub interface: Option<String>,
    /// Snapshot length (bytes to capture per packet)
    pub snaplen: i32,
    /// Buffer size for packet capture
    pub buffer_size: i32,
    /// Read timeout in milliseconds
    pub timeout_ms: i32,
    /// BPF filter string
    pub filter: Option<String>,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interface: None,
            snaplen: 1514,           // Limit packet size to keep more in buffer
            buffer_size: 20_000_000, // 20MB buffer
            timeout_ms: 150,         // 150ms timeout for UI responsiveness
            filter: None,            // Start without filter to ensure we see packets
        }
    }
}

/// Find the best active network device
fn find_best_device() -> Result<Device> {
    let devices = Device::list().map_err(|e| {
        anyhow!(
            "Failed to list network devices: {}. This may indicate insufficient privileges.",
            e
        )
    })?;

    log::info!(
        "Scanning {} devices for best active interface...",
        devices.len()
    );

    // Log all devices for debugging
    for d in &devices {
        let has_valid_ip = d.addresses.iter().any(|addr| match &addr.addr {
            std::net::IpAddr::V4(v4) => {
                !v4.is_link_local() && !v4.is_loopback() && !v4.is_unspecified()
            }
            std::net::IpAddr::V6(v6) => {
                !v6.is_loopback() && !v6.is_multicast() && !v6.is_unspecified()
            }
        });

        log::debug!(
            "  Device: {} [up: {}, running: {}, has_ip: {}]",
            d.name,
            d.flags.is_up(),
            d.flags.is_running(),
            has_valid_ip
        );
    }

    if devices.is_empty() {
        return Err(anyhow!("No network devices found"));
    }

    // Find the best active device
    let suitable_device = devices
        .iter()
        // First priority: up, running, has a valid IP address, and NOT virtual
        .find(|d| {
            // Check if it's a virtual/problematic interface
            let desc_lower = d
                .desc
                .as_ref()
                .map(|s| s.to_lowercase())
                .unwrap_or_default();
            let is_virtual = desc_lower.contains("hyper-v")
                || desc_lower.contains("vmware")
                || desc_lower.contains("virtualbox");

            !d.name.starts_with("lo")
                // Note: 'any' is excluded here because it's not a real interface
                // Users can still specify '-i any' explicitly on Linux
                && d.name != "any"
                && !is_virtual  // Skip virtual adapters in first priority too
                && d.flags.is_up()
                && d.flags.is_running()
                && d.addresses.iter().any(|addr| {
                    match &addr.addr {
                        std::net::IpAddr::V4(v4) => {
                            !v4.is_link_local() && !v4.is_loopback() && !v4.is_unspecified()
                        }
                        std::net::IpAddr::V6(_v6) => false, // Skip IPv6 for now
                    }
                })
        })
        // Second priority: common active interface names
        .or_else(|| {
            devices.iter().find(|d| {
                (d.name == "en0" || d.name == "en1" || d.name.starts_with("eth"))
                    && d.flags.is_up()
                    && d.addresses.iter().any(|addr| addr.addr.is_ipv4())
            })
        })
        // Third priority: any up interface with valid addresses (excluding problematic ones)
        .or_else(|| {
            devices.iter().find(|d| {
                // Check if it's a virtual/problematic interface
                let desc_lower = d
                    .desc
                    .as_ref()
                    .map(|s| s.to_lowercase())
                    .unwrap_or_default();
                let is_virtual = desc_lower.contains("hyper-v")
                    || desc_lower.contains("virtual")
                    || desc_lower.contains("vmware")
                    || desc_lower.contains("virtualbox")
                    || desc_lower.contains("loopback");

                !d.name.starts_with("lo") &&
                !d.name.starts_with("ap") &&     // Skip Apple's ap interfaces
                !d.name.starts_with("awdl") &&   // Skip Apple Wireless Direct
                !d.name.starts_with("llw") &&    // Skip Low latency WLAN
                !d.name.starts_with("bridge") && // Skip bridges
                // TUN/TAP interfaces now supported - removed utun/tun/tap exclusion
                !d.name.starts_with("vmnet") &&  // Skip VM interfaces
                // Note: 'any' is excluded here because it's not a real interface
                // Users can still specify '-i any' explicitly on Linux
                d.name != "any" &&
                !is_virtual &&                    // Skip virtual adapters
                d.flags.is_up() &&
                !d.addresses.is_empty()
            })
        })
        .cloned();

    match suitable_device {
        Some(device) => {
            log::info!(
                "Selected active device: {} ({} addresses)",
                device.name,
                device.addresses.len()
            );
            for addr in &device.addresses {
                log::debug!("  Address: {}", addr.addr);
            }
            Ok(device)
        }
        None => {
            log::error!("No suitable active network device found!");
            log::error!("Try specifying an interface manually with -i flag");
            Err(anyhow!(
                "No active network interface found. Use -i to specify one manually."
            ))
        }
    }
}

/// Setup packet capture with the given configuration
pub fn setup_packet_capture(config: CaptureConfig) -> Result<(Capture<Active>, String, i32)> {
    // Try PKTAP first on macOS for process metadata, but only when:
    // - No interface is explicitly specified
    // - No BPF filter is specified (BPF filters don't work with PKTAP's linktype 149)
    #[cfg(target_os = "macos")]
    if config.interface.is_none() && config.filter.is_none() {
        log::info!("Attempting to use PKTAP for process metadata on macOS");

        match Capture::from_device("pktap") {
            Ok(pktap_builder) => {
                let pktap_cap = pktap_builder
                    .promisc(false) // PKTAP doesn't use promiscuous mode
                    .snaplen(config.snaplen)
                    .buffer_size(config.buffer_size)
                    .timeout(config.timeout_ms)
                    .immediate_mode(true)
                    .want_pktap(true)
                    .open();

                match pktap_cap {
                    Ok(mut cap) => {
                        // Try to set direction for better performance (optional)
                        if let Err(e) = cap.direction(pcap::Direction::InOut) {
                            log::debug!("Could not set PKTAP direction: {}", e);
                        }

                        let linktype = cap.get_datalink();
                        log::info!(
                            "✓ PKTAP enabled successfully, linktype: {} ({})",
                            linktype.0,
                            if linktype.0 == 149 {
                                "Apple PKTAP"
                            } else {
                                "Unknown"
                            }
                        );

                        // Apply BPF filter if specified
                        if let Some(filter) = &config.filter {
                            log::info!("Applying BPF filter to PKTAP: {}", filter);
                            cap.filter(filter, true)?;
                        }

                        log::info!("PKTAP capture ready - process metadata will be available");
                        return Ok((cap, "pktap".to_string(), linktype.0));
                    }
                    Err(e) => {
                        log::warn!("Failed to open PKTAP capture: {}", e);
                        log::info!(
                            "PKTAP requires root privileges - run with 'sudo' for process metadata support"
                        );
                        log::info!(
                            "Falling back to regular capture (process detection will use lsof)"
                        );
                    }
                }
            }
            Err(e) => {
                log::warn!("Failed to create PKTAP device: {}", e);
                log::info!(
                    "PKTAP requires root privileges - run with 'sudo' for process metadata support"
                );
                log::info!("Falling back to regular capture (process detection will use lsof)");
            }
        }
    }

    // Fallback to regular capture (original code)
    #[cfg(target_os = "macos")]
    if config.filter.is_some() {
        log::warn!("BPF filter specified - using regular capture instead of PKTAP (BPF filters don't work with PKTAP)");
    }
    log::info!("Setting up regular packet capture");
    let device = find_capture_device(&config.interface)?;

    // Check if this is a TUN/TAP interface
    use crate::network::link_layer::tun_tap;
    let is_tunnel = tun_tap::is_tunnel_interface(&device.name);
    let tunnel_type = if tun_tap::is_tun_interface(&device.name) {
        "TUN (Layer 3)"
    } else if tun_tap::is_tap_interface(&device.name) {
        "TAP (Layer 2)"
    } else {
        "N/A"
    };

    log::info!(
        "Setting up capture on device: {} ({}){}",
        device.name,
        device.desc.as_deref().unwrap_or("no description"),
        if is_tunnel {
            format!(" [Tunnel: {}]", tunnel_type)
        } else {
            String::new()
        }
    );

    let device_name = device.name.clone();

    // Create capture handle with promiscuous mode disabled
    // We use non-promiscuous mode (read-only packet capture) which only requires CAP_NET_RAW
    let cap = Capture::from_device(device)?
        .promisc(false)
        .snaplen(config.snaplen)
        .buffer_size(config.buffer_size)
        .timeout(config.timeout_ms)
        .immediate_mode(true); // Parse packets ASAP

    // Open the capture
    let mut cap = cap.open()?;

    // Apply BPF filter if specified
    if let Some(filter) = &config.filter {
        log::info!("Applying BPF filter: {}", filter);
        cap.filter(filter, true)?;
    }

    // Note: We're not setting non-blocking mode as we're using timeout instead
    let linktype = cap.get_datalink();

    Ok((cap, device_name, linktype.0))
}

/// Validate that the specified interface exists (if provided)
/// This is useful for failing fast before starting capture threads
pub fn validate_interface(interface_name: &Option<String>) -> Result<()> {
    if let Some(name) = interface_name {
        // This will return an error if the interface doesn't exist
        find_capture_device(&Some(name.clone()))?;
    }
    Ok(())
}

/// Find a capture device by name or return the default
fn find_capture_device(interface_name: &Option<String>) -> Result<Device> {
    match interface_name {
        Some(name) => {
            log::info!("Looking for interface: {}", name);

            // Special handling for 'any' interface
            if name == "any" {
                #[cfg(not(target_os = "linux"))]
                {
                    return Err(anyhow!(
                        "The 'any' interface is only supported on Linux.\n\
                        On your platform, please specify a specific interface with -i <interface>.\n\
                        Run without -i to auto-detect the default interface."
                    ));
                }

                #[cfg(target_os = "linux")]
                {
                    log::info!("Using 'any' pseudo-interface to capture on all interfaces");
                }
            }

            // List all devices
            let devices = Device::list()?;

            // Find exact match first
            if let Some(device) = devices.iter().find(|d| d.name == *name) {
                return Ok(device.clone());
            }

            // Try case-insensitive match
            let name_lower = name.to_lowercase();
            if let Some(device) = devices.iter().find(|d| d.name.to_lowercase() == name_lower) {
                return Ok(device.clone());
            }

            // List available interfaces for error message
            let available: Vec<String> = devices.iter().map(|d| d.name.clone()).collect();

            Err(anyhow!(
                "Interface '{}' not found. Available interfaces: {}",
                name,
                available.join(", ")
            ))
        }
        None => {
            log::info!("No interface specified, using default");

            // Try to get default device
            match Device::lookup() {
                Ok(Some(device)) => {
                    log::info!(
                        "Found default device: {} ({})",
                        device.name,
                        device.desc.as_deref().unwrap_or("no description")
                    );

                    // Check if the default device is actually active
                    let has_valid_ip = device.addresses.iter().any(|addr| {
                        match &addr.addr {
                            std::net::IpAddr::V4(v4) => {
                                !v4.is_link_local() && !v4.is_loopback() && !v4.is_unspecified()
                            }
                            std::net::IpAddr::V6(_v6) => false, // Skip IPv6 for now
                        }
                    });

                    // Check if it's a problematic interface type
                    // Note: 'any' is excluded on non-Linux platforms where it doesn't work
                    let is_problematic = device.name.starts_with("ap")
                        || device.name.starts_with("awdl")
                        || device.name.starts_with("llw")
                        || device.name.starts_with("bridge")
                        // TUN/TAP interfaces now supported - removed utun/tun/tap check
                        || device.name.starts_with("vmnet")
                        || (device.name == "any" && !cfg!(target_os = "linux"))
                        || device.flags.is_loopback();

                    if device.flags.is_up()
                        && device.flags.is_running()
                        && has_valid_ip
                        && !is_problematic
                    {
                        log::info!("Default device appears active, using it");
                        Ok(device)
                    } else {
                        log::warn!(
                            "Default device '{}' is not suitable (up: {}, running: {}, has_ip: {}, problematic: {})",
                            device.name,
                            device.flags.is_up(),
                            device.flags.is_running(),
                            has_valid_ip,
                            is_problematic
                        );
                        log::info!("Looking for a better interface...");

                        // Fall through to the device selection logic below
                        find_best_device()
                    }
                }
                Ok(None) => {
                    log::info!("No default device found");
                    find_best_device()
                }
                Err(e) => Err(e.into()),
            }
        }
    }
}

/// Simple packet reader that handles timeouts gracefully
pub struct PacketReader {
    capture: Capture<Active>,
}

impl PacketReader {
    pub fn new(capture: Capture<Active>) -> Self {
        Self { capture }
    }

    /// Read next packet, returning None on timeout
    pub fn next_packet(&mut self) -> Result<Option<Vec<u8>>> {
        match self.capture.next_packet() {
            Ok(packet) => Ok(Some(packet.data.to_vec())),
            Err(PcapError::TimeoutExpired) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get capture statistics
    pub fn stats(&mut self) -> Result<CaptureStats> {
        let stats = self.capture.stats()?;
        let capture_stats = CaptureStats {
            received: stats.received,
            dropped: stats.dropped,
            if_dropped: stats.if_dropped,
        };

        // Log dropped packets if any occurred
        if capture_stats.total_dropped() > 0 {
            log::debug!(
                "Total {} packets dropped (kernel: {}, interface: {})",
                capture_stats.total_dropped(),
                capture_stats.dropped,
                capture_stats.if_dropped
            );
        }

        Ok(capture_stats)
    }
}

/// Packet capture statistics
#[derive(Debug, Clone, Default)]
pub struct CaptureStats {
    pub received: u32,
    pub dropped: u32,
    /// Interface-level dropped packets (platform-specific)
    pub if_dropped: u32,
}

impl CaptureStats {
    /// Get total packets dropped (both kernel and interface level)
    pub fn total_dropped(&self) -> u32 {
        self.dropped.saturating_add(self.if_dropped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = CaptureConfig::default();
        assert_eq!(config.snaplen, 1514);
        assert!(config.filter.is_none()); // Default starts without filter
    }
}
