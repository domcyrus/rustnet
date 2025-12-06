//! Network privilege detection for packet capture
//!
//! This module checks if the application has sufficient privileges to capture
//! network packets on different platforms (Linux, macOS, Windows).

use anyhow::Result;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
use anyhow::anyhow;
#[cfg(any(
    not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_os = "freebsd"
    )),
    target_os = "windows"
))]
use log::warn;
use log::{debug, info};

/// Privilege check result with detailed information
#[derive(Debug, Clone)]
pub struct PrivilegeStatus {
    /// Whether sufficient privileges are available
    pub has_privileges: bool,
    /// Missing capabilities or permissions
    pub missing: Vec<String>,
    /// Platform-specific instructions to gain privileges
    pub instructions: Vec<String>,
}

impl PrivilegeStatus {
    /// Create a status indicating sufficient privileges
    pub fn sufficient() -> Self {
        Self {
            has_privileges: true,
            missing: Vec::new(),
            instructions: Vec::new(),
        }
    }

    /// Create a status indicating insufficient privileges
    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_os = "freebsd",
        test
    ))]
    pub fn insufficient(missing: Vec<String>, instructions: Vec<String>) -> Self {
        Self {
            has_privileges: false,
            missing,
            instructions,
        }
    }

    /// Get a human-readable error message
    pub fn error_message(&self) -> String {
        if self.has_privileges {
            return String::new();
        }

        let mut msg = String::from("Insufficient privileges for network packet capture.\n\n");

        if !self.missing.is_empty() {
            msg.push_str("Missing:\n");
            for item in &self.missing {
                msg.push_str(&format!("  • {}\n", item));
            }
            msg.push('\n');
        }

        if !self.instructions.is_empty() {
            msg.push_str("How to fix:\n");
            for (i, instruction) in self.instructions.iter().enumerate() {
                msg.push_str(&format!("  {}. {}\n", i + 1, instruction));
            }
        }

        msg
    }
}

/// Check if the current process has sufficient privileges for packet capture
pub fn check_packet_capture_privileges() -> Result<PrivilegeStatus> {
    #[cfg(target_os = "linux")]
    {
        check_linux_privileges()
    }

    #[cfg(target_os = "macos")]
    {
        check_macos_privileges()
    }

    #[cfg(target_os = "windows")]
    {
        check_windows_privileges()
    }

    #[cfg(target_os = "freebsd")]
    {
        check_freebsd_privileges()
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_os = "freebsd"
    )))]
    {
        // Unknown platform - return optimistic result
        warn!("Privilege check not implemented for this platform");
        Ok(PrivilegeStatus::sufficient())
    }
}

#[cfg(target_os = "linux")]
fn check_linux_privileges() -> Result<PrivilegeStatus> {
    use std::fs;

    // Check if running as root by reading /proc/self/status
    let is_root = is_root_user()?;

    if is_root {
        info!("Running as root - all privileges available");
        return Ok(PrivilegeStatus::sufficient());
    }

    debug!("Not running as root, checking capabilities");

    // Check for required capabilities via /proc/self/status
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|e| anyhow!("Failed to read /proc/self/status: {}", e))?;

    // Parse CapEff (effective capabilities) line
    let cap_value = status
        .lines()
        .find(|line| line.starts_with("CapEff:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|cap_hex| u64::from_str_radix(cap_hex, 16).ok())
        .ok_or_else(|| anyhow!("Failed to parse effective capabilities"))?;

    debug!("Current effective capabilities: 0x{:x}", cap_value);

    // Required capability for read-only packet capture (no promiscuous mode)
    const CAP_NET_RAW: u64 = 13; // For packet capture

    let mut missing = Vec::new();

    // Check CAP_NET_RAW
    if (cap_value & (1u64 << CAP_NET_RAW)) != 0 {
        debug!("CAP_NET_RAW: present");
        return Ok(PrivilegeStatus::sufficient());
    } else {
        debug!("CAP_NET_RAW: missing");
        missing.push("CAP_NET_RAW capability (required for packet capture)".to_string());
    }

    // Build instructions for gaining privileges
    let mut instructions = vec![
        "Run with sudo: sudo rustnet".to_string(),
        "Set capabilities (modern Linux 5.8+, with eBPF): sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon=eip' $(which rustnet)".to_string(),
        "Set capabilities (legacy/older kernels, with eBPF): sudo setcap 'cap_net_raw,cap_sys_admin=eip' $(which rustnet)".to_string(),
        "Set capabilities (packet capture only, no eBPF): sudo setcap 'cap_net_raw=eip' $(which rustnet)".to_string(),
    ];

    // Add Docker-specific instructions if it looks like we're in a container
    if is_running_in_container() {
        instructions.push(
            "If running in Docker, add these flags:\n  \
             --cap-add=NET_RAW --cap-add=BPF --cap-add=PERFMON \
             --net=host --pid=host"
                .to_string(),
        );
    }

    Ok(PrivilegeStatus::insufficient(missing, instructions))
}

/// Check if running as root user (UID 0) by reading /proc/self/status
#[cfg(target_os = "linux")]
fn is_root_user() -> Result<bool> {
    use std::fs;

    let status = fs::read_to_string("/proc/self/status")
        .map_err(|e| anyhow!("Failed to read /proc/self/status: {}", e))?;

    // Look for "Uid:" line which contains Real, Effective, Saved Set, and Filesystem UIDs
    // Format: "Uid:    1000    1000    1000    1000"
    let is_root = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .and_then(|line| {
            // Get the effective UID (second field)
            line.split_whitespace().nth(2)
        })
        .and_then(|uid| uid.parse::<u32>().ok())
        .map(|uid| uid == 0)
        .unwrap_or(false);

    Ok(is_root)
}

/// Detect if running inside a container
#[cfg(target_os = "linux")]
fn is_running_in_container() -> bool {
    use std::fs;

    // Check for .dockerenv file
    if fs::metadata("/.dockerenv").is_ok() {
        return true;
    }

    // Check cgroup
    if let Ok(cgroup) = fs::read_to_string("/proc/self/cgroup")
        && (cgroup.contains("docker") || cgroup.contains("kubepods") || cgroup.contains("lxc"))
    {
        return true;
    }

    false
}

#[cfg(target_os = "macos")]
fn check_macos_privileges() -> Result<PrivilegeStatus> {
    use std::fs;

    // Check if running as root by reading effective UID from process
    let is_root = is_root_user()?;

    if is_root {
        info!("Running as root - all privileges available");
        return Ok(PrivilegeStatus::sufficient());
    }

    debug!("Not running as root, checking BPF device permissions");

    // On macOS, packet capture requires access to BPF devices
    // Try to open a BPF device to check permissions
    let bpf_devices = (0..10)
        .map(|i| format!("/dev/bpf{}", i))
        .collect::<Vec<_>>();

    let mut can_access_bpf = false;
    for bpf_device in &bpf_devices {
        if fs::metadata(bpf_device).is_ok() {
            debug!("Checking BPF device: {}", bpf_device);

            // Try to actually open it (this is the real test)
            if std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(bpf_device)
                .is_ok()
            {
                can_access_bpf = true;
                debug!("Successfully opened BPF device: {}", bpf_device);
                break;
            }
        }
    }

    if can_access_bpf {
        return Ok(PrivilegeStatus::sufficient());
    }

    // No BPF access - build error message
    let missing = vec!["Access to BPF devices (/dev/bpf*)".to_string()];

    let instructions = vec![
        "Run with sudo: sudo rustnet".to_string(),
        "Change BPF device permissions (temporary):\n  \
         sudo chmod o+rw /dev/bpf*"
            .to_string(),
        "Install BPF permission helper (persistent):\n  \
         brew install wireshark && sudo /usr/local/bin/install-bpf"
            .to_string(),
    ];

    Ok(PrivilegeStatus::insufficient(missing, instructions))
}

/// Check if running as root user on macOS
#[cfg(target_os = "macos")]
fn is_root_user() -> Result<bool> {
    use std::process::Command;

    // Use `id -u` command to get effective UID safely
    let output = Command::new("id")
        .arg("-u")
        .output()
        .map_err(|e| anyhow!("Failed to run 'id -u': {}", e))?;

    if !output.status.success() {
        return Err(anyhow!("'id -u' command failed"));
    }

    let uid_str = String::from_utf8_lossy(&output.stdout);
    let uid = uid_str
        .trim()
        .parse::<u32>()
        .map_err(|e| anyhow!("Failed to parse UID: {}", e))?;

    Ok(uid == 0)
}

#[cfg(target_os = "windows")]
fn check_windows_privileges() -> Result<PrivilegeStatus> {
    use pcap::Device;

    debug!("Checking Windows privileges by attempting to list network interfaces");

    // Try to list network devices - this will fail if we don't have sufficient privileges
    match Device::list() {
        Ok(devices) => {
            info!(
                "Successfully listed {} network devices - privileges sufficient",
                devices.len()
            );
            Ok(PrivilegeStatus::sufficient())
        }
        Err(e) => {
            debug!("Failed to list network devices: {}", e);

            // Check if the error indicates a permissions issue
            let error_str = e.to_string().to_lowercase();
            if error_str.contains("access")
                || error_str.contains("denied")
                || error_str.contains("permission")
            {
                let missing = vec!["Administrator privileges".to_string()];

                let instructions = vec![
                    "Run as Administrator: Right-click the terminal and select 'Run as Administrator'".to_string(),
                    "If using Npcap: Ensure it was installed with 'WinPcap API-compatible Mode' enabled".to_string(),
                ];

                Ok(PrivilegeStatus::insufficient(missing, instructions))
            } else {
                // Some other error - assume it's not a privilege issue
                warn!(
                    "Network device enumeration failed but error doesn't indicate privilege issue: {}",
                    e
                );
                Ok(PrivilegeStatus::sufficient())
            }
        }
    }
}

#[cfg(target_os = "freebsd")]
fn check_freebsd_privileges() -> Result<PrivilegeStatus> {
    use std::fs;

    // Check if running as root by reading effective UID from process
    let is_root = is_root_user()?;

    if is_root {
        info!("Running as root - all privileges available");
        return Ok(PrivilegeStatus::sufficient());
    }

    debug!("Not running as root, checking BPF device permissions");

    // On FreeBSD, packet capture requires access to BPF devices
    // Try to open a BPF device to check permissions
    let bpf_devices = (0..10)
        .map(|i| format!("/dev/bpf{}", i))
        .collect::<Vec<_>>();

    let mut can_access_bpf = false;
    for bpf_device in &bpf_devices {
        if fs::metadata(bpf_device).is_ok() {
            debug!("Checking BPF device: {}", bpf_device);

            // Try to actually open it (this is the real test)
            if std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(bpf_device)
                .is_ok()
            {
                can_access_bpf = true;
                debug!("Successfully opened BPF device: {}", bpf_device);
                break;
            }
        }
    }

    if can_access_bpf {
        return Ok(PrivilegeStatus::sufficient());
    }

    // No BPF access - build error message
    let missing = vec!["Access to BPF devices (/dev/bpf*)".to_string()];

    let instructions = vec![
        "Run with sudo: sudo rustnet".to_string(),
        "Add your user to the bpf group:\n  \
         sudo pw groupmod bpf -m $(whoami)\n  \
         Then logout and login again"
            .to_string(),
        "Change BPF device permissions (temporary):\n  \
         sudo chmod o+rw /dev/bpf*"
            .to_string(),
    ];

    Ok(PrivilegeStatus::insufficient(missing, instructions))
}

/// Check if running as root user on FreeBSD
#[cfg(target_os = "freebsd")]
fn is_root_user() -> Result<bool> {
    use std::process::Command;

    // Use `id -u` command to get effective UID safely
    let output = Command::new("id")
        .arg("-u")
        .output()
        .map_err(|e| anyhow!("Failed to run 'id -u': {}", e))?;

    if !output.status.success() {
        return Err(anyhow!("'id -u' command failed"));
    }

    let uid_str = String::from_utf8_lossy(&output.stdout);
    let uid = uid_str
        .trim()
        .parse::<u32>()
        .map_err(|e| anyhow!("Failed to parse UID: {}", e))?;

    Ok(uid == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privilege_status_error_message() {
        let status = PrivilegeStatus::insufficient(
            vec!["CAP_NET_RAW".to_string()],
            vec!["Run with sudo".to_string()],
        );

        let msg = status.error_message();
        assert!(msg.contains("Insufficient privileges"));
        assert!(msg.contains("CAP_NET_RAW"));
        assert!(msg.contains("Run with sudo"));
    }

    #[test]
    fn test_sufficient_privileges() {
        let status = PrivilegeStatus::sufficient();
        assert!(status.has_privileges);
        assert!(status.error_message().is_empty());
    }
}
