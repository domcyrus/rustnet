//! Network privilege detection for packet capture
//!
//! This module checks if the application has sufficient privileges to capture
//! network packets on different platforms (Linux, macOS, Windows).

use anyhow::{anyhow, Result};
use log::{debug, info};
#[cfg(any(
    not(any(target_os = "linux", target_os = "macos", target_os = "windows")),
    target_os = "windows",
    target_os = "linux"
))]
use log::warn;

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

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
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

    // Required capabilities for packet capture
    const CAP_NET_RAW: u64 = 13; // For packet capture
    const CAP_NET_ADMIN: u64 = 12; // For network administration

    let mut missing = Vec::new();
    let mut has_net_raw = false;
    let mut has_net_admin = false;

    // Check CAP_NET_RAW
    if (cap_value & (1u64 << CAP_NET_RAW)) != 0 {
        debug!("CAP_NET_RAW: present");
        has_net_raw = true;
    } else {
        debug!("CAP_NET_RAW: missing");
        missing.push("CAP_NET_RAW capability".to_string());
    }

    // Check CAP_NET_ADMIN
    if (cap_value & (1u64 << CAP_NET_ADMIN)) != 0 {
        debug!("CAP_NET_ADMIN: present");
        has_net_admin = true;
    } else {
        debug!("CAP_NET_ADMIN: missing");
        missing.push("CAP_NET_ADMIN capability".to_string());
    }

    // Need at least CAP_NET_RAW for basic packet capture
    if has_net_raw {
        if !has_net_admin {
            warn!("CAP_NET_ADMIN missing - some features may not work");
        }
        return Ok(PrivilegeStatus::sufficient());
    }

    // Build instructions for gaining privileges
    let mut instructions = vec![
        "Run with sudo: sudo rustnet".to_string(),
        "Set capabilities: sudo setcap cap_net_raw,cap_net_admin=eip $(which rustnet)".to_string(),
    ];

    // Add Docker-specific instructions if it looks like we're in a container
    if is_running_in_container() {
        instructions.push(
            "If running in Docker, add these flags:\n  \
             --cap-add=NET_RAW --cap-add=NET_ADMIN --cap-add=BPF --cap-add=PERFMON --cap-add=SYS_PTRACE \
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
    // On Windows, packet capture typically requires administrator privileges
    // We check if running as administrator

    use std::ptr;

    debug!("Checking Windows administrator status");

    // Check if process is elevated
    let is_admin = unsafe {
        let mut token_handle: winapi::um::winnt::HANDLE = ptr::null_mut();

        // Open process token
        if winapi::um::processthreadsapi::OpenProcessToken(
            winapi::um::processthreadsapi::GetCurrentProcess(),
            winapi::um::winnt::TOKEN_QUERY,
            &mut token_handle,
        ) == 0
        {
            warn!("Failed to open process token");
            return false;
        }

        // Check token elevation
        let mut elevation = winapi::um::winnt::TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut return_length = 0u32;

        let result = winapi::um::securitybaseapi::GetTokenInformation(
            token_handle,
            winapi::um::winnt::TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<winapi::um::winnt::TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );

        winapi::um::handleapi::CloseHandle(token_handle);

        result != 0 && elevation.TokenIsElevated != 0
    };

    if is_admin {
        info!("Running as administrator - privileges available");
        return Ok(PrivilegeStatus::sufficient());
    }

    let missing = vec!["Administrator privileges".to_string()];

    let instructions = vec![
        "Right-click rustnet.exe and select 'Run as administrator'".to_string(),
        "Or run from an elevated command prompt/PowerShell".to_string(),
    ];

    Ok(PrivilegeStatus::insufficient(missing, instructions))
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
