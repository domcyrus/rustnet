//! # RustNet Monitor
//!
//! A cross-platform real-time network monitoring tool with a terminal user
//! interface, deep packet inspection, per-connection process attribution,
//! and protocol-aware connection lifecycle tracking. It sits between
//! connection listers (`netstat`, `ss`) and packet analyzers (`Wireshark`,
//! `tcpdump`): it shows which process owns each connection, with live
//! bandwidth and protocol state, and runs over SSH.
//!
//! [`app`] holds orchestration, the packet pipeline, and shared state;
//! [`network`] holds capture, parsers, DPI, DNS, GeoIP, interface stats, and
//! platform process lookup; [`ui`] holds the ratatui rendering and keyboard
//! handling.
//!
//! The library surface is unstable and intended for internal use; the
//! supported product is the `rustnet` binary.

pub mod app;
pub mod cli;
pub mod config;
pub(crate) mod export;
pub(crate) mod filter;
pub mod network;
pub mod ui;

/// Check if the current process is running with Administrator privileges (Windows only)
#[cfg(target_os = "windows")]
pub fn is_admin() -> bool {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token_handle = HANDLE::default();

        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle).is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut return_length = 0u32;

        let result = GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );

        let _ = windows::Win32::Foundation::CloseHandle(token_handle);

        if result.is_err() {
            return false;
        }

        elevation.TokenIsElevated != 0
    }
}
