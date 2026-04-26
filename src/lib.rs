//! # RustNet Monitor
//!
//! A cross-platform real-time network monitoring tool with a terminal user
//! interface (TUI), deep packet inspection (DPI), per-connection process
//! attribution, and protocol-aware connection lifecycle tracking. RustNet
//! sits between simple connection listers (`netstat`, `ss`) and full packet
//! analyzers (`Wireshark`, `tcpdump`): it shows which process owns each
//! connection, with live bandwidth and protocol state, and runs over SSH.
//!
//! ## Capabilities
//!
//! - **Live connection table** for TCP, UDP, ICMP, and ARP, with detailed
//!   state tracking (TCP `ESTABLISHED`/`SYN_SENT`/`TIME_WAIT`, QUIC
//!   `INITIAL`/`HANDSHAKE`/`CONNECTED`, DNS, SSH, and activity-based UDP).
//! - **Deep packet inspection** for HTTP, HTTPS/TLS with SNI extraction,
//!   DNS, SSH, QUIC, NTP, mDNS, LLMNR, DHCP, SNMP, SSDP, and NetBIOS.
//! - **TCP analytics**: retransmissions, out-of-order packets, and fast
//!   retransmit detection, both per-connection and aggregate.
//! - **Process attribution** via procfs on Linux, native APIs on macOS,
//!   Windows, and FreeBSD, and an optional eBPF fast path on Linux.
//! - **GeoIP** lookups against MaxMind GeoLite2 databases.
//! - **Reverse DNS** with background async resolution and caching.
//! - **Vim/fzf-style filtering** (`port:`, `src:`, `dst:`, `sni:`,
//!   `process:`, `state:`, `proto:`, regex via `(?i)…`).
//! - **Security sandboxing** with Linux Landlock (5.13+) and macOS
//!   Seatbelt to restrict filesystem and network access at runtime.
//! - **PCAP export** with process metadata for offline analysis.
//!
//! ## Technology stack
//!
//! - `ratatui` + `crossterm` for the terminal user interface.
//! - `pcap` (libpcap / Npcap) for cross-platform packet capture.
//! - `libbpf-rs` for the optional Linux eBPF process-attribution fast path.
//! - `dashmap` and `crossbeam` channels for lock-free, multi-threaded
//!   connection state and packet pipelines.
//! - `ring` and `aes` for TLS SNI parsing and QUIC Initial decryption.
//! - `maxminddb` for GeoLite2 country/city lookups.
//! - `landlock` and `caps` for Linux capability-based sandboxing;
//!   macOS Seatbelt is invoked via `sandbox_init` directly.
//!
//! ## Modules
//!
//! - [`app`] — application orchestration, packet pipeline, and shared
//!   state.
//! - [`config`] — command-line and runtime configuration.
//! - [`filter`] — vim/fzf-style connection filter parser and matcher.
//! - [`network`] — packet capture, parsers, DPI, DNS, GeoIP, interface
//!   stats, and platform-specific process lookup.
//! - [`ui`] — ratatui rendering, tabs, tables, and keyboard handling.
//!
//! ## Binary vs. library
//!
//! `rustnet-monitor` is primarily distributed as a binary (`rustnet`).
//! The library surface exposed here is unstable and intended for internal
//! use; install via `cargo install rustnet-monitor` or one of the system
//! package managers listed in the README.

pub mod app;
pub mod config;
pub mod filter;
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

        // Open the process token
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle).is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut return_length = 0u32;

        // Get the elevation information
        let result = GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );

        // Close the token handle
        let _ = windows::Win32::Foundation::CloseHandle(token_handle);

        if result.is_err() {
            return false;
        }

        elevation.TokenIsElevated != 0
    }
}
