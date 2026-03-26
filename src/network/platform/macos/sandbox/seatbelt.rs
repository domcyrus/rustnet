//! macOS Seatbelt sandboxing implementation
//!
//! Uses the macOS `sandbox_init_with_parameters` private API (Seatbelt) to
//! restrict the process after initialization. This is analogous to Linux
//! Landlock: existing file descriptors (BPF devices) remain usable, and only
//! future operations are restricted.
//!
//! # What We Restrict
//!
//! - Network: Outbound TCP/UDP connections (RustNet is passive)
//! - Filesystem writes: Only allowed to configured log and PCAP paths
//! - Filesystem writes: All user home directories blocked (/Users, /var/root)
//!
//! # Profile Strategy
//!
//! Uses allow-default with targeted denies. A deny-default profile would
//! require whitelisting all system libraries, Mach ports, locale data, etc.
//! Allow-default provides meaningful security against the primary threats
//! (outbound exfiltration, credential theft) without operational risk.
//!
//! Note: `home-subpath` is not available outside the App Sandbox context.
//! We use hardcoded paths for macOS user home directories instead.
//! SBPL specificity rules ensure that the explicit allow rules for log/PCAP
//! paths override the broader deny rules for /Users and /var/root.

use anyhow::{Context, Result, bail};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::path::PathBuf;

use super::SandboxConfig;

/// Result of Seatbelt application
pub struct SeatbeltResult {
    /// Whether the sandbox was applied
    pub applied: bool,
    /// Human-readable message
    pub message: String,
    /// Whether filesystem write restrictions were applied
    pub fs_restricted: bool,
    /// Whether outbound network connections were blocked
    pub net_blocked: bool,
}

// macOS Seatbelt private API — stable since macOS 10.5, present through macOS 15+
// Part of libSystem.B.dylib which is linked by default on all macOS targets.
// flags = 0 means an inline SBPL profile string (not a named built-in profile).
unsafe extern "C" {
    fn sandbox_init_with_parameters(
        profile: *const c_char,
        flags: u64,
        parameters: *const *const c_char,
        errorbuf: *mut *mut c_char,
    ) -> c_int;

    fn sandbox_free_error(errorbuf: *mut c_char);
}

/// Parameter keys used in the SBPL profile via `(param "KEY")` substitution
const PARAM_LOG_DIR: &str = "LOG_DIR";
const PARAM_JSON_LOG_PATH: &str = "JSON_LOG_PATH";
const PARAM_PCAP_PATH: &str = "PCAP_PATH";
const PARAM_PCAP_JSONL_PATH: &str = "PCAP_JSONL_PATH";
const PARAM_GEOIP_PATH_1: &str = "GEOIP_PATH_1";
const PARAM_GEOIP_PATH_2: &str = "GEOIP_PATH_2";
const PARAM_GEOIP_PATH_3: &str = "GEOIP_PATH_3";

/// Base SBPL profile: allow-default with filesystem and process restrictions.
///
/// Note: `home-subpath` is not used because it is only valid inside the
/// App Sandbox context and fails with `sandbox_init_with_parameters`.
/// Instead we hardcode the macOS-specific home directory prefixes.
const SBPL_PROFILE_BASE: &str = r#"(version 1)

;; Allow-default: everything permitted unless explicitly denied
(allow default)

;; Block reads from user home directories
;; Prevents reading SSH keys, AWS credentials, browser profiles, cookies, etc.
;; if a vulnerability in DPI/packet parsing is exploited.
;; SBPL specificity: more specific allow rules for GeoIP paths below
;; will take precedence over these broader deny rules.
(deny file-read-data
    (subpath "/Users")
    (subpath "/var/root"))

;; Block writes to user home directories
;; Regular user homes on macOS are under /Users; root's home is /var/root.
;; Protects SSH keys, AWS credentials, GPG keys, browser profiles, etc.
;; SBPL specificity: more specific allow rules for log/PCAP paths below
;; will take precedence over these broader deny rules.
(deny file-write*
    (subpath "/Users")
    (subpath "/var/root"))

;; Allow reads from configured GeoIP database paths
;; These may reside under /Users (e.g., ~/.local/share/GeoIP)
(allow file-read-data
    (literal (param "GEOIP_PATH_1"))
    (subpath (param "GEOIP_PATH_1"))
    (literal (param "GEOIP_PATH_2"))
    (subpath (param "GEOIP_PATH_2"))
    (literal (param "GEOIP_PATH_3"))
    (subpath (param "GEOIP_PATH_3")))

;; Allow writes to configured output paths (log files, PCAP exports)
;; These use more specific subpaths that take precedence over the deny rules
;; above when the log/PCAP paths happen to be inside a user home directory.
(allow file-write*
    (literal (param "LOG_DIR"))
    (subpath (param "LOG_DIR"))
    (literal (param "JSON_LOG_PATH"))
    (literal (param "PCAP_PATH"))
    (literal (param "PCAP_JSONL_PATH")))

;; Block execution of all binaries except lsof
;; Prevents shell escapes (/bin/sh, /usr/bin/curl, etc.) if code execution
;; is achieved through a DPI parsing vulnerability.
(deny process-exec)
(allow process-exec
    (literal "/usr/sbin/lsof"))
"#;

/// Network deny SBPL section, appended when `block_network` is true.
///
/// Blocks outbound TCP/UDP connections. Unix domain sockets are explicitly
/// allowed for Mach IPC. Already-open BPF/PKTAP file descriptors are unaffected.
const SBPL_NETWORK_DENY: &str = r#"
;; Block outbound TCP and UDP connections
;; RustNet only reads from BPF/PKTAP — already-open fds are unaffected
(deny network-outbound
    (remote tcp)
    (remote udp))

;; Allow Unix domain socket IPC (required for threading, Mach port bridge)
(allow network-outbound
    (remote unix-socket))
"#;

/// Build the complete SBPL profile string based on configuration.
fn build_sbpl_profile(block_network: bool) -> String {
    if block_network {
        format!("{}{}", SBPL_PROFILE_BASE, SBPL_NETWORK_DENY)
    } else {
        SBPL_PROFILE_BASE.to_string()
    }
}

/// Apply Seatbelt restrictions based on configuration.
///
/// The caller (`apply_sandbox` in mod.rs) handles the `Disabled` mode check,
/// so this function assumes sandboxing is requested.
pub fn apply_seatbelt(config: &SandboxConfig) -> Result<SeatbeltResult> {
    let profile = build_sbpl_profile(config.block_network);
    let profile_cstr = CString::new(profile).context("Profile contains null byte")?;
    let params = build_parameters(config).context("Failed to build sandbox parameters")?;

    // Build null-terminated array of *const c_char for the FFI call.
    // params must outlive ptrs.
    let ptrs: Vec<*const c_char> = params.iter().map(|s| s.as_ptr()).collect();
    let mut ptrs_with_null = ptrs;
    ptrs_with_null.push(std::ptr::null());

    let mut errorbuf: *mut c_char = std::ptr::null_mut();

    // SAFETY:
    // - profile_cstr is a valid null-terminated C string held on the stack
    // - ptrs_with_null is a valid null-terminated array of valid C strings
    //   (params lives at least as long as ptrs_with_null)
    // - errorbuf is a valid out-pointer; we free it with sandbox_free_error
    let ret = unsafe {
        sandbox_init_with_parameters(
            profile_cstr.as_ptr(),
            0,
            ptrs_with_null.as_ptr(),
            &mut errorbuf,
        )
    };

    // Always free the error buffer if non-null (may contain a warning on success)
    let error_message = if !errorbuf.is_null() {
        let msg = unsafe { CStr::from_ptr(errorbuf) }
            .to_string_lossy()
            .into_owned();
        unsafe { sandbox_free_error(errorbuf) };
        Some(msg)
    } else {
        None
    };

    if ret != 0 {
        let detail = error_message.unwrap_or_else(|| "unknown error".to_string());
        bail!("sandbox_init_with_parameters failed ({}): {}", ret, detail);
    }

    if let Some(warn) = &error_message {
        log::warn!("Seatbelt: warning from sandbox_init: {}", warn);
    }

    log::info!(
        "Seatbelt sandbox applied (fs_restricted=true, net_blocked={})",
        config.block_network
    );

    Ok(SeatbeltResult {
        applied: true,
        message: format!(
            "Seatbelt applied (fs restricted, net {})",
            if config.block_network {
                "blocked"
            } else {
                "allowed"
            }
        ),
        fs_restricted: true,
        net_blocked: config.block_network,
    })
}

/// Resolve a path to a canonical absolute path for use in SBPL rules.
///
/// Seatbelt evaluates paths against their canonical (symlink-resolved) form.
/// On macOS, `/tmp` is a symlink to `/private/tmp`, so non-canonical paths
/// would silently fail to match. We use `std::fs::canonicalize()` when possible,
/// falling back to simple absolute resolution if the path doesn't exist yet.
fn resolve_to_absolute(path: &str) -> String {
    let p = PathBuf::from(path);

    // Try full canonicalization first (resolves symlinks)
    if let Ok(canonical) = std::fs::canonicalize(&p) {
        return canonical.to_string_lossy().into_owned();
    }

    // Path doesn't exist yet — make it absolute without symlink resolution
    if p.is_absolute() {
        path.to_string()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(&p).to_string_lossy().into_owned())
            .unwrap_or_else(|_| path.to_string())
    }
}

/// Escape a path string for safe embedding in an SBPL profile.
///
/// SBPL uses S-expression syntax where `"` and `\` have special meaning.
/// While rare in filesystem paths, a crafted path could break SBPL parsing.
fn escape_sbpl_path(path: &str) -> String {
    path.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Build the flat key/value parameter array for `sandbox_init_with_parameters`.
///
/// Unused paths default to `/dev/null` (a safe sentinel that avoids empty-string
/// parse issues and is always present on macOS).
/// Relative paths are resolved to absolute paths before being passed.
fn build_parameters(config: &SandboxConfig) -> Result<Vec<CString>> {
    let devnull = CString::new("/dev/null").unwrap();

    // Helper: resolve path and escape for SBPL safety
    let resolve = |p: &str| escape_sbpl_path(&resolve_to_absolute(p));

    let log_dir = config
        .log_dir
        .as_deref()
        .map(resolve)
        .map(CString::new)
        .transpose()
        .context("log_dir contains null byte")?
        .unwrap_or_else(|| devnull.clone());

    let json_log = config
        .json_log_path
        .as_deref()
        .map(resolve)
        .map(CString::new)
        .transpose()
        .context("json_log_path contains null byte")?
        .unwrap_or_else(|| devnull.clone());

    let pcap = config
        .pcap_export_path
        .as_deref()
        .map(resolve)
        .map(CString::new)
        .transpose()
        .context("pcap_export_path contains null byte")?
        .unwrap_or_else(|| devnull.clone());

    let pcap_jsonl_str = config
        .pcap_export_path
        .as_deref()
        .map(|p| format!("{}.connections.jsonl", resolve(p)));
    let pcap_jsonl = pcap_jsonl_str
        .as_deref()
        .map(CString::new)
        .transpose()
        .context("pcap_jsonl path contains null byte")?
        .unwrap_or_else(|| devnull.clone());

    // GeoIP database paths (up to 3 user-specified or auto-discovered paths)
    let geoip_paths: Vec<CString> = config
        .geoip_paths
        .iter()
        .take(3)
        .map(|p| resolve_to_absolute(p))
        .map(CString::new)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("geoip path contains null byte")?;
    let geoip_1 = geoip_paths
        .first()
        .cloned()
        .unwrap_or_else(|| devnull.clone());
    let geoip_2 = geoip_paths
        .get(1)
        .cloned()
        .unwrap_or_else(|| devnull.clone());
    let geoip_3 = geoip_paths
        .get(2)
        .cloned()
        .unwrap_or_else(|| devnull.clone());

    // Flat key/value pairs: [KEY0, VAL0, KEY1, VAL1, ...]
    // The null terminator is added by the caller just before the FFI call.
    Ok(vec![
        CString::new(PARAM_LOG_DIR).unwrap(),
        log_dir,
        CString::new(PARAM_JSON_LOG_PATH).unwrap(),
        json_log,
        CString::new(PARAM_PCAP_PATH).unwrap(),
        pcap,
        CString::new(PARAM_PCAP_JSONL_PATH).unwrap(),
        pcap_jsonl,
        CString::new(PARAM_GEOIP_PATH_1).unwrap(),
        geoip_1,
        CString::new(PARAM_GEOIP_PATH_2).unwrap(),
        geoip_2,
        CString::new(PARAM_GEOIP_PATH_3).unwrap(),
        geoip_3,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::platform::sandbox::SandboxMode;

    #[test]
    fn test_build_parameters_uses_devnull_for_none() {
        let config = SandboxConfig {
            mode: SandboxMode::BestEffort,
            block_network: true,
            log_dir: None,
            json_log_path: None,
            pcap_export_path: None,
            geoip_paths: vec![],
        };
        let params = build_parameters(&config).unwrap();
        // Values at odd indices should all be /dev/null
        assert_eq!(params[1].to_str().unwrap(), "/dev/null");
        assert_eq!(params[3].to_str().unwrap(), "/dev/null");
        assert_eq!(params[5].to_str().unwrap(), "/dev/null");
        assert_eq!(params[7].to_str().unwrap(), "/dev/null");
        // GeoIP paths should also be /dev/null
        assert_eq!(params[9].to_str().unwrap(), "/dev/null");
        assert_eq!(params[11].to_str().unwrap(), "/dev/null");
        assert_eq!(params[13].to_str().unwrap(), "/dev/null");
    }

    #[test]
    fn test_build_parameters_with_absolute_paths() {
        let config = SandboxConfig {
            mode: SandboxMode::BestEffort,
            block_network: true,
            log_dir: Some("/tmp/rustnet/logs".to_string()),
            json_log_path: Some("/tmp/rustnet/events.jsonl".to_string()),
            pcap_export_path: Some("/tmp/rustnet/capture.pcap".to_string()),
            geoip_paths: vec![],
        };
        let params = build_parameters(&config).unwrap();
        // Keys
        assert_eq!(params[0].to_str().unwrap(), PARAM_LOG_DIR);
        assert_eq!(params[2].to_str().unwrap(), PARAM_JSON_LOG_PATH);
        assert_eq!(params[4].to_str().unwrap(), PARAM_PCAP_PATH);
        assert_eq!(params[6].to_str().unwrap(), PARAM_PCAP_JSONL_PATH);
        // Values
        assert_eq!(params[1].to_str().unwrap(), "/tmp/rustnet/logs");
        assert_eq!(params[3].to_str().unwrap(), "/tmp/rustnet/events.jsonl");
        assert_eq!(params[5].to_str().unwrap(), "/tmp/rustnet/capture.pcap");
        assert_eq!(
            params[7].to_str().unwrap(),
            "/tmp/rustnet/capture.pcap.connections.jsonl"
        );
    }

    #[test]
    fn test_build_parameters_with_geoip_paths() {
        let config = SandboxConfig {
            mode: SandboxMode::BestEffort,
            block_network: true,
            log_dir: None,
            json_log_path: None,
            pcap_export_path: None,
            geoip_paths: vec![
                "/usr/share/GeoIP".to_string(),
                "/opt/homebrew/share/GeoIP".to_string(),
            ],
        };
        let params = build_parameters(&config).unwrap();
        assert_eq!(params[8].to_str().unwrap(), PARAM_GEOIP_PATH_1);
        assert_eq!(params[9].to_str().unwrap(), "/usr/share/GeoIP");
        assert_eq!(params[10].to_str().unwrap(), PARAM_GEOIP_PATH_2);
        assert_eq!(params[11].to_str().unwrap(), "/opt/homebrew/share/GeoIP");
        // Third slot defaults to /dev/null
        assert_eq!(params[12].to_str().unwrap(), PARAM_GEOIP_PATH_3);
        assert_eq!(params[13].to_str().unwrap(), "/dev/null");
    }

    #[test]
    fn test_relative_path_is_resolved_to_absolute() {
        let abs = resolve_to_absolute("logs");
        assert!(abs.starts_with('/'), "Expected absolute path, got: {}", abs);
        assert!(
            abs.ends_with("/logs"),
            "Expected path ending with /logs, got: {}",
            abs
        );
    }

    #[test]
    fn test_absolute_nonexistent_path_is_unchanged() {
        // /tmp/foo doesn't exist, so canonicalize fails and we fall back to returning it as-is
        assert_eq!(resolve_to_absolute("/tmp/foo"), "/tmp/foo");
    }

    #[test]
    fn test_symlink_resolved_by_canonicalize() {
        // On macOS, /tmp is a symlink to /private/tmp.
        // resolve_to_absolute should canonicalize existing paths,
        // ensuring Seatbelt rules match the real filesystem location.
        let resolved = resolve_to_absolute("/tmp");
        assert_eq!(
            resolved, "/private/tmp",
            "Expected /tmp to resolve to /private/tmp via canonicalize, got: {}",
            resolved
        );
    }

    #[test]
    fn test_escape_sbpl_path_no_special_chars() {
        assert_eq!(escape_sbpl_path("/tmp/rustnet/logs"), "/tmp/rustnet/logs");
    }

    #[test]
    fn test_escape_sbpl_path_with_quotes_and_backslashes() {
        assert_eq!(
            escape_sbpl_path(r#"/tmp/path"with\special"#),
            r#"/tmp/path\"with\\special"#
        );
    }

    #[test]
    fn test_profile_variants_are_valid_cstrings() {
        CString::new(SBPL_PROFILE_BASE).expect("SBPL_PROFILE_BASE must not contain null bytes");
        CString::new(build_sbpl_profile(true)).expect("full profile must not contain null bytes");
        CString::new(build_sbpl_profile(false))
            .expect("base-only profile must not contain null bytes");
    }

    #[test]
    fn test_profile_includes_network_deny_when_block_network_true() {
        let profile = build_sbpl_profile(true);
        assert!(
            profile.contains("deny network-outbound"),
            "Expected network deny in profile when block_network=true"
        );
    }

    #[test]
    fn test_profile_excludes_network_deny_when_block_network_false() {
        let profile = build_sbpl_profile(false);
        assert!(
            !profile.contains("deny network-outbound"),
            "Expected no network deny in profile when block_network=false"
        );
    }

    #[test]
    fn test_profile_includes_file_read_deny() {
        let profile = build_sbpl_profile(false);
        assert!(
            profile.contains("deny file-read-data"),
            "Expected file-read-data deny in profile"
        );
        assert!(
            profile.contains(r#"(subpath "/Users")"#),
            "Expected /Users in file-read-data deny"
        );
        assert!(
            profile.contains(r#"(subpath "/var/root")"#),
            "Expected /var/root in file-read-data deny"
        );
    }

    #[test]
    fn test_profile_includes_process_exec_deny() {
        let profile = build_sbpl_profile(false);
        assert!(
            profile.contains("(deny process-exec)"),
            "Expected process-exec deny in profile"
        );
        assert!(
            profile.contains(r#"(allow process-exec"#),
            "Expected process-exec allow for lsof"
        );
        assert!(
            profile.contains(r#"(literal "/usr/sbin/lsof")"#),
            "Expected lsof in process-exec allow"
        );
    }

    #[test]
    fn test_profile_includes_geoip_read_allow() {
        let profile = build_sbpl_profile(false);
        assert!(
            profile.contains(r#"(param "GEOIP_PATH_1")"#),
            "Expected GEOIP_PATH_1 parameter in profile"
        );
        assert!(
            profile.contains(r#"(param "GEOIP_PATH_2")"#),
            "Expected GEOIP_PATH_2 parameter in profile"
        );
        assert!(
            profile.contains(r#"(param "GEOIP_PATH_3")"#),
            "Expected GEOIP_PATH_3 parameter in profile"
        );
    }
}
