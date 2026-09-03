//! macOS Seatbelt sandboxing implementation
//!
//! Uses the macOS `sandbox_init_with_parameters` private API (Seatbelt) to
//! restrict the process after initialization. This is analogous to Linux
//! Landlock: existing file descriptors (BPF devices) remain usable, and only
//! future operations are restricted.
//!
//! # What We Restrict
//!
//! - Network: Outbound TCP/UDP connections, optionally allowing DNS traffic
//!   only to destination port 53 (RustNet is otherwise passive)
//! - Filesystem writes: Only allowed to configured write paths
//! - Filesystem writes: All user home directories blocked (/Users, /var/root)
//! - Filesystem reads: User home directories and system credential stores
//!   (keychains, dslocal account database, SSH host keys) blocked, except
//!   configured read paths (e.g. GeoIP databases under a user home)
//!
//! # Profile Strategy
//!
//! Uses allow-default with targeted denies. A deny-default profile would
//! require whitelisting all system libraries, Mach ports, locale data, etc.
//! Allow-default provides meaningful security against the primary threats
//! (outbound exfiltration, credential theft) without operational risk.
//!
//! The allow rules for the configured read/write paths are generated into
//! the profile (escaped, symlink-resolved); SBPL specificity rules ensure
//! they override the broader deny rules for /Users and /var/root.
//!
//! Note: `home-subpath` is not available outside the App Sandbox context.
//! We use hardcoded paths for macOS user home directories instead.

use anyhow::{Context, Result, bail};
use std::ffi::{CStr, CString};
use std::fmt::Write as _;
use std::os::raw::{c_char, c_int};
use std::path::Path;

use crate::SandboxConfig;

/// Result of Seatbelt application
pub(super) struct SeatbeltResult {
    /// Whether the sandbox was applied
    pub applied: bool,
    /// Human-readable message
    pub message: String,
    /// Whether filesystem write restrictions were applied
    pub fs_restricted: bool,
    /// Whether outbound network connections were restricted
    pub net_restricted: bool,
}

// macOS Seatbelt private API, stable since macOS 10.5 and present through macOS 15+.
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

/// Base SBPL profile: allow-default with filesystem and process restrictions.
const SBPL_PROFILE_BASE: &str = r#"(version 1)

;; Allow-default: everything permitted unless explicitly denied
(allow default)

;; Block reads from user home directories
;; Prevents reading SSH keys, AWS credentials, browser profiles, cookies, etc.
;; if a vulnerability in DPI/packet parsing is exploited.
;; SBPL specificity: more specific allow rules for the configured read paths
;; below will take precedence over these broader deny rules.
(deny file-read-data
    (subpath "/Users")
    (subpath "/var/root"))

;; Block reads of system credential stores outside the user homes above.
;; RustNet never needs these, so denying them limits credential theft if a
;; DPI/packet-parsing vulnerability is exploited. This matters in particular
;; when running as root: Seatbelt is enforced regardless of uid, so it covers
;; secrets that DAC file permissions would otherwise expose to a root process.
;; Both the symlink and resolved forms are listed because macOS resolves
;; /etc -> /private/etc and /var -> /private/var.
(deny file-read*
    (subpath "/Library/Keychains")
    (subpath "/private/var/db/dslocal")
    (subpath "/var/db/dslocal")
    (subpath "/private/etc/ssh")
    (subpath "/etc/ssh"))

;; Block writes to user home directories
;; Regular user homes on macOS are under /Users; root's home is /var/root.
;; Protects SSH keys, AWS credentials, GPG keys, browser profiles, etc.
;; SBPL specificity: more specific allow rules for the configured write paths
;; below will take precedence over these broader deny rules.
(deny file-write*
    (subpath "/Users")
    (subpath "/var/root"))
"#;

/// Trailing SBPL section: exec deny (independent of configured paths).
const SBPL_PROFILE_EXEC: &str = r#"
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
;; RustNet only reads from BPF/PKTAP; already-open fds are unaffected
(deny network-outbound
    (remote tcp)
    (remote udp))

;; Allow Unix domain socket IPC (required for threading, Mach port bridge)
(allow network-outbound
    (remote unix-socket))
"#;

/// Narrow DNS exception, appended after the broader network deny.
///
/// SBPL chooses the more specific port rule, so TCP and UDP DNS traffic is
/// allowed while outbound traffic to every other destination port stays denied.
const SBPL_DNS_ALLOW: &str = r#"
;; Allow DNS resolution while retaining the broader outbound deny
(allow network-outbound
    (remote tcp "*:53")
    (remote udp "*:53"))
"#;

fn build_sbpl_network_profile(config: &SandboxConfig, allow_dns_resolution: bool) -> String {
    if !config.block_network {
        return String::new();
    }

    let mut profile = String::from(SBPL_NETWORK_DENY);
    if allow_dns_resolution {
        profile.push_str(SBPL_DNS_ALLOW);
    }
    profile
}

/// Build the complete SBPL profile string based on configuration.
///
/// The configured read paths (e.g. GeoIP databases, possibly under /Users)
/// get `literal` + `subpath` read allows; the configured write paths get
/// `literal` allows, plus `subpath` when the path is a directory (log dirs).
fn build_sbpl_profile(config: &SandboxConfig, allow_dns_resolution: bool) -> String {
    let mut profile = String::from(SBPL_PROFILE_BASE);

    let read_rules: Vec<String> = config
        .read_paths
        .iter()
        .map(|p| {
            let path = sbpl_path(p);
            format!("    (literal \"{path}\")\n    (subpath \"{path}\")")
        })
        .collect();
    if !read_rules.is_empty() {
        let _ = write!(
            profile,
            "\n;; Allow reads from configured read paths (e.g. GeoIP databases)\n\
             (allow file-read-data\n{})\n",
            read_rules.join("\n")
        );
    }

    let write_rules: Vec<String> = config
        .write_paths
        .iter()
        .map(|p| {
            let path = sbpl_path(p);
            // Directories (e.g. the logs dir) cover their subtree; files get
            // an exact-path rule.
            if Path::new(&resolve_to_absolute(p)).is_dir() {
                format!("    (literal \"{path}\")\n    (subpath \"{path}\")")
            } else {
                format!("    (literal \"{path}\")")
            }
        })
        .collect();
    if !write_rules.is_empty() {
        let _ = write!(
            profile,
            "\n;; Allow writes to configured output paths (log files, exports)\n\
             (allow file-write*\n{})\n",
            write_rules.join("\n")
        );
    }

    profile.push_str(SBPL_PROFILE_EXEC);
    profile.push_str(&build_sbpl_network_profile(config, allow_dns_resolution));
    profile
}

/// Apply Seatbelt restrictions based on configuration.
///
/// The caller (`apply` in mod.rs) handles the `Disabled` mode check, so this
/// function assumes sandboxing is requested.
pub(super) fn apply_seatbelt(
    config: &SandboxConfig,
    allow_dns_resolution: bool,
) -> Result<SeatbeltResult> {
    let profile = build_sbpl_profile(config, allow_dns_resolution);
    let profile_cstr = CString::new(profile).context("Profile contains null byte")?;

    // No (param ...) references remain in the generated profile; pass an
    // empty (null-terminated) parameter list.
    let ptrs_with_null: Vec<*const c_char> = vec![std::ptr::null()];

    let mut errorbuf: *mut c_char = std::ptr::null_mut();

    // SAFETY:
    // - profile_cstr is a valid null-terminated C string held on the stack
    // - ptrs_with_null is a valid null-terminated (empty) parameter array
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
        "Seatbelt sandbox applied (fs_restricted=true, net_restricted={})",
        config.block_network
    );

    Ok(SeatbeltResult {
        applied: true,
        message: format!(
            "Seatbelt applied (fs restricted, net {})",
            if config.block_network && allow_dns_resolution {
                "restricted (DNS allowed)"
            } else if config.block_network {
                "blocked"
            } else {
                "allowed"
            }
        ),
        fs_restricted: true,
        net_restricted: config.block_network,
    })
}

/// Resolve and escape a path for embedding in an SBPL rule.
fn sbpl_path(path: &Path) -> String {
    escape_sbpl_path(&resolve_to_absolute(path))
}

/// Resolve a path to a canonical absolute path for use in SBPL rules.
///
/// Seatbelt evaluates paths against their canonical (symlink-resolved) form.
/// On macOS, `/tmp` is a symlink to `/private/tmp`, so non-canonical paths
/// would silently fail to match. We use `std::fs::canonicalize()` when possible,
/// falling back to simple absolute resolution if the path doesn't exist yet.
fn resolve_to_absolute(path: &Path) -> String {
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return canonical.to_string_lossy().into_owned();
    }

    // Path doesn't exist yet: make it absolute without symlink resolution.
    if path.is_absolute() {
        path.to_string_lossy().into_owned()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path).to_string_lossy().into_owned())
            .unwrap_or_else(|_| path.to_string_lossy().into_owned())
    }
}

/// Escape a path string for safe embedding in an SBPL profile.
///
/// SBPL uses S-expression syntax where `"` and `\` have special meaning.
/// While rare in filesystem paths, a crafted path could break SBPL parsing.
fn escape_sbpl_path(path: &str) -> String {
    path.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SandboxMode;
    use std::path::PathBuf;

    fn config(read: &[&str], write: &[&str], block_network: bool) -> SandboxConfig {
        SandboxConfig {
            mode: SandboxMode::BestEffort,
            block_network,
            read_paths: read.iter().map(PathBuf::from).collect(),
            write_paths: write.iter().map(PathBuf::from).collect(),
            drop_uid: None,
        }
    }

    #[test]
    fn test_profile_includes_configured_paths() {
        let profile = build_sbpl_profile(
            &config(
                &["/usr/share/GeoIP"],
                &["/private/var/rustnet/events.jsonl"],
                true,
            ),
            false,
        );
        assert!(profile.contains(r#"(subpath "/usr/share/GeoIP")"#));
        assert!(profile.contains(r#"(literal "/usr/share/GeoIP")"#));
        assert!(profile.contains(r#"(literal "/private/var/rustnet/events.jsonl")"#));
        // A nonexistent file path must not get a subpath rule
        assert!(!profile.contains(r#"(subpath "/private/var/rustnet/events.jsonl")"#));
    }

    #[test]
    fn test_profile_without_paths_has_no_empty_allow_sections() {
        let profile = build_sbpl_profile(&config(&[], &[], true), false);
        assert!(!profile.contains("(allow file-read-data\n)"));
        assert!(!profile.contains("(allow file-write*\n)"));
        // The deny sections must still be present
        assert!(profile.contains("deny file-read-data"));
        assert!(profile.contains("deny file-write*"));
    }

    #[test]
    fn test_profile_denies_system_credential_stores() {
        // Both with and without network blocking, the base profile must deny
        // reads of the system credential stores rustnet never needs.
        for block_network in [true, false] {
            let profile = build_sbpl_profile(&config(&[], &[], block_network), false);
            for store in ["/Library/Keychains", "/private/var/db/dslocal", "/etc/ssh"] {
                assert!(
                    profile.contains(store),
                    "Expected credential-store deny for {store} (block_network={block_network})"
                );
            }
        }
    }

    #[test]
    fn test_profile_network_deny_toggle() {
        assert_eq!(
            build_sbpl_network_profile(&config(&[], &[], true), false),
            SBPL_NETWORK_DENY
        );
        assert_eq!(
            build_sbpl_network_profile(&config(&[], &[], false), false),
            ""
        );
    }

    #[test]
    fn test_profile_dns_network_policy_is_exact() {
        let expected = r#"
;; Block outbound TCP and UDP connections
;; RustNet only reads from BPF/PKTAP; already-open fds are unaffected
(deny network-outbound
    (remote tcp)
    (remote udp))

;; Allow Unix domain socket IPC (required for threading, Mach port bridge)
(allow network-outbound
    (remote unix-socket))

;; Allow DNS resolution while retaining the broader outbound deny
(allow network-outbound
    (remote tcp "*:53")
    (remote udp "*:53"))
"#;
        assert_eq!(
            build_sbpl_network_profile(&config(&[], &[], true), true),
            expected
        );
        assert_eq!(
            build_sbpl_network_profile(&config(&[], &[], false), true),
            ""
        );
    }

    #[test]
    fn test_profile_includes_process_exec_deny() {
        let profile = build_sbpl_profile(&config(&[], &[], false), false);
        assert!(profile.contains("(deny process-exec)"));
        assert!(profile.contains(r#"(literal "/usr/sbin/lsof")"#));
    }

    #[test]
    fn test_profile_is_valid_cstring_and_escaped() {
        let profile = build_sbpl_profile(
            &config(&[], &[r#"/private/tmp/path"with\special"#], true),
            false,
        );
        CString::new(profile.clone()).expect("profile must not contain null bytes");
        assert!(profile.contains(r#"/private/tmp/path\"with\\special"#));
    }

    #[test]
    fn test_relative_path_is_resolved_to_absolute() {
        let abs = resolve_to_absolute(Path::new("logs"));
        assert!(abs.starts_with('/'), "Expected absolute path, got: {}", abs);
        assert!(
            abs.ends_with("/logs"),
            "Expected path ending with /logs, got: {}",
            abs
        );
    }

    #[test]
    fn test_absolute_nonexistent_path_is_unchanged() {
        // Doesn't exist, so canonicalize fails and we fall back to as-is
        assert_eq!(
            resolve_to_absolute(Path::new("/tmp/rustnet-does-not-exist")),
            "/tmp/rustnet-does-not-exist"
        );
    }

    #[test]
    fn test_symlink_resolved_by_canonicalize() {
        // On macOS, /tmp is a symlink to /private/tmp.
        // resolve_to_absolute should canonicalize existing paths,
        // ensuring Seatbelt rules match the real filesystem location.
        let resolved = resolve_to_absolute(Path::new("/tmp"));
        assert_eq!(
            resolved, "/private/tmp",
            "Expected /tmp to resolve to /private/tmp via canonicalize, got: {}",
            resolved
        );
    }

    #[test]
    fn test_escape_sbpl_path_with_quotes_and_backslashes() {
        assert_eq!(escape_sbpl_path("/tmp/rustnet/logs"), "/tmp/rustnet/logs");
        assert_eq!(
            escape_sbpl_path(r#"/tmp/path"with\special"#),
            r#"/tmp/path\"with\\special"#
        );
    }
}
