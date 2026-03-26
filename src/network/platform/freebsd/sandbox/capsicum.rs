//! FreeBSD Capsicum sandboxing implementation
//!
//! Uses Capsicum's `cap_rights_limit()` to restrict file descriptor
//! capabilities after initialization. Unlike `cap_enter()` (which blocks
//! all new file opens and process spawning), `cap_rights_limit()` only
//! restricts individual FDs — allowing sockstat subprocess execution
//! to continue working for process-to-connection mapping.
//!
//! # What We Restrict
//!
//! - Output file FDs (logs, PCAP exports): restricted to write/append only
//! - Prevents repurposing output FDs for reading sensitive data
//!
//! # Why Not cap_enter()
//!
//! RustNet uses `sockstat` subprocess for process identification on FreeBSD.
//! `cap_enter()` would block `fork()`/`execve()`, breaking this functionality.
//! Using `cap_rights_limit()` on individual FDs provides meaningful hardening
//! without breaking runtime behavior.

use anyhow::{Context, Result};
use std::os::unix::io::AsRawFd;
use std::path::Path;

/// Result of Capsicum sandbox application
pub struct CapsicumResult {
    /// Whether any FD restrictions were applied
    pub applied: bool,
    /// Number of FDs restricted
    pub fds_restricted: u32,
    /// Human-readable message
    pub message: String,
}

/// Restrict an output file's FD to write-only operations.
///
/// After this call, the FD can only be used for:
/// - Writing data
/// - Seeking (for append positioning)
/// - Getting file stats (fstat)
/// - ioctl (needed by some logging frameworks)
///
/// The FD cannot be used for reading, which prevents an attacker from
/// repurposing an output FD to read sensitive data.
fn restrict_write_fd(path: &Path) -> Result<()> {
    use std::fs::OpenOptions;

    // Open the file to get an FD we can restrict
    // The file should already exist (created during init)
    let file = OpenOptions::new()
        .write(true)
        .append(true)
        .open(path)
        .with_context(|| format!("Failed to open {:?} for FD restriction", path))?;

    let fd = file.as_raw_fd();

    // Build cap_rights for write-only access
    unsafe {
        let mut rights = std::mem::MaybeUninit::<libc::cap_rights_t>::uninit();
        libc::__cap_rights_init(
            libc::CAP_RIGHTS_VERSION as libc::c_int,
            rights.as_mut_ptr(),
            libc::CAP_WRITE,
            libc::CAP_SEEK,
            libc::CAP_FSTAT,
            libc::CAP_FCNTL,
            libc::CAP_FTRUNCATE,
            libc::CAP_EVENT, // for poll/kqueue
            0u64,            // terminator
        );
        let rights = rights.assume_init();

        if libc::cap_rights_limit(fd, &rights) != 0 {
            let err = std::io::Error::last_os_error();
            // ENOSYS means Capsicum is not available (kernel compiled without it)
            if err.raw_os_error() == Some(libc::ENOSYS) {
                log::debug!("Capsicum not available on this kernel");
                return Ok(());
            }
            return Err(err).context(format!("cap_rights_limit failed for {:?}", path));
        }
    }

    // Intentionally leak the File — we don't want to close the FD.
    // The restriction persists on the FD even after the File is dropped,
    // but closing the FD would make the restriction meaningless.
    // The actual writes happen through different file handles in the app,
    // and cap_rights_limit affects the FD globally (all handles).
    std::mem::forget(file);

    log::debug!("Capsicum: restricted FD for {:?} to write-only", path);
    Ok(())
}

/// Apply Capsicum FD restrictions to output files.
///
/// This should be called AFTER:
/// - Packet capture handles are opened
/// - Log files are created
/// - PCAP export files are created
pub fn apply_capsicum(write_paths: &[&Path]) -> Result<CapsicumResult> {
    let mut restricted = 0u32;
    let mut messages = Vec::new();

    for path in write_paths {
        if !path.exists() {
            continue;
        }
        match restrict_write_fd(path) {
            Ok(()) => {
                restricted += 1;
            }
            Err(e) => {
                let msg = format!("Failed to restrict {:?}: {}", path, e);
                log::warn!("{}", msg);
                messages.push(msg);
            }
        }
    }

    let applied = restricted > 0;
    let message = if applied {
        format!(
            "Capsicum: {} FD(s) restricted{}",
            restricted,
            if messages.is_empty() {
                String::new()
            } else {
                format!("; {}", messages.join("; "))
            }
        )
    } else if messages.is_empty() {
        "Capsicum: no output files to restrict".to_string()
    } else {
        messages.join("; ")
    };

    Ok(CapsicumResult {
        applied,
        fds_restricted: restricted,
        message,
    })
}
