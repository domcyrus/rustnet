//! Windows restricted token and job object sandboxing
//!
//! After initialization, we:
//! 1. Create a Job Object that prevents child process creation
//! 2. Remove dangerous privileges from the process token
//!
//! This reduces blast radius if a vulnerability in packet parsing is exploited:
//! - Cannot spawn child processes (reverse shell, data exfiltration via curl, etc.)
//! - Cannot debug other processes (SeDebugPrivilege removed)
//! - Cannot take ownership of files (SeTakeOwnershipPrivilege removed)
//! - Cannot back up/restore files (SeBackupPrivilege, SeRestorePrivilege removed)

use anyhow::{Context, Result};
use std::ffi::c_void;
use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_REMOVED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOBOBJECT_BASIC_LIMIT_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Win32 error code returned by `AdjustTokenPrivileges` when the token
/// did not hold the requested privilege (success, but nothing was changed).
const ERROR_NOT_ALL_ASSIGNED: u32 = 1300;

/// Privileges to remove from the process token after initialization.
///
/// These are the most dangerous privileges an attacker could abuse:
const PRIVILEGES_TO_REMOVE: &[&str] = &[
    "SeDebugPrivilege",              // Debug arbitrary processes
    "SeTakeOwnershipPrivilege",      // Take ownership of any securable object
    "SeBackupPrivilege",             // Read any file regardless of ACL
    "SeRestorePrivilege",            // Write any file regardless of ACL
    "SeCreateTokenPrivilege",        // Create primary tokens
    "SeAssignPrimaryTokenPrivilege", // Replace process-level token
    "SeLoadDriverPrivilege",         // Load/unload device drivers
    "SeTcbPrivilege",                // Act as part of the OS
    "SeRemoteShutdownPrivilege",     // Shut down remote systems
    "SeImpersonatePrivilege",        // Impersonate other users
];

/// Result of restricted token application
pub struct RestrictedTokenResult {
    /// Whether privileges were successfully removed
    pub privileges_removed: bool,
    /// Number of privileges removed
    pub privileges_removed_count: u32,
    /// Human-readable message
    pub message: String,
}

/// Result of job object application
pub struct JobObjectResult {
    /// Whether the job object was applied
    pub applied: bool,
    /// Human-readable message
    pub message: String,
}

/// Remove dangerous privileges from the current process token.
///
/// Uses SE_PRIVILEGE_REMOVED which permanently removes privileges —
/// they cannot be re-enabled, even by the process itself.
pub fn remove_dangerous_privileges() -> Result<RestrictedTokenResult> {
    unsafe {
        let mut token_handle = HANDLE::default();

        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token_handle,
        )
        .context("Failed to open process token")?;

        let mut removed_count = 0u32;
        let mut messages = Vec::new();

        for priv_name in PRIVILEGES_TO_REMOVE {
            match remove_single_privilege(token_handle, priv_name) {
                Ok(true) => {
                    removed_count += 1;
                    log::debug!("Removed privilege: {}", priv_name);
                }
                Ok(false) => {
                    // Privilege not held — not an error
                    log::debug!("Privilege not present: {}", priv_name);
                }
                Err(e) => {
                    let msg = format!("Failed to remove {}: {}", priv_name, e);
                    log::warn!("{}", msg);
                    messages.push(msg);
                }
            }
        }

        let _ = CloseHandle(token_handle);

        let message = if removed_count > 0 {
            format!(
                "{} privilege(s) removed{}",
                removed_count,
                if messages.is_empty() {
                    String::new()
                } else {
                    format!("; {}", messages.join("; "))
                }
            )
        } else if messages.is_empty() {
            "No dangerous privileges were held".to_string()
        } else {
            messages.join("; ")
        };

        Ok(RestrictedTokenResult {
            privileges_removed: removed_count > 0,
            privileges_removed_count: removed_count,
            message,
        })
    }
}

/// Remove a single privilege from the token.
/// Returns Ok(true) if removed, Ok(false) if not held, Err on failure.
unsafe fn remove_single_privilege(token: HANDLE, privilege_name: &str) -> Result<bool> {
    unsafe {
        let wide_name: Vec<u16> = privilege_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut luid = LUID::default();
        if LookupPrivilegeValueW(None, windows::core::PCWSTR(wide_name.as_ptr()), &mut luid)
            .is_err()
        {
            // Privilege name not recognized on this system — skip
            return Ok(false);
        }

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_REMOVED,
            }],
        };

        if AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None).is_err() {
            return Err(anyhow::anyhow!(
                "AdjustTokenPrivileges failed for {}",
                privilege_name
            ));
        }

        // Check GetLastError — AdjustTokenPrivileges returns success even if
        // the privilege wasn't held (ERROR_NOT_ALL_ASSIGNED = 1300)
        let last_error = windows::Win32::Foundation::GetLastError();
        if last_error.0 == ERROR_NOT_ALL_ASSIGNED {
            return Ok(false);
        }

        Ok(true)
    }
}

/// Apply a Job Object to the current process that prevents child process creation.
///
/// After this call, any attempt to create a child process will fail.
/// This blocks reverse shells, data exfiltration via exec, etc.
pub fn apply_job_object() -> Result<JobObjectResult> {
    unsafe {
        // Create an unnamed job object
        let job = CreateJobObjectW(None, None).context("Failed to create job object")?;

        // Configure: limit to 1 active process (prevents child spawning)
        let info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
            BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
                LimitFlags: JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
                ActiveProcessLimit: 1,
                ..Default::default()
            },
            ..Default::default()
        };

        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
        .context("Failed to set job object limits")?;

        // Assign current process to the job.
        // On Windows 8+ nested jobs are supported, so this succeeds even if the
        // process is already in a job (e.g., launched from Task Scheduler or a
        // container). On Windows 7 (unsupported) it would fail with ACCESS_DENIED.
        AssignProcessToJobObject(job, GetCurrentProcess())
            .context("Failed to assign process to job object")?;

        // Don't close the job handle — it must remain open for the lifetime
        // of the process, otherwise the restrictions are lifted.
        // Intentionally leak it.

        log::debug!("Job object applied: child process creation blocked");

        Ok(JobObjectResult {
            applied: true,
            message: "Job object applied: child process creation blocked".to_string(),
        })
    }
}
