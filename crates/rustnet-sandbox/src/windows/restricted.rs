//! Windows token privilege removal and job object sandboxing
//!
//! After initialization, all privileges except ordinary directory traversal are removed from the process
//! token and a Job Object that prevents child process creation is applied.
//!
//! This reduces blast radius if a vulnerability in packet parsing is exploited:
//! - Cannot spawn child processes (reverse shell, data exfiltration via curl, etc.)
//! - Cannot debug other processes (SeDebugPrivilege removed)
//! - Cannot take ownership of files (SeTakeOwnershipPrivilege removed)
//! - Cannot back up/restore files (SeBackupPrivilege, SeRestorePrivilege removed)

use anyhow::{Context, Result};
use std::ffi::c_void;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, GetLastError, HANDLE, LUID,
};
use windows::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
    SE_PRIVILEGE_REMOVED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY, TokenPrivileges,
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

/// The only privilege needed after opening the capture and output handles.
///
/// Preserve ordinary directory traversal for image-name and GeoIP lookups.
/// ETW uses a user trace session authorized by group membership, not a system
/// logger requiring SeSystemProfilePrivilege. No privilege is added or enabled.
/// This does NOT remove Administrator group membership or lower integrity.
const RETAINED_PRIVILEGE: windows::core::PCWSTR = windows::core::w!("SeChangeNotifyPrivilege");

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns the handle and closes it exactly once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Result of token privilege removal
pub(super) struct RestrictedTokenResult {
    /// Whether at least one privilege was removed (count > 0).
    /// False if the token already contained only allowlisted privileges.
    pub privileges_removed: bool,
    /// Number of privileges removed
    pub privileges_removed_count: u32,
    /// Whether the privilege restriction step completed without errors.
    /// True even when 0 privileges were removed because the token never
    /// held them: that is the desired end state, not a failure.
    pub succeeded: bool,
    /// Human-readable message
    pub message: String,
}

/// Result of job object application
pub(super) struct JobObjectResult {
    /// Whether the job object was applied
    pub applied: bool,
    /// Human-readable message
    pub message: String,
}

/// Retain only the required traversal privilege in the current process token.
///
/// Uses SE_PRIVILEGE_REMOVED, which permanently removes privileges: they
/// cannot be re-enabled, even by the process itself.
pub(super) fn retain_required_privileges() -> Result<RestrictedTokenResult> {
    // SAFETY: OpenProcessToken initializes the output handle on success.
    unsafe {
        let mut token_handle = HANDLE::default();

        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token_handle,
        )
        .context("Failed to open process token")?;
        let token = OwnedHandle(token_handle);
        restrict_token(token.0)
    }
}

/// Enumerate every privilege, including disabled and future privileges.
fn token_privileges(token: HANDLE) -> Result<Vec<LUID_AND_ATTRIBUTES>> {
    // SAFETY: the second query uses aligned, initialized storage of the size
    // requested by Windows. Validate its count before reading the trailing array.
    unsafe {
        let mut bytes = 0;
        let sizing = GetTokenInformation(token, TokenPrivileges, None, 0, &mut bytes);
        anyhow::ensure!(
            sizing.is_err() && GetLastError() == ERROR_INSUFFICIENT_BUFFER,
            "Cannot determine token privilege buffer size"
        );
        anyhow::ensure!(bytes >= 4, "Invalid token privilege buffer size");
        let mut storage = vec![
            TOKEN_PRIVILEGES::default();
            (bytes as usize).div_ceil(std::mem::size_of::<TOKEN_PRIVILEGES>())
        ];
        let capacity = bytes;
        GetTokenInformation(
            token,
            TokenPrivileges,
            Some(storage.as_mut_ptr().cast()),
            capacity,
            &mut bytes,
        )
        .context("Cannot enumerate token privileges")?;
        let count = storage[0].PrivilegeCount as usize;
        let offset = std::mem::offset_of!(TOKEN_PRIVILEGES, Privileges);
        anyhow::ensure!(
            bytes <= capacity
                && count <= (bytes as usize - offset) / std::mem::size_of::<LUID_AND_ATTRIBUTES>(),
            "Invalid token privilege count"
        );
        Ok(std::slice::from_raw_parts(storage[0].Privileges.as_ptr(), count).to_vec())
    }
}

fn retained_luid() -> Result<LUID> {
    let mut luid = LUID::default();
    // SAFETY: the privilege name is static and NUL-terminated; output is writable.
    unsafe { LookupPrivilegeValueW(None, RETAINED_PRIVILEGE, &mut luid) }
        .context("Cannot resolve the retained traversal privilege")?;
    Ok(luid)
}

fn restrict_token(token: HANDLE) -> Result<RestrictedTokenResult> {
    let retained = retained_luid()?;
    let before = token_privileges(token)?;
    for privilege in &before {
        if privilege.Luid == retained {
            continue;
        }
        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: privilege.Luid,
                Attributes: SE_PRIVILEGE_REMOVED,
            }],
        };
        // SAFETY: the token was opened for adjustment; tp contains one entry.
        unsafe {
            AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None)
                .context("Cannot remove an unnecessary token privilege")?;
            anyhow::ensure!(
                GetLastError().0 != ERROR_NOT_ALL_ASSIGNED,
                "Token privilege removal was not assigned"
            );
        }
    }
    // Verify the resulting token rather than trusting individual API calls.
    let after = token_privileges(token)?;
    anyhow::ensure!(
        after.iter().all(|p| p.Luid == retained),
        "Unexpected token privileges remain after restriction"
    );
    let count = (before.len() - after.len()) as u32;
    Ok(RestrictedTokenResult {
        privileges_removed: count > 0,
        privileges_removed_count: count,
        succeeded: true,
        message: format!(
            "{count} privilege(s) permanently removed; only SeChangeNotifyPrivilege may remain (group membership and integrity unchanged)"
        ),
    })
}

/// Apply a Job Object to the current process that prevents child process creation.
///
/// After this call, any attempt to create a child process will fail.
/// This blocks reverse shells, data exfiltration via exec, etc.
pub(super) fn apply_job_object() -> Result<JobObjectResult> {
    unsafe {
        let job = OwnedHandle(CreateJobObjectW(None, None).context("Failed to create job object")?);

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
            job.0,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
        .context("Failed to set job object limits")?;

        // On Windows 8+ nested jobs are supported, so this succeeds even if the
        // process is already in a job (e.g., launched from Task Scheduler or a
        // container). On Windows 7 (unsupported) it would fail with ACCESS_DENIED.
        AssignProcessToJobObject(job.0, GetCurrentProcess())
            .context("Failed to assign process to job object")?;

        // The job handle is intentionally leaked: it must remain open for the
        // lifetime of the process, otherwise the restrictions are lifted.
        std::mem::forget(job);

        log::debug!("Job object applied: child process creation blocked");

        Ok(JobObjectResult {
            applied: true,
            message: "Job object applied: child process creation blocked".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Security::{
        DuplicateTokenEx, SE_PRIVILEGE_ENABLED, SecurityImpersonation, TOKEN_DUPLICATE,
        TokenPrimary,
    };

    #[test]
    fn privilege_allowlist_is_permanent_and_idempotent() {
        // Work on a duplicate: never remove privileges from the test runner.
        let mut original = HANDLE::default();
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE,
                &mut original,
            )
            .unwrap();
        }
        let original = OwnedHandle(original);
        let mut duplicate = HANDLE::default();
        unsafe {
            DuplicateTokenEx(
                original.0,
                TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                None,
                SecurityImpersonation,
                TokenPrimary,
                &mut duplicate,
            )
            .unwrap();
        }
        let duplicate = OwnedHandle(duplicate);
        let before = token_privileges(duplicate.0).unwrap();
        let retained = retained_luid().unwrap();
        let expected: Vec<_> = before
            .iter()
            .filter(|p| p.Luid == retained)
            .copied()
            .collect();
        let result = restrict_token(duplicate.0).unwrap();
        assert!(result.succeeded);
        assert_eq!(
            result.privileges_removed_count as usize,
            before.len() - expected.len()
        );
        let after = token_privileges(duplicate.0).unwrap();
        assert_eq!(after.len(), expected.len());
        for (actual, expected) in after.iter().zip(&expected) {
            assert_eq!(actual.Luid, expected.Luid);
            assert_eq!(actual.Attributes, expected.Attributes); // never enable extra rights
        }
        for removed in before.iter().filter(|p| p.Luid != retained) {
            let enable = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: removed.Luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            unsafe {
                AdjustTokenPrivileges(duplicate.0, false, Some(&enable), 0, None, None).unwrap();
                assert_eq!(GetLastError().0, ERROR_NOT_ALL_ASSIGNED);
            }
        }
        assert_eq!(
            restrict_token(duplicate.0)
                .unwrap()
                .privileges_removed_count,
            0
        );
        assert_eq!(token_privileges(original.0).unwrap().len(), before.len());
    }

    #[test]
    fn invalid_token_is_an_error() {
        assert!(restrict_token(HANDLE::default()).is_err());
    }

    #[test]
    fn job_limit_blocks_child_processes() {
        const CHILD: &str = "RUSTNET_JOB_LIMIT_TEST_CHILD";
        if std::env::var_os(CHILD).is_some() {
            assert!(apply_job_object().unwrap().applied);
            assert!(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .arg("--list")
                    .spawn()
                    .is_err()
            );
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "windows::restricted::tests::job_limit_blocks_child_processes",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
