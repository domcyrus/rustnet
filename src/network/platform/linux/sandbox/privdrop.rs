//! Root privilege drop (setuid) for Linux
//!
//! When rustnet is started via `sudo` it keeps euid 0 for its whole lifetime,
//! even though root is only needed during initialization: opening the raw
//! capture socket (CAP_NET_RAW) and loading eBPF programs (CAP_BPF +
//! CAP_PERFMON). Dropping capabilities alone still leaves euid 0, and on
//! kernels without Landlock (< 5.13) that means a compromise of the DPI code
//! runs as unconstrained root.
//!
//! This module drops the process to the invoking sudo user (`SUDO_UID` /
//! `SUDO_GID`), or to `nobody` (65534) when started as plain root, after all
//! privileged initialization is complete. Already-open file descriptors (the
//! capture socket, eBPF map/program fds, log and export files) remain valid
//! across the drop.
//!
//! # Trust model
//!
//! `SUDO_UID`/`SUDO_GID` are environment variables and thus caller-controlled,
//! but they can only ever select which *unprivileged* identity we become:
//! uid 0 and unparseable values are rejected and fall back to `nobody`, so a
//! forged value cannot retain or regain privilege.
//!
//! # Trade-offs
//!
//! After the drop, the procfs fallback for process attribution can only scan
//! `/proc/<pid>/fd` of processes owned by the target user; the eBPF fast path
//! is unaffected (it reads already-open map fds). Kubernetes log-directory
//! metadata under `/var/log/pods` may also become unreadable. `--no-uid-drop`
//! keeps the old keep-root behavior.

use anyhow::{Result, anyhow};

/// The uid/gid pair to drop to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DropTarget {
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
}

/// Overflow uid/gid, `nobody`/`nogroup` on all mainstream distros. Used when
/// rustnet runs as plain root (no sudo) or SUDO_UID/SUDO_GID are unusable.
const NOBODY: DropTarget = DropTarget {
    uid: 65534,
    gid: 65534,
};

/// Resolve the identity to drop to, or `None` when not running as root
/// (nothing to drop; the setcap path never has euid 0).
pub fn resolve_drop_target() -> Option<DropTarget> {
    // SAFETY: geteuid() has no failure mode and takes no pointers.
    if unsafe { libc::geteuid() } != 0 {
        return None;
    }
    Some(target_from_env(
        std::env::var("SUDO_UID").ok().as_deref(),
        std::env::var("SUDO_GID").ok().as_deref(),
    ))
}

/// Pick the target from SUDO_UID/SUDO_GID; both must parse to a nonzero id,
/// otherwise fall back to `nobody`. Split out from `resolve_drop_target` for
/// testability (no process-global env manipulation in tests).
fn target_from_env(sudo_uid: Option<&str>, sudo_gid: Option<&str>) -> DropTarget {
    let parse = |v: Option<&str>| v.and_then(|s| s.parse::<u32>().ok()).filter(|&id| id != 0);
    match (parse(sudo_uid), parse(sudo_gid)) {
        (Some(uid), Some(gid)) => DropTarget { uid, gid },
        _ => NOBODY,
    }
}

/// Change the file's owner to the drop target.
///
/// Used on pre-created export files (0600, root-owned) so they can still be
/// reopened by name after the uid drop, e.g. libpcap's `pcap_dump_open` and
/// the per-event sidecar JSONL appends. Operates on the already-open fd
/// (`fchown`), never on the path, so it cannot be redirected by a
/// symlink/rename swap after the O_NOFOLLOW create.
pub fn chown_to_target(file: &std::fs::File, target: DropTarget) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: fchown on a valid owned fd; no pointers involved.
    let rc = unsafe { libc::fchown(file.as_raw_fd(), target.uid, target.gid) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Irreversibly drop root to `target`: supplementary groups first, then gid,
/// then uid (all three of real/effective/saved so root cannot be regained).
///
/// Must be called while euid is 0. Uses the libc wrappers (not raw syscalls):
/// glibc and musl broadcast set*id() to every thread of the process, so
/// threads spawned before the drop (capture, enrichment) are covered too.
///
/// Side effect: transitioning all three uids away from 0 clears the effective
/// and permitted capability sets, which subsumes the explicit capability
/// drops that run before this.
pub fn drop_to(target: DropTarget) -> Result<()> {
    if target.uid == 0 || target.gid == 0 {
        return Err(anyhow!("refusing to 'drop' to uid 0 / gid 0"));
    }

    // SAFETY: setgroups reads `ngroups` gid_t values from the pointer; we pass
    // exactly one element and its valid address.
    let gids = [target.gid];
    if unsafe { libc::setgroups(1, gids.as_ptr()) } != 0 {
        return Err(anyhow!(
            "setgroups failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    // gid before uid: once uid 0 is gone, setresgid would fail.
    // SAFETY: setresgid/setresuid take plain integers.
    if unsafe { libc::setresgid(target.gid, target.gid, target.gid) } != 0 {
        return Err(anyhow!(
            "setresgid({}) failed: {}",
            target.gid,
            std::io::Error::last_os_error()
        ));
    }
    if unsafe { libc::setresuid(target.uid, target.uid, target.uid) } != 0 {
        return Err(anyhow!(
            "setresuid({}) failed: {}",
            target.uid,
            std::io::Error::last_os_error()
        ));
    }

    // Verify the drop stuck and root cannot be regained.
    let (mut ruid, mut euid, mut suid) = (0, 0, 0);
    let (mut rgid, mut egid, mut sgid) = (0, 0, 0);
    // SAFETY: getresuid/getresgid write to the three provided out-pointers.
    unsafe {
        libc::getresuid(&mut ruid, &mut euid, &mut suid);
        libc::getresgid(&mut rgid, &mut egid, &mut sgid);
    }
    if [ruid, euid, suid] != [target.uid; 3] || [rgid, egid, sgid] != [target.gid; 3] {
        return Err(anyhow!(
            "uid/gid drop verification failed (uids {ruid}/{euid}/{suid}, gids {rgid}/{egid}/{sgid})"
        ));
    }
    // SAFETY: setuid takes a plain integer. With ruid/euid/suid all nonzero
    // and no CAP_SETUID this must fail; success means the drop is unsound.
    if unsafe { libc::setuid(0) } == 0 {
        return Err(anyhow!("uid drop verification failed: setuid(0) succeeded"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_from_env_uses_sudo_ids() {
        assert_eq!(
            target_from_env(Some("1000"), Some("1000")),
            DropTarget {
                uid: 1000,
                gid: 1000
            }
        );
    }

    #[test]
    fn test_target_from_env_rejects_root_and_garbage() {
        // uid 0 must never be a drop target
        assert_eq!(target_from_env(Some("0"), Some("0")), NOBODY);
        // unparseable values fall back to nobody
        assert_eq!(target_from_env(Some("abc"), Some("1000")), NOBODY);
        assert_eq!(target_from_env(Some("-1"), Some("1000")), NOBODY);
        // both must be present
        assert_eq!(target_from_env(Some("1000"), None), NOBODY);
        assert_eq!(target_from_env(None, None), NOBODY);
    }

    #[test]
    fn test_drop_to_rejects_root_target() {
        assert!(drop_to(DropTarget { uid: 0, gid: 0 }).is_err());
    }

    #[test]
    fn test_resolve_drop_target_none_when_not_root() {
        // Tests don't run as root in CI; as non-root there is nothing to drop.
        if unsafe { libc::geteuid() } != 0 {
            assert!(resolve_drop_target().is_none());
        }
    }
}
