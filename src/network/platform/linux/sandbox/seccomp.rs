//! Seccomp-BPF syscall filtering
//!
//! Restricts the process to only the syscalls needed for normal operation
//! after initialization is complete. This is a defense-in-depth measure
//! that complements Landlock filesystem/network restrictions.
//!
//! If a vulnerability in DPI/packet parsing is exploited, the attacker
//! cannot use dangerous syscalls like `execve`, `ptrace`, `mount`, etc.
//!
//! # Syscall Allowlist
//!
//! The allowlist covers:
//! - I/O: read, write, close, ioctl (for pcap), recvfrom, sendto
//! - Polling: poll, epoll_*, ppoll (for event loops)
//! - Memory: mmap, munmap, mprotect, brk, madvise
//! - Files: openat, fstat, statx, lseek, getdents64 (for /proc reads)
//! - Signals: rt_sigaction, rt_sigprocmask, rt_sigreturn, sigaltstack
//! - Threading: futex, clone3, set_robust_list, rseq
//! - Time: clock_gettime, clock_nanosleep, nanosleep
//! - Misc: getrandom, exit_group, exit, sched_yield, getpid, gettid
//!
//! # Application Order
//!
//! Seccomp should be applied AFTER Landlock and capability dropping,
//! as the final layer of defense. `apply_filter` internally calls
//! `prctl(PR_SET_NO_NEW_PRIVS)` before installing the filter.

use anyhow::{Context, Result};
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};
use std::collections::HashMap;
use std::convert::TryInto;

/// Apply seccomp-bpf syscall filter to all threads in the process.
///
/// This restricts the process to only the syscalls needed for normal
/// operation after initialization. The filter is applied to all threads
/// using SECCOMP_FILTER_FLAG_TSYNC.
///
/// # Safety
///
/// This internally calls `prctl(PR_SET_NO_NEW_PRIVS, 1)` which is
/// irreversible. After this call, the process cannot gain new privileges
/// through execve of setuid binaries.
pub fn apply_seccomp_filter() -> Result<()> {
    let filter = build_filter().context("Failed to build seccomp filter")?;

    seccompiler::apply_filter_all_threads(&filter)
        .map_err(|e| anyhow::anyhow!("Failed to apply seccomp filter: {}", e))?;

    log::info!("Seccomp-BPF filter applied (all threads)");
    Ok(())
}

/// Build the BPF program from our syscall allowlist.
fn build_filter() -> Result<BpfProgram> {
    let mut rules: HashMap<i64, Vec<SeccompRule>> = HashMap::new();

    // Allow each syscall unconditionally (empty rule vec = no arg checks)
    for syscall in allowed_syscalls() {
        rules.insert(syscall, vec![]);
    }

    let filter = SeccompFilter::new(
        rules.into_iter().collect(),
        // Match action: allow the syscall
        SeccompAction::Allow,
        // Default action: return EPERM for unknown syscalls
        // Using Errno instead of KillProcess for debuggability and graceful failures
        SeccompAction::Errno(libc::EPERM as u32),
        std::env::consts::ARCH
            .try_into()
            .map_err(|_| anyhow::anyhow!("Unsupported architecture for seccomp"))?,
    )
    .map_err(|e| anyhow::anyhow!("Failed to create seccomp filter: {}", e))?;

    let bpf: BpfProgram = filter
        .try_into()
        .map_err(|e| anyhow::anyhow!("Failed to compile seccomp filter: {}", e))?;

    Ok(bpf)
}

/// Syscalls required for rustnet's normal operation after initialization.
///
/// This list is intentionally conservative. Syscalls needed only during
/// initialization (e.g., socket creation, bind, eBPF loading) are NOT
/// included since those operations are complete before the filter is applied.
fn allowed_syscalls() -> Vec<i64> {
    vec![
        // === I/O ===
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_close,
        libc::SYS_ioctl, // pcap uses ioctl on BPF fd
        libc::SYS_recvfrom,
        libc::SYS_sendto,
        libc::SYS_recvmsg,
        // === Polling / event loop ===
        #[cfg(target_arch = "x86_64")]
        libc::SYS_poll, // x86_64 only; aarch64 uses ppoll
        libc::SYS_ppoll,
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_pwait,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_epoll_wait, // x86_64 only; aarch64 uses epoll_pwait
        #[cfg(target_arch = "x86_64")]
        libc::SYS_select, // x86_64 only; aarch64 uses pselect6
        libc::SYS_pselect6,
        // === Memory management ===
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mprotect,
        libc::SYS_brk,
        libc::SYS_madvise,
        libc::SYS_mremap,
        // === File operations (for /proc reads, log writes) ===
        libc::SYS_openat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_lseek,
        libc::SYS_getdents64,
        libc::SYS_fcntl,
        libc::SYS_ftruncate,
        libc::SYS_readlinkat,
        libc::SYS_faccessat2,
        // === Signals ===
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        // === Threading ===
        libc::SYS_futex,
        libc::SYS_clone3,
        libc::SYS_set_robust_list,
        libc::SYS_rseq,
        libc::SYS_sched_yield,
        libc::SYS_sched_getaffinity,
        // === Time ===
        libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep,
        libc::SYS_nanosleep,
        libc::SYS_gettimeofday,
        // === Process info ===
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        // === Random ===
        libc::SYS_getrandom,
        // === Exit ===
        libc::SYS_exit,
        libc::SYS_exit_group,
        // === Pipes (used by crossbeam channels internally) ===
        libc::SYS_pipe2,
        libc::SYS_eventfd2,
        // === Misc ===
        libc::SYS_prctl,           // needed for seccomp itself
        libc::SYS_seccomp,         // needed for TSYNC
        libc::SYS_prlimit64,       // resource limits
        libc::SYS_sysinfo,         // system info queries
        libc::SYS_uname,           // used by various libs
        libc::SYS_tgkill,          // thread signaling
        libc::SYS_restart_syscall, // after signal interruption
        // === Clipboard (wayland/X11 via arboard) ===
        // Note: clipboard may not work under Landlock anyway (socket paths blocked),
        // but we allow the syscalls so failures are clean EACCES not EPERM.
        libc::SYS_socket,   // arboard creates Unix sockets for wayland
        libc::SYS_connect,  // arboard connects to wayland/X11
        libc::SYS_sendmsg,  // wayland protocol
        libc::SYS_shutdown, // socket cleanup
        // === eBPF ring buffer reads (post-init) ===
        libc::SYS_perf_event_open, // eBPF perf buffer polling
        libc::SYS_bpf,             // eBPF map lookups at runtime
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allowed_syscalls_not_empty() {
        assert!(!allowed_syscalls().is_empty());
    }

    #[test]
    fn test_no_duplicate_syscalls() {
        let syscalls = allowed_syscalls();
        let mut seen = std::collections::HashSet::new();
        for s in &syscalls {
            assert!(seen.insert(s), "Duplicate syscall: {}", s);
        }
    }

    #[test]
    fn test_build_filter_succeeds() {
        // Should build without error on Linux
        let result = build_filter();
        assert!(result.is_ok(), "Failed to build filter: {:?}", result.err());
    }

    #[test]
    fn test_dangerous_syscalls_not_in_allowlist() {
        let syscalls = allowed_syscalls();
        // These should never be in the allowlist
        assert!(!syscalls.contains(&libc::SYS_execve));
        assert!(!syscalls.contains(&libc::SYS_execveat));
        assert!(!syscalls.contains(&libc::SYS_ptrace));
        assert!(!syscalls.contains(&libc::SYS_mount));
        assert!(!syscalls.contains(&libc::SYS_umount2));
        assert!(!syscalls.contains(&libc::SYS_reboot));
        assert!(!syscalls.contains(&libc::SYS_init_module));
        assert!(!syscalls.contains(&libc::SYS_pivot_root));
        assert!(!syscalls.contains(&libc::SYS_chroot));
    }
}
