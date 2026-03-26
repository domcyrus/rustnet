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
//! - Memory: mmap/mmap2, munmap, mprotect, brk, madvise
//! - Files: openat, fstat (newfstatat/fstatat64), statx, lseek, getdents64 (for /proc reads)
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
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule,
};
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

    // Override SYS_socket with argument filter: only allow AF_UNIX (domain=1)
    // This prevents creating AF_INET/AF_INET6 sockets for data exfiltration
    // while still allowing Unix domain sockets needed for clipboard (wayland/X11).
    // Note: Landlock cannot block UDP yet (pending kernel ABI V5+), so this
    // seccomp rule is the primary defense against UDP exfiltration.
    rules.insert(
        libc::SYS_socket.into(),
        vec![
            SeccompRule::new(vec![
                SeccompCondition::new(
                    0, // arg0 = domain
                    SeccompCmpArgLen::Dword,
                    SeccompCmpOp::Eq,
                    libc::AF_UNIX as u64,
                )
                .map_err(|e| anyhow::anyhow!("Failed to create socket filter condition: {}", e))?,
            ])
            .map_err(|e| anyhow::anyhow!("Failed to create socket filter rule: {}", e))?,
        ],
    );

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
    let mut syscalls: Vec<i64> = vec![
        // === I/O ===
        libc::SYS_read.into(),
        libc::SYS_write.into(),
        libc::SYS_readv.into(),
        libc::SYS_writev.into(),
        libc::SYS_close.into(),
        libc::SYS_ioctl.into(), // pcap uses ioctl on BPF fd
        libc::SYS_recvfrom.into(),
        libc::SYS_sendto.into(),
        libc::SYS_recvmsg.into(),
        // === Polling / event loop ===
        libc::SYS_ppoll.into(),
        libc::SYS_epoll_create1.into(),
        libc::SYS_epoll_ctl.into(),
        libc::SYS_epoll_pwait.into(),
        libc::SYS_pselect6.into(),
        // === Memory management ===
        libc::SYS_munmap.into(),
        libc::SYS_mprotect.into(),
        libc::SYS_brk.into(),
        libc::SYS_madvise.into(),
        libc::SYS_mremap.into(),
        // === File operations (for /proc reads, log writes) ===
        libc::SYS_openat.into(),
        libc::SYS_statx.into(),
        libc::SYS_lseek.into(),
        libc::SYS_getdents64.into(),
        libc::SYS_fcntl.into(),
        libc::SYS_ftruncate.into(),
        libc::SYS_readlinkat.into(),
        libc::SYS_faccessat2.into(),
        // === Signals ===
        libc::SYS_rt_sigaction.into(),
        libc::SYS_rt_sigprocmask.into(),
        libc::SYS_rt_sigreturn.into(),
        libc::SYS_sigaltstack.into(),
        // === Threading ===
        libc::SYS_futex.into(),
        libc::SYS_clone3.into(),
        libc::SYS_set_robust_list.into(),
        libc::SYS_rseq.into(),
        libc::SYS_sched_yield.into(),
        libc::SYS_sched_getaffinity.into(),
        // === Time ===
        libc::SYS_clock_gettime.into(),
        libc::SYS_clock_nanosleep.into(),
        libc::SYS_nanosleep.into(),
        // === Process info ===
        libc::SYS_getpid.into(),
        libc::SYS_gettid.into(),
        libc::SYS_getuid.into(),
        libc::SYS_geteuid.into(),
        libc::SYS_getgid.into(),
        libc::SYS_getegid.into(),
        // === Random ===
        libc::SYS_getrandom.into(),
        // === Exit ===
        libc::SYS_exit.into(),
        libc::SYS_exit_group.into(),
        // === Pipes (used by crossbeam channels internally) ===
        libc::SYS_pipe2.into(),
        libc::SYS_eventfd2.into(),
        // === Misc ===
        libc::SYS_prctl.into(),           // needed for seccomp itself
        libc::SYS_seccomp.into(),         // needed for TSYNC
        libc::SYS_prlimit64.into(),       // resource limits
        libc::SYS_sysinfo.into(),         // system info queries
        libc::SYS_uname.into(),           // used by various libs
        libc::SYS_tgkill.into(),          // thread signaling
        libc::SYS_restart_syscall.into(), // after signal interruption
        // === Clipboard (wayland/X11 via arboard) ===
        // Note: clipboard may not work under Landlock anyway (socket paths blocked),
        // but we allow the syscalls so failures are clean EACCES not EPERM.
        // SYS_socket is NOT listed here — it has an arg filter (AF_UNIX only)
        // applied separately in build_filter() to block AF_INET/AF_INET6.
        libc::SYS_connect.into(),  // arboard connects to wayland/X11
        libc::SYS_sendmsg.into(),  // wayland protocol
        libc::SYS_shutdown.into(), // socket cleanup
        // === eBPF ring buffer reads (post-init) ===
        libc::SYS_perf_event_open.into(), // eBPF perf buffer polling
        libc::SYS_bpf.into(),             // eBPF map lookups at runtime
    ];

    // === Arch-specific syscalls ===

    // mmap: x86_64/aarch64 have SYS_mmap; 32-bit ARM uses SYS_mmap2
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    syscalls.push(libc::SYS_mmap.into());
    #[cfg(target_arch = "arm")]
    syscalls.push(libc::SYS_mmap2.into());

    // fstat: x86_64/aarch64 have SYS_newfstatat; 32-bit ARM uses SYS_fstatat64
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    syscalls.push(libc::SYS_newfstatat.into());
    #[cfg(target_arch = "arm")]
    syscalls.push(libc::SYS_fstatat64.into());

    // gettimeofday: not available on aarch64 (uses clock_gettime via vDSO)
    #[cfg(any(target_arch = "x86_64", target_arch = "arm"))]
    syscalls.push(libc::SYS_gettimeofday.into());

    // x86_64-only legacy syscalls (aarch64/arm use ppoll, pselect6, epoll_pwait)
    #[cfg(target_arch = "x86_64")]
    {
        syscalls.push(libc::SYS_poll.into());
        syscalls.push(libc::SYS_epoll_wait.into());
        syscalls.push(libc::SYS_select.into());
    }

    // 32-bit ARM needs additional syscalls for 64-bit file operations
    #[cfg(target_arch = "arm")]
    {
        syscalls.push(libc::SYS_fcntl64.into());
        syscalls.push(libc::SYS_ftruncate64.into());
        syscalls.push(libc::SYS__llseek.into());
    }

    syscalls
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
        assert!(!syscalls.contains(&i64::from(libc::SYS_execve)));
        assert!(!syscalls.contains(&i64::from(libc::SYS_execveat)));
        assert!(!syscalls.contains(&i64::from(libc::SYS_ptrace)));
        assert!(!syscalls.contains(&i64::from(libc::SYS_mount)));
        assert!(!syscalls.contains(&i64::from(libc::SYS_umount2)));
        assert!(!syscalls.contains(&i64::from(libc::SYS_reboot)));
        assert!(!syscalls.contains(&i64::from(libc::SYS_init_module)));
        assert!(!syscalls.contains(&i64::from(libc::SYS_pivot_root)));
        assert!(!syscalls.contains(&i64::from(libc::SYS_chroot)));
    }

    #[test]
    fn test_socket_not_in_unconditional_allowlist() {
        // SYS_socket should NOT be in the unconditional allowlist —
        // it has an AF_UNIX-only arg filter applied in build_filter()
        let syscalls = allowed_syscalls();
        assert!(
            !syscalls.contains(&i64::from(libc::SYS_socket)),
            "SYS_socket should be filtered by argument, not unconditionally allowed"
        );
    }
}
