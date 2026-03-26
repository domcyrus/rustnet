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

/// Convert a libc syscall number to the i64 expected by seccompiler.
///
/// `libc::SYS_*` is `c_long`: i64 on 64-bit targets, i32 on 32-bit.
/// This function handles the widening cleanly without triggering
/// clippy lints on either architecture.
fn syscall(nr: libc::c_long) -> i64 {
    // c_long is i64 on 64-bit, i32 on 32-bit
    #[cfg(target_pointer_width = "64")]
    {
        nr
    }
    #[cfg(target_pointer_width = "32")]
    {
        i64::from(nr)
    }
}

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
        syscall(libc::SYS_socket),
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
        syscall(libc::SYS_read),
        syscall(libc::SYS_write),
        syscall(libc::SYS_readv),
        syscall(libc::SYS_writev),
        syscall(libc::SYS_close),
        syscall(libc::SYS_ioctl), // pcap uses ioctl on BPF fd
        syscall(libc::SYS_recvfrom),
        syscall(libc::SYS_sendto),
        syscall(libc::SYS_recvmsg),
        // === Polling / event loop ===
        syscall(libc::SYS_ppoll),
        syscall(libc::SYS_epoll_create1),
        syscall(libc::SYS_epoll_ctl),
        syscall(libc::SYS_epoll_pwait),
        syscall(libc::SYS_pselect6),
        // === Memory management ===
        syscall(libc::SYS_munmap),
        syscall(libc::SYS_mprotect),
        syscall(libc::SYS_brk),
        syscall(libc::SYS_madvise),
        syscall(libc::SYS_mremap),
        // === File operations (for /proc reads, log writes) ===
        syscall(libc::SYS_openat),
        syscall(libc::SYS_statx),
        syscall(libc::SYS_lseek),
        syscall(libc::SYS_getdents64),
        syscall(libc::SYS_fcntl),
        syscall(libc::SYS_ftruncate),
        syscall(libc::SYS_readlinkat),
        syscall(libc::SYS_faccessat2),
        // === Signals ===
        syscall(libc::SYS_rt_sigaction),
        syscall(libc::SYS_rt_sigprocmask),
        syscall(libc::SYS_rt_sigreturn),
        syscall(libc::SYS_sigaltstack),
        // === Threading ===
        syscall(libc::SYS_futex),
        syscall(libc::SYS_clone3),
        syscall(libc::SYS_set_robust_list),
        syscall(libc::SYS_rseq),
        syscall(libc::SYS_sched_yield),
        syscall(libc::SYS_sched_getaffinity),
        // === Time ===
        syscall(libc::SYS_clock_gettime),
        syscall(libc::SYS_clock_nanosleep),
        syscall(libc::SYS_nanosleep),
        // === Process info ===
        syscall(libc::SYS_getpid),
        syscall(libc::SYS_gettid),
        syscall(libc::SYS_getuid),
        syscall(libc::SYS_geteuid),
        syscall(libc::SYS_getgid),
        syscall(libc::SYS_getegid),
        // === Random ===
        syscall(libc::SYS_getrandom),
        // === Exit ===
        syscall(libc::SYS_exit),
        syscall(libc::SYS_exit_group),
        // === Pipes (used by crossbeam channels internally) ===
        syscall(libc::SYS_pipe2),
        syscall(libc::SYS_eventfd2),
        // === Misc ===
        syscall(libc::SYS_prctl),           // needed for seccomp itself
        syscall(libc::SYS_seccomp),         // needed for TSYNC
        syscall(libc::SYS_prlimit64),       // resource limits
        syscall(libc::SYS_sysinfo),         // system info queries
        syscall(libc::SYS_uname),           // used by various libs
        syscall(libc::SYS_tgkill),          // thread signaling
        syscall(libc::SYS_restart_syscall), // after signal interruption
        // === Clipboard (wayland/X11 via arboard) ===
        // Note: clipboard may not work under Landlock anyway (socket paths blocked),
        // but we allow the syscalls so failures are clean EACCES not EPERM.
        // SYS_socket is NOT listed here — it has an arg filter (AF_UNIX only)
        // applied separately in build_filter() to block AF_INET/AF_INET6.
        syscall(libc::SYS_connect),  // arboard connects to wayland/X11
        syscall(libc::SYS_sendmsg),  // wayland protocol
        syscall(libc::SYS_shutdown), // socket cleanup
        // === eBPF ring buffer reads (post-init) ===
        syscall(libc::SYS_perf_event_open), // eBPF perf buffer polling
        syscall(libc::SYS_bpf),             // eBPF map lookups at runtime
    ];

    // === Arch-specific syscalls ===

    // mmap: x86_64/aarch64 have SYS_mmap; 32-bit ARM uses SYS_mmap2
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    syscalls.push(syscall(libc::SYS_mmap));
    #[cfg(target_arch = "arm")]
    syscalls.push(syscall(libc::SYS_mmap2));

    // fstat: x86_64/aarch64 have SYS_newfstatat; 32-bit ARM uses SYS_fstatat64
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    syscalls.push(syscall(libc::SYS_newfstatat));
    #[cfg(target_arch = "arm")]
    syscalls.push(syscall(libc::SYS_fstatat64));

    // gettimeofday: not available on aarch64 (uses clock_gettime via vDSO)
    #[cfg(any(target_arch = "x86_64", target_arch = "arm"))]
    syscalls.push(syscall(libc::SYS_gettimeofday));

    // x86_64-only legacy syscalls (aarch64/arm use ppoll, pselect6, epoll_pwait)
    #[cfg(target_arch = "x86_64")]
    {
        syscalls.push(syscall(libc::SYS_poll));
        syscalls.push(syscall(libc::SYS_epoll_wait));
        syscalls.push(syscall(libc::SYS_select));
    }

    // 32-bit ARM needs additional syscalls for 64-bit file operations
    #[cfg(target_arch = "arm")]
    {
        syscalls.push(syscall(libc::SYS_fcntl64));
        syscalls.push(syscall(libc::SYS_ftruncate64));
        syscalls.push(syscall(libc::SYS__llseek));
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
        assert!(!syscalls.contains(&syscall(libc::SYS_execve)));
        assert!(!syscalls.contains(&syscall(libc::SYS_execveat)));
        assert!(!syscalls.contains(&syscall(libc::SYS_ptrace)));
        assert!(!syscalls.contains(&syscall(libc::SYS_mount)));
        assert!(!syscalls.contains(&syscall(libc::SYS_umount2)));
        assert!(!syscalls.contains(&syscall(libc::SYS_reboot)));
        assert!(!syscalls.contains(&syscall(libc::SYS_init_module)));
        assert!(!syscalls.contains(&syscall(libc::SYS_pivot_root)));
        assert!(!syscalls.contains(&syscall(libc::SYS_chroot)));
    }

    #[test]
    fn test_socket_not_in_unconditional_allowlist() {
        // SYS_socket should NOT be in the unconditional allowlist —
        // it has an AF_UNIX-only arg filter applied in build_filter()
        let syscalls = allowed_syscalls();
        assert!(
            !syscalls.contains(&syscall(libc::SYS_socket)),
            "SYS_socket should be filtered by argument, not unconditionally allowed"
        );
    }
}
