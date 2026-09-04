# rustnet-sandbox

Post-initialization sandboxing and root privilege dropping for
[rustnet](https://github.com/domcyrus/rustnet), usable by any front-end
(the TUI binary or a headless tool) built on the rustnet crates.

One `apply_sandbox(&SandboxConfig) -> Result<SandboxReport>` entry point with
a platform backend behind it:

- **Linux**: `PR_SET_NO_NEW_PRIVS`, capability drops (CAP_NET_RAW, CAP_BPF,
  CAP_PERFMON), the root uid drop, and Landlock filesystem/network/scope
  restrictions (behind the `landlock` feature).
- **macOS**: the root uid drop, then a Seatbelt profile restricting outbound
  network, credential reads, and writes under user home directories
  (behind the `macos-sandbox` feature).
- **Windows**: dangerous token privileges removed and a job object blocking
  child process creation.
- **FreeBSD**: the root uid drop (Capsicum is planned).

The `privdrop` module (Linux/macOS/FreeBSD) resolves the drop target from
`SUDO_UID`/`SUDO_GID` (falling back to `nobody`), chowns pre-created output
files to it, and performs the verified, irreversible drop.

Sandboxing is a post-initialization step: open capture handles, load eBPF
programs, and pre-create output files first, apply the sandbox on the main
thread, and only then spawn the worker threads that should inherit the
restrictions. See the crate docs for the full ordering contract.

RustNet retains its securely opened output descriptors across this transition
and passes an empty `write_paths` list. It does not reopen output paths after
sandboxing. Other library callers can explicitly configure path exceptions.

The crate deliberately depends on no other rustnet crate: callers pass in
paths and an optional drop target, nothing else.

`apply_sandbox_allowing_dns` adds a narrow exception when network restrictions
are enabled. Linux allows reads of the exact libc resolver files and TCP
connections only to destination port 53. Linux Landlock does not yet mediate
UDP. macOS allows outbound TCP and UDP only to destination port 53. All other
configured network restrictions remain active.
