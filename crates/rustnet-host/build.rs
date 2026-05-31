use anyhow::Result;
use std::env;

fn main() -> Result<()> {
    // Compile eBPF programs on Linux when the feature is enabled.
    // Check the TARGET/feature env vars (not cfg!) to handle cross-compilation.
    let target = env::var("TARGET").unwrap_or_default();
    if target.contains("linux") && env::var("CARGO_FEATURE_EBPF").is_ok() {
        compile_ebpf_programs();
    }

    println!("cargo:rerun-if-changed=src/linux/ebpf/programs/");
    println!("cargo:rerun-if-changed=resources/ebpf/vmlinux/");

    Ok(())
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn get_vmlinux_header(arch: &str) -> Result<std::path::PathBuf> {
    use std::path::PathBuf;
    // Use bundled vmlinux.h from this crate's resources directory.
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let bundled_dir = manifest_dir.join("resources/ebpf/vmlinux").join(arch);
    let bundled_file = bundled_dir.join("vmlinux.h");

    if bundled_file.exists() {
        println!("cargo:warning=Using bundled vmlinux.h for {}", arch);
        Ok(bundled_dir)
    } else {
        Err(anyhow::anyhow!(
            "Bundled vmlinux.h not found for architecture '{}'. Expected at: {}",
            arch,
            bundled_file.display()
        ))
    }
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn compile_ebpf_programs() {
    use libbpf_cargo::SkeletonBuilder;
    use std::ffi::OsStr;
    use std::path::PathBuf;

    let mut out = PathBuf::from(env::var("OUT_DIR").unwrap());
    out.push("socket_tracker.skel.rs");

    let src = "src/linux/ebpf/programs/socket_tracker.bpf.c";

    println!("cargo:warning=Building eBPF program using libbpf-cargo");

    // Get target architecture for cross-compilation
    let arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");

    // Map Rust arch names to eBPF target arch defines and vmlinux.h arch names
    let (target_arch_define, vmlinux_arch) = match arch.as_str() {
        "x86_64" => ("-D__TARGET_ARCH_x86", "x86"),
        "aarch64" => ("-D__TARGET_ARCH_arm64", "aarch64"),
        "arm" => ("-D__TARGET_ARCH_arm", "arm"),
        _ => ("-D__TARGET_ARCH_x86", "x86"), // fallback
    };

    // Get bundled architecture-specific vmlinux.h
    let vmlinux_include_path =
        get_vmlinux_header(vmlinux_arch).expect("Failed to locate bundled vmlinux.h");

    SkeletonBuilder::new()
        .source(src)
        .clang_args([
            OsStr::new("-I"),
            vmlinux_include_path.as_os_str(),
            OsStr::new(target_arch_define),
        ])
        .build_and_generate(&out)
        .unwrap();

    println!("cargo:rerun-if-changed={}", src);
}

#[cfg(not(all(target_os = "linux", feature = "ebpf")))]
fn compile_ebpf_programs() {
    // No-op when not on Linux or the eBPF feature is not enabled.
}
