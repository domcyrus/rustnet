use std::env;

fn main() {
    // Only compile eBPF programs on Linux when the feature is enabled
    if cfg!(target_os = "linux") && env::var("CARGO_FEATURE_EBPF").is_ok() {
        compile_ebpf_programs();
    }

    println!("cargo:rerun-if-changed=src/network/platform/linux_ebpf/programs/");
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn compile_ebpf_programs() {
    use libbpf_cargo::SkeletonBuilder;
    use std::path::PathBuf;

    let mut out = PathBuf::from(env::var("OUT_DIR").unwrap());
    out.push("socket_tracker.skel.rs");

    let src = "src/network/platform/linux_ebpf/programs/socket_tracker.bpf.c";

    println!("cargo:warning=Building eBPF program using libbpf-cargo");

    match SkeletonBuilder::new()
        .source(src)
        .clang_args([
            "-I/usr/include",
            "-I/usr/include/linux",
            "-I/usr/include/x86_64-linux-gnu",
            "-D__TARGET_ARCH_x86",
        ])
        .build_and_generate(&out)
    {
        Ok(_) => {
            println!("cargo:warning=eBPF skeleton generated successfully");
        }
        Err(e) => {
            println!("cargo:warning=Failed to build eBPF program: {}", e);

            // Create a placeholder skeleton file that compiles but returns None
            let placeholder_skeleton = r#"
// Placeholder skeleton for failed compilation
#[allow(dead_code)]
pub mod socket_tracker {
    use anyhow::Result;
    
    pub struct SocketTrackerSkel;
    
    impl SocketTrackerSkel {
        pub fn open() -> Result<Self> {
            Err(anyhow::anyhow!("eBPF compilation failed"))
        }
    }
}
"#;
            std::fs::write(&out, placeholder_skeleton).unwrap_or_else(|e| {
                println!(
                    "cargo:warning=Failed to create placeholder skeleton file: {}",
                    e
                );
            });
        }
    }

    println!("cargo:rerun-if-changed={}", src);
}

#[cfg(not(all(target_os = "linux", feature = "ebpf")))]
fn compile_ebpf_programs() {
    // No-op when not on Linux or eBPF feature is not enabled
}
