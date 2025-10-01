use anyhow::Result;
use std::{env, fs::File, path::PathBuf};

fn main() -> Result<()> {
    // Generate shell completions and manpage
    generate_assets()?;

    // Add library search paths for cross-compilation
    setup_cross_compilation_libs();

    // Compile eBPF programs on Linux when the feature is enabled
    if cfg!(target_os = "linux") && env::var("CARGO_FEATURE_EBPF").is_ok() {
        compile_ebpf_programs();
    }

    #[cfg(target_os = "windows")]
    download_windows_npcap_sdk()?;

    println!("cargo:rerun-if-changed=src/network/platform/linux_ebpf/programs/");
    println!("cargo:rerun-if-changed=src/cli.rs");

    Ok(())
}

include!("src/cli.rs");

fn setup_cross_compilation_libs() {
    let target = env::var("TARGET").unwrap_or_default();

    match target.as_str() {
        "aarch64-unknown-linux-gnu" => {
            println!("cargo:rustc-link-search=native=/usr/lib/aarch64-linux-gnu");
            println!("cargo:rustc-link-lib=elf");
            println!("cargo:rustc-link-lib=z");
        }
        "armv7-unknown-linux-gnueabihf" => {
            println!("cargo:rustc-link-search=native=/usr/lib/arm-linux-gnueabihf");
            println!("cargo:rustc-link-lib=elf");
            println!("cargo:rustc-link-lib=z");
        }
        _ => {
            // For other targets, including native builds, let pkg-config handle it
        }
    }
}

fn generate_assets() -> Result<()> {
    use clap::ValueEnum;
    use clap_complete::Shell;
    use clap_mangen::Man;

    let mut cmd = build_cli();

    // build into `RUSTNET_ASSET_DIR` with a fallback to `OUT_DIR`
    let asset_dir: PathBuf = env::var_os("RUSTNET_ASSET_DIR")
        .or_else(|| env::var_os("OUT_DIR"))
        .ok_or_else(|| anyhow::anyhow!("OUT_DIR is unset"))?
        .into();

    // completion
    for &shell in Shell::value_variants() {
        clap_complete::generate_to(shell, &mut cmd, "rustnet", &asset_dir)?;
    }

    // manpage
    let mut manpage_out = File::create(asset_dir.join("rustnet.1"))?;
    let manpage = Man::new(cmd);
    manpage.render(&mut manpage_out)?;

    Ok(())
}

#[cfg(target_os = "windows")]
fn download_windows_npcap_sdk() -> Result<()> {
    use std::{
        fs,
        io::{self, Write},
    };

    println!("cargo:rerun-if-changed=build.rs");

    // get npcap SDK
    const NPCAP_SDK: &str = "npcap-sdk-1.15.zip";

    let npcap_sdk_download_url = format!("https://npcap.com/dist/{NPCAP_SDK}");
    let cache_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?).join("target");
    let npcap_sdk_cache_path = cache_dir.join(NPCAP_SDK);

    let npcap_zip = match fs::read(&npcap_sdk_cache_path) {
        // use cached
        Ok(zip_data) => {
            eprintln!("Found cached npcap SDK");
            zip_data
        }
        // download SDK
        Err(_) => {
            eprintln!("Downloading npcap SDK");

            // download
            let mut zip_data = vec![];
            let _res = http_req::request::get(npcap_sdk_download_url, &mut zip_data)?;

            // write cache
            fs::create_dir_all(cache_dir)?;
            let mut cache = fs::File::create(npcap_sdk_cache_path)?;
            cache.write_all(&zip_data)?;

            zip_data
        }
    };

    // extract libraries based on target architecture
    let target = env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    let (packet_lib_path, wpcap_lib_path) = if target.contains("aarch64") {
        ("Lib/ARM64/Packet.lib", "Lib/ARM64/wpcap.lib")
    } else if target.contains("x86_64") {
        ("Lib/x64/Packet.lib", "Lib/x64/wpcap.lib")
    } else if target.contains("i686") || target.contains("i586") {
        ("Lib/Packet.lib", "Lib/wpcap.lib")
    } else {
        panic!("Unsupported target: {}", target)
    };

    let mut archive = zip::ZipArchive::new(io::Cursor::new(npcap_zip))?;

    // Extract Packet.lib
    let mut packet_lib = archive.by_name(packet_lib_path)?;
    let lib_dir = PathBuf::from(env::var("OUT_DIR")?).join("npcap_sdk");
    fs::create_dir_all(&lib_dir)?;
    let packet_lib_dest = lib_dir.join("Packet.lib");
    let mut packet_file = fs::File::create(packet_lib_dest)?;
    io::copy(&mut packet_lib, &mut packet_file)?;
    drop(packet_lib);

    // Extract wpcap.lib
    let mut wpcap_lib = archive.by_name(wpcap_lib_path)?;
    let wpcap_lib_dest = lib_dir.join("wpcap.lib");
    let mut wpcap_file = fs::File::create(wpcap_lib_dest)?;
    io::copy(&mut wpcap_lib, &mut wpcap_file)?;

    println!(
        "cargo:rustc-link-search=native={}",
        lib_dir
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("{lib_dir:?} is not valid UTF-8"))?
    );

    Ok(())
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn download_vmlinux_header(arch: &str) -> Result<PathBuf> {
    use std::fs;
    use std::io::Write;

    // Cache directory in OUT_DIR
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let cache_dir = out_dir.join("vmlinux_headers").join(arch);
    let vmlinux_file = cache_dir.join("vmlinux.h");

    // Return cached version if it exists
    if vmlinux_file.exists() {
        println!("cargo:warning=Using cached vmlinux.h for {}", arch);
        return Ok(cache_dir);
    }

    // Download from libbpf/vmlinux.h repository
    let url = format!(
        "https://raw.githubusercontent.com/libbpf/vmlinux.h/main/include/{}/vmlinux.h",
        arch
    );

    println!("cargo:warning=Downloading vmlinux.h for {} from {}", arch, url);

    // Create cache directory
    fs::create_dir_all(&cache_dir)?;

    // Download the file using http_req
    let mut content = Vec::new();
    let _res = http_req::request::get(url, &mut content)?;

    // Write to cache
    let mut file = fs::File::create(&vmlinux_file)?;
    file.write_all(&content)?;

    println!("cargo:warning=Downloaded and cached vmlinux.h for {}", arch);

    Ok(cache_dir)
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn compile_ebpf_programs() {
    use libbpf_cargo::SkeletonBuilder;
    use std::ffi::OsStr;
    use std::path::PathBuf;

    let mut out = PathBuf::from(env::var("OUT_DIR").unwrap());
    out.push("socket_tracker.skel.rs");

    let src = "src/network/platform/linux_ebpf/programs/socket_tracker.bpf.c";

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

    // Download architecture-specific vmlinux.h if not cached
    let vmlinux_include_path = download_vmlinux_header(vmlinux_arch)
        .expect("Failed to download vmlinux.h");

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
    // No-op when not on Linux or eBPF feature is not enabled
}

