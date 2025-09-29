use anyhow::Result;
use std::{env, fs::File, path::PathBuf};

fn main() -> Result<()> {
    // Generate shell completions and manpage
    generate_assets()?;

    // Only compile eBPF programs on Linux when the feature is enabled
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

    // extract libraries
    let (packet_lib_path, wpcap_lib_path) = if cfg!(target_arch = "aarch64") {
        ("Lib/ARM64/Packet.lib", "Lib/ARM64/wpcap.lib")
    } else if cfg!(target_arch = "x86_64") {
        ("Lib/x64/Packet.lib", "Lib/x64/wpcap.lib")
    } else if cfg!(target_arch = "x86") {
        ("Lib/Packet.lib", "Lib/wpcap.lib")
    } else {
        panic!("Unsupported target!")
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
