use anyhow::Result;
use std::{env, fs::File, path::PathBuf};

fn main() -> Result<()> {
    generate_assets()?;

    setup_cross_compilation_libs();

    // A stock Npcap install keeps its DLLs under System32\Npcap, outside the
    // default loader search path. Delay-loading lets main() add that directory
    // before Windows resolves the imports.
    setup_windows_npcap_delay_load();

    #[cfg(target_os = "windows")]
    download_windows_npcap_sdk()?;

    embed_windows_manifest();

    println!("cargo:rerun-if-changed=src/cli.rs");

    Ok(())
}

/// Embed the UTF-8 active-code-page application manifest on MSVC Windows
/// targets, the only Windows toolchain releases ship. Two plain linker
/// flags, no build dependency; see the manifest file for why it exists.
/// The GNU toolchain would need a compiled resource object instead and is
/// deliberately left as-is (no manifest, today's behavior).
fn embed_windows_manifest() {
    let target = env::var("TARGET").unwrap_or_default();
    if !target.contains("windows-msvc") {
        return;
    }
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_default())
        .join("resources/packaging/windows/rustnet.exe.manifest");
    println!("cargo:rerun-if-changed={}", manifest.display());
    println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
    println!(
        "cargo:rustc-link-arg-bins=/MANIFESTINPUT:{}",
        manifest.display()
    );
}

include!("src/cli.rs");

fn setup_cross_compilation_libs() {
    let target = env::var("TARGET").unwrap_or_default();
    let host = env::var("HOST").unwrap_or_default();

    // Only apply hard-coded multiarch lib paths when actually cross-compiling.
    // On native builds (e.g. Homebrew on Linux arm64) these paths would shadow
    // package-manager-provided libraries and break linkage.
    if host == target {
        return;
    }

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
        "x86_64-unknown-freebsd" => {
            // FreeBSD uses libpcap from base system (in /usr/lib)
            // When cross-compiling, the sysroot should provide these
            println!("cargo:rustc-link-lib=pcap");
        }
        _ => {
            // For other targets, including native builds, let pkg-config handle it
        }
    }
}

fn setup_windows_npcap_delay_load() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();

    if target_os == "windows" && target_env == "msvc" {
        println!("cargo:rustc-link-arg=/DELAYLOAD:Packet.dll");
        println!("cargo:rustc-link-arg=/DELAYLOAD:wpcap.dll");
        println!("cargo:rustc-link-arg=/DEFAULTLIB:delayimp.lib");
    }
}

fn generate_assets() -> Result<()> {
    use clap::ValueEnum;
    use clap_complete::Shell;
    use clap_mangen::Man;

    let mut cmd = build_cli();

    let asset_dir: PathBuf = env::var_os("RUSTNET_ASSET_DIR")
        .or_else(|| env::var_os("OUT_DIR"))
        .ok_or_else(|| anyhow::anyhow!("OUT_DIR is unset"))?
        .into();

    for &shell in Shell::value_variants() {
        clap_complete::generate_to(shell, &mut cmd, "rustnet", &asset_dir)?;
    }

    let mut manpage_out = File::create(asset_dir.join("rustnet.1"))?;
    let manpage = Man::new(cmd);
    manpage.render(&mut manpage_out)?;

    Ok(())
}

#[cfg(target_os = "windows")]
fn download_windows_npcap_sdk() -> Result<()> {
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        io::{self, Write},
    };

    println!("cargo:rerun-if-changed=build.rs");

    const NPCAP_SDK: &str = "npcap-sdk-1.15.zip";
    const NPCAP_SDK_SHA256: &str =
        "52c7b9fb4abee3ad9fe739bb545c3efe77b731c8e127122bdf328eafdae3ed4f";

    let npcap_sdk_download_url = format!("https://npcap.com/dist/{NPCAP_SDK}");
    let cache_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?).join("target");
    let npcap_sdk_cache_path = cache_dir.join(NPCAP_SDK);

    let npcap_zip = match fs::read(&npcap_sdk_cache_path) {
        Ok(zip_data) => {
            eprintln!("Found cached npcap SDK");
            verify_npcap_checksum(&zip_data)?;
            zip_data
        }
        Err(_) => {
            eprintln!("Downloading npcap SDK");

            let mut zip_data = vec![];
            let _res = http_req::request::get(npcap_sdk_download_url, &mut zip_data)?;

            verify_npcap_checksum(&zip_data)?;

            fs::create_dir_all(cache_dir)?;
            let mut cache = fs::File::create(npcap_sdk_cache_path)?;
            cache.write_all(&zip_data)?;

            zip_data
        }
    };

    fn verify_npcap_checksum(data: &[u8]) -> Result<()> {
        let hash = Sha256::digest(data);
        let actual = hash.iter().map(|b| format!("{b:02x}")).collect::<String>();
        if actual != NPCAP_SDK_SHA256 {
            anyhow::bail!(
                "Npcap SDK checksum mismatch!\n  Expected: {}\n  Actual:   {}\n\
                 The downloaded file may be corrupted or tampered with.",
                NPCAP_SDK_SHA256,
                actual
            );
        }
        eprintln!("Npcap SDK checksum verified: {actual}");
        Ok(())
    }

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

    let mut packet_lib = archive.by_name(packet_lib_path)?;
    let lib_dir = PathBuf::from(env::var("OUT_DIR")?).join("npcap_sdk");
    fs::create_dir_all(&lib_dir)?;
    let packet_lib_dest = lib_dir.join("Packet.lib");
    let mut packet_file = fs::File::create(packet_lib_dest)?;
    io::copy(&mut packet_lib, &mut packet_file)?;
    drop(packet_lib);

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
