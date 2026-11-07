//! One UAC-approved capture session. No service, command runner, or elevated
//! pathname access. The desktop owns all pipes and opens every optional file.
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::fs::File;
use std::io::{Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{
    DUPLICATE_SAME_ACCESS, DuplicateHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, WAIT_OBJECT_0,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_MODE, FILE_TYPE_DISK, GetFileType, OPEN_EXISTING,
    SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
};
use windows::Win32::System::Console::{
    STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle,
};
use windows::Win32::System::Pipes::{GetNamedPipeServerProcessId, WaitNamedPipeW};
use windows::Win32::System::Threading::{
    ExitProcess, GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, WaitForSingleObject,
};

const MAX_REQUEST: usize = 4096;
const ACK: &[u8] = b"RUSTNET/1\n";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u32,
    interface: String,
    // Recording, country, ASN, city. Values refer only to the authenticated UI.
    files: [Option<u64>; 4],
}

pub(crate) struct Session {
    interface: String,
    files: [Option<File>; 4],
    ready: Arc<AtomicBool>,
}

fn raw(handle: &impl AsRawHandle) -> HANDLE {
    HANDLE(handle.as_raw_handle())
}

fn valid_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn decode_request(bytes: &[u8]) -> Result<Request> {
    ensure!(
        bytes.len() <= MAX_REQUEST,
        "Desktop request exceeds its limit"
    );
    let request: Request = serde_json::from_slice(bytes)?;
    ensure!(request.version == 1, "Unsupported desktop helper protocol");
    ensure!(
        request.interface.len() <= 1024 && !request.interface.contains('\0'),
        "Invalid capture interface"
    );
    for handle in request.files.iter().flatten() {
        // Never duplicate a pseudo-handle (in particular CURRENT_PROCESS=-1).
        ensure!(
            *handle > 0 && *handle <= isize::MAX as u64 && *handle % 4 == 0,
            "Invalid desktop file handle"
        );
    }
    Ok(request)
}

fn connect_pipe(id: &str, role: &str, pid: u32, access: u32) -> Result<File> {
    let name: Vec<u16> = format!(r"\\.\pipe\rustnet-desktop-{id}-{role}")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let deadline = Instant::now() + Duration::from_secs(10);
    let handle = loop {
        // Identification only: a pipe server must never impersonate the elevated engine.
        let result = unsafe {
            CreateFileW(
                windows::core::PCWSTR(name.as_ptr()),
                access,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                None,
            )
        };
        match result {
            Ok(handle) => break handle,
            Err(error) if Instant::now() >= deadline => return Err(error.into()),
            Err(_) => {
                unsafe {
                    let _ = WaitNamedPipeW(windows::core::PCWSTR(name.as_ptr()), 100);
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    };
    // SAFETY: CreateFileW transferred ownership of a valid synchronous handle.
    let file = unsafe { File::from_raw_handle(handle.0) };
    let mut server = 0;
    unsafe { GetNamedPipeServerProcessId(raw(&file), &mut server) }?;
    ensure!(
        server == pid,
        "Desktop pipe belongs to an unexpected process"
    );
    Ok(file)
}

fn duplicate_file(parent: &OwnedHandle, value: u64) -> Result<File> {
    let mut handle = HANDLE::default();
    // Copy only existing rights from the UI. Never request increased access,
    // close the source handle, or duplicate from the privileged current process.
    unsafe {
        DuplicateHandle(
            raw(parent),
            HANDLE(value as usize as *mut _),
            GetCurrentProcess(),
            &mut handle,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
    }?;
    let file = unsafe { File::from_raw_handle(handle.0) };
    ensure!(
        unsafe { GetFileType(raw(&file)) } == FILE_TYPE_DISK && file.metadata()?.is_file(),
        "Desktop handle must refer to a regular file"
    );
    Ok(file)
}

pub(crate) fn connect() -> Result<Option<Session>> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.get(1).is_none_or(|arg| arg != "--desktop-helper") {
        return Ok(None);
    }
    ensure!(args.len() == 4, "Invalid desktop helper arguments");
    ensure!(
        crate::is_admin(),
        "The capture helper requires UAC approval"
    );
    let id = args[2]
        .to_str()
        .filter(|id| valid_id(id))
        .context("Invalid desktop pipe identifier")?;
    let pid: u32 = args[3].to_str().context("Invalid desktop PID")?.parse()?;
    ensure!(pid != 0 && pid != std::process::id(), "Invalid desktop PID");
    let parent = unsafe {
        OpenProcess(
            PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            false,
            pid,
        )
    }?;
    let parent = unsafe { OwnedHandle::from_raw_handle(parent.0) };
    let mut input = connect_pipe(id, "control", pid, GENERIC_READ.0)?;
    let mut output = connect_pipe(id, "output", pid, GENERIC_WRITE.0)?;
    let diagnostics = connect_pipe(id, "diagnostics", pid, GENERIC_WRITE.0)?;
    // Keep standard handles valid until process exit, including main's error report.
    unsafe { SetStdHandle(STD_ERROR_HANDLE, HANDLE(diagnostics.into_raw_handle())) }?;

    let ready = Arc::new(AtomicBool::new(false));
    let watchdog_ready = ready.clone();
    // This Windows-only watchdog cannot process packets. Windows token/job
    // restrictions are process-wide and also cover this pre-startup thread.
    // Bound initialization, UI crashes, and a stuck graceful shutdown without
    // giving the medium-integrity UI permission to terminate elevated processes.
    let mut monitor = HANDLE::default();
    // The watchdog retains only wait rights, never PROCESS_DUP_HANDLE.
    unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            raw(&parent),
            GetCurrentProcess(),
            &mut monitor,
            PROCESS_SYNCHRONIZE.0,
            false,
            Default::default(),
        )
    }?;
    let monitor = unsafe { OwnedHandle::from_raw_handle(monitor.0) };
    std::thread::Builder::new()
        .name("desktop-watchdog".into())
        .spawn(move || {
            let started = Instant::now();
            let mut stopping = None;
            loop {
                if unsafe { WaitForSingleObject(raw(&monitor), 100) } == WAIT_OBJECT_0 {
                    crate::bootstrap::SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
                    std::thread::sleep(Duration::from_millis(100));
                }
                if crate::bootstrap::SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
                    let deadline = stopping.get_or_insert_with(Instant::now);
                    if deadline.elapsed() > Duration::from_secs(15) {
                        unsafe {
                            ExitProcess(1);
                        }
                    }
                }
                if !watchdog_ready.load(Ordering::Acquire)
                    && started.elapsed() > Duration::from_secs(30)
                {
                    unsafe {
                        ExitProcess(1);
                    }
                }
            }
        })?;

    let mut length = [0; 4];
    input.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    ensure!(length <= MAX_REQUEST, "Desktop request exceeds its limit");
    let mut bytes = vec![0; length];
    input.read_exact(&mut bytes)?;
    let request = decode_request(&bytes)?;
    let mut files: [Option<File>; 4] = [None, None, None, None];
    for (index, value) in request.files.into_iter().enumerate() {
        if let Some(value) = value {
            files[index] = Some(duplicate_file(&parent, value)?);
        }
    }
    // Acknowledge duplication before the UI releases its original file handles.
    output.write_all(ACK)?;
    unsafe {
        SetStdHandle(STD_INPUT_HANDLE, HANDLE(input.into_raw_handle()))?;
        SetStdHandle(STD_OUTPUT_HANDLE, HANDLE(output.into_raw_handle()))?;
    }
    Ok(Some(Session {
        interface: request.interface,
        files,
        ready,
    }))
}

impl Session {
    pub(crate) fn arguments(&self) -> Vec<String> {
        let mut args: Vec<String> = [
            "rustnet",
            "--headless",
            "--output",
            "jsonl-delta",
            "--headless-details",
            "full",
            "--capture-accounting",
            "--stop-on-stdin-close",
            "--include-historic",
            "--refresh-interval",
            "500",
            "--sandbox-strict",
            "--no-geoip",
            // Keep the privileged helper passive. Windows getnameinfo calls
            // cannot be cancelled and may outlive the shutdown deadline.
            // Observed DNS/SNI names still come from captured traffic.
            "--no-resolve-dns",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        if !self.interface.is_empty() {
            args.extend(["--interface".into(), self.interface.clone()]);
        }
        args
    }
    pub(crate) fn has_recording(&self) -> bool {
        self.files[0].is_some()
    }
    pub(crate) fn take_outputs(&mut self) -> crate::app::AppOutputHandles {
        crate::app::AppOutputHandles {
            pcapng_export: self.files[0].take(),
            ..Default::default()
        }
    }
    pub(crate) fn take_geoip(&mut self) -> Result<crate::network::geoip::GeoIpResolver> {
        Ok(crate::network::geoip::GeoIpResolver::from_preopened([
            self.files[1].take(),
            self.files[2].take(),
            self.files[3].take(),
        ])?)
    }
    pub(crate) fn ready(&self) {
        self.ready.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duplicated_inputs_keep_the_callers_read_only_access() {
        let path =
            std::env::temp_dir().join(format!("rustnet-helper-input-{}", std::process::id()));
        std::fs::write(&path, b"caller data").unwrap();
        let original = File::open(&path).unwrap();
        let parent = unsafe { OpenProcess(PROCESS_DUP_HANDLE, false, std::process::id()) }.unwrap();
        let parent = unsafe { OwnedHandle::from_raw_handle(parent.0) };
        let mut duplicate =
            duplicate_file(&parent, original.as_raw_handle() as usize as u64).unwrap();
        assert!(duplicate.write_all(b"changed").is_err());
        let mut contents = String::new();
        duplicate.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "caller data");
        drop(duplicate);
        drop(original);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_paths_commands_versions_and_pseudo_handles() {
        for value in [
            serde_json::json!({"version":2,"interface":"","files":[null,null,null,null]}),
            serde_json::json!({"version":1,"interface":"","files":[u64::MAX,null,null,null]}),
            serde_json::json!({"version":1,"interface":"","files":[0,null,null,null]}),
            serde_json::json!({"version":1,"interface":"","files":[null,null,null,null],"command":"cmd"}),
            serde_json::json!({"version":1,"interface":"","files":[null,null,null,null],"export":"C:\\Windows\\file"}),
            serde_json::json!({"version":1,"interface":"\u{0}","files":[null,null,null,null]}),
        ] {
            assert!(decode_request(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        assert!(decode_request(&vec![b' '; MAX_REQUEST + 1]).is_err());
        assert!(
            decode_request(br#"{"version":1,"interface":"","files":[null,null,null,null]}"#)
                .is_ok()
        );
        assert!(!valid_id("../pipe"));
        assert!(valid_id(&"a".repeat(64)));
    }

    #[test]
    fn desktop_capture_is_strict_passive_and_stops_on_controller_eof() {
        let session = Session {
            interface: String::new(),
            files: [None, None, None, None],
            ready: Arc::new(AtomicBool::new(false)),
        };
        let matches = crate::cli::build_cli()
            .try_get_matches_from(session.arguments())
            .unwrap();
        assert!(matches.get_flag("headless"));
        assert_eq!(matches.get_one::<String>("output").unwrap(), "jsonl-delta");
        assert!(matches.get_flag("sandbox-strict"));
        assert!(matches.get_flag("stop-on-stdin-close"));
        assert!(matches.get_flag("no-resolve-dns"));
        assert!(matches.get_flag("no-geoip"));
    }
}
