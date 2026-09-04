//! Secure pre-sandbox output-file opening shared by the binary and embedders.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::{AppOutputHandles, Config};

#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputKind {
    JsonLog,
    Pcap,
    PcapSidecar,
    PcapNg,
}

struct OpenedOutput {
    kind: OutputKind,
    path: PathBuf,
    file: fs::File,
    identity: (u64, u64),
}

impl OutputKind {
    fn label(self) -> &'static str {
        match self {
            Self::JsonLog => "JSON log",
            Self::Pcap => "PCAP",
            Self::PcapSidecar => "PCAP sidecar",
            Self::PcapNg => "PCAPNG",
        }
    }
}

fn output_paths(config: &Config) -> Vec<(OutputKind, PathBuf)> {
    let mut outputs = Vec::new();
    if let Some(path) = &config.json_log_file {
        outputs.push((OutputKind::JsonLog, PathBuf::from(path)));
    }
    if let Some(path) = &config.pcap_export_file {
        outputs.push((OutputKind::Pcap, PathBuf::from(path)));
        outputs.push((
            OutputKind::PcapSidecar,
            PathBuf::from(format!("{path}.connections.jsonl")),
        ));
    }
    if let Some(path) = &config.pcapng_export_file {
        outputs.push((OutputKind::PcapNg, PathBuf::from(path)));
    }
    outputs
}

/// Reject overlapping output destinations before any file is opened or
/// truncated. This pathname check is an early diagnostic; callers must use
/// [`prepare_output_handles`] to compare the opened file identities before
/// truncation, including aliases on case-insensitive filesystems.
pub fn validate_output_paths(config: &Config) -> io::Result<()> {
    let mut resolved = Vec::new();
    for (kind, path) in output_paths(config) {
        let label = kind.label();
        let identity = output_identity(&path)?;
        if let Some((other_label, other_path, _)) = resolved
            .iter()
            .find(|(_, _, other_identity)| other_identity == &identity)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{label} output '{}' overlaps {other_label} output '{}'",
                    path.display(),
                    Path::new(other_path).display(),
                ),
            ));
        }
        resolved.push((label, path, identity));
    }
    Ok(())
}

/// Securely open every output before truncating any of them.
///
/// Compare the actual opened files, including aliases created by filesystem
/// case folding, Unicode normalization, or pathname changes after preflight.
/// A failed open or overlapping descriptor leaves existing contents intact.
/// JSON logging appends; capture files and their sidecar start empty.
pub fn prepare_output_handles(config: &Config) -> io::Result<(AppOutputHandles, Option<fs::File>)> {
    let mut opened: Vec<OpenedOutput> = Vec::new();
    for (kind, path) in output_paths(config) {
        let file = open_private(&path, kind == OutputKind::JsonLog, false).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "failed to open {} output '{}': {error}",
                    kind.label(),
                    path.display()
                ),
            )
        })?;
        let identity = opened_file_identity(&file)?;
        if let Some(other) = opened.iter().find(|other| other.identity == identity) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} output '{}' overlaps {} output '{}'",
                    kind.label(),
                    path.display(),
                    other.kind.label(),
                    other.path.display(),
                ),
            ));
        }
        opened.push(OpenedOutput {
            kind,
            path,
            file,
            identity,
        });
    }

    for output in &opened {
        if output.kind != OutputKind::JsonLog {
            output.file.set_len(0)?;
        }
    }

    let mut handles = AppOutputHandles::default();
    let mut pcap = None;
    for output in opened {
        match output.kind {
            OutputKind::JsonLog => handles.json_log = Some(output.file),
            OutputKind::Pcap => pcap = Some(output.file),
            OutputKind::PcapSidecar => handles.pcap_sidecar = Some(output.file),
            OutputKind::PcapNg => handles.pcapng_export = Some(output.file),
        }
    }
    Ok((handles, pcap))
}

#[cfg(unix)]
fn opened_file_identity(file: &fs::File) -> io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata()?;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(windows)]
fn opened_file_identity(file: &fs::File) -> io::Result<(u64, u64)> {
    super::windows_output::file_identity(file)
}

#[cfg(not(any(unix, windows)))]
fn opened_file_identity(_file: &fs::File) -> io::Result<(u64, u64)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "output-file identity checks are unavailable on this platform",
    ))
}

fn output_identity(path: &Path) -> io::Result<PathBuf> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("output path is not a regular file: {}", path.display()),
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() != 1 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("output file has multiple hard links: {}", path.display()),
                    ));
                }
            }
            fs::canonicalize(path)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let name = path.file_name().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "output path has no file name")
            })?;
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty());
            Ok(fs::canonicalize(parent.unwrap_or_else(|| Path::new(".")))?.join(name))
        }
        Err(error) => Err(error),
    }
}

/// Create or truncate a private regular output file without following the
/// final path component when the platform exposes that control.
pub fn precreate_private_file(path: impl AsRef<Path>) -> io::Result<fs::File> {
    open_private(path, false, true)
}

/// Open a private regular output file for append without following the final
/// path component when the platform exposes that control.
pub fn open_private_append_file(path: impl AsRef<Path>) -> io::Result<fs::File> {
    open_private(path, true, false)
}

#[cfg(target_os = "windows")]
fn open_private(path: impl AsRef<Path>, append: bool, truncate: bool) -> io::Result<fs::File> {
    super::windows_output::open_private(path, append, truncate)
}

#[cfg(not(target_os = "windows"))]
fn open_private(path: impl AsRef<Path>, append: bool, truncate: bool) -> io::Result<fs::File> {
    let path = path.as_ref();
    let mut options = fs::OpenOptions::new();
    options.create(true).write(true);
    if append {
        options.append(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .mode(0o600);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("output path is not a regular file: {}", path.display()),
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.nlink() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("output file has multiple hard links: {}", path.display()),
            ));
        }
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }

    if truncate {
        file.set_len(0)?;
    }
    Ok(file)
}

#[cfg(test)]
mod staged_tests {
    use super::prepare_output_handles;
    use crate::app::Config;
    use crate::app::scratch_dir::ScratchDir;
    use std::fs;
    use std::io::Write;

    #[test]
    fn later_open_failure_preserves_every_existing_output() {
        let dir = ScratchDir::new("staged-output", "later_failure");
        let log = dir.join("events.jsonl");
        let capture = dir.join("capture.pcap");
        let sidecar = dir.join("capture.pcap.connections.jsonl");
        fs::write(&log, b"existing log").unwrap();
        fs::write(&capture, b"existing capture").unwrap();
        fs::write(&sidecar, b"existing sidecar").unwrap();
        let config = Config {
            json_log_file: Some(log.to_str().unwrap().to_owned()),
            pcap_export_file: Some(capture.to_str().unwrap().to_owned()),
            pcapng_export_file: Some(dir.path().to_str().unwrap().to_owned()),
            ..Config::default()
        };

        assert!(prepare_output_handles(&config).is_err());
        assert_eq!(fs::read(log).unwrap(), b"existing log");
        assert_eq!(fs::read(capture).unwrap(), b"existing capture");
        assert_eq!(fs::read(sidecar).unwrap(), b"existing sidecar");
    }

    #[test]
    fn descriptor_collision_preserves_existing_contents() {
        let dir = ScratchDir::new("staged-output", "existing_collision");
        let path = dir.join("output");
        fs::write(&path, b"existing data").unwrap();
        let config = Config {
            json_log_file: Some(path.to_str().unwrap().to_owned()),
            pcapng_export_file: Some(path.to_str().unwrap().to_owned()),
            ..Config::default()
        };

        let error = prepare_output_handles(&config).err().unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("overlaps"));
        assert_eq!(fs::read(path).unwrap(), b"existing data");
    }

    fn rejects_filesystem_alias(first: &str, second: &str, tag: &str) {
        let dir = ScratchDir::new("staged-output", tag);
        let first_path = dir.join(first);
        let second_path = dir.join(second);
        fs::write(&first_path, b"alias probe").unwrap();
        let aliases = fs::read(&second_path).is_ok_and(|bytes| bytes == b"alias probe");
        fs::remove_file(&first_path).unwrap();
        if !aliases {
            // This filesystem treats these names as distinct, so they are
            // valid separate destinations and do not exercise the alias case.
            return;
        }

        let capture = dir.join("existing.pcap");
        let sidecar = dir.join("existing.pcap.connections.jsonl");
        fs::write(&capture, b"preserved capture").unwrap();
        fs::write(&sidecar, b"preserved sidecar").unwrap();
        let config = Config {
            json_log_file: Some(first_path.to_str().unwrap().to_owned()),
            pcap_export_file: Some(capture.to_str().unwrap().to_owned()),
            pcapng_export_file: Some(second_path.to_str().unwrap().to_owned()),
            ..Config::default()
        };

        let error = prepare_output_handles(&config).err().unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("overlaps"));
        assert_eq!(fs::read(capture).unwrap(), b"preserved capture");
        assert_eq!(fs::read(sidecar).unwrap(), b"preserved sidecar");
    }

    #[test]
    fn new_case_aliases_do_not_truncate_an_earlier_output() {
        rejects_filesystem_alias("new-output", "NEW-OUTPUT", "case_alias");
    }

    #[test]
    fn new_unicode_aliases_do_not_truncate_an_earlier_output() {
        rejects_filesystem_alias("caf\u{e9}", "cafe\u{301}", "unicode_alias");
    }

    #[test]
    fn distinct_outputs_append_logs_and_truncate_capture_files() {
        let dir = ScratchDir::new("staged-output", "distinct");
        let log = dir.join("events.jsonl");
        let capture = dir.join("capture.pcap");
        let sidecar = dir.join("capture.pcap.connections.jsonl");
        let pcapng = dir.join("capture.pcapng");
        fs::write(&log, b"existing log").unwrap();
        for path in [&capture, &sidecar, &pcapng] {
            fs::write(path, b"old capture data").unwrap();
        }
        let config = Config {
            json_log_file: Some(log.to_str().unwrap().to_owned()),
            pcap_export_file: Some(capture.to_str().unwrap().to_owned()),
            pcapng_export_file: Some(pcapng.to_str().unwrap().to_owned()),
            ..Config::default()
        };

        let (mut handles, mut pcap) = prepare_output_handles(&config).unwrap();
        for path in [&capture, &sidecar, &pcapng] {
            assert!(fs::read(path).unwrap().is_empty());
        }
        handles
            .json_log
            .as_mut()
            .unwrap()
            .write_all(b" appended")
            .unwrap();
        pcap.as_mut().unwrap().write_all(b"new pcap").unwrap();
        handles
            .pcap_sidecar
            .as_mut()
            .unwrap()
            .write_all(b"new sidecar")
            .unwrap();
        handles
            .pcapng_export
            .as_mut()
            .unwrap()
            .write_all(b"new pcapng")
            .unwrap();
        assert_eq!(fs::read(log).unwrap(), b"existing log appended");
        assert_eq!(fs::read(capture).unwrap(), b"new pcap");
        assert_eq!(fs::read(sidecar).unwrap(), b"new sidecar");
        assert_eq!(fs::read(pcapng).unwrap(), b"new pcapng");
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::{open_private_append_file, validate_output_paths};
    use crate::app::Config;
    use crate::app::scratch_dir::ScratchDir;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(tag: &str) -> ScratchDir {
        ScratchDir::new("output", tag)
    }

    #[test]
    fn rejects_collision_with_generated_pcap_sidecar_without_truncating() {
        let dir = scratch("sidecar_collision");
        let capture = dir.join("capture.pcap");
        let sidecar = dir.join("capture.pcap.connections.jsonl");
        std::fs::write(&capture, b"existing capture").unwrap();
        std::fs::write(&sidecar, b"existing log").unwrap();
        let config = Config {
            json_log_file: Some(sidecar.to_str().unwrap().to_owned()),
            pcap_export_file: Some(capture.to_str().unwrap().to_owned()),
            ..Config::default()
        };

        let error = validate_output_paths(&config).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("PCAP sidecar"));
        assert_eq!(std::fs::read(capture).unwrap(), b"existing capture");
        assert_eq!(std::fs::read(sidecar).unwrap(), b"existing log");
    }

    #[test]
    fn rejects_new_output_collision_through_parent_alias() {
        let dir = scratch("parent_alias_collision");
        let actual = dir.join("actual");
        let alias = dir.join("alias");
        std::fs::create_dir(&actual).unwrap();
        std::os::unix::fs::symlink(&actual, &alias).unwrap();
        let config = Config {
            json_log_file: Some(actual.join("capture").to_str().unwrap().to_owned()),
            pcapng_export_file: Some(alias.join("capture").to_str().unwrap().to_owned()),
            ..Config::default()
        };

        let error = validate_output_paths(&config).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(!actual.join("capture").exists());
    }

    #[test]
    fn rejects_hard_link_before_opening_any_output() {
        let dir = scratch("preflight_hard_link");
        let target = dir.join("target");
        let alias = dir.join("alias");
        std::fs::write(&target, b"retain me").unwrap();
        std::fs::hard_link(&target, &alias).unwrap();
        let config = Config {
            json_log_file: Some(target.to_str().unwrap().to_owned()),
            pcapng_export_file: Some(alias.to_str().unwrap().to_owned()),
            ..Config::default()
        };

        assert!(validate_output_paths(&config).is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"retain me");
    }

    #[test]
    fn accepts_distinct_new_output_paths_without_creating_them() {
        let dir = scratch("distinct_outputs");
        let config = Config {
            json_log_file: Some(dir.join("events.jsonl").to_str().unwrap().to_owned()),
            pcap_export_file: Some(dir.join("capture.pcap").to_str().unwrap().to_owned()),
            pcapng_export_file: Some(dir.join("capture.pcapng").to_str().unwrap().to_owned()),
            ..Config::default()
        };

        validate_output_paths(&config).unwrap();
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn creates_file_with_0600_permissions() {
        let dir = scratch("perms");
        let path = dir.join("events.log");
        let file = open_private_append_file(&path).expect("fresh open should succeed");
        let mode = file.metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "new output must be created mode 0o600");
    }

    #[test]
    fn tightens_permissions_on_an_existing_file() {
        let dir = scratch("existing_perms");
        let path = dir.join("events.log");
        std::fs::write(&path, b"existing").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let file = open_private_append_file(&path).unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn rejects_hard_linked_outputs() {
        let dir = scratch("hard_link");
        let target = dir.join("target.log");
        let link = dir.join("events.log");
        std::fs::write(&target, b"existing").unwrap();
        std::fs::hard_link(&target, &link).unwrap();
        let error = open_private_append_file(&link).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn rejects_fifo_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let dir = scratch("fifo");
        let path = dir.join("events.pipe");
        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c_path` is a valid, nul-terminated path for this call.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        assert!(open_private_append_file(&path).is_err());
    }

    #[test]
    fn appends_rather_than_truncates() {
        let dir = scratch("append");
        let path = dir.join("events.log");
        writeln!(open_private_append_file(&path).unwrap(), "line1").unwrap();
        writeln!(open_private_append_file(&path).unwrap(), "line2").unwrap();
        assert_eq!(std::fs::read_to_string(path).unwrap(), "line1\nline2\n");
    }

    #[test]
    fn retained_descriptor_survives_inaccessible_parent() {
        let dir = scratch("retained");
        let path = dir.join("events.log");
        let mut file = open_private_append_file(&path).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o000)).unwrap();
        writeln!(file, "still writable").unwrap();
        file.sync_all().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(std::fs::read_to_string(path).unwrap(), "still writable\n");
    }

    #[test]
    fn refuses_symlinked_path() {
        let dir = scratch("symlink");
        let target = dir.join("real_target.log");
        let link = dir.join("evil.log");
        std::fs::write(&target, b"").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err =
            open_private_append_file(&link).expect_err("O_NOFOLLOW must refuse a symlinked path");
        assert_eq!(err.raw_os_error(), Some(libc::ELOOP));
        assert!(std::fs::read(&target).unwrap().is_empty());
    }
}
