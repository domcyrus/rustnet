//! Secure pre-sandbox output-file opening shared by the binary and embedders.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::Config;

/// Reject overlapping output destinations before any file is opened or
/// truncated. Secure descriptor opening still enforces the file-type and
/// link restrictions when each writer is created.
pub fn validate_output_paths(config: &Config) -> io::Result<()> {
    let mut outputs = Vec::new();
    if let Some(path) = &config.json_log_file {
        outputs.push(("JSON log", PathBuf::from(path)));
    }
    if let Some(path) = &config.pcap_export_file {
        outputs.push(("PCAP", PathBuf::from(path)));
        outputs.push((
            "PCAP sidecar",
            PathBuf::from(format!("{path}.connections.jsonl")),
        ));
    }
    if let Some(path) = &config.pcapng_export_file {
        outputs.push(("PCAPNG", PathBuf::from(path)));
    }

    let mut resolved = Vec::new();
    for (label, path) in outputs {
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
    open_private(path, false)
}

/// Open a private regular output file for append without following the final
/// path component when the platform exposes that control.
pub fn open_private_append_file(path: impl AsRef<Path>) -> io::Result<fs::File> {
    open_private(path, true)
}

#[cfg(target_os = "windows")]
fn open_private(path: impl AsRef<Path>, append: bool) -> io::Result<fs::File> {
    super::windows_output::open_private(path, append)
}

#[cfg(not(target_os = "windows"))]
fn open_private(path: impl AsRef<Path>, append: bool) -> io::Result<fs::File> {
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

    if !append {
        file.set_len(0)?;
    }
    Ok(file)
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
