//! Secure pre-sandbox output-file opening shared by the binary and embedders.

use std::fs;
use std::io;
use std::path::Path;

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
    use super::{open_private_append_file, precreate_private_file};
    use crate::app::scratch_dir::ScratchDir;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(tag: &str) -> ScratchDir {
        ScratchDir::new("output", tag)
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
    fn rejects_hard_link_before_truncating_snapshot_output() {
        let dir = scratch("hard_link_truncate");
        let target = dir.join("target.json");
        let link = dir.join("snapshot.json");
        std::fs::write(&target, b"keep me").unwrap();
        std::fs::hard_link(&target, &link).unwrap();

        let error = precreate_private_file(&link).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(std::fs::read(target).unwrap(), b"keep me");
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
    fn snapshot_output_truncates_existing_content() {
        let dir = scratch("truncate");
        let path = dir.join("snapshot.json");
        std::fs::write(&path, b"stale content").unwrap();

        let mut file = precreate_private_file(&path).unwrap();
        write!(file, "fresh").unwrap();
        file.sync_all().unwrap();

        assert_eq!(std::fs::read(path).unwrap(), b"fresh");
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
