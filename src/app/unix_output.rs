//! Descriptor-anchored opening of private output files on Unix.

use std::collections::VecDeque;
use std::ffi::{CString, OsStr, OsString};
use std::fs::{File, Permissions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

fn c_name(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "output path contains NUL"))
}

fn permitted_owner(uid: u32, invoking_uid: Option<u32>) -> bool {
    uid == unsafe { libc::geteuid() } || invoking_uid == Some(uid)
}

fn validate_directory(file: &File, invoking_uid: Option<u32>) -> io::Result<()> {
    let metadata = file.metadata()?;
    let owner = metadata.uid();
    let mode = metadata.mode();
    if !metadata.is_dir()
        || !(owner == 0 || permitted_owner(owner, invoking_uid))
        || ((mode & 0o022 != 0) && !(owner == 0 && mode & 0o1000 != 0))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "output directory is owned or writable by an untrusted user",
        ));
    }
    Ok(())
}

fn components(path: &Path) -> VecDeque<OsString> {
    path.components()
        .filter_map(|part| match part {
            Component::CurDir => None,
            _ => Some(part.as_os_str().to_os_string()),
        })
        .collect()
}

fn directory_flags() -> libc::c_int {
    // Traversal needs search permission, not read permission on each ancestor.
    #[cfg(target_os = "linux")]
    let access = libc::O_PATH;
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    let access = libc::O_SEARCH;
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
    let access = libc::O_RDONLY;
    access | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
}

fn open_root_dir() -> io::Result<File> {
    let root = c_name(OsStr::new("/"))?;
    // SAFETY: root is a terminated C string and open returns an owned descriptor.
    let fd = unsafe { libc::open(root.as_ptr(), directory_flags()) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: open returned a new, owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn open_dir_at(parent: &File, name: &OsStr) -> io::Result<File> {
    let name = c_name(name)?;
    // SAFETY: parent is an open directory and name is a terminated C string.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), directory_flags()) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: openat returned a new, owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn read_link_at(parent: &File, name: &OsStr) -> io::Result<PathBuf> {
    let name = c_name(name)?;
    let mut capacity = 256;
    loop {
        let mut bytes = vec![0u8; capacity];
        // SAFETY: the writable buffer and terminated name are valid for the call.
        let count = unsafe {
            libc::readlinkat(
                parent.as_raw_fd(),
                name.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        if (count as usize) < bytes.len() {
            bytes.truncate(count as usize);
            return Ok(PathBuf::from(OsStr::from_bytes(&bytes)));
        }
        capacity *= 2;
        if capacity > 65536 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "symlink is too long",
            ));
        }
    }
}

fn parent_dir(path: &Path, invoking_uid: Option<u32>) -> io::Result<(File, OsString)> {
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "output path has no file name")
    })?;
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut pending =
        components(absolute.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "output path has no parent")
        })?);
    let mut dir = open_root_dir()?;
    validate_directory(&dir, invoking_uid)?;
    let mut links = 0;
    while let Some(part) = pending.pop_front() {
        if part == OsStr::new("/") {
            dir = open_root_dir()?;
            continue;
        }
        let name = c_name(&part)?;
        // SAFETY: stat points to writable storage; name and descriptor are valid.
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        let rc = unsafe {
            libc::fstatat(
                dir.as_raw_fd(),
                name.as_ptr(),
                &mut stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        if stat.st_mode & libc::S_IFMT == libc::S_IFLNK {
            if !permitted_owner(stat.st_uid, invoking_uid) && stat.st_uid != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "output path crosses an untrusted symlink",
                ));
            }
            links += 1;
            if links > 40 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "too many symlinks",
                ));
            }
            let target = read_link_at(&dir, &part)?;
            for component in components(&target).into_iter().rev() {
                pending.push_front(component);
            }
            continue;
        }
        let next = open_dir_at(&dir, &part)?;
        validate_directory(&next, invoking_uid)?;
        dir = next;
    }
    Ok((dir, name.to_os_string()))
}

fn open_file_at(parent: &File, name: &OsStr, append: bool, exclusive: bool) -> io::Result<File> {
    let name = c_name(name)?;
    let mut flags =
        libc::O_WRONLY | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
    if append {
        flags |= libc::O_APPEND;
    }
    if exclusive {
        flags |= libc::O_EXCL;
    }
    // SAFETY: parent and name are valid; mode is used only when creating a file.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags, 0o600) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: openat returned a new, owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

pub(super) fn open_private(
    path: &Path,
    append: bool,
    truncate: bool,
    invoking_uid: Option<u32>,
) -> io::Result<File> {
    let (parent, name) = parent_dir(path, invoking_uid)?;
    let file = open_file_at(&parent, &name, append, false)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "output path is not a single-link regular file: {}",
                path.display()
            ),
        ));
    }
    if !permitted_owner(metadata.uid(), invoking_uid) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("output file has an untrusted owner: {}", path.display()),
        ));
    }
    file.set_permissions(Permissions::from_mode(0o600))?;
    if truncate {
        file.set_len(0)?;
    }
    Ok(file)
}

pub(super) fn create_diagnostic(path: &Path, invoking_uid: Option<u32>) -> io::Result<File> {
    let logs = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "diagnostic path has no directory",
        )
    })?;
    let (parent, name) = parent_dir(logs, invoking_uid)?;
    let name = c_name(&name)?;
    // SAFETY: parent and name are valid; an existing directory is checked below.
    let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists {
            return Err(error);
        }
    }
    let dir = open_dir_at(&parent, OsStr::from_bytes(name.as_bytes()))?;
    validate_directory(&dir, invoking_uid)?;
    let dot = c_name(OsStr::new("."))?;
    // SAFETY: dot resolves inside the retained directory, even for an O_PATH
    // or O_SEARCH descriptor that cannot be passed directly to fchmod.
    if unsafe { libc::fchmodat(dir.as_raw_fd(), dot.as_ptr(), 0o700, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "diagnostic path has no file name",
        )
    })?;
    let file = open_file_at(&dir, file_name, false, true)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || !permitted_owner(metadata.uid(), None) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "diagnostic file owner changed",
        ));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::{create_diagnostic, open_file_at, open_private, parent_dir};
    use crate::app::scratch_dir::ScratchDir;
    use std::fs::{self, Permissions};
    use std::io::{self, Write};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[test]
    fn search_only_ancestor_allows_output_and_diagnostic_creation() {
        let root = ScratchDir::new("output", "search-only-ancestor");
        let ancestor = root.join("search");
        let destination = ancestor.join("destination");
        fs::create_dir(&ancestor).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::set_permissions(&ancestor, Permissions::from_mode(0o111)).unwrap();
        let mut output = open_private(&destination.join("capture"), false, true, None).unwrap();
        output.write_all(b"capture").unwrap();
        let mut diagnostic =
            create_diagnostic(&destination.join("logs/expected.log"), None).unwrap();
        diagnostic.write_all(b"diagnostic").unwrap();
        fs::set_permissions(&ancestor, Permissions::from_mode(0o700)).unwrap();
        assert_eq!(fs::read(destination.join("capture")).unwrap(), b"capture");
        assert_eq!(
            fs::read(destination.join("logs/expected.log")).unwrap(),
            b"diagnostic"
        );
        assert_eq!(
            fs::metadata(destination.join("logs")).unwrap().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn diagnostic_file_is_exclusive_and_preserves_planted_content() {
        let root = ScratchDir::new("diagnostic", "exclusive");
        let path = root.join("logs/expected.log");
        fs::create_dir(root.join("logs")).unwrap();
        fs::write(&path, b"planted").unwrap();
        let error = create_diagnostic(&path, None).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(path).unwrap(), b"planted");
    }

    #[test]
    fn diagnostic_directory_symlink_is_rejected() {
        let root = ScratchDir::new("diagnostic", "symlink");
        let target = root.join("target");
        fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&target, root.join("logs")).unwrap();
        assert!(create_diagnostic(&root.join("logs/new.log"), None).is_err());
        assert!(!target.join("new.log").exists());
    }

    #[test]
    fn retained_parent_descriptor_survives_directory_swap() {
        let root = ScratchDir::new("diagnostic", "swap");
        let original = root.join("logs");
        let replacement = root.join("replacement");
        fs::create_dir(&original).unwrap();
        fs::create_dir(&replacement).unwrap();
        let (parent, name) = parent_dir(&original.join("capture"), None).unwrap();
        fs::rename(&original, root.join("saved")).unwrap();
        fs::rename(&replacement, &original).unwrap();
        let mut file = open_file_at(&parent, &name, false, true).unwrap();
        file.write_all(b"private").unwrap();
        assert_eq!(fs::read(root.join("saved/capture")).unwrap(), b"private");
        assert!(!original.join("capture").exists());
    }

    #[test]
    fn foreign_owned_output_is_rejected_before_chmod_or_truncate() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let root = ScratchDir::new("output", "foreign-owner");
        let path = root.join("capture");
        fs::write(&path, b"keep existing bytes").unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
        let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: the path is a valid, terminated C string in this process.
        assert_eq!(unsafe { libc::chown(c_path.as_ptr(), 2001, 2001) }, 0);
        let error = open_private(&path, false, true, None).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(fs::read(&path).unwrap(), b"keep existing bytes");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o644);
        assert_eq!(fs::metadata(&path).unwrap().uid(), 2001);
        let file = open_private(&path, false, true, Some(2001)).unwrap();
        assert_eq!(file.metadata().unwrap().uid(), 2001);
    }
}
