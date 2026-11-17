//! Temporary-directory guard shared by application tests.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_SCRATCH: AtomicU64 = AtomicU64::new(0);

/// Per-test scratch directory under the system temp dir, removed on drop.
pub(crate) struct ScratchDir(PathBuf);

impl ScratchDir {
    /// Create an exclusive directory without replacing other tests' files.
    pub(crate) fn new(prefix: &str, tag: &str) -> Self {
        loop {
            let sequence = NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "rustnet-{prefix}-test-{}-{tag}-{sequence}",
                std::process::id(),
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create scratch directory {}: {error}", path.display()),
            }
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    pub(crate) fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        // Restore write access first so a test that tightened the directory
        // permissions does not leave the tree behind.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
        }
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn same_tag_directories_keep_independent_contents_and_lifetimes() {
    let first = ScratchDir::new("scratch", "same-tag");
    let file = first.join("keep.txt");
    std::fs::write(&file, b"keep").unwrap();
    let second = ScratchDir::new("scratch", "same-tag");
    let second_path = second.path().to_owned();
    assert_ne!(first.path(), second.path());
    drop(second);
    assert!(!second_path.exists());
    assert_eq!(std::fs::read(&file).unwrap(), b"keep");
    let first_path = first.path().to_owned();
    drop(first);
    assert!(!first_path.exists());
}
