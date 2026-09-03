//! Temporary-directory guard for filesystem tests.

use std::path::{Path, PathBuf};

/// Per-test scratch directory under the system temp dir, removed on drop.
pub(crate) struct ScratchDir(PathBuf);

impl ScratchDir {
    /// Create `<temp>/rustnet-<prefix>-test-<pid>-<tag>`, replacing any
    /// leftover tree from a previous run.
    pub(crate) fn new(prefix: &str, tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "rustnet-{}-test-{}-{}",
            prefix,
            std::process::id(),
            tag
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
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
