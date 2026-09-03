//! Temporary-directory guard shared by test modules in the library and the
//! binary. The bin target cannot see a `cfg(test)` module of the library, so
//! each test module includes this file directly with `#[path]`.

// Included from several test modules, and not every one uses every helper.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// Per-test scratch directory under the system temp dir, removed on drop.
pub(super) struct ScratchDir(PathBuf);

impl ScratchDir {
    /// Create `<temp>/rustnet-<prefix>-test-<pid>-<tag>`, replacing any
    /// leftover tree from a previous run.
    pub(super) fn new(prefix: &str, tag: &str) -> Self {
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

    pub(super) fn path(&self) -> &Path {
        &self.0
    }

    pub(super) fn join(&self, name: &str) -> PathBuf {
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
