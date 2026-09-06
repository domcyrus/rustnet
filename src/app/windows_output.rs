//! Secure Windows output-file opening.
//!
//! Windows has no mode-bit equivalent to Unix `0o600`. This module creates a
//! protected DACL containing one full-control ACE for the current token user,
//! supplies it to `CreateFileW`, and reapplies it through the opened handle so
//! pre-existing files owned by the current user are hardened without a
//! pathname race.

use std::fs::File;
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;

use windows::Win32::Foundation::{
    CloseHandle, ERROR_SUCCESS, GENERIC_WRITE, HANDLE, HLOCAL, LocalFree,
};
use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT, SetSecurityInfo};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, AddAccessAllowedAce, DACL_SECURITY_INFORMATION,
    EqualSid, GetLengthSid, GetTokenInformation, InitializeAcl, InitializeSecurityDescriptor,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, SetSecurityDescriptorOwner, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_GENERIC_WRITE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA,
    GetFileInformationByHandle, OPEN_ALWAYS, READ_CONTROL, WRITE_DAC,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::PCWSTR;

/// Open an output file with access restricted to the current token user.
///
/// Existing files are not truncated until their type, link count, and owner
/// have been validated and the protected DACL has been applied. Reparse points
/// and multiply-linked files are rejected.
pub fn open_private(path: impl AsRef<Path>, append: bool) -> io::Result<File> {
    let path = path.as_ref();
    let path_wide = wide_path(path)?;
    let mut security = PrivateSecurity::for_current_user()?;
    let attributes = security.attributes();

    let desired_access = if append {
        FILE_GENERIC_WRITE.0 & !FILE_WRITE_DATA.0
    } else {
        GENERIC_WRITE.0
    } | WRITE_DAC.0
        | READ_CONTROL.0;

    let raw_handle = unsafe {
        CreateFileW(
            PCWSTR(path_wide.as_ptr()),
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            Some(&attributes),
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|error| windows_error("CreateFileW", error))?;

    let file = unsafe { File::from_raw_handle(raw_handle.0) };
    validate_file(&file, path)?;
    validate_owner(&file, path, security.user_sid())?;
    security.apply_to(&file)?;

    if !append {
        file.set_len(0)?;
    }

    Ok(file)
}

fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    let mut path_wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if path_wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "output path contains a NUL character",
        ));
    }
    path_wide.push(0);
    Ok(path_wide)
}

fn validate_file(file: &File, path: &Path) -> io::Result<()> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe {
        GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut info)
            .map_err(|error| windows_error("GetFileInformationByHandle", error))?;
    }

    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("output path is a reparse point: {}", path.display()),
        ));
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("output path is not a regular file: {}", path.display()),
        ));
    }
    if info.nNumberOfLinks != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("output file has multiple hard links: {}", path.display()),
        ));
    }

    Ok(())
}

fn validate_owner(file: &File, path: &Path, expected_owner: PSID) -> io::Result<()> {
    let mut owner = PSID::default();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let status = unsafe {
        GetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            Some(&mut descriptor),
        )
    };
    let _descriptor = OwnedLocalDescriptor(descriptor);
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status.0 as i32));
    }

    if owner.is_invalid() || unsafe { EqualSid(owner, expected_owner) }.is_err() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "output file is not owned by the current user: {}",
                path.display()
            ),
        ));
    }

    Ok(())
}

struct PrivateSecurity {
    // The descriptor and ACL contain pointers into these heap allocations.
    // Keep both allocations alive until CreateFileW and apply_to complete.
    sid_storage: Vec<usize>,
    _acl_storage: Vec<usize>,
    descriptor: SECURITY_DESCRIPTOR,
}

impl PrivateSecurity {
    fn for_current_user() -> io::Result<Self> {
        let mut token = HANDLE::default();
        unsafe {
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
                .map_err(|error| windows_error("OpenProcessToken", error))?;
        }
        let token = OwnedHandle(token);

        let mut required = 0;
        let size_probe = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut required) };
        if required == 0 {
            return Err(match size_probe {
                Ok(()) => io::Error::other("GetTokenInformation returned an empty user SID"),
                Err(error) => windows_error("GetTokenInformation size query", error),
            });
        }

        let sid_words = (required as usize).div_ceil(size_of::<usize>());
        let mut sid_storage = vec![0usize; sid_words];
        unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                Some(sid_storage.as_mut_ptr().cast()),
                required,
                &mut required,
            )
            .map_err(|error| windows_error("GetTokenInformation", error))?;
        }

        let sid = unsafe { sid_storage.as_ptr().cast::<TOKEN_USER>().read().User.Sid };
        if sid.is_invalid() {
            return Err(io::Error::other(
                "GetTokenInformation returned an invalid user SID",
            ));
        }

        let sid_length = unsafe { GetLengthSid(sid) as usize };
        let acl_bytes =
            size_of::<ACL>() + size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>() + sid_length;
        let acl_words = acl_bytes.div_ceil(size_of::<usize>());
        let mut acl_storage = vec![0usize; acl_words];
        let acl = acl_storage.as_mut_ptr().cast::<ACL>();
        unsafe {
            InitializeAcl(acl, acl_bytes as u32, ACL_REVISION)
                .map_err(|error| windows_error("InitializeAcl", error))?;
            AddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS.0, sid)
                .map_err(|error| windows_error("AddAccessAllowedAce", error))?;
        }

        let mut descriptor = SECURITY_DESCRIPTOR::default();
        let descriptor_ptr =
            PSECURITY_DESCRIPTOR((&mut descriptor as *mut SECURITY_DESCRIPTOR).cast());
        unsafe {
            InitializeSecurityDescriptor(descriptor_ptr, 1)
                .map_err(|error| windows_error("InitializeSecurityDescriptor", error))?;
            SetSecurityDescriptorOwner(descriptor_ptr, Some(sid), false)
                .map_err(|error| windows_error("SetSecurityDescriptorOwner", error))?;
            SetSecurityDescriptorDacl(descriptor_ptr, true, Some(acl), false)
                .map_err(|error| windows_error("SetSecurityDescriptorDacl", error))?;
            SetSecurityDescriptorControl(descriptor_ptr, SE_DACL_PROTECTED, SE_DACL_PROTECTED)
                .map_err(|error| windows_error("SetSecurityDescriptorControl", error))?;
        }

        Ok(Self {
            sid_storage,
            _acl_storage: acl_storage,
            descriptor,
        })
    }

    fn attributes(&mut self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: (&mut self.descriptor as *mut SECURITY_DESCRIPTOR).cast(),
            bInheritHandle: false.into(),
        }
    }

    fn user_sid(&self) -> PSID {
        unsafe {
            self.sid_storage
                .as_ptr()
                .cast::<TOKEN_USER>()
                .read()
                .User
                .Sid
        }
    }

    fn apply_to(&mut self, file: &File) -> io::Result<()> {
        let status = unsafe {
            SetSecurityInfo(
                HANDLE(file.as_raw_handle()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(self.descriptor.Dacl),
                None,
            )
        };
        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(status.0 as i32))
        }
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

struct OwnedLocalDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for OwnedLocalDescriptor {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0.0)));
            }
        }
    }
}

fn windows_error(operation: &str, error: windows::core::Error) -> io::Error {
    io::Error::other(format!("{operation} failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::{PrivateSecurity, open_private, validate_owner};
    use std::fs;
    use std::io::{self, Write};
    use std::mem::size_of;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use windows::Win32::Security::{CreateWellKnownSid, PSID, SECURITY_MAX_SID_SIZE, WinWorldSid};

    static NEXT_SCRATCH: AtomicU64 = AtomicU64::new(0);

    struct ScratchDir(PathBuf);

    impl ScratchDir {
        fn new(tag: &str) -> Self {
            let sequence = NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "rustnet-windows-output-{tag}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create scratch directory");
            Self(path)
        }

        fn join(&self, path: impl AsRef<Path>) -> PathBuf {
            self.0.join(path)
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn appends_without_truncating_existing_content() {
        let scratch = ScratchDir::new("append");
        let path = scratch.join("events.log");
        // Elevated tokens can default ordinary new files to Administrators
        // ownership. Seed this positive fixture with the required user owner.
        open_private(&path, false)
            .unwrap()
            .write_all(b"first\n")
            .unwrap();

        let mut file = open_private(&path, true).unwrap();
        writeln!(file, "second").unwrap();
        file.sync_all().unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"first\nsecond\n");
    }

    #[test]
    fn default_token_owner_cannot_bypass_user_ownership_check() {
        let scratch = ScratchDir::new("default-owner");
        let path = scratch.join("events.log");
        fs::write(&path, b"preserve on rejection").unwrap();
        let file = fs::File::open(&path).unwrap();
        let security = PrivateSecurity::for_current_user().unwrap();
        let owned_by_user = validate_owner(&file, &path, security.user_sid()).is_ok();
        drop(file);

        match open_private(&path, false) {
            Ok(_) => {
                assert!(owned_by_user);
                assert!(fs::read(&path).unwrap().is_empty());
            }
            Err(error) => {
                assert!(!owned_by_user);
                assert!(error.to_string().contains("not owned by the current user"));
                assert_eq!(fs::read(&path).unwrap(), b"preserve on rejection");
            }
        }
    }

    #[test]
    fn rejects_hard_links_without_truncating_the_target() {
        let scratch = ScratchDir::new("hard-link");
        let target = scratch.join("target.log");
        let link = scratch.join("events.log");
        fs::write(&target, b"keep me").unwrap();
        fs::hard_link(&target, &link).unwrap();

        let error = open_private(&link, false).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(fs::read(&target).unwrap(), b"keep me");
    }

    #[test]
    fn rejects_a_different_expected_owner() {
        let scratch = ScratchDir::new("owner");
        let path = scratch.join("events.log");
        let file = open_private(&path, false).unwrap();

        let sid_words = (SECURITY_MAX_SID_SIZE as usize).div_ceil(size_of::<usize>());
        let mut sid_storage = vec![0usize; sid_words];
        let world_sid = PSID(sid_storage.as_mut_ptr().cast());
        let mut sid_size = SECURITY_MAX_SID_SIZE;
        unsafe {
            CreateWellKnownSid(WinWorldSid, None, Some(world_sid), &mut sid_size).unwrap();
        }

        let error = validate_owner(&file, &path, world_sid).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
