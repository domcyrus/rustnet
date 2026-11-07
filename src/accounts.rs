//! Cached account labels shared by terminal and headless output.
#[cfg(unix)]
use std::{
    collections::HashMap,
    mem::MaybeUninit,
    ptr,
    sync::{Mutex, OnceLock},
};

#[cfg(unix)]
static USER_NAMES: OnceLock<Mutex<HashMap<u32, Option<String>>>> = OnceLock::new();
#[cfg(unix)]
static GROUP_NAMES: OnceLock<Mutex<HashMap<u32, Option<String>>>> = OnceLock::new();

#[cfg(unix)]
fn account_name_from_buffer(name: *const libc::c_char, buffer: &[libc::c_char]) -> Option<String> {
    if name.is_null() {
        return None;
    }

    let buffer_start = buffer.as_ptr() as usize;
    let buffer_end = buffer_start.checked_add(buffer.len())?;
    let name_address = name as usize;
    if !(buffer_start..buffer_end).contains(&name_address) {
        return None;
    }

    let name_start = name_address - buffer_start;
    let name_len = buffer[name_start..].iter().position(|byte| *byte == 0)?;
    let name_bytes: Vec<u8> = buffer[name_start..name_start + name_len]
        .iter()
        .map(|byte| byte.to_ne_bytes()[0])
        .collect();
    Some(String::from_utf8_lossy(&name_bytes).into_owned())
}

/// Resolve an account id to its name through a `getpwuid_r`-shaped libc call.
///
/// `name_of` projects the name pointer out of a resolved entry; the name
/// itself is read from `buffer` only after bounds validation.
#[cfg(unix)]
fn resolve_account_name<T>(
    id: u32,
    getter: unsafe extern "C" fn(
        u32,
        *mut T,
        *mut libc::c_char,
        libc::size_t,
        *mut *mut T,
    ) -> libc::c_int,
    name_of: fn(&T) -> *const libc::c_char,
) -> Option<String> {
    let mut buffer: Vec<libc::c_char> = vec![0; 1024];
    loop {
        let mut entry = MaybeUninit::<T>::uninit();
        let entry_ptr = entry.as_mut_ptr();
        let mut result = ptr::null_mut();
        // SAFETY: `entry` and `buffer` are writable for the sizes supplied,
        // and `result` is an out-pointer inspected only after a successful call.
        let status = unsafe {
            getter(
                id,
                entry_ptr,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            )
        };
        if status == 0 {
            if result != entry_ptr {
                return None;
            }
            // SAFETY: a successful lookup that returns `entry_ptr` initialized
            // the caller-owned entry.
            let entry = unsafe { entry.assume_init() };
            return account_name_from_buffer(name_of(&entry), &buffer);
        }
        if status != libc::ERANGE || buffer.len() >= 1024 * 1024 {
            return None;
        }
        buffer.resize(buffer.len() * 2, 0);
    }
}

#[cfg(unix)]
fn resolve_user_name(uid: u32) -> Option<String> {
    resolve_account_name(uid, libc::getpwuid_r, |entry: &libc::passwd| {
        entry.pw_name.cast_const()
    })
}

#[cfg(unix)]
fn resolve_group_name(gid: u32) -> Option<String> {
    resolve_account_name(gid, libc::getgrgid_r, |entry: &libc::group| {
        entry.gr_name.cast_const()
    })
}

/// Names are resolved once per id and cached for the process lifetime,
/// including failures. The first lookup can stall a frame on hosts backed by
/// directory services, and a later account rename stays stale; both are
/// acceptable for a capture session.
#[cfg(unix)]
fn cached_account_name(
    cache: &'static OnceLock<Mutex<HashMap<u32, Option<String>>>>,
    id: u32,
    resolve: fn(u32) -> Option<String>,
) -> Option<String> {
    let cache = cache.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(name) = cache.lock().expect("account name cache poisoned").get(&id) {
        return name.clone();
    }

    let name = resolve(id);
    cache
        .lock()
        .expect("account name cache poisoned")
        .insert(id, name.clone());
    name
}

fn user_group_label(
    uid: u32,
    gid: Option<u32>,
    user_name: Option<String>,
    group_name: Option<String>,
) -> String {
    let user = user_name.unwrap_or_else(|| uid.to_string());
    let Some(gid) = gid else {
        return user;
    };
    let group = group_name.unwrap_or_else(|| gid.to_string());
    format!("{user}:{group}")
}

pub(crate) fn format_user_group(uid: u32, gid: Option<u32>) -> String {
    #[cfg(unix)]
    let user_name = cached_account_name(&USER_NAMES, uid, resolve_user_name);
    #[cfg(not(unix))]
    let user_name = None;

    #[cfg(unix)]
    let group_name = gid.and_then(|gid| cached_account_name(&GROUP_NAMES, gid, resolve_group_name));
    #[cfg(not(unix))]
    let group_name = None;

    user_group_label(uid, gid, user_name, group_name)
}

#[cfg(test)]
mod tests {
    use super::{format_user_group, user_group_label};
    #[test]
    fn unknown_account_ids_fall_back_to_numbers() {
        assert_eq!(
            user_group_label(u32::MAX, Some(u32::MAX), None, None),
            "4294967295:4294967295"
        );
    }

    #[cfg(unix)]
    #[test]
    fn current_account_ids_resolve_to_names() {
        // SAFETY: these calls only read this process's effective credentials.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        let user = super::resolve_user_name(uid).expect("current user must resolve");
        let group = super::resolve_group_name(gid).expect("current group must resolve");

        assert_eq!(format_user_group(uid, Some(gid)), format!("{user}:{group}"));
    }

    #[cfg(all(target_os = "linux", feature = "landlock"))]
    #[test]
    fn current_account_ids_resolve_with_landlock_enforced() {
        use rustnet_sandbox::{SandboxConfig, SandboxMode, apply_sandbox};

        let result = apply_sandbox(&SandboxConfig {
            mode: SandboxMode::BestEffort,
            block_network: false,
            read_paths: vec![],
            drop_uid: None,
        })
        .expect("best-effort sandbox must apply without error");
        if !result.fs_restricted {
            return;
        }

        // SAFETY: these calls only read this process's effective credentials.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        assert!(
            super::resolve_user_name(uid).is_some(),
            "current user must resolve inside the sandbox"
        );
        assert!(
            super::resolve_group_name(gid).is_some(),
            "current group must resolve inside the sandbox"
        );
    }

    #[cfg(unix)]
    #[test]
    fn account_name_must_be_terminated_inside_the_supplied_buffer() {
        let buffer = [
            b'x' as libc::c_char,
            b'm' as libc::c_char,
            b'a' as libc::c_char,
            b'r' as libc::c_char,
            b'c' as libc::c_char,
            b'o' as libc::c_char,
            0,
        ];
        assert_eq!(
            super::account_name_from_buffer(buffer[1..].as_ptr(), &buffer).as_deref(),
            Some("marco")
        );

        let external = [b'x' as libc::c_char, 0];
        assert_eq!(
            super::account_name_from_buffer(external.as_ptr(), &buffer),
            None
        );
        assert_eq!(
            super::account_name_from_buffer(std::ptr::null(), &buffer),
            None
        );

        let unterminated = [b'n' as libc::c_char, b'o' as libc::c_char];
        assert_eq!(
            super::account_name_from_buffer(unterminated.as_ptr(), &unterminated),
            None
        );
    }
}
