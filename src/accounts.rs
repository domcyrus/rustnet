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
static HEADLESS_NAMES: OnceLock<Option<background::AccountNames>> = OnceLock::new();

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

/// Headless projection must never wait for a directory service. A single
/// process-wide worker bounds outstanding lookups even across repeated runs.
/// It starts on first use, after the frontend's sandbox transition, and is
/// deliberately detached because libc account lookups cannot be cancelled.
pub(crate) fn format_user_group_nonblocking(uid: u32, gid: Option<u32>) -> String {
    #[cfg(unix)]
    {
        if let Some(names) = HEADLESS_NAMES.get_or_init(|| background::AccountNames::start().ok()) {
            return names.format(uid, gid);
        }
    }
    user_group_label(uid, gid, None, None)
}

#[cfg(unix)]
mod background {
    use super::*;
    use std::sync::{Arc, mpsc};

    const QUEUE_CAPACITY: usize = 64;
    const CACHE_CAPACITY: usize = 4096;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub(super) enum Account {
        User(u32),
        Group(u32),
    }

    pub(super) struct AccountNames {
        // None covers both pending and failed lookups, preventing duplicates.
        names: Arc<Mutex<HashMap<Account, Option<String>>>>,
        requests: mpsc::SyncSender<Account>,
    }

    impl AccountNames {
        pub(super) fn start() -> std::io::Result<Self> {
            Self::with_resolver(|account| match account {
                Account::User(uid) => resolve_user_name(uid),
                Account::Group(gid) => resolve_group_name(gid),
            })
        }

        fn with_resolver(
            resolve: impl Fn(Account) -> Option<String> + Send + 'static,
        ) -> std::io::Result<Self> {
            let names = Arc::new(Mutex::new(HashMap::new()));
            let cache = Arc::clone(&names);
            let (requests, receiver) = mpsc::sync_channel(QUEUE_CAPACITY);
            std::thread::Builder::new()
                .name("account-names".into())
                .spawn(move || {
                    for account in receiver {
                        // Never hold the cache lock across an NSS call.
                        let name = resolve(account);
                        cache
                            .lock()
                            .unwrap_or_else(|error| error.into_inner())
                            .insert(account, name);
                    }
                })?;
            Ok(Self { names, requests })
        }

        fn get(&self, account: Account) -> Option<String> {
            // Cache contention, queue saturation, spawn failure and lookup
            // failure all leave a usable numeric label on the control thread.
            let mut names = self.names.try_lock().ok()?;
            if let Some(name) = names.get(&account) {
                return name.clone();
            }
            if names.len() < CACHE_CAPACITY {
                names.insert(account, None);
                if self.requests.try_send(account).is_err() {
                    // Retry on a later snapshot once there is queue capacity.
                    names.remove(&account);
                }
            }
            None
        }

        pub(super) fn format(&self, uid: u32, gid: Option<u32>) -> String {
            user_group_label(
                uid,
                gid,
                self.get(Account::User(uid)),
                gid.and_then(|gid| self.get(Account::Group(gid))),
            )
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::time::Duration;

        #[test]
        fn full_headless_shutdown_does_not_wait_for_account_names() {
            use std::process::{Command, Stdio};
            use std::sync::atomic::AtomicBool;
            use std::time::Instant;

            use crate::app::{App, Config};
            use crate::headless::{HeadlessFormat, HeadlessOptions};

            const CHILD: &str = "RUSTNET_TEST_STALLED_ACCOUNT_LOOKUP";
            if std::env::var_os(CHILD).is_none() {
                // Isolate the injected process-wide cache from other tests.
                let mut child = Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "accounts::background::tests::full_headless_shutdown_does_not_wait_for_account_names",
                        "--nocapture",
                    ])
                    .env(CHILD, "1")
                    .stdout(Stdio::null())
                    .spawn()
                    .unwrap();
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    if let Some(status) = child.try_wait().unwrap() {
                        assert!(status.success(), "headless shutdown regression: {status}");
                        return;
                    }
                    if Instant::now() >= deadline {
                        child.kill().unwrap();
                        child.wait().unwrap();
                        panic!("headless shutdown waited for account lookup");
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }

            let (entered_tx, entered_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel::<()>();
            let names = AccountNames::with_resolver(move |_| {
                let _ = entered_tx.send(());
                let _ = release_rx.recv();
                Some("resolved".into())
            })
            .unwrap();
            HEADLESS_NAMES.set(Some(names)).ok().unwrap();
            for format in [
                HeadlessFormat::Json,
                HeadlessFormat::JsonLines,
                HeadlessFormat::JsonLinesDelta,
            ] {
                for signal in [false, true] {
                    let mut app = App::new(Config {
                        resolve_dns: false,
                        disable_geoip: true,
                        ..Config::default()
                    })
                    .unwrap();
                    // Seed an already-drained final snapshot, so both live and
                    // terminal projection exercise the same unresolved owner.
                    assert_eq!(app.stop().timed_out_workers, 0);
                    let mut connection = crate::test_support::local_tcp(45000, "client");
                    connection.process_uid = Some(42);
                    app.set_connections_snapshot_for_test(vec![connection]);
                    let output = Arc::new(Mutex::new(Vec::new()));
                    let report = crate::headless::run(
                        &mut app,
                        CapturedOutput(Arc::clone(&output)),
                        &HeadlessOptions {
                            full_details: true,
                            format,
                            duration: (!signal).then_some(Duration::ZERO),
                            ..HeadlessOptions::default()
                        },
                        &AtomicBool::new(signal),
                    )
                    .unwrap();
                    assert_eq!(report.timed_out_workers, 0);
                    let bytes = output.lock().unwrap();
                    let terminal = bytes
                        .split(|byte| *byte == b'\n')
                        .rfind(|line| !line.is_empty())
                        .unwrap();
                    let record: serde_json::Value = serde_json::from_slice(terminal).unwrap();
                    assert_eq!(record["connections"][0]["process"]["user_group"], "42");
                    assert_eq!(
                        record["runtime"]["termination_reason"],
                        if signal {
                            "shutdown_requested"
                        } else {
                            "duration_elapsed"
                        }
                    );
                }
            }
            entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
            drop(release_tx);
        }

        struct CapturedOutput(Arc<Mutex<Vec<u8>>>);

        impl std::io::Write for CapturedOutput {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                std::io::Write::write(&mut *self.0.lock().unwrap(), bytes)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        #[test]
        fn stalled_lookup_keeps_projection_and_drop_nonblocking() {
            let (entered_tx, entered_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel::<()>();
            let names = AccountNames::with_resolver(move |account| {
                let _ = entered_tx.send(account);
                let _ = release_rx.recv();
                Some("resolved".into())
            })
            .unwrap();
            assert_eq!(names.format(42, None), "42");
            assert_eq!(
                entered_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
                Account::User(42)
            );

            let (done_tx, done_rx) = mpsc::channel();
            let caller = std::thread::spawn(move || {
                for _ in 0..100 {
                    assert_eq!(names.format(42, Some(43)), "42:43");
                }
                // Fill the queue while the first lookup is still stalled.
                for uid in 100..200 {
                    assert_eq!(names.format(uid, None), uid.to_string());
                }
                assert!(names.names.lock().unwrap().len() <= QUEUE_CAPACITY + 1);
                drop(names);
                done_tx.send(()).unwrap();
            });
            let finished = done_rx.recv_timeout(Duration::from_secs(1));
            // Always release the worker, including when the assertion fails.
            drop(release_tx);
            caller.join().unwrap();
            finished.expect("account lookup blocked projection or shutdown");
        }

        #[test]
        fn late_names_replace_numeric_labels_and_failures_are_cached() {
            let (calls_tx, calls_rx) = mpsc::channel();
            let names = AccountNames::with_resolver(move |account| {
                calls_tx.send(account).unwrap();
                match account {
                    Account::User(42) => Some("alice".into()),
                    Account::Group(43) => Some("staff".into()),
                    _ => None,
                }
            })
            .unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(1);
            while names.format(42, Some(43)) != "alice:staff" {
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(1));
            }
            for _ in 0..2 {
                calls_rx.recv_timeout(Duration::from_secs(1)).unwrap();
            }
            assert_eq!(names.format(44, None), "44");
            assert_eq!(
                calls_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
                Account::User(44)
            );
            for _ in 0..100 {
                assert_eq!(names.format(44, None), "44");
            }
            assert!(calls_rx.try_recv().is_err());
        }

        #[test]
        fn cache_contention_and_capacity_fall_back_to_numeric_ids() {
            let names = AccountNames::with_resolver(|_| None).unwrap();
            let mut cache = names.names.lock().unwrap();
            assert_eq!(names.format(42, Some(43)), "42:43");
            cache.extend((0..CACHE_CAPACITY as u32).map(|id| (Account::User(id), None)));
            drop(cache);
            assert_eq!(names.format(u32::MAX, None), u32::MAX.to_string());
            assert_eq!(names.names.lock().unwrap().len(), CACHE_CAPACITY);
        }
    }
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
