//! Optional cgroup-v2 socket-cookie correlation. This owns separate maps so
//! creator identity cannot overwrite attribution from a connect/accept probe.

use anyhow::{Context, Result};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use std::os::fd::AsRawFd;
use std::path::Path;

mod skeleton {
    include!(concat!(env!("OUT_DIR"), "/socket_tracker_cookie.skel.rs"));
}
use skeleton::*;

pub(super) struct SocketCookieTracker {
    // Detach before dropping the object or its backing allocation.
    _links: Vec<libbpf_rs::Link>,
    skel: Box<SocketTrackerCookieSkel<'static>>,
    _open_object: Box<std::mem::MaybeUninit<libbpf_rs::OpenObject>>,
}

impl SocketCookieTracker {
    pub(super) fn try_load() -> Option<Self> {
        // Normal file-capability installs deliberately do not grant NET_ADMIN.
        // A missing optional observer must never disable the tracing backend.
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let caps = status
            .lines()
            .find_map(|line| line.strip_prefix("CapEff:"))?;
        if u64::from_str_radix(caps.trim(), 16).ok()? & (1 << 12) == 0 {
            log::debug!("socket-cookie correlation unavailable: CAP_NET_ADMIN not effective");
            return None;
        }
        match Self::load_at(Path::new("/sys/fs/cgroup")) {
            Ok(tracker) => {
                log::info!("eBPF: enabled optional cgroup-v2 socket-cookie correlation");
                Some(tracker)
            }
            Err(error) => {
                log::debug!("socket-cookie correlation unavailable: {error:#}");
                None
            }
        }
    }

    fn load_at(path: &Path) -> Result<Self> {
        anyhow::ensure!(
            path.join("cgroup.controllers").exists(),
            "cgroup v2 unavailable"
        );
        let cgroup = std::fs::File::open(path).context("open cgroup v2 root")?;
        let mut open_object = Box::new(std::mem::MaybeUninit::uninit());
        let open_skel = SocketTrackerCookieSkelBuilder::default()
            .open(&mut open_object)
            .context("open cookie observer")?;
        let skel = open_skel.load().context("load cookie observer")?;
        let mut links = Vec::new();
        for program in [
            &skel.progs.cookie_socket_create,
            &skel.progs.cookie_socket_release,
            &skel.progs.cookie_connect4,
            &skel.progs.cookie_connect6,
            &skel.progs.cookie_sendmsg4,
            &skel.progs.cookie_sendmsg6,
            &skel.progs.cookie_packet_egress,
            &skel.progs.cookie_packet_ingress,
        ] {
            links.push(
                program
                    .attach_cgroup(cgroup.as_raw_fd())
                    .context("attach cookie observer")?,
            );
        }
        // SAFETY: The boxed allocation stays stable, and declaration order
        // drops the skeleton before its borrowed OpenObject allocation.
        let skel = unsafe {
            std::mem::transmute::<SocketTrackerCookieSkel<'_>, SocketTrackerCookieSkel<'static>>(
                skel,
            )
        };
        Ok(Self {
            _links: links,
            skel: Box::new(skel),
            _open_object: open_object,
        })
    }

    pub(super) fn socket_map(&self) -> &libbpf_rs::Map<'_> {
        &self.skel.maps.socket_map
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::ebpf::maps_libbpf::{ConnKey, MapReader};
    use libbpf_rs::MapCore;
    use std::io::{BufRead, BufReader, Write};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
    use std::process::{Command, Stdio};
    use std::time::Duration;

    #[test]
    fn unavailable_cgroup_is_an_optional_failure() {
        assert!(SocketCookieTracker::load_at(Path::new("/rustnet-nonexistent-cgroup")).is_err());
    }

    #[test]
    #[ignore = "helper process for socket-cookie tests"]
    fn cookie_receiver_child() {
        let Ok(ip) = std::env::var("RUSTNET_COOKIE_RECEIVER") else {
            return;
        };
        let ip: IpAddr = ip.parse().unwrap();
        let socket = UdpSocket::bind((ip, 0)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut cookie = 0_u64;
        let mut size = std::mem::size_of_val(&cookie) as libc::socklen_t;
        // SAFETY: The live socket and writable cookie/size have the sizes
        // required by SO_COOKIE. This retrieves the identity assigned by BPF.
        assert_eq!(
            unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_COOKIE,
                    std::ptr::from_mut(&mut cookie).cast(),
                    &mut size,
                )
            },
            0
        );
        println!(
            "COOKIE_ADDR={} COOKIE_ID={cookie}",
            socket.local_addr().unwrap()
        );
        std::io::stdout().flush().unwrap();
        let mut payload = [0; 16];
        assert_eq!(socket.recv_from(&mut payload).unwrap().0, 5);
        // The receiving process never sends, connects, or accepts a socket.
    }

    #[test]
    #[ignore = "requires root, eBPF and a writable private cgroup v2 mount"]
    fn socket_cookie_retains_receive_only_udp_owner() {
        let tracker = SocketCookieTracker::load_at(Path::new("/sys/fs/cgroup")).unwrap();
        for ip in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "linux::ebpf::cookie::tests::cookie_receiver_child",
                    "--nocapture",
                ])
                .env("RUSTNET_COOKIE_RECEIVER", ip.to_string())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let pid = child.id();
            let mut output = BufReader::new(child.stdout.take().unwrap());
            let line = loop {
                let mut line = String::new();
                assert_ne!(
                    output.read_line(&mut line).unwrap(),
                    0,
                    "child reports its socket"
                );
                if let Some((_, address)) = line.trim().split_once("COOKIE_ADDR=") {
                    break address.to_string();
                }
            };
            let (addr, cookie) = line.split_once(" COOKIE_ID=").unwrap();
            let addr: SocketAddr = addr.parse().unwrap();
            let cookie: u64 = cookie.parse().unwrap();
            assert_ne!(cookie, 0);
            let sender = UdpSocket::bind((ip, 0)).unwrap();
            let (level, option, bytes): (_, _, &[u8]) = if ip.is_ipv4() {
                // IPv4 options move the UDP header past the minimum IHL.
                (libc::IPPROTO_IP, libc::IP_OPTIONS, &[1, 1, 1, 0])
            } else {
                // One IPv6 destination-options header with a PadN option.
                (
                    libc::IPPROTO_IPV6,
                    libc::IPV6_DSTOPTS,
                    &[17, 0, 1, 4, 0, 0, 0, 0],
                )
            };
            // SAFETY: bytes is readable for the length supplied to setsockopt.
            assert_eq!(
                unsafe {
                    libc::setsockopt(
                        sender.as_raw_fd(),
                        level,
                        option,
                        bytes.as_ptr().cast(),
                        bytes.len() as libc::socklen_t,
                    )
                },
                0
            );
            sender.send_to(b"hello", addr).unwrap();
            assert!(child.wait().unwrap().success());
            let source = sender.local_addr().unwrap();
            let key = match ip {
                IpAddr::V4(ip) => ConnKey::new_v4(ip, ip, addr.port(), source.port(), false),
                IpAddr::V6(ip) => ConnKey::new_v6(ip, ip, addr.port(), source.port(), false),
            };
            let retained = MapReader::lookup_connection(tracker.socket_map(), key)
                .unwrap()
                .expect("packet tuple retains receive-only owner after exit");
            assert_eq!(retained.pid, pid);
            // Release drops live cookie ownership without deleting delayed attribution.
            assert!(
                tracker
                    .skel
                    .maps
                    .cookie_owners
                    .lookup(&cookie.to_ne_bytes(), libbpf_rs::MapFlags::empty())
                    .unwrap()
                    .is_none()
            );
        }
    }
}
