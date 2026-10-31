//! Run manually with the normal RustNet file capabilities on Linux.
//! Uses only loopback fixtures; does not change firewall or network policy.
#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use std::io::{BufRead, BufReader, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::Duration;
    let test_loss = std::env::args().any(|arg| arg == "--loss");
    let loss_filter = test_loss.then(load_loss_filter).transpose()?;
    let mut fixture = Command::new("python3");
    fixture
        .args(["-u", "-c", FIXTURE])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    if let Some(filter) = &loss_filter {
        let fd = filter.as_raw_fd();
        fixture.env("RUSTNET_DIAGNOSTICS_FILTER_FD", fd.to_string());
        // SAFETY: only the async-signal-safe fcntl call runs after fork. The
        // owned descriptor stays alive through spawn; only this child inherits it.
        unsafe {
            fixture.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let mut child = fixture.spawn()?;
    drop(loss_filter);
    let result = (|| -> anyhow::Result<()> {
        let mut input = child.stdin.take().context("fixture stdin")?;
        let mut output = BufReader::new(child.stdout.take().context("fixture stdout")?);
        let mut line = String::new();
        ensure!(
            output.read_line(&mut line)? > 0,
            "fixture exited before initial report; see fixture stderr"
        );
        let mut expected: serde_json::Value = serde_json::from_str(&line)?;
        let mut lookup = rustnet_host::create_process_lookup(false)?;
        let config = rustnet_sandbox::SandboxConfig {
            block_network: true,
            drop_uid: rustnet_sandbox::privdrop::resolve_drop_target(),
            ..Default::default()
        };
        println!("SANDBOX {:?}", rustnet_sandbox::apply_sandbox(&config)?);
        lookup.start_runtime()?;
        let status = std::fs::read_to_string("/proc/self/status")?;
        for field in ["CapEff:", "CapPrm:"] {
            let value = status
                .lines()
                .find(|line| line.starts_with(field))
                .context("capability status")?
                .split_whitespace()
                .nth(1)
                .context("capability bits")?;
            ensure!(
                u64::from_str_radix(value, 16)? == 0,
                "capabilities not dropped"
            );
        }
        let mut histories = std::collections::HashMap::new();
        let commands = ["initial", "late", "drain", "overflow", "loss", "closed"];
        for command in commands
            .into_iter()
            .filter(|command| *command != "loss" || test_loss)
        {
            if command != "initial" {
                writeln!(input, "{command}")?;
                input.flush()?;
                line.clear();
                ensure!(
                    output.read_line(&mut line)? > 0,
                    "fixture exited during {command}; see fixture stderr"
                );
                expected = serde_json::from_str(&line)?;
            }
            lookup.refresh()?;
            let snapshot = lookup.socket_snapshot();
            println!("{command}: {:?}", snapshot.diagnostics_status);
            for entry in expected["tcp"].as_array().context("TCP fixtures")? {
                let inode = entry["inode"].as_u64().context("inode")?;
                let sample = snapshot
                    .diagnostics
                    .values()
                    .find(|s| s.native_id == inode)
                    .context("missing TCP socket sample")?;
                let q = sample.queues.as_ref().context("missing queues")?;
                ensure!(
                    q.receive == entry["rx"].as_u64().unwrap(),
                    "TCP queue mismatch: {q:?}"
                );
                let tcp = sample.tcp.as_ref().context("missing TCP iterator sample")?;
                // TCP_INFO and iterator reads are sequential. During active loss,
                // counters may advance between them, so compare monotonically.
                if command == "loss" {
                    ensure!(
                        u64::from(tcp.retransmissions)
                            >= entry["retransmissions"].as_u64().unwrap(),
                        "retransmissions went backwards"
                    );
                } else {
                    ensure!(
                        u64::from(tcp.rtt_us) == entry["rtt"].as_u64().unwrap(),
                        "RTT mismatch"
                    );
                    ensure!(
                        u64::from(tcp.rtt_variation_us) == entry["rttvar"].as_u64().unwrap(),
                        "RTT variation mismatch"
                    );
                    ensure!(
                        tcp.congestion_window_segments.map(u64::from) == entry["cwnd"].as_u64(),
                        "cwnd mismatch"
                    );
                    ensure!(
                        u64::from(tcp.retransmissions)
                            == entry["retransmissions"].as_u64().unwrap(),
                        "TCP retransmission mismatch"
                    );
                }
                let history = rustnet_core::network::types::ConnectionDiagnostics::update(
                    histories.get(&inode),
                    std::sync::Arc::clone(sample),
                );
                if command == "loss" && entry["sending"].as_bool() == Some(true) {
                    ensure!(
                        tcp.retransmissions > 0 && q.send > 0,
                        "loss fixture must retransmit outstanding data"
                    );
                    ensure!(
                        history.retransmission_increase.is_some_and(|n| n > 0),
                        "missing retransmission delta"
                    );
                    ensure!(
                        history
                            .findings(std::time::SystemTime::now())
                            .iter()
                            .any(|s| s.contains("retransmissions increased")),
                        "missing finding"
                    );
                }
                histories.insert(inode, history);
                println!(
                    "TCP inode={inode} rx={} tx={} RTT={} cwnd={:?} retransmissions={} increase={:?}",
                    q.receive,
                    q.send,
                    tcp.rtt_us,
                    tcp.congestion_window_segments,
                    tcp.retransmissions,
                    histories[&inode].retransmission_increase
                );
            }
            if command == "overflow" {
                let inode = expected["udp"].as_u64().context("UDP inode")?;
                let drops = snapshot
                    .diagnostics
                    .values()
                    .find(|s| s.native_id == inode)
                    .and_then(|s| s.queues.as_ref())
                    .and_then(|q| q.socket_drops)
                    .context("missing UDP drops")?;
                ensure!(drops > 0, "UDP fixture did not overflow");
                let events = snapshot
                    .drop_events
                    .as_ref()
                    .context("drop collector unavailable")?;
                ensure!(
                    events
                        .counts
                        .values()
                        .any(|r| r.reason == "SKB_DROP_REASON_SOCKET_RCVBUFF" && r.events > 0),
                    "no receive-buffer drop reason: {events:?}"
                );
                println!("UDP socket drops={drops}, reasoned events={events:?}");
            }
            if command == "closed" {
                for inode in expected["closed"].as_array().context("closed inodes")? {
                    ensure!(
                        !snapshot
                            .diagnostics
                            .values()
                            .any(|s| s.native_id == inode.as_u64().unwrap()),
                        "closed socket retained"
                    );
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        println!(
            "PASS: integrated collectors, IPv4/IPv6, late sockets, drain, UDP overflow and closed sockets after sandbox"
        );
        Ok(())
    })();
    let _ = child.kill();
    let _ = child.wait();
    result
}

/// Load a fixed socket filter while the probe still holds its normal CAP_BPF.
/// Passing its FD lets the unprivileged fixture use SO_ATTACH_BPF, without the
/// CAP_NET_ADMIN now required for classic SO_ATTACH_FILTER on TCP sockets.
#[cfg(target_os = "linux")]
fn load_loss_filter() -> anyhow::Result<std::os::fd::OwnedFd> {
    use anyhow::Context;
    use std::os::fd::{FromRawFd, OwnedFd};

    const BPF_PROG_LOAD: libc::c_int = 5;

    // Initial BPF_PROG_LOAD fields from linux/bpf.h. The kernel zero-fills
    // trailing fields not supplied by this older, minimal attribute layout.
    #[repr(C, align(8))]
    struct ProgLoad {
        prog_type: u32,
        insn_cnt: u32,
        insns: u64,
        license: u64,
    }
    // BPF_MOV64_IMM r0, 0; BPF_EXIT. Returning zero drops the received packet.
    let instructions: [[u8; 8]; 2] = [[0xb7, 0, 0, 0, 0, 0, 0, 0], [0x95, 0, 0, 0, 0, 0, 0, 0]];
    let attr = ProgLoad {
        prog_type: 1, // BPF_PROG_TYPE_SOCKET_FILTER
        insn_cnt: instructions.len() as u32,
        insns: instructions.as_ptr() as u64,
        license: c"GPL".as_ptr() as u64,
    };
    // SAFETY: the attribute layout matches the UAPI; all referenced buffers
    // remain valid for this synchronous syscall. A successful result is a new FD.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_LOAD,
            &attr,
            std::mem::size_of::<ProgLoad>(),
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("load loss fixture socket filter with CAP_BPF");
    }
    // SAFETY: the successful BPF_PROG_LOAD returned a uniquely owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This native integration probe requires Linux.");
}

#[cfg(target_os = "linux")]
const FIXTURE: &str = r#"
import socket, os, sys, json, struct, time
with open('/proc/self/status') as status:
    for line in status:
        if line.startswith(('CapEff:', 'CapPrm:')):
            assert int(line.split()[1],16)==0, 'fixture must not retain capabilities'
pairs=[]
closed=[]
def inode(s): return int(os.readlink('/proc/self/fd/%d'%s.fileno())[8:-1])
def pair(family, host):
    listener=socket.socket(family); listener.bind((host,0)); listener.listen()
    sender=socket.socket(family); sender.connect(listener.getsockname())
    receiver,_=listener.accept(); listener.close()
    sender.sendall(b'x'*8192); time.sleep(.03)
    pairs.append((sender,receiver,8192))
for family,host in [(socket.AF_INET,'127.0.0.1'),(socket.AF_INET6,'::1')]: pair(family,host)
udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); udp.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4096); udp.bind(('127.0.0.1',0))
send=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
def report():
    entries=[]
    for sender,receiver,rx in pairs:
        for s,q in [(sender,0),(receiver,rx)]:
            info=s.getsockopt(socket.IPPROTO_TCP,socket.TCP_INFO,104)
            entries.append(dict(inode=inode(s),rx=q,rtt=struct.unpack_from('I',info,68)[0],rttvar=struct.unpack_from('I',info,72)[0],cwnd=struct.unpack_from('I',info,80)[0],retransmissions=struct.unpack_from('I',info,100)[0],sending=s is sender))
    print(json.dumps(dict(tcp=entries,udp=inode(udp),closed=closed)),flush=True)
report()
for command in sys.stdin:
    command=command.strip()
    if command=='late': pair(socket.AF_INET,'127.0.0.1')
    elif command=='drain':
        for i,(s,r,rx) in enumerate(pairs):
            data=b''
            while len(data)<rx: data+=r.recv(rx-len(data))
            pairs[i]=(s,r,0)
    elif command=='overflow':
        for i in range(100): send.sendto(b'x'*512,udp.getsockname())
    elif command=='loss':
        filter_fd=int(os.environ['RUSTNET_DIAGNOSTICS_FILTER_FD'])
        for s,r,_ in pairs:
            r.setsockopt(socket.SOL_SOCKET,50,filter_fd) # SO_ATTACH_BPF, only on fixture sockets.
            s.sendall(b'lost'*256)
        os.close(filter_fd)
        # Bound the control and stop before a second retransmission interval.
        deadline=time.monotonic()+3
        while any(struct.unpack_from('I',s.getsockopt(socket.IPPROTO_TCP,socket.TCP_INFO,104),100)[0]==0 for s,_,_ in pairs):
            if time.monotonic()>deadline: raise RuntimeError('no retransmissions observed')
            time.sleep(.01)
    elif command=='closed':
        for s,r,_ in pairs:
            closed.extend([inode(s),inode(r)]); s.close(); r.close()
        pairs=[]
    time.sleep(.1); report()
"#;
