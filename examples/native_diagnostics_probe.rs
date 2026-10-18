//! Native CI smoke test: loopback queues/EStats before and after RustNet's sandbox.
//! The fixture child starts before sandboxing so it can create later sockets.
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "freebsd"))]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};
    if std::env::args().any(|arg| arg == "--fixture") {
        return fixture();
    }
    let mut child = Command::new(std::env::current_exe()?)
        .arg("--fixture")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let result = (|| -> anyhow::Result<()> {
        let mut input = child.stdin.take().context("fixture input")?;
        let mut output = BufReader::new(child.stdout.take().context("fixture output")?);
        let mut lookup = rustnet_host::create_process_lookup(false)?;
        let mut identities = std::collections::HashMap::new();
        for command in ["initial", "late", "drain", "closed"] {
            if command == "late" {
                let config = rustnet_sandbox::SandboxConfig {
                    block_network: true,
                    ..Default::default()
                };
                let report = rustnet_sandbox::apply_sandbox(&config)?;
                println!("sandbox: {report:?}");
                #[cfg(target_os = "macos")]
                ensure!(
                    report.fs_restricted && report.net_restricted,
                    "Seatbelt must be enforced"
                );
                #[cfg(target_os = "windows")]
                ensure!(
                    report.job_object_applied,
                    "job restriction must be enforced"
                );
            }
            writeln!(input, "{command}")?;
            input.flush()?;
            let mut line = String::new();
            output.read_line(&mut line)?;
            let locals: Vec<std::net::SocketAddr> = serde_json::from_str(&line)?;
            lookup.refresh()?;
            let snapshot = lookup.socket_snapshot();
            println!("{command}: {:?}", snapshot.diagnostics_status);
            if command == "closed" {
                for local in identities.keys() {
                    ensure!(
                        !snapshot.diagnostics.keys().any(|s| &s.local_addr == local),
                        "closed socket still sampled"
                    );
                }
            }
            for local in locals {
                let (socket, sample) = snapshot
                    .diagnostics
                    .iter()
                    .find(|(s, _)| s.local_addr == local)
                    .with_context(|| format!("missing native sample for {local}"))?;
                ensure!(
                    socket.owner.as_ref().is_some_and(|o| o.pid == child.id()),
                    "wrong owner"
                );
                ensure!(sample.native_id != 0, "missing native identity");
                if let Some(old) = identities.insert(local, sample.native_id) {
                    ensure!(old == sample.native_id, "identity changed");
                }
                #[cfg(target_os = "windows")]
                {
                    let tcp = sample.tcp.as_ref().context("EStats Path sample")?;
                    ensure!(
                        tcp.source == "windows_estats" && tcp.congestion_window_segments.is_none(),
                        "source or optional fields"
                    );
                }
                #[cfg(not(target_os = "windows"))]
                {
                    let queues = sample.queues.as_ref().context("byte queue sample")?;
                    ensure!(
                        queues.receive == if command == "drain" { 0 } else { 8192 },
                        "incorrect queue: {queues:?}"
                    );
                    ensure!(
                        queues.send == 0 && queues.socket_drops.is_none(),
                        "unsupported counters"
                    );
                }
                println!("{local}: {sample:?}");
            }
        }
        Ok(())
    })();
    let _ = child.kill();
    let _ = child.wait();
    result
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "freebsd"))]
fn fixture() -> anyhow::Result<()> {
    use std::io::{BufRead, Read, Write};
    use std::net::{TcpListener, TcpStream};
    let mut pairs = Vec::new();
    for command in std::io::stdin().lock().lines() {
        match command?.as_str() {
            "initial" | "late" => {
                for address in ["127.0.0.1:0", "[::1]:0"] {
                    let listener = TcpListener::bind(address)?;
                    let mut sender = TcpStream::connect(listener.local_addr()?)?;
                    let (receiver, _) = listener.accept()?;
                    sender.write_all(&[42; 8192])?;
                    // peek waits for arrival without consuming the queue.
                    let mut byte = [0];
                    receiver.peek(&mut byte)?;
                    pairs.push((sender, receiver));
                }
            }
            "drain" => {
                for (_, receiver) in &mut pairs {
                    receiver.read_exact(&mut [0; 8192])?;
                }
            }
            "closed" => pairs.clear(),
            _ => anyhow::bail!("unknown fixture command"),
        }
        // Let small loopback transfers and acknowledgements settle.
        std::thread::sleep(std::time::Duration::from_millis(100));
        let addresses: Vec<_> = pairs
            .iter()
            .map(|(_, receiver)| receiver.local_addr())
            .collect::<std::io::Result<_>>()?;
        println!("{}", serde_json::to_string(&addresses)?);
        std::io::stdout().flush()?;
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "freebsd")))]
fn main() {
    println!("Use diagnostics_probe on Linux");
}
