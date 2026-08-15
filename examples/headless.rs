//! Minimal headless front-end proving the library-crate pairing the
//! workspace split was made for: `rustnet-capture` (frames) ->
//! `rustnet-core` (parsing + `ConnectionTracker`) -> `rustnet-host`
//! (process attribution), sandboxed by `rustnet-sandbox`, with interface
//! counters from `rustnet-core`'s stats provider. No TUI involved.
//!
//! Run with capture privileges, e.g.:
//!
//! ```text
//! cargo build --example headless
//! sudo ./target/debug/examples/headless
//! ```
//!
//! Prints a connection summary every two seconds until interrupted.

use std::time::{Duration, Instant, SystemTime};

use rustnet_capture::{CaptureConfig, PacketReader, setup_packet_capture};
use rustnet_core::network::parser::PacketParser;
use rustnet_core::network::tracker::ConnectionTracker;
use rustnet_sandbox::{SandboxConfig, SandboxMode, apply_sandbox};

fn main() -> anyhow::Result<()> {
    // 1. Privileged initialization: open the capture device and the process
    //    lookup (on Linux this loads eBPF programs when available). Everything
    //    that needs root or capabilities happens before the sandbox.
    let (capture, device, linktype) = setup_packet_capture(CaptureConfig::default())?;
    let mut reader = PacketReader::new(capture);
    let mut parser = PacketParser::new().with_linktype(linktype);
    // On macOS the flag selects the PKTAP-metadata lookup over lsof; the
    // capture setup reports whether PKTAP is the active device.
    let process_lookup = rustnet_host::create_process_lookup(device == "pktap")?;

    // 2. Apply the sandbox. The already-open capture and eBPF descriptors
    //    survive it; see the rustnet-sandbox crate docs for the ordering
    //    contract. On Linux/macOS/FreeBSD also drop root to the invoking
    //    sudo user.
    let sandbox_config = SandboxConfig {
        mode: SandboxMode::BestEffort,
        block_network: true, // passive monitor: no outbound TCP needed
        ..SandboxConfig::default()
    };
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    let sandbox_config = SandboxConfig {
        drop_uid: rustnet_sandbox::privdrop::resolve_drop_target(),
        ..sandbox_config
    };
    let report = apply_sandbox(&sandbox_config)?;
    println!("sandbox: {} ({})", report.status.label(), report.message);

    // 3. The same interface-stats provider the TUI uses, from rustnet-core.
    let stats_provider = rustnet_core::network::interface_stats::create_stats_provider();

    // 4. Capture loop: fold frames into the tracker, print a summary every
    //    two seconds.
    let tracker = ConnectionTracker::new();
    let mut last_print = Instant::now();
    println!("capturing on {device} (DLT {linktype}); Ctrl-C to stop");

    loop {
        if let Some(packet) = reader.next_packet()?
            && let Some(parsed) = parser.parse_packet_with_refresh(&packet.data)
        {
            tracker.ingest_at(&parsed, packet.timestamp);
        }

        if last_print.elapsed() < Duration::from_secs(2) {
            continue;
        }
        last_print = Instant::now();

        // Cache-based lookups (procfs, lsof, sockstat) only learn about new
        // processes on refresh; the binary does the same every few seconds.
        if let Err(e) = process_lookup.refresh() {
            eprintln!("process lookup refresh failed: {e}");
        }

        tracker.cleanup(SystemTime::now());
        let mut connections = tracker.snapshot();
        connections.sort_by_key(|c| std::cmp::Reverse(c.bytes_sent + c.bytes_received));

        let interfaces = stats_provider
            .get_all_stats()
            .map(|stats| stats.len())
            .unwrap_or(0);
        println!(
            "-- {} active connections ({} interfaces reporting counters)",
            connections.len(),
            interfaces
        );
        // IPv6 "[addr]:port" endpoints outgrow IPv4 widths; size the address
        // columns to the widest endpoint in this snapshot.
        let addr_width = connections
            .iter()
            .take(10)
            .flat_map(|c| {
                [
                    c.local_addr.to_string().len(),
                    c.remote_addr.to_string().len(),
                ]
            })
            .max()
            .unwrap_or(21);
        for conn in connections.iter().take(10) {
            let process = conn
                .process_name
                .clone()
                .or_else(|| {
                    process_lookup
                        .get_process_attribution(conn)
                        .map(|attribution| attribution.name)
                })
                .unwrap_or_else(|| "-".to_string());
            println!(
                "   {:<8} {:>addr_width$} -> {:<addr_width$} tx {:>10} rx {:>10}  {}",
                conn.protocol.to_string(),
                conn.local_addr.to_string(),
                conn.remote_addr.to_string(),
                conn.bytes_sent,
                conn.bytes_received,
                process
            );
        }
    }
}
