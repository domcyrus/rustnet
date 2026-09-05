use std::process::{Command, Stdio};

#[path = "../src/test_support/scratch_dir.rs"]
mod scratch_dir;

#[test]
fn stdout_collisions_fail_before_privileges_or_logging_and_preserve_all_files() {
    for stdout_name in [
        "capture.pcap",
        "capture.pcap.connections.jsonl",
        "capture.pcapng",
        "events.jsonl",
    ] {
        let directory = scratch_dir::ScratchDir::new("cli-stdout", stdout_name);
        assert_stdout_collision(&directory, stdout_name, stdout_name);
    }
}

fn assert_stdout_collision(
    directory: &scratch_dir::ScratchDir,
    stdout_name: &str,
    configured_name: &str,
) {
    let paths = [
        directory.path().join("capture.pcap"),
        directory.path().join("capture.pcap.connections.jsonl"),
        directory.path().join("capture.pcapng"),
        directory.path().join("events.jsonl"),
    ];
    for path in &paths {
        std::fs::write(path, b"preserve existing artifact\n").unwrap();
    }
    let stdout_path = directory.path().join(stdout_name);
    std::fs::write(&stdout_path, b"preserve existing artifact\n").unwrap();
    // The parent deliberately does not truncate or append. If startup writes
    // even one snapshot or capture header, the sentinel will be corrupted.
    let stdout = std::fs::OpenOptions::new()
        .write(true)
        .open(&stdout_path)
        .unwrap();
    let configured_json = if configured_name == stdout_name {
        paths[3].clone()
    } else {
        directory.path().join(configured_name)
    };
    let output = Command::new(env!("CARGO_BIN_EXE_rustnet"))
        .args(["--headless", "--duration", "1", "--log-level", "debug"])
        .arg("--pcap-export")
        .arg(&paths[0])
        .arg("--pcapng-export")
        .arg(&paths[2])
        .arg("--json-log")
        .arg(configured_json)
        .current_dir(directory.path())
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("overlaps stdout"),
        "unexpected stderr: {stderr}"
    );
    for path in paths.iter().chain(std::iter::once(&stdout_path)) {
        assert_eq!(
            std::fs::read(path).unwrap(),
            b"preserve existing artifact\n"
        );
    }
    assert!(!directory.path().join("logs").exists());
}

#[test]
fn stdout_filesystem_aliases_are_rejected_before_startup() {
    for (first, alias, tag) in [
        ("snapshots", "SNAPSHOTS", "case"),
        ("caf\u{e9}", "cafe\u{301}", "unicode"),
    ] {
        let directory = scratch_dir::ScratchDir::new("cli-stdout-alias", tag);
        std::fs::write(directory.path().join(first), b"alias probe").unwrap();
        if !std::fs::read(directory.path().join(alias)).is_ok_and(|bytes| bytes == b"alias probe") {
            // The filesystem treats the names as distinct, not aliases.
            continue;
        }
        assert_stdout_collision(&directory, first, alias);
    }
}

#[cfg(unix)]
#[test]
fn stdout_parent_symlink_alias_is_rejected_before_startup() {
    let directory = scratch_dir::ScratchDir::new("cli-stdout-alias", "parent");
    std::os::unix::fs::symlink(directory.path(), directory.path().join("alias")).unwrap();
    assert_stdout_collision(&directory, "snapshots", "alias/snapshots");
}

#[test]
fn pipe_and_distinct_stdout_pass_collision_validation_without_privileges() {
    for regular_stdout in [false, true] {
        let directory =
            scratch_dir::ScratchDir::new("cli-stdout-valid", &regular_stdout.to_string());
        let capture = directory.path().join("capture.pcap");
        let snapshots = directory.path().join("snapshots.jsonl");
        std::fs::write(&capture, b"existing capture").unwrap();
        std::fs::write(&snapshots, b"existing snapshots").unwrap();
        let stdout = if regular_stdout {
            Stdio::from(
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&snapshots)
                    .unwrap(),
            )
        } else {
            Stdio::piped()
        };
        // A deliberately invalid later artifact gives a deterministic early
        // diagnostic after the valid stdout/PCAP check, before Npcap or root.
        let output = Command::new(env!("CARGO_BIN_EXE_rustnet"))
            .arg("--headless")
            .arg("--pcap-export")
            .arg(&capture)
            .arg("--pcapng-export")
            .arg(directory.path())
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success());
        assert!(
            stderr.contains("not a regular file"),
            "unexpected stderr: {stderr}"
        );
        assert!(!stderr.contains("overlaps"), "unexpected stderr: {stderr}");
        assert!(output.stdout.is_empty());
        assert_eq!(std::fs::read(capture).unwrap(), b"existing capture");
        assert_eq!(std::fs::read(snapshots).unwrap(), b"existing snapshots");
    }
}

#[test]
fn overlapping_outputs_fail_before_logging_or_capture_without_truncating_files() {
    for json_name in ["capture.pcap", "capture.pcap.connections.jsonl"] {
        let directory = scratch_dir::ScratchDir::new("cli-output", json_name);
        let pcap = directory.path().join("capture.pcap");
        let json = directory.path().join(json_name);
        std::fs::write(&pcap, b"existing capture").unwrap();
        if pcap != json {
            std::fs::write(&json, b"existing sidecar").unwrap();
        }
        let previous_json = std::fs::read(&json).unwrap();

        let output = Command::new(env!("CARGO_BIN_EXE_rustnet"))
            .args(["--headless", "--duration", "1", "--log-level", "debug"])
            .arg("--pcap-export")
            .arg(&pcap)
            .arg("--json-log")
            .arg(&json)
            .current_dir(directory.path())
            .stdin(Stdio::null())
            .output()
            .expect("rustnet should reject overlapping output paths");

        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("overlaps"), "unexpected stderr: {stderr}");
        assert_eq!(std::fs::read(&pcap).unwrap(), b"existing capture");
        assert_eq!(std::fs::read(&json).unwrap(), previous_json);
        assert!(!directory.path().join("logs").exists());
    }
}

#[test]
fn default_mode_rejects_non_terminal_output_without_control_sequences() {
    let output = Command::new(env!("CARGO_BIN_EXE_rustnet"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("rustnet should start");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.contains(&0x1b));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("interactive mode requires a terminal"),
        "unexpected stderr: {stderr}"
    );
    assert!(stderr.contains("--headless"), "unexpected stderr: {stderr}");
}

#[test]
fn help_remains_available_without_a_terminal() {
    let output = Command::new(env!("CARGO_BIN_EXE_rustnet"))
        .arg("--help")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("rustnet --help should start");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert!(!output.stdout.contains(&0x1b));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--headless"));
    assert!(stdout.contains("--output <FORMAT>"));
    // Existing interactive controls remain part of the default frontend after
    // adding headless mode. Help exits before privilege or capture setup.
    assert!(stdout.contains("--interface <INTERFACE>"));
    assert!(stdout.contains("--refresh-interval <MILLISECONDS>"));
    assert!(stdout.contains("--no-color"));
    assert!(stdout.contains("--theme <PRESET>"));
}

#[test]
fn version_remains_available_without_a_terminal() {
    let output = Command::new(env!("CARGO_BIN_EXE_rustnet"))
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("rustnet --version should start");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert!(!output.stdout.contains(&0x1b));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("rustnet "),
        "unexpected stdout: {stdout}"
    );
}
