//! `rustnet --headless` argument handling that must fail before any capture
//! is attempted, so these pass without capture privileges.

use std::process::{Command, Output};

fn rustnet(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rustnet"))
        .args(args)
        .output()
        .expect("rustnet binary should run")
}

#[test]
fn snapshot_interval_without_headless_is_rejected_by_clap() {
    let output = rustnet(&["--snapshot-interval", "5"]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success());
    assert!(stderr.contains("--headless"), "stderr: {stderr}");
    assert!(output.stdout.is_empty());
}

#[test]
fn invalid_filter_fails_before_capture() {
    let output = rustnet(&["--headless", "--filter", "port:"]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success());
    assert!(stderr.contains("Invalid --filter"), "stderr: {stderr}");
    assert!(stderr.contains("port:"), "stderr: {stderr}");
    assert!(output.stdout.is_empty());
    // The privilege banner is printed by the step this must fail before.
    assert!(
        !stderr.contains("INSUFFICIENT PRIVILEGES"),
        "stderr: {stderr}"
    );
}

#[test]
fn version_is_printed_in_headless_mode() {
    let output = rustnet(&["--headless", "--version"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success());
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "stdout: {stdout}"
    );
}
