use std::process::{Command, Stdio};

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
