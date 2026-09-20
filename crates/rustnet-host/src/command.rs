use std::io::{self, Read};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub(crate) const PROCESS_TABLE_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Run a command while capturing its output, killing and reaping it on timeout.
pub(crate) fn output_with_timeout_or_cancel(
    command: &mut Command,
    timeout: Duration,
    cancel: Option<&AtomicBool>,
) -> io::Result<Output> {
    if cancel.is_some_and(|flag| flag.load(Ordering::Acquire)) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "command cancelled before startup",
        ));
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let program = command.get_program().to_owned();
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .expect("stdout is piped before the child is spawned");
    let stderr = child
        .stderr
        .take()
        .expect("stderr is piped before the child is spawned");
    let stdout_reader = read_in_background(stdout);
    let stderr_reader = read_in_background(stderr);
    let deadline = Instant::now() + timeout;

    let status = loop {
        if cancel.is_some_and(|flag| flag.load(Ordering::Acquire)) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = join_reader(stdout_reader, "stdout");
            let _ = join_reader(stderr_reader, "stderr");
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                format!("command {program:?} cancelled"),
            ));
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(
                    POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = join_reader(stdout_reader, "stdout");
                let _ = join_reader(stderr_reader, "stderr");
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("command {program:?} timed out after {timeout:?}"),
                ));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = join_reader(stdout_reader, "stdout");
                let _ = join_reader(stderr_reader, "stderr");
                return Err(error);
            }
        }
    };

    collect_output(status, stdout_reader, stderr_reader)
}

fn read_in_background<R>(mut reader: R) -> JoinHandle<io::Result<Vec<u8>>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut output = Vec::new();
        reader.read_to_end(&mut output)?;
        Ok(output)
    })
}

fn collect_output(
    status: ExitStatus,
    stdout_reader: JoinHandle<io::Result<Vec<u8>>>,
    stderr_reader: JoinHandle<io::Result<Vec<u8>>>,
) -> io::Result<Output> {
    Ok(Output {
        status,
        stdout: join_reader(stdout_reader, "stdout")?,
        stderr: join_reader(stderr_reader, "stderr")?,
    })
}

fn join_reader(reader: JoinHandle<io::Result<Vec<u8>>>, stream_name: &str) -> io::Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| io::Error::other(format!("{stream_name} reader panicked")))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_output_and_exit_status() {
        let output = output_with_timeout_or_cancel(
            Command::new("/bin/sh")
                .arg("-c")
                .arg("printf ready; printf problem >&2; exit 7"),
            Duration::from_secs(1),
            None,
        )
        .expect("short command should finish");

        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stdout, b"ready");
        assert_eq!(output.stderr, b"problem");
    }

    #[test]
    fn kills_and_reaps_command_after_timeout() {
        let started = Instant::now();
        let error = output_with_timeout_or_cancel(
            Command::new("/bin/sleep").arg("30"),
            Duration::from_millis(30),
            None,
        )
        .expect_err("sleep should time out");

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn cancellation_kills_and_reaps_a_blocked_command() {
        use std::sync::Arc;

        let cancelled = Arc::new(AtomicBool::new(false));
        let setter = Arc::clone(&cancelled);
        let signal = thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));
            setter.store(true, Ordering::Release);
        });
        let started = Instant::now();
        let error = output_with_timeout_or_cancel(
            Command::new("/bin/sleep").arg("30"),
            Duration::from_secs(5),
            Some(&cancelled),
        )
        .expect_err("cancelled sleep should stop");
        signal.join().unwrap();

        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
