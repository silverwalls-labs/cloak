//! E2E tier: CLI I/O robustness (docs/03 §cross-cutting) — production
//! pipe reality. The collector restarting mid-stream means cloak's
//! stdout closes under it: that must be a clean exit 0 (SIGPIPE
//! semantics), never a panic or error spew.
//!
//! Raw `std::process::Command` instead of assert_cmd: closing the child's
//! stdout mid-stream requires holding and dropping the pipe handle
//! ourselves. Unix-only — the broken-pipe contract is a Unix pipeline
//! concept.
//!
//! Partial writes are not independently forcible through anonymous
//! pipes; the multi-MiB pumps below exercise pipe backpressure (and thus
//! short-write looping in BufWriter/write_all) as a side effect.

#![cfg(unix)]

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};

fn spawn_cloak(args: &[&str]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_cloak"))
        .args(args)
        // Keyed: silences the ephemeral-key stderr warning so the tests
        // can assert stderr stays clean.
        .env("CLOAK_DIGEST_KEY", "robustness-test-key")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cloak")
}

/// Drain the child's stderr on its own thread, started BEFORE `wait()`.
/// Reading stderr only after wait would deadlock if the child writes more
/// than the ~64 KiB pipe buffer (error spew / panic backtraces — the very
/// failure modes these tests exist to catch): the child blocks on the full
/// stderr pipe while the parent blocks in wait. Join the handle after wait.
fn drain_stderr(child: &mut Child) -> std::thread::JoinHandle<String> {
    let mut stderr = child.stderr.take().expect("stderr piped");
    std::thread::spawn(move || {
        let mut err = String::new();
        stderr.read_to_string(&mut err).expect("read stderr");
        err
    })
}

/// Pump `total` bytes of line-shaped data into stdin from a thread,
/// stopping quietly once the child stops reading (write errors are the
/// expected outcome of a dead pipe, not a test failure).
fn pump_stdin(child: &mut Child, total: usize) -> std::thread::JoinHandle<()> {
    let mut stdin = child.stdin.take().expect("stdin piped");
    std::thread::spawn(move || {
        let line = b"plain log line with no secrets at all 1234\n";
        let mut written = 0;
        while written < total {
            if stdin.write_all(line).is_err() {
                break; // child went away — that's the scenario, not an error
            }
            written += line.len();
        }
        // Dropping stdin closes the pipe (EOF) if the child still reads.
    })
}

/// Collector restarts mid-stream: read a little, then close our end of
/// the child's stdout. The child's next write gets EPIPE → BrokenPipe →
/// exit 0, no panic (main.rs walks the error chain).
#[test]
fn broken_pipe_mid_stream_exits_zero() {
    let mut child = spawn_cloak(&[]);
    let pump = pump_stdin(&mut child, 32 * 1024 * 1024);
    let stderr = drain_stderr(&mut child);

    let mut stdout = child.stdout.take().expect("stdout piped");
    let mut first = [0u8; 8192];
    stdout.read_exact(&mut first).expect("first 8 KiB");
    drop(stdout); // collector "restarts"

    let status = child.wait().expect("wait");
    pump.join().unwrap();
    let stderr = stderr.join().unwrap();

    assert!(status.success(), "broken pipe must exit 0, got {status:?}");
    assert!(!stderr.contains("panic"), "stderr: {stderr}");
    assert!(
        !stderr.contains("cloak:"),
        "no error message expected: {stderr}"
    );
}

/// Stdout closed before cloak writes anything: input larger than the
/// pipe buffer forces the first flush into a dead pipe.
#[test]
fn stdout_closed_before_first_write_exits_zero() {
    let mut child = spawn_cloak(&[]);
    drop(child.stdout.take().expect("stdout piped"));
    let pump = pump_stdin(&mut child, 8 * 1024 * 1024);
    let stderr = drain_stderr(&mut child);

    let status = child.wait().expect("wait");
    pump.join().unwrap();
    let stderr = stderr.join().unwrap();

    assert!(status.success(), "expected exit 0, got {status:?}");
    assert!(!stderr.contains("panic"), "stderr: {stderr}");
}

/// Broken pipe with --stats-format: the session dies in push/finish, so
/// stats are never emitted — exit is still 0 and stderr stays clean
/// (pins that stats don't turn a SIGPIPE exit into an error path).
#[test]
fn broken_pipe_with_stats_flag_exits_zero() {
    let mut child = spawn_cloak(&["--stats-format", "json"]);
    let pump = pump_stdin(&mut child, 32 * 1024 * 1024);
    let stderr = drain_stderr(&mut child);

    let mut stdout = child.stdout.take().expect("stdout piped");
    let mut first = [0u8; 4096];
    stdout.read_exact(&mut first).expect("first 4 KiB");
    drop(stdout);

    let status = child.wait().expect("wait");
    pump.join().unwrap();
    let stderr = stderr.join().unwrap();

    assert!(status.success(), "expected exit 0, got {status:?}");
    assert!(!stderr.contains("panic"), "stderr: {stderr}");
    assert!(
        !stderr.contains("bytes_processed"),
        "stats must not be emitted after a broken pipe: {stderr}"
    );
}
