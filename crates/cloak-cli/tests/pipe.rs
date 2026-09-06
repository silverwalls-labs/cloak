use assert_cmd::Command;

/// The golden e2e smoke test — S1 acceptance criterion.
///
/// Pipes a realistic log snippet through the `cloak` binary and asserts
/// the output is byte-identical (zero rules compiled in).
#[test]
fn golden_pipe_passthrough() {
    let input = "\
2026-09-06T10:15:30.123Z INFO  app::server - Listening on 0.0.0.0:8080\n\
2026-09-06T10:15:31.456Z DEBUG app::db - Connected to database\n\
2026-09-06T10:15:32.789Z ERROR app::handler - Request failed: timeout\n";

    Command::cargo_bin("cloak")
        .unwrap()
        .write_stdin(input)
        .assert()
        .success()
        .stdout(input);
}

#[test]
fn empty_stdin() {
    Command::cargo_bin("cloak")
        .unwrap()
        .write_stdin("")
        .assert()
        .success()
        .stdout("");
}

#[test]
fn binary_pipe() {
    // All byte values 0x00..=0xFF — verifies non-matching bytes pass through
    // byte-identical through the full process boundary.
    let input: Vec<u8> = (0..=255).collect();

    Command::cargo_bin("cloak")
        .unwrap()
        .write_stdin(input.clone())
        .assert()
        .success()
        .stdout(input);
}

#[test]
fn large_pipe() {
    // >64 KiB — more than one read chunk, validates the read loop handles
    // multiple iterations correctly.
    let line = b"The quick brown fox jumps over the lazy dog.\n";
    let input: Vec<u8> = line.iter().cycle().take(100 * 1024).copied().collect();

    Command::cargo_bin("cloak")
        .unwrap()
        .write_stdin(input.clone())
        .assert()
        .success()
        .stdout(input);
}
