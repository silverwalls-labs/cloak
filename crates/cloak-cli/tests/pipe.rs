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

#[test]
fn pipe_redacts_github_token_with_keyed_digest() {
    // Deterministic end-to-end: with CLOAK_DIGEST_KEY set, the digest is
    // reproducible, so the exact output can be asserted. The key derivation
    // must mirror cloak-core's resolve_digest_key.
    let secret = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
    let input = format!("deploy: token={secret} done\n");
    let key = blake3::derive_key("cloak digest key", b"e2e-test-key");
    let digest = cloak_core::compute_digest(secret.as_bytes(), &key);
    let tag = cloak_core::format_tag(&cloak_core::RuleId::new("github-token"), &digest);
    let expected = format!("deploy: token={tag} done\n");

    Command::cargo_bin("cloak")
        .unwrap()
        .env("CLOAK_DIGEST_KEY", "e2e-test-key")
        .write_stdin(input)
        .assert()
        .success()
        .stdout(expected);
}

#[test]
fn pipe_never_emits_secret_without_key() {
    // No key configured → ephemeral key: digest is nondeterministic, but the
    // secret bytes must be gone and the tag structure present.
    let secret = "glpat-abcdefghij0123456789";
    let input = format!("ci: {secret} pushed\n");

    let assert = Command::cargo_bin("cloak")
        .unwrap()
        .env_remove("CLOAK_DIGEST_KEY")
        .write_stdin(input)
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        !stdout.contains(secret),
        "secret leaked to stdout: {stdout}"
    );
    assert!(
        stdout.contains("[CLOAK:gitlab-token:"),
        "missing redaction tag: {stdout}"
    );
}

#[test]
fn pipe_token_near_64k_boundary() {
    // Place a token right at the 64 KiB boundary to exercise the CLI's
    // streaming read + carry-over interaction.
    let prefix_len = 64 * 1024 - 20; // token starts 20 bytes before the boundary
    let mut input: Vec<u8> = vec![b'x'; prefix_len];
    let secret = b"npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
    input.extend_from_slice(secret);
    input.extend_from_slice(b" tail\n");

    let assert = Command::cargo_bin("cloak")
        .unwrap()
        .env_remove("CLOAK_DIGEST_KEY")
        .write_stdin(input)
        .assert()
        .success();
    let stdout = assert.get_output().stdout.clone();

    assert!(
        !stdout.windows(secret.len()).any(|w| w == secret),
        "token at 64 KiB boundary must be redacted"
    );
    let text = String::from_utf8_lossy(&stdout);
    assert!(text.contains("[CLOAK:npm-token:"), "tag must be present");
}

#[test]
fn pipe_mixed_tokens_and_pem() {
    // A realistic log snippet with both a token and a PEM block.
    let input = "\
        INFO  deploy token=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789\n\
        DEBUG leaked key follows:\n\
        -----BEGIN EC PRIVATE KEY-----\n\
        MHQCAQEEbase64data\n\
        -----END EC PRIVATE KEY-----\n\
        INFO  deployment complete\n";

    let assert = Command::cargo_bin("cloak")
        .unwrap()
        .env_remove("CLOAK_DIGEST_KEY")
        .write_stdin(input)
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    assert!(stdout.contains("[CLOAK:github-token:"), "github tag");
    assert!(stdout.contains("[CLOAK:pem-private-key:"), "PEM tag");
    assert!(!stdout.contains("ghp_Ab"), "github token leaked");
    assert!(!stdout.contains("MHQCAQEEbase64data"), "PEM body leaked");
    assert!(
        stdout.contains("deployment complete"),
        "clean text preserved"
    );
}

#[test]
fn pipe_redacts_pem_block() {
    // PEM private key piped through the real binary — markers stay visible,
    // body replaced by tag.
    let input = "log line\n\
        -----BEGIN RSA PRIVATE KEY-----\n\
        MIIBogIBAAJBALRiMLAH0123456789abcdefgABCDEFGH\n\
        -----END RSA PRIVATE KEY-----\n\
        more log\n";

    let assert = Command::cargo_bin("cloak")
        .unwrap()
        .env_remove("CLOAK_DIGEST_KEY")
        .write_stdin(input)
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    assert!(
        stdout.contains("-----BEGIN RSA PRIVATE KEY-----"),
        "BEGIN marker must be visible: {stdout}"
    );
    assert!(
        stdout.contains("-----END RSA PRIVATE KEY-----"),
        "END marker must be visible: {stdout}"
    );
    assert!(
        stdout.contains("[CLOAK:pem-private-key:"),
        "PEM tag must be present: {stdout}"
    );
    assert!(
        !stdout.contains("MIIBogIBAAJ"),
        "PEM body must not leak: {stdout}"
    );
    assert!(
        stdout.contains("log line") && stdout.contains("more log"),
        "surrounding text must pass through: {stdout}"
    );
}
