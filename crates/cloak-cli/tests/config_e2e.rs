//! E2E tests for config loading, rule filtering, stats output, file args,
//! and I/O robustness — through the real `cloak` binary at the process boundary.

use assert_cmd::Command;
use std::io::Write;

fn cloak() -> Command {
    let mut cmd = Command::cargo_bin("cloak").unwrap();
    // Suppress ephemeral key warnings so stderr assertions are clean.
    cmd.env("CLOAK_DIGEST_KEY", "e2e-config-test-key");
    cmd
}

fn write_config(content: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

// ── Config loading ──────────────────────────────────────────────────

#[test]
fn config_file_loads_and_disables_rule() {
    let config = write_config(
        r#"
[rules.github-token]
enabled = false
"#,
    );
    let secret = "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";
    cloak()
        .arg("--config")
        .arg(config.path())
        .write_stdin(secret)
        .assert()
        .success()
        .stdout(secret); // disabled → passes through
}

#[test]
fn config_file_disables_pem() {
    let config = write_config(
        r#"
[rules.pem-private-key]
enabled = false
"#,
    );
    let input = "-----BEGIN RSA PRIVATE KEY-----\nBODY\n-----END RSA PRIVATE KEY-----";
    let assert = cloak()
        .arg("--config")
        .arg(config.path())
        .write_stdin(input)
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("BODY"),
        "PEM disabled → body passes through"
    );
}

#[test]
fn config_file_unknown_rule_exits_1() {
    let config = write_config(
        r#"
[rules.not-a-rule]
enabled = false
"#,
    );
    let assert = cloak()
        .arg("--config")
        .arg(config.path())
        .write_stdin("hello")
        .assert()
        .failure()
        .code(1);
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("not-a-rule"),
        "error should name the unknown rule: {stderr}"
    );
}

#[test]
fn config_file_not_found_exits_1() {
    cloak()
        .arg("--config")
        .arg("/nonexistent/cloak.toml")
        .write_stdin("")
        .assert()
        .failure()
        .code(1);
}

#[test]
fn config_file_malformed_exits_1() {
    let config = write_config("[[[broken");
    cloak()
        .arg("--config")
        .arg(config.path())
        .write_stdin("")
        .assert()
        .failure()
        .code(1);
}

// ── Stats output ────────────────────────────────────────────────────

#[test]
fn stats_json_format() {
    let input =
        "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\n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\n";
    let assert = cloak()
        .arg("--stats-format")
        .arg("json")
        .write_stdin(input)
        .assert()
        .success();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    let v: serde_json::Value =
        serde_json::from_str(stderr.trim()).expect("stats must be valid JSON");
    assert_eq!(v["matches"]["github-token"], 1);
    assert_eq!(v["matches"]["npm-token"], 1);
    assert_eq!(v["bytes_processed"], input.len());
}

#[test]
fn stats_json_exact_counts() {
    // Plant 2 github + 1 npm.
    let input = "\
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
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
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
";
    let assert = cloak()
        .arg("--stats-format")
        .arg("json")
        .write_stdin(input)
        .assert()
        .success();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(
        v["matches"]["github-token"], 2,
        "expected 2 github-token matches"
    );
    assert_eq!(v["matches"]["npm-token"], 1, "expected 1 npm-token match");
}

#[test]
fn stats_text_format() {
    let assert = cloak()
        .arg("--stats-format")
        .arg("text")
        .write_stdin("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")
        .assert()
        .success();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("bytes_processed:"),
        "text stats missing bytes: {stderr}"
    );
    assert!(
        stderr.contains("total_matches: 1"),
        "text stats missing total: {stderr}"
    );
    assert!(
        stderr.contains("github-token: 1"),
        "text stats missing rule: {stderr}"
    );
}

#[test]
fn stats_silent_by_default() {
    let assert = cloak()
        .write_stdin("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")
        .assert()
        .success();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.is_empty(),
        "stderr should be empty by default: {stderr:?}"
    );
}

// ── File args ───────────────────────────────────────────────────────

#[test]
fn file_arg_single() {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(b"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\n")
        .unwrap();
    f.flush().unwrap();

    let assert = cloak().arg(f.path()).assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("[CLOAK:github-token:"),
        "file arg should produce redacted output: {stdout}"
    );
    assert!(!stdout.contains("ghp_Ab"), "secret leaked: {stdout}");
}

#[test]
fn file_args_multiple() {
    let mut f1 = tempfile::NamedTempFile::new().unwrap();
    f1.write_all(b"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\n")
        .unwrap();
    f1.flush().unwrap();

    let mut f2 = tempfile::NamedTempFile::new().unwrap();
    f2.write_all(b"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\n")
        .unwrap();
    f2.flush().unwrap();

    let assert = cloak()
        .arg("--stats-format")
        .arg("json")
        .arg(f1.path())
        .arg(f2.path())
        .assert()
        .success();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["matches"]["github-token"], 1);
    assert_eq!(v["matches"]["npm-token"], 1);
}

#[test]
fn file_arg_not_found_exits_1() {
    cloak()
        .arg("/nonexistent/file.log")
        .assert()
        .failure()
        .code(1);
}

// ── I/O robustness ──────────────────────────────────────────────────

#[test]
fn huge_single_line_no_panic() {
    // 2 MiB line with no newline — exercises the streaming path with a
    // very large carry-over buffer.
    let input = vec![b'x'; 2 * 1024 * 1024];
    cloak()
        .write_stdin(input.clone())
        .assert()
        .success()
        .stdout(input);
}

// ── Insta snapshots ─────────────────────────────────────────────────

#[test]
fn help_output_snapshot() {
    let assert = Command::cargo_bin("cloak")
        .unwrap()
        .arg("--help")
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    insta::assert_snapshot!("help", stdout);
}

#[test]
fn stats_json_snapshot() {
    // Deterministic: keyed digest, planted vectors, exact JSON output.
    let input = "\
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
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
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
";
    let assert = Command::cargo_bin("cloak")
        .unwrap()
        .env("CLOAK_DIGEST_KEY", "snapshot-key")
        .arg("--stats-format")
        .arg("json")
        .write_stdin(input)
        .assert()
        .success();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    insta::assert_snapshot!("stats-json", stderr);
}

#[test]
fn error_config_not_found_snapshot() {
    let assert = Command::cargo_bin("cloak")
        .unwrap()
        .env("CLOAK_DIGEST_KEY", "snapshot-key")
        .arg("--config")
        .arg("/nonexistent/cloak.toml")
        .write_stdin("")
        .assert()
        .failure();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    insta::assert_snapshot!("error-config-not-found", stderr);
}

#[test]
fn error_unknown_rule_snapshot() {
    let config = write_config(
        r#"
[rules.typo-rule]
enabled = false
"#,
    );
    let assert = Command::cargo_bin("cloak")
        .unwrap()
        .env("CLOAK_DIGEST_KEY", "snapshot-key")
        .arg("--config")
        .arg(config.path())
        .write_stdin("")
        .assert()
        .failure();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    insta::assert_snapshot!("error-unknown-rule", stderr);
}

// ── Stats edge cases ────────────────────────────────────────────────

#[test]
fn stats_json_zero_matches() {
    // Clean input, no secrets — JSON must have empty matches object.
    let input = "nothing to see here, just plain text\n";
    let assert = cloak()
        .arg("--stats-format")
        .arg("json")
        .write_stdin(input)
        .assert()
        .success();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(stderr.trim()).expect("valid JSON");
    assert_eq!(
        v["matches"],
        serde_json::json!({}),
        "zero matches → empty object"
    );
    assert_eq!(v["bytes_processed"], input.len());
}

#[test]
fn stats_text_zero_matches() {
    // Clean input — text format should not include per_rule section.
    let assert = cloak()
        .arg("--stats-format")
        .arg("text")
        .write_stdin("no secrets here\n")
        .assert()
        .success();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("total_matches: 0"),
        "should report zero: {stderr}"
    );
    assert!(
        !stderr.contains("per_rule:"),
        "zero matches → no per_rule section: {stderr}"
    );
}

// ── CLI flag combinations ───────────────────────────────────────────

#[test]
fn config_and_file_args_combined() {
    // --config disables github-token + file arg contains that secret.
    let config = write_config("[rules.github-token]\nenabled = false\n");
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(b"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\n")
        .unwrap();
    f.flush().unwrap();

    let assert = cloak()
        .arg("--config")
        .arg(config.path())
        .arg(f.path())
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("ghp_Ab"),
        "disabled rule + file arg: secret should pass through: {stdout}"
    );
}

#[test]
fn config_and_stats_combined() {
    // --config disables github-token + --stats-format json.
    let config = write_config("[rules.github-token]\nenabled = false\n");
    let input =
        "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\n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\n";
    let assert = cloak()
        .arg("--config")
        .arg(config.path())
        .arg("--stats-format")
        .arg("json")
        .write_stdin(input)
        .assert()
        .success();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(stderr.trim()).unwrap();
    // github-token disabled → not in stats; npm-token still detected.
    assert!(
        v["matches"].get("github-token").is_none(),
        "disabled rule should not appear in stats"
    );
    assert_eq!(v["matches"]["npm-token"], 1);
}

#[test]
fn empty_file_via_file_arg() {
    let f = tempfile::NamedTempFile::new().unwrap();
    // Empty file — 0 bytes.
    let assert = cloak()
        .arg("--stats-format")
        .arg("json")
        .arg(f.path())
        .assert()
        .success();
    let stdout = assert.get_output().stdout.clone();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stdout.is_empty(), "empty file → empty stdout");
    let v: serde_json::Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["bytes_processed"], 0);
}

#[test]
fn stats_format_invalid_value() {
    // --stats-format csv → clap error (exit 2).
    let assert = Command::cargo_bin("cloak")
        .unwrap()
        .arg("--stats-format")
        .arg("csv")
        .write_stdin("")
        .assert()
        .failure();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("csv") || stderr.contains("invalid"),
        "clap should reject invalid format: {stderr}"
    );
}

#[test]
fn empty_config_file_e2e() {
    // Empty TOML file → all defaults, all rules active.
    let config = write_config("");
    let assert = cloak()
        .arg("--config")
        .arg(config.path())
        .arg("--stats-format")
        .arg("json")
        .write_stdin("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")
        .assert()
        .success();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(
        v["matches"]["github-token"], 1,
        "empty config = all rules active"
    );
}

// ── Token split across file args ────────────────────────────────────

#[test]
fn token_split_across_file_args() {
    // Session carry-over must span file boundaries.
    let mut f1 = tempfile::NamedTempFile::new().unwrap();
    // Valid CRC: CRC32("AbCdEfGhIjKlMnOpQrStUvWxYz0123") → "2piBxe"
    f1.write_all(b"ghp_AbCdEfGhIjKlMn").unwrap();
    f1.flush().unwrap();

    let mut f2 = tempfile::NamedTempFile::new().unwrap();
    f2.write_all(b"OpQrStUvWxYz01232piBxe\n").unwrap();
    f2.flush().unwrap();

    let assert = cloak()
        .arg("--stats-format")
        .arg("json")
        .arg(f1.path())
        .arg(f2.path())
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(
        v["matches"]["github-token"], 1,
        "token split across files must be detected"
    );
    assert!(
        !stdout.contains("ghp_Ab"),
        "split token must be redacted: {stdout}"
    );
}

// ── Fix B: ephemeral warning + stats JSON coexistence ───────────────

#[test]
fn stats_json_with_ephemeral_warning() {
    // When CLOAK_DIGEST_KEY is unset, stderr has a warning line THEN
    // the JSON line. The last non-empty line must be valid JSON.
    let assert = Command::cargo_bin("cloak")
        .unwrap()
        .env_remove("CLOAK_DIGEST_KEY")
        .arg("--stats-format")
        .arg("json")
        .write_stdin("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")
        .assert()
        .success();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    // stderr has warning + JSON on separate lines.
    assert!(
        stderr.contains("ephemeral"),
        "should contain ephemeral key warning: {stderr}"
    );
    let last_line = stderr.lines().rfind(|l| !l.is_empty()).unwrap();
    let v: serde_json::Value = serde_json::from_str(last_line).unwrap_or_else(|e| {
        panic!("last line of stderr must be valid JSON: {e}\nstderr: {stderr}")
    });
    assert_eq!(v["matches"]["github-token"], 1);
}

// ── Fix C: non-env: digest_key rejected at e2e level ────────────────

#[test]
fn config_digest_key_non_env_prefix_exits_1() {
    let config = write_config("[redaction]\ndigest_key = \"my-secret-key\"\n");
    let assert = cloak()
        .arg("--config")
        .arg(config.path())
        .write_stdin("")
        .assert()
        .failure()
        .code(1);
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("env:"),
        "error should mention env: prefix: {stderr}"
    );
}

// ── Tests D: remaining medium/low gaps ──────────────────────────────

#[test]
fn config_directory_as_path_exits_1() {
    let dir = tempfile::tempdir().unwrap();
    cloak()
        .arg("--config")
        .arg(dir.path())
        .write_stdin("")
        .assert()
        .failure()
        .code(1);
}

#[test]
fn config_type_mismatch_exits_1() {
    // enabled = "yes" is a string, not a bool → serde type error.
    let config = write_config("[rules.github-token]\nenabled = \"yes\"\n");
    let assert = cloak()
        .arg("--config")
        .arg(config.path())
        .write_stdin("")
        .assert()
        .failure()
        .code(1);
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("invalid") || stderr.contains("expected"),
        "type mismatch should produce useful error: {stderr}"
    );
}

#[test]
fn config_malformed_error_message_quality() {
    let config = write_config("[[[broken");
    let assert = cloak()
        .arg("--config")
        .arg(config.path())
        .write_stdin("")
        .assert()
        .failure()
        .code(1);
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        !stderr.is_empty(),
        "malformed config should produce an error message"
    );
    assert!(
        stderr.contains("parse") || stderr.contains("invalid") || stderr.contains("expected"),
        "error should be descriptive: {stderr}"
    );
}

#[test]
fn config_custom_digest_key_env_var_e2e() {
    // Config specifies a custom env var, CLI sets it → deterministic digest.
    let config = write_config("[redaction]\ndigest_key = \"env:CLOAK_CUSTOM_E2E_KEY\"\n");
    let secret = "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";
    let key = blake3::derive_key("cloak digest key", b"custom-key-material");
    let digest = cloak_core::compute_digest(secret.as_bytes(), &key);
    let tag = cloak_core::format_tag(&cloak_core::RuleId::new("github-token"), &digest);
    let expected = format!("{tag}\n");

    Command::cargo_bin("cloak")
        .unwrap()
        .env("CLOAK_CUSTOM_E2E_KEY", "custom-key-material")
        .arg("--config")
        .arg(config.path())
        .write_stdin(format!("{secret}\n"))
        .assert()
        .success()
        .stdout(expected);
}
