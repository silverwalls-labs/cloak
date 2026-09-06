use cloak_core::{Config, Digest, Engine, RuleId, Stats, compute_digest, format_tag, write_tag};

fn engine() -> Engine {
    let config = Config {
        digest_key_env: None, // ephemeral key, no env lookup
    };
    Engine::new(&config).unwrap()
}

#[test]
fn full_passthrough() {
    let engine = engine();
    let mut session = engine.session();
    let input = b"\
2026-09-06T10:15:30.123Z INFO  app::server - Listening on 0.0.0.0:8080
2026-09-06T10:15:31.456Z DEBUG app::db - Connected to database
2026-09-06T10:15:32.789Z ERROR app::handler - Request failed: timeout
";
    let mut output = Vec::new();
    session.push(input, &mut output).unwrap();
    let stats = session.finish(&mut output).unwrap();
    assert_eq!(output, input);
    assert_eq!(stats.bytes_processed, input.len() as u64);
}

#[test]
fn empty_input() {
    let engine = engine();
    let session = engine.session();
    let mut output = Vec::new();
    let stats = session.finish(&mut output).unwrap();
    assert!(output.is_empty());
    assert_eq!(stats.bytes_processed, 0);
}

#[test]
fn large_buffer() {
    let engine = engine();
    let mut session = engine.session();
    // 256 KiB of repeated text — larger than the 64 KiB default read chunk.
    let line = b"The quick brown fox jumps over the lazy dog.\n";
    let input: Vec<u8> = line.iter().cycle().take(256 * 1024).copied().collect();
    let mut output = Vec::new();
    session.push(&input, &mut output).unwrap();
    let stats = session.finish(&mut output).unwrap();
    assert_eq!(output, input);
    assert_eq!(stats.bytes_processed, input.len() as u64);
}

#[test]
fn binary_data() {
    let engine = engine();
    let mut session = engine.session();
    // Every byte value 0x00..=0xFF — including invalid UTF-8.
    let input: Vec<u8> = (0..=255).collect();
    let mut output = Vec::new();
    session.push(&input, &mut output).unwrap();
    let stats = session.finish(&mut output).unwrap();
    assert_eq!(output, input, "binary data must pass through unchanged");
    assert_eq!(stats.bytes_processed, 256);
}

#[test]
fn multiple_sessions_from_same_engine() {
    let engine = engine();

    let mut s1 = engine.session();
    let mut out1 = Vec::new();
    s1.push(b"session-one", &mut out1).unwrap();
    let stats1 = s1.finish(&mut out1).unwrap();

    let mut s2 = engine.session();
    let mut out2 = Vec::new();
    s2.push(b"session-two", &mut out2).unwrap();
    let stats2 = s2.finish(&mut out2).unwrap();

    assert_eq!(out1, b"session-one");
    assert_eq!(out2, b"session-two");
    assert_eq!(stats1.bytes_processed, 11);
    assert_eq!(stats2.bytes_processed, 11);
}

#[test]
fn bytes_processed_accuracy() {
    let engine = engine();
    let mut session = engine.session();
    let mut output = Vec::new();
    session.push(b"aaa", &mut output).unwrap();
    session.push(b"bb", &mut output).unwrap();
    session.push(b"c", &mut output).unwrap();
    let stats = session.finish(&mut output).unwrap();
    assert_eq!(stats.bytes_processed, 6);
}

// ── Redaction writer (public API) ──────────────────────────────────

#[test]
fn redaction_tag_format() {
    let rule = RuleId::new("aws-access-key");
    let digest = Digest::new([0x9f, 0x3a]);
    assert_eq!(format_tag(&rule, &digest), "[CLOAK:aws-access-key:9f3a]");
}

#[test]
fn redaction_write_tag_matches_format() {
    let rule = RuleId::new("email");
    let digest = Digest::new([0x00, 0xff]);
    let mut buf = Vec::new();
    write_tag(&rule, &digest, &mut buf).unwrap();
    assert_eq!(String::from_utf8(buf).unwrap(), format_tag(&rule, &digest));
}

#[test]
fn compute_digest_deterministic() {
    let key = blake3::derive_key("integration test key", b"test-material");
    let d1 = compute_digest(b"some-secret-value", &key);
    let d2 = compute_digest(b"some-secret-value", &key);
    assert_eq!(d1, d2);
}

#[test]
fn compute_digest_varies_with_input() {
    let key = blake3::derive_key("integration test key", b"test-material");
    let d1 = compute_digest(b"secret-a", &key);
    let d2 = compute_digest(b"secret-b", &key);
    assert_ne!(d1, d2);
}

// ── Config + Engine construction ──────────────────────────────────

#[test]
fn default_config_constructs_engine() {
    // Uses CLOAK_DIGEST_KEY env var (likely unset → ephemeral).
    let config = Config::default();
    let engine = Engine::new(&config);
    assert!(engine.is_ok());
}

#[test]
fn explicit_ephemeral_config() {
    let config = Config {
        digest_key_env: None,
    };
    let engine = Engine::new(&config);
    assert!(engine.is_ok());
}

// ── Stats ─────────────────────────────────────────────────────────

#[test]
fn stats_total_matches_through_api() {
    let stats = Stats::default();
    assert_eq!(stats.total_matches(), 0);
    assert_eq!(stats.bytes_processed, 0);
}

// ── RuleId ordering ───────────────────────────────────────────────

#[test]
fn rule_id_ordering_is_deterministic() {
    let a = RuleId::new("aws-access-key");
    let b = RuleId::new("github-token");
    let c = RuleId::new("email");
    let mut rules = vec![b.clone(), c.clone(), a.clone()];
    rules.sort();
    assert_eq!(rules, vec![a, c, b]);
}
