//! Integration tier: per-rule vector suites through the public Engine API
//! (docs/03, "Test taxonomy"). Vector data lives beside the rules and is
//! reused verbatim — never duplicated here.

use std::sync::Once;

use cloak_core::{Config, Engine};

const KEY_VAR: &str = "CLOAK_ITEST_DIGEST_KEY";
const KEY_MATERIAL: &str = "integration-test-key";

static INIT: Once = Once::new();

/// Engine with a deterministic digest key, plus the raw key bytes for
/// computing expected outputs. `Once` removes the set_var race (integration
/// tests run multi-threaded).
fn engine_and_key() -> (Engine, [u8; 32]) {
    INIT.call_once(|| {
        // SAFETY: test-only; single dedicated var, set exactly once before
        // any engine is built, never removed.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { std::env::set_var(KEY_VAR, KEY_MATERIAL) };
    });
    let config = Config {
        redaction: cloak_core::RedactionConfig {
            digest_key: format!("env:{KEY_VAR}"),
        },
        ..Config::default()
    };
    let engine = Engine::new(&config).unwrap();
    // Must mirror config::resolve_digest_key's KDF (context string pinned by
    // the `known_vector_stability` golden in cloak-core).
    let key = blake3::derive_key("cloak digest key", KEY_MATERIAL.as_bytes());
    (engine, key)
}

fn redact_one_push(engine: &Engine, input: &[u8]) -> (Vec<u8>, cloak_core::Stats) {
    let mut session = engine.session();
    let mut out = Vec::new();
    session.push(input, &mut out).unwrap();
    let stats = session.finish(&mut out).unwrap();
    (out, stats)
}

#[test]
fn every_vector_through_public_api() {
    let (engine, key) = engine_and_key();
    for v in cloak_core::vectors::all_vectors() {
        let (out, stats) = redact_one_push(&engine, v.input);
        assert_eq!(
            out,
            cloak_core::vectors::expected_output(v, &key),
            "engine output mismatch on vector {}",
            v.name
        );
        assert_eq!(stats.bytes_processed, v.input.len() as u64, "{}", v.name);
        assert_eq!(
            stats.total_matches(),
            v.spans.len() as u64,
            "match count mismatch on vector {}",
            v.name
        );
        // Per-rule attribution matches the expected spans exactly.
        for span in v.spans {
            let expected = v.spans.iter().filter(|s| s.rule == span.rule).count() as u64;
            let rule_id = cloak_core::RuleId::new(span.rule);
            assert_eq!(
                stats.matches[&rule_id], expected,
                "{}: rule {}",
                v.name, span.rule
            );
        }
    }
}

#[test]
fn digest_correlation_same_secret_same_tag() {
    let (engine, _) = engine_and_key();
    let token = b"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";
    let mut input = token.to_vec();
    input.push(b'\n');
    input.extend_from_slice(token);
    let (out, stats) = redact_one_push(&engine, &input);

    let text = String::from_utf8(out).expect("tags and separator are ASCII");
    let lines: Vec<&str> = text.split('\n').collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(
        lines[0], lines[1],
        "same secret + same key must produce identical tags"
    );
    assert!(lines[0].starts_with("[CLOAK:github-token:"));
    assert_eq!(stats.total_matches(), 2);
}

#[test]
fn smoke_golden_redaction() {
    // Pins the golden used by CI's "Smoke — golden redaction" step
    // (.github/workflows/quality-gates.yaml). If a digest or tag change
    // breaks that step, this test must break first, with a better message.
    let key = blake3::derive_key("cloak digest key", b"smoke-test-key");
    // Valid CRC: CRC32("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") → "0uCPlr"
    let secret = b"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";
    let digest = cloak_core::compute_digest(secret, &key);
    let tag = cloak_core::format_tag(&cloak_core::RuleId::new("github-token"), &digest);
    assert_eq!(tag, "[CLOAK:github-token:c122]");
}

#[test]
fn deterministic_key_is_stable_across_engines() {
    // Two engines built from the same env var must correlate.
    let (engine_a, _) = engine_and_key();
    let (engine_b, _) = engine_and_key();
    let token = b"glpat-abcdefghij0123456789";
    let (out_a, _) = redact_one_push(&engine_a, token);
    let (out_b, _) = redact_one_push(&engine_b, token);
    assert_eq!(out_a, out_b);
}

// ── S3: PEM through the public API ───────────────────────────────────

fn redact_chunked(
    engine: &Engine,
    input: &[u8],
    chunk_size: usize,
) -> (Vec<u8>, cloak_core::Stats) {
    let mut session = engine.session();
    let mut out = Vec::new();
    for chunk in input.chunks(chunk_size) {
        session.push(chunk, &mut out).unwrap();
    }
    let stats = session.finish(&mut out).unwrap();
    (out, stats)
}

#[test]
fn pem_vectors_chunked_match_whole_buffer() {
    // Every PEM vector: 7-byte chunks must produce identical output to
    // single whole-buffer push — tests the carry-over for PEM blocks.
    let (engine, key) = engine_and_key();
    for v in cloak_core::vectors::all_vectors() {
        if !v.name.starts_with("pem-") {
            continue;
        }
        let expected = cloak_core::vectors::expected_output(v, &key);
        let (whole, _) = redact_one_push(&engine, v.input);
        let (chunked, _) = redact_chunked(&engine, v.input, 7);
        assert_eq!(whole, expected, "whole-buffer PEM mismatch on '{}'", v.name);
        assert_eq!(chunked, expected, "chunked PEM mismatch on '{}'", v.name);
    }
}

#[test]
fn mixed_secrets_and_pem_in_one_stream() {
    // Tokens and PEM interleaved in one stream — all must be detected.
    let (engine, _) = engine_and_key();
    let mut input = b"log: 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 leaked\n".to_vec();
    input.extend_from_slice(
        b"-----BEGIN EC PRIVATE KEY-----\nECKEYDATA\n-----END EC PRIVATE KEY-----\n",
    );
    input.extend_from_slice(b"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\n");

    let (out, stats) = redact_one_push(&engine, &input);
    let text = String::from_utf8_lossy(&out);

    assert!(
        stats
            .matches
            .contains_key(&cloak_core::RuleId::new("npm-token"))
    );
    assert!(
        stats
            .matches
            .contains_key(&cloak_core::RuleId::new("pem-private-key"))
    );
    assert!(
        stats
            .matches
            .contains_key(&cloak_core::RuleId::new("github-token"))
    );
    assert_eq!(stats.total_matches(), 3);

    // No secrets leaked.
    assert!(!text.contains("npm_Ab"), "npm token leaked");
    assert!(!text.contains("ECKEYDATA"), "PEM body leaked");
    assert!(!text.contains("ghp_Ab"), "github token leaked");
}

#[test]
fn pem_bail_out_large_body_through_api() {
    // PEM body exceeding PEM_BAIL_OUT (16 KiB). The bail-out path must
    // redact the first 16 KiB. Bytes past the bail-out point may pass
    // through (they're no longer considered PEM body).
    let (engine, _) = engine_and_key();
    // Use a recognizable prefix so we can verify it's redacted.
    let mut body = b"SECRET_PREFIX_".to_vec();
    body.extend(vec![b'A'; 20_000 - body.len()]);
    let mut input = b"-----BEGIN RSA PRIVATE KEY-----\n".to_vec();
    input.extend_from_slice(&body);
    input.push(b'\n');
    input.extend_from_slice(b"-----END RSA PRIVATE KEY-----");

    let (out, stats) = redact_one_push(&engine, &input);
    let text = String::from_utf8_lossy(&out);

    assert!(
        stats
            .matches
            .contains_key(&cloak_core::RuleId::new("pem-private-key")),
        "bail-out must still detect PEM"
    );
    assert!(text.contains("[CLOAK:pem-private-key:"));
    // The prefix is in the first 16 KiB of body — must be redacted.
    assert!(
        !text.contains("SECRET_PREFIX_"),
        "body prefix within bail-out window must be redacted"
    );
}
