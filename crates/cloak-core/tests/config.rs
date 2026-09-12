//! Integration tier: config-driven rule filtering through the public API.

use cloak_core::{Config, Engine, RedactionConfig, RuleConfig, RuleId};
use std::collections::BTreeMap;

fn ephemeral_config_with_rules(overrides: &[(&str, bool)]) -> Config {
    let mut rules = BTreeMap::new();
    for &(id, enabled) in overrides {
        rules.insert(id.into(), RuleConfig { enabled });
    }
    Config {
        redaction: RedactionConfig {
            digest_key: String::new(), // ephemeral, no env lookup
        },
        rules,
    }
}

fn redact(engine: &Engine, input: &[u8]) -> (Vec<u8>, cloak_core::Stats) {
    let mut session = engine.session();
    let mut out = Vec::new();
    session.push(input, &mut out).unwrap();
    let stats = session.finish(&mut out).unwrap();
    (out, stats)
}

// ── Default config: all rules detect ────────────────────────────────

#[test]
fn default_config_all_rules_detect() {
    let engine = Engine::new(&Config::ephemeral()).unwrap();
    let (output, stats) = redact(&engine, b"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");
    assert!(stats.matches.contains_key(&RuleId::new("github-token")));
    assert!(!output.windows(4).any(|w| w == b"ghp_"));
}

// ── Disable one rule: its secrets pass through ──────────────────────

#[test]
fn disabled_rule_passes_through() {
    let config = ephemeral_config_with_rules(&[("github-token", false)]);
    let engine = Engine::new(&config).unwrap();
    let input = b"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";
    let (output, stats) = redact(&engine, input);
    // github-token is disabled — secret passes through unchanged.
    assert_eq!(&output[..], &input[..]);
    assert!(!stats.matches.contains_key(&RuleId::new("github-token")));
}

#[test]
fn disabled_rule_does_not_affect_others() {
    let config = ephemeral_config_with_rules(&[("github-token", false)]);
    let engine = Engine::new(&config).unwrap();
    // npm-token should still be caught.
    let (_, stats) = redact(&engine, b"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");
    assert!(stats.matches.contains_key(&RuleId::new("npm-token")));
}

// ── Disable PEM pseudo-rule ─────────────────────────────────────────

#[test]
fn pem_disabled_passes_through() {
    let config = ephemeral_config_with_rules(&[("pem-private-key", false)]);
    let engine = Engine::new(&config).unwrap();
    let input = b"-----BEGIN RSA PRIVATE KEY-----\nBODY\n-----END RSA PRIVATE KEY-----";
    let (output, _stats) = redact(&engine, input);
    // PEM is disabled — body passes through unchanged.
    assert!(output.windows(4).any(|w| w == b"BODY"));
}

#[test]
fn pem_enabled_by_default() {
    let engine = Engine::new(&Config::ephemeral()).unwrap();
    let input = b"-----BEGIN RSA PRIVATE KEY-----\nBODY\n-----END RSA PRIVATE KEY-----";
    let (output, stats) = redact(&engine, input);
    assert!(stats.matches.contains_key(&RuleId::new("pem-private-key")));
    assert!(!output.windows(4).any(|w| w == b"BODY"));
}

// ── Disable all rules ───────────────────────────────────────────────

#[test]
fn all_rules_disabled_pure_passthrough() {
    // Disable every catalog rule + PEM.
    let known_rules = [
        "github-token",
        "gitlab-token",
        "npm-token",
        "aws-access-key",
        "gcp-api-key",
        "pypi-token",
        "aws-secret-key",
        "azure-style-token",
        "jwt",
        "connection-string",
        "email",
        "ipv4",
        "ipv6",
        "credit-card",
        "phone-intl",
        "pem-private-key",
    ];
    let overrides: Vec<(&str, bool)> = known_rules.iter().map(|id| (*id, false)).collect();
    let config = ephemeral_config_with_rules(&overrides);
    let engine = Engine::new(&config).unwrap();

    let input = b"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 and more";
    let (output, stats) = redact(&engine, input);
    assert_eq!(
        &output[..],
        &input[..],
        "all rules disabled = pure passthrough"
    );
    assert_eq!(stats.total_matches(), 0);
}

// ── Unknown rule → BuildError::InvalidConfig ────────────────────────

#[test]
fn unknown_rule_hard_error() {
    let config = ephemeral_config_with_rules(&[("not-a-rule", false)]);
    let result = Engine::new(&config);
    assert!(result.is_err(), "unknown rule should be rejected");
    let msg = result.err().unwrap().to_string();
    assert!(
        msg.contains("not-a-rule"),
        "error should name the unknown rule: {msg}"
    );
}

#[test]
fn typo_rule_hard_error() {
    let config = ephemeral_config_with_rules(&[("github_token", false)]);
    assert!(
        Engine::new(&config).is_err(),
        "underscore typo should be rejected"
    );
}

// ── Mixed enable/disable ────────────────────────────────────────────

#[test]
fn mixed_enable_disable() {
    let config = ephemeral_config_with_rules(&[
        ("github-token", false),
        ("npm-token", true),
        ("phone-intl", false),
    ]);
    let engine = Engine::new(&config).unwrap();

    // npm-token: enabled → redacted
    let (_, stats) = redact(&engine, b"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");
    assert!(stats.matches.contains_key(&RuleId::new("npm-token")));

    // github-token: disabled → passthrough
    let input = b"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";
    let (output, _) = redact(&engine, input);
    assert_eq!(&output[..], &input[..]);
}

// ── TOML round-trip ─────────────────────────────────────────────────

#[test]
fn from_toml_enables_and_disables() {
    let toml = r#"
[rules.github-token]
enabled = false

[rules.npm-token]
enabled = true
"#;
    let config = Config::from_toml(toml).unwrap();
    assert!(!config.is_rule_enabled("github-token"));
    assert!(config.is_rule_enabled("npm-token"));
    assert!(config.is_rule_enabled("aws-access-key")); // not mentioned → enabled
}

// ── Config + streaming integration ──────────────────────────────────
// The streaming guarantee (chunk-boundary invariant) must hold when
// rules are filtered — this category was entirely untested before S5
// test hardening. (Filtered max_window assertions live in the engine
// unit tests — they need private field access.)

fn all_rules_off() -> Vec<(&'static str, bool)> {
    [
        "github-token",
        "gitlab-token",
        "npm-token",
        "aws-access-key",
        "gcp-api-key",
        "pypi-token",
        "aws-secret-key",
        "azure-style-token",
        "jwt",
        "connection-string",
        "email",
        "ipv4",
        "ipv6",
        "credit-card",
        "phone-intl",
        "pem-private-key",
    ]
    .iter()
    .map(|id| (*id, false))
    .collect()
}

#[test]
fn pem_only_streaming_detects_split_begin() {
    // Regression test: all catalog rules disabled, PEM enabled.
    // PEM BEGIN anchor split across two small pushes must still be detected.
    // Before fix: max_window was 0 → no carry-over → BEGIN flushed → key leaked.
    let catalog_off: Vec<(&str, bool)> = all_rules_off()
        .into_iter()
        .filter(|(id, _)| *id != "pem-private-key")
        .collect();
    let config = ephemeral_config_with_rules(&catalog_off);
    let engine = Engine::new(&config).unwrap();

    let input = b"-----BEGIN RSA PRIVATE KEY-----\nBODY\n-----END RSA PRIVATE KEY-----";

    // Whole buffer (reference).
    let (whole, whole_stats) = redact(&engine, input);
    assert_eq!(whole_stats.matches[&RuleId::new("pem-private-key")], 1);

    // 1-byte streaming (exercises carry-over).
    let mut session = engine.session();
    let mut chunked = Vec::new();
    for &byte in input.iter() {
        session.push(&[byte], &mut chunked).unwrap();
    }
    let chunked_stats = session.finish(&mut chunked).unwrap();

    assert_eq!(chunked, whole, "PEM-only streaming must equal whole-buffer");
    assert_eq!(
        chunked_stats.matches, whole_stats.matches,
        "PEM-only streaming stats must match"
    );
    // Body must not leak.
    assert!(
        !chunked.windows(4).any(|w| w == b"BODY"),
        "PEM body must be redacted in PEM-only mode"
    );
}

#[test]
fn disabled_rule_at_chunk_boundary_streaming() {
    // A github-token split across two pushes with github-token disabled
    // must pass through unchanged — carry-over must not accidentally
    // detect disabled rules.
    let config = ephemeral_config_with_rules(&[("github-token", false)]);
    let engine = Engine::new(&config).unwrap();
    let mut session = engine.session();
    let mut output = Vec::new();
    // Split the token mid-body.
    session.push(b"ghp_AbCdEfGhIjKlMn", &mut output).unwrap();
    session
        .push(b"OpQrStUvWxYz01232piBxe tail", &mut output)
        .unwrap();
    let stats = session.finish(&mut output).unwrap();
    let full_input = b"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 tail";
    assert_eq!(
        &output[..],
        &full_input[..],
        "disabled rule: split token must pass through"
    );
    assert!(!stats.matches.contains_key(&RuleId::new("github-token")));
}

#[test]
fn pem_disabled_streaming_passthrough() {
    // Stream PEM data in small chunks with PEM disabled — body must
    // pass through, no panic from unregistered PEM anchor.
    let config = ephemeral_config_with_rules(&[("pem-private-key", false)]);
    let engine = Engine::new(&config).unwrap();
    let input = b"-----BEGIN RSA PRIVATE KEY-----\nBODY\n-----END RSA PRIVATE KEY-----";
    let mut session = engine.session();
    let mut chunked = Vec::new();
    for chunk in input.chunks(7) {
        session.push(chunk, &mut chunked).unwrap();
    }
    let stats = session.finish(&mut chunked).unwrap();
    assert_eq!(
        &chunked[..],
        &input[..],
        "PEM disabled: chunked streaming must pass through"
    );
    assert!(!stats.matches.contains_key(&RuleId::new("pem-private-key")));
}

#[test]
fn streaming_equivalence_with_partial_filtering() {
    // With some rules disabled, whole-buffer must still equal chunked
    // output — the chunk-boundary invariant must hold after filtering.
    let config = ephemeral_config_with_rules(&[
        ("github-token", false),
        ("phone-intl", false),
        ("email", false),
    ]);
    let engine = Engine::new(&config).unwrap();
    // Test with an npm-token (still enabled) plus clean text.
    let input = b"prefix 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 suffix and more text here";

    // Whole buffer.
    let (whole, whole_stats) = redact(&engine, input);

    // 1-byte chunks.
    let mut session = engine.session();
    let mut chunked = Vec::new();
    for &byte in input.iter() {
        session.push(&[byte], &mut chunked).unwrap();
    }
    let chunked_stats = session.finish(&mut chunked).unwrap();

    assert_eq!(
        chunked, whole,
        "streaming must equal whole-buffer with partial filtering"
    );
    assert_eq!(chunked_stats.matches, whole_stats.matches);
}
