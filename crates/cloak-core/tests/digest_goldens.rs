//! Integration tier: digest-stability goldens (docs/03 §cross-cutting).
//!
//! The correlation promise: same input + same key ⇒ same
//! `[CLOAK:rule:xxxx]` tag across releases. Digests live in stored logs
//! and dashboards — changing them (digest algorithm, KDF context, tag
//! format, redaction span of the first positive vector) is a BREAKING
//! change and must fail here, not slip through.
//!
//! Inputs are referenced from the vector suites (defined once, docs/03);
//! only the tag literals are committed here. If a golden changes
//! legitimately (e.g. a vector's redaction span was intentionally
//! altered), update the literal in the same PR and call it out as a
//! breaking change.

use std::sync::Once;

use cloak_core::{Config, Engine, vectors};

const KEY_VAR: &str = "CLOAK_GOLDEN_DIGEST_KEY";
const KEY_MATERIAL: &str = "digest-golden-key-v1";

static INIT: Once = Once::new();

fn golden_engine() -> Engine {
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
    Engine::new(&config).unwrap()
}

/// One golden per rule: the first positive vector's tag under the fixed
/// key. Committed 2026-09-12 (S6).
fn goldens() -> Vec<(&'static str, &'static vectors::Vector, &'static str)> {
    vec![
        (
            "github-token",
            &vectors::github_token::POSITIVE[0],
            "[CLOAK:github-token:fc44]",
        ),
        (
            "gitlab-token",
            &vectors::gitlab_token::POSITIVE[0],
            "[CLOAK:gitlab-token:18e0]",
        ),
        (
            "npm-token",
            &vectors::npm_token::POSITIVE[0],
            "[CLOAK:npm-token:071d]",
        ),
        (
            "aws-access-key",
            &vectors::aws_access_key::POSITIVE[0],
            "[CLOAK:aws-access-key:f7cd]",
        ),
        (
            "gcp-api-key",
            &vectors::gcp_api_key::POSITIVE[0],
            "[CLOAK:gcp-api-key:661b]",
        ),
        (
            "pypi-token",
            &vectors::pypi_token::POSITIVE[0],
            "[CLOAK:pypi-token:5d78]",
        ),
        (
            "aws-secret-key",
            &vectors::aws_secret_key::POSITIVE[0],
            "[CLOAK:aws-secret-key:1deb]",
        ),
        (
            "azure-style-token",
            &vectors::azure_style_token::POSITIVE[0],
            "[CLOAK:azure-style-token:5b02]",
        ),
        ("jwt", &vectors::jwt::POSITIVE[0], "[CLOAK:jwt:59d3]"),
        (
            "connection-string",
            &vectors::connection_string::POSITIVE[0],
            "[CLOAK:connection-string:73b0]",
        ),
        ("email", &vectors::email::POSITIVE[0], "[CLOAK:email:aa30]"),
        ("ipv4", &vectors::ipv4::POSITIVE[0], "[CLOAK:ipv4:c3a4]"),
        ("ipv6", &vectors::ipv6::POSITIVE[0], "[CLOAK:ipv6:6e13]"),
        (
            "credit-card",
            &vectors::credit_card::POSITIVE[0],
            "[CLOAK:credit-card:5d1a]",
        ),
        (
            "phone-intl",
            &vectors::phone_intl::POSITIVE[0],
            "[CLOAK:phone-intl:6ca9]",
        ),
        (
            "pem-private-key",
            vectors::pem::POSITIVE[0],
            "[CLOAK:pem-private-key:fa33]",
        ),
    ]
}

#[test]
fn every_rule_tag_is_stable() {
    let engine = golden_engine();
    for (rule, vector, want_tag) in goldens() {
        let mut session = engine.session();
        let mut out = Vec::new();
        session.push(vector.input, &mut out).unwrap();
        session.finish(&mut out).unwrap();
        let out = String::from_utf8_lossy(&out);
        assert!(
            out.contains(want_tag),
            "digest drift for {rule} (vector {}): expected {want_tag} in output {out:?} — \
             this is a BREAKING change to the correlation promise",
            vector.name
        );
    }
}

/// The raw digest primitive itself — trips on any change to the BLAKE3
/// keying or the "cloak digest key" KDF context string, independent of
/// engine matching.
#[test]
fn compute_digest_is_stable() {
    let key = blake3::derive_key("cloak digest key", KEY_MATERIAL.as_bytes());
    let digest = cloak_core::compute_digest(b"golden-digest-probe", &key);
    assert_eq!(
        digest.to_string(),
        "93e0",
        "raw digest drift — BLAKE3 keying or KDF context changed"
    );
}

/// The goldens table stays in sync with the rules the vector corpus
/// exercises: every rule that appears in a positive-vector span has a
/// golden, and every golden names a rule the corpus exercises.
///
/// NB: this is a vectors↔goldens consistency check, not a `CATALOG` mirror
/// — `rules::CATALOG` is `pub(crate)` and unreachable from an integration
/// test, so a new catalog rule shipped WITHOUT positive vectors would slip
/// past both this test and the corpus. The rule-catalog governance gate is
/// the unit test `rules::tests` beside the catalog; this guards the
/// downstream promise that every corpus-covered rule has a pinned tag.
#[test]
fn goldens_match_vector_rules() {
    let seen: std::collections::BTreeSet<&str> = cloak_core::vectors::all_vectors()
        .iter()
        .flat_map(|v| v.spans.iter().map(|s| s.rule))
        .collect();
    let covered: std::collections::BTreeSet<&str> =
        goldens().iter().map(|(rule, _, _)| *rule).collect();
    assert_eq!(
        seen, covered,
        "goldens table out of sync with the rules the vector corpus exercises"
    );
}
