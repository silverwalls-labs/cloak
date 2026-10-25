//! Regression tests for #53: the pypi-token greedy body scan must not
//! consume the head of an adjacent PEM marker junction.
//!
//! The body charset `[A-Za-z0-9_-]` includes dashes and the letters
//! B/D/E/G/I/N — all of which appear in PEM markers. The DFA pattern
//! ate `-----END` / `-----BEGIN` from abutting trailers, erasing the
//! bytes the #44 shared-dash guard reads. The Custom confirm +
//! `rollback_pem_marker` returns the entire trailing dash run so trailer
//! bytes and `dashes_before` counts are pass-stable.

use cloak_core::{Config, Engine, RedactionConfig};
use std::sync::LazyLock;

/// pypi- + 50 body chars = 55 bytes total.
fn pypi55() -> Vec<u8> {
    b"pypi-AgEIcHlwaS5vcmcCJDU4ZjYyYjQ5LTk4OTAtNDA5OC1hOWJiYQ".to_vec()
}

static KEY_ENV: LazyLock<()> = LazyLock::new(|| {
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { std::env::set_var("TEST_DIGEST_KEY", "test-digest-key") }
});

fn engine_and_key() -> (Engine, [u8; 32]) {
    LazyLock::force(&KEY_ENV);
    let config = Config {
        redaction: RedactionConfig {
            digest_key: "env:TEST_DIGEST_KEY".to_string(),
        },
        ..Config::default()
    };
    let engine = Engine::new(&config).unwrap();
    let key = blake3::derive_key("cloak digest key", b"test-digest-key");
    (engine, key)
}

fn whole(engine: &Engine, input: &[u8]) -> (Vec<u8>, cloak_core::Stats) {
    let mut session = engine.session();
    let mut out = Vec::new();
    session.push(input, &mut out).unwrap();
    let stats = session.finish(&mut out).unwrap();
    (out, stats)
}

fn check_shape(
    engine: &Engine,
    key: &[u8; 32],
    name: &str,
    input: &[u8],
    expected_matches: u64,
    body_visible: bool,
) {
    let (pass1, stats1) = whole(engine, input);
    assert_eq!(
        stats1.total_matches(),
        expected_matches,
        "{name}: unexpected match count\n  pass1: {:?}",
        String::from_utf8_lossy(&pass1),
    );
    assert_eq!(
        pass1.windows(4).any(|w| w == b"AAAA"),
        body_visible,
        "{name}: PEM body visibility wrong\n  pass1: {:?}",
        String::from_utf8_lossy(&pass1),
    );

    let (pass2, stats2) = whole(engine, &pass1);
    let (pass3, _) = whole(engine, &pass2);
    assert_eq!(
        pass2,
        pass1,
        "{name}: redaction not idempotent\n  pass1: {:?}\n  pass2: {:?}",
        String::from_utf8_lossy(&pass1),
        String::from_utf8_lossy(&pass2),
    );
    assert_eq!(pass3, pass1, "{name}: pass 3 diverges from pass 1");
    assert_eq!(
        stats2.matches.values().sum::<u64>(),
        0,
        "{name}: tags re-matched on second pass"
    );

    let (ref_out, ref_stats) = cloak_core::reference::redact(input, key);
    assert_eq!(
        pass1,
        ref_out.as_slice(),
        "{name}: engine ≢ reference\n  engine: {:?}\n  ref:    {:?}",
        String::from_utf8_lossy(&pass1),
        String::from_utf8_lossy(&ref_out),
    );
    assert_eq!(
        stats1.matches, ref_stats.matches,
        "{name}: stats diverge from reference"
    );

    for cs in [1usize, 3, 7, 41, 64, 1024] {
        let mut session = engine.session();
        let mut out = Vec::new();
        for chunk in input.chunks(cs) {
            session.push(chunk, &mut out).unwrap();
        }
        let stats = session.finish(&mut out).unwrap();
        assert_eq!(
            out,
            pass1,
            "{name} cs={cs}: streaming ≢ whole-buffer\n  whole:    {:?}\n  streamed: {:?}",
            String::from_utf8_lossy(&pass1),
            String::from_utf8_lossy(&out),
        );
        assert_eq!(
            stats.matches, stats1.matches,
            "{name} cs={cs}: stats diverge"
        );
    }
}

#[test]
fn repro_pypi_pem_trailer() {
    let (engine, key) = engine_and_key();
    let mut input = pypi55();
    input.extend_from_slice(b"-----END PRIVATE KEY-----BEGIN RSA PRIVATE KEY-----\nAAAA\n");
    check_shape(&engine, &key, "issue-53-pypi-repro", &input, 1, true);
}

#[test]
fn pypi_trailer_junction_sweep() {
    let (engine, key) = engine_and_key();
    for dashes in 0..=12usize {
        let mut input = pypi55();
        input.resize(input.len() + dashes, b'-');
        input.extend_from_slice(b"END PRIVATE KEY-----BEGIN RSA PRIVATE KEY-----\nAAAA\n");
        let (matches, visible) = match dashes {
            0..=4 => (2u64, false),
            _ => (1, true),
        };
        check_shape(
            &engine,
            &key,
            &format!("trailer dashes={dashes}"),
            &input,
            matches,
            visible,
        );
    }
}

#[test]
fn pypi_begin_junction_sweep() {
    let (engine, key) = engine_and_key();
    for dashes in 0..=12usize {
        let mut input = pypi55();
        input.resize(input.len() + dashes, b'-');
        input.extend_from_slice(
            b"BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n",
        );
        let (matches, visible) = match dashes {
            0..=4 => (1u64, true),
            5 => (2, false),
            6..=9 => (1, true),
            _ => (2, false),
        };
        check_shape(
            &engine,
            &key,
            &format!("begin dashes={dashes}"),
            &input,
            matches,
            visible,
        );
    }
}
