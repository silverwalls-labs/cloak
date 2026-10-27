//! Regression tests for #53: the credit-card trailing-separator trim must
//! strip ALL trailing dashes, not just one.
//!
//! When a card number like `4539578763621486` abuts a PEM trailer
//! (`-----END PRIVATE KEY-----`), the scan loop consumes all 5 dashes as
//! separators. A single-step `if` trim removed only 1, leaving 4 dashes
//! in the match — destroying the PEM trailer the shared-dash guard
//! (engine/pem.rs: `dashes_before`) needs. The `while`-loop fix trims
//! all trailing non-digit bytes, preserving the trailer for pass-stable
//! PEM decisions. These tests sweep junction widths and pin the three
//! correctness equivalences.

use cloak_core::{Config, Engine, RedactionConfig};
use std::sync::LazyLock;

/// Visa test card — 16 digits, Luhn-valid.
const CC16: &[u8] = b"4539578763621486";

/// Set `TEST_DIGEST_KEY` exactly once, before any `Engine` is built.
static KEY_ENV: LazyLock<()> = LazyLock::new(|| {
    // SAFETY: written exactly once under LazyLock's init lock, before
    // any Engine (the only reader) is built; nothing else touches
    // TEST_DIGEST_KEY.
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

/// Assert the full contract for one input: match count, PEM-body
/// (`AAAA`) visibility, three-pass idempotence with no re-matched tags,
/// engine ≡ reference, streaming ≡ whole-buffer.
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

/// The exact reproducer from issue #53: cc then `-----END PRIVATE
/// KEY-----` then fused BEGIN block. The while-loop trim must strip all
/// 5 dashes to preserve the trailer for stable PEM decisions.
#[test]
fn repro_cc_pem_trailer() {
    let (engine, key) = engine_and_key();
    let mut input = CC16.to_vec();
    input.extend_from_slice(b"-----END PRIVATE KEY-----BEGIN RSA PRIVATE KEY-----\nAAAA\n");
    check_shape(&engine, &key, "issue-53-cc-repro", &input, 2, false);
}

/// cc + N dashes + `END PRIVATE KEY` + fused BEGIN block. Below 5
/// dashes there is no `-----END ` literal, so the BEGIN confirms and the
/// EOF bail-out hides the body; at ≥5 the trim keeps the trailer intact
/// and the fused BEGIN is accepted (#46) — both redact.
#[test]
fn cc_trailer_junction_sweep() {
    let (engine, key) = engine_and_key();
    for dashes in 0..=12usize {
        let mut input = CC16.to_vec();
        input.resize(input.len() + dashes, b'-');
        input.extend_from_slice(b"END PRIVATE KEY-----BEGIN RSA PRIVATE KEY-----\nAAAA\n");
        let (matches, visible) = (2u64, false);
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

/// cc + N dashes + `BEGIN RSA PRIVATE KEY-----` + complete block.
/// 0–4: no `-----BEGIN ` anchor exists, cc is the only match.
/// ≥5: fused markers accepted (#46) — cc + pem.
#[test]
fn cc_begin_junction_sweep() {
    let (engine, key) = engine_and_key();
    for dashes in 0..=12usize {
        let mut input = CC16.to_vec();
        input.resize(input.len() + dashes, b'-');
        input.extend_from_slice(
            b"BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n",
        );
        let (matches, visible) = match dashes {
            0..=4 => (1u64, true),
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
