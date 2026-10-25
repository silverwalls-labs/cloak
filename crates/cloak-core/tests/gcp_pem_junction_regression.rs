//! Regression tests for #53: the gcp-api-key fixed-length body must not
//! overlap with an adjacent PEM marker junction.
//!
//! The body charset `[0-9A-Za-z_-]` includes dashes and the letters
//! B/D/E/G/I/N. With a fixed 35-char body, the DFA pattern consumed
//! part of an abutting PEM marker's dash run (and possibly its word).
//! Unlike variable-length rules, the body cannot be shortened — the
//! match is rejected entirely when an overlap is detected.

use cloak_core::{Config, Engine, RedactionConfig};
use std::sync::LazyLock;

/// AIza + 35 body chars that do NOT overlap a PEM marker = 39 bytes.
const GCP39: &[u8] = b"AIzaSyC0123456789abcdefghijklmnopqrstuv";

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

/// The exact reproducer from issue #53: gcp + `-----END PRIVATE
/// KEY-----` + fused BEGIN block. The overlap check rejects the gcp
/// match, preserving the full PEM trailer.
#[test]
fn repro_gcp_pem_trailer() {
    let (engine, key) = engine_and_key();
    let mut input = b"AIzaSyA0123456789abcdefghijklmnop".to_vec();
    input.extend_from_slice(b"-----END PRIVATE KEY-----BEGIN RSA PRIVATE KEY-----\nAAAA\n");
    // gcp rejected (overlap), PEM trailer intact → the fused BEGIN is
    // rejected by the shared-dash guard → only the text passes through.
    // No matches at all.
    check_shape(&engine, &key, "issue-53-gcp-repro", &input, 0, true);
}

/// gcp + N dashes + `END PRIVATE KEY` + fused BEGIN block.
/// The overlap check fires whenever the body's trailing dashes (+ word)
/// can reconstruct a PEM `-----END ` marker. At N=0 the body has no
/// trailing dashes (it ends at `p`) — gcp confirms, PEM trailer follows.
#[test]
fn gcp_trailer_junction_sweep() {
    let (engine, key) = engine_and_key();
    for dashes in 0..=12usize {
        // Build: GCP prefix + (35 - dashes) alnum + dashes + END ...
        // But the body is always exactly 35 chars. The dashes and word
        // chars eat into the body from the right.
        let alnum_len = 35usize.saturating_sub(dashes.min(35));
        let body_dashes = dashes.min(35);
        let mut input = b"AIza".to_vec();
        input.extend(std::iter::repeat_n(b'a', alnum_len));
        input.resize(input.len() + body_dashes, b'-');
        // After the 35-char body: remaining dashes (if dashes > 35) + END ...
        // Since dashes <= 12 and body is 35, all dashes fit in the body.
        input.extend_from_slice(b"END PRIVATE KEY-----BEGIN RSA PRIVATE KEY-----\nAAAA\n");

        let (matches, visible) = if dashes >= 1 {
            // Overlap detected → gcp rejected. The END trailer may or
            // may not form a valid `-----END ` depending on total dash
            // count:
            match dashes {
                1..=4 => {
                    // 1-4 body dashes + "END " after → combined has < 5
                    // dashes before END, but the overlap check still
                    // tries offset 0: tail_part = dashes + after. Let's
                    // trace: with 1 dash, tail="-", after="END ...",
                    // combined at o=0 = "-END ..." → doesn't start with
                    // "-----END ". So overlap check returns false → gcp
                    // accepted. No valid `-----END ` exists either.
                    (2u64, false)
                }
                5..=8 => {
                    // Body has 5+ dashes. Overlap check finds a valid
                    // PEM marker → gcp rejected. The `-----END ` prefix
                    // is preserved → PEM trailer is detected → shared-
                    // dash guard rejects the fused BEGIN. 0 matches.
                    (0, true)
                }
                _ => {
                    // 9+ dashes: the body consumed > 8 chars of
                    // junction. The "END" word may or may not be in the
                    // body depending on alignment. But overlap check
                    // should fire. 0 matches.
                    (0, true)
                }
            }
        } else {
            // No trailing dashes → gcp accepted. The `END PRIVATE
            // KEY-----BEGIN` that follows has no `-----END ` prefix, so
            // the BEGIN is seen as independent. PEM body redacts.
            (2, false)
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

/// gcp (clean, no PEM overlap) + PEM block — both should match.
#[test]
fn gcp_clean_before_pem_block() {
    let (engine, key) = engine_and_key();
    let mut input = GCP39.to_vec();
    input.extend_from_slice(
        b" -----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n",
    );
    // Space separates the gcp key from the PEM block — no overlap.
    check_shape(&engine, &key, "gcp-clean-then-pem", &input, 2, false);
}
