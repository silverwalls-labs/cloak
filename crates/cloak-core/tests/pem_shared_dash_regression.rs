//! Regression tests for #44: PEM shared-dash idempotence.
//!
//! When a PEM END trailer shares dashes with a following BEGIN header
//! (fewer than the expected 10 between blocks), the markers are fused.
//! The guard in `confirm_pem_begin` / `confirm_pem_begin_ref` counts the
//! dash run before the anchor and decides:
//!
//! - junction of 6–9 dashes (1–4 before the anchor): fused or malformed
//!   header — rejected on every pass, so `redact(redact(S)) == redact(S)`
//!   holds. Known tradeoff: the fused block's body stays in the clear.
//! - junction of exactly 5 dashes (none before the anchor, private-key
//!   END trailer right before): the anchor's leading dashes double as
//!   the trailer's closing dashes — rejected on every pass.
//! - junction of ≥10 dashes: two independent markers — both redact.
//!
//! These tests sweep every junction width, two fusion shapes (after a
//! private-key block and after an unrelated CERTIFICATE block), and pin
//! the three correctness equivalences: idempotence, engine ≡ reference,
//! streaming ≡ whole-buffer.

use cloak_core::{Config, Engine, RedactionConfig};
use std::sync::LazyLock;

/// Set `TEST_DIGEST_KEY` exactly once, before any `Engine` is built.
static KEY_ENV: LazyLock<()> = LazyLock::new(|| {
    // SAFETY: the variable is written exactly once, synchronized by
    // LazyLock's initialization lock, before any test builds an Engine
    // (the only reader). Nothing else in this test binary reads or
    // writes `TEST_DIGEST_KEY`, so no thread can observe a concurrent
    // environment mutation.
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

/// A private-key block, an END trailer fused with the next BEGIN over
/// `dashes` total junction dashes (10 = clean separation), then a
/// second private-key block.
fn fused_after_private_key(dashes: usize) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(b"-----BEGIN RSA PRIVATE KEY-----\n");
    data.extend_from_slice(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
    data.extend_from_slice(b"-----END RSA PRIVATE KEY");
    data.resize(data.len() + dashes, b'-');
    data.extend_from_slice(b"BEGIN EC PRIVATE KEY-----\n");
    data.extend_from_slice(b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n");
    data.extend_from_slice(b"-----END EC PRIVATE KEY-----\n");
    data
}

/// An (unredacted) CERTIFICATE block, a junction of `dashes` dashes,
/// then a private-key block — the fused BEGIN does not follow a
/// private-key END trailer at all.
fn fused_after_certificate(dashes: usize) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(b"-----BEGIN CERTIFICATE-----\nCCCC\n-----END CERTIFICATE");
    data.resize(data.len() + dashes, b'-');
    data.extend_from_slice(b"BEGIN EC PRIVATE KEY-----\n");
    data.extend_from_slice(b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n");
    data.extend_from_slice(b"-----END EC PRIVATE KEY-----\n");
    data
}

/// Assert the full contract for one input:
///
/// - pass 1 finds exactly `expected_matches` PEM blocks;
/// - the second block's body (`BBBB`) is visible in pass-1 output iff
///   `second_body_visible` — false when it is redacted OR suppressed
///   by the first block's EOF bail-out (no END marker at 0–4 junction
///   dashes), true when it is leaked by the fused-marker reject
///   (5–9 junction dashes, the documented #44 tradeoff);
/// - redaction is idempotent (pass 2 and pass 3 equal pass 1, and
///   neither re-matches a tag);
/// - engine ≡ reference (output and stats);
/// - streaming ≡ whole-buffer at several chunk sizes (output and
///   stats).
fn check_shape(
    engine: &Engine,
    key: &[u8; 32],
    name: &str,
    input: &[u8],
    expected_matches: u64,
    second_body_visible: bool,
) {
    let (pass1, stats1) = whole(engine, input);
    assert_eq!(
        stats1.total_matches(),
        expected_matches,
        "{name}: unexpected match count\n  pass1: {:?}",
        String::from_utf8_lossy(&pass1),
    );
    assert_eq!(
        pass1.windows(4).any(|w| w == b"BBBB"),
        second_body_visible,
        "{name}: second-block body visibility wrong\n  pass1: {:?}",
        String::from_utf8_lossy(&pass1),
    );

    // Idempotence: pass 2 and pass 3 must equal pass 1, byte for byte.
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

    // Engine == reference.
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

    // Streaming == whole-buffer.
    for cs in [1usize, 7, 64, 1024] {
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

/// Junction sweep after a redacted private-key block.
///
/// - 0–4 junction dashes: block 1 has no complete END marker — it
///   bails out at EOF and everything after its BEGIN line is
///   suppressed (F05). One match, body invisible.
/// - 5–9: fused markers — the guard rejects the second BEGIN on every
///   pass. One match; the second body stays visible (documented
///   tradeoff: a strict reader cannot extract it).
/// - ≥10: two independent markers — both redact. Two matches.
#[test]
fn junction_sweep_after_private_key_block() {
    let (engine, key) = engine_and_key();
    for dashes in 0..=12usize {
        let input = fused_after_private_key(dashes);
        let (matches, visible) = match dashes {
            0..=4 => (1u64, false),
            5..=9 => (1, true),
            _ => (2, false),
        };
        check_shape(
            &engine,
            &key,
            &format!("after-private-key dashes={dashes}"),
            &input,
            matches,
            visible,
        );
    }
}

/// Junction sweep after an unrelated CERTIFICATE block — the fused
/// BEGIN is not preceded by a private-key END trailer.
///
/// - 0–4: not a valid marker. No matches, body visible.
/// - 5: exactly five leading dashes, no private-key END fused — a
///   fresh `-----BEGIN ` scan extracts a valid block, so it redacts
///   on every pass. One match.
/// - 6–9: malformed ≥6-dash header — rejected on every pass. No
///   matches, body visible.
/// - ≥10: two independent markers — the block redacts. One match.
#[test]
fn junction_sweep_after_certificate_block() {
    let (engine, key) = engine_and_key();
    for dashes in 0..=12usize {
        let input = fused_after_certificate(dashes);
        let (matches, visible) = match dashes {
            0..=4 => (0u64, true),
            5 => (1, false),
            6..=9 => (0, true),
            _ => (1, false),
        };
        check_shape(
            &engine,
            &key,
            &format!("after-certificate dashes={dashes}"),
            &input,
            matches,
            visible,
        );
    }
}

/// Sanity: the realistic layout — newline-separated blocks — redacts
/// both blocks.
#[test]
fn newline_separated_blocks_redact_both() {
    let (engine, key) = engine_and_key();
    let input = b"-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n-----BEGIN EC PRIVATE KEY-----\nBBBB\n-----END EC PRIVATE KEY-----\n";
    check_shape(&engine, &key, "newline-separated", input, 2, false);
}

/// Large-input variant: padding before the first PEM block pushes the
/// fused junction past the carry-over boundary (`max_window` = 2048),
/// exercising the flush path. The dash-run guard — including its
/// backward END-trailer read (up to 30 bytes) — must hold even when
/// the junction straddles pushes.
#[test]
fn junction_across_carry_boundary() {
    let (engine, key) = engine_and_key();
    for (dashes, matches, visible) in [
        (5usize, 1u64, true), // boundary fusion — rejected, body visible
        (6, 1, true),         // fused — rejected, body visible
        (10, 2, false),       // independent markers — both redact
    ] {
        for pad in [2000, 2048, 2100, 4096, 8000] {
            let mut data = vec![b'X'; pad];
            data.extend_from_slice(b"-----BEGIN RSA PRIVATE KEY-----\n");
            data.extend_from_slice(
                b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
            );
            data.extend_from_slice(b"-----END RSA PRIVATE KEY");
            data.resize(data.len() + dashes, b'-');
            data.extend_from_slice(b"BEGIN EC PRIVATE KEY-----\n");
            data.extend_from_slice(
                b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n",
            );
            data.extend_from_slice(b"-----END EC PRIVATE KEY-----\n");

            check_shape(
                &engine,
                &key,
                &format!("pad={pad} dashes={dashes}"),
                &data,
                matches,
                visible,
            );
        }
    }
}
