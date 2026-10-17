//! Regression tests for #44: PEM shared-dash idempotence.
//!
//! The guard in `confirm_pem_begin` / `confirm_pem_begin_ref` counts the
//! dash run before a BEGIN anchor: 1–4 (junction 6–9) or 0-after-a-
//! private-key-END-trailer (junction exactly 5) are fused markers and
//! reject on every pass; ≥5 (junction ≥10) are two independent markers
//! and both redact. These tests sweep every junction width in two
//! fusion shapes and pin the three correctness equivalences.

use cloak_core::{Config, Engine, RedactionConfig};
use std::sync::LazyLock;

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

/// Private-key block + junction of `dashes` dashes + second block
/// (10 = clean separation).
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

/// Unredacted CERTIFICATE block + junction of `dashes` dashes +
/// private-key block (no private-key END before the junction).
fn fused_after_certificate(dashes: usize) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(b"-----BEGIN CERTIFICATE-----\nCCCC\n-----END CERTIFICATE");
    data.resize(data.len() + dashes, b'-');
    data.extend_from_slice(b"BEGIN EC PRIVATE KEY-----\n");
    data.extend_from_slice(b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n");
    data.extend_from_slice(b"-----END EC PRIVATE KEY-----\n");
    data
}

/// Assert the full contract for one input: match count, body
/// visibility, three-pass idempotence with no re-matched tags,
/// engine ≡ reference, streaming ≡ whole-buffer.
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

/// Junction sweep after a redacted private-key block: 0–4 leaves no
/// complete END (EOF bail-out suppresses the rest), 5–9 is fused
/// (rejected, body visible), ≥10 redacts both.
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

/// Junction sweep after an unrelated CERTIFICATE block: 0–4 no valid
/// marker, 5 redacts (no private-key END fused), 6–9 malformed header
/// (rejected), ≥10 redacts.
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

/// The realistic layout: newline-separated blocks both redact.
#[test]
fn newline_separated_blocks_redact_both() {
    let (engine, key) = engine_and_key();
    let input = b"-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n-----BEGIN EC PRIVATE KEY-----\nBBBB\n-----END EC PRIVATE KEY-----\n";
    check_shape(&engine, &key, "newline-separated", input, 2, false);
}

/// Padding pushes the fused junction past the carry-over boundary
/// (`max_window` = 2048), exercising the flush path.
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

/// Truncated-context regression (fuzz_pem_state CI crash): with more
/// than `max_window` bytes after a rejected 6-dash junction, the drain
/// boundary sweeps past the anchor — the shared-dash pin must keep
/// its backward context so streaming agrees with whole-buffer.
#[test]
fn rejected_anchor_is_not_reconfirmed_across_drain_boundary() {
    let (engine, key) = engine_and_key();
    let mut data = Vec::new();
    data.extend_from_slice(
        b"-----BEGIN CERTIFICATE-----\nCCCC\n-----END CERTIFICATE------BEGIN EC PRIVATE KEY-----\nBBBB\n",
    );
    data.extend_from_slice(&vec![b'X'; 2100]);
    data.extend_from_slice(b"\n-----END EC PRIVATE KEY-----\n");

    let (pass1, stats1) = whole(&engine, &data);
    assert_eq!(stats1.total_matches(), 0, "fused junction must not confirm");
    assert!(pass1.windows(4).any(|w| w == b"BBBB"));
    let (ref_out, ref_stats) = cloak_core::reference::redact(&data, &key);
    assert_eq!(pass1, ref_out.as_slice(), "engine ≢ reference");
    assert_eq!(
        stats1.matches, ref_stats.matches,
        "stats diverge from reference"
    );

    for cs in [1usize, 3, 7, 64, 1024] {
        let mut session = engine.session();
        let mut out = Vec::new();
        for chunk in data.chunks(cs) {
            session.push(chunk, &mut out).unwrap();
        }
        let stats = session.finish(&mut out).unwrap();
        assert_eq!(
            out, pass1,
            "cs={cs}: streaming ≢ whole-buffer across the drain boundary"
        );
        assert_eq!(stats.matches, stats1.matches, "cs={cs}: stats diverge");
    }
}

/// Bail-out digest regression (fuzz_pem_state): an unterminated body
/// ending past `PEM_BAIL_OUT` must produce the same tag as the
/// reference, which caps the digest at exactly the budget (F05).
#[test]
fn unterminated_block_digest_capped_at_bail_out() {
    let (engine, key) = engine_and_key();
    // Pinned by engine::pem::PEM_BAIL_OUT and the oracle's constant.
    const PEM_BAIL_OUT: usize = 16_384;
    let mut data = b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n".to_vec();
    data.extend_from_slice(&vec![b'A'; PEM_BAIL_OUT + 3]);

    let mut session = engine.session();
    let mut eng_out = Vec::new();
    session.push(&data, &mut eng_out).unwrap();
    let stats = session.finish(&mut eng_out).unwrap();
    assert_eq!(stats.total_matches(), 1);

    let (ref_out, ref_stats) = cloak_core::reference::redact(&data, &key);
    assert_eq!(
        eng_out,
        ref_out.as_slice(),
        "engine ≢ reference on the bail-out boundary\n  engine: {:?}\n  ref:    {:?}",
        String::from_utf8_lossy(&eng_out),
        String::from_utf8_lossy(&ref_out),
    );
    assert_eq!(stats.matches, ref_stats.matches);

    for cs in [1usize, 37, 4096, 8192] {
        let mut session = engine.session();
        let mut out = Vec::new();
        for chunk in data.chunks(cs) {
            session.push(chunk, &mut out).unwrap();
        }
        let st = session.finish(&mut out).unwrap();
        assert_eq!(out, eng_out, "cs={cs}: streaming ≢ whole-buffer");
        assert_eq!(st.matches, stats.matches, "cs={cs}: stats diverge");
    }
}
