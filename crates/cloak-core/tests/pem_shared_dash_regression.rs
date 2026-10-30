//! Regression tests for #44, #46, and #49: PEM fused-marker redaction,
//! idempotence, and confirm-decision stability across flush boundaries.
//!
//! Fused markers (junction 5–9 dashes, #46) are accepted on pass 1.
//! Idempotence holds because the `[CLOAK:` prefix guard rejects the
//! fused BEGIN on subsequent passes. These tests sweep every junction
//! width in two fusion shapes and pin the three correctness equivalences.

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
/// (both redact, #46), ≥10 redacts both (independent markers).
#[test]
fn junction_sweep_after_private_key_block() {
    let (engine, key) = engine_and_key();
    for dashes in 0..=12usize {
        let input = fused_after_private_key(dashes);
        let (matches, visible) = match dashes {
            0..=4 => (1u64, false),
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
/// `-----BEGIN` marker, 5–9 fused markers accepted (#46), ≥10 redacts
/// (independent markers).
#[test]
fn junction_sweep_after_certificate_block() {
    let (engine, key) = engine_and_key();
    for dashes in 0..=12usize {
        let input = fused_after_certificate(dashes);
        let (matches, visible) = match dashes {
            0..=4 => (0u64, true),
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
        (5usize, 2u64, false), // boundary fusion — both redact (#46)
        (6, 2, false),         // fused — both redact (#46)
        (10, 2, false),        // independent markers — both redact
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

/// Fused 6-dash junction after CERTIFICATE with a long body: the
/// fused anchor is accepted (#46) and both equivalences hold.
#[test]
fn fused_anchor_across_drain_boundary() {
    let (engine, key) = engine_and_key();
    let mut data = Vec::new();
    data.extend_from_slice(
        b"-----BEGIN CERTIFICATE-----\nCCCC\n-----END CERTIFICATE------BEGIN EC PRIVATE KEY-----\nBBBB\n",
    );
    data.extend_from_slice(&vec![b'X'; 2100]);
    data.extend_from_slice(b"\n-----END EC PRIVATE KEY-----\n");

    check_shape(
        &engine,
        &key,
        "fused-6-after-certificate-drain",
        &data,
        1,     // EC block redacts
        false, // BBBB hidden
    );
}

/// Shape with a fused exactly-5 junction after a PKCS#8 END trailer
/// and a second garbled anchor (#46/#49). After removing the shared-dash
/// guard, c1 (the fused RSA BEGIN) IS confirmed; c2 (invalid label)
/// is still rejected.
fn pin_bisection_shape(pad: usize) -> Vec<u8> {
    let mut d = vec![b'X'; pad];
    d.extend_from_slice(b"-----END PRIVATE KEY"); // trailer [p, p+20)
    d.extend_from_slice(b"-----BEGIN RSA PRIVATE KEY"); // c1 = p+20, exactly-5 fusion
    d.extend_from_slice(b"--------"); // closes c1's line AND hosts c2
    d.extend_from_slice(b"BEGIN Y-----\n"); // c2 = p+49: label invalid
    d.resize(d.len() + 2200, b'A'); // body
    d
}

/// The fused RSA anchor is accepted (#46), producing 1 match
/// (unterminated, body to EOF). All strict equivalences hold.
#[test]
fn fused_anchor_accepted_across_boundary() {
    let (engine, key) = engine_and_key();
    for pad in [0usize, 100, 2048] {
        let input = pin_bisection_shape(pad);
        check_shape(
            &engine,
            &key,
            &format!("fused-accept pad={pad}"),
            &input,
            1,     // the fused RSA block matches (unterminated)
            false, // no BBBB in this shape
        );
    }
}

/// EC block + fused RSA block after a PKCS#8 END trailer (#46/#49).
/// Both blocks redact. The memo survives the carry rebuild after the
/// EC block close.
#[test]
fn fused_anchor_after_pem_close_rebuild() {
    let (engine, key) = engine_and_key();
    let mut data = Vec::new();
    data.extend_from_slice(b"-----BEGIN EC PRIVATE KEY-----\nCCCC\n-----END EC PRIVATE KEY-----\n");
    data.extend_from_slice(&pin_bisection_shape(0));

    check_shape(
        &engine,
        &key,
        "fused-after-close-rebuild",
        &data,
        2,     // EC block + fused RSA block
        false, // no BBBB in this shape
    );
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
