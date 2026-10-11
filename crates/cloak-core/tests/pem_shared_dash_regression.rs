//! Regression test for #44: PEM shared-dash idempotence bug.
//!
//! When a PEM END trailer shares dashes with a following BEGIN header
//! (e.g. 8 dashes instead of the expected 10 between blocks), the fused
//! second BEGIN must be rejected — redacting one half of fused markers
//! breaks idempotence.

use cloak_core::{Config, Engine, RedactionConfig};

fn engine_and_key() -> (Engine, [u8; 32]) {
    let key_material = "test-digest-key";
    let config = Config {
        redaction: RedactionConfig {
            digest_key: "env:TEST_DIGEST_KEY".to_string(),
        },
        ..Config::default()
    };
    // SAFETY: test-only, single-threaded
    unsafe { std::env::set_var("TEST_DIGEST_KEY", key_material) };
    let engine = Engine::new(&config).unwrap();
    let key = blake3::derive_key("cloak digest key", key_material.as_bytes());
    (engine, key)
}

fn whole(engine: &Engine, input: &[u8]) -> (Vec<u8>, cloak_core::Stats) {
    let mut session = engine.session();
    let mut out = Vec::new();
    session.push(input, &mut out).unwrap();
    let stats = session.finish(&mut out).unwrap();
    (out, stats)
}

/// Two back-to-back PEM blocks with `shared` overlapping dashes between
/// the END trailer and the next BEGIN header.
fn shared_dash_input(shared: usize) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(b"-----BEGIN RSA PRIVATE KEY-----\n");
    data.extend_from_slice(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
    // END trailer: "-----END RSA PRIVATE KEY" + (5 + shared_extra) dashes
    // fused with BEGIN header of the next block. With `shared` overlapping
    // dashes the junction has (10 - shared) total dashes instead of 10.
    data.extend_from_slice(b"-----END RSA PRIVATE KEY");
    // Write exactly (10 - shared) dashes: 5 close the END, the remaining
    // (5 - shared) are the start of the next BEGIN — but the next BEGIN
    // needs 5 leading dashes, so only (5 - shared) are "free" and the
    // other `shared` come from the END's closing dashes.
    let junction_dashes = 10usize.saturating_sub(shared);
    for _ in 0..junction_dashes {
        data.push(b'-');
    }
    data.extend_from_slice(b"BEGIN EC PRIVATE KEY-----\n");
    data.extend_from_slice(b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n");
    data.extend_from_slice(b"-----END EC PRIVATE KEY-----\n");
    data
}

#[test]
fn shared_dash_idempotent_whole_buffer() {
    let (engine, _) = engine_and_key();
    // Test shared dashes from 1 to 4 (junction has 9, 8, 7, 6 dashes).
    for shared in 1..=4 {
        let input = shared_dash_input(shared);
        let (pass1, stats1) = whole(&engine, &input);
        assert!(
            stats1.total_matches() >= 1,
            "shared={shared}: first PEM block must be detected"
        );
        let (pass2, stats2) = whole(&engine, &pass1);
        assert_eq!(
            pass2, pass1,
            "shared={shared}: redaction not idempotent\n  pass1: {:?}\n  pass2: {:?}",
            String::from_utf8_lossy(&pass1),
            String::from_utf8_lossy(&pass2),
        );
        assert_eq!(
            stats2.matches.values().sum::<u64>(),
            0,
            "shared={shared}: tags re-matched on second pass"
        );
    }
}

#[test]
fn shared_dash_idempotent_streaming() {
    let (engine, _) = engine_and_key();
    for shared in 1..=4 {
        let input = shared_dash_input(shared);
        let (whole_out, whole_stats) = whole(&engine, &input);

        for cs in [1, 3, 7, 64, 1024] {
            let mut session = engine.session();
            let mut out = Vec::new();
            for chunk in input.chunks(cs) {
                session.push(chunk, &mut out).unwrap();
            }
            let stats = session.finish(&mut out).unwrap();
            assert_eq!(
                out, whole_out,
                "shared={shared} chunk_size={cs}: streaming ≢ whole-buffer\n  whole:    {:?}\n  streamed: {:?}",
                String::from_utf8_lossy(&whole_out),
                String::from_utf8_lossy(&out),
            );
            assert_eq!(
                stats.matches, whole_stats.matches,
                "shared={shared} chunk_size={cs}: stats diverge"
            );
        }
    }
}

#[test]
fn shared_dash_engine_equals_reference() {
    let (engine, key) = engine_and_key();
    for shared in 1..=4 {
        let input = shared_dash_input(shared);
        let (engine_out, engine_stats) = whole(&engine, &input);
        let (ref_out, ref_stats) = cloak_core::reference::redact(&input, &key);
        assert_eq!(
            engine_out,
            ref_out.as_slice(),
            "shared={shared}: engine ≢ reference\n  engine: {:?}\n  ref:    {:?}",
            String::from_utf8_lossy(&engine_out),
            String::from_utf8_lossy(&ref_out),
        );
        assert_eq!(
            engine_stats.matches, ref_stats.matches,
            "shared={shared}: stats diverge from reference"
        );
    }
}

/// Large-input variant: padding before the first PEM block pushes the
/// fused junction past the carry-over boundary (`max_window` = 2048),
/// exercising the flush path. The preceding-dash guard must hold even
/// when the junction bytes have been emitted and only the remainder
/// (`---BEGIN …`, < 5 dashes) survives in the carry-over.
#[test]
fn shared_dash_large_input_across_carry_boundary() {
    let (engine, key) = engine_and_key();
    for pad in [2000, 2048, 2100, 4096, 8000] {
        let mut data = vec![b'X'; pad];
        data.extend_from_slice(b"-----BEGIN RSA PRIVATE KEY-----\n");
        data.extend_from_slice(
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
        );
        // 6-dash fused junction (4 shared dashes).
        data.extend_from_slice(
            b"-----END RSA PRIVATE KEY------BEGIN EC PRIVATE KEY-----\n",
        );
        data.extend_from_slice(
            b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n",
        );
        data.extend_from_slice(b"-----END EC PRIVATE KEY-----\n");

        let (pass1, stats1) = whole(&engine, &data);
        assert!(
            stats1.total_matches() >= 1,
            "pad={pad}: first PEM block must be detected"
        );

        // Idempotence.
        let (pass2, stats2) = whole(&engine, &pass1);
        assert_eq!(
            pass2, pass1,
            "pad={pad}: redaction not idempotent\n  pass1: {:?}\n  pass2: {:?}",
            String::from_utf8_lossy(&pass1),
            String::from_utf8_lossy(&pass2),
        );
        assert_eq!(
            stats2.matches.values().sum::<u64>(),
            0,
            "pad={pad}: tags re-matched on second pass"
        );

        // Engine == reference.
        let (ref_out, ref_stats) = cloak_core::reference::redact(&data, &key);
        assert_eq!(
            pass1,
            ref_out.as_slice(),
            "pad={pad}: engine ≢ reference"
        );
        assert_eq!(
            stats1.matches, ref_stats.matches,
            "pad={pad}: stats diverge from reference"
        );

        // Streaming == whole-buffer (1-byte chunks stress the boundary).
        for cs in [1, 7, 1024] {
            let mut session = engine.session();
            let mut out = Vec::new();
            for chunk in data.chunks(cs) {
                session.push(chunk, &mut out).unwrap();
            }
            let stats = session.finish(&mut out).unwrap();
            assert_eq!(
                out, pass1,
                "pad={pad} cs={cs}: streaming ≢ whole-buffer"
            );
            assert_eq!(
                stats.matches, stats1.matches,
                "pad={pad} cs={cs}: stats diverge"
            );
        }
    }
}
