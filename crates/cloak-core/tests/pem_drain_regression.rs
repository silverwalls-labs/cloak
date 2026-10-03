//! Regression test for fuzz_pem_state crash: PEM bail-out drain mode
//! produces different output in streaming vs whole-buffer mode.

use cloak_core::{CARRY_OVER_BOUND, Config, Engine, RedactionConfig};

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

/// The fuzz crash input: BEGIN + 16357 body bytes + END.
fn crash_input() -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n");
    // Fill body with 'A' lines (65 bytes each: 64 A's + \n)
    while data.len() < 16395 {
        let remaining = 16395 - data.len();
        if remaining >= 65 {
            data.extend_from_slice(
                b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
            );
        } else {
            data.resize(data.len() + remaining, b'A');
        }
    }
    data.truncate(16395);
    data.extend_from_slice(b"-----END ENCRYPTED PRIVATE KEY-----\n");
    data
}

#[test]
fn pem_drain_whole_buffer_ok() {
    let (engine, _) = engine_and_key();
    let data = crash_input();
    let mut session = engine.session();
    let mut out = Vec::new();
    session.push(&data, &mut out).unwrap();
    let stats = session.finish(&mut out).unwrap();
    assert!(
        stats.total_matches() >= 1,
        "PEM must be detected in whole-buffer mode"
    );
}

#[test]
fn pem_drain_1byte_carry_bounded() {
    let (engine, _) = engine_and_key();
    let data = crash_input();
    let mut session = engine.session();
    let mut out = Vec::new();
    for (i, &b) in data.iter().enumerate() {
        session.push(&[b], &mut out).unwrap();
        assert!(
            session.carry_over_len() <= CARRY_OVER_BOUND,
            "carry-over {} exceeds bound {} at byte {}",
            session.carry_over_len(),
            CARRY_OVER_BOUND,
            i
        );
    }
    let stats = session.finish(&mut out).unwrap();
    assert!(
        stats.total_matches() >= 1,
        "PEM must be detected in streaming mode"
    );
}

#[test]
fn pem_drain_streaming_equals_whole() {
    let (engine, _) = engine_and_key();
    let data = crash_input();

    // Whole buffer
    let mut s1 = engine.session();
    let mut out1 = Vec::new();
    s1.push(&data, &mut out1).unwrap();
    let stats1 = s1.finish(&mut out1).unwrap();

    // Multiple chunk sizes
    for cs in [1, 3, 7, 64, 1024] {
        let mut s2 = engine.session();
        let mut out2 = Vec::new();
        for chunk in data.chunks(cs) {
            s2.push(chunk, &mut out2).unwrap();
        }
        let stats2 = s2.finish(&mut out2).unwrap();

        assert_eq!(
            out1,
            out2,
            "streaming chunk_size={cs} ≢ whole-buffer\n  whole:    {:?}\n  streamed: {:?}",
            String::from_utf8_lossy(&out1),
            String::from_utf8_lossy(&out2),
        );
        assert_eq!(
            stats1.matches, stats2.matches,
            "stats diverge at chunk_size={cs}"
        );
    }
}
