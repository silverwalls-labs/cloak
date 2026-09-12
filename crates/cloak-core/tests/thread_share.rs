//! Integration tier: the Send/Sync contract (docs/03 §cross-cutting).
//! One `Engine` shared across threads with concurrent `Session`s — plain
//! test, no loom (no lock-free code in core).
//!
//! Per-vector sessions on purpose: this pins the concurrency contract
//! (shared read-only engine, independent per-thread sessions), not the
//! dense-concatenation behavior tracked in #27.

use std::sync::Once;

use cloak_core::{Config, Engine};

const KEY_VAR: &str = "CLOAK_THREAD_DIGEST_KEY";
const KEY_MATERIAL: &str = "thread-share-test-key";

static INIT: Once = Once::new();

fn engine_and_key() -> (Engine, [u8; 32]) {
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
    let engine = Engine::new(&config).unwrap();
    let key = blake3::derive_key("cloak digest key", KEY_MATERIAL.as_bytes());
    (engine, key)
}

/// 8 threads × 4 rounds of sessions each, all borrowing ONE engine.
/// Every session streams each vector at the thread's chunk size and must
/// produce exactly `vectors::expected_output` — any cross-session state
/// bleed or data race (under `--release` too) breaks the byte-compare.
#[test]
fn engine_shared_across_threads_with_concurrent_sessions() {
    let (engine, key) = engine_and_key();
    let engine = &engine;
    let chunk_sizes = [1usize, 7, 64, usize::MAX];

    std::thread::scope(|scope| {
        for (t, &chunk_size) in (0..8).zip(chunk_sizes.iter().cycle()) {
            scope.spawn(move || {
                for round in 0..4 {
                    for v in cloak_core::vectors::all_vectors() {
                        let mut session = engine.session();
                        let mut out = Vec::new();
                        for chunk in v.input.chunks(chunk_size.min(v.input.len().max(1))) {
                            session.push(chunk, &mut out).unwrap();
                        }
                        let stats = session.finish(&mut out).unwrap();
                        let expected = cloak_core::vectors::expected_output(v, &key);
                        assert_eq!(
                            out, expected,
                            "thread={t} round={round} chunk={chunk_size} vector={}",
                            v.name
                        );
                        assert_eq!(
                            stats.total_matches(),
                            v.spans.len() as u64,
                            "thread={t} vector={}",
                            v.name
                        );
                    }
                }
            });
        }
    });
}

/// Engines built concurrently from the same env key are interchangeable.
#[test]
fn concurrent_engine_construction_is_deterministic() {
    let (reference_engine, key) = engine_and_key();
    let outputs: Vec<Vec<u8>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|_| {
                scope.spawn(|| {
                    let (engine, _key) = engine_and_key();
                    let mut session = engine.session();
                    let mut out = Vec::new();
                    for v in cloak_core::vectors::all_vectors() {
                        session.push(v.input, &mut out).unwrap();
                        session.push(b"\n", &mut out).unwrap();
                    }
                    session.finish(&mut out).unwrap();
                    out
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    let mut session = reference_engine.session();
    let mut expected = Vec::new();
    for v in cloak_core::vectors::all_vectors() {
        session.push(v.input, &mut expected).unwrap();
        session.push(b"\n", &mut expected).unwrap();
    }
    session.finish(&mut expected).unwrap();
    let _ = key;

    for (i, out) in outputs.iter().enumerate() {
        assert_eq!(out, &expected, "concurrently-built engine {i} diverges");
    }
}
