//! Integration tier: the differential invariant (docs/03) —
//! `redact_whole_buffer(S) == redact_reference(S)` for every corpus S.
//! Divergence is a guarantee bug by definition.

use std::sync::Once;

use cloak_core::{Config, Engine};

const KEY_VAR: &str = "CLOAK_DIFF_DIGEST_KEY";
const KEY_MATERIAL: &str = "differential-test-key";

static INIT: Once = Once::new();

fn engine_and_key() -> (Engine, [u8; 32]) {
    INIT.call_once(|| {
        // SAFETY: test-only; single dedicated var, set exactly once before
        // any engine is built, never removed.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { std::env::set_var(KEY_VAR, KEY_MATERIAL) };
    });
    let engine = Engine::new(&Config {
        digest_key_env: Some(KEY_VAR.into()),
    })
    .unwrap();
    let key = blake3::derive_key("cloak digest key", KEY_MATERIAL.as_bytes());
    (engine, key)
}

fn engine_redact(engine: &Engine, input: &[u8]) -> (Vec<u8>, cloak_core::Stats) {
    let mut session = engine.session();
    let mut out = Vec::new();
    session.push(input, &mut out).unwrap();
    let stats = session.finish(&mut out).unwrap();
    (out, stats)
}

fn engine_redact_chunked(
    engine: &Engine,
    input: &[u8],
    chunk_size: usize,
) -> (Vec<u8>, cloak_core::Stats) {
    let mut session = engine.session();
    let mut out = Vec::new();
    for chunk in input.chunks(chunk_size) {
        session.push(chunk, &mut out).unwrap();
    }
    let stats = session.finish(&mut out).unwrap();
    (out, stats)
}

/// The invariant, asserted on output bytes AND stats.
fn assert_engine_equals_reference(engine: &Engine, key: &[u8; 32], input: &[u8], label: &str) {
    let (engine_out, engine_stats) = engine_redact(engine, input);
    let (reference_out, reference_stats) = cloak_core::reference::redact(input, key);
    assert_eq!(
        engine_out, reference_out,
        "engine ≢ reference on corpus: {label}"
    );
    assert_eq!(
        engine_stats.matches, reference_stats.matches,
        "stats diverge on corpus: {label}"
    );
    assert_eq!(
        engine_stats.bytes_processed, reference_stats.bytes_processed,
        "{label}"
    );
}

#[test]
fn every_vector_input() {
    let (engine, key) = engine_and_key();
    for v in cloak_core::vectors::all_vectors() {
        assert_engine_equals_reference(&engine, &key, v.input, v.name);
    }
}

#[test]
fn concatenated_corpora_with_separators() {
    // Concatenation manufactures adjacencies and overlaps the individual
    // vectors don't contain — including the EMPTY separator, which glues
    // token tails directly onto the next vector's anchors.
    let (engine, key) = engine_and_key();
    let separators: [&[u8]; 4] = [b"\n", b" ", b"\x00\xff\x80", b""];
    for sep in separators {
        let mut corpus = Vec::new();
        for v in cloak_core::vectors::all_vectors() {
            corpus.extend_from_slice(v.input);
            corpus.extend_from_slice(sep);
        }
        assert_engine_equals_reference(&engine, &key, &corpus, &format!("concat sep={sep:?}"));
    }
}

#[test]
fn shuffled_concatenation() {
    // Deterministic LCG shuffle: different neighbor pairs than declaration
    // order, reproducible on failure.
    let (engine, key) = engine_and_key();
    let mut vectors = cloak_core::vectors::all_vectors();
    let mut state: u64 = 0x5DEECE66D;
    for i in (1..vectors.len()).rev() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let j = (state >> 33) as usize % (i + 1);
        vectors.swap(i, j);
    }
    let mut corpus = Vec::new();
    for v in vectors {
        corpus.extend_from_slice(v.input);
    }
    assert_engine_equals_reference(&engine, &key, &corpus, "shuffled zero-sep concat");
}

#[test]
fn corpus_framed_in_binary_noise() {
    let (engine, key) = engine_and_key();
    let noise: Vec<u8> = (0..=255).collect();
    let mut corpus = noise.clone();
    for v in cloak_core::vectors::all_vectors() {
        corpus.extend_from_slice(v.input);
        corpus.extend_from_slice(&noise);
    }
    assert_engine_equals_reference(&engine, &key, &corpus, "binary-noise framing");
}

#[test]
fn anchor_fragment_soup() {
    // Near-anchors and truncated anchors everywhere; nothing should match,
    // and both sides must agree on that.
    let (engine, key) = engine_and_key();
    let soup = b"ghp ghp_ gh_p _ghp npm npm_ npm_x glpat glpat- glrt gldt- github_pat \
                 github_pat_ ghx_ NPM_ GLPAT- ghp_short npm_2short gldt-19chars";
    assert_engine_equals_reference(&engine, &key, soup, "anchor-fragment soup");
}

// ---------- S3 chunked streaming differential tests ----------

/// The chunk-boundary guarantee: any chunking of any corpus produces
/// byte-identical output to the reference oracle.
#[test]
fn every_vector_1byte_chunks() {
    let (engine, key) = engine_and_key();
    for v in cloak_core::vectors::all_vectors() {
        let (chunked, chunked_stats) = engine_redact_chunked(&engine, v.input, 1);
        let (reference, reference_stats) = cloak_core::reference::redact(v.input, &key);
        assert_eq!(
            chunked, reference,
            "1-byte streaming ≢ reference on vector '{}'",
            v.name
        );
        assert_eq!(
            chunked_stats.matches, reference_stats.matches,
            "stats diverge on vector '{}' (1-byte)",
            v.name
        );
    }
}

#[test]
fn every_vector_various_chunk_sizes() {
    let (engine, key) = engine_and_key();
    let sizes = [2, 3, 5, 7, 13, 37, 64, 256];
    for v in cloak_core::vectors::all_vectors() {
        for &sz in &sizes {
            let (chunked, _) = engine_redact_chunked(&engine, v.input, sz);
            let (reference, _) = cloak_core::reference::redact(v.input, &key);
            assert_eq!(
                chunked, reference,
                "chunk-size={sz} streaming ≢ reference on vector '{}'",
                v.name
            );
        }
    }
}

#[test]
fn concatenated_corpora_1byte_chunks() {
    let (engine, key) = engine_and_key();
    let separators: [&[u8]; 4] = [b"\n", b" ", b"\x00\xff\x80", b""];
    for sep in separators {
        let mut corpus = Vec::new();
        for v in cloak_core::vectors::all_vectors() {
            corpus.extend_from_slice(v.input);
            corpus.extend_from_slice(sep);
        }
        let (chunked, _) = engine_redact_chunked(&engine, &corpus, 1);
        let (reference, _) = cloak_core::reference::redact(&corpus, &key);
        assert_eq!(
            chunked, reference,
            "1-byte concat streaming ≢ reference (sep={sep:?})"
        );
    }
}

#[test]
fn anchor_fragment_soup_1byte() {
    let (engine, key) = engine_and_key();
    let soup = b"ghp ghp_ gh_p _ghp npm npm_ npm_x glpat glpat- glrt gldt- github_pat \
                 github_pat_ ghx_ NPM_ GLPAT- ghp_short npm_2short gldt-19chars";
    let (chunked, _) = engine_redact_chunked(&engine, soup, 1);
    let (reference, _) = cloak_core::reference::redact(soup, &key);
    assert_eq!(chunked, reference, "1-byte soup streaming ≢ reference");
}

/// Streaming output must equal whole-buffer output for every chunk size.
#[test]
fn streaming_equals_whole_buffer_all_sizes() {
    let (engine, _key) = engine_and_key();
    let sizes = [1, 2, 3, 5, 7, 13, 37, 64, 256];
    for v in cloak_core::vectors::all_vectors() {
        let (whole, _) = engine_redact(&engine, v.input);
        for &sz in &sizes {
            let (chunked, _) = engine_redact_chunked(&engine, v.input, sz);
            assert_eq!(
                chunked, whole,
                "chunk-size={sz} streaming ≢ whole-buffer on vector '{}'",
                v.name
            );
        }
    }
}

#[test]
fn redaction_is_idempotent() {
    // Tags contain no anchors, so redacting redacted output is the identity.
    // Cheap deterministic version of the S4 property test.
    let (engine, key) = engine_and_key();
    let mut corpus = Vec::new();
    for v in cloak_core::vectors::all_vectors() {
        corpus.extend_from_slice(v.input);
        corpus.push(b'\n');
    }
    let (once, _) = engine_redact(&engine, &corpus);
    let (twice, stats) = engine_redact(&engine, &once);
    assert_eq!(once, twice, "redaction must be idempotent");
    assert_eq!(
        stats.total_matches(),
        0,
        "no matches may fire on redacted output"
    );
    // And the reference agrees on the redacted output too.
    assert_engine_equals_reference(&engine, &key, &once, "idempotence corpus");
}
