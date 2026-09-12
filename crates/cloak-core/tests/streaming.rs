//! Property-based invariants for the streaming guarantee (docs/03).
//!
//! Four properties, each with ≥1024 test cases:
//! 1. Chunk-boundary: any chunking ≡ whole-buffer output
//! 2. Passthrough: no anchors ⇒ byte-identical output
//! 3. Idempotence: redact(redact(S)) == redact(S)
//! 4. Bounded memory: carry-over ≤ max_window + PEM_BAIL_OUT + BEGIN line
//!    (the engine's actual guarantee: regular carry is bounded by
//!    max_window; a PEM block held for streaming entry or bail-out
//!    truncation adds at most one PEM body)

use std::sync::Once;

use cloak_core::{Config, Engine};
use proptest::prelude::*;

const KEY_VAR: &str = "CLOAK_STREAM_KEY";
const KEY_MATERIAL: &str = "streaming-proptest-key";

static INIT: Once = Once::new();

fn test_engine() -> Engine {
    INIT.call_once(|| {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { std::env::set_var(KEY_VAR, KEY_MATERIAL) };
    });
    let config = Config {
        redaction: cloak_core::RedactionConfig {
            digest_key: format!("env:{KEY_VAR}"),
        },
        ..Config::default()
    };
    Engine::new(&config).unwrap()
}

fn whole_buffer_redact(engine: &Engine, input: &[u8]) -> Vec<u8> {
    let mut session = engine.session();
    let mut out = Vec::new();
    session.push(input, &mut out).unwrap();
    session.finish(&mut out).unwrap();
    out
}

fn chunked_redact(engine: &Engine, input: &[u8], chunks: &[usize]) -> Vec<u8> {
    let mut session = engine.session();
    let mut out = Vec::new();
    let mut pos = 0;
    for &size in chunks {
        let end = (pos + size).min(input.len());
        session.push(&input[pos..end], &mut out).unwrap();
        pos = end;
        if pos >= input.len() {
            break;
        }
    }
    if pos < input.len() {
        session.push(&input[pos..], &mut out).unwrap();
    }
    session.finish(&mut out).unwrap();
    out
}

// ---------------------------------------------------------------------------
// Corpus generators
// ---------------------------------------------------------------------------

fn planted_token() -> BoxedStrategy<Vec<u8>> {
    prop_oneof![
        Just(b"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".to_vec()),
        Just(b"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".to_vec()),
        Just(b"glpat-abcdefghij0123456789".to_vec()),
    ]
    .boxed()
}

fn planted_pem() -> BoxedStrategy<Vec<u8>> {
    prop_oneof![
        Just(
            b"-----BEGIN RSA PRIVATE KEY-----\nTESTBODYDATA\n-----END RSA PRIVATE KEY-----"
                .to_vec()
        ),
        // Unterminated BEGIN: no END marker — exercises the streaming
        // entry + bail-out path (the H2 regression shape).
        Just(b"-----BEGIN RSA PRIVATE KEY-----\nUNTERMINATED".to_vec()),
    ]
    .boxed()
}

fn corpus_strategy() -> BoxedStrategy<Vec<u8>> {
    prop::collection::vec(
        prop_oneof![
            4 => "[a-zA-Z0-9 \n]{1,100}".prop_map(|s| s.into_bytes()),
            2 => planted_token(),
            1 => planted_pem(),
            1 => prop::collection::vec(any::<u8>(), 0..50),
        ],
        1..8,
    )
    .prop_map(|segments| segments.concat())
    .boxed()
}

fn chunking_strategy(max_len: usize) -> BoxedStrategy<Vec<usize>> {
    prop::collection::vec(1..=max_len.max(1), 1..20).boxed()
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// Chunk-boundary invariant: any chunking of any corpus produces
    /// byte-identical output to a single whole-buffer push.
    #[test]
    fn chunk_boundary(corpus in corpus_strategy(), chunks in chunking_strategy(64)) {
        let engine = test_engine();
        let whole = whole_buffer_redact(&engine, &corpus);
        let chunked = chunked_redact(&engine, &corpus, &chunks);
        prop_assert_eq!(
            chunked, whole,
            "chunked ≢ whole-buffer (corpus len={}, {} chunks)",
            corpus.len(), chunks.len()
        );
    }

    /// Passthrough invariant: input with no rule anchors passes through
    /// byte-identical.
    #[test]
    fn passthrough(input in prop::collection::vec(
        // Restrict to bytes that avoid ALL catalog anchors. After S4,
        // single-byte anchors like `@`, `+`, `:` exist — use only
        // lowercase letters (no digits, no punctuation) to guarantee
        // no anchor can form.
        b'a'..=b'z', 0..500))
    {
        let engine = test_engine();
        let output = whole_buffer_redact(&engine, &input);
        prop_assert_eq!(output, input, "passthrough violated");
    }

    /// Idempotence: redact(redact(S)) == redact(S).
    #[test]
    fn idempotence(corpus in corpus_strategy()) {
        let engine = test_engine();
        let once = whole_buffer_redact(&engine, &corpus);
        let twice = whole_buffer_redact(&engine, &once);
        prop_assert_eq!(
            once, twice,
            "redaction not idempotent (corpus len={})",
            corpus.len()
        );
    }

    /// Bounded memory: carry-over never exceeds the engine's guarantee
    /// during streaming. Regular carry is bounded by max_window (266);
    /// a PEM block held while awaiting its END (streaming entry, bail-out
    /// truncation, or entry deferral) adds at most one PEM body
    /// (PEM_BAIL_OUT) plus the BEGIN line.
    #[test]
    fn bounded_memory(corpus in corpus_strategy(), chunks in chunking_strategy(32)) {
        let engine = test_engine();
        let mut session = engine.session();
        let mut out = Vec::new();
        let mut pos = 0;
        let max_window = 266; // github-token: 11 + 255 (docs/02-rules.md)
        let bound = max_window + 16_384 + 37; // + PEM_BAIL_OUT + max BEGIN line
        for &size in &chunks {
            let end = (pos + size).min(corpus.len());
            session.push(&corpus[pos..end], &mut out).unwrap();
            let carry = session.carry_over_len();
            prop_assert!(
                carry <= bound,
                "carry-over {} exceeds bound {} after push of {} bytes",
                carry, bound, end - pos
            );
            pos = end;
            if pos >= corpus.len() {
                break;
            }
        }
        session.finish(&mut out).unwrap();
    }
}
