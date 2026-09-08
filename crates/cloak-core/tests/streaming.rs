//! Property-based invariants for the streaming guarantee (docs/03).
//!
//! Four properties, each with ≥1024 test cases:
//! 1. Chunk-boundary: any chunking ≡ whole-buffer output
//! 2. Passthrough: no anchors ⇒ byte-identical output
//! 3. Idempotence: redact(redact(S)) == redact(S)
//! 4. Bounded memory: carry-over ≤ max_window + max PEM block size

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
    Engine::new(&Config {
        digest_key_env: Some(KEY_VAR.into()),
    })
    .unwrap()
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
        Just(b"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789".to_vec()),
        Just(b"npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789".to_vec()),
        Just(b"glpat-abcdefghij0123456789".to_vec()),
    ]
    .boxed()
}

fn planted_pem() -> BoxedStrategy<Vec<u8>> {
    Just(b"-----BEGIN RSA PRIVATE KEY-----\nTESTBODYDATA\n-----END RSA PRIVATE KEY-----".to_vec())
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
    fn passthrough(input in prop::collection::vec(any::<u8>(), 0..500)
        .prop_filter("must not contain anchors", |v| {
            let anchors: &[&[u8]] = &[
                b"ghp_", b"gho_", b"ghs_", b"ghu_", b"ghr_", b"github_pat_",
                b"glpat-", b"glrt-", b"gldt-", b"npm_", b"-----BEGIN ",
            ];
            !anchors.iter().any(|a|
                v.windows(a.len()).any(|w| w == *a)
            )
        }))
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

    /// Bounded memory: carry-over never exceeds a reasonable bound during
    /// streaming. The bound depends on max_window plus the largest PEM
    /// block that can appear in the corpus.
    #[test]
    fn bounded_memory(corpus in corpus_strategy(), chunks in chunking_strategy(32)) {
        let engine = test_engine();
        let mut session = engine.session();
        let mut out = Vec::new();
        let mut pos = 0;
        // The max PEM body in our corpus generator is ~73 bytes
        // ("TESTBODYDATA" = 13, plus markers = ~73). The total PEM block
        // is ~140 bytes. Carry-over can grow to max_window + PEM block.
        let bound = 266 /* max_window */ + 200 /* PEM block + margin */;
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
