//! Integration tier: invalid-UTF-8 / binary input is DEFINED behavior
//! (docs/03 §"Invalid UTF-8 & binary input"). The engine operates on
//! bytes — vectors embedded in random binary, truncated UTF-8, and
//! continuation-byte soup are still caught, non-matching garbage passes
//! through byte-identical, and the oracle defines every outcome.

use std::sync::{LazyLock, Once};

use cloak_core::{Config, Engine, RuleId};
use proptest::prelude::*;

const KEY_VAR: &str = "CLOAK_BINEMB_DIGEST_KEY";
const KEY_MATERIAL: &str = "binary-embedding-test-key";

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

/// Built once — the engine is immutable, so rebuilding it per proptest case
/// (256×, and under coverage instrumentation) is pure waste.
static ENGINE_KEY: LazyLock<(Engine, [u8; 32])> = LazyLock::new(engine_and_key);

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

/// Deterministic LCG (same constants as differential.rs) — failures are
/// reproducible without a proptest seed file.
struct Lcg(u64);

impl Lcg {
    fn next_byte(&mut self) -> u8 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 33) as u8
    }
}

/// 64 bytes of soup per generator kind.
fn soup(kind: usize, seed: u64) -> Vec<u8> {
    let mut rng = Lcg(seed);
    let mut out = Vec::with_capacity(64);
    match kind {
        // Random binary bytes.
        0 => {
            for _ in 0..64 {
                out.push(rng.next_byte());
            }
        }
        // Truncated UTF-8: valid multi-byte sequence prefixes, cut short.
        1 => {
            let prefixes: [&[u8]; 4] = [
                &[0xE2, 0x82],       // ‘€’ missing its last byte
                &[0xF0, 0x9F, 0x92], // emoji missing its last byte
                &[0xC3],             // lone 2-byte lead
                &[0xF4, 0x8F],       // plane-16 lead, cut
            ];
            while out.len() < 64 {
                out.extend_from_slice(prefixes[(rng.next_byte() % 4) as usize]);
            }
        }
        // Continuation/overlong soup: bare continuation bytes and the
        // classic overlong `/` encoding.
        _ => {
            while out.len() < 64 {
                if rng.next_byte().is_multiple_of(3) {
                    out.extend_from_slice(&[0xC0, 0xAF]); // overlong '/'
                } else {
                    out.push(0x80 | (rng.next_byte() & 0x3F));
                }
            }
        }
    }
    out
}

/// Every vector, wrapped in every soup kind: the embedded secret is still
/// caught, the oracle agrees byte-for-byte, and chunked streaming matches.
#[test]
fn vectors_embedded_in_soup() {
    let (engine, key) = &*ENGINE_KEY;
    for kind in 0..3 {
        for (i, v) in cloak_core::vectors::all_vectors().iter().enumerate() {
            // Distinct leading/trailing seeds for EVERY kind (the previous
            // kind<<32 vs kind<<40 salting collapsed to the same value when
            // kind==0, so random-binary cases had identical prefix/suffix).
            let base = ((kind as u64) << 40) | i as u64;
            let mut input = soup(kind, base ^ 0x1111_1111_1111_1111);
            input.push(b'\n');
            input.extend_from_slice(v.input);
            input.push(b'\n');
            input.extend_from_slice(&soup(kind, base ^ 0x9999_9999_9999_9999));

            // The oracle defines behavior on garbage — bytes AND stats.
            let (out, stats) = engine_redact(engine, &input);
            let (ref_out, ref_stats) = cloak_core::reference::redact(&input, key);
            assert_eq!(out, ref_out, "soup kind={kind} vector={}", v.name);
            assert_eq!(stats.matches, ref_stats.matches, "{}", v.name);

            // Matching is unaffected by surrounding garbage: every span
            // the bare vector expects is still found (≥ tolerates soup
            // bytes that happen to form additional matches).
            for span in v.spans {
                let rule = RuleId::new(span.rule);
                let expected = v.spans.iter().filter(|s| s.rule == span.rule).count() as u64;
                assert!(
                    stats.matches.get(&rule).copied().unwrap_or(0) >= expected,
                    "soup kind={kind} vector={} lost its {} match",
                    v.name,
                    span.rule
                );
            }

            // Chunk-boundary invariant holds on garbage too.
            let (chunked, chunked_stats) = engine_redact_chunked(engine, &input, 7);
            assert_eq!(chunked, out, "7-byte chunking diverges on {}", v.name);
            assert_eq!(chunked_stats.matches, stats.matches);
        }
    }
}

/// Soup alone (no planted vectors, anchor bytes stripped) passes through
/// byte-identical: `cat file | cloak` with no matches is `cat`.
#[test]
fn anchorless_soup_is_passthrough() {
    let (engine, _key) = &*ENGINE_KEY;
    for kind in 0..3 {
        for round in 0..16u64 {
            let mut input = soup(kind, 0xBEEF << 8 | round);
            // Strip bytes that can seed a candidate window: anchor bytes
            // (`@ + :`), digits (ipv4/credit-card anchors), and `.`.
            input.retain(|b| {
                !b.is_ascii_digit() && !matches!(b, b'@' | b'+' | b':' | b'.' | b'/' | b'=')
            });
            let (out, stats) = engine_redact(engine, &input);
            assert_eq!(out, input, "soup kind={kind} round={round} corrupted");
            assert_eq!(stats.total_matches(), 0);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Random binary with a vector spliced at an arbitrary offset ⇒
    /// engine ≡ reference (256 cases).
    #[test]
    fn planted_vector_in_random_bytes_matches_reference(
        noise in proptest::collection::vec(any::<u8>(), 0..1024),
        pick in any::<prop::sample::Index>(),
        split in any::<prop::sample::Index>(),
    ) {
        let (engine, key) = &*ENGINE_KEY;
        let vectors = cloak_core::vectors::all_vectors();
        let v = vectors[pick.index(vectors.len())];
        let at = split.index(noise.len() + 1);
        let mut input = Vec::with_capacity(noise.len() + v.input.len());
        input.extend_from_slice(&noise[..at]);
        input.extend_from_slice(v.input);
        input.extend_from_slice(&noise[at..]);

        let (out, stats) = engine_redact(engine, &input);
        let (ref_out, ref_stats) = cloak_core::reference::redact(&input, key);
        prop_assert_eq!(out, ref_out, "vector {} at offset {}", v.name, at);
        prop_assert_eq!(stats.matches, ref_stats.matches);
    }
}
