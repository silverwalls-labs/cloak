//! Shared harness plumbing for the fuzz targets (docs/03 §4).
//!
//! Pulled into each target with `#[path = "../src/common.rs"] mod common;`
//! so the fuzz crate needs no lib target (which would fight the libFuzzer
//! `main`). Key setup mirrors `tests/differential.rs`.

use std::sync::LazyLock;

use cloak_core::{Config, Engine, RedactionConfig, Stats};

pub const KEY_VAR: &str = "CLOAK_FUZZ_DIGEST_KEY";
pub const KEY_MATERIAL: &str = "fuzz-digest-key";

/// The engine's max confirm window (jwt, 2048 — pinned by the
/// `engine_max_window` unit test). Inputs at or below this size never
/// flush before `finish`, so the whole guarantee holds unconditionally;
/// above it, the flush boundary can cut backward context for
/// context-guarded rules — the known engine bug tracked as issue #27.
pub const MAX_WINDOW: usize = 2048;

/// Carry-over bound asserted after every push: max_window (2048, jwt) plus
/// PEM_BAIL_OUT (16 KiB) plus the longest BEGIN line (37). Mirrors the
/// bounded-memory proptest in `tests/streaming.rs`.
pub const CARRY_BOUND: usize = MAX_WINDOW + 16_384 + 37;

/// One engine for the whole fuzz process — `Engine` is Send+Sync and
/// sessions are cheap; rebuilding per input would dominate runtime.
pub static ENGINE: LazyLock<Engine> = LazyLock::new(|| {
    // SAFETY: single dedicated var, set exactly once before any engine is
    // built, never removed; libFuzzer drives the target single-threaded.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { std::env::set_var(KEY_VAR, KEY_MATERIAL) };
    let config = Config {
        redaction: RedactionConfig {
            digest_key: format!("env:{KEY_VAR}"),
        },
        ..Config::default()
    };
    Engine::new(&config).expect("engine builds from default config")
});

/// The digest key `ENGINE` resolves — recomputed independently for the
/// reference oracle (same KDF context as `config::resolve_digest_key`).
pub static KEY: LazyLock<[u8; 32]> =
    LazyLock::new(|| blake3::derive_key("cloak digest key", KEY_MATERIAL.as_bytes()));

/// Strict mode (`CLOAK_FUZZ_STRICT=1`): assert the FULL guarantee — every
/// assertion at every input length. A strict-mode find that is not one of
/// the tracked bugs below is a new guarantee bug.
///
/// Default mode (the CI gate) exempts what two tracked engine bugs are
/// known to violate, so the gate stays meaningful while they're open:
/// - engine ≡ reference and idempotence: strict-only. Issue #27
///   (context-keyed rules × carry-over/PEM hold — reproduces below
///   max_window, see corpus `regression-connstring-pem-overlap`) and
///   issue #34 (adjacent redaction erases backward-guard context).
/// - streaming ≡ whole-buffer: capped at `MAX_WINDOW` bytes — above it
///   the flush boundary can cut backward context (#27's other face).
///
/// Asserted unconditionally in BOTH modes, at every length: no panic,
/// carry-over bound, bytes_processed. Default back to strict when #27
/// and #34 are fixed.
pub fn strict() -> bool {
    static STRICT: LazyLock<bool> =
        LazyLock::new(|| std::env::var_os("CLOAK_FUZZ_STRICT").is_some());
    *STRICT
}

/// Whether the streaming ≡ whole-buffer assertion applies (see [`strict`]).
pub fn assert_streaming(input: &[u8]) -> bool {
    strict() || input.len() <= MAX_WINDOW
}

/// Whole-buffer redaction: one push + finish.
pub fn whole(engine: &Engine, input: &[u8]) -> (Vec<u8>, Stats) {
    let mut session = engine.session();
    let mut out = Vec::new();
    session
        .push(input, &mut out)
        .expect("write to Vec cannot fail");
    let stats = session.finish(&mut out).expect("write to Vec cannot fail");
    (out, stats)
}

/// Streaming redaction under `sizes`, asserting the carry-over bound
/// (bounded memory, docs/03 property 4) after every push.
pub fn chunked(
    engine: &Engine,
    input: &[u8],
    mut sizes: impl Iterator<Item = usize>,
) -> (Vec<u8>, Stats) {
    let mut session = engine.session();
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < input.len() {
        let size = sizes.next().unwrap_or(input.len() - pos).max(1);
        let end = (pos + size).min(input.len());
        session
            .push(&input[pos..end], &mut out)
            .expect("write to Vec cannot fail");
        assert!(
            session.carry_over_len() <= CARRY_BOUND,
            "carry-over {} exceeds bound {CARRY_BOUND}",
            session.carry_over_len()
        );
        pos = end;
    }
    let stats = session.finish(&mut out).expect("write to Vec cannot fail");
    (out, stats)
}

/// Deterministic chunk-size schedule in `1..=max`, derived from `seed`
/// (any mutation of the input changes the schedule via [`fold_seed`]).
pub fn lcg_sizes(mut seed: u64, max: usize) -> impl Iterator<Item = usize> {
    std::iter::from_fn(move || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        Some(((seed >> 33) as usize % max.max(1)) + 1)
    })
}

/// Fold the input into a schedule seed.
pub fn fold_seed(data: &[u8]) -> u64 {
    data.iter().fold(data.len() as u64, |acc, &b| {
        acc.rotate_left(7) ^ u64::from(b)
    })
}

/// The differential invariant: engine whole-buffer output ≡ reference
/// oracle, bytes AND stats (`Stats` has no `PartialEq` — field compare,
/// same convention as `tests/differential.rs`).
pub fn assert_reference_equivalence(input: &[u8], engine_out: &[u8], engine_stats: &Stats) {
    let (reference_out, reference_stats) = cloak_core::reference::redact(input, &KEY);
    assert_eq!(engine_out, reference_out.as_slice(), "engine ≢ reference");
    assert_eq!(
        engine_stats.matches, reference_stats.matches,
        "stats diverge from reference"
    );
    assert_eq!(
        engine_stats.bytes_processed,
        reference_stats.bytes_processed
    );
}

/// Streaming ≡ whole-buffer under one schedule (chunk-boundary invariant).
pub fn assert_streaming_equivalence(
    engine: &Engine,
    input: &[u8],
    sizes: impl Iterator<Item = usize>,
    whole_out: &[u8],
    whole_stats: &Stats,
    label: &str,
) {
    let (out, stats) = chunked(engine, input, sizes);
    assert_eq!(out, whole_out, "streaming ({label}) ≢ whole-buffer");
    assert_eq!(
        stats.matches, whole_stats.matches,
        "streaming ({label}) stats ≢ whole-buffer stats"
    );
}
