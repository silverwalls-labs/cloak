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

/// Assertion tiers, split by what actually holds today.
///
/// **Both modes, every input:** no panic and the carry-over bound. These are
/// universal — the robustness half of the guarantee (docs/03 threat model:
/// malicious input must not crash / hang / OOM). This is the PR-gate and
/// nightly signal.
///
/// **Strict mode only (`CLOAK_FUZZ_STRICT=1`), every input:** the three
/// correctness equivalences — engine ≡ reference, streaming ≡ whole-buffer,
/// idempotence. They are strict-only because two tracked engine bugs violate
/// all three on narrow inputs, and asserting them by default would make the
/// gate red for already-filed bugs:
/// - **#27** — a context-keyed extent overlapping a streamed PEM body makes
///   even `streaming ≢ whole-buffer` below max_window (reproducer:
///   `regression-connstring-pem-overlap`), and cuts backward context beyond
///   max_window.
/// - **#34** — redacting a match erases an adjacent candidate's backward
///   guard, breaking idempotence.
///
/// Correctness on KNOWN inputs is still gated every PR by the deterministic
/// `tests/differential.rs` (engine ≡ reference over the vector corpus and
/// concatenations). Strict fuzzing is the tool to (a) reproduce a finding and
/// (b) hunt for NEW divergences once #27 and #34 are fixed — at which point
/// strict becomes the default and this split collapses.
pub fn strict() -> bool {
    static STRICT: LazyLock<bool> = LazyLock::new(|| {
        // Truthy value only, so `CLOAK_FUZZ_STRICT=0` / `=false` DISABLES
        // (mere-presence would make the natural way to turn it off enable it).
        match std::env::var("CLOAK_FUZZ_STRICT") {
            Ok(v) => !matches!(v.trim(), "" | "0" | "false" | "no" | "off"),
            Err(_) => false,
        }
    });
    *STRICT
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
