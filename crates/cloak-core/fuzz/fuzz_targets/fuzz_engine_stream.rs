//! `fuzz_engine_stream` (docs/03 §4): arbitrary bytes + derived chunkings.
//!
//! Asserts, per input: no panic (debug_asserts armed via
//! `-O --debug-assertions`) and bounded carry-over memory at every
//! length; streaming ≡ whole-buffer for inputs ≤ max_window; and — in
//! strict mode — whole-buffer ≡ reference oracle plus idempotence at
//! every length (see `common::strict` for the #27/#34 gating rationale).

#![no_main]

#[path = "../src/common.rs"]
mod common;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let engine = &*common::ENGINE;

    let (whole_out, whole_stats) = common::whole(engine, data);
    assert_eq!(whole_stats.bytes_processed, data.len() as u64);

    if common::strict() {
        common::assert_reference_equivalence(data, &whole_out, &whole_stats);
    }

    if !common::assert_streaming(data) {
        return;
    }

    // Chunk-boundary invariant under three schedules. Exhaustive chunking
    // is proptest's job (tests/streaming.rs); here the schedules mutate
    // with the input.
    let seed = common::fold_seed(data);
    common::assert_streaming_equivalence(
        engine,
        data,
        common::lcg_sizes(seed, 97),
        &whole_out,
        &whole_stats,
        "small chunks",
    );
    common::assert_streaming_equivalence(
        engine,
        data,
        common::lcg_sizes(seed ^ 0xDEAD_BEEF, 8192),
        &whole_out,
        &whole_stats,
        "large chunks",
    );
    if data.len() <= common::MAX_WINDOW {
        common::assert_streaming_equivalence(
            engine,
            data,
            std::iter::repeat(1),
            &whole_out,
            &whole_stats,
            "1-byte chunks",
        );
    }

    // Idempotence: tags don't re-match, nothing is reintroduced.
    // Strict-only until issue #34 is fixed: redacting a match can erase
    // the backward-guard context of an adjacent rejected candidate, which
    // then matches on the second pass (violated at any input length —
    // regression seed `regression-idempotence-tag-context` reproduces).
    if common::strict() && whole_stats.matches.values().sum::<u64>() > 0 {
        let (twice, second_stats) = common::whole(engine, &whole_out);
        assert_eq!(twice, whole_out, "redaction not idempotent");
        assert_eq!(
            second_stats.matches.values().sum::<u64>(),
            0,
            "tags re-matched on second pass"
        );
    }
});
