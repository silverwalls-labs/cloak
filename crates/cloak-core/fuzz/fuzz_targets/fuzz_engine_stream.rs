//! `fuzz_engine_stream` (docs/03 §4): arbitrary bytes + derived chunkings.
//!
//! Every input, both modes: no panic (debug_asserts armed via
//! `-O --debug-assertions`) and the carry-over bound after every push
//! (`common::chunked` asserts it across several chunk schedules).
//!
//! Strict mode only (`CLOAK_FUZZ_STRICT=1`): whole-buffer ≡ reference
//! oracle, streaming ≡ whole-buffer, and idempotence — see `common::strict`
//! for why these are gated (issues #27, #34).

#![no_main]

#[path = "../src/common.rs"]
mod common;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let engine = &*common::ENGINE;

    let (whole_out, whole_stats) = common::whole(engine, data);
    assert_eq!(whole_stats.bytes_processed, data.len() as u64);

    // Exercise several chunk schedules for the carry-over bound (asserted
    // inside `chunked`). Exhaustive chunking is proptest's job
    // (tests/streaming.rs); here the schedules mutate with the input.
    let seed = common::fold_seed(data);
    let streamed = [
        Some(common::chunked(engine, data, common::lcg_sizes(seed, 97))),
        Some(common::chunked(
            engine,
            data,
            common::lcg_sizes(seed ^ 0xDEAD_BEEF, 8192),
        )),
        (data.len() <= common::MAX_WINDOW)
            .then(|| common::chunked(engine, data, std::iter::repeat(1))),
    ];

    if !common::strict() {
        return;
    }

    // Correctness equivalences (strict only).
    common::assert_reference_equivalence(data, &whole_out, &whole_stats);
    for run in streamed.into_iter().flatten() {
        assert_eq!(run.0, whole_out, "streaming ≢ whole-buffer");
        assert_eq!(run.1.matches, whole_stats.matches, "streaming stats diverge");
    }
    if whole_stats.matches.values().sum::<u64>() > 0 {
        let (twice, second) = common::whole(engine, &whole_out);
        assert_eq!(twice, whole_out, "redaction not idempotent");
        assert_eq!(
            second.matches.values().sum::<u64>(),
            0,
            "tags re-matched on second pass"
        );
    }
});
