//! `fuzz_pem_state` (docs/03 §4): adversarial BEGIN/END sequences through
//! the public API — nested, unterminated, huge, straddled markers.
//!
//! Bias toward PEM structure comes from the seed corpus
//! (`corpus/fuzz_pem_state/`) and `dictionaries/pem_state.dict`, not a
//! custom mutator. Chunk schedules are deliberately tiny so BEGIN/END
//! markers straddle push boundaries — the adversarial surface of the PEM
//! state machine (`engine/pem.rs`). Hang/OOM are findings via libFuzzer
//! `-timeout` / `-rss_limit_mb`; the carry-over bound (which includes the
//! PEM bail-out) is asserted after every push, in both modes.
//!
//! Strict mode only: the correctness equivalences (see `common::strict`).

#![no_main]

#[path = "../src/common.rs"]
mod common;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let engine = &*common::ENGINE;

    let (whole_out, whole_stats) = common::whole(engine, data);
    assert_eq!(whole_stats.bytes_processed, data.len() as u64);

    let seed = common::fold_seed(data);
    let streamed = [
        Some(common::chunked(engine, data, common::lcg_sizes(seed, 13))),
        Some(common::chunked(
            engine,
            data,
            common::lcg_sizes(seed ^ 0x9E37, 41),
        )),
        (data.len() <= 4096).then(|| common::chunked(engine, data, std::iter::repeat(1))),
    ];

    if !common::strict() {
        return;
    }

    common::assert_reference_equivalence(data, &whole_out, &whole_stats);
    for run in streamed.into_iter().flatten() {
        assert_eq!(run.0, whole_out, "streaming ≢ whole-buffer");
        assert_eq!(
            run.1.matches, whole_stats.matches,
            "streaming stats diverge"
        );
    }
    // Idempotence — PEM's `[CLOAK:` begin-guard (hardened here via
    // pem_confirm_window) is idempotence-critical, and this target's tiny
    // chunk schedules straddle BEGIN/END markers far more than
    // fuzz_engine_stream's do.
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
