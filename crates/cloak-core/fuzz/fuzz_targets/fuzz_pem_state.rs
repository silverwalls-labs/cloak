//! `fuzz_pem_state` (docs/03 §4): adversarial BEGIN/END sequences through
//! the public API — nested, unterminated, huge, straddled markers.
//!
//! Bias toward PEM structure comes from the seed corpus
//! (`corpus/fuzz_pem_state/`) and `dictionaries/pem_state.dict`, not a
//! custom mutator. Chunk schedules are deliberately tiny so BEGIN/END
//! markers straddle push boundaries — the adversarial surface of the PEM
//! state machine (`engine/pem.rs`). Hang/OOM are findings via libFuzzer
//! `-timeout` / `-rss_limit_mb`; the carry-over bound (which includes the
//! PEM bail-out) is asserted after every push.

#![no_main]

#[path = "../src/common.rs"]
mod common;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let engine = &*common::ENGINE;

    let (whole_out, whole_stats) = common::whole(engine, data);

    if common::strict() {
        common::assert_reference_equivalence(data, &whole_out, &whole_stats);
    }

    if !common::assert_streaming(data) {
        return;
    }

    let seed = common::fold_seed(data);
    common::assert_streaming_equivalence(
        engine,
        data,
        common::lcg_sizes(seed, 13),
        &whole_out,
        &whole_stats,
        "tiny chunks",
    );
    common::assert_streaming_equivalence(
        engine,
        data,
        common::lcg_sizes(seed ^ 0x9E37, 41),
        &whole_out,
        &whole_stats,
        "small chunks",
    );
    if data.len() <= 4096 {
        common::assert_streaming_equivalence(
            engine,
            data,
            std::iter::repeat(1),
            &whole_out,
            &whole_stats,
            "1-byte chunks",
        );
    }
});
