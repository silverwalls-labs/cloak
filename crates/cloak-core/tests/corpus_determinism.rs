//! Determinism pin for the committed benchmark corpora (S7).
//!
//! Regenerates each corpus in-process with the same seeds as
//! `examples/gen_bench_corpora` and asserts byte-identical output against
//! the committed files. If the generator changes without re-running it
//! (and committing the result), this fails — CI always measures the same
//! data as dev.

use std::path::Path;

use rand::SeedableRng;
use rand::rngs::StdRng;

// Share the generation logic with the writer example — one definition, no
// drift between what is written and what is pinned.
#[path = "../examples/gen_bench_corpora/generator.rs"]
mod generator;

fn corpus_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("corpus")
        .join(name)
}

#[test]
fn committed_corpora_match_generator() {
    for (name, gen_fn, seed) in generator::corpora() {
        let mut rng = StdRng::seed_from_u64(seed);
        let expected = gen_fn(&mut rng);
        let path = corpus_path(name);
        let committed = std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
        assert_eq!(
            committed, expected,
            "corpus {name} does not match the generator output — re-run \
             `cargo run -p cloak-core --example gen_bench_corpora` and commit \
             the result, or update the generator and corpora together"
        );
    }
}
