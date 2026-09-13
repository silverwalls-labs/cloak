//! Generate the five committed benchmark corpora (docs/04-performance.md).
//!
//! Usage: `cargo run -p cloak-core --example gen_bench_corpora`
//! Output: `corpus/clean-json`, `corpus/clean-text`, `corpus/dirty-mixed`,
//!         `corpus/dirty-dense`, `corpus/binary-soup` (~1 MB each).
//!
//! Deterministic: seeded RNG (`rand::rngs::StdRng`) — same seeds, same
//! bytes. `tests/corpus_determinism.rs` regenerates in-process and pins
//! the committed files to this generator, so editing it without
//! re-running (and committing) the corpora fails CI.

use std::fs;
use std::path::{Path, PathBuf};

use rand::SeedableRng;
use rand::rngs::StdRng;

mod generator;

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap() // crates/
        .parent()
        .unwrap() // workspace root
        .join("corpus")
}

fn main() {
    let dir = corpus_dir();
    fs::create_dir_all(&dir).expect("create corpus dir");

    for (name, gen_fn, seed) in generator::corpora() {
        let mut rng = StdRng::seed_from_u64(seed);
        let data = gen_fn(&mut rng);
        let path = dir.join(name);
        fs::write(&path, &data).unwrap_or_else(|e| panic!("write corpus {}: {e}", path.display()));
        eprintln!(
            "  {} ({} bytes, {} lines)",
            name,
            data.len(),
            bytecount(&data, b'\n'),
        );
    }
    eprintln!("done — corpus files in {}", dir.display());
}

fn bytecount(data: &[u8], byte: u8) -> usize {
    data.iter().filter(|&&b| b == byte).count()
}
