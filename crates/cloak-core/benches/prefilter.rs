//! Prefilter-only throughput: `Scanner::scan` in isolation.
//!
//! Benchmarks both `AhoCorasickScanner` (production, SIMD-accelerated) and
//! `ScalarScanner` (naive reference, O(n·m)) on every corpus. The ratio is
//! the "SIMD-powered" receipt (docs/04-performance.md, receipts protocol).

use std::path::Path;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use cloak_core::scanner::{AhoCorasickScanner, Candidate, ScalarScanner, Scanner};
use cloak_core::{CATALOG, PEM_ANCHOR, RuleSpec};

const CORPUS_NAMES: &[&str] = &[
    "clean-json",
    "clean-text",
    "dirty-mixed",
    "dirty-dense",
    "binary-soup",
];

fn load_corpus(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("corpus")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read corpus {}: {e}", path.display()))
}

fn catalog_refs() -> Vec<&'static RuleSpec> {
    CATALOG.iter().collect()
}

fn bench_prefilter(c: &mut Criterion) {
    let refs = catalog_refs();
    // Identical anchor sets on both scanners, mirroring the production
    // engine build: catalog anchors + the PEM anchor at the pseudo rule
    // index just past the catalog (engine/mod.rs `pem_rule_idx`). Receipts
    // must measure the shipped configuration.
    let pem_extra: Vec<(&[u8], usize)> = vec![(PEM_ANCHOR, CATALOG.len())];
    let ac = AhoCorasickScanner::new(&refs, &pem_extra).unwrap();
    let scalar = ScalarScanner::new(&refs, &pem_extra);

    let mut group = c.benchmark_group("prefilter");
    for &name in CORPUS_NAMES {
        let data = load_corpus(name);
        group.throughput(Throughput::Bytes(data.len() as u64));

        group.bench_with_input(BenchmarkId::new("aho-corasick", name), &data, |b, data| {
            b.iter(|| {
                let mut candidates: Vec<Candidate> = Vec::new();
                ac.scan(data, &mut candidates);
                candidates.len()
            });
        });

        group.bench_with_input(BenchmarkId::new("scalar", name), &data, |b, data| {
            b.iter(|| {
                let mut candidates: Vec<Candidate> = Vec::new();
                scalar.scan(data, &mut candidates);
                candidates.len()
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_prefilter);
criterion_main!(benches);
