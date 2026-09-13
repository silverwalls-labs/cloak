//! End-to-end throughput: `Session::push` full pipeline
//! (prefilter → confirm → merge → redact → write).
//!
//! Measures MB/s per corpus at 64 KiB chunks (the CLI default).
//! This is the number the CI floor gate checks.

use std::path::Path;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use cloak_core::{Config, Engine};

const CHUNK_SIZE: usize = 64 * 1024;

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

fn bench_throughput(c: &mut Criterion) {
    let engine = Engine::new(&Config::ephemeral()).unwrap();

    let mut group = c.benchmark_group("throughput");
    for &name in CORPUS_NAMES {
        let data = load_corpus(name);
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(BenchmarkId::new("push", name), &data, |b, data| {
            b.iter(|| {
                let mut session = engine.session();
                let mut out = Vec::with_capacity(data.len() + data.len() / 4);
                for chunk in data.chunks(CHUNK_SIZE) {
                    session.push(chunk, &mut out).unwrap();
                }
                session.finish(&mut out).unwrap();
                out
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_throughput);
criterion_main!(benches);
