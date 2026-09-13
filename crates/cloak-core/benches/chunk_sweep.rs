//! Chunk-size sweep: `Session::push` throughput vs chunk size.
//!
//! Characterizes carry-over overhead across chunk sizes from 1 KiB to 1 MiB.
//! Uses `clean-text` (the honest clean path) so carry-over cost is visible
//! without confirm/redact noise.

use std::path::Path;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use cloak_core::{Config, Engine};

const CHUNK_SIZES: &[usize] = &[
    1_024,     // 1 KiB
    2_048,     // 2 KiB
    4_096,     // 4 KiB
    8_192,     // 8 KiB
    16_384,    // 16 KiB
    32_768,    // 32 KiB
    65_536,    // 64 KiB (CLI default)
    131_072,   // 128 KiB
    262_144,   // 256 KiB
    524_288,   // 512 KiB
    1_048_576, // 1 MiB
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

fn format_size(bytes: usize) -> String {
    if bytes >= 1_048_576 {
        format!("{}MiB", bytes / 1_048_576)
    } else {
        format!("{}KiB", bytes / 1_024)
    }
}

fn bench_chunk_sweep(c: &mut Criterion) {
    let engine = Engine::new(&Config::ephemeral()).unwrap();
    let corpus = load_corpus("clean-text");

    let mut group = c.benchmark_group("chunk-sweep");
    for &chunk_size in CHUNK_SIZES {
        let label = format_size(chunk_size);
        group.throughput(Throughput::Bytes(corpus.len() as u64));
        group.bench_with_input(BenchmarkId::new("push", &label), &chunk_size, |b, &cs| {
            b.iter(|| {
                let mut session = engine.session();
                let mut out = Vec::with_capacity(corpus.len() + corpus.len() / 4);
                for chunk in corpus.chunks(cs) {
                    session.push(chunk, &mut out).unwrap();
                }
                session.finish(&mut out).unwrap();
                out
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_chunk_sweep);
criterion_main!(benches);
