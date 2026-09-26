/**
 * Throughput benchmark: Node.js WASM adapter.
 *
 * Same corpus as crates/wasm-parity/benches/throughput.rs — mixed log
 * lines with embedded secrets (~4 KiB per iteration).
 *
 * Run:
 *   CLOAK_DIGEST_KEY=bench-key node --experimental-strip-types --no-warnings bench/throughput.ts
 */

import { createEngine, type CloakEngine } from "../src/index.ts";

// ── Corpus (matches Rust benchmark) ────────────────────────────────

function buildCorpus(): Buffer {
  const parts: Buffer[] = [];
  for (let i = 0; i < 20; i++) {
    parts.push(
      Buffer.from(
        "INFO 2026-09-26T12:00:00Z request completed status=200 user=alice@example.com latency=12ms\n",
      ),
    );
  }
  parts.push(
    Buffer.from(
      "DEBUG auth token=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 granted\n",
    ),
  );
  for (let i = 0; i < 20; i++) {
    parts.push(
      Buffer.from(
        "INFO 2026-09-26T12:00:01Z db query rows=42 duration=3ms\n",
      ),
    );
  }
  parts.push(Buffer.from("WARN key=AKIAIOSFODNN7EXAMPLE exposed\n"));
  for (let i = 0; i < 20; i++) {
    parts.push(
      Buffer.from(
        "INFO 2026-09-26T12:00:02Z response sent bytes=1024\n",
      ),
    );
  }
  return Buffer.concat(parts);
}

// ── Benchmark runner ───────────────────────────────────────────────

function benchmarkRedact(
  engine: CloakEngine,
  corpus: Buffer,
  iterations: number,
): { totalNs: bigint; opsPerSec: number; mibPerSec: number } {
  // Warmup
  for (let i = 0; i < 100; i++) {
    engine.redact(corpus);
  }

  const start = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) {
    engine.redact(corpus);
  }
  const elapsed = process.hrtime.bigint() - start;

  const elapsedSec = Number(elapsed) / 1e9;
  const opsPerSec = iterations / elapsedSec;
  const bytesPerSec = (corpus.length * iterations) / elapsedSec;
  const mibPerSec = bytesPerSec / (1024 * 1024);

  return { totalNs: elapsed, opsPerSec, mibPerSec };
}

function benchmarkStreaming(
  engine: CloakEngine,
  corpus: Buffer,
  chunkSize: number,
  iterations: number,
): { totalNs: bigint; opsPerSec: number; mibPerSec: number } {
  // Warmup
  for (let i = 0; i < 50; i++) {
    const session = engine.session();
    for (let off = 0; off < corpus.length; off += chunkSize) {
      session.push(corpus.subarray(off, Math.min(off + chunkSize, corpus.length)));
    }
    session.finish();
  }

  const start = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) {
    const session = engine.session();
    for (let off = 0; off < corpus.length; off += chunkSize) {
      session.push(corpus.subarray(off, Math.min(off + chunkSize, corpus.length)));
    }
    session.finish();
  }
  const elapsed = process.hrtime.bigint() - start;

  const elapsedSec = Number(elapsed) / 1e9;
  const opsPerSec = iterations / elapsedSec;
  const bytesPerSec = (corpus.length * iterations) / elapsedSec;
  const mibPerSec = bytesPerSec / (1024 * 1024);

  return { totalNs: elapsed, opsPerSec, mibPerSec };
}

// ── Main ───────────────────────────────────────────────────────────

const engine = await createEngine(
  { redaction: { digestKey: "env:CLOAK_DIGEST_KEY" } },
  { CLOAK_DIGEST_KEY: "bench-key" },
);

const corpus = buildCorpus();
const iterations = 50_000;

console.log(`Corpus: ${corpus.length} bytes (${(corpus.length / 1024).toFixed(1)} KiB)`);
console.log(`Iterations: ${iterations.toLocaleString()}\n`);

// One-shot redact
const redactResult = benchmarkRedact(engine, corpus, iterations);
const redactUsPerOp = Number(redactResult.totalNs) / iterations / 1000;
console.log(`── redact() (one-shot) ──`);
console.log(`  ${redactUsPerOp.toFixed(2)} µs/op`);
console.log(`  ${redactResult.mibPerSec.toFixed(1)} MiB/s`);
console.log(`  ${redactResult.opsPerSec.toFixed(0)} ops/sec\n`);

// Streaming with 1 KiB chunks
const stream1k = benchmarkStreaming(engine, corpus, 1024, iterations);
const stream1kUsPerOp = Number(stream1k.totalNs) / iterations / 1000;
console.log(`── streaming (1 KiB chunks) ──`);
console.log(`  ${stream1kUsPerOp.toFixed(2)} µs/op`);
console.log(`  ${stream1k.mibPerSec.toFixed(1)} MiB/s`);
console.log(`  ${stream1k.opsPerSec.toFixed(0)} ops/sec\n`);

// Streaming with 256-byte chunks
const stream256 = benchmarkStreaming(engine, corpus, 256, iterations);
const stream256UsPerOp = Number(stream256.totalNs) / iterations / 1000;
console.log(`── streaming (256 B chunks) ──`);
console.log(`  ${stream256UsPerOp.toFixed(2)} µs/op`);
console.log(`  ${stream256.mibPerSec.toFixed(1)} MiB/s`);
console.log(`  ${stream256.opsPerSec.toFixed(0)} ops/sec\n`);

// Comparison table
console.log(`── comparison (same corpus, same machine) ──`);
console.log(`  Rust native (criterion):        ~229 MiB/s  (~17 µs/op)`);
console.log(`  Rust WASM-via-wasmtime:          ~134 MiB/s  (~29 µs/op)`);
console.log(`  Node WASM (one-shot):            ~${redactResult.mibPerSec.toFixed(0)} MiB/s  (~${redactUsPerOp.toFixed(0)} µs/op)`);
console.log(`  Node WASM (streaming 1K):        ~${stream1k.mibPerSec.toFixed(0)} MiB/s  (~${stream1kUsPerOp.toFixed(0)} µs/op)`);

engine.dispose();
