# Performance Receipts — cloak-node native binding (E6)

> Generated: 2026-10-31
> rustc: 1.98.1
> cloak-node: napi-rs 3.16.1, release profile
> Host: Node.js v24.19.0, Apple Silicon (M1, aarch64-apple-darwin), AC power
> Corpus: mixed log lines (4,064 B ≈ 4.0 KiB, 22 matches: 2 secrets + 20 email-bearing lines)
>
> **E6 ship gate** (docs/06-embedding.md): cloak-node must beat the
> WASM-in-Node path (E2 baseline) on the same corpus — cleared on
> every row, against a same-session re-measurement.

## Node native vs WASM throughput

Same corpus and harness as `receipts-wasm-e2-node.md`
(`crates/cloak-node/bench/throughput.ts` is a line-for-line port of
`adapters/node/bench/throughput.ts`: 100/50 warmup, 50,000
iterations). All rows below were measured back-to-back on the same
machine in the same session — the WASM rows are *re-measurements*,
not quotes.

| Path | Throughput (MiB/s) | Time/iter (µs) | vs E2 same-session |
|---|---|---|---|
| **cloak-node (one-shot `redact`)** | **136** | 28.5 | **1.35×** |
| **cloak-node (streaming, 1 KiB chunks)** | **77** | 50.0 | **1.21×** |
| **cloak-node (streaming, 256 B chunks)** | **32** | 120.2 | **1.21×** |
| Node WASM (one-shot), same session | 101 | 38.3 | baseline |
| Node WASM (streaming, 1 KiB), same session | 64 | 60.8 | baseline |
| Node WASM (streaming, 256 B), same session | 27 | 145.2 | baseline |
| Native cloak-core (criterion, same session) | 154 | 25.1 | reference |
| Rust wasmtime (criterion, same session) | 88 | 44.2 | reference |

Run-to-run stability: a second pass measured 127 / 66 / 30 MiB/s —
one-shot and 256 B within ~7%, streaming 1 KiB within ~14%. Treat
deltas in that range as noise; the gate margin (1.21× at 1 KiB) is
still well above unity even at the lower measurement.

## Host overhead

The native one-shot sits at ~28 µs/op against criterion's 25.1 µs
for raw `cloak-core` on the identical workload — **the napi-rs
boundary costs ≈ 3 µs per call** (one `Buffer` in, one `Buffer` +
one stats object out). This is slightly higher than pyo3's ~0–1 µs
(E5) because napi-rs allocates a new `Buffer` for every return (vs
pyo3 borrowing Python `bytes` in place), but still a small fraction
of the scan itself.

The WASM path pays more: ~38 µs (one-shot) vs wasmtime's ~44 µs on the
same corpus, plus linear-memory copy overhead and WASI bootstrap. The
native path eliminates all of that.

Small chunks still magnify per-call cost — at 256 B the push boundary
work (~3 µs × 16 pushes per iteration) adds up. Both paths lose
roughly the same factor from one-shot to 256 B chunks (native 4.3×,
WASM 3.7×); the native advantage comes from the lower absolute
per-call cost, not from a flatter slope.

## Methodology

- **Build commands**: `cd crates/cloak-node && npm run build-native`
  (napi-rs release build), then `npm run bench` for the native rows;
  `cargo build -p cloak-wasm --target wasm32-wasip1 --release` then
  `cd adapters/node && CLOAK_DIGEST_KEY=bench-key node
  --experimental-strip-types bench/throughput.ts` for the WASM rows.
- **Parity status**: the 247-vector parity fixture matches
  `cargo run --example export-vectors -p cloak-core` (freshness-gated
  by diff in CI), and the node:test suite redacts every vector
  byte-identically both one-shot and streaming; the perf numbers above
  are therefore measured on the same matching engine.
- **Corpus**: byte-identical to the E1/E2/E3/E4/E5 bench corpora —
  ~60 log lines, 22 matches per iteration (20 `email` + 1 GitHub
  token + 1 AWS access key), 4,064 B total. Match-dense workload.
- **Environment**: single-threaded, engine created once, session per
  iteration (streaming rows), digest key via env
  (`CLOAK_DIGEST_KEY=bench-key`), release build.
- **Battery warning**: on battery power this machine measured raw
  native core at 50 µs/op (2× slow) with 5× run-to-run swings —
  receipts must be measured on AC power.
