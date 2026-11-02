# Performance Receipts — cloak-go native binding (E8)

> Generated: 2026-11-01
> rustc: 1.98.1
> cloak-go: cgo over cloak-ffi (staticlib, release profile), Go 1.27.3
> Host: Apple Silicon (M1, aarch64-apple-darwin), macOS 26.4.1, AC power
> Corpus: mixed log lines (4,064 B ≈ 4.0 KiB, 22 matches: 2 secrets + 20 email-bearing lines)
>
> **E8 ship gate** (docs/06-embedding.md): cloak-go must beat the
> WASM-via-wazero path (E4 baseline) on the same corpus — cleared on
> every row, against both the committed E4 receipt and a same-day
> re-measurement.

## Go native vs WASM throughput

Same corpus and harness as `receipts-wasm-e4-go.md`
(`crates/cloak-go/bench/main.go` is a line-for-line port of
`adapters/go/bench/main.go`: 100/50 warmup, 50,000 iterations). All
rows below were measured back-to-back on the same machine on the same
day — the E4 and Rust rows are *re-measurements*, not quotes. The
committed E4 receipt rows are listed for traceability; note this
machine measured globally slower than on 2026-10-25 (criterion reports
raw native core ~64% more time per iteration than its stored baseline
— same OS-update/CPU-state class of drift the receipts protocol
re-measures baselines to absorb), which is exactly why the gate is
judged on the same-day rows.

| Path | Throughput (MiB/s) | Time/iter (µs) | vs E4 same-day |
|---|---|---|---|
| **cloak-go (one-shot `Redact`)** | **97.8** | 39.6 | **2.7×** |
| **cloak-go (streaming, 1 KiB chunks)** | **61.3** | 63.2 | **2.7×** |
| **cloak-go (streaming, 256 B chunks)** | **24.7** | 156.8 | **3.0×** |
| Go WASM / wazero (one-shot), same day | 36.5 | 106.1 | baseline |
| Go WASM / wazero (streaming, 1 KiB), same day | 23.0 | 168.6 | baseline |
| Go WASM / wazero (streaming, 256 B), same day | 8.1 | 480.3 | baseline |
| Go WASM, committed E4 receipt (2026-10-25) | 56 / 34 / 14 | 69 / 114 / 271 | reference |
| Rust wasmtime (same day, fresh artifact) | 59.0 | 65.7 | reference |
| Native cloak-core (criterion, same day) | 101.5 | 38.2 | reference |

Run-to-run stability: a second cloak-go pass measured 96.6 / 61.8 /
24.8 MiB/s and a second wazero pass 36.3 / 23.1 MiB/s — within ~2%;
treat deltas smaller than ~5% as noise. cloak-go also beats the
*committed* E4 receipt rows (1.75× / 1.80× / 1.76×), so the gate
clears under either reading.

## Host overhead

The native one-shot sits at 39.6 µs/op against criterion's 38.2 µs for
raw `cloak-core` on the identical workload — **the cgo + cloak-ffi
boundary costs ≈ 1–2 µs per call** (one pinned `[]byte` in, one
copy-out + `cloak_buf_free`, stats as a small JSON buffer). That is
the wazero-codegen gap E8 existed to close: the same-day wazero
one-shot pays 106.1 µs where the Rust-wasmtime row pays 65.7 µs for
the same module, and both still trail native core by the WASM-runtime
cost itself.

Small chunks magnify per-call cost — at 256 B the harness makes ~19
cgo crossings per iteration (16 pushes + session lifecycle) plus the
carry-over rescans — but the slope is flatter than wazero's: cloak-go
loses 4.0× from one-shot to 256 B chunks, the wazero path loses 4.5×
(and the absolute gap at 256 B is 3.0×).

Concurrency: unlike the WASM adapter (whose take-once error/stats
slots force an engine-wide mutex), cloak-go takes only an RWMutex read
lock per call — concurrent `Redact` calls and sessions run in
parallel. What is verified is concurrent *correctness*, not
throughput (`concurrency_test.go`: byte-identical output across 8
goroutines under `-race`, Close-drains-in-flight-calls) — no
multi-threaded speedup figure is claimed here.

## Methodology

- **Source revision**: benches ran on the tree of the commit
  introducing this receipt — single-threaded, CPU-state sensitive,
  see the battery warning below.
- **Build commands**: `cargo build -p cloak-ffi --release`, then
  `cd crates/cloak-go && go run ./bench` for the native rows;
  `RUSTFLAGS="-Ctarget-feature=+simd128" cargo build -p cloak-wasm
  --target wasm32-wasip1 --release` then `cd adapters/go && go run
  ./bench` for the same-day Go-WASM rows (wazero v1.12.0); `cargo
  bench -p wasm-parity` for the criterion rows.
- **Parity status**: the 247-vector parity fixture matches
  `cargo run --example export-vectors -p cloak-core` (freshness-gated
  by diff in CI), and the Go suite redacts every vector byte-identically
  both one-shot and streaming (`crates/cloak-go/parity_test.go`,
  `streaming_test.go`) — as does the C harness against the same
  staticlib (`crates/cloak-ffi/charness/parity.c`, 247/247); the perf
  numbers above are therefore measured on the same matching engine the
  parity suites exercise.
- **Bench**: `crates/cloak-go/bench/main.go` — line-for-line port of
  `adapters/go/bench/main.go` (same corpus construction, same warmup
  and iteration counts: 100/50 warmup, 50,000 iterations), importing
  the cgo binding instead of the wazero adapter.
- **Corpus**: byte-identical to the E1–E6 bench corpora — ~60 log
  lines, 22 matches per iteration (20 `email` + 1 GitHub token + 1 AWS
  access key), 4,064 B total. Match-dense workload.
- **Environment**: single-threaded, engine created once, session per
  iteration (streaming rows), digest key via env
  (`CLOAK_DIGEST_KEY=bench-key`, set with `os.Setenv` — the native
  binding has no WithEnv), release staticlib (a debug archive would be
  a visible path mistake: the default LDFLAGS point at
  `target/release`).
- **Same-day comparison rows**: `adapters/go/bench/main.go` against a
  `cloak_wasm.wasm` rebuilt from the same tree (wazero v1.12.0, Go
  1.27.3 — same Go toolchain as the committed E4 receipt), and `cargo
  bench -p wasm-parity` for the native/wasmtime criterion rows — all
  measured minutes apart on AC power with the machine otherwise quiet.
- **Battery warning**: on battery power this machine class measures
  raw native core at 2× slow with 5× run-to-run swings (see the E5
  receipt) — receipts must be measured on AC power.
