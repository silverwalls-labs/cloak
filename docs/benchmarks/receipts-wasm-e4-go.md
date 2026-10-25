# Performance Receipts — WASM Go adapter (E4)

> Generated: 2026-10-25
> rustc: 1.98.1
> WASM target: wasm32-wasip1, RUSTFLAGS="-Ctarget-feature=+simd128"
> Host runtime: wazero v1.12.0 (Go 1.27.3, pure Go — no cgo)
> Host CPU: Apple Silicon (M1, aarch64-apple-darwin)
> Corpus: mixed log lines (4,064 B ≈ 4.0 KiB, 22 matches: 2 secrets + 20 email-bearing lines)
>
> **E4 acceptance** (docs/06-embedding.md) — the receipts baseline
> E8 (cloak-go, cgo over cloak-ffi) must beat.

## Go WASM throughput

The same corpus as `receipts-wasm-e1.md` (log-like text with embedded
GitHub token + AWS access key), processed through the Go adapter
against the shared `cloak_wasm.wasm` artifact. Measured by
`adapters/go/bench/main.go` (50,000 iterations after warmup). Figures
are the median of three runs, stable within ~10% on a quiet machine;
treat smaller deltas as noise.

| Path | Throughput (MiB/s) | Time/iter (µs) | Notes |
|---|---|---|---|
| Go WASM (one-shot `Redact`) | **56** | 69 | wazero compiling runtime |
| Go WASM (streaming, 1 KiB chunks) | **34** | 114 | session per iteration |
| Go WASM (streaming, 256 B chunks) | **14** | 271 | per-call overhead dominates |
| Node WASM (one-shot), same machine | 64 | 61 | `receipts-wasm-e3-python.md`, Node 24.19 |
| Node WASM (streaming 1 KiB), same machine | 40 | 98 | |
| Python WASM (one-shot), same machine | 36 | 109 | `receipts-wasm-e3-python.md`, wasmtime-py 50 |
| Rust wasmtime (reference, E1) | 129 | 30.1 | `receipts-wasm-e1.md` |
| Native cloak-core (reference, E1) | 146 | 26.5 | `receipts-wasm-e1.md` |

## Host overhead

The WASM module does the same ~30 µs of scanning work per 4 KiB
regardless of host; everything above that is host-binding overhead.
Go's is the smallest of the three adapter hosts in kind: wazero is
pure Go, so a boundary crossing is a Go function call into
ahead-of-time-compiled machine code — no FFI marshaling layer at all.
That puts Go essentially at Node's level (~15% apart; both are
"compiled WASM + thin host-native glue") and ~1.6× ahead of Python's
ctypes floor.

The remaining ~2.3× gap to the Rust wasmtime host is mostly codegen
quality — wazero's compiler optimizes less aggressively than
wasmtime's Cranelift on this SIMD-heavy scan loop — plus a small
per-call cost (`api.Function.Call` allocates its parameter stack on
every call; `CallWithStack` with a reused buffer is the available fast
path, the Go analog of the Python bridge's `_FastFunc`). The small-
chunk row shows the usual shape: at 256 B the per-push crossings and
session setup outweigh the scanning work. Closing the codegen gap is
exactly what E8's native cgo binding exists for — this table is the
baseline it must beat.

## Methodology

- **Bench**: `adapters/go/bench/main.go` — line-for-line port of
  `adapters/node/bench/throughput.ts` (same corpus construction, same
  warmup and iteration counts: 100/50 warmup, 50,000 iterations).
- **Corpus**: ~60 log lines — 20 request lines each carrying
  `user=alice@example.com` (the `email` rule matches every one), plus
  1 GitHub token and 1 AWS access key: **22 matches per iteration**,
  a match-dense workload. Total 4,064 B (~4.0 KiB) — byte-identical
  to the E1/E2/E3 bench corpora.
- **Environment**: single-threaded, engine created once, session per
  iteration, digest key via WASI env (`CLOAK_DIGEST_KEY=bench-key`).
- **Node/Python comparison rows**: quoted from
  `receipts-wasm-e3-python.md` (same machine, same artifact build
  recipe, measured 2026-10-23) — not re-measured here.
- **Rust/native rows**: quoted from `receipts-wasm-e1.md` (criterion,
  same corpus, same machine class) — not re-measured here.
