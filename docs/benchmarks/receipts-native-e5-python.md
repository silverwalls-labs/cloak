# Performance Receipts — cloak-py native binding (E5)

> Generated: 2026-10-27
> rustc: 1.98.1
> cloak-py: pyo3 0.30.1 (abi3-py313), maturin 1.15.0, release profile
> Host: CPython 3.13.15, Apple Silicon (M1, aarch64-apple-darwin), AC power
> Corpus: mixed log lines (4,064 B ≈ 4.0 KiB, 22 matches: 2 secrets + 20 email-bearing lines)
>
> **E5 ship gate** (docs/06-embedding.md): cloak-py must beat the
> WASM-in-Python path (E3 baseline) on the same corpus — cleared on
> every row, against both the committed E3 receipt and a stronger
> same-day re-measurement.

## Python native vs WASM throughput

Same corpus and harness as `receipts-wasm-e3-python.md`
(`crates/cloak-py/bench/throughput.py` is a line-for-line port of
`adapters/python/bench/throughput.py`: 100/50 warmup, 50,000
iterations). All rows below were measured back-to-back on the same
machine on the same day — the E3 and Rust rows are *re-measurements*,
not quotes — because this class of machine throttles hard on battery
(a first attempt on battery power measured even raw native cloak-core
at half speed). The committed E3 receipt rows are listed for
traceability.

| Path | Throughput (MiB/s) | Time/iter (µs) | vs E3 same-day |
|---|---|---|---|
| **cloak-py (one-shot `redact`)** | **149** | 26.1 | **2.7×** |
| **cloak-py (streaming, 1 KiB chunks)** | **87** | 44.4 | **3.6×** |
| **cloak-py (streaming, 256 B chunks)** | **36** | 108.7 | **4.1×** |
| Python WASM (one-shot), same day | 56 | 69.7 | baseline |
| Python WASM (streaming, 1 KiB), same day | 24.5 | 158.2 | baseline |
| Python WASM (streaming, 256 B), same day | 8.8 | 439.2 | baseline |
| Python WASM, committed E3 receipt (2026-10-23) | 36 / 17 / 6 | 109 / 234 / 673 | reference |
| Rust wasmtime (same day, fresh artifact) | 89 | 43.6 | reference |
| Native cloak-core (criterion, same day) | 154 | 25.1 | reference |

Run-to-run stability: a second cloak-py pass measured 154 / 91 / 38
MiB/s — within ~5%; treat deltas smaller than that as noise.

## Host overhead

The native one-shot sits at 25–26 µs/op against criterion's 25.1 µs
for raw `cloak-core` on the identical workload — **the pyo3 boundary
costs ≈ 0–1 µs per call** (one borrowed `&[u8]` in, one `bytes` + one
stats dict out, GIL detached for the scan). This is the ctypes-floor removal E5 existed for: the E3 bridge pays
~26 µs of total host-path overhead per one-shot — ctypes marshalling
plus linear-memory copies *on top of* the WASM runtime itself (69.7 µs
Python-WASM vs the 43.6 µs Rust-wasmtime row, which already contains
the same runtime) — while the native module pays effectively nothing
beyond the µs-scale pyo3 boundary.

Small chunks still magnify per-call cost — at 256 B the Python-layer
wrapper plus boundary work (~1.6 µs × 16 pushes) and the carry-over
rescans dominate — but the slope is far flatter than ctypes: cloak-py
loses 4.2× from one-shot to 256 B chunks, the WASM path loses 7.9×.

The GIL is released for every scan (`Python::detach`), so these figures
are per-thread and scans from multiple threads run in parallel rather
than serializing at the boundary. What is verified is concurrent
*correctness*, not throughput (`tests/test_threading.py`: byte-identical
output across a shared engine, session hand-off across threads, clean
borrow-check refusal of concurrent same-session pushes) — no
multi-threaded speedup figure is claimed here.

## Methodology

- **Source revision**: benches ran on the tree of `99c2073` (the commit
  introducing this receipt) — single-threaded, CPU-state sensitive,
  see the battery warning below.
- **Build commands**: `cd crates/cloak-py && uv sync --locked` (maturin
  release build of `cloak_py._native`, per `[tool.maturin]
  profile = "release"`), then `uv run python bench/throughput.py` for
  the native rows; `cargo build -p cloak-wasm --target wasm32-wasip1
  --release` then `adapters/python/bench/throughput.py` for the
  same-day Python-WASM rows (wasmtime-py 50.0.1); `cargo bench -p
  wasm-parity` for the criterion rows.
- **Parity status**: the 247-vector parity fixture matches
  `cargo run --example export-vectors -p cloak-core` (freshness-gated
  by diff in CI), and the pytest suite redacts every vector
  byte-identically both one-shot and streaming (`crates/cloak-py/
  tests/test_parity.py`, `test_streaming.py`); the perf numbers above
  are therefore measured on the same matching engine the parity suite
  exercises.
- **Bench**: `crates/cloak-py/bench/throughput.py` — line-for-line
  port of `adapters/python/bench/throughput.py` (same corpus
  construction, same warmup and iteration counts: 100/50 warmup,
  50,000 iterations), importing `cloak_py` instead of `cloak_python`.
- **Corpus**: byte-identical to the E1/E2/E3/E4 bench corpora —
  ~60 log lines, 22 matches per iteration (20 `email` + 1 GitHub
  token + 1 AWS access key), 4,064 B total. Match-dense workload.
- **Environment**: single-threaded, engine created once, session per
  iteration (streaming rows), digest key via env
  (`CLOAK_DIGEST_KEY=bench-key`), release build (`tool.maturin
  profile = "release"` — `uv sync` can never install a debug build).
- **Same-day comparison rows**: `adapters/python/bench/throughput.py`
  against a `cloak_wasm.wasm` rebuilt from the same tree
  (wasmtime-py 50.0.1), and `cargo bench -p wasm-parity` for the
  native/wasmtime criterion rows — all measured minutes apart on AC
  power with the machine otherwise quiet.
- **Battery warning**: on battery power this machine measured raw
  native core at 50 µs/op (2× slow) with 5× run-to-run swings —
  receipts must be measured on AC power.
