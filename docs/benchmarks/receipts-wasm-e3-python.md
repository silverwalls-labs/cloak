# Performance Receipts — WASM Python adapter (E3)

> Generated: 2026-10-18
> rustc: 1.98.1
> WASM target: wasm32-wasip1, RUSTFLAGS="-Ctarget-feature=+simd128"
> Host runtime: wasmtime-py 49.0.0 (CPython 3.13.15)
> Host CPU: Apple Silicon (M1, aarch64-apple-darwin)
> Corpus: mixed log lines (4,064 B ≈ 4.0 KiB, 2 embedded secrets)
>
> **E3 acceptance** (docs/06-embedding.md) — the receipts baseline
> E5 (cloak-py, pyo3) must beat.

## Python WASM throughput

The same corpus as `receipts-wasm-e1.md` (log-like text with embedded
GitHub token + AWS access key), processed through the `cloak-python`
adapter against the shared `cloak_wasm.wasm` artifact. Measured by
`adapters/python/bench/throughput.py` (50,000 iterations after warmup).
Figures are stable run-to-run within ~10% on a quiet machine; treat
smaller deltas as noise.

| Path | Throughput (MiB/s) | Time/iter (µs) | Notes |
|---|---|---|---|
| Python WASM (one-shot `redact`) | **36** | 108 | wasmtime-py, ctypes FFI |
| Python WASM (streaming, 1 KiB chunks) | **17** | 230 | session per iteration |
| Python WASM (streaming, 256 B chunks) | **6** | 648 | per-call overhead dominates |
| Node WASM (one-shot), same machine | 64 | 61 | `adapters/node/bench/throughput.ts`, Node 24.19 |
| Node WASM (streaming 1 KiB), same machine | 40 | 98 | |
| Rust wasmtime (reference, E1) | 129 | 30.1 | `receipts-wasm-e1.md` |
| Native cloak-core (reference, E1) | 146 | 26.5 | `receipts-wasm-e1.md` |

## Host overhead

The WASM module does the same ~30 µs of scanning work per 4 KiB
regardless of host; everything above that is host-binding overhead.
For Python that overhead is ctypes FFI: each boundary crossing
(alloc, call, read result, free, dealloc) costs single-digit µs, and
a one-shot redact makes six of them plus two linear-memory copies.

The bridge already avoids the worst of it: wasmtime-py's stock
`Func.__call__` re-fetches the function type through FFI on every
invocation (~20 µs/call); `cloak_python._bridge._FastFunc` resolves the
i32-only signature once and drives `wasmtime_func_call` directly with
pre-allocated ctypes buffers, which is worth ~4× on this corpus (one-shot
was ~620 µs/op on the stock path). The remaining gap to the Rust host
(~3.5×) and Node (~2×) is the irreducible ctypes floor — exactly the
overhead E5's native pyo3 binding exists to remove. Small chunks magnify
it: at 256 B the per-push crossings outweigh the scanning work, which is
why the streaming rows fall off faster than Node's.

## Methodology

- **Bench**: `adapters/python/bench/throughput.py` — line-for-line port
  of `adapters/node/bench/throughput.ts` (same corpus construction, same
  warmup and iteration counts: 100/50 warmup, 50,000 iterations).
- **Corpus**: ~60 clean log lines interspersed with 2 secrets (GitHub
  token, AWS access key). Total 4,064 B (~4.0 KiB) — identical to the
  E1/E2 corpora.
- **Environment**: single-threaded, engine created once, session per
  iteration, digest key via WASI env (`CLOAK_DIGEST_KEY=bench-key`).
- **Node comparison rows**: measured on the same machine and artifact
  immediately before the Python runs (Node 24.19, `node:wasi` preview1).
- **Rust/native rows**: quoted from `receipts-wasm-e1.md` (criterion,
  same corpus, same machine class) — not re-measured here.
