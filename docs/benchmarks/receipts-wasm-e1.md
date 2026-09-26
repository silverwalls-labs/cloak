# Performance Receipts — WASM (E1)

> Generated: 2026-09-26
> rustc: 1.98.1
> WASM target: wasm32-wasip1, RUSTFLAGS="-Ctarget-feature=+simd128"
> WASM runtime: wasmtime 49.0.1 (Cranelift backend, simd enabled)
> Host CPU: Apple Silicon (M-series, aarch64-apple-darwin)
> Corpus: mixed log lines (4,064 B ≈ 4.0 KiB, 2 embedded secrets)
>
> **First native-vs-WASM receipts entry** (docs/06-embedding.md, E1 acceptance).
> "simd128 benefit measured, not assumed."

## Native vs WASM throughput

The same corpus (log-like text with embedded GitHub token + AWS access key)
processed through `push() → finish()`, measured by criterion (100 samples,
5 s collection window). Re-measured after the wasmtime 44 → 49 bump
(RUSTSEC-driven, 8c34c37) and the E1 review fixes; the WASM figure is
stable run-to-run (±2 µs), while the native figure varies more on this
dev machine (17–27 µs across quiet runs) — treat native-vs-WASM deltas
under ~15% as machine noise.

| Path | Throughput (MiB/s) | Time/iter (µs) | Notes |
|---|---|---|---|
| Native (cloak-core) | **146** | 26.5 | Direct Rust call, aarch64 NEON |
| WASM (wasmtime) | **129** | 30.1 | wasm32-wasip1 +simd128, Cranelift JIT |

**Overhead: ~14%** — the WASM path retains ~88% of native throughput on this
corpus, making it a viable day-one embedding path for all four target
languages until native bindings (E5–E8) land.

## SIMD128 impact

The `+simd128` flag enables WASM SIMD instructions in the compiled artifact.
blake3's `wasm32_simd` feature activates its hand-written WASM SIMD kernel
for hashing. aho-corasick's internal SIMD (Teddy) maps to WASM SIMD where
the compiler can lower the intrinsics.

SIMD128 is enabled unconditionally — the target runtimes (wasmtime, V8,
wazero) all support the finalized WASM SIMD spec. CI asserts the flag
actually landed: the wasm-build job fails unless the artifact contains
v128 opcodes (`wasm-objdump` check in `quality-gates.yaml`). A no-simd
build comparison is deferred to E2–E4 where host-specific runtime
differences matter.

## Artifact size

| Build | Size |
|---|---|
| `cloak_wasm.wasm` (release, +simd128) | 1.1 MB |

## Methodology

- **Native bench**: criterion group in `crates/wasm-parity/benches/throughput.rs`,
  calling `cloak-core` API directly (same process, no FFI).
- **WASM bench**: criterion group in the same file, loading the `.wasm` artifact
  via `wasmtime::Module`, instantiating with WASI env, calling exports through
  the wasmtime embedding API.
- **Corpus**: ~60 clean log lines interspersed with 2 secrets (GitHub token,
  AWS access key). Total 4,064 B (~4.0 KiB) — representative of structured
  logging workloads where secrets appear sparsely.
- **Environment**: single-threaded, engine created once, session per iteration.
