# Embedding & Language Bindings — cloak

> Prev: [roadmap](05-roadmap.md) · This doc designs the **v0.2 embedding milestone** (agreed 2026-09-06, scoping passes 2–6)

## Why this doc exists

Deployment layer 1 ([scope](00-scope.md#who-runs-it-and-where)) is **not** just
"wrap your process in a pipe." The target applications are written in
**Rust, Go, Node.js, and Python**, and cloak must embed *directly* in them — a
hook between code and stdout/stderr, in-process, no subprocess required.

v0.1 ships the CLI (pipe form covers layer 1 as an interim), but embedding is a
first-class pillar of the product, not a footnote. This doc fixes the design so
the v0.2 milestone is derivable.

## Principle: one core, many frontends

```
                        ┌──────────────────┐
                        │    cloak-core    │  the only place logic lives
                        └────────┬─────────┘
        ┌──────────┬─────────────┼──────────────┬─────────────┐
   Rust apps   cloak-ffi     cloak-py      cloak-node     cloak-wasm
   (crate,     (C ABI        (pyo3 +       (napi-rs,      (wasm32,
    direct)     cdylib)       maturin)      npm prebuilt)  sandboxed hosts)
                   │
               cloak-go (cgo wrapper module over cloak-ffi)
```

| Language | First coverage (WASM wave) | Native upgrade (perf wave) | Distribution |
|---|---|---|---|
| Rust | `cloak-core` directly (v0.1) | — already native | crates.io |
| Go | `cloak-wasm` via **wazero** (pure Go, no cgo) | `cloak-go`: cgo over `cloak-ffi` C ABI | Go module |
| Python | `cloak-wasm` via **wasmtime-py** | `cloak-py`: **pyo3** + maturin, abi3 wheels (one per platform, not per Python version) | PyPI |
| Node.js | `cloak-wasm` via built-in WebAssembly/WASI | `cloak-node`: napi-rs, prebuilt `.node` | npm |
| Anything else | `cloak-wasm` via any WASM runtime | `cloak-ffi` C ABI + header (ctypes/cffi/FFI-of-choice) | release artifacts |
| Sandboxed pipelines | `cloak-wasm` natively | — | release artifacts |

## Rollout strategy: WASM first, native second

Agreed 2026-09-06 (third scoping pass):

1. **`cloak-wasm` ships first** — one portable artifact gives day-one embedding in
   all four app languages plus sandboxed pipelines. No per-language build matrix,
   no cgo, no wheel/npm infrastructure yet.
2. **Native bindings follow, one dedicated session each, for performance** —
   pyo3 and napi-rs bind `cloak-core` directly (no WASM runtime overhead, no
   linear-memory copies, real host types, GIL release / event-loop awareness).
3. **C ABI + cgo last, on demand** — wazero already covers Go without cgo pain;
   `cloak-ffi`/`cloak-go` land when Go-native throughput is needed or the Alloy
   integration (F8) requires that boundary.

The [receipts protocol](04-performance.md#the-receipts-protocol-simd-powered-proven)
extends here: **each native binding must publish benchmarks vs the WASM path in its
own language** — a native binding that doesn't beat WASM-in-that-host doesn't ship.
WASM perf note: `simd128` is enabled at build; whether the matching crates use it is
measured, not assumed — the E1 receipts entry records native-vs-WASM throughput.

## API parity contract

Every binding exposes the **same conceptual API** as the core
([architecture](01-architecture.md#core-api-sketch)) — bytes in, bytes out:

```
Engine(config) → engine            # compile ruleset once, reuse
engine.session() → session         # per-stream state, cheap
session.push(bytes) → bytes        # may withhold carry-over
session.finish() → (bytes, stats)  # flush + per-rule counts
engine.redact(bytes) → bytes       # convenience: whole-buffer, no session
```

Binding rules (non-negotiable, they preserve the [guarantee](03-guarantee-and-testing.md)):

1. **Bytes in, bytes out.** No binding ever converts to host strings internally —
   Python `bytes` not `str`, Node `Buffer` not `string`, Go `[]byte`. Encoding
   damage would break byte-exact passthrough.
2. **No plaintext in events/stats** — same rule as `MatchEvent` in core.
3. **No panic crosses a boundary.** FFI/pyo3/napi layers catch and translate to
   host-native errors (C error codes, Python exceptions, JS errors).
4. **Same vectors everywhere.** The per-rule vector corpora run against every
   binding in CI — a binding that diverges from core output is a guarantee bug.

### The stdout/stderr hook shape

The layer-1 use case each binding ships as a convenience on top of `session`:
wrap a writer/stream so everything flowing to it is redacted
(Python: file-like wrapper / logging handler; Node: `Transform` stream;
Go: `io.Writer` wrapper; Rust: `Write` wrapper). Hooks are thin sugar — all
correctness lives in core.

## C ABI design constraints (`cloak-ffi`)

- `cloak_engine_new(config_toml, len, err_out)` / `cloak_engine_free`,
  `cloak_session_new` / `cloak_session_push(in, in_len, out_cb)` /
  `cloak_session_finish` — session lifecycle mirrors core exactly.
- Output via caller-provided callback or cloak-allocated buffer + `cloak_buf_free`
  (decided at implementation; ownership must be single-owner and documented in the
  header).
- Thread-safety contract explicit: `Engine` shareable across threads, `Session` is
  not (matches core).
- ABI versioned (`cloak_abi_version()`); `cdylib` + generated header (cbindgen).

## Versioning & CI

- Binding crates/packages are **version-locked to core** (same version number);
  a core bump republishes all bindings.
- CI additions at the embedding milestone: wheel/npm-prebuild matrices, cgo smoke
  test, parity vector suite per binding. This is real surface — the reason
  embedding is its own milestone and not a v0.1 stowaway.

## Milestone placement & session split

- **v0.1**: CLI only (unchanged). Core API is already binding-shaped
  (bytes in/out, no host types) — S1/S3 must not introduce anything a C ABI or a
  WASM linear-memory interface cannot express.
- **v0.2 = embedding milestone**, split into eight 2–3h sessions — **strictly one
  artifact per session** (same rule as v0.1: each ends CI-green/shippable).
  Supersedes ledger items F1/F2's original framing — see updated
  [ledger](05-roadmap.md#follow-ups-ledger).

Dependency graph (E2–E4 are independent once E1 lands; native sessions depend on
their own host's WASM baseline for receipts):

```
E1 wasm build ─┬─ E2 Node adapter ──── E6 cloak-node (napi-rs)
               ├─ E3 Python adapter ── E5 cloak-py (pyo3)
               └─ E4 Go adapter ────── E8 cloak-go (cgo) ── after E7
                                       E7 cloak-ffi (C ABI, on demand)
```

### E1 — `cloak-wasm` build + buffer ABI
`cloak-wasm` crate exporting a linear-memory API over core (`engine_new(config
ptr/len)`, `session_new`, `push(ptr,len) → (ptr,len)`, `finish`); build
`wasm32-wasip1` with `+simd128`; parity vector runner executing the module
(wasmtime) in CI; first native-vs-WASM receipts entry.
**Done when:** the `.wasm` artifact passes the full vector parity suite + a
chunk-boundary proptest subset; CI builds and gates it.

### E2 — WASM host adapter: Node.js
Thin glue over the E1 artifact via built-in WebAssembly/WASI; `Transform`-stream
stdout/stderr-hook example; per-host parity vectors in CI; "embed cloak today"
docs for Node.
**Done when:** example app redacts through the `.wasm` artifact; Node parity green
in CI.

### E3 — WASM host adapter: Python
Same shape via `wasmtime-py`; file-like wrapper / `logging`-handler hook example;
Python parity vectors in CI; docs.
**Done when:** example app redacts through the same `.wasm`; Python parity green.

### E4 — WASM host adapter: Go
Same shape via `wazero` (pure Go, no cgo); `io.Writer` hook example; Go parity
vectors in CI; docs. This is the supported Go path until E7/E8.
**Done when:** example app redacts through the same `.wasm`; Go parity green.

### E5 — `cloak-py` (pyo3, dedicated) — depends on E3
Native module via pyo3 + maturin; abi3 wheels (linux x86-64/aarch64, macos
aarch64); `bytes` in/out API + file-like wrapper and `logging` handler hooks; GIL
released during scans; wheel CI matrix; parity suite.
**Done when:** wheels install from CI artifacts; parity green; receipts show
`cloak-py` ≥ WASM-in-Python (E3 baseline) — no receipts, no ship.

### E6 — `cloak-node` (napi-rs, dedicated) — depends on E2
Prebuilt `.node` binaries for the three targets; `Buffer` in/out API + `Transform`
stream hook; npm packaging; parity suite.
**Done when:** package installs with prebuilds; parity green; receipts show
`cloak-node` ≥ WASM-in-Node (E2 baseline).

### E7 — `cloak-ffi` (C ABI) — on demand
cbindgen header, single-owner ownership rules, thread-safety contract,
`cloak_abi_version()`, no panic across the boundary. **Unsafe enters here →
Miri/ASAN/LSAN become blocking gates on the FFI boundary tests**
([03 §deferred](03-guarantee-and-testing.md#deferred-with-triggers-recorded-not-forgotten)).
**Trigger:** Go-native throughput need or Alloy integration (F8) start.
**Done when:** header + cdylib published; boundary tests green under sanitizers;
parity via a minimal C harness.

### E8 — `cloak-go` (cgo, dedicated) — depends on E7 + E4
cgo wrapper module over `cloak-ffi` with `io.Writer` hook; parity suite.
**Done when:** parity green; receipts show `cloak-go` ≥ WASM-via-wazero
(E4 baseline).
