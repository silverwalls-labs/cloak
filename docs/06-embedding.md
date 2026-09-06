# Embedding & Language Bindings — cloak

> Prev: [roadmap](05-roadmap.md) · This doc designs the **v0.2 embedding milestone** (agreed 2026-09-06, second scoping pass)

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

| Language | Binding | Mechanism | Distribution |
|---|---|---|---|
| Rust | `cloak-core` | native crate, direct | crates.io |
| Go | `cloak-go` | cgo over the C ABI (`cloak-ffi`) | Go module vendoring `libcloak` |
| Python | `cloak-py` | **pyo3** + maturin, abi3 wheels (one wheel per platform, not per Python version) | PyPI |
| Node.js | `cloak-node` | napi-rs, prebuilt `.node` binaries | npm |
| Anything else | `cloak-ffi` | C ABI + header, via ctypes/cffi/FFI-of-choice | release artifacts |
| Sandboxed pipelines | `cloak-wasm` | wasm32 build of core | release artifacts |

`cloak-ffi` (C ABI) is both the Go path **and** the universal fallback. pyo3 and
napi-rs bind `cloak-core` directly (better ergonomics, real types, GIL/event-loop
awareness) rather than stacking on the C ABI.

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

## Milestone placement

- **v0.1**: CLI only (unchanged). Core API is already binding-shaped
  (bytes in/out, no host types) — S1/S3 must not introduce anything a C ABI
  cannot express.
- **v0.2 = embedding milestone**: `cloak-ffi` + `cloak-go` + `cloak-py` (pyo3) +
  `cloak-node` (napi-rs), parity CI. Supersedes ledger items F1/F2's vague framing —
  see updated [ledger](05-roadmap.md#follow-ups-ledger).
- `cloak-wasm` rides along where cheap; required no later than the Alloy work (F8)
  if the FFI route doesn't fit Alloy's plugin model.
