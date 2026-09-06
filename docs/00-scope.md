# Scope — cloak v0.1

> Status: agreed 2026-09-06 · Source: [issue #2](https://github.com/silverwalls-labs/cloak/issues/2) scoping interview
> Reading order: this file → [architecture](01-architecture.md) → [rules](02-rules.md) → [guarantee & testing](03-guarantee-and-testing.md) → [performance](04-performance.md) → [roadmap](05-roadmap.md) → [embedding](06-embedding.md)

## Problem

Secrets and structured PII leak into logs constantly — from debug prints, serialized
structs, exception messages, misconfigured frameworks. Once a secret reaches the
observability stack (Loki, Grafana, long-term storage) it is effectively published
internally and expensive to purge.

**cloak** is a fast, guarantee-grade redactor that rewrites text streams so that
secrets and structured PII never reach storage.

## Who runs it, and where

cloak is deployed **defense in depth** at three points of the log pipeline:

| Layer | Deployment | Catches |
|-------|------------|---------|
| 1. Application | In-process hook between code and stdout/stderr — apps are written in **Rust, Go, Node.js, and Python**, so cloak embeds natively in all four | Most leaks, at the source |
| 2. Node | Kubernetes log processor (pre-processing) | What layer 1 missed or couldn't see |
| 3. Ingestion | Grafana Alloy / Grafana stack integration | Last line of defense before storage |

A single engine serves all three layers. **v0.1 ships the CLI pipe form**
(`app | cloak | collector`), which covers layers 1–2 via pipe wrappers/sidecars in
the interim. Native embedding — Rust crate, Go (cgo/C ABI), Python (pyo3),
Node.js (napi-rs), WASM — is the **v0.2 embedding milestone**, designed in
[06-embedding.md](06-embedding.md); layer 3 (Alloy) builds on the same boundary.

## What cloak hunts (v0.1)

- **Secrets** — cloud provider keys, VCS/CI tokens, PEM private-key blocks, JWTs,
  connection-string credentials.
- **Structured PII** — emails, IP addresses (v4+v6), credit cards (Luhn-validated),
  phone numbers (anchored international format only).

Full catalog with pattern anchors and precision notes: [02-rules.md](02-rules.md).

**Not hunted:** free-text PII (names, addresses) — that is an NLP problem, not a
pattern problem, and is permanently out of scope for the pattern engine.

## The contract

cloak's headline property is **guaranteed detection, ruleset-relative**:

> If a pattern in the active ruleset appears in the input — including split across
> stream chunks, including inside invalid-UTF-8 data — it **is** matched and redacted.

The guarantee is never "no secret ever leaks." It is "the ruleset is honored,
always." Rules the ruleset doesn't express cannot be guaranteed. Precise statement,
threat model, and the testing that enforces it: [03-guarantee-and-testing.md](03-guarantee-and-testing.md).

Precision stance: **recall-first with tuned rules** — anchored prefixes and
checksums, no heuristic matching. Over-redaction destroys log value, so v0.1 ships
no generic entropy detector (tracked as an opt-in follow-up).

## v0.1 deliverable

A Rust workspace producing:

1. **`cloak-core`** — library: byte-stream engine, built-in ruleset, config types.
2. **`cloak-cli`** — binary: `cloak` reads stdin (or file args), writes redacted
   output to stdout, per-rule counts to stderr (`--stats-format json` for machines).
3. TOML configuration: per-rule enable/disable.
4. Redaction output: typed tag + short deterministic digest — `[CLOAK:aws-key:9f3a]` —
   correlatable without exposure.
5. Test suite proving the guarantee: property tests (chunk-boundary invariant),
   fuzzing, differential testing against a scalar reference implementation.
6. Benchmark suite with a CI-enforced floor: **≥ 500 MB/s single-core** on the
   match-free reference corpus.

## Acceptance criteria (v0.1 is done when…)

- [ ] `app | cloak | collector` redacts every rule in the catalog, streaming, with
      bounded memory.
- [ ] Chunk-boundary property test passes: any split of any corpus produces
      byte-identical output to a whole-buffer scan.
- [ ] Fuzz targets run clean (time-boxed) in CI; invalid UTF-8 and binary input
      have defined, tested behavior.
- [ ] Differential tests: engine output ≡ scalar reference output on all corpora.
- [ ] Criterion benches recorded; clean-path throughput ≥ 500 MB/s single-core;
      scalar-vs-engine comparison published (the "SIMD-powered" receipts).
- [ ] CI green on linux x86-64, linux aarch64, macos aarch64 (stable Rust).
- [ ] README, API docs, pipe + k8s sidecar examples, CHANGELOG, tag `v0.1.0`.

## Non-goals for v0.1

Explicitly out of scope (several are tracked follow-ups — see the
[ledger](05-roadmap.md#follow-ups-ledger)):

- Language bindings & embedding — FFI (C ABI), Go, Python (pyo3), Node.js
  (napi-rs), WASM — designed in [06-embedding.md](06-embedding.md), shipped as the
  v0.2 milestone
- Generic entropy / high-randomness detector
- YAML/JSON config and format conversion
- Per-rule configurable redaction templates
- Prometheus/OTel metrics export
- Hand-rolled SIMD kernels (v0.1 rides SIMD-backed crates)
- Encryption, storage, network I/O, GUI
- Free-text NLP PII (permanent non-goal for this engine)

## Ground rules

- License: MIT. Versioning: SemVer, `0.x` until API stabilizes.
- Stable Rust, edition 2024. No nightly in v0.1.
- Sync I/O — a pipe filter has no need for async.
