# Roadmap — cloak

> Prev: [performance](04-performance.md) · Derived from [issue #2](https://github.com/silverwalls-labs/cloak/issues/2)

## v0.1 — session plan

Eight implementation sessions, each sized **2–3 h**, each ending in a shippable,
CI-green state. Sessions are strictly ordered (each builds on the previous).

### S1 — Workspace skeleton + core types
Workspace (`crates/cloak-core`, `crates/cloak-cli`); CI matrix (linux x86-64,
linux aarch64, macos aarch64: fmt, clippy `-D warnings`, test, doc); core types
(`Engine`, `Session`, `RuleId`, `MatchEvent`, `Stats`); redaction writer with
`[CLOAK:<rule>:<digest4>]` tag + keyed BLAKE3 digest (env key, ephemeral fallback).
**Done when:** `app | cloak` pipes stdin→stdout byte-identical through full engine
plumbing (zero rules compiled in); CI green on all targets.

### S2 — Matching engine v1 (single buffer)
`Scanner` trait; `AhoCorasickScanner` (prefilter) + `regex-automata` confirm step;
overlap resolution (longest-leftmost); `ScalarScanner` naive reference; first rules:
`github-token`, `gitlab-token`, `npm-token` (simplest anchored) with vector suites.
**Done when:** single-buffer redaction works end-to-end; engine ≡ reference on all
vectors; unit tests green.

### S3 — Streaming + carry-over
Bounded carry-over window (`W` from compiled ruleset); `Session::push`/`finish`
streaming semantics; stateful PEM detector (`pem-private-key`) with bail-out.
Proptest: chunk-boundary invariant (split anywhere ⇒ identical output), passthrough,
idempotence, bounded memory.
**Done when:** guarantee mechanics proven — 1-byte-chunk streaming of every vector
corpus matches whole-buffer output; PEM spanning N chunks caught.

### S4 — Full v0.1 ruleset
Remaining secret rules (`aws-access-key`, `aws-secret-key`, `gcp-api-key`,
`azure-style-token`, `pypi-token`, `jwt`, `connection-string`) + PII rules
(`email`, `ipv4`, `ipv6`, `credit-card` with Luhn, `phone-intl` — `+`-anchored
only). Positive/negative vector suites per rule, incl. binary-embedded and
boundary-split variants.
**Done when:** catalog in [02-rules.md](02-rules.md) fully implemented; all vectors
green through engine *and* reference; FP suite (trace IDs, order numbers, base64
payloads, bare 10-digit strings) produces zero matches.

### S5 — Config + CLI surface
Serde-first config structs; TOML frontend; per-rule `enabled`; digest-key env
indirection; CLI: `--config`, file args, `--stats-format {text,json}`; stderr
end-of-stream per-rule counts; exit codes.
**Done when:** `cloak --config cloak.toml < in > out` honors enable/disable; stats
match planted-vector counts exactly; config fuzz target parses arbitrary TOML
without panic.

### S6 — Guarantee hardening
cargo-fuzz targets (`fuzz_engine_stream`, `fuzz_pem_state`, `fuzz_config`);
invalid-UTF-8/binary corpora; differential suite (engine ≡ reference) wired into CI
on all three targets; fuzz smoke + corpus replay as CI gates.
**Done when:** all [03-guarantee-and-testing.md](03-guarantee-and-testing.md) CI
gates exist and are blocking; initial fuzz session (≥ 1 h/target locally) finds
nothing outstanding.

### S7 — Performance
Criterion suites (`push` end-to-end, prefilter-only, chunk-size sweep); five
reference corpora ([04](04-performance.md#reference-corpora-committed-versioned));
scalar-vs-engine receipts table (first entry in `docs/benchmarks/`); ≥ 500 MB/s
clean-path CI gate + 10 % regression gate against stored baselines.
**Done when:** floor gate green on CI; receipts committed; numbers in README are
benchmark-traceable.

### S8 — Docs, packaging, v0.1.0
README rewrite (what/why, 3-layer pipeline diagram, quickstart, guarantee statement
linking [03 §"What the guarantee is NOT"](03-guarantee-and-testing.md#what-the-guarantee-is-not));
examples: pipe usage + k8s sidecar/log-processor snippet; API docs pass
(`#![warn(missing_docs)]` on `cloak-core`); CHANGELOG; `v0.1.0` tag + release;
close issue #2 with pointer to docs.
**Done when:** `v0.1.0` tagged; all [00-scope.md acceptance criteria](00-scope.md#acceptance-criteria-v01-is-done-when) checked.

## Follow-ups ledger

Deliberately deferred in scoping — recorded so nothing is lost. Each becomes an
issue when its milestone opens.

| # | Follow-up | Origin of deferral | Earliest milestone |
|---|---|---|---|
| F1 | **FFI (C ABI) cdylib** — Go/cgo embedding for apps & Alloy | Integration scoping: CLI first | v0.2 |
| F2 | **WASM build** — sandboxed pipeline embedding | Same | v0.2+ |
| F3 | **YAML + JSON config frontends + `cloak config convert`** — serde-first core makes this cheap; YAML crate choice open (`serde_yaml` unmaintained) | Config scoping: TOML-only v0.1 | v0.2 |
| F4 | **Entropy detector, opt-in, off by default** — catches unknown secret shapes at FP cost | Precision scoping: recall-first tuned rules | v0.2+ |
| F5 | **Configurable redaction templates per rule** (mask-only, custom formats) | Redaction scoping: fixed tag+digest v0.1 | v0.2 |
| F6 | **Prometheus / OTel metrics export** — "aws-keys redacted today" as an alertable signal | Telemetry scoping: stderr+JSON v0.1 | Alloy milestone |
| F7 | **Hand-rolled SIMD kernels** (`std::simd`/intrinsics, feature-gated nightly) behind `Scanner` trait — ships only with [receipts](04-performance.md#the-receipts-protocol-simd-powered-proven) | SIMD scoping: crates first, kernels with benchmarks later | v0.3 |
| F8 | **Grafana Alloy integration** (via F1/F2) + Grafana stack docs | Deployment layer 3 | post-FFI |
| F9 | **k8s log-processor packaging** — container image, DaemonSet/sidecar manifests | Deployment layer 2 hardening | v0.2 |
| F10 | **Match-heavy throughput gate** (v0.1 tracks, doesn't gate) | Perf scoping | v0.2 |

## Versioning & policy

- SemVer, `0.x`: minor bumps may break API; rule **ids** are stable from v0.1
  (renames are breaking even in `0.x` — they're config/stats/tag surface).
- New rules land in minor versions, on by default only if FP risk ≤ Low; otherwise
  off by default until a major/minor with release-note callout.
- MIT license (existing `LICENSE`).
