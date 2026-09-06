# Roadmap — cloak

> Prev: [performance](04-performance.md) · Next: [embedding](06-embedding.md) · Derived from [issue #2](https://github.com/silverwalls-labs/cloak/issues/2)

## v0.1 — session plan

Eight implementation sessions, each sized **2–3 h**, each ending in a shippable,
CI-green state. Sessions are strictly ordered (each builds on the previous).

### S1 — Workspace skeleton + core types
Workspace (`crates/cloak-core`, `crates/cloak-cli`); staged CI per
[03 §CI staging](03-guarantee-and-testing.md#ci-staging-all-blocking-at-their-stage)
— smoke stage (fmt, clippy `-D warnings`, build, unit, golden e2e pipe test via
`assert_cmd`) on the 3-target matrix, full stage scaffolded incl. `cargo-deny`
(advisories/licenses/dupes); test-tier layout
(`#[cfg(test)]` / `core/tests/` / `cli/tests/` / `fuzz/`); core types
(`Engine`, `Session`, `RuleId`, `MatchEvent`, `Stats`); redaction writer with
`[CLOAK:<rule>:<digest4>]` tag + keyed BLAKE3 digest (env key, ephemeral fallback).
Decide & record the deliberately-open stack choices (arg parsing, error crates,
CI provider, MSRV — [01-architecture](01-architecture.md#deliberately-left-open--decided-in-s1));
keep the core API binding-shaped ([06-embedding](06-embedding.md#milestone-placement--session-split)).
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
boundary-split variants. Digest-stability goldens committed (correlation promise:
same input + key ⇒ same tag across releases).
**Done when:** catalog in [02-rules.md](02-rules.md) fully implemented; all vectors
green through engine *and* reference; FP suite (trace IDs, order numbers, base64
payloads, bare 10-digit strings) produces zero matches.

### S5 — Config + CLI surface
Serde-first config structs; TOML frontend; per-rule `enabled`; digest-key env
indirection; CLI: `--config`, file args, `--stats-format {text,json}`; stderr
end-of-stream per-rule counts; exit codes. **Full e2e suite** (`cloak-cli/tests/`,
`assert_cmd`): pipe, file args, config loading, stats text + JSON, exit codes;
I/O robustness cases (SIGPIPE/broken pipe → clean exit, closed stdout, huge line);
`insta` snapshots of stats JSON, `--help`, error messages.
**Done when:** `cloak --config cloak.toml < in > out` honors enable/disable; stats
match planted-vector counts exactly (asserted end-to-end through the binary);
config fuzz target parses arbitrary TOML without panic.

### S6 — Guarantee hardening
cargo-fuzz targets (`fuzz_engine_stream`, `fuzz_pem_state`, `fuzz_config`);
invalid-UTF-8/binary corpora; differential suite (engine ≡ reference) wired into CI
on all three targets; fuzz smoke + corpus replay as PR gates; nightly stage
(extended fuzz ≥ 1 h/target, `cargo-mutants` over cloak-core); thread-share test
(Engine across threads); coverage reporting (`cargo-llvm-cov`) published per PR.
**Done when:** all [03-guarantee-and-testing.md](03-guarantee-and-testing.md) CI
gates exist and are blocking; initial fuzz session (≥ 1 h/target locally) finds
nothing outstanding.

### S7 — Performance
Criterion suites (`push` end-to-end, prefilter-only, chunk-size sweep); five
reference corpora ([04](04-performance.md#reference-corpora-committed-versioned));
scalar-vs-engine receipts table (first entry in `docs/benchmarks/`); ≥ 500 MB/s
clean-path CI gate + 10 % regression gate against stored baselines; nightly soak
(tens of GB looped through one `Session`, flat-RSS assertion).
**Done when:** floor gate green on CI; receipts committed; numbers in README are
benchmark-traceable.

### S8 — Docs, packaging, v0.1.0
README rewrite (what/why, 3-layer pipeline diagram, quickstart, guarantee statement
linking [03 §"What the guarantee is NOT"](03-guarantee-and-testing.md#what-the-guarantee-is-not));
examples: pipe usage + k8s sidecar/log-processor snippet; API docs pass
(`#![warn(missing_docs)]` on `cloak-core`); **SECURITY.md** (vulnerability
disclosure policy — table stakes for a security tool); CHANGELOG; `v0.1.0` tag +
release; close issue #2 with pointer to docs.
**Done when:** `v0.1.0` tagged; all [00-scope.md acceptance criteria](00-scope.md#acceptance-criteria-v01-is-done-when) checked.

## Follow-ups ledger

Deliberately deferred in scoping — recorded so nothing is lost. Each becomes an
issue when its milestone opens.

| # | Follow-up | Origin of deferral | Earliest milestone |
|---|---|---|---|
| F1 | **Embedding milestone** — layer-1 apps are Rust/Go/Node/Python. Split into 8 sessions (E1–E8), **strictly one artifact per session**: WASM build (E1) → per-host adapters Node/Python/Go (E2–E4) → dedicated native bindings pyo3 (E5) / napi-rs (E6), each gated on receipts vs its host's WASM baseline → C ABI (E7) + cgo (E8) on demand. Full design: [06-embedding.md](06-embedding.md#milestone-placement--session-split) | Integration scoping: CLI first; later passes confirmed app languages, WASM-first rollout, one-task-per-artifact split | v0.2 |
| F2 | ~~WASM build~~ — **folded into F1 as sessions E1–E2** (WASM is the first embedding wave, not a side quest) | Superseded 2026-09-06 | v0.2 |
| F3 | **YAML + JSON config frontends + `cloak config convert`** — serde-first core makes this cheap; YAML crate choice open (`serde_yaml` unmaintained) | Config scoping: TOML-only v0.1 | v0.2 |
| F4 | **Entropy detector, opt-in, off by default** — catches unknown secret shapes at FP cost | Precision scoping: recall-first tuned rules | v0.2+ |
| F5 | **Configurable redaction templates per rule** (mask-only, custom formats) | Redaction scoping: fixed tag+digest v0.1 | v0.2 |
| F6 | **Prometheus / OTel metrics export** — "aws-keys redacted today" as an alertable signal | Telemetry scoping: stderr+JSON v0.1 | Alloy milestone |
| F7 | **Hand-rolled SIMD kernels** (`std::simd`/intrinsics, feature-gated nightly) behind `Scanner` trait — ships only with [receipts](04-performance.md#the-receipts-protocol-simd-powered-proven); **Miri + sanitizers become blocking gates** when this unsafe lands ([03 §deferred](03-guarantee-and-testing.md#deferred-with-triggers-recorded-not-forgotten)) | SIMD scoping: crates first, kernels with benchmarks later | v0.3 |
| F8 | **Grafana Alloy integration** (via F1/F2 boundary) + Grafana stack docs | Deployment layer 3 | post-embedding |
| F9 | **k8s log-processor packaging** — container image, DaemonSet/sidecar manifests | Deployment layer 2 hardening | v0.2 |
| F10 | **Match-heavy throughput gate** (v0.1 tracks, doesn't gate) | Perf scoping | v0.2 |
| F11 | **Escaped-content decode layer, opt-in** — JSON-string unescape pass (later: base64 spans) so multi-line/escaped-char patterns (PEM!) match inside structured log fields. Must preserve the guarantee (decode is a defined transform, not a heuristic) and byte-exact passthrough of non-matching input | Full-setup review 2026-09-06: JSON logs are the norm in the k8s/Grafana stack, PEM-in-JSON is missed by byte patterns ([03 §threat model](03-guarantee-and-testing.md#threat-model)) | v0.2+ |

## Versioning & policy

- SemVer, `0.x`: minor bumps may break API; rule **ids** are stable from v0.1
  (renames are breaking even in `0.x` — they're config/stats/tag surface).
- New rules land in minor versions, on by default only if FP risk ≤ Low; otherwise
  off by default until a major/minor with release-note callout.
- MIT license (existing `LICENSE`).
