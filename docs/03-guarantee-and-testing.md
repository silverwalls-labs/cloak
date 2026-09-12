# The Guarantee & How We Test It — cloak v0.1

> Prev: [rules](02-rules.md) · Next: [performance](04-performance.md)

## The contract, precisely

> **Guaranteed detection, ruleset-relative.**
> For every enabled rule R and every input byte stream S: if a byte sequence in S
> matches R's specification, cloak redacts it — regardless of how S was chunked,
> and regardless of whether S is valid UTF-8.

Formally, the invariant the test suite enforces:

```
∀ corpus S, ∀ chunking C of S:  redact_streaming(S, C) == redact_whole_buffer(S)
∧  redact_whole_buffer(S) == redact_reference(S)
```

where `redact_reference` is the naive scalar implementation
([architecture](01-architecture.md#the-simd-upgrade-path-kept-honest)) — deliberately
slow, obviously correct, the oracle.

## What the guarantee is NOT

Stated here so nobody oversells it (README must link this section):

- **Not** "no secret ever leaks." A secret whose shape no enabled rule expresses
  passes through untouched. The guarantee is ruleset-relative by construction.
- **Not** resistance to encoding transforms — adversarial *or routine*. A secret
  that is base64-wrapped, hex-dumped, or split by the *emitting application* across
  two log records does not match the rule's byte pattern and is not caught. This
  includes the mundane case: **JSON structured logging escapes `\n`**, so a
  multi-line PEM key inside a JSON string field is missed in v0.1 (single-line
  anchored tokens are unaffected — their bytes survive JSON escaping). Opt-in
  decode layer tracked as [ledger F11](05-roadmap.md#follow-ups-ledger). cloak
  guards against accidental leakage, not against an adversary inside the emitting
  process.
- **Not** a substitute for secret rotation. A caught leak is still a leak; cloak
  buys time and containment, not absolution.
- Digests are correlation hints (16 bits, keyed), not commitments.

Defense in depth across the three deployment layers
([scope](00-scope.md#who-runs-it-and-where)) exists precisely because each single
layer is fallible.

## Threat model

| Actor / event | In scope? | Handling |
|---|---|---|
| Developer accidentally logs a secret/PII | ✅ core case | Ruleset match → redact |
| Framework/exception serializer dumps config | ✅ | Same |
| Secret split across stream *chunks* (transport-level) | ✅ guaranteed | Carry-over buffer |
| Secret split across *log records* by the emitter | ❌ | Out of scope (cloak sees two non-matching fragments) |
| Secret transformed by **routine escaping** (JSON-string `\n`, `\"` in structured logs) | ⚠️ partial | Single-line anchored tokens (`AKIA…`, `ghp_…`, `eyJ…`, emails) still match inside JSON strings — their bytes are unchanged. Patterns *containing* escaped chars — multi-line PEM (`\n`), some connection strings — do **not** match in escaped form. Known v0.1 limitation, tracked as [ledger F11](05-roadmap.md#follow-ups-ledger) (opt-in decode layer). |
| Malicious app tries to smuggle a secret past cloak (encoding games) | ❌ | Out of scope; documented |
| Malicious input tries to crash/hang/OOM cloak | ✅ robustness | Bounded memory by design; fuzzing |
| Malicious input tries to make cloak *emit* secret bytes it buffered | ✅ | Carry-over only ever flushed redacted-or-clean; fuzz-asserted |
| Reading digests to recover secrets | ✅ mitigated | Keyed BLAKE3, 16-bit truncation |

## Invalid UTF-8 & binary input: defined behavior

- The engine operates on **bytes**; it never decodes, validates, or "fixes" UTF-8.
- Non-matching bytes pass through **byte-identical** — cloak never corrupts data it
  didn't redact. (`cat file | cloak` with no matches is `cat`.)
- Matching is unaffected by surrounding garbage: a valid `AKIA…` key embedded in a
  binary blob is still caught (anchors and confirmers are byte patterns).
- This is tested: vectors embedded in random binary, in truncated-UTF-8, and in
  overlong/continuation-byte soup.

## Test taxonomy — five tiers, split cleanly

Every test in the repo belongs to exactly one tier; the tier decides where it
lives, what tooling drives it, and when it runs.

| Tier | Lives in | Tooling | Exercises | Runs |
|---|---|---|---|---|
| **Unit** | `#[cfg(test)]` modules beside the code | libtest | one unit in isolation: a confirmer regex, Luhn, carry-over arithmetic, digest formatting, overlap resolution, config deserialization | every build |
| **Integration** | `crates/cloak-core/tests/` | libtest + `proptest` | the assembled engine through its **public API**: per-rule vector suites, property invariants, differential engine ≡ reference | every PR, both Linux targets¹ |
| **E2E** | `crates/cloak-cli/tests/` | `assert_cmd` | the **real binary** through the process boundary: pipe stdin→stdout, file args, `--config` loading, stderr stats (text + JSON), exit codes | every PR, both Linux targets¹ |
| **Fuzz** | `crates/cloak-core/fuzz/` | `cargo-fuzz` | adversarial robustness: the three targets below | smoke + corpus replay every PR; long runs nightly |
| **Smoke** | tagged subset of the above | — | cheapest always-green signal: build + unit + one golden e2e pipe test (vector corpus in → redacted golden out, byte-compared) | first CI stage, every push |

Rules of the split:

- The **strategy layers** below (vectors, property, differential, fuzz) are the
  *what*; this table is the *where and when*. Vector data is defined once
  (`cloak-core/src/rules/vectors/`) and consumed by unit, integration, e2e (via the
  golden pipe test), and fuzz seeds — never duplicated per tier.
- Anything touching process I/O, flags, or exit codes is e2e — the engine never
  gets tested through the CLI, and the CLI never re-tests engine logic.
- Doc tests (rustdoc examples) count as unit tier and must compile/run — free with
  `cargo test`, listed here so they're not forgotten.
- v0.2 binding parity suites ([06-embedding.md](06-embedding.md#api-parity-contract))
  are the e2e tier of each host language: same vectors, real artifact, per-host CI.
- Coverage is **measured, published, and %-gated per tier** (`cargo-llvm-cov`,
  per-PR report with sticky comment). Thresholds: unit ≥95%, integration ≥70%,
  e2e ≥50%, total ≥92%. These complement — not replace — vectors, properties,
  differential, and fuzz, which enforce correctness better than a line-percentage
  alone. Thresholds are enforced from S1; adjust as the codebase stabilizes.
  Raised in S6 after the coverage gap-fill: unit ≥96%, integration ≥92%,
  e2e ≥90%, total ≥94%.

¹ *"All 3 targets" (linux x86-64, linux aarch64, macos aarch64) is the design
goal; S6 shipped the two Linux ISAs (different SIMD paths asserted equivalent)
and deferred macOS runners to [ledger F14](05-roadmap.md#follow-ups-ledger).*

### Cross-cutting test classes (adopted, v0.1)

| Class | Tier / stage | What it protects |
|---|---|---|
| **Mutation testing** (`cargo-mutants`) | nightly, over `cloak-core` | The tests themselves. Coverage says a line *ran*; a killed mutant says it's *asserted*. A surviving mutant in engine or rules code is an actionable finding (triage: add test or annotate why-not). From S6. |
| **CLI I/O robustness** | e2e cases (S5) | Production pipe reality: SIGPIPE/broken pipe when the collector restarts (clean exit, no panic), closed stdout mid-stream, partial writes, one enormous line. |
| **Snapshot tests** (`insta`) | e2e tooling (S5) | Output contracts: stats JSON (machine-consumed — drift must be a reviewed diff, never silent), `--help`, error messages. |
| **Soak test** | nightly (S7) | Bounded memory as an *observed fact*: stream tens of GB (looped bench corpora) through one `Session`, assert flat RSS. The proptest invariant, made empirical. |
| **Digest-stability goldens** | integration (S4) | The correlation promise. Committed golden digests: same input + same key ⇒ same `[CLOAK:rule:xxxx]` across releases. Digests live in stored logs and dashboards — changing them is a breaking change and must fail a test, not slip through. |
| **Thread-share test** | integration | `Engine` shared across threads (Send/Sync contract) with concurrent `Session`s — plain test, no loom (no lock-free code planned). |
| **Supply-chain gates** (`cargo-deny`) | stage 1 CI (S1) | RustSec advisories, license compliance, duplicate deps. A security tool with a compromised dependency is a punchline. |

### Deferred, with triggers (recorded, not forgotten)

- **Miri + sanitizers (ASAN/LSAN)** — near-zero value while the workspace is 100 %
  safe Rust on maintained crates. Becomes a **blocking gate** the day `unsafe`
  enters: hand-rolled SIMD kernels ([ledger F7](05-roadmap.md#follow-ups-ledger))
  and `cloak-ffi` ([E7](06-embedding.md#e7--cloak-ffi-c-abi--on-demand)).
- **MSRV build check** — lands automatically once S1 pins the MSRV policy.
- **Loom / model checking** — only if lock-free concurrency ever appears in core.
  Not currently planned.

## Test strategy (all of this is v0.1, not aspirational)

The guarantee makes testing a *feature*. Four layers:

### 1. Vector tests (per rule)
Every rule's positive/negative vector suites ([rules](02-rules.md#catalog-governance)),
run against both engine and reference. Positive vectors include variants embedded in
binary garbage and at buffer edges.

### 2. Property tests (`proptest`)
The load-bearing invariants:

- **Chunk-boundary invariant** (the big one): generate corpus (mix of clean text,
  planted vectors, random bytes) + arbitrary chunking (incl. 1-byte chunks, chunks
  splitting a vector at every offset) ⇒ streaming output ≡ whole-buffer output.
- **Passthrough invariant**: corpus with no planted vectors and anchors stripped ⇒
  output ≡ input, byte-identical.
- **Idempotence**: `redact(redact(S)) == redact(S)` (tags don't re-match; no
  reintroduction).
- **Bounded memory**: carry-over never exceeds `W_max` (+ PEM bail-out) regardless
  of input.

### 3. Differential testing
Engine vs scalar reference on: all vector corpora, proptest-generated corpora, and
the fuzz corpus. Any divergence is a guarantee bug by definition. Runs in CI on all
targets (x86-64 and aarch64 take different SIMD paths inside the crates —
divergence between targets is also asserted absent; macOS deferred, F14).

### 4. Fuzzing (`cargo-fuzz`)
Targets:

- `fuzz_engine_stream`: arbitrary bytes + arbitrary chunking → asserts no panic,
  bounded memory, streaming ≡ whole-buffer, output ≡ reference.
- `fuzz_pem_state`: adversarial BEGIN/END sequences (nested, unterminated, huge)
  → asserts bail-out honors bound, no hang.
- `fuzz_config`: arbitrary TOML → parser never panics, errors are typed.

CI runs each target time-boxed per PR (90 s for the two engine targets, 60 s for
config, on both Linux ISAs); the committed corpus (vector seeds + minimized crash
reproducers, generated by `cargo run -p cloak-core --example gen_fuzz_seeds`) is
regression-replayed on every run. The nightly stage runs 1 h/target per ISA; a
crash fails the job and uploads the minimized input as an artifact. Every finding
is back-ported as a deterministic test AND a committed `regression-*` corpus entry.

Until issues #27 (context-keyed rules × carry-over/PEM hold) and #34
(idempotence vs adjacent-redaction context) are fixed, the harness asserts
engine ≡ reference and idempotence only in strict mode (`CLOAK_FUZZ_STRICT=1`)
and caps streaming ≡ whole-buffer at max_window bytes — see
`fuzz/src/common.rs`, which is also where strict becomes the default once both
are fixed. No-panic and bounded memory are asserted unconditionally at every
length in both modes.

### CI staging (all blocking at their stage)

| Stage | When | Contents |
|---|---|---|
| **0 — Smoke** | every push, fail-fast, both Linux targets¹ | fmt, clippy `-D warnings`, build, unit tests, golden e2e pipe test |
| **1 — Full** | every PR, both Linux targets¹ | integration (vectors, property invariants, differential engine ≡ reference — cross-target divergence asserted absent, digest-stability goldens, thread-share), full e2e suite (incl. I/O robustness + `insta` snapshots), doc build + doc tests, fuzz smoke (time-boxed minutes) + committed-corpus regression replay, `cargo-deny` (advisories/licenses/dupes), coverage report published |
| **2 — Nightly** | scheduled (S6 ships fuzz + mutants; soak + criterion land in S7) | extended fuzz (≥ 1 h/target × both ISAs, findings uploaded as artifacts and back-ported to the corpus), `cargo-mutants` over `cloak-core` (4-way shard; surviving mutants reported non-blocking initially, filed as findings), multi-GB soak with flat-RSS assertion, full criterion suite: [≥ 500 MB/s floor + 10 % regression gate](04-performance.md#the-floor-ci-enforced), chunk-size sweep |
| **3 — Release** | tag | everything above + receipts table refresh + released-artifact golden smoke |

Bench gates live in nightly/release rather than per-PR — criterion on shared PR
runners is noise, and a perf regression can't hide longer than a day. A PR that
lands a suspected perf change can trigger the bench stage manually.
