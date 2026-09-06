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
- **Not** resistance to adversarial encoding. A secret that is base64-wrapped,
  hex-dumped, split by the *emitting application* across two log records, or
  otherwise transformed before reaching cloak does not match the rule's byte
  pattern and is not caught. cloak guards against accidental leakage, not against
  an adversary inside the emitting process.
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
three targets (x86-64 and aarch64 take different SIMD paths inside the crates —
divergence between targets is also asserted absent).

### 4. Fuzzing (`cargo-fuzz`)
Targets:

- `fuzz_engine_stream`: arbitrary bytes + arbitrary chunking → asserts no panic,
  bounded memory, streaming ≡ whole-buffer, output ≡ reference.
- `fuzz_pem_state`: adversarial BEGIN/END sequences (nested, unterminated, huge)
  → asserts bail-out honors bound, no hang.
- `fuzz_config`: arbitrary TOML → parser never panics, errors are typed.

CI runs each target time-boxed (smoke, minutes) per PR; the committed corpus
(minimized crashes + interesting inputs) is regression-replayed on every run.
Long-running fuzz sessions are manual/scheduled, with new findings committed to the
corpus.

### CI gates (blocking)

- fmt + clippy `-D warnings`, tests, doc build — on linux x86-64, linux aarch64,
  macos aarch64.
- Differential suite green on all targets.
- Fuzz smoke + corpus replay green.
- Bench floor gate per [04-performance.md](04-performance.md).
