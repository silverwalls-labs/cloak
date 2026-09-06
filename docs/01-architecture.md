# Architecture — cloak v0.1

> Prev: [scope](00-scope.md) · Next: [rules](02-rules.md)

## Workspace layout

```
cloak/
├── Cargo.toml            # workspace
├── crates/
│   ├── cloak-core/       # library: engine, ruleset, config types
│   │   ├── src/
│   │   │   ├── engine/   # streaming scanner, carry-over, prefilter→confirm
│   │   │   ├── rules/    # built-in detector catalog
│   │   │   ├── redact/   # tag + digest writer
│   │   │   ├── config/   # serde-first config types (TOML frontend in v0.1)
│   │   │   └── reference/# naive scalar impl: test oracle + bench baseline
│   │   └── fuzz/         # cargo-fuzz targets
│   └── cloak-cli/        # binary: pipe/file frontend, stats reporting
├── benches/              # criterion suites + reference corpora
└── docs/
```

Two crates, one workspace. `cloak-core` has **no CLI, no I/O policy** — it consumes
byte chunks and emits redacted bytes + match events. Everything the three deployment
layers share lives here; the v0.2 binding crates (`cloak-ffi`, `cloak-py`,
`cloak-node`, `cloak-go`, `cloak-wasm` — see [06-embedding.md](06-embedding.md))
wrap this same core. **Binding-shaped API is a v0.1 constraint**: the core surface
must stay expressible over a C ABI — bytes in/out, no host-language types, no
callbacks richer than a writer — so embedding lands without core rework.

## Engine model: bytes + bounded carry-over

The engine is a **push-based streaming scanner over raw bytes**:

```
caller pushes &[u8] chunks ──▶ [ carry-over buffer | new chunk ]
                                        │
                              prefilter (aho-corasick / memchr)
                                        │ candidate windows
                              confirm  (regex-automata / validators e.g. Luhn)
                                        │ matches
                              redaction writer ──▶ output bytes + MatchEvent per hit
```

Key decisions:

- **Raw bytes, never `str`.** Logs are not clean UTF-8. The engine makes no encoding
  assumption; patterns are byte patterns. This is required by the guarantee
  (see [03](03-guarantee-and-testing.md)).
- **Bounded carry-over.** A match may straddle a chunk boundary. The engine retains
  the trailing `W` bytes of each chunk (`W` = max unresolved-match window) and
  prepends them to the next chunk. Only bytes provably match-free are flushed.
  Memory is O(W), independent of stream length.
- **Multi-line / unbounded patterns (PEM blocks)** are handled by a small stateful
  detector layered on the same carry-over machinery: on `-----BEGIN … PRIVATE KEY-----`
  the engine enters a suppress-until-END state with a configured max-length bail-out,
  so memory stays bounded even for a forged, never-ending BEGIN.
- **Line framing is a CLI concern.** The engine doesn't know what a line is. The CLI
  may choose flush points at newlines for latency, but correctness never depends on it.
- **Sync.** The engine is a pure function of pushed bytes; the CLI drives it with
  blocking reads. Async wrappers can be layered later without touching the core.

## Matching pipeline

v0.1 rides **SIMD-backed crates** — speed is the point, SIMD is the means:

1. **Prefilter:** one `aho-corasick` automaton over all rules' literal anchors
   (`AKIA`, `ghp_`, `eyJ`, `-----BEGIN`, `@`, `://`, `+` …). SIMD-accelerated
   (Teddy / memchr) internally. One pass, all rules.
2. **Confirm:** each candidate window runs the owning rule's `regex-automata` DFA
   and/or validator (Luhn for cards, structural checks for JWT).
3. **Overlap resolution:** overlapping matches merge; longest-leftmost wins.

Every rule **must** declare at least one literal anchor — this keeps the clean path
(no anchors present) at prefilter speed, which is what makes the
[≥ 500 MB/s floor](04-performance.md) achievable.

### The SIMD upgrade path (kept honest)

Hand-rolled kernels (`std::simd` / intrinsics) are a later milestone, **behind the
same trait, justified only by benchmark receipts**:

```rust
pub trait Scanner {
    /// Scan `haystack`, appending candidate windows to `out`.
    fn scan(&self, haystack: &[u8], out: &mut Vec<Candidate>) -> ();
}
// v0.1:  AhoCorasickScanner (crate-backed, SIMD inside)
// v0.1:  ScalarScanner      (naive reference: test oracle + bench baseline)
// v0.2+: KernelScanner      (hand-rolled, feature-gated, must beat AhoCorasickScanner)
```

The **scalar reference implementation** ships in v0.1. It is deliberately naive and
obviously-correct, and serves double duty: differential-test oracle (engine ≡
reference on every corpus) and benchmark baseline (the receipts for "SIMD-powered").

## Core API sketch

```rust
pub struct Engine { /* compiled ruleset, carry-over state factory */ }

pub struct Session<'e> { /* per-stream state: carry-over, PEM state, stats */ }

impl Engine {
    pub fn new(config: &Config) -> Result<Engine, BuildError>;
    pub fn session(&self) -> Session<'_>;
}

impl Session<'_> {
    /// Push a chunk; redacted output is written to `out`.
    /// May withhold trailing bytes (carry-over) until the next push or finish.
    pub fn push(&mut self, chunk: &[u8], out: &mut impl io::Write) -> io::Result<()>;
    /// Flush carry-over, close open states, return per-rule stats.
    pub fn finish(self, out: &mut impl io::Write) -> io::Result<Stats>;
}

pub struct MatchEvent { pub rule: RuleId, pub digest: Digest /* no plaintext */ }
```

`MatchEvent` never carries the matched plaintext — the secret must not escape
through the reporting side-channel.

## Redaction writer

Default output: **typed tag + short deterministic digest**:

```
[CLOAK:aws-access-key:9f3a]
```

- `aws-access-key` — rule id, so ops can grep/alert per rule.
- `9f3a` — truncated keyed digest of the matched bytes: same secret ⇒ same digest,
  so "one secret leaked in 40 places" is visible without exposure. Keyed/salted per
  deployment so digests aren't an offline-bruteforce oracle. Exact scheme:
  [02-rules.md](02-rules.md#redaction-format).

Per-rule template configurability is a follow-up; the config schema below reserves
room for it so it lands without a breaking change.

## Configuration

**Serde-first**: config is a set of `serde` structs; file formats are frontends.
v0.1 ships **TOML only**; YAML/JSON + `cloak config convert` are v0.2 follow-ups
(YAML crate choice is a recorded open decision — `serde_yaml` is unmaintained).

```toml
# cloak.toml (v0.1 surface)
[redaction]
digest_key = "env:CLOAK_DIGEST_KEY"   # keyed digest; env-indirection, never inline

[rules.aws-access-key]
enabled = true                        # every rule: on by default, opt-out

[rules.phone-intl]
enabled = false                       # example: disabling the FP-riskiest rule
```

## CLI surface (v0.1)

```
app | cloak                     # stdin → stdout, default ruleset
cloak --config cloak.toml       # explicit config
cloak file.log > file.red.log   # file args feed the same engine
cloak --stats-format json       # machine-readable per-rule counts on stderr
```

Exit codes: `0` clean, `1` operational error. Stats (per-rule match counts, bytes
processed) go to **stderr** at end of stream — stdout is exclusively the redacted
payload, so the pipe contract stays pure.

## Toolchain & CI

- **Stable Rust, edition 2024.** No nightly in v0.1; `std::simd` enters only with
  the feature-gated kernel milestone.
- CI matrix: **linux x86-64, linux aarch64, macos aarch64** — fmt, clippy
  (`-D warnings`), tests, doc build on all three; fuzz smoke + bench floor gates per
  [03](03-guarantee-and-testing.md)/[04](04-performance.md).
- Runtime CPU-feature detection comes free from the matching crates (AVX2/NEON
  picked at runtime); no per-target build flags needed in v0.1.

### Deliberately left open — decided in S1

CLI arg-parsing crate (`clap` vs lighter), error-handling crates (`thiserror` /
`anyhow` split), CI provider naming, and MSRV policy are intentionally not pinned
here; the S1 session decides and records them. Everything else in this doc is
settled.
