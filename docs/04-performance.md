# Performance — cloak v0.1

> Prev: [guarantee & testing](03-guarantee-and-testing.md) · Next: [roadmap](05-roadmap.md)

## Philosophy

**Speed is the point; SIMD is the means.** v0.1 gets its SIMD from proven crates
(`memchr`, `aho-corasick`, `regex-automata` — Teddy/packed prefilters, runtime
AVX2/NEON dispatch). Hand-rolled kernels come later and only with receipts: a kernel
that doesn't beat the crate-based scanner on the same benchmark doesn't ship.

Every performance claim in the README must trace to a committed benchmark result.
No mood-based "blazingly fast."

## The floor (CI-enforced)

| Metric | Floor | Corpus |
|---|---|---|
| Clean-path throughput, single core | **≥ 500 MB/s** | `corpus/clean-*` (match-free) |
| Match-heavy throughput, single core | tracked, no gate in v0.1 | `corpus/dirty-*` |
| Memory | O(W) bounded (asserted in tests, see [03](03-guarantee-and-testing.md)) | any |

Context for the number: realistic per-node kube log volume is a few MB/s; 500 MB/s
single-core leaves two orders of magnitude of headroom and is comfortably achievable
for an anchored-prefilter design. It is a floor, not a target — measured numbers are
recorded per release.

## Reference corpora (committed, versioned)

| Corpus | Content | Purpose |
|---|---|---|
| `clean-json` | synthetic structured logs (JSON lines), zero matches, zero anchors where possible | best-case clean path |
| `clean-text` | plain app logs, zero matches, natural anchor noise (`@`, `://`, digit runs that fail confirm) | *honest* clean path — prefilter fires, confirm rejects |
| `dirty-mixed` | clean base + planted vectors from every rule at realistic density (~1/10k lines) | realistic redaction load |
| `dirty-dense` | vector-saturated | worst-case confirm + rewrite path |
| `binary-soup` | random bytes + embedded vectors | non-UTF-8 path |

`clean-text` is the corpus that keeps us honest: anchors that fire but fail
confirmation are where naive designs collapse. The floor gate runs on both `clean-*`
corpora; the worse number is the gate.

## Methodology

- **criterion** benches in `benches/`, measuring `Session::push` throughput
  end-to-end (engine + redaction writer, no process I/O) and prefilter-only.
- Single-core, fixed chunk size (64 KiB default) + a chunk-size sweep bench
  (1 KiB → 1 MiB) to characterize carry-over overhead.
- Baselines stored per target (x86-64 AVX2, aarch64 NEON); CI compares against the
  stored baseline of its own target — regression > 10 % fails the gate.
- CI-runner noise: the floor gate uses the median of ≥ 5 runs; the 500 MB/s gate is
  deliberately far below expected performance so flakiness means real trouble, not
  jitter.

## The receipts protocol ("SIMD-powered", proven)

Standing comparison, recorded in `docs/benchmarks/` per release:

| Scanner | Role |
|---|---|
| `ScalarScanner` (naive reference) | baseline — what "no SIMD" costs |
| `AhoCorasickScanner` (v0.1 engine) | current champion |
| `KernelScanner` (future hand-rolled) | challenger — ships only if it wins |

Rules of the protocol:

1. Same corpora, same harness, same machine class for every contender.
2. Results committed as versioned markdown tables (corpus × scanner × target),
   with rustc version and CPU noted.
3. A hand-rolled kernel PR must include its table. **No receipts, no merge** — this
   is the trace the scoping decision demanded ("benchmark that against kernel
   optimization and direct SIMD later — keep trace of that").

## Known perf risks (watch list)

- **Anchor-noise amplification**: cheap anchors (`@`, `://`, `+`, digit runs) fire
  constantly on real logs; confirm-step cost dominates. Mitigation: `clean-text`
  corpus in the gate, per-rule anchor tuning, candidate-window dedup.
- **Carry-over churn at small chunk sizes**: the sweep bench characterizes it;
  the CLI picks a sane default read size (64 KiB).
- **PEM state on `-----BEGIN` noise**: bounded by bail-out; `dirty-dense` includes
  adversarial BEGIN spam.
- **ipv6/credit-card confirm cost**: gnarliest confirmers; if they dominate the
  `clean-text` profile, they get dedicated pre-validators before regex.
