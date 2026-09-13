# Performance Receipts — v0.1

> Generated: 2026-09-13
> rustc: 1.98.1
> Target: aarch64-apple-darwin (dev machine)
> CPU: Apple Silicon (M-series)
> Corpora: `corpus/` (1 MB each, deterministic, committed)
>
> **These are reference numbers from a development machine.** CI nightly
> produces per-target receipts on the two Linux runner classes
> (x86-64 AVX2, aarch64 NEON).

## The receipts protocol (docs/04-performance.md)

"SIMD-powered" is proven, not asserted. The ScalarScanner is a deliberately
naive O(n·m) reference that byte-compares every anchor at every offset — the
cost of "no SIMD." The AhoCorasickScanner is the production prefilter (one
automaton, `aho-corasick` crate with Teddy/packed SIMD inside). A hand-rolled
KernelScanner (future) must include its own table — **no receipts, no merge.**

## Prefilter throughput: ScalarScanner vs AhoCorasickScanner

Both scanners use the production anchor set: catalog anchors + the PEM
anchor (`-----BEGIN `) at the engine's pseudo rule index — receipts measure
the shipped configuration (docs/04, receipts protocol).

| Corpus | ScalarScanner (MiB/s) | AhoCorasickScanner (MiB/s) | Speedup |
|---|---|---|---|
| clean-json  |  6.7 |  475 | **71×** |
| clean-text  |  6.7 |  386 | **58×** |
| dirty-mixed |  6.7 |  502 | **75×** |
| dirty-dense |  6.7 |  443 | **66×** |
| binary-soup |  6.8 |  510 | **75×** |

## End-to-end throughput (Session::push, 64 KiB chunks)

| Corpus | Throughput (MiB/s) |
|---|---|
| clean-json  | 348 |
| clean-text  | 267 |
| dirty-mixed | 423 |
| dirty-dense | 154 |
| binary-soup | 406 |

The clean-text number is the honest floor reference — it has heavy anchor noise
(`@`, `://`, digit-dot, `+`) that fires the prefilter constantly; the confirm
step rejects every candidate. This is where prefilter-only speed stops
mattering and confirm cost dominates.

## Chunk-size sweep (clean-text)

| Chunk Size | Throughput (MiB/s) |
|---|---|
|   1 KiB |   99 |
|   2 KiB |  144 |
|   4 KiB |  186 |
|   8 KiB |  216 |
|  16 KiB |  251 |
|  32 KiB |  263 |
|  64 KiB |  267 |
| 128 KiB |  273 |
| 256 KiB |  277 |
| 512 KiB |  278 |
|   1 MiB |  277 |

The 64 KiB CLI default is near the throughput plateau — diminishing returns
beyond it, and significantly better than the small-chunk regime where
carry-over churn dominates.

## Soak (memory)

The soak receipt (10 GB through one `Session`, flat-RSS assertion) is
produced by the **Linux CI nightly** (`soak` job) — the RSS assertion reads
`/proc/self/status` and is skipped on non-Linux dev machines, so no soak
number appears in this dev-machine doc. The bound itself is
`CARRY_OVER_BOUND` (max rule window + PEM retention), asserted per-push by
the fuzz harness, the corpus tests, and the soak tests.
