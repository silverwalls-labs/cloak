"""Throughput benchmark: Python WASM adapter.

Same corpus as ``crates/wasm-parity/benches/throughput.rs`` and
``adapters/node/bench/throughput.ts`` — mixed log lines with embedded
secrets (~4 KiB per iteration).

Run::

    uv run python bench/throughput.py
"""

from __future__ import annotations

import time
from typing import NamedTuple

from cloak_python import CloakEngine, create_engine

# ── Corpus (matches Rust benchmark) ────────────────────────────────


def build_corpus() -> bytes:
    parts: list[bytes] = []
    for _ in range(20):
        parts.append(
            b"INFO 2026-09-26T12:00:00Z request completed status=200 "
            b"user=alice@example.com latency=12ms\n"
        )
    parts.append(b"DEBUG auth token=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 granted\n")
    for _ in range(20):
        parts.append(b"INFO 2026-09-26T12:00:01Z db query rows=42 duration=3ms\n")
    parts.append(b"WARN key=AKIAIOSFODNN7EXAMPLE exposed\n")
    for _ in range(20):
        parts.append(b"INFO 2026-09-26T12:00:02Z response sent bytes=1024\n")
    return b"".join(parts)


# ── Benchmark runner ───────────────────────────────────────────────


class BenchResult(NamedTuple):
    total_ns: int
    ops_per_sec: float
    mib_per_sec: float


def benchmark_redact(
    engine: CloakEngine, corpus: bytes, iterations: int
) -> BenchResult:
    # Warmup
    for _ in range(100):
        engine.redact(corpus)

    start = time.perf_counter_ns()
    for _ in range(iterations):
        engine.redact(corpus)
    elapsed = time.perf_counter_ns() - start

    elapsed_sec = elapsed / 1e9
    ops_per_sec = iterations / elapsed_sec
    mib_per_sec = (len(corpus) * iterations) / elapsed_sec / (1024 * 1024)
    return BenchResult(elapsed, ops_per_sec, mib_per_sec)


def benchmark_streaming(
    engine: CloakEngine, corpus: bytes, chunk_size: int, iterations: int
) -> BenchResult:
    def one_pass() -> None:
        session = engine.session()
        for off in range(0, len(corpus), chunk_size):
            session.push(corpus[off : off + chunk_size])
        session.finish()

    # Warmup
    for _ in range(50):
        one_pass()

    start = time.perf_counter_ns()
    for _ in range(iterations):
        one_pass()
    elapsed = time.perf_counter_ns() - start

    elapsed_sec = elapsed / 1e9
    ops_per_sec = iterations / elapsed_sec
    mib_per_sec = (len(corpus) * iterations) / elapsed_sec / (1024 * 1024)
    return BenchResult(elapsed, ops_per_sec, mib_per_sec)


# ── Main ───────────────────────────────────────────────────────────


def main() -> None:
    engine = create_engine(
        {"redaction": {"digest_key": "env:CLOAK_DIGEST_KEY"}},
        {"CLOAK_DIGEST_KEY": "bench-key"},
    )

    corpus = build_corpus()
    iterations = 50_000

    print(f"Corpus: {len(corpus)} bytes ({len(corpus) / 1024:.1f} KiB)")
    print(f"Iterations: {iterations:,}\n")

    # One-shot redact
    redact_result = benchmark_redact(engine, corpus, iterations)
    redact_us_per_op = redact_result.total_ns / iterations / 1000
    print("── redact() (one-shot) ──")
    print(f"  {redact_us_per_op:.2f} µs/op")
    print(f"  {redact_result.mib_per_sec:.1f} MiB/s")
    print(f"  {redact_result.ops_per_sec:.0f} ops/sec\n")

    # Streaming with 1 KiB chunks
    stream_1k = benchmark_streaming(engine, corpus, 1024, iterations)
    stream_1k_us_per_op = stream_1k.total_ns / iterations / 1000
    print("── streaming (1 KiB chunks) ──")
    print(f"  {stream_1k_us_per_op:.2f} µs/op")
    print(f"  {stream_1k.mib_per_sec:.1f} MiB/s")
    print(f"  {stream_1k.ops_per_sec:.0f} ops/sec\n")

    # Streaming with 256-byte chunks
    stream_256 = benchmark_streaming(engine, corpus, 256, iterations)
    stream_256_us_per_op = stream_256.total_ns / iterations / 1000
    print("── streaming (256 B chunks) ──")
    print(f"  {stream_256_us_per_op:.2f} µs/op")
    print(f"  {stream_256.mib_per_sec:.1f} MiB/s")
    print(f"  {stream_256.ops_per_sec:.0f} ops/sec\n")

    # Summary of the Python numbers measured on this machine. For the
    # native, Rust-wasmtime, and Node figures on the same corpus, see
    # docs/benchmarks/receipts-wasm-e3-python.md and receipts-wasm-e1.md.
    print("── summary (Python WASM, measured here) ──")
    print(
        f"  Python WASM (one-shot):          "
        f"~{redact_result.mib_per_sec:.0f} MiB/s  (~{redact_us_per_op:.0f} µs/op)"
    )
    print(
        f"  Python WASM (streaming 1K):      "
        f"~{stream_1k.mib_per_sec:.0f} MiB/s  (~{stream_1k_us_per_op:.0f} µs/op)"
    )

    engine.dispose()


if __name__ == "__main__":
    main()
