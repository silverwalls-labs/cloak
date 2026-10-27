"""Parity tests: every vector in the cloak-core corpus must produce
identical output when run through the native module from Python.

Mirrors ``crates/wasm-parity/tests/parity.rs`` and
``adapters/node/test/parity.test.ts`` — same key material, same
vectors, same byte-exact assertion. The vectors are generated from
Rust via ``cargo run --example export-vectors -p cloak-core``.
"""

from __future__ import annotations

import pytest

from cloak_py import CloakEngine

from .conftest import VECTORS, Vector

# ── Parity — one-shot redact() ─────────────────────────────────────


@pytest.mark.parametrize("vector", VECTORS, ids=lambda v: v["name"])
def test_one_shot_byte_identical(engine: CloakEngine, vector: Vector) -> None:
    data = bytes.fromhex(vector["input"])
    expected = bytes.fromhex(vector["expected"])
    actual = engine.redact(data).output
    assert actual == expected, (
        f'vector "{vector["name"]}" output mismatch\n'
        f"  input:    {data!r}\n"
        f"  got:      {actual!r}\n"
        f"  expected: {expected!r}"
    )


# ── Parity — streaming push+finish ─────────────────────────────────


@pytest.mark.parametrize("vector", VECTORS, ids=lambda v: v["name"])
def test_streaming_byte_identical(engine: CloakEngine, vector: Vector) -> None:
    data = bytes.fromhex(vector["input"])
    expected = bytes.fromhex(vector["expected"])

    session = engine.session()
    pushed = session.push(data)
    flushed = session.finish().output
    actual = pushed + flushed

    assert actual == expected, (
        f'vector "{vector["name"]}" streaming mismatch\n'
        f"  input:    {data!r}\n"
        f"  got:      {actual!r}\n"
        f"  expected: {expected!r}"
    )


# ── Parity — edge cases ────────────────────────────────────────────


def test_empty_input_produces_empty_output(engine: CloakEngine) -> None:
    assert engine.redact(b"").output == b""


def test_clean_input_passes_through_unchanged(engine: CloakEngine) -> None:
    text = "hello world, no secrets here\n"
    assert engine.redact(text).output == text.encode()


def test_str_input_accepted_and_redacted(engine: CloakEngine) -> None:
    output = engine.redact("token=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").output
    assert b"[CLOAK:github-token:" in output, f"str input not redacted: {output!r}"


def test_redact_returns_stats(engine: CloakEngine) -> None:
    stats = engine.redact("token=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").stats
    assert stats["bytes_processed"] > 0
    assert stats["matches"]["github-token"] >= 1
