"""Parity tests: every vector in the cloak-core corpus must produce
identical output when run through the native module from Python.

Mirrors ``crates/wasm-parity/tests/parity.rs`` and
``adapters/node/test/parity.test.ts`` — same key material, same
vectors, same byte-exact assertion. The vectors are generated from
Rust via ``cargo run --example export-vectors -p cloak-core``.
"""

from __future__ import annotations

from array import array
from typing import cast

import pytest

from cloak_py import CloakEngine
from cloak_py.engine import Bytes

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


# ── Input coercion ─────────────────────────────────────────────────
# int is the dangerous one: bytes(1_000_000) is a megabyte of zeros,
# not an error — a naive bytes(data) fallback would silently scan it
# and lie in bytes_processed. bool (bytes(True) == b"\x01") and any
# iterable are the same trap.


@pytest.mark.parametrize("bad", [12345, 10**9, 12.5, None, True, ["a", "b"], {"a": 1}])
def test_redact_rejects_non_buffer_input(engine: CloakEngine, bad: object) -> None:
    with pytest.raises(TypeError, match="bytes-like"):
        engine.redact(cast("Bytes", bad))


@pytest.mark.parametrize("bad", [12345, 12.5, None, True])
def test_push_rejects_non_buffer_input(engine: CloakEngine, bad: object) -> None:
    session = engine.session()
    with pytest.raises(TypeError, match="bytes-like"):
        session.push(cast("Bytes", bad))
    # The failed coercion must not consume the session.
    session.push(b"clean")  # still usable
    session.finish()


def test_push_accepts_buffer_protocol_objects(engine: CloakEngine) -> None:
    # array implements the buffer protocol like bytes/bytearray/memoryview;
    # runtime accepts any Buffer (a deliberate superset of the typed
    # `Bytes` union).
    session = engine.session()
    out = session.push(
        cast("Bytes", array("B", b"token=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\n"))
    )
    out += session.finish().output
    assert b"[CLOAK:github-token:" in out, f"array input not redacted: {out!r}"
