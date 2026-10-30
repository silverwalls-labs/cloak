"""Chunk-boundary invariant: split vector inputs at varying boundaries
and verify the native module produces identical output regardless of
chunking — same guarantee as cloak-core (docs/03).

Mirrors ``crates/wasm-parity/tests/streaming.rs`` and
``adapters/node/test/streaming.test.ts`` (same seeded split-point
algorithm), plus host-side session lifecycle semantics.
"""

from __future__ import annotations

import pytest

from cloak_py import CloakEngine, CloakError, create_engine

from .conftest import VECTORS

# ── Helpers ────────────────────────────────────────────────────────


def split_points(length: int, seed: int) -> list[int]:
    """Deterministic split points for a given input length and seed.

    Returns 1-5 split points within ``[0, length)`` — the exact
    algorithm from the Node suite so failures are comparable.
    """
    if length == 0:
        return []
    count = (seed % 5) + 1
    return sorted({(seed * (i + 7)) % length for i in range(count)})


def chunk_at(data: bytes, points: list[int]) -> list[bytes]:
    """Split ``data`` at the given points, skipping non-advancing splits."""
    chunks: list[bytes] = []
    pos = 0
    for split in points:
        if split > pos:
            chunks.append(data[pos:split])
            pos = split
    chunks.append(data[pos:])
    return chunks


# ── Chunk-boundary invariant ───────────────────────────────────────


def test_chunked_push_matches_single_push_for_every_vector(
    engine: CloakEngine,
) -> None:
    for vector in VECTORS:
        data = bytes.fromhex(vector["input"])
        if not data:
            continue

        # Baseline: one-shot redact.
        baseline = engine.redact(data).output

        # Chunked: split at multiple boundaries per vector.
        for seed in range(10):
            session = engine.session()
            actual = b"".join(
                session.push(chunk)
                for chunk in chunk_at(data, split_points(len(data), seed))
            )
            actual += session.finish().output

            assert actual == baseline, (
                f'vector "{vector["name"]}" seed {seed} chunking changed output\n'
                f"  got:      {actual!r}\n"
                f"  expected: {baseline!r}"
            )


def test_single_byte_pushes_match_one_shot(engine: CloakEngine) -> None:
    checked = 0
    for vector in VECTORS:
        data = bytes.fromhex(vector["input"])
        if not data:
            continue

        baseline = engine.redact(data).output
        session = engine.session()
        actual = b"".join(session.push(data[i : i + 1]) for i in range(len(data)))
        actual += session.finish().output

        assert actual == baseline, (
            f'vector "{vector["name"]}" single-byte chunking changed output'
        )
        checked += 1
        if checked == 5:
            break


# ── Session lifecycle ──────────────────────────────────────────────


def test_double_finish_raises(engine: CloakEngine) -> None:
    session = engine.session()
    session.push(b"abc")
    session.finish()
    with pytest.raises(
        CloakError, match=r"session already consumed \(finished or aborted\)"
    ):
        session.finish()


def test_push_after_finish_raises(engine: CloakEngine) -> None:
    session = engine.session()
    session.finish()
    with pytest.raises(CloakError, match="session already consumed"):
        session.push(b"abc")


def test_abort_is_idempotent(engine: CloakEngine) -> None:
    session = engine.session()
    session.push(b"abc")
    session.abort()
    session.abort()  # no error


def test_dispose_with_live_session_raises(engine: CloakEngine) -> None:
    session = engine.session()
    with pytest.raises(CloakError, match="live sessions"):
        engine.dispose()
    session.abort()  # release so the module-scoped engine can dispose cleanly


def test_dispose_is_idempotent() -> None:
    engine = create_engine()
    engine.dispose()
    engine.dispose()  # second call is a no-op


def test_engine_methods_after_dispose_raise() -> None:
    engine = create_engine()
    engine.dispose()
    with pytest.raises(CloakError, match="engine disposed"):
        engine.redact(b"x")
    with pytest.raises(CloakError, match="engine disposed"):
        engine.session()


def test_engine_usable_after_refused_dispose() -> None:
    # A refused dispose (live session) must leave the engine untouched:
    # the native Arc was put back, not dropped.
    engine = create_engine()
    session = engine.session()
    with pytest.raises(CloakError, match="in use"):
        engine.dispose()
    out = engine.redact("token=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").output
    assert b"[CLOAK:github-token:" in out
    session.abort()
    engine.dispose()  # succeeds now
