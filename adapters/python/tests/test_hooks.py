"""Hook tests — CloakWriter (file-like) and CloakHandler (logging).

Mirrors ``adapters/node/test/transform.test.ts``.
"""

from __future__ import annotations

import io
import logging
from collections.abc import Iterator
from typing import cast

import pytest

from cloak_python import CloakEngine, CloakHandler, CloakWriter, create_engine

DIRTY_INPUT = b"token=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\n"
CLEAN_INPUT = b"hello world, nothing secret here\n"


@pytest.fixture(scope="module")
def engine() -> Iterator[CloakEngine]:
    engine = create_engine(env={"CLOAK_DIGEST_KEY": "test-key"})
    yield engine
    engine.dispose()


# ── CloakWriter ────────────────────────────────────────────────────


def test_writer_redacts_dirty_input(engine: CloakEngine) -> None:
    buf = io.BytesIO()
    with CloakWriter(engine, buf) as writer:
        writer.write(DIRTY_INPUT)
    out = buf.getvalue()
    assert b"[CLOAK:github-token:" in out, f"expected redaction, got: {out!r}"
    assert b"ghp_" not in out, "plaintext token must not appear in output"


def test_writer_passes_clean_input_through(engine: CloakEngine) -> None:
    buf = io.BytesIO()
    with CloakWriter(engine, buf) as writer:
        writer.write(CLEAN_INPUT)
    assert buf.getvalue() == CLEAN_INPUT


def test_writer_handles_multi_chunk_input(engine: CloakEngine) -> None:
    buf = io.BytesIO()
    with CloakWriter(engine, buf) as writer:
        writer.write(b"tok")
        writer.write(b"en=ghp_AbCdEfGhIjKl")
        writer.write(b"MnOpQrStUvWxYz01232piBxe\ndone\n")
    out = buf.getvalue()
    assert b"[CLOAK:github-token:" in out, f"multi-chunk not redacted: {out!r}"


def test_writer_output_complete_only_after_close(engine: CloakEngine) -> None:
    buf = io.BytesIO()
    writer = CloakWriter(engine, buf)
    writer.write(DIRTY_INPUT)
    # The carry-over window may withhold tail bytes until finish.
    before_close = buf.getvalue()
    writer.close()
    after_close = buf.getvalue()
    assert len(after_close) >= len(before_close)
    assert b"[CLOAK:github-token:" in after_close
    assert b"ghp_" not in after_close


def test_writer_stats_populated_after_close(engine: CloakEngine) -> None:
    buf = io.BytesIO()
    writer = CloakWriter(engine, buf)
    writer.write(DIRTY_INPUT)
    assert writer.stats is None
    writer.close()
    assert writer.stats is not None
    assert writer.stats["bytes_processed"] == len(DIRTY_INPUT)
    assert writer.stats["matches"]["github-token"] >= 1


def test_writer_close_is_idempotent(engine: CloakEngine) -> None:
    writer = CloakWriter(engine, io.BytesIO())
    writer.close()
    writer.close()  # no error


def test_writer_write_after_close_raises(engine: CloakEngine) -> None:
    writer = CloakWriter(engine, io.BytesIO())
    writer.close()
    with pytest.raises(ValueError, match="closed"):
        writer.write(b"more")


def test_writer_works_through_buffered_writer(engine: CloakEngine) -> None:
    # io.BufferedWriter interprets write()'s return as input bytes
    # consumed — returning emitted counts would corrupt the stream.
    buf = io.BytesIO()
    raw = CloakWriter(engine, buf)
    buffered = io.BufferedWriter(raw, buffer_size=8)
    buffered.write(DIRTY_INPUT)
    buffered.write(b"done\n")
    buffered.close()  # flushes then closes raw
    out = buf.getvalue()
    assert b"[CLOAK:github-token:" in out, f"buffered output not redacted: {out!r}"
    assert b"ghp_" not in out
    assert out.endswith(b"done\n")


def test_writer_abort_drops_session_without_flushing(engine: CloakEngine) -> None:
    buf = io.BytesIO()
    writer = CloakWriter(engine, buf)
    writer.write(DIRTY_INPUT)
    writer.abort()
    writer.abort()  # idempotent
    assert writer.stats is None
    assert writer.closed
    # Carry-over tail was dropped: no finish, no complete redaction line.
    assert b"ghp_" not in buf.getvalue()


def test_writer_aborts_session_when_push_fails() -> None:
    # Mirror the Node mock-engine test: when push raises, the session
    # must be aborted so the engine can still be disposed.
    aborted = False

    class MockSession:
        def push(self, data: object) -> bytes:
            raise RuntimeError("push failed")

        def finish(self) -> object:
            raise RuntimeError("not used in this test")

        def abort(self) -> None:
            nonlocal aborted
            aborted = True

    class MockEngine:
        def session(self) -> MockSession:
            return MockSession()

    writer = CloakWriter(cast(CloakEngine, MockEngine()), io.BytesIO())
    with pytest.raises(RuntimeError, match="push failed"):
        writer.write(b"data")
    assert aborted, "session must be aborted when push raises"
    writer.abort()  # mark closed so GC does not re-run close() → finish()


# ── CloakHandler ───────────────────────────────────────────────────


def _make_logger(handler: logging.Handler, name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.handlers = [handler]
    return logger


def test_handler_redacts_token_in_message(engine: CloakEngine) -> None:
    buf = io.BytesIO()
    logger = _make_logger(CloakHandler(engine, buf), "cloak-test-message")
    logger.info("token=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")
    out = buf.getvalue()
    assert b"[CLOAK:github-token:" in out, f"expected redaction, got: {out!r}"
    assert b"ghp_" not in out


def test_handler_redacts_token_in_args(engine: CloakEngine) -> None:
    buf = io.BytesIO()
    logger = _make_logger(CloakHandler(engine, buf), "cloak-test-args")
    logger.info("leaked %s", "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")
    out = buf.getvalue()
    assert b"[CLOAK:github-token:" in out
    assert b"ghp_" not in out


def test_handler_passes_clean_records_through(engine: CloakEngine) -> None:
    buf = io.BytesIO()
    logger = _make_logger(CloakHandler(engine, buf), "cloak-test-clean")
    logger.info("hello world, nothing secret here")
    assert buf.getvalue() == b"hello world, nothing secret here\n"


def test_handler_respects_formatter(engine: CloakEngine) -> None:
    buf = io.BytesIO()
    handler = CloakHandler(engine, buf)
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    logger = _make_logger(handler, "cloak-test-format")
    logger.warning("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")
    out = buf.getvalue()
    assert out.startswith(b"WARNING ")
    assert b"[CLOAK:github-token:" in out
    assert b"ghp_" not in out
