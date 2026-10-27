"""Hook tests — CloakWriter (file-like) and CloakHandler (logging).

Mirrors ``adapters/node/test/transform.test.ts``.
"""

from __future__ import annotations

import io
import logging
from collections.abc import Iterator
from typing import BinaryIO, cast

import pytest

from cloak_py import CloakEngine, CloakHandler, CloakWriter, create_engine

DIRTY_INPUT = b"token=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\n"
CLEAN_INPUT = b"hello world, nothing secret here\n"


@pytest.fixture(scope="module")
def engine() -> Iterator[CloakEngine]:
    # Pass the digest_key config too: with config=None the engine uses an
    # ephemeral (random) key and never consults CLOAK_DIGEST_KEY, so the
    # env would be dead. Mirror conftest's pattern so the pinned key is live.
    engine = create_engine(
        {"redaction": {"digest_key": "env:CLOAK_DIGEST_KEY"}},
        {"CLOAK_DIGEST_KEY": "test-key"},
    )
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


def test_writer_close_target_closes_target_without_error(engine: CloakEngine) -> None:
    # close_target=True must close the wrapped target exactly once. The
    # inherited RawIOBase.close() calls self.flush() before marking the
    # writer closed, so without a target-closed guard it would re-flush the
    # just-closed target and raise ValueError("I/O operation on closed file").
    buf = io.BytesIO()
    writer = CloakWriter(engine, buf, close_target=True)
    writer.write(DIRTY_INPUT)
    writer.close()  # must not raise
    assert buf.closed, "close_target=True must close the target"
    assert writer.closed
    assert writer.stats is not None  # finish ran to completion


def test_writer_loops_over_short_writing_target(engine: CloakEngine) -> None:
    # Raw/unbuffered targets may legally write fewer bytes than given per
    # call; the writer must loop until the redacted output is fully
    # written — dropping the remainder would silently truncate output.
    class ShortWriter:
        def __init__(self) -> None:
            self.buf = io.BytesIO()

        @property
        def closed(self) -> bool:
            return self.buf.closed

        def write(self, b: bytes) -> int:
            return self.buf.write(b[:3])  # at most 3 bytes per call

        def flush(self) -> None:
            self.buf.flush()

    target = ShortWriter()
    writer = CloakWriter(engine, cast(BinaryIO, target))
    writer.write(DIRTY_INPUT)
    writer.close()
    out = target.buf.getvalue()
    assert b"[CLOAK:github-token:" in out, f"short-writing target lost data: {out!r}"
    assert b"ghp_" not in out


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
    # A failed push must leave the writer terminal, so a later close()
    # (explicit or via GC) is a no-op — it must not call finish() on the
    # already-consumed session and raise a spurious "already consumed".
    assert writer.closed, "writer must be closed after a failed push"
    writer.close()  # no error, no second finish/abort


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


def test_writer_raises_on_zero_progress_target(engine: CloakEngine) -> None:
    # A target returning 0 for a nonempty write makes no progress; the
    # writer must surface it (BlockingIOError) instead of spinning forever.
    class ZeroWriter:
        closed = False

        def write(self, b: bytes) -> int:
            return 0

        def flush(self) -> None:
            pass

    writer = CloakWriter(engine, cast(BinaryIO, ZeroWriter()))
    with pytest.raises(BlockingIOError):
        # Enough clean bytes that push flushes past the carry-over window
        # and the forward actually runs inside write().
        writer.write(b"clean filler line\n" * 1024)
    assert writer.closed, "writer must land terminal after a failed forward"


def test_writer_aborts_when_forwarding_fails(engine: CloakEngine) -> None:
    # If the target fails mid-forward after the session consumed the
    # input, the writer must abort — a later close() succeeding would
    # report completeness over truncated output.
    class FailingWriter:
        closed = False

        def write(self, b: bytes) -> int:
            raise OSError("target gone")

        def flush(self) -> None:
            pass

    writer = CloakWriter(engine, cast(BinaryIO, FailingWriter()))
    with pytest.raises(OSError, match="target gone"):
        writer.write(b"clean filler line\n" * 1024)
    assert writer.closed
    writer.close()  # idempotent no-op, must not raise or "succeed"
    assert writer.stats is None
