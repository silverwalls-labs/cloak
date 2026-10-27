"""File-like binary writer that redacts secrets on the fly.

This is the layer-1 stdout/stderr hook shape from the embedding doc
(the Python analog of the Node ``Transform`` stream): wrap a binary
stream so everything written through it is redacted. Hooks are thin
sugar — all correctness lives in core.

Example::

    import sys
    from cloak_py import create_engine, CloakWriter

    engine = create_engine()
    with CloakWriter(engine, sys.stdout.buffer) as out:
        out.write(b"token=ghp_AAAA...AAAA\\n")
    engine.dispose()
"""

from __future__ import annotations

import io
from collections.abc import Buffer
from typing import BinaryIO

from .engine import CloakEngine, CloakStats

__all__ = ["CloakWriter"]


class CloakWriter(io.RawIOBase):
    """A write-only binary stream that redacts via a cloak session.

    Each ``write()`` pushes through the session and forwards flushed
    bytes to ``target``; ``close()`` finishes the session, writes the
    carry-over tail, and populates :attr:`stats`. The engine must
    outlive the writer.

    Being a ``RawIOBase``, it can be wrapped in ``io.BufferedWriter``
    or ``io.TextIOWrapper`` (e.g. ``print(..., file=...)``).

    :param engine:       Engine to create the session from.
    :param target:       Stream redacted bytes are written to.
    :param close_target: Also close ``target`` when this writer closes.
    """

    def __init__(
        self,
        engine: CloakEngine,
        target: BinaryIO,
        *,
        close_target: bool = False,
    ) -> None:
        super().__init__()
        self._session = engine.session()
        self._target = target
        self._close_target = close_target
        self._aborted = False
        self.stats: CloakStats | None = None
        """Session stats, populated by :meth:`close`; ``None`` before
        close and after :meth:`abort`."""

    def writable(self) -> bool:
        return True

    def _write_all(self, data: bytes) -> None:
        """Write all of ``data`` to ``target``, looping over short writes.

        Raw/unbuffered targets (``open(..., buffering=0)``, pipes) may
        legally write fewer bytes than given — dropping the remainder
        would silently truncate *redacted* output downstream.
        """
        pos = 0
        while pos < len(data):
            n = self._target.write(data[pos:])
            if not n:
                # None (non-blocking) or 0 for a nonempty write — zero
                # progress either way, and this writer has no buffer to
                # park the bytes in, so surface it instead of spinning.
                raise BlockingIOError()
            pos += n

    def write(self, b: Buffer) -> int:
        """Push a chunk through the scanner, forwarding flushed bytes.

        Returns the number of *input* bytes consumed (``len(b)``) per
        the ``RawIOBase`` contract — the carry-over window means the
        bytes emitted to ``target`` may be fewer (or more, once tags
        are substituted).
        """
        if self.closed:
            raise ValueError("I/O operation on closed file")
        data = bytes(b)
        try:
            out = self._session.push(data)
            if out:
                self._write_all(out)
        except Exception:
            # Abort the whole writer, not just the session, so it lands in a
            # terminal state: the session is released (so `engine.dispose()`
            # is not blocked) and a later `close()` — explicit or via GC —
            # won't call `finish()` on the now-consumed session and raise a
            # spurious "already consumed" error, or report a successful
            # close after output was truncated by a failed forward.
            # Mirrors the Node transform's destroy-on-error path.
            self.abort()
            raise
        return len(data)

    def flush(self) -> None:
        """Flush ``target``. Carry-over bytes cannot flush without close."""
        # ``super().close()`` calls ``self.flush()`` before this writer is
        # marked closed, so guard the target too: a ``close_target`` close
        # (or an already-closed target) must not provoke a flush-after-close.
        if self.closed or self._aborted or self._target.closed:
            return
        self._target.flush()

    def close(self) -> None:
        """Finish the session, write the tail, populate :attr:`stats`.

        Idempotent. On failure the session is aborted so the engine can
        still be disposed.
        """
        if self.closed:
            return
        try:
            output, stats = self._session.finish()
            if output:
                self._write_all(output)
            self.stats = stats
            self._target.flush()
            if self._close_target:
                self._target.close()
        except Exception:
            self._aborted = True
            self._session.abort()
            raise
        finally:
            super().close()

    def abort(self) -> None:
        """Drop the session without flushing (broken-pipe path). Idempotent."""
        if self.closed:
            return
        self._aborted = True
        self._session.abort()
        super().close()
