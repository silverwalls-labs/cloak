"""``logging.Handler`` that redacts records before they reach a stream.

The stdlib-logging flavor of the layer-1 hook (the analog of the Node
pino examples): every formatted record is redacted one-shot and written
to a binary stream. One-shot — not a session — because log records are
discrete lines that must be fully flushed at emit time; a streaming
session's carry-over would withhold record tails. For raw byte streams
use :class:`cloak_py.CloakWriter` instead.

Example::

    import logging
    from cloak_py import create_engine, CloakHandler

    engine = create_engine()
    # force=True replaces existing root handlers (which would bypass
    # redaction); without it basicConfig is a no-op when handlers exist.
    logging.basicConfig(
        handlers=[CloakHandler(engine)], level=logging.INFO, force=True
    )
    logging.info("token=%s", some_secret)  # redacted on the way out
"""

from __future__ import annotations

import logging
import sys
from typing import BinaryIO

from .engine import CloakEngine

__all__ = ["CloakHandler"]


class CloakHandler(logging.Handler):
    """Redact formatted log records through a cloak engine.

    Safe to share across logging threads (the base handler lock guards
    ``emit``) **only if** the engine is not used elsewhere concurrently —
    the engine itself is not thread-safe.

    :param engine: Engine used for one-shot redaction. Caller owns it —
                   ``close()`` does not dispose it.
    :param stream: Binary stream records are written to.
                   Defaults to ``sys.stdout.buffer``.
    """

    terminator = b"\n"

    def __init__(self, engine: CloakEngine, stream: BinaryIO | None = None) -> None:
        super().__init__()
        self._engine = engine
        self._stream = stream if stream is not None else sys.stdout.buffer

    def emit(self, record: logging.LogRecord) -> None:
        """Format, redact, and write one record.

        Errors go through :meth:`logging.Handler.handleError` — no
        exception escapes the logging hot path.
        """
        try:
            line = self.format(record).encode("utf-8")
            output, _stats = self._engine.redact(line)
            self._stream.write(output + self.terminator)
            self._stream.flush()
        except Exception:
            self.handleError(record)

    def close(self) -> None:
        """Flush the stream and close the handler (not the engine)."""
        try:
            if not self._stream.closed:
                self._stream.flush()
        finally:
            super().close()
