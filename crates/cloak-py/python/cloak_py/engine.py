"""High-level cloak engine and session API (native pyo3 module).

Wraps the ``cloak_py._native`` extension in the same Python surface as
the WASM adapter (``cloak_python``): ``bytes`` in/out, ``str``
convenience, proper exception raising.

Thread contract: the engine is shareable across threads, and the GIL is
released while a scan runs. A session may move between threads, but
concurrent calls into the *same* session raise ``RuntimeError`` (pyo3's
runtime borrow checking) — one stream, one caller at a time.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import NamedTuple, TypedDict

from . import _native
from ._native import CloakError
from .config import CloakConfig, config_to_toml

__all__ = [
    "Bytes",
    "CloakEngine",
    "CloakError",
    "CloakSession",
    "CloakStats",
    "RedactResult",
    "create_engine",
]

Bytes = str | bytes | bytearray | memoryview
"""Accepted input types — ``str`` is encoded as UTF-8 at the boundary."""


class CloakStats(TypedDict):
    """Per-stream statistics returned by ``finish()`` and ``redact()``."""

    bytes_processed: int
    """Total bytes pushed through the session."""
    matches: dict[str, int]
    """Per-rule match counts (rule-id → count)."""


class RedactResult(NamedTuple):
    """Result of :meth:`CloakEngine.redact` or :meth:`CloakSession.finish`."""

    output: bytes
    """The redacted output bytes."""
    stats: CloakStats
    """Per-stream statistics."""


def _to_bytes(data: Bytes) -> bytes:
    """Coerce accepted input types to ``bytes`` (``str`` → UTF-8)."""
    if isinstance(data, str):
        return data.encode("utf-8")
    return bytes(data)


class CloakSession:
    """A scanning session — per-stream state, cheap to create.

    Create via :meth:`CloakEngine.session`. Movable across threads;
    concurrent use raises ``RuntimeError``.
    """

    def __init__(self, session: _native.Session) -> None:
        self._session = session

    def push(self, data: Bytes) -> bytes:
        """Push a chunk through the scanner.

        Returns redacted bytes flushed by this push (may be empty when
        all bytes are held in the carry-over window). ``str`` inputs are
        encoded as UTF-8. The GIL is released while the scan runs.
        """
        return self._session.push(_to_bytes(data))

    def finish(self) -> RedactResult:
        """Finish the session: flush carry-over and return redacted output + stats.

        The session is consumed — do not reuse after this call.
        """
        output, stats = self._session.finish()
        return RedactResult(output, stats)

    def abort(self) -> None:
        """Abort the session without flushing.

        Drops carry-over and releases the engine pin. Use when a stream
        is abandoned mid-way. Idempotent.
        """
        self._session.abort()


class CloakEngine:
    """A compiled cloak engine — create sessions from it.

    Create via :func:`create_engine`. Usable as a context manager
    (``with create_engine() as engine: ...`` disposes on exit).
    Shareable across threads.
    """

    def __init__(self, native: _native.Engine) -> None:
        self._native = native

    def redact(self, data: Bytes) -> RedactResult:
        """One-shot convenience: redact a complete buffer in one call.

        Equivalent to ``session() → push(all) → finish()`` but without
        the session lifecycle. ``str`` inputs are encoded as UTF-8.
        Returns both the redacted output and per-stream stats. The GIL
        is released while the scan runs.
        """
        output, stats = self._native.redact(_to_bytes(data))
        return RedactResult(output, stats)

    def session(self) -> CloakSession:
        """Create a new scanning session for streaming redaction.

        Sessions are cheap — one per stream/request. Live sessions pin
        the engine: :meth:`dispose` refuses until they finish or abort.
        """
        return CloakSession(self._native.session())

    def dispose(self) -> None:
        """Release the engine.

        Fails if any sessions created from this engine are still live —
        finish or abort them first. Idempotent once released.
        """
        self._native.dispose()

    def __enter__(self) -> CloakEngine:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.dispose()


def create_engine(
    config: CloakConfig | str | None = None,
    env: Mapping[str, str] | None = None,
) -> CloakEngine:
    """Create a new cloak engine.

    Compiles the config into a native engine. Call with no arguments
    for the default config (digest key from ``CLOAK_DIGEST_KEY``,
    ephemeral fallback).

    :param config: Engine configuration (dict, serialized to TOML) or a
                   raw TOML string.
    :param env:    Environment variables visible to the engine while it
                   resolves ``env:``-indirected digest keys. Defaults to
                   ``os.environ``. When given, ``os.environ`` is swapped
                   for the mapping *during construction only* (the native
                   engine reads the process environment exactly once, in
                   its constructor) — mirroring the WASM adapter, where
                   an explicit mapping is the module's entire
                   environment. The swap is process-wide: do not call
                   with ``env`` concurrently with code that reads
                   ``os.environ``.

    Example::

        engine = create_engine({
            "redaction": {"digest_key": "env:CLOAK_DIGEST_KEY"},
        })
        output, stats = engine.redact("token=ghp_AAAA...AAAA")
        engine.dispose()
    """
    if config is None:
        toml = ""
    elif isinstance(config, str):
        toml = config
    else:
        toml = config_to_toml(config)

    if env is None:
        return CloakEngine(_native.Engine(toml))

    saved = dict(os.environ)
    os.environ.clear()
    os.environ.update(env)
    try:
        native = _native.Engine(toml)
    finally:
        os.environ.clear()
        os.environ.update(saved)
    return CloakEngine(native)
