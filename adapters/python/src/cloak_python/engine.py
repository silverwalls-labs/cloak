"""High-level cloak engine and session API.

Wraps the WASM bridge in a Python-idiomatic interface: ``bytes`` in/out,
``str`` convenience, proper exception raising.

Not thread-safe: the WASM module keeps take-once error/stats slots in
thread-local storage, and ``redact``/``finish`` must not interleave with
the stats read. Use one engine per thread, or guard with your own lock.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import NamedTuple, TypedDict

from ._bridge import CloakError, WasmBridge
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


def _read_stats(bridge: WasmBridge) -> CloakStats:
    """Consume the stashed stats, falling back to zeros when absent."""
    raw = bridge.finish_stats()
    if raw is None:
        return {"bytes_processed": 0, "matches": {}}
    return {
        "bytes_processed": int(raw.get("bytes_processed", 0)),
        "matches": dict(raw.get("matches", {})),
    }


class CloakSession:
    """A scanning session — per-stream state, cheap to create.

    Create via :meth:`CloakEngine.session`. Not thread-safe.
    """

    def __init__(self, bridge: WasmBridge, handle: int) -> None:
        self._bridge = bridge
        self._handle = handle
        self._consumed = False

    def push(self, data: Bytes) -> bytes:
        """Push a chunk through the scanner.

        Returns redacted bytes flushed by this push (may be empty when
        all bytes are held in the carry-over window). ``str`` inputs are
        encoded as UTF-8.
        """
        if self._consumed:
            raise CloakError("session already consumed (finished or aborted)")
        return self._bridge.push(self._handle, _to_bytes(data))

    def finish(self) -> RedactResult:
        """Finish the session: flush carry-over and return redacted output + stats.

        The session is consumed — do not reuse after this call.
        """
        if self._consumed:
            raise CloakError("session already consumed (finished or aborted)")
        self._consumed = True
        output = self._bridge.finish(self._handle)
        return RedactResult(output, _read_stats(self._bridge))

    def abort(self) -> None:
        """Abort the session without flushing.

        Drops carry-over and releases the session handle. Use when a
        stream is abandoned mid-way. Idempotent.
        """
        if self._consumed:
            return
        self._consumed = True
        self._bridge.session_free(self._handle)


class CloakEngine:
    """A compiled cloak engine — create sessions from it.

    Create via :func:`create_engine`. Usable as a context manager
    (``with create_engine() as engine: ...`` disposes on exit).
    Not thread-safe.
    """

    def __init__(self, bridge: WasmBridge, handle: int) -> None:
        self._bridge = bridge
        self._handle = handle

    def redact(self, data: Bytes) -> RedactResult:
        """One-shot convenience: redact a complete buffer in one call.

        Equivalent to ``session() → push(all) → finish()`` but without
        the session lifecycle. ``str`` inputs are encoded as UTF-8.
        Returns both the redacted output and per-stream stats.
        """
        output = self._bridge.redact(self._handle, _to_bytes(data))
        return RedactResult(output, _read_stats(self._bridge))

    def session(self) -> CloakSession:
        """Create a new scanning session for streaming redaction.

        Sessions are cheap — one per stream/request. The engine must
        outlive all its sessions.
        """
        return CloakSession(self._bridge, self._bridge.session_new(self._handle))

    def dispose(self) -> None:
        """Release the engine and its WASM resources.

        Fails if any sessions created from this engine are still live —
        finish or abort them first.
        """
        self._bridge.engine_free(self._handle)

    def __enter__(self) -> CloakEngine:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.dispose()


def create_engine(
    config: CloakConfig | str | None = None,
    env: Mapping[str, str] | None = None,
) -> CloakEngine:
    """Create a new cloak engine.

    Loads the WASM module, compiles the config, and returns a
    ready-to-use engine. Call with no arguments for the default config
    (ephemeral digest key, all rules enabled).

    :param config: Engine configuration (dict, serialized to TOML) or a
                   raw TOML string.
    :param env:    Environment variables visible to the WASM module.
                   Defaults to ``os.environ``.

    Example::

        engine = create_engine({
            "redaction": {"digest_key": "env:CLOAK_DIGEST_KEY"},
        })
        output, stats = engine.redact("token=ghp_AAAA...AAAA")
        engine.dispose()
    """
    bridge = WasmBridge.create(env)

    if config is None:
        toml = ""
    elif isinstance(config, str):
        toml = config
    else:
        toml = config_to_toml(config)

    return CloakEngine(bridge, bridge.engine_new(toml))
