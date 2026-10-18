"""Low-level bridge to the ``cloak-wasm`` linear-memory ABI.

Mirrors the ``WasmCloak`` helper in ``crates/wasm-parity/tests/parity.rs``
and the Node bridge in ``adapters/node/src/wasm-bridge.ts`` — same
protocol, Python idioms. All pointer/handle juggling is confined here;
the rest of the adapter works with ``bytes`` values.

Internal — not part of the public API. Use :func:`cloak_python.create_engine`.
"""

from __future__ import annotations

import ctypes
import json
import os
import struct
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, NoReturn, cast

import wasmtime

__all__ = ["CloakError", "WasmBridge"]

# Exports resolved from the WASM instance, in call order below.
_FUNC_EXPORTS = (
    "cloakwasm_alloc",
    "cloakwasm_dealloc",
    "cloakwasm_engine_new",
    "cloakwasm_engine_free",
    "cloakwasm_session_new",
    "cloakwasm_session_free",
    "cloakwasm_push",
    "cloakwasm_finish",
    "cloakwasm_finish_stats",
    "cloakwasm_redact",
    "cloakwasm_buf_free",
    "cloakwasm_last_error",
)


class CloakError(Exception):
    """Error raised by the cloak engine or its WASM bridge."""


class _FastFunc:
    """Cached-arity caller for the i32-only cloak ABI.

    wasmtime-py's ``Func.__call__`` re-fetches the function's type
    through FFI on every invocation (~20 µs/call on Apple Silicon),
    which dwarfs the actual WASM work. The cloak ABI is i32-only, so we
    resolve the signature once and drive ``wasmtime_func_call``
    directly with raw ``wasmtime_val_t`` arrays.

    This leans on wasmtime-py internals (``_ffi``, ``Store._context``,
    ``Func._func``) — acceptable because uv.lock pins the exact version
    and :func:`_make_caller` falls back to the stock (slow but public)
    call path if construction fails after a wasmtime-py bump.
    """

    def __init__(self, func: wasmtime.Func, store: wasmtime.Store) -> None:
        ty = func.type(store)
        params, results = ty.params, ty.results
        if len(results) > 1 or any(str(t) != "i32" for t in (*params, *results)):
            raise TypeError("fast path requires an i32-only signature")
        self._store = store
        self._n_params = len(params)
        self._n_results = len(results)
        # Probe the internals once so _make_caller can fall back early.
        self._ffi = wasmtime._ffi  # type: ignore[attr-defined]
        self._trap_type = ctypes.POINTER(self._ffi.wasm_trap_t)
        # Pre-built, reused per call (the bridge is single-threaded by
        # contract). Param kinds never change — set them once.
        self._func_ref = ctypes.byref(func._func)
        self._params = (self._ffi.wasmtime_val_t * max(self._n_params, 1))()
        for i in range(self._n_params):
            self._params[i].kind = self._ffi.WASMTIME_I32.value
        self._results = (self._ffi.wasmtime_val_t * max(self._n_results, 1))()
        self._trap = self._trap_type()

    def __call__(self, *args: int) -> int:
        ffi = self._ffi
        if len(args) != self._n_params:
            raise TypeError(f"expected {self._n_params} arguments, got {len(args)}")
        params = self._params
        for i, value in enumerate(args):
            params[i].of.i32 = value
        trap = self._trap
        error = ffi.wasmtime_func_call(
            self._store._context(),
            self._func_ref,
            params,
            self._n_params,
            self._results,
            self._n_results,
            ctypes.byref(trap),
        )
        if error:
            raise wasmtime.WasmtimeError._from_ptr(error)  # type: ignore[attr-defined]
        if trap:
            self._trap = self._trap_type()  # the raised Trap consumes this one
            raise wasmtime.Trap._from_ptr(trap)  # type: ignore[attr-defined]
        if self._n_results == 0:
            return 0
        return cast(int, self._results[0].of.i32)


def _make_caller(
    func: wasmtime.Func, store: wasmtime.Store
) -> Callable[..., int]:
    """Wrap a WASM export in the fast i32 caller, or the stock path.

    The fallback keeps the adapter correct (just slower) if wasmtime-py
    internals shift under the fast path.
    """
    try:
        return _FastFunc(func, store)
    except Exception:

        def slow(*args: int) -> int:
            result = func(store, *args)
            return 0 if result is None else cast(int, result)

        return slow


def _wasm_path() -> Path:
    """Resolve the ``.wasm`` artifact path.

    Priority: ``CLOAK_WASM_PATH`` env var, then the standard cargo
    release output relative to this file's location in the repo
    (``src/cloak_python/_bridge.py`` → four parents up = repo root).
    """
    env_path = os.environ.get("CLOAK_WASM_PATH")
    if env_path:
        return Path(env_path)
    return (
        Path(__file__).resolve().parents[4]
        / "target/wasm32-wasip1/release/cloak_wasm.wasm"
    )


class WasmBridge:
    """One instantiated ``cloak-wasm`` module plus its linear-memory helpers.

    Not thread-safe: the WASM module keeps take-once error/stats slots in
    thread-local storage and a single wasmtime ``Store`` must not be used
    from multiple threads.
    """

    def __init__(
        self,
        store: wasmtime.Store,
        memory: wasmtime.Memory,
        funcs: dict[str, Callable[..., int]],
    ) -> None:
        self._store = store
        self._memory = memory
        self._funcs = funcs

    @classmethod
    def create(cls, env: Mapping[str, str] | None = None) -> WasmBridge:
        """Load the WASM module and initialize the WASI reactor.

        :param env: Environment variables visible to the WASM module.
                    Defaults to ``os.environ`` — the digest key is read
                    from here via ``env:CLOAK_DIGEST_KEY`` in the config.
        """
        artifact = _wasm_path()
        if not artifact.is_file():
            raise CloakError(
                f"cloak_wasm.wasm not found at {artifact} — build it with "
                '`RUSTFLAGS="-Ctarget-feature=+simd128" cargo build -p cloak-wasm '
                "--target wasm32-wasip1 --release` or set CLOAK_WASM_PATH"
            )

        engine = wasmtime.Engine()
        module = wasmtime.Module.from_file(engine, artifact)

        wasi = wasmtime.WasiConfig()
        wasi.env = [(k, v) for k, v in (os.environ if env is None else env).items()]
        wasi.inherit_stderr()

        store = wasmtime.Store(engine)
        store.set_wasi(wasi)

        linker = wasmtime.Linker(engine)
        linker.define_wasi()
        instance = linker.instantiate(store, module)
        exports = instance.exports(store)

        # Reactor init: wasmtime-py does not run `_initialize` on
        # instantiation (unlike Node's `wasi.initialize`). Call it when
        # exported; tolerate absence.
        init = exports.get("_initialize")
        if isinstance(init, wasmtime.Func):
            init(store)

        memory = exports.get("memory")
        if not isinstance(memory, wasmtime.Memory):
            raise CloakError("WASM module does not export linear memory")

        funcs: dict[str, Callable[..., int]] = {}
        for name in _FUNC_EXPORTS:
            func = exports.get(name)
            if not isinstance(func, wasmtime.Func):
                raise CloakError(f"WASM module does not export function {name}")
            funcs[name] = _make_caller(func, store)

        return cls(store, memory, funcs)

    def _call(self, name: str, *args: int) -> int:
        """Call a WASM export returning an i32/pointer (0 when void)."""
        return self._funcs[name](*args)

    # ── Linear memory helpers ──────────────────────────────────────

    def write_bytes(self, data: bytes) -> tuple[int, int]:
        """Allocate + copy bytes into WASM linear memory.

        Returns ``(ptr, alloc_size)`` — use ``alloc_size`` for dealloc.
        Always allocates at least 1 byte so dealloc size is never 0.
        """
        alloc_size = max(len(data), 1)
        ptr = self._call("cloakwasm_alloc", alloc_size)
        if ptr == 0:
            raise CloakError(f"WASM alloc failed for {alloc_size} bytes")
        if data:
            self._memory.write(self._store, data, ptr)
        return ptr, alloc_size

    def read_buf_result(self, result_ptr: int) -> bytes:
        """Read a ``BufResult { ptr: u32, len: u32 }`` from linear memory.

        Copies the data out before any further WASM call can move memory.
        """
        header = self._memory.read(self._store, result_ptr, result_ptr + 8)
        data_ptr, data_len = struct.unpack("<II", header)
        if data_len == 0:
            return b""
        return bytes(self._memory.read(self._store, data_ptr, data_ptr + data_len))

    def buf_free(self, result_ptr: int) -> None:
        """Free a ``BufResult`` and its data buffer. Null-safe."""
        if result_ptr == 0:
            return
        self._call("cloakwasm_buf_free", result_ptr)

    def dealloc(self, ptr: int, size: int) -> None:
        """Dealloc a region previously returned by :meth:`write_bytes`."""
        self._call("cloakwasm_dealloc", ptr, size)

    # ── Error retrieval ────────────────────────────────────────────

    def last_error(self) -> str | None:
        """Read and consume the last WASM error message."""
        ptr = self._call("cloakwasm_last_error")
        if ptr == 0:
            return None
        data = self.read_buf_result(ptr)
        self.buf_free(ptr)
        return data.decode("utf-8")

    def raise_last_error(self, context: str) -> NoReturn:
        """Read the last error and raise.

        Call after any WASM function that signals failure via a
        null/zero return.
        """
        err = self.last_error()
        raise CloakError(
            f"{context}: {err}" if err else f"{context} (no error message)"
        )

    # ── Engine lifecycle ───────────────────────────────────────────

    def engine_new(self, config_toml: str) -> int:
        data = config_toml.encode("utf-8")
        ptr, alloc_size = self.write_bytes(data)
        handle = self._call("cloakwasm_engine_new", ptr, len(data))
        self.dealloc(ptr, alloc_size)
        if handle == 0:
            self.raise_last_error("engine_new")
        return handle

    def engine_free(self, handle: int) -> None:
        rc = self._call("cloakwasm_engine_free", handle)
        if rc == 0:
            self.raise_last_error("engine_free")

    # ── Session lifecycle ──────────────────────────────────────────

    def session_new(self, engine_handle: int) -> int:
        handle = self._call("cloakwasm_session_new", engine_handle)
        if handle == 0:
            self.raise_last_error("session_new")
        return handle

    def session_free(self, handle: int) -> None:
        rc = self._call("cloakwasm_session_free", handle)
        if rc == 0:
            self.raise_last_error("session_free")

    def push(self, session_handle: int, data: bytes) -> bytes:
        ptr, alloc_size = self.write_bytes(data)
        result_ptr = self._call("cloakwasm_push", session_handle, ptr, len(data))
        self.dealloc(ptr, alloc_size)
        if result_ptr == 0:
            self.raise_last_error("push")
        output = self.read_buf_result(result_ptr)
        self.buf_free(result_ptr)
        return output

    def finish(self, session_handle: int) -> bytes:
        result_ptr = self._call("cloakwasm_finish", session_handle)
        if result_ptr == 0:
            self.raise_last_error("finish")
        output = self.read_buf_result(result_ptr)
        self.buf_free(result_ptr)
        return output

    def finish_stats(self) -> dict[str, Any] | None:
        """Read the stats stashed by the last ``finish``/``redact``. Take-once."""
        ptr = self._call("cloakwasm_finish_stats")
        if ptr == 0:
            return None
        data = self.read_buf_result(ptr)
        self.buf_free(ptr)
        return cast(dict[str, Any], json.loads(data.decode("utf-8")))

    def redact(self, engine_handle: int, data: bytes) -> bytes:
        ptr, alloc_size = self.write_bytes(data)
        result_ptr = self._call("cloakwasm_redact", engine_handle, ptr, len(data))
        self.dealloc(ptr, alloc_size)
        if result_ptr == 0:
            self.raise_last_error("redact")
        output = self.read_buf_result(result_ptr)
        self.buf_free(result_ptr)
        return output
