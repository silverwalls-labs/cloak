# cloak-py — native Python binding (E5)

Native [pyo3](https://pyo3.rs) binding over `cloak-core`: the same
conceptual API as every cloak binding (`docs/06-embedding.md`), without
the WASM-runtime overhead of the [`cloak-python`
adapter](../../adapters/python/) — no ctypes FFI floor, no linear-memory
copies, and the GIL is released while a scan runs. Receipts:
[`docs/benchmarks/receipts-native-e5-python.md`](../../docs/benchmarks/receipts-native-e5-python.md).

Ships as **abi3 wheels** (`cp313-abi3`, one per platform: linux
x86-64/aarch64, macos aarch64) built by the `cloak-py-wheels` CI job.
Never published to PyPI — install a wheel from CI artifacts, or build
from the repo:

```sh
cd crates/cloak-py
uv sync --locked          # builds cloak_py._native via maturin (release)
# or a distributable wheel:
uvx maturin build --release --locked --out dist
```

## Usage

Bytes in, bytes out — `str` input is encoded as UTF-8 at the boundary,
output is always `bytes` (binding rule #1, `docs/06-embedding.md`):

```python
from cloak_py import create_engine

engine = create_engine(
    {
        "redaction": {"digest_key": "env:CLOAK_DIGEST_KEY"},
    }
)

# One-shot
output, stats = engine.redact(b"token=ghp_AAAA...AAAA\n")

# Streaming (per-request/stream sessions are cheap)
session = engine.session()
out = session.push(chunk)  # may withhold carry-over bytes
tail, stats = session.finish()  # flush + per-rule counts

engine.dispose()  # refuses while sessions are live
```

### stdout/stderr hook (file-like wrapper)

```python
import sys
from cloak_py import CloakWriter, create_engine

engine = create_engine()
with CloakWriter(engine, sys.stdout.buffer) as out:
    out.write(b"token=ghp_AAAA...AAAA\n")
engine.dispose()
```

### `logging` handler

```python
import logging
from cloak_py import CloakHandler, create_engine

engine = create_engine()
logging.basicConfig(handlers=[CloakHandler(engine)], level=logging.INFO, force=True)
logging.info("token=%s", some_secret)  # redacted on the way out
```

## Threading contract

- **Engine**: shareable across threads; the GIL is released during
  `redact`/`push`/`finish`, so scans from multiple threads run in
  parallel.
- **Session**: movable across threads, but one caller at a time —
  concurrent calls into the same session raise `RuntimeError` (pyo3's
  runtime borrow check).
- **`create_engine(..., env=...)`** swaps `os.environ` during
  construction (the native engine resolves `env:`-indirected digest
  keys exactly once, in its constructor); don't call it concurrently
  with code reading the environment.

## Errors and panics

Expected failures (invalid config, engine build failure, lifecycle
misuse) raise `cloak_py.CloakError`. A Rust panic is a bug: it crosses
the boundary as `pyo3.PanicException` (a `BaseException`), deliberately
not remapped so it escapes `except Exception` handlers such as the
logging hot path.

## Development

```sh
uv sync --locked               # build + install into .venv (release profile)
uv run pytest                  # parity vectors, streaming, hooks, config, threading
uv run ruff check . && uv run ruff format --check .
uv run mypy
uv run python bench/throughput.py   # receipts bench (same corpus as E1/E2/E3/E4)
```

The parity fixture `tests/fixtures/vectors.json` is generated from core
(`cargo run --example export-vectors -p cloak-core`) and checked for
staleness in CI, same as every adapter. The Rust layer
(`src/lib.rs`) has no Rust-side tests by design — all behavior is
covered by the pytest suite against the built module.
