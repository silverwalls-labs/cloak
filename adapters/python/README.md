# cloak-python — Embed cloak today (Python)

Python adapter for [cloak](https://github.com/silverwalls-labs/cloak) —
guarantee-grade secrets and PII redaction via WASM. One runtime
dependency ([wasmtime](https://pypi.org/project/wasmtime/)).

## Prerequisites

- **Python 3.13+**, with [uv](https://docs.astral.sh/uv/) for the dev
  workflow
- **cloak WASM artifact** — built from the repo or downloaded from CI:
  ```sh
  RUSTFLAGS="-Ctarget-feature=+simd128" \
    cargo build -p cloak-wasm --target wasm32-wasip1 --release
  ```
  Set `CLOAK_WASM_PATH` to override the artifact location (defaults to
  `target/wasm32-wasip1/release/cloak_wasm.wasm` relative to the repo
  root).

## Quick start

```python
from cloak_python import create_engine

# Create an engine with a stable digest key for cross-run correlation.
engine = create_engine({
    "redaction": {"digest_key": "env:CLOAK_DIGEST_KEY"},
})

# One-shot: str or bytes in, (output, stats) out.
output, stats = engine.redact("token=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")
print(output.decode())
# → token=[CLOAK:github-token:xxxx]
print(stats["matches"])  # {'github-token': 1}

engine.dispose()
```

Engines are context managers too:

```python
with create_engine() as engine:
    output, _ = engine.redact(b"...")
```

## Streaming

Use `CloakWriter` to redact a live byte stream (stdout/stderr hook):

```python
import sys
from cloak_python import create_engine, CloakWriter

engine = create_engine({"redaction": {"digest_key": "env:CLOAK_DIGEST_KEY"}})

# Pipe: stdin → cloak → stdout
with CloakWriter(engine, sys.stdout.buffer) as redactor:
    while chunk := sys.stdin.buffer.read(64 * 1024):
        redactor.write(chunk)
```

`CloakWriter` is an `io.RawIOBase`, so it wraps cleanly in
`io.BufferedWriter` or `io.TextIOWrapper` (e.g. as a `print` target).
Note that `write()` returns the number of input bytes *consumed* — the
carry-over window means the bytes emitted to the target may differ.

## Configuration

Pass a dict — it's serialized to TOML internally (keys map 1:1):

```python
engine = create_engine({
    "redaction": {
        "digest_key": "env:CLOAK_DIGEST_KEY",  # read from WASM env
    },
    "rules": {
        "phone-intl": {"enabled": False},      # disable a rule
    },
})
```

Or pass a raw TOML string:

```python
engine = create_engine('[redaction]\ndigest_key = "env:CLOAK_DIGEST_KEY"\n')
```

Or omit config entirely for the default (ephemeral key, all rules on):

```python
engine = create_engine()
```

The second argument overrides the environment visible to the WASM
module (defaults to `os.environ`) — this is how `env:CLOAK_DIGEST_KEY`
is resolved:

```python
engine = create_engine(config, {"CLOAK_DIGEST_KEY": "my-key"})
```

## Session lifecycle

For streaming (chunked) redaction, use sessions directly:

```python
session = engine.session()

part1 = session.push("first chunk ")
part2 = session.push("second chunk\n")
tail, stats = session.finish()

full = part1 + part2 + tail
print(f"Processed {stats['bytes_processed']} bytes, "
      f"{len(stats['matches'])} rules matched")
```

Abort a session without flushing (abandoned stream):

```python
session = engine.session()
session.push(some_data)
session.abort()  # drops carry-over, releases handle
```

A finished or aborted session is consumed — further `push`/`finish`
raises `CloakError`. `dispose()` fails while sessions are still live;
finish or abort them first.

**Not thread-safe**: the WASM module keeps take-once error/stats slots
in thread-local storage, and a wasmtime store must stay on one thread.
Use one engine per thread, or guard every engine/session call with your
own lock.

## Logging integration

### `CloakHandler` (stdlib logging)

Redacts every formatted record before it reaches the stream. Good for
development and simple deployments:

```python
import logging
from cloak_python import create_engine, CloakHandler

engine = create_engine({"redaction": {"digest_key": "env:CLOAK_DIGEST_KEY"}})

handler = CloakHandler(engine)  # writes to sys.stdout.buffer
logging.basicConfig(handlers=[handler], level=logging.INFO)

logging.info("token=%s", some_secret)
# stdout: token=[CLOAK:github-token:xxxx]
```

### Off-thread with `QueueListener`

Keeps redaction off the application threads — the analog of the Node
worker-thread transport. The engine lives entirely on the listener
thread:

```python
import logging, logging.handlers, queue
from cloak_python import create_engine, CloakHandler

engine = create_engine({"redaction": {"digest_key": "env:CLOAK_DIGEST_KEY"}})

log_queue: queue.Queue = queue.Queue()
listener = logging.handlers.QueueListener(log_queue, CloakHandler(engine))
listener.start()

logging.getLogger().addHandler(logging.handlers.QueueHandler(log_queue))
```

See [`examples/logging_queue.py`](examples/logging_queue.py) for the
full lifecycle (stop the listener before disposing the engine).

## API reference

### `create_engine(config=None, env=None) -> CloakEngine`

Create a cloak engine. `config` is a `CloakConfig` dict or a TOML
string. `env` overrides the environment variables visible to the WASM
module (defaults to `os.environ`).

### `CloakEngine`

| Method | Description |
|---|---|
| `redact(data)` | One-shot redaction. Accepts `str \| bytes \| bytearray \| memoryview`, returns `RedactResult(output: bytes, stats: CloakStats)`. |
| `session()` | Create a streaming session. |
| `dispose()` | Free the engine. Fails if sessions are still live. |

### `CloakSession`

| Method | Description |
|---|---|
| `push(data)` | Push a chunk. Returns redacted bytes flushed (may be empty). |
| `finish()` | Flush and return `RedactResult(output, stats)`. Consumes the session. |
| `abort()` | Drop without flushing. Idempotent. |

### `CloakStats`

```python
class CloakStats(TypedDict):
    bytes_processed: int
    matches: dict[str, int]  # rule-id → count
```

### `CloakWriter(engine, target, *, close_target=False)`

File-like binary writer (`io.RawIOBase`). `write()` streams through a
session; `close()` finishes it, writes the tail, and populates `.stats`;
`abort()` drops without flushing.

### `CloakHandler(engine, stream=None)`

`logging.Handler` that redacts each formatted record one-shot and writes
it to a binary stream (default `sys.stdout.buffer`).

## Running tests

```sh
# Build the WASM artifact first
RUSTFLAGS="-Ctarget-feature=+simd128" \
  cargo build -p cloak-wasm --target wasm32-wasip1 --release

# Generate test vectors (only needed when rules change)
cargo run --example export-vectors -p cloak-core \
  > adapters/python/tests/fixtures/vectors.json

# Run all tests + gates
cd adapters/python
uv sync
uv run pytest
uv run ruff check . && uv run ruff format --check .
uv run mypy
```

## License

MIT — see [LICENSE](../../LICENSE).
