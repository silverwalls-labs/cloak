# cloak Go adapter — Embed cloak today (Go)

Go adapter for [cloak](https://github.com/silverwalls-labs/cloak) —
guarantee-grade secrets and PII redaction via WASM, driven by
[wazero](https://wazero.io) (pure Go, **no cgo**). One runtime
dependency. This is the supported Go path until the native `cloak-go`
binding lands (E7/E8 in [docs/06-embedding.md](../../docs/06-embedding.md)).

```sh
go get github.com/silverwalls-labs/cloak/adapters/go
```

## Prerequisites

- **Go 1.25+**
- **cloak WASM artifact** — built from the repo or downloaded from CI:
  ```sh
  RUSTFLAGS="-Ctarget-feature=+simd128" \
    cargo build -p cloak-wasm --target wasm32-wasip1 --release
  ```
  Set `CLOAK_WASM_PATH` to override the artifact location (defaults to
  `target/wasm32-wasip1/release/cloak_wasm.wasm` relative to the repo
  root — the repo-relative fallback works for `go run`/`go test` from
  the source tree). Binaries deployed elsewhere pass the bytes
  directly with `WithWASM` (pairs well with `go:embed`).

## Quick start

Set the digest key first — with `CLOAK_DIGEST_KEY` unset the engine
still works but falls back to an ephemeral per-process key, so tags
don't correlate across runs:

```sh
export CLOAK_DIGEST_KEY="my-stable-key"
```

```go
package main

import (
	"context"
	"fmt"
	"log"

	cloak "github.com/silverwalls-labs/cloak/adapters/go"
)

func main() {
	// Create an engine with a stable digest key for cross-run correlation.
	engine, err := cloak.CreateEngine(context.Background(), cloak.WithConfig(cloak.Config{
		Redaction: cloak.RedactionConfig{DigestKey: "env:CLOAK_DIGEST_KEY"},
	}))
	if err != nil {
		log.Fatal(err)
	}

	// One-shot: bytes in, (output, stats) out.
	res, err := engine.Redact([]byte("token=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"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", res.Output)
	// → token=[CLOAK:github-token:xxxx]
	fmt.Println(res.Stats.Matches) // map[github-token:1]

	if err := engine.Close(); err != nil {
		log.Fatal(err)
	}
}
```

## Streaming

Use `Writer` to redact a live byte stream (the `io.Writer`
stdout/stderr hook):

```go
engine, _ := cloak.CreateEngine(ctx, cloak.WithConfig(cfg))

// Pipe: stdin → cloak → stdout
w, err := cloak.NewWriter(engine, os.Stdout)
if err != nil {
	log.Fatal(err)
}
if _, err := io.Copy(w, os.Stdin); err != nil {
	_ = w.Abort() // broken pipe — drop without flushing
	log.Fatal(err)
}
if err := w.Close(); err != nil { // flushes the carry-over tail
	log.Fatal(err)
}
fmt.Fprintln(os.Stderr, w.Stats().Matches) // populated by Close — stderr, so the pipe stays clean
```

Note that `Write` returns the number of *input* bytes consumed per the
`io.Writer` contract — the carry-over window means the bytes emitted
to the target may differ. Any write failure aborts the whole writer
(terminal state) so `engine.Close` is never blocked.

## Session lifecycle

For chunked redaction, use sessions directly:

```go
session, err := engine.Session()
if err != nil {
	log.Fatal(err)
}
part1, _ := session.Push([]byte("first chunk "))
part2, _ := session.Push([]byte("second chunk\n"))
tail, _ := session.Finish()

full := append(append(part1, part2...), tail.Output...)
fmt.Printf("Processed %d bytes, %d rules matched\n",
	tail.Stats.BytesProcessed, len(tail.Stats.Matches))
_ = full
```

Abort a session without flushing (abandoned stream):

```go
session, _ := engine.Session()
session.Push(someData)
session.Abort() // drops carry-over, releases handle
```

A finished or aborted session is consumed — further `Push`/`Finish`
returns a `*CloakError`. `Close()` fails while sessions are still
live; finish or abort them first.

**Concurrency**: the engine is safe for concurrent use — the WASM
module keeps take-once error/stats slots, so the engine serializes
every operation (its sessions' included) behind one mutex. A single
`Session` must still stay on one goroutine; concurrent streams get a
session each.

## Configuration

Pass a `Config` — it's serialized to TOML internally (fields map 1:1):

```go
engine, err := cloak.CreateEngine(ctx, cloak.WithConfig(cloak.Config{
	Redaction: cloak.RedactionConfig{
		DigestKey: "env:CLOAK_DIGEST_KEY", // read from WASM env
	},
	Rules: map[string]cloak.RuleConfig{
		"phone-intl": {Enabled: cloak.Bool(false)}, // disable a rule
	},
}))
```

Or pass a raw TOML string:

```go
engine, err := cloak.CreateEngine(ctx,
	cloak.WithConfigTOML("[redaction]\ndigest_key = \"env:CLOAK_DIGEST_KEY\"\n"))
```

Or omit config entirely for the default (ephemeral key, all rules on):

```go
engine, err := cloak.CreateEngine(ctx)
```

`WithEnv` overrides the environment visible to the WASM module
(defaults to the host process environment) — this is how
`env:CLOAK_DIGEST_KEY` is resolved:

```go
engine, err := cloak.CreateEngine(ctx, cloak.WithConfig(cfg),
	cloak.WithEnv(map[string]string{"CLOAK_DIGEST_KEY": "my-key"}))
```

`WithWASM` supplies the artifact bytes directly instead of resolving
`CLOAK_WASM_PATH` — useful with `go:embed` for self-contained
binaries. Copy `cloak_wasm.wasm` into your package's directory first
(the build output under `target/` can't be embedded from an unrelated
location), and note the blank `embed` import the pattern requires:

```go
import _ "embed"

//go:embed cloak_wasm.wasm
var cloakWasm []byte

engine, err := cloak.CreateEngine(ctx, cloak.WithWASM(cloakWasm))
```

## Logging integration (log/slog)

`Handler` redacts every formatted record before it reaches the stream
— one-shot per record, so no carry-over withholds a record tail:

```go
engine, _ := cloak.CreateEngine(ctx, cloak.WithConfig(cfg))

logger := slog.New(cloak.NewHandler(engine, os.Stdout, nil))
logger.Info("auth", "token", someSecret)
// stdout: time=... level=INFO msg=auth token=[CLOAK:github-token:xxxx]
```

`NewJSONHandler` is the same with `slog.NewJSONHandler` formatting.
The caller owns the engine — close it after the logger is done.

## API reference

### `CreateEngine(ctx, opts...) (*Engine, error)`

Options: `WithConfig(Config)`, `WithConfigTOML(string)` (mutually
exclusive), `WithEnv(map[string]string)`, `WithWASM([]byte)`.

### `Engine`

| Method | Description |
|---|---|
| `Redact(input []byte)` | One-shot redaction. Returns `RedactResult{Output []byte, Stats Stats}`. |
| `Session()` | Create a streaming session. |
| `Close()` | Free the engine (`io.Closer`). Fails if sessions are still live. |

### `Session`

| Method | Description |
|---|---|
| `Push(input []byte)` | Push a chunk. Returns redacted bytes flushed (may be empty). |
| `Finish()` | Flush and return `RedactResult`. Consumes the session. |
| `Abort()` | Drop without flushing. Idempotent. |

### `Stats`

```go
type Stats struct {
	BytesProcessed int            `json:"bytes_processed"`
	Matches        map[string]int `json:"matches"` // rule-id → count
}
```

### `Writer` / `NewWriter(engine, target) (*Writer, error)`

`io.WriteCloser`. `Write` streams through a session; `Close` finishes
it, writes the tail, and populates `Stats()`; `Abort` drops without
flushing.

### `Handler` / `NewHandler(engine, target, opts)` / `NewJSONHandler(...)`

`log/slog.Handler` that redacts each formatted record one-shot and
writes it to the target writer.

## Running tests

```sh
# Build the WASM artifact first
RUSTFLAGS="-Ctarget-feature=+simd128" \
  cargo build -p cloak-wasm --target wasm32-wasip1 --release

# Generate test vectors (only needed when rules change)
cargo run --example export-vectors -p cloak-core \
  > adapters/go/testdata/vectors.json

# Run all tests + gates (same checks as the go-parity CI job)
cd adapters/go
go test ./...
test -z "$(gofmt -l .)" && go vet ./...
```

## Benchmarks

`go run ./bench` reproduces the throughput receipts — see
[docs/benchmarks/receipts-wasm-e4-go.md](../../docs/benchmarks/receipts-wasm-e4-go.md).

## License

MIT — see [LICENSE](../../LICENSE).
