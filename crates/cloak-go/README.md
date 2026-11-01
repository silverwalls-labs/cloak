# cloak-go — Embed cloak today (Go, native)

Native Go binding for [cloak](https://github.com/silverwalls-labs/cloak)
— guarantee-grade secrets and PII redaction via cgo over the
[`cloak-ffi`](../cloak-ffi) C ABI (E7/E8 in
[docs/06-embedding.md](../../docs/06-embedding.md)). Zero Go
dependencies. ~2.7× the throughput of the wazero WASM path on the same
corpus, with fully concurrent engine use — receipts in
[docs/benchmarks/receipts-native-e8-go.md](../../docs/benchmarks/receipts-native-e8-go.md).

Prefer no cgo? Use the pure-Go WASM adapter
([`adapters/go`](../../adapters/go)) — same API, same byte-identical
outputs, no native library to build.

```sh
go get github.com/silverwalls-labs/cloak/crates/cloak-go
```

## Prerequisites

- **Go 1.26+** with cgo enabled (the default), and a C toolchain.
- **The cloak-ffi static library** — built from the repo:

  ```sh
  cargo build -p cloak-ffi --release
  ```

  The default build links `target/release/libcloak_ffi.a` by
  repo-relative path, which works for `go run`/`go test` from a source
  checkout (including consumers using a `replace` directive to one).
  Out-of-tree consumers can instead build with
  `-tags cloak_ffi_system` and point the linker at an installed
  library: `CGO_LDFLAGS="-L/path/to/lib" go build -tags cloak_ffi_system`
  (if that resolves to the shared library, runtime path rules apply —
  prefer the static archive).

  One Rust staticlib per final binary: linking a second Rust-derived
  `.a` into the same Go program collides on Rust runtime symbols.

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
	"fmt"
	"log"

	cloak "github.com/silverwalls-labs/cloak/crates/cloak-go"
)

func main() {
	// Create an engine with a stable digest key for cross-run correlation.
	engine, err := cloak.CreateEngine(cloak.WithConfig(cloak.Config{
		Redaction: cloak.RedactionConfig{DigestKey: "env:CLOAK_DIGEST_KEY"},
	}))
	if err != nil {
		log.Fatal(err)
	}
	defer engine.Close()

	// One-shot: bytes in, (output, stats) out.
	res, err := engine.Redact([]byte("token=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"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n%v\n", res.Output, res.Stats.Matches)

	// Streaming: session per stream; Push may withhold carry-over,
	// Finish flushes the tail and returns stats.
	session, err := engine.Session()
	if err != nil {
		log.Fatal(err)
	}
	out, _ := session.Push([]byte("chunk with key=AKIA"))
	tail, _ := session.Finish()
	fmt.Printf("%s%s\n", out, tail.Output)
}
```

Hooks (thin sugar — all correctness lives in core): `NewWriter(engine,
target)` is an `io.WriteCloser` that redacts everything written
through it (`examples/pipe`); `NewHandler`/`NewJSONHandler` are
`log/slog` handlers that redact every record (`examples/slog`).

## Migrating from the WASM adapter

The API is the same, minus the wazero-isms:

- **No `context.Context` on `CreateEngine`** — native construction is
  a synchronous, millisecond-scale call with nothing cancellable.
- **No `WithEnv`** — cloak-core reads the *real process environment*
  at `Engine::new` for `env:`-indirected digest keys. Set
  `CLOAK_DIGEST_KEY` with `os.Setenv` before `CreateEngine` (tests:
  `t.Setenv`). A faithful `WithEnv` would have to swap the process
  environment around the constructor, visible to every concurrent
  goroutine — rejected for a server library.
- **No `WithWASM`** — there is no WASM artifact; the build-time
  prerequisite is the static library above.

## Concurrency

An `Engine` is safe for fully concurrent use and — unlike the WASM
adapter — calls are **not serialized**: the C ABI reports errors
through per-call out-parameters and cloak-core's `Engine` is
Send+Sync, so concurrent `Redact` calls and sessions run in parallel
(an RWMutex read lock is the only shared state; `Close` takes the
write lock and so drains in-flight calls). A `Session` must be used by
at most one goroutine at a time, but may move between goroutines.

Lifecycle is explicit — no finalizers: `engine.Close()` (refuses,
retryably, while sessions are live), `session.Finish()` or
`session.Abort()`. A leaked unclosed engine leaks native memory.

## Benchmarks

`go run ./bench` reproduces the throughput receipts (build cloak-ffi
first; measure on AC power) — see
[docs/benchmarks/receipts-native-e8-go.md](../../docs/benchmarks/receipts-native-e8-go.md):
one-shot **97.8 MiB/s** vs 36.5 same-day wazero (2.7×), streaming
1 KiB **61.3 MiB/s** (2.7×), 256 B **24.7 MiB/s** (3.0×), with the cgo
boundary costing ≈1–2 µs per call (within ~4% of raw cloak-core on the
one-shot row).

## Testing

```sh
cargo build -p cloak-ffi --release
cd crates/cloak-go && go test -race ./...
```

The suite is the e2e tier for the native Go host: the full 247-vector
parity corpus one-shot and streamed (`testdata/vectors.json`,
freshness-gated in CI against `cargo run --example export-vectors`),
chunk-boundary invariance (same split algorithm as the Node/Python
suites), Writer/Handler hooks, config golden TOMLs, and the
concurrency contract under the race detector. The vendored
`include/cloak.h` is freshness-gated against cbindgen output in CI.
