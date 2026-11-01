// Package cloak embeds guarantee-grade secrets/PII redaction in Go
// applications natively, via cgo over the cloak-ffi C ABI (E7/E8 in
// docs/06-embedding.md).
//
// This is the native sibling of the pure-Go WASM adapter
// (github.com/silverwalls-labs/cloak/adapters/go — wazero, no cgo):
// same API, same byte-identical outputs for the shared vector corpus,
// several times the throughput (docs/benchmarks/receipts-native-e8-go.md).
// Pick this package when Go-native speed matters and cgo is acceptable;
// pick the adapter when it is not.
//
// The API mirrors the Node and Python bindings: Engine(config) →
// Session() → Push(bytes) → Finish() → (bytes, stats), plus one-shot
// Redact — bytes in, bytes out. The layer-1 stdout/stderr hook is
// Writer (an io.WriteCloser); the logging flavor is Handler (a
// log/slog.Handler).
//
// # Differences from the WASM adapter
//
//   - CreateEngine takes no context.Context: native engine construction
//     is a synchronous, millisecond-scale ruleset compile with nothing
//     cancellable — a context parameter would advertise cancellation
//     semantics that don't exist.
//   - No WithEnv option: cloak-core resolves `env:CLOAK_DIGEST_KEY`
//     from the real process environment at engine construction. Set the
//     variable with os.Setenv before CreateEngine (tests: t.Setenv).
//     A faithful WithEnv would have to swap os.Environ around the
//     constructor — process-globally visible to every concurrent
//     goroutine — which is unacceptable in a server library.
//   - No WithWASM option (there is no WASM artifact here); the build
//     prerequisite is the cloak-ffi static library — see the README.
//
// # Concurrency
//
// An Engine is safe for fully concurrent use — unlike the WASM adapter,
// calls are NOT serialized behind an engine-wide mutex: the C ABI
// reports errors through per-call out-parameters (no shared slots), and
// the underlying cloak-core Engine is Send+Sync. Concurrent Redact
// calls and sessions run in parallel. A Session must still be used by
// at most one goroutine at a time (it may move between goroutines).
package cloak

// Version is locked to cloak-core (docs/06-embedding.md §Versioning & CI).
const Version = "0.1.0"
