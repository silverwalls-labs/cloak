// Package cloak embeds guarantee-grade secrets/PII redaction in Go
// applications via the shared cloak_wasm.wasm artifact, driven by
// wazero (pure Go, no cgo).
//
// This is the zero-cgo Go path; for native throughput use the cgo
// binding (crates/cloak-go, over the cloak-ffi C ABI — E7/E8 in
// docs/06-embedding.md). The API mirrors the Node and
// Python adapters: Engine(config) → Session() → Push(bytes) →
// Finish() → (bytes, stats), plus one-shot Redact — bytes in, bytes
// out, byte-identical to cloak-core for the shared vector corpus.
//
// The layer-1 stdout/stderr hook is Writer (an io.WriteCloser); the
// logging flavor is Handler (a log/slog.Handler).
package cloak

// Version is locked to cloak-core (docs/06-embedding.md §Versioning & CI).
const Version = "0.1.0"
