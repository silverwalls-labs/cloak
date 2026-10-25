// High-level cloak engine and session API.
//
// Wraps the WASM bridge in a Go-idiomatic interface: []byte in/out,
// errors instead of exceptions, io.Closer for disposal.

package cloak

import (
	"context"
	"sync"
)

// ── Types ──────────────────────────────────────────────────────────

// Stats is the per-stream statistics returned by Finish and Redact.
type Stats struct {
	// BytesProcessed is the total bytes pushed through the stream.
	BytesProcessed int `json:"bytes_processed"`
	// Matches maps rule ID → match count.
	Matches map[string]int `json:"matches"`
}

// RedactResult is the output of a one-shot Redact or a Finish.
type RedactResult struct {
	// Output is the redacted bytes.
	Output []byte
	// Stats is the per-stream statistics (same shape for both paths).
	Stats Stats
}

// ── Options ────────────────────────────────────────────────────────

type engineOptions struct {
	config     *Config
	configTOML *string
	env        map[string]string
	wasmBytes  []byte
}

// Option configures CreateEngine.
type Option func(*engineOptions)

// WithConfig sets the engine configuration (serialized to TOML
// internally). Mutually exclusive with WithConfigTOML.
func WithConfig(config Config) Option {
	return func(o *engineOptions) { o.config = &config }
}

// WithConfigTOML passes a raw TOML config string through unchanged.
// Mutually exclusive with WithConfig.
func WithConfigTOML(toml string) Option {
	return func(o *engineOptions) { o.configTOML = &toml }
}

// WithEnv overrides the environment visible to the WASM module —
// this is how `env:CLOAK_DIGEST_KEY` is resolved. Defaults to the
// host process environment.
func WithEnv(env map[string]string) Option {
	return func(o *engineOptions) { o.env = env }
}

// WithWASM supplies the artifact bytes directly (e.g. from go:embed)
// instead of resolving CLOAK_WASM_PATH / the repo-root build output.
func WithWASM(wasmBytes []byte) Option {
	return func(o *engineOptions) { o.wasmBytes = wasmBytes }
}

// ── Factory ────────────────────────────────────────────────────────

// CreateEngine loads and compiles the WASM module and builds an
// engine from the configured ruleset. Call with no options for the
// default config (ephemeral digest key, all rules enabled).
//
// The context covers compilation/instantiation and every later call
// into the module — use context.Background() unless you need
// cancellation.
//
// Example:
//
//	engine, err := cloak.CreateEngine(ctx, cloak.WithConfig(cloak.Config{
//		Redaction: cloak.RedactionConfig{DigestKey: "env:CLOAK_DIGEST_KEY"},
//	}))
//	if err != nil { ... }
//	defer engine.Close()
//	res, err := engine.Redact([]byte("token=ghp_AAAA...AAAA"))
func CreateEngine(ctx context.Context, opts ...Option) (*Engine, error) {
	var o engineOptions
	for _, opt := range opts {
		opt(&o)
	}

	toml := ""
	switch {
	case o.config != nil && o.configTOML != nil:
		return nil, cloakErrorf("WithConfig and WithConfigTOML are mutually exclusive")
	case o.configTOML != nil:
		toml = *o.configTOML
	case o.config != nil:
		serialized, err := ConfigToTOML(*o.config)
		if err != nil {
			return nil, err
		}
		toml = serialized
	}

	wasmBytes := o.wasmBytes
	if wasmBytes == nil {
		loaded, err := loadWasmBytes()
		if err != nil {
			return nil, err
		}
		wasmBytes = loaded
	}

	b, err := newBridge(ctx, wasmBytes, o.env)
	if err != nil {
		return nil, err
	}

	handle, err := b.engineNew(toml)
	if err != nil {
		_ = b.close()
		return nil, err
	}
	return &Engine{bridge: b, handle: handle}, nil
}

// ── Engine ─────────────────────────────────────────────────────────

// Engine is a compiled cloak engine — create sessions from it.
//
// Safe for concurrent use: the WASM module keeps take-once
// error/stats slots, so the engine serializes every operation
// (its sessions' included) behind one mutex.
type Engine struct {
	mu     sync.Mutex
	bridge *bridge
	handle uint32
	closed bool
}

func errEngineClosed() error { return &CloakError{msg: "engine is closed"} }

// Redact is the one-shot convenience: redact a complete buffer in one
// call. Equivalent to Session → Push(all) → Finish but without the
// session lifecycle. Returns both the redacted output and per-stream
// stats.
func (e *Engine) Redact(input []byte) (RedactResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return RedactResult{}, errEngineClosed()
	}
	output, err := e.bridge.redact(e.handle, input)
	if err != nil {
		return RedactResult{}, err
	}
	stats, err := e.bridge.finishStats()
	if err != nil {
		return RedactResult{}, err
	}
	return RedactResult{Output: output, Stats: stats}, nil
}

// Session creates a new scanning session for streaming redaction.
//
// Sessions are cheap — one per stream/request. The engine must
// outlive all its sessions.
func (e *Engine) Session() (*Session, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, errEngineClosed()
	}
	handle, err := e.bridge.sessionNew(e.handle)
	if err != nil {
		return nil, err
	}
	return &Session{engine: e, handle: handle}, nil
}

// Close releases the engine and its WASM resources (io.Closer).
//
// Fails if any sessions created from this engine are still live —
// finish or abort them first. Closing an already-closed engine
// returns an error.
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return errEngineClosed()
	}
	if err := e.bridge.engineFree(e.handle); err != nil {
		return err
	}
	e.closed = true
	return e.bridge.close()
}

// ── Session ────────────────────────────────────────────────────────

// Session is a scanning session — per-stream state, cheap to create.
//
// A session must not be used from multiple goroutines concurrently;
// distinct sessions of one engine may be (the engine serializes WASM
// access).
type Session struct {
	engine   *Engine
	handle   uint32
	consumed bool
}

func errSessionConsumed() error {
	return &CloakError{msg: "session already consumed (finished or aborted)"}
}

// Push sends a chunk through the scanner.
//
// Returns redacted bytes flushed by this push — possibly empty while
// bytes are held in the carry-over window.
func (s *Session) Push(input []byte) ([]byte, error) {
	s.engine.mu.Lock()
	defer s.engine.mu.Unlock()
	if s.consumed {
		return nil, errSessionConsumed()
	}
	if s.engine.closed {
		return nil, errEngineClosed()
	}
	return s.engine.bridge.push(s.handle, input)
}

// Finish flushes the carry-over and returns redacted output + stats.
//
// The session is consumed — Push/Finish after this call fail.
func (s *Session) Finish() (RedactResult, error) {
	s.engine.mu.Lock()
	defer s.engine.mu.Unlock()
	if s.consumed {
		return RedactResult{}, errSessionConsumed()
	}
	if s.engine.closed {
		return RedactResult{}, errEngineClosed()
	}
	// The WASM module always consumes the handle on finish — success
	// or failure — so mark consumed before the call.
	s.consumed = true
	output, err := s.engine.bridge.finish(s.handle)
	if err != nil {
		return RedactResult{}, err
	}
	stats, err := s.engine.bridge.finishStats()
	if err != nil {
		return RedactResult{}, err
	}
	return RedactResult{Output: output, Stats: stats}, nil
}

// Abort drops the session without flushing.
//
// Releases carry-over and the session handle — use when a stream is
// abandoned mid-way. Idempotent: aborting a consumed session is a
// no-op.
func (s *Session) Abort() error {
	s.engine.mu.Lock()
	defer s.engine.mu.Unlock()
	if s.consumed {
		return nil
	}
	if s.engine.closed {
		return errEngineClosed()
	}
	s.consumed = true
	return s.engine.bridge.sessionFree(s.handle)
}
