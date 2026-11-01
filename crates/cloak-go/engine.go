// High-level cloak engine and session API.
//
// Wraps the cgo bridge in a Go-idiomatic interface: []byte in/out,
// errors instead of status codes, io.Closer for disposal. Mirrors the
// WASM adapter's API (adapters/go) minus the wazero-isms — see doc.go
// for the deliberate deltas (no ctx, no WithEnv/WithWASM).

package cloak

import "sync"

// ── Types ──────────────────────────────────────────────────────────

// Stats is the per-stream statistics returned by Finish and Redact.
type Stats struct {
	// BytesProcessed is the total bytes pushed through the stream.
	BytesProcessed int `json:"bytes_processed"`
	// Matches maps rule ID → match count.
	Matches map[string]int `json:"matches"`
	// NearMisses maps rule ID → near-miss count (F13): candidates that
	// matched the rule's shape (prefix, length, character class) but
	// failed checksum validation (CRC32, Luhn). A spike from zero
	// signals upstream format drift. Nil when no near-miss occurred —
	// the core JSON omits the field when empty.
	NearMisses map[string]int `json:"near_misses,omitempty"`
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

// ── Factory ────────────────────────────────────────────────────────

// abiCheckOnce guards the one-time header-vs-library version probe.
var (
	abiCheckOnce sync.Once
	abiCheckErr  error
)

// CreateEngine compiles the configured ruleset into an engine. Call
// with no options for the default config (digest key from the
// CLOAK_DIGEST_KEY environment variable, ephemeral fallback, all rules
// enabled).
//
// Unlike the WASM adapter there is no context parameter: construction
// is a synchronous native call with nothing cancellable. And no
// WithEnv: `env:CLOAK_DIGEST_KEY` resolves from the real process
// environment — set it with os.Setenv before calling (see doc.go).
//
// Example:
//
//	engine, err := cloak.CreateEngine(cloak.WithConfig(cloak.Config{
//		Redaction: cloak.RedactionConfig{DigestKey: "env:CLOAK_DIGEST_KEY"},
//	}))
//	if err != nil { ... }
//	defer engine.Close()
//	res, err := engine.Redact([]byte("token=ghp_AAAA...AAAA"))
func CreateEngine(opts ...Option) (*Engine, error) {
	abiCheckOnce.Do(func() { abiCheckErr = abiVersionError() })
	if abiCheckErr != nil {
		return nil, abiCheckErr
	}

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

	ffi, err := ffiEngineNew(toml)
	if err != nil {
		return nil, err
	}
	return &Engine{ffi: ffi}, nil
}

// ── Engine ─────────────────────────────────────────────────────────

// Engine is a compiled cloak engine — create sessions from it.
//
// Safe for fully concurrent use: unlike the WASM adapter, calls are
// not serialized — the C ABI reports errors per call and cloak-core's
// Engine is Send+Sync, so concurrent Redact/Session calls only share
// an RWMutex read lock. Close takes the write lock, draining in-flight
// calls before freeing (the ABI's "free must not race other calls"
// rule, enforced Go-side).
type Engine struct {
	mu     sync.RWMutex
	ffi    *ffiEngine
	closed bool
}

func errEngineClosed() error { return &CloakError{msg: "engine is closed"} }

// Redact is the one-shot convenience: redact a complete buffer in one
// call. Equivalent to Session → Push(all) → Finish but without the
// session lifecycle. Returns both the redacted output and per-stream
// stats.
func (e *Engine) Redact(input []byte) (RedactResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.closed {
		return RedactResult{}, errEngineClosed()
	}
	output, stats, err := e.ffi.redact(input)
	if err != nil {
		return RedactResult{}, err
	}
	return RedactResult{Output: output, Stats: stats}, nil
}

// Session creates a new scanning session for streaming redaction.
//
// Sessions are cheap — one per stream/request. The engine must outlive
// all its sessions (Close refuses while any are live).
func (e *Engine) Session() (*Session, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.closed {
		return nil, errEngineClosed()
	}
	ffi, err := e.ffi.sessionNew()
	if err != nil {
		return nil, err
	}
	return &Session{engine: e, ffi: ffi}, nil
}

// Close releases the engine (io.Closer).
//
// Fails — retryably, the engine stays usable — while sessions created
// from it are still live: finish or abort them first. Closing an
// already-closed engine returns an error. Close blocks until in-flight
// Redact/Session calls drain (write lock), so it never races a scan.
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return errEngineClosed()
	}
	if err := e.ffi.free(); err != nil {
		// The live-session refusal leaves the engine valid (ptr still
		// set) — retryable. A caught panic in the ABI invalidates the
		// pointer and ffi.free poisons it (ptr nil): mark the engine
		// closed so a retried Close is "engine is closed", never a
		// re-free of a dead pointer.
		if !e.ffi.valid() {
			e.closed = true
		}
		return err
	}
	e.closed = true
	return nil
}

// ── Session ────────────────────────────────────────────────────────

// Session is a scanning session — per-stream state, cheap to create.
//
// A session must not be used from multiple goroutines concurrently
// (it may move between goroutines); distinct sessions of one engine
// may run fully in parallel.
type Session struct {
	// engine documents ownership and keeps the object graph honest;
	// no lock is taken on it — see Push.
	engine   *Engine
	ffi      *ffiSession
	consumed bool
}

func errSessionConsumed() error {
	return &CloakError{msg: "session already consumed (finished or aborted)"}
}

// Push sends a chunk through the scanner.
//
// Returns redacted bytes flushed by this push — possibly empty while
// bytes are held in the carry-over window.
//
// No engine lock or closed-check: the session holds a strong reference
// to the engine on the Rust side and Close refuses while it is live,
// so a closed engine is unreachable from a live session.
func (s *Session) Push(input []byte) ([]byte, error) {
	if s.consumed {
		return nil, errSessionConsumed()
	}
	return s.ffi.push(input)
}

// Finish flushes the carry-over and returns redacted output + stats.
//
// The session is consumed — Push/Finish after this call fail.
func (s *Session) Finish() (RedactResult, error) {
	if s.consumed {
		return RedactResult{}, errSessionConsumed()
	}
	// The ABI consumes the scanning state on finish — success or
	// failure — so mark consumed before the call, and release the C
	// session object (and its engine pin) either way.
	s.consumed = true
	output, stats, err := s.ffi.finish()
	s.ffi.free()
	if err != nil {
		return RedactResult{}, err
	}
	return RedactResult{Output: output, Stats: stats}, nil
}

// Abort drops the session without flushing.
//
// Releases carry-over and the engine pin — use when a stream is
// abandoned mid-way. Idempotent: aborting a consumed session is a
// no-op. Always returns nil (the error return mirrors the WASM
// adapter, whose abort can fail at the ABI; the native free cannot).
func (s *Session) Abort() error {
	if s.consumed {
		return nil
	}
	s.ffi.free()
	s.consumed = true
	return nil
}
