// log/slog.Handler that redacts records before they reach a stream.
//
// The slog flavor of the layer-1 hook (the analog of the Python
// CloakHandler and the Node pino examples): every formatted record is
// redacted one-shot and written to a writer. One-shot — not a session
// — because log records are discrete lines that must be fully flushed
// at emit time; a streaming session's carry-over would withhold
// record tails. For raw byte streams use Writer instead.

package cloak

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"sync"
)

// Handler redacts formatted log records through a cloak engine.
//
// Records are formatted by an inner slog text or JSON handler into a
// shared buffer, redacted one-shot, and written to the target. Safe
// for concurrent use. The caller owns the engine — the handler never
// closes it.
type Handler struct {
	engine *Engine
	target io.Writer
	mu     *sync.Mutex
	buf    *bytes.Buffer
	inner  slog.Handler
}

var _ slog.Handler = (*Handler)(nil)

// NewHandler returns a Handler that formats records like
// slog.NewTextHandler(target, opts), redacting each line on the way
// out.
//
// Example:
//
//	logger := slog.New(cloak.NewHandler(engine, os.Stdout, nil))
//	logger.Info("auth", "token", someSecret) // redacted on the way out
func NewHandler(engine *Engine, target io.Writer, opts *slog.HandlerOptions) *Handler {
	buf := &bytes.Buffer{}
	return &Handler{
		engine: engine,
		target: target,
		mu:     &sync.Mutex{},
		buf:    buf,
		inner:  slog.NewTextHandler(buf, opts),
	}
}

// NewJSONHandler is NewHandler with slog.NewJSONHandler formatting.
func NewJSONHandler(engine *Engine, target io.Writer, opts *slog.HandlerOptions) *Handler {
	buf := &bytes.Buffer{}
	return &Handler{
		engine: engine,
		target: target,
		mu:     &sync.Mutex{},
		buf:    buf,
		inner:  slog.NewJSONHandler(buf, opts),
	}
}

// Enabled defers to the inner handler's level check.
func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// maxRetainedBufCap bounds the formatting buffer retained between
// records — one oversized record must not pin its capacity for the
// lifetime of the handler and every clone sharing the buffer.
const maxRetainedBufCap = 64 << 10

// Handle formats, redacts, and writes one record (terminator included
// by the inner handler).
func (h *Handler) Handle(ctx context.Context, record slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.buf.Reset()
	defer func() {
		if h.buf.Cap() > maxRetainedBufCap {
			// Replace through the shared pointer so clones drop the
			// oversized backing array too.
			*h.buf = bytes.Buffer{}
		}
	}()
	if err := h.inner.Handle(ctx, record); err != nil {
		return err
	}
	res, err := h.engine.Redact(h.buf.Bytes())
	if err != nil {
		return err
	}
	// Surface short writes instead of silently truncating the redacted
	// record — same discipline as Writer.writeAll.
	n, err := h.target.Write(res.Output)
	if err == nil && n < len(res.Output) {
		return io.ErrShortWrite
	}
	return err
}

// WithAttrs clones the inner handler; the clone shares the buffer and
// lock, so records from all clones serialize correctly.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &Handler{
		engine: h.engine,
		target: h.target,
		mu:     h.mu,
		buf:    h.buf,
		inner:  h.inner.WithAttrs(attrs),
	}
}

// WithGroup clones the inner handler; the clone shares the buffer and
// lock, so records from all clones serialize correctly.
func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{
		engine: h.engine,
		target: h.target,
		mu:     h.mu,
		buf:    h.buf,
		inner:  h.inner.WithGroup(name),
	}
}
