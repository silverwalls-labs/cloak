// io.WriteCloser that redacts secrets on the fly.
//
// This is the layer-1 stdout/stderr hook shape from the embedding doc
// (the Go analog of the Node Transform stream and the Python
// CloakWriter): wrap a writer so everything written through it is
// redacted. Hooks are thin sugar — all correctness lives in core.

package cloak

import "io"

// Writer is a write-only stream that redacts via a cloak session.
//
// Each Write pushes through the session and forwards flushed bytes to
// the target; Close finishes the session, writes the carry-over tail,
// and populates Stats. The engine must outlive the writer.
//
// Not safe for concurrent use — like most io.Writer implementations,
// guard it externally if multiple goroutines write.
type Writer struct {
	session *Session
	target  io.Writer
	stats   *Stats
	closed  bool
}

var _ io.WriteCloser = (*Writer)(nil)

// NewWriter wraps target so everything written through the returned
// Writer is redacted.
//
// Example (stdin → cloak → stdout pipe):
//
//	w, err := cloak.NewWriter(engine, os.Stdout)
//	if err != nil { ... }
//	if _, err := io.Copy(w, os.Stdin); err != nil { ... }
//	if err := w.Close(); err != nil { ... }
func NewWriter(engine *Engine, target io.Writer) (*Writer, error) {
	session, err := engine.Session()
	if err != nil {
		return nil, err
	}
	return &Writer{session: session, target: target}, nil
}

// writeAll forwards redacted bytes to the target, surfacing short
// writes as io.ErrShortWrite — dropping the remainder would silently
// truncate *redacted* output downstream.
func (w *Writer) writeAll(data []byte) error {
	n, err := w.target.Write(data)
	if err == nil && n < len(data) {
		err = io.ErrShortWrite
	}
	return err
}

// Write pushes p through the scanner, forwarding flushed bytes.
//
// Returns len(p) on success per the io.Writer contract — the
// carry-over window means the bytes emitted to the target may be
// fewer (or more, once tags are substituted). Any failure aborts the
// whole writer, not just the session, so it lands in a terminal
// state: the session is released (so engine.Close is not blocked)
// and a later Close won't call Finish on the now-consumed session.
// Mirrors the Node transform's destroy-on-error path.
func (w *Writer) Write(p []byte) (int, error) {
	if w.closed {
		return 0, &CloakError{msg: "write on closed cloak.Writer"}
	}
	out, err := w.session.Push(p)
	if err != nil {
		_ = w.Abort()
		return 0, err
	}
	if len(out) > 0 {
		if err := w.writeAll(out); err != nil {
			_ = w.Abort()
			// The scanner consumed all of p before the forward failed —
			// report n accordingly so byte accounting stays correct.
			return len(p), err
		}
	}
	return len(p), nil
}

// Close finishes the session, writes the tail, and populates Stats.
//
// Idempotent. On failure the session is already released (Finish
// consumes it either way), so the engine can still be closed.
func (w *Writer) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	res, err := w.session.Finish()
	if err != nil {
		return err
	}
	if len(res.Output) > 0 {
		if err := w.writeAll(res.Output); err != nil {
			return err
		}
	}
	stats := res.Stats
	w.stats = &stats
	return nil
}

// Abort drops the session without flushing (broken-pipe path).
// Idempotent.
func (w *Writer) Abort() error {
	if w.closed {
		return nil
	}
	w.closed = true
	return w.session.Abort()
}

// Stats returns the session statistics populated by Close — nil
// before Close and after Abort or a write failure.
func (w *Writer) Stats() *Stats { return w.stats }
