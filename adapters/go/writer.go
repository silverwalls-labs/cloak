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
	// err is the first terminal failure (push or forward in Write,
	// finish or tail-write in Close), latched so a caller that ignored
	// the Write error still learns from Close that redacted output was
	// truncated (bufio.Writer precedent). nil after a clean Close or a
	// user-called Abort.
	err error
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
		if w.err != nil {
			return 0, w.err
		}
		return 0, &CloakError{msg: "write on closed cloak.Writer"}
	}
	out, err := w.session.Push(p)
	if err != nil {
		w.err = err
		_ = w.Abort()
		return 0, err
	}
	if len(out) > 0 {
		if err := w.writeAll(out); err != nil {
			w.err = err
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
// Idempotent on the success path; after a terminal failure the latched
// error is returned again, so a caller that ignored the Write error
// still sees the truncation. Returns nil after a user-called Abort.
// On failure the session is already released (Finish consumes it
// either way), so the engine can still be closed.
func (w *Writer) Close() error {
	if w.closed {
		return w.err
	}
	w.closed = true
	res, err := w.session.Finish()
	if err != nil {
		w.err = err
		return err
	}
	if len(res.Output) > 0 {
		if err := w.writeAll(res.Output); err != nil {
			w.err = err
			return err
		}
	}
	stats := res.Stats
	w.stats = &stats
	return nil
}

// Abort drops the session without flushing (broken-pipe path).
// Idempotent. A user-called Abort is a clean teardown: it latches no
// error, so a later Close returns nil (only Write/Close failures do).
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
