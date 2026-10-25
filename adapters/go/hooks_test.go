// Hook tests: the io.WriteCloser layer-1 hook (Writer) and the
// log/slog.Handler. Mirrors the Node transform and Python hook
// suites: byte parity with one-shot redact, abort-on-error, stats.

package cloak_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	cloak "github.com/silverwalls-labs/cloak/adapters/go"
)

const secretLine = "request ok\ntoken=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\ndone\n"

// ── Writer ─────────────────────────────────────────────────────────

func TestWriterMatchesOneShot(t *testing.T) {
	engine := newTestEngine(t)
	input := []byte(secretLine)

	baseline, err := engine.Redact(input)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	var sink bytes.Buffer
	w, err := cloak.NewWriter(engine, &sink)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	// Write in two chunks across the secret to exercise carry-over.
	mid := len(input) / 2
	for _, chunk := range [][]byte{input[:mid], input[mid:]} {
		n, err := w.Write(chunk)
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		if n != len(chunk) {
			t.Fatalf("Write returned %d, want %d", n, len(chunk))
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if !bytes.Equal(sink.Bytes(), baseline.Output) {
		t.Errorf("writer output diverges from one-shot\n  got:      %q\n  expected: %q",
			sink.Bytes(), baseline.Output)
	}
	stats := w.Stats()
	if stats == nil {
		t.Fatal("Stats should be populated after Close")
	}
	if stats.BytesProcessed != len(input) {
		t.Errorf("BytesProcessed = %d, want %d", stats.BytesProcessed, len(input))
	}
	if stats.Matches["github-token"] < 1 {
		t.Errorf("stats should report github-token match, got %v", stats.Matches)
	}
}

func TestWriterCloseIsIdempotentAndWriteAfterCloseFails(t *testing.T) {
	engine := newTestEngine(t)
	var sink bytes.Buffer
	w, err := cloak.NewWriter(engine, &sink)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("second Close should be a no-op, got %v", err)
	}
	if _, err := w.Write([]byte("x")); err == nil {
		t.Error("Write after Close should fail")
	}
}

func TestWriterAbort(t *testing.T) {
	engine := newTestEngine(t)
	var sink bytes.Buffer
	w, err := cloak.NewWriter(engine, &sink)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if _, err := w.Write([]byte("partial ghp_")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if err := w.Abort(); err != nil {
		t.Errorf("second Abort should be a no-op, got %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("Close after Abort should be a no-op, got %v", err)
	}
	if w.Stats() != nil {
		t.Error("Stats should be nil after Abort")
	}
	// The session was released — the engine closes cleanly.
	if err := engine.Close(); err != nil {
		t.Errorf("engine.Close after writer Abort: %v", err)
	}
}

// shortWriter accepts all but the last byte without reporting an
// error — an io.Writer contract violation the Writer must surface
// instead of silently truncating redacted output.
type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return len(p) - 1, nil
}

func TestWriterSurfacesShortWrites(t *testing.T) {
	engine := newTestEngine(t)
	w, err := cloak.NewWriter(engine, shortWriter{})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	// Clean bulk input flushes on push; the tail flushes on close —
	// whichever path forwards bytes first must report the short write.
	_, writeErr := w.Write(bytes.Repeat([]byte("clean line\n"), 1024))
	closeErr := w.Close()
	if !errors.Is(writeErr, io.ErrShortWrite) && !errors.Is(closeErr, io.ErrShortWrite) {
		t.Errorf("short write not surfaced (write=%v, close=%v)", writeErr, closeErr)
	}

	// Terminal state: the session was released either way.
	if err := engine.Close(); err != nil {
		t.Errorf("engine.Close after short-write failure: %v", err)
	}
}

type errWriter struct{ err error }

func (w errWriter) Write([]byte) (int, error) { return 0, w.err }

func TestWriterAbortsOnTargetError(t *testing.T) {
	engine := newTestEngine(t)
	targetErr := errors.New("broken pipe")
	w, err := cloak.NewWriter(engine, errWriter{err: targetErr})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	_, writeErr := w.Write(bytes.Repeat([]byte("clean line\n"), 1024))
	closeErr := w.Close()
	if !errors.Is(writeErr, targetErr) && !errors.Is(closeErr, targetErr) {
		t.Errorf("target error not surfaced (write=%v, close=%v)", writeErr, closeErr)
	}
	if err := engine.Close(); err != nil {
		t.Errorf("engine.Close after target failure: %v", err)
	}
}

// ── slog Handler ───────────────────────────────────────────────────

func TestHandlerRedactsRecords(t *testing.T) {
	engine := newTestEngine(t)
	var sink bytes.Buffer
	logger := slog.New(cloak.NewHandler(engine, &sink, nil))

	logger.Info("auth", "token", "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")

	out := sink.Bytes()
	if bytes.Contains(out, []byte("ghp_Ab")) {
		t.Errorf("secret leaked through the handler: %q", out)
	}
	if !bytes.Contains(out, []byte("[CLOAK:github-token:")) {
		t.Errorf("expected a CLOAK tag, got %q", out)
	}
}

func TestHandlerRespectsLevel(t *testing.T) {
	engine := newTestEngine(t)
	var sink bytes.Buffer
	logger := slog.New(cloak.NewHandler(engine, &sink,
		&slog.HandlerOptions{Level: slog.LevelWarn}))

	logger.Info("below the threshold")
	if sink.Len() != 0 {
		t.Errorf("info record should be filtered, got %q", sink.Bytes())
	}
	logger.Warn("at the threshold")
	if sink.Len() == 0 {
		t.Error("warn record should be written")
	}
}

func TestHandlerWithAttrsRedacts(t *testing.T) {
	engine := newTestEngine(t)
	var sink bytes.Buffer
	logger := slog.New(cloak.NewHandler(engine, &sink, nil)).
		With("token", "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")

	logger.Info("request")

	out := sink.Bytes()
	if bytes.Contains(out, []byte("ghp_Ab")) {
		t.Errorf("secret leaked through WithAttrs clone: %q", out)
	}
	if !bytes.Contains(out, []byte("[CLOAK:github-token:")) {
		t.Errorf("expected a CLOAK tag, got %q", out)
	}
}

func TestHandlerSurfacesShortWrites(t *testing.T) {
	engine := newTestEngine(t)
	// shortWriter drops the last byte without an error — the handler
	// must surface it instead of silently truncating the record.
	h := cloak.NewHandler(engine, shortWriter{}, nil)
	record := slog.NewRecord(time.Now(), slog.LevelInfo, "auth granted", 0)
	err := h.Handle(context.Background(), record)
	if !errors.Is(err, io.ErrShortWrite) {
		t.Errorf("want io.ErrShortWrite, got %v", err)
	}
}

func TestJSONHandlerRedacts(t *testing.T) {
	engine := newTestEngine(t)
	var sink bytes.Buffer
	logger := slog.New(cloak.NewJSONHandler(engine, &sink, nil))

	logger.Info("auth", "token", "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")

	out := sink.Bytes()
	if bytes.Contains(out, []byte("ghp_Ab")) {
		t.Errorf("secret leaked through the JSON handler: %q", out)
	}
	if !bytes.Contains(out, []byte("[CLOAK:github-token:")) {
		t.Errorf("expected a CLOAK tag, got %q", out)
	}
	if !bytes.Contains(out, []byte(`"msg":"auth"`)) {
		t.Errorf("JSON structure missing, got %q", out)
	}
}
