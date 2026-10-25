// Parity tests: every vector in the cloak-core corpus must produce
// identical output when run through the WASM module from Go.
//
// Mirrors `crates/wasm-parity/tests/parity.rs` — same key material,
// same vectors, same byte-exact assertion. This suite is the e2e tier
// for the Go host (docs/03-guarantee-and-testing.md).

package cloak_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	cloak "github.com/silverwalls-labs/cloak/adapters/go"
)

func TestParityOneShot(t *testing.T) {
	engine := newTestEngine(t)
	for _, v := range loadVectors(t) {
		input := fromHex(t, v.Input)
		expected := fromHex(t, v.Expected)
		res, err := engine.Redact(input)
		if err != nil {
			t.Fatalf("vector %q: Redact: %v", v.Name, err)
		}
		if !bytes.Equal(res.Output, expected) {
			t.Errorf("vector %q output mismatch\n  input:    %s\n  got:      %s\n  expected: %s",
				v.Name, input, res.Output, expected)
		}
	}
}

func TestParityStreaming(t *testing.T) {
	engine := newTestEngine(t)
	for _, v := range loadVectors(t) {
		input := fromHex(t, v.Input)
		expected := fromHex(t, v.Expected)

		session, err := engine.Session()
		if err != nil {
			t.Fatalf("vector %q: Session: %v", v.Name, err)
		}
		pushed, err := session.Push(input)
		if err != nil {
			t.Fatalf("vector %q: Push: %v", v.Name, err)
		}
		res, err := session.Finish()
		if err != nil {
			t.Fatalf("vector %q: Finish: %v", v.Name, err)
		}
		actual := append(append([]byte{}, pushed...), res.Output...)
		if !bytes.Equal(actual, expected) {
			t.Errorf("vector %q streaming mismatch\n  input:    %s\n  got:      %s\n  expected: %s",
				v.Name, input, actual, expected)
		}
	}
}

// ── Edge cases ─────────────────────────────────────────────────────

func TestEmptyInputProducesEmptyOutput(t *testing.T) {
	engine := newTestEngine(t)
	res, err := engine.Redact(nil)
	if err != nil {
		t.Fatalf("Redact(nil): %v", err)
	}
	if len(res.Output) != 0 {
		t.Errorf("empty input should produce empty output, got %q", res.Output)
	}
}

func TestCleanInputPassesThroughUnchanged(t *testing.T) {
	engine := newTestEngine(t)
	input := []byte("hello world, no secrets here\n")
	res, err := engine.Redact(input)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if !bytes.Equal(res.Output, input) {
		t.Errorf("clean input should pass through unchanged, got %q", res.Output)
	}
}

func TestRedactReturnsStats(t *testing.T) {
	engine := newTestEngine(t)
	input := []byte("token=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")
	res, err := engine.Redact(input)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if !bytes.Contains(res.Output, []byte("[CLOAK:github-token:")) {
		t.Fatalf("input not redacted: %q", res.Output)
	}
	if res.Stats.BytesProcessed <= 0 {
		t.Errorf("BytesProcessed should be > 0, got %d", res.Stats.BytesProcessed)
	}
	if res.Stats.Matches["github-token"] < 1 {
		t.Errorf("stats should report github-token match, got %v", res.Stats.Matches)
	}
}

// ── Session lifecycle ──────────────────────────────────────────────

func TestSessionConsumedSemantics(t *testing.T) {
	engine := newTestEngine(t)

	session, err := engine.Session()
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if _, err := session.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	const want = "session already consumed (finished or aborted)"
	if _, err := session.Finish(); err == nil || err.Error() != want {
		t.Errorf("double Finish: want %q, got %v", want, err)
	}
	if _, err := session.Push([]byte("x")); err == nil || err.Error() != want {
		t.Errorf("Push after Finish: want %q, got %v", want, err)
	}
	if err := session.Abort(); err != nil {
		t.Errorf("Abort after Finish should be a no-op, got %v", err)
	}
}

func TestSessionAbortIsIdempotent(t *testing.T) {
	engine := newTestEngine(t)

	session, err := engine.Session()
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if _, err := session.Push([]byte("partial ghp_")); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if err := session.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if err := session.Abort(); err != nil {
		t.Errorf("second Abort should be a no-op, got %v", err)
	}
}

func TestCloseWithLiveSessionFails(t *testing.T) {
	engine := newTestEngine(t)

	session, err := engine.Session()
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if err := engine.Close(); err == nil {
		t.Fatal("Close with a live session should fail")
	}
	if err := session.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if err := engine.Close(); err != nil {
		t.Errorf("Close after aborting the session: %v", err)
	}
}

func TestEngineClosedSemantics(t *testing.T) {
	engine := newTestEngine(t)
	if err := engine.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := engine.Redact([]byte("x")); err == nil {
		t.Error("Redact on a closed engine should fail")
	}
	if _, err := engine.Session(); err == nil {
		t.Error("Session on a closed engine should fail")
	}
	if err := engine.Close(); err == nil {
		t.Error("double Close should fail")
	}
}

// ── Engine creation ────────────────────────────────────────────────

func TestInvalidConfigTOMLRejected(t *testing.T) {
	_, err := cloak.CreateEngine(context.Background(),
		cloak.WithConfigTOML("not = [valid"), cloak.WithEnv(testEnv()))
	if err == nil {
		t.Fatal("invalid TOML should fail engine creation")
	}
	var cloakErr *cloak.CloakError
	if !errors.As(err, &cloakErr) {
		t.Errorf("want *cloak.CloakError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "engine_new") {
		t.Errorf("error should carry the engine_new context, got %v", err)
	}
}

func TestConfigOptionsAreMutuallyExclusive(t *testing.T) {
	_, err := cloak.CreateEngine(context.Background(),
		cloak.WithConfig(testConfig()), cloak.WithConfigTOML(""))
	if err == nil {
		t.Fatal("WithConfig + WithConfigTOML should fail")
	}
}

func TestWithWASMBytes(t *testing.T) {
	wasmBytes, err := os.ReadFile(artifactPath())
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	engine, err := cloak.CreateEngine(context.Background(),
		cloak.WithWASM(wasmBytes),
		cloak.WithConfig(testConfig()), cloak.WithEnv(testEnv()))
	if err != nil {
		t.Fatalf("CreateEngine(WithWASM): %v", err)
	}
	defer func() { _ = engine.Close() }()

	res, err := engine.Redact([]byte("token=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"))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if !bytes.Contains(res.Output, []byte("[CLOAK:github-token:")) {
		t.Errorf("WithWASM engine did not redact: %q", res.Output)
	}
}
