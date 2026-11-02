// Shared test fixtures: the parity config, engine factory, and the
// vector corpus loader (testdata/vectors.json, generated from Rust
// via `cargo run --example export-vectors -p cloak-core`).

package cloak_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	cloak "github.com/silverwalls-labs/cloak/crates/cloak-go"
)

// keyMaterial must match KEY_MATERIAL in export-vectors.rs and
// wasm-parity.
const keyMaterial = "integration-test-key"

func testConfig() cloak.Config {
	return cloak.Config{
		Redaction: cloak.RedactionConfig{DigestKey: "env:CLOAK_DIGEST_KEY"},
	}
}

// newTestEngine builds an engine with the parity config. The digest
// key goes through the real process environment (t.Setenv) — the
// native binding has no WithEnv, core reads the env at construction.
// Closed via t.Cleanup; the error is ignored there so tests that close
// (or fail to fully unwind) explicitly stay quiet.
func newTestEngine(t *testing.T) *cloak.Engine {
	t.Helper()
	t.Setenv("CLOAK_DIGEST_KEY", keyMaterial)
	engine, err := cloak.CreateEngine(cloak.WithConfig(testConfig()))
	if err != nil {
		t.Fatalf("CreateEngine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	return engine
}

type vector struct {
	Name     string `json:"name"`
	Input    string `json:"input"`    // hex
	Expected string `json:"expected"` // hex
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "vectors.json"))
	if err != nil {
		t.Fatalf("read vectors.json: %v", err)
	}
	var vectors []vector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse vectors.json: %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("vectors.json is empty")
	}
	return vectors
}

func fromHex(t *testing.T, s string) []byte {
	t.Helper()
	data, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid hex in vectors.json: %v", err)
	}
	return data
}
