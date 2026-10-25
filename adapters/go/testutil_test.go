// Shared test fixtures: the parity config, engine factory, and the
// vector corpus loader (testdata/vectors.json, generated from Rust
// via `cargo run --example export-vectors -p cloak-core`).

package cloak_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	cloak "github.com/silverwalls-labs/cloak/adapters/go"
)

// keyMaterial must match KEY_MATERIAL in export-vectors.rs and
// wasm-parity.
const keyMaterial = "integration-test-key"

func testConfig() cloak.Config {
	return cloak.Config{
		Redaction: cloak.RedactionConfig{DigestKey: "env:CLOAK_DIGEST_KEY"},
	}
}

func testEnv() map[string]string {
	return map[string]string{"CLOAK_DIGEST_KEY": keyMaterial}
}

// newTestEngine builds an engine with the parity config. Closed via
// t.Cleanup; the error is ignored there so tests that close (or fail
// to fully unwind) explicitly stay quiet.
func newTestEngine(t *testing.T) *cloak.Engine {
	t.Helper()
	engine, err := cloak.CreateEngine(context.Background(),
		cloak.WithConfig(testConfig()), cloak.WithEnv(testEnv()))
	if err != nil {
		t.Fatalf("CreateEngine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	return engine
}

// artifactPath mirrors the bridge's resolution for tests that need
// the raw bytes (WithWASM).
func artifactPath() string {
	if p := os.Getenv("CLOAK_WASM_PATH"); p != "" {
		return p
	}
	return filepath.Join("..", "..",
		"target", "wasm32-wasip1", "release", "cloak_wasm.wasm")
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
