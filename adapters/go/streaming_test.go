// Chunk-boundary invariant: split vector inputs at varying boundaries
// and verify the WASM module produces identical output regardless of
// chunking — same guarantee as cloak-core (docs/03).
//
// Mirrors `crates/wasm-parity/tests/streaming.rs` and the Node/Python
// suites — same split-point algorithm, so failures are comparable
// across hosts.

package cloak_test

import (
	"bytes"
	"slices"
	"testing"
)

// splitPoints generates deterministic split points for a given input
// length and seed: 1–5 unique points within [0, len), sorted. Exact
// port of the Node/Python algorithm.
func splitPoints(length, seed int) []int {
	if length == 0 {
		return nil
	}
	count := seed%5 + 1
	points := make([]int, 0, count)
	for i := 0; i < count; i++ {
		points = append(points, seed*(i+7)%length)
	}
	slices.Sort(points)
	return slices.Compact(points)
}

func TestChunkedPushMatchesSinglePush(t *testing.T) {
	engine := newTestEngine(t)

	for _, v := range loadVectors(t) {
		input := fromHex(t, v.Input)
		if len(input) == 0 {
			continue
		}

		// Baseline: one-shot redact.
		baselineRes, err := engine.Redact(input)
		if err != nil {
			t.Fatalf("vector %q: Redact: %v", v.Name, err)
		}
		baseline := baselineRes.Output

		// Chunked: split at multiple boundaries per vector.
		for seed := 0; seed < 10; seed++ {
			session, err := engine.Session()
			if err != nil {
				t.Fatalf("vector %q: Session: %v", v.Name, err)
			}

			var chunked []byte
			pos := 0
			for _, split := range splitPoints(len(input), seed) {
				if split > pos {
					out, err := session.Push(input[pos:split])
					if err != nil {
						t.Fatalf("vector %q (seed=%d): Push: %v", v.Name, seed, err)
					}
					chunked = append(chunked, out...)
					pos = split
				}
			}
			if pos < len(input) {
				out, err := session.Push(input[pos:])
				if err != nil {
					t.Fatalf("vector %q (seed=%d): Push: %v", v.Name, seed, err)
				}
				chunked = append(chunked, out...)
			}

			res, err := session.Finish()
			if err != nil {
				t.Fatalf("vector %q (seed=%d): Finish: %v", v.Name, seed, err)
			}
			chunked = append(chunked, res.Output...)

			if !bytes.Equal(chunked, baseline) {
				t.Errorf("chunk-boundary divergence for vector %q (seed=%d)\n  got:      %s\n  expected: %s",
					v.Name, seed, chunked, baseline)
			}
		}
	}
}

func TestSingleBytePushes(t *testing.T) {
	engine := newTestEngine(t)

	// First 5 non-empty vectors for a thorough single-byte test.
	var samples []vector
	for _, v := range loadVectors(t) {
		if len(v.Input) > 0 {
			samples = append(samples, v)
		}
		if len(samples) == 5 {
			break
		}
	}

	for _, v := range samples {
		input := fromHex(t, v.Input)
		baselineRes, err := engine.Redact(input)
		if err != nil {
			t.Fatalf("vector %q: Redact: %v", v.Name, err)
		}

		session, err := engine.Session()
		if err != nil {
			t.Fatalf("vector %q: Session: %v", v.Name, err)
		}
		var result []byte
		for i := range input {
			out, err := session.Push(input[i : i+1])
			if err != nil {
				t.Fatalf("vector %q: Push byte %d: %v", v.Name, i, err)
			}
			result = append(result, out...)
		}
		res, err := session.Finish()
		if err != nil {
			t.Fatalf("vector %q: Finish: %v", v.Name, err)
		}
		result = append(result, res.Output...)

		if !bytes.Equal(result, baselineRes.Output) {
			t.Errorf("single-byte push divergence for vector %q", v.Name)
		}
	}
}
