// Native-specific concurrency tests. The headline difference from the
// WASM adapter: an Engine is NOT serialized behind a mutex — concurrent
// Redact calls and sessions run in parallel (per-call error returns in
// the C ABI, Send+Sync engine in core). These tests prove that claim
// byte-for-byte and pin the Close-vs-in-flight-call contract, all
// meaningful under `go test -race`.

package cloak_test

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
)

func TestConcurrentRedactByteIdentical(t *testing.T) {
	engine := newTestEngine(t)
	input := []byte(secretLine)

	baseline, err := engine.Redact(input)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	const goroutines = 8
	const iterations = 200
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				res, err := engine.Redact(input)
				if err != nil {
					errs <- fmt.Errorf("Redact: %w", err)
					return
				}
				if !bytes.Equal(res.Output, baseline.Output) {
					errs <- fmt.Errorf("concurrent output diverges from baseline")
					return
				}
				if res.Stats.BytesProcessed != baseline.Stats.BytesProcessed ||
					res.Stats.Matches["github-token"] != baseline.Stats.Matches["github-token"] {
					errs <- fmt.Errorf("concurrent stats diverge: %+v", res.Stats)
					return
				}
			}
			errs <- nil
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestConcurrentSessionsIndependent(t *testing.T) {
	engine := newTestEngine(t)

	// Distinct inputs per goroutine so cross-talk would be visible.
	vectors := loadVectors(t)
	var samples []vector
	for _, v := range vectors {
		if len(v.Input) > 0 {
			samples = append(samples, v)
		}
		if len(samples) == 8 {
			break
		}
	}

	var wg sync.WaitGroup
	errs := make(chan error, len(samples))
	for _, v := range samples {
		wg.Add(1)
		go func() {
			defer wg.Done()
			input := fromHex(t, v.Input)
			expected := fromHex(t, v.Expected)

			session, err := engine.Session()
			if err != nil {
				errs <- fmt.Errorf("vector %q: Session: %w", v.Name, err)
				return
			}
			var got []byte
			mid := len(input) / 2
			for _, chunk := range [][]byte{input[:mid], input[mid:]} {
				out, err := session.Push(chunk)
				if err != nil {
					errs <- fmt.Errorf("vector %q: Push: %w", v.Name, err)
					return
				}
				got = append(got, out...)
			}
			res, err := session.Finish()
			if err != nil {
				errs <- fmt.Errorf("vector %q: Finish: %w", v.Name, err)
				return
			}
			got = append(got, res.Output...)
			if !bytes.Equal(got, expected) {
				errs <- fmt.Errorf("vector %q: concurrent session diverges", v.Name)
				return
			}
			errs <- nil
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

// Close takes the write lock: it must drain in-flight Redact calls
// (never a use-after-free under the race detector) and flip every
// later call to the "engine is closed" error.
func TestCloseWhileRedacting(t *testing.T) {
	engine := newTestEngine(t)
	input := []byte(secretLine)

	const goroutines = 4
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := engine.Redact(input); err != nil {
					// Only the closed error is acceptable, and once it
					// appears this goroutine is done.
					if err.Error() != "engine is closed" {
						t.Errorf("unexpected Redact error: %v", err)
					}
					return
				}
			}
		}()
	}

	// No sessions are live, so the first Close drains in-flight
	// Redacts on the write lock and must succeed.
	if err := engine.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	close(stop)
	wg.Wait()

	if _, err := engine.Redact(input); err == nil || err.Error() != "engine is closed" {
		t.Errorf("Redact after Close: want closed error, got %v", err)
	}
}

func TestCloseWithLiveSessionRetryable(t *testing.T) {
	engine := newTestEngine(t)

	session, err := engine.Session()
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if err := engine.Close(); err == nil {
		t.Fatal("Close with a live session should fail")
	}

	// The refusal is retryable: the engine is untouched and usable.
	res, err := engine.Redact([]byte("token=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"))
	if err != nil {
		t.Fatalf("Redact after refused Close: %v", err)
	}
	if !bytes.Contains(res.Output, []byte("[CLOAK:github-token:")) {
		t.Errorf("engine must still redact after refused Close: %q", res.Output)
	}

	if err := session.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if err := engine.Close(); err != nil {
		t.Errorf("Close after Abort: %v", err)
	}
}
