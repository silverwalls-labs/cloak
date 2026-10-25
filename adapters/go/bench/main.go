// Throughput benchmark: Go WASM adapter.
//
// Same corpus as crates/wasm-parity/benches/throughput.rs — mixed log
// lines with embedded secrets (~4 KiB per iteration). Line-for-line
// port of adapters/node/bench/throughput.ts (same corpus
// construction, same warmup and iteration counts).
//
// Run from the Go module directory:
//
//	cd adapters/go && go run ./bench
package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"time"

	cloak "github.com/silverwalls-labs/cloak/adapters/go"
)

// ── Corpus (matches Rust benchmark) ────────────────────────────────

func buildCorpus() []byte {
	var buf bytes.Buffer
	for i := 0; i < 20; i++ {
		buf.WriteString("INFO 2026-09-26T12:00:00Z request completed status=200 user=alice@example.com latency=12ms\n")
	}
	buf.WriteString("DEBUG auth token=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 granted\n")
	for i := 0; i < 20; i++ {
		buf.WriteString("INFO 2026-09-26T12:00:01Z db query rows=42 duration=3ms\n")
	}
	buf.WriteString("WARN key=AKIAIOSFODNN7EXAMPLE exposed\n")
	for i := 0; i < 20; i++ {
		buf.WriteString("INFO 2026-09-26T12:00:02Z response sent bytes=1024\n")
	}
	return buf.Bytes()
}

// ── Benchmark runner ───────────────────────────────────────────────

type result struct {
	total     time.Duration
	opsPerSec float64
	mibPerSec float64
}

func summarize(elapsed time.Duration, corpusLen, iterations int) result {
	elapsedSec := elapsed.Seconds()
	return result{
		total:     elapsed,
		opsPerSec: float64(iterations) / elapsedSec,
		mibPerSec: float64(corpusLen) * float64(iterations) / elapsedSec / (1024 * 1024),
	}
}

func mustRedact(engine *cloak.Engine, corpus []byte) {
	if _, err := engine.Redact(corpus); err != nil {
		log.Fatal(err)
	}
}

func streamOnce(engine *cloak.Engine, corpus []byte, chunkSize int) {
	session, err := engine.Session()
	if err != nil {
		log.Fatal(err)
	}
	for off := 0; off < len(corpus); off += chunkSize {
		end := min(off+chunkSize, len(corpus))
		if _, err := session.Push(corpus[off:end]); err != nil {
			log.Fatal(err)
		}
	}
	if _, err := session.Finish(); err != nil {
		log.Fatal(err)
	}
}

func benchmarkRedact(engine *cloak.Engine, corpus []byte, iterations int) result {
	for i := 0; i < 100; i++ { // warmup
		mustRedact(engine, corpus)
	}
	start := time.Now()
	for i := 0; i < iterations; i++ {
		mustRedact(engine, corpus)
	}
	return summarize(time.Since(start), len(corpus), iterations)
}

func benchmarkStreaming(engine *cloak.Engine, corpus []byte, chunkSize, iterations int) result {
	for i := 0; i < 50; i++ { // warmup
		streamOnce(engine, corpus, chunkSize)
	}
	start := time.Now()
	for i := 0; i < iterations; i++ {
		streamOnce(engine, corpus, chunkSize)
	}
	return summarize(time.Since(start), len(corpus), iterations)
}

func report(label string, r result, iterations int) {
	usPerOp := float64(r.total.Nanoseconds()) / float64(iterations) / 1000
	fmt.Printf("── %s ──\n", label)
	fmt.Printf("  %.2f µs/op\n", usPerOp)
	fmt.Printf("  %.1f MiB/s\n", r.mibPerSec)
	fmt.Printf("  %.0f ops/sec\n\n", r.opsPerSec)
}

// ── Main ───────────────────────────────────────────────────────────

func main() {
	engine, err := cloak.CreateEngine(context.Background(),
		cloak.WithConfig(cloak.Config{
			Redaction: cloak.RedactionConfig{DigestKey: "env:CLOAK_DIGEST_KEY"},
		}),
		cloak.WithEnv(map[string]string{"CLOAK_DIGEST_KEY": "bench-key"}))
	if err != nil {
		log.Fatal(err)
	}

	corpus := buildCorpus()
	iterations := 50000

	fmt.Printf("Corpus: %d bytes (%.1f KiB)\n", len(corpus), float64(len(corpus))/1024)
	fmt.Printf("Iterations: %d\n\n", iterations)

	redactResult := benchmarkRedact(engine, corpus, iterations)
	report("redact() (one-shot)", redactResult, iterations)

	stream1k := benchmarkStreaming(engine, corpus, 1024, iterations)
	report("streaming (1 KiB chunks)", stream1k, iterations)

	stream256 := benchmarkStreaming(engine, corpus, 256, iterations)
	report("streaming (256 B chunks)", stream256, iterations)

	// Summary of the Go numbers measured on this machine. For the
	// native and wasmtime figures on the same corpus, see
	// docs/benchmarks/receipts-wasm-e1.md.
	redactUs := float64(redactResult.total.Nanoseconds()) / float64(iterations) / 1000
	stream1kUs := float64(stream1k.total.Nanoseconds()) / float64(iterations) / 1000
	fmt.Printf("── summary (Go WASM, measured here) ──\n")
	fmt.Printf("  Go WASM (one-shot):            ~%.0f MiB/s  (~%.0f µs/op)\n", redactResult.mibPerSec, redactUs)
	fmt.Printf("  Go WASM (streaming 1K):        ~%.0f MiB/s  (~%.0f µs/op)\n", stream1k.mibPerSec, stream1kUs)

	if err := engine.Close(); err != nil {
		log.Fatal(err)
	}
}
