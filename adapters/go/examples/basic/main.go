// One-shot and session basics — "embed cloak today" in Go.
//
// Run from the Go module directory (builds on the default config:
// ephemeral digest key, all rules enabled — see the README for stable
// keys):
//
//	cd adapters/go && go run ./examples/basic
package main

import (
	"context"
	"fmt"
	"log"

	cloak "github.com/silverwalls-labs/cloak/adapters/go"
)

func main() {
	engine, err := cloak.CreateEngine(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	// One-shot: bytes in, (output, stats) out.
	res, err := engine.Redact([]byte("token=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"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("one-shot: %s\n", res.Output)
	fmt.Printf("matches:  %v\n", res.Stats.Matches)

	// Streaming: session per stream; push may withhold carry-over,
	// finish flushes the tail and returns stats.
	session, err := engine.Session()
	if err != nil {
		log.Fatal(err)
	}
	first, err := session.Push([]byte("chunk 1: key=AKIA"))
	if err != nil {
		log.Fatal(err)
	}
	second, err := session.Push([]byte("IOSFODNN7EXAMPLE chunk 2\n"))
	if err != nil {
		log.Fatal(err)
	}
	tail, err := session.Finish()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("stream:   %s%s%s", first, second, tail.Output)
	fmt.Printf("matches:  %v\n", tail.Stats.Matches)

	if err := engine.Close(); err != nil {
		log.Fatal(err)
	}
}
