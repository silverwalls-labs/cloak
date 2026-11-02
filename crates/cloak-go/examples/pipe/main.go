// stdin → cloak → stdout: the layer-1 pipe via the io.WriteCloser
// hook (the Go analog of the Node transform-pipe example).
//
// Run from the Go module directory:
//
//	printf 'token=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\n' | go run ./examples/pipe
package main

import (
	"fmt"
	"io"
	"log"
	"os"

	cloak "github.com/silverwalls-labs/cloak/crates/cloak-go"
)

func main() {
	engine, err := cloak.CreateEngine()
	if err != nil {
		log.Fatal(err)
	}

	w, err := cloak.NewWriter(engine, os.Stdout)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := io.Copy(w, os.Stdin); err != nil {
		_ = w.Abort()
		log.Fatal(err)
	}
	if err := w.Close(); err != nil {
		log.Fatal(err)
	}
	stats := w.Stats()
	fmt.Fprintf(os.Stderr, "bytes=%d matches=%v\n", stats.BytesProcessed, stats.Matches)

	if err := engine.Close(); err != nil {
		log.Fatal(err)
	}
}
