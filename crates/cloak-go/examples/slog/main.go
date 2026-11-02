// log/slog with the cloak Handler: every record is redacted on the
// way out (the Go analog of the Python logging-handler example).
//
// Run from the Go module directory:
//
//	cd crates/cloak-go && go run ./examples/slog
package main

import (
	"log"
	"log/slog"
	"os"

	cloak "github.com/silverwalls-labs/cloak/crates/cloak-go"
)

func main() {
	engine, err := cloak.CreateEngine()
	if err != nil {
		log.Fatal(err)
	}

	logger := slog.New(cloak.NewHandler(engine, os.Stdout, nil))
	logger.Info("auth granted", "token", "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")
	logger.Warn("key exposed", "key", "AKIAIOSFODNN7EXAMPLE")

	// JSON flavor: same redaction, structured output.
	jsonLogger := slog.New(cloak.NewJSONHandler(engine, os.Stdout, nil))
	jsonLogger.Info("auth granted", "token", "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")

	if err := engine.Close(); err != nil {
		log.Fatal(err)
	}
}
