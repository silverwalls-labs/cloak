// Config → TOML serialization tests + round-trips through a real
// engine. Mirrors the Node/Python config suites.

package cloak_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	cloak "github.com/silverwalls-labs/cloak/adapters/go"
)

func TestConfigToTOMLRedactionSection(t *testing.T) {
	toml, err := cloak.ConfigToTOML(cloak.Config{
		Redaction: cloak.RedactionConfig{DigestKey: "env:CLOAK_DIGEST_KEY"},
	})
	if err != nil {
		t.Fatalf("ConfigToTOML: %v", err)
	}
	want := "[redaction]\ndigest_key = \"env:CLOAK_DIGEST_KEY\"\n"
	if toml != want {
		t.Errorf("got %q, want %q", toml, want)
	}
}

func TestConfigToTOMLEmptyConfig(t *testing.T) {
	toml, err := cloak.ConfigToTOML(cloak.Config{})
	if err != nil {
		t.Fatalf("ConfigToTOML: %v", err)
	}
	if toml != "" {
		t.Errorf("empty config should serialize to empty string, got %q", toml)
	}
}

func TestConfigToTOMLRulesSortedAndTyped(t *testing.T) {
	toml, err := cloak.ConfigToTOML(cloak.Config{
		Rules: map[string]cloak.RuleConfig{
			"phone-intl":   {Enabled: cloak.Bool(false)},
			"github-token": {Enabled: cloak.Bool(true)},
			"jwt":          {}, // nil Enabled → section only
		},
	})
	if err != nil {
		t.Fatalf("ConfigToTOML: %v", err)
	}
	want := "[rules.github-token]\nenabled = true\n\n[rules.jwt]\n\n[rules.phone-intl]\nenabled = false\n"
	if toml != want {
		t.Errorf("got %q, want %q", toml, want)
	}
}

func TestConfigToTOMLStringEscaping(t *testing.T) {
	toml, err := cloak.ConfigToTOML(cloak.Config{
		Redaction: cloak.RedactionConfig{DigestKey: "a\\b\"c\nd\re\tf"},
	})
	if err != nil {
		t.Fatalf("ConfigToTOML: %v", err)
	}
	want := "digest_key = \"a\\\\b\\\"c\\nd\\re\\tf\""
	if !strings.Contains(toml, want) {
		t.Errorf("escaping mismatch:\n  got:  %q\n  want: %q", toml, want)
	}
}

func TestConfigToTOMLRejectsInvalidRuleIDs(t *testing.T) {
	invalid := []string{
		"Phone",
		"phone_intl",
		"phone-",
		"-phone",
		"phone--intl",
		"phone intl",
		"phone.intl",
		"phone-intl\n",
		"",
	}
	for _, ruleID := range invalid {
		_, err := cloak.ConfigToTOML(cloak.Config{
			Rules: map[string]cloak.RuleConfig{ruleID: {}},
		})
		if err == nil {
			t.Errorf("rule ID %q should be rejected", ruleID)
			continue
		}
		if !strings.Contains(err.Error(), "invalid rule ID") ||
			!strings.Contains(err.Error(), "must be kebab-case") {
			t.Errorf("rule ID %q: unexpected error message %q", ruleID, err)
		}
	}
}

func TestConfigToTOMLAcceptsValidRuleIDs(t *testing.T) {
	for _, ruleID := range []string{"github-token", "phone-intl", "jwt", "a1-b2-c3"} {
		if _, err := cloak.ConfigToTOML(cloak.Config{
			Rules: map[string]cloak.RuleConfig{ruleID: {}},
		}); err != nil {
			t.Errorf("rule ID %q should be accepted, got %v", ruleID, err)
		}
	}
}

// ── Round-trips through a real engine ──────────────────────────────

func TestDisabledRuleRoundTrip(t *testing.T) {
	config := testConfig()
	config.Rules = map[string]cloak.RuleConfig{
		"github-token": {Enabled: cloak.Bool(false)},
	}
	engine, err := cloak.CreateEngine(context.Background(),
		cloak.WithConfig(config), cloak.WithEnv(testEnv()))
	if err != nil {
		t.Fatalf("CreateEngine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	input := []byte("token=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")
	res, err := engine.Redact(input)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if !bytes.Equal(res.Output, input) {
		t.Errorf("github-token disabled — input should pass through, got %q", res.Output)
	}
}

func TestRawTOMLRoundTrip(t *testing.T) {
	engine, err := cloak.CreateEngine(context.Background(),
		cloak.WithConfigTOML("[redaction]\ndigest_key = \"env:CLOAK_DIGEST_KEY\"\n"),
		cloak.WithEnv(testEnv()))
	if err != nil {
		t.Fatalf("CreateEngine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	res, err := engine.Redact([]byte("token=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"))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if !bytes.Contains(res.Output, []byte("[CLOAK:github-token:")) {
		t.Errorf("raw TOML config engine did not redact: %q", res.Output)
	}
}
