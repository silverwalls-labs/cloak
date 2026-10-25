// Go config struct → TOML serialization.
//
// Hand-rolled for the cloak config surface (two sections, no arrays,
// no nested tables beyond `[rules.<id>]`). Mirrors the Node/Python
// serializers key-for-key.

package cloak

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

// ── Public types ───────────────────────────────────────────────────

// RuleConfig is the per-rule configuration (mirrors `[rules.<id>]` in
// TOML).
type RuleConfig struct {
	// Enabled toggles the rule; nil leaves the engine default.
	Enabled *bool
}

// RedactionConfig mirrors the `[redaction]` TOML section.
type RedactionConfig struct {
	// DigestKey is the digest key source — typically
	// "env:CLOAK_DIGEST_KEY". Maps to `digest_key` in the TOML config.
	// Empty means unset (the section is omitted).
	DigestKey string
}

// Config is the cloak engine configuration.
//
// Serialized to TOML before passing to the WASM module. Rule IDs are
// kebab-case strings matching the cloak catalog ("github-token",
// "phone-intl", etc.).
type Config struct {
	Redaction RedactionConfig
	Rules     map[string]RuleConfig
}

// Bool returns a pointer to v — convenience for RuleConfig.Enabled.
func Bool(v bool) *bool { return &v }

// ── Serialization ──────────────────────────────────────────────────

// tomlString escapes a TOML basic string value.
func tomlString(value string) string {
	replacer := strings.NewReplacer(
		"\\", "\\\\",
		"\"", "\\\"",
		"\n", "\\n",
		"\r", "\\r",
		"\t", "\\t",
	)
	return "\"" + replacer.Replace(value) + "\""
}

// Cloak rule IDs are kebab-case identifiers from a fixed catalog
// (e.g. `github-token`, `phone-intl`). A rule ID containing TOML-
// special characters (`.`, `]`, `"`, whitespace) would produce an
// invalid or misinterpreted section header — reject early with a
// clear message instead of forwarding a broken TOML string to the
// Rust parser. Go's RE2 anchors match end-of-text only (fullmatch
// semantics — a trailing newline is rejected, same as the other
// hosts).
var validRuleID = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

func validateRuleID(ruleID string) error {
	if !validRuleID.MatchString(ruleID) {
		return cloakErrorf(
			"invalid rule ID %q: must be kebab-case (e.g. \"github-token\", \"phone-intl\")",
			ruleID)
	}
	return nil
}

// ConfigToTOML serializes a Config to a TOML string.
//
// DigestKey maps to `digest_key`. Rule IDs are passed through as-is —
// they are domain identifiers, not Go names. Sections are emitted in
// sorted rule-ID order so output is deterministic.
func ConfigToTOML(config Config) (string, error) {
	var lines []string

	if config.Redaction.DigestKey != "" {
		lines = append(lines,
			"[redaction]",
			"digest_key = "+tomlString(config.Redaction.DigestKey),
			"")
	}

	for _, ruleID := range slices.Sorted(maps.Keys(config.Rules)) {
		if err := validateRuleID(ruleID); err != nil {
			return "", err
		}
		lines = append(lines, "[rules."+ruleID+"]")
		if enabled := config.Rules[ruleID].Enabled; enabled != nil {
			lines = append(lines, fmt.Sprintf("enabled = %t", *enabled))
		}
		lines = append(lines, "")
	}

	return strings.Join(lines, "\n"), nil
}
