/**
 * JS config object → TOML serialization.
 *
 * Hand-rolled for the cloak config surface (two sections, no arrays,
 * no nested tables beyond `[rules.<id>]`). Zero dependencies.
 */

// ── Public types ───────────────────────────────────────────────────

/** Per-rule configuration (mirrors `[rules.<id>]` in TOML). */
export interface RuleConfig {
  enabled?: boolean;
}

/** Redaction section (mirrors `[redaction]` in TOML). */
export interface RedactionConfig {
  /**
   * Digest key source — typically `"env:CLOAK_DIGEST_KEY"`.
   * Maps to `digest_key` in the TOML config.
   */
  digestKey?: string;
}

/**
 * Cloak engine configuration.
 *
 * Serialized to TOML before passing to the WASM module. Rule IDs are
 * kebab-case strings matching the cloak catalog (`"github-token"`,
 * `"phone-intl"`, etc.).
 */
export interface CloakConfig {
  redaction?: RedactionConfig;
  rules?: Record<string, RuleConfig>;
}

// ── Serialization ──────────────────────────────────────────────────

/** Escape a TOML basic string value. */
function tomlString(value: string): string {
  const escaped = value
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r")
    .replace(/\t/g, "\\t");
  return `"${escaped}"`;
}

/**
 * Cloak rule IDs are kebab-case identifiers from a fixed catalog
 * (e.g. `github-token`, `phone-intl`). A rule ID containing TOML-
 * special characters (`.`, `]`, `"`, whitespace) would produce an
 * invalid or misinterpreted section header — reject early with a
 * clear message instead of forwarding a broken TOML string to the
 * Rust parser.
 */
const VALID_RULE_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

function validateRuleId(ruleId: string): void {
  if (!VALID_RULE_ID.test(ruleId)) {
    throw new Error(
      `invalid rule ID "${ruleId}": must be kebab-case (e.g. "github-token", "phone-intl")`,
    );
  }
}

/**
 * Serialize a `CloakConfig` to a TOML string.
 *
 * `digestKey` (camelCase) maps to `digest_key` (snake_case). Rule IDs
 * are passed through as-is — they are domain identifiers, not JS
 * property names, so use quoted keys: `{ 'phone-intl': { enabled: false } }`.
 */
export function configToToml(config: CloakConfig): string {
  const lines: string[] = [];

  if (config.redaction) {
    lines.push("[redaction]");
    if (config.redaction.digestKey !== undefined) {
      lines.push(`digest_key = ${tomlString(config.redaction.digestKey)}`);
    }
    lines.push("");
  }

  if (config.rules) {
    for (const [ruleId, ruleConfig] of Object.entries(config.rules)) {
      validateRuleId(ruleId);
      lines.push(`[rules.${ruleId}]`);
      if (ruleConfig.enabled !== undefined) {
        lines.push(`enabled = ${ruleConfig.enabled}`);
      }
      lines.push("");
    }
  }

  return lines.join("\n");
}
