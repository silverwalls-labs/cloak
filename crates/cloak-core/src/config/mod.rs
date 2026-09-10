//! Engine configuration — serde-first, file formats are frontends.
//!
//! v0.1 ships TOML only; YAML/JSON + `cloak config convert` are v0.2
//! follow-ups (docs/01-architecture.md §Configuration).

use std::collections::BTreeMap;

use crate::engine::BuildError;
use crate::engine::pem;
use crate::rules;

/// Top-level configuration.
///
/// All fields are optional with sensible defaults: an empty TOML file
/// (or `Config::default()`) enables every catalog rule and reads the
/// digest key from the `CLOAK_DIGEST_KEY` environment variable.
///
/// ```toml
/// [redaction]
/// digest_key = "env:CLOAK_DIGEST_KEY"
///
/// [rules.phone-intl]
/// enabled = false
/// ```
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Digest-key and redaction settings.
    #[serde(default)]
    pub redaction: RedactionConfig,

    /// Per-rule overrides keyed by rule id. Rules not listed here use
    /// defaults (enabled = true).
    #[serde(default)]
    pub rules: BTreeMap<String, RuleConfig>,
}

/// The `[redaction]` section.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactionConfig {
    /// Digest key source. `"env:VAR_NAME"` reads from an environment
    /// variable and derives the key via BLAKE3 KDF. Absent or empty
    /// uses an ephemeral key (silent — no warning).
    ///
    /// Default: `"env:CLOAK_DIGEST_KEY"`.
    #[serde(default = "default_digest_key")]
    pub digest_key: String,
}

fn default_digest_key() -> String {
    "env:CLOAK_DIGEST_KEY".into()
}

impl Default for RedactionConfig {
    fn default() -> Self {
        Self {
            digest_key: default_digest_key(),
        }
    }
}

/// Per-rule configuration in `[rules.<id>]`.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    /// Whether this rule is active. Default: `true`.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

impl Config {
    /// Parse a TOML string into a `Config`.
    ///
    /// Returns [`BuildError::InvalidConfig`] on parse errors. The
    /// parsed config is NOT validated against the rule catalog — call
    /// [`validate`](Self::validate) (or let [`Engine::new`](crate::Engine::new)
    /// call it) for that.
    pub fn from_toml(s: &str) -> Result<Self, BuildError> {
        toml::from_str(s).map_err(|e| BuildError::InvalidConfig(e.to_string()))
    }

    /// Validate the config against the rule catalog.
    ///
    /// Returns [`BuildError::InvalidConfig`] if any key in `self.rules`
    /// does not match a known rule id from the catalog or the PEM
    /// pseudo-rule.
    pub fn validate(&self) -> Result<(), BuildError> {
        // Digest key: must be empty (ephemeral) or start with "env:".
        let dk = &self.redaction.digest_key;
        if !dk.is_empty() && !dk.starts_with("env:") {
            return Err(BuildError::InvalidConfig(format!(
                "invalid digest_key \"{dk}\": must start with \"env:\" \
                 (e.g. \"env:CLOAK_DIGEST_KEY\"); inline keys are not supported"
            )));
        }

        let known: std::collections::BTreeSet<&str> = rules::CATALOG
            .iter()
            .map(|r| r.id)
            .chain(std::iter::once(pem::PEM_RULE_ID))
            .collect();

        for id in self.rules.keys() {
            if !known.contains(id.as_str()) {
                let names: Vec<&str> = known.iter().copied().collect();
                return Err(BuildError::InvalidConfig(format!(
                    "unknown rule `{id}` in [rules.{id}]; known rules: {}",
                    names.join(", ")
                )));
            }
        }
        Ok(())
    }

    /// Whether the rule with the given id is enabled.
    ///
    /// A rule is enabled unless the config explicitly sets
    /// `enabled = false`.
    pub fn is_rule_enabled(&self, id: &str) -> bool {
        self.rules.get(id).is_none_or(|rc| rc.enabled)
    }

    /// Create a config for testing: ephemeral digest key with no env
    /// lookup and no warning.
    pub fn ephemeral() -> Self {
        Self {
            redaction: RedactionConfig {
                digest_key: String::new(),
            },
            rules: BTreeMap::new(),
        }
    }

    /// Extract the environment variable name from the `digest_key` spec.
    ///
    /// Returns `Some("VAR_NAME")` if `digest_key` starts with `"env:"`,
    /// `None` otherwise (triggering silent ephemeral mode).
    pub(crate) fn digest_key_env_var(&self) -> Option<&str> {
        self.redaction.digest_key.strip_prefix("env:")
    }
}

/// Error resolving the digest key.
#[derive(Debug, thiserror::Error)]
pub enum DigestKeyError {
    #[error("failed to obtain entropy for ephemeral digest key: {0}")]
    Entropy(getrandom::Error),
}

/// Resolve the digest key from the environment.
///
/// - `Some(var_name)` with a set, non-empty env var → derive key via BLAKE3 KDF.
/// - `Some(var_name)` with unset/empty env var → ephemeral key + warning to stderr.
/// - `None` → ephemeral key silently (explicit opt-in, no warning).
pub(crate) fn resolve_digest_key(env_var_name: Option<&str>) -> Result<[u8; 32], DigestKeyError> {
    if let Some(var_name) = env_var_name
        && let Ok(value) = std::env::var(var_name)
        && !value.is_empty()
    {
        return Ok(blake3::derive_key("cloak digest key", value.as_bytes()));
    }

    let mut key = [0u8; 32];
    getrandom::fill(&mut key).map_err(DigestKeyError::Entropy)?;

    // Only warn when a var was configured but the lookup failed — not when
    // ephemeral mode was explicitly chosen (digest_key_env: None).
    if let Some(var_name) = env_var_name {
        eprintln!(
            "cloak: {var_name} not set; \
             using ephemeral digest key (correlation limited to this process)"
        );
    }

    Ok(key)
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;

    // ── Defaults ────────────────────────────────────────────────────

    #[test]
    fn default_config() {
        let config = Config::default();
        assert_eq!(config.redaction.digest_key, "env:CLOAK_DIGEST_KEY");
        assert!(config.rules.is_empty());
    }

    #[test]
    fn ephemeral_config() {
        let config = Config::ephemeral();
        assert!(config.digest_key_env_var().is_none());
        assert!(config.rules.is_empty());
    }

    #[test]
    fn default_digest_key_env_var() {
        let config = Config::default();
        assert_eq!(config.digest_key_env_var(), Some("CLOAK_DIGEST_KEY"));
    }

    // ── TOML parsing ────────────────────────────────────────────────

    #[test]
    fn empty_toml_parses_to_defaults() {
        let config = Config::from_toml("").unwrap();
        assert_eq!(config.redaction.digest_key, "env:CLOAK_DIGEST_KEY");
        assert!(config.rules.is_empty());
    }

    #[test]
    fn toml_digest_key() {
        let config = Config::from_toml(
            r#"
            [redaction]
            digest_key = "env:MY_KEY"
            "#,
        )
        .unwrap();
        assert_eq!(config.digest_key_env_var(), Some("MY_KEY"));
    }

    #[test]
    fn toml_rule_disable() {
        let config = Config::from_toml(
            r#"
            [rules.phone-intl]
            enabled = false
            "#,
        )
        .unwrap();
        assert!(!config.is_rule_enabled("phone-intl"));
        assert!(config.is_rule_enabled("github-token"));
    }

    #[test]
    fn toml_rule_enable_explicit() {
        let config = Config::from_toml(
            r#"
            [rules.aws-access-key]
            enabled = true
            "#,
        )
        .unwrap();
        assert!(config.is_rule_enabled("aws-access-key"));
    }

    #[test]
    fn toml_pem_disable() {
        let config = Config::from_toml(
            r#"
            [rules.pem-private-key]
            enabled = false
            "#,
        )
        .unwrap();
        assert!(!config.is_rule_enabled("pem-private-key"));
    }

    #[test]
    fn toml_rule_config_defaults_enabled() {
        // An empty `[rules.github-token]` section keeps the rule enabled
        // (the `enabled` field defaults to true).
        let config = Config::from_toml(
            r#"
            [rules.github-token]
            "#,
        )
        .unwrap();
        assert!(config.is_rule_enabled("github-token"));
    }

    // ── deny_unknown_fields ─────────────────────────────────────────

    #[test]
    fn unknown_top_level_field() {
        let err = Config::from_toml("foo = 1").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("foo"),
            "error should name the unknown field: {msg}"
        );
    }

    #[test]
    fn unknown_redaction_field() {
        let err = Config::from_toml("[redaction]\nfoo = \"bar\"").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("foo"),
            "error should name the unknown field: {msg}"
        );
    }

    #[test]
    fn unknown_rule_field() {
        let err = Config::from_toml("[rules.github-token]\nfoo = true").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("foo"),
            "error should name the unknown field: {msg}"
        );
    }

    #[test]
    fn malformed_toml() {
        let err = Config::from_toml("[[[broken").unwrap_err();
        assert!(
            err.to_string().contains("invalid"),
            "should report parse error: {err}"
        );
    }

    // ── Validation ──────────────────────────────────────────────────

    #[test]
    fn validate_empty_rules_ok() {
        Config::default().validate().unwrap();
    }

    #[test]
    fn validate_all_known_rules_ok() {
        let mut config = Config::default();
        for spec in rules::CATALOG {
            config
                .rules
                .insert(spec.id.into(), RuleConfig { enabled: true });
        }
        config
            .rules
            .insert(pem::PEM_RULE_ID.into(), RuleConfig { enabled: true });
        config.validate().unwrap();
    }

    #[test]
    fn validate_unknown_rule_hard_error() {
        let mut config = Config::default();
        config
            .rules
            .insert("not-a-rule".into(), RuleConfig { enabled: false });
        let err = config.validate().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not-a-rule"),
            "should name the unknown rule: {msg}"
        );
    }

    #[test]
    fn validate_typo_rule_hard_error() {
        let mut config = Config::default();
        config.rules.insert(
            "github_token".into(), // underscore, not dash
            RuleConfig { enabled: false },
        );
        assert!(config.validate().is_err());
    }

    // ── resolve_digest_key ──────────────────────────────────────────

    #[test]
    fn resolve_key_from_env() {
        let var = "CLOAK_TEST_KEY_FROM_ENV";
        // SAFETY: test-only; each test uses a unique env var name to avoid races.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { std::env::set_var(var, "my-secret-key") };
        let key1 = resolve_digest_key(Some(var)).unwrap();
        let key2 = resolve_digest_key(Some(var)).unwrap();
        assert_eq!(key1, key2, "same env value must produce same key");
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { std::env::remove_var(var) };
    }

    #[test]
    fn resolve_key_different_values() {
        let var_a = "CLOAK_TEST_KEY_DIFF_A";
        let var_b = "CLOAK_TEST_KEY_DIFF_B";
        // SAFETY: test-only; unique var names per test.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            std::env::set_var(var_a, "value-alpha");
            std::env::set_var(var_b, "value-bravo");
        }
        let key_a = resolve_digest_key(Some(var_a)).unwrap();
        let key_b = resolve_digest_key(Some(var_b)).unwrap();
        assert_ne!(key_a, key_b, "different values must produce different keys");
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            std::env::remove_var(var_a);
            std::env::remove_var(var_b);
        }
    }

    #[test]
    fn resolve_key_ephemeral_warns_when_var_configured() {
        let var = "CLOAK_TEST_KEY_UNSET_EPHEMERAL";
        // SAFETY: test-only; ensuring the var is absent.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { std::env::remove_var(var) };
        let key = resolve_digest_key(Some(var)).unwrap();
        assert_ne!(key, [0u8; 32], "ephemeral key must not be all-zero");
    }

    #[test]
    fn resolve_key_none_silent_ephemeral() {
        // None = explicit opt-in to ephemeral mode, no warning emitted.
        let key = resolve_digest_key(None).unwrap();
        assert_ne!(key, [0u8; 32]);
    }

    #[test]
    fn resolve_key_empty_var_name() {
        // "env:" → strip_prefix yields "" → std::env::var("") fails →
        // ephemeral + warning.
        let key = resolve_digest_key(Some("")).unwrap();
        assert_ne!(key, [0u8; 32]);
    }

    #[test]
    fn resolve_key_env_var_set_to_empty() {
        let var = "CLOAK_TEST_KEY_EMPTY_VAL";
        // SAFETY: test-only; unique var name.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { std::env::set_var(var, "") };
        // Empty value triggers the !value.is_empty() check → ephemeral.
        let key = resolve_digest_key(Some(var)).unwrap();
        assert_ne!(key, [0u8; 32]);
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { std::env::remove_var(var) };
    }

    // ── digest_key spec edge cases ──────────────────────────────────

    #[test]
    fn digest_key_empty_string() {
        let config = Config::from_toml("[redaction]\ndigest_key = \"\"").unwrap();
        assert_eq!(
            config.digest_key_env_var(),
            None,
            "empty → silent ephemeral"
        );
    }

    #[test]
    fn digest_key_env_prefix_no_var_name() {
        let config = Config::from_toml("[redaction]\ndigest_key = \"env:\"").unwrap();
        assert_eq!(
            config.digest_key_env_var(),
            Some(""),
            "env: with no name → Some empty"
        );
    }

    #[test]
    fn digest_key_non_env_prefix_rejected() {
        // A digest_key that doesn't start with "env:" is a likely user
        // mistake (thinking the value is used directly). Validation rejects
        // it to prevent silent ephemeral degradation.
        let config = Config::from_toml("[redaction]\ndigest_key = \"literal:my-key\"").unwrap();
        let err = config.validate().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("env:"),
            "error should mention env: prefix: {msg}"
        );
    }

    // ── Low-priority hardening ──────────────────────────────────────

    #[test]
    fn validate_case_sensitivity() {
        let mut config = Config::default();
        config
            .rules
            .insert("GitHub-Token".into(), RuleConfig { enabled: false });
        assert!(
            config.validate().is_err(),
            "mixed-case rule id must be rejected"
        );
    }

    #[test]
    fn toml_duplicate_section_error() {
        let err = Config::from_toml(
            "[rules.github-token]\nenabled = true\n[rules.github-token]\nenabled = false\n",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("github-token"),
            "duplicate section must be rejected"
        );
    }

    #[test]
    fn toml_multi_rule_disable() {
        let config = Config::from_toml(
            r#"
[rules.github-token]
enabled = false
[rules.npm-token]
enabled = false
[rules.phone-intl]
enabled = false
"#,
        )
        .unwrap();
        assert!(!config.is_rule_enabled("github-token"));
        assert!(!config.is_rule_enabled("npm-token"));
        assert!(!config.is_rule_enabled("phone-intl"));
        assert!(config.is_rule_enabled("aws-access-key")); // not mentioned
    }

    #[test]
    fn toml_comments_only() {
        let config = Config::from_toml("# this is a comment\n# another comment\n").unwrap();
        assert_eq!(config.redaction.digest_key, "env:CLOAK_DIGEST_KEY");
        assert!(config.rules.is_empty());
    }
}
