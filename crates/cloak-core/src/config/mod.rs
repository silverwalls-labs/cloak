/// Engine configuration.
///
/// Full TOML/serde config arrives in S5. For now this holds just enough
/// to construct an [`Engine`](crate::Engine).
#[derive(Debug, Clone)]
pub struct Config {
    /// Name of the environment variable holding the digest key material.
    /// Defaults to `"CLOAK_DIGEST_KEY"`. Set to `None` to force an ephemeral key.
    pub digest_key_env: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            digest_key_env: Some("CLOAK_DIGEST_KEY".into()),
        }
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

    #[test]
    fn default_config() {
        let config = Config::default();
        assert_eq!(config.digest_key_env.as_deref(), Some("CLOAK_DIGEST_KEY"));
    }

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
}
