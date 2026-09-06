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

/// Resolve the digest key from the environment.
///
/// If `env_var_name` is `Some` and the variable is set and non-empty, the value
/// is run through `blake3::derive_key` (any string works as key material).
/// Otherwise an ephemeral per-process key is generated via `getrandom` and a
/// warning is emitted to stderr.
pub(crate) fn resolve_digest_key(env_var_name: Option<&str>) -> [u8; 32] {
    if let Some(var_name) = env_var_name
        && let Ok(value) = std::env::var(var_name)
        && !value.is_empty()
    {
        return blake3::derive_key("cloak digest key", value.as_bytes());
    }

    let mut key = [0u8; 32];
    getrandom::fill(&mut key).expect("failed to obtain entropy for ephemeral digest key");
    eprintln!(
        "cloak: no CLOAK_DIGEST_KEY set; \
         using ephemeral digest key (correlation limited to this process)"
    );
    key
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
        let key1 = resolve_digest_key(Some(var));
        let key2 = resolve_digest_key(Some(var));
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
        let key_a = resolve_digest_key(Some(var_a));
        let key_b = resolve_digest_key(Some(var_b));
        assert_ne!(key_a, key_b, "different values must produce different keys");
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            std::env::remove_var(var_a);
            std::env::remove_var(var_b);
        }
    }

    #[test]
    fn resolve_key_ephemeral() {
        let var = "CLOAK_TEST_KEY_UNSET_EPHEMERAL";
        // SAFETY: test-only; ensuring the var is absent.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { std::env::remove_var(var) };
        let key = resolve_digest_key(Some(var));
        assert_ne!(key, [0u8; 32], "ephemeral key must not be all-zero");
    }

    #[test]
    fn resolve_key_none_forces_ephemeral() {
        let key = resolve_digest_key(None);
        assert_ne!(key, [0u8; 32]);
    }
}
