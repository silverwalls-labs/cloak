use std::io;

use crate::types::{Digest, RuleId};

/// Compute a truncated keyed BLAKE3 digest of the matched bytes.
///
/// Returns the first 2 bytes (16 bits = 4 hex chars) of the keyed hash.
/// Same bytes + same key → same digest; different key → different digest.
pub fn compute_digest(matched_bytes: &[u8], key: &[u8; 32]) -> Digest {
    let hash = blake3::keyed_hash(key, matched_bytes);
    let bytes = hash.as_bytes();
    Digest::new([bytes[0], bytes[1]])
}

/// Write a redaction tag directly to a writer without allocating.
///
/// Output: `[CLOAK:<rule>:<digest>]`, e.g. `[CLOAK:aws-access-key:9f3a]`.
pub fn write_tag(rule: &RuleId, digest: &Digest, out: &mut impl io::Write) -> io::Result<()> {
    write!(out, "[CLOAK:{rule}:{digest}]")
}

/// Format a redaction tag as a `String`.
///
/// Convenience wrapper around [`write_tag`] — single source of truth for the
/// tag format.
pub fn format_tag(rule: &RuleId, digest: &Digest) -> String {
    let mut buf = Vec::new();
    write_tag(rule, digest, &mut buf).expect("write to Vec cannot fail");
    // SAFETY (not unsafe, just infallible): the tag is always valid UTF-8
    // because RuleId and Digest both produce ASCII via Display.
    String::from_utf8(buf).expect("tag is always valid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        blake3::derive_key("cloak test key", b"test-secret")
    }

    #[test]
    fn format_tag_output() {
        let rule = RuleId::new("github-token");
        let digest = Digest::new([0xab, 0xcd]);
        assert_eq!(format_tag(&rule, &digest), "[CLOAK:github-token:abcd]");
    }

    #[test]
    fn compute_digest_deterministic() {
        let key = test_key();
        let d1 = compute_digest(b"AKIA1234567890ABCDEF", &key);
        let d2 = compute_digest(b"AKIA1234567890ABCDEF", &key);
        assert_eq!(d1, d2);
    }

    #[test]
    fn compute_digest_key_sensitivity() {
        let key_a = blake3::derive_key("cloak test key", b"key-alpha");
        let key_b = blake3::derive_key("cloak test key", b"key-bravo");
        let d_a = compute_digest(b"same-input", &key_a);
        let d_b = compute_digest(b"same-input", &key_b);
        assert_ne!(d_a, d_b, "different keys must produce different digests");
    }

    #[test]
    fn compute_digest_input_sensitivity() {
        let key = test_key();
        let d1 = compute_digest(b"input-one", &key);
        let d2 = compute_digest(b"input-two", &key);
        assert_ne!(d1, d2, "different inputs must produce different digests");
    }

    #[test]
    fn write_tag_to_vec() {
        let rule = RuleId::new("email");
        let digest = Digest::new([0x01, 0xff]);
        let mut buf = Vec::new();
        write_tag(&rule, &digest, &mut buf).unwrap();
        assert_eq!(buf, format_tag(&rule, &digest).as_bytes());
    }

    #[test]
    fn known_vector_stability() {
        // Stability anchor: a BLAKE3 behavior change or digest truncation
        // regression must fail this test, not slip through silently.
        // Recorded 2026-09-06, blake3 1.8.7.
        let key = blake3::derive_key("cloak digest key", b"stable-test-key");
        let digest = compute_digest(b"ghp_ABCDEFghijklmnop1234567890abcdef12", &key);
        assert_eq!(digest.to_string(), "5d63");
        assert_eq!(
            format_tag(&RuleId::new("github-token"), &digest),
            "[CLOAK:github-token:5d63]"
        );
    }
}
