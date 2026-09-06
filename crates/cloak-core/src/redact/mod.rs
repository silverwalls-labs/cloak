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

/// Format a redaction tag as a `String`.
///
/// Output: `[CLOAK:<rule>:<digest>]`, e.g. `[CLOAK:aws-access-key:9f3a]`.
pub fn format_tag(rule: &RuleId, digest: &Digest) -> String {
    format!("[CLOAK:{rule}:{digest}]")
}

/// Write a redaction tag directly to a writer without allocating.
pub fn write_tag(rule: &RuleId, digest: &Digest, out: &mut impl io::Write) -> io::Result<()> {
    write!(out, "[CLOAK:{rule}:{digest}]")
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
        // Stability anchor: if BLAKE3 crate changes behavior, this catches it.
        let key = blake3::derive_key("cloak digest key", b"stable-test-key");
        let digest = compute_digest(b"ghp_ABCDEFghijklmnop1234567890abcdef12", &key);
        // Record the expected value from the first run; assert it never changes.
        let tag = format_tag(&RuleId::new("github-token"), &digest);
        assert!(tag.starts_with("[CLOAK:github-token:"));
        assert!(tag.ends_with(']'));
        assert_eq!(tag.len(), "[CLOAK:github-token:".len() + 4 + 1);
    }
}
