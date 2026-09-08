//! Test-vector corpora — defined once, beside the rules (docs/02-rules.md),
//! consumed verbatim by unit and integration tests now, and by fuzz seeds
//! (S6) and bench corpora (S7) later. Never duplicated per tier (docs/03).
//!
//! Re-exported `#[doc(hidden)]` from lib.rs purely so integration tests can
//! reach it — this module is **not** part of the public API contract.

pub mod github_token;
pub mod gitlab_token;
pub mod npm_token;
pub mod overlap;
pub mod pem;

use crate::redact;
use crate::types::RuleId;

/// One test vector.
pub struct Vector {
    /// Unique human-readable name (test failure messages).
    pub name: &'static str,
    /// Raw input bytes.
    pub input: &'static [u8],
    /// Spans that MUST be redacted, ascending, non-overlapping, with the
    /// winning rule id. Empty ⇒ input must pass through byte-identical.
    pub spans: &'static [ExpectedSpan],
}

/// One expected redaction span within a [`Vector`]'s input.
pub struct ExpectedSpan {
    pub start: usize,
    pub end: usize,
    /// Winning rule id (must exist in the catalog).
    pub rule: &'static str,
}

/// Splice the expected redacted output for `v` under `key`.
pub fn expected_output(v: &Vector, key: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut pos = 0;
    for span in v.spans {
        out.extend_from_slice(&v.input[pos..span.start]);
        let digest = redact::compute_digest(&v.input[span.start..span.end], key);
        redact::write_tag(&RuleId::new(span.rule), &digest, &mut out)
            .expect("write to Vec cannot fail");
        pos = span.end;
    }
    out.extend_from_slice(&v.input[pos..]);
    out
}

/// All vectors across all rule modules (corpus composition, differential).
pub fn all_vectors() -> Vec<&'static Vector> {
    let mut all = Vec::new();
    all.extend(github_token::POSITIVE);
    all.extend(github_token::NEGATIVE);
    all.extend(gitlab_token::POSITIVE);
    all.extend(gitlab_token::NEGATIVE);
    all.extend(npm_token::POSITIVE);
    all.extend(npm_token::NEGATIVE);
    all.extend(overlap::VECTORS);
    all.extend(pem::POSITIVE);
    all.extend(pem::NEGATIVE);
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        blake3::derive_key("cloak digest key", b"vector-test-key")
    }

    #[test]
    fn expected_output_splices_two_spans() {
        let v = Vector {
            name: "synthetic-two-spans",
            input: b"aaSECRETbbHIDDENcc",
            spans: &[
                ExpectedSpan {
                    start: 2,
                    end: 8,
                    rule: "rule-x",
                },
                ExpectedSpan {
                    start: 10,
                    end: 16,
                    rule: "rule-y",
                },
            ],
        };
        let key = test_key();
        let out = expected_output(&v, &key);
        let dx = redact::compute_digest(b"SECRET", &key);
        let dy = redact::compute_digest(b"HIDDEN", &key);
        let want = format!(
            "aa{}bb{}cc",
            redact::format_tag(&RuleId::new("rule-x"), &dx),
            redact::format_tag(&RuleId::new("rule-y"), &dy),
        );
        assert_eq!(out, want.as_bytes());
    }

    #[test]
    fn expected_output_empty_spans_is_identity() {
        let v = Vector {
            name: "synthetic-passthrough",
            input: b"nothing here",
            spans: &[],
        };
        assert_eq!(expected_output(&v, &test_key()), b"nothing here");
    }

    #[test]
    fn all_vectors_non_empty_with_unique_names() {
        let all = all_vectors();
        assert!(!all.is_empty());
        let mut names = std::collections::BTreeSet::new();
        for v in &all {
            assert!(names.insert(v.name), "duplicate vector name: {}", v.name);
        }
    }

    #[test]
    fn vector_integrity() {
        // Executed over ALL vectors: spans strictly ascending, non-overlapping
        // (touching allowed — strict-overlap merge semantics), in-bounds, and
        // attributed to a real catalog rule.
        let mut known_ids: Vec<&str> = crate::rules::CATALOG.iter().map(|r| r.id).collect();
        known_ids.push(crate::engine::pem::PEM_RULE_ID);
        for v in all_vectors() {
            let mut prev_end = 0;
            for span in v.spans {
                assert!(span.start < span.end, "{}: empty span", v.name);
                assert!(
                    span.start >= prev_end,
                    "{}: spans overlap or unsorted",
                    v.name
                );
                assert!(span.end <= v.input.len(), "{}: span out of bounds", v.name);
                assert!(
                    known_ids.contains(&span.rule),
                    "{}: unknown rule id {}",
                    v.name,
                    span.rule
                );
                prev_end = span.end;
            }
        }
    }

    #[test]
    fn capped_vector_lengths() {
        // The long literals are hand-typed — pin their exact lengths so a
        // miscounted digit fails here, not as a confusing engine mismatch.
        let at_cap = github_token::POSITIVE
            .iter()
            .find(|v| v.name == "github-at-cap-255")
            .unwrap();
        assert_eq!(at_cap.input.len(), 4 + 255);
        let overflow = github_token::POSITIVE
            .iter()
            .find(|v| v.name == "github-cap-overflow-300")
            .unwrap();
        assert_eq!(overflow.input.len(), 4 + 300);
        let gitlab_cap = gitlab_token::POSITIVE
            .iter()
            .find(|v| v.name == "gitlab-at-cap-255")
            .unwrap();
        assert_eq!(gitlab_cap.input.len(), 6 + 255);
    }
}
