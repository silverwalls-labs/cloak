//! Built-in detector catalog (docs/02-rules.md).
//!
//! Rules are static Rust data compiled into the engine at
//! [`Engine::new`](crate::Engine::new). Per-rule enable/disable config
//! arrives in S5; in S2 every catalog rule is always on.

pub mod validators;
pub mod vectors;

use crate::engine::confirm::ConfirmMatch;

/// How a rule's confirm step works.
///
/// `Pattern` rules are compiled into a `regex-automata` DFA at engine
/// build time. `Custom` rules use an arbitrary function — needed when
/// the confirm step requires backward-looking from the anchor (email `@`),
/// custom validation (Luhn, JWT decode), or partial redaction
/// (context-keyed rules that redact only the value sub-span).
pub(crate) enum ConfirmSpec {
    /// Anchored regex pattern compiled into a DFA. The full DFA match
    /// span is the redaction span (byte-oriented, ASCII classes only,
    /// greedy — leftmost-first must equal longest-at-anchor;
    /// see `engine/confirm.rs`).
    Pattern(&'static str),
    /// Custom confirm function. Receives the full haystack and the
    /// anchor start position. Returns `None` to reject, or
    /// `Some(ConfirmMatch)` with the redaction span — which may differ
    /// from the DFA match span for context-keyed rules.
    Custom(fn(&[u8], usize) -> Option<ConfirmMatch>),
}

/// Static specification of one detection rule.
///
/// Compiled at engine build time into a prefilter pattern set and an
/// anchored confirm DFA or custom function (see [`ConfirmSpec`]).
pub(crate) struct RuleSpec {
    /// Stable rule id (docs/02-rules.md — renaming is a breaking change).
    pub id: &'static str,
    /// Literal anchors for the prefilter. Every rule MUST declare at least
    /// one — this keeps the clean path at prefilter speed (docs/01).
    pub anchors: &'static [&'static [u8]],
    /// How to confirm an anchor candidate and determine the redaction span.
    pub confirm: ConfirmSpec,
    /// Max match window `W` = max anchor len + body cap. Bounds the candidate
    /// window in S2 and the carry-over buffer in S3.
    pub window: usize,
}

/// The built-in catalog. Order is significant: catalog order == overlap
/// tie-break order (docs/02-rules.md, "Overlap resolution").
/// Secrets before PII: secrets win overlap tie-breaks against PII.
pub(crate) static CATALOG: &[RuleSpec] = &[
    // ── Secret detectors (S2) ────────────────────────────────────────
    RuleSpec {
        id: "github-token",
        anchors: &[b"ghp_", b"gho_", b"ghs_", b"ghu_", b"ghr_", b"github_pat_"],
        confirm: ConfirmSpec::Pattern(
            "(?:ghp_|gho_|ghs_|ghu_|ghr_|github_pat_)[0-9A-Za-z_]{36,255}",
        ),
        // Body capped at 255 to bound W (docs/02); longest anchor is
        // "github_pat_" (11 bytes).
        window: 11 + 255,
    },
    RuleSpec {
        id: "gitlab-token",
        anchors: &[b"glpat-", b"glrt-", b"gldt-"],
        confirm: ConfirmSpec::Pattern("(?:glpat-|glrt-|gldt-)[0-9A-Za-z_-]{20,255}"),
        // Body capped at 255 to bound W; longest anchor is "glpat-" (6 bytes).
        window: 6 + 255,
    },
    RuleSpec {
        id: "npm-token",
        anchors: &[b"npm_"],
        // Spec-literal: exactly 36 body chars, no trailing-boundary check —
        // a longer alnum run matches its first 36 (docs/02-rules.md).
        confirm: ConfirmSpec::Pattern("npm_[0-9A-Za-z]{36}"),
        window: 4 + 36,
    },
    // ── Secret detectors (S4) ────────────────────────────────────────
    RuleSpec {
        id: "aws-access-key",
        anchors: &[b"AKIA", b"ASIA"],
        confirm: ConfirmSpec::Pattern("(?:AKIA|ASIA)[0-9A-Z]{16}"),
        window: 4 + 16,
    },
    RuleSpec {
        id: "gcp-api-key",
        anchors: &[b"AIza"],
        confirm: ConfirmSpec::Pattern("AIza[0-9A-Za-z_\\-]{35}"),
        window: 4 + 35,
    },
    RuleSpec {
        id: "pypi-token",
        anchors: &[b"pypi-"],
        // Macaroon body: base64url alphabet, min 50 chars, cap 255.
        confirm: ConfirmSpec::Pattern("pypi-[A-Za-z0-9_\\-]{50,255}"),
        window: 5 + 255,
    },
    RuleSpec {
        id: "aws-secret-key",
        anchors: &[b"aws_secret", b"SecretAccessKey"],
        confirm: ConfirmSpec::Custom(validators::confirm_aws_secret),
        // Key name (21) + separator (3) + value (40) + margin.
        window: 70,
    },
    RuleSpec {
        id: "azure-style-token",
        anchors: &[b"AccountKey=", b"accountkey=", b"sig="],
        confirm: ConfirmSpec::Custom(validators::confirm_azure_token),
        // Key (11) + value cap (255).
        window: 270,
    },
    RuleSpec {
        id: "jwt",
        anchors: &[b"eyJ"],
        confirm: ConfirmSpec::Custom(validators::confirm_jwt),
        // JWTs can be large; cap scan at 2048.
        window: 2048,
    },
    RuleSpec {
        id: "connection-string",
        anchors: &[b"://"],
        confirm: ConfirmSpec::Custom(validators::confirm_connection_string),
        // Backward scheme (12) + :// (3) + userinfo + host cap.
        window: 300,
    },
    // ── Structured-PII detectors (S4) ────────────────────────────────
    RuleSpec {
        id: "email",
        anchors: &[b"@"],
        confirm: ConfirmSpec::Custom(validators::confirm_email),
        // Backward local (64) + @ (1) + domain (255).
        window: 320,
    },
    RuleSpec {
        id: "ipv4",
        // Digit-dot composites: more selective than bare `.`.
        anchors: &[
            b"0.", b"1.", b"2.", b"3.", b"4.", b"5.", b"6.", b"7.", b"8.", b"9.",
        ],
        confirm: ConfirmSpec::Custom(validators::confirm_ipv4),
        // Backward (3) + max IP (15) = 18.
        window: 18,
    },
    RuleSpec {
        id: "ipv6",
        anchors: &[b"::"],
        confirm: ConfirmSpec::Custom(validators::confirm_ipv6),
        // Max IPv6 text: ~45.
        window: 50,
    },
    RuleSpec {
        id: "credit-card",
        // Big Four IIN prefixes.
        anchors: &[
            b"34", b"37", // Amex
            b"4",  // Visa
            b"51", b"52", b"53", b"54", b"55", // Mastercard
            b"6011", b"65", // Discover
        ],
        confirm: ConfirmSpec::Custom(validators::confirm_credit_card),
        // 19 digits + 6 separators.
        window: 25,
    },
    RuleSpec {
        id: "phone-intl",
        anchors: &[b"+"],
        confirm: ConfirmSpec::Custom(validators::confirm_phone_intl),
        // + (1) + CC (3) + digits (12) + separators (6).
        window: 25,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_order_is_tie_break_order() {
        let ids: Vec<&str> = CATALOG.iter().map(|r| r.id).collect();
        assert_eq!(
            ids,
            [
                // Secret detectors
                "github-token",
                "gitlab-token",
                "npm-token",
                "aws-access-key",
                "gcp-api-key",
                "pypi-token",
                "aws-secret-key",
                "azure-style-token",
                "jwt",
                "connection-string",
                // PII detectors
                "email",
                "ipv4",
                "ipv6",
                "credit-card",
                "phone-intl",
            ]
        );
    }

    #[test]
    fn ids_unique_and_non_empty() {
        let mut seen = std::collections::BTreeSet::new();
        for rule in CATALOG {
            assert!(!rule.id.is_empty());
            assert!(seen.insert(rule.id), "duplicate rule id: {}", rule.id);
        }
    }

    #[test]
    fn every_rule_has_at_least_one_anchor() {
        for rule in CATALOG {
            assert!(
                !rule.anchors.is_empty(),
                "rule {} violates the mandatory-anchor requirement",
                rule.id
            );
            for anchor in rule.anchors {
                assert!(!anchor.is_empty(), "rule {} has an empty anchor", rule.id);
            }
        }
    }

    #[test]
    fn windows_are_positive_and_larger_than_anchors() {
        // Every rule's window must be larger than its longest anchor —
        // otherwise the confirm step has zero bytes to work with.
        for rule in CATALOG {
            let max_anchor = rule.anchors.iter().map(|a| a.len()).max().unwrap();
            assert!(
                rule.window > max_anchor,
                "window must leave room for a body after the longest anchor (rule {})",
                rule.id
            );
        }
    }

    #[test]
    fn pinned_windows_for_dfa_rules() {
        // W values for DFA rules are documented in docs/02-rules.md —
        // a change here must be a deliberate spec change, not drift.
        let expected = [
            ("github-token", 266),
            ("gitlab-token", 261),
            ("npm-token", 40),
            ("aws-access-key", 20),
            ("gcp-api-key", 39),
            ("pypi-token", 260),
        ];
        for (id, w) in expected {
            let rule = CATALOG.iter().find(|r| r.id == id).unwrap();
            assert_eq!(rule.window, w, "W drifted for rule {}", rule.id);
        }
    }

    #[test]
    fn pattern_rules_contain_their_anchors() {
        // Every Pattern rule's anchor must be reachable by the pattern's
        // alternation — cheap sanity: each anchor appears in the pattern.
        for rule in CATALOG {
            if let ConfirmSpec::Pattern(pat) = rule.confirm {
                for anchor in rule.anchors {
                    let anchor_str = std::str::from_utf8(anchor).unwrap();
                    assert!(
                        pat.contains(anchor_str),
                        "anchor {anchor_str:?} missing from confirm pattern of {}",
                        rule.id
                    );
                }
            }
        }
    }
}
