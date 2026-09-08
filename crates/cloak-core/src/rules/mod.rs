//! Built-in detector catalog (docs/02-rules.md).
//!
//! Rules are static Rust data compiled into the engine at
//! [`Engine::new`](crate::Engine::new). Per-rule enable/disable config
//! arrives in S5; in S2 every catalog rule is always on.

pub mod vectors;

/// Static specification of one detection rule.
///
/// Compiled at engine build time into a prefilter pattern set and an
/// anchored confirm DFA (see `engine/confirm.rs` for the constraints
/// `confirm_pattern` must satisfy).
pub(crate) struct RuleSpec {
    /// Stable rule id (docs/02-rules.md — renaming is a breaking change).
    pub id: &'static str,
    /// Literal anchors for the prefilter. Every rule MUST declare at least
    /// one — this keeps the clean path at prefilter speed (docs/01).
    pub anchors: &'static [&'static [u8]],
    /// Anchored confirm pattern (byte-oriented, ASCII classes only, greedy —
    /// leftmost-first must equal longest-at-anchor; see `engine/confirm.rs`).
    pub confirm_pattern: &'static str,
    /// Max match window `W` = max anchor len + body cap. Bounds the candidate
    /// window in S2 and the carry-over buffer in S3.
    pub window: usize,
}

/// The built-in catalog. Order is significant: catalog order == overlap
/// tie-break order (docs/02-rules.md, "Overlap resolution").
pub(crate) const CATALOG: &[RuleSpec] = &[
    RuleSpec {
        id: "github-token",
        anchors: &[b"ghp_", b"gho_", b"ghs_", b"ghu_", b"ghr_", b"github_pat_"],
        confirm_pattern: "(?:ghp_|gho_|ghs_|ghu_|ghr_|github_pat_)[0-9A-Za-z_]{36,255}",
        // Body capped at 255 to bound W (docs/02); longest anchor is
        // "github_pat_" (11 bytes).
        window: 11 + 255,
    },
    RuleSpec {
        id: "gitlab-token",
        anchors: &[b"glpat-", b"glrt-", b"gldt-"],
        confirm_pattern: "(?:glpat-|glrt-|gldt-)[0-9A-Za-z_-]{20,255}",
        // Body capped at 255 to bound W; longest anchor is "glpat-" (6 bytes).
        window: 6 + 255,
    },
    RuleSpec {
        id: "npm-token",
        anchors: &[b"npm_"],
        // Spec-literal: exactly 36 body chars, no trailing-boundary check —
        // a longer alnum run matches its first 36 (docs/02-rules.md).
        confirm_pattern: "npm_[0-9A-Za-z]{36}",
        window: 4 + 36,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_order_is_tie_break_order() {
        let ids: Vec<&str> = CATALOG.iter().map(|r| r.id).collect();
        assert_eq!(ids, ["github-token", "gitlab-token", "npm-token"]);
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
    fn window_is_max_anchor_len_plus_body_cap() {
        // W values are documented in docs/02-rules.md — a change here must
        // be a deliberate spec change, not drift.
        let expected = [
            ("github-token", 266),
            ("gitlab-token", 261),
            ("npm-token", 40),
        ];
        for (rule, (id, w)) in CATALOG.iter().zip(expected) {
            assert_eq!(rule.id, id);
            assert_eq!(rule.window, w, "W drifted for rule {}", rule.id);
            let max_anchor = rule.anchors.iter().map(|a| a.len()).max().unwrap();
            assert!(
                rule.window > max_anchor,
                "window must leave room for a body after the longest anchor"
            );
        }
    }

    #[test]
    fn windows_bound_confirm_patterns() {
        // Every anchor must be a prefix reachable by the confirm pattern's
        // alternation — cheap sanity: each anchor appears in the pattern.
        for rule in CATALOG {
            for anchor in rule.anchors {
                let anchor_str = std::str::from_utf8(anchor).unwrap();
                assert!(
                    rule.confirm_pattern.contains(anchor_str),
                    "anchor {anchor_str:?} missing from confirm pattern of {}",
                    rule.id
                );
            }
        }
    }
}
