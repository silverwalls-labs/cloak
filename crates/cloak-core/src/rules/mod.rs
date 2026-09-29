//! Built-in detector catalog (docs/02-rules.md).
//!
//! Rules are static Rust data compiled into the engine at
//! [`Engine::new`](crate::Engine::new). Per-rule enable/disable is
//! controlled via [`Config::rules`](crate::Config) — rules not listed
//! (or listed with `enabled = true`) are compiled; disabled rules are
//! excluded from the prefilter and confirm steps.

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
// `pub` for bench-tier access (`#[doc(hidden)]` re-export in lib.rs).
pub enum ConfirmSpec {
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
/// anchored confirm DFA or custom function (see `ConfirmSpec`).
pub struct RuleSpec {
    /// Stable rule id (docs/02-rules.md — renaming is a breaking change).
    pub id: &'static str,
    /// Literal anchors for the prefilter. Every rule MUST declare at least
    /// one — this keeps the clean path at prefilter speed (docs/01).
    pub anchors: &'static [&'static [u8]],
    /// How to confirm an anchor candidate and determine the redaction span.
    pub confirm: ConfirmSpec,
    /// Max match window `W` = max anchor len + body cap. Bounds the candidate
    /// window in S2 and the carry-over buffer in S3. Must cover the confirm
    /// step's full FORWARD reach: a candidate is only confirmed once `W`
    /// bytes are present, so an undersized `W` lets the streaming flush
    /// drop a candidate before its tail arrives (#41 review).
    pub window: usize,
    /// Backward reach `B`: the maximum number of bytes BEFORE the anchor
    /// start that the confirm step may examine. Confirm functions MUST
    /// bound their backward scans to this value — an unbounded scan makes
    /// the match depend on where the carry buffer happens to start, which
    /// breaks streaming/whole-buffer parity (#27). The engine retains
    /// `window + back` bytes behind the emission boundary so a candidate's
    /// backward context is never truncated by a flush before it resolves.
    pub back: usize,
}

/// The built-in catalog. Order is significant: catalog order == overlap
/// tie-break order (docs/02-rules.md, "Overlap resolution").
/// Secrets before PII: secrets win overlap tie-breaks against PII.
pub static CATALOG: &[RuleSpec] = &[
    // ── Secret detectors (S2, CRC-validated S4/F12) ────────────────────
    RuleSpec {
        id: "github-token",
        anchors: &[b"ghp_", b"gho_", b"ghs_", b"ghu_", b"ghr_", b"github_pat_"],
        // Classic prefixes: CRC32-validated, exact prefix+36 (30 entropy +
        // 6 base62 CRC). Fine-grained `github_pat_`: shape-only, greedy
        // [0-9A-Za-z_]{36,255}. See docs/02-rules.md ¹, F12.
        confirm: ConfirmSpec::Custom(validators::confirm_github_token),
        // Body capped at 255 to bound W (docs/02); longest anchor is
        // "github_pat_" (11 bytes).
        window: 11 + 255,
        // Confirm scans forward from the anchor only.
        back: 0,
    },
    RuleSpec {
        id: "gitlab-token",
        anchors: &[b"glpat-", b"glrt-", b"gldt-"],
        confirm: ConfirmSpec::Pattern("(?:glpat-|glrt-|gldt-)[0-9A-Za-z_-]{20,255}"),
        // Body capped at 255 to bound W; longest anchor is "glpat-" (6 bytes).
        window: 6 + 255,
        // Anchored DFA match: forward from the anchor only.
        back: 0,
    },
    RuleSpec {
        id: "npm-token",
        anchors: &[b"npm_"],
        // CRC32-validated: exact prefix+36 (30 entropy + 6 base62 CRC).
        // Body alphabet is alnum only (no underscore). F12.
        confirm: ConfirmSpec::Custom(validators::confirm_npm_token),
        window: 4 + 36,
        // Confirm scans forward from the anchor only.
        back: 0,
    },
    // ── Secret detectors (S4) ────────────────────────────────────────
    RuleSpec {
        id: "aws-access-key",
        anchors: &[b"AKIA", b"ASIA"],
        confirm: ConfirmSpec::Pattern("(?:AKIA|ASIA)[0-9A-Z]{16}"),
        window: 4 + 16,
        // Anchored DFA match: forward from the anchor only.
        back: 0,
    },
    RuleSpec {
        id: "gcp-api-key",
        anchors: &[b"AIza"],
        confirm: ConfirmSpec::Pattern("AIza[0-9A-Za-z_\\-]{35}"),
        window: 4 + 35,
        // Anchored DFA match: forward from the anchor only.
        back: 0,
    },
    RuleSpec {
        id: "pypi-token",
        anchors: &[b"pypi-"],
        // Macaroon body: base64url alphabet, min 50 chars, cap 255.
        confirm: ConfirmSpec::Pattern("pypi-[A-Za-z0-9_\\-]{50,255}"),
        window: 5 + 255,
        // Anchored DFA match: forward from the anchor only.
        back: 0,
    },
    RuleSpec {
        id: "aws-secret-key",
        anchors: &[b"aws_secret", b"SecretAccessKey"],
        confirm: ConfirmSpec::Custom(validators::confirm_aws_secret),
        // Max forward span: key (21) + gap (15) + separator (1) + gap (15)
        // + value (40) = 92. The window MUST cover the full value: with
        // larger rules disabled, a 70-byte window let the flush drop the
        // candidate before the remaining value bytes arrived (#41 review).
        window: 92,
        // One-byte non-alnum boundary check before the anchor.
        back: 1,
    },
    RuleSpec {
        id: "azure-style-token",
        anchors: &[b"AccountKey=", b"accountkey=", b"sig="],
        confirm: ConfirmSpec::Custom(validators::confirm_azure_token),
        // Key (11) + value cap (255).
        window: 270,
        // Confirm scans forward from the anchor only.
        back: 0,
    },
    RuleSpec {
        id: "jwt",
        anchors: &[b"eyJ"],
        confirm: ConfirmSpec::Custom(validators::confirm_jwt),
        // JWTs can be large; cap scan at 2048.
        window: 2048,
        // Confirm scans forward from the anchor only.
        back: 0,
    },
    RuleSpec {
        id: "connection-string",
        anchors: &[b"://"],
        confirm: ConfirmSpec::Custom(validators::confirm_connection_string),
        // Forward: `://` (3) + `@` search bound (300) + `@` (1) + first
        // host byte (1). Backward: longest scheme (`mongodb+srv`) is 11.
        window: 304,
        // Bounded backward scheme scan — see confirm_connection_string.
        back: 12,
    },
    // ── Structured-PII detectors (S4) ────────────────────────────────
    RuleSpec {
        id: "email",
        anchors: &[b"@"],
        confirm: ConfirmSpec::Custom(validators::confirm_email),
        // Backward local (64, capped) + @ (1) + domain (255).
        window: 320,
        // RFC 5321 local-part cap. Locals longer than 64 bytes are capped,
        // not rejected — the redaction span covers the final 64 local
        // bytes plus the domain (#41 review).
        back: 64,
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
        // Bounded backward octet scan (confirm caps at 11 bytes).
        back: 11,
    },
    RuleSpec {
        id: "ipv6",
        // Generic hex/colon candidate path (#41 review): every IPv6
        // address contains a colon followed by a hex digit or another
        // colon, so 2-byte anchors catch every representable address —
        // fully expanded 8-group forms and uppercase hex included —
        // without an enumerated prefix list. (A bare `:` anchor costs
        // ~8% of clean-path throughput: every stray colon in prose,
        // JSON, and URLs would run a confirm.) The F01 prefix anchors
        // missed nonlisted prefixes such as `2a02:0001:…` and uppercase
        // `FE80:`; both are caught now. The confirm scan is bounded at 45
        // bytes on both sides from the anchor.
        anchors: &[
            b"::", b":0", b":1", b":2", b":3", b":4", b":5", b":6", b":7", b":8", b":9", b":a",
            b":b", b":c", b":d", b":e", b":f", b":A", b":B", b":C", b":D", b":E", b":F",
        ],
        confirm: ConfirmSpec::Custom(validators::confirm_ipv6),
        // Max IPv6 text: ~45 (the confirm scan caps at 45 in both
        // directions from the anchor).
        window: 50,
        // Bounded backward scan — see confirm_ipv6.
        back: 45,
    },
    RuleSpec {
        id: "credit-card",
        // Big Four IIN prefixes.
        // F02: added Mastercard 2-series (22-27) and Discover 644-649.
        // 2-digit anchors are used for the 2-series to cover the full
        // 2221-2720 range; the IIN check validates the 4-digit prefix.
        anchors: &[
            b"22", b"23", b"24", b"25", b"26", b"27", // Mastercard 2-series (2221-2720)
            b"34", b"37", // Amex
            b"4",  // Visa
            b"51", b"52", b"53", b"54", b"55", // Mastercard 51-55
            b"6011", b"644", b"645", b"646", b"647", b"648", b"649", b"65", // Discover
        ],
        confirm: ConfirmSpec::Custom(validators::confirm_credit_card),
        // 19 digits + 6 separators.
        window: 25,
        // One-byte non-digit boundary check before the anchor.
        back: 1,
    },
    RuleSpec {
        id: "phone-intl",
        anchors: &[b"+"],
        confirm: ConfirmSpec::Custom(validators::confirm_phone_intl),
        // + (1) + CC (3) + digits (12) + separators (6).
        window: 25,
        // One-byte non-alnum boundary check before the `+`.
        back: 1,
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
    fn back_reach_fits_within_window() {
        // The backward reach is part of the declared match window; a reach
        // larger than the window would be unenforceable.
        for rule in CATALOG {
            assert!(
                rule.back <= rule.window,
                "back reach {} exceeds window {} (rule {})",
                rule.back,
                rule.window,
                rule.id
            );
        }
    }

    #[test]
    fn window_plus_back_within_carry_bound() {
        // The engine retains max(window + back) bytes behind the emission
        // boundary; that total must stay within the shared carry-over bound
        // (2048 — the jwt window; see engine::CARRY_OVER_BOUND).
        for rule in CATALOG {
            assert!(
                rule.window + rule.back <= 2048,
                "window + back = {} exceeds the 2048 carry retention (rule {})",
                rule.window + rule.back,
                rule.id
            );
        }
    }

    #[test]
    fn pinned_windows() {
        // W values documented in docs/02-rules.md — a change here must be
        // a deliberate spec change, not drift.
        let expected = [
            // CRC-validated custom rules (F12)
            ("github-token", 266),
            ("npm-token", 40),
            // DFA rules
            ("gitlab-token", 261),
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
