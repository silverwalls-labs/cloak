//! Deliberately naive whole-buffer redaction — the differential-test oracle
//! (docs/03-guarantee-and-testing.md: `redact_reference`).
//!
//! Independent of the production matcher **by design**: hand-rolled O(n·m)
//! anchor search, per-rule confirm loops (no regex), naive group-absorption
//! overlap merge. It shares ONLY the golden-tested digest/tag primitives
//! (`crate::redact`). Rule constants are re-declared inline — duplication is
//! the point of an oracle; a unit test cross-checks them against
//! `rules::CATALOG` so a typo on either side is caught without coupling the
//! algorithms.
//!
//! Re-exported `#[doc(hidden)]` from lib.rs purely so integration tests can
//! reach it — this module is **not** part of the public API contract.

use std::collections::BTreeMap;

use crate::types::{RuleId, Stats};

/// Rule indices — must mirror catalog order (cross-checked by unit test).
const GITHUB: usize = 0;
const GITLAB: usize = 1;
const NPM: usize = 2;
/// PEM is a separate layer, not in CATALOG — lives after catalog indices.
const PEM: usize = 3;

const RULE_IDS: [&str; 4] = [
    "github-token",
    "gitlab-token",
    "npm-token",
    "pem-private-key",
];

const GITHUB_PREFIXES: [&[u8]; 6] = [b"ghp_", b"gho_", b"ghs_", b"ghu_", b"ghr_", b"github_pat_"];
const GITLAB_PREFIXES: [&[u8]; 3] = [b"glpat-", b"glrt-", b"gldt-"];
const NPM_PREFIX: &[u8] = b"npm_";

const GITHUB_MIN: usize = 36;
const GITLAB_MIN: usize = 20;
const NPM_EXACT: usize = 36;
const BODY_CAP: usize = 255;

/// One confirmed match, pre-merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RefMatch {
    start: usize,
    end: usize,
    rule: usize,
}

fn is_github_body(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_gitlab_body(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn is_npm_body(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

fn confirm_github(input: &[u8], start: usize) -> Option<usize> {
    let rest = &input[start..];
    let prefix = GITHUB_PREFIXES.iter().find(|p| rest.starts_with(p))?;
    let body = &rest[prefix.len()..];
    let mut taken = 0;
    while taken < body.len() && taken < BODY_CAP && is_github_body(body[taken]) {
        taken += 1;
    }
    (taken >= GITHUB_MIN).then_some(start + prefix.len() + taken)
}

fn confirm_gitlab(input: &[u8], start: usize) -> Option<usize> {
    let rest = &input[start..];
    let prefix = GITLAB_PREFIXES.iter().find(|p| rest.starts_with(p))?;
    let body = &rest[prefix.len()..];
    let mut taken = 0;
    while taken < body.len() && taken < BODY_CAP && is_gitlab_body(body[taken]) {
        taken += 1;
    }
    (taken >= GITLAB_MIN).then_some(start + prefix.len() + taken)
}

fn confirm_npm(input: &[u8], start: usize) -> Option<usize> {
    let rest = &input[start..];
    if !rest.starts_with(NPM_PREFIX) {
        return None;
    }
    let body = &rest[NPM_PREFIX.len()..];
    let mut taken = 0;
    while taken < body.len() && taken < NPM_EXACT && is_npm_body(body[taken]) {
        taken += 1;
    }
    (taken == NPM_EXACT).then_some(start + NPM_PREFIX.len() + taken)
}

// PEM constants (oracle-independent re-declarations, cross-checked by test).
const PEM_BEGIN: &[u8] = b"-----BEGIN ";
const PEM_DASHES: &[u8] = b"-----";
const PEM_BAIL_OUT: usize = 16_384;
const PEM_KEY_TYPES: [&[u8]; 6] = [
    b"RSA PRIVATE KEY",
    b"EC PRIVATE KEY",
    b"DSA PRIVATE KEY",
    b"OPENSSH PRIVATE KEY",
    b"ENCRYPTED PRIVATE KEY",
    b"PRIVATE KEY",
];

/// Find all PEM private-key blocks. Returns body spans (between BEGIN and
/// END markers). Enforces bail-out at `PEM_BAIL_OUT` bytes.
fn find_pem_blocks(input: &[u8]) -> Vec<RefMatch> {
    let mut blocks = Vec::new();
    let mut pos = 0;
    while pos < input.len() {
        // Look for -----BEGIN
        if let Some(offset) = find_bytes(&input[pos..], PEM_BEGIN) {
            let begin_start = pos + offset;
            let after_begin = begin_start + PEM_BEGIN.len();
            // Check if it's a private key type.
            if let Some((begin_line_end, key_type)) = confirm_pem_begin_ref(input, after_begin) {
                // Body starts after the BEGIN line.
                let body_start = begin_line_end;
                // Look for the matching END marker.
                let mut end_marker = b"-----END ".to_vec();
                end_marker.extend_from_slice(key_type);
                end_marker.extend_from_slice(PEM_DASHES);

                if let Some(end_offset) = find_bytes(&input[body_start..], &end_marker) {
                    let body_end = body_start + end_offset;
                    let actual_body_len = body_end - body_start;
                    if actual_body_len <= PEM_BAIL_OUT {
                        blocks.push(RefMatch {
                            start: body_start,
                            end: body_end,
                            rule: PEM,
                        });
                        pos = body_end + end_marker.len();
                        continue;
                    } else {
                        // Bail-out: redact first PEM_BAIL_OUT bytes of body.
                        let bail_end = body_start + PEM_BAIL_OUT;
                        blocks.push(RefMatch {
                            start: body_start,
                            end: bail_end,
                            rule: PEM,
                        });
                        pos = bail_end;
                        continue;
                    }
                } else {
                    // No END marker: bail-out the entire remaining body.
                    let bail_end = (body_start + PEM_BAIL_OUT).min(input.len());
                    blocks.push(RefMatch {
                        start: body_start,
                        end: bail_end,
                        rule: PEM,
                    });
                    pos = bail_end;
                    continue;
                }
            }
            pos = after_begin;
        } else {
            break;
        }
    }
    blocks
}

fn confirm_pem_begin_ref(input: &[u8], after_begin: usize) -> Option<(usize, &'static [u8])> {
    let rest = input.get(after_begin..)?;
    for &key_type in &PEM_KEY_TYPES {
        if rest.starts_with(key_type) {
            let after_type = rest.get(key_type.len()..)?;
            if after_type.starts_with(PEM_DASHES) {
                let begin_line_end = after_begin + key_type.len() + PEM_DASHES.len();
                // Idempotence: skip already-redacted PEM blocks.
                if input
                    .get(begin_line_end..)
                    .is_some_and(|b| b.starts_with(b"[CLOAK:"))
                {
                    return None;
                }
                return Some((begin_line_end, key_type));
            }
        }
    }
    None
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Check if a position falls inside any PEM body span.
fn is_in_pem_region(pos: usize, pem_blocks: &[RefMatch]) -> bool {
    pem_blocks.iter().any(|b| pos >= b.start && pos < b.end)
}

/// Try every offset × every rule. Deliberately naive — oracle.
/// Skips positions inside PEM body regions (atomic suppression).
fn find_all_matches(input: &[u8], pem_blocks: &[RefMatch]) -> Vec<RefMatch> {
    let mut matches = Vec::new();
    for start in 0..input.len() {
        if is_in_pem_region(start, pem_blocks) {
            continue; // PEM body is atomic — no other rules run here
        }
        for (rule, confirm) in [
            (GITHUB, confirm_github as fn(&[u8], usize) -> Option<usize>),
            (GITLAB, confirm_gitlab),
            (NPM, confirm_npm),
        ] {
            if let Some(end) = confirm(input, start) {
                matches.push(RefMatch { start, end, rule });
            }
        }
    }
    matches
}

/// Group-absorption merge: each match absorbs every existing group it
/// strictly overlaps (touching spans stay separate — docs/02-rules.md).
/// Structurally different from the engine's sorted sweep, on purpose.
///
/// Group coverage is always contiguous (strict-overlap chains), so a match
/// overlapping a group's span overlaps one of its members.
fn merge_matches(matches: &[RefMatch]) -> Vec<RefMatch> {
    let mut groups: Vec<Vec<RefMatch>> = Vec::new();
    for &m in matches {
        let mut absorbed = vec![m];
        let mut remaining = Vec::new();
        for group in groups.drain(..) {
            let group_start = group
                .iter()
                .map(|x| x.start)
                .min()
                .expect("group is never empty");
            let group_end = group
                .iter()
                .map(|x| x.end)
                .max()
                .expect("group is never empty");
            if m.start < group_end && group_start < m.end {
                absorbed.extend(group);
            } else {
                remaining.push(group);
            }
        }
        remaining.push(absorbed);
        groups = remaining;
    }

    let mut merged: Vec<RefMatch> = groups
        .iter()
        .map(|group| {
            let start = group
                .iter()
                .map(|x| x.start)
                .min()
                .expect("group is never empty");
            let end = group
                .iter()
                .map(|x| x.end)
                .max()
                .expect("group is never empty");
            // Winner: longest-leftmost over the ORIGINAL member spans —
            // leftmost start, then longer, then catalog order.
            let winner = group
                .iter()
                .min_by(|a, b| {
                    a.start
                        .cmp(&b.start)
                        .then(b.end.cmp(&a.end))
                        .then(a.rule.cmp(&b.rule))
                })
                .expect("group is never empty");
            RefMatch {
                start,
                end,
                rule: winner.rule,
            }
        })
        .collect();
    merged.sort_unstable_by_key(|m| m.start);
    merged
}

/// Redact `input` as one whole buffer. Returns the redacted bytes and stats.
pub fn redact(input: &[u8], digest_key: &[u8; 32]) -> (Vec<u8>, Stats) {
    // 1. Find PEM blocks first (they suppress regular rules inside them).
    let pem_blocks = find_pem_blocks(input);
    // 2. Find regular matches, skipping PEM body regions.
    let mut all_matches = find_all_matches(input, &pem_blocks);
    // 3. Add PEM body spans to the match set.
    all_matches.extend_from_slice(&pem_blocks);
    let merged = merge_matches(&all_matches);

    let mut out = Vec::new();
    let mut match_counts: BTreeMap<RuleId, u64> = BTreeMap::new();
    let mut pos = 0;
    for m in &merged {
        out.extend_from_slice(&input[pos..m.start]);
        let rule_id = RuleId::new(RULE_IDS[m.rule]);
        let digest = crate::redact::compute_digest(&input[m.start..m.end], digest_key);
        crate::redact::write_tag(&rule_id, &digest, &mut out).expect("write to Vec cannot fail");
        *match_counts.entry(rule_id).or_insert(0) += 1;
        pos = m.end;
    }
    out.extend_from_slice(&input[pos..]);

    (
        out,
        Stats {
            bytes_processed: input.len() as u64,
            matches: match_counts,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{CATALOG, vectors};

    fn test_key() -> [u8; 32] {
        blake3::derive_key("cloak digest key", b"reference-test-key")
    }

    #[test]
    fn constants_cross_check_catalog() {
        // The oracle re-declares rule constants on purpose; this test is the
        // tripwire for drift between the two declarations.
        // First 3 RULE_IDS match catalog; the 4th is PEM (separate layer).
        assert_eq!(RULE_IDS.len(), CATALOG.len() + 1);
        for (idx, rule) in CATALOG.iter().enumerate() {
            assert_eq!(RULE_IDS[idx], rule.id);
        }
        assert_eq!(RULE_IDS[PEM], crate::engine::pem::PEM_RULE_ID);
        let github_anchors: Vec<&[u8]> = GITHUB_PREFIXES.to_vec();
        assert_eq!(github_anchors, CATALOG[GITHUB].anchors);
        let gitlab_anchors: Vec<&[u8]> = GITLAB_PREFIXES.to_vec();
        assert_eq!(gitlab_anchors, CATALOG[GITLAB].anchors);
        assert_eq!(vec![NPM_PREFIX], CATALOG[NPM].anchors);
        // W = max anchor len + cap (github/gitlab) or exact body (npm).
        assert_eq!(CATALOG[GITHUB].window, 11 + BODY_CAP);
        assert_eq!(CATALOG[GITLAB].window, 6 + BODY_CAP);
        assert_eq!(CATALOG[NPM].window, NPM_PREFIX.len() + NPM_EXACT);
        // PEM constants cross-check.
        assert_eq!(PEM_BEGIN, crate::engine::pem::PEM_ANCHOR);
        assert_eq!(PEM_BAIL_OUT, crate::engine::pem::PEM_BAIL_OUT);
        assert_eq!(PEM_KEY_TYPES.len(), crate::engine::pem::PEM_KEY_TYPES.len());
        for (oracle, engine) in PEM_KEY_TYPES.iter().zip(crate::engine::pem::PEM_KEY_TYPES) {
            assert_eq!(oracle, engine);
        }
    }

    // --- confirmers -------------------------------------------------------

    #[test]
    fn github_min_and_below() {
        let hit = b"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
        assert_eq!(confirm_github(hit, 0), Some(40));
        let miss = b"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345678";
        assert_eq!(confirm_github(miss, 0), None);
    }

    #[test]
    fn github_greedy_takes_40() {
        let input = b"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Wxyz";
        assert_eq!(confirm_github(input, 0), Some(44));
    }

    #[test]
    fn github_cap_at_255() {
        let mut input = b"ghp_".to_vec();
        input.extend(std::iter::repeat_n(b'a', 300));
        assert_eq!(confirm_github(&input, 0), Some(259));
    }

    #[test]
    fn github_charset_break() {
        let input = b"ghp_abcdefghij0123456789-abcdefghij0123456789";
        assert_eq!(confirm_github(input, 0), None);
    }

    #[test]
    fn github_pat_branch() {
        let mut input = b"github_pat_".to_vec();
        input.extend(std::iter::repeat_n(b'x', 82));
        assert_eq!(confirm_github(&input, 0), Some(93));
    }

    #[test]
    fn github_wrong_offset_and_prefix() {
        let input = b"xxghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
        assert_eq!(confirm_github(input, 0), None);
        assert_eq!(confirm_github(input, 2), Some(42));
    }

    #[test]
    fn gitlab_min_dash_body_and_below() {
        assert_eq!(confirm_gitlab(b"glpat-abcdefghij0123456789", 0), Some(26));
        assert_eq!(confirm_gitlab(b"glrt-abcdefghij0123456789", 0), Some(25));
        assert_eq!(confirm_gitlab(b"gldt-abcdefghij0123456789", 0), Some(25));
        assert_eq!(
            confirm_gitlab(b"glpat-ab-cd_ef-gh_ij-kl_mn-qrs", 0),
            Some(30)
        );
        assert_eq!(confirm_gitlab(b"glpat-abcdefghij012345678", 0), None);
    }

    #[test]
    fn gitlab_cap_at_255() {
        let mut input = b"glpat-".to_vec();
        input.extend(std::iter::repeat_n(b'z', 300));
        assert_eq!(confirm_gitlab(&input, 0), Some(261));
    }

    #[test]
    fn npm_exact_36_semantics() {
        assert_eq!(
            confirm_npm(b"npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", 0),
            Some(40)
        );
        // 37 alnum chars: match ends at 40 (first 36), residue ignored.
        assert_eq!(
            confirm_npm(b"npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789X", 0),
            Some(40)
        );
        assert_eq!(
            confirm_npm(b"npm_AbCdEfGhIjKlMnOpQrStUvWxYz012345678", 0),
            None
        );
        // '_' is not npm body.
        assert_eq!(
            confirm_npm(b"npm_AbCdEfGhIjKlMnOpQrStUvWxYz012345678_", 0),
            None
        );
        assert_eq!(
            confirm_npm(b"xpm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", 0),
            None
        );
    }

    // --- merge ------------------------------------------------------------

    #[test]
    fn merge_empty_and_single() {
        assert!(merge_matches(&[]).is_empty());
        let single = [RefMatch {
            start: 5,
            end: 10,
            rule: NPM,
        }];
        assert_eq!(merge_matches(&single), single);
    }

    #[test]
    fn merge_disjoint_stays_sorted() {
        let matches = [
            RefMatch {
                start: 20,
                end: 30,
                rule: GITLAB,
            },
            RefMatch {
                start: 0,
                end: 10,
                rule: GITHUB,
            },
        ];
        let merged = merge_matches(&matches);
        assert_eq!(
            merged,
            [
                RefMatch {
                    start: 0,
                    end: 10,
                    rule: GITHUB
                },
                RefMatch {
                    start: 20,
                    end: 30,
                    rule: GITLAB
                },
            ]
        );
    }

    #[test]
    fn merge_touching_stays_separate() {
        // Strict overlap only: [0,10) + [10,20) do NOT merge.
        let matches = [
            RefMatch {
                start: 0,
                end: 10,
                rule: NPM,
            },
            RefMatch {
                start: 10,
                end: 20,
                rule: GITLAB,
            },
        ];
        assert_eq!(merge_matches(&matches), matches);
    }

    #[test]
    fn merge_overlap_leftmost_wins() {
        let matches = [
            RefMatch {
                start: 5,
                end: 25,
                rule: GITLAB,
            },
            RefMatch {
                start: 0,
                end: 10,
                rule: NPM,
            },
        ];
        assert_eq!(
            merge_matches(&matches),
            [RefMatch {
                start: 0,
                end: 25,
                rule: NPM
            }]
        );
    }

    #[test]
    fn merge_transitive_chain() {
        // A∩B and B∩C but A∌C → one span.
        let matches = [
            RefMatch {
                start: 0,
                end: 10,
                rule: GITHUB,
            },
            RefMatch {
                start: 18,
                end: 30,
                rule: NPM,
            },
            RefMatch {
                start: 8,
                end: 20,
                rule: GITLAB,
            },
        ];
        assert_eq!(
            merge_matches(&matches),
            [RefMatch {
                start: 0,
                end: 30,
                rule: GITHUB
            }]
        );
    }

    #[test]
    fn merge_same_start_longer_wins() {
        let matches = [
            RefMatch {
                start: 0,
                end: 10,
                rule: GITHUB,
            },
            RefMatch {
                start: 0,
                end: 20,
                rule: NPM,
            },
        ];
        assert_eq!(
            merge_matches(&matches),
            [RefMatch {
                start: 0,
                end: 20,
                rule: NPM
            }]
        );
    }

    #[test]
    fn merge_identical_span_catalog_order_wins() {
        let matches = [
            RefMatch {
                start: 0,
                end: 20,
                rule: NPM,
            },
            RefMatch {
                start: 0,
                end: 20,
                rule: GITLAB,
            },
        ];
        assert_eq!(
            merge_matches(&matches),
            [RefMatch {
                start: 0,
                end: 20,
                rule: GITLAB
            }]
        );
    }

    #[test]
    fn merge_contained_outer_wins() {
        let matches = [
            RefMatch {
                start: 5,
                end: 15,
                rule: NPM,
            },
            RefMatch {
                start: 0,
                end: 30,
                rule: GITHUB,
            },
        ];
        assert_eq!(
            merge_matches(&matches),
            [RefMatch {
                start: 0,
                end: 30,
                rule: GITHUB
            }]
        );
    }

    // --- redact (oracle vs. vector corpus) --------------------------------

    #[test]
    fn oracle_agrees_with_every_vector() {
        // The S2 checkpoint: reference green on the whole corpus before the
        // production engine exists.
        let key = test_key();
        for v in vectors::all_vectors() {
            let (out, stats) = redact(v.input, &key);
            assert_eq!(
                out,
                vectors::expected_output(v, &key),
                "oracle output mismatch on vector {}",
                v.name
            );
            assert_eq!(stats.bytes_processed, v.input.len() as u64, "{}", v.name);
            assert_eq!(stats.total_matches(), v.spans.len() as u64, "{}", v.name);
        }
    }

    #[test]
    fn redact_no_match_is_identity() {
        let key = test_key();
        let input: Vec<u8> = (0..=255).collect();
        let (out, stats) = redact(&input, &key);
        assert_eq!(out, input);
        assert_eq!(stats.bytes_processed, 256);
        assert!(stats.matches.is_empty());
    }

    #[test]
    fn redact_counts_per_rule() {
        let key = test_key();
        let input = b"npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789 glpat-abcdefghij0123456789";
        let (_, stats) = redact(input, &key);
        assert_eq!(stats.matches[&RuleId::new("npm-token")], 1);
        assert_eq!(stats.matches[&RuleId::new("gitlab-token")], 1);
    }
}
