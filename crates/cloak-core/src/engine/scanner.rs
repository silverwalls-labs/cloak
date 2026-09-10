//! The prefilter seam (docs/01-architecture.md, "The SIMD upgrade path").
//!
//! v0.1: `AhoCorasickScanner` (crate-backed, SIMD inside) and
//! `ScalarScanner` (naive reference: test oracle + bench baseline).
//! v0.2+: `KernelScanner` (hand-rolled, feature-gated, must beat
//! `AhoCorasickScanner` with receipts — docs/04).

use crate::rules::RuleSpec;

/// A candidate anchor hit produced by the prefilter. Not yet a match — the
/// confirm step decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Candidate {
    /// Byte offset where the anchor begins.
    pub start: usize,
    /// Index into the compiled rule table (catalog order).
    pub rule: usize,
    /// Anchor length (diagnostic; confirm re-scans from `start`).
    pub len: usize,
}

/// Scan `haystack`, appending candidate windows to `out`.
///
/// Contract: **every** occurrence of every rule anchor in `haystack` MUST be
/// appended — order unspecified, duplicates permitted. A missed candidate is
/// a guarantee bug; an extra one only costs confirm time.
pub(crate) trait Scanner {
    fn scan(&self, haystack: &[u8], out: &mut Vec<Candidate>);
}

/// Production prefilter: one automaton over all rules' anchors.
pub(crate) struct AhoCorasickScanner {
    ac: aho_corasick::AhoCorasick,
    /// `PatternID.as_usize()` → (rule index, anchor length).
    patterns: Vec<(usize, usize)>,
}

impl AhoCorasickScanner {
    /// Build the prefilter from a filtered set of catalog rules plus
    /// optional extra anchors (e.g. the PEM `-----BEGIN ` anchor).
    ///
    /// Each rule spec is enumerated in the order of the `catalog` slice
    /// to produce rule indices. When rules have been filtered (some
    /// disabled), the indices map to positions in the *filtered* vec —
    /// callers must compile confirm rules in the same order.
    ///
    /// Extra anchors use the provided `(anchor_bytes, rule_index)` tuples
    /// — the rule index is typically a pseudo-index outside the catalog
    /// range (e.g. PEM).
    pub(crate) fn new(
        catalog: &[&RuleSpec],
        extra_anchors: &[(&[u8], usize)],
    ) -> Result<Self, aho_corasick::BuildError> {
        let mut literals: Vec<&[u8]> = Vec::new();
        let mut patterns = Vec::new();
        for (rule, spec) in catalog.iter().enumerate() {
            for anchor in spec.anchors {
                literals.push(anchor);
                patterns.push((rule, anchor.len()));
            }
        }
        for &(anchor, rule_idx) in extra_anchors {
            literals.push(anchor);
            patterns.push((rule_idx, anchor.len()));
        }
        // MatchKind::Standard is required by find_overlapping_iter (it panics
        // under the leftmost kinds) — set explicitly, don't rely on defaults.
        let ac = aho_corasick::AhoCorasick::builder()
            .match_kind(aho_corasick::MatchKind::Standard)
            .build(literals)?;
        Ok(Self { ac, patterns })
    }
}

impl Scanner for AhoCorasickScanner {
    fn scan(&self, haystack: &[u8], out: &mut Vec<Candidate>) {
        // Overlapping iteration structurally guarantees no anchor occurrence
        // is skipped, even when anchors nest or overlap each other (today's
        // ten don't; future anchors like `@` and `://` will). Non-overlapping
        // find_iter would skip an anchor starting inside a previously
        // reported one. NOTE: matches arrive ordered by END offset, not
        // start — downstream must not assume start-sorted candidates.
        for m in self.ac.find_overlapping_iter(haystack) {
            let (rule, len) = self.patterns[m.pattern().as_usize()];
            out.push(Candidate {
                start: m.start(),
                rule,
                len,
            });
        }
    }
}

/// Deliberately naive prefilter: byte-compare every anchor at every offset.
/// Trait-level oracle for `AhoCorasickScanner` (unit tier) and the S7 bench
/// baseline — the receipts for "SIMD-powered" (docs/04).
#[allow(dead_code)] // bench baseline (S7); exercised by unit tests only in S2
pub(crate) struct ScalarScanner {
    /// (anchor, rule index) pairs, flattened in catalog order.
    anchors: Vec<(&'static [u8], usize)>,
}

#[allow(dead_code)] // bench baseline (S7); exercised by unit tests only in S2
impl ScalarScanner {
    pub(crate) fn new(
        catalog: &[&'static RuleSpec],
        extra_anchors: &[(&'static [u8], usize)],
    ) -> Self {
        let mut anchors = Vec::new();
        for (rule, spec) in catalog.iter().enumerate() {
            for anchor in spec.anchors {
                anchors.push((*anchor, rule));
            }
        }
        for &(anchor, rule_idx) in extra_anchors {
            anchors.push((anchor, rule_idx));
        }
        Self { anchors }
    }
}

impl Scanner for ScalarScanner {
    fn scan(&self, haystack: &[u8], out: &mut Vec<Candidate>) {
        for start in 0..haystack.len() {
            for &(anchor, rule) in &self.anchors {
                if haystack[start..].starts_with(anchor) {
                    out.push(Candidate {
                        start,
                        rule,
                        len: anchor.len(),
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{CATALOG, vectors};

    fn catalog_refs() -> Vec<&'static RuleSpec> {
        CATALOG.iter().collect()
    }

    fn ac_scanner() -> AhoCorasickScanner {
        AhoCorasickScanner::new(&catalog_refs(), &[]).expect("catalog anchors must build")
    }

    fn scan_sorted(scanner: &impl Scanner, haystack: &[u8]) -> Vec<Candidate> {
        let mut out = Vec::new();
        scanner.scan(haystack, &mut out);
        out.sort_unstable();
        out
    }

    #[test]
    fn finds_every_anchor_once_in_anchor_soup() {
        // One occurrence of each of the ten catalog anchors, separated so
        // none overlap.
        let soup = b"ghp_ gho_ ghs_ ghu_ ghr_ github_pat_ glpat- glrt- gldt- npm_";
        let candidates = scan_sorted(&ac_scanner(), soup);
        assert_eq!(candidates.len(), 10);
        // First candidate: ghp_ at 0 (rule 0); last: npm_ at 56 (rule 2).
        assert_eq!(
            candidates[0],
            Candidate {
                start: 0,
                rule: 0,
                len: 4
            }
        );
        assert_eq!(
            candidates[9],
            Candidate {
                start: 56,
                rule: 2,
                len: 4
            }
        );
    }

    #[test]
    fn pattern_to_rule_mapping() {
        let scanner = ac_scanner();
        let candidates = scan_sorted(&scanner, b"github_pat_ and glrt- and npm_");
        assert_eq!(
            candidates,
            [
                Candidate {
                    start: 0,
                    rule: 0,
                    len: 11
                },
                Candidate {
                    start: 16,
                    rule: 1,
                    len: 5
                },
                Candidate {
                    start: 26,
                    rule: 2,
                    len: 4
                },
            ]
        );
    }

    #[test]
    fn duplicate_anchors_yield_duplicate_candidates() {
        let candidates = scan_sorted(&ac_scanner(), b"npm_npm_");
        assert_eq!(
            candidates,
            [
                Candidate {
                    start: 0,
                    rule: 2,
                    len: 4
                },
                Candidate {
                    start: 4,
                    rule: 2,
                    len: 4
                },
            ]
        );
    }

    #[test]
    fn empty_and_anchor_free_haystacks() {
        let scanner = ac_scanner();
        assert!(scan_sorted(&scanner, b"").is_empty());
        // After S4, single-byte anchors (`@`, `+`, `4`, `:`) exist.
        // Use an input that avoids all catalog anchors.
        assert!(scan_sorted(&scanner, b"hello world with no secrets").is_empty());
    }

    #[test]
    fn anchor_truncated_at_eof_is_not_a_candidate() {
        assert!(scan_sorted(&ac_scanner(), b"tail ghp").is_empty());
    }

    #[test]
    fn scalar_scanner_equals_aho_corasick_on_corpus() {
        // Trait-contract differential: both scanners must emit the same
        // candidate set (sorted; both are duplicate-free) on every vector
        // input plus adversarial extras.
        let ac = ac_scanner();
        let refs = catalog_refs();
        let scalar = ScalarScanner::new(&refs, &[]);
        let mut inputs: Vec<&[u8]> = vectors::all_vectors().iter().map(|v| v.input).collect();
        inputs.push(b"ghp_ gho_ ghs_ ghu_ ghr_ github_pat_ glpat- glrt- gldt- npm_");
        inputs.push(b"\x00\xff\x80ghp_\x01npm_\xfe");
        inputs.push(b"ends with anchor npm_");
        for input in inputs {
            assert_eq!(
                scan_sorted(&ac, input),
                scan_sorted(&scalar, input),
                "scanner divergence on {:?}",
                String::from_utf8_lossy(input)
            );
        }
    }
}
