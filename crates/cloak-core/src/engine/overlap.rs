//! Overlap resolution (docs/02-rules.md, "Overlap resolution"):
//! strictly-overlapping confirmed matches union into one redaction span;
//! exactly-touching spans stay separate. Winner per merged span is
//! longest-leftmost — leftmost start, then longer, then catalog order.

/// A confirmed match, pre-merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RawMatch {
    /// Full match extent start (includes context for context-keyed rules).
    /// Used for overlap detection and carry-over boundary decisions.
    pub start: usize,
    /// Full match extent end.
    pub end: usize,
    /// Start of the sub-span to actually redact (== start for full-span rules).
    pub redact_start: usize,
    /// End of the sub-span to actually redact (== end for full-span rules).
    pub redact_end: usize,
    /// Catalog index of the confirming rule.
    pub rule: usize,
}

/// A merged redaction span. `rule` is the winner (longest-leftmost).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MergedMatch {
    /// Full match extent start (for overlap/carry-over).
    pub start: usize,
    /// Full match extent end.
    pub end: usize,
    /// Start of the sub-span to redact.
    pub redact_start: usize,
    /// End of the sub-span to redact.
    pub redact_end: usize,
    pub rule: usize,
}

/// Union strictly-overlapping spans (transitively) into `out`, ascending.
///
/// Sorting by (start asc, end desc, rule asc) makes the first match that
/// OPENS a group its longest-leftmost winner by construction — no separate
/// winner pass. Exact ties (same start+end, different rules) are not
/// constructible end-to-end with the S2 catalog (distinct anchors can't
/// occupy the same offset); the tie-break arm is pinned by synthetic tests.
pub(crate) fn merge(raw: &mut [RawMatch], out: &mut Vec<MergedMatch>) {
    raw.sort_unstable_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then(b.end.cmp(&a.end)) // longer first
            .then(a.rule.cmp(&b.rule)) // catalog order
    });
    for m in raw.iter() {
        match out.last_mut() {
            // Strict overlap only: touching (m.start == last.end) does NOT
            // merge — two adjacent secrets keep two tags (docs/02-rules.md).
            Some(last) if m.start < last.end => {
                last.end = last.end.max(m.end);
                // Union the redaction spans.
                last.redact_start = last.redact_start.min(m.redact_start);
                last.redact_end = last.redact_end.max(m.redact_end);
            }
            _ => out.push(MergedMatch {
                start: m.start,
                end: m.end,
                redact_start: m.redact_start,
                redact_end: m.redact_end,
                rule: m.rule,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn merged(mut raw: Vec<RawMatch>) -> Vec<MergedMatch> {
        let mut out = Vec::new();
        merge(&mut raw, &mut out);
        out
    }

    /// Shorthand for a full-span raw match (redact == match extent).
    fn raw(start: usize, end: usize, rule: usize) -> RawMatch {
        RawMatch {
            start,
            end,
            redact_start: start,
            redact_end: end,
            rule,
        }
    }

    /// Shorthand for a full-span merged match.
    fn mm(start: usize, end: usize, rule: usize) -> MergedMatch {
        MergedMatch {
            start,
            end,
            redact_start: start,
            redact_end: end,
            rule,
        }
    }

    #[test]
    fn empty_and_single() {
        assert!(merged(vec![]).is_empty());
        assert_eq!(merged(vec![raw(3, 9, 1)]), [mm(3, 9, 1)]);
    }

    #[test]
    fn disjoint_pair_sorted_output() {
        let out = merged(vec![raw(20, 30, 1), raw(0, 10, 0)]);
        assert_eq!(out, [mm(0, 10, 0), mm(20, 30, 1)]);
    }

    #[test]
    fn overlapping_pair_unions_leftmost_wins() {
        let out = merged(vec![raw(5, 25, 1), raw(0, 10, 2)]);
        assert_eq!(out, [mm(0, 25, 2)]);
    }

    #[test]
    fn touching_pair_stays_separate() {
        // The strict-overlap pin: [0,10) + [10,20) do NOT merge.
        let out = merged(vec![raw(0, 10, 2), raw(10, 20, 1)]);
        assert_eq!(out, [mm(0, 10, 2), mm(10, 20, 1)]);
    }

    #[test]
    fn transitive_chain_merges_to_one() {
        // A∩B and B∩C but A∌C → one span.
        let out = merged(vec![raw(18, 30, 2), raw(0, 10, 0), raw(8, 20, 1)]);
        assert_eq!(out, [mm(0, 30, 0)]);
    }

    #[test]
    fn contained_match_does_not_extend() {
        let out = merged(vec![raw(5, 15, 2), raw(0, 30, 0)]);
        assert_eq!(out, [mm(0, 30, 0)]);
    }

    #[test]
    fn same_start_longer_wins() {
        let out = merged(vec![raw(0, 10, 0), raw(0, 20, 2)]);
        assert_eq!(out, [mm(0, 20, 2)]);
    }

    #[test]
    fn identical_span_catalog_order_wins() {
        let out = merged(vec![raw(0, 20, 2), raw(0, 20, 1)]);
        assert_eq!(out, [mm(0, 20, 1)]);
    }

    #[test]
    fn unsorted_input_is_handled() {
        // merge() owns the sort — callers may pass candidates in any order.
        let out = merged(vec![raw(40, 50, 2), raw(45, 60, 1), raw(0, 10, 0)]);
        assert_eq!(out, [mm(0, 10, 0), mm(40, 60, 2)]);
    }
}
