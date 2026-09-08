//! Overlap resolution (docs/02-rules.md, "Overlap resolution"):
//! strictly-overlapping confirmed matches union into one redaction span;
//! exactly-touching spans stay separate. Winner per merged span is
//! longest-leftmost — leftmost start, then longer, then catalog order.

/// A confirmed match, pre-merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RawMatch {
    pub start: usize,
    pub end: usize,
    /// Catalog index of the confirming rule.
    pub rule: usize,
}

/// A merged redaction span. `rule` is the winner (longest-leftmost).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MergedMatch {
    pub start: usize,
    pub end: usize,
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
            Some(last) if m.start < last.end => last.end = last.end.max(m.end),
            _ => out.push(MergedMatch {
                start: m.start,
                end: m.end,
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

    #[test]
    fn empty_and_single() {
        assert!(merged(vec![]).is_empty());
        assert_eq!(
            merged(vec![RawMatch {
                start: 3,
                end: 9,
                rule: 1
            }]),
            [MergedMatch {
                start: 3,
                end: 9,
                rule: 1
            }]
        );
    }

    #[test]
    fn disjoint_pair_sorted_output() {
        let out = merged(vec![
            RawMatch {
                start: 20,
                end: 30,
                rule: 1,
            },
            RawMatch {
                start: 0,
                end: 10,
                rule: 0,
            },
        ]);
        assert_eq!(
            out,
            [
                MergedMatch {
                    start: 0,
                    end: 10,
                    rule: 0
                },
                MergedMatch {
                    start: 20,
                    end: 30,
                    rule: 1
                },
            ]
        );
    }

    #[test]
    fn overlapping_pair_unions_leftmost_wins() {
        let out = merged(vec![
            RawMatch {
                start: 5,
                end: 25,
                rule: 1,
            },
            RawMatch {
                start: 0,
                end: 10,
                rule: 2,
            },
        ]);
        assert_eq!(
            out,
            [MergedMatch {
                start: 0,
                end: 25,
                rule: 2
            }]
        );
    }

    #[test]
    fn touching_pair_stays_separate() {
        // The strict-overlap pin: [0,10) + [10,20) do NOT merge.
        let out = merged(vec![
            RawMatch {
                start: 0,
                end: 10,
                rule: 2,
            },
            RawMatch {
                start: 10,
                end: 20,
                rule: 1,
            },
        ]);
        assert_eq!(
            out,
            [
                MergedMatch {
                    start: 0,
                    end: 10,
                    rule: 2
                },
                MergedMatch {
                    start: 10,
                    end: 20,
                    rule: 1
                },
            ]
        );
    }

    #[test]
    fn transitive_chain_merges_to_one() {
        // A∩B and B∩C but A∌C → one span.
        let out = merged(vec![
            RawMatch {
                start: 18,
                end: 30,
                rule: 2,
            },
            RawMatch {
                start: 0,
                end: 10,
                rule: 0,
            },
            RawMatch {
                start: 8,
                end: 20,
                rule: 1,
            },
        ]);
        assert_eq!(
            out,
            [MergedMatch {
                start: 0,
                end: 30,
                rule: 0
            }]
        );
    }

    #[test]
    fn contained_match_does_not_extend() {
        let out = merged(vec![
            RawMatch {
                start: 5,
                end: 15,
                rule: 2,
            },
            RawMatch {
                start: 0,
                end: 30,
                rule: 0,
            },
        ]);
        assert_eq!(
            out,
            [MergedMatch {
                start: 0,
                end: 30,
                rule: 0
            }]
        );
    }

    #[test]
    fn same_start_longer_wins() {
        let out = merged(vec![
            RawMatch {
                start: 0,
                end: 10,
                rule: 0,
            },
            RawMatch {
                start: 0,
                end: 20,
                rule: 2,
            },
        ]);
        assert_eq!(
            out,
            [MergedMatch {
                start: 0,
                end: 20,
                rule: 2
            }]
        );
    }

    #[test]
    fn identical_span_catalog_order_wins() {
        let out = merged(vec![
            RawMatch {
                start: 0,
                end: 20,
                rule: 2,
            },
            RawMatch {
                start: 0,
                end: 20,
                rule: 1,
            },
        ]);
        assert_eq!(
            out,
            [MergedMatch {
                start: 0,
                end: 20,
                rule: 1
            }]
        );
    }

    #[test]
    fn unsorted_input_is_handled() {
        // merge() owns the sort — callers may pass candidates in any order
        // (the overlapping prefilter yields them ordered by END offset).
        let out = merged(vec![
            RawMatch {
                start: 40,
                end: 50,
                rule: 2,
            },
            RawMatch {
                start: 45,
                end: 60,
                rule: 1,
            },
            RawMatch {
                start: 0,
                end: 10,
                rule: 0,
            },
        ]);
        assert_eq!(
            out,
            [
                MergedMatch {
                    start: 0,
                    end: 10,
                    rule: 0
                },
                MergedMatch {
                    start: 40,
                    end: 60,
                    rule: 2
                },
            ]
        );
    }
}
