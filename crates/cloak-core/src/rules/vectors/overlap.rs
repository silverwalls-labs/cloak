//! Cross-rule overlap, adjacency, and containment constructions
//! (docs/02-rules.md, "Overlap resolution").
//!
//! These make the merge semantics visible in data: strict overlap merges
//! (winner = longest-leftmost), exactly-touching spans stay separate.
//!
//! Classic github prefixes are CRC-validated (F12), so overlap vectors
//! use `github_pat_` (shape-only) for the github-token side. npm tokens
//! use valid CRC (same entropy → same checksum as in the npm vectors).

use super::{ExpectedSpan, Vector};

pub static VECTORS: &[Vector] = &[
    Vector {
        // `github_pat_` body contains a valid-CRC `ghp_` token: both confirm,
        // spans overlap → ONE merged span, digest over the full union.
        //
        // Layout: github_pat_(0..11) + "a1b2c3d4e5"(11..21)
        //         + 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(21..61)
        //         + "xyzAB"(61..66)
        // github_pat_ match: [0, 66) — body = 55 chars, greedy
        // ghp_ match: [21, 61) — CRC-valid classic token
        // Overlap: 21 < 61 and 0 < 66 → merge [0, 66), same rule, leftmost wins
        name: "overlap-same-rule-nested-anchor",
        input: b"github_pat_a1b2c3d4e5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xyzAB",
        spans: &[ExpectedSpan {
            start: 0,
            end: 66,
            rule: "github-token",
        }],
    },
    Vector {
        // Cross-rule tail extension: github_pat_ body is 36 chars
        // (31 alnum + "glpat", stopped by '-'), then "glpat-" at 42 confirms
        // a gitlab match [42, 68) extending past the github end [0, 47).
        // Strict overlap (42 < 47) → merged [0, 68), leftmost rule wins.
        name: "overlap-cross-rule-tail-extension",
        input: b"github_pat_AbCdEfGhIjKlMnOpQrStUvWxYz01234glpat-abcdefghij0123456789",
        spans: &[ExpectedSpan {
            start: 0,
            end: 68,
            rule: "github-token",
        }],
    },
    Vector {
        // Zero-gap adjacency: npm match ends at 40 exactly where the gitlab
        // anchor starts. Touching is NOT overlap → TWO separate tags
        // (strict-overlap decision, docs/02-rules.md).
        //
        // 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 = valid CRC.
        name: "overlap-adjacent-zero-gap",
        input: b"npm_AbCdEfGhIjKlMnOpQrStUvWxYz01232piBxeglpat-abcdefghij0123456789",
        spans: &[
            ExpectedSpan {
                start: 0,
                end: 40,
                rule: "npm-token",
            },
            ExpectedSpan {
                start: 40,
                end: 66,
                rule: "gitlab-token",
            },
        ],
    },
    Vector {
        // One byte of separation → unambiguously two tags.
        name: "overlap-one-byte-gap",
        input: b"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 glpat-abcdefghij0123456789",
        spans: &[
            ExpectedSpan {
                start: 0,
                end: 40,
                rule: "npm-token",
            },
            ExpectedSpan {
                start: 41,
                end: 67,
                rule: "gitlab-token",
            },
        ],
    },
    Vector {
        // Containment: a valid-CRC npm match [16, 56) strictly inside a
        // github_pat_ match [0, 61) ("npm_" and alnum chars are valid
        // github body) → union unchanged, leftmost (github) wins.
        //
        // github_pat_ body: "abc12npm_AbCdEfGhIjKlMnOpQrStUvWxYz01232piBxexyz01"
        //   = 50 chars (>= 36 ✓)
        // npm_ starts at 16: prefix(4) + 36 body → ends at 56.
        name: "overlap-contained-cross-rule",
        input: b"github_pat_abc12npm_AbCdEfGhIjKlMnOpQrStUvWxYz01232piBxexyz01",
        spans: &[ExpectedSpan {
            start: 0,
            end: 61,
            rule: "github-token",
        }],
    },
];
