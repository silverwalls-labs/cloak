//! Cross-rule overlap, adjacency, and containment constructions
//! (docs/02-rules.md, "Overlap resolution").
//!
//! These make the merge semantics visible in data: strict overlap merges
//! (winner = longest-leftmost), exactly-touching spans stay separate.

use super::{ExpectedSpan, Vector};

pub static VECTORS: &[Vector] = &[
    Vector {
        // "gho_" nested inside a ghp_ body ('g','h','o','_' are all valid
        // github body chars): both confirm, spans overlap → ONE merged span,
        // digest over the full union.
        // Layout: ghp_ (0..4) + 10 alnum + gho_ (14..18) + 36 body → end 54.
        name: "overlap-same-rule-nested-anchor",
        input: b"ghp_a1b2c3d4e5gho_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        spans: &[ExpectedSpan {
            start: 0,
            end: 54,
            rule: "github-token",
        }],
    },
    Vector {
        // Cross-rule tail extension: github body is 31 alnum + "glpat"
        // (exactly 36, stopped by the '-'), then "glpat-" at 35 confirms a
        // gitlab match [35, 61) extending past the github end [0, 40).
        // Strict overlap (35 < 40) → merged [0, 61), leftmost rule wins.
        name: "overlap-cross-rule-tail-extension",
        input: b"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz01234glpat-abcdefghij0123456789",
        spans: &[ExpectedSpan {
            start: 0,
            end: 61,
            rule: "github-token",
        }],
    },
    Vector {
        // Zero-gap adjacency: npm match ends at 40 exactly where the gitlab
        // anchor starts. Touching is NOT overlap → TWO separate tags
        // (strict-overlap decision, docs/02-rules.md).
        name: "overlap-adjacent-zero-gap",
        input: b"npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789glpat-abcdefghij0123456789",
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
        input: b"npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789 glpat-abcdefghij0123456789",
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
        // Containment: an npm match [9, 49) strictly inside a github match
        // [0, 54) ("npm_" chars are valid github body) → union unchanged,
        // leftmost (github) wins.
        name: "overlap-contained-cross-rule",
        input: b"ghp_abc12npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789xyz01",
        spans: &[ExpectedSpan {
            start: 0,
            end: 54,
            rule: "github-token",
        }],
    },
];
