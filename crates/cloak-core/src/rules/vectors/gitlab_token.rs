//! Vectors for `gitlab-token` (docs/02-rules.md).
//!
//! Body alphabet is `[0-9A-Za-z_-]` (note: `-` and `_` valid, unlike
//! github's), min 20, cap 255. Long bodies use the same 50-digit
//! continuation-line convention as `github_token.rs`.

use super::{ExpectedSpan, Vector};

pub static POSITIVE: &[Vector] = &[
    Vector {
        name: "gitlab-glpat-min-20",
        input: b"glpat-abcdefghij0123456789",
        spans: &[ExpectedSpan {
            start: 0,
            end: 26,
            rule: "gitlab-token",
        }],
    },
    Vector {
        // "glrt-" is a 5-byte anchor (unlike 6-byte "glpat-").
        name: "gitlab-glrt-min-20",
        input: b"glrt-abcdefghij0123456789",
        spans: &[ExpectedSpan {
            start: 0,
            end: 25,
            rule: "gitlab-token",
        }],
    },
    Vector {
        name: "gitlab-gldt-min-20",
        input: b"gldt-abcdefghij0123456789",
        spans: &[ExpectedSpan {
            start: 0,
            end: 25,
            rule: "gitlab-token",
        }],
    },
    Vector {
        // Pins the gitlab charset superset: '-' and '_' inside the body.
        name: "gitlab-dash-underscore-body-24",
        input: b"glpat-ab-cd_ef-gh_ij-kl_mn-qrs",
        spans: &[ExpectedSpan {
            start: 0,
            end: 30,
            rule: "gitlab-token",
        }],
    },
    Vector {
        // Spec-literal charset pin: a body of 20 dashes is a valid match.
        name: "gitlab-all-dashes-body",
        input: b"glpat---------------------",
        spans: &[ExpectedSpan {
            start: 0,
            end: 26,
            rule: "gitlab-token",
        }],
    },
    Vector {
        name: "gitlab-at-cap-255",
        input: b"glpat-\
                 01234567890123456789012345678901234567890123456789\
                 01234567890123456789012345678901234567890123456789\
                 01234567890123456789012345678901234567890123456789\
                 01234567890123456789012345678901234567890123456789\
                 01234567890123456789012345678901234567890123456789\
                 01234",
        spans: &[ExpectedSpan {
            start: 0,
            end: 261,
            rule: "gitlab-token",
        }],
    },
    Vector {
        name: "gitlab-embedded-log-line",
        input: b"ci: glpat-abcdefghij0123456789 pushed\n",
        spans: &[ExpectedSpan {
            start: 4,
            end: 30,
            rule: "gitlab-token",
        }],
    },
];

pub static NEGATIVE: &[Vector] = &[
    Vector {
        name: "gitlab-too-short-19",
        input: b"glpat-abcdefghij012345678",
        spans: &[],
    },
    Vector {
        name: "gitlab-anchor-only",
        input: b"see glpat- here",
        spans: &[],
    },
    Vector {
        // No dash after "glpat" ⇒ no anchor at all.
        name: "gitlab-missing-dash",
        input: b"glpatabcdefghij0123456789",
        spans: &[],
    },
    Vector {
        // Charset break ('!') at body char 11 — only 10 valid chars before it.
        name: "gitlab-charset-break",
        input: b"glpat-abcde12345!fghij67890",
        spans: &[],
    },
];
