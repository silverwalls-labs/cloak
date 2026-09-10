//! Vectors for `aws-access-key` (docs/02-rules.md).
//!
//! Format: `(AKIA|ASIA)[0-9A-Z]{16}` — exactly 20 uppercase-alnum chars.

use super::{ExpectedSpan, Vector};

pub static POSITIVE: &[Vector] = &[
    Vector {
        name: "aws-akia-basic",
        input: b"AKIAIOSFODNN7EXAMPLE",
        spans: &[ExpectedSpan {
            start: 0,
            end: 20,
            rule: "aws-access-key",
        }],
    },
    Vector {
        name: "aws-asia-basic",
        input: b"ASIA1234567890ABCDEF",
        spans: &[ExpectedSpan {
            start: 0,
            end: 20,
            rule: "aws-access-key",
        }],
    },
    Vector {
        name: "aws-akia-embedded-log",
        // "error: credentials " = 19 bytes, then 20-byte key.
        input: b"error: credentials AKIAIOSFODNN7EXAMPLE leaked in deploy\n",
        spans: &[ExpectedSpan {
            start: 19,
            end: 39,
            rule: "aws-access-key",
        }],
    },
    Vector {
        name: "aws-akia-at-buffer-end",
        input: b"key=AKIAIOSFODNN7EXAMPLE",
        spans: &[ExpectedSpan {
            start: 4,
            end: 24,
            rule: "aws-access-key",
        }],
    },
    Vector {
        name: "aws-akia-binary-embedded",
        input: b"\x00\xff\x80AKIAIOSFODNN7EXAMPLE\x01\x02",
        spans: &[ExpectedSpan {
            start: 3,
            end: 23,
            rule: "aws-access-key",
        }],
    },
    Vector {
        name: "aws-two-keys-one-line",
        input: b"AKIAIOSFODNN7EXAMPLE ASIA1234567890ABCDEF",
        spans: &[
            ExpectedSpan {
                start: 0,
                end: 20,
                rule: "aws-access-key",
            },
            ExpectedSpan {
                start: 21,
                end: 41,
                rule: "aws-access-key",
            },
        ],
    },
];

pub static NEGATIVE: &[Vector] = &[
    Vector {
        name: "aws-akia-too-short-15",
        input: b"AKIAIOSFODNN7EXAM",
        spans: &[],
    },
    Vector {
        name: "aws-lowercase-body",
        // Body contains lowercase — not valid for AWS access keys.
        input: b"AKIAiosfodnn7example",
        spans: &[],
    },
    Vector {
        name: "aws-wrong-prefix",
        input: b"AKIB1234567890ABCDEF",
        spans: &[],
    },
    Vector {
        name: "aws-anchor-only",
        input: b"see AKIA for info",
        spans: &[],
    },
    Vector {
        name: "aws-anchor-at-eof",
        input: b"tail AKIA",
        spans: &[],
    },
];
