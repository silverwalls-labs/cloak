//! Vectors for `email` (docs/02-rules.md).
//!
//! RFC-5322-practical: `local@domain.tld`, TLD ≥ 2 alpha chars.

use super::{ExpectedSpan, Vector};

pub static POSITIVE: &[Vector] = &[
    Vector {
        name: "email-basic",
        input: b"user@example.com",
        spans: &[ExpectedSpan {
            start: 0,
            end: 16,
            rule: "email",
        }],
    },
    Vector {
        name: "email-plus-addressing",
        input: b"user+tag@example.com",
        spans: &[ExpectedSpan {
            start: 0,
            end: 20,
            rule: "email",
        }],
    },
    Vector {
        name: "email-dots-in-local",
        input: b"first.last@example.co.uk",
        spans: &[ExpectedSpan {
            start: 0,
            end: 24,
            rule: "email",
        }],
    },
    Vector {
        name: "email-embedded-log",
        // "alert for " = 10 bytes, then "admin@company.org" = 17 bytes (10..27).
        input: b"alert for admin@company.org in prod\n",
        spans: &[ExpectedSpan {
            start: 10,
            end: 27,
            rule: "email",
        }],
    },
    Vector {
        name: "email-binary-embedded",
        input: b"\x00\xffuser@example.com\x01",
        spans: &[ExpectedSpan {
            start: 2,
            end: 18,
            rule: "email",
        }],
    },
];

pub static NEGATIVE: &[Vector] = &[
    Vector {
        name: "email-no-tld",
        input: b"user@localhost",
        spans: &[],
    },
    Vector {
        name: "email-short-tld",
        // TLD "c" is only 1 alpha char — need ≥ 2.
        input: b"user@example.c",
        spans: &[],
    },
    Vector {
        name: "email-at-only",
        input: b"bare @ sign",
        spans: &[],
    },
    Vector {
        name: "email-no-local",
        input: b"@example.com",
        spans: &[],
    },
    Vector {
        name: "email-no-domain",
        input: b"user@",
        spans: &[],
    },
    Vector {
        name: "email-numeric-tld",
        // TLD "123" is all digits — not valid.
        input: b"user@example.123",
        spans: &[],
    },
];
