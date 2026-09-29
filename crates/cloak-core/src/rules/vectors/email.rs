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
    Vector {
        name: "email-long-local-capped",
        // #41 review: locals beyond the 64-byte cap are CAPPED, not
        // rejected — the span covers the final 64 local bytes plus `@`
        // and the domain: @ at 100, span [36, 112).
        input: LONG_LOCAL_INPUT,
        spans: &[ExpectedSpan {
            start: 36,
            end: 112,
            rule: "email",
        }],
    },
];

/// `b"a"*100 + b"@example.com"` — a local part longer than the 64-byte
/// RFC 5321 cap (#41 review). Built in a const block: vectors are static.
const LONG_LOCAL_ARR: [u8; 112] = {
    let mut v = [b'a'; 112];
    v[100] = b'@';
    let mut i = 0;
    while i < 11 {
        v[101 + i] = b"example.com"[i];
        i += 1;
    }
    v
};
const LONG_LOCAL_INPUT: &[u8] = &LONG_LOCAL_ARR;

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
