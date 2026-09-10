//! Vectors for `credit-card` (docs/02-rules.md).
//!
//! Luhn checksum + Big Four IIN validation. Digit runs 13-19 with
//! optional space/dash separators.

use super::{ExpectedSpan, Vector};

pub static POSITIVE: &[Vector] = &[
    Vector {
        name: "cc-visa-16",
        input: b"4539578763621486",
        spans: &[ExpectedSpan {
            start: 0,
            end: 16,
            rule: "credit-card",
        }],
    },
    Vector {
        name: "cc-visa-with-dashes",
        input: b"4539-5787-6362-1486",
        spans: &[ExpectedSpan {
            start: 0,
            end: 19,
            rule: "credit-card",
        }],
    },
    Vector {
        name: "cc-visa-with-spaces",
        input: b"4539 5787 6362 1486",
        spans: &[ExpectedSpan {
            start: 0,
            end: 19,
            rule: "credit-card",
        }],
    },
    Vector {
        name: "cc-mastercard",
        input: b"5105105105105100",
        spans: &[ExpectedSpan {
            start: 0,
            end: 16,
            rule: "credit-card",
        }],
    },
    Vector {
        name: "cc-amex-15",
        input: b"378282246310005",
        spans: &[ExpectedSpan {
            start: 0,
            end: 15,
            rule: "credit-card",
        }],
    },
    Vector {
        name: "cc-discover",
        input: b"6011111111111117",
        spans: &[ExpectedSpan {
            start: 0,
            end: 16,
            rule: "credit-card",
        }],
    },
    Vector {
        name: "cc-embedded-log",
        // "card: " = 6 bytes, then 16-digit number.
        input: b"card: 4539578763621486 charged\n",
        spans: &[ExpectedSpan {
            start: 6,
            end: 22,
            rule: "credit-card",
        }],
    },
];

pub static NEGATIVE: &[Vector] = &[
    Vector {
        name: "cc-luhn-fail",
        // Last digit changed from 6 to 7 — Luhn fails.
        input: b"4539578763621487",
        spans: &[],
    },
    Vector {
        name: "cc-too-short-12",
        input: b"453957876362",
        spans: &[],
    },
    Vector {
        name: "cc-unknown-iin",
        // Starts with 9 — not a Big Four IIN.
        input: b"9111111111111111",
        spans: &[],
    },
    Vector {
        name: "cc-digit-boundary-before",
        // Preceded by a digit — not a clean boundary.
        input: b"14539578763621486",
        spans: &[],
    },
    Vector {
        name: "cc-digit-boundary-after",
        // Followed by a digit — not a clean boundary.
        input: b"45395787636214860",
        spans: &[],
    },
];
