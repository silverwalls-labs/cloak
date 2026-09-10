//! Vectors for `phone-intl` (docs/02-rules.md).
//!
//! Strictly `+`-anchored international format. MUST NEVER match bare
//! 10-digit strings — the `+` anchor is mandatory.

use super::{ExpectedSpan, Vector};

pub static POSITIVE: &[Vector] = &[
    Vector {
        name: "phone-us",
        input: b"+14155551234",
        spans: &[ExpectedSpan {
            start: 0,
            end: 12,
            rule: "phone-intl",
        }],
    },
    Vector {
        name: "phone-uk",
        input: b"+447911123456",
        spans: &[ExpectedSpan {
            start: 0,
            end: 13,
            rule: "phone-intl",
        }],
    },
    Vector {
        name: "phone-with-dashes",
        input: b"+1-415-555-1234",
        spans: &[ExpectedSpan {
            start: 0,
            end: 15,
            rule: "phone-intl",
        }],
    },
    Vector {
        name: "phone-with-spaces",
        input: b"+44 7911 123456",
        spans: &[ExpectedSpan {
            start: 0,
            end: 15,
            rule: "phone-intl",
        }],
    },
    Vector {
        name: "phone-with-dots",
        input: b"+1.415.555.1234",
        spans: &[ExpectedSpan {
            start: 0,
            end: 15,
            rule: "phone-intl",
        }],
    },
    Vector {
        name: "phone-embedded-log",
        // "call " = 5 bytes, then phone.
        input: b"call +14155551234 for info\n",
        spans: &[ExpectedSpan {
            start: 5,
            end: 17,
            rule: "phone-intl",
        }],
    },
    Vector {
        name: "phone-e164-max",
        // E.164 max: 15 digits.
        input: b"+123456789012345",
        spans: &[ExpectedSpan {
            start: 0,
            end: 16,
            rule: "phone-intl",
        }],
    },
    Vector {
        name: "phone-e164-min",
        // E.164 min: 7 digits.
        input: b"+1234567",
        spans: &[ExpectedSpan {
            start: 0,
            end: 8,
            rule: "phone-intl",
        }],
    },
];

pub static NEGATIVE: &[Vector] = &[
    Vector {
        name: "phone-bare-digits",
        // No `+` prefix — must NOT match. Hard constraint.
        input: b"4155551234",
        spans: &[],
    },
    Vector {
        name: "phone-too-short",
        // Only 6 digits — need 7.
        input: b"+123456",
        spans: &[],
    },
    Vector {
        name: "phone-too-long",
        // 16 digits — max is 15.
        input: b"+1234567890123456",
        spans: &[],
    },
    Vector {
        name: "phone-preceded-by-letter",
        // Preceded by a letter — not a boundary.
        input: b"x+14155551234",
        spans: &[],
    },
    Vector {
        name: "phone-preceded-by-digit",
        input: b"1+14155551234",
        spans: &[],
    },
    Vector {
        name: "phone-no-digits-after-plus",
        input: b"+abc",
        spans: &[],
    },
    Vector {
        name: "phone-arithmetic",
        // `+5` in arithmetic context — only 1 digit, too short.
        input: b"count = x + 5",
        spans: &[],
    },
];
