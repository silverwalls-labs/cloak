//! Vectors for `azure-style-token` (docs/02-rules.md).
//!
//! Context-keyed: anchors on `AccountKey=`, `sig=`.
//! Only the base64/urlenc VALUE after `=` is redacted.

use super::{ExpectedSpan, Vector};

pub static POSITIVE: &[Vector] = &[
    Vector {
        name: "azure-account-key",
        // "AccountKey=" = 11 bytes, then 56-byte base64 value (11..67).
        input: b"AccountKey=dGhpcyBpcyBhIHRlc3QgdmFsdWUgd2l0aCBiYXNlNjQgZW5jb2Rpbmc=",
        spans: &[ExpectedSpan {
            start: 11,
            end: 67,
            rule: "azure-style-token",
        }],
    },
    Vector {
        name: "azure-sig-sas",
        // "sig=" = 4 bytes, then 50-byte URL-encoded signature (4..54).
        input: b"sig=dGhpcyBpcyBhIHNpZ25hdHVyZSB0ZXN0IHZhbHVl%2Btest%3D",
        spans: &[ExpectedSpan {
            start: 4,
            end: 54,
            rule: "azure-style-token",
        }],
    },
    Vector {
        name: "azure-embedded-connstring",
        // AccountKey= starts at byte 53, value at 64, semicolon at 120.
        input: b"DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=dGhpcyBpcyBhIHRlc3QgdmFsdWUgd2l0aCBiYXNlNjQgZW5jb2Rpbmc=;EndpointSuffix=core.windows.net",
        spans: &[ExpectedSpan {
            start: 64,
            end: 120,
            rule: "azure-style-token",
        }],
    },
];

pub static NEGATIVE: &[Vector] = &[
    Vector {
        name: "azure-sig-too-short",
        input: b"sig=abc",
        spans: &[],
    },
    Vector {
        name: "azure-empty-value",
        input: b"AccountKey=",
        spans: &[],
    },
    Vector {
        name: "azure-wrong-key",
        input: b"SomeOtherKey=dGhpcyBpcyBhIHRlc3QgdmFsdWUgZW5jb2Rpbmc=",
        spans: &[],
    },
];
