//! Vectors for `pypi-token` (docs/02-rules.md).
//!
//! PyPI API tokens are macaroons: `pypi-` followed by a base64url body.
//! Real tokens have 150+ chars of base64url after the prefix. We match
//! `pypi-[A-Za-z0-9_-]{50,255}` with a body cap at 255 (docs/02).

use super::{ExpectedSpan, Vector};

/// Canonical 50-char base64url body after the `pypi-` prefix (55 total).
const B55: &[u8; 55] = b"pypi-AgEIcHlwaS5vcmcCJDU4ZjYyYjQ5LTk4OTAtNDA5OC1hOWJiYQ";

pub static POSITIVE: &[Vector] = &[
    Vector {
        name: "pypi-min-50",
        input: B55,
        spans: &[ExpectedSpan {
            start: 0,
            end: 55,
            rule: "pypi-token",
        }],
    },
    Vector {
        name: "pypi-realistic-long",
        // Real PyPI tokens are ~150-180 chars. 100-char body here.
        input: b"pypi-AgEIcHlwaS5vcmcCJDU4ZjYyYjQ5LTk4OTAtNDA5OC1hOWJiLWE1M2Q0Y2MyYjZmOQACJXsicGVybWlzc2lvbnMiOiAidXNlciIsICJ2ZXJzaW9uIjogMX0",
        spans: &[ExpectedSpan {
            start: 0,
            end: 124,
            rule: "pypi-token",
        }],
    },
    Vector {
        name: "pypi-embedded-log",
        // "pip: using token " = 17 bytes, then 55-byte token.
        input: b"pip: using token pypi-AgEIcHlwaS5vcmcCJDU4ZjYyYjQ5LTk4OTAtNDA5OC1hOWJiYQ for upload\n",
        spans: &[ExpectedSpan {
            start: 17,
            end: 72,
            rule: "pypi-token",
        }],
    },
    Vector {
        name: "pypi-binary-embedded",
        input: b"\x00\xffpypi-AgEIcHlwaS5vcmcCJDU4ZjYyYjQ5LTk4OTAtNDA5OC1hOWJiYQ\x01",
        spans: &[ExpectedSpan {
            start: 2,
            end: 57,
            rule: "pypi-token",
        }],
    },
];

pub static NEGATIVE: &[Vector] = &[
    Vector {
        // 49 body chars = 54 total: 1 below the 50-char body minimum.
        name: "pypi-too-short-49",
        input: b"pypi-AgEIcHlwaS5vcmcCJDU4ZjYyYjQ5LTk4OTAtNDA5OC1h",
        spans: &[],
    },
    Vector {
        name: "pypi-anchor-only",
        input: b"install pypi-",
        spans: &[],
    },
    Vector {
        name: "pypi-wrong-prefix",
        input: b"pypa-AgEIcHlwaS5vcmcCJDU4ZjYyYjQ5LTk4OTAtNDA5OC1hOWJiYQ",
        spans: &[],
    },
    Vector {
        name: "pypi-charset-break",
        // Space in the body breaks the match early — only 30 valid chars.
        input: b"pypi-AgEIcHlwaS5vcmcCJDU4ZjYyY jQ5LTk4OTAtNDA5OC1hOWJiYQ",
        spans: &[],
    },
];
