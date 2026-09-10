//! Vectors for `gcp-api-key` (docs/02-rules.md).
//!
//! Format: `AIza[0-9A-Za-z_-]{35}` — exactly 39 chars total.

use super::{ExpectedSpan, Vector};

pub static POSITIVE: &[Vector] = &[
    Vector {
        name: "gcp-api-key-basic",
        input: b"AIzaSyC0123456789abcdefghijklmnopqrstuv",
        spans: &[ExpectedSpan {
            start: 0,
            end: 39,
            rule: "gcp-api-key",
        }],
    },
    Vector {
        name: "gcp-api-key-dash-underscore",
        input: b"AIzaSyC_0123456789-abcdefghijklmnopqrst",
        spans: &[ExpectedSpan {
            start: 0,
            end: 39,
            rule: "gcp-api-key",
        }],
    },
    Vector {
        name: "gcp-api-key-embedded-url",
        input: b"https://maps.googleapis.com/maps/api/js?key=AIzaSyC0123456789abcdefghijklmnopqrstuv&callback=init",
        spans: &[ExpectedSpan {
            start: 44,
            end: 83,
            rule: "gcp-api-key",
        }],
    },
    Vector {
        name: "gcp-api-key-binary-embedded",
        input: b"\x00\xffAIzaSyC0123456789abcdefghijklmnopqrstuv\x01",
        spans: &[ExpectedSpan {
            start: 2,
            end: 41,
            rule: "gcp-api-key",
        }],
    },
];

pub static NEGATIVE: &[Vector] = &[
    Vector {
        name: "gcp-too-short-34",
        input: b"AIzaSyC0123456789abcdefghijklmnopqrstu",
        spans: &[],
    },
    Vector {
        name: "gcp-wrong-prefix",
        input: b"AIzb0123456789abcdefghijklmnopqrstuvwx",
        spans: &[],
    },
    Vector {
        name: "gcp-anchor-only",
        input: b"see AIza key",
        spans: &[],
    },
];
