//! Vectors for `npm-token` (docs/02-rules.md).
//!
//! Body alphabet is `[0-9A-Za-z]` (alnum ONLY — no `_`, unlike github's),
//! exactly 36 chars: 30 entropy + 6 CRC32 (base62-encoded). CRC mismatch
//! ⇒ reject. Tokens below were generated with CRC32("entropy") →
//! base62-encode-6.

use super::{ExpectedSpan, Vector};

pub static POSITIVE: &[Vector] = &[
    Vector {
        // CRC32("AbCdEfGhIjKlMnOpQrStUvWxYz0123") = 0x9AC1C92E → "2piBxe"
        name: "npm-valid-crc",
        input: b"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",
        spans: &[ExpectedSpan {
            start: 0,
            end: 40,
            rule: "npm-token",
        }],
    },
    Vector {
        // Valid CRC with extra alnum chars after — match is exactly prefix+36.
        name: "npm-boundary-37",
        input: b"npm_AbCdEfGhIjKlMnOpQrStUvWxYz01232piBxeX",
        spans: &[ExpectedSpan {
            start: 0,
            end: 40,
            rule: "npm-token",
        }],
    },
    Vector {
        // 72 alnum chars: match covers the first 36 (valid CRC), residue passes.
        name: "npm-run-72",
        input: b"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\
                 AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        spans: &[ExpectedSpan {
            start: 0,
            end: 40,
            rule: "npm-token",
        }],
    },
    Vector {
        name: "npm-embedded-log-line",
        input: b"publish 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 ok",
        spans: &[ExpectedSpan {
            start: 8,
            end: 48,
            rule: "npm-token",
        }],
    },
    Vector {
        // Token ends exactly at EOF.
        name: "npm-exact-36-at-eof",
        input: b"pkg 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",
        spans: &[ExpectedSpan {
            start: 4,
            end: 44,
            rule: "npm-token",
        }],
    },
    Vector {
        // CRC32("aB1cD2eF3gH4iJ5kL6mN7oP8qR9sTu") = 0x25C7EC6A → "0gtbj8"
        name: "npm-alternate-entropy",
        input: b"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",
        spans: &[ExpectedSpan {
            start: 0,
            end: 40,
            rule: "npm-token",
        }],
    },
];

pub static NEGATIVE: &[Vector] = &[
    Vector {
        name: "npm-too-short-35",
        input: b"npm_AbCdEfGhIjKlMnOpQrStUvWxYz012345678",
        spans: &[],
    },
    Vector {
        // Trap: '_' as the 36th body char — valid for github bodies, NOT npm.
        name: "npm-underscore-36th-char",
        input: b"npm_AbCdEfGhIjKlMnOpQrStUvWxYz012345678_",
        spans: &[],
    },
    Vector {
        // Charset break ('-') at body char 11.
        name: "npm-dash-in-body",
        input: b"npm_abcde12345-abcdefghij0123456789abcde",
        spans: &[],
    },
    Vector {
        // Anchors are case-sensitive.
        name: "npm-uppercase-anchor",
        input: b"NPM_AbCdEfGhIjKlMnOpQrStUvWxYz01232piBxe",
        spans: &[],
    },
    Vector {
        name: "npm-anchor-only",
        input: b"install npm_ pkg",
        spans: &[],
    },
    // --- CRC failures ---
    Vector {
        // Valid shape, wrong checksum (last char flipped).
        name: "npm-wrong-crc",
        input: b"npm_AbCdEfGhIjKlMnOpQrStUvWxYz01232piBxf",
        spans: &[],
    },
    Vector {
        // Random body without valid CRC — would have matched under old shape-only DFA.
        name: "npm-random-body-no-crc",
        input: b"npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        spans: &[],
    },
];
