//! Vectors for `npm-token` (docs/02-rules.md).
//!
//! Body alphabet is `[0-9A-Za-z]` (alnum ONLY — no `_`, unlike github's),
//! exactly 36 chars, no trailing-boundary check: a longer alnum run matches
//! its first 36 (spec-literal).

use super::{ExpectedSpan, Vector};

pub static POSITIVE: &[Vector] = &[
    Vector {
        name: "npm-exact-36",
        input: b"npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        spans: &[ExpectedSpan {
            start: 0,
            end: 40,
            rule: "npm-token",
        }],
    },
    Vector {
        // Spec-literal pin: 37 alnum chars → first 36 match, 1-char residue.
        name: "npm-boundary-37",
        input: b"npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789X",
        spans: &[ExpectedSpan {
            start: 0,
            end: 40,
            rule: "npm-token",
        }],
    },
    Vector {
        // 72 alnum chars → first 36 match, 36-char residue passes through.
        name: "npm-run-72",
        input: b"npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789\
                 AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        spans: &[ExpectedSpan {
            start: 0,
            end: 40,
            rule: "npm-token",
        }],
    },
    Vector {
        name: "npm-embedded-log-line",
        input: b"publish npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789 ok",
        spans: &[ExpectedSpan {
            start: 8,
            end: 48,
            rule: "npm-token",
        }],
    },
    Vector {
        // Token ends exactly at EOF.
        name: "npm-exact-36-at-eof",
        input: b"pkg npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        spans: &[ExpectedSpan {
            start: 4,
            end: 44,
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
        input: b"NPM_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        spans: &[],
    },
    Vector {
        name: "npm-anchor-only",
        input: b"install npm_ pkg",
        spans: &[],
    },
];
