//! Vectors for `aws-secret-key` (docs/02-rules.md).
//!
//! Context-keyed: anchors on `aws_secret` or `SecretAccessKey`, but only
//! the 40-char base64 VALUE is redacted — not the key name or separator.

use super::{ExpectedSpan, Vector};

/// Canonical 40-char base64 secret key value.
const SECRET40: &[u8] = b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

pub static POSITIVE: &[Vector] = &[
    Vector {
        name: "aws-secret-env-style",
        // "aws_secret_access_key = " = 24 bytes, then 40-byte value.
        input: b"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        spans: &[ExpectedSpan {
            start: 24,
            end: 64,
            rule: "aws-secret-key",
        }],
    },
    Vector {
        name: "aws-secret-json-style",
        // "SecretAccessKey": " = 19 bytes including quote, value at 20..60.
        input: b"\"SecretAccessKey\": \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"",
        spans: &[ExpectedSpan {
            start: 20,
            end: 60,
            rule: "aws-secret-key",
        }],
    },
    Vector {
        name: "aws-secret-equals-no-space",
        // "aws_secret_access_key=" = 22 bytes, value at 22..62.
        input: b"aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        spans: &[ExpectedSpan {
            start: 22,
            end: 62,
            rule: "aws-secret-key",
        }],
    },
    Vector {
        name: "aws-secret-embedded-log",
        // "deploy: aws_secret_access_key = " = 32 bytes, value at 32..72.
        input: b"deploy: aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY leaked\n",
        spans: &[ExpectedSpan {
            start: 32,
            end: 72,
            rule: "aws-secret-key",
        }],
    },
];

pub static NEGATIVE: &[Vector] = &[
    Vector {
        name: "aws-secret-bare-base64",
        // 40 base64 chars without context — must NOT match.
        input: SECRET40,
        spans: &[],
    },
    Vector {
        name: "aws-secret-no-value",
        input: b"aws_secret_access_key = ",
        spans: &[],
    },
    Vector {
        name: "aws-secret-value-too-short",
        // Only 30 base64 chars after separator.
        input: b"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfi",
        spans: &[],
    },
];
