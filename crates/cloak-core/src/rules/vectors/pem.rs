//! Test vectors for the `pem-private-key` rule.
//!
//! PEM detection is handled by a separate stateful layer (not in CATALOG),
//! so the redacted span covers only the body between BEGIN and END markers.
//! The markers themselves pass through to output.

use super::{ExpectedSpan, Vector};

pub const POSITIVE: &[&Vector] = &[
    // --- RSA PRIVATE KEY --- body=[31,111)
    &Vector {
        name: "pem-rsa-minimal",
        input: b"-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALRiMLAH0123456789abcdefgABCDEFGHIJKLMNOPQRSTUVWXYZ\n0123456789+/==\n-----END RSA PRIVATE KEY-----",
        spans: &[ExpectedSpan {
            start: 31,
            end: 111,
            rule: "pem-private-key",
        }],
    },
    // --- EC PRIVATE KEY --- body=[30,40)
    &Vector {
        name: "pem-ec",
        input: b"-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE\n-----END EC PRIVATE KEY-----",
        spans: &[ExpectedSpan {
            start: 30,
            end: 40,
            rule: "pem-private-key",
        }],
    },
    // --- PKCS#8 PRIVATE KEY (generic) --- body=[27,33)
    &Vector {
        name: "pem-pkcs8",
        input: b"-----BEGIN PRIVATE KEY-----\nbody\n-----END PRIVATE KEY-----",
        spans: &[ExpectedSpan {
            start: 27,
            end: 33,
            rule: "pem-private-key",
        }],
    },
    // --- OPENSSH PRIVATE KEY --- body=[35,57)
    &Vector {
        name: "pem-openssh",
        input: b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END OPENSSH PRIVATE KEY-----",
        spans: &[ExpectedSpan {
            start: 35,
            end: 57,
            rule: "pem-private-key",
        }],
    },
    // --- ENCRYPTED PRIVATE KEY --- body=[37,49)
    &Vector {
        name: "pem-encrypted",
        input: b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIE6TAbBg\n-----END ENCRYPTED PRIVATE KEY-----",
        spans: &[ExpectedSpan {
            start: 37,
            end: 49,
            rule: "pem-private-key",
        }],
    },
    // --- PEM embedded in surrounding text --- body=[60,70)
    &Vector {
        name: "pem-embedded-in-log",
        input: b"2024-01-15 ERROR leaked key:\n-----BEGIN RSA PRIVATE KEY-----\nBODYDATA\n-----END RSA PRIVATE KEY-----\nmore log output",
        spans: &[ExpectedSpan {
            start: 60,
            end: 70,
            rule: "pem-private-key",
        }],
    },
    // --- PEM at start of buffer (DSA) --- body=[31,40)
    &Vector {
        name: "pem-at-start",
        input: b"-----BEGIN DSA PRIVATE KEY-----\nDSABODY\n-----END DSA PRIVATE KEY-----\ntail",
        spans: &[ExpectedSpan {
            start: 31,
            end: 40,
            rule: "pem-private-key",
        }],
    },
    // --- BEGIN line exactly at EOF, no body, no END --- empty span [31,31)
    &Vector {
        name: "pem-unterminated-eof",
        input: b"-----BEGIN RSA PRIVATE KEY-----",
        spans: &[ExpectedSpan {
            start: 31,
            end: 31,
            rule: "pem-private-key",
        }],
    },
];

pub const NEGATIVE: &[&Vector] = &[
    // --- CERTIFICATE (not a private key) ---
    &Vector {
        name: "pem-neg-certificate",
        input: b"-----BEGIN CERTIFICATE-----\ncertdata\n-----END CERTIFICATE-----",
        spans: &[],
    },
    // --- PUBLIC KEY ---
    &Vector {
        name: "pem-neg-public-key",
        input: b"-----BEGIN PUBLIC KEY-----\npubdata\n-----END PUBLIC KEY-----",
        spans: &[],
    },
    // --- Truncated BEGIN (no closing dashes) ---
    &Vector {
        name: "pem-neg-truncated-begin",
        input: b"-----BEGIN RSA PRIVATE KEY\nbody\n-----END RSA PRIVATE KEY-----",
        spans: &[],
    },
    // --- Case mismatch ---
    &Vector {
        name: "pem-neg-case-mismatch",
        input: b"-----BEGIN rsa private key-----\nbody\n-----END rsa private key-----",
        spans: &[],
    },
    // --- Just the anchor, no key type ---
    &Vector {
        name: "pem-neg-begin-only",
        input: b"-----BEGIN without completing the pattern",
        spans: &[],
    },
];
