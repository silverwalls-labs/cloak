//! Vectors for `jwt` (docs/02-rules.md).
//!
//! Format: three dot-separated base64url segments. The first (header)
//! must decode to JSON starting with `{"`.

use super::{ExpectedSpan, Vector};

/// HS256 test JWT: {"alg":"HS256","typ":"JWT"}.{"sub":"1234567890"}.signature
/// header:  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
/// payload: eyJzdWIiOiIxMjM0NTY3ODkwIn0
/// sig:     SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
const JWT_HS256: &[u8] = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

pub static POSITIVE: &[Vector] = &[
    Vector {
        name: "jwt-hs256-basic",
        input: JWT_HS256,
        spans: &[ExpectedSpan {
            start: 0,
            end: 108,
            rule: "jwt",
        }],
    },
    Vector {
        name: "jwt-embedded-header",
        // "Authorization: Bearer " = 22 bytes, then 108-byte JWT.
        input: b"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\r\n",
        spans: &[ExpectedSpan {
            start: 22,
            end: 130,
            rule: "jwt",
        }],
    },
    Vector {
        name: "jwt-binary-embedded",
        input: b"\x00\xffeyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\x01",
        spans: &[ExpectedSpan {
            start: 2,
            end: 110,
            rule: "jwt",
        }],
    },
    Vector {
        name: "jwt-pem-trailer-fused",
        // #50 repro: the signature scan must roll back the eaten `-----END`
        // so the trailer keeps rejecting the fused BEGIN (#44 guard) on
        // every pass. jwt=[0,108); the BEGIN anchor at 128 (the trailer's
        // closing dashes double as its leading dashes — exactly-5 junction)
        // is rejected; `AAAA` at 160 stays visible per the #44 junction
        // policy.
        input: b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c-----END PRIVATE KEY-----BEGIN RSA PRIVATE KEY-----\nAAAA\n",
        spans: &[ExpectedSpan {
            start: 0,
            end: 108,
            rule: "jwt",
        }],
    },
    Vector {
        name: "jwt-pem-begin-fused",
        // #50: a directly abutting BEGIN marker is rolled back too, so the
        // PEM layer sees an intact marker. jwt=[0,108), pem body=[139,145).
        input: b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----",
        spans: &[
            ExpectedSpan {
                start: 0,
                end: 108,
                rule: "jwt",
            },
            ExpectedSpan {
                start: 139,
                end: 145,
                rule: "pem-private-key",
            },
        ],
    },
];

pub static NEGATIVE: &[Vector] = &[
    Vector {
        name: "jwt-only-two-segments",
        // Only header.payload — no signature segment.
        input: b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
        spans: &[],
    },
    Vector {
        name: "jwt-invalid-header",
        // eyB decodes to `{ ` — not `{"`, so header is not valid JSON.
        input:
            b"eyBub3RKc29u.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        spans: &[],
    },
    Vector {
        name: "jwt-anchor-only",
        input: b"see eyJ for details",
        spans: &[],
    },
    Vector {
        name: "jwt-empty-signature",
        input: b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.",
        spans: &[],
    },
    Vector {
        name: "jwt-pem-trailer-empty-signature",
        // #50: the "signature" was nothing but the eaten `-----END` — the
        // rollback empties it and the jwt is rejected; the fused BEGIN is
        // rejected by the #44 guard (intact trailer). Nothing matches.
        input: b"eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.-----END PRIVATE KEY-----BEGIN RSA PRIVATE KEY-----\nAAAA\n",
        spans: &[],
    },
];
