//! Vectors for `github-token` (docs/02-rules.md).
//!
//! Classic prefixes (`ghp_`, `gho_`, `ghs_`, `ghu_`, `ghr_`) embed a CRC32
//! checksum: prefix + 30 entropy (base62) + 6 CRC (base62) = exactly 40.
//! Fine-grained (`github_pat_`) is shape-only: `[0-9A-Za-z_]{36,255}`.
//!
//! Tokens below were generated with: CRC32("entropy") → base62-encode-6.
//! CRC32 uses the standard ISO-HDLC polynomial (0xEDB88320).

use super::{ExpectedSpan, Vector};

// ── Positive: classic prefixes with valid CRC ───────────────────────

pub static POSITIVE: &[Vector] = &[
    Vector {
        name: "github-ghp-valid-crc",
        // CRC32("AbCdEfGhIjKlMnOpQrStUvWxYz0123") = 0x9AC1C92E → "2piBxe"
        input: b"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",
        spans: &[ExpectedSpan {
            start: 0,
            end: 40,
            rule: "github-token",
        }],
    },
    Vector {
        name: "github-gho-valid-crc",
        // Same entropy, same CRC — prefix is not part of the hash.
        input: b"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",
        spans: &[ExpectedSpan {
            start: 0,
            end: 40,
            rule: "github-token",
        }],
    },
    Vector {
        name: "github-ghs-valid-crc",
        // CRC32("aB1cD2eF3gH4iJ5kL6mN7oP8qR9sTu") = 0x25C7EC6A → "0gtbj8"
        input: b"ghs_aB1cD2eF3gH4iJ5kL6mN7oP8qR9sTu0gtbj8",
        spans: &[ExpectedSpan {
            start: 0,
            end: 40,
            rule: "github-token",
        }],
    },
    Vector {
        name: "github-ghu-valid-crc",
        // CRC32("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123") = 0xEC46CE3A → "4KGnwg"
        input: b"ghu_ABCDEFGHIJKLMNOPQRSTUVWXYZ01234KGnwg",
        spans: &[ExpectedSpan {
            start: 0,
            end: 40,
            rule: "github-token",
        }],
    },
    Vector {
        name: "github-ghr-valid-crc",
        // CRC32("abcdefghijklmnopqrstuvwxyz0123") = 0x806D9A54 → "2LolCm"
        input: b"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",
        spans: &[ExpectedSpan {
            start: 0,
            end: 40,
            rule: "github-token",
        }],
    },
    // ── classic: trailing chars (exact 36, NOT greedy) ───────────────
    Vector {
        // Valid CRC token followed by more alnum — match stops at 40.
        name: "github-classic-not-greedy",
        input: b"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ExtraChars",
        spans: &[ExpectedSpan {
            start: 0,
            end: 40,
            rule: "github-token",
        }],
    },
    // ── classic: embedded in context ─────────────────────────────────
    Vector {
        name: "github-embedded-log-line",
        input: b"deploy: token=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 done\n",
        spans: &[ExpectedSpan {
            start: 14,
            end: 54,
            rule: "github-token",
        }],
    },
    Vector {
        // Token ends exactly at EOF.
        name: "github-at-buffer-end",
        input: b"log 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",
        spans: &[ExpectedSpan {
            start: 4,
            end: 44,
            rule: "github-token",
        }],
    },
    Vector {
        name: "github-two-classic-tokens",
        input: b"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 \
                 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",
        spans: &[
            ExpectedSpan {
                start: 0,
                end: 40,
                rule: "github-token",
            },
            ExpectedSpan {
                start: 41,
                end: 81,
                rule: "github-token",
            },
        ],
    },
    Vector {
        // Bytes, never str: token embedded in binary garbage still caught.
        name: "github-binary-embedded",
        input: b"\x00\xff\x80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\x01\x02",
        spans: &[ExpectedSpan {
            start: 3,
            end: 43,
            rule: "github-token",
        }],
    },
    // ── Fine-grained: shape-only, no CRC ────────────────────────────
    Vector {
        // Realistic fine-grained PAT shape: 22 chars + '_' + 59 chars = 82.
        name: "github-pat-fine-grained-82",
        input: b"github_pat_ABCDEFGHIJKLMNOPQRSTUV_\
                 abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVW",
        spans: &[ExpectedSpan {
            start: 0,
            end: 93,
            rule: "github-token",
        }],
    },
    Vector {
        // Greedy pin: 40-char body → match ends at 51, not 47.
        name: "github-pat-greedy-body",
        input: b"github_pat_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Wxyz",
        spans: &[ExpectedSpan {
            start: 0,
            end: 51,
            rule: "github-token",
        }],
    },
    Vector {
        // Exactly at the 255-char body cap.
        name: "github-pat-at-cap-255",
        input: b"github_pat_\
                 01234567890123456789012345678901234567890123456789\
                 01234567890123456789012345678901234567890123456789\
                 01234567890123456789012345678901234567890123456789\
                 01234567890123456789012345678901234567890123456789\
                 01234567890123456789012345678901234567890123456789\
                 01234",
        spans: &[ExpectedSpan {
            start: 0,
            end: 266,
            rule: "github-token",
        }],
    },
    Vector {
        // Body over the cap: first 255 chars redacted, 45-char residue
        // passes through (spec-literal, docs/02-rules.md).
        name: "github-pat-cap-overflow-300",
        input: b"github_pat_\
                 01234567890123456789012345678901234567890123456789\
                 01234567890123456789012345678901234567890123456789\
                 01234567890123456789012345678901234567890123456789\
                 01234567890123456789012345678901234567890123456789\
                 01234567890123456789012345678901234567890123456789\
                 01234567890123456789012345678901234567890123456789",
        spans: &[ExpectedSpan {
            start: 0,
            end: 266,
            rule: "github-token",
        }],
    },
];

// ── Negative ────────────────────────────────────────────────────────

pub static NEGATIVE: &[Vector] = &[
    // --- Classic: CRC failures ---
    Vector {
        // Valid shape, wrong checksum (last char flipped).
        name: "github-ghp-wrong-crc",
        input: b"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz01232piBxf",
        spans: &[],
    },
    Vector {
        name: "github-gho-wrong-crc",
        input: b"gho_AbCdEfGhIjKlMnOpQrStUvWxYz01232piBxf",
        spans: &[],
    },
    Vector {
        name: "github-ghs-wrong-crc",
        input: b"ghs_AbCdEfGhIjKlMnOpQrStUvWxYz01232piBxf",
        spans: &[],
    },
    Vector {
        name: "github-ghu-wrong-crc",
        input: b"ghu_AbCdEfGhIjKlMnOpQrStUvWxYz01232piBxf",
        spans: &[],
    },
    Vector {
        name: "github-ghr-wrong-crc",
        input: b"ghr_AbCdEfGhIjKlMnOpQrStUvWxYz01232piBxf",
        spans: &[],
    },
    // --- Classic: structural failures ---
    Vector {
        name: "github-classic-too-short-35",
        input: b"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345678",
        spans: &[],
    },
    Vector {
        // Underscore in classic body — not base62, rejected before CRC.
        name: "github-classic-underscore-body",
        input: b"ghp_AbCdEfGhIjKlMnOp_rStUvWxYz01232piBxe",
        spans: &[],
    },
    Vector {
        // Charset break at body char 21 — only 20 valid chars before '-'.
        name: "github-classic-charset-break",
        input: b"ghp_abcdefghij0123456789-abcdefghij0123456789",
        spans: &[],
    },
    Vector {
        name: "github-anchor-only",
        input: b"push to ghp_ registry",
        spans: &[],
    },
    Vector {
        // Anchor truncated at EOF — insufficient body.
        name: "github-anchor-at-eof",
        input: b"tail ghp_",
        spans: &[],
    },
    Vector {
        // Anchors are case-sensitive.
        name: "github-uppercase-anchor",
        input: b"GHP_AbCdEfGhIjKlMnOpQrStUvWxYz01232piBxe",
        spans: &[],
    },
    Vector {
        name: "github-near-anchor",
        input: b"ghx_AbCdEfGhIjKlMnOpQrStUvWxYz01232piBxe",
        spans: &[],
    },
    // --- Fine-grained: structural failures (shape-only, no CRC) ---
    Vector {
        name: "github-pat-too-short-35",
        input: b"github_pat_AbCdEfGhIjKlMnOpQrStUvWxYz012345678",
        spans: &[],
    },
    // --- Classic: random body without valid CRC (FP reduction) ---
    Vector {
        // This would have matched under the old shape-only DFA.
        // Now it's rejected because the CRC doesn't validate.
        name: "github-classic-random-body-no-crc",
        input: b"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        spans: &[],
    },
];
