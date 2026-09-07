//! Vectors for `github-token` (docs/02-rules.md).
//!
//! Body alphabet is `[0-9A-Za-z_]`, min 36, cap 255. `B36` below is the
//! canonical 36-char body: 26 alternating-case letters + 10 digits.
//! Long bodies use string-continuation (`\` skips newline + indent): each
//! continued line is exactly 50 digits (5 × "0123456789"); lengths are
//! pinned by `vectors::tests::capped_vector_lengths`.

use super::{ExpectedSpan, Vector};

pub static POSITIVE: &[Vector] = &[
    Vector {
        name: "github-ghp-min-36",
        input: b"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        spans: &[ExpectedSpan {
            start: 0,
            end: 40,
            rule: "github-token",
        }],
    },
    Vector {
        name: "github-gho-min-36",
        input: b"gho_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        spans: &[ExpectedSpan {
            start: 0,
            end: 40,
            rule: "github-token",
        }],
    },
    Vector {
        name: "github-ghs-min-36",
        input: b"ghs_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        spans: &[ExpectedSpan {
            start: 0,
            end: 40,
            rule: "github-token",
        }],
    },
    Vector {
        name: "github-ghu-min-36",
        input: b"ghu_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        spans: &[ExpectedSpan {
            start: 0,
            end: 40,
            rule: "github-token",
        }],
    },
    Vector {
        name: "github-ghr-min-36",
        input: b"ghr_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        spans: &[ExpectedSpan {
            start: 0,
            end: 40,
            rule: "github-token",
        }],
    },
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
        // Greedy pin: 40-char body → match ends at 44, not 40.
        name: "github-greedy-body-40",
        input: b"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Wxyz",
        spans: &[ExpectedSpan {
            start: 0,
            end: 44,
            rule: "github-token",
        }],
    },
    Vector {
        // Exactly at the 255-char body cap.
        name: "github-at-cap-255",
        input: b"ghp_\
                 01234567890123456789012345678901234567890123456789\
                 01234567890123456789012345678901234567890123456789\
                 01234567890123456789012345678901234567890123456789\
                 01234567890123456789012345678901234567890123456789\
                 01234567890123456789012345678901234567890123456789\
                 01234",
        spans: &[ExpectedSpan {
            start: 0,
            end: 259,
            rule: "github-token",
        }],
    },
    Vector {
        // Body over the cap: first 255 chars redacted, 45-char residue
        // passes through (spec-literal, docs/02-rules.md).
        name: "github-cap-overflow-300",
        input: b"ghp_\
                 01234567890123456789012345678901234567890123456789\
                 01234567890123456789012345678901234567890123456789\
                 01234567890123456789012345678901234567890123456789\
                 01234567890123456789012345678901234567890123456789\
                 01234567890123456789012345678901234567890123456789\
                 01234567890123456789012345678901234567890123456789",
        spans: &[ExpectedSpan {
            start: 0,
            end: 259,
            rule: "github-token",
        }],
    },
    Vector {
        name: "github-embedded-log-line",
        input: b"deploy: token=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789 done\n",
        spans: &[ExpectedSpan {
            start: 14,
            end: 54,
            rule: "github-token",
        }],
    },
    Vector {
        // Token ends exactly at EOF.
        name: "github-at-buffer-end",
        input: b"log ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        spans: &[ExpectedSpan {
            start: 4,
            end: 44,
            rule: "github-token",
        }],
    },
    Vector {
        name: "github-two-tokens-one-line",
        input: b"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789 \
                 gho_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
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
        input: b"\x00\xff\x80ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789\x01\x02",
        spans: &[ExpectedSpan {
            start: 3,
            end: 43,
            rule: "github-token",
        }],
    },
];

pub static NEGATIVE: &[Vector] = &[
    Vector {
        name: "github-too-short-35",
        input: b"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345678",
        spans: &[],
    },
    Vector {
        // Charset break at body char 21 — only 20 valid chars before it.
        name: "github-charset-break",
        input: b"ghp_abcdefghij0123456789-abcdefghij0123456789",
        spans: &[],
    },
    Vector {
        name: "github-anchor-only",
        input: b"push to ghp_ registry",
        spans: &[],
    },
    Vector {
        // Anchor truncated at EOF — pins S2 single-buffer semantics.
        name: "github-anchor-at-eof",
        input: b"tail ghp_",
        spans: &[],
    },
    Vector {
        // Anchors are case-sensitive.
        name: "github-uppercase-anchor",
        input: b"GHP_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        spans: &[],
    },
    Vector {
        name: "github-pat-too-short-35",
        input: b"github_pat_AbCdEfGhIjKlMnOpQrStUvWxYz012345678",
        spans: &[],
    },
    Vector {
        name: "github-near-anchor",
        input: b"ghx_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        spans: &[],
    },
];
