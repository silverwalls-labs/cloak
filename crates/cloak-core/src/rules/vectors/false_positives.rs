//! False-positive suite (docs/02-rules.md, issue #7).
//!
//! Inputs that look like secrets or PII but MUST produce zero matches.
//! Covers: trace IDs, order numbers, base64 payloads, bare digit strings,
//! version strings, timestamps, diff hunks.

use super::Vector;

pub static VECTORS: &[Vector] = &[
    // ── Trace IDs / UUIDs ────────────────────────────────────────────
    Vector {
        name: "fp-uuid",
        input: b"trace_id=550e8400-e29b-41d4-a716-446655440000",
        spans: &[],
    },
    Vector {
        name: "fp-otel-trace-id",
        input: b"TraceId: 0af7651916cd43dd8448eb211c80319c",
        spans: &[],
    },
    // ── Order numbers / bare digit strings ───────────────────────────
    Vector {
        name: "fp-10-digit-number",
        input: b"order 1234567890",
        spans: &[],
    },
    Vector {
        name: "fp-16-digit-order",
        // 16 digits, starts with 1 — not a valid IIN.
        input: b"ref 1234567890123456",
        spans: &[],
    },
    Vector {
        name: "fp-14-digit-order",
        input: b"ORD-12345678901234",
        spans: &[],
    },
    // ── Base64 payloads ─────────────────────────────────────────────
    Vector {
        name: "fp-data-uri",
        input: b"data:image/png;base64,iVBORw0KGgoAAAANSUhEUg",
        spans: &[],
    },
    Vector {
        name: "fp-generic-base64",
        input: b"payload: SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0",
        spans: &[],
    },
    // ── Version strings (must NOT match IPv4) ───────────────────────
    Vector {
        name: "fp-version-string",
        // 5 components — rejected by the IPv4 5th-dot check.
        input: b"version 1.2.3.4.5",
        spans: &[],
    },
    Vector {
        name: "fp-version-3-part",
        // Only 3 octets — not valid IPv4.
        input: b"v10.0.255",
        spans: &[],
    },
    // ── Timestamps ──────────────────────────────────────────────────
    Vector {
        name: "fp-iso-timestamp",
        input: b"2026-09-10T12:34:56Z",
        spans: &[],
    },
    // ── Diff hunks ──────────────────────────────────────────────────
    Vector {
        name: "fp-diff-hunk",
        input: b"@@ -1,3 +1,4 @@",
        spans: &[],
    },
    // ── Arithmetic / code ───────────────────────────────────────────
    Vector {
        name: "fp-arithmetic-plus",
        input: b"result = x + 5",
        spans: &[],
    },
    Vector {
        name: "fp-cpp-scope",
        input: b"std::vector<int> v;",
        spans: &[],
    },
    // ── URL without credentials (must NOT match connection-string) ──
    Vector {
        name: "fp-https-url",
        input: b"https://example.com/api/v1/users",
        spans: &[],
    },
    Vector {
        name: "fp-file-url",
        input: b"file:///tmp/data.csv",
        spans: &[],
    },
    // ── Redaction-tag tail adjacency (#34) ───────────────────────────
    // A candidate fused DIRECTLY to a `[CLOAK:…]` tag tail must not
    // match: the tag stands in for redacted content the backward guard
    // would have rejected, so accepting it would break idempotence
    // (redact(redact(S)) ≠ redact(S)). A separator (space, newline)
    // between tag and candidate restores normal matching — see the
    // positive controls in `phone_intl.rs`.
    Vector {
        name: "fp-tag-tail-phone",
        // The original #34 reproducer shape: jwt redacted, phone fused.
        input: b"[CLOAK:jwt:6717]+12345678901",
        spans: &[],
    },
    Vector {
        name: "fp-tag-tail-credit-card",
        input: b"[CLOAK:phone-intl:1a2b]2224000000000006",
        spans: &[],
    },
    Vector {
        name: "fp-tag-tail-ipv6",
        input: b"[CLOAK:jwt:6717]2a02:0001:0002:0003:0004:0005:0006:0007",
        spans: &[],
    },
    Vector {
        name: "fp-tag-tail-ipv4",
        input: b"[CLOAK:phone-intl:1a2b]192.168.1.100",
        spans: &[],
    },
    Vector {
        name: "fp-tag-tail-email",
        input: b"[CLOAK:jwt:6717]user@example.com",
        spans: &[],
    },
    Vector {
        name: "fp-tag-tail-connstring",
        input: b"[CLOAK:jwt:6717]postgres://admin:s3cret@db.example.com",
        spans: &[],
    },
    Vector {
        name: "fp-tag-tail-aws-secret",
        input: b"[CLOAK:jwt:6717]aws_secret_access_key = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        spans: &[],
    },
    // ── Redaction-tag head adjacency (#34 forward face) ──────────────
    // A candidate whose forward boundary or forward scan stops on a
    // `[CLOAK:…]` tag head must not match: the tag stands in for redacted
    // content the scan would have absorbed (a longer domain, a digit
    // after the last octet, an authority segment reaching an `@`), so
    // accepting it would break idempotence. Found by strict
    // fuzz_engine_stream; mirrors the tag-tail section above.
    Vector {
        name: "fp-tag-head-ipv4",
        input: b"192.168.1.100[CLOAK:phone-intl:1a2b]",
        spans: &[],
    },
    Vector {
        name: "fp-tag-head-ipv6",
        input: b"2a02:0001:0002:0003:0004:0005:0006:0007[CLOAK:jwt:6717]",
        spans: &[],
    },
    Vector {
        name: "fp-tag-head-credit-card",
        input: b"2224000000000006[CLOAK:phone-intl:1a2b]",
        spans: &[],
    },
    Vector {
        name: "fp-tag-head-phone",
        input: b"+12345678901[CLOAK:jwt:6717]",
        spans: &[],
    },
    Vector {
        name: "fp-tag-head-email",
        // The strict-fuzz reproducer shape: pass 1 rejects
        // `d@m.efglpat-…` (TLD runs into the token), so pass 2 must not
        // accept the short domain the tag head leaves behind.
        input: b"d@m.ef[CLOAK:gitlab-token:610d]",
        spans: &[],
    },
    Vector {
        name: "fp-tag-head-connstring",
        // Pass 1's authority scan breaks on the card's spaces, so pass 2
        // must not sail through the tag to reach the `@`.
        input: b"postgres://user:p![CLOAK:credit-card:1a2b]@host",
        spans: &[],
    },
];
