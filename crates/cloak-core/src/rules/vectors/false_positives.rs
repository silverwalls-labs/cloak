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
];
