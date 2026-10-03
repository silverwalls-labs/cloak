//! Vectors for `ipv6` (docs/02-rules.md).
//!
//! RFC-4291 grammar with `::` compression and fully expanded form.
//! Anchors: `::` plus common IPv6 prefix patterns (F01: `2001:`, `fe80:`, etc.).

use super::{ExpectedSpan, Vector};

pub static POSITIVE: &[Vector] = &[
    Vector {
        name: "ipv6-loopback",
        input: b"::1",
        spans: &[ExpectedSpan {
            start: 0,
            end: 3,
            rule: "ipv6",
        }],
    },
    Vector {
        name: "ipv6-all-zeros",
        input: b"::",
        spans: &[ExpectedSpan {
            start: 0,
            end: 2,
            rule: "ipv6",
        }],
    },
    Vector {
        name: "ipv6-link-local",
        input: b"fe80::1",
        spans: &[ExpectedSpan {
            start: 0,
            end: 7,
            rule: "ipv6",
        }],
    },
    Vector {
        name: "ipv6-compressed-middle",
        input: b"2001:db8::8a2e:370:7334",
        spans: &[ExpectedSpan {
            start: 0,
            end: 23,
            rule: "ipv6",
        }],
    },
    Vector {
        name: "ipv6-v4-mapped",
        input: b"::ffff:192.168.1.1",
        spans: &[ExpectedSpan {
            start: 0,
            end: 18,
            rule: "ipv6",
        }],
    },
    Vector {
        name: "ipv6-embedded-log",
        // "from " = 5 bytes, then IPv6.
        input: b"from ::1 port 22\n",
        spans: &[ExpectedSpan {
            start: 5,
            end: 8,
            rule: "ipv6",
        }],
    },
    // F01: fully expanded 8-group addresses (no `::`).
    Vector {
        name: "ipv6-fully-expanded",
        input: b"2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        spans: &[ExpectedSpan {
            start: 0,
            end: 39,
            rule: "ipv6",
        }],
    },
    Vector {
        name: "ipv6-fully-expanded-embedded",
        // "addr=" = 5 bytes, then 39-byte expanded IPv6.
        input: b"addr=2001:0db8:85a3:0000:0000:8a2e:0370:7334 ok\n",
        spans: &[ExpectedSpan {
            start: 5,
            end: 44,
            rule: "ipv6",
        }],
    },
    // #41 review: nonlisted prefixes and uppercase hex — the F01
    // enumerated prefix anchors missed both; the generic colon anchor
    // catches every representable address.
    Vector {
        name: "ipv6-nonlisted-prefix-expanded",
        input: b"2a02:0001:0002:0003:0004:0005:0006:0007",
        spans: &[ExpectedSpan {
            start: 0,
            end: 39,
            rule: "ipv6",
        }],
    },
    Vector {
        name: "ipv6-uppercase-compressed",
        input: b"FE80::1",
        spans: &[ExpectedSpan {
            start: 0,
            end: 7,
            rule: "ipv6",
        }],
    },
    Vector {
        name: "ipv6-uppercase-expanded",
        input: b"2A07:0DB8:0000:0000:0000:0000:0000:0001",
        spans: &[ExpectedSpan {
            start: 0,
            end: 39,
            rule: "ipv6",
        }],
    },
];

pub static NEGATIVE: &[Vector] = &[
    Vector {
        name: "ipv6-cpp-scope",
        // C++ scope resolution — not an IPv6 address.
        input: b"std::vector",
        spans: &[],
    },
    Vector {
        name: "ipv6-too-many-groups",
        // 9 groups with :: — too many.
        input: b"1:2:3:4:5:6:7::8:9",
        spans: &[],
    },
    Vector {
        name: "ipv6-alnum-boundary",
        // Preceded by an alnum — not a clean boundary.
        input: b"x::1",
        spans: &[],
    },
    Vector {
        name: "ipv6-json-key-value",
        // F01: JSON key:value must not trigger IPv6 detection.
        input: b"{\"host\":\"example.com\"}",
        spans: &[],
    },
    Vector {
        name: "ipv6-timestamp",
        // F01: timestamp with colons must not trigger IPv6 detection.
        input: b"2024-01-15T10:30:45Z",
        spans: &[],
    },
    Vector {
        name: "ipv6-run-exceeds-45-cap",
        // #41 review: a hex/colon run longer than the 45-byte address cap
        // must not yield a mid-run slice match (the scan caps at 45 bytes
        // on both sides and rejects runs that continue past the caps).
        input: b"aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa",
        spans: &[],
    },
];
