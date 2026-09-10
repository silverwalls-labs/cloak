//! Vectors for `ipv6` (docs/02-rules.md).
//!
//! RFC-4291 grammar with `::` compression. Anchor: `::`.

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
];
