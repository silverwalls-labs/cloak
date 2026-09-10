//! Vectors for `ipv4` (docs/02-rules.md).
//!
//! Four dot-separated octets, each 0-255, non-digit boundaries.

use super::{ExpectedSpan, Vector};

pub static POSITIVE: &[Vector] = &[
    Vector {
        name: "ipv4-private",
        input: b"192.168.1.1",
        spans: &[ExpectedSpan {
            start: 0,
            end: 11,
            rule: "ipv4",
        }],
    },
    Vector {
        name: "ipv4-loopback",
        input: b"127.0.0.1",
        spans: &[ExpectedSpan {
            start: 0,
            end: 9,
            rule: "ipv4",
        }],
    },
    Vector {
        name: "ipv4-max-octets",
        input: b"255.255.255.255",
        spans: &[ExpectedSpan {
            start: 0,
            end: 15,
            rule: "ipv4",
        }],
    },
    Vector {
        name: "ipv4-zeros",
        input: b"0.0.0.0",
        spans: &[ExpectedSpan {
            start: 0,
            end: 7,
            rule: "ipv4",
        }],
    },
    Vector {
        name: "ipv4-embedded-log",
        // "from " = 5 bytes, then IP.
        input: b"from 10.0.0.42 port 22\n",
        spans: &[ExpectedSpan {
            start: 5,
            end: 14,
            rule: "ipv4",
        }],
    },
    Vector {
        name: "ipv4-binary-embedded",
        input: b"\x00\xff192.168.1.1\x01",
        spans: &[ExpectedSpan {
            start: 2,
            end: 13,
            rule: "ipv4",
        }],
    },
];

pub static NEGATIVE: &[Vector] = &[
    Vector {
        name: "ipv4-octet-overflow",
        input: b"256.168.1.1",
        spans: &[],
    },
    Vector {
        name: "ipv4-only-three-octets",
        input: b"192.168.1",
        spans: &[],
    },
    Vector {
        name: "ipv4-five-octets",
        input: b"1.2.3.4.5",
        spans: &[],
    },
    Vector {
        name: "ipv4-leading-zeros",
        input: b"01.02.03.04",
        spans: &[],
    },
    Vector {
        name: "ipv4-digit-boundary-before",
        // Preceded by a digit — not a clean boundary.
        input: b"1192.168.1.1",
        spans: &[],
    },
    Vector {
        name: "ipv4-digit-boundary-after",
        // The 4th octet is "2550" — 4 digits, which the parser rejects
        // (max 3 digits per octet). No valid IP can be parsed here.
        input: b"192.168.1.2550",
        spans: &[],
    },
];
