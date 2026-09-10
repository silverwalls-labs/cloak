//! Vectors for `connection-string` (docs/02-rules.md).
//!
//! Context-keyed + partial redaction: only the PASSWORD span is redacted.
//! Output shape: `scheme://user:[CLOAK:connection-string:xxxx]@host`.

use super::{ExpectedSpan, Vector};

pub static POSITIVE: &[Vector] = &[
    Vector {
        name: "connstring-postgres",
        // "postgres://admin:" = 17 bytes, password "s3cret" = 6 bytes (17..23).
        // Host "db" has no TLD — cannot be confused for an email domain.
        input: b"postgres://admin:s3cret@db:5432/mydb",
        spans: &[ExpectedSpan {
            start: 17,
            end: 23,
            rule: "connection-string",
        }],
    },
    Vector {
        name: "connstring-mysql",
        // "mysql://root:" = 13 bytes, password "pa$$w0rd" = 8 bytes (13..21).
        input: b"mysql://root:pa$$w0rd@localhost:3306/app",
        spans: &[ExpectedSpan {
            start: 13,
            end: 21,
            rule: "connection-string",
        }],
    },
    Vector {
        name: "connstring-mongodb",
        // "mongodb://user:" = 15, password "secret123" = 9 bytes (15..24).
        input: b"mongodb://user:secret123@cluster0/db",
        spans: &[ExpectedSpan {
            start: 15,
            end: 24,
            rule: "connection-string",
        }],
    },
    Vector {
        name: "connstring-redis",
        // "redis://default:" = 16, password "mypass" = 6 bytes (16..22).
        input: b"redis://default:mypass@redis:6379",
        spans: &[ExpectedSpan {
            start: 16,
            end: 22,
            rule: "connection-string",
        }],
    },
    Vector {
        name: "connstring-amqp",
        // "amqp://guest:" = 13, password "guest" = 5 bytes (13..18).
        input: b"amqp://guest:guest@rabbitmq:5672/vhost",
        spans: &[ExpectedSpan {
            start: 13,
            end: 18,
            rule: "connection-string",
        }],
    },
    Vector {
        name: "connstring-postgresql",
        // "postgresql://admin:" = 19, password "s3cret" = 6 bytes (19..25).
        input: b"postgresql://admin:s3cret@db:5432/mydb",
        spans: &[ExpectedSpan {
            start: 19,
            end: 25,
            rule: "connection-string",
        }],
    },
    Vector {
        name: "connstring-embedded-log",
        // "DATABASE_URL=postgres://admin:" = 30, password "s3cret" at 30..36.
        input: b"DATABASE_URL=postgres://admin:s3cret@db:5432/app\n",
        spans: &[ExpectedSpan {
            start: 30,
            end: 36,
            rule: "connection-string",
        }],
    },
];

pub static NEGATIVE: &[Vector] = &[
    Vector {
        name: "connstring-https-url",
        // `https` is not in the allowed scheme set.
        input: b"https://user:pass@example.com",
        spans: &[],
    },
    Vector {
        name: "connstring-no-password",
        input: b"postgres://nopass@host:5432/db",
        spans: &[],
    },
    Vector {
        name: "connstring-no-at",
        input: b"postgres://admin:pass",
        spans: &[],
    },
    Vector {
        name: "connstring-bare-scheme",
        input: b"://bare",
        spans: &[],
    },
];
