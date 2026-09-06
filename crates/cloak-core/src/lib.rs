//! `cloak-core` — guarantee-grade secrets and PII redaction engine.
//!
//! This crate provides the core scanning engine that consumes byte chunks
//! and emits redacted bytes plus match events. It has no CLI, no I/O policy —
//! everything the three deployment layers share lives here.
//!
//! The API is deliberately **binding-shaped**: bytes in, bytes out, expressible
//! over a C ABI or WASM linear memory, so embedding (v0.2) lands without
//! core rework.

#![deny(unsafe_code)]

mod config;
mod engine;
mod redact;
mod types;

pub use config::Config;
pub use engine::{BuildError, Engine, Session};
pub use redact::{compute_digest, format_tag, write_tag};
pub use types::{Digest, MatchEvent, RuleId, Stats};
