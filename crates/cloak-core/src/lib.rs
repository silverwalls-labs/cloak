//! `cloak-core` — guarantee-grade secrets and PII redaction engine.
//!
//! This crate provides the core scanning engine that consumes byte chunks
//! and emits redacted bytes plus match events. It has no CLI, no I/O policy —
//! everything the three deployment layers share lives here.
//!
//! The API is deliberately **binding-shaped**: bytes in, bytes out, expressible
//! over a C ABI or WASM linear memory, so embedding (v0.2) lands without
//! core rework.
//!
//! # Example
//!
//! The full pipe loop — config → engine → session → push/finish:
//!
//! ```
//! use cloak_core::{Config, Engine};
//!
//! let config = Config::ephemeral(); // testing: no env lookup, no warning
//! let engine = Engine::new(&config)?;
//!
//! let mut session = engine.session();
//! let mut out = Vec::new();
//! session.push(b"user=alice token=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\n", &mut out)?;
//! let stats = session.finish(&mut out)?;
//!
//! assert!(out.starts_with(b"user=alice token=[CLOAK:github-token:"));
//! assert_eq!(stats.total_matches(), 1);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![deny(unsafe_code)]

mod config;
mod engine;
mod redact;
mod rules;
mod types;

// Test-support surface — NOT part of the public API contract. Re-exported
// `#[doc(hidden)]` so integration tests (and later fuzz/bench tiers) can
// reach the oracle and the vector corpora (docs/03: defined once, reused
// verbatim per tier).
#[doc(hidden)]
pub mod reference;
#[doc(hidden)]
pub use rules::vectors;

pub use config::{Config, RedactionConfig, RuleConfig};
pub use engine::{BuildError, Engine, Session};
pub use redact::{compute_digest, format_tag, write_tag};
pub use types::{Digest, MatchEvent, RuleId, Stats};
