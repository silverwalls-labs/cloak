mod confirm;
mod overlap;
mod scanner;

use std::collections::BTreeMap;
use std::io;
use std::marker::PhantomData;

use crate::config::{self, Config};
use crate::rules;
use crate::types::Stats;
use confirm::CompiledRule;
use overlap::{MergedMatch, RawMatch};
use scanner::{AhoCorasickScanner, Candidate, Scanner};

/// Error constructing an [`Engine`].
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("failed to obtain entropy for digest key: {0}")]
    Entropy(#[from] config::DigestKeyError),

    #[error("failed to build anchor prefilter automaton: {0}")]
    Prefilter(#[from] aho_corasick::BuildError),

    #[error("failed to compile confirm pattern for rule `{rule}`")]
    Confirm {
        rule: crate::types::RuleId,
        // Boxed: dense::BuildError is ~152 bytes and would dominate the
        // size of every Result<_, BuildError> (clippy::result_large_err).
        #[source]
        source: Box<regex_automata::dfa::dense::BuildError>,
    },
}

/// Compiled engine holding the resolved digest key and the compiled ruleset.
///
/// `Engine` is [`Send`] + [`Sync`] — it can be shared across threads, with
/// each thread owning its own [`Session`].
pub struct Engine {
    /// Resolved key for computing redaction digests.
    pub(crate) digest_key: [u8; 32],
    /// Anchor prefilter over all rules (docs/01, "Matching pipeline").
    scanner: AhoCorasickScanner,
    /// Per-rule confirmers, in catalog order (index == `Candidate::rule`).
    rules: Vec<CompiledRule>,
    _config: Config,
}

impl Engine {
    /// Build an engine from the given configuration.
    ///
    /// Compiles the built-in catalog: one prefilter automaton over all
    /// rules' anchors plus one anchored confirm DFA per rule. Per-rule
    /// enable/disable arrives with config in S5 — every rule is on.
    pub fn new(config: &Config) -> Result<Self, BuildError> {
        let digest_key = config::resolve_digest_key(config.digest_key_env.as_deref())?;
        let rules = rules::CATALOG
            .iter()
            .map(confirm::compile_rule)
            .collect::<Result<_, _>>()?;
        let scanner = AhoCorasickScanner::new(rules::CATALOG)?;
        Ok(Self {
            digest_key,
            scanner,
            rules,
            _config: config.clone(),
        })
    }

    /// Create a new per-stream session.
    pub fn session(&self) -> Session<'_> {
        Session {
            engine: self,
            bytes_processed: 0,
            matches: BTreeMap::new(),
            candidates: Vec::new(),
            raw: Vec::new(),
            merged: Vec::new(),
            _not_send: PhantomData,
        }
    }
}

/// Per-stream scanning state.
///
/// `Session` is **not** [`Send`] or [`Sync`] — it is bound to the thread
/// that created it.
///
/// **Why `!Send` (not just `!Sync`):** S3 will add carry-over buffers whose
/// correctness depends on push/finish being called from the same thread that
/// created the session (position-dependent mutable state). Allowing `Send`
/// now and restricting it in S3 would be a breaking API change for any
/// consumer that moves sessions between threads. The conservative choice is
/// `!Send + !Sync` from day one. Revisit for v0.2 bindings if cross-thread
/// move semantics are needed (`docs/06-embedding.md`).
pub struct Session<'e> {
    engine: &'e Engine,
    bytes_processed: u64,
    /// Per-rule match counts, accumulated across pushes.
    matches: BTreeMap<crate::types::RuleId, u64>,
    // Scratch buffers reused across pushes (cleared each call).
    candidates: Vec<Candidate>,
    raw: Vec<RawMatch>,
    merged: Vec<MergedMatch>,
    /// Opt out of auto-Send/Sync. Raw pointers are neither Send nor Sync,
    /// so PhantomData<*const ()> infects the parent struct.
    _not_send: PhantomData<*const ()>,
}

/// Compile-time assertion: `Engine` must be `Send + Sync`.
/// Lives outside `#[cfg(test)]` so regressions are caught by `cargo check`.
#[allow(dead_code)]
const _: () = {
    fn assert_send_sync<T: Send + Sync>() {}
    fn _assert() {
        assert_send_sync::<Engine>();
    }
};

impl Session<'_> {
    /// Push a chunk of bytes through the engine.
    ///
    /// S2 semantics: each chunk is scanned as a **self-contained buffer** —
    /// a match straddling two pushes is not detected. The CLI therefore
    /// slurps whole streams into one push until S3 lands bounded carry-over
    /// (at which point chunk boundaries become invisible, per docs/03).
    pub fn push(&mut self, chunk: &[u8], out: &mut impl io::Write) -> io::Result<()> {
        self.bytes_processed += chunk.len() as u64;

        // 1. Prefilter — the clean path (no anchors) does nothing else.
        self.candidates.clear();
        self.engine.scanner.scan(chunk, &mut self.candidates);
        if self.candidates.is_empty() {
            return out.write_all(chunk);
        }

        // 2. Confirm each candidate window (anchored DFA, longest-at-anchor).
        self.raw.clear();
        for cand in &self.candidates {
            let rule = &self.engine.rules[cand.rule];
            if let Some(end) = confirm::confirm(rule, chunk, cand.start) {
                self.raw.push(RawMatch {
                    start: cand.start,
                    end,
                    rule: cand.rule,
                });
            }
        }
        if self.raw.is_empty() {
            return out.write_all(chunk);
        }

        // 3. Overlap resolution: strict-overlap union, longest-leftmost wins.
        self.merged.clear();
        overlap::merge(&mut self.raw, &mut self.merged);

        // 4. Emit clean gaps and tags; count the winner per merged span.
        let mut pos = 0;
        for m in &self.merged {
            out.write_all(&chunk[pos..m.start])?;
            let rule_id = &self.engine.rules[m.rule].id;
            let digest =
                crate::redact::compute_digest(&chunk[m.start..m.end], &self.engine.digest_key);
            crate::redact::write_tag(rule_id, &digest, out)?;
            *self.matches.entry(rule_id.clone()).or_insert(0) += 1;
            pos = m.end;
        }
        out.write_all(&chunk[pos..])
    }

    /// Flush any carry-over, close open states, and return per-rule statistics.
    ///
    /// Consumes the session — no further pushes are possible after this call.
    /// The `out` parameter is unused until S3 (carry-over flushing) but
    /// required by the API contract from day one.
    pub fn finish(self, _out: &mut impl io::Write) -> io::Result<Stats> {
        Ok(Stats {
            bytes_processed: self.bytes_processed,
            matches: self.matches,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::RuleId;

    fn test_engine() -> Engine {
        let config = Config {
            digest_key_env: None, // force ephemeral, no env lookup
        };
        Engine::new(&config).unwrap()
    }

    fn push_all(engine: &Engine, chunk: &[u8]) -> (Vec<u8>, Stats) {
        let mut session = engine.session();
        let mut output = Vec::new();
        session.push(chunk, &mut output).unwrap();
        let stats = session.finish(&mut output).unwrap();
        (output, stats)
    }

    #[test]
    fn push_passthrough() {
        let engine = test_engine();
        let (output, _) = push_all(&engine, b"hello world");
        assert_eq!(output, b"hello world");
    }

    #[test]
    fn push_empty() {
        let engine = test_engine();
        let (output, stats) = push_all(&engine, b"");
        assert!(output.is_empty());
        assert_eq!(stats.bytes_processed, 0);
    }

    #[test]
    fn push_binary() {
        let engine = test_engine();
        // All byte values 0x00..=0xFF, including invalid UTF-8.
        let input: Vec<u8> = (0..=255).collect();
        let (output, _) = push_all(&engine, &input);
        assert_eq!(output, input);
    }

    #[test]
    fn multiple_pushes() {
        let engine = test_engine();
        let mut session = engine.session();
        let mut output = Vec::new();
        session.push(b"chunk-1 ", &mut output).unwrap();
        session.push(b"chunk-2 ", &mut output).unwrap();
        session.push(b"chunk-3", &mut output).unwrap();
        assert_eq!(output, b"chunk-1 chunk-2 chunk-3");
    }

    #[test]
    fn finish_returns_stats() {
        let engine = test_engine();
        let (_, stats) = push_all(&engine, b"twelve bytes");
        assert_eq!(stats.bytes_processed, 12);
        assert!(stats.matches.is_empty());
        assert_eq!(stats.total_matches(), 0);
    }

    #[test]
    fn finish_empty_session() {
        let engine = test_engine();
        let session = engine.session();
        let mut output = Vec::new();
        let stats = session.finish(&mut output).unwrap();
        assert_eq!(stats.bytes_processed, 0);
    }

    #[test]
    fn push_redacts_github_token_inline() {
        let engine = test_engine();
        let secret = b"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
        let mut input = b"x ".to_vec();
        input.extend_from_slice(secret);
        input.extend_from_slice(b" y");
        let (output, stats) = push_all(&engine, &input);

        let digest = crate::redact::compute_digest(secret, &engine.digest_key);
        let tag = crate::redact::format_tag(&RuleId::new("github-token"), &digest);
        let mut expected = b"x ".to_vec();
        expected.extend_from_slice(tag.as_bytes());
        expected.extend_from_slice(b" y");
        assert_eq!(output, expected);
        assert_eq!(stats.matches[&RuleId::new("github-token")], 1);
    }

    #[test]
    fn push_anchor_without_confirm_is_passthrough() {
        let engine = test_engine();
        let (output, stats) = push_all(&engine, b"push to ghp_ registry");
        assert_eq!(output, b"push to ghp_ registry");
        assert_eq!(stats.total_matches(), 0);
    }

    #[test]
    fn stats_accumulate_across_pushes() {
        let engine = test_engine();
        let mut session = engine.session();
        let mut output = Vec::new();
        let token = b"npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
        session.push(token, &mut output).unwrap();
        session.push(b" clean ", &mut output).unwrap();
        session.push(token, &mut output).unwrap();
        let stats = session.finish(&mut output).unwrap();
        assert_eq!(stats.matches[&RuleId::new("npm-token")], 2);
        assert_eq!(stats.bytes_processed, (token.len() * 2 + 7) as u64);
    }

    #[test]
    fn each_push_is_self_contained_in_s2() {
        // Documents the S2 limitation the CLI works around by slurping:
        // a token split across two pushes is NOT detected (S3 fixes this
        // with bounded carry-over).
        let engine = test_engine();
        let mut session = engine.session();
        let mut output = Vec::new();
        session.push(b"npm_AbCdEfGhIjKlMn", &mut output).unwrap();
        session
            .push(b"OpQrStUvWxYz0123456789", &mut output)
            .unwrap();
        let stats = session.finish(&mut output).unwrap();
        assert_eq!(output, b"npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789");
        assert_eq!(stats.total_matches(), 0);
    }

    #[test]
    fn same_secret_same_digest_across_pushes() {
        let engine = test_engine();
        let token = b"glpat-abcdefghij0123456789";
        let (out_a, _) = push_all(&engine, token);
        let (out_b, _) = push_all(&engine, token);
        assert_eq!(out_a, out_b, "same secret + same key must correlate");
    }
}
