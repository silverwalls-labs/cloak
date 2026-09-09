mod confirm;
mod overlap;
pub(crate) mod pem;
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
    /// Anchor prefilter over all rules + PEM (docs/01, "Matching pipeline").
    scanner: AhoCorasickScanner,
    /// Per-rule confirmers, in catalog order (index == `Candidate::rule`).
    rules: Vec<CompiledRule>,
    /// Pseudo-rule index for PEM candidates in the prefilter. Candidates
    /// with `rule == pem_rule_idx` are routed to the PEM state machine
    /// instead of the regular confirm step.
    pem_rule_idx: usize,
    /// Maximum match window `W` across all compiled rules. Bounds the
    /// carry-over retained between pushes (S3): after every push,
    /// `carry_over.len() <= max_window`.
    max_window: usize,
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
        let rules: Vec<CompiledRule> = rules::CATALOG
            .iter()
            .map(confirm::compile_rule)
            .collect::<Result<_, _>>()?;

        // PEM anchor gets a pseudo-rule index outside the catalog range.
        let pem_rule_idx = rules.len();
        let pem_extra: &[(&[u8], usize)] = &[(pem::PEM_ANCHOR, pem_rule_idx)];
        let scanner = AhoCorasickScanner::new(rules::CATALOG, pem_extra)?;

        let max_window = rules.iter().map(|r| r.window).max().unwrap_or(0);

        Ok(Self {
            digest_key,
            scanner,
            rules,
            pem_rule_idx,
            max_window,
            _config: config.clone(),
        })
    }

    /// Create a new per-stream session.
    pub fn session(&self) -> Session<'_> {
        Session {
            engine: self,
            bytes_processed: 0,
            matches: BTreeMap::new(),
            carry_over: Vec::new(),
            pem_state: pem::PemState::Idle,
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
/// that created it. The carry-over buffer's correctness depends on push/finish
/// being called from the same thread that created the session. Revisit for
/// v0.2 bindings if cross-thread move semantics are needed
/// (`docs/06-embedding.md`).
pub struct Session<'e> {
    engine: &'e Engine,
    bytes_processed: u64,
    /// Per-rule match counts, accumulated across pushes.
    matches: BTreeMap<crate::types::RuleId, u64>,
    /// Trailing bytes from the previous push that could not yet be flushed.
    carry_over: Vec<u8>,
    /// PEM private-key detector state (separate layer from windowed rules).
    pem_state: pem::PemState,
    // Scratch buffers reused across pushes (cleared each call).
    candidates: Vec<Candidate>,
    raw: Vec<RawMatch>,
    merged: Vec<MergedMatch>,
    /// Opt out of auto-Send/Sync.
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
    /// The engine retains trailing bytes (the carry-over) that might be part
    /// of a match straddling the chunk boundary — never more than the
    /// engine's max match window. Only bytes provably match-free are
    /// flushed to `out`. A PEM private-key block whose END marker has not
    /// arrived yet is hashed incrementally by the PEM state machine instead
    /// of being retained. Call [`finish`](Self::finish) to flush remaining
    /// carry-over and obtain per-rule statistics.
    pub fn push(&mut self, chunk: &[u8], out: &mut impl io::Write) -> io::Result<()> {
        self.bytes_processed += chunk.len() as u64;

        if self.pem_state.is_in_block() {
            // Inside a PEM block: body bytes go straight to the incremental
            // state machine. On close, unread bytes land in carry_over.
            self.feed_pem(chunk, out)?;
        } else {
            self.carry_over.extend_from_slice(chunk);
        }

        // Scan until no new streaming PEM entry appears. Each entry hands
        // the retained body to the state machine; a close (END or bail-out)
        // puts unread bytes back into carry_over for the next iteration.
        // Iterative, not recursive: a single large push can contain many
        // oversized blocks.
        while !self.pem_state.is_in_block() && !self.carry_over.is_empty() {
            match self.scan_and_emit(false, out)? {
                None => break,
                Some((_, key_type_idx)) => {
                    // scan_and_emit emitted through the BEGIN line and
                    // drained carry_over to exactly the body so far.
                    let body = std::mem::take(&mut self.carry_over);
                    self.pem_state = pem::PemState::InBlock(Box::new(pem::PemBlockData {
                        hasher: blake3::Hasher::new_keyed(&self.engine.digest_key),
                        body_bytes: 0,
                        end_marker: pem::end_marker_for(key_type_idx),
                        pem_carry: Vec::new(),
                    }));
                    self.feed_pem(&body, out)?;
                }
            }
        }
        Ok(())
    }

    /// Flush carry-over, close open states, return per-rule statistics.
    ///
    /// Consumes the session — no further pushes are possible after this call.
    pub fn finish(mut self, out: &mut impl io::Write) -> io::Result<Stats> {
        // An open PEM block at stream end: write the tag for whatever body
        // was accumulated (truncated-bail-out semantics, matching the
        // whole-buffer path). carry_over is empty while InBlock — the body
        // was consumed by the state machine — so the final scan below
        // cannot double-process the block.
        if self.pem_state.is_in_block() {
            pem::finish_pem(&mut self.pem_state, out)?;
            *self
                .matches
                .entry(crate::types::RuleId::new(pem::PEM_RULE_ID))
                .or_insert(0) += 1;
        }

        let entry = self.scan_and_emit(true, out)?;
        debug_assert!(entry.is_none(), "final flush never enters streaming PEM");
        debug_assert!(self.carry_over.is_empty(), "finish must drain carry-over");
        Ok(Stats {
            bytes_processed: self.bytes_processed,
            matches: self.matches,
        })
    }

    /// Feed data to the incremental PEM state machine (requires `InBlock`).
    /// On close (END found or bail-out), bytes past the redacted body are
    /// put back into carry_over for normal scanning.
    fn feed_pem(&mut self, data: &[u8], out: &mut impl io::Write) -> io::Result<()> {
        match pem::process_pem_body(&mut self.pem_state, data, out)? {
            pem::PemBodyResult::Continuing => {}
            pem::PemBodyResult::Closed { remainder_start } => {
                *self
                    .matches
                    .entry(crate::types::RuleId::new(pem::PEM_RULE_ID))
                    .or_insert(0) += 1;
                if remainder_start < data.len() {
                    self.carry_over.extend_from_slice(&data[remainder_start..]);
                }
            }
            pem::PemBodyResult::BailedOut { remainder } => {
                *self
                    .matches
                    .entry(crate::types::RuleId::new(pem::PEM_RULE_ID))
                    .or_insert(0) += 1;
                self.carry_over.extend_from_slice(&remainder);
            }
        }
        Ok(())
    }

    /// The shared scan→confirm→merge→emit pipeline used by both `push` and
    /// `finish`. When `is_final` is true every byte is flushed (no carry-over
    /// retained); otherwise only the provably match-free prefix is emitted.
    ///
    /// Returns `Some((body_start, key_type_idx))` when a private-key BEGIN is
    /// confirmed whose END marker is not yet in the buffer (streaming,
    /// non-final only): the BEGIN line has been emitted, carry_over has been
    /// drained to exactly the body so far, and the caller must enter the PEM
    /// state machine with those bytes.
    fn scan_and_emit(
        &mut self,
        is_final: bool,
        out: &mut impl io::Write,
    ) -> io::Result<Option<(usize, usize)>> {
        let combined_len = self.carry_over.len();
        if combined_len == 0 {
            return Ok(None);
        }

        // 1. Prefilter — find all anchor candidates in the combined buffer.
        self.candidates.clear();
        self.engine
            .scanner
            .scan(&self.carry_over, &mut self.candidates);

        // 2. Find complete PEM blocks in the buffer (BEGIN + END both present).
        //    Their body spans are added to the regular match pipeline so that
        //    overlap merge handles PEM and regular matches uniformly — matching
        //    the reference oracle's behavior. A confirmed BEGIN without END
        //    (streaming, non-final) becomes the returned entry instead.
        self.raw.clear();
        let pem_window = pem::pem_confirm_window();
        let mut pem_body_regions: Vec<(usize, usize)> = Vec::new();
        // PEM anchor→match extents [anchor_start, match_end) — carry_start
        // must not split these: a PEM match starts at the body, not at the
        // anchor, so retaining from the match start would lose the anchor.
        // Ending at match_end (not the END line) bounds the hold by
        // PEM_BAIL_OUT even for oversized bodies.
        let mut pem_block_extents: Vec<(usize, usize)> = Vec::new();
        let mut pem_entry: Option<(usize, usize)> = None;

        {
            let mut pem_scan_pos = 0;
            for cand in &self.candidates {
                if cand.rule != self.engine.pem_rule_idx {
                    continue;
                }
                if cand.start < pem_scan_pos {
                    continue;
                }
                let resolvable = is_final || cand.start + pem_window <= combined_len;
                if !resolvable {
                    continue;
                }
                if let Some(pm) = pem::confirm_pem_begin(&self.carry_over, cand.start) {
                    let body_start = pm.begin_line_end;
                    let end_marker = pem::end_marker_for(pm.key_type_idx);
                    if let Some(end_offset) = self.carry_over[body_start..]
                        .windows(end_marker.len())
                        .position(|w| w == end_marker.as_slice())
                    {
                        let body_end = body_start + end_offset;
                        let body_len = body_end - body_start;
                        // Bail-out truncation: redact at most PEM_BAIL_OUT
                        // bytes of the body. Everything past the truncation
                        // point is clean text — regular rules and nested
                        // BEGINs apply from there, matching the oracle's
                        // `pos = bail_end` resumption.
                        let match_end = (body_start + pem::PEM_BAIL_OUT).min(body_end);
                        self.raw.push(RawMatch {
                            start: body_start,
                            end: match_end,
                            rule: self.engine.pem_rule_idx,
                        });
                        pem_body_regions.push((body_start, match_end));
                        pem_block_extents.push((cand.start, match_end));
                        // Resume PEM scanning past the END line for full
                        // blocks, at the truncation point for oversized
                        // bodies (the tail is re-scanned).
                        pem_scan_pos = if body_len <= pem::PEM_BAIL_OUT {
                            body_end + end_marker.len()
                        } else {
                            match_end
                        };
                    } else if is_final {
                        // No END in buffer and this is the final flush —
                        // bail-out: redact the body from body_start to the
                        // end of input (or PEM_BAIL_OUT, whichever is less).
                        let bail_end = (body_start + pem::PEM_BAIL_OUT).min(combined_len);
                        self.raw.push(RawMatch {
                            start: body_start,
                            end: bail_end,
                            rule: self.engine.pem_rule_idx,
                        });
                        pem_body_regions.push((body_start, bail_end));
                        pem_block_extents.push((cand.start, bail_end));
                        pem_scan_pos = bail_end;
                    } else {
                        // Streaming: BEGIN confirmed, END not yet seen.
                        // Emit the BEGIN line and hand the body to the
                        // caller for the incremental PEM state machine.
                        pem_entry = Some((body_start, pm.key_type_idx));
                        break;
                    }
                }
            }
        }

        // 3. Confirm resolvable REGULAR candidates, skipping PEM body regions
        //    and the body of a streaming entry (it is hashed, not scanned).
        for cand in &self.candidates {
            if cand.rule == self.engine.pem_rule_idx {
                continue;
            }
            if let Some((body_start, _)) = pem_entry
                && cand.start >= body_start
            {
                continue;
            }
            // Skip candidates whose START is inside a PEM body region.
            if pem_body_regions
                .iter()
                .any(|&(bs, be)| cand.start >= bs && cand.start < be)
            {
                continue;
            }
            let rule = &self.engine.rules[cand.rule];
            let resolvable = is_final || cand.start + rule.window <= combined_len;
            if resolvable && let Some(end) = confirm::confirm(rule, &self.carry_over, cand.start) {
                self.raw.push(RawMatch {
                    start: cand.start,
                    end,
                    rule: cand.rule,
                });
            }
        }

        // 4. Overlap resolution: strict-overlap union, longest-leftmost wins.
        //    PEM body spans participate in the merge alongside regular matches.
        self.merged.clear();
        overlap::merge(&mut self.raw, &mut self.merged);

        // 5. Compute the emission boundary — the point up to which confirmed
        //    matches are provably complete. Conservative: the last max_window
        //    bytes may still hide candidates whose windows are incomplete.
        let mut emit_start = if is_final {
            combined_len
        } else {
            combined_len.saturating_sub(self.engine.max_window)
        };

        // Ensure emit_start doesn't split a complete PEM block: the anchor
        // must stay in the carry so the block can be re-confirmed next push.
        // If emit_start falls inside a block extent, pull it back to the
        // block's anchor.
        for &(block_start, block_end) in &pem_block_extents {
            if emit_start > block_start && emit_start < block_end {
                emit_start = block_start;
            }
        }

        // Adjust emit_start so no confirmed match spans the boundary: a
        // straddling match is retained and re-confirmed next push, by which
        // time any overlapping candidates (possibly not yet resolvable now)
        // will have been confirmed too.
        if !is_final {
            for m in self.merged.iter().rev() {
                if m.start >= emit_start {
                    continue;
                }
                if m.end > emit_start {
                    emit_start = m.start;
                } else {
                    break;
                }
            }
        }

        // 6. Decide the flush point. A streaming PEM entry flushes through
        //    the BEGIN line, so every candidate before it must be
        //    resolvable NOW — an unresolvable candidate's bytes would be
        //    flushed as clean text and its match lost. Conversely, when all
        //    candidates before body_start are resolvable, every match
        //    before body_start is final (its overlapping candidates have
        //    been confirmed or rejected) and is emitted here. Otherwise the
        //    entry is deferred and re-attempted next push.
        let mut entry = None;
        let carry_start = match pem_entry {
            Some((body_start, key_type_idx)) => {
                let blocked = self.candidates.iter().any(|c| {
                    if c.start >= body_start {
                        return false;
                    }
                    let window = if c.rule == self.engine.pem_rule_idx {
                        pem_window
                    } else {
                        self.engine.rules[c.rule].window
                    };
                    c.start + window > combined_len
                });
                if blocked {
                    emit_start
                } else {
                    entry = Some((body_start, key_type_idx));
                    body_start
                }
            }
            None => emit_start,
        };

        // 7. Emit matches (regular + PEM body spans) and clean gaps.
        let mut pos = 0;
        for m in &self.merged {
            if m.start >= carry_start {
                // Final flush emits a zero-length PEM span that starts
                // exactly at EOF (BEGIN line with no body); non-final defers
                // everything from carry_start onward.
                if !(is_final && m.start == carry_start && m.end == carry_start) {
                    break;
                }
            }
            out.write_all(&self.carry_over[pos..m.start])?;
            if m.rule == self.engine.pem_rule_idx {
                let rule_id = crate::types::RuleId::new(pem::PEM_RULE_ID);
                let digest = crate::redact::compute_digest(
                    &self.carry_over[m.start..m.end],
                    &self.engine.digest_key,
                );
                crate::redact::write_tag(&rule_id, &digest, out)?;
                *self.matches.entry(rule_id).or_insert(0) += 1;
            } else {
                let rule_id = &self.engine.rules[m.rule].id;
                let digest = crate::redact::compute_digest(
                    &self.carry_over[m.start..m.end],
                    &self.engine.digest_key,
                );
                crate::redact::write_tag(rule_id, &digest, out)?;
                *self.matches.entry(rule_id.clone()).or_insert(0) += 1;
            }
            pos = m.end;
        }

        // 8. Flush clean bytes up to carry_start, retain the rest.
        if pos < carry_start {
            out.write_all(&self.carry_over[pos..carry_start])?;
        }
        self.carry_over.drain(..carry_start);

        Ok(entry)
    }

    /// Return the current carry-over length (test-support only).
    #[doc(hidden)]
    pub fn carry_over_len(&self) -> usize {
        self.carry_over.len()
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
    fn engine_max_window() {
        // Pinned to docs/02-rules.md spec. W_max = github-token (11 + 255 = 266).
        // This is also the hard bound on carry-over after every push.
        let engine = test_engine();
        assert_eq!(engine.max_window, 266);
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
        // Carry-over withholds trailing bytes; finish flushes them.
        session.finish(&mut output).unwrap();
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
    fn split_token_detected_with_carry_over() {
        // S3 fix: a token split across two pushes IS detected thanks to
        // bounded carry-over (previously the S2 limitation).
        let engine = test_engine();
        let token = b"npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
        let mut session = engine.session();
        let mut output = Vec::new();
        session.push(b"npm_AbCdEfGhIjKlMn", &mut output).unwrap();
        session
            .push(b"OpQrStUvWxYz0123456789", &mut output)
            .unwrap();
        let stats = session.finish(&mut output).unwrap();
        let digest = crate::redact::compute_digest(token, &engine.digest_key);
        let tag = crate::redact::format_tag(&RuleId::new("npm-token"), &digest);
        assert_eq!(output, tag.as_bytes());
        assert_eq!(stats.total_matches(), 1);
    }

    #[test]
    fn same_secret_same_digest_across_pushes() {
        let engine = test_engine();
        let token = b"glpat-abcdefghij0123456789";
        let (out_a, _) = push_all(&engine, token);
        let (out_b, _) = push_all(&engine, token);
        assert_eq!(out_a, out_b, "same secret + same key must correlate");
    }

    #[test]
    fn one_byte_pushes_detect_token() {
        let engine = test_engine();
        let token = b"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
        let mut input = b"x ".to_vec();
        input.extend_from_slice(token);
        input.extend_from_slice(b" y");

        // Push one byte at a time.
        let mut session = engine.session();
        let mut output = Vec::new();
        for &byte in &input {
            session.push(&[byte], &mut output).unwrap();
        }
        let stats = session.finish(&mut output).unwrap();

        // Must match the whole-buffer result.
        let (expected, _) = push_all(&engine, &input);
        assert_eq!(output, expected);
        assert_eq!(stats.matches[&RuleId::new("github-token")], 1);
    }

    #[test]
    fn carry_over_conservative_flush() {
        // Conservative carry-over: always retain max_window bytes.
        let engine = test_engine();
        let mut session = engine.session();
        let mut output = Vec::new();
        let data = vec![b'x'; 500];
        session.push(&data, &mut output).unwrap();

        assert_eq!(session.carry_over_len(), engine.max_window);
        assert_eq!(output.len(), 500 - engine.max_window);

        session.finish(&mut output).unwrap();
        assert_eq!(output, data);
    }

    #[test]
    fn empty_push_is_noop() {
        let engine = test_engine();
        let mut session = engine.session();
        let mut output = Vec::new();
        session.push(b"", &mut output).unwrap();
        assert!(output.is_empty());
        assert_eq!(session.carry_over_len(), 0);
    }

    #[test]
    fn finish_flushes_trailing_carry_over() {
        let engine = test_engine();
        let mut session = engine.session();
        let mut output = Vec::new();
        session.push(b"hello", &mut output).unwrap();
        // "hello" is 5 bytes, all below max_anchor_len (11), so all is
        // carried over and nothing is emitted yet.
        assert!(output.is_empty());
        assert_eq!(session.carry_over_len(), 5);
        let stats = session.finish(&mut output).unwrap();
        assert_eq!(output, b"hello");
        assert_eq!(stats.bytes_processed, 5);
    }

    #[test]
    fn carry_over_bounded_by_max_window() {
        // An unresolvable candidate near the buffer end (the "npm_" anchor
        // whose window extends past the last byte) must be retained for the
        // next push. The conservative flush keeps the last max_window bytes,
        // so the carry can reach max_window but never exceed it.
        let engine = test_engine();
        let mut session = engine.session();
        let mut output = Vec::new();
        let mut input = vec![b'x'; 500];
        input.extend_from_slice(b"npm_");
        session.push(&input, &mut output).unwrap();
        assert!(session.carry_over_len() <= engine.max_window);
        // The retained bytes include the anchor: completing the token in
        // the next push must produce a match.
        session
            .push(b"AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", &mut output)
            .unwrap();
        let stats = session.finish(&mut output).unwrap();
        assert_eq!(stats.matches[&RuleId::new("npm-token")], 1);
    }

    #[test]
    fn unterminated_pem_begin_carry_stays_bounded() {
        // H2 regression: a confirmed PEM BEGIN whose END never arrives must
        // not accumulate the stream in carry-over. The body is hashed
        // incrementally by the PEM state machine; carry stays at 0 while
        // InBlock and <= max_window otherwise. Output must be identical to
        // the whole-buffer path (bail-out at 16 KiB).
        let engine = test_engine();
        let mut input = b"-----BEGIN RSA PRIVATE KEY-----\n".to_vec();
        input.extend_from_slice(&vec![b'A'; 40 * 64 * 1024]);
        let (whole, whole_stats) = push_all(&engine, &input);
        assert_eq!(whole_stats.matches[&RuleId::new("pem-private-key")], 1);

        let mut session = engine.session();
        let mut output = Vec::new();
        for chunk in input.chunks(64 * 1024) {
            session.push(chunk, &mut output).unwrap();
            assert!(
                session.carry_over_len() <= engine.max_window,
                "carry-over must stay bounded while a PEM block is open"
            );
        }
        let stats = session.finish(&mut output).unwrap();
        assert_eq!(output, whole, "chunked must equal whole-buffer");
        assert_eq!(stats.matches, whole_stats.matches);
        assert!(String::from_utf8_lossy(&output).contains("[CLOAK:pem-private-key:"));
    }

    #[test]
    fn oversized_pem_streaming_equals_whole_buffer() {
        // M4 regression: a body larger than PEM_BAIL_OUT must produce
        // byte-identical output (including the truncated-bail-out digest)
        // whether it arrives in one push or many.
        let engine = test_engine();
        let mut input = b"-----BEGIN RSA PRIVATE KEY-----\n".to_vec();
        input.extend_from_slice(&vec![b'A'; pem::PEM_BAIL_OUT + 2000]);
        input.extend_from_slice(b"\n-----END RSA PRIVATE KEY-----\ntail");
        let (whole, whole_stats) = push_all(&engine, &input);
        for chunk_size in [1, 7, 100, 4096, 16385] {
            let mut session = engine.session();
            let mut out = Vec::new();
            for chunk in input.chunks(chunk_size) {
                session.push(chunk, &mut out).unwrap();
            }
            let stats = session.finish(&mut out).unwrap();
            assert_eq!(
                out, whole,
                "chunk-size={chunk_size} streaming diverges from whole-buffer"
            );
            assert_eq!(
                stats.matches, whole_stats.matches,
                "stats diverge at {chunk_size}"
            );
        }
    }

    #[test]
    fn finish_with_open_pem_block_emits_single_tag() {
        // M3 regression: an open block at stream end produces exactly one
        // tag and one match count — identical to the whole-buffer path.
        let engine = test_engine();
        let input = b"-----BEGIN EC PRIVATE KEY-----\nPARTIALBODYDATA";
        let (whole, whole_stats) = push_all(&engine, input);
        assert_eq!(whole_stats.matches[&RuleId::new("pem-private-key")], 1);

        let mut session = engine.session();
        let mut out = Vec::new();
        for chunk in input.chunks(3) {
            session.push(chunk, &mut out).unwrap();
        }
        let stats = session.finish(&mut out).unwrap();
        assert_eq!(out, whole, "chunked open-block finish diverges");
        assert_eq!(stats.matches, whole_stats.matches);
        assert_eq!(
            String::from_utf8_lossy(&out)
                .matches("[CLOAK:pem-private-key:")
                .count(),
            1,
            "exactly one tag expected"
        );
        assert!(
            &out.windows(15).all(|w| w != b"PARTIALBODYDATA"),
            "body must not leak"
        );
    }

    #[test]
    fn multiple_oversized_blocks_in_one_push() {
        // The push loop is iterative: several unterminated oversized blocks
        // in a single push each bail out independently.
        let engine = test_engine();
        let mut input = b"-----BEGIN RSA PRIVATE KEY-----\n".to_vec();
        input.extend_from_slice(&vec![b'A'; pem::PEM_BAIL_OUT + 100]);
        input.extend_from_slice(b"\n-----BEGIN EC PRIVATE KEY-----\n");
        input.extend_from_slice(&vec![b'B'; pem::PEM_BAIL_OUT + 100]);
        let mut session = engine.session();
        let mut out = Vec::new();
        session.push(&input, &mut out).unwrap();
        assert!(
            session.carry_over_len() <= engine.max_window,
            "carry must stay bounded after bail-outs"
        );
        let stats = session.finish(&mut out).unwrap();
        assert_eq!(stats.matches[&RuleId::new("pem-private-key")], 2);
        assert_eq!(
            String::from_utf8_lossy(&out)
                .matches("[CLOAK:pem-private-key:")
                .count(),
            2
        );
        // Both BEGIN lines stay visible (the second one arrives in the
        // bail-out remainder of the first block).
        assert!(out.starts_with(b"-----BEGIN RSA PRIVATE KEY-----"));
        assert!(
            out.windows(30)
                .any(|w| w == b"-----BEGIN EC PRIVATE KEY-----")
        );
    }

    #[test]
    fn streaming_equals_whole_buffer_on_vectors() {
        // For every vector, 1-byte-at-a-time push must produce identical
        // output to a single whole-buffer push.
        let engine = test_engine();
        for v in crate::rules::vectors::all_vectors() {
            let (whole, whole_stats) = push_all(&engine, v.input);

            let mut session = engine.session();
            let mut chunked = Vec::new();
            for &byte in v.input {
                session.push(&[byte], &mut chunked).unwrap();
            }
            let chunked_stats = session.finish(&mut chunked).unwrap();

            assert_eq!(
                chunked, whole,
                "streaming ≢ whole-buffer on vector '{}'",
                v.name
            );
            assert_eq!(
                chunked_stats.matches, whole_stats.matches,
                "stats diverge on vector '{}'",
                v.name
            );
        }
    }

    // ---------------------------------------------------------------
    // PEM through the full Engine API
    // ---------------------------------------------------------------

    #[test]
    fn pem_rsa_single_push() {
        // Dedicated PEM-through-engine test: markers stay visible, body
        // replaced by tag.
        let engine = test_engine();
        let input = b"-----BEGIN RSA PRIVATE KEY-----\nBODY\n-----END RSA PRIVATE KEY-----";
        let (output, stats) = push_all(&engine, input);
        let out_str = String::from_utf8_lossy(&output);

        // BEGIN and END markers visible.
        assert!(
            out_str.starts_with("-----BEGIN RSA PRIVATE KEY-----"),
            "BEGIN marker must be visible: {out_str}"
        );
        assert!(
            out_str.ends_with("-----END RSA PRIVATE KEY-----"),
            "END marker must be visible: {out_str}"
        );
        // Body replaced by a CLOAK tag.
        assert!(
            out_str.contains("[CLOAK:pem-private-key:"),
            "body must be redacted: {out_str}"
        );
        // No raw body leaked.
        assert!(
            !out_str.contains("BODY"),
            "raw body must not appear: {out_str}"
        );
        assert_eq!(stats.matches[&RuleId::new("pem-private-key")], 1);
    }

    #[test]
    fn pem_empty_body() {
        // BEGIN immediately followed by END — zero body bytes.
        let engine = test_engine();
        let input = b"-----BEGIN RSA PRIVATE KEY----------END RSA PRIVATE KEY-----";
        let (output, stats) = push_all(&engine, input);
        let out_str = String::from_utf8_lossy(&output);
        assert!(
            out_str.contains("[CLOAK:pem-private-key:"),
            "empty-body PEM must produce a tag: {out_str}"
        );
        assert_eq!(stats.matches[&RuleId::new("pem-private-key")], 1);
    }

    #[test]
    fn pem_token_inside_body_suppressed() {
        // A github token inside a PEM body must NOT be detected — the PEM
        // body is atomic (no regular rules run inside it).
        let engine = test_engine();
        let mut input = b"-----BEGIN RSA PRIVATE KEY-----\n".to_vec();
        input.extend_from_slice(b"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789\n");
        input.extend_from_slice(b"-----END RSA PRIVATE KEY-----");

        let (output, stats) = push_all(&engine, &input);
        let out_str = String::from_utf8_lossy(&output);

        // PEM detected.
        assert!(out_str.contains("[CLOAK:pem-private-key:"));
        assert_eq!(stats.matches[&RuleId::new("pem-private-key")], 1);
        // The github token inside the PEM body must NOT be matched.
        assert!(
            !stats.matches.contains_key(&RuleId::new("github-token")),
            "token inside PEM body must be suppressed"
        );
        // The raw token bytes must not appear in output.
        assert!(
            !out_str.contains("ghp_"),
            "token bytes must be redacted as part of PEM body"
        );
    }

    #[test]
    fn pem_multiple_blocks_in_one_push() {
        // Two PEM blocks back-to-back in a single push — both must be
        // detected independently.
        let engine = test_engine();
        let mut input = b"-----BEGIN RSA PRIVATE KEY-----\nRSABODY\n".to_vec();
        input.extend_from_slice(b"-----END RSA PRIVATE KEY-----\n");
        input.extend_from_slice(b"-----BEGIN EC PRIVATE KEY-----\nECBODY\n");
        input.extend_from_slice(b"-----END EC PRIVATE KEY-----");

        let (output, stats) = push_all(&engine, &input);
        let out_str = String::from_utf8_lossy(&output);

        assert_eq!(
            stats.matches[&RuleId::new("pem-private-key")],
            2,
            "both PEM blocks must be detected"
        );
        // Both BEGIN/END pairs visible.
        assert!(out_str.contains("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(out_str.contains("-----END RSA PRIVATE KEY-----"));
        assert!(out_str.contains("-----BEGIN EC PRIVATE KEY-----"));
        assert!(out_str.contains("-----END EC PRIVATE KEY-----"));
        // Neither raw body leaked.
        assert!(!out_str.contains("RSABODY"));
        assert!(!out_str.contains("ECBODY"));
    }

    #[test]
    fn pem_at_stream_end_no_end_marker() {
        // PEM BEGIN + body, but no END marker. On finish(), the engine
        // should treat this as a bail-out / truncated PEM and NOT leak
        // the body.
        let engine = test_engine();
        let input = b"-----BEGIN RSA PRIVATE KEY-----\nSECRETKEYDATA";

        let (output, stats) = push_all(&engine, input);
        let out_str = String::from_utf8_lossy(&output);

        // The body must not leak in raw form.
        assert!(
            !out_str.contains("SECRETKEYDATA"),
            "PEM body must not leak when END is missing: {out_str}"
        );
        // A PEM tag must be emitted (bail-out behavior).
        assert!(
            out_str.contains("[CLOAK:pem-private-key:"),
            "bail-out must produce a tag: {out_str}"
        );
        assert_eq!(stats.matches[&RuleId::new("pem-private-key")], 1);
    }

    #[test]
    fn pem_large_block_exceeding_max_window() {
        // A PEM block whose total size exceeds max_window (266), forcing
        // the carry-over to grow. The block must still be detected when
        // pushed in small chunks.
        let engine = test_engine();
        let body = vec![b'A'; 300]; // 300-byte body > max_window
        let mut input = b"-----BEGIN RSA PRIVATE KEY-----\n".to_vec();
        input.extend_from_slice(&body);
        input.push(b'\n');
        input.extend_from_slice(b"-----END RSA PRIVATE KEY-----");

        // Whole-buffer.
        let (whole, whole_stats) = push_all(&engine, &input);
        assert_eq!(whole_stats.matches[&RuleId::new("pem-private-key")], 1);

        // Small chunks (7 bytes).
        let mut session = engine.session();
        let mut chunked = Vec::new();
        for chunk in input.chunks(7) {
            session.push(chunk, &mut chunked).unwrap();
        }
        session.finish(&mut chunked).unwrap();

        assert_eq!(
            chunked, whole,
            "large PEM block: chunked must equal whole-buffer"
        );
    }

    #[test]
    fn pem_greedy_body_overlaps_begin_anchor() {
        // A gitlab-token body (charset includes '-') extends through the
        // dashes of a following PEM BEGIN marker. Both the gitlab match
        // and the PEM body must be detected.
        let engine = test_engine();
        let mut input = b"glpat-abcdefghij0123456789".to_vec(); // 26 bytes, valid gitlab
        input.extend_from_slice(
            b"-----BEGIN RSA PRIVATE KEY-----\nPEMBODY\n-----END RSA PRIVATE KEY-----",
        );

        let (output, stats) = push_all(&engine, &input);
        let out_str = String::from_utf8_lossy(&output);

        // Gitlab token detected (its body extends into the dashes but
        // stops at the space in "-----BEGIN ").
        assert!(
            stats.matches.contains_key(&RuleId::new("gitlab-token")),
            "gitlab match must be detected: {out_str}"
        );
        // PEM body detected.
        assert!(
            stats.matches.contains_key(&RuleId::new("pem-private-key")),
            "PEM must be detected even when BEGIN dashes overlap gitlab body: {out_str}"
        );
        // PEM body must not leak.
        assert!(
            !out_str.contains("PEMBODY"),
            "PEM body must be redacted: {out_str}"
        );
    }
}
