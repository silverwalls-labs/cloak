pub(crate) mod confirm;
mod overlap;
pub(crate) mod pem;
// `pub` (doc-hidden via lib.rs) so criterion benches can access both scanners
// for the receipts protocol (docs/04-performance.md).
pub mod scanner;

use std::collections::BTreeMap;
use std::io;
use std::marker::PhantomData;

use crate::config::{self, Config};
use crate::rules;
use crate::rules::validators::CLOAK_TAG_MAX;
use crate::types::Stats;
use confirm::CompiledRule;
use overlap::{MergedMatch, RawMatch};
use scanner::{AhoCorasickScanner, Candidate, Scanner};

/// Error constructing an [`Engine`].
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// The configuration failed semantic validation (unknown rule id,
    /// malformed digest key reference, …).
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// The OS entropy source failed while generating an ephemeral key.
    #[error("failed to obtain entropy for digest key: {0}")]
    Entropy(#[from] config::DigestKeyError),

    /// The anchor-prefilter automaton failed to build (duplicate or
    /// otherwise invalid anchor set).
    #[error("failed to build anchor prefilter automaton: {0}")]
    Prefilter(#[from] aho_corasick::BuildError),

    /// The confirm DFA for `rule` failed to compile.
    #[error("failed to compile confirm pattern for rule `{rule}`")]
    Confirm {
        /// The rule whose pattern failed to compile.
        rule: crate::types::RuleId,
        // Boxed: dense::BuildError is ~152 bytes and would dominate the
        // size of every Result<_, BuildError> (clippy::result_large_err).
        #[source]
        /// The underlying DFA build failure.
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
    /// Per-rule confirmers, in filtered catalog order
    /// (index == `Candidate::rule`). Only enabled rules are present.
    rules: Vec<CompiledRule>,
    /// Pseudo-rule index for PEM candidates in the prefilter. Candidates
    /// with `rule == pem_rule_idx` are routed to the PEM state machine
    /// instead of the regular confirm step.
    pem_rule_idx: usize,
    /// Maximum of `window + back` across all compiled rules. Bounds the
    /// carry-over retained between pushes (S3): after every push,
    /// `carry_over.len() <= max_window`. The retention includes each
    /// rule's backward reach `back` so a candidate's backward confirm
    /// context is never truncated by a flush before the candidate
    /// resolves (#27).
    max_window: usize,
    _config: Config,
}

impl Engine {
    /// Build an engine from the given configuration.
    ///
    /// Compiles the built-in catalog: one prefilter automaton over all
    /// enabled rules' anchors plus one anchored confirm DFA per rule.
    /// Rules disabled via `config.rules` are excluded from the prefilter
    /// and confirm compilation. PEM is gated separately.
    ///
    /// ```
    /// use cloak_core::{Config, Engine};
    ///
    /// let engine = Engine::new(&Config::ephemeral())?;
    /// # Ok::<(), cloak_core::BuildError>(())
    /// ```
    pub fn new(config: &Config) -> Result<Self, BuildError> {
        config.validate()?;
        let digest_key = config::resolve_digest_key(config.digest_key_env_var())?;

        // Filter catalog: a rule is enabled unless explicitly disabled.
        let enabled_specs: Vec<&rules::RuleSpec> = rules::CATALOG
            .iter()
            .filter(|spec| config.is_rule_enabled(spec.id))
            .collect();

        let rules: Vec<CompiledRule> = enabled_specs
            .iter()
            .map(|spec| confirm::compile_rule(spec))
            .collect::<Result<_, _>>()?;

        // PEM: enabled unless explicitly disabled.
        let pem_enabled = config.is_rule_enabled(pem::PEM_RULE_ID);
        let pem_rule_idx = rules.len();
        let pem_extra: Vec<(&[u8], usize)> = if pem_enabled {
            vec![(pem::PEM_ANCHOR, pem_rule_idx)]
        } else {
            vec![]
        };
        let scanner = AhoCorasickScanner::new(&enabled_specs, &pem_extra)?;

        // Retention is window + back: the forward window a candidate needs
        // to resolve, plus the backward context its confirm step reads
        // (#27). Without `back`, the flush could cross the backward
        // window of an unresolved candidate and change its match.
        let mut max_window = rules.iter().map(|r| r.window + r.back).max().unwrap_or(0);
        // PEM's confirm window must be included when PEM is enabled —
        // otherwise carry-over drops to 0 when all regular rules are
        // disabled, and a PEM BEGIN anchor split across chunks is flushed
        // before the scanner can match it.
        if pem_enabled {
            max_window = max_window.max(pem::pem_confirm_window());
        }

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
            carry_abs: 0,
            ctx_len: 0,
            retained: Vec::new(),
            pem_state: pem::PemState::Idle,
            pem_pre_block: Vec::new(),
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
    /// Absolute stream offset of `carry_over[0]` (bytes flushed so far).
    /// `carry_abs + carry_over.len()` is the absolute position of the next
    /// byte to process. Used by the #27 truncated-context guard.
    carry_abs: u64,
    /// Matches confirmed in an earlier push that could not be emitted yet
    /// (their extent straddled the emission boundary). Stored with
    /// ABSOLUTE stream offsets; re-injected into the raw match set each
    /// push until fully flushed (#27). Carrying the span — instead of
    /// re-deriving it from the candidate — is what makes the
    /// truncated-context candidate skip safe: a candidate whose backward
    /// window has been flushed past is never re-confirmed, so it can never
    /// re-confirm differently than it did with full context.
    retained: Vec<RawMatch>,
    /// Number of LEADING carry bytes that are already-emitted context
    /// retained after a PEM block close (#27): the confirm steps may scan
    /// backward into them, but they must never be re-emitted, and
    /// candidates anchored inside them are suppressed (their bytes were
    /// consumed by the PEM layer, mirroring the whole-buffer path's
    /// PEM-body candidate suppression).
    ctx_len: usize,
    /// PEM private-key detector state (separate layer from windowed rules).
    pem_state: pem::PemState,
    /// The last `CTX_BACK` bytes of the carry before a streaming PEM
    /// entry's body (pre-block text + BEGIN line), stashed when the entry
    /// is chosen and moved into `PemBlockData::pre_block` on block entry.
    /// At close/bail-out the PEM layer uses it to rebuild the
    /// emitted-stream context after the block, chunk-independently (#27).
    pem_pre_block: Vec<u8>,
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
    ///
    /// The chunk is processed internally in bounded slices, so peak memory
    /// does not grow with the chunk size — a multi-gigabyte push costs the
    /// same as a kilobyte one.
    ///
    /// Chunk boundaries never change the output — any chunking of the
    /// same bytes produces identical redacted output (docs/03):
    ///
    /// ```
    /// use cloak_core::{Config, Engine};
    ///
    /// let engine = Engine::new(&Config::ephemeral())?;
    /// let mut session = engine.session();
    /// let mut out = Vec::new();
    /// // A secret split across pushes is still caught.
    /// session.push(b"key=AKIAIOSFO", &mut out)?;
    /// session.push(b"DNN7EXAMPLE ok\n", &mut out)?;
    /// let stats = session.finish(&mut out)?;
    /// assert_eq!(stats.total_matches(), 1);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn push(&mut self, chunk: &[u8], out: &mut impl io::Write) -> io::Result<()> {
        self.bytes_processed += chunk.len() as u64;

        // F10: process the chunk in bounded slices so memory stays
        // O(max_window) no matter how much data a single push carries —
        // carry_over never grows with the chunk, and neither does the
        // unread remainder the PEM layer drops into carry_over on a
        // close. Chunk-invariance (docs/03) keeps the output identical
        // to a whole-chunk push: the slices are just a finer chunking
        // of the same stream. A slice of 2 * max_window guarantees
        // progress — once appended, the emission boundary
        // (combined_len - max_window) lies past the end of the previous
        // buffer, beyond the reach of any straddling match (all shorter
        // than max_window) or pinned PEM block.
        let slice = 2 * self.engine.max_window;
        let mut rest = chunk;
        while !rest.is_empty() {
            if self.pem_state.is_active() {
                // The PEM layer owns incoming bytes (hashing a body or
                // draining a bailed-out block): body bytes go straight
                // to the incremental state machine. On close, unread
                // bytes land in carry_over — at most one slice — and
                // the scan below drains them before the next slice is
                // fed. carry_over is empty while the PEM layer is
                // active, so by the carry_abs invariant the slice
                // starts at the absolute offset carry_abs.
                let take = rest.len().min(slice.max(1));
                let (piece, tail) = rest.split_at(take);
                let piece_abs = self.carry_abs;
                self.feed_pem(piece, piece_abs, out)?;
                rest = tail;
                // An open block (hashing or draining) consumed the
                // piece; the next one continues at its end. On close
                // or bail-out feed_pem has already set carry_abs to
                // the resume point.
                if self.pem_state.is_active() {
                    self.carry_abs = piece_abs + piece.len() as u64;
                }
            } else if slice == 0 {
                // No rules enabled: the scan flushes everything, so the
                // whole chunk can be appended at once.
                self.carry_over.extend_from_slice(rest);
                rest = &[];
            } else {
                // Append a bounded prefix. The previous scan may have
                // been unable to drain past a pinned PEM block
                // (carry_over already at or past the slice bound); a
                // full slice still moves the emission boundary past
                // the block's end.
                let take = if self.carry_over.len() < slice {
                    slice - self.carry_over.len()
                } else {
                    slice
                }
                .min(rest.len());
                let (piece, tail) = rest.split_at(take);
                self.carry_over.extend_from_slice(piece);
                rest = tail;
            }

            // Scan until no new streaming PEM entry appears. Each entry hands
            // the retained body to the state machine; a close (END or bail-out)
            // puts unread bytes back into carry_over for the next iteration.
            // Iterative, not recursive: a single large push can contain many
            // oversized blocks.
            while !self.pem_state.is_active() && !self.carry_over.is_empty() {
                match self.scan_and_emit(false, out)? {
                    None => break,
                    Some((_, key_type_idx)) => {
                        // scan_and_emit emitted through the BEGIN line and
                        // drained carry_over to exactly the body so far.
                        let body = std::mem::take(&mut self.carry_over);
                        // The body starts at the absolute offset carry_abs; the
                        // next unprocessed byte (carry is now empty) is at
                        // carry_abs + body.len().
                        let body_abs = self.carry_abs;
                        self.carry_abs += body.len() as u64;
                        self.ctx_len = 0;
                        self.pem_state = pem::PemState::InBlock(Box::new(pem::PemBlockData {
                            hasher: blake3::Hasher::new_keyed(&self.engine.digest_key),
                            body_bytes: 0,
                            end_marker: pem::end_marker_for(key_type_idx),
                            pem_carry: Vec::new(),
                            pre_block: std::mem::take(&mut self.pem_pre_block),
                        }));
                        self.feed_pem(&body, body_abs, out)?;
                    }
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
        // whole-buffer path). A draining block already wrote — and counted —
        // its tag at the bail-out point, so finish_pem reports false and
        // the suppressed tail is dropped (F05). carry_over is empty while
        // the PEM layer is active — the body was consumed by the state
        // machine — so the final scan below cannot double-process the block.
        if self.pem_state.is_active() && pem::finish_pem(&mut self.pem_state, out)? {
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

    /// Feed data to the incremental PEM state machine (requires an active
    /// PEM state). `data_abs` is the absolute stream offset of `data[0]`.
    /// On close (END found), bytes past the END line are put back into
    /// carry_over for normal scanning, preceded by the emitted-stream
    /// context returned by the PEM layer (pre-block tail + BEGIN line +
    /// tag + END marker, truncated to CTX_BACK bytes): candidates in the
    /// remainder may need backward context that the PEM layer consumed,
    /// and without it their confirm spans would diverge from the
    /// whole-buffer path (#27). The context is built from the emitted
    /// stream — not the raw body — so it is identical at every chunk size.
    /// On bail-out (F05) the tag has been written and the block entered
    /// drain mode: the whole slice is consumed (hashed or suppressed), so
    /// carry_over stays empty and carry_abs advances past the slice.
    fn feed_pem(&mut self, data: &[u8], data_abs: u64, out: &mut impl io::Write) -> io::Result<()> {
        match pem::process_pem_body(&mut self.pem_state, data, out)? {
            pem::PemBodyResult::Continuing => {}
            pem::PemBodyResult::Closed {
                remainder_start,
                ctx,
                count,
            } => {
                if count {
                    *self
                        .matches
                        .entry(crate::types::RuleId::new(pem::PEM_RULE_ID))
                        .or_insert(0) += 1;
                }
                // The PEM layer already emitted the tag and the END marker;
                // `ctx` is the matching emitted-stream context. Its bytes
                // are marked as already emitted (ctx_len): confirms may
                // scan backward into them, but they are never re-emitted
                // and candidates anchored inside them are suppressed.
                self.carry_over.extend_from_slice(&ctx);
                self.carry_over.extend_from_slice(&data[remainder_start..]);
                self.ctx_len = ctx.len();
                self.carry_abs =
                    (data_abs + remainder_start as u64).saturating_sub(ctx.len() as u64);
            }
            pem::PemBodyResult::BailedOut => {
                // F05 bail-out: the tag was written at the truncation point
                // and the block is now draining — the entire slice was
                // consumed (budget bytes hashed, the rest suppressed), so
                // carry_over stays empty and the next unprocessed byte is
                // at the end of the slice.
                *self
                    .matches
                    .entry(crate::types::RuleId::new(pem::PEM_RULE_ID))
                    .or_insert(0) += 1;
                self.carry_abs = data_abs + data.len() as u64;
                self.ctx_len = 0;
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
                // Context-prefix bytes were consumed by the PEM layer —
                // like the whole-buffer path's PEM-body regions, they are
                // not re-confirmed (#27).
                if cand.start < self.ctx_len {
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
                        let end_line_end = body_end + end_marker.len();
                        if body_len <= pem::PEM_BAIL_OUT {
                            // Full redaction: one tag covers the body; the
                            // BEGIN/END lines stay visible; scanning
                            // resumes after the END line.
                            self.raw.push(RawMatch {
                                start: body_start,
                                end: body_end,
                                redact_start: body_start,
                                redact_end: body_end,
                                rule: self.engine.pem_rule_idx,
                            });
                            pem_body_regions.push((body_start, body_end));
                            pem_block_extents.push((cand.start, body_end));
                        } else {
                            // Oversized body (F05): the tag covers exactly
                            // PEM_BAIL_OUT bytes; the tail up to the END
                            // line is part of the match EXTENT but outside
                            // the redact span — the emission suppresses it
                            // (PEM suffixes are never written). The extent
                            // ends at body_end so the END line stays
                            // visible as clean text. Scanning resumes
                            // after the END line.
                            let bail_end = body_start + pem::PEM_BAIL_OUT;
                            self.raw.push(RawMatch {
                                start: body_start,
                                end: body_end,
                                redact_start: body_start,
                                redact_end: bail_end,
                                rule: self.engine.pem_rule_idx,
                            });
                            pem_body_regions.push((body_start, body_end));
                            pem_block_extents.push((cand.start, body_end));
                        }
                        pem_scan_pos = end_line_end;
                    } else if is_final {
                        // No END in buffer and this is the final flush —
                        // bail-out: the tag covers the body from body_start
                        // to the end of input (or PEM_BAIL_OUT, whichever
                        // is less); everything past the truncation point
                        // is suppressed (F05) — the extent runs to EOF and
                        // the emission never writes the suffix.
                        let bail_end = (body_start + pem::PEM_BAIL_OUT).min(combined_len);
                        self.raw.push(RawMatch {
                            start: body_start,
                            end: combined_len,
                            redact_start: body_start,
                            redact_end: bail_end,
                            rule: self.engine.pem_rule_idx,
                        });
                        pem_body_regions.push((body_start, combined_len));
                        pem_block_extents.push((cand.start, combined_len));
                        pem_scan_pos = combined_len;
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
            // Context-prefix bytes were consumed by the PEM layer — not
            // re-confirmed (#27).
            if cand.start < self.ctx_len {
                continue;
            }
            let rule = &self.engine.rules[cand.rule];
            // #27 guard: when the carry buffer does not start at the stream
            // start and the candidate's backward window would reach before
            // it, the confirm runs against truncated backward context. The
            // backward reads are the match-start scan and the #34 tag-tail
            // guard (at most CLOAK_TAG_MAX bytes), so a confirmed match
            // starting at least CLOAK_TAG_MAX bytes into the buffer proves
            // every backward read stayed in-buffer — the outcome is
            // identical to the whole-buffer path and the match is accepted.
            // A truncated candidate whose match starts closer to the buffer
            // edge is dropped: it can only be a re-derivation of a
            // candidate resolved earlier with full context (the emission
            // boundary never crosses the backward window of an unresolved
            // candidate), and an earlier confirmation is re-injected from
            // `retained` below. Post-PEM candidates are NOT re-derivations
            // (their bytes were consumed by the PEM layer), but their
            // backward scans stop at the tag/END-marker barriers well past
            // CLOAK_TAG_MAX, so they always pass the precise check.
            let truncated = self.carry_abs > 0 && cand.start < rule.back;
            let resolvable = is_final || cand.start + rule.window <= combined_len;
            if resolvable && let Some(cm) = confirm::confirm(rule, &self.carry_over, cand.start) {
                if truncated && cm.match_start < CLOAK_TAG_MAX {
                    continue;
                }
                self.raw.push(RawMatch {
                    start: cm.match_start,
                    end: cm.match_end,
                    redact_start: cm.redact_start,
                    redact_end: cm.redact_end,
                    rule: cand.rule,
                });
            }
        }

        // 3.5 Re-inject retained matches (absolute → buffer-relative).
        //     Their spans were confirmed with full context in an earlier
        //     push; carrying them replaces re-derivation from candidates
        //     whose backward context a flush may since have crossed (#27).
        //     PEM-suppression mirrors the candidate skips above: a span
        //     that starts inside a PEM body region (or after a streaming
        //     entry's body start) is dropped, exactly as its candidate is.
        if let Some((body_start, _)) = pem_entry {
            let body_abs = self.carry_abs + body_start as u64;
            self.retained.retain(|m| (m.start as u64) < body_abs);
        }
        for &(bs, be) in &pem_body_regions {
            let bs_abs = self.carry_abs + bs as u64;
            let be_abs = self.carry_abs + be as u64;
            self.retained
                .retain(|m| !((m.start as u64) >= bs_abs && (m.start as u64) < be_abs));
        }
        let base = self.carry_abs;
        for m in &self.retained {
            let rel = RawMatch {
                start: m.start - base as usize,
                end: m.end - base as usize,
                redact_start: m.redact_start - base as usize,
                redact_end: m.redact_end - base as usize,
                rule: m.rule,
            };
            // This push may have re-derived the same span from its candidate
            // (or from the PEM block scan). Overlap merge dedups overlapping
            // spans, but IDENTICAL spans only merge under strict overlap —
            // a zero-length span (empty PEM body) does not, and would be
            // emitted (and counted) twice. Skip exact re-derivations.
            if !self.raw.contains(&rel) {
                self.raw.push(rel);
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
                    // Stash the emitted-stream context before the body —
                    // pre-block text + BEGIN line, up to CTX_BACK bytes. At
                    // close/bail-out the PEM layer combines it with the tag
                    // (and END marker) so the post-block context is
                    // chunk-independent (#27).
                    self.pem_pre_block =
                        self.carry_over[body_start.saturating_sub(CTX_BACK)..body_start].to_vec();
                    body_start
                }
            }
            None => emit_start,
        };

        // 7. Emit matches (regular + PEM body spans) and clean gaps.
        //    For context-keyed rules, `m.start..m.redact_start` and
        //    `m.redact_end..m.end` are context bytes that pass through;
        //    only `m.redact_start..m.redact_end` is replaced by the tag.
        // Emission starts at the context prefix boundary: ctx bytes were
        // already emitted by the PEM layer and must never be re-written.
        // A match whose backward extension reaches into the prefix is
        // still confirmed with full context — only its re-emission is
        // clipped (#27).
        let mut pos = self.ctx_len;
        for m in &self.merged {
            if m.start >= carry_start {
                // Final flush emits a zero-length PEM span that starts
                // exactly at EOF (BEGIN line with no body); non-final defers
                // everything from carry_start onward.
                if !(is_final && m.start == carry_start && m.end == carry_start) {
                    break;
                }
            }
            // Clean gap before the match extent plus the context prefix
            // (empty for full-span rules). The guard clips the portion
            // below `pos` — only reachable when a context-keyed match
            // extends backward into the already-emitted prefix.
            if m.redact_start > pos {
                out.write_all(&self.carry_over[pos..m.redact_start])?;
            }
            // The CLOAK tag — digest covers only the redaction span.
            if m.rule == self.engine.pem_rule_idx {
                let rule_id = crate::types::RuleId::new(pem::PEM_RULE_ID);
                let digest = crate::redact::compute_digest(
                    &self.carry_over[m.redact_start..m.redact_end],
                    &self.engine.digest_key,
                );
                crate::redact::write_tag(&rule_id, &digest, out)?;
                *self.matches.entry(rule_id).or_insert(0) += 1;
            } else {
                let rule_id = &self.engine.rules[m.rule].id;
                let digest = crate::redact::compute_digest(
                    &self.carry_over[m.redact_start..m.redact_end],
                    &self.engine.digest_key,
                );
                crate::redact::write_tag(rule_id, &digest, out)?;
                *self.matches.entry(rule_id.clone()).or_insert(0) += 1;
            }
            // Context suffix (empty for full-span rules). PEM matches never
            // write their suffix: for a full block it is empty, and for an
            // oversized/bailed-out block it is the suppressed tail (F05) —
            // private-key material past the truncation point must not leak.
            if m.rule != self.engine.pem_rule_idx {
                out.write_all(&self.carry_over[m.redact_end..m.end])?;
            }
            pos = m.end;
        }

        // 8. Flush clean bytes up to carry_start, retain the rest.
        if pos < carry_start {
            out.write_all(&self.carry_over[pos..carry_start])?;
        }
        // `merged` spans are relative to the pre-drain buffer; their
        // absolute offsets use the pre-drain carry start.
        let pre_drain_abs = self.carry_abs;
        self.carry_over.drain(..carry_start);
        self.carry_abs += carry_start as u64;
        self.ctx_len = self.ctx_len.saturating_sub(carry_start);

        // 9. Refresh the retained list: every merged span not fully
        //    flushed (end beyond carry_start) is carried into the next
        //    push with absolute offsets (#27). `finish` (is_final) emits
        //    everything, so the list is always empty afterwards.
        if is_final {
            self.retained.clear();
        } else {
            self.retained = self
                .merged
                .iter()
                .filter(|m| m.end > carry_start)
                .map(|m| RawMatch {
                    start: m.start + pre_drain_abs as usize,
                    end: m.end + pre_drain_abs as usize,
                    redact_start: m.redact_start + pre_drain_abs as usize,
                    redact_end: m.redact_end + pre_drain_abs as usize,
                    rule: m.rule,
                })
                .collect();
        }

        Ok(entry)
    }

    /// Return the current carry-over length (test-support only).
    #[doc(hidden)]
    pub fn carry_over_len(&self) -> usize {
        self.carry_over.len()
    }
}

/// Hard upper bound on [`Session::carry_over_len`] after any `push`:
/// the largest rule window in the full catalog (2048, jwt — pinned by the
/// `engine_max_window` unit test) plus PEM retention (`PEM_BAIL_OUT` +
/// `MAX_PEM_LINE`). Shared by the fuzz harness, the S7 corpus tests, and
/// the soak tests so the asserted bound cannot drift between them.
// `pub` for the `#[doc(hidden)]` re-export in lib.rs (bench/test tier) —
// the module itself is private, so this is not part of the public API.
pub const CARRY_OVER_BOUND: usize = 2048 + pem::PEM_BAIL_OUT + pem::MAX_PEM_LINE;

/// Bytes of already-emitted backward context retained in front of the
/// carry-over after a PEM block close (#27): candidates in the remainder
/// need backward context the PEM layer consumed. Must cover the largest
/// rule backward reach in the catalog (email: 94, including the #34
/// tag-tail guard's CLOAK_TAG_MAX) — pinned by the
/// `ctx_back_covers_max_rule_back` unit test.
const CTX_BACK: usize = 94;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::RuleId;

    fn test_engine() -> Engine {
        Engine::new(&Config::ephemeral()).unwrap()
    }

    fn engine_with_rules(overrides: &[(&str, bool)]) -> Engine {
        let mut config = Config::ephemeral();
        for &(id, enabled) in overrides {
            config
                .rules
                .insert(id.to_string(), config::RuleConfig { enabled });
        }
        Engine::new(&config).unwrap()
    }

    fn all_rules_off() -> Vec<(&'static str, bool)> {
        rules::CATALOG
            .iter()
            .map(|spec| (spec.id, false))
            .chain(std::iter::once((pem::PEM_RULE_ID, false)))
            .collect()
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
        // Retention = max(window + back) = jwt (2048 + 0) — the largest
        // in the S4 catalog. This is also the hard bound on carry-over
        // after every push.
        let engine = test_engine();
        assert_eq!(engine.max_window, 2048);
    }

    #[test]
    fn ctx_back_covers_max_rule_back() {
        // The PEM-close context prefix must cover every rule's backward
        // reach, or candidates near a remainder could be skipped with a
        // truncated window (#27).
        for spec in rules::CATALOG {
            assert!(
                spec.back <= CTX_BACK,
                "CTX_BACK ({CTX_BACK}) must cover rule {} backward reach ({})",
                spec.id,
                spec.back
            );
        }
    }

    #[test]
    fn email_long_local_capped_streaming_parity() {
        // #41 review: `b"a"*3000 + b"@example.com"` previously redacted a
        // span that depended on where the carry buffer started — the CLI
        // emitted 964 plaintext `a`s before the tag on its 64 KiB chunk
        // schedule. The 64-byte local cap pins the span: 2936 `a`s pass
        // through, the final 64 plus `@example.com` become exactly one
        // tag, identically at every chunk size.
        let engine = test_engine();
        let mut input = vec![b'a'; 3000];
        input.extend_from_slice(b"@example.com");

        let mut session = engine.session();
        let mut whole = Vec::new();
        session.push(&input, &mut whole).unwrap();
        let whole_stats = session.finish(&mut whole).unwrap();

        assert_eq!(whole_stats.matches[&RuleId::new("email")], 1);
        let tag_start = whole
            .windows(7)
            .position(|w| w == b"[CLOAK:")
            .expect("the email tag must be present");
        assert_eq!(tag_start, 3000 - 64);
        assert!(
            whole[..tag_start].iter().all(|&b| b == b'a'),
            "bytes before the tag must be the uncapped local prefix"
        );
        assert!(whole[tag_start..].starts_with(b"[CLOAK:email:"));

        for cs in [1usize, 7, 64, 1024, 4096, 65536] {
            let mut session = engine.session();
            let mut chunked = Vec::new();
            for chunk in input.chunks(cs) {
                session.push(chunk, &mut chunked).unwrap();
            }
            let chunked_stats = session.finish(&mut chunked).unwrap();
            assert_eq!(
                chunked, whole,
                "chunk size {cs}: streaming must equal whole-buffer"
            );
            assert_eq!(chunked_stats.matches, whole_stats.matches);
        }
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
        // Valid CRC: CRC32("AbCdEfGhIjKlMnOpQrStUvWxYz0123") → "2piBxe"
        let secret = b"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";
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
        // Valid CRC: CRC32("AbCdEfGhIjKlMnOpQrStUvWxYz0123") → "2piBxe"
        let token = b"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";
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
        // Valid CRC: CRC32("AbCdEfGhIjKlMnOpQrStUvWxYz0123") → "2piBxe"
        let token = b"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";
        let mut session = engine.session();
        let mut output = Vec::new();
        // Split at 18 bytes: "npm_AbCdEfGhIjKlMn" | "OpQrStUvWxYz01232piBxe"
        session.push(b"npm_AbCdEfGhIjKlMn", &mut output).unwrap();
        session
            .push(b"OpQrStUvWxYz01232piBxe", &mut output)
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
        // Valid CRC: CRC32("AbCdEfGhIjKlMnOpQrStUvWxYz0123") → "2piBxe"
        let token = b"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";
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
        // Must exceed max_window (2048 after S4) to see a flush.
        let data = vec![b'x'; 5000];
        session.push(&data, &mut output).unwrap();

        assert_eq!(session.carry_over_len(), engine.max_window);
        assert_eq!(output.len(), 5000 - engine.max_window);

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
        // Valid CRC body: CRC32("AbCdEfGhIjKlMnOpQrStUvWxYz0123") → "2piBxe"
        session
            .push(b"AbCdEfGhIjKlMnOpQrStUvWxYz01232piBxe", &mut output)
            .unwrap();
        let stats = session.finish(&mut output).unwrap();
        assert_eq!(stats.matches[&RuleId::new("npm-token")], 1);
    }

    #[test]
    fn one_megabyte_push_bounded_carry() {
        // F10: a single very large push must not grow carry_over with
        // the chunk size — push slices the chunk internally, so the
        // hard bound holds after the push, and chunk-invariance keeps
        // the output identical to an 8 KiB-chunked feed of the same
        // stream. The input mixes AWS keys (regular rules), small
        // complete PEM blocks, and one oversized block that bails out
        // and drains (F05) so every retention path is exercised.
        let engine = test_engine();
        let mut input = Vec::new();
        for i in 0..128 {
            input.extend_from_slice(format!("line {i}: key=AKIAIOSFODNN7EXAMPLE\n").as_bytes());
            input.extend_from_slice(b"-----BEGIN RSA PRIVATE KEY-----\n");
            input.extend_from_slice(&[b'K'; 64]);
            input.extend_from_slice(b"\n-----END RSA PRIVATE KEY-----\n");
            input.extend_from_slice(&vec![b' '; 8000]);
        }
        input.extend_from_slice(b"-----BEGIN EC PRIVATE KEY-----\n");
        input.extend_from_slice(&vec![b'Z'; pem::PEM_BAIL_OUT + 512]);
        input.extend_from_slice(b"\n-----END EC PRIVATE KEY-----\n");
        input.extend_from_slice(b"tail key=AKIAIOSFODNN7EXAMPLE\n");
        assert!(input.len() > 1 << 20, "input must exceed 1 MiB");

        let mut session = engine.session();
        let mut big_out = Vec::new();
        session.push(&input, &mut big_out).unwrap();
        assert!(
            session.carry_over_len() <= CARRY_OVER_BOUND,
            "carry must stay bounded after a 1 MiB push, got {}",
            session.carry_over_len()
        );
        let big_stats = session.finish(&mut big_out).unwrap();

        let mut session = engine.session();
        let mut chunked_out = Vec::new();
        for chunk in input.chunks(8192) {
            session.push(chunk, &mut chunked_out).unwrap();
        }
        let chunked_stats = session.finish(&mut chunked_out).unwrap();

        assert_eq!(
            big_out, chunked_out,
            "1 MiB push diverges from 8 KiB chunks"
        );
        assert_eq!(big_stats.matches, chunked_stats.matches);
        // Every secret and PEM body was redacted, none leaked.
        assert_eq!(
            big_stats.matches[&RuleId::new("aws-access-key")],
            129,
            "128 inline keys + the trailing one"
        );
        assert_eq!(
            big_stats.matches[&RuleId::new("pem-private-key")],
            129,
            "128 small blocks + the oversized one"
        );
        let out_str = String::from_utf8_lossy(&big_out);
        assert!(!out_str.contains("IOSFODNN7EXAMPLE"));
        assert!(!out_str.contains("KKKK"));
        assert!(!out_str.contains("ZZZZ"));
    }

    #[test]
    fn max_window_reflects_filtered_rules() {
        // JWT has window=2048 (largest in catalog). Disable it, and
        // max_window should drop to the next-largest enabled rule.
        let engine = engine_with_rules(&[("jwt", false)]);
        assert!(
            engine.max_window < 2048,
            "jwt disabled → max_window must drop"
        );
    }

    #[test]
    fn max_window_zero_when_all_rules_disabled() {
        // All rules INCLUDING PEM disabled → max_window must be 0.
        let engine = engine_with_rules(&all_rules_off());
        assert_eq!(
            engine.max_window, 0,
            "all rules disabled (incl PEM) → max_window must be 0"
        );
    }

    #[test]
    fn max_window_includes_pem_when_pem_enabled() {
        // All catalog rules disabled but PEM stays enabled (default) →
        // max_window must be at least pem_confirm_window (37), not 0.
        let catalog_off: Vec<(&str, bool)> = all_rules_off()
            .into_iter()
            .filter(|(id, _)| *id != "pem-private-key")
            .collect();
        let engine = engine_with_rules(&catalog_off);
        assert!(
            engine.max_window >= 37,
            "PEM enabled → max_window must include PEM confirm window, got {}",
            engine.max_window
        );
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
    fn tag_after_begin_line_rejected_at_every_chunk_size() {
        // fuzz_pem_state regression: the `[CLOAK:` idempotence guard reads
        // bytes AFTER the BEGIN line, so the confirm window must cover
        // them — with a short window, tiny pushes confirmed the BEGIN
        // before the guard bytes arrived and redacted a block the
        // whole-buffer path rejects (passthrough).
        let engine = test_engine();
        let mut input = b"-----BEGIN ENCRYPTED PRIVATE KEY-----".to_vec();
        input.extend_from_slice(b"[CLOAK:pem-private-key:\nMIIE6TAbBg\n");
        input.extend_from_slice(b"-----END ENCRYPTED PRIVATE KEY-----");
        let (whole, whole_stats) = push_all(&engine, &input);
        assert_eq!(whole, input, "guard must reject the tagged block");
        for chunk_size in [1, 3, 7, 38, 44] {
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
            assert_eq!(stats.matches, whole_stats.matches);
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
        // The push loop is iterative: several oversized blocks in a single
        // push each bail out and drain independently (F05). Unterminated
        // blocks swallow everything after them, so this uses complete
        // blocks — each tag covers exactly PEM_BAIL_OUT bytes, each tail
        // is suppressed, and both END lines stay visible.
        let engine = test_engine();
        let mut input = b"-----BEGIN RSA PRIVATE KEY-----\n".to_vec();
        input.extend_from_slice(&vec![b'A'; pem::PEM_BAIL_OUT + 100]);
        input.extend_from_slice(b"\n-----END RSA PRIVATE KEY-----");
        input.extend_from_slice(b"\n-----BEGIN EC PRIVATE KEY-----\n");
        input.extend_from_slice(&vec![b'B'; pem::PEM_BAIL_OUT + 100]);
        input.extend_from_slice(b"\n-----END EC PRIVATE KEY-----");
        let mut session = engine.session();
        let mut out = Vec::new();
        session.push(&input, &mut out).unwrap();
        assert!(
            session.carry_over_len() <= CARRY_OVER_BOUND,
            "carry must stay bounded after bail-outs"
        );
        let stats = session.finish(&mut out).unwrap();
        assert_eq!(stats.matches[&RuleId::new("pem-private-key")], 2);
        let out_str = String::from_utf8_lossy(&out);
        assert_eq!(out_str.matches("[CLOAK:pem-private-key:").count(), 2);
        // Both BEGIN and END lines stay visible; neither tail leaks. (The
        // newline before each END marker is body — suppressed — so the END
        // lines abut their tags directly.)
        assert!(out.starts_with(b"-----BEGIN RSA PRIVATE KEY-----"));
        assert!(out_str.contains("-----END RSA PRIVATE KEY-----"));
        assert!(out_str.contains("-----BEGIN EC PRIVATE KEY-----"));
        assert!(out_str.ends_with("-----END EC PRIVATE KEY-----"));
        assert!(!out_str.contains("AAAA"));
        assert!(!out_str.contains("BBBB"));
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
        input.extend_from_slice(b"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\n");
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

    #[test]
    fn f01_ipv6_fully_expanded_detected() {
        // F01: fully expanded 8-group IPv6 with no `::` must be detected.
        let engine = test_engine();
        let input = b"2001:0db8:85a3:0000:0000:8a2e:0370:7334";
        let (out, stats) = push_all(&engine, input);
        let ipv6 = crate::types::RuleId::new("ipv6");
        assert_eq!(
            stats.matches.get(&ipv6),
            Some(&1),
            "fully expanded IPv6 must be detected: {}",
            String::from_utf8_lossy(&out)
        );
    }
}
